"""Низкоуровневые операции Windows: реестр, подписи, свойства файлов, ACL.

Модуль не зависит от Tkinter, поэтому его можно тестировать отдельно.
"""

from __future__ import annotations

import base64
import ctypes
import hashlib
import json
import logging
import os
import re
import subprocess
import tempfile
import threading
import time
import winreg
from concurrent.futures import ThreadPoolExecutor, as_completed
from ctypes import wintypes
from datetime import datetime
from pathlib import Path
from typing import Callable, Iterable, Optional

from .models import FileInfo, LiveInfo, SignatureInfo

log = logging.getLogger(__name__)

CREATE_NO_WINDOW = 0x08000000
SYSTEM_ROOT = os.environ.get("SystemRoot", r"C:\Windows")
SYSTEM_DRIVE = os.environ.get("SystemDrive", "C:") + "\\"

ProgressCallback = Callable[[int, str], None]

# ---------------------------------------------------------------------------
# ctypes-обёртки
# ---------------------------------------------------------------------------

_version = ctypes.WinDLL("version", use_last_error=True)
_version.GetFileVersionInfoSizeW.argtypes = [
    wintypes.LPCWSTR,
    ctypes.POINTER(wintypes.DWORD),
]
_version.GetFileVersionInfoSizeW.restype = wintypes.DWORD
_version.GetFileVersionInfoW.argtypes = [
    wintypes.LPCWSTR,
    wintypes.DWORD,
    wintypes.DWORD,
    ctypes.c_void_p,
]
_version.GetFileVersionInfoW.restype = wintypes.BOOL
_version.VerQueryValueW.argtypes = [
    ctypes.c_void_p,
    wintypes.LPCWSTR,
    ctypes.POINTER(ctypes.c_void_p),
    ctypes.POINTER(wintypes.UINT),
]
_version.VerQueryValueW.restype = wintypes.BOOL

_shlwapi = ctypes.WinDLL("shlwapi", use_last_error=True)
_shlwapi.SHLoadIndirectString.argtypes = [
    wintypes.LPCWSTR,
    wintypes.LPWSTR,
    wintypes.UINT,
    ctypes.c_void_p,
]
_shlwapi.SHLoadIndirectString.restype = ctypes.c_long

VERSION_FIELDS = (
    "CompanyName",
    "FileDescription",
    "ProductName",
    "FileVersion",
    "OriginalFilename",
    "InternalName",
    "LegalCopyright",
)


def is_admin() -> bool:
    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        return False


def enable_dpi_awareness() -> None:
    """Убирает размытие интерфейса Tkinter на мониторах с масштабированием."""
    try:
        ctypes.windll.shcore.SetProcessDpiAwareness(1)
    except Exception:
        try:
            ctypes.windll.user32.SetProcessDPIAware()
        except Exception:
            pass


def resolve_indirect_string(value: str) -> str:
    """Разворачивает строки вида '@%SystemRoot%\\system32\\x.dll,-1000'."""
    if not value:
        return ""
    if not value.startswith("@"):
        return value
    buffer = ctypes.create_unicode_buffer(4096)
    try:
        hresult = _shlwapi.SHLoadIndirectString(value, buffer, len(buffer), None)
        if hresult == 0 and buffer.value:
            return buffer.value
    except Exception:
        pass
    # Запасной вариант: убираем «@» и «,-1234».
    fallback = re.sub(r",-\d+$", "", value)
    return fallback.lstrip("@")


def get_version_info(path: str) -> dict[str, str]:
    """Читает свойства версии из PE-файла (exe/dll/sys)."""
    dummy = wintypes.DWORD()
    try:
        size = _version.GetFileVersionInfoSizeW(path, ctypes.byref(dummy))
    except Exception:
        return {}
    if not size:
        return {}
    data = ctypes.create_string_buffer(size)
    try:
        if not _version.GetFileVersionInfoW(path, 0, size, data):
            return {}
        pointer = ctypes.c_void_p()
        length = wintypes.UINT()
        if not _version.VerQueryValueW(
            data,
            "\\VarFileInfo\\Translation",
            ctypes.byref(pointer),
            ctypes.byref(length),
        ):
            return {}
        words = ctypes.cast(pointer, ctypes.POINTER(wintypes.WORD))
        language, codepage = words[0], words[1]
    except Exception:
        return {}

    result: dict[str, str] = {}
    for field in VERSION_FIELDS:
        query = f"\\StringFileInfo\\{language:04x}{codepage:04x}\\{field}"
        value_pointer = ctypes.c_void_p()
        value_length = wintypes.UINT()
        try:
            if _version.VerQueryValueW(
                data,
                query,
                ctypes.byref(value_pointer),
                ctypes.byref(value_length),
            ) and value_pointer.value:
                result[field] = ctypes.wstring_at(value_pointer.value).strip()
        except Exception:
            continue
    return result


_version_cache: dict[tuple[str, int], dict[str, str]] = {}
_version_lock = threading.Lock()


def get_file_info(path: str) -> FileInfo:
    """Собирает размер, даты и свойства версии файла."""
    info = FileInfo(path=path or "")
    if not path:
        info.error = "Путь не указан"
        return info
    try:
        stat = os.stat(path)
    except PermissionError as exc:
        info.error = str(exc)
        info.access_denied = True
        try:
            info.exists = os.path.exists(path)
        except OSError:
            pass
        return info
    except OSError as exc:
        info.error = str(exc)
        return info

    info.exists = True
    info.size = stat.st_size
    try:
        info.created = datetime.fromtimestamp(stat.st_ctime)
        info.modified = datetime.fromtimestamp(stat.st_mtime)
    except (OverflowError, OSError, ValueError):
        pass

    key = (os.path.normcase(os.path.abspath(path)), stat.st_mtime_ns)
    with _version_lock:
        cached = _version_cache.get(key)
    if cached is None:
        cached = get_version_info(path)
        with _version_lock:
            _version_cache[key] = cached

    info.company = cached.get("CompanyName", "")
    info.product = cached.get("ProductName", "")
    info.description = cached.get("FileDescription", "")
    info.version = cached.get("FileVersion", "")
    info.original_name = cached.get("OriginalFilename", "")
    info.internal_name = cached.get("InternalName", "")
    return info


def sha256_file(path: str, max_size: int = 512 * 1024 * 1024) -> str:
    """Считает SHA-256. Возвращает '' при ошибке или слишком большом файле."""
    try:
        if os.path.getsize(path) > max_size:
            return ""
        digest = hashlib.sha256()
        with open(path, "rb") as handle:
            while True:
                chunk = handle.read(1024 * 1024)
                if not chunk:
                    break
                digest.update(chunk)
        return digest.hexdigest()
    except OSError as exc:
        log.debug("Не удалось посчитать хэш %s: %s", path, exc)
        return ""


# ---------------------------------------------------------------------------
# Разбор ImagePath
# ---------------------------------------------------------------------------

_DRIVE_RE = re.compile(r"^[a-zA-Z]:")


def expand_windows_path(path: str) -> str:
    """Раскрывает %переменные%, \\SystemRoot, System32\\ и \\??\\."""
    if not path:
        return ""
    value = path.strip().strip('"')
    value = os.path.expandvars(value)
    low = value.lower()

    if low.startswith("\\systemroot\\"):
        value = SYSTEM_ROOT + value[len("\\systemroot") :]
    elif low.startswith("systemroot\\"):
        value = SYSTEM_ROOT + "\\" + value[len("systemroot\\") :]
    elif low.startswith("system32\\") or low.startswith("syswow64\\"):
        value = os.path.join(SYSTEM_ROOT, value)

    if value.startswith("\\??\\"):
        value = value[4:]
    elif value.startswith("??\\"):
        value = value[3:]
    if value.lower().startswith("unc\\"):
        value = "\\\\" + value[4:]
    if value.lower().startswith("dosdevices\\"):
        value = value[len("dosdevices\\") :]

    return value.strip().strip('"')


def split_image_path(binpath: str) -> tuple[str, str, bool]:
    """Возвращает (путь, аргументы, был_ли_путь_в_кавычках)."""
    raw = (binpath or "").strip()
    if not raw:
        return "", "", False

    quoted = raw.startswith('"')
    if quoted:
        end = raw.find('"', 1)
        if end == -1:
            path_part, args = raw[1:], ""
        else:
            path_part, args = raw[1:end], raw[end + 1 :].strip()
    else:
        match = re.match(
            r"^(.*?\.(?:exe|sys|dll|com|bat|cmd|ps1|vbs|scr|msi))(?=\s|$)",
            raw,
            re.IGNORECASE,
        )
        if match:
            path_part = match.group(1)
            args = raw[match.end() :].strip()
        else:
            pieces = raw.split(None, 1)
            path_part = pieces[0]
            args = pieces[1] if len(pieces) > 1 else ""

    path = expand_windows_path(path_part)
    if path:
        low = path.lower()
        if not _DRIVE_RE.match(path) and not path.startswith("\\\\"):
            if "\\" not in path and "/" not in path:
                # Голое имя: Windows ищет его в System32.
                candidate = os.path.join(SYSTEM_ROOT, "System32", path)
                if os.path.exists(candidate):
                    path = candidate
            else:
                path = os.path.join(SYSTEM_ROOT, path)
        path = os.path.normpath(path)
    return path, args, quoted


def get_drive_type(path: str) -> int:
    """GetDriveTypeW: 2 — съёмный, 3 — локальный, 4 — сетевой."""
    try:
        drive = os.path.splitdrive(path)[0]
        root = (drive + "\\") if drive else path
        return int(ctypes.windll.kernel32.GetDriveTypeW(root))
    except Exception:
        return 0


# ---------------------------------------------------------------------------
# Проверка цифровой подписи
# ---------------------------------------------------------------------------

_signature_cache: dict[tuple[str, int, int], SignatureInfo] = {}
_signature_lock = threading.Lock()


def _powershell_command(script: str) -> list[str]:
    encoded = base64.b64encode(script.encode("utf-16-le")).decode("ascii")
    powershell = os.path.join(
        os.environ.get("SystemRoot", r"C:\Windows"),
        "System32",
        "WindowsPowerShell",
        "v1.0",
        "powershell.exe",
    )
    if not os.path.exists(powershell):
        powershell = "powershell.exe"
    return [
        powershell,
        "-NoProfile",
        "-NonInteractive",
        "-ExecutionPolicy",
        "Bypass",
        "-WindowStyle",
        "Hidden",
        "-EncodedCommand",
        encoded,
    ]


def _run_powershell(script: str, timeout: int = 180) -> subprocess.CompletedProcess:
    return subprocess.run(
        _powershell_command(script),
        capture_output=True,
        timeout=timeout,
        creationflags=CREATE_NO_WINDOW,
    )


_SIGNATURE_SCRIPT = r"""
$ProgressPreference = 'SilentlyContinue'
$ErrorActionPreference = 'SilentlyContinue'
$paths = @()
try {
    $json = [IO.File]::ReadAllText('__INPUT_PATH__', [Text.Encoding]::UTF8)
    $parsed = $json | ConvertFrom-Json
    $paths = @($parsed)
} catch { }

$result = foreach ($path in $paths) {
    $item = [ordered]@{
        path = $path
        status = 'Error'
        statusMessage = ''
        subject = ''
        issuer = ''
        notAfter = ''
        thumbprint = ''
        timestamped = $false
        osBinary = $false
    }
    try {
        if (-not (Test-Path -LiteralPath $path -PathType Leaf)) {
            $item.status = 'Missing'
            $item.statusMessage = 'Файл не найден'
        } else {
            $sig = Get-AuthenticodeSignature -LiteralPath $path -ErrorAction Stop
            $item.status = $sig.Status.ToString()
            $item.statusMessage = [string]$sig.StatusMessage
            if ($null -ne $sig.SignerCertificate) {
                $item.subject = [string]$sig.SignerCertificate.Subject
                $item.issuer = [string]$sig.SignerCertificate.Issuer
                $item.notAfter = $sig.SignerCertificate.NotAfter.ToUniversalTime().ToString('o')
                $item.thumbprint = [string]$sig.SignerCertificate.Thumbprint
            }
            try { $item.osBinary = [bool]$sig.IsOSBinary } catch { }
            try { $item.timestamped = ($null -ne $sig.TimeStamperCertificate) } catch { }
        }
    } catch {
        $item.status = 'Error'
        $item.statusMessage = [string]$_.Exception.Message
    }
    [pscustomobject]$item
}

$json = ConvertTo-Json -InputObject @($result) -Compress -Depth 4
[IO.File]::WriteAllText('__OUTPUT_PATH__', $json, [Text.UTF8Encoding]::new($false))
"""


def _status_from_dict(data: dict) -> SignatureInfo:
    info = SignatureInfo(
        status=str(data.get("status") or "Error"),
        status_message=str(data.get("statusMessage") or ""),
        subject=str(data.get("subject") or ""),
        issuer=str(data.get("issuer") or ""),
        thumbprint=str(data.get("thumbprint") or ""),
        not_after=str(data.get("notAfter") or ""),
        timestamped=bool(data.get("timestamped")),
        os_binary=bool(data.get("osBinary")),
    )
    subject = info.subject.replace('\\,', ',')
    match_org = re.search(r"(?:^|,\s*)O=([^,]+)", subject)
    if match_org:
        info.signer_org = match_org.group(1).strip().strip('"')
    match_cn = re.search(r"(?:^|,\s*)CN=([^,]+)", subject)
    if match_cn:
        info.signer_cn = match_cn.group(1).strip().strip('"')
    if info.status == "UnknownError" and info.status_message:
        info.error = info.status_message
    return info


def _signature_chunk(paths: list[str]) -> dict[str, SignatureInfo]:
    if not paths:
        return {}
    result: dict[str, SignatureInfo] = {}
    with tempfile.TemporaryDirectory(prefix="sa_sig_") as temp_dir:
        input_path = os.path.join(temp_dir, "paths.json")
        output_path = os.path.join(temp_dir, "result.json")
        Path(input_path).write_text(
            json.dumps(paths, ensure_ascii=False), encoding="utf-8"
        )
        script = _SIGNATURE_SCRIPT.replace(
            "__INPUT_PATH__", input_path.replace("'", "''")
        ).replace("__OUTPUT_PATH__", output_path.replace("'", "''"))
        try:
            process = _run_powershell(script, timeout=240)
        except Exception as exc:
            log.warning("PowerShell не смог проверить подписи: %s", exc)
            for path in paths:
                result[path] = SignatureInfo(status="Error", error=str(exc))
            return result

        try:
            raw = Path(output_path).read_text(encoding="utf-8-sig")
            data = json.loads(raw)
        except Exception as exc:
            stderr = process.stderr.decode("mbcs", errors="replace")[:500]
            log.warning("Не удалось разобрать ответ PowerShell: %s (%s)", exc, stderr)
            for path in paths:
                result[path] = SignatureInfo(status="Error", error="Нет ответа PowerShell")
            return result

        if isinstance(data, dict):
            data = [data]
        for item in data:
            if not isinstance(item, dict):
                continue
            path = str(item.get("path") or "")
            if path:
                result[path] = _status_from_dict(item)
    return result


def get_signatures(
    paths: Iterable[str],
    progress: Optional[ProgressCallback] = None,
    cancel_event: Optional[threading.Event] = None,
    max_workers: int = 4,
) -> dict[str, SignatureInfo]:
    """Проверяет подписи пакетно, в несколько процессов PowerShell.

    Возвращает словарь {путь: SignatureInfo}. Отсутствующие файлы тоже попадают
    в результат со статусом Missing.
    """
    unique: list[str] = []
    seen: set[str] = set()
    for path in paths:
        if not path:
            continue
        key = os.path.normcase(path)
        if key in seen:
            continue
        seen.add(key)
        unique.append(path)

    results: dict[str, SignatureInfo] = {}
    to_check: list[str] = []
    now_keys: dict[str, tuple[str, int, int]] = {}

    for path in unique:
        try:
            stat = os.stat(path)
            key = (os.path.normcase(path), stat.st_mtime_ns, stat.st_size)
            now_keys[path] = key
            with _signature_lock:
                cached = _signature_cache.get(key)
            if cached is not None:
                results[path] = cached
                continue
        except OSError:
            results[path] = SignatureInfo(status="Missing", status_message="Файл не найден")
            continue
        to_check.append(path)

    if not to_check:
        if progress:
            progress(100, "Подписи взяты из кэша")
        return results

    chunk_size = max(25, min(60, (len(to_check) + max_workers - 1) // max_workers))
    chunks = [to_check[i : i + chunk_size] for i in range(0, len(to_check), chunk_size)]
    completed = 0
    total = len(to_check)

    with ThreadPoolExecutor(max_workers=min(max_workers, len(chunks))) as executor:
        futures = {executor.submit(_signature_chunk, chunk): chunk for chunk in chunks}
        for future in as_completed(futures):
            if cancel_event is not None and cancel_event.is_set():
                for pending in futures:
                    pending.cancel()
                break
            chunk = futures[future]
            try:
                chunk_result = future.result()
            except Exception as exc:
                log.warning("Ошибка проверки подписей: %s", exc)
                chunk_result = {
                    path: SignatureInfo(status="Error", error=str(exc)) for path in chunk
                }
            for path, info in chunk_result.items():
                results[path] = info
                key = now_keys.get(path)
                if key:
                    with _signature_lock:
                        _signature_cache[key] = info
            completed += len(chunk)
            if progress:
                percent = 15 + int(60 * completed / max(1, total))
                progress(percent, f"Проверка подписи: {completed} из {total} файлов")

    # Файлы, до которых не дошла очередь из-за отмены, получают Unknown.
    for path in to_check:
        results.setdefault(path, SignatureInfo(status="Unknown", error="Проверка отменена"))
    return results


# ---------------------------------------------------------------------------
# Службы: реестр и состояния
# ---------------------------------------------------------------------------

_SERVICE_KEY = r"SYSTEM\CurrentControlSet\Services"


def _read_value(key, name: str, default=None):
    try:
        return winreg.QueryValueEx(key, name)[0]
    except (OSError, ValueError, TypeError):
        return default


def enumerate_registry_services(include_drivers: bool = False) -> list[dict]:
    """Читает описания служб и драйверов из HKLM\\SYSTEM\\CurrentControlSet\\Services."""
    entries: list[dict] = []
    try:
        root = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, _SERVICE_KEY)
    except OSError as exc:
        log.error("Не удалось открыть реестр служб: %s", exc)
        return entries

    with root:
        try:
            subkey_count = winreg.QueryInfoKey(root)[0]
        except OSError as exc:
            log.error("Не удалось перечислить службы: %s", exc)
            return entries

        for index in range(subkey_count):
            try:
                name = winreg.EnumKey(root, index)
            except OSError:
                continue
            try:
                key = winreg.OpenKey(root, name)
            except OSError:
                continue

            with key:
                service_type = _read_value(key, "Type", 0)
                if not isinstance(service_type, int) or service_type <= 0:
                    continue
                is_driver = service_type < 0x10
                if is_driver and not include_drivers:
                    continue
                if not is_driver and service_type < 0x10:
                    continue

                image_path = _read_value(key, "ImagePath", "") or ""
                service_dll = ""
                try:
                    params = winreg.OpenKey(key, "Parameters")
                    with params:
                        service_dll = _read_value(params, "ServiceDll", "") or ""
                except OSError:
                    pass

                if not image_path and not service_dll:
                    continue

                display_name = resolve_indirect_string(
                    str(_read_value(key, "DisplayName", "") or "")
                )
                description = resolve_indirect_string(
                    str(_read_value(key, "Description", "") or "")
                )
                account = str(_read_value(key, "ObjectName", "") or "")
                dependencies = _read_value(key, "DependOnService", []) or []
                if isinstance(dependencies, str):
                    dependencies = [dependencies]

                entries.append(
                    {
                        "name": name,
                        "display_name": display_name or name,
                        "description": description,
                        "service_type": service_type,
                        "is_driver": is_driver,
                        "image_path": str(image_path),
                        "service_dll": str(service_dll),
                        "account": account,
                        "start": _read_value(key, "Start", 3),
                        "delayed": bool(_read_value(key, "DelayedAutoStart", 0)),
                        "dependencies": [str(item) for item in dependencies],
                        "registry_key": f"HKEY_LOCAL_MACHINE\\{_SERVICE_KEY}\\{name}",
                    }
                )
    return entries


def get_service_states(include_drivers: bool = False) -> dict[str, dict]:
    """Возвращает состояния и PID служб, а при необходимости и драйверов.

    Состояния служб читаются через psutil (нативный API), драйверов — через
    WMI. Это надёжнее локализованного sc.exe, который на русской Windows
    может по-разному печатать названия полей.
    """
    states: dict[str, dict] = {}
    try:
        import psutil

        for service in psutil.win_service_iter():
            try:
                data = service.as_dict()
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue
            status_text = str(data.get("status") or "")
            key = status_text.replace("_", " ").lower()
            state_code = {
                "stopped": 1,
                "start pending": 2,
                "stop pending": 3,
                "running": 4,
                "continue pending": 5,
                "pause pending": 6,
                "paused": 7,
            }.get(key, 0)
            pid = int(data.get("pid") or 0)
            states[str(data.get("name") or "")] = {
                "state": state_code,
                "state_text": status_text,
                "pid": pid,
            }
    except Exception as exc:
        log.info("psutil недоступен для состояний служб: %s", exc)

    if include_drivers or not states:
        states.update(_cim_states(include_drivers=include_drivers))
    return states


_DRIVER_STATE_SCRIPT = r"""
$ProgressPreference = 'SilentlyContinue'
$ErrorActionPreference = 'SilentlyContinue'
$items = @()
Get-CimInstance Win32_SystemDriver -ErrorAction SilentlyContinue | ForEach-Object {
    $items += [pscustomobject]@{ name = $_.Name; state = $_.State; pid = 0 }
}
$json = ConvertTo-Json -InputObject @($items) -Compress -Depth 3
[IO.File]::WriteAllText('__OUTPUT_PATH__', $json, [Text.UTF8Encoding]::new($false))
"""

_SERVICE_STATE_SCRIPT = r"""
$ProgressPreference = 'SilentlyContinue'
$ErrorActionPreference = 'SilentlyContinue'
$items = @()
Get-CimInstance Win32_Service -ErrorAction SilentlyContinue | ForEach-Object {
    $items += [pscustomobject]@{ name = $_.Name; state = $_.State; pid = [int]$_.ProcessId }
}
$json = ConvertTo-Json -InputObject @($items) -Compress -Depth 3
[IO.File]::WriteAllText('__OUTPUT_PATH__', $json, [Text.UTF8Encoding]::new($false))
"""


def _run_state_script(script: str) -> list[dict]:
    with tempfile.TemporaryDirectory(prefix="sa_state_") as temp_dir:
        output_path = os.path.join(temp_dir, "states.json")
        script = script.replace("__OUTPUT_PATH__", output_path.replace("'", "''"))
        try:
            _run_powershell(script, timeout=60)
            data = json.loads(Path(output_path).read_text(encoding="utf-8-sig"))
        except Exception as exc:
            log.warning("Не удалось прочитать состояния через WMI: %s", exc)
            return []
        if isinstance(data, dict):
            data = [data]
        return [item for item in data if isinstance(item, dict)]


def _cim_states(include_drivers: bool) -> dict[str, dict]:
    result: dict[str, dict] = {}
    scripts = [_SERVICE_STATE_SCRIPT]
    if include_drivers:
        scripts.append(_DRIVER_STATE_SCRIPT)
    for script in scripts:
        for item in _run_state_script(script):
            name = str(item.get("name") or "")
            if not name:
                continue
            status_text = str(item.get("state") or "")
            key = status_text.strip().lower()
            state_code = {
                "stopped": 1,
                "start pending": 2,
                "stop pending": 3,
                "running": 4,
                "continue pending": 5,
                "pause pending": 6,
                "paused": 7,
            }.get(key, 0)
            result[name] = {
                "state": state_code,
                "state_text": status_text,
                "pid": int(item.get("pid") or 0),
            }
    return result


# ---------------------------------------------------------------------------
# Права на папку (необязательный глубокий анализ)
# ---------------------------------------------------------------------------

_ACL_SCRIPT = r"""
$ProgressPreference = 'SilentlyContinue'
$ErrorActionPreference = 'SilentlyContinue'
$dirs = @()
try {
    $json = [IO.File]::ReadAllText('__INPUT_PATH__', [Text.Encoding]::UTF8)
    $parsed = $json | ConvertFrom-Json
    $dirs = @($parsed)
} catch { }

$suspects = @('S-1-1-0','S-1-5-32-545','S-1-5-11','S-1-5-4','S-1-5-32-546')
$writeMask = 278

$result = foreach ($dir in $dirs) {
    $ok = $true
    $writable = $false
    try {
        $acl = Get-Acl -LiteralPath $dir -ErrorAction Stop
        $denied = @{}
        foreach ($ace in $acl.Access) {
            $sid = ''
            try { $sid = $ace.IdentityReference.Translate([System.Security.Principal.SecurityIdentifier]).Value } catch { continue }
            if ($suspects -notcontains $sid) { continue }
            $mask = [int]$ace.FileSystemRights
            if (($mask -band $writeMask) -eq 0) { continue }
            if ($ace.AccessControlType -eq 'Deny') { $denied[$sid] = $true }
        }
        foreach ($ace in $acl.Access) {
            if ($ace.AccessControlType -ne 'Allow') { continue }
            $sid = ''
            try { $sid = $ace.IdentityReference.Translate([System.Security.Principal.SecurityIdentifier]).Value } catch { continue }
            if ($suspects -notcontains $sid) { continue }
            if ($denied.ContainsKey($sid)) { continue }
            $mask = [int]$ace.FileSystemRights
            if (($mask -band $writeMask) -ne 0) { $writable = $true; break }
        }
    } catch {
        $ok = $false
    }
    [pscustomobject]@{ path = $dir; ok = $ok; writable = $writable }
}

$json = ConvertTo-Json -InputObject @($result) -Compress -Depth 3
[IO.File]::WriteAllText('__OUTPUT_PATH__', $json, [Text.UTF8Encoding]::new($false))
"""


def _acl_chunk(directories: list[str]) -> dict[str, Optional[bool]]:
    if not directories:
        return {}
    result: dict[str, Optional[bool]] = {}
    with tempfile.TemporaryDirectory(prefix="sa_acl_") as temp_dir:
        input_path = os.path.join(temp_dir, "dirs.json")
        output_path = os.path.join(temp_dir, "result.json")
        Path(input_path).write_text(
            json.dumps(directories, ensure_ascii=False), encoding="utf-8"
        )
        script = _ACL_SCRIPT.replace(
            "__INPUT_PATH__", input_path.replace("'", "''")
        ).replace("__OUTPUT_PATH__", output_path.replace("'", "''"))
        try:
            _run_powershell(script, timeout=180)
            data = json.loads(Path(output_path).read_text(encoding="utf-8-sig"))
        except Exception as exc:
            log.warning("Не удалось проверить права на папки: %s", exc)
            return {directory: None for directory in directories}

        if isinstance(data, dict):
            data = [data]
        for item in data:
            if not isinstance(item, dict):
                continue
            path = str(item.get("path") or "")
            if not path:
                continue
            if not item.get("ok", False):
                result[path] = None
            else:
                result[path] = bool(item.get("writable"))
    for directory in directories:
        result.setdefault(directory, None)
    return result


def check_directories_writable(
    directories: Iterable[str],
    progress: Optional[ProgressCallback] = None,
    cancel_event: Optional[threading.Event] = None,
) -> dict[str, Optional[bool]]:
    """Проверяет, могут ли обычные пользователи писать в каталоги."""
    unique: list[str] = []
    seen: set[str] = set()
    for directory in directories:
        if not directory:
            continue
        key = os.path.normcase(directory)
        if key not in seen and os.path.isdir(directory):
            seen.add(key)
            unique.append(directory)
    if not unique:
        return {}

    chunks = [unique[i : i + 25] for i in range(0, len(unique), 25)]
    results: dict[str, Optional[bool]] = {}
    completed = 0
    with ThreadPoolExecutor(max_workers=min(3, len(chunks))) as executor:
        futures = {executor.submit(_acl_chunk, chunk): chunk for chunk in chunks}
        for future in as_completed(futures):
            if cancel_event is not None and cancel_event.is_set():
                for pending in futures:
                    pending.cancel()
                break
            chunk = futures[future]
            try:
                results.update(future.result())
            except Exception as exc:
                log.warning("Ошибка ACL: %s", exc)
                for directory in chunk:
                    results[directory] = None
            completed += len(chunk)
            if progress:
                percent = 82 + int(12 * completed / max(1, len(unique)))
                progress(percent, f"Проверка прав на папки: {completed} из {len(unique)}")
    return results


# ---------------------------------------------------------------------------
# Поведение запущенных служб
# ---------------------------------------------------------------------------

def collect_live_data(
    pids: Iterable[int],
    cancel_event: Optional[threading.Event] = None,
    sample_seconds: float = 1.2,
) -> dict[int, LiveInfo]:
    """Снимает ЦП, память, родителя и сетевые соединения процессов служб."""
    pid_list = [int(pid) for pid in pids if pid and pid > 0]
    if not pid_list:
        return {}
    try:
        import psutil
    except Exception as exc:
        log.info("psutil недоступен, поведение не проверяется: %s", exc)
        return {}

    # Первый вызов cpu_percent() задаёт точку отсчёта.
    try:
        for process in psutil.process_iter():
            try:
                process.cpu_percent(None)
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue
    except Exception:
        pass

    deadline = time.monotonic() + sample_seconds
    while time.monotonic() < deadline:
        if cancel_event is not None and cancel_event.is_set():
            break
        time.sleep(0.1)

    results: dict[int, LiveInfo] = {}
    for pid in pid_list:
        live = LiveInfo(pid=pid)
        try:
            process = psutil.Process(pid)
            live.cpu_percent = round(process.cpu_percent(None), 1)
            live.memory_mb = round(process.memory_info().rss / (1024 * 1024), 1)
            live.parent_pid = process.ppid()
            try:
                parent = psutil.Process(live.parent_pid)
                live.parent_name = parent.name()
            except Exception:
                pass
            try:
                live.process_exe = process.exe()
            except Exception:
                pass
            try:
                connections = process.net_connections(kind="inet")
            except Exception as exc:
                connections = []
                live.error = f"Сетевые соединения недоступны: {exc}"
            for connection in connections:
                raddr = connection.raddr
                if not raddr or raddr.ip in ("0.0.0.0", "::", "127.0.0.1", "::1"):
                    continue
                if connection.status != psutil.CONN_ESTABLISHED:
                    continue
                live.connections.append(
                    {
                        "ip": raddr.ip,
                        "port": raddr.port,
                        "status": connection.status,
                    }
                )
                if len(live.connections) >= 20:
                    break
        except Exception as exc:
            live.error = str(exc)
        results[pid] = live
    return results


def get_file_properties(path: str) -> bool:
    """Открывает стандартное окно свойств файла."""
    try:
        result = ctypes.windll.shell32.ShellExecuteW(
            None, "properties", path, None, None, 1
        )
        return int(result) > 32
    except Exception:
        return False


def get_computer_caption() -> str:
    name = os.environ.get("COMPUTERNAME", "unknown")
    try:
        return f"{name} · {os.environ.get('OS', 'Windows')}"
    except Exception:
        return name
