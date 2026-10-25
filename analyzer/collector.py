"""Сбор информации о службах и запуск полного конвейера анализа."""

from __future__ import annotations

import logging
import os
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
from typing import Callable, Optional

from . import constants as C
from .models import (
    FileInfo,
    LiveInfo,
    ScanOptions,
    ScanResult,
    ServiceRecord,
    SignatureInfo,
)
from .rules import AnalysisContext, evaluate_all
from .winapi import (
    check_directories_writable,
    collect_live_data,
    enumerate_registry_services,
    expand_windows_path,
    get_file_info,
    get_service_states,
    get_signatures,
    is_admin,
    sha256_file,
    split_image_path,
)

log = logging.getLogger(__name__)

ProgressCallback = Callable[[int, str], None]


class ScanCancelled(Exception):
    """Сканирование остановлено пользователем."""


def _check_cancel(cancel_event: Optional[threading.Event]) -> None:
    if cancel_event is not None and cancel_event.is_set():
        raise ScanCancelled()


def _report(progress: Optional[ProgressCallback], percent: int, text: str) -> None:
    if progress is not None:
        progress(max(0, min(100, percent)), text)


def _account_label(account: str, is_driver: bool) -> str:
    low = (account or "").strip().lower()
    if not low:
        return "Система (ядро)" if is_driver else "Система (LocalSystem)"
    if low in ("localsystem", "nt authority\\system"):
        return "Система (LocalSystem)"
    if low in ("nt authority\\localservice", "localservice"):
        return "LocalService (ограниченные права)"
    if low in ("nt authority\\networkservice", "networkservice"):
        return "NetworkService (ограниченные права)"
    return account


def _service_type_label(service_type: int, is_driver: bool) -> str:
    if service_type in C.SERVICE_TYPE_LABELS:
        return C.SERVICE_TYPE_LABELS[service_type]
    if is_driver:
        return "Драйвер"
    if service_type & 0x20:
        return "Общий процесс"
    if service_type & 0x10:
        return "Собственный процесс"
    return "Служба"


def _state_label(code: int) -> str:
    return C.STATE_LABELS.get(code, "Неизвестно")


def build_records(
    entries: list[dict],
    states: dict[str, dict],
) -> tuple[list[ServiceRecord], list[str]]:
    records: list[ServiceRecord] = []
    errors: list[str] = []

    for entry in entries:
        try:
            image_path, image_args, image_quoted = split_image_path(
                entry.get("image_path", "")
            )
            service_dll_raw = entry.get("service_dll", "") or ""
            service_dll = expand_windows_path(service_dll_raw) if service_dll_raw else ""
            service_type = int(entry.get("service_type") or 0)
            is_driver = bool(entry.get("is_driver"))
            is_svchost = os.path.basename(image_path).lower() == "svchost.exe"
            is_shared = bool(service_type & 0x20) or is_svchost

            if service_dll and (is_shared or not image_path):
                effective_path = service_dll
            else:
                effective_path = image_path

            state = states.get(entry["name"], {})
            state_code = int(state.get("state") or 0)
            pid = int(state.get("pid") or 0) or None
            if is_shared:
                # PID общий для всех служб внутри svchost.exe, поэтому
                # поведение конкретной службы по нему не определить.
                pid = pid

            start_code = entry.get("start", 3)
            try:
                start_code = int(start_code)
            except (TypeError, ValueError):
                start_code = -1
            start_label = C.START_TYPE_LABELS.get(start_code, "Неизвестно")
            if entry.get("delayed") and start_code == 2:
                start_label = "Автоматически (отложенно)"

            record = ServiceRecord(
                name=entry["name"],
                display_name=entry.get("display_name") or entry["name"],
                description=entry.get("description") or "",
                kind="driver" if is_driver else "service",
                registry_key=entry.get("registry_key", ""),
                image_path_raw=entry.get("image_path", ""),
                image_path=image_path,
                image_args=image_args,
                image_quoted=image_quoted,
                service_dll_raw=service_dll_raw,
                service_dll=service_dll,
                effective_path=effective_path,
                is_shared_host=is_shared,
                host_exe=image_path if is_shared else "",
                service_type=service_type,
                service_type_label=_service_type_label(service_type, is_driver),
                state_code=state_code,
                state_label=_state_label(state_code),
                start_code=start_code,
                start_label=start_label,
                delayed_start=bool(entry.get("delayed")),
                account=entry.get("account") or "",
                account_label=_account_label(entry.get("account", ""), is_driver),
                dependencies=list(entry.get("dependencies") or []),
                pid=pid,
                file=FileInfo(path=effective_path or ""),
            )
            records.append(record)
        except Exception as exc:
            log.exception("Не удалось разобрать службу %s", entry.get("name"))
            errors.append(f"{entry.get('name', '?')}: {exc}")

    return records, errors


def _read_file_info(
    records: list[ServiceRecord],
    progress: Optional[ProgressCallback],
    cancel_event: Optional[threading.Event],
) -> None:
    total = len(records)
    for index, record in enumerate(records, 1):
        _check_cancel(cancel_event)
        record.file = get_file_info(record.effective_path) if record.effective_path else FileInfo()
        if index % 25 == 0 or index == total:
            percent = 8 + int(7 * index / max(1, total))
            _report(progress, percent, f"Чтение свойств файлов: {index} из {total}")


def _attach_signatures(
    records: list[ServiceRecord],
    progress: Optional[ProgressCallback],
    cancel_event: Optional[threading.Event],
) -> None:
    paths: list[str] = []
    for record in records:
        if record.effective_path:
            paths.append(record.effective_path)
        if record.host_exe and record.host_exe != record.effective_path:
            paths.append(record.host_exe)

    signatures = get_signatures(paths, progress=progress, cancel_event=cancel_event)
    _check_cancel(cancel_event)

    by_normalized = {
        os.path.normcase(path): info for path, info in signatures.items()
    }

    def lookup(path: str) -> SignatureInfo:
        if not path:
            return SignatureInfo(status="Missing", status_message="Файл не найден")
        return signatures.get(path) or by_normalized.get(
            os.path.normcase(path),
            SignatureInfo(status="Missing", status_message="Файл не найден"),
        )

    for record in records:
        record.signature = lookup(record.effective_path)
        if record.host_exe:
            record.host_signature = lookup(record.host_exe)


def _attach_live_data(
    records: list[ServiceRecord],
    progress: Optional[ProgressCallback],
    cancel_event: Optional[threading.Event],
) -> None:
    pids = {
        record.pid
        for record in records
        if record.pid and not record.is_shared_host and record.is_running
    }
    if not pids:
        return
    _report(progress, 76, "Анализ нагрузки ЦП и сетевых соединений…")
    live_map = collect_live_data(pids, cancel_event=cancel_event)
    _check_cancel(cancel_event)
    for record in records:
        if record.pid and not record.is_shared_host:
            record.live = live_map.get(record.pid, LiveInfo(pid=record.pid))


def _attach_permissions(
    records: list[ServiceRecord],
    progress: Optional[ProgressCallback],
    cancel_event: Optional[threading.Event],
) -> None:
    directories: list[str] = []
    for record in records:
        if not record.file.exists:
            continue
        if record.signature.is_valid and record.signature.is_microsoft:
            continue
        directory = os.path.dirname(record.effective_path)
        if directory:
            directories.append(directory)
    if not directories:
        return
    _report(progress, 82, "Проверка прав доступа к папкам…")
    acl = check_directories_writable(directories, progress=progress, cancel_event=cancel_event)
    _check_cancel(cancel_event)
    for record in records:
        if not record.file.exists:
            continue
        directory = os.path.dirname(record.effective_path)
        record.dir_writable_by_users = acl.get(directory)


def _compute_hashes(
    records: list[ServiceRecord],
    progress: Optional[ProgressCallback],
    cancel_event: Optional[threading.Event],
) -> None:
    targets = [
        record
        for record in records
        if record.file.exists
        and not record.sha256
        and (record.level != C.LEVEL_SAFE or not record.signature.is_microsoft)
    ]
    if not targets:
        return
    completed = 0
    total = len(targets)
    with ThreadPoolExecutor(max_workers=min(4, total)) as executor:
        futures = {
            executor.submit(sha256_file, record.effective_path): record
            for record in targets
        }
        for future in as_completed(futures):
            if cancel_event is not None and cancel_event.is_set():
                for pending in futures:
                    pending.cancel()
                break
            record = futures[future]
            try:
                record.sha256 = future.result()
            except Exception as exc:
                log.debug("Ошибка хэширования %s: %s", record.effective_path, exc)
            completed += 1
            if progress:
                percent = 96 + int(4 * completed / max(1, total))
                progress(percent, f"Вычисление хэшей: {completed} из {total}")


def collect_services(
    options: Optional[ScanOptions] = None,
    progress: Optional[ProgressCallback] = None,
    cancel_event: Optional[threading.Event] = None,
) -> ScanResult:
    """Полный проход: реестр → файлы → подписи → поведение → оценка."""
    options = options or ScanOptions()
    started_at = datetime.now()
    result = ScanResult(options=options, started_at=started_at, is_admin=is_admin())

    _report(progress, 1, "Чтение списка служб из реестра…")
    entries = enumerate_registry_services(include_drivers=options.include_drivers)
    _check_cancel(cancel_event)
    if not entries:
        result.errors.append(
            "Не удалось прочитать список служб. Запустите программу от имени администратора."
        )
        result.finished_at = datetime.now()
        return result

    _report(progress, 4, f"Найдено записей: {len(entries)}. Чтение состояний…")
    states = get_service_states(include_drivers=options.include_drivers)
    _check_cancel(cancel_event)

    records, build_errors = build_records(entries, states)
    result.errors.extend(build_errors)
    result.records = records

    _report(progress, 8, f"Служб и драйверов: {len(records)}. Чтение свойств файлов…")
    _read_file_info(records, progress, cancel_event)

    _report(progress, 15, "Проверка цифровых подписей…")
    _attach_signatures(records, progress, cancel_event)

    if options.live_metrics:
        _attach_live_data(records, progress, cancel_event)

    if options.deep_acl:
        _attach_permissions(records, progress, cancel_event)

    _report(progress, 94, "Оценка риска и объяснения…")
    context = AnalysisContext(is_admin=result.is_admin)
    evaluate_all(records, context)
    _check_cancel(cancel_event)

    if not options.deep_acl:
        # Быстрый режим: отмечаем, что права не проверялись.
        for record in records:
            record.dir_writable_by_users = None

    _report(progress, 96, "Вычисление хэшей файлов…")
    _compute_hashes(records, progress, cancel_event)

    result.finished_at = datetime.now()
    result.duration_seconds = (result.finished_at - result.started_at).total_seconds()
    result.signature_engine = "PowerShell Authenticode"
    _report(progress, 100, "Готово")
    log.info(
        "Сканирование завершено: %s записей за %.1f с",
        len(records),
        result.duration_seconds,
    )
    return result
