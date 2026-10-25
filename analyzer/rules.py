"""Правила оценки риска и объяснения к ним.

Каждое найденное правило возвращает Finding с понятным описанием и советом.
Итоговый уровень — это сумма весов, а не «магическое» решение: пользователь
всегда видит, из чего сложилась оценка.
"""

from __future__ import annotations

import os
import re
from dataclasses import dataclass
from datetime import datetime

from . import constants as C
from .models import ServiceRecord
from .winapi import SYSTEM_DRIVE, SYSTEM_ROOT, get_drive_type


@dataclass
class AnalysisContext:
    system_root: str = SYSTEM_ROOT
    system_drive: str = SYSTEM_DRIVE
    is_admin: bool = False


# ---------------------------------------------------------------------------
# Вспомогательные функции
# ---------------------------------------------------------------------------

def _normalize_path(path: str) -> str:
    if not path:
        return ""
    try:
        return os.path.normcase(os.path.abspath(path)).lower()
    except Exception:
        return path.lower()


def _is_under(path: str, root: str) -> bool:
    norm_path = _normalize_path(path)
    norm_root = _normalize_path(root).rstrip("\\")
    return bool(norm_root) and (
        norm_path == norm_root or norm_path.startswith(norm_root + "\\")
    )


def _is_privileged_account(account: str) -> bool:
    low = (account or "").strip().lower()
    if not low:
        return True  # драйверы и службы по умолчанию работают от системы
    markers = (
        "localsystem",
        "nt authority\\system",
        "localservice",
        "networkservice",
        "nt authority\\local service",
        "nt authority\\network service",
        "administrator",
    )
    return any(marker in low for marker in markers)


def _is_system_account(account: str) -> bool:
    low = (account or "").strip().lower()
    if not low:
        return True
    return any(
        marker in low
        for marker in (
            "localsystem",
            "nt authority\\system",
            "localservice",
            "networkservice",
            "nt authority\\local service",
            "nt authority\\network service",
        )
    )


def _levenshtein(first: str, second: str) -> int:
    if first == second:
        return 0
    if len(first) < len(second):
        first, second = second, first
    previous = list(range(len(second) + 1))
    for i, char_first in enumerate(first, 1):
        current = [i]
        for j, char_second in enumerate(second, 1):
            insert = current[j - 1] + 1
            delete = previous[j] + 1
            replace = previous[j - 1] + (char_first != char_second)
            current.append(min(insert, delete, replace))
        previous = current
    return previous[-1]


def _signer_text(record: ServiceRecord) -> str:
    sig = record.signature
    return f"{sig.signer_org} {sig.signer_cn} {sig.subject}".lower()


def _is_microsoft(record: ServiceRecord) -> bool:
    return record.signature.is_valid and record.signature.is_microsoft


def _is_valid(record: ServiceRecord) -> bool:
    return record.signature.status == "Valid"


def _path_category(path: str) -> tuple[str, str, int]:
    """Возвращает (категория, описание, вес)."""
    norm = _normalize_path(path)
    if not norm:
        return "none", "", 0
    if norm.startswith("\\\\"):
        return "network", "сетевой путь (UNC)", 32

    if "\\windows\\temp\\" in norm:
        return "temp", "временная папка Windows", 44

    marker_categories = {
        "\\appdata\\": ("appdata", "папка AppData в профиле пользователя", 42),
        "\\temp\\": ("temp", "временная папка", 44),
        "\\tmp\\": ("tmp", "временная папка", 44),
        "\\downloads\\": ("downloads", "папка загрузок", 42),
        "\\desktop\\": ("desktop", "рабочий стол", 40),
        "\\documents\\": ("documents", "папка документов", 38),
        "\\users\\public\\": ("public", "общая папка пользователей", 40),
        "\\$recycle.bin\\": ("recycle", "корзина", 45),
    }
    for marker, value in marker_categories.items():
        if marker in norm:
            return value

    if "\\programdata\\" in norm:
        return "programdata", "папка ProgramData", 20

    if "\\users\\" in norm:
        return "userprofile", "профиль пользователя", 30

    for marker in C.SYSTEM_PATH_MARKERS:
        if marker in norm:
            return "system", "системный каталог Windows", 0

    for marker in C.PROGRAM_FILES_MARKERS:
        if marker in norm:
            return "program_files", "каталог Program Files", 0

    norm_root = _normalize_path(SYSTEM_ROOT).rstrip("\\")
    if norm.startswith(norm_root + "\\"):
        return "system_other", "каталог Windows", 0

    drive, _ = os.path.splitdrive(path)
    if drive and drive.lower() != SYSTEM_DRIVE.rstrip("\\").lower():
        return "other_drive", "не системный диск", 8

    return "other", "нестандартный каталог", 5


def _companies_match(signer: str, company: str) -> bool:
    """Сравнивает издателя подписи и CompanyName без ложных срабатываний."""
    if not signer or not company:
        return True
    ignored = {
        "inc", "llc", "ltd", "corp", "corporation", "gmbh", "co", "company",
        "limited", "sa", "ag", "bv", "plc", "oy", "ab", "the", "and",
        "technologies", "technology", "software", "systems", "system",
        "solutions", "group", "holding", "international", "ooo", "ооо",
    }

    def tokens(value: str) -> set[str]:
        parts = re.split(r"[^a-zа-я0-9]+", value.lower())
        return {part for part in parts if len(part) > 1 and part not in ignored}

    first = tokens(signer)
    second = tokens(company)
    if not first or not second:
        return True
    if first & second:
        return True
    return any(one in other for one in first for other in second if len(one) >= 4)


def _recent_days(value) -> float | None:
    if not value:
        return None
    try:
        delta = datetime.now() - value
        return delta.total_seconds() / 86400
    except Exception:
        return None


# ---------------------------------------------------------------------------
# Основная оценка
# ---------------------------------------------------------------------------

def evaluate_record(record: ServiceRecord, context: AnalysisContext) -> ServiceRecord:
    """Добавляет причины, положительные факторы и итоговый уровень."""
    record.findings.clear()
    record.positives.clear()

    _evaluate_signature(record)
    _evaluate_path(record)
    _evaluate_service_config(record)
    _evaluate_file(record)
    _evaluate_miner(record)
    _evaluate_live_behavior(record)
    _evaluate_permissions(record)

    if record.file.access_denied:
        record.add_finding(
            "file_access_denied",
            "info",
            "Нет доступа к файлу службы",
            "Windows не разрешила прочитать файл"
            + (f": {record.file.error}" if record.file.error else ".")
            + " Обычно это защищённый системный файл; запустите программу от "
            "имени администратора, чтобы проверить его полностью.",
            "Запустите анализатор от имени администратора.",
            0,
        )
    elif record.file.exists is False:
        record.add_finding(
            "file_missing",
            "high",
            "Файл службы не найден",
            f"По пути «{record.path_for_display or '—'}» нет файла. "
            "Служба может быть остатком удалённой программы, либо файл скрыт "
            "или недоступен для чтения.",
            "Проверьте конфигурацию службы (sc.exe qc <имя>). Если программа "
            "удалена, службу можно удалить; если файл должен быть — восстановите "
            "её из доверенного источника.",
            45,
        )

    score = sum(finding.weight for finding in record.findings if finding.weight > 0)
    record.score = max(0, min(100, score))
    critical = any(finding.severity == "critical" for finding in record.findings)
    if critical or record.score >= 55:
        record.level = C.LEVEL_DANGER
    elif record.score >= 30:
        record.level = C.LEVEL_SUSPICIOUS
    elif record.score >= 12:
        record.level = C.LEVEL_CHECK
    else:
        record.level = C.LEVEL_SAFE

    if record.level == C.LEVEL_SAFE and not record.positives:
        record.add_positive("Проверки не выявили подозрительных признаков")
    if record.level == C.LEVEL_SAFE and not any(f.severity == "info" for f in record.findings):
        record.add_positive("Подпись, расположение и настройки службы выглядят ожидаемо")

    record.evaluated_at = datetime.now()
    return record


def _evaluate_signature(record: ServiceRecord) -> None:
    sig = record.signature
    if record.file.access_denied:
        return
    if not record.file.exists:
        return

    if sig.status == "Valid":
        record.add_positive("Цифровая подпись действительна")
        if sig.is_microsoft:
            record.add_positive("Подписано Microsoft")
        elif sig.is_hardware_compat:
            record.add_positive("Подписано через WHQL (совместимость с Windows)")
        elif sig.signer_org:
            record.add_positive(f"Подписано: {sig.signer_org}")
        elif sig.signer_cn:
            record.add_positive(f"Подписано: {sig.signer_cn}")

        if sig.signer_org and C.is_known_publisher(sig.signer_org):
            record.add_positive(f"Известный издатель: {sig.signer_org}")
        if sig.os_binary:
            record.add_positive("Компонент операционной системы Windows")
        return

    if sig.status == "NotSigned":
        record.add_finding(
            "not_signed",
            "medium",
            "Файл не подписан цифровой подписью",
            "У файла нет действительной подписи Authenticode. Это обычная "
            "ситуация для небольших программ и самодельных сборок, но также "
            "типично для вредоносных программ, которые не хотят раскрывать издателя.",
            "Само по себе не приговор. Проверьте издателя в свойствах файла, "
            "дату создания и хэш в VirusTotal.",
            16,
        )
        return

    if sig.status == "HashMismatch":
        record.add_finding(
            "hash_mismatch",
            "critical",
            "Подпись не совпадает с файлом",
            "Файл был изменён после подписи. Так выглядит подмена подписанного "
            "файла вредоносным кодом. Это очень сильный признак заражения.",
            "Не запускайте файл. Проверьте его в VirusTotal и запустите полную "
            "проверку антивирусом. При возможности восстановите файл из резервной "
            "копии или переустановите программу.",
            65,
        )
        return

    if sig.status == "NotTrusted":
        record.add_finding(
            "not_trusted",
            "critical",
            "Подпись не является доверенной",
            "Сертификат подписи не входит в доверенные корневые центры, отозван "
            "или выпущен неизвестным центром. Подлинность издателя не подтверждена.",
            "Проверьте файл в VirusTotal. Если программа вам неизвестна, не "
            "запускайте службу.",
            52,
        )
        return

    if sig.status in ("Error", "UnknownError", "Unknown", "Cancelled"):
        record.add_finding(
            "signature_error",
            "medium",
            "Не удалось проверить цифровую подпись",
            "Проверка Authenticode завершилась ошибкой"
            + (f": {sig.error or sig.status_message}" if (sig.error or sig.status_message) else ".")
            + " Возможно, файл повреждён, занят другим процессом или проверка "
            "была отменена.",
            "Повторите сканирование. Если ошибка сохраняется, проверьте файл "
            "антивирусом и в VirusTotal.",
            16,
        )
        return

    if sig.status == "Missing":
        return  # отдельное правило про отсутствующий файл

    record.add_finding(
        "signature_other",
        "low",
        "Нестандартный результат проверки подписи",
        f"Authenticode вернул статус «{sig.status}»"
        + (f": {sig.status_message}" if sig.status_message else "."),
        "Проверьте файл в VirusTotal, если служба вам незнакома.",
        8,
    )


def _evaluate_path(record: ServiceRecord) -> None:
    path = record.effective_path or record.image_path
    if not path:
        record.add_finding(
            "no_path",
            "medium",
            "Не удалось определить путь к файлу",
            "В конфигурации службы нет корректного ImagePath, либо путь не "
            "разобрался. Проверить файл невозможно.",
            "Откройте реестр по ключу службы и проверьте параметр ImagePath.",
            22,
        )
        return

    category, label, weight = _path_category(path)
    microsoft = _is_microsoft(record)
    valid = _is_valid(record)
    norm = _normalize_path(path)

    if category == "system":
        record.add_positive("Файл находится в системном каталоге Windows")
        if not microsoft and not record.signature.is_hardware_compat:
            # Сторонние подписанные драйверы в System32\drivers и DriverStore —
            # обычное дело: так устанавливаются драйверы оборудования.
            driver_component = (
                record.kind == "driver"
                and valid
                and ("\\drivers\\" in norm or "\\driverstore\\" in norm)
            )
            if driver_component:
                record.add_positive(
                    "Драйвер подписан сторонним издателем и установлен "
                    "в системный каталог драйверов"
                )
                return
            # Сторонние подписанные файлы в System32 встречаются, но реже.
            severity = "medium" if valid else "high"
            record.add_finding(
                "system_dir_third_party",
                severity,
                "Файл находится в System32, но подписан не Microsoft",
                "Системный каталог предназначен для компонентов Windows. "
                "Сторонние файлы здесь встречаются у драйверов и некоторых "
                "антивирусов, но не являются нормой для обычных служб.",
                "Убедитесь, что программа вам знакома. Проверьте подпись и хэш "
                "в VirusTotal.",
                22 if valid else 30,
            )
        return

    if category == "program_files":
        record.add_positive("Файл находится в стандартном каталоге Program Files")
        return

    if category == "programdata":
        if microsoft and "\\programdata\\microsoft\\" in norm:
            record.add_positive("Ожидаемое расположение компонентов Microsoft")
            return
        record.add_finding(
            "programdata",
            "medium" if not microsoft else "low",
            "Файл службы находится в ProgramData",
            "ProgramData используют легальные программы для общих данных и "
            "обновлений, но также вредоносные программы: каталог доступен для "
            "записи шире, чем Program Files.",
            "Проверьте, устанавливали ли вы эту программу. При сомнениях "
            "посмотрите хэш в VirusTotal.",
            20 if not microsoft else 6,
        )
        return

    if category == "system_other":
        if microsoft:
            record.add_positive("Файл находится в каталоге Windows")
        else:
            record.add_finding(
                "windows_dir_third_party",
                "medium",
                "Сторонний файл в каталоге Windows",
                f"Файл расположен вне System32/Program Files: {label}. "
                "В каталоге Windows обычно находятся только компоненты системы.",
                "Проверьте издателя и программу, которой принадлежит служба.",
                16,
            )
        return

    if category == "userprofile":
        record.add_finding(
            "user_profile",
            "medium" if microsoft else "high",
            "Файл службы находится в профиле пользователя",
            "Службы обычно устанавливаются в Program Files или System32. "
            "Запуск из профиля пользователя характерен для программ, "
            "установленных без администратора, и для вредоносного кода.",
            "Проверьте, что это за программа. При сомнениях проверьте файл "
            "в VirusTotal.",
            15 if microsoft else 32,
        )
        return

    if category in ("appdata", "temp", "tmp", "downloads", "desktop", "documents", "public", "recycle"):
        record.add_finding(
            "user_writable_path",
            "high" if not microsoft else "medium",
            f"Файл службы находится в папке «{label}»",
            "Такие папки доступны для записи обычному пользователю и часто "
            "используются майнерами и другим вредоносным кодом. Легальные службы "
            "здесь встречаются, но это нетипично.",
            "Проверьте файл в VirusTotal. Если служба вам неизвестна, отключите "
            "её и проверьте систему антивирусом.",
            22 if microsoft else max(weight, 38),
        )
        return

    if category == "network":
        record.add_finding(
            "network_path",
            "high",
            "Служба запускается с сетевого пути",
            "Запуск исполняемого файла по сети позволяет злоумышленнику "
            "подменить его и усложняет проверку подлинности.",
            "Для обычных служб это нетипично. Проверьте источник и отключите "
            "службу, если не используете её.",
            32,
        )
        return

    drive_type = get_drive_type(path)
    if drive_type == 2:
        record.add_finding(
            "removable_path",
            "high",
            "Служба запускается со съёмного носителя",
            "Файл находится на съёмном диске. Это нетипично для службы и "
            "позволяет подменить программу.",
            "Проверьте носитель и отключите службу, если она вам неизвестна.",
            32,
        )
        return

    if category == "other_drive":
        record.add_finding(
            "other_drive",
            "low" if not microsoft else "info",
            "Файл службы находится не на системном диске",
            "Это не обязательно опасно: некоторые программы устанавливаются "
            "на другой диск. Но такие службы сложнее контролировать.",
            "Убедитесь, что программа вам знакома.",
            8 if not microsoft else 0,
        )
        return

    if not microsoft:
        record.add_finding(
            "nonstandard_path",
            "info",
            "Нестандартное расположение файла",
            f"Файл находится в каталоге «{label}», который не является системным "
            "или Program Files. Само по себе это не опасно.",
            "Проверьте, что программа вам знакома.",
            3,
        )


def _evaluate_service_config(record: ServiceRecord) -> None:
    base_name = os.path.basename(record.image_path or record.effective_path).lower()
    stem = os.path.splitext(base_name)[0]
    low_name = record.name.lower()
    microsoft = _is_microsoft(record)
    account = (record.account or "").strip()
    norm_image = _normalize_path(record.image_path)
    host_base = os.path.basename(record.image_path).lower() if record.image_path else ""

    if record.image_path:
        if host_base == "svchost.exe" and "\\windows\\system32\\svchost.exe" not in norm_image:
            record.add_finding(
                "svchost_outside_system",
                "critical",
                "svchost.exe запущен не из System32",
                f"Хост-процесс службы: «{record.image_path}». Настоящий svchost.exe "
                "всегда находится в C:\\Windows\\System32.",
                "Это сильный признак подмены системного процесса. Не запускайте "
                "службу, проверьте файл антивирусом и в VirusTotal.",
                55,
            )
        elif record.is_shared_host and host_base and host_base != "svchost.exe":
            # Общие службы вроде SamSs/EFS живут внутри lsass.exe, это норма.
            record.add_positive(
                f"Служба работает внутри системного процесса {host_base}"
            )

        if record.service_dll and not record.service_dll.lower().endswith(".dll"):
            record.add_finding(
                "service_dll_wrong_ext",
                "high",
                "ServiceDll не является DLL-файлом",
                f"В параметрах службы указан файл «{record.service_dll}». "
                "Для библиотеки службы ожидается расширение .dll.",
                "Проверьте параметр ServiceDll в реестре и файл в VirusTotal.",
                30,
            )

        if host_base in ("svchost.exe", "lsass.exe") and not record.service_dll:
            record.add_finding(
                "service_dll_unknown",
                "info",
                "Отдельная библиотека службы не указана",
                f"Служба работает внутри {host_base}, но параметр ServiceDll "
                "отсутствует или недоступен. Windows загружает такие службы "
                "по-другому, поэтому проверить конкретный файл реализации "
                "не получилось — проверен только сам хост-процесс.",
                "Запустите программу от имени администратора, чтобы прочитать "
                "параметр ServiceDll в реестре.",
                0,
            )

    lolbin_exempt = base_name == "msiexec.exe" and low_name == "msiserver"
    if base_name in C.LOLBINS and not lolbin_exempt:
        record.add_finding(
            "lolbin",
            "critical",
            "Служба запускает системную утилиту или скриптовый движок",
            f"Образ службы — «{base_name}». Такие утилиты (PowerShell, cmd, "
            "rundll32, mshta и т.п.) штатно не используются как службы, зато "
            "часто применяются для скрытого запуска кода.",
            "Срочно проверьте аргументы запуска и файл. Если вы не настраивали "
            "это сознательно — отключите службу и проверьте систему.",
            48,
        )

    if record.image_path:
        extension = os.path.splitext(record.image_path)[1].lower()
        if extension in C.SCRIPT_EXTENSIONS:
            record.add_finding(
                "script_as_service",
                "critical",
                "Служба запускает скрипт вместо программы",
                f"Образ службы имеет расширение «{extension}». Службы Windows "
                "должны запускать исполняемый файл, а скрипты используют для "
                "обхода защиты и автозапуска.",
                "Не запускайте службу. Проверьте содержимое скрипта и файл "
                "антивирусом.",
                50,
            )

    if re.search(C.DOUBLE_EXTENSION_RE, base_name, re.IGNORECASE):
        record.add_finding(
            "double_extension",
            "medium",
            "Двойное расширение файла",
            f"Имя «{base_name}» содержит два расширения. Так маскируют "
            "исполняемые файлы под документы или изображения.",
            "Проверьте файл в VirusTotal и не открывайте его вручную.",
            26,
        )

    if stem and not microsoft and not _is_system_account(account):
        record.add_finding(
            "user_account",
            "medium",
            "Служба работает под пользовательской учётной записью",
            f"Учётная запись службы: «{account}». Это бывает нужно для "
            "изоляции программы, но также позволяет вредоносному коду работать "
            "без прав системы и оставаться незаметным.",
            "Убедитесь, что учётная запись и программа вам знакомы.",
            12,
        )

    display_low = (record.display_name or "").lower()
    if low_name in C.KNOWN_WINDOWS_SERVICES and not microsoft:
        record.add_finding(
            "windows_service_name",
            "high",
            "Имя совпадает с системной службой Windows",
            f"Служба называется «{record.name}», как настоящая служба Windows, "
            "но её файл подписан не Microsoft.",
            "Проверьте файл и издателя. Такое совпадение часто используют для "
            "маскировки.",
            30,
        )
    if not microsoft and any(hint in display_low for hint in C.DISPLAY_IMPERSONATION_HINTS):
        record.add_finding(
            "display_impersonation",
            "high",
            "Название службы маскируется под компонент Microsoft",
            f"Отображаемое имя «{record.display_name}» похоже на системное, "
            "но подпись файла принадлежит другому издателю.",
            "Проверьте файл в VirusTotal. Если служба не от Microsoft, её имя "
            "вводит в заблуждение.",
            28,
        )

    if (
        record.image_path
        and record.kind != "driver"
        and record.file.exists
        and not record.image_quoted
        and " " in record.image_path
        and _is_privileged_account(account)
        and not record.is_shared_host
    ):
        record.add_finding(
            "unquoted_path",
            "medium",
            "Незакавыченный путь к программе",
            "Путь содержит пробелы и не заключён в кавычки. Windows может "
            "попытаться запустить программу из другой папки — это известная "
            "уязвимость повышения прав.",
            "Заключите путь в кавычки в параметре ImagePath службы.",
            18,
        )

    # Похожее на системное имя файла (svch0st.exe, scvhost.exe и т.п.)
    if stem and not microsoft:
        for system_name in C.SYSTEM_BINARY_NAMES:
            if stem == system_name:
                break
            if _levenshtein(stem, system_name) <= 2:
                record.add_finding(
                    "system_name_lookalike",
                    "high",
                    "Имя файла похоже на системное",
                    f"Файл «{base_name}» отличается от системного "
                    f"«{system_name}.exe» на 1–2 символа. Так вредоносные "
                    "программы маскируются под компоненты Windows.",
                    "Проверьте файл в VirusTotal и сравните с настоящим файлом "
                    "в C:\\Windows\\System32.",
                    28,
                )
                break

    if record.kind == "driver" and record.start_code in (0, 1):
        record.add_positive("Драйвер загружается вместе с системой")

    if not record.description and not microsoft and record.kind == "service":
        record.add_finding(
            "no_description",
            "low",
            "У службы нет описания",
            "Описание помогает понять назначение службы. Его отсутствие "
            "встречается и у легальных программ, но затрудняет проверку.",
            "Посмотрите папку и издателя файла — это подскажет назначение.",
            4,
        )


def _evaluate_file(record: ServiceRecord) -> None:
    file = record.file
    if not file.exists or file.access_denied:
        return

    if file.size == 0:
        record.add_finding(
            "empty_file",
            "high",
            "Файл службы имеет нулевой размер",
            "Пустой файл не может быть рабочей программой. Возможно, файл "
            "повреждён, заблокирован или подменён.",
            "Проверьте файл и восстановите его из доверенного источника.",
            30,
        )

    if not file.version and not _is_valid(record):
        record.add_finding(
            "no_version_info",
            "low",
            "В файле нет сведений о версии и издателе",
            "У файла нет ресурса версии. Так бывает у вредоносных программ "
            "и у небольших самодельных утилит.",
            "Проверьте хэш файла в VirusTotal.",
            8,
        )

    sig = record.signature
    if (
        sig.status == "Valid"
        and sig.signer_org
        and file.company
        and not sig.is_microsoft
        and not sig.is_hardware_compat
    ):
        if not _companies_match(sig.signer_org, file.company):
            record.add_finding(
                "company_mismatch",
                "low",
                "Компания в файле отличается от издателя подписи",
                f"Подпись выдана «{sig.signer_org}», а в свойствах файла "
                f"указана компания «{file.company}». У крупных компаний подпись "
                "часто оформлена на юридическое лицо (например, OU Privacy "
                "Technologies), поэтому расхождение само по себе не опасно.",
                "Проверьте издателя и программу. Если служба вам незнакома, "
                "проверьте файл в VirusTotal.",
                6,
            )

    days = _recent_days(file.created)
    if days is not None and days <= 7:
        if not _is_valid(record):
            record.add_finding(
                "recent_file",
                "medium",
                "Файл создан совсем недавно",
                f"Файл появился {int(days)} дн. назад и при этом не подписан. "
                "Это может быть свежая установка, а может — недавно "
                "подброшенный вредоносный файл.",
                "Сверьте дату с моментом установки программ. При сомнениях "
                "проверьте файл в VirusTotal.",
                15,
            )
        elif not _is_microsoft(record):
            record.add_finding(
                "recent_file_signed",
                "low",
                "Файл создан недавно",
                f"Файл появился {int(days)} дн. назад. Обычно это результат "
                "недавнего обновления программы.",
                "Если вы не обновляли программу, проверьте её издателя.",
                6,
            )


def _evaluate_miner(record: ServiceRecord) -> None:
    base = os.path.basename(record.effective_path or record.image_path).lower()
    dll_base = os.path.basename(record.service_dll).lower()
    name_text = f"{record.name} {record.display_name} {record.description}".lower()
    args = record.image_args or ""
    args_low = args.lower()

    matched_name = ""
    for hint in C.MINER_NAME_HINTS:
        if hint in base or hint in dll_base or hint in name_text:
            matched_name = hint
            break

    matched_arg = ""
    match = re.search(C.MINER_ARG_RE, args_low, re.IGNORECASE)
    if match:
        matched_arg = match.group(0)

    pool_match = re.search(C.POOL_HINT_RE, args_low, re.IGNORECASE)
    wallet_match = re.search(C.MONERO_WALLET_RE, args)

    if pool_match:
        record.add_finding(
            "mining_pool_arg",
            "critical",
            "В командной строке службы найден адрес майнинг-пула",
            f"Аргументы запуска содержат «{pool_match.group(0)}». Это прямой "
            "признак скрытого майнинга криптовалюты.",
            "Не запускайте службу. Проверьте файл в VirusTotal, запустите "
            "полную проверку антивирусом и удалите программу.",
            70,
        )
    elif matched_arg:
        record.add_finding(
            "miner_arg",
            "critical",
            "В аргументах службы найдены параметры майнера",
            f"Аргументы запуска содержат «{matched_arg}». Такие параметры "
            "используют программы для майнинга криптовалют.",
            "Не запускайте службу. Проверьте файл в VirusTotal и удалите "
            "программу после проверки антивирусом.",
            58,
        )

    if wallet_match:
        record.add_finding(
            "miner_wallet",
            "critical",
            "В командной строке найден адрес криптокошелька",
            "Аргументы службы содержат строку, похожую на адрес криптовалютного "
            "кошелька. Это характерно для майнеров.",
            "Не запускайте службу. Проверьте систему антивирусом.",
            58,
        )

    if matched_name:
        record.add_finding(
            "miner_name",
            "critical",
            "Имя или описание службы указывает на майнер",
            f"Найден признак «{matched_name}» в имени файла, службы или описании. "
            "Это может быть легальный инструмент для майнинга, но в составе "
            "скрытой службы почти всегда означает майнер.",
            "Проверьте файл в VirusTotal. Если вы не устанавливали программу "
            "для майнинга, удалите её.",
            52,
        )

    if record.live.connections:
        for connection in record.live.connections:
            if connection.get("port") in C.MINING_PORTS:
                record.add_finding(
                    "mining_port",
                    "critical",
                    "Служба подключена к порту, типичному для майнинг-пула",
                    f"Установлено соединение с {connection.get('ip')}:"
                    f"{connection.get('port')}. Этот порт часто используют "
                    "пулы для майнинга.",
                    "Проверьте службу и сетевую активность. Отключите её, если "
                    "не можете объяснить соединение.",
                    60,
                )
                break


def _evaluate_live_behavior(record: ServiceRecord) -> None:
    live = record.live
    if not live.pid or record.is_shared_host:
        return

    microsoft = _is_microsoft(record)

    if live.cpu_percent is not None and live.cpu_percent >= 70:
        if microsoft:
            record.add_finding(
                "high_cpu_microsoft",
                "info",
                f"Высокая нагрузка ЦП: {live.cpu_percent:.0f}%",
                "Файл подписан Microsoft, поэтому высокая нагрузка скорее "
                "связана с обновлением, антивирусной проверкой или индексацией.",
                "Если нагрузка не спадает, проверьте систему антивирусом.",
                0,
            )
        else:
            weight = 30 if live.cpu_percent >= 85 else 19
            record.add_finding(
                "high_cpu",
                "high" if weight >= 30 else "medium",
                f"Служба постоянно нагружает процессор: {live.cpu_percent:.0f}%",
                "Майнеры часто маскируются под службы и круглосуточно "
                "используют процессор. Легальные службы тоже иногда нагружают "
                "ЦП, но обычно короткими всплесками.",
                "Проверьте, какую программу обслуживает служба. Сравните "
                "нагрузку с моментом, когда она появилась, и проверьте файл "
                "в VirusTotal.",
                weight,
            )

    if live.parent_name and live.parent_name.lower() != "services.exe":
        record.add_finding(
            "unexpected_parent",
            "low",
            "Процесс службы запущен не от services.exe",
            f"Родительский процесс: «{live.parent_name}» (PID {live.parent_pid}). "
            "Обычно службы запускает диспетчер служб services.exe. Другое "
            "происхождение бывает при ручном запуске или перехвате.",
            "Проверьте, не запускалась ли программа вручную. При сомнениях "
            "перезагрузите компьютер и проверьте родителя снова.",
            10,
        )

    if live.process_exe and record.effective_path:
        try:
            same = os.path.samefile(live.process_exe, record.effective_path)
        except OSError:
            same = os.path.normcase(os.path.abspath(live.process_exe)) == os.path.normcase(
                os.path.abspath(record.effective_path)
            )
        if not same:
            record.add_finding(
                "process_path_mismatch",
                "high",
                "Запущенный процесс не совпадает с файлом в конфигурации",
                f"Служба настроена на «{record.effective_path}», а процесс "
                f"запущен из «{live.process_exe}». Это может означать подмену "
                "файла или что служба ещё не перезапускалась после обновления.",
                "Перезапустите службу и повторите проверку. Если путь снова "
                "отличается — проверьте файл антивирусом.",
                24,
            )


def _evaluate_permissions(record: ServiceRecord) -> None:
    if record.dir_writable_by_users is not True:
        return
    privileged = _is_privileged_account(record.account) or record.is_shared_host
    record.add_finding(
        "writable_directory",
        "high" if privileged else "medium",
        "Папка с файлом службы доступна для записи обычным пользователям",
        "Пользователь без прав администратора может заменить файл службы. "
        "Если служба работает от SYSTEM, это позволяет повысить права или "
        "выполнить вредоносный код.",
        "Ограничьте права на папку: запись должна быть только у "
        "администраторов и SYSTEM. После исправления повторите проверку.",
        32 if privileged else 16,
    )


def apply_virustotal_result(record: ServiceRecord, result: dict) -> None:
    """Добавляет результат VirusTotal в объяснение и пересчитывает уровень."""
    record.vt_result = result
    record.findings = [
        finding
        for finding in record.findings
        if not finding.code.startswith("vt_")
    ]
    if not result:
        return
    if not result.get("found"):
        record.add_finding(
            "vt_not_found",
            "info",
            "VirusTotal не знает этот файл",
            "Хэш отсутствует в базе VirusTotal. Это не значит, что файл "
            "безопасен: он может быть новым или уникальным.",
            "Загрузите файл на VirusTotal вручную, если он вызывает сомнения.",
            0,
        )
    elif result.get("malicious", 0) > 0 or result.get("suspicious", 0) > 0:
        malicious = int(result.get("malicious", 0))
        suspicious = int(result.get("suspicious", 0))
        record.add_finding(
            "vt_detections",
            "critical" if malicious >= 2 else "high",
            f"VirusTotal: обнаружений {malicious + suspicious}",
            f"Антивирусы VirusTotal: вредоносных — {malicious}, подозрительных — "
            f"{suspicious} из {result.get('total', '?')}. Один-два детекта могут "
            "быть ложным срабатыванием, но несколько — серьёзный сигнал.",
            "Не запускайте файл. Проверьте отчёт VirusTotal по ссылке и "
            "запустите полную проверку антивирусом.",
            80 if malicious >= 2 else 45,
        )
    else:
        record.add_positive(
            f"VirusTotal: {result.get('total', '?')} антивирусов не нашли угроз"
        )

    record.score = max(0, min(100, sum(f.weight for f in record.findings if f.weight > 0)))
    if any(f.severity == "critical" for f in record.findings) or record.score >= 55:
        record.level = C.LEVEL_DANGER
    elif record.score >= 30:
        record.level = C.LEVEL_SUSPICIOUS
    elif record.score >= 12:
        record.level = C.LEVEL_CHECK
    else:
        record.level = C.LEVEL_SAFE


def evaluate_all(records: list[ServiceRecord], context: AnalysisContext) -> None:
    for record in records:
        evaluate_record(record, context)
