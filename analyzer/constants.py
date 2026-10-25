"""Справочные данные и константы анализатора служб Windows.

Здесь собраны списки признаков, которые используются правилами оценки риска.
Все списки намеренно консервативны: цель — не «поймать всё», а дать понятные
причины для проверки, не заваливая пользователя ложными срабатываниями.
"""

from __future__ import annotations

APP_NAME = "Анализатор служб Windows"
APP_VERSION = "2.0"

# ---------------------------------------------------------------------------
# Уровни риска
# ---------------------------------------------------------------------------

LEVEL_SAFE = "safe"
LEVEL_CHECK = "check"
LEVEL_SUSPICIOUS = "suspicious"
LEVEL_DANGER = "danger"

LEVEL_ORDER = {
    LEVEL_DANGER: 3,
    LEVEL_SUSPICIOUS: 2,
    LEVEL_CHECK: 1,
    LEVEL_SAFE: 0,
}

LEVEL_LABELS = {
    LEVEL_DANGER: "Опасно",
    LEVEL_SUSPICIOUS: "Подозрительно",
    LEVEL_CHECK: "Проверить",
    LEVEL_SAFE: "Безопасно",
}

LEVEL_ICONS = {
    LEVEL_DANGER: "⛔",
    LEVEL_SUSPICIOUS: "▲",
    LEVEL_CHECK: "?",
    LEVEL_SAFE: "✔",
}

# Фон строк таблицы и цвет текста
LEVEL_COLORS = {
    LEVEL_DANGER: {"bg": "#ffe0e0", "fg": "#9b1c1c"},
    LEVEL_SUSPICIOUS: {"bg": "#ffecd6", "fg": "#9a4a00"},
    LEVEL_CHECK: {"bg": "#fff9d6", "fg": "#7a6400"},
    LEVEL_SAFE: {"bg": "#e6f7e6", "fg": "#176b17"},
}

LEVEL_DESCRIPTIONS = {
    LEVEL_DANGER: (
        "Есть сильные признаки вредоносной или скомпрометированной службы "
        "(подмена файла, майнер, запуск из временной папки и т.п.). "
        "Не запускайте файл и проверьте его антивирусом."
    ),
    LEVEL_SUSPICIOUS: (
        "Есть нетипичные признаки, которые встречаются и у легальных программ, "
        "но требуют вашего внимания: неизвестный издатель, странная папка, "
        "высокая нагрузка или слабые права на папку."
    ),
    LEVEL_CHECK: (
        "Служба выглядит скорее нормально, но подпись или расположение файла "
        "нетипичны. Стоит взглянуть на издателя и при сомнениях проверить файл."
    ),
    LEVEL_SAFE: (
        "Признаков вредоносности не найдено: подпись действительна, файл "
        "находится в ожидаемом месте, поведение не выделяется. Это не "
        "абсолютная гарантия, а результат проверок, перечисленных справа."
    ),
}

LEVEL_ACTIONS = {
    LEVEL_DANGER: (
        "1. Не запускайте службу и не перезагружайте компьютер без необходимости.\n"
        "2. Нажмите «VirusTotal» и проверьте хэш файла.\n"
        "3. Запустите полную проверку антивируса (Microsoft Defender или ваш антивирус).\n"
        "4. Если служба вам неизвестна, отключите её: sc.exe stop <имя> и "
        "sc.exe config <имя> start= disabled (только осознанно).\n"
        "5. Сохраните отчёт и при необходимости обратитесь к специалисту."
    ),
    LEVEL_SUSPICIOUS: (
        "1. Посмотрите издателя, дату создания файла и папку.\n"
        "2. Проверьте хэш в VirusTotal.\n"
        "3. Вспомните, устанавливали ли вы эту программу.\n"
        "4. Если не узнаёте службу — временно отключите её и понаблюдайте за системой."
    ),
    LEVEL_CHECK: (
        "1. Убедитесь, что издатель и программа вам знакомы.\n"
        "2. При сомнениях проверьте файл в VirusTotal.\n"
        "3. Специальных действий обычно не требуется."
    ),
    LEVEL_SAFE: (
        "Действий не требуется. Если компьютер ведёт себя странно (нагрузка ЦП, "
        "неизвестный сетевой трафик), проверьте систему антивирусом: одна "
        "безопасная служба не гарантирует чистоту всей системы."
    ),
}

# ---------------------------------------------------------------------------
# Состояния и типы служб
# ---------------------------------------------------------------------------

STATE_LABELS = {
    1: "Остановлена",
    2: "Запускается…",
    3: "Останавливается…",
    4: "Работает",
    5: "Продолжается…",
    6: "Приостанавливается…",
    7: "Приостановлена",
}

START_TYPE_LABELS = {
    0: "Загрузка",
    1: "Система",
    2: "Автоматически",
    3: "Вручную",
    4: "Отключена",
}

SERVICE_TYPE_LABELS = {
    0x1: "Драйвер ядра",
    0x2: "Драйвер файловой системы",
    0x4: "Драйвер адаптера",
    0x8: "Драйвер-распознаватель",
    0x10: "Собственный процесс",
    0x20: "Общий процесс",
    0x110: "Интерактивный процесс",
    0x120: "Общий интерактивный процесс",
}

RUNNING_STATES = {2, 3, 4, 5, 6}

# ---------------------------------------------------------------------------
# Известные издатели (для понятной подсказки, не для снятия риска)
# ---------------------------------------------------------------------------

KNOWN_PUBLISHER_KEYWORDS = (
    "microsoft",
    "nvidia",
    "intel",
    "amd",
    "advanced micro devices",
    "realtek",
    "qualcomm",
    "broadcom",
    "marvell",
    "dell",
    "hewlett-packard",
    "hp inc",
    "lenovo",
    "asus",
    "asustek",
    "acer",
    "msi",
    "micro-star",
    "gigabyte",
    "samsung",
    "apple",
    "google",
    "adobe",
    "mozilla",
    "valve",
    "epic games",
    "discord",
    "teamviewer",
    "anydesk",
    "citrix",
    "vmware",
    "oracle",
    "ibm",
    "sap ",
    "jetbrains",
    "python software foundation",
    "kaspersky",
    "eset",
    "avast",
    "avg",
    "bitdefender",
    "malwarebytes",
    "dr.web",
    "avira",
    "sophos",
    "trend micro",
    "mcafee",
    "norton",
    "symantec",
    "acronis",
    "paragon",
    "aomei",
    "easeus",
    "minitool",
    "piriform",
    "dropbox",
    "logitech",
    "corsair",
    "razer",
    "steelseries",
    "synaptics",
    "logmein",
    "nch software",
    "cyberlink",
    "corel",
    "autodesk",
    "unity technologies",
    "zoom video",
    "slack technologies",
    "telegram",
)


def is_known_publisher(org: str) -> bool:
    """Издатель входит в список широко известных компаний."""
    low = (org or "").lower()
    return any(keyword in low for keyword in KNOWN_PUBLISHER_KEYWORDS)


# ---------------------------------------------------------------------------
# Признаки майнеров
# ---------------------------------------------------------------------------

MINER_NAME_HINTS = (
    "xmrig",
    "minerd",
    "cpuminer",
    "nbminer",
    "lolminer",
    "t-rex",
    "trexminer",
    "phoenixminer",
    "ethminer",
    "srbminer",
    "bfgminer",
    "cgminer",
    "gminer",
    "teamredminer",
    "wildrig",
    "xmr-stak",
    "nanominer",
    "onezerominer",
    "kawpowminer",
    "silentxmr",
    "xmrdll",
    "minergate",
    "nicehash",
    "kryptex",
    "unmineable",
    "randomx",
    "cryptonight",
)

MINER_ARG_RE = (
    r"stratum\+?(?:tcp|ssl|tls)://"
    r"|xmrig://"
    r"|--donate-level"
    r"|--rig-id"
    r"|--coin\b"
    r"|--algo\b"
    r"|--cpu-max-threads-hint"
    r"|--huge-pages"
    r"|--randomx"
    r"|--cryptonight"
    r"|\brandomx\b"
    r"|\bcryptonight\b"
    r"|\bkawpow\b"
    r"|\bethash\b"
    r"|\bautolykos\b"
)

POOL_HINT_RE = (
    r"(?:stratum\+?(?:tcp|ssl|tls)://"
    r"|pool\."
    r"|minexmr"
    r"|xmrpool"
    r"|supportxmr"
    r"|nanopool"
    r"|2miners"
    r"|ethermine"
    r"|flexpool"
    r"|herominers"
    r"|minergate"
    r"|nicehash"
    r"|kryptex"
    r"|unmineable)"
)

MONERO_WALLET_RE = r"\b[48][1-9A-HJ-NP-Za-km-z]{94}\b"

# Порты, которые массово используют майнинг-пулы. Список намеренно узкий.
MINING_PORTS = {3333, 3334, 4444, 5555, 7777, 9999, 14444, 45560, 45700}

# ---------------------------------------------------------------------------
# Опасные и подозрительные каталоги
# ---------------------------------------------------------------------------

# (маркер в нормализованном пути, понятное название, вес)
DANGEROUS_PATH_MARKERS = (
    ("\\appdata\\", "папка AppData в профиле пользователя", 42),
    ("\\temp\\", "временная папка", 44),
    ("\\tmp\\", "временная папка", 44),
    ("\\downloads\\", "папка загрузок", 42),
    ("\\desktop\\", "рабочий стол", 40),
    ("\\documents\\", "папка документов", 38),
    ("\\users\\public\\", "общая папка пользователей", 40),
    ("\\$recycle.bin\\", "корзина", 45),
)

PROGRAMDATA_MARKER = "\\programdata\\"
USER_PROFILE_MARKER = "\\users\\"

# Каталоги, которым доверяем как «системным» (только вместе с подписью)
SYSTEM_PATH_MARKERS = (
    "\\windows\\system32\\",
    "\\windows\\syswow64\\",
    "\\windows\\winsxs\\",
    "\\windows\\system32\\drivers\\",
    "\\windows\\system32\\driverstore\\",
)

PROGRAM_FILES_MARKERS = (
    "\\program files\\",
    "\\program files (x86)\\",
    "\\program files\\windowsapps\\",
)

# ---------------------------------------------------------------------------
# Службы и процессы
# ---------------------------------------------------------------------------

# Бинарники, которые не должны быть образом службы (LOLBins и скриптовые хосты).
LOLBINS = {
    "powershell.exe",
    "pwsh.exe",
    "cmd.exe",
    "wscript.exe",
    "cscript.exe",
    "mshta.exe",
    "rundll32.exe",
    "regsvr32.exe",
    "certutil.exe",
    "bitsadmin.exe",
    "msiexec.exe",
    "installutil.exe",
    "regasm.exe",
    "regsvcs.exe",
    "wmic.exe",
    "schtasks.exe",
    "at.exe",
    "curl.exe",
    "msbuild.exe",
    "cmstp.exe",
    "forfiles.exe",
    "pcalua.exe",
    "hh.exe",
    "rundll32.exe",
    "explorer.exe",
    "notepad.exe",
    "mspaint.exe",
}

SYSTEM_BINARY_NAMES = (
    "svchost",
    "lsass",
    "winlogon",
    "csrss",
    "services",
    "wininit",
    "smss",
    "explorer",
    "conhost",
    "dwm",
    "taskhostw",
    "sihost",
    "runtimebroker",
    "dllhost",
    "spoolsv",
    "searchindexer",
    "msmpeng",
    "fontdrvhost",
    "ctfmon",
    "logonui",
    "userinit",
    "lsm",
    "securityhealthservice",
    "winlogon",
    "smartscreen",
    "nissrv",
)

# Имена настоящих служб Windows. Если файл с таким именем подписан не Microsoft —
# это уже серьёзный повод присмотреться.
KNOWN_WINDOWS_SERVICES = {
    "bits",
    "brokerinfrastructure",
    "cryptsvc",
    "dhcp",
    "dnscache",
    "eventlog",
    "lanmanserver",
    "lanmanworkstation",
    "lmhosts",
    "mpssvc",
    "msiserver",
    "netlogon",
    "nsi",
    "plugplay",
    "policyagent",
    "power",
    "profsvc",
    "rpcss",
    "samss",
    "schedule",
    "seclogon",
    "sens",
    "sensrsvc",
    "sessionenv",
    "shellhwdetection",
    "spooler",
    "srservice",
    "sysmain",
    "systemeventsbroker",
    "tabletinputservice",
    "termservice",
    "themes",
    "trustedinstaller",
    "umrdpservice",
    "usermanager",
    "vaultsvc",
    "w32time",
    "wdiServiceHost".lower(),
    "windefend",
    "winmgmt",
    "wlansvc",
    "wpnservice",
    "wscsvc",
    "wuauserv",
    "audiosrv",
    "audioendpointbuilder",
    "bfe",
    "diagtrack",
    "dosvc",
    "dps",
    "gpsvc",
    "ikEEXT".lower(),
    "iphlpsvc",
    "keyiso",
    "lanmanworkstation",
    "licenseManager".lower(),
    "lxsst",
    "mmcss",
    "netprofm",
    "nlasvc",
    "pcasvc",
    "seclogon",
    "securityhealthservice",
    "storsvc",
    "sysmain",
    "tapisrv",
    "timebrokerSvc".lower(),
    "tokenbroker",
    "userdataSvc".lower(),
    "vds",
    "vss",
    "wcncsvc",
    "webclient",
    "wecsvc",
    "winhttpautoproxysvc",
    "wudfsvc",
}

DISPLAY_IMPERSONATION_HINTS = (
    "windows defender",
    "microsoft windows",
    "windows security",
    "security essentials",
    "windows update",
    "microsoft store",
    "microsoft edge",
)

# ---------------------------------------------------------------------------
# Прочее
# ---------------------------------------------------------------------------

DOUBLE_EXTENSION_RE = (
    r"\.(?:pdf|docx?|xlsx?|pptx?|jpe?g|png|gif|txt|rtf|zip|rar|7z|mp3|mp4|avi|"
    r"html?|csv|iso|exe|dll|sys)\.(?:exe|scr|com|pif|bat|cmd|js|vbs|ps1)$"
)

# Расширения, которые не являются нормальным образом службы
SCRIPT_EXTENSIONS = {".bat", ".cmd", ".ps1", ".vbs", ".js", ".jse", ".wsf", ".hta", ".scr", ".msi"}

# Расширения, которые проверяет Authenticode
SIGNABLE_EXTENSIONS = {".exe", ".dll", ".sys", ".ocx", ".cpl", ".msi", ".ps1", ".vbs"}

RECOMMENDATION_DISCLAIMER = (
    "Программа не является антивирусом и не даёт гарантии безопасности. "
    "Она показывает признаки, по которым можно отличить типичную системную "
    "службу от подозрительной, и подсказывает, что проверить дальше."
)
