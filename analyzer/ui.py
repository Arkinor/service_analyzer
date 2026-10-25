"""Основной интерфейс приложения на Tkinter."""

from __future__ import annotations

import ctypes
import logging
import os
import queue
import subprocess
import sys
import threading
import traceback
import webbrowser
import winreg
from pathlib import Path
from tkinter import filedialog, messagebox, ttk
from typing import Optional
from urllib.parse import quote_plus
import tkinter as tk

from . import constants as C
from .collector import ScanCancelled, collect_services
from .config import load_config, save_config, log_path
from .help_text import ABOUT_TEXT, HELP_TEXT
from .models import ScanOptions, ScanResult, ServiceRecord
from .report import (
    default_export_name,
    export_csv,
    export_html,
    export_json,
    signature_label,
)
from .rules import apply_virustotal_result
from .vt import VirusTotalError, format_result, lookup_hash
from .winapi import get_file_properties, is_admin, sha256_file

log = logging.getLogger(__name__)

LEVEL_FILTERS = (
    "Все уровни",
    "Опасно",
    "Подозрительно",
    "Опасно + подозрительно",
    "Проверить",
    "Безопасно",
)

KIND_FILTERS = ("Все типы", "Только службы", "Только драйверы")

TABLE_COLUMNS = (
    "level",
    "display_name",
    "name",
    "state",
    "start",
    "publisher",
    "signature",
    "path",
)

TABLE_LABELS = {
    "level": "Уровень",
    "display_name": "Служба",
    "name": "Имя",
    "state": "Состояние",
    "start": "Запуск",
    "publisher": "Издатель",
    "signature": "Подпись",
    "path": "Файл",
}

TABLE_WIDTHS = {
    "level": 105,
    "display_name": 240,
    "name": 130,
    "state": 90,
    "start": 105,
    "publisher": 170,
    "signature": 110,
    "path": 300,
}

SEVERITY_ORDER = {
    "critical": 0,
    "high": 1,
    "medium": 2,
    "low": 3,
    "info": 4,
    "good": 5,
}

SEVERITY_PREFIX = {
    "critical": "⛔",
    "high": "▲",
    "medium": "!",
    "low": "·",
    "info": "ℹ",
    "good": "✔",
}

SEVERITY_TAG = {
    "critical": "sev_critical",
    "high": "sev_high",
    "medium": "sev_medium",
    "low": "sev_low",
    "info": "sev_info",
    "good": "sev_good",
}


class ServiceAnalyzerApp:
    def __init__(self, root: tk.Tk, auto_scan: bool = True):
        self.root = root
        self.config = load_config()
        self.records: list[ServiceRecord] = []
        self._by_name: dict[str, ServiceRecord] = {}
        self._row_map: dict[str, ServiceRecord] = {}
        self.scan_result: Optional[ScanResult] = None

        self.queue: queue.Queue = queue.Queue()
        self._cancel_event = threading.Event()
        self._scan_thread: Optional[threading.Thread] = None
        self._vt_inflight: set[str] = set()
        self._selected_name = ""
        self._search_after: Optional[str] = None

        self._sort_column = "level"
        self._sort_desc = True
        self._headings: dict[str, str] = {}

        self._level_filter_var = tk.StringVar(value="Все уровни")
        self._kind_filter_var = tk.StringVar(value="Все типы")
        self._search_var = tk.StringVar()
        self._running_var = tk.BooleanVar(value=False)

        self._include_drivers_var = tk.BooleanVar(
            value=bool(self.config.get("include_drivers", False))
        )
        self._live_var = tk.BooleanVar(value=bool(self.config.get("live_metrics", True)))
        self._deep_acl_var = tk.BooleanVar(value=bool(self.config.get("deep_acl", False)))

        self._progress_text = tk.StringVar(value="Готово к сканированию")
        self._filter_info = tk.StringVar(value="Показано: 0 из 0")
        self._status_var = tk.StringVar(value="Готово")
        self._admin_state_var = tk.StringVar()
        self._vt_state_var = tk.StringVar()

        self._scale = 1.0
        self._detail_buttons: list[ttk.Button] = []
        self._scan_buttons: list[tk.Widget] = []

        self._configure_root()
        self._build_style()
        self._build_menu()
        self._build_ui()
        self._refresh_security_status()
        self._show_detail_placeholder()

        self.root.protocol("WM_DELETE_WINDOW", self.on_close)
        self.root.after(100, self._poll_queue)
        self.root.after(150, self._setup_sash)

        if auto_scan:
            self.root.after(450, self.start_scan)

    # ------------------------------------------------------------------
    # Построение интерфейса
    # ------------------------------------------------------------------

    def _configure_root(self) -> None:
        self.root.title(f"{C.APP_NAME} {C.APP_VERSION}")
        self.root.minsize(1180, 720)
        try:
            self.root.state("zoomed")
        except Exception:
            self.root.geometry("1440x900")
        try:
            dpi = self.root.winfo_fpixels("1i")
            self._scale = max(1.0, dpi / 96.0)
            self.root.tk.call("tk", "scaling", dpi / 72.0)
        except Exception:
            self._scale = 1.0

    def _s(self, value: int) -> int:
        return max(1, int(value * self._scale))

    def _build_style(self) -> None:
        style = ttk.Style(self.root)
        themes = style.theme_names()
        if "vista" in themes:
            style.theme_use("vista")
        elif "clam" in themes:
            style.theme_use("clam")
        style.configure("Treeview", rowheight=self._s(24), font=("Segoe UI", 9))
        style.configure(
            "Treeview.Heading", font=("Segoe UI", 9, "bold"), padding=(4, 4)
        )
        style.configure("TButton", font=("Segoe UI", 9))
        style.configure("TLabel", font=("Segoe UI", 9))
        style.configure("TCheckbutton", font=("Segoe UI", 9))
        style.configure(
            "Accent.TButton", font=("Segoe UI", 9, "bold"), padding=(14, 6)
        )
        style.configure("Card.TFrame", background="white")
        style.configure("CardTitle.TLabel", background="white", foreground="#64748b")
        style.configure("CardNumber.TLabel", background="white", font=("Segoe UI", 17, "bold"))
        style.configure("Muted.TLabel", foreground="#64748b")
        style.configure("Small.TLabel", font=("Segoe UI", 8), foreground="#64748b")

    def _build_menu(self) -> None:
        menubar = tk.Menu(self.root)

        file_menu = tk.Menu(menubar, tearoff=0)
        file_menu.add_command(
            label="Экспорт отчёта HTML…", command=lambda: self.export_report("html")
        )
        file_menu.add_command(
            label="Экспорт CSV…", command=lambda: self.export_report("csv")
        )
        file_menu.add_command(
            label="Экспорт JSON…", command=lambda: self.export_report("json")
        )
        file_menu.add_separator()
        file_menu.add_command(label="Настройки…", command=self.open_settings)
        file_menu.add_separator()
        file_menu.add_command(label="Выход", command=self.on_close)
        menubar.add_cascade(label="Файл", menu=file_menu)

        scan_menu = tk.Menu(menubar, tearoff=0)
        scan_menu.add_command(
            label="Сканировать", command=self.start_scan, accelerator="F5"
        )
        scan_menu.add_command(label="Остановить", command=self.stop_scan)
        menubar.add_cascade(label="Сканирование", menu=scan_menu)

        help_menu = tk.Menu(menubar, tearoff=0)
        help_menu.add_command(
            label="Как читать результаты", command=self.show_help, accelerator="F1"
        )
        help_menu.add_command(label="О программе", command=self.show_about)
        help_menu.add_separator()
        help_menu.add_command(
            label="Открыть журнал", command=lambda: self._open_path(str(log_path()))
        )
        menubar.add_cascade(label="Справка", menu=help_menu)

        self.root.config(menu=menubar)
        self.root.bind("<F5>", lambda event: self.start_scan())
        self.root.bind("<F1>", lambda event: self.show_help())
        self.root.bind("<Control-e>", lambda event: self.export_report("html"))

    def _build_ui(self) -> None:
        self._build_header()
        self._build_admin_banner()
        self._build_toolbar()
        self._build_scan_options()
        self._build_progress()
        self._build_summary()
        self._build_body()
        self._build_status_bar()

    def _build_header(self) -> None:
        header = tk.Frame(self.root, bg="#0f4c81", padx=16, pady=10)
        header.pack(fill=tk.X)

        title_frame = tk.Frame(header, bg="#0f4c81")
        title_frame.pack(side=tk.LEFT)
        tk.Label(
            title_frame,
            text=C.APP_NAME,
            bg="#0f4c81",
            fg="white",
            font=("Segoe UI", 16, "bold"),
        ).pack(anchor="w")
        tk.Label(
            title_frame,
            text="Подпись · расположение · настройки · поведение · признаки майнеров",
            bg="#0f4c81",
            fg="#cfe3f5",
            font=("Segoe UI", 9),
        ).pack(anchor="w")

        buttons = tk.Frame(header, bg="#0f4c81")
        buttons.pack(side=tk.RIGHT)

        self.scan_button = tk.Button(
            buttons,
            text="Сканировать",
            command=self.start_scan,
            bg="white",
            fg="#0f4c81",
            activebackground="#e8f1f9",
            activeforeground="#0f4c81",
            relief=tk.FLAT,
            font=("Segoe UI", 10, "bold"),
            padx=20,
            pady=6,
            cursor="hand2",
        )
        self.scan_button.pack(side=tk.LEFT, padx=(0, 8))

        self.stop_button = tk.Button(
            buttons,
            text="Остановить",
            command=self.stop_scan,
            bg="#2a6b9c",
            fg="white",
            activebackground="#3a7dad",
            activeforeground="white",
            relief=tk.FLAT,
            font=("Segoe UI", 9),
            padx=14,
            pady=7,
            state=tk.DISABLED,
            cursor="hand2",
        )
        self.stop_button.pack(side=tk.LEFT)
        self._scan_buttons = [self.scan_button, self.stop_button]

    def _build_admin_banner(self) -> None:
        self.admin_banner = tk.Frame(self.root, bg="#fff4d6", padx=14, pady=6)
        if is_admin():
            return
        self.admin_banner.pack(fill=tk.X)
        tk.Label(
            self.admin_banner,
            text=(
                "Программа запущена без прав администратора. Часть защищённых "
                "файлов и сетевых данных может быть недоступна."
            ),
            bg="#fff4d6",
            fg="#7a4b00",
            font=("Segoe UI", 9),
        ).pack(side=tk.LEFT)
        tk.Button(
            self.admin_banner,
            text="Перезапустить от администратора",
            command=self.relaunch_as_admin,
            bg="#f0b429",
            fg="#3d2b00",
            relief=tk.FLAT,
            font=("Segoe UI", 8, "bold"),
            padx=10,
            pady=3,
            cursor="hand2",
        ).pack(side=tk.RIGHT)

    def _build_toolbar(self) -> None:
        toolbar = ttk.Frame(self.root, padding=(12, 8, 12, 2))
        toolbar.pack(fill=tk.X)

        ttk.Label(toolbar, text="Поиск:").pack(side=tk.LEFT)
        search_entry = ttk.Entry(toolbar, textvariable=self._search_var, width=28)
        search_entry.pack(side=tk.LEFT, padx=(4, 12))
        self._search_var.trace_add("write", lambda *args: self._schedule_filter())

        ttk.Label(toolbar, text="Уровень:").pack(side=tk.LEFT)
        level_combo = ttk.Combobox(
            toolbar,
            textvariable=self._level_filter_var,
            values=LEVEL_FILTERS,
            state="readonly",
            width=24,
        )
        level_combo.pack(side=tk.LEFT, padx=(4, 12))
        level_combo.bind("<<ComboboxSelected>>", lambda event: self.apply_filters())

        ttk.Label(toolbar, text="Тип:").pack(side=tk.LEFT)
        kind_combo = ttk.Combobox(
            toolbar,
            textvariable=self._kind_filter_var,
            values=KIND_FILTERS,
            state="readonly",
            width=17,
        )
        kind_combo.pack(side=tk.LEFT, padx=(4, 12))
        kind_combo.bind("<<ComboboxSelected>>", lambda event: self.apply_filters())

        ttk.Checkbutton(
            toolbar,
            text="Только запущенные",
            variable=self._running_var,
            command=self.apply_filters,
        ).pack(side=tk.LEFT, padx=(0, 14))

        help_button = ttk.Button(toolbar, text="Справка", command=self.show_help)
        help_button.pack(side=tk.RIGHT, padx=(6, 0))
        settings_button = ttk.Button(
            toolbar, text="Настройки", command=self.open_settings
        )
        settings_button.pack(side=tk.RIGHT, padx=(6, 0))

        export_menu = tk.Menu(self.root, tearoff=0)
        export_menu.add_command(
            label="Отчёт HTML…", command=lambda: self.export_report("html")
        )
        export_menu.add_command(label="Таблица CSV…", command=lambda: self.export_report("csv"))
        export_menu.add_command(label="Данные JSON…", command=lambda: self.export_report("json"))
        export_button = ttk.Menubutton(toolbar, text="Экспорт", menu=export_menu)
        export_button.pack(side=tk.RIGHT, padx=(6, 0))

    def _build_scan_options(self) -> None:
        options = ttk.Frame(self.root, padding=(12, 0, 12, 4))
        options.pack(fill=tk.X)
        ttk.Label(options, text="При сканировании:", style="Muted.TLabel").pack(
            side=tk.LEFT, padx=(0, 8)
        )
        self._option_checks: list[ttk.Checkbutton] = []
        for text, variable in (
            ("включая драйверы", self._include_drivers_var),
            ("проверять нагрузку ЦП и сеть", self._live_var),
            ("глубоко: права на папки", self._deep_acl_var),
        ):
            check = ttk.Checkbutton(options, text=text, variable=variable)
            check.pack(side=tk.LEFT, padx=(0, 14))
            self._option_checks.append(check)
        ttk.Label(
            options,
            text="Глубокий анализ и проверка прав увеличивают время сканирования.",
            style="Small.TLabel",
        ).pack(side=tk.LEFT, padx=(8, 0))

    def _build_progress(self) -> None:
        frame = ttk.Frame(self.root, padding=(12, 2, 12, 2))
        frame.pack(fill=tk.X)
        self.progress = ttk.Progressbar(
            frame, mode="determinate", maximum=100, length=320
        )
        self.progress.pack(side=tk.LEFT, padx=(0, 12))
        ttk.Label(
            frame,
            textvariable=self._progress_text,
            style="Muted.TLabel",
            anchor="w",
        ).pack(side=tk.LEFT, fill=tk.X, expand=True)

    def _build_summary(self) -> None:
        frame = tk.Frame(self.root, bg="#f4f6f8", padx=8, pady=4)
        frame.pack(fill=tk.X)
        self.card_values: dict[str, tk.Label] = {}
        definitions = (
            ("total", "Всего", "#2563eb"),
            ("danger", "Опасно", "#b91c1c"),
            ("suspicious", "Подозрительно", "#c2410c"),
            ("check", "Проверить", "#a16207"),
            ("safe", "Безопасно", "#15803d"),
        )
        for key, title, color in definitions:
            card = tk.Frame(
                frame,
                bg="white",
                highlightthickness=1,
                highlightbackground="#dbe2e8",
                padx=14,
                pady=4,
            )
            card.pack(side=tk.LEFT, padx=(0, 8))
            number = tk.Label(
                card,
                text="0",
                bg="white",
                fg=color,
                font=("Segoe UI", 16, "bold"),
                cursor="hand2",
            )
            number.pack(anchor="w")
            label = tk.Label(
                card,
                text=title,
                bg="white",
                fg="#64748b",
                font=("Segoe UI", 8),
                cursor="hand2",
            )
            label.pack(anchor="w")
            self.card_values[key] = number
            for widget in (card, number, label):
                widget.bind("<Button-1>", lambda event, k=key: self._card_clicked(k))
        self._summary_frame = frame

    def _build_body(self) -> None:
        self.paned = ttk.PanedWindow(self.root, orient=tk.HORIZONTAL)
        self.paned.pack(fill=tk.BOTH, expand=True, padx=10, pady=(4, 2))

        left = ttk.Frame(self.paned)
        right = ttk.Frame(self.paned)
        self.paned.add(left, weight=3)
        self.paned.add(right, weight=2)

        # ---- Таблица ----
        tree_frame = ttk.Frame(left)
        tree_frame.pack(fill=tk.BOTH, expand=True)
        tree_frame.rowconfigure(0, weight=1)
        tree_frame.columnconfigure(0, weight=1)

        self.tree = ttk.Treeview(
            tree_frame,
            columns=TABLE_COLUMNS,
            show="headings",
            selectmode="browse",
        )
        for column in TABLE_COLUMNS:
            label = TABLE_LABELS[column]
            self._headings[column] = label
            self.tree.heading(
                column, text=label, command=lambda c=column: self.sort_by(c)
            )
            self.tree.column(
                column,
                width=self._s(TABLE_WIDTHS[column]),
                minwidth=self._s(60),
                anchor=tk.W if column not in ("level", "state") else tk.CENTER,
                stretch=False,
            )
        self.tree.grid(row=0, column=0, sticky="nsew")
        vertical = ttk.Scrollbar(tree_frame, orient="vertical", command=self.tree.yview)
        horizontal = ttk.Scrollbar(
            tree_frame, orient="horizontal", command=self.tree.xview
        )
        self.tree.configure(yscrollcommand=vertical.set, xscrollcommand=horizontal.set)
        vertical.grid(row=0, column=1, sticky="ns")
        horizontal.grid(row=1, column=0, sticky="ew")

        for level, colors in C.LEVEL_COLORS.items():
            self.tree.tag_configure(
                level, background=colors["bg"], foreground=colors["fg"]
            )

        hint = ttk.Frame(left)
        hint.pack(fill=tk.X, pady=(2, 0))
        ttk.Label(
            hint,
            text=(
                "Двойной клик — открыть папку · правый клик — действия · "
                "клик по заголовку — сортировка"
            ),
            style="Small.TLabel",
        ).pack(side=tk.LEFT)
        ttk.Label(hint, textvariable=self._filter_info, style="Small.TLabel").pack(
            side=tk.RIGHT
        )

        self.tree.bind("<<TreeviewSelect>>", self._on_select)
        self.tree.bind("<Double-1>", lambda event: self.open_folder())
        self.tree.bind("<Button-3>", self._show_context_menu)
        self._build_context_menu()

        # ---- Детали ----
        right.rowconfigure(1, weight=1)
        right.columnconfigure(0, weight=1)
        actions = ttk.Frame(right, padding=(6, 0, 6, 4))
        actions.grid(row=0, column=0, sticky="ew")
        self._detail_buttons = []
        for index, (text, command) in enumerate(
            (
                ("Копировать путь", self.copy_path),
                ("Открыть папку", self.open_folder),
                ("Свойства", self.open_properties),
            )
        ):
            button = ttk.Button(actions, text=text, command=command, width=16)
            button.grid(row=0, column=index, padx=(0, 4), sticky="ew")
            actions.columnconfigure(index, weight=1)
            self._detail_buttons.append(button)

        self.vt_button = ttk.Button(
            actions, text="Проверить в VirusTotal", command=self.check_virustotal
        )
        self.vt_button.grid(row=1, column=0, columnspan=2, padx=(0, 4), pady=(4, 0), sticky="ew")
        self.web_button = ttk.Button(
            actions, text="Искать в интернете", command=self.search_web
        )
        self.web_button.grid(row=1, column=2, pady=(4, 0), sticky="ew")
        self._detail_buttons.extend([self.vt_button, self.web_button])

        text_frame = ttk.Frame(right)
        text_frame.grid(row=1, column=0, sticky="nsew")
        text_frame.rowconfigure(0, weight=1)
        text_frame.columnconfigure(0, weight=1)
        self.detail = tk.Text(
            text_frame,
            wrap="word",
            borderwidth=0,
            highlightthickness=1,
            highlightbackground="#dbe2e8",
            bg="white",
            padx=self._s(14),
            pady=self._s(10),
            font=("Segoe UI", 9),
            spacing1=1,
            spacing3=3,
            cursor="arrow",
        )
        detail_scroll = ttk.Scrollbar(
            text_frame, orient="vertical", command=self.detail.yview
        )
        self.detail.configure(yscrollcommand=detail_scroll.set)
        self.detail.grid(row=0, column=0, sticky="nsew")
        detail_scroll.grid(row=0, column=1, sticky="ns")
        self.detail.configure(state=tk.DISABLED)
        self._configure_detail_tags()

    def _configure_detail_tags(self) -> None:
        self.detail.tag_configure(
            "title", font=("Segoe UI", 14, "bold"), foreground="#0f172a", spacing3=6
        )
        self.detail.tag_configure(
            "subtitle", font=("Segoe UI", 9), foreground="#64748b", spacing3=8
        )
        self.detail.tag_configure(
            "h2",
            font=("Segoe UI", 9, "bold"),
            foreground="#0f4c81",
            spacing1=12,
            spacing3=4,
        )
        self.detail.tag_configure("body", font=("Segoe UI", 9), foreground="#1f2933")
        self.detail.tag_configure(
            "muted", font=("Segoe UI", 9), foreground="#64748b"
        )
        self.detail.tag_configure("mono", font=("Consolas", 8), foreground="#334155")
        self.detail.tag_configure(
            "kv_label", font=("Segoe UI", 9, "bold"), foreground="#334155"
        )
        self.detail.tag_configure(
            "finding_title", font=("Segoe UI", 9, "bold"), spacing1=4
        )
        self.detail.tag_configure(
            "finding_body",
            font=("Segoe UI", 9),
            lmargin1=self._s(14),
            lmargin2=self._s(14),
            foreground="#475569",
        )
        self.detail.tag_configure(
            "advice",
            font=("Segoe UI", 8),
            lmargin1=self._s(14),
            lmargin2=self._s(14),
            foreground="#64748b",
            spacing3=4,
        )
        self.detail.tag_configure(
            "weight", font=("Segoe UI", 8), foreground="#94a3b8"
        )
        self.detail.tag_configure(
            "positive", font=("Segoe UI", 9), foreground="#15803d", lmargin1=4
        )
        self.detail.tag_configure("link", foreground="#0b5cad", underline=True)
        self.detail.tag_configure("sev_critical", foreground="#991b1b")
        self.detail.tag_configure("sev_high", foreground="#9a3412")
        self.detail.tag_configure("sev_medium", foreground="#854d0e")
        self.detail.tag_configure("sev_low", foreground="#475569")
        self.detail.tag_configure("sev_info", font=("Segoe UI", 8), foreground="#64748b")
        self.detail.tag_configure("sev_good", foreground="#15803d")
        self.detail.tag_configure(
            "level_safe", font=("Segoe UI", 12, "bold"), foreground="#15803d"
        )
        self.detail.tag_configure(
            "level_check", font=("Segoe UI", 12, "bold"), foreground="#a16207"
        )
        self.detail.tag_configure(
            "level_suspicious", font=("Segoe UI", 12, "bold"), foreground="#c2410c"
        )
        self.detail.tag_configure(
            "level_danger", font=("Segoe UI", 12, "bold"), foreground="#b91c1c"
        )

    def _build_status_bar(self) -> None:
        bar = tk.Frame(self.root, bg="#eef2f6", padx=12, pady=4)
        bar.pack(fill=tk.X)
        tk.Label(
            bar,
            textvariable=self._status_var,
            bg="#eef2f6",
            fg="#334155",
            font=("Segoe UI", 8),
            anchor="w",
        ).pack(side=tk.LEFT, fill=tk.X, expand=True)
        tk.Label(
            bar,
            textvariable=self._vt_state_var,
            bg="#eef2f6",
            fg="#64748b",
            font=("Segoe UI", 8),
        ).pack(side=tk.RIGHT, padx=(12, 0))
        tk.Label(
            bar,
            textvariable=self._admin_state_var,
            bg="#eef2f6",
            fg="#64748b",
            font=("Segoe UI", 8),
        ).pack(side=tk.RIGHT)

    def _build_context_menu(self) -> None:
        self.context_menu = tk.Menu(self.root, tearoff=0)
        self.context_menu.add_command(label="Копировать путь", command=self.copy_path)
        self.context_menu.add_command(label="Копировать имя службы", command=self.copy_name)
        self.context_menu.add_command(
            label="Копировать SHA-256", command=self.copy_hash
        )
        self.context_menu.add_separator()
        self.context_menu.add_command(label="Открыть папку с файлом", command=self.open_folder)
        self.context_menu.add_command(label="Свойства файла", command=self.open_properties)
        self.context_menu.add_command(
            label="Проверить в VirusTotal", command=self.check_virustotal
        )
        self.context_menu.add_command(label="Искать в интернете", command=self.search_web)
        self.context_menu.add_separator()
        self.context_menu.add_command(
            label="Открыть службы Windows", command=self.open_services_console
        )
        self.context_menu.add_command(
            label="Открыть ключ реестра", command=self.open_registry_key
        )

    def _setup_sash(self) -> None:
        try:
            self.root.update_idletasks()
            width = self.paned.winfo_width()
            if width > 200:
                self.paned.sashpos(0, int(width * 0.63))
        except Exception:
            pass

    # ------------------------------------------------------------------
    # Вспомогательные методы интерфейса
    # ------------------------------------------------------------------

    def _refresh_security_status(self) -> None:
        self._admin_state_var.set(
            "Права: администратор" if is_admin() else "Права: обычные"
        )
        self._vt_state_var.set(
            "VirusTotal: ключ задан"
            if self.config.get("vt_api_key")
            else "VirusTotal: не настроен"
        )

    def _set_status(self, text: str) -> None:
        self._status_var.set(text)

    def _schedule_filter(self) -> None:
        if self._search_after:
            try:
                self.root.after_cancel(self._search_after)
            except Exception:
                pass
        self._search_after = self.root.after(250, self.apply_filters)

    def _card_clicked(self, key: str) -> None:
        mapping = {
            "total": "Все уровни",
            "danger": "Опасно",
            "suspicious": "Опасно + подозрительно",
            "check": "Проверить",
            "safe": "Безопасно",
        }
        if key == "suspicious":
            # Отдельная карточка «Подозрительно» показывает только этот уровень.
            self._level_filter_var.set("Подозрительно")
        else:
            self._level_filter_var.set(mapping.get(key, "Все уровни"))
        self.apply_filters()

    def _detail_placeholder_text(self) -> str:
        return (
            "Выберите службу в таблице, чтобы увидеть подробности.\n\n"
            "Программа объясняет, почему служба получила такой уровень, "
            "и что именно было проверено. Начните со сканирования, затем "
            "отсортируйте таблицу по уровню (щёлкните заголовок «Уровень»).\n\n"
            "Полезно знать:\n"
            "• «Безопасно» — не найдено известных признаков проблемы, "
            "а не абсолютная гарантия.\n"
            "• «Опасно» — есть сильные признаки: подмена подписи, майнер, "
            "запуск из временной папки.\n"
            "• Службы внутри svchost.exe проверяются по их ServiceDll, "
            "а не по самому svchost.exe.\n"
            "• Кнопка VirusTotal отправляет только SHA-256 файла."
        )

    def _show_detail_placeholder(self) -> None:
        self.detail.configure(state=tk.NORMAL)
        self.detail.delete("1.0", tk.END)
        self.detail.insert("1.0", self._detail_placeholder_text(), ("body",))
        self.detail.configure(state=tk.DISABLED)
        self._set_detail_buttons(False)

    def _set_detail_buttons(self, enabled: bool) -> None:
        state = tk.NORMAL if enabled else tk.DISABLED
        for button in self._detail_buttons:
            button.configure(state=state)

    def _insert_detail(self, text: str, tags=("body",)) -> None:
        self.detail.insert(tk.END, text, tags)

    def _kv(self, label: str, value, mono: bool = False) -> None:
        text = "" if value is None else str(value)
        if not text:
            text = "—"
        self._insert_detail(f"{label}: ", ("body", "kv_label"))
        tags = ("body", "mono") if mono else ("body",)
        self._insert_detail(text + "\n", tags)

    def _section(self, title: str) -> None:
        self._insert_detail(title.upper() + "\n", ("h2",))

    # ------------------------------------------------------------------
    # Сканирование
    # ------------------------------------------------------------------

    def start_scan(self) -> None:
        if self._scan_thread and self._scan_thread.is_alive():
            return

        self._cancel_event.clear()
        self._vt_inflight.clear()
        self.records = []
        self._by_name.clear()
        self._row_map.clear()
        self.scan_result = None
        self._selected_name = ""
        for item in self.tree.get_children():
            self.tree.delete(item)
        self._update_summary_cards()
        self._filter_info.set("Показано: 0 из 0")
        self._show_detail_placeholder()

        options = ScanOptions(
            include_drivers=bool(self._include_drivers_var.get()),
            live_metrics=bool(self._live_var.get()),
            deep_acl=bool(self._deep_acl_var.get()),
        )
        for key, variable in (
            ("include_drivers", self._include_drivers_var),
            ("live_metrics", self._live_var),
            ("deep_acl", self._deep_acl_var),
        ):
            self.config[key] = bool(variable.get())
        save_config(self.config)

        self.progress["value"] = 0
        self._progress_text.set("Подготовка к сканированию…")
        self._set_status("Сканирование запущено…")
        self._set_scanning_state(True)

        self._scan_thread = threading.Thread(
            target=self._scan_worker, args=(options,), daemon=True
        )
        self._scan_thread.start()

    def _scan_worker(self, options: ScanOptions) -> None:
        try:
            result = collect_services(
                options=options,
                progress=lambda percent, text: self.queue.put(
                    ("progress", (percent, text))
                ),
                cancel_event=self._cancel_event,
            )
            self.queue.put(("done", result))
        except ScanCancelled:
            self.queue.put(("cancelled", None))
        except Exception as exc:
            log.exception("Ошибка сканирования")
            self.queue.put(("error", f"{exc}\n\nПодробности в журнале:\n{log_path()}"))

    def stop_scan(self) -> None:
        if self._scan_thread and self._scan_thread.is_alive():
            self._cancel_event.set()
            self.stop_button.configure(state=tk.DISABLED)
            self._progress_text.set("Останавливаю сканирование…")
            self._set_status("Останавливаю сканирование…")

    def _set_scanning_state(self, scanning: bool) -> None:
        self.scan_button.configure(state=tk.DISABLED if scanning else tk.NORMAL)
        self.stop_button.configure(state=tk.NORMAL if scanning else tk.DISABLED)
        for check in self._option_checks:
            check.configure(state=tk.DISABLED if scanning else tk.NORMAL)

    def _poll_queue(self) -> None:
        try:
            while True:
                kind, payload = self.queue.get_nowait()
                if kind == "progress":
                    percent, text = payload
                    self.progress["value"] = percent
                    self._progress_text.set(text)
                elif kind == "done":
                    self._handle_done(payload)
                elif kind == "cancelled":
                    self._handle_cancelled()
                elif kind == "error":
                    self._handle_error(payload)
                elif kind == "hash":
                    name, digest = payload
                    record = self._by_name.get(name)
                    if record:
                        record.sha256 = digest
                        if self._selected_name == name:
                            self.show_record(record)
                elif kind == "vt":
                    name, result = payload
                    self._handle_vt_result(name, result)
                elif kind == "vt_error":
                    name, message = payload
                    self._vt_inflight.discard(name)
                    self._set_status("VirusTotal: ошибка")
                    messagebox.showerror("VirusTotal", message, parent=self.root)
        except queue.Empty:
            pass
        except Exception:
            log.exception("Ошибка обработки очереди интерфейса")
        finally:
            try:
                self.root.after(100, self._poll_queue)
            except Exception:
                pass

    def _handle_done(self, result: ScanResult) -> None:
        self.scan_result = result
        self.records = result.records
        self._by_name = {record.name: record for record in result.records}
        self._set_scanning_state(False)
        self.progress["value"] = 100
        counts = result.counts()
        notes = []
        if not result.options.include_drivers:
            notes.append("драйверы не проверялись")
        if not result.options.deep_acl:
            notes.append("права на папки не проверялись")
        suffix = (" · " + ", ".join(notes)) if notes else ""
        self._progress_text.set(
            "Готово: {0} записей за {1:.1f} с{2}".format(
                len(result.records), result.duration_seconds, suffix
            )
        )
        self._update_summary_cards()
        self.apply_filters()

        if result.errors:
            self._set_status(
                f"Сканирование завершено с предупреждениями: {len(result.errors)}. "
                f"Подробности в журнале {log_path()}"
            )
        else:
            self._set_status(
                "Готово: {total} проверено · {danger} опасно · "
                "{suspicious} подозрительно · {check} проверить · "
                "{safe} безопасно{notes}".format(
                    total=len(result.records),
                    danger=counts.get(C.LEVEL_DANGER, 0),
                    suspicious=counts.get(C.LEVEL_SUSPICIOUS, 0),
                    check=counts.get(C.LEVEL_CHECK, 0),
                    safe=counts.get(C.LEVEL_SAFE, 0),
                    notes=suffix,
                )
            )

        target = None
        for record in result.records:
            if record.level == C.LEVEL_DANGER:
                target = record
                break
        if target is None and result.records:
            # Показываем самую «интересную» запись, а не первую по алфавиту.
            target = max(
                result.records,
                key=lambda item: (C.LEVEL_ORDER.get(item.level, 0), item.score),
            )
        if target is not None:
            self._select_record(target)

    def _handle_cancelled(self) -> None:
        self._set_scanning_state(False)
        self._progress_text.set("Сканирование отменено")
        self._set_status("Сканирование отменено пользователем")
        self.progress["value"] = 0

    def _handle_error(self, message: str) -> None:
        self._set_scanning_state(False)
        self._progress_text.set("Ошибка сканирования")
        self._set_status("Ошибка сканирования")
        messagebox.showerror("Ошибка", message, parent=self.root)

    # ------------------------------------------------------------------
    # Таблица, фильтры и сортировка
    # ------------------------------------------------------------------

    def _matches(self, record: ServiceRecord) -> bool:
        level_filter = self._level_filter_var.get()
        if level_filter == "Опасно" and record.level != C.LEVEL_DANGER:
            return False
        if level_filter == "Подозрительно" and record.level != C.LEVEL_SUSPICIOUS:
            return False
        if level_filter == "Опасно + подозрительно" and record.level not in (
            C.LEVEL_DANGER,
            C.LEVEL_SUSPICIOUS,
        ):
            return False
        if level_filter == "Проверить" and record.level != C.LEVEL_CHECK:
            return False
        if level_filter == "Безопасно" and record.level != C.LEVEL_SAFE:
            return False

        kind_filter = self._kind_filter_var.get()
        if kind_filter == "Только службы" and record.kind != "service":
            return False
        if kind_filter == "Только драйверы" and record.kind != "driver":
            return False

        if self._running_var.get() and not record.is_running:
            return False

        query = self._search_var.get().strip().lower()
        if query:
            haystack = " ".join(
                (
                    record.name,
                    record.display_name,
                    record.description,
                    record.path_for_display,
                    record.publisher,
                    record.file.company,
                    record.file.product,
                    record.sha256,
                    record.account,
                    " ".join(finding.title for finding in record.findings),
                )
            ).lower()
            if query not in haystack:
                return False
        return True

    def _sort_value(self, record: ServiceRecord, column: str):
        if column == "level":
            return (C.LEVEL_ORDER.get(record.level, 0), record.score)
        if column == "score":
            return record.score
        if column == "display_name":
            return (record.display_name or record.name).lower()
        if column == "name":
            return record.name.lower()
        if column == "state":
            return (0 if record.is_running else 1, record.state_label)
        if column == "start":
            order = {2: 0, 3: 1, 0: 2, 1: 3, 4: 4}
            return (order.get(record.start_code, 9), record.start_label)
        if column == "publisher":
            return record.publisher.lower()
        if column == "signature":
            return signature_label(record.signature.status)
        if column == "path":
            return record.path_for_display.lower()
        return ""

    def sort_by(self, column: str) -> None:
        if column == self._sort_column:
            self._sort_desc = not self._sort_desc
        else:
            self._sort_column = column
            self._sort_desc = column in ("level", "score")
        self.render_table()

    def _visible_records(self) -> list[ServiceRecord]:
        records = [record for record in self.records if self._matches(record)]
        records.sort(
            key=lambda record: self._sort_value(record, self._sort_column),
            reverse=self._sort_desc,
        )
        return records

    def apply_filters(self) -> None:
        self.render_table()

    def render_table(self) -> None:
        selected_name = self._selected_name
        for item in self.tree.get_children():
            self.tree.delete(item)
        records = self._visible_records()
        self._row_map.clear()

        for index, record in enumerate(records):
            iid = f"r{index}"
            values = (
                f"{C.LEVEL_ICONS.get(record.level, '')} "
                f"{C.LEVEL_LABELS.get(record.level, record.level)}",
                record.display_name or record.name,
                record.name,
                record.state_label,
                record.start_label,
                record.publisher or "—",
                signature_label(record.signature.status),
                record.path_for_display or "—",
            )
            self.tree.insert("", tk.END, iid=iid, values=values, tags=(record.level,))
            self._row_map[iid] = record

        self._filter_info.set(f"Показано: {len(records)} из {len(self.records)}")
        self._update_headings()

        if selected_name:
            for iid, record in self._row_map.items():
                if record.name == selected_name:
                    self.tree.selection_set(iid)
                    self.tree.see(iid)
                    break

    def _update_headings(self) -> None:
        for column in TABLE_COLUMNS:
            label = self._headings[column]
            if column == self._sort_column:
                label += " ▼" if self._sort_desc else " ▲"
            self.tree.heading(column, text=label)

    def _select_record(self, record: ServiceRecord) -> None:
        for iid, candidate in self._row_map.items():
            if candidate is record:
                self.tree.selection_set(iid)
                self.tree.see(iid)
                self.show_record(record)
                break

    def _on_select(self, event=None) -> None:
        selection = self.tree.selection()
        if not selection:
            return
        record = self._row_map.get(selection[0])
        if record:
            self._selected_name = record.name
            self.show_record(record)

    def _update_summary_cards(self) -> None:
        counts = {"total": len(self.records), "danger": 0, "suspicious": 0, "check": 0, "safe": 0}
        for record in self.records:
            counts[record.level] = counts.get(record.level, 0) + 1
        for key, label in self.card_values.items():
            label.configure(text=str(counts.get(key, 0)))

    def _show_context_menu(self, event) -> None:
        iid = self.tree.identify_row(event.y)
        if not iid:
            return
        self.tree.selection_set(iid)
        record = self._row_map.get(iid)
        if not record:
            return
        self._selected_name = record.name
        self.show_record(record)
        try:
            self.context_menu.tk_popup(event.x_root, event.y_root)
        finally:
            self.context_menu.grab_release()

    # ------------------------------------------------------------------
    # Панель подробностей
    # ------------------------------------------------------------------

    def _selected_record(self) -> Optional[ServiceRecord]:
        selection = self.tree.selection()
        if selection:
            return self._row_map.get(selection[0])
        return self._by_name.get(self._selected_name)

    def show_record(self, record: ServiceRecord) -> None:
        self._selected_name = record.name
        self.detail.configure(state=tk.NORMAL)
        self.detail.delete("1.0", tk.END)

        self._insert_detail((record.display_name or record.name) + "\n", ("title",))
        self._insert_detail(
            f"{C.LEVEL_ICONS.get(record.level, '')} "
            f"{C.LEVEL_LABELS.get(record.level, record.level)}",
            (f"level_{record.level}",),
        )
        self._insert_detail(
            f"   ·   оценка {record.score}/100   ·   "
            f"{'драйвер' if record.kind == 'driver' else 'служба'}\n",
            ("subtitle",),
        )
        self._insert_detail(
            C.LEVEL_DESCRIPTIONS.get(record.level, "") + "\n", ("body",)
        )

        self._section("Почему такой вердикт")
        findings = sorted(
            record.findings,
            key=lambda finding: (
                SEVERITY_ORDER.get(finding.severity, 9),
                -finding.weight,
            ),
        )
        score_findings = [
            finding for finding in findings if finding.severity != "info"
        ]
        info_findings = [finding for finding in findings if finding.severity == "info"]
        if not score_findings:
            self._insert_detail(
                "✔ Признаков вредоносности не найдено\n", ("positive",)
            )
        for finding in score_findings:
            prefix = SEVERITY_PREFIX.get(finding.severity, "•")
            self._insert_detail(
                f"{prefix} {finding.title}",
                (SEVERITY_TAG.get(finding.severity, "sev_low"), "finding_title"),
            )
            if finding.weight:
                self._insert_detail(f"  +{finding.weight}\n", ("weight",))
            else:
                self._insert_detail("\n", ("weight",))
            self._insert_detail(finding.detail + "\n", ("finding_body",))
            if finding.advice:
                self._insert_detail(
                    "Что делать: " + finding.advice + "\n", ("advice",)
                )
        for finding in info_findings:
            self._insert_detail(
                f"ℹ {finding.title}. {finding.detail}\n", ("finding_body",)
            )

        if record.positives:
            self._section("Что проверено и подтверждено")
            for text in record.positives:
                self._insert_detail(f"✔ {text}\n", ("positive",))

        self._section("Служба")
        self._kv("Имя", record.name)
        self._kv("Отображаемое имя", record.display_name)
        self._kv(
            "Тип",
            f"{record.service_type_label}"
            + (" · драйвер" if record.kind == "driver" else " · служба"),
        )
        state = record.state_label
        if record.pid and not record.is_shared_host:
            state += f" · PID {record.pid}"
        self._kv("Состояние", state)
        self._kv("Запуск", record.start_label)
        self._kv("Учётная запись", record.account_label)
        if record.dependencies:
            self._kv("Зависимости", ", ".join(record.dependencies))
        if record.is_shared_host:
            self._kv("Хост-процесс", record.host_exe or "svchost.exe")
        self._kv("Ключ реестра", record.registry_key, mono=True)
        if record.description:
            self._insert_detail("\n" + record.description + "\n", ("muted",))

        self._section("Файл")
        self._kv("Путь", record.path_for_display, mono=True)
        if record.service_dll and record.service_dll != record.image_path:
            self._kv("ServiceDll", record.service_dll, mono=True)
        self._kv("Существует", "да" if record.file.exists else "нет")
        if record.file.exists:
            self._kv("Размер", _format_size(record.file.size))
            self._kv("Создан", _format_datetime(record.file.created))
            self._kv("Изменён", _format_datetime(record.file.modified))
            self._kv("Компания", record.file.company)
            self._kv("Продукт", record.file.product)
            self._kv("Описание", record.file.description)
            self._kv("Версия", record.file.version)
            if record.sha256:
                self._kv("SHA-256", record.sha256, mono=True)
            else:
                self._insert_detail(
                    "SHA-256: не вычислялся (файл считается доверенным или "
                    "ещё не проверялся)\n",
                    ("muted",),
                )

        self._section("Цифровая подпись")
        sig = record.signature
        self._kv("Статус", signature_label(sig.status))
        if sig.signer_org:
            self._kv("Издатель", sig.signer_org)
        if sig.subject:
            self._kv("Субъект", sig.subject, mono=True)
        if sig.issuer:
            self._kv("Центр сертификации", sig.issuer, mono=True)
        if sig.not_after:
            self._kv("Действует до", _format_iso_date(sig.not_after))
        self._kv("Метка времени", "да" if sig.timestamped else "нет")
        self._kv("Компонент ОС", "да" if sig.os_binary else "нет")
        if sig.error:
            self._kv("Ошибка", sig.error, mono=True)
        if record.host_signature and record.is_shared_host:
            host_sig = record.host_signature
            self._kv(
                "Подпись хоста",
                f"{signature_label(host_sig.status)}"
                + (f" · {host_sig.signer_org}" if host_sig.signer_org else ""),
            )

        self._section("Поведение")
        if record.is_shared_host:
            self._insert_detail(
                "Служба работает внутри общего процесса "
                f"{record.host_exe or 'svchost.exe'}. Нагрузка ЦП и сетевые "
                "соединения относятся ко всем службам этого процесса, поэтому "
                "для оценки используется файл ServiceDll.\n",
                ("muted",),
            )
        elif record.live.pid:
            self._kv(
                "Загрузка ЦП",
                f"{record.live.cpu_percent:.1f}%"
                if record.live.cpu_percent is not None
                else "—",
            )
            self._kv(
                "Память",
                f"{record.live.memory_mb:.1f} МБ"
                if record.live.memory_mb is not None
                else "—",
            )
            self._kv(
                "Родительский процесс",
                f"{record.live.parent_name or '—'}"
                + (f" (PID {record.live.parent_pid})" if record.live.parent_pid else ""),
            )
            if record.live.process_exe:
                self._kv("Процесс", record.live.process_exe, mono=True)
            if record.live.connections:
                self._insert_detail(
                    f"Сетевые соединения ({len(record.live.connections)}):\n",
                    ("body",),
                )
                for connection in record.live.connections[:10]:
                    self._insert_detail(
                        f"  {connection.get('ip')}:{connection.get('port')}\n",
                        ("mono",),
                    )
            else:
                self._kv("Сетевые соединения", "нет активных внешних соединений")
            if record.live.error:
                self._insert_detail(record.live.error + "\n", ("muted",))
        else:
            if record.is_running:
                self._insert_detail(
                    "Служба запущена, но анализ нагрузки был отключён при "
                    "сканировании. Включите «проверять нагрузку ЦП и сеть» и "
                    "повторите сканирование, чтобы увидеть ЦП, память и "
                    "сетевые соединения.\n",
                    ("muted",),
                )
            else:
                self._insert_detail(
                    "Служба остановлена, поэтому наблюдать её поведение сейчас "
                    "нельзя. Это нормально для служб, запускаемых вручную или "
                    "по требованию.\n",
                    ("muted",),
                )

        self._section("Права на папку")
        if record.dir_writable_by_users is True:
            self._insert_detail(
                "Папка доступна для записи обычным пользователям — это риск "
                "подмены файла.\n",
                ("sev_high",),
            )
        elif record.dir_writable_by_users is False:
            self._insert_detail(
                "Запись в папку есть только у администраторов и SYSTEM.\n",
                ("positive",),
            )
        else:
            self._insert_detail(
                "Не проверялось (включите «глубоко: права на папки»).\n",
                ("muted",),
            )

        self._section("VirusTotal")
        if record.vt_result:
            result = record.vt_result
            if result.get("found"):
                self._insert_detail(
                    f"Обнаружений: {result.get('malicious', 0) + result.get('suspicious', 0)} "
                    f"из {result.get('total', '?')}\n",
                    ("body",),
                )
                if result.get("last_analysis_date"):
                    self._insert_detail(
                        f"Последняя проверка: {result['last_analysis_date']}\n",
                        ("muted",),
                    )
                self._insert_detail(result.get("link", "") + "\n", ("link",))
            else:
                self._insert_detail(
                    "Файл с таким хэшем отсутствует в базе VirusTotal.\n",
                    ("muted",),
                )
        elif self.config.get("vt_api_key"):
            self._insert_detail(
                "Ещё не проверялось. Нажмите «Проверить в VirusTotal» — "
                "отправляется только SHA-256.\n",
                ("muted",),
            )
        else:
            self._insert_detail(
                "API-ключ VirusTotal не задан. Его можно добавить в настройках; "
                "файл при проверке не загружается, отправляется только хэш.\n",
                ("muted",),
            )

        self._section("Что делать")
        self._insert_detail(C.LEVEL_ACTIONS.get(record.level, "") + "\n", ("body",))
        self._insert_detail("\n" + C.RECOMMENDATION_DISCLAIMER + "\n", ("muted",))

        self.detail.configure(state=tk.DISABLED)
        self.detail.see("1.0")
        self._set_detail_buttons(True)
        self._set_status(
            f"Выбрана служба: {record.name} · {C.LEVEL_LABELS.get(record.level)} "
            f"({record.score}/100)"
        )

    # ------------------------------------------------------------------
    # Действия
    # ------------------------------------------------------------------

    def copy_path(self) -> None:
        record = self._selected_record()
        if not record:
            return
        path = record.path_for_display
        if not path:
            return
        self.root.clipboard_clear()
        self.root.clipboard_append(path)
        self._set_status(f"Путь скопирован: {path}")

    def copy_name(self) -> None:
        record = self._selected_record()
        if not record:
            return
        self.root.clipboard_clear()
        self.root.clipboard_append(record.name)
        self._set_status(f"Имя службы скопировано: {record.name}")

    def copy_hash(self) -> None:
        record = self._selected_record()
        if not record:
            return
        if not record.sha256:
            messagebox.showinfo(
                "SHA-256",
                "Хэш ещё не вычислялся. Нажмите «Проверить в VirusTotal» — "
                "хэш будет вычислен автоматически.",
                parent=self.root,
            )
            return
        self.root.clipboard_clear()
        self.root.clipboard_append(record.sha256)
        self._set_status("SHA-256 скопирован в буфер обмена")

    def open_folder(self) -> None:
        record = self._selected_record()
        if not record:
            return
        path = record.path_for_display
        if not path:
            return
        try:
            if os.path.isfile(path):
                subprocess.Popen(["explorer.exe", f"/select,{path}"])
            elif os.path.isdir(path):
                os.startfile(path)
            else:
                folder = os.path.dirname(path)
                if os.path.isdir(folder):
                    os.startfile(folder)
                else:
                    messagebox.showwarning(
                        "Папка не найдена",
                        f"Файл или папка не существуют:\n{path}",
                        parent=self.root,
                    )
        except Exception as exc:
            messagebox.showerror("Ошибка", f"Не удалось открыть папку: {exc}", parent=self.root)

    def open_properties(self) -> None:
        record = self._selected_record()
        if not record:
            return
        path = record.path_for_display
        if not path or not os.path.isfile(path):
            messagebox.showwarning(
                "Файл не найден",
                "Свойства доступны только для существующего файла.",
                parent=self.root,
            )
            return
        if not get_file_properties(path):
            messagebox.showerror(
                "Ошибка",
                "Не удалось открыть свойства файла.",
                parent=self.root,
            )

    def open_services_console(self) -> None:
        try:
            subprocess.Popen(["mmc.exe", "services.msc"])
        except Exception as exc:
            messagebox.showerror("Ошибка", f"Не удалось открыть services.msc: {exc}", parent=self.root)

    def open_registry_key(self) -> None:
        record = self._selected_record()
        if not record or not record.registry_key:
            return
        try:
            key_path = (
                r"Software\Microsoft\Windows\CurrentVersion\Applets\Regedit"
            )
            key = winreg.CreateKey(winreg.HKEY_CURRENT_USER, key_path)
            with key:
                winreg.SetValueEx(key, "LastKey", 0, winreg.REG_SZ, record.registry_key)
            subprocess.Popen(["regedit.exe"])
        except Exception as exc:
            messagebox.showerror("Ошибка", f"Не удалось открыть реестр: {exc}", parent=self.root)

    def search_web(self) -> None:
        record = self._selected_record()
        if not record:
            return
        query = f"{record.display_name} {record.name} windows service"
        self._open_url("https://www.google.com/search?q=" + quote_plus(query))

    def _open_url(self, url: str) -> None:
        try:
            webbrowser.open(url)
            self._set_status(f"Открыто в браузере: {url}")
        except Exception as exc:
            messagebox.showerror("Ошибка", f"Не удалось открыть ссылку: {exc}", parent=self.root)

    # ------------------------------------------------------------------
    # VirusTotal
    # ------------------------------------------------------------------

    def check_virustotal(self) -> None:
        record = self._selected_record()
        if not record:
            return

        api_key = str(self.config.get("vt_api_key") or "")
        if not api_key:
            self.open_settings()
            api_key = str(self.config.get("vt_api_key") or "")
            if not api_key:
                return

        if record.name in self._vt_inflight:
            self._set_status("VirusTotal: запрос уже выполняется…")
            return
        if not record.path_for_display or not os.path.isfile(record.path_for_display):
            messagebox.showwarning(
                "Файл не найден",
                "Проверить в VirusTotal можно только существующий файл.",
                parent=self.root,
            )
            return

        self._vt_inflight.add(record.name)
        self._set_status(
            f"VirusTotal: вычисляю хэш и запрашиваю отчёт для {record.name}…"
        )
        thread = threading.Thread(
            target=self._vt_worker,
            args=(
                record.name,
                record.path_for_display,
                record.sha256,
                api_key,
            ),
            daemon=True,
        )
        thread.start()

    def _vt_worker(self, name: str, path: str, sha256: str, api_key: str) -> None:
        try:
            if not sha256:
                sha256 = sha256_file(path)
                if sha256:
                    self.queue.put(("hash", (name, sha256)))
            if not sha256:
                self.queue.put(
                    ("vt_error", (name, "Не удалось вычислить SHA-256 файла."))
                )
                return
            result = lookup_hash(api_key, sha256)
            self.queue.put(("vt", (name, result)))
        except VirusTotalError as exc:
            self.queue.put(("vt_error", (name, str(exc))))
        except Exception as exc:
            log.exception("Ошибка VirusTotal")
            self.queue.put(("vt_error", (name, f"Неожиданная ошибка: {exc}")))

    def _handle_vt_result(self, name: str, result: dict) -> None:
        self._vt_inflight.discard(name)
        record = self._by_name.get(name)
        if not record:
            return
        apply_virustotal_result(record, result)
        self._update_summary_cards()
        self.render_table()
        if self._selected_name == name:
            self.show_record(record)
        self._set_status(
            "VirusTotal: {} — обнаружений {} из {}".format(
                name,
                result.get("malicious", 0) + result.get("suspicious", 0),
                result.get("total", "?"),
            )
            if result.get("found")
            else f"VirusTotal: файл {name} отсутствует в базе"
        )
        messagebox.showinfo(
            "VirusTotal", format_result(result), parent=self.root
        )
        if result.get("link") and messagebox.askyesno(
            "VirusTotal",
            "Открыть подробный отчёт в браузере?",
            parent=self.root,
        ):
            self._open_url(result["link"])

    # ------------------------------------------------------------------
    # Настройки и справка
    # ------------------------------------------------------------------

    def open_settings(self) -> None:
        window = tk.Toplevel(self.root)
        window.title("Настройки")
        window.transient(self.root)
        window.resizable(False, False)
        window.grab_set()

        frame = ttk.Frame(window, padding=18)
        frame.pack(fill=tk.BOTH, expand=True)

        ttk.Label(
            frame,
            text="API-ключ VirusTotal",
            font=("Segoe UI", 10, "bold"),
        ).pack(anchor="w")
        ttk.Label(
            frame,
            text=(
                "Ключ нужен только для добровольной проверки файлов по SHA-256. "
                "Сам файл не загружается. Ключ хранится локально в файле "
                "настроек в открытом виде."
            ),
            wraplength=520,
            style="Muted.TLabel",
            justify=tk.LEFT,
        ).pack(anchor="w", pady=(2, 10))

        key_var = tk.StringVar(value=str(self.config.get("vt_api_key") or ""))
        entry = ttk.Entry(frame, textvariable=key_var, width=64, show="*")
        entry.pack(fill=tk.X)
        entry.focus_set()

        show_var = tk.BooleanVar(value=False)
        ttk.Checkbutton(
            frame,
            text="Показать ключ",
            variable=show_var,
            command=lambda: entry.configure(show="" if show_var.get() else "*"),
        ).pack(anchor="w", pady=(4, 2))

        link = ttk.Label(
            frame,
            text="Получить бесплатный ключ на virustotal.com",
            foreground="#0b5cad",
            cursor="hand2",
        )
        link.pack(anchor="w", pady=(0, 8))
        link.bind(
            "<Button-1>",
            lambda event: self._open_url("https://www.virustotal.com/gui/my-apikey"),
        )

        ttk.Label(
            frame,
            text=(
                "Бесплатный тариф VirusTotal: 4 запроса в минуту. Если ключ "
                "не нужен, просто оставьте поле пустым."
            ),
            wraplength=520,
            style="Small.TLabel",
            justify=tk.LEFT,
        ).pack(anchor="w", pady=(0, 12))

        buttons = ttk.Frame(frame)
        buttons.pack(fill=tk.X, pady=(8, 0))

        def save() -> None:
            self.config["vt_api_key"] = key_var.get().strip()
            if save_config(self.config):
                self._refresh_security_status()
                self._set_status(
                    "Настройки сохранены"
                    if self.config["vt_api_key"]
                    else "API-ключ VirusTotal удалён"
                )
                if self._selected_record():
                    self.show_record(self._selected_record())
            else:
                messagebox.showerror(
                    "Ошибка",
                    "Не удалось сохранить настройки. Проверьте журнал.",
                    parent=window,
                )
            window.destroy()

        ttk.Button(buttons, text="Сохранить", command=save).pack(side=tk.RIGHT)
        ttk.Button(buttons, text="Отмена", command=window.destroy).pack(
            side=tk.RIGHT, padx=(0, 8)
        )

        window.update_idletasks()
        self._center_window(window, 620, 340)
        window.wait_window()

    def show_help(self) -> None:
        self._show_text_window("Как читать результаты", HELP_TEXT, 920, 720)

    def show_about(self) -> None:
        self._show_text_window("О программе", ABOUT_TEXT, 660, 420)

    def _show_text_window(self, title: str, text: str, width: int, height: int) -> None:
        window = tk.Toplevel(self.root)
        window.title(title)
        window.transient(self.root)
        frame = ttk.Frame(window, padding=12)
        frame.pack(fill=tk.BOTH, expand=True)

        text_widget = tk.Text(
            frame,
            wrap="word",
            font=("Segoe UI", 9),
            padx=10,
            pady=8,
            borderwidth=0,
            highlightthickness=1,
            highlightbackground="#dbe2e8",
        )
        scroll = ttk.Scrollbar(frame, orient="vertical", command=text_widget.yview)
        text_widget.configure(yscrollcommand=scroll.set)
        text_widget.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        scroll.pack(side=tk.RIGHT, fill=tk.Y)
        text_widget.insert("1.0", text)
        text_widget.configure(state=tk.DISABLED)

        ttk.Button(window, text="Закрыть", command=window.destroy).pack(
            pady=(0, 10)
        )
        self._center_window(window, width, height)

    def _center_window(self, window: tk.Toplevel, width: int, height: int) -> None:
        try:
            self.root.update_idletasks()
            x = self.root.winfo_rootx() + max(0, (self.root.winfo_width() - width) // 2)
            y = self.root.winfo_rooty() + max(0, (self.root.winfo_height() - height) // 2)
            window.geometry(f"{width}x{height}+{x}+{y}")
        except Exception:
            window.geometry(f"{width}x{height}")

    def relaunch_as_admin(self) -> None:
        try:
            if getattr(sys, "frozen", False):
                executable = sys.executable
                params = ""
            else:
                executable = sys.executable
                params = f'"{Path(sys.argv[0]).resolve()}"'
            result = ctypes.windll.shell32.ShellExecuteW(
                None, "runas", executable, params, None, 1
            )
            if int(result) <= 32:
                messagebox.showerror(
                    "Не удалось перезапустить",
                    "Запуск от имени администратора отменён или запрещён.",
                    parent=self.root,
                )
            else:
                self.root.destroy()
        except Exception as exc:
            messagebox.showerror(
                "Ошибка", f"Не удалось перезапустить программу: {exc}", parent=self.root
            )

    # ------------------------------------------------------------------
    # Экспорт
    # ------------------------------------------------------------------

    def export_report(self, fmt: str) -> None:
        if not self.scan_result or not self.records:
            messagebox.showinfo(
                "Экспорт",
                "Сначала выполните сканирование.",
                parent=self.root,
            )
            return

        filetypes = {
            "html": [("HTML-отчёт", "*.html"), ("Все файлы", "*.*")],
            "csv": [("CSV-таблица", "*.csv"), ("Все файлы", "*.*")],
            "json": [("JSON-данные", "*.json"), ("Все файлы", "*.*")],
        }
        titles = {
            "html": "Сохранить HTML-отчёт",
            "csv": "Сохранить CSV-таблицу",
            "json": "Сохранить JSON",
        }
        initial_dir = str(self.config.get("last_export_dir") or "")
        path = filedialog.asksaveasfilename(
            parent=self.root,
            title=titles.get(fmt, "Экспорт"),
            defaultextension=f".{fmt}",
            initialfile=default_export_name(fmt),
            initialdir=initial_dir or None,
            filetypes=filetypes.get(fmt, [("Все файлы", "*.*")]),
        )
        if not path:
            return

        try:
            if fmt == "html":
                export_html(self.scan_result, path)
            elif fmt == "csv":
                export_csv(self.scan_result, path)
            else:
                export_json(self.scan_result, path)
            self.config["last_export_dir"] = str(Path(path).parent)
            save_config(self.config)
            self._set_status(f"Отчёт сохранён: {path}")
            if messagebox.askyesno(
                "Экспорт",
                f"Отчёт сохранён:\n{path}\n\nОткрыть его сейчас?",
                parent=self.root,
            ):
                os.startfile(path)
        except Exception as exc:
            log.exception("Ошибка экспорта")
            messagebox.showerror(
                "Ошибка экспорта",
                f"Не удалось сохранить отчёт: {exc}",
                parent=self.root,
            )

    # ------------------------------------------------------------------
    # Завершение
    # ------------------------------------------------------------------

    def on_close(self) -> None:
        if self._scan_thread and self._scan_thread.is_alive():
            if not messagebox.askyesno(
                "Сканирование",
                "Сканирование ещё выполняется. Остановить его и выйти?",
                parent=self.root,
            ):
                return
            self._cancel_event.set()
        self.config["include_drivers"] = bool(self._include_drivers_var.get())
        self.config["live_metrics"] = bool(self._live_var.get())
        self.config["deep_acl"] = bool(self._deep_acl_var.get())
        save_config(self.config)
        try:
            self.root.destroy()
        except Exception:
            pass


# ---------------------------------------------------------------------------
# Форматирование
# ---------------------------------------------------------------------------

def _format_size(size: int) -> str:
    if not size:
        return "—"
    value = float(size)
    for unit in ("Б", "КБ", "МБ", "ГБ"):
        if value < 1024 or unit == "ГБ":
            return f"{value:.1f} {unit}" if unit != "Б" else f"{int(value)} Б"
        value /= 1024
    return f"{size} Б"


def _format_datetime(value) -> str:
    if not value:
        return "—"
    try:
        return value.strftime("%d.%m.%Y %H:%M:%S")
    except Exception:
        return str(value)


def _format_iso_date(value: str) -> str:
    try:
        from datetime import datetime

        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
        return parsed.astimezone().strftime("%d.%m.%Y %H:%M")
    except Exception:
        return value
