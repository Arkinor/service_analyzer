"""Точка входа приложения «Анализатор служб Windows»."""

from __future__ import annotations

import ctypes
import logging
import os
import sys
import traceback
from logging.handlers import RotatingFileHandler

from analyzer.config import log_dir, log_path


def setup_logging() -> None:
    try:
        log_dir().mkdir(parents=True, exist_ok=True)
        handler = RotatingFileHandler(
            log_path(),
            maxBytes=1_500_000,
            backupCount=3,
            encoding="utf-8",
        )
        formatter = logging.Formatter(
            "%(asctime)s %(levelname)-7s %(name)s: %(message)s",
            datefmt="%Y-%m-%d %H:%M:%S",
        )
        handler.setFormatter(formatter)
        root_logger = logging.getLogger()
        root_logger.setLevel(logging.INFO)
        root_logger.addHandler(handler)
        if sys.stderr is not None and not getattr(sys, "frozen", False):
            console = logging.StreamHandler()
            console.setFormatter(formatter)
            root_logger.addHandler(console)
    except Exception:
        # Логирование не должно мешать запуску приложения.
        pass


def main() -> int:
    if os.name != "nt":
        print("Эта программа работает только в Windows.")
        return 1

    setup_logging()
    log = logging.getLogger("service_analyzer")
    log.info("Запуск %s", sys.argv)

    try:
        from analyzer.ui import ServiceAnalyzerApp
        from analyzer.winapi import enable_dpi_awareness
        import tkinter as tk

        enable_dpi_awareness()
        root = tk.Tk()
        auto_scan = "--no-scan" not in sys.argv
        ServiceAnalyzerApp(root, auto_scan=auto_scan)
        root.mainloop()
        return 0
    except Exception as exc:
        log.exception("Критическая ошибка приложения")
        message = (
            "Произошла критическая ошибка:\n\n"
            f"{exc}\n\n"
            f"Подробности записаны в журнал:\n{log_path()}"
        )
        try:
            ctypes.windll.user32.MessageBoxW(None, message, "Анализатор служб Windows", 0x10)
        except Exception:
            print(message)
            traceback.print_exc()
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
