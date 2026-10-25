"""Небольшое хранилище настроек в %APPDATA%\\ServiceAnalyzer\\config.json."""

from __future__ import annotations

import json
import logging
import os
from pathlib import Path
from typing import Any

log = logging.getLogger(__name__)

DEFAULT_CONFIG: dict[str, Any] = {
    "vt_api_key": "",
    "include_drivers": False,
    "live_metrics": True,
    "deep_acl": False,
    "show_drivers": True,
    "window_geometry": "",
}


def config_dir() -> Path:
    base = os.environ.get("APPDATA") or str(Path.home())
    return Path(base) / "ServiceAnalyzer"


def config_path() -> Path:
    return config_dir() / "config.json"


def load_config() -> dict[str, Any]:
    data = dict(DEFAULT_CONFIG)
    path = config_path()
    try:
        if path.exists():
            loaded = json.loads(path.read_text(encoding="utf-8"))
            if isinstance(loaded, dict):
                data.update(loaded)
    except Exception as exc:
        log.warning("Не удалось прочитать настройки: %s", exc)
    return data


def save_config(config: dict[str, Any]) -> bool:
    path = config_path()
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(
            json.dumps(config, ensure_ascii=False, indent=2),
            encoding="utf-8",
        )
        return True
    except Exception as exc:
        log.warning("Не удалось сохранить настройки: %s", exc)
        return False


def log_dir() -> Path:
    base = os.environ.get("LOCALAPPDATA") or os.environ.get("TEMP") or str(Path.home())
    return Path(base) / "ServiceAnalyzer"


def log_path() -> Path:
    return log_dir() / "service_analyzer.log"
