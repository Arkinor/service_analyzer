"""Анализатор служб Windows.

Пакет разделён по ответственности:
- constants — справочники и тексты уровней;
- models — структуры данных;
- winapi — реестр, подписи, свойства файлов, ACL, поведение;
- collector — конвейер сбора данных;
- rules — правила оценки и объяснения;
- report — экспорт HTML/CSV/JSON;
- ui — интерфейс Tkinter;
- vt — необязательная проверка SHA-256 в VirusTotal.
"""

from .constants import APP_NAME, APP_VERSION

__all__ = ["APP_NAME", "APP_VERSION"]
