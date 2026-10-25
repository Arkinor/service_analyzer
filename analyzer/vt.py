"""Минимальный клиент VirusTotal: проверка только по SHA-256.

Файл на VirusTotal не загружается. Отправляется только хэш, что не раскрывает
содержимое файла. Для работы нужен бесплатный API-ключ пользователя.
"""

from __future__ import annotations

import json
import urllib.error
import urllib.request
from datetime import datetime, timezone
from typing import Any

API_URL = "https://www.virustotal.com/api/v3/files/"
PUBLIC_URL = "https://www.virustotal.com/gui/file/"


class VirusTotalError(Exception):
    pass


def lookup_hash(api_key: str, sha256: str, timeout: int = 25) -> dict[str, Any]:
    """Возвращает краткую сводку по хэшу или выбрасывает VirusTotalError."""
    if not api_key:
        raise VirusTotalError("Не задан API-ключ VirusTotal.")
    if not sha256:
        raise VirusTotalError("Не удалось вычислить SHA-256 файла.")

    request = urllib.request.Request(
        API_URL + sha256,
        headers={
            "x-apikey": api_key.strip(),
            "accept": "application/json",
            "user-agent": "ServiceAnalyzer/2.0",
        },
    )
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            payload = json.loads(response.read().decode("utf-8"))
    except urllib.error.HTTPError as exc:
        if exc.code == 404:
            return {
                "found": False,
                "link": PUBLIC_URL + sha256,
                "sha256": sha256,
            }
        if exc.code == 401:
            raise VirusTotalError(
                "VirusTotal отклонил API-ключ (401). Проверьте ключ в настройках."
            ) from exc
        if exc.code == 429:
            raise VirusTotalError(
                "Превышен лимит VirusTotal (429). Бесплатный ключ допускает "
                "4 запроса в минуту. Попробуйте позже."
            ) from exc
        raise VirusTotalError(f"VirusTotal вернул ошибку HTTP {exc.code}.") from exc
    except urllib.error.URLError as exc:
        raise VirusTotalError(f"Нет связи с VirusTotal: {exc.reason}") from exc
    except Exception as exc:
        raise VirusTotalError(f"Не удалось запросить VirusTotal: {exc}") from exc

    try:
        attributes = payload["data"]["attributes"]
        stats = attributes.get("last_analysis_stats") or {}
        malicious = int(stats.get("malicious") or 0)
        suspicious = int(stats.get("suspicious") or 0)
        undetected = int(stats.get("undetected") or 0)
        harmless = int(stats.get("harmless") or 0)
        total = malicious + suspicious + undetected + harmless
        timestamp = attributes.get("last_analysis_date")
        analyzed = ""
        if timestamp:
            try:
                analyzed = datetime.fromtimestamp(
                    int(timestamp), tz=timezone.utc
                ).astimezone().strftime("%d.%m.%Y %H:%M")
            except (ValueError, OSError):
                analyzed = ""
        return {
            "found": True,
            "sha256": sha256,
            "malicious": malicious,
            "suspicious": suspicious,
            "undetected": undetected,
            "harmless": harmless,
            "total": total,
            "name": attributes.get("meaningful_name") or "",
            "reputation": attributes.get("reputation"),
            "last_analysis_date": analyzed,
            "link": PUBLIC_URL + sha256,
        }
    except Exception as exc:
        raise VirusTotalError("Не удалось разобрать ответ VirusTotal.") from exc


def format_result(result: dict[str, Any]) -> str:
    if not result:
        return "Нет данных."
    if not result.get("found"):
        return (
            "Файл с таким хэшем отсутствует в базе VirusTotal.\n\n"
            "Это не означает, что файл безопасен: он может быть новым или "
            "уникальным. При сомнениях загрузите файл на VirusTotal вручную."
        )
    malicious = result.get("malicious", 0)
    suspicious = result.get("suspicious", 0)
    total = result.get("total", 0)
    lines = [
        f"Обнаружений: {malicious + suspicious} из {total}",
        f"Вредоносных: {malicious}",
        f"Подозрительных: {suspicious}",
    ]
    if result.get("name"):
        lines.append(f"Имя в базе: {result['name']}")
    if result.get("last_analysis_date"):
        lines.append(f"Последняя проверка: {result['last_analysis_date']}")
    if result.get("reputation") is not None:
        lines.append(f"Репутация: {result['reputation']}")
    lines.append("")
    lines.append(result.get("link", ""))
    return "\n".join(lines)
