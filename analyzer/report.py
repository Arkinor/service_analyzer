"""Экспорт результатов сканирования в HTML, CSV и JSON."""

from __future__ import annotations

import csv
import html
import json
from datetime import datetime
from pathlib import Path
from typing import Any

from . import constants as C
from .models import ScanResult, ServiceRecord
from .winapi import get_computer_caption

SIGNATURE_LABELS = {
    "Valid": "Действительна",
    "NotSigned": "Нет подписи",
    "HashMismatch": "Хэш не совпадает",
    "NotTrusted": "Не доверенная",
    "UnknownError": "Ошибка проверки",
    "Error": "Ошибка",
    "Missing": "Файл не найден",
    "Unknown": "Не проверена",
    "NotSupportedFileFormat": "Формат не поддержан",
}


def signature_label(status: str) -> str:
    return SIGNATURE_LABELS.get(status, status or "—")


def _format_size(size: int) -> str:
    if not size:
        return "—"
    value = float(size)
    for unit in ("Б", "КБ", "МБ", "ГБ"):
        if value < 1024 or unit == "ГБ":
            return f"{value:.1f} {unit}" if unit != "Б" else f"{int(value)} Б"
        value /= 1024
    return f"{size} Б"


def _format_date(value) -> str:
    if not value:
        return "—"
    try:
        return value.strftime("%d.%m.%Y %H:%M")
    except Exception:
        return str(value)


def _level_label(level: str) -> str:
    return f"{C.LEVEL_ICONS.get(level, '')} {C.LEVEL_LABELS.get(level, level)}".strip()


def _record_sort_key(record: ServiceRecord) -> tuple:
    return (
        -C.LEVEL_ORDER.get(record.level, 0),
        -record.score,
        (record.display_name or record.name).lower(),
    )


def result_to_dict(result: ScanResult) -> dict[str, Any]:
    return {
        "app": C.APP_NAME,
        "version": C.APP_VERSION,
        "computer": get_computer_caption(),
        "generated_at": datetime.now().astimezone().isoformat(timespec="seconds"),
        "started_at": result.started_at.isoformat(timespec="seconds"),
        "finished_at": (
            result.finished_at.isoformat(timespec="seconds")
            if result.finished_at
            else None
        ),
        "duration_seconds": round(result.duration_seconds, 1),
        "is_admin": result.is_admin,
        "options": {
            "include_drivers": result.options.include_drivers,
            "live_metrics": result.options.live_metrics,
            "deep_acl": result.options.deep_acl,
        },
        "counts": result.counts(),
        "errors": result.errors,
        "records": [record.to_dict() for record in sorted(result.records, key=_record_sort_key)],
    }


def export_json(result: ScanResult, path: str) -> None:
    Path(path).write_text(
        json.dumps(result_to_dict(result), ensure_ascii=False, indent=2),
        encoding="utf-8",
    )


def export_csv(result: ScanResult, path: str) -> None:
    headers = [
        "Уровень",
        "Баллы",
        "Служба",
        "Отображаемое имя",
        "Тип",
        "Состояние",
        "Запуск",
        "Учётная запись",
        "PID",
        "Издатель",
        "Подпись",
        "Путь",
        "Компания",
        "Версия",
        "Создан",
        "SHA-256",
        "Причины",
        "Что делать",
    ]
    with open(path, "w", encoding="utf-8-sig", newline="") as handle:
        writer = csv.writer(handle, delimiter=";", lineterminator="\n")
        writer.writerow(headers)
        for record in sorted(result.records, key=_record_sort_key):
            findings = " | ".join(
                f"{finding.title} (+{finding.weight})"
                for finding in record.findings
                if finding.weight > 0
            )
            advice = " | ".join(
                finding.advice for finding in record.findings if finding.advice
            )
            writer.writerow(
                [
                    C.LEVEL_LABELS.get(record.level, record.level),
                    record.score,
                    record.name,
                    record.display_name,
                    "Драйвер" if record.kind == "driver" else "Служба",
                    record.state_label,
                    record.start_label,
                    record.account_label,
                    record.pid or "",
                    record.publisher,
                    signature_label(record.signature.status),
                    record.path_for_display,
                    record.file.company,
                    record.file.version,
                    _format_date(record.file.created),
                    record.sha256,
                    findings,
                    advice,
                ]
            )


def export_html(result: ScanResult, path: str) -> None:
    counts = result.counts()
    generated = datetime.now().astimezone().strftime("%d.%m.%Y %H:%M:%S")
    records = sorted(result.records, key=_record_sort_key)

    level_classes = {
        C.LEVEL_DANGER: "danger",
        C.LEVEL_SUSPICIOUS: "suspicious",
        C.LEVEL_CHECK: "check",
        C.LEVEL_SAFE: "safe",
    }

    rows: list[str] = []
    details_blocks: list[str] = []
    for record in records:
        level_class = level_classes.get(record.level, "safe")
        rows.append(
            "<tr class='{cls}'>"
            "<td><span class='badge {cls}'>{level}</span></td>"
            "<td class='score'>{score}</td>"
            "<td><b>{display}</b><div class='muted small'>{name} · {kind}</div></td>"
            "<td>{state}</td><td>{start}</td><td>{account}</td>"
            "<td>{publisher}</td><td>{signature}</td>"
            "<td class='path'>{path}</td>"
            "</tr>".format(
                cls=level_class,
                level=html.escape(_level_label(record.level)),
                score=record.score,
                display=html.escape(record.display_name or record.name),
                name=html.escape(record.name),
                kind="драйвер" if record.kind == "driver" else "служба",
                state=html.escape(record.state_label),
                start=html.escape(record.start_label),
                account=html.escape(record.account_label),
                publisher=html.escape(record.publisher or "—"),
                signature=html.escape(signature_label(record.signature.status)),
                path=html.escape(record.path_for_display or "—"),
            )
        )

        if record.findings or record.positives or record.level != C.LEVEL_SAFE:
            findings_html = []
            for finding in record.findings:
                advice = (
                    f"<div class='advice'><b>Что делать:</b> {html.escape(finding.advice)}</div>"
                    if finding.advice
                    else ""
                )
                findings_html.append(
                    "<li class='finding {severity}'>"
                    "<b>{title}</b> <span class='weight'>(+{weight})</span>"
                    "<div>{detail}</div>{advice}</li>".format(
                        severity=html.escape(finding.severity),
                        title=html.escape(finding.title),
                        weight=finding.weight,
                        detail=html.escape(finding.detail),
                        advice=advice,
                    )
                )
            positives_html = "".join(
                f"<li class='positive'>{html.escape(item)}</li>"
                for item in record.positives
            )
            details_blocks.append(
                "<details class='record {cls}'>"
                "<summary><span class='badge {cls}'>{level}</span> "
                "<b>{display}</b> <span class='muted'>· {name} · {state} · "
                "баллы: {score}</span></summary>"
                "<div class='detail-body'>"
                "<p class='muted'>{description}</p>"
                "<p><b>Файл:</b> <span class='path'>{path}</span></p>"
                "<p><b>Издатель:</b> {publisher} &nbsp; <b>Подпись:</b> {signature} "
                "&nbsp; <b>Компания:</b> {company} &nbsp; <b>Версия:</b> {version}</p>"
                "<p><b>SHA-256:</b> <span class='hash'>{sha}</span></p>"
                "<h4>Причины оценки</h4><ul class='findings'>{findings}</ul>"
                "<h4>Положительные признаки</h4><ul class='findings'>{positives}</ul>"
                "</div></details>".format(
                    cls=level_class,
                    level=html.escape(_level_label(record.level)),
                    display=html.escape(record.display_name or record.name),
                    name=html.escape(record.name),
                    state=html.escape(record.state_label),
                    score=record.score,
                    description=html.escape(record.description or "Описание отсутствует."),
                    path=html.escape(record.path_for_display or "—"),
                    publisher=html.escape(record.publisher or "—"),
                    signature=html.escape(signature_label(record.signature.status)),
                    company=html.escape(record.file.company or "—"),
                    version=html.escape(record.file.version or "—"),
                    sha=html.escape(record.sha256 or "не вычислялся"),
                    findings="".join(findings_html) or "<li>Нет</li>",
                    positives=positives_html or "<li>Нет</li>",
                )
            )

    errors_html = (
        "<div class='warn'><b>Предупреждения:</b><ul>"
        + "".join(f"<li>{html.escape(error)}</li>" for error in result.errors)
        + "</ul></div>"
        if result.errors
        else ""
    )

    document = """<!DOCTYPE html>
<html lang="ru">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{title} — отчёт</title>
<style>
:root {{ color-scheme: light; }}
* {{ box-sizing: border-box; }}
body {{ margin: 0; padding: 32px; font: 14px/1.5 "Segoe UI", Arial, sans-serif;
       color: #1f2933; background: #f4f6f8; }}
.wrap {{ max-width: 1500px; margin: 0 auto; }}
h1 {{ margin: 0 0 4px; font-size: 28px; }}
h2 {{ margin-top: 32px; font-size: 20px; }}
h4 {{ margin: 18px 0 6px; font-size: 14px; }}
.muted {{ color: #66727d; }}
.small {{ font-size: 12px; }}
.cards {{ display: flex; flex-wrap: wrap; gap: 12px; margin: 20px 0; }}
.card {{ background: white; border-radius: 10px; padding: 14px 18px; min-width: 150px;
         border-left: 5px solid #cbd5e1; box-shadow: 0 1px 2px rgba(0,0,0,.06); }}
.card .num {{ font-size: 26px; font-weight: 700; }}
.card.danger {{ border-color: #dc2626; }} .card.suspicious {{ border-color: #ea580c; }}
.card.check {{ border-color: #ca8a04; }} .card.safe {{ border-color: #16a34a; }}
.card.total {{ border-color: #2563eb; }}
table {{ width: 100%; border-collapse: collapse; background: white; border-radius: 10px;
         overflow: hidden; box-shadow: 0 1px 2px rgba(0,0,0,.06); }}
th, td {{ padding: 9px 10px; text-align: left; vertical-align: top; border-bottom: 1px solid #e5e7eb; }}
th {{ background: #eef2f6; font-size: 12px; text-transform: uppercase; letter-spacing: .04em; }}
tr.danger td {{ background: #fff1f1; }} tr.suspicious td {{ background: #fff7ed; }}
tr.check td {{ background: #fefce8; }} tr.safe td {{ background: #f0fdf4; }}
.badge {{ display: inline-block; padding: 2px 8px; border-radius: 999px; font-weight: 600;
          white-space: nowrap; font-size: 12px; }}
.badge.danger {{ background: #fee2e2; color: #991b1b; }}
.badge.suspicious {{ background: #ffedd5; color: #9a3412; }}
.badge.check {{ background: #fef9c3; color: #854d0e; }}
.badge.safe {{ background: #dcfce7; color: #166534; }}
.score {{ font-weight: 700; }}
.path {{ font-family: Consolas, monospace; font-size: 12px; word-break: break-all; max-width: 380px; }}
.hash {{ font-family: Consolas, monospace; font-size: 11px; word-break: break-all; }}
details.record {{ background: white; border-radius: 8px; margin: 10px 0; padding: 12px 16px;
                  border-left: 4px solid #cbd5e1; box-shadow: 0 1px 2px rgba(0,0,0,.05); }}
details.record.danger {{ border-color: #dc2626; }}
details.record.suspicious {{ border-color: #ea580c; }}
details.record.check {{ border-color: #ca8a04; }}
details.record.safe {{ border-color: #16a34a; }}
details.record summary {{ cursor: pointer; }}
.detail-body {{ margin-top: 12px; }}
ul.findings {{ margin: 6px 0 0; padding-left: 20px; }}
ul.findings li {{ margin-bottom: 10px; }}
li.finding.critical {{ color: #991b1b; }} li.finding.high {{ color: #9a3412; }}
li.finding.medium {{ color: #854d0e; }} li.finding.low {{ color: #475569; }}
li.finding.info {{ color: #475569; }} li.positive {{ color: #166534; }}
.weight {{ color: #64748b; font-weight: 400; }}
.advice {{ margin-top: 4px; padding: 6px 9px; background: #f8fafc; border-radius: 5px;
           color: #334155; font-size: 13px; }}
.warn {{ background: #fff7ed; border-left: 4px solid #f59e0b; padding: 12px 16px;
         border-radius: 6px; margin: 18px 0; }}
footer {{ margin-top: 40px; padding-top: 16px; border-top: 1px solid #dbe2e8;
          color: #66727d; font-size: 12px; }}
@media print {{ body {{ background: white; padding: 0; }} .card, table, details {{ box-shadow: none; }}
  details.record {{ break-inside: avoid; }} }}
</style>
</head>
<body>
<div class="wrap">
<h1>{title}</h1>
<div class="muted">Отчёт создан {generated} · {computer}</div>
<div class="muted">Сканирование: {started} — {finished} ({duration} с). {options}</div>

<div class="cards">
  <div class="card total"><div class="num">{total}</div><div>Всего проверено</div></div>
  <div class="card danger"><div class="num">{danger}</div><div>Опасно</div></div>
  <div class="card suspicious"><div class="num">{suspicious}</div><div>Подозрительно</div></div>
  <div class="card check"><div class="num">{check}</div><div>Проверить</div></div>
  <div class="card safe"><div class="num">{safe}</div><div>Безопасно</div></div>
</div>

<div class="warn"><b>Как читать отчёт.</b> «Безопасно» означает, что не найдено
признаков подмены, майнера или странного расположения файла. Это не гарантия
чистоты системы. «Проверить» — повод взглянуть на издателя, «Подозрительно» —
проверить файл в VirusTotal, «Опасно» — не запускать и проверить антивирусом.</div>
{errors}

<h2>Список служб</h2>
<table>
<thead><tr><th>Уровень</th><th>Баллы</th><th>Служба</th><th>Состояние</th>
<th>Запуск</th><th>Учётная запись</th><th>Издатель</th><th>Подпись</th><th>Путь</th></tr></thead>
<tbody>{rows}</tbody>
</table>

<h2>Подробности и объяснения</h2>
{details}

<footer>
<p>{disclaimer}</p>
<p>Локальный файл: {path}</p>
</footer>
</div>
</body>
</html>
""".format(
        title=html.escape(C.APP_NAME),
        generated=html.escape(generated),
        computer=html.escape(get_computer_caption()),
        started=html.escape(result.started_at.strftime("%d.%m.%Y %H:%M:%S")),
        finished=html.escape(
            result.finished_at.strftime("%d.%m.%Y %H:%M:%S")
            if result.finished_at
            else "—"
        ),
        duration=round(result.duration_seconds, 1),
        options=html.escape(
            "Драйверы: {0}; поведение: {1}; права на папки: {2}; права администратора: {3}".format(
                "да" if result.options.include_drivers else "нет",
                "да" if result.options.live_metrics else "нет",
                "да" if result.options.deep_acl else "нет",
                "да" if result.is_admin else "нет",
            )
        ),
        total=len(result.records),
        danger=counts.get(C.LEVEL_DANGER, 0),
        suspicious=counts.get(C.LEVEL_SUSPICIOUS, 0),
        check=counts.get(C.LEVEL_CHECK, 0),
        safe=counts.get(C.LEVEL_SAFE, 0),
        errors=errors_html,
        rows="\n".join(rows) or "<tr><td colspan='9'>Нет данных</td></tr>",
        details="\n".join(details_blocks) or "<p class='muted'>Подробностей нет.</p>",
        disclaimer=html.escape(C.RECOMMENDATION_DISCLAIMER),
        path=html.escape(str(Path(path).resolve())),
    )

    Path(path).write_text(document, encoding="utf-8")


def default_export_name(extension: str) -> str:
    stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    return f"service_report_{stamp}.{extension}"
