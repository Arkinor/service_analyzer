"""Модели данных анализатора."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Optional


@dataclass
class Finding:
    """Одна причина, влияющая на оценку риска."""

    code: str
    severity: str  # critical | high | medium | low | info | good
    title: str
    detail: str
    advice: str = ""
    weight: int = 0

    def to_dict(self) -> dict[str, Any]:
        return {
            "code": self.code,
            "severity": self.severity,
            "title": self.title,
            "detail": self.detail,
            "advice": self.advice,
            "weight": self.weight,
        }


@dataclass
class FileInfo:
    path: str = ""
    exists: bool = False
    size: int = 0
    created: Optional[datetime] = None
    modified: Optional[datetime] = None
    company: str = ""
    product: str = ""
    description: str = ""
    version: str = ""
    original_name: str = ""
    internal_name: str = ""
    error: str = ""
    access_denied: bool = False

    def to_dict(self) -> dict[str, Any]:
        return {
            "path": self.path,
            "exists": self.exists,
            "size": self.size,
            "created": _iso(self.created),
            "modified": _iso(self.modified),
            "company": self.company,
            "product": self.product,
            "description": self.description,
            "version": self.version,
            "original_name": self.original_name,
            "internal_name": self.internal_name,
            "error": self.error,
            "access_denied": self.access_denied,
        }


@dataclass
class SignatureInfo:
    """Результат проверки Authenticode."""

    status: str = "Unknown"
    status_message: str = ""
    subject: str = ""
    issuer: str = ""
    signer_org: str = ""
    signer_cn: str = ""
    thumbprint: str = ""
    not_after: str = ""
    timestamped: bool = False
    os_binary: bool = False
    error: str = ""

    @property
    def is_valid(self) -> bool:
        return self.status == "Valid"

    @property
    def is_microsoft(self) -> bool:
        text = f"{self.signer_org} {self.signer_cn} {self.subject}".lower()
        return "microsoft" in text

    @property
    def is_hardware_compat(self) -> bool:
        text = f"{self.signer_cn} {self.subject}".lower()
        return "hardware compatibility" in text

    def to_dict(self) -> dict[str, Any]:
        return {
            "status": self.status,
            "status_message": self.status_message,
            "subject": self.subject,
            "issuer": self.issuer,
            "signer_org": self.signer_org,
            "signer_cn": self.signer_cn,
            "thumbprint": self.thumbprint,
            "not_after": self.not_after,
            "timestamped": self.timestamped,
            "os_binary": self.os_binary,
            "error": self.error,
        }


@dataclass
class LiveInfo:
    """Данные о запущенном процессе службы."""

    pid: Optional[int] = None
    cpu_percent: Optional[float] = None
    memory_mb: Optional[float] = None
    parent_pid: Optional[int] = None
    parent_name: str = ""
    process_exe: str = ""
    connections: list[dict[str, Any]] = field(default_factory=list)
    error: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "pid": self.pid,
            "cpu_percent": self.cpu_percent,
            "memory_mb": self.memory_mb,
            "parent_pid": self.parent_pid,
            "parent_name": self.parent_name,
            "process_exe": self.process_exe,
            "connections": self.connections,
            "error": self.error,
        }


@dataclass
class ServiceRecord:
    name: str
    display_name: str = ""
    description: str = ""
    kind: str = "service"  # service | driver
    registry_key: str = ""

    image_path_raw: str = ""
    image_path: str = ""
    image_args: str = ""
    image_quoted: bool = False
    service_dll_raw: str = ""
    service_dll: str = ""
    effective_path: str = ""  # что реально анализируем (exe или ServiceDll)
    is_shared_host: bool = False
    host_exe: str = ""

    service_type: int = 0
    service_type_label: str = ""
    state_code: int = 0
    state_label: str = "Неизвестно"
    start_code: int = -1
    start_label: str = "Неизвестно"
    delayed_start: bool = False
    account: str = ""
    account_label: str = ""
    dependencies: list[str] = field(default_factory=list)
    pid: Optional[int] = None

    file: FileInfo = field(default_factory=FileInfo)
    host_file: Optional[FileInfo] = None
    signature: SignatureInfo = field(default_factory=SignatureInfo)
    host_signature: Optional[SignatureInfo] = None
    live: LiveInfo = field(default_factory=LiveInfo)
    sha256: str = ""
    dir_writable_by_users: Optional[bool] = None
    vt_result: Optional[dict[str, Any]] = None

    findings: list[Finding] = field(default_factory=list)
    positives: list[str] = field(default_factory=list)
    score: int = 0
    level: str = "safe"
    evaluated_at: Optional[datetime] = None

    @property
    def is_running(self) -> bool:
        return self.state_code in (2, 3, 4, 5, 6)

    @property
    def path_for_display(self) -> str:
        return self.effective_path or self.image_path or self.service_dll or ""

    @property
    def publisher(self) -> str:
        return self.signature.signer_org or self.signature.signer_cn or ""

    def add_finding(
        self,
        code: str,
        severity: str,
        title: str,
        detail: str,
        advice: str = "",
        weight: int = 0,
    ) -> None:
        self.findings.append(
            Finding(
                code=code,
                severity=severity,
                title=title,
                detail=detail,
                advice=advice,
                weight=weight,
            )
        )

    def add_positive(self, text: str) -> None:
        if text and text not in self.positives:
            self.positives.append(text)

    def to_dict(self, include_findings: bool = True) -> dict[str, Any]:
        data: dict[str, Any] = {
            "name": self.name,
            "display_name": self.display_name,
            "description": self.description,
            "kind": self.kind,
            "registry_key": self.registry_key,
            "image_path_raw": self.image_path_raw,
            "image_path": self.image_path,
            "image_args": self.image_args,
            "service_dll": self.service_dll,
            "effective_path": self.effective_path,
            "is_shared_host": self.is_shared_host,
            "host_exe": self.host_exe,
            "service_type": self.service_type,
            "service_type_label": self.service_type_label,
            "state_code": self.state_code,
            "state_label": self.state_label,
            "start_code": self.start_code,
            "start_label": self.start_label,
            "delayed_start": self.delayed_start,
            "account": self.account,
            "account_label": self.account_label,
            "dependencies": self.dependencies,
            "pid": self.pid,
            "file": self.file.to_dict(),
            "host_file": self.host_file.to_dict() if self.host_file else None,
            "signature": self.signature.to_dict(),
            "host_signature": self.host_signature.to_dict() if self.host_signature else None,
            "live": self.live.to_dict(),
            "sha256": self.sha256,
            "dir_writable_by_users": self.dir_writable_by_users,
            "vt_result": self.vt_result,
            "score": self.score,
            "level": self.level,
            "positives": self.positives,
            "evaluated_at": _iso(self.evaluated_at),
        }
        if include_findings:
            data["findings"] = [finding.to_dict() for finding in self.findings]
        return data


@dataclass
class ScanOptions:
    include_drivers: bool = False
    live_metrics: bool = True
    deep_acl: bool = False


@dataclass
class ScanResult:
    records: list[ServiceRecord] = field(default_factory=list)
    options: ScanOptions = field(default_factory=ScanOptions)
    started_at: datetime = field(default_factory=lambda: datetime.now())
    finished_at: Optional[datetime] = None
    errors: list[str] = field(default_factory=list)
    is_admin: bool = False
    signature_engine: str = ""
    duration_seconds: float = 0.0

    def counts(self) -> dict[str, int]:
        result = {"safe": 0, "check": 0, "suspicious": 0, "danger": 0}
        for record in self.records:
            result[record.level] = result.get(record.level, 0) + 1
        return result


def _iso(value: Optional[datetime]) -> Optional[str]:
    if not value:
        return None
    if value.tzinfo is None:
        value = value.astimezone()
    return value.isoformat(timespec="seconds")
