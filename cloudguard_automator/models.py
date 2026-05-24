from __future__ import annotations

from dataclasses import asdict, dataclass
from enum import Enum


class Severity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


@dataclass(frozen=True)
class Finding:
    check_id: str
    title: str
    severity: Severity
    resource: str
    region: str
    service: str
    description: str
    remediation: str

    def to_dict(self) -> dict[str, str]:
        data = asdict(self)
        data["severity"] = self.severity.value
        return data

