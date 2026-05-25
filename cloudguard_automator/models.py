from __future__ import annotations

from dataclasses import asdict, dataclass
from enum import Enum

from cloudguard_automator.control_mapping import controls_for_check


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

    @property
    def control_refs(self) -> list[str]:
        return controls_for_check(self.check_id)

    def to_dict(self) -> dict[str, object]:
        data = asdict(self)
        data["severity"] = self.severity.value
        data["control_refs"] = self.control_refs
        return data
