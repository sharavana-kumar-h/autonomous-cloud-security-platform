from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path

from pydantic import BaseModel


class AuditRecord(BaseModel):
    timestamp: datetime
    actor: str
    action: str
    resource_type: str
    resource_id: str
    outcome: str
    details: str


class AuditLogStore:
    def __init__(self, path: Path) -> None:
        self.path = path
        self.path.parent.mkdir(parents=True, exist_ok=True)
        if not self.path.exists():
            self.path.touch()

    def append(self, record: AuditRecord) -> None:
        with self.path.open("a", encoding="utf-8") as handle:
            handle.write(record.model_dump_json())
            handle.write("\n")

    def list_records(self) -> list[AuditRecord]:
        records: list[AuditRecord] = []
        with self.path.open("r", encoding="utf-8") as handle:
            for line in handle:
                payload = line.strip()
                if not payload:
                    continue
                records.append(AuditRecord.model_validate_json(payload))
        return sorted(records, key=lambda item: item.timestamp, reverse=True)


def build_audit_record(
    actor: str,
    action: str,
    resource_type: str,
    resource_id: str,
    outcome: str,
    details: str,
) -> AuditRecord:
    return AuditRecord(
        timestamp=datetime.now(UTC),
        actor=actor,
        action=action,
        resource_type=resource_type,
        resource_id=resource_id,
        outcome=outcome,
        details=details,
    )
