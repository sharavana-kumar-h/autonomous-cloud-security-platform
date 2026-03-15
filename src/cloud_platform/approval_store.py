from __future__ import annotations

import json
from pathlib import Path

from .models import RemediationApprovalRecord


class RemediationApprovalStore:
    def __init__(self, path: Path) -> None:
        self.path = path
        self.path.parent.mkdir(parents=True, exist_ok=True)
        if not self.path.exists():
            self.path.write_text("[]", encoding="utf-8")

    def list_all(self) -> list[RemediationApprovalRecord]:
        payload = json.loads(self.path.read_text(encoding="utf-8"))
        if not isinstance(payload, list):
            raise ValueError("Remediation approval store must contain a JSON array.")
        normalized: list[RemediationApprovalRecord] = []
        changed = False
        for item in payload:
            if "approver_role" not in item:
                item = {**item, "approver_role": "platform_admin"}
                changed = True
            if "stage_name" not in item:
                item = {**item, "stage_name": None}
                changed = True
            if "revoked_at" not in item:
                item = {**item, "revoked_at": None, "revoked_by": None, "revoke_reason": None}
                changed = True
            normalized.append(RemediationApprovalRecord.model_validate(item))
        if changed:
            self.save_all(normalized)
        return normalized

    def save_all(self, items: list[RemediationApprovalRecord]) -> None:
        serialized = [item.model_dump(mode="json") for item in items]
        self.path.write_text(json.dumps(serialized, indent=2), encoding="utf-8")
