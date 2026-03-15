from __future__ import annotations

import json
from pathlib import Path

from .models import RemediationException


class RemediationExceptionStore:
    def __init__(self, path: Path) -> None:
        self.path = path
        self.path.parent.mkdir(parents=True, exist_ok=True)
        if not self.path.exists():
            self.path.write_text("[]", encoding="utf-8")

    def list_all(self) -> list[RemediationException]:
        payload = json.loads(self.path.read_text(encoding="utf-8"))
        if not isinstance(payload, list):
            raise ValueError("Remediation exception store must contain a JSON array.")
        return [RemediationException.model_validate(item) for item in payload]

    def save_all(self, items: list[RemediationException]) -> None:
        serialized = [item.model_dump(mode="json") for item in items]
        self.path.write_text(json.dumps(serialized, indent=2), encoding="utf-8")
