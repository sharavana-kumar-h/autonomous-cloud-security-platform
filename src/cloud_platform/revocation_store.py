from __future__ import annotations

import json
from pathlib import Path


class RevocationStore:
    def __init__(self, path: Path) -> None:
        self.path = path
        self.path.parent.mkdir(parents=True, exist_ok=True)
        if not self.path.exists():
            self.path.write_text("[]", encoding="utf-8")

    def revoke(self, jti: str) -> None:
        revoked = set(self._load())
        revoked.add(jti)
        self.path.write_text(json.dumps(sorted(revoked), indent=2), encoding="utf-8")

    def is_revoked(self, jti: str) -> bool:
        return jti in set(self._load())

    def _load(self) -> list[str]:
        payload = json.loads(self.path.read_text(encoding="utf-8"))
        if not isinstance(payload, list):
            raise ValueError("Revocation store must contain a JSON array.")
        return [str(item) for item in payload]
