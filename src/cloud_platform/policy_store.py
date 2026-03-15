from __future__ import annotations

import json
from pathlib import Path

from .models import TenantResponsePolicy


class TenantPolicyStore:
    def __init__(self, path: Path) -> None:
        self.path = path
        self.path.parent.mkdir(parents=True, exist_ok=True)
        if not self.path.exists():
            self.path.write_text("[]", encoding="utf-8")

    def load_all(self) -> dict[str, TenantResponsePolicy]:
        payload = json.loads(self.path.read_text(encoding="utf-8"))
        if not isinstance(payload, list):
            raise ValueError("Tenant policy store must contain a JSON array.")
        policies = [TenantResponsePolicy.model_validate(item) for item in payload]
        return {policy.tenant_id: policy for policy in policies}

    def save_all(self, policies: dict[str, TenantResponsePolicy]) -> None:
        serialized = [policy.model_dump(mode="json") for policy in sorted(policies.values(), key=lambda item: item.tenant_id)]
        self.path.write_text(json.dumps(serialized, indent=2), encoding="utf-8")
