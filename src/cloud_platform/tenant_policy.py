from __future__ import annotations

import json
import os

from .models import ResponsePolicy, TenantResponsePolicy
from .policy_store import TenantPolicyStore


class TenantPolicyRegistry:
    def __init__(
        self,
        policies: dict[str, TenantResponsePolicy] | None = None,
        store: TenantPolicyStore | None = None,
    ) -> None:
        self.store = store
        if policies is not None:
            self._policies = policies
            if self.store is not None:
                self.store.save_all(self._policies)
            return

        stored_policies = self.store.load_all() if self.store is not None else {}
        if stored_policies:
            self._policies = stored_policies
            return

        self._policies = load_bootstrap_policies()
        if self.store is not None and self._policies:
            self.store.save_all(self._policies)

    def list_policies(self) -> list[TenantResponsePolicy]:
        return sorted(self._policies.values(), key=lambda item: item.tenant_id)

    def for_tenant(self, tenant_id: str) -> TenantResponsePolicy | None:
        return self._policies.get(tenant_id)

    def upsert(self, policy: TenantResponsePolicy) -> TenantResponsePolicy:
        self._policies[policy.tenant_id] = policy
        self._persist()
        return policy

    def delete(self, tenant_id: str) -> bool:
        removed = self._policies.pop(tenant_id, None)
        if removed is None:
            return False
        self._persist()
        return True

    def response_policy_for_tenant(self, tenant_id: str) -> ResponsePolicy:
        tenant_policy = self.for_tenant(tenant_id)
        if tenant_policy is None:
            return ResponsePolicy()
        require_approval_for = (
            tenant_policy.require_approval_for
            if tenant_policy.require_approval_for
            else ["isolate_namespace", "suspend_service_account", "block_egress"]
        )
        return ResponsePolicy(
            auto_execute_confidence_threshold=tenant_policy.auto_execute_confidence_threshold,
            require_approval_for=require_approval_for,
            max_auto_severity=tenant_policy.max_auto_severity,
        )

    def _persist(self) -> None:
        if self.store is not None:
            self.store.save_all(self._policies)


def load_bootstrap_policies() -> dict[str, TenantResponsePolicy]:
    raw = os.getenv("PLATFORM_TENANT_POLICIES_JSON", "").strip()
    if not raw:
        return {}
    payload = json.loads(raw)
    if not isinstance(payload, list):
        raise ValueError("PLATFORM_TENANT_POLICIES_JSON must be a JSON array.")
    policies = [TenantResponsePolicy.model_validate(item) for item in payload]
    return {policy.tenant_id: policy for policy in policies}
