from pathlib import Path

from cloud_platform.models import TenantResponsePolicy
from cloud_platform.policy_store import TenantPolicyStore
from cloud_platform.tenant_policy import TenantPolicyRegistry


def test_policy_store_persists_policies(tmp_path: Path) -> None:
    store = TenantPolicyStore(tmp_path / "tenant-policies.json")
    registry = TenantPolicyRegistry(store=store)

    policy = TenantResponsePolicy(
        tenant_id="tenant-store",
        allowed_actions=["snapshot_forensics"],
        namespace_allowlist=["payments"],
        require_approval_for=["snapshot_forensics"],
    )
    registry.upsert(policy)

    restored = TenantPolicyRegistry(store=store)
    loaded = restored.for_tenant("tenant-store")

    assert loaded is not None
    assert loaded.allowed_actions == ["snapshot_forensics"]
