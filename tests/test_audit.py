from pathlib import Path

from cloud_platform.audit import AuditLogStore, build_audit_record


def test_audit_log_store_persists_records(tmp_path: Path) -> None:
    store = AuditLogStore(tmp_path / "audit.jsonl")
    store.append(
        build_audit_record(
            actor="admin",
            action="tenant_policy_upsert",
            resource_type="tenant_policy",
            resource_id="tenant-a",
            outcome="success",
            details="created policy",
        )
    )

    records = store.list_records()
    assert len(records) == 1
    assert records[0].resource_id == "tenant-a"
