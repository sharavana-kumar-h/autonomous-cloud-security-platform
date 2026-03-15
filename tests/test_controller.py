from cloud_platform.controller import build_remediation_plan, execute_remediation_plan
from cloud_platform.models import Detection, TenantResponsePolicy


def test_critical_detection_requires_approval() -> None:
    detection = Detection(
        detection_id="det-1",
        tenant_id="tenant-a",
        severity="critical",
        title="Critical test detection",
        summary="Test",
        mitre_tactics=["Execution"],
        mitre_techniques=["T1059"],
        confidence=0.98,
        session_key="tenant-a::svc-api::prod/payments/api-7d9",
        evidence_event_ids=["evt-1"],
        debugging_context=["Inspect workload."],
        mitigation_plan=["Quarantine workload."],
    )

    plan = build_remediation_plan(detection)
    assert plan.approval_required is True
    assert any(action.action_type == "suspend_service_account" for action in plan.actions)

    blocked = execute_remediation_plan(plan, approved=False)
    assert blocked.status == "blocked"

    executed = execute_remediation_plan(plan, approved=True)
    assert executed.status == "executed"


def test_tenant_policy_filters_disallowed_actions() -> None:
    detection = Detection(
        detection_id="det-tenant-filter",
        tenant_id="tenant-restricted",
        severity="critical",
        title="Critical test detection",
        summary="Test",
        mitre_tactics=["Execution", "Credential Access"],
        mitre_techniques=["T1059", "T1552"],
        confidence=0.98,
        session_key="tenant-restricted::svc-api::prod/payments/api-7d9",
        evidence_event_ids=["evt-1"],
        debugging_context=["Inspect workload."],
        mitigation_plan=["Quarantine workload."],
    )

    tenant_policy = TenantResponsePolicy(
        tenant_id="tenant-restricted",
        allowed_actions=["snapshot_forensics"],
        namespace_allowlist=["payments"],
        require_approval_for=["snapshot_forensics"],
    )

    plan = build_remediation_plan(detection, tenant_policy=tenant_policy)

    assert len(plan.actions) == 1
    assert plan.actions[0].action_type == "snapshot_forensics"
    assert plan.blocked_actions
