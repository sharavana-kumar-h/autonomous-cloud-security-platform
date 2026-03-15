from cloud_platform.models import (
    Detection,
    KubernetesActionResult,
    RemediationExecutionRequest,
    TenantResponsePolicy,
)
from cloud_platform.repository import PlatformRepository
from cloud_platform.service import CloudPlatformService
from cloud_platform.tenant_policy import TenantPolicyRegistry


class FakeKubernetesAdapter:
    def apply_plan(self, plan, dry_run: bool = True):
        return [
            KubernetesActionResult(
                action_id=action.action_id,
                action_type=action.action_type,
                target=action.target,
                status="dry_run" if dry_run else "applied",
                resource_kind="Fake",
                resource_name=action.target,
                namespace="payments",
                details="fake adapter executed action",
            )
            for action in plan.actions
        ]


def test_service_executes_remediation_through_adapter() -> None:
    service = CloudPlatformService(repository=PlatformRepository(), kubernetes_adapter=FakeKubernetesAdapter())
    detection = Detection(
        detection_id="det-real-k8s",
        tenant_id="tenant-a",
        severity="critical",
        title="Critical detection",
        summary="Test",
        mitre_tactics=["Execution"],
        mitre_techniques=["T1059"],
        confidence=0.97,
        session_key="tenant-a::svc-api::prod/payments/api-7d9",
        evidence_event_ids=["evt-1"],
        debugging_context=["Inspect pod."],
        mitigation_plan=["Block egress."],
    )
    service.repository.upsert_detection(detection)

    result = service.execute_remediation(
        RemediationExecutionRequest(detection_id="det-real-k8s", approved=True, dry_run=False)
    )

    assert result.status == "executed"
    assert result.action_results
    assert all(item.status == "applied" for item in result.action_results)


def test_service_applies_tenant_policy_before_adapter_execution() -> None:
    registry = TenantPolicyRegistry(
        {
            "tenant-a": TenantResponsePolicy(
                tenant_id="tenant-a",
                allowed_actions=["snapshot_forensics"],
                namespace_allowlist=["payments"],
                require_approval_for=["snapshot_forensics"],
            )
        }
    )
    service = CloudPlatformService(
        repository=PlatformRepository(),
        kubernetes_adapter=FakeKubernetesAdapter(),
        policy_registry=registry,
    )
    detection = Detection(
        detection_id="det-policy-k8s",
        tenant_id="tenant-a",
        severity="critical",
        title="Critical detection",
        summary="Test",
        mitre_tactics=["Execution", "Credential Access"],
        mitre_techniques=["T1059", "T1552"],
        confidence=0.97,
        session_key="tenant-a::svc-api::prod/payments/api-7d9",
        evidence_event_ids=["evt-1"],
        debugging_context=["Inspect pod."],
        mitigation_plan=["Block egress."],
    )
    service.repository.upsert_detection(detection)

    plan = service.remediation_plan("det-policy-k8s")
    assert len(plan.actions) == 1
    assert plan.actions[0].action_type == "snapshot_forensics"

    result = service.execute_remediation(
        RemediationExecutionRequest(detection_id="det-policy-k8s", approved=True, dry_run=False)
    )
    assert len(result.action_results) == 1
