from __future__ import annotations

from hashlib import sha1
from typing import Literal

from .models import (
    Detection,
    RemediationAction,
    RemediationExecutionResult,
    RemediationPlan,
    ResponsePolicy,
    TenantResponsePolicy,
    WorkloadContext,
)


SEVERITY_ORDER = {
    "low": 0,
    "medium": 1,
    "high": 2,
    "critical": 3,
}


def build_remediation_plan(
    detection: Detection,
    policy: ResponsePolicy | None = None,
    tenant_policy: TenantResponsePolicy | None = None,
    workload_context: WorkloadContext | None = None,
) -> RemediationPlan:
    active_policy = policy or ResponsePolicy()
    namespace = workload_context.namespace if workload_context and workload_context.namespace else _infer_namespace(detection.session_key)
    workload = workload_context.workload_scope_key if workload_context is not None else detection.session_key.split("::")[-1]
    service_account = workload_context.service_account if workload_context and workload_context.service_account else "default"

    actions: list[RemediationAction] = []

    if "Execution" in detection.mitre_tactics or detection.severity == "critical":
        actions.append(
            _action(
                detection.detection_id,
                "suspend_service_account",
                workload,
                "Compromised workload identity may be driving malicious activity.",
                f"kubectl -n {namespace} patch serviceaccount {service_account} -p '{{\"automountServiceAccountToken\":false}}'",
                "Restore the original service account token mounting configuration after containment review.",
                active_policy,
            )
        )
        actions.append(
            _action(
                detection.detection_id,
                "block_egress",
                namespace,
                "Outbound communication should be constrained while the incident is investigated.",
                f"kubectl -n {namespace} apply -f generated-egress-deny-policy.yaml",
                "Remove the temporary egress deny policy after validation that the workload is clean.",
                active_policy,
            )
        )

    if "Credential Access" in detection.mitre_tactics or "Privilege Escalation" in detection.mitre_tactics:
        actions.append(
            _action(
                detection.detection_id,
                "isolate_namespace",
                namespace,
                "Namespace isolation reduces blast radius for suspected secret abuse.",
                f"kubectl label namespace {namespace} quarantine=enabled --overwrite",
                "Remove the quarantine label and restore traffic policies once the namespace is cleared.",
                active_policy,
            )
        )
        actions.append(
            _action(
                detection.detection_id,
                "rotate_credentials",
                namespace,
                "Rotating secrets limits reuse of duplicated or exposed credentials.",
                f"kubectl -n {namespace} rollout restart deployment",
                "Reissue known-good credentials and redeploy dependent workloads if rotation causes instability.",
                active_policy,
            )
        )

    actions.append(
        _action(
            detection.detection_id,
            "snapshot_forensics",
            workload,
            "Capture evidence before deeper remediation changes the workload state.",
            f"kubectl debug {workload} --copy-to={workload}-forensics",
            "Delete the temporary forensic copy after evidence collection is complete.",
            active_policy,
        )
    )

    blocked_actions: list[str] = []
    if tenant_policy is not None:
        actions, blocked_actions = _filter_actions(actions, namespace, tenant_policy)

    approval_required = any(action.requires_approval for action in actions)
    notes = [
        "Remediation plans are evaluated against tenant-scoped policy before execution.",
        "High-blast-radius actions should remain operator-approved until workload and tenant safety checks are in place.",
    ]
    if blocked_actions:
        notes.append("Some actions were removed by tenant policy constraints before execution planning.")
    if detection.confidence >= active_policy.auto_execute_confidence_threshold and not approval_required:
        notes.append("This plan is eligible for future auto-execution once a real controller backend is connected.")

    return RemediationPlan(
        detection_id=detection.detection_id,
        tenant_id=detection.tenant_id,
        approval_required=approval_required,
        actions=actions,
        blocked_actions=blocked_actions,
        operator_notes=notes,
    )


def execute_remediation_plan(plan: RemediationPlan, approved: bool) -> RemediationExecutionResult:
    if not plan.actions and plan.blocked_actions:
        return RemediationExecutionResult(
            detection_id=plan.detection_id,
            status="blocked",
            executed_actions=[],
            action_results=[],
            blocked_reason=plan.blocked_actions[0],
        )
    if plan.approval_required and not approved:
        return RemediationExecutionResult(
            detection_id=plan.detection_id,
            status="blocked",
            executed_actions=[],
            action_results=[],
            blocked_reason="Operator approval is required before executing this remediation plan.",
        )

    return RemediationExecutionResult(
        detection_id=plan.detection_id,
        status="executed" if approved or not plan.approval_required else "planned",
        executed_actions=[action.action_id for action in plan.actions],
        action_results=[],
        blocked_reason=None,
    )


def _action(
    detection_id: str,
    action_type: Literal[
        "isolate_namespace",
        "suspend_service_account",
        "block_egress",
        "snapshot_forensics",
        "rotate_credentials",
    ],
    target: str,
    reason: str,
    simulated_command: str,
    rollback: str,
    policy: ResponsePolicy,
) -> RemediationAction:
    requires_approval = (
        action_type in set(policy.require_approval_for)
        or SEVERITY_ORDER["critical"] > SEVERITY_ORDER[policy.max_auto_severity]
    )
    return RemediationAction(
        action_id=sha1(f"{detection_id}:{action_type}:{target}".encode("utf-8")).hexdigest()[:12],
        action_type=action_type,
        target=target,
        reason=reason,
        requires_approval=requires_approval,
        simulated_command=simulated_command,
        rollback=rollback,
    )


def _infer_namespace(session_key: str) -> str:
    parts = session_key.split("::")
    if len(parts) < 3:
        return "default"
    workload = parts[-1]
    workload_parts = workload.split("/")
    if len(workload_parts) >= 2:
        return workload_parts[1]
    return "default"


def _filter_actions(
    actions: list[RemediationAction],
    namespace: str,
    tenant_policy: TenantResponsePolicy,
) -> tuple[list[RemediationAction], list[str]]:
    allowed_actions = set(tenant_policy.allowed_actions)
    namespace_allowlist = set(tenant_policy.namespace_allowlist)
    filtered: list[RemediationAction] = []
    blocked: list[str] = []

    for action in actions:
        if allowed_actions and action.action_type not in allowed_actions:
            blocked.append(f"{action.action_type}: blocked by allowed_actions policy")
            continue
        if namespace_allowlist and namespace not in namespace_allowlist:
            blocked.append(f"{action.action_type}: namespace {namespace} is outside tenant allowlist")
            continue
        filtered.append(action)

    return filtered, blocked
