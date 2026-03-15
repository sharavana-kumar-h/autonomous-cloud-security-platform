from __future__ import annotations

from datetime import datetime
from fnmatch import fnmatch
from typing import Any, Literal

from pydantic import BaseModel, Field


EventKind = Literal["database_query", "kubernetes_audit", "application_log"]
ProtocolType = Literal["postgresql", "mysql"]
ProtocolMessageType = Literal["startup", "query", "terminate", "login", "command"]
UserRole = Literal["platform_admin", "policy_admin", "remediation_approver", "auditor", "viewer"]
PermissionName = Literal["users:write", "users:read", "policies:write", "policies:read", "audit:read", "remediation:approve"]


class ActorContext(BaseModel):
    user: str
    ip: str | None = None


class WorkloadContext(BaseModel):
    cluster: str | None = None
    namespace: str | None = None
    pod: str | None = None
    container: str | None = None
    service_account: str | None = None
    labels: dict[str, str] = Field(default_factory=dict)

    @property
    def environment(self) -> str | None:
        return self.cluster

    @property
    def workload_group(self) -> str | None:
        if not self.pod:
            return None
        pod = self.pod
        for separator in ("-", "_"):
            if separator in pod:
                candidate = pod.rsplit(separator, 1)[0]
                if candidate:
                    return candidate
        return pod

    @property
    def workload_scope_key(self) -> str:
        return "/".join(
            [
                self.cluster or "unknown-cluster",
                self.namespace or "unknown-namespace",
                self.workload_group or "unknown-workload",
            ]
        )

    @property
    def label_scope_keys(self) -> list[str]:
        return [f"{key}={value}" for key, value in sorted(self.labels.items())]


class DatabaseContext(BaseModel):
    engine: str
    name: str
    session_id: str
    statement: str
    rows_returned: int = 0


class KubernetesContext(BaseModel):
    verb: str
    resource: str
    name: str


class ApplicationContext(BaseModel):
    service: str
    level: str
    message: str


class NetworkContext(BaseModel):
    destination_ip: str | None = None
    destination_port: int | None = None
    protocol: str | None = None


class TelemetryEvent(BaseModel):
    event_id: str
    kind: EventKind
    timestamp: datetime
    actor: ActorContext
    workload: WorkloadContext = Field(default_factory=WorkloadContext)
    database: DatabaseContext | None = None
    kubernetes: KubernetesContext | None = None
    application: ApplicationContext | None = None
    network: NetworkContext | None = None
    attributes: dict[str, Any] = Field(default_factory=dict)


class TelemetryEnvelope(BaseModel):
    tenant_id: str
    source: str
    events: list[TelemetryEvent]


class ProtocolActor(BaseModel):
    user: str
    ip: str | None = None


class ProtocolWorkload(BaseModel):
    cluster: str | None = None
    namespace: str | None = None
    pod: str | None = None
    container: str | None = None
    service_account: str | None = None
    labels: dict[str, str] = Field(default_factory=dict)


class DatabaseProtocolFrame(BaseModel):
    frame_id: str
    protocol: ProtocolType
    message_type: ProtocolMessageType
    timestamp: datetime
    actor: ProtocolActor
    workload: ProtocolWorkload = Field(default_factory=ProtocolWorkload)
    database_name: str
    session_id: str
    statement: str | None = None
    rows_returned: int = 0
    destination_ip: str | None = None
    destination_port: int | None = None
    metadata: dict[str, Any] = Field(default_factory=dict)


class DatabaseProtocolEnvelope(BaseModel):
    tenant_id: str
    source: str
    frames: list[DatabaseProtocolFrame]


class StreamRecord(BaseModel):
    offset: int
    tenant_id: str
    source: str
    event: TelemetryEvent


class SessionCluster(BaseModel):
    session_key: str
    tenant_id: str
    actor: str
    workload: str
    event_ids: list[str]
    kinds: list[EventKind]
    started_at: datetime
    ended_at: datetime
    anomaly_score: float
    reasons: list[str]


class Detection(BaseModel):
    detection_id: str
    tenant_id: str
    severity: Literal["low", "medium", "high", "critical"]
    title: str
    summary: str
    mitre_tactics: list[str]
    mitre_techniques: list[str]
    confidence: float
    session_key: str
    evidence_event_ids: list[str]
    debugging_context: list[str]
    mitigation_plan: list[str]


class ResponsePolicy(BaseModel):
    auto_execute_confidence_threshold: float = 0.9
    require_approval_for: list[str] = Field(
        default_factory=lambda: ["isolate_namespace", "suspend_service_account", "block_egress"]
    )
    max_auto_severity: Literal["low", "medium", "high", "critical"] = "high"


class ApprovalStagePolicy(BaseModel):
    stage_name: str
    required_roles: list[UserRole] = Field(default_factory=list)
    required_approver_groups: list[str] = Field(default_factory=list)
    required_approver_classes: list[str] = Field(default_factory=list)
    required_count: int = 1
    applies_to_actions: list[str] = Field(default_factory=list)


class TenantResponsePolicy(BaseModel):
    tenant_id: str
    allowed_actions: list[str] = Field(default_factory=list)
    namespace_allowlist: list[str] = Field(default_factory=list)
    environment_allowlist: list[str] = Field(default_factory=list)
    workload_allowlist: list[str] = Field(default_factory=list)
    service_account_allowlist: list[str] = Field(default_factory=list)
    workload_label_allowlist: list[str] = Field(default_factory=list)
    selector_expressions: list[str] = Field(default_factory=list)
    selector_mode: Literal["all", "any"] = "all"
    required_approval_count: int = 1
    approval_stages: list[ApprovalStagePolicy] = Field(default_factory=list)
    require_approval_for: list[str] = Field(default_factory=list)
    auto_execute_confidence_threshold: float = 0.9
    max_auto_severity: Literal["low", "medium", "high", "critical"] = "high"
    kubernetes_namespace_prefix: str | None = None


class TenantApproverClass(BaseModel):
    tenant_id: str
    class_name: str
    description: str | None = None
    allowed_roles: list[UserRole] = Field(default_factory=list)
    allowed_approver_groups: list[str] = Field(default_factory=list)
    required_permissions: list[PermissionName] = Field(default_factory=lambda: ["remediation:approve"])


class RemediationAction(BaseModel):
    action_id: str
    action_type: Literal[
        "isolate_namespace",
        "suspend_service_account",
        "block_egress",
        "snapshot_forensics",
        "rotate_credentials",
    ]
    target: str
    reason: str
    requires_approval: bool
    simulated_command: str
    rollback: str


class RemediationPlan(BaseModel):
    detection_id: str
    tenant_id: str
    approval_required: bool
    actions: list[RemediationAction]
    blocked_actions: list[str] = Field(default_factory=list)
    operator_notes: list[str]


class RemediationExecutionRequest(BaseModel):
    detection_id: str
    approved: bool = False
    dry_run: bool = True
    approval_id: str | None = None


class KubernetesActionResult(BaseModel):
    action_id: str
    action_type: str
    target: str
    status: Literal["dry_run", "applied", "failed"]
    resource_kind: str
    resource_name: str
    namespace: str | None = None
    details: str


class RemediationExecutionResult(BaseModel):
    detection_id: str
    status: Literal["planned", "blocked", "executed"]
    executed_actions: list[str]
    action_results: list[KubernetesActionResult] = Field(default_factory=list)
    blocked_reason: str | None = None


class RemediationException(BaseModel):
    exception_id: str
    tenant_id: str
    detection_id: str | None = None
    selector_expressions: list[str] = Field(default_factory=list)
    selector_mode: Literal["all", "any"] = "all"
    reason: str
    created_by: str
    created_at: datetime
    expires_at: datetime


class CreateRemediationExceptionRequest(BaseModel):
    tenant_id: str
    detection_id: str | None = None
    selector_expressions: list[str] = Field(default_factory=list)
    selector_mode: Literal["all", "any"] = "all"
    reason: str
    expires_at: datetime


class RemediationApprovalRecord(BaseModel):
    approval_id: str
    detection_id: str
    tenant_id: str
    approved_by: str
    approver_role: UserRole
    approver_class: str | None = None
    stage_name: str | None = None
    reason: str
    approved_at: datetime
    expires_at: datetime
    revoked_at: datetime | None = None
    revoked_by: str | None = None
    revoke_reason: str | None = None


class CreateRemediationApprovalRequest(BaseModel):
    stage_name: str | None = None
    approver_class: str | None = None
    reason: str
    expires_at: datetime


class RevokeRemediationApprovalRequest(BaseModel):
    reason: str


class IngestResponse(BaseModel):
    ingested_events: int
    new_sessions: int
    new_detections: int
    detections: list[Detection]


class ReplayResponse(BaseModel):
    replayed_events: int
    detections: list[Detection]


class PlatformArchitecture(BaseModel):
    pipeline: list[str]
    implemented_layers: list[str]
    planned_layers: list[str]


class AdminContext(BaseModel):
    actor: str
    role: UserRole
    permissions: list[PermissionName] = Field(default_factory=list)
    tenant_scopes: list[str] = Field(default_factory=list)
    namespace_scopes: list[str] = Field(default_factory=list)
    environment_scopes: list[str] = Field(default_factory=list)
    workload_scopes: list[str] = Field(default_factory=list)
    service_account_scopes: list[str] = Field(default_factory=list)
    workload_label_scopes: list[str] = Field(default_factory=list)
    approver_groups: list[str] = Field(default_factory=list)

    def matches_workload_scope(self, workload_key: str | None) -> bool:
        if self.role == "platform_admin" or not self.workload_scopes:
            return True
        if not workload_key:
            return False
        return any(fnmatch(workload_key, pattern) for pattern in self.workload_scopes)

    def matches_service_account_scope(self, service_account: str | None) -> bool:
        if self.role == "platform_admin" or not self.service_account_scopes:
            return True
        if not service_account:
            return False
        return any(fnmatch(service_account, pattern) for pattern in self.service_account_scopes)

    def matches_workload_labels(self, labels: list[str]) -> bool:
        if self.role == "platform_admin" or not self.workload_label_scopes:
            return True
        return any(
            fnmatch(label_key, pattern)
            for label_key in labels
            for pattern in self.workload_label_scopes
        )


class IdentityUser(BaseModel):
    username: str
    password_hash: str
    password_salt: str
    role: UserRole
    tenant_scopes: list[str] = Field(default_factory=list)
    namespace_scopes: list[str] = Field(default_factory=list)
    environment_scopes: list[str] = Field(default_factory=list)
    workload_scopes: list[str] = Field(default_factory=list)
    service_account_scopes: list[str] = Field(default_factory=list)
    workload_label_scopes: list[str] = Field(default_factory=list)
    approver_groups: list[str] = Field(default_factory=list)
    created_at: datetime


class SessionToken(BaseModel):
    token: str
    username: str
    role: Literal["admin", "viewer"]
    created_at: datetime
    expires_at: datetime
    revoked_at: datetime | None = None


class LoginRequest(BaseModel):
    username: str
    password: str


class LoginResponse(BaseModel):
    token: str
    username: str
    role: UserRole
    permissions: list[PermissionName]
    tenant_scopes: list[str]
    namespace_scopes: list[str]
    environment_scopes: list[str]
    workload_scopes: list[str]
    service_account_scopes: list[str]
    workload_label_scopes: list[str]
    approver_groups: list[str]
    expires_at: datetime


class LogoutResponse(BaseModel):
    status: str


class CreateUserRequest(BaseModel):
    username: str
    password: str
    role: UserRole
    tenant_scopes: list[str] = Field(default_factory=list)
    namespace_scopes: list[str] = Field(default_factory=list)
    environment_scopes: list[str] = Field(default_factory=list)
    workload_scopes: list[str] = Field(default_factory=list)
    service_account_scopes: list[str] = Field(default_factory=list)
    workload_label_scopes: list[str] = Field(default_factory=list)
    approver_groups: list[str] = Field(default_factory=list)


class UpsertTenantApproverClassRequest(BaseModel):
    description: str | None = None
    allowed_roles: list[UserRole] = Field(default_factory=list)
    allowed_approver_groups: list[str] = Field(default_factory=list)
    required_permissions: list[PermissionName] = Field(default_factory=lambda: ["remediation:approve"])


class UpdateUserRoleRequest(BaseModel):
    role: UserRole


class UpdateUserScopesRequest(BaseModel):
    tenant_scopes: list[str] = Field(default_factory=list)
    namespace_scopes: list[str] = Field(default_factory=list)
    environment_scopes: list[str] = Field(default_factory=list)
    workload_scopes: list[str] = Field(default_factory=list)
    service_account_scopes: list[str] = Field(default_factory=list)
    workload_label_scopes: list[str] = Field(default_factory=list)
    approver_groups: list[str] = Field(default_factory=list)


class RotatePasswordRequest(BaseModel):
    new_password: str
