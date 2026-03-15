from __future__ import annotations

from datetime import UTC, datetime
from fnmatch import fnmatch
from uuid import uuid4

from .approval_store import RemediationApprovalStore
from .analytics import build_session_clusters
from .audit import AuditLogStore, AuditRecord, build_audit_record
from .config import load_settings
from .controller import build_remediation_plan, execute_remediation_plan
from .detections import build_detections
from .exception_store import RemediationExceptionStore
from .identity_store import IdentityStore
from .jwt_auth import JwtManager
from .kubernetes_adapter import KubernetesAdapter, KubernetesControllerAdapter, SafeKubernetesAdapter
from .models import (
    ApprovalStagePolicy,
    AdminContext,
    CreateRemediationApprovalRequest,
    CreateRemediationExceptionRequest,
    CreateUserRequest,
    DatabaseProtocolEnvelope,
    Detection,
    IngestResponse,
    LoginRequest,
    LoginResponse,
    LogoutResponse,
    PlatformArchitecture,
    RevokeRemediationApprovalRequest,
    RemediationApprovalRecord,
    RemediationExecutionRequest,
    RemediationExecutionResult,
    RemediationException,
    RemediationPlan,
    ReplayResponse,
    RotatePasswordRequest,
    StreamRecord,
    TelemetryEnvelope,
    TenantResponsePolicy,
    UpdateUserRoleRequest,
    UpdateUserScopesRequest,
)
from .policy_store import TenantPolicyStore
from .persistence import StreamEventLog
from .protocols import protocol_frames_to_envelope
from .repository import PlatformRepository
from .revocation_store import RevocationStore
from .selectors import evaluate_policy_selectors
from .tenant_policy import TenantPolicyRegistry


class CloudPlatformService:
    def __init__(
        self,
        repository: PlatformRepository | None = None,
        kubernetes_adapter: KubernetesAdapter | None = None,
        policy_registry: TenantPolicyRegistry | None = None,
        audit_log: AuditLogStore | None = None,
        exception_store: RemediationExceptionStore | None = None,
        approval_store: RemediationApprovalStore | None = None,
        identity_store: IdentityStore | None = None,
        jwt_manager: JwtManager | None = None,
        revocation_store: RevocationStore | None = None,
    ) -> None:
        settings = load_settings()
        if repository is None:
            repository = PlatformRepository(event_log=StreamEventLog(settings.stream_log_path))
        self.repository = repository
        self.policy_registry = policy_registry or TenantPolicyRegistry(
            store=TenantPolicyStore(settings.tenant_policy_store_path)
        )
        if kubernetes_adapter is None:
            try:
                kubernetes_adapter = KubernetesControllerAdapter(
                    namespace_prefix=settings.kubernetes_namespace_prefix
                )
            except Exception:
                kubernetes_adapter = SafeKubernetesAdapter()
        self.kubernetes_adapter = kubernetes_adapter
        self.default_kubernetes_dry_run = settings.kubernetes_dry_run
        self.audit_log = audit_log or AuditLogStore(settings.audit_log_path)
        self.exception_store = exception_store or RemediationExceptionStore(
            settings.remediation_exception_store_path
        )
        self.approval_store = approval_store or RemediationApprovalStore(
            settings.remediation_approval_store_path
        )
        self.identity_store = identity_store or IdentityStore(
            settings.identity_store_path,
            settings.bootstrap_admin_username,
            settings.bootstrap_admin_password,
        )
        self.jwt_manager = jwt_manager or JwtManager(settings.jwt_secret, settings.session_expire_minutes)
        self.revocation_store = revocation_store or RevocationStore(settings.revocation_store_path)
        if self.repository.list_stream():
            self._recompute()

    def architecture(self) -> PlatformArchitecture:
        return PlatformArchitecture(
            pipeline=[
                "database proxies",
                "kubernetes telemetry",
                "application logs",
                "event streaming pipeline",
                "behavioral analytics engine",
                "threat detection and debugging",
                "automated mitigation controller",
            ],
            implemented_layers=[
                "normalized telemetry ingestion",
                "durable local event log",
                "session clustering",
                "behavioral anomaly scoring",
                "MITRE-style detection generation",
                "debugging context and mitigation planning",
            ],
            planned_layers=[
                "database wire protocol parsers",
                "durable distributed stream broker",
                "kubernetes remediation controllers",
                "autoscaling analytics workers",
                "stateful session clustering across nodes",
            ],
        )

    def ingest(self, envelope: TelemetryEnvelope) -> IngestResponse:
        existing_session_count = len(self.repository.sessions)
        for event in envelope.events:
            record = StreamRecord(
                offset=self.repository.next_offset(),
                tenant_id=envelope.tenant_id,
                source=envelope.source,
                event=event,
            )
            self.repository.append_stream(record)

        detections = self._recompute()
        return IngestResponse(
            ingested_events=len(envelope.events),
            new_sessions=max(len(self.repository.sessions) - existing_session_count, 0),
            new_detections=len(detections),
            detections=detections,
        )

    def ingest_protocol_frames(self, payload: DatabaseProtocolEnvelope) -> IngestResponse:
        return self.ingest(protocol_frames_to_envelope(payload))

    def replay(self) -> ReplayResponse:
        detections = self._recompute()
        return ReplayResponse(
            replayed_events=len(self.repository.stream),
            detections=detections,
        )

    def list_stream(self) -> list[StreamRecord]:
        return self.repository.list_stream()

    def list_sessions(self):
        return self.repository.list_sessions()

    def list_detections(self) -> list[Detection]:
        return self.repository.list_detections()

    def get_detection(self, detection_id: str) -> Detection:
        detection = self.repository.detections.get(detection_id)
        if detection is None:
            raise KeyError(detection_id)
        return detection

    def require_tenant_scope(self, tenant_id: str, admin: AdminContext) -> None:
        if admin.role == "platform_admin":
            return
        if tenant_id in set(admin.tenant_scopes):
            return
        raise PermissionError(f"Tenant {tenant_id} is outside the caller scope.")

    def require_namespace_scope(self, namespace: str | None, admin: AdminContext) -> None:
        if admin.role == "platform_admin":
            return
        if not admin.namespace_scopes:
            return
        if namespace in set(admin.namespace_scopes):
            return
        raise PermissionError(f"Namespace {namespace or 'unknown'} is outside the caller scope.")

    def require_environment_scope(self, environment: str | None, admin: AdminContext) -> None:
        if admin.role == "platform_admin":
            return
        if not admin.environment_scopes:
            return
        if environment in set(admin.environment_scopes):
            return
        raise PermissionError(f"Environment {environment or 'unknown'} is outside the caller scope.")

    def require_workload_scope(self, workload_key: str | None, admin: AdminContext) -> None:
        if admin.matches_workload_scope(workload_key):
            return
        raise PermissionError(f"Workload {workload_key or 'unknown'} is outside the caller scope.")

    def require_service_account_scope(self, service_account: str | None, admin: AdminContext) -> None:
        if admin.matches_service_account_scope(service_account):
            return
        raise PermissionError(f"Service account {service_account or 'unknown'} is outside the caller scope.")

    def require_workload_label_scope(self, labels: list[str], admin: AdminContext) -> None:
        if not labels:
            return
        if admin.matches_workload_labels(labels):
            return
        raise PermissionError("Workload labels are outside the caller scope.")

    def detection_namespace(self, detection: Detection) -> str | None:
        context = self._detection_workload_context(detection)
        return context.namespace if context is not None else None

    def detection_environment(self, detection: Detection) -> str | None:
        context = self._detection_workload_context(detection)
        return context.environment if context is not None else None

    def detection_workload_scope(self, detection: Detection) -> str | None:
        context = self._detection_workload_context(detection)
        return context.workload_scope_key if context is not None else None

    def detection_service_account(self, detection: Detection) -> str | None:
        context = self._detection_workload_context(detection)
        return context.service_account if context is not None else None

    def detection_workload_labels(self, detection: Detection) -> list[str]:
        context = self._detection_workload_context(detection)
        return context.label_scope_keys if context is not None else []

    def remediation_plan(self, detection_id: str) -> RemediationPlan:
        detection = self.get_detection(detection_id)
        tenant_policy = self.policy_registry.for_tenant(detection.tenant_id)
        response_policy = self.policy_registry.response_policy_for_tenant(detection.tenant_id)
        workload_context = self._detection_workload_context(detection)
        plan = build_remediation_plan(
            detection,
            policy=response_policy,
            tenant_policy=tenant_policy,
            workload_context=workload_context,
        )
        if tenant_policy is None:
            return plan
        selector_allowed, selector_reason = evaluate_policy_selectors(
            workload_context,
            tenant_policy,
        )
        exception = self._matching_exception(detection)
        if selector_allowed or exception is not None:
            if not selector_allowed and exception is not None:
                notes = list(plan.operator_notes)
                notes.append(
                    f"Remediation exception {exception.exception_id} temporarily overrode selector-policy blocking."
                )
                return plan.model_copy(update={"operator_notes": notes})
            return plan
        blocked_actions = list(plan.blocked_actions)
        blocked_actions.append(f"selector_policy: {selector_reason}")
        notes = list(plan.operator_notes)
        notes.append("Selector expressions blocked automated remediation for this workload context.")
        return plan.model_copy(
            update={
                "actions": [],
                "approval_required": False,
                "blocked_actions": blocked_actions,
                "operator_notes": notes,
            }
        )

    def execute_remediation(self, request: RemediationExecutionRequest) -> RemediationExecutionResult:
        plan = self.remediation_plan(request.detection_id)
        approved = request.approved or self._approval_is_sufficient(request.detection_id, request.approval_id)
        result = execute_remediation_plan(plan, approved=approved)
        if result.status == "blocked":
            return result
        action_results = self.kubernetes_adapter.apply_plan(
            plan,
            dry_run=request.dry_run if request.dry_run is not None else self.default_kubernetes_dry_run,
        )
        result.action_results = action_results
        result.executed_actions = [item.action_id for item in action_results if item.status in {"dry_run", "applied"}]
        return result

    def list_tenant_policies(self) -> list[TenantResponsePolicy]:
        return self.policy_registry.list_policies()

    def list_tenant_policies_for_admin(self, admin: AdminContext) -> list[TenantResponsePolicy]:
        policies = self.policy_registry.list_policies()
        if admin.role == "platform_admin":
            return policies
        allowed = set(admin.tenant_scopes)
        visible: list[TenantResponsePolicy] = []
        for policy in policies:
            if policy.tenant_id not in allowed:
                continue
            if admin.namespace_scopes and policy.namespace_allowlist:
                if not set(policy.namespace_allowlist).intersection(admin.namespace_scopes):
                    continue
            if admin.environment_scopes and policy.environment_allowlist:
                if not set(policy.environment_allowlist).intersection(admin.environment_scopes):
                    continue
            if admin.workload_scopes and policy.workload_allowlist:
                if not any(
                    any(fnmatch(workload_key, pattern) for pattern in admin.workload_scopes)
                    for workload_key in policy.workload_allowlist
                ):
                    continue
            if admin.service_account_scopes and policy.service_account_allowlist:
                if not any(
                    any(fnmatch(service_account, pattern) for pattern in admin.service_account_scopes)
                    for service_account in policy.service_account_allowlist
                ):
                    continue
            if admin.workload_label_scopes and policy.workload_label_allowlist:
                if not any(
                    any(fnmatch(label_key, pattern) for pattern in admin.workload_label_scopes)
                    for label_key in policy.workload_label_allowlist
                ):
                    continue
            visible.append(policy)
        return visible

    def get_tenant_policy(self, tenant_id: str) -> TenantResponsePolicy:
        policy = self.policy_registry.for_tenant(tenant_id)
        if policy is None:
            raise KeyError(tenant_id)
        return policy

    def upsert_tenant_policy(self, policy: TenantResponsePolicy) -> TenantResponsePolicy:
        return self.policy_registry.upsert(policy)

    def delete_tenant_policy(self, tenant_id: str) -> bool:
        return self.policy_registry.delete(tenant_id)

    def list_audit_records(self) -> list[AuditRecord]:
        return self.audit_log.list_records()

    def list_remediation_exceptions(self) -> list[RemediationException]:
        return self._active_exceptions()

    def create_remediation_exception(
        self,
        request: CreateRemediationExceptionRequest,
        admin: AdminContext,
    ) -> RemediationException:
        item = RemediationException(
            exception_id=uuid4().hex[:12],
            tenant_id=request.tenant_id,
            detection_id=request.detection_id,
            selector_expressions=request.selector_expressions,
            selector_mode=request.selector_mode,
            reason=request.reason,
            created_by=admin.actor,
            created_at=datetime.now(UTC),
            expires_at=request.expires_at,
        )
        items = self._active_exceptions()
        items.append(item)
        self.exception_store.save_all(items)
        self.audit_log.append(
            build_audit_record(
                actor=admin.actor,
                action="remediation_exception_create",
                resource_type="remediation_exception",
                resource_id=item.exception_id,
                outcome="success",
                details=f"Created remediation exception for tenant {item.tenant_id}.",
            )
        )
        return item

    def delete_remediation_exception(self, exception_id: str, admin: AdminContext) -> bool:
        items = self.exception_store.list_all()
        remaining = [item for item in items if item.exception_id != exception_id]
        deleted = len(remaining) != len(items)
        if deleted:
            self.exception_store.save_all(remaining)
        self.audit_log.append(
            build_audit_record(
                actor=admin.actor,
                action="remediation_exception_delete",
                resource_type="remediation_exception",
                resource_id=exception_id,
                outcome="success" if deleted else "not_found",
                details="Remediation exception delete requested.",
            )
        )
        return deleted

    def list_remediation_approvals(self) -> list[RemediationApprovalRecord]:
        return self._active_approvals()

    def create_remediation_approval(
        self,
        detection_id: str,
        request: CreateRemediationApprovalRequest,
        admin: AdminContext,
    ) -> RemediationApprovalRecord:
        detection = self.get_detection(detection_id)
        stage = self._resolve_approval_stage(detection_id, request.stage_name)
        if stage is not None:
            self._validate_approval_stage_access(detection_id, stage, admin)
        item = RemediationApprovalRecord(
            approval_id=uuid4().hex[:12],
            detection_id=detection_id,
            tenant_id=detection.tenant_id,
            approved_by=admin.actor,
            approver_role=admin.role,
            stage_name=stage.stage_name if stage is not None else None,
            reason=request.reason,
            approved_at=datetime.now(UTC),
            expires_at=request.expires_at,
        )
        items = self._active_approvals()
        items.append(item)
        self.approval_store.save_all(items)
        self.audit_log.append(
            build_audit_record(
                actor=admin.actor,
                action="remediation_approval_create",
                resource_type="remediation_approval",
                resource_id=item.approval_id,
                outcome="success",
                details=(
                    f"Approved remediation for detection {detection_id}"
                    f"{f' at stage {item.stage_name}' if item.stage_name else ''}."
                ),
            )
        )
        return item

    def revoke_remediation_approval(
        self,
        approval_id: str,
        request: RevokeRemediationApprovalRequest,
        admin: AdminContext,
    ) -> RemediationApprovalRecord:
        items = self.approval_store.list_all()
        updated: RemediationApprovalRecord | None = None
        next_items: list[RemediationApprovalRecord] = []
        for item in items:
            if item.approval_id == approval_id and item.revoked_at is None:
                updated = item.model_copy(
                    update={
                        "revoked_at": datetime.now(UTC),
                        "revoked_by": admin.actor,
                        "revoke_reason": request.reason,
                    }
                )
                next_items.append(updated)
            else:
                next_items.append(item)
        if updated is None:
            raise ValueError("Remediation approval not found.")
        self.approval_store.save_all(next_items)
        self.audit_log.append(
            build_audit_record(
                actor=admin.actor,
                action="remediation_approval_revoke",
                resource_type="remediation_approval",
                resource_id=approval_id,
                outcome="success",
                details=f"Revoked remediation approval for detection {updated.detection_id}.",
            )
        )
        return updated

    def login(self, request: LoginRequest) -> LoginResponse:
        user = self.identity_store.authenticate(request.username, request.password)
        if user is None:
            raise ValueError("Invalid username or password.")
        return self.jwt_manager.issue_token(user)

    def resolve_admin_session(self, token: str) -> AdminContext | None:
        try:
            admin, jti = self.jwt_manager.decode_admin(token)
        except Exception:
            return None
        if self.revocation_store.is_revoked(jti):
            return None
        return admin

    def logout(self, token: str) -> LogoutResponse:
        try:
            jti = self.jwt_manager.decode_jti(token)
        except Exception:
            raise ValueError("Session not found.")
        if self.revocation_store.is_revoked(jti):
            raise ValueError("Session not found.")
        self.revocation_store.revoke(jti)
        return LogoutResponse(status="logged_out")

    def list_users(self):
        return self.identity_store.list_users()

    def create_user(self, request: CreateUserRequest, admin: AdminContext):
        user = self.identity_store.create_user(request)
        self.audit_log.append(
            build_audit_record(
                actor=admin.actor,
                action="identity_user_create",
                resource_type="identity_user",
                resource_id=user.username,
                outcome="success",
                details=f"Created user with role {user.role}.",
            )
        )
        return user

    def update_user_role(self, username: str, request: UpdateUserRoleRequest, admin: AdminContext):
        user = self.identity_store.update_user_role(username, request.role)
        self.audit_log.append(
            build_audit_record(
                actor=admin.actor,
                action="identity_user_role_update",
                resource_type="identity_user",
                resource_id=user.username,
                outcome="success",
                details=f"Updated user role to {user.role}.",
            )
        )
        return user

    def update_user_scopes(self, username: str, request: UpdateUserScopesRequest, admin: AdminContext):
        user = self.identity_store.update_user_scopes(
            username,
            request.tenant_scopes,
            request.namespace_scopes,
            request.environment_scopes,
            request.workload_scopes,
            request.service_account_scopes,
            request.workload_label_scopes,
            request.approver_groups,
        )
        self.audit_log.append(
            build_audit_record(
                actor=admin.actor,
                action="identity_user_scope_update",
                resource_type="identity_user",
                resource_id=user.username,
                outcome="success",
                details=(
                    f"Updated tenant scopes to {','.join(user.tenant_scopes) or 'global'} "
                    f"and namespace scopes to {','.join(user.namespace_scopes) or 'global'}; "
                    f"environment scopes to {','.join(user.environment_scopes) or 'global'}; "
                    f"workload scopes to {','.join(user.workload_scopes) or 'global'}; "
                    f"service account scopes to {','.join(user.service_account_scopes) or 'global'}; "
                    f"label scopes to {','.join(user.workload_label_scopes) or 'global'}; "
                    f"approver groups to {','.join(user.approver_groups) or 'none'}."
                ),
            )
        )
        return user

    def rotate_user_password(self, username: str, request: RotatePasswordRequest, admin: AdminContext):
        user = self.identity_store.rotate_password(username, request.new_password)
        self.audit_log.append(
            build_audit_record(
                actor=admin.actor,
                action="identity_user_password_rotate",
                resource_type="identity_user",
                resource_id=user.username,
                outcome="success",
                details="Rotated user password.",
            )
        )
        return user

    def audited_upsert_tenant_policy(
        self,
        policy: TenantResponsePolicy,
        admin: AdminContext,
    ) -> TenantResponsePolicy:
        saved = self.policy_registry.upsert(policy)
        self.audit_log.append(
            build_audit_record(
                actor=admin.actor,
                action="tenant_policy_upsert",
                resource_type="tenant_policy",
                resource_id=policy.tenant_id,
                outcome="success",
                details="Tenant policy created or updated.",
            )
        )
        return saved

    def audited_delete_tenant_policy(self, tenant_id: str, admin: AdminContext) -> bool:
        deleted = self.policy_registry.delete(tenant_id)
        self.audit_log.append(
            build_audit_record(
                actor=admin.actor,
                action="tenant_policy_delete",
                resource_type="tenant_policy",
                resource_id=tenant_id,
                outcome="success" if deleted else "not_found",
                details="Tenant policy delete requested.",
            )
        )
        return deleted

    def _recompute(self) -> list[Detection]:
        self.repository.reset_derived_state()
        sessions = build_session_clusters(self.repository.list_stream())
        for session in sessions:
            self.repository.upsert_session(session)

        detections: list[Detection] = []
        records = self.repository.list_stream()
        for session in sessions:
            for detection in build_detections(session, records):
                self.repository.upsert_detection(detection)
                detections.append(detection)
        return detections

    def _detection_workload_context(self, detection: Detection):
        event_ids = set(detection.evidence_event_ids)
        for record in reversed(self.repository.list_stream()):
            if record.tenant_id == detection.tenant_id and record.event.event_id in event_ids:
                return record.event.workload
        workload_parts = self._detection_workload_parts(detection)
        if len(workload_parts) < 3:
            return None
        from .models import WorkloadContext

        return WorkloadContext(
            cluster=workload_parts[0],
            namespace=workload_parts[1],
            pod=workload_parts[2],
        )

    def _detection_workload_parts(self, detection: Detection) -> list[str]:
        parts = detection.session_key.split("::")
        if len(parts) < 3:
            return []
        return parts[-1].split("/")

    def _active_exceptions(self) -> list[RemediationException]:
        now = datetime.now(UTC)
        return [item for item in self.exception_store.list_all() if item.expires_at > now]

    def _active_approvals(self) -> list[RemediationApprovalRecord]:
        now = datetime.now(UTC)
        return [
            item
            for item in self.approval_store.list_all()
            if item.expires_at > now and item.revoked_at is None
        ]

    def _approval_is_sufficient(self, detection_id: str, approval_id: str | None) -> bool:
        detection = self.get_detection(detection_id)
        tenant_policy = self.policy_registry.for_tenant(detection.tenant_id)
        approvals = [item for item in self._active_approvals() if item.detection_id == detection_id]
        if approval_id and not any(item.approval_id == approval_id for item in approvals):
            return False
        stages = self._required_approval_stages(detection_id)
        if stages:
            return all(self._stage_is_satisfied(stage, approvals) for stage in stages)
        required_count = tenant_policy.required_approval_count if tenant_policy is not None else 1
        unique_approvers = {item.approved_by for item in approvals}
        return len(unique_approvers) >= max(required_count, 1)

    def _required_approval_stages(self, detection_id: str) -> list[ApprovalStagePolicy]:
        detection = self.get_detection(detection_id)
        tenant_policy = self.policy_registry.for_tenant(detection.tenant_id)
        if tenant_policy is None or not tenant_policy.approval_stages:
            return []
        plan = self.remediation_plan(detection_id)
        action_types = {action.action_type for action in plan.actions}
        stages: list[ApprovalStagePolicy] = []
        for stage in tenant_policy.approval_stages:
            if not stage.applies_to_actions or action_types.intersection(stage.applies_to_actions):
                stages.append(stage)
        return stages

    def _resolve_approval_stage(self, detection_id: str, stage_name: str | None) -> ApprovalStagePolicy | None:
        stages = self._required_approval_stages(detection_id)
        if not stages:
            return None
        if stage_name is None:
            raise ValueError("Stage name is required for this remediation approval policy.")
        for stage in stages:
            if stage.stage_name == stage_name:
                return stage
        raise ValueError("Unknown approval stage.")

    def _validate_approval_stage_access(
        self,
        detection_id: str,
        stage: ApprovalStagePolicy,
        admin: AdminContext,
    ) -> None:
        if stage.required_roles and admin.role not in stage.required_roles:
            raise PermissionError(f"Role {admin.role} cannot approve stage {stage.stage_name}.")
        if stage.required_approver_groups and not set(stage.required_approver_groups).intersection(admin.approver_groups):
            raise PermissionError(f"Approver groups {','.join(stage.required_approver_groups)} are required for stage {stage.stage_name}.")
        stages = self._required_approval_stages(detection_id)
        approvals = [item for item in self._active_approvals() if item.detection_id == detection_id]
        for candidate in stages:
            if candidate.stage_name == stage.stage_name:
                break
            if not self._stage_is_satisfied(candidate, approvals):
                raise PermissionError(f"Stage {candidate.stage_name} must be completed before {stage.stage_name}.")

    def _stage_is_satisfied(
        self,
        stage: ApprovalStagePolicy,
        approvals: list[RemediationApprovalRecord],
    ) -> bool:
        stage_approvals = [item for item in approvals if item.stage_name == stage.stage_name]
        if stage.required_roles:
            stage_approvals = [item for item in stage_approvals if item.approver_role in stage.required_roles]
        unique_approvers = {item.approved_by for item in stage_approvals}
        return len(unique_approvers) >= max(stage.required_count, 1)

    def _matching_exception(self, detection: Detection) -> RemediationException | None:
        workload = self._detection_workload_context(detection)
        for item in self._active_exceptions():
            if item.tenant_id != detection.tenant_id:
                continue
            if item.detection_id and item.detection_id != detection.detection_id:
                continue
            if item.selector_expressions:
                allowed, _ = evaluate_policy_selectors(
                    workload,
                    TenantResponsePolicy(
                        tenant_id=item.tenant_id,
                        selector_expressions=item.selector_expressions,
                        selector_mode=item.selector_mode,
                    ),
                )
                if not allowed:
                    continue
            return item
        return None
