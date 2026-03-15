from __future__ import annotations

from fastapi import Depends, FastAPI, Header, HTTPException

from .config import load_settings
from .models import (
    AdminContext,
    CreateRemediationApprovalRequest,
    CreateRemediationExceptionRequest,
    CreateUserRequest,
    DatabaseProtocolEnvelope,
    IdentityUser,
    IngestResponse,
    LoginRequest,
    LoginResponse,
    LogoutResponse,
    PermissionName,
    PlatformArchitecture,
    RevokeRemediationApprovalRequest,
    RemediationApprovalRecord,
    RemediationExecutionRequest,
    RemediationExecutionResult,
    RemediationException,
    RemediationPlan,
    ReplayResponse,
    RotatePasswordRequest,
    TelemetryEnvelope,
    TenantResponsePolicy,
    UpdateUserRoleRequest,
    UpdateUserScopesRequest,
)
from .service import CloudPlatformService

app = FastAPI(
    title="Autonomous Cloud Security & Observability Platform",
    version="0.1.0",
    description="Telemetry ingestion, behavioral analytics, threat detection, debugging, and mitigation planning.",
)
service = CloudPlatformService()


def require_admin(
    authorization: str | None = Header(default=None),
    x_admin_token: str | None = Header(default=None),
) -> AdminContext:
    if authorization and authorization.startswith("Bearer "):
        token = authorization.removeprefix("Bearer ").strip()
        admin = service.resolve_admin_session(token)
        if admin is not None:
            return admin
    expected = load_settings().admin_api_token
    if expected and x_admin_token == expected:
        return AdminContext(
            actor="platform-admin",
            role="platform_admin",
            permissions=[
                "users:write",
                "users:read",
                "policies:write",
                "policies:read",
                "audit:read",
                "remediation:approve",
            ],
            tenant_scopes=[],
            namespace_scopes=[],
            environment_scopes=[],
            workload_scopes=[],
            service_account_scopes=[],
            workload_label_scopes=[],
            approver_groups=["platform", "security"],
        )
    if authorization and authorization.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Invalid admin session.")
    if expected:
        raise HTTPException(status_code=401, detail="Invalid admin credentials.")
    raise HTTPException(status_code=503, detail="Admin authentication is not configured.")


def require_permission(permission: PermissionName):
    def dependency(admin: AdminContext = Depends(require_admin)) -> AdminContext:
        if permission not in admin.permissions:
            raise HTTPException(status_code=403, detail=f"Missing permission: {permission}")
        return admin

    return dependency


@app.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok"}


@app.post("/auth/login", response_model=LoginResponse)
def login(payload: LoginRequest) -> LoginResponse:
    try:
        return service.login(payload)
    except ValueError as exc:
        raise HTTPException(status_code=401, detail=str(exc)) from exc


@app.post("/auth/logout", response_model=LogoutResponse)
def logout(authorization: str | None = Header(default=None)) -> LogoutResponse:
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Bearer token is required.")
    token = authorization.removeprefix("Bearer ").strip()
    try:
        return service.logout(token)
    except ValueError as exc:
        raise HTTPException(status_code=401, detail=str(exc)) from exc


@app.get("/platform/architecture", response_model=PlatformArchitecture)
def platform_architecture() -> PlatformArchitecture:
    return service.architecture()


@app.get("/platform/tenant-policies", response_model=list[TenantResponsePolicy])
def list_tenant_policies(
    admin: AdminContext = Depends(require_permission("policies:read")),
) -> list[TenantResponsePolicy]:
    return service.list_tenant_policies_for_admin(admin)


@app.get("/platform/users", response_model=list[IdentityUser])
def list_users(_: AdminContext = Depends(require_permission("users:read"))) -> list[IdentityUser]:
    return service.list_users()


@app.post("/platform/users", response_model=IdentityUser)
def create_user(
    payload: CreateUserRequest,
    admin: AdminContext = Depends(require_permission("users:write")),
) -> IdentityUser:
    try:
        return service.create_user(payload, admin)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@app.patch("/platform/users/{username}/role", response_model=IdentityUser)
def update_user_role(
    username: str,
    payload: UpdateUserRoleRequest,
    admin: AdminContext = Depends(require_permission("users:write")),
) -> IdentityUser:
    try:
        return service.update_user_role(username, payload, admin)
    except ValueError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc


@app.post("/platform/users/{username}/rotate-password", response_model=IdentityUser)
def rotate_user_password(
    username: str,
    payload: RotatePasswordRequest,
    admin: AdminContext = Depends(require_permission("users:write")),
) -> IdentityUser:
    try:
        return service.rotate_user_password(username, payload, admin)
    except ValueError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc


@app.patch("/platform/users/{username}/scopes", response_model=IdentityUser)
def update_user_scopes(
    username: str,
    payload: UpdateUserScopesRequest,
    admin: AdminContext = Depends(require_permission("users:write")),
) -> IdentityUser:
    try:
        return service.update_user_scopes(username, payload, admin)
    except ValueError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc


@app.get("/platform/tenant-policies/{tenant_id}", response_model=TenantResponsePolicy)
def get_tenant_policy(
    tenant_id: str,
    admin: AdminContext = Depends(require_permission("policies:read")),
) -> TenantResponsePolicy:
    try:
        service.require_tenant_scope(tenant_id, admin)
        policy = service.get_tenant_policy(tenant_id)
        for namespace in policy.namespace_allowlist:
            service.require_namespace_scope(namespace, admin)
        for environment in policy.environment_allowlist:
            service.require_environment_scope(environment, admin)
        for workload_key in policy.workload_allowlist:
            service.require_workload_scope(workload_key, admin)
        for service_account in policy.service_account_allowlist:
            service.require_service_account_scope(service_account, admin)
        service.require_workload_label_scope(policy.workload_label_allowlist, admin)
        return policy
    except KeyError as exc:
        raise HTTPException(status_code=404, detail="Tenant policy not found.") from exc
    except PermissionError as exc:
        raise HTTPException(status_code=403, detail=str(exc)) from exc


@app.put("/platform/tenant-policies/{tenant_id}", response_model=TenantResponsePolicy)
def upsert_tenant_policy(
    tenant_id: str,
    policy: TenantResponsePolicy,
    admin: AdminContext = Depends(require_permission("policies:write")),
) -> TenantResponsePolicy:
    if policy.tenant_id != tenant_id:
        raise HTTPException(status_code=400, detail="Tenant ID in path must match payload.")
    try:
        service.require_tenant_scope(tenant_id, admin)
        for namespace in policy.namespace_allowlist:
            service.require_namespace_scope(namespace, admin)
        for environment in policy.environment_allowlist:
            service.require_environment_scope(environment, admin)
        for workload_key in policy.workload_allowlist:
            service.require_workload_scope(workload_key, admin)
        for service_account in policy.service_account_allowlist:
            service.require_service_account_scope(service_account, admin)
        service.require_workload_label_scope(policy.workload_label_allowlist, admin)
    except PermissionError as exc:
        raise HTTPException(status_code=403, detail=str(exc)) from exc
    return service.audited_upsert_tenant_policy(policy, admin)


@app.delete("/platform/tenant-policies/{tenant_id}")
def delete_tenant_policy(
    tenant_id: str,
    admin: AdminContext = Depends(require_permission("policies:write")),
) -> dict[str, str]:
    try:
        service.require_tenant_scope(tenant_id, admin)
    except PermissionError as exc:
        raise HTTPException(status_code=403, detail=str(exc)) from exc
    deleted = service.audited_delete_tenant_policy(tenant_id, admin)
    if not deleted:
        raise HTTPException(status_code=404, detail="Tenant policy not found.")
    return {"status": "deleted"}


@app.get("/platform/audit-log")
def list_audit_log(_: AdminContext = Depends(require_permission("audit:read"))):
    return service.list_audit_records()


@app.get("/platform/remediation-exceptions", response_model=list[RemediationException])
def list_remediation_exceptions(
    _: AdminContext = Depends(require_permission("policies:read")),
) -> list[RemediationException]:
    return service.list_remediation_exceptions()


@app.post("/platform/remediation-exceptions", response_model=RemediationException)
def create_remediation_exception(
    payload: CreateRemediationExceptionRequest,
    admin: AdminContext = Depends(require_permission("policies:write")),
) -> RemediationException:
    try:
        service.require_tenant_scope(payload.tenant_id, admin)
        return service.create_remediation_exception(payload, admin)
    except PermissionError as exc:
        raise HTTPException(status_code=403, detail=str(exc)) from exc


@app.delete("/platform/remediation-exceptions/{exception_id}")
def delete_remediation_exception(
    exception_id: str,
    admin: AdminContext = Depends(require_permission("policies:write")),
) -> dict[str, str]:
    deleted = service.delete_remediation_exception(exception_id, admin)
    if not deleted:
        raise HTTPException(status_code=404, detail="Remediation exception not found.")
    return {"status": "deleted"}


@app.get("/platform/remediation-approvals", response_model=list[RemediationApprovalRecord])
def list_remediation_approvals(
    _: AdminContext = Depends(require_permission("audit:read")),
) -> list[RemediationApprovalRecord]:
    return service.list_remediation_approvals()


@app.post("/platform/remediation-approvals/{approval_id}/revoke", response_model=RemediationApprovalRecord)
def revoke_remediation_approval(
    approval_id: str,
    payload: RevokeRemediationApprovalRequest,
    admin: AdminContext = Depends(require_permission("remediation:approve")),
) -> RemediationApprovalRecord:
    try:
        return service.revoke_remediation_approval(approval_id, payload, admin)
    except ValueError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc


@app.post("/telemetry/ingest", response_model=IngestResponse)
def telemetry_ingest(payload: TelemetryEnvelope) -> IngestResponse:
    return service.ingest(payload)


@app.post("/telemetry/ingest/protocol", response_model=IngestResponse)
def telemetry_ingest_protocol(payload: DatabaseProtocolEnvelope) -> IngestResponse:
    return service.ingest_protocol_frames(payload)


@app.get("/streams/events")
def list_stream_events():
    return service.list_stream()


@app.get("/streams/status")
def stream_status() -> dict[str, int]:
    records = service.list_stream()
    return {
        "persisted_events": len(records),
        "latest_offset": records[-1].offset if records else -1,
    }


@app.get("/sessions")
def list_sessions():
    return service.list_sessions()


@app.get("/detections")
def list_detections():
    return service.list_detections()


@app.get("/detections/{detection_id}/remediation", response_model=RemediationPlan)
def get_remediation_plan(detection_id: str) -> RemediationPlan:
    try:
        return service.remediation_plan(detection_id)
    except KeyError as exc:
        raise HTTPException(status_code=404, detail="Detection not found.") from exc


@app.post("/detections/{detection_id}/approve", response_model=RemediationApprovalRecord)
def approve_remediation(
    detection_id: str,
    payload: CreateRemediationApprovalRequest,
    admin: AdminContext = Depends(require_permission("remediation:approve")),
) -> RemediationApprovalRecord:
    try:
        detection = service.get_detection(detection_id)
        service.require_tenant_scope(detection.tenant_id, admin)
        service.require_namespace_scope(service.detection_namespace(detection), admin)
        service.require_environment_scope(service.detection_environment(detection), admin)
        service.require_workload_scope(service.detection_workload_scope(detection), admin)
        service.require_service_account_scope(service.detection_service_account(detection), admin)
        service.require_workload_label_scope(service.detection_workload_labels(detection), admin)
        return service.create_remediation_approval(detection_id, payload, admin)
    except KeyError as exc:
        raise HTTPException(status_code=404, detail="Detection not found.") from exc
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    except PermissionError as exc:
        raise HTTPException(status_code=403, detail=str(exc)) from exc


@app.post("/detections/execute", response_model=RemediationExecutionResult)
def execute_remediation(
    request: RemediationExecutionRequest,
    admin: AdminContext = Depends(require_permission("remediation:approve")),
) -> RemediationExecutionResult:
    try:
        detection = service.get_detection(request.detection_id)
        service.require_tenant_scope(detection.tenant_id, admin)
        service.require_namespace_scope(service.detection_namespace(detection), admin)
        service.require_environment_scope(service.detection_environment(detection), admin)
        service.require_workload_scope(service.detection_workload_scope(detection), admin)
        service.require_service_account_scope(service.detection_service_account(detection), admin)
        service.require_workload_label_scope(service.detection_workload_labels(detection), admin)
        return service.execute_remediation(request)
    except KeyError as exc:
        raise HTTPException(status_code=404, detail="Detection not found.") from exc
    except PermissionError as exc:
        raise HTTPException(status_code=403, detail=str(exc)) from exc


@app.post("/detections/replay", response_model=ReplayResponse)
def replay_detections() -> ReplayResponse:
    return service.replay()
