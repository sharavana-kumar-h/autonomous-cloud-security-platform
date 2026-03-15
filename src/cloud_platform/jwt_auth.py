from __future__ import annotations

import secrets
from datetime import UTC, datetime, timedelta

import jwt

from .models import AdminContext, IdentityUser, LoginResponse, PermissionName, UserRole


ROLE_PERMISSIONS: dict[UserRole, list[PermissionName]] = {
    "platform_admin": [
        "users:write",
        "users:read",
        "policies:write",
        "policies:read",
        "audit:read",
        "remediation:approve",
    ],
    "policy_admin": ["policies:write", "policies:read", "audit:read"],
    "remediation_approver": ["remediation:approve", "policies:read"],
    "auditor": ["audit:read", "policies:read", "users:read"],
    "viewer": ["policies:read"],
}


class JwtManager:
    def __init__(self, secret: str, expire_minutes: int) -> None:
        self.secret = secret
        self.expire_minutes = expire_minutes

    def issue_token(self, user: IdentityUser) -> LoginResponse:
        now = datetime.now(UTC)
        expires_at = now + timedelta(minutes=self.expire_minutes)
        jti = secrets.token_urlsafe(16)
        permissions = ROLE_PERMISSIONS[user.role]
        token = jwt.encode(
            {
                "sub": user.username,
                "role": user.role,
                "permissions": permissions,
                "tenant_scopes": user.tenant_scopes,
                "namespace_scopes": user.namespace_scopes,
                "environment_scopes": user.environment_scopes,
                "workload_scopes": user.workload_scopes,
                "service_account_scopes": user.service_account_scopes,
                "workload_label_scopes": user.workload_label_scopes,
                "approver_groups": user.approver_groups,
                "iat": int(now.timestamp()),
                "exp": int(expires_at.timestamp()),
                "jti": jti,
            },
            self.secret,
            algorithm="HS256",
        )
        return LoginResponse(
            token=token,
            username=user.username,
            role=user.role,
            permissions=permissions,
            tenant_scopes=user.tenant_scopes,
            namespace_scopes=user.namespace_scopes,
            environment_scopes=user.environment_scopes,
            workload_scopes=user.workload_scopes,
            service_account_scopes=user.service_account_scopes,
            workload_label_scopes=user.workload_label_scopes,
            approver_groups=user.approver_groups,
            expires_at=expires_at,
        )

    def decode_admin(self, token: str) -> tuple[AdminContext, str]:
        payload = jwt.decode(token, self.secret, algorithms=["HS256"])
        role = payload.get("role")
        permissions = payload.get("permissions") or ROLE_PERMISSIONS.get(role, [])
        tenant_scopes = payload.get("tenant_scopes") or []
        namespace_scopes = payload.get("namespace_scopes") or []
        environment_scopes = payload.get("environment_scopes") or []
        workload_scopes = payload.get("workload_scopes") or []
        service_account_scopes = payload.get("service_account_scopes") or []
        workload_label_scopes = payload.get("workload_label_scopes") or []
        approver_groups = payload.get("approver_groups") or []
        if role not in ROLE_PERMISSIONS:
            raise ValueError("Known role required.")
        username = payload.get("sub")
        jti = payload.get("jti")
        if not username or not jti:
            raise ValueError("Invalid token payload.")
        return (
            AdminContext(
                actor=username,
                role=role,
                permissions=permissions,
                tenant_scopes=tenant_scopes,
                namespace_scopes=namespace_scopes,
                environment_scopes=environment_scopes,
                workload_scopes=workload_scopes,
                service_account_scopes=service_account_scopes,
                workload_label_scopes=workload_label_scopes,
                approver_groups=approver_groups,
            ),
            jti,
        )

    def decode_jti(self, token: str) -> str:
        payload = jwt.decode(token, self.secret, algorithms=["HS256"], options={"verify_exp": False})
        jti = payload.get("jti")
        if not jti:
            raise ValueError("Invalid token payload.")
        return jti
