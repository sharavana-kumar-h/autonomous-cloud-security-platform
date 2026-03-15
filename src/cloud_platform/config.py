from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class Settings:
    stream_log_path: Path
    tenant_policy_store_path: Path
    audit_log_path: Path
    remediation_exception_store_path: Path
    remediation_approval_store_path: Path
    identity_store_path: Path
    revocation_store_path: Path
    admin_api_token: str | None
    bootstrap_admin_username: str
    bootstrap_admin_password: str
    jwt_secret: str
    session_expire_minutes: int
    kubernetes_dry_run: bool
    kubernetes_namespace_prefix: str | None


def load_settings() -> Settings:
    raw_path = os.getenv("PLATFORM_STREAM_LOG_PATH", "data/event_stream.jsonl")
    raw_policy_path = os.getenv("PLATFORM_TENANT_POLICY_STORE_PATH", "data/tenant_policies.json")
    raw_audit_path = os.getenv("PLATFORM_AUDIT_LOG_PATH", "data/audit_log.jsonl")
    raw_exception_path = os.getenv("PLATFORM_REMEDIATION_EXCEPTION_STORE_PATH", "data/remediation_exceptions.json")
    raw_approval_path = os.getenv("PLATFORM_REMEDIATION_APPROVAL_STORE_PATH", "data/remediation_approvals.json")
    raw_identity_path = os.getenv("PLATFORM_IDENTITY_STORE_PATH", "data/identities.json")
    raw_revocation_path = os.getenv("PLATFORM_REVOCATION_STORE_PATH", "data/revoked_tokens.json")
    admin_api_token = os.getenv("PLATFORM_ADMIN_API_TOKEN") or None
    bootstrap_admin_username = os.getenv("PLATFORM_BOOTSTRAP_ADMIN_USERNAME", "admin")
    bootstrap_admin_password = os.getenv("PLATFORM_BOOTSTRAP_ADMIN_PASSWORD", "change-me-now")
    jwt_secret = os.getenv("PLATFORM_JWT_SECRET", "replace-this-jwt-secret")
    session_expire_minutes = int(os.getenv("PLATFORM_SESSION_EXPIRE_MINUTES", "480"))
    dry_run = os.getenv("PLATFORM_KUBERNETES_DRY_RUN", "true").lower() != "false"
    namespace_prefix = os.getenv("PLATFORM_KUBERNETES_NAMESPACE_PREFIX") or None
    return Settings(
        stream_log_path=Path(raw_path),
        tenant_policy_store_path=Path(raw_policy_path),
        audit_log_path=Path(raw_audit_path),
        remediation_exception_store_path=Path(raw_exception_path),
        remediation_approval_store_path=Path(raw_approval_path),
        identity_store_path=Path(raw_identity_path),
        revocation_store_path=Path(raw_revocation_path),
        admin_api_token=admin_api_token,
        bootstrap_admin_username=bootstrap_admin_username,
        bootstrap_admin_password=bootstrap_admin_password,
        jwt_secret=jwt_secret,
        session_expire_minutes=session_expire_minutes,
        kubernetes_dry_run=dry_run,
        kubernetes_namespace_prefix=namespace_prefix,
    )
