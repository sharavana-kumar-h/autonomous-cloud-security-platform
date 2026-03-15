from __future__ import annotations

import hashlib
import json
import secrets
from datetime import UTC, datetime
from pathlib import Path

from .models import CreateUserRequest, IdentityUser


class IdentityStore:
    def __init__(self, path: Path, bootstrap_username: str, bootstrap_password: str) -> None:
        self.path = path
        self.path.parent.mkdir(parents=True, exist_ok=True)
        if not self.path.exists():
            self.path.write_text('{"users":[]}', encoding="utf-8")
        self.bootstrap_admin(bootstrap_username, bootstrap_password)

    def bootstrap_admin(self, username: str, password: str) -> None:
        users = self._load_users()
        if any(user.username == username for user in users):
            self._save(users)
            return
        users.append(
            _build_user(
                username=username,
                password=password,
                role="platform_admin",
                tenant_scopes=[],
                namespace_scopes=[],
                environment_scopes=[],
                workload_scopes=[],
                service_account_scopes=[],
                workload_label_scopes=[],
                approver_groups=["platform", "security"],
            )
        )
        self._save(users)

    def authenticate(self, username: str, password: str) -> IdentityUser | None:
        user = self.get_user(username)
        if user is None or not _verify_password(password, user):
            return None
        return user

    def list_users(self) -> list[IdentityUser]:
        return sorted(self._load_users(), key=lambda item: item.created_at)

    def get_user(self, username: str) -> IdentityUser | None:
        users = self._load_users()
        return next((item for item in users if item.username == username), None)

    def create_user(self, request: CreateUserRequest) -> IdentityUser:
        users = self._load_users()
        if any(user.username == request.username for user in users):
            raise ValueError("User already exists.")
        user = _build_user(
            request.username,
            request.password,
            request.role,
            request.tenant_scopes,
            request.namespace_scopes,
            request.environment_scopes,
            request.workload_scopes,
            request.service_account_scopes,
            request.workload_label_scopes,
            request.approver_groups,
        )
        users.append(user)
        self._save(users)
        return user

    def update_user_role(self, username: str, role: str) -> IdentityUser:
        users = self._load_users()
        updated_user: IdentityUser | None = None
        next_users: list[IdentityUser] = []
        for user in users:
            if user.username == username:
                updated_user = user.model_copy(update={"role": role})
                next_users.append(updated_user)
            else:
                next_users.append(user)
        if updated_user is None:
            raise ValueError("User not found.")
        self._save(next_users)
        return updated_user

    def update_user_scopes(
        self,
        username: str,
        tenant_scopes: list[str],
        namespace_scopes: list[str],
        environment_scopes: list[str],
        workload_scopes: list[str],
        service_account_scopes: list[str],
        workload_label_scopes: list[str],
        approver_groups: list[str],
    ) -> IdentityUser:
        users = self._load_users()
        updated_user: IdentityUser | None = None
        next_users: list[IdentityUser] = []
        for user in users:
            if user.username == username:
                updated_user = user.model_copy(
                    update={
                        "tenant_scopes": tenant_scopes,
                        "namespace_scopes": namespace_scopes,
                        "environment_scopes": environment_scopes,
                        "workload_scopes": workload_scopes,
                        "service_account_scopes": service_account_scopes,
                        "workload_label_scopes": workload_label_scopes,
                        "approver_groups": approver_groups,
                    }
                )
                next_users.append(updated_user)
            else:
                next_users.append(user)
        if updated_user is None:
            raise ValueError("User not found.")
        self._save(next_users)
        return updated_user

    def rotate_password(self, username: str, new_password: str) -> IdentityUser:
        users = self._load_users()
        updated_user: IdentityUser | None = None
        next_users: list[IdentityUser] = []
        for user in users:
            if user.username == username:
                updated_user = _build_user(
                    username=user.username,
                    password=new_password,
                    role=user.role,
                    tenant_scopes=user.tenant_scopes,
                    namespace_scopes=user.namespace_scopes,
                    environment_scopes=user.environment_scopes,
                    workload_scopes=user.workload_scopes,
                    service_account_scopes=user.service_account_scopes,
                    workload_label_scopes=user.workload_label_scopes,
                    approver_groups=user.approver_groups,
                )
                updated_user = updated_user.model_copy(update={"created_at": user.created_at})
                next_users.append(updated_user)
            else:
                next_users.append(user)
        if updated_user is None:
            raise ValueError("User not found.")
        self._save(next_users)
        return updated_user

    def _load_raw(self) -> dict:
        return json.loads(self.path.read_text(encoding="utf-8"))

    def _load_users(self) -> list[IdentityUser]:
        raw = self._load_raw()
        changed = False
        users: list[IdentityUser] = []
        for raw_user in raw.get("users", []):
            if "password_salt" not in raw_user:
                raw_user = {**raw_user, "password_salt": "legacy-sha256"}
                changed = True
            if raw_user.get("role") == "admin":
                raw_user = {**raw_user, "role": "platform_admin"}
                changed = True
            if "tenant_scopes" not in raw_user:
                raw_user = {**raw_user, "tenant_scopes": []}
                changed = True
            if "namespace_scopes" not in raw_user:
                raw_user = {**raw_user, "namespace_scopes": []}
                changed = True
            if "environment_scopes" not in raw_user:
                raw_user = {**raw_user, "environment_scopes": []}
                changed = True
            if "workload_scopes" not in raw_user:
                raw_user = {**raw_user, "workload_scopes": []}
                changed = True
            if "service_account_scopes" not in raw_user:
                raw_user = {**raw_user, "service_account_scopes": []}
                changed = True
            if "workload_label_scopes" not in raw_user:
                raw_user = {**raw_user, "workload_label_scopes": []}
                changed = True
            if "approver_groups" not in raw_user:
                raw_user = {
                    **raw_user,
                    "approver_groups": ["platform", "security"] if raw_user.get("role") == "platform_admin" else [],
                }
                changed = True
            elif raw_user.get("role") == "platform_admin" and not raw_user.get("approver_groups"):
                raw_user = {**raw_user, "approver_groups": ["platform", "security"]}
                changed = True
            users.append(IdentityUser.model_validate(raw_user))
        if changed:
            self._save(users)
        return users

    def _save(self, users: list[IdentityUser]) -> None:
        payload = {"users": [user.model_dump(mode="json") for user in users]}
        self.path.write_text(json.dumps(payload, indent=2), encoding="utf-8")


def _build_user(
    username: str,
    password: str,
    role: str,
    tenant_scopes: list[str],
    namespace_scopes: list[str],
    environment_scopes: list[str],
    workload_scopes: list[str],
    service_account_scopes: list[str],
    workload_label_scopes: list[str],
    approver_groups: list[str],
) -> IdentityUser:
    salt = secrets.token_hex(16)
    return IdentityUser(
        username=username,
        password_hash=_hash_password(password, salt),
        password_salt=salt,
        role=role,
        tenant_scopes=tenant_scopes,
        namespace_scopes=namespace_scopes,
        environment_scopes=environment_scopes,
        workload_scopes=workload_scopes,
        service_account_scopes=service_account_scopes,
        workload_label_scopes=workload_label_scopes,
        approver_groups=approver_groups,
        created_at=datetime.now(UTC),
    )


def _hash_password(password: str, salt: str) -> str:
    return hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt.encode("utf-8"), 100_000).hex()


def _verify_password(password: str, user: IdentityUser) -> bool:
    if user.password_salt == "legacy-sha256":
        return hashlib.sha256(password.encode("utf-8")).hexdigest() == user.password_hash
    return _hash_password(password, user.password_salt) == user.password_hash
