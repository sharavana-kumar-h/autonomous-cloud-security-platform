from pathlib import Path

from cloud_platform.identity_store import IdentityStore
from cloud_platform.models import CreateUserRequest


def test_identity_store_bootstraps_and_creates_users(tmp_path: Path) -> None:
    store = IdentityStore(tmp_path / "identities.json", "admin", "change-me-now")

    admin = store.authenticate("admin", "change-me-now")
    assert admin is not None
    assert admin.role == "platform_admin"

    created = store.create_user(
        CreateUserRequest(
            username="viewer-user",
            password="viewer-pass",
            role="viewer",
            approver_groups=["tenant_owner"],
        )
    )
    assert created.username == "viewer-user"
    assert created.approver_groups == ["tenant_owner"]
    assert store.authenticate("viewer-user", "viewer-pass") is not None
