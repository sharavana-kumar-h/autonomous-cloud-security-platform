from cloud_platform.models import TenantResponsePolicy, WorkloadContext
from cloud_platform.selectors import evaluate_policy_selectors


def test_selector_expressions_support_all_mode() -> None:
    policy = TenantResponsePolicy(
        tenant_id="tenant-a",
        selector_expressions=[
            "environment=prod",
            "namespace=payments",
            "service_account=payments-api",
            "label.app=payments-api",
            "workload=prod/payments/api*",
        ],
        selector_mode="all",
    )
    workload = WorkloadContext(
        cluster="prod",
        namespace="payments",
        pod="api-7d9",
        service_account="payments-api",
        labels={"app": "payments-api", "tier": "backend"},
    )

    allowed, reason = evaluate_policy_selectors(workload, policy)

    assert allowed is True
    assert reason is None


def test_selector_expressions_report_non_match() -> None:
    policy = TenantResponsePolicy(
        tenant_id="tenant-a",
        selector_expressions=["service_account=payments-api", "label.team=security"],
        selector_mode="all",
    )
    workload = WorkloadContext(
        cluster="prod",
        namespace="payments",
        pod="api-7d9",
        service_account="payments-api",
        labels={"app": "payments-api"},
    )

    allowed, reason = evaluate_policy_selectors(workload, policy)

    assert allowed is False
    assert reason == "At least one selector expression did not match the workload context."
