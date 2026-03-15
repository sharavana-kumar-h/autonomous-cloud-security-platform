from __future__ import annotations

from fnmatch import fnmatch

from .models import TenantResponsePolicy, WorkloadContext


def evaluate_policy_selectors(
    workload: WorkloadContext | None,
    policy: TenantResponsePolicy,
) -> tuple[bool, str | None]:
    expressions = policy.selector_expressions
    if not expressions:
        return True, None
    if workload is None:
        return False, "No workload context was available for selector evaluation."

    results = [_evaluate_expression(expression, workload) for expression in expressions]
    if policy.selector_mode == "any":
        if any(result for result in results):
            return True, None
        return False, "No selector expression matched the workload context."
    if all(result for result in results):
        return True, None
    return False, "At least one selector expression did not match the workload context."


def _evaluate_expression(expression: str, workload: WorkloadContext) -> bool:
    expression = expression.strip()
    if not expression:
        return True
    operator = "!=" if "!=" in expression else "="
    if operator not in expression:
        raise ValueError(f"Unsupported selector expression: {expression}")
    key, value = expression.split(operator, 1)
    key = key.strip()
    value = value.strip()
    actual_values = _values_for_key(key, workload)
    matched = any(fnmatch(item, value) for item in actual_values)
    return not matched if operator == "!=" else matched


def _values_for_key(key: str, workload: WorkloadContext) -> list[str]:
    if key == "namespace":
        return [workload.namespace or ""]
    if key == "environment":
        return [workload.environment or ""]
    if key == "workload":
        return [workload.workload_scope_key]
    if key == "service_account":
        return [workload.service_account or ""]
    if key.startswith("label."):
        label_key = key.removeprefix("label.")
        return [workload.labels.get(label_key, "")]
    raise ValueError(f"Unsupported selector key: {key}")
