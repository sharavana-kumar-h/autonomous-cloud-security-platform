from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Protocol

from .models import KubernetesActionResult, RemediationAction, RemediationPlan

try:
    from kubernetes import client, config
    from kubernetes.client import ApiException
except ImportError:  # pragma: no cover
    client = None
    config = None
    ApiException = Exception


class KubernetesAdapter(Protocol):
    def apply_plan(self, plan: RemediationPlan, dry_run: bool = True) -> list[KubernetesActionResult]:
        ...


@dataclass
class SafeKubernetesAdapter:
    reason: str = "Kubernetes client is not configured; returning dry-run style controller results."

    def apply_plan(self, plan: RemediationPlan, dry_run: bool = True) -> list[KubernetesActionResult]:
        results: list[KubernetesActionResult] = []
        for action in plan.actions:
            namespace = _namespace_from_target(action.target)
            results.append(
                KubernetesActionResult(
                    action_id=action.action_id,
                    action_type=action.action_type,
                    target=action.target,
                    status="dry_run",
                    resource_kind="Simulated",
                    resource_name=action.target,
                    namespace=namespace,
                    details=self.reason,
                )
            )
        return results


@dataclass
class KubernetesControllerAdapter:
    namespace_prefix: str | None = None

    def __post_init__(self) -> None:
        if client is None or config is None:  # pragma: no cover
            raise RuntimeError("The kubernetes package is required to use the Kubernetes controller adapter.")
        self._load_config()
        self.core_api = client.CoreV1Api()
        self.apps_api = client.AppsV1Api()
        self.networking_api = client.NetworkingV1Api()

    def apply_plan(self, plan: RemediationPlan, dry_run: bool = True) -> list[KubernetesActionResult]:
        results: list[KubernetesActionResult] = []
        for action in plan.actions:
            try:
                results.append(self._apply_action(action, dry_run=dry_run))
            except ApiException as exc:  # pragma: no cover
                results.append(
                    KubernetesActionResult(
                        action_id=action.action_id,
                        action_type=action.action_type,
                        target=action.target,
                        status="failed",
                        resource_kind="KubernetesApiError",
                        resource_name=action.target,
                        namespace=self._namespace_for_action(action),
                        details=f"{exc.status}: {exc.reason}",
                    )
                )
        return results

    def _apply_action(self, action: RemediationAction, dry_run: bool) -> KubernetesActionResult:
        if action.action_type == "isolate_namespace":
            return self._label_namespace(action, dry_run)
        if action.action_type == "suspend_service_account":
            return self._patch_service_account(action, dry_run)
        if action.action_type == "block_egress":
            return self._apply_network_policy(action, dry_run)
        if action.action_type == "rotate_credentials":
            return self._restart_deployments(action, dry_run)
        if action.action_type == "snapshot_forensics":
            return self._create_forensics_configmap(action, dry_run)
        raise ValueError(f"Unsupported action type: {action.action_type}")

    def _label_namespace(self, action: RemediationAction, dry_run: bool) -> KubernetesActionResult:
        namespace = self._resolve_namespace(action.target)
        body = {"metadata": {"labels": {"security.cloud/quarantine": "enabled"}}}
        self.core_api.patch_namespace(namespace, body, dry_run="All" if dry_run else None)
        return self._result(action, dry_run, "Namespace", namespace, namespace, "Applied quarantine label to namespace.")

    def _patch_service_account(self, action: RemediationAction, dry_run: bool) -> KubernetesActionResult:
        namespace = self._namespace_for_action(action)
        body = {"automountServiceAccountToken": False}
        self.core_api.patch_namespaced_service_account(
            "default",
            namespace,
            body,
            dry_run="All" if dry_run else None,
        )
        return self._result(action, dry_run, "ServiceAccount", "default", namespace, "Disabled automount on default service account.")

    def _apply_network_policy(self, action: RemediationAction, dry_run: bool) -> KubernetesActionResult:
        namespace = self._resolve_namespace(action.target)
        name = "security-cloud-deny-egress"
        body = client.V1NetworkPolicy(
            metadata=client.V1ObjectMeta(name=name, namespace=namespace),
            spec=client.V1NetworkPolicySpec(
                pod_selector=client.V1LabelSelector(match_labels={}),
                policy_types=["Egress"],
                egress=[],
            ),
        )
        try:
            self.networking_api.replace_namespaced_network_policy(
                name=name,
                namespace=namespace,
                body=body,
                dry_run="All" if dry_run else None,
            )
        except ApiException as exc:
            if getattr(exc, "status", None) != 404:
                raise
            self.networking_api.create_namespaced_network_policy(
                namespace=namespace,
                body=body,
                dry_run="All" if dry_run else None,
            )
        return self._result(action, dry_run, "NetworkPolicy", name, namespace, "Applied deny-all egress network policy.")

    def _restart_deployments(self, action: RemediationAction, dry_run: bool) -> KubernetesActionResult:
        namespace = self._resolve_namespace(action.target)
        deployments = self.apps_api.list_namespaced_deployment(namespace=namespace).items
        timestamp = datetime.now(UTC).isoformat()
        for deployment in deployments:
            body = {
                "spec": {
                    "template": {
                        "metadata": {
                            "annotations": {
                                "kubectl.kubernetes.io/restartedAt": timestamp,
                            }
                        }
                    }
                }
            }
            self.apps_api.patch_namespaced_deployment(
                deployment.metadata.name,
                namespace,
                body,
                dry_run="All" if dry_run else None,
            )
        detail = f"Restarted {len(deployments)} deployment(s) to trigger credential-dependent rollout."
        return self._result(action, dry_run, "Deployment", "*", namespace, detail)

    def _create_forensics_configmap(self, action: RemediationAction, dry_run: bool) -> KubernetesActionResult:
        namespace = self._namespace_for_action(action)
        name = f"{self._sanitize_name(action.target)}-forensics-request"
        body = client.V1ConfigMap(
            metadata=client.V1ObjectMeta(name=name, namespace=namespace),
            data={
                "requestedAt": datetime.now(UTC).isoformat(),
                "reason": action.reason,
                "target": action.target,
            },
        )
        try:
            self.core_api.replace_namespaced_config_map(
                name=name,
                namespace=namespace,
                body=body,
                dry_run="All" if dry_run else None,
            )
        except ApiException as exc:
            if getattr(exc, "status", None) != 404:
                raise
            self.core_api.create_namespaced_config_map(
                namespace=namespace,
                body=body,
                dry_run="All" if dry_run else None,
            )
        return self._result(action, dry_run, "ConfigMap", name, namespace, "Recorded a forensic capture request for the workload.")

    def _namespace_for_action(self, action: RemediationAction) -> str:
        if action.action_type in {"isolate_namespace", "block_egress", "rotate_credentials"}:
            return self._resolve_namespace(action.target)
        parts = action.target.split("/")
        if len(parts) >= 2:
            return self._resolve_namespace(parts[1])
        return self._resolve_namespace("default")

    def _resolve_namespace(self, namespace: str) -> str:
        if self.namespace_prefix:
            return f"{self.namespace_prefix}-{namespace}"
        return namespace

    def _result(
        self,
        action: RemediationAction,
        dry_run: bool,
        resource_kind: str,
        resource_name: str,
        namespace: str | None,
        details: str,
    ) -> KubernetesActionResult:
        return KubernetesActionResult(
            action_id=action.action_id,
            action_type=action.action_type,
            target=action.target,
            status="dry_run" if dry_run else "applied",
            resource_kind=resource_kind,
            resource_name=resource_name,
            namespace=namespace,
            details=details,
        )

    def _load_config(self) -> None:
        try:
            config.load_incluster_config()
        except Exception:
            config.load_kube_config()

def _sanitize_name(self, raw: str) -> str:
        return raw.replace("/", "-").replace("_", "-").lower()


def _namespace_from_target(target: str) -> str | None:
    parts = target.split("/")
    if len(parts) >= 2:
        return parts[1]
    if target:
        return target
    return None
