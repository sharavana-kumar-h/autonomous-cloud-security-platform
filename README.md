# Autonomous Cloud Security & Observability Platform

Cloud-native security and observability backend built around a normalized telemetry pipeline, database wire-protocol style ingestion, behavioral analytics, ATT&CK-aligned detections, debugging context, and automated mitigation planning.

## Architecture

```text
Database proxies      Kubernetes telemetry      Application logs
        \                     |                     /
                 Event streaming pipeline
                           |
                 Behavioral analytics engine
                           |
              Threat detection + debugging
                           |
             Automated mitigation controller
```

## What This Project Includes

- normalized event schema for database, Kubernetes, and application telemetry
- simplified PostgreSQL/MySQL proxy frame ingestion into normalized telemetry
- durable local event log with replayable envelopes
- session clustering across actors, workloads, and database sessions
- behavioral analytics for anomaly scoring and confidence estimation
- MITRE ATT&CK-oriented detection generation
- debugging context that ties detections back to workload, container, and query evidence
- mitigation planner with guarded automation recommendations
- Kubernetes controller adapter using the official Python client with dry-run by default
- FastAPI API, sample payloads, tests, Docker support, and Render config

## Project Layout

```text
autonomous-cloud-security-platform/
  src/cloud_platform/
  tests/
  samples/
  Dockerfile
  render.yaml
```

## Quick Start

```powershell
cd autonomous-cloud-security-platform
py -m venv .venv
.venv\Scripts\Activate.ps1
pip install -e .[dev]
uvicorn cloud_platform.main:app --reload
```

## API Endpoints

- `GET /health`
- `POST /auth/login`
- `POST /auth/logout`
- `GET /platform/architecture`
- `GET /platform/tenant-policies`
- `GET /platform/tenant-policies/{tenant_id}`
- `PUT /platform/tenant-policies/{tenant_id}`
- `DELETE /platform/tenant-policies/{tenant_id}`
- `GET /platform/audit-log`
- `GET /platform/remediation-exceptions`
- `POST /platform/remediation-exceptions`
- `DELETE /platform/remediation-exceptions/{exception_id}`
- `GET /platform/remediation-approvals`
- `POST /platform/remediation-approvals/{approval_id}/revoke`
- `POST /telemetry/ingest`
- `POST /telemetry/ingest/protocol`
- `GET /streams/events`
- `GET /streams/status`
- `GET /sessions`
- `GET /detections`
- `GET /detections/{detection_id}/remediation`
- `POST /detections/{detection_id}/approve`
- `POST /detections/execute`
- `POST /detections/replay`

## Kubernetes Controller Adapter

`POST /detections/execute` now routes remediation plans through a Kubernetes adapter.

- By default, execution is `dry_run=true`
- If kubeconfig or in-cluster config is available, the platform uses the official Kubernetes Python client
- If Kubernetes access is unavailable, the platform falls back to a safe simulated adapter instead of failing startup

Supported action mappings:

- `isolate_namespace` -> patches namespace quarantine labels
- `suspend_service_account` -> patches the default service account
- `block_egress` -> creates or replaces a deny-all egress `NetworkPolicy`
- `rotate_credentials` -> patches deployments with a restart annotation
- `snapshot_forensics` -> creates a forensic request `ConfigMap`

Relevant environment variables:

- `PLATFORM_KUBERNETES_DRY_RUN=true|false`
- `PLATFORM_KUBERNETES_NAMESPACE_PREFIX=<optional-prefix>`
- `PLATFORM_TENANT_POLICY_STORE_PATH=data/tenant_policies.json`
- `PLATFORM_TENANT_POLICIES_JSON=<json array of tenant response policies>`

Tenant policies are now persisted to a local control-plane store and managed through API endpoints. `PLATFORM_TENANT_POLICIES_JSON` is still supported as a bootstrap seed for first run.

## Control Plane Auth

Tenant policy, audit, and user-management endpoints now support signed JWT-based admin auth via `Authorization: Bearer <token>`.
The legacy `x-admin-token` header still works as a fallback when `PLATFORM_ADMIN_API_TOKEN` is configured.

Relevant environment variables:

- `PLATFORM_BOOTSTRAP_ADMIN_USERNAME=admin`
- `PLATFORM_BOOTSTRAP_ADMIN_PASSWORD=change-me-now`
- `PLATFORM_IDENTITY_STORE_PATH=data/identities.json`
- `PLATFORM_REVOCATION_STORE_PATH=data/revoked_tokens.json`
- `PLATFORM_JWT_SECRET=replace-this-jwt-secret`
- `PLATFORM_SESSION_EXPIRE_MINUTES=480`
- `PLATFORM_ADMIN_API_TOKEN=<required for protected control-plane endpoints>`
- `PLATFORM_AUDIT_LOG_PATH=data/audit_log.jsonl`
- `PLATFORM_REMEDIATION_EXCEPTION_STORE_PATH=data/remediation_exceptions.json`
- `PLATFORM_REMEDIATION_APPROVAL_STORE_PATH=data/remediation_approvals.json`

Login example:

```powershell
Invoke-RestMethod -Method Post `
  -Uri http://localhost:8000/auth/login `
  -ContentType 'application/json' `
  -Body '{"username":"admin","password":"change-me-now"}'
```

Passwords are now stored using salted PBKDF2 hashing, and issued bearer sessions expire automatically based on `PLATFORM_SESSION_EXPIRE_MINUTES`.
Logged-out JWTs are tracked in a revocation store so they cannot be reused before expiry.

Admin user management endpoints:

- `GET /platform/users`
- `POST /platform/users`
- `PATCH /platform/users/{username}/role`
- `PATCH /platform/users/{username}/scopes`
- `POST /platform/users/{username}/rotate-password`

Current control-plane roles:

- `platform_admin`: full control-plane access
- `policy_admin`: tenant policy read/write plus audit visibility within assigned tenants
- `remediation_approver`: can approve remediation execution and read policies within assigned tenants
- `auditor`: read-only access to audit, users, and policies
- `viewer`: read-only policy visibility

Non-global roles can be constrained with `tenant_scopes`, `namespace_scopes`, `environment_scopes`, `workload_scopes`, `service_account_scopes`, and `workload_label_scopes`, which are embedded in JWTs and enforced on tenant policy and remediation actions.
`environment_scopes` typically map to workload cluster or environment names like `prod` or `stage`, `workload_scopes` support wildcard patterns such as `prod/payments/api*`, `service_account_scopes` map to Kubernetes workload identity, and `workload_label_scopes` support selectors like `app=payments-api`.
Tenant policies can also use `selector_expressions` with admission-style matching such as `environment=prod`, `namespace=payments`, `workload=prod/payments/api*`, `service_account=payments-api`, or `label.app=payments-api`. `selector_mode` controls whether all expressions must match or any single expression is enough.
If a selector blocks remediation, operators can create a time-bounded remediation exception or a time-bounded approval record so the override path stays explicit and auditable.
Tenant policies can also require multiple distinct approvers with `required_approval_count`, and approvals can be revoked before execution if incident conditions change.
For higher-risk actions, `approval_stages` supports ordered signoff by specific roles and approver groups, such as a `security` reviewer followed by a `platform` approver.

Tenant policy example:

```json
[
  {
    "tenant_id": "acme-prod",
    "allowed_actions": ["snapshot_forensics", "block_egress"],
    "namespace_allowlist": ["payments", "checkout"],
    "environment_allowlist": ["prod"],
    "workload_allowlist": ["prod/payments/api*", "prod/checkout/web*"],
    "service_account_allowlist": ["payments-api", "checkout-web"],
    "workload_label_allowlist": ["app=payments-api", "tier=frontend"],
    "selector_expressions": ["environment=prod", "service_account=payments-api", "label.app=payments-api"],
    "selector_mode": "all",
    "required_approval_count": 2,
    "approval_stages": [
      {
        "stage_name": "ops_review",
        "required_roles": ["remediation_approver"],
        "required_approver_groups": ["security"],
        "required_count": 1,
        "applies_to_actions": ["block_egress"]
      },
      {
        "stage_name": "executive_signoff",
        "required_roles": ["platform_admin"],
        "required_approver_groups": ["platform"],
        "required_count": 1,
        "applies_to_actions": ["block_egress"]
      }
    ],
    "require_approval_for": ["block_egress", "snapshot_forensics"],
    "auto_execute_confidence_threshold": 0.98,
    "max_auto_severity": "medium"
  }
]
```

## Sample Run

```powershell
Invoke-RestMethod -Method Post `
  -Uri http://localhost:8000/telemetry/ingest `
  -ContentType 'application/json' `
  -InFile .\samples\hybrid_intrusion.json
```

Protocol-style ingestion sample:

```powershell
Invoke-RestMethod -Method Post `
  -Uri http://localhost:8000/telemetry/ingest/protocol `
  -ContentType 'application/json' `
  -InFile .\samples\postgres_proxy_frames.json
```

## Notes

This first implementation is intentionally a strong control-plane and analytics foundation. It now persists events to a local append-only log so detections survive restarts and can be replayed, and it includes a guarded remediation controller that turns detections into approval-aware Kubernetes-style action plans. It does not yet include real packet capture, Kubernetes operators, or a distributed stream broker, but the code is structured so those pieces can be added without replacing the API contract.
