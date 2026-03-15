# Architecture

## Target Pipeline

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

## Implemented In This Repo

- `src/cloud_platform/models.py`
  Shared schema for heterogeneous telemetry events, policy allowlists, workload identity fields, and workload scope keys.
- `src/cloud_platform/protocols.py`
  Converts PostgreSQL/MySQL-style proxy frames into normalized telemetry events.
- `src/cloud_platform/service.py`
  Control-plane service for ingest, replay, and API-facing orchestration.
- `src/cloud_platform/analytics.py`
  Session clustering and anomaly scoring logic.
- `src/cloud_platform/detections.py`
  ATT&CK-style detections, debugging context, and mitigation planning.
- `src/cloud_platform/controller.py`
  Guarded remediation plans with approval gates, simulated commands, and rollback guidance.
- `src/cloud_platform/kubernetes_adapter.py`
  Real Kubernetes API adapter with dry-run support and safe local fallback behavior.
- `src/cloud_platform/tenant_policy.py`
  Tenant-scoped remediation policy registry for action allowlists, namespace bounds, and approval thresholds.
- `src/cloud_platform/policy_store.py`
  Local control-plane persistence for tenant remediation policies.
- `src/cloud_platform/audit.py`
  Append-only audit log for protected control-plane mutations.
- `src/cloud_platform/exception_store.py`
  Persistent time-bounded remediation exceptions used for explicit selector-policy overrides.
- `src/cloud_platform/identity_store.py`
  Persisted identities plus role and password lifecycle management.
- `src/cloud_platform/jwt_auth.py`
  Signed JWT issuance and verification for control-plane authentication with tenant, namespace, environment, workload, service-account, and label-scoped permissions.
- `src/cloud_platform/selectors.py`
  Admission-style selector evaluation for tenant policies using workload, environment, service-account, and label expressions.
- `src/cloud_platform/approval_store.py`
  Persistent remediation approval records that execution can verify, revoke, and count toward multi-approver policy gates.
- `src/cloud_platform/main.py`
  Also exposes staged remediation approval and revocation APIs for guarded execution workflows.
- `src/cloud_platform/revocation_store.py`
  Persistent revocation tracking for logged-out JWTs.
- `src/cloud_platform/repository.py`
  Durable event log integration plus session and detection storage.
- `src/cloud_platform/persistence.py`
  Append-only local stream log used for replay and restart recovery.

## Next Steps

- replace the local event log with Kafka, Redpanda, or another durable event bus
- deepen the wire-protocol layer from simplified frames into byte-level parser support
- add richer policy languages, trust chains, and exception workflows on top of the current selector-based admission rules
- split ingest, analytics, and case-management APIs into separate services
