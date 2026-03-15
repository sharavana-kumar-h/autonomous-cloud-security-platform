from cloud_platform.models import DatabaseProtocolEnvelope
from cloud_platform.protocols import protocol_frames_to_envelope


def test_protocol_frames_convert_to_normalized_events() -> None:
    payload = DatabaseProtocolEnvelope.model_validate(
        {
            "tenant_id": "tenant-z",
            "source": "mysql-proxy",
            "frames": [
                {
                    "frame_id": "mysql-1",
                    "protocol": "mysql",
                    "message_type": "login",
                    "timestamp": "2026-03-15T12:00:00Z",
                    "actor": {"user": "svc-reporting", "ip": "10.0.0.40"},
                    "workload": {"cluster": "prod", "namespace": "reports", "pod": "worker-1", "container": "job"},
                    "database_name": "analytics",
                    "session_id": "mysql-55"
                },
                {
                    "frame_id": "mysql-2",
                    "protocol": "mysql",
                    "message_type": "command",
                    "timestamp": "2026-03-15T12:00:01Z",
                    "actor": {"user": "svc-reporting", "ip": "10.0.0.40"},
                    "workload": {"cluster": "prod", "namespace": "reports", "pod": "worker-1", "container": "job"},
                    "database_name": "analytics",
                    "session_id": "mysql-55",
                    "statement": "SELECT * FROM jobs"
                }
            ]
        }
    )

    envelope = protocol_frames_to_envelope(payload)

    assert envelope.tenant_id == "tenant-z"
    assert len(envelope.events) == 2
    assert envelope.events[0].database is not None
    assert envelope.events[0].database.engine == "mysql"
    assert envelope.events[1].database is not None
    assert envelope.events[1].database.statement == "SELECT * FROM jobs"
