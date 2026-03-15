from __future__ import annotations

from .models import (
    ActorContext,
    DatabaseContext,
    DatabaseProtocolEnvelope,
    DatabaseProtocolFrame,
    NetworkContext,
    TelemetryEnvelope,
    TelemetryEvent,
    WorkloadContext,
)


def protocol_frames_to_envelope(payload: DatabaseProtocolEnvelope) -> TelemetryEnvelope:
    events: list[TelemetryEvent] = []
    for frame in payload.frames:
        statement = _statement_for_frame(frame)
        if statement is None:
            continue
        events.append(
            TelemetryEvent(
                event_id=frame.frame_id,
                kind="database_query",
                timestamp=frame.timestamp,
                actor=ActorContext(user=frame.actor.user, ip=frame.actor.ip),
                workload=WorkloadContext(
                    cluster=frame.workload.cluster,
                    namespace=frame.workload.namespace,
                    pod=frame.workload.pod,
                    container=frame.workload.container,
                    service_account=frame.workload.service_account,
                    labels=frame.workload.labels,
                ),
                database=DatabaseContext(
                    engine=frame.protocol,
                    name=frame.database_name,
                    session_id=frame.session_id,
                    statement=statement,
                    rows_returned=frame.rows_returned,
                ),
                network=NetworkContext(
                    destination_ip=frame.destination_ip,
                    destination_port=frame.destination_port,
                    protocol="TCP",
                ),
                attributes={
                    "protocol_message_type": frame.message_type,
                    "wire_protocol": frame.protocol,
                    **frame.metadata,
                },
            )
        )
    return TelemetryEnvelope(tenant_id=payload.tenant_id, source=payload.source, events=events)


def _statement_for_frame(frame: DatabaseProtocolFrame) -> str | None:
    if frame.message_type in {"query", "command"}:
        return frame.statement or ""
    if frame.message_type in {"startup", "login"}:
        return f"{frame.protocol} session start for {frame.actor.user}"
    if frame.message_type == "terminate":
        return f"{frame.protocol} session terminate for {frame.actor.user}"
    return frame.statement
