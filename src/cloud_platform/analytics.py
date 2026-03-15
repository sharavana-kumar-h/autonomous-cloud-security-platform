from __future__ import annotations

from collections import defaultdict

from .models import SessionCluster, StreamRecord, TelemetryEvent


def _workload_name(event: TelemetryEvent) -> str:
    parts = [
        event.workload.cluster or "unknown-cluster",
        event.workload.namespace or "unknown-namespace",
        event.workload.pod or "unknown-pod",
    ]
    return "/".join(parts)


def build_session_clusters(records: list[StreamRecord]) -> list[SessionCluster]:
    grouped: dict[str, list[StreamRecord]] = defaultdict(list)
    for record in records:
        key_parts = [
            record.tenant_id,
            record.event.actor.user,
            record.event.database.session_id if record.event.database else _workload_name(record.event),
        ]
        grouped["::".join(key_parts)].append(record)

    sessions: list[SessionCluster] = []
    for session_key, session_records in grouped.items():
        session_records.sort(key=lambda item: item.event.timestamp)
        reasons: list[str] = []
        anomaly_score = 0.1

        has_db = any(item.event.kind == "database_query" for item in session_records)
        has_k8s = any(item.event.kind == "kubernetes_audit" for item in session_records)
        has_app = any(item.event.kind == "application_log" for item in session_records)
        if has_db and has_k8s:
            anomaly_score += 0.3
            reasons.append("Database activity correlated with privileged Kubernetes control-plane activity.")
        if has_db and has_app:
            anomaly_score += 0.2
            reasons.append("Application instability aligns with suspicious database session behavior.")

        for item in session_records:
            event = item.event
            if event.database:
                statement = event.database.statement.lower()
                if "copy " in statement and "program" in statement:
                    anomaly_score += 0.35
                    reasons.append("Database statement resembles command execution or bulk exfiltration.")
                if event.database.rows_returned > 5000:
                    anomaly_score += 0.1
                    reasons.append("Unusually large result set returned from a database session.")
            if event.kubernetes and event.kubernetes.resource in {"secrets", "clusterroles", "rolebindings"}:
                anomaly_score += 0.15
                reasons.append("Sensitive Kubernetes resource modification detected.")
            if str(event.attributes.get("bytes_sent", 0)).isdigit() and int(event.attributes.get("bytes_sent", 0)) > 1_000_000:
                anomaly_score += 0.1
                reasons.append("High outbound byte volume suggests potential data movement.")

        anomaly_score = min(round(anomaly_score, 2), 0.99)
        workload = _workload_name(session_records[0].event)
        sessions.append(
            SessionCluster(
                session_key=session_key,
                tenant_id=session_records[0].tenant_id,
                actor=session_records[0].event.actor.user,
                workload=workload,
                event_ids=[item.event.event_id for item in session_records],
                kinds=[item.event.kind for item in session_records],
                started_at=session_records[0].event.timestamp,
                ended_at=session_records[-1].event.timestamp,
                anomaly_score=anomaly_score,
                reasons=reasons or ["Behavior deviates from normal workload baseline."],
            )
        )
    return sessions
