from __future__ import annotations

from hashlib import sha1

from .models import Detection, SessionCluster, StreamRecord


def build_detections(session: SessionCluster, records: list[StreamRecord]) -> list[Detection]:
    session_records = [record for record in records if record.event.event_id in set(session.event_ids)]
    statement_blob = " ".join(
        record.event.database.statement.lower()
        for record in session_records
        if record.event.database
    )
    app_blob = " ".join(
        record.event.application.message.lower()
        for record in session_records
        if record.event.application
    )

    detections: list[Detection] = []

    if "copy " in statement_blob and "program" in statement_blob:
        detections.append(
            Detection(
                detection_id=_detection_id(session.session_key, "db-command-execution"),
                tenant_id=session.tenant_id,
                severity="critical",
                title="Suspicious database command execution pattern",
                summary="A database session issued a statement pattern consistent with server-side program execution and bulk data transfer.",
                mitre_tactics=["Execution", "Exfiltration"],
                mitre_techniques=["T1059", "T1048"],
                confidence=min(round(session.anomaly_score + 0.15, 2), 0.99),
                session_key=session.session_key,
                evidence_event_ids=session.event_ids,
                debugging_context=[
                    f"Inspect workload {session.workload} for deployment drift or credential abuse.",
                    "Correlate the database session with outbound network connections and recent config changes.",
                ],
                mitigation_plan=[
                    "Quarantine the implicated workload or revoke its service account token.",
                    "Terminate the database session and rotate any exposed credentials.",
                    "Block the observed outbound destination and preserve forensic logs.",
                ],
            )
        )

    if any(record.event.kubernetes and record.event.kubernetes.resource == "secrets" for record in session_records):
        detections.append(
            Detection(
                detection_id=_detection_id(session.session_key, "secret-access-expansion"),
                tenant_id=session.tenant_id,
                severity="high",
                title="Suspicious Kubernetes secret manipulation",
                summary="Workload behavior included sensitive Kubernetes secret creation or duplication during an anomalous session.",
                mitre_tactics=["Credential Access", "Privilege Escalation"],
                mitre_techniques=["T1552", "T1078"],
                confidence=min(round(session.anomaly_score + 0.05, 2), 0.99),
                session_key=session.session_key,
                evidence_event_ids=session.event_ids,
                debugging_context=[
                    "Review RBAC changes, admission logs, and the originating pod identity.",
                    "Compare this action with the expected deployment workflow for the namespace.",
                ],
                mitigation_plan=[
                    "Suspend the service account or workload identity used by the pod.",
                    "Delete unauthorized duplicated secrets and rotate dependent credentials.",
                    "Apply an admission-control or RBAC policy to block repeat actions.",
                ],
            )
        )

    if "unexpected outbound connection" in app_blob:
        detections.append(
            Detection(
                detection_id=_detection_id(session.session_key, "debug-correlation"),
                tenant_id=session.tenant_id,
                severity="medium",
                title="Application instability correlated with security anomaly",
                summary="Application error logs align with suspicious control-plane and database activity, indicating possible live compromise or abuse.",
                mitre_tactics=["Discovery", "Command and Control"],
                mitre_techniques=["T1082", "T1071"],
                confidence=max(round(session.anomaly_score - 0.05, 2), 0.4),
                session_key=session.session_key,
                evidence_event_ids=session.event_ids,
                debugging_context=[
                    "Inspect traces around the failing request path and match them against the suspicious session timeline.",
                    "Diff the current deployment against the last known good release artifact.",
                ],
                mitigation_plan=[
                    "Shift traffic away from the affected deployment if error rate continues rising.",
                    "Capture memory, pod logs, and deployment metadata for incident response.",
                ],
            )
        )

    return detections


def _detection_id(session_key: str, suffix: str) -> str:
    return sha1(f"{session_key}:{suffix}".encode("utf-8")).hexdigest()[:12]
