from __future__ import annotations

from dataclasses import dataclass, field

from .models import Detection, SessionCluster, StreamRecord
from .persistence import StreamEventLog


@dataclass
class PlatformRepository:
    event_log: StreamEventLog | None = None
    stream: list[StreamRecord] = field(default_factory=list)
    sessions: dict[str, SessionCluster] = field(default_factory=dict)
    detections: dict[str, Detection] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if self.event_log is not None and not self.stream:
            self.stream = self.event_log.read_all()

    def append_stream(self, record: StreamRecord) -> None:
        if self.event_log is not None:
            self.event_log.append(record)
        self.stream.append(record)

    def upsert_session(self, session: SessionCluster) -> None:
        self.sessions[session.session_key] = session

    def upsert_detection(self, detection: Detection) -> None:
        self.detections[detection.detection_id] = detection

    def list_stream(self) -> list[StreamRecord]:
        return list(self.stream)

    def list_sessions(self) -> list[SessionCluster]:
        return sorted(self.sessions.values(), key=lambda item: item.started_at, reverse=True)

    def list_detections(self) -> list[Detection]:
        return sorted(self.detections.values(), key=lambda item: item.confidence, reverse=True)

    def next_offset(self) -> int:
        return len(self.stream)

    def reset_derived_state(self) -> None:
        self.sessions.clear()
        self.detections.clear()
