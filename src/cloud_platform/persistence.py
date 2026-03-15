from __future__ import annotations

from pathlib import Path

from .models import StreamRecord


class StreamEventLog:
    def __init__(self, path: Path) -> None:
        self.path = path
        self.path.parent.mkdir(parents=True, exist_ok=True)
        if not self.path.exists():
            self.path.touch()

    def append(self, record: StreamRecord) -> None:
        with self.path.open("a", encoding="utf-8") as handle:
            handle.write(record.model_dump_json())
            handle.write("\n")

    def read_all(self) -> list[StreamRecord]:
        records: list[StreamRecord] = []
        with self.path.open("r", encoding="utf-8") as handle:
            for line in handle:
                payload = line.strip()
                if not payload:
                    continue
                records.append(StreamRecord.model_validate_json(payload))
        return records
