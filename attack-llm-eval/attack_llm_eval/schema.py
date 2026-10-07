"""Normalized event schema.

Every log source is parsed into a list of `Event` objects. Everything
downstream (process-tree building, windowing, prompting, scoring) operates on
this format only, so adding a new log source means writing one parser that
emits `Event`s and nothing else changes.
"""
from __future__ import annotations

import json
from dataclasses import dataclass, field, asdict
from datetime import datetime
from typing import Any, Iterable, Iterator, Optional


# Canonical event types. Keep this list small and source-agnostic.
EVENT_TYPES = {
    "process_create",
    "process_terminate",
    "network_connect",
    "file_create",
    "file_delete",
    "raw_access_read",
    "process_access",
    "other",
}


@dataclass
class Event:
    """A single normalized host-telemetry event."""

    event_id: str                       # stable unique id for this event
    timestamp: Optional[datetime]       # event time (UTC) if known
    event_type: str                     # one of EVENT_TYPES
    host: Optional[str] = None
    user: Optional[str] = None

    # process identity / lineage
    pid: Optional[int] = None
    ppid: Optional[int] = None
    process_guid: Optional[str] = None
    parent_process_guid: Optional[str] = None

    # process details
    image: Optional[str] = None
    command_line: Optional[str] = None
    parent_image: Optional[str] = None
    parent_command_line: Optional[str] = None
    current_directory: Optional[str] = None

    # file events
    target_filename: Optional[str] = None

    # network events
    dest_ip: Optional[str] = None
    dest_port: Optional[int] = None
    dest_hostname: Optional[str] = None
    protocol: Optional[str] = None

    # original source record, for debugging / faithful evidence checks
    raw: dict = field(default_factory=dict)

    def __post_init__(self) -> None:
        if self.event_type not in EVENT_TYPES:
            self.event_type = "other"

    # ---- serialization -------------------------------------------------
    def to_dict(self) -> dict:
        d = asdict(self)
        d["timestamp"] = self.timestamp.isoformat() if self.timestamp else None
        return d

    @classmethod
    def from_dict(cls, d: dict) -> "Event":
        d = dict(d)
        ts = d.get("timestamp")
        d["timestamp"] = datetime.fromisoformat(ts) if ts else None
        # drop unknown keys defensively
        known = {f for f in cls.__dataclass_fields__}  # type: ignore[attr-defined]
        return cls(**{k: v for k, v in d.items() if k in known})

    # ---- human / model readable text ----------------------------------
    def to_text(self) -> str:
        """Compact single-event rendering fed to the model and used for the
        evidence-faithfulness check."""
        parts = [f"[{self.event_type}]"]
        if self.timestamp:
            parts.append(f"time={self.timestamp.isoformat()}")
        if self.user:
            parts.append(f"user={self.user}")
        for label, val in [
            ("image", self.image),
            ("cmdline", self.command_line),
            ("parent_image", self.parent_image),
            ("parent_cmdline", self.parent_command_line),
            ("cwd", self.current_directory),
            ("target_file", self.target_filename),
            ("dest_ip", self.dest_ip),
            ("dest_port", self.dest_port),
            ("dest_host", self.dest_hostname),
            ("proto", self.protocol),
            ("pid", self.pid),
            ("ppid", self.ppid),
        ]:
            if val not in (None, ""):
                parts.append(f"{label}={val}")
        return " ".join(str(p) for p in parts)


def write_ndjson(events: Iterable[Event], path: str) -> int:
    n = 0
    with open(path, "w", encoding="utf-8") as fh:
        for ev in events:
            fh.write(json.dumps(ev.to_dict(), ensure_ascii=False) + "\n")
            n += 1
    return n


def read_ndjson(path: str) -> Iterator[Event]:
    with open(path, "r", encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if line:
                yield Event.from_dict(json.loads(line))
