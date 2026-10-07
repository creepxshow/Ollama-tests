"""Group raw events into *analysis units* — the thing the model classifies.

Three granularities (an experimental variable in the study):

  * "event"        : one unit per event. Maximum volume, least context.
  * "process_tree" : one unit per root process, containing that process's
                     subtree of events (its descendants' process/file/network
                     activity). Usually the most informative.
  * "window"       : one unit per fixed time window (e.g. 60s) per host.

A unit carries the events plus a rendered text block used both as the model
prompt body and as the reference text for evidence-faithfulness checks.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import timedelta
from typing import Optional

from .schema import Event


@dataclass
class AnalysisUnit:
    unit_id: str
    events: list[Event] = field(default_factory=list)
    host: Optional[str] = None

    @property
    def start(self):
        ts = [e.timestamp for e in self.events if e.timestamp]
        return min(ts) if ts else None

    @property
    def end(self):
        ts = [e.timestamp for e in self.events if e.timestamp]
        return max(ts) if ts else None

    def to_text(self, max_events: int = 60) -> str:
        """Render the unit as a numbered event list for the model."""
        lines = []
        evs = self.events[:max_events]
        for i, ev in enumerate(evs):
            lines.append(f"{i+1}. {ev.to_text()}")
        if len(self.events) > max_events:
            lines.append(f"... (+{len(self.events) - max_events} more events truncated)")
        return "\n".join(lines)


# --------------------------------------------------------------------------
def _by_time(events: list[Event]) -> list[Event]:
    return sorted(events, key=lambda e: (e.timestamp is None, e.timestamp))


def units_per_event(events: list[Event]) -> list[AnalysisUnit]:
    return [AnalysisUnit(unit_id=e.event_id, events=[e], host=e.host)
            for e in _by_time(events)]


def units_per_window(events: list[Event], window_seconds: int = 60) -> list[AnalysisUnit]:
    units: list[AnalysisUnit] = []
    by_host: dict[Optional[str], list[Event]] = {}
    for e in events:
        by_host.setdefault(e.host, []).append(e)
    for host, evs in by_host.items():
        evs = _by_time(evs)
        bucket: list[Event] = []
        bucket_start = None
        idx = 0
        for e in evs:
            if e.timestamp is None:
                bucket.append(e)
                continue
            if bucket_start is None:
                bucket_start = e.timestamp
            if e.timestamp - bucket_start > timedelta(seconds=window_seconds):
                units.append(AnalysisUnit(
                    unit_id=f"{host}:w{idx}", events=bucket, host=host))
                idx += 1
                bucket = []
                bucket_start = e.timestamp
            bucket.append(e)
        if bucket:
            units.append(AnalysisUnit(unit_id=f"{host}:w{idx}", events=bucket, host=host))
    return units


def units_per_process_tree(events: list[Event]) -> list[AnalysisUnit]:
    """One unit per root process. A process's unit contains its own
    process_create plus all events whose process is that process or a
    descendant of it (by ProcessGuid lineage). Events without GUIDs fall back
    to their own single-event unit."""
    # index process_create events by guid
    guid_to_parent: dict[str, Optional[str]] = {}
    guid_present: set[str] = set()
    for e in events:
        if e.event_type == "process_create" and e.process_guid:
            guid_to_parent[e.process_guid] = e.parent_process_guid
            guid_present.add(e.process_guid)

    def root_of(guid: Optional[str]) -> Optional[str]:
        """Walk up to the highest ancestor that we actually observed."""
        seen = set()
        cur = guid
        root = guid
        while cur and cur not in seen:
            seen.add(cur)
            parent = guid_to_parent.get(cur)
            if parent in guid_present:
                root = parent
                cur = parent
            else:
                break
        return root

    groups: dict[str, list[Event]] = {}
    loose: list[Event] = []
    for e in events:
        g = e.process_guid
        if g:
            r = root_of(g) or g
            groups.setdefault(r, []).append(e)
        else:
            loose.append(e)

    units: list[AnalysisUnit] = []
    for root_guid, evs in groups.items():
        evs = _by_time(evs)
        host = next((x.host for x in evs if x.host), None)
        units.append(AnalysisUnit(unit_id=f"tree:{root_guid}", events=evs, host=host))
    for e in loose:
        units.append(AnalysisUnit(unit_id=f"loose:{e.event_id}", events=[e], host=e.host))

    # stable order by start time
    units.sort(key=lambda u: (u.start is None, u.start))
    return units


def build_units(events: list[Event], granularity: str = "process_tree",
               window_seconds: int = 60) -> list[AnalysisUnit]:
    if granularity == "event":
        return units_per_event(events)
    if granularity == "window":
        return units_per_window(events, window_seconds)
    if granularity == "process_tree":
        return units_per_process_tree(events)
    raise ValueError(f"unknown granularity: {granularity}")
