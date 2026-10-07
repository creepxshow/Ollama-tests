"""Ground-truth labels.

You generate ground truth by running known techniques (e.g. Atomic Red Team)
in a lab and recording, per technique, the UTC start/stop time. A benign
capture simply has no label rows, so every unit in it is benign.

Label file is CSV with columns:
    technique_id,start,end,host,image_contains,note

  * technique_id  : e.g. T1059.004  (required)
  * start,end     : ISO-8601 UTC timestamps bounding the activity (required)
  * host          : optional; restrict to this host
  * image_contains: optional substring; an event only matches if one of its
                    image / parent_image / command_line / target_filename
                    fields contains this string (tightens loose time windows)
  * note          : free text, ignored by the tool

A unit's gold set = union of techniques of all its events that fall inside a
matching window.
"""
from __future__ import annotations

import csv
from dataclasses import dataclass
from datetime import datetime
from typing import Optional

from .schema import Event
from .process_tree import AnalysisUnit


@dataclass
class LabelWindow:
    technique_id: str
    start: datetime
    end: datetime
    host: Optional[str] = None
    image_contains: Optional[str] = None


def _parse_ts(val: str) -> datetime:
    val = val.strip()
    dt = datetime.fromisoformat(val)
    if dt.tzinfo is None:
        from datetime import timezone
        dt = dt.replace(tzinfo=timezone.utc)
    return dt


def load_labels(path: str) -> list[LabelWindow]:
    out: list[LabelWindow] = []
    with open(path, newline="", encoding="utf-8") as fh:
        reader = csv.DictReader(fh)
        for row in reader:
            tid = (row.get("technique_id") or "").strip()
            if not tid:
                continue
            out.append(LabelWindow(
                technique_id=tid,
                start=_parse_ts(row["start"]),
                end=_parse_ts(row["end"]),
                host=(row.get("host") or "").strip() or None,
                image_contains=(row.get("image_contains") or "").strip() or None,
            ))
    return out


def _event_matches(ev: Event, w: LabelWindow) -> bool:
    if ev.timestamp is None:
        return False
    if not (w.start <= ev.timestamp <= w.end):
        return False
    if w.host and ev.host and w.host != ev.host:
        return False
    if w.image_contains:
        hay = " ".join(filter(None, [
            ev.image, ev.parent_image, ev.command_line,
            ev.parent_command_line, ev.target_filename,
        ])).lower()
        if w.image_contains.lower() not in hay:
            return False
    return True


def gold_for_event(ev: Event, windows: list[LabelWindow]) -> set[str]:
    return {w.technique_id for w in windows if _event_matches(ev, w)}


def gold_for_unit(unit: AnalysisUnit, windows: list[LabelWindow]) -> set[str]:
    gold: set[str] = set()
    for ev in unit.events:
        gold |= gold_for_event(ev, windows)
    return gold
