"""Parse Sysmon for Linux events.

Sysmon for Linux (sysmonforlinux) writes each event to syslog as an XML
`<Event>...</Event>` blob. Depending on how you collect it you may have:

  * raw syslog lines  (/var/log/syslog, or `journalctl -t sysmon`)
  * one <Event> per line, or pretty-printed across lines
  * with or without the Windows events XML namespace

This parser is deliberately tolerant: it scans the text for `<Event ... >
... </Event>` spans, strips XML namespaces, and pulls fields out of the
`<EventData><Data Name="...">value</Data></EventData>` block.

Usage:
    from attack_llm_eval.normalize.sysmon_linux import parse_file
    events = list(parse_file("sysmon.log"))
"""
from __future__ import annotations

import re
import hashlib
from datetime import datetime, timezone
from typing import Iterator, Optional
import xml.etree.ElementTree as ET

from ..schema import Event

_EVENT_RE = re.compile(r"<Event\b.*?</Event>", re.DOTALL)
_NS_RE = re.compile(r"\sxmlns(:\w+)?=\"[^\"]*\"")

# Sysmon EventID -> normalized event_type
_EVENTID_MAP = {
    "1": "process_create",
    "3": "network_connect",
    "5": "process_terminate",
    "9": "raw_access_read",
    "10": "process_access",
    "11": "file_create",
    "23": "file_delete",
    "26": "file_delete",
}


def _localname(tag: str) -> str:
    return tag.split("}")[-1]


def _parse_utctime(val: Optional[str]) -> Optional[datetime]:
    if not val:
        return None
    val = val.strip()
    # Sysmon format: "2024-01-15 10:23:45.123"
    for fmt in ("%Y-%m-%d %H:%M:%S.%f", "%Y-%m-%d %H:%M:%S"):
        try:
            return datetime.strptime(val, fmt).replace(tzinfo=timezone.utc)
        except ValueError:
            continue
    # ISO fallback
    try:
        dt = datetime.fromisoformat(val)
        return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)
    except ValueError:
        return None


def _to_int(val: Optional[str]) -> Optional[int]:
    if val is None:
        return None
    try:
        return int(val)
    except (TypeError, ValueError):
        return None


def parse_event_xml(xml_text: str) -> Optional[Event]:
    """Parse one <Event>...</Event> string into an Event, or None if it is
    not a supported Sysmon record."""
    cleaned = _NS_RE.sub("", xml_text)
    try:
        root = ET.fromstring(cleaned)
    except ET.ParseError:
        return None

    system = {}
    data: dict[str, str] = {}
    for child in root:
        name = _localname(child.tag)
        if name == "System":
            for sc in child:
                sysname = _localname(sc.tag)
                if sysname == "EventID":
                    system["EventID"] = (sc.text or "").strip()
                elif sysname == "Computer":
                    system["Computer"] = (sc.text or "").strip()
                elif sysname == "Provider":
                    system["Provider"] = sc.attrib.get("Name", "")
        elif name == "EventData":
            for d in child:
                if _localname(d.tag) == "Data":
                    key = d.attrib.get("Name", "")
                    if key:
                        data[key] = (d.text or "")

    provider = system.get("Provider", "")
    if provider and "sysmon" not in provider.lower():
        return None

    event_type = _EVENTID_MAP.get(system.get("EventID", ""), "other")

    ts = _parse_utctime(data.get("UtcTime"))

    # Build a stable id: prefer ProcessGuid+UtcTime+EventID, else hash the xml.
    seed = (
        data.get("ProcessGuid", "")
        + "|" + data.get("UtcTime", "")
        + "|" + system.get("EventID", "")
        + "|" + data.get("TargetFilename", "")
        + "|" + data.get("DestinationIp", "")
    )
    if seed.strip("|"):
        event_id = hashlib.sha1(seed.encode("utf-8")).hexdigest()[:16]
    else:
        event_id = hashlib.sha1(cleaned.encode("utf-8")).hexdigest()[:16]

    return Event(
        event_id=event_id,
        timestamp=ts,
        event_type=event_type,
        host=system.get("Computer") or data.get("Computer"),
        user=data.get("User"),
        pid=_to_int(data.get("ProcessId")),
        ppid=_to_int(data.get("ParentProcessId")),
        process_guid=data.get("ProcessGuid"),
        parent_process_guid=data.get("ParentProcessGuid"),
        image=data.get("Image"),
        command_line=data.get("CommandLine"),
        parent_image=data.get("ParentImage"),
        parent_command_line=data.get("ParentCommandLine"),
        current_directory=data.get("CurrentDirectory"),
        target_filename=data.get("TargetFilename"),
        dest_ip=data.get("DestinationIp"),
        dest_port=_to_int(data.get("DestinationPort")),
        dest_hostname=data.get("DestinationHostname"),
        protocol=data.get("Protocol"),
        raw=data,
    )


def parse_text(text: str) -> Iterator[Event]:
    """Yield Events from a blob of text that contains Sysmon <Event> records."""
    for match in _EVENT_RE.finditer(text):
        ev = parse_event_xml(match.group(0))
        if ev is not None:
            yield ev


def parse_file(path: str) -> Iterator[Event]:
    with open(path, "r", encoding="utf-8", errors="replace") as fh:
        yield from parse_text(fh.read())
