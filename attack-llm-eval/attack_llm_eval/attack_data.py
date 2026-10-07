"""MITRE ATT&CK knowledge base loaded from the official STIX bundle.

We parse the STIX JSON directly (no heavy dependencies). Download the bundle
with scripts/fetch_attack_stix.py, which saves enterprise-attack.json.

Provides:
  * is_valid(id)            -> technique/sub-technique ID exists and is current
  * base(id)                -> "T1059.004" -> "T1059"
  * tactics(id)             -> set of tactic shortnames for a technique
  * technique(id)           -> Technique record (name, description, tactics, ...)
  * all_techniques()        -> iterable of Technique
"""
from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from typing import Iterable, Optional

ID_RE = re.compile(r"^T\d{4}(\.\d{3})?$")


@dataclass
class Technique:
    id: str
    name: str
    description: str
    tactics: tuple[str, ...]          # tactic shortnames, e.g. ("execution",)
    is_subtechnique: bool
    deprecated: bool = False
    platforms: tuple[str, ...] = field(default_factory=tuple)

    @property
    def base_id(self) -> str:
        return self.id.split(".")[0]


def base(technique_id: str) -> str:
    """Strip a sub-technique suffix: T1059.004 -> T1059."""
    return technique_id.split(".")[0] if technique_id else technique_id


class AttackData:
    def __init__(self, techniques: dict[str, Technique]):
        self._tech = techniques

    # ---- construction --------------------------------------------------
    @classmethod
    def from_stix_file(cls, path: str) -> "AttackData":
        with open(path, "r", encoding="utf-8") as fh:
            bundle = json.load(fh)
        return cls.from_bundle(bundle)

    @classmethod
    def from_bundle(cls, bundle: dict) -> "AttackData":
        techniques: dict[str, Technique] = {}
        for obj in bundle.get("objects", []):
            if obj.get("type") != "attack-pattern":
                continue
            ext_id = None
            for ref in obj.get("external_references", []):
                if ref.get("source_name") == "mitre-attack":
                    ext_id = ref.get("external_id")
                    break
            if not ext_id or not ID_RE.match(ext_id):
                continue
            tactics = tuple(
                ph["phase_name"]
                for ph in obj.get("kill_chain_phases", [])
                if ph.get("kill_chain_name") == "mitre-attack"
            )
            techniques[ext_id] = Technique(
                id=ext_id,
                name=obj.get("name", ""),
                description=obj.get("description", ""),
                tactics=tactics,
                is_subtechnique=bool(obj.get("x_mitre_is_subtechnique", False)),
                deprecated=bool(obj.get("x_mitre_deprecated", False))
                or bool(obj.get("revoked", False)),
                platforms=tuple(obj.get("x_mitre_platforms", [])),
            )
        if not techniques:
            raise ValueError(
                "No techniques parsed from STIX bundle. Is this the "
                "enterprise-attack.json file?"
            )
        return cls(techniques)

    # ---- queries -------------------------------------------------------
    def is_valid(self, technique_id: str, include_deprecated: bool = False) -> bool:
        if not technique_id or not ID_RE.match(technique_id):
            return False
        t = self._tech.get(technique_id)
        if t is None:
            return False
        return include_deprecated or not t.deprecated

    def technique(self, technique_id: str) -> Optional[Technique]:
        return self._tech.get(technique_id)

    def tactics(self, technique_id: str) -> tuple[str, ...]:
        """Tactics for an ID. A sub-technique inherits its parent's tactics if
        it has none of its own recorded."""
        t = self._tech.get(technique_id)
        if t and t.tactics:
            return t.tactics
        parent = self._tech.get(base(technique_id))
        return parent.tactics if parent else tuple()

    def all_techniques(self, platform: Optional[str] = None,
                       include_deprecated: bool = False) -> Iterable[Technique]:
        for t in self._tech.values():
            if t.deprecated and not include_deprecated:
                continue
            if platform and t.platforms and platform not in t.platforms:
                continue
            yield t

    def __len__(self) -> int:
        return len(self._tech)
