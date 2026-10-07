"""Run analysis units through a model and parse structured predictions.

Wraps the Ollama chat API with:
  * JSON-schema structured output (format=OUTPUT_SCHEMA)
  * deterministic options (temperature 0, fixed seed, explicit num_ctx)
  * per-unit latency measurement
  * tolerant response parsing (supports old/new ollama-python return shapes)

A MockRunner with the same interface lets the whole pipeline be tested without
a running Ollama server.
"""
from __future__ import annotations

import json
import time
from dataclasses import dataclass, field
from typing import Optional

from .prompts import OUTPUT_SCHEMA, build_messages


@dataclass
class Prediction:
    id: str
    confidence: float
    evidence: str


@dataclass
class UnitResult:
    unit_id: str
    predictions: list[Prediction] = field(default_factory=list)
    latency_s: float = 0.0
    raw: str = ""
    error: Optional[str] = None

    @property
    def predicted_ids(self) -> set[str]:
        return {p.id for p in self.predictions}


def _extract_content(resp) -> str:
    # new ollama-python: resp.message.content ; dict access also works
    try:
        return resp["message"]["content"]
    except (TypeError, KeyError):
        pass
    msg = getattr(resp, "message", None)
    if msg is not None:
        content = getattr(msg, "content", None)
        if content is not None:
            return content
    return str(resp)


def _parse_predictions(content: str) -> list[Prediction]:
    content = content.strip()
    # strip accidental code fences
    if content.startswith("```"):
        content = content.strip("`")
        if content.lstrip().lower().startswith("json"):
            content = content.lstrip()[4:]
    try:
        obj = json.loads(content)
    except json.JSONDecodeError:
        # try to locate the first {...} span
        start, end = content.find("{"), content.rfind("}")
        if start == -1 or end == -1:
            return []
        try:
            obj = json.loads(content[start:end + 1])
        except json.JSONDecodeError:
            return []
    out = []
    for item in obj.get("techniques", []) if isinstance(obj, dict) else []:
        if not isinstance(item, dict):
            continue
        tid = str(item.get("id", "")).strip().upper()
        if not tid:
            continue
        try:
            conf = float(item.get("confidence", 0.0))
        except (TypeError, ValueError):
            conf = 0.0
        out.append(Prediction(id=tid, confidence=conf,
                              evidence=str(item.get("evidence", ""))))
    return out


class OllamaRunner:
    def __init__(self, model: str, host: Optional[str] = None,
                 temperature: float = 0.0, seed: int = 42, num_ctx: int = 8192):
        from ollama import Client
        self.client = Client(host=host) if host else Client()
        self.model = model
        self.options = {"temperature": temperature, "seed": seed, "num_ctx": num_ctx}

    def embed(self, model: str, text: str):
        resp = self.client.embed(model=model, input=text)
        # normalize return shape -> list[list[float]]
        try:
            return resp["embeddings"]
        except (TypeError, KeyError):
            return getattr(resp, "embeddings")

    def run_unit(self, unit_id: str, unit_text: str, mode: str = "zero_shot",
                 rag_context: Optional[str] = None) -> UnitResult:
        messages = build_messages(unit_text, mode=mode, rag_context=rag_context)
        t0 = time.perf_counter()
        try:
            resp = self.client.chat(
                model=self.model, messages=messages,
                format=OUTPUT_SCHEMA, options=self.options,
            )
            dt = time.perf_counter() - t0
            content = _extract_content(resp)
            return UnitResult(unit_id=unit_id, predictions=_parse_predictions(content),
                              latency_s=dt, raw=content)
        except Exception as exc:  # noqa: BLE001 - surface any client/server error
            return UnitResult(unit_id=unit_id, latency_s=time.perf_counter() - t0,
                              error=f"{type(exc).__name__}: {exc}")


class MockRunner:
    """Deterministic fake model for tests and dry runs.

    Applies a few keyword rules so the pipeline produces non-trivial output
    without a server. NOT a detector — only for wiring/metrics validation.
    """

    RULES = [
        ("/etc/shadow", "T1003.008", "/etc/shadow"),
        ("authorized_keys", "T1098.004", "authorized_keys"),
        ("/etc/cron", "T1053.003", "/etc/cron"),
        (".bash_history", "T1070.003", ".bash_history"),
        ("useradd", "T1136.001", "useradd"),
        ("curl ", "T1105", "curl"),
        ("wget ", "T1105", "wget"),
        ("sudo ", "T1548.003", "sudo"),
    ]

    def __init__(self, *args, **kwargs):
        self.model = kwargs.get("model", "mock")

    def embed(self, model: str, text: str):
        # cheap deterministic pseudo-embedding
        import hashlib
        h = hashlib.sha256(text.encode()).digest()
        return [[b / 255.0 for b in h[:16]]]

    def run_unit(self, unit_id: str, unit_text: str, mode: str = "zero_shot",
                 rag_context: Optional[str] = None) -> UnitResult:
        t0 = time.perf_counter()
        low = unit_text.lower()
        preds = []
        for needle, tid, ev in self.RULES:
            if needle in low:
                # recover a verbatim substring for faithfulness
                i = low.find(needle)
                verbatim = unit_text[i:i + len(needle)]
                preds.append(Prediction(id=tid, confidence=0.8, evidence=verbatim))
        return UnitResult(unit_id=unit_id, predictions=preds,
                          latency_s=time.perf_counter() - t0, raw="mock")
