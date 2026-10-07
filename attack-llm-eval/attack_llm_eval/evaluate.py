"""Metrics.

Classification is multi-label per unit. We project gold and predicted ID sets
to three levels and compute set-based P/R/F1:

  * tactic        : each ID -> its tactic shortnames (via STIX)
  * technique     : each ID -> base technique (T1059.004 -> T1059)
  * subtechnique  : each ID as-is (predicting the parent when a sub is correct
                    counts here as a miss, exposing the common failure mode)

Both micro (pooled TP/FP/FN) and macro (mean of per-class F1) are reported.

Also computes, from the raw predictions:
  * hallucination_rate   : predicted IDs not valid in ATT&CK / all predicted
  * evidence_faithfulness: predictions whose evidence is a substring of the unit
  * benign_fp_rate       : benign units (gold empty) that got any prediction
  * throughput           : units/sec and mean/median latency
  * consistency          : mean pairwise Jaccard of predicted sets across repeats
"""
from __future__ import annotations

import re
import statistics
from dataclasses import dataclass, field
from typing import Callable, Optional

from .attack_data import AttackData, base
from .ollama_runner import UnitResult


# ---- level projections ---------------------------------------------------
def project_subtech(ids: set[str]) -> set[str]:
    return set(ids)


def project_tech(ids: set[str]) -> set[str]:
    return {base(i) for i in ids}


def make_project_tactic(attack: AttackData) -> Callable[[set[str]], set[str]]:
    def proj(ids: set[str]) -> set[str]:
        out: set[str] = set()
        for i in ids:
            out |= set(attack.tactics(i))
        return out
    return proj


# ---- PRF -----------------------------------------------------------------
@dataclass
class PRF:
    tp: int = 0
    fp: int = 0
    fn: int = 0

    @property
    def precision(self) -> float:
        return self.tp / (self.tp + self.fp) if (self.tp + self.fp) else 0.0

    @property
    def recall(self) -> float:
        return self.tp / (self.tp + self.fn) if (self.tp + self.fn) else 0.0

    @property
    def f1(self) -> float:
        p, r = self.precision, self.recall
        return 2 * p * r / (p + r) if (p + r) else 0.0


def score_level(pairs: list[tuple[set[str], set[str]]]) -> dict:
    """pairs = list of (gold_set, pred_set) already projected to one level."""
    micro = PRF()
    per_class: dict[str, PRF] = {}
    for gold, pred in pairs:
        for x in pred & gold:
            micro.tp += 1
            per_class.setdefault(x, PRF()).tp += 1
        for x in pred - gold:
            micro.fp += 1
            per_class.setdefault(x, PRF()).fp += 1
        for x in gold - pred:
            micro.fn += 1
            per_class.setdefault(x, PRF()).fn += 1

    macro_p = statistics.mean([c.precision for c in per_class.values()]) if per_class else 0.0
    macro_r = statistics.mean([c.recall for c in per_class.values()]) if per_class else 0.0
    macro_f = statistics.mean([c.f1 for c in per_class.values()]) if per_class else 0.0
    return {
        "micro": {"precision": micro.precision, "recall": micro.recall,
                  "f1": micro.f1, "tp": micro.tp, "fp": micro.fp, "fn": micro.fn},
        "macro": {"precision": macro_p, "recall": macro_r, "f1": macro_f},
        "per_class": {k: {"precision": v.precision, "recall": v.recall,
                          "f1": v.f1, "tp": v.tp, "fp": v.fp, "fn": v.fn}
                      for k, v in sorted(per_class.items())},
    }


# ---- LLM-specific metrics ------------------------------------------------
_WS = re.compile(r"\s+")


def _norm(s: str) -> str:
    return _WS.sub(" ", s.lower()).strip()


@dataclass
class EvalInputs:
    """One scored run: aligned lists of gold sets, results, and unit texts."""
    gold: list[set[str]]
    results: list[UnitResult]
    unit_texts: list[str]


def evaluate_run(inp: EvalInputs, attack: AttackData) -> dict:
    proj_tactic = make_project_tactic(attack)

    levels = {}
    for name, proj in [("tactic", proj_tactic),
                       ("technique", project_tech),
                       ("subtechnique", project_subtech)]:
        pairs = [(proj(g), proj(r.predicted_ids))
                 for g, r in zip(inp.gold, inp.results)]
        levels[name] = score_level(pairs)

    # hallucination + faithfulness over individual predictions
    total_preds = 0
    invalid = 0
    faithful = 0
    for res, text in zip(inp.results, inp.unit_texts):
        ntext = _norm(text)
        for p in res.predictions:
            total_preds += 1
            if not attack.is_valid(p.id):
                invalid += 1
            if p.evidence and _norm(p.evidence) in ntext:
                faithful += 1
    hallucination_rate = invalid / total_preds if total_preds else 0.0
    faithfulness = faithful / total_preds if total_preds else 1.0

    # benign FP rate
    benign_total = sum(1 for g in inp.gold if not g)
    benign_fp = sum(1 for g, r in zip(inp.gold, inp.results)
                    if not g and r.predicted_ids)
    benign_fp_rate = benign_fp / benign_total if benign_total else 0.0

    # throughput
    lats = [r.latency_s for r in inp.results if r.latency_s]
    total_time = sum(lats)
    throughput = (len(inp.results) / total_time) if total_time else 0.0
    errors = sum(1 for r in inp.results if r.error)

    return {
        "n_units": len(inp.results),
        "n_benign_units": benign_total,
        "n_predictions": total_preds,
        "errors": errors,
        "levels": levels,
        "hallucination_rate": hallucination_rate,
        "evidence_faithfulness": faithfulness,
        "benign_fp_rate": benign_fp_rate,
        "throughput_units_per_s": throughput,
        "latency_mean_s": statistics.mean(lats) if lats else 0.0,
        "latency_median_s": statistics.median(lats) if lats else 0.0,
    }


def _jaccard(a: set[str], b: set[str]) -> float:
    if not a and not b:
        return 1.0
    return len(a & b) / len(a | b) if (a | b) else 1.0


def consistency(runs: list[list[UnitResult]]) -> float:
    """Mean pairwise Jaccard of predicted-id sets across repeated runs,
    averaged over units. runs = list (per repeat) of aligned UnitResult lists."""
    if len(runs) < 2:
        return 1.0
    n_units = len(runs[0])
    unit_scores = []
    for u in range(n_units):
        sets = [run[u].predicted_ids for run in runs]
        pair_scores = []
        for i in range(len(sets)):
            for j in range(i + 1, len(sets)):
                pair_scores.append(_jaccard(sets[i], sets[j]))
        if pair_scores:
            unit_scores.append(statistics.mean(pair_scores))
    return statistics.mean(unit_scores) if unit_scores else 1.0


def format_report(summary: dict) -> str:
    lines = []
    lines.append(f"units={summary['n_units']}  benign={summary['n_benign_units']}  "
                 f"predictions={summary['n_predictions']}  errors={summary['errors']}")
    for level in ("tactic", "technique", "subtechnique"):
        mi = summary["levels"][level]["micro"]
        ma = summary["levels"][level]["macro"]
        lines.append(
            f"[{level:12}] micro P={mi['precision']:.3f} R={mi['recall']:.3f} "
            f"F1={mi['f1']:.3f} (tp={mi['tp']} fp={mi['fp']} fn={mi['fn']})  |  "
            f"macro P={ma['precision']:.3f} R={ma['recall']:.3f} F1={ma['f1']:.3f}"
        )
    lines.append(
        f"hallucination_rate={summary['hallucination_rate']:.3f}  "
        f"evidence_faithfulness={summary['evidence_faithfulness']:.3f}  "
        f"benign_fp_rate={summary['benign_fp_rate']:.3f}"
    )
    lines.append(
        f"throughput={summary['throughput_units_per_s']:.2f} units/s  "
        f"latency_mean={summary['latency_mean_s']:.3f}s  "
        f"latency_median={summary['latency_median_s']:.3f}s"
    )
    if "consistency" in summary:
        lines.append(f"consistency(Jaccard across repeats)={summary['consistency']:.3f}")
    return "\n".join(lines)
