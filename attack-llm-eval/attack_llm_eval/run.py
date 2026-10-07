"""End-to-end runner.

Example:
  python -m attack_llm_eval.run \
      --logs data/t1003_capture.log --log-format sysmon_linux \
      --labels data/labels.csv \
      --stix data/enterprise-attack.json \
      --model llama3.1:8b --granularity process_tree --mode zero_shot \
      --repeats 3 --out results/

Use --mock to run without an Ollama server (wiring / metrics smoke test).
"""
from __future__ import annotations

import argparse
import json
import os
import sys
from datetime import datetime, timezone

from .schema import read_ndjson, write_ndjson, Event
from .normalize import sysmon_linux
from .attack_data import AttackData
from .process_tree import build_units
from .labels import load_labels, gold_for_unit
from .ollama_runner import OllamaRunner, MockRunner, UnitResult
from .evaluate import EvalInputs, evaluate_run, consistency, format_report
from . import inject as injection


def load_events(path: str, fmt: str) -> list[Event]:
    if fmt == "sysmon_linux":
        return list(sysmon_linux.parse_file(path))
    if fmt == "ndjson":
        return list(read_ndjson(path))
    raise ValueError(f"unknown --log-format: {fmt}")


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(description="Evaluate an LLM as an ATT&CK log triager.")
    p.add_argument("--logs", nargs="+", required=True,
                   help="one or more log files (attack captures and/or benign)")
    p.add_argument("--log-format", default="sysmon_linux",
                   choices=["sysmon_linux", "ndjson"])
    p.add_argument("--labels", default=None,
                   help="CSV of ground-truth windows; omit for unlabeled/benign-only")
    p.add_argument("--stix", required=True, help="enterprise-attack.json path")
    p.add_argument("--model", default="llama3.1:8b")
    p.add_argument("--host", default=None, help="Ollama host URL (optional)")
    p.add_argument("--granularity", default="process_tree",
                   choices=["event", "process_tree", "window"])
    p.add_argument("--window-seconds", type=int, default=60)
    p.add_argument("--mode", default="zero_shot",
                   choices=["zero_shot", "few_shot", "rag"])
    p.add_argument("--embed-model", default="nomic-embed-text",
                   help="embedding model for --mode rag")
    p.add_argument("--rag-top-k", type=int, default=8)
    p.add_argument("--num-ctx", type=int, default=8192)
    p.add_argument("--temperature", type=float, default=0.0)
    p.add_argument("--seed", type=int, default=42)
    p.add_argument("--repeats", type=int, default=1)
    p.add_argument("--max-events-per-unit", type=int, default=60)
    p.add_argument("--injection-test", action="store_true",
                   help="run the prompt-injection robustness test")
    p.add_argument("--mock", action="store_true",
                   help="use the built-in mock model (no Ollama needed)")
    p.add_argument("--out", default="results", help="output directory")
    p.add_argument("--save-events", action="store_true",
                   help="also write normalized events as NDJSON")
    return p


def main(argv=None) -> int:
    args = build_parser().parse_args(argv)
    os.makedirs(args.out, exist_ok=True)

    # 1. normalize
    events: list[Event] = []
    for path in args.logs:
        evs = load_events(path, args.log_format)
        print(f"[+] {path}: {len(evs)} events", file=sys.stderr)
        events.extend(evs)
    if not events:
        print("[!] no events parsed; aborting", file=sys.stderr)
        return 2
    if args.save_events:
        write_ndjson(events, os.path.join(args.out, "events.ndjson"))

    # 2. ATT&CK KB
    attack = AttackData.from_stix_file(args.stix)
    print(f"[+] ATT&CK techniques loaded: {len(attack)}", file=sys.stderr)

    # 3. units + gold
    units = build_units(events, granularity=args.granularity,
                        window_seconds=args.window_seconds)
    windows = load_labels(args.labels) if args.labels else []
    gold = [gold_for_unit(u, windows) for u in units]
    unit_texts = [u.to_text(max_events=args.max_events_per_unit) for u in units]
    n_pos = sum(1 for g in gold if g)
    print(f"[+] units={len(units)} (labeled-positive={n_pos}, "
          f"benign={len(units) - n_pos})", file=sys.stderr)

    # 4. runner
    if args.mock:
        runner = MockRunner(model="mock")
    else:
        runner = OllamaRunner(model=args.model, host=args.host,
                              temperature=args.temperature, seed=args.seed,
                              num_ctx=args.num_ctx)

    # 4b. optional RAG retriever
    retriever = None
    if args.mode == "rag":
        from .rag import Retriever
        cache = os.path.join(args.out, "rag_cache.npz")
        retriever = Retriever(attack, runner, args.embed_model,
                              platform="Linux", cache_path=cache,
                              top_k=args.rag_top_k)
        print("[+] RAG index ready", file=sys.stderr)

    # 5. run (with repeats)
    all_runs: list[list[UnitResult]] = []
    for rep in range(args.repeats):
        results: list[UnitResult] = []
        for u, text in zip(units, unit_texts):
            rag_ctx = retriever.context_for(text) if retriever else None
            res = runner.run_unit(u.unit_id, text, mode=args.mode, rag_context=rag_ctx)
            results.append(res)
        all_runs.append(results)
        print(f"[+] repeat {rep + 1}/{args.repeats} done", file=sys.stderr)

    # 6. score (use first run for PRF; consistency across all runs)
    summary = evaluate_run(EvalInputs(gold=gold, results=all_runs[0],
                                      unit_texts=unit_texts), attack)
    if args.repeats > 1:
        summary["consistency"] = consistency(all_runs)

    # 7. injection test (optional)
    if args.injection_test and not all(not g for g in gold):
        clean_ids = {u.unit_id: r.predicted_ids for u, r in zip(units, all_runs[0])}
        cases = injection.build_injection_cases(units, gold)
        inj_scored = []
        for case in cases:
            orig_id = case.unit.unit_id.replace("::inj", "")
            g = next((gg for uu, gg in zip(units, gold) if uu.unit_id == orig_id), set())
            text = case.unit.to_text(max_events=args.max_events_per_unit)
            res = runner.run_unit(case.unit.unit_id, text, mode=args.mode,
                                  rag_context=retriever.context_for(text) if retriever else None)
            inj_scored.append((orig_id, g, res, case.payload))
        summary["injection"] = injection.evasion_rate(clean_ids, inj_scored)

    # 8. write outputs
    run_meta = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "model": "mock" if args.mock else args.model,
        "granularity": args.granularity,
        "mode": args.mode,
        "repeats": args.repeats,
        "num_ctx": args.num_ctx,
        "temperature": args.temperature,
        "seed": args.seed,
        "logs": args.logs,
    }
    summary["run"] = run_meta

    with open(os.path.join(args.out, "summary.json"), "w") as fh:
        json.dump(summary, fh, indent=2)

    # per-unit predictions (first run)
    with open(os.path.join(args.out, "predictions.ndjson"), "w") as fh:
        for u, g, r in zip(units, gold, all_runs[0]):
            fh.write(json.dumps({
                "unit_id": u.unit_id,
                "host": u.host,
                "gold": sorted(g),
                "predicted": [p.__dict__ for p in r.predictions],
                "latency_s": r.latency_s,
                "error": r.error,
            }) + "\n")

    print("\n" + "=" * 70)
    print(format_report(summary))
    if "injection" in summary:
        inj = summary["injection"]
        print(f"[injection] cases={inj['injected_cases_scored']}  "
              f"evasion_rate={inj['evasion_rate']:.3f}")
    print("=" * 70)
    print(f"[+] wrote {args.out}/summary.json and predictions.ndjson", file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
