"""Self-contained tests. Run: python -m pytest tests/ -q
(or: python tests/test_pipeline.py for a no-pytest smoke run)."""
import os
import sys

HERE = os.path.dirname(__file__)
ROOT = os.path.dirname(HERE)
sys.path.insert(0, ROOT)

from attack_llm_eval.normalize import sysmon_linux
from attack_llm_eval.attack_data import AttackData, base
from attack_llm_eval.process_tree import build_units
from attack_llm_eval.labels import load_labels, gold_for_unit, LabelWindow
from attack_llm_eval.ollama_runner import MockRunner, _parse_predictions
from attack_llm_eval.evaluate import EvalInputs, evaluate_run, consistency
from attack_llm_eval import inject as injection
from datetime import datetime, timezone

SAMPLE = os.path.join(HERE, "sample_sysmon.log")
STIX = os.path.join(HERE, "mini_attack.json")


def test_parse_sysmon():
    events = list(sysmon_linux.parse_file(SAMPLE))
    assert len(events) == 6, f"expected 6 events, got {len(events)}"
    # namespaced first event parsed correctly
    e0 = events[0]
    assert e0.image == "/usr/bin/bash"
    assert e0.host == "lab-vm"
    # the shadow read
    shadow = [e for e in events if e.command_line and "/etc/shadow" in e.command_line]
    assert len(shadow) == 1
    assert shadow[0].event_type == "process_create"
    # the file create
    fc = [e for e in events if e.event_type == "file_create"]
    assert len(fc) == 1 and "authorized_keys" in fc[0].target_filename


def test_attack_data():
    attack = AttackData.from_stix_file(STIX)
    assert attack.is_valid("T1003.008")
    assert not attack.is_valid("T9999")          # nonexistent
    assert not attack.is_valid("not-an-id")
    assert base("T1003.008") == "T1003"
    assert "credential-access" in attack.tactics("T1003.008")
    # sub-technique inherits parent tactic if needed
    assert "persistence" in attack.tactics("T1098.004")


def test_process_tree_grouping():
    events = list(sysmon_linux.parse_file(SAMPLE))
    units = build_units(events, granularity="process_tree")
    # The attack chain (bash + children + file create) should group under the
    # bash root; benign git is a separate root.
    root_unit = max(units, key=lambda u: len(u.events))
    cmds = " ".join(e.command_line or e.target_filename or "" for e in root_unit.events)
    assert "/etc/shadow" in cmds
    assert "authorized_keys" in cmds
    assert "useradd" in cmds
    # git is not in the attack tree
    assert "git status" not in cmds


def test_labels_assignment():
    events = list(sysmon_linux.parse_file(SAMPLE))
    units = build_units(events, granularity="event")
    windows = [
        LabelWindow("T1003.008",
                    datetime(2024, 1, 15, 10, 23, 40, tzinfo=timezone.utc),
                    datetime(2024, 1, 15, 10, 23, 50, tzinfo=timezone.utc),
                    host="lab-vm", image_contains="/etc/shadow"),
    ]
    golds = [gold_for_unit(u, windows) for u in units]
    pos = [g for g in golds if g]
    assert len(pos) == 1 and pos[0] == {"T1003.008"}


def test_parse_predictions_tolerant():
    assert _parse_predictions('```json\n{"techniques":[{"id":"T1059","confidence":0.5,"evidence":"x"}]}\n```')[0].id == "T1059"
    assert _parse_predictions('garbage') == []


def test_end_to_end_mock():
    events = list(sysmon_linux.parse_file(SAMPLE))
    attack = AttackData.from_stix_file(STIX)
    units = build_units(events, granularity="process_tree")
    windows = [
        LabelWindow("T1003.008",
                    datetime(2024, 1, 15, 10, 23, 40, tzinfo=timezone.utc),
                    datetime(2024, 1, 15, 10, 23, 50, tzinfo=timezone.utc),
                    image_contains="/etc/shadow"),
        LabelWindow("T1098.004",
                    datetime(2024, 1, 15, 10, 25, 0, tzinfo=timezone.utc),
                    datetime(2024, 1, 15, 10, 25, 10, tzinfo=timezone.utc),
                    image_contains="authorized_keys"),
        LabelWindow("T1136.001",
                    datetime(2024, 1, 15, 10, 26, 0, tzinfo=timezone.utc),
                    datetime(2024, 1, 15, 10, 26, 15, tzinfo=timezone.utc),
                    image_contains="useradd"),
    ]
    gold = [gold_for_unit(u, windows) for u in units]
    texts = [u.to_text() for u in units]
    runner = MockRunner()
    results = [runner.run_unit(u.unit_id, t) for u, t in zip(units, texts)]
    summary = evaluate_run(EvalInputs(gold, results, texts), attack)

    # mock should catch all three in the attack tree
    sub = summary["levels"]["subtechnique"]["micro"]
    assert sub["tp"] >= 3, summary["levels"]["subtechnique"]
    # evidence is copied verbatim -> faithfulness 1.0
    assert summary["evidence_faithfulness"] == 1.0
    # no invalid IDs from the mock
    assert summary["hallucination_rate"] == 0.0
    # benign git unit should not fire
    assert summary["benign_fp_rate"] == 0.0


def test_consistency_identical_runs():
    events = list(sysmon_linux.parse_file(SAMPLE))
    units = build_units(events, granularity="process_tree")
    runner = MockRunner()
    texts = [u.to_text() for u in units]
    run_a = [runner.run_unit(u.unit_id, t) for u, t in zip(units, texts)]
    run_b = [runner.run_unit(u.unit_id, t) for u, t in zip(units, texts)]
    assert consistency([run_a, run_b]) == 1.0


def test_injection_builds_cases():
    events = list(sysmon_linux.parse_file(SAMPLE))
    units = build_units(events, granularity="process_tree")
    gold = [{"T1003.008"} if any("/etc/shadow" in (e.command_line or "")
            for e in u.events) else set() for u in units]
    cases = injection.build_injection_cases(units, gold)
    assert len(cases) == len(injection.DEFAULT_PAYLOADS)
    # payload is appended to a command line
    inj_text = cases[0].unit.to_text()
    assert "ignore previous instructions" in inj_text.lower()


if __name__ == "__main__":
    fns = [v for k, v in sorted(globals().items()) if k.startswith("test_")]
    passed = 0
    for fn in fns:
        fn()
        print(f"  ok  {fn.__name__}")
        passed += 1
    print(f"\n{passed}/{len(fns)} tests passed")
