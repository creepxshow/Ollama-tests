# attack-llm-eval

Evaluate local LLMs (served by [Ollama](https://ollama.com)) as **MITRE ATT&CK
log triagers** for Linux host telemetry. The harness normalizes logs, groups
them into analysis units, runs them through a model with structured output,
validates results against the official ATT&CK STIX data, and scores detection
quality — plus LLM-specific failure modes (hallucinated technique IDs,
unfaithful evidence, benign false positives, run-to-run inconsistency, and
prompt-injection evasion).

This is **defensive / blue-team research tooling**. The only "offensive" step
is running Atomic Red Team in a throwaway lab VM to produce labeled ground
truth; see `scripts/atomic_runbook.md`.

## What's in the box

```
attack_llm_eval/
  schema.py            Normalized Event type (source-agnostic) + NDJSON I/O
  normalize/
    sysmon_linux.py    Parse Sysmon-for-Linux <Event> XML from syslog/journald
  attack_data.py       Load ATT&CK STIX; validate IDs; technique->tactic mapping
  process_tree.py      Group events into units: event | process_tree | window
  labels.py            Time-window ground truth -> per-unit gold technique sets
  prompts.py           Zero-shot / few-shot / RAG prompts + output JSON schema
  rag.py               Embedding retrieval over technique descriptions (optional)
  ollama_runner.py     Ollama client (structured output, deterministic) + MockRunner
  inject.py            Prompt-injection robustness test
  evaluate.py          P/R/F1 at tactic/technique/subtech + LLM-specific metrics
  run.py               CLI orchestrator
scripts/
  fetch_attack_stix.py Download enterprise-attack.json
  collect_sysmon.sh    Install Sysmon-for-Linux and dump events on the lab VM
  atomic_runbook.md    How to generate labeled ground truth safely
  run_grid.sh          Sweep model x granularity x prompting mode
tests/                 Synthetic fixtures + self-contained test suite
```

The pipeline is format-agnostic after parsing: to add auditd/Laurel later,
write one parser in `normalize/` that emits `Event`s — nothing downstream
changes.

## Install

Requires Python 3.9+.

```bash
cd attack-llm-eval
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt     # ollama, and numpy only if you use RAG
```

Install Ollama and pull a model (on the analysis machine, not necessarily the
lab VM):

```bash
# https://ollama.com/download
ollama pull llama3.1:8b
ollama pull nomic-embed-text         # only for --mode rag
```

Download the ATT&CK knowledge base (pin a version for reproducibility):

```bash
python scripts/fetch_attack_stix.py --version 15.1 --out data/enterprise-attack.json
```

## Verify the install (no Ollama needed)

```bash
python tests/test_pipeline.py                      # 8/8 tests pass
python -m attack_llm_eval.run \
  --logs tests/sample_sysmon.log \
  --labels examples/labels.example.csv \
  --stix tests/mini_attack.json \
  --mock --repeats 3 --injection-test --out /tmp/smoke
```

`--mock` uses a built-in keyword "model" so you can confirm wiring and metrics
before involving a real model.

## Deploy — full workflow

### 1. Collect telemetry on the lab VM

```bash
sudo ./scripts/collect_sysmon.sh install        # Sysmon for Linux
```

### 2. Generate labeled ground truth

Follow `scripts/atomic_runbook.md`: run known techniques, recording UTC
start/stop times into `labels.csv`; separately record a benign session with no
labels. Then export events:

```bash
sudo ./scripts/collect_sysmon.sh dump capture.log      # attack session
sudo ./scripts/collect_sysmon.sh dump benign.log       # benign session
```

### 3. Run an evaluation

```bash
python -m attack_llm_eval.run \
  --logs capture.log benign.log \
  --labels labels.csv \
  --stix data/enterprise-attack.json \
  --model llama3.1:8b \
  --granularity process_tree \
  --mode zero_shot \
  --repeats 3 \
  --injection-test \
  --out results/llama31-8b_tree_zeroshot
```

Outputs in the `--out` directory:
- `summary.json` — all metrics + run metadata
- `predictions.ndjson` — per-unit gold vs predicted, latency, errors

### 4. Sweep the experiment grid

Edit the arrays in `scripts/run_grid.sh`, then:

```bash
LOGS="capture.log benign.log" LABELS=labels.csv ./scripts/run_grid.sh
```

## Key options

| Flag | Meaning |
|---|---|
| `--granularity` | `event`, `process_tree` (default), or `window` |
| `--window-seconds` | window size for `--granularity window` |
| `--mode` | `zero_shot`, `few_shot`, or `rag` |
| `--embed-model` | embedding model for RAG (default `nomic-embed-text`) |
| `--repeats` | runs per config; enables the consistency metric |
| `--num-ctx` | **set this explicitly** — the default context is small and silently truncates long units |
| `--temperature` / `--seed` | default 0 / 42 for determinism |
| `--injection-test` | append adversarial strings to attacker-controlled fields and measure evasion |
| `--mock` | run without Ollama |

## Metrics reported

- **P/R/F1 at three levels** — tactic, technique, sub-technique, each micro and
  macro averaged. The gap between technique and sub-technique F1 exposes the
  common "right family, wrong sub-technique" failure.
- **hallucination_rate** — predicted IDs not present in ATT&CK.
- **evidence_faithfulness** — fraction of predictions whose cited evidence is a
  verbatim substring of the unit text.
- **benign_fp_rate** — benign units that received any prediction.
- **throughput / latency** — units/sec and per-unit latency.
- **consistency** — mean pairwise Jaccard of predictions across `--repeats`.
- **injection.evasion_rate** — share of truly-detected techniques that vanish
  once an injection payload is planted in the logs.

## Notes and limitations

- **Ground truth is the hard part on Linux.** Prefer generating your own via
  Atomic Red Team over scraping unlabeled captures. Consider adding Falco as a
  weak-label baseline to answer "does the LLM beat/complement existing rules?".
- Network/C2 techniques are weak in host telemetry alone; the starter technique
  set is host-based where this approach is strongest.
- The model sees only what you put in each unit. Process-tree granularity
  usually wins because many techniques only make sense in lineage context —
  but that's a hypothesis to test, which is what `--granularity` is for.
- Treat log content as attacker-controlled; `--injection-test` is there because
  a triage model is itself an injection target.
