#!/usr/bin/env bash
# Sweep the experiment grid: model x granularity x prompting mode.
# Edit the arrays, then run from the repo root:  ./scripts/run_grid.sh
set -euo pipefail

LOGS="${LOGS:-capture.log benign.log}"
LABELS="${LABELS:-labels.csv}"
STIX="${STIX:-data/enterprise-attack.json}"
REPEATS="${REPEATS:-3}"

MODELS=("llama3.1:8b" "qwen2.5:7b" "llama3.3:70b")
GRANULARITIES=("event" "process_tree" "window")
MODES=("zero_shot" "few_shot" "rag")

for model in "${MODELS[@]}"; do
  for gran in "${GRANULARITIES[@]}"; do
    for mode in "${MODES[@]}"; do
      safe="${model//[:\/]/_}"
      out="results/${safe}__${gran}__${mode}"
      echo "=== ${model} | ${gran} | ${mode} -> ${out} ==="
      python -m attack_llm_eval.run \
        --logs ${LOGS} --labels "${LABELS}" --stix "${STIX}" \
        --model "${model}" --granularity "${gran}" --mode "${mode}" \
        --repeats "${REPEATS}" --injection-test --out "${out}" \
        || echo "[!] run failed: ${out}"
    done
  done
done

echo "[+] grid complete. Collect results/*/summary.json for your tables."
