"""Prompt construction and the structured-output schema.

Three prompting modes (an experimental variable):
  * zero_shot : instructions only
  * few_shot  : instructions + a handful of worked examples
  * rag       : instructions + candidate techniques retrieved for this unit
"""
from __future__ import annotations

from typing import Optional

# JSON schema passed to Ollama's `format` parameter so output is parseable.
OUTPUT_SCHEMA = {
    "type": "object",
    "properties": {
        "techniques": {
            "type": "array",
            "items": {
                "type": "object",
                "properties": {
                    "id": {"type": "string"},
                    "confidence": {"type": "number"},
                    "evidence": {"type": "string"},
                },
                "required": ["id", "confidence", "evidence"],
            },
        }
    },
    "required": ["techniques"],
}

SYSTEM_PROMPT = (
    "You are a precise SOC detection analyst. You are given Linux host "
    "telemetry (process, file, and network events). Identify only MITRE "
    "ATT&CK techniques that are directly evidenced by the events. "
    "Rules:\n"
    "- Output MITRE ATT&CK technique IDs in the form Txxxx or Txxxx.yyy.\n"
    "- Only report a technique if a specific event supports it. If the "
    "activity looks like normal/benign system behavior, return an empty list.\n"
    "- Do not guess or pad. Precision matters more than recall.\n"
    "- For each technique, 'evidence' MUST be copied verbatim from the input "
    "text (an exact substring), not paraphrased.\n"
    "- 'confidence' is your calibrated probability from 0.0 to 1.0.\n"
    "Return JSON only, matching the requested schema."
)

FEW_SHOT_EXAMPLES = [
    (
        "1. [process_create] image=/usr/bin/cat cmdline=cat /etc/shadow "
        "parent_image=/usr/bin/bash user=www-data",
        {"techniques": [
            {"id": "T1003.008", "confidence": 0.9,
             "evidence": "cat /etc/shadow"}
        ]},
    ),
    (
        "1. [process_create] image=/usr/bin/ls cmdline=ls -la /home "
        "parent_image=/usr/bin/bash user=alice",
        {"techniques": []},
    ),
    (
        "1. [file_create] target_file=/home/bob/.ssh/authorized_keys "
        "image=/usr/bin/bash user=bob",
        {"techniques": [
            {"id": "T1098.004", "confidence": 0.85,
             "evidence": "/home/bob/.ssh/authorized_keys"}
        ]},
    ),
]


def _format_examples() -> str:
    import json
    blocks = []
    for inp, out in FEW_SHOT_EXAMPLES:
        blocks.append(
            "INPUT:\n" + inp + "\nOUTPUT:\n" + json.dumps(out)
        )
    return "\n\n".join(blocks)


def build_messages(unit_text: str, mode: str = "zero_shot",
                   rag_context: Optional[str] = None) -> list[dict]:
    system = SYSTEM_PROMPT
    user_parts = []

    if mode == "few_shot":
        user_parts.append(
            "Here are examples of correct analysis:\n\n" + _format_examples()
            + "\n\n---\n"
        )
    elif mode == "rag":
        if rag_context:
            user_parts.append(
                "Candidate techniques retrieved for this activity (choose only "
                "those actually evidenced; you may also use others you are "
                "certain of, and may return none):\n\n" + rag_context + "\n\n---\n"
            )

    user_parts.append(
        "Analyze the following events and return the techniques as JSON.\n\n"
        "EVENTS:\n" + unit_text
    )

    return [
        {"role": "system", "content": system},
        {"role": "user", "content": "\n".join(user_parts)},
    ]
