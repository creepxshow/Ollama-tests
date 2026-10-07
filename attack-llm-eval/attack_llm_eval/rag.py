"""Retrieve candidate ATT&CK techniques for a unit via embedding similarity.

Uses Ollama's embeddings endpoint. Technique-description embeddings are
computed once and cached to a .npz next to the STIX file, keyed by model +
technique id, so repeated runs are cheap.

Optional: the whole pipeline runs fine with mode != "rag" and no numpy.
"""
from __future__ import annotations

import os
from typing import Optional

from .attack_data import AttackData, Technique


class Retriever:
    def __init__(self, attack: AttackData, client, embed_model: str,
                 platform: Optional[str] = "Linux", cache_path: Optional[str] = None,
                 top_k: int = 8):
        import numpy as np  # local import so numpy is only needed for RAG
        self.np = np
        self.attack = attack
        self.client = client
        self.embed_model = embed_model
        self.top_k = top_k
        self.techniques: list[Technique] = [
            t for t in attack.all_techniques(platform=platform)
        ]
        self.cache_path = cache_path
        self._matrix = None          # (N, D) normalized
        self._build_index()

    def _embed(self, text: str):
        resp = self.client.embed(self.embed_model, text)
        vec = self.np.asarray(resp[0], dtype="float32")
        norm = self.np.linalg.norm(vec)
        return vec / norm if norm else vec

    def _doc_text(self, t: Technique) -> str:
        desc = (t.description or "").split("\n\n")[0][:600]
        return f"{t.id} {t.name}. {desc}"

    def _build_index(self):
        np = self.np
        ids = [t.id for t in self.techniques]
        if self.cache_path and os.path.exists(self.cache_path):
            data = np.load(self.cache_path, allow_pickle=True)
            if list(data["ids"]) == ids and str(data["model"]) == self.embed_model:
                self._matrix = data["matrix"]
                return
        vecs = []
        for t in self.techniques:
            vecs.append(self._embed(self._doc_text(t)))
        self._matrix = np.vstack(vecs).astype("float32")
        if self.cache_path:
            np.savez(self.cache_path, ids=np.array(ids), matrix=self._matrix,
                     model=np.array(self.embed_model))

    def retrieve(self, unit_text: str) -> list[Technique]:
        q = self._embed(unit_text)
        sims = self._matrix @ q
        idx = self.np.argsort(-sims)[: self.top_k]
        return [self.techniques[i] for i in idx]

    def context_for(self, unit_text: str) -> str:
        cands = self.retrieve(unit_text)
        lines = []
        for t in cands:
            desc = (t.description or "").split("\n\n")[0][:200]
            lines.append(f"- {t.id} {t.name}: {desc}")
        return "\n".join(lines)
