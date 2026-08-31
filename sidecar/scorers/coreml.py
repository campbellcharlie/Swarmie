"""Tier 3: Core ML encoder classifier — runs on the Apple Neural Engine.

Loads a converted `.mlpackage` (see sidecar/convert_coreml.py) plus its tokenizer and a
`meta.json` describing the input/output names, sequence length, and which logit index is the
positive ("injection") class. Needs coremltools + transformers, so this module is imported
lazily and only when the coreml scorer is selected — tiers that don't use it never import it.

The mapping between the model's raw output and {injection, benign} is baked at convert time
by empirically probing the source model, never hard-coded here.
"""
from __future__ import annotations

import json
from pathlib import Path

from . import ScoreResult


class CoreMLScorer:
    def __init__(self, model_dir: str):
        import coremltools as ct  # noqa: F401  (import cost is one-time at startup)
        import numpy as np
        from transformers import AutoTokenizer

        self._np = np
        root = Path(model_dir)
        meta = json.loads((root / "meta.json").read_text())
        self.model = ct.models.MLModel(str(root / meta["mlpackage"]))
        self.tokenizer = AutoTokenizer.from_pretrained(str(root / meta["tokenizer"]))
        self.max_length = int(meta["max_length"])
        self.positive_index = int(meta["positive_index"])
        self.input_ids_name = meta["input_ids_name"]
        self.attention_mask_name = meta["attention_mask_name"]
        self.logits_name = meta["logits_name"]
        self.model_id = meta["model_id"]

    def score(self, text: str, *, response_type: str = "") -> ScoreResult:
        np = self._np
        enc = self.tokenizer(text, truncation=True, max_length=self.max_length,
                             padding="max_length", return_tensors="np")
        feed = {
            self.input_ids_name: enc["input_ids"].astype(np.int32),
            self.attention_mask_name: enc["attention_mask"].astype(np.int32),
        }
        out = self.model.predict(feed)
        logits = np.asarray(out[self.logits_name], dtype=np.float64).reshape(-1)
        logits -= logits.max()
        probs = np.exp(logits)
        probs /= probs.sum()
        score = float(probs[self.positive_index])
        label = "injection" if score >= 0.5 else "benign"
        return ScoreResult(label=label, score=score, spans=[])
