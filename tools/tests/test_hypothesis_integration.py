#!/usr/bin/env python3
"""Integration test: hypothesis-to-detector.py delegates analogical search
to exploit-chain-correlator.py --analogical and receives ≥2 vault-family
neighbours for a vault-centred hypothesis (Phase 32, PR #84).

If the correlator subprocess is unreachable, the tool silently falls back
to an inline token-overlap scan — that path is also exercised here via a
monkeypatched CORRELATOR path.

Run:  python3 tools/tests/test_hypothesis_integration.py
"""
from __future__ import annotations

import importlib.util
import sys
import unittest
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent.parent
TOOL = REPO / "tools" / "hypothesis-to-detector.py"


def _load():
    spec = importlib.util.spec_from_file_location("hyp", TOOL)
    mod = importlib.util.module_from_spec(spec)
    sys.modules["hyp"] = mod
    assert spec.loader is not None
    spec.loader.exec_module(mod)
    return mod


hyp = _load()

HYPOTHESIS = (
    "Vault.withdraw reads balanceOf(this) without minimum supply check"
)
CLASS_NAME = "vault-donation-share-inflation"


class HypothesisIntegrationTest(unittest.TestCase):
    def test_correlator_seed_is_vault_family(self) -> None:
        seed = hyp._pick_seed_detector(CLASS_NAME, HYPOTHESIS)
        self.assertIsNotNone(seed, "expected seed detector to be picked")
        self.assertIn("vault", seed.lower(),
                      f"seed {seed!r} should be vault-family")

    def test_correlator_returns_vault_neighbours(self) -> None:
        analogs = hyp.analogical_hints(CLASS_NAME, HYPOTHESIS, top=5)
        self.assertGreaterEqual(
            len(analogs), 2,
            f"expected >=2 analogical neighbours, got {analogs}"
        )
        vault_like = [
            a for a in analogs
            if any(t in a.lower()
                   for t in ("vault", "share", "deposit", "withdraw",
                             "erc4626", "donation", "rebas"))
        ]
        self.assertGreaterEqual(
            len(vault_like), 2,
            f"expected >=2 vault-family neighbours, got {analogs}"
        )

    def test_fallback_when_correlator_missing(self) -> None:
        """If the correlator binary is gone, inline scan still yields hits."""
        saved = hyp.CORRELATOR
        try:
            hyp.CORRELATOR = Path("/definitely/does/not/exist.py")
            analogs = hyp.analogical_hints(CLASS_NAME, HYPOTHESIS, top=5)
            self.assertGreaterEqual(len(analogs), 1,
                                    "inline fallback should still return hits")
        finally:
            hyp.CORRELATOR = saved


if __name__ == "__main__":
    unittest.main()
