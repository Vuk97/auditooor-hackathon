"""Guard: batch-2 Makefile wirings (A6-S5 + S6).

A6-S5: the audit-closeout recipe invokes ranker-learn-surface (own-findings seed +
       corpus reindex) so the learning loop's read-back half fires on every closeout.
S6:    the chained-attack-plans recipe passes --emit-chain-synth-source-links so the
       planner emits chain_synth_source_links.json (was 100% blocked -> 0 chains).

Asserts on the recipe BLOCK (target line to next top-level target), not the whole file,
so an unrelated mention elsewhere cannot mask a regression.
"""
import re
import unittest
from pathlib import Path

MAKEFILE = Path(__file__).resolve().parents[2] / "Makefile"


def _recipe_block(text: str, target: str) -> str:
    lines = text.splitlines()
    out, capturing = [], False
    for ln in lines:
        if ln.startswith(f"{target}:"):
            capturing = True
            out.append(ln)
            continue
        if capturing:
            # next top-level target (non-indent, ends with ':') closes the block
            if ln and not ln.startswith(("\t", " ")) and re.match(r"^[A-Za-z0-9_.-]+:", ln):
                break
            out.append(ln)
    return "\n".join(out)


class TestBatch2MakefileWiring(unittest.TestCase):
    def setUp(self):
        self.text = MAKEFILE.read_text(encoding="utf-8")

    def test_a6s5_closeout_invokes_ranker_learn_surface(self):
        block = _recipe_block(self.text, "audit-closeout")
        self.assertTrue(block, "audit-closeout recipe not found")
        self.assertIn("ranker-learn-surface", block,
                      "A6-S5: audit-closeout must invoke ranker-learn-surface (learning read-back)")

    def test_s6_chained_plans_emits_source_links(self):
        block = _recipe_block(self.text, "chained-attack-plans")
        self.assertTrue(block, "chained-attack-plans recipe not found")
        self.assertIn("--emit-chain-synth-source-links", block,
                      "S6: chained-attack-plans must pass --emit-chain-synth-source-links")


if __name__ == "__main__":
    unittest.main()
