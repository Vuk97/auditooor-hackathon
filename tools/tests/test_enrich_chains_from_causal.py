#!/usr/bin/env python3
"""Regression: enrich-chains-from-causal builds the composer's enriched-invariant feed from
the linkage-bearing causal_chains corpus (NOT the thin finding-sidecar fuel), producing rows
that satisfy BOTH composer gates: the boolean linkage gate (5 linkage fields present) AND the
numeric _score_tuple gate (commit_point_pattern + defense_layer derived from CLEAN attack_class,
boilerplate stripped). 2026-07-08."""
import importlib.util
import json
import tempfile
import unittest
from pathlib import Path

_H = Path(__file__).resolve().parent
_s = importlib.util.spec_from_file_location("ecfc", _H.parent / "enrich-chains-from-causal.py")
m = importlib.util.module_from_spec(_s)
_s.loader.exec_module(m)


class T(unittest.TestCase):
    def _row(self, **kw):
        base = {"chain_id": "chain:abc", "attack_class": "oracle-manipulation",
                "produces_state": ["state:price-skewed"], "requires_state": ["state:oracle-read"],
                "source_refs": ["a/b.jsonl:3"], "target_language": "solidity",
                "defense": "TWAP disclosure 2023", "trigger": "flash loan"}
        base.update(kw)
        return base

    def test_enriches_all_linkage_fields(self):
        e = m.enrich_row(self._row())
        for f in ("source_refs", "produces_state", "requires_state",
                  "producer_source_refs", "consumer_source_refs",
                  "commit_point_pattern", "defense_layer"):
            self.assertTrue(e.get(f), f"missing/empty {f}")
        self.assertEqual(e["audit_verdict"], "TRUE-POSITIVE")
        self.assertEqual(e["category"], "oracle-manipulation")
        self.assertEqual(e["target_lang"], "solidity")

    def test_drops_rows_without_state_linkage(self):
        self.assertIsNone(m.enrich_row(self._row(produces_state=[])))
        self.assertIsNone(m.enrich_row(self._row(requires_state=[])))
        self.assertIsNone(m.enrich_row(self._row(source_refs=[])))

    def test_boilerplate_stripped_from_score_fields(self):
        # commit_point_pattern/defense_layer must NOT contain years / advisory boilerplate
        e = m.enrich_row(self._row())
        blob = (e["commit_point_pattern"] + " " + e["defense_layer"]).lower()
        for junk in ("2023", "disclosure"):
            self.assertNotIn(junk, blob, f"boilerplate '{junk}' leaked into score field")
        # derived from the CLEAN attack_class so same-cluster rows SHARE (score can pass)
        self.assertIn("oracle", e["commit_point_pattern"])

    def test_end_to_end_writes_feed(self):
        src = Path(tempfile.mkdtemp()) / "causal.jsonl"
        dst = Path(tempfile.mkdtemp()) / "enriched.jsonl"
        src.write_text("\n".join(json.dumps(self._row(chain_id=f"chain:{i}")) for i in range(3)))
        rc = m.main(["--src", str(src), "--dst", str(dst)])
        self.assertEqual(rc, 0)
        rows = [json.loads(l) for l in dst.read_text().splitlines() if l.strip()]
        self.assertEqual(len(rows), 3)


if __name__ == "__main__":
    unittest.main()
