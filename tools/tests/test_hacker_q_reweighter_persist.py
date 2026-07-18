# <!-- r36-rebuttal: registered lane reweighter-persist-fix in .auditooor/agent_pathspec.json -->
#!/usr/bin/env python3
"""Tests for hacker-q-reweighter persistence (FIX 1).

The self-learning reweighter must PERSIST a durable ledger on every run, not
just print. The wired Makefile call (`--json`, no --out) was previously the
print-only failure mode; these tests lock in:

  * a no-`--out` run writes the canonical stable ledger AND a dated snapshot;
  * an explicit `--out` run honors that path exactly (back-compat unchanged);
  * the persisted ledger is valid JSONL with the reweight schema.
"""
import importlib.util
import json
import tempfile
import unittest
from pathlib import Path

_TOOLS = Path(__file__).resolve().parent.parent
_SPEC = importlib.util.spec_from_file_location(
    "hacker_q_reweighter", _TOOLS / "hacker-q-reweighter.py"
)
rw = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(rw)


_SYNTHETIC = {
    # question_id -> list of applies values; enough evals to clear --min-evals.
    "q_high_signal": ["yes", "yes", "yes", "maybe"],
    "q_low_signal": ["no", "no", "no", "no", "no"],
    "q_below_min": ["yes"],  # 1 eval -> filtered out at default min-evals=2
}


class ReweighterPersistTest(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.tmp = Path(self._tmp.name)
        # Redirect both persistence targets into the temp dir so the real
        # repo corpus is never touched by the test.
        self._orig_root = rw.AUDITOOOR_ROOT
        self._orig_canon = rw.CANONICAL_REWEIGHT_LEDGER
        self._orig_scan = rw.scan_sidecars
        rw.AUDITOOOR_ROOT = self.tmp
        rw.CANONICAL_REWEIGHT_LEDGER = (
            self.tmp / "audit/corpus_tags/derived" / "hacker_q_reweight_latest.jsonl"
        )
        rw.scan_sidecars = lambda: dict(_SYNTHETIC)

    def tearDown(self):
        rw.AUDITOOOR_ROOT = self._orig_root
        rw.CANONICAL_REWEIGHT_LEDGER = self._orig_canon
        rw.scan_sidecars = self._orig_scan
        self._tmp.cleanup()

    def _read_jsonl(self, path: Path):
        return [json.loads(ln) for ln in path.read_text().splitlines() if ln.strip()]

    def test_no_out_persists_canonical_and_dated(self):
        rc = rw.main(["--json"])
        self.assertEqual(rc, 0)
        canon = rw.CANONICAL_REWEIGHT_LEDGER
        self.assertTrue(canon.exists(), "canonical ledger must be persisted on no-out run")
        # A dated snapshot must also exist alongside the canonical ledger.
        derived = self.tmp / "audit/corpus_tags/derived"
        dated = sorted(derived.glob("hacker_q_reweight_2*.jsonl"))
        self.assertTrue(dated, "dated snapshot must be persisted on no-out run")
        # Both must contain valid reweight records, and be identical content.
        canon_rows = self._read_jsonl(canon)
        self.assertTrue(canon_rows, "canonical ledger must be non-empty")
        for r in canon_rows:
            self.assertEqual(r["schema_version"], rw.SCHEMA)
            self.assertIn("signal_class", r)
        ids = {r["question_id"] for r in canon_rows}
        self.assertIn("q_high_signal", ids)
        self.assertIn("q_low_signal", ids)
        self.assertNotIn("q_below_min", ids, "below-min-evals question must be filtered")
        self.assertEqual(self._read_jsonl(dated[0]), canon_rows)

    def test_explicit_out_honored_exactly(self):
        out = self.tmp / "custom" / "my_ledger.jsonl"
        rc = rw.main(["--out", str(out)])
        self.assertEqual(rc, 0)
        self.assertTrue(out.exists(), "explicit --out path must be written")
        # Back-compat: explicit --out does NOT also write the canonical ledger.
        self.assertFalse(
            rw.CANONICAL_REWEIGHT_LEDGER.exists(),
            "explicit --out must not clobber the canonical ledger",
        )
        rows = self._read_jsonl(out)
        self.assertTrue(rows)
        for r in rows:
            self.assertEqual(r["schema_version"], rw.SCHEMA)


if __name__ == "__main__":
    unittest.main()
