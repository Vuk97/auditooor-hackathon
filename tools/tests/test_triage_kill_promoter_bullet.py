"""Regression: triage-kill-promoter must parse BULLET-format triage logs
(- <cand> @ <loc> -> KILLED: <reason>), not only markdown tables. This is the
shape the per-workspace loop actually writes to <ws>/.auditooor/triage_log.md.
Without it, killed candidates never reach reports/known_dead_ends.jsonl and a
future run re-hypothesizes them. Generic-fix anchor: monero-oxide's 3 kills sat
only in triage_log.md.
"""
import importlib.util, sys, tempfile, unittest
from pathlib import Path

_T = Path(__file__).resolve().parent.parent / "triage-kill-promoter.py"


def _load():
    spec = importlib.util.spec_from_file_location("tkp", _T)
    m = importlib.util.module_from_spec(spec)
    sys.modules["tkp"] = m
    spec.loader.exec_module(m)
    return m


TKP = _load()

LOG = """# ws triage log (loop)
- fiat_shamir_forgery @ ringct/clsag/src/multisig.rs:361 -> KILLED R53: superseded by prior audit A1
- div_before_mul @ wallet/src/scan.rs:64 -> KILLED R76-misfire: cited code is mem::swap, no arithmetic
- reentrancy_send -> DROP-OOS: .send() is a Rust channel, not a contract call
- some narrative line that is not a kill at all
Verdict so far: 0 fileable.
"""


class TestBulletKills(unittest.TestCase):
    def test_parses_bullet_kills(self):
        with tempfile.TemporaryDirectory() as td:
            md = Path(td) / "triage_log.md"
            md.write_text(LOG, encoding="utf-8")
            recs = TKP.parse_md_bullet_kills(md, workspace="ws")
            self.assertEqual(len(recs), 3, [r["candidate_id"] for r in recs])
            by = {r["candidate_id"]: r for r in recs}
            self.assertIn("fiat_shamir_forgery", by)
            self.assertEqual(by["fiat_shamir_forgery"]["kill_verdict"], "KILLED")
            self.assertIn("multisig.rs:361", by["fiat_shamir_forgery"]["evidence_file_line"])
            self.assertTrue(by["fiat_shamir_forgery"]["record_id"].startswith("md-triage:ws:"))
            # DROP verdict captured too
            self.assertEqual(by["reentrancy_send"]["kill_verdict"], "DROP-OOS")
            # narrative line is NOT a kill
            self.assertNotIn("some narrative line that is not a kill at all", by)

    def test_table_and_bullet_both_run(self):
        # a table-format kill must still parse (regression guard on the table path)
        with tempfile.TemporaryDirectory() as td:
            md = Path(td) / "t.md"
            md.write_text(
                "| cand_x | HIGH | **KILL-DUPE** | already filed |\n"
                "- cand_y @ a.rs:1 -> KILLED: misfire\n", encoding="utf-8")
            recs = TKP.parse_md_table_kills(md) + TKP.parse_md_bullet_kills(md, "ws")
            cands = {r["candidate_id"] for r in recs}
            self.assertTrue(any("cand_x" in c for c in cands))
            self.assertIn("cand_y", cands)


if __name__ == "__main__":
    unittest.main()
