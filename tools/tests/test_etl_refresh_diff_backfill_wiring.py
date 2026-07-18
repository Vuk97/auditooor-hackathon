"""Guard: wave-2 #3 - hackerman-etl-refresh runs git-mining-diff-backfill BEFORE the
git-mining ETL, so records classify from real diffs (not commit subjects).

Asserts (source-level, no network):
 (a) the refresh module invokes git-mining-diff-backfill.py and orders it BEFORE
     hackerman-etl-from-git-mining.py;
 (b) the backfill is gated by --skip-git-mining-diff-backfill (opt-out, default on);
 (c) the backfill stage is best-effort (uses _run_json_best_effort, not the raising _run).
"""
import re
import unittest
from pathlib import Path

SRC = Path(__file__).resolve().parents[1] / "hackerman-etl-refresh.py"


class TestDiffBackfillWiring(unittest.TestCase):
    def setUp(self):
        self.text = SRC.read_text(encoding="utf-8")

    def test_backfill_invoked_before_git_mining_etl(self):
        bf = self.text.find("git-mining-diff-backfill.py")
        etl = self.text.find("hackerman-etl-from-git-mining.py")
        self.assertGreater(bf, 0, "diff-backfill must be invoked in etl-refresh")
        self.assertGreater(etl, 0)
        self.assertLess(bf, etl, "backfill must run BEFORE the git-mining ETL")

    def test_backfill_is_gated_and_best_effort(self):
        self.assertIn("--skip-git-mining-diff-backfill", self.text)
        # the backfill block must use the non-raising best-effort runner
        block = self.text[self.text.find("skip_git_mining_diff_backfill"):
                          self.text.find("hackerman-etl-from-git-mining.py")]
        self.assertIn("_run_json_best_effort", block,
                      "backfill must be best-effort (never abort the refresh)")


if __name__ == "__main__":
    unittest.main()
