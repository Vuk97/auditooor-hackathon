#!/usr/bin/env python3
"""Guard: honesty + honest-zero credit a genuine mutation kill written with
verdict='killed'+genuine_verdict='non-vacuous' and NO oracle_verdict key (the
per-fn producer's real shape) - the SSV/forge serving-join that false-RED'd
pass-genuinely-audited + the recomputed honest-0."""
import importlib.util, sys, unittest
from pathlib import Path
def _load(mod, fn):
    s = importlib.util.spec_from_file_location(mod, str(Path(__file__).resolve().parent.parent / fn))
    m = importlib.util.module_from_spec(s); sys.modules[mod] = m; s.loader.exec_module(m); return m
AHC = _load("_ahc_t", "audit-honesty-check.py")
HZV = _load("_hzv_t", "honest-zero-verify.py")
KILL_NO_ORACLE = {"mutation_verified": True, "killed": True,
                  "genuine_verdict": "non-vacuous", "verdict": "killed"}
VACUOUS = {"mutation_verified": True, "killed": False, "verdict": "vacuous"}


class T(unittest.TestCase):
    def test_ahc_credits_alias_kill(self):
        self.assertTrue(AHC._mvc_entry_is_genuine_kill(KILL_NO_ORACLE))
    def test_hzv_credits_alias_kill(self):
        self.assertTrue(HZV._mvc_entry_is_genuine_kill(KILL_NO_ORACLE))
    def test_vacuous_not_credited(self):
        self.assertFalse(AHC._mvc_entry_is_genuine_kill(VACUOUS))
        self.assertFalse(HZV._mvc_entry_is_genuine_kill(VACUOUS))
    def test_unkilled_not_credited(self):
        e = {"mutation_verified": True, "killed": False, "genuine_verdict": "non-vacuous"}
        self.assertFalse(AHC._mvc_entry_is_genuine_kill(e))
    def test_oracle_verdict_still_works(self):
        e = {"mutation_verified": True, "killed": True, "oracle_verdict": "non-vacuous"}
        self.assertTrue(AHC._mvc_entry_is_genuine_kill(e))
        self.assertTrue(HZV._mvc_entry_is_genuine_kill(e))


if __name__ == "__main__":
    unittest.main()
