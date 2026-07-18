#!/usr/bin/env python3
"""Regression: invariant-fuzz-completeness._campaign_call_metrics reads a retained medusa
log in .auditooor/fuzz_logs/ (UNDERSCORE - the canonical persist-fuzz-campaign target).

Bug (Strata 2026-07-07): the scan list had `.auditooor/fuzz-logs` (HYPHEN) + fuzz_runs but
NOT `.auditooor/fuzz_logs` (underscore), so 4 genuine >=1M campaign logs on disk read as
'corpus-only, no machine-readable call count' and hard-failed the gate - a serving-join
(evidence present, reader looking in the wrong dir)."""
import importlib.util
import unittest
import tempfile
from pathlib import Path

_H = Path(__file__).resolve().parent
_s = importlib.util.spec_from_file_location("ifc", _H.parent / "invariant-fuzz-completeness.py")
ifc = importlib.util.module_from_spec(_s)
_s.loader.exec_module(ifc)


class T(unittest.TestCase):
    def _ws(self, logdir):
        ws = Path(tempfile.mkdtemp())
        (ws / ".auditooor" / logdir).mkdir(parents=True)
        (ws / "chimera_harnesses" / "FooConservation").mkdir(parents=True)
        (ws / ".auditooor" / logdir / "medusa_FooConservation.log").write_text(
            "medusa fuzzing...\n[status] elapsed: 3m0s   calls: 1207467 (6708/sec)   coverage: 812\n")
        return ws

    def test_underscore_fuzz_logs_dir_is_read(self):
        ws = self._ws("fuzz_logs")
        calls, dry = ifc._campaign_call_metrics(ws, ws / "chimera_harnesses" / "FooConservation")
        self.assertGreaterEqual(calls, 1_000_000)
        self.assertFalse(dry)

    def test_legacy_hyphen_dir_still_read(self):
        ws = self._ws("fuzz-logs")
        calls, _ = ifc._campaign_call_metrics(ws, ws / "chimera_harnesses" / "FooConservation")
        self.assertGreaterEqual(calls, 1_000_000)


if __name__ == "__main__":
    unittest.main()
