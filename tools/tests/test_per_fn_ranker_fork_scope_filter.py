"""Loop-fix 2026-06-22: the per-fn ranker must intersect the ranked set with the
fork-scoped inscope_units.jsonl, so a STALE per_fn_hacker_questions.jsonl cannot leak
unmodified-upstream fork files (bor go-ethereum core/test) into the hunt (measured 31%
OOS-leak on polygon). Completeness-safe: no manifest -> keep all.
"""
import importlib.util
import json
import sys
import tempfile
import unittest
from pathlib import Path

_TOOLS = Path(__file__).resolve().parent.parent


def _load():
    spec = importlib.util.spec_from_file_location(
        "per_fn_ranker", str(_TOOLS / "per-fn-question-ranker.py"))
    mod = importlib.util.module_from_spec(spec)
    sys.modules["per_fn_ranker"] = mod
    spec.loader.exec_module(mod)
    return mod


def _ws_with_manifest(files):
    ws = Path(tempfile.mkdtemp()).resolve()
    (ws / ".auditooor").mkdir(parents=True)
    with (ws / ".auditooor" / "inscope_units.jsonl").open("w") as fh:
        for f in files:
            fh.write(json.dumps({"file": f}) + "\n")
    return ws


class TestForkScopeFilter(unittest.TestCase):
    def setUp(self):
        self.m = _load()

    def test_drops_units_not_in_manifest(self):
        ws = _ws_with_manifest(["src/pol-token/PolygonMigration.sol",
                                "src/cosmos-sdk/types/coin.go"])
        qs = [
            {"file": "src/pol-token/PolygonMigration.sol", "function": "burn"},   # in
            {"unit_id": "src/cosmos-sdk/types/coin.go:113"},                       # in
            {"file": "src/bor/core/evm.go", "function": "Transfer"},              # OOS upstream
            {"source_path": "src/bor/accounts/abi/bind/backends/simulated.go"},   # OOS test
        ]
        kept, dropped = self.m.filter_to_fork_scoped_manifest(qs, ws)
        self.assertEqual(dropped, 2)
        kept_files = {self.m._question_file(q) for q in kept}
        self.assertIn("src/pol-token/PolygonMigration.sol", kept_files)
        self.assertNotIn("src/bor/core/evm.go", kept_files)

    def test_drops_categorical_oos_even_if_in_stale_manifest(self):
        # belt-and-suspenders: a STALE manifest (built pre-F5) still lists a test
        # file (bor SimulatedBackend simulated.go). It passes the membership check
        # but the is_oos classifier must still drop it (the simulated.go leak that
        # reached the polygon step-3 hunt).
        ws = _ws_with_manifest(["src/pol-token/PolygonMigration.sol",
                                "src/bor/accounts/abi/bind/backends/simulated.go"])
        qs = [
            {"file": "src/pol-token/PolygonMigration.sol"},                       # in + not OOS -> keep
            {"file": "src/bor/accounts/abi/bind/backends/simulated.go"},          # in manifest BUT test -> drop
        ]
        kept, dropped = self.m.filter_to_fork_scoped_manifest(qs, ws)
        self.assertEqual(dropped, 1)
        kept_files = {self.m._question_file(q) for q in kept}
        self.assertIn("src/pol-token/PolygonMigration.sol", kept_files)
        self.assertNotIn("src/bor/accounts/abi/bind/backends/simulated.go", kept_files)

    def test_no_manifest_keeps_all(self):
        ws = Path(tempfile.mkdtemp()).resolve()  # no .auditooor/inscope_units.jsonl
        # evm.go is unmodified-upstream (only the manifest catches that) but NOT
        # categorically test/generated -> with no manifest it is kept.
        qs = [{"file": "src/bor/core/evm.go"}, {"file": "anything.sol"}]
        kept, dropped = self.m.filter_to_fork_scoped_manifest(qs, ws)
        self.assertEqual(dropped, 0)
        self.assertEqual(len(kept), 2)

    def test_no_file_is_kept_completeness_safe(self):
        ws = _ws_with_manifest(["src/A.sol"])
        qs = [{"question_text": "no file field at all"}]
        kept, dropped = self.m.filter_to_fork_scoped_manifest(qs, ws)
        self.assertEqual(dropped, 0)
        self.assertEqual(len(kept), 1)


if __name__ == "__main__":
    unittest.main(verbosity=2)
