"""test_per_fn_mimo_impact_frame.py

The CANONICAL scoped-hunt enablement of the (unit x frame) substrate: per-fn-mimo-
batch-gen.build_enriched_task tags each task with an `impact` FRAME (real impact_id
when present, else the question_class), so haiku-fanout _sidecar_slug (brick 1)
writes a frame-DISTINCT sidecar. Regression: same function under two different
frames -> two distinct sidecars (the strata MIN_SHARES collision fix). Default ON;
PER_IMPACT_FRAMES=0 restores the legacy frame-less task.
"""
from __future__ import annotations

import importlib.util
import os
import pathlib
import sys
import tempfile
import unittest

REPO_ROOT = pathlib.Path(__file__).resolve().parents[2]
GEN_PATH = REPO_ROOT / "tools" / "per-fn-mimo-batch-gen.py"
FANOUT_PATH = REPO_ROOT / "tools" / "haiku-fanout-dispatcher.py"


def _load(path, name):
    spec = importlib.util.spec_from_file_location(name, path)
    mod = importlib.util.module_from_spec(spec)
    sys.modules[name] = mod
    spec.loader.exec_module(mod)  # type: ignore[union-attr]
    return mod


GEN = _load(GEN_PATH, "per_fn_mimo_batch_gen")
FANOUT = _load(FANOUT_PATH, "haiku_fanout_dispatcher_mimo")


def _task(q, ws):
    return GEN.build_enriched_task(0, q, ws, "strata", "", {}, {}, [])


def _q(fn, qclass, **extra):
    d = {"file": "src/contracts/tranches/Tranche.sol", "function": fn,
         "question": "hunt it", "question_class": qclass, "language": "solidity"}
    d.update(extra)
    return d


class TestPerFnMimoImpactFrame(unittest.TestCase):
    def setUp(self):
        os.environ.pop("PER_IMPACT_FRAMES", None)

    def test_task_carries_question_class_frame(self):
        with tempfile.TemporaryDirectory() as td:
            t = _task(_q("withdraw", "permanent-freeze-funds"), pathlib.Path(td))
            self.assertEqual(t["impact"], "permanent-freeze-funds")

    def test_real_impact_id_preferred_over_question_class(self):
        with tempfile.TemporaryDirectory() as td:
            t = _task(_q("withdraw", "sum-preserved", impact_id="direct-theft-funds"),
                      pathlib.Path(td))
            self.assertEqual(t["impact"], "direct-theft-funds")

    def test_per_impact_frames_off_restores_legacy(self):
        os.environ["PER_IMPACT_FRAMES"] = "0"
        try:
            with tempfile.TemporaryDirectory() as td:
                t = _task(_q("withdraw", "permanent-freeze-funds"), pathlib.Path(td))
                self.assertEqual(t["impact"], "")
        finally:
            os.environ.pop("PER_IMPACT_FRAMES", None)

    def test_same_fn_two_frames_yield_distinct_sidecars(self):
        """The collision fix, end-to-end through brick 1's _sidecar_slug."""
        with tempfile.TemporaryDirectory() as td:
            ws = pathlib.Path(td)
            theft = _task(_q("withdraw", "sum-preserved"), ws)
            freeze = _task(_q("withdraw", "permanent-freeze-funds"), ws)
            s_theft = FANOUT._sidecar_slug(theft, theft["task_id"])
            s_freeze = FANOUT._sidecar_slug(freeze, freeze["task_id"])
            self.assertNotEqual(s_theft, s_freeze)
            self.assertIn("__I-sum-preserved", s_theft)
            self.assertIn("__I-permanent-freeze-funds", s_freeze)

    def test_bare_unit_id_recovers_fn_no_collision(self):
        """BARE-UNIT_ID REGRESSION: the per-fn-question-ranker emits the function
        identity in `unit_id` as a BARE token (e.g. unit_id='PauseVault') with
        function/fn absent. build_enriched_task must recover fn from the bare
        unit_id, not leave it '?'. A '?' fn collapses _sidecar_slug to a per-FILE
        path so every function of a file overwrites ONE sidecar (NUVA residual: 14
        msg_server.go units -> 1 file, silently losing per-fn coverage credit)."""
        with tempfile.TemporaryDirectory() as td:
            ws = pathlib.Path(td)
            q1 = {"source_path": "src/vault/keeper/msg_server.go",
                  "unit_id": "PauseVault", "question": "q", "question_class": "generic"}
            q2 = {"source_path": "src/vault/keeper/msg_server.go",
                  "unit_id": "UnpauseVault", "question": "q", "question_class": "generic"}
            t1 = _task(q1, ws)
            t2 = _task(q2, ws)
            self.assertEqual(t1["function_anchor"]["fn"], "PauseVault")
            self.assertEqual(t2["function_anchor"]["fn"], "UnpauseVault")
            # Two distinct functions of the SAME file -> two distinct sidecars.
            s1 = FANOUT._sidecar_slug(t1, t1["task_id"])
            s2 = FANOUT._sidecar_slug(t2, t2["task_id"])
            self.assertNotEqual(s1, s2)
            self.assertIn("PauseVault", s1)
            self.assertIn("UnpauseVault", s2)

    def test_case_only_sibling_fns_no_line_get_distinct_slugs(self):
        """CASE-COLLISION REGRESSION (NUVA 2026-07-03): on a case-insensitive
        filesystem (macOS APFS), Go's exported GetVault and unexported getVault -
        same file, differing ONLY by case, both with no decl line - would collapse
        to the SAME physical sidecar. _sidecar_slug must make them differ by more
        than case when no line is available to disambiguate."""
        t_upper = {"function_anchor": {"file": "src/vault/keeper/vault.go",
                                       "fn": "GetVault", "start_line": 0, "end_line": 0}}
        t_lower = {"function_anchor": {"file": "src/vault/keeper/vault.go",
                                       "fn": "getVault", "start_line": 0, "end_line": 0}}
        s_upper = FANOUT._sidecar_slug(t_upper, "t1")
        s_lower = FANOUT._sidecar_slug(t_lower, "t2")
        # Distinct even when lowercased (the case-insensitive FS test).
        self.assertNotEqual(s_upper.lower(), s_lower.lower(),
                            f"case-only siblings must not collide on a case-insensitive FS: {s_upper} vs {s_lower}")

    def test_lowercase_only_fn_slug_unchanged(self):
        """The case-collision discriminator must NOT touch lowercase-only fns (they
        cannot case-collide) - their slug stays byte-identical to the legacy scheme."""
        t = {"function_anchor": {"file": "src/vault/keeper/vault.go",
                                 "fn": "getvault", "start_line": 0, "end_line": 0}}
        s = FANOUT._sidecar_slug(t, "t")
        self.assertNotIn("__f", s, f"lowercase-only fn must not get a case-discriminator suffix: {s}")

    def test_qualified_unit_id_still_recovers_fn(self):
        """Backward-compat: a 'File::fn' qualified unit_id keeps recovering the fn
        (the pre-existing '::' path is unchanged)."""
        with tempfile.TemporaryDirectory() as td:
            t = _task({"source_path": "src/Vault.sol",
                       "unit_id": "src/Vault.sol::deposit",
                       "question": "q", "question_class": "generic"}, pathlib.Path(td))
            self.assertEqual(t["function_anchor"]["fn"], "deposit")

    def test_off_yields_colliding_sidecars(self):
        """Sanity: with the flag off, same fn -> same slug (legacy collision) -
        confirms the frame is what separates them."""
        os.environ["PER_IMPACT_FRAMES"] = "0"
        try:
            with tempfile.TemporaryDirectory() as td:
                ws = pathlib.Path(td)
                a = _task(_q("withdraw", "sum-preserved"), ws)
                b = _task(_q("withdraw", "permanent-freeze-funds"), ws)
                self.assertEqual(FANOUT._sidecar_slug(a, a["task_id"]),
                                 FANOUT._sidecar_slug(b, b["task_id"]))
        finally:
            os.environ.pop("PER_IMPACT_FRAMES", None)


if __name__ == "__main__":
    unittest.main()
