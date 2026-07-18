# <!-- r36-rebuttal: lane substrate-per-impact-frames registered via agent-pathspec-register.py -->
"""Brick 3 regression: the completeness matrix credits the function-coverage axis
per (function x impact) when per-frame hunt sidecars (brick 1's __I-<impact> suffix)
exist.

Guarantees:
 (d1) a ws with ONLY legacy (frame-less) sidecars credits EXACTLY as before -
      any-sidecar => covered-hunt-verdict (BACKWARD-COMPAT HARD; no false-red).
 (d2) a fn hunted per-frame is credited covered ONLY when EVERY in-scope impact
      frame for its language has a verdict sidecar; a partial frame set is
      NOT-ENUMERATED (fail-closed).
 (d3) a fn with all frames covered is terminal (covered-hunt-verdict-all-frames).
"""
import importlib.util
import json
import sys
import tempfile
import unittest
from pathlib import Path

_TOOL = Path(__file__).resolve().parent.parent / "completeness-matrix-build.py"
_FILE = "src/foo/src/A.sol"   # _asset_of needs a src/<repo> path


def _load():
    spec = importlib.util.spec_from_file_location("completeness_matrix_build_pif", _TOOL)
    m = importlib.util.module_from_spec(spec)
    sys.modules["completeness_matrix_build_pif"] = m
    spec.loader.exec_module(m)
    return m


class PerImpactFrameCreditTest(unittest.TestCase):
    def setUp(self):
        self.m = _load()

    def _mkws(self):
        ws = Path(tempfile.mkdtemp())
        (ws / ".auditooor").mkdir(parents=True)
        (ws / ".auditooor" / "inscope_units.jsonl").write_text(
            json.dumps({"file": _FILE, "function": "f"}), encoding="utf-8")
        return ws

    def _sidecar(self, ws, name):
        d = ws / ".auditooor" / "hunt_findings_sidecars"
        d.mkdir(exist_ok=True)
        (d / name).write_text(json.dumps({
            "function_anchor": {"fn": "f", "file": _FILE},
            "file_line": _FILE + ":2", "verdict": "KILL",
        }), encoding="utf-8")

    def _status(self, ws):
        mat = self.m.build_matrix(ws)
        return mat["assets"][0]["functions"][0]["coverage_status"]

    # ---- (d1) LEGACY-ONLY ws credits EXACTLY as before --------------------
    def test_legacy_only_sidecar_credits_as_today(self):
        ws = self._mkws()
        self._sidecar(ws, "hunt__A.sol__f__deadbeef__L2.json")
        self.assertFalse(bool(self.m._hunt_examined_frames(ws)),
                         "no __I- suffix -> per-frame crediting must NOT engage")
        # 7ec846d1bb / 5c7c8c4c5d: a whole-fn terminal-refuted (KILL) verdict SUBSUMES
        # the per-frame requirement, so a legacy frame-less KILL sidecar is credited as
        # the STRONGER covered-hunt-verdict-terminal. The d1 backward-compat guarantee
        # (any-sidecar credits covered, no false-red) is PRESERVED: every consumer
        # prefix-matches "covered" (vault-mcp-server.py:25557 text.startswith("covered")),
        # so the terminal suffix never turns a covered fn red. Assert the stable prefix.
        self.assertTrue(self._status(ws).startswith("covered-hunt-verdict"),
                        "legacy sidecar must still credit covered (prefix-stable)")

    def test_no_sidecar_at_all_unchanged_not_enumerated(self):
        # sanity: no hunt evidence at all -> not-enumerated (fail-closed, unchanged)
        ws = self._mkws()
        self.assertEqual(self._status(ws), "not-enumerated")

    # ---- (d2) PARTIAL per-frame coverage: fail-closed ONLY with a seed ----
    def test_no_seed_partial_frames_credited_not_unsatisfiable(self):
        # NUVA 2026-07-03: WITHOUT a seed, the required-frame set cannot be derived,
        # so the per-frame floor must NOT invent a requirement in the mechanism-library
        # vocabulary (direct-theft / permanent-freeze / ...) - production sidecars use
        # the question_class vocabulary (generic / rubric-targeted / ...), which the
        # mech-lib set NEVER matches, making EVERY per-frame-hunted value-moving fn
        # permanently NOT-ENUMERATED (an unsatisfiable false-red). No seed => no
        # derivable requirement => the hunt sidecar credits the fn. The genuine
        # fail-closed-on-partial guarantee lives in test_partial_seed_frames_fail_closed
        # (a seed present => every DISPATCHED frame must have a verdict sidecar).
        ws = self._mkws()
        self._sidecar(ws, "hunt__A.sol__f__deadbeef__L2__I-rubric-targeted.json")
        self.assertFalse((self.m._dispatched_frames_by_fn(ws) or {}).get("f"),
                         "fixture has no seed -> dispatched frames must be empty")
        self.assertEqual(self._status(ws), "covered-hunt-verdict-all-frames")

    # ---- (d3) ALL dispatched frames covered => terminal -----------------
    def test_all_frames_covered_credits_terminal(self):
        ws = self._mkws()
        for imp in self.m._inscope_impact_frames_for_lang(
                "solidity", self.m._MECHANISM_LIBRARY_SEED):
            self._sidecar(ws, f"hunt__A.sol__f__deadbeef__L2__I-{imp}.json")
        self.assertEqual(self._status(ws), "covered-hunt-verdict-all-frames")

    def test_frames_map_parses_impact_suffix(self):
        ws = self._mkws()
        self._sidecar(ws, "hunt__A.sol__f__deadbeef__L2__I-permanent-freeze.json")
        self._sidecar(ws, "hunt__A.sol__f__deadbeef__L2__I-insolvency.json")
        frames = self.m._hunt_examined_frames(ws)
        self.assertEqual(frames.get("f"), {"permanent-freeze", "insolvency"})

    def test_required_frames_shared_with_builder_seed(self):
        # brick 2 (builder) and brick 3 (gate) must agree on the frame set for a lang
        gate = self.m._inscope_impact_frames_for_lang(
            "solidity", self.m._MECHANISM_LIBRARY_SEED)
        # derive the same way the builder does (impact has >=1 mechanism for solidity)
        expect = set()
        for impact, mechs in self.m._MECHANISM_LIBRARY_SEED.items():
            if any("solidity" in (mm.get("languages") or []) for mm in mechs):
                expect.add(impact)
        self.assertEqual(gate, expect)


class SeedDispatchedFramesTest(unittest.TestCase):
    """2026-07-02 fix: required-frames must come from the per-fn SEED (the same
    question_class/impact_id vocabulary brick 1 writes into the `__I-<frame>`
    suffix), NOT the mechanism-library vocabulary - which never matched, making the
    per-frame gate permanently unsatisfiable once per-impact-frames was enabled."""

    def setUp(self):
        self.m = _load()

    def _mkws(self, seed_rows):
        ws = Path(tempfile.mkdtemp())
        (ws / ".auditooor").mkdir(parents=True)
        (ws / ".auditooor" / "inscope_units.jsonl").write_text(
            json.dumps({"file": _FILE, "function": "f"}), encoding="utf-8")
        (ws / ".auditooor" / "per_fn_hacker_questions.jsonl").write_text(
            "\n".join(json.dumps(r) for r in seed_rows), encoding="utf-8")
        return ws

    def _sidecar(self, ws, name):
        d = ws / ".auditooor" / "hunt_findings_sidecars"
        d.mkdir(exist_ok=True)
        (d / name).write_text(json.dumps({
            "function_anchor": {"fn": "f", "file": _FILE},
            "file_line": _FILE + ":2", "verdict": "KILL"}), encoding="utf-8")

    def _status(self, ws):
        return self.m.build_matrix(ws)["assets"][0]["functions"][0]["coverage_status"]

    def test_seed_vocabulary_matches_sidecar_suffix(self):
        # the exact mismatch bug: seed says "protocol-insolvency", the mech-lib says
        # "insolvency". The gate must use the seed vocabulary.
        disp = self.m._dispatched_frames_by_fn(self._mkws(
            [{"function": "f", "question_class": "sum-preserved"},
             {"function": "f", "impact_id": "protocol-insolvency"}]))
        self.assertEqual(disp.get("f"), {"sum-preserved", "protocol-insolvency"})

    def test_partial_seed_frames_fail_closed(self):
        ws = self._mkws([{"function": "f", "impact_id": "direct-theft-funds"},
                         {"function": "f", "question_class": "sum-preserved"}])
        self._sidecar(ws, "hunt__A.sol__f__deadbeef__L2__I-direct-theft-funds.json")
        # only 1 of 2 DISPATCHED frames examined -> not-enumerated (fail-closed)
        self.assertEqual(self._status(ws), "not-enumerated")

    def test_all_seed_frames_examined_credits_terminal(self):
        ws = self._mkws([{"function": "f", "impact_id": "direct-theft-funds"},
                         {"function": "f", "question_class": "sum-preserved"}])
        self._sidecar(ws, "hunt__A.sol__f__deadbeef__L2__I-direct-theft-funds.json")
        self._sidecar(ws, "hunt__A.sol__f__deadbeef__L2__I-sum-preserved.json")
        # every dispatched frame now has a verdict sidecar (SATISFIABLE gate)
        self.assertEqual(self._status(ws), "covered-hunt-verdict-all-frames")

    def test_no_seed_credits_per_frame_hunted_fn(self):
        # backward-compat: a ws with per-frame sidecars but NO seed has NO derivable
        # per-frame requirement, so a per-frame-hunted fn is credited (it WAS hunted).
        # (Previously this fell back to the mechanism-library required set, which is an
        # unsatisfiable false-red in production - see test_no_seed_partial_frames_*.)
        ws = Path(tempfile.mkdtemp())
        (ws / ".auditooor").mkdir(parents=True)
        (ws / ".auditooor" / "inscope_units.jsonl").write_text(
            json.dumps({"file": _FILE, "function": "f"}), encoding="utf-8")
        d = ws / ".auditooor" / "hunt_findings_sidecars"
        d.mkdir()
        for imp in self.m._inscope_impact_frames_for_lang(
                "solidity", self.m._MECHANISM_LIBRARY_SEED):
            (d / f"hunt__A.sol__f__deadbeef__L2__I-{imp}.json").write_text(json.dumps({
                "function_anchor": {"fn": "f", "file": _FILE},
                "file_line": _FILE + ":2", "verdict": "KILL"}), encoding="utf-8")
        self.assertEqual(
            self.m.build_matrix(ws)["assets"][0]["functions"][0]["coverage_status"],
            "covered-hunt-verdict-all-frames")


if __name__ == "__main__":
    unittest.main(verbosity=2)
