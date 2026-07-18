#!/usr/bin/env python3
"""Regression tests for the LLM-hunt-only (Obyte Oscript) depth axis in
tools/depth-certificate-build.py + tools/depth-certificate-check.py.

WHY (Obyte 2026-07-09): the depth cert's guards_enumerated / sibling_pairs come
from STATIC analyzers (guard-negative-space / sibling-diff) that only parse the
engine languages (solidity/vyper/rust/go). A language with NO static/fuzz engine
- ``is_llm_hunt_only(lang)`` is True (Obyte Oscript AAs, ``.oscript``/``.aa``) -
emits ZERO static guards, so the depth cert would either:
  (a) silently 0-pass (false-green: the Oscript units are invisible), or
  (b) falsely-block (an Oscript-only workspace pinned at depth-not-run forever,
      because a static guard-enumeration that cannot exist is demanded).

The fix credits the LANGUAGE-APPROPRIATE evidence - an LLM hunt verdict
(hunt_findings_sidecar anchored to a unit's file). An LLM-hunt-only unit is
depth-covered iff a matching hunt sidecar exists; one WITHOUT stays uncovered
(no over-credit). The axis is ADDITIVE + default-off: an engine-only workspace
cert is byte-identical, and the Solidity/Go static depth logic is untouched.

Load-bearing assertions:
  * ENGINE-ONLY workspace: the cert has NO ``llm_hunt_only_depth`` block, and the
    check overlay is a no-op (byte-identical gate result).
  * RECOGNITION: an Oscript-bearing workspace's cert recognizes the units
    (units_total > 0) instead of dropping them as unknown-ext (silent-0).
  * PER-UNIT CREDIT / NO OVER-CREDIT: a unit whose file has a matching sidecar is
    credited (covered); a unit whose file has NO sidecar stays uncovered. A
    basename-only collision (city-aa/governance.oscript vs coop-aa/governance.oscript)
    does NOT cross-credit.
  * FALSE-BLOCK FIX: an entirely-Oscript workspace with FULL coverage passes the
    gate (pass-oscript-depth-llm-hunt-credited) instead of the false
    fail-depth-not-run; PARTIAL / ZERO coverage yields a distinct honest
    fail-oscript-depth-uncovered (never a silent pass).
  * MIXED workspace: the axis is advisory-only - the engine-derived verdict
    stands (Solidity/Go behavior byte-identical).
"""
from __future__ import annotations

import importlib.util
import json
import tempfile
import unittest
from pathlib import Path

TOOLS = Path(__file__).resolve().parents[1]
BUILD_TOOL = TOOLS / "depth-certificate-build.py"
CHECK_TOOL = TOOLS / "depth-certificate-check.py"


def _load(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    mod = importlib.util.module_from_spec(spec)
    assert spec and spec.loader
    spec.loader.exec_module(mod)
    return mod


BUILD = _load("_oscript_depth_build", BUILD_TOOL)
CHECK = _load("_oscript_depth_check", CHECK_TOOL)


def _jsonl(p: Path, rows: list[dict]) -> None:
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text("\n".join(json.dumps(r) for r in rows) + "\n", encoding="utf-8")


def _unit(file: str, fn: str, lang: str = "oscript") -> dict:
    return {"file": file, "fn": fn, "function": fn, "lang": lang,
            "file_line": f"{file}:1", "kind": "getter"}


def _sidecar(ws: Path, name: str, file: str, function: str = "case") -> None:
    d = ws / ".auditooor" / "hunt_findings_sidecars"
    d.mkdir(parents=True, exist_ok=True)
    (d / name).write_text(json.dumps({
        "workspace_path": str(ws),
        "function_anchor": {"file": file, "function": function, "line": 1},
        "task_type": "hunt",
        "verification_tier": "tier-1-source-read-verified",
        "result": {"applies_to_target": "no", "confidence": "high"},
    }), encoding="utf-8")


class TestOscriptLLMHuntOnlyDepth(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.ws = Path(self._tmp.name)
        self.aud = self.ws / ".auditooor"
        self.aud.mkdir(parents=True, exist_ok=True)

    def tearDown(self):
        self._tmp.cleanup()

    def _cert(self) -> dict:
        BUILD.write_certificate(self.ws, BUILD.build_certificate(self.ws, None))
        return json.loads((self.aud / "depth_certificate.json").read_text())

    # --- ENGINE-ONLY: no block, byte-identical gate --------------------------
    def test_engine_only_workspace_has_no_axis_block(self):
        # A solidity-only inscope manifest plus a full static depth run must
        # produce a cert with NO llm_hunt_only_depth key (byte-identical).
        _jsonl(self.aud / "inscope_units.jsonl", [
            _unit("src/x.sol", "foo", lang="solidity"),
            _unit("src/y.sol", "bar", lang="solidity"),
        ])
        cert = BUILD.build_certificate(self.ws, None)
        self.assertNotIn("llm_hunt_only_depth", cert)
        # And the check overlay is a strict no-op: the result equals the static
        # core result exactly (no advisory keys added).
        BUILD.write_certificate(self.ws, cert)
        core = CHECK._check_depth_core(self.ws)
        full = CHECK.check_depth(self.ws)
        self.assertEqual(core, full)
        self.assertNotIn("llm_hunt_only_depth", full)

    def test_no_inscope_manifest_is_byte_identical(self):
        # No inscope_units.jsonl at all (the axis returns None) -> no block.
        cert = BUILD.build_certificate(self.ws, None)
        self.assertNotIn("llm_hunt_only_depth", cert)

    # --- RECOGNITION + PER-UNIT CREDIT + NO OVER-CREDIT ----------------------
    def test_units_recognized_and_credited_per_file(self):
        # Two files share the BASENAME governance.oscript in different dirs; only
        # one has a sidecar. The other must stay uncovered (no basename cross-credit).
        _jsonl(self.aud / "inscope_units.jsonl", [
            _unit("src/city-aa/governance.oscript", "$a"),   # covered (has sidecar)
            _unit("src/city-aa/governance.oscript", "$b"),   # covered (same file)
            _unit("src/coop-aa/governance.oscript", "$c"),   # UNcovered (no sidecar)
            _unit("src/friend/friend.aa", "$d"),             # covered (.aa sidecar)
        ])
        _sidecar(self.ws, "s_city.json", "src/city-aa/governance.oscript")
        _sidecar(self.ws, "s_friend.json", "src/friend/friend.aa")
        block = BUILD._llm_hunt_only_depth_axis(self.ws)
        self.assertIsNotNone(block)
        # RECOGNITION: units are not dropped as unknown-ext.
        self.assertEqual(block["units_total"], 4)
        self.assertEqual(block["langs"], ["oscript"])
        self.assertEqual(block["engine_units_total"], 0)
        # PER-UNIT CREDIT: 3 covered (2 city + 1 friend), 1 uncovered (coop).
        self.assertEqual(block["covered_units"], 3)
        self.assertEqual(block["uncovered_units"], 1)
        self.assertEqual(block["axis_verdict"], "partial")
        # NO OVER-CREDIT: the coop file (no sidecar) is in uncovered_files, and
        # the basename-colliding coop governance is NOT credited from city's sidecar.
        self.assertIn("src/coop-aa/governance.oscript", block["uncovered_files"])
        self.assertIn("src/city-aa/governance.oscript", block["covered_files"])
        self.assertNotIn("src/coop-aa/governance.oscript", block["covered_files"])

    def test_solidity_sidecar_does_not_credit_oscript_axis(self):
        # A sidecar anchored to a .sol file is an ENGINE-lang sidecar; it must NOT
        # count toward the hunt-only axis (nor could it join by path).
        _jsonl(self.aud / "inscope_units.jsonl", [_unit("src/a.oscript", "$f")])
        _sidecar(self.ws, "sol.json", "src/a.sol")  # engine-lang anchor
        block = BUILD._llm_hunt_only_depth_axis(self.ws)
        self.assertEqual(block["hunt_sidecars_total"], 0)
        self.assertEqual(block["covered_units"], 0)
        self.assertEqual(block["axis_verdict"], "uncovered")

    # --- FALSE-BLOCK FIX: all-oscript, full coverage -> PASS -----------------
    def test_all_oscript_full_coverage_passes_gate(self):
        _jsonl(self.aud / "inscope_units.jsonl", [
            _unit("src/a.oscript", "$f1"),
            _unit("src/a.oscript", "$f2"),
            _unit("src/b.aa", "$g1"),
        ])
        _sidecar(self.ws, "sa.json", "src/a.oscript")
        _sidecar(self.ws, "sb.json", "src/b.aa")
        cert = self._cert()
        # The static verdict is (correctly) depth-not-run: no static guards exist.
        self.assertEqual(cert["verdict"], BUILD.VERDICT_NOT_RUN)
        # But the GATE credits the oscript axis and PASSES (false-block fixed).
        res = CHECK.check_depth(self.ws)
        self.assertEqual(res["verdict"], CHECK.PASS_OSCRIPT, res)
        self.assertEqual(res["would_be_verdict_static"], CHECK.FAIL_DEPTH_NOT_RUN)
        rc = CHECK.main(["--workspace", str(self.ws), "--json"])
        self.assertEqual(rc, 0)

    def test_all_oscript_partial_coverage_fails_honestly(self):
        _jsonl(self.aud / "inscope_units.jsonl", [
            _unit("src/a.oscript", "$f1"),
            _unit("src/b.aa", "$g1"),  # uncovered
        ])
        _sidecar(self.ws, "sa.json", "src/a.oscript")
        self._cert()
        res = CHECK.check_depth(self.ws)
        self.assertEqual(res["verdict"], CHECK.FAIL_OSCRIPT_UNCOVERED, res)
        rc = CHECK.main(["--workspace", str(self.ws), "--json"])
        self.assertEqual(rc, 1)

    def test_all_oscript_zero_sidecars_is_not_silent_pass(self):
        # No sidecars at all: the gate must NOT silently pass an unhunted oscript
        # workspace; it fails distinctly (uncovered), never fail-depth-not-run.
        _jsonl(self.aud / "inscope_units.jsonl", [_unit("src/a.oscript", "$f1")])
        self._cert()
        res = CHECK.check_depth(self.ws)
        self.assertEqual(res["verdict"], CHECK.FAIL_OSCRIPT_UNCOVERED, res)
        self.assertNotIn(res["verdict"], CHECK._PASS_VERDICTS)

    # --- MIXED: advisory only; engine verdict stands -------------------------
    def test_mixed_workspace_axis_is_advisory_only(self):
        # engine (solidity) units present + a fully-covered oscript set. The
        # static passes did NOT run, so the engine verdict is depth-not-run; the
        # oscript axis must NOT flip that to a pass (advisory-first).
        _jsonl(self.aud / "inscope_units.jsonl", [
            _unit("src/x.sol", "foo", lang="solidity"),
            _unit("src/a.oscript", "$f1"),
        ])
        _sidecar(self.ws, "sa.json", "src/a.oscript")
        self._cert()
        res = CHECK.check_depth(self.ws)
        # engine verdict stands (NOT overridden to a pass).
        self.assertEqual(res["verdict"], CHECK.FAIL_DEPTH_NOT_RUN, res)
        self.assertNotIn(res["verdict"], CHECK._PASS_VERDICTS)
        # but the axis IS surfaced advisorily (recognition, not silent).
        self.assertIn("llm_hunt_only_depth", res)
        self.assertEqual(res["llm_hunt_only_depth"]["engine_units_total"], 1)
        self.assertEqual(res["llm_hunt_only_depth"]["units_total"], 1)

    def test_mixed_engine_audited_still_ignores_uncovered_oscript(self):
        # A mixed ws whose ENGINE depth is fully audited passes on the engine
        # axis; advisory-first means an uncovered oscript set does NOT block it
        # (surfaced, not enforced) - keeping Solidity gate behavior unchanged.
        _jsonl(self.aud / "inscope_units.jsonl", [
            _unit("src/x.sol", "foo", lang="solidity"),
            _unit("src/a.oscript", "$f1"),  # uncovered oscript
        ])
        _jsonl(self.aud / "negative_space_worklist.jsonl", [
            {"schema": "auditooor.guard_negative_space.v1", "guard_id": "NS-a",
             "file_line": "src/x.sol:10", "kinds": ["require"], "checks": "require(x>0)"},
        ])
        _jsonl(self.aud / "negative_space_gaps.jsonl", [
            {"schema": "auditooor.guard_negative_space.v1", "guard_id": "NS-a",
             "file_line": "src/x.sol:10", "gap_found": True,
             "exploitation_attempt_artifact": "poc/a_test.sol"},
        ])
        _jsonl(self.aud / "sibling_guard_asymmetries.jsonl", [])
        BUILD.write_certificate(
            self.ws,
            BUILD.build_certificate(self.ws, {"findings_drafted": [{"id": "F1"}]}),
        )
        res = CHECK.check_depth(self.ws)
        self.assertEqual(res["verdict"], CHECK.PASS, res)  # engine PASS unchanged
        self.assertEqual(res["llm_hunt_only_depth"]["axis_verdict"], "uncovered")


if __name__ == "__main__":
    unittest.main()
