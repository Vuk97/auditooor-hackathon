#!/usr/bin/env python3
# <!-- r36-rebuttal: lane FIX-HONEST-ZERO-VERIFY registered via agent-pathspec-register.py -->
"""Guard: honest-zero-verify RECOMPUTES the honest-0 from evidence, so a
hand-written honest_zero.json cannot fake it. Every load-bearing check must be
individually able to fail the verdict (no single soft spot).
"""
import importlib.util
import json
import os
import sys
import tempfile
import time
import unittest
from pathlib import Path

_TOOLS = Path(__file__).resolve().parent.parent
spec = importlib.util.spec_from_file_location("hzv", str(_TOOLS / "honest-zero-verify.py"))
m = importlib.util.module_from_spec(spec)
sys.modules["hzv"] = m
spec.loader.exec_module(m)


def _write_economic_harness(ws: Path, name: str) -> str:
    """Write a harness file with genuine economic vocabulary; return the relative path."""
    harness_dir = ws / "test" / "harnesses"
    harness_dir.mkdir(parents=True, exist_ok=True)
    harness_path = harness_dir / name
    harness_path.write_text(
        "// Economic invariant: total collateral >= total debt\n"
        "function invariant_solvency() external {\n"
        "    assert(totalCollateral() >= totalDebt());\n"
        "    // checks mint/burn conservation\n"
        "}\n"
    )
    return str(harness_path.relative_to(ws))


def _write_source_file(ws: Path, name: str) -> str:
    """Write a minimal source file; return the relative path."""
    src_dir = ws / "src"
    src_dir.mkdir(parents=True, exist_ok=True)
    src_path = src_dir / name
    src_path.write_text("// core contract\n")
    return str(src_path.relative_to(ws))


def _per_function_entry(ws: Path, harness_rel: str, source_rel: str) -> dict:
    return {
        "function": "invariant_solvency",
        "mutation_verified": True,
        "oracle_verdict": "non-vacuous",
        "killed": True,
        "harness_file": harness_rel,
        "source_file": source_rel,
    }


def _genuine_ws() -> Path:
    """A workspace that legitimately satisfies every honest-0 check."""
    ws = Path(tempfile.mkdtemp())
    a = ws / ".auditooor"
    a.mkdir()
    # (1) fresh pass-audit-complete STRICT marker
    (a / "audit_complete_last_result.json").write_text(json.dumps(
        {"verdict": "pass-audit-complete", "strict": True}))
    # (2) unhunted gate passes: no queue/packet artifacts => pass-no-workspace-inputs
    #     (the gate returns a pass-* verdict when there are no surfaces)
    # (3) nothing fileable: no submissions/paste_ready, no open candidate-findings
    (a / "residual_hunt_verdicts.json").write_text(json.dumps(
        [{"lead_id": "X", "verdict": "refuted"}]))
    # (4) deep evidence
    (a / "deep-engine-findings").mkdir()
    (a / "deep-engine-findings" / "CORE-SOLVENCY-fuzz.md").write_text("x" * 400)
    # Build 3 genuine economic per_function entries for check (5)
    per_fn = []
    for i in range(3):
        h_rel = _write_economic_harness(ws, f"Econ{i}.sol")
        s_rel = _write_source_file(ws, f"Core{i}.sol")
        per_fn.append(_per_function_entry(ws, h_rel, s_rel))
    (a / "mutation_verify_coverage.json").write_text(json.dumps(
        {
            "counts": {"cross_function_verified": 5, "per_function_verified": 3},
            "per_function": per_fn,
        }
    ))
    (a / "coverage_report.json").write_text(json.dumps({"covered": 10, "uncovered": 0}))
    return ws


class TestHonestZeroVerify(unittest.TestCase):
    def test_genuine_passes(self):
        r = m.verify(_genuine_ws())
        self.assertTrue(r["ok"], r["reason"])

    def test_no_audit_complete_marker_fails(self):
        ws = _genuine_ws()
        (ws / ".auditooor" / "audit_complete_last_result.json").unlink()
        r = m.verify(ws)
        self.assertFalse(r["ok"])
        self.assertFalse(r["checks"]["audit_complete"]["ok"])

    def test_non_strict_marker_fails(self):
        ws = _genuine_ws()
        (ws / ".auditooor" / "audit_complete_last_result.json").write_text(json.dumps(
            {"verdict": "pass-audit-complete", "strict": False}))
        self.assertFalse(m.verify(ws)["ok"])

    def test_missing_deep_evidence_fails(self):
        ws = _genuine_ws()
        (ws / ".auditooor" / "mutation_verify_coverage.json").write_text(json.dumps(
            {"counts": {"cross_function_verified": 0, "per_function_verified": 0}}))
        r = m.verify(ws)
        self.assertFalse(r["ok"])
        self.assertFalse(r["checks"]["deep_evidence"]["ok"])

    def test_trivial_fuzz_artifact_fails(self):
        ws = _genuine_ws()
        # shrink the fuzz md below the non-trivial threshold
        (ws / ".auditooor" / "deep-engine-findings" / "CORE-SOLVENCY-fuzz.md").write_text("tiny")
        self.assertFalse(m.verify(ws)["ok"])

    def test_open_candidate_finding_fails(self):
        ws = _genuine_ws()
        (ws / ".auditooor" / "residual_hunt_verdicts.json").write_text(json.dumps(
            [{"lead_id": "X", "verdict": "candidate-finding"}]))
        r = m.verify(ws)
        self.assertFalse(r["ok"], "an open candidate-finding must block honest-0")
        self.assertFalse(r["checks"]["nothing_fileable"]["ok"])

    def test_paste_ready_present_is_not_a_zero(self):
        ws = _genuine_ws()
        pr = ws / "submissions" / "paste_ready"
        pr.mkdir(parents=True)
        (pr / "finding.md").write_text("a real finding")
        r = m.verify(ws)
        self.assertFalse(r["ok"], "a paste_ready submission means it is NOT a 0")

    def test_stale_marker_fails(self):
        ws = _genuine_ws()
        mk = ws / ".auditooor" / "audit_complete_last_result.json"
        old = time.time() - 10 * 3600
        os.utime(mk, (old, old))
        self.assertFalse(m.verify(ws, ttl_hours=6)["ok"])

    def test_hand_written_file_does_not_short_circuit(self):
        """Writing a honest_zero.json with all_gates_green=true must NOT make
        verify() pass when the underlying evidence is absent - verify ignores
        the file and recomputes."""
        ws = Path(tempfile.mkdtemp())
        (ws / ".auditooor").mkdir()
        (ws / ".auditooor" / "honest_zero.json").write_text(json.dumps(
            {"all_gates_green": True, "verified_by": "honest-zero-verify.py"}))
        r = m.verify(ws)
        self.assertFalse(r["ok"], "a hand-written honest_zero must not fake the verdict")


class TestEconomicInvariantsCheck(unittest.TestCase):
    """Check #5: economic_invariants gate tests."""

    def _base_mvc(self, ws: Path, per_fn: list) -> None:
        a = ws / ".auditooor"
        a.mkdir(exist_ok=True)
        (a / "mutation_verify_coverage.json").write_text(json.dumps({
            "counts": {
                "cross_function_verified": len(per_fn),
                "per_function_verified": len(per_fn),
            },
            "per_function": per_fn,
        }))

    def _economic_entry(self, ws: Path, idx: int) -> dict:
        h_rel = _write_economic_harness(ws, f"EconTest{idx}.sol")
        s_rel = _write_source_file(ws, f"CoreTest{idx}.sol")
        return _per_function_entry(ws, h_rel, s_rel)

    def test_three_real_economic_invariants_pass(self):
        """>=3 genuine economic kills => check passes."""
        ws = Path(tempfile.mkdtemp())
        entries = [self._economic_entry(ws, i) for i in range(3)]
        self._base_mvc(ws, entries)
        ok, detail, fp = m._check_economic_invariants(ws)
        self.assertTrue(ok, detail)
        self.assertIn("3", detail)
        self.assertTrue(fp.startswith("econ:"))

    def test_fewer_than_minimum_fails(self):
        """Only 2 genuine economic kills (min=3) => check fails."""
        ws = Path(tempfile.mkdtemp())
        entries = [self._economic_entry(ws, i) for i in range(2)]
        self._base_mvc(ws, entries)
        ok, detail, fp = m._check_economic_invariants(ws)
        self.assertFalse(ok, "2 < 3 must fail")
        self.assertIn("2", detail)
        self.assertEqual(fp, "")

    def test_zero_invariants_fails(self):
        """No per_function entries => check fails."""
        ws = Path(tempfile.mkdtemp())
        self._base_mvc(ws, [])
        ok, detail, _fp = m._check_economic_invariants(ws)
        self.assertFalse(ok, "zero entries must fail")

    def test_stub_only_harness_does_not_count(self):
        """A harness with no economic vocabulary keyword must not count."""
        ws = Path(tempfile.mkdtemp())
        # write a stub harness with no economic terms
        stub_dir = ws / "test" / "harnesses"
        stub_dir.mkdir(parents=True, exist_ok=True)
        stub_path = stub_dir / "StubHarness.sol"
        stub_path.write_text("function invariant_stub() external { assert(true); }\n")
        s_rel = _write_source_file(ws, "StubCore.sol")
        stub_entry = {
            "function": "invariant_stub",
            "mutation_verified": True,
            "oracle_verdict": "non-vacuous",
            "killed": True,
            "harness_file": str(stub_path.relative_to(ws)),
            "source_file": s_rel,
        }
        self._base_mvc(ws, [stub_entry, stub_entry, stub_entry])
        ok, detail, _fp = m._check_economic_invariants(ws)
        self.assertFalse(ok, "stub-only harnesses must not satisfy economic check")
        self.assertIn("0", detail)

    def test_non_disk_harness_not_counted(self):
        """A per_function entry whose harness_file does not exist on disk must not count."""
        ws = Path(tempfile.mkdtemp())
        s_rel = _write_source_file(ws, "CoreGhost.sol")
        ghost_entry = {
            "function": "invariant_solvency",
            "mutation_verified": True,
            "oracle_verdict": "non-vacuous",
            "killed": True,
            "harness_file": "test/harnesses/DoesNotExist.sol",
            "source_file": s_rel,
        }
        self._base_mvc(ws, [ghost_entry, ghost_entry, ghost_entry])
        ok, detail, _fp = m._check_economic_invariants(ws)
        self.assertFalse(ok, "phantom harness file must not count")

    def test_l37_rebuttal_escape(self):
        """l37-rebuttal with 'economic_invariants' line flips check to ok-rebuttal."""
        ws = Path(tempfile.mkdtemp())
        a = ws / ".auditooor"
        a.mkdir(exist_ok=True)
        # zero economic invariants - would normally fail
        self._base_mvc(ws, [])
        # write rebuttal file
        (a / "l37-rebuttal").write_text(
            "some-other-gate\neconomic_invariants\nanother-gate\n"
        )
        ok, detail, fp = m._check_economic_invariants(ws)
        self.assertTrue(ok, "rebuttal escape must flip to pass")
        self.assertIn("ok-rebuttal", detail)
        self.assertEqual(fp, "econ:rebuttal")

    def test_l37_rebuttal_wrong_key_does_not_escape(self):
        """A rebuttal file without the 'economic_invariants' key must not escape."""
        ws = Path(tempfile.mkdtemp())
        a = ws / ".auditooor"
        a.mkdir(exist_ok=True)
        self._base_mvc(ws, [])
        (a / "l37-rebuttal").write_text("some-other-gate\nyet-another\n")
        ok, _detail, _fp = m._check_economic_invariants(ws)
        self.assertFalse(ok, "wrong rebuttal key must not escape")

    def test_economic_check_wired_into_verify(self):
        """economic_invariants is present as a named key in verify() output."""
        ws = _genuine_ws()
        r = m.verify(ws)
        self.assertIn("economic_invariants", r["checks"])

    def test_genuine_ws_passes_economic_check(self):
        """The _genuine_ws fixture satisfies the economic invariants check."""
        ws = _genuine_ws()
        r = m.verify(ws)
        econ = r["checks"].get("economic_invariants", {})
        self.assertTrue(econ.get("ok"), econ.get("detail", "check missing"))

    def test_env_override_min_invariants(self):
        """AUDITOOOR_HZ_ECON_MIN_INVARIANTS env var overrides the minimum."""
        import os as _os
        ws = Path(tempfile.mkdtemp())
        # write exactly 1 genuine economic entry
        entries = [self._economic_entry(ws, 0)]
        self._base_mvc(ws, entries)
        # with default min=3, should fail
        ok_default, _, _ = m._check_economic_invariants(ws)
        self.assertFalse(ok_default, "1 < 3 must fail by default")
        # with env override to 1, should pass
        _os.environ["AUDITOOOR_HZ_ECON_MIN_INVARIANTS"] = "1"
        try:
            ok_override, detail, _ = m._check_economic_invariants(ws)
            self.assertTrue(ok_override, f"with min=1, 1 entry should pass: {detail}")
        finally:
            del _os.environ["AUDITOOOR_HZ_ECON_MIN_INVARIANTS"]


class TestEconomicCreditingFixes(unittest.TestCase):
    """Generic fixes: the economic counter reads the canonical registrar field
    `harness` (not only the dead `harness_file`), and folds standalone
    mutation-verify-coverage.v1 sidecars (CUT-keyed, never in the aggregate
    per_function). UN-FAKEABLE criteria preserved (killed + non-vacuous + CUT on
    disk + economic vocab) - no false-green."""

    def _econ_cut(self, ws: Path, name: str) -> Path:
        src = ws / "src" / name
        src.parent.mkdir(parents=True, exist_ok=True)
        # economic vocabulary so the CUT-text fallback matches _ECON_VOCAB_RE
        src.write_text("contract C { uint256 fee; function setFee(uint256 f) external { fee = f; } }\n")
        return src

    def _sidecar(self, ws: Path, name: str, src: Path, killed=True, verdict="non-vacuous"):
        d = ws / ".auditooor" / "cross-function-coverage"
        d.mkdir(parents=True, exist_ok=True)
        (d / name).write_text(json.dumps({
            "schema": "auditooor.mutation_verify_coverage.v1",
            "verdict": verdict,
            "source_file": str(src),
            "function": name.replace(".json", ""),
            "baseline": {"status": "pass"},
            "mutant_results": [{"mutant_id": "m0", "killed": killed}],
        }))

    def test_standalone_v1_sidecars_counted(self):
        ws = Path(tempfile.mkdtemp())
        (ws / ".auditooor").mkdir(parents=True, exist_ok=True)
        for i in range(3):
            self._sidecar(ws, f"inv{i}.json", self._econ_cut(ws, f"C{i}.sol"))
        self.assertEqual(m._standalone_economic_sidecar_count(ws), 3)
        ok, detail, _ = m._check_economic_invariants(ws)
        self.assertTrue(ok, detail)

    def test_unkilled_sidecar_not_counted(self):
        ws = Path(tempfile.mkdtemp())
        (ws / ".auditooor").mkdir(parents=True, exist_ok=True)
        self._sidecar(ws, "inv.json", self._econ_cut(ws, "C.sol"), killed=False)
        self.assertEqual(m._standalone_economic_sidecar_count(ws), 0)

    def test_standalone_verified_count_folds_sidecars(self):
        # deep_evidence per_function_verified credit: a genuine mutation-verified
        # sidecar counts (killed); an un-killed one does not (no false-green).
        ws = Path(tempfile.mkdtemp())
        (ws / ".auditooor").mkdir(parents=True, exist_ok=True)
        self._sidecar(ws, "k1.json", self._econ_cut(ws, "K1.sol"), killed=True)
        self._sidecar(ws, "k2.json", self._econ_cut(ws, "K2.sol"), killed=True)
        self._sidecar(ws, "x.json", self._econ_cut(ws, "X.sol"), killed=False)
        self.assertEqual(m._standalone_verified_count(ws), 2)

    def test_aggregate_harness_field_name_read(self):
        # canonical registrar writes `harness` (+ source_file), not `harness_file`
        ws = Path(tempfile.mkdtemp())
        a = ws / ".auditooor"; a.mkdir(parents=True, exist_ok=True)
        src = self._econ_cut(ws, "Core.sol")
        hdir = ws / "test" / "h"; hdir.mkdir(parents=True, exist_ok=True)
        (hdir / "H.sol").write_text("function invariant_fee() external { assert(fee <= 1); }\n")
        (a / "mutation_verify_coverage.json").write_text(json.dumps({
            "counts": {"per_function_verified": 1},
            "per_function": [{
                "function": "setFee", "mutation_verified": True,
                "oracle_verdict": "non-vacuous", "killed": True,
                "harness": str(hdir), "source_file": str(src),
            }],
        }))
        self.assertGreaterEqual(m._corroborated_economic_count(ws), 1)


if __name__ == "__main__":
    unittest.main(verbosity=2)
