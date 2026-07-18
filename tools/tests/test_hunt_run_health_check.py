"""Tests for tools/hunt-run-health-check.py (HUNT-RUN-HEALTH detector).

Covers:
  (a) all-rate-limited fixture -> verdict failed-run / needs_re_hunt
  (b) real-anchor fixture -> verdict healthy
  (c) success_fraction computed correctly
  (d) classification + verdict logic is generic (no workspace literal)
"""
from __future__ import annotations

import importlib.util
import json
import shutil
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
TOOL = ROOT / "tools" / "hunt-run-health-check.py"
FIXTURES = Path(__file__).resolve().parent / "fixtures" / "hunt_run_health"


def _load_module():
    spec = importlib.util.spec_from_file_location("hunt_run_health_check", TOOL)
    mod = importlib.util.module_from_spec(spec)
    assert spec and spec.loader
    spec.loader.exec_module(mod)
    return mod


HRH = _load_module()


class TestClassifyRecord(unittest.TestCase):
    def test_rate_limited_failed(self):
        rec = {"status": "failed", "error": "retry-max-exhausted: rate-limited",
               "result": None}
        self.assertEqual(HRH.classify_record(rec)[0], "rate_limited")

    def test_timeout_classified_rate_limited(self):
        rec = {"status": "failed", "error": "connection timeout", "result": None}
        self.assertEqual(HRH.classify_record(rec)[0], "rate_limited")

    def test_plain_failed_not_rate_limited(self):
        rec = {"status": "failed", "error": "assertion error in parser",
               "result": None}
        self.assertEqual(HRH.classify_record(rec)[0], "failed")

    def test_auth_failed_halted_is_never_ran_not_empty(self):
        # strata 2026-07-01: a keyless mimo/deepseek dispatch halts with
        # error="auth-failed" and result=null. The model NEVER ran, so it must
        # bucket as rate_limited (never-ran), NOT "empty" (ran-but-anchored-
        # nothing) - otherwise the record-based success_fraction reads as a
        # coverage gap when the surface was simply never dispatched.
        rec = {"status": "halted", "error": "auth-failed", "result": None,
               "provider": "mimo",
               "function_anchor": {"file": "src/contracts/Tranche.sol:267",
                                   "fn": "Tranche._deposit"}}
        self.assertEqual(HRH.classify_record(rec)[0], "rate_limited")

    def test_no_api_key_and_unauthorized_are_never_ran(self):
        for err in ("no-api-key", "401 Unauthorized", "missing api key",
                    "invalid api key", "forbidden"):
            rec = {"status": "halted", "error": err, "result": None}
            self.assertEqual(HRH.classify_record(rec)[0], "rate_limited",
                             msg=f"error={err!r} should bucket as never-ran")

    def test_genuine_empty_still_empty_not_masked(self):
        # a record that RAN (no infra error) but produced no anchor stays empty -
        # the infra-abort widening must not swallow a genuine ran-but-empty run.
        rec = {"status": "ok", "error": "", "result": {"note": "no finding"}}
        self.assertEqual(HRH.classify_record(rec)[0], "empty")

    def test_ok_explicit_no_is_engaged_clean(self):
        # status ok, applies_to_target=no (the dydx "299" shape): the model RAN
        # and explicitly DECLINED to anchor. This is an engaged-clean record
        # (trustworthy coverage on a clean target), NOT a silent "empty" - so a
        # fully-executed 0-finding hunt is not branded failed-run. Generic-fix
        # anchor: monero-oxide STRICT failed-run from 1887 honest "no" verdicts.
        rec = {
            "status": "ok",
            "error": None,
            "function_anchor": {"file": "?", "fn": "?"},
            "result": '```json\n{"applies_to_target": "no", "file_line": "NA"}\n```',
        }
        self.assertEqual(HRH.classify_record(rec)[0], "engaged")

    def test_ok_with_real_function_anchor_is_success(self):
        rec = {
            "status": "ok",
            "error": None,
            "function_anchor": {"file": "src/Vault.sol", "fn": "withdraw"},
            "result": '```json\n{"applies_to_target": "yes"}\n```',
        }
        klass, fref = HRH.classify_record(rec)
        self.assertEqual(klass, "success")
        self.assertEqual(fref, "src/Vault.sol")

    def test_ok_with_real_file_line_in_payload_is_success(self):
        rec = {
            "status": "ok",
            "error": None,
            "result": '```json\n{"applies_to_target": "yes", "file_line": "src/X.sol:L42"}\n```',
        }
        klass, fref = HRH.classify_record(rec)
        self.assertEqual(klass, "success")
        self.assertEqual(fref, "src/X.sol:L42")

    def test_conceptual_anchor_rejected(self):
        rec = {
            "status": "ok",
            "result": '```json\n{"applies_to_target": "yes", "file_line": "N/A conceptual pattern"}\n```',
        }
        self.assertEqual(HRH.classify_record(rec)[0], "empty")


class TestVerdict(unittest.TestCase):
    def test_failed_run(self):
        # many records, ~0 success
        self.assertEqual(HRH.verdict_for(total=300, success=2), "failed-run")

    def test_healthy(self):
        self.assertEqual(HRH.verdict_for(total=100, success=80), "healthy")

    def test_degraded(self):
        self.assertEqual(HRH.verdict_for(total=100, success=20), "degraded")

    def test_small_zero_is_insufficient_not_failed(self):
        # below FAILED_RUN_MIN_RECORDS we do not condemn
        self.assertEqual(HRH.verdict_for(total=5, success=0), "insufficient-data")

    def test_no_records(self):
        self.assertEqual(HRH.verdict_for(total=0, success=0), "no-records")


class TestBuildReportFromFixtures(unittest.TestCase):
    def _derived_with(self, ws_name: str, fixture_subdir: str, tmp: Path) -> Path:
        """Copy a fixture dir into a temp derived-root under a
        workspace-named mimo_harness dir so dir-discovery exercises generically."""
        derived = tmp / "derived"
        derived.mkdir()
        dst = derived / f"mimo_harness_{ws_name}"
        shutil.copytree(FIXTURES / fixture_subdir, dst)
        return derived

    def test_all_rate_limited_fixture_failed_run(self):
        import tempfile
        with tempfile.TemporaryDirectory() as td:
            tmp = Path(td)
            derived = self._derived_with("fakewsone", "all_rate_limited", tmp)
            rep = HRH.build_report(derived, "fakewsone", "/audits/fakewsone")
            self.assertEqual(rep["verdict"], "failed-run")
            self.assertTrue(rep["needs_re_hunt"])
            self.assertEqual(rep["success"], 0)
            self.assertEqual(rep["rate_limited"], 25)
            self.assertEqual(rep["total_records"], 25)
            self.assertEqual(rep["success_fraction"], 0.0)
            self.assertEqual(rep["distinct_anchored_files"], 0)

    def test_healthy_fixture(self):
        import tempfile
        with tempfile.TemporaryDirectory() as td:
            tmp = Path(td)
            derived = self._derived_with("fakewstwo", "healthy", tmp)
            rep = HRH.build_report(derived, "fakewstwo", "/audits/fakewstwo")
            self.assertEqual(rep["verdict"], "healthy")
            self.assertFalse(rep["needs_re_hunt"])
            self.assertEqual(rep["success"], 25)
            self.assertEqual(rep["rate_limited"], 0)
            # success_fraction computed correctly: 25/25 = 1.0
            self.assertEqual(rep["success_fraction"], 1.0)
            # distinct anchored files: all 25 share src/Vault.sol -> 1 distinct
            self.assertEqual(rep["distinct_anchored_files"], 1)

    def test_success_fraction_math_mixed(self):
        import tempfile
        with tempfile.TemporaryDirectory() as td:
            tmp = Path(td)
            derived = tmp / "derived"
            derived.mkdir()
            dst = derived / "mimo_harness_mixedws"
            dst.mkdir()
            # 30 healthy + 10 rate-limited -> frac 30/40 = 0.75 -> healthy
            for i, rec in enumerate(
                [json.loads((FIXTURES / "healthy" / f"rec_{j:04d}.json").read_text())
                 for j in range(25)]
                + [json.loads((FIXTURES / "all_rate_limited" / f"rec_{j:04d}.json").read_text())
                   for j in range(10)]
            ):
                (dst / f"r_{i:04d}.json").write_text(json.dumps(rec))
            rep = HRH.build_report(derived, "mixedws", "/audits/mixedws")
            self.assertEqual(rep["total_records"], 35)
            self.assertEqual(rep["success"], 25)
            self.assertEqual(rep["rate_limited"], 10)
            self.assertEqual(rep["success_fraction"], round(25 / 35, 4))
            self.assertEqual(rep["verdict"], "healthy")

    def test_report_is_schema_versioned(self):
        import tempfile
        with tempfile.TemporaryDirectory() as td:
            tmp = Path(td)
            derived = self._derived_with("schemaws", "healthy", tmp)
            rep = HRH.build_report(derived, "schemaws", "/audits/schemaws")
            self.assertEqual(rep["schema"], "auditooor.hunt_run_health.v1")
            self.assertIn("context_pack_id", rep)
            self.assertIn("context_pack_hash", rep)


class TestGenericNoWorkspaceLiteral(unittest.TestCase):
    def test_no_hardcoded_workspace_in_logic(self):
        # The tool must not special-case known workspaces in its logic.
        src = TOOL.read_text(encoding="utf-8")
        # docstring may mention dydx as the motivating anchor; logic must not.
        # Split off the module docstring (between the first pair of triple-quotes).
        body = src.split('"""', 2)[-1] if src.count('"""') >= 2 else src
        for ws in ("dydx", "hyperbridge", "morpho", "near"):
            self.assertNotIn(
                f'"{ws}"', body,
                f"workspace literal {ws!r} must not appear in tool logic",
            )


if __name__ == "__main__":
    unittest.main()


class TestPerUnitTrustRedundantFailedDispatches(unittest.TestCase):
    """Strata 2026-07-01: trust must be per-UNIT, not per-record. A REDUNDANT
    failed/empty dispatch run (dead provider halted on a missing API key) over
    functions ANOTHER provider already hunted with a real verdict must NOT drag
    trust down. 318 halted-mimo records over 135 functions all also carrying a
    real Sonnet verdict => per-record ran_frac=0.18 (degraded), per-unit=1.0
    (healthy). False-green-safe: a function with ONLY empty/failed records stays
    uncredited."""

    def _rec(self, fn, klass):
        # klass in {success, engaged, empty, halted}
        base = {"function_anchor": {"file": f"src/A.sol", "fn": fn}}
        if klass == "success":
            base["status"] = "ok"
            base["result"] = json.dumps({"applies_to_target": "yes", "file_line": "src/A.sol:10"})
        elif klass == "engaged":
            base["status"] = "ok"
            base["result"] = json.dumps({"applies_to_target": "no"})
        elif klass == "empty":
            base["status"] = "ok"; base["result"] = "{}"
        elif klass == "halted":
            base["status"] = "halted"; base["result"] = "{}"
        elif klass == "failed":
            base["status"] = "failed"; base["result"] = None
        return base

    def _mk(self, tmp, records):
        d = tmp / ".auditooor" / "hunt_findings_sidecars"; d.mkdir(parents=True)
        for i, r in enumerate(records):
            (d / f"r_{i:04d}.json").write_text(json.dumps(r))
        return tmp

    def test_redundant_halted_records_do_not_condemn_hunted_units(self):
        import tempfile
        tmp = Path(tempfile.mkdtemp())
        # 30 functions each with 1 real engaged verdict + 10 redundant halted dupes
        recs = []
        for f in range(30):
            recs.append(self._rec(f"fn{f}", "engaged"))
            recs.extend(self._rec(f"fn{f}", "halted") for _ in range(10))
        self._mk(tmp, recs)
        rep = HRH.build_report(tmp, tmp.name, str(tmp))
        # record-based would be ~30/330 = 0.09 (degraded); per-unit = 30/30 = 1.0
        self.assertEqual(rep["distinct_units"], 30)
        self.assertEqual(rep["units_engaged"], 30)
        self.assertIn(rep["verdict"], ("healthy", "healthy-clean"))

    def test_genuinely_unhunted_units_stay_uncredited(self):
        import tempfile
        tmp = Path(tempfile.mkdtemp())
        # 120 functions with ONLY halted/empty records - no real verdict anywhere
        recs = []
        for f in range(120):
            recs.extend(self._rec(f"fn{f}", "failed") for _ in range(3))
        self._mk(tmp, recs)
        rep = HRH.build_report(tmp, tmp.name, str(tmp))
        self.assertEqual(rep["units_engaged"], 0, "no real verdict -> 0 engaged units")
        self.assertNotIn(rep["verdict"], ("healthy", "healthy-clean"),
                         "a fully-unhunted surface must NOT read healthy")


if __name__ == "__main__":
    unittest.main(verbosity=2)
