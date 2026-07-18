#!/usr/bin/env python3
"""Sibling test for the L37 closeout-honesty wiring.

Proves that ``tools/audit-completeness-check.py``'s honesty signal (signal r,
``hollow-not-genuinely-audited``) actually fires end-to-end:

  Case 1  a HOLLOW workspace (a fake-coverage / hollow-engines honesty fixture)
          -> the honesty signal reports ``fail-hollow-not-genuinely-audited``,
          that verdict is in the top-level ``failures`` list, and the overall
          verdict is NOT ``pass-audit-complete``.
  Case 2  the SAME hollow workspace + a valid
          ``.auditooor/audit_completeness_rebuttal.txt`` carrying
          ``l37-rebuttal: hollow-not-genuinely-audited: <reason>`` -> the
          honesty signal is rebutted (``ok-rebuttal``) and
          ``fail-hollow-not-genuinely-audited`` is NO LONGER in ``failures``.
          A bare ``l37-rebuttal: all: <reason>`` is exercised too.
  Case 3  a GENUINELY-AUDITED honesty fixture (real engine execution + no
          fake-coverage) -> the honesty signal PASSES and does not fire.
  Case 4  the ``audit-honesty-check.py`` tooling is absent / raises ->
          graceful degrade: the honesty signal WARN-passes and does NOT
          contribute ``fail-hollow-not-genuinely-audited`` to ``failures``
          (tooling-absence alone must never hard-fail L37).

The test does NOT modify the tool. Cases 1-3 exercise
``audit-completeness-check.py`` end-to-end via its real CLI against TMPDIR
fixtures (never a live workspace). Case 4 exercises the graceful-degrade path
both end-to-end (a tools-dir copy with the honesty tool removed) and in-process
(monkeypatching the module loader to None / to a raising stub).
"""
from __future__ import annotations

import importlib.util
import json
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

_REPO = Path(__file__).resolve().parents[2]
_TOOL = _REPO / "tools" / "audit-completeness-check.py"
_HONESTY_TOOL = _REPO / "tools" / "audit-honesty-check.py"
_HOLLOW_VERDICT = "fail-hollow-not-genuinely-audited"
_HONESTY_SIGNAL = "hollow-not-genuinely-audited"


def _load_acc_module():
    """Import audit-completeness-check.py with sys.modules registration.

    Registration before exec is required because the module uses @dataclass and
    Python 3.14's dataclass introspection resolves the owning module dict via
    sys.modules (the tool registers its own sibling loads the same way)."""
    spec = importlib.util.spec_from_file_location(
        "_acc_honesty_test_mod", _TOOL
    )
    mod = importlib.util.module_from_spec(spec)
    sys.modules["_acc_honesty_test_mod"] = mod
    spec.loader.exec_module(mod)
    return mod


def _mk_ws() -> Path:
    ws = Path(tempfile.mkdtemp(prefix="l37_honesty_"))
    (ws / ".auditooor").mkdir(parents=True, exist_ok=True)
    (ws / "src").mkdir(parents=True, exist_ok=True)
    # A trivial in-scope Solidity unit so the honesty gate detects lang=solidity.
    (ws / "src" / "X.sol").write_text("pragma solidity ^0.8.0;\ncontract X {}\n")
    return ws


def _write_json(p: Path, obj) -> None:
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(json.dumps(obj), encoding="utf-8")


def _make_hollow_ws() -> Path:
    """A workspace the honesty gate flags HOLLOW.

    The g15 coverage gate reports 100% (coverage_pct=1.0) but every covered
    unit is budget-skipped -> true coverage 0% -> ``fail-fake-coverage``. With
    no engine artifact, ``fail-hollow-engines`` also fires. Both are HARD
    hollow verdicts in _HONESTY_HARD_FAILS, so the L37 honesty signal must
    fire ``fail-hollow-not-genuinely-audited``."""
    ws = _mk_ws()
    _write_json(
        ws / ".auditooor" / "g15_hunt_coverage_gate_last_result.json",
        {
            "coverage_pct": 1.0,
            "total_units": 10,
            "covered": 10,
            "budget_skipped_units": [f"u{i}" for i in range(10)],
        },
    )
    return ws


def _make_genuine_ws() -> Path:
    """A workspace the honesty gate flags GENUINELY-AUDITED.

    A top-level Solidity engine artifact with status=ok -> real_execution=True.
    A g15 coverage gate file with coverage_pct=1.0 and no budget-skipped units ->
    gate_file_missing=False and true coverage=100%. No Setup.sol -> no mock-target.
    So honesty returns ``pass-genuinely-audited`` and the L37 honesty signal does
    not fire.

    NOTE (Fix 4 / r36-rebuttal: bugfix-inventory-claude-20260610 agent_pathspec.json):
    A g15 file is required. A workspace where engines ran but the coverage gate was
    never written now fires fail-no-coverage-gate (fail-closed). The old fixture had
    no g15 file and was asserting the OLD lenient behavior (a bug). Supply real
    coverage evidence so this fixture remains a genuine pass under the fail-closed gate.
    """
    # r36-rebuttal: bugfix-inventory-claude-20260610 agent_pathspec.json
    ws = _mk_ws()
    _write_json(ws / ".auditooor" / "halmos" / "artifact.json", {"status": "ok"})
    # Fix 4 requires a coverage gate file when engines genuinely ran (fail-closed).
    _write_json(
        ws / ".auditooor" / "g15_hunt_coverage_gate_last_result.json",
        {"coverage_pct": 1.0, "total_units": 1, "covered": 1, "budget_skipped_units": []},
    )
    # R81 requires a depth_certificate when the workspace looks audited.
    _write_json(
        ws / ".auditooor" / "depth_certificate.json",
        {"negative_space_ran": True, "sibling_diff_ran": True},
    )
    return ws


def _run_cli_json(ws: Path, *, tools_dir: Path | None = None) -> dict:
    """Run audit-completeness-check.py --json end-to-end and parse stdout.

    ``tools_dir`` lets case 4 point at a copied tools directory whose
    audit-honesty-check.py was removed (true end-to-end tooling-absence)."""
    tool = (tools_dir / "audit-completeness-check.py") if tools_dir else _TOOL
    cp = subprocess.run(
        [sys.executable, str(tool), str(ws), "--json"],
        capture_output=True,
        text=True,
    )
    if not cp.stdout.strip():
        raise AssertionError(
            f"no JSON on stdout (rc={cp.returncode}); stderr=\n{cp.stderr}"
        )
    return json.loads(cp.stdout)


def _honesty_signal(result: dict) -> dict:
    rows = [s for s in result["signals"] if s["signal"] == _HONESTY_SIGNAL]
    assert len(rows) == 1, f"expected exactly one honesty signal row, got {rows}"
    return rows[0]


class HollowFiresTest(unittest.TestCase):
    """Case 1: hollow workspace -> honesty signal fires the hollow verdict."""

    def setUp(self):
        self.ws = _make_hollow_ws()

    def tearDown(self):
        shutil.rmtree(self.ws, ignore_errors=True)

    def test_hollow_signal_fires(self):
        res = _run_cli_json(self.ws)
        sig = _honesty_signal(res)
        # The honesty signal itself reports the hollow verdict and is not ok.
        self.assertFalse(sig["ok"], f"honesty signal should be FAIL: {sig}")
        self.assertEqual(sig["verdict"], _HOLLOW_VERDICT)
        # The hollow verdict is carried into the top-level failures list.
        self.assertIn(_HOLLOW_VERDICT, res["failures"])
        # And the overall result is NOT a clean pass.
        self.assertNotEqual(res["verdict"], "pass-audit-complete")
        # The signal detail surfaces the underlying honesty hard-hollow fails.
        hard = sig["detail"].get("hard_hollow_fails") or []
        self.assertTrue(
            any(h.startswith("fail-") for h in hard),
            f"expected a HARD hollow fail in detail.hard_hollow_fails: {sig['detail']}",
        )
        self.assertIn("fail-fake-coverage", hard)


class RebuttalSilencesTest(unittest.TestCase):
    """Case 2: same hollow ws + l37-rebuttal -> honesty signal rebutted."""

    def setUp(self):
        self.ws = _make_hollow_ws()

    def tearDown(self):
        shutil.rmtree(self.ws, ignore_errors=True)

    def _baseline_fires(self):
        res = _run_cli_json(self.ws)
        self.assertIn(
            _HOLLOW_VERDICT,
            res["failures"],
            "precondition: hollow verdict must fire BEFORE the rebuttal is added",
        )

    def test_named_signal_rebuttal(self):
        self._baseline_fires()
        (self.ws / ".auditooor" / "audit_completeness_rebuttal.txt").write_text(
            "l37-rebuttal: hollow-not-genuinely-audited: greenfield ws, "
            "engine harnesses not built yet\n",
            encoding="utf-8",
        )
        res = _run_cli_json(self.ws)
        sig = _honesty_signal(res)
        self.assertTrue(sig["ok"], f"rebutted honesty signal should be ok: {sig}")
        self.assertEqual(sig["verdict"], "ok-rebuttal")
        # The hollow verdict must no longer contribute to failures.
        self.assertNotIn(_HOLLOW_VERDICT, res["failures"])
        # The rebuttal is recorded in the rebutted list.
        self.assertTrue(
            any(r.get("signal") == _HONESTY_SIGNAL for r in res["rebutted"]),
            f"honesty rebuttal should appear in result.rebutted: {res['rebutted']}",
        )

    def test_all_signal_rebuttal(self):
        self._baseline_fires()
        (self.ws / ".auditooor" / "audit_completeness_rebuttal.txt").write_text(
            "l37-rebuttal: all: operator-authorized N/A across the engagement\n",
            encoding="utf-8",
        )
        res = _run_cli_json(self.ws)
        sig = _honesty_signal(res)
        self.assertTrue(sig["ok"], f"all:-rebutted honesty signal should be ok: {sig}")
        self.assertEqual(sig["verdict"], "ok-rebuttal")
        self.assertNotIn(_HOLLOW_VERDICT, res["failures"])


class GenuineDoesNotFireTest(unittest.TestCase):
    """Case 3: genuinely-audited honesty fixture -> honesty signal passes."""

    def setUp(self):
        self.ws = _make_genuine_ws()

    def tearDown(self):
        shutil.rmtree(self.ws, ignore_errors=True)

    def test_genuine_signal_passes(self):
        res = _run_cli_json(self.ws)
        sig = _honesty_signal(res)
        self.assertTrue(sig["ok"], f"genuine-ws honesty signal should PASS: {sig}")
        self.assertEqual(sig["verdict"], "pass")
        self.assertNotIn(_HOLLOW_VERDICT, res["failures"])
        self.assertEqual(
            sig["detail"].get("honesty_verdict"), "pass-genuinely-audited"
        )


class ToolingAbsentGracefulTest(unittest.TestCase):
    """Case 4: honesty tooling absent / raises -> graceful WARN-pass."""

    def setUp(self):
        self.ws = _make_hollow_ws()  # hollow so a FAIL would be the un-graceful outcome

    def tearDown(self):
        shutil.rmtree(self.ws, ignore_errors=True)

    def test_end_to_end_tooling_removed(self):
        """Copy the tools dir, delete audit-honesty-check.py, run end-to-end.

        Even though the workspace is hollow, with the honesty tool absent the
        honesty signal must NOT contribute fail-hollow-not-genuinely-audited;
        it degrades to a WARN-pass (other signals may still fail - that is
        fine, this asserts the honesty signal does not HARD-fail on absence)."""
        tmp_tools = Path(tempfile.mkdtemp(prefix="l37_tools_"))
        try:
            dst = tmp_tools / "tools"
            shutil.copytree(_REPO / "tools", dst)
            removed = dst / "audit-honesty-check.py"
            self.assertTrue(removed.exists())
            removed.unlink()
            self.assertFalse(removed.exists())
            res = _run_cli_json(self.ws, tools_dir=dst)
            sig = _honesty_signal(res)
            self.assertTrue(
                sig["ok"],
                f"absent honesty tool must WARN-pass, not hard-fail: {sig}",
            )
            self.assertNotEqual(sig["verdict"], _HOLLOW_VERDICT)
            self.assertNotIn(_HOLLOW_VERDICT, res["failures"])
            self.assertEqual(sig["detail"].get("honesty_tool"), "unavailable")
        finally:
            shutil.rmtree(tmp_tools, ignore_errors=True)

    def test_in_process_loader_returns_none(self):
        """Monkeypatch the loader to None -> check_honesty WARN-passes."""
        mod = _load_acc_module()
        orig = mod._load_audit_honesty_module
        mod._load_audit_honesty_module = lambda: None
        try:
            sig = mod.check_honesty(self.ws)
        finally:
            mod._load_audit_honesty_module = orig
        self.assertTrue(sig.ok, f"None-loader should WARN-pass: {sig}")
        self.assertEqual(sig.detail.get("honesty_tool"), "unavailable")

    def test_in_process_check_raises(self):
        """Monkeypatch a honesty module whose check() raises -> WARN-pass."""
        mod = _load_acc_module()

        class _Raising:
            def _detect_lang(self, ws):  # noqa: D401 - stub
                return "solidity"

            def check(self, ws, lang):
                raise RuntimeError("boom")

        orig = mod._load_audit_honesty_module
        mod._load_audit_honesty_module = lambda: _Raising()
        try:
            sig = mod.check_honesty(self.ws)
        finally:
            mod._load_audit_honesty_module = orig
        self.assertTrue(sig.ok, f"raising honesty check should WARN-pass: {sig}")
        self.assertIn("honesty_error", sig.detail)


if __name__ == "__main__":  # pragma: no cover
    unittest.main(verbosity=2)
