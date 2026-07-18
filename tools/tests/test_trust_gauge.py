#!/usr/bin/env python3
"""Hermetic tests for tools/trust-gauge.py (PR #127).

Tests inject fake runners into main() / assemble_report() so no real
subprocess is launched.  Each fixture exercises a verdict state per the
Codex-revised plan (docs/PLAN_TRUST_GAUGE.md):

  - READY    : all hard blockers pass + all soft signals green   (exit 0)
  - REVIEW   : all hard blockers pass + ≥1 soft signal yellow/red (exit 1)
  - BLOCK    : Check #25 fails                                    (exit 2)
  - BLOCK    : Check #26 fails                                    (exit 2)
  - BLOCK    : scope-reasoner block-mode fails                    (exit 2)
  - tooling-error: dependency reports errno >= 64                 (exit ≥64)
  - --bundle ⇒ paste-ready (READY) / review-manifest (REVIEW & BLOCK)
  - --include-scope-verdict toggles scope boilerplate inclusion
"""
from __future__ import annotations

import io
import json
import os
import sys
import tempfile
import textwrap
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "tools"))

# Tool path uses dash; load via importlib spec.
import importlib.util

_spec = importlib.util.spec_from_file_location(
    "trust_gauge", ROOT / "tools" / "trust-gauge.py"
)
trust_gauge = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(trust_gauge)  # type: ignore[union-attr]


# --------------------------------------------------------------------------
# fake-runner factories
# --------------------------------------------------------------------------

def _make_pre_submit(check25="pass", check26="pass", check23="pass", returncode=0):
    def runner(draft, log_dir):
        log_dir.mkdir(parents=True, exist_ok=True)
        log = log_dir / "pre-submit.log"
        log.write_text(f"# fake pre-submit log: 25={check25} 26={check26}\n")
        return {
            "returncode": returncode, "stdout": "", "stderr": "", "log": log,
            "check_25": check25, "check_26": check26, "check_23": check23,
        }
    return runner


def _make_scope(verdict="pass", risk_level="none"):
    def runner(draft, log_dir):
        log_dir.mkdir(parents=True, exist_ok=True)
        log = log_dir / "scope-reasoner.log"
        log.write_text(f"# fake scope log: verdict={verdict}\n")
        return {
            "returncode": 0, "stdout": "{}", "stderr": "", "log": log,
            "risk_level": risk_level, "verdict": verdict,
        }
    return runner


def _make_originality(verdict="green"):
    def runner(draft, log_dir):
        log_dir.mkdir(parents=True, exist_ok=True)
        log = log_dir / "originality-grep.log"
        log.write_text(f"# fake originality log: verdict={verdict}\n")
        return {"verdict": verdict, "returncode": 1, "stdout": "", "stderr": "",
                "log": log, "keyword": "fake"}
    return runner


def _make_variant(verdict="green"):
    def runner(draft, workspace, log_dir):
        log_dir.mkdir(parents=True, exist_ok=True)
        log = log_dir / "variant-detector.log"
        log.write_text(f"# fake variant log: verdict={verdict}\n")
        return {"verdict": verdict, "returncode": 0, "stdout": "{}", "stderr": "",
                "log": log, "workspace": str(workspace) if workspace else "fake"}
    return runner


def _make_pattern(verdict="green"):
    def runner(log_dir):
        log_dir.mkdir(parents=True, exist_ok=True)
        log = log_dir / "pattern-dedupe.log"
        log.write_text(f"# fake pattern-dedupe log: verdict={verdict}\n")
        return {"verdict": verdict, "returncode": 0, "stdout": "", "stderr": "",
                "log": log}
    return runner


def _make_severity(verdict="green"):
    def runner(draft):
        return {"verdict": verdict,
                "has_rubric_citation": verdict == "green",
                "has_dollar_impact":   verdict == "green",
                "has_tier_example":    verdict == "green"}
    return runner


def _make_tooling_error_pre_submit():
    def runner(draft, log_dir):
        return {"error": "missing tool: pre-submit-check.sh",
                "errno": trust_gauge.EXIT_TOOL_MISSING}
    return runner


# --------------------------------------------------------------------------
# helpers
# --------------------------------------------------------------------------

def _draft(tmp: Path, *, with_severity=True) -> Path:
    p = tmp / "draft.md"
    body = textwrap.dedent("""
        # Sample finding title

        ## Summary
        Some text.

        ## Severity
        Medium per Immunefi rubric. Impact: $5,000 USD.

        Cited tier example: see POLY-198 for the gold standard.

        ## PoC
        ```sol
        // mock-free
        ```
    """).strip() + "\n"
    if not with_severity:
        body = "# Sample finding title\n\nbody only.\n"
    p.write_text(body)
    return p


def _all_green_runners():
    return {
        "pre_submit":     _make_pre_submit(),
        "scope_reasoner": _make_scope(),
        "originality":    _make_originality("green"),
        "variant":        _make_variant("green"),
        "pattern_dedupe": _make_pattern("green"),
        "severity":       _make_severity("green"),
    }


def _invoke(argv, runners):
    """Run trust_gauge.main with stdout/stderr captured."""
    out = io.StringIO()
    err = io.StringIO()
    with redirect_stdout(out), redirect_stderr(err):
        rc = trust_gauge.main(argv, runners=runners)
    return rc, out.getvalue(), err.getvalue()


# --------------------------------------------------------------------------
# tests
# --------------------------------------------------------------------------

class TrustGaugeVerdictMatrix(unittest.TestCase):
    def test_ready_all_green_exits_zero_and_paste_ready_with_bundle(self):
        with tempfile.TemporaryDirectory() as tmp:
            tmp = Path(tmp)
            draft = _draft(tmp)
            out_dir = tmp / "out"
            rc, stdout, _ = _invoke(
                [str(draft), "--bundle", "--out-dir", str(out_dir),
                 "--json-only"],
                _all_green_runners(),
            )
            self.assertEqual(rc, 0, msg=f"expected READY exit 0, got {rc}\n{stdout}")
            payload = json.loads(stdout)
            self.assertEqual(payload["verdict"], "READY")
            self.assertTrue(payload["raw_outputs_preserved"])
            self.assertTrue((out_dir / "paste-ready.txt").exists())
            self.assertFalse((out_dir / "review-manifest.txt").exists())
            # No scope boilerplate without flag.
            paste = (out_dir / "paste-ready.txt").read_text()
            self.assertNotIn("Internal scope-reasoner verdict", paste)
            self.assertIn("trust-gauge verdict: READY", paste)
            # Hard blockers all pass; soft signals all green.
            self.assertTrue(
                all(v == "pass" for v in payload["hard_blockers"].values()))
            self.assertTrue(
                all(v == "green" for v in payload["soft_signals"].values()))
            # Log paths preserved.
            for key, p in payload["log_paths"].items():
                self.assertIsNotNone(p, msg=f"log path missing: {key}")
                self.assertTrue(Path(p).exists(),
                                msg=f"log file missing on disk: {p}")

    def test_review_soft_signal_yellow_exits_one_and_review_manifest(self):
        with tempfile.TemporaryDirectory() as tmp:
            tmp = Path(tmp)
            draft = _draft(tmp)
            out_dir = tmp / "out"
            runners = _all_green_runners()
            runners["originality"] = _make_originality("yellow")
            rc, stdout, _ = _invoke(
                [str(draft), "--bundle", "--out-dir", str(out_dir),
                 "--json-only"],
                runners,
            )
            self.assertEqual(rc, 1)
            payload = json.loads(stdout)
            self.assertEqual(payload["verdict"], "REVIEW")
            self.assertEqual(payload["soft_signals"]["originality_grep"], "yellow")
            # Hard blockers all pass.
            self.assertTrue(
                all(v == "pass" for v in payload["hard_blockers"].values()))
            self.assertTrue((out_dir / "review-manifest.txt").exists())
            self.assertFalse((out_dir / "paste-ready.txt").exists())
            manifest = (out_dir / "review-manifest.txt").read_text()
            self.assertIn("verdict: REVIEW", manifest)
            self.assertIn("originality_grep", manifest)
            self.assertIn("NOT paste-ready", manifest)

    def test_block_check25_fails_exits_two(self):
        with tempfile.TemporaryDirectory() as tmp:
            tmp = Path(tmp)
            draft = _draft(tmp)
            out_dir = tmp / "out"
            runners = _all_green_runners()
            runners["pre_submit"] = _make_pre_submit(check25="fail",
                                                     returncode=1)
            rc, stdout, _ = _invoke(
                [str(draft), "--bundle", "--out-dir", str(out_dir),
                 "--json-only"],
                runners,
            )
            self.assertEqual(rc, 2)
            payload = json.loads(stdout)
            self.assertEqual(payload["verdict"], "BLOCK")
            self.assertEqual(payload["hard_blockers"]["check_25_in_scope"],
                             "fail")
            self.assertEqual(payload["hard_blockers"]["check_26_poc_integrity"],
                             "pass")
            self.assertTrue((out_dir / "review-manifest.txt").exists())
            self.assertFalse((out_dir / "paste-ready.txt").exists())
            manifest = (out_dir / "review-manifest.txt").read_text()
            self.assertIn("BLOCK", manifest)
            self.assertIn("check_25_in_scope", manifest)

    def test_block_check26_fails_exits_two(self):
        with tempfile.TemporaryDirectory() as tmp:
            tmp = Path(tmp)
            draft = _draft(tmp)
            out_dir = tmp / "out"
            runners = _all_green_runners()
            runners["pre_submit"] = _make_pre_submit(check26="fail",
                                                     returncode=1)
            rc, stdout, _ = _invoke(
                [str(draft), "--bundle", "--out-dir", str(out_dir),
                 "--json-only"],
                runners,
            )
            self.assertEqual(rc, 2)
            payload = json.loads(stdout)
            self.assertEqual(payload["verdict"], "BLOCK")
            self.assertEqual(
                payload["hard_blockers"]["check_26_poc_integrity"], "fail")
            manifest = (out_dir / "review-manifest.txt").read_text()
            self.assertIn("check_26_poc_integrity", manifest)

    def test_block_scope_reasoner_block_mode_fails_exits_two(self):
        with tempfile.TemporaryDirectory() as tmp:
            tmp = Path(tmp)
            draft = _draft(tmp)
            out_dir = tmp / "out"
            runners = _all_green_runners()
            runners["scope_reasoner"] = _make_scope(verdict="fail",
                                                    risk_level="likely-OOS")
            rc, stdout, _ = _invoke(
                [str(draft), "--bundle", "--out-dir", str(out_dir),
                 "--json-only"],
                runners,
            )
            self.assertEqual(rc, 2)
            payload = json.loads(stdout)
            self.assertEqual(payload["verdict"], "BLOCK")
            self.assertEqual(
                payload["hard_blockers"]["scope_reasoner_block_mode"], "fail")

    def test_block_does_not_upgrade_when_soft_signals_green(self):
        """Codex item #2 — Stage A failures BLOCK regardless of Stage B."""
        with tempfile.TemporaryDirectory() as tmp:
            tmp = Path(tmp)
            draft = _draft(tmp)
            out_dir = tmp / "out"
            runners = _all_green_runners()
            runners["pre_submit"] = _make_pre_submit(check25="fail",
                                                     returncode=1)
            # All Stage B green → must NOT upgrade away from BLOCK.
            rc, stdout, _ = _invoke(
                [str(draft), "--bundle", "--out-dir", str(out_dir),
                 "--json-only"],
                runners,
            )
            self.assertEqual(rc, 2)
            payload = json.loads(stdout)
            self.assertEqual(payload["verdict"], "BLOCK")

    def test_pre_submit_nonzero_returncode_forces_BLOCK_even_with_25_26_pass(self):
        """Codex 15:52Z blocker (PR #127): non-zero pre-submit returncode is a
        hard blocker even when Check #25 + #26 + scope-reasoner all pass and
        every soft signal is green.

        Repro shape from Codex's comment:
          - pre-submit returncode=1 (some other check, e.g. live-proof, failed)
          - Check #25 parsed as pass
          - Check #26 parsed as pass
          - scope-reasoner: pass (risk_level=none)
          - originality / variant / pattern_dedupe / severity: all green

        Pre-fix: verdict was REVIEW (or could even reach READY).
        Post-fix: verdict MUST be BLOCK with `pre_submit_all_checks` in the
        hard_blockers list set to "fail".
        """
        with tempfile.TemporaryDirectory() as tmp:
            tmp = Path(tmp)
            draft = _draft(tmp)
            out_dir = tmp / "out"
            runners = _all_green_runners()
            # pre-submit returns rc=1 but reports Check #25 + #26 individually pass.
            runners["pre_submit"] = _make_pre_submit(
                check25="pass", check26="pass", check23="pass", returncode=1,
            )
            rc, stdout, _ = _invoke(
                [str(draft), "--bundle", "--out-dir", str(out_dir),
                 "--json-only"],
                runners,
            )
            self.assertEqual(rc, 2,
                             msg=f"expected BLOCK (exit 2), got {rc}\n{stdout}")
            payload = json.loads(stdout)
            self.assertEqual(payload["verdict"], "BLOCK")
            # Aggregate blocker surfaced by name.
            self.assertIn("pre_submit_all_checks", payload["hard_blockers"])
            self.assertEqual(
                payload["hard_blockers"]["pre_submit_all_checks"], "fail")
            # Individual checks still report their parsed pass state — the
            # aggregate gate is what triggers the BLOCK.
            self.assertEqual(
                payload["hard_blockers"]["check_25_in_scope"], "pass")
            self.assertEqual(
                payload["hard_blockers"]["check_26_poc_integrity"], "pass")
            self.assertEqual(
                payload["hard_blockers"]["scope_reasoner_block_mode"], "pass")
            # Soft signals are all still green (proves they did NOT upgrade).
            self.assertTrue(
                all(v == "green" for v in payload["soft_signals"].values()))
            # Diagnostic context: returncode + reason in details.
            self.assertEqual(payload["details"]["pre_submit_returncode"], 1)
            self.assertIn("returncode=1",
                          payload["details"]["pre_submit_aggregate_reason"])
            # Manifest names the aggregate blocker for the operator.
            manifest = (out_dir / "review-manifest.txt").read_text()
            self.assertIn("pre_submit_all_checks", manifest)
            self.assertIn("BLOCK", manifest)

    def test_tooling_error_returns_high_exit(self):
        with tempfile.TemporaryDirectory() as tmp:
            tmp = Path(tmp)
            draft = _draft(tmp)
            out_dir = tmp / "out"
            runners = _all_green_runners()
            runners["pre_submit"] = _make_tooling_error_pre_submit()
            rc, stdout, _ = _invoke(
                [str(draft), "--out-dir", str(out_dir), "--json-only"],
                runners,
            )
            self.assertGreaterEqual(rc, 64)
            payload = json.loads(stdout)
            self.assertTrue(payload.get("_tooling_error"))
            self.assertEqual(payload.get("_errno"), trust_gauge.EXIT_TOOL_MISSING)

    def test_draft_missing_returns_tooling_error(self):
        with tempfile.TemporaryDirectory() as tmp:
            out_dir = Path(tmp) / "out"
            rc, stdout, stderr = _invoke(
                [str(Path(tmp) / "no-such-draft.md"),
                 "--out-dir", str(out_dir), "--json-only"],
                _all_green_runners(),
            )
            self.assertGreaterEqual(rc, 64)
            self.assertIn("draft not found", stderr)


class TrustGaugeBundleSemantics(unittest.TestCase):
    def test_no_bundle_flag_emits_nothing_to_disk(self):
        with tempfile.TemporaryDirectory() as tmp:
            tmp = Path(tmp)
            draft = _draft(tmp)
            out_dir = tmp / "out"
            rc, _, _ = _invoke(
                [str(draft), "--out-dir", str(out_dir), "--json-only"],
                _all_green_runners(),
            )
            self.assertEqual(rc, 0)
            self.assertFalse((out_dir / "paste-ready.txt").exists())
            self.assertFalse((out_dir / "review-manifest.txt").exists())

    def test_bundle_with_review_emits_manifest_not_paste_ready(self):
        with tempfile.TemporaryDirectory() as tmp:
            tmp = Path(tmp)
            draft = _draft(tmp)
            out_dir = tmp / "out"
            runners = _all_green_runners()
            runners["variant"] = _make_variant("red")
            rc, _, _ = _invoke(
                [str(draft), "--bundle", "--out-dir", str(out_dir),
                 "--json-only"],
                runners,
            )
            self.assertEqual(rc, 1)
            self.assertFalse((out_dir / "paste-ready.txt").exists())
            self.assertTrue((out_dir / "review-manifest.txt").exists())

    def test_bundle_with_block_emits_manifest_not_paste_ready(self):
        with tempfile.TemporaryDirectory() as tmp:
            tmp = Path(tmp)
            draft = _draft(tmp)
            out_dir = tmp / "out"
            runners = _all_green_runners()
            runners["pre_submit"] = _make_pre_submit(check25="fail",
                                                     returncode=1)
            rc, _, _ = _invoke(
                [str(draft), "--bundle", "--out-dir", str(out_dir),
                 "--json-only"],
                runners,
            )
            self.assertEqual(rc, 2)
            self.assertFalse((out_dir / "paste-ready.txt").exists())
            self.assertTrue((out_dir / "review-manifest.txt").exists())

    def test_include_scope_verdict_toggles_boilerplate(self):
        with tempfile.TemporaryDirectory() as tmp:
            tmp = Path(tmp)
            draft = _draft(tmp)

            # Without flag — no boilerplate.
            out_dir1 = tmp / "out1"
            rc1, _, _ = _invoke(
                [str(draft), "--bundle", "--out-dir", str(out_dir1),
                 "--json-only"],
                _all_green_runners(),
            )
            self.assertEqual(rc1, 0)
            paste1 = (out_dir1 / "paste-ready.txt").read_text()
            self.assertNotIn("Internal scope-reasoner verdict", paste1)

            # With flag — boilerplate present.
            out_dir2 = tmp / "out2"
            rc2, _, _ = _invoke(
                [str(draft), "--bundle", "--out-dir", str(out_dir2),
                 "--include-scope-verdict", "--json-only"],
                _all_green_runners(),
            )
            self.assertEqual(rc2, 0)
            paste2 = (out_dir2 / "paste-ready.txt").read_text()
            self.assertIn("Internal scope-reasoner verdict", paste2)


class TrustGaugeUnitFunctions(unittest.TestCase):
    def test_compute_verdict_short_circuits_on_hard(self):
        block = trust_gauge.compute_verdict(
            {"a": "fail", "b": "pass", "c": "pass"},
            {"x": "green", "y": "green", "z": "green", "w": "green"},
        )
        self.assertEqual(block, "BLOCK")

    def test_compute_verdict_review_on_yellow(self):
        review = trust_gauge.compute_verdict(
            {"a": "pass", "b": "pass", "c": "pass"},
            {"x": "yellow", "y": "green", "z": "green", "w": "green"},
        )
        self.assertEqual(review, "REVIEW")

    def test_compute_verdict_ready_when_all_green(self):
        ready = trust_gauge.compute_verdict(
            {"a": "pass", "b": "pass", "c": "pass"},
            {"x": "green", "y": "green", "z": "green", "w": "green"},
        )
        self.assertEqual(ready, "READY")

    def test_parse_pre_submit_output_extracts_check_verdicts(self):
        sample = textwrap.dedent("""
              ✅ 23. scope-reasoner: in_scope
              ❌ 25. oos-prerequisite-root-cause-missing: foo
              ✅ 26. Mock-PoC contamination gate: bar
        """).strip()
        verdicts = trust_gauge.parse_pre_submit_output(sample)
        self.assertEqual(verdicts.get(23), "pass")
        self.assertEqual(verdicts.get(25), "fail")
        self.assertEqual(verdicts.get(26), "pass")

    def test_severity_defensibility_green_yellow_red(self):
        with tempfile.TemporaryDirectory() as tmp:
            tmp = Path(tmp)

            # All three signals → green.
            green_draft = tmp / "green.md"
            green_draft.write_text(
                "Severity per Immunefi rubric: Medium. Impact: $50,000 USD.\n"
                "See POLY-198 for cited tier example.\n"
            )
            self.assertEqual(
                trust_gauge.assess_severity_defensibility(green_draft)["verdict"],
                "green")

            # One signal → yellow.
            yellow_draft = tmp / "yellow.md"
            yellow_draft.write_text("Impact: $1,000 of damages.\n")
            self.assertEqual(
                trust_gauge.assess_severity_defensibility(yellow_draft)["verdict"],
                "yellow")

            # Zero signals → red.
            red_draft = tmp / "red.md"
            red_draft.write_text("Plain prose with no qualifying terms.\n")
            self.assertEqual(
                trust_gauge.assess_severity_defensibility(red_draft)["verdict"],
                "red")


if __name__ == "__main__":
    unittest.main()
