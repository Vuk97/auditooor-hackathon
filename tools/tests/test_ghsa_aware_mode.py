#!/usr/bin/env python3
# r36-rebuttal: lane TASK-B-GHSA-AWARE-MODE registered in .auditooor/agent_pathspec.json
"""
Tests for the GHSA-AWARE MODE of tools/pre-submit-check.sh and its helper tools
(ghsa-mode-detect.py, ghsa-requirements-check.py, ghsa-poc-inline-check.py).

Covers:
  - GHSA_MODE detection (marker / sibling / structural / negative)
  - skip-set: #11/#31/#41/#42/#68 SKIPPED, #42b/#43b GHSA equivalents enforced
  - #72 global corpus tier-debt decoupled to WARN (per-draft rc not blocked)
  - Cantina + HackenProof non-regression (gates behave exactly as before)
"""

from __future__ import annotations

import importlib.util
import os
import subprocess
import tempfile
import textwrap
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
PRE_SUBMIT = ROOT / "tools" / "pre-submit-check.sh"
DETECT_TOOL = ROOT / "tools" / "ghsa-mode-detect.py"
REQ_TOOL = ROOT / "tools" / "ghsa-requirements-check.py"
POC_TOOL = ROOT / "tools" / "ghsa-poc-inline-check.py"


def _load(path: Path, name: str):
    spec = importlib.util.spec_from_file_location(name, path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


DETECT = _load(DETECT_TOOL, "ghsa_mode_detect")
REQ = _load(REQ_TOOL, "ghsa_requirements_check")


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

GHSA_DRAFT = textwrap.dedent(
    """\
    <!-- l34-rebuttal: authorized new draft -->
    <!-- target-format: ghsa -->

    # Mempool slot leak in zebrad allows an unauthenticated peer to disable the cap

    ## Advisory Details

    **Title:** Mempool per-peer slot leak in zebrad lets an unauthenticated peer disable the cap.

    ### Summary
    A per-peer counter leaks on the verify-timeout arm. Affects zebrad <= 4.5.0.

    ### Details
    Root cause at downloads.rs:261 - the timeout arm removes cancel_handles but
    never calls release_peer_slot, so the stale pending_per_peer count is never
    decremented and the per-peer cap is effectively disabled.

    ### PoC
    Run the harness:

    ```
    cargo test -p zebrad --lib mempool::downloads_poc_tests
    # test result: ok. 2 passed; 0 failed
    let mut downloads = Downloads::new();
    downloads.timeout_arm();
    assert_eq!(downloads.pending_per_peer(peer), 0); // FAILS at pin, passes patched
    ```

    Transcript shows `test result: ok. 2 passed`. Negative control included.

    ### Impact
    CWE-400 resource consumption. Node operators are impacted by an unauthenticated peer.

    ## Affected products
    - **Ecosystem:** crates.io (Rust)
    - **Package name:** zebrad
    - **Affected versions:** `<= 4.5.0`
    - **Patched versions:** none

    ## Severity
    - **Severity band:** Medium
    - **CVSS:3.1 vector:** `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:L` (base 5.3)

    ## Weaknesses
    - CWE-400 Uncontrolled Resource Consumption
    - CWE-459 Incomplete Cleanup

    ## Originality (R47 / R53)
    Distinct from any prior published Zebra advisory; downloads.rs:261 timeout arm.

    ## Prior-Audit Supersede Scan (R53)
    No prior audit covers the timeout-arm slot leak.
    """
)

CANTINA_DRAFT = textwrap.dedent(
    """\
    # Reentrancy in Vault leads to direct theft of user funds

    **Severity:** High
    **Rubric:** Direct theft of user funds.
    **Dollar impact:** $500,000 of user funds.

    Choose Severity: High
    Choose Likelihood: High
    Choose Impact(s): Direct theft of user funds

    ## Impact
    Non-self impact demonstrated; protocol-custody funds not controlled by the attacker.
    """
)

HACKENPROOF_TXT = textwrap.dedent(
    """\
    Title: Reentrancy in Vault

    Severity: High

    PoC:
    See the attached vault-poc.zip for the full harness and transcript.
    """
)

# r36-rebuttal: lane TASK-A-GHSA-HIGH-SCAFFOLD-SKIP registered in .auditooor/agent_pathspec.json
# A HIGH-severity GHSA-format advisory. Identical shape to GHSA_DRAFT but the
# severity band + CVSS vector are High, so the 4 HIGH+ orchestration-scaffolding
# gates (#27 production-path, #76 HIGH-PLUS-MCP-LIVE-HARDENING,
# #80 PREFILING-STRESS-ARTIFACT, #82 CANDIDATE-JUDGMENT-PACKET) would fire if not
# GHSA-skipped. A GHSA advisory cannot produce the cosmos/EVM exploit-conversion
# artifacts those gates demand.
GHSA_HIGH_DRAFT = (
    GHSA_DRAFT.replace(
        "- **Severity band:** Medium",
        "- **Severity band:** High",
    ).replace(
        "`CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:L` (base 5.3)",
        "`CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H` (base 7.5)",
    )
)


class TestDetection(unittest.TestCase):
    def _write(self, tmp, name, body):
        p = Path(tmp) / name
        p.write_text(body, encoding="utf-8")
        return p

    def test_marker_detected(self):
        with tempfile.TemporaryDirectory() as tmp:
            p = self._write(tmp, "d.md", GHSA_DRAFT)
            is_ghsa, via, _ = DETECT.detect(p)
            self.assertTrue(is_ghsa)
            self.assertTrue(any("marker" in v for v in via))

    def test_structural_triple_detected_without_marker(self):
        body = GHSA_DRAFT.replace("<!-- target-format: ghsa -->\n", "")
        with tempfile.TemporaryDirectory() as tmp:
            p = self._write(tmp, "d.md", body)
            is_ghsa, via, _ = DETECT.detect(p)
            self.assertTrue(is_ghsa)
            self.assertTrue(any("structural" in v for v in via))

    def test_sibling_advisory_md_detected(self):
        body = "# plain draft\n\nno ghsa markers here\n"
        with tempfile.TemporaryDirectory() as tmp:
            p = self._write(tmp, "d.md", body)
            self._write(tmp, "d.advisory.md", "# rendered paste\n")
            is_ghsa, via, paste = DETECT.detect(p)
            self.assertTrue(is_ghsa)
            self.assertTrue(any("sibling" in v for v in via))
            self.assertTrue(str(paste).endswith("d.advisory.md"))

    def test_paste_artifact_falls_back_to_source(self):
        with tempfile.TemporaryDirectory() as tmp:
            p = self._write(tmp, "d.md", GHSA_DRAFT)
            _, _, paste = DETECT.detect(p)
            self.assertEqual(paste, p)

    def test_negative_cantina_not_ghsa(self):
        with tempfile.TemporaryDirectory() as tmp:
            p = self._write(tmp, "d.md", CANTINA_DRAFT)
            is_ghsa, via, _ = DETECT.detect(p)
            self.assertFalse(is_ghsa)
            self.assertEqual(via, [])

    def test_field_is_ghsa_cli(self):
        with tempfile.TemporaryDirectory() as tmp:
            p = self._write(tmp, "d.md", GHSA_DRAFT)
            out = subprocess.run(
                ["python3", str(DETECT_TOOL), str(p), "--field", "is_ghsa"],
                capture_output=True, text=True)
            self.assertEqual(out.returncode, 0)
            self.assertEqual(out.stdout.strip(), "1")

    def test_field_is_ghsa_cli_negative_exit_zero(self):
        with tempfile.TemporaryDirectory() as tmp:
            p = self._write(tmp, "d.md", CANTINA_DRAFT)
            out = subprocess.run(
                ["python3", str(DETECT_TOOL), str(p), "--field", "is_ghsa"],
                capture_output=True, text=True)
            # field mode never aborts the caller even on non-GHSA
            self.assertEqual(out.returncode, 0)
            self.assertEqual(out.stdout.strip(), "0")


class TestRequirementsGate(unittest.TestCase):
    def test_complete_draft_passes(self):
        with tempfile.TemporaryDirectory() as tmp:
            p = Path(tmp) / "d.md"
            p.write_text(GHSA_DRAFT, encoding="utf-8")
            rc, payload = REQ.check(p)
            self.assertEqual(rc, 0, payload.get("reason"))
            self.assertEqual(payload["verdict"], "pass-ghsa-requirements-met")

    def test_missing_cwe_fails(self):
        body = GHSA_DRAFT.replace("- CWE-400 Uncontrolled Resource Consumption\n", "")
        body = body.replace("- CWE-459 Incomplete Cleanup\n", "")
        body = body.replace("CWE-400 resource consumption.", "resource consumption.")
        with tempfile.TemporaryDirectory() as tmp:
            p = Path(tmp) / "d.md"
            p.write_text(body, encoding="utf-8")
            rc, payload = REQ.check(p)
            self.assertEqual(rc, 1)
            self.assertTrue(any("CWE" in f for f in payload["failures"]))

    def test_missing_originality_fails(self):
        body = GHSA_DRAFT.split("## Originality")[0]
        with tempfile.TemporaryDirectory() as tmp:
            p = Path(tmp) / "d.md"
            p.write_text(body, encoding="utf-8")
            rc, payload = REQ.check(p)
            self.assertEqual(rc, 1)
            self.assertTrue(any("Originality" in f for f in payload["failures"]))

    def test_leading_rebuttal_comment_does_not_fail(self):
        # source draft legitimately carries leading rebuttal HTML-comments;
        # the requirements gate must NOT fail on the residue rule.
        with tempfile.TemporaryDirectory() as tmp:
            p = Path(tmp) / "d.md"
            p.write_text(GHSA_DRAFT, encoding="utf-8")
            rc, payload = REQ.check(p)
            self.assertEqual(rc, 0)
            self.assertFalse(any("HTML-comment" in f for f in payload["failures"]))


def _run_presubmit(draft: Path, severity: str = "Medium"):
    env = os.environ.copy()
    return subprocess.run(
        ["bash", str(PRE_SUBMIT), str(draft), "--severity", severity],
        capture_output=True, text=True, env=env)


class TestShellGHSAMode(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.dir = Path(self._tmp.name)

    def tearDown(self):
        self._tmp.cleanup()

    def _draft(self, body, name="zebra-slot-leak.md"):
        p = self.dir / name
        p.write_text(body, encoding="utf-8")
        return p

    def test_ghsa_mode_engaged_and_skips_cantina_gates(self):
        p = self._draft(GHSA_DRAFT)
        out = _run_presubmit(p).stdout
        self.assertIn("GHSA-AWARE MODE engaged", out)
        self.assertIn("11. Scope-review artifact: SKIPPED under GHSA-AWARE MODE", out)
        self.assertIn("31. PROGRAM-IMPACT-MAPPING: SKIPPED under GHSA-AWARE MODE", out)
        self.assertIn("41. Impact-contract preflight: SKIPPED under GHSA-AWARE MODE", out)
        self.assertIn("42. FINAL-PASTE-FORM-GATE: SKIPPED under GHSA-AWARE MODE", out)
        self.assertIn("68. L33-CHANGELOG-DRIFT-COVERAGE: SKIPPED under GHSA-AWARE MODE", out)

    def test_ghsa_equivalents_enforced(self):
        p = self._draft(GHSA_DRAFT)
        out = _run_presubmit(p).stdout
        self.assertIn("42b. GHSA-REQUIREMENTS", out)
        self.assertIn("pass-ghsa-requirements-met", out)
        self.assertIn("43b. GHSA-POC-INLINE", out)
        self.assertIn("pass-ghsa-md-inline-poc", out)

    def test_72_global_tier_debt_decoupled_to_warn(self):
        p = self._draft(GHSA_DRAFT)
        out = _run_presubmit(p).stdout
        # the draft cites zero tier-5 records; global corpus tier-debt must NOT
        # appear as a hard FAIL on #72.
        self.assertNotIn("72. HACKERMAN-RECORD-VERIFICATION-TIER blocked", out)
        # it must surface as the decoupled WARN line when tier-debt exists.
        if "HACKERMAN-RECORD-VERIFICATION-TIER" in out:
            self.assertTrue(
                ("72. HACKERMAN-RECORD-VERIFICATION-TIER (decoupled)" in out)
                or ("✅ 72. HACKERMAN-RECORD-VERIFICATION-TIER" in out),
                "expected decoupled WARN or clean PASS, got hard fail",
            )

    def test_88_skipped_with_not_configured_rebuttal(self):
        body = GHSA_DRAFT.replace(
            "<!-- target-format: ghsa -->\n",
            "<!-- target-format: ghsa -->\n<!-- not-configured-component: self-contained crate-level resource leak -->\n",
        )
        p = self._draft(body)
        out = _run_presubmit(p).stdout
        self.assertIn("88. CONFIG-DOWNSTREAM-TRACE: SKIPPED under GHSA-AWARE MODE", out)


class TestNonRegression(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.dir = Path(self._tmp.name)

    def tearDown(self):
        self._tmp.cleanup()

    def test_cantina_draft_no_ghsa_banner(self):
        p = self.dir / "cantina.md"
        p.write_text(CANTINA_DRAFT, encoding="utf-8")
        out = _run_presubmit(p).stdout
        self.assertNotIn("GHSA-AWARE MODE engaged", out)
        # the Cantina #42 selector gate must still RUN (not be GHSA-skipped)
        self.assertNotIn("42. FINAL-PASTE-FORM-GATE: SKIPPED under GHSA-AWARE MODE", out)
        # and it must still appear as a real gate line
        self.assertIn("42. FINAL-PASTE-FORM-GATE", out)

    def test_cantina_gates_not_skipped(self):
        p = self.dir / "cantina.md"
        p.write_text(CANTINA_DRAFT, encoding="utf-8")
        out = _run_presubmit(p).stdout
        for skip in (
            "11. Scope-review artifact: SKIPPED under GHSA-AWARE MODE",
            "31. PROGRAM-IMPACT-MAPPING: SKIPPED under GHSA-AWARE MODE",
            "41. Impact-contract preflight: SKIPPED under GHSA-AWARE MODE",
        ):
            self.assertNotIn(skip, out)

    def test_hackenproof_txt_not_ghsa(self):
        p = self.dir / "f.hackenproof-plain.txt"
        p.write_text(HACKENPROOF_TXT, encoding="utf-8")
        out = _run_presubmit(p).stdout
        self.assertNotIn("GHSA-AWARE MODE engaged", out)


class TestSeventyTwoDecoupleUnit(unittest.TestCase):
    """Unit-level proof of the #72 decouple semantics on the tier-check tool."""

    def test_tool_separates_global_debt_from_submission_refs(self):
        tool = ROOT / "tools" / "hackerman-record-verification-tier-check.py"
        # Run the real tool against a clean GHSA draft. Whatever the global
        # corpus tier-debt is, the draft cites zero tier-5 quarantine records,
        # so submission_quarantine_refs must be empty.
        import json
        with tempfile.TemporaryDirectory() as tmp:
            p = Path(tmp) / "d.md"
            p.write_text(GHSA_DRAFT, encoding="utf-8")
            out = subprocess.run(
                ["python3", str(tool), "--json", "--submission", str(p),
                 "--allow-missing-tags-dir"],
                capture_output=True, text=True, cwd=str(ROOT))
            payload = json.loads(out.stdout)
            self.assertEqual(payload.get("submission_quarantine_refs") or [], [])


# r36-rebuttal: lane TASK-A-GHSA-HIGH-SCAFFOLD-SKIP registered in .auditooor/agent_pathspec.json
class TestGHSAHighScaffoldingGatesSkipped(unittest.TestCase):
    """A HIGH GHSA advisory must SKIP the 4 cosmos/EVM exploit-conversion
    scaffolding gates (#27/#76/#80/#82) with a logged GHSA-N/A reason, because a
    GHSA-format finding cannot produce the production-path schema / live on-chain
    role enumeration / prefiling-stress / prove-top-leads artifacts they demand.
    The GHSA requirement gates (#42b/#43b) must still PASS so rigor is preserved.
    """

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.dir = Path(self._tmp.name)

    def tearDown(self):
        self._tmp.cleanup()

    def _draft(self, body, name="zebra-slot-leak.md"):
        p = self.dir / name
        p.write_text(body, encoding="utf-8")
        return p

    def test_27_production_path_skipped(self):
        p = self._draft(GHSA_HIGH_DRAFT)
        out = _run_presubmit(p, severity="High").stdout
        self.assertIn("GHSA-AWARE MODE engaged", out)
        self.assertIn(
            "27. production-path: SKIPPED under GHSA-AWARE MODE", out
        )
        self.assertIn("GHSA-N/A", out)
        # the scaffolding gate must NOT hard-fail the GHSA draft
        self.assertNotIn("❌ 27. production-path: fail", out)

    def test_76_high_plus_live_hardening_skipped(self):
        p = self._draft(GHSA_HIGH_DRAFT)
        out = _run_presubmit(p, severity="High").stdout
        self.assertIn(
            "76. HIGH-PLUS-MCP-LIVE-HARDENING: SKIPPED under GHSA-AWARE MODE",
            out,
        )
        self.assertNotIn("76. HIGH-PLUS-MCP-LIVE-HARDENING blocked", out)

    def test_80_prefiling_stress_artifact_skipped(self):
        p = self._draft(GHSA_HIGH_DRAFT)
        out = _run_presubmit(p, severity="High").stdout
        self.assertIn(
            "80. PREFILING-STRESS-ARTIFACT: SKIPPED under GHSA-AWARE MODE", out
        )
        self.assertNotIn("80. PREFILING-STRESS-ARTIFACT blocked", out)

    def test_82_candidate_judgment_packet_skipped(self):
        p = self._draft(GHSA_HIGH_DRAFT)
        out = _run_presubmit(p, severity="High").stdout
        self.assertIn(
            "82. CANDIDATE-JUDGMENT-PACKET: SKIPPED under GHSA-AWARE MODE", out
        )
        self.assertNotIn("82. CANDIDATE-JUDGMENT-PACKET blocked", out)

    # r36-rebuttal: lane TASK-B-GHSA-81-SKIP registered in .auditooor/agent_pathspec.json
    def test_81_source_read_receipts_skipped(self):
        # source-read receipts are a cosmos/EVM pre-source-read-injector /
        # hacker-question orchestration artifact; a GHSA advisory grep-verifies
        # its source cites at the audit pin and produces no receipt. The gate
        # must SKIP (not hard-fail) under GHSA-AWARE MODE.
        p = self._draft(GHSA_HIGH_DRAFT)
        out = _run_presubmit(p, severity="High").stdout
        self.assertIn(
            "81. SOURCE-READ-RECEIPTS: SKIPPED under GHSA-AWARE MODE", out
        )
        self.assertIn("GHSA-N/A", out)
        self.assertNotIn(
            "❌ 81. SOURCE-READ-RECEIPTS missing or stale", out
        )

    def test_ghsa_requirement_gates_still_enforced_on_high(self):
        # rigor preserved: the GHSA-format requirement + inline-PoC gates must
        # still run and PASS on the HIGH GHSA draft.
        p = self._draft(GHSA_HIGH_DRAFT)
        out = _run_presubmit(p, severity="High").stdout
        self.assertIn("42b. GHSA-REQUIREMENTS", out)
        self.assertIn("pass-ghsa-requirements-met", out)
        self.assertIn("43b. GHSA-POC-INLINE", out)
        self.assertIn("pass-ghsa-md-inline-poc", out)

    def test_high_ghsa_has_no_scaffolding_hard_fail(self):
        # one-line confirm: a GHSA HIGH must show none of the 4 scaffolding
        # gates as a hard FAIL / blocked line.
        p = self._draft(GHSA_HIGH_DRAFT)
        out = _run_presubmit(p, severity="High").stdout
        for forbidden in (
            "❌ 27. production-path: fail",
            "❌ 76. HIGH-PLUS-MCP-LIVE-HARDENING blocked",
            "❌ 80. PREFILING-STRESS-ARTIFACT blocked",
            "❌ 82. CANDIDATE-JUDGMENT-PACKET blocked",
        ):
            self.assertNotIn(forbidden, out)


# r36-rebuttal: lane TASK-A-GHSA-HIGH-SCAFFOLD-SKIP registered in .auditooor/agent_pathspec.json
class TestNonGHSAHighScaffoldingGatesStillFire(unittest.TestCase):
    """Regression: a non-GHSA (Cantina/EVM/cosmos) HIGH draft must STILL trigger
    all 4 scaffolding gates - none of them may be GHSA-skipped. This locks the
    Cantina + EVM + cosmos HIGH path byte-identical to pre-change behavior.
    """

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.dir = Path(self._tmp.name)

    def tearDown(self):
        self._tmp.cleanup()

    def _draft(self, body, name="cantina-high.md"):
        p = self.dir / name
        p.write_text(body, encoding="utf-8")
        return p

    def test_cantina_high_no_ghsa_banner(self):
        p = self._draft(CANTINA_DRAFT)
        out = _run_presubmit(p, severity="High").stdout
        self.assertNotIn("GHSA-AWARE MODE engaged", out)

    # r36-rebuttal: lane TASK-B-GHSA-81-SKIP registered in .auditooor/agent_pathspec.json
    def test_cantina_high_scaffolding_gates_not_ghsa_skipped(self):
        p = self._draft(CANTINA_DRAFT)
        out = _run_presubmit(p, severity="High").stdout
        for skip in (
            "27. production-path: SKIPPED under GHSA-AWARE MODE",
            "76. HIGH-PLUS-MCP-LIVE-HARDENING: SKIPPED under GHSA-AWARE MODE",
            "80. PREFILING-STRESS-ARTIFACT: SKIPPED under GHSA-AWARE MODE",
            "81. SOURCE-READ-RECEIPTS: SKIPPED under GHSA-AWARE MODE",
            "82. CANDIDATE-JUDGMENT-PACKET: SKIPPED under GHSA-AWARE MODE",
        ):
            self.assertNotIn(skip, out)

    def test_cantina_high_scaffolding_gates_still_run(self):
        # each gate must still emit its real (non-GHSA) gate line.
        p = self._draft(CANTINA_DRAFT)
        out = _run_presubmit(p, severity="High").stdout
        self.assertIn("27. production-path", out)
        self.assertIn("76. HIGH-PLUS-MCP-LIVE-HARDENING", out)
        self.assertIn("80. PREFILING-STRESS-ARTIFACT", out)
        self.assertIn("81. SOURCE-READ-RECEIPTS", out)
        self.assertIn("82. CANDIDATE-JUDGMENT-PACKET", out)


if __name__ == "__main__":
    unittest.main()
