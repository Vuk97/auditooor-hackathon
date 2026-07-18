#!/usr/bin/env python3
"""Tests for tools/prior-audit-finding-supersede-check.py (Rule 53, Check #99).

Covers 15 cases:
  1.  Severity MEDIUM -> pass-out-of-scope (gate skips)
  2.  HIGH + no prior_audits/ dir -> pass-no-prior-audits-corpus
  3.  HIGH + prior_audits/ exists but no overlap -> pass-no-matching-prior-finding
  4.  HIGH + overlap found + section present + extension-distinct -> pass-extension-distinct-from-prior
  5.  HIGH + overlap found + section MISSING -> fail-no-supersede-scan
  6.  HIGH + overlap found + section present + NO extension-distinct field -> fail-superseded-by-prior-audit
  7.  HIGH + valid r53-rebuttal inline marker -> ok-rebuttal
  8.  HIGH + valid HTML comment rebuttal -> ok-rebuttal
  9.  HIGH + empty r53-rebuttal (ignored) + no section -> fail-no-supersede-scan
  10. Mezo anchor: liquidation-underflow draft vs prior-audit with Cantina 3.2.5 -> fail
  11. polymarket anchor: architectural-by-design finding vs prior-audit body -> fail
  12. JSON output: schema field, verdict, prior_audits_scanned populated
  13. Section with all 4 sub-fields but acknowledged-in-prior True -> still pass if extension present
  14. CRITICAL severity triggers same as HIGH
  15. Missing draft file -> exit code 2 (error)
"""

from __future__ import annotations

import importlib.util
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
TOOL_PATH = REPO_ROOT / "tools" / "prior-audit-finding-supersede-check.py"


def _load_module():
    spec = importlib.util.spec_from_file_location(
        "prior_audit_finding_supersede_check", TOOL_PATH
    )
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot load {TOOL_PATH}")
    module = importlib.util.module_from_spec(spec)
    sys.modules["prior_audit_finding_supersede_check"] = module
    spec.loader.exec_module(module)
    return module


mod = _load_module()


# ---------------------------------------------------------------------------
# Fixture helpers
# ---------------------------------------------------------------------------

_FULL_SECTION = """
## Prior-Audit Supersede Scan
- Workspace prior_audits/ inventory: prior_audits/cantina_audit_2025.txt
- Matched prior finding: Cantina 3.2.5 covers liquidation underflow at vault.sol:L88
  verbatim quote: "liquidation path underflows if collateral is zero"
- Extension-distinct evidence: the prior finding was risk-accepted with a
  minimum-collateral guard that was reverted in commit abc123; the guard is
  absent at audit pin, creating a new downstream surface not covered by the
  prior mitigation. See vault.sol:L55 - new call site added post-audit.
- Verdict: pass-extension-distinct-from-prior
"""

_SECTION_NO_EXTENSION = """
## Prior-Audit Supersede Scan
- Workspace prior_audits/ inventory: prior_audits/cantina_audit_2025.txt
- Matched prior finding: Cantina 3.2.5 covers this root cause
- Verdict: fail-superseded-by-prior-audit
"""

_SECTION_ALL_FIELDS_ACKNOWLEDGED = """
## Prior-Audit Supersede Scan
- Workspace prior_audits/ inventory: prior_audits/cantina_audit_2025.txt
- Matched prior finding: Cantina 3.2.6 acknowledged loss of funds risk as accepted-risk
  verbatim quote: "acknowledged, risk-accepted by protocol team"
- Extension-distinct evidence: new bypass via a downstream surface not covered by the
  prior - the attacker now exploits the re-initialized state that was not present
  in the prior engagement scope.
- Verdict: pass-extension-distinct-from-prior
"""


def _make_draft(
    severity: str = "High",
    section: str = "",
    extra: str = "",
    rebuttal: str = "",
) -> str:
    rebut_line = f"\nr53-rebuttal: {rebuttal}\n" if rebuttal else ""
    return f"""# Finding: Loss of funds in vault leads to permanent freeze
- Severity: {severity}

## Root Cause
Integer overflow / underflow in liquidation path causes loss of funds.
Missing check allows unauthorized transfer.

## Impact
Direct loss of funds for users.
{section}
{rebut_line}
{extra}
"""


def _make_prior_audit_text(
    content: str = "",
    include_ack: bool = False,
) -> str:
    ack = "\nThis finding was acknowledged and risk-accepted by the team.\n" if include_ack else ""
    return f"""# Protocol Security Audit Report

## 3.2.5 Liquidation Underflow
Loss of funds. Integer underflow in the liquidation path.
Missing validation allows unauthorized access.
{ack}
{content}
"""


def _make_prior_audit_no_overlap() -> str:
    return """# Protocol Security Audit Report

## 5.1 Gas optimization note
The loop at line 42 iterates more than necessary.
Consider caching the array length.
"""


# ---------------------------------------------------------------------------
# Test cases
# ---------------------------------------------------------------------------


class TestR53PriorAuditSupersede(unittest.TestCase):

    # --- Case 1: MEDIUM severity skips the gate ---------------------------
    def test_01_medium_severity_skips(self):
        with tempfile.TemporaryDirectory() as ws:
            ws_path = Path(ws)
            (ws_path / "prior_audits").mkdir()
            (ws_path / "prior_audits" / "audit.txt").write_text(
                _make_prior_audit_text(), encoding="utf-8"
            )
            draft = ws_path / "draft.md"
            draft.write_text(_make_draft(severity="Medium"), encoding="utf-8")
            result = mod.check(draft, ws_path, severity_cli="auto")
        self.assertEqual(result["verdict"], "pass-out-of-scope")

    # --- Case 2: HIGH + no prior_audits/ dir ------------------------------
    def test_02_high_no_prior_audits_dir(self):
        with tempfile.TemporaryDirectory() as ws:
            ws_path = Path(ws)
            draft = ws_path / "draft.md"
            draft.write_text(_make_draft(severity="High"), encoding="utf-8")
            # corpus_scan=False isolates the in-workspace path under test.
            result = mod.check(draft, ws_path, corpus_scan=False)
        self.assertEqual(result["verdict"], "pass-no-prior-audits-corpus")

    # --- Case 3: HIGH + prior_audits exists but no root-cause overlap -----
    def test_03_no_overlap_in_prior_audits(self):
        with tempfile.TemporaryDirectory() as ws:
            ws_path = Path(ws)
            (ws_path / "prior_audits").mkdir()
            (ws_path / "prior_audits" / "audit.txt").write_text(
                _make_prior_audit_no_overlap(), encoding="utf-8"
            )
            draft = ws_path / "draft.md"
            draft.write_text(_make_draft(severity="High"), encoding="utf-8")
            # corpus_scan=False isolates the in-workspace no-overlap path.
            result = mod.check(draft, ws_path, corpus_scan=False)
        self.assertEqual(result["verdict"], "pass-no-matching-prior-finding")
        self.assertIn("audit.txt", str(result.get("prior_audits_scanned", [])))

    # --- Case 4: overlap + section + extension-distinct -> PASS -----------
    def test_04_extension_distinct_passes(self):
        with tempfile.TemporaryDirectory() as ws:
            ws_path = Path(ws)
            (ws_path / "prior_audits").mkdir()
            (ws_path / "prior_audits" / "audit.txt").write_text(
                _make_prior_audit_text(), encoding="utf-8"
            )
            draft = ws_path / "draft.md"
            draft.write_text(
                _make_draft(severity="High", section=_FULL_SECTION), encoding="utf-8"
            )
            result = mod.check(draft, ws_path)
        self.assertEqual(result["verdict"], "pass-extension-distinct-from-prior")

    # --- Case 5: overlap + section MISSING -> fail-no-supersede-scan ------
    def test_05_missing_section_fails(self):
        with tempfile.TemporaryDirectory() as ws:
            ws_path = Path(ws)
            (ws_path / "prior_audits").mkdir()
            (ws_path / "prior_audits" / "audit.txt").write_text(
                _make_prior_audit_text(), encoding="utf-8"
            )
            draft = ws_path / "draft.md"
            draft.write_text(_make_draft(severity="High"), encoding="utf-8")
            result = mod.check(draft, ws_path)
        self.assertEqual(result["verdict"], "fail-no-supersede-scan")

    # --- Case 6: overlap + section present + no extension -> fail-superseded
    def test_06_no_extension_fails(self):
        with tempfile.TemporaryDirectory() as ws:
            ws_path = Path(ws)
            (ws_path / "prior_audits").mkdir()
            (ws_path / "prior_audits" / "audit.txt").write_text(
                _make_prior_audit_text(), encoding="utf-8"
            )
            draft = ws_path / "draft.md"
            draft.write_text(
                _make_draft(severity="High", section=_SECTION_NO_EXTENSION),
                encoding="utf-8",
            )
            result = mod.check(draft, ws_path)
        self.assertEqual(result["verdict"], "fail-superseded-by-prior-audit")

    # --- Case 7: valid r53-rebuttal inline -> ok-rebuttal -----------------
    def test_07_rebuttal_inline_passes(self):
        with tempfile.TemporaryDirectory() as ws:
            ws_path = Path(ws)
            (ws_path / "prior_audits").mkdir()
            (ws_path / "prior_audits" / "audit.txt").write_text(
                _make_prior_audit_text(), encoding="utf-8"
            )
            draft = ws_path / "draft.md"
            draft.write_text(
                _make_draft(
                    severity="High",
                    rebuttal="prior 3.2.5 covers underflow at L88; new finding exploits L55 post-revert guard absent",
                ),
                encoding="utf-8",
            )
            result = mod.check(draft, ws_path)
        self.assertEqual(result["verdict"], "ok-rebuttal")

    # --- Case 8: HTML comment rebuttal -> ok-rebuttal ---------------------
    def test_08_rebuttal_html_comment_passes(self):
        with tempfile.TemporaryDirectory() as ws:
            ws_path = Path(ws)
            (ws_path / "prior_audits").mkdir()
            (ws_path / "prior_audits" / "audit.txt").write_text(
                _make_prior_audit_text(), encoding="utf-8"
            )
            draft = ws_path / "draft.md"
            txt = _make_draft(severity="High")
            txt += "\n<!-- r53-rebuttal: prior audit only covers L88; new surface at L55 is distinct -->\n"
            draft.write_text(txt, encoding="utf-8")
            result = mod.check(draft, ws_path)
        self.assertEqual(result["verdict"], "ok-rebuttal")

    # --- Case 9: empty rebuttal (ignored) + no section -> fail ------------
    def test_09_empty_rebuttal_ignored(self):
        with tempfile.TemporaryDirectory() as ws:
            ws_path = Path(ws)
            (ws_path / "prior_audits").mkdir()
            (ws_path / "prior_audits" / "audit.txt").write_text(
                _make_prior_audit_text(), encoding="utf-8"
            )
            draft = ws_path / "draft.md"
            # empty rebuttal should NOT count
            txt = _make_draft(severity="High") + "\n<!-- r53-rebuttal:  -->\n"
            draft.write_text(txt, encoding="utf-8")
            result = mod.check(draft, ws_path)
        # empty rebuttal -> tool falls through to normal checks -> fail-no-supersede-scan
        self.assertIn(result["verdict"], ("fail-no-supersede-scan", "fail-superseded-by-prior-audit"))

    # --- Case 10: Mezo anchor - liquidation-underflow vs prior Cantina 3.2.5/3.2.6
    def test_10_mezo_liquidation_underflow_anchor(self):
        prior_text = """# Mezo Cantina Audit
## 3.2.5 Liquidation Underflow
The liquidation path underflows when collateral is zero causing loss of funds.
Acknowledged and risk-accepted: no fix planned.
## 3.2.6 Missing validation on withdrawal
Missing check on withdrawal path allows unauthorized transfer.
Acknowledged.
## 3.6.5 Integer overflow in reward distribution
Integer overflow acknowledged.
"""
        draft_text = """# Finding: Liquidation underflow in vault allows loss of funds
- Severity: High

## Root Cause
Integer underflow in liquidation calculation causes loss of funds.
vault.sol:L88 - missing bounds check.

## Impact
Direct loss of funds for liquidated users.
"""
        with tempfile.TemporaryDirectory() as ws:
            ws_path = Path(ws)
            (ws_path / "prior_audits").mkdir()
            (ws_path / "prior_audits" / "mezo_audit.txt").write_text(prior_text, encoding="utf-8")
            draft = ws_path / "draft.md"
            draft.write_text(draft_text, encoding="utf-8")
            result = mod.check(draft, ws_path)
        # No section in draft -> fail-no-supersede-scan
        self.assertEqual(result["verdict"], "fail-no-supersede-scan")
        self.assertTrue(len(result.get("prior_audits_scanned", [])) >= 1)

    # --- Case 11: polymarket anchor - architectural by design -------------
    def test_11_polymarket_architectural_anchor(self):
        prior_text = """# Polymarket Security Audit - Pre-deployment report
## Finding H-02 Order validation bypass
The order book does not validate slippage. This is by design; the protocol
intentionally delegates slippage protection to the UI layer. Acknowledged.
Access control for order placement is intentional - only approved operators.
"""
        draft_text = """# Finding: Missing slippage check in order placement allows loss of funds
- Severity: High

## Root Cause
No slippage validation on order placement allows unauthorized loss of funds.

## Impact
Front-running leads to loss of funds for users.
"""
        with tempfile.TemporaryDirectory() as ws:
            ws_path = Path(ws)
            (ws_path / "prior_audits").mkdir()
            (ws_path / "prior_audits" / "polymarket_pre_deploy.txt").write_text(
                prior_text, encoding="utf-8"
            )
            draft = ws_path / "draft.md"
            draft.write_text(draft_text, encoding="utf-8")
            result = mod.check(draft, ws_path)
        self.assertEqual(result["verdict"], "fail-no-supersede-scan")

    # --- Case 12: JSON output has required fields -------------------------
    def test_12_json_output(self):
        with tempfile.TemporaryDirectory() as ws:
            ws_path = Path(ws)
            (ws_path / "prior_audits").mkdir()
            (ws_path / "prior_audits" / "audit.txt").write_text(
                _make_prior_audit_no_overlap(), encoding="utf-8"
            )
            draft = ws_path / "draft.md"
            draft.write_text(_make_draft(severity="High"), encoding="utf-8")
            proc = subprocess.run(
                [sys.executable, str(TOOL_PATH), str(draft),
                 "--workspace", ws, "--no-corpus-scan", "--json"],
                capture_output=True, text=True,
            )
        out = json.loads(proc.stdout)
        self.assertIn("schema", out)
        self.assertIn("verdict", out)
        self.assertEqual(out["schema"], "auditooor.r53_prior_audit_supersede.v1")
        self.assertIn("prior_audits_scanned", out)

    # --- Case 13: acknowledged-in-prior + extension present -> PASS -------
    def test_13_acknowledged_but_extension_present_passes(self):
        with tempfile.TemporaryDirectory() as ws:
            ws_path = Path(ws)
            (ws_path / "prior_audits").mkdir()
            (ws_path / "prior_audits" / "audit.txt").write_text(
                _make_prior_audit_text(include_ack=True), encoding="utf-8"
            )
            draft = ws_path / "draft.md"
            draft.write_text(
                _make_draft(severity="High", section=_SECTION_ALL_FIELDS_ACKNOWLEDGED),
                encoding="utf-8",
            )
            result = mod.check(draft, ws_path)
        self.assertEqual(result["verdict"], "pass-extension-distinct-from-prior")
        self.assertTrue(result["overlapping_prior_audits"][0]["acknowledged_in_prior"])

    # --- Case 14: CRITICAL severity triggers same as HIGH -----------------
    def test_14_critical_triggers_same_as_high(self):
        with tempfile.TemporaryDirectory() as ws:
            ws_path = Path(ws)
            (ws_path / "prior_audits").mkdir()
            (ws_path / "prior_audits" / "audit.txt").write_text(
                _make_prior_audit_text(), encoding="utf-8"
            )
            draft = ws_path / "draft.md"
            draft.write_text(_make_draft(severity="Critical"), encoding="utf-8")
            result = mod.check(draft, ws_path)
        # No section -> fail-no-supersede-scan
        self.assertEqual(result["verdict"], "fail-no-supersede-scan")
        self.assertEqual(result["severity"], "critical")

    # --- Case 15: missing draft file -> exit code 2 -----------------------
    def test_15_missing_draft_file_exit_code(self):
        with tempfile.TemporaryDirectory() as ws:
            proc = subprocess.run(
                [sys.executable, str(TOOL_PATH),
                 "/nonexistent/path/to/draft.md",
                 "--workspace", ws, "--no-corpus-scan", "--json"],
                capture_output=True, text=True,
            )
        self.assertEqual(proc.returncode, 2)


# ---------------------------------------------------------------------------
# Cross-workspace corpus dedup (R53 corpus scan) guard tests
# ---------------------------------------------------------------------------


def _write_corpus_record(tags_dir: Path, name: str, body: str) -> Path:
    """Write a corpus hackerman record under <root>/audit/corpus_tags/tags/."""
    tags_dir.mkdir(parents=True, exist_ok=True)
    f = tags_dir / name
    f.write_text(body, encoding="utf-8")
    return f


# A realistic prior-audit corpus record (shape mirrors a real tags/*.yaml) that
# shares file-ref vault.sol:l88 AND >=2 root-cause tokens (loss of funds,
# integer underflow, missing check) with the candidate draft below.
_CORPUS_PRIOR_AUDIT_BODY = """schema_version: auditooor.hackerman_record.v1.1
record_id: prior-audit:othermezo:prior_audits-cantina-liquidation.txt:L88:S5:deadbeef0001
source_audit_ref: prior-audit:othermezo:prior_audits/cantina-liquidation.txt:L88:S5
target_domain: lending
target_language: solidity
target_component: vault.sol
bug_class: arithmetic
attack_class: integer-underflow
attacker_action_sequence: >-
  Loss of funds in the liquidation path. Integer underflow at vault.sol:L88 when
  collateral is zero. Missing check on the bounds allows unauthorized transfer of
  protocol funds. Acknowledged and risk-accepted by the team; no fix planned.
impact_class: theft
severity_at_finding: high
year: 2024
verification_tier: tier-2-verified-public-archive
"""

# A solodit corpus record that is unrelated (gas optimization, different file).
_CORPUS_SOLODIT_UNRELATED_BODY = """schema_version: auditooor.hackerman_record.v1.1
record_id: solodit-spec:99999:cafef00d
source_audit_ref: solodit-spec:detectors/_specs/gas/loop-cache.yaml:loop-cache
target_component: helper.sol
bug_class: gas-optimization
attacker_action_sequence: The loop at line 42 in helper.sol caches the array length.
severity_at_finding: low
year: 2025
"""

# A record that is NOT a finding-bearing family (dsl_pattern_*): must be ignored.
_CORPUS_DSL_PATTERN_BODY = """schema_version: auditooor.hackerman_record.v1.1
record_id: dsl-pattern:loss-of-funds-vault
attacker_action_sequence: Loss of funds, integer underflow, missing check, vault.sol:L88.
"""


class TestR53CorpusCrossWorkspaceDedup(unittest.TestCase):

    def _candidate_draft(self) -> str:
        # HIGH, NO in-ws prior_audits, shares vault.sol:L88 + multiple tokens
        # with the corpus prior-audit record.
        return """# Finding: Liquidation underflow in vault drains protocol funds
- Severity: High

## Root Cause
Integer underflow in the liquidation calculation at vault.sol:L88 causes loss
of funds. Missing check on bounds allows unauthorized transfer.

## Impact
Direct loss of funds for the protocol.
"""

    def _unrelated_draft(self) -> str:
        # HIGH, shares no file-ref / tokens with any finding-bearing corpus rec.
        return """# Finding: Reentrancy in staking rewards at staking.sol:L200 drains rewards
- Severity: High

## Root Cause
Reentrancy in claimRewards at staking.sol:L200 lets an attacker re-enter and
drain rewards before the balance is zeroed.

## Impact
Reentrancy loss of funds in the rewards pool.
"""

    def _make_corpus_root(self, ws_root: Path, *, with_match: bool) -> Path:
        """Create <ws_root>/corpus/audit/corpus_tags/tags/ with records."""
        corpus_root = ws_root / "corpus"
        tags = corpus_root / "audit" / "corpus_tags" / "tags"
        # always-present noise: unrelated solodit + ignored dsl_pattern
        _write_corpus_record(tags, "solodit-spec_99999.yaml", _CORPUS_SOLODIT_UNRELATED_BODY)
        _write_corpus_record(tags, "dsl_pattern_loss-of-funds-vault.yaml", _CORPUS_DSL_PATTERN_BODY)
        if with_match:
            _write_corpus_record(
                tags,
                "prior-audit-othermezo-cantina-liquidation.txt-L88-S5-deadbeef0001.yaml",
                _CORPUS_PRIOR_AUDIT_BODY,
            )
        return corpus_root

    # --- Guard 1: corpus record sharing file-ref + >=2 tokens -> FAIL ------
    def test_corpus_match_fails_superseded(self):
        with tempfile.TemporaryDirectory() as ws:
            ws_path = Path(ws)
            corpus_root = self._make_corpus_root(ws_path, with_match=True)
            draft = ws_path / "draft.md"
            draft.write_text(self._candidate_draft(), encoding="utf-8")
            result = mod.check(
                draft, ws_path, corpus_scan=True, corpus_root=corpus_root
            )
        self.assertEqual(result["verdict"], "fail-superseded-by-corpus-prior-audit")
        overlaps = result["overlapping_corpus_prior_audits"]
        self.assertTrue(overlaps)
        top = overlaps[0]
        # The cited record is the REAL overlapping corpus record (no faked match).
        self.assertIn("prior-audit:othermezo", top["record_id"])
        self.assertIn("vault.sol", top["common_file_refs"])
        self.assertGreaterEqual(len(top["common_tokens"]), 2)
        # dsl_pattern_* family is NOT finding-bearing -> never the match.
        self.assertNotIn("dsl-pattern", top["record_id"])

    # --- Guard 2: unrelated candidate -> PASS (no corpus match) -----------
    def test_corpus_no_match_passes(self):
        with tempfile.TemporaryDirectory() as ws:
            ws_path = Path(ws)
            corpus_root = self._make_corpus_root(ws_path, with_match=True)
            draft = ws_path / "draft.md"
            draft.write_text(self._unrelated_draft(), encoding="utf-8")
            result = mod.check(
                draft, ws_path, corpus_scan=True, corpus_root=corpus_root
            )
        self.assertEqual(result["verdict"], "pass-no-matching-corpus-prior-finding")

    # --- Guard 3: shared tokens but NO shared file-ref -> PASS (gated) -----
    def test_corpus_tokens_without_file_ref_passes(self):
        with tempfile.TemporaryDirectory() as ws:
            ws_path = Path(ws)
            corpus_root = self._make_corpus_root(ws_path, with_match=True)
            # same tokens (loss of funds / underflow / missing check) but a
            # DIFFERENT file-ref -> the file:line co-occurrence gate blocks it.
            draft = ws_path / "draft.md"
            draft.write_text(
                """# Finding: Underflow drains funds in pool.sol
- Severity: High

## Root Cause
Integer underflow at pool.sol:L10 causes loss of funds; missing check on bounds.

## Impact
Loss of funds for the protocol.
""",
                encoding="utf-8",
            )
            result = mod.check(
                draft, ws_path, corpus_scan=True, corpus_root=corpus_root
            )
        self.assertEqual(result["verdict"], "pass-no-matching-corpus-prior-finding")

    # --- Guard 4: --no-corpus-scan disables the cross-workspace scan ------
    def test_corpus_scan_disabled(self):
        with tempfile.TemporaryDirectory() as ws:
            ws_path = Path(ws)
            corpus_root = self._make_corpus_root(ws_path, with_match=True)
            draft = ws_path / "draft.md"
            draft.write_text(self._candidate_draft(), encoding="utf-8")
            result = mod.check(
                draft, ws_path, corpus_scan=False, corpus_root=corpus_root
            )
        # in-ws path only: no prior_audits/ dir -> pass-no-prior-audits-corpus
        self.assertEqual(result["verdict"], "pass-no-prior-audits-corpus")

    # --- Guard 5: extension-distinct section flips corpus FAIL -> PASS ----
    def test_corpus_match_extension_distinct_passes(self):
        section = """
## Prior-Audit Supersede Scan
- Workspace prior_audits/ inventory: corpus prior-audit othermezo cantina-liquidation
- Matched prior finding: corpus record covers underflow at vault.sol:L88
- Extension-distinct evidence: the prior mitigation guard was reverted; new
  downstream surface not covered by the prior at vault.sol:L120 is exploited.
- Verdict: pass-extension-distinct-from-prior
"""
        with tempfile.TemporaryDirectory() as ws:
            ws_path = Path(ws)
            corpus_root = self._make_corpus_root(ws_path, with_match=True)
            draft = ws_path / "draft.md"
            draft.write_text(self._candidate_draft() + section, encoding="utf-8")
            result = mod.check(
                draft, ws_path, corpus_scan=True, corpus_root=corpus_root
            )
        self.assertEqual(result["verdict"], "pass-extension-distinct-from-prior")

    # --- Guard 6: AUDITOOOR_R53_CORPUS_ROOT env drives the CLI -----------
    def test_corpus_root_env_cli(self):
        import os as _os
        with tempfile.TemporaryDirectory() as ws:
            ws_path = Path(ws)
            corpus_root = self._make_corpus_root(ws_path, with_match=True)
            draft = ws_path / "draft.md"
            draft.write_text(self._candidate_draft(), encoding="utf-8")
            env = dict(_os.environ)
            env["AUDITOOOR_R53_CORPUS_ROOT"] = str(corpus_root)
            env["AUDITOOOR_MCP_REQUIRED"] = "0"
            proc = subprocess.run(
                [sys.executable, str(TOOL_PATH), str(draft),
                 "--workspace", str(ws_path), "--json"],
                capture_output=True, text=True, env=env,
            )
        self.assertEqual(proc.returncode, 1)
        out = json.loads(proc.stdout)
        self.assertEqual(out["verdict"], "fail-superseded-by-corpus-prior-audit")


if __name__ == "__main__":
    unittest.main()
