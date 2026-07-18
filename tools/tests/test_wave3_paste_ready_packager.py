#!/usr/bin/env python3
"""Tests for tools/wave3-paste-ready-packager.py.

Synthetic fixtures only (synthetic_fixture: true). All paths constructed
in tempdirs; no production paste-ready submissions are touched.
"""
from __future__ import annotations

import importlib.util
import json
import os
import sys
import tempfile
import unittest
from pathlib import Path


HERE = Path(__file__).resolve().parent
TOOLS_DIR = HERE.parent
REPO_ROOT = TOOLS_DIR.parent
PACKAGER_PATH = TOOLS_DIR / "wave3-paste-ready-packager.py"


def _load_module():
    spec = importlib.util.spec_from_file_location("wave3_paste_ready_packager", PACKAGER_PATH)
    assert spec and spec.loader
    mod = importlib.util.module_from_spec(spec)
    sys.modules["wave3_paste_ready_packager"] = mod
    spec.loader.exec_module(mod)
    return mod


PKG = _load_module()


CANONICAL_DRAFT_TEMPLATE = """\
<!-- synthetic_fixture: true -->
# Direct loss of user funds in {protocol} settlement path leads to permanent loss

## Severity
- Severity: {severity_label}
- Likelihood: High
- Impact: High

Rubric quote (verbatim):
> Direct theft of any user funds

## Summary
A signed message replay in the settlement path allows an attacker to drain
victim balances without holding any victim key material.

## Root Cause
File `src/Settlement.sol:142` reads the nonce after the external call returns,
allowing reentrancy via the receiver hook. The vulnerable surface is reachable
from any non-privileged user.

## Impact
Attacker drains victim balances. Non-self impact: victim address `0xBEEF`
loses 100% of deposit. Treasury impacted at `protocolAddr`.

## Severity Justification
Matches the rubric verbatim row for direct theft of user funds.

## Override
N/A (no prior overlapping finding).

## Likelihood
High - non-privileged trigger, no protocol-side guard, attack is single-tx.

## Program Impact Mapping
- selected_impact: Direct theft of any user funds
- severity_tier: {severity_label}
- listed_impact_proven: true
- evidence_class: executed_poc
- oos_traps: [centralization, privileged_role, frontend, off_chain, weird_token]
- stop_condition: do_not_claim_critical_unless_extended

## Source-Only Justification
N/A - executed PoC included.

## Real-Component Precondition
1. Real Settlement contract deployed at audit pin.
2. Reachable from non-privileged user.
3. No mock replacements in the vulnerable path.

## Production Path
1. Attacker calls Settlement.settle(victim, payload).
2. Settlement performs external call before nonce update.
3. Receiver hook re-enters Settlement.settle.
4. Funds are debited twice from victim address; attacker withdraws.

## Impact Contract
- selected_impact: Direct theft of any user funds
- severity_tier: {severity_label}
- listed_impact_proven: true
- evidence_class: executed_poc
- oos_traps: [centralization, privileged_role, frontend, off_chain, weird_token]
- stop_condition: do_not_claim_critical_unless_extended
- Victim: depositor at 0xBEEF
- Attacker: any non-privileged EOA
- Impacted contract: src/Settlement.sol
- Impacted asset: USDC
- Source-proof: src/Settlement.sol:142

## Scope And Originality
Root cause is in scope. No prior audit pin advisory references this surface.

## Proof of Concept
File `test/SettlementReentry.t.sol`:

```solidity
contract SettlementReentryTest {{
    function test_PoC_drain() public {{
        // attacker -> victim drain via reentrancy
        assert(victimBalanceBefore > victimBalanceAfter);
    }}
}}
```

Run: `forge test --match-test test_PoC_drain -vv`.

Result:
```
[PASS] test_PoC_drain() (gas: 142000)
Suite result: ok. 1 passed; 0 failed; 0 skipped
```

## Recommended Fix
Apply the checks-effects-interactions pattern: update nonce BEFORE the
external call. Mirrors PR #1234 in the upstream reference implementation.
"""


def _make_draft(tmp: Path, *, severity_label: str = "High", protocol: str = "thegraph",
                  extra: str = "") -> Path:
    body = CANONICAL_DRAFT_TEMPLATE.format(severity_label=severity_label, protocol=protocol)
    body += "\n" + extra
    path = tmp / f"synth-{protocol}-{severity_label}.md"
    path.write_text(body, encoding="utf-8")
    return path


class TestRubricLoad(unittest.TestCase):
    def test_load_cantina(self):
        r = PKG.load_rubric("cantina", None)
        self.assertEqual(r.get("platform"), "cantina")
        self.assertIn("tiers", r)
        self.assertGreater(len(r["tiers"]), 0)

    def test_load_immunefi_has_poi(self):
        r = PKG.load_rubric("immunefi", None)
        self.assertIn("primacy-of-impact", r.get("selector_modes", []))

    def test_load_sherlock(self):
        r = PKG.load_rubric("sherlock", None)
        self.assertEqual(r.get("platform"), "sherlock")

    def test_load_code4rena(self):
        r = PKG.load_rubric("code4rena", None)
        self.assertEqual(r.get("platform"), "code4rena")


class TestPlatformShape(unittest.TestCase):
    def setUp(self):
        self.tmp_obj = tempfile.TemporaryDirectory()
        self.tmp = Path(self.tmp_obj.name)
        self.draft = _make_draft(self.tmp)

    def tearDown(self):
        self.tmp_obj.cleanup()

    def _package(self, platform: str, severity: str = "High"):
        draft = _make_draft(self.tmp, severity_label=severity, protocol=platform)
        reshaped, result = PKG.package(
            draft_path=draft,
            platform=platform,
            workspace=self.tmp,
            target_protocol="synthetic-protocol",
            rubric_override=None,
            strict=False,
            dry_run_gates=True,
        )
        return reshaped, result

    def test_cantina_shape_pass(self):
        reshaped, result = self._package("cantina")
        self.assertIn("## Severity", reshaped)
        self.assertIn("## Proof of Concept", reshaped)
        self.assertIn("## Recommended Fix", reshaped)
        self.assertEqual(result.target_platform, "cantina")
        # dry-run-gates: all gates SKIP, so no blocking; overall READY_TO_PASTE.
        self.assertEqual(result.overall_status, "READY_TO_PASTE")

    def test_immunefi_shape_pass(self):
        reshaped, result = self._package("immunefi")
        # Immunefi requires Vulnerability Details + Impact Details + Recommendation + Proof of Concept
        self.assertIn("## Vulnerability Details", reshaped)
        self.assertIn("## Impact Details", reshaped)
        self.assertIn("## Recommendation", reshaped)
        self.assertIn("## Proof of Concept", reshaped)
        self.assertEqual(result.target_platform, "immunefi")

    def test_sherlock_shape_pass(self):
        reshaped, result = self._package("sherlock")
        self.assertIn("## Vulnerability Detail", reshaped)
        self.assertIn("## Code Snippet", reshaped)
        self.assertIn("## Tool used", reshaped)
        self.assertEqual(result.target_platform, "sherlock")

    def test_code4rena_shape_pass(self):
        reshaped, result = self._package("code4rena")
        self.assertIn("## Lines of code", reshaped)
        self.assertIn("## Vulnerability details", reshaped)
        self.assertIn("## Recommended Mitigation Steps", reshaped)
        self.assertEqual(result.target_platform, "code4rena")

    def test_platform_switch_same_draft(self):
        draft = _make_draft(self.tmp, severity_label="High", protocol="multi")
        outputs: dict[str, str] = {}
        for platform in ("cantina", "immunefi", "sherlock", "code4rena"):
            reshaped, _ = PKG.package(
                draft_path=draft,
                platform=platform,
                workspace=self.tmp,
                target_protocol="multi",
                rubric_override=None,
                strict=False,
                dry_run_gates=True,
            )
            outputs[platform] = reshaped
        # Each platform output is non-empty and platform-specific.
        for platform, body in outputs.items():
            self.assertGreater(len(body), 200, f"{platform} output too short")
        # No two platform outputs are byte-identical (different section orders).
        self.assertNotEqual(outputs["cantina"], outputs["immunefi"])
        self.assertNotEqual(outputs["sherlock"], outputs["code4rena"])


class TestGateOrchestration(unittest.TestCase):
    def setUp(self):
        self.tmp_obj = tempfile.TemporaryDirectory()
        self.tmp = Path(self.tmp_obj.name)

    def tearDown(self):
        self.tmp_obj.cleanup()

    def test_gate_dry_run_all_skip(self):
        draft = _make_draft(self.tmp)
        _, result = PKG.package(
            draft_path=draft,
            platform="cantina",
            workspace=self.tmp,
            target_protocol="synth",
            rubric_override=None,
            strict=False,
            dry_run_gates=True,
        )
        statuses = {g.gate_id: g.status for g in result.gate_results}
        # Every gate should be SKIP under dry-run.
        for gate, status in statuses.items():
            self.assertEqual(status, "SKIP", f"gate {gate} should be SKIP in dry-run, got {status}")

    def test_rebuttal_marker_detected(self):
        # Inject an r24 rebuttal directly into the draft body.
        draft = _make_draft(self.tmp, extra="<!-- r24-rebuttal: synthetic test of override path -->")
        rebuttals = PKG.detect_rebuttals(draft.read_text(encoding="utf-8"))
        self.assertIn("r24", rebuttals)

    def test_cosmos_detection_positive(self):
        body = "This finding affects cosmos-sdk app-chains via BaseApp.FinalizeBlock."
        self.assertTrue(PKG.detect_cosmos(body, None))

    def test_cosmos_detection_negative(self):
        body = "Solidity reentrancy in src/Token.sol; no cosmos surface."
        self.assertFalse(PKG.detect_cosmos(body, None))


class TestSeverityAndMetadata(unittest.TestCase):
    def setUp(self):
        self.tmp_obj = tempfile.TemporaryDirectory()
        self.tmp = Path(self.tmp_obj.name)

    def tearDown(self):
        self.tmp_obj.cleanup()

    def test_severity_extraction_high(self):
        draft = _make_draft(self.tmp, severity_label="High")
        sev = PKG.detect_severity(draft.read_text(encoding="utf-8"))
        self.assertEqual(sev, "high")

    def test_severity_extraction_critical(self):
        draft = _make_draft(self.tmp, severity_label="Critical")
        sev = PKG.detect_severity(draft.read_text(encoding="utf-8"))
        self.assertEqual(sev, "critical")

    def test_title_extraction(self):
        draft = _make_draft(self.tmp)
        title = PKG.detect_title(draft.read_text(encoding="utf-8"))
        self.assertIsNotNone(title)
        self.assertIn("Direct loss", title)

    def test_rubric_tier_lookup(self):
        rubric = PKG.load_rubric("immunefi", None)
        tier = PKG.find_rubric_tier(rubric, "critical")
        self.assertIsNotNone(tier)
        self.assertIn("Direct theft", tier.get("rubric_verbatim", ""))


class TestCLISmoke(unittest.TestCase):
    def setUp(self):
        self.tmp_obj = tempfile.TemporaryDirectory()
        self.tmp = Path(self.tmp_obj.name)

    def tearDown(self):
        self.tmp_obj.cleanup()

    def test_main_json_mode(self):
        draft = _make_draft(self.tmp)
        # Redirect stdout to capture.
        import io
        import contextlib
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf), contextlib.redirect_stderr(io.StringIO()):
            rc = PKG.main([
                "--input", str(draft),
                "--platform", "cantina",
                "--target-protocol", "synth",
                "--workspace", str(self.tmp),
                "--json",
                "--dry-run-gates",
            ])
        self.assertEqual(rc, 0)
        payload = json.loads(buf.getvalue())
        self.assertEqual(payload["schema_version"], PKG.SCHEMA_VERSION)
        self.assertEqual(payload["target_platform"], "cantina")
        self.assertIn("gate_results", payload)

    def test_main_writes_output_file(self):
        draft = _make_draft(self.tmp)
        out = self.tmp / "out-cantina.md"
        import io
        import contextlib
        with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
            rc = PKG.main([
                "--input", str(draft),
                "--platform", "immunefi",
                "--output", str(out),
                "--target-protocol", "synth",
                "--workspace", str(self.tmp),
                "--dry-run-gates",
            ])
        self.assertEqual(rc, 0)
        self.assertTrue(out.exists())
        body = out.read_text(encoding="utf-8")
        self.assertIn("Vulnerability Details", body)
        # No em-dashes per the global formatting rule.
        self.assertNotIn("—", body, "em-dash leaked into output")
        self.assertNotIn("–", body, "en-dash leaked into output")


class TestNoEmDashesInTool(unittest.TestCase):
    def test_tool_source_no_em_dash(self):
        text = PACKAGER_PATH.read_text(encoding="utf-8")
        # The tool itself must not contain em-dashes or en-dashes in user-facing output paths.
        self.assertNotIn("—", text, "em-dash present in tool source")
        self.assertNotIn("–", text, "en-dash present in tool source")


if __name__ == "__main__":
    unittest.main()
