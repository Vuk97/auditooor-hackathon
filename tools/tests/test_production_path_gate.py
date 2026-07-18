#!/usr/bin/env python3
"""V4 Phase P1 — production-path gate (Check #27) regression tests.

Covers V4 §2 Workstream A1+A2+A3:

  * A1 section detection + severity-gated PASS/WARN/FAIL behavior
  * A1 mock-component triggers (MockVerifier, MockOracle, MockPortal,
    MockRegistry, MockProof, MockSignature, hardcoded `returns true`
    verifier in PoC)
  * A1 prose triggers ("forged proof", "invalid TEE", "invalid ZK",
    "operator does not", "Base does not", "guardian does not",
    "project does not", "will not blacklist") — require item 9 to cite
    an exact program clause
  * A1 local-path-in-PoC always-FAIL on High/Critical
  * A2 packager manifest fields (production_path schema in manifest.json)
  * A3 LLM verdict block parsing (advisory, never hard-blocking)
  * 4 acceptance fixtures from `tools/tests/fixtures/production_path/`

The 4 fixture acceptance criteria match V4 §4 Phase P1:

  1. FN-1-style real-branch bug, no mock verifier, in-scope cite -> PASS
  2. FN-5-style mock-verifier Critical, no upstream bypass cite  -> FAIL
  3. Local-path-only PoC command (`~/audits/...`)                -> FAIL
  4. Draft with `## Production Path` but no item 9 OOS citation:
     - Medium severity                                           -> WARN
     - High/Critical severity                                    -> FAIL
"""
from __future__ import annotations

import importlib.util
import json
import subprocess
import sys
import tempfile
import textwrap
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
PRE_SUBMIT = ROOT / "tools" / "pre-submit-check.sh"
PRODUCTION_PATH_LIB = ROOT / "tools" / "lib" / "production_path.py"
FIXTURES_DIR = ROOT / "tools" / "tests" / "fixtures" / "production_path"
LLM_SCOPE_TRIAGE = ROOT / "tools" / "llm-scope-triage.py"


def _load_lib():
    """Import ``tools/lib/production_path.py`` for in-process tests."""
    name = "_pp_lib_test"
    if name in sys.modules:
        return sys.modules[name]
    spec = importlib.util.spec_from_file_location(name, PRODUCTION_PATH_LIB)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    # Python 3.14 dataclass requires the module to be registered in
    # sys.modules BEFORE exec_module so introspection can resolve it.
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


def _load_llm_scope_triage():
    """Import ``tools/llm-scope-triage.py`` for in-process tests."""
    name = "_llm_scope_triage_test"
    if name in sys.modules:
        return sys.modules[name]
    spec = importlib.util.spec_from_file_location(name, LLM_SCOPE_TRIAGE)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


def _run_pre_submit(draft: Path, severity: str) -> subprocess.CompletedProcess:
    return subprocess.run(
        ["bash", str(PRE_SUBMIT), str(draft), "--severity", severity],
        capture_output=True,
        text=True,
    )


def _run_lib_cli(
    draft: Path, severity: str = "", manifest: bool = False
) -> subprocess.CompletedProcess:
    cmd = [sys.executable, str(PRODUCTION_PATH_LIB), str(draft)]
    if severity:
        cmd += ["--severity", severity]
    if manifest:
        cmd += ["--manifest"]
    return subprocess.run(cmd, capture_output=True, text=True)


# ---------------------------------------------------------------------------
# Fixture acceptance scenarios (V4 §4 Phase P1)
# ---------------------------------------------------------------------------


class FixtureAcceptanceTests(unittest.TestCase):
    """The 4 V4 §4 Phase P1 acceptance scenarios.

    Each test asserts the LIB-level CLI verdict (rc 0/1/2 == PASS/FAIL/WARN)
    on the canonical fixture. The bash gate's wiring is exercised in
    ``BashGateIntegrationTests`` below.
    """

    def test_fn1_real_branch_passes_at_high(self) -> None:
        proc = _run_lib_cli(
            FIXTURES_DIR / "fn1_real_branch_passes.md", severity="High"
        )
        self.assertEqual(
            proc.returncode, 0, f"expected PASS (rc=0); got rc={proc.returncode}\n{proc.stdout}"
        )
        self.assertIn("pass\tproduction-path gate", proc.stdout)

    def test_fn5_mock_verifier_critical_fails(self) -> None:
        proc = _run_lib_cli(
            FIXTURES_DIR / "fn5_mock_verifier_critical_fails.md",
            severity="Critical",
        )
        self.assertEqual(
            proc.returncode,
            1,
            f"expected FAIL (rc=1); got rc={proc.returncode}\n{proc.stdout}",
        )
        self.assertIn("fail\tproduction-path gate", proc.stdout)
        self.assertIn("MockVerifier", proc.stdout)

    def test_local_path_in_poc_fails(self) -> None:
        proc = _run_lib_cli(
            FIXTURES_DIR / "local_path_in_poc_fails.md", severity="High"
        )
        self.assertEqual(
            proc.returncode,
            1,
            f"expected FAIL (rc=1); got rc={proc.returncode}\n{proc.stdout}",
        )
        self.assertIn("fail\tproduction-path gate", proc.stdout)
        self.assertIn("~/audits/", proc.stdout)

    def test_medium_missing_oos_warns(self) -> None:
        proc = _run_lib_cli(
            FIXTURES_DIR / "medium_missing_oos_warns.md", severity="Medium"
        )
        self.assertEqual(
            proc.returncode,
            2,
            f"expected WARN (rc=2); got rc={proc.returncode}\n{proc.stdout}",
        )
        self.assertIn("warn\tproduction-path gate", proc.stdout)

    def test_medium_missing_oos_at_high_fails(self) -> None:
        """The same fixture re-tagged High/Critical hard-fails (acceptance #4)."""
        proc = _run_lib_cli(
            FIXTURES_DIR / "medium_missing_oos_warns.md", severity="High"
        )
        self.assertEqual(
            proc.returncode,
            1,
            f"expected FAIL (rc=1); got rc={proc.returncode}\n{proc.stdout}",
        )
        self.assertIn("fail\tproduction-path gate", proc.stdout)
        self.assertIn("item 9", proc.stdout)


# ---------------------------------------------------------------------------
# A1 unit tests: in-process library checks
# ---------------------------------------------------------------------------


class SectionDetectionTests(unittest.TestCase):
    def setUp(self) -> None:
        self.lib = _load_lib()

    def test_section_absent_high_fails(self) -> None:
        text = "**Severity:** High\n\n## Impact\n\nNo production-path section.\n"
        result = self.lib.evaluate_gate(text, "HIGH")
        self.assertEqual(result.status, "FAIL")
        self.assertTrue(any("missing `## Production Path`" in r for r in result.reasons))

    def test_section_absent_medium_warns(self) -> None:
        text = "**Severity:** Medium\n\n## Impact\n\nNothing.\n"
        result = self.lib.evaluate_gate(text, "MEDIUM")
        self.assertEqual(result.status, "WARN")

    def test_section_absent_low_passes(self) -> None:
        text = "**Severity:** Low\n\n## Impact\n\nNothing.\n"
        result = self.lib.evaluate_gate(text, "LOW")
        self.assertEqual(result.status, "PASS")

    def test_complete_section_high_passes(self) -> None:
        text = textwrap.dedent(
            """
            **Severity:** High

            ## Production Path

            1. In-scope asset: ContractFoo
            2. Affected contract / function: `ContractFoo.bar()`
            3. Reachability: permissionless on-chain
            4. Attacker-controlled inputs: amount, recipient
            5. Non-attacker preconditions: prior deposit
            6. Privileged roles involved: none
            7. Mock components used in PoC: none
            8. Real component replacement for each mock: production deploy
            9. OOS clauses checked: program OOS section 4.2 reviewed
            10. Final in-scope impact: $1m loss
            """
        ).strip()
        result = self.lib.evaluate_gate(text, "HIGH")
        self.assertEqual(result.status, "PASS")


class MockTriggerTests(unittest.TestCase):
    def setUp(self) -> None:
        self.lib = _load_lib()

    def _draft_with_section(self, item_8_value: str, mock_token: str) -> str:
        return textwrap.dedent(
            f"""
            **Severity:** Critical

            ## Impact

            PoC uses {mock_token}.

            ## Production Path

            1. In-scope asset: Foo
            2. Affected contract / function: Foo.bar
            3. Reachability: permissionless
            4. Attacker-controlled inputs: amount
            5. Non-attacker preconditions: none
            6. Privileged roles involved: none
            7. Mock components used in PoC: {mock_token}
            8. Real component replacement for each mock: {item_8_value}
            9. OOS clauses checked: program OOS section 4.2 reviewed
            10. Final in-scope impact: $1m loss
            """
        ).strip()

    def test_mockverifier_without_item_8_fails(self) -> None:
        text = self._draft_with_section(item_8_value="", mock_token="MockVerifier")
        result = self.lib.evaluate_gate(text, "CRITICAL")
        self.assertEqual(result.status, "FAIL")
        self.assertTrue(any("MockVerifier" in r for r in result.reasons))

    def test_mockverifier_with_item_8_passes(self) -> None:
        text = self._draft_with_section(
            item_8_value="real EnclaveVerifier in production", mock_token="MockVerifier"
        )
        result = self.lib.evaluate_gate(text, "CRITICAL")
        self.assertEqual(result.status, "PASS")

    def test_hardcoded_returns_true_triggers_mock_gate(self) -> None:
        text = textwrap.dedent(
            """
            **Severity:** High

            ## Impact

            ```solidity
            contract StubVerifier {
                function verify(bytes calldata, bytes32) external pure returns (bool) {
                    return true;
                }
            }
            ```

            ## Production Path

            1. In-scope asset: Foo
            2. Affected contract / function: Foo.bar
            3. Reachability: permissionless
            4. Attacker-controlled inputs: amount
            5. Non-attacker preconditions: none
            6. Privileged roles involved: none
            7. Mock components used in PoC: stub verifier
            8. Real component replacement for each mock:
            9. OOS clauses checked: section 4.2 reviewed
            10. Final in-scope impact: $1m
            """
        ).strip()
        result = self.lib.evaluate_gate(text, "HIGH")
        self.assertEqual(result.status, "FAIL")
        self.assertTrue(
            any("hardcoded-returns-true-verifier" in r for r in result.reasons),
            f"reasons={result.reasons}",
        )


class ProseTriggerTests(unittest.TestCase):
    def setUp(self) -> None:
        self.lib = _load_lib()

    def _draft_with_prose_trigger(self, prose: str, item_9_value: str) -> str:
        return textwrap.dedent(
            f"""
            **Severity:** High

            ## Impact

            The attack relies on {prose} to drain bridge funds.

            ## Production Path

            1. In-scope asset: Foo
            2. Affected contract / function: Foo.bar
            3. Reachability: permissionless
            4. Attacker-controlled inputs: amount
            5. Non-attacker preconditions: none
            6. Privileged roles involved: none
            7. Mock components used in PoC: none
            8. Real component replacement for each mock: n/a (no mock used)
            9. OOS clauses checked: {item_9_value}
            10. Final in-scope impact: $1m
            """
        ).strip()

    def test_forged_proof_without_clause_citation_fails(self) -> None:
        text = self._draft_with_prose_trigger(
            "forged proof", item_9_value="reviewed scope"
        )
        result = self.lib.evaluate_gate(text, "HIGH")
        self.assertEqual(result.status, "FAIL")
        self.assertTrue(any("forged proof" in r for r in result.reasons))

    def test_forged_proof_with_clause_citation_passes(self) -> None:
        text = self._draft_with_prose_trigger(
            "forged proof",
            item_9_value="program OOS section 4.2 reviewed; clause inapplicable",
        )
        result = self.lib.evaluate_gate(text, "HIGH")
        self.assertEqual(result.status, "PASS")

    def test_will_not_blacklist_triggers_check(self) -> None:
        text = self._draft_with_prose_trigger(
            "the assumption that the project will not blacklist the attacker",
            item_9_value="reviewed",
        )
        result = self.lib.evaluate_gate(text, "HIGH")
        self.assertEqual(result.status, "FAIL")


class LocalPathInPocTests(unittest.TestCase):
    def setUp(self) -> None:
        self.lib = _load_lib()

    def test_tilde_audits_path_fails(self) -> None:
        text = textwrap.dedent(
            """
            **Severity:** High

            ## Production Path

            1. In-scope asset: Foo
            2. Affected contract / function: Foo.bar
            3. Reachability: permissionless
            4. Attacker-controlled inputs: amount
            5. Non-attacker preconditions: none
            6. Privileged roles involved: none
            7. Mock components used in PoC: none
            8. Real component replacement for each mock: n/a
            9. OOS clauses checked: section 4 reviewed
            10. Final in-scope impact: $1m

            ## PoC

            ```bash
            forge test --root ~/audits/example/
            ```
            """
        ).strip()
        result = self.lib.evaluate_gate(text, "HIGH")
        self.assertEqual(result.status, "FAIL")


class BranchPreconditionReachabilityTests(unittest.TestCase):
    def setUp(self) -> None:
        self.lib = _load_lib()

    def _base_draft(self, extra: str) -> str:
        return textwrap.dedent(
            f"""
            **Severity:** High

            ## Summary

            Parent game resolves CHALLENGER_WINS, then the child parent-loss branch pays the wrong actor.

            ## Production Path

            1. In-scope asset: AggregateVerifier
            2. Affected contract / function: resolve()
            3. Reachability: branch reached after parentGameStatus == CHALLENGER_WINS
            4. Attacker-controlled inputs: game creation
            5. Non-attacker preconditions: parent status
            6. Privileged roles involved: none claimed
            7. Mock components used in PoC: none
            8. Real component replacement for each mock: n/a
            9. OOS clauses checked: program OOS section 4.2 reviewed
            10. Final in-scope impact: bond misrouting

            {extra}
            """
        ).strip()

    def test_branch_precondition_without_reachability_section_fails(self) -> None:
        result = self.lib.evaluate_gate(self._base_draft(""), "HIGH")
        self.assertEqual(result.status, "FAIL")
        self.assertTrue(any("Precondition-Reachability" in r for r in result.reasons))

    def test_oos_only_precondition_section_fails(self) -> None:
        text = self._base_draft(
            """
            ## Precondition-Reachability

            - Path A: guardian blacklistDisputeGame admin action sets the parent invalid.
            - Path B: invalid TEE proof or ZK soundness break.
            """
        )
        result = self.lib.evaluate_gate(text, "HIGH")
        self.assertEqual(result.status, "FAIL")
        self.assertTrue(any("admin/OOS" in r for r in result.reasons))

    def test_external_in_scope_precondition_section_passes(self) -> None:
        text = self._base_draft(
            """
            ## Precondition-Reachability

            - Path A: permissionless external challenger calls challenge() and resolve()
              with no access control; scope verdict: in-scope because it uses only the
              in-scope dispute game surface.
            """
        )
        result = self.lib.evaluate_gate(text, "HIGH")
        self.assertEqual(result.status, "PASS", result.reasons)

    def test_strict_workspace_marker_requires_section_even_without_keyword(self) -> None:
        text = textwrap.dedent(
            """
            **Severity:** High

            ## Production Path

            1. In-scope asset: Foo
            2. Affected contract / function: Foo.bar
            3. Reachability: user calls bar
            4. Attacker-controlled inputs: amount
            5. Non-attacker preconditions: none
            6. Privileged roles involved: none
            7. Mock components used in PoC: none
            8. Real component replacement for each mock: n/a
            9. OOS clauses checked: section 4 reviewed
            10. Final in-scope impact: funds lost
            """
        ).strip()
        result = self.lib.evaluate_gate(text, "HIGH", strict_preconditions=True)
        self.assertEqual(result.status, "FAIL")
        self.assertTrue(any("Precondition-Reachability" in r for r in result.reasons))

    def test_users_audits_path_fails(self) -> None:
        text = textwrap.dedent(
            """
            **Severity:** High

            ## Production Path

            1. In-scope asset: Foo
            2. Affected contract / function: Foo.bar
            3. Reachability: permissionless
            4. Attacker-controlled inputs: amount
            5. Non-attacker preconditions: none
            6. Privileged roles involved: none
            7. Mock components used in PoC: none
            8. Real component replacement for each mock: n/a
            9. OOS clauses checked: section 4 reviewed
            10. Final in-scope impact: $1m

            ## PoC

            See `/Users/alice/audits/example/poc.t.sol`.
            """
        ).strip()
        result = self.lib.evaluate_gate(text, "HIGH")
        self.assertEqual(result.status, "FAIL")


# ---------------------------------------------------------------------------
# A1 bash gate integration
# ---------------------------------------------------------------------------


class BashGateIntegrationTests(unittest.TestCase):
    """Confirm Check #27 wires through the bash script + lib correctly."""

    def test_check27_label_appears_in_output(self) -> None:
        proc = _run_pre_submit(
            FIXTURES_DIR / "fn1_real_branch_passes.md", severity="High"
        )
        self.assertIn("27. Production-path gate (V4 §2 A1)", proc.stdout)

    def test_check27_pass_does_not_increment_fails(self) -> None:
        proc = _run_pre_submit(
            FIXTURES_DIR / "fn1_real_branch_passes.md", severity="High"
        )
        self.assertIn("✅ 27. production-path:", proc.stdout)

    def test_check27_fail_signature_on_fn5(self) -> None:
        proc = _run_pre_submit(
            FIXTURES_DIR / "fn5_mock_verifier_critical_fails.md",
            severity="Critical",
        )
        self.assertIn("❌ 27. production-path:", proc.stdout)

    def test_check27_warn_signature_on_medium_fixture(self) -> None:
        proc = _run_pre_submit(
            FIXTURES_DIR / "medium_missing_oos_warns.md", severity="Medium"
        )
        self.assertIn("⚠️  27. production-path-warning:", proc.stdout)


# ---------------------------------------------------------------------------
# A2 manifest field tests
# ---------------------------------------------------------------------------


class ManifestFieldTests(unittest.TestCase):
    def setUp(self) -> None:
        self.lib = _load_lib()

    def test_manifest_has_required_v4_a2_keys(self) -> None:
        text = (FIXTURES_DIR / "fn1_real_branch_passes.md").read_text()
        manifest = self.lib.build_manifest(text, severity="HIGH")
        for key in (
            "section_present",
            "scope_asset",
            "affected_code",
            "attacker_controlled_inputs",
            "privileged_preconditions",
            "mock_components",
            "real_component_replacements",
            "oos_clauses_checked",
            "impact_mapping",
        ):
            self.assertIn(key, manifest, f"manifest missing required key {key}")

    def test_manifest_section_present_true_when_section_exists(self) -> None:
        text = (FIXTURES_DIR / "fn1_real_branch_passes.md").read_text()
        manifest = self.lib.build_manifest(text, severity="HIGH")
        self.assertTrue(manifest["section_present"])
        self.assertIn("AggregateVerifier", manifest["scope_asset"])

    def test_manifest_section_present_false_when_section_missing(self) -> None:
        text = "**Severity:** High\n\n## Impact\n\nNothing.\n"
        manifest = self.lib.build_manifest(text, severity="HIGH")
        self.assertFalse(manifest["section_present"])
        self.assertEqual(manifest["scope_asset"], "")
        self.assertEqual(manifest["mock_components"], [])
        self.assertEqual(manifest["missing_items"], list(range(1, 11)))

    def test_manifest_detects_mock_triggers(self) -> None:
        text = (FIXTURES_DIR / "fn5_mock_verifier_critical_fails.md").read_text()
        manifest = self.lib.build_manifest(text, severity="CRITICAL")
        self.assertIn("MockVerifier", manifest["mock_triggers_detected"])

    def test_manifest_detects_local_paths(self) -> None:
        text = (FIXTURES_DIR / "local_path_in_poc_fails.md").read_text()
        manifest = self.lib.build_manifest(text, severity="HIGH")
        self.assertTrue(
            any("~/audits/" in p for p in manifest["local_paths_in_poc"]),
            f"manifest local_paths_in_poc={manifest['local_paths_in_poc']}",
        )

    def test_packager_wrapper_adds_gate_status(self) -> None:
        """Packager's ``build_production_path_manifest`` wraps ``build_manifest``
        with gate evaluation; downstream consumers can read ``gate_status``
        directly out of the bundle's manifest.json."""
        name = "_packager_test"
        if name in sys.modules:
            module = sys.modules[name]
        else:
            spec = importlib.util.spec_from_file_location(
                name, ROOT / "tools" / "submission-packager.py"
            )
            assert spec is not None and spec.loader is not None
            module = importlib.util.module_from_spec(spec)
            sys.modules[name] = module
            spec.loader.exec_module(module)
        manifest = module.build_production_path_manifest(
            FIXTURES_DIR / "fn5_mock_verifier_critical_fails.md",
            severity="CRITICAL",
        )
        self.assertIn("gate_status", manifest)
        self.assertEqual(manifest["gate_status"], "FAIL")
        self.assertTrue(manifest["gate_reasons"])


# ---------------------------------------------------------------------------
# A3 LLM verdict block parsing
# ---------------------------------------------------------------------------


class LLMVerdictParseTests(unittest.TestCase):
    def setUp(self) -> None:
        self.mod = _load_llm_scope_triage()

    def _full_response(self, json_block: str) -> str:
        # The legacy four lines must precede the JSON block.
        return textwrap.dedent(
            f"""
            SCOPE: IN_SCOPE
            SEVERITY: High
            CONFIDENCE: HIGH
            RATIONALE: The finding cites a real production path with no
            mock contamination.

            ```json PRODUCTION_PATH
            {json_block}
            ```
            """
        ).strip()

    def test_parser_extracts_production_path_block(self) -> None:
        response = self._full_response(
            json.dumps(
                {
                    "production_path_verdict": "PROVEN",
                    "scope_verdict": "IN_SCOPE",
                    "severity_verdict": "SUPPORTED",
                    "mock_contamination": "NONE",
                    "blocking_quotes": [],
                    "required_fix": "ship as-is",
                }
            )
        )
        parsed = self.mod.parse_triage_verdict(response)
        self.assertIsNotNone(parsed["production_path"])
        self.assertEqual(
            parsed["production_path"]["production_path_verdict"], "PROVEN"
        )
        self.assertEqual(parsed["production_path"]["scope_verdict"], "IN_SCOPE")
        self.assertEqual(
            parsed["production_path"]["mock_contamination"], "NONE"
        )

    def test_parser_clamps_unknown_verdicts(self) -> None:
        response = self._full_response(
            json.dumps(
                {
                    "production_path_verdict": "totally-broken",
                    "scope_verdict": "fishy",
                    "severity_verdict": "SUPPORTED",
                    "mock_contamination": "weird",
                    "blocking_quotes": ["quote"],
                    "required_fix": "fix me",
                }
            )
        )
        parsed = self.mod.parse_triage_verdict(response)
        pp = parsed["production_path"]
        # Unknown values clamp to the helper's default (UNCLEAR for verdict
        # enums; NONE for mock_contamination).
        self.assertIn(
            pp["production_path_verdict"],
            self.mod.PRODUCTION_PATH_VERDICTS,
        )
        self.assertIn(pp["scope_verdict"], self.mod.SCOPE_VERDICTS)
        self.assertIn(pp["mock_contamination"], self.mod.MOCK_CONTAMINATION_VERDICTS)

    def test_parser_returns_none_when_block_absent(self) -> None:
        response = textwrap.dedent(
            """
            SCOPE: IN_SCOPE
            SEVERITY: High
            CONFIDENCE: HIGH
            RATIONALE: legacy response without the V4 block.
            """
        ).strip()
        parsed = self.mod.parse_triage_verdict(response)
        self.assertIsNone(parsed["production_path"])
        # Legacy fields still parse — backwards-compat contract.
        self.assertEqual(parsed["scope"], "IN_SCOPE")
        self.assertEqual(parsed["severity"], "High")

    def test_consensus_advisory_flag_always_true(self) -> None:
        """V4 §2 A3 explicit: LLM verdict stays advisory until calibration."""
        kimi = {
            "production_path_verdict": "MISSING",
            "scope_verdict": "OOS",
            "severity_verdict": "OVERCLAIMED",
            "mock_contamination": "UNDISCLOSED",
            "blocking_quotes": ["forged proof"],
        }
        minimax = {
            "production_path_verdict": "MISSING",
            "scope_verdict": "OOS",
            "severity_verdict": "OVERCLAIMED",
            "mock_contamination": "UNDISCLOSED",
            "blocking_quotes": ["forged proof"],
        }
        consensus = self.mod.compute_production_path_consensus(kimi, minimax)
        self.assertTrue(consensus["advisory"])
        self.assertEqual(consensus["agreement"], "BOTH")
        self.assertEqual(consensus["production_path_verdict"], "MISSING")

    def test_consensus_disagreement_marks_disagreed(self) -> None:
        kimi = {
            "production_path_verdict": "PROVEN",
            "scope_verdict": "IN_SCOPE",
            "severity_verdict": "SUPPORTED",
            "mock_contamination": "NONE",
            "blocking_quotes": [],
        }
        minimax = {
            "production_path_verdict": "MISSING",
            "scope_verdict": "OOS",
            "severity_verdict": "OVERCLAIMED",
            "mock_contamination": "UNDISCLOSED",
            "blocking_quotes": ["forged proof"],
        }
        consensus = self.mod.compute_production_path_consensus(kimi, minimax)
        self.assertEqual(consensus["agreement"], "DISAGREED")
        self.assertEqual(consensus["production_path_verdict"], "DISAGREED")
        self.assertTrue(consensus["advisory"])

    def test_consensus_one_side_only(self) -> None:
        kimi = {
            "production_path_verdict": "PROVEN",
            "scope_verdict": "IN_SCOPE",
            "severity_verdict": "SUPPORTED",
            "mock_contamination": "NONE",
            "blocking_quotes": [],
        }
        consensus = self.mod.compute_production_path_consensus(kimi, None)
        self.assertEqual(consensus["agreement"], "ONE_SIDE")
        self.assertEqual(consensus["production_path_verdict"], "PROVEN")
        self.assertTrue(consensus["advisory"])


# ---------------------------------------------------------------------------
# Manifest CLI smoke
# ---------------------------------------------------------------------------


class ManifestCliTests(unittest.TestCase):
    def test_manifest_cli_emits_valid_json(self) -> None:
        proc = _run_lib_cli(
            FIXTURES_DIR / "fn1_real_branch_passes.md",
            severity="High",
            manifest=True,
        )
        self.assertEqual(proc.returncode, 0)
        data = json.loads(proc.stdout)
        self.assertTrue(data["section_present"])
        self.assertIn("AggregateVerifier", data["scope_asset"])
        self.assertEqual(data["severity"], "HIGH")


if __name__ == "__main__":
    unittest.main()
