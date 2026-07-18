"""Tests for SUPPRESSED_PATTERNS suppression in mining-brief-generator.

PR #120 lesson 4. Regression target: engagement-4 Polymarket re-runs kept
re-emitting briefs for the same six saturated pattern-class clusters
(delegatecall-onlyOwner, NegRisk-race-dupe, UMA-public-by-design,
BulletinBoard-off-chain, UserPausable-msg.sender, Solady-vs-ERC4626 detector
FP). The suppression filter lets workspace operators record per-cluster
fingerprints + clearance cites so subsequent runs auto-drop them and emit a
ledger explaining why.
"""

from __future__ import annotations

import importlib.util
import json
import sys
import unittest
from pathlib import Path
import tempfile


REPO = Path(__file__).resolve().parents[2]
TOOL = REPO / "tools" / "mining-brief-generator.py"
TOOLS_DIR = REPO / "tools"


def _load_module():
    # mining-brief-generator.py uses sibling-module imports
    # (`from submission_ledger import ...`). Make tools/ importable
    # before loading by file path.
    if str(TOOLS_DIR) not in sys.path:
        sys.path.insert(0, str(TOOLS_DIR))
    spec = importlib.util.spec_from_file_location("mining_brief_generator", TOOL)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


class SuppressionLoaderTest(unittest.TestCase):
    def test_missing_file_returns_empty(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp)
            mod = _load_module()
            self.assertEqual(mod.load_suppressed_patterns(ws), [])

    def test_invalid_json_is_non_fatal(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp)
            (ws / "SUPPRESSED_PATTERNS.json").write_text("{not json")
            mod = _load_module()
            self.assertEqual(mod.load_suppressed_patterns(ws), [])

    def test_loads_workspace_local_json(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp)
            (ws / "SUPPRESSED_PATTERNS.json").write_text(json.dumps({
                "suppressions": [
                    {
                        "id": "solady_erc20_not_erc4626",
                        "angle_id": "A-ERC4626",
                        "contract_regex": r"^(CollateralToken|WrappedCollateral)$",
                        "clearance_cite": "FINDINGS.md:921 #R18.8",
                        "reason": "Solady ERC20 + WRAPPER_ROLE 1:1 wrap/unwrap",
                    }
                ]
            }))
            mod = _load_module()
            rules = mod.load_suppressed_patterns(ws)
        self.assertEqual(len(rules), 1)
        self.assertEqual(rules[0]["id"], "solady_erc20_not_erc4626")

    def test_audit_subdir_takes_precedence_when_present(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp)
            (ws / "audit").mkdir()
            (ws / "audit" / "SUPPRESSED_PATTERNS.json").write_text(json.dumps({
                "suppressions": [
                    {"id": "from_audit_subdir", "angle_id": "A-X",
                     "clearance_cite": "audit/x.md"},
                ]
            }))
            (ws / "SUPPRESSED_PATTERNS.json").write_text(json.dumps({
                "suppressions": [
                    {"id": "from_root", "angle_id": "A-Y",
                     "clearance_cite": "root.md"},
                ]
            }))
            mod = _load_module()
            rules = mod.load_suppressed_patterns(ws)
        # Both load (no precedence override semantics — operators can put
        # rules in either spot). The order is audit/ first per
        # _suppression_candidate_paths().
        ids = [r["id"] for r in rules]
        self.assertEqual(ids, ["from_audit_subdir", "from_root"])

    def test_rule_with_all_empty_patterns_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp)
            (ws / "SUPPRESSED_PATTERNS.json").write_text(json.dumps({
                "suppressions": [
                    {"id": "would_kill_everything", "clearance_cite": "x"},
                ]
            }))
            mod = _load_module()
            rules = mod.load_suppressed_patterns(ws)
        self.assertEqual(rules, [])

    def test_rule_without_clearance_cite_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp)
            (ws / "SUPPRESSED_PATTERNS.json").write_text(json.dumps({
                "suppressions": [
                    {"id": "no_cite", "angle_id": "A-X"},
                ]
            }))
            mod = _load_module()
            rules = mod.load_suppressed_patterns(ws)
        # Audit hygiene: every closure must be human-verifiable.
        self.assertEqual(rules, [])


class SuppressionMatcherTest(unittest.TestCase):
    def test_matches_on_angle_id_alone(self) -> None:
        mod = _load_module()
        rules = [{
            "id": "kill_reent", "angle_id": "A-REENT",
            "contract_regex": "", "detector_regex": "", "title_regex": "",
            "clearance_cite": "x", "reason": "y", "scope": "workspace",
        }]
        self.assertEqual(
            mod.is_angle_suppressed({"id": "A-REENT", "title": "anything"}, rules)["id"],
            "kill_reent",
        )
        self.assertIsNone(
            mod.is_angle_suppressed({"id": "A-OTHER", "title": "anything"}, rules)
        )

    def test_matches_on_contract_regex(self) -> None:
        mod = _load_module()
        rules = [{
            "id": "solady", "angle_id": "",
            "contract_regex": r"^(CollateralToken|WrappedCollateral)$",
            "detector_regex": "", "title_regex": "",
            "clearance_cite": "x", "reason": "y", "scope": "workspace",
        }]
        # Match if any of the angle's contracts hits.
        self.assertIsNotNone(
            mod.is_angle_suppressed(
                {"id": "A-X", "contracts": ["WrappedCollateral", "Other"]},
                rules,
            )
        )
        # No match if no contract matches.
        self.assertIsNone(
            mod.is_angle_suppressed(
                {"id": "A-X", "contracts": ["Trading", "Vault"]},
                rules,
            )
        )

    def test_matches_combined_angle_id_and_contract(self) -> None:
        """Both predicates must hold (AND semantics, not OR)."""
        mod = _load_module()
        rules = [{
            "id": "narrow",
            "angle_id": "A-AUTH",
            "contract_regex": r"^Foo$",
            "detector_regex": "", "title_regex": "",
            "clearance_cite": "x", "reason": "y", "scope": "workspace",
        }]
        self.assertIsNotNone(mod.is_angle_suppressed(
            {"id": "A-AUTH", "contracts": ["Foo"]}, rules))
        # Wrong angle, right contract.
        self.assertIsNone(mod.is_angle_suppressed(
            {"id": "A-RACE", "contracts": ["Foo"]}, rules))
        # Right angle, wrong contract.
        self.assertIsNone(mod.is_angle_suppressed(
            {"id": "A-AUTH", "contracts": ["Bar"]}, rules))

    def test_invalid_regex_falls_back_to_substring(self) -> None:
        """A bad operator regex must not silently fail to suppress —
        fall back to substring containment."""
        mod = _load_module()
        rules = [{
            "id": "bad_regex", "angle_id": "[unclosed",
            "contract_regex": "", "detector_regex": "", "title_regex": "",
            "clearance_cite": "x", "reason": "y", "scope": "workspace",
        }]
        # angle id contains the literal pattern as substring.
        self.assertIsNotNone(mod.is_angle_suppressed(
            {"id": "A-[unclosed-foo"}, rules))
        # angle id does not contain it.
        self.assertIsNone(mod.is_angle_suppressed({"id": "A-OTHER"}, rules))


class ImpactContractGateTest(unittest.TestCase):
    def test_ranked_row_missing_impact_contract_renders_blocking_gate(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp)
            mod = _load_module()
            angle = {
                "id": "A-RACE",
                "severity": "HIGH",
                "title": "Cross-contract stale state",
                "contracts": ["Market"],
                "line": 42,
                "_ranked_priority_row": {
                    "impact_contract_required": True,
                    "impact_contract_id": "",
                    "candidate_kind": "detector_harness_task_candidate",
                },
            }
            brief = mod.generate_brief(
                angle,
                1,
                9.0,
                ws,
                [],
                [],
                [],
                {},
                {},
                {},
                "missing",
                [],
            )
        self.assertIn("## Impact Contract Gate", brief)
        self.assertIn("Status: `blocked_missing_impact_contract`", brief)
        self.assertIn("Impact contract: `MISSING`", brief)
        self.assertIn("Do not dispatch agent, harness, PoC, severity, or report work", brief)


if __name__ == "__main__":
    unittest.main()
