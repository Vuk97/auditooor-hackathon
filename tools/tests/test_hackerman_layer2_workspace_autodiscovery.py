#!/usr/bin/env python3
"""Tests for Gap #33 Layer-2 callable workspace-auto-discovery.

Lane CAPABILITY-GAPS-33-35-HACKER-MCP-USABILITY (2026-05-26).

When workers call the 4 Layer-2 hacker MCP callables with ONLY a
``workspace_path`` (no typed inputs), each callable now auto-derives
its missing inputs from the workspace state (LIVE_TARGET_REPORT.json,
scope.json, BRAIN_PRIMING_REPORT.md, engage_report.md). This file
locks the behaviour with focused unit tests.

Targets:
- ``vault_function_mindset``
- ``vault_attack_class_evidence_v3``
- ``vault_adversarial_hypothesis_differential``
- ``vault_hacker_brief_for_lane_v3``
"""
from __future__ import annotations

import importlib.util
import json
import sys
import tempfile
import unittest
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[2]
SERVER_PATH = REPO_ROOT / "tools" / "vault-mcp-server.py"


def _load_server_module():
    spec = importlib.util.spec_from_file_location("vault_server_for_layer2_test", SERVER_PATH)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"could not load {SERVER_PATH}")
    mod = importlib.util.module_from_spec(spec)
    sys.modules["vault_server_for_layer2_test"] = mod
    spec.loader.exec_module(mod)
    return mod


SERVER = _load_server_module()


def _make_workspace(tmp: Path, slug: str = "hyperbridge") -> Path:
    ws = tmp / slug
    ws.mkdir(parents=True, exist_ok=True)
    (ws / "src").mkdir(exist_ok=True)
    (ws / "src" / "Foo.sol").write_text("contract Foo {\n  function bar() public {}\n}\n")
    (ws / "src" / "Bar.sol").write_text("contract Bar {\n  function baz() public {}\n}\n")
    (ws / "docs").mkdir(exist_ok=True)
    live = {
        "schema": "auditooor.live_target_intelligence.v3",
        "workspace": str(ws),
        "entry_points": [
            {
                "cluster_id": "fee-on-transfer-not-accounted",
                "file_line": "src/Foo.sol:42",
                "hunt_priority": "HIGH-PRIORITY-HUNT",
                "matched_anti_patterns": ["solidity.fee-on-transfer"],
                "engage_severity_score": 50.0,
            },
            {
                "cluster_id": "reentrancy-no-guard",
                "file_line": "src/Bar.sol:10",
                "hunt_priority": "HIGH-PRIORITY-HUNT",
                "matched_anti_patterns": ["solidity.reentrancy"],
                "engage_severity_score": 60.0,
            },
        ],
    }
    (ws / "docs" / "LIVE_TARGET_REPORT.json").write_text(json.dumps(live, indent=2))
    scope = {
        "platform": "TestPlatform",
        "program": slug,
        "targets": [
            {
                "repo_url": f"https://github.com/example/{slug}",
                "pin": "deadbeef",
                "local_name": slug,
                "type": "Bridge",
                "asset_class": "Smart Contract",
                "max_severity": "Critical",
            }
        ],
    }
    (ws / "scope.json").write_text(json.dumps(scope, indent=2))
    (ws / "SCOPE.md").write_text(f"# {slug} Scope\n")
    (ws / "engage_report.md").write_text("# engage\n")
    (ws / "BRAIN_PRIMING_REPORT.md").write_text(
        f"# Brain Priming Report - {slug}\n\nLanguage: `solidity`\n"
    )
    return ws


class TestWorkspaceAutoDiscoveryHelper(unittest.TestCase):
    """Direct unit tests for ``_workspace_auto_discover_inputs``."""

    def _vault(self):
        return SERVER.VaultQuery(SERVER.Path(REPO_ROOT))

    def test_empty_workspace_returns_safe_defaults(self):
        v = self._vault()
        out = v._workspace_auto_discover_inputs("")
        self.assertEqual(out["workspace_slug"], "")
        self.assertEqual(out["top_attack_classes"], [])
        self.assertEqual(out["source_paths"], [])

    def test_missing_workspace_dir_returns_safe_defaults(self):
        v = self._vault()
        out = v._workspace_auto_discover_inputs("/nonexistent/abcdef")
        self.assertEqual(out["workspace_slug"], "")

    def test_workspace_with_live_target_report(self):
        v = self._vault()
        with tempfile.TemporaryDirectory() as tmp:
            ws = _make_workspace(Path(tmp))
            out = v._workspace_auto_discover_inputs(str(ws))
            self.assertEqual(out["workspace_slug"], "hyperbridge")
            self.assertEqual(out["target_repo"], "example/hyperbridge")
            self.assertEqual(out["target_domain"], "bridge")
            self.assertEqual(out["primary_language"], "solidity")
            self.assertIn("fee-on-transfer-not-accounted", out["top_attack_classes"])
            self.assertIn("reentrancy-no-guard", out["top_attack_classes"])
            self.assertEqual(out["representative_attack_class"], "fee-on-transfer-not-accounted")
            self.assertEqual(out["representative_file_path"], "src/Foo.sol")
            # All 4 workspace artifacts visible to the helper
            self.assertIn("docs/LIVE_TARGET_REPORT.json", out["available_workspace_state"])
            self.assertIn("scope.json", out["available_workspace_state"])
            self.assertIn("SCOPE.md", out["available_workspace_state"])
            # source_paths resolved to existing files
            self.assertGreater(len(out["source_paths"]), 0)
            for sp in out["source_paths"]:
                self.assertTrue(Path(sp).is_file())

    def test_unknown_workspace_falls_back_to_bridge_domain(self):
        v = self._vault()
        with tempfile.TemporaryDirectory() as tmp:
            ws = _make_workspace(Path(tmp), slug="someunknownproj")
            out = v._workspace_auto_discover_inputs(str(ws))
            self.assertEqual(out["workspace_slug"], "someunknownproj")
            self.assertEqual(out["target_domain"], "bridge")


class TestFunctionMindsetWorkspaceAutoDiscovery(unittest.TestCase):
    """`vault_function_mindset` accepts workspace_path and auto-derives."""

    def _vault(self):
        return SERVER.VaultQuery(SERVER.Path(REPO_ROOT))

    def test_workspace_only_call_no_longer_degrades(self):
        v = self._vault()
        with tempfile.TemporaryDirectory() as tmp:
            ws = _make_workspace(Path(tmp))
            out = v.vault_function_mindset(workspace_path=str(ws))
            # No degraded for missing target_repo/file_path now
            self.assertIn("workspace_auto_discovery", out)
            ad = out["workspace_auto_discovery"]
            self.assertEqual(ad["target_repo"], "example/hyperbridge")
            self.assertEqual(ad["representative_file_path"], "src/Foo.sol")
            # Target picked up the auto-discovered values
            target = out.get("target") or {}
            self.assertEqual(target.get("repo"), "example/hyperbridge")
            self.assertEqual(target.get("file_path"), "src/Foo.sol")

    def test_explicit_target_repo_overrides_auto_discovery(self):
        v = self._vault()
        with tempfile.TemporaryDirectory() as tmp:
            ws = _make_workspace(Path(tmp))
            out = v.vault_function_mindset(
                workspace_path=str(ws),
                target_repo="user/explicit-repo",
                file_path="some/explicit.sol",
            )
            target = out.get("target") or {}
            self.assertEqual(target.get("repo"), "user/explicit-repo")
            self.assertEqual(target.get("file_path"), "some/explicit.sol")


class TestAttackClassEvidenceV3WorkspaceAutoDiscovery(unittest.TestCase):
    """`vault_attack_class_evidence_v3` accepts workspace_path."""

    def _vault(self):
        return SERVER.VaultQuery(SERVER.Path(REPO_ROOT))

    def test_workspace_only_call_no_longer_degrades_for_missing_attack_class(self):
        v = self._vault()
        with tempfile.TemporaryDirectory() as tmp:
            ws = _make_workspace(Path(tmp))
            out = v.vault_attack_class_evidence_v3(workspace_path=str(ws))
            # degraded=False; attack_class auto-set
            self.assertFalse(out.get("degraded"))
            self.assertEqual(out.get("attack_class"), "fee-on-transfer-not-accounted")
            self.assertIn("workspace_auto_discovery", out)
            ad = out["workspace_auto_discovery"]
            self.assertEqual(ad["representative_attack_class"], "fee-on-transfer-not-accounted")

    def test_explicit_attack_class_overrides_auto_discovery(self):
        v = self._vault()
        with tempfile.TemporaryDirectory() as tmp:
            ws = _make_workspace(Path(tmp))
            out = v.vault_attack_class_evidence_v3(
                workspace_path=str(ws),
                attack_class="explicit-class-foo",
            )
            self.assertEqual(out.get("attack_class"), "explicit-class-foo")


class TestAdversarialHypothesisDifferentialWorkspaceAutoDiscovery(unittest.TestCase):
    """`vault_adversarial_hypothesis_differential` accepts workspace_path."""

    def _vault(self):
        return SERVER.VaultQuery(SERVER.Path(REPO_ROOT))

    def test_workspace_only_call_derives_source_paths(self):
        v = self._vault()
        with tempfile.TemporaryDirectory() as tmp:
            ws = _make_workspace(Path(tmp))
            out = v.vault_adversarial_hypothesis_differential(
                workspace_path=str(ws),
                max_functions=5,
                max_hypotheses_per_function=1,
            )
            self.assertFalse(out.get("degraded"))
            self.assertIn("workspace_auto_discovery", out)
            ad = out["workspace_auto_discovery"]
            self.assertGreater(len(ad.get("source_paths") or []), 0)

    def test_explicit_source_paths_skip_auto_discovery(self):
        v = self._vault()
        with tempfile.TemporaryDirectory() as tmp:
            ws = _make_workspace(Path(tmp))
            explicit = ws / "src" / "Foo.sol"
            out = v.vault_adversarial_hypothesis_differential(
                workspace_path=str(ws),
                source_paths=[str(explicit)],
                max_functions=5,
            )
            self.assertFalse(out.get("degraded"))
            # When explicit source_paths is supplied, auto_discovery is not
            # invoked. The envelope still carries a workspace_auto_discovery
            # key (set by the envelope helper) but it should be empty / falsy.
            ad = out.get("workspace_auto_discovery")
            self.assertIn(ad, ({}, None))


class TestHackerBriefForLaneV3LaneIdFallback(unittest.TestCase):
    """`vault_hacker_brief_for_lane_v3` recovers from invalid lane_id."""

    def _vault(self):
        return SERVER.VaultQuery(SERVER.Path(REPO_ROOT))

    def test_invalid_lane_id_falls_back_to_workspace_generic(self):
        v = self._vault()
        with tempfile.TemporaryDirectory() as tmp:
            ws = _make_workspace(Path(tmp))
            out = v.vault_hacker_brief_for_lane_v3(
                workspace_path=str(ws),
                lane_id="!!! invalid !!!",
                with_severity_calibration=False,
                cross_corpus_dedupe=False,
                limit=2,
            )
            self.assertFalse(out.get("degraded"))
            self.assertEqual(out.get("lane_id"), "workspace-generic-hyperbridge")

    def test_missing_lane_id_falls_back_to_workspace_generic(self):
        v = self._vault()
        with tempfile.TemporaryDirectory() as tmp:
            ws = _make_workspace(Path(tmp))
            out = v.vault_hacker_brief_for_lane_v3(
                workspace_path=str(ws),
                with_severity_calibration=False,
                cross_corpus_dedupe=False,
                limit=2,
            )
            self.assertFalse(out.get("degraded"))
            self.assertEqual(out.get("lane_id"), "workspace-generic-hyperbridge")

    def test_explicit_lane_id_is_preserved(self):
        v = self._vault()
        with tempfile.TemporaryDirectory() as tmp:
            ws = _make_workspace(Path(tmp))
            out = v.vault_hacker_brief_for_lane_v3(
                workspace_path=str(ws),
                lane_id="H1-explicit-lane",
                with_severity_calibration=False,
                cross_corpus_dedupe=False,
                limit=2,
            )
            self.assertEqual(out.get("lane_id"), "H1-explicit-lane")


if __name__ == "__main__":
    unittest.main()
