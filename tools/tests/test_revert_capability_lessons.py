from __future__ import annotations

import importlib.util
import json
import sys
import tempfile
import types
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
LESSONS = ROOT / "docs" / "CLAUDE_TAKEOVER_BURNDOWN.md"


def _write_minimal_stableswap_workspace(root: Path) -> Path:
    """Create a tiny source tree with the same routing shape as the regression."""
    files = {
        "README.md": "# StableSwap Hooks\n\nFactory-created pools with configurable fees and amplification.\n",
        "SCOPE.md": "In scope: Solidity files under src/.\n",
        "src/factories/StableSwapHooksFactory.sol": "contract StableSwapHooksFactory { function create() external {} }\n",
        "src/interfaces/IStableSwapHooks.sol": "interface IStableSwapHooks { function swap() external; }\n",
        "src/Amp.sol": "contract Amp { uint256 MAX_AMP; constructor(uint256 _baseAmp) { if (_baseAmp >= MAX_AMP) revert(); } }\n",
        "src/Base.sol": "contract Base { struct PoolKey { uint24 fee; } function init(uint256 lpFee) external { PoolKey memory k = PoolKey({fee: toUint24(lpFee)}); } function toUint24(uint256 v) internal pure returns (uint24) { return uint24(v); } }\n",
        "src/Fees.sol": "contract Fees { uint256 constant FEE_PRECISION = 1e6; function fee(uint256 lpFeePercentage, uint256 amount) external pure returns (uint256) { return amount * lpFeePercentage / FEE_PRECISION; } }\n",
        "src/Swap.sol": "contract Swap { function swap() external {} }\n",
        "src/libraries/StableSwapMath.sol": "library StableSwapMath { function calc(uint256 amplification) internal pure returns (uint256) { uint256 ampTimesCoins = amplification; return 1 / ampTimesCoins; } }\n",
    }
    for rel, text in files.items():
        path = root / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8")
    return root


def _load_tool(path: Path, module_name: str):
    tools_dir = str(ROOT / "tools")
    if tools_dir not in sys.path:
        sys.path.insert(0, tools_dir)
    spec = importlib.util.spec_from_file_location(module_name, path)
    assert spec is not None and spec.loader is not None
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


class RevertCapabilityLessonsDocTest(unittest.TestCase):
    def test_lessons_doc_records_p0_p1_regression_expectations(self) -> None:
        text = LESSONS.read_text(encoding="utf-8")

        self.assertIn("Solidity Regression Lessons", text)
        self.assertIn("Proof-readiness and submission-readiness are still too coupled", text)
        self.assertIn("Static High/Medium rows are leads, not findings", text)
        self.assertIn("nested Foundry roots", text)
        self.assertIn("Symbolic tooling needs compatibility classifications", text)


class RevertSourceMiningRoutingLessonsTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.smc = _load_tool(ROOT / "tools" / "source-mining-campaign.py", "revert_source_mining_campaign")

    def test_factory_config_liveness_slice_keeps_factory_interfaces_and_core_files(self) -> None:
        with tempfile.TemporaryDirectory(prefix="stableswap_routing_") as td:
            ws = _write_minimal_stableswap_workspace(Path(td))
            domains = self.smc.slice_domains(ws)
            routed = set(domains.get("factory-config-liveness", []))

            self.assertIn("src/factories/StableSwapHooksFactory.sol", routed)
            self.assertIn("src/interfaces/IStableSwapHooks.sol", routed)
            self.assertIn("src/Amp.sol", routed)
            self.assertIn("src/Base.sol", routed)
            self.assertIn("src/Fees.sol", routed)
            self.assertIn("src/Swap.sol", routed)

    def test_kimi_packet_preserves_top_level_truth_context_without_severity_promotion(self) -> None:
        with tempfile.TemporaryDirectory(prefix="stableswap_packet_") as td:
            ws = _write_minimal_stableswap_workspace(Path(td))
            files = self.smc.slice_domains(ws).get("factory-config-liveness", [])
            truth = self.smc._read_truth_block(ws)
            packet, coverage = self.smc.build_kimi_packet(
                workspace=ws,
                domain="factory-config-liveness",
                files=files,
                truth_block=truth,
                char_cap=250_000,
            )

            self.assertIn("=== README.md ===", packet)
            self.assertIn("target_files:", packet)
            self.assertIn("src/factories/StableSwapHooksFactory.sol", packet)
            self.assertIn("Do NOT propose severities", packet)
            self.assertIn("NOT_SUBMIT_READY", json.dumps(coverage))
            self.assertIn("src/interfaces/IStableSwapHooks.sol", coverage["files_included"])


class RevertSolidityOnlyCoverageNoiseTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.engage = _load_tool(ROOT / "tools" / "engage.py", "revert_engage")

    def test_fresh_solidity_only_workspace_warns_instead_of_failing_asset_retro_gate(self) -> None:
        with tempfile.TemporaryDirectory(prefix="revert_solidity_only_gate_") as td:
            ws = Path(td)
            (ws / "INTAKE_BASELINE.json").write_text(
                json.dumps(
                    {
                        "assets_in_scope": ["Smart Contract"],
                        "asset_coverage_plan": {
                            "Smart Contract": {
                                "roots": ["src/"],
                                "strategy": "solidity-source-mining",
                                "estimated_hours": 2,
                                "agent_hour_quota_pct": 100,
                                "plan_status": "ready",
                            }
                        },
                    }
                ),
                encoding="utf-8",
            )

            verdict, errors = self.engage._asset_retro_gate(ws)

            self.assertEqual(verdict, "warn")
            self.assertEqual(len(errors), 1)

    def test_solidity_asset_skip_still_fails_after_unrelated_dispatch_exists(self) -> None:
        with tempfile.TemporaryDirectory(prefix="revert_solidity_skip_gate_") as td:
            ws = Path(td)
            (ws / "agent_outputs").mkdir()
            (ws / "agent_outputs" / "dispatch_other.md").write_text(
                "Reviewed unrelated docs only.\n",
                encoding="utf-8",
            )
            (ws / "INTAKE_BASELINE.json").write_text(
                json.dumps(
                    {
                        "assets_in_scope": ["Smart Contract"],
                        "asset_coverage_plan": {
                            "Smart Contract": {
                                "roots": ["src/"],
                                "plan_status": "ready",
                            }
                        },
                    }
                ),
                encoding="utf-8",
            )

            verdict, errors = self.engage._asset_retro_gate(ws)

            self.assertEqual(verdict, "fail")
            self.assertEqual(len(errors), 1)


if __name__ == "__main__":
    unittest.main()
