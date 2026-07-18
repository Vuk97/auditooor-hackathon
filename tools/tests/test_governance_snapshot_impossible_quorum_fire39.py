from __future__ import annotations

import importlib.util
import os
import py_compile
import re
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
DETECTOR_PATH = ROOT / "detectors" / "wave17" / "governance_snapshot_impossible_quorum_fire39.py"
RUNNER = ROOT / "detectors" / "run_regex_detectors.py"
DETECTOR_NAME = "governance-snapshot-impossible-quorum-fire39"
POSITIVE = (
    ROOT
    / "detectors"
    / "test_fixtures"
    / "positive"
    / "governance_snapshot_impossible_quorum_fire39.sol"
)
NEGATIVE = (
    ROOT
    / "detectors"
    / "test_fixtures"
    / "negative"
    / "governance_snapshot_impossible_quorum_fire39.sol"
)


def _load_detector():
    module_name = "governance_snapshot_impossible_quorum_fire39"
    if module_name in sys.modules:
        return sys.modules[module_name]
    spec = importlib.util.spec_from_file_location(module_name, DETECTOR_PATH)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[module_name] = module
    spec.loader.exec_module(module)
    return module


def _read(path: Path) -> str:
    return path.read_text(encoding="utf-8")


class GovernanceSnapshotImpossibleQuorumFire39Test(unittest.TestCase):
    def test_detector_and_test_compile(self) -> None:
        py_compile.compile(str(DETECTOR_PATH), doraise=True)
        py_compile.compile(str(Path(__file__)), doraise=True)

        detector = _load_detector()
        self.assertEqual(detector.DETECTOR_NAME, DETECTOR_NAME)
        self.assertEqual(detector.DETECTOR_SEVERITY_DEFAULT, "High")
        self.assertEqual(detector.VERIFICATION_TIER, "tier-3-synthetic-taxonomy-anchored")
        self.assertEqual(detector.ATTACK_CLASS, "governance-snapshot-mismatch")

    def test_positive_fixture_flags_live_supply_quorum_against_snapshot_votes(self) -> None:
        detector = _load_detector()
        findings = detector.scan(_read(POSITIVE), str(POSITIVE))

        self.assertEqual(len(findings), 2)
        self.assertEqual({finding.detector for finding in findings}, {DETECTOR_NAME})
        self.assertEqual({finding.severity for finding in findings}, {"High"})
        self.assertEqual({finding.function for finding in findings}, {"quorum", "_quorumReached"})

        messages = "\n".join(finding.message for finding in findings)
        self.assertIn("live denominator `votesToken.totalSupply()`", messages)
        self.assertIn("snapshot-aware elsewhere", messages)
        self.assertIn("getPastTotalSupply", messages)

    def test_negative_fixture_keeps_snapshot_bound_and_bait_silent(self) -> None:
        detector = _load_detector()
        findings = detector.scan(_read(NEGATIVE), str(NEGATIVE))

        self.assertEqual(findings, [])
        clean = _read(NEGATIVE)
        self.assertIn("votesToken.getPastTotalSupply(proposal.snapshotBlock)", clean)
        self.assertIn("uint256 requiredVotes = (proposal.supplySnapshot * quorumBps) / BPS;", clean)
        self.assertIn("uint256 quorumSupply = _checkpointedSupply(proposalId);", clean)
        self.assertIn("return votesToken.totalSupply();", clean)
        self.assertIn("stringBait", clean)

    def test_semantic_boundary_requires_governance_snapshot_mismatch(self) -> None:
        detector = _load_detector()

        live_supply_without_snapshot_votes = """
        pragma solidity ^0.8.20;
        contract SupplyViewer {
            IERC20 token;
            function quorum(uint256) external view returns (uint256) {
                return token.totalSupply() / 2;
            }
        }
        interface IERC20 { function totalSupply() external view returns (uint256); }
        """
        self.assertEqual(detector.scan(live_supply_without_snapshot_votes, "viewer.sol"), [])

        snapshot_safe_with_superficial_live_supply = """
        pragma solidity ^0.8.20;
        contract SafeGovernor {
            IVotes token;
            mapping(uint256 => uint256) snapshotBlock;
            function castVote(uint256 id) external {
                token.getPastVotes(msg.sender, snapshotBlock[id]);
            }
            function quorum(uint256 id) public view returns (uint256) {
                uint256 snapshotSupply = token.getPastTotalSupply(snapshotBlock[id]);
                return snapshotSupply * 4_000 / 10_000;
            }
            function previewLiveSupply() external view returns (uint256) {
                return token.totalSupply();
            }
        }
        interface IVotes {
            function totalSupply() external view returns (uint256);
            function getPastVotes(address account, uint256 blockNumber) external view returns (uint256);
            function getPastTotalSupply(uint256 blockNumber) external view returns (uint256);
        }
        """
        self.assertEqual(detector.scan(snapshot_safe_with_superficial_live_supply, "safe.sol"), [])

    def test_regex_runner_records_positive_hits_and_negative_silence(self) -> None:
        with tempfile.TemporaryDirectory(prefix="fire39_governance_quorum_") as tmp:
            env = os.environ.copy()
            env["PYTHONDONTWRITEBYTECODE"] = "1"

            for fixture, expected_hits in ((POSITIVE, 2), (NEGATIVE, 0)):
                with self.subTest(fixture=fixture.name):
                    proc = subprocess.run(
                        [
                            sys.executable,
                            str(RUNNER),
                            str(fixture),
                            "--workspace",
                            tmp,
                            "--detector",
                            DETECTOR_NAME,
                            "--no-manifest",
                        ],
                        cwd=ROOT,
                        env=env,
                        stdout=subprocess.PIPE,
                        stderr=subprocess.STDOUT,
                        text=True,
                        timeout=30,
                    )
                    self.assertEqual(proc.returncode, 0, proc.stdout)
                    match = re.search(r"total hits:\s*(\d+)", proc.stdout)
                    self.assertIsNotNone(match, proc.stdout)
                    self.assertEqual(int(match.group(1)), expected_hits, proc.stdout)

    def test_source_refs_and_no_unicode_dashes_in_owned_sources(self) -> None:
        detector_text = _read(DETECTOR_PATH)
        self.assertIn(
            "reports/detector_lift_fire38_20260605/post_priorities_solidity.md",
            detector_text,
        )
        self.assertIn("reference/patterns.dsl/glider-impossible-quorum.yaml", detector_text)
        self.assertIn("detectors/wave17/glider_impossible_quorum.py", detector_text)
        self.assertIn("auditooor.vault_context_pack.v1:resume:cbdd9eeb5255863c", detector_text)
        self.assertIn("NOT_SUBMIT_READY", detector_text)
        self.assertIn("R40/R76/R80 caveat", detector_text)

        for path in (DETECTOR_PATH, POSITIVE, NEGATIVE, Path(__file__)):
            with self.subTest(path=path.name):
                text = path.read_text(encoding="utf-8")
                self.assertIsNone(re.search("[\u2013\u2014]", text))


if __name__ == "__main__":
    unittest.main()
