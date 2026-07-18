from __future__ import annotations

import importlib.util
import os
import py_compile
import re
import subprocess
import sys
import unittest
from pathlib import Path


REPO = Path(__file__).resolve().parents[2]
DETECTOR_PATH = REPO / "detectors" / "wave17" / "bridge_message_channel_domain_fire31.py"
POSITIVE = (
    REPO
    / "detectors"
    / "test_fixtures"
    / "positive"
    / "bridge_message_channel_domain_fire31.sol"
)
NEGATIVE = (
    REPO
    / "detectors"
    / "test_fixtures"
    / "negative"
    / "bridge_message_channel_domain_fire31.sol"
)
RUNNER = REPO / "detectors" / "run_regex_detectors.py"
DETECTOR_NAME = "bridge-message-channel-domain-fire31"


def _load_detector():
    module_name = "bridge_message_channel_domain_fire31"
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


class BridgeMessageChannelDomainFire31Test(unittest.TestCase):
    def test_detector_and_test_compile(self) -> None:
        py_compile.compile(str(DETECTOR_PATH), doraise=True)
        py_compile.compile(str(Path(__file__)), doraise=True)

        detector_text = _read(DETECTOR_PATH)
        self.assertIn(f'DETECTOR_NAME = "{DETECTOR_NAME}"', detector_text)
        self.assertIn('SUBMISSION_POSTURE = "NOT_SUBMIT_READY"', detector_text)
        self.assertIn('VERIFICATION_TIER = "tier-3-synthetic-taxonomy-anchored"', detector_text)
        self.assertIn("detector_fixture_smoke_only", detector_text)
        self.assertIn("bridge-proof-domain-bypass", detector_text)
        self.assertIn("bridge-replay-key-omits-chain-domain", detector_text)
        self.assertIn("bridge-receiver-domain-omitted-from-proof-digest", detector_text)
        self.assertIn("message root or commitment", detector_text)
        self.assertIn("channel, lane, destination chain, or application", detector_text)

    def test_fixture_pair_contains_semantic_contrast(self) -> None:
        positive = _read(POSITIVE)
        negative = _read(NEGATIVE)

        self.assertIn("function executeChannelMessage(", positive)
        self.assertIn("channelId", positive)
        self.assertIn("laneId", positive)
        self.assertIn("destinationChainId", positive)
        self.assertIn("application", positive)
        self.assertIn(
            "keccak256(abi.encode(messageRoot, commitment, nonce, keccak256(payload)))",
            positive,
        )
        self.assertIn("processedMessages[replayKey] = true;", positive)
        self.assertNotIn("BRIDGE_CHANNEL_DOMAIN_FIRE31", positive)
        self.assertNotIn("address(this)", positive)

        self.assertIn("BRIDGE_CHANNEL_DOMAIN_FIRE31", negative)
        self.assertIn("destinationChainId == block.chainid", negative)
        self.assertIn("bytes32 replayKey = keccak256(", negative)
        self.assertIn("channelId,\n                laneId", negative)
        self.assertIn("destinationChainId,\n                application", negative)
        self.assertIn("address(this),\n                nonce", negative)
        self.assertIn("messageRoot,\n                commitment", negative)
        self.assertIn("processedMessages[replayKey] = true;", negative)

    def test_positive_fixture_fires_and_negative_fixture_is_silent(self) -> None:
        detector = _load_detector()
        positive = detector.scan(_read(POSITIVE), str(POSITIVE))
        negative = detector.scan(_read(NEGATIVE), str(NEGATIVE))

        self.assertEqual(len(positive), 1)
        self.assertEqual(negative, [])
        self.assertEqual(positive[0].detector, DETECTOR_NAME)
        self.assertEqual(positive[0].severity, "High")
        self.assertEqual(positive[0].function, "executeChannelMessage")
        self.assertIn("channel id", positive[0].message)
        self.assertIn("lane id", positive[0].message)
        self.assertIn("destination chain id", positive[0].message)
        self.assertIn("application address", positive[0].message)
        self.assertIn("NOT_SUBMIT_READY", positive[0].message)

    def test_regex_runner_discovers_detector_for_owned_fixture_pair(self) -> None:
        env = os.environ.copy()
        env["PYTHONDONTWRITEBYTECODE"] = "1"

        for fixture, expected_hits in ((POSITIVE, 1), (NEGATIVE, 0)):
            with self.subTest(fixture=fixture.name):
                proc = subprocess.run(
                    [
                        sys.executable,
                        str(RUNNER),
                        str(fixture),
                        "--detector",
                        DETECTOR_NAME,
                        "--no-manifest",
                    ],
                    cwd=REPO,
                    env=env,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.STDOUT,
                    text=True,
                    timeout=30,
                )
                self.assertEqual(proc.returncode, 0, proc.stdout)
                self.assertNotIn("No custom detectors found", proc.stdout)
                match = re.search(r"total hits:\s*(\d+)", proc.stdout)
                self.assertIsNotNone(match, proc.stdout)
                self.assertEqual(int(match.group(1)), expected_hits, proc.stdout)


if __name__ == "__main__":
    unittest.main()
