from __future__ import annotations

import importlib.util
import py_compile
import re
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


HERE = Path(__file__).resolve().parent
REPO_ROOT = HERE.parent.parent
RUST_DETECT = REPO_ROOT / "tools" / "rust-detect.py"
WAVE1_DIR = REPO_ROOT / "detectors" / "rust_wave1"
FIXTURES = WAVE1_DIR / "test_fixtures"

DETECTOR = "rust_bridge_destination_frontrun_after_approve_fire30"
DETECTOR_ID = f"rust_wave1.{DETECTOR}"
DETECTOR_PATH = WAVE1_DIR / f"{DETECTOR}.py"
POSITIVE = FIXTURES / f"{DETECTOR}_positive.rs"
NEGATIVE = FIXTURES / f"{DETECTOR}_negative.rs"
LEGACY_POSITIVE = FIXTURES / "r94_loop_bridge_destination_frontrun_after_approve_positive.rs"
_HIT_RE = re.compile(rf"^=== {re.escape(DETECTOR)}\s+\((\d+) hits\)", re.MULTILINE)


def _run_fixture(fixture: Path) -> tuple[int, str]:
    with tempfile.NamedTemporaryFile(suffix=".log", delete=False) as tmp:
        log_path = Path(tmp.name)
    try:
        proc = subprocess.run(
            [
                sys.executable,
                str(RUST_DETECT),
                str(FIXTURES),
                "--only",
                DETECTOR,
                "--file",
                str(fixture),
                "--log",
                str(log_path),
            ],
            cwd=REPO_ROOT,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            check=False,
            timeout=60,
        )
        if proc.returncode != 0:
            raise AssertionError(proc.stderr or proc.stdout)
        log_text = log_path.read_text(encoding="utf-8", errors="ignore")
        match = _HIT_RE.search(log_text)
        return (int(match.group(1)) if match else 0), log_text
    finally:
        log_path.unlink(missing_ok=True)


def _load_detector():
    wave1_path = str(WAVE1_DIR)
    if wave1_path not in sys.path:
        sys.path.insert(0, wave1_path)
    spec = importlib.util.spec_from_file_location(DETECTOR, DETECTOR_PATH)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)  # type: ignore[union-attr]
    return module


class RustBridgeDestinationFrontrunAfterApproveFire30Tests(unittest.TestCase):
    def test_detector_compiles(self) -> None:
        py_compile.compile(str(DETECTOR_PATH), doraise=True)

    def test_detector_and_fixture_sources_are_aligned(self) -> None:
        detector_text = DETECTOR_PATH.read_text(encoding="utf-8")
        positive_text = POSITIVE.read_text(encoding="utf-8")
        negative_text = NEGATIVE.read_text(encoding="utf-8")

        self.assertIn(DETECTOR_ID, detector_text)
        self.assertIn("bridge-proof-domain-bypass", detector_text)
        self.assertIn("bridge-replay-key-omits-chain-domain", detector_text)
        self.assertIn("bridge-proof-domain-bypass-umbrella", detector_text)
        self.assertIn("message-in-success-with-zero-amount-mints-token", detector_text)
        self.assertIn("NOT_SUBMIT_READY", detector_text)

        self.assertIn("destination_chain", positive_text)
        self.assertIn("channel_id", positive_text)
        self.assertIn("destination", positive_text)
        self.assertIn("token_owner.require_auth()", positive_text)
        self.assertIn(
            "sha256(&(token_owner.clone(), token_id, payload_hash(&payload)))",
            positive_text,
        )

        self.assertIn("require_auth_for_args", negative_text)
        self.assertIn("destination_chain", negative_text)
        self.assertIn("channel_id", negative_text)
        self.assertIn("destination.clone()", negative_text)
        self.assertIn("BRIDGE_DESTINATION_AUTH_V1", negative_text)

    def test_positive_fixture_fires_and_negative_fixture_is_silent(self) -> None:
        positive_hits, positive_log = _run_fixture(POSITIVE)
        negative_hits, negative_log = _run_fixture(NEGATIVE)

        self.assertEqual(positive_hits, 1, positive_log)
        self.assertEqual(negative_hits, 0, negative_log)
        self.assertIn("bridge_nft", positive_log)
        self.assertIn("destination_chain", positive_log)
        self.assertIn("channel_or_lane", positive_log)
        self.assertIn("bridge-proof-domain-bypass", positive_log)
        self.assertIn("NOT_SUBMIT_READY", positive_log)

    def test_legacy_r94_fixture_now_fires_under_fire30_detector(self) -> None:
        hits, log_text = _run_fixture(LEGACY_POSITIVE)
        self.assertEqual(hits, 1, log_text)
        self.assertIn("moves an owner asset after approval", log_text)

    def test_scan_file_metadata_marks_candidate_boundary(self) -> None:
        module = _load_detector()
        hits = module.scan_file(str(POSITIVE))
        self.assertEqual(len(hits), 1, hits)
        hit = hits[0]
        self.assertEqual(hit["detector_id"], DETECTOR_ID)
        self.assertEqual(hit["attack_class"], "bridge-proof-domain-bypass")
        self.assertEqual(hit["submission_posture"], "NOT_SUBMIT_READY")
        self.assertEqual(hit["severity"], "high")
        self.assertEqual(hit["fn_name"], "bridge_nft")
        self.assertIn("destination_chain", hit["destination_groups"])
        self.assertIn("channel_or_lane", hit["destination_groups"])


if __name__ == "__main__":
    unittest.main()
