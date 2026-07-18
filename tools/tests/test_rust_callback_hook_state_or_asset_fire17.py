from __future__ import annotations

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
DETECTOR = (
    REPO_ROOT
    / "detectors"
    / "rust_wave1"
    / "callback_hook_state_or_asset_fire17.py"
)
FIXTURES = REPO_ROOT / "detectors" / "rust_wave1" / "test_fixtures"
DETECTOR_ID = "callback_hook_state_or_asset_fire17"
POSITIVE = FIXTURES / "callback_hook_state_or_asset_fire17_positive.rs"
NEGATIVE = FIXTURES / "callback_hook_state_or_asset_fire17_negative.rs"
ASSET_RELEASE_MISS = FIXTURES / "callback_hook_asset_release_fire13_positive.rs"
RECEIVER_MISS = FIXTURES / "onerc721received_never_fires_on_mint_transfer_positive.rs"
STALE_OWNER_MISS = FIXTURES / "previous_nft_owner_can_burn_nft_from_new_owner_positive.rs"
_HIT_RE = re.compile(rf"^=== {DETECTOR_ID}\s+\((\d+) hits\)", re.MULTILINE)


def _run_fixture(fixture: Path) -> tuple[int, str]:
    with tempfile.NamedTemporaryFile(prefix=".rust_callback_fire17_", suffix=".log") as tmp:
        proc = subprocess.run(
            [
                sys.executable,
                str(RUST_DETECT),
                str(FIXTURES),
                "--only",
                DETECTOR_ID,
                "--file",
                str(fixture),
                "--log",
                tmp.name,
            ],
            cwd=REPO_ROOT,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            timeout=120,
        )
        if proc.returncode != 0:
            raise AssertionError(proc.stdout)
        text = Path(tmp.name).read_text(encoding="utf-8", errors="ignore")
    match = _HIT_RE.search(text)
    return (int(match.group(1)) if match else 0, text)


class RustCallbackHookStateOrAssetFire17Test(unittest.TestCase):
    def test_detector_compiles(self) -> None:
        py_compile.compile(str(DETECTOR), doraise=True)

    def test_positive_fixture_fires_on_three_callback_hook_shapes(self) -> None:
        hits, log_text = _run_fixture(POSITIVE)
        self.assertEqual(hits, 3, log_text)
        self.assertIn("callback/hook runs", log_text)
        self.assertIn("safe ERC721 wrapper", log_text)
        self.assertIn("secondary owner map", log_text)

    def test_negative_fixture_is_silent(self) -> None:
        hits, log_text = _run_fixture(NEGATIVE)
        self.assertEqual(hits, 0, log_text)

    def test_confirmed_asset_release_miss_now_fires(self) -> None:
        hits, log_text = _run_fixture(ASSET_RELEASE_MISS)
        self.assertGreaterEqual(hits, 1, log_text)

    def test_confirmed_receiver_callback_miss_now_fires(self) -> None:
        hits, log_text = _run_fixture(RECEIVER_MISS)
        self.assertGreaterEqual(hits, 1, log_text)
        self.assertIn("safe ERC721 wrapper", log_text)

    def test_confirmed_stale_owner_miss_now_fires(self) -> None:
        hits, log_text = _run_fixture(STALE_OWNER_MISS)
        self.assertGreaterEqual(hits, 1, log_text)
        self.assertIn("secondary owner map", log_text)


if __name__ == "__main__":
    unittest.main()
