from __future__ import annotations

import re
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


HERE = Path(__file__).resolve().parent
REPO_ROOT = HERE.parent.parent
RUST_DETECT = REPO_ROOT / "tools" / "rust-detect.py"
FIXTURES = REPO_ROOT / "detectors" / "rust_wave1" / "test_fixtures"

DETECTOR = "rust_proxy_user_controlled_delegate_target"
POSITIVE = "rust_proxy_user_controlled_delegate_target_positive.rs"
NEGATIVE = "rust_proxy_user_controlled_delegate_target_negative.rs"
_HIT_RE = re.compile(rf"^=== {re.escape(DETECTOR)}\s+\((\d+) hits\)", re.MULTILINE)


def _run_fixture(fixture_name: str) -> tuple[int, str]:
    with tempfile.NamedTemporaryFile(suffix=".log", delete=False) as tf:
        log_path = Path(tf.name)
    try:
        proc = subprocess.run(
            [
                sys.executable,
                str(RUST_DETECT),
                str(FIXTURES),
                "--only",
                DETECTOR,
                "--file",
                str(FIXTURES / fixture_name),
                "--log",
                str(log_path),
            ],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            check=False,
            timeout=30,
        )
        if proc.returncode != 0:
            raise AssertionError(proc.stderr or proc.stdout)
        text = log_path.read_text(encoding="utf-8", errors="ignore")
        match = _HIT_RE.search(text)
        return (int(match.group(1)) if match else 0), text
    finally:
        log_path.unlink(missing_ok=True)


class RustProxyUserControlledDelegateTargetTests(unittest.TestCase):
    def test_positive_fixture_flags_delegate_target_takeover(self) -> None:
        hits, log_text = _run_fixture(POSITIVE)
        self.assertEqual(hits, 1, log_text)
        self.assertIn("caller-supplied `implementation_hash`", log_text)
        self.assertIn("proxy execution authority", log_text)

    def test_negative_fixture_is_silent_with_admin_and_impl_registry(self) -> None:
        hits, log_text = _run_fixture(NEGATIVE)
        self.assertEqual(hits, 0, log_text)

    def test_positive_fixture_contains_real_execution_authority_route(self) -> None:
        positive_text = (FIXTURES / POSITIVE).read_text(encoding="utf-8")
        self.assertIn("delegate_target: Pubkey", positive_text)
        self.assertIn("proxy.delegate_target = delegate_target", positive_text)
        self.assertIn("program_id: proxy.delegate_target", positive_text)
        self.assertIn("invoke_signed", positive_text)
        self.assertNotIn("implementation_registry", positive_text)

    def test_priority_miss_delegatecall_to_user_address_is_lifted(self) -> None:
        hits, log_text = _run_fixture("delegatecall_to_user_address_positive.rs")
        self.assertEqual(hits, 1, log_text)
        self.assertIn("caller-controlled external client", log_text)

    def test_priority_miss_initializer_first_caller_route_is_lifted(self) -> None:
        hits, log_text = _run_fixture(
            "initializer_first_caller_config_takeover_positive.rs"
        )
        self.assertEqual(hits, 1, log_text)
        self.assertIn("first caller claim bridge or proxy route authority", log_text)

    def test_priority_miss_non_upgradeable_ownable_proxy_is_lifted(self) -> None:
        hits, log_text = _run_fixture(
            "r94_loop_ownable_non_upgradeable_in_proxy_positive.rs"
        )
        self.assertEqual(hits, 1, log_text)
        self.assertIn("non-upgradeable Ownable", log_text)


if __name__ == "__main__":
    unittest.main()
