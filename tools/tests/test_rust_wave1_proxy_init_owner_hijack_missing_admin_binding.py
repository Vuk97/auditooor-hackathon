from __future__ import annotations

import re
import subprocess
import sys
import tempfile
import unittest
import importlib.util
from pathlib import Path


HERE = Path(__file__).resolve().parent
REPO_ROOT = HERE.parent.parent
RUST_DETECT = REPO_ROOT / "tools" / "rust-detect.py"
FIXTURES = REPO_ROOT / "detectors" / "rust_wave1" / "test_fixtures"

DETECTOR = "rust_proxy_init_owner_hijack_missing_admin_binding"
POSITIVE = "rust_proxy_init_owner_hijack_missing_admin_binding_positive.rs"
NEGATIVE = "rust_proxy_init_owner_hijack_missing_admin_binding_negative.rs"

NEARBY_PROXY_ADMIN_DETECTORS = (
    "frontrun_initialize_takeover",
    "r94_loop_initialize_frontrun_ownership_steal",
    "r94_loop_proxy_constructor_state_not_initialize",
    "r94_loop_proxy_admin_wrong_address_blocks_upgrade",
    "r94_loop_ownable_non_upgradeable_in_proxy",
    "r94_loop_storage_migration_missing_reinitializer",
    "storage_slot_collision_in_proxy",
    "admin_origin_or_role_guard_missing",
    "two_step_admin_missing",
)


def _run_fixture(detector_id: str, fixture_name: str) -> tuple[int, str]:
    hit_re = re.compile(rf"^=== {re.escape(detector_id)}\s+\((\d+) hits\)", re.MULTILINE)
    with tempfile.NamedTemporaryFile(suffix=".log", delete=False) as tf:
        log_path = Path(tf.name)
    try:
        proc = subprocess.run(
            [
                sys.executable,
                str(RUST_DETECT),
                str(FIXTURES),
                "--only",
                detector_id,
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
        match = hit_re.search(text)
        return (int(match.group(1)) if match else 0), text
    finally:
        log_path.unlink(missing_ok=True)


class RustProxyInitOwnerHijackMissingAdminBindingTests(unittest.TestCase):
    def test_positive_fixture_fires_on_deployer_bound_proxy_admin(self) -> None:
        hits, log_text = _run_fixture(DETECTOR, POSITIVE)
        self.assertEqual(hits, 1, log_text)
        self.assertIn("configured admin", log_text)
        self.assertIn("ctx.accounts.deployer.key()", log_text)

    def test_negative_fixture_is_silent_with_configured_admin_binding(self) -> None:
        hits, log_text = _run_fixture(DETECTOR, NEGATIVE)
        self.assertEqual(hits, 0, log_text)

    def test_positive_fixture_is_not_generic_initialize_only(self) -> None:
        positive_text = (FIXTURES / POSITIVE).read_text(encoding="utf-8")
        self.assertIn("proxy_admin", positive_text)
        self.assertIn("implementation_hash", positive_text)
        self.assertIn("ctx.accounts.deployer.key()", positive_text)
        self.assertNotIn("configured_admin", positive_text)

    def test_nearby_proxy_admin_detectors_do_not_already_cover_positive(self) -> None:
        for detector_id in NEARBY_PROXY_ADMIN_DETECTORS:
            with self.subTest(detector_id=detector_id):
                hits, log_text = _run_fixture(detector_id, POSITIVE)
                self.assertEqual(hits, 0, log_text)

    def test_anchor_authority_detector_does_not_already_cover_positive(self) -> None:
        detector_path = REPO_ROOT / "detectors" / "rust_wave1" / "anchor_owner_check_missing_on_authority.py"
        spec = importlib.util.spec_from_file_location(
            "anchor_owner_check_missing_on_authority",
            detector_path,
        )
        assert spec and spec.loader
        module = importlib.util.module_from_spec(spec)
        if str(detector_path.parent) not in sys.path:
            sys.path.insert(0, str(detector_path.parent))
        spec.loader.exec_module(module)  # type: ignore[union-attr]

        hits = module.scan_file(str(FIXTURES / POSITIVE))
        self.assertEqual(hits, [], hits)


if __name__ == "__main__":
    unittest.main()
