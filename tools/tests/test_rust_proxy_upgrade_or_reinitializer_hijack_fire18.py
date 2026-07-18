from __future__ import annotations

import importlib.util
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

DETECTOR = "proxy_upgrade_or_reinitializer_hijack_fire18"
POSITIVE = f"{DETECTOR}_positive.rs"
NEGATIVE = f"{DETECTOR}_negative.rs"
HIT_RE = re.compile(rf"^=== {re.escape(DETECTOR)}\s+\((\d+) hits\)", re.MULTILINE)


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
        log_text = log_path.read_text(encoding="utf-8", errors="ignore")
        match = HIT_RE.search(log_text)
        return (int(match.group(1)) if match else 0), log_text
    finally:
        log_path.unlink(missing_ok=True)


def _load_detector():
    detector_path = WAVE1_DIR / f"{DETECTOR}.py"
    spec = importlib.util.spec_from_file_location(DETECTOR, detector_path)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    if str(WAVE1_DIR) not in sys.path:
        sys.path.insert(0, str(WAVE1_DIR))
    spec.loader.exec_module(module)  # type: ignore[union-attr]
    return module


def _load_ast_engine():
    module_name = "ast_engine"
    if module_name in sys.modules:
        return sys.modules[module_name]
    engine_path = REPO_ROOT / "tools" / "ast-engine.py"
    spec = importlib.util.spec_from_file_location(module_name, engine_path)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    sys.modules[module_name] = module
    spec.loader.exec_module(module)  # type: ignore[union-attr]
    return module


class RustProxyUpgradeOrReinitializerHijackFire18Tests(unittest.TestCase):
    def test_positive_fixture_fires_on_proxy_migration_and_baseline_shapes(self) -> None:
        hits, log_text = _run_fixture(POSITIVE)
        self.assertEqual(hits, 4, log_text)
        self.assertIn("deploy_proxy", log_text)
        self.assertIn("initialize_proxy", log_text)
        self.assertIn("open_baseline_position", log_text)
        self.assertIn("Migration marker", log_text)
        self.assertIn("current contract as admin", log_text)
        self.assertIn("wrong actor", log_text)
        self.assertIn("context-free baseline", log_text)

    def test_negative_fixture_keeps_upgrade_path_but_is_silent(self) -> None:
        hits, log_text = _run_fixture(NEGATIVE)
        self.assertEqual(hits, 0, log_text)

    def test_detector_module_reports_expected_message_families(self) -> None:
        module = _load_detector()
        source = (FIXTURES / POSITIVE).read_bytes()
        ast_engine = _load_ast_engine()

        engine = ast_engine.AstEngine("rust", source)
        findings = module.run(engine.parse(), source, str(FIXTURES / POSITIVE))
        self.assertEqual(len(findings), 4, findings)
        messages = "\n".join(finding["message"] for finding in findings)
        self.assertIn("Migration marker", messages)
        self.assertIn("upgradeable proxy", messages)
        self.assertIn("wrong actor", messages)
        self.assertIn("global baseline", messages)
        self.assertEqual({finding["severity"] for finding in findings}, {"high"})


if __name__ == "__main__":
    unittest.main()
