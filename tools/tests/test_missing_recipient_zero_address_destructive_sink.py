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

import yaml


ROOT = Path(__file__).resolve().parents[2]
RUNNER = ROOT / "detectors" / "run_custom.py"
TOOL = ROOT / "tools" / "pattern-compile.py"
PATTERN = "missing-recipient-zero-address-destructive-sink"
REFERENCE = ROOT / "reference" / "patterns.dsl" / f"{PATTERN}.yaml"
DETECTOR = ROOT / "detectors" / "wave18" / "missing_recipient_zero_address_destructive_sink.py"
POSITIVE = ROOT / "patterns" / "fixtures" / f"{PATTERN}_vuln.sol"
CLEAN = ROOT / "patterns" / "fixtures" / f"{PATTERN}_clean.sol"
ERC20_BURN_MISS = ROOT / "patterns" / "fixtures" / "erc20-burn-from-can-accept-zero-address_vuln.sol"
NOUNS_DELEGATE_MISS = ROOT / "patterns" / "fixtures" / "glider-nouns-delegates-zero-address-vote-burn_vuln.sol"


def _load_pattern_compile():
    spec = importlib.util.spec_from_file_location("pattern_compile", TOOL)
    mod = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(mod)
    return mod


def _python_with_slither() -> str | None:
    candidates = [
        os.environ.get("SLITHER_PYTHON"),
        sys.executable,
        "/opt/homebrew/opt/python@3.13/bin/python3.13",
        "/opt/homebrew/bin/python3.13",
    ]
    seen: set[str] = set()
    for candidate in candidates:
        if not candidate or candidate in seen:
            continue
        seen.add(candidate)
        try:
            probe = subprocess.run(
                [candidate, "-c", "import slither; import slither.detectors.abstract_detector"],
                cwd=ROOT,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                timeout=10,
            )
        except (OSError, subprocess.TimeoutExpired):
            continue
        if probe.returncode == 0:
            return candidate
    return None


class MissingRecipientZeroAddressDestructiveSinkTest(unittest.TestCase):
    def _hits(self, fixture: Path) -> tuple[int, str]:
        slither_python = _python_with_slither()
        if slither_python is None:
            self.skipTest("slither-analyzer is not importable by the tested Python interpreters")

        env = os.environ.copy()
        env["AUDITOOOR_FIXTURE_SMOKE_MODE"] = "1"
        env["AUDITOOOR_SLITHER_NOCACHE"] = "1"
        proc = subprocess.run(
            [slither_python, str(RUNNER), "--tier=ALL", str(fixture), PATTERN],
            cwd=ROOT,
            env=env,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            timeout=120,
        )
        self.assertEqual(proc.returncode, 0, proc.stdout)
        self.assertIn(PATTERN, proc.stdout)
        self.assertNotIn("No custom detectors found", proc.stdout)
        match = re.search(r"total hits:\s*(\d+)", proc.stdout)
        self.assertIsNotNone(match, proc.stdout)
        return int(match.group(1)), proc.stdout

    def test_pattern_compile_round_trip_matches_generated_detector(self) -> None:
        py_compile.compile(str(DETECTOR), doraise=True)
        compiler = _load_pattern_compile()
        with tempfile.TemporaryDirectory(prefix=".pattern_compile_missing_recipient_sink_", dir=ROOT) as tmp:
            out_dir = Path(tmp) / "wave18"
            compiled = compiler.compile_pattern(
                REFERENCE,
                out_dir,
                strict_yaml_shapes=True,
                strict_unsupported_keys=True,
            )
            self.assertTrue(compiled)
            generated = out_dir / DETECTOR.name
            self.assertTrue(generated.is_file(), f"missing generated detector: {generated}")
            self.assertEqual(DETECTOR.read_text(encoding="utf-8"), generated.read_text(encoding="utf-8"))

    def test_reference_yaml_classifies_as_missing_recipient(self) -> None:
        spec = yaml.safe_load(REFERENCE.read_text(encoding="utf-8"))
        self.assertEqual(spec["pattern"], PATTERN)
        self.assertIn("missing-recipient-validation", spec["tags"])
        self.assertEqual(spec["fixtures"]["vuln"], str(POSITIVE.relative_to(ROOT)))
        self.assertEqual(spec["fixtures"]["clean"], str(CLEAN.relative_to(ROOT)))

        backtest_path = ROOT / "tools" / "audit" / "detector-catch-rate-backtest.py"
        bt_spec = importlib.util.spec_from_file_location("detector_catch_rate_backtest", backtest_path)
        backtest = importlib.util.module_from_spec(bt_spec)
        assert bt_spec.loader is not None
        bt_spec.loader.exec_module(backtest)
        self.assertEqual(
            backtest.derive_attack_class(PATTERN, spec.get("tags")),
            "missing-recipient-validation",
        )

    def test_positive_fixture_fires_and_clean_fixture_stays_quiet(self) -> None:
        positive_hits, _ = self._hits(POSITIVE)
        clean_hits, _ = self._hits(CLEAN)
        self.assertEqual(positive_hits, 3)
        self.assertEqual(clean_hits, 0)

    def test_prior_zero_address_miss_fixtures_fire(self) -> None:
        erc20_hits, erc20_stdout = self._hits(ERC20_BURN_MISS)
        nouns_hits, nouns_stdout = self._hits(NOUNS_DELEGATE_MISS)
        self.assertGreaterEqual(erc20_hits, 1, erc20_stdout)
        self.assertGreaterEqual(nouns_hits, 2, nouns_stdout)


if __name__ == "__main__":
    unittest.main()
