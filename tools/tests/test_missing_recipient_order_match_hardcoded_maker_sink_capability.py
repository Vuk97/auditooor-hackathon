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
PATTERN = "missing-recipient-order-match-hardcoded-maker-sink"
REFERENCE = ROOT / "reference" / "patterns.dsl" / f"{PATTERN}.yaml"
DETECTOR = ROOT / "detectors" / "wave18" / "missing_recipient_order_match_hardcoded_maker_sink.py"
FIXTURE_DIR = ROOT / "detectors" / "fixtures" / "missing_recipient_order_match_hardcoded_maker_sink"
POSITIVE = FIXTURE_DIR / "positive.sol"
CLEAN = FIXTURE_DIR / "clean.sol"
POLYMARKET_TRADING = Path("/Users/wolf/audits/polymarket/lib/ctf-exchange/src/exchange/mixins/Trading.sol")


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


class MissingRecipientOrderMatchHardcodedMakerSinkCapabilityTest(unittest.TestCase):
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
        with tempfile.TemporaryDirectory(prefix=".pattern_compile_missing_recipient_order_", dir=ROOT) as tmp:
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

    def test_reference_yaml_points_at_owned_fixture_pair(self) -> None:
        spec = yaml.safe_load(REFERENCE.read_text(encoding="utf-8"))
        self.assertEqual(spec["pattern"], PATTERN)
        self.assertIn("missing-recipient-validation", spec["tags"])
        self.assertEqual(spec["fixtures"]["vuln"], str(POSITIVE.relative_to(ROOT)))
        self.assertEqual(spec["fixtures"]["clean"], str(CLEAN.relative_to(ROOT)))

    def test_positive_fixture_fires_and_clean_fixture_stays_quiet(self) -> None:
        positive_hits, _ = self._hits(POSITIVE)
        clean_hits, _ = self._hits(CLEAN)
        self.assertEqual(positive_hits, 1)
        self.assertEqual(clean_hits, 0)

    def test_polymarket_trading_external_shape_fires_when_available(self) -> None:
        if not POLYMARKET_TRADING.is_file():
            self.skipTest(f"external recall sample not present at {POLYMARKET_TRADING}")
        if _python_with_slither() is None:
            self.skipTest("slither-analyzer is not importable by the tested Python interpreters")

        from slither import Slither

        spec = yaml.safe_load(REFERENCE.read_text(encoding="utf-8"))
        engine_spec = importlib.util.spec_from_file_location(
            "predicate_engine",
            ROOT / "detectors" / "_predicate_engine.py",
        )
        predicate_engine = importlib.util.module_from_spec(engine_spec)
        assert engine_spec.loader is not None
        engine_spec.loader.exec_module(predicate_engine)

        slither = Slither(str(POLYMARKET_TRADING))
        hits = 0
        for contract in slither.contracts:
            if not predicate_engine.eval_preconditions(contract, spec["preconditions"]):
                continue
            for function in contract.functions_and_modifiers_declared:
                if predicate_engine.eval_function_match(function, spec["match"]):
                    hits += 1

        source = POLYMARKET_TRADING.read_text(encoding="utf-8")
        self.assertGreaterEqual(hits, 1)
        self.assertIn("function _matchOrders(", source)
        self.assertIn("_transfer(address(this), takerOrder.maker", source)


if __name__ == "__main__":
    unittest.main()
