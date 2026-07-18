from __future__ import annotations

import importlib.util
import os
import py_compile
import re
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
PATTERN = "bridge-proof-payout-missing-consume-once-fire9"
REFERENCE = ROOT / "reference" / "patterns.dsl" / f"{PATTERN}.yaml"
POSITIVE = ROOT / "detectors" / "test_fixtures" / "positive" / f"{PATTERN}.sol"
NEGATIVE = ROOT / "detectors" / "test_fixtures" / "negative" / f"{PATTERN}.sol"
PATTERN_COMPILE = ROOT / "tools" / "pattern-compile.py"
RUN_CUSTOM = ROOT / "detectors" / "run_custom.py"


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


def _load_pattern_compile():
    spec = importlib.util.spec_from_file_location("pattern_compile_fire9", PATTERN_COMPILE)
    if spec is None or spec.loader is None:
        raise AssertionError("could not load pattern compiler")
    module = importlib.util.module_from_spec(spec)
    sys.modules["pattern_compile_fire9"] = module
    spec.loader.exec_module(module)
    return module


def _temp_runner(tmp: Path) -> Path:
    detectors_dir = tmp / "detectors"
    wave_dir = detectors_dir / "wave17"
    wave_dir.mkdir(parents=True)
    for name in ("run_custom.py", "_template_utils.py", "_predicate_engine.py"):
        shutil.copy2(ROOT / "detectors" / name, detectors_dir / name)

    compiler = _load_pattern_compile()
    compiler.AUDITOOOR_DIR = tmp
    ok = compiler.compile_pattern(
        REFERENCE,
        wave_dir,
        strict_yaml_shapes=True,
        strict_unsupported_keys=True,
    )
    if not ok:
        raise AssertionError("pattern compiler skipped the fire9 detector")

    generated = wave_dir / f"{PATTERN.replace('-', '_')}.py"
    py_compile.compile(str(generated), doraise=True)
    return detectors_dir / "run_custom.py"


class BridgeProofPayoutMissingConsumeOnceFire9Test(unittest.TestCase):
    def _hits(self, fixture: Path) -> int:
        slither_python = _python_with_slither()
        if slither_python is None:
            self.skipTest("slither-analyzer is not importable by the tested Python interpreters")

        with tempfile.TemporaryDirectory(prefix="auditooor_fire9_") as td:
            runner = _temp_runner(Path(td))
            env = os.environ.copy()
            env["AUDITOOOR_FIXTURE_SMOKE_MODE"] = "1"
            env["AUDITOOOR_SLITHER_NOCACHE"] = "1"
            proc = subprocess.run(
                [slither_python, str(runner), "--tier=ALL", str(fixture), PATTERN],
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
        return int(match.group(1))

    def test_reference_uses_confirmed_bridge_proof_domain_anchors_only(self) -> None:
        reference = REFERENCE.read_text(encoding="utf-8")
        positive = POSITIVE.read_text(encoding="utf-8")
        negative = NEGATIVE.read_text(encoding="utf-8")

        self.assertIn("pattern: bridge-proof-payout-missing-consume-once-fire9", reference)
        self.assertIn("status: not-submit-ready", reference)
        self.assertIn("coverage_claim: detector_fixture_smoke_only", reference)
        self.assertIn("submission_posture: NOT_SUBMIT_READY", reference)
        self.assertIn("attack_class: bridge-proof-domain-bypass", reference)
        self.assertIn("tier-2-verified-public-archive", reference)
        self.assertIn("darknavy-web3:hyperbridge-ismp-forged-proof-dot-mint", reference)
        self.assertIn("darknavy-web3:bridge-eth-tbtc-usdc-drain", reference)
        self.assertIn("darknavy-web3:kelpdao-rseth-layerzero-packet-drain", reference)
        self.assertNotIn("reported_unverified", reference)
        self.assertNotIn("Verus", reference)

        self.assertIn("contract BridgeProofPayoutMissingConsumeOncePositive", positive)
        self.assertIn("MerkleProof.verify(proof, root, leaf)", positive)
        self.assertIn("token.transfer(recipient, amount)", positive)
        self.assertNotIn("consumedMessages", positive)

        self.assertIn("contract BridgeProofPayoutMissingConsumeOnceNegative", negative)
        self.assertIn("mapping(bytes32 => bool) private consumedMessages", negative)
        self.assertIn("require(!consumedMessages[messageHash]", negative)
        self.assertIn("consumedMessages[messageHash] = true", negative)

    def test_positive_fixture_fires_and_negative_fixture_stays_quiet(self) -> None:
        self.assertEqual(self._hits(POSITIVE), 1)
        self.assertEqual(self._hits(NEGATIVE), 0)


if __name__ == "__main__":
    unittest.main()
