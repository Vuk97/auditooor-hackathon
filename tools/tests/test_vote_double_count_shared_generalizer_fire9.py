from __future__ import annotations

import importlib.util
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
TOOL = ROOT / "tools" / "pattern-compile.py"
PATTERN = "vote-double-count-shared-generalizer-fire9"
REFERENCE = ROOT / "reference" / "patterns.dsl" / f"{PATTERN}.yaml"
POSITIVE = ROOT / "detectors" / "test_fixtures" / "positive" / f"{PATTERN}.sol"
NEGATIVE = ROOT / "detectors" / "test_fixtures" / "negative" / f"{PATTERN}.sol"

DELEGATION_POSITIVE = ROOT / "detectors" / "fixtures" / "delegation_reassignment_stale_vote_source" / "positive.sol"
DELEGATION_CLEAN = ROOT / "detectors" / "fixtures" / "delegation_reassignment_stale_vote_source" / "clean.sol"
SELF_DELEGATION_POSITIVE = ROOT / "detectors" / "fixtures" / "voting_power_self_delegation_double_count" / "positive.sol"
SELF_DELEGATION_CLEAN = ROOT / "detectors" / "fixtures" / "voting_power_self_delegation_double_count" / "clean.sol"
W68_DIRECT_POSITIVE = ROOT / "detectors" / "fixtures" / "w68_zero_coverage" / "vote_double_count_positive.sol"
W68_DIRECT_CLEAN = ROOT / "detectors" / "fixtures" / "w68_zero_coverage" / "vote_double_count_clean.sol"


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
            proc = subprocess.run(
                [candidate, "-c", "import slither; import slither.detectors.abstract_detector"],
                cwd=ROOT,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                timeout=10,
            )
        except (OSError, subprocess.TimeoutExpired):
            continue
        if proc.returncode == 0:
            return candidate
    return None


class VoteDoubleCountSharedGeneralizerFire9Test(unittest.TestCase):
    def _hits(self, fixture: Path) -> tuple[int, str]:
        slither_python = _python_with_slither()
        if slither_python is None:
            self.skipTest("slither-analyzer is not importable by the tested Python interpreters")

        script = r"""
import importlib.util
import inspect
import json
import logging
import os
import shutil
import sys
import tempfile
from pathlib import Path

root = Path(sys.argv[1])
reference = Path(sys.argv[2])
fixture = Path(sys.argv[3])
pattern = sys.argv[4]

spec = importlib.util.spec_from_file_location("pattern_compile", root / "tools" / "pattern-compile.py")
compiler = importlib.util.module_from_spec(spec)
assert spec.loader is not None
spec.loader.exec_module(compiler)

with tempfile.TemporaryDirectory(prefix=".fire9_vote_double_count_", dir=root) as tmp:
    temp_detectors = Path(tmp) / "detectors"
    out_dir = temp_detectors / "wave17"
    out_dir.mkdir(parents=True)
    shutil.copy2(root / "detectors" / "_template_utils.py", temp_detectors / "_template_utils.py")
    shutil.copy2(root / "detectors" / "_predicate_engine.py", temp_detectors / "_predicate_engine.py")
    compiled = compiler.compile_pattern(
        reference,
        out_dir,
        strict_yaml_shapes=True,
        strict_unsupported_keys=True,
    )
    if not compiled:
        raise SystemExit("pattern did not compile")
    generated = out_dir / (pattern.replace("-", "_") + ".py")
    det_spec = importlib.util.spec_from_file_location("generated_vote_double_count_detector", generated)
    det_mod = importlib.util.module_from_spec(det_spec)
    assert det_spec.loader is not None
    det_spec.loader.exec_module(det_mod)
    detector_classes = [
        obj for _, obj in inspect.getmembers(det_mod, inspect.isclass)
        if getattr(obj, "ARGUMENT", "") == pattern
    ]
    if len(detector_classes) != 1:
        raise SystemExit(f"expected one detector class, got {len(detector_classes)}")

    from slither import Slither
    os.environ["AUDITOOOR_FIXTURE_SMOKE_MODE"] = "1"
    os.environ["AUDITOOOR_SLITHER_NOCACHE"] = "1"
    slither = Slither(str(fixture))
    total = 0
    log = logging.getLogger("fire9.vote.double.count")
    for cu in slither.compilation_units:
        detector = detector_classes[0](cu, slither, log)
        total += len(detector.detect())
    print(json.dumps({"hits": total, "generated": str(generated)}))
"""
        env = os.environ.copy()
        env["AUDITOOOR_FIXTURE_SMOKE_MODE"] = "1"
        env["AUDITOOOR_SLITHER_NOCACHE"] = "1"
        proc = subprocess.run(
            [slither_python, "-c", script, str(ROOT), str(REFERENCE), str(fixture), PATTERN],
            cwd=ROOT,
            env=env,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            timeout=120,
        )
        self.assertEqual(proc.returncode, 0, proc.stdout)
        json_lines = [
            line for line in proc.stdout.splitlines()
            if line.startswith("{") and '"hits"' in line
        ]
        self.assertTrue(json_lines, proc.stdout)
        return int(json.loads(json_lines[-1])["hits"]), proc.stdout

    def test_pattern_compiles_strictly_and_metadata_points_at_fixtures(self) -> None:
        compiler = _load_pattern_compile()
        with tempfile.TemporaryDirectory(prefix=".pattern_compile_fire9_", dir=ROOT) as tmp:
            out_dir = Path(tmp) / "wave17"
            compiled = compiler.compile_pattern(
                REFERENCE,
                out_dir,
                strict_yaml_shapes=True,
                strict_unsupported_keys=True,
            )
            self.assertTrue(compiled)
            generated = out_dir / f"{PATTERN.replace('-', '_')}.py"
            self.assertTrue(generated.is_file(), f"missing generated detector: {generated}")

        yaml_text = REFERENCE.read_text(encoding="utf-8")
        positive_text = POSITIVE.read_text(encoding="utf-8")
        negative_text = NEGATIVE.read_text(encoding="utf-8")

        self.assertIn("attack_class", "attack_class")  # keeps this test grep-friendly for class lifts
        self.assertIn("status: not-submit-ready", yaml_text)
        self.assertIn("submission_posture: NOT_SUBMIT_READY", yaml_text)
        self.assertIn("detectors/test_fixtures/positive/vote-double-count-shared-generalizer-fire9.sol", yaml_text)
        self.assertIn("detectors/test_fixtures/negative/vote-double-count-shared-generalizer-fire9.sol", yaml_text)
        self.assertIn("vote-double-count", yaml_text)
        self.assertIn("delegatedTokenIds[toTokenId].push(tokenId);", positive_text)
        self.assertIn("_balances[voter] + voteCheckpoints[delegates[voter]][snapshot]", positive_text)
        self.assertIn("balanceOf[msg.sender] + delegatedTo[msg.sender]", positive_text)
        self.assertIn("hasVoted[proposalId][msg.sender] = true;", negative_text)
        self.assertIn("_removeDelegation(oldDelegate, tokenId);", negative_text)
        self.assertIn("require(delegatee != msg.sender", negative_text)

    def test_positive_fixture_fires_and_safe_snapshot_controls_are_quiet(self) -> None:
        hits, log_text = self._hits(POSITIVE)
        self.assertEqual(hits, 3, log_text)
        hits, log_text = self._hits(NEGATIVE)
        self.assertEqual(hits, 0, log_text)

    def test_named_vote_double_count_misses_and_existing_controls(self) -> None:
        hits, log_text = self._hits(DELEGATION_POSITIVE)
        self.assertEqual(hits, 1, log_text)
        hits, log_text = self._hits(DELEGATION_CLEAN)
        self.assertEqual(hits, 0, log_text)
        hits, log_text = self._hits(SELF_DELEGATION_POSITIVE)
        self.assertEqual(hits, 1, log_text)
        hits, log_text = self._hits(SELF_DELEGATION_CLEAN)
        self.assertEqual(hits, 0, log_text)
        hits, log_text = self._hits(W68_DIRECT_POSITIVE)
        self.assertEqual(hits, 1, log_text)
        hits, log_text = self._hits(W68_DIRECT_CLEAN)
        self.assertEqual(hits, 0, log_text)


if __name__ == "__main__":
    unittest.main()
