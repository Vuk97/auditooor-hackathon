from __future__ import annotations

import importlib.util
import os
import py_compile
import re
import subprocess
import sys
import tempfile
import textwrap
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
PATTERN = "bridge-proof-omits-receiver-domain-fire9"
REFERENCE = ROOT / "reference" / "patterns.dsl" / f"{PATTERN}.yaml"
POSITIVE = ROOT / "detectors" / "test_fixtures" / "positive" / f"{PATTERN}.sol"
NEGATIVE = ROOT / "detectors" / "test_fixtures" / "negative" / f"{PATTERN}.sol"
COMPILE = ROOT / "tools" / "pattern-compile.py"


EVAL_SNIPPET = r"""
import sys
from pathlib import Path

import yaml
from slither import Slither

root = Path(sys.argv[1])
yaml_path = Path(sys.argv[2])
fixture = Path(sys.argv[3])
sys.path.insert(0, str(root))

from detectors._predicate_engine import eval_function_match, eval_preconditions

spec = yaml.safe_load(yaml_path.read_text(encoding="utf-8"))
slither = Slither(str(fixture))
hits = 0
for contract in slither.contracts:
    if not eval_preconditions(contract, spec.get("preconditions", [])):
        continue
    for function in contract.functions_and_modifiers_declared:
        if eval_function_match(function, spec.get("match", [])):
            hits += 1
print(f"HITS={hits}")
"""


def _load_module(path: Path, mod_name: str):
    tools_dir = str(path.parent)
    if tools_dir not in sys.path:
        sys.path.insert(0, tools_dir)
    spec = importlib.util.spec_from_file_location(mod_name, path)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


def _import_yaml():
    try:
        import yaml  # type: ignore

        return yaml
    except ImportError:
        return None


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
                [candidate, "-c", "import yaml; import slither; import slither.detectors.abstract_detector"],
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


class BridgeProofOmitsReceiverDomainFire9Test(unittest.TestCase):
    def setUp(self) -> None:
        self.yaml = _import_yaml()
        if self.yaml is None:
            self.skipTest("PyYAML is not available")

    def _spec(self) -> dict:
        return self.yaml.safe_load(REFERENCE.read_text(encoding="utf-8"))

    def _hits(self, fixture: Path) -> int:
        slither_python = _python_with_slither()
        if slither_python is None:
            self.skipTest("slither-analyzer is not importable by the tested Python interpreters")

        cache_path = ROOT / "detectors" / "test_fixtures" / "cache" / "solidity-files-cache.json"
        cache_bytes = cache_path.read_bytes() if cache_path.exists() else None
        env = os.environ.copy()
        env["AUDITOOOR_FIXTURE_SMOKE_MODE"] = "1"
        env["AUDITOOOR_SLITHER_NOCACHE"] = "1"
        try:
            proc = subprocess.run(
                [slither_python, "-c", EVAL_SNIPPET, str(ROOT), str(REFERENCE), str(fixture)],
                cwd=ROOT,
                env=env,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                timeout=120,
            )
        finally:
            if cache_bytes is None:
                if cache_path.exists():
                    cache_path.unlink()
            else:
                cache_path.write_bytes(cache_bytes)
        self.assertEqual(proc.returncode, 0, proc.stdout)
        match = re.search(r"^HITS=(\d+)$", proc.stdout, re.MULTILINE)
        self.assertIsNotNone(match, proc.stdout)
        return int(match.group(1))

    def test_dsl_metadata_and_fixtures_are_source_backed(self) -> None:
        spec = self._spec()
        positive = POSITIVE.read_text(encoding="utf-8")
        negative = NEGATIVE.read_text(encoding="utf-8")

        self.assertEqual(spec["pattern"], PATTERN)
        self.assertEqual(spec["attack_class"], "bridge-proof-domain-bypass")
        self.assertEqual(spec["submission_posture"], "NOT_SUBMIT_READY")
        self.assertEqual(spec["fixtures"]["vuln"], str(POSITIVE.relative_to(ROOT)))
        self.assertEqual(spec["fixtures"]["clean"], str(NEGATIVE.relative_to(ROOT)))
        self.assertGreaterEqual(len(spec.get("references", [])), 3)
        self.assertTrue(
            all(ref["verification_tier"] in {"tier-2-verified-public-archive", "source-state-validated-pre-fix"} for ref in spec["references"])
        )

        self.assertIn("function claimBridgeProof(", positive)
        self.assertIn("keccak256(abi.encode(root, sourceReceipt, recipient, amount))", positive)
        self.assertNotIn("abi.encode(receiverDomain, uint32(block.chainid)", positive)
        self.assertIn("abi.encode(receiverDomain, uint32(block.chainid)", negative)

    def test_dsl_compiles_to_detector_syntax_without_checked_in_emission(self) -> None:
        compiler = _load_module(COMPILE, "pattern_compile_fire9")
        with tempfile.TemporaryDirectory(dir=ROOT) as tmp:
            out_dir = Path(tmp)
            ok = compiler.compile_pattern(
                REFERENCE,
                out_dir,
                strict_yaml_shapes=True,
                strict_unsupported_keys=True,
            )
            self.assertTrue(ok)
            generated = out_dir / f"{PATTERN.replace('-', '_')}.py"
            self.assertTrue(generated.is_file())
            py_compile.compile(str(generated), doraise=True)
            generated_text = generated.read_text(encoding="utf-8")
            self.assertIn(f'ARGUMENT = "{PATTERN}"', generated_text)
            self.assertIn("_PRECONDITIONS", generated_text)
            self.assertIn("_MATCH", generated_text)

    def test_positive_fixture_fires_and_negative_fixture_stays_quiet(self) -> None:
        self.assertEqual(self._hits(POSITIVE), 1)
        self.assertEqual(self._hits(NEGATIVE), 0)


if __name__ == "__main__":
    unittest.main()
