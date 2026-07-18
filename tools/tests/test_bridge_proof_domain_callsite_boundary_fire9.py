from __future__ import annotations

import importlib.util
import logging
import os
import shutil
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
PATTERN = "bridge-proof-domain-callsite-boundary-fire9"
REFERENCE = ROOT / "reference" / "patterns.dsl" / f"{PATTERN}.yaml"
POSITIVE = ROOT / "detectors" / "test_fixtures" / "positive" / f"{PATTERN}.sol"
NEGATIVE = ROOT / "detectors" / "test_fixtures" / "negative" / f"{PATTERN}.sol"
PATTERN_COMPILE = ROOT / "tools" / "pattern-compile.py"
RUN_CUSTOM = ROOT / "detectors" / "run_custom.py"


def _load_module(path: Path, name: str):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


def _slither_available() -> bool:
    try:
        __import__("slither")
        __import__("slither.detectors.abstract_detector")
    except ImportError:
        return False
    return True


class BridgeProofDomainCallsiteBoundaryFire9Test(unittest.TestCase):
    def _compiled_detectors(self, tmp_root: Path):
        compiler = _load_module(PATTERN_COMPILE, "pattern_compile_fire9")
        temp_detectors = tmp_root / "detectors"
        wave_dir = temp_detectors / "wave99"
        temp_detectors.mkdir(parents=True)
        shutil.copy2(ROOT / "detectors" / "_template_utils.py", temp_detectors)
        shutil.copy2(ROOT / "detectors" / "_predicate_engine.py", temp_detectors)

        compiled = compiler.compile_pattern(
            REFERENCE,
            wave_dir,
            strict_yaml_shapes=True,
            strict_unsupported_keys=True,
        )
        self.assertTrue(compiled)

        run_custom = _load_module(RUN_CUSTOM, "run_custom_fire9")
        detectors = run_custom.load_detectors(
            temp_detectors,
            name_filter=PATTERN,
            tier_filter="ALL",
        )
        self.assertEqual(len(detectors), 1)
        return run_custom, detectors

    def _hits(self, fixture: Path) -> int:
        if not _slither_available():
            self.skipTest("slither-analyzer is not importable")

        old_fixture_mode = os.environ.get("AUDITOOOR_FIXTURE_SMOKE_MODE")
        old_nocache = os.environ.get("AUDITOOOR_SLITHER_NOCACHE")
        os.environ["AUDITOOOR_FIXTURE_SMOKE_MODE"] = "1"
        os.environ["AUDITOOOR_SLITHER_NOCACHE"] = "1"
        try:
            with tempfile.TemporaryDirectory(prefix=".fire9_detector_", dir=ROOT) as tmp:
                run_custom, detectors = self._compiled_detectors(Path(tmp))
                slither = run_custom._get_slither_cached(str(fixture), {})
                total = 0
                for detector_class in detectors:
                    for compilation_unit in slither.compilation_units:
                        detector = detector_class(
                            compilation_unit,
                            slither,
                            logging.getLogger(PATTERN),
                        )
                        total += len(detector.detect())
                return total
        finally:
            if old_fixture_mode is None:
                os.environ.pop("AUDITOOOR_FIXTURE_SMOKE_MODE", None)
            else:
                os.environ["AUDITOOOR_FIXTURE_SMOKE_MODE"] = old_fixture_mode
            if old_nocache is None:
                os.environ.pop("AUDITOOOR_SLITHER_NOCACHE", None)
            else:
                os.environ["AUDITOOOR_SLITHER_NOCACHE"] = old_nocache

    def test_reference_yaml_is_source_backed_and_points_to_owned_fixtures(self) -> None:
        text = REFERENCE.read_text(encoding="utf-8")
        self.assertIn(f"pattern: {PATTERN}", text)
        self.assertIn("snowbridge-4855ace3-parent", text)
        self.assertIn("reports/snowbridge_bridgeproof_prefix_validation_2026-05-18.md", text)
        self.assertIn(str(POSITIVE.relative_to(ROOT)), text)
        self.assertIn(str(NEGATIVE.relative_to(ROOT)), text)

    def test_fixture_pair_models_same_callsite_with_helper_boundary_fix(self) -> None:
        positive = POSITIVE.read_text(encoding="utf-8")
        negative = NEGATIVE.read_text(encoding="utf-8")

        self.assertIn("verifyCommitment(", positive)
        self.assertIn("isCommitmentInHeaderDigest(commitment, proof.header, isV2)", positive)
        self.assertIn("verifyMMRLeafProof", positive)
        self.assertIn("data[0] == DIGEST_ITEM_OTHER_SNOWBRIDGE", positive)
        self.assertNotIn("digestItemOtherKind = isV2", positive)

        self.assertIn("verifyCommitment(", negative)
        self.assertIn("isCommitmentInHeaderDigest(commitment, proof.header, isV2)", negative)
        self.assertIn("verifyMMRLeafProof", negative)
        self.assertIn("digestItemOtherKind = isV2", negative)
        self.assertIn("data[0] == digestItemOtherKind", negative)

    def test_positive_fixture_fires_and_negative_fixture_stays_quiet(self) -> None:
        self.assertEqual(self._hits(POSITIVE), 1)
        self.assertEqual(self._hits(NEGATIVE), 0)


if __name__ == "__main__":
    unittest.main()
