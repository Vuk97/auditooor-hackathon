import importlib.util
import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[2]
MODULE_PATH = REPO_ROOT / "tools" / "detector-provenance-v2.py"


def load_module():
    spec = importlib.util.spec_from_file_location("detector_provenance_v2", MODULE_PATH)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


prov = load_module()


class DetectorProvenanceV2Test(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix="auditooor-prov2-")
        self.repo_root = Path(self.tmp.name)
        (self.repo_root / "detectors" / "wave12").mkdir(parents=True)
        (self.repo_root / "detectors" / "go_wave1").mkdir(parents=True)
        (self.repo_root / "detectors" / "rust_wave2").mkdir(parents=True)
        (self.repo_root / "detectors" / "fixtures" / "sample").mkdir(parents=True)
        (self.repo_root / "tools" / "tests").mkdir(parents=True)
        (self.repo_root / "reference" / "patterns.dsl").mkdir(parents=True)
        (self.repo_root / "detectors" / "_specs").mkdir(parents=True)
        (self.repo_root / "tools").mkdir(exist_ok=True)

        (self.repo_root / "detectors" / "wave12" / "alpha.py").write_text(
            """
from slither.detectors.abstract_detector import AbstractDetector
class Alpha(AbstractDetector):
    ARGUMENT = "alpha-pattern"
    WIKI = "https://example.local/reference/patterns.dsl/alpha-pattern.yaml"
"""
            "\n"
            '"""alpha-pattern - generated from reference/patterns.dsl/alpha-pattern.yaml"""\n'
            '"""Spec: detectors/_specs/alpha-pattern.yaml"""\n',
            encoding="utf-8",
        )
        (self.repo_root / "detectors" / "go_wave1" / "go_alpha.py").write_text(
            'ARGUMENT = "go-alpha"\n',
            encoding="utf-8",
        )
        (self.repo_root / "tools" / "rust-detector-runner.py").write_text(
            '''"""Fixture rust runner."""

_WAVE2_DETECTORS: dict[str, str] = {
    "rust.frost.wave2.nonce_reuse_risk_unscoped_secret":
        "frost_nonce_reuse_risk_unscoped_secret",
}


def _detect_dkg_self_identifier(funcs):
    """Detect DKG self identifier misuse in round packages."""
    return []


def _detect_aggregate_under_threshold(funcs):
    """Detect aggregate threshold checks on raw signature-share sets."""
    return []


def scan_workspace(workspace):
    pattern_results: dict[str, list[str]] = {
        "rust.frost.dkg.self_identifier_in_round_packages":
            _detect_dkg_self_identifier(funcs),
        "rust.frost.aggregate.under_threshold_signature_shares":
            _detect_aggregate_under_threshold(funcs),
    }
    pattern_results.update(_run_wave2_detectors(workspace))
    return pattern_results
''',
            encoding="utf-8",
        )
        (self.repo_root / "detectors" / "rust_wave2" / "frost_nonce_reuse_risk_unscoped_secret.py").write_text(
            '''"""Detect signing paths that reuse nonces without a freshness guard."""

DETECTOR_ID = "frost_nonce_reuse_risk_unscoped_secret"


def scan(root):
    return []
''',
            encoding="utf-8",
        )
        (self.repo_root / "detectors" / "fixtures" / "sample" / "manifest.json").write_text(
            json.dumps(
                {
                    "source_pattern_path": "reference/patterns.dsl/alpha-pattern.yaml",
                    "smoke_record_path": "detectors/fixtures/sample/smoke.json",
                    "detector_path": "detectors/wave12/alpha.py",
                    "legacy_detector_path": "detectors/wave_graveyard/syntax_broken/alpha.py",
                }
            ),
            encoding="utf-8",
        )
        (self.repo_root / "tools" / "tests" / "test_alpha_detector.py").write_text(
            "ARG='alpha-pattern'\n", encoding="utf-8"
        )
        (self.repo_root / "tools" / "tests" / "test_rust_detector_runner.py").write_text(
            "\n".join(
                [
                    "PID = 'rust.frost.dkg.self_identifier_in_round_packages'",
                    "PID2 = 'rust.frost.aggregate.under_threshold_signature_shares'",
                    "PID3 = 'rust.frost.wave2.nonce_reuse_risk_unscoped_secret'",
                    "",
                ]
            ),
            encoding="utf-8",
        )
        (self.repo_root / "tools" / "tests" / "test_rust_wave2_detectors.py").write_text(
            "DETECTOR = 'frost_nonce_reuse_risk_unscoped_secret'\n",
            encoding="utf-8",
        )
        (self.repo_root / "reference" / "patterns.dsl" / "alpha-pattern.yaml").write_text(
            "name: alpha-pattern\n", encoding="utf-8"
        )
        (self.repo_root / "detectors" / "_specs" / "alpha-pattern.yaml").write_text(
            "name: alpha-pattern\n", encoding="utf-8"
        )

    def tearDown(self):
        self.tmp.cleanup()

    def test_solidity_detector_resolution(self):
        out = prov.resolve(self.repo_root, "alpha-pattern")
        self.assertEqual(out["backend"], "solidity")
        self.assertEqual(out["detector_path"], "detectors/wave12/alpha.py")
        self.assertEqual(out["argument"], "alpha-pattern")
        self.assertTrue(out["generated_from_dsl_path"].endswith("alpha-pattern.yaml"))
        self.assertTrue(out["fixture_manifests"])
        self.assertTrue(out["focused_test_refs"])
        self.assertEqual(
            out["advisory_boundary"], "advisory_only_local_metadata_no_impact_claim"
        )
        blob = json.dumps(out)
        self.assertNotIn(str(self.repo_root), blob)
        self.assertIn("context_pack_hash", out)

    def test_non_solidity_detector_rejected(self):
        out = prov.resolve(self.repo_root, "go-alpha")
        self.assertEqual(out["error"], "unsupported_backend")

    def test_rust_runner_native_detector_resolution(self):
        out = prov.resolve(
            self.repo_root, "rust.frost.dkg.self_identifier_in_round_packages"
        )
        self.assertEqual(out["backend"], "rust")
        self.assertEqual(out["resolution_kind"], "runner_native")
        self.assertEqual(out["detector_path"], "tools/rust-detector-runner.py")
        self.assertEqual(out["runner_path"], "tools/rust-detector-runner.py")
        self.assertEqual(out["callee"], "_detect_dkg_self_identifier")
        self.assertGreater(out["dispatch_line"], 0)
        self.assertGreater(out["def_line"], 0)
        self.assertIn("round packages", out["docstring"])
        self.assertTrue(out["focused_test_refs"])
        self.assertIn("tools/rust-detector-runner.py", out["source_refs"])
        blob = json.dumps(out)
        self.assertNotIn(str(self.repo_root), blob)
        self.assertIn("context_pack_hash", out)

    def test_rust_wave2_pattern_id_resolution(self):
        out = prov.resolve(
            self.repo_root, "rust.frost.wave2.nonce_reuse_risk_unscoped_secret"
        )
        self.assertEqual(out["backend"], "rust")
        self.assertEqual(out["resolution_kind"], "wave2_standalone")
        self.assertEqual(out["canonical_detector_id"], out["detector_id"])
        self.assertEqual(
            out["detector_path"],
            "detectors/rust_wave2/frost_nonce_reuse_risk_unscoped_secret.py",
        )
        self.assertEqual(out["standalone_detector_id"], "frost_nonce_reuse_risk_unscoped_secret")
        self.assertEqual(out["callee"], "scan")
        self.assertGreater(out["dispatch_line"], 0)
        self.assertGreater(out["def_line"], 0)
        self.assertIn("reuse nonces", out["docstring"])
        self.assertTrue(
            any(
                ref.startswith("tools/tests/test_rust_detector_runner.py:")
                for ref in out["focused_test_refs"]
            )
        )
        self.assertTrue(
            any(
                ref.startswith("tools/tests/test_rust_wave2_detectors.py:")
                for ref in out["focused_test_refs"]
            )
        )

    def test_rust_wave2_raw_detector_id_resolution(self):
        out = prov.resolve(self.repo_root, "frost_nonce_reuse_risk_unscoped_secret")
        self.assertEqual(out["backend"], "rust")
        self.assertEqual(out["resolution_kind"], "wave2_standalone")
        self.assertEqual(
            out["canonical_detector_id"],
            "rust.frost.wave2.nonce_reuse_risk_unscoped_secret",
        )
        self.assertEqual(out["standalone_detector_id"], "frost_nonce_reuse_risk_unscoped_secret")

    def test_unknown_detector(self):
        out = prov.resolve(self.repo_root, "missing-pattern")
        self.assertEqual(out["error"], "not_found")

    def test_cli_repo_root_and_detector_id(self):
        proc = subprocess.run(
            [
                sys.executable,
                str(MODULE_PATH),
                "--repo-root",
                str(self.repo_root),
                "--detector-id",
                "alpha-pattern",
            ],
            check=True,
            capture_output=True,
            text=True,
        )
        out = json.loads(proc.stdout)
        self.assertEqual(out["detector_id"], "alpha-pattern")
        self.assertEqual(out["backend"], "solidity")
        self.assertEqual(out["detector_path"], "detectors/wave12/alpha.py")

    def test_relative_provenance_paths_are_repo_root_based_from_other_cwd(self):
        old_cwd = Path.cwd()
        try:
            with tempfile.TemporaryDirectory(prefix="outside-prov2-cwd-") as outside:
                os.chdir(outside)
                out = prov.resolve(self.repo_root, "alpha-pattern")
        finally:
            os.chdir(old_cwd)

        self.assertEqual(out["generated_from_dsl_path"], "reference/patterns.dsl/alpha-pattern.yaml")
        self.assertEqual(
            out["fixture_manifests"][0]["smoke_record_path"],
            "detectors/fixtures/sample/smoke.json",
        )
        self.assertEqual(
            out["fixture_manifests"][0]["manifest_path"],
            "detectors/fixtures/sample/manifest.json",
        )
        self.assertEqual(
            out["fixture_manifests"][0]["detector_path"],
            "detectors/wave12/alpha.py",
        )
        self.assertEqual(
            out["fixture_manifests"][0]["legacy_detector_path"],
            "detectors/wave_graveyard/syntax_broken/alpha.py",
        )


if __name__ == "__main__":
    unittest.main()
