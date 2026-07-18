import importlib.util
import json
import sys
import tempfile
import unittest
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[2]
MODULE_PATH = REPO_ROOT / "tools" / "vault-mcp-server.py"


def load_module():
    spec = importlib.util.spec_from_file_location("vault_mcp_server_prov", MODULE_PATH)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


vault_mcp_server = load_module()


_FIXTURE_RUNNER = '''
"""fake go-detector-runner fixture."""

def _detect_alpha(funcs):
    """Pattern alpha — fixture detector for tests.

    Detects nothing in particular; this docstring is the ground-truth
    provenance text.
    """
    return []


def _detect_beta(funcs):
    """Pattern beta."""
    return []


def scan_workspace(workspace, guard_names):
    pattern_results = {
        "go.fixture.alpha":
            _detect_alpha(funcs),
        "go.fixture.beta":
            _detect_beta(funcs),
    }
    return pattern_results
'''


class VaultDetectorProvenanceTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix="auditooor-prov-")
        self.repo_root = Path(self.tmp.name)
        (self.repo_root / "tools").mkdir()
        (self.repo_root / "tools" / "tests").mkdir()
        (self.repo_root / "docs" / "next-loop").mkdir(parents=True)
        (self.repo_root / "detectors" / "wave12").mkdir(parents=True)
        (self.repo_root / "detectors" / "rust_wave2").mkdir(parents=True)
        (self.repo_root / "detectors" / "fixtures" / "sample").mkdir(parents=True)
        runner = self.repo_root / "tools" / "go-detector-runner.py"
        runner.write_text(_FIXTURE_RUNNER, encoding="utf-8")
        (self.repo_root / "tools" / "rust-detector-runner.py").write_text(
            '''"""Fixture rust runner."""

_WAVE2_DETECTORS: dict[str, str] = {
    "rust.frost.wave2.nonce_reuse_risk_unscoped_secret":
        "frost_nonce_reuse_risk_unscoped_secret",
}


def scan_workspace(workspace):
    pattern_results: dict[str, list[str]] = {}
    pattern_results.update(_run_wave2_detectors(workspace))
    return pattern_results
''',
            encoding="utf-8",
        )
        (self.repo_root / "detectors" / "wave12" / "alpha.py").write_text(
            """
from slither.detectors.abstract_detector import AbstractDetector
class Alpha(AbstractDetector):
    ARGUMENT = "alpha-pattern"
    WIKI = "https://example.local/reference/patterns.dsl/alpha-pattern.yaml"
"""
            "\n"
            '"""alpha-pattern - generated from reference/patterns.dsl/alpha-pattern.yaml"""\n',
            encoding="utf-8",
        )
        (
            self.repo_root
            / "detectors"
            / "rust_wave2"
            / "frost_nonce_reuse_risk_unscoped_secret.py"
        ).write_text(
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
        # Test file with one slug mention
        (self.repo_root / "tools" / "tests" / "test_go_detector_runner.py").write_text(
            "# fake test\n# slug: go.fixture.alpha\n", encoding="utf-8"
        )
        (self.repo_root / "tools" / "tests" / "test_alpha_detector.py").write_text(
            "ARG = 'alpha-pattern'\n", encoding="utf-8"
        )
        (self.repo_root / "tools" / "tests" / "test_rust_detector_runner.py").write_text(
            "\n".join(
                [
                    "PID = 'rust.frost.wave2.nonce_reuse_risk_unscoped_secret'",
                    "RAW = 'frost_nonce_reuse_risk_unscoped_secret'",
                    "",
                ]
            ),
            encoding="utf-8",
        )
        # Doc file referencing the slug
        (self.repo_root / "docs" / "next-loop" / "alpha_seed_l9.md").write_text(
            "Pattern seed for go.fixture.alpha (LLL).\n", encoding="utf-8"
        )
        (self.repo_root / "docs" / "next-loop" / "unrelated.md").write_text(
            "no mention\n", encoding="utf-8"
        )
        (self.repo_root / "obsidian-vault").mkdir()
        self.vault = vault_mcp_server.VaultQuery(
            self.repo_root / "obsidian-vault", self.repo_root
        )

    def tearDown(self):
        self.tmp.cleanup()

    def test_detector_provenance_returns_callee_def_line_and_docstring(self):
        result = self.vault.vault_detector_provenance(pattern_slug="go.fixture.alpha")
        self.assertEqual(result["schema"], vault_mcp_server.DETECTOR_PROVENANCE_SCHEMA)
        self.assertEqual(result["kind"], "detector_provenance")
        self.assertEqual(result["pattern_slug"], "go.fixture.alpha")
        self.assertEqual(result["callee"], "_detect_alpha")
        self.assertGreater(result["dispatch_line"], 0)
        self.assertGreater(result["def_line"], 0)
        self.assertIn("Pattern alpha", result["docstring"])
        self.assertIn("ground-truth", result["docstring"])
        self.assertEqual(result["runner_path"], "tools/go-detector-runner.py")
        # Test cross-ref discovered
        self.assertEqual(result["test_path"], "tools/tests/test_go_detector_runner.py")
        self.assertTrue(result["test_hit_lines"])
        # Doc cross-ref
        self.assertIn("docs/next-loop/alpha_seed_l9.md", result["doc_refs"])
        self.assertNotIn("docs/next-loop/unrelated.md", result["doc_refs"])
        # Stable hash
        again = self.vault.vault_detector_provenance(pattern_slug="go.fixture.alpha")
        self.assertEqual(result["context_pack_hash"], again["context_pack_hash"])
        # Privacy: no absolute paths
        blob = json.dumps(result)
        self.assertNotIn(str(self.repo_root), blob)

    def test_detector_provenance_unknown_slug_returns_not_found(self):
        result = self.vault.vault_detector_provenance(
            pattern_slug="go.fixture.does_not_exist"
        )
        self.assertEqual(result["error"], "not_found")
        self.assertEqual(result["pattern_slug"], "go.fixture.does_not_exist")
        self.assertTrue(result["dispatch_block_present"])

    def test_detector_provenance_missing_or_invalid_slug(self):
        missing = self.vault.vault_detector_provenance()
        self.assertEqual(missing["error"], "missing_pattern_slug")

        invalid = self.vault.vault_detector_provenance(pattern_slug="NOT-VALID")
        self.assertEqual(invalid["error"], "invalid_pattern_slug")

    def test_detector_provenance_runner_not_found_returns_error(self):
        # delete runner
        (self.repo_root / "tools" / "go-detector-runner.py").unlink()
        result = self.vault.vault_detector_provenance(pattern_slug="go.fixture.alpha")
        self.assertEqual(result["error"], "runner_not_found")

    def test_detector_provenance_call_dispatch_routes_through_call(self):
        result = self.vault.call(
            "vault_detector_provenance", {"pattern_slug": "go.fixture.beta"}
        )
        self.assertEqual(result["callee"], "_detect_beta")

    def test_detector_provenance_v2_solidity_routes_through_mcp(self):
        result = self.vault.call(
            "vault_detector_provenance_v2", {"detector_id": "alpha-pattern"}
        )
        self.assertEqual(result["schema"], vault_mcp_server.DETECTOR_PROVENANCE_V2_SCHEMA)
        self.assertEqual(result["kind"], "detector_provenance_v2")
        self.assertEqual(
            result["resolver_schema"], "auditooor.detector_provenance_v2.solidity.v1"
        )
        self.assertEqual(result["backend"], "solidity")
        self.assertEqual(result["detector_path"], "detectors/wave12/alpha.py")
        self.assertEqual(result["argument"], "alpha-pattern")
        self.assertTrue(result["fixture_manifests"])
        self.assertEqual(
            result["fixture_manifests"][0]["legacy_detector_path"],
            "detectors/wave_graveyard/syntax_broken/alpha.py",
        )
        self.assertTrue(result["focused_test_refs"])
        self.assertEqual(
            result["advisory_boundary"], "advisory_only_local_metadata_no_impact_claim"
        )
        self.assertTrue(result["privacy_guards"]["repo_relative_refs_only"])
        self.assertIn("context_pack_hash", result)
        self.assertNotIn(str(self.repo_root), json.dumps(result))

    def test_detector_provenance_v2_rust_wave2_routes_through_mcp(self):
        result = self.vault.vault_detector_provenance_v2(
            detector_id="rust.frost.wave2.nonce_reuse_risk_unscoped_secret"
        )
        self.assertEqual(result["schema"], vault_mcp_server.DETECTOR_PROVENANCE_V2_SCHEMA)
        self.assertEqual(result["backend"], "rust")
        self.assertEqual(result["resolution_kind"], "wave2_standalone")
        self.assertEqual(
            result["detector_path"],
            "detectors/rust_wave2/frost_nonce_reuse_risk_unscoped_secret.py",
        )
        self.assertEqual(result["runner_path"], "tools/rust-detector-runner.py")
        self.assertEqual(
            result["standalone_detector_id"],
            "frost_nonce_reuse_risk_unscoped_secret",
        )
        self.assertEqual(result["callee"], "scan")
        self.assertGreater(result["dispatch_line"], 0)
        self.assertGreater(result["def_line"], 0)
        self.assertIn("reuse nonces", result["docstring"])
        self.assertTrue(
            any(
                ref.startswith("tools/tests/test_rust_detector_runner.py:")
                for ref in result["focused_test_refs"]
            )
        )
        self.assertNotIn(str(self.repo_root), json.dumps(result))

    def test_detector_provenance_v2_unknown_and_invalid_detector_id(self):
        unknown = self.vault.vault_detector_provenance_v2(detector_id="missing-pattern")
        self.assertEqual(unknown["schema"], vault_mcp_server.DETECTOR_PROVENANCE_V2_SCHEMA)
        self.assertEqual(unknown["error"], "not_found")
        self.assertEqual(unknown["detector_id"], "missing-pattern")

        missing = self.vault.vault_detector_provenance_v2()
        self.assertEqual(missing["error"], "missing_detector_id")

        invalid = self.vault.vault_detector_provenance_v2(detector_id="../secret")
        self.assertEqual(invalid["error"], "invalid_detector_id")

    def test_detector_provenance_v2_tool_schema_is_exposed(self):
        schemas = {schema["name"]: schema for schema in vault_mcp_server.TOOL_SCHEMAS}
        self.assertIn("vault_detector_provenance_v2", schemas)
        self.assertEqual(
            schemas["vault_detector_provenance_v2"]["inputSchema"]["required"],
            ["detector_id"],
        )


if __name__ == "__main__":
    unittest.main()
