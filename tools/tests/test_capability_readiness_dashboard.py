"""Tests for tools/audit/capability-readiness-dashboard.py (Lane W4.11).

Synthetic fixtures only (synthetic_fixture: true). A fake repo root is
scaffolded with a Makefile, a tools/ tree, a detectors/ tree and a small
corpus so each dashboard axis (exists / wired / tested / exercised) and
the GREEN/YELLOW/RED grading can be exercised without touching the real
corpus.
"""

from __future__ import annotations

import importlib.util
import json
import tempfile
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent.parent
TOOL_PATH = REPO_ROOT / "tools" / "audit" / "capability-readiness-dashboard.py"


def _load_module():
    spec = importlib.util.spec_from_file_location(
        "capability_readiness_dashboard", str(TOOL_PATH)
    )
    mod = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(mod)
    return mod


CRD = _load_module()


def _scaffold(tmp: Path) -> Path:
    """Build a minimal synthetic repo root (synthetic_fixture: true)."""
    root = tmp / "repo"
    (root / "tools" / "audit").mkdir(parents=True)
    (root / "tools" / "tests").mkdir(parents=True)
    (root / "detectors" / "rust_wave1").mkdir(parents=True)
    (root / "detectors" / "wave1").mkdir(parents=True)
    (root / "audit" / "corpus_tags" / "tags").mkdir(parents=True)
    (root / "audit" / "corpus_tags" / "derived").mkdir(parents=True)

    # Detectors: 2 rust, 1 solidity.
    (root / "detectors" / "rust_wave1" / "d1.py").write_text("# det\n")
    (root / "detectors" / "rust_wave1" / "d2.py").write_text("# det\n")
    (root / "detectors" / "wave1" / "s1.py").write_text("# det\n")

    # MCP server with 2 callables.
    (root / "tools" / "vault-mcp-server.py").write_text(
        '{"name": "vault_get"}\n{"name": "vault_search"}\n'
    )

    # Corpus tag YAMLs.
    for i in range(3):
        (root / "audit" / "corpus_tags" / "tags" / f"t{i}.yaml").write_text("x: 1\n")
    rq = root / "audit" / "corpus_tags" / "derived" / "record_quality.jsonl"
    rq.write_text(
        json.dumps(
            {"record_tier": "submission-derived",
             "reason": "verification_tier tier-1 (live-API verified)"}
        )
        + "\n"
        + json.dumps({"record_tier": "synthetic", "reason": "no tier here"})
        + "\n"
    )

    # Capability files referenced by the registry.
    for rel in [
        "detectors/run_custom.py",
        "detectors/run_regex_detectors.py",
        "tools/engage.py",
        "tools/audit-deep.sh",
        "tools/audit/universal_fp_runner.py",
        "tools/audit/fp_tp_feedback_loop.py",
        "tools/audit/invariant-harness-generator.py",
        "tools/halmos-runner.sh",
        "tools/symbolic-runner.sh",
        "tools/medusa-fuzz.sh",
        "tools/echidna-campaign.sh",
        "tools/base-evm-config-coverage.py",
        "tools/hackerman-stratify-verification-tier.py",
    ]:
        p = root / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text("# stub\n")

    # Test files (sibling test coverage signals).
    for name in [
        "test_universal_fp_runner.py",
        "test_vault_mcp_server.py",
        "test_makefile_vault_routing.py",
        "test_audit_deep_target.py",
        "test_fp_tp_feedback_loop.py",
        "test_invariant_harness_generator.py",
        "test_symbolic_runner.py",
        "test_hackerman_stratify_verification_tier.py",
        "test_medusa_fuzz.py",
        "test_echidna_campaign.py",
    ]:
        (root / "tools" / "tests" / name).write_text("# test\n")

    # Makefile wiring all W4.11-closed targets; medusa/echidna additionally
    # referenced in the audit-deep recipe body.
    (root / "Makefile").write_text(
        "regex-detectors:\n\t@echo det\n"
        "mcp-callable-count:\n\t@echo mcp\n"
        "audit:\n\t@echo audit\n"
        "audit-deep:\n"
        "\tbash tools/medusa-fuzz.sh $$ws\n"
        "\tbash tools/echidna-campaign.sh $$ws\n"
        "wave3-fp-runner:\n\t@echo fp\n"
        "fp-tp-feedback-loop:\n\t@echo fptp\n"
        "tier-stratify:\n\t@echo tier\n"
        "invariant-harness-gen:\n\t@echo inv\n"
        "symbolic-runner-test:\n\t@echo sym\n"
        "a11-precompile-diff:\n\t@echo diff\n"
    )
    return root


class TestCapabilityReadinessDashboard(unittest.TestCase):
    def test_real_repo_renders(self):
        """Against the real repo the dashboard renders with no RED."""
        dash = CRD.build_dashboard(REPO_ROOT)
        self.assertEqual(dash["schema"], CRD.SCHEMA_ID)
        self.assertEqual(dash["tally"][CRD.RED], 0,
                         "no capability should be RED on the real repo")
        self.assertGreater(dash["surface"]["mcp_callables"], 0)
        self.assertGreater(dash["surface"]["detectors"]["total"], 0)

    def test_synthetic_grading(self):
        with tempfile.TemporaryDirectory() as td:
            root = _scaffold(Path(td))
            dash = CRD.build_dashboard(root)
            caps = {c["id"]: c for c in dash["capabilities"]}

            # Detector engine: exists+wired+tested -> GREEN.
            self.assertEqual(caps["detector-engine"]["colour"], CRD.GREEN)
            # FP/TP feedback loop: W4.11 closed - wired via make target -> GREEN.
            self.assertEqual(caps["fp-tp-feedback-loop"]["colour"], CRD.GREEN)
            self.assertTrue(caps["fp-tp-feedback-loop"]["wired"])
            # Tier stratification: W4.11 closed - wired via make target -> GREEN.
            self.assertEqual(caps["corpus-tier-stratification"]["colour"], CRD.GREEN)
            self.assertTrue(caps["corpus-tier-stratification"]["wired"])
            # Medusa: wired via pipeline recipe body + W4.11 sibling test -> GREEN.
            self.assertEqual(caps["fuzz-medusa"]["colour"], CRD.GREEN)
            self.assertTrue(caps["fuzz-medusa"]["wired"])
            self.assertTrue(caps["fuzz-medusa"]["tested"])
            # Echidna: wired via pipeline recipe body + W4.11 sibling test -> GREEN.
            self.assertEqual(caps["fuzz-echidna"]["colour"], CRD.GREEN)
            self.assertTrue(caps["fuzz-echidna"]["tested"])
            # Invariant harness gen: wired+tested -> GREEN.
            self.assertEqual(caps["invariant-harness-generator"]["colour"], CRD.GREEN)

    def test_red_when_file_missing(self):
        with tempfile.TemporaryDirectory() as td:
            root = _scaffold(Path(td))
            (root / "tools" / "audit" / "universal_fp_runner.py").unlink()
            dash = CRD.build_dashboard(root)
            caps = {c["id"]: c for c in dash["capabilities"]}
            self.assertEqual(caps["universal-fp-runner"]["colour"], CRD.RED)
            self.assertFalse(caps["universal-fp-runner"]["exists"])

    def test_corpus_tier_extraction(self):
        with tempfile.TemporaryDirectory() as td:
            root = _scaffold(Path(td))
            corp = CRD.probe_corpus(root)
            self.assertEqual(corp["record_quality_rows"], 2)
            self.assertEqual(corp["tag_yaml_count"], 3)
            self.assertIn("tier-1", corp["verification_tier_stratification"])
            self.assertIn("unstated", corp["verification_tier_stratification"])
            self.assertIn("submission-derived", corp["record_tier_stratification"])

    def test_markdown_render(self):
        with tempfile.TemporaryDirectory() as td:
            root = _scaffold(Path(td))
            dash = CRD.build_dashboard(root)
            md = CRD.render_markdown(dash)
            self.assertIn("# Capability-readiness dashboard", md)
            self.assertIn("Tally:", md)
            self.assertIn("| Capability | Colour |", md)


if __name__ == "__main__":
    unittest.main()
