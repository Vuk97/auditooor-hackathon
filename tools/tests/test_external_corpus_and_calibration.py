"""Tests for external-corpus-fetch + vault_external_corpus_search + vault_llm_calibration (PR #658 commit 7)."""
import importlib.util
import json
import os
import pathlib
import subprocess
import sys
import tempfile
import unittest

REPO = pathlib.Path(__file__).resolve().parents[2]
FETCH = REPO / "tools" / "external-corpus-fetch.py"
MCP = REPO / "tools" / "vault-mcp-server.py"


def _load_mcp_module():
    spec = importlib.util.spec_from_file_location("vault_mcp_server_test", MCP)
    if spec is None or spec.loader is None:
        raise RuntimeError("failed to load vault-mcp-server.py")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


class TestExternalCorpusFetch(unittest.TestCase):
    def test_kind_required(self):
        proc = subprocess.run(["python3", str(FETCH)], capture_output=True, text=True)
        self.assertNotEqual(proc.returncode, 0)
        self.assertIn("--kind", proc.stderr)

    def test_invalid_kind(self):
        proc = subprocess.run(["python3", str(FETCH), "--kind=nonexistent"], capture_output=True, text=True)
        self.assertNotEqual(proc.returncode, 0)

    def test_dry_run_dispatches_to_zkbugs(self):
        # --dry-run + --help on the underlying tool should exit cleanly
        proc = subprocess.run(
            ["python3", str(FETCH), "--kind=zkbugs", "--dry-run", "--", "--help"],
            capture_output=True, text=True,
        )
        self.assertIn("dispatching", proc.stderr)
        self.assertIn("zkbugs-ingest.py", proc.stderr)

    def test_extras_passed_through(self):
        proc = subprocess.run(
            ["python3", str(FETCH), "--kind=zkbugs", "--", "--zkbugs-root", "/nonexistent"],
            capture_output=True, text=True,
        )
        self.assertIn("--zkbugs-root /nonexistent", proc.stderr)


class TestVaultExternalCorpusSearch(unittest.TestCase):
    def _call(self, **args):
        proc = subprocess.run(
            ["python3", str(MCP), "--call", "vault_external_corpus_search", "--args", json.dumps(args)],
            capture_output=True, text=True,
        )
        # Skip [vault-mcp-server] prefix line
        lines = proc.stdout.split("\n")
        for i, l in enumerate(lines):
            if l.startswith("{"):
                return json.loads("\n".join(lines[i:]))
        raise RuntimeError(f"no JSON in output: {proc.stdout}")

    def test_schema_is_correct(self):
        result = self._call(corpus="rust", query="abort", limit=2)
        self.assertEqual(result["schema"], "auditooor.vault_external_corpus_search.v1")

    def test_corpus_filter_works(self):
        result = self._call(corpus="rust", query="abort", limit=5)
        self.assertEqual(result["corpus"], "rust")
        # Should find at least 1 result in rust corpus
        self.assertGreater(len(result["results"]), 0)

    def test_limit_caps_results(self):
        result = self._call(corpus="rust", query="abort", limit=1)
        self.assertLessEqual(len(result["results"]), 1)

    def test_unknown_corpus_uses_all(self):
        result = self._call(corpus="zkbugs", query="bound-check", limit=3)
        # zkbugs dir may be empty; just verify schema doesn't crash
        self.assertEqual(result["schema"], "auditooor.vault_external_corpus_search.v1")


class TestVaultExternalCorpusSearchScoring(unittest.TestCase):
    def setUp(self):
        self.tmpdir = tempfile.TemporaryDirectory()
        self.repo_root = pathlib.Path(self.tmpdir.name)
        (self.repo_root / "obsidian-vault").mkdir()
        self.module = _load_mcp_module()
        self.query = self.module.VaultQuery(self.repo_root / "obsidian-vault", repo_root=self.repo_root)

    def tearDown(self):
        self.tmpdir.cleanup()

    def _write(self, relpath: str, content: str):
        path = self.repo_root / relpath
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content, encoding="utf-8")
        return path

    def test_ranking_prefers_metadata_dense_match(self):
        self._write(
            "reference/patterns.dsl.r94_solodit_rust/missing-bound-check.yaml",
            """id: missing-bound-check
title: Missing bound check on commission rate
language: rust
framework: anchor
attack_class: input-validation
pattern: rust.missing-bound-check
description: Missing bound check permits commission rate griefing.
""",
        )
        self._write(
            "reference/patterns.dsl.r94_solodit_rust/weak-match.md",
            """# Notes

This report mentions a missing bound check once in passing, without metadata.
""",
        )

        result = self.query.vault_external_corpus_search(corpus="rust", query="missing bound check", limit=5)
        self.assertEqual(result["query_terms"], ["missing", "bound", "check"])
        self.assertGreaterEqual(len(result["results"]), 1)
        top = result["results"][0]
        self.assertEqual(top["slug"], "missing-bound-check")
        self.assertEqual(top["corpus"], "rust")
        self.assertEqual(top["language"], "rust")
        self.assertEqual(top["framework"], "anchor")
        self.assertEqual(top["attack_class"], "input-validation")
        self.assertEqual(top["pattern_id"], "rust.missing-bound-check")
        self.assertIn("matched_terms", top)
        self.assertEqual(top["matched_terms"], ["missing", "bound", "check"])
        self.assertIn("matched_fields", top)
        self.assertIn("pattern_id", top["matched_fields"])
        self.assertIn("title", top["matched_fields"])
        self.assertGreater(top["score"], result["results"][-1]["score"])
        self.assertGreater(top["normalized_score"], 0.0)

    def test_all_corpus_search_preserves_backward_fields_and_infers_corpus(self):
        self._write(
            ".audit_logs/zkbugs_farming/circom-nullifier.md",
            """---
title: Circom nullifier reuse
attack_class: replay
framework: circom
---
Nullifier reuse lets an attacker replay a proof.
""",
        )

        result = self.query.vault_external_corpus_search(query="nullifier replay", limit=3)
        self.assertEqual(result["corpus"], "all")
        self.assertEqual(result["schema"], "auditooor.vault_external_corpus_search.v1")
        hit = result["results"][0]
        for key in ("path", "slug", "snippet", "source", "score"):
            self.assertIn(key, hit)
        self.assertEqual(hit["corpus"], "zkbugs")
        self.assertEqual(hit["framework"], "circom")
        self.assertEqual(hit["attack_class"], "replay")
        self.assertEqual(hit["source"], "all")
        self.assertGreaterEqual(hit["term_match_count"], 1)

    def test_out_of_repo_external_memory_hit_path_is_redacted(self):
        prefixed_vault = self.repo_root.parent / f"{self.repo_root.name}-shadow" / "obsidian-vault"
        (prefixed_vault / "external-memory").mkdir(parents=True)
        (prefixed_vault / "external-memory" / "nullifier-replay.md").write_text(
            """---
title: Nullifier replay note
attack_class: replay
framework: circom
---
Nullifier replay permits proof reuse.
""",
            encoding="utf-8",
        )
        query = self.module.VaultQuery(prefixed_vault, repo_root=self.repo_root)

        result = query.vault_external_corpus_search(query="nullifier replay", limit=3)

        self.assertGreaterEqual(len(result["results"]), 1)
        self.assertEqual(result["results"][0]["path"], "[redacted-local-path]")


class TestVaultLlmCalibration(unittest.TestCase):
    def _call(self, **args):
        proc = subprocess.run(
            ["python3", str(MCP), "--call", "vault_llm_calibration", "--args", json.dumps(args)],
            capture_output=True, text=True,
        )
        lines = proc.stdout.split("\n")
        for i, l in enumerate(lines):
            if l.startswith("{"):
                return json.loads("\n".join(lines[i:]))
        raise RuntimeError(f"no JSON in output: {proc.stdout}")

    def test_schema(self):
        result = self._call(provider="claude", limit=3)
        self.assertEqual(result["schema"], "auditooor.vault_llm_calibration.v1")

    def test_provider_filter(self):
        result = self._call(provider="claude", limit=5)
        # Should return claude rows or "no log" (both are valid for empty
        # calibration state). Not a hard assert on n_total.
        self.assertIn("provider", result)
        self.assertEqual(result["provider"], "claude")

    def test_recommended_requires_min_decided(self):
        result = self._call(provider="claude", limit=5)
        # Recommended requires >=10 decided rows; in fresh state n_decided is small
        if result.get("n_decided", 0) < 10:
            self.assertFalse(result.get("recommended"))


if __name__ == "__main__":
    unittest.main()
