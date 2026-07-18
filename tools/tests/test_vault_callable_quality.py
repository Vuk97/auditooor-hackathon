"""Quality regression tests for hacker MCP callables.

CAP-HACKER-MCP-SUITE-FIX-2026-05-26 (lane-CAPABILITY-HACKER-MCP-SUITE-FIX):

Regression coverage for the 7 broken hacker MCP callables identified by the
SMT hunt's hacker-stack-reeval lane:

- vault_hackerman_chain_candidates    (perf regression >60s timeout)
- vault_hackerman_exploit_predicates  (returned 0 bytes; stale sidecar)
- vault_hackerman_detector_relationships (returned 0 bytes; stale sidecar)
- vault_hackerman_novel_vector_context (OpenVM bias; 222k pairs -> 0 hypotheses)
- vault_adversarial_hypothesis_differential (documented Layer-1 but Layer-2)
- vault_attack_class_evidence_v3       (documented Layer-1 but Layer-2)
- vault_function_mindset               (documented Layer-1 but Layer-2)

These tests assert:

  A. The 4 hackerman-corpus callables return substantive output (records >= N)
     in under TIME_BUDGET_S seconds when the sidecars are fresh OR within the
     stale-tolerance window (AUDITOOOR_SIDECAR_STALE_TOLERANCE_PCT, default 5%).
  B. vault_hackerman_novel_vector_context accepts and honors the new
     `exclude_target_repos` and `min_shape_overlap` parameters.
  C. vault_hackerman_detector_relationships autodiscovers
     `<workspace>/engage_report.{json,md}` when called with only a
     workspace_path.
  D. The 3 Layer-2 callables (function_mindset, attack_class_evidence_v3,
     adversarial_hypothesis_differential) return `degraded:true` with a clear
     reason when invoked without their required Layer-2 inputs - they do NOT
     silently return empty data.

Tests skip with informative messages when the corpus or sidecars are missing
so the suite remains green on a fresh checkout that has not built the sidecars.
"""

from __future__ import annotations

import importlib.util
import json
import os
import sys
import tempfile
import time
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
MODULE_PATH = REPO_ROOT / "tools" / "vault-mcp-server.py"
TAGS_DIR = REPO_ROOT / "audit" / "corpus_tags" / "tags"
DERIVED_DIR = REPO_ROOT / "audit" / "corpus_tags" / "derived"

# Per-call wall time budget. Sidecar-backed calls should finish in <10s on a
# warm cache; cold start can take 5-10s when the in-memory catalog is built.
TIME_BUDGET_S = 20.0


def _load_module():
    spec = importlib.util.spec_from_file_location("vault_mcp_server", MODULE_PATH)
    module = importlib.util.module_from_spec(spec)
    assert spec is not None and spec.loader is not None
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def _corpus_available() -> bool:
    return TAGS_DIR.is_dir() and any(TAGS_DIR.iterdir())


def _sidecar_present(stem: str) -> bool:
    manifest = DERIVED_DIR / f"{stem}.manifest.json"
    monolith = DERIVED_DIR / f"{stem}.jsonl"
    return manifest.is_file() or (monolith.is_file() and monolith.stat().st_size > 0)


class HackermanCorpusCallableQualityTests(unittest.TestCase):
    """Fix #34: assert the 4 hackerman corpus callables return substantive
    output and respect the time budget."""

    @classmethod
    def setUpClass(cls) -> None:
        if not _corpus_available():
            raise unittest.SkipTest(f"corpus tags missing at {TAGS_DIR}")
        cls.module = _load_module()
        # VaultQuery(vault_dir, repo_root) - vault_dir can be a synthetic path
        # because the hacker corpus callables read corpus_tags/ via repo_root.
        cls.vq = cls.module.VaultQuery(REPO_ROOT / "obsidian-vault", REPO_ROOT)

    def _assert_under_budget(self, elapsed: float, callable_name: str) -> None:
        self.assertLess(
            elapsed,
            TIME_BUDGET_S,
            f"{callable_name} exceeded budget: {elapsed:.2f}s > {TIME_BUDGET_S}s",
        )

    def test_hackerman_exploit_predicates_returns_records(self) -> None:
        if not _sidecar_present("exploit_predicates"):
            self.skipTest("exploit_predicates sidecar not built")
        t0 = time.time()
        out = self.vq.vault_hackerman_exploit_predicates(limit=3)
        elapsed = time.time() - t0
        self._assert_under_budget(elapsed, "vault_hackerman_exploit_predicates")
        self.assertEqual(out["kind"], "hackerman_exploit_predicates")
        self.assertGreaterEqual(int(out.get("total_records_available") or 0), 100)
        self.assertGreater(len(out.get("records") or []), 0)
        first = out["records"][0]
        # Records must carry the core predicate-shape fields
        self.assertIn("record_id", first)
        self.assertIn("attack_class", first)
        self.assertIn("preconditions", first)

    def test_hackerman_detector_relationships_loads_sidecar(self) -> None:
        if not _sidecar_present("detector_relationship_records"):
            self.skipTest("detector_relationship_records sidecar not built")
        t0 = time.time()
        out = self.vq.vault_hackerman_detector_relationships(limit=3)
        elapsed = time.time() - t0
        self._assert_under_budget(elapsed, "vault_hackerman_detector_relationships")
        self.assertEqual(out["kind"], "hackerman_detector_relationships")
        summary = out.get("summary") or {}
        # Without an engage_report no detectors will be scanned; that is honest
        # behavior. But records_loaded MUST be > 0 - that confirms the sidecar
        # is actually being read.
        self.assertGreater(int(summary.get("records_loaded") or 0), 100)
        # sidecar_used should be True; if it falls through to slow fallback the
        # response shape changes and we want the test to fail.
        self.assertTrue(out.get("sidecar_used"))

    def test_hackerman_chain_candidates_returns_candidates(self) -> None:
        if not _sidecar_present("chain_candidates"):
            self.skipTest("chain_candidates sidecar not built")
        t0 = time.time()
        out = self.vq.vault_hackerman_chain_candidates(limit=3, include_generic=False)
        elapsed = time.time() - t0
        # chain_candidates loads two sidecars; allow extra headroom
        self.assertLess(
            elapsed,
            TIME_BUDGET_S + 10,
            f"chain_candidates exceeded budget: {elapsed:.2f}s",
        )
        self.assertEqual(out["kind"], "hackerman_chain_candidates")
        # Either the legacy `candidates` block OR the unified `chains` block
        # should be non-empty; the test passes if at least one is populated.
        self.assertTrue(
            int(out.get("total_candidates") or 0) > 0 or int(out.get("total_chains") or 0) > 0,
            f"chain_candidates: both candidates and chains empty: {out!r}",
        )

    def test_hackerman_novel_vector_excludes_dominant_repo(self) -> None:
        """Fix #32: OpenVM bias - exclude_target_repos + min_shape_overlap
        unblock hypothesis generation on non-OpenVM workspaces."""
        # No sidecar dependency - this callable builds the catalog in-memory
        t0 = time.time()
        out = self.vq.vault_hackerman_novel_vector_context(
            limit=3,
            exclude_target_repos=["openvm"],
            max_targets=200,
            min_shape_overlap=0.0,
        )
        elapsed = time.time() - t0
        # Allow extra headroom (this builds an in-memory catalog of all 26k records)
        self.assertLess(
            elapsed,
            60.0,
            f"novel_vector exceeded budget: {elapsed:.2f}s",
        )
        # inputs must reflect the new params
        inputs = out.get("inputs") or {}
        self.assertEqual(inputs.get("exclude_target_repos"), ["openvm"])
        self.assertEqual(inputs.get("max_targets"), 200)
        # filtered_target_excluded_repo MUST be > 0 (OpenVM had ~20+ records)
        self.assertGreater(
            int(out.get("filtered_target_excluded_repo") or 0),
            0,
            "novel_vector did not actually exclude any OpenVM records",
        )
        # target_selection_preview MUST contain at least one non-OpenVM repo
        previews = out.get("target_selection_preview") or []
        non_openvm = [
            row for row in previews
            if "openvm" not in str(row.get("target_repo") or "").lower()
        ]
        self.assertGreater(
            len(non_openvm),
            0,
            "target_selection_preview is still 100% OpenVM after exclude",
        )


class HackermanLayer2RequiredInputTests(unittest.TestCase):
    """Fix #33: assert the 3 Layer-2 callables return `degraded:true` with a
    clear reason when invoked without their required inputs - they do NOT
    silently return empty data."""

    @classmethod
    def setUpClass(cls) -> None:
        cls.module = _load_module()
        # VaultQuery(vault_dir, repo_root) - vault_dir can be a synthetic path
        # because the hacker corpus callables read corpus_tags/ via repo_root.
        cls.vq = cls.module.VaultQuery(REPO_ROOT / "obsidian-vault", REPO_ROOT)

    def test_function_mindset_requires_target_repo_and_file_path(self) -> None:
        out = self.vq.vault_function_mindset()
        self.assertTrue(out.get("degraded"), f"expected degraded=True, got: {out}")
        self.assertEqual(out.get("reason"), "missing_required_target_repo_or_file_path")
        self.assertEqual(out.get("ranked_attack_classes") or [], [])

    def test_attack_class_evidence_v3_requires_attack_class(self) -> None:
        out = self.vq.vault_attack_class_evidence_v3()
        self.assertTrue(out.get("degraded"), f"expected degraded=True, got: {out}")
        self.assertEqual(out.get("reason"), "missing_attack_class")

    def test_attack_class_evidence_v3_with_class_returns_records(self) -> None:
        # Sanity check: with a class, the callable should return records OR
        # an honest degraded response (corpus may not have rows for the class).
        out = self.vq.vault_attack_class_evidence_v3(attack_class="reentrancy", limit=2)
        # Either records returned OR an honest no-rows-for-class indication;
        # both are acceptable - what we DON'T want is silent emptiness.
        self.assertIn("records", out)
        if not out.get("degraded"):
            # When not degraded, schema fields should be present
            self.assertEqual(out.get("schema"), self.module.ATTACK_CLASS_EVIDENCE_V3_SCHEMA)

    def test_adversarial_hypothesis_differential_warns_when_empty(self) -> None:
        # vault_adversarial_hypothesis_differential does NOT use the
        # degraded:true convention; instead it returns warnings[] when
        # source_paths / source_path / sources / manifest_path are absent.
        # Confirm it emits an honest warning instead of silent emptiness.
        out = self.vq.vault_adversarial_hypothesis_differential()
        warnings = out.get("warnings") or []
        self.assertGreater(
            len(warnings),
            0,
            "adversarial_hypothesis_differential should warn on missing source inputs",
        )
        # The warning text should mention source paths or manifest
        combined = " ".join(str(w) for w in warnings).lower()
        self.assertTrue(
            "source" in combined or "manifest" in combined,
            f"warning text should mention source/manifest, got: {warnings}",
        )


class DetectorRelationshipsAutodiscoveryTests(unittest.TestCase):
    """Fix #34 part B: vault_hackerman_detector_relationships autodiscovers
    <workspace>/engage_report.{json,md} when given only workspace_path."""

    @classmethod
    def setUpClass(cls) -> None:
        if not _sidecar_present("detector_relationship_records"):
            raise unittest.SkipTest("detector_relationship_records sidecar not built")
        cls.module = _load_module()
        # VaultQuery(vault_dir, repo_root) - vault_dir can be a synthetic path
        # because the hacker corpus callables read corpus_tags/ via repo_root.
        cls.vq = cls.module.VaultQuery(REPO_ROOT / "obsidian-vault", REPO_ROOT)

    def test_autodiscovers_engage_report_md(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            workspace = Path(tmp) / "synthetic_workspace"
            workspace.mkdir()
            # synthetic_fixture: true
            engage_report = workspace / "engage_report.md"
            engage_report.write_text(
                "# Engage report\n\n"
                "## Cluster 1: Reentrancy\n"
                "- src/Foo.sol:42 - external call without check\n",
                encoding="utf-8",
            )
            out = self.vq.vault_hackerman_detector_relationships(
                workspace_path=str(workspace),
                limit=3,
            )
            inputs = out.get("inputs") or {}
            self.assertTrue(
                inputs.get("engage_report_autodiscovered"),
                f"expected engage_report_autodiscovered=True, got inputs={inputs}",
            )
            # The discovered path should be reflected
            engage_ref = inputs.get("engage_report") or ""
            self.assertIn("engage_report.md", str(engage_ref))

    def test_autodiscovers_engage_report_in_auditooor_dir(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            workspace = Path(tmp) / "synthetic_workspace"
            (workspace / ".auditooor").mkdir(parents=True)
            engage_report = workspace / ".auditooor" / "engage_report.json"
            # synthetic_fixture: true
            engage_report.write_text(
                json.dumps({"detectors": []}),
                encoding="utf-8",
            )
            out = self.vq.vault_hackerman_detector_relationships(
                workspace_path=str(workspace),
                limit=3,
            )
            inputs = out.get("inputs") or {}
            self.assertTrue(
                inputs.get("engage_report_autodiscovered"),
                f"expected autodiscovery from .auditooor/, got inputs={inputs}",
            )

    def test_no_autodiscovery_when_engage_report_passed_explicitly(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            workspace = Path(tmp) / "synthetic_workspace"
            workspace.mkdir()
            explicit_report = Path(tmp) / "explicit_report.md"
            explicit_report.write_text("# explicit\n", encoding="utf-8")
            out = self.vq.vault_hackerman_detector_relationships(
                workspace_path=str(workspace),
                engage_report=str(explicit_report),
                limit=3,
            )
            inputs = out.get("inputs") or {}
            self.assertFalse(
                inputs.get("engage_report_autodiscovered"),
                f"autodiscovery should not fire when engage_report is explicit, got inputs={inputs}",
            )


class StaleTolerantFreshnessTests(unittest.TestCase):
    """Fix #31/#34: AUDITOOOR_SIDECAR_STALE_TOLERANCE_PCT allows the sidecars
    to be reused on minor corpus drift instead of falling back to a 60-90s
    re-parse."""

    def _load_sidecar_module(self, script: str, name: str):
        path = REPO_ROOT / "tools" / script
        spec = importlib.util.spec_from_file_location(name, path)
        mod = importlib.util.module_from_spec(spec)
        # Ensure tools dir on path for the module's own imports
        tools_dir = str(REPO_ROOT / "tools")
        added = False
        if tools_dir not in sys.path:
            sys.path.insert(0, tools_dir)
            added = True
        try:
            spec.loader.exec_module(mod)
        finally:
            if added:
                sys.path.remove(tools_dir)
        return mod

    def test_freshness_helper_accepts_minor_drift(self) -> None:
        from pathlib import Path as _Path
        mod = self._load_sidecar_module(
            "hackerman-exploit-predicates-sidecar.py",
            "_test_stale_tolerance_predicates",
        )
        # Hand-built fake meta with drift below the default 5% tolerance:
        # cached=10000, current=10010 -> 0.10% drift, well under 5%.
        fake_tag_dir = REPO_ROOT  # arbitrary; we patch corpus_content_fingerprint

        # Patch the module's corpus_content_fingerprint to return a known fake
        original = mod.corpus_content_fingerprint
        try:
            mod.corpus_content_fingerprint = lambda *_a, **_k: ("differentfingerprint", 10010)
            meta = {"corpus_fingerprint": "originalfingerprint", "corpus_file_count": 10000}
            fresh, reason = mod._freshness_from_meta(fake_tag_dir, meta)
            self.assertTrue(fresh, f"expected fresh=True for 0.10% drift, got reason={reason}")
            self.assertIn("stale-tolerant", reason)
        finally:
            mod.corpus_content_fingerprint = original

    def test_freshness_helper_rejects_large_drift(self) -> None:
        mod = self._load_sidecar_module(
            "hackerman-exploit-predicates-sidecar.py",
            "_test_stale_tolerance_predicates_large",
        )
        original = mod.corpus_content_fingerprint
        try:
            # cached=10000, current=12000 -> 20% drift, exceeds 5% tolerance
            mod.corpus_content_fingerprint = lambda *_a, **_k: ("differentfingerprint", 12000)
            meta = {"corpus_fingerprint": "originalfingerprint", "corpus_file_count": 10000}
            fresh, reason = mod._freshness_from_meta(REPO_ROOT, meta)
            self.assertFalse(fresh, f"expected fresh=False for 20% drift, got reason={reason}")
            self.assertIn("exceeds tolerance", reason)
        finally:
            mod.corpus_content_fingerprint = original

    def test_freshness_helper_rejects_same_count_diff_fingerprint(self) -> None:
        """A content modification (file count unchanged) MUST be stale.
        Pure-modification cases preserve the historical contract that callers
        rely on (e.g. test_freshness_check_detects_modified_record in the
        sibling sidecar test suite)."""
        mod = self._load_sidecar_module(
            "hackerman-exploit-predicates-sidecar.py",
            "_test_stale_tolerance_predicates_samecount",
        )
        original = mod.corpus_content_fingerprint
        try:
            mod.corpus_content_fingerprint = lambda *_a, **_k: ("differentfingerprint", 10000)
            meta = {"corpus_fingerprint": "originalfingerprint", "corpus_file_count": 10000}
            fresh, reason = mod._freshness_from_meta(REPO_ROOT, meta)
            self.assertFalse(fresh, f"expected fresh=False on pure-modification, got reason={reason}")
            self.assertIn("fingerprint changed", reason)
        finally:
            mod.corpus_content_fingerprint = original

    def test_freshness_helper_strict_mode_via_env(self) -> None:
        """When AUDITOOOR_SIDECAR_STALE_TOLERANCE_PCT=0, all drift fails."""
        mod = self._load_sidecar_module(
            "hackerman-exploit-predicates-sidecar.py",
            "_test_stale_tolerance_predicates_strict",
        )
        original = mod.corpus_content_fingerprint
        prev_env = os.environ.get("AUDITOOOR_SIDECAR_STALE_TOLERANCE_PCT")
        os.environ["AUDITOOOR_SIDECAR_STALE_TOLERANCE_PCT"] = "0"
        try:
            mod.corpus_content_fingerprint = lambda *_a, **_k: ("differentfingerprint", 10010)
            meta = {"corpus_fingerprint": "originalfingerprint", "corpus_file_count": 10000}
            fresh, reason = mod._freshness_from_meta(REPO_ROOT, meta)
            self.assertFalse(fresh, f"expected fresh=False in strict mode")
            # In strict mode, the reason is the legacy one
            self.assertIn("changed", reason)
        finally:
            mod.corpus_content_fingerprint = original
            if prev_env is None:
                os.environ.pop("AUDITOOOR_SIDECAR_STALE_TOLERANCE_PCT", None)
            else:
                os.environ["AUDITOOOR_SIDECAR_STALE_TOLERANCE_PCT"] = prev_env


if __name__ == "__main__":
    unittest.main()
