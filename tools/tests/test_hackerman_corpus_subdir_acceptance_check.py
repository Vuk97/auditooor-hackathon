"""Tests for tools/hackerman-corpus-subdir-acceptance-check.py.

Builds small synthetic corpus subtrees and calls the loaded module directly
to keep the suite fast and deterministic.
"""
from __future__ import annotations

import importlib.util
import json
import tempfile
import unittest
from pathlib import Path
from typing import List, Optional


REPO_ROOT = Path(__file__).resolve().parents[2]
TOOL_PATH = REPO_ROOT / "tools" / "hackerman-corpus-subdir-acceptance-check.py"


def _load_tool():
    spec = importlib.util.spec_from_file_location(
        "_hackerman_corpus_subdir_acceptance_check", str(TOOL_PATH)
    )
    mod = importlib.util.module_from_spec(spec)
    assert spec.loader
    spec.loader.exec_module(mod)
    return mod


def _v1_yaml(
    *,
    record_id: str,
    tier_tag: Optional[str] = "tier-1-verified-realtime-api",
    extra_tags: Optional[List[str]] = None,
    schema_version: str = "auditooor.hackerman_record.v1",
    omit_shape_tags: bool = False,
) -> str:
    tags: List[str] = list(extra_tags or ["bug-class-foo", "pkg-example"])
    if tier_tag:
        tags.append(f"verification_tier:{tier_tag}")
    tags_block = "\n".join(f"    - {t}" for t in tags)
    shape_block = (
        "function_shape:\n"
        "  raw_signature: example\n"
        + ("" if omit_shape_tags else f"  shape_tags:\n{tags_block}\n")
    )
    return (
        f"schema_version: {schema_version}\n"
        f"record_id: {record_id}\n"
        "source_audit_ref: example\n"
        "target_domain: dlt\n"
        "target_language: go\n"
        "target_repo: example/repo\n"
        "target_component: example\n"
        f"{shape_block}"
        "bug_class: example\n"
        "attack_class: example\n"
        "attacker_role: unprivileged\n"
        "attacker_action_sequence: example\n"
        "required_preconditions:\n"
        "  - example\n"
        "impact_class: dos\n"
        "impact_actor: validator-set\n"
        "impact_dollar_class: $100K-$1M\n"
        "fix_pattern: example\n"
        "fix_anti_pattern_avoided: example\n"
        "severity_at_finding: high\n"
        "year: 2025\n"
        "record_tier: public-corpus\n"
        "source_extraction_method: corpus-etl\n"
        "source_extraction_confidence: 0.9\n"
    )


def _write_record(corpus_dir: Path, slug: str, body: str) -> Path:
    sub = corpus_dir / slug
    sub.mkdir(parents=True, exist_ok=True)
    path = sub / "record.yaml"
    path.write_text(body, encoding="utf-8")
    return path


class CorpusSubdirAcceptanceCheckTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.mod = _load_tool()

    # ------------------------------------------------------------------ #
    # 1. tier-1-heavy directory: passes the 80% threshold
    # ------------------------------------------------------------------ #
    def test_tier1_heavy_pass(self):
        with tempfile.TemporaryDirectory() as tmp:
            corpus = Path(tmp) / "tier1_heavy"
            corpus.mkdir()
            for i in range(9):
                _write_record(
                    corpus,
                    f"rec{i}",
                    _v1_yaml(
                        record_id=f"rid-{i}",
                        tier_tag="tier-1-verified-realtime-api",
                    ),
                )
            # 1 tier-3 record → 9/10 = 90% tier-1 → pass
            _write_record(
                corpus,
                "rec9",
                _v1_yaml(
                    record_id="rid-9",
                    tier_tag="tier-3-synthetic-taxonomy-anchored",
                ),
            )
            rep = self.mod.audit_corpus_dir(corpus, min_coverage_pct=80.0)
            self.assertEqual(rep["verdict"], "pass")
            self.assertEqual(rep["hackerman_record_count"], 10)
            self.assertEqual(rep["bucket_counts"]["tier-1"], 9)
            self.assertEqual(rep["bucket_counts"]["tier-3"], 1)
            self.assertAlmostEqual(rep["tier1_tier2_pct"], 90.0, places=2)

    # ------------------------------------------------------------------ #
    # 2. tier-3-heavy directory: fails
    # ------------------------------------------------------------------ #
    def test_tier3_heavy_fail(self):
        with tempfile.TemporaryDirectory() as tmp:
            corpus = Path(tmp) / "tier3_heavy"
            corpus.mkdir()
            for i in range(8):
                _write_record(
                    corpus,
                    f"rec{i}",
                    _v1_yaml(
                        record_id=f"rid-{i}",
                        tier_tag="tier-3-synthetic-taxonomy-anchored",
                    ),
                )
            for i in range(8, 10):
                _write_record(
                    corpus,
                    f"rec{i}",
                    _v1_yaml(
                        record_id=f"rid-{i}",
                        tier_tag="tier-1-verified-realtime-api",
                    ),
                )
            rep = self.mod.audit_corpus_dir(corpus, min_coverage_pct=80.0)
            self.assertEqual(rep["verdict"], "fail")
            self.assertEqual(rep["bucket_counts"]["tier-3"], 8)
            self.assertEqual(rep["bucket_counts"]["tier-1"], 2)
            self.assertAlmostEqual(rep["tier1_tier2_pct"], 20.0, places=2)

    # ------------------------------------------------------------------ #
    # 3. quarantine directory is skipped
    # ------------------------------------------------------------------ #
    def test_quarantine_skip(self):
        with tempfile.TemporaryDirectory() as tmp:
            corpus = Path(tmp) / "_QUARANTINE_FABRICATED_CVE"
            corpus.mkdir()
            for i in range(3):
                _write_record(
                    corpus,
                    f"rec{i}",
                    _v1_yaml(
                        record_id=f"rid-{i}",
                        tier_tag="tier-5-quarantine",
                    ),
                )
            rep = self.mod.audit_corpus_dir(corpus, min_coverage_pct=80.0)
            self.assertEqual(rep["verdict"], "skip-quarantine")
            # quarantine path: we do not iterate records
            self.assertEqual(rep["hackerman_record_count"], 0)

    # ------------------------------------------------------------------ #
    # 4. record with missing shape_tags block fails (counts as unlabeled)
    # ------------------------------------------------------------------ #
    def test_missing_shape_tags_fail(self):
        with tempfile.TemporaryDirectory() as tmp:
            corpus = Path(tmp) / "missing_shape_tags"
            corpus.mkdir()
            # 10 records all lacking shape_tags entirely → all unlabeled
            for i in range(10):
                _write_record(
                    corpus,
                    f"rec{i}",
                    _v1_yaml(
                        record_id=f"rid-{i}",
                        tier_tag=None,
                        omit_shape_tags=True,
                    ),
                )
            rep = self.mod.audit_corpus_dir(corpus, min_coverage_pct=80.0)
            self.assertEqual(rep["verdict"], "fail")
            self.assertEqual(rep["bucket_counts"].get("unlabeled", 0), 10)
            self.assertEqual(rep["tier1_tier2_count"], 0)

    # ------------------------------------------------------------------ #
    # 5. records without verification_tier shape_tag → unlabeled, fails
    # ------------------------------------------------------------------ #
    def test_unlabeled_fail(self):
        with tempfile.TemporaryDirectory() as tmp:
            corpus = Path(tmp) / "unlabeled"
            corpus.mkdir()
            for i in range(5):
                # shape_tags present but no verification_tier:
                _write_record(
                    corpus,
                    f"rec{i}",
                    _v1_yaml(
                        record_id=f"rid-{i}",
                        tier_tag=None,
                        extra_tags=["bug-class-x", "pkg-y"],
                    ),
                )
            rep = self.mod.audit_corpus_dir(corpus, min_coverage_pct=80.0)
            self.assertEqual(rep["verdict"], "fail")
            self.assertEqual(rep["bucket_counts"].get("unlabeled", 0), 5)
            self.assertEqual(rep["tier1_tier2_pct"], 0.0)

    # ------------------------------------------------------------------ #
    # 6. mixed-pass: 4 tier-1 + 4 tier-2 + 2 tier-3 = 80% pass
    # ------------------------------------------------------------------ #
    def test_mixed_pass(self):
        with tempfile.TemporaryDirectory() as tmp:
            corpus = Path(tmp) / "mixed_pass"
            corpus.mkdir()
            for i in range(4):
                _write_record(
                    corpus,
                    f"t1-{i}",
                    _v1_yaml(
                        record_id=f"t1-{i}",
                        tier_tag="tier-1-verified-realtime-api",
                    ),
                )
            for i in range(4):
                _write_record(
                    corpus,
                    f"t2-{i}",
                    _v1_yaml(
                        record_id=f"t2-{i}",
                        tier_tag="tier-2-verified-public-archive",
                    ),
                )
            for i in range(2):
                _write_record(
                    corpus,
                    f"t3-{i}",
                    _v1_yaml(
                        record_id=f"t3-{i}",
                        tier_tag="tier-3-synthetic-taxonomy-anchored",
                    ),
                )
            rep = self.mod.audit_corpus_dir(corpus, min_coverage_pct=80.0)
            self.assertEqual(rep["verdict"], "pass")
            self.assertAlmostEqual(rep["tier1_tier2_pct"], 80.0, places=2)

    # ------------------------------------------------------------------ #
    # 7. mixed-fail: 7 tier-2 + 3 tier-4 = 70% → fail
    # ------------------------------------------------------------------ #
    def test_mixed_fail(self):
        with tempfile.TemporaryDirectory() as tmp:
            corpus = Path(tmp) / "mixed_fail"
            corpus.mkdir()
            for i in range(7):
                _write_record(
                    corpus,
                    f"t2-{i}",
                    _v1_yaml(
                        record_id=f"t2-{i}",
                        tier_tag="tier-2-verified-public-archive",
                    ),
                )
            for i in range(3):
                _write_record(
                    corpus,
                    f"t4-{i}",
                    _v1_yaml(
                        record_id=f"t4-{i}",
                        tier_tag="tier-4-bundled-fixture",
                    ),
                )
            rep = self.mod.audit_corpus_dir(corpus, min_coverage_pct=80.0)
            self.assertEqual(rep["verdict"], "fail")
            self.assertAlmostEqual(rep["tier1_tier2_pct"], 70.0, places=2)

    # ------------------------------------------------------------------ #
    # 8. empty directory → skip-empty
    # ------------------------------------------------------------------ #
    def test_empty_dir(self):
        with tempfile.TemporaryDirectory() as tmp:
            corpus = Path(tmp) / "empty_dir"
            corpus.mkdir()
            rep = self.mod.audit_corpus_dir(corpus, min_coverage_pct=80.0)
            self.assertEqual(rep["verdict"], "skip-empty")
            self.assertEqual(rep["hackerman_record_count"], 0)

    # ------------------------------------------------------------------ #
    # 9. single tier-1 record → pass
    # ------------------------------------------------------------------ #
    def test_single_record_dir_pass(self):
        with tempfile.TemporaryDirectory() as tmp:
            corpus = Path(tmp) / "single_pass"
            corpus.mkdir()
            _write_record(
                corpus,
                "only",
                _v1_yaml(
                    record_id="rid-only",
                    tier_tag="tier-2-verified-public-archive",
                ),
            )
            rep = self.mod.audit_corpus_dir(corpus, min_coverage_pct=80.0)
            self.assertEqual(rep["verdict"], "pass")
            self.assertEqual(rep["hackerman_record_count"], 1)
            self.assertAlmostEqual(rep["tier1_tier2_pct"], 100.0, places=2)

    # ------------------------------------------------------------------ #
    # 10. single tier-3 record → fail (and stays at 0% tier-1/2)
    # ------------------------------------------------------------------ #
    def test_single_record_dir_fail(self):
        with tempfile.TemporaryDirectory() as tmp:
            corpus = Path(tmp) / "single_fail"
            corpus.mkdir()
            _write_record(
                corpus,
                "only",
                _v1_yaml(
                    record_id="rid-only",
                    tier_tag="tier-3-synthetic-taxonomy-anchored",
                ),
            )
            rep = self.mod.audit_corpus_dir(corpus, min_coverage_pct=80.0)
            self.assertEqual(rep["verdict"], "fail")
            self.assertEqual(rep["hackerman_record_count"], 1)
            self.assertEqual(rep["tier1_tier2_pct"], 0.0)

    # ------------------------------------------------------------------ #
    # 11. non-hackerman-v1 schema records are skipped (do not count)
    # ------------------------------------------------------------------ #
    def test_non_hackerman_schema_skipped(self):
        with tempfile.TemporaryDirectory() as tmp:
            corpus = Path(tmp) / "non_hk"
            corpus.mkdir()
            # 2 non-hackerman + 3 tier-1: real coverage = 3/3 = 100%
            for i in range(2):
                _write_record(
                    corpus,
                    f"alien-{i}",
                    _v1_yaml(
                        record_id=f"alien-{i}",
                        tier_tag=None,
                        schema_version="auditooor.verdict_tag.v2",
                    ),
                )
            for i in range(3):
                _write_record(
                    corpus,
                    f"t1-{i}",
                    _v1_yaml(
                        record_id=f"t1-{i}",
                        tier_tag="tier-1-verified-realtime-api",
                    ),
                )
            rep = self.mod.audit_corpus_dir(corpus, min_coverage_pct=80.0)
            self.assertEqual(rep["verdict"], "pass")
            self.assertEqual(rep["hackerman_record_count"], 3)
            self.assertEqual(rep["skipped_non_hackerman_v1"], 2)
            self.assertAlmostEqual(rep["tier1_tier2_pct"], 100.0, places=2)

    # ------------------------------------------------------------------ #
    # 11b. Wave-2 Phase-3 schema migration: v1.1 records must be counted
    #      (NOT skipped). Regression-guard for the exact-match → prefix-match
    #      migration on the schema_version check in classify_record.
    # ------------------------------------------------------------------ #
    def test_hackerman_v1_1_schema_recognised(self):
        with tempfile.TemporaryDirectory() as tmp:
            corpus = Path(tmp) / "v1_1"
            corpus.mkdir()
            # 5 v1.1 records all at tier-1: real coverage = 5/5 = 100%
            for i in range(5):
                _write_record(
                    corpus,
                    f"v1_1-{i}",
                    _v1_yaml(
                        record_id=f"v1_1-{i}",
                        tier_tag="tier-1-verified-realtime-api",
                        schema_version="auditooor.hackerman_record.v1.1",
                    ),
                )
            rep = self.mod.audit_corpus_dir(corpus, min_coverage_pct=80.0)
            self.assertEqual(rep["verdict"], "pass")
            self.assertEqual(rep["hackerman_record_count"], 5)
            self.assertEqual(rep["skipped_non_hackerman_v1"], 0)
            self.assertAlmostEqual(rep["tier1_tier2_pct"], 100.0, places=2)

    # ------------------------------------------------------------------ #
    # 12. --all CLI exercise (smoke + JSON shape sanity)
    # ------------------------------------------------------------------ #
    def test_cli_all_json(self):
        with tempfile.TemporaryDirectory() as tmp:
            tags = Path(tmp) / "tags"
            tags.mkdir()
            # subdir 1: pass
            good = tags / "good_subtree"
            good.mkdir()
            for i in range(5):
                _write_record(
                    good,
                    f"rec{i}",
                    _v1_yaml(
                        record_id=f"good-{i}",
                        tier_tag="tier-1-verified-realtime-api",
                    ),
                )
            # subdir 2: fail
            bad = tags / "bad_subtree"
            bad.mkdir()
            for i in range(5):
                _write_record(
                    bad,
                    f"rec{i}",
                    _v1_yaml(
                        record_id=f"bad-{i}",
                        tier_tag="tier-4-bundled-fixture",
                    ),
                )
            # subdir 3: quarantine (should skip)
            q = tags / "_QUARANTINE_FABRICATED_CVE"
            q.mkdir()
            for i in range(2):
                _write_record(
                    q,
                    f"rec{i}",
                    _v1_yaml(
                        record_id=f"q-{i}",
                        tier_tag="tier-5-quarantine",
                    ),
                )

            # Capture JSON output via mod.main
            import io
            from contextlib import redirect_stdout

            buf = io.StringIO()
            with redirect_stdout(buf):
                rc = self.mod.main([
                    "--all",
                    "--tags-dir",
                    str(tags),
                    "--json",
                ])
            self.assertEqual(rc, 0)
            payload = json.loads(buf.getvalue())
            self.assertEqual(payload["schema"], self.mod.SCHEMA)
            self.assertEqual(payload["directory_count"], 2)  # quarantine excluded
            self.assertEqual(payload["pass_count"], 1)
            self.assertEqual(payload["fail_count"], 1)

    # ------------------------------------------------------------------ #
    # 13. --strict exit code = 1 on failure
    # ------------------------------------------------------------------ #
    def test_strict_returns_nonzero_on_fail(self):
        with tempfile.TemporaryDirectory() as tmp:
            corpus = Path(tmp) / "strict_fail"
            corpus.mkdir()
            for i in range(5):
                _write_record(
                    corpus,
                    f"rec{i}",
                    _v1_yaml(
                        record_id=f"r-{i}",
                        tier_tag="tier-3-synthetic-taxonomy-anchored",
                    ),
                )
            import io
            from contextlib import redirect_stdout

            buf = io.StringIO()
            with redirect_stdout(buf):
                rc = self.mod.main([
                    "--corpus-dir",
                    str(corpus),
                    "--strict",
                ])
            self.assertEqual(rc, 1)

    # ------------------------------------------------------------------ #
    # 14. classify_record handles malformed verification_tier values
    # ------------------------------------------------------------------ #
    def test_classify_malformed_tier(self):
        bucket, value = self.mod.classify_record(
            ["bug-class-foo", "verification_tier:tier-9-nonexistent"]
        )
        # malformed tier slug → unlabeled
        self.assertEqual(bucket, "unlabeled")
        bucket2, _ = self.mod.classify_record(
            ["bug-class-foo", "verification_tier:tier-1-verified-realtime-api"]
        )
        self.assertEqual(bucket2, "tier-1")

    # ------------------------------------------------------------------ #
    # 15. _is_quarantine_dir / _select_subdirs helpers
    # ------------------------------------------------------------------ #
    def test_select_subdirs_filters_quarantine(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "tags"
            root.mkdir()
            (root / "alpha").mkdir()
            (root / "beta").mkdir()
            (root / "_QUARANTINE_FABRICATED_CVE").mkdir()
            (root / "_QUARANTINE_legacy").mkdir()
            subs = self.mod._select_subdirs(root)
            names = sorted(p.name for p in subs)
            self.assertEqual(names, ["alpha", "beta"])


# --------------------------------------------------------------------------- #
# Acceptance-exemptions registry tests
# --------------------------------------------------------------------------- #


_REGISTRY_YAML = """
schema: auditooor.hackerman_corpus_acceptance_exemptions.v1
generated_at: 2026-05-16
documented_in: docs/HACKERMAN_CORPUS_ACCEPTANCE_FAIL_INVESTIGATION_2026-05-16.md

exemptions:
  - corpus_dir: bad_subtree
    category: A
    reason: synthetic taxonomy fan-out; tier-3 by design
    expected_tier_distribution:
      tier-3: 1.0
    review_at: 2026-06-15
    documented_in: docs/HACKERMAN_CORPUS_ACCEPTANCE_FAIL_INVESTIGATION_2026-05-16.md

  - corpus_dir: another_subtree
    category: B
    reason: mixed-wave; anchor tier-1, fan-out tier-3
    expected_tier_distribution:
      tier-1: 0.2
      tier-3: 0.8
    review_at: indefinite
"""


def _make_tier3_subtree(parent: Path, name: str, n: int = 5) -> Path:
    corpus = parent / name
    corpus.mkdir()
    for i in range(n):
        _write_record(
            corpus,
            f"rec{i}",
            _v1_yaml(
                record_id=f"{name}-{i}",
                tier_tag="tier-3-synthetic-taxonomy-anchored",
            ),
        )
    return corpus


class ExemptionsRegistryTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.mod = _load_tool()

    # ------------------------------------------------------------------ #
    # 16. Registry YAML parser extracts entries keyed by corpus_dir
    # ------------------------------------------------------------------ #
    def test_parse_exemptions_yaml_basic(self):
        parsed = self.mod._parse_exemptions_yaml(_REGISTRY_YAML)
        self.assertIn("bad_subtree", parsed)
        self.assertIn("another_subtree", parsed)
        self.assertEqual(parsed["bad_subtree"]["category"], "A")
        self.assertEqual(parsed["another_subtree"]["category"], "B")
        # expected_tier_distribution is parsed as a nested map of floats
        etd = parsed["bad_subtree"]["expected_tier_distribution"]
        self.assertIsInstance(etd, dict)
        self.assertAlmostEqual(etd["tier-3"], 1.0)
        etd2 = parsed["another_subtree"]["expected_tier_distribution"]
        self.assertAlmostEqual(etd2["tier-1"], 0.2)
        self.assertAlmostEqual(etd2["tier-3"], 0.8)
        # review_at preserved
        self.assertEqual(parsed["another_subtree"]["review_at"], "indefinite")

    # ------------------------------------------------------------------ #
    # 17. load_exemptions returns {} when file missing (registry optional)
    # ------------------------------------------------------------------ #
    def test_load_exemptions_missing_file(self):
        with tempfile.TemporaryDirectory() as tmp:
            missing = Path(tmp) / "nope.yaml"
            self.assertEqual(self.mod.load_exemptions(missing), {})

    # ------------------------------------------------------------------ #
    # 18. --all + registry: failing exempt subtree renders as `fail-exempt`
    #     and --strict returns 0 (exemption respected).
    # ------------------------------------------------------------------ #
    def test_strict_exempts_listed_fail(self):
        with tempfile.TemporaryDirectory() as tmp:
            tags = Path(tmp) / "tags"
            tags.mkdir()
            # Good subtree: 5 tier-1 records → pass
            good = tags / "good_subtree"
            good.mkdir()
            for i in range(5):
                _write_record(
                    good,
                    f"rec{i}",
                    _v1_yaml(
                        record_id=f"good-{i}",
                        tier_tag="tier-1-verified-realtime-api",
                    ),
                )
            # Bad subtree: 5 tier-3 records → fail (but listed in registry)
            _make_tier3_subtree(tags, "bad_subtree", n=5)

            # Registry exempts `bad_subtree`
            registry = Path(tmp) / "acceptance_exemptions.yaml"
            registry.write_text(_REGISTRY_YAML, encoding="utf-8")

            import io
            from contextlib import redirect_stdout

            buf = io.StringIO()
            with redirect_stdout(buf):
                rc = self.mod.main([
                    "--all",
                    "--tags-dir",
                    str(tags),
                    "--exemptions-file",
                    str(registry),
                    "--json",
                    "--strict",
                ])
            # Exempt fail → --strict still returns 0
            self.assertEqual(rc, 0)
            payload = json.loads(buf.getvalue())
            self.assertEqual(payload["pass_count"], 1)
            # fail_count counts only non-exempt fails
            self.assertEqual(payload["fail_count"], 0)
            self.assertEqual(payload["fail_exempt_count"], 1)
            self.assertEqual(payload["exemptions_loaded"], 2)
            self.assertFalse(payload["no_exempt"])
            # Per-report verdict on the bad subtree is fail-exempt with
            # the exemption block attached.
            bad_rep = next(
                r
                for r in payload["reports"]
                if Path(r["corpus_dir"]).name == "bad_subtree"
            )
            self.assertEqual(bad_rep["verdict"], "fail-exempt")
            self.assertIsInstance(bad_rep.get("exemption"), dict)
            self.assertEqual(bad_rep["exemption"]["category"], "A")
            self.assertIn("review_at", bad_rep["exemption"])

    # ------------------------------------------------------------------ #
    # 19. --no-exempt bypasses the registry: same fail → plain `fail`,
    #     --strict returns 1.
    # ------------------------------------------------------------------ #
    def test_no_exempt_bypasses_registry(self):
        with tempfile.TemporaryDirectory() as tmp:
            tags = Path(tmp) / "tags"
            tags.mkdir()
            _make_tier3_subtree(tags, "bad_subtree", n=5)
            registry = Path(tmp) / "acceptance_exemptions.yaml"
            registry.write_text(_REGISTRY_YAML, encoding="utf-8")

            import io
            from contextlib import redirect_stdout

            buf = io.StringIO()
            with redirect_stdout(buf):
                rc = self.mod.main([
                    "--all",
                    "--tags-dir",
                    str(tags),
                    "--exemptions-file",
                    str(registry),
                    "--json",
                    "--strict",
                    "--no-exempt",
                ])
            self.assertEqual(rc, 1)
            payload = json.loads(buf.getvalue())
            self.assertEqual(payload["fail_count"], 1)
            self.assertEqual(payload["fail_exempt_count"], 0)
            self.assertEqual(payload["exemptions_loaded"], 0)
            self.assertTrue(payload["no_exempt"])
            bad_rep = next(
                r
                for r in payload["reports"]
                if Path(r["corpus_dir"]).name == "bad_subtree"
            )
            self.assertEqual(bad_rep["verdict"], "fail")
            self.assertNotIn("exemption", bad_rep)

    # ------------------------------------------------------------------ #
    # 20. Non-exempt fail co-existing with exempt fail: --strict rc=1 still,
    #     but exempt row is annotated independently.
    # ------------------------------------------------------------------ #
    def test_mixed_exempt_and_nonexempt_fails(self):
        with tempfile.TemporaryDirectory() as tmp:
            tags = Path(tmp) / "tags"
            tags.mkdir()
            # Exempt fail
            _make_tier3_subtree(tags, "bad_subtree", n=5)
            # Non-exempt fail (NOT in registry)
            _make_tier3_subtree(tags, "unlisted_fail", n=5)
            registry = Path(tmp) / "acceptance_exemptions.yaml"
            registry.write_text(_REGISTRY_YAML, encoding="utf-8")

            import io
            from contextlib import redirect_stdout

            buf = io.StringIO()
            with redirect_stdout(buf):
                rc = self.mod.main([
                    "--all",
                    "--tags-dir",
                    str(tags),
                    "--exemptions-file",
                    str(registry),
                    "--json",
                    "--strict",
                ])
            # Non-exempt fail still produces rc=1
            self.assertEqual(rc, 1)
            payload = json.loads(buf.getvalue())
            self.assertEqual(payload["fail_count"], 1)
            self.assertEqual(payload["fail_exempt_count"], 1)
            verdicts = {
                Path(r["corpus_dir"]).name: r["verdict"]
                for r in payload["reports"]
            }
            self.assertEqual(verdicts["bad_subtree"], "fail-exempt")
            self.assertEqual(verdicts["unlisted_fail"], "fail")


if __name__ == "__main__":
    unittest.main()
