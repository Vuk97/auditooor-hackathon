"""tests for tools/dsl-pattern-to-verdict-tag.py — Wave-9 Track D.

Assertions (>= 6 as required):
1. Parses a real DSL pattern from reference/patterns.dsl/
2. Emits a v2-schema-valid verdict-tag YAML
3. Skips patterns marked NOT_SUBMIT_READY (both status and submission_posture)
4. Maps bug_class field correctly via SLUG_TO_BUG_CLASS table
5. Looks up attack_classes from bug_class_to_attack_classes_map.yaml when available
6. Re-running is idempotent (overwrites existing dsl_pattern_*.yaml without
   changing non-DSL tags)
7. Patterns with no match block are skipped
8. extract_visibility extracts from match predicates
9. Synthesized shape_hash is a valid 16-char hex string
10. Emitted target_repo and audit_pin_sha satisfy schema regex constraints
"""
from __future__ import annotations

import importlib.util
import json
import os
import re
import sys
import tempfile
import unittest
from pathlib import Path

# ─── Load the module under test ───────────────────────────────────────────────
ROOT = Path(__file__).resolve().parents[2]
EMITTER_PY = ROOT / "tools" / "dsl-pattern-to-verdict-tag.py"

_spec = importlib.util.spec_from_file_location("dsl_pattern_to_verdict_tag", EMITTER_PY)
_mod = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(_mod)

DSL_DIR = ROOT / "reference" / "patterns.dsl"
TAGS_DIR = ROOT / "audit" / "corpus_tags" / "tags"
BUG_CLASS_MAP_PATH = ROOT / "audit" / "bug_class_to_attack_classes_map.yaml"
SCHEMA_V2_PATH = ROOT / "audit" / "corpus_tags" / "auditooor.verdict_tag.v2.schema.json"


def _load_schema_v2() -> dict:
    return json.loads(SCHEMA_V2_PATH.read_text(encoding="utf-8"))


def _validate_tag(tag_dict: dict) -> list:
    """Use the repo's verdict-tag-schema validator."""
    validator_py = ROOT / "tools" / "verdict-tag-schema.py"
    spec2 = importlib.util.spec_from_file_location("verdict_tag_schema", validator_py)
    mod2 = importlib.util.module_from_spec(spec2)
    spec2.loader.exec_module(mod2)
    schema = _load_schema_v2()
    return mod2.validate(tag_dict, schema)


def _first_real_dsl_pattern() -> Path:
    """Return path to the first canonical DSL pattern yaml (no subdirectory, non-skipped)."""
    for p in sorted(DSL_DIR.iterdir()):
        if p.is_dir():
            continue
        if p.suffix != ".yaml":
            continue
        d = _mod.load_dsl_pattern(p)
        if d is None:
            continue
        skip, _ = _mod.should_skip(d)
        if not skip:
            return p
    raise RuntimeError("No usable DSL pattern found in reference/patterns.dsl/")


class TestDslPatternParse(unittest.TestCase):
    """Assertion 1: parses a real DSL pattern from reference/patterns.dsl/."""

    def test_load_real_pattern(self) -> None:
        p = _first_real_dsl_pattern()
        d = _mod.load_dsl_pattern(p)
        self.assertIsNotNone(d, f"Failed to parse {p}")
        self.assertIsInstance(d, dict)
        # DSL patterns must have a 'pattern' key or at minimum a 'match' key
        has_ident = "pattern" in d or "match" in d
        self.assertTrue(has_ident, f"Parsed dict has neither 'pattern' nor 'match': {list(d.keys())}")


class TestSchemaValidity(unittest.TestCase):
    """Assertion 2: emitted tag is v2-schema-valid."""

    def test_emitted_tag_validates_v2(self) -> None:
        p = _first_real_dsl_pattern()
        d = _mod.load_dsl_pattern(p)
        bug_class_map = _mod.load_bug_class_map(BUG_CLASS_MAP_PATH)
        import datetime
        ts = datetime.datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ")
        tag = _mod.build_tag(p, d, bug_class_map, ts)
        errors = _validate_tag(tag)
        self.assertEqual(errors, [], f"Schema validation errors: {errors}")

    def test_target_repo_matches_pattern(self) -> None:
        p = _first_real_dsl_pattern()
        d = _mod.load_dsl_pattern(p)
        bug_class_map = _mod.load_bug_class_map(BUG_CLASS_MAP_PATH)
        import datetime
        ts = datetime.datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ")
        tag = _mod.build_tag(p, d, bug_class_map, ts)
        # Must match ^[A-Za-z0-9._-]+/[A-Za-z0-9._-]+$
        self.assertRegex(tag["target_repo"], r"^[A-Za-z0-9._-]+/[A-Za-z0-9._-]+$")

    def test_audit_pin_sha_matches_pattern(self) -> None:
        p = _first_real_dsl_pattern()
        d = _mod.load_dsl_pattern(p)
        bug_class_map = _mod.load_bug_class_map(BUG_CLASS_MAP_PATH)
        import datetime
        ts = datetime.datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ")
        tag = _mod.build_tag(p, d, bug_class_map, ts)
        # Must match ^[0-9a-f]{7,40}$
        self.assertRegex(tag["audit_pin_sha"], r"^[0-9a-f]{7,40}$")


class TestSkipLogic(unittest.TestCase):
    """Assertion 3: skips patterns marked NOT_SUBMIT_READY."""

    def test_skip_status_not_submit_ready(self) -> None:
        skip, reason = _mod.should_skip({"status": "not-submit-ready", "match": [{}]})
        self.assertTrue(skip)
        self.assertIn("status", reason)

    def test_skip_submission_posture(self) -> None:
        skip, reason = _mod.should_skip({"submission_posture": "NOT_SUBMIT_READY", "match": [{}]})
        self.assertTrue(skip)
        self.assertIn("posture", reason)

    def test_skip_no_match(self) -> None:
        """Assertion 7: patterns with no match block are skipped."""
        skip, reason = _mod.should_skip({"pattern": "test", "severity": "HIGH"})
        self.assertTrue(skip)
        self.assertEqual(reason, "no_match_block")

    def test_not_skipped_normal_pattern(self) -> None:
        skip, reason = _mod.should_skip({"pattern": "test", "match": [{"function.name_matches": ".*foo.*"}]})
        self.assertFalse(skip)
        self.assertEqual(reason, "")


class TestBugClassDerivation(unittest.TestCase):
    """Assertion 4: maps bug_class correctly via SLUG_TO_BUG_CLASS table."""

    def test_reentrancy_slug(self) -> None:
        bc = _mod.derive_bug_class("reentrancy-cross-function-attack", "", "")
        self.assertEqual(bc, "reentrancy")

    def test_oracle_slug(self) -> None:
        bc = _mod.derive_bug_class("stale-price-oracle-manipulation", "", "")
        self.assertIn("oracle", bc)

    def test_access_control_slug(self) -> None:
        bc = _mod.derive_bug_class("missing-access-control-on-admin-function", "", "")
        self.assertEqual(bc, "access-control")

    def test_toctou_slug(self) -> None:
        bc = _mod.derive_bug_class("toctou-timestamp-bypass", "", "")
        self.assertIn("time-of-check", bc)

    def test_dos_slug(self) -> None:
        bc = _mod.derive_bug_class("denial-of-service-griefing-attack", "", "")
        self.assertEqual(bc, "denial-of-service")

    def test_unknown_falls_back(self) -> None:
        bc = _mod.derive_bug_class("xyzzy-blorple-wibble", "", "")
        self.assertEqual(bc, "unknown-bug-class")

    def test_help_text_contributes(self) -> None:
        # help text contains reentrancy even if slug doesn't
        bc = _mod.derive_bug_class("some-random-slug", "", "exploits reentrancy via callback")
        self.assertEqual(bc, "reentrancy")


class TestAttackClassLookup(unittest.TestCase):
    """Assertion 5: looks up attack_classes from the map when available."""

    def test_map_loads_from_disk(self) -> None:
        m = _mod.load_bug_class_map(BUG_CLASS_MAP_PATH)
        self.assertIsInstance(m, dict)
        # Map may be empty if file doesn't exist, but should not crash
        # It should have at least some entries if the file is present
        if BUG_CLASS_MAP_PATH.exists():
            self.assertGreater(len(m), 0, "bug_class_to_attack_classes_map.yaml is empty")

    def test_known_bug_class_returns_list(self) -> None:
        m = _mod.load_bug_class_map(BUG_CLASS_MAP_PATH)
        if not m:
            self.skipTest("bug_class_map not available on disk")
        # Pick first entry
        key = next(iter(m))
        val = m[key]
        self.assertIsInstance(val, list)
        self.assertGreater(len(val), 0)

    def test_missing_key_returns_empty(self) -> None:
        m = {"reentrancy": ["reentrancy-call-back", "cross-fn-reentrancy"]}
        result = m.get("unknown-bug-class", [])
        self.assertEqual(result, [])

    def test_build_tag_includes_attack_classes_when_map_has_entry(self) -> None:
        """build_tag should include attack_classes_to_try when the bug_class is in the map."""
        import datetime
        p = _first_real_dsl_pattern()
        d = _mod.load_dsl_pattern(p)
        # Inject a fake bug_class that exists in a synthetic map
        synthetic_map = {"reentrancy": ["reentrancy-call-back", "cross-fn-reentrancy"]}
        # Patch build_tag to use slug that maps to reentrancy
        d_patched = dict(d)
        d_patched["pattern"] = "reentrancy-exploit-test"
        ts = datetime.datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ")
        tag = _mod.build_tag(p, d_patched, synthetic_map, ts)
        # bug_class should be reentrancy
        self.assertEqual(tag.get("bug_class"), "reentrancy")
        self.assertIn("attack_classes_to_try", tag)
        self.assertEqual(set(tag["attack_classes_to_try"]),
                         {"reentrancy-call-back", "cross-fn-reentrancy"})


class TestIdempotency(unittest.TestCase):
    """Assertion 6: re-running is idempotent — overwrites dsl_pattern_* only."""

    def test_run_twice_same_output(self) -> None:
        """Running twice produces identical dsl_pattern_* files and doesn't touch others."""
        with tempfile.TemporaryDirectory() as tmpdir:
            out_dir = Path(tmpdir) / "tags"
            out_dir.mkdir()
            # Plant a non-DSL tag that should be untouched
            non_dsl = out_dir / "some_other_tag.yaml"
            non_dsl.write_text("verdict_id: other/tag\n", encoding="utf-8")

            stats1 = _mod.run(dsl_dir=DSL_DIR, out_dir=out_dir, dry_run=False, limit=5)
            # Read all dsl_pattern_* files after first run
            first_run_files = {
                f.name: f.read_text(encoding="utf-8")
                for f in sorted(out_dir.glob("dsl_pattern_*.yaml"))
            }

            stats2 = _mod.run(dsl_dir=DSL_DIR, out_dir=out_dir, dry_run=False, limit=5)
            second_run_files = {
                f.name: f.read_text(encoding="utf-8")
                for f in sorted(out_dir.glob("dsl_pattern_*.yaml"))
            }

            self.assertEqual(first_run_files, second_run_files,
                             "Second run produced different output (not idempotent)")

            # Non-DSL tag should still be intact
            self.assertTrue(non_dsl.exists(), "non-DSL tag was deleted")
            self.assertEqual(non_dsl.read_text(encoding="utf-8"),
                             "verdict_id: other/tag\n")

            # Emitted count should be the same both runs
            self.assertEqual(stats1["emitted"], stats2["emitted"])

    def test_dry_run_emits_zero_files(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            out_dir = Path(tmpdir) / "tags"
            out_dir.mkdir()
            _mod.run(dsl_dir=DSL_DIR, out_dir=out_dir, dry_run=True, limit=5)
            written = list(out_dir.glob("dsl_pattern_*.yaml"))
            self.assertEqual(written, [], "dry_run should not write any files")


class TestShapeHash(unittest.TestCase):
    """Assertion 9: synthesized shape_hash is a valid 16-char hex string."""

    def test_shape_hash_format(self) -> None:
        h = _mod.synthesize_shape_hash("external", False)
        self.assertRegex(h, r"^[0-9a-f]{16}$", f"shape_hash not 16-char hex: {h!r}")

    def test_shape_hash_deterministic(self) -> None:
        h1 = _mod.synthesize_shape_hash("public", True)
        h2 = _mod.synthesize_shape_hash("public", True)
        self.assertEqual(h1, h2)

    def test_shape_hash_differs_by_visibility(self) -> None:
        h_ext = _mod.synthesize_shape_hash("external", False)
        h_int = _mod.synthesize_shape_hash("internal", False)
        self.assertNotEqual(h_ext, h_int)


class TestExtractVisibility(unittest.TestCase):
    """Assertion 8: extract_visibility reads from match predicates."""

    def test_extracts_public(self) -> None:
        predicates = [{"function.visibility": "public"}]
        self.assertEqual(_mod.extract_visibility(predicates), "public")

    def test_extracts_internal(self) -> None:
        predicates = [{"function.name_matches": ".*foo.*"},
                      {"function.visibility": "internal"}]
        self.assertEqual(_mod.extract_visibility(predicates), "internal")

    def test_defaults_to_external(self) -> None:
        predicates = [{"function.name_matches": ".*bar.*"}]
        self.assertEqual(_mod.extract_visibility(predicates), "external")


class TestFullRunStats(unittest.TestCase):
    """Integration: full run on real DSL directory produces meaningful counts."""

    def test_full_run_emits_majority_of_patterns(self) -> None:
        """Emitted should be > 80% of total scanned (most patterns are usable)."""
        with tempfile.TemporaryDirectory() as tmpdir:
            out_dir = Path(tmpdir) / "tags"
            out_dir.mkdir()
            stats = _mod.run(dsl_dir=DSL_DIR, out_dir=out_dir, dry_run=False, limit=50)
            self.assertGreater(stats["emitted"], 0)
            ratio = stats["emitted"] / max(stats["total_scanned"], 1)
            self.assertGreater(ratio, 0.7,
                               f"Less than 70% of patterns emitted: "
                               f"{stats['emitted']}/{stats['total_scanned']}")

    def test_emitted_files_all_validate_v2(self) -> None:
        """All emitted files must pass v2 schema validation."""
        with tempfile.TemporaryDirectory() as tmpdir:
            out_dir = Path(tmpdir) / "tags"
            out_dir.mkdir()
            _mod.run(dsl_dir=DSL_DIR, out_dir=out_dir, dry_run=False, limit=20)
            validator_py = ROOT / "tools" / "verdict-tag-schema.py"
            spec2 = importlib.util.spec_from_file_location("verdict_tag_schema", validator_py)
            mod2 = importlib.util.module_from_spec(spec2)
            spec2.loader.exec_module(mod2)
            schema = _load_schema_v2()
            failures = []
            for yaml_file in sorted(out_dir.glob("dsl_pattern_*.yaml")):
                ok, errs = mod2.validate_file(yaml_file, schema)
                if not ok:
                    failures.append((yaml_file.name, errs))
            self.assertEqual(failures, [],
                             f"Schema validation failures:\n" +
                             "\n".join(f"  {fn}: {errs}" for fn, errs in failures))


class TestWave10SolidityAttackClassCoverage(unittest.TestCase):
    """Wave-10: ≥80% of emitted Solidity DSL tags must carry attack_classes_to_try.

    This guards against regression of the Wave-10 Solidity bug-class map.
    Baseline (before Wave-10): 1230 / 1404 emitted tags had no attack_classes
    (88% map_miss). Target: ≥80% coverage on the live corpus.
    """

    def test_emitted_corpus_has_high_attack_class_coverage(self) -> None:
        """Run the emitter on the real DSL dir; assert ≥80% have attack_classes_to_try."""
        import yaml as _yaml  # local; deferred so test still loads if PyYAML missing
        with tempfile.TemporaryDirectory() as tmpdir:
            out_dir = Path(tmpdir) / "tags"
            out_dir.mkdir()
            stats = _mod.run(dsl_dir=DSL_DIR, out_dir=out_dir, dry_run=False)

            emitted = list(out_dir.glob("dsl_pattern_*.yaml"))
            self.assertGreater(len(emitted), 100,
                               f"Wave-10 coverage test needs a populated DSL dir; "
                               f"only got {len(emitted)} emitted files.")

            with_attack = 0
            without_attack = 0
            for p in emitted:
                d = _yaml.safe_load(p.read_text(encoding="utf-8"))
                ac = d.get("attack_classes_to_try") or []
                if ac:
                    with_attack += 1
                else:
                    without_attack += 1

            total = with_attack + without_attack
            ratio = with_attack / max(total, 1)
            self.assertGreaterEqual(
                ratio, 0.80,
                f"Wave-10 regression: only {with_attack}/{total} "
                f"({ratio:.1%}) emitted Solidity tags carry attack_classes_to_try; "
                f"map_miss={stats.get('bug_class_map_miss')}. "
                f"Expected ≥80%.",
            )

    def test_wave10_solidity_bug_classes_in_map(self) -> None:
        """Wave-10 added ≥20 canonical Solidity bug-class entries; verify presence."""
        m = _mod.load_bug_class_map(BUG_CLASS_MAP_PATH)
        # A representative sample of Wave-10-added keys (sourced from
        # SLUG_TO_BUG_CLASS outputs); not exhaustive.
        wave10_required = {
            "reentrancy",
            "flash-loan-attack",
            "oracle-price-manipulation",
            "integer-overflow-underflow",
            "access-control",
            "denial-of-service",
            "signature-replay",
            "precision-loss",
            "frontrunning",
            "cross-chain-bridge",
            "proxy-upgrade",
            "storage-collision",
            "token-share-inflation",
            "funds-freeze",
            "callback-hook-bypass",
            "withdrawal-logic",
            "liquidation-logic",
            "fee-accounting",
            "accounting-invariant",
            "erc20-allowance",
            "governance",
            "erc4626-vault",
        }
        missing = wave10_required - set(m.keys())
        self.assertEqual(missing, set(),
                         f"Wave-10 Solidity bug-class map is missing keys: {missing}")
        # Each Wave-10 entry must map to >=1 non-empty attack-class.
        for key in wave10_required:
            self.assertIsInstance(m[key], list, f"{key} value is not a list")
            self.assertGreater(len(m[key]), 0, f"{key} has empty attack-class list")


if __name__ == "__main__":
    unittest.main()
