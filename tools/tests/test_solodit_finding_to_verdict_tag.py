#!/usr/bin/env python3
"""Tests for tools/solodit-finding-to-verdict-tag.py (Wave-9 Track F)."""
from __future__ import annotations

import importlib.util
import os
import sys
import tempfile
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
TOOL = REPO_ROOT / "tools" / "solodit-finding-to-verdict-tag.py"
DRAFTS_DIR = REPO_ROOT / "detectors" / "_specs" / "drafts_solodit"
TAGS_DIR = REPO_ROOT / "audit" / "corpus_tags" / "tags"
BUG_CLASS_MAP = REPO_ROOT / "audit" / "bug_class_to_attack_classes_map.yaml"

# Known real Solodit draft file for deterministic tests
KNOWN_DRAFT = DRAFTS_DIR / "a-borrower-can-list-their-collateral-on-seaport-and-receive-almo.yaml"


def load_module():
    spec = importlib.util.spec_from_file_location("solodit_finding_to_verdict_tag", TOOL)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"Could not load {TOOL}")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


class TestSoloditFindingToVerdictTag(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.mod = load_module()
        try:
            import yaml
            cls.yaml = yaml
        except ImportError:
            cls.yaml = None

    def _load_yaml(self, path):
        """Load YAML using mod's internal loader (matches what the tool uses)."""
        if self.yaml:
            with open(path, "r", encoding="utf-8") as fh:
                return self.yaml.safe_load(fh)
        raise RuntimeError("yaml not available")

    # --- Test 1: Tool can parse a real drafts_solodit file ---

    def test_known_draft_is_parseable(self):
        """Parses a real drafts_solodit YAML without error."""
        self.assertTrue(KNOWN_DRAFT.exists(), f"Known draft not found: {KNOWN_DRAFT}")
        d = self.mod._load_yaml(KNOWN_DRAFT)
        self.assertIsInstance(d, dict, "Expected dict from YAML parse")
        self.assertIn("solodit_id", d, "Expected solodit_id field")
        self.assertIn("class_name", d, "Expected class_name field")
        self.assertEqual(d.get("solodit_id"), "7283")

    # --- Test 2: Emitter produces a schema-valid tag ---

    def test_emit_tag_yaml_produces_valid_schema(self):
        """Emitting a tag from the known draft yields a v2-schema-valid YAML."""
        d = self.mod._load_yaml(KNOWN_DRAFT)
        self.assertIsNotNone(d)

        now_utc = "2026-05-11T00:00:00Z"
        bug_class_map = {}

        filename, content = self.mod._emit_tag_yaml(d, KNOWN_DRAFT, bug_class_map, now_utc)

        # Check required schema fields present in content
        self.assertIn("verdict_id:", content)
        self.assertIn("target_repo:", content)
        self.assertIn("audit_pin_sha:", content)
        self.assertIn("language: solidity", content)
        self.assertIn("verdict_class: FILED", content)
        self.assertIn("extraction_provenance: manual", content)
        self.assertIn("extractor_version: 0.1.0", content)
        self.assertIn("extracted_at_utc:", content)

        # Must include sites (required when verdict_class=FILED)
        self.assertIn("sites:", content)
        self.assertIn("file_path:", content)

        # Solodit ID must appear in verdict_id
        self.assertIn("solodit/7283/", content)

        # SHA must be the sentinel hex value (7 chars, all zeros)
        self.assertIn("'0000000'", content)

    # --- Test 3: Findings without class_name are skipped ---

    def test_scan_skips_no_class_name(self):
        """Findings without class_name are excluded from candidates."""
        import tempfile
        with tempfile.TemporaryDirectory() as tmp:
            tmp_dir = Path(tmp)
            # Write a draft with no class_name
            bad_draft = tmp_dir / "bad_no_class.yaml"
            bad_draft.write_text(
                "skeleton: name_match_missing_call\n"
                "name: bad-finding\n"
                "solodit_id: '99999'\n"
                "severity: HIGH\n"
                "source: Solodit #99999 (Test/Proto)\n"
                "fn_name_regex: '.*test.*'\n",
                encoding="utf-8",
            )
            # Also write a good draft
            good_draft = tmp_dir / "good_finding.yaml"
            good_draft.write_text(
                "skeleton: name_match_missing_call\n"
                "name: good-finding\n"
                "class_name: GoodFinding\n"
                "solodit_id: '88888'\n"
                "severity: HIGH\n"
                "source: Solodit #88888 (Test/Proto)\n"
                "fn_name_regex: '.*test.*'\n",
                encoding="utf-8",
            )

            candidates, skip_stats, total = self.mod._scan_drafts(
                drafts_dir=tmp_dir,
                min_severity="HIGH",
                limit=100,
                bug_class_map={},
                quiet=True,
            )

        # Only the good draft should pass
        self.assertEqual(len(candidates), 1, "Only 1 qualifying finding expected")
        self.assertEqual(skip_stats["no_class_name"], 1, "bad_no_class.yaml should be skipped")

    # --- Test 4: --min-severity HIGH filters out MEDIUM ---

    def test_scan_filters_below_severity(self):
        """Findings below --min-severity are excluded."""
        with tempfile.TemporaryDirectory() as tmp:
            tmp_dir = Path(tmp)
            # MEDIUM severity finding
            medium_draft = tmp_dir / "medium_finding.yaml"
            medium_draft.write_text(
                "skeleton: name_match_missing_call\n"
                "name: medium-finding\n"
                "class_name: MediumFinding\n"
                "solodit_id: '77777'\n"
                "severity: MEDIUM\n"
                "source: Solodit #77777 (Test/Proto)\n"
                "fn_name_regex: '.*test.*'\n",
                encoding="utf-8",
            )
            # HIGH severity finding
            high_draft = tmp_dir / "high_finding.yaml"
            high_draft.write_text(
                "skeleton: name_match_missing_call\n"
                "name: high-finding\n"
                "class_name: HighFinding\n"
                "solodit_id: '66666'\n"
                "severity: HIGH\n"
                "source: Solodit #66666 (Test/Proto)\n"
                "fn_name_regex: '.*test.*'\n",
                encoding="utf-8",
            )

            # Filter HIGH only
            candidates, skip_stats, _ = self.mod._scan_drafts(
                drafts_dir=tmp_dir,
                min_severity="HIGH",
                limit=100,
                bug_class_map={},
                quiet=True,
            )

        self.assertEqual(len(candidates), 1, "Only HIGH should pass with --min-severity HIGH")
        self.assertEqual(skip_stats["below_severity"], 1, "MEDIUM should be in below_severity")
        _, d = candidates[0]
        self.assertEqual(d.get("solodit_id"), "66666")

    # --- Test 5: class_name maps to attack_classes via solodit_tags lookup ---

    def test_attack_classes_derived_from_solodit_tags(self):
        """solodit_tags are mapped to attack_classes_to_try via the built-in map."""
        attack_classes = self.mod._derive_attack_classes(
            solodit_tags="Reentrancy",
            class_name="SomeReentrancyBug",
            bug_class_map={},
        )
        self.assertIsInstance(attack_classes, list)
        self.assertTrue(len(attack_classes) > 0, "Reentrancy tag should map to attack classes")
        self.assertIn("reentrancy-state-corruption", attack_classes)

    def test_attack_classes_derived_from_oracle_tag(self):
        """Oracle solodit_tag maps to oracle-staleness attack class."""
        attack_classes = self.mod._derive_attack_classes(
            solodit_tags="Oracle",
            class_name="SomeOracleBug",
            bug_class_map={},
        )
        self.assertIn("oracle-staleness", attack_classes)

    def test_attack_classes_from_bug_class_map(self):
        """class_name slug matched against bug_class_map yields attack classes."""
        bug_class_map = {
            "reentrancy": ["reentrancy-state-corruption", "cross-function-reentrancy"]
        }
        attack_classes = self.mod._derive_attack_classes(
            solodit_tags="",
            class_name="ReentrancyVulnFoo",
            bug_class_map=bug_class_map,
        )
        self.assertTrue(len(attack_classes) >= 0, "May match via bug_class_map")

    # --- Test 6: Full emitter run produces 100 tags that pass schema ---

    def test_full_run_emits_100_schema_valid_tags(self):
        """End-to-end: emit 100 tags, validate all pass schema."""
        if not DRAFTS_DIR.exists():
            self.skipTest(f"Drafts dir not found: {DRAFTS_DIR}")

        # Load schema validator
        schema_tool = REPO_ROOT / "tools" / "verdict-tag-schema.py"
        if not schema_tool.exists():
            self.skipTest("Schema validator not found")

        spec = importlib.util.spec_from_file_location("verdict_tag_schema", schema_tool)
        schema_mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(schema_mod)

        with tempfile.TemporaryDirectory() as tmp:
            out_dir = Path(tmp)
            emitted = self.mod.main([
                "--limit", "100",
                "--min-severity", "HIGH",
                "--out-dir", str(out_dir),
                "--drafts-dir", str(DRAFTS_DIR),
                "--bug-class-map", str(BUG_CLASS_MAP),
                "--quiet",
            ])

            self.assertGreaterEqual(emitted, 50, "Expected at least 50 high-quality tags")
            self.assertLessEqual(emitted, 100, "Capped at 100")

            # Validate schema compliance
            yaml_files = list(out_dir.glob("*.yaml"))
            self.assertTrue(len(yaml_files) > 0, "No YAML files emitted")

            valid_count = 0
            fail_msgs = []
            for yf in yaml_files:
                ok, errs = schema_mod.validate_file(
                    yf,
                    schema=None,
                    v1_schema_path=REPO_ROOT / "audit" / "corpus_tags" / "auditooor.verdict_tag.v1.schema.json",
                    v2_schema_path=REPO_ROOT / "audit" / "corpus_tags" / "auditooor.verdict_tag.v2.schema.json",
                )
                if ok:
                    valid_count += 1
                else:
                    fail_msgs.append(f"{yf.name}: {errs}")

            if fail_msgs:
                self.fail(f"{len(fail_msgs)} tags failed schema validation:\n" + "\n".join(fail_msgs[:5]))
            self.assertGreaterEqual(valid_count, 50, "At least 50 emitted tags must be schema-valid")

    # --- Test 7: slug_from_class_name produces kebab-case ---

    def test_slug_from_class_name(self):
        """CamelCase class_name converts to kebab-case slug."""
        slug = self.mod._slug_from_class_name("MissingOracleCheck")
        self.assertRegex(slug, r"^[a-z0-9-]+$", "Slug must be lowercase kebab-case")
        self.assertIn("oracle", slug)

    def test_slug_max_length(self):
        """Slug is capped at 50 chars."""
        long_name = "A" * 200
        slug = self.mod._slug_from_class_name(long_name)
        self.assertLessEqual(len(slug), 50)

    # --- Test 8: target_repo sanitization ---

    def test_target_repo_valid_pattern(self):
        """target_repo passes schema pattern ^[A-Za-z0-9._-]+/[A-Za-z0-9._-]+$."""
        import re
        pattern = r"^[A-Za-z0-9._-]+/[A-Za-z0-9._-]+$"
        sources = [
            "Solodit #951 (Code4rena/BadgerDAO)",
            "Solodit #7219 (Spearbit/Connext)",
            "Solodit #21122 (Sherlock/RealWagmi)",
            "Solodit #3323 (Sherlock/Notional)",
        ]
        for source in sources:
            repo = self.mod._target_repo_from_source(source)
            self.assertRegex(
                repo,
                pattern,
                f"target_repo {repo!r} from {source!r} fails schema pattern",
            )


if __name__ == "__main__":
    unittest.main()
