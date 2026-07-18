"""Tests for tools/hackerman-tier3-deep-attribution-analyzer.py.

The analyzer is investigative-only: it groups tier-3-synthetic-taxonomy-
anchored records by prefix and classifies each prefix into one of three
buckets: genuinely-synthetic, deeper-attribution-possible, or
unknown-needs-investigation.

These tests exercise:
  - classify_prefix on each bucket
  - has_url_signal on URL-bearing, CVE-bearing, and templated records
  - extract_prefix on canonical / fallback inputs
  - load_record_fields on YAML + JSON record forms
  - end-to-end main() integration against a synthesised tags directory
"""
from __future__ import annotations

import importlib.util
import json
import tempfile
import textwrap
import unittest
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[2]
TOOL_PATH = REPO_ROOT / "tools" / "hackerman-tier3-deep-attribution-analyzer.py"


def _load_tool():
    spec = importlib.util.spec_from_file_location(
        "_hackerman_tier3_deep_attribution_analyzer", str(TOOL_PATH)
    )
    mod = importlib.util.module_from_spec(spec)
    assert spec.loader
    spec.loader.exec_module(mod)
    return mod


TOOL = _load_tool()


# --------------------------------------------------------------------------- #
# Pure-function unit tests
# --------------------------------------------------------------------------- #


class ExtractPrefixTests(unittest.TestCase):
    def test_canonical_prefix(self):
        self.assertEqual(
            TOOL.extract_prefix("corpus-mined:code4arena_slice_aa.md:L100:S69:73863d4152bc"),
            "corpus-mined",
        )

    def test_zk_auditor_prefix(self):
        self.assertEqual(
            TOOL.extract_prefix("zk-auditor:asymmetric-research:polygon-zkevm:S1:abc123"),
            "zk-auditor",
        )

    def test_no_colon_fallback(self):
        rid = "abcdefghij" * 5  # 50 chars
        self.assertEqual(TOOL.extract_prefix(rid), rid[:30])

    def test_empty_record_id(self):
        self.assertEqual(TOOL.extract_prefix(""), "")


class HasUrlSignalTests(unittest.TestCase):
    def test_https_url_in_source_audit_ref(self):
        fields = {"source_audit_ref": "https://rekt.news/foo-rekt"}
        self.assertTrue(TOOL.has_url_signal(fields))

    def test_github_url_in_preconds(self):
        fields = {
            "required_preconditions": [
                "Reference advisory at https://github.com/foo/bar/issues/1"
            ]
        }
        self.assertTrue(TOOL.has_url_signal(fields))

    def test_cve_id_in_action_sequence(self):
        fields = {
            "attacker_action_sequence": "Exploits CVE-2023-39363 in Vyper..."
        }
        self.assertTrue(TOOL.has_url_signal(fields))

    def test_sol_compiler_bug_id(self):
        fields = {"source_audit_ref": "solc-spec:SOL-2021-2:abi-codec"}
        self.assertTrue(TOOL.has_url_signal(fields))

    def test_public_archive_host(self):
        fields = {
            "required_preconditions": ["Reference writeup at blocknative.com"]
        }
        self.assertTrue(TOOL.has_url_signal(fields))

    def test_no_signal_templated(self):
        fields = {
            "source_audit_ref": "corpus-mined:slice_aa.md:L1:S1",
            "attacker_action_sequence": "DETECTOR. NO.",
            "required_preconditions": ["oracle component exposes oracle-manipulation"],
        }
        self.assertFalse(TOOL.has_url_signal(fields))


class ClassifyPrefixTests(unittest.TestCase):
    def test_genuinely_synthetic_corpus_mined(self):
        cls, _ = TOOL.classify_prefix("corpus-mined", [])
        self.assertEqual(cls, "genuinely-synthetic")

    def test_genuinely_synthetic_solc_compiler(self):
        cls, _ = TOOL.classify_prefix("solc-compiler", [])
        self.assertEqual(cls, "genuinely-synthetic")

    def test_deeper_attribution_zk_auditor(self):
        cls, _ = TOOL.classify_prefix("zk-auditor", [])
        self.assertEqual(cls, "deeper-attribution-possible")

    def test_deeper_attribution_bridge_incident(self):
        cls, _ = TOOL.classify_prefix("bridge-incident", [])
        self.assertEqual(cls, "deeper-attribution-possible")

    def test_unknown_prefix_no_samples(self):
        cls, _ = TOOL.classify_prefix("brand-new-prefix-xyz", [])
        self.assertEqual(cls, "unknown-needs-investigation")

    def test_unknown_prefix_url_majority_flips_to_deeper(self):
        samples = [
            {"source_audit_ref": "https://example.com/a"},
            {"source_audit_ref": "https://example.com/b"},
            {"source_audit_ref": "templated-no-url"},
        ]
        cls, _ = TOOL.classify_prefix("brand-new-prefix-xyz", samples)
        self.assertEqual(cls, "deeper-attribution-possible")

    def test_unknown_prefix_no_url_in_samples(self):
        samples = [
            {"source_audit_ref": "templated-a"},
            {"source_audit_ref": "templated-b"},
        ]
        cls, _ = TOOL.classify_prefix("brand-new-prefix-xyz", samples)
        self.assertEqual(cls, "unknown-needs-investigation")


# --------------------------------------------------------------------------- #
# Record loader tests
# --------------------------------------------------------------------------- #


class LoadRecordFieldsTests(unittest.TestCase):
    def test_load_yaml(self):
        with tempfile.TemporaryDirectory() as tdir:
            p = Path(tdir) / "rec.yaml"
            p.write_text(textwrap.dedent("""\
                schema_version: auditooor.hackerman_record.v1
                record_id: "zk-auditor:foo:S1:abc"
                source_audit_ref: "https://example.com/audit.pdf"
                required_preconditions:
                  - "first precond"
                  - "second precond"
                """), encoding="utf-8")
            fields = TOOL.load_record_fields(p)
            self.assertEqual(fields["record_id"], "zk-auditor:foo:S1:abc")
            self.assertEqual(fields["source_audit_ref"], "https://example.com/audit.pdf")
            self.assertIn("first precond", fields["required_preconditions"])

    def test_load_json(self):
        with tempfile.TemporaryDirectory() as tdir:
            p = Path(tdir) / "rec.json"
            payload = {
                "record_id": "bridge-incident:foo:abc",
                "source_audit_ref": "https://rekt.news/foo",
                "required_preconditions": ["Reference at https://example.com"],
            }
            p.write_text(json.dumps(payload), encoding="utf-8")
            fields = TOOL.load_record_fields(p)
            self.assertEqual(fields["record_id"], "bridge-incident:foo:abc")
            self.assertEqual(fields["source_audit_ref"], "https://rekt.news/foo")

    def test_load_missing_file_returns_empty(self):
        p = Path("/nonexistent/path/does/not/exist.yaml")
        self.assertEqual(TOOL.load_record_fields(p), {})


# --------------------------------------------------------------------------- #
# Integration test
# --------------------------------------------------------------------------- #


class MainIntegrationTests(unittest.TestCase):
    def _build_fixture(self, root: Path) -> Path:
        """Build a tiny verification-tier-candidates.jsonl + record set
        so that build_prefix_groups + classify_all can be exercised
        end-to-end."""
        tags_dir = root / "audit" / "corpus_tags" / "tags"
        tags_dir.mkdir(parents=True, exist_ok=True)

        # Genuinely-synthetic: corpus-mined
        cm_path = tags_dir / "corpus-mined-foo.yaml"
        cm_path.write_text(textwrap.dedent("""\
            schema_version: auditooor.hackerman_record.v1
            record_id: "corpus-mined:slice_aa.md:L1:S1:aaa111"
            source_audit_ref: "corpus-mined:slice_aa.md:L1:S1"
            attacker_action_sequence: "DETECTOR. NO."
            """), encoding="utf-8")

        # Deeper-attribution-possible: zk-auditor (prefix-table)
        zk_path = tags_dir / "zk-auditor-asymmetric.yaml"
        zk_path.write_text(textwrap.dedent("""\
            schema_version: auditooor.hackerman_record.v1
            record_id: "zk-auditor:asymmetric-research:foo:S1:bbb222"
            source_audit_ref: "https://github.com/asymmetric-research/audit.pdf"
            """), encoding="utf-8")

        # Unknown-prefix with URL-bearing samples (should flip to deeper-
        # attribution-possible via the heuristic).
        un_dir = tags_dir / "newcohort"
        un_dir.mkdir(parents=True, exist_ok=True)
        un_path = un_dir / "record.json"
        un_path.write_text(json.dumps({
            "record_id": "newcohort:foo:S1:ccc333",
            "source_audit_ref": "https://example.com/post-mortem",
        }), encoding="utf-8")

        # Unknown-prefix with NO URL signal (should stay unknown).
        nx_path = tags_dir / "nocluecohort-foo.yaml"
        nx_path.write_text(textwrap.dedent("""\
            schema_version: auditooor.hackerman_record.v1
            record_id: "nocluecohort:foo:S1:ddd444"
            source_audit_ref: "nocluecohort:foo:S1"
            """), encoding="utf-8")

        # Write the candidates JSONL.
        cands_dir = root / ".auditooor"
        cands_dir.mkdir(parents=True, exist_ok=True)
        cand_path = cands_dir / "verification-tier-candidates.jsonl"
        with cand_path.open("w", encoding="utf-8") as fh:
            for record_id, fpath in [
                ("corpus-mined:slice_aa.md:L1:S1:aaa111", "audit/corpus_tags/tags/corpus-mined-foo.yaml"),
                ("zk-auditor:asymmetric-research:foo:S1:bbb222", "audit/corpus_tags/tags/zk-auditor-asymmetric.yaml"),
                ("newcohort:foo:S1:ccc333", "audit/corpus_tags/tags/newcohort/record.json"),
                ("nocluecohort:foo:S1:ddd444", "audit/corpus_tags/tags/nocluecohort-foo.yaml"),
            ]:
                fh.write(json.dumps({
                    "record_id": record_id,
                    "file": fpath,
                    "verification_tier": "tier-3-synthetic-taxonomy-anchored",
                    "reason": "test-fixture",
                }) + "\n")
            # Add a tier-2 record that MUST NOT appear in the analysis.
            fh.write(json.dumps({
                "record_id": "code4rena:something:eee555",
                "file": "audit/corpus_tags/tags/c4-something.yaml",
                "verification_tier": "tier-2-verified-public-archive",
                "reason": "test-fixture-tier2",
            }) + "\n")
        return cand_path

    def test_end_to_end(self):
        with tempfile.TemporaryDirectory() as tdir:
            root = Path(tdir)
            cand_path = self._build_fixture(root)
            out_jsonl = root / ".auditooor" / "tier3_prefix_analysis.jsonl"
            out_doc = root / "docs" / "TEST_TIER3_PROMOTION.md"
            rc = TOOL.main([
                "--candidates", str(cand_path),
                "--repo-root", str(root),
                "--out-jsonl", str(out_jsonl),
                "--out-doc", str(out_doc),
            ])
            self.assertEqual(rc, 0)
            self.assertTrue(out_jsonl.exists())
            self.assertTrue(out_doc.exists())
            rows = [json.loads(l) for l in out_jsonl.read_text().splitlines() if l.strip()]
            by_prefix = {r["prefix"]: r for r in rows}
            self.assertEqual(by_prefix["corpus-mined"]["classification"], "genuinely-synthetic")
            self.assertEqual(by_prefix["zk-auditor"]["classification"], "deeper-attribution-possible")
            self.assertEqual(by_prefix["newcohort"]["classification"], "deeper-attribution-possible")
            self.assertEqual(by_prefix["nocluecohort"]["classification"], "unknown-needs-investigation")
            # Tier-2 record must not appear.
            self.assertNotIn("code4rena", by_prefix)

    def test_missing_candidates_exits_2(self):
        with tempfile.TemporaryDirectory() as tdir:
            rc = TOOL.main([
                "--candidates", str(Path(tdir) / "nope.jsonl"),
                "--repo-root", tdir,
                "--out-jsonl", str(Path(tdir) / "out.jsonl"),
                "--out-doc", str(Path(tdir) / "out.md"),
            ])
            self.assertEqual(rc, 2)


if __name__ == "__main__":
    unittest.main()
