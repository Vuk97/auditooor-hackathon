"""Tests for vault-ontology-validate.py (PR #658 commit 1)."""
import os
import pathlib
import subprocess
import tempfile
import unittest

REPO = pathlib.Path(__file__).resolve().parents[2]
TOOL = REPO / "tools" / "vault-ontology-validate.py"


def _make_note(frontmatter_yaml, body="Body content."):
    fm_block = "---\n" + frontmatter_yaml.strip() + "\n---\n"
    return fm_block + body + "\n"


def _run_on_text(text, *args):
    """Writes text to a temp md file, runs the validator, returns (returncode, stderr, stdout)."""
    with tempfile.NamedTemporaryFile(mode="w", suffix=".md", delete=False) as fh:
        fh.write(text)
        path = fh.name
    try:
        proc = subprocess.run(
            ["python3", str(TOOL), path, *args],
            capture_output=True,
            text=True,
        )
        return proc.returncode, proc.stderr, proc.stdout
    finally:
        os.unlink(path)


class TestVaultOntologyValidator(unittest.TestCase):
    def test_l0_minimal_valid(self):
        text = _make_note("""
layer: L0
source_uri: https://github.com/dydxprotocol/cometbft/blob/904204b/blocksync/reactor.go
extracted_at: 2026-05-08T22:00:00Z
verbatim: true
""")
        rc, err, _ = _run_on_text(text)
        self.assertEqual(rc, 0, f"expected valid; stderr:\n{err}")

    def test_l0_missing_source_uri(self):
        text = _make_note("""
layer: L0
extracted_at: 2026-05-08T22:00:00Z
""")
        rc, err, _ = _run_on_text(text)
        self.assertEqual(rc, 1)
        self.assertIn("L0 requires source_uri", err)

    def test_l1_minimal_valid_with_l0_link(self):
        text = _make_note("""
layer: L1
pattern_id: paired_function_divergence
tier: B
links_to_l0:
  - case_study/spark_lead_h_d.md
""")
        rc, err, _ = _run_on_text(text, "--check-cross-refs")
        self.assertEqual(rc, 0, f"stderr:\n{err}")

    def test_l1_orphan_no_links(self):
        text = _make_note("""
layer: L1
pattern_id: orphan_pattern
""")
        rc, err, _ = _run_on_text(text, "--check-cross-refs")
        self.assertEqual(rc, 1)
        self.assertIn("orphan-pattern gate", err)

    def test_l2_requires_engagement(self):
        text = _make_note("""
layer: L2
root_cause_class: missing_validation
""")
        rc, err, _ = _run_on_text(text)
        self.assertEqual(rc, 1)
        self.assertIn("L2 requires engagement", err)

    def test_l3_minimal_valid(self):
        text = _make_note("""
layer: L3
frame_id: AMF-001
applicable_classes:
  - missing_validation
case_studies:
  - case_study/spark_lead_h_d.md
  - case_study/spark_77043.md
""")
        rc, err, _ = _run_on_text(text, "--check-cross-refs")
        self.assertEqual(rc, 0, f"stderr:\n{err}")

    def test_l3_requires_two_case_studies(self):
        text = _make_note("""
layer: L3
frame_id: AMF-001
applicable_classes:
  - missing_validation
case_studies:
  - case_study/only_one.md
""")
        rc, err, _ = _run_on_text(text, "--check-cross-refs")
        self.assertEqual(rc, 1)
        self.assertIn("≥2 case_studies", err)

    def test_l4_requires_triggers(self):
        text = _make_note("""
layer: L4
rule_id: L32
""")
        rc, err, _ = _run_on_text(text)
        self.assertEqual(rc, 1)
        self.assertIn("L4 requires triggers", err)

    def test_l4_minimal_valid(self):
        text = _make_note("""
layer: L4
rule_id: L32
triggers:
  - panic
  - validator-crash
""")
        rc, err, _ = _run_on_text(text)
        self.assertEqual(rc, 0, f"stderr:\n{err}")

    def test_invalid_layer_value(self):
        text = _make_note("""
layer: L99
""")
        rc, err, _ = _run_on_text(text)
        self.assertEqual(rc, 1)
        self.assertIn("invalid layer", err)

    def test_no_frontmatter_advisory(self):
        # Phase A migration: notes without layer field warn but don't error
        text = "# Just a markdown note\n\nNo frontmatter here.\n"
        rc, err, _ = _run_on_text(text)
        self.assertEqual(rc, 0, f"missing-frontmatter is migration advisory only; stderr:\n{err}")

    def test_print_schema(self):
        proc = subprocess.run(
            ["python3", str(TOOL), "--print-schema"],
            capture_output=True,
            text=True,
        )
        self.assertEqual(proc.returncode, 0)
        import json
        schema = json.loads(proc.stdout)
        self.assertEqual(schema["$id"], "auditooor.vault_layer.v1")


if __name__ == "__main__":
    unittest.main()
