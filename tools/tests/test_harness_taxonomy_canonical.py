"""Acceptance test for P0-z: docs/HARNESS_FAILURE_TAXONOMY.md is the canonical 20-mode source.

Asserts the canonical doc parses 20 numbered modes (1-20) plus the 4b refinement, each
carrying a non-empty proven_fix and a real_example_file_line matching `\\.sol:\\d+|\\.json`,
and that the parsed mode-name set EQUALS the set tools/harness-failure-memory.py SEED_ROOTS
loads as semantic modes (P0-c).
"""
import importlib.util
import re
import sys
import unittest
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[2]
DOC_PATH = REPO_ROOT / "docs" / "HARNESS_FAILURE_TAXONOMY.md"
MODULE_PATH = REPO_ROOT / "tools" / "harness-failure-memory.py"

# A mode block opens with "### Mode <N> - <slug>" where N is 1..20 or 4b.
MODE_HEADER_RE = re.compile(r"^###\s+Mode\s+(\d+b?)\s+-\s+(?P<slug>[a-z0-9-]+)\s*$")
FIELD_RE = re.compile(r"^-\s+(?P<key>[a-z_-]+):\s*(?P<value>.+?)\s*$")
FILE_LINE_RE = re.compile(r"\.sol:\d+|\.json")
EXPECTED_NUMBERS = [str(n) for n in range(1, 21)] + ["4b"]


def load_module(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


hfm = load_module("harness_failure_memory", MODULE_PATH)


def parse_modes(text):
    """Return ordered list of {number, slug, fields} blocks parsed from the doc."""
    modes = []
    current = None
    for line in text.splitlines():
        header = MODE_HEADER_RE.match(line)
        if header:
            if current is not None:
                modes.append(current)
            current = {"number": header.group(1), "slug": header.group("slug"), "fields": {}}
            continue
        if current is None:
            continue
        if line.startswith("### ") or line.startswith("## "):
            modes.append(current)
            current = None
            continue
        field = FIELD_RE.match(line)
        if field:
            current["fields"][field.group("key")] = field.group("value")
    if current is not None:
        modes.append(current)
    return modes


class HarnessTaxonomyCanonicalTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.text = DOC_PATH.read_text(encoding="utf-8")
        cls.modes = parse_modes(cls.text)

    def test_doc_exists(self):
        self.assertTrue(DOC_PATH.is_file(), f"{DOC_PATH} missing")

    def test_parses_twenty_modes_plus_4b(self):
        self.assertEqual(len(self.modes), 21, "expected 20 modes (1-20) plus the 4b refinement")
        numbers = [mode["number"] for mode in self.modes]
        self.assertEqual(sorted(numbers, key=lambda n: (int(n[:-1]) if n.endswith("b") else int(n), n)),
                         sorted(EXPECTED_NUMBERS, key=lambda n: (int(n[:-1]) if n.endswith("b") else int(n), n)))
        self.assertEqual(set(numbers), set(EXPECTED_NUMBERS))

    def test_each_mode_has_nonempty_proven_fix_and_real_example(self):
        for mode in self.modes:
            label = f"Mode {mode['number']} ({mode['slug']})"
            fields = mode["fields"]
            self.assertIn("proven_fix", fields, f"{label}: missing proven_fix")
            self.assertTrue(fields["proven_fix"].strip(), f"{label}: proven_fix is empty")
            self.assertIn("real_example_file_line", fields, f"{label}: missing real_example_file_line")
            self.assertTrue(
                FILE_LINE_RE.search(fields["real_example_file_line"]),
                f"{label}: real_example_file_line must match .sol:N or .json",
            )
            # mode-name field must echo the header slug.
            self.assertEqual(fields.get("mode-name"), mode["slug"], f"{label}: mode-name mismatch")

    def test_mode_name_set_equals_seed_roots_semantic_modes(self):
        doc_names = {mode["slug"] for mode in self.modes}
        seed_names = set(hfm.SEMANTIC_MODE_NAMES)

        self.assertEqual(
            doc_names,
            seed_names,
            "canonical doc mode-name set must equal SEED_ROOTS semantic_mode_seeds() names",
        )
        # And the ordered accessor name set is identical too.
        self.assertEqual(set(hfm.semantic_mode_seeds()[0]) >= {"root_cause_id"}, True)
        self.assertEqual({s["root_cause_id"] for s in hfm.semantic_mode_seeds()}, doc_names)


if __name__ == "__main__":
    unittest.main()
