"""Test the --language filter in tools/solodit-ingest.py (Tier-A #3).

Verifies:
- No filter   → all 4 fixture findings ingested.
- rust filter → only the Rust finding ingested; Solidity/Go/blank skipped.
- multi-lang  → comma-separated and repeated --language both work.
- unlabeled   → finding with empty language field is dropped when filter active.
- summary counts match (skipped_language, written).
"""
from __future__ import annotations

import importlib.util
import json
import sys
import tempfile
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent.parent
TOOL_PATH = REPO_ROOT / "tools" / "solodit-ingest.py"


def _load_module():
    spec = importlib.util.spec_from_file_location("solodit_ingest", TOOL_PATH)
    mod = importlib.util.module_from_spec(spec)
    sys.modules["solodit_ingest"] = mod
    spec.loader.exec_module(mod)
    return mod


SAMPLE_FINDINGS = [
    {
        "id": "1001",
        "severity": "HIGH",
        "title": "Reentrancy in ERC20 wrapper",
        "language": "Solidity",
        "has_public_fix": True,
    },
    {
        "id": "1002",
        "severity": "CRITICAL",
        "title": "Integer overflow in scalar mult",
        "language": "Rust",
        "has_public_fix": True,
    },
    {
        "id": "1003",
        "severity": "HIGH",
        "title": "Goroutine leak in coordinator",
        "language": "Go",
        "has_public_fix": True,
    },
    {
        "id": "1004",
        "severity": "HIGH",
        "title": "Some unlabeled finding",
        "language": "",
        "has_public_fix": True,
    },
]


class LanguageFilterTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.mod = _load_module()

    def _run(self, **kwargs):
        with tempfile.TemporaryDirectory() as tmp:
            out_dir = Path(tmp) / "out"
            return self.mod.ingest(
                findings=SAMPLE_FINDINGS,
                out_dir=out_dir,
                cursor_file=None,
                max_findings=100,
                strict_privacy=False,
                dry_run=True,
                **kwargs,
            )

    def test_no_filter_writes_all(self):
        s = self._run(language_filter=None)
        self.assertEqual(s["written"], 4)
        self.assertEqual(s["skipped_language"], 0)
        self.assertEqual(s["language_filter"], [])

    def test_rust_filter_keeps_only_rust(self):
        s = self._run(language_filter=["rust"])
        self.assertEqual(s["written"], 1)
        self.assertEqual(s["skipped_language"], 3)
        self.assertEqual(s["language_filter"], ["rust"])

    def test_comma_separated_filter(self):
        s = self._run(language_filter=["rust,go"])
        self.assertEqual(s["written"], 2)
        self.assertEqual(s["skipped_language"], 2)
        self.assertEqual(sorted(s["language_filter"]), ["go", "rust"])

    def test_repeated_filter(self):
        s = self._run(language_filter=["rust", "go"])
        self.assertEqual(s["written"], 2)
        self.assertEqual(s["skipped_language"], 2)

    def test_case_insensitive(self):
        s = self._run(language_filter=["RUST"])
        self.assertEqual(s["written"], 1)
        self.assertEqual(s["skipped_language"], 3)

    def test_unlabeled_dropped_when_filter_active(self):
        # The id=1004 finding has an empty language string. Under filter,
        # it must be dropped (skipped_language) — never silently ingested.
        s = self._run(language_filter=["solidity"])
        self.assertEqual(s["written"], 1)
        self.assertEqual(s["skipped_language"], 3)


if __name__ == "__main__":
    unittest.main()
