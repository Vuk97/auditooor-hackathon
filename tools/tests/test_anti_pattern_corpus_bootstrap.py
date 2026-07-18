from __future__ import annotations

import importlib.util
import json
import sys
import tempfile
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
MODULE_PATH = REPO_ROOT / "tools" / "anti-pattern-corpus-bootstrap.py"


def _load_module():
    spec = importlib.util.spec_from_file_location("anti_pattern_corpus_bootstrap", MODULE_PATH)
    module = importlib.util.module_from_spec(spec)
    assert spec is not None and spec.loader is not None
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


bootstrap = _load_module()


class TestAntiPatternCorpusBootstrap(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix="anti-pattern-bootstrap-")
        self.root = Path(self.tmp.name)
        (self.root / "reference").mkdir(parents=True)
        (self.root / "audit" / "corpus_tags" / "tags").mkdir(parents=True)
        rejections = []
        for idx in range(1, 6):
            examples = [f"#{idx}: concrete rejected lesson"] if idx <= 2 else ["(None yet in submissions)"]
            rejections.append(
                {
                    "id": f"R{idx}",
                    "name": f"Lesson {idx}",
                    "triager_language": ["theoretical"],
                    "pre_submit_guard": f"Require concrete proof for lesson {idx}.",
                    "description": f"Lesson {idx} description.",
                    "examples": examples,
                }
            )
        (self.root / "reference" / "triager_patterns.json").write_text(
            json.dumps({"rejections": rejections, "acceptances": [], "version": 1}),
            encoding="utf-8",
        )
        outcomes = [
            {"finding_id": "1", "status": "Rejected (event-only)", "title": "one"},
            {"submission_id": "workspace-2", "outcome_class": "rejected", "title": "two"},
        ]
        (self.root / "reference" / "outcomes.jsonl").write_text(
            "\n".join(json.dumps(row) for row in outcomes) + "\n",
            encoding="utf-8",
        )
        (self.root / "audit" / "corpus_tags" / "tags" / "sample.yaml").write_text(
            "fix_anti_pattern_avoided: shipping theoretical claims without concrete proof\n",
            encoding="utf-8",
        )

    def tearDown(self):
        self.tmp.cleanup()

    def test_bootstrap_writes_expected_frontmatter_fields(self):
        written = bootstrap.bootstrap(self.root, limit=5)
        self.assertEqual(len(written), 5)
        note = self.root / "obsidian-vault" / "anti-patterns" / "lesson-1.md"
        body = note.read_text(encoding="utf-8")
        self.assertIn("recommendation:", body)
        self.assertIn("sample_size:", body)
        self.assertIn("confidence:", body)
        self.assertIn("counter_examples:", body)

    def test_outcome_evidence_can_raise_confidence_but_fix_phrases_cannot(self):
        bootstrap.bootstrap(self.root, limit=5)
        with_outcome = (self.root / "obsidian-vault" / "anti-patterns" / "lesson-1.md").read_text(
            encoding="utf-8"
        )
        without_outcome = (self.root / "obsidian-vault" / "anti-patterns" / "lesson-3.md").read_text(
            encoding="utf-8"
        )
        self.assertIn("confidence: medium", with_outcome)
        self.assertIn("confidence: low", without_outcome)
        self.assertIn("do not raise confidence", without_outcome)
        self.assertNotIn("confidence: high", without_outcome)


if __name__ == "__main__":
    unittest.main()
