"""Guard: X-hackerq-dedup - quarantine zero-payload verbatim-template HQ blocks.

(a) a >=min-block group sharing one question_text with empty payload fields is selected;
(b) a same-size group that carries grep_patterns is PROTECTED (not quarantined);
(c) dry-run returns rc=1 when an eligible block exists (hygiene gate fires).
"""
import importlib.util
import json
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
TOOL = ROOT / "tools" / "hacker-q-library-quarantine.py"


def _load():
    spec = importlib.util.spec_from_file_location("hq_quarantine", TOOL)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


class TestHQQuarantine(unittest.TestCase):
    def test_selects_zero_payload_block_and_protects_payload_block(self):
        mod = _load()
        rows = []
        # 60 zero-payload rows sharing one question_text -> quarantine
        for i in range(60):
            rows.append({"question_id": f"z{i}", "question_text": "VERBATIM TEMPLATE NOISE",
                         "grep_patterns": [], "linked_invariant_ids": [], "target_function_patterns": []})
        # 60 rows sharing another question_text but WITH grep payload -> protected
        for i in range(60):
            rows.append({"question_id": f"p{i}", "question_text": "REAL REPEATED QUESTION",
                         "grep_patterns": ["withdraw"], "linked_invariant_ids": [], "target_function_patterns": []})
        # a normal singleton
        rows.append({"question_id": "s1", "question_text": "unique q", "grep_patterns": []})
        keep, quar, blocks = mod.select_quarantine(rows, min_block=50)
        self.assertEqual(len(quar), 60, "zero-payload block must be quarantined")
        self.assertIn("VERBATIM TEMPLATE NOISE", blocks)
        self.assertNotIn("REAL REPEATED QUESTION", blocks, "payload block must be protected")
        self.assertEqual(len(keep), 61)  # 60 payload + 1 singleton

    def test_dry_run_rc1_when_block_present(self):
        mod = _load()
        with tempfile.TemporaryDirectory() as td:
            lib = Path(td) / "lib.jsonl"
            rows = [{"question_id": f"z{i}", "question_text": "NOISE",
                     "grep_patterns": [], "linked_invariant_ids": [], "target_function_patterns": []}
                    for i in range(55)]
            lib.write_text("\n".join(json.dumps(r) for r in rows), encoding="utf-8")
            rc = mod.main(["--library", str(lib)])
            self.assertEqual(rc, 1, "dry-run must rc=1 when an eligible block exists")
            # dry-run must NOT modify the file
            self.assertEqual(len(lib.read_text().splitlines()), 55)


if __name__ == "__main__":
    unittest.main()
