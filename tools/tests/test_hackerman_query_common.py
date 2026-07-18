from __future__ import annotations

import importlib.util
import json
import sys
import unittest
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[2]
TOOL_PATH = REPO_ROOT / "tools" / "hackerman_query_common.py"


def _load_tool():
    spec = importlib.util.spec_from_file_location("_hackerman_query_common_worker_aj", str(TOOL_PATH))
    mod = importlib.util.module_from_spec(spec)
    assert spec.loader
    sys.modules["_hackerman_query_common_worker_aj"] = mod
    spec.loader.exec_module(mod)
    return mod


class HackermanQueryCommonTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tool = _load_tool()

    def test_build_corpus_backed_hypotheses_pairs_question_with_provenance(self) -> None:
        ranked = [
            {
                "attack_class": "admin-bypass",
                "score": 4.2,
                "confidence": 0.91,
                "evidence": [
                    {
                        "record_id": "row-admin",
                        "match_kind": "fine_exact",
                        "match_weight": 1.0,
                        "record_tier": "dydx-filed",
                        "record_quality_score": 4.9,
                    }
                ],
            }
        ]
        questions = [
            {
                "question_source": "corpus-derived",
                "attack_class": "admin-bypass",
                "question": "Can authority checks be bypassed on this path before state mutation?",
                "proof_obligation": "Show a concrete caller path that reaches the mutation without the expected authority gate.",
                "kill_condition": "The same authority gate is enforced before the mutation on every reachable path.",
                "claim_boundary": "Advisory hacker question only; do not claim exploitability without target proof.",
                "proof_gate": "source_confirmed",
                "source_record_id": "question-admin",
                "canonical_hackerman_evidence": {
                    "source_record_id": "canonical-admin",
                    "match_kind": "fine_exact",
                    "match_weight": 1.0,
                    "record_tier": "confirmed",
                    "record_quality_score": 0.99,
                },
                "cross_language_analogues": [
                    {
                        "target_language": "go",
                        "analogue_record_id": "go/admin-bypass",
                        "confidence": 0.82,
                        "pattern_translation": "unused in pre-source-read brief",
                    }
                ],
                "submission_posture": "NOT_SUBMIT_READY",
            }
        ]

        out = self.tool.build_corpus_backed_hypotheses(ranked, questions, 3)

        self.assertEqual(len(out), 1)
        item = out[0]
        self.assertEqual(item["attack_class"], "admin-bypass")
        self.assertEqual(item["provenance"]["source_record_id"], "canonical-admin")
        self.assertEqual(item["provenance"]["match_kind"], "fine_exact")
        self.assertEqual(item["provenance"]["record_tier"], "confirmed")
        self.assertEqual(item["cross_language_analogues"][0]["analogue_record_id"], "go/admin-bypass")
        self.assertNotIn("submission_posture", json.dumps(item))

    def test_build_corpus_backed_hypotheses_is_bounded_to_five(self) -> None:
        ranked = []
        questions = []
        for idx in range(7):
            attack_class = f"class-{idx}"
            ranked.append(
                {
                    "attack_class": attack_class,
                    "score": 5.0 - idx * 0.1,
                    "confidence": 0.9,
                    "evidence": [{"record_id": f"row-{idx}", "match_kind": "coarse_exact"}],
                }
            )
            questions.append(
                {
                    "question_source": "corpus-derived",
                    "attack_class": attack_class,
                    "question": f"Question {idx}",
                    "proof_obligation": f"Obligation {idx}",
                    "kill_condition": f"Kill {idx}",
                    "claim_boundary": "Advisory hacker question only.",
                    "proof_gate": "source_confirmed",
                    "source_record_id": f"question-{idx}",
                }
            )

        out = self.tool.build_corpus_backed_hypotheses(ranked, questions, 9)

        self.assertEqual(len(out), 5)
        self.assertEqual([row["attack_class"] for row in out], [f"class-{idx}" for idx in range(5)])


if __name__ == "__main__":
    unittest.main()
