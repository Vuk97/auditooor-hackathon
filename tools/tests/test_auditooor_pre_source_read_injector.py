from __future__ import annotations

import importlib.util
import json
import tempfile
import unittest
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[2]
TOOL_PATH = REPO_ROOT / "tools" / "auditooor-pre-source-read-injector.py"


def _load_tool():
    spec = importlib.util.spec_from_file_location("_psri_worker_aj", str(TOOL_PATH))
    mod = importlib.util.module_from_spec(spec)
    assert spec.loader
    spec.loader.exec_module(mod)
    return mod


class AuditooorPreSourceReadInjectorTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tool = _load_tool()

    def test_build_payload_unifies_corpus_backed_hypotheses_with_provenance(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            source_file = Path(td) / "msg_server.go"
            source_file.write_text("package keeper\n\nfunc RegisterAffiliate() {}\n", encoding="utf-8")

            old_extract = self.tool._extract_functions_via_extractor
            old_rank = self.tool._rank_function
            old_build = self.tool._build_hackerman_function_payload
            old_render = self.tool.render_hacker_questions
            old_cache = dict(self.tool._HACKERMAN_FUNCTION_PAYLOAD_CACHE)
            self.tool._HACKERMAN_FUNCTION_PAYLOAD_CACHE.clear()

            def fake_extract(resolved, rel_path, language):
                return [
                    {
                        "function_name": "RegisterAffiliate",
                        "function_signature": (
                            "func (k msgServer) RegisterAffiliate(ctx context.Context, "
                            "msg *types.MsgRegisterAffiliate) "
                            "(*types.MsgRegisterAffiliateResponse, error)"
                        ),
                        "line_start": 3,
                        "visibility": "exported",
                        "receiver_type": "msgServer",
                    }
                ]

            def fake_rank(**kwargs):
                return ([], {"shape_hash": "shape-coarse", "shape_hash_fine": "shape-fine"})

            def fake_hackerman_payload(**kwargs):
                rows = []
                for idx in range(6):
                    rows.append(
                        {
                            "attack_class": f"class-{idx}",
                            "score": 10.0 - idx,
                            "confidence": 0.95,
                            "evidence": [
                                {
                                    "record_id": f"canonical-{idx}",
                                    "match_kind": "fine_exact",
                                    "match_weight": 1.0,
                                    "record_tier": "confirmed",
                                    "record_quality_score": 0.99 - idx * 0.01,
                                    "proof_hardening": {"submission_posture": "NOT_SUBMIT_READY"},
                                }
                            ],
                        }
                    )
                return {
                    "schema": "auditooor.hackerman.function_mindset.v1",
                    "context_pack_id": "ctx-hackerman",
                    "degraded": False,
                    "total_records_matched": 6,
                    "target": {"shape_hashes_queried": ["shape-coarse", "shape-fine"]},
                    "ranked_attack_classes": rows,
                    "source_refs": [
                        str(REPO_ROOT / "audit" / "corpus_tags" / "index" / "by_shape_hash.jsonl")
                    ],
                    "sidecar_gaps": [],
                }

            def fake_render(**kwargs):
                questions = []
                for idx in range(6):
                    questions.append(
                        {
                            "schema": "auditooor.hacker_question.v1",
                            "question_source": "corpus-derived",
                            "attack_class": f"class-{idx}",
                            "question": f"Question {idx}",
                            "proof_obligation": f"Obligation {idx}",
                            "kill_condition": f"Kill {idx}",
                            "claim_boundary": "Advisory hacker question only; do not claim exploitability without target proof.",
                            "proof_gate": "source_confirmed",
                            "source_record_id": f"question-{idx}",
                            "canonical_hackerman_evidence": {
                                "source_record_id": f"canonical-{idx}",
                                "match_kind": "fine_exact",
                                "match_weight": 1.0,
                                "record_tier": "confirmed",
                                "record_quality_score": 0.99 - idx * 0.01,
                            },
                            "submission_posture": "NOT_SUBMIT_READY",
                        }
                    )
                return questions

            try:
                self.tool._extract_functions_via_extractor = fake_extract
                self.tool._rank_function = fake_rank
                self.tool._build_hackerman_function_payload = fake_hackerman_payload
                self.tool.render_hacker_questions = fake_render

                payload = self.tool.build_injection_payload(
                    file_path=str(source_file),
                    target_repo="dydxprotocol/v4-chain",
                    top_n=7,
                )
            finally:
                self.tool._extract_functions_via_extractor = old_extract
                self.tool._rank_function = old_rank
                self.tool._build_hackerman_function_payload = old_build
                self.tool.render_hacker_questions = old_render
                self.tool._HACKERMAN_FUNCTION_PAYLOAD_CACHE.clear()
                self.tool._HACKERMAN_FUNCTION_PAYLOAD_CACHE.update(old_cache)

        self.assertEqual(payload["functions_analyzed"], 1)
        fn = payload["functions"][0]
        self.assertEqual(len(fn["corpus_backed_hypotheses"]), 5)
        self.assertEqual(fn["corpus_backed_hypotheses"][0]["attack_class"], "class-0")
        self.assertEqual(
            fn["corpus_backed_hypotheses"][0]["provenance"]["source_record_id"],
            "canonical-0",
        )
        self.assertEqual(
            fn["hackerman_shape_evidence"]["shape_hashes_queried"],
            ["shape-coarse", "shape-fine"],
        )
        self.assertNotIn("submission_posture", json.dumps(fn["corpus_backed_hypotheses"]))


if __name__ == "__main__":
    unittest.main()
