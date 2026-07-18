"""Tests for tools/auditooor-pre-source-read-injector.py — Wave-6 Phase C."""
from __future__ import annotations

import importlib.util
import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[2]
TOOL_PATH = REPO_ROOT / "tools" / "auditooor-pre-source-read-injector.py"
WRAPPER_PATH = REPO_ROOT / "scripts" / "pre-source-read-inject.sh"
FIXTURE_GO = REPO_ROOT / "tools" / "tests" / "fixtures" / "fn_sig_extractor_go" / "sample.go"
FIXTURE_RS = REPO_ROOT / "tools" / "tests" / "fixtures" / "fn_sig_extractor_rust" / "sample.rs"
RANKER_LOG = REPO_ROOT / "audit" / "ranker_predictions_log.jsonl"


def _load_tool():
    spec = importlib.util.spec_from_file_location("_psri", str(TOOL_PATH))
    mod = importlib.util.module_from_spec(spec)
    assert spec.loader
    spec.loader.exec_module(mod)
    return mod


def _run_cli(*args: str) -> dict:
    """Invoke the injector CLI and return parsed JSON."""
    proc = subprocess.run(
        [sys.executable, str(TOOL_PATH), *args],
        capture_output=True,
        text=True,
        timeout=60,
    )
    if proc.returncode != 0:
        raise AssertionError(f"CLI failed rc={proc.returncode}: {proc.stderr}")
    return json.loads(proc.stdout)


class PreSourceReadInjectorTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tool = _load_tool()

    # 1) file-not-found
    def test_file_not_found_returns_zero_functions(self) -> None:
        payload = self.tool.build_injection_payload(
            file_path="/tmp/definitely-does-not-exist-xyzzy.go",
            target_repo="dydxprotocol/v4-chain",
            top_n=3,
            min_confidence=0.4,
        )
        self.assertEqual(payload["functions_analyzed"], 0)
        self.assertTrue(payload["skipped_reasons"], "skipped_reasons must be non-empty")
        self.assertTrue(
            any("file-not-found" in r for r in payload["skipped_reasons"]),
            f"got {payload['skipped_reasons']}",
        )
        # Schema name preserved
        self.assertEqual(payload["schema"], "auditooor.pre_source_read_injection.v1")

    # 2) unsupported extension
    def test_unsupported_extension_returns_zero(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            p = Path(td) / "notes.md"
            p.write_text("# nothing here\n")
            payload = self.tool.build_injection_payload(
                file_path=str(p),
                target_repo="dydxprotocol/v4-chain",
                top_n=3,
            )
            self.assertEqual(payload["functions_analyzed"], 0)
            self.assertTrue(
                any("unsupported-extension" in r for r in payload["skipped_reasons"]),
                f"got {payload['skipped_reasons']}",
            )

    # 3) real Go fixture returns >=1 function
    def test_real_go_fixture_returns_functions(self) -> None:
        self.assertTrue(FIXTURE_GO.exists(), f"fixture missing: {FIXTURE_GO}")
        payload = self.tool.build_injection_payload(
            file_path=str(FIXTURE_GO),
            target_repo="dydxprotocol/v4-chain",
            top_n=3,
        )
        self.assertGreaterEqual(payload["functions_analyzed"], 1)
        self.assertEqual(payload["language"], "go")
        # At least one function name should be RegisterAffiliate
        names = {f["name"] for f in payload["functions"]}
        self.assertIn("RegisterAffiliate", names)

    def test_rust_fixture_uses_structured_signature_extractor(self) -> None:
        self.assertTrue(FIXTURE_RS.exists(), f"fixture missing: {FIXTURE_RS}")
        recs = self.tool._extract_functions_via_extractor(
            FIXTURE_RS, "sample.rs", "rust"
        )
        self.assertGreaterEqual(len(recs), 1)
        by_name = {r.get("function_name"): r for r in recs}
        self.assertIn("process_message", by_name)
        proc = by_name["process_message"]
        self.assertEqual(proc.get("return_types"), ["Result<(), ProgramError>"])
        param_types = [p.get("type") for p in proc.get("params", [])]
        self.assertIn("&mut Context<'a>", param_types)

    def test_solidity_uses_structured_signature_extractor(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            p = Path(td) / "Vault.sol"
            p.write_text(
                """
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract Vault {
    function withdraw(uint256 assets, address receiver) external returns (uint256 shares) {
        return assets;
    }
}
""".lstrip(),
                encoding="utf-8",
            )

            recs = self.tool._extract_functions_via_extractor(p, "Vault.sol", "solidity")

        by_name = {r.get("function_name"): r for r in recs}
        self.assertIn("withdraw", by_name)
        withdraw = by_name["withdraw"]
        self.assertEqual(withdraw.get("language"), "solidity")
        self.assertEqual(withdraw.get("visibility"), "external")
        self.assertEqual(withdraw.get("state_mutability"), "nonpayable")
        param_types = [param.get("type") for param in withdraw.get("params", [])]
        self.assertEqual(param_types, ["uint256", "address"])
        self.assertEqual(withdraw.get("return_types"), ["uint256 shares"])

    def test_solidity_build_payload_routes_through_structured_extractor(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            p = Path(td) / "Vault.sol"
            p.write_text(
                "contract Vault { function withdraw(uint256 assets) external {} }\n",
                encoding="utf-8",
            )
            old_extract = self.tool._extract_functions_via_extractor
            old_regex = self.tool._extract_regex_fallback
            old_rank = self.tool._rank_function
            old_build = self.tool._build_hackerman_function_payload
            calls: dict[str, str] = {}

            def fake_extract(resolved, rel_path, language):
                calls["extract_language"] = language
                return [
                    {
                        "file_path": rel_path,
                        "language": language,
                        "function_name": "withdraw",
                        "function_signature": "function withdraw(uint256 assets) external",
                        "line_start": 1,
                        "visibility": "external",
                        "receiver_type": None,
                        "params": [{"name": "assets", "type": "uint256"}],
                        "return_types": [],
                    }
                ]

            def fail_regex(*args, **kwargs):
                self.fail("Solidity should use structured extraction before regex fallback")

            def fake_rank(**kwargs):
                return (
                    [
                        {
                            "attack_class": "reentrancy",
                            "score": 1.0,
                            "confidence": 0.9,
                            "evidence": [{"record_id": "record-solidity"}],
                        }
                    ],
                    {"shape_hash": "shape-sol", "shape_hash_fine": "shape-sol-fine"},
                )

            def fake_build(**kwargs):
                return {"ranked_attack_classes": []}

            try:
                self.tool._extract_functions_via_extractor = fake_extract
                self.tool._extract_regex_fallback = fail_regex
                self.tool._rank_function = fake_rank
                self.tool._build_hackerman_function_payload = fake_build
                payload = self.tool.build_injection_payload(
                    file_path=str(p),
                    target_repo="example/vault",
                    top_n=1,
                )
            finally:
                self.tool._extract_functions_via_extractor = old_extract
                self.tool._extract_regex_fallback = old_regex
                self.tool._rank_function = old_rank
                self.tool._build_hackerman_function_payload = old_build

        self.assertEqual(calls["extract_language"], "solidity")
        self.assertEqual(payload["language"], "solidity")
        self.assertEqual(payload["functions_analyzed"], 1)
        self.assertEqual(payload["functions"][0]["name"], "withdraw")
        self.assertNotIn("regex-fallback-zero-solidity", payload["skipped_reasons"])

    def test_solidity_falls_back_to_regex_when_structured_extractor_returns_zero(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            p = Path(td) / "Vault.sol"
            p.write_text(
                "contract Vault { function withdraw(uint256 assets) external {} }\n",
                encoding="utf-8",
            )
            old_extract = self.tool._extract_functions_via_extractor
            old_regex = self.tool._extract_regex_fallback
            old_rank = self.tool._rank_function
            old_build = self.tool._build_hackerman_function_payload
            calls: dict[str, str] = {}

            def fake_extract(resolved, rel_path, language):
                calls["extract_language"] = language
                return []

            def fake_regex(resolved, rel_path, language):
                calls["regex_language"] = language
                return [
                    {
                        "file_path": rel_path,
                        "language": language,
                        "function_name": "withdraw",
                        "function_signature": "function withdraw(uint256 assets) external",
                        "line_start": 1,
                        "visibility": "external",
                        "receiver_type": None,
                    }
                ]

            def fake_rank(**kwargs):
                return ([], {"shape_hash": "shape-sol", "shape_hash_fine": "shape-sol-fine"})

            def fake_build(**kwargs):
                return {"ranked_attack_classes": []}

            try:
                self.tool._extract_functions_via_extractor = fake_extract
                self.tool._extract_regex_fallback = fake_regex
                self.tool._rank_function = fake_rank
                self.tool._build_hackerman_function_payload = fake_build
                payload = self.tool.build_injection_payload(
                    file_path=str(p),
                    target_repo="example/vault",
                    top_n=1,
                )
            finally:
                self.tool._extract_functions_via_extractor = old_extract
                self.tool._extract_regex_fallback = old_regex
                self.tool._rank_function = old_rank
                self.tool._build_hackerman_function_payload = old_build

        self.assertEqual(calls["extract_language"], "solidity")
        self.assertEqual(calls["regex_language"], "solidity")
        self.assertEqual(payload["functions_analyzed"], 1)
        self.assertIn("solidity-extractor-returned-zero", payload["skipped_reasons"])

    # 4) Output schema and required top-level keys
    def test_output_schema_complete(self) -> None:
        payload = self.tool.build_injection_payload(
            file_path=str(FIXTURE_GO),
            target_repo="dydxprotocol/v4-chain",
            top_n=3,
        )
        required_top = {
            "schema", "hacker_question_schema", "context_pack_id", "context_pack_hash",
            "file_path", "target_repo", "language", "functions_analyzed", "functions",
            "summary", "skipped_reasons",
            "advisory_disclaimer", "performance_budget_note", "generated_at_utc",
        }
        self.assertTrue(required_top.issubset(payload.keys()),
                        f"missing keys: {required_top - payload.keys()}")
        # Per-function shape
        for fn in payload["functions"]:
            self.assertIn("name", fn)
            self.assertIn("line", fn)
            self.assertIn("shape_hash", fn)
            self.assertIn("shape_hash_fine", fn)
            self.assertIn("top_attack_classes", fn)
            self.assertIn("hacker_questions", fn)
            self.assertEqual(fn["hacker_question_count"], len(fn["hacker_questions"]))
            self.assertIn("hacker_question_counts_by_source", fn)
            self.assertIn("corpus_backed_hypothesis_count", fn)
            for ac in fn["top_attack_classes"]:
                self.assertIn("class_id", ac)
                self.assertIn("score", ac)
                self.assertIn("confidence", ac)
            for question in fn["hacker_questions"]:
                self.assertEqual(question["schema"], "auditooor.hacker_question.v1")
                self.assertIn("question", question)
                # W5-F1: hacker_questions now mix two sources - corpus-derived
                # rows carry attack-class proof obligations; curated-library
                # rows carry shape-class reasoning fields.
                source = question.get("question_source")
                if source == "curated-library":
                    self.assertIn("shape_class", question)
                    self.assertIn("reasoning_axis", question)
                else:
                    self.assertIn("attack_class", question)
                    self.assertIn("function_shape_fine", question)
                self.assertIn("proof_gate", question)
                self.assertIn("claim_boundary", question)
                self.assertIn("proof_obligation", question)
                self.assertIn("kill_condition", question)
        self.assertEqual(
            payload["summary"]["hacker_question_count"],
            sum(len(fn["hacker_questions"]) for fn in payload["functions"]),
        )

    # 5) --top-n 3 caps to <=3 attack classes per function
    def test_top_n_limits_attack_classes(self) -> None:
        payload = self.tool.build_injection_payload(
            file_path=str(FIXTURE_GO),
            target_repo="dydxprotocol/v4-chain",
            top_n=3,
            min_confidence=0.4,
        )
        for fn in payload["functions"]:
            self.assertLessEqual(
                len(fn["top_attack_classes"]), 3,
                f"function {fn['name']} got >3 attack classes",
            )

    # 6) --min-confidence 0.95 filters out everything (sanity-check the filter wires through)
    def test_min_confidence_filters_correctly(self) -> None:
        payload = self.tool.build_injection_payload(
            file_path=str(FIXTURE_GO),
            target_repo="dydxprotocol/v4-chain",
            top_n=5,
            min_confidence=0.95,
        )
        # With a 0.95 floor on the ranker's confidence sigmoid, expect zero or
        # near-zero attack classes per function (current ranker tops out near
        # 0.77 on the fixture). The test asserts the per-function attack-class
        # list is empty for at least one function — proving filter wires through.
        any_empty = any(len(fn["top_attack_classes"]) == 0 for fn in payload["functions"])
        self.assertTrue(any_empty, "expected min_confidence=0.95 to filter at least one fn empty")

    # 7) CLI smoke (end-to-end JSON output)
    def test_cli_smoke_end_to_end(self) -> None:
        data = _run_cli(
            str(FIXTURE_GO),
            "--target-repo", "dydxprotocol/v4-chain",
            "--top-n", "3",
            "--min-confidence", "0.4",
            "--json",
        )
        self.assertEqual(data["schema"], "auditooor.pre_source_read_injection.v1")
        self.assertGreaterEqual(data["functions_analyzed"], 1)

    def test_cli_claude_hook_output_is_bounded_system_message(self) -> None:
        data = _run_cli(
            str(FIXTURE_GO),
            "--target-repo", "dydxprotocol/v4-chain",
            "--top-n", "3",
            "--min-confidence", "0.4",
            "--claude-hook-output",
            "--hook-max-chars", "1200",
        )
        self.assertEqual(data["hookSpecificOutput"]["hookEventName"], "PreToolUse")
        self.assertEqual(data["hookSpecificOutput"]["permissionDecision"], "allow")
        # additionalContext is the canonical PreToolUse injection field (feeds model context).
        # systemMessage is a display-layer copy (TUI transcript).
        self.assertIn("additionalContext", data["hookSpecificOutput"],
                      "additionalContext must be inside hookSpecificOutput for PreToolUse injection")
        card = data["hookSpecificOutput"]["additionalContext"]
        self.assertIn("Auditooor pre-source-read hacker questions", card)
        self.assertIn("Advisory only", card)
        self.assertLessEqual(len(card), 1200)
        # systemMessage display copy also present and bounded
        self.assertIn("systemMessage", data)
        self.assertIn("Auditooor pre-source-read hacker questions", data["systemMessage"])
        self.assertLessEqual(len(data["systemMessage"]), 1200)

    def test_cli_claude_hook_output_additionalContext_matches_systemMessage(self) -> None:
        """additionalContext and systemMessage carry the same card text (both bounded)."""
        data = _run_cli(
            str(FIXTURE_GO),
            "--target-repo", "dydxprotocol/v4-chain",
            "--top-n", "3",
            "--min-confidence", "0.4",
            "--claude-hook-output",
            "--hook-max-chars", "2000",
        )
        self.assertEqual(
            data["hookSpecificOutput"]["additionalContext"],
            data["systemMessage"],
            "additionalContext and systemMessage must carry the same card text",
        )

    def test_build_payload_does_not_append_ranker_prediction_log_by_default(self) -> None:
        old_hook_opt_in = os.environ.pop("AUDITOOOR_PRE_SOURCE_READ_LOG_RANKER", None)
        before = RANKER_LOG.read_bytes() if RANKER_LOG.exists() else b""
        try:
            payload = self.tool.build_injection_payload(
                file_path=str(FIXTURE_GO),
                target_repo="dydxprotocol/v4-chain",
                top_n=2,
            )
            self.assertGreaterEqual(payload["functions_analyzed"], 1)
            after = RANKER_LOG.read_bytes() if RANKER_LOG.exists() else b""
            self.assertEqual(after, before)
        finally:
            if old_hook_opt_in is not None:
                os.environ["AUDITOOOR_PRE_SOURCE_READ_LOG_RANKER"] = old_hook_opt_in

    # 8) max_functions cap surfaces truncated-to-top reason
    def test_max_functions_truncation_documented(self) -> None:
        # Force truncation by setting max_functions=1 on a 3-function fixture
        payload = self.tool.build_injection_payload(
            file_path=str(FIXTURE_GO),
            target_repo="dydxprotocol/v4-chain",
            top_n=3,
            max_functions=1,
        )
        self.assertEqual(payload["functions_analyzed"], 1)
        self.assertTrue(
            any("truncated-to-top-1-by-line" in r for r in payload["skipped_reasons"]),
            f"got {payload['skipped_reasons']}",
        )

    def test_hacker_question_renderer_preserves_provenance(self) -> None:
        questions = self.tool.render_hacker_questions(
            ranked=[
                {
                    "attack_class": "admin-bypass",
                    "score": 1.2,
                    "confidence": 0.8,
                    "evidence": [
                        {
                            "record_id": "record-123",
                            "match_kind": "fine_exact",
                            "match_weight": 1.0,
                            "record_tier": "confirmed",
                            "record_quality_score": 0.91,
                            "cross_language_analogues": [
                                {
                                    "target_language": "go",
                                    "pattern_translation": "solidity share inflation -> go zero-share vault residual",
                                    "analogue_record_id": "record-456",
                                    "confidence": 0.8,
                                }
                            ],
                        }
                    ],
                }
            ],
            function_name="RegisterAffiliate",
            shape_hash="shape-a",
            shape_hash_fine="shape-b",
            file_path="protocol/x/affiliates/keeper/msg_server.go",
            context_pack_id="ctx-1",
        )

        # W5-F1: render now appends curated-library rows; the corpus-derived
        # provenance row is the one carrying the attack-class evidence anchors.
        corpus_rows = [q for q in questions
                       if q.get("question_source") == "corpus-derived"]
        self.assertEqual(len(corpus_rows), 1)
        question = corpus_rows[0]
        self.assertEqual(question["schema"], "auditooor.hacker_question.v1")
        self.assertEqual(question["attack_class"], "admin-bypass")
        self.assertEqual(question["source_record_id"], "record-123")
        self.assertEqual(question["record_tier"], "confirmed")
        self.assertEqual(question["record_quality_score"], 0.91)
        self.assertEqual(question["canonical_hackerman_evidence"]["source_record_id"], "record-123")
        self.assertEqual(question["canonical_hackerman_evidence"]["match_kind"], "fine_exact")
        self.assertEqual(question["proof_gate"], "source_confirmed")
        self.assertIn("Advisory hacker question only", question["claim_boundary"])
        self.assertEqual(question["mcp_context_pack_id"], "ctx-1")
        self.assertEqual(question["function_shape_fine"], "shape-b")
        self.assertEqual(question["cross_language_analogues"][0]["target_language"], "go")
        self.assertEqual(question["cross_language_analogues"][0]["analogue_record_id"], "record-456")
        self.assertIn("authority", question["question"])

    def test_build_payload_prefers_canonical_hackerman_shape_evidence(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            p = Path(td) / "msg_server.go"
            p.write_text("package keeper\n\nfunc RegisterAffiliate() {}\n", encoding="utf-8")

            old_extract = self.tool._extract_functions_via_extractor
            old_rank = self.tool._rank_function
            old_build = self.tool._build_hackerman_function_payload
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
                return (
                    [
                        {
                            "attack_class": "admin-bypass",
                            "score": 0.4,
                            "confidence": 0.5,
                            "evidence": [{"record_id": "legacy-admin"}],
                        },
                        {
                            "attack_class": "fee-redirect",
                            "score": 0.3,
                            "confidence": 0.45,
                            "evidence": [{"record_id": "legacy-fee"}],
                        },
                    ],
                    {"shape_hash": "shape-coarse", "shape_hash_fine": "shape-fine"},
                )

            def fake_hackerman_payload(**kwargs):
                return {
                    "schema": "auditooor.function_mindset.v1",
                    "context_pack_id": "ctx-hackerman",
                    "degraded": False,
                    "total_records_matched": 2,
                    "ranked_attack_classes": [
                        {
                            "attack_class": "admin-bypass",
                            "score": 9.0,
                            "confidence": 0.97,
                            "evidence": [
                                {
                                    "record_id": "canonical-admin",
                                    "match_kind": "fine_exact",
                                    "match_weight": 1.0,
                                    "record_tier": "confirmed",
                                    "record_quality_score": 0.99,
                                }
                            ],
                        },
                        {
                            "attack_class": "fee-redirect",
                            "score": 8.0,
                            "confidence": 0.91,
                            "evidence": [
                                {
                                    "record_id": "canonical-fee",
                                    "match_kind": "coarse_exact",
                                    "match_weight": 0.7,
                                }
                            ],
                        },
                    ],
                    "source_refs": [
                        str(REPO_ROOT / "audit" / "corpus_tags" / "index" / "by_function_shape.jsonl")
                    ],
                    "sidecar_gaps": ["external_repo_recall_measurement_missing"],
                }

            try:
                self.tool._extract_functions_via_extractor = fake_extract
                self.tool._rank_function = fake_rank
                self.tool._build_hackerman_function_payload = fake_hackerman_payload

                payload = self.tool.build_injection_payload(
                    file_path=str(p),
                    target_repo="dydxprotocol/v4-chain",
                    top_n=2,
                )
            finally:
                self.tool._extract_functions_via_extractor = old_extract
                self.tool._rank_function = old_rank
                self.tool._build_hackerman_function_payload = old_build
                self.tool._HACKERMAN_FUNCTION_PAYLOAD_CACHE.clear()
                self.tool._HACKERMAN_FUNCTION_PAYLOAD_CACHE.update(old_cache)

        self.assertEqual(payload["functions_analyzed"], 1)
        fn = payload["functions"][0]
        self.assertEqual(
            [row["class_id"] for row in fn["top_attack_classes"]],
            ["admin-bypass", "fee-redirect"],
        )
        self.assertEqual(fn["top_attack_classes"][0]["score"], 9.0)
        admin_question = next(
            q for q in fn["hacker_questions"]
            if q.get("question_source") == "corpus-derived"
            and q.get("attack_class") == "admin-bypass"
        )
        self.assertEqual(admin_question["source_record_id"], "canonical-admin")
        self.assertEqual(admin_question["canonical_hackerman_evidence"]["match_kind"], "fine_exact")

        summary = fn["hackerman_shape_evidence"]
        self.assertEqual(summary["total_records_matched"], 2)
        self.assertEqual(summary["top_hypotheses"][0]["source_record_id"], "canonical-admin")
        self.assertEqual(summary["source_refs"], ["audit/corpus_tags/index/by_function_shape.jsonl"])
        self.assertNotIn("evidence", json.dumps(summary))

    def test_hacker_question_renderer_marks_proof_domain_boundaries(self) -> None:
        questions = self.tool.render_hacker_questions(
            ranked=[
                {
                    "attack_class": "bridge-proof-verifier-replay",
                    "evidence": [{"record_id": "bridge-proof-1"}],
                }
            ],
            function_name="finalizeWithdrawal",
            shape_hash="shape-bridge",
            file_path="contracts/BridgePortal.sol",
            context_pack_id="ctx-bridge",
            include_library=False,
            include_economic=False,
        )

        self.assertEqual(len(questions), 1)
        question = questions[0]
        self.assertEqual(question["proof_gate"], "production_reachability_required")
        self.assertIn("production verifier accepts", question["question"])
        self.assertIn("verifier acceptance on the production entry point", question["proof_obligation"])
        self.assertIn("Bridge/proof-domain question only", question["claim_boundary"])
        self.assertIn("unreachable finalization", question["kill_condition"])

    def test_hacker_question_renderer_uses_zero_output_lesson_template(self) -> None:
        questions = self.tool.render_hacker_questions(
            ranked=[
                {
                    "attack_class": "erc4626-share-price-manipulation",
                    "evidence": [{"record_id": "zero-output-1"}],
                },
                {
                    "attack_class": "withdrawal-bypass",
                    "evidence": [{"record_id": "withdrawal-2"}],
                },
            ],
            function_name="previewMint",
            shape_hash="shape-zero",
            file_path="contracts/Vault.sol",
            context_pack_id="ctx-zero",
            include_library=False,
            include_economic=False,
        )

        zero_question, control_question = questions
        self.assertIn("pre-curated", zero_question["question"])
        self.assertIn("floor to zero", zero_question["question"].lower())
        self.assertIn("realistic control case", zero_question["proof_obligation"].lower())
        self.assertIn("artificial pre-curated setup", zero_question["kill_condition"].lower())
        self.assertNotIn("pre-curated", control_question["question"])
        self.assertNotIn("realistic control case", control_question["proof_obligation"].lower())

    def test_hacker_question_renderer_uses_tail_health_lesson_template(self) -> None:
        questions = self.tool.render_hacker_questions(
            ranked=[
                {
                    "attack_class": "liquidation-trigger-poison",
                    "evidence": [{"record_id": "tail-health-1"}],
                },
                {
                    "attack_class": "admin-bypass",
                    "evidence": [{"record_id": "admin-2"}],
                },
            ],
            function_name="withdrawFromSP",
            shape_hash="shape-tail",
            file_path="contracts/StabilityPool.sol",
            context_pack_id="ctx-tail",
            include_library=False,
            include_economic=False,
        )

        tail_question, control_question = questions
        self.assertIn("sorted-list tail", tail_question["question"])
        self.assertIn("live ICR", tail_question["question"])
        self.assertIn("live icr or health check", tail_question["proof_obligation"].lower())
        self.assertIn("sorted-list tail and live health check agree", tail_question["kill_condition"].lower())
        self.assertNotIn("sorted-list tail", control_question["question"])
        self.assertNotIn("live icr or health check", control_question["proof_obligation"].lower())

    def test_hacker_question_renderer_uses_adjacent_safe_callsite_template(self) -> None:
        questions = self.tool.render_hacker_questions(
            ranked=[
                {
                    "attack_class": "fix-not-applied-to-sibling",
                    "evidence": [{"record_id": "sibling-1"}],
                },
                {
                    "attack_class": "proof-of-life",
                    "evidence": [{"record_id": "proof-life-2"}],
                },
            ],
            function_name="redeemCollateral",
            shape_hash="shape-sibling",
            file_path="contracts/TroveManager.sol",
            context_pack_id="ctx-sibling",
            include_library=False,
            include_economic=False,
        )

        sibling_question, control_question = questions
        self.assertIn("nearby safe callsite", sibling_question["question"])
        self.assertIn("repairs the same invariant", sibling_question["proof_obligation"])
        self.assertIn("same guard is already applied", sibling_question["kill_condition"])
        self.assertNotIn("nearby safe callsite", control_question["question"])
        self.assertNotIn("repairs the same invariant", control_question["proof_obligation"])

    def test_hacker_question_renderer_does_not_overclassify_plain_withdrawal(self) -> None:
        questions = self.tool.render_hacker_questions(
            ranked=[
                {
                    "attack_class": "withdrawal-accounting-drift",
                    "evidence": [{"record_id": "withdrawal-1"}],
                }
            ],
            function_name="withdraw",
            shape_hash="shape-withdraw",
            file_path="contracts/Vault.sol",
            context_pack_id="ctx-withdraw",
            include_library=False,
            include_economic=False,
        )

        self.assertEqual(len(questions), 1)
        question = questions[0]
        self.assertEqual(question["proof_gate"], "source_confirmed")
        self.assertIn("Advisory hacker question only", question["claim_boundary"])
        self.assertNotIn("attestation", question["proof_obligation"].lower())
        self.assertNotIn("verifier", question["proof_obligation"].lower())

    def test_hacker_question_renderer_does_not_overclassify_plain_proof_or_quorum(self) -> None:
        questions = self.tool.render_hacker_questions(
            ranked=[
                {"attack_class": "proof-of-life", "evidence": [{"record_id": "proof-life"}]},
                {"attack_class": "governance-quorum-bypass", "evidence": [{"record_id": "quorum"}]},
            ],
            function_name="vote",
            shape_hash="shape-governance",
            file_path="contracts/Governor.sol",
            context_pack_id="ctx-gov",
            include_library=False,
            include_economic=False,
        )

        self.assertEqual([q["proof_gate"] for q in questions], ["source_confirmed", "source_confirmed"])
        self.assertTrue(all("Advisory hacker question only" in q["claim_boundary"] for q in questions))

    def test_hacker_question_renderer_does_not_overclassify_bridge_nonproof_classes(self) -> None:
        questions = self.tool.render_hacker_questions(
            ranked=[
                {"attack_class": "bridge-accounting-drift", "evidence": [{"record_id": "bridge-accounting"}]},
                {"attack_class": "portal-role-bypass", "evidence": [{"record_id": "portal-role"}]},
                {"attack_class": "cross-chain-message-replay", "evidence": [{"record_id": "crosschain-message"}]},
            ],
            function_name="handleMessage",
            shape_hash="shape-msg",
            file_path="contracts/BridgeRouter.sol",
            context_pack_id="ctx-msg",
            include_library=False,
            include_economic=False,
        )

        self.assertEqual([q["proof_gate"] for q in questions], ["source_confirmed"] * 3)
        self.assertTrue(all("Advisory hacker question only" in q["claim_boundary"] for q in questions))


class PreSourceReadObligationPersistenceTests(unittest.TestCase):
    """Lane 5: obligation persistence wired into pre-source-read-injector CLI."""

    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory(prefix="psri-obl-")
        self.ws = Path(self.tmp.name)
        self.tool = _load_tool()

    def tearDown(self) -> None:
        self.tmp.cleanup()

    def test_workspace_arg_persists_obligations(self) -> None:
        """--workspace causes injected questions to be written as open obligations."""
        if not FIXTURE_GO.exists():
            self.skipTest(f"fixture missing: {FIXTURE_GO}")
        obligations_path = self.ws / ".auditooor" / "hacker_question_obligations.jsonl"
        receipts_path = self.ws / ".auditooor" / "source_read_receipts.jsonl"
        self.assertFalse(obligations_path.exists(), "no obligations before inject")
        self.assertFalse(receipts_path.exists(), "no receipts before inject")

        _run_cli(
            str(FIXTURE_GO),
            "--target-repo", "dydxprotocol/v4-chain",
            "--top-n", "2",
            "--workspace", str(self.ws),
        )

        self.assertTrue(obligations_path.exists(), "obligations file must be created")
        self.assertTrue(receipts_path.exists(), "source-read receipts file must be created")
        lines = [
            l.strip()
            for l in obligations_path.read_text(encoding="utf-8").splitlines()
            if l.strip()
        ]
        self.assertGreater(len(lines), 0, "at least one obligation must be written")
        first = json.loads(lines[0])
        self.assertEqual(first["schema"], "auditooor.hacker_question_obligation.v1")
        self.assertEqual(first["state"], "open")
        receipts = [
            json.loads(l)
            for l in receipts_path.read_text(encoding="utf-8").splitlines()
            if l.strip()
        ]
        self.assertEqual(receipts[-1]["schema"], "auditooor.source_read_receipt.v1")
        self.assertGreaterEqual(receipts[-1]["functions_analyzed"], 1)
        self.assertGreater(receipts[-1]["hacker_question_count"], 0)
        self.assertIn("hacker_question_counts_by_source", receipts[-1])
        self.assertIn("corpus_backed_hypothesis_count", receipts[-1])

    def test_make_target_ws_persists_receipt_and_resolves_relative_source(self) -> None:
        """The Makefile wrapper must pass WS through to the receipt ledger."""
        source = self.ws / "src" / "Notes.md"
        source.parent.mkdir(parents=True, exist_ok=True)
        source.write_text("# fixture\n", encoding="utf-8")
        receipts_path = self.ws / ".auditooor" / "source_read_receipts.jsonl"

        proc = subprocess.run(
            [
                "make",
                "pre-source-read-inject",
                f"WS={self.ws}",
                "SOURCE=src/Notes.md",
                "JSON=1",
            ],
            cwd=REPO_ROOT,
            capture_output=True,
            text=True,
            timeout=60,
        )

        self.assertEqual(
            proc.returncode,
            0,
            f"make pre-source-read-inject failed\nstdout:\n{proc.stdout}\nstderr:\n{proc.stderr}",
        )
        data = json.loads(proc.stdout)
        self.assertEqual(data["functions_analyzed"], 0)
        self.assertEqual(data["absolute_file_path"], str(source.resolve()))
        self.assertTrue(receipts_path.exists(), "Makefile target must create source-read receipt")
        receipts = [
            json.loads(l)
            for l in receipts_path.read_text(encoding="utf-8").splitlines()
            if l.strip()
        ]
        self.assertEqual(receipts[-1]["schema"], "auditooor.source_read_receipt.v1")
        self.assertEqual(receipts[-1]["workspace"], str(self.ws))
        self.assertEqual(receipts[-1]["absolute_file_path"], str(source.resolve()))
        self.assertEqual(receipts[-1]["hacker_question_count"], 0)
        self.assertIn("unsupported-extension", receipts[-1]["no_questions_reason"])

    def test_make_target_workspace_alias_persists_receipt(self) -> None:
        """WORKSPACE remains supported for callers that have not moved to WS."""
        source = self.ws / "src" / "Other.md"
        source.parent.mkdir(parents=True, exist_ok=True)
        source.write_text("# fixture\n", encoding="utf-8")
        receipts_path = self.ws / ".auditooor" / "source_read_receipts.jsonl"

        proc = subprocess.run(
            [
                "make",
                "pre-source-read-inject",
                f"WORKSPACE={self.ws}",
                "SOURCE=src/Other.md",
                "JSON=1",
            ],
            cwd=REPO_ROOT,
            capture_output=True,
            text=True,
            timeout=60,
        )

        self.assertEqual(
            proc.returncode,
            0,
            f"make pre-source-read-inject failed\nstdout:\n{proc.stdout}\nstderr:\n{proc.stderr}",
        )
        self.assertTrue(receipts_path.exists(), "WORKSPACE alias must create source-read receipt")
        receipts = [
            json.loads(l)
            for l in receipts_path.read_text(encoding="utf-8").splitlines()
            if l.strip()
        ]
        self.assertEqual(receipts[-1]["workspace"], str(self.ws))
        self.assertEqual(receipts[-1]["absolute_file_path"], str(source.resolve()))

    def test_no_workspace_no_obligations_file(self) -> None:
        """Without --workspace, no obligations file is created."""
        if not FIXTURE_GO.exists():
            self.skipTest(f"fixture missing: {FIXTURE_GO}")
        _run_cli(
            str(FIXTURE_GO),
            "--target-repo", "dydxprotocol/v4-chain",
            "--top-n", "2",
        )
        obligations_path = self.ws / ".auditooor" / "hacker_question_obligations.jsonl"
        receipts_path = self.ws / ".auditooor" / "source_read_receipts.jsonl"
        self.assertFalse(obligations_path.exists(), "no workspace -> no obligations")
        self.assertFalse(receipts_path.exists(), "no workspace -> no receipts")

    def test_strict_persistence_fails_when_receipt_cannot_be_written(self) -> None:
        """--strict-persistence turns receipt persistence failures into rc=1."""
        workspace_file = self.ws / "not-a-directory"
        workspace_file.write_text("not a workspace directory\n", encoding="utf-8")

        proc = subprocess.run(
            [
                sys.executable,
                str(TOOL_PATH),
                str(FIXTURE_GO),
                "--target-repo",
                "dydxprotocol/v4-chain",
                "--top-n",
                "1",
                "--workspace",
                str(workspace_file),
                "--strict-persistence",
            ],
            cwd=REPO_ROOT,
            capture_output=True,
            text=True,
            timeout=60,
        )

        self.assertNotEqual(proc.returncode, 0, proc.stderr)
        self.assertIn("WARN receipt persistence failed", proc.stderr)
        self.assertIn("auditooor.pre_source_read_injection.v1", proc.stdout)

    def test_strict_env_alias_fails_without_workspace(self) -> None:
        """AUDITOOOR_PRE_SOURCE_READ_STRICT enforces persistence, including workspace presence."""
        env = os.environ.copy()
        env["AUDITOOOR_PRE_SOURCE_READ_STRICT"] = "1"

        proc = subprocess.run(
            [
                sys.executable,
                str(TOOL_PATH),
                str(FIXTURE_GO),
                "--target-repo",
                "dydxprotocol/v4-chain",
                "--top-n",
                "1",
            ],
            cwd=REPO_ROOT,
            env=env,
            capture_output=True,
            text=True,
            timeout=60,
        )

        self.assertNotEqual(proc.returncode, 0, proc.stderr)
        self.assertIn("strict persistence requested but no workspace", proc.stderr)
        self.assertIn("auditooor.pre_source_read_injection.v1", proc.stdout)

    def test_wrapper_forwards_strict_persistence_to_injector(self) -> None:
        """The pre-source-read shell wrapper must enforce strict persistence."""
        workspace_file = self.ws / "not-a-directory"
        workspace_file.write_text("not a workspace directory\n", encoding="utf-8")
        env = os.environ.copy()
        env["AUDITOOOR_PRE_SOURCE_READ_STRICT_PERSISTENCE"] = "1"
        env["TARGET_REPO"] = "dydxprotocol/v4-chain"

        proc = subprocess.run(
            ["bash", str(WRAPPER_PATH), str(FIXTURE_GO), str(workspace_file)],
            cwd=REPO_ROOT,
            env=env,
            capture_output=True,
            text=True,
            timeout=60,
        )

        self.assertEqual(proc.returncode, 1, proc.stderr)
        self.assertIn("WARN receipt persistence failed", proc.stderr)

    def test_wrapper_forwards_strict_alias_to_injector(self) -> None:
        """AUDITOOOR_PRE_SOURCE_READ_STRICT is the operator-facing strict alias."""
        workspace_file = self.ws / "not-a-directory"
        workspace_file.write_text("not a workspace directory\n", encoding="utf-8")
        env = os.environ.copy()
        env["AUDITOOOR_PRE_SOURCE_READ_STRICT"] = "1"
        env["TARGET_REPO"] = "dydxprotocol/v4-chain"

        proc = subprocess.run(
            ["bash", str(WRAPPER_PATH), str(FIXTURE_GO), str(workspace_file)],
            cwd=REPO_ROOT,
            env=env,
            capture_output=True,
            text=True,
            timeout=60,
        )

        self.assertEqual(proc.returncode, 1, proc.stderr)
        self.assertIn("WARN receipt persistence failed", proc.stderr)

    def test_make_target_strict_fails_when_workspace_is_invalid(self) -> None:
        workspace_file = self.ws / "not-a-directory"
        workspace_file.write_text("not a workspace directory\n", encoding="utf-8")

        proc = subprocess.run(
            [
                "make",
                "pre-source-read-inject",
                f"WS={workspace_file}",
                f"SOURCE={FIXTURE_GO}",
                "STRICT=1",
                "JSON=1",
            ],
            cwd=REPO_ROOT,
            capture_output=True,
            text=True,
            timeout=60,
        )

        self.assertNotEqual(proc.returncode, 0, proc.stderr)
        self.assertIn("WARN receipt persistence failed", proc.stderr)
        self.assertIn("auditooor.pre_source_read_injection.v1", proc.stdout)

    def test_re_inject_is_idempotent(self) -> None:
        """Injecting the same file twice does not duplicate any obligation.

        The ranker may produce slightly different attack classes across runs
        (cache warm-up, ordering variance), so total count is not compared.
        The invariant is: no obligation_id appears more than once, and no
        (file, function_name, question) triple appears more than once.
        """
        if not FIXTURE_GO.exists():
            self.skipTest(f"fixture missing: {FIXTURE_GO}")
        # Inject twice
        for _ in range(2):
            _run_cli(
                str(FIXTURE_GO),
                "--target-repo", "dydxprotocol/v4-chain",
                "--top-n", "2",
                "--workspace", str(self.ws),
            )
        obligations_path = self.ws / ".auditooor" / "hacker_question_obligations.jsonl"
        lines = [
            l.strip()
            for l in obligations_path.read_text(encoding="utf-8").splitlines()
            if l.strip()
        ]
        rows = [json.loads(l) for l in lines]
        # No duplicate obligation_ids
        ids = [r["obligation_id"] for r in rows]
        self.assertEqual(len(ids), len(set(ids)), "duplicate obligation_ids found after double-inject")
        # No duplicate (file, function_name, question) triples
        triples = [(r["file"], r["function_name"], r["question"]) for r in rows]
        self.assertEqual(len(triples), len(set(triples)), "duplicate (file,fn,question) triples found")

    def test_persist_obligations_helper_silently_nops_on_absent_tool(self) -> None:
        """_persist_obligations must not raise if obligations tool is absent."""
        payload = {
            "schema": "auditooor.pre_source_read_injection.v1",
            "context_pack_id": "",
            "file_path": "src/Foo.sol",
            "functions_analyzed": 1,
            "functions": [
                {
                    "name": "foo",
                    "line": 1,
                    "shape_hash": "abc",
                    "shape_hash_fine": "abcfine",
                    "top_attack_classes": [],
                    "hacker_questions": [
                        {
                            "schema": "auditooor.hacker_question.v1",
                            "question": "Test question?",
                            "question_source": "corpus-derived",
                            "attack_class": "reentrancy",
                        }
                    ],
                }
            ],
        }
        # Should not raise even with a bogus workspace
        try:
            self.tool._persist_obligations("/nonexistent/path/ws", payload)
        except Exception as exc:
            self.fail(f"_persist_obligations raised unexpectedly: {exc}")


if __name__ == "__main__":
    unittest.main()
