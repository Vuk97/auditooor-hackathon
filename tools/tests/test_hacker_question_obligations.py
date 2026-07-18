"""Tests for tools/hacker-question-obligations.py (Lane 5)."""
from __future__ import annotations

import argparse
import contextlib
import hashlib
import importlib.util
import io
import json
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
TOOL = ROOT / "tools" / "hacker-question-obligations.py"
EXPLOIT_QUEUE_TOOL = ROOT / "tools" / "exploit-queue.py"


def _load_tool():
    spec = importlib.util.spec_from_file_location("_hq_obl_test", str(TOOL))
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot load {TOOL}")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def _load_eq_tool():
    spec = importlib.util.spec_from_file_location("_eq_test", str(EXPLOIT_QUEUE_TOOL))
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot load {EXPLOIT_QUEUE_TOOL}")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def _make_minimal_injection_payload(file_path: str = "src/Foo.sol") -> dict:
    """Minimal pre-source-read injection payload with 1 function / 2 questions."""
    return {
        "schema": "auditooor.pre_source_read_injection.v1",
        "context_pack_id": "test-pack-001",
        "file_path": file_path,
        "absolute_file_path": f"/tmp/{file_path}",
        "target_repo": "test/repo",
        "language": "solidity",
        "functions_analyzed": 1,
        "functions": [
            {
                "name": "withdraw",
                "line": 42,
                "shape_hash": "abc123",
                "shape_hash_fine": "abc123fine",
                "function_signature": "function withdraw(uint256 amount) external",
                "top_attack_classes": [
                    {"class_id": "reentrancy", "score": 0.85, "confidence": 0.72},
                    {"class_id": "accounting-drift", "score": 0.60, "confidence": 0.55},
                ],
                "hacker_questions": [
                    {
                        "schema": "auditooor.hacker_question.v1",
                        "question": "Can withdraw make an external call before all accounting is finalized?",
                        "question_source": "corpus-derived",
                        "attack_class": "reentrancy",
                        "source_record_id": "record-001",
                        "proof_gate": "source_confirmed",
                        "claim_boundary": "Advisory hacker question only.",
                        "proof_obligation": "Prove re-entry.",
                        "kill_condition": "Kill if guarded.",
                        "function_shape": "abc123",
                        "function_shape_fine": "abc123fine",
                        "target_file": file_path,
                        "mcp_context_pack_id": "test-pack-001",
                    },
                    {
                        "schema": "auditooor.hacker_question.v1",
                        "question": "Can accounting balances drift before state update?",
                        "question_source": "curated-library",
                        "shape_class": "withdrawal-redemption-fn",
                        "attack_class": "",
                        "reasoning_axis": "accounting",
                        "rationale": "Accounting drift risk.",
                        "proof_gate": "source_confirmed",
                        "claim_boundary": "Advisory hacker question only.",
                        "proof_obligation": "Answer accounting question.",
                        "kill_condition": "Kill if no drift.",
                        "function_shape": "abc123",
                        "target_file": file_path,
                        "mcp_context_pack_id": "test-pack-001",
                    },
                ],
                "corpus_backed_hypotheses": [],
            }
        ],
        "skipped_reasons": [],
        "generated_at_utc": "2026-05-19T00:00:00Z",
        "advisory_disclaimer": "Advisory only.",
        "performance_budget_note": "Budget note.",
    }


class TestObligationAppendDedup(unittest.TestCase):
    """append_obligations: idempotent append and deduplication."""

    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory(prefix="obl-test-")
        self.ws = Path(self.tmp.name)
        self.tool = _load_tool()

    def tearDown(self) -> None:
        self.tmp.cleanup()

    def test_append_creates_file(self) -> None:
        ob = self.tool.make_obligation(
            workspace=str(self.ws),
            file="src/Foo.sol",
            function_signature="function withdraw(uint256) external",
            function_name="withdraw",
            attack_class="reentrancy",
            question="Can attacker re-enter?",
        )
        result = self.tool.append_obligations(self.ws, [ob])
        self.assertEqual(result["appended"], 1)
        self.assertEqual(result["skipped_duplicate"], 0)
        p = self.ws / ".auditooor" / "hacker_question_obligations.jsonl"
        self.assertTrue(p.exists(), "obligations file not created")

    def test_append_dedup_by_id(self) -> None:
        ob = self.tool.make_obligation(
            workspace=str(self.ws),
            file="src/Foo.sol",
            function_signature="function withdraw(uint256) external",
            function_name="withdraw",
            attack_class="reentrancy",
            question="Can attacker re-enter?",
        )
        # First append
        r1 = self.tool.append_obligations(self.ws, [ob])
        self.assertEqual(r1["appended"], 1)
        # Second append of same obligation -> dedup
        r2 = self.tool.append_obligations(self.ws, [ob])
        self.assertEqual(r2["appended"], 0)
        self.assertEqual(r2["skipped_duplicate"], 1)
        # Only 1 row on disk
        rows = self.tool.load_obligations(self.ws)
        self.assertEqual(len(rows), 1)

    def test_duplicate_append_enriches_missing_context_without_state_reset(self) -> None:
        ob = self.tool.make_obligation(
            workspace=str(self.ws),
            file="src/Foo.sol",
            function_signature="function withdraw(uint256) external",
            function_name="withdraw",
            attack_class="",
            question="Can attacker re-enter?",
            source_refs=["record-a"],
        )
        self.tool.append_obligations(self.ws, [ob])
        self.tool.update_obligation(self.ws, ob["obligation_id"], state="answered")

        richer = dict(ob)
        richer.update(
            {
                "attack_class": "reentrancy",
                "proof_gate": "source_confirmed",
                "proof_obligation": "Prove reachable external callback.",
                "source_refs": ["record-a", "record-b"],
                "extra_metadata": {"provider": "mined-bridge"},
                "state": "open",
            }
        )
        result = self.tool.append_obligations(self.ws, [richer])

        self.assertEqual(result["appended"], 0)
        self.assertEqual(result["skipped_duplicate"], 1)
        self.assertEqual(result["merged_duplicate"], 1)
        rows = self.tool.load_obligations(self.ws)
        self.assertEqual(len(rows), 1)
        row = rows[0]
        self.assertEqual(row["state"], "answered")
        self.assertEqual(row["attack_class"], "reentrancy")
        self.assertEqual(row["proof_gate"], "source_confirmed")
        self.assertEqual(row["proof_obligation"], "Prove reachable external callback.")
        self.assertEqual(row["source_refs"], ["record-a", "record-b"])
        self.assertEqual(row["extra_metadata"], {"provider": "mined-bridge"})

    def test_different_questions_same_function_are_distinct(self) -> None:
        def _make(q: str) -> dict:
            return self.tool.make_obligation(
                workspace=str(self.ws),
                file="src/Foo.sol",
                function_signature="function withdraw(uint256) external",
                function_name="withdraw",
                attack_class="reentrancy",
                question=q,
            )

        r = self.tool.append_obligations(self.ws, [_make("Q1"), _make("Q2")])
        self.assertEqual(r["appended"], 2)
        rows = self.tool.load_obligations(self.ws)
        self.assertEqual(len(rows), 2)

    def test_schema_field_correct(self) -> None:
        ob = self.tool.make_obligation(
            workspace=str(self.ws),
            file="src/Foo.sol",
            function_signature="function foo()",
            function_name="foo",
            attack_class="admin-bypass",
            question="Is admin check missing?",
        )
        self.assertEqual(ob["schema"], "auditooor.hacker_question_obligation.v1")

    def test_obligation_id_is_deterministic(self) -> None:
        ob1 = self.tool.make_obligation(
            workspace=str(self.ws),
            file="src/Foo.sol",
            function_signature="function foo()",
            function_name="foo",
            attack_class="admin-bypass",
            question="Same question.",
        )
        ob2 = self.tool.make_obligation(
            workspace=str(self.ws),
            file="src/Foo.sol",
            function_signature="function foo()",
            function_name="foo",
            attack_class="admin-bypass",
            question="Same question.",
        )
        self.assertEqual(ob1["obligation_id"], ob2["obligation_id"])

    def test_cli_append_preserves_supported_and_extra_metadata(self) -> None:
        payload = {
            "schema": "caller.schema",
            "obligation_id": "caller-id-must-not-win",
            "workspace": "/caller/workspace",
            "file": "src/Foo.sol",
            "function_signature": "function withdraw(uint256) external",
            "function_name": "withdraw",
            "attack_class": "reentrancy",
            "question": "Can attacker re-enter?",
            "question_source": "corpus-derived",
            "corpus_provenance": "record-001",
            "source_refs": ["record-001"],
            "local_verification_cmd": "forge test --match-test testReenter",
            "operator_notes": "caller note",
            "context_pack_id": "pack-001",
            "proof_gate": "source_confirmed",
            "claim_boundary": "Advisory only.",
            "proof_obligation": "Prove re-entry reaches production state.",
            "kill_condition": "Kill if accounting precedes external call.",
            "function_shape": "shape-coarse",
            "function_shape_fine": "shape-fine",
            "reasoning_axis": "state-ordering",
            "rationale": "External call before effects is risky.",
            "economic_primitive": "withdrawal",
            "economic_category": "vault",
            "profit_source": "drained funds",
            "incident_anchor": "incident-001",
            "extra_metadata": {"provider": "prebuilt"},
        }
        args = argparse.Namespace(
            workspace=str(self.ws),
            payload_json=json.dumps(payload),
            json=True,
        )

        with contextlib.redirect_stdout(io.StringIO()):
            rc = self.tool._cmd_append(args)

        self.assertEqual(rc, 0)
        rows = self.tool.load_obligations(self.ws)
        self.assertEqual(len(rows), 1)
        row = rows[0]
        self.assertEqual(row["schema"], "auditooor.hacker_question_obligation.v1")
        self.assertNotEqual(row["obligation_id"], "caller-id-must-not-win")
        self.assertEqual(row["workspace"], str(self.ws.resolve()))
        self.assertEqual(row["proof_gate"], "source_confirmed")
        self.assertEqual(row["claim_boundary"], "Advisory only.")
        self.assertEqual(row["proof_obligation"], "Prove re-entry reaches production state.")
        self.assertEqual(row["kill_condition"], "Kill if accounting precedes external call.")
        self.assertEqual(row["function_shape"], "shape-coarse")
        self.assertEqual(row["function_shape_fine"], "shape-fine")
        self.assertEqual(row["reasoning_axis"], "state-ordering")
        self.assertEqual(row["rationale"], "External call before effects is risky.")
        self.assertEqual(row["economic_primitive"], "withdrawal")
        self.assertEqual(row["economic_category"], "vault")
        self.assertEqual(row["profit_source"], "drained funds")
        self.assertEqual(row["incident_anchor"], "incident-001")
        self.assertEqual(row["extra_metadata"], {"provider": "prebuilt"})


class TestObligationStateTransitions(unittest.TestCase):
    """update_obligation: state transitions."""

    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory(prefix="obl-state-")
        self.ws = Path(self.tmp.name)
        self.tool = _load_tool()
        # Seed one obligation
        ob = self.tool.make_obligation(
            workspace=str(self.ws),
            file="src/Bar.sol",
            function_signature="function transfer(address, uint256) external",
            function_name="transfer",
            attack_class="accounting-drift",
            question="Can accounting drift?",
        )
        self.tool.append_obligations(self.ws, [ob])
        self.obligation_id = ob["obligation_id"]

    def tearDown(self) -> None:
        self.tmp.cleanup()

    def test_transition_open_to_answered(self) -> None:
        found = self.tool.update_obligation(
            self.ws, self.obligation_id, state="answered", operator_notes="Checked; no drift."
        )
        self.assertTrue(found)
        rows = self.tool.query_obligations(self.ws, state="answered")
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["operator_notes"], "Checked; no drift.")

    def test_transition_to_killed(self) -> None:
        self.tool.update_obligation(self.ws, self.obligation_id, state="killed")
        rows = self.tool.query_obligations(self.ws, state="killed")
        self.assertEqual(len(rows), 1)

    def test_transition_to_promoted_to_chain(self) -> None:
        self.tool.update_obligation(self.ws, self.obligation_id, state="promoted_to_chain")
        rows = self.tool.query_obligations(self.ws, state="promoted_to_chain")
        self.assertEqual(len(rows), 1)

    def test_transition_to_promoted_to_poc(self) -> None:
        self.tool.update_obligation(self.ws, self.obligation_id, state="promoted_to_poc")
        rows = self.tool.query_obligations(self.ws, state="promoted_to_poc")
        self.assertEqual(len(rows), 1)

    def test_invalid_state_raises(self) -> None:
        with self.assertRaises(ValueError):
            self.tool.update_obligation(
                self.ws, self.obligation_id, state="bogus_state"
            )

    def test_update_missing_id_returns_false(self) -> None:
        found = self.tool.update_obligation(
            self.ws, "nonexistent-id-xyz", state="killed"
        )
        self.assertFalse(found)

    def test_open_not_overwritten_by_re_append(self) -> None:
        # Transition to answered
        self.tool.update_obligation(self.ws, self.obligation_id, state="answered")
        # Re-append same obligation (simulating re-injection)
        ob = self.tool.make_obligation(
            workspace=str(self.ws),
            file="src/Bar.sol",
            function_signature="function transfer(address, uint256) external",
            function_name="transfer",
            attack_class="accounting-drift",
            question="Can accounting drift?",
        )
        r = self.tool.append_obligations(self.ws, [ob])
        self.assertEqual(r["skipped_duplicate"], 1)
        # State should still be answered (dedup preserves existing row)
        rows = self.tool.query_obligations(self.ws, state="answered")
        self.assertEqual(len(rows), 1)


class TestIngestInjectionPayload(unittest.TestCase):
    """ingest_injection_payload: parse injection JSON and append obligations."""

    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory(prefix="obl-ingest-")
        self.ws = Path(self.tmp.name)
        self.tool = _load_tool()

    def tearDown(self) -> None:
        self.tmp.cleanup()

    def test_ingest_appends_questions(self) -> None:
        payload = _make_minimal_injection_payload("src/Foo.sol")
        result = self.tool.ingest_injection_payload(self.ws, payload)
        # 2 questions from the 1 function
        self.assertEqual(result["appended"], 2)
        self.assertEqual(result["skipped_duplicate"], 0)

    def test_ingest_idempotent(self) -> None:
        payload = _make_minimal_injection_payload("src/Foo.sol")
        self.tool.ingest_injection_payload(self.ws, payload)
        # Second ingest of same payload -> all duplicates
        r2 = self.tool.ingest_injection_payload(self.ws, payload)
        self.assertEqual(r2["appended"], 0)
        self.assertEqual(r2["skipped_duplicate"], 2)

    def test_ingested_obligations_are_open(self) -> None:
        payload = _make_minimal_injection_payload("src/Foo.sol")
        self.tool.ingest_injection_payload(self.ws, payload)
        rows = self.tool.query_obligations(self.ws, state="open")
        self.assertEqual(len(rows), 2)

    def test_ingested_fields_populated(self) -> None:
        payload = _make_minimal_injection_payload("src/Foo.sol")
        self.tool.ingest_injection_payload(self.ws, payload)
        rows = self.tool.load_obligations(self.ws)
        corpus_derived = [r for r in rows if r.get("question_source") == "corpus-derived"]
        self.assertEqual(len(corpus_derived), 1)
        ob = corpus_derived[0]
        self.assertEqual(ob["attack_class"], "reentrancy")
        self.assertEqual(ob["function_name"], "withdraw")
        self.assertEqual(ob["file"], "src/Foo.sol")
        self.assertEqual(ob["context_pack_id"], "test-pack-001")
        self.assertEqual(ob["corpus_provenance"], "record-001")
        self.assertEqual(ob["proof_gate"], "source_confirmed")
        self.assertEqual(ob["proof_obligation"], "Prove re-entry.")
        self.assertEqual(ob["kill_condition"], "Kill if guarded.")
        self.assertEqual(ob["function_shape"], "abc123")
        self.assertEqual(ob["function_shape_fine"], "abc123fine")

    def test_empty_injection_payload_no_obligations(self) -> None:
        payload = {
            "schema": "auditooor.pre_source_read_injection.v1",
            "context_pack_id": "",
            "file_path": "src/Empty.sol",
            "functions_analyzed": 0,
            "functions": [],
            "skipped_reasons": ["file-not-found"],
        }
        result = self.tool.ingest_injection_payload(self.ws, payload)
        self.assertEqual(result["appended"], 0)

    def test_ingest_curated_library_question_uses_shape_class_as_provenance(self) -> None:
        payload = _make_minimal_injection_payload("src/Foo.sol")
        self.tool.ingest_injection_payload(self.ws, payload)
        rows = self.tool.load_obligations(self.ws)
        lib_rows = [r for r in rows if r.get("question_source") == "curated-library"]
        self.assertEqual(len(lib_rows), 1)
        self.assertEqual(lib_rows[0]["corpus_provenance"], "withdrawal-redemption-fn")
        self.assertEqual(lib_rows[0]["attack_class"], "withdrawal-redemption-fn")
        self.assertEqual(lib_rows[0]["proof_obligation"], "Answer accounting question.")


class TestQueryObligations(unittest.TestCase):
    """query_obligations: filter by state / attack_class / file."""

    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory(prefix="obl-query-")
        self.ws = Path(self.tmp.name)
        self.tool = _load_tool()
        # Seed two obligations in different states
        obs = [
            self.tool.make_obligation(
                workspace=str(self.ws), file="src/A.sol",
                function_signature="function foo()", function_name="foo",
                attack_class="reentrancy", question="Q1", state="open",
            ),
            self.tool.make_obligation(
                workspace=str(self.ws), file="src/B.sol",
                function_signature="function bar()", function_name="bar",
                attack_class="oracle-manipulation", question="Q2", state="open",
            ),
        ]
        self.tool.append_obligations(self.ws, obs)
        # Transition one to killed
        self.tool.update_obligation(self.ws, obs[1]["obligation_id"], state="killed")

    def tearDown(self) -> None:
        self.tmp.cleanup()

    def test_query_all_returns_both(self) -> None:
        rows = self.tool.query_obligations(self.ws)
        self.assertEqual(len(rows), 2)

    def test_query_open_returns_one(self) -> None:
        rows = self.tool.query_obligations(self.ws, state="open")
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["function_name"], "foo")

    def test_query_killed_returns_one(self) -> None:
        rows = self.tool.query_obligations(self.ws, state="killed")
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["function_name"], "bar")

    def test_query_by_attack_class(self) -> None:
        rows = self.tool.query_obligations(self.ws, attack_class="reentrancy")
        self.assertEqual(len(rows), 1)

    def test_query_by_file(self) -> None:
        rows = self.tool.query_obligations(self.ws, file="src/A.sol")
        self.assertEqual(len(rows), 1)


class TestGracefulAbsence(unittest.TestCase):
    """All operations graceful when file is absent."""

    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory(prefix="obl-absent-")
        self.ws = Path(self.tmp.name)
        self.tool = _load_tool()

    def tearDown(self) -> None:
        self.tmp.cleanup()

    def test_load_absent_returns_empty(self) -> None:
        rows = self.tool.load_obligations(self.ws)
        self.assertEqual(rows, [])

    def test_query_absent_returns_empty(self) -> None:
        rows = self.tool.query_obligations(self.ws, state="open")
        self.assertEqual(rows, [])

    def test_update_absent_returns_false(self) -> None:
        found = self.tool.update_obligation(self.ws, "nonexistent", state="killed")
        self.assertFalse(found)

    def test_gather_queue_rows_absent_returns_empty(self) -> None:
        rows = self.tool.gather_open_obligations_as_queue_rows(self.ws)
        self.assertEqual(rows, [])


class TestExploitQueueObligationsIngest(unittest.TestCase):
    """exploit-queue.py ingest of open obligations (Lane 5)."""

    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory(prefix="eq-obl-test-")
        self.ws = Path(self.tmp.name)
        self.obl_tool = _load_tool()
        self.eq_tool = _load_eq_tool()

    def tearDown(self) -> None:
        self.tmp.cleanup()

    def test_no_obligations_file_graceful(self) -> None:
        """exploit-queue runs cleanly when no obligations file exists."""
        result = self.eq_tool.run(["--workspace", str(self.ws)])
        self.assertEqual(result["schema"], "auditooor.exploit_queue.v1")
        self.assertIsInstance(result["queue"], list)

    def test_open_obligations_appear_in_queue(self) -> None:
        """Open obligations are ingested as queue rows."""
        ob = self.obl_tool.make_obligation(
            workspace=str(self.ws),
            file="src/Vault.sol",
            function_signature="function redeem(uint256) external",
            function_name="redeem",
            attack_class="first-depositor-inflation",
            question="Can first depositor inflate share price?",
        )
        self.obl_tool.append_obligations(self.ws, [ob])

        result = self.eq_tool.run(["--workspace", str(self.ws)])
        self.assertGreater(result["total_candidates"], 0)
        # Obligations source should be listed
        self.assertIn("hacker_question_obligations", result["source_artifacts_consumed"])
        # The queue row should reference the obligation
        queue_rows = result["queue"]
        obl_rows = [r for r in queue_rows if "obligation:" in str(r.get("source_refs", []))]
        self.assertGreater(len(obl_rows), 0, "expected obligation-sourced rows in queue")

    def test_killed_obligations_not_ingested(self) -> None:
        """Killed obligations should not appear in the exploit queue."""
        ob = self.obl_tool.make_obligation(
            workspace=str(self.ws),
            file="src/X.sol",
            function_signature="function foo()",
            function_name="foo",
            attack_class="admin-bypass",
            question="Is admin check missing?",
        )
        self.obl_tool.append_obligations(self.ws, [ob])
        self.obl_tool.update_obligation(self.ws, ob["obligation_id"], state="killed")

        result = self.eq_tool.run(["--workspace", str(self.ws)])
        queue_rows = result["queue"]
        obl_rows = [r for r in queue_rows if "obligation:" in str(r.get("source_refs", []))]
        self.assertEqual(len(obl_rows), 0, "killed obligations must not appear in queue")

    def test_queue_key_not_renamed(self) -> None:
        """Constraint: top-level 'queue' key must not be renamed."""
        result = self.eq_tool.run(["--workspace", str(self.ws)])
        self.assertIn("queue", result)

    def test_schema_preserved(self) -> None:
        result = self.eq_tool.run(["--workspace", str(self.ws)])
        self.assertEqual(result["schema"], "auditooor.exploit_queue.v1")


class TestGateDraft(unittest.TestCase):
    """gate-draft blocks High/Critical filing when matching questions are open."""

    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory(prefix="obl-gate-draft-")
        self.ws = Path(self.tmp.name)
        self.tool = _load_tool()

    def tearDown(self) -> None:
        self.tmp.cleanup()

    def _seed(self, **overrides) -> dict:
        ob = self.tool.make_obligation(
            workspace=str(self.ws),
            file=overrides.get("file", "src/Vault.sol"),
            function_signature=overrides.get(
                "function_signature",
                "function withdraw(uint256 amount) external",
            ),
            function_name=overrides.get("function_name", "withdraw"),
            attack_class=overrides.get("attack_class", "reentrancy"),
            question=overrides.get(
                "question",
                "Can withdraw re-enter before accounting is finalized?",
            ),
            state=overrides.get("state", "open"),
        )
        self.tool.append_obligations(self.ws, [ob])
        return ob

    def test_gate_draft_fails_on_open_file_and_function_match(self) -> None:
        self._seed()
        draft = self.ws / "draft.md"
        draft.write_text(
            "Root cause in src/Vault.sol: withdraw can re-enter.",
            encoding="utf-8",
        )

        result = self.tool.gate_draft_obligations(self.ws, draft)

        self.assertEqual(result["status"], "fail")
        self.assertEqual(result["counts"]["blocking"], 1)
        self.assertIn(
            "file_and_function_name",
            result["blocking_obligations"][0]["match_reasons"],
        )

    def test_gate_draft_fails_on_explicit_obligation_id(self) -> None:
        ob = self._seed()
        draft = self.ws / "draft.md"
        draft.write_text(f"Tracked as obligation:{ob['obligation_id']}.", encoding="utf-8")

        result = self.tool.gate_draft_obligations(self.ws, draft)

        self.assertEqual(result["status"], "fail")
        self.assertIn(
            "obligation_id",
            result["blocking_obligations"][0]["match_reasons"],
        )

    def test_gate_draft_fails_on_function_signature_match(self) -> None:
        self._seed()
        draft = self.ws / "draft.md"
        draft.write_text(
            "The path reaches function withdraw(uint256 amount) external.",
            encoding="utf-8",
        )

        result = self.tool.gate_draft_obligations(self.ws, draft)

        self.assertEqual(result["status"], "fail")
        self.assertIn(
            "function_signature",
            result["blocking_obligations"][0]["match_reasons"],
        )

    def test_gate_draft_ignores_non_open_matching_obligation(self) -> None:
        for state in ("answered", "killed", "promoted_to_chain", "promoted_to_poc"):
            with self.subTest(state=state):
                self.tmp.cleanup()
                self.tmp = tempfile.TemporaryDirectory(prefix="obl-gate-draft-")
                self.ws = Path(self.tmp.name)
                self._seed(state=state)
                draft = self.ws / "draft.md"
                draft.write_text("src/Vault.sol withdraw", encoding="utf-8")

                result = self.tool.gate_draft_obligations(self.ws, draft)

                self.assertEqual(result["status"], "pass", result)

    def test_gate_draft_does_not_block_unmatched_open_obligation(self) -> None:
        self._seed(file="src/A.sol", function_name="redeem")
        draft = self.ws / "draft.md"
        draft.write_text("Finding is about src/B.sol withdraw.", encoding="utf-8")

        result = self.tool.gate_draft_obligations(self.ws, draft)

        self.assertEqual(result["status"], "pass")

    def test_gate_draft_missing_draft_is_error(self) -> None:
        result = self.tool.gate_draft_obligations(self.ws, self.ws / "missing.md")

        self.assertEqual(result["status"], "error")
        self.assertEqual(result["counts"]["blocking"], 0)

    def test_matching_open_obligations_can_use_changed_artifact_path(self) -> None:
        self._seed()
        matches = self.tool.matching_open_obligations_for_text(
            self.ws,
            "withdraw has a reachable external-call path.",
            changed_artifacts=["src/Vault.sol"],
        )

        self.assertEqual(len(matches), 1)
        self.assertIn("file_and_function_name", matches[0]["match_reasons"])


class TestSourceReadReceiptGate(unittest.TestCase):
    """Strict source-read receipt helper for High/Critical pre-submit mode."""

    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory(prefix="source-read-receipt-")
        self.ws = Path(self.tmp.name)
        self.tool = _load_tool()

    def tearDown(self) -> None:
        self.tmp.cleanup()

    def _draft(self, text: str) -> Path:
        draft = self.ws / "draft.md"
        draft.write_text(text, encoding="utf-8")
        return draft

    def test_gate_passes_when_cited_source_has_source_read_receipt(self) -> None:
        self.tool.record_source_read_receipt(
            self.ws,
            {
                "schema": "auditooor.pre_source_read_injection.v1",
                "file_path": "src/Vault.sol",
                "absolute_file_path": str(self.ws / "src" / "Vault.sol"),
                "target_repo": "test/repo",
                "language": "solidity",
                "functions_analyzed": 1,
                "functions": [{"name": "withdraw"}],
                "context_pack_id": "ctx-1",
            },
        )
        draft = self._draft("Root cause is in `src/Vault.sol`.")

        result = self.tool.gate_draft_source_read_receipts(self.ws, draft)

        self.assertEqual(result["status"], "pass", result)
        self.assertEqual(result["counts"]["with_receipts"], 1)
        self.assertEqual(
            result["cited_source_files"][0]["receipt"]["kind"],
            "source_read_receipt",
        )
        self.assertEqual(
            result["cited_source_files"][0]["receipt"]["hash_status"],
            "missing_legacy_hash",
        )

    def test_source_read_receipt_records_hash_metadata_when_source_exists(self) -> None:
        source = self.ws / "src" / "Vault.sol"
        source.parent.mkdir(parents=True)
        source.write_text("contract Vault {}\n", encoding="utf-8")

        receipt = self.tool.record_source_read_receipt(
            self.ws,
            {
                "schema": "auditooor.pre_source_read_injection.v1",
                "file_path": "src/Vault.sol",
                "absolute_file_path": str(source),
                "target_repo": "test/repo",
                "language": "solidity",
                "functions_analyzed": 1,
                "functions": [{"name": "withdraw"}],
                "context_pack_id": "ctx-1",
            },
        )

        self.assertIn("source_sha256", receipt)
        self.assertIn("source_mtime_ns", receipt)
        self.assertEqual(receipt["source_size_bytes"], source.stat().st_size)

    def test_source_read_receipt_carries_corpus_index_hash_from_manifest(self) -> None:
        source = self.ws / "src" / "Vault.sol"
        source.parent.mkdir(parents=True)
        source.write_text("contract Vault {}\n", encoding="utf-8")
        manifest = self.ws / "index_manifest.json"
        manifest.write_text(
            json.dumps(
                {
                    "schema": "auditooor.hackerman_index_manifest.v1",
                    "corpus_index_hash": "a" * 64,
                    "files": [],
                }
            ),
            encoding="utf-8",
        )
        old_manifest = self.tool.CORPUS_INDEX_MANIFEST_PATH
        self.tool.CORPUS_INDEX_MANIFEST_PATH = manifest
        try:
            receipt = self.tool.record_source_read_receipt(
                self.ws,
                {
                    "schema": "auditooor.pre_source_read_injection.v1",
                    "file_path": "src/Vault.sol",
                    "absolute_file_path": str(source),
                    "target_repo": "test/repo",
                    "language": "solidity",
                    "functions_analyzed": 1,
                    "functions": [{"name": "withdraw"}],
                    "context_pack_id": "ctx-1",
                },
            )
        finally:
            self.tool.CORPUS_INDEX_MANIFEST_PATH = old_manifest

        self.assertEqual(receipt["corpus_index_hash"], "a" * 64)
        self.assertEqual(receipt["corpus_index_hash_status"], "present")
        self.assertEqual(
            receipt["corpus_index_manifest_schema"],
            "auditooor.hackerman_index_manifest.v1",
        )

    def test_source_read_receipt_marks_missing_corpus_manifest_without_hashing_indexes(self) -> None:
        source = self.ws / "src" / "Vault.sol"
        source.parent.mkdir(parents=True)
        source.write_text("contract Vault {}\n", encoding="utf-8")
        old_manifest = self.tool.CORPUS_INDEX_MANIFEST_PATH
        self.tool.CORPUS_INDEX_MANIFEST_PATH = self.ws / "missing_manifest.json"
        try:
            receipt = self.tool.record_source_read_receipt(
                self.ws,
                {
                    "schema": "auditooor.pre_source_read_injection.v1",
                    "file_path": "src/Vault.sol",
                    "absolute_file_path": str(source),
                    "target_repo": "test/repo",
                    "language": "solidity",
                    "functions_analyzed": 1,
                    "functions": [{"name": "withdraw"}],
                    "context_pack_id": "ctx-1",
                },
            )
        finally:
            self.tool.CORPUS_INDEX_MANIFEST_PATH = old_manifest

        self.assertEqual(receipt["corpus_index_hash"], "")
        self.assertEqual(receipt["corpus_index_hash_status"], "missing_manifest")

    def test_source_read_receipt_marks_invalid_corpus_manifest(self) -> None:
        source = self.ws / "src" / "Vault.sol"
        source.parent.mkdir(parents=True)
        source.write_text("contract Vault {}\n", encoding="utf-8")
        manifest = self.ws / "bad_manifest.json"
        manifest.write_text(json.dumps({"corpus_index_hash": "not-a-sha"}), encoding="utf-8")
        old_manifest = self.tool.CORPUS_INDEX_MANIFEST_PATH
        self.tool.CORPUS_INDEX_MANIFEST_PATH = manifest
        try:
            receipt = self.tool.record_source_read_receipt(
                self.ws,
                {
                    "schema": "auditooor.pre_source_read_injection.v1",
                    "file_path": "src/Vault.sol",
                    "absolute_file_path": str(source),
                    "target_repo": "test/repo",
                    "language": "solidity",
                    "functions_analyzed": 1,
                    "functions": [{"name": "withdraw"}],
                    "context_pack_id": "ctx-1",
                },
            )
        finally:
            self.tool.CORPUS_INDEX_MANIFEST_PATH = old_manifest

        self.assertEqual(receipt["corpus_index_hash"], "")
        self.assertEqual(receipt["corpus_index_hash_status"], "invalid_manifest")

    def test_gate_passes_legacy_receipt_without_hash_even_when_source_exists(self) -> None:
        source = self.ws / "src" / "Vault.sol"
        source.parent.mkdir(parents=True)
        source.write_text("contract Vault {}\n", encoding="utf-8")
        self.tool.append_source_read_receipt(
            self.ws,
            {
                "schema": "auditooor.source_read_receipt.v1",
                "receipt_id": "legacy-1",
                "workspace": str(self.ws),
                "file": "src/Vault.sol",
                "absolute_file_path": str(source),
                "functions_analyzed": 1,
                "created_at_utc": "2026-05-19T00:00:00Z",
            },
        )
        draft = self._draft("Root cause is in `src/Vault.sol`.")

        result = self.tool.gate_draft_source_read_receipts(self.ws, draft)

        self.assertEqual(result["status"], "pass", result)
        self.assertEqual(
            result["cited_source_files"][0]["receipt"]["hash_status"],
            "missing_legacy_hash",
        )

    def test_gate_fails_when_hashed_source_read_receipt_is_stale(self) -> None:
        source = self.ws / "src" / "Vault.sol"
        source.parent.mkdir(parents=True)
        source.write_text("contract Vault {}\n", encoding="utf-8")
        self.tool.record_source_read_receipt(
            self.ws,
            {
                "schema": "auditooor.pre_source_read_injection.v1",
                "file_path": "src/Vault.sol",
                "absolute_file_path": str(source),
                "target_repo": "test/repo",
                "language": "solidity",
                "functions_analyzed": 1,
                "functions": [{"name": "withdraw"}],
                "context_pack_id": "ctx-1",
            },
        )
        source.write_text("contract Vault { uint256 changed; }\n", encoding="utf-8")
        draft = self._draft("Root cause is in `src/Vault.sol`.")

        result = self.tool.gate_draft_source_read_receipts(self.ws, draft)

        self.assertEqual(result["status"], "fail")
        self.assertEqual(result["counts"]["stale_receipts"], 1)
        self.assertEqual(result["stale_receipts"], ["src/Vault.sol"])
        self.assertEqual(result["cited_source_files"][0]["status"], "stale_receipt")
        self.assertEqual(
            result["cited_source_files"][0]["receipt"]["hash_status"],
            "mismatch",
        )

    def test_gate_checks_current_workspace_relative_source_before_stored_absolute_path(self) -> None:
        old_root = self.ws / "old-checkout"
        old_source = old_root / "src" / "Vault.sol"
        old_source.parent.mkdir(parents=True)
        old_source.write_text("contract Vault {}\n", encoding="utf-8")
        current_source = self.ws / "src" / "Vault.sol"
        current_source.parent.mkdir(parents=True)
        current_source.write_text("contract Vault { uint256 changed; }\n", encoding="utf-8")
        self.tool.append_source_read_receipt(
            self.ws,
            {
                "schema": "auditooor.source_read_receipt.v1",
                "receipt_id": "stale-absolute-1",
                "workspace": str(self.ws),
                "file": "src/Vault.sol",
                "absolute_file_path": str(old_source),
                "functions_analyzed": 1,
                "source_sha256": hashlib.sha256(old_source.read_bytes()).hexdigest(),
                "created_at_utc": "2026-05-19T00:00:00Z",
            },
        )
        draft = self._draft("Root cause is in `src/Vault.sol`.")

        result = self.tool.gate_draft_source_read_receipts(self.ws, draft)

        self.assertEqual(result["status"], "fail", result)
        self.assertEqual(result["stale_receipts"], ["src/Vault.sol"])
        receipt = result["cited_source_files"][0]["receipt"]
        self.assertEqual(receipt["hash_status"], "mismatch")
        self.assertEqual(receipt["source_path"], str(current_source))

    def test_gate_fails_when_hashed_source_read_receipt_source_is_missing(self) -> None:
        source = self.ws / "src" / "Vault.sol"
        source.parent.mkdir(parents=True)
        source.write_text("contract Vault {}\n", encoding="utf-8")
        source_hash = hashlib.sha256(source.read_bytes()).hexdigest()
        source.unlink()
        self.tool.append_source_read_receipt(
            self.ws,
            {
                "schema": "auditooor.source_read_receipt.v1",
                "receipt_id": "missing-source-1",
                "workspace": str(self.ws),
                "file": "src/Vault.sol",
                "absolute_file_path": str(source),
                "functions_analyzed": 1,
                "source_sha256": source_hash,
                "created_at_utc": "2026-05-19T00:00:00Z",
            },
        )
        draft = self._draft("Root cause is in `src/Vault.sol`.")

        result = self.tool.gate_draft_source_read_receipts(self.ws, draft)

        self.assertEqual(result["status"], "fail", result)
        self.assertEqual(result["stale_receipts"], ["src/Vault.sol"])
        receipt = result["cited_source_files"][0]["receipt"]
        self.assertEqual(receipt["hash_status"], "current_source_missing")

    def test_gate_passes_when_hashed_source_read_receipt_matches_current_file(self) -> None:
        source = self.ws / "src" / "Vault.sol"
        source.parent.mkdir(parents=True)
        source.write_text("contract Vault {}\n", encoding="utf-8")
        self.tool.record_source_read_receipt(
            self.ws,
            {
                "schema": "auditooor.pre_source_read_injection.v1",
                "file_path": "src/Vault.sol",
                "absolute_file_path": str(source),
                "target_repo": "test/repo",
                "language": "solidity",
                "functions_analyzed": 1,
                "functions": [{"name": "withdraw"}],
                "context_pack_id": "ctx-1",
            },
        )
        draft = self._draft("Root cause is in `src/Vault.sol`.")

        result = self.tool.gate_draft_source_read_receipts(self.ws, draft)

        self.assertEqual(result["status"], "pass", result)
        self.assertEqual(
            result["cited_source_files"][0]["receipt"]["hash_status"],
            "match",
        )

    def test_gate_passes_when_newer_receipt_matches_after_earlier_stale_read(self) -> None:
        """False-positive suppression (#81): an early read that later went stale must
        not FAIL the gate when a NEWER receipt matches the current source bytes.

        Prefer the newest current-hash match over the oldest path-match.
        """
        source = self.ws / "src" / "Vault.sol"
        source.parent.mkdir(parents=True)
        source.write_text("contract Vault {}\n", encoding="utf-8")
        stale_hash = hashlib.sha256(source.read_bytes()).hexdigest()
        # 1) Oldest receipt: recorded against the ORIGINAL bytes...
        self.tool.append_source_read_receipt(
            self.ws,
            {
                "schema": "auditooor.source_read_receipt.v1",
                "receipt_id": "old-stale-1",
                "workspace": str(self.ws),
                "file": "src/Vault.sol",
                "absolute_file_path": str(source),
                "functions_analyzed": 1,
                "source_sha256": stale_hash,
                "created_at_utc": "2026-05-19T00:00:00Z",
            },
        )
        # 2) Source is re-pinned / edited (invalidating the old receipt)...
        source.write_text("contract Vault { uint256 changed; }\n", encoding="utf-8")
        # 3) ...then re-read: newest receipt matches the CURRENT bytes.
        self.tool.record_source_read_receipt(
            self.ws,
            {
                "schema": "auditooor.pre_source_read_injection.v1",
                "file_path": "src/Vault.sol",
                "absolute_file_path": str(source),
                "target_repo": "test/repo",
                "language": "solidity",
                "functions_analyzed": 1,
                "functions": [{"name": "withdraw"}],
                "context_pack_id": "ctx-1",
            },
        )
        draft = self._draft("Root cause is in `src/Vault.sol`.")

        result = self.tool.gate_draft_source_read_receipts(self.ws, draft)

        self.assertEqual(result["status"], "pass", result)
        self.assertEqual(result["counts"]["stale_receipts"], 0)
        self.assertEqual(result["cited_source_files"][0]["status"], "receipt_found")
        self.assertEqual(
            result["cited_source_files"][0]["receipt"]["hash_status"],
            "match",
        )
        # Ledger is append-only: both rows still on disk, unmodified.
        rows = self.tool.load_source_read_receipts(self.ws)
        self.assertEqual(len(rows), 2)
        self.assertEqual(rows[0]["source_sha256"], stale_hash)

    def test_gate_still_fails_when_all_receipts_are_stale_regardless_of_order(self) -> None:
        """CONTROL true-positive: with NO current-hash match, the newest stale
        receipt must still surface `stale_receipt` and FAIL (all-stale FAILs).
        """
        source = self.ws / "src" / "Vault.sol"
        source.parent.mkdir(parents=True)
        source.write_text("contract Vault {}\n", encoding="utf-8")
        first_hash = hashlib.sha256(source.read_bytes()).hexdigest()
        source.write_text("contract Vault { uint256 v1; }\n", encoding="utf-8")
        second_hash = hashlib.sha256(source.read_bytes()).hexdigest()
        # Two stale receipts (neither matches the final current bytes).
        for rid, sha in (("stale-a", first_hash), ("stale-b", second_hash)):
            self.tool.append_source_read_receipt(
                self.ws,
                {
                    "schema": "auditooor.source_read_receipt.v1",
                    "receipt_id": rid,
                    "workspace": str(self.ws),
                    "file": "src/Vault.sol",
                    "absolute_file_path": str(source),
                    "functions_analyzed": 1,
                    "source_sha256": sha,
                    "created_at_utc": "2026-05-19T00:00:00Z",
                },
            )
        # Final source differs from BOTH receipts.
        source.write_text("contract Vault { uint256 v2; }\n", encoding="utf-8")
        draft = self._draft("Root cause is in `src/Vault.sol`.")

        result = self.tool.gate_draft_source_read_receipts(self.ws, draft)

        self.assertEqual(result["status"], "fail", result)
        self.assertEqual(result["counts"]["stale_receipts"], 1)
        self.assertEqual(result["stale_receipts"], ["src/Vault.sol"])
        self.assertEqual(result["cited_source_files"][0]["status"], "stale_receipt")
        self.assertEqual(
            result["cited_source_files"][0]["receipt"]["hash_status"],
            "mismatch",
        )

    def test_gate_passes_when_cited_source_has_hacker_question_obligation(self) -> None:
        ob = self.tool.make_obligation(
            workspace=str(self.ws),
            file="contracts/Vault.sol",
            function_signature="function withdraw(uint256 amount) external",
            function_name="withdraw",
            attack_class="reentrancy",
            question="Can withdraw re-enter?",
            state="answered",
        )
        self.tool.append_obligations(self.ws, [ob])
        draft = self._draft("Root cause is in `contracts/Vault.sol`.")

        result = self.tool.gate_draft_source_read_receipts(self.ws, draft)

        self.assertEqual(result["status"], "pass", result)
        self.assertEqual(
            result["cited_source_files"][0]["receipt"]["kind"],
            "hacker_question_obligation",
        )

    def test_gate_fails_when_cited_source_lacks_any_receipt(self) -> None:
        draft = self._draft("Root cause is in `src/Vault.sol` and `src/Router.sol`.")

        result = self.tool.gate_draft_source_read_receipts(self.ws, draft)

        self.assertEqual(result["status"], "fail")
        self.assertEqual(result["counts"]["missing_receipts"], 2)
        self.assertEqual(result["missing_receipts"], ["src/Vault.sol", "src/Router.sol"])

    def test_gate_checks_extra_touched_source_files(self) -> None:
        draft = self._draft("Root cause is in the withdrawal path.")

        result = self.tool.gate_draft_source_read_receipts(
            self.ws,
            draft,
            extra_source_files=["src/Vault.sol"],
        )

        self.assertEqual(result["status"], "fail")
        self.assertEqual(result["counts"]["cited_source_files"], 1)
        self.assertEqual(result["missing_receipts"], ["src/Vault.sol"])

    def test_explicit_different_directories_do_not_match_by_basename_only(self) -> None:
        self.tool.record_source_read_receipt(
            self.ws,
            {
                "schema": "auditooor.pre_source_read_injection.v1",
                "file_path": "contracts/Vault.sol",
                "absolute_file_path": str(self.ws / "contracts" / "Vault.sol"),
                "target_repo": "test/repo",
                "language": "solidity",
                "functions_analyzed": 1,
                "functions": [{"name": "withdraw"}],
            },
        )
        draft = self._draft("Root cause is in `src/Vault.sol`.")

        result = self.tool.gate_draft_source_read_receipts(self.ws, draft)

        self.assertEqual(result["status"], "fail")
        self.assertEqual(result["missing_receipts"], ["src/Vault.sol"])

    def test_extraction_skips_tests_pocs_and_docs(self) -> None:
        draft = self._draft(
            "See `src/Vault.sol`, `test/Vault.t.sol`, `tests/foo_test.go`, "
            "`docs/Spec.py`, and `poc/repro.rs`."
        )

        cited = self.tool.extract_cited_source_files(draft.read_text(encoding="utf-8"))

        self.assertEqual(cited, ["src/Vault.sol"])


if __name__ == "__main__":
    unittest.main()
