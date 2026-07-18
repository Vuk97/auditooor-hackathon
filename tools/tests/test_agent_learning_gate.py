"""Tests for agent-learning-gate.py."""

from __future__ import annotations

import importlib.util
import json
import sys
import tempfile
import unittest
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[2]
TOOL = REPO_ROOT / "tools" / "agent-learning-gate.py"


def load_tool():
    spec = importlib.util.spec_from_file_location("agent_learning_gate", TOOL)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules["agent_learning_gate"] = module
    spec.loader.exec_module(module)
    return module


def write_report(path: Path, artifacts: list[dict]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(
            {
                "schema_version": "auditooor.agent_artifact_mining.v2",
                "total_artifacts": len(artifacts),
                "artifact_type_counts": {},
                "artifacts": artifacts,
            },
            indent=2,
            sort_keys=True,
        ),
        encoding="utf-8",
    )


def terminal_row(
    artifact_id: str,
    *,
    terminal_kind: str = "typed_lesson",
    reason: str | None = None,
    scoped: bool = True,
) -> str:
    row: dict[str, object] = {
        "artifact_id": artifact_id,
        "terminal_kind": terminal_kind,
    }
    if scoped:
        row.update(
            {
                "proposition": f"Terminal disposition for {artifact_id}",
                "evidence_polarity": "context_only" if terminal_kind == "NO_ACTION" else "limits",
                "primary_for": "methodology",
                # K4 - K3a-scoped rows must declare a canonical reuse_action.
                "reuse_action": "none" if terminal_kind == "NO_ACTION" else "add_hacker_question",
            }
        )
    if reason is not None:
        row["reason"] = reason
    return json.dumps(row)


class TestAgentLearningGate(unittest.TestCase):
    def test_empty_workspace_without_report_passes(self) -> None:
        tool = load_tool()
        with tempfile.TemporaryDirectory() as tmp:
            payload = tool.evaluate(Path(tmp), strict=True)
            self.assertEqual(payload["status"], "pass")
            self.assertEqual(payload["artifact_count"], 0)

    def test_missing_report_with_inputs_warns_or_fails_strict(self) -> None:
        tool = load_tool()
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp)
            out = ws / "agent_outputs" / "round1" / "REPORT.md"
            out.parent.mkdir(parents=True)
            out.write_text("VERDICT: NEGATIVE\nKILL: not reachable\n", encoding="utf-8")

            loose = tool.evaluate(ws, strict=False)
            strict = tool.evaluate(ws, strict=True)

            self.assertEqual(loose["status"], "warn")
            self.assertEqual(strict["status"], "fail")
            self.assertEqual(strict["blockers"][0]["code"], "missing_agent_artifact_report")

    def test_accepts_auditooor_report_path(self) -> None:
        tool = load_tool()
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp)
            write_report(ws / ".auditooor" / "agent_artifact_mining_report.json", [])
            payload = tool.evaluate(ws, strict=True)
            self.assertEqual(payload["status"], "pass")
            self.assertTrue(payload["selected_report_path"].endswith(".auditooor/agent_artifact_mining_report.json"))

    def test_accepts_canonical_agent_artifacts_learning_ledger(self) -> None:
        tool = load_tool()
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp)
            write_report(
                ws / "agent_artifact_mining_report.json",
                [
                    {
                        "artifact_id": "a1",
                        "artifact_type": "known_limitation",
                        "title": "learned row",
                        "verification_tier": "tier-3-synthetic-taxonomy-anchored",
                        "source_has_local_proof": False,
                    }
                ],
            )
            ledger = ws / ".auditooor" / "agent_artifacts" / "learning_ledger.jsonl"
            ledger.parent.mkdir(parents=True)
            ledger.write_text(
                terminal_row("a1") + "\n",
                encoding="utf-8",
            )

            payload = tool.evaluate(ws, strict=True)

            self.assertEqual(payload["status"], "pass")
            self.assertTrue(payload["learning_ledger_present"])
            self.assertEqual(payload["learning_ledger_paths"], [str(ledger.resolve())])
            self.assertEqual(payload["learning_ledger_covered_count"], 1)
            self.assertEqual(payload["unclassified_agent_artifact_count"], 0)

    def test_strict_missing_learning_ledger_for_artifacts_fails(self) -> None:
        tool = load_tool()
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp)
            write_report(
                ws / "agent_artifact_mining_report.json",
                [
                    {
                        "artifact_id": "a1",
                        "artifact_type": "known_limitation",
                        "title": "learned row",
                        "verification_tier": "tier-3-synthetic-taxonomy-anchored",
                        "source_has_local_proof": False,
                    }
                ],
            )

            loose = tool.evaluate(ws, strict=False)
            strict = tool.evaluate(ws, strict=True)

            self.assertEqual(loose["status"], "warn")
            self.assertEqual(loose["warnings"][0]["code"], "learning_ledger_missing")
            self.assertEqual(strict["status"], "fail")
            self.assertEqual(strict["blockers"][0]["code"], "learning_ledger_missing")

    def test_learning_ledger_must_cover_each_artifact_or_terminal_no_action(self) -> None:
        tool = load_tool()
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp)
            write_report(
                ws / "agent_artifact_mining_report.json",
                [
                    {
                        "artifact_id": "a1",
                        "artifact_type": "known_limitation",
                        "title": "lesson",
                        "verification_tier": "tier-3-synthetic-taxonomy-anchored",
                    },
                    {
                        "artifact_id": "a2",
                        "artifact_type": "kill_review",
                        "title": "no action",
                        "verification_tier": "tier-3-synthetic-taxonomy-anchored",
                    },
                ],
            )
            ledger = ws / ".auditooor" / "agent_artifacts" / "learning_ledger.jsonl"
            ledger.parent.mkdir(parents=True)
            ledger.write_text(terminal_row("a1") + "\n", encoding="utf-8")

            missing = tool.evaluate(ws, strict=True)
            self.assertEqual(missing["status"], "fail")
            self.assertEqual(missing["unclassified_agent_artifact_count"], 1)
            self.assertEqual(missing["blockers"][-1]["code"], "unclassified_agent_artifacts")

            ledger.write_text(
                "\n".join(
                    [
                        terminal_row("a1"),
                        terminal_row("a2", terminal_kind="NO_ACTION", reason="provider output duplicated an existing killed lane"),
                    ]
                )
                + "\n",
                encoding="utf-8",
            )

            covered = tool.evaluate(ws, strict=True)
            self.assertEqual(covered["status"], "pass")
            self.assertEqual(covered["learning_ledger_covered_count"], 2)
            self.assertEqual(covered["unclassified_agent_artifact_count"], 0)

    def test_no_action_learning_ledger_row_requires_reason(self) -> None:
        tool = load_tool()
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp)
            write_report(
                ws / "agent_artifact_mining_report.json",
                [
                    {
                        "artifact_id": "a1",
                        "artifact_type": "kill_review",
                        "title": "empty no action",
                        "verification_tier": "tier-3-synthetic-taxonomy-anchored",
                    }
                ],
            )
            ledger = ws / ".auditooor" / "agent_artifacts" / "learning_ledger.jsonl"
            ledger.parent.mkdir(parents=True)
            ledger.write_text(terminal_row("a1", terminal_kind="NO_ACTION") + "\n", encoding="utf-8")

            payload = tool.evaluate(ws, strict=True)

            self.assertEqual(payload["status"], "fail")
            self.assertEqual(payload["no_action_without_reason_count"], 1)
            self.assertEqual(payload["blockers"][-1]["code"], "no_action_without_reason")

    def test_bare_artifact_id_ledger_row_does_not_cover_artifact(self) -> None:
        tool = load_tool()
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp)
            write_report(
                ws / "agent_artifact_mining_report.json",
                [
                    {
                        "artifact_id": "a1",
                        "artifact_type": "known_limitation",
                        "title": "bare row",
                        "verification_tier": "tier-3-synthetic-taxonomy-anchored",
                    }
                ],
            )
            ledger = ws / ".auditooor" / "agent_artifacts" / "learning_ledger.jsonl"
            ledger.parent.mkdir(parents=True)
            ledger.write_text('{"artifact_id":"a1"}\n', encoding="utf-8")

            payload = tool.evaluate(ws, strict=True)

            self.assertEqual(payload["status"], "fail")
            self.assertEqual(payload["learning_ledger_covered_count"], 0)
            self.assertEqual(payload["unclassified_agent_artifact_count"], 1)

    def test_terminal_learning_rows_require_proposition_scope_fields(self) -> None:
        tool = load_tool()
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp)
            write_report(
                ws / "agent_artifact_mining_report.json",
                [
                    {
                        "artifact_id": "a1",
                        "artifact_type": "known_limitation",
                        "title": "unscoped terminal row",
                        "verification_tier": "tier-3-synthetic-taxonomy-anchored",
                    }
                ],
            )
            ledger = ws / ".auditooor" / "agent_artifacts" / "learning_ledger.jsonl"
            ledger.parent.mkdir(parents=True)
            ledger.write_text(terminal_row("a1", scoped=False) + "\n", encoding="utf-8")

            loose = tool.evaluate(ws, strict=False)
            strict = tool.evaluate(ws, strict=True)

            self.assertEqual(loose["status"], "warn")
            self.assertEqual(loose["terminal_scope_violation_count"], 1)
            self.assertEqual(strict["status"], "fail")
            self.assertIn("terminal_learning_row_missing_scope", {row["code"] for row in strict["blockers"]})

    def test_provider_only_artifact_cannot_be_promoted_without_local_verification(self) -> None:
        tool = load_tool()
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp)
            write_report(
                ws / "agent_artifact_mining_report.json",
                [
                    {
                        "artifact_id": "p1",
                        "artifact_type": "known_limitation",
                        "title": "provider-only",
                        "provider_only": True,
                        "verification_tier": "tier-5-quarantine",
                    }
                ],
            )
            ledger = ws / ".auditooor" / "agent_artifacts" / "learning_ledger.jsonl"
            ledger.parent.mkdir(parents=True)
            ledger.write_text(terminal_row("p1") + "\n", encoding="utf-8")

            payload = tool.evaluate(ws, strict=True)

            self.assertEqual(payload["status"], "fail")
            self.assertEqual(payload["provider_only_terminal_promotion_count"], 1)
            self.assertEqual(payload["blockers"][-1]["code"], "provider_only_terminal_promotion_without_local_verification")

    def test_provider_only_no_action_with_reason_passes(self) -> None:
        tool = load_tool()
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp)
            write_report(
                ws / "agent_artifact_mining_report.json",
                [
                    {
                        "artifact_id": "p1",
                        "artifact_type": "known_limitation",
                        "title": "provider-only no action",
                        "provider_only": True,
                        "verification_tier": "tier-5-quarantine",
                    }
                ],
            )
            ledger = ws / ".auditooor" / "agent_artifacts" / "learning_ledger.jsonl"
            ledger.parent.mkdir(parents=True)
            ledger.write_text(
                terminal_row("p1", terminal_kind="NO_ACTION", reason="provider_only") + "\n",
                encoding="utf-8",
            )

            payload = tool.evaluate(ws, strict=True)

            self.assertEqual(payload["status"], "pass")
            self.assertEqual(payload["provider_only_terminal_promotion_count"], 0)

    def test_malformed_artifact_accounting_fails_strict(self) -> None:
        tool = load_tool()
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp)
            report = ws / "agent_artifact_mining_report.json"
            report.write_text(
                json.dumps({"schema_version": "auditooor.agent_artifact_mining.v2", "artifacts": {"bad": "shape"}}),
                encoding="utf-8",
            )
            payload = tool.evaluate(ws, strict=True)
            self.assertEqual(payload["status"], "fail")
            self.assertEqual(payload["blockers"][-1]["code"], "malformed_artifacts_list")

            write_report(
                report,
                [
                    {
                        "artifact_type": "known_limitation",
                        "title": "missing id",
                    },
                    {
                        "artifact_id": "dup",
                        "artifact_type": "known_limitation",
                        "title": "first",
                    },
                    {
                        "artifact_id": "dup",
                        "artifact_type": "known_limitation",
                        "title": "second",
                    },
                ],
            )
            ledger = ws / ".auditooor" / "agent_artifacts" / "learning_ledger.jsonl"
            ledger.parent.mkdir(parents=True)
            ledger.write_text(terminal_row("dup") + "\n", encoding="utf-8")

            payload = tool.evaluate(ws, strict=True)
            codes = {row["code"] for row in payload["blockers"]}
            self.assertIn("artifact_id_missing", codes)
            self.assertIn("duplicate_artifact_id", codes)

    def test_provider_only_tier_above_quarantine_fails(self) -> None:
        tool = load_tool()
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp)
            write_report(
                ws / "agent_artifact_mining_report.json",
                [
                    {
                        "artifact_id": "p1",
                        "artifact_type": "rejection_pattern",
                        "title": "provider claim",
                        "provider_only": True,
                        "verification_tier": "tier-2-verified-public-archive",
                        "source_has_local_proof": False,
                    }
                ],
            )
            payload = tool.evaluate(ws, strict=False)
            self.assertEqual(payload["status"], "fail")
            self.assertEqual(payload["provider_only_promotion_escape_count"], 1)

    def test_proof_mapping_without_local_proof_fails(self) -> None:
        tool = load_tool()
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp)
            write_report(
                ws / "agent_artifact_mining_report.json",
                [
                    {
                        "artifact_id": "proof1",
                        "artifact_type": "proof_artifact_mapping_candidate",
                        "title": "passing claim without proof",
                        "verification_tier": "tier-3-synthetic-taxonomy-anchored",
                        "source_has_local_proof": False,
                    }
                ],
            )
            payload = tool.evaluate(ws, strict=True)
            self.assertEqual(payload["status"], "fail")
            self.assertEqual(payload["proof_mapping_without_local_proof_count"], 1)

    def test_report_path_mismatch_fails_only_strict(self) -> None:
        tool = load_tool()
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp)
            write_report(ws / "agent_artifact_mining_report.json", [])
            write_report(
                ws / ".auditooor" / "agent_artifact_mining_report.json",
                [
                    {
                        "artifact_id": "x",
                        "artifact_type": "known_limitation",
                        "title": "different",
                        "verification_tier": "tier-3-synthetic-taxonomy-anchored",
                        "source_has_local_proof": False,
                    }
                ],
            )

            loose = tool.evaluate(ws, strict=False)
            strict = tool.evaluate(ws, strict=True)

            self.assertEqual(loose["status"], "warn")
            self.assertEqual(strict["status"], "fail")
            self.assertTrue(strict["report_path_mismatch"])


    # K4: a K3a-compiled row that carries an invalid reuse_action value should fail.
    def test_invalid_k4_reuse_action_value_fails(self) -> None:
        """K4: a terminal row with a non-canonical reuse_action must be flagged."""
        tool = load_tool()
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp)
            write_report(
                ws / "agent_artifact_mining_report.json",
                [
                    {
                        "artifact_id": "bad1",
                        "artifact_type": "known_limitation",
                        "title": "row with invalid reuse_action",
                        "verification_tier": "tier-3-synthetic-taxonomy-anchored",
                    }
                ],
            )
            ledger = ws / ".auditooor" / "agent_artifacts" / "learning_ledger.jsonl"
            ledger.parent.mkdir(parents=True)
            bad_row = {
                "artifact_id": "bad1",
                "terminal_kind": "typed_lesson",
                "proposition": "Invalid reuse action test",
                "evidence_polarity": "context_only",
                "primary_for": "methodology",
                # K4: this is NOT in the canonical enum.
                "reuse_action": "do_something_invalid",
            }
            ledger.write_text(json.dumps(bad_row) + "\n", encoding="utf-8")

            payload = tool.evaluate(ws, strict=True)

        self.assertEqual(payload["status"], "fail")
        codes = {row["code"] for row in payload["blockers"]}
        self.assertIn(
            "terminal_learning_row_missing_reuse_action",
            codes,
            "K4: invalid reuse_action must trigger terminal_learning_row_missing_reuse_action",
        )
        self.assertGreater(payload.get("reuse_action_violation_count", 0), 0)

    # K4: a K3a-compiled row that is MISSING reuse_action should also fail.
    def test_k3a_row_missing_reuse_action_fails(self) -> None:
        """K4: K3a-scoped row with no reuse_action must be flagged."""
        tool = load_tool()
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp)
            write_report(
                ws / "agent_artifact_mining_report.json",
                [
                    {
                        "artifact_id": "m1",
                        "artifact_type": "known_limitation",
                        "title": "row with missing reuse_action",
                        "verification_tier": "tier-3-synthetic-taxonomy-anchored",
                    }
                ],
            )
            ledger = ws / ".auditooor" / "agent_artifacts" / "learning_ledger.jsonl"
            ledger.parent.mkdir(parents=True)
            # A K3a row: has proposition + evidence_polarity + primary_for but NO reuse_action.
            missing_reuse_row = {
                "artifact_id": "m1",
                "terminal_kind": "typed_lesson",
                "proposition": "Some useful learning",
                "evidence_polarity": "context_only",
                "primary_for": "methodology",
                # Deliberately omit reuse_action.
            }
            ledger.write_text(json.dumps(missing_reuse_row) + "\n", encoding="utf-8")

            payload = tool.evaluate(ws, strict=True)

        self.assertEqual(payload["status"], "fail")
        codes = {row["code"] for row in payload["blockers"]}
        self.assertIn(
            "terminal_learning_row_missing_reuse_action",
            codes,
            "K4: missing reuse_action on K3a row must trigger violation",
        )

    # K3a: a ledger row with evidence_polarity='contradicts' should not be used
    # as positive proof. Verify the gate correctly passes a row labeled
    # 'contradicts' so long as primary_for != 'proof' (negative != positive proof).
    def test_contradicts_polarity_with_non_proof_primary_for_passes(self) -> None:
        """K3a: contradicts polarity is valid so long as it is not primary_for='proof'."""
        tool = load_tool()
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp)
            write_report(
                ws / "agent_artifact_mining_report.json",
                [
                    {
                        "artifact_id": "neg1",
                        "artifact_type": "rejection_pattern",
                        "title": "OOS reject",
                        "verification_tier": "tier-3-synthetic-taxonomy-anchored",
                    }
                ],
            )
            ledger = ws / ".auditooor" / "agent_artifacts" / "learning_ledger.jsonl"
            ledger.parent.mkdir(parents=True)
            # contradicts polarity is fine for kill_reason rows.
            row = {
                "artifact_id": "neg1",
                "terminal_kind": "kill_reason",
                "proposition": "OOS rejection - not in scope",
                "evidence_polarity": "contradicts",
                "primary_for": "OOS",
                "reuse_action": "add_kill_rubric",
            }
            ledger.write_text(json.dumps(row) + "\n", encoding="utf-8")

            payload = tool.evaluate(ws, strict=True)

        self.assertEqual(payload["status"], "pass")

    # K3a enforcement: a kill_reason row (negative kind) with
    # evidence_polarity='supports' and primary_for='proof' must be REJECTED by the gate.
    # This was previously a documented gap (wave-9); wave-10 closes it.
    def test_k3a_negative_kind_with_positive_proof_fails(self) -> None:
        """K3a enforcement: gate rejects kill_reason rows claiming positive polarity+proof scope.

        A kill_reason row represents a negative outcome (the exploit did not work, was
        OOS, etc.).  Labelling it evidence_polarity='supports' + primary_for='proof'
        would allow a negative outcome to masquerade as positive proof of exploit
        mechanics - a K3a violation.  The gate must fail hard for this combination.
        """
        tool = load_tool()
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp)
            write_report(
                ws / "agent_artifact_mining_report.json",
                [
                    {
                        "artifact_id": "neg_as_proof",
                        "artifact_type": "rejection_pattern",
                        "title": "OOS kill",
                        "verification_tier": "tier-3-synthetic-taxonomy-anchored",
                    }
                ],
            )
            ledger = ws / ".auditooor" / "agent_artifacts" / "learning_ledger.jsonl"
            ledger.parent.mkdir(parents=True)
            # A kill_reason row incorrectly claiming positive polarity + proof scope.
            # This violates K3a: negative outcome reused as positive proof evidence.
            bad_row = {
                "artifact_id": "neg_as_proof",
                "terminal_kind": "kill_reason",   # negative kind
                "proposition": "Some negative finding",
                "evidence_polarity": "supports",  # incorrectly positive
                "primary_for": "proof",            # incorrectly proof scope
                "reuse_action": "add_kill_rubric",
            }
            ledger.write_text(json.dumps(bad_row) + "\n", encoding="utf-8")

            payload = tool.evaluate(ws, strict=True)

        self.assertEqual(
            payload["status"],
            "fail",
            "K3a: gate must reject kill_reason rows claiming evidence_polarity=supports + primary_for=proof",
        )
        codes = {row["code"] for row in payload["blockers"]}
        self.assertIn(
            "k3a_negative_kind_claims_positive_proof",
            codes,
            "K3a: expected blocker code k3a_negative_kind_claims_positive_proof",
        )
        self.assertGreater(payload.get("negative_kind_positive_proof_violation_count", 0), 0)

    def test_k3a_kill_reason_with_oos_primary_for_passes(self) -> None:
        """K3a: a kill_reason row with primary_for='OOS' is a legitimate kill row and must pass."""
        tool = load_tool()
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp)
            write_report(
                ws / "agent_artifact_mining_report.json",
                [
                    {
                        "artifact_id": "kill_oos",
                        "artifact_type": "rejection_pattern",
                        "title": "OOS kill row",
                        "verification_tier": "tier-3-synthetic-taxonomy-anchored",
                    }
                ],
            )
            ledger = ws / ".auditooor" / "agent_artifacts" / "learning_ledger.jsonl"
            ledger.parent.mkdir(parents=True)
            # kill_reason with supports polarity is fine when primary_for is not 'proof'.
            ok_row = {
                "artifact_id": "kill_oos",
                "terminal_kind": "kill_reason",
                "proposition": "Finding is out of scope for this engagement",
                "evidence_polarity": "supports",   # fine: supports an OOS conclusion
                "primary_for": "OOS",              # scope is OOS, not proof
                "reuse_action": "add_kill_rubric",
            }
            ledger.write_text(json.dumps(ok_row) + "\n", encoding="utf-8")

            payload = tool.evaluate(ws, strict=True)

        self.assertEqual(
            payload["status"],
            "pass",
            "K3a: kill_reason + supports polarity is allowed when primary_for='OOS'",
        )
        self.assertEqual(payload.get("negative_kind_positive_proof_violation_count", 0), 0)

    def test_k3a_kill_reason_with_contradicts_polarity_passes(self) -> None:
        """K3a: a kill_reason row with evidence_polarity='contradicts' is a legitimate negative row."""
        tool = load_tool()
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp)
            write_report(
                ws / "agent_artifact_mining_report.json",
                [
                    {
                        "artifact_id": "kill_contra",
                        "artifact_type": "rejection_pattern",
                        "title": "Contradicts kill row",
                        "verification_tier": "tier-3-synthetic-taxonomy-anchored",
                    }
                ],
            )
            ledger = ws / ".auditooor" / "agent_artifacts" / "learning_ledger.jsonl"
            ledger.parent.mkdir(parents=True)
            # kill_reason with contradicts polarity + proof primary_for is fine:
            # it says "this evidence contradicts the proof hypothesis" which is
            # exactly what a kill row should say.
            ok_row = {
                "artifact_id": "kill_contra",
                "terminal_kind": "kill_reason",
                "proposition": "Exploit mechanics do not hold under production conditions",
                "evidence_polarity": "contradicts",   # contradicts = negative signal
                "primary_for": "proof",               # scoped to proof (as a kill)
                "reuse_action": "add_kill_rubric",
            }
            ledger.write_text(json.dumps(ok_row) + "\n", encoding="utf-8")

            payload = tool.evaluate(ws, strict=True)

        self.assertEqual(
            payload["status"],
            "pass",
            "K3a: kill_reason + contradicts polarity is always allowed",
        )
        self.assertEqual(payload.get("negative_kind_positive_proof_violation_count", 0), 0)

    def test_k3a_proof_artifact_with_positive_proof_passes(self) -> None:
        """K3a: a proof_artifact row with evidence_polarity='supports' + primary_for='proof' must pass."""
        tool = load_tool()
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp)
            write_report(
                ws / "agent_artifact_mining_report.json",
                [
                    {
                        "artifact_id": "good_proof",
                        "artifact_type": "proof_artifact_mapping_candidate",
                        "title": "Verified proof artifact",
                        "verification_tier": "tier-2-verified-public-archive",
                        "source_has_local_proof": True,
                    }
                ],
            )
            ledger = ws / ".auditooor" / "agent_artifacts" / "learning_ledger.jsonl"
            ledger.parent.mkdir(parents=True)
            # proof_artifact (positive kind) + supports + proof = canonical correct row.
            ok_row = {
                "artifact_id": "good_proof",
                "terminal_kind": "proof_artifact",
                "is_primary_signal": True,
                "can_promote_to_proof": True,
                "local_verification_ref": "poc-tests/exploit_test.go",
                "proposition": "Exploit is exploitable under the stated conditions",
                "evidence_polarity": "supports",
                "primary_for": "proof",
                "reuse_action": "add_detector",
            }
            ledger.write_text(json.dumps(ok_row) + "\n", encoding="utf-8")

            payload = tool.evaluate(ws, strict=True)

        self.assertEqual(
            payload["status"],
            "pass",
            "K3a: proof_artifact row with supports+proof is the canonical correct shape and must pass",
        )
        self.assertEqual(payload.get("negative_kind_positive_proof_violation_count", 0), 0)

    def test_k3a_triager_objection_with_positive_proof_fails(self) -> None:
        """K3a: triager_objection is also a negative kind; supports+proof on it must fail."""
        tool = load_tool()
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp)
            write_report(
                ws / "agent_artifact_mining_report.json",
                [
                    {
                        "artifact_id": "objection_as_proof",
                        "artifact_type": "triager_lesson",
                        "title": "Triager rejection",
                        "verification_tier": "tier-3-synthetic-taxonomy-anchored",
                    }
                ],
            )
            ledger = ws / ".auditooor" / "agent_artifacts" / "learning_ledger.jsonl"
            ledger.parent.mkdir(parents=True)
            bad_row = {
                "artifact_id": "objection_as_proof",
                "terminal_kind": "triager_objection",  # negative kind
                "proposition": "Triager said the exploit is invalid",
                "evidence_polarity": "supports",       # contradicts K3a
                "primary_for": "proof",                # contradicts K3a
                "reuse_action": "add_kill_rubric",
            }
            ledger.write_text(json.dumps(bad_row) + "\n", encoding="utf-8")

            payload = tool.evaluate(ws, strict=True)

        self.assertEqual(
            payload["status"],
            "fail",
            "K3a: triager_objection + supports + proof must be rejected just like kill_reason",
        )
        codes = {row["code"] for row in payload["blockers"]}
        self.assertIn("k3a_negative_kind_claims_positive_proof", codes)

    # K3: provider_only_promotion_escape_count from the gate perspective.
    # A provider-only artifact that somehow has a proof_artifact ledger row
    # (escape scenario) must trigger a non-zero escape count in the gate.
    def test_gate_counts_provider_only_proof_escape_in_ledger(self) -> None:
        """K3: gate must count provider-only rows that escaped to proof_artifact in ledger."""
        tool = load_tool()
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp)
            write_report(
                ws / "agent_artifact_mining_report.json",
                [
                    {
                        "artifact_id": "escape1",
                        "artifact_type": "proof_artifact_mapping_candidate",
                        "title": "Provider proof escape",
                        "provider_only": True,
                        "verification_tier": "tier-5-quarantine",
                        "source_has_local_proof": True,
                    }
                ],
            )
            ledger = ws / ".auditooor" / "agent_artifacts" / "learning_ledger.jsonl"
            ledger.parent.mkdir(parents=True)
            # Deliberately write an escape: provider_only=True + proof_artifact kind.
            escaped_row = {
                "artifact_id": "escape1",
                "terminal_kind": "proof_artifact",
                "provider_only": True,
                "proposition": "Escape scenario",
                "evidence_polarity": "supports",
                "primary_for": "proof",
                "reuse_action": "add_detector",
            }
            ledger.write_text(json.dumps(escaped_row) + "\n", encoding="utf-8")

            payload = tool.evaluate(ws, strict=True)

        self.assertGreater(
            payload["provider_only_promotion_escape_count"],
            0,
            "K3: gate must report provider_only_promotion_escape_count > 0 for escaped row",
        )
        self.assertEqual(payload["status"], "fail")


if __name__ == "__main__":
    unittest.main()
