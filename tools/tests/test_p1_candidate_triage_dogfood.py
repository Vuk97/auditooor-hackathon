#!/usr/bin/env python3
"""Tests for tools/p1-candidate-triage-dogfood.py."""
from __future__ import annotations

import importlib.util
import json
import sys
import tempfile
import textwrap
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
TOOL = ROOT / "tools" / "p1-candidate-triage-dogfood.py"


def load_tool():
    spec = importlib.util.spec_from_file_location("p1_candidate_triage_dogfood", TOOL)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"could not load {TOOL}")
    mod = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = mod
    spec.loader.exec_module(mod)
    return mod


def write_json(path: Path, obj: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(obj, indent=2, sort_keys=True) + "\n", encoding="utf-8")


class P1CandidateTriageDogfoodTest(unittest.TestCase):
    def setUp(self) -> None:
        self.tool = load_tool()

    def write_fixture(self, root: Path) -> tuple[Path, Path]:
        workspace = root / "ws"
        aud = workspace / ".auditooor"
        out = root / "out"
        (workspace / "submissions" / "filed" / "hb-auth").mkdir(parents=True)
        (workspace / "submissions" / "_killed" / "hb-killed").mkdir(parents=True)
        aud.mkdir(parents=True)

        invariants = root / "invariants.jsonl"
        invariants.write_text(
            "\n".join(
                [
                    json.dumps(
                        {
                            "invariant_id": "INV-AUTH-001",
                            "category": "authorization",
                            "statement": "Privileged state writes MUST require an authorized caller or signer.",
                            "target_lang": "solidity",
                            "commit_point_pattern": "require authorized caller before state mutation",
                            "defense_layer": "onlyOwner or signature authorization",
                        }
                    ),
                    json.dumps(
                        {
                            "invariant_id": "INV-UNI-001",
                            "category": "uniqueness",
                            "statement": "A signed cross-chain message MUST be consumable at most once; replays with the same nonce MUST be rejected.",
                            "target_lang": "solidity",
                            "commit_point_pattern": "nonce consumed before message effect",
                            "defense_layer": "nonce mapping and consumed message set",
                        }
                    ),
                    json.dumps(
                        {
                            "invariant_id": "INV-BND-001",
                            "category": "bounds",
                            "statement": "Array lengths and numeric casts MUST stay within explicit bounds.",
                            "target_lang": "any",
                            "commit_point_pattern": "check length before allocation or downcast",
                            "defense_layer": "bounds check",
                        }
                    ),
                ]
            )
            + "\n",
            encoding="utf-8",
        )

        (workspace / "engage_report.md").write_text(
            textwrap.dedent(
                """\
                # Engagement Report - fixture

                - Workspace: `/tmp/ws`
                - Total hits: **2**

                ## Clusters

                ### Cluster: `signature-without-nonce` (1 hit)

                - **[LOW] `signature-without-nonce`** - `/tmp/ws/src/Gateway.sol:42`
                  - snippet: `recover signer but nonce is not consumed`

                ### Cluster: `unrelated-style-warning` (1 hit)

                - **[LOW] `unrelated-style-warning`** - `/tmp/ws/src/Style.sol:7`
                  - snippet: `local variable name is verbose`
                """
            ),
            encoding="utf-8",
        )

        write_json(
            aud / "exploit_queue.json",
            {
                "schema": "auditooor.exploit_queue.v1",
                "queue": [
                    {
                        "lead_id": "EQ-001",
                        "title": "Signed cross-chain message replay because nonce is not consumed",
                        "attack_class": "signature-replay",
                        "proof_status": "needs_source",
                        "quality_gate_status": "needs_source",
                        "source_refs": ["src/Gateway.sol:42"],
                        "root_cause_hypothesis": "signature can be replayed with the same nonce",
                    },
                    {
                        "lead_id": "EQ-002",
                        "title": "Cosmetic naming issue",
                        "attack_class": "style-only",
                        "proof_status": "needs_source",
                        "quality_gate_status": "needs_source",
                        "source_refs": ["src/Style.sol:7"],
                    },
                    {
                        "lead_id": "EQ-003",
                        "title": "Refund accounting mismatch",
                        "attack_class": "refund-recipient-mismatch",
                        "proof_status": "killed",
                        "quality_gate_status": "disqualified",
                        "blockers": ["source review proved intended behavior"],
                        "source_refs": ["src/Refund.sol:9"],
                    },
                ],
            },
        )
        write_json(
            aud / "candidate_judgment_packet.json",
            {
                "packets": [
                    {
                        "candidate_id": "EQ-001",
                        "attack_class": "signature-replay",
                        "verdict": "needs_source",
                        "judgment_inputs": {"attacker": "replay signed message"},
                    }
                ]
            },
        )
        write_json(
            aud / "proof_obligation_queue.json",
            {
                "tasks": [
                    {
                        "task_id": "POQ-001",
                        "proof_needed": "For EQ-001, prove replay with same nonce and same signed message.",
                    }
                ]
            },
        )

        filed = workspace / "submissions" / "filed" / "hb-auth" / "hb-auth.md"
        filed.write_text(
            "# Filed auth issue\n\nThis filed submission cites indexed invariant INV-AUTH-001.\n",
            encoding="utf-8",
        )
        killed = workspace / "submissions" / "_killed" / "hb-killed" / "hb-killed.md"
        killed.write_text("# Killed issue\n\nNo invariant citation here.\n", encoding="utf-8")
        return workspace, invariants

    def test_states_and_read_only_submission_behavior(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            workspace, invariants = self.write_fixture(root)
            filed = workspace / "submissions" / "filed" / "hb-auth" / "hb-auth.md"
            killed = workspace / "submissions" / "_killed" / "hb-killed" / "hb-killed.md"
            before = {filed: filed.read_text(encoding="utf-8"), killed: killed.read_text(encoding="utf-8")}

            result = self.tool.run_triage(
                workspace,
                root / "out",
                invariant_paths=[invariants],
                max_suggestions=2,
            )
            rows = {row["candidate_id"]: row for row in result["candidate_rows"]}

            self.assertEqual(rows["hb-auth"]["state"], "cited")
            self.assertEqual(rows["hb-auth"]["indexed_cited_invariant_ids"], ["INV-AUTH-001"])
            self.assertEqual(rows["EQ-001"]["state"], "suggested")
            self.assertEqual(rows["EQ-001"]["suggested_mappings"][0]["invariant_id"], "INV-UNI-001")
            self.assertIn("candidate_packet", rows["EQ-001"]["sources_present"])
            self.assertIn("proof_packet", rows["EQ-001"]["sources_present"])
            self.assertIn("engage_cluster", rows["EQ-001"]["sources_present"])
            self.assertEqual(rows["EQ-002"]["state"], "no-match")
            self.assertEqual(rows["EQ-003"]["state"], "blocked")
            self.assertEqual(rows["hb-killed"]["state"], "blocked")

            self.assertTrue((root / "out" / "p1_candidate_triage_dogfood.json").exists())
            self.assertTrue((root / "out" / "p1_candidate_triage_dogfood.md").exists())
            self.assertEqual(before[filed], filed.read_text(encoding="utf-8"))
            self.assertEqual(before[killed], killed.read_text(encoding="utf-8"))
            self.assertTrue(result["summary"]["no_draft_or_submission_edits"])

    def test_accepted_sidecar_is_distinct_from_suggestions(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            workspace, invariants = self.write_fixture(root)
            write_json(
                workspace / ".auditooor" / "p1_invariant_attribution_sidecar.json",
                {
                    "schema": "auditooor.p1_invariant_attribution_sidecar.v1",
                    "policy": {"non_submission_artifact": True},
                    "mappings": [
                        {
                            "candidate_id": "EQ-001",
                            "p1_invariant_id": "INV-UNI-001",
                            "attribution_status": "accepted_by_local_review",
                            "evidence": "local review accepted this invariant mapping",
                            "evidence_refs": ["source_proofs/EQ-001/source_proof.json"],
                        },
                        {
                            "candidate_id": "EQ-002",
                            "p1_invariant_id": "INV-BND-001",
                            "attribution_status": "suggested",
                            "suggested_only": True,
                        },
                    ],
                },
            )

            result = self.tool.run_triage(
                workspace,
                root / "out",
                invariant_paths=[invariants],
                max_suggestions=2,
            )
            rows = {row["candidate_id"]: row for row in result["candidate_rows"]}

            self.assertEqual(rows["EQ-001"]["state"], "accepted")
            self.assertEqual(rows["EQ-001"]["accepted_mappings"][0]["invariant_id"], "INV-UNI-001")
            self.assertEqual(rows["EQ-001"]["suggested_mappings"], [])
            self.assertEqual(rows["EQ-002"]["state"], "no-match")
            self.assertEqual(result["summary"]["states"]["accepted"], 1)
            self.assertEqual(result["summary"]["accepted_sidecar_mappings"], 1)
            self.assertTrue(result["summary"]["no_draft_or_submission_edits"])

    def test_accepted_sidecar_resolves_exact_pilot_ref_not_in_primary_source(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            workspace, invariants = self.write_fixture(root)
            pilot = root / "invariants_pilot.jsonl"
            pilot.write_text(
                json.dumps(
                    {
                        "invariant_id": "INV-FRESH-011",
                        "category": "freshness",
                        "statement": "State roots MUST be finalized before bridge verification consumes them.",
                        "target_lang": "any",
                        "commit_point_pattern": "accept root only after finality",
                        "defense_layer": "finality gate",
                    }
                )
                + "\n",
                encoding="utf-8",
            )
            write_json(
                workspace / ".auditooor" / "p1_invariant_attribution_sidecar.json",
                {
                    "schema": "auditooor.p1_invariant_attribution_sidecar.v1",
                    "policy": {"non_submission_artifact": True},
                    "mappings": [
                        {
                            "candidate_id": "EQ-001",
                            "p1_invariant_id": "INV-FRESH-011",
                            "attribution_status": "accepted_by_local_review",
                            "evidence": "local review accepted this exact pilot invariant mapping",
                            "evidence_refs": [f"{pilot}:1"],
                        }
                    ],
                },
            )

            original_pilot = self.tool.DEFAULT_PILOT
            self.tool.DEFAULT_PILOT = pilot
            try:
                result = self.tool.run_triage(
                    workspace,
                    root / "out",
                    invariant_paths=[invariants],
                    max_suggestions=2,
                )
            finally:
                self.tool.DEFAULT_PILOT = original_pilot
            rows = {row["candidate_id"]: row for row in result["candidate_rows"]}

            self.assertEqual(rows["EQ-001"]["state"], "accepted")
            self.assertEqual(rows["EQ-001"]["accepted_mappings"][0]["invariant_id"], "INV-FRESH-011")
            self.assertEqual(result["summary"]["accepted_sidecar_mappings"], 1)
            self.assertEqual(result["summary"]["accepted_sidecar_supplemental_invariants"], 1)
            self.assertNotIn(
                "unknown invariant: INV-FRESH-011",
                "\n".join(result["warnings"]),
            )

    def test_default_invariant_source_prefers_audited_primary(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            workspace, _ = self.write_fixture(root)
            audited = root / "invariants_pilot_audited.jsonl"
            extracted = root / "invariants_extracted.jsonl"
            pilot = root / "invariants_pilot.jsonl"
            audited.write_text(
                json.dumps(
                    {
                        "invariant_id": "INV-AUD-001",
                        "category": "uniqueness",
                        "statement": "Signed messages with nonces MUST reject replay.",
                        "target_lang": "solidity",
                        "commit_point_pattern": "consume nonce before message effect",
                        "defense_layer": "nonce mapping",
                    }
                )
                + "\n",
                encoding="utf-8",
            )
            extracted.write_text(
                json.dumps(
                    {
                        "invariant_id": "INV-BROAD-001",
                        "category": "uniqueness",
                        "statement": "Broad extracted template row about signed message replay.",
                        "target_lang": "solidity",
                        "commit_point_pattern": "nonce consumed",
                        "defense_layer": "template",
                    }
                )
                + "\n",
                encoding="utf-8",
            )
            pilot.write_text("", encoding="utf-8")
            self.tool.DEFAULT_AUDITED_PRIMARY = audited
            self.tool.DEFAULT_EXTRACTED = extracted
            self.tool.DEFAULT_PILOT = pilot

            result = self.tool.run_triage(workspace, root / "out")
            rows = {row["candidate_id"]: row for row in result["candidate_rows"]}

            self.assertEqual(result["summary"]["invariant_quality_source"], "audited_primary")
            self.assertFalse(result["summary"]["include_extracted_broad"])
            self.assertEqual(result["invariant_source_policy"]["paths"], [str(audited)])
            self.assertEqual(result["summary"]["indexed_invariant_count"], 1)
            self.assertEqual(rows["EQ-001"]["suggested_mappings"][0]["invariant_id"], "INV-AUD-001")
            self.assertNotIn(
                "INV-BROAD-001",
                {m["invariant_id"] for row in rows.values() for m in row["suggested_mappings"]},
            )

    def test_broad_extracted_rows_require_explicit_opt_in(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            audited = root / "invariants_pilot_audited.jsonl"
            extracted = root / "invariants_extracted.jsonl"
            pilot = root / "invariants_pilot.jsonl"
            audited.write_text("", encoding="utf-8")
            extracted.write_text("", encoding="utf-8")
            pilot.write_text("", encoding="utf-8")
            self.tool.DEFAULT_AUDITED_PRIMARY = audited
            self.tool.DEFAULT_EXTRACTED = extracted
            self.tool.DEFAULT_PILOT = pilot

            paths, policy, warnings = self.tool.resolve_invariant_paths()
            self.assertEqual(paths, [audited])
            self.assertEqual(policy["quality_source"], "audited_primary")
            self.assertFalse(policy["include_extracted_broad"])
            self.assertEqual(warnings, [])

            paths, policy, warnings = self.tool.resolve_invariant_paths(include_extracted=True)
            self.assertEqual(paths, [audited, extracted])
            self.assertEqual(policy["quality_source"], "audited_primary")
            self.assertTrue(policy["include_extracted_broad"])
            self.assertEqual(policy["broad_extracted_policy"], "opt_in_only")
            self.assertEqual(warnings, [])

            paths, policy, warnings = self.tool.resolve_invariant_paths([extracted])
            self.assertEqual(paths, [extracted])
            self.assertEqual(policy["quality_source"], "explicit")
            self.assertTrue(policy["explicit_invariants"])
            self.assertTrue(policy["include_extracted_broad"])
            self.assertEqual(warnings, [])


if __name__ == "__main__":
    unittest.main()
