from __future__ import annotations

import importlib.util
import json
import sys
import tempfile
import unittest
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[2]
TOOL_PATH = REPO_ROOT / "tools" / "hackerman-proof-artifact-record-proposals.py"
VALIDATOR_PATH = REPO_ROOT / "tools" / "hackerman-record-validate.py"


def _load_module(path: Path, name: str):
    spec = importlib.util.spec_from_file_location(name, str(path))
    mod = importlib.util.module_from_spec(spec)
    assert spec and spec.loader
    sys.modules[spec.name] = mod
    spec.loader.exec_module(mod)
    return mod


class HackermanProofArtifactRecordProposalTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tool = _load_module(TOOL_PATH, "_hackerman_proof_artifact_record_proposals")
        self.validator = _load_module(VALIDATOR_PATH, "_hackerman_record_validate_for_proposals")
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)

    def tearDown(self) -> None:
        self.tmp.cleanup()

    def _write_packets(self, rows: list[dict[str, object]]) -> Path:
        path = self.root / "packets.jsonl"
        path.write_text("".join(json.dumps(row, sort_keys=True) + "\n" for row in rows), encoding="utf-8")
        return path

    def _packet(self, **overrides: object) -> dict[str, object]:
        packet: dict[str, object] = {
            "schema": self.tool.PACKET_SCHEMA,
            "source_queue_path": "reports/proof_artifact_missing_record_import_queue_slice10.jsonl",
            "queue_key": "paste_ready/filed/sample-CRITICAL.md",
            "engagement": "dydx",
            "submission_path": "audits/dydx/submissions/paste_ready/filed/sample-CRITICAL.md",
            "submission_status": "filed",
            "submission_title": "SubaccountFilter validation gap in AccountPlus permits permissioned-key fund movement from non-whitelisted subaccounts",
            "suggested_record_slug": "subaccountfilter-validation-gap-in-accountplus-permits-permissioned-key-fund-movement",
            "validation_status": "ready_for_manual_record_creation",
            "artifact_candidates": [
                {
                    "candidate_proof_path": "audits/dydx/external/v4-chain/protocol/x/clob/e2e/accountplus_sending_filter_poc_test.go",
                    "candidate_artifact_kind": "test-file",
                    "exists": True,
                    "blockers": [],
                }
            ],
        }
        packet.update(overrides)
        return packet

    def test_generates_schema_valid_submission_derived_record(self) -> None:
        packets = self._write_packets([self._packet()])
        out_dir = self.root / "tags"

        summary = self.tool.generate_records(packets, out_dir=out_dir)

        self.assertEqual(summary["records_emitted"], 1)
        files = list(out_dir.glob("*.yaml"))
        self.assertEqual(len(files), 1)
        doc = self.validator.load_yaml(files[0])
        self.assertEqual(doc["schema_version"], "auditooor.hackerman_record.v1.1")
        self.assertEqual(doc["record_tier"], "submission-derived")
        self.assertTrue(doc["verdict_artefact"])
        self.assertEqual(doc["proof_artifact_path"], "audits/dydx/external/v4-chain/protocol/x/clob/e2e/accountplus_sending_filter_poc_test.go")
        self.assertEqual(self.validator.validate_doc(doc), [])

    def test_dry_run_reports_existing_output_collisions(self) -> None:
        packets = self._write_packets([self._packet()])
        out_dir = self.root / "tags"
        self.tool.generate_records(packets, out_dir=out_dir)

        dry_summary = self.tool.generate_records(packets, out_dir=out_dir, dry_run=True)

        self.assertEqual(dry_summary["records_built"], 1)
        self.assertEqual(dry_summary["records_emitted"], 0)
        self.assertEqual(dry_summary["records_existing"], 1)
        self.assertEqual(dry_summary["failed_count"], 0)
        self.assertEqual(dry_summary["conversion_status"], "dry-run-already-materialized")
        self.assertEqual(dry_summary["skipped_counts"], {"output_exists": 1})
        self.assertEqual(len(dry_summary["existing_files"]), 1)

    def test_dry_run_reports_partial_existing_outputs(self) -> None:
        packets = self._write_packets(
            [
                self._packet(),
                self._packet(
                    queue_key="paste_ready/filed/sample-2-HIGH.md",
                    submission_path="audits/dydx/submissions/paste_ready/filed/sample-2-HIGH.md",
                    submission_title="Nil-pointer dereference in Cosmos SDK gov proposals query leads to remote query panic",
                    suggested_record_slug="nil-pointer-dereference-in-cosmos-sdk-gov-proposals-query",
                    artifact_candidates=[
                        {
                            "candidate_proof_path": "audits/dydx/external/v4-chain/protocol/x/gov/proposal_query_poc_test.go",
                            "candidate_artifact_kind": "test-file",
                            "exists": True,
                            "blockers": [],
                        }
                    ],
                ),
            ]
        )
        out_dir = self.root / "tags"
        first_packet = self.root / "first-packet.jsonl"
        first_packet.write_text(json.dumps(self._packet(), sort_keys=True) + "\n", encoding="utf-8")
        self.tool.generate_records(first_packet, out_dir=out_dir)

        dry_summary = self.tool.generate_records(packets, out_dir=out_dir, dry_run=True)

        self.assertEqual(dry_summary["records_built"], 2)
        self.assertEqual(dry_summary["records_emitted"], 1)
        self.assertEqual(dry_summary["records_existing"], 1)
        self.assertEqual(dry_summary["failed_count"], 0)
        self.assertEqual(dry_summary["conversion_status"], "dry-run-partial-existing")
        self.assertEqual(dry_summary["skipped_counts"], {"output_exists": 1})

    def test_real_run_blocks_existing_output_without_overwrite(self) -> None:
        packets = self._write_packets([self._packet()])
        out_dir = self.root / "tags"
        self.tool.generate_records(packets, out_dir=out_dir)

        summary = self.tool.generate_records(packets, out_dir=out_dir)

        self.assertEqual(summary["records_built"], 1)
        self.assertEqual(summary["records_emitted"], 0)
        self.assertEqual(summary["records_existing"], 1)
        self.assertEqual(summary["failed_count"], 0)
        self.assertEqual(summary["conversion_status"], "already-materialized")
        self.assertEqual(summary["skipped_counts"], {"output_exists": 1})

    def test_refuses_symlink_output_even_with_overwrite(self) -> None:
        packets = self._write_packets([self._packet()])
        out_dir = self.root / "tags"
        dry_summary = self.tool.generate_records(packets, out_dir=out_dir, dry_run=True)
        out_dir.mkdir(parents=True, exist_ok=True)
        target = self.root / "outside.yaml"
        target.write_text("sentinel: true\n", encoding="utf-8")
        Path(dry_summary["files"][0]).symlink_to(target)

        summary = self.tool.generate_records(packets, out_dir=out_dir, overwrite=True)

        self.assertEqual(summary["records_built"], 1)
        self.assertEqual(summary["records_emitted"], 0)
        self.assertEqual(summary["records_existing"], 0)
        self.assertEqual(summary["failed_count"], 1)
        self.assertEqual(summary["conversion_status"], "partial")
        self.assertEqual(summary["skipped_counts"], {"output_path_symlink": 1})
        self.assertEqual(target.read_text(encoding="utf-8"), "sentinel: true\n")

    def test_skips_not_ready_packets(self) -> None:
        packets = self._write_packets([self._packet(validation_status="blocked")])
        out_dir = self.root / "tags"

        summary = self.tool.generate_records(packets, out_dir=out_dir)

        self.assertEqual(summary["records_built"], 0)
        self.assertEqual(summary["records_emitted"], 0)
        self.assertEqual(summary["skipped_counts"], {"packet_not_ready": 1})

    def test_reports_proof_path_fanout(self) -> None:
        packets = self._write_packets(
            [
                self._packet(
                    artifact_candidates=[
                        {
                            "candidate_proof_path": "audits/dydx/poc-tests/a.go",
                            "candidate_artifact_kind": "test-file",
                            "exists": True,
                            "blockers": [],
                        },
                        {
                            "candidate_proof_path": "audits/dydx/poc-tests/a.log",
                            "candidate_artifact_kind": "execution-output",
                            "exists": True,
                            "blockers": [],
                        },
                    ]
                )
            ]
        )
        out_dir = self.root / "tags"

        summary = self.tool.generate_records(packets, out_dir=out_dir)

        self.assertEqual(summary["records_with_multiple_proof_paths"], 1)
        self.assertEqual(summary["max_proof_paths_per_record"], 2)

    def test_distinguishes_unsafe_proof_paths_from_missing_paths(self) -> None:
        packets = self._write_packets(
            [
                self._packet(
                    artifact_candidates=[
                        {
                            "candidate_proof_path": "../outside/poc.go",
                            "candidate_artifact_kind": "test-file",
                            "exists": True,
                            "blockers": [],
                        }
                    ]
                )
            ]
        )
        out_dir = self.root / "tags"

        summary = self.tool.generate_records(packets, out_dir=out_dir)

        self.assertEqual(summary["records_built"], 0)
        self.assertEqual(summary["records_emitted"], 0)
        self.assertEqual(summary["failed_count"], 1)
        self.assertEqual(summary["skipped_counts"], {"proof_artifact_path_unsafe": 1})

    def test_rejects_in_path_parent_segments(self) -> None:
        packets = self._write_packets(
            [
                self._packet(
                    artifact_candidates=[
                        {
                            "candidate_proof_path": "audits/dydx/../outside/poc.go",
                            "candidate_artifact_kind": "test-file",
                            "exists": True,
                            "blockers": [],
                        }
                    ]
                )
            ]
        )
        out_dir = self.root / "tags"

        summary = self.tool.generate_records(packets, out_dir=out_dir)

        self.assertEqual(summary["records_built"], 0)
        self.assertEqual(summary["records_emitted"], 0)
        self.assertEqual(summary["failed_count"], 1)
        self.assertEqual(summary["skipped_counts"], {"proof_artifact_path_unsafe": 1})

    def test_rejects_non_final_submission_status_even_when_packet_says_ready(self) -> None:
        packets = self._write_packets([self._packet(submission_status="packaged")])
        out_dir = self.root / "tags"

        summary = self.tool.generate_records(packets, out_dir=out_dir)

        self.assertEqual(summary["records_built"], 0)
        self.assertEqual(summary["records_emitted"], 0)
        self.assertEqual(summary["failed_count"], 1)
        self.assertEqual(summary["skipped_counts"], {"submission_status_not_eligible": 1})

    def test_quotes_dollar_class_that_starts_with_greater_than(self) -> None:
        packets = self._write_packets([self._packet(submission_title="Direct theft of LP funds", queue_key="paste_ready/filed/sample-CRITICAL.md")])
        out_dir = self.root / "tags"

        self.tool.generate_records(packets, out_dir=out_dir)

        doc = self.validator.load_yaml(next(out_dir.glob("*.yaml")))
        self.assertEqual(doc["impact_dollar_class"], ">=$1M")
        self.assertEqual(self.validator.validate_doc(doc), [])

    def test_status_only_titles_map_to_specific_bug_classes(self) -> None:
        packets = self._write_packets(
            [
                self._packet(
                    engagement="base-azul",
                    queue_key="ready/FN6-READY.md",
                    submission_title="Global Verifier.nullified flag can brick TEE/ZK proving for all AggregateVerifier clones",
                    artifact_candidates=[
                        {
                            "candidate_proof_path": "audits/base-azul/submissions/verification_runs/FN6_PROFILEFIX_VALIDATOR.presubmit.log",
                            "candidate_artifact_kind": "execution-output",
                            "exists": True,
                            "blockers": [],
                        }
                    ],
                ),
                self._packet(
                    engagement="polymarket",
                    queue_key="submitted/R77_archive/R77-08.md",
                    submission_title="NegRiskOperator unflag race: resolveQuestion preempts admin emergencyResolveQuestion due to DELAY_PERIOD = 0",
                    artifact_candidates=[
                        {
                            "candidate_proof_path": "audits/polymarket/pocs/test/r77/negrisk/08_negrisk_unflag_race.t.sol",
                            "candidate_artifact_kind": "test-file",
                            "exists": True,
                            "blockers": [],
                        }
                    ],
                ),
                self._packet(
                    engagement="polymarket",
                    queue_key="submitted/R77_archive/R77-13.md",
                    submission_title="WrappedCollateral lacks recovery for WCOL/underlying sent to the contract; mistransfers are permanently locked",
                    artifact_candidates=[
                        {
                            "candidate_proof_path": "audits/polymarket/pocs/test/r77/negrisk/13_wrapped_collateral_unwrap.t.sol",
                            "candidate_artifact_kind": "test-file",
                            "exists": True,
                            "blockers": [],
                        }
                    ],
                ),
            ]
        )
        out_dir = self.root / "tags"

        self.tool.generate_records(packets, out_dir=out_dir)

        docs = [self.validator.load_yaml(path) for path in out_dir.glob("*.yaml")]
        by_title = {doc["target_component"]: doc for doc in docs}
        self.assertEqual(
            by_title["Global Verifier.nullified flag can brick TEE/ZK proving for all AggregateVerifier clones"]["attack_class"],
            "global-finalization-freeze",
        )
        self.assertEqual(
            by_title["NegRiskOperator unflag race: resolveQuestion preempts admin emergencyResolveQuestion due to DELAY_PERIOD = 0"]["bug_class"],
            "race-condition",
        )
        self.assertEqual(
            by_title["WrappedCollateral lacks recovery for WCOL/underlying sent to the contract; mistransfers are permanently locked"]["attack_class"],
            "permanent-asset-lock",
        )
        for doc in docs:
            self.assertEqual(self.validator.validate_doc(doc), [])


if __name__ == "__main__":
    unittest.main()
