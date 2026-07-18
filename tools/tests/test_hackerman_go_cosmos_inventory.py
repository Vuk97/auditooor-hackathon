from __future__ import annotations

import importlib.util
import io
import json
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[2]
TOOL = REPO_ROOT / "tools" / "hackerman-go-cosmos-inventory.py"
STAGE_TOOL = REPO_ROOT / "tools" / "hackerman-go-cosmos-stage-imports.py"


def _load(path: Path, name: str):
    spec = importlib.util.spec_from_file_location(name, str(path))
    mod = importlib.util.module_from_spec(spec)
    assert spec.loader
    spec.loader.exec_module(mod)
    return mod


class HackermanGoCosmosInventoryTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tool = _load(TOOL, "_hackerman_go_cosmos_inventory")
        self.stage_tool = _load(STAGE_TOOL, "_hackerman_go_cosmos_stage_imports")
        self.tmp = tempfile.TemporaryDirectory(prefix="hackerman-go-cosmos-inventory-")
        self.root = Path(self.tmp.name)
        self.tag_dir = self.root / "audit" / "corpus_tags" / "tags"
        self.reference = self.root / "reference"
        self.tag_dir.mkdir(parents=True)
        self.reference.mkdir()

    def tearDown(self) -> None:
        self.tmp.cleanup()

    def _write_tag(self, name: str, body: str) -> None:
        (self.tag_dir / name).write_text(body, encoding="utf-8")

    def _write_findings_rows(self, rows: list[dict]) -> Path:
        path = self.reference / "findings_go.jsonl"
        path.write_text("".join(json.dumps(row, sort_keys=True) + "\n" for row in rows), encoding="utf-8")
        return path

    def _args(self, **overrides):
        return type(
            "Args",
            (),
            {
                "tag_dir": str(overrides.get("tag_dir", self.tag_dir)),
                "reference_root": str(overrides.get("reference_root", self.root)),
            },
        )()

    def test_inventory_reports_covered_and_uncovered_go_cosmos_inputs(self) -> None:
        self._write_tag(
            "findings-go-covered.yaml",
            """
schema_version: auditooor.hackerman_record.v1
record_id: findings-go:covered-cosmos:abc123
source_audit_ref: findings-go:reference/findings_go.jsonl:covered-cosmos
target_language: go
target_repo: cosmos/cosmos-sdk
target_domain: consensus
bug_class: go.cosmos.validatebasic_gap
""".strip()
            + "\n",
        )
        self._write_tag(
            "sibling-cosmos.yaml",
            """
schema_version: auditooor.hackerman_record.v1
record_id: legacy:sibling_cosmos-sdk_case:abc123
source_audit_ref: external_audit/zellic/cosmos-sdk/case
target_language: go
target_repo: cosmos/cosmos-sdk
target_domain: staking
bug_class: delegation-edge-cases
""".strip()
            + "\n",
        )
        self._write_findings_rows(
            [
                {
                    "finding_id": "covered-cosmos",
                    "protocol": "cosmos-sdk",
                    "language": "go",
                    "impact_tier": "high",
                    "bug_class": "go.cosmos.validatebasic_gap",
                    "github_ref": "github.com/cosmos/cosmos-sdk@abc",
                    "summary": "ValidateBasic gap in MsgServer keeper path.",
                    "provenance": {"source": "fixture"},
                },
                {
                    "finding_id": "new-dydx-consensus",
                    "protocol": "dydx",
                    "language": "go",
                    "impact_tier": "high",
                    "bug_class": "go.cosmos.extendvote_consensus_grief",
                    "github_ref": "github.com/dydxprotocol/v4-chain@def",
                    "summary": "CometBFT ExtendVote handling can grief consensus.",
                    "provenance": {"source": "fixture"},
                },
                {
                    "finding_id": "not-go",
                    "protocol": "solidity-protocol",
                    "language": "solidity",
                    "impact_tier": "high",
                    "bug_class": "access-control",
                    "github_ref": "github.com/example/solidity",
                    "summary": "Ignored by Go inventory.",
                    "provenance": {"source": "fixture"},
                },
            ]
        )
        prior = self.root / "alpha" / "prior_audits" / "report.txt"
        prior.parent.mkdir(parents=True)
        prior.write_text(
            "H-01 MsgServer.PlaceOrder bypasses ValidateBasic in x/clob keeper\n"
            "Repository: dydxprotocol/v4-chain\n"
            "Malformed payload reaches a Cosmos SDK keeper state transition.\n",
            encoding="utf-8",
        )

        report = self.tool.summarize(self._args())

        self.assertEqual(report["summary"]["tag_records_go_cosmos"], 2)
        self.assertEqual(report["summary"]["local_findings_go_rows"], 2)
        self.assertEqual(report["summary"]["local_prior_audit_candidate_docs"], 1)
        self.assertTrue(report["summary"]["importable_local_go_cosmos_records_found"])
        self.assertEqual(report["summary"]["local_importable_uncovered_records"], 2)
        candidate_paths = {item["source_path"] for item in report["candidate_import_targets"]}
        self.assertTrue(any(path.endswith("reference/findings_go.jsonl") for path in candidate_paths))
        self.assertTrue(any(path.endswith(str(prior.relative_to(self.root))) for path in candidate_paths))
        commands = "\n".join(item["ingest_command"] for item in report["candidate_import_targets"])
        self.assertIn("tools/hackerman-etl-from-findings-go.py", commands)
        self.assertIn("tools/hackerman-etl-from-prior-audits.py", commands)

    def test_cross_language_analogue_does_not_count_as_top_level_go_record(self) -> None:
        self._write_tag(
            "solidity-with-go-analogue.yaml",
            """
schema_version: auditooor.hackerman_record.v1
record_id: solidity:case:abc123
source_audit_ref: solodit-spec:case
target_language: solidity
target_repo: example/protocol
bug_class: access-control
cross_language_analogues:
  - target_language: go
    note: Cosmos SDK analogue only.
""".strip()
            + "\n",
        )

        report = self.tool.summarize(self._args())

        self.assertEqual(report["summary"]["tag_records_go_cosmos"], 0)
        self.assertEqual(report["coverage"]["tagged_by_source_family"], [])

    def test_nested_prior_audit_doc_is_covered_by_full_source_ref(self) -> None:
        prior = self.root / "extracted_audits" / "zkbugs" / "gnark.txt"
        prior.parent.mkdir(parents=True)
        prior.write_text(
            "H-01 Audit of Linea's gnark std\n"
            "Repository: Consensys/gnark\n"
            "A Go gadget can panic during proof verification.\n",
            encoding="utf-8",
        )
        self._write_tag(
            "covered-prior.yaml",
            f"""
schema_version: auditooor.hackerman_record.v1
record_id: "prior-audit:{self.root.name}:extracted_audits-zkbugs-gnark.txt:L1:S1:abc123"
source_audit_ref: "prior-audit:{self.root.name}:extracted_audits/zkbugs/gnark.txt:L1:S1"
target_language: go
target_repo: Consensys/gnark
target_domain: zk-proof
bug_class: denial-of-service
""".strip()
            + "\n",
        )

        report = self.tool.summarize(self._args())

        self.assertEqual(report["summary"]["local_prior_audit_candidate_docs"], 1)
        self.assertEqual(report["summary"]["local_importable_uncovered_records"], 0)
        self.assertFalse(report["summary"]["importable_local_go_cosmos_records_found"])

    def test_corpus_text_docs_are_discovered_and_covered_by_corpus_ref(self) -> None:
        corpus = self.reference / "corpus_txt" / "zellic" / "astria.txt"
        corpus.parent.mkdir(parents=True)
        corpus.write_text(
            "Critical\n"
            "3.1 PrepareProposal can exceed CometBFT max bytes and halt consensus\n"
            "The Cosmos SDK app can repeatedly fail block production.\n",
            encoding="utf-8",
        )

        report = self.tool.summarize(self._args())

        self.assertEqual(report["summary"]["local_audit_text_corpus_candidate_docs"], 1)
        self.assertEqual(report["summary"]["local_importable_uncovered_records"], 1)
        candidate = report["candidate_import_targets"][0]
        self.assertEqual(candidate["source_family"], "audit-text-corpus")
        self.assertIn("tools/hackerman-etl-from-prior-audits.py --source-file", candidate["ingest_command"])

        source_key = self.tool.rel(corpus)
        self._write_tag(
            "covered-corpus-text.yaml",
            f"""
schema_version: auditooor.hackerman_record.v1
record_id: "corpus-txt:{source_key}:L1:S1:abc123"
source_audit_ref: "corpus-txt:{source_key}:L1:S1"
target_language: go
target_repo: unknown
target_domain: consensus
bug_class: denial-of-service
""".strip()
            + "\n",
        )

        covered_report = self.tool.summarize(self._args())
        self.assertEqual(covered_report["summary"]["local_importable_uncovered_records"], 0)

    def test_corpus_text_doc_coverage_accepts_non_go_import_result(self) -> None:
        corpus = self.reference / "corpus_txt" / "zellic" / "astria-bridge.txt"
        corpus.parent.mkdir(parents=True)
        corpus.write_text(
            "Medium\n"
            "4.1 Bridge relayer can mishandle IBC packet retries\n"
            "The Cosmos bridge service can repeatedly retry packets and block progress.\n",
            encoding="utf-8",
        )
        source_key = self.tool.rel(corpus)
        self._write_tag(
            "covered-corpus-text-rust.yaml",
            f"""
schema_version: auditooor.hackerman_record.v1
record_id: "corpus-txt:{source_key}:L1:S1:abc123"
source_audit_ref: "corpus-txt:{source_key}:L1:S1"
target_language: rust
target_repo: astriaorg/astria-bridge
target_domain: bridge
bug_class: denial-of-service
""".strip()
            + "\n",
        )

        report = self.tool.summarize(self._args())

        self.assertEqual(report["summary"]["tag_records_go_cosmos"], 0)
        self.assertEqual(report["summary"]["local_audit_text_corpus_candidate_docs"], 1)
        self.assertEqual(report["summary"]["local_importable_uncovered_records"], 0)

    def test_candidate_targets_prioritize_dydx_relevant_sources(self) -> None:
        generic = self.reference / "corpus_txt" / "hexens" / "aa-generic-evm.txt"
        generic.parent.mkdir(parents=True)
        generic.write_text(
            "Security Review Report\n"
            "This Solidity smart contract report mentions Cosmos only in an appendix taxonomy.\n",
            encoding="utf-8",
        )
        gte = self.reference / "corpus_txt" / "zellic" / "zz-gte-clob.txt"
        gte.parent.mkdir(parents=True)
        gte.write_text(
            "Critical\n"
            "3.1 GTE CLOB matching engine can mis-handle liquidation accounting\n"
            "The keeper and module account flow resembles dYdX CLOB and perps liquidation paths.\n"
            "Recommendation: enforce accounting invariants before settlement.\n",
            encoding="utf-8",
        )

        report = self.tool.summarize(self._args())

        self.assertGreaterEqual(len(report["candidate_import_targets"]), 1)
        top = report["candidate_import_targets"][0]
        self.assertTrue(top["source_path"].endswith("zz-gte-clob.txt"))
        candidate_paths = {item["source_path"] for item in report["candidate_import_targets"]}
        self.assertFalse(any(path.endswith("aa-generic-evm.txt") for path in candidate_paths))

    def test_uncovered_inputs_are_classified_by_repo_family_and_priority(self) -> None:
        self._write_tag(
            "covered-cosmos-sdk.yaml",
            """
schema_version: auditooor.hackerman_record.v1
record_id: findings-go:covered-sdk:abc123
source_audit_ref: findings-go:reference/findings_go.jsonl:covered-sdk
target_language: go
target_repo: cosmos/cosmos-sdk
bug_class: input-validation
""".strip()
            + "\n",
        )
        self._write_findings_rows(
            [
                {
                    "finding_id": "covered-sdk",
                    "protocol": "cosmos-sdk",
                    "language": "go",
                    "bug_class": "input-validation",
                    "github_ref": "github.com/cosmos/cosmos-sdk@abc",
                    "summary": "Covered Cosmos SDK ValidateBasic path.",
                },
                {
                    "finding_id": "dydx-clob-critical",
                    "protocol": "dydx",
                    "language": "go",
                    "bug_class": "accounting",
                    "github_ref": "github.com/dydxprotocol/v4-chain@def",
                    "summary": "x/clob liquidation accounting can drift in a keeper.",
                },
                {
                    "finding_id": "cometbft-extendvote",
                    "protocol": "cometbft",
                    "language": "go",
                    "bug_class": "consensus",
                    "github_ref": "github.com/cometbft/cometbft@fed",
                    "summary": "ExtendVote handling can grief consensus.",
                },
                {
                    "finding_id": "ibc-packet-retry",
                    "protocol": "ibc-go",
                    "language": "go",
                    "bug_class": "bridge",
                    "github_ref": "github.com/cosmos/ibc-go@123",
                    "summary": "IBC packet retry handling can block a bridge flow.",
                },
            ]
        )

        report = self.tool.summarize(self._args())

        family_rows = {row["repo_family"]: row for row in report["coverage"]["repo_family_gap_rows"]}
        self.assertEqual(family_rows["dydx"]["uncovered_local_records"], 1)
        self.assertEqual(family_rows["dydx"]["staging_priority"], "P0-dydx-critical-proof")
        self.assertEqual(family_rows["cometbft"]["staging_priority"], "P1-consensus-core")
        self.assertEqual(family_rows["ibc"]["staging_priority"], "P2-ibc-bridge")
        uncovered_families = {row["repo_family"] for row in report["coverage"]["uncovered_by_repo_family"]}
        self.assertEqual({"dydx", "cometbft", "ibc"}, uncovered_families)

        top_priority = report["import_planning"]["top_staging_priorities"][0]
        self.assertEqual(top_priority["repo_family"], "dydx")
        self.assertEqual(top_priority["staging_priority"], "P0-dydx-critical-proof")
        self.assertIn("ingest_command", report["import_planning"]["mechanical_fields"])

    def test_candidate_targets_include_mechanical_family_priority_fields(self) -> None:
        corpus = self.reference / "corpus_txt" / "zellic" / "mezo-consensus.txt"
        corpus.parent.mkdir(parents=True)
        corpus.write_text(
            "High\n"
            "Mezo Cosmos SDK keeper can mishandle FinalizeBlock accounting\n"
            "The Mezo app uses MsgServer state transitions with module account drift.\n",
            encoding="utf-8",
        )

        report = self.tool.summarize(self._args())

        candidate = report["candidate_import_targets"][0]
        self.assertEqual(candidate["repo_family"], "mezo")
        self.assertEqual(candidate["staging_priority"], "P3-spark-mezo-adjacent")
        self.assertEqual(candidate["import_selector"]["repo_family"], "mezo")
        self.assertEqual(candidate["import_selector"]["source_path"], candidate["source_path"])

    def test_cosmos_taxonomy_only_evm_doc_is_not_import_candidate(self) -> None:
        generic = self.reference / "corpus_txt" / "hexens" / "aa-generic-evm.txt"
        generic.parent.mkdir(parents=True)
        generic.write_text(
            "Security Review Report\n"
            "This Solidity smart contract report mentions Cosmos only in an appendix taxonomy.\n"
            "The relevant finding is an ERC20 access-control issue.\n",
            encoding="utf-8",
        )

        report = self.tool.summarize(self._args())

        self.assertEqual(report["summary"]["local_audit_text_corpus_candidate_docs"], 0)
        self.assertEqual(report["candidate_import_targets"], [])

    def test_stage_imports_uses_ranked_candidate_targets(self) -> None:
        generic = self.reference / "corpus_txt" / "hexens" / "aa-generic-evm.txt"
        generic.parent.mkdir(parents=True)
        generic.write_text(
            "Security Review Report\n"
            "This Solidity smart contract report mentions Cosmos only in an appendix taxonomy.\n",
            encoding="utf-8",
        )
        gte = self.reference / "corpus_txt" / "zellic" / "zz-gte-clob.txt"
        gte.parent.mkdir(parents=True)
        gte.write_text(
            "Critical\n"
            "3.1 GTE CLOB matching engine can halt a keeper path\n"
            "The Cosmos SDK keeper, CLOB, and module account flow resembles dYdX.\n"
            "Recommendation: validate accounting before FinalizeBlock.\n",
            encoding="utf-8",
        )
        out_dir = self.root / "stage-ranked"
        stage_artifact = self.root / "stage_ranked.json"

        rc = self.stage_tool.main(
            [
                "--tag-dir",
                str(self.tag_dir),
                "--reference-root",
                str(self.root),
                "--out-dir",
                str(out_dir),
                "--stage-artifact-out",
                str(stage_artifact),
                "--limit",
                "1",
                "--json-summary",
            ]
        )

        self.assertEqual(rc, 0)
        payload = json.loads(stage_artifact.read_text(encoding="utf-8"))
        self.assertEqual(payload["source_files_selected"], [str(gte.resolve())])
        self.assertEqual(payload["documents_scanned"], 1)

    def test_cli_writes_json_and_markdown_outputs(self) -> None:
        self._write_findings_rows(
            [
                {
                    "finding_id": "new-cosmos",
                    "protocol": "cosmos-sdk",
                    "language": "go",
                    "impact_tier": "medium",
                    "bug_class": "go.cosmos.module_account_accounting",
                    "github_ref": "github.com/cosmos/cosmos-sdk@abc",
                    "summary": "Module account accounting drift in Cosmos SDK keeper.",
                    "provenance": {"source": "fixture"},
                }
            ]
        )
        json_out = self.root / "report.json"
        md_out = self.root / "report.md"

        json_rc = self.tool.main(
            [
                "--tag-dir",
                str(self.tag_dir),
                "--reference-root",
                str(self.root),
                "--json",
                "--out",
                str(json_out),
            ]
        )
        md_rc = self.tool.main(
            [
                "--tag-dir",
                str(self.tag_dir),
                "--reference-root",
                str(self.root),
                "--out",
                str(md_out),
            ]
        )

        self.assertEqual(json_rc, 0)
        self.assertEqual(md_rc, 0)
        payload = json.loads(json_out.read_text(encoding="utf-8"))
        self.assertEqual(payload["schema_version"], "auditooor.hackerman_go_cosmos_inventory.v1")
        self.assertIn("Candidate Import Targets", md_out.read_text(encoding="utf-8"))

    def test_stage_imports_cli_writes_valid_staging_artifact(self) -> None:
        corpus = self.reference / "corpus_txt" / "zellic" / "cosmos.txt"
        corpus.parent.mkdir(parents=True)
        corpus.write_text(
            "# Critical\n"
            "H-01 PrepareProposal can halt CometBFT consensus\n"
            "The Cosmos SDK app reaches a keeper path that panics during FinalizeBlock.\n",
            encoding="utf-8",
        )
        out_dir = self.root / "stage"
        stage_artifact = self.root / "stage_imports.json"

        rc = self.stage_tool.main(
            [
                "--tag-dir",
                str(self.tag_dir),
                "--reference-root",
                str(self.root),
                "--out-dir",
                str(out_dir),
                "--stage-artifact-out",
                str(stage_artifact),
                "--json-summary",
            ]
        )

        self.assertEqual(rc, 0)
        payload = json.loads(stage_artifact.read_text(encoding="utf-8"))
        self.assertEqual(payload["schema_version"], "auditooor.hackerman_go_cosmos_stage_imports.v1")
        self.assertEqual(payload["documents_scanned"], 1)
        self.assertEqual(payload["records_emitted"], 1)
        self.assertEqual(payload["validation"], {"valid": 1, "invalid": 0, "skipped": 0})
        self.assertEqual(payload["promotion_ready_records"], 0)
        self.assertEqual(payload["emitted_review_blocked_records"], 1)
        self.assertEqual(payload["review_status_counts"], {"needs_source_review": 1})
        self.assertEqual(
            payload["review_flag_counts"],
            {
                "line1_segment_review": 1,
                "unknown_target_repo": 1,
            },
        )
        self.assertEqual(len(payload["record_manifest"]), 1)
        manifest_row = payload["record_manifest"][0]
        self.assertEqual(manifest_row["validation_status"], "valid")
        self.assertEqual(manifest_row["target_language"], "go")
        self.assertIn("unknown_target_repo", manifest_row["review_flags"])
        self.assertIn("line1_segment_review", manifest_row["review_flags"])
        self.assertEqual(manifest_row["review_status"], "needs_source_review")
        self.assertFalse(manifest_row["promotion_ready"])
        self.assertEqual(len(list(out_dir.glob("*.yaml"))), 1)

    def test_stage_manifest_flags_cross_language_and_unknown_repo_rows(self) -> None:
        corpus = self.reference / "corpus_txt" / "zellic" / "gte.txt"
        corpus.parent.mkdir(parents=True)
        corpus.write_text(
            "High\n"
            "3.1 GTE CLOB market creation is permissionless\n"
            "Target CLOBFactory Category Coding Mistakes Severity High Likelihood High Impact High\n"
            "The createMarket function in the Solidity contract is currently permissionless.\n"
            "Recommendations\n"
            "Add an onlyOwner modifier to the createMarket function.\n",
            encoding="utf-8",
        )
        out_dir = self.root / "stage-review"
        stage_artifact = self.root / "stage_review.json"

        rc = self.stage_tool.main(
            [
                "--tag-dir",
                str(self.tag_dir),
                "--reference-root",
                str(self.root),
                "--out-dir",
                str(out_dir),
                "--stage-artifact-out",
                str(stage_artifact),
                "--json-summary",
            ]
        )

        self.assertEqual(rc, 0)
        payload = json.loads(stage_artifact.read_text(encoding="utf-8"))
        self.assertEqual(payload["records_emitted"], 0)
        self.assertEqual(payload["context_records_filtered"], 1)
        self.assertEqual(payload["promotion_ready_records"], 0)
        self.assertEqual(payload["emitted_review_blocked_records"], 0)
        self.assertEqual(payload["review_status_counts"], {"context_only_not_promoted": 1})
        self.assertEqual(payload["record_manifest"], [])
        row = payload["context_record_manifest"][0]
        self.assertEqual(row["review_status"], "context_only_not_promoted")
        self.assertIn("cross_language_not_go", row["review_flags"])
        self.assertIn("unknown_target_repo", row["review_flags"])
        self.assertNotEqual(row["fix_pattern"], "Recommendations")

    def test_stage_validation_ignores_stale_yaml_from_previous_runs(self) -> None:
        corpus = self.reference / "corpus_txt" / "zellic" / "cosmos.txt"
        corpus.parent.mkdir(parents=True)
        corpus.write_text(
            "# High\n"
            "H-01 MsgServer keeper panic can halt CometBFT consensus\n"
            "The Cosmos SDK app reaches FinalizeBlock and the keeper panics.\n",
            encoding="utf-8",
        )
        out_dir = self.root / "stage-stale"
        out_dir.mkdir()
        (out_dir / "stale-invalid.yaml").write_text("not: a hackerman record\n", encoding="utf-8")
        stage_artifact = self.root / "stage_stale.json"

        rc = self.stage_tool.main(
            [
                "--tag-dir",
                str(self.tag_dir),
                "--reference-root",
                str(self.root),
                "--out-dir",
                str(out_dir),
                "--stage-artifact-out",
                str(stage_artifact),
                "--json-summary",
            ]
        )

        self.assertEqual(rc, 0)
        payload = json.loads(stage_artifact.read_text(encoding="utf-8"))
        self.assertEqual(payload["records_emitted"], 1)
        self.assertEqual(payload["validation"], {"valid": 1, "invalid": 0, "skipped": 0})

    def test_sig_extract_source_family_recognized(self) -> None:
        """Wave-3 Tier-C C1: hackerman-etl-from-sig-extracts.py emits
        records with source_audit_ref starting ``sig-extract:`` and
        ``target_language: go``. The inventory must classify them as
        scope=cosmos source_family=sig-extract so the expanded corpus
        is observable in coverage reports rather than vanishing into
        the 'unknown' bucket."""
        self._write_tag(
            "sig-extract-sample.yaml",
            """
schema_version: auditooor.hackerman_record.v1
record_id: "sig-extract:dydx-v4-chain:protocol-x-clob-keeper:place-order:abc123"
source_audit_ref: "sig-extract:dydx-v4-chain.jsonl:protocol/x/clob/keeper/keeper.go:PlaceOrder:L1-L40"
target_language: go
target_repo: dydxprotocol/v4-chain
target_domain: dex
bug_class: matching-engine
attack_class: matching-engine-corruption
""".strip()
            + "\n",
        )
        report = self.tool.summarize(self._args())
        self.assertEqual(report["summary"]["tag_records_go_cosmos"], 1)
        families = report["coverage"]["tagged_by_source_family"]
        self.assertTrue(
            any(row.get("source_family") == "sig-extract" for row in families),
            f"expected source_family 'sig-extract' in {families}",
        )

    def test_canonical_corpus_meets_wave3_go_cosmos_floor(self) -> None:
        """Wave-3 Tier-C C1 success gate: after running Wave-3 expansion
        the canonical ``audit/corpus_tags/tags/`` directory must hold
        at least 1500 ``target_language: go`` records.

        We resolve the canonical tag dir via the inventory tool's
        DEFAULT_TAG_DIR symbol so this test stays correct if the layout
        moves. If the canonical tag dir is missing (e.g. running the
        unit test suite in a stripped checkout that has no corpus, or
        in CI that mounts only ``tools/``), the assertion is skipped
        with a clear message rather than failing closed - the gate
        only fires when the corpus is actually present.
        """
        canonical_tag_dir = self.tool.DEFAULT_TAG_DIR
        if not canonical_tag_dir.exists():
            self.skipTest(
                f"canonical tag dir not present at {canonical_tag_dir}; "
                "Wave-3 floor only enforces when the corpus is mounted."
            )
        report = self.tool.summarize(self._args(tag_dir=canonical_tag_dir))
        go_records = report["summary"]["tag_records_go_cosmos"]
        self.assertGreaterEqual(
            go_records,
            1500,
            (
                f"Wave-3 Tier-C C1 expansion floor: expected >=1500 Go/Cosmos "
                f"tag records in {canonical_tag_dir}, got {go_records}. "
                "Run tools/hackerman-go-cosmos-expand.py + "
                "tools/hackerman-etl-from-sig-extracts.py to refresh."
            ),
        )

    def test_stage_cli_text_summary_surfaces_review_readiness(self) -> None:
        corpus = self.reference / "corpus_txt" / "zellic" / "cosmos.txt"
        corpus.parent.mkdir(parents=True)
        corpus.write_text(
            "# Critical\n"
            "H-01 PrepareProposal can halt CometBFT consensus\n"
            "The Cosmos SDK app reaches a keeper path that panics during FinalizeBlock.\n",
            encoding="utf-8",
        )
        out_dir = self.root / "stage-text"
        stage_artifact = self.root / "stage_text.json"
        stdout = io.StringIO()

        with redirect_stdout(stdout):
            rc = self.stage_tool.main(
                [
                    "--tag-dir",
                    str(self.tag_dir),
                    "--reference-root",
                    str(self.root),
                    "--out-dir",
                    str(out_dir),
                    "--stage-artifact-out",
                    str(stage_artifact),
                ]
            )

        self.assertEqual(rc, 0)
        output = stdout.getvalue()
        self.assertIn("promotion_ready=0", output)
        self.assertIn("review_blocked=1", output)
        self.assertIn("context_only=0", output)


if __name__ == "__main__":
    unittest.main()
