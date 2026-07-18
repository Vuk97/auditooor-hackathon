from __future__ import annotations

import contextlib
import importlib.util
import io
import json
import tempfile
import unittest
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[2]
TOOL_PATH = REPO_ROOT / "tools" / "hackerman-etl-from-prior-audits.py"
VALIDATOR_PATH = REPO_ROOT / "tools" / "hackerman-record-validate.py"
FIXTURE_ROOT = REPO_ROOT / "tools" / "tests" / "fixtures" / "prior_audit_etl"


def _load(path: Path, name: str):
    spec = importlib.util.spec_from_file_location(name, str(path))
    mod = importlib.util.module_from_spec(spec)
    assert spec.loader
    spec.loader.exec_module(mod)
    return mod


class HackermanEtlFromPriorAuditsTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tool = _load(TOOL_PATH, "_hackerman_etl_from_prior_audits")
        self.validator = _load(VALIDATOR_PATH, "_hackerman_record_validate_for_etl")

    def test_segments_markdown_findings_conservatively(self) -> None:
        text = (FIXTURE_ROOT / "workspaces" / "alpha" / "prior_audits" / "report.md").read_text(
            encoding="utf-8"
        )
        segments = self.tool.segment_findings(text)
        self.assertEqual([segment.title for segment in segments], [
            "H-01 First depositor can inflate ERC4626 shares",
            "M-02 Oracle price can be stale during liquidation",
        ])

    def test_segments_markdown_finding_keeps_nested_subheadings(self) -> None:
        text = (
            "# Report\n\n"
            "## H-01 MsgServer path can bypass checks\n\n"
            "Summary paragraph.\n\n"
            "### Impact\n\n"
            "Users can be affected.\n\n"
            "### Recommendation\n\n"
            "Add guardrails.\n\n"
            "## M-02 Keeper accounting drift\n\n"
            "Second finding body.\n"
        )
        segments = self.tool.segment_findings(text)
        self.assertEqual(len(segments), 2)
        self.assertIn("### Impact", segments[0].body)
        self.assertIn("### Recommendation", segments[0].body)
        self.assertEqual(segments[0].heading_line, 3)

    def test_segments_plaintext_findings_for_go_cosmos_style_reports(self) -> None:
        text = (
            "Executive summary for auditors.\n\n"
            "H-01 MsgServer.PlaceOrder bypasses ValidateBasic in x/clob keeper\n"
            "Repository: dydxprotocol/v4-chain\n"
            "Attacker reaches a keeper path with malformed payload.\n"
            "Recommendation: enforce ValidateBasic before state transition.\n\n"
            "M-02 module account accounting can drift via IBC path\n"
            "A relayer-triggered path can desync balance accounting.\n"
            "Mitigation: verify module account and IAVL-backed state before commit.\n"
        )
        segments = self.tool.segment_findings(text)
        self.assertEqual([segment.title for segment in segments], [
            "H-01 MsgServer.PlaceOrder bypasses ValidateBasic in x/clob keeper",
            "M-02 module account accounting can drift via IBC path",
        ])
        self.assertEqual(segments[0].heading_line, 3)
        self.assertEqual(segments[1].heading_line, 8)

    def test_segments_pdf_field_blocks_and_prefers_severity_field(self) -> None:
        text = (
            "Table of Contents\n"
            "Findings\n\n"
            "Findings                                                                                          5\n"
            "\f© 2024 Informal Systems\n\n"
            "Keeping dYdX forks Updated with Slinky's Cosmos SDK and CometBFT\n"
            "referenced version\n\n"
            " Project                        dYdX 2024 Q2\n\n"
            " Type                            OTHER\n\n"
            " Severity                        INFORMATIONAL\n\n"
            " Impact                          HIGH\n\n"
            " Status                          ACKNOWLEDGED\n\n"
            "Description\n"
            "Custom fork changes can affect Slinky, Cosmos SDK, and CometBFT flows.\n\n"
            "Missing automatic detection of validators not reporting certain CP price updates\n\n"
            " Project                        dYdX 2024 Q2\n\n"
            " Type                            PROTOCOL\n\n"
            " Severity                        MEDIUM\n\n"
            " Impact                          HIGH\n\n"
            " Status                          ACKNOWLEDGED\n\n"
            "Description\n"
            "Validators can omit CP price updates and the protocol may not detect this.\n"
        )

        segments = self.tool.segment_findings(text)

        self.assertEqual(len(segments), 2)
        self.assertEqual(
            segments[0].title,
            "Keeping dYdX forks Updated with Slinky's Cosmos SDK and CometBFT referenced version",
        )
        self.assertEqual(
            segments[1].title,
            "Missing automatic detection of validators not reporting certain CP price updates",
        )
        self.assertEqual(self.tool.infer_severity(segments[0].body), "info")
        self.assertEqual(self.tool.infer_severity(segments[1].body), "medium")

    def test_segments_numbered_detailed_findings_without_toc_pollution(self) -> None:
        text = (
            "Contents\n"
            "3. Detailed Findings\n"
            "3.1. Critical issue in processMakerFill                                      12\n"
            "3.2. High issue in liquidation flag                                          14\n\n"
            "3. Detailed Findings   3.1. Critical issue in processMakerFill\n"
            "MakerFill permits fund theft when update ordering is wrong.\n\n"
            "Category            Coding Mistakes                     Severity          Critical\n"
            "Likelihood          High                                Impact            Critical\n\n"
            "Description\n"
            "The processMakerFill path updates the position after checking liquidation state.\n"
            "Recommendation\n"
            "Move the position update before the check.\n\n"
            "3.2. High issue in liquidation flag\n"
            "A liquidation path fails to reset a flag and can block user positions.\n\n"
            "Category            Coding Mistakes                     Severity          High\n"
            "Likelihood          High                                Impact            High\n\n"
            "Description\n"
            "The flag remains set after liquidation.\n"
            "Recommendation\n"
            "Reset the flag after the liquidation completes.\n"
        )

        segments = self.tool.segment_findings(text)

        self.assertEqual([segment.title for segment in segments], [
            "3.1. Critical issue in processMakerFill",
            "3.2. High issue in liquidation flag",
        ])
        self.assertEqual(self.tool.infer_severity(segments[0].body), "critical")
        self.assertEqual(self.tool.infer_severity(segments[1].body), "high")
        self.assertGreater(segments[0].heading_line, 4)

    def test_discover_docs_prefers_text_over_pdf_sibling(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            workspace = Path(tmp) / "alpha"
            audit_dir = workspace / "prior_audits"
            audit_dir.mkdir(parents=True)
            (audit_dir / "report.txt").write_text("H-01 Text sibling wins.\n", encoding="utf-8")
            (audit_dir / "report.pdf").write_bytes(b"%PDF-1.4 fake pdf bytes")

            docs = self.tool.discover_docs([workspace])

            self.assertEqual(len(docs), 1)
            self.assertEqual(docs[0].path.name, "report.txt")

    def test_extract_pdf_text_uses_pdftotext_when_available(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            pdf = Path(tmp) / "report.pdf"
            pdf.write_bytes(b"%PDF-1.4 fake pdf bytes")

            original_which = self.tool.shutil.which
            original_run = self.tool.subprocess.run
            try:
                self.tool.shutil.which = lambda cmd: "/usr/bin/pdftotext" if cmd == "pdftotext" else None

                def fake_run(cmd, capture_output, text, encoding, errors, check):
                    self.assertEqual(cmd[0], "/usr/bin/pdftotext")
                    self.assertEqual(cmd[-1], "-")
                    return self.tool.subprocess.CompletedProcess(cmd, 0, stdout="H-01 PDF extracted finding\nBody\n", stderr="")

                self.tool.subprocess.run = fake_run
                text, method = self.tool.extract_pdf_text(pdf)
            finally:
                self.tool.shutil.which = original_which
                self.tool.subprocess.run = original_run

            self.assertEqual(method, "pdftotext")
            self.assertIn("H-01 PDF extracted finding", text)

    def test_extract_records_infers_core_fields(self) -> None:
        workspace = FIXTURE_ROOT / "workspaces" / "alpha"
        records, counters = self.tool.extract_records([workspace])
        self.assertEqual(counters["documents_scanned"], 1)
        self.assertEqual(len(records), 2)
        first = records[0]
        self.assertEqual(first["severity_at_finding"], "high")
        self.assertEqual(first["target_language"], "solidity")
        self.assertEqual(first["target_domain"], "vault")
        self.assertEqual(first["bug_class"], "share-inflation")
        self.assertEqual(first["attack_class"], "first-deposit-share-inflation")
        self.assertEqual(first["target_repo"], "example/alpha-vault")

    def test_extract_records_infers_go_cosmos_hints_and_provenance(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            workspace = Path(tmp) / "dydx"
            source = workspace / "prior_audits" / "go-cosmos-findings.txt"
            source.parent.mkdir(parents=True)
            source.write_text(
                "H-01 MsgServer.PlaceOrder bypasses ValidateBasic in x/clob keeper\n"
                "Repository: dydxprotocol/v4-chain\n"
                "Malformed payloads can skip expected validation in a keeper state transition.\n"
                "Recommendation: call ValidateBasic and enforce module account invariants.\n\n"
                "M-02 ExtendVote path can be abused for consensus griefing\n"
                "CometBFT flow assumptions are too strict and can trigger repeated block failures.\n"
                "Mitigation: bound failures and harden PrepareProposal and ExtendVote handling.\n",
                encoding="utf-8",
            )
            records, counters = self.tool.extract_records([workspace])
            self.assertEqual(len(records), 2)
        first = records[0]
        self.assertEqual(first["target_language"], "go")
        self.assertEqual(first["target_repo"], "dydxprotocol/v4-chain")
        self.assertIn(first["target_domain"], {"dex", "consensus", "governance"})
        self.assertIn("MsgServer.PlaceOrder", first["target_component"])
        self.assertRegex(first["source_audit_ref"], r"prior-audit:dydx:prior_audits/go-cosmos-findings.txt:L1:S1")
        self.assertEqual(first["severity_at_finding"], "high")
        self.assertEqual(counters["pdf_documents"], 0)
        self.assertEqual(counters["documents_with_text"], 1)

    def test_extract_records_supports_standalone_corpus_text_files(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            source = Path(tmp) / "Astria Shared Sequencer April - Zellic Audit Report.txt"
            source.write_text(
                "Critical\n"
                "3.1 PrepareProposal can exceed CometBFT max bytes and halt consensus\n"
                "The Cosmos SDK application can emit an oversized proposal, repeatedly failing block production.\n"
                "Recommendation: bound proposal bytes before returning from PrepareProposal.\n",
                encoding="utf-8",
            )

            records, counters = self.tool.extract_records([], source_files=[source])

        self.assertEqual(len(records), 1)
        record = records[0]
        self.assertTrue(str(record["source_audit_ref"]).startswith("corpus-txt:"))
        self.assertTrue(str(record["record_id"]).startswith("corpus-txt:"))
        self.assertEqual(record["target_language"], "go")
        self.assertIn(record["target_domain"], {"consensus", "governance"})
        self.assertEqual(record["severity_at_finding"], "critical")
        self.assertEqual(counters["documents_scanned"], 1)
        self.assertEqual(counters["documents_with_text"], 1)

    def test_extract_records_infers_spark_chain_watcher_as_go_input_validation(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            workspace = Path(tmp) / "spark"
            source = workspace / "prior_audits" / "spark-chain-watcher.txt"
            source.parent.mkdir(parents=True)
            source.write_text(
                "H-01 Chain watcher accepts unrelated cooperative exit txid\n"
                "The statechain chain watcher records a txid for a UTXO without validating the cooperative exit body.\n"
                "A coop_exit path can mark leaf status as pending after key tweak while the sender keeps a refund.\n"
                "Recommendation: validate the Bitcoin transaction id and UTXO script before updating state.\n",
                encoding="utf-8",
            )

            records, _ = self.tool.extract_records([workspace])

            self.assertEqual(len(records), 1)
            record = records[0]
            self.assertEqual(record["target_language"], "go")
            self.assertEqual(record["target_domain"], "consensus")
            self.assertEqual(record["bug_class"], "input-validation")
            self.assertEqual(record["attack_class"], "missing-input-validation")

    def test_extract_records_supports_pdf_sources_via_local_extractor(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            workspace = Path(tmp) / "dydx"
            source = workspace / "prior_audits" / "report.pdf"
            source.parent.mkdir(parents=True)
            source.write_bytes(b"%PDF-1.4 fake pdf bytes")

            original_extract_pdf_text = self.tool.extract_pdf_text
            try:
                self.tool.extract_pdf_text = lambda _path: (
                    "H-01 MsgServer.PlaceOrder bypasses ValidateBasic in x/clob keeper\n"
                    "Repository: dydxprotocol/v4-chain\n"
                    "Malformed payloads can skip expected validation in a keeper state transition.\n"
                    "Recommendation: call ValidateBasic before commit.\n",
                    "pdftotext",
                )
                records, counters = self.tool.extract_records([workspace])
            finally:
                self.tool.extract_pdf_text = original_extract_pdf_text

            self.assertEqual(len(records), 1)
            self.assertEqual(records[0]["target_language"], "go")
            self.assertEqual(counters["pdf_documents"], 1)
            self.assertEqual(counters["pdf_text_extracted"], 1)
            self.assertEqual(counters["extraction_methods"]["pdftotext"], 1)

    def test_repo_inference_prefers_real_repos_over_path_fragments(self) -> None:
        self.assertEqual(
            self.tool.infer_repo("See https://github.com/dydxprotocol/v4-chain/blob/main/protocol/x/clob/keeper.go"),
            "dydxprotocol/v4-chain",
        )
        self.assertEqual(
            self.tool.infer_repo("See https://github.com/dydxprotocol/v4/blob/main/protocol/x/clob/keeper.go"),
            "dydxprotocol/v4-chain",
        )
        self.assertEqual(
            self.tool.infer_repo("See https://github.com/dydxprotocol/v4-/blob/main/protocol/x/clob/keeper.go"),
            "dydxprotocol/v4-chain",
        )
        self.assertEqual(
            self.tool.infer_repo("dYdX finding involving FOK/IOC order removal and protocol/x/clob paths."),
            "dydxprotocol/v4-chain",
        )
        self.assertEqual(
            self.tool.infer_repo("The subaccounts/keeper path and 2/3 threshold are mentioned without a repo."),
            "unknown",
        )
        self.assertEqual(self.tool.infer_repo("Finding references src/adapters/GeneralAdapter1.sol only."), "unknown")
        self.assertEqual(self.tool.infer_repo("Broken report URL https://github.com/centrifuge without repo slug."), "unknown")
        self.assertEqual(self.tool.infer_repo("Audit portal profile cantina.xyz/u/researcher is not a repo."), "unknown")
        self.assertEqual(self.tool.infer_repo("Resolved/partially and critical/major are status labels."), "unknown")
        self.assertEqual(self.tool.infer_repo("and/or, try/catch, bin/bash, transfer/mint are prose fragments."), "unknown")
        self.assertEqual(self.tool.infer_repo("functions/events and Upgrade/version are section labels."), "unknown")
        self.assertEqual(self.tool.infer_repo("N/A is not a repository."), "unknown")
        self.assertEqual(self.tool.infer_repo("Morpho/Cantina is a report label, not a repo."), "unknown")
        self.assertEqual(self.tool.infer_repo("Generic text with FOK/IOC, 2/3, and hours/days."), "unknown")
        self.assertEqual(self.tool.infer_repo("Only decaf377/src/r1cs path fragments appear."), "unknown")
        self.assertEqual(
            self.tool.infer_repo(
                "The decaf377/src/r1cs gadget accepts an incomplete witness.",
                (
                    "Scope: https://github.com/penumbra-zone/penumbra/tree/v0.56.0\n"
                    "Scope: https://github.com/penumbra-zone/decaf377/tree/0.4.0/src/r1cs\n"
                ),
            ),
            "penumbra-zone/decaf377",
        )

    def test_year_inference_uses_report_header_and_compact_date_filenames(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            phase_report = Path(tmp) / "Informal-Systems-Audit-Report-Phase-I-II.txt"
            phase_report.write_text(
                "Security Audit Report\nLast revised 15 September, 2023\n\nH-01 Later finding text without date.\n",
                encoding="utf-8",
            )

            self.assertEqual(self.tool.infer_year("H-01 Later finding text without date.", phase_report), 2023)
            self.assertEqual(
                self.tool.infer_year("No year in this segment.", Path(tmp) / "zcash-frost-audit-report-20210323.txt"),
                2021,
            )

    def test_component_inference_skips_generic_quoted_function_phrases(self) -> None:
        component = self.tool.infer_component(
            "H-01 Generic quoted component",
            "`function contains` appears in the PDF text, but Keeper.PlaceOrder in x/clob is the real component.",
        )

        self.assertEqual(component, "Keeper.PlaceOrder")

    def test_component_inference_skips_more_generic_function_phrases(self) -> None:
        component = self.tool.infer_component(
            "H-02 PDF prose phrases are not components",
            (
                "`function as` and `function to` appear in wrapped PDF prose, "
                "but x/clob/keeper/orders.go is the concrete component."
            ),
        )

        self.assertEqual(component, "x/clob/keeper/orders.go")

    def test_fix_pattern_skips_bare_recommendations_heading(self) -> None:
        fix = self.tool.infer_fix_pattern(
            "Description\n"
            "Market creation is permissionless.\n"
            "Recommendations\n"
            "Add an onlyOwner modifier to the createMarket function.\n",
            "access-control",
        )

        self.assertEqual(fix, "Add an onlyOwner modifier to the createMarket function.")

    def test_yaml_scalar_quotes_colon_values(self) -> None:
        self.assertEqual(self.tool.yaml_scalar("Recommendation:"), "\"Recommendation:\"")
        self.assertEqual(
            self.tool.yaml_scalar("prior-audit:dydx:prior_audits/report.txt:L1:S1"),
            "\"prior-audit:dydx:prior_audits/report.txt:L1:S1\"",
        )

    def test_cli_writes_schema_valid_yaml_with_deterministic_names(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            out_dir = Path(tmp) / "out"
            with contextlib.redirect_stdout(io.StringIO()):
                rc = self.tool.main(
                    [
                        "--audits-root",
                        str(FIXTURE_ROOT / "workspaces"),
                        "--workspace",
                        "alpha",
                        "--workspace",
                        "beta",
                        "--out-dir",
                        str(out_dir),
                        "--json-summary",
                    ]
                )
            self.assertEqual(rc, 0)
            files = sorted(out_dir.glob("*.yaml"))
            self.assertEqual(len(files), 3)
            self.assertEqual([path.name for path in files], sorted(path.name for path in files))
            schema = self.validator.load_schema()
            for path in files:
                status, errors = self.validator.validate_file(path, schema)
                self.assertEqual(status, "valid", (path, errors))

    def test_dry_run_and_limit_do_not_write(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            out_dir = Path(tmp) / "out"
            with contextlib.redirect_stdout(io.StringIO()):
                rc = self.tool.main(
                    [
                        "--workspace",
                        str(FIXTURE_ROOT / "workspaces" / "alpha"),
                        "--out-dir",
                        str(out_dir),
                        "--limit",
                        "1",
                        "--dry-run",
                        "--json-summary",
                    ]
                )
            self.assertEqual(rc, 0)
            self.assertFalse(out_dir.exists())
            records, _ = self.tool.extract_records([FIXTURE_ROOT / "workspaces" / "alpha"], limit=1)
            self.assertEqual(len(records), 1)

    # r36-rebuttal: lane advisory-prior-tier-stamp registered in .auditooor/agent_pathspec.json
    def test_default_records_omit_verification_tier_and_stay_v1(self) -> None:
        # Rule 37 regression lock: the legacy shape is preserved byte-for-byte
        # when --verification-tier is not passed.
        records, _ = self.tool.extract_records(
            [FIXTURE_ROOT / "workspaces" / "alpha"], limit=1
        )
        self.assertEqual(len(records), 1)
        record = records[0]
        self.assertEqual(record["schema_version"], "auditooor.hackerman_record.v1")
        self.assertNotIn("verification_tier", record)

    def test_verification_tier_stamps_field_and_bumps_schema_to_v11(self) -> None:
        records, _ = self.tool.extract_records(
            [FIXTURE_ROOT / "workspaces" / "alpha"],
            limit=1,
            verification_tier="tier-2-verified-public-archive",
        )
        self.assertEqual(len(records), 1)
        record = records[0]
        self.assertEqual(record["schema_version"], "auditooor.hackerman_record.v1.1")
        self.assertEqual(
            record["verification_tier"], "tier-2-verified-public-archive"
        )

    def test_cli_verification_tier_writes_schema_valid_v11_yaml(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            out_dir = Path(tmp) / "out"
            buf = io.StringIO()
            with contextlib.redirect_stdout(buf):
                rc = self.tool.main(
                    [
                        "--workspace",
                        str(FIXTURE_ROOT / "workspaces" / "alpha"),
                        "--out-dir",
                        str(out_dir),
                        "--verification-tier",
                        "tier-2-verified-public-archive",
                        "--json-summary",
                    ]
                )
            self.assertEqual(rc, 0)
            summary = json.loads(buf.getvalue().strip().splitlines()[-1])
            self.assertEqual(
                summary["verification_tier"], "tier-2-verified-public-archive"
            )
            self.assertEqual(
                summary["schema_version"], "auditooor.hackerman_record.v1.1"
            )
            files = sorted(out_dir.glob("*.yaml"))
            self.assertTrue(files)
            for path in files:
                parsed = self.validator.load_yaml(path)
                self.assertEqual(
                    parsed["verification_tier"], "tier-2-verified-public-archive"
                )
                # schema=None -> validator auto-detects v1.1 from schema_version.
                status, errors = self.validator.validate_file(path)
                self.assertEqual(status, "valid", (path, errors))

    def test_cli_rejects_unknown_verification_tier(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            out_dir = Path(tmp) / "out"
            with contextlib.redirect_stderr(io.StringIO()):
                with self.assertRaises(SystemExit):
                    self.tool.main(
                        [
                            "--workspace",
                            str(FIXTURE_ROOT / "workspaces" / "alpha"),
                            "--out-dir",
                            str(out_dir),
                            "--verification-tier",
                            "tier-1-officially-disclosed",
                        ]
                    )

    def test_cli_writes_stage_artifact(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            workspace = Path(tmp) / "pdfws"
            source = workspace / "prior_audits" / "report.pdf"
            source.parent.mkdir(parents=True)
            source.write_bytes(b"%PDF-1.4 fake pdf bytes")
            out_dir = Path(tmp) / "out"
            stage = Path(tmp) / "agent_outputs" / "stage.json"

            original_extract_pdf_text = self.tool.extract_pdf_text
            try:
                self.tool.extract_pdf_text = lambda _path: (
                    "# H-01 Access control bypass\n\n"
                    "High severity Solidity access control issue in example/protocol.\n",
                    "pdftotext",
                )
                with contextlib.redirect_stdout(io.StringIO()):
                    rc = self.tool.main(
                        [
                            "--workspace",
                            str(workspace),
                            "--out-dir",
                            str(out_dir),
                            "--stage-artifact-out",
                            str(stage),
                            "--json-summary",
                        ]
                    )
            finally:
                self.tool.extract_pdf_text = original_extract_pdf_text

            self.assertEqual(rc, 0)
            payload = json.loads(stage.read_text(encoding="utf-8"))
            self.assertEqual(payload["schema_version"], "auditooor.hackerman_prior_audit_stage.v1")
            self.assertEqual(payload["summary"]["pdf_documents"], 1)
            self.assertEqual(payload["summary"]["pdf_text_extracted"], 1)
            self.assertEqual(payload["documents"][0]["text_extraction_method"], "pdftotext")
            self.assertEqual(payload["documents"][0]["records_emitted"], 1)

    def test_record_id_is_schema_safe_when_source_path_has_spaces(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            workspace = Path(tmp) / "space ws"
            source = workspace / "prior_audits" / "Report With + Marker.txt"
            source.parent.mkdir(parents=True)
            source.write_text(
                "# H-01 Access control bypass\n\n"
                "High severity Solidity access control issue in example/protocol.\n",
                encoding="utf-8",
            )

            records, _ = self.tool.extract_records([workspace])

            self.assertEqual(len(records), 1)
            record = records[0]
            self.assertRegex(record["record_id"], r"^[A-Za-z0-9._:/-]{8,160}$")
            status, errors = self.validator.validate_file(
                self._write_temp_record(record),
                self.validator.load_schema(),
            )
            self.assertEqual(status, "valid", errors)

    def test_numeric_heading_component_stays_yaml_string(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            workspace = Path(tmp) / "numeric"
            source = workspace / "prior_audits" / "chainsecurity.txt"
            source.parent.mkdir(parents=True)
            source.write_text(
                "# H-01 Numeric component\n\n"
                "High severity Solidity accounting issue in `2025` for example/protocol.\n",
                encoding="utf-8",
            )

            records, _ = self.tool.extract_records([workspace])

            self.assertEqual(len(records), 1)
            path = self._write_temp_record(records[0])
            status, errors = self.validator.validate_file(path, self.validator.load_schema())
            self.assertEqual(status, "valid", errors)
            parsed = self.validator.load_yaml(path)
            self.assertEqual(parsed["target_component"], "2025")
            self.assertEqual(parsed["function_shape"]["shape_tags"][2], "2025")

    def test_yaml_dump_preserves_optional_numeric_enrichment_fields(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            workspace = Path(tmp) / "numeric-enrichment"
            source = workspace / "prior_audits" / "report.txt"
            source.parent.mkdir(parents=True)
            source.write_text(
                "# H-01 Access control bypass\n\n"
                "High severity Solidity access control issue in example/protocol.\n",
                encoding="utf-8",
            )

            records, _ = self.tool.extract_records([workspace])
            record = records[0]
            record["record_tier"] = "local-workspace"
            record["record_quality_score"] = 3.5
            record["source_extraction_method"] = "regex-derived"
            record["source_extraction_confidence"] = 0.75
            path = self._write_temp_record(record)
            status, errors = self.validator.validate_file(path, self.validator.load_schema())
            self.assertEqual(status, "valid", errors)
            parsed = self.validator.load_yaml(path)
            self.assertIsInstance(parsed["record_quality_score"], float)
            self.assertIsInstance(parsed["source_extraction_confidence"], float)

    def _write_temp_record(self, record):
        tmp = tempfile.NamedTemporaryFile("w", suffix=".yaml", delete=False, encoding="utf-8")
        path = Path(tmp.name)
        try:
            tmp.write(self.tool.yaml_dump(record))
        finally:
            tmp.close()
        self.addCleanup(lambda: path.exists() and path.unlink())
        return path


class HackermanEtlPriorAuditsB8ZkSpecializedTests(unittest.TestCase):
    """B8 (EXEC-WAVE-2-MULTI): verify the ZK-specialized parsing branch
    refuses to extract bare paragraph words as raw_signature and uses
    the ZK-aware attack-class taxonomy."""

    def setUp(self) -> None:
        self.tool = _load(TOOL_PATH, "_hackerman_etl_from_prior_audits_b8")

    def test_is_zk_source_path_matches_extracted_audits_zkbugs(self) -> None:
        self.assertTrue(
            self.tool.is_zk_source_path(Path("extracted_audits/zkbugs/trailofbits-telepathy.txt"))
        )
        self.assertTrue(
            self.tool.is_zk_source_path(Path("/abs/extracted_audits/zkbugs/x.txt"))
        )
        self.assertFalse(self.tool.is_zk_source_path(Path("prior_audits/dydx/q2-audit.txt")))

    def test_is_zk_content_density_threshold(self) -> None:
        # 5 hits across the keyword set triggers
        text = "circuit constraint witness prover verifier"
        self.assertTrue(self.tool.is_zk_content(text))
        # 4 hits should NOT trigger (threshold is 5)
        self.assertFalse(self.tool.is_zk_content("circuit constraint witness prover"))
        # generic Solidity prose should not trigger
        self.assertFalse(
            self.tool.is_zk_content("a typical solidity reentrancy bug in a vault contract")
        )

    def test_infer_zk_component_refuses_bare_paragraph_words(self) -> None:
        body = "The function out described in section 4.1 is broken."
        result = self.tool.infer_zk_component("Finding H-1: telepathy issue", body)
        self.assertEqual(result, "<unresolved-zk-component>")

    def test_infer_zk_component_accepts_rust_fn_signature(self) -> None:
        body = (
            "The vulnerable function is "
            "`fn is_nonnegative(&self) -> Result<Boolean<Fq>, SynthesisError>`."
        )
        result = self.tool.infer_zk_component("Finding H-1", body)
        self.assertIn("fn is_nonnegative", result)

    def test_infer_zk_component_accepts_circom_template(self) -> None:
        body = "The template G1BigIntToSignFlag(N, K) is missing a range check."
        result = self.tool.infer_zk_component("Finding H-1", body)
        self.assertEqual(result, "template G1BigIntToSignFlag(N, K)")

    def test_infer_zk_signature_refuses_to_synthesize_fn_bareword(self) -> None:
        self.assertEqual(
            self.tool.infer_zk_signature("<unresolved-zk-component>", "rust"),
            "<unresolved-zk-signature>",
        )

    def test_infer_zk_signature_preserves_well_formed_signature(self) -> None:
        sig = "fn modSub(a: Element, b: Element) -> Element"
        self.assertEqual(self.tool.infer_zk_signature(sig, "rust"), sig)

    def test_infer_zk_bug_and_attack_prefers_unconstrained_taxonomy(self) -> None:
        text = "the witness for the range check is unconstrained, allowing forgery."
        bug, attack = self.tool.infer_zk_bug_and_attack(text)
        self.assertEqual(bug, "zk-constraint")
        self.assertEqual(attack, "unconstrained-variable")

    def test_b8_end_to_end_refuses_fn_out_on_paragraph_body(self) -> None:
        """End-to-end: build_record on a zkbugs-pathed doc with a paragraph
        body that previously produced `fn out` must now refuse and emit
        an unresolved sentinel (or a well-formed signature).
        """
        with tempfile.TemporaryDirectory(prefix="b8-zk-end2end-") as tmp:
            tmpdir = Path(tmp)
            zk_dir = tmpdir / "extracted_audits" / "zkbugs"
            zk_dir.mkdir(parents=True)
            src = zk_dir / "synthetic.txt"
            src.write_text(
                "Finding H-1: telepathy issue\n"
                "The function out described in section 4.1 returns a wrong value.\n"
                "Circuit constraint witness prover verifier missing.\n",
                encoding="utf-8",
            )
            segment = self.tool.FindingSegment(
                title="Finding H-1: telepathy issue",
                body=(
                    "The function out described in section 4.1 returns a wrong value. "
                    "Circuit constraint witness prover verifier missing."
                ),
                heading_line=1,
                ordinal=1,
            )
            doc = self.tool.SourceDoc(
                workspace=tmpdir,
                audit_kind=self.tool.CORPUS_TEXT_AUDIT_KIND,
                path=src,
                rel_path=Path("extracted_audits/zkbugs/synthetic.txt"),
            )
            record = self.tool.build_record(doc, segment)
            raw_sig = record["function_shape"]["raw_signature"]
            self.assertNotEqual(
                raw_sig,
                "fn out",
                "B8 ZK branch must refuse to emit `fn out` on paragraph words",
            )
            self.assertTrue(
                raw_sig == "<unresolved-zk-signature>" or self.tool.is_zk_signature_shape(raw_sig),
                f"B8 ZK branch emitted suspect raw_signature: {raw_sig!r}",
            )


if __name__ == "__main__":
    unittest.main()
