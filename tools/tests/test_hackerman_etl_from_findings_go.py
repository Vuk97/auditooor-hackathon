from __future__ import annotations

import importlib.util
import json
import tempfile
import unittest
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[2]
TOOL = REPO_ROOT / "tools" / "hackerman-etl-from-findings-go.py"
VALIDATOR = REPO_ROOT / "tools" / "hackerman-record-validate.py"


def _load(path: Path, name: str):
    spec = importlib.util.spec_from_file_location(name, str(path))
    mod = importlib.util.module_from_spec(spec)
    assert spec.loader
    spec.loader.exec_module(mod)
    return mod


def _row(**overrides):
    row = {
        "finding_id": "spark-lead1-2026-05-06",
        "protocol": "Spark",
        "language": "go",
        "impact_tier": "critical",
        "bug_class": "go.bitcoin.txid_equality_without_utxo_spend_check",
        "github_ref": "github.com/buildonspark/spark@e8311d2",
        "summary": (
            "Chain-watcher accepts arbitrary txid as cooperative exit proof "
            "without verifying the transaction spends the leaf UTXO, causing direct loss."
        ),
        "provenance": {
            "source": "spark_engagement_back_feed",
            "kind": "submitted_critical",
            "engagement_date": "2026-05-06",
        },
    }
    row.update(overrides)
    return row


class HackermanFindingsGoEtlTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tool = _load(TOOL, "_hackerman_etl_from_findings_go")
        self.validator = _load(VALIDATOR, "_hackerman_record_validate_findings_go")
        self.tmp = tempfile.TemporaryDirectory(prefix="hackerman-findings-go-")
        self.root = Path(self.tmp.name)
        self.input = self.root / "findings_go_fixture.jsonl"
        self.out = self.root / "out"

    def tearDown(self) -> None:
        self.tmp.cleanup()

    def _write_rows(self, rows) -> None:
        self.input.write_text(
            "".join(json.dumps(row, sort_keys=True) + "\n" for row in rows),
            encoding="utf-8",
        )

    def _generated_records(self):
        return [
            self.validator.load_yaml(path)
            for path in sorted(self.out.glob("*.yaml"))
        ]

    def test_emits_schema_valid_records_without_extra_jsonl_fields(self) -> None:
        rows = [
            _row(),
            _row(
                finding_id="swival-go-crypto-005",
                protocol="go-stdlib-crypto",
                impact_tier="medium",
                bug_class="go.tls.context_cancel_after_completion",
                github_ref="github.com/golang/go (audit-pinned)",
                summary="HandshakeContext cancellation can race a completed TLS handshake.",
                provenance={
                    "source": "swival_go_crypto_audit_corpus",
                    "kind": "verified_audit_finding",
                    "affected_location": "src/crypto/tls/conn.go:1511",
                    "category": "TLS",
                    "fetched_at": "2026-05-07",
                },
                quality_score=0.65,
            ),
            _row(
                finding_id="GHSA-6447-269v-g68m",
                protocol="mezo-mezod",
                bug_class="go.evm.dual_context_statedb_stale_overwrite",
                github_ref="github.com/mezo-org/mezod@17af5fd",
                summary="ERC-20 bridgeOut burn erased by stale outer StateDB overwrite; real tokens released to attacker.",
                provenance={
                    "source": "github_security_advisory",
                    "ghsa_id": "GHSA-6447-269v-g68m",
                    "published_at": "2026-04-28T14:07:24Z",
                },
                fix_commit={"summary": "Propagate inner StateDB state changes to the outer StateDB."},
                source_refs=[{"file": "x/evm/statedb/statedb.go"}],
                detector_seeds=[{"slug": "go.evm.inner_statedb", "desc": "detect inner StateDB writes"}],
            ),
            _row(
                finding_id="ext-stepca-GHSA-q4r8-xm5f-56gw-2026-03-19",
                protocol="step-ca",
                bug_class="go.protocol.authorization_bypass_via_unsupported_message_type",
                github_ref="github.com/smallstep/certificates@<v0.30.0",
                summary="Unsupported SCEP message types fall through authorization checks.",
                provenance={
                    "source": "l23_external_advisory_recon",
                    "ghsa_id": "GHSA-q4r8-xm5f-56gw",
                    "scan_date": "2026-05-08",
                },
            ),
        ]
        self._write_rows(rows)

        summary = self.tool.convert_findings([self.input], self.out)

        self.assertEqual(summary["errors"], [])
        self.assertEqual(summary["rows_scanned"], 4)
        self.assertEqual(summary["rows_after_dedupe"], 4)
        self.assertEqual(summary["records_emitted"], 4)
        self.assertEqual(len(list(self.out.glob("*.yaml"))), 4)
        schema = self.validator.load_schema()
        for record in self._generated_records():
            self.assertEqual(self.validator.validate_doc(record, schema), [])
            self.assertEqual(record["target_language"], "go")
            self.assertNotIn("quality_score", record)
            self.assertNotIn("source_refs", record)
            self.assertNotIn("detector_seeds", record)
            self.assertNotIn("fix_commit", record)
        repos = {record["record_id"]: record["target_repo"] for record in self._generated_records()}
        self.assertIn("buildonspark/spark", repos.values())
        self.assertIn("golang/go", repos.values())
        self.assertIn("mezo-org/mezod", repos.values())
        self.assertIn("smallstep/certificates", repos.values())

    def test_repo_parser_handles_supported_refs_and_fallback(self) -> None:
        self.assertEqual(
            self.tool.repo_from_github_ref("github.com/buildonspark/spark@e8311d2"),
            "buildonspark/spark",
        )
        self.assertEqual(
            self.tool.repo_from_github_ref("github.com/smallstep/certificates@<v0.30.0"),
            "smallstep/certificates",
        )
        self.assertEqual(self.tool.repo_from_github_ref("not github"), "unknown")

    def test_deterministic_output_for_same_input(self) -> None:
        self._write_rows([_row()])
        first = self.tool.convert_findings([self.input], self.out)
        first_payload = {
            path.name: path.read_text(encoding="utf-8")
            for path in sorted(self.out.glob("*.yaml"))
        }

        second = self.tool.convert_findings([self.input], self.out)
        second_payload = {
            path.name: path.read_text(encoding="utf-8")
            for path in sorted(self.out.glob("*.yaml"))
        }

        self.assertEqual(first["errors"], [])
        self.assertEqual(second["errors"], [])
        self.assertEqual(first_payload, second_payload)

    def test_duplicate_finding_id_errors(self) -> None:
        self._write_rows([_row(), _row(summary="same id, different row")])

        summary = self.tool.convert_findings([self.input], self.out, dry_run=True)

        self.assertTrue(any("duplicate finding_id" in err for err in summary["errors"]))

    def test_duplicate_ghsa_is_skipped_after_first_row(self) -> None:
        self._write_rows(
            [
                _row(
                    finding_id="canonical-ghsa",
                    provenance={"ghsa_id": "GHSA-27vh-h6mc-q6g8", "published_at": "2026-01-01"},
                ),
                _row(
                    finding_id="duplicate-ghsa",
                    provenance={"ghsa_id": "GHSA-27vh-h6mc-q6g8", "published_at": "2026-01-02"},
                ),
            ]
        )

        summary = self.tool.convert_findings([self.input], self.out)

        self.assertEqual(summary["errors"], [])
        self.assertEqual(summary["rows_scanned"], 2)
        self.assertEqual(summary["rows_after_dedupe"], 1)
        self.assertEqual(summary["records_emitted"], 1)
        self.assertEqual(summary["duplicates_skipped"], 1)


if __name__ == "__main__":
    unittest.main()
