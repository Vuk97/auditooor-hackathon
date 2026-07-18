"""Tests for tools/antipattern-catalog-build.py and tools/lib/antipattern_schema.py.

Schema: auditooor.antipattern_catalog.v1 (PLAN-P3 prescaffold).

Coverage:
  * Schema validation passes on the 5 hand-curated solidity patterns shipped
    under obsidian-vault/anti-patterns/v2/solidity/.
  * Schema rejects malformed records (wrong schema_version, missing keys,
    bad enum values, severity_floor > ceiling, bad FPR, too few sources).
  * ``--list`` enumerates exactly the 5 patterns.
  * ``--validate`` exits 0 on the canonical set.
  * ``--scan-corpus`` returns the 5 hand-curated patterns with the
    documented TBD note.
  * ``--query`` runs a bounded lexical grep MVP with explicit matched,
    no_matches, semantic command-plan query_degraded, query_unsupported, and
    query_error states; unknown pattern_id is a clean non-2 exit.
  * Loaded JSON conforms to the schema_version constant.
  * Re-list is idempotent (catalog load is pure).
"""
from __future__ import annotations

import io
import json
import os
import re
import subprocess
import sys
import tempfile
import unittest
from contextlib import redirect_stdout, redirect_stderr
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[2]
TOOL_PATH = REPO_ROOT / "tools" / "antipattern-catalog-build.py"
CATALOG_ROOT = REPO_ROOT / "obsidian-vault" / "anti-patterns" / "v2"

# Make tools.lib + the catalog tool importable as modules.
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

import importlib.util  # noqa: E402

from tools.lib.antipattern_schema import (  # noqa: E402
    SCHEMA_VERSION,
    AntipatternValidationError,
    validate_record,
    is_valid_record,
)


def _import_catalog_tool():
    """Import the dash-named script as a module."""
    spec = importlib.util.spec_from_file_location(
        "antipattern_catalog_build", TOOL_PATH
    )
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


CATALOG_TOOL = _import_catalog_tool()


def _canonical_record() -> dict:
    return {
        "schema_version": SCHEMA_VERSION,
        "pattern_id": "solidity.example-canonical-pattern",
        "category": "reentrancy",
        "language": "solidity",
        "severity_floor": "low",
        "severity_ceiling": "high",
        "query_type": "slither-detector",
        "query_source": "detectors/foo.py:1",
        "description": "Example canonical record for unit testing only.",
        "false_positive_rate_estimate": 0.25,
        "source_finding_ids": [
            "corpus-mined:slice_a:L1:S1:hash1",
            "corpus-mined:slice_b:L2:S2:hash2",
        ],
        "target_invariants": ["INV-ORD-001"],
    }


class SchemaValidationTests(unittest.TestCase):
    def test_canonical_record_passes(self) -> None:
        rec = _canonical_record()
        self.assertIs(validate_record(rec), rec)
        self.assertTrue(is_valid_record(rec))

    def test_wrong_schema_version_rejected(self) -> None:
        rec = _canonical_record()
        rec["schema_version"] = "auditooor.antipattern_catalog.v0"
        with self.assertRaises(AntipatternValidationError) as ctx:
            validate_record(rec)
        self.assertIn("schema_version", str(ctx.exception))

    def test_missing_required_key_rejected(self) -> None:
        rec = _canonical_record()
        del rec["category"]
        with self.assertRaises(AntipatternValidationError) as ctx:
            validate_record(rec)
        self.assertIn("category", str(ctx.exception))

    def test_bad_pattern_id_rejected(self) -> None:
        rec = _canonical_record()
        rec["pattern_id"] = "Solidity Bad Pattern ID"
        with self.assertRaises(AntipatternValidationError):
            validate_record(rec)

    def test_bad_category_rejected(self) -> None:
        rec = _canonical_record()
        rec["category"] = "not-a-real-category"
        with self.assertRaises(AntipatternValidationError):
            validate_record(rec)

    def test_bad_language_rejected(self) -> None:
        rec = _canonical_record()
        rec["language"] = "esperanto"
        with self.assertRaises(AntipatternValidationError):
            validate_record(rec)

    def test_floor_greater_than_ceiling_rejected(self) -> None:
        rec = _canonical_record()
        rec["severity_floor"] = "critical"
        rec["severity_ceiling"] = "low"
        with self.assertRaises(AntipatternValidationError) as ctx:
            validate_record(rec)
        self.assertIn("severity_floor", str(ctx.exception))

    def test_bad_fpr_out_of_range_rejected(self) -> None:
        rec = _canonical_record()
        rec["false_positive_rate_estimate"] = 1.5
        with self.assertRaises(AntipatternValidationError):
            validate_record(rec)

    def test_bad_fpr_wrong_type_rejected(self) -> None:
        rec = _canonical_record()
        rec["false_positive_rate_estimate"] = "high"
        with self.assertRaises(AntipatternValidationError):
            validate_record(rec)

    def test_too_few_source_ids_rejected(self) -> None:
        rec = _canonical_record()
        rec["source_finding_ids"] = ["only-one-id"]
        with self.assertRaises(AntipatternValidationError):
            validate_record(rec)

    def test_empty_target_invariants_allowed(self) -> None:
        rec = _canonical_record()
        rec["target_invariants"] = []
        # Empty list is intentionally allowed (patterns may exist without an
        # P1 invariant binding yet); the schema requires the key to be a list.
        self.assertTrue(is_valid_record(rec))

    def test_description_too_short_rejected(self) -> None:
        rec = _canonical_record()
        rec["description"] = "short"
        with self.assertRaises(AntipatternValidationError):
            validate_record(rec)


class CatalogLoadTests(unittest.TestCase):
    """Tests that exercise the on-disk hand-curated catalog."""

    def test_catalog_loads_sixty_two_patterns(self) -> None:
        records = CATALOG_TOOL.load_catalog(CATALOG_ROOT)
        self.assertGreaterEqual(
            len(records),
            130,
            f"expected catalog floor >=130 patterns, got {len(records)}",
        )
        ids = {r["pattern_id"] for r in records}
        expected = {
            # solidity prescaffold (P3-SOLIDITY-COLLAPSE-PRESCAFF)
            "solidity.unchecked-external-call-return-value",
            "solidity.reentrancy-without-modifier",
            "solidity.unbounded-loop-over-user-input",
            "solidity.block-timestamp-as-randomness-source",
            "solidity.tx-origin-for-authorization",
            # go prescaffold (P3-GO-PRESCAFF)
            "go.mutex-unlock-not-deferred",
            "go.nil-pointer-deref-before-check",
            "go.unbounded-slice-allocation-from-user-input",
            "go.concurrent-map-write-no-sync",
            "go.error-not-checked-from-state-write",
            # rust/substrate prescaffold (HB-P3-RUST-PRESCAFF)
            "substrate-rust.call-decompressor-validate-unsigned-size-cap-mismatch",
            "substrate-rust.attacker-controlled-scale-string-length",
            "rust-solana-anchor.remaining-accounts-cpi-unvalidated",
            "rust-solana-anchor.spl-token-mint-account-mismatch",
            # HB-P3-FULL first-batch conservative expansion
            "solidity.swap-missing-min-out-or-deadline",
            "solidity.erc4626-first-deposit-share-inflation",
            "solidity.signature-domain-replay-missing-chain-binding",
            "solidity.proxy-initializer-replay-or-callable-implementation",
            "rust.oracle-cache-missing-per-asset-freshness",
            "rust.unchecked-integer-cast-or-addition",
            "go-cosmos-sdk.ibc-packet-denom-or-ack-missing-validation",
            "go-cosmos-sdk.msgserver-authority-update-without-authority-binding",
            "move.signer-capability-stored-or-leaked",
            "move.oracle-price-used-without-freshness-check",
            "circom.unconstrained-witness-assignment-consumed",
            "circom.missing-range-check-on-field-element",
            "halo2.fiat-shamir-transcript-domain-confusion",
            "halo2.verifier-public-input-not-bound",
            # HB-P3-HYPERBRIDGE-GAP-PATTERNS
            "substrate-rust.cross-chain-consensus-client-nonfinal-state-root",
            "solidity.exact-output-refund-recipient-mismatch-pooled-escrow",
            # V3-P3-SOLIDITY-BATCH-01
            "solidity.cross-domain-optimistic-veto-denominator-mismatch",
            "solidity.erc4626-balanceof-self-donation-share-inflation",
            "solidity.exact-output-fee-asymmetry",
            "solidity.exact-output-low-decimal-descale-up",
            "solidity.l2-oracle-unfinalized-confirmation-check",
            "solidity.native-eth-removeliquidity-reentrancy-stale-reserves",
            "solidity.opposed-trace-defense-signer-withholding",
            "solidity.public-poke-reward-rounding-suppression",
            "solidity.wrapper-refund-fee-payer-mismatch",
            "solidity.zap-liquidity-zero-inner-slippage",
            # V3-P3-SOLIDITY-BATCH-02
            "solidity.batch02-bridge-message-domain-or-nonce-not-bound",
            "solidity.batch02-erc4626-max-view-actual-path-divergence",
            "solidity.batch02-exact-output-one-leg-rounding-drain",
            "solidity.batch02-fee-reward-split-truncation-dust-stranding",
            "solidity.batch02-governance-quorum-denominator-cast-votes",
            "solidity.batch02-native-transfer-before-accounting-reentrancy",
            "solidity.batch02-optimistic-oracle-callback-refund-state-desync",
            "solidity.batch02-role-key-compromise-boundary-confusion",
            "solidity.batch02-slippage-bound-checked-on-wrong-leg",
            "solidity.batch02-wrapper-full-balance-refund-sweep",
            # CAP-004/005/006/007/018/019 precision detector rows
            "solidity.inverted-verify-return",
            "solidity.division-by-zero",
            "solidity.erc2771-msgsender-forgery",
            "solidity.external-call-before-state-update",
            "solidity.pausable-no-unpause-exposed",
            "solidity.lzreceive-no-sender-check",
            # V3-P3-RUST-GO-ZK-SUBSTRATE-BATCH-03
            "go.bridge-message-hash-missing-source-domain-binding",
            "go.oracle-median-allows-stale-observation-window",
            "go-cosmos-sdk.ibc-timeout-height-or-timestamp-not-enforced",
            "go-cosmos-sdk.oracle-vote-extension-aggregate-missing-validator-binding",
            "rust.bridge-attestation-quorum-counts-duplicate-signers",
            "rust.bridge-message-hash-missing-lane-or-chain-domain",
            "rust.oracle-decimal-normalization-mismatch-between-feed-and-asset",
            "substrate-rust.bridge-outbound-nonce-incremented-before-dispatch-ack",
            "substrate-rust.oracle-offchain-worker-price-accepted-without-era-bound",
            "substrate-rust.xcm-origin-location-converted-without-filter",
            "circom.poseidon-merkle-path-index-bit-not-binary-constrained",
            "halo2.lookup-enable-flag-not-constrained-to-selector-domain",
        }
        self.assertTrue(
            expected.issubset(ids),
            "expected baseline pattern ids to remain present in catalog",
        )

    def test_each_catalog_record_passes_validation(self) -> None:
        records = CATALOG_TOOL.load_catalog(CATALOG_ROOT)
        for rec in records:
            with self.subTest(pattern_id=rec["pattern_id"]):
                # load_catalog already validates, but re-run defensively to
                # guard against any future loader that skips validation.
                self.assertTrue(is_valid_record(rec))

    def test_no_catalog_records_use_slither_detector_query_type(self) -> None:
        records = CATALOG_TOOL.load_catalog(CATALOG_ROOT)
        slither_ids = {
            r["pattern_id"]
            for r in records
            if r["query_type"] == "slither-detector"
        }
        self.assertEqual(slither_ids, set())
        self.assertEqual(
            set(CATALOG_TOOL.SLITHER_QUERY_DETECTOR_ARGUMENTS),
            {
                "solidity.unchecked-external-call-return-value",
                "solidity.reentrancy-without-modifier",
                "solidity.unbounded-loop-over-user-input",
            },
        )

    def test_re_list_is_idempotent(self) -> None:
        a = CATALOG_TOOL.load_catalog(CATALOG_ROOT)
        b = CATALOG_TOOL.load_catalog(CATALOG_ROOT)
        self.assertEqual(
            [r["pattern_id"] for r in a],
            [r["pattern_id"] for r in b],
        )

    def test_go_patterns_validate_against_schema(self) -> None:
        """Lane P3-GO-PRESCAFF specific: every Go YAML round-trips through
        the schema validator independently of the Solidity siblings."""
        records = CATALOG_TOOL.load_catalog(CATALOG_ROOT)
        go_records = [r for r in records if r["language"] == "go"]
        self.assertGreaterEqual(
            len(go_records),
            7,
            f"expected Go anti-pattern floor >=7, got {len(go_records)}",
        )
        for rec in go_records:
            with self.subTest(pattern_id=rec["pattern_id"]):
                # Re-validate to guard against any future loader that skips
                # validation, mirroring the test_each_catalog_record check
                # but scoped to the Go subset.
                self.assertTrue(is_valid_record(rec))
                # Every Go pattern must cite >=2 corpus source_finding_ids
                # and >=1 target invariant.
                self.assertGreaterEqual(len(rec["source_finding_ids"]), 2)
                self.assertGreaterEqual(len(rec["target_invariants"]), 1)
                # Go-family pattern_ids should use either the core Go or
                # Cosmos-SDK Go namespace.
                self.assertTrue(
                    rec["pattern_id"].startswith(("go.", "go-cosmos-sdk.")),
                    (
                        "Go pattern_id must start with 'go.' or "
                        f"'go-cosmos-sdk.', got {rec['pattern_id']!r}"
                    ),
                )

    def test_go_patterns_cover_expected_categories(self) -> None:
        """Lane P3-GO-PRESCAFF specific: the 5 Go anti-patterns span the
        atomicity/bounds/custody categories per the P5-MVP2-COMPOSE
        composability recommendation."""
        records = CATALOG_TOOL.load_catalog(CATALOG_ROOT)
        go_records = [r for r in records if r["language"] == "go"]
        categories = {r["category"] for r in go_records}
        # The 5 Go patterns intentionally span 3 schema categories:
        # atomicity-and-ordering (3), bounds-and-bounds-checks (1),
        # custody-and-accounting (1). This composability spread is the
        # design constraint coming out of P5-MVP2-COMPOSE.
        self.assertIn("atomicity-and-ordering", categories)
        self.assertIn("bounds-and-bounds-checks", categories)
        self.assertIn("custody-and-accounting", categories)
        # Expanded Go coverage now spans 5 distinct categories across 7
        # patterns.
        self.assertGreaterEqual(
            len(categories),
            5,
            f"expected Go category floor >=5, got {sorted(categories)}",
        )

    def test_rust_substrate_patterns_validate_against_schema(self) -> None:
        """Lane HB-P3-RUST-PRESCAFF specific: Rust/Solana/Anchor and
        Substrate seed records are schema-valid and evidence-backed."""
        records = CATALOG_TOOL.load_catalog(CATALOG_ROOT)
        rust_records = [
            r for r in records
            if r["language"] in {"rust-solana-anchor", "substrate-rust"}
        ]
        self.assertGreaterEqual(
            len(rust_records),
            8,
            f"expected Rust/Substrate anti-pattern floor >=8, got {len(rust_records)}",
        )
        for rec in rust_records:
            with self.subTest(pattern_id=rec["pattern_id"]):
                self.assertTrue(is_valid_record(rec))
                self.assertGreaterEqual(len(rec["source_finding_ids"]), 2)
                self.assertGreaterEqual(len(rec["target_invariants"]), 1)
                self.assertIn(
                    rec["language"],
                    {"rust-solana-anchor", "substrate-rust"},
                )

    def test_hb_p3_full_first_batch_language_counts(self) -> None:
        """Lane HB-P3-FULL-FIRST-BATCH: keep the first expansion conservative
        and balanced across the requested language families."""
        records = CATALOG_TOOL.load_catalog(CATALOG_ROOT)
        langs = [r["language"] for r in records]
        self.assertGreaterEqual(len(records), 130)
        self.assertGreaterEqual(langs.count("solidity"), 30)
        self.assertGreaterEqual(langs.count("go"), 7)
        self.assertGreaterEqual(langs.count("go-cosmos-sdk"), 4)
        self.assertGreaterEqual(langs.count("rust"), 5)
        self.assertGreaterEqual(langs.count("substrate-rust"), 6)
        self.assertGreaterEqual(langs.count("rust-solana-anchor"), 2)
        self.assertGreaterEqual(langs.count("move"), 2)
        self.assertGreaterEqual(langs.count("circom"), 3)
        self.assertGreaterEqual(langs.count("halo2"), 3)

    def test_catalog_quality_summary_distinguishes_real_and_degraded_records(self) -> None:
        records = CATALOG_TOOL.load_catalog(CATALOG_ROOT)
        quality = CATALOG_TOOL.catalog_quality_summary(records)
        self.assertEqual(quality["pattern_count"], len(records))
        self.assertEqual(quality["target_band"], {"min": 80, "max": 120})
        self.assertEqual(quality["target_band_status"], "above-target-expanded")
        self.assertGreaterEqual(quality["executable_query_records"], 120)
        self.assertGreaterEqual(quality["command_plan_records"], 1)
        self.assertEqual(quality["placeholder_record_count"], 0)
        self.assertEqual(quality["placeholder_records"], [])
        self.assertEqual(
            quality["executable_query_records"] + quality["command_plan_records"],
            len(records),
        )
        self.assertEqual(
            quality["query_type_counts"],
            {"ast": 7, "grep": 145, "semgrep": 7, "tree-sitter": 4},
        )

    def test_hb_p3_full_first_batch_records_are_evidence_backed(self) -> None:
        first_batch_ids = {
            "solidity.swap-missing-min-out-or-deadline",
            "solidity.erc4626-first-deposit-share-inflation",
            "solidity.signature-domain-replay-missing-chain-binding",
            "solidity.proxy-initializer-replay-or-callable-implementation",
            "rust.oracle-cache-missing-per-asset-freshness",
            "rust.unchecked-integer-cast-or-addition",
            "go-cosmos-sdk.ibc-packet-denom-or-ack-missing-validation",
            "go-cosmos-sdk.msgserver-authority-update-without-authority-binding",
            "move.signer-capability-stored-or-leaked",
            "move.oracle-price-used-without-freshness-check",
            "circom.unconstrained-witness-assignment-consumed",
            "circom.missing-range-check-on-field-element",
            "halo2.fiat-shamir-transcript-domain-confusion",
            "halo2.verifier-public-input-not-bound",
        }
        records = CATALOG_TOOL.load_catalog(CATALOG_ROOT)
        batch = [r for r in records if r["pattern_id"] in first_batch_ids]
        self.assertEqual(len(batch), 14)
        for rec in batch:
            with self.subTest(pattern_id=rec["pattern_id"]):
                self.assertGreaterEqual(len(rec["source_finding_ids"]), 2)
                self.assertGreaterEqual(len(rec["target_invariants"]), 1)
                self.assertIn(rec["recall_priority"], {"P0", "P1"})

    def test_v3_solidity_batch_records_are_evidence_backed(self) -> None:
        batch_ids = {
            "solidity.cross-domain-optimistic-veto-denominator-mismatch",
            "solidity.erc4626-balanceof-self-donation-share-inflation",
            "solidity.exact-output-fee-asymmetry",
            "solidity.exact-output-low-decimal-descale-up",
            "solidity.l2-oracle-unfinalized-confirmation-check",
            "solidity.native-eth-removeliquidity-reentrancy-stale-reserves",
            "solidity.opposed-trace-defense-signer-withholding",
            "solidity.public-poke-reward-rounding-suppression",
            "solidity.wrapper-refund-fee-payer-mismatch",
            "solidity.zap-liquidity-zero-inner-slippage",
        }
        records = CATALOG_TOOL.load_catalog(CATALOG_ROOT)
        batch = [r for r in records if r["pattern_id"] in batch_ids]
        self.assertEqual(len(batch), 10)
        for rec in batch:
            with self.subTest(pattern_id=rec["pattern_id"]):
                self.assertEqual(rec["language"], "solidity")
                self.assertTrue(is_valid_record(rec))
                self.assertGreaterEqual(len(rec["source_finding_ids"]), 2)
                self.assertGreaterEqual(len(rec["target_invariants"]), 1)
                self.assertIn(rec["recall_priority"], {"P0", "P1"})

    def test_cap_precision_detector_records_have_source_shape_gates(self) -> None:
        records = {
            r["pattern_id"]: r
            for r in CATALOG_TOOL.load_catalog(CATALOG_ROOT)
        }
        required_terms = {
            "solidity.inverted-verify-return": [
                "CAP-004",
                "bool return type",
                "inverted bool control flow",
                "IConsensusV2.verify() returning",
            ],
            "solidity.division-by-zero": [
                "CAP-005",
                "reported division expression",
                "named constant divisors",
                "prior modulo expression",
            ],
            "solidity.erc2771-msgsender-forgery": [
                "CAP-006",
                "ERC2771 or trusted-forwarder context",
                "_msgSender() returns msg.sender verbatim",
                "erc-2771-msgSender-forgery",
            ],
            "solidity.external-call-before-state-update": [
                "CAP-007",
                "same ledger amount is",
                "no post-call storage mutation",
                "non-value view-style calls",
            ],
            "solidity.pausable-no-unpause-exposed": [
                "CAP-018",
                "public or external unpause",
                "same contract",
                "internal, private, no-op",
            ],
            "solidity.lzreceive-no-sender-check": [
                "CAP-019",
                "revert tombstones",
                "source and nonce validation",
                "sibling forwarder calls",
            ],
        }
        self.assertTrue(required_terms.keys() <= records.keys())
        for pattern_id, terms in required_terms.items():
            with self.subTest(pattern_id=pattern_id):
                rec = records[pattern_id]
                self.assertEqual(rec["language"], "solidity")
                self.assertEqual(rec["query_type"], "grep")
                haystack = "\n".join(
                    str(rec.get(key, ""))
                    for key in (
                        "query_source",
                        "description",
                        "known_bug_class_from_corpus",
                        "empirical_anchors",
                    )
                )
                for term in terms:
                    self.assertIn(term, haystack)


class FallbackYamlLoaderTests(unittest.TestCase):
    def test_fallback_loader_handles_inline_and_block(self) -> None:
        text = (
            "schema_version: auditooor.antipattern_catalog.v1\n"
            "pattern_id: solidity.example-canonical-pattern\n"
            "category: reentrancy\n"
            "language: solidity\n"
            "severity_floor: low\n"
            "severity_ceiling: high\n"
            "query_type: slither-detector\n"
            "query_source: |\n"
            "  detectors/foo.py:1\n"
            "  second line of inline expression\n"
            "description: |\n"
            "  Example canonical record for unit testing only.\n"
            "false_positive_rate_estimate: 0.25\n"
            "source_finding_ids:\n"
            "  - corpus-mined:slice_a:L1:S1:hash1\n"
            "  - corpus-mined:slice_b:L2:S2:hash2\n"
            "target_invariants:\n"
            "  - INV-ORD-001\n"
        )
        rec = CATALOG_TOOL._load_yaml_text_fallback(text)
        self.assertEqual(rec["pattern_id"], "solidity.example-canonical-pattern")
        self.assertEqual(rec["language"], "solidity")
        self.assertEqual(rec["false_positive_rate_estimate"], 0.25)
        self.assertEqual(rec["source_finding_ids"], [
            "corpus-mined:slice_a:L1:S1:hash1",
            "corpus-mined:slice_b:L2:S2:hash2",
        ])
        self.assertEqual(rec["target_invariants"], ["INV-ORD-001"])
        # Pipe-block keeps both lines.
        self.assertIn("second line", rec["query_source"])


class CliCommandTests(unittest.TestCase):
    """Run the CLI via its main() and assert exit codes / JSON output."""

    def _run(self, *argv: str) -> tuple[int, str, str]:
        out_buf = io.StringIO()
        err_buf = io.StringIO()
        with redirect_stdout(out_buf), redirect_stderr(err_buf):
            rc = CATALOG_TOOL.main(list(argv))
        return rc, out_buf.getvalue(), err_buf.getvalue()

    def test_list_human_exits_zero(self) -> None:
        rc, out, _ = self._run("--list")
        self.assertEqual(rc, 0, out)
        self.assertIn("solidity.tx-origin-for-authorization", out)
        m = re.search(r"patterns:\s+(\d+)", out)
        self.assertIsNotNone(m, out)
        assert m is not None
        self.assertGreaterEqual(int(m.group(1)), 130)

    def test_list_json_includes_expected_baseline_and_floor(self) -> None:
        rc, out, _ = self._run("--list", "--json")
        self.assertEqual(rc, 0, out)
        payload = json.loads(out)
        self.assertEqual(payload["schema_version"], SCHEMA_VERSION)
        self.assertGreaterEqual(payload["pattern_count"], 130)
        self.assertEqual(payload["quality"]["placeholder_record_count"], 0)
        self.assertGreaterEqual(payload["quality"]["executable_query_records"], 120)
        self.assertGreaterEqual(payload["quality"]["command_plan_records"], 1)
        ids = {p["pattern_id"] for p in payload["patterns"]}
        self.assertIn("solidity.reentrancy-without-modifier", ids)
        self.assertIn("go.mutex-unlock-not-deferred", ids)
        self.assertIn("substrate-rust.attacker-controlled-scale-string-length", ids)
        self.assertIn("rust-solana-anchor.remaining-accounts-cpi-unvalidated", ids)
        self.assertIn("circom.unconstrained-witness-assignment-consumed", ids)
        self.assertIn("move.signer-capability-stored-or-leaked", ids)
        self.assertIn("go-cosmos-sdk.ibc-packet-denom-or-ack-missing-validation", ids)
        self.assertIn("substrate-rust.cross-chain-consensus-client-nonfinal-state-root", ids)
        self.assertIn("solidity.exact-output-refund-recipient-mismatch-pooled-escrow", ids)
        self.assertIn("solidity.cross-domain-optimistic-veto-denominator-mismatch", ids)
        self.assertIn("solidity.erc4626-balanceof-self-donation-share-inflation", ids)
        self.assertIn("solidity.exact-output-fee-asymmetry", ids)
        self.assertIn("solidity.exact-output-low-decimal-descale-up", ids)
        self.assertIn("solidity.l2-oracle-unfinalized-confirmation-check", ids)
        self.assertIn("solidity.native-eth-removeliquidity-reentrancy-stale-reserves", ids)
        self.assertIn("solidity.opposed-trace-defense-signer-withholding", ids)
        self.assertIn("solidity.public-poke-reward-rounding-suppression", ids)
        self.assertIn("solidity.wrapper-refund-fee-payer-mismatch", ids)
        self.assertIn("solidity.zap-liquidity-zero-inner-slippage", ids)
        self.assertIn("solidity.batch02-bridge-message-domain-or-nonce-not-bound", ids)
        self.assertIn("solidity.batch02-wrapper-full-balance-refund-sweep", ids)
        self.assertIn("solidity.inverted-verify-return", ids)
        self.assertIn("solidity.division-by-zero", ids)
        self.assertIn("solidity.erc2771-msgsender-forgery", ids)
        self.assertIn("solidity.external-call-before-state-update", ids)
        self.assertIn("solidity.pausable-no-unpause-exposed", ids)
        self.assertIn("solidity.lzreceive-no-sender-check", ids)
        self.assertIn("go.bridge-message-hash-missing-source-domain-binding", ids)
        self.assertIn("go-cosmos-sdk.ibc-timeout-height-or-timestamp-not-enforced", ids)
        self.assertIn("rust.bridge-attestation-quorum-counts-duplicate-signers", ids)
        self.assertIn("substrate-rust.xcm-origin-location-converted-without-filter", ids)
        self.assertIn("circom.poseidon-merkle-path-index-bit-not-binary-constrained", ids)
        self.assertIn("halo2.lookup-enable-flag-not-constrained-to-selector-domain", ids)
        # Language split: 14 prescaffold + 14 first-batch records + 2 HB gap
        # records + 20 V3 Solidity batch records + CAP precision rows.
        langs = [p["language"] for p in payload["patterns"]]
        self.assertGreaterEqual(langs.count("solidity"), 30)
        self.assertGreaterEqual(langs.count("go"), 7)
        self.assertGreaterEqual(langs.count("go-cosmos-sdk"), 4)
        self.assertGreaterEqual(langs.count("rust"), 5)
        self.assertGreaterEqual(langs.count("substrate-rust"), 6)
        self.assertGreaterEqual(langs.count("rust-solana-anchor"), 2)
        self.assertGreaterEqual(langs.count("move"), 2)
        self.assertGreaterEqual(langs.count("circom"), 3)
        self.assertGreaterEqual(langs.count("halo2"), 3)

    def test_validate_exits_zero(self) -> None:
        rc, out, _ = self._run("--validate")
        self.assertEqual(rc, 0, out)
        self.assertIn("PASS", out)
        self.assertIn("placeholder_records=0", out)

    def test_validate_json_includes_quality_evidence(self) -> None:
        rc, out, _ = self._run("--validate", "--json")
        self.assertEqual(rc, 0, out)
        payload = json.loads(out)
        self.assertEqual(payload["verdict"], "pass-all-records-valid")
        self.assertEqual(payload["quality"]["placeholder_record_count"], 0)
        self.assertEqual(payload["quality"]["target_band_status"], "above-target-expanded")
        self.assertGreaterEqual(payload["quality"]["executable_query_records"], 120)
        self.assertGreaterEqual(payload["quality"]["command_plan_records"], 1)

    def test_scan_corpus_emits_expanded_catalog_quality_evidence(self) -> None:
        rc, out, _ = self._run("--scan-corpus", "--json")
        self.assertEqual(rc, 0, out)
        payload = json.loads(out)
        self.assertEqual(payload["stage"], "expanded-hand-curated-catalog")
        self.assertIn("directly executable grep records", payload["note"])
        self.assertGreaterEqual(payload["pattern_count"], 130)
        self.assertEqual(payload["quality"]["placeholder_record_count"], 0)
        self.assertEqual(payload["quality"]["target_band_status"], "above-target-expanded")

    def test_query_inline_regex_matches_tiny_fixture(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            target = Path(tmp)
            (target / "Auth.sol").write_text(
                "contract Auth {\n"
                "  address owner;\n"
                "  function withdraw() external {\n"
                "    require(tx.origin == owner);\n"
                "  }\n"
                "}\n",
                encoding="utf-8",
            )
            rc, out, _ = self._run(
                "--query",
                "solidity.tx-origin-for-authorization",
                str(target),
                "--json",
            )
        self.assertEqual(rc, 0, out)
        payload = json.loads(out)
        self.assertEqual(payload["verdict"], "matched")
        self.assertFalse(payload["semantic_tp_claim"])
        self.assertIn("lexical grep-style candidate hits", payload["note"])
        self.assertEqual(len(payload["matches"]), 1)
        self.assertEqual(payload["matches"][0]["path"], "Auth.sol")
        self.assertEqual(payload["matches"][0]["line_number"], 4)

    def test_query_grep_first_line_matches_tiny_fixture(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            target = Path(tmp)
            (target / "race.go").write_text(
                "package main\n"
                "func f() {\n"
                "  m[key] = value\n"
                "}\n",
                encoding="utf-8",
            )
            rc, out, _ = self._run(
                "--query",
                "go.concurrent-map-write-no-sync",
                str(target),
                "--json",
            )
        self.assertEqual(rc, 0, out)
        payload = json.loads(out)
        self.assertEqual(payload["verdict"], "matched")
        self.assertEqual(payload["include_globs"], ["*.go"])
        self.assertEqual(payload["matches"][0]["path"], "race.go")
        self.assertEqual(payload["matches"][0]["line_number"], 3)

    def test_query_no_matches_tiny_fixture(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            target = Path(tmp)
            (target / "Auth.sol").write_text(
                "contract Auth { function withdraw() external {} }\n",
                encoding="utf-8",
            )
            rc, out, _ = self._run(
                "--query",
                "solidity.tx-origin-for-authorization",
                str(target),
                "--json",
            )
        self.assertEqual(rc, 0, out)
        payload = json.loads(out)
        self.assertEqual(payload["verdict"], "no_matches")
        self.assertEqual(payload["matches"], [])
        self.assertGreaterEqual(payload["files_scanned"], 1)

    def _query_single_solidity_source(self, pattern_id: str, source: str) -> dict:
        with tempfile.TemporaryDirectory() as tmp:
            target = Path(tmp)
            (target / "Case.sol").write_text(source, encoding="utf-8")
            rc, out, _ = self._run("--query", pattern_id, str(target), "--json")
        self.assertEqual(rc, 0, out)
        return json.loads(out)

    def test_cap_precision_query_guards_keep_positive_shapes(self) -> None:
        cases = {
            "solidity.inverted-verify-return": """
                contract BoolVerifier {
                  function verifyProof(bytes calldata) public returns (bool) { return false; }
                  function check(bytes calldata proof) external {
                    require(!verifyProof(proof));
                  }
                }
            """,
            "solidity.division-by-zero": """
                contract Ratios {
                  function quote(uint256 total, uint256 denominator) external pure returns (uint256) {
                    return total / denominator;
                  }
                }
            """,
            "solidity.erc2771-msgsender-forgery": """
                contract Forwarded is ERC2771Context {
                  address owner;
                  function update() external {
                    owner = _msgSender();
                  }
                }
            """,
            "solidity.external-call-before-state-update": """
                contract Withdraw {
                  mapping(address => uint256) balances;
                  function withdraw(uint256 amount) external {
                    (bool sent,) = msg.sender.call{value: amount}("");
                    require(sent);
                    balances[msg.sender] -= amount;
                  }
                }
            """,
            "solidity.pausable-no-unpause-exposed": """
                contract PausableLike {
                  bool paused;
                  modifier whenNotPaused() { require(!paused); _; }
                  function pause() external { paused = true; }
                  function submit() external whenNotPaused {}
                }
            """,
            "solidity.lzreceive-no-sender-check": """
                contract Receiver {
                  function lzReceive(Origin calldata, bytes32, bytes calldata payload, address, bytes calldata) external payable {
                    _process(payload);
                  }
                }
            """,
        }
        for pattern_id, source in cases.items():
            with self.subTest(pattern_id=pattern_id):
                payload = self._query_single_solidity_source(pattern_id, source)
                self.assertEqual(payload["verdict"], "matched", payload)
                self.assertGreaterEqual(len(payload["matches"]), 1)

    def test_cap_precision_query_guards_filter_known_fp_shapes(self) -> None:
        cases = {
            "solidity.inverted-verify-return": """
                interface IConsensusV2 {
                  function verify(bytes calldata proof) external returns (bytes memory, IntermediateState[] memory, uint256);
                }
                contract SP1Beefy is IConsensusV2 {
                  function verify(bytes calldata proof) external returns (bytes memory, IntermediateState[] memory, uint256) {
                    verifier.verifyProof(proof);
                    return (proof, new IntermediateState[](0), 0);
                  }
                }
            """,
            "solidity.division-by-zero": """
                contract Ratios {
                  uint256 internal constant SCALE = 1e18;
                  function quote(uint256 total, uint256 denominator) external pure returns (uint256) {
                    uint256 scaled = total / SCALE;
                    require(denominator != 0);
                    return total / denominator;
                  }
                }
            """,
            "solidity.erc2771-msgsender-forgery": """
                import "@openzeppelin/contracts/metatx/ERC2771Context.sol";
                contract MentionOnly {
                  address owner;
                  function update(address nextOwner) external {
                    owner = nextOwner;
                  }
                }
            """,
            "solidity.external-call-before-state-update": """
                contract Refund {
                  mapping(address => uint256) balances;
                  function refund(uint256 amount) external {
                    balances[msg.sender] -= amount;
                    (bool sent,) = msg.sender.call{value: amount}("");
                    require(sent);
                  }
                }
            """,
            "solidity.pausable-no-unpause-exposed": """
                contract PausableLike {
                  bool paused;
                  modifier whenNotPaused() { require(!paused); _; }
                  function pause() external { paused = true; }
                  function unpause() external { paused = false; }
                  function submit() external whenNotPaused {}
                }
            """,
            "solidity.lzreceive-no-sender-check": """
                contract Receiver {
                  function lzReceive(Origin calldata, bytes32, bytes calldata, address, bytes calldata) external payable {
                    revert("disabled");
                  }
                }
            """,
        }
        for pattern_id, source in cases.items():
            with self.subTest(pattern_id=pattern_id):
                payload = self._query_single_solidity_source(pattern_id, source)
                self.assertEqual(payload["verdict"], "no_matches", payload)
                self.assertEqual(payload["matches"], [])
                self.assertGreaterEqual(payload["filtered_match_count"], 1)
                self.assertTrue(payload["filtered_matches_by_guard"])

    def test_cap019_query_guard_filters_validated_oapp_delivery(self) -> None:
        payload = self._query_single_solidity_source(
            "solidity.lzreceive-no-sender-check",
            """
            contract Endpoint {
              function onAccept(IncomingPostRequest calldata incoming) external onlyHost {
                PostRequest calldata request = incoming.request;
                if (keccak256(request.from) != keccak256(abi.encodePacked(address(this)))) revert UnknownSource();
                uint32 expectedEid = _stateMachineToEid[keccak256(request.source)];
                if (expectedEid == 0 || expectedEid != srcEid) revert UnknownSource();
                uint64 expectedNonce = _inboundNonce[receiverAddr][srcEid][sender] + 1;
                if (nonce != expectedNonce) revert InvalidNonce(expectedNonce, nonce);
                _inboundNonce[receiverAddr][srcEid][sender] = nonce;
                ILayerZeroReceiver(receiverAddr).lzReceive(origin, guid, message, address(0), "");
              }
            }
            """,
        )
        self.assertEqual(payload["verdict"], "no_matches", payload)
        self.assertEqual(payload["matches"], [])
        self.assertGreaterEqual(payload["filtered_match_count"], 1)
        self.assertIn(
            "CAP-019 precision gate: delivery has source and nonce validation",
            payload["filtered_matches_by_guard"],
        )

    def test_query_converted_reentrancy_pattern_uses_grep_engine(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            rc, out, _ = self._run(
                "--query",
                "solidity.reentrancy-without-modifier",
                tmp,
                "--json",
            )
        self.assertEqual(rc, 0, out)
        payload = json.loads(out)
        self.assertEqual(payload["verdict"], "no_matches")
        self.assertEqual(payload["engine"], "bounded-regex-grep-mvp")
        self.assertFalse(payload["semantic_tp_claim"])
        self.assertIn("lexical grep-style candidate hits", payload["note"])
        self.assertEqual(payload["query_type"], "grep")
        self.assertEqual(payload["matches"], [])

    def test_query_converted_records_are_supported_by_grep_engine(self) -> None:
        converted_pattern_ids = {
            "solidity.unchecked-external-call-return-value",
            "solidity.reentrancy-without-modifier",
            "solidity.unbounded-loop-over-user-input",
        }
        with tempfile.TemporaryDirectory() as tmp:
            for pattern_id in converted_pattern_ids:
                with self.subTest(pattern_id=pattern_id):
                    rc, out, _ = self._run(
                        "--query",
                        pattern_id,
                        tmp,
                        "--json",
                    )
                    self.assertEqual(rc, 0, out)
                    payload = json.loads(out)
                    self.assertEqual(payload["verdict"], "no_matches")
                    self.assertEqual(payload["engine"], "bounded-regex-grep-mvp")
                    self.assertEqual(payload["query_type"], "grep")
                    self.assertEqual(payload["matches"], [])

    def test_reentrancy_queries_do_not_match_nonreentrant_guard_only(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            target = Path(tmp)
            (target / "Guarded.sol").write_text(
                "contract Guarded {\n"
                "  function protectedAction() external nonReentrant {}\n"
                "}\n",
                encoding="utf-8",
            )
            for pattern_id in (
                "solidity.reentrancy-without-modifier",
                "solidity.batch02-native-transfer-before-accounting-reentrancy",
            ):
                with self.subTest(pattern_id=pattern_id):
                    rc, out, _ = self._run(
                        "--query",
                        pattern_id,
                        str(target),
                        "--json",
                    )
                    self.assertEqual(rc, 0, out)
                    payload = json.loads(out)
                    self.assertEqual(payload["verdict"], "no_matches")
                    self.assertEqual(payload["matches"], [])

    def test_mutex_unlock_row_is_ast_plan_not_lock_only_grep(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            target = Path(tmp)
            (target / "safe.go").write_text(
                "package p\n"
                "func f() {\n"
                "  mu.Lock()\n"
                "  defer mu.Unlock()\n"
                "  return\n"
                "}\n",
                encoding="utf-8",
            )
            rc, out, _ = self._run(
                "--query",
                "go.mutex-unlock-not-deferred",
                str(target),
                "--json",
            )
        self.assertEqual(rc, 0, out)
        payload = json.loads(out)
        self.assertEqual(payload["verdict"], "query_degraded")
        self.assertEqual(payload["query_type"], "ast")
        self.assertEqual(payload["engine"], "ast-command-plan")
        self.assertEqual(payload["execution_state"], "planned-not-executed")
        self.assertFalse(payload["semantic_tp_claim"])
        self.assertEqual(payload["matches"], [])

    def test_query_converted_pattern_missing_target_returns_query_error(self) -> None:
        rc, out, _ = self._run(
            "--query",
            "solidity.reentrancy-without-modifier",
            "/tmp/some-target-dir-that-may-not-exist",
            "--json",
        )
        self.assertEqual(rc, 1)
        payload = json.loads(out)
        self.assertEqual(payload["verdict"], "query_error")
        self.assertEqual(payload["engine"], "bounded-regex-grep-mvp")
        self.assertIn("does not exist", payload["error"])
        self.assertEqual(payload["matches"], [])

    def test_query_semgrep_prose_pattern_returns_degraded_command_plan(self) -> None:
        record = _canonical_record()
        record["pattern_id"] = "solidity.example-semgrep-pattern"
        record["query_type"] = "semgrep"
        record["query_source"] = "patterns/example.yml"
        with tempfile.TemporaryDirectory() as tmp:
            catalog_root = Path(tmp) / "catalog"
            (catalog_root / "solidity").mkdir(parents=True)
            (catalog_root / "solidity" / "example.yaml").write_text(
                "\n".join([
                    "schema_version: auditooor.antipattern_catalog.v1",
                    "pattern_id: solidity.example-semgrep-pattern",
                    "category: reentrancy",
                    "language: solidity",
                    "severity_floor: low",
                    "severity_ceiling: high",
                    "query_type: semgrep",
                    "query_source: patterns/example.yml",
                    "description: Example canonical record for unit testing only.",
                    "false_positive_rate_estimate: 0.25",
                    "source_finding_ids:",
                    "  - corpus-mined:slice_a:L1:S1:hash1",
                    "  - corpus-mined:slice_b:L2:S2:hash2",
                    "target_invariants:",
                    "  - INV-ORD-001",
                    "",
                ]),
                encoding="utf-8",
            )
            rc, out, _ = self._run(
                "--catalog-root",
                str(catalog_root),
                "--query",
                record["pattern_id"],
                tmp,
                "--json",
            )
        self.assertEqual(rc, 0, out)
        payload = json.loads(out)
        self.assertEqual(payload["verdict"], "query_degraded")
        self.assertEqual(payload["engine"], "semgrep-command-plan")
        self.assertEqual(payload["execution_state"], "planned-not-executed")
        self.assertTrue(payload["rule_materialization_required"])
        self.assertFalse(payload["semantic_tp_claim"])
        self.assertIn("semgrep", payload["degraded_reason"])
        self.assertEqual(payload["command_plan"]["tool"], "semgrep")
        self.assertEqual(payload["matches"], [])

    def test_query_unsupported_for_malformed_grep_source(self) -> None:
        record = _canonical_record()
        record["pattern_id"] = "solidity.example-malformed-grep-pattern"
        record["query_type"] = "grep"
        record["query_source"] = "not-a-supported-query-form"
        with tempfile.TemporaryDirectory() as tmp:
            catalog_root = Path(tmp) / "catalog"
            (catalog_root / "solidity").mkdir(parents=True)
            (catalog_root / "solidity" / "example.yaml").write_text(
                "\n".join([
                    "schema_version: auditooor.antipattern_catalog.v1",
                    "pattern_id: solidity.example-malformed-grep-pattern",
                    "category: reentrancy",
                    "language: solidity",
                    "severity_floor: low",
                    "severity_ceiling: high",
                    "query_type: grep",
                    "query_source: not-a-supported-query-form",
                    "description: Example canonical record for unit testing only.",
                    "false_positive_rate_estimate: 0.25",
                    "source_finding_ids:",
                    "  - corpus-mined:slice_a:L1:S1:hash1",
                    "  - corpus-mined:slice_b:L2:S2:hash2",
                    "target_invariants:",
                    "  - INV-ORD-001",
                    "",
                ]),
                encoding="utf-8",
            )
            rc, out, _ = self._run(
                "--catalog-root",
                str(catalog_root),
                "--query",
                record["pattern_id"],
                tmp,
                "--json",
            )
        self.assertEqual(rc, 0, out)
        payload = json.loads(out)
        self.assertEqual(payload["verdict"], "query_unsupported")
        self.assertIn("not an MVP-supported", payload["unsupported_reason"])
        self.assertEqual(payload["matches"], [])

    def test_catalog_semgrep_ast_tree_sitter_queries_are_not_unsupported(self) -> None:
        samples = {
            "semgrep": "solidity.batch03-fee-on-transfer-token-accounting-uses-requested-amount",
            "ast": "go.batch03-go-vote-extension-price-aggregate-missing-power-threshold",
            "tree-sitter": "rust.batch03-anchor-cpi-authority-seeds-not-checked",
        }
        with tempfile.TemporaryDirectory() as tmp:
            for query_type, pattern_id in samples.items():
                with self.subTest(query_type=query_type, pattern_id=pattern_id):
                    rc, out, _ = self._run(
                        "--query",
                        pattern_id,
                        tmp,
                        "--json",
                    )
                    self.assertEqual(rc, 0, out)
                    payload = json.loads(out)
                    self.assertEqual(payload["query_type"], query_type)
                    self.assertEqual(payload["verdict"], "query_degraded")
                    self.assertNotEqual(payload["verdict"], "query_unsupported")
                    self.assertEqual(
                        payload["engine"],
                        f"{query_type}-command-plan",
                    )
                    self.assertEqual(
                        payload["execution_state"],
                        "planned-not-executed",
                    )
                    self.assertTrue(payload["rule_materialization_required"])
                    self.assertFalse(payload["semantic_tp_claim"])
                    self.assertIn("command_plan", payload)
                    self.assertEqual(payload["matches"], [])

    def test_all_catalog_queries_have_usable_wiring_on_empty_target(self) -> None:
        records = CATALOG_TOOL.load_catalog(CATALOG_ROOT)
        with tempfile.TemporaryDirectory() as tmp:
            for rec in records:
                with self.subTest(pattern_id=rec["pattern_id"]):
                    rc, out, _ = self._run(
                        "--query",
                        rec["pattern_id"],
                        tmp,
                        "--json",
                    )
                    self.assertEqual(rc, 0, out)
                    payload = json.loads(out)
                    self.assertIn(
                        payload["verdict"],
                        {"no_matches", "matched", "query_degraded"},
                    )
                    self.assertNotEqual(payload["verdict"], "query_unsupported")
                    self.assertNotEqual(payload["verdict"], "query_error")
                    dependency = payload.get("dependency") or {}
                    self.assertIsNot(
                        dependency.get("adapter_supported"),
                        False,
                        dependency.get("adapter_error"),
                    )

    def test_query_missing_target_returns_query_error(self) -> None:
        rc, out, _ = self._run(
            "--query",
            "solidity.tx-origin-for-authorization",
            "/tmp/some-target-dir-that-may-not-exist",
            "--json",
        )
        self.assertEqual(rc, 1)
        payload = json.loads(out)
        self.assertEqual(payload["verdict"], "query_error")
        self.assertIn("does not exist", payload["error"])
        self.assertEqual(payload["matches"], [])

    def test_bridge_proof_zero_root_query_filters_utility_noise(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            utility_dir = root / "src" / "solidity-merkle-trees" / "src"
            bridge_dir = root / "src" / "hyperbridge" / "evm" / "src" / "apps"
            utility_dir.mkdir(parents=True)
            bridge_dir.mkdir(parents=True)
            (utility_dir / "VWAPOracle.sol").write_text(
                """
                contract VWAPOracle {
                  bytes32 internal root;
                  function currentRoot() external view returns (bytes32) {
                    return root;
                  }
                  function defaultBranch() external pure returns (bytes32) {
                    return bytes32(0);
                  }
                }
                """,
                encoding="utf-8",
            )
            (utility_dir / "EthereumTrie.sol").write_text(
                """
                contract EthereumTrie {
                  bytes32 internal branch;
                  function defaultBranch() external view returns (bytes32) {
                    return branch == bytes32(0) ? bytes32(0) : branch;
                  }
                }
                """,
                encoding="utf-8",
            )
            (bridge_dir / "BridgeVerifier.sol").write_text(
                """
                contract BridgeVerifier {
                  uint32 public sourceDomain;
                  uint32 public destinationDomain;
                  function verifyBridgeProof(bytes32 root, bytes32 branch) external view returns (bool) {
                    require(root != bytes32(0), "zero root");
                    require(branch != bytes32(0), "default branch");
                    return sourceDomain != destinationDomain;
                  }
                }
                """,
                encoding="utf-8",
            )

            rc, out, _ = self._run(
                "--query",
                "solidity.batch03-bridge-proof-verifier-accepts-zero-root-or-default-branch",
                str(root),
                "--json",
            )

        self.assertEqual(rc, 0, out)
        payload = json.loads(out)
        self.assertEqual(payload["verdict"], "matched")
        self.assertGreaterEqual(payload["filtered_match_count"], 2)
        self.assertTrue(
            any("CAP-020" in reason for reason in payload["filtered_matches_by_guard"]),
            payload["filtered_matches_by_guard"],
        )
        matched_paths = {match["path"] for match in payload["matches"]}
        self.assertIn("src/hyperbridge/evm/src/apps/BridgeVerifier.sol", matched_paths)
        self.assertNotIn("src/solidity-merkle-trees/src/VWAPOracle.sol", matched_paths)
        self.assertNotIn("src/solidity-merkle-trees/src/EthereumTrie.sol", matched_paths)

    def test_query_unknown_pattern_returns_non_zero(self) -> None:
        rc, _out, err = self._run(
            "--query", "solidity.not-a-real-pattern", "/tmp", "--json",
        )
        # Unknown pattern is a structured non-error; exit 2 per arg-error
        # convention so callers can distinguish from rc=0 success.
        self.assertEqual(rc, 2)


class SchemaConstantInvariantTests(unittest.TestCase):
    def test_schema_version_constant_value(self) -> None:
        self.assertEqual(SCHEMA_VERSION, "auditooor.antipattern_catalog.v1")

    def test_default_catalog_root_matches_repo_layout(self) -> None:
        # The tool's default catalog root must resolve under the same
        # obsidian-vault path the YAML files live in.
        self.assertEqual(
            CATALOG_TOOL.DEFAULT_CATALOG_ROOT.resolve(),
            CATALOG_ROOT.resolve(),
        )


if __name__ == "__main__":
    unittest.main()
