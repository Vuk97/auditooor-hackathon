"""Tests for tools/go-detector-runner.py (SPARK-GAP-001 seed)."""
from __future__ import annotations

import importlib.util
import json
import os
import shutil
import sys
import tempfile
import unittest
from pathlib import Path


HERE = Path(__file__).resolve().parent
TOOLS_DIR = HERE.parent
RUNNER_PATH = TOOLS_DIR / "go-detector-runner.py"
FIXTURES = HERE / "fixtures" / "go-detector-runner"


def _load_runner():
    """go-detector-runner.py has a hyphen so it isn't a normal Python module."""
    spec = importlib.util.spec_from_file_location(
        "go_detector_runner", RUNNER_PATH
    )
    assert spec and spec.loader
    mod = importlib.util.module_from_spec(spec)
    # @dataclass needs the module to be findable in sys.modules during load.
    sys.modules["go_detector_runner"] = mod
    spec.loader.exec_module(mod)
    return mod


class GoDetectorRunnerTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.mod = _load_runner()

    # ------------------------------------------------------------------
    # Pattern 1 — txid_equality_without_utxo_spend_check
    # ------------------------------------------------------------------
    def test_txid_eq_without_spend_positive(self):
        with tempfile.TemporaryDirectory() as ws:
            shutil.copy(
                FIXTURES / "positive" / "txid_eq_no_spend.go",
                Path(ws) / "txid_eq_no_spend.go",
            )
            summary = self.mod.scan_workspace(
                Path(ws), tuple(self.mod._DEFAULT_GUARDS)
            )
            pid = "go.bitcoin.txid_equality_without_utxo_spend_check"
            self.assertGreaterEqual(
                summary["patterns"][pid]["hit_count"], 2,
                f"expected >=2 hits in positive fixture, got: {summary['patterns'][pid]}",
            )

    def test_txid_query_without_spend_positive(self):
        """LEAD 1 shape: ent-query *TxidIn(...) without spend verifier."""
        with tempfile.TemporaryDirectory() as ws:
            shutil.copy(
                FIXTURES / "positive" / "txid_query_no_spend.go",
                Path(ws) / "txid_query_no_spend.go",
            )
            summary = self.mod.scan_workspace(
                Path(ws), tuple(self.mod._DEFAULT_GUARDS)
            )
            pid = "go.bitcoin.txid_equality_without_utxo_spend_check"
            self.assertGreaterEqual(
                summary["patterns"][pid]["hit_count"], 1,
                f"expected >=1 hit in ent-query positive fixture, got: {summary['patterns'][pid]}",
            )
            functions = [
                h["extra"]["function"]
                for h in summary["patterns"][pid]["hits"]
            ]
            self.assertIn("ConfirmCoopExits", functions)

    def test_txid_eq_with_spend_negative(self):
        with tempfile.TemporaryDirectory() as ws:
            shutil.copy(
                FIXTURES / "negative" / "txid_eq_with_spend.go",
                Path(ws) / "txid_eq_with_spend.go",
            )
            summary = self.mod.scan_workspace(
                Path(ws), tuple(self.mod._DEFAULT_GUARDS)
            )
            pid = "go.bitcoin.txid_equality_without_utxo_spend_check"
            self.assertEqual(
                summary["patterns"][pid]["hit_count"], 0,
                f"expected 0 hits in negative fixture, got: {summary['patterns'][pid]}",
            )

    def test_proto_enum_dispatch_negative(self):
        """L7 FP-kill: `hashVariant == pb.HashVariant_HASH_VARIANT_V2` is
        proto-enum dispatch, not a missing-spend bug. Models the 4 Spark
        FPs at common/proof.go:14, deposit_handler.go:542/572, and
        internal_deposit_handler.go:438. See
        docs/next-loop/scan_go_proto_enum_fp_kill_2026-05-06.md.
        """
        with tempfile.TemporaryDirectory() as ws:
            shutil.copy(
                FIXTURES / "negative" / "proto_enum_dispatch.go",
                Path(ws) / "proto_enum_dispatch.go",
            )
            summary = self.mod.scan_workspace(
                Path(ws), tuple(self.mod._DEFAULT_GUARDS)
            )
            pid = "go.bitcoin.txid_equality_without_utxo_spend_check"
            self.assertEqual(
                summary["patterns"][pid]["hit_count"], 0,
                f"expected 0 hits in proto-enum-dispatch negative fixture, "
                f"got: {summary['patterns'][pid]}",
            )

    # ------------------------------------------------------------------
    # Pattern go.bitcoin.txid_without_vout_outpoint_binding
    # Spark LEAD 1 txid-vs-UTXO class: txid-only match without vout binding
    # ------------------------------------------------------------------
    def test_txid_without_vout_binding_positive(self):
        """Positive fixture: txid equality check with no vout/outputIndex
        present in the body. The detector MUST fire (>=2 hits for the two
        function shapes in the fixture)."""
        with tempfile.TemporaryDirectory() as ws:
            shutil.copy(
                FIXTURES / "positive" / "txid_no_vout_binding.go",
                Path(ws) / "txid_no_vout_binding.go",
            )
            summary = self.mod.scan_workspace(
                Path(ws), tuple(self.mod._DEFAULT_GUARDS)
            )
            pid = "go.bitcoin.txid_without_vout_outpoint_binding"
            self.assertGreaterEqual(
                summary["patterns"][pid]["hit_count"], 2,
                f"expected >=2 hits in positive fixture (txid-only, no vout), "
                f"got: {summary['patterns'][pid]}",
            )
            functions = {
                h["extra"]["function"]
                for h in summary["patterns"][pid]["hits"]
            }
            self.assertIn(
                "ConfirmExitByTxidOnly", functions,
                f"expected ConfirmExitByTxidOnly flagged, got {functions}",
            )
            self.assertIn(
                "WatchChainExitMatch", functions,
                f"expected WatchChainExitMatch flagged, got {functions}",
            )

    def test_txid_with_vout_binding_negative(self):
        """Negative control: txid equality check WITH vout/outputIndex
        binding present. The detector MUST NOT fire because the code
        correctly constrains the full outpoint (txid + vout)."""
        with tempfile.TemporaryDirectory() as ws:
            shutil.copy(
                FIXTURES / "negative" / "txid_with_vout_binding.go",
                Path(ws) / "txid_with_vout_binding.go",
            )
            summary = self.mod.scan_workspace(
                Path(ws), tuple(self.mod._DEFAULT_GUARDS)
            )
            pid = "go.bitcoin.txid_without_vout_outpoint_binding"
            self.assertEqual(
                summary["patterns"][pid]["hit_count"], 0,
                f"expected 0 hits in negative fixture (txid+vout full outpoint), "
                f"got: {summary['patterns'][pid]}",
            )

    # ------------------------------------------------------------------
    # Pattern 2 — guard_only_on_one_path
    # ------------------------------------------------------------------
    def test_guard_only_one_path_positive(self):
        with tempfile.TemporaryDirectory() as ws:
            shutil.copy(
                FIXTURES / "positive" / "guard_only_one_path.go",
                Path(ws) / "guard_only_one_path.go",
            )
            summary = self.mod.scan_workspace(
                Path(ws), tuple(self.mod._DEFAULT_GUARDS),
            )
            pid = "go.statemachine.guard_only_on_one_path"
            self.assertGreaterEqual(
                summary["patterns"][pid]["hit_count"], 1,
                f"expected >=1 hit in positive fixture, got: {summary['patterns'][pid]}",
            )
            # Should flag the unguarded sibling specifically.
            functions = [
                h["extra"]["function"]
                for h in summary["patterns"][pid]["hits"]
            ]
            self.assertIn("SilentlyAdvance", functions)

    def test_all_paths_guarded_negative(self):
        with tempfile.TemporaryDirectory() as ws:
            shutil.copy(
                FIXTURES / "negative" / "all_paths_guarded.go",
                Path(ws) / "all_paths_guarded.go",
            )
            summary = self.mod.scan_workspace(
                Path(ws), tuple(self.mod._DEFAULT_GUARDS),
            )
            pid = "go.statemachine.guard_only_on_one_path"
            self.assertEqual(
                summary["patterns"][pid]["hit_count"], 0,
                f"expected 0 hits in negative fixture, got: {summary['patterns'][pid]}",
            )

    def test_guard_only_one_path_validate_handlers_positive(self):
        """LEAD H-D shape: project-specific guard `validate*` called by
        only one sibling, missing from 4 *Request-shaped public handlers
        that mutate Status. Sharpened detector arm should fire on the 4
        unguarded handlers via the package_project_guard arm.
        """
        with tempfile.TemporaryDirectory() as ws:
            shutil.copy(
                FIXTURES / "positive" / "guard_only_one_path_validate_handlers.go",
                Path(ws) / "guard_only_one_path_validate_handlers.go",
            )
            summary = self.mod.scan_workspace(
                Path(ws), tuple(self.mod._DEFAULT_GUARDS),
            )
            pid = "go.statemachine.guard_only_on_one_path"
            self.assertGreaterEqual(
                summary["patterns"][pid]["hit_count"], 4,
                f"expected >=4 hits, got: {summary['patterns'][pid]}",
            )
            functions = {
                h["extra"]["function"]
                for h in summary["patterns"][pid]["hits"]
            }
            for expected in (
                "ClaimTransferTweakKeys",
                "ClaimTransfer",
                "ClaimTransferSignRefunds",
                "InitiateSettleReceiverKeyTweak",
            ):
                self.assertIn(expected, functions,
                              f"expected {expected} flagged, got {functions}")
            arms = {
                h["extra"].get("predicate_arm")
                for h in summary["patterns"][pid]["hits"]
            }
            self.assertIn("package_project_guard", arms,
                          f"expected package_project_guard arm, got {arms}")

    def test_guard_called_in_all_handlers_negative(self):
        """All 4 status-mutating handlers call the project-specific
        guard, so neither detector arm should fire."""
        with tempfile.TemporaryDirectory() as ws:
            shutil.copy(
                FIXTURES / "negative" / "guard_called_in_all_handlers.go",
                Path(ws) / "guard_called_in_all_handlers.go",
            )
            summary = self.mod.scan_workspace(
                Path(ws), tuple(self.mod._DEFAULT_GUARDS),
            )
            pid = "go.statemachine.guard_only_on_one_path"
            self.assertEqual(
                summary["patterns"][pid]["hit_count"], 0,
                f"expected 0 hits, got: {summary['patterns'][pid]}",
            )

    # ------------------------------------------------------------------
    # Pattern 3 — self_heal_on_unexpected_status
    # ------------------------------------------------------------------
    def test_self_heal_positive(self):
        with tempfile.TemporaryDirectory() as ws:
            shutil.copy(
                FIXTURES / "positive" / "self_heal_status.go",
                Path(ws) / "self_heal_status.go",
            )
            summary = self.mod.scan_workspace(
                Path(ws), tuple(self.mod._DEFAULT_GUARDS),
            )
            pid = "go.statemachine.self_heal_on_unexpected_status"
            self.assertGreaterEqual(
                summary["patterns"][pid]["hit_count"], 1,
                f"expected >=1 hit in positive fixture, got: {summary['patterns'][pid]}",
            )

    def test_self_heal_with_return_negative(self):
        with tempfile.TemporaryDirectory() as ws:
            shutil.copy(
                FIXTURES / "negative" / "self_heal_returns.go",
                Path(ws) / "self_heal_returns.go",
            )
            summary = self.mod.scan_workspace(
                Path(ws), tuple(self.mod._DEFAULT_GUARDS),
            )
            pid = "go.statemachine.self_heal_on_unexpected_status"
            self.assertEqual(
                summary["patterns"][pid]["hit_count"], 0,
                f"expected 0 hits in negative fixture, got: {summary['patterns'][pid]}",
            )

    # ------------------------------------------------------------------
    # Pattern 5 — protohash.kind_identifier_collision
    # ------------------------------------------------------------------
    def test_protohash_kind_collision_positive(self):
        with tempfile.TemporaryDirectory() as ws:
            shutil.copy(
                FIXTURES / "positive" / "protohash_kind_collision.go",
                Path(ws) / "protohash_kind_collision.go",
            )
            summary = self.mod.scan_workspace(
                Path(ws), tuple(self.mod._DEFAULT_GUARDS),
            )
            pid = "go.protohash.kind_identifier_collision"
            self.assertGreaterEqual(
                summary["patterns"][pid]["hit_count"], 1,
                f"expected >=1 hit in positive fixture, got: {summary['patterns'][pid]}",
            )

    def test_protohash_single_kind_negative(self):
        with tempfile.TemporaryDirectory() as ws:
            shutil.copy(
                FIXTURES / "negative" / "protohash_single_kind.go",
                Path(ws) / "protohash_single_kind.go",
            )
            summary = self.mod.scan_workspace(
                Path(ws), tuple(self.mod._DEFAULT_GUARDS),
            )
            pid = "go.protohash.kind_identifier_collision"
            self.assertEqual(
                summary["patterns"][pid]["hit_count"], 0,
                f"expected 0 hits in negative fixture, got: {summary['patterns'][pid]}",
            )

    # ------------------------------------------------------------------
    # Pattern 6 — gossip_perimeter_trust
    # ------------------------------------------------------------------
    def test_gossip_perimeter_trust_positive(self):
        with tempfile.TemporaryDirectory() as ws:
            shutil.copy(
                FIXTURES / "positive" / "gossip_perimeter_trust.go",
                Path(ws) / "gossip_perimeter_trust.go",
            )
            summary = self.mod.scan_workspace(
                Path(ws), tuple(self.mod._DEFAULT_GUARDS),
            )
            pid = "go.consensus.gossip_perimeter_trust"
            self.assertGreaterEqual(
                summary["patterns"][pid]["hit_count"], 1,
                f"expected >=1 hit in positive fixture, got: {summary['patterns'][pid]}",
            )
            functions = [
                h["extra"]["function"]
                for h in summary["patterns"][pid]["hits"]
            ]
            self.assertIn("Gossip", functions)

    def test_gossip_perimeter_signed_negative(self):
        with tempfile.TemporaryDirectory() as ws:
            shutil.copy(
                FIXTURES / "negative" / "gossip_perimeter_signed.go",
                Path(ws) / "gossip_perimeter_signed.go",
            )
            summary = self.mod.scan_workspace(
                Path(ws), tuple(self.mod._DEFAULT_GUARDS),
            )
            pid = "go.consensus.gossip_perimeter_trust"
            self.assertEqual(
                summary["patterns"][pid]["hit_count"], 0,
                f"expected 0 hits in negative fixture, got: {summary['patterns'][pid]}",
            )

    # ------------------------------------------------------------------
    # Pattern 7 — byte_reversed_lookup_set
    # ------------------------------------------------------------------
    def test_byte_reversed_lookup_positive(self):
        with tempfile.TemporaryDirectory() as ws:
            shutil.copy(
                FIXTURES / "positive" / "byte_reversed_lookup.go",
                Path(ws) / "byte_reversed_lookup.go",
            )
            summary = self.mod.scan_workspace(
                Path(ws), tuple(self.mod._DEFAULT_GUARDS),
            )
            pid = "go.bitcoin.byte_reversed_lookup_set"
            self.assertGreaterEqual(
                summary["patterns"][pid]["hit_count"], 1,
                f"expected >=1 hit in positive fixture, got: {summary['patterns'][pid]}",
            )

    def test_byte_reversed_single_negative(self):
        with tempfile.TemporaryDirectory() as ws:
            shutil.copy(
                FIXTURES / "negative" / "byte_reversed_single.go",
                Path(ws) / "byte_reversed_single.go",
            )
            summary = self.mod.scan_workspace(
                Path(ws), tuple(self.mod._DEFAULT_GUARDS),
            )
            pid = "go.bitcoin.byte_reversed_lookup_set"
            self.assertEqual(
                summary["patterns"][pid]["hit_count"], 0,
                f"expected 0 hits in negative fixture, got: {summary['patterns'][pid]}",
            )

    # ------------------------------------------------------------------
    # Pattern 8 — cosmos message_ordering_replay
    # ------------------------------------------------------------------
    def test_cosmos_msg_ordering_positive(self):
        with tempfile.TemporaryDirectory() as ws:
            shutil.copy(
                FIXTURES / "positive" / "cosmos_msg_ordering.go",
                Path(ws) / "cosmos_msg_ordering.go",
            )
            summary = self.mod.scan_workspace(
                Path(ws), tuple(self.mod._DEFAULT_GUARDS),
            )
            pid = "go.cosmos.message_ordering_replay"
            self.assertGreaterEqual(
                summary["patterns"][pid]["hit_count"], 1,
                f"expected >=1 hit in positive fixture, got: {summary['patterns'][pid]}",
            )
            functions = [
                h["extra"]["function"]
                for h in summary["patterns"][pid]["hits"]
            ]
            self.assertIn("HandleMsgTransfer", functions)

    def test_cosmos_msg_with_sequence_negative(self):
        with tempfile.TemporaryDirectory() as ws:
            shutil.copy(
                FIXTURES / "negative" / "cosmos_msg_with_sequence.go",
                Path(ws) / "cosmos_msg_with_sequence.go",
            )
            summary = self.mod.scan_workspace(
                Path(ws), tuple(self.mod._DEFAULT_GUARDS),
            )
            pid = "go.cosmos.message_ordering_replay"
            self.assertEqual(
                summary["patterns"][pid]["hit_count"], 0,
                f"expected 0 hits in negative fixture, got: {summary['patterns'][pid]}",
            )

    # ------------------------------------------------------------------
    # Pattern 9 — lightning htlc_settlement_state_drift
    # ------------------------------------------------------------------
    def test_htlc_state_drift_positive(self):
        with tempfile.TemporaryDirectory() as ws:
            shutil.copy(
                FIXTURES / "positive" / "htlc_state_drift.go",
                Path(ws) / "htlc_state_drift.go",
            )
            summary = self.mod.scan_workspace(
                Path(ws), tuple(self.mod._DEFAULT_GUARDS),
            )
            pid = "go.lightning.htlc_settlement_state_drift"
            self.assertGreaterEqual(
                summary["patterns"][pid]["hit_count"], 1,
                f"expected >=1 hit in positive fixture, got: {summary['patterns'][pid]}",
            )

    def test_htlc_with_crosscheck_negative(self):
        with tempfile.TemporaryDirectory() as ws:
            shutil.copy(
                FIXTURES / "negative" / "htlc_with_crosscheck.go",
                Path(ws) / "htlc_with_crosscheck.go",
            )
            summary = self.mod.scan_workspace(
                Path(ws), tuple(self.mod._DEFAULT_GUARDS),
            )
            pid = "go.lightning.htlc_settlement_state_drift"
            self.assertEqual(
                summary["patterns"][pid]["hit_count"], 0,
                f"expected 0 hits in negative fixture, got: {summary['patterns'][pid]}",
            )

    # ------------------------------------------------------------------
    # Pattern 10 — frost aggregate_pubkey_invariant_violation
    # ------------------------------------------------------------------
    def test_frost_pubkey_invariant_positive(self):
        with tempfile.TemporaryDirectory() as ws:
            shutil.copy(
                FIXTURES / "positive" / "frost_pubkey_invariant.go",
                Path(ws) / "frost_pubkey_invariant.go",
            )
            summary = self.mod.scan_workspace(
                Path(ws), tuple(self.mod._DEFAULT_GUARDS),
            )
            pid = "go.frost.aggregate_pubkey_invariant_violation"
            self.assertGreaterEqual(
                summary["patterns"][pid]["hit_count"], 1,
                f"expected >=1 hit in positive fixture, got: {summary['patterns'][pid]}",
            )
            functions = [
                h["extra"]["function"]
                for h in summary["patterns"][pid]["hits"]
            ]
            self.assertIn("TweakKeyShare", functions)

    def test_frost_pubkey_recomputed_negative(self):
        with tempfile.TemporaryDirectory() as ws:
            shutil.copy(
                FIXTURES / "negative" / "frost_pubkey_recomputed.go",
                Path(ws) / "frost_pubkey_recomputed.go",
            )
            summary = self.mod.scan_workspace(
                Path(ws), tuple(self.mod._DEFAULT_GUARDS),
            )
            pid = "go.frost.aggregate_pubkey_invariant_violation"
            self.assertEqual(
                summary["patterns"][pid]["hit_count"], 0,
                f"expected 0 hits in negative fixture, got: {summary['patterns'][pid]}",
            )

    # ------------------------------------------------------------------
    # Pattern 11 — cosmos gas_price_zero_unchecked
    # ------------------------------------------------------------------
    def test_gas_price_zero_unchecked_positive(self):
        """LEAD solodit-55256 (SEDA M-10) shape: tally divides by gasPrice
        without checking for the zero value first.
        """
        with tempfile.TemporaryDirectory() as ws:
            shutil.copy(
                FIXTURES / "positive" / "gas_price_zero_unchecked.go",
                Path(ws) / "gas_price_zero_unchecked.go",
            )
            summary = self.mod.scan_workspace(
                Path(ws), tuple(self.mod._DEFAULT_GUARDS),
            )
            pid = "go.cosmos.gas_price_zero_unchecked"
            self.assertGreaterEqual(
                summary["patterns"][pid]["hit_count"], 1,
                f"expected >=1 hit in positive fixture, got: {summary['patterns'][pid]}",
            )
            functions = [
                h["extra"]["function"]
                for h in summary["patterns"][pid]["hits"]
            ]
            self.assertIn("tallyDataRequest", functions)

    def test_gas_price_zero_guarded_negative(self):
        with tempfile.TemporaryDirectory() as ws:
            shutil.copy(
                FIXTURES / "negative" / "gas_price_zero_guarded.go",
                Path(ws) / "gas_price_zero_guarded.go",
            )
            summary = self.mod.scan_workspace(
                Path(ws), tuple(self.mod._DEFAULT_GUARDS),
            )
            pid = "go.cosmos.gas_price_zero_unchecked"
            self.assertEqual(
                summary["patterns"][pid]["hit_count"], 0,
                f"expected 0 hits in negative fixture, got: {summary['patterns'][pid]}",
            )

    # ------------------------------------------------------------------
    # Pattern 12 — cosmos vote_extension_unverified
    # ------------------------------------------------------------------
    def test_vote_extension_unverified_positive(self):
        """LEAD solodit-47220 (Ethos OtterSec) shape: iterate vote
        extensions, sum totalVP from proposer-injected metadata, no
        ValidateVoteExtensions call, no per-VE signature verifier.
        """
        with tempfile.TemporaryDirectory() as ws:
            shutil.copy(
                FIXTURES / "positive" / "vote_extension_unverified.go",
                Path(ws) / "vote_extension_unverified.go",
            )
            summary = self.mod.scan_workspace(
                Path(ws), tuple(self.mod._DEFAULT_GUARDS),
            )
            pid = "go.cosmos.vote_extension_unverified"
            self.assertGreaterEqual(
                summary["patterns"][pid]["hit_count"], 1,
                f"expected >=1 hit in positive fixture, got: {summary['patterns'][pid]}",
            )
            functions = [
                h["extra"]["function"]
                for h in summary["patterns"][pid]["hits"]
            ]
            self.assertIn("TallyVoteExtensions", functions)

    def test_vote_extension_validated_negative(self):
        with tempfile.TemporaryDirectory() as ws:
            shutil.copy(
                FIXTURES / "negative" / "vote_extension_validated.go",
                Path(ws) / "vote_extension_validated.go",
            )
            summary = self.mod.scan_workspace(
                Path(ws), tuple(self.mod._DEFAULT_GUARDS),
            )
            pid = "go.cosmos.vote_extension_unverified"
            self.assertEqual(
                summary["patterns"][pid]["hit_count"], 0,
                f"expected 0 hits in negative fixture, got: {summary['patterns'][pid]}",
            )

    # ------------------------------------------------------------------
    # Pattern 13 — tree_node.terminal_state_revival (SP-3049 / LEAD H-D
    # write-side mirror)
    # ------------------------------------------------------------------
    def test_tree_node_terminal_revival_positive(self):
        """SP-3049 vulnerable shape: pre-fix cancelTransferUnlockLeaves
        unconditionally sets every leaf's status to AVAILABLE. Pattern 13
        must fire on BOTH the .SetStatus(...AVAILABLE) form and the
        direct field-assign form.
        """
        with tempfile.TemporaryDirectory() as ws:
            shutil.copy(
                FIXTURES / "positive" / "tree_node_terminal_revival.go",
                Path(ws) / "tree_node_terminal_revival.go",
            )
            summary = self.mod.scan_workspace(
                Path(ws), tuple(self.mod._DEFAULT_GUARDS),
            )
            pid = "go.spark.tree_node.terminal_state_revival"
            self.assertGreaterEqual(
                summary["patterns"][pid]["hit_count"], 2,
                f"expected >=2 hits in positive fixture, got: {summary['patterns'][pid]}",
            )
            functions = [
                h["extra"]["function"]
                for h in summary["patterns"][pid]["hits"]
            ]
            self.assertIn("CancelTransferUnlockLeavesVulnerable", functions)
            self.assertIn("ResetLeafField", functions)
            forms = {h["extra"]["mutation_form"] for h in summary["patterns"][pid]["hits"]}
            self.assertIn("set_status_builder", forms)
            self.assertIn("field_assign", forms)

    def test_tree_node_terminal_revival_with_guard_negative(self):
        """SP-3049 fix shape: the ent-builder mutation is preceded by
        either Status.CanBecomeAvailable(), TreeNodeCanBecomeAvailable(),
        or an explicit terminal-status compare. Pattern 13 must NOT fire.
        """
        with tempfile.TemporaryDirectory() as ws:
            shutil.copy(
                FIXTURES / "negative" / "tree_node_with_can_become_available_guard.go",
                Path(ws) / "tree_node_with_can_become_available_guard.go",
            )
            summary = self.mod.scan_workspace(
                Path(ws), tuple(self.mod._DEFAULT_GUARDS),
            )
            pid = "go.spark.tree_node.terminal_state_revival"
            self.assertEqual(
                summary["patterns"][pid]["hit_count"], 0,
                f"expected 0 hits in negative fixture, got: {summary['patterns'][pid]}",
            )

    def test_tree_node_terminal_revival_skips_test_files(self):
        """Pattern 13 must not fire on *_test.go fixtures: production tests
        legitimately force terminal statuses in setup helpers (e.g.
        TestCancelTransfer_DoesNotReviveExitedLeaf) and flagging them is
        noise.
        """
        with tempfile.TemporaryDirectory() as ws:
            # Take the POSITIVE fixture body but rename it as a Go test file.
            src = (FIXTURES / "positive" / "tree_node_terminal_revival.go").read_text()
            (Path(ws) / "cancel_handler_test.go").write_text(src)
            summary = self.mod.scan_workspace(
                Path(ws), tuple(self.mod._DEFAULT_GUARDS),
            )
            pid = "go.spark.tree_node.terminal_state_revival"
            self.assertEqual(
                summary["patterns"][pid]["hit_count"], 0,
                f"expected 0 hits when only *_test.go files exist; got: {summary['patterns'][pid]}",
            )

    # ------------------------------------------------------------------
    # Pattern 13 (Worker-FFF) — coop_exit.coordinator_confirmation_guard_asymmetry
    # ------------------------------------------------------------------
    def test_coop_exit_coord_guard_asymmetry_positive(self):
        """SP-2961 (LEAD 1) shape. Multi-file fixture: the package contains
        the guard helper checkCoopExitTxBroadcasted (in transfer_handler.go)
        and the coordinator-side VerifyAndUpdateTransfer (in
        finalize_signature_handler.go) loads a transfer in pre-finalize
        ReceiverRefundSigned state but does NOT call the guard. Detector's
        package_coop_exit_guard arm should flag VerifyAndUpdateTransfer
        and ONLY VerifyAndUpdateTransfer.
        """
        with tempfile.TemporaryDirectory() as ws:
            src_dir = FIXTURES / "positive" / "coop_exit_coord_guard_asymmetry"
            dst_dir = Path(ws) / "coop_exit_coord_guard_asymmetry"
            shutil.copytree(src_dir, dst_dir)
            summary = self.mod.scan_workspace(
                Path(ws), tuple(self.mod._DEFAULT_GUARDS),
            )
            pid = "go.spark.coop_exit.coordinator_confirmation_guard_asymmetry"
            self.assertGreaterEqual(
                summary["patterns"][pid]["hit_count"], 1,
                f"expected >=1 hit in positive fixture, got: {summary['patterns'][pid]}",
            )
            functions = [
                h["extra"]["function"]
                for h in summary["patterns"][pid]["hits"]
            ]
            self.assertIn("VerifyAndUpdateTransfer", functions,
                          f"expected VerifyAndUpdateTransfer flagged, got {functions}")
            # FinalizeTransferWithTransferPackage calls the guard — must NOT
            # be flagged.
            self.assertNotIn("FinalizeTransferWithTransferPackage", functions,
                             f"guarded sibling must not be flagged, got {functions}")
            # checkCoopExitTxBroadcasted is the guard def itself — must NOT
            # be flagged.
            self.assertNotIn("checkCoopExitTxBroadcasted", functions,
                             f"guard def must not be flagged, got {functions}")
            # Verify predicate_arm tag is present.
            arms = {
                h["extra"].get("predicate_arm")
                for h in summary["patterns"][pid]["hits"]
            }
            self.assertIn("package_coop_exit_guard", arms,
                          f"expected package_coop_exit_guard arm, got {arms}")

    def test_coop_exit_coord_guard_asymmetry_negative(self):
        """Post-SP-2961 fix shape. Coordinator-side VerifyAndUpdateTransfer
        now calls checkCoopExitTxBroadcasted. Detector must NOT fire.
        """
        with tempfile.TemporaryDirectory() as ws:
            src_dir = FIXTURES / "negative" / "coop_exit_coord_guard_asymmetry"
            dst_dir = Path(ws) / "coop_exit_coord_guard_asymmetry"
            shutil.copytree(src_dir, dst_dir)
            summary = self.mod.scan_workspace(
                Path(ws), tuple(self.mod._DEFAULT_GUARDS),
            )
            pid = "go.spark.coop_exit.coordinator_confirmation_guard_asymmetry"
            self.assertEqual(
                summary["patterns"][pid]["hit_count"], 0,
                f"expected 0 hits in negative fixture, got: {summary['patterns'][pid]}",
            )

    def test_coop_exit_coord_guard_pattern_id_registered(self):
        """Pattern slug must appear in the runner's pattern_results dict
        even when the workspace has no Go files (schema registration test).
        """
        with tempfile.TemporaryDirectory() as ws:
            (Path(ws) / "README.md").write_text("hello")
            summary = self.mod.scan_workspace(
                Path(ws), tuple(self.mod._DEFAULT_GUARDS),
            )
            self.assertIn(
                "go.spark.coop_exit.coordinator_confirmation_guard_asymmetry",
                summary["patterns"],
                f"pattern slug must be registered, got keys: "
                f"{sorted(summary['patterns'].keys())}",
            )

    # ------------------------------------------------------------------
    # Pattern 14 — coop_exit.key_tweak_resumability (SP-2988 — commits
    # c36d0a4 + 9e06adf on buildonspark/spark)
    # ------------------------------------------------------------------
    def test_coop_exit_key_tweak_resumability_positive(self):
        """SP-2988 vulnerable shape: tweakKeysForCoopExit iterates
        transferLeaves and mutates per-leaf state via ClearKeyTweak +
        Update().Save(ctx) WITHOUT an in-loop continue keyed off the
        cleared sentinel field. Pattern 14 must fire.
        """
        with tempfile.TemporaryDirectory() as ws:
            shutil.copy(
                FIXTURES / "positive" / "coop_exit_key_tweak_no_resume.go",
                Path(ws) / "coop_exit_key_tweak_no_resume.go",
            )
            summary = self.mod.scan_workspace(
                Path(ws), tuple(self.mod._DEFAULT_GUARDS),
            )
            pid = "go.spark.coop_exit.key_tweak_resumability"
            self.assertGreaterEqual(
                summary["patterns"][pid]["hit_count"], 1,
                f"expected >=1 hit in positive fixture, got: {summary['patterns'][pid]}",
            )
            functions = [
                h["extra"]["function"]
                for h in summary["patterns"][pid]["hits"]
            ]
            self.assertIn("tweakKeysForCoopExitVulnerable", functions)
            collections = {
                h["extra"]["collection"]
                for h in summary["patterns"][pid]["hits"]
            }
            self.assertIn("transferLeaves", collections)

    def test_coop_exit_key_tweak_resumability_with_guard_negative(self):
        """SP-2988 fix shapes: BOTH ``if leaf.KeyTweak == nil { continue }``
        (post-fix c36d0a4 form) AND ``if len(leaf.KeyTweak) == 0 { continue
        }`` (v1 9e06adf form) must suppress the detector.
        """
        with tempfile.TemporaryDirectory() as ws:
            shutil.copy(
                FIXTURES / "negative" / "coop_exit_key_tweak_with_resume.go",
                Path(ws) / "coop_exit_key_tweak_with_resume.go",
            )
            summary = self.mod.scan_workspace(
                Path(ws), tuple(self.mod._DEFAULT_GUARDS),
            )
            pid = "go.spark.coop_exit.key_tweak_resumability"
            self.assertEqual(
                summary["patterns"][pid]["hit_count"], 0,
                f"expected 0 hits in negative fixture, got: {summary['patterns'][pid]}",
            )

    def test_coop_exit_key_tweak_resumability_skips_test_files(self):
        """Pattern 14 must NOT fire on *_test.go fixtures: setup helpers
        legitimately mutate per-leaf state without resumability guards
        when staging unit-test scenarios.
        """
        with tempfile.TemporaryDirectory() as ws:
            src = (FIXTURES / "positive" / "coop_exit_key_tweak_no_resume.go").read_text()
            (Path(ws) / "watch_chain_test.go").write_text(src)
            summary = self.mod.scan_workspace(
                Path(ws), tuple(self.mod._DEFAULT_GUARDS),
            )
            pid = "go.spark.coop_exit.key_tweak_resumability"
            self.assertEqual(
                summary["patterns"][pid]["hit_count"], 0,
                f"expected 0 hits when only *_test.go files exist; got: {summary['patterns'][pid]}",
            )

    # ------------------------------------------------------------------
    # Pattern 15 — go.spark.signed_payload.req_identity_validator
    # (L14-BACK-1; SP-5998 ``6daafae89b``)
    # ------------------------------------------------------------------
    def test_signed_payload_req_identity_no_db_positive(self):
        """SP-5998 pre-fix: req-identity passed straight to
        ValidateTransferPackage without DB-sourced identity reconciliation.
        """
        with tempfile.TemporaryDirectory() as ws:
            shutil.copy(
                FIXTURES / "positive" / "signed_payload_req_identity_no_db.go",
                Path(ws) / "signed_payload_req_identity_no_db.go",
            )
            summary = self.mod.scan_workspace(
                Path(ws), tuple(self.mod._DEFAULT_GUARDS),
            )
            pid = "go.spark.signed_payload.req_identity_validator"
            self.assertGreaterEqual(
                summary["patterns"][pid]["hit_count"], 1,
                f"expected >=1 hit in positive fixture, got: {summary['patterns'][pid]}",
            )
            functions = [
                h["extra"]["function"]
                for h in summary["patterns"][pid]["hits"]
            ]
            self.assertIn("FinalizeTransferWithTransferPackagePreFix", functions)

    def test_signed_payload_req_identity_with_db_compare_negative(self):
        """SP-5998 post-fix: mimo.GetSingleTransferSender + Equals compare
        before ValidateTransferPackage suppresses the detector.
        """
        with tempfile.TemporaryDirectory() as ws:
            shutil.copy(
                FIXTURES / "negative" / "signed_payload_req_identity_with_db_compare.go",
                Path(ws) / "signed_payload_req_identity_with_db_compare.go",
            )
            summary = self.mod.scan_workspace(
                Path(ws), tuple(self.mod._DEFAULT_GUARDS),
            )
            pid = "go.spark.signed_payload.req_identity_validator"
            self.assertEqual(
                summary["patterns"][pid]["hit_count"], 0,
                f"expected 0 hits in negative fixture, got: {summary['patterns'][pid]}",
            )

    def test_signed_payload_req_identity_skips_test_files(self):
        """Pattern 15 must NOT fire on *_test.go fixtures."""
        with tempfile.TemporaryDirectory() as ws:
            src = (FIXTURES / "positive" / "signed_payload_req_identity_no_db.go").read_text()
            (Path(ws) / "transfer_handler_test.go").write_text(src)
            summary = self.mod.scan_workspace(
                Path(ws), tuple(self.mod._DEFAULT_GUARDS),
            )
            pid = "go.spark.signed_payload.req_identity_validator"
            self.assertEqual(
                summary["patterns"][pid]["hit_count"], 0,
                f"expected 0 hits in *_test.go files, got: {summary['patterns'][pid]}",
            )

    # ------------------------------------------------------------------
    # Pattern 16 — go.spark.retry.prior_phase_commit_check
    # (L14-BACK-2; SP-5498 ``f26284dd5f``)
    # ------------------------------------------------------------------
    def test_retry_prior_phase_no_check_positive(self):
        """SP-5498 pre-fix: coordinator-portion key-tweak package
        decrypted unconditionally, no useStoredKeyTweaks gate.
        """
        with tempfile.TemporaryDirectory() as ws:
            shutil.copy(
                FIXTURES / "positive" / "retry_no_prior_phase_check.go",
                Path(ws) / "retry_no_prior_phase_check.go",
            )
            summary = self.mod.scan_workspace(
                Path(ws), tuple(self.mod._DEFAULT_GUARDS),
            )
            pid = "go.spark.retry.prior_phase_commit_check"
            self.assertGreaterEqual(
                summary["patterns"][pid]["hit_count"], 1,
                f"expected >=1 hit in positive fixture, got: {summary['patterns'][pid]}",
            )
            functions = [
                h["extra"]["function"]
                for h in summary["patterns"][pid]["hits"]
            ]
            self.assertIn("ClaimTransferPreFix", functions)

    def test_retry_prior_phase_with_check_negative(self):
        """SP-5498 post-fix: useStoredKeyTweaks gate keyed off
        TransferReceiverStatusKeyTweakLocked / KeyTweakApplied /
        RefundSigned suppresses the detector.
        """
        with tempfile.TemporaryDirectory() as ws:
            shutil.copy(
                FIXTURES / "negative" / "retry_with_prior_phase_check.go",
                Path(ws) / "retry_with_prior_phase_check.go",
            )
            summary = self.mod.scan_workspace(
                Path(ws), tuple(self.mod._DEFAULT_GUARDS),
            )
            pid = "go.spark.retry.prior_phase_commit_check"
            self.assertEqual(
                summary["patterns"][pid]["hit_count"], 0,
                f"expected 0 hits in negative fixture, got: {summary['patterns'][pid]}",
            )

    def test_retry_prior_phase_skips_test_files(self):
        """Pattern 16 must NOT fire on *_test.go fixtures."""
        with tempfile.TemporaryDirectory() as ws:
            src = (FIXTURES / "positive" / "retry_no_prior_phase_check.go").read_text()
            (Path(ws) / "transfer_handler_test.go").write_text(src)
            summary = self.mod.scan_workspace(
                Path(ws), tuple(self.mod._DEFAULT_GUARDS),
            )
            pid = "go.spark.retry.prior_phase_commit_check"
            self.assertEqual(
                summary["patterns"][pid]["hit_count"], 0,
                f"expected 0 hits in *_test.go files, got: {summary['patterns'][pid]}",
            )

    # ------------------------------------------------------------------
    # Pattern 17 — go.spark.cross_so.tweak_guard_pre_post_persist
    # (L14-BACK-5; SP-5589 ``dae7686f2c``)
    # ------------------------------------------------------------------
    def test_cross_so_tweak_guard_post_only_positive(self):
        """SP-5589 pre-fix shape (one half only): post-persist DB-backed
        validator without pre-persist in-memory matcher.
        """
        with tempfile.TemporaryDirectory() as ws:
            shutil.copy(
                FIXTURES / "positive" / "cross_so_tweak_guard_post_only.go",
                Path(ws) / "cross_so_tweak_guard_post_only.go",
            )
            summary = self.mod.scan_workspace(
                Path(ws), tuple(self.mod._DEFAULT_GUARDS),
            )
            pid = "go.spark.cross_so.tweak_guard_pre_post_persist"
            self.assertGreaterEqual(
                summary["patterns"][pid]["hit_count"], 1,
                f"expected >=1 hit in positive fixture, got: {summary['patterns'][pid]}",
            )
            functions = [
                h["extra"]["function"]
                for h in summary["patterns"][pid]["hits"]
            ]
            self.assertIn("CommitSenderKeyTweaksPostOnly", functions)
            halves = {
                h["extra"]["guard_half"]
                for h in summary["patterns"][pid]["hits"]
            }
            self.assertIn("post_persist_only", halves)

    def test_cross_so_tweak_guard_pre_and_post_negative(self):
        """SP-5589 post-fix shape: BOTH halves invoked — pre-persist match
        AND post-persist validate. Detector must NOT fire.
        """
        with tempfile.TemporaryDirectory() as ws:
            shutil.copy(
                FIXTURES / "negative" / "cross_so_tweak_guard_pre_and_post.go",
                Path(ws) / "cross_so_tweak_guard_pre_and_post.go",
            )
            summary = self.mod.scan_workspace(
                Path(ws), tuple(self.mod._DEFAULT_GUARDS),
            )
            pid = "go.spark.cross_so.tweak_guard_pre_post_persist"
            self.assertEqual(
                summary["patterns"][pid]["hit_count"], 0,
                f"expected 0 hits in negative fixture, got: {summary['patterns'][pid]}",
            )

    def test_cross_so_tweak_guard_skips_test_files(self):
        """Pattern 17 must NOT fire on *_test.go fixtures."""
        with tempfile.TemporaryDirectory() as ws:
            src = (FIXTURES / "positive" / "cross_so_tweak_guard_post_only.go").read_text()
            (Path(ws) / "base_transfer_handler_test.go").write_text(src)
            summary = self.mod.scan_workspace(
                Path(ws), tuple(self.mod._DEFAULT_GUARDS),
            )
            pid = "go.spark.cross_so.tweak_guard_pre_post_persist"
            self.assertEqual(
                summary["patterns"][pid]["hit_count"], 0,
                f"expected 0 hits in *_test.go files, got: {summary['patterns'][pid]}",
            )

    # ------------------------------------------------------------------
    # Pattern 18 — go.spark.leaf_marshal.knob_gated_residual_disclosure
    # (L14-BACK-3; SP-5846 ``25c37ff813``)
    # ------------------------------------------------------------------
    def test_knob_gated_marshal_residual_positive(self):
        """SP-5846 residual: receiver-facing endpoint marshals via the
        unfiltered MarshalProto under a knob-gated branch with no
        per-receiver companion call.
        """
        with tempfile.TemporaryDirectory() as ws:
            shutil.copy(
                FIXTURES / "positive" / "knob_gated_marshal_residual.go",
                Path(ws) / "knob_gated_marshal_residual.go",
            )
            summary = self.mod.scan_workspace(
                Path(ws), tuple(self.mod._DEFAULT_GUARDS),
            )
            pid = "go.spark.leaf_marshal.knob_gated_residual_disclosure"
            self.assertGreaterEqual(
                summary["patterns"][pid]["hit_count"], 1,
                f"expected >=1 hit in positive fixture, got: {summary['patterns'][pid]}",
            )
            functions = [
                h["extra"]["function"]
                for h in summary["patterns"][pid]["hits"]
            ]
            self.assertIn("QueryPendingTransfersResidual", functions)

    def test_knob_gated_marshal_with_per_receiver_negative(self):
        """SP-5846 post-fix: BOTH MarshalProtoForReceiver AND MarshalProto
        are present — the unfiltered call sits on the safe sender / non-
        MIMO branch. Detector must NOT fire.
        """
        with tempfile.TemporaryDirectory() as ws:
            shutil.copy(
                FIXTURES / "negative" / "knob_gated_marshal_with_per_receiver.go",
                Path(ws) / "knob_gated_marshal_with_per_receiver.go",
            )
            summary = self.mod.scan_workspace(
                Path(ws), tuple(self.mod._DEFAULT_GUARDS),
            )
            pid = "go.spark.leaf_marshal.knob_gated_residual_disclosure"
            self.assertEqual(
                summary["patterns"][pid]["hit_count"], 0,
                f"expected 0 hits in negative fixture, got: {summary['patterns'][pid]}",
            )

    def test_knob_gated_marshal_skips_test_files(self):
        """Pattern 18 must NOT fire on *_test.go fixtures."""
        with tempfile.TemporaryDirectory() as ws:
            src = (FIXTURES / "positive" / "knob_gated_marshal_residual.go").read_text()
            (Path(ws) / "transfer_handler_test.go").write_text(src)
            summary = self.mod.scan_workspace(
                Path(ws), tuple(self.mod._DEFAULT_GUARDS),
            )
            pid = "go.spark.leaf_marshal.knob_gated_residual_disclosure"
            self.assertEqual(
                summary["patterns"][pid]["hit_count"], 0,
                f"expected 0 hits in *_test.go files, got: {summary['patterns'][pid]}",
            )

    # ------------------------------------------------------------------
    # Pattern 19 — go.spark.background_session.parent_tx_reopen_hook_missing
    # (L14-BACK-4; SP-6329 ``dfb6b50ec9``)
    # ------------------------------------------------------------------
    def test_background_session_no_reopen_hook_positive(self):
        """SP-6329 pre-fix: background-session function shares parent tx
        with deferred cleanup but no OnCommit / OnRollback hooks.
        """
        with tempfile.TemporaryDirectory() as ws:
            shutil.copy(
                FIXTURES / "positive" / "background_session_no_reopen_hook.go",
                Path(ws) / "background_session_no_reopen_hook.go",
            )
            summary = self.mod.scan_workspace(
                Path(ws), tuple(self.mod._DEFAULT_GUARDS),
            )
            pid = "go.spark.background_session.parent_tx_reopen_hook_missing"
            self.assertGreaterEqual(
                summary["patterns"][pid]["hit_count"], 1,
                f"expected >=1 hit in positive fixture, got: {summary['patterns'][pid]}",
            )
            functions = [
                h["extra"]["function"]
                for h in summary["patterns"][pid]["hits"]
            ]
            self.assertIn("CleanupChainwatcherSecretsResidual", functions)

    def test_background_session_with_reopen_hook_negative(self):
        """SP-6329 post-fix: bindTx registers OnCommit + OnRollback hooks
        before deferred cleanup. Detector must NOT fire.
        """
        with tempfile.TemporaryDirectory() as ws:
            shutil.copy(
                FIXTURES / "negative" / "background_session_with_reopen_hook.go",
                Path(ws) / "background_session_with_reopen_hook.go",
            )
            summary = self.mod.scan_workspace(
                Path(ws), tuple(self.mod._DEFAULT_GUARDS),
            )
            pid = "go.spark.background_session.parent_tx_reopen_hook_missing"
            self.assertEqual(
                summary["patterns"][pid]["hit_count"], 0,
                f"expected 0 hits in negative fixture, got: {summary['patterns'][pid]}",
            )

    def test_background_session_skips_test_files(self):
        """Pattern 19 must NOT fire on *_test.go fixtures."""
        with tempfile.TemporaryDirectory() as ws:
            src = (FIXTURES / "positive" / "background_session_no_reopen_hook.go").read_text()
            (Path(ws) / "watch_chain_test.go").write_text(src)
            summary = self.mod.scan_workspace(
                Path(ws), tuple(self.mod._DEFAULT_GUARDS),
            )
            pid = "go.spark.background_session.parent_tx_reopen_hook_missing"
            self.assertEqual(
                summary["patterns"][pid]["hit_count"], 0,
                f"expected 0 hits in *_test.go files, got: {summary['patterns'][pid]}",
            )

    # ------------------------------------------------------------------
    # Pattern 20 — go.spark.post_commit_rollback_unprotected
    # (SPARK-PT-L15-001; SP-6390 ``a5550e78e5632a8675bfefdad74a6e6054d89d2f``)
    # ------------------------------------------------------------------
    def test_post_commit_rollback_unprotected_positive(self):
        """SP-6390 pre-fix: defer Rollback() then Commit() with NO
        ``committed`` boolean guard. Both sister functions must be flagged.
        """
        with tempfile.TemporaryDirectory() as ws:
            shutil.copy(
                FIXTURES / "positive" / "post_commit_rollback_unprotected.go",
                Path(ws) / "post_commit_rollback_unprotected.go",
            )
            summary = self.mod.scan_workspace(
                Path(ws), tuple(self.mod._DEFAULT_GUARDS),
            )
            pid = "go.spark.post_commit_rollback_unprotected"
            self.assertGreaterEqual(
                summary["patterns"][pid]["hit_count"], 2,
                f"expected >=2 hits in positive fixture, got: {summary['patterns'][pid]}",
            )
            functions = {
                h["extra"]["function"]
                for h in summary["patterns"][pid]["hits"]
            }
            self.assertIn("CleanupSigningKeyshareSecretPreFix", functions)
            self.assertIn("PrepareSigningKeyshareSecretRotationPreFix", functions)

    def test_post_commit_rollback_with_committed_guard_negative(self):
        """SP-6390 post-fix: ``committed`` boolean guards the deferred
        Rollback. Detector must NOT fire.
        """
        with tempfile.TemporaryDirectory() as ws:
            shutil.copy(
                FIXTURES / "negative" / "post_commit_rollback_with_committed_guard.go",
                Path(ws) / "post_commit_rollback_with_committed_guard.go",
            )
            summary = self.mod.scan_workspace(
                Path(ws), tuple(self.mod._DEFAULT_GUARDS),
            )
            pid = "go.spark.post_commit_rollback_unprotected"
            self.assertEqual(
                summary["patterns"][pid]["hit_count"], 0,
                f"expected 0 hits in negative fixture, got: {summary['patterns'][pid]}",
            )

    def test_post_commit_rollback_skips_test_files(self):
        """Pattern 20 must NOT fire on *_test.go fixtures."""
        with tempfile.TemporaryDirectory() as ws:
            src = (FIXTURES / "positive" / "post_commit_rollback_unprotected.go").read_text()
            (Path(ws) / "signingkeyshare_extension_test.go").write_text(src)
            summary = self.mod.scan_workspace(
                Path(ws), tuple(self.mod._DEFAULT_GUARDS),
            )
            pid = "go.spark.post_commit_rollback_unprotected"
            self.assertEqual(
                summary["patterns"][pid]["hit_count"], 0,
                f"expected 0 hits in *_test.go files, got: {summary['patterns'][pid]}",
            )

    # ------------------------------------------------------------------
    # Pattern 21 — go.spark.cron_forupdate.adjacent_read_lock_missing
    # (L14-BACK-6; SP-5433 ``594a8dbab7``)
    # ------------------------------------------------------------------
    def test_cron_forupdate_adjacent_read_positive(self):
        """SP-5433 pre-fix: read uses Query().Only(ctx) WITHOUT ForUpdate
        in a package whose cron task DOES use ForUpdate over the same
        entity. Both read-side functions must be flagged.
        """
        with tempfile.TemporaryDirectory() as ws:
            shutil.copy(
                FIXTURES / "positive" / "cron_forupdate_adjacent_read.go",
                Path(ws) / "cron_forupdate_adjacent_read.go",
            )
            summary = self.mod.scan_workspace(
                Path(ws), tuple(self.mod._DEFAULT_GUARDS),
            )
            pid = "go.spark.cron_forupdate.adjacent_read_lock_missing"
            self.assertGreaterEqual(
                summary["patterns"][pid]["hit_count"], 2,
                f"expected >=2 hits in positive fixture, got: {summary['patterns'][pid]}",
            )
            functions = {
                h["extra"]["function"]
                for h in summary["patterns"][pid]["hits"]
            }
            self.assertIn("CreatePrimaryCounterSwap", functions)
            self.assertIn("InitiatePrimaryTransfer", functions)
            self.assertNotIn("CancelStuckCounterSwap", functions)

    def test_cron_forupdate_adjacent_read_with_lock_negative(self):
        """SP-5433 post-fix: read uses ForUpdate. Detector must NOT fire."""
        with tempfile.TemporaryDirectory() as ws:
            shutil.copy(
                FIXTURES / "negative" / "cron_forupdate_with_lock.go",
                Path(ws) / "cron_forupdate_with_lock.go",
            )
            summary = self.mod.scan_workspace(
                Path(ws), tuple(self.mod._DEFAULT_GUARDS),
            )
            pid = "go.spark.cron_forupdate.adjacent_read_lock_missing"
            self.assertEqual(
                summary["patterns"][pid]["hit_count"], 0,
                f"expected 0 hits in negative fixture, got: {summary['patterns'][pid]}",
            )

    def test_cron_forupdate_skips_test_files(self):
        """Pattern 21 must NOT fire on *_test.go fixtures."""
        with tempfile.TemporaryDirectory() as ws:
            src = (FIXTURES / "positive" / "cron_forupdate_adjacent_read.go").read_text()
            (Path(ws) / "counter_swap_test.go").write_text(src)
            summary = self.mod.scan_workspace(
                Path(ws), tuple(self.mod._DEFAULT_GUARDS),
            )
            pid = "go.spark.cron_forupdate.adjacent_read_lock_missing"
            self.assertEqual(
                summary["patterns"][pid]["hit_count"], 0,
                f"expected 0 hits in *_test.go files, got: {summary['patterns'][pid]}",
            )

    # ------------------------------------------------------------------
    # Pattern 22 — go.spark.coordinator_fanout.tx_commit_before_remote_call
    # (L14-BACK-7; SP-5783 ``b154174cee``)
    # ------------------------------------------------------------------
    def test_coordinator_fanout_no_commit_positive(self):
        """SP-5783 pre-fix: tx-bound write then ExecuteTaskWithAllOperators
        without an intermediate commit. Both sister functions must be
        flagged.
        """
        with tempfile.TemporaryDirectory() as ws:
            shutil.copy(
                FIXTURES / "positive" / "coordinator_fanout_no_commit.go",
                Path(ws) / "coordinator_fanout_no_commit.go",
            )
            summary = self.mod.scan_workspace(
                Path(ws), tuple(self.mod._DEFAULT_GUARDS),
            )
            pid = "go.spark.coordinator_fanout.tx_commit_before_remote_call"
            self.assertGreaterEqual(
                summary["patterns"][pid]["hit_count"], 2,
                f"expected >=2 hits in positive fixture, got: {summary['patterns'][pid]}",
            )
            functions = {
                h["extra"]["function"]
                for h in summary["patterns"][pid]["hits"]
            }
            self.assertIn("SettlePreimageSwapCoordinator", functions)
            self.assertIn("CoopExitCoordinatorSettleAndFanout", functions)

    def test_coordinator_fanout_with_commit_negative(self):
        """SP-5783 post-fix: explicit Commit between write and fanout.
        Detector must NOT fire.
        """
        with tempfile.TemporaryDirectory() as ws:
            shutil.copy(
                FIXTURES / "negative" / "coordinator_fanout_with_commit.go",
                Path(ws) / "coordinator_fanout_with_commit.go",
            )
            summary = self.mod.scan_workspace(
                Path(ws), tuple(self.mod._DEFAULT_GUARDS),
            )
            pid = "go.spark.coordinator_fanout.tx_commit_before_remote_call"
            self.assertEqual(
                summary["patterns"][pid]["hit_count"], 0,
                f"expected 0 hits in negative fixture, got: {summary['patterns'][pid]}",
            )

    def test_coordinator_fanout_skips_test_files(self):
        """Pattern 22 must NOT fire on *_test.go fixtures."""
        with tempfile.TemporaryDirectory() as ws:
            src = (FIXTURES / "positive" / "coordinator_fanout_no_commit.go").read_text()
            (Path(ws) / "preimage_swap_test.go").write_text(src)
            summary = self.mod.scan_workspace(
                Path(ws), tuple(self.mod._DEFAULT_GUARDS),
            )
            pid = "go.spark.coordinator_fanout.tx_commit_before_remote_call"
            self.assertEqual(
                summary["patterns"][pid]["hit_count"], 0,
                f"expected 0 hits in *_test.go files, got: {summary['patterns'][pid]}",
            )

    # ------------------------------------------------------------------
    # Pattern 23 — go.spark.grpc.default_service_config_last_write_wins
    # (SPARK-PT-L15-009; SP-6314 ``51dc21a3ce``)
    # ------------------------------------------------------------------
    def test_grpc_default_service_config_dup_positive(self):
        """SP-6314 pre-fix: TWO grpc.WithDefaultServiceConfig calls on the
        same DialOption chain. Both sister functions must be flagged.
        """
        with tempfile.TemporaryDirectory() as ws:
            shutil.copy(
                FIXTURES / "positive" / "grpc_default_service_config_dup.go",
                Path(ws) / "grpc_default_service_config_dup.go",
            )
            summary = self.mod.scan_workspace(
                Path(ws), tuple(self.mod._DEFAULT_GUARDS),
            )
            pid = "go.spark.grpc.default_service_config_last_write_wins"
            self.assertGreaterEqual(
                summary["patterns"][pid]["hit_count"], 2,
                f"expected >=2 hits in positive fixture, got: {summary['patterns'][pid]}",
            )
            functions = {
                h["extra"]["function"]
                for h in summary["patterns"][pid]["hits"]
            }
            self.assertIn("dialWithRetryAndLB", functions)
            self.assertIn("dialChainAppend", functions)

    def test_grpc_default_service_config_single_negative(self):
        """SP-6314 post-fix: a single WithDefaultServiceConfig call.
        Detector must NOT fire.
        """
        with tempfile.TemporaryDirectory() as ws:
            shutil.copy(
                FIXTURES / "negative" / "grpc_default_service_config_single.go",
                Path(ws) / "grpc_default_service_config_single.go",
            )
            summary = self.mod.scan_workspace(
                Path(ws), tuple(self.mod._DEFAULT_GUARDS),
            )
            pid = "go.spark.grpc.default_service_config_last_write_wins"
            self.assertEqual(
                summary["patterns"][pid]["hit_count"], 0,
                f"expected 0 hits in negative fixture, got: {summary['patterns'][pid]}",
            )

    def test_grpc_default_service_config_skips_test_files(self):
        """Pattern 23 must NOT fire on *_test.go fixtures."""
        with tempfile.TemporaryDirectory() as ws:
            src = (FIXTURES / "positive" / "grpc_default_service_config_dup.go").read_text()
            (Path(ws) / "grpc_dial_test.go").write_text(src)
            summary = self.mod.scan_workspace(
                Path(ws), tuple(self.mod._DEFAULT_GUARDS),
            )
            pid = "go.spark.grpc.default_service_config_last_write_wins"
            self.assertEqual(
                summary["patterns"][pid]["hit_count"], 0,
                f"expected 0 hits in *_test.go files, got: {summary['patterns'][pid]}",
            )

    # ------------------------------------------------------------------
    # Pattern 24 — go.spark.multi_receiver.rollup_first_only
    # ------------------------------------------------------------------
    def test_multi_receiver_rollup_first_only_positive(self):
        """SP-5842 pre-fix: CancelStuckTransfer / RefundExpiredTransfer
        collapse to ``QueryReceivers().First(ctx)`` / ``receivers[0]``.
        Both sister functions must be flagged.
        """
        with tempfile.TemporaryDirectory() as ws:
            shutil.copy(
                FIXTURES / "positive" / "multi_receiver_rollup_first_only.go",
                Path(ws) / "multi_receiver_rollup_first_only.go",
            )
            summary = self.mod.scan_workspace(
                Path(ws), tuple(self.mod._DEFAULT_GUARDS),
            )
            pid = "go.spark.multi_receiver.rollup_first_only"
            self.assertGreaterEqual(
                summary["patterns"][pid]["hit_count"], 2,
                f"expected >=2 hits in positive fixture, got: {summary['patterns'][pid]}",
            )
            functions = {
                h["extra"]["function"]
                for h in summary["patterns"][pid]["hits"]
            }
            self.assertIn("CancelStuckTransfer", functions)
            self.assertIn("RefundExpiredTransfer", functions)

    def test_multi_receiver_rollup_with_enumeration_negative(self):
        """SP-5842 post-fix: enumerate every receiver via ``range``.
        Detector must NOT fire.
        """
        with tempfile.TemporaryDirectory() as ws:
            shutil.copy(
                FIXTURES / "negative" / "multi_receiver_rollup_with_enumeration.go",
                Path(ws) / "multi_receiver_rollup_with_enumeration.go",
            )
            summary = self.mod.scan_workspace(
                Path(ws), tuple(self.mod._DEFAULT_GUARDS),
            )
            pid = "go.spark.multi_receiver.rollup_first_only"
            self.assertEqual(
                summary["patterns"][pid]["hit_count"], 0,
                f"expected 0 hits in negative fixture, got: {summary['patterns'][pid]}",
            )

    def test_multi_receiver_rollup_skips_test_files(self):
        """Pattern 24 must NOT fire on *_test.go fixtures."""
        with tempfile.TemporaryDirectory() as ws:
            src = (FIXTURES / "positive" / "multi_receiver_rollup_first_only.go").read_text()
            (Path(ws) / "multi_receiver_test.go").write_text(src)
            summary = self.mod.scan_workspace(
                Path(ws), tuple(self.mod._DEFAULT_GUARDS),
            )
            pid = "go.spark.multi_receiver.rollup_first_only"
            self.assertEqual(
                summary["patterns"][pid]["hit_count"], 0,
                f"expected 0 hits in *_test.go files, got: {summary['patterns'][pid]}",
            )

    # ------------------------------------------------------------------
    # Pattern 25 — go.spark.so_pubkey.req_payload_not_session
    # ------------------------------------------------------------------
    def test_so_pubkey_req_payload_not_session_positive(self):
        """Bug shape: handler reads req.<*>(SO|Operator)<*>(Public|Identity)Key
        and feeds it into a downstream resolver with no session-bound
        identity check. Both sister functions must be flagged.
        """
        with tempfile.TemporaryDirectory() as ws:
            shutil.copy(
                FIXTURES / "positive" / "so_pubkey_req_payload_not_session.go",
                Path(ws) / "so_pubkey_req_payload_not_session.go",
            )
            summary = self.mod.scan_workspace(
                Path(ws), tuple(self.mod._DEFAULT_GUARDS),
            )
            pid = "go.spark.so_pubkey.req_payload_not_session"
            self.assertGreaterEqual(
                summary["patterns"][pid]["hit_count"], 2,
                f"expected >=2 hits in positive fixture, got: {summary['patterns'][pid]}",
            )
            functions = {
                h["extra"]["function"]
                for h in summary["patterns"][pid]["hits"]
            }
            self.assertIn("VerifyOperatorSignatureFromReq", functions)
            self.assertIn("DispatchSignedToSO", functions)

    def test_so_pubkey_session_bound_negative(self):
        """Defended shape: handler reads h.config.Identifier or
        session.OperatorPublicKey. Detector must NOT fire.
        """
        with tempfile.TemporaryDirectory() as ws:
            shutil.copy(
                FIXTURES / "negative" / "so_pubkey_session_bound.go",
                Path(ws) / "so_pubkey_session_bound.go",
            )
            summary = self.mod.scan_workspace(
                Path(ws), tuple(self.mod._DEFAULT_GUARDS),
            )
            pid = "go.spark.so_pubkey.req_payload_not_session"
            self.assertEqual(
                summary["patterns"][pid]["hit_count"], 0,
                f"expected 0 hits in negative fixture, got: {summary['patterns'][pid]}",
            )

    def test_so_pubkey_skips_test_files(self):
        """Pattern 25 must NOT fire on *_test.go fixtures."""
        with tempfile.TemporaryDirectory() as ws:
            src = (FIXTURES / "positive" / "so_pubkey_req_payload_not_session.go").read_text()
            (Path(ws) / "so_pubkey_test.go").write_text(src)
            summary = self.mod.scan_workspace(
                Path(ws), tuple(self.mod._DEFAULT_GUARDS),
            )
            pid = "go.spark.so_pubkey.req_payload_not_session"
            self.assertEqual(
                summary["patterns"][pid]["hit_count"], 0,
                f"expected 0 hits in *_test.go files, got: {summary['patterns'][pid]}",
            )

    # ------------------------------------------------------------------
    # Pattern 26 — go.spark.guard_set.shrinkage_status_still_set
    # ------------------------------------------------------------------
    def test_guard_set_shrinkage_status_still_set_positive(self):
        """SP-6286 bug shape: guard slice prunes an enum value that is
        still SET in production code. Detector must flag.
        """
        with tempfile.TemporaryDirectory() as ws:
            shutil.copy(
                FIXTURES / "positive" / "guard_set_shrinkage_status_still_set.go",
                Path(ws) / "guard_set_shrinkage_status_still_set.go",
            )
            summary = self.mod.scan_workspace(
                Path(ws), tuple(self.mod._DEFAULT_GUARDS),
            )
            pid = "go.spark.guard_set.shrinkage_status_still_set"
            self.assertGreaterEqual(
                summary["patterns"][pid]["hit_count"], 1,
                f"expected >=1 hit in positive fixture, got: {summary['patterns'][pid]}",
            )
            missing = {
                h["extra"]["missing_enum_value"]
                for h in summary["patterns"][pid]["hits"]
            }
            self.assertIn("TreeNodeStatusInvalid", missing)

    def test_guard_set_full_coverage_negative(self):
        """Defended shape: guard slice covers every SetStatus value in
        production. Detector must NOT fire.
        """
        with tempfile.TemporaryDirectory() as ws:
            shutil.copy(
                FIXTURES / "negative" / "guard_set_full_coverage.go",
                Path(ws) / "guard_set_full_coverage.go",
            )
            summary = self.mod.scan_workspace(
                Path(ws), tuple(self.mod._DEFAULT_GUARDS),
            )
            pid = "go.spark.guard_set.shrinkage_status_still_set"
            self.assertEqual(
                summary["patterns"][pid]["hit_count"], 0,
                f"expected 0 hits in negative fixture, got: {summary['patterns'][pid]}",
            )

    def test_guard_set_skips_test_files(self):
        """Pattern 26 must NOT consider SetStatus call sites inside
        *_test.go files when deciding whether a guard slice has a
        production leak.
        """
        with tempfile.TemporaryDirectory() as ws:
            # Place the bug-shape source under a *_test.go path. The
            # guard-decl pass also skips test files, so the detector
            # must report 0 hits.
            src = (FIXTURES / "positive" / "guard_set_shrinkage_status_still_set.go").read_text()
            (Path(ws) / "guard_set_test.go").write_text(src)
            summary = self.mod.scan_workspace(
                Path(ws), tuple(self.mod._DEFAULT_GUARDS),
            )
            pid = "go.spark.guard_set.shrinkage_status_still_set"
            self.assertEqual(
                summary["patterns"][pid]["hit_count"], 0,
                f"expected 0 hits in *_test.go files, got: {summary['patterns'][pid]}",
            )

    # ------------------------------------------------------------------
    # Pattern 27 — go.crypto.alias.constructor_stores_caller_slice_without_copy
    # ------------------------------------------------------------------
    def test_constructor_alias_positive(self):
        """Swival #023 / Spark bitmap.go shape: NewX([]byte) stores
        caller slice verbatim without a defensive copy. Detector must
        flag both constructors in the positive fixture.
        """
        with tempfile.TemporaryDirectory() as ws:
            shutil.copy(
                FIXTURES / "positive" / "constructor_stores_caller_slice.go",
                Path(ws) / "constructor_stores_caller_slice.go",
            )
            summary = self.mod.scan_workspace(
                Path(ws), tuple(self.mod._DEFAULT_GUARDS),
            )
            pid = "go.crypto.alias.constructor_stores_caller_slice_without_copy"
            self.assertGreaterEqual(
                summary["patterns"][pid]["hit_count"], 2,
                f"expected >=2 hits in positive fixture, got: {summary['patterns'][pid]}",
            )
            funcs = {h["extra"]["function"] for h in summary["patterns"][pid]["hits"]}
            self.assertIn("NewBitMapFromBytes", funcs)
            self.assertIn("NewBuffer", funcs)

    def test_constructor_alias_negative_with_copy(self):
        """Defended shape: bytes.Clone / append / explicit copy used
        before the field-write. Detector must NOT fire.
        """
        with tempfile.TemporaryDirectory() as ws:
            shutil.copy(
                FIXTURES / "negative" / "constructor_with_copy.go",
                Path(ws) / "constructor_with_copy.go",
            )
            summary = self.mod.scan_workspace(
                Path(ws), tuple(self.mod._DEFAULT_GUARDS),
            )
            pid = "go.crypto.alias.constructor_stores_caller_slice_without_copy"
            self.assertEqual(
                summary["patterns"][pid]["hit_count"], 0,
                f"expected 0 hits in negative fixture, got: {summary['patterns'][pid]}",
            )

    def test_constructor_alias_skips_test_files(self):
        """Pattern 27 must NOT fire on *_test.go fixtures."""
        with tempfile.TemporaryDirectory() as ws:
            src = (
                FIXTURES / "positive" / "constructor_stores_caller_slice.go"
            ).read_text()
            (Path(ws) / "alias_test.go").write_text(src)
            summary = self.mod.scan_workspace(
                Path(ws), tuple(self.mod._DEFAULT_GUARDS),
            )
            pid = "go.crypto.alias.constructor_stores_caller_slice_without_copy"
            self.assertEqual(
                summary["patterns"][pid]["hit_count"], 0,
                f"expected 0 hits in *_test.go files, got: {summary['patterns'][pid]}",
            )

    # ------------------------------------------------------------------
    # Pattern 28 — go.crypto.unmarshal.trailing_bytes_accepted
    # ------------------------------------------------------------------
    def test_unmarshal_trailing_bytes_positive(self):
        """Swival #011 / #039 / #056 shape: Unmarshal call without a
        post-call trailing-byte check. Detector must flag.
        """
        with tempfile.TemporaryDirectory() as ws:
            shutil.copy(
                FIXTURES / "positive" / "unmarshal_trailing_bytes.go",
                Path(ws) / "unmarshal_trailing_bytes.go",
            )
            summary = self.mod.scan_workspace(
                Path(ws), tuple(self.mod._DEFAULT_GUARDS),
            )
            pid = "go.crypto.unmarshal.trailing_bytes_accepted"
            self.assertGreaterEqual(
                summary["patterns"][pid]["hit_count"], 2,
                f"expected >=2 hits in positive fixture, got: {summary['patterns'][pid]}",
            )

    def test_unmarshal_trailing_bytes_negative(self):
        """Defended shape: explicit len(rest) > 0 / len(...) != 0 guard
        after Unmarshal. Detector must NOT fire.
        """
        with tempfile.TemporaryDirectory() as ws:
            shutil.copy(
                FIXTURES / "negative" / "unmarshal_with_trailing_check.go",
                Path(ws) / "unmarshal_with_trailing_check.go",
            )
            summary = self.mod.scan_workspace(
                Path(ws), tuple(self.mod._DEFAULT_GUARDS),
            )
            pid = "go.crypto.unmarshal.trailing_bytes_accepted"
            self.assertEqual(
                summary["patterns"][pid]["hit_count"], 0,
                f"expected 0 hits in negative fixture, got: {summary['patterns'][pid]}",
            )

    def test_unmarshal_trailing_bytes_skips_test_files(self):
        """Pattern 28 must NOT fire on *_test.go fixtures."""
        with tempfile.TemporaryDirectory() as ws:
            src = (
                FIXTURES / "positive" / "unmarshal_trailing_bytes.go"
            ).read_text()
            (Path(ws) / "trailing_test.go").write_text(src)
            summary = self.mod.scan_workspace(
                Path(ws), tuple(self.mod._DEFAULT_GUARDS),
            )
            pid = "go.crypto.unmarshal.trailing_bytes_accepted"
            self.assertEqual(
                summary["patterns"][pid]["hit_count"], 0,
                f"expected 0 hits in *_test.go files, got: {summary['patterns'][pid]}",
            )

    # ------------------------------------------------------------------
    # Pattern 28 — L21 ABA refinement coverage
    # Refinement 1: byte_source annotation (db_load suppression)
    # Refinement 2: encoder asymmetry (json.Unmarshal exclusion)
    # Refinement 3: signature_boundary tag + suppression
    # ------------------------------------------------------------------
    def test_unmarshal_trailing_bytes_refinement2_json_excluded(self):
        """L21 ABA refinement 2: pattern must NOT fire on json.Unmarshal
        because stdlib JSON rejects trailing non-whitespace bytes
        (verified L20 runtime).
        """
        with tempfile.TemporaryDirectory() as ws:
            shutil.copy(
                FIXTURES / "negative" / "unmarshal_json_only.go",
                Path(ws) / "unmarshal_json_only.go",
            )
            summary = self.mod.scan_workspace(
                Path(ws), tuple(self.mod._DEFAULT_GUARDS),
            )
            pid = "go.crypto.unmarshal.trailing_bytes_accepted"
            self.assertEqual(
                summary["patterns"][pid]["hit_count"], 0,
                f"expected 0 hits on json-only fixture, got: {summary['patterns'][pid]}",
            )

    def test_unmarshal_trailing_bytes_refinement1_db_load_suppressed(self):
        """L21 ABA refinement 1: proto.Unmarshal of DB-loaded bytes paired
        with a same-package proto.Marshal producer = canonical-only round
        trip. byte_source=db_load → must NOT fire.
        """
        with tempfile.TemporaryDirectory() as ws:
            shutil.copy(
                FIXTURES / "negative" / "unmarshal_db_load.go",
                Path(ws) / "unmarshal_db_load.go",
            )
            summary = self.mod.scan_workspace(
                Path(ws), tuple(self.mod._DEFAULT_GUARDS),
            )
            pid = "go.crypto.unmarshal.trailing_bytes_accepted"
            self.assertEqual(
                summary["patterns"][pid]["hit_count"], 0,
                f"expected 0 hits on db-load fixture, got: {summary['patterns'][pid]}",
            )

    def test_unmarshal_trailing_bytes_refinement3_no_signature_suppressed(self):
        """L21 ABA refinement 3: permissive parser of unknown-source
        bytes WITHOUT a downstream signature/hash boundary → no impact
        channel, must NOT fire.
        """
        with tempfile.TemporaryDirectory() as ws:
            shutil.copy(
                FIXTURES / "negative" / "unmarshal_no_signature_boundary.go",
                Path(ws) / "unmarshal_no_signature_boundary.go",
            )
            summary = self.mod.scan_workspace(
                Path(ws), tuple(self.mod._DEFAULT_GUARDS),
            )
            pid = "go.crypto.unmarshal.trailing_bytes_accepted"
            self.assertEqual(
                summary["patterns"][pid]["hit_count"], 0,
                f"expected 0 hits on no-signature-boundary fixture, got: {summary['patterns'][pid]}",
            )

    def test_unmarshal_trailing_bytes_refinement_extras_emitted(self):
        """L21 ABA refinements 1+3: hits must carry ``byte_source`` and
        ``signature_boundary`` extra fields. Positive fixture ParseCert
        has byte_source=unknown + signature_boundary=true; positive
        fixture DecryptAndParseShare has byte_source=decrypted_plaintext
        + signature_boundary=true.
        """
        with tempfile.TemporaryDirectory() as ws:
            shutil.copy(
                FIXTURES / "positive" / "unmarshal_trailing_bytes.go",
                Path(ws) / "unmarshal_trailing_bytes.go",
            )
            summary = self.mod.scan_workspace(
                Path(ws), tuple(self.mod._DEFAULT_GUARDS),
            )
            pid = "go.crypto.unmarshal.trailing_bytes_accepted"
            hits = summary["patterns"][pid]["hits"]
            self.assertGreaterEqual(len(hits), 2, hits)
            for h in hits:
                self.assertIn("byte_source", h["extra"], h)
                self.assertIn("signature_boundary", h["extra"], h)
            sources = sorted(h["extra"]["byte_source"] for h in hits)
            self.assertIn("decrypted_plaintext", sources, sources)

    def test_unmarshal_trailing_bytes_refinement_network_with_sig_fires(self):
        """L21 ABA: positive fixture with NETWORK-RECEIVED bytes feeding
        a signature verification must still fire (preserve signal).
        """
        with tempfile.TemporaryDirectory() as ws:
            shutil.copy(
                FIXTURES / "positive" / "unmarshal_network_with_sig.go",
                Path(ws) / "unmarshal_network_with_sig.go",
            )
            summary = self.mod.scan_workspace(
                Path(ws), tuple(self.mod._DEFAULT_GUARDS),
            )
            pid = "go.crypto.unmarshal.trailing_bytes_accepted"
            hits = summary["patterns"][pid]["hits"]
            self.assertEqual(
                len(hits), 1,
                f"expected exactly 1 hit on network+sig fixture, got: {summary['patterns'][pid]}",
            )
            extra = hits[0]["extra"]
            self.assertEqual(extra["byte_source"], "network_received", extra)
            self.assertTrue(extra["signature_boundary"], extra)

    # ------------------------------------------------------------------
    # Pattern 29 — go.spark.rpc_boundary.bare_fmterrorf_user_input_parse_failure
    # ------------------------------------------------------------------
    def test_rpc_bare_fmterrorf_positive(self):
        """SP-6420 shape: RPC handler returns bare fmt.Errorf wrapping a
        user-input parse failure (uuid.Parse, keys.ParsePublicKey, etc).
        Detector must flag.
        """
        with tempfile.TemporaryDirectory() as ws:
            shutil.copy(
                FIXTURES / "positive" / "rpc_bare_fmterrorf_parse.go",
                Path(ws) / "rpc_bare_fmterrorf_parse.go",
            )
            summary = self.mod.scan_workspace(
                Path(ws), tuple(self.mod._DEFAULT_GUARDS),
            )
            pid = "go.spark.rpc_boundary.bare_fmterrorf_user_input_parse_failure"
            self.assertGreaterEqual(
                summary["patterns"][pid]["hit_count"], 1,
                f"expected >=1 hit in positive fixture, got: {summary['patterns'][pid]}",
            )

    def test_rpc_bare_fmterrorf_negative(self):
        """Defended shape: every fmt.Errorf is wrapped in
        errors.InvalidArgument*(...). Detector must NOT fire.
        """
        with tempfile.TemporaryDirectory() as ws:
            shutil.copy(
                FIXTURES / "negative" / "rpc_wrapped_fmterrorf_parse.go",
                Path(ws) / "rpc_wrapped_fmterrorf_parse.go",
            )
            summary = self.mod.scan_workspace(
                Path(ws), tuple(self.mod._DEFAULT_GUARDS),
            )
            pid = "go.spark.rpc_boundary.bare_fmterrorf_user_input_parse_failure"
            self.assertEqual(
                summary["patterns"][pid]["hit_count"], 0,
                f"expected 0 hits in negative fixture, got: {summary['patterns'][pid]}",
            )

    def test_rpc_bare_fmterrorf_skips_test_files(self):
        """Pattern 29 must NOT fire on *_test.go fixtures."""
        with tempfile.TemporaryDirectory() as ws:
            src = (
                FIXTURES / "positive" / "rpc_bare_fmterrorf_parse.go"
            ).read_text()
            (Path(ws) / "rpc_test.go").write_text(src)
            summary = self.mod.scan_workspace(
                Path(ws), tuple(self.mod._DEFAULT_GUARDS),
            )
            pid = "go.spark.rpc_boundary.bare_fmterrorf_user_input_parse_failure"
            self.assertEqual(
                summary["patterns"][pid]["hit_count"], 0,
                f"expected 0 hits in *_test.go files, got: {summary['patterns'][pid]}",
            )

    # ------------------------------------------------------------------
    # Pattern 30 — go.crypto.alias.exported_getter_returns_internal_slice_without_copy
    # ------------------------------------------------------------------
    def test_exported_getter_alias_positive(self):
        """Swival #023/#024/#025 + Spark bitmap.go:33 shape:
        zero-arg exported method returns a struct's []byte field
        directly. Detector must flag both `Bytes` and `Data`.
        """
        with tempfile.TemporaryDirectory() as ws:
            shutil.copy(
                FIXTURES / "positive" / "exported_getter_returns_internal_slice.go",
                Path(ws) / "exported_getter_returns_internal_slice.go",
            )
            summary = self.mod.scan_workspace(
                Path(ws), tuple(self.mod._DEFAULT_GUARDS),
            )
            pid = "go.crypto.alias.exported_getter_returns_internal_slice_without_copy"
            self.assertGreaterEqual(
                summary["patterns"][pid]["hit_count"], 2,
                f"expected >=2 hits in positive fixture, got: {summary['patterns'][pid]}",
            )
            methods = {h["extra"]["method"] for h in summary["patterns"][pid]["hits"]}
            self.assertIn("Bytes", methods)
            self.assertIn("Data", methods)
            # The defensive `BytesCopy` method must NOT be in the hit set.
            self.assertNotIn("BytesCopy", methods)

    def test_exported_getter_alias_negative_with_clone(self):
        """Defended shapes: every exported getter performs a defensive
        copy (bytes.Clone, copy(), append). Detector must NOT fire.
        """
        with tempfile.TemporaryDirectory() as ws:
            shutil.copy(
                FIXTURES / "negative" / "exported_getter_with_clone.go",
                Path(ws) / "exported_getter_with_clone.go",
            )
            summary = self.mod.scan_workspace(
                Path(ws), tuple(self.mod._DEFAULT_GUARDS),
            )
            pid = "go.crypto.alias.exported_getter_returns_internal_slice_without_copy"
            self.assertEqual(
                summary["patterns"][pid]["hit_count"], 0,
                f"expected 0 hits in negative fixture, got: {summary['patterns'][pid]}",
            )

    def test_exported_getter_alias_skips_test_files(self):
        """Pattern 30 must NOT fire on *_test.go fixtures."""
        with tempfile.TemporaryDirectory() as ws:
            src = (
                FIXTURES / "positive" / "exported_getter_returns_internal_slice.go"
            ).read_text()
            (Path(ws) / "getter_test.go").write_text(src)
            summary = self.mod.scan_workspace(
                Path(ws), tuple(self.mod._DEFAULT_GUARDS),
            )
            pid = "go.crypto.alias.exported_getter_returns_internal_slice_without_copy"
            self.assertEqual(
                summary["patterns"][pid]["hit_count"], 0,
                f"expected 0 hits in *_test.go files, got: {summary['patterns'][pid]}",
            )

    # ------------------------------------------------------------------
    # Pattern 31 — go.spark.ent.edge_join_with_eq_when_denormalized_column_exists
    # ------------------------------------------------------------------
    def test_ent_edge_join_eq_positive(self):
        """SP-6416 / PT-L17-002 shape: ent edge-join Has<X>With(<pkg>.<Y>EQ(...)).
        Detector must flag at least one site (validateOutputsMatch...
        and signTokenLoop both fire).
        """
        with tempfile.TemporaryDirectory() as ws:
            shutil.copy(
                FIXTURES / "positive" / "ent_edge_join_with_eq.go",
                Path(ws) / "ent_edge_join_with_eq.go",
            )
            summary = self.mod.scan_workspace(
                Path(ws), tuple(self.mod._DEFAULT_GUARDS),
            )
            pid = "go.spark.ent.edge_join_with_eq_when_denormalized_column_exists"
            self.assertGreaterEqual(
                summary["patterns"][pid]["hit_count"], 2,
                f"expected >=2 hits in positive fixture, got: {summary['patterns'][pid]}",
            )

    def test_ent_edge_join_eq_negative_denormalized(self):
        """Defended shape: every query uses the denormalized column
        predicate directly. Detector must NOT fire.
        """
        with tempfile.TemporaryDirectory() as ws:
            shutil.copy(
                FIXTURES / "negative" / "ent_denormalized_eq.go",
                Path(ws) / "ent_denormalized_eq.go",
            )
            summary = self.mod.scan_workspace(
                Path(ws), tuple(self.mod._DEFAULT_GUARDS),
            )
            pid = "go.spark.ent.edge_join_with_eq_when_denormalized_column_exists"
            self.assertEqual(
                summary["patterns"][pid]["hit_count"], 0,
                f"expected 0 hits in negative fixture, got: {summary['patterns'][pid]}",
            )

    def test_ent_edge_join_eq_skips_test_files(self):
        """Pattern 31 must NOT fire on *_test.go fixtures."""
        with tempfile.TemporaryDirectory() as ws:
            src = (
                FIXTURES / "positive" / "ent_edge_join_with_eq.go"
            ).read_text()
            (Path(ws) / "edge_join_test.go").write_text(src)
            summary = self.mod.scan_workspace(
                Path(ws), tuple(self.mod._DEFAULT_GUARDS),
            )
            pid = "go.spark.ent.edge_join_with_eq_when_denormalized_column_exists"
            self.assertEqual(
                summary["patterns"][pid]["hit_count"], 0,
                f"expected 0 hits in *_test.go files, got: {summary['patterns'][pid]}",
            )

    # ------------------------------------------------------------------
    # Pattern 32 — go.crypto.panic.zero_or_negative_length_reaches_make_slice
    # ------------------------------------------------------------------
    def test_zero_or_negative_make_positive(self):
        """Swival #047/#048/#049/#052/#053 shape: caller-controlled
        integer length flows into make([]byte, n) without a guard.
        Detector must flag at least 3 functions in the fixture.
        """
        with tempfile.TemporaryDirectory() as ws:
            shutil.copy(
                FIXTURES / "positive" / "zero_or_negative_make_byte_slice.go",
                Path(ws) / "zero_or_negative_make_byte_slice.go",
            )
            summary = self.mod.scan_workspace(
                Path(ws), tuple(self.mod._DEFAULT_GUARDS),
            )
            pid = "go.crypto.panic.zero_or_negative_length_reaches_make_slice"
            self.assertGreaterEqual(
                summary["patterns"][pid]["hit_count"], 3,
                f"expected >=3 hits in positive fixture, got: {summary['patterns'][pid]}",
            )
            funcs = {h["extra"]["function"] for h in summary["patterns"][pid]["hits"]}
            self.assertIn("AllocBuffer", funcs)
            self.assertIn("AllocPaddedBuffer", funcs)
            self.assertIn("AllocLength", funcs)

    def test_zero_or_negative_make_negative_guarded(self):
        """Defended shape: every make([]byte, n) is preceded by a
        zero/negative-length guard on the same param. Detector must NOT
        fire.
        """
        with tempfile.TemporaryDirectory() as ws:
            shutil.copy(
                FIXTURES / "negative" / "guarded_make_byte_slice.go",
                Path(ws) / "guarded_make_byte_slice.go",
            )
            summary = self.mod.scan_workspace(
                Path(ws), tuple(self.mod._DEFAULT_GUARDS),
            )
            pid = "go.crypto.panic.zero_or_negative_length_reaches_make_slice"
            self.assertEqual(
                summary["patterns"][pid]["hit_count"], 0,
                f"expected 0 hits in negative fixture, got: {summary['patterns'][pid]}",
            )

    def test_zero_or_negative_make_skips_test_files(self):
        """Pattern 32 must NOT fire on *_test.go fixtures."""
        with tempfile.TemporaryDirectory() as ws:
            src = (
                FIXTURES / "positive" / "zero_or_negative_make_byte_slice.go"
            ).read_text()
            (Path(ws) / "make_test.go").write_text(src)
            summary = self.mod.scan_workspace(
                Path(ws), tuple(self.mod._DEFAULT_GUARDS),
            )
            pid = "go.crypto.panic.zero_or_negative_length_reaches_make_slice"
            self.assertEqual(
                summary["patterns"][pid]["hit_count"], 0,
                f"expected 0 hits in *_test.go files, got: {summary['patterns'][pid]}",
            )

    # ------------------------------------------------------------------
    # Pattern 33 — go.crypto.parse.negative_or_zero_int_unchecked
    # ------------------------------------------------------------------
    def test_parse_neg_zero_int_positive(self):
        """Swival #060/#061/#062/#063 shape: parsed integer flows
        downstream with no lower-bound guard. Detector must flag at
        least 3 functions in the fixture.
        """
        with tempfile.TemporaryDirectory() as ws:
            shutil.copy(
                FIXTURES / "positive" / "parse_neg_zero_int_unchecked.go",
                Path(ws) / "parse_neg_zero_int_unchecked.go",
            )
            summary = self.mod.scan_workspace(
                Path(ws), tuple(self.mod._DEFAULT_GUARDS),
            )
            pid = "go.crypto.parse.negative_or_zero_int_unchecked"
            self.assertGreaterEqual(
                summary["patterns"][pid]["hit_count"], 3,
                f"expected >=3 hits in positive fixture, got: {summary['patterns'][pid]}",
            )
            funcs = {h["extra"]["function"] for h in summary["patterns"][pid]["hits"]}
            self.assertIn("ParsePolicyConstraints", funcs)
            self.assertIn("ParseIterCount", funcs)
            self.assertIn("ReadOpcode", funcs)

    def test_parse_neg_zero_int_negative_guarded(self):
        """Defended shape: every parsed int is guarded by a lower-bound
        check before downstream use. Detector must NOT fire.
        """
        with tempfile.TemporaryDirectory() as ws:
            shutil.copy(
                FIXTURES / "negative" / "parse_neg_zero_int_guarded.go",
                Path(ws) / "parse_neg_zero_int_guarded.go",
            )
            summary = self.mod.scan_workspace(
                Path(ws), tuple(self.mod._DEFAULT_GUARDS),
            )
            pid = "go.crypto.parse.negative_or_zero_int_unchecked"
            self.assertEqual(
                summary["patterns"][pid]["hit_count"], 0,
                f"expected 0 hits in negative fixture, got: {summary['patterns'][pid]}",
            )

    def test_parse_neg_zero_int_skips_test_files(self):
        """Pattern 33 must NOT fire on *_test.go fixtures."""
        with tempfile.TemporaryDirectory() as ws:
            src = (
                FIXTURES / "positive" / "parse_neg_zero_int_unchecked.go"
            ).read_text()
            (Path(ws) / "parse_test.go").write_text(src)
            summary = self.mod.scan_workspace(
                Path(ws), tuple(self.mod._DEFAULT_GUARDS),
            )
            pid = "go.crypto.parse.negative_or_zero_int_unchecked"
            self.assertEqual(
                summary["patterns"][pid]["hit_count"], 0,
                f"expected 0 hits in *_test.go files, got: {summary['patterns'][pid]}",
            )

    # ------------------------------------------------------------------
    # Pattern 34 — go.crypto.scalar_mult.identity_point_unchecked
    # ------------------------------------------------------------------
    def test_scalar_mult_identity_positive(self):
        """Swival #028/#029/#034/#035/#066/#067/#073 shape: ScalarMult /
        ScalarBaseMult / ScalarMultBase with no IsOnCurve / IsIdentity /
        Params().N guard. Detector must flag at least 3 functions.
        """
        with tempfile.TemporaryDirectory() as ws:
            shutil.copy(
                FIXTURES / "positive" / "scalar_mult_identity_unchecked.go",
                Path(ws) / "scalar_mult_identity_unchecked.go",
            )
            summary = self.mod.scan_workspace(
                Path(ws), tuple(self.mod._DEFAULT_GUARDS),
            )
            pid = "go.crypto.scalar_mult.identity_point_unchecked"
            self.assertGreaterEqual(
                summary["patterns"][pid]["hit_count"], 3,
                f"expected >=3 hits in positive fixture, got: {summary['patterns'][pid]}",
            )
            funcs = {h["extra"]["function"] for h in summary["patterns"][pid]["hits"]}
            self.assertIn("ScalarMultUnsafe", funcs)
            self.assertIn("ScalarBaseMultUnsafe", funcs)
            self.assertIn("DerivePointUnsafe", funcs)

    def test_scalar_mult_identity_negative_guarded(self):
        """Defended shape: every curve op is preceded by an IsOnCurve /
        Params().N guard. Detector must NOT fire.
        """
        with tempfile.TemporaryDirectory() as ws:
            shutil.copy(
                FIXTURES / "negative" / "scalar_mult_identity_guarded.go",
                Path(ws) / "scalar_mult_identity_guarded.go",
            )
            summary = self.mod.scan_workspace(
                Path(ws), tuple(self.mod._DEFAULT_GUARDS),
            )
            pid = "go.crypto.scalar_mult.identity_point_unchecked"
            self.assertEqual(
                summary["patterns"][pid]["hit_count"], 0,
                f"expected 0 hits in negative fixture, got: {summary['patterns'][pid]}",
            )

    def test_scalar_mult_identity_skips_test_files(self):
        """Pattern 34 must NOT fire on *_test.go fixtures."""
        with tempfile.TemporaryDirectory() as ws:
            src = (
                FIXTURES / "positive" / "scalar_mult_identity_unchecked.go"
            ).read_text()
            (Path(ws) / "scalar_test.go").write_text(src)
            summary = self.mod.scan_workspace(
                Path(ws), tuple(self.mod._DEFAULT_GUARDS),
            )
            pid = "go.crypto.scalar_mult.identity_point_unchecked"
            self.assertEqual(
                summary["patterns"][pid]["hit_count"], 0,
                f"expected 0 hits in *_test.go files, got: {summary['patterns'][pid]}",
            )

    # ------------------------------------------------------------------
    # Pattern 35 — go.go.panic.dereference_before_nil_check
    # ------------------------------------------------------------------
    def test_panic_deref_before_nil_check_positive(self):
        """Swival #028/#029/#042/#074 shape: pointer-typed parameter
        field is dereferenced BEFORE any nil-guard. Detector must flag
        at least 3 functions in the fixture.
        """
        with tempfile.TemporaryDirectory() as ws:
            shutil.copy(
                FIXTURES / "positive" / "panic_deref_before_nil_check.go",
                Path(ws) / "panic_deref_before_nil_check.go",
            )
            summary = self.mod.scan_workspace(
                Path(ws), tuple(self.mod._DEFAULT_GUARDS),
            )
            pid = "go.go.panic.dereference_before_nil_check"
            self.assertGreaterEqual(
                summary["patterns"][pid]["hit_count"], 3,
                f"expected >=3 hits in positive fixture, got: {summary['patterns'][pid]}",
            )
            funcs = {h["extra"]["function"] for h in summary["patterns"][pid]["hits"]}
            self.assertIn("ProcessOptions", funcs)
            self.assertIn("ConnectWithConfig", funcs)
            self.assertIn("RouteRequest", funcs)

    def test_panic_deref_before_nil_check_negative_guarded(self):
        """Defended shape: every pointer parameter has a nil-check
        BEFORE field dereference. Detector must NOT fire.
        """
        with tempfile.TemporaryDirectory() as ws:
            shutil.copy(
                FIXTURES / "negative" / "panic_deref_with_nil_guard.go",
                Path(ws) / "panic_deref_with_nil_guard.go",
            )
            summary = self.mod.scan_workspace(
                Path(ws), tuple(self.mod._DEFAULT_GUARDS),
            )
            pid = "go.go.panic.dereference_before_nil_check"
            self.assertEqual(
                summary["patterns"][pid]["hit_count"], 0,
                f"expected 0 hits in negative fixture, got: {summary['patterns'][pid]}",
            )

    def test_panic_deref_before_nil_check_skips_test_files(self):
        """Pattern 35 must NOT fire on *_test.go fixtures."""
        with tempfile.TemporaryDirectory() as ws:
            src = (
                FIXTURES / "positive" / "panic_deref_before_nil_check.go"
            ).read_text()
            (Path(ws) / "deref_test.go").write_text(src)
            summary = self.mod.scan_workspace(
                Path(ws), tuple(self.mod._DEFAULT_GUARDS),
            )
            pid = "go.go.panic.dereference_before_nil_check"
            self.assertEqual(
                summary["patterns"][pid]["hit_count"], 0,
                f"expected 0 hits in *_test.go files, got: {summary['patterns'][pid]}",
            )

    # ------------------------------------------------------------------
    # Pattern 36 — go.crypto.loop.untrusted_length_unbounded
    # ------------------------------------------------------------------
    def test_loop_untrusted_length_unbounded_positive(self):
        """Swival #010 / #067 shape: parsed length-prefix drives a loop
        bound without any upper-bound cap. Detector must flag at least
        3 functions in the fixture.
        """
        with tempfile.TemporaryDirectory() as ws:
            shutil.copy(
                FIXTURES / "positive" / "loop_untrusted_length_unbounded.go",
                Path(ws) / "loop_untrusted_length_unbounded.go",
            )
            summary = self.mod.scan_workspace(
                Path(ws), tuple(self.mod._DEFAULT_GUARDS),
            )
            pid = "go.crypto.loop.untrusted_length_unbounded"
            self.assertGreaterEqual(
                summary["patterns"][pid]["hit_count"], 3,
                f"expected >=3 hits in positive fixture, got: {summary['patterns'][pid]}",
            )
            funcs = {h["extra"]["function"] for h in summary["patterns"][pid]["hits"]}
            self.assertIn("ParseTLVUnbounded", funcs)
            self.assertIn("ConsumeBytesUnbounded", funcs)
            self.assertIn("ReadFieldsUnbounded", funcs)

    def test_loop_untrusted_length_unbounded_negative_capped(self):
        """Defended shape: every parsed length is capped against a
        documented upper bound before the loop. Detector must NOT fire.
        """
        with tempfile.TemporaryDirectory() as ws:
            shutil.copy(
                FIXTURES / "negative" / "loop_length_capped.go",
                Path(ws) / "loop_length_capped.go",
            )
            summary = self.mod.scan_workspace(
                Path(ws), tuple(self.mod._DEFAULT_GUARDS),
            )
            pid = "go.crypto.loop.untrusted_length_unbounded"
            self.assertEqual(
                summary["patterns"][pid]["hit_count"], 0,
                f"expected 0 hits in negative fixture, got: {summary['patterns'][pid]}",
            )

    def test_loop_untrusted_length_unbounded_skips_test_files(self):
        """Pattern 36 must NOT fire on *_test.go fixtures."""
        with tempfile.TemporaryDirectory() as ws:
            src = (
                FIXTURES / "positive" / "loop_untrusted_length_unbounded.go"
            ).read_text()
            (Path(ws) / "loop_test.go").write_text(src)
            summary = self.mod.scan_workspace(
                Path(ws), tuple(self.mod._DEFAULT_GUARDS),
            )
            pid = "go.crypto.loop.untrusted_length_unbounded"
            self.assertEqual(
                summary["patterns"][pid]["hit_count"], 0,
                f"expected 0 hits in *_test.go files, got: {summary['patterns'][pid]}",
            )

    # ------------------------------------------------------------------
    # Pattern 37 — go.crypto.counter.wrap_unchecked
    # ------------------------------------------------------------------
    def test_counter_wrap_unchecked_positive(self):
        """Swival #009 / #044 shape: counter increment without an
        overflow / wrap guard. Detector must flag at least 3 functions.
        """
        with tempfile.TemporaryDirectory() as ws:
            shutil.copy(
                FIXTURES / "positive" / "counter_wrap_unchecked.go",
                Path(ws) / "counter_wrap_unchecked.go",
            )
            summary = self.mod.scan_workspace(
                Path(ws), tuple(self.mod._DEFAULT_GUARDS),
            )
            pid = "go.crypto.counter.wrap_unchecked"
            self.assertGreaterEqual(
                summary["patterns"][pid]["hit_count"], 3,
                f"expected >=3 hits in positive fixture, got: {summary['patterns'][pid]}",
            )
            funcs = {h["extra"]["function"] for h in summary["patterns"][pid]["hits"]}
            self.assertIn("Next", funcs)
            self.assertIn("AdvanceN", funcs)
            self.assertIn("NextNonce", funcs)

    def test_counter_wrap_unchecked_negative_guarded(self):
        """Defended shape: every counter increment is paired with a
        wrap guard or Reset/Rotate/Rekey call. Detector must NOT fire.
        """
        with tempfile.TemporaryDirectory() as ws:
            shutil.copy(
                FIXTURES / "negative" / "counter_wrap_guarded.go",
                Path(ws) / "counter_wrap_guarded.go",
            )
            summary = self.mod.scan_workspace(
                Path(ws), tuple(self.mod._DEFAULT_GUARDS),
            )
            pid = "go.crypto.counter.wrap_unchecked"
            self.assertEqual(
                summary["patterns"][pid]["hit_count"], 0,
                f"expected 0 hits in negative fixture, got: {summary['patterns'][pid]}",
            )

    def test_counter_wrap_unchecked_skips_test_files(self):
        """Pattern 37 must NOT fire on *_test.go fixtures."""
        with tempfile.TemporaryDirectory() as ws:
            src = (
                FIXTURES / "positive" / "counter_wrap_unchecked.go"
            ).read_text()
            (Path(ws) / "counter_test.go").write_text(src)
            summary = self.mod.scan_workspace(
                Path(ws), tuple(self.mod._DEFAULT_GUARDS),
            )
            pid = "go.crypto.counter.wrap_unchecked"
            self.assertEqual(
                summary["patterns"][pid]["hit_count"], 0,
                f"expected 0 hits in *_test.go files, got: {summary['patterns'][pid]}",
            )

    # ------------------------------------------------------------------
    # Pattern 38 — go.crypto.fips.approval_on_uninit
    # ------------------------------------------------------------------
    def test_fips_approval_on_uninit_positive(self):
        """Swival #075 shape: FIPS approval helper called on an
        uninitialised hash / algo argument without a zero-sentinel
        guard. Detector must flag at least 3 functions.
        """
        with tempfile.TemporaryDirectory() as ws:
            shutil.copy(
                FIXTURES / "positive" / "fips_approval_on_uninit.go",
                Path(ws) / "fips_approval_on_uninit.go",
            )
            summary = self.mod.scan_workspace(
                Path(ws), tuple(self.mod._DEFAULT_GUARDS),
            )
            pid = "go.crypto.fips.approval_on_uninit"
            self.assertGreaterEqual(
                summary["patterns"][pid]["hit_count"], 3,
                f"expected >=3 hits in positive fixture, got: {summary['patterns'][pid]}",
            )
            funcs = {h["extra"]["function"] for h in summary["patterns"][pid]["hits"]}
            self.assertIn("CheckHashApproved", funcs)
            self.assertIn("CheckHashValidated", funcs)
            self.assertIn("CheckAlgoAllowed", funcs)

    def test_fips_approval_on_uninit_negative_guarded(self):
        """Defended shape: every approval call is preceded by a
        zero-sentinel guard on the argument. Detector must NOT fire.
        """
        with tempfile.TemporaryDirectory() as ws:
            shutil.copy(
                FIXTURES / "negative" / "fips_approval_with_uninit_guard.go",
                Path(ws) / "fips_approval_with_uninit_guard.go",
            )
            summary = self.mod.scan_workspace(
                Path(ws), tuple(self.mod._DEFAULT_GUARDS),
            )
            pid = "go.crypto.fips.approval_on_uninit"
            self.assertEqual(
                summary["patterns"][pid]["hit_count"], 0,
                f"expected 0 hits in negative fixture, got: {summary['patterns'][pid]}",
            )

    def test_fips_approval_on_uninit_skips_test_files(self):
        """Pattern 38 must NOT fire on *_test.go fixtures."""
        with tempfile.TemporaryDirectory() as ws:
            src = (
                FIXTURES / "positive" / "fips_approval_on_uninit.go"
            ).read_text()
            (Path(ws) / "fips_test.go").write_text(src)
            summary = self.mod.scan_workspace(
                Path(ws), tuple(self.mod._DEFAULT_GUARDS),
            )
            pid = "go.crypto.fips.approval_on_uninit"
            self.assertEqual(
                summary["patterns"][pid]["hit_count"], 0,
                f"expected 0 hits in *_test.go files, got: {summary['patterns'][pid]}",
            )

    # ------------------------------------------------------------------
    # Pattern 39 — go.crypto.race.unsynchronized_concurrent_access
    # ------------------------------------------------------------------
    def test_race_unsynchronized_concurrent_access_positive(self):
        """Swival #008 / #022 / #027 shape: exported method on a pointer
        receiver mutates a self-field without any sync primitive.
        Detector must flag at least 3 functions in the fixture.
        """
        with tempfile.TemporaryDirectory() as ws:
            shutil.copy(
                FIXTURES / "positive" / "race_unsynchronized_access.go",
                Path(ws) / "race_unsynchronized_access.go",
            )
            summary = self.mod.scan_workspace(
                Path(ws), tuple(self.mod._DEFAULT_GUARDS),
            )
            pid = "go.crypto.race.unsynchronized_concurrent_access"
            self.assertGreaterEqual(
                summary["patterns"][pid]["hit_count"], 3,
                f"expected >=3 hits in positive fixture, got: {summary['patterns'][pid]}",
            )
            methods = {h["extra"]["method"] for h in summary["patterns"][pid]["hits"]}
            self.assertIn("Put", methods)
            self.assertIn("AdvanceAndMaybeClose", methods)
            self.assertIn("Set", methods)

    def test_race_unsynchronized_concurrent_access_negative_synced(self):
        """Defended shape: every exported method takes a lock or routes
        through atomic helpers. Detector must NOT fire.
        """
        with tempfile.TemporaryDirectory() as ws:
            shutil.copy(
                FIXTURES / "negative" / "race_synchronized_access.go",
                Path(ws) / "race_synchronized_access.go",
            )
            summary = self.mod.scan_workspace(
                Path(ws), tuple(self.mod._DEFAULT_GUARDS),
            )
            pid = "go.crypto.race.unsynchronized_concurrent_access"
            self.assertEqual(
                summary["patterns"][pid]["hit_count"], 0,
                f"expected 0 hits in negative fixture, got: {summary['patterns'][pid]}",
            )

    def test_race_unsynchronized_concurrent_access_skips_test_files(self):
        """Pattern 39 must NOT fire on *_test.go fixtures."""
        with tempfile.TemporaryDirectory() as ws:
            src = (
                FIXTURES / "positive" / "race_unsynchronized_access.go"
            ).read_text()
            (Path(ws) / "race_test.go").write_text(src)
            summary = self.mod.scan_workspace(
                Path(ws), tuple(self.mod._DEFAULT_GUARDS),
            )
            pid = "go.crypto.race.unsynchronized_concurrent_access"
            self.assertEqual(
                summary["patterns"][pid]["hit_count"], 0,
                f"expected 0 hits in *_test.go files, got: {summary['patterns'][pid]}",
            )

    # ------------------------------------------------------------------
    # Pattern 40 — go.crypto.skip_allowed.strict_lt_only
    # ------------------------------------------------------------------
    def test_skip_allowed_strict_lt_only_positive(self):
        """Swival #032 / #033 shape: strict ``<`` check without a paired
        ``==`` / delta-bound check. Detector must flag at least 3
        functions in the fixture.
        """
        with tempfile.TemporaryDirectory() as ws:
            shutil.copy(
                FIXTURES / "positive" / "skip_allowed_strict_lt.go",
                Path(ws) / "skip_allowed_strict_lt.go",
            )
            summary = self.mod.scan_workspace(
                Path(ws), tuple(self.mod._DEFAULT_GUARDS),
            )
            pid = "go.crypto.skip_allowed.strict_lt_only"
            self.assertGreaterEqual(
                summary["patterns"][pid]["hit_count"], 3,
                f"expected >=3 hits in positive fixture, got: {summary['patterns'][pid]}",
            )
            funcs = {h["extra"]["function"] for h in summary["patterns"][pid]["hits"]}
            self.assertIn("Accept", funcs)
            self.assertIn("Validate", funcs)
            self.assertIn("IsFresh", funcs)

    def test_skip_allowed_strict_lt_only_negative_paired(self):
        """Defended shape: every strict ``<`` check is paired with an
        ``==`` or a delta-bound check. Detector must NOT fire.
        """
        with tempfile.TemporaryDirectory() as ws:
            shutil.copy(
                FIXTURES / "negative" / "skip_allowed_strict_lt_paired.go",
                Path(ws) / "skip_allowed_strict_lt_paired.go",
            )
            summary = self.mod.scan_workspace(
                Path(ws), tuple(self.mod._DEFAULT_GUARDS),
            )
            pid = "go.crypto.skip_allowed.strict_lt_only"
            self.assertEqual(
                summary["patterns"][pid]["hit_count"], 0,
                f"expected 0 hits in negative fixture, got: {summary['patterns'][pid]}",
            )

    def test_skip_allowed_strict_lt_only_skips_test_files(self):
        """Pattern 40 must NOT fire on *_test.go fixtures."""
        with tempfile.TemporaryDirectory() as ws:
            src = (
                FIXTURES / "positive" / "skip_allowed_strict_lt.go"
            ).read_text()
            (Path(ws) / "skip_test.go").write_text(src)
            summary = self.mod.scan_workspace(
                Path(ws), tuple(self.mod._DEFAULT_GUARDS),
            )
            pid = "go.crypto.skip_allowed.strict_lt_only"
            self.assertEqual(
                summary["patterns"][pid]["hit_count"], 0,
                f"expected 0 hits in *_test.go files, got: {summary['patterns'][pid]}",
            )

    # ------------------------------------------------------------------
    # Pattern 41 — go.crypto.x509.suffix_match_no_dot_anchor
    # ------------------------------------------------------------------
    def test_x509_suffix_match_no_dot_anchor_positive(self):
        """Swival #038 shape: ``strings.HasSuffix`` for a name-constraint
        check WITHOUT a leading ``.`` anchor. Detector must flag at
        least 3 functions in the fixture.
        """
        with tempfile.TemporaryDirectory() as ws:
            shutil.copy(
                FIXTURES / "positive" / "x509_suffix_match_no_dot.go",
                Path(ws) / "x509_suffix_match_no_dot.go",
            )
            summary = self.mod.scan_workspace(
                Path(ws), tuple(self.mod._DEFAULT_GUARDS),
            )
            pid = "go.crypto.x509.suffix_match_no_dot_anchor"
            self.assertGreaterEqual(
                summary["patterns"][pid]["hit_count"], 3,
                f"expected >=3 hits in positive fixture, got: {summary['patterns'][pid]}",
            )
            funcs = {h["extra"]["function"] for h in summary["patterns"][pid]["hits"]}
            self.assertIn("MatchEmailDomain", funcs)
            self.assertIn("MatchURIPrefix", funcs)
            self.assertIn("MatchDNSAlt", funcs)

    def test_x509_suffix_match_no_dot_anchor_negative(self):
        """Defended shape: every suffix match is dot-anchored or routed
        through an IDNA / publicsuffix helper. Detector must NOT fire.
        """
        with tempfile.TemporaryDirectory() as ws:
            shutil.copy(
                FIXTURES / "negative" / "x509_suffix_match_dot_anchored.go",
                Path(ws) / "x509_suffix_match_dot_anchored.go",
            )
            summary = self.mod.scan_workspace(
                Path(ws), tuple(self.mod._DEFAULT_GUARDS),
            )
            pid = "go.crypto.x509.suffix_match_no_dot_anchor"
            self.assertEqual(
                summary["patterns"][pid]["hit_count"], 0,
                f"expected 0 hits in negative fixture, got: {summary['patterns'][pid]}",
            )

    def test_x509_suffix_match_no_dot_anchor_skips_test_files(self):
        """Pattern 41 must NOT fire on *_test.go fixtures."""
        with tempfile.TemporaryDirectory() as ws:
            src = (
                FIXTURES / "positive" / "x509_suffix_match_no_dot.go"
            ).read_text()
            (Path(ws) / "x509_test.go").write_text(src)
            summary = self.mod.scan_workspace(
                Path(ws), tuple(self.mod._DEFAULT_GUARDS),
            )
            pid = "go.crypto.x509.suffix_match_no_dot_anchor"
            self.assertEqual(
                summary["patterns"][pid]["hit_count"], 0,
                f"expected 0 hits in *_test.go files, got: {summary['patterns'][pid]}",
            )

    # ------------------------------------------------------------------
    # Pattern 39 stage-2 narrowing (L24 ABM) — suspect_class classifier
    # ------------------------------------------------------------------
    def test_race_pattern39_stage2_unmarshaler_suppressed(self):
        """L24 ABM stage-2: ``unmarshaler`` suspect_class is
        DEFAULT-SUPPRESSED. Methods with type-name suffix ``JSON`` /
        ``Decoder`` or method-name shape ``UnmarshalX``/``DecodeX``/
        ``Scan`` are caller-synchronised by Go convention — no fire.
        """
        with tempfile.TemporaryDirectory() as ws:
            shutil.copy(
                FIXTURES / "negative" / "race_unmarshaler_class.go",
                Path(ws) / "race_unmarshaler_class.go",
            )
            summary = self.mod.scan_workspace(
                Path(ws), tuple(self.mod._DEFAULT_GUARDS),
            )
            pid = "go.crypto.race.unsynchronized_concurrent_access"
            self.assertEqual(
                summary["patterns"][pid]["hit_count"], 0,
                f"expected 0 hits (unmarshaler suppressed), got: {summary['patterns'][pid]}",
            )

    def test_race_pattern39_stage2_ent_generated_suppressed(self):
        """L24 ABM stage-2: ``ent_generated`` suspect_class is
        DEFAULT-SUPPRESSED. File path under ``ent/`` triggers the
        ent-generated bucket — caller-synchronised by ent transaction
        layer above. No fire.
        """
        with tempfile.TemporaryDirectory() as ws:
            ent_dir = Path(ws) / "ent"
            ent_dir.mkdir()
            shutil.copy(
                FIXTURES / "negative" / "race_ent_generated_class.go",
                ent_dir / "leaf_create.go",
            )
            summary = self.mod.scan_workspace(
                Path(ws), tuple(self.mod._DEFAULT_GUARDS),
            )
            pid = "go.crypto.race.unsynchronized_concurrent_access"
            self.assertEqual(
                summary["patterns"][pid]["hit_count"], 0,
                f"expected 0 hits (ent_generated suppressed), got: {summary['patterns'][pid]}",
            )

    def test_race_pattern39_stage2_setter_suppressed(self):
        """L24 ABM stage-2: ``setter`` suspect_class is
        DEFAULT-SUPPRESSED. SetX/WithX builder pattern is
        caller-synchronised by Go convention. No fire.
        """
        with tempfile.TemporaryDirectory() as ws:
            shutil.copy(
                FIXTURES / "negative" / "race_setter_class.go",
                Path(ws) / "race_setter_class.go",
            )
            summary = self.mod.scan_workspace(
                Path(ws), tuple(self.mod._DEFAULT_GUARDS),
            )
            pid = "go.crypto.race.unsynchronized_concurrent_access"
            self.assertEqual(
                summary["patterns"][pid]["hit_count"], 0,
                f"expected 0 hits (setter suppressed), got: {summary['patterns'][pid]}",
            )

    def test_race_pattern39_stage2_genuine_concurrent_preserved(self):
        """L24 ABM stage-2: ``genuine_concurrent`` is the preserved
        signal class. Existing positive fixture has 3 methods (Put /
        AdvanceAndMaybeClose / Set) on receivers that are NOT
        encoders / not in ent/ / not Set-prefix exported names.

        Note: ``Set`` (3-char, no PascalCase tail) does NOT match
        ``^Set[A-Z]\\w*$`` so ConfigStore.Set bucket as
        genuine_concurrent. ``Put``, ``AdvanceAndMaybeClose`` also
        bucket as genuine_concurrent. Detector must still fire >=3
        AND every hit must carry suspect_class=genuine_concurrent.
        """
        with tempfile.TemporaryDirectory() as ws:
            shutil.copy(
                FIXTURES / "positive" / "race_unsynchronized_access.go",
                Path(ws) / "race_unsynchronized_access.go",
            )
            summary = self.mod.scan_workspace(
                Path(ws), tuple(self.mod._DEFAULT_GUARDS),
            )
            pid = "go.crypto.race.unsynchronized_concurrent_access"
            self.assertGreaterEqual(
                summary["patterns"][pid]["hit_count"], 3,
                f"expected >=3 genuine_concurrent hits, got: {summary['patterns'][pid]}",
            )
            for h in summary["patterns"][pid]["hits"]:
                self.assertIn("suspect_class", h["extra"], h)
                self.assertEqual(
                    h["extra"]["suspect_class"], "genuine_concurrent", h,
                )

    # ------------------------------------------------------------------
    # Pattern 42 — go.crypto.context_cancel.afterfunc_on_success
    # ------------------------------------------------------------------
    def test_context_afterfunc_on_success_positive(self):
        """Swival #005 shape: context.AfterFunc registered without a
        stop-handle invocation on the success path. Detector must
        flag all 3 fixture functions.
        """
        with tempfile.TemporaryDirectory() as ws:
            shutil.copy(
                FIXTURES / "positive" / "context_afterfunc_no_stop.go",
                Path(ws) / "context_afterfunc_no_stop.go",
            )
            summary = self.mod.scan_workspace(
                Path(ws), tuple(self.mod._DEFAULT_GUARDS),
            )
            pid = "go.crypto.context_cancel.afterfunc_on_success"
            self.assertGreaterEqual(
                summary["patterns"][pid]["hit_count"], 3,
                f"expected >=3 hits in positive fixture, got: {summary['patterns'][pid]}",
            )
            funcs = {h["extra"]["function"] for h in summary["patterns"][pid]["hits"]}
            self.assertIn("DialAndUseAfterFuncBug", funcs)
            self.assertIn("DialAndDiscardAfterFunc", funcs)
            self.assertIn("DialAndBareAfterFunc", funcs)

    def test_context_afterfunc_on_success_negative(self):
        """Defended shape: every AfterFunc handle is invoked via defer
        / direct call. Detector must NOT fire.
        """
        with tempfile.TemporaryDirectory() as ws:
            shutil.copy(
                FIXTURES / "negative" / "context_afterfunc_with_stop.go",
                Path(ws) / "context_afterfunc_with_stop.go",
            )
            summary = self.mod.scan_workspace(
                Path(ws), tuple(self.mod._DEFAULT_GUARDS),
            )
            pid = "go.crypto.context_cancel.afterfunc_on_success"
            self.assertEqual(
                summary["patterns"][pid]["hit_count"], 0,
                f"expected 0 hits in negative fixture, got: {summary['patterns'][pid]}",
            )

    def test_context_afterfunc_on_success_skips_test_files(self):
        """Pattern 42 must NOT fire on *_test.go fixtures."""
        with tempfile.TemporaryDirectory() as ws:
            src = (
                FIXTURES / "positive" / "context_afterfunc_no_stop.go"
            ).read_text()
            (Path(ws) / "afterfunc_test.go").write_text(src)
            summary = self.mod.scan_workspace(
                Path(ws), tuple(self.mod._DEFAULT_GUARDS),
            )
            pid = "go.crypto.context_cancel.afterfunc_on_success"
            self.assertEqual(
                summary["patterns"][pid]["hit_count"], 0,
                f"expected 0 hits in *_test.go files, got: {summary['patterns'][pid]}",
            )

    # ------------------------------------------------------------------
    # Pattern 43 — go.crypto.kem.imported_key_skips_pairwise_consistency_test
    # ------------------------------------------------------------------
    def test_kem_imported_key_skips_pairwise_positive(self):
        """Swival #026 shape: ImportPrivateKey / ParseKEM*Key /
        LoadKEM*Key returns parsed key without an encap-then-decap
        pairwise consistency test. Detector must flag all 3 fixture
        functions.
        """
        with tempfile.TemporaryDirectory() as ws:
            shutil.copy(
                FIXTURES / "positive" / "kem_import_no_pairwise.go",
                Path(ws) / "kem_import_no_pairwise.go",
            )
            summary = self.mod.scan_workspace(
                Path(ws), tuple(self.mod._DEFAULT_GUARDS),
            )
            pid = "go.crypto.kem.imported_key_skips_pairwise_consistency_test"
            self.assertGreaterEqual(
                summary["patterns"][pid]["hit_count"], 3,
                f"expected >=3 hits in positive fixture, got: {summary['patterns'][pid]}",
            )
            funcs = {h["extra"]["function"] for h in summary["patterns"][pid]["hits"]}
            self.assertIn("ImportPrivateKey", funcs)
            self.assertIn("ParseKyberPrivateKey", funcs)
            self.assertIn("LoadHPKEPrivateKey", funcs)

    def test_kem_imported_key_skips_pairwise_negative(self):
        """Defended shape: every KEM import does an encap-then-decap
        (or named pairwise helper) check before returning. Detector
        must NOT fire.
        """
        with tempfile.TemporaryDirectory() as ws:
            shutil.copy(
                FIXTURES / "negative" / "kem_import_with_pairwise.go",
                Path(ws) / "kem_import_with_pairwise.go",
            )
            summary = self.mod.scan_workspace(
                Path(ws), tuple(self.mod._DEFAULT_GUARDS),
            )
            pid = "go.crypto.kem.imported_key_skips_pairwise_consistency_test"
            self.assertEqual(
                summary["patterns"][pid]["hit_count"], 0,
                f"expected 0 hits in negative fixture, got: {summary['patterns'][pid]}",
            )

    def test_kem_imported_key_skips_pairwise_skips_test_files(self):
        """Pattern 43 must NOT fire on *_test.go fixtures."""
        with tempfile.TemporaryDirectory() as ws:
            src = (
                FIXTURES / "positive" / "kem_import_no_pairwise.go"
            ).read_text()
            (Path(ws) / "kem_test.go").write_text(src)
            summary = self.mod.scan_workspace(
                Path(ws), tuple(self.mod._DEFAULT_GUARDS),
            )
            pid = "go.crypto.kem.imported_key_skips_pairwise_consistency_test"
            self.assertEqual(
                summary["patterns"][pid]["hit_count"], 0,
                f"expected 0 hits in *_test.go files, got: {summary['patterns'][pid]}",
            )

    # ------------------------------------------------------------------
    # Schema / no-op behavior
    # ------------------------------------------------------------------
    def test_no_go_files_is_no_op(self):
        with tempfile.TemporaryDirectory() as ws:
            (Path(ws) / "README.md").write_text("hello")
            summary = self.mod.scan_workspace(
                Path(ws), tuple(self.mod._DEFAULT_GUARDS),
            )
            self.assertEqual(summary["go_files_scanned"], 0)
            self.assertEqual(summary["totals"]["hits"], 0)
            # Schema check: patterns dispatch must always contain at least
            # the canonical keys below. Use issubset rather than equality
            # so multiple parallel-worker pattern additions in the same
            # loop (e.g. FFF pattern #12 + HHH pattern #13) don't trigger
            # cross-worker schema-test churn. Workers that ADD a pattern
            # key are expected to extend this set in their own commit.
            required_keys = {
                "go.bitcoin.txid_equality_without_utxo_spend_check",
                "go.bitcoin.txid_without_vout_outpoint_binding",
                "go.statemachine.guard_only_on_one_path",
                "go.statemachine.self_heal_on_unexpected_status",
                "go.protohash.kind_identifier_collision",
                "go.consensus.gossip_perimeter_trust",
                "go.bitcoin.byte_reversed_lookup_set",
                "go.cosmos.message_ordering_replay",
                "go.lightning.htlc_settlement_state_drift",
                "go.frost.aggregate_pubkey_invariant_violation",
                "go.cosmos.gas_price_zero_unchecked",
                "go.cosmos.vote_extension_unverified",
                "go.spark.tree_node.terminal_state_revival",
                "go.spark.coop_exit.key_tweak_resumability",
                "go.spark.signed_payload.req_identity_validator",
                "go.spark.retry.prior_phase_commit_check",
                "go.spark.cross_so.tweak_guard_pre_post_persist",
                "go.spark.leaf_marshal.knob_gated_residual_disclosure",
                "go.spark.background_session.parent_tx_reopen_hook_missing",
                "go.spark.post_commit_rollback_unprotected",
                "go.spark.cron_forupdate.adjacent_read_lock_missing",
                "go.spark.coordinator_fanout.tx_commit_before_remote_call",
                "go.spark.grpc.default_service_config_last_write_wins",
                "go.spark.multi_receiver.rollup_first_only",
                "go.spark.so_pubkey.req_payload_not_session",
                "go.spark.guard_set.shrinkage_status_still_set",
                "go.crypto.alias.constructor_stores_caller_slice_without_copy",
                "go.crypto.unmarshal.trailing_bytes_accepted",
                "go.spark.rpc_boundary.bare_fmterrorf_user_input_parse_failure",
                "go.crypto.alias.exported_getter_returns_internal_slice_without_copy",
                "go.spark.ent.edge_join_with_eq_when_denormalized_column_exists",
                "go.crypto.panic.zero_or_negative_length_reaches_make_slice",
                "go.crypto.parse.negative_or_zero_int_unchecked",
                "go.crypto.scalar_mult.identity_point_unchecked",
                "go.go.panic.dereference_before_nil_check",
                "go.crypto.loop.untrusted_length_unbounded",
                "go.crypto.counter.wrap_unchecked",
                "go.crypto.fips.approval_on_uninit",
                "go.crypto.race.unsynchronized_concurrent_access",
                "go.crypto.skip_allowed.strict_lt_only",
                "go.crypto.x509.suffix_match_no_dot_anchor",
                "go.crypto.context_cancel.afterfunc_on_success",
                "go.crypto.kem.imported_key_skips_pairwise_consistency_test",
                "go.cosmos.subaccount_filter_mismatch",
                "go.cosmos.stale_tail_health_check",
            }
            actual_keys = set(summary["patterns"].keys())
            self.assertTrue(
                required_keys.issubset(actual_keys),
                f"missing canonical pattern keys: {sorted(required_keys - actual_keys)}",
            )

    # ------------------------------------------------------------------
    # Pattern 44 — go.cosmos.subaccount_filter_mismatch (Lane 11 NBQ-010)
    # ------------------------------------------------------------------
    def test_subaccount_filter_mismatch_positive(self):
        """Positive fixture: body uses GetSubaccountId + bankKeeper.GetBalance
        against module address WITHOUT deriving per-subaccount address. Pattern
        MUST fire on both functions."""
        with tempfile.TemporaryDirectory() as ws:
            shutil.copy(
                FIXTURES / "positive" / "subaccount_filter_mismatch.go",
                Path(ws) / "subaccount_filter_mismatch.go",
            )
            summary = self.mod.scan_workspace(
                Path(ws), tuple(self.mod._DEFAULT_GUARDS),
            )
            pid = "go.cosmos.subaccount_filter_mismatch"
            self.assertGreaterEqual(
                summary["patterns"][pid]["hit_count"], 1,
                f"expected >=1 hit in positive fixture, got: {summary['patterns'][pid]}",
            )
            functions = {
                h["extra"]["function"]
                for h in summary["patterns"][pid]["hits"]
            }
            self.assertIn(
                "GetSubaccountCollateral", functions,
                f"expected GetSubaccountCollateral flagged, got {functions}",
            )

    def test_subaccount_filter_mismatch_negative(self):
        """Negative control: body derives per-subaccount address via
        SubaccountIdToAddress before calling GetBalance. Pattern MUST NOT fire."""
        with tempfile.TemporaryDirectory() as ws:
            shutil.copy(
                FIXTURES / "negative" / "subaccount_filter_matched.go",
                Path(ws) / "subaccount_filter_matched.go",
            )
            summary = self.mod.scan_workspace(
                Path(ws), tuple(self.mod._DEFAULT_GUARDS),
            )
            pid = "go.cosmos.subaccount_filter_mismatch"
            self.assertEqual(
                summary["patterns"][pid]["hit_count"], 0,
                f"expected 0 hits in negative fixture (address derived from subaccount), "
                f"got: {summary['patterns'][pid]}",
            )

    def test_subaccount_filter_mismatch_registered(self):
        """Pattern slug must appear in the runner output even on empty workspace."""
        with tempfile.TemporaryDirectory() as ws:
            summary = self.mod.scan_workspace(
                Path(ws), tuple(self.mod._DEFAULT_GUARDS),
            )
            self.assertIn(
                "go.cosmos.subaccount_filter_mismatch",
                summary["patterns"],
            )

    # ------------------------------------------------------------------
    # Pattern 45 — go.cosmos.stale_tail_health_check (Lane 11 NBQ-010)
    # ------------------------------------------------------------------
    def test_stale_tail_health_check_positive(self):
        """Positive fixture: functions read only the latest/tail element and
        apply a health assertion without iterating the full collection. Pattern
        MUST fire."""
        with tempfile.TemporaryDirectory() as ws:
            shutil.copy(
                FIXTURES / "positive" / "stale_tail_health_check.go",
                Path(ws) / "stale_tail_health_check.go",
            )
            summary = self.mod.scan_workspace(
                Path(ws), tuple(self.mod._DEFAULT_GUARDS),
            )
            pid = "go.cosmos.stale_tail_health_check"
            self.assertGreaterEqual(
                summary["patterns"][pid]["hit_count"], 1,
                f"expected >=1 hit in positive fixture, got: {summary['patterns'][pid]}",
            )
            functions = {
                h["extra"]["function"]
                for h in summary["patterns"][pid]["hits"]
            }
            self.assertIn(
                "CheckLatestCommitHealthTailOnly", functions,
                f"expected CheckLatestCommitHealthTailOnly flagged, got {functions}",
            )

    def test_stale_tail_health_check_negative(self):
        """Negative control: full-iteration variant (for range, IterateAll)
        ensures pattern does NOT fire. Also verifies the no-assertion variant
        is silent."""
        with tempfile.TemporaryDirectory() as ws:
            shutil.copy(
                FIXTURES / "negative" / "stale_tail_health_full_iter.go",
                Path(ws) / "stale_tail_health_full_iter.go",
            )
            summary = self.mod.scan_workspace(
                Path(ws), tuple(self.mod._DEFAULT_GUARDS),
            )
            pid = "go.cosmos.stale_tail_health_check"
            self.assertEqual(
                summary["patterns"][pid]["hit_count"], 0,
                f"expected 0 hits in negative fixture (full iteration present), "
                f"got: {summary['patterns'][pid]}",
            )

    def test_stale_tail_health_check_registered(self):
        """Pattern slug must appear in the runner output even on empty workspace."""
        with tempfile.TemporaryDirectory() as ws:
            summary = self.mod.scan_workspace(
                Path(ws), tuple(self.mod._DEFAULT_GUARDS),
            )
            self.assertIn(
                "go.cosmos.stale_tail_health_check",
                summary["patterns"],
            )

    def test_writes_findings_artifact(self):
        with tempfile.TemporaryDirectory() as ws:
            shutil.copy(
                FIXTURES / "positive" / "self_heal_status.go",
                Path(ws) / "self_heal_status.go",
            )
            summary = self.mod.scan_workspace(
                Path(ws), tuple(self.mod._DEFAULT_GUARDS),
            )
            out_path = self.mod._write_outputs(Path(ws), summary)
            self.assertTrue(out_path.exists())
            data = json.loads(out_path.read_text())
            self.assertEqual(data["scanner"], "go-detector-runner.py")
            self.assertEqual(data["schema_version"], 1)


class FireOnlyFilterTests(unittest.TestCase):
    """Tests for the --fire-only / fire_only=True provenance filter.

    Verifies that:
    1. fire_only=False (default) preserves ALL patterns including broad ones.
    2. fire_only=True excludes every pattern in _FIRE_EXCLUDED_PATTERN_IDS.
    3. The broad nil-deref pattern (go.go.panic.dereference_before_nil_check)
       is specifically absent from fire-only output.
    4. fire_only=True result carries fire_only=True in the JSON envelope.
    5. CLI --fire-only flag round-trips through main() with rc=0.
    """

    @classmethod
    def setUpClass(cls):
        cls.mod = _load_runner()

    def _make_ws_with_nil_deref(self) -> tempfile.TemporaryDirectory:
        """Create a minimal workspace that triggers the broad nil-deref pattern."""
        ws = tempfile.TemporaryDirectory()
        # Minimal Go snippet that triggers go.go.panic.dereference_before_nil_check:
        # a function that dereferences a pointer before checking it for nil.
        go_src = '''\
package example

func fetchValue(p *int) int {
\tv := *p
\tif p == nil {
\t\treturn 0
\t}
\treturn v
}
'''
        (Path(ws.name) / "example.go").write_text(go_src)
        return ws

    def test_full_scan_includes_excluded_patterns(self):
        """Default (fire_only=False) includes the broad patterns in output."""
        with self._make_ws_with_nil_deref() as ws:
            summary = self.mod.scan_workspace(
                Path(ws), tuple(self.mod._DEFAULT_GUARDS), fire_only=False
            )
            excluded = self.mod._FIRE_EXCLUDED_PATTERN_IDS
            for pid in excluded:
                self.assertIn(
                    pid, summary["patterns"],
                    f"full scan should include excluded pattern {pid}",
                )
            self.assertFalse(
                summary.get("fire_only"),
                "fire_only flag should be False in default mode",
            )

    def test_fire_only_excludes_all_broad_patterns(self):
        """fire_only=True removes every pattern in _FIRE_EXCLUDED_PATTERN_IDS."""
        with self._make_ws_with_nil_deref() as ws:
            summary = self.mod.scan_workspace(
                Path(ws), tuple(self.mod._DEFAULT_GUARDS), fire_only=True
            )
            excluded = self.mod._FIRE_EXCLUDED_PATTERN_IDS
            for pid in excluded:
                self.assertNotIn(
                    pid, summary["patterns"],
                    f"fire-only scan must NOT include broad pattern {pid}",
                )

    def test_fire_only_nil_deref_specifically_absent(self):
        """The known flood pattern nil-deref is absent from fire-only output."""
        with self._make_ws_with_nil_deref() as ws:
            summary = self.mod.scan_workspace(
                Path(ws), tuple(self.mod._DEFAULT_GUARDS), fire_only=True
            )
            self.assertNotIn(
                "go.go.panic.dereference_before_nil_check",
                summary["patterns"],
                "nil-deref broad pattern must be excluded by --fire-only",
            )

    def test_fire_only_envelope_flag(self):
        """fire_only=True sets fire_only=True in the JSON envelope."""
        with self._make_ws_with_nil_deref() as ws:
            summary = self.mod.scan_workspace(
                Path(ws), tuple(self.mod._DEFAULT_GUARDS), fire_only=True
            )
            self.assertTrue(
                summary.get("fire_only"),
                "summary envelope must carry fire_only=True when flag is set",
            )

    def test_fire_only_preserves_remaining_patterns(self):
        """fire-only output still includes all non-excluded patterns."""
        mod = self.mod
        with self._make_ws_with_nil_deref() as ws:
            full = mod.scan_workspace(
                Path(ws), tuple(mod._DEFAULT_GUARDS), fire_only=False
            )
            fire = mod.scan_workspace(
                Path(ws), tuple(mod._DEFAULT_GUARDS), fire_only=True
            )
            all_ids = frozenset(full["patterns"].keys())
            expected_fire_ids = mod._build_fire_pattern_ids(all_ids)
            self.assertEqual(
                frozenset(fire["patterns"].keys()),
                expected_fire_ids,
                "fire-only output pattern set must match _build_fire_pattern_ids(all_ids)",
            )

    def test_fire_only_totals_match_included_hits(self):
        """Totals in fire-only mode count only included pattern hits."""
        with self._make_ws_with_nil_deref() as ws:
            summary = self.mod.scan_workspace(
                Path(ws), tuple(self.mod._DEFAULT_GUARDS), fire_only=True
            )
            computed_total = sum(
                v["hit_count"] for v in summary["patterns"].values()
            )
            self.assertEqual(
                summary["totals"]["hits"],
                computed_total,
                "totals.hits must equal sum of included pattern hit_count values",
            )

    def test_cli_fire_only_flag_rc0(self):
        """main() with --fire-only returns 0 and writes go_findings.json."""
        with self._make_ws_with_nil_deref() as ws:
            rc = self.mod.main(["--workspace", ws, "--fire-only"])
            self.assertEqual(rc, 0, "--fire-only CLI invocation should return 0")
            out = Path(ws) / ".auditooor" / "go_findings.json"
            self.assertTrue(out.exists(), "go_findings.json should be written")
            data = json.loads(out.read_text())
            self.assertTrue(data.get("fire_only"), "JSON fire_only flag should be True")
            self.assertNotIn(
                "go.go.panic.dereference_before_nil_check",
                data["patterns"],
                "nil-deref broad pattern must be absent from --fire-only output file",
            )

    def test_build_fire_pattern_ids_helper(self):
        """_build_fire_pattern_ids is the set-difference of all minus excluded."""
        mod = self.mod
        fake_all = frozenset({
            "go.go.panic.dereference_before_nil_check",
            "go.crypto.race.unsynchronized_concurrent_access",
            "go.crypto.parse.negative_or_zero_int_unchecked",
            "go.cosmos.stale_tail_health_check",
            "go.spark.rpc_boundary.bare_fmterrorf_user_input_parse_failure",
        })
        result = mod._build_fire_pattern_ids(fake_all)
        self.assertNotIn("go.go.panic.dereference_before_nil_check", result)
        self.assertNotIn("go.crypto.race.unsynchronized_concurrent_access", result)
        self.assertNotIn("go.crypto.parse.negative_or_zero_int_unchecked", result)
        self.assertIn("go.cosmos.stale_tail_health_check", result)
        self.assertIn(
            "go.spark.rpc_boundary.bare_fmterrorf_user_input_parse_failure", result
        )


class GoStrictCanonicalVerificationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.mod = _load_runner()

    def _write_inventory(self, ws: Path, row: dict) -> None:
        aud = ws / ".auditooor"
        aud.mkdir(exist_ok=True)
        (aud / "inscope_units.jsonl").write_text(
            json.dumps(row) + "\n", encoding="utf-8"
        )

    def test_strict_requires_canonical_inventory(self):
        with tempfile.TemporaryDirectory() as ws:
            summary = self.mod.scan_workspace(
                Path(ws), tuple(self.mod._DEFAULT_GUARDS), strict=True
            )
            self.assertEqual(summary["strict_verification"]["verdict"], "fail")
            self.assertTrue(any("missing canonical" in e for e in summary["strict_verification"]["errors"]))
            self.assertEqual(summary["strict_verification"]["scanned_unit_count"], 0)

    def test_strict_no_hit_accounts_for_every_inventory_unit(self):
        with tempfile.TemporaryDirectory() as ws:
            root = Path(ws)
            source = root / "clean.go"
            source.write_text("package clean\n\nfunc clean() {}\n", encoding="utf-8")
            self._write_inventory(root, {"file": "clean.go", "unit_id": "go-clean-1", "lang": "go"})
            summary = self.mod.scan_workspace(
                root, tuple(self.mod._DEFAULT_GUARDS), strict=True
            )
            verification = summary["strict_verification"]
            self.assertEqual(verification["verdict"], "pass")
            self.assertEqual(verification["inventory"]["unit_count"], 1)
            self.assertEqual(verification["scanned_unit_count"], 1)
            self.assertEqual(verification["emitted_hit_count"], 0)

    def test_strict_hit_requires_exact_typed_local_disposition(self):
        with tempfile.TemporaryDirectory() as ws:
            root = Path(ws)
            fixture = FIXTURES / "positive" / "parse_neg_zero_int_unchecked.go"
            shutil.copy(fixture, root / "fixture.go")
            self._write_inventory(root, {"file": "fixture.go", "unit_id": "go-fixture-1", "lang": "go"})
            summary = self.mod.scan_workspace(
                root, tuple(self.mod._DEFAULT_GUARDS), strict=True
            )
            verification = summary["strict_verification"]
            self.assertEqual(verification["verdict"], "fail")
            hit = summary["patterns"]["go.crypto.parse.negative_or_zero_int_unchecked"]["hits"][0]
            self.assertTrue(hit["stable_id"].startswith("go-hit-"))
            self.assertEqual(verification["unresolved_hits"][0]["reason"], "no exact typed disposition")

            records = []
            for pattern in summary["patterns"].values():
                for emitted in pattern["hits"]:
                    records.append({
                        "schema": self.mod.STRICT_DISPOSITION_SCHEMA,
                        "hit_id": emitted["stable_id"],
                        "pattern_id": emitted["pattern_id"],
                        "unit_id": "go-fixture-1",
                        "disposition_type": "refuted",
                        "source_evidence": [{"file": "fixture.go", "line": 1}],
                    })
            (root / ".auditooor" / self.mod.STRICT_DISPOSITION_FILENAME).write_text(
                "".join(json.dumps(record) + "\n" for record in records),
                encoding="utf-8",
            )
            closed = self.mod.scan_workspace(
                root, tuple(self.mod._DEFAULT_GUARDS), strict=True
            )
            self.assertEqual(closed["strict_verification"]["verdict"], "pass")

    def test_strict_rejects_parser_error_even_with_no_hits(self):
        with tempfile.TemporaryDirectory() as ws:
            root = Path(ws)
            (root / "broken.go").write_text(
                "package broken\n\nfunc broken() {\n", encoding="utf-8"
            )
            self._write_inventory(root, {"file": "broken.go", "unit_id": "go-broken-1", "lang": "go"})
            summary = self.mod.scan_workspace(
                root, tuple(self.mod._DEFAULT_GUARDS), strict=True
            )
            self.assertEqual(summary["strict_verification"]["verdict"], "fail")
            self.assertTrue(any("parser error" in e for e in summary["strict_verification"]["errors"]))

    def test_strict_rejects_degraded_inventory_unit(self):
        with tempfile.TemporaryDirectory() as ws:
            root = Path(ws)
            (root / "degraded.go").write_text("package degraded\n", encoding="utf-8")
            self._write_inventory(root, {
                "file": "degraded.go", "unit_id": "go-degraded-1", "lang": "go",
                "degraded": True,
            })
            summary = self.mod.scan_workspace(
                root, tuple(self.mod._DEFAULT_GUARDS), strict=True
            )
            self.assertEqual(summary["strict_verification"]["verdict"], "fail")
            self.assertTrue(any("degraded" in e for e in summary["strict_verification"]["errors"]))


if __name__ == "__main__":
    unittest.main()
