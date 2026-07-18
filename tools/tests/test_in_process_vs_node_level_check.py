"""Unit tests for Rule 18 / Rule 19 in-process-vs-node-level preflight."""

from __future__ import annotations

import importlib.util
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
_spec = importlib.util.spec_from_file_location(
    "in_process_vs_node_level_check",
    ROOT / "tools" / "in-process-vs-node-level-check.py",
)
mod = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(mod)  # type: ignore[union-attr]


def _workspace() -> Path:
    root = Path(tempfile.mkdtemp(prefix="r18_node_"))
    (root / "submissions" / "paste_ready").mkdir(parents=True)
    (root / "poc-tests").mkdir()
    return root


def _write_case(body: str, source: str | None = None, source_name: str = "poc_test.go") -> Path:
    root = _workspace()
    if source is not None:
        d = root / "poc-tests" / "case"
        d.mkdir(parents=True)
        (d / source_name).write_text(source, encoding="utf-8")
        body += "\nPoC: `poc-tests/case`\n"
    draft = root / "submissions" / "paste_ready" / "draft-HIGH.md"
    draft.write_text(body, encoding="utf-8")
    return draft


class InProcessVsNodeLevelTests(unittest.TestCase):
    def test_medium_severity_out_of_scope(self) -> None:
        draft = _write_case("Severity: MEDIUM\nNetwork-level liveness failure.\n")
        rc, payload = mod.run(draft, strict=True)
        self.assertEqual(rc, 0)
        self.assertEqual(payload["verdict"], "pass-out-of-scope")

    def test_high_without_production_keyword_passes(self) -> None:
        draft = _write_case("Severity: HIGH\nDirect theft of user funds.\n")
        rc, payload = mod.run(draft, strict=True)
        self.assertEqual(rc, 0)
        self.assertEqual(payload["verdict"], "pass-rubric-no-production-keyword")

    def test_network_level_claim_direct_keeper_fails(self) -> None:
        draft = _write_case(
            "Severity: HIGH\nClaimed impact: network-level liveness failure.\n",
            "package poc\nfunc TestX(t *testing.T){ k.ProcessSingleMatch(ctx, match) }\n",
        )
        rc, payload = mod.run(draft, strict=True)
        self.assertEqual(rc, 1)
        self.assertEqual(payload["verdict"], "fail-production-grade-claim-with-in-process-only-poc")

    def test_matching_engine_claim_with_advance_to_block_passes(self) -> None:
        draft = _write_case(
            "Severity: HIGH\nClaimed impact: matching-engine degradation.\n",
            "package poc\nfunc TestX(t *testing.T){ tApp.AdvanceToBlock(12) }\n",
        )
        rc, payload = mod.run(draft, strict=True)
        self.assertEqual(rc, 0)
        self.assertEqual(payload["verdict"], "pass-production-grade-poc-present")

    def test_r19_apphash_claim_without_finalizeblock_fails(self) -> None:
        draft = _write_case(
            "Severity: CRITICAL\nClaimed impact: AppHash divergence during block execution.\n",
            "package poc\nfunc TestX(t *testing.T){ app.ClobKeeper.PlacePerpetualLiquidation(ctx, order) }\n",
        )
        rc, payload = mod.run(draft, strict=True)
        self.assertEqual(rc, 1)
        self.assertTrue(payload["evidence"]["r19_trigger_hits"])

    def test_r19_finalizeblock_passes(self) -> None:
        draft = _write_case(
            "Severity: CRITICAL\nClaimed impact: state-machine write path corruption.\n",
            "package poc\nfunc TestX(t *testing.T){ res, err := app.BaseApp.FinalizeBlock(req); _, _ = res, err }\n",
        )
        rc, payload = mod.run(draft, strict=True)
        self.assertEqual(rc, 0)
        self.assertEqual(payload["verdict"], "pass-production-grade-poc-present")

    def test_commit_pipeline_claim_with_rootmulti_commit_passes(self) -> None:
        draft = _write_case(
            "Severity: HIGH\nClaimed impact: commit pipeline halt.\n",
            "package poc\nfunc TestX(t *testing.T){ store.rootmulti.Commit() }\n",
        )
        rc, payload = mod.run(draft, strict=True)
        self.assertEqual(rc, 0)
        self.assertEqual(payload["verdict"], "pass-production-grade-poc-present")

    def test_rebuttal_passes(self) -> None:
        draft = _write_case(
            "Severity: HIGH\nnetwork-level impact. <!-- l32-rebuttal: source-only node path unavailable, production call graph cited -->"
        )
        rc, payload = mod.run(draft, strict=True)
        self.assertEqual(rc, 0)
        self.assertEqual(payload["verdict"], "ok-rebuttal")

    def test_not_proven_scope_line_does_not_trigger(self) -> None:
        draft = _write_case("Severity: HIGH\nnot_proven: chain halt; AppHash divergence.\n")
        rc, payload = mod.run(draft, strict=True)
        self.assertEqual(rc, 0)
        self.assertEqual(payload["verdict"], "pass-rubric-no-production-keyword")

    def test_strict_missing_poc_dir_fails(self) -> None:
        draft = _write_case("Severity: HIGH\nNetwork-level liveness failure.\n")
        rc, payload = mod.run(draft, strict=True)
        self.assertEqual(rc, 1)
        self.assertEqual(payload["verdict"], "fail-missing-poc-dir")

    def test_missing_file_error(self) -> None:
        rc, payload = mod.run(Path("/no/such/file.md"))
        self.assertEqual(rc, 2)
        self.assertEqual(payload["verdict"], "error")

    # --- cross-ecosystem generalization (Substrate / EVM / Solana) ---

    def test_substrate_node_level_poc_passes(self) -> None:
        draft = _write_case(
            "Severity: CRITICAL\nClaimed impact: block import halt and finality gadget stall.\n",
            "fn test_block_import() {\n"
            "    let mut ext = TestExternalities::new(storage);\n"
            "    ext.execute_with(|| { Executive::execute_block(block); });\n"
            "}\n",
            source_name="poc_test.rs",
        )
        rc, payload = mod.run(draft, strict=True)
        self.assertEqual(rc, 0)
        self.assertEqual(payload["verdict"], "pass-production-grade-poc-present")

    def test_evm_forked_mainnet_poc_passes(self) -> None:
        draft = _write_case(
            "Severity: HIGH\nClaimed impact: consensus split via state root mismatch.\n",
            "function testFork() public {\n"
            "    uint256 fork = vm.createSelectFork(\"https://rpc\");\n"
            "    // exercise the bug against forked mainnet state\n"
            "}\n",
            source_name="poc_test.sol",
        )
        rc, payload = mod.run(draft, strict=True)
        self.assertEqual(rc, 0)
        self.assertEqual(payload["verdict"], "pass-production-grade-poc-present")

    def test_evm_in_memory_only_poc_fails(self) -> None:
        draft = _write_case(
            "Severity: HIGH\nClaimed impact: block reorg and consensus split.\n",
            "function testInternal() public {\n"
            "    // internal function unit test, no fork\n"
            "    vm.store(target, slot, bytes32(uint256(1)));\n"
            "    _internalLogic();\n"
            "}\n",
            source_name="poc_test.sol",
        )
        rc, payload = mod.run(draft, strict=True)
        self.assertEqual(rc, 1)
        self.assertEqual(payload["verdict"], "fail-production-grade-claim-with-in-process-only-poc")

    def test_substrate_new_test_ext_only_for_production_claim_fails(self) -> None:
        draft = _write_case(
            "Severity: CRITICAL\nClaimed impact: runtime apply state-machine write path corruption.\n",
            "fn test_pallet() {\n"
            "    new_test_ext().execute_with(|| {\n"
            "        Pallet::<T>::do_thing(origin, payload);  // bypassing dispatch\n"
            "    });\n"
            "}\n",
            source_name="poc_test.rs",
        )
        rc, payload = mod.run(draft, strict=True)
        self.assertEqual(rc, 1)
        self.assertEqual(payload["verdict"], "fail-production-grade-claim-with-in-process-only-poc")

    def test_solana_banks_client_poc_passes(self) -> None:
        draft = _write_case(
            "Severity: HIGH\nClaimed impact: network-level liveness failure.\n",
            "async fn test_program() {\n"
            "    let mut banks_client = ProgramTest::new(\"prog\", id, None).start().await;\n"
            "    bank.process_transaction(tx).await.unwrap();\n"
            "}\n",
            source_name="poc_test.rs",
        )
        rc, payload = mod.run(draft, strict=True)
        self.assertEqual(rc, 0)
        self.assertEqual(payload["verdict"], "pass-production-grade-poc-present")


if __name__ == "__main__":
    unittest.main(verbosity=2)
