#!/usr/bin/env python3
"""Tests for go-bitcoin-protocol-validation.py.

Covers: class-N/A honesty, cited-empty (all obligations present), the survivor
set-difference (missing header-in-chain / confirmation-depth), transitive closure
crediting a helper-hop obligation, and the NON-VACUOUS mutation pair (adding the
missing dominating check makes the survivor disappear).
"""
from __future__ import annotations

import importlib.util
import json
import unittest
from pathlib import Path

_HERE = Path(__file__).resolve().parent
_TOOL = _HERE.parent / "go-bitcoin-protocol-validation.py"

_spec = importlib.util.spec_from_file_location("go_btc_proto_val", _TOOL)
mod = importlib.util.module_from_spec(_spec)
assert _spec and _spec.loader
_spec.loader.exec_module(mod)


# ---- Go fixtures -----------------------------------------------------------

# A vulnerable SPV bridge: verifies the merkle proof + binds the amount/script, but
# never checks header-in-honest-chain NOR confirmation-depth before minting.
VULN_GO = """package bridge

func (k Keeper) ProcessPegIn(ctx Context, proof SPVProof, tx BtcTx) error {
	if !VerifyMerkleProof(proof, tx.Txid) {
		return ErrBadProof
	}
	amount := extractAmount(tx, k.depositScriptPubKey)
	if amount == 0 {
		return ErrNoOutput
	}
	k.Mint(ctx, tx.Recipient, amount)
	return nil
}
"""

# Fully validated bridge: same sink, but ALSO checks header-in-honest-chain and
# confirmation-depth. This is the KEPT (cited-empty) case.
SAFE_GO = """package bridge

func (k Keeper) ProcessPegInSafe(ctx Context, proof SPVProof, tx BtcTx) error {
	if !VerifyMerkleProof(proof, tx.Txid) {
		return ErrBadProof
	}
	if !k.isHeaderInBestChain(proof.BlockHeader) {
		return ErrForkedHeader
	}
	if proof.Confirmations < k.minConfirmations {
		return ErrNotEnoughConfirmations
	}
	amount := verifyOutputScript(tx, k.depositScriptPubKey)
	k.Mint(ctx, tx.Recipient, amount)
	return nil
}
"""

# Transitive-closure fixture: the sink fn misses conf-depth in its own body, but a
# helper it calls performs the confirmation-depth check. Closure must credit it.
CLOSURE_GO = """package bridge

func (k Keeper) HandleDeposit(ctx Context, proof MerkleProof, tx BitcoinTx) error {
	if err := k.validateProof(proof, tx); err != nil {
		return err
	}
	amt := bindAmount(tx, k.pkScript)
	k.Release(ctx, tx.Recipient, amt)
	return nil
}

func (k Keeper) validateProof(proof MerkleProof, tx BitcoinTx) error {
	if !VerifyMerkleProof(proof, tx.Txid) {
		return ErrBadProof
	}
	if !k.headerInMainChain(proof.BlockHeader) {
		return ErrFork
	}
	if proof.Confirmations < requiredConfirmations {
		return ErrShallow
	}
	return nil
}
"""

# No BTC surface at all: a plain cosmos keeper. Must be class-N/A.
NO_BTC_GO = """package bank

func (k Keeper) SendCoins(ctx Context, from, to Address, amt Coin) error {
	k.subBalance(from, amt)
	k.addBalance(to, amt)
	return nil
}
"""


def _write(root: Path, name: str, content: str) -> None:
    p = root / name
    p.write_text(content, encoding="utf-8")


def _run(ws: Path, src: Path):
    emit = ws / ".auditooor" / "go_bitcoin_protocol_validation_obligations.jsonl"
    summary = mod.run([
        "--workspace", str(ws), "--src-root", str(src),
        "--emit", str(emit), "--json",
    ])
    return summary, emit


class GoBitcoinProtocolValidationTests(unittest.TestCase):
    def setUp(self):
        import tempfile
        self._td = tempfile.TemporaryDirectory()
        self.ws = Path(self._td.name)
        self.src = self.ws / "src"
        self.src.mkdir(parents=True, exist_ok=True)

    def tearDown(self):
        self._td.cleanup()

    def test_class_na_when_no_btc_surface(self):
        _write(self.src, "bank.go", NO_BTC_GO)
        summary, emit = _run(self.ws, self.src)
        self.assertTrue(summary["language_na"])
        self.assertFalse(summary["substrate_present"])
        self.assertEqual(summary["counts"]["survivors_missing_obligation"], 0)
        # emit file should be present but empty
        self.assertTrue(emit.exists())
        self.assertEqual(emit.read_text().strip(), "")

    def test_survivor_missing_header_and_confdepth(self):
        _write(self.src, "vuln.go", VULN_GO)
        summary, emit = _run(self.ws, self.src)
        self.assertTrue(summary["substrate_present"])
        self.assertFalse(summary["language_na"])
        self.assertEqual(summary["counts"]["survivors_missing_obligation"], 1)
        surv = summary["survivors"][0]
        self.assertEqual(surv["fn"], "ProcessPegIn")
        self.assertIn("header-in-honest-chain", surv["missing"])
        self.assertIn("confirmation-depth", surv["missing"])
        # merkle + amount are present, so NOT in missing
        self.assertIn("merkle-proof-verify", surv["present"])
        self.assertIn("amount-output-script-binding", surv["present"])
        # obligation ledger row written and well-formed
        rows = [json.loads(l) for l in emit.read_text().splitlines() if l.strip()]
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["schema"], "auditooor.go_bitcoin_protocol_validation.v1")
        self.assertEqual(rows[0]["attack_class"], "btc-spv-forged-proof-mint")
        self.assertEqual(rows[0]["likely_severity"], "critical")

    def test_cited_empty_when_all_obligations_present(self):
        _write(self.src, "safe.go", SAFE_GO)
        summary, _ = _run(self.ws, self.src)
        self.assertTrue(summary["substrate_present"])
        self.assertEqual(summary["counts"]["survivors_missing_obligation"], 0)
        self.assertEqual(summary["counts"]["PRESENT_kept"], 1)

    def test_transitive_closure_credits_helper_hop(self):
        # header-in-chain + conf-depth live in a called helper; closure must credit them.
        _write(self.src, "closure.go", CLOSURE_GO)
        summary, _ = _run(self.ws, self.src)
        self.assertEqual(
            summary["counts"]["survivors_missing_obligation"], 0,
            "helper-hop obligations should be credited via the callgraph closure")
        self.assertEqual(summary["counts"]["PRESENT_kept"], 1)

    def test_nonvacuous_mutation_pair(self):
        # NON-VACUOUS mutation: start from the vulnerable bridge (1 survivor). Add the
        # missing dominating checks (header-in-chain + confirmation-depth) -> the
        # survivor MUST disappear. If both variants gave the same verdict the check
        # would be vacuous.
        _write(self.src, "vuln.go", VULN_GO)
        before, _ = _run(self.ws, self.src)
        self.assertEqual(before["counts"]["survivors_missing_obligation"], 1)

        mutated = VULN_GO.replace(
            "\tamount := extractAmount(tx, k.depositScriptPubKey)",
            "\tif !k.isHeaderInBestChain(proof.BlockHeader) {\n"
            "\t\treturn ErrForkedHeader\n"
            "\t}\n"
            "\tif proof.Confirmations < k.minConfirmations {\n"
            "\t\treturn ErrNotEnoughConfirmations\n"
            "\t}\n"
            "\tamount := extractAmount(tx, k.depositScriptPubKey)",
        )
        self.assertNotEqual(mutated, VULN_GO, "mutation must change the source")
        (self.src / "vuln.go").write_text(mutated, encoding="utf-8")
        after, _ = _run(self.ws, self.src)
        self.assertEqual(
            after["counts"]["survivors_missing_obligation"], 0,
            "adding the dominating header-in-chain + conf-depth checks must remove "
            "the survivor (non-vacuous set-difference)")
        self.assertEqual(after["counts"]["PRESENT_kept"], 1)


if __name__ == "__main__":
    unittest.main()
