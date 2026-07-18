#!/usr/bin/env python3
"""MQ-B04 quorum-degradation-screen - non-vacuous regression.

Pins tools/quorum-degradation-screen.py: for a K-of-N aggregator (multi-oracle
median / committee-signature count / validator-attestation tally) that FILTERS
inputs upstream (drops stale/zero/sentinel/duplicate/reverting entries), it flags
(verdict="needs-fuzz") when the SURVIVING distinct-and-live count is NOT re-asserted
against the declared threshold K before the aggregated result is used.

Non-vacuity is enforced three ways (HARD RULE 6):
  (1) PLANTED POSITIVE fires  - a filter-and-tally aggregator with NO survivor
      re-check fires, in BOTH Solidity and Go.
  (2) GUARDED NEGATIVE silent - the same aggregator WITH `count >= K` / `count == K`
      re-asserted is silent.
  (3) NEUTRALIZE the core predicate -> the positive assertion FAILS:
      (a) monkeypatching `_reasserts_survivor` to always-True makes the positive go
          silent (proves the guard-detection is the load-bearing predicate); and
      (b) stripping the threshold token from the positive drops the row entirely
          (proves the K-of-N threshold is load-bearing, not a bug shape).

The advisory-first contract (verdict=needs-fuzz, advisory=True, auto_credit=False,
default exit 0, --strict exit 1) and the .auditooor sidecar emission are pinned too.

REAL-FLEET mutation-verify (HARD RULE 5) is reproduced as SILENT-on-guarded checks
against the actual fleet sources when present (etherfi MultiSig.checkSignatures /
sei clique Snapshot.apply); they SKIP if the source is absent (no faked pass).
"""
from __future__ import annotations

import importlib.util
import json
import os
import pathlib
import tempfile
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[2]
TOOLS = ROOT / "tools"


def _load_tool():
    spec = importlib.util.spec_from_file_location(
        "quorum_degradation_screen_t", TOOLS / "quorum-degradation-screen.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)  # type: ignore
    return mod


MOD = _load_tool()

# ---------------------------------------------------------------------------
# Fixtures - a K-of-N aggregator that FILTERS inputs upstream of the tally.
# ---------------------------------------------------------------------------

# Solidity: a multi-oracle quorum median. Reads the threshold `q`, filters zero /
# sentinel answers with `continue`, tallies survivors in `valid` - but NEVER
# re-asserts `valid >= q` before dividing. => FIRES.
SOL_POSITIVE = """
pragma solidity ^0.8.0;
contract OracleQuorum {
    struct S { uint256 quorum; }
    S internal $;
    event Aggregated(uint256 q, uint256 valid);
    function aggregate(address[] calldata oracles, uint256[] calldata answers)
        external returns (uint256)
    {
        uint256 q = $.quorum;
        uint256 sum = 0;
        uint256 valid = 0;
        for (uint256 i = 0; i < oracles.length; i++) {
            if (answers[i] == 0) continue;
            if (oracles[i] == address(0)) continue;
            sum += answers[i];
            valid++;
        }
        emit Aggregated(q, valid);
        return sum / valid;
    }
}
"""

# The GUARDED sibling: identical, plus `if (valid < q) revert` - the surviving count
# IS re-asserted against the threshold. => SILENT.
SOL_GUARDED = SOL_POSITIVE.replace(
    "        emit Aggregated(q, valid);",
    "        if (valid < q) revert(\"quorum\");\n        emit Aggregated(q, valid);")

# Go: a committee/attestation tally. Reads `threshold`, filters stale / zero-hash
# reports with `continue`, tallies survivors - but never re-checks `valid` vs
# `threshold`. => FIRES.
GO_POSITIVE = """
package consensus
type Report struct { Stale bool; Hash [32]byte }
func Aggregate(reports []Report, threshold int) [32]byte {
	valid := 0
	var support int
	var out [32]byte
	for _, r := range reports {
		if r.Stale {
			continue
		}
		if r.Hash == ([32]byte{}) {
			continue
		}
		support++
		valid++
		out = r.Hash
	}
	_ = threshold
	_ = support
	return out
}
"""

# GUARDED Go sibling: add `if valid < threshold { return [32]byte{} }`. => SILENT.
GO_GUARDED = GO_POSITIVE.replace(
    "\t_ = threshold\n",
    "\tif valid < threshold {\n\t\treturn [32]byte{}\n\t}\n\t_ = threshold\n")


def _rows(text, name):
    return MOD.scan_file(pathlib.Path(name), name, file_text=text)


class TestPlantedPositiveFires(unittest.TestCase):
    def test_solidity_positive_fires(self):
        rows = _rows(SOL_POSITIVE, "OracleQuorum.sol")
        self.assertEqual(len(rows), 1, rows)
        r = rows[0]
        self.assertEqual(r["function"], "aggregate")
        self.assertTrue(r["fires"])
        self.assertFalse(r["reasserts_survivor_count"])
        self.assertEqual(r["capability"], "MQ-B04-quorum-degradation")

    def test_go_positive_fires(self):
        rows = _rows(GO_POSITIVE, "aggregate.go")
        self.assertEqual(len(rows), 1, rows)
        r = rows[0]
        self.assertEqual(r["function"], "Aggregate")
        self.assertTrue(r["fires"])
        self.assertEqual(r["lang"], "go")


class TestGuardedNegativeSilent(unittest.TestCase):
    def test_solidity_guarded_silent(self):
        rows = _rows(SOL_GUARDED, "OracleQuorum.sol")
        self.assertEqual(len(rows), 1, rows)
        self.assertFalse(rows[0]["fires"])
        self.assertTrue(rows[0]["reasserts_survivor_count"])
        self.assertIn("valid < q", rows[0]["guard_line"])

    def test_go_guarded_silent(self):
        rows = _rows(GO_GUARDED, "aggregate.go")
        self.assertEqual(len(rows), 1, rows)
        self.assertFalse(rows[0]["fires"])
        self.assertTrue(rows[0]["reasserts_survivor_count"])


class TestNeutralizeCorePredicate(unittest.TestCase):
    """Neutralizing the core predicate must make the positive assertion FAIL."""

    def test_neutralize_guard_detector_kills_the_fire(self):
        # Force the survivor re-assertion detector to always report "guarded".
        orig = MOD._reasserts_survivor
        try:
            MOD._reasserts_survivor = lambda body, terms: (True, "NEUTRALIZED")
            rows = _rows(SOL_POSITIVE, "OracleQuorum.sol")
        finally:
            MOD._reasserts_survivor = orig
        # The positive no longer fires -> the guard-detection is load-bearing.
        self.assertEqual(len(rows), 1)
        self.assertFalse(rows[0]["fires"])

    def test_strip_threshold_token_drops_the_row(self):
        # Remove the only threshold reference: no K -> not a K-of-N aggregator.
        stripped = (SOL_POSITIVE
                    .replace("uint256 q = $.quorum;", "uint256 q = 5;")
                    .replace("struct S { uint256 quorum; }", "struct S { uint256 xx; }"))
        self.assertNotIn("quorum", stripped)
        rows = _rows(stripped, "OracleQuorum.sol")
        self.assertEqual(rows, [], "row must vanish once the threshold token is gone")


class TestAdvisoryContractAndSidecar(unittest.TestCase):
    def test_rows_are_advisory_needs_fuzz(self):
        r = _rows(SOL_POSITIVE, "OracleQuorum.sol")[0]
        self.assertEqual(r["verdict"], "needs-fuzz")
        self.assertTrue(r["advisory"])
        self.assertFalse(r["auto_credit"])

    def test_workspace_emits_sidecar_and_exit_codes(self):
        with tempfile.TemporaryDirectory() as td:
            ws = pathlib.Path(td)
            src = ws / "src"
            src.mkdir()
            (src / "OracleQuorum.sol").write_text(SOL_POSITIVE)
            (src / "aggregate.go").write_text(GO_POSITIVE)
            # default (advisory) -> exit 0 even though degraded aggregators exist
            rc = MOD.main(["--workspace", str(ws)])
            self.assertEqual(rc, 0)
            side = ws / ".auditooor" / MOD._SIDE_NAME
            self.assertTrue(side.exists(), "sidecar must be emitted under .auditooor/")
            rows = [json.loads(l) for l in side.read_text().splitlines() if l.strip()]
            self.assertEqual(len(rows), 2)
            for r in rows:
                self.assertIn("file", r)
                self.assertIn("line", r)
                self.assertIn("function", r)
                self.assertEqual(r["capability"], "MQ-B04-quorum-degradation")
                self.assertEqual(r["verdict"], "needs-fuzz")
            # --strict -> exit 1 when a degraded aggregator fired
            rc_strict = MOD.main(["--workspace", str(ws), "--strict"])
            self.assertEqual(rc_strict, 1)
            # --check re-reads the sidecar (advisory), default exit 0
            rc_check = MOD.main(["--workspace", str(ws), "--check"])
            self.assertEqual(rc_check, 0)


class TestSurvivorRecountForms(unittest.TestCase):
    """FP-fix regression (fleet FPs -> 0): survivor re-count forms that were previously
    unrecognized must now be seen as a re-assertion (SILENT). Inline, self-contained
    reproductions of the sei-chain fleet FPs (msg.go verifyQC / timeout.go Verify /
    multisig.go VerifyMultisignature)."""

    def test_weighted_quorum_reassert_silent(self):
        # `weight < quorumWeight` - `weight` is the survivor (weighted) count.
        src = """
package consensus
func (m *M) verifyQC(c *Committee, quorumWeight uint64, sigs []*Signature) error {
\tweight := uint64(0)
\tdone := map[PublicKey]struct{}{}
\tfor _, sig := range sigs {
\t\tif _, ok := done[sig.key]; ok { return errDup }
\t\tdone[sig.key] = struct{}{}
\t\tweight += c.Weight(sig.key)
\t\tif err := sm.VerifySig(c); err != nil { return err }
\t}
\tif weight < quorumWeight {
\t\treturn errNotEnough
\t}
\treturn nil
}
"""
        rows = _rows(src, "msg.go")
        self.assertEqual(len(rows), 1, rows)
        self.assertFalse(rows[0]["fires"], rows[0])
        self.assertTrue(rows[0]["reasserts_survivor_count"])

    def test_go_tuple_alias_reassert_silent(self):
        # `if got, want := weight, c.TimeoutQuorum(); got < want` - alias resolution.
        src = """
package consensus
func (m *TimeoutQC) Verify(c *Committee) error {
\tweight := uint64(0)
\tdone := map[PublicKey]struct{}{}
\tfor _, v := range m.votes {
\t\tif _, ok := done[v.sig.key]; ok { return errDup }
\t\tweight += c.Weight(v.sig.key)
\t\tdone[v.sig.key] = struct{}{}
\t\tif err := v.VerifySig(c); err != nil { return err }
\t}
\tif got, want := weight, c.TimeoutQuorum(); got < want {
\t\treturn errNotEnough
\t}
\treturn nil
}
"""
        rows = _rows(src, "timeout.go")
        self.assertEqual(len(rows), 1, rows)
        self.assertFalse(rows[0]["fires"], rows[0])
        self.assertIn("got, want", rows[0]["guard_line"])

    def test_balanced_call_operand_reassert_silent(self):
        # `NumTrueBitsBefore(size) < int(m.Threshold)` / `len(sigs) < int(m.Threshold)`
        # - the balanced call operand must not truncate to `size)` / `sigs)`.
        src = """
package multisig
func (m *Key) VerifyMultisignature(sig *MultiSignatureData) error {
\tsigs := sig.Signatures
\tsize := sig.BitArray.Count()
\tif len(sigs) < int(m.Threshold) || len(sigs) > size {
\t\treturn errBadSize
\t}
\tif sig.BitArray.NumTrueBitsBefore(size) < int(m.Threshold) {
\t\treturn errNotEnough
\t}
\tsigIndex := 0
\tfor i := 0; i < size; i++ {
\t\tif sig.BitArray.GetIndex(i) {
\t\t\tif err := verifyOne(i); err != nil { return err }
\t\t\tsigIndex++
\t\t}
\t}
\treturn nil
}
"""
        rows = _rows(src, "multisig.go")
        self.assertEqual(len(rows), 1, rows)
        self.assertFalse(rows[0]["fires"], rows[0])
        self.assertTrue(rows[0]["reasserts_survivor_count"])


class TestNonAggregatorNoiseDropped(unittest.TestCase):
    """FP-fix regression: non-aggregator noise no longer produces a row."""

    def test_cancun_signer_is_not_a_threshold(self):
        # `NewCancunSigner` must NOT match the `nSigners` K token mid-word.
        src = """
package transactions
func TransactionsBySender(block *Block, sender Address) (int64, error) {
\ttxCount := int64(0)
\tfor _, tx := range block.Transactions() {
\t\tsigner := types.NewCancunSigner(tx.ChainId())
\t\ttxSender, err := types.Sender(signer, tx)
\t\tif err != nil { return 0, err }
\t\tif txSender == sender { txCount++ }
\t}
\treturn txCount, nil
}
"""
        self.assertEqual(_rows(src, "count.go"), [],
                         "NewCancunSigner is not a K-of-N threshold")

    def test_cli_main_entrypoint_dropped(self):
        # a `main` CLI entrypoint whose threshold token is flag/log prose is not scanned.
        src = """
package main
func main() {
\tif flagStr == "" { log.Crit("--prestate-hash is required") }
\tsupported := make([]string, 0)
\tfor _, name := range names {
\t\tif !filter(name) { continue }
\t\tsupported = append(supported, name)
\t}
\t_ = supported
}
"""
        self.assertEqual(_rows(src, "main.go"), [],
                         "CLI main entrypoint must not be scanned as an aggregator")

    def test_standalone_n_signers_still_a_threshold(self):
        # recall guard: a STANDALONE `nSigners` identifier is still a K token.
        src = """
package quorum
func tally(sigs []Sig, nSigners int) bool {
\tvalid := 0
\tfor _, s := range sigs { if s.ok { valid++ } }
\treturn valid > 0 && nSigners > 0
}
"""
        rows = _rows(src, "q.go")
        self.assertEqual(len(rows), 1, rows)
        self.assertEqual(rows[0]["threshold_expr"], "nSigners")


class TestRealFleetGuardedSilent(unittest.TestCase):
    """HARD RULE 5 - the tool is SILENT on the actual guarded fleet source (the
    mutation-verify FIRE half is done out-of-band on a temp copy, never mutating a
    ws file). SKIP when the fleet source is not checked out (no faked pass)."""

    def test_etherfi_multisig_checkSignatures_silent(self):
        f = pathlib.Path(
            "/Users/wolf/audits/etherfi/src/cash-v3/src/safe/MultiSig.sol")
        if not f.exists():
            self.skipTest("etherfi fleet source not present")
        rows = MOD.scan_file(f, f.name)
        cs = [r for r in rows if r["function"] == "checkSignatures"]
        self.assertEqual(len(cs), 1, "checkSignatures must be seen as an aggregator")
        self.assertFalse(cs[0]["fires"], "guarded checkSignatures must be SILENT")

    def test_sei_clique_snapshot_apply_silent(self):
        f = pathlib.Path(
            "/Users/wolf/audits/sei/src/go-ethereum/consensus/clique/snapshot.go")
        if not f.exists():
            self.skipTest("sei fleet source not present")
        rows = MOD.scan_file(f, f.name)
        ap = [r for r in rows if r["function"] == "apply"]
        self.assertEqual(len(ap), 1, "clique apply must be seen as an aggregator")
        self.assertFalse(ap[0]["fires"], "guarded clique apply must be SILENT")


if __name__ == "__main__":
    unittest.main()
