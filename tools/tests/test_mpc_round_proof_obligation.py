#!/usr/bin/env python3
"""Tests for tools/mpc-round-proof-obligation.py - the MPC per-round proof-obligation
reasoner (BitForge/GG20 CONSUME\\PROVEN set-difference + value-identity + round-order).

Includes a NON-VACUOUS mutation PAIR:
  (M1) add the missing per-round verify DOMINATING the sink over the SAME field local
       -> the survivor DISAPPEARS (moves to KEPT).
  (M2) verify a DIFFERENT local than the sink consumes (verify-then-swap)
       -> the survivor REAPPEARS, tagged verify_then_swap.
"""

from __future__ import annotations

import importlib.util
import json
import tempfile
import unittest
from pathlib import Path

_HERE = Path(__file__).resolve().parent
_TOOL = _HERE.parent / "mpc-round-proof-obligation.py"

_spec = importlib.util.spec_from_file_location("mpc_round_proof_obligation", _TOOL)
mpc = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(mpc)


def _rec(fn, var, sink_kind, sink_callee, sink_line, *, hops=None,
         confidence="semantic-ssa", language="rust", degraded=False,
         file="/ws/src/tofn/keygen/r3.rs", src_line=10, guards=None):
    return {
        "schema": "dataflow_path.v1",
        "path_id": f"dfp-{fn}-{var}-{sink_callee}",
        "language": language,
        "direction": "backward",
        "engine": "rust-mir",
        "source": {"kind": "param", "fn": fn, "var": var, "file": file,
                   "line": src_line},
        "sink": {"kind": sink_kind, "callee": sink_callee, "arg_pos": 1,
                 "fn": fn, "file": file, "line": sink_line},
        "hops": hops or [],
        "call_depth": len(hops or []),
        "unguarded": True,
        "guard_nodes": guards or [],
        "source_unit_ids": [], "sink_unit_ids": [],
        "confidence": confidence,
        "degraded": degraded,
    }


def _write(ws: Path, records):
    ad = ws / ".auditooor"
    ad.mkdir(parents=True, exist_ok=True)
    p = ad / "dataflow_paths.jsonl"
    with p.open("w", encoding="utf-8") as fh:
        for r in records:
            fh.write(json.dumps(r) + "\n")
    return p


def _run(ws: Path, extra=None):
    argv = ["--workspace", str(ws), "--json"]
    if extra:
        argv += extra
    # run() prints json to stdout; we call it directly and read the returned summary.
    return mpc.run(argv)


class MpcRoundProofTest(unittest.TestCase):

    def test_1_baseline_survivor_missing_verify(self):
        """A GG20 keygen round-3 field (paillier ciphertext) flows into
        lagrange_interpolate with NO verify -> survivor."""
        with tempfile.TemporaryDirectory() as d:
            ws = Path(d)
            _write(ws, [
                _rec("tofn::keygen::r3::execute", "paillier_ct",
                     "value-move", "lagrange_interpolate", 42),
            ])
            s = _run(ws)
            c = s["counts"]
            self.assertEqual(c["CONSUME"], 1, s)
            self.assertEqual(c["PROVEN_kept"], 0, s)
            self.assertEqual(c["survivors_CONSUME_minus_PROVEN"], 1, s)
            self.assertFalse(s["language_na"])
            self.assertFalse(s["substrate_vacuous"])
            # obligation emitted + cites source AND sink line
            obs = [json.loads(l) for l in
                   (ws / ".auditooor" /
                    "mpc_round_proof_obligation_obligations.jsonl").read_text().splitlines()]
            self.assertEqual(len(obs), 1)
            self.assertEqual(obs[0]["attack_class"], "mpc-key-extraction")
            self.assertEqual(obs[0]["likely_severity"], "critical")
            self.assertEqual(obs[0]["failing_axis"], "missing-verify")

    def test_2_mutation_add_dominating_verify_kills_survivor(self):
        """M1: add a feldman/vss verify that DOMINATES the sink (verify line < sink
        line) over the SAME field local -> survivor DISAPPEARS (KEPT)."""
        with tempfile.TemporaryDirectory() as d:
            ws = Path(d)
            _write(ws, [
                # same field now also passes a verify node at line 30 (< sink 42)
                _rec("tofn::keygen::r3::execute", "paillier_ct",
                     "value-move", "lagrange_interpolate", 42,
                     hops=[{"from_var": "paillier_ct", "to_var": "ok",
                            "fn": "paillier_blum_verify", "via": "internal_call",
                            "file": "/ws/src/tofn/keygen/r3.rs", "line": 30,
                            "ir": "ok = paillier_blum_verify(copy paillier_ct)",
                            "guarded": True}]),
            ])
            s = _run(ws)
            c = s["counts"]
            self.assertEqual(c["CONSUME"], 1, s)
            self.assertEqual(c["PROVEN_kept"], 1, s)
            self.assertEqual(c["survivors_CONSUME_minus_PROVEN"], 0, s)

    def test_3_mutation_verify_then_swap_reintroduces_survivor(self):
        """M2: verify a DIFFERENT local (nonce_commit) than the sink consumes
        (paillier_ct) -> survivor REAPPEARS, tagged verify_then_swap."""
        with tempfile.TemporaryDirectory() as d:
            ws = Path(d)
            _write(ws, [
                # consumed field: paillier_ct -> sink, NO verify on its own slice
                _rec("tofn::keygen::r3::execute", "paillier_ct",
                     "value-move", "lagrange_interpolate", 42),
                # a DIFFERENT field in the same fn IS verified (the swap)
                _rec("tofn::keygen::r3::execute", "nonce_commit",
                     "state-write", "store_tmp", 20,
                     hops=[{"from_var": "nonce_commit", "to_var": "ok",
                            "fn": "feldman_verify", "via": "internal_call",
                            "file": "/ws/src/tofn/keygen/r3.rs", "line": 15,
                            "ir": "ok = feldman_verify(copy nonce_commit)",
                            "guarded": True}]),
            ])
            s = _run(ws)
            c = s["counts"]
            self.assertEqual(c["survivors_CONSUME_minus_PROVEN"], 1, s)
            self.assertEqual(c["verify_then_swap"], 1, s)
            surv = s["survivors"][0]
            self.assertTrue(surv["swap"], s)
            self.assertEqual(surv["var"], "paillier_ct")

    def test_4_cited_empty_over_semantic_mpc_substrate(self):
        """MPC ceremony present + semantic, but NO field reaches a secret sink
        (only a non-secret log write) -> CONSUME=0, honest cited-empty, NOT vacuous,
        NOT language_na."""
        with tempfile.TemporaryDirectory() as d:
            ws = Path(d)
            _write(ws, [
                _rec("tofn::keygen::r1::execute", "commit",
                     "state-write", "emit_log", 12),  # non-secret sink
            ])
            s = _run(ws)
            self.assertEqual(s["counts"]["CONSUME"], 0, s)
            self.assertFalse(s["language_na"], s)
            self.assertFalse(s["substrate_vacuous"], s)
            self.assertTrue(s["substrate_present"], s)

    def test_5_non_mpc_records_excluded_language_na(self):
        """Generic Go cosmos-sdk keeper Set/Delete (no MPC marker) must be EXCLUDED;
        with no MPC crate on disk this is honest MPC-N/A, and --fail-closed PASSES."""
        with tempfile.TemporaryDirectory() as d:
            ws = Path(d)
            _write(ws, [
                _rec("store.Set", "key", "state-write", "Set", 119,
                     language="go", file="/ws/vendor/cosmos-sdk/store/cache.go"),
                _rec("keeper.SetClientState", "height", "state-write",
                     "SetChannel", 88, language="go",
                     file="/ws/x/ibc/keeper/keeper.go"),
            ])
            s = _run(ws)
            self.assertTrue(s["language_na"], s)
            self.assertEqual(s["counts"]["CONSUME"], 0, s)
            self.assertFalse(s["substrate_failed_to_materialize"], s)
            # fail-closed must PASS (no MPC crate on disk)
            rc = 0
            try:
                _run(ws, extra=["--fail-closed"])
            except SystemExit as e:
                rc = e.code
            self.assertEqual(rc, 0, "MPC-N/A must not fail-closed")

    def test_6_substrate_vacuous_all_syntactic(self):
        """MPC ceremony records present but ALL syntactic (no semantic-ssa) ->
        substrate_vacuous advisory + --fail-closed FAILS."""
        with tempfile.TemporaryDirectory() as d:
            ws = Path(d)
            _write(ws, [
                _rec("tofn::sign::r5::execute", "partial_sig",
                     "value-move", "add_partial_sig", 50, confidence="syntactic"),
            ])
            s = _run(ws)
            self.assertTrue(s["substrate_vacuous"], s)
            self.assertEqual(s["mpc_semantic_rows"], 0, s)
            rc = 0
            try:
                _run(ws, extra=["--fail-closed"])
            except SystemExit as e:
                rc = e.code
            self.assertEqual(rc, 3, "vacuous MPC substrate must fail-closed")

    def test_7_ordering_axis_verify_after_sink_is_survivor(self):
        """Round-ordering axis (a): a verify that occurs AFTER the sink (verify line >
        sink line) does NOT prove the field -> survivor (a stale/late proof)."""
        with tempfile.TemporaryDirectory() as d:
            ws = Path(d)
            _write(ws, [
                _rec("tofn::sign::r6::execute", "sigma_i",
                     "value-move", "sign_finalize", 30,
                     hops=[{"from_var": "sigma_i", "to_var": "ok",
                            "fn": "range_proof_verify", "via": "internal_call",
                            "file": "/ws/src/tofn/sign/r6.rs", "line": 55,  # AFTER 30
                            "ir": "ok = range_proof_verify(copy sigma_i)",
                            "guarded": True}]),
            ])
            s = _run(ws)
            self.assertEqual(s["counts"]["survivors_CONSUME_minus_PROVEN"], 1, s)
            self.assertEqual(s["counts"]["PROVEN_kept"], 0, s)


    def test_8_multisig_lookalike_crate_is_language_na_not_failed(self):
        """A crate literally NAMED like an MPC crate (tofnd) but that is a single-key
        MULTISIG fork - NO ceremony primitives in source (no MtA/Paillier/VSS/round
        handlers), only stale `[crate::gg20::mnemonic]` doc-comment links - must be
        honest MPC-N/A, NOT a false 'substrate failed to materialize' infra-gap."""
        with tempfile.TemporaryDirectory() as d:
            ws = Path(d)
            # non-MPC substrate (generic go keeper write, no ceremony marker) so the
            # analysis is language_na and the crate-on-disk discriminator is exercised
            _write(ws, [
                _rec("store.Set", "k", "state-write", "Set", 5, language="go",
                     file="/ws/vendor/x/keeper.go")
            ])
            # multisig look-alike crate on disk: name matches, source has ZERO primitives
            crate = ws / "src" / "tofnd"
            (crate / "src" / "multisig").mkdir(parents=True)
            (crate / "Cargo.toml").write_text('[package]\nname = "tofnd"\n')
            (crate / "src" / "multisig" / "sign.rs").write_text(
                "// re-generate secret key from seed, then sign\n"
                "pub fn handle_sign() {}\n")
            (crate / "src" / "mnemonic.rs").write_text(
                "//! kv-store for [crate::gg20::Entropy] and [crate::gg20::mnemonic]\n")
            s = _run(ws, extra=["--src-root", str(crate)])
            self.assertTrue(s["language_na"], s)
            self.assertFalse(s["substrate_failed_to_materialize"], s)
            self.assertEqual(s["mpc_crate_on_disk"], "", s)
            rc = 0
            try:
                _run(ws, extra=["--src-root", str(crate), "--fail-closed"])
            except SystemExit as e:
                rc = e.code
            self.assertEqual(rc, 0, "multisig look-alike must not fail-closed")

    def test_9_real_ceremony_crate_zero_rows_is_failed_to_materialize(self):
        """A crate that carries REAL ceremony primitives in source (MtA/Paillier round
        handler) but produced 0 ceremony dataflow rows -> the MIR backend genuinely
        failed to lift it: fail-loud is preserved."""
        with tempfile.TemporaryDirectory() as d:
            ws = Path(d)
            _write(ws, [
                _rec("store.Set", "k", "state-write", "Set", 5, language="go",
                     file="/ws/vendor/x/keeper.go")  # non-MPC row -> language_na
            ])
            crate = ws / "src" / "tofn"
            (crate / "src" / "sign").mkdir(parents=True)
            (crate / "Cargo.toml").write_text('[package]\nname = "tofn"\n')
            (crate / "src" / "sign" / "r5.rs").write_text(
                "pub fn r5_execute() { let _ = mta_response_verify(); "
                "add_partial_sig(); }\n")
            s = _run(ws, extra=["--src-root", str(crate)])
            self.assertTrue(s["language_na"], s)
            self.assertTrue(s["substrate_failed_to_materialize"], s)
            self.assertTrue(s["mpc_crate_on_disk"], s)


if __name__ == "__main__":
    unittest.main(verbosity=2)
