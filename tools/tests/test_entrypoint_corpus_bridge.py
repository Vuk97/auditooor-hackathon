#!/usr/bin/env python3
"""Adversarial regression for tools/entrypoint-corpus-bridge.py.

The bridge terminal-closes ONLY corpus-INV `blocked_missing_truth` exploit-queue rows
whose function is PROVABLY a non-entry-point (per the authoritative
go_entrypoint_surface classifier) AND that carry a missing-trigger marker. These tests
build tiny synthetic workspaces on disk and assert the HARD SAFETY INVARIANTS:

  (i)   an ENTRY-POINT function (msg-server handler) is NEVER closed, even WITH marker;
  (ii)  a genesis/app-init NON-entry-point function WITH marker IS listed to close,
        with a cited source_ref;
  (iii) a packet MISSING the trigger-marker is NEVER closed;
  (iv)  a Solidity / non-Cosmos-Go workspace (no Go entry classifier) is a safe NO-OP.

A regression that lets the bridge close an attacker-reachable (entry-point) lead, or
close a marker-less lead, or leak into a Solidity workspace, FAILS here.
"""
from __future__ import annotations

import importlib.util
import json
import sys
import tempfile
import unittest
from pathlib import Path

_TOOLS = Path(__file__).resolve().parent.parent


def _load_bridge():
    spec = importlib.util.spec_from_file_location(
        "entrypoint_corpus_bridge", str(_TOOLS / "entrypoint-corpus-bridge.py")
    )
    mod = importlib.util.module_from_spec(spec)
    sys.modules["entrypoint_corpus_bridge"] = mod
    spec.loader.exec_module(mod)
    return mod


B = _load_bridge()


def _packet(candidate_id, contract, fn, markers, state="blocked_missing_truth"):
    return {
        "candidate_id": candidate_id,
        "packet_state": state,
        "promotion_blockers": list(markers),
        "impact_enumeration": {"function": fn},
        "required_judgment_fields": {
            "dupe_triple": f"contract={contract} | function={fn} | attack_class=x"
        },
    }


def _admin_packet(candidate_id, contract, fn, markers):
    return _packet(
        candidate_id, contract, fn, markers,
        state="blocked_admin_gated_or_by_design",
    )


def _queue_row(lead_id, status="open"):
    return {"lead_id": lead_id, "proof_status": status, "title": f"lead {lead_id}"}


def _write_artifacts(ws: Path, packets, rows):
    aud = ws / ".auditooor"
    aud.mkdir(parents=True, exist_ok=True)
    (aud / "prove_top_leads_candidate_judgment_packet.json").write_text(
        json.dumps({"packets": packets}), encoding="utf-8"
    )
    (aud / "exploit_queue.json").write_text(
        json.dumps({"queue": rows}), encoding="utf-8"
    )


def _make_cosmos_go_ws(root: Path) -> Path:
    """A workspace confidently classified as Cosmos/Go-L1 (go.mod + x/ layout)."""
    ws = root / "cosmos_ws"
    (ws / "app").mkdir(parents=True, exist_ok=True)
    (ws / "x" / "evm" / "keeper").mkdir(parents=True, exist_ok=True)
    (ws / "go.mod").write_text(
        "module example.com/chain\n\nrequire (\n"
        "\tgithub.com/cosmos/cosmos-sdk v0.50.0\n"
        "\tgithub.com/cometbft/cometbft v0.38.0\n)\n",
        encoding="utf-8",
    )
    # An ENTRY-POINT function: a msg-server handler (receiver *msgServer).
    (ws / "x" / "evm" / "keeper" / "msg_server.go").write_text(
        "package keeper\n\n"
        "func (s msgServer) EVMTransaction(goCtx context.Context, msg *types.MsgEVMTransaction) "
        "(*types.MsgEVMTransactionResponse, error) {\n\treturn nil, nil\n}\n",
        encoding="utf-8",
    )
    # A NON-entry-point genesis/app-init helper (free function, non-boundary file).
    (ws / "app" / "app.go").write_text(
        "package app\n\n"
        "func InitModuleAccountPermissions() map[string][]string {\n\treturn nil\n}\n",
        encoding="utf-8",
    )
    # A NON-entry-point crypto_signing constructor (free function, internal helper) - the
    # sensitive admin-gated shape: a signing-adjacent function that is NOT tx-invocable.
    (ws / "x" / "evm" / "types").mkdir(parents=True, exist_ok=True)
    (ws / "x" / "evm" / "types" / "types.go").write_text(
        "package types\n\n"
        "func NewSignature(bz []byte) (sig Signature, err error) {\n\treturn Signature{}, nil\n}\n",
        encoding="utf-8",
    )
    return ws


class EntrypointCorpusBridgeSafety(unittest.TestCase):
    def test_i_entry_point_never_closed_even_with_marker(self):
        with tempfile.TemporaryDirectory() as td:
            ws = _make_cosmos_go_ws(Path(td))
            packets = [
                _packet(
                    "L-ENTRY",
                    "x/evm/keeper/msg_server.go",
                    "EVMTransaction",
                    ["missing:permissionless_trigger"],
                )
            ]
            _write_artifacts(ws, packets, [_queue_row("L-ENTRY")])
            plan = B.build_plan(ws)
            self.assertNotIn("L-ENTRY", plan["would_close_lead_ids"])
            self.assertEqual(plan["counts"]["would_close"], 0)
            self.assertEqual(plan["counts"]["kept_entry_point"], 1)
            self.assertTrue(plan["per_function_entry_verdict"].get("EVMTransaction"))
            # a decision record must loudly refuse it
            refusals = [d for d in plan["decisions"] if d["decision"] == "keep-entry-point"]
            self.assertTrue(any(d["lead_id"] == "L-ENTRY" for d in refusals))

    def test_ii_genesis_nonentry_with_marker_is_listed_with_citation(self):
        with tempfile.TemporaryDirectory() as td:
            ws = _make_cosmos_go_ws(Path(td))
            packets = [
                _packet(
                    "L-INIT",
                    "app/app.go",
                    "InitModuleAccountPermissions",
                    ["missing:attacker_actor"],
                )
            ]
            _write_artifacts(ws, packets, [_queue_row("L-INIT")])
            plan = B.build_plan(ws)
            self.assertIn("L-INIT", plan["would_close_lead_ids"])
            self.assertEqual(plan["counts"]["would_close"], 1)
            dec = next(d for d in plan["decisions"] if d["lead_id"] == "L-INIT")
            self.assertEqual(dec["decision"], "close")
            self.assertFalse(dec["entry_point"])
            self.assertTrue(dec.get("source_ref"))  # cited source ref
            self.assertIn("app/app.go", dec["source_ref"])
            self.assertIn("non-entry-point", dec["reason"])

    def test_iii_missing_marker_never_closed(self):
        with tempfile.TemporaryDirectory() as td:
            ws = _make_cosmos_go_ws(Path(td))
            # Same non-entry function, but NO missing-trigger marker.
            packets = [
                _packet(
                    "L-NOMARK",
                    "app/app.go",
                    "InitModuleAccountPermissions",
                    ["missing:required_evidence_class"],
                )
            ]
            _write_artifacts(ws, packets, [_queue_row("L-NOMARK")])
            plan = B.build_plan(ws)
            self.assertNotIn("L-NOMARK", plan["would_close_lead_ids"])
            self.assertEqual(plan["counts"]["would_close"], 0)
            self.assertEqual(plan["counts"]["kept_no_marker"], 1)

    def test_iv_solidity_workspace_is_safe_noop(self):
        with tempfile.TemporaryDirectory() as td:
            ws = Path(td) / "sol_ws"
            (ws / "src").mkdir(parents=True, exist_ok=True)
            (ws / "foundry.toml").write_text("[profile.default]\n", encoding="utf-8")
            (ws / "src" / "Vault.sol").write_text(
                "pragma solidity ^0.8.0;\ncontract Vault { function deposit() external {} }\n",
                encoding="utf-8",
            )
            packets = [
                _packet(
                    "L-SOL",
                    "src/Vault.sol",
                    "deposit",
                    ["missing:permissionless_trigger"],
                )
            ]
            _write_artifacts(ws, packets, [_queue_row("L-SOL")])
            plan = B.build_plan(ws)
            self.assertFalse(plan["go_entry_classifier_applies"])
            self.assertEqual(plan["counts"]["would_close"], 0)
            self.assertEqual(plan["counts"]["kept_non_go_workspace"], 1)
            self.assertNotIn("L-SOL", plan["would_close_lead_ids"])

    def test_v_already_terminal_row_never_reclosed(self):
        with tempfile.TemporaryDirectory() as td:
            ws = _make_cosmos_go_ws(Path(td))
            packets = [
                _packet(
                    "L-DONE",
                    "app/app.go",
                    "InitModuleAccountPermissions",
                    ["missing:attacker_actor"],
                )
            ]
            # already a real finding
            _write_artifacts(ws, packets, [_queue_row("L-DONE", status="filed")])
            plan = B.build_plan(ws)
            self.assertNotIn("L-DONE", plan["would_close_lead_ids"])
            self.assertEqual(plan["counts"]["kept_already_terminal"], 1)

    def test_vi_dry_run_default_does_not_mutate_queue(self):
        with tempfile.TemporaryDirectory() as td:
            ws = _make_cosmos_go_ws(Path(td))
            packets = [
                _packet(
                    "L-INIT",
                    "app/app.go",
                    "InitModuleAccountPermissions",
                    ["missing:attacker_actor"],
                )
            ]
            _write_artifacts(ws, packets, [_queue_row("L-INIT")])
            # main() default (no --write) must leave the queue byte-untouched
            qpath = ws / ".auditooor" / "exploit_queue.json"
            before = qpath.read_text()
            rc = B.main(["--workspace", str(ws)])
            self.assertEqual(rc, 0)
            self.assertEqual(qpath.read_text(), before)

    def test_vii_write_applies_only_closed_rows(self):
        with tempfile.TemporaryDirectory() as td:
            ws = _make_cosmos_go_ws(Path(td))
            packets = [
                _packet("L-INIT", "app/app.go", "InitModuleAccountPermissions",
                        ["missing:attacker_actor"]),
                _packet("L-ENTRY", "x/evm/keeper/msg_server.go", "EVMTransaction",
                        ["missing:permissionless_trigger"]),
            ]
            _write_artifacts(ws, packets, [_queue_row("L-INIT"), _queue_row("L-ENTRY")])
            plan = B.build_plan(ws)
            mutated = B.apply_plan(ws, plan)
            self.assertEqual(mutated, 1)
            q = json.loads((ws / ".auditooor" / "exploit_queue.json").read_text())
            idx = {r["lead_id"]: r for r in q["queue"]}
            self.assertEqual(idx["L-INIT"]["proof_status"], "closed_negative")
            # entry-point row stays OPEN
            self.assertEqual(idx["L-ENTRY"]["proof_status"], "open")


    # ---- blocked_admin_gated_or_by_design extension (state 2) --------------------

    def test_viii_admin_gated_nonentry_with_marker_is_closed(self):
        with tempfile.TemporaryDirectory() as td:
            ws = _make_cosmos_go_ws(Path(td))
            packets = [
                _admin_packet(
                    "L-ADMIN",
                    "app/app.go",
                    "InitModuleAccountPermissions",
                    ["admin_gated_or_by_design", "missing:required_evidence_class"],
                )
            ]
            _write_artifacts(ws, packets, [_queue_row("L-ADMIN")])
            plan = B.build_plan(ws)
            self.assertIn("L-ADMIN", plan["would_close_lead_ids"])
            self.assertEqual(plan["counts"]["would_close"], 1)
            self.assertEqual(plan["counts"]["would_close_admin_gated"], 1)
            self.assertEqual(plan["counts"]["blocked_admin_gated_total"], 1)
            dec = next(d for d in plan["decisions"] if d["lead_id"] == "L-ADMIN")
            self.assertEqual(dec["decision"], "close")
            self.assertFalse(dec["entry_point"])
            self.assertIn("non-entry-point", dec["reason"])
            self.assertIn("admin gate", dec["reason"])

    def test_ix_admin_gated_entry_point_never_closed(self):
        """The priv-esc-hiding case: an admin gate on a REAL entry point must NOT close."""
        with tempfile.TemporaryDirectory() as td:
            ws = _make_cosmos_go_ws(Path(td))
            packets = [
                _admin_packet(
                    "L-ADMIN-ENTRY",
                    "x/evm/keeper/msg_server.go",
                    "EVMTransaction",
                    ["admin_gated_or_by_design"],
                )
            ]
            _write_artifacts(ws, packets, [_queue_row("L-ADMIN-ENTRY")])
            plan = B.build_plan(ws)
            self.assertNotIn("L-ADMIN-ENTRY", plan["would_close_lead_ids"])
            self.assertEqual(plan["counts"]["would_close"], 0)
            self.assertEqual(plan["counts"]["kept_entry_point"], 1)
            refusals = [d for d in plan["decisions"] if d["decision"] == "keep-entry-point"]
            self.assertTrue(any(d["lead_id"] == "L-ADMIN-ENTRY" for d in refusals))

    def test_x_admin_gated_without_admin_marker_never_closed(self):
        """An admin-gated row lacking the admin_gated_or_by_design marker stays open."""
        with tempfile.TemporaryDirectory() as td:
            ws = _make_cosmos_go_ws(Path(td))
            packets = [
                _admin_packet(
                    "L-ADMIN-NOMARK",
                    "app/app.go",
                    "InitModuleAccountPermissions",
                    ["missing:required_evidence_class"],  # no admin_gated_or_by_design
                )
            ]
            _write_artifacts(ws, packets, [_queue_row("L-ADMIN-NOMARK")])
            plan = B.build_plan(ws)
            self.assertNotIn("L-ADMIN-NOMARK", plan["would_close_lead_ids"])
            self.assertEqual(plan["counts"]["would_close"], 0)
            self.assertEqual(plan["counts"]["kept_no_marker"], 1)

    def test_xi_admin_gated_crypto_signing_constructor_closed(self):
        """A non-entry crypto_signing constructor (NewSignature) IS closeable admin-gated."""
        with tempfile.TemporaryDirectory() as td:
            ws = _make_cosmos_go_ws(Path(td))
            packets = [
                _admin_packet(
                    "L-SIG",
                    "x/evm/types/types.go",
                    "NewSignature",
                    ["admin_gated_or_by_design"],
                )
            ]
            _write_artifacts(ws, packets, [_queue_row("L-SIG")])
            plan = B.build_plan(ws)
            self.assertIn("L-SIG", plan["would_close_lead_ids"])
            dec = next(d for d in plan["decisions"] if d["lead_id"] == "L-SIG")
            self.assertEqual(dec["decision"], "close")
            self.assertFalse(dec["entry_point"])
            self.assertIn("x/evm/types/types.go", dec["source_ref"])

    def test_xii_mixed_states_close_and_counts(self):
        """Both states drained together; per-state counts add up."""
        with tempfile.TemporaryDirectory() as td:
            ws = _make_cosmos_go_ws(Path(td))
            packets = [
                _packet("L-MT", "app/app.go", "InitModuleAccountPermissions",
                        ["missing:attacker_actor"]),
                _admin_packet("L-AG", "x/evm/types/types.go", "NewSignature",
                              ["admin_gated_or_by_design"]),
            ]
            _write_artifacts(ws, packets,
                             [_queue_row("L-MT"), _queue_row("L-AG")])
            plan = B.build_plan(ws)
            self.assertEqual(plan["counts"]["would_close"], 2)
            self.assertEqual(plan["counts"]["would_close_missing_truth"], 1)
            self.assertEqual(plan["counts"]["would_close_admin_gated"], 1)
            self.assertEqual(plan["counts"]["blocked_total"], 2)


if __name__ == "__main__":
    unittest.main(verbosity=2)
