#!/usr/bin/env python3
"""Regression: an entrypoint-corpus-bridge close, once emitted as a durable
terminal-negative hunt sidecar by tools/entrypoint-corpus-sidecar-emit.py, SURVIVES
an exploit_queue REBUILD via tools/exploit-queue-terminal-join.py.

This is the durability guarantee the sidecar emitter exists to provide: a direct
bridge --write to exploit_queue.json is wiped when prove-top-leads rebuilds the
queue, but the sidecar-backed close is re-applied by terminal-join on every rebuild.

Hard invariants asserted here:
  (i)   a NON-entry-point bridge close is re-terminalized (closed_negative) AFTER a
        simulated rebuild resets the row to proof_status=open;
  (ii)  an ENTRY-POINT row (never in the bridge close set, no sidecar) is NEVER
        closed by the emitted sidecars - it stays open;
  (iii) the sidecars are fn-index-inert: a same-named entry-point row on a DIFFERENT
        contract is NOT collaterally closed via a (fn, stem) / fn-only-fallback join.
"""
from __future__ import annotations

import importlib.util
import json
import sys
import tempfile
import unittest
from pathlib import Path

_TOOLS = Path(__file__).resolve().parent.parent


def _load(mod_name, filename):
    spec = importlib.util.spec_from_file_location(mod_name, str(_TOOLS / filename))
    mod = importlib.util.module_from_spec(spec)
    sys.modules[mod_name] = mod
    spec.loader.exec_module(mod)
    return mod


EMIT = _load("entrypoint_corpus_sidecar_emit", "entrypoint-corpus-sidecar-emit.py")
TJOIN = _load("exploit_queue_terminal_join", "exploit-queue-terminal-join.py")


def _make_cosmos_go_ws(root: Path) -> Path:
    ws = root / "cosmos_ws"
    (ws / "app").mkdir(parents=True, exist_ok=True)
    (ws / "x" / "evm" / "keeper").mkdir(parents=True, exist_ok=True)
    (ws / "go.mod").write_text(
        "module example.com/chain\n\nrequire (\n"
        "\tgithub.com/cosmos/cosmos-sdk v0.50.0\n"
        "\tgithub.com/cometbft/cometbft v0.38.0\n)\n",
        encoding="utf-8",
    )
    # ENTRY-POINT: a msg-server handler.
    (ws / "x" / "evm" / "keeper" / "msg_server.go").write_text(
        "package keeper\n\n"
        "func (s msgServer) EVMTransaction(goCtx context.Context, msg *types.MsgEVMTransaction) "
        "(*types.MsgEVMTransactionResponse, error) {\n\treturn nil, nil\n}\n",
        encoding="utf-8",
    )
    # NON-entry-point genesis/app-init helper.
    (ws / "app" / "app.go").write_text(
        "package app\n\n"
        "func InitModuleAccountPermissions() map[string][]string {\n\treturn nil\n}\n",
        encoding="utf-8",
    )
    # A DIFFERENT contract that also declares a func named EVMTransaction (free fn) -
    # used to prove the sidecars do NOT collaterally close it by name.
    (ws / "app" / "helper.go").write_text(
        "package app\n\nfunc EVMTransaction() {}\n",
        encoding="utf-8",
    )
    return ws


def _packet(candidate_id, contract, fn, markers):
    return {
        "candidate_id": candidate_id,
        "packet_state": "blocked_missing_truth",
        "promotion_blockers": list(markers),
        "impact_enumeration": {"function": fn},
        "required_judgment_fields": {
            "dupe_triple": f"contract={contract} | function={fn} | attack_class=x"
        },
    }


def _row(lead_id, fn, contract, status="open"):
    return {"lead_id": lead_id, "proof_status": status, "function": fn, "contract": contract}


class DurableAcrossRebuild(unittest.TestCase):
    def _setup(self, td):
        ws = _make_cosmos_go_ws(Path(td))
        aud = ws / ".auditooor"
        aud.mkdir(parents=True, exist_ok=True)
        packets = [
            _packet("L-INIT", "app/app.go", "InitModuleAccountPermissions",
                    ["missing:attacker_actor"]),
            _packet("L-ENTRY", "x/evm/keeper/msg_server.go", "EVMTransaction",
                    ["missing:permissionless_trigger"]),
        ]
        (aud / "prove_top_leads_candidate_judgment_packet.json").write_text(
            json.dumps({"packets": packets}), encoding="utf-8")
        return ws, aud

    def _write_queue(self, aud, rows):
        # Both queue files that prove-top-leads / terminal-join operate on.
        for name in ("exploit_queue.json", "exploit_queue.source_mined.json"):
            (aud / name).write_text(json.dumps({"queue": rows}), encoding="utf-8")

    def test_bridge_close_survives_rebuild(self):
        with tempfile.TemporaryDirectory() as td:
            ws, aud = self._setup(td)
            self._write_queue(aud, [
                _row("L-INIT", "InitModuleAccountPermissions", "app/app.go"),
                _row("L-ENTRY", "EVMTransaction", "x/evm/keeper/msg_server.go"),
                # same-named entry fn on a DIFFERENT contract - must NOT be closed.
                _row("L-ENTRY2", "EVMTransaction", "app/helper.go"),
            ])

            # 1) Emit durable sidecars for the bridge close set (L-INIT only).
            res = EMIT.emit(ws, marker="test", write=True)
            self.assertEqual(res["written"], 1)
            scdir = ws / ".auditooor" / "hunt_findings_sidecars"
            self.assertTrue((scdir / "entrypoint_corpus__L-INIT.json").is_file())
            self.assertFalse((scdir / "entrypoint_corpus__L-ENTRY.json").is_file())

            # 2) Simulate a queue REBUILD: rows reset to proof_status=open
            #    (a direct bridge --write would have been wiped here).
            self._write_queue(aud, [
                _row("L-INIT", "InitModuleAccountPermissions", "app/app.go"),
                _row("L-ENTRY", "EVMTransaction", "x/evm/keeper/msg_server.go"),
                _row("L-ENTRY2", "EVMTransaction", "app/helper.go"),
            ])

            # 3) terminal-join re-applies from the persistent sidecars.
            for qn in ("exploit_queue.json", "exploit_queue.source_mined.json"):
                TJOIN.join(ws, marker="test", apply=True, queue_name=qn)

            q = json.loads((aud / "exploit_queue.source_mined.json").read_text())
            idx = {r["lead_id"]: r for r in q["queue"]}
            # (i) non-entry close survived the rebuild
            self.assertEqual(idx["L-INIT"]["proof_status"], "closed_negative")
            self.assertEqual(idx["L-INIT"]["quality_gate_status"], "closed_negative")
            self.assertIn("terminal_join", idx["L-INIT"])
            # (ii) entry-point row never closed
            self.assertEqual(idx["L-ENTRY"]["proof_status"], "open")
            # (iii) same-named entry fn on a different contract not collaterally closed
            self.assertEqual(idx["L-ENTRY2"]["proof_status"], "open")

    def test_idempotent_reemit(self):
        with tempfile.TemporaryDirectory() as td:
            ws, aud = self._setup(td)
            self._write_queue(aud, [_row("L-INIT", "InitModuleAccountPermissions", "app/app.go")])
            r1 = EMIT.emit(ws, write=True)
            r2 = EMIT.emit(ws, write=True)
            self.assertEqual(r1["written"], r2["written"], 1)
            scfiles = list((ws / ".auditooor" / "hunt_findings_sidecars").glob("entrypoint_corpus__*.json"))
            self.assertEqual(len(scfiles), 1)


if __name__ == "__main__":
    unittest.main(verbosity=2)
