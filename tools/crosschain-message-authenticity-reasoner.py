#!/usr/bin/env python3
"""crosschain-message-authenticity-reasoner.py - the Nomad $190M / Wormhole $325M
cross-chain forgery reasoning query.

LOGIC CAPABILITY (docs/LOGIC_ARSENAL_ROADMAP.md, cross-chain forgery class). This is
a SET / COMPOSITION query over the OWNED dataflow-closure backend, NOT a token
detector.

THE LOGIC TRIPLE (extracted from the Nomad/Wormhole/Multichain hack class)
  ASSUMPTION (that the hacks falsified):
    an inbound cross-chain message/packet delivered to a handler was already
    authenticated - its merkle root / signature / nonce / source-chain binding
    was verified and BOUND to the exact payload being acted on.
  INVARIANT the protocol must uphold:
    Let
      ACT      = { inbound cross-chain message-handler entrypoint  h :
                   h's forward callee closure REACHES a value/execute SINK
                   (mint / release / value-move / burn / authority-execute) that
                   acts on the inbound payload }
      VERIFIED = { inbound cross-chain message-handler entrypoint  h :
                   h's closure REACHES an AUTHENTICITY-BINDING node - a verified
                   merkle/proof membership check, a signature/quorum verify, a
                   replay/nonce/receipt idempotence guard, OR a source-chain
                   lookup that binds the acted payload to a trusted origin }
    The cross-chain trust boundary requires   ACT  is a SUBSET of  VERIFIED.
  TRUST-BOUNDARY that breaks:
    every  h in the SET-DIFFERENCE   ACT \\ VERIFIED   acts (mint/release/execute)
    on an inbound cross-chain message whose authenticity binding is MISSING,
    DEFAULTED-TRUSTED, or NOT BOUND to the acted payload - that is exactly the
    Nomad `acceptableRoot[0]==true` / Wormhole unverified-VAA class, emitted as a
    `crosschain-message-forgery` obligation.

WHY THIS IS LOGIC, NOT A SHAPE (guard-rail satisfied)
  It is NOT `body_contains('verifyVAA') absent`. It differs on the three axes that
  make it a graph-set relation - the SAME axes that make the Euler set-difference
  hunter a reasoning query rather than a regex:
    (a) membership is TRANSITIVE forward/backward-closure reachability to a
        SEMANTIC value/execute SINK and to a SEMANTIC authenticity node - a
        verifier reached through an N-hop helper (or a sibling IBC core hop)
        correctly places the handler in VERIFIED; a body-scoped regex cannot see
        past the immediate function body;
    (b) the finding is a RELATION between TWO SETS of entrypoints (the subset test
        ACT is a subset of VERIFIED) whose answer is the SET-DIFFERENCE, not a
        boolean over one function's text;
    (c) the authenticity node need NOT co-occur in the handler body: it is UNIONed
        across EVERY dataflow-path record that shares the same entrypoint, so a
        verifier that lives in one path while the mint sink lives in another still
        KEEPS the handler - impossible for any token-adjacency / same-file regex.

BACKEND (owned)
  <ws>/.auditooor/dataflow_paths.jsonl (schema dataflow_path.v1) + any scoped
  sidecar <ws>/.auditooor/dataflow_paths.*.jsonl (e.g. dataflow_paths.nexus.jsonl),
  produced by the go-ssa / slither / rust-mir dataflow engines. Each record binds a
  param/local SOURCE to a classified SINK (sink.kind), carries the closure HOPS
  (hop.ir call-sites + hop.fn callees) and the closure GUARD nodes
  (guard_nodes[].expr). ACT reads sink.kind; VERIFIED reads whether ANY closure
  node (sink.callee / hop.fn / a callee parsed from hop.ir / a guard_nodes expr)
  satisfies authenticity_pred.

OUTPUT
  <ws>/.auditooor/crosschain_forgery_obligations.jsonl - one row per survivor,
  schema `auditooor.crosschain_message_authenticity.v1`, exploit_queue-ingest
  compatible (contract/function/source_refs/root_cause_hypothesis/attack_class/
  broken_invariant_ids/quality_gate_status='needs_source'). exploit-queue.py ingests
  it via _gather_from_crosschain_forgery_obligations -> the queue ->
  per-fn-mimo-batch-gen OPEN-OBLIGATIONS block.

  A summary is printed / emitted (--json) with |ACT|, |VERIFIED|, |ACT\\VERIFIED|,
  the KEPT (acted-and-verified, proving the subtraction is non-vacuous) and the
  survivors.
"""

from __future__ import annotations

import argparse
import collections
import json
import re
import sys
import time
from pathlib import Path

_HERE = Path(__file__).resolve().parent
_REPO_ROOT = _HERE.parent


# ---------------------------------------------------------------------------
# ACT sink taxonomy - the value/execute sinks that an inbound cross-chain
# message is "acted on" through (mint a wrapped asset / release-transfer escrow /
# burn / execute an authority-changing op). These are the go-dataflow classifySink
# kinds + Solidity sink taxonomy that REALIZE the inbound payload. `state-write`
# is EXCLUDED from the default (an admin-config write is not a cross-chain
# value/execute action) - re-enable with --act-kinds.
# ---------------------------------------------------------------------------
_DEFAULT_ACT_KINDS = {"mint", "value-move", "burn", "safeTransfer", "authority", "execute"}


# ---------------------------------------------------------------------------
# INBOUND cross-chain message-handler ENTRYPOINT surface. This is entrypoint
# SELECTION (exactly like the Euler hunter's entrypoint filter) - the LOGIC is the
# set-difference wrapped around it, not this name set. It matches the cross-chain
# inbound-handler conventions across the stacks in scope:
#   * IBC / Cosmos:      OnRecvPacket / OnAcknowledgementPacket / WriteAcknowledgement
#   * Axelar:            RouteMessage / ExecuteMessage / SetNewMessage /
#                        HandleGeneralMessage / _handleMessage / SetMessageExecuted
#   * generic bridge/AMB:receiveMessage / handleMessage / processMessage /
#                        completeTransfer / deliver / handlePacket
#   * EVM LZ/CCIP/AMB:   lzReceive / _lzReceive / ccipReceive / _ccipReceive /
#                        onOFTReceived / executeMessage / receiveWormholeMessages
# Matched against the SHORT (last-segment) fn name, case-insensitively.
# ---------------------------------------------------------------------------
_DEFAULT_INBOUND = re.compile(
    r"^(?:"
    r"onrecvpacket|onrecv|onacknowledgementpacket|onacknowledge(?:packet)?|"
    r"writeacknowledgement|acknowledgepacket|"
    r"routemessage|executemessage|handlegeneralmessage|handlemessage|_handlemessage|"
    r"receivemessage|processmessage|completetransfer|deliver(?:message|packet)?|"
    r"handlepacket|setnewmessage|setmessageexecuted|"
    r"lzreceive|_lzreceive|ccipreceive|_ccipreceive|nonblockinglzreceive|"
    r"onoftreceived|receivewormholemessages|receivepayload|_execute(?:message)?"
    r")$",
    re.IGNORECASE,
)


# ---------------------------------------------------------------------------
# AUTHENTICITY-BINDING node predicate. Classifies a single CLOSURE node (a callee
# name / hop fn / guard expr) as "the required authenticity binding". This is the
# node predicate the extracted invariant mandates; the LOGIC is the transitive-
# closure set-difference wrapped around it (exactly as solvency_guard_pred is a
# per-node predicate under the Euler set logic). Four families the Nomad/Wormhole/
# Multichain post-mortems name as the missing binding:
#   (1) verified merkle root / proof membership (Nomad `acceptableRoot`)
#   (2) signature / quorum / guardian-set verify (Wormhole `parseAndVerifyVM`)
#   (3) replay / nonce / receipt idempotence (IBC packet-receipt, `messageExecuted`)
#   (4) source-chain / trusted-remote binding (Multichain src-chain, LZ trustedRemote)
# ---------------------------------------------------------------------------
_AUTH_IDENT = re.compile(
    r"(?:"
    # (1) merkle / proof membership / verified root
    r"verifymembership|verifynonmembership|verifypacket(?:commitment)?|"
    r"verifymerkle|merkleverify|calculateroot|getconsensusstate|verifyheight|"
    r"acceptableroot|provehash|verifyproof|checkproof|"
    # (2) signature / quorum / guardian verify
    r"verifysig|verifysignature|parseandverifyvm|verifyvm|verifyvaa|"
    r"ecrecover|checksig|_checksig|verifyquorum|verifyweightedsig|"
    r"validatesignatures|verifycommand|"
    # (3) replay / nonce / receipt idempotence
    r"setmessageexecuted|ismessageexecuted|messageexecuted|"
    r"packetreceipt|setpacketreceipt|getpacketreceipt|hasreceipt|getreceipt|"
    r"isexecuted|markexecuted|consumednonce|usednonce|"
    # (4) source-chain / trusted-remote binding
    r"getchain(?:byname|bynativeasset)?|chainbyname|isactivated(?:chain)?|"
    r"activatedchain|trustedremote|istrustedremote|verifysender|"
    r"isapprovedbygateway|approvecontractcall|iscontractcallapproved|"
    r"validatecontractcall|getcommandid|validateincoming|authenticate"
    r")",
    re.IGNORECASE,
)


def authenticity_pred(name: str) -> bool:
    """True iff the closure node NAME (a callee / hop fn / guard expr) is a
    cross-chain authenticity-binding node. Pure per-node predicate; the set /
    closure logic lives in the caller."""
    n = (name or "").strip()
    if not n:
        return False
    return bool(_AUTH_IDENT.search(n))


# a call-site token: `Ident(` inside a hop IR string.
_CALLRE = re.compile(r"([A-Za-z_][\w.$]*)\s*\(")


def _short_fn(fn: str) -> str:
    """Last identifier segment of a (possibly Go-receiver-qualified) fn id."""
    f = (fn or "").strip()
    if not f:
        return ""
    # strip a trailing SSA-closure suffix like $1
    core = f.split("(")[-1] if f.endswith(")") else f
    core = f
    seg = core.rstrip(")").split(".")[-1]
    return seg.strip()


def _contract_of(fn: str) -> str:
    """Best-effort enclosing type/contract for a fn id (Go receiver / dotted
    Solidity qualifier)."""
    f = (fn or "").strip()
    if not f:
        return ""
    m = re.search(r"([A-Za-z_]\w*)\)\.[A-Za-z_]", f)  # (*pkg.Type).Method
    if m:
        return m.group(1)
    parts = f.replace("(", "").replace(")", "").split(".")
    if len(parts) >= 2:
        return parts[-2]
    return ""


class _Unit:
    """One inbound cross-chain message-handler entrypoint, folding every dataflow
    path that shares its fn id."""

    __slots__ = ("fn", "lang", "file", "line", "inbound", "act_kinds",
                 "act_callees", "auth_nodes")

    def __init__(self, fn: str):
        self.fn = fn
        self.lang = ""
        self.file = ""
        self.line = 0
        self.inbound = False
        self.act_kinds: set[str] = set()
        self.act_callees: set[str] = set()
        self.auth_nodes: set[str] = set()


def _closure_nodes(rec: dict) -> list[str]:
    """Every node name reachable in this path's closure that could be an
    authenticity binding: the sink callee, each hop fn, each call-site parsed from
    a hop IR, and each guard-node expr."""
    out: list[str] = []
    sink = rec.get("sink") or {}
    out.append(sink.get("callee") or "")
    out.append(sink.get("fn") or "")
    for h in rec.get("hops") or []:
        if not isinstance(h, dict):
            continue
        out.append(h.get("fn") or "")
        ir = h.get("ir") or ""
        if ir:
            out.extend(_CALLRE.findall(ir))
    for g in rec.get("guard_nodes") or []:
        if isinstance(g, dict):
            out.append(g.get("expr") or "")
    return [o for o in out if o]


def build_units(dataflow_paths: list[Path],
                inbound_re: re.Pattern,
                act_kinds: set[str],
                warnings: list[str]) -> dict[str, _Unit]:
    """Fold every dataflow path record into per-ENTRYPOINT _Unit objects. The
    entrypoint key is the SOURCE fn id (the handler under analysis); every path
    sharing it is UNIONed - this is axis (c): a verifier in a sibling path still
    KEEPs the handler."""
    units: dict[str, _Unit] = {}
    seen_rows = 0
    for dfp in dataflow_paths:
        if not dfp.exists():
            warnings.append(f"dataflow absent: {dfp}")
            continue
        with dfp.open(encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if not line:
                    continue
                try:
                    rec = json.loads(line)
                except json.JSONDecodeError:
                    continue
                if not isinstance(rec, dict):
                    continue
                seen_rows += 1
                src = (rec.get("source") or {})
                fn = src.get("fn") or ""
                if not fn:
                    continue
                u = units.get(fn)
                if u is None:
                    u = _Unit(fn)
                    units[fn] = u
                if not u.lang:
                    u.lang = rec.get("language") or ""
                # locate the handler at its source decl for the citation.
                if not u.file and src.get("file"):
                    u.file = src.get("file")
                    u.line = int(src.get("line") or 0)
                short = _short_fn(fn)
                if inbound_re.search(short):
                    u.inbound = True
                sink = rec.get("sink") or {}
                if sink.get("kind") in act_kinds:
                    u.act_kinds.add(sink.get("kind"))
                    cal = sink.get("callee") or ""
                    if cal:
                        u.act_callees.add(_short_fn(cal))
                for node in _closure_nodes(rec):
                    if authenticity_pred(node):
                        u.auth_nodes.add(_short_fn(node)[:40] or node[:40])
    if seen_rows == 0:
        warnings.append("dataflow substrate empty (0 rows) - nothing to reason over")
    return units


def classify(units: dict[str, _Unit]) -> tuple[list[_Unit], list[_Unit], list[_Unit]]:
    """ACT = inbound handlers reaching a value/execute sink. VERIFIED = those whose
    closure reaches an authenticity node. survivors = ACT \\ VERIFIED; kept = the
    intersection (proves the subtraction is non-vacuous)."""
    act = [u for u in units.values() if u.inbound and u.act_kinds]
    survivors = [u for u in act if not u.auth_nodes]
    kept = [u for u in act if u.auth_nodes]
    # deterministic order
    survivors.sort(key=lambda u: u.fn)
    kept.sort(key=lambda u: u.fn)
    act.sort(key=lambda u: u.fn)
    return act, kept, survivors


_DEFAULT_INVARIANT_ID = "crosschain-inbound-message-authenticity-binding"


def make_obligation(u: _Unit, invariant_id: str) -> dict:
    short = _short_fn(u.fn)
    contract = _contract_of(u.fn)
    src_ref = u.file + (f":{u.line}" if u.line else "") if u.file else ""
    kinds = sorted(u.act_kinds)
    callees = sorted(u.act_callees)[:4]
    root = (
        f"Inbound cross-chain message handler '{u.fn}' acts on the inbound payload "
        f"through a value/execute sink ({', '.join(kinds)}"
        + (f" via {', '.join(callees)}" if callees else "")
        + ") but its call closure reaches NO authenticity-binding node - no "
        "verified merkle root / proof-membership, no signature/quorum verify, no "
        "replay/nonce/receipt idempotence guard, and no source-chain / trusted-"
        "remote binding (set-difference ACT\\VERIFIED). Nomad acceptableRoot[0]==true "
        "/ Wormhole unverified-VAA class: an attacker forges or replays an inbound "
        "message and the handler mints / releases / executes on it."
    )
    return {
        "schema": "auditooor.crosschain_message_authenticity.v1",
        "obligation_type": "crosschain-message-forgery",
        "contract": contract,
        "function": short,
        "function_signature": u.fn,
        "language": u.lang,
        "source_refs": [src_ref] if src_ref else [],
        "file": u.file,
        "line": u.line,
        "act_sink_kinds": kinds,
        "act_sink_callees": callees,
        "attack_class": "crosschain-inbound-message-forgery-no-authenticity-binding",
        # a permissionless relayer can submit an inbound message => high-priority.
        "permissionless": True,
        "priority_rank": 0,
        "likely_severity": "critical",
        "broken_invariant_ids": [invariant_id],
        "root_cause_hypothesis": root,
        "quality_gate_status": "needs_source",
        "proof_status": "needs_source",
        "advisory_only": True,
        "learning_route": "mine-source",
        "falsification_requirements": [
            "AUTH_CLOSURE: prove NO authenticity-binding node (verified root / "
            "signature / nonce-receipt / source-chain lookup) is reachable in the "
            "closure of this handler - a verifier N hops away OR in a sibling "
            "dataflow path (e.g. IBC core proof verification upstream of "
            "OnRecvPacket) KILLS the lead.",
            "PAYLOAD_BINDING: confirm the acted quantity/target is DERIVED FROM the "
            "inbound message payload (not a locally-fixed constant), so forging the "
            "message controls the mint/release/execute.",
            "FORGERY_SEQUENCE: show a permissionless actor can submit an inbound "
            "message with an attacker-chosen payload that the handler accepts "
            "(default-trusted root / missing sig-check / replayable nonce).",
        ],
        "next_command": (
            "python3 tools/crosschain-message-authenticity-reasoner.py "
            f"--workspace <ws>  # then mine {src_ref or short}"
        )[:200],
    }


def run(argv=None) -> dict:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--workspace", required=True)
    ap.add_argument("--dataflow", default=None,
                    help="override the primary dataflow_paths.jsonl path")
    ap.add_argument("--act-kinds", default=None,
                    help="comma sink kinds counted as value/execute ACT "
                         "(default mint,value-move,burn,safeTransfer,authority,execute)")
    ap.add_argument("--inbound-extra", default=None,
                    help="comma extra inbound-handler short-name regex alternatives")
    ap.add_argument("--invariant-id", default=_DEFAULT_INVARIANT_ID)
    ap.add_argument("--emit", default=None,
                    help="output jsonl path (default "
                         "<ws>/.auditooor/crosschain_forgery_obligations.jsonl)")
    ap.add_argument("--json", action="store_true")
    ap.add_argument("--fail-closed", action="store_true",
                    help="exit non-zero if the dataflow substrate is absent/empty")
    args = ap.parse_args(argv)

    ws = Path(args.workspace).expanduser().resolve()
    warnings: list[str] = []

    # Resolve the dataflow substrate: the primary jsonl + every scoped sidecar
    # dataflow_paths.*.jsonl (auto-union, e.g. dataflow_paths.nexus.jsonl).
    paths: list[Path] = []
    if args.dataflow:
        paths.append(Path(args.dataflow).expanduser())
    else:
        primary = ws / ".auditooor" / "dataflow_paths.jsonl"
        if primary.exists():
            paths.append(primary)
        ad = ws / ".auditooor"
        if ad.is_dir():
            for sib in sorted(ad.glob("dataflow_paths.*.jsonl")):
                paths.append(sib)
    if not paths:
        warnings.append("no dataflow_paths substrate found under "
                        f"{ws / '.auditooor'}")

    act_kinds = (set(k.strip() for k in args.act_kinds.split(",") if k.strip())
                 if args.act_kinds else set(_DEFAULT_ACT_KINDS))

    inbound_re = _DEFAULT_INBOUND
    if args.inbound_extra:
        extra = "|".join(x.strip() for x in args.inbound_extra.split(",") if x.strip())
        if extra:
            inbound_re = re.compile(
                _DEFAULT_INBOUND.pattern[:-2] + "|" + extra + ")$", re.IGNORECASE)

    units = build_units(paths, inbound_re, act_kinds, warnings)
    act, kept, survivors = classify(units)

    emit = Path(args.emit).expanduser() if args.emit else \
        ws / ".auditooor" / "crosschain_forgery_obligations.jsonl"
    emit.parent.mkdir(parents=True, exist_ok=True)
    obligations = [make_obligation(u, args.invariant_id) for u in survivors]
    with emit.open("w", encoding="utf-8") as fh:
        for ob in obligations:
            fh.write(json.dumps(ob) + "\n")

    summary = {
        "schema": "auditooor.crosschain_message_authenticity.summary.v1",
        "workspace": str(ws),
        "dataflow_paths": [str(p) for p in paths],
        "act_kinds": sorted(act_kinds),
        "counts": {
            "inbound_handlers": sum(1 for u in units.values() if u.inbound),
            "ACT": len(act),
            "VERIFIED_kept": len(kept),
            "survivors_ACT_minus_VERIFIED": len(survivors),
        },
        "kept": [
            {"fn": u.fn, "act": sorted(u.act_kinds),
             "auth_nodes": sorted(u.auth_nodes)[:4]}
            for u in kept[:20]
        ],
        "survivors": [
            {"fn": u.fn, "act": sorted(u.act_kinds),
             "src": (u.file + (f":{u.line}" if u.line else "")) if u.file else ""}
            for u in survivors[:40]
        ],
        "emit": str(emit),
        "warnings": warnings,
        "generated_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
    }

    if args.json:
        print(json.dumps(summary, indent=2))
    else:
        c = summary["counts"]
        print(f"[crosschain-forgery] |inbound|={c['inbound_handlers']} "
              f"|ACT|={c['ACT']} |VERIFIED|={c['VERIFIED_kept']} "
              f"|ACT\\VERIFIED|={c['survivors_ACT_minus_VERIFIED']} -> {emit}")
        for u in kept[:8]:
            print(f"  KEPT     {_short_fn(u.fn)}  act={sorted(u.act_kinds)} "
                  f"auth={sorted(u.auth_nodes)[:3]}")
        for u in survivors[:20]:
            print(f"  SURVIVOR {_short_fn(u.fn)}  act={sorted(u.act_kinds)}  "
                  f"{(u.file + ':' + str(u.line)) if u.file else ''}")
        for w in warnings:
            print(f"  WARN {w}", file=sys.stderr)

    if args.fail_closed and (not paths or
                             all("empty" in w or "absent" in w for w in warnings)
                             and warnings):
        # only fail on a genuinely absent/empty substrate, never on a clean 0.
        substrate_dead = (not paths) or any(
            "empty (0 rows)" in w for w in warnings)
        if substrate_dead:
            print("[crosschain-forgery] FAIL-CLOSED: dataflow substrate "
                  "absent/empty", file=sys.stderr)
            sys.exit(3)

    return summary


if __name__ == "__main__":
    run()
