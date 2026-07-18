#!/usr/bin/env python3
"""go-protocol-invariant.py - the IBC / cross-chain protocol STATE-MACHINE
invariant set-difference query (replay / out-of-order / cross-channel confusion /
double-process class).

LOGIC CAPABILITY (docs/LOGIC_ARSENAL_ROADMAP.md, protocol state-machine class).
This is a SET-DIFFERENCE over the OWNED go-ssa dataflow-closure backend, NOT a
grep for the words 'sequence' / 'nonce'.

DISTINCT FROM crosschain-message-authenticity-reasoner.py
  authenticity  = the message is who it claims (MISSING signature / merkle / proof
                  verify).  THIS query assumes the message is authentic and asks a
                  DIFFERENT question: is the protocol STATE MACHINE respected -
                  monotonic sequence advance, source (chain+channel) binding, and
                  once-only idempotent consume.  A perfectly-signed IBC packet that
                  is replayed, delivered out-of-order, or consumed twice STILL
                  drains escrow / diverges consensus even though every signature
                  verified.  These two live in orthogonal invariant families and are
                  emitted as separate obligation classes.

THE LOGIC TRIPLE (extracted from IBC ordered-channel replay / packet-receipt-absence
and Axelar SetMessageExecuted double-process post-mortems)
  ASSUMPTION (that the class falsifies):
    an inbound protocol message keyed on a (src-chain, channel/port, sequence)
    tuple, once its handler runs a credit/mint/execute sink, has already been
    checked against the protocol state machine: its sequence advances monotonically,
    it is bound to the source chain+channel it claims, and it can be consumed at
    most once.
  INVARIANT the protocol state machine must uphold, per handler h:
    REQUIRED_PROTOCOL_INVARIANTS(h) = { MONOTONIC_SEQUENCE, SOURCE_BINDING,
                                        ONCE_ONLY_CONSUME }
    ENFORCED_ON_PATH(h) = { family F : some node in h's forward/backward closure
                            (sink callee / hop fn / call parsed from hop IR / guard
                            expr) satisfies family F's node predicate }
    The state-machine trust boundary requires
       REQUIRED_PROTOCOL_INVARIANTS(h)  is a SUBSET of  ENFORCED_ON_PATH(h).
  TRUST-BOUNDARY that breaks:
    every handler h whose SET-DIFFERENCE
       missing(h) = REQUIRED_PROTOCOL_INVARIANTS(h) \\ ENFORCED_ON_PATH(h)
    is NON-EMPTY processes a protocol message that CAN be replayed (no once-only),
    delivered out-of-order (no monotonic sequence), or accepted from the wrong
    channel (no source binding) -> replay drain / out-of-order execution /
    cross-channel confusion / double-process -> fund loss or consensus divergence.
    Emitted as a `go-protocol-state-machine-invariant-violation` obligation.

WHY THIS IS LOGIC, NOT A SHAPE (guard-rail satisfied)
  It is NOT `body_contains('sequence')`. It is a set-difference of INVARIANT
  FAMILIES over the transitive dataflow closure:
    (a) family membership is TRANSITIVE closure reachability - a receipt-absence
        check reached through an N-hop keeper helper (or a sibling core hop that
        runs before OnRecvPacket) correctly places the handler's ONCE_ONLY family in
        ENFORCED; a body-scoped regex cannot see past the immediate function body;
    (b) the finding is the SET-DIFFERENCE of two FAMILY sets per handler
        (REQUIRED \\ ENFORCED), reported per missing family - not a boolean over one
        function's text;
    (c) an enforcement node need NOT co-occur in the handler body: each family is
        UNIONed across EVERY dataflow-path record that shares the same entrypoint,
        so a sequence check that lives in one path while the credit sink lives in
        another still credits the MONOTONIC_SEQUENCE family - impossible for any
        token-adjacency regex.

BACKEND (owned)
  <ws>/.auditooor/dataflow_paths.jsonl (schema dataflow_path.v1) + every scoped
  sidecar <ws>/.auditooor/dataflow_paths.*.jsonl (auto-union, e.g.
  dataflow_paths.nexus.jsonl), produced by the go-ssa dataflow engine. Each record
  binds a param/local SOURCE to a classified SINK (sink.kind), carries the closure
  HOPS (hop.ir call-sites + hop.fn callees) and closure GUARD nodes
  (guard_nodes[].expr).

OUTPUT
  <ws>/.auditooor/go_protocol_invariant_obligations.jsonl - one row per survivor,
  schema `auditooor.go_protocol_invariant.v1`, exploit_queue-ingest compatible
  (contract/function/source_refs/root_cause_hypothesis/attack_class/
  broken_invariant_ids/quality_gate_status='needs_source'). A summary is printed /
  emitted (--json) with |protocol handlers|, |required-invariants|, |enforced|,
  |survivors|, KEPT (handlers enforcing all three families, proving the subtraction
  is non-vacuous), and the survivors with their missing families + file:line.

HONESTY
  cited-empty  = substrate present, 0 survivors -> honest clean 0.
  substrate_vacuous = no protocol handler ever reached (no IBC/cross-chain surface)
                      -> N/A, NOT a clean 0. --fail-closed exits non-zero only on a
                      genuinely absent/empty dataflow substrate.
  Every survivor is advisory_only + quality_gate_status='needs_source': a lead to
  mine at source, never a filed finding.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
import time
from pathlib import Path

_HERE = Path(__file__).resolve().parent
_REPO_ROOT = _HERE.parent


# ---------------------------------------------------------------------------
# PROC sink taxonomy - the sinks through which an inbound protocol message is
# actually PROCESSED (credit / mint / release / burn / execute an authority op /
# record-consume via a protocol state-write). A protocol handler that never reaches
# one of these does not "process" the message in a fund/consensus-affecting way, so
# it is not in the ACT/protocol-handler set. `state-write` IS included here (unlike
# the authenticity reasoner): recording a packet as received / advancing a sequence
# IS the protocol-processing action whose ordering/idempotency we reason over.
# Re-scope with --proc-kinds.
# ---------------------------------------------------------------------------
_DEFAULT_PROC_KINDS = {"mint", "value-move", "burn", "safeTransfer", "authority",
                       "execute", "state-write"}


# ---------------------------------------------------------------------------
# INBOUND protocol-message-handler ENTRYPOINT surface. Entrypoint SELECTION (the
# set-difference is the logic, not this name set). Matches the inbound
# protocol-message / packet-processing conventions across the Go/Cosmos stacks in
# scope. Matched against the SHORT (last-segment) fn name, case-insensitively.
#   * IBC core:      OnRecvPacket / RecvPacket / recvPacket / OnAcknowledgementPacket
#                    / AcknowledgePacket / OnTimeoutPacket / TimeoutPacket /
#                    WriteAcknowledgement / OnRecvAsync
#   * Axelar nexus:  RouteMessage / ExecuteMessage / SetNewMessage /
#                    SetMessageExecuted / HandleGeneralMessage / RouteIBCTransfers
#   * generic relay: handleMessage / processMessage / handlePacket / deliver /
#                    relayMessage / consumeMessage
# ---------------------------------------------------------------------------
_DEFAULT_INBOUND = re.compile(
    r"^(?:"
    r"onrecvpacket|onrecv(?:async)?|recvpacket|"
    r"onacknowledgementpacket|acknowledgepacket|onacknowledge(?:packet)?|"
    r"ontimeoutpacket|timeoutpacket|ontimeout(?:onclose)?|"
    r"writeacknowledgement|"
    r"routemessage|executemessage|handlegeneralmessage|handlemessage|_handlemessage|"
    r"setnewmessage|setmessageexecuted|routeibctransfers|"
    r"receivemessage|processmessage|handlepacket|deliver(?:message|packet)?|"
    r"relaymessage|consumemessage|processpacket|processreceived"
    r")$",
    re.IGNORECASE,
)


# ---------------------------------------------------------------------------
# The three REQUIRED protocol state-machine invariant FAMILIES, each a per-node
# predicate over a single closure node (callee / hop fn / guard expr). The LOGIC is
# the per-family transitive-closure set-difference wrapped around these predicates.
# ---------------------------------------------------------------------------

# (1) MONOTONIC_SEQUENCE - the message sequence advances by exactly one / is
# checked against the expected next sequence; ordered-channel replay and
# out-of-order delivery are the impacts of its absence.
_SEQ_IDENT = re.compile(
    r"(?:"
    r"nextsequence(?:recv|send|ack)?|getnextsequence(?:recv|send|ack)?|"
    r"setnextsequence(?:recv|send|ack)?|"
    r"recvstartsequence|setrecvstartsequence|getrecvstartsequence|"
    r"verifynextsequence|expectedsequence|sequencecheck|checksequence|"
    r"packetsequence|orderedchannel|assertsequence"
    r")",
    re.IGNORECASE,
)

# (2) SOURCE_BINDING - the message is bound to the source chain + channel/port it
# claims; its absence is cross-channel confusion (a packet accepted as if from a
# different, trusted channel).
_SRC_IDENT = re.compile(
    r"(?:"
    r"getchannel|channelkeeper|verifychannel|assertchannel|"
    r"sourcechannel|destinationchannel|sourceport|destinationport|"
    r"getconnection|verifyconnection|connectionhops|"
    r"getchain(?:byname|bynativeasset)?|chainbyname|"
    r"validatechannel|matchchannel|bindport|authenticatecapability|"
    r"getcapability|lookupmodulebychannel"
    r")",
    re.IGNORECASE,
)

# (3) ONCE_ONLY_CONSUME - the message can be consumed at most once (packet-receipt
# presence/absence, commitment delete, executed-flag); its absence is replay /
# double-process.
_ONCE_IDENT = re.compile(
    r"(?:"
    r"packetreceipt|setpacketreceipt|getpacketreceipt|verifypacketreceiptabsence|"
    r"hasreceipt|getreceipt|setpacketacknowledgement|getpacketacknowledgement|"
    r"deletepacketcommitment|packetcommitment|getpacketcommitment|"
    r"ismessageexecuted|setmessageexecuted|messageexecuted|markexecuted|isexecuted|"
    r"timeoutexecuted|alreadyrelayed|consumednonce|usednonce|nonceused|"
    r"deletepacket|removepacket"
    r")",
    re.IGNORECASE,
)

_FAMILIES = (
    ("MONOTONIC_SEQUENCE", _SEQ_IDENT),
    ("SOURCE_BINDING", _SRC_IDENT),
    ("ONCE_ONLY_CONSUME", _ONCE_IDENT),
)
_REQUIRED = {name for name, _ in _FAMILIES}


def enforced_families(name: str) -> set[str]:
    """Return the set of protocol-invariant families a single closure NODE (a
    callee / hop fn / guard expr) enforces. Pure per-node predicate; the set /
    closure logic lives in the caller."""
    n = (name or "").strip()
    if not n:
        return set()
    out: set[str] = set()
    for fam, rx in _FAMILIES:
        if rx.search(n):
            out.add(fam)
    return out


# a call-site token: `Ident(` inside a hop IR string.
_CALLRE = re.compile(r"([A-Za-z_][\w.$]*)\s*\(")


def _short_fn(fn: str) -> str:
    """Last identifier segment of a (possibly Go-receiver-qualified) fn id."""
    f = (fn or "").strip()
    if not f:
        return ""
    seg = f.rstrip(")").split(".")[-1]
    return seg.strip()


def _contract_of(fn: str) -> str:
    """Best-effort enclosing type/contract for a fn id (Go receiver)."""
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
    """One inbound protocol-message handler entrypoint, folding every dataflow path
    that shares its fn id."""

    __slots__ = ("fn", "lang", "file", "line", "inbound", "proc_kinds",
                 "proc_callees", "enforced", "enf_nodes")

    def __init__(self, fn: str):
        self.fn = fn
        self.lang = ""
        self.file = ""
        self.line = 0
        self.inbound = False
        self.proc_kinds: set[str] = set()
        self.proc_callees: set[str] = set()
        self.enforced: set[str] = set()          # families enforced on path
        self.enf_nodes: dict[str, str] = {}       # family -> a witness node name


def _closure_nodes(rec: dict) -> list[str]:
    """Every node name reachable in this path's closure: the sink callee/fn, each
    hop fn, each call-site parsed from a hop IR, and each guard-node expr."""
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
                proc_kinds: set[str],
                warnings: list[str]) -> tuple[dict[str, _Unit], int]:
    """Fold every dataflow path record into per-ENTRYPOINT _Unit objects. The
    entrypoint key is the SOURCE fn id; every path sharing it is UNIONed (axis (c):
    an enforcement node in a sibling path still credits its family)."""
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
                if not u.file and src.get("file"):
                    u.file = src.get("file")
                    u.line = int(src.get("line") or 0)
                short = _short_fn(fn)
                if inbound_re.search(short):
                    u.inbound = True
                sink = rec.get("sink") or {}
                if sink.get("kind") in proc_kinds:
                    u.proc_kinds.add(sink.get("kind"))
                    cal = sink.get("callee") or ""
                    if cal:
                        u.proc_callees.add(_short_fn(cal))
                for node in _closure_nodes(rec):
                    fams = enforced_families(node)
                    for fam in fams:
                        u.enforced.add(fam)
                        u.enf_nodes.setdefault(fam, _short_fn(node)[:40] or node[:40])
    if seen_rows == 0:
        warnings.append("dataflow substrate empty (0 rows) - nothing to reason over")
    return units, seen_rows


def classify(units: dict[str, _Unit]):
    """protocol_handlers = inbound handlers reaching a proc sink. For each, missing
    = REQUIRED \\ ENFORCED. survivors = handlers with a non-empty missing set; kept =
    those enforcing all three families (proves the subtraction is non-vacuous)."""
    handlers = [u for u in units.values() if u.inbound and u.proc_kinds]
    survivors = [u for u in handlers if (_REQUIRED - u.enforced)]
    kept = [u for u in handlers if not (_REQUIRED - u.enforced)]
    survivors.sort(key=lambda u: u.fn)
    kept.sort(key=lambda u: u.fn)
    handlers.sort(key=lambda u: u.fn)
    return handlers, kept, survivors


_DEFAULT_INVARIANT_ID = "go-protocol-message-state-machine-invariant"

# per-family impact narration for the obligation root-cause.
_FAM_IMPACT = {
    "MONOTONIC_SEQUENCE": ("no monotonic-sequence-advance check (ordered-channel "
                           "out-of-order delivery / replay of a prior sequence)"),
    "SOURCE_BINDING": ("no source chain+channel/port binding (cross-channel "
                       "confusion: a packet accepted as if from a trusted channel)"),
    "ONCE_ONLY_CONSUME": ("no once-only-consume guard - packet-receipt / commitment "
                          "/ executed-flag (replay / double-process of the message)"),
}


def make_obligation(u: _Unit, invariant_id: str) -> dict:
    short = _short_fn(u.fn)
    contract = _contract_of(u.fn)
    src_ref = u.file + (f":{u.line}" if u.line else "") if u.file else ""
    missing = sorted(_REQUIRED - u.enforced)
    kinds = sorted(u.proc_kinds)
    callees = sorted(u.proc_callees)[:4]
    miss_txt = "; ".join(_FAM_IMPACT.get(m, m) for m in missing)
    enf_txt = ", ".join(f"{k}<-{v}" for k, v in sorted(u.enf_nodes.items())) or "none"
    root = (
        f"Inbound protocol-message handler '{u.fn}' processes the inbound message "
        f"through a sink ({', '.join(kinds)}"
        + (f" via {', '.join(callees)}" if callees else "")
        + ") keyed on a (src-chain, channel/port, sequence) tuple, but its call "
        f"closure FAILS to enforce {len(missing)} required protocol state-machine "
        f"invariant(s): {miss_txt}. Set-difference REQUIRED\\ENFORCED "
        f"(enforced: {enf_txt}). An authentic-but-mis-sequenced / replayed / "
        "wrong-channel message reaches the processing sink -> replay drain, "
        "out-of-order execution, cross-channel confusion, or double-process -> fund "
        "loss / consensus divergence."
    )
    return {
        "schema": "auditooor.go_protocol_invariant.v1",
        "obligation_type": "go-protocol-state-machine-invariant-violation",
        "contract": contract,
        "function": short,
        "function_signature": u.fn,
        "language": u.lang,
        "source_refs": [src_ref] if src_ref else [],
        "file": u.file,
        "line": u.line,
        "proc_sink_kinds": kinds,
        "proc_sink_callees": callees,
        "required_invariants": sorted(_REQUIRED),
        "enforced_invariants": sorted(u.enforced),
        "missing_invariants": missing,
        "enforcement_witnesses": dict(sorted(u.enf_nodes.items())),
        "attack_class": "go-protocol-message-state-machine-invariant-violation",
        "permissionless": True,
        "priority_rank": 0,
        "likely_severity": "critical",
        "broken_invariant_ids": [invariant_id] +
                                [f"{invariant_id}:{m}" for m in missing],
        "root_cause_hypothesis": root,
        "quality_gate_status": "needs_source",
        "proof_status": "needs_source",
        "advisory_only": True,
        "learning_route": "mine-source",
        "falsification_requirements": [
            "ENFORCEMENT_CLOSURE: for EACH missing family, prove NO enforcing node "
            "(monotonic-sequence check / source chain+channel binding / "
            "once-only receipt-commitment-executed guard) is reachable in this "
            "handler's closure - an ordered-channel sequence check or a "
            "VerifyPacketReceiptAbsence run by IBC core BEFORE OnRecvPacket, or in a "
            "sibling dataflow path, KILLS the corresponding family.",
            "PROTOCOL_KEYING: confirm the processed quantity/target is keyed on the "
            "inbound (src-chain, channel, sequence) tuple, so mis-sequencing / "
            "replaying / re-channeling the message changes what is credited.",
            "EXPLOIT_SEQUENCE: show a permissionless relayer can submit a "
            "state-machine-violating message (replayed sequence / out-of-order / "
            "wrong channel) that the handler processes to fund-loss or consensus "
            "divergence.",
        ],
        "next_command": (
            "python3 tools/go-protocol-invariant.py "
            f"--workspace <ws>  # then mine {src_ref or short}"
        )[:200],
    }


def run(argv=None) -> dict:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--workspace", required=True)
    ap.add_argument("--src-root", default=None,
                    help="source root for citation display (informational; the "
                         "substrate is the dataflow jsonl)")
    ap.add_argument("--dataflow", default=None,
                    help="override the primary dataflow_paths.jsonl path")
    ap.add_argument("--proc-kinds", default=None,
                    help="comma sink kinds counted as protocol-processing (default "
                         "mint,value-move,burn,safeTransfer,authority,execute,"
                         "state-write)")
    ap.add_argument("--inbound-extra", default=None,
                    help="comma extra inbound-handler short-name regex alternatives")
    ap.add_argument("--invariant-id", default=_DEFAULT_INVARIANT_ID)
    ap.add_argument("--emit", default=None,
                    help="output jsonl path (default "
                         "<ws>/.auditooor/go_protocol_invariant_obligations.jsonl)")
    ap.add_argument("--json", action="store_true")
    ap.add_argument("--fail-closed", action="store_true",
                    help="exit non-zero if the dataflow substrate is absent/empty")
    args = ap.parse_args(argv)

    ws = Path(args.workspace).expanduser().resolve()
    warnings: list[str] = []

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

    proc_kinds = (set(k.strip() for k in args.proc_kinds.split(",") if k.strip())
                  if args.proc_kinds else set(_DEFAULT_PROC_KINDS))

    inbound_re = _DEFAULT_INBOUND
    if args.inbound_extra:
        extra = "|".join(x.strip() for x in args.inbound_extra.split(",") if x.strip())
        if extra:
            inbound_re = re.compile(
                _DEFAULT_INBOUND.pattern[:-2] + "|" + extra + ")$", re.IGNORECASE)

    units, seen_rows = build_units(paths, inbound_re, proc_kinds, warnings)
    handlers, kept, survivors = classify(units)

    # honesty classification
    if seen_rows == 0 or not paths:
        substrate_status = "substrate_absent"
    elif not handlers:
        substrate_status = "substrate_vacuous"   # no protocol handler reached -> N/A
    elif not survivors:
        substrate_status = "cited_empty"          # honest clean 0
    else:
        substrate_status = "survivors_present"

    emit = Path(args.emit).expanduser() if args.emit else \
        ws / ".auditooor" / "go_protocol_invariant_obligations.jsonl"
    emit.parent.mkdir(parents=True, exist_ok=True)
    obligations = [make_obligation(u, args.invariant_id) for u in survivors]
    with emit.open("w", encoding="utf-8") as fh:
        for ob in obligations:
            fh.write(json.dumps(ob) + "\n")

    # |required-invariants| = sum over handlers of |REQUIRED| (3 each);
    # |enforced| = sum over handlers of |ENFORCED_ON_PATH|.
    req_total = len(handlers) * len(_REQUIRED)
    enf_total = sum(len(u.enforced) for u in handlers)

    summary = {
        "schema": "auditooor.go_protocol_invariant.summary.v1",
        "workspace": str(ws),
        "src_root": args.src_root or "",
        "dataflow_paths": [str(p) for p in paths],
        "proc_kinds": sorted(proc_kinds),
        "required_families": sorted(_REQUIRED),
        "substrate_status": substrate_status,
        "counts": {
            "protocol_handlers": len(handlers),
            "required_invariants": req_total,
            "enforced_invariants": enf_total,
            "survivors": len(survivors),
            "KEPT": len(kept),
        },
        "kept": [
            {"fn": u.fn, "proc": sorted(u.proc_kinds),
             "enforced": sorted(u.enforced),
             "witnesses": dict(sorted(u.enf_nodes.items()))}
            for u in kept[:20]
        ],
        "survivors": [
            {"fn": u.fn, "proc": sorted(u.proc_kinds),
             "missing": sorted(_REQUIRED - u.enforced),
             "enforced": sorted(u.enforced),
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
        print(f"[go-protocol-invariant] status={substrate_status} "
              f"|handlers|={c['protocol_handlers']} "
              f"|required|={c['required_invariants']} "
              f"|enforced|={c['enforced_invariants']} "
              f"|survivors|={c['survivors']} KEPT={c['KEPT']} -> {emit}")
        for u in kept[:8]:
            print(f"  KEPT     {_short_fn(u.fn)}  enforced={sorted(u.enforced)}")
        for u in survivors[:20]:
            print(f"  SURVIVOR {_short_fn(u.fn)}  missing={sorted(_REQUIRED - u.enforced)}"
                  f"  {(u.file + ':' + str(u.line)) if u.file else ''}")
        for w in warnings:
            print(f"  WARN {w}", file=sys.stderr)

    if args.fail_closed and substrate_status in ("substrate_absent",):
        print("[go-protocol-invariant] FAIL-CLOSED: dataflow substrate absent/empty",
              file=sys.stderr)
        sys.exit(3)

    return summary


if __name__ == "__main__":
    run()
