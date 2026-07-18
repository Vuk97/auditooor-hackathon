#!/usr/bin/env python3
"""go-mpc-coordination.py - the Go ORCHESTRATION-side threshold-signature
coordination reasoner (axelar-core vald + x/tss + x/multisig).

CORPUS ANCHOR
  The corpus-mine flagged the `mpc.*` CRITICAL cluster as an axelar blind-spot.
  tofnd/tofn does the ECDSA/EdDSA crypto, but the Go side COORDINATES the
  threshold-signature ceremony - session start, signer-set selection, threshold
  check, key rotation, vote tallying. A coordination bug is a full threshold-sig
  CRITICAL (forgery / lockout / nonce-reuse key-leak) even though the curve math
  is correct. This reasoner hunts THREE coordination bugs, each a set-difference
  over the OWNED Go callgraph closure, NOT a grep.

THE REASONING QUERY (per arm)
  For each coordination entrypoint `p` (a rotation / threshold-accept / session-
  start path) build its forward CALLGRAPH CLOSURE. Then:
      SURVIVOR(p)  iff  REQUIRED_COUPLED_ACTION(p)  \\  PRESENT_ON_PATH(p)  != {}
  i.e. the coordination path is MISSING the coupled action the threshold-sig
  ceremony requires. The finding is the SET-DIFFERENCE, not a boolean over one
  function body.

  ARM A - SIGNER-SET-ROTATION-WITHOUT-RESHARING
    ACT       = rotation entrypoints (rotate / assign / activate the active key
                / validator signer set) that WRITE the active-key/epoch state.
    REQUIRED  = the closure must reach a RESHARING / KEYGEN trigger - a new
                keygen session for the rotated-to signer set (so the secret
                shares actually match the new set).
    SURVIVOR  = rotation writes the active set but never triggers a keygen /
                reshare -> old shares stay valid OR new signers hold no share ->
                forgery (stale quorum still signs) or lockout (new set cannot
                sign).

  ARM B - THRESHOLD-CHECK-AGAINST-ACTIVE-SET-ONLY
    ACT       = signature/vote ACCEPTANCE entrypoints whose closure reaches a
                THRESHOLD check (meets/below/getThreshold).
    REQUIRED  = the closure must also reach a PRODUCED-SET binding - the snapshot
                / key that PRODUCED the shares (keyed by keyID), so the threshold
                is measured against the set that generated the secret, not the
                mutable current active set.
    SURVIVOR  = threshold is checked but bound to the CURRENT active set only ->
                a shrunk / rotated set lets a sub-threshold coalition forge.

  ARM C - NONCE / SESSION REUSE
    ACT       = session-start entrypoints (start keygen / start signing / create
                session) keyed by a session-id / key-id / nonce.
    REQUIRED  = the closure must reach a PER-SESSION FRESHNESS consume - a
                duplicate/existence guard on the id (getSession..ok / hasSession
                / sessionExists / delete/consume) so the id cannot be reused.
    SURVIVOR  = a session id / nonce / key-id is (re)used with no freshness guard
                -> replay / nonce-reuse -> ECDSA k-reuse private-key leak.

WHY THIS IS LOGIC, NOT A GREP (guard-rail)
  Each arm is a required-coupled-action SET-DIFFERENCE over the transitive
  callgraph CLOSURE, on three axes a `grep rotate|threshold|nonce` cannot see:
    (a) membership is TRANSITIVE - the coupled action (keygen trigger / produced-
        set binding / freshness consume) may live N hops away through a helper
        (msgServer.RotateKey -> Keeper.RotateKey -> ...); a body regex sees only
        the immediate body.
    (b) the finding is a RELATION between the REQUIRED-action set and the
        PRESENT-on-path set, whose answer is the set-difference, not a token hit.
    (c) the coupled action need NOT co-occur syntactically with the trigger - it
        is UNIONed across the WHOLE closure, so a reshare reached via one callee
        while the state-write lives in another still KEEPS the path.

SUBSTRATE (owned)
  The Go SOURCE tree under --src-root (a real, if lightweight, callgraph built
  here: top-level funcs -> called idents -> transitive forward closure). Codegen
  (.pb.go/.pb.gw.go), _test.go and mock/testutils dirs are excluded. This is the
  Go orchestration side the dataflow engine under-emits for (the nexus sidecar
  covers x/nexus, not x/tss / x/multisig / vald).

OUTPUT
  <ws>/.auditooor/go_mpc_coordination_obligations.jsonl - one row per SURVIVOR,
  schema `auditooor.go_mpc_coordination.v1`, exploit_queue-ingest compatible
  (contract/function/source_refs/root_cause_hypothesis/attack_class/
  broken_invariant_ids/quality_gate_status='needs_source'/advisory_only). A
  summary is printed / emitted (--json) with, per arm, |ACT| paths, the REQUIRED
  action, the survivors and the KEPT (proving the subtraction is non-vacuous).

HONESTY
  * substrate_vacuous : src-root missing / 0 Go funcs parsed / 0 coordination
    entrypoints matched across all arms - nothing to reason over (advisory).
  * cited-empty       : entrypoints matched but 0 survivors - an honest clean 0.
  Every survivor is advisory (`needs_source`): a coordination path can be coupled
  through a runtime dispatch / interface the static callgraph cannot resolve, so
  each row demands source confirmation before filing.
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

# --------------------------------------------------------------------------
# Go source parsing - a lightweight forward callgraph.
# --------------------------------------------------------------------------
_SKIP_DIR = re.compile(r"(?:^|/)(?:mock|mocks|testutils|testutil|test)(?:/|$)")
_SKIP_FILE = re.compile(r"(?:_test\.go|\.pb\.go|\.pb\.gw\.go|\.gen\.go)$")

# `func (recv Recv) Name(` or `func Name(`
_FUNC_RE = re.compile(
    r"^func\s*(?:\(\s*[\w*]+\s+([\w.*\[\]]+)\s*\)\s*)?([A-Za-z_]\w*)\s*[\(\[]",
    re.MULTILINE,
)
# a called ident: `Ident(` or `.Method(`
_CALL_RE = re.compile(r"(?:\.|\b)([A-Za-z_]\w*)\s*\(")


def _iter_go_files(root: Path):
    for p in root.rglob("*.go"):
        rel = str(p)
        if _SKIP_FILE.search(rel):
            continue
        if _SKIP_DIR.search(rel):
            continue
        yield p


def _balance_body(text: str, open_idx: int) -> str:
    """Return the brace-balanced body starting at the first '{' at/after
    open_idx (inclusive of braces). Best-effort; ignores braces in strings only
    coarsely."""
    i = text.find("{", open_idx)
    if i < 0:
        return ""
    depth = 0
    j = i
    n = len(text)
    while j < n:
        c = text[j]
        if c == "{":
            depth += 1
        elif c == "}":
            depth -= 1
            if depth == 0:
                return text[i:j + 1]
        j += 1
    return text[i:]


class _Func:
    __slots__ = ("name", "recv", "file", "line", "callees")

    def __init__(self, name, recv, file, line):
        self.name = name          # short name, lowercased for matching
        self.recv = recv          # receiver type (best-effort)
        self.file = file
        self.line = line
        self.callees = set()      # short callee names, lowercased


def parse_go_callgraph(root: Path, warnings: list) -> dict:
    """name(lower) -> list[_Func]. A function name can have several defs; we key
    on the short name for closure resolution (Go receiver-overloading is folded,
    which only ever ENLARGES a closure - conservative for a set-difference that
    KEEPS a path when the coupled action is present)."""
    by_name: dict[str, list] = {}
    total = 0
    for gf in _iter_go_files(root):
        try:
            text = gf.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        for m in _FUNC_RE.finditer(text):
            recv = (m.group(1) or "").lstrip("*").split(".")[-1]
            name = m.group(2)
            line = text.count("\n", 0, m.start()) + 1
            body = _balance_body(text, m.end())
            fn = _Func(name.lower(), recv, str(gf), line)
            for cm in _CALL_RE.finditer(body):
                cal = cm.group(1).lower()
                if cal in ("if", "for", "switch", "return", "func", "go", "defer",
                           "range", "select", "make", "new", "len", "cap", "append"):
                    continue
                fn.callees.add(cal)
            by_name.setdefault(fn.name, []).append(fn)
            total += 1
    if total == 0:
        warnings.append(f"substrate_vacuous: 0 Go funcs parsed under {root}")
    return by_name


def forward_closure(entry: "_Func", by_name: dict, max_depth: int = 8) -> set:
    """Union of every callee short-name reachable in the forward closure of the
    entrypoint. PRESENT_ON_PATH - the transitive axis (a)/(c).

    A callee NAME is always recorded (so a cross-package trigger token is still
    seen), but it is only EXPANDED into its own callees when the resolved def
    lives in the SAME PACKAGE (directory) as the entrypoint. This kills the
    short-name over-fold false-KEEP: an unrelated same-named getter in another
    package no longer drags its transitive keygen/snapshot tokens into this
    closure (found on axelar: Keeper.RotateKey folded to NewKeygenSession via a
    generic getKeyID getter)."""
    pkg = str(Path(entry.file).parent)
    present: set = set(entry.callees)
    frontier = list(entry.callees)
    seen_fns = set()
    depth = 0
    while frontier and depth < max_depth:
        nxt = []
        for nm in frontier:
            if nm in seen_fns:
                continue
            seen_fns.add(nm)
            for callee_fn in by_name.get(nm, ()):
                if str(Path(callee_fn.file).parent) != pkg:
                    continue  # cross-package: record the name, do not expand
                for c in callee_fn.callees:
                    if c not in present:
                        present.add(c)
                        nxt.append(c)
        frontier = nxt
        depth += 1
    return present


# --------------------------------------------------------------------------
# Per-arm predicates. entrypoint selector, ACT gate node, REQUIRED coupled node.
# All matched against short callee/entrypoint names (lowercased).
# --------------------------------------------------------------------------
_ARMS = {
    "A_rotation_without_resharing": {
        "entrypoint": re.compile(
            r"^(?:rotatekey|rotate|assignkey|assignnextkey|setnextkey|"
            r"activatekey|activatenextkey|rotatevalidators|rotatesignerset|"
            r"updatesignerset|setactivekey)$"),
        # ACT gate: the rotation actually WRITES active-key / epoch / signer-set
        # state (otherwise it is a read-only query, not a rotation act).
        "act_gate": re.compile(
            r"(?:setkey|setkeyepoch|setkeyrotationcount|setactivekey|"
            r"deactivatekeyatepoch|setnextkeyid|assign|rotate|"
            r"updatesignerset|setsignerset|store|set|delete)"),
        # REQUIRED coupled action: a resharing / keygen TRIGGER for the new set.
        # Only creation/trigger verbs count - a READ like getKeygenSession /
        # getKeygenSessionKey must NOT satisfy the coupling (it does not reshare).
        "required": re.compile(
            r"(?:createkeygensession|newkeygensession|"
            r"(?:start|trigger|init|begin|schedule|do)keygen|"
            r"reshare|resharing|startresharing|generatekeyshares|submitpubkey)"),
        "invariant_id": "signer-set-rotation-must-trigger-resharing",
        "attack_class": "signer-set-rotation-without-resharing-stale-or-empty-shares",
        "impact": ("rotation updates the active signer set but never triggers a "
                   "keygen/reshare of the secret shares: the old signer set's "
                   "shares stay valid (stale quorum forges) or the new set holds "
                   "no shares (permanent signing lockout / bridge freeze)."),
    },
    "B_threshold_against_active_set_only": {
        "entrypoint": re.compile(
            r"^(?:submitsignature|submitsig|submitpubkey|acceptsignature|"
            r"handlesignature|votesig|vote|tally|aggregate|processsignature|"
            r"completesign|finalizesigning|onsignature)$"),
        # ACT gate: the acceptance path reaches a THRESHOLD comparison.
        "act_gate": re.compile(
            r"(?:signingthreshold|keygenthreshold|meetsthreshold|belowthreshold|"
            r"getthreshold|isthresholdmet|reachedthreshold|thresholdmet|"
            r"getparticipantsweight|getbondedweight|bondedweight)"),
        # REQUIRED: the threshold must be bound to the PRODUCED set - the
        # snapshot / key that generated the shares (keyed by keyID / sig-id).
        "required": re.compile(
            r"(?:snapshot|getkeygensession|getsigningsession|getkey|"
            r"key\.snapshot|producedset|signingsnapshot|getsnapshot|"
            r"getkeygensnapshot|keyrequirement|getparticipants|participantsof)"),
        "invariant_id": "threshold-must-bind-to-share-producing-set",
        "attack_class": "threshold-check-against-active-set-not-produced-set",
        "impact": ("the signature/vote threshold is measured against the CURRENT "
                   "active set rather than the snapshot that produced the shares: "
                   "after the set shrinks/rotates a sub-threshold coalition of the "
                   "original signers clears the (now lower) bar and forges."),
    },
    "C_nonce_session_reuse": {
        "entrypoint": re.compile(
            r"^(?:startkeygen|startsign|startsigning|createkeygensession|"
            r"createsigningsession|startsigningsession|newsigningsession|"
            r"newkeygensession|initiatesign|schedulesign|beginsigning|"
            r"createsession|opensigningsession)$"),
        # ACT gate: a session-start always creates/stores a session -> the id is
        # in play. (any session-start entrypoint qualifies)
        "act_gate": re.compile(
            r"(?:setkeygensession|setsigningsession|newkeygensession|"
            r"newsigningsession|createsession|store|set|createsnapshot|"
            r"createsigningsession|createkeygensession)"),
        # REQUIRED: a per-session freshness / duplicate-consume guard on the id.
        "required": re.compile(
            r"(?:getkeygensession|getsigningsession|haskeygensession|"
            r"hassigningsession|hassession|sessionexists|deletekeygensession|"
            r"deletesigningsession|consumednonce|nonceused|markconsumed|"
            r"freshsessionid|assertunused|alreadyexists|isactive|exists)"),
        "invariant_id": "session-id-nonce-must-have-freshness-guard",
        "attack_class": "signing-session-id-or-nonce-reuse-no-freshness-guard",
        "impact": ("a signing-session id / key-id / nonce is (re)used with no "
                   "per-session freshness or duplicate-consume guard: an actor "
                   "replays a prior session or forces nonce (k) reuse across two "
                   "signatures, from which the ECDSA private key is recovered."),
    },
}


def _contract_of(fn: "_Func") -> str:
    return fn.recv or Path(fn.file).stem


def make_obligation(arm_id: str, arm: dict, fn: "_Func", missing: list) -> dict:
    src_ref = f"{fn.file}:{fn.line}"
    root = (
        f"Coordination path '{fn.name}' ({_contract_of(fn)}) is an arm-{arm_id[0]} "
        f"survivor: its forward callgraph closure is MISSING the required coupled "
        f"action [{arm['invariant_id']}]. {arm['impact']} "
        f"Set-difference REQUIRED\\PRESENT is non-empty (missing coupled-action "
        f"family: {arm['attack_class']})."
    )
    return {
        "schema": "auditooor.go_mpc_coordination.v1",
        "arm": arm_id,
        "obligation_type": "go-mpc-coordination-gap",
        "contract": _contract_of(fn),
        "function": fn.name,
        "language": "go",
        "source_refs": [src_ref],
        "file": fn.file,
        "line": fn.line,
        "attack_class": arm["attack_class"],
        "permissionless": True,
        "priority_rank": 0,
        "likely_severity": "critical",
        "broken_invariant_ids": [arm["invariant_id"]],
        "root_cause_hypothesis": root,
        "quality_gate_status": "needs_source",
        "proof_status": "needs_source",
        "advisory_only": True,
        "learning_route": "mine-source",
        "falsification_requirements": [
            "COUPLED_ACTION_ABSENT: confirm NO keygen/reshare trigger (A) / "
            "produced-set binding (B) / per-session freshness guard (C) is "
            "reachable in the real closure - a coupled action dispatched through "
            "a runtime interface / router the static callgraph cannot resolve "
            "KILLS the lead.",
            "COORDINATION_REACH: confirm the entrypoint is externally reachable "
            "(a Msg/gRPC handler or a BeginBlock/EndBlock hook), not dead code.",
            "IMPACT_SEQUENCE: show the concrete forgery (A/B) or nonce-reuse "
            "key-leak (C) sequence against the produced-vs-active share set.",
        ],
        "next_command": (
            "python3 tools/go-mpc-coordination.py --workspace <ws>  # mine "
            f"{src_ref}")[:200],
    }


def run(argv=None) -> dict:
    ap = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--workspace", required=True)
    ap.add_argument("--src-root", default=None,
                    help="Go source root to build the coordination callgraph "
                         "over (default <ws>/src if present else <ws>)")
    ap.add_argument("--emit", default=None,
                    help="output jsonl (default "
                         "<ws>/.auditooor/go_mpc_coordination_obligations.jsonl)")
    ap.add_argument("--arm", default=None,
                    help="restrict to one arm id (A_*/B_*/C_*), default all")
    ap.add_argument("--max-depth", type=int, default=8)
    ap.add_argument("--json", action="store_true")
    ap.add_argument("--fail-closed", action="store_true",
                    help="exit non-zero if the substrate is vacuous")
    args = ap.parse_args(argv)

    ws = Path(args.workspace).expanduser().resolve()
    warnings: list = []

    if args.src_root:
        src_root = Path(args.src_root).expanduser().resolve()
    else:
        cand = ws / "src"
        src_root = cand if cand.is_dir() else ws
    if not src_root.is_dir():
        warnings.append(f"substrate_vacuous: src-root not a dir: {src_root}")
        by_name = {}
    else:
        by_name = parse_go_callgraph(src_root, warnings)

    arms = {k: v for k, v in _ARMS.items()
            if not args.arm or k.startswith(args.arm) or k == args.arm}

    per_arm = {}
    all_obligations = []
    total_entrypoints = 0
    for arm_id, arm in arms.items():
        act = []      # (fn, present_set)
        survivors = []
        kept = []
        for name, fns in by_name.items():
            if not arm["entrypoint"].match(name):
                continue
            for fn in fns:
                # exclude Go value constructors (no receiver, name starts 'new'):
                # NewKeygenSession/NewSigningSession are type factories in types/,
                # not orchestration handlers.
                if not fn.recv and fn.name.startswith("new"):
                    continue
                present = forward_closure(fn, by_name, args.max_depth)
                # ACT gate: entrypoint's closure reaches the arm's act node.
                present_all = present | {fn.name}
                if not any(arm["act_gate"].search(x) for x in present_all):
                    continue
                act.append(fn)
                total_entrypoints += 1
                has_required = any(arm["required"].search(x) for x in present_all)
                if has_required:
                    kept.append((fn, present_all))
                else:
                    survivors.append((fn, present_all))
        survivors.sort(key=lambda t: (t[0].file, t[0].line))
        kept.sort(key=lambda t: (t[0].file, t[0].line))
        for fn, present in survivors:
            # the "missing" family = the required-token alternatives (advisory).
            missing = [arm["required"].pattern[4:40]]
            all_obligations.append(make_obligation(arm_id, arm, fn, missing))
        per_arm[arm_id] = {
            "required_coupled_action": arm["invariant_id"],
            "attack_class": arm["attack_class"],
            "ACT_paths": len(act),
            "KEPT": [{"fn": f.name, "recv": f.recv,
                      "src": f"{f.file}:{f.line}"} for f, _ in kept[:20]],
            "survivors": [{"fn": f.name, "recv": f.recv,
                           "src": f"{f.file}:{f.line}"} for f, _ in survivors[:40]],
            "survivor_count": len(survivors),
        }

    # honesty verdict
    if total_entrypoints == 0:
        if any(w.startswith("substrate_vacuous") for w in warnings):
            substrate_status = "substrate_vacuous"
        else:
            substrate_status = "substrate_vacuous"
            warnings.append("substrate_vacuous: 0 coordination entrypoints "
                            "matched across all arms")
    elif not all_obligations:
        substrate_status = "cited_empty"
    else:
        substrate_status = "survivors_found"

    emit = Path(args.emit).expanduser() if args.emit else \
        ws / ".auditooor" / "go_mpc_coordination_obligations.jsonl"
    emit.parent.mkdir(parents=True, exist_ok=True)
    with emit.open("w", encoding="utf-8") as fh:
        for ob in all_obligations:
            fh.write(json.dumps(ob) + "\n")

    summary = {
        "schema": "auditooor.go_mpc_coordination.summary.v1",
        "workspace": str(ws),
        "src_root": str(src_root),
        "substrate_status": substrate_status,
        "advisory": True,
        "quality_gate_status": "needs_source",
        "total_coordination_entrypoints": total_entrypoints,
        "total_survivors": len(all_obligations),
        "arms": per_arm,
        "emit": str(emit),
        "warnings": warnings,
        "generated_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
    }

    if args.json:
        print(json.dumps(summary, indent=2))
    else:
        print(f"[go-mpc-coordination] status={substrate_status} "
              f"entrypoints={total_entrypoints} survivors={len(all_obligations)} "
              f"-> {emit}")
        for arm_id, a in per_arm.items():
            print(f"  [{arm_id}] required={a['required_coupled_action']} "
                  f"ACT={a['ACT_paths']} KEPT={len(a['KEPT'])} "
                  f"SURVIVORS={a['survivor_count']}")
            for k in a["KEPT"][:4]:
                print(f"      KEPT     {k['recv']}.{k['fn']}  {k['src']}")
            for s in a["survivors"][:8]:
                print(f"      SURVIVOR {s['recv']}.{s['fn']}  {s['src']}")
        for w in warnings:
            print(f"  WARN {w}", file=sys.stderr)

    if args.fail_closed and substrate_status == "substrate_vacuous":
        print("[go-mpc-coordination] FAIL-CLOSED: substrate vacuous",
              file=sys.stderr)
        sys.exit(3)

    return summary


if __name__ == "__main__":
    run()
