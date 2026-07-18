#!/usr/bin/env python3
"""cross-contract-privilege-trust-graph.py - LOGIC CAPABILITY #7.

(docs/LOGIC_ARSENAL_ROADMAP.md, the 8 logic reasoners). This is a TRUST-EDGE
REACHABILITY query over an OWNED trust backend, NOT a token detector.

------------------------------------------------------------------------------
THE LOGIC TRIPLE (the class this reasoner targets)
------------------------------------------------------------------------------
  ASSUMPTION (what the code silently relies on):
      a dispatcher / verifier that FORWARDS value or AUTHORITY to - or
      AUTHENTICATES a message against - an address `T` trusts that `T` is a
      protocol-sanctioned contract/key. Downstream state (a transfer, a
      privileged call, a "signature is valid" verdict) is granted on that trust.

  INVARIANT (what must hold for the assumption to be safe):
      every dispatched / verified target address `T` is either
        (i)  IMMUTABLE  (constructor-pinned / `immutable` / `constant`), OR
        (ii) VALIDATED before it is trusted - membership-checked against a
             governance-controlled allowlist/registry mapping, compared to a
             governance-pinned state var, or set only by a governance-guarded
             setter.
      i.e.  { dispatch/verifier targets that are TRUSTED }
              is a SUBSET of
            { targets that are IMMUTABLE or VALIDATED-before-trust }.

  TRUST-BOUNDARY (who the attacker is + what they cross):
      an actor who controls the target-DERIVATION input - a calldata param, or
      a non-immutable state var writable through a NON-governance path - can
      SUBSTITUTE a contract/key of their choosing that the system then trusts.
      The attacker-influenced target REACHES a contract action that trusts this
      dispatcher (the value-move / privileged call / auth verdict).

The finding is the SET-DIFFERENCE
    TRUSTED_TARGETS \\ (IMMUTABLE union VALIDATED)
- every survivor is a payload-derived, non-immutable, trust-anchored dispatch/
  verifier target with no membership/authorization validation on its
  derivation, emitted as a `payload-derived-trusted-dispatch` obligation.

------------------------------------------------------------------------------
WHY THIS IS LOGIC, NOT A SHAPE (guard-rail satisfied)
------------------------------------------------------------------------------
It never reduces to "token X present / token Y absent". Membership in each
operand set is a RELATION computed over the trust backend, and the answer is a
difference of two SETS:
  (a) TRUSTED_TARGETS is the set of address refs the trust graph shows are
      forwarded value/authority or authenticated against (a call / delegatecall
      receiver, a value-move recipient, an ecrecover-compared signer). This is
      the cross-contract owner/authorized-caller + dispatcher/verifier target
      relation the arch-delegation-trust-closure backend expresses.
  (b) PAYLOAD_DERIVED is a DERIVATION relation - the target flows from a
      calldata parameter, or from a state var whose only writers are
      non-governance setters. A governance-pinned or constructor-pinned target
      is NOT in this set (so `amlSigner` set by an `onlyOwner` setter is
      correctly excluded - impossible for a body-scoped regex to decide).
  (c) VALIDATED is a guard-CLOSURE relation - the target ref is membership-
      checked against an allowlist/registry mapping (`isDestination[T]`), or
      compared to a governance-pinned anchor. A check that lives ANYWHERE in the
      dispatcher's reachable body, on the SAME ref, removes the target from the
      survivors (impossible for a token-adjacency regex).
The survivor is the residue of the subtraction, so the reasoner reports the
KEPT set too (payload-derived-but-validated) to PROVE the subtraction is
non-vacuous, exactly like the Euler set-difference reasoner (#3).

------------------------------------------------------------------------------
OWNED BACKENDS CONSUMED (no new engine is built here)
------------------------------------------------------------------------------
SOL arm - reads the arch-delegation-trust-closure backend
    (tools/arch-delegation-trust-closure.py). This capability IMPORTS that
    module's owned primitives - `_parse_file` (brace-balanced Solidity parse),
    `_iter_guard_conditions`, `_has_enforcement_guard` (the concrete-enforcement
    predicate = the owner/authorized-caller edge classifier), `_enumerate_sol`,
    `_strip_comments`, `_MSGSENDER_EQ_VAR` - and, when present, the artifact it
    emits (<ws>/.auditooor/delegation_trust_closure.jsonl) as supplementary
    trust-seam edges. The enforcement predicate is the SINGLE SOURCE OF TRUTH
    for "is this guard a trust anchor" across both arms.

DATAFLOW arm (Go / Rust) - reads <ws>/.auditooor/dataflow_paths.jsonl
    (schema dataflow_path.v1, produced by tools/go-dataflow.py). A record whose
    SOURCE is a param entrypoint (payload) reaching a SINK of kind authority /
    value-move (trust-anchored dispatch) with NO guard_node classifying as an
    authorization/membership validation is the same subtraction expressed over
    the language-agnostic dataflow closure. This lets #7 fire on a Go/Rust
    workspace (axelar) where the Solidity trust-graph is empty.

DEDUP (distinct from the shipped reasoners):
  - callgraph-set-difference-hunter (#3): its CHECK predicate is a SOLVENCY /
    conservation assertion over DOWNWARD-mutation sinks. #7's CHECK is an
    AUTHORIZATION / allowlist-MEMBERSHIP validation of the dispatch TARGET, over
    dispatch/verifier sinks. Orthogonal guard_pred + orthogonal sink focus.
  - arch-delegation-trust-closure (R3): asks "does a mutated safety property
    bottom out unenforced". #7 asks the DUAL cross-contract question - "is the
    trusted CALLEE/VERIFIER address itself attacker-substitutable". R3's rows
    are unenforced ROOTS; #7's rows are swappable TRUSTED TARGETS.

OUTPUT
  <ws>/.auditooor/payload_derived_trusted_dispatch_obligations.jsonl
    one row per survivor, schema
    `auditooor.payload_derived_trusted_dispatch.v1`, exploit_queue-ingest
    compatible (contract/function/source_refs/root_cause_hypothesis/
    attack_class/broken_invariant_ids/quality_gate_status='needs_source').
  A summary (--json) with |TRUSTED|, |VALIDATED/IMMUTABLE among trusted|, the
  SET-DIFFERENCE survivors, and the KEPT (trusted-but-validated) proof set.
"""

from __future__ import annotations

import argparse
import importlib.util
import json
import re
import sys
import time
from pathlib import Path

_HERE = Path(__file__).resolve().parent
_REPO_ROOT = _HERE.parent


# ---------------------------------------------------------------------------
# Load the arch-delegation-trust-closure OWNED backend (hyphenated filename ->
# importlib). Its primitives ARE the trust-graph parser + owner/authorized-caller
# edge classifier this capability reads.
# ---------------------------------------------------------------------------
def _load_arch():
    p = _HERE / "arch-delegation-trust-closure.py"
    spec = importlib.util.spec_from_file_location("_arch_delegation_backend", str(p))
    if spec is None or spec.loader is None:
        raise ImportError(f"cannot load arch backend at {p}")
    mod = importlib.util.module_from_spec(spec)
    sys.modules["_arch_delegation_backend"] = mod
    spec.loader.exec_module(mod)
    return mod


try:
    _ARCH = _load_arch()
except Exception as _exc:  # pragma: no cover - arch backend must exist in repo
    _ARCH = None
    _ARCH_ERR = str(_exc)


# ---------------------------------------------------------------------------
# scope OOS guard (single source of truth), same degrade path as capability #3.
# ---------------------------------------------------------------------------
try:
    from tools.lib.scope_exclusion import is_oos  # type: ignore
except Exception:  # pragma: no cover
    _LIB = _HERE / "lib"
    if str(_LIB) not in sys.path:
        sys.path.insert(0, str(_LIB))
    try:
        from scope_exclusion import is_oos  # type: ignore
    except Exception:
        def is_oos(rel: str, **_) -> bool:  # type: ignore[misc]
            n = ("/" + str(rel).replace("\\", "/")).lower()
            return any(m in n for m in (
                "/test/", "/tests/", "_test.", ".t.sol", "/mock", "/vendor/",
                "/node_modules/", "/out/", "/build/", "/target/", "/.auditooor/",
            ))

_VENDOR_MARKERS = ("/pkg/mod/", "/go/pkg/", "/vendor/", "/node_modules/")
_CODEGEN_SUFFIXES = (".pb.go", ".pb.gw.go", ".gen.go", "_pb2.py")


def _in_scope_file(fpath: str, ws_root: Path, include_oos: bool) -> bool:
    if not fpath:
        return False
    low = fpath.replace("\\", "/").lower()
    if any(m in low for m in _VENDOR_MARKERS):
        return False
    if any(low.endswith(s) for s in _CODEGEN_SUFFIXES):
        return False
    try:
        # resolve BOTH sides so a symlinked root (macOS /var -> /private/var) does
        # not spuriously drop an in-scope file.
        rel = Path(fpath).resolve().relative_to(ws_root.resolve())
    except Exception:
        return False
    if not include_oos and is_oos(str(rel)):
        return False
    return True


# ---------------------------------------------------------------------------
# TRUST-VALIDATION node predicate (the CHECK operand for set VALIDATED). This
# classifies a single guard-condition / guard-node expr as an AUTHORIZATION or
# allowlist-MEMBERSHIP validation of a dispatch target. It is DISTINCT from #3's
# solvency predicate. The set/closure/reachability LOGIC lives in the caller; a
# guard_pred is always a per-node predicate (mirrors #3's solvency_guard_pred).
# ---------------------------------------------------------------------------
_MEMBERSHIP_MAP = re.compile(
    r"\b\w*(?:is|allow|whitelist|registr|approv|authoriz|trusted|valid|"
    r"destination|known|supported|enabled|member|peer|route)\w*\s*\[",
    re.IGNORECASE,
)
_AUTHZ_TOK = re.compile(
    r"(?:msg\.sender|hasrole|onlyrole|_checkrole|_checkowner|isowner|"
    r"isauthorized|authorized|owner|admin|guardian|onlyupdater|"
    r"_authorizeupgrade)",
    re.IGNORECASE,
)


def trust_validation_pred(expr: str, target: str | None = None) -> bool:
    """True iff the guard-node expr VALIDATES a dispatch target before it is
    trusted: a membership lookup in an allowlist/registry map, an authorization
    token, or (when `target` is given) a direct comparison of the target ref to a
    governance anchor. Pure node predicate."""
    e = (expr or "")
    if not e.strip():
        return False
    if _MEMBERSHIP_MAP.search(e):
        return True
    if _AUTHZ_TOK.search(e):
        return True
    if target:
        t = re.escape(target)
        # `T == govVar` / `govVar == T` where the OTHER side is an identifier
        # (not a payload literal) -> comparison to a pinned anchor.
        if re.search(rf"\b{t}\s*==\s*[A-Za-z_]\w*|[A-Za-z_]\w*\s*==\s*\b{t}\b", e):
            return True
    return False


# ===========================================================================
# SOL ARM - trust graph + dispatch/verifier target derivation over the
# arch-delegation-trust-closure Solidity parser (owned backend).
# ===========================================================================

# Dispatch/verifier target uses over a receiver identifier `X`:
_CALL_MEMBER = re.compile(r"(?<![.\w])([A-Za-z_]\w*)\s*\.\s*[A-Za-z_]\w*\s*\(")
# interface-cast dispatch: `IFoo(X).bar(...)` -> the dispatch target is the cast
# ARGUMENT X (the address the call is routed to), not the interface type. This is
# the dominant Solidity form (IVerifier(verifier).isValid / IRouter(router).fwd /
# IERC20(token).transfer) - a bare-identifier receiver regex would miss it.
_CAST_CALL = re.compile(
    r"(?<![.\w])(?:I?[A-Z]\w*)\s*\(\s*([A-Za-z_]\w*)\s*\)\s*\.\s*[A-Za-z_]\w*\s*\(")
_LOWLEVEL = re.compile(r"(?<![.\w])([A-Za-z_]\w*)\s*\.\s*(call|delegatecall|staticcall)\s*[({]")
# value recipient: `.transfer(X` / `.safeTransfer(X` / `safeTransferFrom(from, X,`.
# an optional `address(` cast prefix is unwrapped so `transfer(address(dest))`
# captures the inner ref `dest` (the real recipient), not the `address` keyword.
_VALUE_1ARG = re.compile(
    r"\.\s*(?:safeTransfer|transfer)\s*\(\s*(?:address\s*\(\s*)?([A-Za-z_]\w*)")
_VALUE_2ARG = re.compile(
    r"(?:safeTransferFrom|transferFrom)\s*\(\s*[^,]+,\s*(?:address\s*\(\s*)?([A-Za-z_]\w*)")
# verifier-signer: an ECDSA/ecrecover result compared to a target ref.
_RECOVER = re.compile(r"ecrecover|ECDSA\s*\.\s*recover", re.IGNORECASE)
_SIGNER_CMP = re.compile(
    r"(?:recoveredSigner|recovered|signer|recoveredAddress)\s*(?:==|!=)\s*([A-Za-z_]\w*)"
    r"|([A-Za-z_]\w*)\s*(?:==|!=)\s*(?:recoveredSigner|recovered|recoveredAddress)",
    re.IGNORECASE)

# state-var declaration at contract scope: `<Type> [vis] [immutable|constant] name;`
_STATE_DECL = re.compile(
    r"\b(address|I[A-Z]\w*|[A-Z]\w*)\s+"
    r"((?:public|private|internal|immutable|constant)\s+)*"
    r"([A-Za-z_]\w*)\s*(?:;|=)")

_SOL_BUILTIN_RECV = {
    "abi", "type", "block", "msg", "tx", "address", "super", "this",
    "keccak256", "sha256", "ecrecover", "require", "assert", "revert",
    "ECDSA", "MessageHashUtils", "Clones", "Math", "SafeERC20", "Strings",
}


def _state_var_info(text: str):
    """Return {name: {'immutable': bool}} for contract-scope state vars. A var
    declared `immutable`/`constant` (or only ever constructor-assigned) is a
    pinned target that the attacker cannot swap."""
    info: dict[str, dict] = {}
    for m in _STATE_DECL.finditer(text):
        mods = (m.group(2) or "")
        name = m.group(3)
        imm = bool(re.search(r"\b(?:immutable|constant)\b", mods))
        cur = info.get(name)
        if cur is None:
            info[name] = {"immutable": imm}
        elif imm:
            cur["immutable"] = True
    return info


def _params_of(header_and_sig: str):
    """address/interface-typed parameter names from a `(...)` param list text."""
    out: set[str] = set()
    for tm in re.finditer(
            r"\b(address|I[A-Z]\w*)\s+(?:calldata\s+|memory\s+|storage\s+)?"
            r"([A-Za-z_]\w*)", header_and_sig):
        out.add(tm.group(2))
    return out


class SolFn:
    __slots__ = ("name", "contract", "file", "line", "visibility", "is_view",
                 "modifiers", "body", "params")

    def __init__(self, f, params):
        self.name = f.name
        self.contract = f.contract
        self.file = f.file
        self.line = f.line
        self.visibility = f.visibility
        self.is_view = f.is_view
        self.modifiers = list(getattr(f, "modifiers", []) or [])
        self.body = f.body
        self.params = params


def _parse_sol_fns(fp: Path, rel: str):
    """Reuse arch `_parse_file` for the fn bodies, then recover each fn's
    address-typed PARAM names from the raw param list (arch keeps the header but
    not the param list)."""
    fns = _ARCH._parse_file(fp, rel)  # type: ignore[attr-defined]
    raw = _ARCH._strip_comments(  # type: ignore[attr-defined]
        fp.read_text(encoding="utf-8", errors="replace"))
    out = []
    for f in fns:
        params: set[str] = set()
        # locate `function <name> (` then the balanced param list.
        pat = re.compile(r"\bfunction\s+" + re.escape(f.name) + r"\s*\(")
        m = pat.search(raw)
        if m:
            op = raw.find("(", m.start())
            end = _ARCH._balanced(raw, op, "(", ")")  # type: ignore[attr-defined]
            if end != -1:
                params = _params_of(raw[op:end])
        out.append(SolFn(f, params))
    return out, raw


def _closure_bodies(root, byname, edges, max_fns=200):
    """concat the bodies of root + its forward-callee closure (for the VALIDATED
    reachability test: an allowlist check N hops away still validates)."""
    seen, stack, chunks = set(), [root], []
    while stack and len(seen) < max_fns:
        cur = stack.pop()
        if cur in seen:
            continue
        seen.add(cur)
        for f in byname.get(cur, ()):
            chunks.append(f.body)
        for nxt in edges.get(cur, ()):
            if nxt not in seen:
                stack.append(nxt)
    return "\n".join(chunks)


def _dispatch_targets(fn: SolFn):
    """Yield (target_ref, kind) dispatch/verifier uses in fn.body.

    A Solidity builtin / language keyword receiver (`address`, `msg`, `this`,
    `type`, `block`, `tx`, ...) is NEVER an attacker-substitutable trust target -
    it is a language primitive, not an address the protocol delegates trust to -
    so it is filtered on EVERY arm. Previously only the bare-identifier
    `_CALL_MEMBER` arm filtered builtins, so `token.safeTransferFrom(from,
    address(this), amt)` and `msg`-derived signer comparisons leaked `address`/
    `msg` into the TRUSTED count as phantom targets, inflating the accounting and
    the cited-empty numbers."""
    for m in _LOWLEVEL.finditer(fn.body):
        if m.group(1) not in _SOL_BUILTIN_RECV:
            yield m.group(1), m.group(2)
    for m in _CALL_MEMBER.finditer(fn.body):
        recv = m.group(1)
        if recv in _SOL_BUILTIN_RECV:
            continue
        yield recv, "call"
    for m in _CAST_CALL.finditer(fn.body):
        if m.group(1) not in _SOL_BUILTIN_RECV:
            yield m.group(1), "call"
    for rx in (_VALUE_1ARG, _VALUE_2ARG):
        for m in rx.finditer(fn.body):
            recv = m.group(1)
            if recv in _SOL_BUILTIN_RECV:
                continue
            yield recv, "value-recipient"
    if _RECOVER.search(fn.body):
        for m in _SIGNER_CMP.finditer(fn.body):
            v = m.group(1) or m.group(2)
            if v and v not in _SOL_BUILTIN_RECV:
                yield v, "verifier-signer"


def _sol_arm(ws: Path, target: Path | None, include_oos: bool):
    acct = {"arm": "solidity", "files": 0, "functions": 0,
            "dispatch_target_refs": 0, "trusted": 0,
            "payload_derived_trusted": 0, "validated_or_immutable": 0,
            "survivors": 0}
    survivors, kept = [], []
    if _ARCH is None:
        acct["status"] = f"arch-backend-unavailable: {globals().get('_ARCH_ERR','?')}"
        return survivors, kept, acct
    tgt = target if target is not None else ws
    files = _ARCH._enumerate_sol(tgt)  # type: ignore[attr-defined]
    files = [f for f in files if _in_scope_file(str(f), ws, include_oos)]
    acct["files"] = len(files)
    if not files:
        acct["status"] = "0-no-in-scope-solidity"
        return survivors, kept, acct

    all_fns, raw_by_file = [], {}
    for fp in files:
        try:
            rel = str(fp.relative_to(ws))
        except ValueError:
            rel = str(fp)
        fns, raw = _parse_sol_fns(fp, rel)
        all_fns.extend(fns)
        raw_by_file[rel] = raw
    acct["functions"] = len(all_fns)

    byname: dict[str, list] = {}
    for f in all_fns:
        byname.setdefault(f.name, []).append(f)
    names = set(byname)
    edges: dict[str, set] = {}
    for nm, fns in byname.items():
        cs = set()
        for f in fns:
            for cm in re.finditer(r"(?<![.\w])([A-Za-z_]\w*)\s*\(", f.body):
                if cm.group(1) in names:
                    cs.add(cm.group(1))
        cs.discard(nm)
        edges[nm] = cs

    # per-file state var immutability.
    svinfo_by_file = {rel: _state_var_info(raw) for rel, raw in raw_by_file.items()}
    # ATTACKER-WRITABLE state vars = the PAYLOAD_DERIVED operand for state-var
    # targets. A var is attacker-writable ONLY through a setter that is
    #   (a) external/public,  (b) NOT a construction context (constructor /
    #   initialize / an `initializer`-modified fn - those PIN a config address at
    #   deploy, they are not a steady-state attacker path), AND
    #   (c) NOT enforcement-guarded (arch owner/authorized-caller predicate).
    # A var written only in construction / behind a governance guard is
    # governance-PINNED and excluded (so `token`/`amlSigner`/`assetVault` set in
    # initialize or by an onlyOwner setter never counts as attacker-swappable).
    unguarded_setter_vars: set[str] = set()
    guarded_setter_vars: set[str] = set()
    for f in all_fns:
        af = _mk_arch_fn(f)
        if f.name == "constructor" or _ARCH._is_construction(af):  # type: ignore[attr-defined]
            continue
        if f.visibility not in ("external", "public"):
            # an internal writer is only reachable through an external caller;
            # treat its guardedness as its own (conservative: it still needs an
            # external unguarded entry, approximated by external/public setters).
            continue
        guarded = _ARCH._has_enforcement_guard(af)  # type: ignore[attr-defined]
        for am in re.finditer(r"\b([A-Za-z_]\w*)\s*=\s*[^=]", f.body):
            v = am.group(1)
            (guarded_setter_vars if guarded else unguarded_setter_vars).add(v)

    seen_ob = set()
    # A dispatch/verifier site can live in ANY function (the value-recipient is
    # often in a `private` helper like `_doDeposit(_amount,_destinationAddress)`),
    # so we examine every non-view, non-construction fn and derive PAYLOAD from
    # THAT fn's own address params (a calldata value threaded through the call
    # chain) or an attacker-writable state var. The obligation's
    # falsification_requirements carry the "prove externally reachable" burden to
    # the hunt (advisory pre-hunt producer).
    for fn in all_fns:
        if fn.is_view or fn.name == "constructor":
            continue
        # construction context (constructor / initialize / `initializer`-modified /
        # `new X(...)`) PINS config addresses at deploy - not a steady-state
        # attacker dispatch, so it is not a root here (mirrors arch R3).
        if _ARCH._is_construction(_mk_arch_fn(fn)):  # type: ignore[attr-defined]
            continue
        svinfo = svinfo_by_file.get(fn.file, {})
        closure_txt = _closure_bodies(fn.name, byname, edges)
        for ref, kind in _dispatch_targets(fn):
            acct["dispatch_target_refs"] += 1
            # TRUSTED: a dispatch/verifier use is a trust anchor by construction
            # (value / authority / verification delegated to `ref`).
            acct["trusted"] += 1
            # PAYLOAD_DERIVED: param OR non-immutable attacker-writable state var.
            is_param = ref in fn.params
            imm = bool(svinfo.get(ref, {}).get("immutable"))
            attacker_writable_state = (
                ref in unguarded_setter_vars and ref not in guarded_setter_vars
                and not imm)
            payload_derived = is_param or attacker_writable_state
            if imm:
                acct["validated_or_immutable"] += 1
                continue
            if not payload_derived:
                # governance-pinned / constructor-pinned target -> safe, excluded.
                continue
            # VALIDATED: a membership/authorization check on THIS ref reachable in
            # the dispatcher's fwd closure (allowlist map lookup, authz token, or
            # comparison to a pinned anchor).
            validated = _ref_validated(ref, closure_txt)
            if validated:
                acct["validated_or_immutable"] += 1
                dk = (fn.file, fn.line, fn.name, ref)
                if dk not in seen_ob:
                    seen_ob.add(dk)
                    kept.append({"contract": fn.contract, "fn": fn.name,
                                 "target": ref, "kind": kind,
                                 "file": fn.file, "line": fn.line,
                                 "derivation": "param" if is_param
                                 else "attacker-writable-state"})
                continue
            acct["payload_derived_trusted"] += 1
            dk = (fn.file, fn.line, fn.name, ref)
            if dk in seen_ob:
                continue
            seen_ob.add(dk)
            survivors.append({
                "contract": fn.contract, "fn": fn.name, "target": ref,
                "kind": kind, "file": fn.file, "line": fn.line,
                "language": "solidity",
                "derivation": "param" if is_param else "attacker-writable-state",
            })
    acct["survivors"] = len(survivors)
    acct["status"] = "ok"
    return survivors, kept, acct


def _mk_arch_fn(f: SolFn):
    """wrap a SolFn as an arch Fn for _has_enforcement_guard (needs .modifiers +
    .body). Re-parse modifiers is unnecessary: the enforcement predicate reads
    .modifiers + .body; we pass an empty modifier list + the body (guard-helper /
    require-condition tokens in the body still anchor)."""
    return _ARCH.Fn(f.name, f.contract, f.file, f.line, f.visibility,  # type: ignore[attr-defined]
                    f.is_view, list(f.modifiers), f.body, "")


def _ref_validated(ref: str, closure_txt: str) -> bool:
    """VALIDATED-operand membership test for a target ref over the dispatcher's
    fwd-closure text: an allowlist/registry map keyed on the ref, an authz token
    guard, or a comparison of the ref to a pinned anchor. Uses the shared
    trust_validation_pred node predicate on each guard-relevant fragment."""
    t = re.escape(ref)
    # allowlist / registry membership keyed on the ref:  map[ref]  (any map whose
    # name matches the membership lexicon).
    if re.search(rf"\b\w*(?:is|allow|whitelist|registr|approv|authoriz|trusted|"
                 rf"valid|destination|known|supported|enabled|member|peer|route)"
                 rf"\w*\s*\[[^\]]*\b{t}\b", closure_txt, re.IGNORECASE):
        return True
    # comparison of the ref to a pinned identifier anchor.
    if re.search(rf"\b{t}\s*==\s*[A-Za-z_]\w*|[A-Za-z_]\w*\s*==\s*\b{t}\b",
                 closure_txt):
        # exclude comparison to address(0) sanitisation only.
        for mm in re.finditer(rf"\b{t}\s*==\s*([A-Za-z_]\w*)|([A-Za-z_]\w*)\s*==\s*\b{t}\b",
                              closure_txt):
            other = mm.group(1) or mm.group(2)
            if other and other not in ("address",):
                return True
    return False


# ===========================================================================
# DATAFLOW ARM (Go / Rust) - the same subtraction over dataflow_paths.jsonl.
# ===========================================================================
_DISPATCH_SINK_KINDS = {"authority", "value-move"}
_DF_ENTRY_SRC = {"param", "param-entrypoint", "entrypoint"}
# generic cosmos/go arg names that must never count as a payload-selected callee
# even if they collide with a receiver-type token.
_DF_GENERIC_VARS = {
    "ctx", "types", "keeper", "coins", "vault", "module", "addr", "args",
    "amt", "amount", "sender", "recipient", "coin", "msg", "req", "resp",
    "store", "params", "denom", "account",
}


def _dataflow_arm(ws: Path, df_paths, include_oos: bool):
    acct = {"arm": "dataflow", "records": 0, "degraded": 0,
            "trusted": 0, "payload_derived_trusted": 0,
            "validated": 0, "survivors": 0, "files": [str(p) for p in df_paths]}
    survivors, kept = [], []
    seen = set()
    any_file = False
    for df in df_paths:
        if not df.is_file():
            continue
        any_file = True
        with df.open(encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if not line:
                    continue
                try:
                    rec = json.loads(line)
                except Exception:
                    continue
                acct["records"] += 1
                if rec.get("degraded"):
                    acct["degraded"] += 1
                    continue
                src = rec.get("source") or {}
                sink = rec.get("sink") or {}
                if str(sink.get("kind") or "") not in _DISPATCH_SINK_KINDS:
                    continue
                if str(src.get("kind") or "") not in _DF_ENTRY_SRC:
                    continue
                fn = str(sink.get("fn") or src.get("fn") or "")
                fpath = str(sink.get("file") or src.get("file") or "")
                if not _in_scope_file(fpath, ws, include_oos):
                    continue
                # TRUSTED: authority/value-move dispatch reached with an
                # attacker-influenced (param) argument.
                acct["trusted"] += 1
                callee = str(sink.get("callee") or "")
                svar = str(src.get("var") or "")
                # PAYLOAD-DERIVED **CALLEE** gate (the #7 axis - NOT #3's
                # payload-derived VALUE). go-dataflow resolves callees STATICALLY
                # to concrete, immutable-wired methods (a cosmos keeper
                # dependency), so the source param is almost always just an
                # ARGUMENT, never the callee/receiver selector. We only treat the
                # dispatch TARGET as attacker-substitutable when the resolved
                # callee identity itself references the tainted source var (a
                # dynamic dispatch through a payload-selected handler/verifier).
                # This keeps the Go/Rust arm faithful to the payload-derived-callee
                # class and avoids collapsing into #3's value-flow shape; on a
                # statically-wired keeper module it correctly yields no survivors.
                acct["dispatch_records"] = acct.get("dispatch_records", 0) + 1
                # Match the tainted var ONLY against the short receiver.method of
                # the callee (drop the import PATH so a coincidental package token
                # like `vault`/`types` in `github.com/.../vault/types.BankKeeper`
                # never counts), and require a discriminating var name (>=4 chars,
                # not a generic cosmos token) so the payload-derived-callee signal
                # is real dynamic dispatch, not a path collision.
                short_callee = callee.rsplit("/", 1)[-1]
                svar_lc = svar.lower()
                payload_callee = bool(
                    svar and len(svar) >= 4
                    and svar_lc not in _DF_GENERIC_VARS
                    and re.search(r"\b" + re.escape(svar) + r"\b", short_callee))
                if not payload_callee:
                    continue
                # VALIDATED: any guard node classifies as an authorization /
                # membership validation (shared trust_validation_pred).
                gnodes = rec.get("guard_nodes") or []
                validated = any(
                    trust_validation_pred(str((g or {}).get("expr") or ""))
                    for g in gnodes)
                # dedup per (file, fn, callee, kind) - a fn with N identical
                # dispatch sinks (e.g. two SendCoins) is ONE trust-target unit.
                dk = (fpath, fn, callee, sink.get("kind"))
                if validated:
                    acct["validated"] += 1
                    if dk not in seen:
                        seen.add(dk)
                        kept.append({"fn": fn, "callee": callee,
                                     "kind": sink.get("kind"), "file": fpath,
                                     "line": sink.get("line")})
                    continue
                acct["payload_derived_trusted"] += 1
                if dk in seen:
                    continue
                seen.add(dk)
                survivors.append({
                    "contract": _go_recv(fn), "fn": _go_short(fn),
                    "target": callee or "<payload-dispatch>",
                    "kind": str(sink.get("kind")), "file": fpath,
                    "line": int(sink.get("line") or 0),
                    "language": str(rec.get("language") or "go"),
                    "derivation": "param-entrypoint",
                    "signature": fn,
                })
    acct["survivors"] = len(survivors)
    acct["status"] = "ok" if any_file else "0-no-dataflow"
    return survivors, kept, acct


def _go_short(fn: str) -> str:
    s = (fn or "").strip()
    if ")." in s:
        s = s.rsplit(").", 1)[-1]
    return s.split("(")[0].replace("*", "").split(".")[-1].strip()


def _go_recv(fn: str) -> str:
    s = (fn or "").strip()
    if ")." in s:
        recv = s.rsplit(").", 1)[0].lstrip("(").lstrip("*")
        return recv.split(".")[-1]
    return ""


# ===========================================================================
# obligation row + driver.
# ===========================================================================
def make_obligation(s: dict, invariant_id: str) -> dict:
    contract = s.get("contract") or ""
    fn = s.get("fn") or ""
    line = int(s.get("line") or 0)
    src_ref = (s.get("file") or "") + (f":{line}" if line else "")
    target = s.get("target") or "<target>"
    kind = s.get("kind") or "dispatch"
    deriv = s.get("derivation") or "payload"
    root = (
        f"Dispatcher/verifier '{contract}.{fn}' trusts target address `{target}` "
        f"(use={kind}) whose derivation is {deriv} (payload-derived, "
        f"non-immutable) and reaches NO membership/authorization validation of "
        f"that target in its forward closure (set-difference "
        f"TRUSTED\\(IMMUTABLE|VALIDATED)). An actor who controls `{target}` can "
        f"substitute a contract/key the protocol then trusts - the value-move / "
        f"privileged call / signature verdict is granted to an attacker-chosen "
        f"callee. Cross-contract privilege-trust class."
    )
    return {
        "schema": "auditooor.payload_derived_trusted_dispatch.v1",
        "obligation_type": "payload-derived-trusted-dispatch",
        "contract": contract,
        "function": fn,
        "function_signature": s.get("signature") or f"{contract}.{fn}",
        "language": s.get("language") or "",
        "trusted_target_ref": target,
        "dispatch_kind": kind,
        "target_derivation": deriv,
        "source_refs": [src_ref] if src_ref else [],
        "file": s.get("file") or "",
        "line": line,
        "attack_class": "payload-derived-trusted-dispatch-no-validation",
        "likely_severity": "high",
        "broken_invariant_ids": [invariant_id],
        "root_cause_hypothesis": root,
        "quality_gate_status": "needs_source",
        "proof_status": "needs_source",
        "advisory_only": True,
        "learning_route": "mine-source",
        "falsification_requirements": [
            "TARGET_DERIVATION: prove the target address is genuinely attacker-"
            "influenced (a calldata param, or a non-immutable var writable "
            "through a non-governance path) - a constructor-pinned/immutable or "
            "onlyOwner-set target KILLS the lead.",
            "NO_VALIDATION_CLOSURE: prove NO allowlist/registry membership check "
            "or authorization gate on THIS target ref is reachable in the "
            "dispatcher's fwd closure (a check N hops away in a helper KILLS it).",
            "TRUST_CONSEQUENCE: show the value-move / privileged call / signature "
            "verdict granted to the attacker-chosen callee yields a concrete "
            "impact (theft / auth bypass / message forgery).",
        ],
        "next_command": (
            "read the dispatcher + callee/verifier derivation; if the target is "
            "attacker-substitutable and unvalidated, author the trust-substitution "
            "PoC (swap the callee, show the trusted action fires)."
        ),
    }


def make_examined_record(sol_acct: dict, df_acct: dict, invariant_id: str,
                         no_substrate: bool) -> dict:
    """CITED-EMPTY examined-record (the NEVER-a-silent-0 marker).

    Emitted to the obligation ledger when the TRUSTED\\(IMMUTABLE|VALIDATED)
    set-difference yielded no survivors. It records WHAT substrate was examined
    and WHY nothing survived, so a downstream consumer
    (exploit-queue / logic-obligation-resolution-check) sees a terminal-clean
    EXAMINED result rather than an absent/starved ledger (which is
    indistinguishable from "the reasoner never ran"). The row is deliberately
    ANCHOR-LESS (no function/contract/op/site) and carries the literal
    `cited-empty` note + a `report.totals` block, which
    logic-obligation-resolution-check._is_advisory_row already classifies as
    ADVISORY (not an open obligation). It is tagged obligation_type
    `trust-graph-examined-record` so exploit-queue skips it, and its
    proof/quality status are terminal so any non-advisory consumer still reads it
    as resolved."""
    n_trusted = int(sol_acct.get("trusted", 0)) + int(df_acct.get("trusted", 0))
    n_valid = (int(sol_acct.get("validated_or_immutable", 0))
               + int(df_acct.get("validated", 0)))
    sol_refs = int(sol_acct.get("dispatch_target_refs", 0))
    df_recs = int(df_acct.get("records", 0))
    df_disp = int(df_acct.get("dispatch_records", 0))
    if no_substrate:
        note = ("cited-empty (N/A): no in-scope Solidity dispatch surface and no "
                "Go/Rust dataflow substrate examined - the cross-contract "
                "privilege-trust class is genuinely absent on this workspace.")
    else:
        note = (f"cited-empty: examined {n_trusted} trusted dispatch/verifier "
                f"target(s) (sol dispatch_target_refs={sol_refs}, dataflow "
                f"records={df_recs}/dispatch={df_disp}); {n_valid} were "
                f"IMMUTABLE or VALIDATED and the remainder were "
                f"governance/constructor-pinned (not payload-derived) or "
                f"statically-wired callees - 0 survived the "
                f"TRUSTED\\(IMMUTABLE|VALIDATED) set-difference. Terminal-clean, "
                f"not a starved/absent run.")
    return {
        "schema": "auditooor.payload_derived_trusted_dispatch.v1",
        "obligation_type": "trust-graph-examined-record",
        "row_is_advisory": True,
        "advisory_only": True,
        "note": note,
        "report": {
            "degraded": bool(no_substrate),
            "totals": {
                "trusted": n_trusted,
                "validated_or_immutable": n_valid,
                "survivors": 0,
            },
        },
        "examined": {"sol_arm": sol_acct, "dataflow_arm": df_acct},
        "broken_invariant_ids": [invariant_id],
        "attack_class": "payload-derived-trusted-dispatch-no-validation",
        "quality_gate_status": "cleared",
        "proof_status": "not-applicable",
        "generated_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
    }


def run(argv=None):
    ap = argparse.ArgumentParser(
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--workspace", required=True)
    ap.add_argument("--target", default=None,
                    help="Solidity file/dir override for the sol arm (default ws)")
    ap.add_argument("--dataflow", default=None,
                    help="override dataflow_paths.jsonl path")
    ap.add_argument("--include-oos", action="store_true")
    ap.add_argument("--invariant-id",
                    default="INV-DISPATCH-TARGET-IMMUTABLE-OR-VALIDATED",
                    help="broken_invariant_id stamped on every obligation")
    ap.add_argument("--emit", default=None)
    ap.add_argument("--json", action="store_true")
    ap.add_argument("--fail-closed", action="store_true",
                    help="exit non-zero if BOTH arms have no substrate at all")
    args = ap.parse_args(argv)

    ws = Path(args.workspace).expanduser().resolve()
    target = Path(args.target).expanduser() if args.target else None

    df_paths = []
    if args.dataflow:
        df_paths.append(Path(args.dataflow).expanduser())
    else:
        main_df = ws / ".auditooor" / "dataflow_paths.jsonl"
        if main_df.is_file():
            df_paths.append(main_df)
        for sib in sorted((ws / ".auditooor").glob("dataflow_paths.*.jsonl")):
            if sib not in df_paths:
                df_paths.append(sib)

    sol_surv, sol_kept, sol_acct = _sol_arm(ws, target, args.include_oos)
    df_surv, df_kept, df_acct = _dataflow_arm(ws, df_paths, args.include_oos)

    survivors = sol_surv + df_surv
    kept = sol_kept + df_kept

    obligations = [make_obligation(s, args.invariant_id) for s in survivors]

    n_trusted = sol_acct.get("trusted", 0) + df_acct.get("trusted", 0)
    n_validated = (sol_acct.get("validated_or_immutable", 0)
                   + df_acct.get("validated", 0))
    no_substrate = (sol_acct.get("files", 0) == 0
                    and df_acct.get("records", 0) == 0)

    # NEVER a silent 0: when the set-difference yielded no survivors, persist a
    # single CITED-EMPTY examined-record so the ledger is a terminal-clean
    # EXAMINED result, not an absent/starved file. Kept separate from the real
    # obligation count in the summary.
    rows_to_write = list(obligations)
    examined_record = None
    if not obligations:
        examined_record = make_examined_record(
            sol_acct, df_acct, args.invariant_id, no_substrate)
        rows_to_write.append(examined_record)

    emit = Path(args.emit).expanduser() if args.emit else \
        ws / ".auditooor" / "payload_derived_trusted_dispatch_obligations.jsonl"
    emit.parent.mkdir(parents=True, exist_ok=True)
    with emit.open("w", encoding="utf-8") as fh:
        for ob in rows_to_write:
            fh.write(json.dumps(ob) + "\n")

    summary = {
        "schema": "auditooor.cross_contract_privilege_trust_graph.v1",
        "workspace": str(ws),
        "generated_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "size_TRUSTED": n_trusted,
        "size_VALIDATED_or_IMMUTABLE_among_trusted": n_validated,
        "size_DIFF_survivors": len(survivors),
        "kept_trusted_but_validated": kept[:40],
        "survivors": survivors[:80],
        "obligations_written": len(obligations),
        "examined_record_written": examined_record is not None,
        "obligations_path": str(emit),
        "sol_arm": sol_acct,
        "dataflow_arm": df_acct,
        "no_substrate": no_substrate,
    }

    if args.json:
        print(json.dumps(summary, indent=2))
    else:
        print(f"[xcontract-trust-graph] {ws.name}: "
              f"|TRUSTED|={n_trusted} "
              f"|VALIDATED/IMMUTABLE(among trusted)|={n_validated} "
              f"survivors(TRUSTED\\VALIDATED)={len(survivors)} "
              f"-> {len(obligations)} payload-derived-trusted-dispatch obligation(s)")
        if kept:
            print(f"  KEPT (trusted but validated, removed from diff): {len(kept)}")
        for s in survivors[:40]:
            print(f"  SURVIVOR {s.get('contract')}.{s.get('fn')} "
                  f"target=`{s.get('target')}` [{s.get('kind')}/"
                  f"{s.get('derivation')}] {s.get('file')}:{s.get('line')}")
        if examined_record is not None:
            print(f"  CITED-EMPTY examined-record written (never a silent 0): "
                  f"{examined_record['note'][:120]}")
        print(f"  sol_arm={sol_acct.get('status')} "
              f"dataflow_arm={df_acct.get('status')}")
        print(f"  -> {emit}")

    if args.fail_closed and no_substrate:
        return 3
    return summary


if __name__ == "__main__":
    out = run()
    if out == 3:
        sys.exit(3)
