#!/usr/bin/env python3
"""deferred-execution-param-binding-screen.py - the DEFERRED-EXECUTION PARAM-BINDING screen (MQ-B03).

GENERAL LOGIC / TRUST-ENFORCEMENT class (never a bug SHAPE, never an impact silo). It
instantiates the north-star method ("a TRUSTED ENFORCEMENT is bypassable or its private
invariant is unsound") for ONE delegated-and-trusted safety property that the external-
freshness models (A17) cannot reach - this is INTERNAL request-param integrity across a
two-phase boundary, not the freshness of an external feed:

  DELEGATED-TRUSTED INVARIANT : a two-phase authorize-then-execute flow
    (timelock / withdrawal-queue / L1->L2 message / commit-reveal / signed-order) binds a
    set of security-relevant params {amount, recipient, target, price, nonce, value, root}
    at AUTHORIZE time (submit / propose / queue / prove / commit / sign) into a stored,
    hash/proof/signature/readiness-COMMITTED request object R.
  PRIVATE INVARIANT           : the EXECUTE path (accept / finalize / claim / relay /
    redeem / settle / process) acts on EXACTLY the params bound in R - it REPLAYS R.<field>.
  ATTACK                      : the execute path RE-DERIVES / RE-READS a security-relevant
    param from MUTABLE state (a storage variable other than R, an external live getter,
    block.timestamp/number, or msg.*) that an attacker can move BETWEEN the two phases. The
    authorize-time check then validated a DIFFERENT value than the one executed -> the
    delegated integrity of the request is broken, and the mutation is externally drivable.

This is adjacent to A17 (external-freshness) but distinct: A17 asks "is this external read
stale?"; MQ-B03 asks "did the execute path replay the bound internal value, or silently
substitute a live mutable one?". The seam is the two-phase authorize/execute boundary.

Enforcement point = one EXECUTE-phase function that carries a BOUND HANDLE R (a stored
request whose readiness field validAt/readyAt/... is checked, OR a struct object that is
hash/proof/signature-verified). Per point the screen answers, for every security-relevant
sink argument (transfer recipient/amount, call target/value, _setX value, mint/burn):
  {bound_handle, sink, arg, replayed_from_R? , re_derived_from_mutable_state?}
and flags (verdict=needs-fuzz) ONLY when a security-relevant sink arg is RE-DERIVED from
mutable state instead of replayed from R.

ADVISORY-FIRST: every row carries verdict='needs-fuzz', advisory=True, auto_credit=False.
It NEVER auto-credits and NEVER fail-closes in default mode. --strict (or the env
AUDITOOOR_DEFERRED_PARAM_BINDING_STRICT) only raises the exit code; it still emits no credit.

Languages: Solidity (primary - two-phase authorize/execute is a canonical EVM pattern) and
Go (keeper-stored request executed later). Silent on trees with neither.

Usage:
  --workspace <ws>   scan <ws>/src -> .auditooor/deferred_execution_param_binding_hypotheses.jsonl + summary
  --source <dir>     scan an arbitrary dir, print rows as JSON
  --file <f>         scan a single .sol/.go file, print rows as JSON
  --check            re-read the emitted sidecar, print cert verdict (advisory)
  --strict           (or env) elevate exit code when a re-derived point exists
  --json             machine summary to stdout
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import sys
from pathlib import Path

HYP_SCHEMA = "auditooor.deferred_execution_param_binding_hypotheses.v1"
CAPABILITY = "MQB03-deferred-execution-param-binding"
_SIDE_NAME = "deferred_execution_param_binding_hypotheses.jsonl"
_STRICT_ENV = "AUDITOOOR_DEFERRED_PARAM_BINDING_STRICT"

_SKIP_DIRS = {"target", ".git", "node_modules", "vendor", "_archive", "out",
              "cache", "lib", "__pycache__", "dist", "build", ".auditooor",
              "forge-artifacts", "artifacts", "benches", "benchmarks", "coverage"}
# test / mock / script dirs+files are excluded: a two-phase flow re-read there is not an
# attacker-drivable production path.
_TEST_HINT = re.compile(
    r"(^|/)(tests?|test_fixtures|mock|mocks|script|scripts|examples?|fuzz|echidna|"
    r"halmos|chimera_harnesses|harness)(/|$)", re.I)
_TEST_FILE = re.compile(r"(\.t\.sol$|_test\.go$|Mock|\.s\.sol$|Test\.sol$|Invariant)", re.I)

# EVM builtin globals are NOT stored requests: `block.timestamp` / `block.number` /
# `msg.value` / `tx.origin` reads must NEVER fabricate a two-phase committed request handle
# R. Excluded as request-object roots (a `block` root would make any fee/timestamp read look
# like an authorize-then-execute binding). Real requests are storage/param structs.
_BUILTIN_ROOTS = {"block", "msg", "tx", "abi"}

# --- deferral binding fields: the readiness/commitment stamp of a stored request R -------
_BIND_FIELDS = (
    "validAt", "readyAt", "executableAt", "executeAfter", "deadline", "maturity",
    "unlockTime", "unlockAt", "availableAt", "provenAt", "timestamp", "createdAt",
    "requestTime", "queuedAt", "scheduledAt", "eta", "nonce", "root", "hash")
_BIND_FIELD_RE = re.compile(
    r"\b([A-Za-z_]\w*)\s*(\[[^\]]*\])?\s*\.\s*(?:" + "|".join(_BIND_FIELDS) + r")\b")

# request-object name roots (a stored request struct / mapping)
_REQ_NAME = re.compile(
    r"(pending|request|req|queued|queue|proposal|withdrawal|withdraw|order|"
    r"commitment|commit|message|scheduled|schedule|ticket|voucher|claim|"
    r"redemption|redeem|op\b|_tx\b|txn|operation)", re.I)

# verification / commitment binding calls: what turns a struct into an authorized request
_VERIFY_CALL = re.compile(
    r"(keccak256\s*\(|\bhash[A-Z]\w*\s*\(|Hashing\.\w+\s*\(|check[A-Z]\w*\s*\(|"
    r"ecrecover\s*\(|MerkleProof|SecureMerkleTrie|\bverify\w*\s*\(|_verify\w*\s*\(|"
    r"isValidSignature|SignatureChecker|_validate\w*\s*\(|_authorize\w*\s*\()")

# --- security-relevant SINKS (args are inherently amount/recipient/target/value/price) ---
_SINK_RE = re.compile(
    r"(?:"
    r"\.\s*(?:safeTransfer|safeTransferFrom|transfer|transferFrom|send|mint|burn|"
    r"withdrawTo|deposit|unlockETH|lockETH)\s*\("      # token/value movers
    r"|\bSafeCall\s*\.\s*\w+\s*\("                        # SafeCall.callWithMinGas(...)
    r"|\bcallWithMinGas\s*\("
    r"|\.\s*call\s*\{[^}]*\}\s*\("                        # low-level call{value:}(...)
    r"|\b_set[A-Z]\w*\s*\("                               # config setter _setCap/_setFee/...
    r"|\bexcessivelySafeCall\s*\("
    r")")

# an external live getter used as a value (re-derivation from a live source)
_EXT_GETTER = re.compile(
    r"(\.\s*balanceOf\s*\(|\.\s*latestAnswer\s*\(|\.\s*latestRoundData\s*\(|"
    r"\.\s*price\w*\s*\(|\.\s*getPrice\w*\s*\(|\.\s*getReserves\s*\(|"
    r"\.\s*convertTo\w*\s*\(|\.\s*totalSupply\s*\(|\.\s*totalAssets\s*\(|"
    r"\.\s*getAmount\w*\s*\(|\.\s*quote\w*\s*\(|\.\s*exchangeRate\w*\s*\()")
_LIVE_BLOCK = re.compile(r"\bblock\s*\.\s*(timestamp|number|basefee|prevrandao|difficulty)\b")

# inert args we never treat as a re-derivation violation
_INERT_ARG = re.compile(
    r"^\s*(address\s*\(\s*this\s*\)|address\s*\(\s*0\s*\)|msg\s*\.\s*sender|"
    r"_msgSender\s*\(\s*\)|true|false|0x0|\d[\d_]*|\"[^\"]*\"|''|bytes\s*\(\s*\"\"\s*\)|"
    r"type\s*\(|Constants\.\w+|address\s*\(\s*0x0*\s*\))\s*$")

# Go two-phase / execute-verb names
_GO_EXEC = re.compile(
    r"\bfunc\s*(?:\([^)]*\))?\s*([A-Z]\w*)?\s*\(?", )
_GO_EXEC_NAME = re.compile(
    r"(Execute|Finalize|Process|Complete|Claim|Distribute|Relay|Settle|Fulfill|"
    r"Release|Payout|Redeem|Withdraw|Consume|Apply)", re.I)
_GO_SINK = re.compile(
    r"(\.\s*SendCoins\w*\s*\(|\.\s*Send\w*\s*\(|\.\s*MintCoins\s*\(|\.\s*BurnCoins\s*\(|"
    r"\.\s*Transfer\w*\s*\(|\.\s*Mint\w*\s*\(|\.\s*Delegate\s*\(|\.\s*Undelegate\s*\()")
_GO_GETTER = re.compile(
    r"(\.\s*Get[A-Z]\w*\s*\(|\.\s*GetBalance\s*\(|\.\s*SpendableCoins\s*\(|"
    r"ctx\s*\.\s*BlockTime\s*\(|ctx\s*\.\s*BlockHeight\s*\(|\.\s*GetSupply\s*\()")

_EXEC_VERB = re.compile(
    r"^(accept|execute|finalize|claim|redeem|process|relay|settle|fulfill|complete|"
    r"release|distribute|unlock|consume|withdraw|payout|apply|run|dispatch)", re.I)


# -------------------------------------------------------------------------------------
def _mask_comments(text: str) -> str:
    """Blank // and /* */ comments (and Go // */), preserving newlines and per-line length
    so line indices stay aligned. Not string-literal aware -> errs toward SILENCE (can only
    drop a token, never invent a sink/binding), the safe direction for an advisory screen."""
    out = []
    i, n = 0, len(text)
    in_line = in_block = False
    while i < n:
        c = text[i]
        nxt = text[i + 1] if i + 1 < n else ""
        if in_line:
            out.append("\n" if c == "\n" else " ")
            if c == "\n":
                in_line = False
            i += 1
        elif in_block:
            if c == "*" and nxt == "/":
                out.append("  ")
                i += 2
                in_block = False
            else:
                out.append("\n" if c == "\n" else " ")
                i += 1
        elif c == "/" and nxt == "/":
            in_line = True
            out.append("  ")
            i += 2
        elif c == "/" and nxt == "*":
            in_block = True
            out.append("  ")
            i += 2
        else:
            out.append(c)
            i += 1
    return "".join(out)


def _iter_source_files(root: Path, exts):
    for dp, dn, fn in os.walk(root):
        dn[:] = [d for d in dn if d not in _SKIP_DIRS]
        if _TEST_HINT.search(dp.replace(os.sep, "/")):
            continue
        for f in fn:
            if any(f.endswith(e) for e in exts) and not _TEST_FILE.search(f):
                yield Path(dp) / f


def _split_top_args(argstr: str):
    """Split a call's arg list on top-level commas (respecting (), [], {}, <>)."""
    args, depth, cur = [], 0, []
    for ch in argstr:
        if ch in "([{":
            depth += 1
            cur.append(ch)
        elif ch in ")]}":
            depth -= 1
            cur.append(ch)
        elif ch == "," and depth == 0:
            args.append("".join(cur).strip())
            cur = []
        else:
            cur.append(ch)
    if "".join(cur).strip():
        args.append("".join(cur).strip())
    return args


def _extract_call_args(text: str, open_paren_idx: int):
    """Given index of '(' return (argstr, index_after_close) via brace matching."""
    depth = 0
    i = open_paren_idx
    n = len(text)
    while i < n:
        c = text[i]
        if c == "(":
            depth += 1
        elif c == ")":
            depth -= 1
            if depth == 0:
                return text[open_paren_idx + 1:i], i + 1
        i += 1
    return text[open_paren_idx + 1:], n


# ------------------------------ Solidity state vars ----------------------------------
_STATE_DECL = re.compile(
    r"^\s*(?:mapping\s*\(.*\)\s*(?:public|private|internal)?\s*|"
    r"[A-Za-z_][\w\.\[\]]*\s+(?:public\s+|private\s+|internal\s+|constant\s+|immutable\s+|"
    r"memory\s+|storage\s+)*)([A-Za-z_]\w*)\s*(?:=|;)")


# constant/immutable qualifiers make a declaration compile-time / construction-fixed: such a
# value CANNOT move between the authorize and execute phases, so a read of it is never an
# attacker-drivable re-derivation. These declarations are excluded from the mutable state set.
_NONMUTABLE_QUAL = re.compile(r"\b(constant|immutable)\b")


def _solidity_state_vars(lines):
    """Collect contract-scope (brace depth == 1) MUTABLE state variable names.

    constant/immutable declarations are excluded: they are fixed at compile/construction
    time and cannot be moved between the authorize and execute phases, so reading one in the
    execute path is inert, not an attacker-drivable re-derivation."""
    names = set()
    depth = 0
    for ln in lines:
        stripped = ln.strip()
        # capture at contract-body depth, before applying this line's braces
        if depth == 1 and stripped and not stripped.startswith(("function", "modifier",
                "event", "error", "struct", "enum", "using", "import", "pragma",
                "constructor", "receive", "fallback", "//", "/*", "*", "}")):
            m = _STATE_DECL.match(ln)
            if m and not _NONMUTABLE_QUAL.search(stripped):
                # exclude obvious function/modifier signatures that slipped through
                if "(" not in stripped.split(m.group(1))[0] or "mapping" in stripped:
                    names.add(m.group(1))
        depth += ln.count("{") - ln.count("}")
        if depth < 0:
            depth = 0
    return names


def _iter_functions_sol(lines):
    """Yield (name, header_str, body_str, header_start_idx, body_start_idx) per function."""
    n = len(lines)
    i = 0
    fn_re = re.compile(r"\bfunction\s+([A-Za-z_]\w*)")
    while i < n:
        m = fn_re.search(lines[i])
        if not m:
            i += 1
            continue
        name = m.group(1)
        # gather header until the first '{' or ';'
        header_lines = []
        j = i
        opened = False
        while j < n:
            header_lines.append(lines[j])
            if "{" in lines[j]:
                opened = True
                break
            if ";" in lines[j] and "{" not in lines[j]:
                break  # interface / abstract decl, no body
            j += 1
        if not opened:
            i = j + 1
            continue
        header = "\n".join(header_lines)
        # brace-match the body from line j
        depth = 0
        started = False
        body_lines = []
        k = j
        while k < n:
            depth += lines[k].count("{") - lines[k].count("}")
            body_lines.append(lines[k])
            if "{" in lines[k]:
                started = True
            if started and depth <= 0:
                break
            k += 1
        yield name, header, "\n".join(body_lines), i, j
        i = max(k, i + 1)


def _param_names_sol(header):
    """Base names of a Solidity function's parameters (last identifier per top-level arg)."""
    idx = header.find("(")
    if idx < 0:
        return set()
    argstr, _ = _extract_call_args(header, idx)
    names = set()
    for a in _split_top_args(argstr):
        toks = re.findall(r"[A-Za-z_]\w*", a)
        if toks:
            names.add(toks[-1])
    return names


# a local declared as `<Type> memory|calldata|storage <var> = <inputParam>[...]/.field` -
# i.e. a fresh copy of a function INPUT, not a stored authorize-time-committed request R.
_INPUT_LOCAL_DECL = re.compile(
    r"\b[A-Za-z_][\w\.\[\]]*\s+(?:memory|calldata|storage)\s+"
    r"([A-Za-z_]\w*)\s*=\s*([A-Za-z_]\w*)\s*[\[.]")


def _bound_handles_sol(name, header, body):
    """Return (set_of_bound_handle_roots, evidence) for an execute-phase fn, or (set(), '')."""
    roots = set()
    ev = []
    params = _param_names_sol(header)
    # locals that are just a per-call copy/index of a function INPUT param (e.g. a loop var
    # `BatchData memory currentBatch = batches[i]`). Their `.timestamp`/`.deadline` reads are
    # validating the FRESH input, not replaying a previously-committed stored request - so
    # they must NOT fabricate a two-phase binding handle. A genuine stored request is loaded
    # from STORAGE (`Req memory r = requests[id]`), whose RHS root is a state var, not a param.
    input_locals = {m.group(1) for m in _INPUT_LOCAL_DECL.finditer(body)
                    if m.group(2) in params}
    # 1) readiness/binding-field reads in header (modifier) or body -> stored request R
    for m in _BIND_FIELD_RE.finditer(header + "\n" + body):
        root = m.group(1)
        # EVM builtins (block.timestamp/number, msg.*, tx.*) are live globals, not a stored
        # committed request - they must not fabricate a two-phase binding handle.
        if root in _BUILTIN_ROOTS or root in input_locals:
            continue
        roots.add(root)
        ev.append(f"binding-field:{root}")
    # 2) struct memory/calldata params that are hash/proof/sig verified in the body
    param_re = re.compile(
        r"\b([A-Z]\w*)\s+(?:memory|calldata)\s+([A-Za-z_]\w*)")
    struct_params = [(pm.group(2)) for pm in param_re.finditer(header)]
    if _VERIFY_CALL.search(body):
        for p in struct_params:
            # only credit a struct param actually referenced in a verify/hash call arg,
            # else any struct param passing through would count
            if re.search(re.escape(p) + r"\b", body):
                roots.add(p)
                ev.append(f"verified-request:{p}")
    return roots, ";".join(sorted(set(ev)))


def _classify_arg(arg, state_vars, bound_roots):
    """Return 'replayed' | 're-derived' | 'inert' for one sink argument expression."""
    a = arg.strip()
    if not a:
        return "inert"
    # replayed: references a bound-handle root token
    for r in bound_roots:
        if re.search(r"\b" + re.escape(r) + r"\b", a):
            return "replayed"
    if _INERT_ARG.match(a):
        return "inert"
    # re-derived from a live external getter / block value
    if _EXT_GETTER.search(a) or _LIVE_BLOCK.search(a):
        return "re-derived"
    # re-derived from a mutable contract state variable read (not a bound handle)
    for m in re.finditer(r"\b([A-Za-z_]\w*)\b", a):
        tok = m.group(1)
        if tok in state_vars and tok not in bound_roots:
            return "re-derived"
    return "inert"


def _stable_id(file_rel, fn, sink_line, arg):
    h = hashlib.sha1()
    h.update(f"{file_rel}|{fn}|{sink_line}|{arg}".encode())
    return h.hexdigest()[:16]


def scan_file_sol(path: Path, rel: str, file_text: str = None):
    raw = file_text if file_text is not None else path.read_text(
        encoding="utf-8", errors="ignore")
    text = _mask_comments(raw)
    lines = text.split("\n")
    state_vars = _solidity_state_vars(lines)
    rows = []
    for name, header, body, hdr_idx, body_idx in _iter_functions_sol(lines):
        bound_roots, ev = _bound_handles_sol(name, header, body)
        is_exec = bool(_EXEC_VERB.match(name)) or bool(_BIND_FIELD_RE.search(header)) \
            or bool(_VERIFY_CALL.search(body))
        if not bound_roots or not is_exec:
            continue
        # scan security-relevant sinks in the body
        for sm in _SINK_RE.finditer(body):
            # find the '(' that opens this sink's arg list (last '(' in the match)
            paren = body.rfind("(", sm.start(), sm.end())
            if paren < 0:
                continue
            argstr, _ = _extract_call_args(body, paren)
            args = _split_top_args(argstr)
            # line number of the sink within the file
            sink_line = body_idx + body[:sm.start()].count("\n") + 1
            for arg in args:
                cls = _classify_arg(arg, state_vars, bound_roots)
                if cls != "re-derived":
                    continue
                rows.append({
                    "schema": HYP_SCHEMA,
                    "capability": CAPABILITY,
                    "id": _stable_id(rel, name, sink_line, arg),
                    "file": rel,
                    "function": name,
                    "line": sink_line,
                    "lang": "solidity",
                    "bound_handle": sorted(bound_roots),
                    "bound_evidence": ev,
                    "sink": body[sm.start():min(sm.end() + 1, len(body))].strip(),
                    "re_derived_arg": arg,
                    "replayed_from_R": False,
                    "re_derived_from_mutable_state": True,
                    "fires": True,
                    "verdict": "needs-fuzz",
                    "advisory": True,
                    "auto_credit": False,
                    "question": (
                        f"execute-phase `{name}` is gated on committed request "
                        f"{sorted(bound_roots)} but passes security-relevant sink arg "
                        f"`{arg}` re-read from MUTABLE state instead of replaying the value "
                        f"bound at authorize time - can an attacker move that state between "
                        f"the authorize and execute phases?"),
                })
    return rows


# ------------------------------------- Go arm ----------------------------------------
def _iter_functions_go(lines):
    n = len(lines)
    i = 0
    fn_re = re.compile(r"^\s*func\s*(?:\([^)]*\))?\s*([A-Za-z_]\w*)\s*\(")
    while i < n:
        m = fn_re.match(lines[i])
        if not m:
            i += 1
            continue
        name = m.group(1)
        depth = 0
        started = False
        body_lines = []
        k = i
        while k < n:
            depth += lines[k].count("{") - lines[k].count("}")
            body_lines.append(lines[k])
            if "{" in lines[k]:
                started = True
            if started and depth <= 0:
                break
            k += 1
        yield name, "\n".join(body_lines), i, i
        i = max(k, i + 1)


def scan_file_go(path: Path, rel: str, file_text: str = None):
    raw = file_text if file_text is not None else path.read_text(
        encoding="utf-8", errors="ignore")
    text = _mask_comments(raw)
    lines = text.split("\n")
    rows = []
    for name, body, hdr_idx, body_idx in _iter_functions_go(lines):
        if not _GO_EXEC_NAME.search(name):
            continue
        # bound handle: a request loaded via k.GetX(ctx, id) / a `req :=` / a param named req/msg
        bound = set()
        # a REQUEST load (not any getter): `req := k.GetWithdrawal(ctx,id)` - the getter name
        # must denote a stored request, else a live-state getter (GetBalance) would falsely
        # bind and mask the very re-derivation we hunt.
        _req_load = re.compile(
            r"\b([A-Za-z_]\w*)\s*(?::=|,\s*\w+\s*:=)\s*[\w\.]*Get\w*"
            r"(?:Withdrawal|Request|Order|Proposal|Message|Msg|Operation|Op|Ticket|"
            r"Claim|Queue|Voucher|Pending|Scheduled)\w*\s*\(", re.I)
        for m in _req_load.finditer(body):
            bound.add(m.group(1))
        for m in re.finditer(r"\b(req|request|msg|order|withdrawal|proposal|op)\b", body):
            bound.add(m.group(1))
        if not bound:
            continue
        # locals tainted by a live getter read (`amt := k.GetBalance(ctx, x)`): a value
        # re-derived from mutable keeper state, not replayed from the bound request.
        tainted = set()
        for m in re.finditer(r"\b([A-Za-z_]\w*)\s*(?::=|=)\s*[^\n]*", body):
            lhs, rhs = m.group(1), m.group(0)
            if lhs in bound:
                continue
            if _GO_GETTER.search(rhs):
                tainted.add(lhs)
        for sm in _GO_SINK.finditer(body):
            paren = body.find("(", sm.start())
            if paren < 0:
                continue
            argstr, _ = _extract_call_args(body, paren)
            args = _split_top_args(argstr)
            sink_line = body_idx + body[:sm.start()].count("\n") + 1
            for arg in args:
                a = arg.strip()
                if not a:
                    continue
                replayed = any(re.search(r"\b" + re.escape(r) + r"\b", a) for r in bound)
                if replayed:
                    continue
                arg_tainted = any(re.fullmatch(re.escape(t), a) for t in tainted)
                if _GO_GETTER.search(a) or arg_tainted:
                    rows.append({
                        "schema": HYP_SCHEMA,
                        "capability": CAPABILITY,
                        "id": _stable_id(rel, name, sink_line, a),
                        "file": rel,
                        "function": name,
                        "line": sink_line,
                        "lang": "go",
                        "bound_handle": sorted(bound),
                        "bound_evidence": "go-request-load",
                        "sink": body[sm.start():min(sm.end() + 1, len(body))].strip(),
                        "re_derived_arg": a,
                        "replayed_from_R": False,
                        "re_derived_from_mutable_state": True,
                        "fires": True,
                        "verdict": "needs-fuzz",
                        "advisory": True,
                        "auto_credit": False,
                        "question": (
                            f"execute-phase `{name}` loads a stored request {sorted(bound)} "
                            f"but re-reads sink arg `{a}` from a live keeper getter instead "
                            f"of the value bound at request time - drivable between phases?"),
                    })
    return rows


# ---------------------------------- driver -------------------------------------------
def scan_tree(root: Path):
    rows = []
    for p in _iter_source_files(root, (".sol",)):
        try:
            rel = str(p.relative_to(root))
        except ValueError:
            rel = str(p)
        rows.extend(scan_file_sol(p, rel))
    for p in _iter_source_files(root, (".go",)):
        try:
            rel = str(p.relative_to(root))
        except ValueError:
            rel = str(p)
        rows.extend(scan_file_go(p, rel))
    return rows


def scan_path(p: Path):
    if p.suffix == ".go":
        return scan_file_go(p, p.name)
    return scan_file_sol(p, p.name)


def _emit_sidecar(ws: Path, rows):
    outdir = ws / ".auditooor"
    outdir.mkdir(parents=True, exist_ok=True)
    out = outdir / _SIDE_NAME
    with out.open("w") as fh:
        for r in rows:
            fh.write(json.dumps(r) + "\n")
    return out


def _summary(rows):
    fired = [r for r in rows if r.get("fires")]
    return {
        "schema": HYP_SCHEMA,
        "capability": CAPABILITY,
        "enforcement_points": len(rows),
        "fired": len(fired),
        "files": sorted({r["file"] for r in fired}),
        "verdict": "needs-fuzz" if fired else "clean-advisory",
        "advisory": True,
        "auto_credit": False,
    }


def main(argv=None):
    ap = argparse.ArgumentParser(
        description="MQ-B03 deferred-execution param-binding screen (advisory)")
    ap.add_argument("--workspace", "--ws")
    ap.add_argument("--source")
    ap.add_argument("--file")
    ap.add_argument("--check", action="store_true")
    ap.add_argument("--strict", action="store_true")
    ap.add_argument("--json", action="store_true")
    args = ap.parse_args(argv)

    strict = args.strict or os.environ.get(_STRICT_ENV, "").strip() not in ("", "0", "false")

    if args.file:
        rows = scan_path(Path(args.file))
        print(json.dumps(rows, indent=2))
        return 0

    if args.source:
        rows = scan_tree(Path(args.source))
        print(json.dumps(rows, indent=2))
        return 0

    if not args.workspace:
        ap.error("one of --workspace / --source / --file is required")

    ws = Path(args.workspace)
    if not ws.is_absolute():
        cand = Path("/Users/wolf/audits") / args.workspace
        if cand.exists():
            ws = cand
    side = ws / ".auditooor" / _SIDE_NAME

    if args.check:
        rows = []
        if side.exists():
            rows = [json.loads(l) for l in side.read_text().splitlines() if l.strip()]
        summ = _summary(rows)
        summ["source"] = "sidecar"
        print(json.dumps(summ, indent=2))
        return 1 if (strict and summ["fired"]) else 0

    src = ws / "src"
    root = src if src.exists() else ws
    rows = scan_tree(root)
    _emit_sidecar(ws, rows)
    summ = _summary(rows)
    print(json.dumps(summ, indent=2))
    return 1 if (strict and summ["fired"]) else 0


if __name__ == "__main__":
    sys.exit(main())
