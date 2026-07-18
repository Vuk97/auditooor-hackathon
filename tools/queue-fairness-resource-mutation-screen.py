#!/usr/bin/env python3
"""queue-fairness-resource-mutation-screen.py - the QUEUE-FAIRNESS RESOURCE-MUTATION screen (EXT2_04).

GENERAL enforcement-layer / ORDERING-invariant class (never a bug SHAPE, never an impact
silo). It instantiates the north-star method ("a TRUSTED ENFORCEMENT is bypassable or its
private invariant is unsound") for ONE ordering enforcement that the freshness / param-
binding screens cannot reach - queue FAIRNESS when the shared resource pool mutates BETWEEN
a request's enqueue and its service:

  ORDERING INVARIANT : a FIFO / priority queue, rate-limiter, or reservation ledger holds a
    set of PENDING requests that share ONE finite resource pool (liquidity, quota, allowance,
    epoch budget, reserve). The invariant the queue exists to protect is
       "if the queue is NON-EMPTY, a newly-arriving request must NOT be serviced in full
        (or ahead) of the older queued entries."
  ATTACK             : between the OLD request's enqueue and its service, the shared pool
    MUTATES (a deposit / repay / harvest / reconcile / reserve top-up / epoch reset makes
    liquidity freshly available). A NEW request that arrives with the fresh pool is satisfied
    DIRECTLY from it - because the service guard gates on INSTANTANEOUS RESOURCE AVAILABILITY
    ("do I have enough right now?") rather than on QUEUE-NONEMPTINESS ("is anyone ahead of
    me?"). The older queued entries starve. Every individual operation is locally sound; the
    violation lives only in the temporal ordering across two state-mutating operations.

ANCHOR: Certora FV of infiniFi redemptions - freshly-available liquidity could fully satisfy
a NEW redemption while an older queued request stayed pending, breaking the invariant "if the
redemption queue is non-empty, a new redemption must not receive the full asset amount".
https://www.certora.com/blog/ensuring-fair-redemptions-in-infinifi-with-formal-verification

Enforcement point = ONE function that, inside a module that maintains a pending queue,
directly SERVICES a request (pays / transfers / mints to a recipient) and gates only on an
INSTANTANEOUS availability read (balanceOf(this) / totalAssets() / getReserves() /
SpendableCoins / a `reserve`/`available` comparison). Per point the screen answers:
  {queue_present, reads_instantaneous_availability, has_value_sink, enqueues?,
   walks_or_dequeues_queue?, gates_on_queue_nonemptiness?}
and FIRES (verdict=needs-fuzz) ONLY when a service point is availability-gated AND does NOT
gate on queue-nonemptiness AND does NOT itself enqueue (the safe request-creation path) AND
does NOT walk / dequeue the queue (the legit in-order FIFO drainer). A point that consults
the queue head / length / emptiness, or that iterates the queue in order, is SILENT.

Why net-new: no overflow / reentrancy / missing access-control - the bypass is a cross-
request temporal ordering violation that AST/pattern detectors have no notion of. The nearest
wired caps (ordering-dependent-invariant E9 = intra-function refresher-domination;
deferred-execution-param-binding MQ-B03 = param replay across a two-phase boundary) cannot see
a queue-position / FIFO-fairness violation that spans enqueue+service.

ADVISORY-FIRST: every row carries verdict='needs-fuzz', advisory=True, auto_credit=False. It
NEVER auto-credits and NEVER fail-closes in default mode. --strict (or the env
AUDITOOOR_QUEUE_FAIRNESS_STRICT) only raises the exit code; it still emits no credit.

Languages: Solidity (redemption/withdrawal-queue vaults) and Go (cosmos keeper pending-queue).
Machine-generated (protobuf/abigen/codegen), test, sim, and chimera scaffolding are excluded.

Usage:
  --workspace <ws>   scan <ws>/src -> .auditooor/queue_fairness_resource_mutation_hypotheses.jsonl + summary
  --source <dir>     scan an arbitrary dir, print rows as JSON (NO sidecar - for tests/verify)
  --file <f>         scan a single .sol/.go file, print rows as JSON
  --check            re-read the emitted sidecar, print cert verdict (advisory)
  --strict           (or env) elevate exit code when a fired point exists
  --json             machine summary to stdout
"""
from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import os
import re
import sys
from pathlib import Path

TOOLS_DIR = Path(__file__).resolve().parent
if str(TOOLS_DIR) not in sys.path:
    sys.path.insert(0, str(TOOLS_DIR))

# Shared synthetic/codegen/test exclusion (single source of truth).
from lib.synthetic_target_exclusion import (  # noqa: E402
    is_chimera_mutation_harness_path,
    is_codegen_path,
    is_test_target_path,
)

HYP_SCHEMA = "auditooor.queue_fairness_resource_mutation_hypotheses.v1"
KEY = "EXT2_04"
CAPABILITY = "EXT2_04-queue-fairness-resource-mutation"
_SIDE_NAME = "queue_fairness_resource_mutation_hypotheses.jsonl"
_STRICT_ENV = "AUDITOOOR_QUEUE_FAIRNESS_STRICT"

_SKIP_DIRS = {"target", ".git", "node_modules", "vendor", "_archive", "out",
              "cache", "lib", "__pycache__", "dist", "build", ".auditooor",
              "forge-artifacts", "artifacts", "benches", "benchmarks", "coverage",
              "chimera_harnesses", "certora", "fuzz_run", "fuzz_run_manip"}
_TEST_HINT = re.compile(
    r"(^|/)(tests?|test_fixtures|mock|mocks|script|scripts|examples?|fuzz|echidna|"
    r"halmos|chimera_harnesses|harness|simulation|simapp|testdata)(/|$)", re.I)
_TEST_FILE = re.compile(r"(\.t\.sol$|_test\.go$|Mock|\.s\.sol$|Test\.sol$|Invariant)", re.I)


# ----- load the sibling screen's _is_generated_source (mandated for the walk) ---------
def _load_generated_source_predicate():
    """Import _is_generated_source from declared-control-mutator-completeness-screen.py.

    Faithfully reuses the sibling's codegen predicate (suffix fast-path + Go/`go generate`
    'Code generated ... DO NOT EDIT' sentinel). Falls back to a byte-identical local replica
    if the sibling cannot be loaded (never fails the walk)."""
    sib = TOOLS_DIR / "declared-control-mutator-completeness-screen.py"
    try:
        spec = importlib.util.spec_from_file_location("_dcm_screen", sib)
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)  # type: ignore[union-attr]
        return mod._is_generated_source
    except Exception:
        _gen_suffixes = (".pb.go", ".pulsar.go", ".pb.gw.go", "_gen.go", ".gen.go",
                         "_generated.go")
        _gen_sentinel = re.compile(r"Code generated .{0,80}?DO NOT EDIT", re.I)

        def _fallback(path: Path) -> bool:
            if path.name.lower().endswith(_gen_suffixes):
                return True
            try:
                with open(path, "r", encoding="utf-8", errors="replace") as fh:
                    head = fh.read(4096)
            except (OSError, UnicodeError):
                return False
            return bool(_gen_sentinel.search(head))
        return _fallback


_IS_GENERATED_SOURCE = _load_generated_source_predicate()


# -------------------------------------------------------------------------------------
def _mask_comments(text: str) -> str:
    """Blank // and /* */ comments, preserving newlines + per-line length so line indices
    stay aligned. Not string-literal aware -> errs toward SILENCE (can only drop a token,
    never invent a sink/gate), the safe direction for an advisory screen."""
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


def _excluded_path(p: Path) -> bool:
    s = str(p).replace(os.sep, "/")
    if is_chimera_mutation_harness_path(s) or is_test_target_path(s):
        return True
    if is_codegen_path(s):
        return True
    if _IS_GENERATED_SOURCE(p):
        return True
    return False


def _iter_source_files(root: Path, exts):
    for dp, dn, fn in os.walk(root):
        dn[:] = [d for d in dn if d not in _SKIP_DIRS]
        if _TEST_HINT.search(dp.replace(os.sep, "/")):
            continue
        for f in fn:
            if not any(f.endswith(e) for e in exts):
                continue
            if _TEST_FILE.search(f):
                continue
            p = Path(dp) / f
            if _excluded_path(p):
                continue
            yield p


# ================================ shared predicates ==================================
# QUEUE PRESENCE (module/file scope): the ordering invariant only exists where a pending
# REQUEST queue is maintained. We require genuine request-FIFO SEMANTICS (enqueue/dequeue
# verbs, a WalkDue drainer, a pending-request store, a request-id cursor, or an explicit
# redemption/payout/claim queue) - NOT a bare `*Queue` noun. A bare `*Queue` collides with
# market-priority lists (MetaMorpho `withdrawQueue`/`supplyQueue` are arrays of market Id,
# not queued user requests sharing a pool) and would spray false enforcement points. A real
# withdrawal FIFO also carries enqueue/dequeue or a request cursor, so it is still caught.
_QUEUE_PRESENCE_RE = re.compile(
    r"\benqueue\w*\b|\bdequeue\w*\b"
    r"|\bWalkDue\b|\bPendingSwapOut\w*\b"
    r"|\bpendingRedemptions?\b|\bpendingWithdrawals?\b|\bpendingSwapOuts?\b"
    r"|\bredemptionRequests?\b|\bwithdrawalRequests?\b|\bpendingRequests?\b|\bpendingClaims?\b"
    r"|\b(?:redemption|redeem|payout|claim|unstake|swap[Oo]ut|reservation)\w*[Qq]ueue\b"
    r"|\b[Qq]ueued(?:Redemption|Withdrawal|Request|Payout|Claim)s?\b"
    r"|\bfirstUnprocessed\w*\b|\bnextRequestId\b|\blastProcessedId\b|\bnextToServe\w*\b"
    r"|\bnextWithdrawalId\b|\bnextRedemptionId\b|\bnextClaimId\b"
    r"|\bheadRequest\b|\btailRequest\b|\brequestHead\b|\brequestTail\b")


def _has_queue_structure(text: str) -> bool:
    return bool(_QUEUE_PRESENCE_RE.search(text))


# ----------------------------------- Solidity ----------------------------------------
# INSTANTANEOUS availability reads (the guard the enforcement shape forbids as the SOLE gate)
_AVAIL_SOL = re.compile(
    r"\.\s*balanceOf\s*\(\s*address\s*\(\s*this\s*\)\s*\)"        # token.balanceOf(address(this))
    r"|address\s*\(\s*this\s*\)\s*\.\s*balance\b"                 # address(this).balance
    r"|\.\s*totalAssets\s*\(\s*\)"                                # vault.totalAssets()
    r"|\.\s*getReserves?\s*\("                                    # pair.getReserves()
    r"|\.\s*getCash\s*\(|\bgetCash\s*\("                          # money-market cash
    r"|\.\s*maxWithdraw\s*\(|\.\s*availableLiquidity\s*\(")
# availability-ish identifier used in a numeric comparison on the SAME line
_AVAIL_IDENT_SOL = re.compile(
    r"\b(availableLiquidity|available|liquidity|reserves?|freeAssets|idleAssets|idle|"
    r"cash|buffer|spendable|withdrawable|freeBalance)\b")
_CMP = re.compile(r"(>=|<=|!=|==|>|<)")

# direct value sink to a recipient (the "service" act)
_SINK_SOL = re.compile(
    r"\.\s*safeTransfer(?:From)?\s*\("
    r"|\.\s*transfer(?:From)?\s*\("
    r"|\.\s*send\s*\("
    r"|\.\s*call\s*\{[^}]*value[^}]*\}\s*\("
    r"|\bpayable\s*\([^)]*\)\s*\.\s*(?:transfer|send)\s*\("
    r"|\b_?mint\s*\(|\bsafeMint\s*\(")

# ENQUEUE (safe request-creation path - excluded)
_ENQUEUE_SOL = re.compile(
    r"\benqueue\w*\s*\(|\b_enqueue\w*\s*\(|\.\s*push\s*\(|\.\s*append\s*\("
    r"|\b\w*[Qq]ueue\w*\s*\[[^\]]*\]\s*="
    r"|\b(?:pending|withdrawal|redemption)\w*[Rr]equests?\s*\[[^\]]*\]\s*="
    r"|\bcreate(?:Withdrawal|Redemption|Request)\w*\s*\(")

# WALK / DEQUEUE the queue in order (the legit FIFO drainer - excluded)
_DRAIN_SOL = re.compile(
    r"\bdequeue\w*\s*\(|\b_dequeue\w*\s*\(|\.\s*pop\s*\(|\bpopFront\s*\("
    r"|\b(?:process|drain|service|advance|settle|fulfill)Queue\w*\s*\("
    r"|\bfor\s*\([^)]*[Qq]ueue|\bwhile\s*\([^)]*[Qq]ueue")

# gate on QUEUE-NONEMPTINESS (the SAFE gate whose presence makes the point SILENT)
_QGATE_SOL = re.compile(
    r"\b\w*[Qq]ueue\w*\s*\.\s*(?:length|len|size|count|empty|isEmpty)\b"
    r"|\bqueueLength\b|\bqueueSize\b|\bpendingCount\b|\bnumPending\b|\btotalPending\b"
    r"|\bhead\s*(?:==|!=)\s*tail\b|\btail\s*(?:==|!=)\s*head\b"
    r"|\bnextRequestId\s*(?:==|!=|>=|>)\s*(?:lastProcessed|lastServed|nextToServe|firstUnprocessed)\w*"
    r"|\b(?:firstUnprocessed|nextToProcess|nextToServe)\w*\s*(?:==|!=|>=|<|>)"
    r"|\.\s*isEmpty\s*\(|\.\s*empty\s*\("
    r"|\b(?:process|drain|service)Queue\w*\s*\(")

_SERVICE_VERB = re.compile(
    r"(withdraw|redeem|claim|payout|pay_?out|unstake|settle|fulfill|distribute|"
    r"process|swapout|swap_?out|dispatch|release|complete)", re.I)


def _line_has_avail_ident(body: str) -> bool:
    for ln in body.split("\n"):
        if _AVAIL_IDENT_SOL.search(ln) and _CMP.search(ln):
            return True
    return False


def _reads_instantaneous_availability_sol(body: str) -> bool:
    """CORE PREDICATE (Solidity). True when the body gates on an instantaneous resource-pool
    read - a live balance/reserve/liquidity value the enforcement shape forbids as the SOLE
    guard. Neutralizing this to a constant collapses every fired hypothesis."""
    if _AVAIL_SOL.search(body):
        return True
    return _line_has_avail_ident(body)


# ------------------------------------- Go arm ----------------------------------------
_AVAIL_GO = re.compile(
    r"\.\s*SpendableCoins?\s*\(|\.\s*SpendableCoin\s*\(|\.\s*GetBalance\s*\("
    r"|\.\s*GetAllBalances\s*\(|\.\s*GetSupply\s*\(|\bAllowSwapOut\w*\s*\("
    r"|\.\s*LockedCoins\s*\(|\.\s*GetAccountBalance\s*\(")
_AVAIL_IDENT_GO = re.compile(
    r"\b(available\w*|reserve\w*|liquidity\w*|spendable\w*|freeBalance\w*|cash)\b", re.I)

_SINK_GO = re.compile(
    r"\.\s*SendCoins\w*\s*\(|\.\s*SendCoinsFromModule\w*\s*\(|\.\s*MintCoins\s*\("
    r"|\.\s*Transfer\w*\s*\(|\.\s*DelegateCoins\s*\(|\.\s*SendManyCoins\s*\(")

_ENQUEUE_GO = re.compile(r"\.\s*Enqueue\w*\s*\(|\.\s*Push\s*\(|\bEnqueue\w*\s*\(")
_DRAIN_GO = re.compile(
    r"\.\s*Dequeue\w*\s*\(|\.\s*Walk\w*\s*\(|\.\s*Iterate\w*\s*\(|\.\s*Peek\s*\("
    r"|\.\s*Front\s*\(|\.\s*WalkDue\s*\(|\bfor\s+[^\n{]*[Qq]ueue")
_QGATE_GO = re.compile(
    r"\.\s*IsEmpty\s*\(|\.\s*Len\s*\(|\.\s*Peek\s*\(|\.\s*Front\s*\(|\.\s*Size\s*\("
    r"|\b\w*[Qq]ueue\w*\s*\.\s*(?:Len|Size|IsEmpty|Count)\b|\.\s*WalkDue\s*\(|\.\s*Walk\s*\(")

_GO_SERVICE_VERB = re.compile(
    r"(SwapOut|Redeem|Withdraw|Payout|Claim|Fulfill|Distribute|Settle|Process|"
    r"Release|Complete|Dispatch|Pay)")


def _reads_instantaneous_availability_go(body: str) -> bool:
    """CORE PREDICATE (Go). Live keeper-state availability read used as the service guard."""
    if _AVAIL_GO.search(body):
        return True
    for ln in body.split("\n"):
        if _AVAIL_IDENT_GO.search(ln) and _CMP.search(ln):
            return True
    return False


# NEUTRALIZE HOOK: both language cores route through this module-level dispatcher so a test
# can monkeypatch ONE symbol (`_reads_instantaneous_availability`) to a constant and stop
# every fired hypothesis (the non-vacuity neutralize leg).
def _reads_instantaneous_availability(body: str, lang: str) -> bool:
    if lang == "go":
        return _reads_instantaneous_availability_go(body)
    return _reads_instantaneous_availability_sol(body)


# --------------------------- function extraction (sol) -------------------------------
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
        header_lines = []
        j = i
        opened = False
        while j < n:
            header_lines.append(lines[j])
            if "{" in lines[j]:
                opened = True
                break
            if ";" in lines[j] and "{" not in lines[j]:
                break
            j += 1
        if not opened:
            i = j + 1
            continue
        header = "\n".join(header_lines)
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


def _stable_id(file_rel, fn, line):
    h = hashlib.sha1()
    h.update(f"{KEY}|{file_rel}|{fn}|{line}".encode())
    return h.hexdigest()[:16]


def _mk_row(rel, name, line, lang, fires, evid):
    row = {
        "schema": HYP_SCHEMA,
        "capability": CAPABILITY,
        "key": KEY,
        "id": _stable_id(rel, name, line),
        "file": rel,
        "function": name,
        "line": line,
        "lang": lang,
        "fires": bool(fires),
        "advisory": True,
        "auto_credit": False,
        "verdict": "needs-fuzz",
        # class fields (per-point enforcement enumeration)
        "queue_present": True,
        "reads_instantaneous_availability": evid["avail"],
        "has_value_sink": evid["sink"],
        "enqueues": evid["enqueue"],
        "walks_or_dequeues_queue": evid["drain"],
        "gates_on_queue_nonemptiness": evid["qgate"],
        "question": (
            f"service point `{name}` sits in a module that maintains a pending queue and pays "
            f"a recipient gated on INSTANTANEOUS resource availability, but does NOT gate on "
            f"queue-nonemptiness, enqueue the request, or drain the queue in order - if the "
            f"pool is topped up (deposit/repay/harvest/reserve/epoch-reset) between an older "
            f"request's enqueue and its service, can this NEW request jump the queue and "
            f"starve the older one? (Certora infiniFi redemption-fairness class)"
            if fires else
            f"service point `{name}` is enumerated for queue-fairness; it is SAFE here "
            f"(enqueue={evid['enqueue']} drain={evid['drain']} queue-gate={evid['qgate']})."),
    }
    return row


def scan_file_sol(path: Path, rel: str, queue_present: bool, file_text: str = None):
    raw = file_text if file_text is not None else path.read_text(
        encoding="utf-8", errors="ignore")
    text = _mask_comments(raw)
    if not queue_present and not _has_queue_structure(text):
        return []
    lines = text.split("\n")
    rows = []
    for name, header, body, hdr_idx, body_idx in _iter_functions_sol(lines):
        visible = bool(re.search(r"\b(external|public)\b", header))
        service = visible or bool(_SERVICE_VERB.search(name))
        has_sink = bool(_SINK_SOL.search(body))
        reads_avail = _reads_instantaneous_availability(body, "solidity")
        if not (service and has_sink and reads_avail):
            continue
        enqueue = bool(_ENQUEUE_SOL.search(body))
        drain = bool(_DRAIN_SOL.search(body))
        qgate = bool(_QGATE_SOL.search(body))
        fires = not (enqueue or drain or qgate)
        line = hdr_idx + 1
        evid = {"avail": reads_avail, "sink": has_sink, "enqueue": enqueue,
                "drain": drain, "qgate": qgate}
        rows.append(_mk_row(rel, name, line, "solidity", fires, evid))
    return rows


def scan_file_go(path: Path, rel: str, queue_present: bool, file_text: str = None):
    raw = file_text if file_text is not None else path.read_text(
        encoding="utf-8", errors="ignore")
    text = _mask_comments(raw)
    if not queue_present and not _has_queue_structure(text):
        return []
    lines = text.split("\n")
    rows = []
    for name, body, hdr_idx, body_idx in _iter_functions_go(lines):
        exported = bool(name[:1].isupper())
        service = exported and bool(_GO_SERVICE_VERB.search(name))
        has_sink = bool(_SINK_GO.search(body))
        reads_avail = _reads_instantaneous_availability(body, "go")
        if not (service and has_sink and reads_avail):
            continue
        enqueue = bool(_ENQUEUE_GO.search(body))
        drain = bool(_DRAIN_GO.search(body))
        qgate = bool(_QGATE_GO.search(body))
        fires = not (enqueue or drain or qgate)
        line = hdr_idx + 1
        evid = {"avail": reads_avail, "sink": has_sink, "enqueue": enqueue,
                "drain": drain, "qgate": qgate}
        rows.append(_mk_row(rel, name, line, "go", fires, evid))
    return rows


# ---------------------------------- driver -------------------------------------------
def _dir_queue_presence(root: Path, exts):
    """Pass-1: directories (immediate parent of a source file) whose files declare a queue
    structure. Queue-fairness is a MODULE property (Go package / Solidity contract dir); a
    service function in a sibling file of the same package inherits the module's queue."""
    qdirs = set()
    qfiles = {}
    for p in _iter_source_files(root, exts):
        try:
            txt = _mask_comments(p.read_text(encoding="utf-8", errors="ignore"))
        except OSError:
            continue
        present = _has_queue_structure(txt)
        qfiles[p] = present
        if present:
            qdirs.add(p.parent)
    return qdirs, qfiles


def scan_tree(root: Path):
    rows = []
    for exts, scan in ((".sol", scan_file_sol), (".go", scan_file_go)):
        qdirs, qfiles = _dir_queue_presence(root, (exts,))
        for p, present in qfiles.items():
            queue_present = present or (p.parent in qdirs)
            if not queue_present:
                continue
            try:
                rel = str(p.relative_to(root))
            except ValueError:
                rel = str(p)
            rows.extend(scan(p, rel, queue_present=True))
    return rows


def scan_path(p: Path):
    """Single-file scan: queue presence must be file-local."""
    if p.suffix == ".go":
        return scan_file_go(p, p.name, queue_present=_has_queue_structure(
            _mask_comments(p.read_text(encoding="utf-8", errors="ignore"))))
    return scan_file_sol(p, p.name, queue_present=_has_queue_structure(
        _mask_comments(p.read_text(encoding="utf-8", errors="ignore"))))


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
        "key": KEY,
        "enforcement_points": len(rows),
        "fired": len(fired),
        "files": sorted({r["file"] for r in fired}),
        "verdict": "needs-fuzz" if fired else "clean-advisory",
        "advisory": True,
        "auto_credit": False,
    }


def main(argv=None):
    ap = argparse.ArgumentParser(
        description="EXT2_04 queue-fairness resource-mutation screen (advisory)")
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
        return 1 if (strict and any(r["fires"] for r in rows)) else 0

    if args.source:
        rows = scan_tree(Path(args.source))
        print(json.dumps(rows, indent=2))
        return 1 if (strict and any(r["fires"] for r in rows)) else 0

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
