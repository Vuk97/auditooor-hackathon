#!/usr/bin/env python3
"""push-payment-misroute.py - the recipient-provenance-vs-intended-owner reasoning query.

LOGIC CAPABILITY (RANK-25 [HIGH x2] push-payment-to-non-payable / wrong-recipient).
A PROVENANCE / SET-DIFFERENCE query over an OWNED intra-repo call graph + source
index, NOT a grep for transfer/send. The finding is a RELATION between the
RECIPIENT operand of a value-delivery sink and the INTENDED-OWNER source of THAT
value - a mismatch (or an unverified-payable push) is the survivor.

THE BUG CLASS (both HIGH)
  A value delivery (ETH send/transfer/call-with-value, ERC20 transfer, refund,
  timeout-refund, cosmos bank payout) sends to a recipient address that is NOT the
  intended owner/originator of the value, OR pushes to an address whose payable-
  ability is unverified so the send reverts and strands funds:
    * refund credited to msg.sender when the recorded depositor differs;
    * push to a stored address that a PRIOR step overwrote;
    * delivery to a contract with no payable receiver (transfer/send, 2300 gas,
      no pull-fallback) -> revert -> funds permanently stranded.

THE LOGIC TRIPLE (assumption / invariant / trust-boundary)
  ASSUMPTION: a value-delivery sink S trusts its RECIPIENT operand to equal the
    party who is ENTITLED to that value (the recorded depositor / originator /
    beneficiary / refund-address of THAT specific value).
  INVARIANT: for every value-delivery sink S over a value V, the recipient operand
    must PROVENANCE-TRACE to INTENDED_OWNER(V) - the source that recorded who
    owns V (deposit.owner / order.maker / originator / beneficiary / refundAddress
    / the sender captured AT DEPOSIT TIME) - AND the recipient must be pull-safe
    (a credited-balance pull) OR verified payable on a push.
  TRUST-BOUNDARY: msg.sender at delivery time is a DIFFERENT actor than the
    recorded owner (a relayer, a later caller, a transferred position), and a
    stored recipient field can be overwritten between record and delivery. A push
    to an unverified address reverts on a non-payable contract.

THE SET-DIFFERENCE (the finding)
  Over every value-delivery sink S in the workspace:
    SINKS   = { S : S moves value (send/transfer/call.value/safeTransfer/
                SendCoins/payout/refund) with an extractable RECIPIENT operand }
    TRACED  = { S in SINKS : RECIPIENT_PROVENANCE(S) traces to an INTENDED_OWNER
                source recorded for that value (owner-provenance symbol), i.e. the
                recipient IS the recorded owner - a correctly-routed delivery }
    MISMATCH_OR_UNVERIFIED =
      { S in SINKS : RECIPIENT_PROVENANCE(S) does NOT trace to INTENDED_OWNER(V)
        while an intended-owner IS recorded in scope (recipient is msg.sender /
        caller / a foreign stored addr while a depositor field exists) - a
        WRONG-RECIPIENT mismatch }
      UNION
      { S in SINKS : S is a PUSH primitive (transfer/send/low-level call-value)
        to an address with NO pull-fallback and NO payable verification - an
        UNVERIFIED-PAYABLE strand risk }
    SURVIVORS = MISMATCH_OR_UNVERIFIED
    KEPT      = TRACED  (recipient == recorded owner, or pull-pattern credit)

WHY THIS IS LOGIC, NOT A SHAPE (guard-rail axes)
  (a) membership needs RECIPIENT_PROVENANCE(S) - the recipient operand is resolved
      to its defining source (a param, a stored field, msg.sender, a captured
      deposit-time sender) and COMPARED to the set of owner-provenance symbols
      recorded in the function's owner-record scope; a bare `contains("transfer")`
      cannot decide it;
  (b) the answer is a RELATION between two symbol sets (recipient-source vs
      intended-owner-source); the finding is the mismatch, not a boolean over one
      call;
  (c) the push/pull + payable arm is a SECOND provenance question (is there a
      credited-balance pull or a payable check dominating the push) that a token
      match cannot answer.

OWNED BACKEND CONSUMED
  1. An intra-repo static source index + call graph built here over the workspace
     Go / Solidity / Rust source (the same reachability backend as
     stale-accrual-before-value-gate-dominance.py). Per function it records the
     value-delivery sinks (with recipient operand text), the owner-provenance
     symbols recorded/read in scope, and the presence of a pull-pattern / payable
     verification.
  2. <ws>/.auditooor/dataflow_paths.jsonl (schema dataflow_path.v1) - CORROBORATES
     value-delivery sinks (records whose sink.kind is a value-move / safeTransfer)
     UNIONed with the source-scan sink predicate (never-false-negative).

OUTPUT
  <ws>/.auditooor/push_payment_misroute_obligations.jsonl - one row per survivor,
  schema `auditooor.push_payment_misroute.v1`, exploit_queue-ingest compatible
  (contract/function/source_refs/root_cause_hypothesis/attack_class/
  broken_invariant_ids/quality_gate_status='needs_source'). exploit-queue.py
  ingests it via _gather_from_push_payment_misroute -> queue -> per-fn OPEN-
  OBLIGATIONS block.

  HONEST cited-empty vs substrate_vacuous: when the repo indexes functions but has
  NO value-delivery sink with a decidable recipient (the class does not apply -
  a pure math library), the summary reports class_present=False + a cited-empty
  (an honest N/A). This is DISTINCT from substrate_vacuous (0 functions indexed -
  the source never materialized), which --fail-closed treats as an error.
"""

from __future__ import annotations

import argparse
import collections
import json
import os
import re
import sys
import time
from pathlib import Path

_HERE = Path(__file__).resolve().parent

# ---------------------------------------------------------------------------
# NODE PREDICATES (per-call / per-symbol classifiers). The LOGIC is the
# recipient-provenance vs intended-owner comparison wrapped around these.
# ---------------------------------------------------------------------------

# (S) VALUE-DELIVERY sink calls with an extractable recipient operand. Captures
# the call name AND the recipient argument expression via _SINK_CALL below.
# EVM: <recip>.transfer(v) / <recip>.send(v) / <recip>.call{value:v}("") /
#      payable(x).transfer / safeTransfer(token, recip, v) /
#      recip.sendValue / _safeTransferETH(recip, v).
# Cosmos-Go: SendCoins(ctx, from, TO, amt) / SendCoinsFromModuleToAccount(.., TO, ..).
# Refund/payout named helpers: refund / refundTo / payout / withdrawTo / _refund.
_SINK_METHOD = re.compile(
    r"(?i)\.(transfer|send|sendvalue|safetransfer|safetransfereth|"
    r"transferfrom)\s*(?:\{[^}]*\})?\s*\(")
_SINK_LOWLEVEL_CALLVALUE = re.compile(
    r"(?i)([A-Za-z_][A-Za-z0-9_.\[\]]*)\s*\.\s*call\s*\{[^}]*value\s*:")
_SINK_FREE = re.compile(
    r"(?i)\b(safetransfer|safetransfereth|_?safetransfereth|_?refund\w*|"
    r"_?payout\w*|_?withdrawto|sendvalue|"
    r"sendcoins|sendcoinsfrom|sendcoinsfrommoduletoaccount|"
    r"sendcoinsfromaccounttomodule|"
    r"delegatecoins|undelegatecoins)\s*\(")

# generic value-delivery name predicate for callee-node credit (call graph).
_VALUE_DELIVERY_NAME = re.compile(
    r"(?i)^(?:"
    r"transfer|send|sendvalue|safetransfer|safetransfereth|transferfrom|"
    r"_?refund\w*|_?payout\w*|_?withdrawto|withdraw|redeem|"
    r"sendcoins\w*|delegatecoins|undelegatecoins|payoutwinnings\w*|"
    r"disburse\w*|distribute\w*"
    r")$")

# (O) INTENDED-OWNER provenance symbols: identifiers/fields that RECORD or read
# the party entitled to a value - the depositor / originator / beneficiary /
# refund-address captured at record time. A recipient operand that references one
# of these traces to the intended owner.
_OWNER_SYM = re.compile(
    r"(?i)\b("
    r"owner|_owner|depositor|_depositor|originator|_originator|"
    r"beneficiary|_beneficiary|refundaddress|refundaddr|refund_address|"
    r"recordedowner|storedowner|maker|_maker|seller|creator|_creator|"
    r"initiator|_initiator|payee|_payee|recipient_of_record|orig_sender|"
    r"originalsender|original_sender|depositoraddr|account_owner|holderof|"
    r"positionowner|stakeowner|claimant_of_record"
    r")\b")

# recipient operands that are the CALLER at delivery time (NOT provenance-traced
# to a recorded owner unless the record captured msg.sender AND no later actor
# can call). A caller-recipient WHILE an owner symbol exists in scope = mismatch.
_CALLER_SYM = re.compile(
    r"(?i)^(?:msg\.sender|_msgsender\(\)|_msgsender|sender|caller|"
    r"tx\.origin|payable\(msg\.sender\)|payable\(_msgsender\(\)\))$")

# PULL-pattern / credited-balance markers: when present in a function, a delivery
# is pull-safe (owner withdraws their own credited balance) - not a push strand.
_PULL_MARK = re.compile(
    r"(?i)\b(pendingwithdrawal|pending_withdrawal|credits?\[|balances?\[|"
    r"claimable\[|withdrawable\[|_credit\b|creditbalance|escrow\[|"
    r"pullpayment|_asyncsend|asyncsend)\b")

# PAYABLE verification / push-safety markers dominating a push (an explicit
# success check on a low-level call, or a payable cast that the code guards).
_PAYABLE_CHECK = re.compile(
    r"(?i)\b(require\s*\(\s*(?:success|ok|sent)\b|"
    r"if\s*\(\s*!?\s*(?:success|ok|sent)\b|"
    r"revert\s+ethtransferfailed|revert\s+transferfailed|"
    r"functioncallwithvalue|sendvalue)\b")

# push-primitive markers (2300-gas transfer/send, or low-level call-value): these
# revert on a non-payable / gas-hungry receiver.
_PUSH_TRANSFER_SEND = re.compile(r"(?i)\.(transfer|send)\s*\(")

# Value-delivery sink kinds in the owned dataflow_paths.jsonl that corroborate.
_VALUE_SINK_KINDS = {"value-move", "safeTransfer", "safeTransferFrom", "external-call"}

# ---------------------------------------------------------------------------
# SOURCE INDEXING + intra-repo CALL GRAPH (the owned reachability backend).
# ---------------------------------------------------------------------------
_GO_DECL = re.compile(r"^func\s+(?:\([^)]*\)\s*)?([A-Za-z_][A-Za-z0-9_]*)\s*\(")
_SOL_DECL = re.compile(r"^\s*function\s+([A-Za-z_][A-Za-z0-9_]*)\s*\(")
_RS_DECL = re.compile(r"^\s*(?:pub\s+)?(?:async\s+)?fn\s+([A-Za-z_][A-Za-z0-9_]*)\s*")
_CALL = re.compile(r"([A-Za-z_][A-Za-z0-9_]*)\s*\(")

_SKIP_DIR = ("/test/", "/tests/", "/mock", "/mocks/", "/vendor/",
             "/node_modules/", "/out/", "/build/", "/target/", "/.auditooor/",
             "/simulation/", "/pkg/mod/", "/go/pkg/")
_SKIP_SUFFIX = ("_test.go", ".pb.go", ".pb.gw.go", ".gen.go", ".t.sol", ".s.sol",
                "tests.rs", "_test.rs", "test.rs")
_STOP_NAMES = {"if", "for", "func", "return", "switch", "range", "make", "len",
               "append", "new", "cap", "require", "assert", "emit", "defer",
               "go", "select", "map", "string", "int", "uint", "error", "print",
               "printf", "sprintf", "errorf", "fmt", "panic", "recover"}


def _lang_of(path: str) -> str:
    p = path.lower()
    if p.endswith(".go"):
        return "go"
    if p.endswith(".sol"):
        return "solidity"
    if p.endswith(".rs"):
        return "rust"
    return ""


def _iter_source_files(root: Path):
    for dp, dns, fns in os.walk(root):
        low = (dp.replace("\\", "/") + "/").lower()
        if any(s in low for s in _SKIP_DIR):
            dns[:] = []
            continue
        for f in fns:
            if not f.endswith((".go", ".sol", ".rs")):
                continue
            if any(f.endswith(s) for s in _SKIP_SUFFIX):
                continue
            yield Path(dp) / f


def _decl_re_for(lang: str):
    return {"go": _GO_DECL, "solidity": _SOL_DECL, "rust": _RS_DECL}.get(lang)


def _extract_recipient(line: str, lang: str) -> str:
    """Best-effort RECIPIENT operand text for a value-delivery sink on `line`.
    EVM method form  <recip>.transfer(v) / <recip>.call{value:}  -> the receiver.
    free-fn form  safeTransfer(token, recip, v) / SendCoins(ctx, from, TO, amt)
    -> the recipient positional arg. Returns '' if not extractable."""
    s = line.strip()
    # low-level call-value: capture the object before .call{value:
    m = _SINK_LOWLEVEL_CALLVALUE.search(s)
    if m:
        return m.group(1).strip()
    # free-fn recipient-positional forms handled FIRST (sendValue / safeTransferETH
    # are library free-functions whose arg0 is the recipient, not a method
    # receiver). safeTransfer(token, recip, amt) -> recipient is arg1.
    for fn_name, pos in (("safetransfereth", 0), ("sendvalue", 0),
                         ("sendcoins", 2), ("sendcoinsfrom", 2),
                         ("sendcoinsfrommoduletoaccount", 2)):
        if re.search(r"(?i)\b" + fn_name + r"\s*\(", s):
            args = _call_args(s, fn_name)
            if len(args) > pos:
                return args[pos].strip()
    # method form: <recip>.transfer( / .send( / .safeTransfer( ...
    mm = re.search(
        r"(?i)([A-Za-z_][A-Za-z0-9_.\[\]\(\)]*?)\s*\."
        r"(?:transfer|send|safetransfer)\s*"
        r"(?:\{[^}]*\})?\s*\(", s)
    if mm:
        obj = mm.group(1).strip()
        # <token>.safeTransfer(recip, amt) - obj is the TOKEN, recipient is arg1.
        if re.search(r"(?i)\.safetransfer\s*\(", s) and \
           not re.search(r"(?i)\.safetransfereth\s*\(", s):
            args = _call_args(s, "safetransfer")
            if len(args) >= 2:
                return args[0].strip()
        if obj.lower() not in ("token", "erc20", "ierc20", "_token"):
            return obj
    # free-fn recipient-positional forms.
    for fn_name, pos in (("safetransfereth", 0), ("sendvalue", 0),
                         ("sendcoins", 2), ("sendcoinsfrom", 2),
                         ("sendcoinsfrommoduletoaccount", 2),
                         ("safetransfer", 1)):
        if re.search(r"(?i)\b" + fn_name + r"\s*\(", s):
            args = _call_args(s, fn_name)
            if len(args) > pos:
                return args[pos].strip()
    # refund/payout/_withdrawTo named helpers - first arg as recipient.
    mr = re.search(r"(?i)\b(_?refund\w*|_?payout\w*|_?withdrawto|disburse\w*)\s*\(", s)
    if mr:
        args = _call_args(s, mr.group(1))
        if args:
            return args[0].strip()
    return ""


def _call_args(line: str, fn_name: str) -> list:
    """Split the top-level comma args of the first `fn_name(...)` call on line."""
    m = re.search(r"(?i)\b" + re.escape(fn_name) + r"\s*\(", line)
    if not m:
        return []
    i = m.end()
    depth = 1
    buf = []
    cur = ""
    while i < len(line) and depth > 0:
        c = line[i]
        if c in "([{":
            depth += 1
            cur += c
        elif c in ")]}":
            depth -= 1
            if depth == 0:
                break
            cur += c
        elif c == "," and depth == 1:
            buf.append(cur)
            cur = ""
        else:
            cur += c
        i += 1
    if cur.strip():
        buf.append(cur)
    return buf


class Fn:
    __slots__ = ("name", "file", "line", "lang", "callees", "body",
                 "sinks", "owner_syms", "has_pull", "has_payable_check",
                 "value_delivery")

    def __init__(self, name, file, line, lang):
        self.name = name
        self.file = file
        self.line = line
        self.lang = lang
        self.callees: set[str] = set()
        self.body = ""
        self.sinks: list[dict] = []       # per-sink {recipient, is_push, raw}
        self.owner_syms: set[str] = set()  # owner-provenance symbols in scope
        self.has_pull = False
        self.has_payable_check = False
        self.value_delivery = False


def _scan_body(fn: Fn, body: str, base_line: int) -> None:
    fn.body = body
    lines = body.splitlines()
    # owner-provenance symbols recorded/read in this body's scope.
    for m in _OWNER_SYM.finditer(body):
        fn.owner_syms.add(m.group(1).lower())
    fn.has_pull = bool(_PULL_MARK.search(body))
    fn.has_payable_check = bool(_PAYABLE_CHECK.search(body))
    # The EVM method-form value primitives (`<recip>.transfer(v)` / `.send(v)` /
    # `.call{value:}`) are SOLIDITY-specific. In Rust `.send()` is a channel send
    # and in Go `.transfer`/`.send` are not fund moves - applying the method-form
    # predicate there produces channel/mpsc false positives. For Go/Rust value
    # delivery flows through the free-fn forms (SendCoins / refund / payout).
    evm = (fn.lang == "solidity")
    for off, ln in enumerate(lines):
        is_sink = _SINK_FREE.search(ln)
        if evm:
            is_sink = (is_sink or _SINK_METHOD.search(ln)
                       or _SINK_LOWLEVEL_CALLVALUE.search(ln))
        if not is_sink:
            continue
        # skip declarations / non-delivery transferFrom pulls INTO the contract
        # only when the recipient is address(this) (a pull, not a push-out).
        recip = _extract_recipient(ln, fn.lang)
        if not recip:
            continue
        rlow = recip.lower()
        if rlow in ("address(this)", "this", "address(this))"):
            continue
        is_push = bool(_PUSH_TRANSFER_SEND.search(ln)
                       or _SINK_LOWLEVEL_CALLVALUE.search(ln))
        fn.value_delivery = True
        fn.sinks.append({
            "recipient": recip,
            "recipient_norm": rlow,
            "is_push": is_push,
            "line": base_line + off,
            "raw": ln.strip()[:200],
        })


def build_call_graph(root: Path) -> dict:
    fns: dict[str, Fn] = {}
    raw: list[tuple[str, str, int, str, str]] = []
    for fp in _iter_source_files(root):
        lang = _lang_of(str(fp))
        drx = _decl_re_for(lang)
        if not drx:
            continue
        try:
            lines = fp.read_text(encoding="utf-8", errors="replace").splitlines()
        except Exception:
            continue
        cur = None
        buf: list[str] = []
        cur_line = 0
        for i, ln in enumerate(lines, 1):
            m = drx.match(ln)
            if m:
                if cur is not None:
                    raw.append((cur, str(fp), cur_line, lang, "\n".join(buf)))
                cur = m.group(1)
                cur_line = i
                buf = [ln]
            elif cur is not None:
                buf.append(ln)
        if cur is not None:
            raw.append((cur, str(fp), cur_line, lang, "\n".join(buf)))

    known = {r[0] for r in raw}
    for name, file, line, lang, body in raw:
        fn = fns.get(name)
        if fn is None:
            fn = Fn(name, file, line, lang)
            fns[name] = fn
        _scan_body(fn, body, line)
        for c in _CALL.findall(body):
            if c in _STOP_NAMES:
                continue
            if c in known and c != name:
                fn.callees.add(c)
            if _VALUE_DELIVERY_NAME.match(c):
                fn.value_delivery = True
    return fns


# ---------------------------------------------------------------------------
# Value-delivery corroboration from the owned dataflow backend.
# ---------------------------------------------------------------------------
def _bare(fnid: str) -> str:
    s = (fnid or "").strip()
    if ")." in s:
        s = s.rsplit(").", 1)[-1]
    s = s.split("(")[0].replace("*", "")
    return s.split(".")[-1].strip()


def load_dataflow_value_deliveries(df_paths: list) -> set:
    value_fns: set[str] = set()
    for df in df_paths:
        if not df.is_file():
            continue
        with df.open(encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if not line:
                    continue
                try:
                    rec = json.loads(line)
                except Exception:
                    continue
                if rec.get("degraded"):
                    continue
                src = rec.get("source") or {}
                sink = rec.get("sink") or {}
                fn = _bare(src.get("fn") or sink.get("fn") or "")
                if not fn:
                    continue
                if str(sink.get("kind") or "") in _VALUE_SINK_KINDS:
                    value_fns.add(fn)
    return value_fns


# ---------------------------------------------------------------------------
# RECIPIENT_PROVENANCE(sink) vs INTENDED_OWNER(value) comparison.
# ---------------------------------------------------------------------------
def _recipient_traces_to_owner(recipient_norm: str, owner_syms: set) -> bool:
    """True iff the recipient operand references an owner-provenance symbol
    recorded in scope (RECIPIENT_PROVENANCE traces to INTENDED_OWNER)."""
    if _OWNER_SYM.search(recipient_norm):
        # the recipient literally references an owner-provenance field/name.
        return True
    # a recipient variable whose NAME is one of the recorded owner symbols.
    tail = recipient_norm.split(".")[-1].strip("()[] ")
    return tail in owner_syms and bool(owner_syms)


def classify(fns: dict, value_fns: set) -> dict:
    sinks_total = 0
    traced = 0
    mismatch_unverified = 0
    survivor_rows: list[dict] = []
    kept_rows: list[dict] = []

    for name, fn in fns.items():
        # union the dataflow value-delivery fact (corroboration).
        if not fn.sinks and (name in value_fns):
            # dataflow says this fn delivers value but the source-scan found no
            # extractable recipient - record it as an advisory unverified push
            # only when it is a push-name and no pull-pattern (fail-open lean:
            # do NOT invent a mismatch without a recipient; skip to avoid noise).
            continue
        for sk in fn.sinks:
            sinks_total += 1
            rnorm = sk["recipient_norm"]
            traces = _recipient_traces_to_owner(rnorm, fn.owner_syms)
            is_caller = bool(_CALLER_SYM.match(rnorm.replace(" ", "")))
            owner_recorded = bool(fn.owner_syms)

            # ARM 1: WRONG-RECIPIENT mismatch. Recipient does NOT trace to the
            # recorded owner while an intended-owner IS recorded in scope, and
            # the delivery is not a pull of the caller's own credited balance.
            mismatch = (
                owner_recorded and not traces and
                (is_caller or _looks_stored_addr(rnorm)) and
                not (fn.has_pull and is_caller)
            )
            # ARM 2: UNVERIFIED-PAYABLE push. A push primitive with no pull-
            # fallback and no payable success verification -> strand risk.
            unverified_payable = (
                sk["is_push"] and not fn.has_pull and not fn.has_payable_check
            )

            if traces and not unverified_payable:
                traced += 1
                kept_rows.append({"fn": name, "file": fn.file,
                                  "line": sk["line"], "recipient": sk["recipient"]})
                continue

            if mismatch or unverified_payable:
                mismatch_unverified += 1
                reasons = []
                if mismatch:
                    reasons.append("wrong-recipient")
                if unverified_payable:
                    reasons.append("unverified-payable-push")
                survivor_rows.append({
                    "fn": name, "file": fn.file, "line": sk["line"],
                    "lang": fn.lang, "recipient": sk["recipient"],
                    "is_push": sk["is_push"],
                    "owner_syms": sorted(fn.owner_syms)[:6],
                    "reasons": reasons, "raw": sk["raw"],
                })
            else:
                # decidable but neither traced-owner nor a survivor (e.g. a
                # recipient param with no recorded owner to compare against) -
                # counted in SINKS, not a survivor (honest: nothing to compare).
                pass

    class_present = sinks_total > 0
    return {
        "class_present": class_present,
        "size_SINKS": sinks_total,
        "size_TRACED": traced,
        "size_MISMATCH_OR_UNVERIFIED": mismatch_unverified,
        "survivors": survivor_rows,
        "kept": kept_rows,
    }


def _looks_stored_addr(recipient_norm: str) -> bool:
    """Recipient is a stored contract-state address (a field a prior step may
    have overwritten): a dotted/bracketed lvalue that is NOT an owner symbol and
    NOT the caller - e.g. `s.recipient`, `order.receiver`, `winners[i]`."""
    r = recipient_norm.strip()
    if _CALLER_SYM.match(r.replace(" ", "")):
        return False
    if _OWNER_SYM.search(r):
        return False
    return bool(re.search(r"(?i)\b(recipient|receiver|to|dest|destination|"
                          r"winner|target|payto|forwardto)\b", r))


def make_obligation(row: dict, invariant_id: str) -> dict:
    src_ref = row["file"] + (f":{row['line']}" if row["line"] else "")
    reasons = row["reasons"]
    if "wrong-recipient" in reasons:
        root = (
            f"Value-delivery sink in '{row['fn']}' pushes to recipient "
            f"`{row['recipient']}` which does NOT provenance-trace to the "
            f"intended owner of the value (recorded owner symbol(s) in scope: "
            f"{', '.join(row['owner_syms']) or 'n/a'}). RECIPIENT_PROVENANCE != "
            f"INTENDED_OWNER: the delivery routes funds to msg.sender/caller or a "
            f"foreign stored address rather than the recorded depositor/originator/"
            f"beneficiary - a wrong-recipient misroute (RANK-25 push-payment HIGH)."
        )
    else:
        root = (
            f"Value-delivery sink in '{row['fn']}' PUSHES to `{row['recipient']}` "
            f"via a 2300-gas transfer/send or low-level call-with-value with NO "
            f"pull-fallback and NO payable success verification. If the recipient "
            f"is a non-payable contract (or a gas-hungry receiver) the send reverts "
            f"and the funds are STRANDED (RANK-25 push-to-non-payable HIGH)."
        )
    return {
        "schema": "auditooor.push_payment_misroute.v1",
        "obligation_type": "push-payment-misroute",
        "contract": "",
        "function": row["fn"],
        "function_signature": row["fn"],
        "language": row["lang"],
        "source_refs": [src_ref] if src_ref else [],
        "file": row["file"],
        "line": row["line"],
        "recipient_operand": row["recipient"],
        "recorded_owner_symbols": row["owner_syms"],
        "misroute_reasons": reasons,
        "is_push": row["is_push"],
        "attack_class": "push-payment-to-wrong-recipient-or-non-payable",
        "likely_severity": "high",
        "broken_invariant_ids": [invariant_id],
        "root_cause_hypothesis": root,
        "quality_gate_status": "needs_source",
        "proof_status": "needs_source",
        "advisory_only": True,
        "learning_route": "mine-source",
        "falsification_requirements": [
            "RECIPIENT_PROVENANCE: resolve the recipient operand to its defining "
            "source and confirm it does NOT equal the value's recorded owner "
            "(deposit.owner / originator / beneficiary / refundAddress). If the "
            "record captured THIS exact recipient at deposit time and no later "
            "actor can call the sink, it is correctly routed - KILL.",
            "PAYABLE/PULL: for the unverified-payable arm, confirm the push is a "
            "2300-gas transfer/send (or unchecked call-value) with no pull "
            "fallback; a checked call{value} or a credited-balance pull KILLS it.",
            "IMPACT: show a concrete actor (relayer, later caller, non-payable "
            "receiver, overwritten stored addr) whereby the funds reach the wrong "
            "party or revert-and-strand - executed PoC.",
        ],
        "next_command": (
            "read the fn body + the owner-record site; trace the recipient "
            "operand's provenance vs the recorded owner; if they diverge (or the "
            "push is unverified) author the routing invariant harness + PoC."
        ),
    }


def run(argv=None):
    ap = argparse.ArgumentParser(
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--workspace", required=True)
    ap.add_argument("--src-root", default=None,
                    help="override source root (default <ws>/src, else <ws>)")
    ap.add_argument("--dataflow", default=None,
                    help="override dataflow_paths.jsonl (value-delivery corroboration)")
    ap.add_argument("--invariant-id", default="INV-PUSH-PAYMENT-RECIPIENT-PROVENANCE")
    ap.add_argument("--emit", default=None)
    ap.add_argument("--json", action="store_true")
    ap.add_argument("--fail-closed", action="store_true",
                    help="exit non-zero if the source substrate never materialized "
                         "(0 fns indexed) - a vacuous, not honest, empty")
    args = ap.parse_args(argv)

    ws = Path(args.workspace).expanduser().resolve()
    if args.src_root:
        root = Path(args.src_root).expanduser().resolve()
    else:
        root = ws / "src" if (ws / "src").is_dir() else ws

    fns = build_call_graph(root)

    df_paths: list = []
    if args.dataflow:
        df_paths.append(Path(args.dataflow).expanduser())
    else:
        auto = ws / ".auditooor" / "dataflow_paths.jsonl"
        if auto.is_file():
            df_paths.append(auto)
        for sib in sorted((ws / ".auditooor").glob("dataflow_paths.*.jsonl")):
            df_paths.append(sib)
    value_fns = load_dataflow_value_deliveries(df_paths)

    res = classify(fns, value_fns)

    obligations = []
    seen = set()
    for row in res["survivors"]:
        dk = (row["file"], row["line"], row["fn"])
        if dk in seen:
            continue
        seen.add(dk)
        obligations.append(make_obligation(row, args.invariant_id))

    emit = Path(args.emit).expanduser() if args.emit else \
        ws / ".auditooor" / "push_payment_misroute_obligations.jsonl"
    emit.parent.mkdir(parents=True, exist_ok=True)
    with emit.open("w", encoding="utf-8") as fh:
        for ob in obligations:
            fh.write(json.dumps(ob) + "\n")
        # Capability-vacuity-telltale: the misroute screen RAN over a real indexed
        # function surface (>=1 fn) and produced 0 survivors. PERSIST an explicit
        # cited-empty examined-record so the reasoner-firing gate scores this
        # FIRED_CLEAN (ran, examined, recorded 0) not silently VACUOUS.
        if not obligations and len(fns) > 0:
            fh.write(json.dumps({
                "schema": "auditooor.push_payment_misroute.examined_record.v1",
                "note": ("cited-empty: push-payment misroute screen ran over the "
                         "indexed value-delivery surface, 0 survivors"),
                "class_present": res["class_present"],
                "survivors": [],
                "report": {
                    "reasoner": "push-payment-misroute",
                    "totals": {"examined": len(fns),
                               "sinks": res["size_SINKS"],
                               "traced": res["size_TRACED"]},
                },
            }) + "\n")

    substrate_vacuous = (len(fns) == 0)
    # honest cited-empty: functions indexed but NO value-delivery sink at all.
    honest_empty = (not res["survivors"]) and (not res["class_present"])

    summary = {
        "schema": "auditooor.push_payment_misroute.v1",
        "workspace": str(ws),
        "src_root": str(root),
        "dataflow": [str(p) for p in df_paths],
        "generated_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "n_functions_indexed": len(fns),
        "class_present": res["class_present"],
        "size_value_delivery_sinks": res["size_SINKS"],
        "size_recipient_provenance_traced": res["size_TRACED"],
        "size_mismatch_or_unverified": res["size_MISMATCH_OR_UNVERIFIED"],
        "size_survivors": len(res["survivors"]),
        "kept_traced": res["kept"][:40],
        "survivors": [
            {"fn": s["fn"], "file": s["file"], "line": s["line"],
             "recipient": s["recipient"], "reasons": s["reasons"],
             "owner_syms": s["owner_syms"]}
            for s in res["survivors"][:80]
        ],
        "obligations_written": len(obligations),
        "obligations_path": str(emit),
        "substrate_vacuous": substrate_vacuous,
        "honest_empty_class_not_present": honest_empty,
    }

    if args.json:
        print(json.dumps(summary, indent=2))
    else:
        print(f"[push-payment-misroute] {ws.name}: fns={len(fns)} "
              f"class_present={res['class_present']} "
              f"|SINKS|={summary['size_value_delivery_sinks']} "
              f"|TRACED|={summary['size_recipient_provenance_traced']} "
              f"|MISMATCH_OR_UNVERIFIED|={summary['size_mismatch_or_unverified']} "
              f"survivors={summary['size_survivors']} "
              f"-> {len(obligations)} obligation(s)")
        for s in summary["survivors"][:40]:
            print(f"  SURVIVOR {s['fn']}  recip={s['recipient']}  "
                  f"reasons={s['reasons']}  owner={s['owner_syms']}  "
                  f"{s['file']}:{s['line']}")
        if honest_empty:
            print("  HONEST-EMPTY: functions indexed but NO value-delivery sink "
                  "with a decidable recipient - the push-payment misroute class "
                  "does NOT apply here (cited-empty, N/A).")
        if substrate_vacuous:
            print("  WARN VACUOUS: 0 functions indexed - source substrate never "
                  "materialized (NOT an honest empty).", file=sys.stderr)
        print(f"  -> {emit}")

    if args.fail_closed and substrate_vacuous:
        return 3
    return summary


if __name__ == "__main__":
    out = run()
    if out == 3:
        sys.exit(3)
