#!/usr/bin/env python3
"""rust-account-owner-signer-confusion.py - the Solana account-confusion query.

LOGIC CAPABILITY (docs/LOGIC_ARSENAL_ROADMAP.md family; the RUST/Solana account
owner/signer/key-confusion class - sealevel-attacks "owner"/"signer"/"account
data matching", Neodyme workshop levels 1-4). This is a SET / REACHABILITY query
over an OWNED account-flow (data-flow) backend, NOT a token detector.

THE INVARIANT (Solana account confusion, rekt many times):
  A Solana/Anchor instruction receives its accounts as CALLER-SUPPLIED input. The
  runtime does NOT verify that a passed account is the RIGHT account - only the
  program can, by checking one of:
     (owner)   account_info.owner == expected_program_id,
     (signer)  account_info.is_signer,
     (key-eq)  account.key() == expected_pubkey  (has_one / require_keys_eq /
               constraint = ... .key()).
  Let
    AUTH_USE  = { (fn, account-param) : a data-flow slice shows the caller-supplied
                  account PARAM reaches an AUTHORITY-USE sink - the account is used
                  to authorize a value-move / CPI / privileged state-write /
                  signature verification (sink.kind='authority' or a CPI/op callee
                  that treats the account as authority/owner/signer/from) }
    CHECK     = { (fn, account-param) in AUTH_USE whose flow CLOSURE carries an
                  owner / signer / key-equality validating guard node }
  The trust boundary requires   AUTH_USE  is a SUBSET of  CHECK.
  Every (fn, account-param) in the SET-DIFFERENCE   AUTH_USE \\ CHECK   is an
  account used as a trusted authority with NO owner/signer/key check on its path
  -> that is the account-confusion class, emitted as an
  `account-owner-signer-confusion` obligation.

WHY THIS IS LOGIC, NOT A SHAPE (guard-rail satisfied)
  A name regex ("does the body contain `is_signer`?") false-positives whenever a
  check exists for a DIFFERENT account and false-negatives whenever the check
  lives in an Anchor `#[account(..)]` constraint macro / a helper N hops away.
  This query differs on the three axes that make it a graph-set relation:
    (a) membership is a REACHABILITY relation over the account-flow graph - the
        account PARAM must actually FLOW (source.kind=param -> sink) to the
        authority use; a `is_signer` on an unrelated account never grants CHECK
        because the guard node must sit on THIS param's flow closure;
    (b) the answer is a relation between TWO SETS of (fn, param) pairs (the subset
        test AUTH_USE is a subset of CHECK) whose finding is the SET-DIFFERENCE,
        not a boolean over one function's text;
    (c) the validating check and the authority use need not co-occur in any single
        body - the check is located anywhere in the flow CLOSURE (guard_nodes
        accumulated across the inter-procedural hops), so no token-adjacency /
        same-file assumption is used.

OWNED BACKEND CONSUMED (no new call-graph engine is built here)
  <ws>/.auditooor/dataflow_paths.jsonl  (schema dataflow_path.v1) produced by
  tools/rust-dataflow.py (Rust MIR / syntactic def-use) for the Rust arm and by
  go-dataflow.py / dataflow-slice.py for the Go / Solidity arms - the SAME shared
  DefUsePath substrate the Euler set-difference hunter reads. Each record ties a
  caller-supplied PARAM source (source.kind in {param, param-entrypoint}) to a
  SINK, and carries the CLOSURE-consulted guard nodes (guard_nodes[].expr).
  AUTH_USE reads sink.kind / sink.callee; CHECK reads whether ANY closure guard
  node satisfies account_check_pred (owner|signer|key-equality). Scoped sidecars
  <ws>/.auditooor/dataflow_paths.*.jsonl are auto-unioned (a per-crate rust run).

OUTPUT
  <ws>/.auditooor/account_confusion_obligations.jsonl - one row per survivor,
  schema `auditooor.account_owner_signer_confusion.v1`, exploit_queue-ingest
  compatible. exploit-queue.py ingests it via
  _gather_from_account_confusion_obligations -> the queue -> per-fn-mimo-batch-gen
  OPEN-OBLIGATIONS block. A summary is printed / emitted (--json) with |AUTH_USE|,
  |CHECK|, |AUTH_USE\\CHECK|, the KEPT (checked, proving the subtraction is
  non-vacuous) and the survivors.
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
# AUTHORITY-USE sink taxonomy. An account param is used as an AUTHORITY when it
# reaches a sink that treats it as owner/signer/from/authority. On the shared
# dataflow schema this is:
#   * sink.kind == "authority"  (go-dataflow classifySink authority kind: a
#     privilege / owner / authority use of the value) - ALWAYS authority-use;
#   * a value-move / mint / burn / state-write sink whose CALLEE is a Solana /
#     token CPI or op that consumes an account AS the authority / owner / from /
#     signer role (set_authority / invoke_signed / token transfer / mint_to /
#     burn / close / assign / SetAuthority). A bare state-write with no such
#     callee is NOT an authority use (it does not trust the account's identity).
# ---------------------------------------------------------------------------
_AUTHORITY_SINK_KINDS = {"authority"}
_AUTHORITY_ROLE_SINK_KINDS = {"value-move", "mint", "burn", "state-write",
                              "safeTransfer", "transfer"}

# CPI / op callees that consume a passed account in an AUTHORITY / OWNER / FROM /
# SIGNER role (Solana SPL-token, system program, Anchor CPI, generic authority
# setters). Matching is on the callee identity, not the fn body.
_AUTHORITY_OP_RE = re.compile(
    r"set_?authority|setauthority|invoke_signed|invoke_?signed|"
    r"close_?account|\.close\b|"
    r"token::transfer|token_?transfer|spl_?token|transfer_?checked|"
    r"mint_?to|burn_?checked|freeze_?account|thaw_?account|"
    r"system_?instruction::(?:transfer|assign|allocate)|"
    r"set_?owner|change_?authority|delegate|approve|"
    r"authorize|as_authority|signer_?seeds",
    re.IGNORECASE,
)


def is_authority_use_sink(sink: dict) -> bool:
    """True iff a data-flow SINK is an AUTHORITY-USE of a passed account: either
    the backend classified it kind='authority', or it is a value-moving / op sink
    whose callee consumes the account in an authority/owner/from/signer role.
    Pure per-node predicate; the reachability/set logic lives in the caller."""
    if not isinstance(sink, dict):
        return False
    kind = str(sink.get("kind") or "").strip()
    if kind in _AUTHORITY_SINK_KINDS:
        return True
    if kind in _AUTHORITY_ROLE_SINK_KINDS:
        callee = str(sink.get("callee") or "")
        if callee and _AUTHORITY_OP_RE.search(callee):
            return True
    return False


# ---------------------------------------------------------------------------
# The OWNER / SIGNER / KEY-EQUALITY validating guard_pred. This classifies a
# single guard NODE (an expr string) as "a check that validates the identity of
# the account before it is trusted". It is the node predicate the invariant
# mandates; the LOGIC is the transitive-closure set-difference wrapped around it,
# not this node classifier.
# ---------------------------------------------------------------------------

# (1) SIGNER checks: is_signer read, Anchor Signer<'info> type, ensure/require
#     signer helpers, #[account(signer)].
_SIGNER_RE = re.compile(
    r"\bis_signer\b|\.is_signer|require_?signer|ensure_?signer|"
    r"\bSigner\s*<|assert_?signer|check_?signer|only_?signer|must_?sign",
    re.IGNORECASE,
)

# (2) OWNER checks: account_info.owner == program_id, owner comparison, Anchor
#     owner = ..., owner_check helpers. Requires an OWNER token AND a comparison
#     operator OR a named owner-check helper / macro constraint.
_OWNER_TOKEN_RE = re.compile(r"\bowner\b|owner_?id|owning_?program", re.IGNORECASE)
_OWNER_HELPER_RE = re.compile(
    r"owner_?check|check_?owner|assert_?owner|require_?owner|"
    r"owner\s*=\s|has_one\s*=\s*.*authority|owner_?is",
    re.IGNORECASE,
)

# (3) KEY-EQUALITY checks: account.key() == expected, has_one, require_keys_eq,
#     Anchor constraint = ... .key(), address = ..., assert_eq!(...key...).
_KEY_EQ_RE = re.compile(
    r"require_?keys?_?eq|\bhas_one\b|keys?_?eq|"
    r"assert_?eq!?\s*\([^)]*\.key|"
    r"\.key\s*\(\s*\)\s*==|==\s*[^=;]*\.key\s*\(\s*\)|"
    r"pubkey\s*==|==\s*[^=;]*pubkey|"
    r"constraint\s*=|address\s*=\s*",
    re.IGNORECASE,
)

_CMP_RE = re.compile(r"[<>]=?|==|!=")


def account_check_pred(expr: str) -> bool:
    """True iff the guard-node expression validates the IDENTITY of a passed
    account before it is trusted as an authority: an owner check, a signer check,
    or a key-equality check. This is the OVERRIDE guard_pred(node)->bool for the
    account-flow closure - NOT a generic bound / access-control guard on an
    unrelated value. Pure node predicate; the set/closure logic lives in the
    caller."""
    e = (expr or "").strip()
    if not e:
        return False
    # signer check
    if _SIGNER_RE.search(e):
        return True
    # key-equality check (has_one / require_keys_eq / .key()== / constraint=)
    if _KEY_EQ_RE.search(e):
        return True
    # owner check: a named owner helper/macro-constraint, OR an owner token in a
    # comparison (owner == program_id). A bare mention of `owner` with no
    # comparison and no helper is NOT a validating check.
    if _OWNER_HELPER_RE.search(e):
        return True
    if _OWNER_TOKEN_RE.search(e) and _CMP_RE.search(e):
        return True
    return False


# ---------------------------------------------------------------------------
# Record -> (entrypoint fn, account param) unit. The account-confusion unit is
# keyed on (fn, param-var) because the SAME fn may take several accounts and only
# ONE of them may be unchecked - a per-fn key would merge a checked account with
# an unchecked one and hide the bug. For a backward slice the entrypoint is the
# param source's fn; the account is source.var.
# ---------------------------------------------------------------------------
_PARAM_SRC_KINDS = {"param", "param-entrypoint", "entrypoint"}


def _unit_key(rec: dict) -> tuple[str, str] | None:
    src = rec.get("source") or {}
    if str(src.get("kind") or "") not in _PARAM_SRC_KINDS:
        return None
    fn = str(src.get("fn") or "")
    if not fn:
        sink = rec.get("sink") or {}
        fn = str(sink.get("fn") or "")
    if not fn:
        return None
    var = str(src.get("var") or "") or "<account>"
    return (fn, var)


def _src_file(rec: dict) -> str:
    src = rec.get("source") or {}
    sink = rec.get("sink") or {}
    return str(src.get("file") or sink.get("file") or "")


def _src_line(rec: dict) -> int:
    src = rec.get("source") or {}
    sink = rec.get("sink") or {}
    return int(src.get("line") or sink.get("line") or 0)


# ---------------------------------------------------------------------------
# scope OOS guard (single source of truth); degrade to a conservative default.
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


_VENDOR_MARKERS = ("/pkg/mod/", "/go/pkg/", "/vendor/", "/node_modules/",
                   "/.cargo/", "/registry/src/")
_CODEGEN_SUFFIXES = (".pb.go", ".pb.gw.go", ".gen.go", "_pb2.py")


def _in_scope_file(fpath: str, ws_root: Path, include_oos: bool) -> bool:
    """An in-scope account-flow unit's file must live UNDER the workspace root
    (a vendored crate under ~/.cargo / go/pkg/mod is outside ws), must not be
    codegen, and must pass the shared OOS guard."""
    if not fpath:
        return False
    low = fpath.replace("\\", "/").lower()
    if any(m in low for m in _VENDOR_MARKERS):
        return False
    if any(low.endswith(s) for s in _CODEGEN_SUFFIXES):
        return False
    try:
        rel = Path(fpath).resolve().relative_to(ws_root)
    except Exception:
        return False
    if not include_oos and is_oos(str(rel)):
        return False
    return True


def _short_fn(fn: str) -> str:
    """Bare function name from a Solidity 'C.f(uint256)' / Go '(*pkg.T).Method' /
    Rust 'crate::mod::func' identity."""
    s = (fn or "").strip()
    if ")." in s:
        s = s.rsplit(").", 1)[-1]
    s = s.split("(")[0].replace("*", "")
    if "::" in s:
        s = s.split("::")[-1]
    return s.split(".")[-1].strip()


def _contract_of(fn: str) -> str:
    """Qualifier (Solidity contract / Go type / Rust module) best-effort."""
    s = (fn or "").strip()
    if ")." in s:
        recv = s.rsplit(").", 1)[0].lstrip("(").lstrip("*")
        return recv.split(".")[-1].split("::")[-1]
    if "::" in s:
        parts = s.split("(")[0].split("::")
        return parts[-2] if len(parts) > 1 else ""
    head = s.split("(")[0]
    parts = head.split(".")
    return parts[0] if len(parts) > 1 else ""


class Unit:
    __slots__ = ("fn", "var", "file", "line", "lang",
                 "auth_sink_kinds", "auth_callees", "guard_exprs", "n_records")

    def __init__(self, fn: str, var: str):
        self.fn = fn
        self.var = var
        self.file = ""
        self.line = 0
        self.lang = ""
        self.auth_sink_kinds: set[str] = set()
        self.auth_callees: set[str] = set()
        self.guard_exprs: list[str] = []
        self.n_records = 0


def build_sets(dataflow_path: Path, ws_root: Path,
               include_oos: bool = False) -> tuple[dict, list[str]]:
    """Fold dataflow_paths.jsonl into per-(fn,account-param) Units, tagging
    AUTH_USE membership (the account param reaches an authority-use sink) and
    accumulating the CLOSURE guard-node exprs. Returns (units_by_key, warnings)."""
    units: dict[tuple[str, str], Unit] = {}
    warnings: list[str] = []
    n_total = n_degraded = 0
    if not dataflow_path.is_file():
        warnings.append(f"dataflow_paths absent: {dataflow_path}")
        return units, warnings
    with dataflow_path.open(encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            try:
                rec = json.loads(line)
            except Exception:
                continue
            n_total += 1
            if rec.get("degraded"):
                n_degraded += 1
                continue
            key = _unit_key(rec)
            if key is None:
                continue
            fpath = _src_file(rec)
            if not _in_scope_file(fpath, ws_root, include_oos):
                continue
            u = units.get(key)
            if u is None:
                u = Unit(key[0], key[1])
                u.file = fpath
                u.line = _src_line(rec)
                u.lang = str(rec.get("language") or "")
                units[key] = u
            u.n_records += 1
            if not u.file and fpath:
                u.file = fpath
            sink = rec.get("sink") or {}
            if is_authority_use_sink(sink):
                u.auth_sink_kinds.add(str(sink.get("kind") or ""))
                if sink.get("callee"):
                    u.auth_callees.add(str(sink["callee"]))
            for g in rec.get("guard_nodes") or []:
                e = g.get("expr")
                if e:
                    u.guard_exprs.append(str(e))
    if n_total and n_degraded == n_total:
        warnings.append(
            f"ALL {n_total} dataflow records are DEGRADED (substrate-starved: "
            f"compile-fail / rust MIR failure / dataflow timeout) - the "
            f"account-flow set-difference is vacuously empty because the flow "
            f"graph never materialized, NOT because AUTH_USE is a subset of "
            f"CHECK. Re-run rust-dataflow.py scoped to the in-scope crate.")
    return units, warnings


def classify(units: dict) -> dict:
    """Compute AUTH_USE, CHECK, and the SET-DIFFERENCE AUTH_USE\\CHECK."""
    auth = {k for k, u in units.items() if u.auth_sink_kinds}
    check = set()
    for k in auth:
        u = units[k]
        if any(account_check_pred(e) for e in u.guard_exprs):
            check.add(k)
    survivors = sorted(auth - check)
    kept = sorted(auth & check)
    return {
        "auth_use": sorted(auth),
        "check": sorted(check),
        "survivors": survivors,
        "kept": kept,
    }


def make_obligation(u: Unit, invariant_id: str) -> dict:
    short = _short_fn(u.fn)
    contract = _contract_of(u.fn)
    src_ref = u.file + (f":{u.line}" if u.line else "")
    kinds = sorted(k for k in u.auth_sink_kinds if k)
    callees = sorted(u.auth_callees)[:4]
    root = (
        f"Caller-supplied account param '{u.var}' of '{u.fn}' flows to an "
        f"authority-use sink ({', '.join(kinds) or 'authority'}"
        + (f" via {', '.join(callees)}" if callees else "")
        + ") but its flow closure carries NO owner / signer / key-equality check "
        "on that account (set-difference AUTH_USE\\CHECK). Solana account-"
        "confusion class: an attacker substitutes a look-alike account they own "
        "and the program trusts it as the authority."
    )
    return {
        "schema": "auditooor.account_owner_signer_confusion.v1",
        "obligation_type": "account-owner-signer-confusion",
        "contract": contract,
        "function": short,
        "function_signature": u.fn,
        "account_param": u.var,
        "language": u.lang,
        "source_refs": [src_ref] if src_ref else [],
        "file": u.file,
        "line": u.line,
        "authority_sink_kinds": kinds,
        "authority_sink_callees": callees,
        "attack_class": "account-owner-signer-confusion",
        "likely_severity": "high",
        "broken_invariant_ids": [invariant_id],
        "root_cause_hypothesis": root,
        "quality_gate_status": "needs_source",
        "proof_status": "needs_source",
        "advisory_only": True,
        "learning_route": "mine-source",
        "falsification_requirements": [
            "OWNER_SIGNER_KEY_CLOSURE: prove NO owner (account.owner == "
            "program_id), signer (is_signer / Signer<'info>) or key-equality "
            "(has_one / require_keys_eq / .key()==) check on THIS account param is "
            "reachable in its flow closure - a check in an Anchor #[account(..)] "
            "constraint or an N-hop helper KILLS the lead.",
            "ATTACKER_SUBSTITUTION: confirm the account is fully caller-supplied "
            "(an instruction account / fn param), not a PDA the program re-derives "
            "and pins, and that a look-alike attacker-owned account is accepted.",
            "AUTHORITY_IMPACT: show the trusted account gates a value-move / CPI / "
            "privileged mutation whose misuse yields theft or unauthorized action.",
        ],
        "next_command": (
            "read the fn signature + its account struct + callee closure; if no "
            "owner/signer/key check on this account is reachable, author the "
            "substitution PoC (pass an attacker-owned look-alike account)."
        ),
    }


def run(argv=None) -> dict | int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--workspace", required=True)
    ap.add_argument("--dataflow", default=None,
                    help="override dataflow_paths.jsonl path")
    ap.add_argument("--alt-dataflow", default=None,
                    help="additional dataflow jsonl to UNION (e.g. a scoped crate run)")
    ap.add_argument("--include-oos", action="store_true",
                    help="do NOT apply the scope OOS filter (debug)")
    ap.add_argument("--invariant-id",
                    default="INV-ACCOUNT-OWNER-SIGNER-KEY-CHECK-SUBSET",
                    help="broken_invariant_id stamped on every obligation")
    ap.add_argument("--emit", default=None,
                    help="output jsonl path (default "
                         "<ws>/.auditooor/account_confusion_obligations.jsonl)")
    ap.add_argument("--json", action="store_true")
    ap.add_argument("--fail-closed", action="store_true",
                    help="exit non-zero if the dataflow substrate is fully "
                         "degraded (the set-difference could not be computed)")
    args = ap.parse_args(argv)

    ws = Path(args.workspace).expanduser().resolve()
    df = Path(args.dataflow).expanduser() if args.dataflow else \
        ws / ".auditooor" / "dataflow_paths.jsonl"

    units, warnings = build_sets(df, ws, include_oos=args.include_oos)

    # Union any SCOPED sidecars <ws>/.auditooor/dataflow_paths.*.jsonl (a per-crate
    # rust-dataflow run) + any explicit --alt-dataflow.
    alt_paths: list[Path] = []
    if args.alt_dataflow:
        alt_paths.append(Path(args.alt_dataflow).expanduser())
    if not args.dataflow:
        for sib in sorted((ws / ".auditooor").glob("dataflow_paths.*.jsonl")):
            if sib.resolve() != df.resolve():
                alt_paths.append(sib)
    for alt in alt_paths:
        alt_units, alt_warn = build_sets(alt, ws, include_oos=args.include_oos)
        warnings.extend(alt_warn)
        for k, au in alt_units.items():
            u = units.get(k)
            if u is None:
                units[k] = au
                continue
            u.auth_sink_kinds |= au.auth_sink_kinds
            u.auth_callees |= au.auth_callees
            u.guard_exprs.extend(au.guard_exprs)
            u.n_records += au.n_records
            if not u.file:
                u.file = au.file

    res = classify(units)

    obligations = []
    _seen_ob = set()
    for k in res["survivors"]:
        u = units[k]
        dk = (u.file, u.line, _short_fn(u.fn), u.var)
        if dk in _seen_ob:
            continue
        _seen_ob.add(dk)
        obligations.append(make_obligation(u, args.invariant_id))

    emit = Path(args.emit).expanduser() if args.emit else \
        ws / ".auditooor" / "account_confusion_obligations.jsonl"
    emit.parent.mkdir(parents=True, exist_ok=True)
    with emit.open("w", encoding="utf-8") as fh:
        for ob in obligations:
            fh.write(json.dumps(ob) + "\n")
        # Capability-vacuity-telltale: the account-owner/signer-confusion screen RAN
        # over a real Rust account-param surface (>=1 unit) and produced 0 survivors.
        # PERSIST an explicit cited-empty examined-record so the reasoner-firing gate
        # scores this FIRED_CLEAN (ran, examined the Rust surface, recorded 0) not
        # silently VACUOUS. Gated on a real surface - 0 units is substrate_degraded.
        if not obligations and len(units) > 0:
            fh.write(json.dumps({
                "schema": "auditooor.account_owner_signer_confusion.examined_record.v1",
                "note": ("cited-empty: account-owner/signer-confusion screen ran over "
                         "the Rust account-param surface, 0 unchecked-authority survivors"),
                "survivors": [],
                "report": {"reasoner": "rust-account-owner-signer-confusion",
                           "totals": {"examined": len(units),
                                      "auth_use": len(res["auth_use"])}},
            }) + "\n")

    substrate_degraded = any("DEGRADED" in w for w in warnings) and not units

    summary = {
        "schema": "auditooor.account_owner_signer_confusion_summary.v1",
        "workspace": str(ws),
        "dataflow": str(df),
        "generated_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "n_account_param_units": len(units),
        "size_AUTH_USE": len(res["auth_use"]),
        "size_CHECK_among_auth": len(res["kept"]),
        "size_DIFF_survivors": len(res["survivors"]),
        "kept_auth_and_checked": [
            f"{_short_fn(fn)}({var})" for fn, var in res["kept"]],
        "survivors": [
            {"fn": _short_fn(fn), "signature": fn, "account_param": var,
             "file": units[(fn, var)].file, "line": units[(fn, var)].line,
             "authority_sink_kinds": sorted(units[(fn, var)].auth_sink_kinds)}
            for fn, var in res["survivors"]
        ],
        "obligations_written": len(obligations),
        "obligations_path": str(emit),
        "warnings": warnings,
        "substrate_degraded": substrate_degraded,
    }

    if args.json:
        print(json.dumps(summary, indent=2))
    else:
        print(f"[account-confusion] {ws.name}: "
              f"|AUTH_USE|={summary['size_AUTH_USE']} "
              f"|CHECK(among AUTH_USE)|={summary['size_CHECK_among_auth']} "
              f"survivors(AUTH_USE\\CHECK)={summary['size_DIFF_survivors']} "
              f"-> {len(obligations)} account-owner-signer-confusion obligation(s)")
        if res["kept"]:
            print("  KEPT (auth-use + reaches owner/signer/key check, removed from "
                  "diff): " + ", ".join(summary["kept_auth_and_checked"]))
        for s in summary["survivors"][:40]:
            print(f"  SURVIVOR {s['fn']}({s['account_param']})  "
                  f"{sorted(s['authority_sink_kinds'])}  {s['file']}:{s['line']}")
        for w in warnings:
            print(f"  WARN {w}", file=sys.stderr)
        print(f"  -> {emit}")

    if args.fail_closed and substrate_degraded:
        return 3
    return summary


if __name__ == "__main__":
    out = run()
    if out == 3:
        sys.exit(3)
