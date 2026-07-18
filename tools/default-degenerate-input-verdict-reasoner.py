#!/usr/bin/env python3
"""default-degenerate-input-verdict-reasoner.py - LOGIC CAPABILITY #6.

docs/LOGIC_ARSENAL_ROADMAP.md capability #6: "each verification/proof/status gate
must carry a verdict on its ZERO/DEFAULT/EMPTY input branch. Reads every
proof/root/status/verification gate body + its default-init and error-return
branches (CFG). Logic = a CFG branch-coverage query (does the gate have a reasoned
verdict on the degenerate-input branch), NOT a regex for a token."

This is a SET / CFG-BRANCH-COVERAGE query over an OWNED call-graph / branch
backend, NOT a token detector.

THE LOGIC TRIPLE (extracted from the corpus class it targets - the ecrecover(0)
/ empty-merkle-proof / empty-signer-set / zero-root class, e.g. nuva `_verifyAML`
signature admission, Cosmos empty-vote-set quorum):
  ASSUMPTION      : a verification / proof / status / root gate is REACHED with an
                    input at its ZERO / DEFAULT / EMPTY value (an empty signature
                    bytes, a zero merkle root, an empty signer/validator set, a
                    zero threshold, a default-initialized status struct).
  INVARIANT       : every gate's control-flow must carry a REASONED verdict on
                    that degenerate-input branch - i.e. the CFG path taken when the
                    verified input is degenerate must reach an EXPLICIT REJECT
                    (revert / return-false / require) rather than falling through
                    to the ACCEPT verdict.
  TRUST-BOUNDARY  : the gate is the admission boundary. If the degenerate-input
                    branch is UNCOVERED (no reject predicate anywhere in the gate's
                    validated closure), a caller who supplies the zero/empty/default
                    value is silently ADMITTED - authentication / proof / quorum
                    bypass.

THE SET RELATION (this is the LOGIC, mirroring the Euler set-difference #3):
  Let
    GATES = { external/public/internal fn f : f is a verification / proof / status
              / root ADMISSION gate (a fn whose purpose is to admit-or-reject,
              classified structurally + by admission-verb name, NOT a setter /
              getter / a plain noun like 'validator') }
    DEGEN_REASONED = { f in GATES : f's validated forward closure contains at least
              one CFG BRANCH PREDICATE that tests a verified value for its
              ZERO / EMPTY / DEFAULT form (a `== 0` / `!= address(0)` /
              `len(x)==0` / `.length > 0` / `== nil` / `IsZero()` / `== ""` guard
              node observed on a control-flow edge of the gate) }
  The trust boundary requires   GATES  is a SUBSET of  DEGEN_REASONED.
  Every f in the SET-DIFFERENCE   GATES \\ DEGEN_REASONED   is an admission gate
  whose degenerate-input branch carries NO reasoned verdict -> emitted as a
  `degenerate-input-unverdicted-gate` obligation.

WHY THIS IS LOGIC, NOT A SHAPE (guard-rail satisfied)
  It does NOT reduce to "token X present, token Y absent". The three axes that make
  it a CFG-branch-coverage set relation rather than a regex:
    (a) membership in DEGEN_REASONED is a query over the gate's ACCUMULATED
        CLOSURE branch predicates (the guard_nodes the owned go/ssa + slither
        engine placed on control-flow edges dominating/observed by the gate),
        NOT a same-body text scan - a degenerate-reject that lives N hops away in a
        helper the gate calls correctly places the gate in DEGEN_REASONED
        (impossible for a body-scoped regex);
    (b) the finding is a relation between TWO SETS of functions (the subset test
        GATES is a subset of DEGEN_REASONED) whose output is the SET-DIFFERENCE,
        not a boolean over one function's text;
    (c) the degenerate-branch node predicate is evaluated over the gate's
        control-flow BRANCH conditions (a coverage question: does the CFG branch on
        a zero/empty/default value at all), never over free token adjacency - a
        gate that contains the string "0" but never BRANCHES on a degenerate value
        is (correctly) a survivor.

OWNED BACKEND CONSUMED (no new engine is built here)
  <ws>/.auditooor/dataflow_paths.jsonl  (schema dataflow_path.v1) produced by
  tools/go-dataflow.py (go/ssa + callgraph + backward DefUse slice) for the Go arm
  and by the Slither data_dependency arm for Solidity. Each record ties an
  ENTRYPOINT to a sink and carries the CLOSURE-consulted branch/guard nodes
  (guard_nodes[].expr) that the engine observed on the control-flow edges of the
  gate's validated closure. GATES membership reads the entrypoint identity; the
  DEGEN_REASONED CFG-branch-coverage test reads guard_nodes[].expr. Auto-unions any
  scoped sibling dataflow_paths.*.jsonl (a per-package go-dataflow run produced when
  the merged sidecar timed out on a heavy Cosmos monorepo).

OUTPUT
  <ws>/.auditooor/degenerate_input_verdict_obligations.jsonl - one row per survivor,
  schema `auditooor.degenerate_input_verdict_gap.v1`, exploit_queue-ingest
  compatible. exploit-queue.py ingests it via
  _gather_from_degenerate_input_verdict_obligations -> the queue ->
  per-fn-mimo-batch-gen OPEN-OBLIGATIONS block.

  A summary is printed / emitted (--json) with |GATES|, |DEGEN_REASONED|,
  |GATES\\DEGEN_REASONED|, the KEPT (gate WITH a degenerate-branch verdict, proving
  the subtraction is non-vacuous) and the survivors.
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
# GATE classification - is this entrypoint a verification / proof / status /
# root ADMISSION gate? An admission gate's purpose is to admit-or-reject; a
# SETTER / GETTER / a plain noun ('validator') is NOT a gate. This is a coarse
# UNIVERSE pre-filter (exactly as the Euler #3 hunter pre-filters DOWN by
# sink.kind); the LOAD-BEARING logic is the degenerate-branch coverage relation
# below, not this name signal.
# ---------------------------------------------------------------------------

# Admission-verb / proof-noun signals. Word-ish anchoring so 'validator' (a noun)
# does NOT match 'validate' (the admission verb): validate must be followed by a
# verb ending (e / es / ed / ing / ion / ity) and NOT by 'or'.
_GATE_NAME = re.compile(
    r"(?:^|[^a-z])(?:"
    r"verif(?:y|ies|ied|ication)|"
    r"validat(?:e|es|ed|ing|ion|ity)|"       # validate/validated/validation, NOT validator
    r"is[_]?valid|"
    r"authenticat|"
    r"authoriz|"
    r"attest|"
    r"check[_]?(?:sig|signature|proof|quorum|threshold|status|auth|merkle|root)|"
    r"(?:verify|check|valid)[_]?merkle|"
    r"merkle[_]?proof|"
    r"verify[_]?proof|"
    r"prove[_]?|"
    r"ecrecover|recover[_]?signer|"
    r"require[_]?(?:auth|status|quorum|signer|valid)|"
    r"quorum|threshold[_]?(?:met|check|reached)"
    r")",
    re.IGNORECASE,
)

# Structural EXCLUSIONS: an admission gate is not a state MUTATOR / accessor /
# constructor. A fn whose bare name starts with one of these is a setter/getter/
# factory, never a verdict gate (kills the cosmos-sdk `SetValidator...` noise
# that matches `validat` inside the noun 'Validator').
_NON_GATE_PREFIX = re.compile(
    r"^(?:set|get|store|save|write|put|add|remove|delete|new|make|init|"
    r"register|update|emit|mint|burn|transfer|deposit|withdraw|create)",
    re.IGNORECASE,
)


def is_gate(fn_ident: str) -> bool:
    """True iff the fn identity is a verification / proof / status / root
    ADMISSION gate (pure name+role classifier; the CFG-branch logic is the
    set-difference in the caller)."""
    short = _short_fn(fn_ident)
    if not short:
        return False
    if _NON_GATE_PREFIX.match(short):
        return False
    return bool(_GATE_NAME.search(short))


# ---------------------------------------------------------------------------
# The DEGENERATE-BRANCH node predicate. Classifies a single CFG BRANCH / guard
# NODE (an expr string) as "a branch that tests a verified value for its ZERO /
# EMPTY / DEFAULT form". This is a per-NODE predicate exactly as the Euler
# hunter's solvency_guard_pred is a per-node predicate; the LOGIC is the
# transitive-closure branch-coverage set-difference wrapped around it, not this
# node classifier.
# ---------------------------------------------------------------------------

# (1) zero / default numeric or sentinel comparison: == 0 / != 0 / == 0x0 /
#     > 0 / < 1 / >= 1 (a branch that separates the zero value from the rest).
_DEGEN_ZERO = re.compile(
    r"(==|!=|<=|>=|<|>)\s*(0x0+|0\b)|"          # cmp against 0 / 0x0
    r"\b(0x0+|0)\s*(==|!=|<|>|<=|>=)|"          # 0 on the left
    r"\bnonzero\b|\bnon[_]?zero\b",
    re.IGNORECASE,
)
# (2) empty-collection / empty-length branch: .length (== / != / > / <) ...,
#     len(x) (== / != / > / <) ..., IsEmpty()/Empty()/isEmpty, empty(x).
_DEGEN_EMPTY = re.compile(
    r"\.length\s*(==|!=|<=|>=|<|>)|"
    r"\blen\s*\([^)]*\)\s*(==|!=|<=|>=|<|>)|"
    r"\bis[_]?empty\b|\.empty\s*\(|\bempty\s*\(|"
    r"==\s*\"\"|!=\s*\"\"|==\s*''|!=\s*''",
    re.IGNORECASE,
)
# (3) zero-address / zero-hash / nil sentinel branch: == address(0), != address(0),
#     == bytes32(0), == nil, != nil, IsZero(), == common.Address{}.
_DEGEN_SENTINEL = re.compile(
    r"address\(0\)|bytes32\(0\)|bytes\(0\)|"
    r"(==|!=)\s*nil|\bnil\s*(==|!=)|"
    r"\bis[_]?zero\b|\.iszero\b|"
    r"common\.address\{\}|\bzeroaddress\b|address\(this\)\s*==",
    re.IGNORECASE,
)


def degenerate_branch_pred(expr: str) -> bool:
    """True iff the guard-NODE expression is a CFG branch that tests a verified
    value for its ZERO / EMPTY / DEFAULT form. Pure node predicate; the
    set/closure branch-coverage logic lives in the caller."""
    e = (expr or "").strip()
    if not e:
        return False
    if _DEGEN_ZERO.search(e):
        return True
    if _DEGEN_EMPTY.search(e):
        return True
    if _DEGEN_SENTINEL.search(e):
        return True
    return False


# ---------------------------------------------------------------------------
# Record -> entrypoint unit helpers (shared shape with the Euler #3 hunter).
# ---------------------------------------------------------------------------
_ENTRY_SRC_KINDS = {"param-entrypoint", "entrypoint", "param"}


def _entrypoint_of(rec: dict) -> str:
    src = rec.get("source") or {}
    sink = rec.get("sink") or {}
    if str(src.get("kind") or "") in _ENTRY_SRC_KINDS and src.get("fn"):
        return str(src["fn"])
    if sink.get("fn"):
        return str(sink["fn"])
    return str(src.get("fn") or "")


def _fn_file(rec: dict, fn: str) -> str:
    sink = rec.get("sink") or {}
    src = rec.get("source") or {}
    if src.get("fn") == fn and src.get("file"):
        return str(src["file"])
    if sink.get("fn") == fn and sink.get("file"):
        return str(sink["file"])
    return str(src.get("file") or sink.get("file") or "")


def _fn_line(rec: dict, fn: str) -> int:
    src = rec.get("source") or {}
    sink = rec.get("sink") or {}
    if src.get("fn") == fn and src.get("line"):
        return int(src["line"])
    if sink.get("fn") == fn and sink.get("line"):
        return int(sink["line"])
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


# Vendored dependency trees + generated code never carry an in-scope obligation
# (shared with the Euler #3 hunter). `/pkg/mod/`, `/go/pkg/` = the Go module cache
# (cosmos-sdk et al); `.pb.go` = protoc/grpc codegen.
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
        rel = Path(fpath).resolve().relative_to(ws_root)
    except Exception:
        return False
    if not include_oos and is_oos(str(rel)):
        return False
    return True


def _short_fn(fn: str) -> str:
    """Bare function name from a Solidity 'C.f(uint256)' or Go '(*pkg.T).Method'
    / 'pkg.func' identity. The Go receiver form STARTS with '(' so it is handled
    BEFORE any split on '('."""
    s = (fn or "").strip()
    if ")." in s:
        s = s.rsplit(").", 1)[-1]
    s = s.split("(")[0].replace("*", "")
    return s.split(".")[-1].strip()


def _contract_of(fn: str) -> str:
    s = (fn or "").strip()
    if ")." in s:
        recv = s.rsplit(").", 1)[0].lstrip("(").lstrip("*")
        return recv.split(".")[-1]
    head = s.split("(")[0]
    parts = head.split(".")
    return parts[0] if len(parts) > 1 else ""


class Gate:
    __slots__ = ("fn", "file", "line", "lang", "guard_exprs",
                 "degen_exprs", "n_records")

    def __init__(self, fn: str):
        self.fn = fn
        self.file = ""
        self.line = 0
        self.lang = ""
        self.guard_exprs: list[str] = []
        self.degen_exprs: list[str] = []   # branch exprs that DID test a degenerate value
        self.n_records = 0


def build_gates(dataflow_path: Path, ws_root: Path,
                include_oos: bool = False) -> tuple[dict, list[str]]:
    """Fold dataflow_paths.jsonl into per-ENTRYPOINT Gate units, restricted to
    verification/proof/status/root admission gates, accumulating the CLOSURE
    branch-node exprs and tagging which of them test a degenerate value.
    Returns (gates_by_fn, warnings)."""
    gates: dict[str, Gate] = {}
    warnings: list[str] = []
    n_total = n_degraded = 0
    if not dataflow_path.is_file():
        warnings.append(f"dataflow_paths absent: {dataflow_path}")
        return gates, warnings
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
            fn = _entrypoint_of(rec)
            if not fn or not is_gate(fn):
                continue
            fpath = _fn_file(rec, fn)
            if not _in_scope_file(fpath, ws_root, include_oos):
                continue
            g = gates.get(fn)
            if g is None:
                g = Gate(fn)
                g.file = fpath
                g.line = _fn_line(rec, fn)
                g.lang = str(rec.get("language") or "")
                gates[fn] = g
            g.n_records += 1
            if not g.file and fpath:
                g.file = fpath
            for gn in rec.get("guard_nodes") or []:
                e = gn.get("expr")
                if not e:
                    continue
                e = str(e)
                g.guard_exprs.append(e)
                if degenerate_branch_pred(e):
                    g.degen_exprs.append(e)
    if n_total and n_degraded == n_total:
        warnings.append(
            f"ALL {n_total} dataflow records are DEGRADED (substrate-starved: "
            f"compile-fail / go-dataflow timeout) - the set-difference is "
            f"vacuously empty because the call graph never materialized, NOT "
            f"because GATES is a subset of DEGEN_REASONED. Re-run go-dataflow.py "
            f"scoped to the in-scope package (see --alt-dataflow).")
    return gates, warnings


def classify(gates: dict) -> dict:
    """Compute GATES, DEGEN_REASONED, and the SET-DIFFERENCE GATES\\DEGEN_REASONED."""
    all_gates = set(gates.keys())
    degen_reasoned = {fn for fn, g in gates.items() if g.degen_exprs}
    survivors = sorted(all_gates - degen_reasoned)
    kept = sorted(all_gates & degen_reasoned)
    return {
        "gates": sorted(all_gates),
        "degen_reasoned": sorted(degen_reasoned),
        "survivors": survivors,
        "kept": kept,
    }


def make_obligation(g: Gate, invariant_id: str) -> dict:
    short = _short_fn(g.fn)
    contract = _contract_of(g.fn)
    src_ref = g.file + (f":{g.line}" if g.line else "")
    n_branches = len(set(g.guard_exprs))
    root = (
        f"Verification/proof/status gate '{g.fn}' is an admission boundary whose "
        f"validated closure carries {n_branches} branch predicate(s) but NONE of "
        "them tests the verified input for its ZERO / EMPTY / DEFAULT value "
        "(set-difference GATES\\DEGEN_REASONED). The degenerate-input branch has "
        "NO reasoned verdict: a caller supplying an empty signature / zero merkle "
        "root / empty signer-or-vote set / zero threshold / default-init status "
        "reaches the ACCEPT verdict with no reject rejecting the tx - "
        "authentication / proof / quorum bypass (ecrecover(0) / empty-proof class)."
    )
    return {
        "schema": "auditooor.degenerate_input_verdict_gap.v1",
        "obligation_type": "degenerate-input-unverdicted-gate",
        "contract": contract,
        "function": short,
        "function_signature": g.fn,
        "language": g.lang,
        "source_refs": [src_ref] if src_ref else [],
        "file": g.file,
        "line": g.line,
        "closure_branch_count": n_branches,
        "closure_branch_exprs": sorted(set(g.guard_exprs))[:8],
        "attack_class": "verification-gate-degenerate-input-no-verdict",
        "likely_severity": "high",
        "broken_invariant_ids": [invariant_id],
        "root_cause_hypothesis": root,
        "quality_gate_status": "needs_source",
        "proof_status": "needs_source",
        "advisory_only": True,
        "learning_route": "mine-source",
        "falsification_requirements": [
            "DEGENERATE_BRANCH: prove NO reject predicate over the verified input's "
            "zero/empty/default value is reachable in the gate's fwd closure (a "
            "`== 0` / `!= address(0)` / `len(x)==0` / `.length>0` / `== nil` / "
            "IsZero()/IsEmpty() branch N hops away in a helper KILLS the lead).",
            "VERIFIED_INPUT: confirm the gate ADMITS on an attacker-suppliable "
            "input whose degenerate value is meaningful (signature bytes, merkle "
            "proof, signer/vote set, threshold, root), not an internal invariant.",
            "ACCEPT_REACHABLE: show the degenerate-input CFG path reaches the "
            "ACCEPT verdict (return true / no-revert / status=ok) and that admission "
            "yields an unauthorized effect (mint / transfer / state advance).",
        ],
        "next_command": (
            "read the gate body + its callee closure; if the zero/empty/default "
            "input branch genuinely reaches ACCEPT with no reject, author the "
            "admission-boundary invariant and drive an executed bypass PoC "
            "(e.g. ecrecover-returns-0 / empty-proof)."
        ),
    }


def run(argv=None) -> dict:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--workspace", required=True)
    ap.add_argument("--dataflow", default=None,
                    help="override dataflow_paths.jsonl path")
    ap.add_argument("--alt-dataflow", default=None,
                    help="additional dataflow jsonl to UNION (e.g. a scoped "
                         "package run when the merged sidecar is degraded)")
    ap.add_argument("--include-oos", action="store_true",
                    help="do NOT apply the scope OOS filter (debug)")
    ap.add_argument("--invariant-id",
                    default="INV-VERIFICATION-GATE-DEGENERATE-INPUT-VERDICT",
                    help="broken_invariant_id stamped on every obligation")
    ap.add_argument("--emit", default=None,
                    help="output jsonl path (default "
                         "<ws>/.auditooor/degenerate_input_verdict_obligations.jsonl)")
    ap.add_argument("--json", action="store_true")
    ap.add_argument("--fail-closed", action="store_true",
                    help="exit non-zero if the dataflow substrate is fully "
                         "degraded (the set-difference could not be computed)")
    args = ap.parse_args(argv)

    ws = Path(args.workspace).expanduser().resolve()
    df = Path(args.dataflow).expanduser() if args.dataflow else \
        ws / ".auditooor" / "dataflow_paths.jsonl"

    gates, warnings = build_gates(df, ws, include_oos=args.include_oos)

    # Union any SCOPED sidecars <ws>/.auditooor/dataflow_paths.*.jsonl (e.g. a
    # per-package go-dataflow run produced because the merged sidecar timed out /
    # degraded on a heavy Cosmos monorepo). Plus any explicit --alt-dataflow.
    alt_paths: list[Path] = []
    if args.alt_dataflow:
        alt_paths.append(Path(args.alt_dataflow).expanduser())
    if not args.dataflow:
        for sib in sorted((ws / ".auditooor").glob("dataflow_paths.*.jsonl")):
            if sib.resolve() != df.resolve():
                alt_paths.append(sib)
    for alt in alt_paths:
        alt_gates, alt_warn = build_gates(alt, ws, include_oos=args.include_oos)
        warnings.extend(alt_warn)
        for fn, ag in alt_gates.items():
            g = gates.get(fn)
            if g is None:
                gates[fn] = ag
                continue
            g.guard_exprs.extend(ag.guard_exprs)
            g.degen_exprs.extend(ag.degen_exprs)
            g.n_records += ag.n_records
            if not g.file:
                g.file = ag.file

    res = classify(gates)

    obligations = []
    _seen_ob = set()
    for fn in res["survivors"]:
        g = gates[fn]
        dk = (g.file, g.line, _short_fn(fn))
        if dk in _seen_ob:
            continue
        _seen_ob.add(dk)
        obligations.append(make_obligation(g, args.invariant_id))

    emit = Path(args.emit).expanduser() if args.emit else \
        ws / ".auditooor" / "degenerate_input_verdict_obligations.jsonl"
    emit.parent.mkdir(parents=True, exist_ok=True)
    with emit.open("w", encoding="utf-8") as fh:
        for ob in obligations:
            fh.write(json.dumps(ob) + "\n")

    substrate_degraded = any("DEGRADED" in w for w in warnings) and not gates

    summary = {
        "schema": "auditooor.degenerate_input_verdict_verdict.v1",
        "workspace": str(ws),
        "dataflow": str(df),
        "generated_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "n_gate_units": len(gates),
        "size_GATES": len(res["gates"]),
        "size_DEGEN_REASONED_among_gates": len(res["kept"]),
        "size_DIFF_survivors": len(res["survivors"]),
        "kept_gate_with_degenerate_verdict": [_short_fn(f) for f in res["kept"]],
        "survivors": [
            {"fn": _short_fn(f), "signature": f,
             "file": gates[f].file, "line": gates[f].line,
             "closure_branch_count": len(set(gates[f].guard_exprs))}
            for f in res["survivors"]
        ],
        "obligations_written": len(obligations),
        "obligations_path": str(emit),
        "warnings": warnings,
        "substrate_degraded": substrate_degraded,
    }

    if args.json:
        print(json.dumps(summary, indent=2))
    else:
        print(f"[degen-input-verdict] {ws.name}: "
              f"|GATES|={summary['size_GATES']} "
              f"|DEGEN_REASONED(among GATES)|={summary['size_DEGEN_REASONED_among_gates']} "
              f"survivors(GATES\\DEGEN_REASONED)={summary['size_DIFF_survivors']} "
              f"-> {len(obligations)} degenerate-input-unverdicted-gate obligation(s)")
        if res["kept"]:
            print("  KEPT (gate WITH a degenerate-branch verdict, removed from diff): "
                  + ", ".join(summary["kept_gate_with_degenerate_verdict"]))
        for s in summary["survivors"][:40]:
            print(f"  SURVIVOR {s['fn']}  branches={s['closure_branch_count']}  "
                  f"{s['file']}:{s['line']}")
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
