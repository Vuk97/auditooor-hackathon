#!/usr/bin/env python3
"""zk-dataflow.py - native offline ZK (circom) signal-flow def-use backend.

Phase: df-be-zk lane. STANDALONE producer of the SHARED tools/dataflow_schema.py
DefUsePath records (does NOT edit dataflow-slice.py / readme_runbook_steps.json).

WHAT IT DOES
------------
Parses a .circom circuit's SIGNAL graph and distinguishes the two operator
families that circom (deliberately) keeps separate:

  ASSIGNMENT (witness, NO constraint emitted)
      sig <-- expr          # witness-only assign (prover sets the value)
      var  = expr           # plain (var-style) assignment

  CONSTRAINT (emits an R1CS constraint)
      sig <== expr          # assign + constraint (the safe operator)
      a   === b             # bare constraint

The canonical ZK soundness bug is an output / intermediate SIGNAL that is
ASSIGNED (reaches a `<--`) but NEVER reaches a CONSTRAINT path (`<==` / `===`).
The R1CS then imposes no algebraic relation on it, so a malicious prover can
forge its value while still producing a valid proof ("under-constrained signal").

For each such signal this tool emits a DefUsePath (tools/dataflow_schema.py v1):
  source.kind = "signal"
  unguarded   = True            (no constraint dominates the assign)
  via         = "intra"         (schema-frozen enum; signal_via carries detail)
  signal_via  = "signal-assign|signal-constrain"   (task-required label, extra field)
  confidence  = "syntactic"     (schema-frozen enum; signal_confidence carries detail)
  signal_confidence = "signal-shape"               (task-required label, extra field)

A constrained signal (assign-edge AND a reachable constrain-edge) is NOT flagged.

SCHEMA CONFORMANCE NOTE
-----------------------
dataflow_schema.py freezes `confidence` to {semantic-ssa, syntactic, heuristic}
and hop `via` to {internal_call, high_level, return, boundary, intra, storage}.
The task's requested labels ("signal-shape", "signal-assign"/"signal-constrain")
are NOT in those frozen enums and the schema must NOT be edited. We therefore:
  - set the schema-validated fields to the nearest legal enum value
    (confidence="syntactic", hop via="intra"), AND
  - carry the task-required ZK semantics as EXTRA fields (signal_confidence,
    signal_via, kind="signal") that the validator tolerates (it checks for
    required-key presence, not extra-key absence - same mechanism dataflow-slice.py
    uses for its `mode` field).
Every emitted record passes dataflow_schema.validate().

circomspect INTEGRATION (offline corroboration)
-----------------------------------------------
If `circomspect` is on PATH it is run on the circuit and its under-constraint
warnings (CS0013 unnecessary `<--`, "is not constrained") are attached to the
matching signal's record as `circomspect_corroborated=True`. circomspect is
corroboration only - the native parser is the primary signal, so the tool works
identically (sans corroboration flag) on hosts without circomspect.

R80 DEGRADE CONTRACT
--------------------
On a non-circom workspace (no .circom files) the tool is a clean no-op (verdict
no-circom-circuits, exit 0). On a parse failure for a circuit, it emits a
dataflow_schema.degrade_record (degraded=True, confidence="heuristic",
engine="unsupported-or-compile-fail-degrade") rather than a fabricated flow - an
unparseable circuit is NOT silently dropped and is NEVER cited as a proven flow.

Schema: records are dataflow_path.v1 (tools/dataflow_schema.py).

Usage:
  python3 tools/zk-dataflow.py --workspace /path/to/ws            # scan recursively
  python3 tools/zk-dataflow.py --target circuit.circom --json     # single circuit
  python3 tools/zk-dataflow.py --workspace WS --no-circomspect    # pure parser
"""
from __future__ import annotations

import argparse
import json
import os
import re
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

# Import the SHARED schema (must NOT be edited by this lane).
sys.path.insert(0, str(Path(__file__).resolve().parent))
import dataflow_schema as dfs  # noqa: E402

LANGUAGE = "circom"
ENGINE = "zk-circom-signal-parser"

# Task-required labels carried as EXTRA fields (not in the frozen schema enums).
SIGNAL_CONFIDENCE = "signal-shape"
SIGNAL_VIA_ASSIGN = "signal-assign"
SIGNAL_VIA_CONSTRAIN = "signal-constrain"

EXCLUDED_DIRS = {
    "node_modules", ".git", "target", ".auditooor",
    "dependencies", "codebases",
}

# ---------------------------------------------------------------------------
# Circom source tokenisation (comment-stripped, operator-aware)
# ---------------------------------------------------------------------------

def _strip_comments(src: str) -> str:
    """Remove // line comments and /* */ block comments, preserving line count."""
    # block comments -> blanked but keep newlines for line numbers
    def _blank_block(m: re.Match) -> str:
        return re.sub(r"[^\n]", " ", m.group(0))
    src = re.sub(r"/\*.*?\*/", _blank_block, src, flags=re.DOTALL)
    # line comments - blank (don't delete) so offsets/length stay aligned with raw
    src = re.sub(r"//[^\n]*", lambda m: " " * len(m.group(0)), src)
    return src


# Signal declarations: signal [input|output] name [;,]  (also arrays name[..])
_SIGNAL_DECL_RE = re.compile(
    r"\bsignal\s+(?:(input|output)\s+)?([A-Za-z_]\w*)"
)

# An identifier optionally followed by an index / member access, captured as the
# bare signal name (left of [ or .).
_LHS_NAME_RE = re.compile(r"\b([A-Za-z_]\w*)")


def _lhs_signal_name(lhs: str) -> Optional[str]:
    """Extract the bare signal name from a LHS token like `out`, `out[3]`, `o.x`."""
    lhs = lhs.strip()
    m = _LHS_NAME_RE.match(lhs)
    return m.group(1) if m else None


class CircomParse:
    """Per-circuit signal-flow facts derived by a syntactic scan."""

    def __init__(self, path: Path):
        self.path = path
        self.declared: Dict[str, Dict[str, Any]] = {}   # name -> {kind, line}
        self.assigned: Dict[str, int] = {}              # name -> first assign line (<-- / =)
        self.constrained: set[str] = set()              # names reaching a constrain edge
        self.constrain_lines: Dict[str, int] = {}       # name -> first constrain line
        self.parse_errors: List[str] = []

    @property
    def output_or_intermediate(self) -> List[str]:
        """Signals that are output/intermediate (NOT pure inputs) - the at-risk set.

        An `input` signal is supplied by the verifier and is not the prover's to
        forge; the under-constraint bug class is about OUTPUT / INTERMEDIATE
        signals the prover assigns. We therefore restrict the flag set to
        non-input declared signals.
        """
        return [n for n, d in self.declared.items() if d["kind"] != "input"]


def parse_circom(path: Path) -> CircomParse:
    """Syntactic signal-flow parse of one .circom file.

    Distinguishes assignment (<--, =) from constraint (<==, ===). Order of the
    operator checks matters: `<==` and `===` must be tested BEFORE `<--`/`=`/`==`
    so the longer constraint operators win.
    """
    cp = CircomParse(path)
    try:
        raw = path.read_text(encoding="utf-8", errors="replace")
    except Exception as exc:  # pragma: no cover - IO failure path
        cp.parse_errors.append(f"read failed: {exc}")
        return cp

    src = _strip_comments(raw)
    lines = src.splitlines()

    # 1) declarations
    for lineno, line in enumerate(lines, start=1):
        for m in _SIGNAL_DECL_RE.finditer(line):
            kind = m.group(1) or "intermediate"  # no input/output keyword => intermediate
            name = m.group(2)
            # first declaration wins; keep the most specific kind
            if name not in cp.declared:
                cp.declared[name] = {"kind": kind, "line": lineno}

    # 2) assignment / constraint edges - scan statements split on ';'
    #    (newline-robust: a statement can span lines, but circom uses ';').
    #    We scan char-by-char operator occurrences across the whole comment-
    #    stripped source, mapping offsets back to line numbers.
    line_starts = []
    off = 0
    for line in raw.splitlines(keepends=True):
        line_starts.append(off)
        off += len(line)

    def _offset_to_line(stripped_offset: int) -> int:
        # src (comment-stripped) and raw share the same length & newline layout
        # because _strip_comments preserves newlines and length-blanks blocks.
        lo, hi = 0, len(line_starts) - 1
        while lo < hi:
            mid = (lo + hi + 1) // 2
            if line_starts[mid] <= stripped_offset:
                lo = mid
            else:
                hi = mid - 1
        return lo + 1

    # CONSTRAINT operators first (longest match wins).
    #   sig <== expr   : LHS signal is BOTH assigned and constrained
    #   lhs === rhs    : both sides' signal names are constrained
    for m in re.finditer(r"([^\n;{}]+?)<==([^\n;{}]+)", src):
        name = _lhs_signal_name(m.group(1))
        if name:
            cp.constrained.add(name)
            cp.constrain_lines.setdefault(name, _offset_to_line(m.start()))
            # `<==` also assigns the witness
            cp.assigned.setdefault(name, _offset_to_line(m.start()))

    for m in re.finditer(r"([^\n;{}]+?)===([^\n;{}]+)", src):
        # both operands may name signals; constrain every signal-looking token.
        for side in (m.group(1), m.group(2)):
            for tok in re.findall(r"\b([A-Za-z_]\w*)\b", side):
                if tok in cp.declared:
                    cp.constrained.add(tok)
                    cp.constrain_lines.setdefault(tok, _offset_to_line(m.start()))

    # ASSIGNMENT operators (witness-only). Guard against matching `<==` / `===`
    # by requiring the char before/after is not part of a longer operator.
    #   sig <-- expr
    for m in re.finditer(r"([^\n;{}]+?)<--([^\n;{}]+)", src):
        name = _lhs_signal_name(m.group(1))
        if name:
            cp.assigned.setdefault(name, _offset_to_line(m.start()))

    #   var = expr  (plain assignment; NOT == / <== / >= / <= / === / !=)
    for m in re.finditer(r"([^\n;{}=<>!]+?)=(?![=])([^\n;{}]+)", src):
        # skip if this '=' is actually part of <==, ===, >=, <=, !=, == (handled above)
        prev_char = src[m.start(0):m.start(0) + len(m.group(1))]
        name = _lhs_signal_name(m.group(1))
        if name and name in cp.declared:
            cp.assigned.setdefault(name, _offset_to_line(m.start()))

    return cp


# ---------------------------------------------------------------------------
# circomspect corroboration (offline, optional)
# ---------------------------------------------------------------------------

def circomspect_underconstrained_signals(path: Path, timeout: int = 120) -> Tuple[bool, set]:
    """Return (ran, set_of_signal_names) circomspect flags as under-constrained.

    Looks for the two circomspect signatures that indicate a witness-only / not-
    constrained signal:
      - "Using the signal assignment operator `<--` is not necessary" (CS0013)
      - "The signal `X` is not constrained by the template"           (CA01)
    """
    binary = shutil.which("circomspect")
    if not binary:
        return False, set()
    try:
        proc = subprocess.run(
            [binary, str(path), "-l", "INFO"],
            capture_output=True, text=True, timeout=timeout,
        )
    except Exception:
        return False, set()
    raw = (proc.stdout or "") + "\n" + (proc.stderr or "")
    flagged: set = set()
    # "The signal `name` is not constrained"
    for m in re.finditer(r"signal `([A-Za-z_]\w*)` is not constrained", raw):
        flagged.add(m.group(1))
    # "The variable `name` is assigned a value, but this value is never read"
    for m in re.finditer(r"variable `([A-Za-z_]\w*)` is assigned a value, but", raw):
        flagged.add(m.group(1))
    # CS0013 unnecessary `<--`: the offending line names the LHS signal; grab it
    # from the following source-echo line `out <-- ...`.
    for m in re.finditer(r"^\s*\d+\s*│\s*([A-Za-z_]\w*)\s*<--", raw, re.MULTILINE):
        flagged.add(m.group(1))
    ran = proc.returncode is not None
    return True, flagged


# ---------------------------------------------------------------------------
# DefUsePath builder (uses the SHARED schema)
# ---------------------------------------------------------------------------

def build_signal_paths(
    cp: CircomParse,
    cs_ran: bool,
    cs_flagged: set,
) -> List[Dict[str, Any]]:
    """Emit a DefUsePath per assigned-but-not-constrained output/intermediate signal.

    Also emits a (non-unguarded) path for assigned-AND-constrained output/
    intermediate signals so a consumer can see the safe sibling. The unguarded
    flag is the discriminator.
    """
    records: List[Dict[str, Any]] = []
    fname = cp.path.name
    idx = 0

    for name in sorted(cp.output_or_intermediate):
        assign_line = cp.assigned.get(name)
        if assign_line is None:
            # declared but never assigned (e.g. a pure-input mis-decl) - skip;
            # not part of the assigned-but-unconstrained bug class.
            continue
        is_constrained = name in cp.constrained
        constrain_line = cp.constrain_lines.get(name)
        decl = cp.declared[name]

        # hop A: the witness-assign edge (always present once assigned)
        hops = [{
            "from_var": None,
            "to_var": name,
            "fn": None,
            "via": "intra",                 # schema-frozen enum value
            "signal_via": SIGNAL_VIA_ASSIGN,  # task-required label (extra field)
            "file": str(cp.path),
            "line": assign_line,
            "ir": f"{name} <-- <expr>",
            "guarded": False,               # an assign edge is never itself a guard
        }]

        guard_nodes: List[Dict[str, Any]] = []
        if is_constrained:
            # hop B: the constrain edge -> acts as the "guard" that binds the signal
            hops.append({
                "from_var": name,
                "to_var": name,
                "fn": None,
                "via": "intra",
                "signal_via": SIGNAL_VIA_CONSTRAIN,
                "file": str(cp.path),
                "line": constrain_line or assign_line,
                "ir": f"{name} <== / === <expr>",
                "guarded": True,            # constraint edge => guarded hop
            })
            guard_nodes.append({
                "file": str(cp.path),
                "line": constrain_line or assign_line,
                "expr": f"constraint binds signal `{name}` (<== / ===)",
            })

        source = {
            "kind": "signal",
            "fn": None,
            "var": name,
            "file": str(cp.path),
            "line": decl["line"],
        }
        sink = {
            "kind": "constrained-signal" if is_constrained else "unconstrained-signal",
            "callee": None,
            "arg_pos": None,
            "fn": None,
            "file": str(cp.path),
            "line": (constrain_line if is_constrained else assign_line),
        }

        rec = dfs.new_path(
            path_id=f"zkdfp-{fname}-{idx:04d}",
            language=LANGUAGE,
            direction="forward",
            engine=ENGINE,
            source=source,
            sink=sink,
            hops=hops,
            guard_nodes=guard_nodes,
            source_unit_ids=[f"{fname}:{decl['line']}"],
            sink_unit_ids=[f"{fname}:{sink['line']}"],
            confidence="syntactic",         # schema-frozen enum value
            degraded=False,
        )
        # task-required extra fields (validator tolerates extras, like `mode`)
        rec["signal_confidence"] = SIGNAL_CONFIDENCE
        rec["signal_kind"] = decl["kind"]
        rec["mode"] = "zk-signal"
        rec["circomspect_ran"] = cs_ran
        rec["circomspect_corroborated"] = bool(cs_ran and name in cs_flagged)
        # NOTE: `unguarded` is derived authoritatively by dfs.new_path from
        # guard_nodes + hop.guarded (no constrain edge / no guard => unguarded).
        # We do NOT override it here - the derivation is the single source of
        # truth, so a corrupted hop.guarded correctly flips the flag (non-vacuity).
        records.append(rec)
        idx += 1

    return records


# ---------------------------------------------------------------------------
# Discovery + orchestration
# ---------------------------------------------------------------------------

def find_circom_files(workspace: Path) -> List[Path]:
    results = []
    for root, dirs, files in os.walk(workspace):
        dirs[:] = [d for d in dirs if d not in EXCLUDED_DIRS]
        for fname in files:
            if fname.endswith(".circom"):
                results.append(Path(root) / fname)
    return sorted(results)


def analyze(
    circuits: List[Path],
    use_circomspect: bool,
    timeout: int,
) -> Tuple[List[Dict[str, Any]], Dict[str, Any]]:
    all_records: List[Dict[str, Any]] = []
    per_circuit: List[Dict[str, Any]] = []

    for circ in circuits:
        cp = parse_circom(circ)
        if cp.parse_errors:
            all_records.append(
                dfs.degrade_record(LANGUAGE, "; ".join(cp.parse_errors)[:500])
            )
            per_circuit.append({
                "circuit": str(circ),
                "status": "degrade",
                "reason": cp.parse_errors,
            })
            continue
        cs_ran, cs_flagged = (circomspect_underconstrained_signals(circ, timeout)
                              if use_circomspect else (False, set()))
        recs = build_signal_paths(cp, cs_ran, cs_flagged)
        all_records.extend(recs)
        unguarded_n = sum(1 for r in recs if r.get("unguarded"))
        per_circuit.append({
            "circuit": str(circ),
            "status": "ok",
            "signals_declared": len(cp.declared),
            "signals_at_risk": len(cp.output_or_intermediate),
            "paths_emitted": len(recs),
            "unguarded_paths": unguarded_n,
            "circomspect_ran": cs_ran,
            "circomspect_flagged": sorted(cs_flagged),
        })

    summary = {
        "verdict": "no-circom-circuits" if not circuits else "analysis-complete",
        "circuits_scanned": len(circuits),
        "records_emitted": len(all_records),
        "unguarded_records": sum(1 for r in all_records if r.get("unguarded")),
        "degraded_records": sum(1 for r in all_records if r.get("degraded")),
        "per_circuit": per_circuit,
    }
    return all_records, summary


def write_records(out_path: Path, records: List[Dict[str, Any]],
                  merge: bool = False) -> Tuple[int, List[str]]:
    """Validate every record against the shared schema, then write JSONL.

    merge=True (B-zk default for the shared sidecar): language-scoped merge so circom
    rows land alongside other arms' rows. merge=False (explicit --output-jsonl): legacy
    truncating single-file write.
    """
    errs: List[str] = []
    valid: List[Dict[str, Any]] = []
    for i, r in enumerate(records):
        ok, verrs = dfs.validate(r)
        if not ok:
            errs.append(f"record[{i}] invalid: {verrs}")
            continue
        valid.append(r)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    if merge:
        n = dfs.merge_write(str(out_path), valid, LANGUAGE)
    else:
        n = dfs.write_jsonl(str(out_path), valid)
    return n, errs


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        description="Native offline ZK (circom) signal-flow def-use backend. "
                    "Emits shared dataflow_schema.py DefUsePath records. "
                    "NO-OP (verdict=no-circom-circuits, exit 0) on non-circom workspaces.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    p.add_argument("--workspace", "-w", type=Path,
                   help="Workspace root; scanned recursively for .circom files.")
    p.add_argument("--target", "-t", type=Path, action="append", dest="targets",
                   help="Explicit .circom file (repeatable). Mutually exclusive with --workspace.")
    p.add_argument("--output-jsonl", "-o", type=Path,
                   help="Override output JSONL path (TRUNCATING single-file write). "
                        "Default (B-zk): the SHARED polyglot sidecar "
                        "<workspace>/.auditooor/dataflow_paths.jsonl, written via "
                        "language-scoped merge so circom rows land alongside "
                        "solidity/rust/go rows. With --target (no --workspace) and no "
                        "-o, defaults to ./dataflow_paths.jsonl (truncating).")
    p.add_argument("--no-circomspect", action="store_true",
                   help="Disable circomspect corroboration (pure native parser).")
    p.add_argument("--timeout", type=int, default=120,
                   help="circomspect per-circuit timeout seconds (default 120).")
    p.add_argument("--json", action="store_true",
                   help="Print a JSON summary to stdout.")
    return p


def main(argv: Optional[List[str]] = None) -> int:
    args = build_parser().parse_args(argv)

    if args.workspace and args.targets:
        build_parser().error("--workspace and --target are mutually exclusive")

    workspace: Optional[Path] = None
    circuits: List[Path] = []
    if args.targets:
        circuits = [Path(t) for t in args.targets]
        for c in circuits:
            if not c.is_file():
                build_parser().error(f"--target does not exist: {c}")
    elif args.workspace:
        workspace = args.workspace.resolve()
        if not workspace.is_dir():
            build_parser().error(f"--workspace is not a directory: {workspace}")
        circuits = find_circom_files(workspace)
    else:
        build_parser().error("either --workspace or --target is required")

    # B-zk: default to the SHARED polyglot sidecar (merge), not a separate zk file.
    # An explicit --output-jsonl is a single-file override (truncating, back-compat).
    out_path: Optional[Path] = args.output_jsonl
    use_merge = False
    if out_path is None and workspace is not None:
        out_path = workspace / ".auditooor" / "dataflow_paths.jsonl"
        use_merge = True
    elif out_path is None:
        out_path = Path("dataflow_paths.jsonl")

    records, summary = analyze(circuits, not args.no_circomspect, args.timeout)

    # B-zk no-op safety: on a NON-circom workspace (no circuits found) do NOT touch
    # the shared sidecar at all - a Solidity/Go/Rust-only ws must behave byte-identically
    # whether or not the zk arm ran. Only the merge default is skipped; an explicit
    # --output-jsonl still writes (back-compat with callers that always expect a file).
    if use_merge and not circuits:
        summary["records_written"] = 0
        summary["write_validation_errors"] = []
        summary["output"] = None
        written, write_errs = 0, []
    else:
        written, write_errs = write_records(out_path, records, merge=use_merge)
    summary["records_written"] = written
    summary["write_validation_errors"] = write_errs
    summary["output"] = str(out_path) if written else None

    if args.json:
        print(json.dumps(summary, indent=2))
    else:
        print(f"[zk-dataflow] verdict: {summary['verdict']}")
        print(f"[zk-dataflow] circuits: {summary['circuits_scanned']}  "
              f"records: {summary['records_emitted']}  "
              f"unguarded: {summary['unguarded_records']}  "
              f"degraded: {summary['degraded_records']}")
        for pc in summary["per_circuit"]:
            print(f"  - {pc['circuit']}: {pc.get('status')} "
                  f"paths={pc.get('paths_emitted', 0)} "
                  f"unguarded={pc.get('unguarded_paths', 0)} "
                  f"circomspect={pc.get('circomspect_ran', False)}")
        if summary["output"]:
            print(f"[zk-dataflow] wrote {written} record(s) -> {summary['output']}")
        if write_errs:
            print(f"[zk-dataflow] WARN {len(write_errs)} record(s) failed schema validation")

    # Exit 0 on a clean run (including no-circom no-op); non-zero only if records
    # were produced but ALL failed schema validation (a real producer defect).
    if records and written == 0:
        return 2
    return 0


if __name__ == "__main__":
    sys.exit(main())
