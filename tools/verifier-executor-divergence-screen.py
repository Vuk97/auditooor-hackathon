#!/usr/bin/env python3
"""verifier-executor-divergence-screen.py - the VERIFIER->EXECUTOR SEMANTIC
DIVERGENCE screen (EXT03): "validate representation A, run representation B".

GENERAL LOGIC / TRUST-ENFORCEMENT class (never a bug SHAPE). It instantiates the
north-star method ("a TRUSTED ENFORCEMENT is structurally BLIND to a corrupted
LOWER layer") lifted to the compiler / JIT / codegen / serializer / optimizer
enforcement layer:

  DELEGATED-TRUSTED INVARIANT : a static VERIFIER establishes a safety property
    (bounds / permission / writability / type / resource-limit) on ONE
    representation of a program or datum - source, wasm/eBPF bytecode, IR, AST, a
    schema-validated blob.
  PRIVATE INVARIANT           : a LATER stage (a JIT / single-pass codegen /
    optimizer / object-graph builder) produces a DIFFERENT representation that is
    actually EXECUTED or trusted, and it RE-DERIVES every verifier property on the
    form it runs (or a differential-equivalence argument bridges the two forms).
  ATTACK                      : the verifier==executor equivalence is ASSUMED, not
    proven. The classic instance (Solana sBPF JIT, Zellic 2024): a hand-written
    x86 encoder chose opcode 0x81 (32-bit compare) instead of 0x80 (8-bit), so a
    permission check read struct padding and mis-classified a read-only region as
    writable - the eBPF-bytecode verifier's approval never covered the generated
    x86. The trusted enforcer is BLIND to the corrupted lower layer.

Enforcement points = every CODEGEN / EMITTER site that HAND-PICKS a machine-code
or byte encoding (a raw opcode byte, or an operand WIDTH selected by a size
switch) inside a codebase that ALSO carries a VERIFIER establishing a safety
property on a different representation (so a divergence surface exists). For each
point the screen answers:
  {seam, role, hazard, declared_width, emitted_width, has_recheck, function}

It has TWO tiers:
  * SOUNDNESS (severity-eligible, fires=true): a width-dispatched emit ARM whose
    declared operand size (S8/S16/S32/S64, BYTE/WORD/DWORD/QWORD, case 8/16/32/64,
    emit_uN) does NOT match the operand-encoding width actually emitted (register
    suffix Rb/Rw/Rd/Rq, size keyword, emit_uN) - the sBPF 0x81-vs-0x80 signature.
    Memory-address registers ([...] contents, always pointer-width) are stripped
    and explicit width-conversion arms (>=2 size tokens: movzx/movsx style) are
    skipped, so correct codegen stays SILENT.
  * ENUMERATION (advisory lead, fires=false): every emitter function that
    hand-picks encoding is enumerated as a differential-fuzz lead flagging the
    verifier/executor seam.

ADVISORY-FIRST: every row carries verdict='needs-fuzz', advisory=True,
auto_credit=False. It NEVER auto-credits and NEVER fail-closes in default mode;
the opt-in env AUDITOOOR_VERIFIER_EXECUTOR_STRICT (or --strict) only raises the
exit code when a SOUNDNESS (width-mismatch) point fired. The kill/confirm is
DIFFERENTIAL FUZZING between the verifier-approved form and the executed form.

Language-general: Rust (.rs), Go (.go), C/C++ (.c/.cc/.cpp/.cxx/.h/.hpp),
Solidity (.sol) - the codegen/JIT/verifier layer lives in host languages. Silent
on trees with no verifier/executor seam (an ordinary contract has neither).

Usage:
  --workspace/--ws <ws>  scan the ws source tree -> .auditooor/
                         verifier_executor_divergence_hypotheses.jsonl + summary
  --source <dir>         scan an arbitrary dir, print rows as JSON (NO sidecar)
  --file <f>             scan a single source file, print rows as JSON
  --check                re-read the emitted sidecar, print cert verdict (advisory)
  --strict               (or env) elevate exit code when a width-mismatch fired
  --json                 machine summary to stdout
"""
from __future__ import annotations

import argparse
import json
import os
import re
import sys
from pathlib import Path

HYP_SCHEMA = "auditooor.verifier_executor_divergence_hypotheses.v1"
_SIDE_NAME = "verifier_executor_divergence_hypotheses.jsonl"
_STRICT_ENV = "AUDITOOOR_VERIFIER_EXECUTOR_STRICT"
_CAPABILITY = "EXT03"

_SKIP_DIRS = {"target", ".git", "node_modules", "vendor", "_archive", "out",
              "cache", "__pycache__", "dist", "build", ".auditooor",
              "benches", "benchmarks", "deployments",
              "prior_audits", "reference", "reports", "docs",
              "fuzz_runs", "cost_runs", "mining_rounds", "monitoring"}
_TEST_HINT = re.compile(
    r"(^|/)(tests?|test_fixtures|mock|mocks|benches|benchmarks?|examples|"
    r"fixtures|testdata|testing)(/|$)")

_SRC_EXT = (".rs", ".go", ".sol", ".c", ".cc", ".cpp", ".cxx", ".h", ".hpp")
_TEST_FILE_SUFFIX = ("_test.go", ".t.sol", "_test.rs", "_test.cc", "_test.cpp")

# --- generated-code exclusion (ported from
#     declared-control-mutator-completeness-screen.py) -------------------------
_GENERATED_SUFFIXES = (".pb.go", ".pulsar.go", "_gen.go", ".gen.go",
                       ".pb.rs", ".generated.rs", ".g.dart")
_GENERATED_SENTINEL = re.compile(
    r"(?i)(?:code generated .* do not edit|@generated|autogenerated|"
    r"do not edit(?: this file)?[.! ]|this file is automatically generated)")


def _is_generated_source(path: Path) -> bool:
    low = path.name.lower()
    if low.endswith(_GENERATED_SUFFIXES):
        return True
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as fh:
            head = fh.read(4096)
    except (OSError, UnicodeError):
        return False
    return bool(_GENERATED_SENTINEL.search(head))


def _iter_source_files(root: Path):
    for dp, dn, fn in os.walk(root):
        dn[:] = [d for d in dn if d not in _SKIP_DIRS]
        rel = dp.replace(os.sep, "/")
        if _TEST_HINT.search(rel):
            continue
        for f in fn:
            low = f.lower()
            if not low.endswith(_SRC_EXT):
                continue
            if low.endswith(_TEST_FILE_SUFFIX):
                continue
            if _TEST_HINT.search(f):
                continue
            p = Path(dp) / f
            if _is_generated_source(p):
                continue
            yield p


# --- role lexicons ----------------------------------------------------------
# VERIFIER role: a stage that establishes a safety property on a representation.
_VERIFIER_RE = re.compile(
    r"\b(?:"
    r"validate_(?:module|all|code|wasm|bytecode|program|memory)"
    r"|fn\s+validate\b|Validator\b|validate_all\b"
    r"|verify_(?:code|program|proof|bytecode|signature|bounds|access)"
    r"|bounds_check|check_bounds|check_access|access_check"
    r"|is_writable|writable\b|read[_-]?only\b|readonly\b"
    r"|well[_-]?formed|type[_-]?check|typecheck"
    r"|resource[_-]?limit|verify_meter|gas_meter|metering"
    r"|MemoryError|VerifierError|VerificationError|InvalidBytecode"
    r")\b")

# EXECUTOR / CODEGEN role: a stage that produces / runs a *different* form.
_CODEGEN_RE = re.compile(
    r"\b(?:"
    r"jit\b|JIT\b|codegen|code_gen|emitter|emit_bytes|emit_u\d"
    r"|singlepass|machine_?code|assembler|assemble\b|dynasm"
    r"|opcode|Opcode|OpCode|bytecode_to|to_machine|encode_insn|encode_instruction"
    r"|interpreter\b|jump_table|jumpTable|dispatch_table|jump_dest"
    r")\b")

# a hand-picked raw opcode byte written into an emit stream (the 0x81/0x80 seam)
_RAW_OPCODE_EMIT_RE = re.compile(
    r"(?:emit_bytes?|emit_u8|push_u8|write_u8|writeByte|append|self\.push|"
    r"buf(?:fer)?\.push|out\.push|code\.push|\.emit\(|dynasm!)"
    r".{0,60}0x[0-9a-fA-F]{2}\b")

# --- width tokens -----------------------------------------------------------
# declared operand size in an arm PATTERN
_DECL_SIZE_RE = re.compile(r"\bS(8|16|32|64)\b")               # Rust Size::S32 etc
_DECL_CASE_RE = re.compile(r"\bcase\s+(8|16|32|64)\b")         # Go/C switch case 32:
_DECL_UINT_RE = re.compile(r"\b[ui](8|16|32|64)\b")           # u32 / i64 scrutinee

# emitted operand-encoding width in an arm BODY
_ENC_REG_RE = re.compile(r"\bR([bwdq])\s*\(")                  # dynasm Rb/Rw/Rd/Rq(
_ENC_SIZEKW_RE = re.compile(r"\b(BYTE|WORD|DWORD|QWORD)\b")
_ENC_EMITN_RE = re.compile(
    r"\b(?:emit|write|put|Put|append)_?[Uu]?int?(8|16|32|64)\b")

_REGW = {"b": 8, "w": 16, "d": 32, "q": 64}
_KWW = {"BYTE": 8, "WORD": 16, "DWORD": 32, "QWORD": 64}

# instruction mnemonics that legitimately cross widths -> never a mismatch
_CROSS_WIDTH_INSN = re.compile(
    r"\b(movzx|movsx|movsxd|cbw|cwde|cdqe|cwd|cdq|cqo|cvt\w*|"
    r"lea|bswap|sign_?extend|zero_?extend|extend|truncate|trunc)\b")


def _decl_bits_from_pattern(pat: str):
    """Return the single declared width in an arm pattern, or None if 0 or >=2
    distinct size tokens (a >=2 case is an explicit width-conversion arm)."""
    bits = set()
    for m in _DECL_SIZE_RE.finditer(pat):
        bits.add(int(m.group(1)))
    for m in _DECL_CASE_RE.finditer(pat):
        bits.add(int(m.group(1)))
    if not bits:
        for m in _DECL_UINT_RE.finditer(pat):
            bits.add(int(m.group(1)))
    if len(bits) == 1:
        return next(iter(bits))
    return None


def _strip_address_operands(body: str) -> str:
    """Remove [...] memory-address contents (address registers are pointer-width,
    not operand-width) so they never pollute the operand-width comparison."""
    return re.sub(r"\[[^\]]*\]", " ", body)


def _emitted_bits(body: str):
    """Set of operand-encoding widths emitted in an arm body (brackets stripped,
    cross-width instructions removed)."""
    if _CROSS_WIDTH_INSN.search(body):
        return set()
    b = _strip_address_operands(body)
    bits = set()
    for m in _ENC_REG_RE.finditer(b):
        bits.add(_REGW[m.group(1)])
    for m in _ENC_SIZEKW_RE.finditer(b):
        bits.add(_KWW[m.group(1)])
    for m in _ENC_EMITN_RE.finditer(b):
        bits.add(int(m.group(1)))
    return bits


# ---- LOAD-BEARING CORE PREDICATE -------------------------------------------
def _width_mismatch(declared_bits, emitted_bits_set):
    """The soundness predicate: a codegen arm declares operand width
    `declared_bits` but emits a SINGLE, DIFFERENT operand-encoding width. This is
    the verifier/executor divergence (the sBPF 0x81-vs-0x80 wrong-width encode).

    Conservative: silent when the emitted width is unknown (empty) or ambiguous
    (>1 distinct width, e.g. a genuine movzx-style mix) so correct codegen never
    fires. Monkeypatch this to `lambda *a: False` to neutralize the screen."""
    if declared_bits is None:
        return False
    if len(emitted_bits_set) != 1:
        return False
    (w,) = tuple(emitted_bits_set)
    return w != declared_bits


# --- function attribution ---------------------------------------------------
_FN_DECL_RE = re.compile(
    r"^\s*(?:pub\s+)?(?:async\s+)?(?:unsafe\s+)?(?:extern\s+\"[^\"]*\"\s+)?"
    r"fn\s+([A-Za-z_]\w*)"                       # Rust/C-ish fn foo
    r"|^\s*macro_rules!\s+([A-Za-z_]\w*)"         # Rust macro_rules! foo
    r"|^\s*func\s+(?:\([^)]*\)\s*)?([A-Za-z_]\w*)"  # Go func (recv) Foo
    r"|^\s*(?:function\s+([A-Za-z_]\w*))")        # Solidity function foo


def _fn_at(lines, idx):
    """Nearest enclosing function/macro name at or before line idx."""
    for i in range(idx, -1, -1):
        m = _FN_DECL_RE.match(lines[i])
        if m:
            return (m.group(1) or m.group(2) or m.group(3)
                    or m.group(4) or "<anon>")
    return "<file>"


# --- arm extraction (width-dispatched codegen arms) -------------------------
def _iter_arms(text, lines):
    """Yield (arm_head_line_idx, pattern_text, body_text) for each match/switch
    arm that contains a `=>` (Rust) split. Body = the block after `=>` (balanced
    braces) or the rest of the line/expr. Also handles Go/C `case ...:` arms."""
    n = len(text)
    # Rust/Sol style `<pattern> => <body>`
    for m in re.finditer(r"=>", text):
        arrow = m.start()
        # pattern = from the previous arm terminator / block open to the arrow
        pstart = max(text.rfind("\n", 0, arrow),
                     text.rfind("{", 0, arrow),
                     text.rfind(";", 0, arrow),
                     text.rfind("},", 0, arrow) + 1)
        pattern = text[pstart + 1:arrow]
        # body: skip ws after arrow
        j = arrow + 2
        while j < n and text[j] in " \t":
            j += 1
        if j < n and text[j] == "{":
            depth = 0
            k = j
            while k < n:
                c = text[k]
                if c == "{":
                    depth += 1
                elif c == "}":
                    depth -= 1
                    if depth == 0:
                        k += 1
                        break
                k += 1
            body = text[j:k]
        else:
            # to end of arm: next top-level ',' or newline
            k = j
            depth = 0
            while k < n:
                c = text[k]
                if c in "([{":
                    depth += 1
                elif c in ")]}":
                    if depth == 0:
                        break
                    depth -= 1
                elif c == "," and depth == 0:
                    break
                elif c == "\n" and depth == 0:
                    break
                k += 1
            body = text[j:k]
        line_idx = text.count("\n", 0, arrow)
        yield (line_idx, pattern, body)


def scan_file(path: Path):
    """Return dict with role signals + collected codegen arms/points for a file.
    Does NOT apply the seam gate (caller does, tree-wide)."""
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except (OSError, UnicodeError):
        return None
    lines = text.split("\n")
    verifier_role = bool(_VERIFIER_RE.search(text))
    codegen_role = bool(_CODEGEN_RE.search(text))

    mismatches = []   # soundness fires
    leads = set()     # (function,) enumeration leads

    if codegen_role:
        for (idx, pattern, body) in _iter_arms(text, lines):
            decl = _decl_bits_from_pattern(pattern)
            if decl is None:
                continue
            emitted = _emitted_bits(body)
            fn = _fn_at(lines, idx)
            leads.add(fn)
            if _width_mismatch(decl, emitted):
                (ew,) = tuple(emitted)
                mismatches.append({
                    "line": idx + 1,
                    "function": fn,
                    "declared_width": decl,
                    "emitted_width": ew,
                    "arm": pattern.strip()[:120],
                })
        # raw-opcode-byte hand-pick sites also enumerate a lead
        for i, ln in enumerate(lines):
            if _RAW_OPCODE_EMIT_RE.search(ln):
                leads.add(_fn_at(lines, i))

    return {
        "verifier_role": verifier_role,
        "codegen_role": codegen_role,
        "mismatches": mismatches,
        "leads": sorted(leads),
    }


def _row(path_str, rec_file, line, function, fires, hazard, severity_eligible,
         extra=None):
    # A real survivor (a fired width-mismatch, severity-eligible) is an OPEN
    # obligation, NOT advisory-green: advisory=False + proof_status='open' so a
    # downstream advisory filter counts it OPEN instead of draining silently to
    # advisory (vacuity-telltale fix). The handpicked-encoding enumeration leads
    # (fires==False / severity_eligible==False) stay advisory=True.
    survivor = bool(fires or severity_eligible)
    row = {
        "capability": _CAPABILITY,
        "schema": HYP_SCHEMA,
        "fires": fires,
        "file": rec_file,
        "line": line,
        "function": function,
        "advisory": not survivor,
        "proof_status": "open" if survivor else "advisory",
        "auto_credit": False,
        "verdict": "needs-fuzz",
        "class": "verifier-executor-semantic-divergence",
        "hazard": hazard,
        "severity_eligible": severity_eligible,
        "kill_confirm": "differential-fuzz verifier-approved-form vs executed-form",
    }
    if extra:
        row.update(extra)
    return row


def scan_tree(root: Path, rel_to: Path = None):
    """Scan a tree. Emit rows ONLY if the verifier/executor SEAM is present
    (>=1 verifier-role file AND >=1 codegen-role file) - so a tree with no
    dual-representation seam stays SILENT (no FP-spray on ordinary code)."""
    rel_to = rel_to or root
    per_file = []
    verifier_seen = False
    codegen_seen = False
    for p in _iter_source_files(root):
        rec = scan_file(p)
        if rec is None:
            continue
        verifier_seen = verifier_seen or rec["verifier_role"]
        codegen_seen = codegen_seen or rec["codegen_role"]
        if rec["mismatches"] or rec["leads"]:
            per_file.append((p, rec))

    rows = []
    seam = verifier_seen and codegen_seen
    if not seam:
        return rows  # no dual-representation seam -> silent
    for p, rec in per_file:
        try:
            rel = str(p.relative_to(rel_to))
        except ValueError:
            rel = str(p)
        for mm in rec["mismatches"]:
            rows.append(_row(
                str(p), rel, mm["line"], mm["function"],
                fires=True, hazard="width-mismatch", severity_eligible=True,
                extra={
                    "declared_width": mm["declared_width"],
                    "emitted_width": mm["emitted_width"],
                    "divergence": (f"arm declares S{mm['declared_width']} but "
                                   f"emits a {mm['emitted_width']}-bit operand "
                                   f"encoding"),
                    "arm": mm["arm"],
                    "has_recheck": False,
                }))
        for fn in rec["leads"]:
            rows.append(_row(
                str(p), rel, 0, fn,
                fires=False, hazard="handpicked-encoding", severity_eligible=False,
                extra={
                    "lead": True,
                    "note": ("codegen site hand-picks opcode/operand encoding; "
                             "verifier property is established on a different "
                             "representation - differential-fuzz this seam"),
                }))
    return rows


# --- workspace source roots -------------------------------------------------
def _ws_roots(ws: Path):
    for c in (ws / "src", ws / "repos", ws / "contracts", ws):
        if c.exists():
            return c
    return ws


def _write_sidecar(ws: Path, rows):
    side_dir = ws / ".auditooor"
    side_dir.mkdir(parents=True, exist_ok=True)
    side = side_dir / _SIDE_NAME
    with open(side, "w", encoding="utf-8") as fh:
        for r in rows:
            fh.write(json.dumps(r, sort_keys=True) + "\n")
    return side


def _summ(rows):
    fires = [r for r in rows if r.get("fires")]
    sev = [r for r in rows if r.get("severity_eligible")]
    return {
        "capability": _CAPABILITY,
        "schema": HYP_SCHEMA,
        "rows": len(rows),
        "fires": len(fires),
        "severity_eligible_fires": len(sev),
        "leads": len([r for r in rows if r.get("lead")]),
        "seam_present": bool(rows),
    }


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--workspace", "--ws", dest="workspace")
    ap.add_argument("--source")
    ap.add_argument("--file")
    ap.add_argument("--check", action="store_true")
    ap.add_argument("--strict", action="store_true")
    ap.add_argument("--json", action="store_true")
    args = ap.parse_args(argv)

    strict = args.strict or os.environ.get(_STRICT_ENV) == "1"

    # --check: re-read the emitted sidecar (workspace) and print a cert verdict
    if args.check:
        if not args.workspace:
            print("--check requires --workspace", file=sys.stderr)
            return 2
        side = Path(args.workspace) / ".auditooor" / _SIDE_NAME
        rows = []
        if side.exists():
            for ln in side.read_text(encoding="utf-8").splitlines():
                ln = ln.strip()
                if ln:
                    rows.append(json.loads(ln))
        summ = _summ(rows)
        summ["sidecar"] = str(side)
        print(json.dumps(summ, indent=2))
        return 1 if (strict and summ["severity_eligible_fires"]) else 0

    if args.file:
        p = Path(args.file)
        rows = scan_tree(p.parent, rel_to=p.parent) if False else []
        rec = scan_file(p)
        # single-file mode: skip the seam gate, report intrinsic signals
        if rec is not None:
            for mm in rec["mismatches"]:
                rows.append(_row(str(p), p.name, mm["line"], mm["function"],
                                 True, "width-mismatch", True,
                                 extra={"declared_width": mm["declared_width"],
                                        "emitted_width": mm["emitted_width"],
                                        "arm": mm["arm"], "has_recheck": False}))
            for fn in rec["leads"]:
                rows.append(_row(str(p), p.name, 0, fn, False,
                                 "handpicked-encoding", False,
                                 extra={"lead": True}))
        out = {"summary": _summ(rows), "rows": rows}
        print(json.dumps(out, indent=2))
        return 1 if (strict and out["summary"]["severity_eligible_fires"]) else 0

    if args.source:
        root = Path(args.source)
        rows = scan_tree(root, rel_to=root)
        out = {"summary": _summ(rows), "rows": rows}
        print(json.dumps(out, indent=2))
        return 1 if (strict and out["summary"]["severity_eligible_fires"]) else 0

    if args.workspace:
        ws = Path(args.workspace)
        root = _ws_roots(ws)
        rows = scan_tree(root, rel_to=root)
        side = _write_sidecar(ws, rows)
        summ = _summ(rows)
        summ["sidecar"] = str(side)
        if args.json:
            print(json.dumps(summ, indent=2))
        else:
            print(f"[{_CAPABILITY}] {summ['rows']} rows "
                  f"({summ['severity_eligible_fires']} width-mismatch fires, "
                  f"{summ['leads']} leads) -> {side}")
        return 1 if (strict and summ["severity_eligible_fires"]) else 0

    ap.print_help()
    return 2


if __name__ == "__main__":
    sys.exit(main())
