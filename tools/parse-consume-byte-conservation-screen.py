#!/usr/bin/env python3
"""parse-consume-byte-conservation-screen.py - GEN-A1, the PARSE/CONSUME
BYTE-CONSERVATION SEAM screen (Solidity + Go arms).

GENERAL LOGIC / TRUST-ENFORCEMENT class (impact-agnostic, never a bug SHAPE). An
enforcement point that decodes an UNTRUSTED blob into a structured object owes a
byte-conservation contract:

  (a) CONSUMED == DECLARED : the bytes it read equal the blob's declared length -
      no trailing bytes silently ignored, no short read accepted (the alt-context
      re-decode / signature-malleability class), AND
  (b) CHILD DOES NOT OVERFLOW PARENT : when a child element's length/offset field
      is TAKEN FROM the blob and then used to index/reslice the parent buffer,
      that child length is BOUNDED against the parent's remaining length before
      the read (the Polygon `RLPReader.toList` class - a child length field larger
      than the remaining parent slice reads out of bounds / reinterprets memory).

A decode site that reads a length/offset out of the blob and dereferences it
WITHOUT one of those assertions is flagged (advisory, verdict=needs-fuzz).

This is the RUST arm's cross-language sibling; the Rust EIP-2718 non-exact decode
scanner already lives at tools/rust-non-exact-decode-trailing-bytes-scan.py and is
NOT rebuilt here. This tool is the NET-NEW Solidity + Go arms.

Pattern classes
---------------
Solidity:
  * S_ASM_UNBOUNDED_SLICE : assembly `mload`/`calldataload`/`calldatacopy`/`mcopy`
      at a COMPUTED offset (`add(base, offset)`) that references a function
      parameter, with NO length/offset bound check (`require`/`revert`/`if` that
      compares against `.length` or against the offset var) in the same function.
      -> missing_assertion = "child-overflow-parent".
  * S_DECODE_TRAILING : `abi.decode(<blob>, (...))` where `<blob>` is a raw
      calldata SLICE (`data[a:]`, `data[a:b]`) or `msg.data[...]` and the function
      body carries NO length assertion on that blob.
      -> missing_assertion = "consumed==declared".
Go:
  * G_LENPREFIX_RESLICE : a length value decoded from the buffer
      (`binary.BigEndian.Uint{16,32,64}(...)` / `binary.Read`) then used in a
      slice/`make`/copy expression WITHOUT any `len(...)` bound comparison on that
      length var in the function.
      -> missing_assertion = "child-overflow-parent".

ADVISORY-FIRST: every row carries verdict='needs-fuzz', advisory=True,
auto_credit=False, and the tool exits 0 in default mode. The opt-in
env AUDITOOOR_BYTE_CONSERVATION_STRICT (or --strict) only raises the exit code
when a fired row exists.

Excludes machine-generated (.pb.go/.pulsar.go + "DO NOT EDIT"), test, sim and
vendored code via the shared exclusion libs. Silent on other trees.

Usage:
  --workspace <ws>   scan <ws>/src -> .auditooor/byte_conservation_hypotheses.jsonl + summary
  --source <dir>     scan an arbitrary dir, print rows as JSON (NO sidecar - tests/verify)
  --file <f>         scan a single .sol/.go file, print rows as JSON
  --check            re-read the emitted sidecar, print cert verdict (advisory)
  --strict           (or env) elevate exit code when a fired row exists
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

HYP_SCHEMA = "auditooor.byte_conservation_hypotheses.v1"
_SIDE_NAME = "byte_conservation_hypotheses.jsonl"
_STRICT_ENV = "AUDITOOOR_BYTE_CONSERVATION_STRICT"
_CAPABILITY = "GEN_A1"

TOOLS_DIR = Path(__file__).resolve().parent
if str(TOOLS_DIR) not in sys.path:
    sys.path.insert(0, str(TOOLS_DIR))

# --- shared exclusion (reuse, never rebuild) --------------------------------
try:  # tools/lib/synthetic_target_exclusion.py
    from lib.synthetic_target_exclusion import (  # noqa: E402
        is_chimera_mutation_harness_path,
        is_codegen_path,
        is_test_target_path,
    )
except Exception:  # pragma: no cover - degrade to no-op if lib unavailable
    def is_test_target_path(_p):  # type: ignore
        return False

    def is_codegen_path(_p, workspace=None):  # type: ignore
        return False

    def is_chimera_mutation_harness_path(_p):  # type: ignore
        return False


def _load_codegen_sentinel():
    """Reuse declared-control-mutator-completeness-screen.py::_is_generated_source
    (the .go/.sol codegen sentinel) rather than re-inline the DO-NOT-EDIT logic."""
    tool = TOOLS_DIR / "declared-control-mutator-completeness-screen.py"
    try:
        spec = importlib.util.spec_from_file_location("_dc_screen_bc", tool)
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)  # type: ignore
        return mod._is_generated_source
    except Exception:  # pragma: no cover
        _SUF = (".pb.go", ".pulsar.go", ".pb.gw.go", "_gen.go", ".gen.go",
                "_generated.go")
        _SENT = re.compile(r"Code generated .{0,80}?DO NOT EDIT", re.I)

        def _fallback(path: Path) -> bool:
            if path.name.lower().endswith(_SUF):
                return True
            try:
                return bool(_SENT.search(
                    path.read_text(encoding="utf-8", errors="replace")[:4096]))
            except OSError:
                return False
        return _fallback


_is_generated_source = _load_codegen_sentinel()

_SKIP_DIRS = {"target", ".git", "node_modules", "vendor", "_archive", "out",
              "cache", "lib", "__pycache__", "dist", "build", ".auditooor",
              "benches", "benchmarks", "script", "scripts", "deployments",
              "prior_audits", "reference", "certora", "simulation", "simapp",
              "node", "testdata"}
_TEST_HINT = re.compile(
    r"(^|/)(tests?|test_fixtures|mock|mocks|benches|benchmarks?|examples|"
    r"fixtures|simulation|simapp|testdata)(/|$)")


# ============================================================================
# comment/string masking + function extraction (Solidity + Go)
# ============================================================================
def _mask_comments(text: str) -> str:
    """Blank // and /* */ comments and string literals, preserving newlines / line
    length so indices stay source-accurate. Errs toward SILENCE."""
    out = []
    i, n = 0, len(text)
    in_line = in_block = in_str = False
    quote = ""
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
        elif in_str:
            out.append(" ")
            if c == "\\":
                out.append(" ")
                i += 2
                continue
            if c == quote:
                in_str = False
            i += 1
        elif c in ('"', "'", "`"):
            in_str = True
            quote = c
            out.append(" ")
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


_FN_DECL_RE = re.compile(
    r"^\s*(?:"
    r"function\s+([A-Za-z_]\w*)"                 # Solidity function foo
    r"|(constructor)\b"                          # Solidity constructor
    r"|func\s+(?:\([^)]*\)\s*)?([A-Za-z_]\w*)"   # Go func (recv) Foo / func Foo
    r")")


def _fn_name(m):
    return m.group(1) or m.group(2) or m.group(3)


def _functions(lines):
    """Yield (name, decl_idx, sig_text, body_lines) for each brace-matched fn.
    body_lines is a list of (abs_idx, line) covering signature -> closing brace."""
    i, n = 0, len(lines)
    while i < n:
        m = _FN_DECL_RE.match(lines[i])
        if not m:
            i += 1
            continue
        name = _fn_name(m) or "<anon>"
        depth = 0
        started = False
        body = []
        sig_parts = []
        j = i
        seen_brace = False
        while j < n:
            line = lines[j]
            if not seen_brace:
                sig_parts.append(line)
                if "{" in line:
                    seen_brace = True
            depth += line.count("{") - line.count("}")
            body.append((j, line))
            if "{" in line:
                started = True
            if started and depth <= 0:
                break
            j += 1
        yield name, i, "\n".join(sig_parts), body
        i = max(j, i + 1)


# ============================================================================
# parameter-list extraction (Solidity)
# ============================================================================
def _matching_paren(s: str, open_idx: int) -> int:
    depth = 0
    for k in range(open_idx, len(s)):
        if s[k] == "(":
            depth += 1
        elif s[k] == ")":
            depth -= 1
            if depth == 0:
                return k + 1
    return len(s)


def _param_str_sol(sig_text: str) -> str:
    j = sig_text.find("(")
    if j < 0:
        return ""
    return sig_text[j + 1:_matching_paren(sig_text, j) - 1]


_LOC_KW = {"memory", "calldata", "storage", "indexed", "payable"}


def _split_top_commas(param_str: str):
    out, depth, cur = [], 0, []
    for ch in param_str:
        if ch in "([{<":
            depth += 1
        elif ch in ")]}>":
            depth = max(0, depth - 1)
        if ch == "," and depth == 0:
            out.append("".join(cur))
            cur = []
        else:
            cur.append(ch)
    if cur:
        out.append("".join(cur))
    return [c.strip() for c in out if c.strip()]


def _sol_param_names(param_str: str):
    names = []
    for chunk in _split_top_commas(param_str):
        if "mapping" in chunk or chunk.startswith("function"):
            continue
        toks = [t for t in chunk.split() if t not in _LOC_KW]
        if len(toks) < 2:
            continue
        names.append(toks[-1])
    return names


# ============================================================================
# helpers
# ============================================================================
def _body_after_sig(body_lines) -> str:
    joined = "\n".join(l for _i, l in body_lines)
    brace = joined.find("{")
    return joined[brace + 1:] if brace >= 0 else joined


def _line_of_offset(text: str, off: int) -> int:
    return text.count("\n", 0, off) + 1


def _balanced_arg(s: str, open_paren_idx: int) -> str:
    """Return the text between s[open_paren_idx]=='(' and its matching ')'."""
    end = _matching_paren(s, open_paren_idx)
    return s[open_paren_idx + 1:end - 1]


def _idents(expr: str):
    return set(re.findall(r"[A-Za-z_]\w*", expr))


def _stable_id(rel, fn, kind, var, line):
    h = hashlib.sha1()
    h.update(f"{rel}|{fn}|{kind}|{var}|{line}".encode())
    return h.hexdigest()[:16]


def _excerpt(text: str, off: int) -> str:
    ls = text.rfind("\n", 0, off) + 1
    le = text.find("\n", off)
    if le == -1:
        le = len(text)
    return text[ls:le].strip()[:180]


# ============================================================================
# Solidity arm
# ============================================================================
_ASM_READ_RE = re.compile(
    r"\b(mload|calldataload|calldatacopy|mcopy|returndatacopy)\s*\(")
# a bound check: require/revert/if whose predicate touches `.length`, or a relop
# against a length/offset token.
_LEN_GUARD_RE = re.compile(
    r"\b(require|revert|assert)\b[^;{]*\.length"
    r"|\bif\s*\([^)]*\.length[^)]*\)"
    r"|\.length\b[^;\n]{0,80}?(<=|>=|<|>)"
    r"|(<=|>=|<|>)[^;\n]{0,40}?\.length\b")
_ABI_DECODE_RE = re.compile(r"\babi\s*\.\s*decode\s*\(")
# calldata slice / msg.data slice inside a decode's blob arg
_CALLDATA_SLICE_RE = re.compile(r"\bmsg\s*\.\s*data\b|\[\s*[^\]]*:[^\]]*\]")


def _sol_has_len_guard(body: str, var_names) -> bool:
    if _LEN_GUARD_RE.search(body):
        return True
    # explicit relop comparison that references the offset var directly
    for v in var_names:
        if not v:
            continue
        ve = re.escape(v)
        if re.search(rf"\b(require|revert|assert)\b[^;{{]*\b{ve}\b[^;{{]*(<=|>=|<|>)",
                     body):
            return True
        if re.search(rf"\bif\s*\([^)]*\b{ve}\b[^)]*(<=|>=|<|>)[^)]*\)", body):
            return True
    return False


def _scan_sol_fn(rel, name, decl_idx, sig, body, rows):
    param_names = set(_sol_param_names(_param_str_sol(sig)))

    # ---- S_ASM_UNBOUNDED_SLICE ------------------------------------------
    for m in _ASM_READ_RE.finditer(body):
        op = m.group(1)
        arg = _balanced_arg(body, m.end() - 1)
        if "add(" not in arg.replace(" ", ""):
            continue  # not a computed offset - fixed slot read
        arg_ids = _idents(arg)
        # the computed offset must reference a function parameter (an
        # attacker/caller-supplied offset or blob), not only constants/locals.
        referenced_params = arg_ids & param_names
        if not referenced_params:
            continue
        # a length bound in the function neutralizes the finding.
        if _sol_has_len_guard(body, referenced_params | arg_ids):
            continue
        off = m.start()
        var = sorted(referenced_params)[0]
        rows.append(_mk_row(
            rel, name, _line_of_offset(body, off) + decl_idx, "solidity",
            "S_ASM_UNBOUNDED_SLICE", var, "child-overflow-parent",
            _excerpt(body, off),
            f"assembly {op} reads at a computed offset add(...) over param "
            f"`{var}` with no length/offset bound check (require/revert/if "
            f"comparing against .length) in `{name}` - a child length/offset "
            f"taken from the blob can index past the parent buffer "
            f"(RLPReader.toList / BytesLib class)."))

    # ---- S_DECODE_TRAILING ----------------------------------------------
    for m in _ABI_DECODE_RE.finditer(body):
        blob = _balanced_arg(body, m.end() - 1)
        # first (comma-top-level) arg is the blob
        first = _split_top_commas(blob)
        blob_arg = first[0] if first else blob
        if not _CALLDATA_SLICE_RE.search(blob_arg):
            continue
        if _sol_has_len_guard(body, _idents(blob_arg)):
            continue
        off = m.start()
        rows.append(_mk_row(
            rel, name, _line_of_offset(body, off) + decl_idx, "solidity",
            "S_DECODE_TRAILING", blob_arg.strip()[:60], "consumed==declared",
            _excerpt(body, off),
            f"abi.decode over a raw calldata slice `{blob_arg.strip()[:60]}` in "
            f"`{name}` with no length assertion - trailing / short bytes are "
            f"silently accepted; the same bytes decoded in an alternate context "
            f"can diverge (consumed != declared)."))


# ============================================================================
# Go arm
# ============================================================================
_GO_LENDECODE_RE = re.compile(
    r"\b([A-Za-z_]\w*)\s*(?::=|=)\s*"
    r"(?:int\d*\(\s*)?binary\.(?:BigEndian|LittleEndian)\.Uint(?:16|32|64)\s*\(")
_GO_BINREAD_RE = re.compile(r"\bbinary\.Read\s*\(")


def _go_len_bound_checked(body: str, var: str) -> bool:
    """True iff the fn compares `var` against a len(...) / cap(...) (or is
    compared inside an if/return-error guard)."""
    ve = re.escape(var)
    # var <op> len(...) or len(...) <op> var
    if re.search(rf"\b{ve}\b[^;\n]{{0,60}}?(<=|>=|<|>|==|!=)[^;\n]{{0,40}}?\blen\s*\(",
                 body):
        return True
    if re.search(rf"\blen\s*\([^)]*\)[^;\n]{{0,40}}?(<=|>=|<|>|==|!=)[^;\n]{{0,60}}?\b{ve}\b",
                 body):
        return True
    if re.search(rf"\bcap\s*\([^)]*\)[^;\n]{{0,40}}?(<=|>=|<|>|==|!=)[^;\n]{{0,60}}?\b{ve}\b",
                 body):
        return True
    return False


def _go_var_used_as_index(body: str, var: str) -> bool:
    ve = re.escape(var)
    word = re.compile(rf"\b{ve}\b")
    # any index/slice bracket expression `[ ... ]` that references the var
    # (covers x[var], x[a:var], x[var:], x[4 : 4+var], etc.)
    for m in re.finditer(r"\[([^\]\[]*)\]", body):
        if word.search(m.group(1)):
            return True
    # make([]byte, var) / make([]T, var, var) - var drives the allocation size
    if re.search(rf"\bmake\s*\(\s*\[\][^,)]*,[^,)]*\b{ve}\b", body):
        return True
    # copy(dst, src[:var]) already covered by the bracket scan above
    return False


def _scan_go_fn(rel, name, decl_idx, sig, body, rows):
    for m in _GO_LENDECODE_RE.finditer(body):
        var = m.group(1)
        if not _go_var_used_as_index(body, var):
            continue
        if _go_len_bound_checked(body, var):
            continue
        off = m.start()
        rows.append(_mk_row(
            rel, name, _line_of_offset(body, off) + decl_idx, "go",
            "G_LENPREFIX_RESLICE", var, "child-overflow-parent",
            _excerpt(body, off),
            f"length prefix `{var}` decoded from the buffer via binary.*Uint "
            f"is used to reslice/allocate in `{name}` with no len()/cap() bound "
            f"check - a child length larger than the remaining parent buffer "
            f"reads out of bounds (RLPReader.toList class)."))


# ============================================================================
# row + summary
# ============================================================================
def _mk_row(rel, fn, line, lang, kind, decoded_var, missing, excerpt, why):
    return {
        "schema": HYP_SCHEMA,
        "capability": _CAPABILITY,
        "id": _stable_id(rel, fn, kind, decoded_var, line),
        "file": rel,
        "line": line,
        "function": fn,
        "context": fn,
        "lang": lang,
        "pattern_id": kind,
        "decoded_var": decoded_var,
        "missing_assertion": missing,
        "excerpt": excerpt,
        "why_severity_anchored": why,
        "fires": True,
        "verdict": "needs-fuzz",
        "advisory": True,
        "auto_credit": False,
    }


def scan_file(path: Path, rel: str, file_text: str = None):
    raw = file_text if file_text is not None else path.read_text(
        encoding="utf-8", errors="ignore")
    text = _mask_comments(raw)
    lang = "go" if rel.lower().endswith(".go") else "solidity"
    lines = text.split("\n")
    rows = []
    for name, decl_idx, sig, body_lines in _functions(lines):
        body = _body_after_sig(body_lines)
        if lang == "go":
            _scan_go_fn(rel, name, decl_idx, sig, body, rows)
        else:
            _scan_sol_fn(rel, name, decl_idx, sig, body, rows)
    return rows


def _iter_source_files(root: Path, workspace: Path = None):
    for dp, dn, fn in os.walk(root):
        dn[:] = [d for d in dn if d not in _SKIP_DIRS]
        if _TEST_HINT.search(dp.replace(os.sep, "/")):
            continue
        for f in fn:
            low = f.lower()
            if not (low.endswith(".sol") or low.endswith(".go")):
                continue
            if low.endswith("_test.go") or low.endswith(".t.sol"):
                continue
            if _TEST_HINT.search(f):
                continue
            p = Path(dp) / f
            rel = str(p)
            if (is_test_target_path(rel) or is_chimera_mutation_harness_path(rel)
                    or is_codegen_path(rel, workspace)):
                continue
            if _is_generated_source(p):
                continue
            yield p


def scan_tree(root: Path, workspace: Path = None):
    rows = []
    for p in _iter_source_files(root, workspace):
        try:
            rel = str(p.relative_to(root))
        except ValueError:
            rel = str(p)
        try:
            rows.extend(scan_file(p, rel))
        except Exception:
            continue
    return rows


def _emit_sidecar(ws: Path, rows):
    outdir = ws / ".auditooor"
    outdir.mkdir(parents=True, exist_ok=True)
    out = outdir / _SIDE_NAME
    with out.open("w") as fh:
        for r in rows:
            fh.write(json.dumps(r) + "\n")
    return out


def _count(rows, key):
    out = {}
    for r in rows:
        v = str(r.get(key, ""))
        out[v] = out.get(v, 0) + 1
    return out


def _summary(rows):
    fired = [r for r in rows if r.get("fires")]
    return {
        "schema": HYP_SCHEMA,
        "capability": _CAPABILITY,
        "decode_sites": len(rows),
        "fired": len(fired),
        "by_pattern": _count(rows, "pattern_id"),
        "by_lang": _count(rows, "lang"),
        "by_missing_assertion": _count(rows, "missing_assertion"),
        "verdict": "needs-fuzz" if fired else "clean-advisory",
        "advisory": True,
        "auto_credit": False,
    }


def main(argv=None):
    ap = argparse.ArgumentParser(
        description="GEN-A1 parse/consume byte-conservation seam screen "
                    "(Solidity + Go, advisory)")
    ap.add_argument("--workspace", "--ws")
    ap.add_argument("--source")
    ap.add_argument("--file")
    ap.add_argument("--check", action="store_true")
    ap.add_argument("--strict", action="store_true")
    ap.add_argument("--json", action="store_true")
    args = ap.parse_args(argv)

    strict = args.strict or os.environ.get(
        _STRICT_ENV, "").strip() not in ("", "0", "false")

    if args.file:
        p = Path(args.file)
        rows = scan_file(p, p.name)
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
            rows = [json.loads(l) for l in side.read_text().splitlines()
                    if l.strip()]
        summ = _summary(rows)
        summ["source"] = "sidecar"
        print(json.dumps(summ, indent=2))
        return 1 if (strict and summ["fired"]) else 0

    src = ws / "src"
    root = src if src.exists() else ws
    rows = scan_tree(root, workspace=ws)
    _emit_sidecar(ws, rows)
    summ = _summary(rows)
    print(json.dumps(summ, indent=2))
    return 1 if (strict and summ["fired"]) else 0


if __name__ == "__main__":
    sys.exit(main())
