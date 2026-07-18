#!/usr/bin/env python3
"""deserialize-precap-amplification-screen.py  (E7) - allocate/iterate-before-cap screen.

WHAT THIS TOOL DOES
===================
E7 is a GENERAL cross-language ENFORCEMENT screen (Go / Rust / Solidity). It does
not hunt one bug shape - it enumerates a single delegated-and-trusted safety
property and attacks its private invariant, per the north-star method:

  DELEGATED-TRUSTED INVARIANT
      "A length / count / size field decoded from attacker-controlled input is
       BOUNDED before it is allowed to drive an allocation or a bounded loop."
      The decoder DELEGATES the bound to an upstream cap check and then TRUSTS
      the field when it sizes memory / iteration.

  PRIVATE INVARIANT (per allocation/loop site sized by operand N)
      exists a cap  `N <= K`  (or a clamp  `N = min(N, K)`) that runs BEFORE the
      site, so allocation/iteration is bounded by a constant, not by N.

  ATTACK (what this screen looks for)
      A site whose size operand is attacker-derived (a decoded length prefix, a
      header/message count field, or a size-hinted parameter) reaches the
      allocation/loop with NO dominating cap. A tiny pre-auth message can then
      declare a huge N -> memory/CPU amplification (OOM / validator halt / DoS).

This MERGES the two Go alloc/loop detectors (backlog G9 unbounded-alloc,
RU8 length-prefixed eager-alloc) and LIFTS them to Rust + Solidity via a shared
source-text predicate:  make(_, N) / Vec::with_capacity(N) / reserve(N) /
vec![_; N] / new T[](N) / new bytes(N) / for(... < N) / for _ in 0..N.

WHAT IT IS NOT
==============
It is NOT an impact-specific "DoS detector" and it never claims a bug. It is a
trust-enforcement screen: it reports enforcement points where the bound-the-size
invariant is UN-established, so a fuzz/manual pass can confirm reachability.

  ADVISORY-FIRST / NO-AUTO-CREDIT  - every emitted row carries
  verdict="needs-fuzz". This tool NEVER flips a gate, resolves a unit, or
  fail-closes. A site that HAS a dominating cap is SILENT (guarded/benign).

  FAIL-OPEN - on an unreadable/empty target it emits an empty hypotheses file +
  an accounting record and exits 0.

Usage:
  python3 tools/deserialize-precap-amplification-screen.py --workspace <ws> [--json]
  python3 tools/deserialize-precap-amplification-screen.py --path <file> [--json]
  python3 tools/deserialize-precap-amplification-screen.py --stdin --lang rust
"""
from __future__ import annotations

import argparse
import bisect
import json
import os
import pathlib
import re
import sys

SCHEMA = "auditooor.e7_precap_amplification.v1"
OUT_REL = os.path.join(".auditooor", "e7_precap_amplification_hypotheses.jsonl")
ACC_REL = os.path.join(".auditooor", "e7_precap_amplification_accounting.json")

DELEGATED_INVARIANT = (
    "a length/count/size field decoded from attacker-controlled input is bounded "
    "before it drives an allocation or bounded loop"
)
PRIVATE_INVARIANT = (
    "for each allocation/loop sized by operand N there exists a cap N<=K (or clamp "
    "N=min(N,K)) dominating the site"
)
ATTACK = (
    "attacker-derived size reaches the alloc/loop with no dominating cap -> a tiny "
    "pre-auth message declaring a huge N causes memory/CPU amplification"
)

LANG_BY_EXT = {".go": "go", ".rs": "rust", ".sol": "solidity"}

# Tokens that mark an identifier as a plausible size/length/count field.
SIZE_HINT_TOKENS = {
    "len", "length", "size", "sz", "count", "cnt", "num", "amount", "amt",
    "capacity", "cap", "total", "parts", "shards", "entries", "items",
    "elements", "elems", "width", "rows", "cols", "nbytes", "nbits", "nparts",
    "n",
}

# RHS tokens that mark a local as decode/deserialize-sourced (attacker origin).
DECODE_TOKENS = (
    "decode", "deserialize", "unmarshal", "from_slice", "try_from_slice",
    "read_u", "read_i", "read_var", "readvarint", "read_uleb", "read_compact",
    "from_reader", "borsh", "abi.decode", "abidecode", "from_bytes", "frombytes",
    "readuint", "readbytes", "next_u", "getvarint", "uvarint", "binary.read",
)

# Struct-ish receivers that name a decoded header/message field.
_HEADER_FIELD_RE = re.compile(
    r"\b(?:header|hdr|msg|message|req|request|payload|input|packet|frame|body|"
    r"proof|chunk|record|entry|meta)\w*\s*\.\s*\w*"
    r"(?:len|length|size|count|num|parts|shards|entries|items|elements)\w*",
    re.IGNORECASE,
)

# Language keywords / builtins that are never a size operand identifier.
_KEYWORDS = {
    "make", "new", "for", "if", "let", "mut", "return", "func", "fn", "function",
    "uint", "uint256", "bytes", "byte", "string", "usize", "u8", "u16", "u32",
    "u64", "i32", "i64", "int", "map", "chan", "vec", "Vec", "self", "as", "in",
    "true", "false", "nil", "None", "Some", "Ok", "Err", "min", "max", "std",
    "cmp", "memory", "storage", "calldata", "pub", "const", "static", "type",
}

# Cap / reject keywords that appear in a bound-guard window.
_REJECT_RE = re.compile(
    r"\b(?:return|revert|Err|err|panic|break|continue|throw|abort|require|"
    r"assert|ensure|bail|reject|error|fail)\b"
)


# --------------------------------------------------------------------------- #
# text primitives
# --------------------------------------------------------------------------- #
def classify_lang(path: str) -> str | None:
    return LANG_BY_EXT.get(pathlib.Path(path).suffix.lower())


def _identifiers(expr: str) -> list[str]:
    return re.findall(r"[A-Za-z_][A-Za-z0-9_]*", expr)


def _is_constanty(ident: str) -> bool:
    # numeric literal, or an ALL_CAPS (SCREAMING_SNAKE) named constant.
    if re.fullmatch(r"[0-9][0-9_xXa-fA-F]*", ident):
        return True
    letters = [c for c in ident if c.isalpha()]
    return bool(letters) and ident.upper() == ident


def _camel_snake_tokens(name: str) -> set[str]:
    parts: list[str] = []
    for chunk in re.split(r"[_\W]+", name):
        if not chunk:
            continue
        # split camelCase / PascalCase / trailing digits
        parts += re.findall(r"[A-Z]+(?![a-z])|[A-Z][a-z0-9]*|[a-z0-9]+", chunk)
    return {p.lower() for p in parts if p}


def has_size_hint(name: str) -> bool:
    return bool(_camel_snake_tokens(name) & SIZE_HINT_TOKENS)


def _match_bracket(text: str, open_idx: int, opench: str, closech: str) -> int:
    depth = 0
    for i in range(open_idx, len(text)):
        c = text[i]
        if c == opench:
            depth += 1
        elif c == closech:
            depth -= 1
            if depth == 0:
                return i
    return -1


def split_top_commas(s: str) -> list[str]:
    out, depth, cur = [], 0, []
    for c in s:
        if c in "([{":
            depth += 1
        elif c in ")]}":
            depth -= 1
        if c == "," and depth == 0:
            out.append("".join(cur))
            cur = []
        else:
            cur.append(c)
    if cur:
        out.append("".join(cur))
    return [p.strip() for p in out if p.strip()]


# --------------------------------------------------------------------------- #
# function splitter (Go / Rust / Solidity all brace-delimited)
# --------------------------------------------------------------------------- #
_HEADER_RE = {
    "go": re.compile(r"(?m)^[ \t]*func\b"),
    "rust": re.compile(
        r"(?m)^[ \t]*(?:pub(?:\([^)]*\))?\s+)?(?:default\s+)?(?:async\s+)?"
        r"(?:const\s+)?(?:unsafe\s+)?(?:extern\s+\"[^\"]*\"\s+)?fn\s+\w+"
    ),
    "solidity": re.compile(r"(?m)^[ \t]*function\s+\w+"),
}


def _line_starts(text: str) -> list[int]:
    starts, off = [0], 0
    for line in text.split("\n")[:-1]:
        off += len(line) + 1
        starts.append(off)
    return starts


def split_functions(text: str, lang: str) -> list[dict]:
    """Return [{start,body_start,end,params}] with 1-based inclusive line nums."""
    hre = _HEADER_RE.get(lang)
    if not hre:
        return []
    starts = _line_starts(text)

    def lineno(off: int) -> int:
        return bisect.bisect_right(starts, off)

    fns: list[dict] = []
    for m in hre.finditer(text):
        paren = text.find("(", m.end())
        if paren == -1:
            continue
        pclose = _match_bracket(text, paren, "(", ")")
        if pclose == -1:
            continue
        params_txt = text[paren + 1:pclose]
        # first non-space after the (possibly multi-part) signature -> body '{'
        brace = text.find("{", pclose)
        semi = text.find(";", pclose)
        if brace == -1 or (semi != -1 and semi < brace):
            continue  # declaration / interface stub, no body
        bclose = _match_bracket(text, brace, "{", "}")
        if bclose == -1:
            bclose = len(text) - 1
        fns.append({
            "start": lineno(m.start()),
            "body_start": lineno(brace),
            "end": lineno(bclose),
            "params": set(_identifiers(params_txt)),
        })
    return fns


# --------------------------------------------------------------------------- #
# origin classification (the CORE attacker-derived predicate)
# --------------------------------------------------------------------------- #
_LEN_OF_COLLECTION_RE = re.compile(
    r"\.\s*(?:len|member_len|count|size|length|capacity)\s*\(\s*\)|(?<![\w.])len\s*\("
)


def collect_decode_locals(body_lines: list[str]) -> set[str]:
    out: set[str] = set()
    for ln in body_lines:
        low = ln.lower()
        if not any(tok in low for tok in DECODE_TOKENS):
            continue
        # LHS of the first '=' / ':=' that is an assignment (not ==, <=, >=, !=)
        m = re.search(r"^(.*?)(?::=|(?<![=<>!:])=(?!=))", ln)
        if not m:
            continue
        lhs = m.group(1)
        lhs = re.sub(r"^\s*(?:let|const|var)\s+(?:mut\s+)?", "", lhs)
        for idv in _identifiers(lhs):
            if idv not in _KEYWORDS:
                out.add(idv)
    return out


def is_attacker_derived(size_expr: str, params: set[str],
                        decode_locals: set[str]) -> tuple[bool, str, str | None]:
    """Return (fires, origin, operand_name).

    EXCLUDED (benign): a `.len()` of an already-materialised collection (the
    payload is already in memory - no amplification), and a pure constant.
    """
    if _LEN_OF_COLLECTION_RE.search(size_expr):
        return (False, "len-of-collection", None)
    idents = [i for i in _identifiers(size_expr)
              if i not in _KEYWORDS and not _is_constanty(i)]
    if not idents:
        return (False, "constant", None)
    for idv in idents:
        if idv in decode_locals:
            return (True, "decoded", idv)
    if _HEADER_FIELD_RE.search(size_expr):
        return (True, "header-field", idents[0])
    for idv in idents:
        if idv in params and has_size_hint(idv):
            return (True, "param", idv)
    return (False, "internal", None)


def _capped_inline(size_expr: str) -> bool:
    # size expr itself clamps: min(N,K) / N.min(K) / clamp / saturating.
    return bool(re.search(
        r"\.\s*min\s*\(|(?<![\w.])min\s*\(|\bclamp\b|\bsaturating_", size_expr))


def has_cap_before(op: str, lines: list[str], alloc_idx: int,
                   fn_start_idx: int) -> bool:
    """Does a dominating upper-bound cap on `op` appear before line alloc_idx?

    alloc_idx / fn_start_idx are 0-based indices into `lines`.
    """
    if not op:
        return False
    esc = re.escape(op)
    has_op = re.compile(rf"(?<![\w]){esc}(?![\w])")
    clamp = re.compile(rf"(?<![\w]){esc}(?![\w])\s*=\s*.*?"
                       rf"(?:\.\s*min\s*\(|(?<![\w.])min\s*\(|clamp|saturating_)")
    req = re.compile(rf"(?:require|ensure|assert|assert_le|debug_assert)?\s*!?\s*"
                     rf"\(?\s*(?<![\w]){esc}(?![\w])\s*(?:<=|<)\s*\S")
    upper = re.compile(rf"(?<![\w]){esc}(?![\w])\s*(?:>=|>)\s*\S")
    lower_reject = re.compile(rf"(?<![\w]){esc}(?![\w])\s*(?:<=|<)\s*\S")
    for i in range(fn_start_idx, alloc_idx):
        ln = lines[i]
        if not has_op.search(ln):
            continue
        if clamp.search(ln):
            return True
        # require/ensure/assert(N <= K) upper-bound guard
        if re.search(r"\b(?:require|ensure|assert|debug_assert|assert_le)\b", ln) \
                and req.search(ln):
            return True
        # `if N > K { ... return/revert/Err ... }` reject-too-big, 4-line window
        if upper.search(ln) and _REJECT_RE.search(" ".join(lines[i:i + 4])):
            return True
        # `if N <= K { proceed } else { return }`  (accept-small branch)
        if lower_reject.search(ln) and _REJECT_RE.search(" ".join(lines[i:i + 4])):
            return True
    return False


# --------------------------------------------------------------------------- #
# allocation / loop site extraction
# --------------------------------------------------------------------------- #
def _call_args(line: str, open_paren_idx: int) -> str | None:
    close = _match_bracket(line, open_paren_idx, "(", ")")
    if close == -1:
        return None
    return line[open_paren_idx + 1:close]


def alloc_sites(line: str, lang: str) -> list[tuple[str, str]]:
    """Return [(kind, size_expr)] for each allocation/loop on this line."""
    out: list[tuple[str, str]] = []
    if lang == "go":
        for m in re.finditer(r"\bmake\s*\(", line):
            args = _call_args(line, m.end() - 1)
            if args is None:
                continue
            parts = split_top_commas(args)
            # make(TYPE, len[, cap]) - size operands are every arg after the type
            for sz in parts[1:]:
                out.append(("make-alloc", sz))
        for kind, bound in _go_sol_loops(line):
            out.append((kind, bound))
    elif lang == "rust":
        for kw in ("with_capacity", "reserve", "reserve_exact"):
            for m in re.finditer(rf"\b{kw}\s*\(", line):
                args = _call_args(line, m.end() - 1)
                if args is not None:
                    for sz in split_top_commas(args):
                        out.append((kw, sz))
        for m in re.finditer(r"\bvec!\s*\[", line):
            close = _match_bracket(line, m.end() - 1, "[", "]")
            if close == -1:
                continue
            inner = line[m.end():close]
            if ";" in inner:
                out.append(("vec-macro", inner.split(";")[-1].strip()))
        for m in re.finditer(r"\bfor\s+\w+\s+in\s+[\w:]*\s*[\w.]*\s*\.\.=?\s*",
                             line):
            bound = re.split(r"\.\.=?", line[m.start():], maxsplit=1)[-1]
            bound = re.split(r"[\s{]", bound.strip(), maxsplit=1)[0]
            if bound:
                out.append(("bounded-loop", bound))
    elif lang == "solidity":
        for m in re.finditer(r"\bnew\s+[A-Za-z_]\w*\s*\[\s*\]\s*\(", line):
            args = _call_args(line, line.index("(", m.end() - 1))
            if args is not None:
                for sz in split_top_commas(args):
                    out.append(("new-array", sz))
        for m in re.finditer(r"\bnew\s+(?:bytes|string)\s*\(", line):
            args = _call_args(line, m.end() - 1)
            if args is not None:
                for sz in split_top_commas(args):
                    out.append(("new-bytes", sz))
        for kind, bound in _go_sol_loops(line):
            out.append((kind, bound))
    return out


def _go_sol_loops(line: str) -> list[tuple[str, str]]:
    out = []
    m = re.search(r"\bfor\b[^{;]*;[^{;<>]*?<\s*=?\s*([^;{]+?)\s*;", line)
    if m:
        out.append(("bounded-loop", m.group(1).strip()))
    return out


# --------------------------------------------------------------------------- #
# core screen
# --------------------------------------------------------------------------- #
def screen_text(text: str, lang: str, path: str = "<mem>") -> list[dict]:
    if lang not in ("go", "rust", "solidity"):
        return []
    lines = text.split("\n")
    findings: list[dict] = []
    for fn in split_functions(text, lang):
        body_start_idx = fn["body_start"] - 1
        end_idx = min(fn["end"], len(lines))
        body_lines = lines[body_start_idx:end_idx]
        decode_locals = collect_decode_locals(body_lines)
        for idx in range(body_start_idx, end_idx):
            line = lines[idx]
            for kind, size_expr in alloc_sites(line, lang):
                if _capped_inline(size_expr):
                    continue
                fires, origin, opname = is_attacker_derived(
                    size_expr, fn["params"], decode_locals)
                if not fires:
                    continue
                if has_cap_before(opname, lines, idx, body_start_idx):
                    continue  # SILENT: the private invariant is established
                findings.append({
                    "schema": SCHEMA,
                    "file": path,
                    "line": idx + 1,
                    "lang": lang,
                    "alloc_kind": kind,
                    "size_operand": opname,
                    "size_expr": size_expr.strip(),
                    "origin": origin,
                    "snippet": line.strip()[:200],
                    "delegated_invariant": DELEGATED_INVARIANT,
                    "private_invariant": PRIVATE_INVARIANT,
                    "attack": ATTACK,
                    "verdict": "needs-fuzz",
                })
    return findings


def screen_file(path: str) -> list[dict]:
    lang = classify_lang(path)
    if not lang:
        return []
    try:
        text = pathlib.Path(path).read_text(encoding="utf-8", errors="replace")
    except OSError:
        return []
    return screen_text(text, lang, path)


_SKIP_DIRS = {
    ".git", ".auditooor", "node_modules", "vendor", "target", "testdata",
    "test", "tests", "mocks", "mock", "third_party", "reports", "docs",
    "fixtures", "examples", "example", "dist", "build",
}
_SKIP_FILE_RE = re.compile(r"(?:_test\.go$|\.t\.sol$|/test_|(?:^|/)test_|mock)",
                           re.IGNORECASE)


def iter_source_files(root: str):
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in _SKIP_DIRS]
        for fn in filenames:
            if classify_lang(fn) is None:
                continue
            full = os.path.join(dirpath, fn)
            if _SKIP_FILE_RE.search(full):
                continue
            yield full


def screen_workspace(root: str) -> tuple[list[dict], dict]:
    findings: list[dict] = []
    n_files = 0
    for full in iter_source_files(root):
        n_files += 1
        rel = os.path.relpath(full, root)
        for f in screen_file(full):
            f["file"] = rel
            findings.append(f)
    acc = {
        "schema": SCHEMA + ".accounting",
        "workspace_root": root,
        "files_screened": n_files,
        "hypotheses": len(findings),
        "verdict": "needs-fuzz" if findings else "clean",
        "advisory_only": True,
        "delegated_invariant": DELEGATED_INVARIANT,
    }
    return findings, acc


# --------------------------------------------------------------------------- #
# CLI
# --------------------------------------------------------------------------- #
def _resolve_ws(ws: str) -> str:
    # An explicit path (contains a separator or is dot/absolute) is literal.
    if os.sep in ws or ws.startswith(".") or os.path.isabs(ws):
        return ws
    # A bare ws NAME resolves against the canonical audits root first, so a
    # same-named stray dir in the cwd cannot shadow the real workspace.
    cand = os.path.join("/Users/wolf/audits", ws)
    if os.path.isdir(cand):
        return cand
    return ws


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description="E7 allocate/iterate-before-cap screen")
    ap.add_argument("--workspace", help="ws name under /Users/wolf/audits or a path")
    ap.add_argument("--path", help="single source file to screen")
    ap.add_argument("--stdin", action="store_true", help="read source from stdin")
    ap.add_argument("--lang", choices=("go", "rust", "solidity"),
                    help="language for --stdin")
    ap.add_argument("--json", action="store_true", help="emit findings as JSON")
    ap.add_argument("--out", action="store_true",
                    help="also write .auditooor sidecar + accounting")
    args = ap.parse_args(argv)

    findings: list[dict] = []
    acc: dict = {"schema": SCHEMA + ".accounting", "advisory_only": True}
    ws_root = None

    if args.stdin:
        text = sys.stdin.read()
        findings = screen_text(text, args.lang or "rust", "<stdin>")
        acc.update({"files_screened": 1, "hypotheses": len(findings),
                    "verdict": "needs-fuzz" if findings else "clean"})
    elif args.path:
        findings = screen_file(args.path)
        acc.update({"files_screened": 1, "hypotheses": len(findings),
                    "verdict": "needs-fuzz" if findings else "clean"})
    elif args.workspace:
        ws_root = _resolve_ws(args.workspace)
        if not os.path.isdir(ws_root):
            acc.update({"error": f"workspace not found: {ws_root}",
                        "files_screened": 0, "hypotheses": 0, "verdict": "clean"})
        else:
            findings, acc = screen_workspace(ws_root)
    else:
        ap.error("one of --workspace / --path / --stdin is required")

    if args.out and ws_root:
        outdir = os.path.join(ws_root, ".auditooor")
        os.makedirs(outdir, exist_ok=True)
        with open(os.path.join(ws_root, OUT_REL), "w") as fh:
            for f in findings:
                fh.write(json.dumps(f) + "\n")
        with open(os.path.join(ws_root, ACC_REL), "w") as fh:
            json.dump(acc, fh, indent=2)

    if args.json:
        print(json.dumps({"accounting": acc, "findings": findings}, indent=2))
    else:
        print(f"[E7] files={acc.get('files_screened', 0)} "
              f"hypotheses={acc.get('hypotheses', len(findings))} "
              f"verdict={acc.get('verdict', 'clean')} (advisory, needs-fuzz)")
        for f in findings[:40]:
            print(f"  {f['file']}:{f['line']}  {f['alloc_kind']}"
                  f"  N={f['size_operand']} origin={f['origin']}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
