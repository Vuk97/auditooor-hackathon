#!/usr/bin/env python3
"""traversal-terminal-canonicalization-screen.py - GEN-A2, the TRAVERSAL
TERMINAL-STATE CANONICALIZATION screen (Solidity + Go + Rust arms).

GENERAL LOGIC / TRUST-ENFORCEMENT class (impact-agnostic, NORTH-STAR trust-
boundary class, never a bug SHAPE). A delegated VARIABLE-LENGTH-WALK verifier -
a merkle / MPT / trie proof-path walk, a threshold-signature accumulation loop, a
linked-list / chain walk, a state-replay loop - must ACCEPT its result IFF the
CANONICAL TERMINAL was reached:

  * the last leaf / terminal node (a LEAF flag / node-type == LEAF / path pointer
    == path length),
  * the required signer/quorum count (count >= threshold, power >= 2/3),
  * the chain tip / expected index (i == expected_len, computed == root).

The bug class: an EARLY-STOP or a MID-WALK node reinterpreted as the terminal -
the Polygon MPT-extension-hash reinterpreted as the value payload; a merkle
verify that returns true on a PARTIAL path; a threshold loop that breaks before
reaching quorum. Concretely, a walk/verify loop that:

  (a) can return accept / true (or set a verified flag) WITHOUT any dominating
      terminal-condition assertion (isLeaf / node-type == LEAF / index ==
      expected_len / count >= threshold / computed == root) in the function, OR
  (b) RETURNS a value read at a NON-terminal iteration as the trusted result.

A walk-verify site matching (a) or (b) is flagged (advisory, verdict=needs-fuzz).

ADVISORY-FIRST: every row carries verdict='needs-fuzz', advisory=True,
auto_credit=False, and the tool exits 0 in default mode. The opt-in env
AUDITOOOR_TERMINAL_CANON_STRICT (or --strict) only raises the exit code when a
fired row exists.

Excludes machine-generated (.pb.go/.pulsar.go + "DO NOT EDIT"), test, sim and
vendored code via the shared exclusion libs. Silent on other trees.

Pattern classes (per lang, S_/G_/R_ prefix)
-------------------------------------------
  * WALK_ACCEPT_NO_TERMINAL : a for/while/loop over a proof/path/nodes/signers/
      validators collection whose function can return accept/true (or set a
      verified flag) with NO terminal-condition guard anywhere in the function.
      -> missing_assertion = "canonical-terminal".
  * MIDWALK_VALUE_RETURN : a `return <expr>` INSIDE the walk loop body that
      surfaces a per-iteration node/element value as the trusted result, with no
      terminal guard - a mid-walk node reinterpreted as the terminal payload
      (the Polygon extension-hash-as-value class).
      -> missing_assertion = "non-terminal-value-trusted".

Usage:
  --workspace <ws>   scan <ws>/src -> .auditooor/terminal_canonicalization_hypotheses.jsonl + summary
  --source <dir>     scan an arbitrary dir, print rows as JSON (NO sidecar - tests/verify)
  --file <f>         scan a single .sol/.go/.rs file, print rows as JSON
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

HYP_SCHEMA = "auditooor.terminal_canonicalization_hypotheses.v1"
_SIDE_NAME = "terminal_canonicalization_hypotheses.jsonl"
_STRICT_ENV = "AUDITOOOR_TERMINAL_CANON_STRICT"
_CAPABILITY = "GEN_A2"

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
    (the .go/.sol/.rs codegen sentinel) rather than re-inline the DO-NOT-EDIT
    logic."""
    tool = TOOLS_DIR / "declared-control-mutator-completeness-screen.py"
    try:
        spec = importlib.util.spec_from_file_location("_dc_screen_tc", tool)
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
    r"(^|/)(tests?|testutil|testonly|testhelper|test_fixtures|mock|mocks|"
    r"benches|benchmarks?|examples|fixtures|simulation|simapp|testdata)(/|$)")


# ============================================================================
# comment/string masking + function extraction (Solidity + Go + Rust)
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
    r"function\s+([A-Za-z_]\w*)"                       # Solidity function foo
    r"|(constructor)\b"                                # Solidity constructor
    r"|func\s+(?:\([^)]*\)\s*)?([A-Za-z_]\w*)"         # Go func (recv) Foo
    r"|(?:pub\s+)?(?:async\s+)?(?:unsafe\s+)?fn\s+([A-Za-z_]\w*)"  # Rust fn foo
    r")")


def _fn_name(m):
    return m.group(1) or m.group(2) or m.group(3) or m.group(4)


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
# helpers
# ============================================================================
def _body_after_sig(body_lines) -> str:
    joined = "\n".join(l for _i, l in body_lines)
    brace = joined.find("{")
    return joined[brace + 1:] if brace >= 0 else joined


def _line_of_offset(text: str, off: int) -> int:
    return text.count("\n", 0, off) + 1


def _matching_brace(s: str, open_idx: int) -> int:
    depth = 0
    for k in range(open_idx, len(s)):
        if s[k] == "{":
            depth += 1
        elif s[k] == "}":
            depth -= 1
            if depth == 0:
                return k + 1
    return len(s)


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
# terminal-canonicalization predicates (cross-language)
# ============================================================================
# a walk collection: STRONG proof-path / signer-set nouns only. Deliberately
# excludes generic nouns (path/paths, chain, links, nodes, node, branch, leaf,
# leaves, powers, hashes) that spray on filepath/blockchain/getter code - the
# north-star is proof-verification and threshold-accumulation, not any loop.
_WALK_NOUN_RE = re.compile(
    r"(?i)\b(proofs?|parentnodes?|siblings?|signers?|signatures?|validators?|"
    r"validatorset|quorum|witness(?:es)?|merkle|trie|mpt|nibble|encodedpath)\b")
# a verification / accumulation / walk intent in the FUNCTION NAME.
_VERIFY_FN_RE = re.compile(
    r"(?i)(verify|prove|proof|validate|accumulate|walk|traverse|recover|"
    r"computeroot|checkmerkle|checksig|threshold|processproof)")
_LOOP_RE = re.compile(r"\b(for|while)\b|\bloop\b")

# accept: a boolean success returned or a verified flag set true.
_ACCEPT_RE = re.compile(
    r"\breturn\s+true\b"
    r"|\bOk\s*\(\s*true\s*\)"
    r"|\b(verified|valid|isvalid|is_valid|ok|success|authorized|passed|"
    r"matched|proven|proved)\s*=\s*true\b",
    re.I)

# --- terminal-condition guards (any of these present == canonical terminal is
# asserted somewhere in the function) --------------------------------------
_PTR = r"(i|j|k|idx|index|pos|ptr|pathptr|cursor|offset|consumed|traversed|depth|count)"
_LEN = r"(\.length|len\s*\([^)]*\)|Length\b|expected\w*|_len\b|size\b)"
_G_ROOT = re.compile(r"(==|!=)\s*[\w.\[\]]*root\w*|\b\w*root\w*\s*(==|!=)", re.I)
# leaf/terminal FLAG check only - NOT the bare `leaf` VALUE variable (which is
# present in every merkle verify and is the value being proven, not a terminal
# condition). A LEAF *constant* is matched case-sensitively in a comparison.
_G_LEAF = re.compile(
    r"\bis_?leaf\b|\bis_?terminal\b|\.terminal\b|node_?type", re.I)
_G_LEAF_CONST = re.compile(r"(==|!=)\s*[\w.]*LEAF\b|\bLEAF\b\s*(==|!=)")
_G_PTRLEN_FWD = re.compile(
    rf"\b{_PTR}\b[\w\s+\-]{{0,24}}(==|>=|>)\s*[\w.\(\)]*{_LEN}", re.I)
_G_PTRLEN_REV = re.compile(
    rf"{_LEN}\s*(==|<=|<|>=|>)\s*[\w\s+\-]{{0,24}}\b{_PTR}\b", re.I)
_G_THRESHOLD = re.compile(
    r"threshold|quorum|totalpower|totalvotingpower|votingpower|two_?thirds|"
    r"2\s*/\s*3|2\s*\*\s*total|majority|numsigners\b|required\s*signatures", re.I)


def _has_terminal_guard(body: str) -> bool:
    return bool(_G_ROOT.search(body) or _G_LEAF.search(body)
                or _G_LEAF_CONST.search(body)
                or _G_PTRLEN_FWD.search(body) or _G_PTRLEN_REV.search(body)
                or _G_THRESHOLD.search(body))


def _loop_spans(body: str):
    """Yield (start, end) text-offset spans of each loop's brace-delimited body."""
    for m in _LOOP_RE.finditer(body):
        brace = body.find("{", m.end())
        if brace < 0 or brace - m.end() > 200:
            continue
        end = _matching_brace(body, brace)
        yield (brace, end)


# a mid-walk value return: `return <expr>` that is NOT a bare bool / nil / err and
# that references an index/element read (loop var or collection element).
_RET_VALUE_RE = re.compile(r"\breturn\s+([^;{}\n]+)")
_NONVALUE_RET = re.compile(
    r"^\s*(true|false|nil|Ok\s*\(|Err\s*\(|None|Some\s*\(\s*\)|;|$)", re.I)
# an error / diagnostic return is not a mid-walk trusted-value result.
_ERR_RET = re.compile(r"\berr\b|errorf|errors\s*\.|\berror\s*\(|fmt\s*\.", re.I)


# ============================================================================
# core per-function scan
# ============================================================================
def _scan_fn(rel, name, decl_idx, sig, body, lang, rows):
    if not _LOOP_RE.search(body):
        return
    if not _WALK_NOUN_RE.search(body):
        return
    spans = list(_loop_spans(body))
    walk_noun_in_loop = any(
        _WALK_NOUN_RE.search(body[s:e]) for s, e in spans)
    verify_fn = bool(_VERIFY_FN_RE.search(name))
    # a delegated variable-length verification: a real loop that walks a
    # proof/path/nodes/signers collection, in a verify-intent function OR whose
    # loop body itself iterates such a collection.
    if not (walk_noun_in_loop or verify_fn):
        return

    terminal = _has_terminal_guard(body)

    # ---- Pattern A: WALK_ACCEPT_NO_TERMINAL -----------------------------
    if not terminal:
        am = _ACCEPT_RE.search(body)
        if am:
            off = am.start()
            rows.append(_mk_row(
                rel, name, _line_of_offset(body, off) + decl_idx, lang,
                _kind(lang, "WALK_ACCEPT_NO_TERMINAL"), name,
                "canonical-terminal", _excerpt(body, off),
                f"walk-verify loop in `{name}` can return accept/true (or set a "
                f"verified flag) with NO terminal-condition assertion (isLeaf / "
                f"node-type == LEAF / index == expected_len / count >= threshold "
                f"/ computed == root) dominating the accept - an early-stop or a "
                f"partial-path proof is accepted as if it reached the canonical "
                f"terminal (Polygon MPT / partial-merkle / sub-quorum class).",
                early_break=("break" in body)))

    # ---- Pattern B: MIDWALK_VALUE_RETURN --------------------------------
    # verify-intent only: a general getter that returns an element mid-loop is
    # not a trust boundary. The genuine class is a PROOF/TRIE verifier that
    # surfaces a per-iteration node as the trusted result (Polygon extension-
    # hash-as-value).
    if not terminal and verify_fn:
        for s, e in spans:
            seg = body[s:e]
            for rm in _RET_VALUE_RE.finditer(seg):
                expr = rm.group(1).strip()
                if _NONVALUE_RET.match(expr) or _ERR_RET.search(expr):
                    continue
                # must surface a per-iteration element/index read as the result.
                if not re.search(r"\[[^\]]*\]", expr):
                    continue
                off = s + rm.start()
                rows.append(_mk_row(
                    rel, name, _line_of_offset(body, off) + decl_idx, lang,
                    _kind(lang, "MIDWALK_VALUE_RETURN"), expr[:60],
                    "non-terminal-value-trusted", _excerpt(body, off),
                    f"`return {expr[:60]}` inside the walk loop of `{name}` "
                    f"surfaces a per-iteration node/element value as the trusted "
                    f"result with no terminal-condition guard - a mid-walk node "
                    f"can be reinterpreted as the terminal payload (the Polygon "
                    f"extension-hash-as-value class).",
                    early_break=True))
                break  # one mid-walk-return row per loop is enough signal


def _kind(lang, base):
    return {"solidity": "S_", "go": "G_", "rust": "R_"}.get(lang, "X_") + base


# ============================================================================
# row + summary
# ============================================================================
def _mk_row(rel, fn, line, lang, kind, subj, missing, excerpt, why,
            early_break=False):
    return {
        "schema": HYP_SCHEMA,
        "capability": _CAPABILITY,
        "id": _stable_id(rel, fn, kind, subj, line),
        "file": rel,
        "line": line,
        "function": fn,
        "context": fn,
        "lang": lang,
        "pattern_id": kind,
        "subject": subj,
        "missing_assertion": missing,
        "early_break": bool(early_break),
        "excerpt": excerpt,
        "why_severity_anchored": why,
        "fires": True,
        "verdict": "needs-fuzz",
        "advisory": True,
        "auto_credit": False,
    }


def _lang_of(rel: str) -> str:
    low = rel.lower()
    if low.endswith(".go"):
        return "go"
    if low.endswith(".rs"):
        return "rust"
    return "solidity"


def scan_file(path: Path, rel: str, file_text: str = None):
    raw = file_text if file_text is not None else path.read_text(
        encoding="utf-8", errors="ignore")
    text = _mask_comments(raw)
    lang = _lang_of(rel)
    lines = text.split("\n")
    rows = []
    for name, decl_idx, sig, body_lines in _functions(lines):
        body = _body_after_sig(body_lines)
        _scan_fn(rel, name, decl_idx, sig, body, lang, rows)
    return rows


def _iter_source_files(root: Path, workspace: Path = None):
    for dp, dn, fn in os.walk(root):
        dn[:] = [d for d in dn if d not in _SKIP_DIRS]
        if _TEST_HINT.search(dp.replace(os.sep, "/")):
            continue
        for f in fn:
            low = f.lower()
            if not (low.endswith(".sol") or low.endswith(".go")
                    or low.endswith(".rs")):
                continue
            if (low.endswith("_test.go") or low.endswith(".t.sol")
                    or low.endswith("_test.rs")):
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
        "walk_sites": len(rows),
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
        description="GEN-A2 traversal terminal-state canonicalization screen "
                    "(Solidity + Go + Rust, advisory)")
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
