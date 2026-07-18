#!/usr/bin/env python3
"""
cosmos-detector-runner.py — first executor for `backend: cosmos` DSL rows.

Wave 2 capability uplift. PR #460 (Wave 1) added the schema slot for
`backend: cosmos` (alongside `anchor` / `geth_runtime` / `circom`) so that
`detector-lint --fail-unknown-function-kind` would stop flagging Cosmos-SDK
specific function-kind markers (e.g. `cosmos_msg_handler`) as Solidity
typos. But no executor existed: the slot was `documentation_only de facto`.
This script ships the FIRST one.

What it does:
  1. Walks workspace `*.go` files (Cosmos SDK is Go).
  2. Reads DSL rows from `reference/patterns.dsl/*.yaml` where
     `backend: cosmos`.
  3. Evaluates a SMALL predicate vocabulary against each top-level Go
     function:
       - chain.is_cosmos_sdk         (precondition, always true if any
                                      go.mod under workspace mentions
                                      cosmos-sdk; required, else SKIP)
       - contract.source_matches_regex   (precondition, file-level regex)
       - function.kind: cosmos_msg_handler  (always true here — surface
                                             marker that detector-lint
                                             wants tied to backend: cosmos)
       - function.name_matches            (regex on Go function name)
       - function.body_contains_regex     (regex on function body)
       - function.body_not_contains_regex (negated regex on function body)
       - function.not_in_skip_list: true  (always true; we already skip
                                           vendor/test/build dirs)
       - function.not_source_matches_regex (negated regex on file source)
  4. Writes findings JSON to `<workspace>/.auditooor/cosmos_findings.json`
     with `pattern, file:line, severity, confidence, evidence_class:
     scaffolded_unverified` (matching the Wave 1 evidence-class vocabulary).

Discipline:
  - stdlib only. No PyYAML. We parse the small DSL surface ourselves —
    every cosmos pattern follows the same shape (top-level scalars +
    `preconditions:`/`match:` lists of single-key dicts).
  - Unsupported predicates produce a clear `[skip predicate ...]` log
    line; the rest of the row continues to evaluate. A row that has only
    unsupported predicates emits NO findings.
  - Always exits 0 (this is a lead generator, not a gate). Exit 2 only
    on argv misuse or when the workspace path does not exist.
  - `evidence_class: scaffolded_unverified` is the deliberate Wave 1
    contract: regex hits are leads, not proof. Promotion to a higher
    evidence class is a downstream production-path / fixture step.

Usage:
    python3 tools/cosmos-detector-runner.py <workspace>
    python3 tools/cosmos-detector-runner.py <workspace> --only <pattern-id>
    python3 tools/cosmos-detector-runner.py <workspace> --patterns-dir <dir>
    python3 tools/cosmos-detector-runner.py <workspace> --out <findings.json>

Wired into `make audit` via the `cosmos-detect` Makefile target. See
docs/COSMOS_BACKEND.md for schema, supported predicates, file walker, and
output schema.
"""
from __future__ import annotations

import argparse
import contextlib
import json
import os
import re
import signal
import sys
import time
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
DEFAULT_PATTERNS_DIR = REPO / "reference" / "patterns.dsl"

# PER-FILE wall-clock guard (Task #162, SEI 2026-07-05): the DSL matcher runs
# author-supplied regexes (re.search / finditer) over whole-file source + every
# function body. Python's stdlib `re` has NO backtracking bound, so ONE
# catastrophic-backtracking (regex x large generated .go file) pair spins at 100%
# CPU indefinitely - hanging the entire step-2 scan (observed: a single detector
# file stuck >10min, blocking step-3 until the 3600s outer timeout, then feeding a
# partial scan downstream = silent degrade). Bounding each file's matching to a
# wall-clock cap converts an unbounded hang into a TYPED, logged per-file skip.
_PER_FILE_TIMEOUT_S = int(os.environ.get("AUDITOOOR_COSMOS_DETECT_FILE_TIMEOUT", "25"))


class _MatchTimeout(Exception):
    """Raised when a single file's detector matching exceeds the wall-clock cap."""


@contextlib.contextmanager
def _time_limit(seconds: int):
    """Bound the enclosed block to ``seconds`` wall-clock via SIGALRM. No-op (never
    raises) when unsupported (non-main-thread / no SIGALRM / seconds<=0) so behavior
    fail-OPEN to the current unbounded scan rather than crash. Unix main-thread only."""
    if seconds <= 0 or not hasattr(signal, "SIGALRM"):
        yield
        return

    def _handler(signum, frame):
        raise _MatchTimeout()

    try:
        prev = signal.signal(signal.SIGALRM, _handler)
    except (ValueError, OSError):
        # Not the main thread -> cannot arm SIGALRM; run unbounded (fail-open).
        yield
        return
    signal.setitimer(signal.ITIMER_REAL, seconds)
    try:
        yield
    finally:
        signal.setitimer(signal.ITIMER_REAL, 0)
        signal.signal(signal.SIGALRM, prev)

SKIP_PARTS = {
    ".git",
    "node_modules",
    "vendor",
    "third_party",
    "third-party",
    "testdata",
    "tests",
    "test",
    "build",
    "dist",
    "out",
    "__pycache__",
    "target",
}

SUPPORTED_PREDICATES = {
    # preconditions
    "chain.is_cosmos_sdk",
    "contract.source_matches_regex",
    # match
    "function.kind",
    "function.name_matches",
    "function.body_contains_regex",
    "function.body_not_contains_regex",
    "function.not_in_skip_list",
    "function.not_source_matches_regex",
}

# function.kind tokens we recognise. Anything else is unsupported. The
# whole point of the cosmos backend split (PR #460) was to stop flagging
# `cosmos_msg_handler` as a Solidity typo — so we simply accept that token
# and require nothing else; the actual filter work is done by the
# `function.name_matches` regex on the same row.
COSMOS_FUNCTION_KINDS = {"cosmos_msg_handler", "any"}


# ---------------------------------------------------------------------------
# Tiny YAML subset parser
# ---------------------------------------------------------------------------
#
# We parse exactly what the DSL files use:
#   - top-level `key: scalar` lines
#   - top-level `key:` followed by an indented block of either
#     `- scalar` items OR `- single_key: scalar` items
#   - comments (`#`) ignored; blank lines ignored
#   - quoted strings (single or double) preserved as scalars
#   - block scalar values for `help:` etc are treated as plain strings
#
# This is intentionally NOT a general-purpose YAML parser. We only need it
# to ingest reference/patterns.dsl/*.yaml rows whose `backend:` is
# `cosmos`. Other rows may have shapes (block scalars, multi-line lists)
# this parser does not handle — which is fine, because we ignore them.


def _strip_comment(line: str) -> str:
    # Remove trailing # comment, but ignore # inside quoted strings.
    in_single = False
    in_double = False
    out = []
    i = 0
    while i < len(line):
        ch = line[i]
        if ch == "'" and not in_double:
            in_single = not in_single
        elif ch == '"' and not in_single:
            in_double = not in_double
        elif ch == "#" and not in_single and not in_double:
            break
        out.append(ch)
        i += 1
    return "".join(out)


def _unquote(s: str) -> str:
    s = s.strip()
    if len(s) >= 2 and s[0] == s[-1] and s[0] in ("'", '"'):
        # Replace YAML-style escaped doubled quote inside the same kind.
        inner = s[1:-1]
        if s[0] == "'":
            inner = inner.replace("''", "'")
        else:
            inner = inner.replace('\\"', '"').replace("\\\\", "\\")
        return inner
    return s


def _coerce(v: str):
    sv = v.strip()
    if sv == "":
        return None
    if sv in ("true", "True", "TRUE"):
        return True
    if sv in ("false", "False", "FALSE"):
        return False
    if sv in ("null", "Null", "NULL", "~"):
        return None
    return _unquote(sv)


def _indent(line: str) -> int:
    n = 0
    for ch in line:
        if ch == " ":
            n += 1
        elif ch == "\t":
            # Treat tabs as 4 spaces; the DSL files don't use tabs but
            # be defensive.
            n += 4
        else:
            break
    return n


def parse_dsl_yaml(text: str) -> dict:
    """Parse the small DSL YAML subset. Returns a dict; raises ValueError
    on shapes we cannot interpret."""
    raw_lines = text.splitlines()
    # Pre-strip comments + blank lines but keep original line indices for
    # error reporting. We keep "" as a sentinel for blanks that we then
    # skip in the cursor loop.
    cleaned: list[tuple[int, str]] = []
    for i, ln in enumerate(raw_lines):
        stripped = _strip_comment(ln).rstrip()
        if stripped.strip() == "":
            continue
        cleaned.append((i, stripped))

    out: dict = {}
    idx = 0
    while idx < len(cleaned):
        lineno, line = cleaned[idx]
        ind = _indent(line)
        if ind != 0:
            # Top-level key indented? skip — not a shape we support.
            idx += 1
            continue
        body = line.strip()
        if ":" not in body:
            idx += 1
            continue
        key, _, rest = body.partition(":")
        key = key.strip()
        rest = rest.strip()
        if rest != "":
            # scalar value on the same line
            out[key] = _coerce(rest)
            idx += 1
            continue
        # block value: peek at next line
        idx += 1
        block_items: list = []
        block_dict: dict = {}
        # Sniff first non-blank child indent
        first_child_ind = None
        while idx < len(cleaned):
            cl_lineno, cl_line = cleaned[idx]
            cl_ind = _indent(cl_line)
            if cl_ind == 0:
                break
            if first_child_ind is None:
                first_child_ind = cl_ind
            if cl_ind < first_child_ind:
                break
            stripped = cl_line.strip()
            if stripped.startswith("- "):
                item_body = stripped[2:].strip()
                # `- key: value` (single-key dict) OR `- scalar`
                if ":" in item_body:
                    ik, _, iv = item_body.partition(":")
                    ik = ik.strip()
                    iv_raw = iv.strip()
                    if iv_raw == "":
                        # `- key:` then nested children (e.g. list of strings)
                        # We support exactly one level of nesting here.
                        idx += 1
                        nested_items: list = []
                        while idx < len(cleaned):
                            n_lineno, n_line = cleaned[idx]
                            n_ind = _indent(n_line)
                            if n_ind <= cl_ind:
                                break
                            nstripped = n_line.strip()
                            if nstripped.startswith("- "):
                                nested_items.append(_coerce(nstripped[2:].strip()))
                            idx += 1
                        block_items.append({ik: nested_items})
                        continue
                    else:
                        block_items.append({ik: _coerce(iv_raw)})
                else:
                    block_items.append(_coerce(item_body))
                idx += 1
            else:
                # nested mapping `subkey: value`
                if ":" in stripped:
                    sk, _, sv = stripped.partition(":")
                    block_dict[sk.strip()] = _coerce(sv.strip())
                idx += 1
        if block_items and not block_dict:
            out[key] = block_items
        elif block_dict and not block_items:
            out[key] = block_dict
        else:
            # Empty block — record empty list; downstream will treat as no-op.
            out[key] = block_items or block_dict or []
    return out


# ---------------------------------------------------------------------------
# Workspace discovery
# ---------------------------------------------------------------------------


def is_cosmos_sdk_workspace(workspace: Path) -> tuple[bool, str | None]:
    """Returns (is_cosmos, evidence_path). Cosmos-SDK chains are Go modules
    that import `github.com/cosmos/cosmos-sdk` in some go.mod under the
    workspace. Searches ALL go.mod (not just root) so that monorepos work."""
    candidates = list(workspace.rglob("go.mod"))
    if not candidates:
        return (False, None)
    for gm in candidates:
        # Skip vendor/test/build dirs
        parts = set(gm.resolve().parts)
        if parts & SKIP_PARTS:
            continue
        try:
            text = gm.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        if "cosmos-sdk" in text or "cosmossdk.io" in text:
            return (True, str(gm))
    return (False, None)


def _load_scope_helpers():
    """Lazy-load scope_exclusion.is_in_scope (manifest-authoritative) + is_oos_dir
    (dir-shape OOS). Returns (is_in_scope_or_None, is_oos_dir_or_None) so the walk
    degrades to its prior SKIP_PARTS behavior if the lib is unavailable."""
    try:
        import sys as _sys
        _lib = str(Path(__file__).resolve().parent / "lib")
        if _lib not in _sys.path:
            _sys.path.insert(0, _lib)
        from scope_exclusion import is_in_scope, is_oos_dir  # type: ignore
        return is_in_scope, is_oos_dir
    except Exception:
        return None, None


def discover_go_files(workspace: Path) -> list[Path]:
    # SCOPE: when <ws>/.auditooor/inscope_units.jsonl exists, is_in_scope is the
    # AUTHORITATIVE inclusion filter (the manifest is already OOS-dir-filtered AND
    # fork-modified-pruned, so unmodified-upstream go-ethereum/cosmos-sdk and OOS
    # dirs are excluded automatically). is_oos_dir is the dir-shape backstop for
    # the no-manifest fallback so we never scan vendored/test/historical trees.
    is_in_scope, is_oos_dir = _load_scope_helpers()
    out: list[Path] = []
    for p in workspace.rglob("*.go"):
        rp = p.resolve()
        parts = set(rp.parts)
        if parts & SKIP_PARTS:
            continue
        if rp.name.endswith("_test.go"):
            continue
        try:
            rel = str(rp.relative_to(workspace.resolve())).replace("\\", "/")
        except ValueError:
            rel = rp.name
        # manifest-authoritative inclusion (preferred); else dir-shape OOS skip.
        if is_in_scope is not None:
            if not is_in_scope(rel, workspace=workspace):
                continue
        elif is_oos_dir is not None and is_oos_dir(rel):
            continue
        out.append(rp)
    return sorted(out)


# ---------------------------------------------------------------------------
# Go function extraction (regex-based; stdlib-only)
# ---------------------------------------------------------------------------
# Cosmos-SDK handlers look like:
#     func (k Keeper) SendCoins(ctx sdk.Context, ...) error { ... }
#     func MsgSend(...) { ... }
# We scan top-level `func ...` declarations. The DSL evaluator only needs:
#   - function name
#   - function body text
#   - line number (1-indexed) of the `func` keyword
# A naive `{...}` matcher would mishandle braces inside string literals or
# comments; for this lead-generator we use a simple brace counter that
# skips line-comments and strings. This is intentionally cheap and
# imperfect — false negatives are acceptable; we never claim proof.

_FUNC_HEADER_RE = re.compile(
    r"""
    ^func\s+                                  # 'func '
    (?:\(\s*\w+\s+\*?\w+(?:\.\w+)?\s*\)\s+)?  # optional receiver: (k Keeper)
    (?P<name>[A-Za-z_][A-Za-z0-9_]*)          # function name
    \s*\(                                     # opening paren of params
    """,
    re.VERBOSE | re.MULTILINE,
)


def extract_go_functions(source: str) -> list[dict]:
    """Returns [{name, line, body}] for each top-level Go function.

    `body` is the text between (and including) the matching braces, with
    string literals and comments left intact (we don't strip them — the
    DSL regexes are run as-is)."""
    funcs: list[dict] = []
    for m in _FUNC_HEADER_RE.finditer(source):
        name = m.group("name")
        header_start = m.start()
        # Find the opening brace `{` of the body, after the param list.
        # Walk forward from the end of the header, counting parens to find
        # the param-list close, then find the next `{` that is the body.
        i = m.end()
        depth = 1  # we just consumed the `(`
        n = len(source)
        # Skip through param list
        while i < n and depth > 0:
            ch = source[i]
            if ch == "(":
                depth += 1
            elif ch == ")":
                depth -= 1
            i += 1
        # Now skip optional return-list — anything until the next `{` or
        # newline-followed-by-non-brace. We just look forward for the
        # first `{` that starts the body. If the function is an interface
        # method (no body) we skip it.
        brace_open = -1
        j = i
        while j < n:
            ch = source[j]
            if ch == "{":
                brace_open = j
                break
            if ch == "\n":
                # Allow multi-line return lists; only abort when we see a
                # top-level `func` again (very unlikely without braces).
                pass
            j += 1
        if brace_open < 0:
            continue
        # Find matching close brace, accounting for strings + comments.
        body_end = _scan_matching_brace(source, brace_open)
        if body_end < 0:
            continue
        body = source[brace_open : body_end + 1]
        line = source.count("\n", 0, header_start) + 1
        funcs.append({"name": name, "line": line, "body": body})
    return funcs


def _scan_matching_brace(source: str, open_idx: int) -> int:
    """Given source and index of `{`, return index of matching `}`. -1 if
    unmatched. Skips // line comments, /* block comments */, and string
    literals (`"..."`, `'...'`, and Go raw strings `` `...` ``)."""
    n = len(source)
    if source[open_idx] != "{":
        return -1
    depth = 0
    i = open_idx
    while i < n:
        ch = source[i]
        # // line comment
        if ch == "/" and i + 1 < n and source[i + 1] == "/":
            nl = source.find("\n", i + 2)
            if nl < 0:
                return -1
            i = nl + 1
            continue
        # /* block comment */
        if ch == "/" and i + 1 < n and source[i + 1] == "*":
            end = source.find("*/", i + 2)
            if end < 0:
                return -1
            i = end + 2
            continue
        # raw string literal
        if ch == "`":
            end = source.find("`", i + 1)
            if end < 0:
                return -1
            i = end + 1
            continue
        # double-quoted string
        if ch == '"':
            j = i + 1
            while j < n:
                if source[j] == "\\" and j + 1 < n:
                    j += 2
                    continue
                if source[j] == '"':
                    break
                if source[j] == "\n":
                    break
                j += 1
            i = j + 1
            continue
        # single-quoted rune
        if ch == "'":
            j = i + 1
            while j < n:
                if source[j] == "\\" and j + 1 < n:
                    j += 2
                    continue
                if source[j] == "'":
                    break
                if source[j] == "\n":
                    break
                j += 1
            i = j + 1
            continue
        if ch == "{":
            depth += 1
        elif ch == "}":
            depth -= 1
            if depth == 0:
                return i
        i += 1
    return -1


# ---------------------------------------------------------------------------
# Predicate evaluation
# ---------------------------------------------------------------------------


def _predicate_kv(item) -> tuple[str, object]:
    """A DSL predicate item is a single-key dict (`{key: value}`). Return
    (key, value). Raises ValueError on a malformed item."""
    if isinstance(item, dict):
        if len(item) != 1:
            raise ValueError(f"expected single-key dict, got {item!r}")
        k, v = next(iter(item.items()))
        return (k, v)
    raise ValueError(f"expected dict predicate, got {item!r}")


def predicate_supported(name: str) -> bool:
    return name in SUPPORTED_PREDICATES


def eval_preconditions(preconds: list, source_text: str, *, log) -> tuple[bool, list[str]]:
    """Evaluate file-level preconditions. Returns (all_passed, reasons)."""
    reasons: list[str] = []
    for item in preconds or []:
        try:
            k, v = _predicate_kv(item)
        except ValueError as e:
            log(f"[warn] malformed precondition: {e}")
            return (False, ["malformed-precondition"])
        if k == "chain.is_cosmos_sdk":
            # Already gated at workspace level. v should be true; if it is
            # explicitly false we bail (no cosmos pattern asks for false).
            if v is False:
                return (False, ["chain.is_cosmos_sdk: false"])
            continue
        if k == "contract.source_matches_regex":
            if not isinstance(v, str):
                log(f"[warn] non-string regex value for {k}: {v!r}")
                return (False, [f"{k}: non-string"])
            try:
                if not re.search(v, source_text):
                    return (False, [f"{k} did not match"])
            except re.error as e:
                log(f"[warn] bad regex in {k}: {e}")
                return (False, [f"{k}: bad regex"])
            continue
        # Unsupported precondition — log + fail closed for the file. We
        # err on the side of NOT firing on unsupported shapes (silent
        # over-fire would be worse).
        log(f"[skip predicate] unsupported precondition `{k}` — pattern will not fire on this workspace")
        return (False, [f"unsupported predicate {k}"])
    return (True, reasons)


def eval_function_match(match: list, fn: dict, source_text: str, *, log) -> bool:
    """Evaluate match predicates against a single Go function. Returns
    True iff every supported predicate passes; unsupported predicates are
    skipped (logged) and force a False return so we don't false-positive
    on partial evaluation."""
    if not match:
        return False
    body = fn["body"]
    name = fn["name"]
    for item in match:
        try:
            k, v = _predicate_kv(item)
        except ValueError as e:
            log(f"[warn] malformed match predicate: {e}")
            return False
        if k == "function.kind":
            if not isinstance(v, str) or v not in COSMOS_FUNCTION_KINDS:
                log(f"[skip predicate] unsupported function.kind `{v}` — pattern will not fire")
                return False
            # `cosmos_msg_handler` is a marker for detector-lint; we accept
            # the row's `function.name_matches` to do the actual filter.
            continue
        if k == "function.name_matches":
            if not isinstance(v, str):
                log(f"[warn] non-string regex value for {k}: {v!r}")
                return False
            try:
                if not re.search(v, name):
                    return False
            except re.error as e:
                log(f"[warn] bad regex in {k}: {e}")
                return False
            continue
        if k == "function.body_contains_regex":
            if not isinstance(v, str):
                log(f"[warn] non-string regex value for {k}: {v!r}")
                return False
            try:
                if not re.search(v, body):
                    return False
            except re.error as e:
                log(f"[warn] bad regex in {k}: {e}")
                return False
            continue
        if k == "function.body_not_contains_regex":
            if not isinstance(v, str):
                log(f"[warn] non-string regex value for {k}: {v!r}")
                return False
            try:
                if re.search(v, body):
                    return False
            except re.error as e:
                log(f"[warn] bad regex in {k}: {e}")
                return False
            continue
        if k == "function.not_in_skip_list":
            # We already pre-filter vendor/test/build dirs in
            # discover_go_files. Treat this as always-true.
            continue
        if k == "function.not_source_matches_regex":
            if not isinstance(v, str):
                log(f"[warn] non-string regex value for {k}: {v!r}")
                return False
            try:
                if re.search(v, source_text):
                    return False
            except re.error as e:
                log(f"[warn] bad regex in {k}: {e}")
                return False
            continue
        log(f"[skip predicate] unsupported match `{k}` — pattern will not fire on this function")
        return False
    return True


# ---------------------------------------------------------------------------
# Pattern loading
# ---------------------------------------------------------------------------


def load_cosmos_patterns(patterns_dir: Path, *, log) -> list[dict]:
    out: list[dict] = []
    if not patterns_dir.exists():
        log(f"[warn] patterns dir not found: {patterns_dir}")
        return out
    for yp in sorted(patterns_dir.glob("*.yaml")):
        try:
            text = yp.read_text(encoding="utf-8", errors="replace")
        except OSError as e:
            log(f"[warn] could not read {yp.name}: {e}")
            continue
        # Quick filter: we only care about rows that declare `backend: cosmos`.
        # Avoid parsing every pattern in the corpus.
        if not re.search(r"^\s*backend\s*:\s*cosmos\s*$", text, re.MULTILINE):
            continue
        try:
            spec = parse_dsl_yaml(text)
        except Exception as e:
            log(f"[warn] could not parse {yp.name}: {e}")
            continue
        if not isinstance(spec, dict) or "pattern" not in spec:
            continue
        if str(spec.get("backend", "")).strip() != "cosmos":
            continue
        spec["__source_yaml"] = str(yp)
        out.append(spec)
    return out


# ---------------------------------------------------------------------------
# Runner
# ---------------------------------------------------------------------------


def run(workspace: Path, *, only: str | None, patterns_dir: Path,
        out_path: Path | None, quiet: bool) -> int:
    log_lines: list[str] = []

    def log(msg: str) -> None:
        log_lines.append(msg)
        if not quiet:
            print(msg, file=sys.stderr)

    if not workspace.exists():
        print(f"[err] workspace not found: {workspace}", file=sys.stderr)
        return 2

    is_cosmos, gomod = is_cosmos_sdk_workspace(workspace)
    patterns = load_cosmos_patterns(patterns_dir, log=log)
    if only:
        patterns = [p for p in patterns if p.get("pattern") == only]
    go_files = discover_go_files(workspace)

    findings: list[dict] = []
    summary = {
        "tool": "cosmos-detector-runner",
        "tool_version": "wave2-1",
        "workspace": str(workspace),
        "is_cosmos_sdk_workspace": is_cosmos,
        "go_mod_evidence": gomod,
        "patterns_dir": str(patterns_dir),
        "patterns_considered": len(patterns),
        "go_files_scanned": 0,
        "findings_count": 0,
        "skipped_reason": None,
        "started_at": int(time.time()),
        "log_excerpt": [],
    }

    if not patterns:
        summary["skipped_reason"] = "no cosmos patterns present"
        log("[stage: cosmos-detect] SKIPPED — no DSL rows with `backend: cosmos`")
        _write_findings(out_path, summary, findings, workspace)
        return 0

    if not go_files:
        summary["skipped_reason"] = "no .go files in workspace"
        log("[stage: cosmos-detect] SKIPPED — no .go files in workspace")
        _write_findings(out_path, summary, findings, workspace)
        return 0

    if not is_cosmos:
        # We have go files but no cosmos-sdk go.mod. The precondition
        # `chain.is_cosmos_sdk` is required by every cosmos pattern (see
        # the evmos row). Skip with a clear log.
        summary["skipped_reason"] = "no cosmos-sdk go.mod found"
        log("[stage: cosmos-detect] SKIPPED — no go.mod under workspace mentions cosmos-sdk")
        _write_findings(out_path, summary, findings, workspace)
        return 0

    log(f"[stage: cosmos-detect] {len(patterns)} cosmos pattern(s), {len(go_files)} .go file(s), "
        f"per-file cap {_PER_FILE_TIMEOUT_S}s")
    summary["go_files_scanned"] = len(go_files)
    timed_out_files: list[dict] = []

    for go_path in go_files:
        try:
            source_text = go_path.read_text(encoding="utf-8", errors="replace")
        except OSError as e:
            log(f"[warn] could not read {go_path}: {e}")
            continue
        try:
            funcs = extract_go_functions(source_text)
        except Exception as e:
            log(f"[warn] func extract failed for {go_path}: {e}")
            continue
        # Bound this file's whole match pass. A catastrophic-backtracking regex on a
        # large file raises _MatchTimeout -> we record a TYPED skip (never a silent
        # skip, never a fabricated finding) and move on, so one file cannot hang the
        # scan. The outer scan timeout stays as a coarse backstop.
        _t0 = time.monotonic()
        try:
            with _time_limit(_PER_FILE_TIMEOUT_S):
                for spec in patterns:
                    preconds = spec.get("preconditions") or []
                    match = spec.get("match") or []
                    ok, _reasons = eval_preconditions(preconds, source_text, log=log)
                    if not ok:
                        continue
                    for fn in funcs:
                        if eval_function_match(match, fn, source_text, log=log):
                            findings.append({
                                "pattern": spec.get("pattern"),
                                "file": str(go_path),
                                "line": fn["line"],
                                "function": fn["name"],
                                "severity": str(spec.get("severity", "MEDIUM")).upper(),
                                "confidence": str(spec.get("confidence", "MEDIUM")).upper(),
                                "evidence_class": "scaffolded_unverified",
                                "backend": "cosmos",
                                "source_yaml": spec.get("__source_yaml"),
                                "help": spec.get("help") or spec.get("wiki_title") or "",
                            })
        except _MatchTimeout:
            rec = {"file": str(go_path), "bytes": len(source_text),
                   "elapsed_s": round(time.monotonic() - _t0, 1),
                   "reason": f"regex match exceeded {_PER_FILE_TIMEOUT_S}s cap "
                             "(likely catastrophic backtracking on a large/generated file)"}
            timed_out_files.append(rec)
            log(f"[warn] cosmos-detect TIMEOUT skip {go_path} "
                f"({rec['bytes']}b, >{_PER_FILE_TIMEOUT_S}s) - typed skip, not silent")
            continue

    if timed_out_files:
        summary["timed_out_files"] = timed_out_files
        summary["timed_out_file_count"] = len(timed_out_files)
    summary["findings_count"] = len(findings)
    summary["log_excerpt"] = log_lines[-50:]
    _write_findings(out_path, summary, findings, workspace)
    log(f"[stage: cosmos-detect] {len(findings)} finding(s)")
    return 0


def _write_findings(out_path: Path | None, summary: dict, findings: list[dict],
                    workspace: Path) -> None:
    if out_path is None:
        out_dir = workspace / ".auditooor"
        out_dir.mkdir(parents=True, exist_ok=True)
        out_path = out_dir / "cosmos_findings.json"
    else:
        out_path.parent.mkdir(parents=True, exist_ok=True)
    payload = {"summary": summary, "findings": findings}
    out_path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n",
                        encoding="utf-8")


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[1])
    ap.add_argument("workspace", type=Path)
    ap.add_argument("--only", help="Run only this pattern id")
    ap.add_argument("--patterns-dir", type=Path, default=DEFAULT_PATTERNS_DIR,
                    help="Where to look for DSL yaml rows (default: "
                         "reference/patterns.dsl)")
    ap.add_argument("--out", type=Path, default=None,
                    help="Findings JSON path (default: "
                         "<workspace>/.auditooor/cosmos_findings.json)")
    ap.add_argument("--quiet", action="store_true",
                    help="Suppress stderr log lines")
    args = ap.parse_args()
    return run(args.workspace.resolve(), only=args.only,
               patterns_dir=args.patterns_dir.resolve(),
               out_path=args.out.resolve() if args.out else None,
               quiet=args.quiet)


if __name__ == "__main__":
    sys.exit(main())
