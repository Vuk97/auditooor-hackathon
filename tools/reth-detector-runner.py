#!/usr/bin/env python3
"""reth-detector-runner.py — first executor for `backend: reth` DSL rows.

Wave 3 capability uplift (P1-1 burn-down, 2026-04-29). Until Wave 2 the
DSL had per-backend executors for `solidity`, `rust` (rust_wave1
tree-sitter), `circom`, `cosmos` (PR #485) and `anchor` (PR #486).
Execution-engine codebases shaped like reth — multi-crate Cargo
workspaces with a consensus-client crate and an EVM/execution-client
crate — had no live lane. Rows tagged `backend: reth` would only exist
as documentation markers (the `documentation_only de facto` failure mode
called out in `docs/KNOWN_LIMITATIONS.md` P1-1).

This script ships the FIRST `backend: reth` executor. Same posture as the
cosmos and anchor runners:

  - stdlib-only (no PyYAML, no `cargo`, no `syn`, no tree-sitter).
  - Self-skip on workspaces that don't look like reth (no `Cargo.toml`
    mentions `reth`, `alloy`, or `revm`).
  - Walks `*.rs` files, skipping `target/`, `tests/`, `benches/`.
  - Fail-closed on unsupported predicates: a row that asks for a
    predicate this v1 engine doesn't implement logs `[skip predicate]`
    and DOES NOT fire on the affected function. Silent over-fire would
    be worse than no-fire.
  - Emits `<workspace>/.auditooor/reth_findings.json` with
    `evidence_class: scaffolded_unverified` (Wave 1 vocabulary). Findings
    are leads, not proof; promotion to a higher evidence class is a
    downstream production-path / fixture step.
  - Always exits 0 (lead generator, not a gate). Exit 2 only on argv
    misuse / missing workspace.

Predicate vocabulary (v1 — six predicates, all opt-in):

  - function.kind: pub_fn | impl_fn | trait_method | function | any
        Region kind. `pub_fn` = top-level `pub fn` declaration.
        `impl_fn` = `fn` declared inside an `impl ... { ... }` block.
        `trait_method` = method declared inside a `trait ... { ... }`
        block (signatures with or without default body). `function` and
        `any` accept all three. Anything else logs `[skip predicate]`.
  - function.name_matches: <regex>
        Regex match against the function name (or struct name for
        trait/impl). Bad regex => fail-closed.
  - function.body_contains_regex: <regex>
        Regex match against the function body (text from the opening
        `{` of the body to the matching `}`). Strings, comments, and
        nested generic bounds are tolerated by the brace walker.
  - function.body_not_contains_regex: <regex>
        Negated body match.
  - crate.is_consensus_client: true | false
        HEURISTIC: the function lives in a Cargo crate whose package
        name (or path component) contains `consensus`, `engine`, or
        `derive`. Matches reth's `reth-consensus`, `reth-engine`, and
        `reth-evm-derive` style crates.
  - crate.is_execution_client: true | false
        HEURISTIC: the function lives in a Cargo crate whose package
        name (or path component) contains `evm`, `revm`, `exex`, or
        `payload`. Matches reth's `reth-evm`, `revm`, `reth-exex`, and
        `reth-payload-builder`-style crates.

Workspace discovery:
  A workspace is treated as reth-shaped iff at least one `Cargo.toml`
  under the workspace mentions `reth`, `alloy`, or `revm` as a dependency
  / package name. We search ALL `Cargo.toml` files (not just the root)
  so monorepos / vendored sub-crates work. Vendored / generated dirs
  (`target/`, `tests/`, `benches/`) are skipped to keep the walk cheap.

CLI:
    python3 tools/reth-detector-runner.py <workspace>
    python3 tools/reth-detector-runner.py <workspace> --only <pattern-id>
    python3 tools/reth-detector-runner.py <workspace> --patterns-dir <dir>
    python3 tools/reth-detector-runner.py <workspace> --out <findings.json>
    python3 tools/reth-detector-runner.py <workspace> --quiet

Wired into `audit-deep.sh` as Step 10 ("reth-backend DSL executor"). See
`docs/RETH_BACKEND.md` for predicate semantics, output schema, and the
list of vendored starter patterns.
"""
from __future__ import annotations

import argparse
import json
import re
import sys
import time
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
DEFAULT_PATTERNS_DIR = REPO / "reference" / "patterns.dsl"

# Directory parts we never descend into. Mirrors cosmos/anchor runners
# but adds reth-specific dirs (`benches`, `examples`, generated `target`).
SKIP_PARTS = {
    ".git",
    "node_modules",
    "vendor",
    "third_party",
    "third-party",
    "testdata",
    "tests",
    "test",
    "benches",
    "bench",
    "examples",
    "build",
    "dist",
    "out",
    "__pycache__",
    "target",
    ".auditooor",
    "scanners",
    "differential_fuzz",
}

SUPPORTED_PREDICATES = {
    # match (per-function)
    "function.kind",
    "function.name_matches",
    "function.body_contains_regex",
    "function.body_not_contains_regex",
    # match (per-crate, evaluated against the function's home crate)
    "crate.is_consensus_client",
    "crate.is_execution_client",
}

# function.kind tokens this engine understands.
RETH_FUNCTION_KINDS = {"pub_fn", "impl_fn", "trait_method", "function", "any"}

# Crate-name heuristics. Conservative tokens — we accept the lowest bar
# that still distinguishes reth's consensus vs execution split, so a DSL
# author can write a single token and have it match the typical reth /
# op-reth / base-reth crate naming.
CONSENSUS_CRATE_TOKENS = ("consensus", "engine", "derive")
EXECUTION_CRATE_TOKENS = ("evm", "revm", "exex", "payload")


# ---------------------------------------------------------------------------
# Tiny YAML subset parser — copied from cosmos-detector-runner.py so we
# don't introduce a cross-tool import. Same limits: top-level scalars
# plus ordered list bodies of single-key dicts.
# ---------------------------------------------------------------------------

def _strip_comment(line: str) -> str:
    in_single = False
    in_double = False
    out: list[str] = []
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
            n += 4
        else:
            break
    return n


def parse_dsl_yaml(text: str) -> dict:
    """Parse the small DSL YAML subset. Returns a dict; raises ValueError
    on shapes we cannot interpret."""
    raw_lines = text.splitlines()
    cleaned: list[tuple[int, str]] = []
    for i, ln in enumerate(raw_lines):
        stripped = _strip_comment(ln).rstrip()
        if stripped.strip() == "":
            continue
        cleaned.append((i, stripped))

    out: dict = {}
    idx = 0
    while idx < len(cleaned):
        _lineno, line = cleaned[idx]
        ind = _indent(line)
        if ind != 0:
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
            out[key] = _coerce(rest)
            idx += 1
            continue
        idx += 1
        block_items: list = []
        block_dict: dict = {}
        first_child_ind: int | None = None
        while idx < len(cleaned):
            _cl_lineno, cl_line = cleaned[idx]
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
                if ":" in item_body:
                    ik, _, iv = item_body.partition(":")
                    ik = ik.strip()
                    iv_raw = iv.strip()
                    if iv_raw == "":
                        idx += 1
                        nested_items: list = []
                        while idx < len(cleaned):
                            _n_lineno, n_line = cleaned[idx]
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
                if ":" in stripped:
                    sk, _, sv = stripped.partition(":")
                    block_dict[sk.strip()] = _coerce(sv.strip())
                idx += 1
        if block_items and not block_dict:
            out[key] = block_items
        elif block_dict and not block_items:
            out[key] = block_dict
        else:
            out[key] = block_items or block_dict or []
    return out


# ---------------------------------------------------------------------------
# Workspace discovery — "is this a reth-shaped Cargo workspace?"
# ---------------------------------------------------------------------------

# Regex hints — any of these in a Cargo.toml means "treat as reth-shaped".
# `reth` matches reth, op-reth, base-reth, reth-* crates. `alloy` and
# `revm` cover the typical execution-client dependency surface.
_CARGO_RETH_HINT_RE = re.compile(
    r"\b(reth|alloy|revm)(?:-[A-Za-z0-9_-]+)?\b"
)


def _relative_parts(path: Path, workspace: Path) -> list[str]:
    """Return the parts of `path` UNDER `workspace`, so we can apply
    SKIP_PARTS only to children of the audit workspace (not to absolute
    path components above it). Without this, a workspace whose absolute
    path happens to contain `tests/` or `target/` would always be
    self-skipped — which broke fixture discovery.
    """
    try:
        rel = path.resolve().relative_to(workspace.resolve())
    except ValueError:
        return list(path.parts)
    return list(rel.parts)


def is_reth_workspace(workspace: Path) -> tuple[bool, str | None]:
    """Returns (is_reth, evidence_path).

    A workspace is reth-shaped iff at least one `Cargo.toml` (anywhere
    under the workspace, excluding generated dirs) mentions `reth`,
    `alloy`, or `revm`. SKIP_PARTS is applied only to path components
    UNDER the workspace, not to absolute components above it.
    """
    if not workspace.is_dir():
        return (False, None)
    for cargo in workspace.rglob("Cargo.toml"):
        rel_parts = _relative_parts(cargo, workspace)
        # All parts EXCEPT the final filename — we never want to skip a
        # Cargo.toml because of its own basename.
        if any(part in SKIP_PARTS for part in rel_parts[:-1]):
            continue
        try:
            text = cargo.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        if _CARGO_RETH_HINT_RE.search(text):
            return (True, str(cargo.resolve()))
    return (False, None)


def discover_rust_files(workspace: Path) -> list[Path]:
    """All `*.rs` files under workspace, skipping target/tests/benches.

    SKIP_PARTS is applied only to path components UNDER the workspace.
    """
    out: list[Path] = []
    for p in workspace.rglob("*.rs"):
        rel_parts = _relative_parts(p, workspace)
        if any(part in SKIP_PARTS for part in rel_parts[:-1]):
            continue
        out.append(p.resolve())
    return sorted(out)


# Map a Rust file to the nearest enclosing crate (Cargo.toml ancestor).
# We cache crate name + classification so we don't re-read every file.

_CRATE_NAME_RE = re.compile(
    r'^\s*name\s*=\s*"([A-Za-z0-9_-]+)"', re.MULTILINE,
)


def crate_for_file(file_path: Path, workspace: Path,
                   cache: dict[Path, tuple[str, Path]] | None) -> tuple[str, Path | None]:
    """Walk up from file_path until we find a `Cargo.toml`. Return
    (crate_name, cargo_toml_path). crate_name falls back to the parent
    directory name when the Cargo.toml has no `[package] name`.

    `cache` is keyed by Cargo.toml path → (crate_name, cargo_toml_path).
    """
    if cache is None:
        cache = {}
    cur = file_path.parent
    workspace_resolved = workspace.resolve()
    while True:
        cargo = cur / "Cargo.toml"
        if cargo.is_file():
            cargo_resolved = cargo.resolve()
            cached = cache.get(cargo_resolved)
            if cached is not None:
                return cached
            try:
                text = cargo.read_text(encoding="utf-8", errors="replace")
            except OSError:
                text = ""
            m = _CRATE_NAME_RE.search(text)
            if m:
                name = m.group(1)
            else:
                # workspace-root Cargo.toml might be virtual — fall back
                # to the dir name so the heuristic still has a string.
                name = cur.name
            cache[cargo_resolved] = (name, cargo_resolved)
            return (name, cargo_resolved)
        if cur == cur.parent or cur.resolve() == workspace_resolved.parent:
            return (file_path.parent.name, None)
        cur = cur.parent


def _crate_path_tokens(crate_name: str, cargo_path: Path | None) -> list[str]:
    """Return lowercased name tokens we use for is_consensus / is_execution.

    Includes the crate's `name = "..."` value AND the path components of
    its Cargo.toml (so a workspace member at `crates/evm/foo/Cargo.toml`
    matches the `evm` token even if the package name is `foo`).
    """
    tokens: list[str] = []
    if crate_name:
        tokens.append(crate_name.lower())
    if cargo_path is not None:
        for part in cargo_path.parts:
            tokens.append(part.lower())
    return tokens


def crate_is_consensus_client(crate_name: str, cargo_path: Path | None) -> bool:
    tokens = _crate_path_tokens(crate_name, cargo_path)
    return any(any(tok in t for tok in CONSENSUS_CRATE_TOKENS) for t in tokens)


def crate_is_execution_client(crate_name: str, cargo_path: Path | None) -> bool:
    tokens = _crate_path_tokens(crate_name, cargo_path)
    return any(any(tok in t for tok in EXECUTION_CRATE_TOKENS) for t in tokens)


# ---------------------------------------------------------------------------
# Rust function/region extraction.
# ---------------------------------------------------------------------------
# We extract three kinds of regions:
#   - pub_fn      : top-level `pub fn` declarations (file-scope or in a
#                   non-impl/trait `mod` block).
#   - impl_fn     : `fn` declared inside `impl ... { ... }`.
#   - trait_method: `fn` declared inside `trait ... { ... }` (signatures,
#                   provided default bodies, OR signature-only methods).
#
# Body extraction uses a brace counter that respects:
#   - line comments  (`//`)
#   - block comments (`/* ... */`)
#   - string literals (`"..."`, escapes)
#   - char literals  (`'a'`)
#   - lifetime tokens (`'static`, `'info`) — distinguished from chars
#   - raw strings    (`r"..."`, `r#"..."#`)
# ---------------------------------------------------------------------------

_FN_HEADER_RE = re.compile(
    r"""
    (?P<pub>pub(?:\s*\([^)]+\))?\s+)?  # optional pub / pub(crate)
    (?:async\s+)?
    (?:unsafe\s+)?
    fn\s+
    (?P<name>[A-Za-z_][A-Za-z0-9_]*)
    \s*(?:<[^>{}]*>)?                  # optional generic <T: Foo>
    \s*\(                              # opening paren of params
    """,
    re.VERBOSE,
)


def _scan_matching_brace(source: str, open_idx: int) -> int:
    """Return index of `}` matching `source[open_idx]` (which must be
    `{`). Returns -1 if unmatched. Skips // line comments, /* block
    comments */, "double-quoted strings", 'char/lifetime' literals, and
    Rust raw strings r"..."/r#"..."#.
    """
    n = len(source)
    if open_idx < 0 or open_idx >= n or source[open_idx] != "{":
        return -1
    depth = 0
    i = open_idx
    while i < n:
        ch = source[i]
        nxt = source[i + 1] if i + 1 < n else ""
        # // line comment
        if ch == "/" and nxt == "/":
            nl = source.find("\n", i + 2)
            if nl < 0:
                return -1
            i = nl + 1
            continue
        # /* block comment */ (Rust block comments nest, but we handle
        # only the non-nested case — nested block comments inside fn
        # bodies are vanishingly rare in reth-shaped code).
        if ch == "/" and nxt == "*":
            end = source.find("*/", i + 2)
            if end < 0:
                return -1
            i = end + 2
            continue
        # raw string r"..." or r#"..."#  (b"" / br#""# not handled
        # specially; the inner brace counter will see them and recurse,
        # which is wrong but extremely rare in fn bodies — accept the FN).
        if ch == "r" and i + 1 < n and source[i + 1] in ("\"", "#"):
            j = i + 1
            hashes = 0
            while j < n and source[j] == "#":
                hashes += 1
                j += 1
            if j < n and source[j] == "\"":
                # find closing "<hashes># sequence
                close = "\"" + ("#" * hashes)
                end = source.find(close, j + 1)
                if end < 0:
                    return -1
                i = end + len(close)
                continue
        # double-quoted string (with backslash escapes)
        if ch == "\"":
            j = i + 1
            while j < n:
                if source[j] == "\\" and j + 1 < n:
                    j += 2
                    continue
                if source[j] == "\"":
                    break
                j += 1
            i = j + 1
            continue
        # single quote: lifetime vs char literal
        if ch == "'":
            after = source[i + 1:i + 3]
            if (len(after) >= 1 and (after[0].isalpha() or after[0] == "_")
                    and not (len(after) >= 2 and after[1] == "'")):
                # lifetime token like 'a, 'static, 'info — not a string
                i += 1
                continue
            # char literal: scan to the next un-escaped `'`
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


def _line_of(source: str, idx: int) -> int:
    return source.count("\n", 0, idx) + 1


# Detect impl / trait blocks so we can classify fn regions inside them.
_IMPL_BLOCK_RE = re.compile(
    r"^\s*(?:unsafe\s+)?impl\b[^{]*\{",
    re.MULTILINE,
)
_TRAIT_BLOCK_RE = re.compile(
    r"^\s*(?:pub(?:\s*\([^)]+\))?\s+)?(?:unsafe\s+)?trait\s+[A-Za-z_][A-Za-z0-9_]*[^{]*\{",
    re.MULTILINE,
)


def _block_ranges(source: str, header_re: re.Pattern[str]) -> list[tuple[int, int]]:
    """Return list of (open_brace_idx, close_brace_idx) for every
    block whose header matches `header_re` (anchored at start-of-line).
    """
    ranges: list[tuple[int, int]] = []
    for m in header_re.finditer(source):
        open_idx = source.rfind("{", m.start(), m.end())
        if open_idx < 0:
            # The header regex captures up through the `{`; its end-1
            # should be the brace.
            open_idx = m.end() - 1
        if open_idx < 0 or source[open_idx] != "{":
            # Walk forward to the next `{` if the header didn't end on one.
            open_idx = source.find("{", m.start())
            if open_idx < 0:
                continue
        close_idx = _scan_matching_brace(source, open_idx)
        if close_idx < 0:
            continue
        ranges.append((open_idx, close_idx))
    return ranges


def extract_rust_regions(source: str) -> list[dict]:
    """Extract function-shaped regions with their classification.

    Each region is a dict with:
      - name: function identifier
      - line: 1-based line of the `fn` keyword
      - body: text from the opening `{` of the body through matching
              `}`. For trait methods that have no body (signature ends
              in `;`), body is the empty string and the region is still
              emitted so DSL rows that match on the name can fire.
      - kind: "pub_fn" | "impl_fn" | "trait_method"
      - has_pub: bool — the `pub` keyword preceded `fn`
      - signature: text from the start of the `fn` keyword through the
                   end of the signature (either `{` or `;`)
    """
    impl_ranges = _block_ranges(source, _IMPL_BLOCK_RE)
    trait_ranges = _block_ranges(source, _TRAIT_BLOCK_RE)
    regions: list[dict] = []
    for m in _FN_HEADER_RE.finditer(source):
        name = m.group("name")
        header_start = m.start()
        # Walk through param list: find the `(` we just consumed and
        # match its `)` (including nested parens for `(impl Trait)` etc.
        # plus `<>` generics that don't contain unbalanced parens).
        i = m.end()
        depth = 1
        n = len(source)
        while i < n and depth > 0:
            ch = source[i]
            if ch == "(":
                depth += 1
            elif ch == ")":
                depth -= 1
            i += 1
        # Now skip optional return type / where clause until we hit `{`
        # (body) or `;` (signature-only — trait method).
        body_open = -1
        sig_terminator = -1
        # Track bracket/angle depth so a return type like `[u8; 32]` does
        # not look like a trait-method semicolon. Const generics can also
        # contain `{ N }`; avoid treating those braces as the function body.
        angle = 0
        square = 0
        paren = 0
        const_brace = 0
        j = i
        while j < n:
            ch = source[j]
            nxt = source[j + 1] if j + 1 < n else ""
            # Skip line / block comments + strings, same as
            # _scan_matching_brace.
            if ch == "/" and nxt == "/":
                nl = source.find("\n", j + 2)
                if nl < 0:
                    break
                j = nl + 1
                continue
            if ch == "/" and nxt == "*":
                end = source.find("*/", j + 2)
                if end < 0:
                    break
                j = end + 2
                continue
            if ch == "\"":
                k = j + 1
                while k < n:
                    if source[k] == "\\" and k + 1 < n:
                        k += 2
                        continue
                    if source[k] == "\"":
                        break
                    k += 1
                j = k + 1
                continue
            if ch == "<":
                angle += 1
                j += 1
                continue
            if ch == ">":
                if angle > 0:
                    angle -= 1
                j += 1
                continue
            if ch == "[":
                square += 1
                j += 1
                continue
            if ch == "]":
                if square > 0:
                    square -= 1
                j += 1
                continue
            if ch == "(":
                paren += 1
                j += 1
                continue
            if ch == ")":
                if paren > 0:
                    paren -= 1
                j += 1
                continue
            if ch == "{" and angle > 0:
                const_brace += 1
                j += 1
                continue
            if ch == "}" and const_brace > 0:
                const_brace -= 1
                j += 1
                continue
            if angle == 0 and square == 0 and paren == 0 and const_brace == 0:
                if ch == "{":
                    body_open = j
                    break
                if ch == ";":
                    sig_terminator = j
                    break
            j += 1
        line = _line_of(source, header_start)
        # Determine kind by enclosing block.
        in_impl = any(open_b < header_start < close_b for (open_b, close_b) in impl_ranges)
        in_trait = any(open_b < header_start < close_b for (open_b, close_b) in trait_ranges)
        has_pub = m.group("pub") is not None
        if in_trait:
            kind = "trait_method"
        elif in_impl:
            kind = "impl_fn"
        elif has_pub:
            kind = "pub_fn"
        else:
            # private free fn — we keep it under "impl_fn" semantics
            # would be wrong; we omit private free fns entirely. The
            # six-predicate vocabulary is opt-in to public surfaces.
            continue
        if body_open >= 0:
            close_b = _scan_matching_brace(source, body_open)
            if close_b < 0:
                continue
            body = source[body_open:close_b + 1]
            sig = source[header_start:body_open]
        elif sig_terminator >= 0:
            body = ""
            sig = source[header_start:sig_terminator]
        else:
            continue
        regions.append({
            "name": name,
            "line": line,
            "body": body,
            "kind": kind,
            "has_pub": has_pub,
            "signature": sig,
        })
    return regions


# ---------------------------------------------------------------------------
# Predicate evaluation.
# ---------------------------------------------------------------------------


def _predicate_kv(item) -> tuple[str, object]:
    if isinstance(item, dict):
        if len(item) != 1:
            raise ValueError(f"expected single-key dict, got {item!r}")
        k, v = next(iter(item.items()))
        return (k, v)
    raise ValueError(f"expected dict predicate, got {item!r}")


def predicate_supported(name: str) -> bool:
    return name in SUPPORTED_PREDICATES


def _bool_token(v: object) -> bool | None:
    if isinstance(v, bool):
        return v
    if isinstance(v, str):
        s = v.strip().lower()
        if s in ("true", "yes", "1"):
            return True
        if s in ("false", "no", "0"):
            return False
    return None


def _strip_rust_comments(source: str) -> str:
    """Remove Rust // and /* */ comments before text predicates run.

    The runner is intentionally regex-grade, but comments should not be
    executable evidence. Keeping strings intact preserves patterns that match
    literal error names or opcode markers embedded in code.
    """
    out: list[str] = []
    i = 0
    n = len(source)
    while i < n:
        ch = source[i]
        nxt = source[i + 1] if i + 1 < n else ""
        if ch == "/" and nxt == "/":
            nl = source.find("\n", i + 2)
            if nl < 0:
                break
            out.append("\n")
            i = nl + 1
            continue
        if ch == "/" and nxt == "*":
            end = source.find("*/", i + 2)
            if end < 0:
                break
            out.append("\n" * source.count("\n", i, end + 2))
            i = end + 2
            continue
        out.append(ch)
        i += 1
    return "".join(out)


def eval_function_match(match: list, region: dict, *,
                         crate_consensus: bool, crate_execution: bool,
                         log) -> bool:
    """Evaluate match predicates against a region. AND semantics — every
    predicate must pass. Unsupported predicates fail closed AND log
    `[skip predicate]` exactly once per call.
    """
    if not match:
        return False
    body = _strip_rust_comments(region["body"])
    name = region["name"]
    kind = region["kind"]
    for item in match:
        try:
            k, v = _predicate_kv(item)
        except ValueError as e:
            log(f"[warn] malformed match predicate: {e}")
            return False
        if k == "function.kind":
            if not isinstance(v, str):
                log(f"[skip predicate] non-string function.kind value: {v!r}")
                return False
            if v not in RETH_FUNCTION_KINDS:
                log(f"[skip predicate] unsupported function.kind `{v}` — "
                    f"reth runner accepts {sorted(RETH_FUNCTION_KINDS)}")
                return False
            if v not in ("any", "function") and kind != v:
                return False
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
        if k == "crate.is_consensus_client":
            want = _bool_token(v)
            if want is None:
                log(f"[warn] non-bool value for {k}: {v!r}")
                return False
            if crate_consensus != want:
                return False
            continue
        if k == "crate.is_execution_client":
            want = _bool_token(v)
            if want is None:
                log(f"[warn] non-bool value for {k}: {v!r}")
                return False
            if crate_execution != want:
                return False
            continue
        log(f"[skip predicate] unsupported match `{k}` — pattern will not fire")
        return False
    return True


# ---------------------------------------------------------------------------
# Pattern loading.
# ---------------------------------------------------------------------------


def load_reth_patterns(patterns_dir: Path, *, log) -> list[dict]:
    """Load every DSL row whose `backend:` is `reth`.

    Searches the patterns dir RECURSIVELY (via `rglob`) so reth patterns
    can live in a sub-folder like `r78_reth_chain/` without the top-level
    flat layout becoming unwieldy.
    """
    out: list[dict] = []
    if not patterns_dir.exists():
        log(f"[warn] patterns dir not found: {patterns_dir}")
        return out
    for yp in sorted(patterns_dir.rglob("*.yaml")):
        # Skip `_held` review-staging dirs (DSL convention).
        if any(part == "_held" for part in yp.parts):
            continue
        try:
            text = yp.read_text(encoding="utf-8", errors="replace")
        except OSError as e:
            log(f"[warn] could not read {yp.name}: {e}")
            continue
        # Quick filter: only parse rows that declare `backend: reth`.
        if not re.search(r"^\s*backend\s*:\s*reth\s*$", text, re.MULTILINE):
            continue
        try:
            spec = parse_dsl_yaml(text)
        except Exception as e:
            log(f"[warn] could not parse {yp.name}: {e}")
            continue
        if not isinstance(spec, dict) or "pattern" not in spec:
            continue
        if str(spec.get("backend", "")).strip() != "reth":
            continue
        spec["__source_yaml"] = str(yp)
        out.append(spec)
    return out


# ---------------------------------------------------------------------------
# Runner.
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

    is_reth, evidence_cargo = is_reth_workspace(workspace)
    patterns = load_reth_patterns(patterns_dir, log=log)
    if only:
        patterns = [p for p in patterns if p.get("pattern") == only]
    rust_files = discover_rust_files(workspace) if is_reth else []

    findings: list[dict] = []
    summary = {
        "tool": "reth-detector-runner",
        "tool_version": "wave3-1",
        "workspace": str(workspace),
        "is_reth_workspace": is_reth,
        "cargo_evidence": evidence_cargo,
        "patterns_dir": str(patterns_dir),
        "patterns_considered": len(patterns),
        "rust_files_scanned": 0,
        "findings_count": 0,
        "skipped_reason": None,
        "started_at": int(time.time()),
        "log_excerpt": [],
    }

    if not patterns:
        summary["skipped_reason"] = "no reth patterns present"
        log("[stage: reth-detect] SKIPPED — no DSL rows with `backend: reth`")
        _write_findings(out_path, summary, findings, workspace)
        return 0

    if not is_reth:
        summary["skipped_reason"] = "no reth-shaped Cargo workspace"
        log("[stage: reth-detect] SKIPPED — no Cargo.toml under workspace mentions "
            "reth/alloy/revm")
        _write_findings(out_path, summary, findings, workspace)
        return 0

    if not rust_files:
        summary["skipped_reason"] = "no .rs files in workspace"
        log("[stage: reth-detect] SKIPPED — no .rs files under workspace")
        _write_findings(out_path, summary, findings, workspace)
        return 0

    log(f"[stage: reth-detect] {len(patterns)} reth pattern(s), "
        f"{len(rust_files)} .rs file(s)")
    summary["rust_files_scanned"] = len(rust_files)

    crate_cache: dict[Path, tuple[str, Path]] = {}
    crate_classify_cache: dict[Path | None, tuple[bool, bool]] = {}
    for rs_path in rust_files:
        try:
            source_text = rs_path.read_text(encoding="utf-8", errors="replace")
        except OSError as e:
            log(f"[warn] could not read {rs_path}: {e}")
            continue
        try:
            regions = extract_rust_regions(source_text)
        except Exception as e:
            log(f"[warn] region extract failed for {rs_path}: {e}")
            continue
        crate_name, cargo_path = crate_for_file(rs_path, workspace, crate_cache)
        cls = crate_classify_cache.get(cargo_path)
        if cls is None:
            cls = (
                crate_is_consensus_client(crate_name, cargo_path),
                crate_is_execution_client(crate_name, cargo_path),
            )
            crate_classify_cache[cargo_path] = cls
        is_consensus, is_execution = cls
        for spec in patterns:
            match = spec.get("match") or []
            for region in regions:
                if eval_function_match(match, region,
                                       crate_consensus=is_consensus,
                                       crate_execution=is_execution,
                                       log=log):
                    findings.append({
                        "pattern": spec.get("pattern"),
                        "file": str(rs_path),
                        "line": region["line"],
                        "function": region["name"],
                        "region_kind": region["kind"],
                        "crate": crate_name,
                        "crate_is_consensus_client": is_consensus,
                        "crate_is_execution_client": is_execution,
                        "severity": str(spec.get("severity", "MEDIUM")).upper(),
                        "confidence": str(spec.get("confidence", "MEDIUM")).upper(),
                        "evidence_class": "scaffolded_unverified",
                        "backend": "reth",
                        "source_yaml": spec.get("__source_yaml"),
                        "help": spec.get("help") or spec.get("wiki_title") or "",
                    })

    summary["findings_count"] = len(findings)
    summary["log_excerpt"] = log_lines[-50:]
    _write_findings(out_path, summary, findings, workspace)
    log(f"[stage: reth-detect] {len(findings)} finding(s)")
    return 0


def _write_findings(out_path: Path | None, summary: dict, findings: list[dict],
                    workspace: Path) -> None:
    if out_path is None:
        out_dir = workspace / ".auditooor"
        out_dir.mkdir(parents=True, exist_ok=True)
        out_path = out_dir / "reth_findings.json"
    else:
        out_path.parent.mkdir(parents=True, exist_ok=True)
    payload = {"summary": summary, "findings": findings}
    out_path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n",
                        encoding="utf-8")


def main() -> int:
    ap = argparse.ArgumentParser(
        description=("First executor for `backend: reth` DSL rows. "
                     "Stdlib-only; emits scaffolded-unverified findings "
                     "for reth/op-reth/base-reth Cargo workspaces."),
    )
    ap.add_argument("workspace", type=Path)
    ap.add_argument("--only", help="Run only this pattern id")
    ap.add_argument("--patterns-dir", type=Path, default=DEFAULT_PATTERNS_DIR,
                    help="DSL yaml directory (default: reference/patterns.dsl)")
    ap.add_argument("--out", type=Path, default=None,
                    help="Findings JSON path (default: "
                         "<workspace>/.auditooor/reth_findings.json)")
    ap.add_argument("--quiet", action="store_true",
                    help="Suppress stderr log lines")
    args = ap.parse_args()
    return run(args.workspace.resolve(), only=args.only,
               patterns_dir=args.patterns_dir.resolve(),
               out_path=args.out.resolve() if args.out else None,
               quiet=args.quiet)


if __name__ == "__main__":
    sys.exit(main())
