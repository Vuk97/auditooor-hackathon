#!/usr/bin/env python3
"""anchor-detector-runner.py — first per-backend executor for `backend: anchor`
DSL rows.

P1-1 burn-down (Wave 2 capability uplift, 2026-04-29): until today the only
per-backend engine that actually executed DSL rows was `solidity` (via
`tools/ast-engine.py` + Slither IR) and the partial `rust_wave1` tree-sitter
lane. Rows declaring `backend: anchor` were lint-clean but had no executor —
they only existed as documentation markers (see KNOWN_LIMITATIONS P1-1 stop
condition). This tool closes that gap with a stdlib-only, regex-driven
runner specialised for the Anchor (Solana) program shape.

Scope and discipline:
  - Stdlib-only. No `cargo`, no `anchor`, no `syn`/`tree-sitter`. We treat
    Anchor source as Rust + macro attributes and surface findings at the
    Slither-callgraph altitude — same posture as `tools/rust-source-graph.py`.
  - Conservative: every heuristic is regex/text and is documented inline
    with an explicit `HEURISTIC` comment. False positives are acceptable
    because every emitted finding carries
    `evidence_class: scaffolded_unverified`. Operators/PoC scaffolders
    must promote a finding before it counts as a triage outcome.
  - Confidence ceiling: `scaffolded-unverified`. The tool never emits
    "high-confidence" findings; promotion happens elsewhere.
  - Output: `<workspace>/.auditooor/anchor_findings.json`.

Predicate vocabulary (Anchor-aware):
  - function.name_matches: <regex>
        Match against the union of:
          (a) `pub fn <name>` declarations inside `#[program]` mods
              (Anchor instruction handlers), AND
          (b) `#[derive(Accounts)]` struct names (the per-instruction
              accounts struct that ships next to the handler).
        We deliberately match BOTH sets because real Anchor patterns
        often anchor on either the handler name (`withdraw_fees`) or the
        accounts struct name (`WithdrawFees`). The union strategy is
        documented in HEURISTIC-NAME-UNION below.
  - function.body_contains_regex: <regex>
        Substring/regex match anywhere inside the function body. The
        "function body" for an Anchor handler is the textual range from
        the opening `{` of the `pub fn` to the matching closing `}`. For
        an `#[derive(Accounts)]` struct, the body is the struct
        declaration through its closing brace, INCLUDING the field-level
        `#[account(...)]` attributes — that is what makes shapes like
        "missing `#[account(mut)]` on pool_state" detectable.
  - function.body_not_contains_regex: <regex>
        Negated form of body_contains_regex. The whole match must fail
        for the predicate to pass (i.e. "this token is absent").
  - function.has_anchor_derive: true|false
        HEURISTIC: the function/struct is preceded by a
        `#[derive(...Accounts...)]` attribute within 6 lines and no
        intervening item declaration.
  - function.is_anchor_handler: true|false
        HEURISTIC: the function is a `pub fn` declared inside a Rust
        `mod <name> { ... }` whose mod attribute set contains
        `#[program]`. We detect the enclosing `#[program] pub mod ...`
        by walking backwards until we leave the file or the mod's
        opening brace; nesting heuristics are deliberately shallow.
  - function.not_in_skip_list: true (always passes; reserved for parity
        with the Solidity backend which has a project-specific skip
        registry).
  - function.not_source_matches_regex: <regex>
        Negated source-path / contents check. Used to drop fixtures and
        mocks (`tests`, `fixtures`, `mock`).

Workspace layout discovery (matches rust-source-graph.py):
  1. `<workspace>/programs/<crate>/src/**.rs`   — canonical Anchor.
  2. `<workspace>/contracts/<crate>/src/**.rs`  — fallback for projects
     that vendor an Anchor program inside a Soroban-style tree.

CLI:
  tools/anchor-detector-runner.py --workspace <path> [--out <path>]
                                  [--patterns <dsl_dir>]
                                  [--print-json]

Exit codes:
  0  scan completed (regardless of whether any findings emitted)
  2  invalid CLI arguments / missing workspace
"""
from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Tuple


SCHEMA_VERSION = "auditooor.anchor_findings.v1"
SKIP_DIR_PARTS = {"target", "node_modules", ".git", "build", "out", ".auditooor"}

# Default DSL pattern directory (relative to repo root). Overridable via
# --patterns.
DEFAULT_PATTERNS_DIR = Path(__file__).resolve().parent.parent / "reference" / "patterns.dsl"


# ---------------------------------------------------------------------------
# Workspace discovery — the brief mandates programs/<crate>/src primary,
# contracts/<crate>/src fallback. We do NOT walk the entire workspace; that
# is rust-source-graph.py's job.
# ---------------------------------------------------------------------------

def _skip_path(path: Path) -> bool:
    return any(part in SKIP_DIR_PARTS for part in path.parts)


def _rs_files_in(root: Path) -> List[Path]:
    if not root.exists() or not root.is_dir():
        return []
    out: List[Path] = []
    for p in root.rglob("*.rs"):
        if not p.is_file():
            continue
        if _skip_path(p):
            continue
        out.append(p)
    return sorted(out)


def discover_anchor_files(workspace: Path) -> List[Path]:
    """Return ordered list of Rust files to scan for Anchor patterns.

    Primary lane: `programs/<crate>/src/**.rs`.
    Fallback:     `contracts/<crate>/src/**.rs` — only if `programs/`
                  doesn't exist or contains no `.rs` files.

    The brief explicitly says "Missing programs/ dir → skip cleanly", so
    a workspace with neither programs/ nor contracts/ returns []. The
    runner emits an empty findings list in that case.
    """
    files: List[Path] = []
    programs_dir = workspace / "programs"
    if programs_dir.is_dir():
        for child in sorted(programs_dir.iterdir()):
            if child.is_dir() and not _skip_path(child):
                files.extend(_rs_files_in(child / "src"))
    if files:
        return files
    contracts_dir = workspace / "contracts"
    if contracts_dir.is_dir():
        for child in sorted(contracts_dir.iterdir()):
            if child.is_dir() and not _skip_path(child):
                files.extend(_rs_files_in(child / "src"))
    return files


# ---------------------------------------------------------------------------
# Anchor source structure — we extract three kinds of "function-shaped"
# regions from each file:
#   (a) Anchor instruction handlers:
#         `#[program] pub mod <name> { pub fn <handler>(...) -> Result<...> { ... } ... }`
#   (b) Anchor accounts structs:
#         `#[derive(Accounts)] pub struct <Name><'info> { ... }`
#   (c) Top-level `pub fn` (non-handler, kept as a fallback so legacy
#         non-`#[program]`-wrapped Anchor code still surfaces).
#
# For each region we capture: file, line, name, kind, body_text. Body
# text is the EXACT range we evaluate body_contains_regex /
# body_not_contains_regex against.
# ---------------------------------------------------------------------------

# HEURISTIC: `#[derive(Accounts)]` recognition. Anchor's derive macro is
# conventionally `#[derive(Accounts)]`; some projects add extra derives
# (`#[derive(Accounts, Clone)]`). We accept any derive list that contains
# the literal `Accounts` token.
_DERIVE_ACCOUNTS_RE = re.compile(r"#\[\s*derive\s*\(([^)]*)\)\s*\]")
_DERIVE_HAS_ACCOUNTS = re.compile(r"\bAccounts\b")

# HEURISTIC: `#[program]` mod. Anchor handlers live inside
# `#[program] pub mod <name> { ... }`. We allow the attribute to be on
# its own line above the mod, and any `pub`/`pub(crate)` visibility.
_PROGRAM_ATTR_RE = re.compile(r"#\[\s*program\s*\]")
_MOD_OPEN_RE = re.compile(
    r"^\s*pub(?:\s*\([^)]+\))?\s+mod\s+([A-Za-z_][A-Za-z0-9_]*)\s*\{"
)

# HEURISTIC: pub struct declaration line. We require `pub struct` so
# private helpers don't trigger; lifetime/generic params are tolerated.
# MULTILINE so `^` matches at every line boundary inside finditer().
_PUB_STRUCT_RE = re.compile(
    r"^\s*pub\s+struct\s+([A-Za-z_][A-Za-z0-9_]*)\s*(?:<[^>]*>)?\s*\{",
    re.MULTILINE,
)

# HEURISTIC: `pub fn` declaration. We deliberately do not match `fn` (no
# visibility) — Anchor handlers are always `pub`. `pub(crate)` is also
# accepted because some projects re-wrap handlers. MULTILINE so the
# leading `^\s*` anchors at every line.
_PUB_FN_RE = re.compile(
    r"^\s*pub(?:\s*\([^)]+\))?\s+(?:async\s+)?(?:unsafe\s+)?fn\s+"
    r"([A-Za-z_][A-Za-z0-9_]*)\s*(?:<[^>]*>)?\s*\(",
    re.MULTILINE,
)


# ---------------------------------------------------------------------------
# Brace-balanced body extraction. Stdlib-only — we do NOT use a real
# parser. The walker treats `{` and `}` outside string/char/line-comment
# context as the only delimiters that bump depth. This is enough for the
# Anchor shapes we target; a real parser is intentionally out of scope.
# ---------------------------------------------------------------------------

def _find_matching_brace(text: str, open_idx: int) -> int:
    """Return the index of the `}` matching `text[open_idx]` (which must
    be `{`). Returns len(text) if unmatched (caller should treat that as
    "rest of file"). Skips `{` / `}` inside line comments, block
    comments, string literals, and char literals — same caveats as
    rust-source-graph.py's heuristics.
    """
    assert text[open_idx] == "{", "expected `{` at open_idx"
    depth = 0
    i = open_idx
    n = len(text)
    in_line_comment = False
    in_block_comment = False
    in_string = False
    string_char = ""  # '"' for strings, "'" for char literals
    while i < n:
        ch = text[i]
        nxt = text[i + 1] if i + 1 < n else ""
        if in_line_comment:
            if ch == "\n":
                in_line_comment = False
            i += 1
            continue
        if in_block_comment:
            if ch == "*" and nxt == "/":
                in_block_comment = False
                i += 2
                continue
            i += 1
            continue
        if in_string:
            if ch == "\\":
                i += 2
                continue
            if ch == string_char:
                in_string = False
                string_char = ""
            i += 1
            continue
        # Not in any escape state.
        if ch == "/" and nxt == "/":
            in_line_comment = True
            i += 2
            continue
        if ch == "/" and nxt == "*":
            in_block_comment = True
            i += 2
            continue
        if ch == '"':
            in_string = True
            string_char = '"'
            i += 1
            continue
        if ch == "'":
            # Raw lifetime token (e.g. `'info`) vs char literal. Heuristic:
            # if the next char is a letter/underscore and the char after
            # that is NOT a `'`, treat as a lifetime — do not enter string
            # mode.
            after = text[i + 1:i + 3]
            if (len(after) >= 1 and (after[0].isalpha() or after[0] == "_")
                    and not (len(after) >= 2 and after[1] == "'")):
                i += 1
                continue
            in_string = True
            string_char = "'"
            i += 1
            continue
        if ch == "{":
            depth += 1
        elif ch == "}":
            depth -= 1
            if depth == 0:
                return i
        i += 1
    return n


def _line_of(text: str, idx: int) -> int:
    """1-based line number of byte offset `idx` in `text`."""
    return text.count("\n", 0, idx) + 1


# ---------------------------------------------------------------------------
# Region extraction.
# ---------------------------------------------------------------------------

class Region:
    """An Anchor-relevant function-shaped region.

    Attributes:
      kind: 'handler' (pub fn inside #[program] mod), 'accounts_struct'
            (#[derive(Accounts)] struct), or 'pub_fn' (top-level pub fn,
            no #[program] enclosure).
      name: handler / struct / fn name.
      file: relative path string.
      line: 1-based line of the declaration.
      body: textual body, INCLUDING attributes preceding fields for
            accounts_struct (so `#[account(mut)]` is searchable). For
            handlers / pub_fn the body is from the `{` after the
            signature through the matching `}`.
      attrs: list of attribute names declared immediately above the
             region. Includes `program` for handlers and `derive` for
             accounts structs.
      preceded_by_accounts_derive: True iff a `#[derive(... Accounts ...)]`
             attribute sits in the 6 lines above the declaration with
             no other item declaration in between (HEURISTIC: matches
             AGENTS.md "shallow-window attribute binding" approach).
      inside_program_mod: True iff the region's textual offset sits
             between the open `{` of a `pub mod` whose attribute set
             contains `#[program]` and that mod's matching `}`.
    """

    __slots__ = (
        "kind", "name", "file", "line",
        "body", "attrs",
        "preceded_by_accounts_derive", "inside_program_mod",
    )

    def __init__(self, kind: str, name: str, file: str, line: int,
                 body: str, attrs: List[str],
                 preceded_by_accounts_derive: bool,
                 inside_program_mod: bool) -> None:
        self.kind = kind
        self.name = name
        self.file = file
        self.line = line
        self.body = body
        self.attrs = attrs
        self.preceded_by_accounts_derive = preceded_by_accounts_derive
        self.inside_program_mod = inside_program_mod


def _attrs_above(text: str, item_offset: int, line_window: int = 6) -> List[str]:
    """Return attribute names (e.g. 'program', 'derive', 'account') that
    appear in the `line_window` lines immediately above `item_offset`,
    stopping at the first non-blank, non-attribute, non-comment line.
    """
    # Walk backwards line-by-line.
    start = text.rfind("\n", 0, item_offset)
    end = item_offset
    if start < 0:
        return []
    lines_back: List[str] = []
    cursor = start
    for _ in range(line_window * 2):
        prev = text.rfind("\n", 0, cursor)
        line = text[prev + 1:cursor] if prev >= 0 else text[:cursor]
        lines_back.append(line)
        if prev < 0:
            break
        cursor = prev
    attrs: List[str] = []
    seen_blank_and_non_attr = False
    for raw in lines_back[: line_window * 2]:
        line = raw.strip()
        if line == "":
            # Blanks between attribute clusters are tolerated.
            continue
        if line.startswith("#["):
            m = re.match(r"#\[\s*([A-Za-z_][A-Za-z0-9_:]*)", line)
            if m:
                attrs.append(m.group(1))
            continue
        if line.startswith("//") or line.startswith("/*"):
            continue
        # Hit a non-attribute, non-comment line — stop walking up.
        seen_blank_and_non_attr = True
        break
    return attrs


def _has_accounts_derive_above(text: str, item_offset: int) -> bool:
    """Look for `#[derive(... Accounts ...)]` directly above the item."""
    # Search the previous up to 8 lines for a derive line; treat any
    # intervening item declaration as a barrier.
    cursor = item_offset
    for _ in range(8):
        prev = text.rfind("\n", 0, cursor - 1)
        line = text[prev + 1:cursor] if prev >= 0 else text[:cursor]
        cursor = prev if prev >= 0 else 0
        s = line.strip()
        if s == "":
            continue
        if s.startswith("//") or s.startswith("/*"):
            continue
        if s.startswith("#["):
            m = _DERIVE_ACCOUNTS_RE.search(line)
            if m and _DERIVE_HAS_ACCOUNTS.search(m.group(1)):
                return True
            # Other attribute — keep walking; attribute clusters allowed.
            continue
        # Any non-attribute/comment line is a barrier.
        return False
        if cursor <= 0:
            break
    return False


def _program_mod_ranges(text: str) -> List[Tuple[int, int]]:
    """Return list of `(open_brace_offset, close_brace_offset)` for every
    `#[program] pub mod ... { ... }` in this file. Multiple program mods
    are rare but possible (test crates).
    """
    ranges: List[Tuple[int, int]] = []
    for m in re.finditer(r"^\s*pub(?:\s*\([^)]+\))?\s+mod\s+[A-Za-z_][A-Za-z0-9_]*\s*\{",
                         text, re.M):
        open_brace = text.find("{", m.start())
        if open_brace < 0:
            continue
        # Walk attributes above this mod; require `#[program]` to be present.
        attrs = _attrs_above(text, m.start())
        if "program" not in attrs:
            continue
        close_brace = _find_matching_brace(text, open_brace)
        ranges.append((open_brace, close_brace))
    return ranges


_CTX_ACCOUNTS_RE = re.compile(
    r"\bCtx(?:Context)?\s*<\s*([A-Za-z_][A-Za-z0-9_]*)\s*>"
    r"|\bContext\s*<\s*([A-Za-z_][A-Za-z0-9_]*)\s*>"
)


def _linked_accounts_struct_name(handler_signature: str) -> Optional[str]:
    """HEURISTIC: extract the `T` from `Context<T>` in an Anchor handler
    signature so the runner can splice the accounts-struct body into the
    handler's effective body.

    Anchor handlers conventionally take `ctx: Context<WithdrawFees>` (or
    `Box<Context<...>>`, which we do not chase). Without this splice,
    DSL rows that mix handler-body checks (e.g. `token::transfer`) with
    accounts-field checks (e.g. `pub pool_state: Account<`) cannot fire
    on a single region. The cost is some false-negative cases where the
    accounts struct is anonymous or generic — acceptable given the
    `evidence_class: scaffolded_unverified` ceiling.
    """
    m = _CTX_ACCOUNTS_RE.search(handler_signature)
    if not m:
        return None
    return m.group(1) or m.group(2)


def extract_regions(file_path: Path, workspace: Path) -> List[Region]:
    """Pull all Anchor-relevant regions out of one .rs file."""
    try:
        text = file_path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return []
    rel = _rel(workspace, file_path)
    program_ranges = _program_mod_ranges(text)
    regions: List[Region] = []

    # (a) Accounts structs. We collect them first so handlers can splice
    # their linked accounts struct into the effective body (see
    # _linked_accounts_struct_name).
    accounts_struct_bodies: Dict[str, str] = {}
    for m in _PUB_STRUCT_RE.finditer(text):
        if not _has_accounts_derive_above(text, m.start()):
            continue
        open_brace = text.find("{", m.start())
        close_brace = _find_matching_brace(text, open_brace)
        body = text[m.start():close_brace + 1]
        line = _line_of(text, m.start())
        attrs = _attrs_above(text, m.start())
        accounts_struct_bodies[m.group(1)] = body
        regions.append(Region(
            kind="accounts_struct",
            name=m.group(1),
            file=rel,
            line=line,
            body=body,
            attrs=attrs,
            preceded_by_accounts_derive=True,
            inside_program_mod=False,
        ))

    # (b) `pub fn` declarations — classify as handler vs pub_fn.
    for m in _PUB_FN_RE.finditer(text):
        # Only line-anchored matches are valid pub fn declarations; the
        # regex already enforces line-anchored via leading `^\s*` thanks
        # to the MULTILINE shape of finditer over the full text without
        # MULTILINE flag — finditer respects `^` only with MULTILINE, so
        # we re-anchor manually here.
        # Re-derive line start.
        line_start = text.rfind("\n", 0, m.start()) + 1
        # The regex starts with `\s*` so any whitespace-only prefix is
        # OK. Ensure nothing non-whitespace precedes on the same line.
        prefix = text[line_start:m.start()]
        if prefix.strip() != "":
            continue
        open_brace = text.find("{", m.end())
        if open_brace < 0:
            continue
        close_brace = _find_matching_brace(text, open_brace)
        body = text[m.start():close_brace + 1]
        line = _line_of(text, m.start())
        # Inside a #[program] mod?
        inside = any(open_brace > o and close_brace <= c for (o, c) in program_ranges)
        # If a fn opens before any program mod opens, it could still be
        # bracketed by checking start position vs (o, c).
        if not inside:
            inside = any(m.start() > o and close_brace <= c for (o, c) in program_ranges)
        attrs = _attrs_above(text, m.start())
        kind = "handler" if inside else "pub_fn"
        # HEURISTIC: splice the handler's linked accounts-struct body
        # onto the end of the handler body when the `Context<T>`
        # parameter resolves to a known accounts struct in this file.
        # This lets DSL rows that combine handler-body checks (e.g.
        # `token::transfer`) with accounts-field checks (e.g.
        # `pub pool_state: Account<`) fire on a single region. Documented
        # in the module docstring as the "name-union body splice".
        signature_text = text[m.start():open_brace]
        linked = _linked_accounts_struct_name(signature_text)
        effective_body = body
        if kind == "handler" and linked and linked in accounts_struct_bodies:
            effective_body = body + "\n// === linked accounts struct ===\n" \
                + accounts_struct_bodies[linked]
        regions.append(Region(
            kind=kind,
            name=m.group(1),
            file=rel,
            line=line,
            body=effective_body,
            attrs=attrs,
            preceded_by_accounts_derive=_has_accounts_derive_above(text, m.start()),
            inside_program_mod=inside,
        ))
    return regions


# ---------------------------------------------------------------------------
# DSL pattern parsing — stdlib-only line scanner. We deliberately do NOT
# pull in PyYAML (matches detector-lint.py / rust-source-graph.py
# discipline). We only need to extract:
#   - top-level scalars: pattern, severity, confidence, backend
#   - ordered list `match:` entries of the shape `- key: <value>`
# Anything unrecognised is preserved as raw and skipped during eval (we
# emit a single warning per unsupported predicate at parse time).
# ---------------------------------------------------------------------------

def _read_text(path: Path) -> str:
    try:
        return path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return ""


_TOP_SCALAR_RE = re.compile(r"^([A-Za-z_][A-Za-z0-9_]*)\s*:\s*(.*?)\s*(?:#.*)?$")


def _strip_yaml_quotes(val: str) -> str:
    val = val.strip()
    if len(val) >= 2 and val[0] == val[-1] and val[0] in ("'", '"'):
        return val[1:-1]
    return val


def parse_dsl(path: Path) -> Optional[Dict[str, Any]]:
    """Parse a DSL YAML file and return:
       {
         pattern, severity, confidence, backend, source_file,
         match: [ {predicate, value}, ... ],
         preconditions: [ {predicate, value}, ... ],
         raw_warnings: [str, ...],
       }
       or None if the file is not a recognisable DSL row.
    """
    text = _read_text(path)
    if not text:
        return None
    out: Dict[str, Any] = {
        "pattern": None,
        "severity": None,
        "confidence": None,
        "backend": "solidity",
        "source_file": str(path),
        "match": [],
        "preconditions": [],
        "raw_warnings": [],
    }
    section: Optional[str] = None  # 'match' or 'preconditions' or None
    for raw_line in text.splitlines():
        # Strip trailing comments AT THE LINE LEVEL (cannot do mid-string;
        # acceptable because DSL values are short and stylistic comments
        # in our DSL only appear at end of line).
        line = raw_line.rstrip()
        if line.strip().startswith("#"):
            continue
        if line.strip() == "":
            continue
        # Top-level scalar?
        if not line.startswith(" ") and not line.startswith("\t") \
                and not line.lstrip().startswith("- "):
            m = _TOP_SCALAR_RE.match(line)
            if m:
                key = m.group(1)
                val = _strip_yaml_quotes(m.group(2))
                if key in ("pattern", "severity", "confidence", "backend"):
                    out[key] = val
                    section = None
                    continue
                if key in ("match", "preconditions"):
                    section = key
                    continue
                # Ignored top-level scalar (help, wiki_*, source, etc.).
                section = None
                continue
        # Indented list item: `  - <predicate>: <value>`
        stripped = line.strip()
        if stripped.startswith("- ") and section in ("match", "preconditions"):
            entry = stripped[2:].strip()
            # `function.body_contains_regex: '<re>'` shape.
            m = re.match(r"([A-Za-z_][A-Za-z0-9_.]*)\s*:\s*(.*)", entry)
            if not m:
                out["raw_warnings"].append(f"unrecognised match entry: {entry}")
                continue
            pred = m.group(1).strip()
            val = _strip_yaml_quotes(m.group(2))
            out[section].append({"predicate": pred, "value": val})
            continue
    return out


# ---------------------------------------------------------------------------
# Predicate evaluation — Anchor-aware.
# ---------------------------------------------------------------------------

# Predicates this engine UNDERSTANDS. Anything else is treated as an
# unsupported predicate and the row will not fire (we log once per
# pattern via warnings collector). We deliberately whitelist rather
# than blacklist: a future predicate must be opt-in.
SUPPORTED_PREDICATES = {
    "function.name_matches",
    "function.body_contains_regex",
    "function.body_not_contains_regex",
    "function.has_anchor_derive",
    "function.is_anchor_handler",
    "function.not_in_skip_list",
    "function.not_source_matches_regex",
    "function.not_leaf_helper",  # always passes — placeholder for parity
    "function.kind",  # used as a tag; we accept handler/anchor_instruction
}


def _bool_token(s: str) -> Optional[bool]:
    s = s.strip().lower()
    if s in ("true", "yes", "1"):
        return True
    if s in ("false", "no", "0"):
        return False
    return None


def _re_compile(pattern: str) -> Optional[re.Pattern[str]]:
    try:
        return re.compile(pattern)
    except re.error:
        return None


def evaluate_match(match_predicates: List[Dict[str, str]],
                   region: Region,
                   file_text: str) -> Tuple[bool, List[str]]:
    """Apply every predicate in `match_predicates` against `region`.

    Returns (matched, predicate_log). All predicates must pass for the
    row to fire (AND semantics — same as Solidity backend).
    `predicate_log` is a per-predicate list of "<pred>=PASS|FAIL" strings
    used downstream for debugging unfired rows.
    """
    log: List[str] = []
    for entry in match_predicates:
        pred = entry["predicate"]
        val = entry["value"]
        if pred not in SUPPORTED_PREDICATES:
            log.append(f"{pred}=SKIP_UNSUPPORTED")
            return False, log

        if pred == "function.name_matches":
            rx = _re_compile(val)
            if rx is None:
                log.append(f"{pred}=BAD_REGEX")
                return False, log
            # HEURISTIC-NAME-UNION: match against handler name OR
            # accounts struct name. For accounts structs the "name" is
            # the struct name; for handlers it's the fn name. The DSL
            # author can write a single regex that matches the
            # snake_case handler form (e.g. `withdraw_fees`) and the
            # PascalCase struct form (`WithdrawFees`).
            if not rx.search(region.name):
                log.append(f"{pred}=FAIL")
                return False, log
            log.append(f"{pred}=PASS")
            continue

        if pred == "function.body_contains_regex":
            rx = _re_compile(val)
            if rx is None:
                log.append(f"{pred}=BAD_REGEX")
                return False, log
            if not rx.search(region.body):
                log.append(f"{pred}=FAIL")
                return False, log
            log.append(f"{pred}=PASS")
            continue

        if pred == "function.body_not_contains_regex":
            rx = _re_compile(val)
            if rx is None:
                log.append(f"{pred}=BAD_REGEX")
                return False, log
            if rx.search(region.body):
                log.append(f"{pred}=FAIL")
                return False, log
            log.append(f"{pred}=PASS")
            continue

        if pred == "function.has_anchor_derive":
            want = _bool_token(val)
            if want is None:
                log.append(f"{pred}=BAD_BOOL")
                return False, log
            got = region.preceded_by_accounts_derive or region.kind == "accounts_struct"
            if got != want:
                log.append(f"{pred}=FAIL")
                return False, log
            log.append(f"{pred}=PASS")
            continue

        if pred == "function.is_anchor_handler":
            want = _bool_token(val)
            if want is None:
                log.append(f"{pred}=BAD_BOOL")
                return False, log
            got = region.kind == "handler"
            if got != want:
                log.append(f"{pred}=FAIL")
                return False, log
            log.append(f"{pred}=PASS")
            continue

        if pred == "function.not_in_skip_list":
            # Always passes (parity with Solidity skip registry shape).
            log.append(f"{pred}=PASS")
            continue

        if pred == "function.not_leaf_helper":
            # Heuristic: a region with `kind=handler` or `accounts_struct`
            # is, by construction, NOT a leaf helper. A `pub_fn` outside
            # any #[program] mod could be a helper — but the brief says
            # not_leaf_helper should only block leaf-only patterns. We
            # treat it as PASS for handlers/accounts structs and PASS
            # for pub_fn unless the body is trivially short (< 4 lines),
            # which is a conservative leaf signal.
            if region.kind in ("handler", "accounts_struct"):
                log.append(f"{pred}=PASS")
                continue
            line_count = region.body.count("\n")
            if line_count < 4:
                log.append(f"{pred}=FAIL_LEAF")
                return False, log
            log.append(f"{pred}=PASS")
            continue

        if pred == "function.not_source_matches_regex":
            rx = _re_compile(val)
            if rx is None:
                log.append(f"{pred}=BAD_REGEX")
                return False, log
            # Apply against both file path and the region body — same
            # discipline as the Solidity backend's filename+source skip.
            if rx.search(region.file) or rx.search(region.body):
                log.append(f"{pred}=FAIL")
                return False, log
            log.append(f"{pred}=PASS")
            continue

        if pred == "function.kind":
            # Accept any of: handler, anchor_instruction, accounts_struct,
            # pub_fn. The DSL existing patterns use `handler` and
            # `anchor_instruction` interchangeably; we map both to the
            # `handler` region kind.
            tokens = {t.strip() for t in val.split("|")}
            mapped = {"anchor_instruction": "handler"}
            tokens = {mapped.get(t, t) for t in tokens}
            if region.kind not in tokens:
                log.append(f"{pred}=FAIL")
                return False, log
            log.append(f"{pred}=PASS")
            continue

    return True, log


# ---------------------------------------------------------------------------
# Driver
# ---------------------------------------------------------------------------

def _rel(workspace: Path, path: Path) -> str:
    try:
        return str(path.resolve().relative_to(workspace.resolve()))
    except ValueError:
        return str(path)


def load_anchor_patterns(patterns_dir: Path) -> List[Dict[str, Any]]:
    """Return parsed DSL rows whose `backend:` is `anchor`."""
    rows: List[Dict[str, Any]] = []
    if not patterns_dir.is_dir():
        return rows
    for yaml_path in sorted(patterns_dir.glob("*.yaml")):
        parsed = parse_dsl(yaml_path)
        if parsed is None:
            continue
        if parsed.get("backend") != "anchor":
            continue
        if not parsed.get("match"):
            continue
        rows.append(parsed)
    return rows


def run_scan(workspace: Path, patterns_dir: Path) -> Dict[str, Any]:
    """Execute every `backend: anchor` DSL row against discovered files.

    Output schema:
      {
        "_meta": { schema_version, workspace, files_scanned,
                   patterns_evaluated },
        "findings": [
          {
            "pattern": "<pattern-name>",
            "file": "<rel/path.rs>:<line>",
            "severity": "...",
            "confidence": "...",
            "evidence_class": "scaffolded_unverified",
            "region_kind": "handler" | "accounts_struct" | "pub_fn",
            "region_name": "<fn or struct name>",
            "predicate_log": [...]
          }, ...
        ]
      }
    """
    files = discover_anchor_files(workspace)
    patterns = load_anchor_patterns(patterns_dir)
    findings: List[Dict[str, Any]] = []
    for f in files:
        regions = extract_regions(f, workspace)
        for region in regions:
            for row in patterns:
                matched, log = evaluate_match(row["match"], region, region.body)
                if not matched:
                    continue
                findings.append({
                    "pattern": row["pattern"],
                    "file": f"{region.file}:{region.line}",
                    "severity": row.get("severity"),
                    "confidence": row.get("confidence"),
                    "evidence_class": "scaffolded_unverified",
                    "region_kind": region.kind,
                    "region_name": region.name,
                    "predicate_log": log,
                })
    return {
        "_meta": {
            "schema_version": SCHEMA_VERSION,
            "workspace": str(workspace),
            "files_scanned": len(files),
            "patterns_evaluated": len(patterns),
        },
        "findings": findings,
    }


def _default_out(workspace: Path) -> Path:
    return workspace / ".auditooor" / "anchor_findings.json"


def main(argv: Optional[List[str]] = None) -> int:
    p = argparse.ArgumentParser(
        prog="anchor-detector-runner",
        description=(
            "First per-backend executor for `backend: anchor` DSL rows. "
            "Stdlib-only; emits scaffolded-unverified findings for the "
            "Anchor (Solana) program shape."
        ),
    )
    p.add_argument("--workspace", type=Path, required=True,
                   help="Audit workspace (must contain programs/ or contracts/).")
    p.add_argument("--out", type=Path, default=None,
                   help="Path to write findings JSON "
                        "(default: <workspace>/.auditooor/anchor_findings.json).")
    p.add_argument("--patterns", type=Path, default=DEFAULT_PATTERNS_DIR,
                   help="Directory containing DSL YAML rows "
                        "(default: <repo>/reference/patterns.dsl).")
    p.add_argument("--print-json", action="store_true",
                   help="Also print the findings JSON to stdout.")
    args = p.parse_args(argv)

    workspace = args.workspace.expanduser().resolve()
    if not workspace.is_dir():
        print(f"[anchor-runner] ERR workspace not found: {workspace}",
              file=sys.stderr)
        return 2

    patterns_dir = args.patterns.expanduser().resolve()
    result = run_scan(workspace, patterns_dir)

    out = args.out.expanduser().resolve() if args.out else _default_out(workspace)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n",
                   encoding="utf-8")

    if args.print_json:
        sys.stdout.write(json.dumps(result, indent=2, sort_keys=True) + "\n")

    print(
        f"[anchor-runner] OK files={result['_meta']['files_scanned']} "
        f"patterns={result['_meta']['patterns_evaluated']} "
        f"findings={len(result['findings'])} json={out}",
        file=sys.stderr,
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
