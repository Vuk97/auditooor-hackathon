#!/usr/bin/env python3
"""rust-detector-runner.py — L13 bootstrap (Frost / Spark-OOS-but-PoI seeds).

Mirrors the structural shape of ``tools/go-detector-runner.py`` for ``.rs``
sources. Stdlib-only — pure regex over Rust source text plus brace-balanced
function-body slicing. We deliberately do not shell out to ``rustc`` /
``syn`` so the runner works in sandboxes without a Rust toolchain.

Initial pattern set (2 of 5 Worker-CCC L12 Frost seeds):

1. ``rust.frost.dkg.self_identifier_in_round_packages`` — a DKG round-package
   construction (``BTreeMap<Identifier, ...Package>`` populated inside a
   function whose name signals DKG round 2 / 3 — ``part2`` / ``part3`` /
   ``compute_round*_packages`` / ``round[12]::Package`` builders) does NOT
   exclude ``self.identifier`` / ``self_identifier`` / the identifier
   parameter from the recipient set. Stage-1 predicate looks for: function
   name shape AND a map insert of an Identifier-keyed package AND the absence
   of a ``!=`` / ``filter`` / ``ne(`` / ``continue`` skip against
   ``self.identifier`` / ``self_identifier`` / ``my_identifier`` /
   ``own_identifier``. Mirrors ``ff5ec8d`` "core: misc fixes".

2. ``rust.frost.aggregate.under_threshold_signature_shares`` — a function
   whose name starts with ``aggregate`` (and which takes a
   ``signature_shares`` / ``shares`` parameter) does NOT enforce a length
   check ``signature_shares.len() >= MIN_SIGNERS`` (or ``threshold`` /
   ``min_signers``) before dispatching to the aggregation core. Stage-1
   predicate: function-name match AND ``signature_shares`` (or ``shares``)
   parameter AND no ``len()`` comparison guard / ``return Err(...)`` or
   ``ensure!(...)`` against ``min_signers`` / ``threshold`` /
   ``MIN_SIGNERS`` in the body. Mirrors ``ff5ec8d``.

Both Frost patterns are PoI-eligible (per ``CLAUDE.md`` "Spark Primacy of
Impact"): pattern fires on ``lightsparkdev/frost`` would route via the PoI
placeholder row in the Immunefi form (NOT the listed-asset row), since
Frost is OOS-but-Spark-mainnet-dependent.

Outputs (idempotent rewrite):

    <workspace>/.auditooor/rust_findings.json
    <workspace>/.auditooor/SCAN_RUST_SUMMARY.json    (compat alias)
    <workspace>/scanners/rust/SCAN_RUST_SUMMARY.json (intake-baseline gate path)
    <workspace>/scanners/rust/SCAN_RUST_SUMMARY.md   (intake-baseline gate path)

JSON shape::

    {
      "schema_version": 1,
      "scanner_schema": "auditooor.rust_detector_runner.v1",
      "workspace": "<abs path>",
      "scanner": "rust-detector-runner.py",
      "scanner_version": "0.1.0",
      "rust_files_scanned": <int>,
      "patterns": {
          "<pattern_id>": {
              "id": "<pattern_id>",
              "hits": [
                  {"file": "<rel path>", "line": <int>, "snippet": "..."}
              ],
              "hit_count": <int>
          },
          ...
      },
      "totals": {"hits": <int>, "files": <int>}
    }

When no Rust files are present the runner exits 0 with
``rust_files_scanned=0`` and an empty ``patterns`` map — i.e. it is a
no-op for non-Rust workspaces.

Modes::

    --workspace PATH    scan PATH for *.rs files and write JSON outputs
    --scan PATH         alias of --workspace (parallel to go runner naming)
    --list              print pattern IDs (one per line) and exit
    --json              print summary JSON to stdout (after writing files)
    --print             alias of --json (parallel to go runner naming)
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterable

SCANNER_VERSION = "0.1.0"
SCHEMA_SLUG = "auditooor.rust_detector_runner.v1"
STRICT_SCHEMA = "auditooor.rust_detector_runner.strict.v1"
STRICT_DISPOSITION_SCHEMA = "auditooor.detector_disposition.v1"
STRICT_DISPOSITION_FILENAME = "rust_detector_dispositions.jsonl"
_STRICT_DISPOSITION_TYPES = frozenset({
    "accepted", "covered", "duplicate", "filed", "false-positive",
    "known-issue", "not-applicable", "refuted", "resolved",
})

# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------

# Skip these directories when walking — vendored / generated / test-output
# trees that bloat scan time without yielding actionable findings.
_SKIP_DIRS = {
    ".git", ".idea", ".vscode", "node_modules", "vendor", "third_party",
    "_archive", "_archived", ".auditooor", "dist", "build", "out",
    "target",   # cargo build output
}

# Valid pattern IDs surfaced by --list. Mirrors the go runner's
# enumeration shape so downstream tooling (gap-analyzer, scanner-wiring
# audits) can introspect what's wired.
_VALID_PATTERN_IDS = (
    # wave-1
    "rust.frost.dkg.self_identifier_in_round_packages",
    "rust.frost.aggregate.under_threshold_signature_shares",
    # wave-2 (FROST-derived standalone detectors in detectors/rust_wave2/)
    "rust.frost.wave2.nonce_reuse_risk_unscoped_secret",
    "rust.frost.wave2.threshold_check_against_active_set_only",
    "rust.frost.wave2.keypackage_serialization_unauthenticated",
    # class-B: untrusted-ingress -> unguarded panic (RU1)
    "rust.panic.untrusted_ingress_unguarded_panic",
)

# Engines this runner ships with (analogous to VALID_ENGINES in the
# go runner).
VALID_ENGINES = ("rust",)


# ---------------------------------------------------------------------------
# Rust function header regex
# ---------------------------------------------------------------------------
#
# Rust function headers can be more complex than Go — they may have
# generics ``<T, U: Trait>``, where-clauses, and the parameter list can
# span multiple lines. We use a permissive name+open-paren capture and
# rely on brace-balanced slicing to find the body. Generic angle
# brackets are tolerated by allowing them inside the param list region.
#
# We accept ``pub``/``pub(crate)``/visibility prefixes, ``async``,
# ``const``, and ``unsafe`` keywords ahead of ``fn``.
_RUST_FUNC_HEADER = re.compile(
    r"^[ \t]*"
    r"(?:pub(?:\s*\([^)]*\))?\s+)?"
    r"(?:async\s+)?"
    r"(?:const\s+)?"
    r"(?:unsafe\s+)?"
    r"fn\s+"
    r"(?P<name>[A-Za-z_][A-Za-z0-9_]*)"
    r"(?:\s*<[^{>]*>)?"   # optional generics
    r"\s*\(",
    re.MULTILINE,
)


# ---------------------------------------------------------------------------
# Test-context recognition (FP guard for the ingress-panic detectors).
# ---------------------------------------------------------------------------
#
# A `#[test]` / `#[rstest]` / `#[cfg(test)]` fn (or a fn inside a
# `#[cfg(test)] mod` / a `*_test.rs` / `tests/` file) takes CONST fixture
# params, not attacker-supplied external ingress. Indexing/unwrapping a
# fixture param is NOT a reachable-panic-on-untrusted-input, so the
# ingress-panic detectors (RU1 / RU2) skip test-context fns.

# A fn attribute (or an enclosing-mod attribute) that marks the fn as a test.
_TEST_FN_ATTR_RE = re.compile(
    r"#\[\s*(?:test|rstest|tokio::test|async_std::test|actix_rt::test|"
    r"test_case|googletest::test|proptest)\b"
    r"|#\[\s*[A-Za-z_][\w:]*::test\b"                 # any <crate>::test
    r"|#\[\s*cfg\s*\(\s*(?:all\s*\(\s*)?test\b"        # #[cfg(test)] / cfg(all(test,..))
)

# A `#[cfg(test)] mod ..` header - `test` must be the FIRST cfg predicate so
# `#[cfg(not(test))]` (non-test code) is NOT matched. Interposed attrs (e.g.
# `#[allow(..)]`) between the cfg and the `mod` are tolerated.
_CFG_TEST_MOD_RE = re.compile(
    r"#\[\s*cfg\s*\(\s*(?:all\s*\(\s*)?test\b[^\]]*\]"
    r"\s*(?:#\[[^\]]*\]\s*)*"
    r"(?:pub(?:\s*\([^)]*\))?\s+)?mod\s+[A-Za-z_]\w*\s*\{"
)

# ---------------------------------------------------------------------------
# Test-scaffolding / mock recognition (FP guard, CONTAINER-based).
# ---------------------------------------------------------------------------
#
# A `#[cfg(test)]` marker is not the only test-context tell. A conventionally
# named scaffolding module - `(pub) mod test_utils|test_helpers|mock(s)` (often
# NOT `#[cfg(test)]`-gated because it is shared by integration tests / benches)
# - and an `impl (.. for) Mock<X>` block hold FIXTURE data and MOCK trait
# implementations. A method there takes const/fixture inputs, not attacker
# ingress, so the ingress-panic detectors must not fire inside it. Crucially
# this is CONTAINER-based (module / impl-Self name), NEVER fn-name based, so a
# real prod `fn read` OUTSIDE such a container still fires (precision-conscious).
#
# `mod test_utils_extra` / `mod mock_data` do NOT match (the `\b` after the name
# requires the module name to end there), and an `impl Trait for RealType` whose
# Self type is not `Mock*` does NOT match (the Self type is parsed out of the
# header - see `_test_helper_spans`).
_TEST_HELPER_MOD_RE = re.compile(
    r"(?:pub(?:\s*\([^)]*\))?\s+)?mod\s+"
    r"(?:test_utils|test_util|test_helpers|test_helper|test_support|mocks?)"
    r"\b[^\{;]*\{"
)

# An `impl` header up to (and including) its generics; the Self type is parsed
# out of the text between here and the body `{` in `_test_helper_spans`.
_IMPL_HEADER_RE = re.compile(r"\bimpl\b(?:\s*<[^>]*>)?")


# Pattern 1 — DKG self-identifier in round packages.
#
# Function-name shape that signals a DKG round-2 / round-3 builder:
#   * ``part2`` / ``part3`` (frost-core canonical names)
#   * ``compute_round1_packages`` / ``compute_round2_packages``
#   * ``generate_round1_packages`` / ``generate_round2_packages``
#   * ``build_round1_packages`` / ``build_round2_packages``
#   * ``round1_packages`` / ``round2_packages`` (when used as fn name)
_DKG_ROUND_FN_NAME = re.compile(
    r"^("
    r"part[23]"
    r"|(?:compute|generate|build|make|create)_round[123]_packages?"
    r"|round[123]_packages?"
    r"|distribute_round[123]_packages?"
    r")$"
)

# An Identifier-keyed map insert. We accept either:
#   * ``round_packages.insert(identifier, package);``
#   * ``packages.insert(*identifier, ...);``
#   * ``map.insert(other_id, dkg::round1::Package { ... })``
# The ``insert`` method is the canonical BTreeMap/HashMap entry-point.
_IDENT_MAP_INSERT = re.compile(
    r"\.insert\s*\(\s*"
    r"(?:&|\*|mut\s+)?"
    r"(?P<key>[A-Za-z_][\w\.\(\)\*&]*)"
    r"\s*[,)]"
)

# Self-identifier exclusion guard. Any of these in the body indicates
# the author HAS thought about excluding self.
#
# We accept three guard shapes:
#  (a) inline loop-skip:  ``if id == self.identifier { continue; }``
#                         (also continue;, .filter(), .iter().filter(), etc.)
#  (b) pre-validation:    ``if <collection>.contains_key(&self.identifier)``
#                         / ``...contains(&self_identifier)`` / etc.
#                         Returns Err early if self appears in the input.
#                         This is the shape the upstream `ff5ec8d` fix uses
#                         in frost-core/src/keys/dkg.rs::part2 and ::part3.
#  (c) explicit ne/eq comparison against a known self-identifier name.
_SELF_IDENT_GUARD = re.compile(
    r"\b(?:"
    r"self\.identifier"
    r"|self_identifier"
    r"|my_identifier"
    r"|own_identifier"
    r"|sender_identifier"
    r"|secret_package\.identifier"
    r"|round2_secret_package\.identifier"
    r")\b"
    r"\s*(?:!=|\.ne\s*\(|==\s*[^=]|\.eq\s*\()"
    r"|\bcontinue\s*;"
    r"|\.filter\s*\("
    r"|\.iter\s*\(\s*\)\s*\.\s*filter"
    r"|if\s+\w+\s*==\s*self\.identifier"
    r"|if\s+\w+\s*==\s*self_identifier"
    r"|\.contains_key\s*\(\s*&\s*(?:self\.identifier|self_identifier|"
    r"my_identifier|own_identifier|secret_package\.identifier|"
    r"round2_secret_package\.identifier)\s*\)"
    r"|\.contains\s*\(\s*&\s*(?:self\.identifier|self_identifier|"
    r"my_identifier|own_identifier|secret_package\.identifier|"
    r"round2_secret_package\.identifier)\s*\)"
)

# A round-package construction marker: at least one of these in the body
# shows the function is in fact assembling DKG round packages (so the
# detector doesn't fire on unrelated fn-name false friends).
_DKG_PACKAGE_MARKER = re.compile(
    r"\b(?:"
    r"dkg::round[12]::Package"
    r"|round[12]::Package"
    r"|Round[12]Package"
    r"|round[12]_package"
    r")\b"
    r"|BTreeMap\s*<\s*Identifier"
    r"|HashMap\s*<\s*Identifier"
)

# Pattern 2 — aggregate under-threshold signature shares.
#
# Function-name shape: starts with "aggregate" (case-insensitive on the
# leading char) optionally followed by an underscore segment.
_AGGREGATE_FN_NAME = re.compile(
    r"^aggregate(?:_[A-Za-z0-9_]+)?$"
)

# Param-list signal: takes a ``signature_shares`` (preferred) or
# ``shares`` (looser) collection. Accept ``&BTreeMap<...>``,
# ``&HashMap<...>``, ``&[...]``, ``Vec<...>`` styles.
_SIG_SHARES_PARAM = re.compile(
    r"\b(?:signature_shares|shares)\b\s*:"
)

# Wrapper-delegation suppressor: a tiny aggregate body that simply
# forwards to another aggregate-shaped fn (``aggregate_custom``, an
# upstream ``frost::aggregate``, etc.) is not itself missing a
# threshold guard — the wrapped callee enforces it. We treat presence
# of any of these call shapes as "delegated, do not flag".
_AGGREGATE_DELEGATION = re.compile(
    r"\baggregate_custom\s*\("
    # any path-segment shape ``<x>::aggregate(`` / ``<x>::aggregate_custom(``
    # — covers crate::, frost::, frost_core::, frost_rerandomized::,
    # frost::core::, super::, etc.
    r"|\b[A-Za-z_][\w]*(?:::[A-Za-z_][\w]*)*::aggregate(?:_custom)?(?:::<[^>]*>)?\s*\("
)

# Threshold-guard markers. ANY of these in the body counts as the author
# enforcing the min-signers threshold. We are deliberately permissive
# here so we don't fire on bodies that delegate the check to a helper
# that obviously enforces it.
_THRESHOLD_GUARD = re.compile(
    r"\b(?:"
    r"min_signers"
    r"|MIN_SIGNERS"
    r"|threshold"
    r"|Threshold"
    r"|min_threshold"
    r"|signers_threshold"
    r")\b"
    r"|\.len\s*\(\s*\)\s*<"
    r"|\.len\s*\(\s*\)\s*<="
    r"|\.len\s*\(\s*\)\s*>="
    r"|\.len\s*\(\s*\)\s*>"
    r"|\.len\s*\(\s*\)\s*!="
    r"|\.len\s*\(\s*\)\s*=="
    r"|ensure!\s*\("
    r"|return\s+Err\s*\("
    r"|InvalidNumberOfShares"
    r"|IncorrectNumberOfShares"
    r"|NotEnoughShares"
    r"|InvalidSignatureShare"
)


# ---------------------------------------------------------------------------
# data classes
# ---------------------------------------------------------------------------

@dataclass
class Hit:
    file: str
    line: int
    snippet: str
    extra: dict = field(default_factory=dict)

    def to_json(self) -> dict:
        d = {"file": self.file, "line": self.line, "snippet": self.snippet}
        if self.extra:
            d["extra"] = self.extra
        return d


@dataclass
class RustFunction:
    name: str
    params: str
    start_line: int           # 1-indexed line of the `fn` keyword
    body_start_line: int      # 1-indexed line of opening `{`
    body: str                 # raw text between the matching braces (exclusive)
    file: Path                # relative path under workspace
    sig: str = ""             # full signature text `fn ..` up to the body `{`
    attrs: str = ""           # contiguous attribute/doc lines immediately above
    in_test_mod: bool = False  # fn sits inside a `#[cfg(test)] mod ..` block
    in_test_helper: bool = False  # fn sits inside a `mod test_utils|mock..` /
    #                               `impl (.. for) Mock<X>` scaffolding block

    @property
    def header(self) -> str:
        return f"fn {self.name}({self.params})"


# ---------------------------------------------------------------------------
# Rust function extraction
# ---------------------------------------------------------------------------

def _balance_braces(src: str, start_idx: int) -> int | None:
    """Given index of an opening ``{``, return index just past matching ``}``.

    Skips string / char / line-comment / block-comment contents. Returns
    ``None`` if no balancing brace is found (truncated source).
    """
    depth = 0
    i = start_idx
    n = len(src)
    in_str: str | None = None
    in_line_comment = False
    in_block_comment = False
    block_comment_depth = 0
    while i < n:
        ch = src[i]
        nxt = src[i + 1] if i + 1 < n else ""
        if in_line_comment:
            if ch == "\n":
                in_line_comment = False
        elif in_block_comment:
            # Rust supports nested block comments.
            if ch == "/" and nxt == "*":
                block_comment_depth += 1
                i += 1
            elif ch == "*" and nxt == "/":
                block_comment_depth -= 1
                if block_comment_depth == 0:
                    in_block_comment = False
                i += 1
        elif in_str is not None:
            if ch == "\\":
                i += 1  # skip escaped char
            elif ch == in_str:
                in_str = None
        else:
            if ch == "/" and nxt == "/":
                in_line_comment = True
                i += 1
            elif ch == "/" and nxt == "*":
                in_block_comment = True
                block_comment_depth = 1
                i += 1
            elif ch == "\"":
                in_str = ch
            elif ch == "'":
                # Distinguish lifetime ('a) from char literal ('a').
                # A char literal is two-or-more chars before next `'`. A
                # lifetime never contains a `'` after the leading one.
                # Simple heuristic: peek for closing quote within 4 chars.
                end = src.find("'", i + 1, i + 6)
                if end > 0:
                    in_str = ch
                # else: lifetime, leave in_str=None
            elif ch == "{":
                depth += 1
            elif ch == "}":
                depth -= 1
                if depth == 0:
                    return i + 1
        i += 1
    return None


def _matched_paren_end(src: str, open_idx: int) -> int | None:
    """Given index of an opening ``(``, return index of matching ``)``."""
    depth = 0
    i = open_idx
    n = len(src)
    while i < n:
        ch = src[i]
        if ch == "(":
            depth += 1
        elif ch == ")":
            depth -= 1
            if depth == 0:
                return i
        i += 1
    return None


def _test_mod_spans(src: str) -> list[tuple[int, int]]:
    """[(start, end)] byte spans of every `#[cfg(test)] mod ..` block in
    ``src`` (brace-balanced). A fn whose header offset falls inside a span is
    test-context."""
    spans: list[tuple[int, int]] = []
    for m in _CFG_TEST_MOD_RE.finditer(src):
        brace = m.end() - 1               # the `{` captured by the regex
        end = _balance_braces(src, brace)
        if end is not None:
            spans.append((m.start(), end))
    return spans


# A path-qualified type name: skip leading `crate::mock::` path segments and
# capture the final type identifier (so `impl .. for crate::mocks::MockClient`
# resolves the Self type to `MockClient`).
_IMPL_SELF_TY_RE = re.compile(
    r"\s*(?:[A-Za-z_]\w*\s*::\s*)*(?P<ty>[A-Za-z_]\w*)"
)


def _test_helper_spans(src: str) -> list[tuple[int, int]]:
    """[(start, end)] byte spans of every test-scaffolding container in ``src``:

      * a `(pub) mod test_utils|test_helpers|test_support|mock(s)` inline module
        (brace-balanced); and
      * an `impl (<gen>)? (Trait for)? Mock<X>` block whose Self type name
        starts with ``Mock`` (brace-balanced).

    A fn whose header offset falls inside a span is test/mock context - its
    methods take fixture/mock inputs, not attacker ingress. CONTAINER-based, so
    a real prod `fn read` outside such a container still fires."""
    spans: list[tuple[int, int]] = []
    # (a) scaffolding modules.
    for m in _TEST_HELPER_MOD_RE.finditer(src):
        brace = m.end() - 1               # the `{` captured by the regex
        end = _balance_braces(src, brace)
        if end is not None:
            spans.append((m.start(), end))
    # (b) `impl .. Mock<X>` blocks. Parse the Self type out of the header (the
    #     token after the last ` for `, else the token after `impl<gen>`), and
    #     only accept it when it starts with ``Mock``.
    for m in _IMPL_HEADER_RE.finditer(src):
        brace = _find_body_open(src, m.end())
        if brace is None:
            continue
        header = src[m.end():brace]
        if "Mock" not in header:
            continue                      # cheap pre-filter before balancing
        fm = None
        for fmatch in re.finditer(r"\bfor\b", header):
            fm = fmatch                   # last ` for ` wins (Self is after it)
        self_region = header[fm.end():] if fm else header
        sm = _IMPL_SELF_TY_RE.match(self_region)
        if not sm or not sm.group("ty").startswith("Mock"):
            continue
        end = _balance_braces(src, brace)
        if end is not None:
            spans.append((m.start(), end))
    return spans


def _preceding_attrs(src: str, fn_start: int) -> str:
    """The contiguous run of attribute / doc-comment / blank lines immediately
    preceding the fn header at ``fn_start`` (start-of-line offset). Used to
    detect a `#[test]` / `#[cfg(test)]` / `#[rstest]` marker on the fn."""
    out: list[str] = []
    for ln in reversed(src[:fn_start].splitlines()):
        s = ln.strip()
        if (s == "" or s.startswith("#[") or s.startswith("#![")
                or s.startswith("//") or s.startswith("/*")
                or s.startswith("*")):
            out.append(ln)
            continue
        break
    return "\n".join(reversed(out))


def _extract_functions(src: str, file: Path) -> list[RustFunction]:
    funcs: list[RustFunction] = []
    test_mod_spans = _test_mod_spans(src)
    test_helper_spans = _test_helper_spans(src)
    for m in _RUST_FUNC_HEADER.finditer(src):
        # m.end() points just past the opening '(' of params. Find matching ')'.
        open_paren = m.end() - 1
        close_paren = _matched_paren_end(src, open_paren)
        if close_paren is None:
            continue
        params = src[open_paren + 1:close_paren]
        # Look for the opening brace of the body. It may follow a return
        # type ``-> T`` or a where-clause. Skip until the next '{', but
        # only if we don't hit a ';' first (which would indicate a fn
        # declaration without a body — trait fn signature).
        scan_from = close_paren + 1
        # find first '{' or ';' that's outside strings / comments
        body_open = _find_body_open(src, scan_from)
        if body_open is None:
            continue
        end_idx = _balance_braces(src, body_open)
        if end_idx is None:
            continue
        body = src[body_open + 1:end_idx - 1]
        start_line = src.count("\n", 0, m.start()) + 1
        body_start_line = src.count("\n", 0, body_open) + 1
        sig = src[m.start():body_open]
        in_test_mod = any(s <= m.start() < e for s, e in test_mod_spans)
        in_test_helper = any(
            s <= m.start() < e for s, e in test_helper_spans
        )
        funcs.append(
            RustFunction(
                name=m.group("name"),
                params=params,
                start_line=start_line,
                body_start_line=body_start_line,
                body=body,
                file=file,
                sig=sig,
                attrs=_preceding_attrs(src, m.start()),
                in_test_mod=in_test_mod,
                in_test_helper=in_test_helper,
            )
        )
    return funcs


def _find_body_open(src: str, start: int) -> int | None:
    """Find the next ``{`` that opens a function body, skipping the
    return-type / where-clause region. Returns ``None`` if a ``;`` is
    encountered first (trait fn signature)."""
    i = start
    n = len(src)
    in_str: str | None = None
    in_line_comment = False
    in_block_comment = False
    block_comment_depth = 0
    while i < n:
        ch = src[i]
        nxt = src[i + 1] if i + 1 < n else ""
        if in_line_comment:
            if ch == "\n":
                in_line_comment = False
        elif in_block_comment:
            if ch == "/" and nxt == "*":
                block_comment_depth += 1
                i += 1
            elif ch == "*" and nxt == "/":
                block_comment_depth -= 1
                if block_comment_depth == 0:
                    in_block_comment = False
                i += 1
        elif in_str is not None:
            if ch == "\\":
                i += 1
            elif ch == in_str:
                in_str = None
        else:
            if ch == "/" and nxt == "/":
                in_line_comment = True
                i += 1
            elif ch == "/" and nxt == "*":
                in_block_comment = True
                block_comment_depth = 1
                i += 1
            elif ch == "\"":
                in_str = ch
            elif ch == "{":
                return i
            elif ch == ";":
                return None
        i += 1
    return None


_LINE_COMMENT_RE = re.compile(r"//[^\n]*")
_BLOCK_COMMENT_RE = re.compile(r"/\*.*?\*/", re.DOTALL)


def _strip_comments(s: str) -> str:
    s = _BLOCK_COMMENT_RE.sub("", s)
    s = _LINE_COMMENT_RE.sub("", s)
    return s


# ---------------------------------------------------------------------------
# detector predicates
# ---------------------------------------------------------------------------

def _detect_dkg_self_identifier(funcs: Iterable[RustFunction]) -> list[Hit]:
    """Pattern 1 — DKG round-package construction missing self-exclusion.

    Stage-1 predicate (high precision):
      * function name matches ``part2`` / ``part3`` / ``*round[12]_package*``;
      * body contains a DKG-package construction marker (``dkg::round1::Package``,
        ``BTreeMap<Identifier, ...>``, ``HashMap<Identifier, ...>``);
      * body inserts into an Identifier-keyed map (``.insert(<key>, ...)``);
      * body does NOT contain a self-identifier exclusion guard
        (``self.identifier !=``, ``continue;`` after self-id check,
        ``.filter(`` over identifiers, etc.).
    """
    hits: list[Hit] = []
    for fn in funcs:
        if not _DKG_ROUND_FN_NAME.match(fn.name):
            continue
        body_no_comments = _strip_comments(fn.body)
        if not _DKG_PACKAGE_MARKER.search(body_no_comments):
            continue
        insert_match = _IDENT_MAP_INSERT.search(body_no_comments)
        if not insert_match:
            continue
        if _SELF_IDENT_GUARD.search(body_no_comments):
            continue
        # Anchor on the insert call in the original body.
        orig_match = _IDENT_MAP_INSERT.search(fn.body) or insert_match
        idx = orig_match.start()
        line_off = fn.body[:idx].count("\n")
        lines = fn.body.splitlines()
        snippet = lines[line_off].strip() if line_off < len(lines) else fn.header
        hits.append(
            Hit(
                file=str(fn.file),
                line=fn.body_start_line + line_off,
                snippet=snippet[:200],
                extra={
                    "function": fn.name,
                    "insert_key": orig_match.group("key"),
                },
            )
        )
    return hits


def _detect_aggregate_under_threshold(funcs: Iterable[RustFunction]) -> list[Hit]:
    """Pattern 2 — aggregate fn missing min-signers / threshold guard.

    Stage-1 predicate (high precision):
      * function name starts with ``aggregate`` (matches ``aggregate``,
        ``aggregate_with_tweak``, etc.);
      * params include a ``signature_shares`` or ``shares`` parameter;
      * body does NOT contain any threshold-guard marker
        (``min_signers``, ``threshold``, ``ensure!(``, ``return Err(``,
        ``.len() <`` / ``<=`` / ``>=`` / ``>``, etc.).
    """
    hits: list[Hit] = []
    for fn in funcs:
        if not _AGGREGATE_FN_NAME.match(fn.name):
            continue
        if not _SIG_SHARES_PARAM.search(fn.params):
            continue
        body_no_comments = _strip_comments(fn.body)
        if _THRESHOLD_GUARD.search(body_no_comments):
            continue
        # Wrapper-delegation suppression: if the body forwards to another
        # aggregate-shaped fn (``aggregate_custom``, upstream ``frost::aggregate``,
        # etc.) we trust the callee to enforce the threshold and do not
        # double-flag every cipher-suite re-export. See L13 Frost scan
        # rationale in docs/next-loop/rust_detector_runner_v0_l13_2026-05-07.md.
        if _AGGREGATE_DELEGATION.search(body_no_comments):
            continue
        # Heuristic: skip tiny stubs (<2 lines of body) so test fixtures
        # with empty bodies don't count.
        if fn.body.count("\n") < 2:
            continue
        hits.append(
            Hit(
                file=str(fn.file),
                line=fn.start_line,
                snippet=fn.header[:200],
                extra={"function": fn.name},
            )
        )
    return hits


# ---------------------------------------------------------------------------
# class-B: untrusted-ingress -> unguarded panic (RU1)
# ---------------------------------------------------------------------------
#
# Generalizes rust-from-u8-panic-on-untrusted-input-scan.py (narrow From<u8>
# precedent) and base-rust-swival-shape-scan.py (presence-only). FIRE when an
# untrusted-ingress fn parameter (name/type in {bytes,data,input,&[u8],Vec<u8>})
# flows to a panic sink with NO dominating guard between def and sink in the
# same fn. Guard-dominance mirrors rust-dataflow.py _local_is_guarded: a guard
# only counts if it TEXTUALLY PRECEDES the sink (dominates it). When MIR is
# available rust-dataflow's MIR guard-dominance is the exact analog; here we
# use the same-fn brace-slice + guard-token heuristic (no toolchain needed).

# Ingress param names (untrusted-input naming convention).
_INGRESS_NAMES = frozenset({
    "bytes", "data", "input", "buf", "buffer",
    "payload", "msg", "raw", "encoded", "ssz_bytes",
})

# Ingress param types: byte-slice / byte-vec carriers of untrusted input.
_INGRESS_TYPE_RE = re.compile(
    r"&\s*(?:mut\s+)?\[\s*u8\s*\]"      # &[u8] / &mut [u8]
    r"|\bVec\s*<\s*u8\s*>"                # Vec<u8>
    r"|&\s*Vec\s*<\s*u8\s*>"              # &Vec<u8>
    r"|\[\s*u8\s*\]"                       # [u8]
)

# Panic-macro sinks (not tied to a specific var, but only counted when the
# enclosing fn carries an ingress param and lacks a dominating guard).
_PANIC_MACRO_RE = re.compile(r"\b(?:panic|unreachable|unimplemented|todo)\s*!")

# ---------------------------------------------------------------------------
# RU3 - advisory rust-OOB axis (copy_from_slice / untrusted-offset slice-range)
# ---------------------------------------------------------------------------
#
# OFF by default. Enable with AUDITOOR_RUST_OOB_AXIS=1. Emits needs-fuzz
# hypotheses (NO-AUTO-CREDIT) to .auditooor/rust_oob_hypotheses.jsonl - it
# never flips a gate or resolves a unit.
#
# DEDUP boundary (A1): RU3's headline slice+alloc sinks are already covered by
# RU2 + 2 alloc scanners (decode-bomb). We MUST exclude alloc/with_capacity/
# vec! or RU3 re-derives decode-bomb. The genuinely net-new signal is:
#   (a) copy_from_slice ON an ingress buffer (length-mismatch panic - a DIFFERENT
#       panic than an OOB slice-index), and
#   (b) a range-index buf[a..b] on a SEPARATE buffer (buf != ingress param)
#       whose bound references the untrusted ingress len/offset.
# We tag each hit with covered_by=<RU1 slice_index pattern> when the same
# offset was already emitted by the RU1 slice-index sink (transparency; RU3
# lives in a separate stream so this is never a double count).
_RUST_OOB_AXIS_ENV = "AUDITOOR_RUST_OOB_AXIS"
_RUST_OOB_PATTERN_ID = "rust.oob.untrusted_slice_copy_range"
_RU1_SLICE_INDEX_PID = "rust.panic.untrusted_ingress_unguarded_panic#slice_index"

# Alloc sinks are covered by RU2 + the 2 alloc scanners - excluding them is the
# A1 dedup boundary (prevents decode-bomb re-derivation).
_ALLOC_EXCLUDE_RE = re.compile(r"\bwith_capacity\s*\(|\bvec!\s*\[")


def _oob_axis_enabled() -> bool:
    return os.environ.get(_RUST_OOB_AXIS_ENV, "").strip().lower() in {
        "1", "true", "yes", "on",
    }


def _split_params(params: str) -> list[tuple[str, str]]:
    """Split a Rust param list into (name, type) pairs, depth-aware on the
    top-level commas so generic args (``HashMap<K, V>``) are not mis-split."""
    out: list[tuple[str, str]] = []
    depth = 0
    cur: list[str] = []
    for ch in params:
        if ch in "<([":
            depth += 1
        elif ch in ">)]":
            depth = max(0, depth - 1)
        if ch == "," and depth == 0:
            out.append("".join(cur))
            cur = []
        else:
            cur.append(ch)
    if cur:
        out.append("".join(cur))
    pairs: list[tuple[str, str]] = []
    for seg in out:
        seg = seg.strip()
        if not seg or seg.startswith(("self", "&self", "mut self", "&mut self")):
            continue
        m = re.match(r"(?:mut\s+)?(?P<n>[A-Za-z_]\w*)\s*:\s*(?P<t>.+)$", seg,
                     re.DOTALL)
        if m:
            pairs.append((m.group("n"), m.group("t").strip()))
    return pairs


def _ingress_params(fn: "RustFunction") -> list[str]:
    """Names of parameters that carry untrusted ingress (name or type match)."""
    names: list[str] = []
    for name, ptype in _split_params(fn.params):
        if name in _INGRESS_NAMES or _INGRESS_TYPE_RE.search(ptype):
            names.append(name)
    return names


# Directory parts that mark a Rust test / test-scaffolding tree.
_TEST_DIR_PARTS = frozenset({
    "tests", "test_utils", "test_helpers", "test_support", "mocks",
})
# File basenames that ARE a test / test-scaffolding module (the file IS the
# module body, e.g. a `mod test_utils;` whose body lives in `test_utils.rs`).
_TEST_HELPER_BASENAMES = frozenset({
    "test.rs", "tests.rs",
    "test_utils.rs", "test_util.rs",
    "test_helpers.rs", "test_helper.rs", "test_support.rs",
    "mock.rs", "mocks.rs",
})


def _is_test_path(file: "Path") -> bool:
    """True if ``file`` is a Rust test / test-scaffolding file: a `tests/`
    integration dir (or a `test_utils/`/`test_helpers/`/`mocks/` dir), a
    `*_test.rs` / `*_tests.rs` unit file, or a conventional
    `test_utils.rs` / `test_helpers.rs` / `mock(s).rs` helper-module file.

    The `test_utils.rs` etc. basenames are the FILE analog of the inline
    `mod test_utils { .. }` span (`_test_helper_spans`): the file IS the module
    body, so a `MockCompressor` living in `.../src/test_utils.rs` takes fixture
    inputs, not attacker ingress. This is path-based, NOT fn-name based, so a
    real prod `fn read` in a normal source file still fires."""
    parts = [p.lower() for p in Path(file).parts]
    if any(p in _TEST_DIR_PARTS for p in parts[:-1]):
        return True
    name = parts[-1] if parts else ""
    return (name.endswith("_test.rs") or name.endswith("_tests.rs")
            or name in _TEST_HELPER_BASENAMES)


def _is_test_context(fn: "RustFunction") -> bool:
    """True if ``fn`` is TEST / MOCK code - a `#[test]` / `#[cfg(test)]` /
    `#[rstest]` fn, a fn inside a `#[cfg(test)] mod`, a fn inside a scaffolding
    `mod test_utils|mock(s)` / `impl (.. for) Mock<X>` block, or a
    `*_test.rs` / `tests/` / `test_utils.rs` file. Such a fn's const/fixture
    params are NOT untrusted external ingress, so the ingress-panic detectors
    must not fire on them."""
    if getattr(fn, "in_test_mod", False):
        return True
    if getattr(fn, "in_test_helper", False):
        return True
    if fn.attrs and _TEST_FN_ATTR_RE.search(fn.attrs):
        return True
    return _is_test_path(fn.file)


# Serialization / encoding methods & free-functions. A local named like an
# ingress carrier (e.g. `payload`) that is SERIALIZED/encoded is an OUTBOUND
# value, not inbound untrusted ingress - a `.unwrap()` on the serialize result
# is not a reachable-panic-on-untrusted-input.
_SERIALIZE_METHODS = (
    r"serialize(?:_\w+)?|encode(?:_\w+)?|to_vec|to_bytes|to_writer|to_string"
)


def _sink_is_outbound_serialize(body_nc: str, off: int, pe: str) -> bool:
    """True if the sink at ``off`` is really an OUTBOUND serialize/encode of
    ``pe`` (``pe`` is the SUBJECT: ``pe.serialize()`` / ``to_vec(&pe)``), i.e.
    ``pe`` is an outbound value being encoded, not inbound untrusted ingress.
    ``pe`` is a regex-safe token (escaped param name)."""
    lo = max(
        body_nc.rfind(";", 0, off),
        body_nc.rfind("{", 0, off),
        body_nc.rfind("}", 0, off),
    ) + 1
    hi_cands = [i for i in (body_nc.find(";", off), body_nc.find("\n", off))
                if i != -1]
    hi = min(hi_cands) if hi_cands else len(body_nc)
    stmt = body_nc[lo:hi]
    # pe passed as the value to a serialize/encode free-fn: to_vec(&pe), etc.
    if re.search(
        rf"\b(?:{_SERIALIZE_METHODS})\s*\(\s*&?\s*(?:mut\s+)?{pe}\b", stmt
    ):
        return True
    # pe as the receiver of a serialize/encode method: pe.serialize()/pe.to_vec()
    if re.search(rf"\b{pe}\s*\.\s*(?:{_SERIALIZE_METHODS})\s*\(", stmt):
        return True
    return False


def _err_guard_tethered(pre: str, pe: str) -> bool:
    """True if a `return Err(..)` / `ensure!(..)` guard in ``pre`` is TETHERED
    to the ingress var ``pe`` - its condition co-mentions ``pe`` (or a
    pe-derived local on the same guard statement). An UNRELATED early
    `return Err(flag_err)` about a different value must NOT suppress a later
    genuine ingress sink, so we credit the guard only when its condition names
    ``pe``. ``pe`` is a regex-safe token."""
    # ensure!( <cond>, err ) - the condition is inside the balanced macro call.
    for m in re.finditer(r"\bensure!\s*\(", pre):
        end = _matched_paren_end(pre, m.end() - 1)
        args = pre[m.end():end] if end is not None else pre[m.end():]
        if re.search(rf"\b{pe}\b", args):
            return True
    # return Err( .. ) - the condition is the enclosing `if <cond> {`; scan the
    # statement window from the last `;`/`}` boundary up to the `return` (that
    # window spans the enclosing `if <cond> {`).
    for m in re.finditer(r"\breturn\s+Err\s*\(", pre):
        lo = max(pre.rfind(";", 0, m.start()), pre.rfind("}", 0, m.start())) + 1
        if re.search(rf"\b{pe}\b", pre[lo:m.start()]):
            return True
    return False


# ---------------------------------------------------------------------------
# ecrecover / signature-verify self-clamp (FP guard for the panic detectors).
# ---------------------------------------------------------------------------
#
# In an ecrecover / signature-verify path a recovery-id / index operand is
# conventionally SELF-CLAMPED to its valid domain - a `% N` modulo, a `& MASK`
# bitmask, or a `.min(..)` / `cmp::min(..)` - before it feeds a table index or a
# `RecoveryId::from_*(..).unwrap()`. A self-clamped operand cannot go out of
# range, so the index/unwrap is NOT attacker-panic-reachable. We scope this
# suppression to sig-verify context (precision-conscious): a bare `% x` in an
# arbitrary fn can still panic on a zero modulus, so we do NOT globally treat a
# modulo as a bounds guard - only inside a proven ecrecover/ECDSA path.
_SIG_VERIFY_CTX_RE = re.compile(
    r"\becrecover\b|\bec_recover\b"
    r"|\brecover_(?:signer|pubkey|public_key|address|verifying_key|id)\b"
    r"|\bRecoveryId\b|\brecovery_id\b|\brec_id\b|\bParity\b"
    r"|\bsecp256k1\b|\bk256\b|\blibsecp256k1\b"
    r"|\becdsa\b|\bEcdsa\b|\bECDSA\b"
    r"|\bVerifyingKey\b|\bfrom_recoverable\b"
)

# A self-clamp EXPRESSION as it appears immediately AFTER the operand (`op % N`
# / `op & MASK` / `op.min(..)`). `&` is only a bitmask when followed by a
# numeric / const-cased token (rules out `&&` logical-and).
_SELF_CLAMP_EXPR = (
    r"%\s*[A-Za-z0-9_(]"                                  # % N (modulo)
    r"|&\s*(?:0x[0-9A-Fa-f]+|[0-9]+|[A-Z][A-Z0-9_]*)"      # & MASK (bitmask)
    r"|\.\s*min\s*\(|\bmin\s*\("                            # .min(..) / min(..)
)
# The operand clamped INLINE (`op % N` / `op & MASK` / `op.min(..)`).
_SELF_CLAMP_INLINE_TMPL = r"\b{op}\s*(?:" + _SELF_CLAMP_EXPR + r")"
# A clamp expression anywhere in an RHS. The bitmask arm additionally requires a
# preceding operand (a word char or `)`), so a `&FOO` REFERENCE at the start of
# an RHS (`let t = &TABLE;`) is NOT mistaken for a `x & MASK` bitmask.
_SELF_CLAMP_RHS_RE = re.compile(
    r"%\s*[A-Za-z0-9_(]"
    r"|[)\w]\s*&\s*(?:0x[0-9A-Fa-f]+|[0-9]+|[A-Z][A-Z0-9_]*)"
    r"|\.\s*min\s*\(|\bmin\s*\("
)


def _self_clamped_vars(pre: str) -> set:
    """Names of vars assigned from a self-clamp expression (`let v = raw % N;` /
    `v = raw & MASK;` / `v = raw.min(..)`) anywhere in ``pre``. Mirrors
    ``_panicreach_assignments`` statement-splitting."""
    out: set = set()
    for stmt in re.split(r"[;\n{}]", pre):
        m = re.match(
            r"\s*(?:let\s+(?:mut\s+)?)?([A-Za-z_]\w*)\s*(?::[^=]+)?"
            r"=\s*(?![=<>])(.+)$",
            stmt,
        )
        if m and _SELF_CLAMP_RHS_RE.search(m.group(2)):
            out.add(m.group(1))
    return out


def _self_clamp_dominates(body: str, sink_off: int, op: str) -> bool:
    """True if the index/unwrap operand ``op`` is bounded by a SELF-CLAMP - a
    modulo / bitmask / min. Three shapes:

      (a) ``op`` itself was assigned from a clamp (`let op = raw % N;`);
      (b) ``op`` is clamped INLINE in the sink statement (`table[op % N]`);
      (c) the sink statement references ANOTHER var that was self-clamped
          earlier - the index/unwrap really depends on that clamped operand, not
          the assignment LHS (`let recovery_id = RecoveryId::from_u8(rec_id)
          .unwrap();` where ``rec_id = raw % 4``).

    Callers gate this to ecrecover/signature-verify context (see
    ``_SIG_VERIFY_CTX_RE``) so a modulo/mask is only credited as a bounds guard
    where a recovery-id operand is clamped to its valid domain."""
    pre = body[:sink_off]
    clamped = _self_clamped_vars(pre)
    # (a) `op` assigned from a clamp expression somewhere before the sink.
    if op in clamped:
        return True
    # sink statement window.
    lo = max(pre.rfind(";"), pre.rfind("{"), pre.rfind("}")) + 1
    hi_cands = [i for i in (body.find(";", sink_off), body.find("\n", sink_off))
                if i != -1]
    hi = min(hi_cands) if hi_cands else len(body)
    stmt = body[lo:hi]
    # (b) `op` clamped INLINE within the sink statement window.
    if re.search(_SELF_CLAMP_INLINE_TMPL.format(op=re.escape(op)), stmt):
        return True
    # (c) the sink statement references another self-clamped operand.
    for cv in clamped:
        if cv != op and re.search(rf"\b{re.escape(cv)}\b", stmt):
            return True
    return False


def _guard_dominates(body: str, sink_off: int, pe: str) -> bool:
    """True if a guard on ``pe`` textually PRECEDES the sink at ``sink_off`` in
    ``body`` (dominance heuristic)."""
    pre = body[:sink_off]
    # length / emptiness / option / result checks on the ingress var
    if re.search(rf"\b{pe}\s*\.\s*len\s*\(\s*\)", pre):
        return True
    if re.search(rf"\b{pe}\s*\.\s*is_empty\s*\(", pre):
        return True
    if re.search(rf"\b{pe}\s*\.\s*(?:is_some|is_none|is_ok|is_err)\s*\(", pre):
        return True
    # matches!/? referencing the ingress var
    if re.search(rf"matches!\s*\([^)]*\b{pe}\b", pre):
        return True
    if re.search(rf"\b{pe}\b[^\n;]*\?", pre):
        return True
    # early-return-Err / ensure! guard preceding the sink - TETHERED to the
    # ingress var (co-mention on the guard condition). An unrelated early
    # `return Err(..)` / `ensure!(..)` about a DIFFERENT value must not
    # suppress a later genuine ingress sink.
    if _err_guard_tethered(pre, pe):
        return True
    # ecrecover / signature-verify self-clamp: within a sig-verify path a
    # recovery-id / index operand bounded by a preceding (or inline) modulo /
    # bitmask / min on the SAME operand cannot go out of range, so the
    # index/unwrap is not attacker-panic-reachable. Scoped to sig-verify context
    # to stay precision-conscious (a bare `% x` elsewhere can panic on x==0).
    if _SIG_VERIFY_CTX_RE.search(body) and _self_clamp_dominates(
        body, sink_off, pe
    ):
        return True
    return False


def _impact_contract() -> dict:
    return {
        "class": "untrusted_ingress_unguarded_panic",
        "impact": "remote/attacker-supplied bytes reach a panic (DoS/abort)",
        "requires": "ingress externally reachable + no dominating length/validity guard",
        "status": "advisory_until_harnessed",
    }


def _oob_impact_contract() -> dict:
    return {
        "class": "untrusted_ingress_slice_oob_panic",
        "impact": "attacker len/offset drives a copy_from_slice / range-slice "
                  "panic (DoS/abort)",
        "requires": "ingress externally reachable + no dominating len/bound "
                    "guard; NOT an alloc sink (dedup vs RU2/alloc scanners)",
        "status": "advisory_needs_fuzz",
    }


def _detect_untrusted_ingress_panic(
    funcs: Iterable["RustFunction"],
    oob_axis: bool = False,
) -> list[Hit]:
    """Class-B (RU1) - untrusted-ingress param reaches an unguarded panic.

    Stage-1 predicate:
      * fn has >=1 untrusted-ingress param (name/type in the ingress set);
      * an ingress-referencing panic sink exists in the body
        (``ingress[i]`` / ``ingress[a..b]`` slice-index, ``.unwrap()`` /
        ``.expect(`` on an ingress-referencing line, or a ``panic!`` /
        ``unreachable!`` macro);
      * NO guard dominates the sink (no ``ingress.len()`` compare /
        ``is_some`` / ``is_ok`` / ``matches!`` / ``?`` / early ``return Err``
        textually before the sink).
    """
    hits: list[Hit] = []
    for fn in funcs:
        # A #[test]/#[cfg(test)]/#[rstest] fn (or a tests/ file) takes CONST
        # fixture params, not attacker ingress - do not fire on test code.
        if _is_test_context(fn):
            continue
        ingress = _ingress_params(fn)
        if not ingress:
            continue
        body_nc = _strip_comments(fn.body)
        lines = body_nc.splitlines()
        seen_off: set[int] = set()
        seen_off_oob: set[int] = set()
        for pe_name in ingress:
            pe = re.escape(pe_name)
            sinks: list[tuple[int, str]] = []
            # slice-index on the ingress var: bytes[i] / bytes[a..b]
            for m in re.finditer(rf"\b{pe}\s*\[[^\]\n]*\]", body_nc):
                sinks.append((m.start(), "slice_index"))
            # unwrap/expect on a line that references the ingress var
            for m in re.finditer(
                rf"\b{pe}\b[^\n;]*?\.\s*(?:unwrap|expect)\s*\(", body_nc
            ):
                sinks.append((m.start(), "unwrap_expect"))
            # NOTE: an UNTETHERED panic!/unreachable! sink was removed (2026-07-10):
            # it fired on ANY panic in an ingress-carrying fn regardless of a dataflow
            # link to the param, and a ws that uses panic! as its revert idiom (near:
            # 185 FPs) blew up. The real reachable-panic-on-untrusted-input signal is the
            # OPERAND-TETHERED sinks above (slice-index / unwrap-expect ON the ingress
            # var); a tethered panic (panic!("{}", bytes[i])) is already caught via its
            # inner slice/unwrap operand, so no coverage is lost.
            for off, kind in sinks:
                if _guard_dominates(body_nc, off, pe):
                    continue
                # An ingress-named local that is SERIALIZED/encoded here is an
                # OUTBOUND value (e.g. `to_vec(&payload).unwrap()`), not inbound
                # untrusted ingress - skip the outbound-serialize sink.
                if _sink_is_outbound_serialize(body_nc, off, pe):
                    continue
                if off in seen_off:
                    continue
                seen_off.add(off)
                line_off = body_nc[:off].count("\n")
                snippet = (
                    lines[line_off].strip()
                    if line_off < len(lines) else fn.header
                )
                hits.append(
                    Hit(
                        file=str(fn.file),
                        line=fn.body_start_line + line_off,
                        snippet=snippet[:200],
                        extra={
                            "function": fn.name,
                            "ingress_param": pe_name,
                            "sink_kind": kind,
                            "candidate_status": "default-to-kill",
                            "impact_contract": _impact_contract(),
                        },
                    )
                )

            # --- RU3 advisory rust-OOB axis (off unless oob_axis) -----------
            if not oob_axis:
                continue
            oob_sinks: list[tuple[int, str]] = []
            # (a) copy_from_slice ON the ingress buffer: dst.len()-mismatch panic
            #     (buf.copy_from_slice(..) / buf[..].copy_from_slice(..)).
            for m in re.finditer(
                rf"\b{pe}\s*(?:\[[^\]\n]*\])?\s*\.\s*copy_from_slice\s*\(",
                body_nc,
            ):
                oob_sinks.append((m.start(), "copy_from_slice"))
            # (b) range-index on a SEPARATE buffer whose bound refs the untrusted
            #     ingress param: other[a..b] with pe inside the range, other != pe.
            for m in re.finditer(r"\b([A-Za-z_]\w*)\s*\[([^\]\n]*\.\.[^\]\n]*)\]",
                                 body_nc):
                bufname, idx = m.group(1), m.group(2)
                if bufname == pe_name:
                    continue  # same buffer = RU1 slice_index territory
                if not re.search(rf"\b{pe}\b", idx):
                    continue  # bound does not reference untrusted ingress
                oob_sinks.append((m.start(), "slice_range"))
            for off, kind in oob_sinks:
                if _guard_dominates(body_nc, off, pe):
                    continue
                if off in seen_off_oob:
                    continue
                seen_off_oob.add(off)
                line_off = body_nc[:off].count("\n")
                sink_line = lines[line_off] if line_off < len(lines) else ""
                # A1 dedup boundary: alloc sinks belong to RU2 + alloc scanners.
                if _ALLOC_EXCLUDE_RE.search(sink_line):
                    continue
                snippet = sink_line.strip() if sink_line else fn.header
                covered_by = (
                    _RU1_SLICE_INDEX_PID if off in seen_off else None
                )
                hits.append(
                    Hit(
                        file=str(fn.file),
                        line=fn.body_start_line + line_off,
                        snippet=snippet[:200],
                        extra={
                            "function": fn.name,
                            "ingress_param": pe_name,
                            "sink_kind": kind,
                            "axis": "rust-OOB",
                            "candidate_status": "needs-fuzz",
                            "verdict": "needs-fuzz",
                            "covered_by": covered_by,
                            "impact_contract": _oob_impact_contract(),
                        },
                    )
                )
    return hits


# ---------------------------------------------------------------------------
# RU6 - advisory nondeterminism -> consensus-divergence axis
# ---------------------------------------------------------------------------
#
# OFF by default. Enable with AUDITOOR_RUST_NONDET_AXIS=1. Emits needs-fuzz
# hypotheses (NO-AUTO-CREDIT) to .auditooor/rust_nondet_hypotheses.jsonl - it
# never flips a gate or resolves a unit.
#
# Class: consensus-divergence (Rust analog of the Go
# go_wave1.cosmos_nondeterministic_map_iteration detector). std HashMap /
# HashSet iteration order is randomized per process; f32/f64 arith and
# SystemTime/Instant::now are host/time nondeterministic. If a validator /
# EL execution path feeds such a nondeterministic SOURCE into an
# ORDER-DEPENDENT sink (Vec push/extend, state/root/hash write, serialize)
# WITHOUT first sorting keys / using a BTreeMap / IndexMap, two nodes can
# derive different state -> apphash / block-hash divergence -> consensus
# halt.
#
# FP-guard (the teeth): HashMap iteration is pervasive and almost always
# benign (idempotent cache loads, membership checks). We do NOT fire on a
# bare map iteration - we require an ORDER-DEPENDENT sink INSIDE the map
# loop body (not any write). A `for a in m.keys() { load_cache(a) }`
# idempotent load is the negative control and MUST NOT fire. The f64 arm is
# gated to consensus/execution modules only (a UI/log float is not a
# consensus fault).
#
# DEDUP boundary (A1): the covered_by signal is NOT re-derived. This axis
# is the RUST analog of go_wave1.cosmos_nondeterministic_map_iteration; that
# detector only ever emits on `.go` sources, so the emitted-hit sets are
# disjoint by construction (this runner walks `.rs` only). Every hypothesis
# is tagged sibling_detector for transparency; covered_by stays None because
# no `.rs` hit can be a cosmos-`.go` duplicate.
_RUST_NONDET_AXIS_ENV = "AUDITOOR_RUST_NONDET_AXIS"
_RUST_NONDET_PATTERN_ID = "rust.nondet.consensus_divergence"
_RUST_NONDET_SIBLING = "go_wave1.cosmos_nondeterministic_map_iteration"

# Path gate for the f64/f32 arm: a float is only a consensus fault inside a
# consensus / execution / state-root module. A float in a metrics/log/rpc
# path is benign, so that arm stays silent there.
_CONSENSUS_PATH_RE = re.compile(
    r"(?:^|[/\\])(?:consensus|execution|engine[-_]?tree|state[-_]?root|"
    r"trie|payload|derive)(?:[/\\]|$|\.)"
)

# Map-specific iterator methods (Vec has no `.keys()`/`.values()`).
_MAP_METHOD_ITER_RE = re.compile(r"\.\s*(?:keys|values|values_mut)\s*\(\s*\)")

# Generic iterator methods - only a map source when HashMap/HashSet evidence
# is present in the same fn (a `.iter()` over a Vec is ordered/benign).
_GENERIC_ITER_RE = re.compile(r"\.\s*(?:iter|iter_mut|into_iter|drain)\s*\(")

# std HashMap / HashSet evidence in-fn (distinguishes from an ordered map).
_HASHMAP_TYPE_RE = re.compile(
    r"\bHashMap\s*<|\bHashSet\s*<|\bHashMap::new|\bHashSet::new"
    r"|:\s*&?\s*(?:mut\s+)?HashMap\b|:\s*&?\s*(?:mut\s+)?HashSet\b"
)

# Determinism guard: sorting the keys, or using an ordered/insertion-ordered
# map, makes the iteration deterministic -> suppress.
_DETERMINISM_GUARD_RE = re.compile(
    r"\bBTreeMap\b|\bBTreeSet\b|\bIndexMap\b|\bIndexSet\b"
    r"|\.\s*sort(?:_by|_by_key|_unstable|_unstable_by|_unstable_by_key)?\s*\("
    r"|\bsort_keys\b|\.\s*sorted(?:_by|_by_key)?\s*\("
)

# ORDER-DEPENDENT sink (the teeth). A bare write is NOT enough - the sink
# must be one whose RESULT depends on the order elements arrive in:
#   * Vec growth: push / extend / extend_from_slice / append
#   * a consensus root/hash assignment (specific names, NOT bare `hash =`
#     which matches innocent `let tx_hash = ...`)
#   * a streaming hasher fed in-order: .update( / .finalize(
#   * serialization / encoding of the accumulated order
_ORDERED_SINK_RE = re.compile(
    r"\.\s*push\s*\("
    r"|\.\s*extend(?:_from_slice)?\s*\("
    r"|\.\s*append\s*\("
    r"|\b(?:state_root|app_hash|apphash|block_hash|merkle_root|state_hash|"
    r"commitment|accumulator)\s*=(?!=)"
    r"|\.\s*update\s*\("
    r"|\.\s*finalize\s*\("
    r"|\bkeccak256\s*\("
    r"|\bserialize\w*\s*\("
    r"|\.\s*encode\w*\s*\("
)

# NARROW consensus-state sink for the float/time arms. A wall-clock value or a
# float pushed to a metrics/log Vec is benign; the divergence fault is the
# value being written into a consensus ROOT/HASH, fed to a streaming hasher, or
# serialized into a block. So these arms drop the loose push/extend/append that
# the map arm keeps (a hashmap-order Vec-collect IS the map-arm bug) and require
# a root/hash write / hasher / serialize sink.
_STATE_SINK_RE = re.compile(
    r"\b(?:state_root|app_hash|apphash|block_hash|merkle_root|state_hash|"
    r"commitment|accumulator)\s*=(?!=)"
    r"|\.\s*update\s*\("
    r"|\.\s*finalize\s*\("
    r"|\bkeccak256\s*\("
    r"|\bserialize\w*\s*\("
)

# for-loop header up to the opening `{` of its body.
_FOR_HEADER_RE = re.compile(
    r"\bfor\s+(?P<pat>[^\n{]+?)\s+in\s+(?P<expr>[^{\n]+?)\s*\{"
)

# f32/f64 arithmetic: a float token adjacent to an arithmetic operator, or
# an `as f64` cast feeding arithmetic. Presence-only is too loose, so we
# require a float token AND an arith op in the body.
_FLOAT_TOKEN_RE = re.compile(r"\b(?:f32|f64)\b")
_ARITH_OP_RE = re.compile(r"[+\-*/]\s*[A-Za-z0-9_.(]|\.\s*(?:powf|sqrt|ln|exp|sin|cos)\s*\(")

# SystemTime / Instant nondeterministic time source. NOTE: ``.elapsed()`` is
# deliberately excluded - it is a duration measurement that is almost always a
# metrics/latency read, not a wall-clock value written into consensus state.
_TIME_NOW_RE = re.compile(
    r"\b(?:SystemTime|Instant)\s*::\s*now\s*\("
    r"|\b(?:unix_timestamp|current_timestamp|now_millis|now_ms)\s*\("
)


def _nondet_axis_enabled() -> bool:
    return os.environ.get(_RUST_NONDET_AXIS_ENV, "").strip().lower() in {
        "1", "true", "yes", "on",
    }


def _is_map_iter_expr(expr: str, body_nc: str) -> bool:
    """True if the for-loop iterand ``expr`` is a std HashMap/HashSet
    iteration (order-random per process). ``.keys()``/``.values()`` are
    map-specific; a bare binding or ``.iter()`` needs in-fn HashMap
    evidence."""
    if _MAP_METHOD_ITER_RE.search(expr):
        return True
    if _HASHMAP_TYPE_RE.search(body_nc):
        if _GENERIC_ITER_RE.search(expr):
            return True
        m = re.match(r"^\s*&?\s*(?:mut\s+)?([A-Za-z_][\w.]*)\s*$", expr)
        if m:
            binding = m.group(1).split(".")[-1]
            be = re.escape(binding)
            if re.search(
                rf"\b{be}\b\s*:\s*&?\s*(?:mut\s+)?(?:HashMap|HashSet)\b",
                body_nc,
            ) or re.search(
                rf"\blet\s+(?:mut\s+)?{be}\b[^;]*(?:HashMap|HashSet)",
                body_nc,
            ):
                return True
    return False


def _iter_for_loops(body_nc: str):
    """Yield (header_start_off, loop_body_text, iterand_expr) for each
    ``for .. in EXPR { .. }`` loop in ``body_nc``."""
    for m in _FOR_HEADER_RE.finditer(body_nc):
        brace_idx = m.end() - 1  # position of the `{`
        end = _balance_braces(body_nc, brace_idx)
        if end is None:
            continue
        loop_body = body_nc[brace_idx + 1:end - 1]
        yield m.start(), loop_body, m.group("expr").strip()


def _nondet_impact_contract() -> dict:
    return {
        "class": "consensus_divergence",
        "impact": "nondeterministic source (hashmap-order / float / wall-clock) "
                  "feeds an order-dependent sink -> nodes derive different "
                  "state -> apphash/block-hash divergence -> consensus halt",
        "requires": "source reachable on a validator/EL execution path + "
                    "no sort/BTreeMap/IndexMap determinism guard",
        "status": "advisory_needs_fuzz",
    }


def _detect_nondeterminism_consensus(
    funcs: Iterable["RustFunction"],
) -> list[Hit]:
    """RU6 (advisory) - nondeterministic source -> order-dependent sink.

    Stage-1 predicate (per fn):
      * a nondeterministic SOURCE is present:
          (map) a ``for .. in <HashMap/HashSet iteration>`` loop, OR
          (float) f32/f64 arithmetic in a consensus/execution module, OR
          (time) ``SystemTime::now()`` / ``Instant::now()`` / ``.elapsed()``;
      * an ORDER-DEPENDENT sink is reachable from that source (for the map
        arm the sink must be INSIDE the map-loop body; for float/time the
        sink is anywhere in the fn body);
      * NO determinism guard (``BTreeMap`` / ``IndexMap`` / ``.sort*()``).

    All hits are advisory (verdict=needs-fuzz, NO-AUTO-CREDIT).
    """
    hits: list[Hit] = []
    for fn in funcs:
        body_nc = _strip_comments(fn.body)
        # The map/ordered-map TYPE is frequently declared in the signature
        # (param/return), not the body, so scan params+body for the
        # determinism guard and for the HashMap evidence.
        sig_and_body = fn.params + "\n" + body_nc
        if _DETERMINISM_GUARD_RE.search(sig_and_body):
            # keys are sorted / an ordered map (BTreeMap/IndexMap) is used
            # -> iteration is deterministic.
            continue
        path = str(fn.file).replace("\\", "/")
        in_consensus = bool(_CONSENSUS_PATH_RE.search("/" + path))

        # --- map arm: sink must live INSIDE the hashmap-loop body ---------
        for hdr_off, loop_body, expr in _iter_for_loops(body_nc):
            if not _is_map_iter_expr(expr, sig_and_body):
                continue
            sink = _ORDERED_SINK_RE.search(loop_body)
            if not sink:
                continue  # bare/idempotent map loop = negative control
            line_off = body_nc[:hdr_off].count("\n")
            src_lines = body_nc.splitlines()
            snippet = (
                src_lines[line_off].strip()
                if line_off < len(src_lines) else fn.header
            )
            hits.append(Hit(
                file=str(fn.file),
                line=fn.body_start_line + line_off,
                snippet=snippet[:200],
                extra={
                    "function": fn.name,
                    "source_kind": "hashmap_iteration",
                    "sink": sink.group(0).strip()[:40],
                    "axis": "rust-nondet",
                    "verdict": "needs-fuzz",
                    "candidate_status": "needs-fuzz",
                    "covered_by": None,
                    "sibling_detector": _RUST_NONDET_SIBLING,
                    "impact_contract": _nondet_impact_contract(),
                },
            ))

        # --- float arm: gated to consensus/execution modules only --------
        if in_consensus and _FLOAT_TOKEN_RE.search(body_nc) \
                and _ARITH_OP_RE.search(body_nc):
            sink = _STATE_SINK_RE.search(body_nc)
            if sink:
                fm = _FLOAT_TOKEN_RE.search(body_nc)
                line_off = body_nc[:fm.start()].count("\n")
                src_lines = body_nc.splitlines()
                snippet = (
                    src_lines[line_off].strip()
                    if line_off < len(src_lines) else fn.header
                )
                hits.append(Hit(
                    file=str(fn.file),
                    line=fn.body_start_line + line_off,
                    snippet=snippet[:200],
                    extra={
                        "function": fn.name,
                        "source_kind": "float_arith",
                        "sink": sink.group(0).strip()[:40],
                        "axis": "rust-nondet",
                        "verdict": "needs-fuzz",
                        "candidate_status": "needs-fuzz",
                        "covered_by": None,
                        "sibling_detector": _RUST_NONDET_SIBLING,
                        "impact_contract": _nondet_impact_contract(),
                    },
                ))

        # --- time arm: wall-clock source into a consensus-state sink -----
        # Path-gated (like the float arm) + narrow state-sink: a timestamp
        # pushed to a metrics/latency Vec is benign; only a wall-clock value
        # written into a root/hash / hasher / serialize sink can diverge.
        tm = _TIME_NOW_RE.search(body_nc) if in_consensus else None
        if tm and _STATE_SINK_RE.search(body_nc):
            sink = _STATE_SINK_RE.search(body_nc)
            line_off = body_nc[:tm.start()].count("\n")
            src_lines = body_nc.splitlines()
            snippet = (
                src_lines[line_off].strip()
                if line_off < len(src_lines) else fn.header
            )
            hits.append(Hit(
                file=str(fn.file),
                line=fn.body_start_line + line_off,
                snippet=snippet[:200],
                extra={
                    "function": fn.name,
                    "source_kind": "wall_clock",
                    "sink": sink.group(0).strip()[:40],
                    "axis": "rust-nondet",
                    "verdict": "needs-fuzz",
                    "candidate_status": "needs-fuzz",
                    "covered_by": None,
                    "sibling_detector": _RUST_NONDET_SIBLING,
                    "impact_contract": _nondet_impact_contract(),
                },
            ))
    return hits


# ---------------------------------------------------------------------------
# RU7 - advisory lock-poison panic-while-holding axis
# ---------------------------------------------------------------------------
#
# OFF by default. Enable with AUDITOOR_RUST_LOCKPOISON_AXIS=1. Emits
# needs-fuzz hypotheses (NO-AUTO-CREDIT) to
# .auditooor/rust_lockpoison_hypotheses.jsonl - it never flips a gate or
# resolves a unit.
#
# Class: lock-poison DoS. A std::sync Mutex/RwLock guard is bound, >=1 field
# is written THROUGH the guard, and then a panic-capable op (unwrap / expect /
# index / checked-less arith) is reachable BEFORE the guard drops. If that op
# panics while the guard is held, the lock is POISONED. Every subsequent
# `.lock().expect(...)` / `.unwrap()` on the same lock then panics -> the
# guarded state machine is permanently wedged (DoS). The precondition for the
# poison to matter is the partial guarded write: state is left half-updated
# AND the lock is dead.
#
# FP-guard (the teeth): gate to std::sync ONLY. parking_lot's Mutex/RwLock do
# NOT poison, so a parking_lot guard is out of class. The tell is that std
# `.lock()`/`.read()`/`.write()` return a Result the caller must unwrap
# (`.unwrap()`/`.expect(`/`?`), whereas parking_lot returns the guard directly
# with no Result. We therefore require the guard binding to (a) call
# `.lock()`/`.read()`/`.write()` with EMPTY parens (rules out io::Read/Write
# whose read/write take a buffer arg) AND (b) immediately handle a Result
# (`.unwrap()`/`.expect(`/`?`). An explicit `drop(<guard>)` before the panic
# op releases the lock -> suppressed.
#
# NOTE (advisory-first): the broader "partial-write-persists even without a
# panic" branch (a guarded write followed by an early `return` that leaves the
# set half-updated) is deliberately NOT emitted here - it is a wider, noisier
# class. This axis stays on the narrow poison-panic shape.
#
# DEDUP boundary (A1): the covered_by signal is NOT re-derived. When a RU7
# panic op lands at the SAME (file,line) already emitted by the RU1 detector
# (rust.panic.untrusted_ingress_unguarded_panic), we tag covered_by with the
# RU1 pattern id by matching against RU1's EMITTED hit set (passed in) - we do
# not recompute whether the sink is untrusted-ingress. RU7's net-new signal is
# the guarded/poison context, which RU1 never models.
_RUST_LOCKPOISON_AXIS_ENV = "AUDITOOR_RUST_LOCKPOISON_AXIS"
_RUST_LOCKPOISON_PATTERN_ID = "rust.lockpoison.panic_while_holding_guard"
_RUST_LOCKPOISON_SIBLING = "rust.panic.untrusted_ingress_unguarded_panic"

# std::sync guard binding. Empty-parens `.lock()`/`.read()`/`.write()` (rules
# out io Read/Write which take a buffer arg) + Result handling
# (`.unwrap()`/`.expect(`/`?`) = the std-poisonable tell (parking_lot returns
# the guard directly, no Result).
_LOCKPOISON_GUARD_BIND = re.compile(
    r"\blet\s+(?:mut\s+)?(?P<g>[A-Za-z_]\w*)\s*=\s*"
    r"(?P<recv>[^;=\n{}]+?)"
    r"\.\s*(?P<m>lock|read|write)\s*\(\s*\)\s*"
    r"(?:\.\s*unwrap\s*\(\s*\)|\.\s*expect\s*\([^;\n]*?\)|\?)"
)

# Panic-capable op reachable after a guarded write (before the guard drops).
#   * `.unwrap()`  (empty parens -> not `.unwrap_or*`)
#   * `.expect(`
#   * an index expression `ident[...]` (OOB panic)
#   * checked-less arith: `.len() -` underflow (unsigned len minus x).
_LOCKPOISON_PANIC_OP = re.compile(
    r"\.\s*unwrap\s*\(\s*\)"
    r"|\.\s*expect\s*\("
    r"|\b[A-Za-z_]\w*\s*\[[^\]\n;{}]*\]"
    r"|\.\s*len\s*\(\s*\)\s*-\s*"
)


def _lockpoison_axis_enabled() -> bool:
    return os.environ.get(_RUST_LOCKPOISON_AXIS_ENV, "").strip().lower() in {
        "1", "true", "yes", "on",
    }


def _lockpoison_impact_contract() -> dict:
    return {
        "class": "lock_poison_panic_while_holding",
        "impact": "a panic while a std::sync guard is held (after a partial "
                  "guarded write) POISONS the lock -> every later "
                  "lock().unwrap()/expect() panics -> guarded state machine "
                  "permanently wedged (DoS)",
        "requires": "std::sync Mutex/RwLock (NOT parking_lot) + >=1 guarded "
                    "field write + a panic-capable op reachable before the "
                    "guard drops + the panic externally triggerable",
        "status": "advisory_needs_fuzz",
    }


def _detect_lockpoison_panic_while_holding(
    funcs: Iterable["RustFunction"],
    ru1_covered: set | None = None,
) -> list[Hit]:
    """RU7 (advisory) - panic-capable op reachable while a std::sync guard is
    held after a partial guarded write.

    Stage-1 predicate (per guard binding in a fn):
      * a std::sync Mutex/RwLock guard is bound (empty-parens
        `.lock()`/`.read()`/`.write()` + Result handling - the poison tell
        that excludes parking_lot);
      * >=1 field is written THROUGH the guard after the binding
        (`g.field = / += / .push( / .insert( ...`);
      * a panic-capable op (`.unwrap()` / `.expect(` / `ident[..]` /
        `.len() -`) is reachable AFTER that first write and BEFORE the guard
        is explicitly dropped.

    All hits are advisory (verdict=needs-fuzz, NO-AUTO-CREDIT).
    """
    ru1_covered = ru1_covered or set()
    hits: list[Hit] = []
    for fn in funcs:
        body_nc = _strip_comments(fn.body)
        for bm in _LOCKPOISON_GUARD_BIND.finditer(body_nc):
            g = bm.group("g")
            ge = re.escape(g)
            bind_end = bm.end()
            # first field WRITE through the guard after the binding.
            wmatch = re.search(
                rf"\b{ge}\s*\.\s*\w+\s*(?:=(?!=)|\+=|-=|\*=|/=|"
                rf"\.\s*(?:push|insert|remove|pop|clear|extend|append|"
                rf"swap_remove|retain|truncate|drain)\s*\()",
                body_nc[bind_end:],
            )
            if not wmatch:
                continue
            write_abs_end = bind_end + wmatch.end()
            # explicit drop of the guard closes the poison window.
            drop_m = re.search(rf"\bdrop\s*\(\s*{ge}\s*\)", body_nc[write_abs_end:])
            pregion_end = (
                write_abs_end + drop_m.start() if drop_m else len(body_nc)
            )
            pregion = body_nc[write_abs_end:pregion_end]
            pm = _LOCKPOISON_PANIC_OP.search(pregion)
            if not pm:
                continue
            panic_abs = write_abs_end + pm.start()
            line_off = body_nc[:panic_abs].count("\n")
            src_lines = body_nc.splitlines()
            snippet = (
                src_lines[line_off].strip()
                if line_off < len(src_lines) else fn.header
            )
            hit_line = fn.body_start_line + line_off
            # A1 dedup: tag covered_by from RU1's EMITTED hit set only.
            covered_by = (
                _RUST_LOCKPOISON_SIBLING
                if (str(fn.file), hit_line) in ru1_covered else None
            )
            hits.append(Hit(
                file=str(fn.file),
                line=hit_line,
                snippet=snippet[:200],
                extra={
                    "function": fn.name,
                    "guard_var": g,
                    "lock_method": bm.group("m"),
                    "panic_op": pm.group(0).strip()[:40],
                    "axis": "rust-lockpoison",
                    "verdict": "needs-fuzz",
                    "candidate_status": "needs-fuzz",
                    "covered_by": covered_by,
                    "sibling_detector": _RUST_LOCKPOISON_SIBLING,
                    "impact_contract": _lockpoison_impact_contract(),
                },
            ))
    return hits


# ---------------------------------------------------------------------------
# RU9 - advisory str byte-slice char-boundary panic axis
# ---------------------------------------------------------------------------
#
# OFF by default. Enable with AUDITOOR_RUST_STRSLICE_AXIS=1. Emits needs-fuzz
# hypotheses (NO-AUTO-CREDIT) to .auditooor/rust_strslice_hypotheses.jsonl - it
# never flips a gate or resolves a unit.
#
# Class: str/String slice on a NON char-boundary byte index -> panic (DoS).
# Rust panics if `s[a..b]` on a str is cut at a byte that is not a UTF-8 char
# boundary. A `.len()` check proves the byte index is IN RANGE but says NOTHING
# about char boundaries - a multibyte char (e.g. a 2-4 byte UTF-8 sequence)
# straddling index a or b aborts the process. FIRE when a str/String-typed var
# is sliced by a byte-range `[a..b]`/`[..b]`/`[a..]` and the enclosing fn has NO
# char-boundary guard (is_char_boundary / char_indices / chars / a fixed-length
# ASCII-delimiter prefix). The char-boundary insight: byte-`.len()` is a
# NON-guard here (that is exactly the RU1/RU2 vs RU9 dedup boundary).
#
# FP-guard (the teeth): ASCII-guaranteed slices are benign. A slice whose bounds
# are all numeric literals (or empty) AND that follows a `starts_with(..)` /
# `strip_prefix(..)` / `.is_ascii*` guard on the same var (e.g. a hex `0x`
# prefix, a backtick delimiter) cuts inside a KNOWN ASCII prefix, so no
# multibyte char can straddle it -> suppressed. Any is_char_boundary /
# char_indices / .chars() token in the fn body also suppresses (author has
# modelled the boundary). A len-derived bound (`s[1..s.len()-1]`) is NOT ASCII-
# guaranteed and fires (the natural near near_fmt::Bytes::from_str instance).
#
# DEDUP boundary (A1): the covered_by signal is NOT re-derived. RU1
# (rust.panic.untrusted_ingress_unguarded_panic) only fires on BYTE-typed
# ingress vars (&[u8]/Vec<u8> or ingress-named); RU9 is STR-typed. When a str
# param happens to also be RU1-named (e.g. `data: &str`) and a RU9 slice lands
# at the SAME (file,line) already emitted by RU1, we tag covered_by with the RU1
# pattern id by matching against RU1's EMITTED hit set (passed in) - never
# recomputing the RU1 verdict. RU9's net-new signal is the char-boundary
# reasoning, which RU1 never models.
_RUST_STRSLICE_AXIS_ENV = "AUDITOOR_RUST_STRSLICE_AXIS"
_RUST_STRSLICE_PATTERN_ID = "rust.panic.str_byte_slice_char_boundary"
_RUST_STRSLICE_SIBLING = "rust.panic.untrusted_ingress_unguarded_panic"

# A str/String-ish type in a param or a let annotation. `(?<![:\w])String`
# rules out OsString / a `str` inside a longer ident.
_STR_TYPE_RE = re.compile(
    r"&\s*(?:'[a-z_]\w*\s+)?(?:mut\s+)?str\b"     # &str / &'a str / &mut str
    r"|(?<![:\w])String\b"                          # String / &String
    r"|\bCow\s*<[^>]*\bstr\b"                        # Cow<'_, str>
    r"|\bBox\s*<\s*str\s*>"
    r"|\b(?:Arc|Rc)\s*<\s*str\s*>"
)

# Container carriers that merely CONTAIN a String are NOT str-sliceable in the
# char-boundary sense (`Vec<String>[a..b]` yields a &[String], no boundary
# panic). Exclude them so a `names: Vec<String>` param is not mis-typed as str.
_STR_CONTAINER_EXCLUDE_RE = re.compile(
    r"\bVec\s*<|\bHashMap\b|\bBTreeMap\b|\bHashSet\b|\bBTreeSet\b|\[\s*String"
)

# let-bound str: explicit annotation OR an RHS that yields a str/String.
_STR_LET_RE = re.compile(
    r"\blet\s+(?:mut\s+)?(?P<n>[A-Za-z_]\w*)\s*"
    r"(?::\s*&\s*(?:'[a-z_]\w*\s+)?(?:mut\s+)?str\b"
    r"|:\s*String\b"
    r"|=\s*[^;\n]*?\.\s*(?:as_str|to_string|to_owned|to_str|trim|trim_start|"
    r"trim_end|trim_matches)\s*\()"
)

# Char-boundary guard tokens: the author has reasoned about UTF-8 boundaries.
_CHAR_BOUNDARY_GUARD_RE = re.compile(
    r"\bis_char_boundary\s*\("
    r"|\bchar_indices\s*\("
    r"|\.\s*chars\s*\(\s*\)"
    r"|\bfloor_char_boundary\s*\("
    r"|\bceil_char_boundary\s*\("
)


def _strslice_axis_enabled() -> bool:
    return os.environ.get(_RUST_STRSLICE_AXIS_ENV, "").strip().lower() in {
        "1", "true", "yes", "on",
    }


def _str_typed_vars(fn: "RustFunction", body_nc: str) -> list[str]:
    """Names of vars in ``fn`` that are str/String-typed (param annotation,
    let annotation, or a str-yielding RHS)."""
    names: list[str] = []
    for name, ptype in _split_params(fn.params):
        if _STR_CONTAINER_EXCLUDE_RE.search(ptype):
            continue
        if _STR_TYPE_RE.search(ptype):
            names.append(name)
    for m in _STR_LET_RE.finditer(body_nc):
        n = m.group("n")
        if n and n not in names:
            names.append(n)
    return names


def _is_ascii_guaranteed_slice(idx: str, pre: str, ve: str) -> bool:
    """True if the str slice is ASCII-guaranteed (benign):

      (a) its bounds are all numeric literals (or empty) AND a fixed
          ASCII-delimiter/prefix guard on the same var (``starts_with`` /
          ``strip_prefix`` / ``.is_ascii*``) precedes it (a hex ``0x`` prefix,
          a backtick delimiter); OR
      (b) the strip-matched-prefix idiom ``ve[X.len()..]`` guarded by a
          preceding ``ve.starts_with(X)`` - the matched prefix ends on a char
          boundary, so the suffix slice cannot cut a multibyte char.

    A len-/ident-derived bound with no matching prefix guard is NOT
    ASCII-guaranteed."""
    bounds = idx.split("..")
    # (b) strip-matched-prefix idiom: ve[X.len()..] after ve.starts_with(X).
    if len(bounds) == 2 and bounds[1].strip() == "":
        lo = bounds[0].strip()
        mlo = re.fullmatch(r"([A-Za-z_]\w*)\s*\.\s*len\s*\(\s*\)", lo)
        if mlo and re.search(
            rf"\b{ve}\s*\.\s*starts_with\s*\(\s*&?\s*{re.escape(mlo.group(1))}\b",
            pre,
        ):
            return True
    # (a) literal-only bounds after an ASCII prefix/delimiter guard.
    lit_only = all(b.strip() == "" or b.strip().isdigit() for b in bounds)
    if not lit_only:
        return False
    if re.search(rf"\b{ve}\s*\.\s*starts_with\s*\(", pre):
        return True
    if re.search(rf"\b{ve}\s*\.\s*strip_prefix\s*\(", pre):
        return True
    if re.search(rf"\b{ve}\s*\.\s*is_ascii", pre):
        return True
    return False


# A byte-array / byte-slice / Vec rebinding of the same name (shadowing). When a
# str-typed param `seed: &str` is later shadowed by `let mut seed: [u8; N]` the
# slice `seed[..len]` is on the BYTE shadow (RU1/RU2 territory), NOT the str -
# the char-boundary class does not apply. Matches `let (mut) v: [..`,
# `let (mut) v = [..`, `let (mut) v = vec![..`, and `let (mut) v: &[..`.
_BYTE_SHADOW_RE_TMPL = (
    r"\blet\s+(?:mut\s+)?{ve}\s*"
    r"(?::\s*(?:&\s*(?:mut\s+)?)?\[|=\s*(?:&\s*)?\[|=\s*vec!\s*\[)"
)


def _strslice_impact_contract() -> dict:
    return {
        "class": "str_byte_slice_char_boundary_panic",
        "impact": "a str/String sliced at a byte index whose only guard is "
                  ".len() panics when the index is not a UTF-8 char boundary "
                  "(multibyte input) -> DoS/abort",
        "requires": "attacker-influenced str content reaches the slice + no "
                    "is_char_boundary/char_indices/chars/ascii-delimiter guard",
        "status": "advisory_until_harnessed",
    }


def _detect_str_byte_slice_char_boundary(
    funcs: Iterable["RustFunction"],
    ru1_covered: set | None = None,
) -> list[Hit]:
    """RU9 (advisory) - str/String byte-range slice with only a ``.len()``
    guard (no char-boundary guard) -> non-boundary slice panic.

    Stage-1 predicate (per str-typed var in a fn):
      * the var is str/String-typed (param/let annotation or str-yielding RHS);
      * it is sliced by a byte-range ``v[a..b]`` / ``v[..b]`` / ``v[a..]``
        (a whole-range ``v[..]`` is skipped);
      * the enclosing fn has NO char-boundary guard
        (is_char_boundary / char_indices / .chars() / floor|ceil_char_boundary);
      * the slice is not ASCII-guaranteed (literal-only bounds after a
        starts_with / strip_prefix / is_ascii prefix guard).

    All hits are advisory (verdict=needs-fuzz, NO-AUTO-CREDIT).
    """
    ru1_covered = ru1_covered or set()
    hits: list[Hit] = []
    for fn in funcs:
        body_nc = _strip_comments(fn.body)
        # char-boundary guard anywhere in the fn body -> author modelled it.
        if _CHAR_BOUNDARY_GUARD_RE.search(body_nc):
            continue
        str_vars = _str_typed_vars(fn, body_nc)
        if not str_vars:
            continue
        lines = body_nc.splitlines()
        seen_off: set[int] = set()
        for vname in str_vars:
            ve = re.escape(vname)
            for m in re.finditer(
                rf"\b{ve}\s*\[(?P<idx>[^\]\n]*\.\.[^\]\n]*)\]", body_nc
            ):
                idx = m.group("idx").strip()
                if idx in ("", ".."):
                    continue  # whole-range slice, no byte-index panic
                pre = body_nc[:m.start()]
                # byte-array/vec shadow of the same name -> not a str slice.
                if re.search(_BYTE_SHADOW_RE_TMPL.format(ve=ve), pre):
                    continue
                if _is_ascii_guaranteed_slice(idx, pre, ve):
                    continue
                off = m.start()
                if off in seen_off:
                    continue
                seen_off.add(off)
                line_off = body_nc[:off].count("\n")
                snippet = (
                    lines[line_off].strip()
                    if line_off < len(lines) else fn.header
                )
                hit_line = fn.body_start_line + line_off
                covered_by = (
                    _RUST_STRSLICE_SIBLING
                    if (str(fn.file), hit_line) in ru1_covered else None
                )
                hits.append(Hit(
                    file=str(fn.file),
                    line=hit_line,
                    snippet=snippet[:200],
                    extra={
                        "function": fn.name,
                        "str_var": vname,
                        "slice_index": idx[:60],
                        "axis": "rust-strslice",
                        "verdict": "needs-fuzz",
                        "candidate_status": "needs-fuzz",
                        "covered_by": covered_by,
                        "sibling_detector": _RUST_STRSLICE_SIBLING,
                        "impact_contract": _strslice_impact_contract(),
                    },
                ))
    return hits


# ---------------------------------------------------------------------------
# RU10 - advisory crypto-fn missing CryptoRng bound (weak-entropy) axis
# ---------------------------------------------------------------------------
#
# OFF by default. Enable with AUDITOOR_RUST_ENTROPY_AXIS=1. Emits needs-fuzz
# hypotheses (NO-AUTO-CREDIT) to .auditooor/rust_entropy_hypotheses.jsonl - it
# never flips a gate or resolves a unit.
#
# Class: weak / attacker-predictable entropy in a crypto routine. A fn whose
# name signals a secret-drawing crypto op (sign / prove / nonce / keygen) is
# generic over `RngCore` but does NOT constrain it with a `+ CryptoRng` bound
# (arm A), OR it draws its randomness from an explicitly-weak source
# (SmallRng / thread_rng-seeded / seed_from_u64) inside a crypto module
# (arm B). Without the CryptoRng bound the caller may pass a deterministic /
# low-entropy RNG, so the per-signature nonce becomes predictable - and a
# predictable Schnorr/CLSAG/ECDSA nonce leaks the signing key (nonce reuse ->
# key recovery). monero-oxide's `sign_core<R: RngCore + CryptoRng>` is the
# secure CONTROL: the bound is present, so arm A stays silent; dropping the
# `+ CryptoRng` (the injected mutation) fires it.
#
# FP-guard (the teeth): a bare `RngCore` bound is pervasive and mostly benign
# (test helpers, non-crypto shufflers). The CryptoRng-bound regex is FP-prone
# on generic non-crypto fns, so we require BOTH (a) crypto scope - the file
# path is a crypto crate OR the body references curve/scalar/key primitives -
# AND (b) a scalar/nonce SAMPLE actually drawn in the body
# (Scalar::random / .random( / fill_bytes / nonce / gen(). A generic
# `fn sign<R: RngCore>` with no secret draw (e.g. a message-signing wrapper
# that hashes only) is out of class and stays silent.
#
# DEDUP boundary (A1): the covered_by signal is NOT re-derived. When an RU10
# hit lands at the SAME (file,line) already emitted by the RU1 detector
# (rust.panic.untrusted_ingress_unguarded_panic) we tag covered_by with the
# RU1 pattern id by matching against RU1's EMITTED hit set (passed in) - we do
# not recompute the RU1 verdict. RU10's net-new signal is the entropy-bound
# reasoning, which RU1 never models; in practice a crypto sign fn is not an
# untrusted-ingress panic sink so the sets are disjoint (covered_by=None).
_RUST_ENTROPY_AXIS_ENV = "AUDITOOR_RUST_ENTROPY_AXIS"
_RUST_ENTROPY_PATTERN_ID = "rust.entropy.crypto_fn_missing_cryptorng_bound"
_RUST_ENTROPY_SIBLING = "rust.panic.untrusted_ingress_unguarded_panic"

# fn-name shape signalling a secret-drawing crypto op. Segment-anchored so
# `sign_core` / `gen_nonce` / `keygen` fire but `assign` / `design` /
# `signature` (no `_`/end after the token) do NOT.
_CRYPTO_FN_NAME_RE = re.compile(r"(?:^|_)(?:sign|prove|nonce|keygen)(?:_|$)")

# `RngCore` / `CryptoRng` trait bounds anywhere in the signature (generics or
# a where-clause both live inside `fn.sig`).
_RNGCORE_BOUND_RE = re.compile(r"\bRngCore\b")
_CRYPTORNG_BOUND_RE = re.compile(r"\bCryptoRng\b")

# arm B: an explicitly-weak / seedable RNG drawn in the body.
_WEAK_RNG_RE = re.compile(
    r"\bSmallRng\b"
    r"|\bthread_rng\s*\("
    r"|\bseed_from_u64\s*\("
    r"|\bXorShiftRng\b"
    r"|\bChaCha\w*Rng::from_seed\b"
)

# crypto scope arm (a): the file path is a crypto crate/module.
_CRYPTO_SCOPE_PATH_RE = re.compile(
    r"(?:^|[/\\])(?:clsag|mlsag|ringct|bulletproofs?|borromean|crypto|"
    r"schnorr|ecdsa|eddsa|ed25519|ristretto|dalek|frost|dkg|"
    r"monero-oxide)(?:[/\\]|$|[._-])"
)

# crypto scope arm (b): the body references curve/scalar/key primitives.
_CRYPTO_SCOPE_BODY_RE = re.compile(
    r"\bScalar\b|\bEdwardsPoint\b|\bRistretto\w*\b|\bMontgomery\b"
    r"|\bSecretKey\b|\bPrivateKey\b|\bSigningKey\b|\bKeyPair\b"
    r"|\bCompressedEdwards\w*\b|\bScalar::random\b"
)

# FP-guard (b): a scalar/nonce SAMPLE actually drawn in the body. Without an
# entropy draw the missing bound is inert, so we require one.
_CRYPTO_SAMPLE_RE = re.compile(
    r"\bScalar::random\b"
    r"|\brandom_scalar\b"
    r"|\.\s*random\s*\("
    r"|\bnonce\b"
    r"|\bfill_bytes\s*\("
    r"|\.\s*gen\s*\(\s*\)"
    r"|\bgen_range\s*\("
    r"|\bsample\s*\("
    r"|\brandom_nonzero\w*\b"
    r"|\bfrom_rng\s*\("
)


def _entropy_axis_enabled() -> bool:
    return os.environ.get(_RUST_ENTROPY_AXIS_ENV, "").strip().lower() in {
        "1", "true", "yes", "on",
    }


def _entropy_impact_contract() -> dict:
    return {
        "class": "crypto_fn_missing_cryptorng_bound",
        "impact": "a crypto sign/prove/nonce/keygen fn generic over RngCore "
                  "without a CryptoRng bound (or drawing from a weak/seedable "
                  "RNG) can be handed low-entropy randomness -> predictable "
                  "per-signature nonce -> signing-key recovery",
        "requires": "crypto scope (crypto crate/module or curve/scalar/key "
                    "primitives) + an actual scalar/nonce sample in the body "
                    "+ no `+ CryptoRng` bound (arm A) or a weak RNG source "
                    "(arm B); a real fuzz/PoC must confirm the caller can "
                    "supply weak entropy",
        "status": "advisory_needs_fuzz",
    }


def _detect_crypto_fn_missing_cryptorng(
    funcs: Iterable["RustFunction"],
    ru1_covered: set | None = None,
) -> list[Hit]:
    """RU10 (advisory) - a crypto sign/prove/nonce/keygen fn lacks a CryptoRng
    entropy bound (or draws from a weak RNG) while sampling a secret scalar.

    Stage-1 predicate (per fn):
      * fn name signals a secret-drawing crypto op (sign / prove / nonce /
        keygen, segment-anchored);
      * it is generic over ``RngCore`` (arm A) OR its body draws from an
        explicitly-weak RNG (``SmallRng`` / ``thread_rng`` / ``seed_from_u64``,
        arm B);
      * FP-guard: crypto scope (crypto crate path OR curve/scalar/key
        primitive in the body) AND an actual scalar/nonce SAMPLE in the body;
      * the defect: arm A fires only when NO ``+ CryptoRng`` bound is present
        (a ``RngCore + CryptoRng`` fn is the secure control and stays silent);
        arm B fires on the weak RNG regardless.

    All hits are advisory (verdict=needs-fuzz, NO-AUTO-CREDIT).
    """
    ru1_covered = ru1_covered or set()
    hits: list[Hit] = []
    for fn in funcs:
        if not _CRYPTO_FN_NAME_RE.search(fn.name):
            continue
        sig = fn.sig or fn.header
        body_nc = _strip_comments(fn.body)
        rngcore = bool(_RNGCORE_BOUND_RE.search(sig))
        weak = bool(_WEAK_RNG_RE.search(body_nc))
        if not (rngcore or weak):
            continue
        # FP-guard (a): crypto scope required.
        path = str(fn.file).replace("\\", "/")
        scoped = bool(_CRYPTO_SCOPE_PATH_RE.search("/" + path)) or bool(
            _CRYPTO_SCOPE_BODY_RE.search(body_nc)
        )
        if not scoped:
            continue
        # FP-guard (b): an actual scalar/nonce sample must be drawn.
        if not _CRYPTO_SAMPLE_RE.search(body_nc):
            continue
        # The defect discriminator.
        if rngcore and not _CRYPTORNG_BOUND_RE.search(sig):
            arm = "missing_cryptorng_bound"
        elif weak:
            arm = "weak_seeded_rng"
        else:
            # rngcore WITH a CryptoRng bound and no weak source = secure
            # control (monero-oxide sign_core) -> silent.
            continue
        hit_line = fn.start_line
        # snippet: the `fn ..` header line.
        snippet = sig.strip().splitlines()[0].strip() if sig.strip() else fn.header
        covered_by = (
            _RUST_ENTROPY_SIBLING
            if (str(fn.file), hit_line) in ru1_covered else None
        )
        hits.append(Hit(
            file=str(fn.file),
            line=hit_line,
            snippet=snippet[:200],
            extra={
                "function": fn.name,
                "arm": arm,
                "rngcore_generic": rngcore,
                "has_cryptorng_bound": bool(_CRYPTORNG_BOUND_RE.search(sig)),
                "axis": "rust-entropy",
                "verdict": "needs-fuzz",
                "candidate_status": "needs-fuzz",
                "covered_by": covered_by,
                "sibling_detector": _RUST_ENTROPY_SIBLING,
                "impact_contract": _entropy_impact_contract(),
            },
        ))
    return hits


# ---------------------------------------------------------------------------
# RU11 - advisory Drop-delegated safety post-condition unsoundness axis
# ---------------------------------------------------------------------------
#
# OFF by default. Enable with AUDITOOR_RUST_DROPSAFETY_AXIS=1. Emits needs-fuzz
# hypotheses (NO-AUTO-CREDIT) to .auditooor/rust_dropsafety_hypotheses.jsonl -
# it never flips a gate or resolves a unit.
#
# Class: a safety POST-CONDITION (secret zeroize / lock unlock / settlement /
# reentrancy-guard clear) is DELEGATED to a `Drop` impl. The security of the
# type then rests on the RAII runs-once / after-guarded-state / in-order
# invariant of that Drop - an invariant the compiler does NOT enforce and an
# attacker can break. RU11 fires when a type with such a safety-Drop has its
# invariant put at risk by any of:
#   arm A (suppression): a `mem::forget` / `ManuallyDrop` / `.forget()` in the
#     same module. Each defeats runs-once: the Drop never runs so the secret is
#     never zeroized / the lock never released (attacker-reachable leak / wedge).
#   arm B (panic-in-drop): a panic-capable op (`.unwrap()` / `.expect(` /
#     `panic!` / `assert!`) inside the Drop body BEFORE / around the post-
#     condition. A panic mid-drop aborts the settle/zeroize half-done.
#   arm C (early move/return): a bare `return;` or a move-out
#     (`mem::take` / `mem::replace` / `.take()`) inside the Drop body that can
#     skip the post-condition or run it on emptied state (in-order broken).
# monero-oxide's ClsagMultisigMaskReceiver Drop (`(*self.buf.lock()).zeroize()`)
# is the secure CONTROL: safety-Drop present, no suppression, no panic op, no
# early move -> silent. Injecting `mem::forget` / `ManuallyDrop` (arm A) or a
# panic op / early move into the drop (arm B/C) fires it.
#
# FP-guard (the teeth): we only consider EXPLICIT `impl Drop for T` blocks whose
# drop body actually performs a safety op (zeroize / unlock / release / settle /
# reentrancy-clear); a plain derived `Drop` or a Drop that only logs is out of
# class and stays silent. Arm B/C are scoped to the DROP BODY only, so a
# `.take()` / `.expect()` elsewhere in the file (normal consumption) does not
# fire. A safety-Drop with NONE of the three risk arms present is the benign
# control and is silent.
#
# DEDUP boundary (A1): the covered_by signal is NOT re-derived. RU7
# (rust.lockpoison.panic_while_holding_guard) models a panic reachable WHILE a
# std::sync guard is held (poison DoS); RU11 models the RAII enforcer's private
# runs-once + forget-suppression + in-order invariant of a Drop-delegated
# post-condition - a distinct plane (RU11 fires with NO std guard and NO
# ingress). When an RU11 drop line coincides with a (file,line) already emitted
# by the RU1 detector we tag covered_by by matching against RU1's EMITTED hit
# set (passed in) - never recomputing the RU1 verdict. In practice a safety-Drop
# body is not an untrusted-ingress panic sink so the sets are disjoint
# (covered_by=None).
_RUST_DROPSAFETY_AXIS_ENV = "AUDITOOR_RUST_DROPSAFETY_AXIS"
_RUST_DROPSAFETY_PATTERN_ID = "rust.dropsafety.drop_delegated_postcond_unsound"
_RUST_DROPSAFETY_SIBLING = "rust.lockpoison.panic_while_holding_guard"

# `impl [<generics>] Drop for T` header (captures the guarded type name T).
_RU11_IMPL_DROP_RE = re.compile(
    r"impl(?:\s*<[^>]*>)?\s+Drop\s+for\s+(?P<ty>[A-Za-z_]\w*)"
)

# A safety post-condition delegated to the Drop body: secret zeroize, lock
# unlock/release, settlement, or a reentrancy-guard clear.
_RU11_SAFETY_OP_RE = re.compile(
    r"\bzeroize\w*\s*\("
    r"|\bunlock\s*\("
    r"|\brelease\s*\("
    r"|\bsettle\w*\s*\("
    r"|\block(?:ed)?\s*=\s*false\b"
    r"|reentran\w*\s*=\s*(?:false|0)\b"
    r"|\bentered\s*=\s*false\b"
    r"|\bNOT_ENTERED\b"
    r"|\bclear_reentr\w*\s*\("
)

# arm A - drop-suppression: `mem::forget` / `ManuallyDrop` / a `.forget()` call.
# Each defeats the runs-once RAII invariant so the post-condition never runs.
_RU11_SUPPRESS_RE = re.compile(
    r"\b(?:core::|std::)?mem::forget\s*\("
    r"|\bManuallyDrop\b"
    r"|\.\s*forget\s*\(\s*\)"
)

# arm B - panic-capable op inside a Drop body (panic-in-drop aborts the
# post-condition mid-flight -> runs-once / in-order invariant is unsound).
_RU11_DROP_PANIC_RE = re.compile(
    r"\.\s*unwrap\s*\(\s*\)"
    r"|\.\s*expect\s*\("
    r"|\bpanic!\s*\("
    r"|\bunreachable!\s*\("
    r"|\bassert\w*!\s*\("
)

# arm C - early exit / move-out of the guarded field before the post-condition:
# a bare `return;` inside the drop, or a move that empties the secret
# (`mem::take` / `mem::replace` / `.take()`).
_RU11_EARLY_MOVE_RE = re.compile(
    r"\breturn\s*;"
    r"|\bmem::take\s*\("
    r"|\bmem::replace\s*\("
    r"|\.\s*take\s*\(\s*\)"
)


def _dropsafety_axis_enabled() -> bool:
    return os.environ.get(_RUST_DROPSAFETY_AXIS_ENV, "").strip().lower() in {
        "1", "true", "yes", "on",
    }


def _dropsafety_impact_contract() -> dict:
    return {
        "class": "drop_delegated_safety_postcond_unsound",
        "impact": "a safety post-condition (zeroize / unlock / settle / "
                  "reentrancy-clear) delegated to a Drop impl can be skipped or "
                  "run half-done via attacker-reachable mem::forget/ManuallyDrop "
                  "(runs-once broken), a panic-in-drop, or an early move/return "
                  "-> secret retained in memory / lock left held / guard left set",
        "requires": "an explicit `impl Drop for T` whose body performs a safety "
                    "op, AND a suppression (forget/ManuallyDrop) in the module "
                    "OR a panic op / early move inside the drop body; a real "
                    "fuzz/PoC must confirm the suppression/reorder is reachable",
        "status": "advisory_needs_fuzz",
    }


def _find_safety_drop_types(src: str) -> list[dict]:
    """Return one dict per `impl Drop for T` whose drop body performs a safety
    post-condition: ``{ty, impl_line, drop_line, drop_body}``."""
    out: list[dict] = []
    for m in _RU11_IMPL_DROP_RE.finditer(src):
        ty = m.group("ty")
        brace = src.find("{", m.end())
        if brace < 0:
            continue
        end = _balance_braces(src, brace)
        if end is None:
            continue
        # locate the `fn drop(...)` header inside [brace, end).
        fm = re.compile(r"\bfn\s+drop\s*\(").search(src, brace, end)
        if not fm:
            continue
        open_paren = src.find("(", fm.start())
        if open_paren < 0:
            continue
        close_paren = _matched_paren_end(src, open_paren)
        if close_paren is None:
            continue
        body_open = _find_body_open(src, close_paren + 1)
        if body_open is None:
            continue
        body_end = _balance_braces(src, body_open)
        if body_end is None:
            continue
        drop_body = src[body_open + 1:body_end - 1]
        if not _RU11_SAFETY_OP_RE.search(_strip_comments(drop_body)):
            continue
        out.append({
            "ty": ty,
            "impl_line": src.count("\n", 0, m.start()) + 1,
            "drop_line": src.count("\n", 0, fm.start()) + 1,
            "drop_body": drop_body,
        })
    return out


def _detect_drop_delegated_safety_postcond(
    file_srcs: dict[str, str],
    ru1_covered: set | None = None,
) -> list[Hit]:
    """RU11 (advisory) - a safety post-condition delegated to a Drop impl whose
    runs-once / in-order / no-suppression invariant is unsound.

    Stage-1 predicate (per file): >=1 explicit ``impl Drop for T`` whose body
    performs a safety op (zeroize / unlock / release / settle / reentrancy-clear).

    Stage-2 risk arms (fire when >=1 is present; a safety-Drop with none is the
    benign control and stays silent):
      * arm A - a suppression (``mem::forget`` / ``ManuallyDrop`` / ``.forget()``)
        anywhere in the module (defeats runs-once);
      * arm B - a panic-capable op inside the drop body (panic-in-drop);
      * arm C - a bare ``return;`` or move-out (``mem::take`` / ``mem::replace``
        / ``.take()``) inside the drop body (in-order broken).

    All hits are advisory (verdict=needs-fuzz, NO-AUTO-CREDIT).
    """
    ru1_covered = ru1_covered or set()
    hits: list[Hit] = []
    for rel, src in file_srcs.items():
        sdrops = _find_safety_drop_types(src)
        if not sdrops:
            continue
        file_suppress = bool(_RU11_SUPPRESS_RE.search(_strip_comments(src)))
        for sd in sdrops:
            body_nc = _strip_comments(sd["drop_body"])
            arms: list[str] = []
            if file_suppress:
                arms.append("drop_suppression_forget_manuallydrop")
            if _RU11_DROP_PANIC_RE.search(body_nc):
                arms.append("panic_in_drop")
            if _RU11_EARLY_MOVE_RE.search(body_nc):
                arms.append("early_return_or_move_in_drop")
            if not arms:
                # benign control: safety-Drop present, invariant intact.
                continue
            line = sd["drop_line"]
            covered_by = (
                _RUST_DROPSAFETY_SIBLING
                if (rel, line) in ru1_covered else None
            )
            hits.append(Hit(
                file=rel,
                line=line,
                snippet=("impl Drop for %s { fn drop ... } (safety post-cond)"
                         % sd["ty"])[:200],
                extra={
                    "drop_type": sd["ty"],
                    "arms": arms,
                    "impl_line": sd["impl_line"],
                    "axis": "rust-dropsafety",
                    "verdict": "needs-fuzz",
                    "candidate_status": "needs-fuzz",
                    "covered_by": covered_by,
                    "sibling_detector": _RUST_DROPSAFETY_SIBLING,
                    "impact_contract": _dropsafety_impact_contract(),
                },
            ))
    return hits


# ---------------------------------------------------------------------------
# RU2 / R11 - advisory untrusted-ingress -> reachable panic-primitive census
# ---------------------------------------------------------------------------
#
# OFF by default. Enable with AUDITOOR_RUST_PANIC_REACH_AXIS=1. Emits needs-fuzz
# hypotheses (NO-AUTO-CREDIT) to .auditooor/rust_panic_reach_hypotheses.jsonl -
# it never flips a gate or resolves a unit. Structurally identical to the other
# advisory axes (RU3/RU6/RU7/RU9/RU10/RU11): own env, own stream, verdict=
# needs-fuzz, auto_credit=False, never folded into patterns/totals.
#
# Class: a GENERAL untrusted-ingress -> panic-capable-primitive REACHABILITY
# census. This promotes four grep-only backlog scanners into ONE detector that
# shares RU1's guard-dominance discipline but adds a def-use taint JOIN:
#   * rust-decode-bomb-scan.py               (attacker-len-token NAME heuristic)
#   * rust-host-length-cast-unbounded-alloc-scan.py (<=10-line PROXIMITY)
#   * rust-numeric-overflow-underflow-scan.py       (guard-nearby heuristic)
#   * rust-from-u8-panic-on-untrusted-input-scan.py (From<u8> wildcard)
# All four emit on grep signals with NO ingress->primitive reachability JOIN;
# RU2 replaces the name/proximity heuristic with a real ingress-seam -> taint
# fixpoint -> guard-dominance JOIN and unifies the four classes under one axis.
#
# NET-NEW over RU1 (rust.panic.untrusted_ingress_unguarded_panic):
#   (i)  taint PROPAGATION so a DERIVED local (a decoded length `n`, `n as
#        usize`) reaching a primitive fires even though the raw ingress name
#        never appears at the sink (RU1 only keys the sink on the same ingress
#        var NAME textually present in the sink line);
#   (ii) two primitive classes RU1 has none of - unchecked ARITH (over/underflow
#        panic) and unbounded ALLOC (decode-bomb OOM);
#   (iii) a wider ingress SEAM - decode/handler/rpc entrypoints + decoded values,
#        not just byte-typed params.
#
# DEDUP boundary (A1): the covered_by signal is NOT re-derived. When an RU2 hit
# lands at a (file,line) already emitted by the RU1 detector (e.g. a plain
# `bytes[i]` slice-index both detectors see), we tag covered_by with the RU1
# pattern id by matching against RU1's EMITTED (file,line) set (passed in) and
# EXCLUDE it from net_new - never recomputing the RU1 verdict. Distinct from RU3
# (rust.oob.untrusted_slice_copy_range): RU3 owns the MEMORY-SAFETY OOB plane
# (copy_from_slice length-mismatch + separate-buffer range-slice) and DELIBERATELY
# EXCLUDES alloc sinks; RU2 owns exactly that complement - the alloc + unchecked-
# arith + unwrap/expect + index panic-DoS LIVENESS plane. RU2 does NOT emit
# copy_from_slice (RU3's territory), so the two axes are disjoint by construction.
#
# HONESTY CONTRACT (two-tier, same as rust-dataflow.py): the in-runner pass is a
# possibly-conservative SYNTACTIC def-use taint (confidence=syntactic); when a
# crate COMPILES the seam+JOIN should defer to rust-dataflow.py semantic-MIR taint
# (confidence=semantic-ssa). This runner is the toolchain-free fallback.
_RUST_PANICREACH_AXIS_ENV = "AUDITOOR_RUST_PANIC_REACH_AXIS"
_RUST_PANICREACH_PATTERN_ID = (
    "rust.panic.untrusted_ingress_reachable_panic_primitive"
)
_RUST_PANICREACH_SIBLING = "rust.panic.untrusted_ingress_unguarded_panic"

# (a) decode/deserialize ENTRYPOINT fn-name shapes. The fn's byte/reader param
# (or a `&self` decode receiver reading self-owned bytes) is attacker ingress.
# `from` / `try_from` are broad, so they are only treated as entrypoints when
# they actually carry a byte/reader param (see _ingress_taint_seed).
_PANICREACH_DECODE_FN_RE = re.compile(
    r"^(?:"
    r"deserialize\w*"
    r"|decode(?:_v\d+)?\w*"
    r"|from_bytes|from_slice|try_from_slice|try_from|from"
    r"|read(?:_\w+)?"
    r"|parse\w*"
    r")$"
)
# The strong-decode subset that seeds an entrypoint even with no byte param
# (a `&self` decode receiver reading self-owned bytes). Excludes from/try_from.
_PANICREACH_STRONG_DECODE_FN_RE = re.compile(
    r"^(?:"
    r"deserialize\w*|decode(?:_v\d+)?\w*"
    r"|from_bytes|from_slice|try_from_slice"
    r"|read(?:_\w+)?|parse\w*"
    r")$"
)
# (c) NETWORK/RPC/handler entrypoint fn-name shapes.
_PANICREACH_RPC_FN_RE = re.compile(
    r"^(?:"
    r"handle\w*|on_message|on_\w+|process\w*|execute\w*"
    r"|ingest\w*|dispatch\w*|recv\w*"
    r")$"
)
# Reader/byte carriers seeded for an entrypoint fn (the seam is the reader param).
_READER_TYPE_RE = re.compile(
    r"\bReader\b|\bBytesMut\b|\bBytes\b|\bBufMut\b|\bBuf\b|\bCursor\b"
    r"|impl\s+(?:std::io::)?Read\b|\bBufReader\b|[A-Za-z_]*[Rr]eader\b"
)
# (b) a decode READ that yields an attacker-derived scalar (length/count/tag) -
# the KEY net-new seam: the tainted thing is a decoded LENGTH, not the raw bytes.
_PANICREACH_DECODE_READ_RE = re.compile(
    r"\.\s*read_[iu]\d+\w*\s*\("           # reader.read_u32() / read_u64_le()
    r"|\.\s*read_var\w*\s*\("               # read_varint / read_var_u32
    r"|\.\s*get_[iu]\d+\w*\s*\("            # buf.get_u32() (bytes crate)
    r"|[iu]\d+\s*::\s*from_(?:le|be|ne)_bytes\s*\("  # u32::from_le_bytes(..)
)
# checked/saturating/wrapping wrappers => the author reasoned about overflow.
_PANICREACH_ARITH_WRAPPER_RE = re.compile(
    r"checked_|saturating_|wrapping_|overflowing_"
)


def _panicreach_axis_enabled() -> bool:
    return os.environ.get(_RUST_PANICREACH_AXIS_ENV, "").strip().lower() in {
        "1", "true", "yes", "on",
    }


def _panicreach_impact_contract() -> dict:
    return {
        "class": "untrusted_ingress_reachable_panic_primitive",
        "impact": "an attacker-supplied ingress value (decoded length/count/index "
                  "or raw bytes) reaches a panic-capable primitive - unwrap/expect, "
                  "OOB index/slice, unchecked arith over/underflow, or unbounded "
                  "allocation - with no dominating clamp/bounds guard -> panic / "
                  "abort / OOM (DoS / liveness)",
        "requires": "ingress externally reachable + a def-use taint path from the "
                    "ingress seam to the primitive operand + no textually-dominating "
                    "clamp/len/bounds guard; a real coverage-guided fuzz/PoC must "
                    "confirm the reachable panic",
        "status": "advisory_needs_fuzz",
    }


def _panicreach_entry_seam(fn: "RustFunction") -> str | None:
    """The entrypoint seam label for a fn by name, or None. Decode entrypoints
    win over rpc when both name-match (a decode fn is the more specific seam)."""
    if _PANICREACH_DECODE_FN_RE.match(fn.name):
        return "decode_entrypoint"
    if _PANICREACH_RPC_FN_RE.match(fn.name):
        return "rpc"
    return None


def _ingress_taint_seed(fn: "RustFunction") -> tuple[dict, bool]:
    """Compute the ingress TAINT SEED for ``fn`` and whether it is an entrypoint.

    Returns ``(seeds, entrypoint)`` where ``seeds`` maps a seed var NAME to
    ``{"seam", "root", "hops"}`` (hops=0). Three attacker-input entry classes:
      (a) byte-typed / ingress-named params (reuse RU1's ``_ingress_params``);
      (b) a decode/deserialize/handler/rpc ENTRYPOINT fn's byte/reader params;
      (c) the ``entrypoint`` flag enables decoded-value reads (``read_u32`` /
          ``from_le_bytes``) in the body to be seeded as taint even off a
          ``&self`` / field receiver (see ``_derive_tainted_locals``).
    """
    seeds: dict[str, dict] = {}
    for n in _ingress_params(fn):
        seeds[n] = {"seam": "param", "root": n, "hops": 0}
    entry_seam = _panicreach_entry_seam(fn)
    entrypoint = False
    if entry_seam:
        for name, ptype in _split_params(fn.params):
            if name in seeds:
                continue
            if _READER_TYPE_RE.search(ptype) or _INGRESS_TYPE_RE.search(ptype):
                seeds[name] = {"seam": entry_seam, "root": name, "hops": 0}
        entrypoint = bool(seeds) or bool(
            _PANICREACH_STRONG_DECODE_FN_RE.match(fn.name)
        )
    return seeds, entrypoint


def _panicreach_assignments(body_nc: str) -> list[tuple[str, str]]:
    """Coarse ``(name, rhs)`` pairs for ``let (mut) v = rhs`` and ``v = rhs``.

    Statement-split on ``;`` / newline / braces (positional info is not needed -
    the taint fixpoint only needs the NAME set; sink offsets are found separately
    over the full body). Comparisons (``==`` / ``<=`` ...) do not match because
    the reassignment arm requires the identifier to be immediately followed by a
    single ``=`` not part of a comparison operator."""
    assigns: list[tuple[str, str]] = []
    for stmt in re.split(r"[;\n{}]", body_nc):
        m = re.match(
            r"\s*let\s+(?:mut\s+)?([A-Za-z_]\w*)\s*(?::[^=]+)?=\s*(.+)$", stmt
        )
        if not m:
            m = re.match(r"\s*([A-Za-z_]\w*)\s*=\s*(?![=<>])(.+)$", stmt)
        if m:
            assigns.append((m.group(1), m.group(2)))
    return assigns


def _derive_tainted_locals(
    body_nc: str, seeds: dict, entrypoint: bool = False
) -> dict:
    """Bounded transitive-closure taint over ``let v = rhs`` / ``v = rhs``.

    Monotonic: a var is added once (with its shortest hop count) and never
    downgraded. A local ``v`` becomes tainted when its rhs mentions any already
    tainted name (incl. inside ``as usize`` / ``as u64`` casts, which is
    automatic since the tainted name appears in the rhs text), OR - only in an
    entrypoint fn - when its rhs is a decode read (``read_u32`` /
    ``from_le_bytes``) even off a ``&self`` / field receiver. Returns the same
    ``name -> {"seam","root","hops"}`` shape as the seed. This is the
    possibly-conservative SYNTACTIC reachability JOIN (confidence=syntactic)."""
    tainted: dict[str, dict] = {k: dict(v) for k, v in seeds.items()}
    assigns = _panicreach_assignments(body_nc)
    changed = True
    while changed:
        changed = False
        for name, rhs in assigns:
            if name in tainted:
                continue
            contrib = [
                tn for tn in tainted
                if re.search(rf"\b{re.escape(tn)}\b", rhs)
            ]
            is_decode = entrypoint and bool(
                _PANICREACH_DECODE_READ_RE.search(rhs)
            )
            if not contrib and not is_decode:
                continue
            if contrib:
                c0 = min(contrib, key=lambda c: tainted[c]["hops"])
                hops = tainted[c0]["hops"] + 1
                root = tainted[c0]["root"]
            else:
                hops = 1
                root = name
            tainted[name] = {"seam": "decoded_value", "root": root, "hops": hops}
            changed = True
    return tainted


def _panicreach_guard_dominates(body: str, sink_off: int, operand: str) -> bool:
    """True if a guard/clamp on ``operand`` textually PRECEDES the sink.

    Reuses RU1's ``_guard_dominates`` (len/is_empty/is_some/matches!/? and an
    operand-TETHERED return Err/ensure!) and EXTENDS it with the alloc/arith
    clamp idioms: a ``.min(`` /
    ``clamp(`` on the operand, a ``if operand >/< N`` bound check, a MAX/LIMIT
    constant compared with the operand, or a checked/saturating/wrapping call on
    the operand. Keeps a guarded primitive GREEN (the teeth)."""
    if _guard_dominates(body, sink_off, operand):
        return True
    pre = body[:sink_off]
    op = re.escape(operand)
    # .min( / clamp( on the operand (e.g. `let n = n.min(MAX_LEN);`).
    if re.search(rf"\b{op}\s*\.\s*(?:min|clamp)\s*\(", pre):
        return True
    if re.search(rf"\bclamp\s*\(\s*{op}\b", pre):
        return True
    # if operand >/< N  (bounds check / early return on the operand).
    if re.search(rf"\bif\s+{op}\s*(?:<|>|<=|>=)", pre):
        return True
    if re.search(rf"\bif\s+[^\n{{]*[<>]=?\s*{op}\b", pre):
        return True
    # a MAX/LIMIT/CAP constant compared against the operand.
    if re.search(rf"\b{op}\s*(?:<|>|<=|>=)\s*[A-Za-z_]*(?:MAX|LIMIT|CAP|BOUND)",
                 pre) or re.search(
                     rf"\b[A-Za-z_]*(?:MAX|LIMIT|CAP|BOUND)[A-Za-z_]*\s*"
                     rf"(?:<|>|<=|>=)\s*{op}\b", pre):
        return True
    # checked/saturating/wrapping call on the operand.
    if re.search(rf"\b{op}\s*\.\s*(?:checked_|saturating_|wrapping_|"
                 rf"overflowing_)", pre):
        return True
    return False


def _detect_panic_reach_primitives(
    funcs: Iterable["RustFunction"],
    ru1_covered: set | None = None,
) -> list[Hit]:
    """RU2 / R11 (advisory) - an untrusted-ingress value reaches a panic-capable
    primitive (unwrap/expect, OOB index/slice, unchecked arith, unbounded alloc)
    with no dominating clamp/bounds guard.

    Stage-1 (per fn): compute the ingress taint seed + entrypoint flag, then the
    derived-taint set via the def-use fixpoint. Stage-2: for each of the four
    primitive sink kinds, fire when its operand is in the taint set and no guard
    textually dominates it (literal-only operands are skipped). All hits are
    advisory (verdict=needs-fuzz, NO-AUTO-CREDIT)."""
    ru1_covered = ru1_covered or set()
    hits: list[Hit] = []
    for fn in funcs:
        # Test-context fns (const fixture params) are not attacker ingress.
        if _is_test_context(fn):
            continue
        seeds, entrypoint = _ingress_taint_seed(fn)
        if not seeds and not entrypoint:
            continue
        body_nc = _strip_comments(fn.body)
        tainted = _derive_tainted_locals(body_nc, seeds, entrypoint)
        if not tainted:
            continue
        lines = body_nc.splitlines()
        # (off) -> (kind, operand). Dedup by offset; first sink wins.
        sinks: dict[int, tuple[str, str]] = {}

        def _add(off: int, kind: str, operand: str) -> None:
            if off not in sinks:
                sinks[off] = (kind, operand)

        # Longest names first so a tainted `data_len` is preferred over `data`.
        tnames = sorted(tainted.keys(), key=len, reverse=True)

        for tv in tnames:
            pe = re.escape(tv)
            # (1) unwrap/expect on a line referencing the tainted var.
            for m in re.finditer(
                rf"\b{pe}\b[^\n;]*?\.\s*(?:unwrap|expect)\s*\(", body_nc
            ):
                _add(m.start(), "unwrap_expect", tv)
            # (3) unchecked arithmetic (over/underflow panic) on a tainted
            #     operand with no checked/saturating/wrapping wrapper.
            arith_res = (
                rf"\b{pe}\s*-\s*[A-Za-z0-9_(]",            # tv - x (underflow)
                rf"[A-Za-z0-9_)]\s*-\s*{pe}\b",             # x - tv
                rf"\b{pe}\b[^\n;=]*?\.\s*len\s*\(\s*\)\s*-",  # tv.len() - N
                rf"\b{pe}\s*[+*]\s*[A-Za-z0-9_(]",          # tv +|* x (overflow)
                rf"[A-Za-z0-9_)]\s*[+*]\s*{pe}\b",          # x +|* tv
            )
            for pat in arith_res:
                for m in re.finditer(pat, body_nc):
                    off = m.start()
                    line_off = body_nc[:off].count("\n")
                    line = lines[line_off] if line_off < len(lines) else ""
                    if _PANICREACH_ARITH_WRAPPER_RE.search(line):
                        continue
                    _add(off, "unchecked_arith", tv)
            # (5) unbounded allocation whose size arg is the tainted operand.
            alloc_res = (
                (rf"\bwith_capacity\s*\(\s*([^)]*)\)", "unbounded_alloc"),
                (rf"\.\s*reserve(?:_exact)?\s*\(\s*([^)]*)\)", "unbounded_alloc"),
                (rf"\bvec!\s*\[[^\];\n]*;\s*([^\]\n]+)\]", "unbounded_alloc"),
                (rf"\brepeat\s*\([^)]*\)\s*\.\s*take\s*\(\s*([^)]*)\)",
                 "unbounded_alloc"),
                (rf"\.\s*take\s*\(\s*([^)]*)\)", "unbounded_alloc"),
            )
            for pat, kind in alloc_res:
                for m in re.finditer(pat, body_nc):
                    arg = m.group(1)
                    if not arg or arg.strip().isdigit():
                        continue  # literal-only size = not attacker-controlled
                    if not re.search(rf"\b{pe}\b", arg):
                        continue
                    _add(m.start(), kind, tv)

        # (2) index / slice sink: a tainted BUFFER indexed (empty-slice /
        #     OOB panic), or ANY buffer indexed by a tainted scalar bound.
        for m in re.finditer(r"([A-Za-z_]\w*)\s*\[([^\]\n]*)\]", body_nc):
            bufname, idx = m.group(1), m.group(2)
            if idx.strip() in ("", ".."):
                continue  # whole-range slice, no index panic
            if bufname in tainted:
                _add(m.start(), "index_slice", bufname)
                continue
            for tv in tnames:
                if re.search(rf"\b{re.escape(tv)}\b", idx):
                    _add(m.start(), "index_slice", tv)
                    break

        for off in sorted(sinks):
            kind, operand = sinks[off]
            if _panicreach_guard_dominates(body_nc, off, operand):
                continue
            info = tainted.get(operand, {"seam": "decoded_value",
                                         "root": operand, "hops": 1})
            line_off = body_nc[:off].count("\n")
            snippet = (
                lines[line_off].strip() if line_off < len(lines) else fn.header
            )
            hit_line = fn.body_start_line + line_off
            covered_by = (
                _RUST_PANICREACH_SIBLING
                if (str(fn.file), hit_line) in ru1_covered else None
            )
            hits.append(Hit(
                file=str(fn.file),
                line=hit_line,
                snippet=snippet[:200],
                extra={
                    "function": fn.name,
                    "ingress_param": info["root"],
                    "ingress_seam": info["seam"],
                    "sink_kind": kind,
                    "taint_hops": info["hops"],
                    "axis": "rust-panic-reach",
                    "verdict": "needs-fuzz",
                    "candidate_status": "needs-fuzz",
                    "covered_by": covered_by,
                    "sibling_detector": _RUST_PANICREACH_SIBLING,
                    "impact_contract": _panicreach_impact_contract(),
                },
            ))
    return hits


# ---------------------------------------------------------------------------
# wave-2 standalone detector integration
# ---------------------------------------------------------------------------
#
# Wave-2 detectors live as standalone Python scripts in
# ``detectors/rust_wave2/<id>.py``.  Each script exposes a ``scan(root)``
# function returning ``list[tuple[str, int, str]]`` (filepath, line, message).
# We import them at runtime so we don't need to commit their logic here and
# so they can be maintained independently of this runner.
#
# If the wave-2 directory doesn't exist (e.g. in a fresh checkout before the
# PR lands) we silently skip and emit empty patterns for those IDs.

_WAVE2_DIR = Path(__file__).resolve().parent.parent / "detectors" / "rust_wave2"

_WAVE2_DETECTORS: dict[str, str] = {
    # pattern_id -> script filename (without .py)
    "rust.frost.wave2.nonce_reuse_risk_unscoped_secret":
        "frost_nonce_reuse_risk_unscoped_secret",
    "rust.frost.wave2.threshold_check_against_active_set_only":
        "frost_threshold_check_against_active_set_only",
    "rust.frost.wave2.keypackage_serialization_unauthenticated":
        "frost_keypackage_serialization_unauthenticated",
}


def _run_wave2_detectors(
    workspace: Path,
    strict_errors: list[str] | None = None,
    allowed_files: set[str] | None = None,
) -> dict[str, list[Hit]]:
    """Import and run each wave-2 detector script, returning Hit lists keyed by
    pattern ID.  Missing scripts or import errors are silently skipped."""
    import importlib.util

    results: dict[str, list[Hit]] = {}
    for pid, module_name in _WAVE2_DETECTORS.items():
        script = _WAVE2_DIR / f"{module_name}.py"
        if not script.exists():
            results[pid] = []
            if strict_errors is not None:
                strict_errors.append(f"missing Rust detector module: {script}")
            continue
        try:
            spec = importlib.util.spec_from_file_location(module_name, script)
            if spec is None or spec.loader is None:
                results[pid] = []
                continue
            mod = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(mod)  # type: ignore[union-attr]
            raw: list[tuple[str, int, str]] = mod.scan(str(workspace))
        except Exception as exc:
            results[pid] = []
            if strict_errors is not None:
                strict_errors.append(f"Rust detector degraded: {module_name}: {exc}")
            continue

        hits: list[Hit] = []
        for fpath, line, msg in raw:
            try:
                rel = str(Path(fpath).relative_to(workspace))
            except ValueError:
                rel = fpath
            if allowed_files is not None and rel.replace("\\", "/") not in allowed_files:
                continue
            hits.append(Hit(file=rel, line=line, snippet=msg[:200]))
        results[pid] = hits
    return results


# ---------------------------------------------------------------------------
# orchestration
# ---------------------------------------------------------------------------

class _StrictVerificationError(ValueError):
    """An invalid canonical inventory or strict evidence input."""


def _strict_unit_id(row: dict, rel: str) -> str:
    for key in ("unit_id", "inventory_unit_id", "id"):
        value = row.get(key)
        if isinstance(value, str) and value.strip():
            return value.strip()
    identity = {
        "file": rel,
        "function": str(row.get("function") or row.get("fn") or "").strip(),
    }
    digest = hashlib.sha256(
        json.dumps(identity, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()[:24]
    return f"rust-unit-{digest}"


def _strict_hit_id(pattern_id: str, hit: Hit) -> str:
    body = {
        "language": "rust",
        "pattern_id": pattern_id,
        "file": hit.file,
        "line": hit.line,
        "snippet": hit.snippet,
        "function": hit.extra.get("function", ""),
    }
    digest = hashlib.sha256(
        json.dumps(body, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()[:24]
    return f"rust-hit-{digest}"


def _strict_row_is_excluded(row: dict) -> bool:
    return row.get("applicable") is False or row.get("in_scope") is False


def _strict_status_errors(row: dict, label: str) -> list[str]:
    errors: list[str] = []
    if row.get("degraded") is True:
        errors.append(f"{label}:degraded")
    for key in ("parser_error", "parse_error", "parser_errors", "parse_errors"):
        value = row.get(key)
        if value not in (None, False, [], ""):
            errors.append(f"{label}:{key}")
    status = str(row.get("parser_status") or row.get("scan_status") or row.get("status") or "").strip().lower()
    if status in {"missing", "degraded", "error", "failed", "parser-error", "parser_error"}:
        errors.append(f"{label}:{status}")
    return errors


def _load_strict_inventory(workspace: Path) -> tuple[list[dict], dict[str, dict], list[Path], str]:
    path = workspace / ".auditooor" / "inscope_units.jsonl"
    if not path.is_file() or path.is_symlink():
        raise _StrictVerificationError("missing canonical in-scope inventory")
    rows: list[dict] = []
    errors: list[str] = []
    try:
        raw_lines = path.read_text(encoding="utf-8").splitlines()
    except OSError as exc:
        raise _StrictVerificationError(f"cannot read canonical inventory: {exc}") from exc
    if not raw_lines:
        raise _StrictVerificationError("empty canonical in-scope inventory")
    for line_no, raw in enumerate(raw_lines, 1):
        if not raw.strip():
            errors.append(f"inventory:{line_no}:blank row")
            continue
        try:
            row = json.loads(raw)
        except json.JSONDecodeError:
            errors.append(f"inventory:{line_no}:malformed JSON")
            continue
        if not isinstance(row, dict):
            errors.append(f"inventory:{line_no}:object required")
            continue
        rows.append(row)
    if errors:
        raise _StrictVerificationError("; ".join(errors))

    units: dict[str, dict] = {}
    files: dict[str, Path] = {}
    for index, row in enumerate(rows, 1):
        if _strict_row_is_excluded(row):
            continue
        raw_file = row.get("file") or row.get("path")
        if not isinstance(raw_file, str) or not raw_file.strip():
            errors.append(f"inventory:{index}:missing file")
            continue
        rel = raw_file.replace("\\", "/").strip().lstrip("./")
        candidate = Path(rel)
        if candidate.is_absolute() or ".." in candidate.parts:
            errors.append(f"inventory:{index}:path escapes workspace")
            continue
        if candidate.suffix.lower() != ".rs":
            declared = str(row.get("lang") or row.get("language") or "").strip().lower()
            if declared in {"rust", ".rs", "rs"}:
                errors.append(f"inventory:{index}:Rust row is not an .rs source")
            continue
        declared = str(row.get("lang") or row.get("language") or "").strip().lower()
        if declared and declared not in {"rust", ".rs", "rs"}:
            errors.append(f"inventory:{index}:language mismatch")
            continue
        source = workspace / candidate
        if source.is_symlink() or not source.is_file():
            errors.append(f"inventory:{index}:missing source {rel}")
            continue
        unit_id = _strict_unit_id(row, rel)
        if unit_id in units:
            errors.append(f"inventory:{index}:duplicate unit id {unit_id}")
            continue
        normalized = dict(row)
        normalized["file"] = rel
        normalized["unit_id"] = unit_id
        units[unit_id] = normalized
        files[rel] = source
        errors.extend(_strict_status_errors(row, f"inventory:{index}"))
    if errors:
        raise _StrictVerificationError("; ".join(errors))
    return rows, units, [files[key] for key in sorted(files)], hashlib.sha256(path.read_bytes()).hexdigest()


def _strict_parse_errors(src: str) -> list[str]:
    errors: list[str] = []
    for match in _RUST_FUNC_HEADER.finditer(src):
        open_paren = match.end() - 1
        close_paren = _matched_paren_end(src, open_paren)
        if close_paren is None:
            line = src.count("\n", 0, match.start()) + 1
            errors.append(f"parser error at line {line}: unbalanced function parameters")
            continue
        body_open = _find_body_open(src, close_paren + 1)
        if body_open is not None and _balance_braces(src, body_open) is None:
            line = src.count("\n", 0, match.start()) + 1
            errors.append(f"parser error at line {line}: unbalanced function body")
    return errors


def _strict_disposition_paths(workspace: Path) -> list[Path]:
    names = (STRICT_DISPOSITION_FILENAME, "detector_dispositions.jsonl")
    return [workspace / ".auditooor" / name for name in names
            if (workspace / ".auditooor" / name).is_file()]


def _strict_source_evidence(workspace: Path, value, inventory_files: set[str]) -> bool:
    entries = [value] if isinstance(value, dict) else value
    if not isinstance(entries, list) or not entries:
        return False
    for entry in entries:
        if isinstance(entry, str):
            match = re.match(r"^(.+):(\d+)$", entry.strip())
            if not match:
                return False
            rel, line = match.group(1), int(match.group(2))
        elif isinstance(entry, dict):
            rel = entry.get("file") or entry.get("path") or entry.get("source_ref")
            line = entry.get("line")
            if not isinstance(rel, str) or not rel.strip() or isinstance(line, bool):
                return False
            try:
                line = int(line)
            except (TypeError, ValueError):
                return False
        else:
            return False
        rel = str(rel).replace("\\", "/").strip().lstrip("./")
        candidate = Path(rel)
        if candidate.is_absolute() or ".." in candidate.parts or line <= 0:
            return False
        if rel not in inventory_files:
            return False
        source = workspace / candidate
        if source.is_symlink() or not source.is_file():
            return False
        if line > len(source.read_text(encoding="utf-8", errors="replace").splitlines()):
            return False
    return True


def _strict_verify_hits(
    workspace: Path,
    pattern_results: dict[str, list[Hit]],
    units: dict[str, dict],
    scanned_units: set[str],
    inventory_sha256: str,
    parser_errors: list[str],
) -> dict:
    by_file: dict[str, list[dict]] = {}
    for unit in units.values():
        by_file.setdefault(unit["file"], []).append(unit)
    dispositions: dict[str, dict] = {}
    errors = list(parser_errors)
    for path in _strict_disposition_paths(workspace):
        for line_no, raw in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
            if not raw.strip():
                errors.append(f"disposition:{path.name}:{line_no}:blank row")
                continue
            try:
                record = json.loads(raw)
            except json.JSONDecodeError:
                errors.append(f"disposition:{path.name}:{line_no}:malformed JSON")
                continue
            if not isinstance(record, dict):
                errors.append(f"disposition:{path.name}:{line_no}:object required")
                continue
            hit_id = record.get("hit_id") or record.get("stable_id") or record.get("finding_id")
            disposition_type = record.get("disposition_type")
            if not isinstance(hit_id, str) or not hit_id.strip():
                errors.append(f"disposition:{path.name}:{line_no}:missing stable hit id")
                continue
            if disposition_type not in _STRICT_DISPOSITION_TYPES:
                errors.append(f"disposition:{path.name}:{line_no}:invalid disposition type")
                continue
            if record.get("schema") not in (None, STRICT_DISPOSITION_SCHEMA):
                errors.append(f"disposition:{path.name}:{line_no}:schema mismatch")
                continue
            if hit_id in dispositions:
                errors.append(f"disposition:{path.name}:{line_no}:duplicate stable hit id")
                continue
            dispositions[hit_id] = record

    unresolved: list[dict] = []
    emitted = 0
    for pattern_id, hits in pattern_results.items():
        for hit in hits:
            emitted += 1
            hit_id = _strict_hit_id(pattern_id, hit)
            candidates = by_file.get(hit.file, [])
            function = str(hit.extra.get("function") or "").strip()
            if function:
                matching = [u for u in candidates if str(u.get("function") or u.get("fn") or "").strip() == function]
                if matching:
                    candidates = matching
            if len(candidates) != 1:
                unresolved.append({"hit_id": hit_id, "pattern_id": pattern_id, "file": hit.file, "line": hit.line, "reason": "hit not mapped to one inventory unit"})
                continue
            record = dispositions.get(hit_id)
            if record is None:
                unresolved.append({"hit_id": hit_id, "pattern_id": pattern_id, "unit_id": candidates[0]["unit_id"], "file": hit.file, "line": hit.line, "reason": "no exact typed disposition"})
                continue
            if record.get("unit_id") != candidates[0]["unit_id"]:
                unresolved.append({"hit_id": hit_id, "pattern_id": pattern_id, "file": hit.file, "line": hit.line, "reason": "disposition unit id mismatch"})
                continue
            if record.get("pattern_id") not in (None, pattern_id):
                unresolved.append({"hit_id": hit_id, "pattern_id": pattern_id, "file": hit.file, "line": hit.line, "reason": "disposition pattern id mismatch"})
                continue
            evidence = record.get("source_evidence") or record.get("source_refs")
            if not _strict_source_evidence(workspace, evidence, set(by_file)):
                unresolved.append({"hit_id": hit_id, "pattern_id": pattern_id, "unit_id": candidates[0]["unit_id"], "file": hit.file, "line": hit.line, "reason": "missing local source evidence"})

    missing_units = sorted(set(units) - scanned_units)
    return {
        "schema": STRICT_SCHEMA,
        "mode": "strict",
        "language": "rust",
        "verdict": "pass" if not errors and not unresolved and not missing_units else "fail",
        "inventory": {"path": ".auditooor/inscope_units.jsonl", "sha256": inventory_sha256, "unit_count": len(units), "source_file_count": len(by_file)},
        "scanned_units": sorted(scanned_units),
        "scanned_unit_count": len(scanned_units),
        "missing_units": missing_units,
        "emitted_hit_count": emitted,
        "unresolved_hits": unresolved,
        "disposition_paths": [str(p.relative_to(workspace)) for p in _strict_disposition_paths(workspace)],
        "errors": errors,
    }

def _walk_rust_files(root: Path) -> Iterable[Path]:
    for path in root.rglob("*.rs"):
        if any(part in _SKIP_DIRS for part in path.parts):
            continue
        yield path


def scan_workspace(workspace: Path, *, strict: bool = False) -> dict:
    workspace = workspace.resolve()
    strict_units: dict[str, dict] = {}
    strict_inventory_sha256 = ""
    strict_errors: list[str] = []
    if strict:
        try:
            _, strict_units, strict_paths, strict_inventory_sha256 = _load_strict_inventory(workspace)
            files = strict_paths
        except _StrictVerificationError as exc:
            strict_errors.append(str(exc))
            files = []
    else:
        files = list(_walk_rust_files(workspace))

    funcs: list[RustFunction] = []
    file_srcs: dict[str, str] = {}
    strict_scanned_units: set[str] = set()
    for f in files:
        try:
            src = f.read_text(encoding="utf-8", errors="replace")
        except OSError as exc:
            if strict:
                strict_errors.append(f"source read error {f}: {exc}")
            continue
        rel = f.relative_to(workspace)
        file_srcs[str(rel)] = src
        new_funcs = _extract_functions(src, rel)
        funcs.extend(new_funcs)
        if strict:
            rel_text = rel.as_posix()
            file_units = [u for u in strict_units.values() if u["file"] == rel_text]
            strict_errors.extend(_strict_parse_errors(src))
            for unit in file_units:
                declared_fn = str(unit.get("function") or unit.get("fn") or "").strip()
                if declared_fn and not any(fn.name == declared_fn for fn in new_funcs):
                    strict_errors.append(
                        f"parser did not enumerate inventory function {rel_text}::{declared_fn}"
                    )
                else:
                    strict_scanned_units.add(unit["unit_id"])

    oob_axis = _oob_axis_enabled()
    ingress_hits = _detect_untrusted_ingress_panic(funcs, oob_axis=oob_axis)
    # RU3 advisory axis lives in its OWN stream (needs-fuzz, NO-AUTO-CREDIT):
    # split it out so the default RU1 pattern + totals are byte-identical when
    # the axis is off.
    ru1_hits = [h for h in ingress_hits if h.extra.get("axis") != "rust-OOB"]
    oob_hits = [h for h in ingress_hits if h.extra.get("axis") == "rust-OOB"]

    pattern_results: dict[str, list[Hit]] = {
        "rust.frost.dkg.self_identifier_in_round_packages":
            _detect_dkg_self_identifier(funcs),
        "rust.frost.aggregate.under_threshold_signature_shares":
            _detect_aggregate_under_threshold(funcs),
        "rust.panic.untrusted_ingress_unguarded_panic": ru1_hits,
    }
    # Merge wave-2 standalone detector results.
    pattern_results.update(_run_wave2_detectors(
        workspace,
        strict_errors if strict else None,
        {unit["file"] for unit in strict_units.values()} if strict else None,
    ))

    patterns_out: dict = {}
    total_hits = 0
    hit_files: set[str] = set()
    for pid, hits in pattern_results.items():
        hit_rows = []
        for hit in hits:
            row = hit.to_json()
            if strict:
                row["stable_id"] = _strict_hit_id(pid, hit)
                row["pattern_id"] = pid
                candidates = [
                    unit for unit in strict_units.values()
                    if unit["file"] == hit.file
                ]
                function = str(hit.extra.get("function") or "").strip()
                matching = [
                    unit for unit in candidates
                    if str(unit.get("function") or unit.get("fn") or "").strip() == function
                ] if function else candidates
                if len(matching) == 1:
                    row["unit_id"] = matching[0]["unit_id"]
            hit_rows.append(row)
        patterns_out[pid] = {
            "id": pid,
            "hit_count": len(hits),
            "hits": hit_rows,
        }
        total_hits += len(hits)
        hit_files.update(h.file for h in hits)

    summary = {
        "schema_version": 1,
        "scanner_schema": SCHEMA_SLUG,
        "workspace": str(workspace),
        "scanner": "rust-detector-runner.py",
        "scanner_version": SCANNER_VERSION,
        "rust_files_scanned": len(files),
        "patterns": patterns_out,
        "totals": {"hits": total_hits, "files": len(hit_files)},
    }
    if strict:
        summary["strict_verification"] = _strict_verify_hits(
            workspace,
            pattern_results,
            strict_units,
            strict_scanned_units,
            strict_inventory_sha256,
            strict_errors,
        )
    # RU3 advisory rust-OOB axis: a SEPARATE needs-fuzz hypotheses stream (never
    # folded into patterns/totals). Present only when the axis is enabled so the
    # default output is unchanged.
    if oob_axis:
        net_new = [h for h in oob_hits if not h.extra.get("covered_by")]
        summary["rust_oob_axis"] = {
            "id": _RUST_OOB_PATTERN_ID,
            "enabled": True,
            "env": _RUST_OOB_AXIS_ENV,
            "verdict": "needs-fuzz",
            "auto_credit": False,
            "hypothesis_count": len(oob_hits),
            "net_new_count": len(net_new),
            "hypotheses": [h.to_json() for h in oob_hits],
        }
    # RU6 advisory nondeterminism -> consensus-divergence axis. Same contract as
    # RU3: OFF by default, its OWN needs-fuzz stream, never folded into
    # patterns/totals, NO-AUTO-CREDIT.
    if _nondet_axis_enabled():
        nondet_hits = _detect_nondeterminism_consensus(funcs)
        # DEDUP boundary (A1): sibling is the Go cosmos detector which only
        # emits on `.go`; `.rs` hits are disjoint by construction so
        # net_new == all. covered_by is never re-derived.
        net_new = [h for h in nondet_hits if not h.extra.get("covered_by")]
        summary["rust_nondet_axis"] = {
            "id": _RUST_NONDET_PATTERN_ID,
            "enabled": True,
            "env": _RUST_NONDET_AXIS_ENV,
            "verdict": "needs-fuzz",
            "auto_credit": False,
            "sibling_detector": _RUST_NONDET_SIBLING,
            "hypothesis_count": len(nondet_hits),
            "net_new_count": len(net_new),
            "hypotheses": [h.to_json() for h in nondet_hits],
        }
    # RU7 advisory lock-poison panic-while-holding axis. Same contract as
    # RU3/RU6: OFF by default, its OWN needs-fuzz stream, never folded into
    # patterns/totals, NO-AUTO-CREDIT.
    if _lockpoison_axis_enabled():
        # A1 dedup: pass RU1's EMITTED (file,line) set; covered_by is matched
        # against it, never re-derived.
        ru1_covered = {(h.file, h.line) for h in ru1_hits}
        lp_hits = _detect_lockpoison_panic_while_holding(funcs, ru1_covered)
        net_new = [h for h in lp_hits if not h.extra.get("covered_by")]
        summary["rust_lockpoison_axis"] = {
            "id": _RUST_LOCKPOISON_PATTERN_ID,
            "enabled": True,
            "env": _RUST_LOCKPOISON_AXIS_ENV,
            "verdict": "needs-fuzz",
            "auto_credit": False,
            "sibling_detector": _RUST_LOCKPOISON_SIBLING,
            "hypothesis_count": len(lp_hits),
            "net_new_count": len(net_new),
            "hypotheses": [h.to_json() for h in lp_hits],
        }
    # RU9 advisory str byte-slice char-boundary axis. Same contract as
    # RU3/RU6/RU7: OFF by default, its OWN needs-fuzz stream, never folded into
    # patterns/totals, NO-AUTO-CREDIT.
    if _strslice_axis_enabled():
        # A1 dedup: pass RU1's EMITTED (file,line) set; covered_by is matched
        # against it, never re-derived (RU1=byte-typed, RU9=str-typed).
        ru1_covered = {(h.file, h.line) for h in ru1_hits}
        ss_hits = _detect_str_byte_slice_char_boundary(funcs, ru1_covered)
        net_new = [h for h in ss_hits if not h.extra.get("covered_by")]
        summary["rust_strslice_axis"] = {
            "id": _RUST_STRSLICE_PATTERN_ID,
            "enabled": True,
            "env": _RUST_STRSLICE_AXIS_ENV,
            "verdict": "needs-fuzz",
            "auto_credit": False,
            "sibling_detector": _RUST_STRSLICE_SIBLING,
            "hypothesis_count": len(ss_hits),
            "net_new_count": len(net_new),
            "hypotheses": [h.to_json() for h in ss_hits],
        }
    # RU10 advisory crypto-fn missing-CryptoRng-bound axis. Same contract as
    # RU3/RU6/RU7/RU9: OFF by default, its OWN needs-fuzz stream, never folded
    # into patterns/totals, NO-AUTO-CREDIT.
    if _entropy_axis_enabled():
        # A1 dedup: pass RU1's EMITTED (file,line) set; covered_by is matched
        # against it, never re-derived (RU1=panic sink, RU10=entropy bound).
        ru1_covered = {(h.file, h.line) for h in ru1_hits}
        en_hits = _detect_crypto_fn_missing_cryptorng(funcs, ru1_covered)
        net_new = [h for h in en_hits if not h.extra.get("covered_by")]
        summary["rust_entropy_axis"] = {
            "id": _RUST_ENTROPY_PATTERN_ID,
            "enabled": True,
            "env": _RUST_ENTROPY_AXIS_ENV,
            "verdict": "needs-fuzz",
            "auto_credit": False,
            "sibling_detector": _RUST_ENTROPY_SIBLING,
            "hypothesis_count": len(en_hits),
            "net_new_count": len(net_new),
            "hypotheses": [h.to_json() for h in en_hits],
        }
    # RU11 advisory Drop-delegated safety post-condition axis. Same contract as
    # RU3/RU6/RU7/RU9/RU10: OFF by default, its OWN needs-fuzz stream, never
    # folded into patterns/totals, NO-AUTO-CREDIT.
    if _dropsafety_axis_enabled():
        # A1 dedup: pass RU1's EMITTED (file,line) set; covered_by is matched
        # against it, never re-derived (RU1=ingress panic sink, RU11=Drop RAII
        # runs-once/forget-suppression invariant; distinct from RU7 poison).
        ru1_covered = {(h.file, h.line) for h in ru1_hits}
        ds_hits = _detect_drop_delegated_safety_postcond(file_srcs, ru1_covered)
        net_new = [h for h in ds_hits if not h.extra.get("covered_by")]
        summary["rust_dropsafety_axis"] = {
            "id": _RUST_DROPSAFETY_PATTERN_ID,
            "enabled": True,
            "env": _RUST_DROPSAFETY_AXIS_ENV,
            "verdict": "needs-fuzz",
            "auto_credit": False,
            "sibling_detector": _RUST_DROPSAFETY_SIBLING,
            "hypothesis_count": len(ds_hits),
            "net_new_count": len(net_new),
            "hypotheses": [h.to_json() for h in ds_hits],
        }
    # RU2/R11 advisory untrusted-ingress -> reachable panic-primitive census.
    # Same contract as RU3/RU6/RU7/RU9/RU10/RU11: OFF by default, its OWN
    # needs-fuzz stream, never folded into patterns/totals, NO-AUTO-CREDIT.
    if _panicreach_axis_enabled():
        # A1 dedup: pass RU1's EMITTED (file,line) set; covered_by is matched
        # against it, never re-derived (RU1=same-var panic sink, RU2=derived-
        # value taint + arith/alloc primitives + wider decode/rpc seam).
        ru1_covered = {(h.file, h.line) for h in ru1_hits}
        pr_hits = _detect_panic_reach_primitives(funcs, ru1_covered)
        net_new = [h for h in pr_hits if not h.extra.get("covered_by")]
        summary["rust_panic_reach_axis"] = {
            "id": _RUST_PANICREACH_PATTERN_ID,
            "enabled": True,
            "env": _RUST_PANICREACH_AXIS_ENV,
            "verdict": "needs-fuzz",
            "auto_credit": False,
            "sibling_detector": _RUST_PANICREACH_SIBLING,
            "hypothesis_count": len(pr_hits),
            "net_new_count": len(net_new),
            "hypotheses": [h.to_json() for h in pr_hits],
        }
    return summary


def _build_summary_md(summary: dict) -> str:
    """Build a Markdown summary compatible with the intake-baseline gate.

    The gate only checks file presence, but we emit a minimal readable
    summary so humans can inspect standalone ``make scan-rust`` output.
    """
    import datetime

    ws = summary.get("workspace", "")
    ts = datetime.datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ")
    files = summary.get("rust_files_scanned", 0)
    totals = summary.get("totals", {})
    total_hits = totals.get("hits", 0)
    patterns = summary.get("patterns", {})

    lines = [
        "# Rust Scan Summary",
        "",
        f"- Workspace: `{ws}`",
        f"- Generated: `{ts}`",
        f"- Rust files scanned: **{files}**",
        f"- Total hits: **{total_hits}**",
        f"- Scanner: `{summary.get('scanner', 'rust-detector-runner.py')}`"
        f" v{summary.get('scanner_version', '')}",
        "",
        "## Pattern results",
        "",
        "| Pattern | Hits |",
        "|---|---:|",
    ]
    for pid, pdata in sorted(patterns.items()):
        lines.append(f"| `{pid}` | {pdata.get('hit_count', 0)} |")
    lines.append("")
    lines.append(
        "_Generated by rust-detector-runner.py standalone scan. "
        "For full cargo-audit / semgrep / clippy results run "
        "`tools/rust-scan-runner.sh`._"
    )
    lines.append("")
    return "\n".join(lines)


def _write_outputs(workspace: Path, summary: dict) -> Path:
    # Primary .auditooor outputs (existing contract).
    out_dir = workspace / ".auditooor"
    out_dir.mkdir(parents=True, exist_ok=True)
    main_out = out_dir / "rust_findings.json"
    alias_out = out_dir / "SCAN_RUST_SUMMARY.json"
    text = json.dumps(summary, indent=2, sort_keys=True) + "\n"
    main_out.write_text(text, encoding="utf-8")
    alias_out.write_text(text, encoding="utf-8")

    # intake-baseline gate paths: scanners/rust/SCAN_RUST_SUMMARY.{json,md}
    # The gate (_has_rust_scan_artifact) checks this directory first; the
    # standalone runner must satisfy it so that ``make scan-rust`` followed
    # by ``make intake-baseline`` does not report "no scan-rust artifact".
    scanners_dir = workspace / "scanners" / "rust"
    scanners_dir.mkdir(parents=True, exist_ok=True)
    (scanners_dir / "SCAN_RUST_SUMMARY.json").write_text(text, encoding="utf-8")
    (scanners_dir / "SCAN_RUST_SUMMARY.md").write_text(
        _build_summary_md(summary), encoding="utf-8"
    )

    # RU3 advisory axis: emit needs-fuzz hypotheses JSONL (NO-AUTO-CREDIT).
    axis = summary.get("rust_oob_axis")
    if axis:
        recs = []
        for h in axis.get("hypotheses", []):
            ex = h.get("extra", {})
            recs.append({
                "file": h.get("file"),
                "line": h.get("line"),
                "function": ex.get("function"),
                "ingress_param": ex.get("ingress_param"),
                "sink_kind": ex.get("sink_kind"),
                "axis": ex.get("axis"),
                "attack_class": "untrusted_ingress_slice_oob_panic",
                "covered_by": ex.get("covered_by"),
                "source": "rust-detector-runner.py:RU3",
                "verdict": "needs-fuzz",
                "snippet": h.get("snippet"),
            })
        jsonl = "".join(json.dumps(r, sort_keys=True) + "\n" for r in recs)
        (out_dir / "rust_oob_hypotheses.jsonl").write_text(jsonl,
                                                           encoding="utf-8")

    # RU6 advisory axis: emit needs-fuzz hypotheses JSONL (NO-AUTO-CREDIT).
    nondet = summary.get("rust_nondet_axis")
    if nondet:
        recs = []
        for h in nondet.get("hypotheses", []):
            ex = h.get("extra", {})
            recs.append({
                "file": h.get("file"),
                "line": h.get("line"),
                "function": ex.get("function"),
                "source_kind": ex.get("source_kind"),
                "sink": ex.get("sink"),
                "axis": ex.get("axis"),
                "attack_class": "consensus_divergence",
                "covered_by": ex.get("covered_by"),
                "sibling_detector": ex.get("sibling_detector"),
                "source": "rust-detector-runner.py:RU6",
                "verdict": "needs-fuzz",
                "snippet": h.get("snippet"),
            })
        jsonl = "".join(json.dumps(r, sort_keys=True) + "\n" for r in recs)
        (out_dir / "rust_nondet_hypotheses.jsonl").write_text(
            jsonl, encoding="utf-8")

    # RU7 advisory axis: emit needs-fuzz hypotheses JSONL (NO-AUTO-CREDIT).
    lockpoison = summary.get("rust_lockpoison_axis")
    if lockpoison:
        recs = []
        for h in lockpoison.get("hypotheses", []):
            ex = h.get("extra", {})
            recs.append({
                "file": h.get("file"),
                "line": h.get("line"),
                "function": ex.get("function"),
                "guard_var": ex.get("guard_var"),
                "lock_method": ex.get("lock_method"),
                "panic_op": ex.get("panic_op"),
                "axis": ex.get("axis"),
                "attack_class": "lock_poison_panic_while_holding",
                "covered_by": ex.get("covered_by"),
                "sibling_detector": ex.get("sibling_detector"),
                "source": "rust-detector-runner.py:RU7",
                "verdict": "needs-fuzz",
                "snippet": h.get("snippet"),
            })
        jsonl = "".join(json.dumps(r, sort_keys=True) + "\n" for r in recs)
        (out_dir / "rust_lockpoison_hypotheses.jsonl").write_text(
            jsonl, encoding="utf-8")

    # RU9 advisory axis: emit needs-fuzz hypotheses JSONL (NO-AUTO-CREDIT).
    strslice = summary.get("rust_strslice_axis")
    if strslice:
        recs = []
        for h in strslice.get("hypotheses", []):
            ex = h.get("extra", {})
            recs.append({
                "file": h.get("file"),
                "line": h.get("line"),
                "function": ex.get("function"),
                "str_var": ex.get("str_var"),
                "slice_index": ex.get("slice_index"),
                "axis": ex.get("axis"),
                "attack_class": "str_byte_slice_char_boundary_panic",
                "covered_by": ex.get("covered_by"),
                "sibling_detector": ex.get("sibling_detector"),
                "source": "rust-detector-runner.py:RU9",
                "verdict": "needs-fuzz",
                "snippet": h.get("snippet"),
            })
        jsonl = "".join(json.dumps(r, sort_keys=True) + "\n" for r in recs)
        (out_dir / "rust_strslice_hypotheses.jsonl").write_text(
            jsonl, encoding="utf-8")

    # RU10 advisory axis: emit needs-fuzz hypotheses JSONL (NO-AUTO-CREDIT).
    entropy = summary.get("rust_entropy_axis")
    if entropy:
        recs = []
        for h in entropy.get("hypotheses", []):
            ex = h.get("extra", {})
            recs.append({
                "file": h.get("file"),
                "line": h.get("line"),
                "function": ex.get("function"),
                "arm": ex.get("arm"),
                "rngcore_generic": ex.get("rngcore_generic"),
                "has_cryptorng_bound": ex.get("has_cryptorng_bound"),
                "axis": ex.get("axis"),
                "attack_class": "crypto_fn_missing_cryptorng_bound",
                "covered_by": ex.get("covered_by"),
                "sibling_detector": ex.get("sibling_detector"),
                "source": "rust-detector-runner.py:RU10",
                "verdict": "needs-fuzz",
                "snippet": h.get("snippet"),
            })
        jsonl = "".join(json.dumps(r, sort_keys=True) + "\n" for r in recs)
        (out_dir / "rust_entropy_hypotheses.jsonl").write_text(
            jsonl, encoding="utf-8")

    # RU11 advisory axis: emit needs-fuzz hypotheses JSONL (NO-AUTO-CREDIT).
    dropsafety = summary.get("rust_dropsafety_axis")
    if dropsafety:
        recs = []
        for h in dropsafety.get("hypotheses", []):
            ex = h.get("extra", {})
            recs.append({
                "file": h.get("file"),
                "line": h.get("line"),
                "drop_type": ex.get("drop_type"),
                "arms": ex.get("arms"),
                "impl_line": ex.get("impl_line"),
                "axis": ex.get("axis"),
                "attack_class": "drop_delegated_safety_postcond_unsound",
                "covered_by": ex.get("covered_by"),
                "sibling_detector": ex.get("sibling_detector"),
                "source": "rust-detector-runner.py:RU11",
                "verdict": "needs-fuzz",
                "snippet": h.get("snippet"),
            })
        jsonl = "".join(json.dumps(r, sort_keys=True) + "\n" for r in recs)
        (out_dir / "rust_dropsafety_hypotheses.jsonl").write_text(
            jsonl, encoding="utf-8")

    # RU2/R11 advisory axis: emit needs-fuzz hypotheses JSONL (NO-AUTO-CREDIT).
    panic_reach = summary.get("rust_panic_reach_axis")
    if panic_reach:
        recs = []
        for h in panic_reach.get("hypotheses", []):
            ex = h.get("extra", {})
            recs.append({
                "file": h.get("file"),
                "line": h.get("line"),
                "primitive": ex.get("sink_kind"),
                "ingress": ex.get("ingress_param"),
                "ingress_seam": ex.get("ingress_seam"),
                "path": ex.get("taint_hops"),
                "function": ex.get("function"),
                "axis": ex.get("axis"),
                "attack_class": "untrusted-panic-dos",
                "covered_by": ex.get("covered_by"),
                "sibling_detector": ex.get("sibling_detector"),
                "source": "rust-detector-runner.py:RU2",
                "verdict": "needs-fuzz",
                "snippet": h.get("snippet"),
            })
        jsonl = "".join(json.dumps(r, sort_keys=True) + "\n" for r in recs)
        (out_dir / "rust_panic_reach_hypotheses.jsonl").write_text(
            jsonl, encoding="utf-8")

    return main_out


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(
        description=__doc__.splitlines()[0] if __doc__ else ""
    )
    p.add_argument(
        "--workspace", type=Path,
        help="Workspace root to scan for *.rs files (alias of --scan).",
    )
    p.add_argument(
        "--scan", type=Path, dest="scan_path",
        help="Workspace root to scan for *.rs files (alias of --workspace).",
    )
    p.add_argument(
        "--list", action="store_true",
        help="List all valid pattern IDs (one per line) and exit 0.",
    )
    p.add_argument(
        "--json", action="store_true",
        help="Print summary JSON to stdout (after writing files).",
    )
    p.add_argument(
        "--print", action="store_true", dest="print_alias",
        help="Alias of --json for parity with go runner.",
    )
    p.add_argument(
        "--strict",
        action="store_true",
        help=(
            "Use the canonical in-scope inventory and fail closed on missing "
            "coverage, parser/read errors, or unresolved emitted hits."
        ),
    )
    args = p.parse_args(argv)

    if args.list:
        for pid in _VALID_PATTERN_IDS:
            print(pid)
        return 0

    ws = args.workspace or args.scan_path
    if ws is None:
        print(
            "[rust-detector-runner] ERR --workspace or --scan PATH is required",
            file=sys.stderr,
        )
        return 2
    if not ws.exists() or not ws.is_dir():
        print(
            f"[rust-detector-runner] ERR workspace not found: {ws}",
            file=sys.stderr,
        )
        return 2

    summary = scan_workspace(ws, strict=args.strict)
    out_path = _write_outputs(ws, summary)
    print(
        f"[rust-detector-runner] scanned {summary['rust_files_scanned']} rust files; "
        f"{summary['totals']['hits']} hits across "
        f"{len(summary['patterns'])} patterns -> {out_path}"
    )
    if args.json or args.print_alias:
        print(json.dumps(summary, indent=2, sort_keys=True))
    if args.strict and summary["strict_verification"]["verdict"] != "pass":
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
