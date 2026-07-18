#!/usr/bin/env python3
"""workspace-coverage-heatmap.py - SWEPT-SURFACE coverage map + per-contract heatmap.

r36-rebuttal: registered lane mimo-harness-build-2026-05-27.

Two related capabilities live in this tool:

1. Per-contract MIMO hypothesis-density heatmap (the original mode). Each MIMO
   sidecar carries a file_path_hint; aggregating across 21K+ sidecars produces
   a per-contract heatmap (high counts = many hypotheses; zero = UNCOVERED).
   USAGE: --workspace hyperbridge [--all-workspaces] [--json].

2. SWEPT-SURFACE coverage REPORT (the audit-completeness signal, this lane).
   Given a workspace PATH, enumerate every in-scope unit (Solidity FUNCTIONS
   first; degrade to FILE-level for .go/.rs/.move/.cairo), classify each as
   COVERED (>=1 hypothesis / hunt-hit / candidate references it) vs UNCOVERED,
   and emit a SCHEMA-VERSIONED machine-readable JSON report. This directly
   answers the standing operator question "is every surface actually audited?"
   The honest answer is a coverage MAP that is REPORTED, never papered over.

   NO-SILENT-CAPS DISCIPLINE: the report ALWAYS carries the true
   ``uncovered`` count. The ``uncovered_units`` list may be capped for size,
   but ``uncovered_units_truncated`` + ``uncovered`` always disclose the real
   total. The empirical anchor is Hyperbridge: the heatmap reported 742/743
   contracts UNCOVERED - that is the kind of signal that must be loud.

   USAGE: --workspace-path ~/audits/hyperbridge --coverage-report [--json]
   OUTPUT: <ws>/.auditooor/coverage_report.json (schema-versioned) consumed by
   the L37 audit-completeness gate as a first-class signal.

OUTPUT (heatmap mode): markdown report at reports/coverage_heatmap_<ws>_<date>.md
"""
from __future__ import annotations

import argparse
import collections
import glob
import hashlib
import json
import os
import re
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

AUDITOOOR_ROOT = Path(__file__).resolve().parent.parent
AUDITS_ROOT = Path.home() / "audits"

# Go/Cosmos external-entry-surface classifier (sibling module in tools/). Mirrors
# the import in tools/function-coverage-completeness.py so the coverage_report
# DENOMINATOR applies the SAME Go/Cosmos entry-point narrowing the per-function-
# completeness gate already applies - otherwise a Go/Cosmos L1's coverage_report
# (consumed by tools/hunt-coverage-gate.py) keeps an every-exported denominator
# while fcc's is narrowed, and the two gates disagree on the same workspace.
# Fail-open: absent import keeps the every-exported/full-source denominator (the
# larger/stricter direction), so this can never silently pass a workspace.
sys.path.insert(0, str(Path(__file__).resolve().parent))
try:
    import go_entrypoint_surface as _go_entry
except Exception:  # pragma: no cover - fail-open to full-source behavior
    _go_entry = None

# Env kill-switch for the coverage_report Go/Cosmos scope-narrowing (Lane
# CAP-HUNT-COVERAGE-SCOPE-NARROW). ``...=0/false/no/off`` disables it and
# restores the pre-existing full-source denominator unconditionally.
_ENV_COVERAGE_SCOPE_NARROW_DISABLE = "AUDITOOOR_COVERAGE_SCOPE_NARROW"

# Named strict env for the coverage-completeness backstop (defect 2, Obyte
# 2026-07-09). Unset/false = ADVISORY: a whole in-scope language silently
# dropped from the denominator is recorded in the report + emitted as a LOUD
# stderr WARN, but the report still writes and the CLI returns 0. Truthy
# (1/true/yes/on) = BLOCK: the CLI returns a non-zero exit so the L37 gate
# fails closed. Advisory-first by design; never silently passes.
_ENV_COVERAGE_COMPLETENESS_STRICT = "AUDITOOOR_COVERAGE_COMPLETENESS_STRICT"

# Schema for the SWEPT-SURFACE coverage report (mode 2).
COVERAGE_SCHEMA = "auditooor.workspace_coverage_report.v1"
RUST_SOURCE_GRAPH_SCHEMA = "auditooor.rust_source_graph.v1"
SOURCE_FRESHNESS_SCHEMA = "auditooor.coverage_source_freshness.v1"
NUMERATOR_FRESHNESS_SCHEMA = "auditooor.coverage_numerator_freshness.v1"
SOURCE_FRESHNESS_ALGORITHM = "sha256-canonical-json-v1"

# Default cap on how many uncovered unit names are inlined into the JSON. The
# TRUE count is always reported via `uncovered`; this only bounds the list size.
DEFAULT_UNCOVERED_LIST_CAP = 500
DEFAULT_SKIPPED_COVERAGE_LIST_CAP = 500

# r36-rebuttal: lane auto-coverage-closer-extend registered in .auditooor/agent_pathspec.json
# Source-file extensions we enumerate, mapped to enumeration granularity.
# "function" => parse function signatures as units (Solidity, Noir, and -
#               since the per-function-invariant-gen function parsers were
#               wired in - Rust/Go/Move/Cairo/Vyper too).
# "file"     => degrade gracefully: each source file is one unit.
#
# Non-Solidity languages were historically degraded to FILE granularity here.
# They are now FUNCTION-granular, REUSING the SAME function parsers that
# tools/per-function-invariant-gen.py uses (its `_GEN_FN_RES` table) so the
# coverage denominator matches the per-function-invariant unit set. The
# enumeration PREFERS the on-disk per_function_invariants/manifest.json
# (authoritative function list for the workspace) and falls back to an
# in-file regex parse, and only file-level when no function parses. `.sol`
# and `.nr` behavior is UNCHANGED. Generic: driven by file extension only.
_COVERAGE_EXT_GRANULARITY = {
    ".sol": "function",
    ".nr": "function",  # Noir (Rust-like `fn` / `pub fn` / `unconstrained fn`)
    ".vy": "function",
    ".go": "function",
    ".rs": "function",
    ".move": "function",
    ".cairo": "function",
}

# SSOT-REGISTRY BACKFILL (Obyte 2026-07-09 false-green fix). The explicit map
# above lists ONLY the extensions this module can parse at FUNCTION granularity
# (it ships a per-language function matcher for each). Every OTHER recognized
# source language in the canonical registry (tools/lib/source_extensions.py:
# Oscript `.oscript`/`.aa`, Clarity, Circom, ZoKrates, TS/JS/Py, ...) is a real
# in-scope surface too and MUST be enumerated - at FILE granularity, the honest
# degrade when no function parser exists here. Historically this map was a
# hand-maintained Solidity-plus-a-few list, so a whole language (Obyte's 382 AA
# units) read 0 in coverage_report.json while inscope_units.jsonl carried them -
# 63% of scope invisible and the map warn-PASSED. REUSING the registry means
# adding a language is a single edit THERE and every importer (this tool,
# function-coverage-completeness.py, hunt-sidecar-bridge.py) sees it. Fail-open:
# an import error keeps the explicit function-granular map unchanged, so a
# Solidity-only workspace classifies bit-for-bit identically either way.
try:
    from lib.source_extensions import SOURCE_EXTS as _REGISTRY_SOURCE_EXTS
    from lib.source_extensions import lang_of as _registry_lang_of
except Exception:  # pragma: no cover - fail-open to the explicit map
    _REGISTRY_SOURCE_EXTS = ()

    def _registry_lang_of(_p):  # type: ignore[misc]
        return None

for _reg_ext in _REGISTRY_SOURCE_EXTS:
    _COVERAGE_EXT_GRANULARITY.setdefault(_reg_ext, "file")

# Dirs never treated as in-scope source when enumerating coverage units.
_COVERAGE_PRUNE = (
    "/node_modules/", "/.git/", "/test/", "/tests/", "/build/", "/cache/",
    "/out/", "/target/", "/artifacts/", "/lib/", "/vendor/", "/third_party/",
    "/mocks/", "/.auditooor/", "/.audit_logs/", "/submissions/",
    "/prior_audits/", "/mining_rounds/", "/reports/", "/poc_execution/",
    "/poc-tests/", "/docs/", "/chimera_harnesses/",
    # Integration/E2E test frameworks (Cosmos `interchaintest`) are not a
    # production surface; their helpers/contracts inflate the denominator.
    "/interchaintest/",
)

# A directory whose basename matches a test-infra naming convention
# (testutil, testdata, testing, testpeggy, testtxfees, ...) is non-production
# and pruned by name - generic complement to the literal segments above.
_TEST_INFRA_DIR_RE = re.compile(r"^test[a-z0-9_]+$", re.IGNORECASE)

# Prune segments that are a SOLIDITY/JS dependency-vendoring convention (Foundry
# `lib/`, npm `vendor/`) but are STRUCTURAL package layout for some languages and
# must NOT auto-exclude those source files. Noir/Nargo packages canonically nest
# their source under a `lib/<pkg>/src/` tree, so a `.nr` file under `/lib/` is
# in-scope source, not a vendored dependency. Keyed by file extension.
# Other prune segments (test/tests/target/node_modules/.git/...) still apply.
_PRUNE_SEGMENT_EXEMPT_BY_EXT = {
    ".nr": ("/lib/",),
}

# r36-rebuttal: bugfix-inventory-claude-20260610
# Per-extension FILENAME exclusion patterns. Files whose names match these
# patterns are NOT counted as in-scope production source, even when they sit
# outside a directory-level prune segment. Mirrors the _gen_is_test_file logic
# in tools/per-function-invariant-gen.py so the coverage denominator and the
# per-function-invariant unit set exclude the same test files.
# Generic: keyed by extension, no workspace or target literal.
#   .go  - Go convention: any file ending in `_test.go` is a test file and
#           is NEVER part of the production surface (Go toolchain rule). The
#           per-function-invariant manifest never emits these (gen skips them
#           at line 531); the regex-fallback path in enumerate_units must do
#           the same exclusion or the denominator is inflated with test helpers
#           that the hunt never produces questions for.
_COVERAGE_FILE_EXCLUDE_BY_EXT: dict[str, re.Pattern] = {
    # Go: test files PLUS generated code by filename convention - protobuf
    # (`.pb.go` / gateway `.pb.gw.go`) and ETH ABI bindings (`.abigen.go`).
    # Generated code is never an auditable production surface; counting it
    # inflates the coverage denominator with XXX_Marshal / Size /
    # RegisterQueryHandler stubs that no hunt can adjudicate.
    ".go": re.compile(r"(_test\.go|_test_suite\.go|\.pb\.go|\.pb\.gw\.go|\.abigen\.go)$|^test_[a-z0-9_]*\.go$"),
    # Rust: unit/integration test source modules (e.g. CosmWasm contracts ship
    # `*_test.rs` / `integration_*test*.rs` as src modules, not under /tests/).
    ".rs": re.compile(r"(_tests?\.rs$|integration_.*test.*\.rs$)"),
    # Solidity: Foundry test (`*.t.sol`) and script (`*.s.sol`) contracts are
    # never production surface (the deep-engine harness gen already skips them).
    # ALSO mutation-testing artifact contracts (`*Mutant*.sol`, e.g.
    # SSVClustersMutantA.sol / SSVEBAccountingMutantB.sol) - deliberately BROKEN
    # copies seeded for non-vacuity verification, never deployed/in-scope; counting
    # their fns inflates the denominator with permanently-hollow rows (the SSV
    # 7-hollow false-red). Complemented by the mutation-artifact header check below.
    ".sol": re.compile(r"\.(t|s)\.sol$|[Mm]utant[A-Za-z0-9]*\.sol$"),
}

# Mutation-testing artifact marker: a seeded-mutant contract carries a header like
# `// MUTANT-A: Drop balance-sufficiency guard` / `mutation-testing`. Content-based
# complement to the `*Mutant*.sol` filename pattern - catches un-conventionally
# named mutants. Never a production surface.
_MUTATION_ARTIFACT_HEADER_RE = re.compile(
    r"\bMUTANT[- ]?[A-Z0-9]\b|mutation[- ]testing artifact", re.IGNORECASE)

# Canonical generated-code marker (Go `// Code generated ... DO NOT EDIT.`,
# golang.org/s/generatedcode; also emitted by gogo/protoc/abigen/mockgen and
# widely honoured cross-language). A file whose head carries it is machine-
# generated and is excluded from the coverage denominator regardless of name -
# the robust content-based complement to the filename patterns above.
_GENERATED_HEADER_RE = re.compile(r"Code generated .*DO NOT EDIT", re.IGNORECASE)


def _is_generated_source_file(full: str) -> bool:
    """True when the file head carries the canonical generated-code marker OR a
    mutation-testing artifact marker - both are non-production surfaces excluded
    from the coverage denominator regardless of filename."""
    try:
        with open(full, "r", encoding="utf-8", errors="replace") as fh:
            head = fh.read(4096)
    except OSError:
        return False
    return bool(_GENERATED_HEADER_RE.search(head)
                or _MUTATION_ARTIFACT_HEADER_RE.search(head))


# A Solidity `interface` is a body-less function DECLARATION set (every function
# ends in `;`, no `{ }` implementation), so no hunt can ever "cover" it - counting
# its functions inflates the coverage denominator with permanently-uncoverable
# rows (axelar-sc: 277 of 293 uncovered were `contracts/interfaces/I*.sol`). The
# `.sol` filename regex above only drops test/script/mutant contracts; line-235's
# claim that interfaces are excluded was never enforced. This content-based check
# (mirrors _is_generated_source_file) excludes a file ONLY when it declares purely
# interfaces - a file carrying any `contract`/`library` implementation is KEPT, so
# an abstract base or a mixed file is never wrongly pruned.
_SOL_IMPL_TYPE_RE = re.compile(r"\b(?:contract|library)\s+[A-Za-z_]\w*", re.MULTILINE)
_SOL_INTERFACE_RE = re.compile(r"\binterface\s+[A-Za-z_]\w*", re.MULTILINE)
_SOL_LINE_COMMENT_RE = re.compile(r"//[^\n]*")
_SOL_BLOCK_COMMENT_RE = re.compile(r"/\*.*?\*/", re.DOTALL)


def _is_interface_only_sol_file(full: str) -> bool:
    """True iff a `.sol` file declares ONLY interface(s) (no contract/library
    implementation). Body-less interface declarations can never be hunt-covered,
    so they are exempt from the coverable denominator. Conservative: any
    contract/library implementation in the file => not interface-only => kept."""
    try:
        with open(full, "r", encoding="utf-8", errors="replace") as fh:
            text = fh.read()
    except OSError:
        return False
    text = _SOL_BLOCK_COMMENT_RE.sub(" ", text)
    text = _SOL_LINE_COMMENT_RE.sub(" ", text)
    if _SOL_IMPL_TYPE_RE.search(text):
        return False
    return bool(_SOL_INTERFACE_RE.search(text))


def _oos_head(full: str, nbytes: int = 512) -> str | None:
    """Read the leading bytes of a file for the head-aware OOS check (F5).

    scope_exclusion.is_oos_dir(head=) fires the `Code generated ... DO NOT EDIT`
    regex against this text, so abigen/protoc/mockgen output that carries the
    header but NOT a conventional `.pb.go`/`.abigen.go` basename (e.g.
    contracts/bindings/*.go) is recognised as generated and excluded. Returns None
    on read failure so the caller degrades to filename-only classification."""
    try:
        with open(full, "r", encoding="utf-8", errors="replace") as fh:
            return fh.read(nbytes)
    except OSError:
        return None

# Solidity function-definition matcher. Captures the function name. Tolerant of
# modifiers/visibility on the same or following lines; we only need the name to
# build a unit key. Also matches constructor / fallback / receive.
_SOL_FN_RE = re.compile(
    r"\bfunction\s+([A-Za-z_$][A-Za-z0-9_$]*)\s*\(",
)
_SOL_SPECIAL_RE = re.compile(r"\b(constructor|fallback|receive)\s*\(")

# Noir function-definition matcher (Rust-like). Captures the function name.
# Tolerant of leading qualifiers on the SAME `fn` token line:
#   fn foo(...)           pub fn foo(...)        pub(crate) fn foo(...)
#   unconstrained fn x()  pub unconstrained fn y()   comptime fn z()
# The qualifiers are consumed by the broad `\bfn\s+<name>\s*\(` core; the
# leading `pub`/`unconstrained`/`comptime` simply precede `fn` so we only need
# to anchor on the `fn <name> (` shape. Trait/impl method decls match too,
# which is the desired FUNCTION granularity.
_NOIR_FN_RE = re.compile(
    r"\bfn\s+([A-Za-z_][A-Za-z0-9_]*)\s*(?:<[^>{(]*>)?\s*\(",
)

# r36-rebuttal: lane auto-coverage-closer-extend registered in .auditooor/agent_pathspec.json
# Per-language function matchers for the NON-Solidity function-granularity
# extensions. These mirror tools/per-function-invariant-gen.py `_GEN_FN_RES`
# EXACTLY so the coverage denominator and the per-function-invariant unit set
# enumerate the same functions. Keyed by file extension. (Solidity/Noir keep
# their own dedicated matchers above; do not route them through this table.)
_GENERIC_FN_RE_BY_EXT = {
    ".rs": re.compile(
        r"^\s*(?:pub(?:\s*\([^)]*\))?\s+)?(?:async\s+)?fn\s+([A-Za-z_]\w*)\s*[<(]",
        re.MULTILINE,
    ),
    ".go": re.compile(
        r"^\s*func\s*(?:\([^)]*\)\s*)?([A-Za-z_]\w*)\s*[\[(]", re.MULTILINE
    ),
    ".move": re.compile(
        r"^\s*(?:public\s+)?(?:entry\s+)?fun\s+([A-Za-z_]\w*)\s*[<(]",
        re.MULTILINE,
    ),
    ".cairo": re.compile(
        r"^\s*(?:pub\s+)?fn\s+([A-Za-z_]\w*)\s*[<(]", re.MULTILINE
    ),
    ".vy": re.compile(r"^\s*def\s+([A-Za-z_]\w*)\s*\(", re.MULTILINE),
}

# Per-function-invariant manifest (authoritative function list for the
# workspace, emitted by tools/per-function-invariant-gen.py). When present we
# prefer its `functions[]` rows over an in-file regex parse so coverage units
# track exactly what the per-function-invariant stage produced. Searched in the
# canonical .auditooor location first, then the legacy poc-tests location.
_PER_FN_MANIFEST_RELS = (
    os.path.join(".auditooor", "per_function_invariants", "manifest.json"),
    os.path.join("poc-tests", "per_function_invariants", "manifest.json"),
)


def _load_per_fn_manifest_index(ws: Path) -> dict[str, list[str]]:
    """Return {relpath -> [function names]} from the per-function-invariant
    manifest(s), or {} when no manifest exists.

    The manifest's ``functions[]`` rows carry ``source`` like
    ``src/contracts/.../accounts.rs:19`` (workspace-relative path + line) and
    ``function``. We index by the workspace-relative path (line suffix
    stripped) so :func:`_enumerate_functions` can look up a file's functions by
    its ``rel`` path. Generic: language-agnostic; reads whatever languages the
    manifest happens to carry.
    """
    index: dict[str, list[str]] = {}
    for rel in _PER_FN_MANIFEST_RELS:
        mpath = ws / rel
        if not mpath.is_file():
            continue
        try:
            data = json.loads(mpath.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            continue
        rows = data.get("functions") if isinstance(data, dict) else None
        if not isinstance(rows, list):
            continue
        for row in rows:
            if not isinstance(row, dict):
                continue
            src = str(row.get("source") or "")
            fn = str(row.get("function") or "").strip()
            if not src or not fn:
                continue
            # strip an optional ``:<line>`` suffix; normalize separators
            rel_path = src.rsplit(":", 1)[0].strip().replace("\\", "/")
            if not rel_path:
                continue
            index.setdefault(rel_path, [])
            if fn not in index[rel_path]:
                index[rel_path].append(fn)
    return index


def iso_now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _record_workspace_path_match(
    record: dict,
    workspace_path: Path | str | None,
) -> bool | None:
    if workspace_path is None or not isinstance(record, dict):
        return None
    target = Path(workspace_path).expanduser().resolve(strict=False)
    for key in ("workspace_path", "workspace"):
        raw = record.get(key)
        if not isinstance(raw, str) or not raw.strip():
            continue
        value = raw.strip()
        if key == "workspace" and "/" not in value and not value.startswith("~"):
            continue
        candidate = Path(value).expanduser().resolve(strict=False)
        return candidate == target
    return None


def _record_matches_workspace_path(
    record: dict,
    workspace_path: Path | str | None,
    *,
    require_binding: bool = False,
) -> bool:
    match = _record_workspace_path_match(record, workspace_path)
    if match is None:
        return not require_binding
    return match


def collect_hits(
    workspace: str,
    workspace_path: Path | str | None = None,
) -> tuple[collections.Counter, dict]:
    """Walk mimo_harness_<ws>* dirs; tally file_path_hint per contract.

    Returns (Counter of contract→hit-count, dict of contract→[applies-vals]).
    """
    counter = collections.Counter()
    applies_by_contract = collections.defaultdict(list)
    pattern = str(AUDITOOOR_ROOT / f"audit/corpus_tags/derived/mimo_harness_{workspace}*/*.json")
    for f in glob.glob(pattern):
        try:
            d = json.loads(Path(f).read_text())
        except Exception:
            continue
        if not _record_matches_workspace_path(
            d,
            workspace_path,
            require_binding=workspace_path is not None,
        ):
            continue
        if d.get("status") != "ok":
            continue
        r = d.get("result", "")
        if not isinstance(r, str) or not r.strip():
            continue
        body = r.strip().strip("`").lstrip("json").strip()
        try:
            j = json.loads(body)
        except json.JSONDecodeError:
            continue
        if not isinstance(j, dict):
            continue
        if not _record_matches_workspace_path(j, workspace_path):
            continue
        if _sidecar_has_hallucination_signal(d, j):
            continue
        hint = (j.get("file_path_hint") or "").strip()
        if not hint or hint.upper() in ("NA", "N/A", "NULL"):
            continue
        # Normalise: extract just the contract / module name
        norm = hint.split("/")[-1].split(":")[0]
        counter[norm] += 1
        applies_by_contract[norm].append(j.get("applies_to_target") or "?")
    return counter, dict(applies_by_contract)


def _harvest_mimo_file_path_hint_tokens(
    workspace: str,
    tokens: set[str],
    workspace_path: Path | str | None = None,
    denominator: dict | None = None,
    skipped: list[dict] | None = None,
) -> None:
    """Harvest path-qualified coverage tokens from MIMO file_path_hint records."""
    pattern = str(AUDITOOOR_ROOT / f"audit/corpus_tags/derived/mimo_harness_{workspace}*/*.json")
    for f in glob.glob(pattern):
        try:
            d = json.loads(Path(f).read_text())
        except Exception:
            continue
        if not _record_matches_workspace_path(
            d,
            workspace_path,
            require_binding=workspace_path is not None,
        ):
            continue
        artifact = _artifact_path_label(
            Path(workspace_path).expanduser().resolve(strict=False)
            if workspace_path is not None else Path(),
            Path(f),
        )
        status = str(d.get("status") or "").strip().lower()
        if status != "ok":
            parsed = _embedded_result_json(d)
            hint = parsed.get("file_path_hint") if isinstance(parsed, dict) else None
            fn_name = (
                parsed.get("function")
                or parsed.get("function_name")
                or parsed.get("fn")
            ) if isinstance(parsed, dict) else None
            if isinstance(hint, str) and hint.strip():
                _append_skipped_coverage(
                    skipped,
                    "mimo_file_path_hint",
                    artifact,
                    hint,
                    fn_name if isinstance(fn_name, str) else None,
                    _hunt_status_skip_reason(status),
                )
            continue
        r = d.get("result", "")
        if not isinstance(r, str) or not r.strip():
            _append_skipped_coverage(
                skipped,
                "mimo_file_path_hint",
                artifact,
                None,
                None,
                "missing_result_payload",
            )
            continue
        body = r.strip().strip("`").lstrip("json").strip()
        try:
            j = json.loads(body)
        except json.JSONDecodeError:
            _append_skipped_coverage(
                skipped,
                "mimo_file_path_hint",
                artifact,
                None,
                None,
                "invalid_result_payload",
            )
            continue
        if not isinstance(j, dict):
            _append_skipped_coverage(
                skipped,
                "mimo_file_path_hint",
                artifact,
                None,
                None,
                "invalid_result_payload",
            )
            continue
        if not _record_matches_workspace_path(j, workspace_path):
            continue
        hint = (j.get("file_path_hint") or "").strip()
        if _sidecar_has_hallucination_signal(d, j):
            _append_skipped_coverage(
                skipped, "mimo_file_path_hint", artifact, hint, None,
                "hallucination_tainted",
            )
            continue
        hint = (j.get("file_path_hint") or "").strip()
        if not hint or hint.upper() in ("NA", "N/A", "NULL"):
            _append_skipped_coverage(
                skipped,
                "mimo_file_path_hint",
                artifact,
                hint or None,
                None,
                "missing_file_path_hint",
            )
            continue
        if denominator is not None:
            _add_denominator_validated_tokens(
                tokens, denominator, hint, None, skipped, "mimo_file_path_hint",
                artifact, d, j,
            )
        else:
            token = _workspace_relative_source_token(hint, workspace_path)
            if token:
                _add_source_ref_tokens(tokens, token)


def list_workspace_files(ws_path: Path) -> set:
    """Return set of contract / module file basenames in workspace src."""
    out = set()
    if not ws_path.is_dir():
        return out
    for ext in ("*.sol", "*.go", "*.rs", "*.ts"):
        for f in ws_path.rglob(ext):
            # Skip vendored / test / build paths
            sp = str(f)
            if any(skip in sp for skip in ["/node_modules/", "/.git/", "/test/",
                                            "/tests/", "/build/", "/cache/",
                                            "/out/", "/target/", "/artifacts/"]):
                continue
            out.add(f.name)
    return out


def render_markdown(workspace: str, hits: collections.Counter,
                     applies_by: dict, ws_files: set) -> str:
    total_hits = sum(hits.values())
    covered = set(hits.keys()) & ws_files
    uncovered = ws_files - set(hits.keys())
    hits_only = set(hits.keys()) - ws_files  # hits where the file_hint doesn't match a real file
    yes_per = {k: sum(1 for a in applies_by.get(k, []) if a == "yes") for k in hits}

    lines = [
        f"# Coverage Heatmap - {workspace} - {iso_now()}",
        "",
        "Per-contract MIMO hypothesis-density. High counts = many hypotheses tested.",
        "**Zero-coverage files are where unspoken-of bugs hide.**",
        "",
        "## Summary",
        f"- Total MIMO hits with file_path_hint: **{total_hits}**",
        f"- Unique contracts hypothesized: **{len(hits)}**",
        f"- Workspace contract files: **{len(ws_files)}**",
        f"- Covered (hit ≥ 1): **{len(covered)}**",
        f"- **UNCOVERED (zero hypothesis attempts)**: **{len(uncovered)}**",
        f"- Phantom hits (file_hint doesn't match real file): {len(hits_only)}",
        "",
        "## Top 20 most-hypothesized contracts",
        "",
        "| Contract | Hits | applies=yes | applies=maybe | applies=no |",
        "|---|---|---|---|---|",
    ]
    for c, n in hits.most_common(20):
        avals = applies_by.get(c, [])
        y = sum(1 for v in avals if v == "yes")
        m = sum(1 for v in avals if v == "maybe")
        no = sum(1 for v in avals if v == "no")
        lines.append(f"| `{c}` | {n} | {y} | {m} | {no} |")

    lines.extend([
        "",
        "## UNCOVERED contracts (0 hits) - drill these next",
        "",
    ])
    if uncovered:
        for f in sorted(uncovered)[:50]:
            lines.append(f"  - `{f}`")
        if len(uncovered) > 50:
            lines.append(f"  ... + {len(uncovered) - 50} more")
    else:
        lines.append("  (full coverage)")

    if hits_only:
        lines.extend([
            "",
            "## Phantom hits (file_path_hint not matching real workspace files)",
            "MIMO hallucinated these file names. Likely R75 hallucination signal.",
            "",
        ])
        for c, n in collections.Counter({k: hits[k] for k in hits_only}).most_common(20):
            lines.append(f"  - `{c}` ({n} hits)")
    return "\n".join(lines)


def workspace_to_path(ws: str) -> Path:
    return AUDITS_ROOT / ws


# ==========================================================================
# SWEPT-SURFACE coverage REPORT (mode 2) - the audit-completeness signal.
# Given a workspace PATH, enumerate in-scope units, classify covered vs
# UNCOVERED, emit a schema-versioned JSON. NO SILENT TRUNCATION of the true
# uncovered count. Generic: no hardcoded target/workspace literal in the logic.
# ==========================================================================
def _coverage_pruned(path_str: str, ext: str | None = None) -> bool:
    """True iff the path is in a vendored / test / build dir we never count.

    When ``ext`` is supplied and that extension has exempt prune segments
    (see ``_PRUNE_SEGMENT_EXEMPT_BY_EXT``), those segments do NOT cause a prune -
    e.g. a Noir ``.nr`` file under ``/lib/`` is in-scope source, not a vendored
    dependency. All other prune segments still apply. ``ext`` is None when
    pruning a DIRECTORY (no extension), in which case the full prune list is
    used so directory-level pruning stays language-agnostic.
    """
    norm = "/" + path_str.replace("\\", "/").strip("/") + "/"
    exempt = _PRUNE_SEGMENT_EXEMPT_BY_EXT.get(ext or "", ())
    return any(seg in norm for seg in _COVERAGE_PRUNE if seg not in exempt)


# Union of every ext-exempt prune segment across all languages.
_ALL_EXEMPT_SEGMENTS = frozenset(
    seg for segs in _PRUNE_SEGMENT_EXEMPT_BY_EXT.values() for seg in segs
)


def _coverage_dir_pruned(path_str: str) -> bool:
    """True iff a DIRECTORY should be pruned at os.walk time.

    A directory is kept (not pruned) when its only prune reason is an
    ext-exempt segment - that lets an exempt-extension file nested beneath it
    (e.g. a Noir `.nr` under a `/lib/` package dir) still be reached. The
    ext-aware per-FILE check then prunes any non-exempt extensions found there.
    A directory pruned for a non-exempt reason (`/test/`, `/target/`,
    `/node_modules/`, ...) stays pruned.
    """
    norm = "/" + path_str.replace("\\", "/").strip("/") + "/"
    if any(seg in norm for seg in _COVERAGE_PRUNE if seg not in _ALL_EXEMPT_SEGMENTS):
        return True
    # Generic test-infra directory basename (testutil / testdata / testpeggy /
    # testtxfees / testing / ...). `test`/`tests` themselves are handled by the
    # literal segments above; this catches the `test<suffix>` package dirs.
    last = norm.strip("/").rsplit("/", 1)[-1]
    return bool(_TEST_INFRA_DIR_RE.match(last))


def _coverage_source_root(ws: Path) -> Path:
    """Prefer <ws>/src as the in-scope source root; fall back to ws itself."""
    src = ws / "src"
    if src.is_dir():
        return src
    return ws


# ----------------------------------------------------------------------------
# (BUG 2) SCOPE RESOLUTION. The denominator must be the IN-SCOPE asset set, not
# the whole repo. Precedence:
#   (a) curated-src     - <ws>/src is a curated subset (symlink-farm or small
#                         explicit subset) -> treat it as already-in-scope.
#   (b) scope-file      - a SCOPE.md / scope.json / asset-list / INTAKE_BASELINE
#                         asset section lists in-scope paths/globs -> enumerate
#                         ONLY files matching those.
#   (c) unscoped-fallback - neither signal present -> current behavior, but the
#                         report is HONESTLY LABELLED so a low number can never
#                         be mistaken for in-scope coverage.
# No workspace/program literal is hardcoded; curated-src is detected
# STRUCTURALLY and SCOPE.md is parsed GENERICALLY.
# ----------------------------------------------------------------------------

# Filenames (case-insensitive, in <ws> or <ws>/.auditooor) that may declare the
# in-scope asset set. JSON forms ("scope.json", asset-list JSON) and prose forms
# ("SCOPE.md", "INTAKE_BASELINE.md") are both parsed.
_SCOPE_FILE_CANDIDATES = (
    "SCOPE.md", "scope.json", "scope.md", "in_scope.json", "in_scope.txt",
    "assets.json", "INTAKE_BASELINE.md", "intake_baseline.md",
)

# A symlink-farm / curated subset is detected structurally: <ws>/src contains at
# least one symlink (audit roots symlinked to real package locations, the Aztec
# pattern). This is target-agnostic - any symlinked src/ counts.


def _src_has_symlink(src: Path) -> bool:
    """True iff <ws>/src (or anything one level under it) is/contains a symlink,
    the structural signature of a curated symlink-farm source root."""
    try:
        if src.is_symlink():
            return True
        for child in src.iterdir():
            if child.is_symlink():
                return True
    except OSError:
        return False
    return False


def _parse_scope_globs(ws: Path) -> tuple[list[str], list[str]]:
    """Parse in-scope and explicit out-of-scope path globs from SCOPE files /
    INTAKE_BASELINE asset section under <ws> or <ws>/.auditooor. Generic: we
    look for path-shaped tokens (containing ``/`` or ending in a known source
    extension, optionally with a ``*`` glob) and return them as globs. Never
    raises. Returns [] when no scope file yields any path token."""
    globs: list[str] = []
    exclude_globs: list[str] = []
    seen: set[str] = set()
    seen_exclude: set[str] = set()
    search_dirs = [ws, ws / ".auditooor"]
    path_tok_re = re.compile(
        r"(?<![\w./-])"
        r"([A-Za-z0-9_][A-Za-z0-9_./*\-]*"
        r"(?:/[A-Za-z0-9_./*\-]+|\.(?:" + "|".join(_SOURCE_REF_EXTS) + r")))"
    )
    # EXPLICIT-SCOPE-AUTHORITATIVE: when an operator provides a machine-readable
    # scope file (scope.json / in_scope.json / assets.json), it is the AUTHORITATIVE
    # in-scope definition - use ONLY it and skip the prose harvest from SCOPE.md /
    # INTAKE_BASELINE.md. Rationale (observed on the OP Stack monorepo): the prose
    # harvester over-includes cargo-workspace siblings (it pulls every crate under a
    # listed `src/rust` parent) and can MISS sibling-language dirs (op-node/op-dispute-mon
    # Go), so on a multi-language monorepo where only some crates/dirs are in scope the
    # prose-derived globs are wrong. An explicit scope.json is the operator's precise
    # statement of scope and must not be diluted by the noisy prose fallback. Workspaces
    # WITHOUT any JSON scope file keep the prior prose-parsing behavior unchanged.
    _json_scope_cands = ("scope.json", "in_scope.json", "assets.json")
    _authoritative_json = any(
        (d / c).is_file() and (d / c).stat().st_size > 0
        for d in search_dirs if d.is_dir()
        for c in _json_scope_cands
    )
    _candidates = (
        [c for c in _SCOPE_FILE_CANDIDATES if c.lower().endswith(".json")]
        if _authoritative_json else list(_SCOPE_FILE_CANDIDATES)
    )
    for d in search_dirs:
        if not d.is_dir():
            continue
        for cand in _candidates:
            f = d / cand
            if not f.is_file():
                # case-insensitive fallback
                matches = [p for p in d.glob("*")
                           if p.is_file() and p.name.lower() == cand.lower()]
                if not matches:
                    continue
                f = matches[0]
            try:
                raw = f.read_text(encoding="utf-8", errors="replace")
            except OSError:
                continue
            toks: list[str] = []
            excluded_toks: list[str] = []
            if f.suffix.lower() == ".json":
                toks, excluded_toks = _scope_glob_sets_from_json(raw)
            else:
                # prose: harvest path-shaped tokens, but only inside an asset /
                # in-scope context so we don't grab arbitrary doc paths. If an
                # explicit in-scope section exists, restrict to it; else scan all.
                body = _scope_section(raw)
                excluded_section = False
                for line in body.splitlines():
                    low = line.lower()
                    if low.lstrip().startswith("#"):
                        excluded_section = (
                            "out of scope" in low
                            or "out-of-scope" in low
                            or "not in scope" in low
                            or "excluded" in low
                        )
                    line_excluded = excluded_section or any(
                        marker in low
                        for marker in (
                            "out of scope",
                            "out-of-scope",
                            "not in scope",
                            "not-in-scope",
                            "excluded",
                            "exclude:",
                            "excludes:",
                            "excluding",
                        )
                    )
                    for m in path_tok_re.finditer(line):
                        tok = m.group(1).rstrip(".,;:)")
                        # require a real source extension or a directory glob so we
                        # don't harvest prose like "the-protocol".
                        if ("/" in tok or "*" in tok
                                or tok.lower().endswith(
                                    tuple("." + e for e in _SOURCE_REF_EXTS))):
                            if line_excluded:
                                excluded_toks.append(tok)
                            else:
                                toks.append(tok)
            for t in toks:
                if t and t not in seen:
                    seen.add(t)
                    globs.append(t)
            for t in excluded_toks:
                if t and t not in seen_exclude:
                    seen_exclude.add(t)
                    exclude_globs.append(t)
    # IN-SCOPE PRECEDENCE reconciliation (Axelar-DLT field run 2026-07-12):
    # A scope-NARROWING clause like "in the tofn repository, the only thing IN
    # SCOPE is src/ecdsa/mod.rs" NAMES an in-scope path but is phrased inside the
    # program's verbatim OUT-OF-SCOPE clause block, so the exclude harvester
    # grabbed `src/ecdsa/mod.rs` as an OOS glob. Because the cloned workspace path
    # `src/tofn/src/ecdsa/mod.rs` ends with that token, the ONE explicitly
    # in-scope file was silently EXCLUDED from the unit manifest (its 7 fns never
    # reached the hunt), while sibling `ed25519/mod.rs` stayed. Guard: an exclude
    # glob that equals, or is a path-suffix of, any explicitly IN-SCOPE glob is
    # dropped - an explicitly in-scope path can never be out of scope. Only fires
    # when the in-scope side is the MORE specific path, so a broad in-scope root
    # (e.g. `src/tofn`) never rescues a genuine narrower exclude (e.g. a test file).
    def _exclude_is_suffix_of_inscope(exc: str, inc: str) -> bool:
        e = exc.strip("/")
        i = inc.strip("/")
        return bool(e) and (e == i or i.endswith("/" + e))
    if globs and exclude_globs:
        exclude_globs = [
            e for e in exclude_globs
            if not any(_exclude_is_suffix_of_inscope(e, inc) for inc in globs)
        ]
    return globs, exclude_globs


def _scope_globs_from_json(raw: str) -> list[str]:
    return _scope_glob_sets_from_json(raw)[0]


def _scope_glob_sets_from_json(raw: str) -> tuple[list[str], list[str]]:
    """Extract path-shaped strings from a scope.json / asset-list JSON. Walks
    the JSON recursively and returns in-scope and explicit out-of-scope strings
    that look like a path or glob. Never raises."""
    try:
        data = json.loads(raw)
    except ValueError:
        return [], []
    out: list[str] = []
    excluded_out: list[str] = []

    def _is_oos_key(key: str) -> bool:
        norm = key.lower().replace("-", "_").replace(" ", "_")
        return any(
            marker in norm
            for marker in (
                "out_of_scope",
                "outscope",
                "exclude",
                "excluded",
                "not_in_scope",
                "not_scope",
            )
        )

    def _walk(o, *, excluded: bool = False):
        if isinstance(o, str):
            s = o.strip()
            if s and ("/" in s or "*" in s
                      or s.lower().endswith(
                          tuple("." + e for e in _SOURCE_REF_EXTS))):
                if excluded:
                    excluded_out.append(s)
                else:
                    out.append(s)
        elif isinstance(o, dict):
            for k, v in o.items():
                # Skip comment/metadata keys (``_comment``, ``_note``, ...): they
                # hold prose, not scope paths, and the path-token heuristic would
                # otherwise harvest a sentence containing a "/" as a bogus glob.
                if str(k).startswith("_"):
                    continue
                _walk(v, excluded=excluded or _is_oos_key(str(k)))
        elif isinstance(o, list):
            for v in o:
                _walk(v, excluded=excluded)

    _walk(data)
    return out, excluded_out


def _scope_section(raw: str) -> str:
    """Return the in-scope asset section of a prose scope file, or the whole
    text if no explicit section header is found. Generic: matches a heading line
    containing 'in scope' / 'in-scope' / 'scope' / 'assets in scope' and returns
    from there to the next heading (or 'out of scope' / 'out-of-scope')."""
    lines = raw.splitlines()
    start = None
    for i, ln in enumerate(lines):
        low = ln.lower()
        if not low.lstrip().startswith("#"):
            continue
        if "out of scope" in low or "out-of-scope" in low:
            continue
        if (
            "in scope" in low or "in-scope" in low
            or "assets" in low or low.rstrip().endswith("scope")
        ):
            start = i
            break
    if start is None:
        return raw
    out_lines = [lines[start]]
    for ln in lines[start + 1:]:
        low = ln.lower()
        if low.lstrip().startswith("#"):
            break
        out_lines.append(ln)
    return "\n".join(out_lines)


def _glob_to_regex(glob_pat: str) -> re.Pattern:
    """Compile a path glob (supporting ``*`` and ``**``) to a regex that matches
    if the glob appears as a path SUFFIX/SUBPATH of a file's path. We match
    permissively (substring-anchored on path segment boundaries) so a scope
    entry like ``src/Vault.sol`` matches an absolute ``/ws/src/Vault.sol`` and a
    directory entry like ``contracts/`` or ``contracts/**`` matches anything
    beneath it."""
    g = glob_pat.strip().strip("/")
    # normalise a trailing dir entry to match everything beneath it
    if glob_pat.rstrip().endswith("/") and "*" not in g:
        g = g + "/**"
    parts = []
    i = 0
    while i < len(g):
        if g[i:i + 2] == "**":
            parts.append(r".*")
            i += 2
            if i < len(g) and g[i] == "/":
                i += 1
        elif g[i] == "*":
            parts.append(r"[^/]*")
            i += 1
        else:
            parts.append(re.escape(g[i]))
            i += 1
    # match as a sub-path: optional leading dir, then the pattern, to EOL or '/'
    return re.compile(r"(?:^|/)" + "".join(parts) + r"(?:/|$)")


def _path_matches_any(regexes: list[re.Pattern], rel: str, full: str) -> bool:
    if not regexes:
        return False
    norm_full = full.replace("\\", "/")
    return any(rx.search(rel) or rx.search(norm_full) for rx in regexes)


def resolve_scope(ws: Path) -> dict:
    """Resolve the in-scope file set for a workspace.

    Returns a dict: {scope_mode, source_root, scope_globs (list, scope-file
    only)}. scope_mode is one of: 'curated-src', 'scope-file', 'unscoped-fallback'.
    Precedence: scope-file > curated-src > unscoped-fallback. Generic - no
    workspace/program literal; curated-src is structural, scope-file is parsed.
    """
    src = ws / "src"
    # (a) scope-file: an in-scope asset list yields path globs that ACTUALLY
    #     match real source files. We only accept scope-file mode when the
    #     harvested globs select >=1 real source file under the source root -
    #     otherwise a descriptive prose SCOPE.md (dYdX-style, listing tiers and
    #     reward tables, not asset paths) would mis-parse generic prose tokens
    #     ("network/liveness", "2/3") as globs and FALSELY over-restrict the
    #     denominator. A scope file that names no real source path is not a real
    #     asset listing; fall through to unscoped-fallback.
    src_root = _coverage_source_root(ws)
    globs, exclude_globs = _parse_scope_globs(ws)
    # UNION the SCOPE.md OOS spec's exclude globs (backtick paths, named
    # components, AND the canonical testnet/mock carve-out) into the denominator
    # exclusions. Without this, a documented-as-prose carve-out ("testnet + mock
    # files are NOT covered") never reached the source-unit denominator, so
    # example/** + loadtest/** demo contracts inflated it (SEI 2026-07-05: ~1k
    # throwaway units made the hunt-coverage gate demand hunts of demo code).
    # Kill-switch: AUDITOOOR_SCOPE_OOS=0. FAIL-OPEN on any import/parse error.
    if os.environ.get("AUDITOOOR_SCOPE_OOS", "1") != "0":
        try:
            from lib.scope_oos_globs import load_oos_spec
            _oos = load_oos_spec(str(ws))
            for _g in _oos.get("exclude_globs", []):
                if _g not in exclude_globs:
                    exclude_globs.append(_g)
        except Exception:
            pass
    # IN-SCOPE PRECEDENCE (Axelar-DLT field run 2026-07-12): a scope-NARROWING
    # clause ("in the tofn repository, the only thing IN SCOPE is
    # src/ecdsa/mod.rs") lives in the program's verbatim OUT-OF-SCOPE block, so
    # BOTH exclude harvesters (_parse_scope_globs AND lib.scope_oos_globs over
    # OOS_CHECKLIST.md) grabbed `src/ecdsa/mod.rs` as an OOS glob. Because the
    # cloned path `src/tofn/src/ecdsa/mod.rs` ends with that token, the ONE
    # explicitly in-scope file was excluded from the unit manifest (its 7 fns
    # never reached the hunt). Reconcile at this choke point (after BOTH exclude
    # sources merge, against the UNFILTERED in-scope globs which still hold the
    # specific `tofn/src/ecdsa/mod.rs` token): drop any exclude glob that equals,
    # or is a path-suffix of, an explicitly in-scope glob. Fires only when the
    # in-scope side is the more specific path, so a broad in-scope root never
    # rescues a genuine narrower exclude.
    if globs and exclude_globs:
        def _exc_suffix_of_inc(exc: str, inc: str) -> bool:
            e = exc.strip("/"); i = inc.strip("/")
            return bool(e) and (e == i or i.endswith("/" + e))
        exclude_globs = [
            e for e in exclude_globs
            if not any(_exc_suffix_of_inc(e, g) for g in globs)
        ]
    # Keep only globs that ACTUALLY match a real source file. This drops prose
    # tokens a descriptive SCOPE.md misparses ("network/liveness", "2/3") that
    # would otherwise either falsely flip into scope-file mode or pollute the
    # restriction regex set. A scope file that names no real source path is not
    # a real asset listing.
    scope_root = ws
    real_globs = _filter_globs_to_matching(ws, scope_root, globs)
    real_exclude_globs = _filter_globs_to_matching(ws, scope_root, exclude_globs)
    # AUTHORITATIVE MACHINE SCOPE: targets.tsv lists EVERY in-scope repo by
    # local_name; each resolves to a `src/<local_name>/` directory glob that
    # makes the repo's WHOLE tree (all nested components + all supported source
    # languages incl. Solidity) in-scope. This is additive and never-reduce: we
    # UNION the targets.tsv repo dirs with the prose/json globs (dedup, order:
    # targets.tsv first so a complete repo is preferred over an incidental
    # sub-tree token). Root cause it fixes: a prose SCOPE.md with HTTPS-URL repo
    # rows yields no path tokens for whole repos, so the harvester would falsely
    # confine the walk to a few incidental sub-tree tokens and drop entire
    # in-scope repos + every Solidity component (false-green coverage).
    targets_globs = _targets_tsv_inscope_globs(ws)
    if targets_globs:
        union: list[str] = []
        seen_u: set[str] = set()
        for g in targets_globs + real_globs:
            if g not in seen_u:
                seen_u.add(g)
                union.append(g)
        return {"scope_mode": "scope-file",
                "source_root": str(scope_root),
                "scope_globs": union,
                "scope_exclude_globs": real_exclude_globs}
    if real_globs:
        return {"scope_mode": "scope-file",
                "source_root": str(scope_root),
                "scope_globs": real_globs,
                "scope_exclude_globs": real_exclude_globs}
    # (b) curated-src: <ws>/src is a symlink-farm / curated subset.
    if src.is_dir() and _src_has_symlink(src):
        return {"scope_mode": "curated-src", "source_root": str(src),
                "scope_globs": [], "scope_exclude_globs": []}
    # (c) unscoped-fallback: current behavior, honestly labelled.
    return {"scope_mode": "unscoped-fallback",
            "source_root": str(src_root),
            "scope_globs": [],
            "scope_exclude_globs": []}


def _filter_globs_to_matching(ws: Path, src_root: Path,
                              globs: list[str]) -> list[str]:
    """Return the subset of ``globs`` that match >=1 real source file under
    ``src_root``. Guards against descriptive prose scope files whose tokens are
    not actual asset paths. Bounded single walk; never raises. Preserves input
    order of the surviving globs."""
    if not globs:
        return []
    regexes = [(_glob_to_regex(g), g) for g in globs]
    matched: set[str] = set()
    try:
        for dirpath, dirnames, filenames in os.walk(src_root, followlinks=True):
            dirnames[:] = [d for d in dirnames if not d.startswith(".")
                           and not _coverage_dir_pruned(
                               os.path.join(dirpath, d))]
            for fn in filenames:
                ext = os.path.splitext(fn)[1].lower()
                if ext not in _COVERAGE_EXT_GRANULARITY:
                    continue
                full = os.path.join(dirpath, fn)
                if _coverage_pruned(full, ext=ext):
                    continue
                rel = os.path.relpath(full, str(ws)).replace("\\", "/")
                norm_full = full.replace("\\", "/")
                for rx, g in regexes:
                    if g not in matched and (rx.search(rel)
                                             or rx.search(norm_full)):
                        matched.add(g)
                if len(matched) == len(regexes):
                    return [g for g in globs if g in matched]
    except OSError:
        return []
    return [g for g in globs if g in matched]


def _targets_tsv_inscope_globs(ws: Path) -> list[str]:
    """Return authoritative in-scope DIRECTORY globs from ``<ws>/targets.tsv``.

    ``targets.tsv`` is the MACHINE scope source (one tab-separated row per
    in-scope repo: ``<repo_url>\t<pin>\t<local_name>``; ``#`` comment lines are
    skipped). Each ``local_name`` is the directory name under ``<ws>/src`` that
    holds that repo's checkout. This returns one ``src/<local_name>/`` glob per
    row whose ``src/<local_name>`` directory ACTUALLY exists, so the whole tree
    of EVERY in-scope repo (incl. nested multi-component repos like an
    omni-bridge with sibling near/ + evm/ + solana/ component dirs) is walked.

    Why this is needed (root cause): a prose SCOPE.md lists repos as HTTPS URLs
    in a markdown table, which the path-token harvester ignores; it then picks up
    only the few incidental ``foo/bar`` path tokens that appear in prose notes
    and treats THOSE as the entire scope, silently confining the coverage walk to
    a couple of sub-trees and dropping whole in-scope repos + every Solidity
    component. targets.tsv carries the precise, complete repo set, so it is the
    authoritative in-scope source when present.

    Generic: no workspace/program literal; driven only by the tsv rows + the
    existence of ``src/<local_name>``. Returns [] when there is no targets.tsv or
    no row resolves to a real directory (callers then keep prior behaviour).
    Never raises.
    """
    tsv = ws / "targets.tsv"
    if not tsv.is_file():
        return []
    try:
        raw = tsv.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return []
    globs: list[str] = []
    seen: set[str] = set()
    src = ws / "src"
    for ln in raw.splitlines():
        line = ln.strip()
        if not line or line.startswith("#"):
            continue
        parts = ln.split("\t")
        # local_name is the 3rd column; fall back to the last non-empty column
        # when a row is malformed (still tolerant of extra trailing columns).
        local_name = ""
        if len(parts) >= 3 and parts[2].strip():
            local_name = parts[2].strip()
        else:
            nonempty = [p.strip() for p in parts if p.strip()]
            if nonempty:
                local_name = nonempty[-1]
        # Guard against accidentally grabbing a URL/pin as a local_name.
        if (not local_name or "/" in local_name or ":" in local_name
                or local_name.startswith("http")):
            continue
        if not (src / local_name).is_dir():
            continue
        g = f"src/{local_name}/"
        if g not in seen:
            seen.add(g)
            globs.append(g)
    return globs


def _canonical_sha256(obj) -> str:
    data = json.dumps(
        obj, sort_keys=True, separators=(",", ":"), ensure_ascii=True,
    ).encode("utf-8")
    return hashlib.sha256(data).hexdigest()


def _source_file_records(
    ws: Path, scope: dict, ignore_allowlist: bool = False
) -> list[dict]:
    """Return deterministic source-file records after current scope filtering.

    This intentionally mirrors the file walk used by ``enumerate_units`` but
    records only source denominator facts. Generated timestamps, mtimes,
    coverage tokens, and numerator artifacts are excluded from the hash inputs.

    ``ignore_allowlist=True`` additionally skips the SCOPE.md enumerated
    allowlist filter (see below). This is used ONLY when the caller needs the
    true workspace-wide basename population (basename-ambiguity detection) -
    an out-of-scope duplicate basename must still be counted so its coverage
    tokens are never silently basename-matched onto an in-scope unit of the
    same name (a scope-filtered-out file is not the same file).
    """
    scope_globs = scope.get("scope_globs", []) or []
    scope_regexes = [_glob_to_regex(g) for g in scope_globs] if scope_globs else []
    scope_exclude_globs = scope.get("scope_exclude_globs", []) or []
    scope_exclude_regexes = (
        [_glob_to_regex(g) for g in scope_exclude_globs]
        if scope_exclude_globs else []
    )
    root = Path(scope.get("source_root") or _coverage_source_root(ws))
    records: list[dict] = []
    if not root.is_dir():
        return records
    # Canonical OOS exclusion (shared) - third walk in this module that needs it,
    # so consumers of _source_file_records (per-function preflight, etc.) get the
    # same OOS-dir-filtered set as the manifest. (TODO: unify the 3 walks.)
    _is_oos = _load_is_oos()
    # SCOPE.md ENUMERATED allowlist (Strata 2026-06-30): _source_file_records feeds
    # the per-function preflight + coverage denominator. is_oos only drops
    # test/vendored/generated shapes, NOT files outside an enumerated in-scope target
    # list - so for an Immunefi "exactly these N targets" scope it leaked OOS files
    # (Strata: lens/, swap/, Strategy, DiscreteAccounting) into the preflight, which
    # generated per-fn MCP packs over the WHOLE repo (unbounded + wrong coverage).
    # Mirror write_inscope_manifest's _scope_md_allowlist_filter: drop a file whose
    # path matches no enumerated in-scope token. Allowlist-gated (whole-repo scope
    # docs unchanged) + fail-safe (errors -> no extra filtering).
    _allow_mf, _allow_smp = (
        (None, None) if ignore_allowlist else _load_scope_md_allowlist(ws)
    )
    seen_real: set[str] = set()
    for dirpath, dirnames, filenames in os.walk(root, followlinks=True):
        real = os.path.realpath(dirpath)
        if real in seen_real:
            dirnames[:] = []
            continue
        seen_real.add(real)
        dirnames[:] = [
            d for d in dirnames
            if not d.startswith(".")
            and not _coverage_dir_pruned(os.path.join(dirpath, d))
        ]
        for fn in filenames:
            ext = os.path.splitext(fn)[1].lower()
            if ext not in _COVERAGE_EXT_GRANULARITY:
                continue
            full = os.path.join(dirpath, fn)
            if _coverage_pruned(full, ext=ext):
                continue
            rel = os.path.relpath(full, str(ws)).replace("\\", "/")
            # F5: pass head= so the generated-header (DO NOT EDIT) catch fires for
            # abigen/protoc output without a conventional generated basename.
            if _is_oos is not None:
                _head = _oos_head(full)
                if _is_oos(rel, head=_head):
                    # is_oos_dir is EXTENSION-BLIND: it prunes a `/lib/` segment
                    # as a Foundry/npm vendored dep. For an ext whose layout uses
                    # that segment STRUCTURALLY (Noir/Nargo `.nr` under
                    # `lib/<pkg>/src/`), honor the same exemption the heatmap's own
                    # per-ext prune already applies - re-test is_oos with the
                    # exempt segment(s) neutralized; if the ONLY oos reason was an
                    # exempt segment, keep the file. ext with no exemption (.sol,
                    # .go, .rs, ...) is unaffected and still dropped.
                    _exempt = _PRUNE_SEGMENT_EXEMPT_BY_EXT.get(ext)
                    _kept = False
                    if _exempt:
                        _probe = "/" + rel.strip("/")
                        for _seg in _exempt:
                            _probe = _probe.replace(_seg, "/")
                        _probe = _probe.strip("/")
                        if not _is_oos(_probe, head=_head):
                            _kept = True
                    if not _kept:
                        continue
            if scope_regexes and not _path_matches_any(scope_regexes, rel, full):
                continue
            if _path_matches_any(scope_exclude_regexes, rel, full):
                continue
            if _allow_mf is not None and _allow_smp is not None:
                try:
                    if not _allow_smp.is_path_in_scope(rel, _allow_mf)[0]:
                        continue
                except Exception:
                    pass
            p = Path(full)
            try:
                payload = p.read_bytes()
                size = p.stat().st_size
            except OSError:
                payload = b""
                size = None
            records.append({
                "path": rel,
                "size": size,
                "sha256": hashlib.sha256(payload).hexdigest(),
            })
    return sorted(records, key=lambda r: r["path"])


def _load_is_oos():
    """Lazy-load scope_exclusion.is_oos_dir - the DIRECTORY-SHAPE-ONLY OOS check
    (vendored-dep dirs + test/mock/script/docs/historical + generated), WITHOUT
    project-NAME vendored markers. Critical for in-scope FORK repos (src/cosmos-sdk,
    src/cometbft): is_oos would drop the whole fork (under-scope), is_oos_dir keeps
    the fork's production source. Returns None if unavailable (degrade gracefully)."""
    try:
        import sys as _sys
        _lib = str(Path(__file__).resolve().parent / "lib")
        if _lib not in _sys.path:
            _sys.path.insert(0, _lib)
        from scope_exclusion import is_oos_dir  # type: ignore
        return is_oos_dir
    except Exception:
        return None


def enumerate_units(ws: Path, scope: dict | None = None) -> tuple[list[str], dict]:
    """Enumerate every in-scope unit in the workspace.

    Solidity (.sol) is enumerated at FUNCTION granularity (unit key
    ``<basename>::<fnname>``). Other languages degrade gracefully to FILE
    granularity (unit key ``<basename>``). Returns (sorted unique unit keys,
    detail dict with per-language/granularity counts).

    ``scope`` is the dict from :func:`resolve_scope`. When ``scope_mode`` is
    ``scope-file`` the enumeration is RESTRICTED to files matching the in-scope
    globs (BUG 2 fix); otherwise the whole source root is walked. The detail
    dict echoes ``scope_mode`` (and the globs used, for scope-file) so the
    coverage number is self-describing. When ``scope`` is None it is resolved
    here, preserving the old single-arg call shape.

    Generic: the enumeration is driven by file extension only - no target or
    workspace literal appears in the logic.
    """
    if scope is None:
        scope = resolve_scope(ws)
    scope_mode = scope.get("scope_mode", "unscoped-fallback")
    scope_globs = scope.get("scope_globs", []) or []
    scope_regexes = [_glob_to_regex(g) for g in scope_globs] if scope_globs else []
    scope_exclude_globs = scope.get("scope_exclude_globs", []) or []
    scope_exclude_regexes = (
        [_glob_to_regex(g) for g in scope_exclude_globs]
        if scope_exclude_globs else []
    )
    root = Path(scope.get("source_root") or _coverage_source_root(ws))
    # Canonical OOS-dir / vendored / test / historical exclusion (single source of
    # truth, shared with the scanners + CCIA) so the in-scope manifest + every
    # coverage denominator never carry previousVersions/mocks/scripts/docs/.t.sol/
    # soldeer-deps rows. Applied per-file on the workspace-relative path below.
    _is_oos = _load_is_oos()
    # SCOPE.md ENUMERATED allowlist (strata 2026-06-30): _source_file_records +
    # write_inscope_manifest already drop files outside an enumerated in-scope target
    # list, but enumerate_units (the coverage DENOMINATOR + every gate's live-unit set)
    # did NOT - so a SCOPE.md that names SPECIFIC files in an in-scope dir
    # (tranches/oracles/providers/AprPairProvider.sol) still admitted the dir's OOS
    # siblings (Aave*Provider.sol), inflating the denominator (strata: 372 vs 135 true,
    # coverage_report 750) and false-failing every coverage/hunt gate. Apply the SAME
    # allowlist the manifest uses so all three walks agree. Allowlist-gated (whole-repo
    # scope docs unchanged) + fail-safe (errors -> no extra filtering).
    _allow_mf, _allow_smp = _load_scope_md_allowlist(ws)
    units: set[str] = set()
    lang_counts: collections.Counter = collections.Counter()
    granularity: dict[str, str] = {}
    denominator_mode_by_ext: dict[str, str] = {}
    rust_source_unit_fallback_files: set[str] = set()
    files_scanned = 0
    if not root.is_dir():
        return [], {"languages": {}, "granularity": {}, "files_scanned": 0,
                    "source_root": str(root), "scope_mode": scope_mode,
                    "scope_globs": scope_globs}
    root_wide_scope = dict(scope)
    root_wide_scope["scope_globs"] = []
    root_wide_scope["scope_exclude_globs"] = []
    # ignore_allowlist=True: ambiguity detection must see EVERY file sharing a
    # basename workspace-wide, including ones a SCOPE.md enumerated allowlist
    # would otherwise drop - an out-of-scope duplicate still makes the basename
    # ambiguous, so its coverage tokens are never wrongly basename-matched onto
    # the in-scope file of the same name (see _source_file_records docstring).
    basename_counts = collections.Counter(
        Path(str(record.get("path") or "")).name
        for record in _source_file_records(ws, root_wide_scope, ignore_allowlist=True)
    )
    # r36-rebuttal: lane auto-coverage-closer-extend registered in .auditooor/agent_pathspec.json
    # Authoritative per-function-invariant manifest index (relpath -> [fns]).
    # When present, the non-Solidity function-granularity enumeration prefers it
    # so coverage units track the per-function-invariant unit set exactly.
    per_fn_manifest_index = _load_per_fn_manifest_index(ws)
    rust_graph_units, rust_graph_detail = _rust_source_graph_entrypoint_units(
        ws, scope_regexes, basename_counts, scope_exclude_regexes
    )
    rust_graph_mode = bool(rust_graph_units)
    rust_graph_files = set(rust_graph_detail.get("rust_source_graph_files") or [])
    # followlinks=True so a curated in-scope `src/` symlink-farm (audit roots
    # symlinked to their real package locations, as the Aztec workspace does) is
    # actually traversed - without it os.walk skips the symlinked dirs and the
    # whole workspace reads 0 files, degenerating to a FALSE coverage_fraction
    # of 1.0. A realpath-visited set bounds symlink cycles so the walk
    # terminates. Generic: no target literal; any symlinked source root benefits.
    seen_real: set[str] = set()
    for dirpath, dirnames, filenames in os.walk(root, followlinks=True):
        real = os.path.realpath(dirpath)
        if real in seen_real:
            dirnames[:] = []
            continue
        seen_real.add(real)
        # Prune in place. We keep any dir whose ONLY prune reason is an
        # ext-exempt segment (e.g. a Noir `lib/` package dir), so the per-file
        # ext-aware check below can decide language-by-language. Dirs pruned for
        # a non-exempt reason (test/, target/, node_modules/, ...) stay pruned.
        dirnames[:] = [
            d for d in dirnames
            if not d.startswith(".")
            and not _coverage_dir_pruned(os.path.join(dirpath, d))
        ]
        for fn in filenames:
            ext = os.path.splitext(fn)[1].lower()
            gran = _COVERAGE_EXT_GRANULARITY.get(ext)
            if gran is None:
                continue
            full = os.path.join(dirpath, fn)
            # Per-extension filename exclusion: skip test files that are
            # language-conventionally test-only (e.g. Go *_test.go). These are
            # never production surface and are skipped by per-function-invariant-gen
            # too, so the coverage denominator matches the invariant unit set.
            # Generic: driven entirely by _COVERAGE_FILE_EXCLUDE_BY_EXT; no
            # workspace or target literal. r36-rebuttal: bugfix-inventory-claude-20260610
            _file_excl = _COVERAGE_FILE_EXCLUDE_BY_EXT.get(ext)
            if _file_excl is not None and _file_excl.search(fn):
                continue
            # Content-based generated-code exclusion: machine-generated files
            # (protobuf, abigen, mockgen, gRPC-gateway) carry the canonical
            # `Code generated ... DO NOT EDIT` header and are not an auditable
            # surface. Robust complement to the filename patterns above (catches
            # generators that do not use a .pb/.abigen name). r36-rebuttal:
            # lane coverage-denominator-generated-exclude registered.
            if _is_generated_source_file(full):
                continue
            # Body-less Solidity interface files are permanently uncoverable.
            if ext == ".sol" and _is_interface_only_sol_file(full):
                continue
            # ext-aware file prune: exempt segments for this ext do not prune it.
            if _coverage_pruned(full, ext=ext):
                continue
            rel = os.path.relpath(full, str(ws)).replace("\\", "/")
            # Canonical OOS exclusion (shared single source of truth): drop
            # vendored / test / mock / script / docs / previousVersions / .t.sol
            # rows so they never enter the manifest or any coverage denominator.
            # F5: head= for the generated-header catch (complements the
            # _is_generated_source_file check above for abigen-style bindings).
            if _is_oos is not None:
                _head = _oos_head(full)
                if _is_oos(rel, head=_head):
                    # is_oos_dir is EXTENSION-BLIND: it prunes a `/lib/` segment
                    # as a Foundry/npm vendored dep. For an ext whose layout uses
                    # that segment STRUCTURALLY (Noir/Nargo `.nr` under
                    # `lib/<pkg>/src/`), honor the same exemption the heatmap's own
                    # per-ext prune already applies - re-test is_oos with the
                    # exempt segment(s) neutralized; if the ONLY oos reason was an
                    # exempt segment, keep the file. ext with no exemption (.sol,
                    # .go, .rs, ...) is unaffected and still dropped.
                    _exempt = _PRUNE_SEGMENT_EXEMPT_BY_EXT.get(ext)
                    _kept = False
                    if _exempt:
                        _probe = "/" + rel.strip("/")
                        for _seg in _exempt:
                            _probe = _probe.replace(_seg, "/")
                        _probe = _probe.strip("/")
                        if not _is_oos(_probe, head=_head):
                            _kept = True
                    if not _kept:
                        continue
            # (BUG 2) scope-file restriction: in scope-file mode, ONLY enumerate
            # files matching an in-scope glob. The match is on the path relative
            # to the workspace root (and the absolute path) so a glob like
            # ``src/Vault.sol`` or ``contracts/**`` selects precisely.
            if scope_regexes:
                if not _path_matches_any(scope_regexes, rel, full):
                    continue
            if _path_matches_any(scope_exclude_regexes, rel, full):
                continue
            # SCOPE.md enumerated-allowlist filter (parity with _source_file_records +
            # write_inscope_manifest): drop a file outside the enumerated in-scope
            # target list so the coverage denominator never carries an in-scope-dir's
            # OOS siblings. Allowlist-gated + fail-safe.
            if _allow_mf is not None and _allow_smp is not None:
                try:
                    if not _allow_smp.is_path_in_scope(rel, _allow_mf)[0]:
                        continue
                except Exception:
                    pass
            files_scanned += 1
            lang_counts[ext] += 1
            # r36-rebuttal: lane auto-coverage-closer-extend registered in .auditooor/agent_pathspec.json
            # When the per-function-invariant manifest carries function rows for
            # this non-Solidity file, it is the AUTHORITATIVE function-granular
            # enumeration and SUPERSEDES the coarser rust-source-graph entrypoint
            # subset for that file (1693 manifest fns vs 175 graph entrypoints on
            # near-intents). Generic: applies to .rs/.go/.move/.cairo/.vy alike.
            manifest_covers = (
                ext not in (".sol", ".nr")
                and rel in per_fn_manifest_index
                and bool(per_fn_manifest_index.get(rel))
            )
            granularity[ext] = (
                "per_function_invariant_manifest"
                if manifest_covers
                else "rust_source_graph_entrypoint"
                if ext == ".rs" and rust_graph_mode
                else gran
            )
            if manifest_covers:
                denominator_mode_by_ext[ext] = "function-level-manifest"
            elif ext == ".rs" and rust_graph_mode:
                denominator_mode_by_ext[ext] = "rust-source-graph-only"
            elif gran == "function":
                denominator_mode_by_ext[ext] = "function-level"
            else:
                denominator_mode_by_ext[ext] = "source-unit-only"
            base = rel if basename_counts.get(fn, 0) > 1 else fn
            # rust-graph short-circuit only applies when the manifest does NOT
            # cover the file (manifest is the stronger, function-granular source).
            if (
                ext == ".rs"
                and rust_graph_mode
                and rel in rust_graph_files
                and not manifest_covers
            ):
                continue
            # Function-granular when: (a) the manifest covers the file, OR (b) a
            # plain function-granularity ext that is NOT a rust-graph fallback
            # file (a rust-graph .rs fallback file with no manifest coverage keeps
            # its EXISTING source-unit behavior).
            effective_function_gran = manifest_covers or (
                gran == "function"
                and not (ext == ".rs" and rust_graph_mode)
            )
            if effective_function_gran:
                fn_units = _enumerate_functions(
                    Path(full), base, ext, rel=rel,
                    manifest_index=per_fn_manifest_index,
                )
                if fn_units:
                    units.update(fn_units)
                else:
                    # A function-granularity file with no parsable function
                    # (interface-only .sol / constants-only .nr) is still a unit
                    # at file granularity so it is never silently dropped from
                    # the denominator.
                    units.add(base)
            else:
                if ext == ".rs" and rust_graph_mode:
                    rust_source_unit_fallback_files.add(rel)
                    denominator_mode_by_ext[ext] = (
                        "rust-source-graph-partial-plus-source-unit-fallback"
                    )
                units.add(base)
    if rust_graph_mode:
        units.update(rust_graph_units)
        denominator_mode_by_ext[".rs"] = (
            "rust-source-graph-partial-plus-source-unit-fallback"
            if rust_source_unit_fallback_files
            else "rust-source-graph-only"
        )
    # r36-rebuttal: lane auto-coverage-closer-extend registered in .auditooor/agent_pathspec.json
    # Union in EVERY per-function-invariant manifest function unit. The manifest
    # is the authoritative in-scope function enumeration (emitted by
    # per-function-invariant-gen against the resolved src roots), so a function
    # whose source file the os.walk did not reach (source-root / scope-glob /
    # prune-segment differences) is still a genuine function-granular unit and
    # must not be silently dropped. This is what lifts a manifest-backed
    # workspace from the coarser file/graph count toward its true function count
    # (near-intents: ~175 graph entrypoints -> ~1693 manifest functions). For a
    # file whose basename is ambiguous workspace-wide the unit key stays
    # path-qualified (matching the walk's keying). Honest: only manifest-listed
    # functions are added; no synthesized names. Gated by scope-file globs so a
    # scoped run is not inflated by manifest files outside the in-scope globs.
    manifest_units_added = 0
    if per_fn_manifest_index:
        for rel_path, fns in per_fn_manifest_index.items():
            rp = rel_path.replace("\\", "/")
            full_p = str(ws / rp).replace("\\", "/")
            if scope_regexes and not _path_matches_any(scope_regexes, rp, full_p):
                continue
            if _path_matches_any(scope_exclude_regexes, rp, full_p):
                continue
            fname = os.path.basename(rp)
            ext_m = os.path.splitext(fname)[1].lower()
            if ext_m in (".sol", ".nr"):
                continue
            mbase = rp if basename_counts.get(fname, 0) > 1 else fname
            for nm in fns:
                key = f"{mbase}::{nm}"
                if key not in units:
                    units.add(key)
                    manifest_units_added += 1
            if ext_m and ext_m not in denominator_mode_by_ext:
                denominator_mode_by_ext[ext_m] = "function-level-manifest"
                granularity.setdefault(ext_m, "per_function_invariant_manifest")
    return sorted(units), {
        "languages": dict(lang_counts),
        "granularity": granularity,
        "denominator_mode_by_ext": denominator_mode_by_ext,
        "per_function_invariant_manifest_units_added": manifest_units_added,
        "rust_source_unit_fallback_files": sorted(rust_source_unit_fallback_files),
        "rust_source_unit_fallback_units": len(rust_source_unit_fallback_files),
        "files_scanned": files_scanned,
        "source_root": str(root),
        "scope_mode": scope_mode,
        "scope_globs": scope_globs,
        "scope_exclude_globs": scope_exclude_globs,
        "ambiguous_source_basenames": sorted(
            base for base, count in basename_counts.items() if count > 1
        ),
        **rust_graph_detail,
    }


def _rust_source_graph_entrypoint_units(
    ws: Path,
    scope_regexes: list[re.Pattern] | None = None,
    basename_counts: collections.Counter | None = None,
    scope_exclude_regexes: list[re.Pattern] | None = None,
) -> tuple[set[str], dict]:
    """Return Rust entrypoint units from <ws>/.auditooor/rust_source_graph.json.

    Unit keys reuse the existing function-granularity coverage shape. Duplicate
    basenames stay path-qualified as ``<relpath>.rs::<fn>``.
    """
    path = ws / ".auditooor" / "rust_source_graph.json"
    try:
        graph = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return set(), {}
    if not isinstance(graph, dict):
        return set(), {}
    meta = graph.get("_meta")
    if not isinstance(meta, dict):
        return set(), {}
    schema = meta.get("schema_version") or meta.get("schema")
    if schema != RUST_SOURCE_GRAPH_SCHEMA:
        return set(), {}

    scope_regexes = scope_regexes or []
    scope_exclude_regexes = scope_exclude_regexes or []
    basename_counts = basename_counts or collections.Counter()
    units: set[str] = set()
    graph_files: set[str] = set()
    crate_count = 0
    raw_entrypoint_count = 0
    scoped_out_count = 0
    for crate, payload in graph.items():
        if crate == "_meta" or not isinstance(payload, dict):
            continue
        crate_count += 1
        for entry in payload.get("entrypoints") or []:
            if not isinstance(entry, dict):
                continue
            file_rel = entry.get("file")
            fn = entry.get("fn")
            if not isinstance(file_rel, str) or not file_rel.strip():
                continue
            if not isinstance(fn, str) or not fn.strip():
                continue
            raw_entrypoint_count += 1
            rel = file_rel.strip().replace("\\", "/")
            norm_full = str(ws / rel).replace("\\", "/")
            if not (ws / rel).is_file():
                continue
            if scope_regexes and not _path_matches_any(scope_regexes, rel, norm_full):
                scoped_out_count += 1
                continue
            if _path_matches_any(scope_exclude_regexes, rel, norm_full):
                scoped_out_count += 1
                continue
            base_name = Path(rel).name
            base = rel if basename_counts.get(base_name, 0) > 1 else base_name
            if not base:
                continue
            graph_files.add(rel)
            units.add(f"{base}::{fn.strip()}")

    if not units:
        return set(), {}
    return units, {
        "rust_source_graph_path": str(path),
        "rust_source_graph_schema": schema,
        "rust_source_graph_sha256": _canonical_sha256(graph),
        "rust_source_graph_crates": crate_count,
        "rust_source_graph_entrypoints": raw_entrypoint_count,
        "rust_source_graph_units": len(units),
        "rust_source_graph_files": sorted(graph_files),
        "rust_source_graph_scoped_out": scoped_out_count,
    }


def build_function_denominator_honesty(enum_detail: dict) -> dict:
    """Summarize whether the denominator is truly function-level."""

    granularity = enum_detail.get("granularity") if isinstance(enum_detail, dict) else {}
    languages = enum_detail.get("languages") if isinstance(enum_detail, dict) else {}
    granularity = granularity if isinstance(granularity, dict) else {}
    languages = languages if isinstance(languages, dict) else {}

    function_level: set[str] = set()
    partial_function: set[str] = set()
    source_unit: set[str] = set()
    partial_reasons: dict[str, str] = {}

    for ext, gran in granularity.items():
        ext_s = str(ext)
        gran_s = str(gran)
        if gran_s == "function":
            function_level.add(ext_s)
        elif gran_s == "rust_source_graph_entrypoint":
            partial_function.add(ext_s)
            partial_reasons[ext_s] = "rust_source_graph_entrypoints_only"
        else:
            source_unit.add(ext_s)

    rust_files_scanned = int(languages.get(".rs") or 0)
    rust_graph_files = enum_detail.get("rust_source_graph_files") or []
    if ".rs" in partial_function and rust_files_scanned > len(rust_graph_files):
        source_unit.add(".rs")

    if partial_function or (function_level and source_unit):
        status = "partial"
    elif function_level and not source_unit:
        status = "complete"
    else:
        status = "source-unit-only"

    return {
        "function_denominator_status": status,
        "function_level_extensions": sorted(function_level),
        "partial_function_extensions": sorted(partial_function),
        "source_unit_extensions": sorted(source_unit),
        "partial_function_reasons": partial_reasons,
        "full_in_scope_function_denominator": status == "complete",
    }


def _enumerate_functions(
    path: Path,
    base: str,
    ext: str,
    rel: str | None = None,
    manifest_index: dict[str, list[str]] | None = None,
) -> list[str]:
    """Return ``<base>::<fnname>`` unit keys for every function in a
    function-granularity source file, dispatched by extension.
    # r36-rebuttal: lane auto-coverage-closer-extend registered in .auditooor/agent_pathspec.json

    ``.sol`` -> Solidity functions + constructor/fallback/receive.
    ``.nr``  -> Noir functions (``fn`` / ``pub fn`` / ``unconstrained fn`` ...).
    ``.rs`` / ``.go`` / ``.move`` / ``.cairo`` / ``.vy`` -> generic per-language
        function parse (the SAME parsers tools/per-function-invariant-gen.py
        uses). When ``manifest_index`` carries the file's ``rel`` path we PREFER
        the manifest's authoritative function list over the in-file regex parse;
        the regex parse is the fallback when no manifest covers the file.
    Unknown function-granularity extensions return [] so the caller degrades to
    file granularity (never silently drops the file from the denominator).
    """
    # PREFER the per-function-invariant manifest's authoritative function list
    # for the non-Solidity languages (function-granular for ALL languages).
    if (
        ext not in (".sol", ".nr")
        and manifest_index
        and rel is not None
        and rel in manifest_index
    ):
        names = manifest_index.get(rel) or []
        if names:
            return sorted({f"{base}::{n}" for n in names})

    try:
        txt = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return []
    out: list[str] = []
    if ext == ".sol":
        for m in _SOL_FN_RE.finditer(txt):
            out.append(f"{base}::{m.group(1)}")
        for m in _SOL_SPECIAL_RE.finditer(txt):
            out.append(f"{base}::{m.group(1)}")
    elif ext == ".nr":
        for m in _NOIR_FN_RE.finditer(txt):
            out.append(f"{base}::{m.group(1)}")
    else:
        # Generic per-language function parse (Rust/Go/Move/Cairo/Vyper),
        # reusing the per-function-invariant-gen matchers. Fallback path when no
        # manifest covers this file. Returns [] for an unmatched ext so the
        # caller degrades to FILE granularity (never silently drops the file).
        gen_re = _GENERIC_FN_RE_BY_EXT.get(ext)
        if gen_re is not None:
            for m in gen_re.finditer(txt):
                out.append(f"{base}::{m.group(1)}")
    # de-dup while preserving deterministic order
    return sorted(set(out))


def _unit_file_key(unit: str) -> str:
    return unit.partition("::")[0]


def _unit_basename(unit: str) -> str:
    return _unit_file_key(unit).split("/")[-1].split("\\")[-1]


def _unique_file_keys_by_basename(
    units: list[str],
    ambiguous_basenames: set[str] | None = None,
) -> dict[str, str]:
    ambiguous_basenames = ambiguous_basenames or set()
    by_base: dict[str, set[str]] = collections.defaultdict(set)
    for unit in units:
        by_base[_unit_basename(unit)].add(_unit_file_key(unit))
    return {
        base: next(iter(keys))
        for base, keys in by_base.items()
        if len(keys) == 1 and base not in ambiguous_basenames
    }


_SIDECAR_SHA_KEYS = (
    "source_sha256", "source_file_sha256", "file_sha256",
    "source_content_sha256", "source_digest_sha256", "code_sha256",
)

_SIDECAR_EXCERPT_KEYS = (
    "code_excerpt", "source_excerpt", "function_excerpt", "excerpt",
)

_HALLUCINATION_TEXT_MARKERS = (
    "hallucination", "unable-to-anchor", "unable to anchor",
    "excerpt unavailable", "file or fn not found", "file/function not found",
    "target function not found", "cannot synthesize", "placeholder",
    "conceptual pattern", "hypothetical", "illustrative", "generic sample",
)

_PLACEHOLDER_VALUES = frozenset({"", "na", "n/a", "null", "none", "?", "0..0", "?:0"})


def _build_denominator_index(
    ws: Path,
    scope: dict,
    units: list[str],
    enum_detail: dict,
) -> dict:
    source_records = _source_file_records(ws, scope)
    source_by_rel = {
        str(row.get("path") or ""): row
        for row in source_records
        if row.get("path")
    }
    by_base: dict[str, list[str]] = collections.defaultdict(list)
    for rel in source_by_rel:
        by_base[Path(rel).name].append(rel)
    for rels in by_base.values():
        rels.sort()

    ambiguous = set(enum_detail.get("ambiguous_source_basenames") or [])
    unit_set = set(units)
    units_by_file_key: dict[str, set[str]] = collections.defaultdict(set)
    for unit in units:
        units_by_file_key[_unit_file_key(unit)].add(unit)

    rel_to_file_key: dict[str, str] = {}
    for rel in source_by_rel:
        base = Path(rel).name
        rel_to_file_key[rel] = rel if base in ambiguous else base

    return {
        "workspace": ws,
        "source_by_rel": source_by_rel,
        "source_by_basename": dict(by_base),
        "units": unit_set,
        "units_by_file_key": units_by_file_key,
        "rel_to_file_key": rel_to_file_key,
        "ambiguous_source_basenames": ambiguous,
    }


def _append_skipped_coverage(
    skipped: list[dict] | None,
    source: str,
    artifact: str,
    file_ref: str | None,
    fn_name: str | None,
    reason: str,
) -> None:
    if skipped is None:
        return
    row = {
        "source": source,
        "artifact": artifact,
        "reason": reason,
    }
    if file_ref:
        row["file"] = file_ref
    if fn_name:
        row["function"] = fn_name
    skipped.append(row)


def _hunt_status_skip_reason(status: str) -> str:
    normalized = str(status or "").strip().lower().replace("-", "_")
    if not normalized:
        return "missing_hunt_status"
    if normalized in _MEGA_FAILED_STATUSES:
        return f"hunt_status_{normalized}"
    if normalized in _MEGA_SUCCESS_STATUSES:
        return "non_actionable_success_status"
    return f"hunt_status_{normalized}"


def _embedded_result_json(rec: dict) -> dict:
    raw = rec.get("result") if isinstance(rec, dict) else None
    if not isinstance(raw, str) or not raw.strip():
        return {}
    body = raw.strip().strip("`").lstrip("json").strip()
    try:
        parsed = json.loads(body)
    except json.JSONDecodeError:
        return {}
    return parsed if isinstance(parsed, dict) else {}


def _mega_record_skip_reason(rec: dict) -> str | None:
    if not isinstance(rec, dict):
        return "invalid_hunt_record"
    status = str(rec.get("status") or rec.get("verdict") or rec.get("result") or "").strip().lower()
    if status in _MEGA_FAILED_STATUSES:
        return _hunt_status_skip_reason(status)
    if status not in _MEGA_SUCCESS_STATUSES:
        return "missing_hunt_status" if not status else _hunt_status_skip_reason(status)
    err = rec.get("error")
    if isinstance(err, str) and err.strip():
        return "hunt_error"
    fa = rec.get("function_anchor")
    if not isinstance(fa, dict):
        return "missing_function_anchor"
    fp = fa.get("file")
    if not isinstance(fp, str) or not fp.strip() or fp.strip().lower() in _MEGA_EMPTY_ANCHOR_FILES:
        return "missing_anchor_file"
    return None


def _sidecar_field_values(*objs: dict, keys: tuple[str, ...]) -> list[str]:
    out: list[str] = []
    for obj in objs:
        if not isinstance(obj, dict):
            continue
        for key in keys:
            value = obj.get(key)
            if isinstance(value, str):
                out.append(value)
    return out


def _placeholder_text(value: str | None) -> bool:
    text = str(value or "").strip().lower()
    if text in _PLACEHOLDER_VALUES:
        return True
    return "excerpt unavailable" in text or "file or fn not found" in text


def _sidecar_has_hallucination_signal(*objs: dict) -> bool:
    for obj in objs:
        if not isinstance(obj, dict):
            continue
        applies = obj.get("applies_to_target")
        if isinstance(applies, bool) and applies is False:
            return True
        if isinstance(applies, str) and applies.strip().lower() in {"no", "false", "n/a", "na"}:
            return True
        verdict = obj.get("r76_verdict") or obj.get("hallucination_guard_verdict")
        if isinstance(verdict, str) and verdict.strip().lower().startswith("fail"):
            return True
        file_line = obj.get("file_line")
        if isinstance(file_line, str):
            low = file_line.strip().lower()
            if low in _PLACEHOLDER_VALUES or any(
                word in low
                for word in ("conceptual", "pattern", "hypothetical", "illustrative")
            ):
                return True
        for text in _sidecar_field_values(
            obj,
            keys=(
                "notes", "candidate_finding", "candidate_findings",
                "dupe_check", "falsification_attempt", "code_excerpt",
            ),
        ):
            low = text.lower()
            if any(marker in low for marker in _HALLUCINATION_TEXT_MARKERS):
                return True
    return False


def _first_sidecar_sha(*objs: dict) -> str | None:
    for obj in objs:
        if not isinstance(obj, dict):
            continue
        for key in _SIDECAR_SHA_KEYS:
            value = obj.get(key)
            if isinstance(value, str):
                text = value.strip().lower()
                if re.fullmatch(r"[0-9a-f]{64}", text):
                    return text
    return None


def _first_real_excerpt(*objs: dict) -> str | None:
    for text in _sidecar_field_values(*objs, keys=_SIDECAR_EXCERPT_KEYS):
        if not _placeholder_text(text):
            return text.strip()
    return None


def _resolve_denominator_file(
    denominator: dict,
    raw_ref: str,
) -> tuple[str | None, str | None]:
    ws = denominator.get("workspace")
    token = _workspace_relative_source_token(raw_ref, ws)
    if not token:
        return None, "missing_source_ref"
    token = token.replace("\\", "/").strip("/")
    source_by_rel = denominator.get("source_by_rel") or {}
    if token in source_by_rel:
        return token, None

    has_path = "/" in token
    if has_path:
        matches = [
            rel for rel in source_by_rel
            if rel.endswith("/" + token)
        ]
        if len(matches) == 1:
            return matches[0], None
        if len(matches) > 1:
            return None, "ambiguous_denominator_file"
        return None, "missing_denominator_file"

    matches = list((denominator.get("source_by_basename") or {}).get(token) or [])
    if len(matches) == 1:
        return matches[0], None
    if len(matches) > 1:
        return None, "ambiguous_denominator_file"
    return None, "missing_denominator_file"


def _sidecar_source_stale_reason(
    denominator: dict,
    rel: str,
    *objs: dict,
) -> str | None:
    source_by_rel = denominator.get("source_by_rel") or {}
    row = source_by_rel.get(rel) or {}
    current_sha = str(row.get("sha256") or "").lower()
    expected_sha = _first_sidecar_sha(*objs)
    if expected_sha and current_sha and expected_sha != current_sha:
        return "stale_source_sha256"

    excerpt = _first_real_excerpt(*objs)
    if excerpt:
        ws = denominator.get("workspace")
        path = Path(ws) / rel if isinstance(ws, Path) else None
        try:
            text = path.read_text(encoding="utf-8", errors="replace") if path else ""
        except OSError:
            text = ""
        if text and excerpt not in text:
            return "stale_source_excerpt"
    return None


def _add_denominator_validated_tokens(
    tokens: set[str],
    denominator: dict,
    file_ref: str,
    fn_name: str | None,
    skipped: list[dict] | None,
    source: str,
    artifact: str,
    *sidecar_objs: dict,
) -> bool:
    rel, reason = _resolve_denominator_file(denominator, file_ref)
    fn_clean = ""
    if isinstance(fn_name, str):
        fn_clean = fn_name.strip()
        if fn_clean.lower() in _MEGA_EMPTY_ANCHOR_FILES:
            fn_clean = ""
    if rel is None:
        _append_skipped_coverage(skipped, source, artifact, file_ref, fn_clean or None, reason or "missing_denominator_file")
        return False

    stale_reason = _sidecar_source_stale_reason(denominator, rel, *sidecar_objs)
    if stale_reason:
        _append_skipped_coverage(skipped, source, artifact, file_ref, fn_clean or None, stale_reason)
        return False

    file_key = (denominator.get("rel_to_file_key") or {}).get(rel, Path(rel).name)
    units = denominator.get("units") or set()
    if fn_clean:
        unit = f"{file_key}::{fn_clean}"
        if unit not in units:
            _append_skipped_coverage(
                skipped, source, artifact, file_ref, fn_clean,
                "missing_denominator_function",
            )
            return False
        tokens.add(unit)
        if file_key == Path(rel).name:
            tokens.add(f"{Path(rel).name}::{fn_clean}")
        return True

    if file_key in units:
        tokens.add(file_key)
        if file_key == Path(rel).name:
            tokens.add(Path(rel).name)
    else:
        tokens.add(file_key)
    return True


def build_denominator_disclosure(
    units: list[str],
    covered_units: list[str],
    uncovered_units: list[str],
    source_freshness: dict,
    denominator_honesty: dict,
    list_cap: int,
) -> dict:
    def _count_by_kind(rows: list[str]) -> dict:
        return {
            "function": sum(1 for row in rows if "::" in row),
            "source_file": sum(1 for row in rows if "::" not in row),
        }

    return {
        "explicit": True,
        "coverage_basis": "source-unit",
        "source_files_count": source_freshness.get("source_files_count"),
        "total_units": len(units),
        "covered_units": len(covered_units),
        "uncovered_units": len(uncovered_units),
        "unit_denominator_by_kind": _count_by_kind(units),
        "covered_units_by_kind": _count_by_kind(covered_units),
        "uncovered_units_by_kind": _count_by_kind(uncovered_units),
        "uncovered_units_list_cap": list_cap,
        "function_denominator_status": denominator_honesty.get("function_denominator_status"),
        "function_level_extensions": denominator_honesty.get("function_level_extensions"),
        "partial_function_extensions": denominator_honesty.get("partial_function_extensions"),
        "source_unit_extensions": denominator_honesty.get("source_unit_extensions"),
        "full_in_scope_function_denominator": denominator_honesty.get("full_in_scope_function_denominator"),
    }


def _enumerate_solidity_functions(path: Path, base: str) -> list[str]:
    """Back-compat shim: Solidity-only function enumeration."""
    return _enumerate_functions(path, base, ".sol")


def collect_coverage_tokens(ws: Path) -> set[str]:
    tokens, _skipped = collect_coverage_tokens_with_skips(ws)
    return tokens


def collect_coverage_tokens_with_skips(
    ws: Path,
    *,
    scope: dict | None = None,
    units: list[str] | None = None,
    enum_detail: dict | None = None,
) -> tuple[set[str], list[dict]]:
    """Collect every token a hypothesis / hunt-hit / candidate references that
    could mark a unit COVERED. Tokens are normalised basenames and
    ``<basename>::<fnname>`` keys harvested from:

      - MIMO sidecars' file_path_hint (heatmap source),
      - SUCCESS-ONLY mega/mimo per-fn ``function_anchor`` (BUG 3 fix): the real
        per-function hunt records put the source ref in
        ``function_anchor.file`` / ``function_anchor.fn`` (NOT file_path_hint),
        so they were harvesting ZERO. We now harvest them - but ONLY when the
        record is a REAL hunt result (status not failed/error/rate-limited AND
        ``function_anchor.file`` is a real path, not ``"?"``). A failed /
        rate-limited record hunted NOTHING and MUST NOT be credited; crediting
        it would FABRICATE coverage (the exact opposite honesty error).
      - <ws>/.auditooor/exploit_queue.json candidate file / function fields,
      - <ws>/hunt_findings_sidecars/*.json finding file / function fields,
      - <ws>/.auditooor coverage-bearing JSON (engage_report, coverage matrix),
      - <ws>/submissions/<status>/.../*.md FILED FINDING DRAFTS (BUG 1 fix):
        the source references a finding cites (file paths, file:line, and
        contract/function names) mark THOSE units COVERED. A draft that cites
        ``Vault.sol::deposit`` covers that unit precisely - it does NOT
        blanket-cover the whole workspace or even the rest of ``Vault.sol``.
      - <ws>/.auditooor/pre_flight_packs/pre_flight_pack_*.json current
        per-function preflight packs. Their ``source_ref`` + ``function`` pair
        marks exactly that function covered and does not blanket-cover siblings.
      - <ws>/{agent_outputs,poc-tests,mining_rounds,findings,
        deep_counterexamples,swarm}/**/*.{md,json} AGENT ARTIFACTS (BUG 3 fix):
        the real hunt work the numerator previously ignored entirely. Source
        refs cited in these artifacts (``Foo.go:50``, ``Foo.sol::deposit``,
        ``function bar``) mark THOSE units COVERED, precisely (not blanket). A
        bare ``function bar`` (no file) is scoped to the files CO-CITED in the
        SAME artifact (no global bare ``bar`` token - the over-credit fix).

    Returns the set of normalised coverage tokens. Generic across workspaces.
    """
    tokens: set[str] = set()
    skipped: list[dict] = []
    denominator = None
    if scope is not None and units is not None and enum_detail is not None:
        denominator = _build_denominator_index(ws, scope, units, enum_detail)

    # 1. MIMO sidecars keyed by workspace name (matches the heatmap source).
    #    These carry file_path_hint (back-compat - kept for any record that
    #    actually has it).
    if denominator is None:
        hits, _applies = collect_hits(ws.name, workspace_path=ws)
        for contract in hits:
            tokens.add(contract)
    _harvest_mimo_file_path_hint_tokens(
        ws.name,
        tokens,
        workspace_path=ws,
        denominator=denominator,
        skipped=skipped,
    )

    # 1b. (BUG 3) SUCCESS-ONLY mega/mimo per-fn function_anchor harvest. The
    #     real per-fn hunt records key the source ref under function_anchor,
    #     not file_path_hint, so collect_hits() above harvests nothing from
    #     them. Honesty-gated: failed/rate-limited records and ``"?"`` anchors
    #     contribute NOTHING.
    _harvest_mega_mimo_anchor_tokens(
        ws.name,
        tokens,
        workspace_path=ws,
        denominator=denominator,
        skipped=skipped,
    )

    # 2. exploit_queue.json candidate rows.
    eq = ws / ".auditooor" / "exploit_queue.json"
    _harvest_json_tokens(eq, tokens)

    # 3. hunt_findings_sidecars/*.json (workspace and .auditooor variants).
    for scd in (ws / "hunt_findings_sidecars", ws / ".auditooor" / "hunt_findings_sidecars"):
        if not scd.is_dir():
            continue
        for f in scd.glob("*.json"):
            _harvest_json_tokens(f, tokens)

    # 3b. source_artifacts review evidence can be nested.
    for sad in (ws / "source_artifacts", ws / ".auditooor" / "source_artifacts"):
        if not sad.is_dir():
            continue
        for f in sad.rglob("*.json"):
            _harvest_review_json_file_tokens(f, tokens)

    # 4. any other coverage-bearing JSON in .auditooor (best-effort).
    a = ws / ".auditooor"
    if a.is_dir():
        for name in ("engage_report.json", "coverage_tokens.json",
                     "mimo_coverage.json"):
            _harvest_json_tokens(a / name, tokens)

    # 5. (BUG 1) filed/staged finding DRAFTS under <ws>/submissions/. Each draft
    #    cites the source units it reports on; those units count as COVERED.
    _harvest_submission_draft_tokens(ws, tokens)

    # 6. Per-function preflight packs are current hunt work. Credit only the
    #    exact source_ref + function pair, denominator-validated when available.
    _harvest_preflight_pack_tokens(ws, tokens, denominator=denominator, skipped=skipped)

    # 7. (BUG 3) AGENT ARTIFACT dirs the numerator ignored entirely.
    _harvest_agent_artifact_tokens(ws, tokens)

    return tokens, skipped


# Record-status values that mean the hunt FAILED and the record must contribute
# NOTHING to coverage. A failed / rate-limited / errored record hunted nothing;
# crediting it would FABRICATE coverage. Matched case-insensitively.
_MEGA_FAILED_STATUSES = frozenset({"failed", "error", "rate-limited", "rate_limited"})
_MEGA_SUCCESS_STATUSES = frozenset({
    "ok",
    "pass",
    "passed",
    "success",
    "succeeded",
    "complete",
    "completed",
    "done",
    "verified",
    "confirmed",
})

# Anchor file placeholders that mean "no real source location was anchored".
_MEGA_EMPTY_ANCHOR_FILES = frozenset({"?", "", "na", "n/a", "null", "none"})


def _mega_record_is_real_hunt(rec: dict) -> tuple[str, str] | None:
    """Return ``(anchor_file, anchor_fn)`` for a mega/mimo per-fn record IFF it
    is a REAL hunt result, else None.

    The two honesty conditions (both must hold):
      (a) ``status`` is NOT a failed/error/rate-limited value, AND the record's
          ``error`` field is empty (a non-empty error means the run did not
          complete a real hunt even if status is missing/ok-ish).
      (b) ``function_anchor.file`` is a REAL path - not ``"?"`` / empty / N/A.

    A record failing either condition contributes NOTHING (returns None). This
    is the honesty line: a failed or unanchored record must not be credited as
    coverage. Never raises.
    """
    if not isinstance(rec, dict):
        return None
    status = str(rec.get("status") or rec.get("verdict") or rec.get("result") or "").strip().lower()
    if status in _MEGA_FAILED_STATUSES:
        return None
    if status not in _MEGA_SUCCESS_STATUSES:
        return None
    # A non-empty error means the run errored even if status is not "failed".
    err = rec.get("error")
    if isinstance(err, str) and err.strip():
        return None
    fa = rec.get("function_anchor")
    if not isinstance(fa, dict):
        return None
    fp = fa.get("file")
    if not isinstance(fp, str):
        return None
    if fp.strip().lower() in _MEGA_EMPTY_ANCHOR_FILES:
        return None
    fpc = fp.strip()
    if not fpc:
        return None
    fn = fa.get("fn")
    fnc = ""
    if isinstance(fn, str):
        fnc = fn.strip()
        if fnc.lower() in _MEGA_EMPTY_ANCHOR_FILES:
            fnc = ""
    return fpc, fnc


def _harvest_mega_mimo_anchor_tokens(
    workspace: str,
    tokens: set[str],
    workspace_path: Path | str | None = None,
    denominator: dict | None = None,
    skipped: list[dict] | None = None,
) -> None:
    """Harvest coverage tokens from the SUCCESS-ONLY ``function_anchor`` of
    mega*<ws>*/ and mimo_harness_<ws>* per-fn hunt records.

    Honesty-gated via :func:`_mega_record_is_real_hunt`: a failed /
    rate-limited record, or a record whose anchor file is ``"?"``, contributes
    NOTHING. For each real-hunt record we add:
      - ``<basename>`` (file-granularity token), and
      - ``<basename>::<fn>`` when a real ``fn`` is present (function-precise).
    Precision preserved: ``Foo.go::bar`` covers ``bar``, not its siblings.
    Never raises.
    """
    derived = AUDITOOOR_ROOT / "audit" / "corpus_tags" / "derived"
    patterns = (
        str(derived / f"mega*{workspace}*" / "*.json"),
        str(derived / f"mimo_harness_{workspace}*" / "*.json"),
    )
    seen_files: set[str] = set()
    for pat in patterns:
        for f in glob.glob(pat):
            if f in seen_files:
                continue
            seen_files.add(f)
            try:
                rec = json.loads(Path(f).read_text(encoding="utf-8",
                                                    errors="replace"))
            except (OSError, ValueError):
                continue
            if not _record_matches_workspace_path(
                rec,
                workspace_path,
                require_binding=workspace_path is not None,
            ):
                continue
            parsed = _embedded_result_json(rec)
            artifact = _artifact_path_label(
                Path(workspace_path).expanduser().resolve(strict=False)
                if workspace_path is not None else Path(),
                Path(f),
            )
            if _sidecar_has_hallucination_signal(rec, parsed):
                fa = rec.get("function_anchor") if isinstance(rec, dict) else None
                file_ref = fa.get("file") if isinstance(fa, dict) else parsed.get("file_path_hint")
                fn_name = fa.get("fn") if isinstance(fa, dict) else parsed.get("function")
                _append_skipped_coverage(
                    skipped,
                    "mega_function_anchor",
                    artifact,
                    file_ref if isinstance(file_ref, str) else None,
                    fn_name if isinstance(fn_name, str) else None,
                    "hallucination_tainted",
                )
                continue
            real = _mega_record_is_real_hunt(rec)
            if real is None:
                fa = rec.get("function_anchor") if isinstance(rec, dict) else None
                file_ref = fa.get("file") if isinstance(fa, dict) else parsed.get("file_path_hint")
                fn_name = fa.get("fn") if isinstance(fa, dict) else parsed.get("function")
                if not isinstance(fa, dict) and isinstance(file_ref, str) and file_ref.strip():
                    continue
                _append_skipped_coverage(
                    skipped,
                    "mega_function_anchor",
                    artifact,
                    file_ref if isinstance(file_ref, str) else None,
                    fn_name if isinstance(fn_name, str) else None,
                    _mega_record_skip_reason(rec) or "unusable_hunt_record",
                )
                continue
            anchor_file, anchor_fn = real
            if denominator is not None:
                _add_denominator_validated_tokens(
                    tokens,
                    denominator,
                    anchor_file,
                    anchor_fn or None,
                    skipped,
                    "mega_function_anchor",
                    artifact,
                    rec,
                    parsed,
                )
            else:
                token = _workspace_relative_source_token(anchor_file, workspace_path)
                if not token:
                    continue
                _add_source_ref_tokens(tokens, token, anchor_fn or None)


# Agent-artifact directories under <ws> that carry REAL hunt work the coverage
# numerator must credit. Each may hold .md / .json artifacts citing source refs.
_AGENT_ARTIFACT_DIRS = (
    "agent_outputs", "poc-tests", "mining_rounds", "findings",
    "deep_counterexamples", "swarm",
)

# Artifact filename stems that are bookkeeping/index, not hunt work. Matched
# case-insensitively against the stem. Kept conservative so we don't drop real
# hunt artifacts (PLAN / VERDICT / results are hunt work and ARE harvested).
_ARTIFACT_BOOKKEEPING_STEMS = frozenset({
    "readme", "index", "tracker",
})

# Generated harness/build output can be very large and is not source-review
# evidence. Harvest the human-authored harness notes, not Foundry/crytic blobs.
_AGENT_ARTIFACT_GENERATED_DIRS = frozenset({
    "__pycache__",
    "artifacts",
    "broadcast",
    "build",
    "build-info",
    "cache",
    "coverage",
    "crytic-export",
    "lib",
    "node_modules",
    "out",
    "target",
    "vendor",
})


def _harvest_agent_artifact_tokens(ws: Path, tokens: set[str]) -> None:
    """Harvest coverage tokens from the SOURCE REFERENCES cited in the agent
    artifact dirs under <ws> (agent_outputs/, poc-tests/, mining_rounds/,
    findings/, deep_counterexamples/, swarm/).

    Walks each dir recursively for .md / .json, parsing each artifact body via
    :func:`_harvest_artifact_text_tokens` (PER-ARTIFACT co-occurrence scoping),
    so tokens line up with enumerated units. For each cited ref we add:
      - ``Foo.go`` for a bare file or file:line citation (file granularity),
      - ``Foo.sol::deposit`` for a function-precise citation, plus
      - for each BARE ``function <name>`` reference, a file-qualified
        ``<base>::<name>`` token for every source-file basename CO-CITED IN
        THE SAME ARTIFACT (a bare fn with no co-cited file covers nothing -
        the over-credit honesty fix; no global bare ``<name>`` is emitted).
    Covers the cited units PRECISELY (not blanket-by-workspace): a file-level
    token only blanket-covers a file's functions when no function-precise
    token exists for that base (the ``_unit_is_covered`` precision rule).
    Obvious non-source bookkeeping (README / INDEX / TRACKER) is skipped.
    Never raises.
    """
    for dname in _AGENT_ARTIFACT_DIRS:
        d = ws / dname
        if not d.is_dir():
            continue
        for dirpath, dirnames, filenames in os.walk(d):
            # Skip hidden dirs and generated harness/build outputs.
            dirnames[:] = [
                dd for dd in dirnames
                if not dd.startswith(".")
                and dd.lower() not in _AGENT_ARTIFACT_GENERATED_DIRS
            ]
            for fn in filenames:
                ext = os.path.splitext(fn)[1].lower()
                if ext not in (".md", ".json"):
                    continue
                stem = os.path.splitext(fn)[0].lower()
                if stem in _ARTIFACT_BOOKKEEPING_STEMS:
                    continue
                p = Path(dirpath) / fn
                try:
                    txt = p.read_text(encoding="utf-8", errors="replace")
                except OSError:
                    continue
                _harvest_artifact_text_tokens(txt, tokens)


def _file_sha256(path: Path) -> str | None:
    h = hashlib.sha256()
    try:
        with path.open("rb") as fh:
            for chunk in iter(lambda: fh.read(1024 * 1024), b""):
                h.update(chunk)
    except OSError:
        return None
    return h.hexdigest()


def _artifact_path_label(ws: Path, path: Path) -> str:
    try:
        rel = path.relative_to(ws)
        return "workspace:" + rel.as_posix()
    except ValueError:
        pass
    try:
        rel = path.relative_to(AUDITOOOR_ROOT)
        return "auditooor:" + rel.as_posix()
    except ValueError:
        return str(path)


def _append_numerator_artifact_record(
    records: list[dict],
    seen: set[str],
    ws: Path,
    path: Path,
) -> None:
    try:
        st = path.stat()
    except OSError:
        return
    if not path.is_file():
        return
    key = str(path)
    if key in seen:
        return
    sha = _file_sha256(path)
    if sha is None:
        return
    seen.add(key)
    records.append({
        "path": _artifact_path_label(ws, path),
        "size": st.st_size,
        "sha256": sha,
    })


# Bookkeeping draft stems that are NOT finding reports (tracker / index files).
# Matched case-insensitively against the .md filename stem.
_SUBMISSION_BOOKKEEPING_STEMS = frozenset({
    "submissions", "readme", "tracker", "index", "hold_note", "hold-note",
    "holdnote",
})

# Source-file extensions a finding draft may cite. Mirrors the enumerator's
# extension set so tokens line up with enumerated units.
_SOURCE_REF_EXTS = ("sol", "go", "rs", "vy", "nr", "move", "cairo")

# Match a source reference inside a draft body. Three shapes, all anchored on a
# real source-file basename so we never harvest prose words:
#   <path/>Foo.sol            -> file-granularity token Foo.sol
#   <path/>Foo.sol:52         -> file-granularity token Foo.sol (line dropped)
#   Foo.sol::deposit          -> function-precise token Foo.sol::deposit
# The basename (last path segment) is captured plus an optional ::fn suffix.
_DRAFT_SOURCE_REF_RE = re.compile(
    r"((?:[A-Za-z0-9_.\-]+[\\/])*[A-Za-z_][A-Za-z0-9_.\-]*\.(?:"
    + "|".join(_SOURCE_REF_EXTS) + r"))"
    r"(?:::([A-Za-z_][A-Za-z0-9_]*))?"
    r"(?::[0-9]+(?:-[0-9]+)?)?"
)

# A bare ``function <name>`` / ``func <name>`` reference (no file). Captured so a
# real function name on the SAME LINE as a source-file basename can be credited
# as ``<base>::<name>`` (tight-proximity scoping). Group 1 is the name; group 2
# is the literal ``(`` IFF the name is immediately followed by an open paren
# (i.e. written as a real signature / call ``deposit(``). The name + paren-flag
# are passed to :func:`_is_plausible_fn_name`, which rejects English prose words
# that follow the literal word "function" in a sentence ("function is called",
# "function reverts", "function that checks") so prose never manufactures junk
# tokens like ``is`` / ``reverts`` / ``uncallable`` that would multiply across
# every co-cited file.
_DRAFT_BARE_FN_RE = re.compile(
    r"\b(?:function|func|fn)\s+([A-Za-z_][A-Za-z0-9_]*)\s*(\()?"
)

# English prose words that commonly follow the literal word "function" in a
# sentence ("the function is called", "a function for X", "function arguments").
# Captured as a bare-fn name they would multiply junk coverage across every
# co-cited file, so they are rejected outright. Biased to DROP ambiguous
# lowercase single-word matches: it is better to miss a real lowercase fn named
# ``call`` than to credit ``is`` across 71 files.
_PROSE_STOPWORDS = frozenset({
    "is", "as", "that", "for", "the", "this", "these", "those", "with", "and",
    "or", "to", "of", "in", "a", "an", "it", "its", "by", "on", "at", "be",
    "are", "was", "were", "been", "being", "has", "have", "had", "will",
    "would", "should", "could", "may", "might", "must", "can", "do", "does",
    "did", "not", "no", "if", "then", "else", "when", "while", "which", "who",
    "whose", "what", "where", "how", "all", "any", "some", "each", "every",
    "from", "into", "onto", "out", "up", "down", "over", "under", "above",
    "below", "but", "so", "such", "than", "too", "very", "just", "only",
    "also", "here", "there", "now", "call", "calls", "called", "calling",
    "selector", "selectors", "signature", "signatures", "argument",
    "arguments", "arg", "args", "param", "params", "parameter", "parameters",
    "return", "returns", "value", "values", "name", "names", "type", "types",
    "body", "header", "definition", "declaration", "implementation", "logic",
    "pointer", "pointers",
    # prose VERBS / adjectives that follow "function" in NatSpec / sentences
    # ("this function reverts", "the function donates", "function uncallable",
    # "function that checks", "function throws") - len>=6, so they slipped past
    # a pure length filter and multiplied across co-cited OpenZeppelin/UniV4
    # interface files. Listed here and additionally length-gated below.
    "reverts", "revert", "donates", "donate", "provides", "provide",
    "uncallable", "checks", "check", "throws", "throw", "emits", "emit",
    "computes", "compute", "handles", "handle", "performs", "perform",
    "executes", "execute", "processes", "process", "applies", "apply",
    "ensures", "ensure", "requires", "require", "stores", "store", "loads",
    "load", "fetches", "fetch", "updates", "update", "modifies", "modify",
    "accepts", "accept", "rejects", "reject", "allows", "allow", "enables",
    "enable", "disables", "disable", "wrapper", "helper", "method", "methods",
    "above", "below", "external", "internal", "public", "private", "payable",
    "virtual", "override", "modifier", "interface", "contract", "library",
    "struct", "mapping", "abstract",
})


def _source_ref_token(raw: str) -> str | None:
    value = (raw or "").strip().replace("\\", "/")
    if not value:
        return None
    value = re.sub(r"(?::[0-9]+(?:-[0-9]+)?)$", "", value)
    while value.startswith("./"):
        value = value[2:]
    value = value.strip("/")
    return value or None


def _review_source_path_hint(raw: Any) -> str | None:
    text = str(raw or "").strip().replace("\\", "/")
    if not text:
        return None
    match = re.search(
        r"([A-Za-z0-9_./-]+\.(?:sol|vy|nr|rs|go|move|cairo|ts|tsx|js|jsx|py))"
        r"(?::[0-9]+(?:-[0-9]+)?)?",
        text,
    )
    if match:
        return _source_ref_token(match.group(1))
    return _source_ref_token(text)


def _add_review_unit_tokens(
    tokens: set[str],
    raw_name: Any,
    raw_ref: Any = None,
) -> None:
    name = str(raw_name or "").strip()
    if "::" not in name:
        return
    file_hint, fn_name = name.split("::", 1)
    fn_name = fn_name.split("(", 1)[0].strip()
    if not file_hint.strip() or not fn_name:
        return
    source_ref = _review_source_path_hint(raw_ref) or _review_source_path_hint(file_hint)
    if not source_ref:
        return
    _add_source_ref_tokens(tokens, source_ref, fn_name)


def _harvest_review_json_tokens(data: Any, tokens: set[str]) -> None:
    if not isinstance(data, dict):
        return

    target = data.get("target")
    if isinstance(target, dict):
        _add_review_unit_tokens(
            tokens,
            target.get("name") or target.get("unit") or target.get("source_unit"),
            target.get("source_ref") or target.get("path") or target.get("file"),
        )

    for key in _REVIEW_UNIT_LIST_KEYS:
        raw_units = data.get(key)
        if not isinstance(raw_units, list):
            continue
        for raw_unit in raw_units:
            if isinstance(raw_unit, str):
                _add_review_unit_tokens(tokens, raw_unit)
            elif isinstance(raw_unit, dict):
                _add_review_unit_tokens(
                    tokens,
                    raw_unit.get("name") or raw_unit.get("unit") or raw_unit.get("source_unit"),
                    raw_unit.get("source_ref") or raw_unit.get("path") or raw_unit.get("file"),
                )

    citations = data.get("source_citations")
    if not isinstance(citations, list):
        return
    for citation in citations:
        if isinstance(citation, str):
            _add_review_unit_tokens(tokens, citation)
            continue
        if not isinstance(citation, dict):
            continue
        _add_review_unit_tokens(
            tokens,
            citation.get("name") or citation.get("unit") or citation.get("source_unit"),
            citation.get("source_ref") or citation.get("path") or citation.get("file"),
        )


def _workspace_relative_source_token(
    raw: str,
    workspace_path: Path | str | None = None,
) -> str | None:
    value = str(raw or "").strip()
    if not value:
        return None
    if workspace_path is not None:
        candidate = Path(value).expanduser()
        if candidate.is_absolute():
            try:
                root = Path(workspace_path).expanduser().resolve(strict=False)
                rel = candidate.resolve(strict=False).relative_to(root)
                return str(rel).replace("\\", "/")
            except (OSError, ValueError):
                return None
    return _source_ref_token(value)


def _add_source_ref_tokens(tokens: set[str], ref: str, fn_name: str | None = None) -> set[str]:
    added: set[str] = set()
    token = _source_ref_token(ref)
    if not token:
        return added
    base = token.split("/")[-1]
    for file_token in {token, base}:
        tokens.add(file_token)
        added.add(file_token)
        if fn_name:
            fn_token = f"{file_token}::{fn_name}"
            tokens.add(fn_token)
            added.add(fn_token)
    return added


def _is_plausible_fn_name(name: str, has_paren: bool) -> bool:
    """True if ``name`` looks like a real Solidity/Go/Rust function identifier
    rather than an English prose word that happened to follow the literal word
    "function" in a sentence / NatSpec comment.

    Acceptance is deliberately conservative (DROP-on-ambiguity):
      - reject any case-folded prose stopword (``is`` / ``reverts`` /
        ``uncallable`` / ``call`` ...),
      - accept a mixed-case / camelCase / PascalCase / snake_case identifier
        (contains an uppercase letter or an underscore - real fn names almost
        always carry case or an underscore; prose words never do). This holds
        with OR without a trailing paren (``_fillSameChain`` / ``lzReceive``),
      - accept an all-lowercase token ONLY when it is written as a real
        signature / call - i.e. immediately followed by ``(`` (``deposit(`` /
        ``withdraw(``). Prose ("function reverts when ...") has no ``(`` after
        the word, so it is dropped,
      - reject everything else.

    The trailing-paren requirement for all-lowercase names is the load-bearing
    guard: it is what stops prose verbs like ``donates`` / ``reverts`` /
    ``checks`` (which read as plausible 6+-char lowercase words) from being
    credited to whatever file is cited on the same NatSpec line. The bias is to
    miss a bare lowercase fn mentioned WITHOUT a paren before crediting a prose
    verb across many co-cited interface files.
    """
    if not name:
        return False
    if name.lower() in _PROSE_STOPWORDS:
        return False
    # camelCase / PascalCase / snake_case -> almost certainly a real identifier;
    # accept with or without a paren.
    if any(c.isupper() for c in name) or "_" in name:
        return True
    # all-lowercase: accept ONLY if written as a real signature / call (paren).
    return bool(has_paren)


def _harvest_artifact_text_tokens(txt: str, tokens: set[str]) -> None:
    """Harvest coverage tokens from one text artifact (draft / agent_output /
    mega-md) with TIGHT-PROXIMITY SCOPING for bare function names.

    For a single artifact body we add:
      - ``Foo.sol`` for a bare file or file:line citation (file granularity),
      - ``Foo.sol::deposit`` for a function-precise ``Foo.sol::deposit``
        citation (file-precise, exact),
      - and for each BARE function name (``function deposit``), a file-qualified
        token ``<base>::<fn>`` ONLY for source-file basenames that appear on the
        SAME LINE as the ``function <fn>`` mention (tight-proximity scoping).

    The tight-proximity window is the SINGLE LINE: a bare fn is credited to a
    file only when that file's basename is cited on the same line as the
    ``function <fn>`` text. A bare fn whose line has no file citation covers
    nothing (no file context in the tight window = no credit). This closes the
    artifact-wide co-occurrence leak where a bare ``function deposit`` would be
    blanket-credited to EVERY file cited anywhere in the artifact (so an
    artifact citing ``function deposit`` + Vault.sol + Other.sol no longer
    credits Other.sol::deposit unless ``deposit`` appears on a line with
    Other.sol).

    The captured bare-fn name is additionally passed through
    :func:`_is_plausible_fn_name` so English prose words that follow the literal
    word "function" ("function is" / "function that" / "function call" ...) are
    rejected and never manufacture junk ``is`` / ``as`` / ``call`` tokens.

    Existing file-precise and bare-file coverage is preserved exactly (those
    tokens are still harvested artifact-wide; only the bare-fn -> file
    attribution is tightened to same-line proximity). Generic across workspaces
    / languages.
    """
    # File-anchored source refs (file + file-precise ``<base>::<fn>``) are
    # harvested artifact-wide - their attribution is already exact, so an
    # artifact-wide scan is correct and unchanged.
    for m in _DRAFT_SOURCE_REF_RE.finditer(txt):
        _add_source_ref_tokens(tokens, m.group(1), m.group(2))
    # Bare ``function <fn>`` references are scoped by TIGHT (same-line)
    # proximity to a file citation. Process line by line: for each line, collect
    # the file basenames cited on that line and the plausible bare-fn names on
    # that line, then credit ``<base>::<fn>`` only for that line's files.
    for line in txt.splitlines():
        bare_fns: set[str] = set()
        for m in _DRAFT_BARE_FN_RE.finditer(line):
            name = m.group(1)
            has_paren = m.group(2) is not None
            if _is_plausible_fn_name(name, has_paren):
                bare_fns.add(name)
        if not bare_fns:
            continue
        line_files: set[str] = set()
        for m in _DRAFT_SOURCE_REF_RE.finditer(line):
            line_files.update(_add_source_ref_tokens(tokens, m.group(1)))
        # No file on this line -> the bare fn has no tight-window file; it covers
        # nothing. With files present, credit each bare fn to each same-line file
        # (typically exactly one file -> one ``<base>::<fn>`` token).
        for fn_name in bare_fns:
            for base in line_files:
                tokens.add(f"{base}::{fn_name}")


def _is_finding_draft(p: Path) -> bool:
    """A finding-draft .md is any .md whose stem is NOT a bookkeeping tracker.
    Per-finding-folder layout (R41) and legacy flat layout both supported."""
    if p.suffix.lower() != ".md":
        return False
    stem = p.stem.lower()
    # strip backup-ish suffixes the bookkeeping files carry (SUBMISSIONS.bak ...)
    return stem not in _SUBMISSION_BOOKKEEPING_STEMS


def _harvest_submission_draft_tokens(ws: Path, tokens: set[str]) -> None:
    """Harvest coverage tokens from the SOURCE REFERENCES cited in finding
    drafts under <ws>/submissions/. Walks every status dir (filed, paste_ready,
    staging, staged, packaged, held, superseded, _killed, _oos_rejected, and any
    sibling) recursively, so both the per-finding-folder (R41) layout and the
    legacy flat layout are covered. Bookkeeping files (README / SUBMISSIONS /
    TRACKER / INDEX / HOLD_NOTE) are skipped. Never raises.

    For each draft we add (via :func:`_harvest_artifact_text_tokens`, with
    TIGHT same-line proximity scoping for bare fns):
      - ``Foo.sol`` for a bare file or file:line citation (file granularity), and
      - ``Foo.sol::deposit`` for a function-precise citation, plus
      - for each bare ``function deposit`` citation, a file-qualified
        ``<base>::deposit`` token only for source files cited on the SAME LINE
        as the ``function deposit`` text (a bare fn whose line has no file
        citation covers nothing; prose stopwords after "function" are rejected -
        the over-credit + prose-stopword honesty fix).
    A file-granularity token covers a file's units only when no function-precise
    token exists for that base (the existing ``_unit_is_covered`` precision
    rule), so a report citing one function does not blanket-cover its siblings.
    """
    sub = ws / "submissions"
    if not sub.is_dir():
        return
    for dirpath, dirnames, filenames in os.walk(sub):
        # Skip hidden dirs (e.g. a stray .git) but keep status dirs incl. those
        # with a leading underscore (_killed, _oos_rejected, _lessons-learned).
        dirnames[:] = [d for d in dirnames if not d.startswith(".")]
        for fn in filenames:
            p = Path(dirpath) / fn
            if not _is_finding_draft(p):
                continue
            try:
                txt = p.read_text(encoding="utf-8", errors="replace")
            except OSError:
                continue
            _harvest_artifact_text_tokens(txt, tokens)


def _preflight_pack_target_fields(pack: dict) -> tuple[str, str]:
    target = pack.get("target")
    if not isinstance(target, dict):
        target = {}
    source_ref = pack.get("source_ref")
    if not isinstance(source_ref, str) or not source_ref.strip():
        source_ref = target.get("source_ref")
    fn_name = pack.get("function")
    if not isinstance(fn_name, str) or not fn_name.strip():
        fn_name = target.get("function")
    source_text = source_ref.strip() if isinstance(source_ref, str) else ""
    fn_text = fn_name.strip() if isinstance(fn_name, str) else ""
    return source_text, fn_text


def _harvest_preflight_pack_tokens(
    ws: Path,
    tokens: set[str],
    *,
    denominator: dict | None = None,
    skipped: list[dict] | None = None,
) -> None:
    packs_dir = ws / ".auditooor" / "pre_flight_packs"
    if not packs_dir.is_dir():
        return
    for path in sorted(packs_dir.glob("pre_flight_pack_*.json")):
        try:
            pack = json.loads(path.read_text(encoding="utf-8", errors="replace"))
        except (OSError, ValueError):
            continue
        if not isinstance(pack, dict):
            continue
        source_ref, fn_name = _preflight_pack_target_fields(pack)
        if not source_ref:
            _append_skipped_coverage(
                skipped,
                "pre_flight_pack",
                _artifact_path_label(ws, path),
                None,
                fn_name or None,
                "missing_source_ref",
            )
            continue
        if denominator is not None:
            _add_denominator_validated_tokens(
                tokens,
                denominator,
                source_ref,
                fn_name or None,
                skipped,
                "pre_flight_pack",
                _artifact_path_label(ws, path),
                pack,
            )
        else:
            token = _workspace_relative_source_token(source_ref, ws)
            if token:
                _add_source_ref_tokens(tokens, token, fn_name or None)


# JSON keys whose string values may carry a file path or function reference.
_TOKEN_KEYS = (
    "file", "file_path", "file_path_hint", "path", "source_file", "contract",
    "contract_name", "unit", "target_file", "affected_file", "source_ref",
)
_FN_KEYS = ("function", "function_name", "fn", "method", "affected_function")
_REVIEW_UNIT_LIST_KEYS = ("reviewed_units", "scanned_units", "covered_units")


def _norm_source_json_ref(val: str) -> str | None:
    val = (val or "").strip()
    if not val or val.upper() in ("NA", "N/A", "NULL"):
        return None
    return _source_ref_token(val)


def _harvest_json_tokens(path: Path, tokens: set[str]) -> None:
    """Best-effort harvest of file/function coverage tokens from a JSON file.
    Walks dicts/lists recursively; never raises."""
    try:
        data = json.loads(path.read_text(encoding="utf-8", errors="replace"))
    except (OSError, ValueError):
        return
    _harvest_review_json_tokens(data, tokens)

    def _walk(obj):
        if isinstance(obj, dict):
            base = None
            file_token = None
            for k in _TOKEN_KEYS:
                v = obj.get(k)
                if isinstance(v, str):
                    ref = _norm_source_json_ref(v)
                    if ref:
                        _add_source_ref_tokens(tokens, ref)
                        file_token = ref
                        base = ref.split("/")[-1]
            for k in _FN_KEYS:
                v = obj.get(k)
                if isinstance(v, str) and v.strip():
                    fn = v.strip().split("(")[0].strip()
                    if fn and base:
                        # File-qualified only. The fn is scoped to the file cited
                        # in the SAME dict (co-occurrence). A bare ``<fn>`` with
                        # NO file in the same record covers nothing - no file
                        # context = no credit (the over-credit honesty fix).
                        tokens.add(f"{base}::{fn}")
                        if file_token and file_token != base:
                            tokens.add(f"{file_token}::{fn}")
            for v in obj.values():
                _walk(v)
        elif isinstance(obj, list):
            for v in obj:
                _walk(v)

    _walk(data)


def _harvest_review_json_file_tokens(path: Path, tokens: set[str]) -> None:
    """Harvest only explicit review-evidence tokens from a JSON file."""
    try:
        data = json.loads(path.read_text(encoding="utf-8", errors="replace"))
    except (OSError, ValueError):
        return
    _harvest_review_json_tokens(data, tokens)


def _collect_workspace_mimo_numerator_artifacts(
    ws: Path,
    records: list[dict],
    seen: set[str],
) -> None:
    workspace = ws.name
    derived = AUDITOOOR_ROOT / "audit" / "corpus_tags" / "derived"
    patterns = (
        str(derived / f"mimo_harness_{workspace}*" / "*.json"),
        str(derived / f"mega*{workspace}*" / "*.json"),
    )
    for pattern in patterns:
        for raw in glob.glob(pattern):
            path = Path(raw)
            try:
                rec = json.loads(path.read_text(encoding="utf-8", errors="replace"))
            except (OSError, ValueError):
                continue
            if not _record_matches_workspace_path(rec, ws, require_binding=True):
                continue
            valid = _mega_record_is_real_hunt(rec) is not None
            if not valid and rec.get("status") == "ok":
                result = rec.get("result", "")
                if isinstance(result, str) and result.strip():
                    body = result.strip().strip("`").lstrip("json").strip()
                    try:
                        parsed = json.loads(body)
                    except json.JSONDecodeError:
                        parsed = None
                    if isinstance(parsed, dict) and _record_matches_workspace_path(parsed, ws):
                        hint = (parsed.get("file_path_hint") or "").strip()
                        valid = bool(_workspace_relative_source_token(hint, ws))
            if valid:
                _append_numerator_artifact_record(records, seen, ws, path)


def collect_coverage_numerator_artifact_records(ws: Path) -> list[dict]:
    """Return content fingerprints for every artifact that can feed numerator tokens."""
    records: list[dict] = []
    seen: set[str] = set()

    _collect_workspace_mimo_numerator_artifacts(ws, records, seen)

    a = ws / ".auditooor"
    for rel in (
        ".auditooor/exploit_queue.json",
        ".auditooor/exploit_queue.source_mined.json",
        ".auditooor/engage_report.json",
        ".auditooor/coverage_tokens.json",
        ".auditooor/mimo_coverage.json",
    ):
        _append_numerator_artifact_record(records, seen, ws, ws / rel)

    for sidecars in (ws / "hunt_findings_sidecars", ws / ".auditooor" / "hunt_findings_sidecars"):
        if not sidecars.is_dir():
            continue
        for path in sorted(sidecars.glob("*.json")):
            _append_numerator_artifact_record(records, seen, ws, path)

    for source_artifacts in (ws / "source_artifacts", ws / ".auditooor" / "source_artifacts"):
        if not source_artifacts.is_dir():
            continue
        for path in sorted(source_artifacts.rglob("*.json")):
            _append_numerator_artifact_record(records, seen, ws, path)

    packs_dir = ws / ".auditooor" / "pre_flight_packs"
    if packs_dir.is_dir():
        _append_numerator_artifact_record(records, seen, ws, packs_dir / "manifest.json")
        for path in sorted(packs_dir.glob("pre_flight_pack_*.json")):
            _append_numerator_artifact_record(records, seen, ws, path)

    submissions = ws / "submissions"
    if submissions.is_dir():
        for dirpath, dirnames, filenames in os.walk(submissions):
            dirnames[:] = [d for d in dirnames if not d.startswith(".")]
            for fn in filenames:
                path = Path(dirpath) / fn
                if _is_finding_draft(path):
                    _append_numerator_artifact_record(records, seen, ws, path)

    for dname in _AGENT_ARTIFACT_DIRS:
        d = ws / dname
        if not d.is_dir():
            continue
        for dirpath, dirnames, filenames in os.walk(d):
            dirnames[:] = [dd for dd in dirnames if not dd.startswith(".")]
            for fn in filenames:
                ext = os.path.splitext(fn)[1].lower()
                if ext not in (".md", ".json"):
                    continue
                stem = os.path.splitext(fn)[0].lower()
                if stem in _ARTIFACT_BOOKKEEPING_STEMS:
                    continue
                _append_numerator_artifact_record(records, seen, ws, Path(dirpath) / fn)

    return sorted(records, key=lambda row: row["path"])


def _bases_with_fn_precise_tokens(tokens: set[str]) -> set[str]:
    """Return the set of file basenames that have at least one function-precise
    ``<base>::<fn>`` coverage token. For such a base, a BARE file token must NOT
    blanket-cover the file's other functions - otherwise naming one function in
    a candidate would silently mark every sibling function covered, papering
    over the genuinely-UNCOVERED functions in the same file."""
    out: set[str] = set()
    for t in tokens:
        if "::" in t:
            out.add(t.split("::", 1)[0])
    return out


def _unit_is_covered(unit: str, tokens: set[str],
                     fn_precise_bases: set[str] | None = None,
                     unique_file_keys: dict[str, str] | None = None) -> bool:
    """A unit is COVERED iff a coverage token matches it precisely.

    - file-granularity unit (no ``::``): covered iff its basename is a token.
    - function-granularity unit (``<base>::<fn>``): covered iff the precise
      ``<base>::<fn>`` token exists. A bare file or file-line token does not
      blanket-cover sibling functions because that can make a full function
      denominator look green after only one file-level citation. A global bare
      function-name token is never sufficient because it can be manufactured by
      malformed JSON fields such as ``{"path": "deposit"}`` and would credit
      every same-named function across the workspace.
    """
    if unit in tokens:
        return True
    file_key = _unit_file_key(unit)
    basename = _unit_basename(unit)
    unique_file_keys = unique_file_keys or {}
    if "::" in unit:
        _base, _, fn = unit.partition("::")
        if unique_file_keys.get(basename) == file_key:
            if f"{basename}::{fn}" in tokens:
                return True
    elif file_key in tokens:
        return True
    elif unique_file_keys.get(basename) == file_key and basename in tokens:
        return True
    return False


def build_source_freshness(
    ws: Path,
    scope: dict | None = None,
    units: list[str] | None = None,
    denominator_honesty: dict | None = None,
) -> dict:
    """Build the source-denominator freshness fingerprint.

    The fingerprint covers only denominator inputs: scope mode, matched scope
    globs, source file content, and enumerated source units. It excludes coverage
    tokens and all numerator artifacts, so L37 can reject stale source maps
    without false-failing on non-source hunt artifact drift.
    """
    if scope is None:
        scope = resolve_scope(ws)
    if units is None:
        units, enum_detail = enumerate_units(ws, scope=scope)
        # NARROWING-CONSISTENCY (coverage-map L37 recompute, Lane
        # CAP-HUNT-GATE-NARROWING-CONSISTENT parity): build_coverage_report
        # applies the Go/Cosmos entry-point narrowing to its units BEFORE calling
        # this fn (units=<narrowed>), so its stored source_freshness denominator is
        # narrowed (e.g. SEI 2819). The L37 coverage-map signal recomputes via
        # build_source_freshness(ws) with units=None; without the SAME narrowing it
        # enumerates the every-exported surface (SEI 22055) and the stored vs
        # recomputed fingerprints can NEVER match on a narrowed Cosmos-Go-L1, so
        # coverage-map FAILs forever. Apply the identical narrowing here. Fail-open:
        # apply_go_cosmos_coverage_scope_narrowing returns units unchanged when the
        # go_entrypoint_surface import/kill-switch is off. Passed-in units are
        # already narrowed by the caller and must NOT be re-narrowed.
        units, _cov_map_narrow_detail = apply_go_cosmos_coverage_scope_narrowing(
            ws, units
        )
    else:
        _unused_units, enum_detail = enumerate_units(ws, scope=scope)
    source_files = _source_file_records(ws, scope)
    scope_payload = {
        "scope_mode": scope.get("scope_mode", "unscoped-fallback"),
        "scope_globs": sorted(scope.get("scope_globs", []) or []),
        "scope_exclude_globs": sorted(scope.get("scope_exclude_globs", []) or []),
    }
    source_units = sorted(units)
    if denominator_honesty is None:
        denominator_honesty = build_function_denominator_honesty(enum_detail)
    out = {
        "schema": SOURCE_FRESHNESS_SCHEMA,
        "algorithm": SOURCE_FRESHNESS_ALGORITHM,
        "coverage_basis": "source-unit",
        "scope_mode": scope_payload["scope_mode"],
        "scope_globs_sha256": _canonical_sha256(scope_payload),
        "rust_source_graph_sha256": enum_detail.get("rust_source_graph_sha256"),
        "source_files_count": len(source_files),
        "source_files_sha256": _canonical_sha256(source_files),
        "source_units_count": len(source_units),
        "source_units_sha256": _canonical_sha256(source_units),
        "function_denominator_status": denominator_honesty.get("function_denominator_status"),
        "function_level_extensions": denominator_honesty.get("function_level_extensions"),
        "partial_function_extensions": denominator_honesty.get("partial_function_extensions"),
        "source_unit_extensions": denominator_honesty.get("source_unit_extensions"),
        "partial_function_reasons": denominator_honesty.get("partial_function_reasons"),
        "full_in_scope_function_denominator": denominator_honesty.get("full_in_scope_function_denominator"),
    }
    denominator_payload = {
        "schema": out["schema"],
        "algorithm": out["algorithm"],
        "coverage_basis": out["coverage_basis"],
        "scope_mode": out["scope_mode"],
        "scope_globs_sha256": out["scope_globs_sha256"],
        "rust_source_graph_sha256": out["rust_source_graph_sha256"],
        "source_files_count": out["source_files_count"],
        "source_files_sha256": out["source_files_sha256"],
        "source_units_count": out["source_units_count"],
        "source_units_sha256": out["source_units_sha256"],
        "function_denominator_status": out["function_denominator_status"],
        "function_level_extensions": out["function_level_extensions"],
        "partial_function_extensions": out["partial_function_extensions"],
        "source_unit_extensions": out["source_unit_extensions"],
        "partial_function_reasons": out["partial_function_reasons"],
        "full_in_scope_function_denominator": out["full_in_scope_function_denominator"],
    }
    out["denominator_sha256"] = _canonical_sha256(denominator_payload)
    return out


def build_coverage_numerator_freshness_from_parts(
    tokens: set[str],
    covered_units: list[str],
    uncovered_units: list[str],
    numerator_artifacts: list[dict] | None = None,
) -> dict:
    """Build a semantic fingerprint for coverage numerator inputs."""
    sorted_tokens = sorted(str(token) for token in tokens)
    sorted_covered = sorted(str(unit) for unit in covered_units)
    sorted_uncovered = sorted(str(unit) for unit in uncovered_units)
    sorted_artifacts = sorted(
        (
            {
                "path": str(record.get("path") or ""),
                "size": int(record.get("size") or 0),
                "sha256": str(record.get("sha256") or ""),
            }
            for record in (numerator_artifacts or [])
        ),
        key=lambda row: row["path"],
    )
    out = {
        "schema": NUMERATOR_FRESHNESS_SCHEMA,
        "algorithm": SOURCE_FRESHNESS_ALGORITHM,
        "coverage_basis": "source-unit",
        "coverage_tokens_count": len(sorted_tokens),
        "coverage_tokens_sha256": _canonical_sha256(sorted_tokens),
        "covered_units_count": len(sorted_covered),
        "covered_units_sha256": _canonical_sha256(sorted_covered),
        "uncovered_units_count": len(sorted_uncovered),
        "uncovered_units_sha256": _canonical_sha256(sorted_uncovered),
        "numerator_artifacts_count": len(sorted_artifacts),
        "numerator_artifacts_sha256": _canonical_sha256(sorted_artifacts),
        "total_units_count": len(sorted_covered) + len(sorted_uncovered),
    }
    out["numerator_sha256"] = _canonical_sha256(out)
    return out


# --------------------------------------------------------------------------
# Go/Cosmos coverage_report SCOPE NARROWING (Lane CAP-HUNT-COVERAGE-SCOPE-NARROW)
# --------------------------------------------------------------------------
# The narrowing predicate + crown-jewel/documented-OOS/fork-delta logic lives in
# ``tools/go_entrypoint_surface.py`` (single source of truth, Lane
# CAP-HUNT-GATE-NARROWING-CONSISTENT) so ``tools/hunt-coverage-gate.py``'s own
# live in-scope enumeration can apply the IDENTICAL narrowing before comparing
# against this report's (already-narrowed) total, and the two call sites can
# never drift apart. This wrapper only supplies the two heatmap-local pieces
# (the ``unit -> file_key`` splitter + the per-extension fn-decl regex table)
# that ``go_entrypoint_surface`` cannot define without duplicating them.
def apply_go_cosmos_coverage_scope_narrowing(
    ws: Path, units: list[str]
) -> tuple[list[str], dict]:
    """Thin wrapper over
    ``go_entrypoint_surface.apply_go_cosmos_coverage_scope_narrowing`` binding
    this module's ``_unit_file_key`` + ``_GENERIC_FN_RE_BY_EXT``. Fail-open
    (returns ``units`` unchanged) when the ``go_entrypoint_surface`` import is
    unavailable, matching this module's existing fail-open convention for that
    import (see the top-of-file ``_go_entry`` import try/except)."""
    if _go_entry is None:
        return list(units), {
            "applied": False,
            "reason": "go_entrypoint_surface-unavailable",
            "go_units_in": 0, "go_units_kept": 0, "excluded_total": 0,
            "excluded_by_reason": {}, "crown_jewel_protected": 0,
        }
    return _go_entry.apply_go_cosmos_coverage_scope_narrowing(
        ws, units, _unit_file_key, _GENERIC_FN_RE_BY_EXT
    )


def _resolve_go_unit_file_paths(ws: Path, go_units: list[str]) -> dict[str, str]:
    """Back-compat shim (existing tests reach into this private helper
    directly): delegates to ``go_entrypoint_surface``'s extracted
    implementation binding this module's ``_unit_file_key`` splitter."""
    if _go_entry is None:
        return {}
    return _go_entry._resolve_go_unit_file_paths(ws, go_units, _unit_file_key)


# ==========================================================================
# COVERAGE-COMPLETENESS BACKSTOP (defect 2, Obyte 2026-07-09 false-green fix).
# A per-language completeness guard against the SSOT in-scope manifest. When a
# whole in-scope language is present in inscope_units.jsonl (>0 units) but the
# coverage_report classified ZERO units of it (the classifier was blind to the
# extension), that is the false-green: material scope survived but 0 was
# counted, and the map silently warn-passed. This detects it PRECISELY (per
# language, so the file-vs-function granularity gap never false-fires) and
# FAILS LOUD - advisory WARN by default, BLOCK under the named strict env.
# Generic: language-agnostic, no target literal; fail-open when the manifest is
# absent/unreadable (no manifest => nothing to backstop against).
# ==========================================================================
def _completeness_strict_enabled() -> bool:
    """True iff AUDITOOOR_COVERAGE_COMPLETENESS_STRICT is set truthy."""
    return os.environ.get(_ENV_COVERAGE_COMPLETENESS_STRICT, "").strip().lower() \
        not in ("", "0", "false", "no", "off")


def _load_inscope_manifest_lang_counts(ws: Path) -> dict[str, int]:
    """Return ``{language -> in-scope unit count}`` from
    ``<ws>/.auditooor/inscope_units.jsonl`` - the SSOT in-scope unit set. The
    ``lang`` field is used when present; otherwise the language is derived from
    the row's file extension via the canonical registry (``_registry_lang_of``).
    Returns ``{}`` when the manifest is absent or unreadable (fail-open: no
    backstop). Generic - no target/workspace literal."""
    counts: collections.Counter = collections.Counter()
    mpath = ws / ".auditooor" / "inscope_units.jsonl"
    if not mpath.is_file():
        return {}
    try:
        text = mpath.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return {}
    for line in text.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            row = json.loads(line)
        except ValueError:
            continue
        if not isinstance(row, dict):
            continue
        lang = str(row.get("lang") or "").strip().lower()
        if not lang:
            ref = str(row.get("file") or row.get("file_line") or "").split(":", 1)[0]
            lang = (_registry_lang_of(ref) or "").strip().lower()
        if lang:
            counts[lang] += 1
    return dict(counts)


def _coverage_report_lang_counts(report: dict) -> dict[str, int]:
    """Map the coverage report's per-EXTENSION classified file counts
    (``enumeration.languages``, keyed like ``".sol"``) to per-LANGUAGE counts
    (keyed like ``"solidity"``) via the canonical registry, so they compare
    apples-to-apples with the manifest's ``lang`` field."""
    enum = report.get("enumeration") if isinstance(report, dict) else None
    langs = enum.get("languages") if isinstance(enum, dict) else None
    out: collections.Counter = collections.Counter()
    if isinstance(langs, dict):
        for ext, n in langs.items():
            lang = (_registry_lang_of(str(ext)) or str(ext).lstrip(".")).strip().lower()
            try:
                out[lang] += int(n or 0)
            except (TypeError, ValueError):
                continue
    return dict(out)


def check_coverage_completeness_vs_manifest(ws: Path, report: dict) -> dict:
    """Backstop the coverage report against the in-scope manifest, per language.

    Returns a self-describing dict. ``dropped_languages`` maps each language
    that has >0 units in ``inscope_units.jsonl`` but ZERO classified units in
    the coverage report to its manifest unit count - that is a whole in-scope
    language silently dropped from the denominator (the false-green). ``status``
    is ``"ok"`` (nothing dropped), ``"warn"`` (dropped, advisory), or
    ``"block"`` (dropped AND the strict env is set). Fail-open: an empty/absent
    manifest yields ``checked=False`` and ``status="ok"``.
    """
    manifest_counts = _load_inscope_manifest_lang_counts(ws)
    coverage_counts = _coverage_report_lang_counts(report)
    dropped = {
        lang: n
        for lang, n in manifest_counts.items()
        if n > 0 and coverage_counts.get(lang, 0) == 0
    }
    strict = _completeness_strict_enabled()
    if not manifest_counts:
        status = "ok"
    elif dropped:
        status = "block" if strict else "warn"
    else:
        status = "ok"
    return {
        "checked": bool(manifest_counts),
        "manifest_lang_counts": dict(sorted(manifest_counts.items())),
        "coverage_lang_counts": dict(sorted(coverage_counts.items())),
        "dropped_languages": dict(sorted(dropped.items())),
        "manifest_total_units": sum(manifest_counts.values()),
        "coverage_total_units": int(report.get("total_units") or 0)
        if isinstance(report, dict) else 0,
        "material_undercount": bool(dropped),
        "strict_env": _ENV_COVERAGE_COMPLETENESS_STRICT,
        "strict": strict,
        "status": status,
    }


def _emit_completeness_backstop_warning(ws: Path, backstop: dict) -> None:
    """Emit a LOUD stderr WARN when the backstop found a dropped language.
    Called by the writing/CLI path (never during a pure build) so importing
    gates that call ``build_coverage_report`` do not get stderr spam."""
    if not isinstance(backstop, dict) or not backstop.get("material_undercount"):
        return
    dropped = backstop.get("dropped_languages") or {}
    detail = ", ".join(f"{k}={v}" for k, v in dropped.items())
    verb = "BLOCK" if backstop.get("status") == "block" else "WARN"
    sys.stderr.write(
        f"[coverage-completeness] {verb}: {ws} - a whole in-scope language was "
        f"DROPPED from the coverage denominator: {detail} unit(s) in "
        f"inscope_units.jsonl but 0 classified in coverage_report.json. This is a "
        f"FALSE-GREEN (material scope survived but 0 counted). "
        f"set {_ENV_COVERAGE_COMPLETENESS_STRICT}=1 to fail the gate closed.\n"
    )


_VMF_MOD_HM: object | None = None
_VMF_MOD_HM_TRIED = False


def _load_value_moving_mod_hm():
    """Load tools/value-moving-functions.py (hyphenated) for the JS/Oscript
    value-moving classifier. Cached; None on any error (fail-open)."""
    global _VMF_MOD_HM, _VMF_MOD_HM_TRIED
    if _VMF_MOD_HM_TRIED:
        return _VMF_MOD_HM
    _VMF_MOD_HM_TRIED = True
    try:
        import importlib.util
        tool = Path(__file__).with_name("value-moving-functions.py")
        if not tool.is_file():
            return None
        spec = importlib.util.spec_from_file_location("_vmf_for_heatmap", tool)
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
        _VMF_MOD_HM = mod
    except Exception:  # noqa: BLE001 - advisory helper must never break the report
        _VMF_MOD_HM = None
    return _VMF_MOD_HM


def build_nonvaluemoving_js_advisory(ws: Path, units: list[str]) -> dict:
    """ADVISORY (never changes total_units here): list the JS denominator units the
    JS/Oscript value-moving classifier (value-moving-functions.py, the single
    source of truth also consumed by hunt-coverage-gate.py's denominator
    exemption) classifies as genuinely non-value-moving (config / test-CLI /
    pure-util / pure-infra). This surfaces, in the report itself, which file-level
    JS units the gate will shed from the coverage FRACTION denominator so a low
    coverage number is legible: it is measured over VALUE-MOVING surface, not
    inflated by eslint configs / deploy scripts / telemetry plumbing. Oscript and
    every non-JS language are never listed (fail-open value-moving)."""
    mod = _load_value_moving_mod_hm()
    out = {"enabled": mod is not None, "units": [], "count": 0, "reasons": {}}
    if mod is None or not hasattr(mod, "js_oscript_unit_value_moving_verdict"):
        return out
    _skip = ("/node_modules/", "/vendor/", "/build/", "/target/", "/.git/",
             "/tests/", "/test/", "/mock/", "/mocks/")

    def _resolve_text(file_part: str) -> str | None:
        # Direct relpath first; else rglob a bare basename (excluding vendored/
        # test trees) so the source value-signal veto runs on file-level units
        # that are keyed by basename - identical resolution posture to the gate
        # (_resolve_unit_source), so the advisory and the gate agree.
        cand = ws / file_part
        if not cand.is_file() and "/" not in file_part and "\\" not in file_part:
            for m in ws.rglob(file_part):
                sp = str(m).replace("\\", "/")
                if m.is_file() and not any(s in sp for s in _skip):
                    cand = m
                    break
        try:
            if cand.is_file():
                return cand.read_text(encoding="utf-8", errors="replace")
        except OSError:
            return None
        return None

    exempt: list[str] = []
    reasons: dict[str, str] = {}
    for u in units:
        file_part = u.split("::", 1)[0]
        if not file_part.lower().endswith(".js"):
            continue
        text = _resolve_text(file_part)
        try:
            verdict, reason = mod.js_oscript_unit_value_moving_verdict(file_part, text)
        except Exception:  # noqa: BLE001
            continue
        if verdict == "non-value-moving":
            exempt.append(u)
            reasons[u] = reason
    out["units"] = sorted(exempt)
    out["count"] = len(exempt)
    out["reasons"] = reasons
    return out


def build_coverage_report(ws: Path, list_cap: int = DEFAULT_UNCOVERED_LIST_CAP) -> dict:
    """Build the schema-versioned SWEPT-SURFACE coverage report for a workspace.

    NEVER silently truncates the true uncovered total: ``uncovered`` is always
    the real count; ``uncovered_units`` may be capped but
    ``uncovered_units_truncated`` and ``uncovered_units_omitted`` disclose it.
    """
    scope = resolve_scope(ws)
    units, enum_detail = enumerate_units(ws, scope=scope)
    units, go_scope_narrow_detail = apply_go_cosmos_coverage_scope_narrowing(
        ws, list(units)
    )
    enum_detail = dict(enum_detail)
    enum_detail["go_cosmos_scope_narrowing"] = go_scope_narrow_detail
    denominator_honesty = build_function_denominator_honesty(enum_detail)
    source_freshness = build_source_freshness(
        ws,
        scope=scope,
        units=units,
        denominator_honesty=denominator_honesty,
    )
    tokens, skipped_coverage = collect_coverage_tokens_with_skips(
        ws,
        scope=scope,
        units=units,
        enum_detail=enum_detail,
    )
    fn_precise = _bases_with_fn_precise_tokens(tokens)
    unique_file_keys = _unique_file_keys_by_basename(
        units,
        set(enum_detail.get("ambiguous_source_basenames") or []),
    )

    covered_units = [
        u for u in units if _unit_is_covered(u, tokens, fn_precise, unique_file_keys)
    ]
    uncovered_units = [
        u for u in units if not _unit_is_covered(u, tokens, fn_precise, unique_file_keys)
    ]
    numerator_artifacts = collect_coverage_numerator_artifact_records(ws)
    numerator_freshness = build_coverage_numerator_freshness_from_parts(
        tokens,
        covered_units,
        uncovered_units,
        numerator_artifacts,
    )

    total = len(units)
    n_cov = len(covered_units)
    n_unc = len(uncovered_units)
    frac = (n_cov / total) if total else 1.0  # empty surface => trivially 1.0

    # (defect 2) Per-language completeness backstop against inscope_units.jsonl.
    # Computed on a partial report shape carrying just the enumeration languages
    # so a whole dropped language is detected here (not silently warn-passed).
    _completeness_backstop = check_coverage_completeness_vs_manifest(
        ws, {"enumeration": enum_detail, "total_units": total}
    )

    capped = uncovered_units[:list_cap] if list_cap >= 0 else uncovered_units
    omitted = max(0, n_unc - len(capped))
    skipped_cap = DEFAULT_SKIPPED_COVERAGE_LIST_CAP
    skipped_capped = skipped_coverage[:skipped_cap]
    skipped_omitted = max(0, len(skipped_coverage) - len(skipped_capped))
    denominator_disclosure = build_denominator_disclosure(
        units,
        covered_units,
        uncovered_units,
        source_freshness,
        denominator_honesty,
        list_cap,
    )

    return {
        "schema": COVERAGE_SCHEMA,
        "generated_at": iso_now(),
        "workspace": str(ws),
        "workspace_name": ws.name,
        # (BUG 2) self-describing scope: a low coverage number can never again be
        # mistaken for in-scope coverage when it is actually unscoped.
        "scope_mode": scope["scope_mode"],
        "scope_globs": scope["scope_globs"],
        "scope_exclude_globs": scope.get("scope_exclude_globs", []),
        "coverage_basis": "source-unit",
        "source_freshness": source_freshness,
        "numerator_freshness": numerator_freshness,
        "denominator_disclosure": denominator_disclosure,
        "function_denominator_status": denominator_honesty["function_denominator_status"],
        "function_level_extensions": denominator_honesty["function_level_extensions"],
        "partial_function_extensions": denominator_honesty["partial_function_extensions"],
        "source_unit_extensions": denominator_honesty["source_unit_extensions"],
        "partial_function_reasons": denominator_honesty["partial_function_reasons"],
        "full_in_scope_function_denominator": denominator_honesty["full_in_scope_function_denominator"],
        "denominator_units": list(units),
        "total_units": total,
        "covered": n_cov,
        "uncovered": n_unc,  # TRUE count - never truncated
        "coverage_fraction": round(frac, 6),
        "coverage_tokens": len(tokens),
        "skipped_coverage": skipped_capped,
        "skipped_coverage_count": len(skipped_coverage),
        "skipped_coverage_reasons": dict(sorted(collections.Counter(
            str(row.get("reason") or "unknown") for row in skipped_coverage
        ).items())),
        "skipped_coverage_truncated": skipped_omitted > 0,
        "skipped_coverage_omitted": skipped_omitted,
        "uncovered_units": capped,
        "uncovered_units_truncated": omitted > 0,
        "uncovered_units_omitted": omitted,  # how many names are NOT inlined
        "uncovered_units_listed": len(capped),
        "enumeration": enum_detail,
        "coverage_completeness_backstop": _completeness_backstop,
        "nonvaluemoving_js_advisory": build_nonvaluemoving_js_advisory(ws, list(units)),
    }


def write_coverage_report(ws: Path, list_cap: int = DEFAULT_UNCOVERED_LIST_CAP) -> tuple[Path, dict]:
    """Build + write the coverage report to <ws>/.auditooor/coverage_report.json.
    Returns (output_path, report_dict)."""
    report = build_coverage_report(ws, list_cap=list_cap)
    out = ws / ".auditooor" / "coverage_report.json"
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(report, indent=2), encoding="utf-8")
    # (defect 2) FAIL LOUD on a silently-dropped in-scope language.
    _emit_completeness_backstop_warning(
        ws, report.get("coverage_completeness_backstop") or {}
    )
    return out, report


# ==========================================================================
# GENERIC IN-SCOPE MANIFEST (mode 3) - the inscope_units.jsonl emitter.
#
# Closes the standing gap: no tool wrote <ws>/.auditooor/inscope_units.jsonl,
# yet guard-negative-space-analyzer (the audit-depth precondition) consumes it.
# This mode REUSES the in-scope enumeration machinery (scope resolution, prune
# rules, function/file granularity, rust-source-graph entrypoints) to emit one
# JSONL row per in-scope unit, matching the reference manifest shape EXACTLY:
#
#     {"file": <ws-relative path>,
#      "function": <function name or "" for file-granularity units>,
#      "file_line": "<file>:<line>",
#      "lang": <"solidity"|"rust"|"go"|"move"|"cairo"|"vyper"|"noir">,
#      "prior_covered": <bool, true iff a coverage token already references it>}
#
# Generic: no target/workspace literal; driven by file extension + scope only.
# ==========================================================================

# Extension -> language NAME used in the manifest `lang` field (full names, not
# the bare extension), matching the existing in-scope manifest vocabulary.
# Keep this compatibility name for consumers in this module, but derive it from
# the canonical source-language registry.  The manifest must never grow a
# separate extension-to-language vocabulary from the rest of the audit tools.
_EXT_LANG_NAME = {
    ext: _registry_lang_of(ext)
    for ext in _REGISTRY_SOURCE_EXTS
    if _registry_lang_of(ext) is not None
}


def _manifest_perlang_gate() -> bool:
    """AUDITOOOR_INSCOPE_MANIFEST_LEGACY_FILEGRAN truthiness gate (opt-OUT, rare
    escape hatch). Default (unset) = the FIX below is active: the in-scope
    manifest decomposes .rs/.go/.move/.cairo/.vy into real per-function rows,
    matching what :func:`enumerate_units` (the coverage DENOMINATOR) has done
    since bf67eeb0c0 (2026-06-08, ungated, shipped-for-all-languages). Setting
    this var to a truthy value freezes a workspace on the PRE-fix manifest
    shape (one function='' row per non-Solidity/Noir file) - only for an
    operator who needs to pin a prior-certified matrix bit-for-bit; never the
    default posture."""
    return os.environ.get("AUDITOOOR_INSCOPE_MANIFEST_LEGACY_FILEGRAN", "") not in (
        "", "0", "false", "no")


def _enumerate_functions_with_lines(
    path: Path, ext: str, manifest_index: dict[str, list[str]] | None = None,
    rel: str | None = None,
) -> list[tuple[str, int]]:
    """Return ``(function_name, line_number)`` pairs for a function-granularity
    source file. Reuses the SAME function-definition regexes as
    :func:`_enumerate_functions` (``_SOL_FN_RE`` / ``_SOL_SPECIAL_RE`` /
    ``_NOIR_FN_RE`` / ``_GENERIC_FN_RE_BY_EXT``) so the manifest function set is
    identical to the coverage denominator's; this variant additionally captures
    the 1-based line number of each match. De-duplicated on ``(name, line)``,
    deterministically ordered.

    GENERIC Go/Rust/Move/Cairo/Vyper decomposition (fixes the manifest/
    denominator divergence: enumerate_units function-granularizes these exts
    via ``_GENERIC_FN_RE_BY_EXT`` [bf67eeb0c0], but this sibling enumerator
    never got the same arm, so EVERY non-Solidity/Noir file collapsed to one
    ``function=''`` placeholder row here regardless of how many real functions
    it defines - NUVA 2026-07-03: 241 Go value-mover cells stuck value_moving
    with no real function to hang an invariant on). When ``manifest_index``
    (the per-function-invariant-gen authoritative function list) covers
    ``rel``, its names are preferred (parity with :func:`_enumerate_functions`);
    each name is then line-anchored to its first regex match in-file (falls
    back to line 0 - still well-formed - when the manifest name has no local
    regex match, e.g. a method promoted via an embedded/trait receiver the
    regex table does not special-case). Otherwise the in-file
    ``_GENERIC_FN_RE_BY_EXT`` regex parse is used directly, exactly as
    :func:`_enumerate_functions`'s fallback path does. Opt-out via
    :func:`_manifest_perlang_gate` freezes the legacy (pre-fix) shape."""
    try:
        txt = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return []
    out: list[tuple[str, int]] = []
    seen: set[tuple[str, int]] = set()

    def _add(name: str, pos: int) -> None:
        line = txt.count("\n", 0, pos) + 1
        key = (name, line)
        if key not in seen:
            seen.add(key)
            out.append(key)

    if ext == ".sol":
        for m in _SOL_FN_RE.finditer(txt):
            _add(m.group(1), m.start())
        for m in _SOL_SPECIAL_RE.finditer(txt):
            _add(m.group(1), m.start())
    elif ext == ".nr":
        for m in _NOIR_FN_RE.finditer(txt):
            _add(m.group(1), m.start())
    elif not _manifest_perlang_gate():
        manifest_names: list[str] | None = None
        if manifest_index and rel is not None and rel in manifest_index:
            manifest_names = manifest_index.get(rel) or None
        gen_re = _GENERIC_FN_RE_BY_EXT.get(ext)
        if manifest_names:
            # Authoritative function list: line-anchor each name to its first
            # in-file regex match when the local parser also finds it (keeps
            # file_line accurate); a manifest-only name (regex missed it) still
            # gets a well-formed row at line 0 rather than being dropped.
            by_name_pos: dict[str, int] = {}
            if gen_re is not None:
                for m in gen_re.finditer(txt):
                    nm = m.group(1)
                    if nm not in by_name_pos:
                        by_name_pos[nm] = m.start()
            for nm in manifest_names:
                if nm in by_name_pos:
                    _add(nm, by_name_pos[nm])
                else:
                    key = (nm, 0)
                    if key not in seen:
                        seen.add(key)
                        out.append(key)
        elif gen_re is not None:
            for m in gen_re.finditer(txt):
                _add(m.group(1), m.start())
    return sorted(out, key=lambda nl: (nl[1], nl[0]))


def _rust_graph_rows_by_file(ws: Path) -> dict[str, list[tuple[str, int]]]:
    """Map ws-relative rust file -> ``[(fn, line), ...]`` from the rust source
    graph, when present and schema-matched. Lines come from the graph entry's
    ``line`` field when available, else 0 (file-line still well-formed). Mirrors
    the scope-agnostic raw extraction in :func:`_rust_source_graph_entrypoint_units`;
    scope filtering is applied by the caller during the walk."""
    path = ws / ".auditooor" / "rust_source_graph.json"
    try:
        graph = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}
    if not isinstance(graph, dict):
        return {}
    meta = graph.get("_meta")
    if not isinstance(meta, dict):
        return {}
    if (meta.get("schema_version") or meta.get("schema")) != RUST_SOURCE_GRAPH_SCHEMA:
        return {}
    by_file: dict[str, list[tuple[str, int]]] = collections.defaultdict(list)
    seen: dict[str, set[tuple[str, int]]] = collections.defaultdict(set)
    for crate, payload in graph.items():
        if crate == "_meta" or not isinstance(payload, dict):
            continue
        for entry in payload.get("entrypoints") or []:
            if not isinstance(entry, dict):
                continue
            file_rel = entry.get("file")
            fn = entry.get("fn")
            if not isinstance(file_rel, str) or not file_rel.strip():
                continue
            if not isinstance(fn, str) or not fn.strip():
                continue
            rel = file_rel.strip().replace("\\", "/")
            line = entry.get("line")
            try:
                line_i = int(line)
            except (TypeError, ValueError):
                line_i = 0
            key = (fn.strip(), line_i)
            if key not in seen[rel]:
                seen[rel].add(key)
                by_file[rel].append(key)
    return dict(by_file)


def _load_fork_modified_lib():
    """Lazy-load tools/lib/fork_modified (compute_modified_files). The lib is
    MULTI-LANGUAGE (Go/Sol/Rust/Move/Cairo/Vyper/...) and already landed; we do
    NOT reimplement it. Returns the module or None if unavailable (degrade =
    keep-all)."""
    try:
        import sys as _sys
        _lib = str(Path(__file__).resolve().parent / "lib")
        if _lib not in _sys.path:
            _sys.path.insert(0, _lib)
        import fork_modified  # type: ignore
        return fork_modified
    except Exception:
        return None


def _load_fork_bases(ws: Path) -> list[dict] | None:
    """Read ``<ws>/.auditooor/fork_bases.json`` (the resolve-fork-bases sidecar).

    Returns the list of ``{local_name, upstream_repo, base_ref}`` rows, or None
    when the sidecar is absent / unreadable / malformed. A NON-fork workspace
    (no sidecar) returns None -> the emitter prunes NOTHING (exact back-compat).
    """
    fb = ws / ".auditooor" / "fork_bases.json"
    if not fb.is_file():
        return None
    try:
        data = json.loads(fb.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None
    if not isinstance(data, list):
        return None
    out: list[dict] = []
    for r in data:
        if isinstance(r, dict) and r.get("local_name"):
            out.append(r)
    return out


def _clone_upstream_for_fork(upstream_repo: str, ref: str, dest: Path) -> bool:
    """Shallow clone ``owner/repo`` at ref into dest. True on success. Mirrors
    fork-modified-files-scope.py::_clone_upstream (kept here so the in-process
    emitter does not shell out to that CLI)."""
    if not upstream_repo or not ref:
        return False
    url = f"https://github.com/{upstream_repo}.git"
    try:
        rc = subprocess.run(
            ["git", "clone", "--depth", "1", "--branch", ref, url, str(dest)],
            capture_output=True, text=True, timeout=600,
        )
    except (OSError, subprocess.SubprocessError):
        return False
    return rc.returncode == 0


def _fork_scope_signature(fork_bases: list[dict]) -> str:
    """Deterministic signature of the fork-base set, stamped into the manifest
    sidecar so a re-emit over an already-scoped tree is recognisably idempotent.
    Order-independent (sorted on local_name)."""
    items = sorted(
        (str(r.get("local_name")), str(r.get("upstream_repo") or ""),
         str(r.get("base_ref") or ""))
        for r in fork_bases
    )
    blob = json.dumps(items, separators=(",", ":"))
    return hashlib.sha256(blob.encode("utf-8")).hexdigest()


def _apply_fork_scope(ws: Path, rows: list[dict]) -> tuple[list[dict], dict]:
    """Drop manifest rows whose repo-relative file is UNMODIFIED-upstream for a
    resolved fork. COMPLETENESS-SAFE + LANGUAGE-GENERAL + idempotent.

    - No fork_bases.json / unresolved base / clone failure / lib unavailable ->
      KEEP ALL of that fork's rows + a loud WARN + the one-line manual step
      (run resolve-fork-bases.py). NEVER silently under-scope.
    - Pruning reuses tools/lib/fork_modified.compute_modified_files (multi-lang);
      a row is kept iff its repo-relative path is in the fork's modified set.
    - Rows for non-fork files (no ``src/<local_name>/`` prefix) pass through.
    - Idempotent: re-emit over an already-scoped tree yields the SAME row set
      (the modified set is computed from the fork checkout vs upstream, not from
      whatever rows already exist).

    Returns ``(scoped_rows, detail)`` where detail feeds the sidecar stamp.
    """
    fork_bases = _load_fork_bases(ws)
    if not fork_bases:
        return rows, {"applied": False, "reason": "no-fork_bases.json"}

    fm = _load_fork_modified_lib()
    if fm is None:
        sys.stderr.write(
            "[inscope-manifest] WARN tools/lib/fork_modified unavailable; "
            "KEEPING ALL fork units (completeness-safe, no under-scope)\n"
        )
        return rows, {"applied": False, "reason": "fork_modified-lib-unavailable"}

    import tempfile as _tempfile

    detail: dict = {
        "applied": True,
        "fork_scope_signature": _fork_scope_signature(fork_bases),
        "forks": [],
    }
    # modified_files per local_name; None = keep-all (unresolved/clone-fail).
    modified_by_name: dict[str, set | None] = {}
    for fr in fork_bases:
        name = str(fr.get("local_name"))
        upstream_repo = str(fr.get("upstream_repo") or "")
        base_ref = str(fr.get("base_ref") or "")
        fork_dir = ws / "src" / name
        fork_detail = {
            "local_name": name, "upstream_repo": upstream_repo,
            "base_ref": base_ref,
        }
        if not fork_dir.is_dir():
            # declared-but-absent fork dir: nothing to prune, no warn needed.
            modified_by_name[name] = None
            fork_detail["verdict"] = "fork-dir-absent-keep-all"
            detail["forks"].append(fork_detail)
            continue
        if not upstream_repo or not base_ref:
            sys.stderr.write(
                f"[inscope-manifest] WARN fork '{name}' base unresolved "
                f"(upstream_repo/base_ref missing); KEEPING ALL its units "
                f"(completeness-safe). MANUAL STEP: run "
                f"`python3 tools/resolve-fork-bases.py --workspace {ws}` "
                f"after adding a SCOPE.md '## Fork Bases' row.\n"
            )
            modified_by_name[name] = None
            fork_detail["verdict"] = "base-unresolved-keep-all"
            detail["forks"].append(fork_detail)
            continue
        # clone upstream + compute the multi-language modified surface.
        with _tempfile.TemporaryDirectory(prefix="inscope-fork-") as td:
            dest = Path(td) / f"upstream_{name}"
            if not _clone_upstream_for_fork(upstream_repo, base_ref, dest):
                sys.stderr.write(
                    f"[inscope-manifest] WARN upstream "
                    f"{upstream_repo}@{base_ref} for fork '{name}' could not be "
                    f"cloned; KEEPING ALL its units (completeness-safe). MANUAL "
                    f"STEP: verify the base ref then re-run "
                    f"`python3 tools/resolve-fork-bases.py --workspace {ws}`.\n"
                )
                modified_by_name[name] = None
                fork_detail["verdict"] = "clone-failed-keep-all"
                detail["forks"].append(fork_detail)
                continue
            try:
                modified = fm.compute_modified_files(fork_dir, dest, skip_tests=True)
            except Exception as exc:  # pragma: no cover - defensive
                sys.stderr.write(
                    f"[inscope-manifest] WARN diff of fork '{name}' vs upstream "
                    f"failed ({exc}); KEEPING ALL its units (completeness-safe).\n"
                )
                modified = None
            modified_by_name[name] = modified
            fork_detail["verdict"] = (
                "scoped" if modified is not None else "diff-failed-keep-all"
            )
            fork_detail["modified_file_count"] = (
                len(modified) if modified is not None else None
            )
            detail["forks"].append(fork_detail)

    # Prune rows. A row under ``src/<name>/`` is kept iff its repo-relative path
    # is in that fork's modified set (None modified set => keep-all). Rows that
    # belong to no resolved fork pass through untouched.
    kept: list[dict] = []
    for row in rows:
        f = str(row.get("file") or "")
        matched_fork = None
        rel_in_repo = None
        for name in modified_by_name:
            prefix = f"src/{name}/"
            seg = f"/src/{name}/"
            if f.startswith(prefix):
                matched_fork = name
                rel_in_repo = f[len(prefix):]
                break
            if seg in f:
                matched_fork = name
                rel_in_repo = f.split(seg, 1)[1]
                break
        if matched_fork is None:
            kept.append(row)
            continue
        modified = modified_by_name[matched_fork]
        if modified is None:
            kept.append(row)  # keep-all for this fork (completeness-safe)
            continue
        if rel_in_repo in modified:
            kept.append(row)
        # else: unmodified-upstream -> dropped (OOS)
    detail["rows_in"] = len(rows)
    detail["rows_out"] = len(kept)
    return kept, detail


def build_inscope_manifest_rows(ws: Path, scope: dict | None = None) -> list[dict]:
    """Build the in-scope manifest rows for a workspace.

    REUSES the same scope resolution, prune rules, granularity map, and
    rust-source-graph entrypoint extraction that :func:`enumerate_units` uses,
    so the manifest's unit set is identical to the coverage denominator. Each
    row matches the canonical ``inscope_units.jsonl`` shape EXACTLY. The
    ``prior_covered`` flag is computed by feeding each row's canonical unit key
    through :func:`_unit_is_covered` against the workspace's coverage tokens, so
    a manifest row is ``prior_covered=true`` iff the coverage report would mark
    that unit COVERED.

    Generic: enumeration is driven by file extension + scope only; no target or
    workspace literal appears in the logic.
    """
    if scope is None:
        scope = resolve_scope(ws)
    units, enum_detail = enumerate_units(ws, scope=scope)
    tokens, _skipped = collect_coverage_tokens_with_skips(
        ws, scope=scope, units=units, enum_detail=enum_detail
    )
    fn_precise = _bases_with_fn_precise_tokens(tokens)
    ambiguous = set(enum_detail.get("ambiguous_source_basenames") or [])
    unique_file_keys = _unique_file_keys_by_basename(units, ambiguous)

    scope_globs = scope.get("scope_globs", []) or []
    scope_regexes = [_glob_to_regex(g) for g in scope_globs] if scope_globs else []
    scope_exclude_globs = scope.get("scope_exclude_globs", []) or []
    scope_exclude_regexes = (
        [_glob_to_regex(g) for g in scope_exclude_globs] if scope_exclude_globs else []
    )
    root = Path(scope.get("source_root") or _coverage_source_root(ws))
    if not root.is_dir():
        return []
    # Canonical OOS exclusion (shared single source of truth) - drop vendored /
    # test / mock / script / docs / previousVersions / .t.sol / soldeer-deps rows
    # so the manifest never ships OOS units. This walk is separate from
    # enumerate_units' walk, so the same guard is applied here too.
    _is_oos = _load_is_oos()

    # Ambiguous-basename detection mirrors enumerate_units (root-wide, unscoped)
    # so the file-key choice (basename vs relpath) matches the unit set exactly.
    rust_graph_by_file = _rust_graph_rows_by_file(ws)
    rust_graph_mode = bool(rust_graph_by_file)
    # Same authoritative per-function-invariant manifest _enumerate_functions
    # (the denominator's own enumerator) prefers, so the in-scope manifest's
    # Go/Rust/Move/Cairo/Vyper decomposition matches it exactly (see
    # _enumerate_functions_with_lines).
    per_fn_manifest_index = _load_per_fn_manifest_index(ws)

    rows: list[dict] = []

    def _emit(rel: str, fn: str, line: int, lang: str, file_key: str) -> None:
        unit = f"{file_key}::{fn}" if fn else file_key
        covered = _unit_is_covered(unit, tokens, fn_precise, unique_file_keys)
        rows.append({
            "file": rel,
            "function": fn,
            "file_line": f"{rel}:{line}" if line else rel,
            "lang": lang,
            "prior_covered": bool(covered),
        })

    seen_real: set[str] = set()
    for dirpath, dirnames, filenames in os.walk(root, followlinks=True):
        real = os.path.realpath(dirpath)
        if real in seen_real:
            dirnames[:] = []
            continue
        seen_real.add(real)
        dirnames[:] = sorted(
            d for d in dirnames
            if not d.startswith(".")
            and not _coverage_dir_pruned(os.path.join(dirpath, d))
        )
        for fn_name in sorted(filenames):
            ext = os.path.splitext(fn_name)[1].lower()
            gran = _COVERAGE_EXT_GRANULARITY.get(ext)
            if gran is None:
                continue
            full = os.path.join(dirpath, fn_name)
            if _coverage_pruned(full, ext=ext):
                continue
            # Filename-pattern exclude (test/script/.t.sol + mutation-test
            # artifact *Mutant*.sol) - mirror enumerate_units so the manifest
            # unit set matches the coverage denominator and never ships a
            # seeded-mutant contract as an in-scope function (the SSV 7-hollow
            # false-red). r36-rebuttal: lane coverage-denominator-generated-exclude.
            _file_excl = _COVERAGE_FILE_EXCLUDE_BY_EXT.get(ext)
            if _file_excl is not None and _file_excl.search(fn_name):
                continue
            # Content-based exclude: generated-code + mutation-test-artifact headers.
            if _is_generated_source_file(full):
                continue
            # Body-less Solidity interface files are permanently uncoverable.
            if ext == ".sol" and _is_interface_only_sol_file(full):
                continue
            rel = os.path.relpath(full, str(ws)).replace("\\", "/")
            # F5: head= for the generated-header (DO NOT EDIT) catch.
            if _is_oos is not None:
                _head = _oos_head(full)
                if _is_oos(rel, head=_head):
                    # is_oos_dir is EXTENSION-BLIND: it prunes a `/lib/` segment
                    # as a Foundry/npm vendored dep. For an ext whose layout uses
                    # that segment STRUCTURALLY (Noir/Nargo `.nr` under
                    # `lib/<pkg>/src/`), honor the same exemption the heatmap's own
                    # per-ext prune already applies - re-test is_oos with the
                    # exempt segment(s) neutralized; if the ONLY oos reason was an
                    # exempt segment, keep the file. ext with no exemption (.sol,
                    # .go, .rs, ...) is unaffected and still dropped.
                    _exempt = _PRUNE_SEGMENT_EXEMPT_BY_EXT.get(ext)
                    _kept = False
                    if _exempt:
                        _probe = "/" + rel.strip("/")
                        for _seg in _exempt:
                            _probe = _probe.replace(_seg, "/")
                        _probe = _probe.strip("/")
                        if not _is_oos(_probe, head=_head):
                            _kept = True
                    if not _kept:
                        continue
            if scope_regexes and not _path_matches_any(scope_regexes, rel, full):
                continue
            if _path_matches_any(scope_exclude_regexes, rel, full):
                continue
            lang = _registry_lang_of(ext)
            if lang is None:
                continue
            # File-key choice mirrors enumerate_units: a relpath when the
            # basename is ambiguous (appears under >1 path), else the basename.
            base = Path(rel).name
            file_key = rel if base in ambiguous else base

            if ext == ".rs" and rust_graph_mode and rel in rust_graph_by_file:
                for gfn, gline in rust_graph_by_file[rel]:
                    _emit(rel, gfn, gline, lang, file_key)
                continue
            if gran == "function":
                pairs = _enumerate_functions_with_lines(
                    Path(full), ext, manifest_index=per_fn_manifest_index, rel=rel,
                )
                if pairs:
                    for pfn, pline in pairs:
                        _emit(rel, pfn, pline, lang, file_key)
                else:
                    # Function-granularity file with no parsable function ->
                    # file-granularity unit (never silently dropped).
                    _emit(rel, "", 0, lang, file_key)
            else:
                # File granularity (.go/.rs without graph/.move/.cairo/.vy).
                _emit(rel, "", 0, lang, file_key)
    # FORK-SCOPE PRUNE: when <ws>/.auditooor/fork_bases.json exists, drop rows
    # whose repo-relative file is unmodified-upstream per fork (reusing the
    # multi-language tools/lib/fork_modified). Completeness-safe + idempotent;
    # a non-fork ws (no sidecar) is a no-op so existing behaviour is preserved.
    rows, fork_scope_detail = _apply_fork_scope(ws, rows)
    build_inscope_manifest_rows._last_fork_scope_detail = fork_scope_detail  # type: ignore[attr-defined]
    return rows


def _inscope_units_sample_paths(ws, limit: int = 300) -> list[str]:
    """Up to `limit` distinct repo-relative source-file paths from
    <ws>/.auditooor/inscope_units.jsonl (the AUTHORITATIVE intake enumeration that
    the hunt uses). Used to GROUND a SCOPE.md enumerated allowlist against the real
    in-scope file universe. Empty list when the manifest is absent/unreadable."""
    p = Path(ws) / ".auditooor" / "inscope_units.jsonl"
    if not p.is_file():
        return []
    out: list[str] = []
    seen: set[str] = set()
    try:
        with p.open(encoding="utf-8", errors="replace") as fh:
            for line in fh:
                line = line.strip()
                if not line:
                    continue
                try:
                    d = json.loads(line)
                except ValueError:
                    continue
                f = str(d.get("file") or d.get("path") or "").strip()
                if not f or f in seen:
                    continue
                seen.add(f)
                out.append(f)
                if len(out) >= limit:
                    break
    except OSError:
        return []
    return out


def _scope_token_is_path_like(tok: str) -> bool:
    """A SCOPE.md enumerated in-scope token can serve as a FILE allowlist only if
    it looks like a path/file token: it contains a '/' path separator OR ends in a
    known source-file extension. Deployed-address / symbolic-name enumerations
    (NUVA 2026-07-01: `ETH_NVPRIME_VAULT_ROUTER`, `0x50AE...`, Provenance bech32
    `pb10yzu...`, `nvYLDS Vault Proxy SC Address`) are NOT path-like - using them
    as a per-file allowlist matches ZERO real source files and drops the entire
    coverage denominator. Generic: no workspace/target literal."""
    t = (tok or "").strip()
    if not t:
        return False
    if "/" in t:
        return True
    return os.path.splitext(t)[1].lower() in _COVERAGE_EXT_GRANULARITY


def _load_scope_md_allowlist(ws):
    """Return (manifest, scope_md_parser_module) when <ws>/SCOPE.md declares a
    NON-EMPTY enumerated in-scope allowlist of PATH-LIKE tokens; else (None, None).
    Shared by the inscope_units emitter AND _source_file_records so both honor the
    same allowlist. Fail-safe: any error -> (None, None) (no extra filtering).

    NUVA 2026-07-01: the per-file consumers (_source_file_records, enumerate_units)
    apply is_path_in_scope with NO batch fail-safe (unlike _scope_md_allowlist_filter's
    `kept if kept else rows`). So when SCOPE.md enumerates ONLY deployed addresses /
    symbolic names (no file paths) - a legitimate Immunefi address-scope shape - the
    allowlist matches nothing and empties the coverage denominator (coverage-map
    FAIL: 0 units vs 205 inscope). Treat an allowlist with NO path-like token as
    ABSENT so the surface is bounded by scope_globs + is_oos alone (exactly how the
    inscope manifest survives it via its fail-safe). Never under-scopes."""
    try:
        import importlib.util as _ilu
        _smp_path = Path(__file__).resolve().parent / "scope-md-parser.py"
        _spec = _ilu.spec_from_file_location("scope_md_parser_wch", str(_smp_path))
        _smp = _ilu.module_from_spec(_spec)
        sys.modules["scope_md_parser_wch"] = _smp
        _spec.loader.exec_module(_smp)
        mf = _smp.parse_scope_md(Path(ws) / "SCOPE.md")
        if not mf.in_scope_paths:
            return None, None
        if not any(_scope_token_is_path_like(p) for p in mf.in_scope_paths):
            # enumerated allowlist is address/symbol-only, not a file allowlist
            return None, None
        # SEI 2026-07-04: a PROSE SCOPE.md (whole-repo Primacy-of-Impact scope) can
        # MIS-PARSE vuln-class words into in_scope_paths ('Crash/halt',
        # 'tx-fee-calculation') that pass _scope_token_is_path_like (they contain
        # '/' or '-') yet match ZERO real source files. The per-file coverage
        # consumers apply is_path_in_scope with NO batch fail-safe, so such a
        # spurious allowlist empties the whole coverage denominator (SEI: admitted
        # 0 of 2949 in-scope .go, total_units collapsed to 5 OOS Rust examples).
        # GROUND the allowlist against the authoritative intake enumeration
        # (inscope_units.jsonl, already batch-fail-safe-filtered): if it admits NONE
        # of those real in-scope files, it is a mis-parse -> treat as ABSENT
        # (whole-repo scope, bounded by scope_globs + is_oos alone). Skipped when
        # inscope_units.jsonl is absent (the emission path, which has its own batch
        # fail-safe). Never under-scopes: a genuine path allowlist admits its files.
        _sample = _inscope_units_sample_paths(ws, limit=300)
        if _sample and not any(_smp.is_path_in_scope(p, mf)[0] for p in _sample):
            return None, None
        return mf, _smp
    except Exception:
        return None, None


def _scope_md_allowlist_filter(ws: Path, rows: list) -> list:
    """Intersect the in-scope manifest rows with the SCOPE.md ENUMERATED allowlist.

    Strata 2026-06-30: the intake over-collects the whole cloned repo into the
    AUTHORITATIVE inscope_units.jsonl (scope_exclusion.is_in_scope trusts it verbatim
    for inclusion). When SCOPE.md enumerates an EXPLICIT in-scope target list ("exactly
    these N targets, nothing else"), an unfiltered manifest leaks OOS files (Strata:
    Strategy.sol=149 units, DiscreteAccounting, lens/, swap/) into the worklist +
    coverage denominator. Drop every row whose file matches no enumerated in-scope
    token. ALLOWLIST-GATED + fail-safe: only filters when SCOPE.md declares a non-empty
    enumerated allowlist; a whole-repo scope doc (no enumerated paths) is returned
    unchanged (never under-scopes). Errors -> rows unchanged (more coverage)."""
    try:
        import importlib.util as _ilu
        _smp_path = Path(__file__).resolve().parent / "scope-md-parser.py"
        _spec = _ilu.spec_from_file_location("scope_md_parser_wch", str(_smp_path))
        _smp = _ilu.module_from_spec(_spec)
        sys.modules["scope_md_parser_wch"] = _smp
        _spec.loader.exec_module(_smp)
        mf = _smp.parse_scope_md(Path(ws) / "SCOPE.md")
        if not mf.in_scope_paths:
            return rows  # no enumerated allowlist -> whole-repo scope, unchanged
        kept = []
        for r in rows:
            rel = str(r.get("file") or r.get("path") or r.get("rel") or "")
            in_scope, _ = _smp.is_path_in_scope(rel, mf)
            if in_scope:
                kept.append(r)
        return kept if kept else rows  # never empty the manifest (fail-safe)
    except Exception:
        return rows


def _oos_adjudication_filter(ws: Path, rows: list) -> list:
    """Drop manifest rows whose file already has an EXPLICIT verdict:oos
    commit_adjudication WITH a cited reason.

    Strata 2026-07-07: the enumerator over-collects transitively-reachable
    first-party files SCOPE.md excludes (read-only lens/ view helpers). CDOLens got
    17 units into the manifest despite a verdict:oos adjudication ("lens/ not among
    the in-scope targets; read-only view helper"), which tripped
    inscope-disposition-guard and inflated the fcc denominator on EVERY manifest
    regen (a one-shot reconcile got undone). Wiring the drop here - at the single
    manifest-write chokepoint, AFTER the SCOPE.md allowlist filter - makes it
    persist across regens. SAFETY: only drops a file that carries a real OOS verdict
    + reason; a value-mover with no such adjudication is never touched (unlike a
    strict allowlist, which would wrongly drop Accounting/DiscreteAccounting/StrataCDO
    transitive value-flow that SCOPE.md does not enumerate). Fail-open on any error."""
    try:
        import glob as _glob
        oos = {}
        for p in _glob.glob(str(ws / ".auditooor" / "*adjudication*.jsonl")):
            for line in Path(p).read_text(errors="ignore").splitlines():
                line = line.strip()
                if not line:
                    continue
                try:
                    j = json.loads(line)
                except (json.JSONDecodeError, ValueError):
                    continue
                if not isinstance(j, dict):
                    continue
                v = str(j.get("verdict", "")).lower().replace(" ", "-")
                reason = str(j.get("reason", "")).strip()
                ref = j.get("source_ref") or j.get("file") or ""
                if v in ("oos", "out-of-scope", "out_of_scope", "not-in-scope") and reason and ref:
                    base = os.path.basename(str(ref).split(":")[0])
                    if base.endswith((".sol", ".rs", ".go", ".vy", ".cairo", ".move", ".nr")):
                        oos[base] = reason
        if not oos:
            return rows
        kept = [r for r in rows
                if os.path.basename(str(r.get("file") or r.get("path") or "")) not in oos]
        return kept if kept else rows  # never empty the manifest (fail-safe)
    except Exception:  # noqa: BLE001 - fail-open (more coverage, never under-scope on error)
        return rows


_IFACE_DECL_RE = re.compile(r"^\s*(?:abstract\s+)?interface\s+\w", re.MULTILINE)
_CONTRACT_DECL_RE = re.compile(r"^\s*(?:abstract\s+)?contract\s+\w|^\s*library\s+\w", re.MULTILINE)


def _interface_only_filter(ws: Path, rows: list) -> list:
    """Drop manifest rows whose FILE is a pure Solidity `interface` declaration
    (an `interface X {...}` file with no implementing `contract`/`library`).

    Strata 2026-07-07: interfaces are signature-only ABI - no implementation, no
    state, no value movement, so no SEVERITY.md impact is reachable from one and a
    per-function security hunt is not applicable. Yet the enumerator counts every
    interface method as an in-scope unit, which (a) inflates the fcc denominator
    with un-coverable stubs (blocking 100%) and (b) collides head-on with the
    coverage-map swept-surface disposition: marking an interface unit
    skipped-oos-interface trips inscope-disposition-guard (a manifest unit closed
    OOS). Excluding interface files from the manifest removes them from the fcc
    denominator AND the inscope-disposition scan in one move. Solidity-only; other
    languages and any parse error fall through unchanged (fail-open, never
    under-scope). Never empties the manifest."""
    try:
        cache: dict = {}

        def _is_iface(rel: str) -> bool:
            if rel in cache:
                return cache[rel]
            verdict = False
            try:
                if rel.endswith(".sol"):
                    txt = (ws / rel).read_text(errors="ignore")
                    verdict = bool(_IFACE_DECL_RE.search(txt)) and not _CONTRACT_DECL_RE.search(txt)
            except OSError:
                verdict = False
            cache[rel] = verdict
            return verdict

        kept = [r for r in rows if not _is_iface(str(r.get("file") or r.get("path") or ""))]
        return kept if kept else rows
    except Exception:  # noqa: BLE001 - fail-open
        return rows


_OSCRIPT_MOD = None
_OSCRIPT_MOD_TRIED = False


def _oscript_module():
    """Lazy-load tools/oscript-aa-enumerate.py (hyphenated filename -> not a
    normal import). Returns the module or None if unavailable. The Obyte
    Autonomous-Agent enumerator teaches this manifest to include .oscript/.aa
    units alongside .sol/.rs/.go/... - ADDITIVELY: it never touches the existing
    rows, it only appends AA rows when AA files exist in scope."""
    global _OSCRIPT_MOD, _OSCRIPT_MOD_TRIED
    if _OSCRIPT_MOD_TRIED:
        return _OSCRIPT_MOD
    _OSCRIPT_MOD_TRIED = True
    try:
        import importlib.util
        tool = Path(__file__).with_name("oscript-aa-enumerate.py")
        if not tool.is_file():
            return None
        spec = importlib.util.spec_from_file_location("oscript_aa_enumerate", tool)
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
        _OSCRIPT_MOD = mod
    except Exception:  # noqa: BLE001 - additive helper must never break the emit
        _OSCRIPT_MOD = None
    return _OSCRIPT_MOD


def _oscript_inscope_rows(ws: Path) -> list[dict]:
    """Enumerate in-scope Obyte AA (.oscript/.aa) units. Returns [] on any
    failure (never disturbs the primary-language rows)."""
    mod = _oscript_module()
    if mod is None:
        return []
    try:
        return mod.enumerate_workspace(Path(ws))
    except Exception:  # noqa: BLE001
        return []


def _oscript_aa_files(ws: Path) -> list:
    """List in-scope AA (.oscript/.aa) files under ``ws`` (or [] on failure)."""
    mod = _oscript_module()
    if mod is None:
        return []
    try:
        return list(mod.list_aa_files(Path(ws)))
    except Exception:  # noqa: BLE001
        return []


def _inscope_row_sort_key(row: dict) -> tuple[str, str, str, str, bool]:
    """Stable ordering for the canonical manifest, including AA rows."""
    return (
        str(row.get("file") or ""),
        str(row.get("function") or ""),
        str(row.get("file_line") or ""),
        str(row.get("lang") or ""),
        bool(row.get("prior_covered")),
    )


def build_expected_inscope_manifest_rows(ws: Path) -> list[dict]:
    """Return the complete deterministic row sequence emitted for ``ws``.

    This is deliberately the single freshness and validation authority.  It
    retains the producer's scope, OOS, interface, fork, and specialized AA
    enumeration paths, but normalizes their final ordering before comparison or
    serialization.
    """
    rows = build_inscope_manifest_rows(ws)
    rows = _scope_md_allowlist_filter(ws, rows)
    rows = _oos_adjudication_filter(ws, rows)
    rows = _interface_only_filter(ws, rows)
    rows = rows + _oscript_inscope_rows(ws)
    return sorted(rows, key=_inscope_row_sort_key)


def _serialize_inscope_manifest_rows(rows: list[dict]) -> str:
    return "".join(json.dumps(row, separators=(", ", ": ")) + "\n" for row in rows)


def write_inscope_manifest(
    ws: Path, force: bool = False
) -> tuple[Path, int, bool]:
    """Write ``<ws>/.auditooor/inscope_units.jsonl``. Idempotent: if the
    existing serialized rows equal the complete current deterministic expected
    row sequence (and ``force`` is False), it is left untouched. Returns
    ``(path, row_count, wrote)`` where ``wrote`` is False when an identical
    existing manifest was kept.

    Additive Oscript arm: when the workspace contains Obyte Autonomous-Agent
    sources (.oscript / .aa) - as the Obyte engagement does - their message-case
    / getter / init units are APPENDED after the primary-language rows. The
    freshness gate below is extended so an AA-uncovered (or AA-stale) manifest is
    re-emitted; the primary-language rows are rebuilt byte-identically."""
    out = ws / ".auditooor" / "inscope_units.jsonl"
    if out.is_file() and not force:
        try:
            expected_rows = build_expected_inscope_manifest_rows(ws)
            if out.read_text(encoding="utf-8") == _serialize_inscope_manifest_rows(expected_rows):
                return out, len(expected_rows), False
        except (OSError, ValueError, TypeError):
            pass
    rows = build_expected_inscope_manifest_rows(ws)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(_serialize_inscope_manifest_rows(rows), encoding="utf-8")
    # Stamp the fork-scope signature sidecar so a re-emit over an already-scoped
    # tree is recognisably idempotent (and downstream gates can see whether a
    # fork prune was applied). Only written when fork-scope actually ran.
    fork_detail = getattr(
        build_inscope_manifest_rows, "_last_fork_scope_detail", None
    )
    if isinstance(fork_detail, dict) and fork_detail.get("applied"):
        sidecar = out.parent / "inscope_units.fork_scope.json"
        try:
            sidecar.write_text(
                json.dumps({
                    "schema": "auditooor.inscope_fork_scope.v1",
                    **fork_detail,
                }, indent=2, sort_keys=True) + "\n",
                encoding="utf-8",
            )
        except OSError:
            pass
    return out, len(rows), True


def main(argv: list[str]) -> int:
    p = argparse.ArgumentParser()
    p.add_argument("--workspace", help="Single workspace name (e.g. hyperbridge)")
    p.add_argument("--all-workspaces", action="store_true",
                   help="Run all known workspaces (morpho-midnight, hyperbridge, near, dydx, zebra)")
    p.add_argument("--out-dir", default=str(AUDITOOOR_ROOT / "reports"),
                   help="Output dir for markdown reports")
    p.add_argument("--json", action="store_true", help="Emit summary JSON to stdout")
    # SWEPT-SURFACE coverage report mode (mode 2 - the L37 signal).
    p.add_argument("--coverage-report", action="store_true",
                   help="Emit the schema-versioned SWEPT-SURFACE coverage report "
                        "to <ws>/.auditooor/coverage_report.json")
    p.add_argument("--workspace-path",
                   help="Absolute workspace PATH (required for --coverage-report "
                        "/ --emit-inscope-manifest)")
    # GENERIC in-scope manifest mode (mode 3) - the inscope_units.jsonl emitter.
    p.add_argument("--emit-inscope-manifest", action="store_true",
                   help="Emit the GENERIC in-scope manifest to "
                        "<ws>/.auditooor/inscope_units.jsonl (idempotent unless "
                        "--force).")
    p.add_argument("--force", action="store_true",
                   help="With --emit-inscope-manifest: overwrite even a fresh "
                        "existing manifest.")
    p.add_argument("--uncovered-list-cap", type=int, default=DEFAULT_UNCOVERED_LIST_CAP,
                   help="Cap on inlined uncovered unit names (true count never "
                        "truncated). Negative = no cap.")
    args = p.parse_args(argv)

    # ---- mode 3: GENERIC in-scope manifest (inscope_units.jsonl) ----
    if args.emit_inscope_manifest:
        if not args.workspace_path and not args.workspace:
            p.error("--emit-inscope-manifest requires --workspace-path "
                    "(or --workspace name)")
        ws = (
            Path(os.path.expanduser(args.workspace_path)).resolve()
            if args.workspace_path
            else workspace_to_path(args.workspace)
        )
        if not ws.is_dir():
            sys.stderr.write(f"[inscope-manifest] workspace path not found: {ws}\n")
            return 2
        out_path, count, wrote = write_inscope_manifest(ws, force=args.force)
        verb = "wrote" if wrote else "kept fresh existing"
        sys.stderr.write(f"[inscope-manifest] {verb} {out_path} ({count} units)\n")
        if args.json:
            print(json.dumps({
                "workspace": str(ws),
                "manifest_path": str(out_path),
                "unit_count": count,
                "wrote": wrote,
            }, indent=2))
        else:
            print(f"{ws.name}: {count} in-scope units -> {out_path} "
                  f"({'written' if wrote else 'kept fresh existing'})")
        return 0

    # ---- mode 2: SWEPT-SURFACE coverage report ----
    if args.coverage_report:
        if not args.workspace_path and not args.workspace:
            p.error("--coverage-report requires --workspace-path (or --workspace name)")
        ws = (
            Path(os.path.expanduser(args.workspace_path)).resolve()
            if args.workspace_path
            else workspace_to_path(args.workspace)
        )
        if not ws.is_dir():
            sys.stderr.write(f"[coverage] workspace path not found: {ws}\n")
            return 2
        out_path, report = write_coverage_report(ws, list_cap=args.uncovered_list_cap)
        sys.stderr.write(f"[coverage] wrote {out_path}\n")
        if args.json:
            print(json.dumps(report, indent=2))
        else:
            print(
                f"{report['workspace_name']}: {report['covered']}/{report['total_units']} "
                f"covered, {report['uncovered']} UNCOVERED "
                f"(coverage_fraction={report['coverage_fraction']})"
            )
            if report["uncovered_units_truncated"]:
                print(f"  (uncovered list capped; {report['uncovered_units_omitted']} "
                      f"names omitted, TRUE uncovered count = {report['uncovered']})")
        # (defect 2) Under the named strict env, a whole in-scope language
        # silently dropped from the denominator BLOCKS (non-zero exit) so the
        # L37 coverage gate fails closed. Advisory (WARN-only) otherwise.
        _backstop = report.get("coverage_completeness_backstop") or {}
        if _backstop.get("status") == "block":
            return 4
        return 0

    if not args.workspace and not args.all_workspaces:
        p.error("--workspace or --all-workspaces required")

    workspaces = (
        ["morpho-midnight", "hyperbridge", "near", "dydx", "zebra"]
        if args.all_workspaces
        else [args.workspace]
    )

    out_dir = Path(args.out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    summary = {"timestamp": iso_now(), "workspaces": {}}
    for ws in workspaces:
        sys.stderr.write(f"[coverage] processing {ws}...\n")
        ws_path = workspace_to_path(ws)
        hits, applies = collect_hits(ws, workspace_path=ws_path)
        ws_files = list_workspace_files(ws_path)
        md = render_markdown(ws, hits, applies, ws_files)
        date = datetime.now().strftime("%Y-%m-%d")
        # Sanitize the workspace token: an absolute-path ws (/Users/.../strata) embeds
        # slashes into the filename -> nested nonexistent dirs -> FileNotFoundError that
        # crashed the whole heatmap run (strata 2026-06-30). Slug it to a flat basename.
        _ws_slug = re.sub(r"[^A-Za-z0-9_.-]+", "_", str(ws)).strip("_") or "workspace"
        out_path = out_dir / f"coverage_heatmap_{_ws_slug}_{date}.md"
        out_path.write_text(md)
        sys.stderr.write(f"  wrote {out_path} ({len(md)} chars)\n")
        summary["workspaces"][ws] = {
            "total_hits": sum(hits.values()),
            "unique_contracts_hit": len(hits),
            "workspace_files": len(ws_files),
            "covered": len(set(hits.keys()) & ws_files),
            "uncovered": len(ws_files - set(hits.keys())),
            "phantom_hits": len(set(hits.keys()) - ws_files),
            "output_path": str(out_path),
        }

    if args.json:
        print(json.dumps(summary, indent=2))
    else:
        for ws, s in summary["workspaces"].items():
            print(f"{ws}: {s['total_hits']} hits / {s['unique_contracts_hit']} contracts / "
                  f"{s['uncovered']}/{s['workspace_files']} UNCOVERED / {s['phantom_hits']} phantom")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
