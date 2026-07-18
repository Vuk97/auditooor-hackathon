#!/usr/bin/env python3
"""MQ-B07 - Total-order comparator soundness enforcement screen (GENERAL).

North-star framing (w8mv5mpcw - "A TRUSTED ENFORCEMENT is bypassable or its
private invariant is unsound"):

  * DELEGATED-AND-TRUSTED enforcement: every ordering-dependent container /
    algorithm in Rust (``BTreeMap`` / ``BTreeSet`` / ``BinaryHeap`` /
    ``slice::sort_by`` / ``sort_unstable_by`` / ``binary_search_by`` /
    ``min_by`` / ``max_by``) DELEGATES its structural correctness to (TRUSTS) the
    comparator it is handed - a closure or a hand-written ``Ord`` /
    ``PartialOrd`` impl.  The container NEVER re-checks the comparator; it
    assumes the delegated relation upholds a private mathematical contract.
  * PRIVATE INVARIANT: the comparator is a *proven total order* - total
    (never returns ``None`` / partial), transitive, and antisymmetric - for the
    ENTIRE value domain that can reach it.
  * ATTACK ON THE INVARIANT: when the comparator is derived from a *partial*
    order via ``partial_cmp(..).unwrap()`` / ``.expect(..)`` / ``.unwrap_or(..)``
    (the canonical float shape: ``NaN`` makes ``partial_cmp`` return ``None``),
    or a hand-rolled ``cmp`` that is non-transitive / non-antisymmetric, then an
    attacker who can steer a single value into the ``NaN`` (or contradictory)
    case breaks the delegated invariant.  The blast radius is decided at
    RUN TIME, not here: a ``.unwrap()`` panics (validator / node halt); a
    ``.unwrap_or(Equal)`` silently violates transitivity and CORRUPTS the
    container (``BTreeMap`` loses keys, ``sort`` drops/duplicates elements,
    ``binary_search`` mis-dedups).

This is a GENERAL invariant/enforcement CLASS, not a bug shape:
  - It enumerates the WHOLE ordering-dependent-comparator family (every closure
    comparator sink + every hand-written ``cmp`` / ``partial_cmp`` body that a
    ``BTreeMap`` / ``BinaryHeap`` key type delegates to) and asks a single
    enforcement-completeness question of each: "is the delegated comparison a
    PROVEN total order, or a partial order laundered into an ``Ordering``?"
  - The IMPACT is left OPEN (verdict=needs-fuzz).  Nothing here decides a tier -
    whether the run-time consequence is a halting panic, a silent container
    corruption, or a benign integer tuple (``partial_cmp`` that can never be
    ``None`` in practice) is exactly what the downstream fuzz harness settles.

Why the two-half predicate is non-vacuous (see the tests):
  * HALF 1 ``classify_ordering_sink`` - is this an ordering-dependent comparator
    site at all?  Neutralizing it (return no sinks) makes every row disappear.
  * HALF 2 ``is_total_order_sound`` - is the delegated comparison a proven total
    order (uses ``.cmp`` only, or a ``total_cmp`` / ``OrderedFloat`` / ``NotNan``
    total-order wrapper)?  A row is emitted ONLY when a sink is found AND the
    comparison is NOT sound.  Neutralizing it (pretend every comparator is a
    proven total order) also makes every row disappear.

Deduplication vs pre-existing tools (tool-duplication preflight, do-NOT #10):
  - ``rust-detector-runner.py`` RU6 (HashMap/float/wall-clock non-determinism)
    flags float/iteration NON-DETERMINISM in a deterministic (consensus) path;
    it is about *reproducibility across nodes*, not about whether a comparator
    is a total order.  MQ-B07 fires on a *single-node* container-corruption /
    panic from an unsound ordering relation, independent of determinism, and
    keys on the ``sort_by`` / ``Ord``-impl comparator specifically.
  - The generic ``unwrap``/panic detectors flag ANY ``.unwrap()``; MQ-B07 fires
    ONLY when the ``unwrap`` (or ``unwrap_or``) launders a ``partial_cmp`` into
    an ordering-dependent SINK - the enforcement-completeness join, not the
    panic primitive.
  MQ-B07 rows are ADVISORY (verdict=needs-fuzz), never auto-credited, never
  fail-closing; they are a superset lens keyed on "comparator not a proven total
  order", so a shape-specific NaN-panic detector remains the higher-precision
  confirmer.

Fleet (mutation-verify corpus, read-only): near / base-azul.

Advisory-first contract:
  - The screen emits a row ONLY for an ordering-dependent comparator whose
    delegated comparison is NOT a proven total order (i.e. it FIRES when the
    total-order guarantee is absent, is SILENT on ``.cmp`` / ``total_cmp`` /
    ``OrderedFloat`` / ``NotNan`` comparators).
  - Every row carries ``verdict="needs-fuzz"`` and ``auto_credit=False``.  The
    process NEVER exits non-zero on findings unless ``--strict`` is explicitly
    passed (opt-in CI signal); default is advisory (exit 0).

CLI:
    python3 tools/total-order-comparator-screen.py --workspace ~/audits/near --print-json
    python3 tools/total-order-comparator-screen.py --workspace ~/audits/near   # writes sidecar
"""
from __future__ import annotations

import argparse
import json
import re
import sys
from dataclasses import asdict, dataclass, field
from pathlib import Path

try:
    from lib.project_source_roots import rust_crate_scan_roots
except ModuleNotFoundError:  # pragma: no cover
    sys.path.insert(0, str(Path(__file__).resolve().parent))
    from lib.project_source_roots import rust_crate_scan_roots


SCHEMA_VERSION = "auditooor.total_order_comparator_screen.v1"

DEFAULT_SCAN_ROOTS = (
    "src",
    "crates",
    "external/base/crates",
)

TEST_PATH_TOKENS = (
    "/tests/",
    "/test_",
    "/testing/",
    "_tests.rs",
    "/benches/",
    "/examples/",
    "/fuzz/",
    "/bench/",
    "/benchmarks/",
    # Non-production test-support / fuzzing contracts and dev/estimation tooling
    # (NOT the audited runtime): flagging these fabricates fleet FPs.
    "/near-test-contracts/",
    "/contract-for-fuzzing-rs/",
    "/runtime-params-estimator/",
    "/state-viewer/",
)

# ---------------------------------------------------------------------------
# Ordering-dependent comparator SINKS (HALF 1 of the core predicate).
#
# Closure-comparator methods: each takes a ``|a, b| -> Ordering`` closure whose
# body IS the delegated comparator.  We capture the closure region by paren
# matching from the call's opening paren.
#
# The ``_by_key`` / ``sort_by_cached_key`` variants are deliberately EXCLUDED:
# they order by the KEY's ``Ord`` and the compiler REJECTS a non-``Ord`` key
# (e.g. a bare ``f64``), so a partial order cannot silently reach them.  A key
# type WITH a hand-written ``Ord`` is instead covered by the CUSTOM-ORD sink.
# ---------------------------------------------------------------------------
CLOSURE_SINKS: tuple[tuple[str, "re.Pattern[str]"], ...] = (
    ("sort_by", re.compile(r"\.\s*sort_by\s*\(")),
    ("sort_unstable_by", re.compile(r"\.\s*sort_unstable_by\s*\(")),
    ("binary_search_by", re.compile(r"\.\s*binary_search_by\s*\(")),
    ("partition_point_by", re.compile(r"\.\s*partition_point\s*\(")),
    ("select_nth_unstable_by", re.compile(r"\.\s*select_nth_unstable_by\s*\(")),
    ("min_by", re.compile(r"\.\s*min_by\s*\(")),
    ("max_by", re.compile(r"\.\s*max_by\s*\(")),
    ("is_sorted_by", re.compile(r"\.\s*is_sorted_by\s*\(")),
)

# CUSTOM-ORD sink: a hand-written comparator body that BTreeMap / BTreeSet /
# BinaryHeap and every downstream ordered op DELEGATE to.  ``cmp`` /
# ``partial_cmp`` are the reserved trait method names, so a ``fn cmp(&self,
# other: &Self) -> Ordering`` / ``fn partial_cmp(&self, other: &Self) ->
# Option<Ordering>`` is (essentially always) the ``Ord`` / ``PartialOrd`` impl.
CUSTOM_ORD_RE = re.compile(
    r"\bfn\s+(?P<name>cmp|partial_cmp)\s*\(\s*&self\s*,"
)

# ---------------------------------------------------------------------------
# Total-order SOUNDNESS (HALF 2 of the core predicate).
# ---------------------------------------------------------------------------
# Proven-total-order guard tokens.  If ANY appears in the comparator region the
# comparison is treated as sound (float values wrapped into a total order, or
# the explicit ``f64::total_cmp`` total order).
TOTAL_ORDER_GUARD_TOKENS = (
    "total_cmp",
    "OrderedFloat",
    "ordered_float",
    "NotNan",
    "NotNaN",
    "FloatOrd",
    "float_ord",
)

# The unsound laundering shape: a ``partial_cmp(..)`` result forced into an
# ``Ordering`` via unwrap / expect / unwrap_or (a partial order laundered into a
# total-order sink).  A bare ``partial_cmp`` that RETURNS ``Option`` (the sound
# ``PartialOrd`` impl form, ``Some(self.cmp(other))``) has no such terminator
# and is NOT flagged.
_PARTIAL_CMP_RE = re.compile(r"\.\s*partial_cmp\s*\(")
_LAUNDER_TERMINATOR_RE = re.compile(
    r"\.\s*(?:unwrap|expect|unwrap_or|unwrap_or_else|unwrap_unchecked)\s*\("
)

# Comparator-region signal that a body actually performs a comparison (so a
# custom ``cmp`` that just forwards to a field ``.cmp`` is still a comparator).
_COMPARISON_SIGNAL_RE = re.compile(r"\bcmp\b|Ordering")


FN_START_RE = re.compile(
    r"\b(?:pub(?:\s*\([^)]*\))?\s+)?(?:async\s+)?(?:const\s+)?(?:unsafe\s+)?"
    r"(?:extern\s+\"[^\"]*\"\s+)?fn\s+(?P<name>[A-Za-z_][A-Za-z0-9_]*)\s*"
    r"(?:<[^>]*>)?\s*\(",
    re.DOTALL,
)


# ---------------------------------------------------------------------------
# Data model
# ---------------------------------------------------------------------------


@dataclass
class ComparatorRow:
    file: str
    line: int
    sink_kind: str          # sort_by / min_by / impl_ord_cmp / ...
    function: str           # enclosing fn (closure sink) or the cmp fn name
    comparator: str         # the delegated comparator region (trimmed)
    unsound_signal: str     # e.g. "partial_cmp().unwrap()"
    invariant: str = (
        "the delegated comparator is a proven total order (total, transitive, "
        "antisymmetric) over its whole reachable value domain"
    )
    capability: str = "MQ-B07"
    enforcement_status: str = "unproven-total-order"
    proven_total_order: bool = False
    snippet: str = ""
    verdict: str = "needs-fuzz"
    auto_credit: bool = False
    advisory: bool = True
    recommendation: str = (
        "Do not launder a partial order into an ordering-dependent sink. For "
        "float keys use f64::total_cmp / an OrderedFloat / NotNan wrapper (a "
        "proven total order), or reject NaN at the boundary before the value "
        "reaches the comparator. For a hand-written Ord, prove totality, "
        "transitivity and antisymmetry (and Ord-consistent-with-Eq)."
    )
    harness_task: str = (
        "Fuzz: steer a NaN / contradictory value into this comparator and assert "
        "(a) no panic (no unwrap on a None partial_cmp) and (b) the container "
        "invariant holds (no dropped/duplicated keys, sort stays a total order)."
    )
    not_applicable_impacts: list[str] = field(default_factory=list)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _line_for_offset(text: str, offset: int) -> int:
    return text.count("\n", 0, offset) + 1


def _safe_rel(path: Path, workspace: Path) -> str:
    try:
        return str(path.relative_to(workspace))
    except ValueError:
        return str(path)


def _strip_test_blocks(text: str) -> str:
    out_parts: list[str] = []
    i = 0
    while True:
        m = re.search(r"#\[cfg\(test\)\]\s*\n?\s*(?:pub\s+)?mod\s+\w+\s*\{", text[i:])
        if not m:
            out_parts.append(text[i:])
            break
        out_parts.append(text[i : i + m.start()])
        depth = 0
        j = i + m.end() - 1
        n = len(text)
        while j < n:
            c = text[j]
            if c == "{":
                depth += 1
            elif c == "}":
                depth -= 1
                if depth == 0:
                    j += 1
                    break
            j += 1
        i = j
    return "".join(out_parts)


def _match_paren(text: str, open_idx: int) -> tuple[str, int]:
    """Return (inner_text, close_idx) for the paren opening at ``open_idx``.

    ``text[open_idx]`` must be ``(``.  Depth-tracks nested parens so a comparator
    like ``partial_cmp(&(a.h, a.s))`` is captured whole.
    """
    assert text[open_idx] == "("
    depth = 0
    n = len(text)
    j = open_idx
    while j < n:
        c = text[j]
        if c == "(":
            depth += 1
        elif c == ")":
            depth -= 1
            if depth == 0:
                return text[open_idx + 1 : j], j
        j += 1
    return text[open_idx + 1 :], n


def _match_brace(text: str, open_idx: int) -> tuple[str, int]:
    """Return (inner_text, close_idx) for the brace opening at ``open_idx``."""
    depth = 0
    n = len(text)
    j = open_idx
    while j < n:
        c = text[j]
        if c == "{":
            depth += 1
        elif c == "}":
            depth -= 1
            if depth == 0:
                return text[open_idx + 1 : j], j
        j += 1
    return text[open_idx + 1 :], n


def _enclosing_fn_name(text: str, offset: int) -> str:
    last_name = "<module>"
    for m in FN_START_RE.finditer(text, 0, offset + 1):
        last_name = m.group("name")
    return last_name


def _snippet(text: str, offset: int) -> str:
    line_start = text.rfind("\n", 0, offset) + 1
    line_end = text.find("\n", offset)
    if line_end == -1:
        line_end = len(text)
    return text[line_start:line_end].strip()[:200]


# ---------------------------------------------------------------------------
# CORE PREDICATE
# ---------------------------------------------------------------------------


def classify_ordering_sink(text: str, start: int) -> tuple[str, str, int] | None:
    """HALF 1: is the token at ``start`` an ordering-dependent comparator sink?

    Returns (sink_kind, comparator_region, region_start_offset) or ``None``.
    For a closure sink the region is the closure argument (paren-matched); for a
    custom-Ord sink the region is the fn body (brace-matched).  Neutralizing this
    predicate (return ``None`` for everything) must make every positive row
    disappear - see the non-vacuity test.
    """
    for kind, pat in CLOSURE_SINKS:
        m = pat.match(text, start)
        if m:
            open_idx = m.end() - 1  # the '(' consumed by the pattern
            region, _close = _match_paren(text, open_idx)
            return kind, region, open_idx + 1
    m = CUSTOM_ORD_RE.match(text, start)
    if m:
        brace = text.find("{", m.end())
        if brace == -1:
            return None
        region, _close = _match_brace(text, brace)
        name = m.group("name")
        return f"impl_{name}", region, brace + 1
    return None


def is_total_order_sound(comparator: str) -> bool:
    """HALF 2: is the delegated comparison a PROVEN total order?

    Sound when it either uses a proven total-order construct (``total_cmp`` /
    an ``OrderedFloat`` / ``NotNan`` wrapper) OR never launders a partial order
    (no ``partial_cmp(..).unwrap()/.expect()/.unwrap_or()``).  A row is emitted
    ONLY when a sink is found AND this returns ``False``.  Neutralizing this
    predicate (return ``True`` for everything) must silence every positive row -
    see the non-vacuity test.
    """
    return _unsound_signal(comparator) is None


def _unsound_signal(comparator: str) -> str | None:
    """Return the laundered-partial-order signal, or ``None`` if sound."""
    # A proven total-order construct dominates: float wrapped into a total order.
    if any(tok in comparator for tok in TOTAL_ORDER_GUARD_TOKENS):
        return None
    # A partial_cmp result forced into an Ordering via unwrap/expect/unwrap_or.
    for pm in _PARTIAL_CMP_RE.finditer(comparator):
        open_idx = comparator.find("(", pm.end() - 1)
        if open_idx == -1:
            continue
        _inner, close_idx = _match_paren(comparator, open_idx)
        tail = comparator[close_idx + 1 : close_idx + 1 + 80]
        tm = _LAUNDER_TERMINATOR_RE.search(tail)
        if tm:
            term = tm.group(0).strip().lstrip(".").rstrip("(").strip()
            return f"partial_cmp().{term}()"
    return None


# ---------------------------------------------------------------------------
# Per-file scanning
# ---------------------------------------------------------------------------


def scan_text(text: str, rel: str) -> list[ComparatorRow]:
    cleaned = _strip_test_blocks(text)
    rows: list[ComparatorRow] = []
    seen: set[tuple[int, str]] = set()

    # Build the union of sink start positions by scanning for each opener.
    sink_starts: list[int] = []
    for _kind, pat in CLOSURE_SINKS:
        for m in pat.finditer(cleaned):
            sink_starts.append(m.start())
    for m in CUSTOM_ORD_RE.finditer(cleaned):
        sink_starts.append(m.start())
    sink_starts.sort()

    for start in sink_starts:
        classified = classify_ordering_sink(cleaned, start)
        if classified is None:
            continue
        sink_kind, region, region_start = classified

        # Only a comparator that actually performs a comparison is in scope
        # (a custom cmp body that forwards `.cmp` still qualifies).
        if not _COMPARISON_SIGNAL_RE.search(region) and "partial_cmp" not in region:
            continue

        if is_total_order_sound(region):
            continue  # SILENT on proven total-order comparators.

        signal = _unsound_signal(region) or "unproven-total-order"
        line = _line_for_offset(cleaned, start)
        key = (line, sink_kind)
        if key in seen:
            continue
        seen.add(key)

        if sink_kind.startswith("impl_"):
            fn_name = sink_kind.split("_", 1)[1]
        else:
            fn_name = _enclosing_fn_name(cleaned, start)

        rows.append(
            ComparatorRow(
                file=rel,
                line=line,
                sink_kind=sink_kind,
                function=fn_name,
                comparator=region.strip()[:240],
                unsound_signal=signal,
                snippet=_snippet(cleaned, start),
            )
        )
    return rows


def scan_file(file_path: Path, workspace: Path) -> list[ComparatorRow]:
    try:
        text = file_path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return []
    return scan_text(text, _safe_rel(file_path, workspace))


# ---------------------------------------------------------------------------
# File enumeration
# ---------------------------------------------------------------------------


def enumerate_files(workspace: Path, extra_roots: list[str]) -> list[Path]:
    seen: set[Path] = set()
    out: list[Path] = []
    roots = rust_crate_scan_roots(workspace, DEFAULT_SCAN_ROOTS) + list(extra_roots)
    if not roots:
        roots = ["."]
    for rel in roots:
        root = (workspace / rel).resolve()
        if not root.is_dir():
            continue
        for path in sorted(root.rglob("*.rs")):
            spath = str(path)
            if any(tok in spath for tok in TEST_PATH_TOKENS):
                continue
            if path.name.endswith("_test.rs") or path.name.endswith("_tests.rs"):
                continue
            # A module's sibling test file (`#[cfg(test)] mod tests;` -> tests.rs)
            # is not audited runtime.
            if path.name in ("tests.rs", "test.rs"):
                continue
            if path in seen:
                continue
            seen.add(path)
            out.append(path)
    return out


def _count_by(rows: list[ComparatorRow], key) -> dict[str, int]:
    out: dict[str, int] = {}
    for r in rows:
        k = key(r)
        out[k] = out.get(k, 0) + 1
    return out


def run(workspace: Path, extra_roots: list[str]) -> list[ComparatorRow]:
    files = enumerate_files(workspace, extra_roots)
    rows: list[ComparatorRow] = []
    for f in files:
        rows.extend(scan_file(f, workspace))
    rows.sort(key=lambda r: (r.file, r.line, r.sink_kind))
    return rows


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="total-order-comparator-screen.py",
        description=(
            "MQ-B07 - GENERAL total-order comparator soundness screen. "
            "Advisory-first: flags ordering-dependent comparators (sort_by / "
            "binary_search_by / min_by / max_by / custom Ord|PartialOrd that "
            "BTreeMap|BinaryHeap delegate to) whose delegated comparison is NOT "
            "a proven total order - a partial order laundered via "
            "partial_cmp().unwrap()/.expect()/.unwrap_or() (verdict=needs-fuzz)."
        ),
    )
    parser.add_argument("--workspace", required=True, type=Path)
    parser.add_argument(
        "--root",
        action="append",
        default=[],
        help="Extra workspace-relative path to walk. May be repeated.",
    )
    parser.add_argument(
        "--print-json",
        action="store_true",
        help="Print the JSON payload to stdout instead of writing the sidecar.",
    )
    parser.add_argument(
        "--strict",
        action="store_true",
        help=(
            "OPT-IN CI signal: exit 1 when any advisory row is emitted. Default "
            "is advisory-first (exit 0 regardless of rows)."
        ),
    )
    args = parser.parse_args(argv)

    workspace: Path = args.workspace
    if not workspace.is_dir():
        print(
            f"[total-order-comparator-screen] ERR workspace not a directory: {workspace}",
            file=sys.stderr,
        )
        return 2

    rows = run(workspace, list(args.root))

    payload = {
        "schema": SCHEMA_VERSION,
        "capability": "MQ-B07",
        "workspace": str(workspace),
        "advisory_first": True,
        "verdict_all": "needs-fuzz",
        "row_count": len(rows),
        "sink_kind_counts": _count_by(rows, lambda r: r.sink_kind),
        "signal_counts": _count_by(rows, lambda r: r.unsound_signal),
        "rows": [asdict(r) for r in rows],
    }

    # Advisory sidecar for the hunt corpus: JSONL, one needs-fuzz / no-auto-credit
    # row per hypothesis, under <ws>/.auditooor/ so the pipeline consumer can
    # ingest it (mkdir the parent first).
    _sidecar_dir = workspace / ".auditooor"
    _sidecar_dir.mkdir(parents=True, exist_ok=True)
    _sidecar_path = _sidecar_dir / "total_order_comparator_hypotheses.jsonl"
    with open(_sidecar_path, "w", encoding="utf-8") as _sf:
        for _r in rows:
            _sf.write(
                json.dumps(
                    {
                        **asdict(_r),
                        "capability": "MQ-B07",
                        "verdict": "needs-fuzz",
                        "advisory": True,
                        "auto_credit": False,
                    }
                )
                + "\n"
            )

    if args.print_json:
        sys.stdout.write(json.dumps(payload, indent=2, sort_keys=True) + "\n")
    else:
        out_dir = workspace / "critical_hunt" / "total_order_comparator"
        out_dir.mkdir(parents=True, exist_ok=True)
        json_path = out_dir / "total_order_comparator_screen.json"
        json_path.write_text(
            json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8"
        )
        print(
            f"[total-order-comparator-screen] wrote {json_path.relative_to(workspace)} "
            f"({len(rows)} advisory row(s)); sidecar "
            f"{_sidecar_path.relative_to(workspace)}",
            file=sys.stderr,
        )

    # Advisory-first: default NEVER fail-closes. --strict is an opt-in signal.
    if args.strict and rows:
        print(
            f"[total-order-comparator-screen] STRICT: {len(rows)} advisory row(s)",
            file=sys.stderr,
        )
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
