#!/usr/bin/env python3
"""
fixture-duplicate-detector.py — flag near-duplicate fixtures (Phase 25, PR #84).

Companion to tools/detector-dedupe.py. While that tool scores DETECTOR source-code
similarity, this one scores the regression-evidence FIXTURES under patterns/fixtures/
so we can spot copy-pasted .sol files where only a line or two was tweaked. High
fixture similarity is a signal that the backing detectors may also be redundant.

Method:
    - Glob patterns/fixtures/*.sol (skip files <100 bytes as too-thin to compare).
    - Normalize each: drop `// ...` and `/* ... */` comments, drop `pragma`/`import`/
      SPDX header lines, collapse whitespace. Preserve function names, state-variable
      names, contract/interface/library/struct/event names (these carry the "what is
      this fixture about" signal). Anonymize ONLY local variables and parameter names
      (`uint256 foo` inside a function body -> `T X`).
    - Tokenize, build unigram+bigram set, pairwise Jaccard (|A n B| / |A u B|).
    - Skip `_vuln.sol` vs `_clean.sol` pairs sharing the same detector stem
      (those SHOULD be similar — they back the same detector).
    - Apply `--min-tokens` gate (default 30): fixtures with < N distinct tokens
      are trivial boilerplate and excluded from comparison.
    - Flag pairs >= `--threshold` (default 0.95) and emit the report.

Advisory only — always exits 0. Use `make fixture-dupe`.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
FIX_DIR = ROOT / "patterns" / "fixtures"
REPORT = ROOT / "docs" / "FIXTURE_DUPLICATE_REPORT.md"

DEFAULT_THRESHOLD = 0.95
DEFAULT_MIN_TOKENS = 30
MIN_BYTES = 100
TOP_N = 30

# Item #11 burn-down (PR: warn/fail thresholds + machine-readable manifest):
# Below warn  -> PASS. At/above warn but below fail -> WARN. At/above fail -> FAIL.
# Defaults are intentionally conservative: a few flagged pairs do not warrant a
# WARN, but >= 50 starts to feel like systemic copy-paste, and >= 200 is "stop
# adding fixtures, refactor first".
DEFAULT_THRESHOLD_WARN = 50
DEFAULT_THRESHOLD_FAIL = 200

# Operator-opt-in env var for the prune (deletion-plan only) flow. The script
# never deletes fixtures; even with --prune we only emit a JSON deletion plan
# the operator can act on manually.
PRUNE_OPTIN_ENV = "AUDITOOOR_FIXTURE_PRUNE_OPTIN"

# Status sentinels mirror tools/audit-closeout-check.py vocabulary.
STATUS_PASS = "PASS"
STATUS_WARN = "WARN"
STATUS_FAIL = "FAIL"

# Solidity value types / common types — normalized to the sentinel token `T`.
_TYPE_WORDS = {
    "address", "bool", "bytes", "string",
    "uint", "uint8", "uint16", "uint32", "uint64", "uint128", "uint256",
    "int", "int8", "int16", "int32", "int64", "int128", "int256",
    "bytes1", "bytes2", "bytes4", "bytes8", "bytes16", "bytes20", "bytes32",
    "mapping", "memory", "calldata", "storage", "payable",
}

# Solidity keywords kept as-is (structural signal).
_KEYWORDS = {
    "contract", "interface", "library", "function", "modifier", "event",
    "constructor", "fallback", "receive", "struct", "enum", "return",
    "returns", "emit", "require", "revert", "assert", "if", "else", "for",
    "while", "do", "break", "continue", "new", "delete", "this", "super",
    "public", "external", "internal", "private", "view", "pure", "virtual",
    "override", "abstract", "immutable", "constant", "using", "is", "try",
    "catch", "assembly", "unchecked", "true", "false",
}

_COMMENT_LINE = re.compile(r"//[^\n]*")
_COMMENT_BLOCK = re.compile(r"/\*.*?\*/", re.DOTALL)
_PRAGMA_LINE = re.compile(r"^\s*pragma[^\n]*$", re.MULTILINE)
_IMPORT_LINE = re.compile(r"^\s*import[^\n]*$", re.MULTILINE)
_SPDX_LINE = re.compile(r"^\s*//\s*SPDX[^\n]*$", re.MULTILINE)
_TOKEN_RE = re.compile(r"[A-Za-z_][A-Za-z0-9_]*|[^\sA-Za-z0-9_]")

# Identifiers we preserve verbatim because they name *what the fixture is about*:
#   - Contract/interface/library/struct/enum/event names (declared at top level).
#   - Function names (declared via `function <name>(...)`).
#   - State variable names (declared at contract scope, outside any function body).
# What we anonymize: local variables and parameter names (inside `{}` function bodies).


def _collect_preserved_names(src: str) -> set[str]:
    """Extract names we want to keep un-anonymized.

    Heuristics (stdlib regex, not a real parser — good enough for our fixtures):
      - `contract|interface|library|struct|enum|event <Name>` — name kept.
      - `function <name>` — name kept.
      - State vars: top-level declarations at brace-depth 1 (inside a contract but
        outside any function body). We walk the source tracking brace depth and
        function-ness; at depth 1 outside a function, any `<type> <name>` pattern
        contributes `<name>`.
    """
    preserved: set[str] = set()

    # Top-level type declarations — always preserve the name.
    for m in re.finditer(
        r"\b(contract|interface|library|struct|enum|event)\s+([A-Za-z_][A-Za-z0-9_]*)",
        src,
    ):
        preserved.add(m.group(2))

    # Function names.
    for m in re.finditer(r"\bfunction\s+([A-Za-z_][A-Za-z0-9_]*)", src):
        preserved.add(m.group(1))

    # Modifier names.
    for m in re.finditer(r"\bmodifier\s+([A-Za-z_][A-Za-z0-9_]*)", src):
        preserved.add(m.group(1))

    # State variables: declarations at brace-depth 1 that are NOT inside a function.
    # Walk character-by-character tracking depth and whether the current depth-1
    # block is a function body. We approximate a "function body" as any block whose
    # opening `{` was preceded on the same statement by the `function` keyword.
    depth = 0
    i = 0
    n = len(src)
    # Stack of booleans — True if that scope is a function body.
    fn_stack: list[bool] = []
    # Buffer of chars since last `;` or `{` or `}` — lets us inspect "statement so far".
    stmt_start = 0
    while i < n:
        c = src[i]
        if c == "{":
            stmt = src[stmt_start:i]
            is_fn = bool(re.search(r"\bfunction\b", stmt)) or bool(
                re.search(r"\b(constructor|fallback|receive|modifier)\b", stmt)
            )
            fn_stack.append(is_fn)
            depth += 1
            stmt_start = i + 1
        elif c == "}":
            if fn_stack:
                fn_stack.pop()
            depth -= 1
            stmt_start = i + 1
        elif c == ";":
            # If we're at depth 1 (inside a contract body) and not in a function,
            # this statement is a state-variable declaration candidate.
            if depth == 1 and (not fn_stack or not fn_stack[-1] is True):
                # Actually we need the innermost scope; but since we only pushed
                # on `{`, fn_stack reflects nesting. At depth 1 there is exactly
                # 1 entry on the stack — the contract body itself (is_fn=False).
                if fn_stack and fn_stack[-1] is False:
                    stmt = src[stmt_start:i]
                    # `<type-ish> ... <name>` — grab the last identifier before `;`
                    # that isn't a keyword/type. State vars commonly look like:
                    #   `uint256 public foo = 1;` or `mapping(...) private bar;`.
                    idents = re.findall(r"[A-Za-z_][A-Za-z0-9_]*", stmt)
                    for ident in reversed(idents):
                        low = ident.lower()
                        if low in _TYPE_WORDS or low in _KEYWORDS:
                            continue
                        # Skip assignment-RHS identifiers: stop at first non-kw
                        # identifier walking from the right.
                        preserved.add(ident)
                        break
            stmt_start = i + 1
        i += 1
    return preserved


def _detector_stem(name: str) -> str:
    """Strip `_vuln.sol` / `_clean.sol` to get the shared detector stem."""
    for suf in ("_vuln.sol", "_clean.sol"):
        if name.endswith(suf):
            return name[: -len(suf)]
    return name[:-4] if name.endswith(".sol") else name


def normalize(src: str) -> list[str]:
    """Strip comments/pragma/imports, preserve semantic names, anonymize locals."""
    src = _SPDX_LINE.sub("", src)
    src = _COMMENT_BLOCK.sub("", src)
    src = _COMMENT_LINE.sub("", src)
    src = _PRAGMA_LINE.sub("", src)
    src = _IMPORT_LINE.sub("", src)

    preserved = _collect_preserved_names(src)

    out: list[str] = []
    for tok in _TOKEN_RE.findall(src):
        if tok.isspace():
            continue
        if not (tok[0].isalpha() or tok[0] == "_"):
            out.append(tok)
            continue
        low = tok.lower()
        if low in _TYPE_WORDS:
            out.append("T")
        elif low in _KEYWORDS:
            out.append(low)
        elif tok.isdigit():
            out.append("N")
        elif tok in preserved:
            # Preserve function names, contract names, state-var names verbatim.
            out.append(tok)
        else:
            # Local variable or parameter — anonymize.
            out.append("X")
    return out


def token_set(tokens: list[str]) -> set[str]:
    """Build the set used for Jaccard. Include unigrams + bigrams for shape signal."""
    unigrams = set(tokens)
    bigrams = {f"{a}|{b}" for a, b in zip(tokens, tokens[1:])}
    return unigrams | bigrams


def jaccard(a: set[str], b: set[str]) -> float:
    if not a or not b:
        return 0.0
    inter = len(a & b)
    union = len(a | b)
    return inter / union if union else 0.0


def diff_sample(src_a: str, src_b: str, limit: int = 3) -> list[str]:
    """Cheap 3-line diff: first up-to-3 lines that differ between the two files."""
    la = src_a.splitlines()
    lb = src_b.splitlines()
    out: list[str] = []
    for i in range(min(len(la), len(lb))):
        if la[i].strip() != lb[i].strip():
            out.append(f"L{i+1}: A={la[i].strip()[:80]!r} | B={lb[i].strip()[:80]!r}")
            if len(out) >= limit:
                break
    if not out and len(la) != len(lb):
        out.append(f"length diff: A={len(la)} lines, B={len(lb)} lines")
    return out


def _classify_status(
    flagged: int, *, threshold_warn: int, threshold_fail: int
) -> str:
    """Map flagged-pair count to PASS/WARN/FAIL using item #11 thresholds.

    Order matters: FAIL is checked first so a misconfiguration where
    ``threshold_fail < threshold_warn`` still produces a FAIL on the higher
    bound. ``threshold_warn <= 0`` is treated as "no warn band" so the
    default-PASS path remains reachable when an operator deliberately
    disables the warn step.
    """
    if threshold_fail > 0 and flagged >= threshold_fail:
        return STATUS_FAIL
    if threshold_warn > 0 and flagged >= threshold_warn:
        return STATUS_WARN
    return STATUS_PASS


def _group_pairs(pairs: list[tuple[float, int, int]]) -> list[set[int]]:
    """Union-find over flagged pairs to count duplicate *groups*.

    A group is a connected component in the "fixture A is a near-duplicate of
    fixture B" graph; the manifest reports both `duplicate_pairs` (edge count)
    and `duplicate_groups` (component count) so closeout downstream can
    cite "how many distinct clusters" rather than just edges.
    """
    parent: dict[int, int] = {}

    def find(x: int) -> int:
        # Path compression — the recursion depth here is bounded by the
        # number of fixtures, but we use the iterative form to be safe on
        # large fixture corpora.
        root = x
        while parent.get(root, root) != root:
            root = parent[root]
        cur = x
        while parent.get(cur, cur) != root:
            nxt = parent.get(cur, cur)
            parent[cur] = root
            cur = nxt
        return root

    def union(a: int, b: int) -> None:
        ra, rb = find(a), find(b)
        if ra != rb:
            parent[rb] = ra

    nodes: set[int] = set()
    for _score, i, j in pairs:
        parent.setdefault(i, i)
        parent.setdefault(j, j)
        nodes.add(i)
        nodes.add(j)
        union(i, j)
    groups: dict[int, set[int]] = {}
    for n in nodes:
        groups.setdefault(find(n), set()).add(n)
    return list(groups.values())


def _by_pattern_breakdown(
    entries: list[tuple[Path, str, str, set[str]]],
    pairs: list[tuple[float, int, int]],
) -> list[dict[str, object]]:
    """Per-detector-stem rollup of pair counts.

    Useful for closeout to cite the noisiest patterns rather than only a
    flat total. Sorted by descending pair-count, then stem name.
    """
    counts: dict[str, int] = {}
    for _score, i, j in pairs:
        for idx in (i, j):
            stem = entries[idx][2]
            counts[stem] = counts.get(stem, 0) + 1
    rows = [
        {"pattern_stem": stem, "pair_count": count}
        for stem, count in counts.items()
    ]
    rows.sort(key=lambda r: (-int(r["pair_count"]), str(r["pattern_stem"])))
    return rows


def _write_manifest(
    manifest_path: Path,
    *,
    total_fixtures: int,
    duplicate_pairs: int,
    duplicate_groups: int,
    by_pattern: list[dict[str, object]],
    threshold_warn: int,
    threshold_fail: int,
    status: str,
    similarity_threshold: float,
    min_tokens: int,
) -> None:
    """Emit the machine-readable manifest closeout reads.

    Schema is ``auditooor.fixture_duplicate.v1``. Closeout downstream
    matches on ``status`` (PASS/WARN/FAIL) and ``duplicate_pairs`` /
    ``duplicate_groups`` to surface a one-line summary.
    """
    manifest_path.parent.mkdir(parents=True, exist_ok=True)
    payload = {
        "schema": "auditooor.fixture_duplicate.v1",
        "total_fixtures": total_fixtures,
        "duplicate_pairs": duplicate_pairs,
        "duplicate_groups": duplicate_groups,
        "by_pattern": by_pattern,
        "threshold_warn": threshold_warn,
        "threshold_fail": threshold_fail,
        "status": status,
        "similarity_threshold": similarity_threshold,
        "min_tokens": min_tokens,
    }
    manifest_path.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")


def _emit_prune_plan(
    plan_path: Path,
    entries: list[tuple[Path, str, str, set[str]]],
    pairs: list[tuple[float, int, int]],
) -> None:
    """Emit a deletion *plan* — never deletes anything.

    Plan rule: within each connected component, keep the lexicographically
    smallest path (deterministic, reviewable) and propose deleting the rest.
    The operator must inspect this file and remove fixtures by hand. No
    code path in this script ever calls ``Path.unlink`` or ``shutil.rmtree``.
    """
    groups = _group_pairs(pairs)
    plan_groups: list[dict[str, object]] = []
    for group in groups:
        members = sorted(str(entries[idx][0]) for idx in group)
        keep = members[0] if members else None
        proposed_delete = members[1:] if len(members) > 1 else []
        plan_groups.append(
            {
                "keep": keep,
                "proposed_delete": proposed_delete,
                "size": len(members),
            }
        )
    plan = {
        "schema": "auditooor.fixture_duplicate_prune_plan.v1",
        "warning": (
            "This is a PROPOSAL ONLY. No fixtures are deleted by this tool. "
            "Review every entry, verify the kept fixture preserves coverage, "
            "and remove duplicates manually with `git rm`."
        ),
        "groups": plan_groups,
    }
    plan_path.parent.mkdir(parents=True, exist_ok=True)
    plan_path.write_text(json.dumps(plan, indent=2) + "\n", encoding="utf-8")


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="Flag near-duplicate Solidity fixtures.")
    ap.add_argument(
        "--threshold",
        type=float,
        default=DEFAULT_THRESHOLD,
        help=f"Jaccard similarity cutoff (default {DEFAULT_THRESHOLD}).",
    )
    ap.add_argument(
        "--min-tokens",
        type=int,
        default=DEFAULT_MIN_TOKENS,
        dest="min_tokens",
        help=(
            f"Skip fixtures with fewer than N distinct normalized tokens "
            f"(default {DEFAULT_MIN_TOKENS}); filters trivial boilerplate."
        ),
    )
    ap.add_argument(
        "--top",
        type=int,
        default=TOP_N,
        help=f"Show top N pairs in the report (default {TOP_N}).",
    )
    ap.add_argument(
        "--threshold-warn",
        type=int,
        default=DEFAULT_THRESHOLD_WARN,
        dest="threshold_warn",
        help=(
            "Flag count at/above which the manifest status becomes WARN "
            f"(default {DEFAULT_THRESHOLD_WARN}). Item #11 burn-down."
        ),
    )
    ap.add_argument(
        "--threshold-fail",
        type=int,
        default=DEFAULT_THRESHOLD_FAIL,
        dest="threshold_fail",
        help=(
            "Flag count at/above which the manifest status becomes FAIL "
            f"(default {DEFAULT_THRESHOLD_FAIL}). Item #11 burn-down."
        ),
    )
    ap.add_argument(
        "--workspace",
        type=Path,
        default=None,
        help=(
            "Write manifest under <workspace>/.auditooor/. Defaults to the "
            "repo root so `make fixture-dupe` produces a discoverable manifest "
            "at <repo>/.auditooor/fixture_duplicate_manifest.json."
        ),
    )
    ap.add_argument(
        "--manifest-out",
        type=Path,
        default=None,
        dest="manifest_out",
        help=(
            "Explicit manifest path (overrides --workspace). Useful for tests "
            "that pin the manifest into a temp directory."
        ),
    )
    ap.add_argument(
        "--fixtures-dir",
        type=Path,
        default=None,
        dest="fixtures_dir",
        help=(
            "Override the patterns/fixtures directory. Tests use this to "
            "scaffold a synthetic corpus under a TemporaryDirectory."
        ),
    )
    ap.add_argument(
        "--report-out",
        type=Path,
        default=None,
        dest="report_out",
        help=(
            "Explicit Markdown report path (overrides the default "
            "docs/FIXTURE_DUPLICATE_REPORT.md). Hermetic tests use this."
        ),
    )
    ap.add_argument(
        "--prune",
        action="store_true",
        help=(
            "Emit a JSON deletion PLAN (never deletes). Requires the "
            f"{PRUNE_OPTIN_ENV}=1 environment variable as an opt-in: "
            "high-impact, operator-only."
        ),
    )
    ap.add_argument(
        "--prune-plan-out",
        type=Path,
        default=None,
        dest="prune_plan_out",
        help=(
            "Path for the prune deletion plan (defaults to "
            "<workspace>/.auditooor/fixture_duplicate_prune_plan.json)."
        ),
    )
    args = ap.parse_args(argv)

    threshold = args.threshold
    min_tokens = args.min_tokens
    top_n = args.top
    threshold_warn = args.threshold_warn
    threshold_fail = args.threshold_fail

    fix_dir = args.fixtures_dir.resolve() if args.fixtures_dir else FIX_DIR
    report_path = args.report_out.resolve() if args.report_out else REPORT
    workspace = (args.workspace.resolve() if args.workspace else ROOT)

    if args.manifest_out is not None:
        manifest_path = args.manifest_out.resolve()
    else:
        manifest_path = workspace / ".auditooor" / "fixture_duplicate_manifest.json"

    if args.prune and os.environ.get(PRUNE_OPTIN_ENV) != "1":
        print(
            f"[fixture-dupe] --prune refused: set {PRUNE_OPTIN_ENV}=1 to opt in. "
            f"Even then this only emits a deletion PLAN; no files are deleted.",
            file=sys.stderr,
        )
        return 2

    files = sorted(p for p in fix_dir.glob("*.sol") if p.is_file())
    entries: list[tuple[Path, str, str, set[str]]] = []
    skipped_small = 0
    skipped_thin = 0
    for p in files:
        try:
            raw = p.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        if len(raw) < MIN_BYTES:
            skipped_small += 1
            continue
        toks = normalize(raw)
        tset = token_set(toks)
        # Distinct-token gate: count unigrams only (bigrams are derived).
        distinct = len(set(toks))
        if distinct < min_tokens:
            skipped_thin += 1
            continue
        entries.append((p, raw, _detector_stem(p.name), tset))

    print(
        f"[fixture-dupe] scanning {len(entries)} fixtures "
        f"(>= {MIN_BYTES}B, >= {min_tokens} distinct tokens; "
        f"skipped {skipped_small} small, {skipped_thin} thin) ...",
        file=sys.stderr,
    )

    pairs: list[tuple[float, int, int]] = []
    for i in range(len(entries)):
        _, _raw_i, stem_i, set_i = entries[i]
        for j in range(i + 1, len(entries)):
            _, _raw_j, stem_j, set_j = entries[j]
            if stem_i == stem_j:
                continue
            score = jaccard(set_i, set_j)
            if score >= threshold:
                pairs.append((score, i, j))

    pairs.sort(key=lambda t: -t[0])
    flagged = len(pairs)
    top = pairs[:top_n]
    groups = _group_pairs(pairs)
    by_pattern = _by_pattern_breakdown(entries, pairs)
    status = _classify_status(
        flagged, threshold_warn=threshold_warn, threshold_fail=threshold_fail
    )

    lines: list[str] = []
    lines.append("# Fixture Duplicate Report")
    lines.append("")
    lines.append(
        f"Scanned: **{len(entries)}** fixtures "
        f"(>= {MIN_BYTES} bytes, >= {min_tokens} distinct tokens) "
        f"from `patterns/fixtures/`."
    )
    lines.append(
        f"Threshold: Jaccard >= **{threshold}** on normalized token sets "
        f"(unigrams + bigrams). Identifiers are anonymized EXCEPT function names, "
        f"contract/struct/event names, and state-variable names — those carry the "
        f"semantic signal for what the fixture is about."
    )
    lines.append(
        f"Flagged pairs: **{flagged}** ({len(groups)} duplicate group(s)). "
        f"Showing top {len(top)}."
    )
    lines.append(
        f"Burn-down status (item #11): **{status}** "
        f"[warn at >= {threshold_warn}, fail at >= {threshold_fail}]"
    )
    lines.append("")
    lines.append(
        "Pairs of `_vuln.sol` vs `_clean.sol` sharing the same detector stem "
        "are skipped (expected to be similar)."
    )
    lines.append("")
    if flagged > 100:
        lines.append(
            "> **ADVISORY — wholesale fixture refactoring needed.** The flagged "
            "count is high enough that targeted merges will not be cost-effective; "
            "treat this as a signal to rebuild fixtures from a small set of "
            "canonical templates rather than hand-merging pairs."
        )
        lines.append("")
    if not top:
        lines.append("_No pairs above threshold. Fixtures look distinct._")
    for rank, (score, i, j) in enumerate(top, 1):
        pi = entries[i][0]
        pj = entries[j][0]
        src_i = entries[i][1]
        src_j = entries[j][1]
        stem_i = entries[i][2]
        stem_j = entries[j][2]
        same_side = pi.name.split("_")[-1] == pj.name.split("_")[-1]
        lines.append(f"## {rank}. `{pi.name}` <-> `{pj.name}`  —  score {score:.3f}")
        lines.append("")
        lines.append(f"- Detector stems: `{stem_i}` vs `{stem_j}`")
        lines.append(f"- Same side (both vuln or both clean): {same_side}")
        lines.append("- Diff sample (first differing lines, trimmed):")
        ds = diff_sample(src_i, src_j)
        if not ds:
            lines.append("  - (files are effectively identical)")
        else:
            for d in ds:
                lines.append(f"  - {d}")
        if score >= 0.98:
            rec = "**MERGE** — effectively identical; delete one and re-point its detector."
        elif score >= 0.95:
            rec = "**REVIEW/MERGE** — very high overlap even after preserving function names; likely copy-paste."
        else:
            rec = "**REVIEW** — similar shape; verify backing detectors test distinct bugs."
        lines.append(f"- Remediation: {rec}")
        lines.append("")

    report_path.parent.mkdir(parents=True, exist_ok=True)
    report_path.write_text("\n".join(lines) + "\n", encoding="utf-8")

    _write_manifest(
        manifest_path,
        total_fixtures=len(entries),
        duplicate_pairs=flagged,
        duplicate_groups=len(groups),
        by_pattern=by_pattern,
        threshold_warn=threshold_warn,
        threshold_fail=threshold_fail,
        status=status,
        similarity_threshold=threshold,
        min_tokens=min_tokens,
    )

    if args.prune:
        # Already gated above on PRUNE_OPTIN_ENV. We never delete here.
        plan_path = (
            args.prune_plan_out.resolve()
            if args.prune_plan_out
            else workspace / ".auditooor" / "fixture_duplicate_prune_plan.json"
        )
        _emit_prune_plan(plan_path, entries, pairs)
        print(
            f"[fixture-dupe] PRUNE PLAN ONLY (no deletions performed): "
            f"wrote deletion proposal to {plan_path}",
            file=sys.stderr,
        )

    try:
        rel_report = report_path.relative_to(ROOT)
    except ValueError:
        rel_report = report_path
    print(
        f"[fixture-dupe] wrote {rel_report} "
        f"({flagged} flagged at >= {threshold}, top {len(top)} shown); "
        f"manifest -> {manifest_path} (status={status})",
        file=sys.stderr,
    )
    # Advisory exit per the script's original contract: never fail the
    # process on threshold breach. Closeout reads the manifest and surfaces
    # WARN/FAIL through the close-out gate. Returning non-zero here would
    # break `make fixture-dupe` for legacy callers.
    return 0


if __name__ == "__main__":
    sys.exit(main())
