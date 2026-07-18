#!/usr/bin/env python3
"""Mine changelog/source drift in Solidity workspaces.

This is a heuristic miner for a narrow audit workflow:

1. discover changelog-like markdown files,
2. extract claims about changed/removed behavior or assumptions,
3. derive likely Solidity primitives from those claims, and
4. scan current Solidity functions for consumers that still look like they
   rely on the old primitive/assumption.

The miner is intentionally stdlib-only and advisory. It does not compile or
fully parse Solidity; it emits review targets.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable


SCHEMA = "auditooor.changelog_source_drift_miner.v1"
VERDICT_SAFE = "safe"
VERDICT_UPDATED = "consumer-updated"
VERDICT_EXPOSED = "consumer-NOT-updated-EXPOSED"
VERDICT_UNPARSEABLE = "unparseable"
VERDICTS = {VERDICT_SAFE, VERDICT_UPDATED, VERDICT_EXPOSED, VERDICT_UNPARSEABLE}

CLAIM_KEYWORDS = (
    "removed",
    "changed",
    "now",
    "instead of",
    "previously",
    "ordering",
    "behavior",
    "invariant",
    "assumption",
    "replaced",
    "deprecated",
)

ASSUMPTION_TERMS = (
    "ordering",
    "order",
    "sorted",
    "tail",
    "last",
    "first",
    "previously",
    "instead",
    "assumption",
    "invariant",
    "behavior",
    "icr",
    "nicr",
    "collateral",
    "principal",
    "interest",
)

UPDATED_MARKERS = (
    "for (",
    "while (",
    ".getprev(",
    ".getnext(",
    "getprev(",
    "getnext(",
    "scan",
    "iterate",
    "iterator",
    "newordering",
    "new_ordering",
    "doesnotassume",
    "donotassume",
    "no longer assumes",
    "no-longer-assumes",
)

SOURCE_SKIP_DIRS = {
    ".git",
    ".hg",
    ".svn",
    "node_modules",
    "artifacts",
    "cache",
    "out",
    "broadcast",
    # Vendored dependency + build trees. Foundry installs deps under lib/ (and
    # hardhat under node_modules/); these are NOT the project's own source and
    # scanning them descends into thousands of .sol files (the unbounded-rglob
    # hang). changelog-source-drift compares the project's OWN changelog claims
    # against its OWN source, so vendored code is out of scope here.
    "lib",
    "dependencies",
    "vendor",
    "target",
    "build",
    "dist",
    "coverage",
}

# Defensive upper bound on how many .sol files this advisory miner will scan,
# so a pathological monorepo cannot hang the pipeline even after dir-pruning.
# Override via env (0/empty = no cap).
_DEFAULT_MAX_SOL_FILES = 6000
CHANGELOG_SKIP_DIRS = {
    ".git",
    ".next",
    "__pycache__",
    "artifacts",
    "build",
    "cache",
    "coverage",
    "dist",
    "node_modules",
    "out",
    "target",
    "vendor",
}

_LINE_COMMENT_RE = re.compile(r"//[^\n]*")
_BLOCK_COMMENT_RE = re.compile(r"/\*.*?\*/", re.DOTALL)
_FUNCTION_RE = re.compile(
    r"\bfunction\s+(?P<name>[A-Za-z_][A-Za-z0-9_]*)\s*"
    r"\((?P<params>[^)]*)\)\s*(?P<mods>[^;{]*)\{",
    re.MULTILINE,
)
_CONTRACT_RE = re.compile(
    r"\b(?:abstract\s+contract|contract|library|interface)\s+"
    r"(?P<name>[A-Za-z_][A-Za-z0-9_]*)\b",
    re.MULTILINE,
)
_IDENT_RE = re.compile(r"\b[A-Za-z_][A-Za-z0-9_]*\b")
_DOT_REF_RE = re.compile(
    r"\b[A-Z][A-Za-z0-9_]*\s*\.\s*[A-Za-z_][A-Za-z0-9_]*\b"
)
_CALLISH_RE = re.compile(r"\b[A-Za-z_][A-Za-z0-9_]*\s*\(\)")
_CODE_SPAN_RE = re.compile(r"`([^`]+)`")


@dataclass(frozen=True)
class SolidityFunction:
    file_path: Path
    relative_path: str
    line: int
    contract: str | None
    name: str
    signature: str
    body: str
    source: str


def _is_under_skip_dir(path: Path) -> bool:
    return any(part in SOURCE_SKIP_DIRS or part.startswith(".") for part in path.parts)


def _rel(path: Path, workspace: Path) -> str:
    try:
        return path.relative_to(workspace).as_posix()
    except ValueError:
        return path.as_posix()


def _clean_markdown_line(line: str) -> str:
    line = line.strip()
    line = re.sub(r"^\s{0,3}(?:[-*+]|\d+[.)])\s+", "", line)
    line = re.sub(r"^\s{0,6}#{1,6}\s*", "", line)
    return line.strip()


def _has_claim_keyword(text: str) -> list[str]:
    lower = text.lower()
    return [kw for kw in CLAIM_KEYWORDS if kw in lower]


def _is_changelog_filename(name: str) -> bool:
    lower_name = name.lower()
    return (
        lower_name == "changelog.md"
        or re.fullmatch(r"changelog-[a-z0-9_.-]+\.md", lower_name) is not None
        or lower_name in {"migration.md", "breaking.md", "releases.md"}
    )


def discover_changelog_files(workspace: Path, skip_dirs: set[str] | None = CHANGELOG_SKIP_DIRS) -> list[Path]:
    """Return changelog-like markdown files in deterministic order."""
    found: list[Path] = []
    normalized_skip_dirs = {entry.lower() for entry in skip_dirs} if skip_dirs is not None else set()
    for root, dirs, files in os.walk(workspace):
        if skip_dirs is not None:
            dirs[:] = [dirname for dirname in dirs if dirname.lower() not in normalized_skip_dirs]
        root_path = Path(root)
        for filename in files:
            if _is_changelog_filename(filename):
                found.append(root_path / filename)
    return sorted(found, key=lambda p: _rel(p, workspace).lower())


def _candidate_primitives_from_text(text: str) -> list[str]:
    primitives: set[str] = set()
    stop = {
        "The",
        "This",
        "That",
        "Now",
        "Previously",
        "Instead",
        "Removed",
        "Changed",
        "Deprecated",
        "Migration",
        "Release",
        "Breaking",
    }

    for span in _CODE_SPAN_RE.findall(text):
        cleaned = span.strip().strip(".,;:")
        if cleaned:
            primitives.add(cleaned)

    for m in _DOT_REF_RE.finditer(text):
        primitives.add(re.sub(r"\s+", "", m.group(0)))

    for m in _CALLISH_RE.finditer(text):
        primitives.add(m.group(0).replace(" ", "").rstrip("()"))

    for token in _IDENT_RE.findall(text):
        if token in stop:
            continue
        if token.isupper() and len(token) >= 3:
            primitives.add(token)
        elif re.match(r"^(?:I?[A-Z][A-Za-z0-9]*|[a-z]+[A-Z][A-Za-z0-9]*)$", token):
            primitives.add(token)

    return sorted(primitives, key=lambda s: (s.lower(), s))


def _assumption_terms_from_text(text: str) -> list[str]:
    lower = text.lower()
    return sorted({term for term in ASSUMPTION_TERMS if term in lower})


def extract_claims(workspace: Path, changelog_files: Iterable[Path], limit: int | None = None) -> list[dict[str, Any]]:
    claims: list[dict[str, Any]] = []
    for path in changelog_files:
        try:
            lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
        except OSError:
            continue
        for line_no, raw_line in enumerate(lines, start=1):
            text = _clean_markdown_line(raw_line)
            if not text:
                continue
            keywords = _has_claim_keyword(text)
            if not keywords:
                continue
            claim_no = len(claims) + 1
            claims.append(
                {
                    "claim_id": f"claim-{claim_no:04d}",
                    "source_path": _rel(path, workspace),
                    "line": line_no,
                    "text": text,
                    "keywords": keywords,
                    "primitives": _candidate_primitives_from_text(text),
                    "assumption_terms": _assumption_terms_from_text(text),
                }
            )
            if limit is not None and len(claims) >= limit:
                return claims
    return claims


def _strip_comments(src: str) -> str:
    src = _BLOCK_COMMENT_RE.sub("", src)
    src = _LINE_COMMENT_RE.sub("", src)
    return src


def discover_solidity_files(
    workspace: Path, max_files: int | None = None
) -> tuple[list[Path], bool]:
    """Discover the workspace's own .sol files.

    Uses os.walk with in-place dir pruning so vendored/build trees (lib/,
    node_modules/, target/, hidden dirs, ...) are never descended into - the
    previous rglob("*.sol") implementation walked the ENTIRE tree (incl. the
    thousands of foundry lib/ deps) and only filtered afterwards, which hung the
    pipeline on large workspaces. Returns (files, truncated)."""
    if max_files is None:
        raw = os.environ.get("AUDITOOOR_DRIFT_MAX_SOL_FILES")
        if raw is not None and raw.strip():
            try:
                parsed = int(raw.strip())
                max_files = parsed if parsed > 0 else None
            except ValueError:
                max_files = _DEFAULT_MAX_SOL_FILES
        else:
            max_files = _DEFAULT_MAX_SOL_FILES
    normalized_skip = {entry.lower() for entry in SOURCE_SKIP_DIRS}
    files: list[Path] = []
    truncated = False
    for root, dirs, names in os.walk(workspace):
        dirs[:] = [
            d for d in dirs
            if d.lower() not in normalized_skip and not d.startswith(".")
        ]
        root_path = Path(root)
        for name in names:
            if name.endswith(".sol"):
                files.append(root_path / name)
                if max_files is not None and len(files) >= max_files:
                    truncated = True
                    break
        if truncated:
            break
    return sorted(files, key=lambda p: _rel(p, workspace).lower()), truncated


def _find_matching_brace(src: str, opening: int) -> int | None:
    depth = 0
    i = opening
    in_string: str | None = None
    escaped = False
    while i < len(src):
        ch = src[i]
        if in_string:
            if escaped:
                escaped = False
            elif ch == "\\":
                escaped = True
            elif ch == in_string:
                in_string = None
        else:
            if ch in {"'", '"'}:
                in_string = ch
            elif ch == "{":
                depth += 1
            elif ch == "}":
                depth -= 1
                if depth == 0:
                    return i
        i += 1
    return None


def _contract_at(src: str, offset: int) -> str | None:
    current: str | None = None
    for match in _CONTRACT_RE.finditer(src, 0, offset):
        current = match.group("name")
    return current


def parse_solidity_functions(workspace: Path, sol_files: Iterable[Path]) -> tuple[list[SolidityFunction], list[dict[str, str]]]:
    functions: list[SolidityFunction] = []
    errors: list[dict[str, str]] = []
    for path in sol_files:
        try:
            raw = path.read_text(encoding="utf-8", errors="replace")
        except OSError as exc:
            errors.append({"path": _rel(path, workspace), "error": str(exc)})
            continue
        src = _strip_comments(raw)
        for match in _FUNCTION_RE.finditer(src):
            opening = match.end() - 1
            closing = _find_matching_brace(src, opening)
            if closing is None:
                errors.append(
                    {
                        "path": _rel(path, workspace),
                        "error": f"unbalanced function body at line {src.count(chr(10), 0, match.start()) + 1}",
                    }
                )
                continue
            line = src.count("\n", 0, match.start()) + 1
            header = src[match.start() : opening].strip()
            functions.append(
                SolidityFunction(
                    file_path=path,
                    relative_path=_rel(path, workspace),
                    line=line,
                    contract=_contract_at(src, match.start()),
                    name=match.group("name"),
                    signature=header,
                    body=src[opening : closing + 1],
                    source=src[match.start() : closing + 1],
                )
            )
    return functions, errors


def _primitive_variants(primitive: str) -> set[str]:
    primitive = primitive.strip().strip("`").strip(".,;:")
    if not primitive:
        return set()
    variants = {primitive, primitive.replace(".", ""), primitive.split(".")[-1]}
    if primitive.startswith("I") and len(primitive) > 1 and primitive[1].isupper():
        variants.add(primitive[1:])
    compact = re.sub(r"[^A-Za-z0-9_]", "", primitive)
    if compact:
        variants.add(compact)
        variants.add(compact[:1].lower() + compact[1:])
        variants.add(compact.lower())
    return {v for v in variants if len(v) >= 3}


def _normalise_for_marker(src: str) -> str:
    return re.sub(r"[\s_]+", "", src.lower())


def _matches_primitive(function: SolidityFunction, primitives: list[str]) -> list[str]:
    haystack = function.source.lower()
    matched: list[str] = []
    for primitive in primitives:
        variants = _primitive_variants(primitive)
        if any(variant.lower() in haystack for variant in variants):
            matched.append(primitive)
    return sorted(set(matched), key=lambda s: (s.lower(), s))


def _matched_assumption_terms(function: SolidityFunction, claim: dict[str, Any]) -> list[str]:
    haystack = function.source.lower()
    terms = set(claim.get("assumption_terms") or [])
    if "ordering" in terms:
        terms.update({"tail", "last", "sorted", "icr", "nicr"})
    matched = {term for term in terms if term and term.lower() in haystack}
    return sorted(matched)


def _looks_updated(function: SolidityFunction) -> bool:
    lower = function.source.lower()
    compact = _normalise_for_marker(function.source)
    if any(marker in lower for marker in UPDATED_MARKERS):
        return True
    return any(marker in compact for marker in UPDATED_MARKERS)


def _looks_exposed(function: SolidityFunction, claim: dict[str, Any], matched_terms: list[str]) -> bool:
    lower = function.source.lower()
    claim_terms = set(claim.get("assumption_terms") or [])
    old_order_claim = bool(claim_terms & {"ordering", "order", "sorted", "tail", "last", "icr", "nicr"})
    old_tail_consumer = any(term in lower for term in ("getlast", ".getlast", "last", "tail"))
    collateral_gate = any(
        term in lower
        for term in ("icr", "nicr", "collateral", "undercollateral", "under-collateral", "cr")
    )
    hard_gate = any(term in lower for term in ("require", "revert", "assert", "_require", "check"))
    if old_order_claim and old_tail_consumer and collateral_gate:
        return True
    if matched_terms and hard_gate and old_tail_consumer:
        return True
    return False


def _snippet(source: str) -> str:
    lines = [line.strip() for line in source.splitlines() if line.strip()]
    return " ".join(lines[:4])[:320]


def _score_call_site(
    function: SolidityFunction,
    matched_primitives: list[str],
    matched_terms: list[str],
    exposed: bool,
    updated: bool,
) -> int:
    score = 10 * len(matched_primitives) + 6 * len(matched_terms)
    lower = function.source.lower()
    if exposed:
        score += 60
    if updated:
        score -= 30
    if "getlast" in lower or ".getlast" in lower:
        score += 25
    if "require" in lower or function.name.lower().startswith("_require"):
        score += 10
    if "undercollateral" in lower:
        score += 12
    if "icr" in lower or "nicr" in lower:
        score += 8
    return max(score, 0)


def analyse_claims(
    workspace: Path,
    claims: list[dict[str, Any]],
    functions: list[SolidityFunction],
    parse_errors: list[dict[str, str]],
    call_site_limit: int | None = None,
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    verdicts: list[dict[str, Any]] = []
    call_sites: list[dict[str, Any]] = []

    for claim in claims:
        primitives = claim.get("primitives") or []
        if parse_errors and not functions:
            verdicts.append(
                {
                    "claim_id": claim["claim_id"],
                    "verdict": VERDICT_UNPARSEABLE,
                    "reason": "solidity source could not be parsed",
                    "consumer_count": 0,
                    "exposed_call_site_ids": [],
                }
            )
            continue
        if not primitives:
            verdicts.append(
                {
                    "claim_id": claim["claim_id"],
                    "verdict": VERDICT_UNPARSEABLE,
                    "reason": "no Solidity-like primitive found in claim",
                    "consumer_count": 0,
                    "exposed_call_site_ids": [],
                }
            )
            continue

        claim_call_sites: list[dict[str, Any]] = []
        for function in functions:
            matched_primitives = _matches_primitive(function, primitives)
            if not matched_primitives:
                continue
            matched_terms = _matched_assumption_terms(function, claim)
            updated = _looks_updated(function)
            exposed = not updated and _looks_exposed(function, claim, matched_terms)
            if not exposed and not updated and not matched_terms:
                continue
            verdict = VERDICT_EXPOSED if exposed else VERDICT_UPDATED if updated else VERDICT_SAFE
            call_site_id = f"{claim['claim_id']}:{len(claim_call_sites) + 1:03d}"
            claim_call_sites.append(
                {
                    "call_site_id": call_site_id,
                    "claim_id": claim["claim_id"],
                    "verdict": verdict,
                    "score": _score_call_site(function, matched_primitives, matched_terms, exposed, updated),
                    "file_path": function.relative_path,
                    "line": function.line,
                    "contract": function.contract,
                    "function": function.name,
                    "signature": function.signature,
                    "matched_primitives": matched_primitives,
                    "matched_assumption_terms": matched_terms,
                    "snippet": _snippet(function.source),
                    "reason": (
                        "consumer still reads tail/order-sensitive primitive"
                        if exposed
                        else "consumer contains update/iteration markers"
                        if updated
                        else "consumer reference found without exposed stale-tail markers"
                    ),
                }
            )

        exposed_ids = [site["call_site_id"] for site in claim_call_sites if site["verdict"] == VERDICT_EXPOSED]
        updated_count = sum(1 for site in claim_call_sites if site["verdict"] == VERDICT_UPDATED)
        if exposed_ids:
            verdict = VERDICT_EXPOSED
            reason = "one or more current call sites still look order/tail-assumption dependent"
        elif updated_count:
            verdict = VERDICT_UPDATED
            reason = "consumers reference the primitive but include update/iteration markers"
        elif claim_call_sites:
            verdict = VERDICT_SAFE
            reason = "primitive references found, but no stale assumption consumer was exposed"
        else:
            verdict = VERDICT_SAFE
            reason = "no current Solidity consumer matched extracted primitives"

        verdicts.append(
            {
                "claim_id": claim["claim_id"],
                "verdict": verdict,
                "reason": reason,
                "consumer_count": len(claim_call_sites),
                "exposed_call_site_ids": exposed_ids,
            }
        )
        call_sites.extend(claim_call_sites)

    call_sites.sort(
        key=lambda site: (
            0 if site["verdict"] == VERDICT_EXPOSED else 1,
            -int(site["score"]),
            site["file_path"],
            int(site["line"]),
            site["function"],
        )
    )
    for rank, site in enumerate(call_sites, start=1):
        site["rank"] = rank
    if call_site_limit is not None:
        call_sites = call_sites[:call_site_limit]
    return verdicts, call_sites


def mine(workspace: Path, limit: int | None = None, no_skip_dirs: bool = False) -> dict[str, Any]:
    workspace = workspace.expanduser().resolve()
    changelog_files = discover_changelog_files(
        workspace,
        skip_dirs=None if no_skip_dirs else CHANGELOG_SKIP_DIRS,
    )
    claims = extract_claims(workspace, changelog_files, limit=limit)
    sol_files, sol_scan_truncated = discover_solidity_files(workspace)
    functions, parse_errors = parse_solidity_functions(workspace, sol_files)
    verdicts, ranked_call_sites = analyse_claims(
        workspace,
        claims,
        functions,
        parse_errors,
        call_site_limit=limit,
    )
    ranked_exposed_call_sites = [
        site for site in ranked_call_sites if site["verdict"] == VERDICT_EXPOSED
    ]
    verdict_counts = {verdict: 0 for verdict in sorted(VERDICTS)}
    for verdict in verdicts:
        verdict_counts[verdict["verdict"]] += 1
    return {
        "schema": SCHEMA,
        "workspace_path": str(workspace),
        "discovered_changelogs": [_rel(path, workspace) for path in changelog_files],
        "claims": claims,
        "verdicts": verdicts,
        "ranked_call_sites": ranked_call_sites,
        "ranked_exposed_call_sites": ranked_exposed_call_sites,
        "stats": {
            "changelog_count": len(changelog_files),
            "claim_count": len(claims),
            "solidity_file_count": len(sol_files),
            "solidity_scan_truncated": sol_scan_truncated,
            "solidity_function_count": len(functions),
            "parse_error_count": len(parse_errors),
            "verdict_counts": verdict_counts,
        },
        "parse_errors": parse_errors,
    }


def _write_output(path: Path, payload: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("workspace", nargs="?", help="workspace path to scan")
    parser.add_argument("--workspace", dest="workspace_opt", help="workspace path to scan")
    parser.add_argument("--limit", type=int, default=None, help="maximum claims/call sites to emit")
    parser.add_argument("--json", action="store_true", help="emit structured JSON to stdout")
    parser.add_argument("--output", type=Path, help="write structured JSON to this file")
    parser.add_argument(
        "--no-skip-dirs",
        action="store_true",
        help="include changelog-like files inside default skipped directories",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    workspace_arg = args.workspace_opt or args.workspace
    if not workspace_arg:
        parser.error("workspace path is required")
    workspace = Path(workspace_arg)
    if not workspace.exists() or not workspace.is_dir():
        parser.error(f"workspace does not exist or is not a directory: {workspace}")
    if args.limit is not None and args.limit < 1:
        parser.error("--limit must be >= 1")

    payload = mine(workspace, limit=args.limit, no_skip_dirs=args.no_skip_dirs)
    if args.output:
        _write_output(args.output, payload)

    if args.json or not args.output:
        print(json.dumps(payload, indent=2, sort_keys=True))
    else:
        exposed = payload["stats"]["verdict_counts"].get(VERDICT_EXPOSED, 0)
        print(
            f"{payload['stats']['claim_count']} claims, "
            f"{len(payload['ranked_exposed_call_sites'])} exposed call sites, "
            f"{exposed} exposed verdicts"
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
