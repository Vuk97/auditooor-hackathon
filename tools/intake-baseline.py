#!/usr/bin/env python3
"""Build a mechanical intake baseline before agent/manual audit work.

The goal is not to find bugs directly. It makes the boring-but-critical first
pass explicit: what intel exists, which PDFs still need extracted text, whether
scanner artifacts are already present, and which deterministic commands should
run before dispatching agents.
"""
from __future__ import annotations

import argparse
import json
import re
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path


KNOWN_INTEL_NAMES = {
    "ATTACK_TREE.md",
    "CANTINA_COVERAGE.md",
    "EXTERNAL_INTEL.md",
    "KNOWN_VULNS.md",
    "PRIOR_CONCERNS.md",
    "RUBRIC_COVERAGE.md",
    "SCOPE.md",
    "SEVERITY.md",
    "SEVERITY_BLOCKCHAIN_DLT.md",
    "SEVERITY_SMART_CONTRACTS.md",
    "SUBMISSIONS.md",
}

IGNORED_DIR_NAMES = {
    ".git",
    ".hg",
    ".svn",
    ".venv",
    "node_modules",
    "target",
    "cache",
    "out",
}

SCAN_ARTIFACTS = (
    "SCAN_REPORT.md",
    "PATTERN_HITS.md",
    "static-analysis-summary.md",
    "custom-detectors.log",
    "SOLODIT_SEARCH_PLAN.md",
    "HYPOTHESIS_PROMPT.md",
)

SEVERITY_SOURCE_NAMES = (
    "SEVERITY.md",
    "SEVERITY_SMART_CONTRACTS.md",
    "SEVERITY_BLOCKCHAIN_DLT.md",
    "severity-rubric.md",
)

PLACEHOLDER_MARKERS = (
    "TODO:",
    "paste the bounty",
    "Placeholder",
    "copy from bounty platform",
    "do not rely on memory",
    "no OOS bullets parsed",
    "no severity caps parsed",
    "TBD",
)

SEVERITY_CAPS_NO_CAPS_MARKER = "no program-specific severity caps listed"

RUBRIC_UNAVAILABLE = "RUBRIC_UNAVAILABLE.md"

OPERATOR_TRUTH_FILES = (
    "SCOPE.md",
    "OOS_PASTED.md",
    "OOS_CHECKLIST.md",
    "SEVERITY_CAPS.md",
)

PRIOR_AUDIT_EVIDENCE_GLOBS = (
    "prior_audits/*.pdf",
    "prior_audits/*.txt",
    "prior_audits/*.md",
    "prior_audits/*.json",
    "prior_audits/.ingested_findings.tsv",
    "prior_audits/DIGEST_*.md",
)

# Gap E - asset-coverage hard-gate. Each rubric source file implies an
# in-scope asset type. Maps filename -> asset label used in asset_coverage_plan.
ASSET_RUBRIC_FILES: dict[str, str] = {
    "SEVERITY_SMART_CONTRACTS.md": "Smart Contract",
    "SEVERITY_BLOCKCHAIN_DLT.md": "Blockchain/DLT",
}

# SCOPE.md asset-label regex. Matches common Immunefi-style lines:
#   - Assets in scope:
#   - Smart Contract: ...
#   - Blockchain/DLT: ...
#   - Asset Type: Smart Contracts
# The regex is intentionally permissive; the operator should verify against
# the bounty page when parsing yields a surprising label set.
_SCOPE_ASSET_RE = re.compile(
    r"(?im)^\s*(?:[-*]\s+)?"
    r"(?:asset\s*type|asset|assets?\s*in\s*scope)\s*[:\-]\s*(?P<value>.+?)\s*$"
)
# Inline "Smart Contract" / "Blockchain/DLT" mentions as fallback.
_SCOPE_ASSET_MENTIONS: dict[str, str] = {
    "smart contract": "Smart Contract",
    "smart-contracts": "Smart Contract",
    "smart contracts": "Smart Contract",
    "blockchain/dlt": "Blockchain/DLT",
    "blockchain / dlt": "Blockchain/DLT",
    "blockchain-dlt": "Blockchain/DLT",
}

# Roots that imply a Rust/BDL asset - when present, scan-rust evidence is
# required before dispatch stages run.
_RUST_ROOT_HINTS: tuple[str, ...] = ("Cargo.toml",)

# Path-segment patterns that are NEVER genuine in-scope audit roots.
# A Cargo.toml found inside any directory whose relative path contains one of
# these segments (case-insensitive) is silently excluded from rust_roots.
# This prevents example code, load-test fixtures, and vendored deps from
# triggering the scan-rust blocker (V3 workflow gap #2, Sei field run).
#
# Conservative: only non-audit-target directories are excluded.  A real
# in-scope Rust crate whose path happens to contain e.g. "testutil" as a
# prefix of a component name would still be caught because the match is done
# against individual *parts* of the path, not a substring of the whole string.
_RUST_NON_AUDIT_ROOT_PARTS: frozenset[str] = frozenset(
    {
        "example",
        "examples",
        "loadtest",
        "load-test",
        "testutil",
        "test",
        "tests",
        "fixtures",
        "fixture",
        "mock",
        "mocks",
        "vendor",
        "third_party",
        "thirdparty",
        "node_modules",
        "target",
    }
)

# Substring patterns checked against the FULL relative path of the Cargo.toml
# parent directory (lower-cased).  Used for vendored-dependency markers that
# appear in multi-segment path components such as "libwasmvm".
_RUST_NON_AUDIT_ROOT_PATH_SUBSTRINGS: tuple[str, ...] = (
    "libwasmvm",
    "lib_wasmvm",
)

# Required scan-rust artifact layout. Two contracts are accepted:
#   * PR #115 rust-scan-runner.sh default: <ws>/scanners/rust/SCAN_RUST_SUMMARY.{json,md}
#   * Legacy rust-scan.sh layout:           <ws>/audit/rust-scan/summary.md,
#                                           <ws>/audit/rust-scan/rust-scan.log
# Any file in this list signals the stage ran.
_RUST_SCAN_ARTIFACTS: tuple[str, ...] = (
    "scanners/rust/SCAN_RUST_SUMMARY.md",
    "scanners/rust/SCAN_RUST_SUMMARY.json",
    "audit/rust-scan/summary.md",
    "audit/rust-scan/rust-scan.log",
)

# Operator-waiver filename template. One waiver per asset; explicit is better
# than implicit so the close-out can cite each one.
_ASSET_WAIVER_TEMPLATE = "ASSET_WAIVER_{slug}.md"


def _asset_slug(asset: str) -> str:
    """Filesystem-safe slug for asset names. 'Blockchain/DLT' -> 'Blockchain_DLT'."""
    return re.sub(r"[^A-Za-z0-9]+", "_", asset).strip("_")


def _iter_files(workspace: Path) -> list[Path]:
    files: list[Path] = []
    for path in workspace.rglob("*"):
        if any(part in IGNORED_DIR_NAMES for part in path.relative_to(workspace).parts):
            continue
        if path.is_file():
            files.append(path)
    return sorted(files)


def _rel(path: Path, root: Path) -> str:
    try:
        return path.relative_to(root).as_posix()
    except ValueError:
        return path.as_posix()


def _pdf_text_candidates(pdf: Path, workspace: Path) -> list[Path]:
    rel = pdf.relative_to(workspace)
    candidates = [
        pdf.with_suffix(".txt"),
        pdf.with_name(pdf.name + ".txt"),
        workspace / "extracted_text" / rel.with_suffix(".txt"),
        workspace / "prior_audits" / rel.name.replace(".pdf", ".txt"),
    ]
    return list(dict.fromkeys(candidates))


def _has_extracted_text(pdf: Path, workspace: Path) -> bool:
    for candidate in _pdf_text_candidates(pdf, workspace):
        if candidate.is_file() and candidate.stat().st_size > 0:
            return True
    return False


def _read_text(path: Path) -> str:
    try:
        return path.read_text(errors="ignore")
    except OSError:
        return ""


def _looks_placeholder(text: str) -> bool:
    if not text.strip():
        return True
    lowered = text.lower()
    return any(marker.lower() in lowered for marker in PLACEHOLDER_MARKERS)


def _auto_oos_block_populated(text: str) -> bool:
    """True when the machine-generated OOS block carries >=1 REAL bullet.

    ``tools/extract-oos.sh`` writes the authoritative OOS rows between
    ``AUDITOOOR_AUTO_OOS_BEGIN`` / ``..._END`` (parsed from SCOPE.md). When it
    runs in ``appended-legacy`` mode it leaves the bootstrap stub lines
    (``TBD - operator edit``) ABOVE the block intact, so ``_looks_placeholder``
    (which trips on the global ``TBD`` marker) false-flags an OOS_CHECKLIST.md
    that is in fact populated. A populated auto-block is the genuine, operator-
    truth-equivalent content, so it overrides the legacy-stub placeholder marker
    - mirroring the existing ``explicit_no_caps`` carve-out for SEVERITY_CAPS.md.
    A bullet only counts as real if it is NOT itself a TBD/placeholder stub."""
    begin = "auditooor_auto_oos_begin"
    end = "auditooor_auto_oos_end"
    lo = text.lower()
    i = lo.find(begin)
    if i < 0:
        return False
    j = lo.find(end, i)
    block = text[i:j] if j > i else text[i:]
    for line in block.splitlines():
        s = line.strip()
        if not s.startswith("-"):
            continue
        if "oos-" not in s.lower():
            continue
        if "tbd" in s.lower() or "operator edit" in s.lower():
            continue
        return True
    return False


def _tier_count(text: str) -> int:
    lowered = text.lower()
    return sum(1 for tier in ("critical", "high", "medium", "low") if tier in lowered)


_SEV_TABLE_ROW_RE = re.compile(r"^\|\s*(critical|high|medium|low)\s*\|\s*(.+?)\s*\|", re.I)
_SEV_TIER_HDR_RE = re.compile(r"^(#+\s*|\*\*\s*)(critical|high|medium|low)\b", re.I)
_SEV_BULLET_RE = re.compile(r"^([-*]|\d+\.)\s+\S")


def _severity_rubric_row_count(text: str) -> int:
    """Count genuine rubric impact rows in a severity source - markdown TABLE
    rows (| Critical | impact |) AND tier-header + bullet sections. Used as a
    truth-override so a fully-populated rubric is NOT mis-flagged a stub merely
    because it carries an incidental placeholder token (e.g. a 'TBD' note that
    the sub-Critical reward dollar figures are set on the program page). A
    bootstrap stub has zero real rows, so this cleanly distinguishes the two."""
    rows = 0
    under_tier = False
    for line in text.splitlines():
        s = line.strip()
        m = _SEV_TABLE_ROW_RE.match(s)
        if m:
            impact = m.group(2).strip()
            if impact and set(impact) - set("- "):
                rows += 1
            continue
        if _SEV_TIER_HDR_RE.match(s):
            under_tier = True
            continue
        if under_tier and _SEV_BULLET_RE.match(s):
            rows += 1
    return rows


def _truth_file_state(workspace: Path, name: str) -> dict:
    path = workspace / name
    if not path.is_file():
        return {
            "path": name,
            "present": False,
            "bytes": 0,
            "placeholder": False,
            "populated": False,
        }
    text = _read_text(path)
    placeholder = _looks_placeholder(text)
    explicit_no_caps = (
        name == "SEVERITY_CAPS.md"
        and SEVERITY_CAPS_NO_CAPS_MARKER in text.lower()
    )
    # A populated machine-generated OOS auto-block overrides a legacy "TBD" stub
    # left above it by extract-oos.sh's appended-legacy mode (false-placeholder).
    explicit_auto_oos = (
        name == "OOS_CHECKLIST.md"
        and _auto_oos_block_populated(text)
    )
    # A severity source with >=1 genuinely-parsed rubric row is operator-truth
    # content; an incidental placeholder token (e.g. a 'TBD' reward-tier note)
    # must not demote a fully-populated rubric to a stub.
    explicit_severity_rubric = (
        name in SEVERITY_SOURCE_NAMES
        and _severity_rubric_row_count(text) >= 1
    )
    truth_override = explicit_no_caps or explicit_auto_oos or explicit_severity_rubric
    return {
        "path": name,
        "present": True,
        "bytes": path.stat().st_size,
        "placeholder": placeholder and not truth_override,
        "populated": bool(text.strip()) and (not placeholder or truth_override),
    }


def _operator_truth_state(workspace: Path) -> dict:
    files = {name: _truth_file_state(workspace, name) for name in OPERATOR_TRUTH_FILES}
    oos_sources = [files["OOS_PASTED.md"], files["OOS_CHECKLIST.md"]]
    return {
        "files": files,
        "scope_populated": files["SCOPE.md"]["populated"],
        "oos_text_populated": any(source["populated"] for source in oos_sources),
        "derived_oos_checklist_populated": files["OOS_CHECKLIST.md"]["populated"],
        "severity_caps_populated": files["SEVERITY_CAPS.md"]["populated"],
    }


def _prior_disclosure_state(workspace: Path) -> dict:
    index_path = workspace / ".auditooor" / "prior_disclosure_index.json"
    index_present = index_path.is_file()
    index_valid = False
    total_rows = 0
    parse_error = ""
    if index_present:
        try:
            payload = json.loads(index_path.read_text(encoding="utf-8"))
            summary = payload.get("summary") if isinstance(payload, dict) else {}
            total_rows = int((summary or {}).get("total_rows", 0) or 0)
            index_valid = payload.get("schema_version") == "auditooor.prior_disclosure_index.v1"
        except Exception as exc:  # pragma: no cover - exact message not important
            parse_error = str(exc)

    evidence_paths: list[str] = []
    for pattern in PRIOR_AUDIT_EVIDENCE_GLOBS:
        for path in workspace.glob(pattern):
            if path.is_file() and path.stat().st_size > 0:
                rel = _rel(path, workspace)
                if rel not in evidence_paths:
                    evidence_paths.append(rel)
    waiver_state = _truth_file_state(workspace, "NO_PRIOR_AUDITS.md")
    return {
        "index_path": _rel(index_path, workspace),
        "index_present": index_present,
        "index_valid": index_valid,
        "index_total_rows": total_rows,
        "index_parse_error": parse_error,
        "prior_audit_evidence": sorted(evidence_paths),
        "prior_audit_evidence_count": len(evidence_paths),
        "no_prior_audits_waiver": waiver_state,
        "ready": index_present and index_valid and (
            total_rows > 0 or waiver_state["populated"]
        ),
    }


def _severity_sources(workspace: Path) -> list[dict]:
    sources: list[dict] = []
    for name in SEVERITY_SOURCE_NAMES:
        path = workspace / name
        if not path.is_file():
            continue
        text = _read_text(path)
        # A severity source with >=1 genuinely-parsed rubric row is operator-truth
        # content; an incidental placeholder token (e.g. a 'TBD' reward-tier note)
        # must not demote a fully-populated rubric to a stub. Mirrors the
        # truth-override in _truth_file_state.
        placeholder = _looks_placeholder(text) and _severity_rubric_row_count(text) < 1
        sources.append(
            {
                "path": _rel(path, workspace),
                "bytes": path.stat().st_size,
                "placeholder": placeholder,
                "tier_count": _tier_count(text),
            }
        )
    return sources


def _detect_assets_in_scope(workspace: Path, populated_sources: list[dict]) -> list[str]:
    """Derive asset labels from split rubric files + SCOPE.md.

    Order preserved: Smart Contract first when present, Blockchain/DLT second.
    Deduped.
    """
    assets: list[str] = []
    source_paths = {source["path"] for source in populated_sources}
    for name, label in ASSET_RUBRIC_FILES.items():
        if name in source_paths and label not in assets:
            assets.append(label)

    scope = workspace / "SCOPE.md"
    if scope.is_file():
        text = _read_text(scope)
        lowered = text.lower()
        for match in _SCOPE_ASSET_RE.finditer(text):
            value = match.group("value").lower()
            for token, label in _SCOPE_ASSET_MENTIONS.items():
                if token in value and label not in assets:
                    assets.append(label)
        # Fallback: bare mention anywhere in SCOPE.md.
        for token, label in _SCOPE_ASSET_MENTIONS.items():
            if token in lowered and label not in assets:
                assets.append(label)

    return assets


_ASSET_PLAN_ROOTS_HEADING_RE = re.compile(
    r"^\s*#{1,6}\s+.*\broots?\b", re.IGNORECASE
)
_ASSET_PLAN_OOS_ROOTS_HEADING_RE = re.compile(
    r"^\s*#{1,6}\s+.*\bout[- ]of[- ]scope\s+roots?\b", re.IGNORECASE
)
_ASSET_PLAN_BULLET_RE = re.compile(
    r"^\s*[-*+]\s+(?P<body>.+?)\s*$"
)
_ASSET_PLAN_PARENTHETICAL_TAIL_RE = re.compile(r"\s*\([^)]*\)\s*$")


def _strip_root_bullet(body: str) -> str:
    """Normalize a bulleted root entry into a bare path.

    Drops markdown emphasis (`*foo*`, `**foo**`), backticks, leading/trailing
    quotes, and a trailing parenthetical comment if present (e.g.
    "`packages/horizon/` (Horizon upgrade)" → "packages/horizon/").
    """
    text = body.strip()
    # Strip trailing parenthetical (description)
    text = _ASSET_PLAN_PARENTHETICAL_TAIL_RE.sub("", text).strip()
    # Strip surrounding markdown emphasis
    text = re.sub(r"^[*_]+|[*_]+$", "", text).strip()
    # Strip backticks (may surround whole path or partial)
    text = text.replace("`", "").strip()
    # Strip surrounding quotes
    text = text.strip("'\"").strip()
    # Drop trailing whitespace + comma
    text = text.rstrip(",").strip()
    return text


def _parse_asset_plan_roots(text: str) -> tuple[list[str], str]:
    """Parse a markdown bulleted Roots section.

    Returns (roots, parse_status). parse_status ∈ {parsed, malformed, missing}.

    Heading detection is permissive ("## Roots", "### Source roots", etc.).
    The bulleted list immediately following the heading is consumed until
    a blank line followed by another heading or until EOF.
    """
    lines = text.splitlines()
    n = len(lines)
    i = 0
    while i < n:
        if _ASSET_PLAN_ROOTS_HEADING_RE.match(lines[i]):
            break
        i += 1
    if i >= n:
        return [], "missing"
    # Skip the heading + any blank lines
    i += 1
    while i < n and not lines[i].strip():
        i += 1
    roots: list[str] = []
    saw_bullet = False
    while i < n:
        line = lines[i]
        stripped = line.strip()
        if not stripped:
            # Allow one blank line inside a bullet list, then keep reading.
            # Stop at TWO consecutive blanks or a new heading.
            j = i + 1
            while j < n and not lines[j].strip():
                j += 1
            if j >= n or lines[j].lstrip().startswith("#"):
                break
            i = j
            continue
        if stripped.startswith("#"):
            break
        m = _ASSET_PLAN_BULLET_RE.match(line)
        if m:
            saw_bullet = True
            normalized = _strip_root_bullet(m.group("body"))
            if normalized:
                roots.append(normalized)
            i += 1
            continue
        # Non-bullet content under the heading: stop the list.
        break
    if not saw_bullet:
        return [], "malformed"
    return roots, "parsed"


def _read_plan_file(workspace: Path, filename: str) -> dict | None:
    """Parse an operator-supplied asset plan file.

    Supported layouts (all plain markdown so operators don't need JSON):
      - `Roots: path1, path2`               (key:value form, comma-separated)
      - `## Roots\\n- path1\\n- path2`        (markdown bulleted list - added
                                              for HH-style multi-package
                                              plans, see PR #120 lesson 3)
      - `Strategy: ...`
      - `Estimated hours: N`
      - `Agent hour quota pct: N`
      - `Plan status: ready|missing|placeholder|not_started`
    """
    path = workspace / filename
    if not path.is_file():
        return None
    raw = _read_text(path)
    if not raw.strip():
        return {"plan_status": "placeholder", "source": filename,
                "roots_parse_status": "missing"}
    plan: dict = {"source": filename}
    for line in raw.splitlines():
        m = re.match(r"^\s*[-*]?\s*([A-Za-z][A-Za-z _]+?)\s*[:=]\s*(.+?)\s*$", line)
        if not m:
            continue
        key = m.group(1).strip().lower().replace(" ", "_")
        value = m.group(2).strip()
        if key == "roots":
            plan["roots"] = [r.strip() for r in re.split(r"[,\s]+", value) if r.strip()]
        elif key == "strategy":
            plan["strategy"] = value
        elif key in ("estimated_hours", "hours"):
            try:
                plan["estimated_hours"] = int(float(value))
            except ValueError:
                pass
        elif key in ("agent_hour_quota_pct", "quota_pct"):
            try:
                plan["agent_hour_quota_pct"] = int(float(value))
            except ValueError:
                pass
        elif key == "plan_status":
            plan["plan_status"] = value.lower()
    # Bulleted-list fallback for `## Roots\n- path1\n- path2` shape.
    # Only applies if the line-based parse did not already populate roots
    # (so an explicit `Roots: ...` line still wins).
    if "roots" not in plan or not plan.get("roots"):
        bulleted, status = _parse_asset_plan_roots(raw)
        if bulleted:
            plan["roots"] = bulleted
            plan["roots_parse_status"] = status
        elif status != "missing":
            plan["roots_parse_status"] = status
    else:
        plan["roots_parse_status"] = "parsed"
    plan.setdefault("plan_status", "not_started")
    return plan


def _parse_asset_plan_oos_roots(text: str) -> list[str]:
    """Parse an optional '## Out-of-scope roots' section from an asset plan.

    Returns a (possibly empty) list of path prefixes that should be excluded
    from rust_roots detection.  Same bullet-list parsing as _parse_asset_plan_roots.
    """
    lines = text.splitlines()
    n = len(lines)
    i = 0
    while i < n:
        if _ASSET_PLAN_OOS_ROOTS_HEADING_RE.match(lines[i]):
            break
        i += 1
    if i >= n:
        return []
    i += 1
    while i < n and not lines[i].strip():
        i += 1
    roots: list[str] = []
    while i < n:
        line = lines[i]
        stripped = line.strip()
        if not stripped:
            j = i + 1
            while j < n and not lines[j].strip():
                j += 1
            if j >= n or lines[j].lstrip().startswith("#"):
                break
            i = j
            continue
        if stripped.startswith("#"):
            break
        m = _ASSET_PLAN_BULLET_RE.match(line)
        if m:
            normalized = _strip_root_bullet(m.group("body"))
            if normalized:
                roots.append(normalized)
            i += 1
            continue
        break
    return roots


def _collect_plan_oos_roots(workspace: Path) -> tuple[str, ...]:
    """Aggregate OOS root prefixes from all ASSET_PLAN_*.md files in workspace.

    These are honoured by _has_rust_roots to suppress spurious Rust-root
    detections for directories the operator has declared out-of-scope.
    """
    prefixes: list[str] = []
    for path in workspace.glob("ASSET_PLAN_*.md"):
        text = _read_text(path)
        for root in _parse_asset_plan_oos_roots(text):
            if root not in prefixes:
                prefixes.append(root)
    return tuple(prefixes)


def _asset_plan_filename(asset: str) -> str:
    return f"ASSET_PLAN_{_asset_slug(asset)}.md"


def _is_non_audit_rust_root(rel_dir: str) -> bool:
    """Return True when a Cargo.toml directory should be excluded from rust_roots.

    Exclusion criteria (V3 workflow gap #2 fix):
    1. Any path *part* (directory component) matches a known non-audit segment
       (example, loadtest, test, vendor, etc.).
    2. The full relative path (lower-cased) contains a vendored-dependency
       substring marker (e.g. "libwasmvm").
    """
    if not rel_dir or rel_dir == ".":
        return False
    parts = [p.lower() for p in Path(rel_dir).parts]
    if any(part in _RUST_NON_AUDIT_ROOT_PARTS for part in parts):
        return True
    rel_lower = rel_dir.lower()
    if any(sub in rel_lower for sub in _RUST_NON_AUDIT_ROOT_PATH_SUBSTRINGS):
        return True
    return False


def _is_cosmwasm_contract_crate(cargo_toml: Path) -> bool:
    """Return True when a Cargo.toml is a CosmWasm *contract* crate.

    CosmWasm contracts compile to a wasm blob (``crate-type`` includes
    ``cdylib``) and depend on ``cosmwasm-std``. Inside a Go/BDL chain repo these
    are wasm test fixtures / example dApps - e.g. Sei's
    ``parallelization/{bank,wasm,staking}`` OCC-scheduler test contracts - NOT
    the chain's own Rust audit surface, so they must not trigger the scan-rust
    blocker (V3 workflow gap #2b, Sei field run 2026-07-04). A genuine in-scope
    Rust target (Solana program, Substrate pallet, a Rust node) is a ``bin`` /
    ``lib`` crate that does NOT declare ``crate-type = cdylib`` together with a
    ``cosmwasm-std`` dependency, so this exclusion never suppresses real
    Rust-BDL detection.
    """
    try:
        text = cargo_toml.read_text(encoding="utf-8", errors="replace")
    except (OSError, UnicodeError, ValueError):
        return False
    low = text.lower()
    has_cdylib = "crate-type" in low and "cdylib" in low
    has_cosmwasm = "cosmwasm-std" in low or "cosmwasm_std" in low
    return has_cdylib and has_cosmwasm


def _has_rust_roots(workspace: Path, oos_root_prefixes: tuple[str, ...] = ()) -> list[str]:
    """Return list of relative directories that contain a Rust root marker.

    Excludes non-audit directories (examples, load-test fixtures, vendored
    deps) via _is_non_audit_rust_root().  Also excludes any path that starts
    with a prefix in *oos_root_prefixes*, which are derived from the workspace
    asset plan's explicit Out-of-scope roots section when available.

    Used both for detecting a BDL-style workspace and for inferring scan-rust
    evidence requirement.
    """
    roots: list[str] = []
    for marker in _RUST_ROOT_HINTS:
        for path in workspace.rglob(marker):
            rel_parts = path.relative_to(workspace).parts
            if any(part in IGNORED_DIR_NAMES for part in rel_parts):
                continue
            rel = _rel(path.parent, workspace) or "."
            if _is_non_audit_rust_root(rel):
                continue
            # CosmWasm contract crates (cdylib + cosmwasm-std) are wasm
            # fixtures / example dApps inside a Go/BDL chain repo, not the
            # chain's Rust audit surface - exclude from the scan-rust blocker.
            if _is_cosmwasm_contract_crate(path):
                continue
            # Honor explicit OOS root prefixes from asset plan.
            if oos_root_prefixes and any(
                rel == prefix or rel.startswith(prefix.rstrip("/") + "/")
                for prefix in oos_root_prefixes
            ):
                continue
            if rel not in roots:
                roots.append(rel)
    return roots


def _has_rust_scan_artifact(workspace: Path) -> bool:
    return any((workspace / rel).is_file() for rel in _RUST_SCAN_ARTIFACTS)


def _asset_waiver_present(workspace: Path, asset: str) -> Path | None:
    slug = _asset_slug(asset)
    path = workspace / _ASSET_WAIVER_TEMPLATE.format(slug=slug)
    if path.is_file() and path.stat().st_size > 0:
        return path
    return None


def _existing_baseline_plan(workspace: Path) -> dict:
    """Load `asset_coverage_plan` from a prior INTAKE_BASELINE.json if present.

    Used so that operator-curated `roots[]` entries are preserved across
    re-runs of intake (Codex review rule on PR #120 lesson 3: never silently
    overwrite a non-empty roots array).
    """
    path = workspace / "INTAKE_BASELINE.json"
    if not path.is_file():
        return {}
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return {}
    if not isinstance(data, dict):
        return {}
    plan = data.get("asset_coverage_plan")
    return plan if isinstance(plan, dict) else {}


def _build_asset_coverage_plan(
    workspace: Path,
    assets: list[str],
    rust_roots: list[str],
) -> tuple[dict, list[str], list[str]]:
    """Assemble asset_coverage_plan{} + warnings/blockers list.

    Per roadmap L74-94, each entry has:
      {roots, strategy, estimated_hours, agent_hour_quota_pct, plan_status}

    Plan files live at ASSET_PLAN_<Asset_Slug>.md in the workspace root.
    Missing/placeholder files produce blockers unless an
    ASSET_WAIVER_<Asset_Slug>.md is present.
    """
    plan: dict = {}
    warnings: list[str] = []
    blockers: list[str] = []
    prior_plan = _existing_baseline_plan(workspace)
    for asset in assets:
        entry: dict = {
            "roots": [],
            "strategy": "",
            "estimated_hours": 0,
            "agent_hour_quota_pct": 0,
            "plan_status": "missing",
        }
        plan_file = _asset_plan_filename(asset)
        parsed = _read_plan_file(workspace, plan_file)
        waiver = _asset_waiver_present(workspace, asset)
        if parsed:
            for key in ("roots", "strategy", "estimated_hours",
                        "agent_hour_quota_pct", "plan_status"):
                if key in parsed:
                    entry[key] = parsed[key]
            entry["source"] = parsed.get("source", plan_file)
            if "roots_parse_status" in parsed:
                entry["roots_parse_status"] = parsed["roots_parse_status"]
        # Preservation rule: if a prior INTAKE_BASELINE.json had non-empty
        # operator-curated roots[] for this asset, never silently overwrite.
        # The plan-file-derived roots are still recorded under
        # `roots_from_plan` for diff visibility.
        prior_entry = prior_plan.get(asset) if isinstance(prior_plan, dict) else None
        if isinstance(prior_entry, dict):
            prior_roots = prior_entry.get("roots") or []
            if prior_roots and entry.get("roots") and prior_roots != entry["roots"]:
                entry["roots_from_plan"] = entry["roots"]
                entry["roots"] = list(prior_roots)
                warnings.append(
                    f"asset '{asset}': preserved curated roots from "
                    f"existing INTAKE_BASELINE.json ({len(prior_roots)} entries); "
                    "plan-file roots recorded under `roots_from_plan`"
                )
            elif prior_roots and not entry.get("roots"):
                entry["roots"] = list(prior_roots)
                entry["roots_parse_status"] = entry.get(
                    "roots_parse_status", "preserved_from_prior"
                )
        # BDL/Rust assets: if Rust roots are present, scan-rust evidence
        # (or explicit waiver) is required. A Blockchain/DLT asset without
        # Rust roots (e.g. protocol-design-only scope) does NOT trigger the
        # rust-scan blocker.
        if asset == "Blockchain/DLT" and rust_roots and not entry["roots"]:
            entry["roots"] = rust_roots[:8]
        needs_rust_evidence = (
            asset == "Blockchain/DLT" and bool(rust_roots)
        ) or (
            rust_roots and asset not in ("Smart Contract",)
        )
        if needs_rust_evidence and not _has_rust_scan_artifact(workspace):
            if waiver is not None:
                warnings.append(
                    f"asset '{asset}' has no scan-rust artifact but waived "
                    f"via `{_rel(waiver, workspace)}`"
                )
            else:
                # DEFERRED, NOT A BLOCKER (Axelar-DLT field run 2026-07-12):
                # intake-baseline is engage stage 1; scan-rust is a LATER stage
                # of the same `make audit` pipeline (intake-baseline -> orient ->
                # ... -> scan-rust). Hard-blocking here on an artifact a
                # downstream stage produces DEADLOCKS every Rust-containing
                # workspace under --fail-fast (scan-rust never runs). This is the
                # same situation as the other not-yet-run scanners, which are
                # already WARNINGS. So emit a warning + autofix hint; the
                # downstream scan-rust stage is the real producer/enforcer, and a
                # persistent absence still surfaces (just non-fatally) so close-out
                # can see it. Pure-Go/Sol workspaces never reach this branch.
                warnings.append(
                    f"asset coverage: {asset} - Rust/BDL roots in scope but no "
                    "scan-rust artifact yet (runs downstream in `make audit`; or "
                    f"run `make scan-rust WS={workspace}` explicitly). Expected "
                    "scanners/rust/SCAN_RUST_SUMMARY.md or audit/rust-scan/summary.md."
                )
        if waiver is not None:
            # Explicit waiver bypasses plan_status gating but must be recorded
            # so close-out can cite it.
            entry["waiver"] = _rel(waiver, workspace)
            entry["plan_status"] = entry.get("plan_status") or "waived"
            if entry["plan_status"] != "ready":
                warnings.append(
                    f"asset '{asset}' plan_status={entry['plan_status']} "
                    f"(waived via `{entry['waiver']}`)"
                )
            plan[asset] = entry
            continue
        status = entry.get("plan_status", "missing")
        if status != "ready":
            blockers.append(f"asset coverage blocker: {asset} (plan_status={status})")
        plan[asset] = entry
    # I-02 (PR #158 follow-up): if any plan-status blockers were emitted, append
    # a single autofix hint pointing at the scaffold tool. Operators previously
    # had to read intake-baseline.py source to discover the required ASSET_PLAN
    # file structure.
    if any(b.startswith("asset coverage blocker:") and "plan_status=" in b
           for b in blockers):
        blockers.append(
            "Hint: run 'tools/init-asset-plan.sh <workspace>' to scaffold the "
            "missing plan(s)."
        )
    return plan, warnings, blockers


def _rubric_coverage_state(workspace: Path, severity_sources: list[dict]) -> dict:
    path = workspace / "RUBRIC_COVERAGE.md"
    if not path.is_file():
        return {
            "path": "RUBRIC_COVERAGE.md",
            "present": False,
            "placeholder": False,
            "row_count": 0,
            "not_checked_count": 0,
            "mentions_sources": [],
        }

    text = _read_text(path)
    row_verdict = re.compile(
        r"\|\s*(?:✅\s*)?(?:PASS|🚀\s*SUBMITTED|⚠️\s*PARTIAL|"
        r"🚫\s*OOS|❌\s*N/A|📋\s*NOT CHECKED)\s*\|",
        re.IGNORECASE,
    )
    row_count = sum(1 for line in text.splitlines() if row_verdict.search(line))
    mentions_sources = [
        source["path"]
        for source in severity_sources
        if source["path"] in text
    ]
    return {
        "path": "RUBRIC_COVERAGE.md",
        "present": True,
        "placeholder": _looks_placeholder(text),
        "row_count": row_count,
        "not_checked_count": text.count("NOT CHECKED"),
        "mentions_sources": mentions_sources,
    }


def build_baseline(workspace: Path, *, strict_operator_truth: bool = False) -> dict:
    files = _iter_files(workspace)
    ext_counts = Counter(path.suffix.lower() or "<none>" for path in files)
    pdfs = [path for path in files if path.suffix.lower() == ".pdf"]
    intel = [
        path for path in files
        if path.name in KNOWN_INTEL_NAMES
        or path.name.endswith("_COVERAGE.md")
        or path.name.endswith("_VULNS.md")
    ]
    missing_pdf_text = [
        {
            "pdf": _rel(pdf, workspace),
            "expected_text_candidates": [
                _rel(candidate, workspace)
                for candidate in _pdf_text_candidates(pdf, workspace)
            ],
        }
        for pdf in pdfs
        if not _has_extracted_text(pdf, workspace)
    ]
    scan_artifacts = {
        name: (workspace / name).is_file()
        for name in SCAN_ARTIFACTS
    }
    severity_sources = _severity_sources(workspace)
    populated_severity_sources = [
        source for source in severity_sources
        if not source["placeholder"] and source["tier_count"] >= 2
    ]
    rubric_coverage = _rubric_coverage_state(workspace, populated_severity_sources)
    split_sources_expected = {"SEVERITY_SMART_CONTRACTS.md", "SEVERITY_BLOCKCHAIN_DLT.md"}
    split_sources_present = {
        source["path"] for source in populated_severity_sources
        if source["path"] in split_sources_expected
    }
    explicit_unavailable = workspace / RUBRIC_UNAVAILABLE

    assets_in_scope = _detect_assets_in_scope(workspace, populated_severity_sources)
    plan_oos_roots = _collect_plan_oos_roots(workspace)
    rust_roots = _has_rust_roots(workspace, oos_root_prefixes=plan_oos_roots)
    asset_coverage_plan, asset_warnings, asset_blockers = _build_asset_coverage_plan(
        workspace, assets_in_scope, rust_roots
    )
    operator_truth = _operator_truth_state(workspace)
    prior_disclosure = _prior_disclosure_state(workspace)

    warnings: list[str] = []
    blockers: list[str] = []
    if missing_pdf_text:
        warnings.append(f"{len(missing_pdf_text)} PDF(s) lack extracted text")
    missing_scan = [name for name, present in scan_artifacts.items() if not present]
    if missing_scan:
        warnings.append(f"{len(missing_scan)} scanner artifact(s) not present yet")
    if not intel:
        warnings.append("no known intel markdown files detected")
    # I-15 (PR #158): downstream stages (`flow-gate.sh` Step 5,
    # `agent-dispatch-enforced.sh`, `dispatch-brief.sh`) HARD-STOP on
    # missing `OOS_CHECKLIST.md` / `SEVERITY_CAPS.md`. Intake-baseline
    # itself doesn't generate these but it is the operator's first
    # signal - surface a warning so they know to run `extract-oos.sh`
    # before the pipeline blocks them mid-chain.
    missing_scope_artifacts = [
        name for name in ("OOS_CHECKLIST.md", "SEVERITY_CAPS.md")
        if not (workspace / name).is_file()
    ]
    if missing_scope_artifacts:
        warnings.append(
            f"missing scope artifact(s) {', '.join(missing_scope_artifacts)} "
            "(hint: run `tools/extract-oos.sh <workspace>` to derive from "
            "SCOPE.md before flow-gate Step 5)"
        )
    if strict_operator_truth:
        files_state = operator_truth["files"]
        if not files_state["SCOPE.md"]["populated"]:
            blockers.append(
                "strict operator-truth blocker: SCOPE.md missing or placeholder "
                "(paste the live program scope/assets before audit work starts)"
            )
        if not operator_truth["oos_text_populated"]:
            blockers.append(
                "strict operator-truth blocker: no populated OOS text found "
                "(expected OOS_PASTED.md from operator-oos-import or "
                "OOS_CHECKLIST.md from extract-oos.sh)"
            )
        if not files_state["OOS_CHECKLIST.md"]["populated"]:
            blockers.append(
                "strict operator-truth blocker: OOS_CHECKLIST.md missing or placeholder "
                "(run `tools/extract-oos.sh <workspace>` after SCOPE.md is populated)"
            )
        if not files_state["SEVERITY_CAPS.md"]["populated"]:
            blockers.append(
                "strict operator-truth blocker: SEVERITY_CAPS.md missing or placeholder "
                "(run `tools/extract-oos.sh <workspace>` and verify caps against the live program)"
            )
        if not prior_disclosure["index_present"]:
            blockers.append(
                "strict operator-truth blocker: prior disclosure index missing "
                "(run `make prior-disclosure-index WS=<workspace>` before audit work starts)"
            )
        elif not prior_disclosure["index_valid"]:
            blockers.append(
                "strict operator-truth blocker: prior disclosure index is invalid "
                "(delete/regenerate .auditooor/prior_disclosure_index.json)"
            )
        elif prior_disclosure["index_total_rows"] == 0 and not (
            prior_disclosure["no_prior_audits_waiver"]["populated"]
        ):
            blockers.append(
                "strict operator-truth blocker: prior disclosure index has zero rows "
                "and NO_PRIOR_AUDITS.md waiver is absent"
            )
    if not explicit_unavailable.is_file():
        if not populated_severity_sources:
            blockers.append(
                "no populated severity rubric source found "
                "(expected SEVERITY.md or split SEVERITY_SMART_CONTRACTS.md + "
                "SEVERITY_BLOCKCHAIN_DLT.md)"
            )
        if not rubric_coverage["present"]:
            blockers.append(
                "RUBRIC_COVERAGE.md missing "
                "(hint: run `tools/init-rubric-coverage.sh <workspace>` "
                "to scaffold from SEVERITY.md)"
            )
        elif rubric_coverage["placeholder"] or rubric_coverage["row_count"] == 0:
            blockers.append(
                "RUBRIC_COVERAGE.md is placeholder or has no rubric rows "
                "(hint: rerun `tools/init-rubric-coverage.sh <workspace>` "
                "to repopulate from SEVERITY.md)"
            )
        if split_sources_present and split_sources_present != split_sources_expected:
            missing_split = sorted(split_sources_expected - split_sources_present)
            blockers.append(
                "split rubric mode is incomplete; missing populated source(s): "
                + ", ".join(missing_split)
            )
        if split_sources_present == split_sources_expected:
            mentioned = set(rubric_coverage.get("mentions_sources") or [])
            missing_mentions = sorted(split_sources_expected - mentioned)
            if missing_mentions:
                blockers.append(
                    "RUBRIC_COVERAGE.md does not cite split rubric source(s): "
                    + ", ".join(missing_mentions)
                )
    else:
        warnings.append(
            f"{RUBRIC_UNAVAILABLE} present; rubric gate bypassed by explicit operator note"
        )

    # Asset-coverage hard-gate (Gap E). Blockers here halt the pipeline before
    # mine-prioritize; warnings only redirect next action.
    warnings.extend(asset_warnings)
    blockers.extend(asset_blockers)
    if rust_roots and not _has_rust_scan_artifact(workspace):
        if not any(b.startswith("asset coverage blocker:") and "scan-rust" in b for b in blockers):
            warnings.append(
                f"workspace has {len(rust_roots)} Rust root(s) but no scan-rust "
                "artifact at scanners/rust/SCAN_RUST_SUMMARY.md or "
                "audit/rust-scan/summary.md"
            )

    recommended = [
        (
            f"populate {workspace}/SEVERITY.md, or both "
            f"{workspace}/SEVERITY_SMART_CONTRACTS.md and "
            f"{workspace}/SEVERITY_BLOCKCHAIN_DLT.md"
        ),
        f"./tools/init-rubric-coverage.sh {workspace} --force",
        f"make extract DIR={workspace}",
        (
            "python3 tools/engage.py "
            f"--workspace {workspace} "
            "--stages intake-baseline,orient,live-checks,env-check,"
            "mine-prioritize,scan,correlate,dedupe,report --summary"
        ),
        f"python3 tools/engage.py --workspace {workspace} --stage mine-briefs --summary",
        f"python3 tools/engage.py --workspace {workspace} --stage dispatch-brief --summary",
    ]

    return {
        "schema": "auditooor.intake-baseline.v1",
        "generated_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "workspace": str(workspace),
        "summary": {
            "file_count": len(files),
            "pdf_count": len(pdfs),
            "pdfs_missing_extracted_text": len(missing_pdf_text),
            "known_intel_files": len(intel),
            "severity_sources_populated": len(populated_severity_sources),
            "rubric_coverage_rows": rubric_coverage["row_count"],
            "scanner_artifacts_present": sum(1 for present in scan_artifacts.values() if present),
            "scanner_artifacts_total": len(scan_artifacts),
            "assets_in_scope_count": len(assets_in_scope),
            "assets_ready": sum(
                1 for entry in asset_coverage_plan.values()
                if entry.get("plan_status") == "ready"
            ),
            "rust_roots_detected": len(rust_roots),
            "rust_scan_artifact_present": _has_rust_scan_artifact(workspace),
            "strict_operator_truth": strict_operator_truth,
            "operator_truth_ready": (
                operator_truth["scope_populated"]
                and operator_truth["oos_text_populated"]
                and operator_truth["derived_oos_checklist_populated"]
                and operator_truth["severity_caps_populated"]
                and prior_disclosure["ready"]
            ),
            "prior_disclosure_ready": prior_disclosure["ready"],
            "prior_disclosure_rows": prior_disclosure["index_total_rows"],
            "warning_count": len(warnings),
            "blocker_count": len(blockers),
        },
        "file_extension_counts": dict(sorted(ext_counts.items())),
        "known_intel": [_rel(path, workspace) for path in intel],
        "severity_sources": severity_sources,
        "rubric_coverage": rubric_coverage,
        "pdfs_missing_extracted_text": missing_pdf_text,
        "scanner_artifacts": scan_artifacts,
        "assets_in_scope": assets_in_scope,
        "asset_coverage_plan": asset_coverage_plan,
        "rust_roots": rust_roots,
        "operator_truth": operator_truth,
        "prior_disclosure": prior_disclosure,
        "warnings": warnings,
        "blockers": blockers,
        "recommended_mechanical_order": recommended,
    }


def render_markdown(payload: dict) -> str:
    summary = payload["summary"]
    lines = [
        "# Intake Baseline",
        "",
        f"- Workspace: `{payload['workspace']}`",
        f"- Generated: `{payload['generated_at']}`",
        f"- Files indexed: {summary['file_count']}",
        f"- PDFs: {summary['pdf_count']}",
        f"- PDFs missing extracted text: {summary['pdfs_missing_extracted_text']}",
        f"- Known intel files: {summary['known_intel_files']}",
        f"- Populated severity rubric sources: {summary['severity_sources_populated']}",
        f"- Rubric coverage rows: {summary['rubric_coverage_rows']}",
        (
            "- Scanner artifacts present: "
            f"{summary['scanner_artifacts_present']}/{summary['scanner_artifacts_total']}"
        ),
        f"- Blocking intake issues: {summary['blocker_count']}",
        "",
        "## Blocking Intake Issues",
        "",
    ]
    blockers = payload.get("blockers") or []
    if blockers:
        lines.extend(f"- {blocker}" for blocker in blockers)
    else:
        lines.append("- None")

    lines.extend([
        "",
        "## Warnings",
        "",
    ])
    warnings = payload.get("warnings") or []
    if warnings:
        lines.extend(f"- {warning}" for warning in warnings)
    else:
        lines.append("- None")

    lines.extend(["", "## Known Intel", ""])
    intel = payload.get("known_intel") or []
    if intel:
        lines.extend(f"- `{path}`" for path in intel[:50])
        if len(intel) > 50:
            lines.append(f"- ... {len(intel) - 50} more")
    else:
        lines.append("- None detected")

    lines.extend(["", "## Operator Truth", ""])
    operator_truth = payload.get("operator_truth") or {}
    truth_files = operator_truth.get("files") or {}
    if truth_files:
        for name in OPERATOR_TRUTH_FILES:
            state = truth_files.get(name) or {}
            if not state.get("present"):
                status = "missing"
            elif state.get("placeholder"):
                status = "placeholder"
            elif state.get("populated"):
                status = "populated"
            else:
                status = "empty"
            lines.append(f"- `{name}`: {status}")
        ready = "yes" if summary.get("operator_truth_ready") else "no"
        strict = "yes" if summary.get("strict_operator_truth") else "no"
        lines.append(f"- Strict operator-truth mode: {strict}; ready: {ready}")
    else:
        lines.append("- Not evaluated")
    prior = payload.get("prior_disclosure") or {}
    if prior:
        idx_state = "valid" if prior.get("index_valid") else "missing/invalid"
        if prior.get("index_present") and not prior.get("index_valid"):
            idx_state = "invalid"
        elif not prior.get("index_present"):
            idx_state = "missing"
        lines.append(
            "- Prior disclosure index: "
            f"{idx_state}, rows={prior.get('index_total_rows', 0)}, "
            f"prior_audit_evidence={prior.get('prior_audit_evidence_count', 0)}"
        )
        waiver = (prior.get("no_prior_audits_waiver") or {}).get("populated")
        if waiver:
            lines.append("- Prior audit waiver: `NO_PRIOR_AUDITS.md`")

    lines.extend(["", "## Asset Coverage Plan", ""])
    assets = payload.get("assets_in_scope") or []
    plan = payload.get("asset_coverage_plan") or {}
    if not assets:
        lines.append("- No in-scope assets detected (populate SEVERITY_SMART_CONTRACTS.md / SEVERITY_BLOCKCHAIN_DLT.md or SCOPE.md)")
    else:
        lines.append(f"- Assets in scope: {', '.join(assets)}")
        for asset in assets:
            entry = plan.get(asset, {})
            status = entry.get("plan_status", "missing")
            roots = entry.get("roots") or []
            strategy = entry.get("strategy") or "(no strategy recorded)"
            hours = entry.get("estimated_hours", 0)
            quota = entry.get("agent_hour_quota_pct", 0)
            waiver = entry.get("waiver")
            lines.append(
                f"- **{asset}** - plan_status=`{status}`, "
                f"planned_hours={hours}, agent_quota_pct={quota}"
            )
            if roots:
                lines.append(f"    - roots: {', '.join(f'`{r}`' for r in roots)}")
            lines.append(f"    - strategy: {strategy}")
            if waiver:
                lines.append(f"    - waiver: `{waiver}`")
    rust_roots = payload.get("rust_roots") or []
    if rust_roots:
        art = "present" if payload.get("summary", {}).get("rust_scan_artifact_present") else "missing"
        lines.append(f"- Rust roots detected: {len(rust_roots)} (scan-rust artifact: {art})")

    lines.extend(["", "## Severity And Rubric Coverage", ""])
    sources = payload.get("severity_sources") or []
    if sources:
        for source in sources:
            state = "placeholder" if source.get("placeholder") else "populated"
            lines.append(
                f"- `{source['path']}`: {state}, "
                f"{source.get('tier_count', 0)} tier keyword(s)"
            )
    else:
        lines.append("- No severity rubric source files detected")
    coverage = payload.get("rubric_coverage") or {}
    if coverage.get("present"):
        lines.append(
            f"- `RUBRIC_COVERAGE.md`: {coverage.get('row_count', 0)} row(s), "
            f"{coverage.get('not_checked_count', 0)} NOT CHECKED"
        )
        mentions = coverage.get("mentions_sources") or []
        if mentions:
            lines.append("- Rubric source citations: " + ", ".join(f"`{m}`" for m in mentions))
    else:
        lines.append("- `RUBRIC_COVERAGE.md`: missing")

    lines.extend(["", "## PDFs Missing Extracted Text", ""])
    missing = payload.get("pdfs_missing_extracted_text") or []
    if missing:
        for item in missing[:50]:
            lines.append(f"- `{item['pdf']}`")
    else:
        lines.append("- None")

    lines.extend(["", "## Scanner Artifacts", ""])
    for name, present in payload.get("scanner_artifacts", {}).items():
        status = "present" if present else "missing"
        lines.append(f"- `{name}`: {status}")

    lines.extend(["", "## Mechanical First Order", ""])
    for command in payload.get("recommended_mechanical_order", []):
        lines.append(f"- `{command}`")
    lines.append("")
    return "\n".join(lines)


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Write intake baseline artifacts before scanners/agents run."
    )
    parser.add_argument("workspace", type=Path)
    parser.add_argument("--out-json", type=Path)
    parser.add_argument("--out-md", type=Path)
    parser.add_argument("--json", action="store_true", help="print JSON to stdout")
    parser.add_argument(
        "--strict-operator-truth",
        action="store_true",
        help=(
            "fail intake when SCOPE/OOS/severity-cap operator truth is missing "
            "or placeholder"
        ),
    )
    args = parser.parse_args()

    workspace = args.workspace.expanduser().resolve()
    if not workspace.is_dir():
        parser.error(f"workspace not found: {workspace}")

    payload = build_baseline(
        workspace,
        strict_operator_truth=args.strict_operator_truth,
    )
    out_json = args.out_json or workspace / "INTAKE_BASELINE.json"
    out_md = args.out_md or workspace / "INTAKE_BASELINE.md"
    out_json.parent.mkdir(parents=True, exist_ok=True)
    out_md.parent.mkdir(parents=True, exist_ok=True)
    out_json.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n")
    out_md.write_text(render_markdown(payload))

    if args.json:
        print(json.dumps(payload, indent=2, sort_keys=True))
    else:
        summary = payload["summary"]
        print(
            "wrote "
            f"{out_json} and {out_md} "
            f"({summary['warning_count']} warning(s), "
            f"{summary['blocker_count']} blocker(s))"
        )
    return 2 if payload.get("blockers") else 0


if __name__ == "__main__":
    raise SystemExit(main())
