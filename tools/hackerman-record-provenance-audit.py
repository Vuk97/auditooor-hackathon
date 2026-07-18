#!/usr/bin/env python3
"""hackerman-record-provenance-audit.

Provenance-audit tool that verifies each hackerman corpus record carries
enough source-ref data to be REGENERATABLE from public sources. The audit
is purely a read-only crawl over `audit/corpus_tags/tags/` and writes a
machine-readable verdict ledger to `.auditooor/provenance_audit.jsonl`
(gitignored).

Sibling to `tools/hackerman-record-verification-tier-check.py` (which
audits ONLY the verification_tier:tier-N-* tag axis). This tool audits
FOUR independent axes:

  1. `source_audit_ref`: non-empty AND well-formed. Accepted forms:
     - URL (https://…)
     - git-mining repo-ref:        `git-mining:owner/repo@<sha>`
     - CVE-ID:                     `CVE-YYYY-NNNN+`
     - GHSA-ID:                    `GHSA-xxxx-xxxx-xxxx`
     - ASA-ID (Asymmetric/Audit):  `ASA-YYYY-NNNN`
     - Contest finding-id:         `code4rena:<slug>:<n>`,
                                   `sherlock:<slug>:<n>`,
                                   `solodit:<id>`
     - Audit-firm publication:     `audit-firm:<firm-slug>:<pdf-or-md-path>`
     - Solc / Vyper / zk-bug refs: `solc-bugs-json:*`, `zkbugs:*`,
                                   `zkbugtracker:*`
  2. `required_preconditions`: non-empty AND contains >=1 entry with a
     citation URL (http:// or https://). This is the *cite* axis - if
     no citation URL is present anywhere in preconditions, future
     regenerators have nothing to chase.
  3. `verification_tier`: exactly one `verification_tier:tier-N-*` tag in
     `function_shape.shape_tags`. Same regex as the sibling tier-check
     tool - `tier-[1-5]-<lowercase-slug>`.
  4. Tier-1 re-fetchability: when verification_tier is tier-1, the
     `source_audit_ref` must look like something a future agent can
     actually re-pull from a public API or archive in one shot - i.e.
     URL, GHSA-ID, CVE-ID, or contest finding-id. A bare audit-firm PDF
     ref (zellic-publications, pashov-audits, etc.) does NOT pass this
     stricter gate because PDFs are not REST-API-re-fetchable. The gate
     does not fetch the network; it asks "does the ref shape allow
     re-fetching?".

Outputs:

  - `.auditooor/provenance_audit.jsonl` - one JSON object per record,
    keys: file, record_id, subtree, source_audit_ref, source_ref_scheme,
    preconds_count, preconds_url_count, verification_tier,
    tier1_refetchable, gaps (list), verdict, reason.

  - Stdout: human or JSON summary (use --json for the machine envelope).

Exit codes:
    0  - pass (zero records with gaps OR --strict not set)
    1  - fail (under --strict, any record with gaps fails the audit)
    2  - error (corpus dir missing, unreadable, etc.)

Run:
    python3 tools/hackerman-record-provenance-audit.py
    python3 tools/hackerman-record-provenance-audit.py --json
    python3 tools/hackerman-record-provenance-audit.py --strict
"""
from __future__ import annotations

import argparse
import json
import re
import sys
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Tuple


SCHEMA = "auditooor.hackerman_record_provenance_audit.v1"
HACKERMAN_V1_SCHEMA = "auditooor.hackerman_record.v1"

REPO_ROOT_GUESS = Path(__file__).resolve().parent.parent
DEFAULT_TAGS_DIR = REPO_ROOT_GUESS / "audit" / "corpus_tags" / "tags"
DEFAULT_OUT_JSONL = REPO_ROOT_GUESS / ".auditooor" / "provenance_audit.jsonl"

QUARANTINE_PATH_MARKERS = (
    "_QUARANTINE_FABRICATED_CVE",
    "_QUARANTINE_FABRICATED",
    "_QUARANTINE_",
    "_deprecated",
)

VERIFICATION_TIER_VALUE_RE = re.compile(
    r"^verification_tier:(tier-[1-5]-[a-z0-9][a-z0-9-]*)$"
)

# Source-audit-ref well-formedness. Patterns are tried in order; first
# match wins. Each pattern carries a `scheme` label used in the per-record
# verdict and in the aggregate gap report.
SOURCE_REF_PATTERNS: List[Tuple[str, re.Pattern[str]]] = [
    ("url-https", re.compile(r"^https?://[^\s]+$")),
    ("git-mining", re.compile(r"^git-mining:[A-Za-z0-9._/-]+@[A-Fa-f0-9]{7,40}$")),
    ("cve-id", re.compile(r"^CVE-\d{4}-\d{4,7}$")),
    ("ghsa-id", re.compile(r"^GHSA-[a-z0-9]{4}-[a-z0-9]{4}-[a-z0-9]{4}$", re.IGNORECASE)),
    ("asa-id", re.compile(r"^ASA-\d{4}-\d{3,5}$", re.IGNORECASE)),
    ("code4rena", re.compile(r"^code4rena:[A-Za-z0-9._/-]+:[A-Za-z0-9._-]+$")),
    ("sherlock", re.compile(r"^sherlock:[A-Za-z0-9._/-]+:[A-Za-z0-9._-]+$")),
    ("solodit", re.compile(r"^solodit:[A-Za-z0-9._/-]+$")),
    # audit-firm refs reference repo-relative PDF/MD paths that frequently
    # contain spaces, parens, and unicode; we only require <firm-slug>:<path>
    # with a non-empty path portion.
    ("audit-firm", re.compile(r"^audit-firm:[A-Za-z0-9._-]+:.+\S$")),
    ("solc-bugs", re.compile(r"^solc-bugs-json:[A-Za-z0-9._/-]+$")),
    ("zkbugs", re.compile(r"^zkbugs:[A-Za-z0-9._/-]+$")),
    ("zkbugtracker", re.compile(r"^zkbugtracker:[A-Za-z0-9._/-]+$")),
    # Internal ETL scheme: any `<scheme>:<non-empty>` shape. Pipelines like
    # solodit-spec, solidity-fork-pattern, sig-extract, prior-audit,
    # corpus-mined, zk-auditor, mev-flashloan use these.
    # Catches everything not already matched above; the scheme name is the
    # prefix before the first `:`. We DO require at least one `:` separator
    # so a free-text title (e.g. a bare relative path) still fails as
    # malformed.
    ("internal-scheme", re.compile(r"^[a-z][a-z0-9_-]*:.+\S$")),
]

# Schemes that count as "tier-1 re-fetchable" - a future agent with an
# internet connection and (optionally) a GitHub token can pull this back.
# Audit-firm PDF refs are intentionally excluded: they're behind various
# repo paths and not REST-API-re-fetchable in one shot.
TIER1_REFETCHABLE_SCHEMES = {
    "url-https",
    "git-mining",
    "cve-id",
    "ghsa-id",
    "code4rena",
    "sherlock",
    "solodit",
}


URL_IN_PRECOND_RE = re.compile(r"https?://[^\s\"'<>)\]]+", re.IGNORECASE)


# --------------------------------------------------------------------------- #
# Record loading (mirrors hackerman-record-verification-tier-check.py)
# --------------------------------------------------------------------------- #


def _is_under_quarantine(path: Path, tags_dir: Path) -> bool:
    try:
        rel = path.resolve().relative_to(tags_dir.resolve())
    except ValueError:
        rel = path
    for part in rel.parts:
        upart = part.upper()
        for marker in QUARANTINE_PATH_MARKERS:
            if marker.upper() in upart:
                return True
    return False


def _subtree_of(path: Path, tags_dir: Path) -> str:
    """Return the immediate child of tags_dir that contains `path`."""
    try:
        rel = path.resolve().relative_to(tags_dir.resolve())
    except ValueError:
        return "<unknown>"
    parts = rel.parts
    if not parts:
        return "<root>"
    return parts[0]


def _iter_record_files(tags_dir: Path) -> Iterable[Path]:
    if not tags_dir.exists():
        return
    for path in sorted(tags_dir.rglob("*")):
        if not path.is_file():
            continue
        name = path.name.lower()
        if name == "readme.md":
            continue
        if name in {"record.yaml", "record.json"}:
            yield path
            continue
        if path.suffix.lower() == ".yaml" and path.parent == tags_dir:
            yield path
            continue
        if path.suffix.lower() == ".yaml" and path.parent != tags_dir:
            sibling_record = path.parent / "record.yaml"
            if sibling_record.exists() and sibling_record != path:
                continue
            yield path


def _strip_yaml_quotes(value: str) -> str:
    v = value.strip()
    if len(v) >= 2 and ((v[0] == '"' and v[-1] == '"') or (v[0] == "'" and v[-1] == "'")):
        return v[1:-1]
    return v


def _parse_record(text: str, fmt: str) -> Dict[str, Any]:
    """Return a dict with: schema_version, record_id, source_audit_ref,
    required_preconditions (list[str]), shape_tags (list[str])."""
    if fmt == "json":
        try:
            payload = json.loads(text)
        except json.JSONDecodeError:
            return {}
        out = {
            "schema_version": payload.get("schema_version"),
            "record_id": payload.get("record_id"),
            "source_audit_ref": payload.get("source_audit_ref"),
            "required_preconditions": payload.get("required_preconditions") or [],
            "shape_tags": ((payload.get("function_shape") or {}).get("shape_tags")) or [],
        }
        if not isinstance(out["required_preconditions"], list):
            out["required_preconditions"] = []
        if not isinstance(out["shape_tags"], list):
            out["shape_tags"] = []
        out["required_preconditions"] = [str(x) for x in out["required_preconditions"]]
        out["shape_tags"] = [str(x) for x in out["shape_tags"]]
        return out

    # Minimal YAML - no PyYAML dependency. Handles flat scalars,
    # function_shape.shape_tags (list), required_preconditions (list).
    schema_version: Optional[str] = None
    record_id: Optional[str] = None
    source_audit_ref: Optional[str] = None
    preconds: List[str] = []
    shape_tags: List[str] = []

    lines = text.splitlines()
    in_fs = False
    in_fs_tags = False
    fs_tags_indent: Optional[int] = None
    in_preconds = False
    preconds_indent: Optional[int] = None

    for raw in lines:
        if not raw.strip():
            continue
        stripped = raw.strip()
        is_top = not raw.startswith(" ") and not raw.startswith("\t")
        indent = len(raw) - len(raw.lstrip(" "))

        if is_top:
            # Top-level key resets nested states.
            in_fs = in_fs_tags = False
            in_preconds = False
            if stripped.startswith("schema_version:"):
                _, _, rhs = stripped.partition(":")
                schema_version = _strip_yaml_quotes(rhs.strip())
            elif stripped.startswith("record_id:"):
                _, _, rhs = stripped.partition(":")
                record_id = _strip_yaml_quotes(rhs.strip())
            elif stripped.startswith("source_audit_ref:"):
                _, _, rhs = stripped.partition(":")
                source_audit_ref = _strip_yaml_quotes(rhs.strip())
            elif stripped.startswith("function_shape:"):
                in_fs = True
            elif stripped.startswith("required_preconditions:"):
                in_preconds = True
                preconds_indent = indent
            continue

        # Indented lines
        if in_fs:
            if stripped.startswith("shape_tags:"):
                in_fs_tags = True
                fs_tags_indent = indent
                continue
            if in_fs_tags:
                if stripped.startswith("- "):
                    if fs_tags_indent is not None and indent >= fs_tags_indent:
                        shape_tags.append(_strip_yaml_quotes(stripped[2:].strip()))
                        continue
                    else:
                        in_fs_tags = False
                else:
                    if fs_tags_indent is not None and indent <= fs_tags_indent:
                        in_fs_tags = False
        if in_preconds:
            if stripped.startswith("- "):
                if preconds_indent is not None and indent > preconds_indent:
                    preconds.append(_strip_yaml_quotes(stripped[2:].strip()))
                    continue
                else:
                    in_preconds = False
            else:
                if preconds_indent is not None and indent <= preconds_indent:
                    in_preconds = False

    return {
        "schema_version": schema_version,
        "record_id": record_id,
        "source_audit_ref": source_audit_ref,
        "required_preconditions": preconds,
        "shape_tags": shape_tags,
    }


# --------------------------------------------------------------------------- #
# Per-axis checks
# --------------------------------------------------------------------------- #


def classify_source_ref(ref: Optional[str]) -> Tuple[Optional[str], bool]:
    """Return (scheme, well_formed). When `ref` is empty, returns (None, False)."""
    if not ref or not str(ref).strip():
        return None, False
    v = str(ref).strip()
    for scheme, pattern in SOURCE_REF_PATTERNS:
        if pattern.match(v):
            return scheme, True
    return None, False


def count_url_preconds(preconds: List[str]) -> int:
    return sum(1 for p in preconds if URL_IN_PRECOND_RE.search(str(p)))


def extract_verification_tier(shape_tags: List[str]) -> Optional[str]:
    strict_hits = [t for t in shape_tags if VERIFICATION_TIER_VALUE_RE.match(str(t).strip())]
    if not strict_hits:
        return None
    m = VERIFICATION_TIER_VALUE_RE.match(strict_hits[0].strip())
    return m.group(1) if m else None


# --------------------------------------------------------------------------- #
# Per-record audit
# --------------------------------------------------------------------------- #


# Verdicts:
#   pass                 - record has full provenance and passes all 4 axes
#   pass-quarantine      - record is in _QUARANTINE_* subtree; not audited
#   skipped-non-v1       - record is not a hackerman v1 schema
#   gaps                 - one or more provenance gaps (see gaps[] list)
#   error                - unreadable file


def audit_record(path: Path, tags_dir: Path) -> Dict[str, Any]:
    fmt = "json" if path.suffix.lower() == ".json" else "yaml"
    subtree = _subtree_of(path, tags_dir)
    quarantine = _is_under_quarantine(path, tags_dir)
    base: Dict[str, Any] = {
        "file": str(path),
        "subtree": subtree,
        "record_id": None,
        "schema_version": None,
        "source_audit_ref": None,
        "source_ref_scheme": None,
        "preconds_count": 0,
        "preconds_url_count": 0,
        "verification_tier": None,
        "tier1_refetchable": None,
        "quarantine": quarantine,
        "gaps": [],
        "verdict": "pass",
        "reason": "",
    }

    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError as exc:
        base["verdict"] = "error"
        base["reason"] = f"unreadable: {exc}"
        return base

    parsed = _parse_record(text, fmt)
    base["schema_version"] = parsed.get("schema_version")
    base["record_id"] = parsed.get("record_id")

    if parsed.get("schema_version") != HACKERMAN_V1_SCHEMA:
        base["verdict"] = "skipped-non-v1"
        base["reason"] = f"schema_version={parsed.get('schema_version')!r}; out of audit scope"
        return base

    if quarantine:
        base["verdict"] = "pass-quarantine"
        base["reason"] = "record sits under quarantine/deprecated subtree; provenance not audited"
        return base

    # Axis 1: source_audit_ref well-formedness
    ref = parsed.get("source_audit_ref")
    base["source_audit_ref"] = ref
    scheme, well_formed = classify_source_ref(ref)
    base["source_ref_scheme"] = scheme
    if not ref or not str(ref).strip():
        base["gaps"].append("empty-source-audit-ref")
    elif not well_formed:
        base["gaps"].append("malformed-source-audit-ref")

    # Axis 2: required_preconditions has >=1 URL
    preconds = parsed.get("required_preconditions") or []
    base["preconds_count"] = len(preconds)
    url_count = count_url_preconds(preconds)
    base["preconds_url_count"] = url_count
    if not preconds:
        base["gaps"].append("empty-required-preconditions")
    elif url_count == 0:
        base["gaps"].append("no-url-citation-in-preconditions")

    # Axis 3: verification_tier present
    tier = extract_verification_tier(parsed.get("shape_tags") or [])
    base["verification_tier"] = tier
    if not tier:
        base["gaps"].append("missing-verification-tier")

    # Axis 4: tier-1 re-fetchability
    if tier and tier.startswith("tier-1-"):
        refetchable = scheme in TIER1_REFETCHABLE_SCHEMES
        base["tier1_refetchable"] = refetchable
        if not refetchable:
            base["gaps"].append("tier1-not-refetchable")

    if base["gaps"]:
        base["verdict"] = "gaps"
        base["reason"] = ",".join(base["gaps"])
    else:
        base["verdict"] = "pass"
        base["reason"] = (
            f"scheme={scheme} preconds={len(preconds)} url-cites={url_count} tier={tier}"
        )
    return base


# --------------------------------------------------------------------------- #
# Driver
# --------------------------------------------------------------------------- #


PASS_VERDICTS = {"pass", "pass-quarantine", "skipped-non-v1"}
FAIL_VERDICTS = {"gaps", "error"}


def run(
    tags_dir: Path,
    *,
    out_jsonl: Optional[Path] = None,
    limit: Optional[int] = None,
    strict: bool = False,
    fail_on_missing_dir: bool = True,
) -> Tuple[int, Dict[str, Any]]:
    payload: Dict[str, Any] = {
        "schema": SCHEMA,
        "generated_at": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
        "tags_dir": str(tags_dir),
        "out_jsonl": str(out_jsonl) if out_jsonl else None,
        "scanned": 0,
        "audited_hackerman_v1": 0,
        "skipped_non_v1": 0,
        "quarantine": 0,
        "verdict_counts": {},
        "subtree_counts": {},
        "gap_counts": {},
        "scheme_counts": {},
        "tier_counts": {},
        "failed_records": [],
        "verdict": "pass",
        "reason": "",
    }

    if not tags_dir.exists():
        payload["verdict"] = "error"
        payload["reason"] = f"tags dir does not exist: {tags_dir}"
        return (2 if fail_on_missing_dir else 0), payload

    scanned = 0
    verdict_counter: Counter[str] = Counter()
    subtree_pf: Dict[str, Counter[str]] = {}
    gap_counter: Counter[str] = Counter()
    scheme_counter: Counter[str] = Counter()
    tier_counter: Counter[str] = Counter()
    failed: List[Dict[str, Any]] = []

    jsonl_lines: List[str] = []

    for record_path in _iter_record_files(tags_dir):
        scanned += 1
        if limit is not None and scanned > limit:
            scanned -= 1
            break
        audit = audit_record(record_path, tags_dir)
        verdict_counter[audit["verdict"]] += 1
        subtree = audit["subtree"]
        if subtree not in subtree_pf:
            subtree_pf[subtree] = Counter()
        subtree_pf[subtree][audit["verdict"]] += 1
        for gap in audit["gaps"]:
            gap_counter[gap] += 1
        if audit.get("source_ref_scheme"):
            scheme_counter[audit["source_ref_scheme"]] += 1
        if audit.get("verification_tier"):
            tier_counter[audit["verification_tier"]] += 1
        if audit["verdict"] == "gaps":
            failed.append(audit)
        jsonl_lines.append(json.dumps(audit, sort_keys=True))

    payload["scanned"] = scanned
    payload["skipped_non_v1"] = verdict_counter.get("skipped-non-v1", 0)
    payload["quarantine"] = verdict_counter.get("pass-quarantine", 0)
    payload["audited_hackerman_v1"] = (
        scanned - payload["skipped_non_v1"] - payload["quarantine"]
    )
    payload["verdict_counts"] = dict(verdict_counter)
    payload["subtree_counts"] = {
        s: dict(c) for s, c in sorted(subtree_pf.items())
    }
    payload["gap_counts"] = dict(gap_counter.most_common())
    payload["scheme_counts"] = dict(scheme_counter.most_common())
    payload["tier_counts"] = dict(tier_counter.most_common())
    payload["failed_records"] = failed[:200]

    if out_jsonl is not None:
        out_jsonl.parent.mkdir(parents=True, exist_ok=True)
        out_jsonl.write_text("\n".join(jsonl_lines) + ("\n" if jsonl_lines else ""), encoding="utf-8")

    gaps_count = verdict_counter.get("gaps", 0)
    err_count = verdict_counter.get("error", 0)
    if gaps_count == 0 and err_count == 0:
        payload["verdict"] = "pass"
        payload["reason"] = (
            f"audited={payload['audited_hackerman_v1']} all records carry "
            f"full provenance (source_audit_ref + url-cite + verification_tier)"
        )
        return 0, payload

    parts: List[str] = []
    if gaps_count:
        parts.append(f"{gaps_count} record(s) with provenance gaps")
    if err_count:
        parts.append(f"{err_count} unreadable record(s)")
    payload["reason"] = "; ".join(parts)
    if strict:
        payload["verdict"] = "fail"
        return 1, payload
    payload["verdict"] = "pass-with-gaps"
    return 0, payload


# --------------------------------------------------------------------------- #
# Output
# --------------------------------------------------------------------------- #


def _print_human(payload: Dict[str, Any]) -> None:
    print("# hackerman-record-provenance-audit")
    print(f"tags_dir:    {payload['tags_dir']}")
    if payload.get("out_jsonl"):
        print(f"out_jsonl:   {payload['out_jsonl']}")
    print(f"scanned:     {payload['scanned']}")
    print(f"audited:     {payload['audited_hackerman_v1']} (hackerman v1, non-quarantine)")
    print(f"quarantine:  {payload['quarantine']}")
    print(f"skipped:     {payload['skipped_non_v1']} (non-hackerman-v1)")
    print()
    print("# verdict_counts")
    for verdict, count in sorted(payload["verdict_counts"].items()):
        print(f"  {verdict:<22} {count:>7}")
    if payload.get("gap_counts"):
        print()
        print("# top gap_counts")
        for i, (gap, count) in enumerate(list(payload["gap_counts"].items())[:10]):
            print(f"  {gap:<40} {count:>7}")
    if payload.get("scheme_counts"):
        print()
        print("# source_ref scheme_counts")
        for scheme, count in payload["scheme_counts"].items():
            print(f"  {scheme:<24} {count:>7}")
    if payload.get("subtree_counts"):
        print()
        print("# per-subtree pass/fail (top 12)")
        subtree_items = sorted(
            payload["subtree_counts"].items(),
            key=lambda kv: -(kv[1].get("gaps", 0)),
        )
        for subtree, counts in subtree_items[:12]:
            gaps = counts.get("gaps", 0)
            ok = counts.get("pass", 0) + counts.get("pass-quarantine", 0)
            skipped = counts.get("skipped-non-v1", 0)
            print(f"  {subtree:<40} pass={ok:>5} gaps={gaps:>5} skip={skipped:>5}")
    failed = payload.get("failed_records") or []
    if failed:
        print()
        print("# example failed_records (first 5)")
        for entry in failed[:5]:
            print(f"  - {entry.get('record_id') or '?':<55} {entry['file']}")
            print(f"      gaps: {','.join(entry.get('gaps') or [])}")
    print()
    print(f"verdict: {payload['verdict']}")
    if payload.get("reason"):
        print(f"reason:  {payload['reason']}")


def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n", 1)[0])
    parser.add_argument(
        "--tags-dir",
        type=Path,
        default=DEFAULT_TAGS_DIR,
        help="Directory of hackerman corpus tag records.",
    )
    parser.add_argument(
        "--out-jsonl",
        type=Path,
        default=DEFAULT_OUT_JSONL,
        help="Path to emit per-record audit ledger (default .auditooor/provenance_audit.jsonl).",
    )
    parser.add_argument(
        "--no-jsonl",
        action="store_true",
        help="Suppress writing the jsonl ledger.",
    )
    parser.add_argument(
        "--limit",
        type=int,
        default=None,
        help="Cap scanned files (for smoke / CI sanity).",
    )
    parser.add_argument(
        "--strict",
        action="store_true",
        help="Exit non-zero when any record has provenance gaps.",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="Emit the full JSON payload on stdout (silences the human report).",
    )
    parser.add_argument(
        "--allow-missing-tags-dir",
        action="store_true",
        help="When the corpus dir is missing, exit 0 with a warning instead of error.",
    )
    args = parser.parse_args(argv)

    out_jsonl = None if args.no_jsonl else args.out_jsonl.expanduser()

    rc, payload = run(
        args.tags_dir.expanduser(),
        out_jsonl=out_jsonl,
        limit=args.limit,
        strict=args.strict,
        fail_on_missing_dir=not args.allow_missing_tags_dir,
    )

    if args.json:
        json.dump(payload, sys.stdout, sort_keys=True, indent=2)
        sys.stdout.write("\n")
    else:
        _print_human(payload)
    return rc


if __name__ == "__main__":
    sys.exit(main())
