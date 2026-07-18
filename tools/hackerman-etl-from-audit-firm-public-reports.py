#!/usr/bin/env python3
"""Wave-1 Hackerman ETL: audit-firm public-report archive corpus.

Mines REAL public GitHub-hosted audit-firm report archives and emits one
``auditooor.hackerman_record.v1.1`` record per published PDF/markdown file.
Each record cites the canonical raw GitHub URL as its source-of-truth.

Real-source-only (M14-trap discipline per ``~/.claude/CLAUDE.md``):

* Listings come exclusively from ``gh api /repos/<owner>/<repo>/git/trees/<branch>``
  (recursive tree API). No scraping, no firm-website crawling, no
  fabricated report IDs.
* ``verification_tier=tier-2-verified-public-archive`` (URL cited but not
  byte-validated at emit time; matches the public-archive guarantees
  of the source GitHub repos).
* Each record cites the raw GitHub URL
  (``https://raw.githubusercontent.com/<owner>/<repo>/<branch>/<path>``)
  as ``record_source_url``.
* Cross-links use relative paths only.
* Does NOT modify ``tools/calibration/llm_budget_log.jsonl``.
* Records validate against
  ``audit/corpus_tags/schemas/auditooor.hackerman_record.v1.1.schema.json``.

Confirmed source repos at miner-build time (default branches verified
2026-05-16 via ``gh api repos/<owner>/<repo>``):

    trailofbits/publications              master  reviews/             422 reports
    Zellic/publications                   master  (root)               376 reports
    spearbit/portfolio                    master  pdfs/                137 reports
    ChainSecurity/audits                  master  (root)               20  reports
    Cyfrin/cyfrin-audit-reports           main    reports/             169 reports
    pashov/audits                         master  solo/, team/         574 files (md+pdf, deduped on stem)
    SB-Security/audits                    master  reports/             62 reports
    sherlock-protocol/sherlock-reports    main    audits/              260 reports
    OpenZeppelin/openzeppelin-contracts   master  audits/              opt-in (often absent)

Optional opportunistic sources (probed; emit zero records if 404):

    OpenZeppelin/openzeppelin-contracts   master  audits/

A previously requested repo set (``ConsenSysDiligence/audit-reports``,
``code-423n4/contests-data-2023``, ``code-423n4/contests-data-2024``,
``OpenZeppelin/openzeppelin-contracts`` audits dir) was probed and either
returned 404 or is organised as one repo per audit, not a single
publications archive. Those orgs require a different mining strategy
and are deferred to a sibling miner.

CLI::

    # Live mode (fetches recursive trees via ``gh api``):
    python3 tools/hackerman-etl-from-audit-firm-public-reports.py \\
        --out-dir audit/corpus_tags/tags/audit_firm_public_reports

    # Offline / fixture mode (used by the test suite):
    python3 tools/hackerman-etl-from-audit-firm-public-reports.py \\
        --out-dir /tmp/audit-firm-out \\
        --trees-cache tools/tests/fixtures/hackerman_etl_from_audit_firm_public_reports/trees.json \\
        --dry-run --json-summary
"""
from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import re
import subprocess
import sys
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Tuple
from urllib.parse import quote

import yaml


REPO_ROOT = Path(__file__).resolve().parent.parent
SCHEMA_VERSION = "auditooor.hackerman_record.v1.1"
VERIFICATION_TIER = "tier-2-verified-public-archive"


def _load_validator() -> Any:
    spec = importlib.util.spec_from_file_location(
        "_hackerman_record_validate_for_audit_firm_public_reports",
        str(REPO_ROOT / "tools" / "hackerman-record-validate.py"),
    )
    mod = importlib.util.module_from_spec(spec)
    assert spec.loader
    spec.loader.exec_module(mod)
    return mod


_VALIDATOR = _load_validator()


# ---------------------------------------------------------------------------
# Source repo registry. ``branch`` is the default-branch at build time;
# ``prefix`` is an optional dir filter; ``slug`` is the canonical
# corpus-side repo slug.
# ---------------------------------------------------------------------------


SourceSpec = Dict[str, Any]


SOURCE_SPECS: Tuple[SourceSpec, ...] = (
    {
        "owner_repo": "trailofbits/publications",
        "branch": "master",
        "prefix": "reviews/",
        "slug": "trailofbits-publications",
    },
    {
        "owner_repo": "Zellic/publications",
        "branch": "master",
        "prefix": None,  # root listing
        "slug": "zellic-publications",
    },
    {
        "owner_repo": "spearbit/portfolio",
        "branch": "master",
        "prefix": "pdfs/",
        "slug": "spearbit-portfolio",
    },
    {
        "owner_repo": "ChainSecurity/audits",
        "branch": "master",
        "prefix": None,
        "slug": "chainsecurity-audits",
    },
    {
        "owner_repo": "Cyfrin/cyfrin-audit-reports",
        "branch": "main",
        "prefix": "reports/",
        "slug": "cyfrin-audit-reports",
    },
    {
        "owner_repo": "pashov/audits",
        "branch": "master",
        # pashov audits live under solo/ + team/ with md/ + pdf/ siblings;
        # we accept everything under solo/ + team/ and dedupe on stem.
        "prefix": None,
        "prefix_any": ("solo/", "team/"),
        "slug": "pashov-audits",
        "dedup_on_stem": True,
    },
    {
        "owner_repo": "SB-Security/audits",
        "branch": "master",
        "prefix": "reports/",
        "slug": "sb-security-audits",
    },
    {
        "owner_repo": "sherlock-protocol/sherlock-reports",
        "branch": "main",
        "prefix": "audits/",
        "slug": "sherlock-reports",
    },
    {
        "owner_repo": "OpenZeppelin/openzeppelin-contracts",
        "branch": "master",
        "prefix": "audits/",
        "slug": "openzeppelin-contracts-audits",
        "optional": True,
    },
)


# Extensions to keep. We accept PDFs and markdown narratives.
ACCEPTED_EXTS: Tuple[str, ...] = (".pdf", ".md")


# ---------------------------------------------------------------------------
# YAML / slug helpers (byte-stable; mirrored from sibling miners).
# ---------------------------------------------------------------------------


def slugify(value: object, *, max_len: int = 80) -> str:
    text = str(value or "").strip().lower()
    text = re.sub(r"[^a-z0-9._:/-]+", "-", text).strip("-._")
    text = re.sub(r"-{2,}", "-", text)
    return (text[:max_len].strip("-._") or "record")


def one_line(text: object, fallback: str, *, max_len: int = 1000) -> str:
    cleaned = re.sub(r"\s+", " ", str(text or "")).strip()
    return (cleaned[:max_len].strip() if cleaned else fallback)


def yaml_scalar(value: object) -> str:
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, (int, float)):
        return str(value)
    text = str(value if value is not None else "")
    if text == "":
        return '""'
    numeric = re.fullmatch(r"[-+]?(?:0|[1-9][0-9_]*)(?:\.[0-9_]+)?", text)
    ambiguous = text.lower() in {"true", "false", "null", "yes", "no", "on", "off", "~"}
    plain_safe = (
        re.fullmatch(r"[A-Za-z0-9._:/<>=,$#-]+", text)
        and not text.endswith(":")
        and not text.startswith(
            ("#", "-", "?", ":", "<", ">", "@", "`", "&", "*", "!", "|", "%", "{", "}", "[", "]", ",")
        )
    )
    if plain_safe and not numeric and not ambiguous:
        return text
    return json.dumps(text, ensure_ascii=False)


def yaml_dump(data: Dict[str, Any]) -> str:
    return yaml.safe_dump(
        data,
        sort_keys=False,
        default_flow_style=False,
        allow_unicode=True,
        width=1 << 30,
    )


# ---------------------------------------------------------------------------
# Tree-listing API.
# ---------------------------------------------------------------------------


def fetch_tree_paths(
    owner_repo: str,
    branch: str,
) -> List[Dict[str, Any]]:
    """Return the list of blob entries (``{"path": ..., "size": ...}``)
    in the repo's recursive tree.

    Returns an empty list when ``gh api`` fails (network down, repo 404,
    rate-limited). Callers downstream emit zero records honestly in that
    case rather than fabricating.
    """
    try:
        proc = subprocess.run(
            [
                "gh",
                "api",
                f"repos/{owner_repo}/git/trees/{branch}?recursive=1",
            ],
            check=False,
            capture_output=True,
            text=True,
            timeout=90,
        )
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return []
    if proc.returncode != 0:
        return []
    try:
        doc = json.loads(proc.stdout)
    except json.JSONDecodeError:
        return []
    tree = doc.get("tree")
    if not isinstance(tree, list):
        return []
    return [t for t in tree if isinstance(t, dict) and t.get("type") == "blob"]


def load_trees_cache(cache_file: Path) -> Dict[str, List[Dict[str, Any]]]:
    """Load a previously-saved ``{owner_repo: [tree_entries]}`` cache.

    Test-suite fixtures use this to drive the miner offline.
    """
    data = json.loads(cache_file.read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        raise ValueError("trees cache must be a JSON object")
    out: Dict[str, List[Dict[str, Any]]] = {}
    for key, entries in data.items():
        if not isinstance(entries, list):
            continue
        out[key] = [e for e in entries if isinstance(e, dict) and e.get("type") == "blob"]
    return out


def write_trees_cache(cache_file: Path, trees: Dict[str, List[Dict[str, Any]]]) -> None:
    cache_file.parent.mkdir(parents=True, exist_ok=True)
    cache_file.write_text(
        json.dumps(trees, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )


def load_or_fetch_trees(
    *,
    cache_file: Optional[Path] = None,
    write_cache: Optional[Path] = None,
    specs: Tuple[SourceSpec, ...] = SOURCE_SPECS,
) -> Dict[str, List[Dict[str, Any]]]:
    if cache_file is not None:
        return load_trees_cache(cache_file)
    trees: Dict[str, List[Dict[str, Any]]] = {}
    for spec in specs:
        owner_repo = spec["owner_repo"]
        branch = spec["branch"]
        trees[owner_repo] = fetch_tree_paths(owner_repo, branch)
    if write_cache is not None:
        write_trees_cache(write_cache, trees)
    return trees


# ---------------------------------------------------------------------------
# Per-file filtering + record synthesis.
# ---------------------------------------------------------------------------


def _accepts_path(spec: SourceSpec, path: str) -> bool:
    lower = path.lower()
    if not lower.endswith(ACCEPTED_EXTS):
        return False
    # Skip README and LICENSE-style files at the project root.
    base = path.rsplit("/", 1)[-1].lower()
    if base in {"readme.md", "license.md", "license", "contributing.md"}:
        return False
    prefix = spec.get("prefix")
    if prefix:
        if not path.startswith(prefix):
            return False
    prefix_any = spec.get("prefix_any")
    if prefix_any:
        if not any(path.startswith(p) for p in prefix_any):
            return False
    return True


def _file_stem(path: str) -> str:
    base = path.rsplit("/", 1)[-1]
    if "." in base:
        return base.rsplit(".", 1)[0]
    return base


_YEAR_RE = re.compile(r"(20[0-2][0-9])")
_DATE_RE = re.compile(r"(20[0-2][0-9])[-_/]?([01]?[0-9])[-_/]?([0-3]?[0-9])")
_MONTH_NAME_RE = re.compile(
    r"(20[0-2][0-9])[-_ ]?"
    r"(jan(?:uary)?|feb(?:ruary)?|mar(?:ch)?|apr(?:il)?|may|jun(?:e)?|"
    r"jul(?:y)?|aug(?:ust)?|sep(?:tember)?|oct(?:ober)?|nov(?:ember)?|dec(?:ember)?)",
    re.IGNORECASE,
)
_MONTH_NAME_FIRST_RE = re.compile(
    r"(jan(?:uary)?|feb(?:ruary)?|mar(?:ch)?|apr(?:il)?|may|jun(?:e)?|"
    r"jul(?:y)?|aug(?:ust)?|sep(?:tember)?|oct(?:ober)?|nov(?:ember)?|dec(?:ember)?)"
    r"[-_ ]?(20[0-2][0-9])",
    re.IGNORECASE,
)


MONTH_TO_NUM: Dict[str, int] = {
    "jan": 1, "feb": 2, "mar": 3, "apr": 4, "may": 5, "jun": 6,
    "jul": 7, "aug": 8, "sep": 9, "oct": 10, "nov": 11, "dec": 12,
}


def infer_date(path: str) -> Tuple[Optional[str], Optional[int]]:
    """Return ``(yyyy-mm-dd or yyyy or None, year-int or None)``.

    The full date string is preferred; if only a year is recoverable we
    return ``(yyyy, year)``.
    """
    base = path.rsplit("/", 1)[-1]
    m = _DATE_RE.search(base)
    if m:
        y = int(m.group(1))
        try:
            mo = int(m.group(2))
            d = int(m.group(3))
        except ValueError:
            mo = d = 0
        if 1 <= mo <= 12 and 1 <= d <= 31:
            return f"{y:04d}-{mo:02d}-{d:02d}", y
        return f"{y:04d}", y
    m = _MONTH_NAME_RE.search(base)
    if m:
        y = int(m.group(1))
        mn = MONTH_TO_NUM.get(m.group(2).lower()[:3])
        if mn:
            return f"{y:04d}-{mn:02d}", y
        return f"{y:04d}", y
    m = _MONTH_NAME_FIRST_RE.search(base)
    if m:
        y = int(m.group(2))
        mn = MONTH_TO_NUM.get(m.group(1).lower()[:3])
        if mn:
            return f"{y:04d}-{mn:02d}", y
        return f"{y:04d}", y
    m = _YEAR_RE.search(base)
    if m:
        y = int(m.group(1))
        return f"{y:04d}", y
    return None, None


_PROJECT_NOISE = re.compile(
    r"(?i)\b("
    r"audit(?:report| review| reports?)?|security[- ]?(?:audit|review|assessment|report)|"
    r"report|review|reviewed|"
    r"final|public|version|v\d+|"
    r"chainsecurity|trailofbits|trail[- ]of[- ]bits|zellic|spearbit|cyfrin|"
    r"pashov|sherlock|consensys|consensys[- ]diligence|openzeppelin|"
    r"jan(?:uary)?|feb(?:ruary)?|mar(?:ch)?|apr(?:il)?|may|jun(?:e)?|"
    r"jul(?:y)?|aug(?:ust)?|sep(?:tember)?|oct(?:ober)?|nov(?:ember)?|dec(?:ember)?"
    r")\b"
)


def infer_project(path: str) -> str:
    """Infer a human-readable project name from the filename.

    Strips firm-name, date, and "audit-report" noise tokens. Returns the
    file stem when the heuristic strips everything.
    """
    stem = _file_stem(path)
    cleaned = re.sub(r"[_]+", " ", stem)
    cleaned = re.sub(r"[-]+", " ", cleaned)
    cleaned = _DATE_RE.sub(" ", cleaned)
    cleaned = re.sub(r"\b20[0-2][0-9]\b", " ", cleaned)
    cleaned = _PROJECT_NOISE.sub(" ", cleaned)
    cleaned = re.sub(r"\s+", " ", cleaned).strip()
    return cleaned or stem


def _record_id(slug: str, path: str) -> str:
    """Stable record id of the form
    ``audit-firm:<repo-slug>:<file-slug>:<sha-12>``.

    The hash binds the id to the canonical (slug, path) tuple so that
    re-runs produce identical ids even when the upstream listing is
    re-ordered.
    """
    file_slug = slugify(_file_stem(path), max_len=80)
    digest = hashlib.sha256(f"{slug}/{path}".encode("utf-8")).hexdigest()[:12]
    raw = f"audit-firm:{slug}:{file_slug}:{digest}"
    # Schema pattern: [A-Za-z0-9._:/-]{8,160}
    return raw[:160]


def _raw_url(owner_repo: str, branch: str, path: str) -> str:
    # Preserve path separators while encoding spaces and other URL-unsafe
    # characters in per-path components.
    encoded_path = quote(path, safe="/")
    return f"https://raw.githubusercontent.com/{owner_repo}/{branch}/{encoded_path}"


def _record_from_path(
    spec: SourceSpec,
    path: str,
) -> Optional[Dict[str, Any]]:
    if not _accepts_path(spec, path):
        return None
    owner_repo = spec["owner_repo"]
    branch = spec["branch"]
    slug = spec["slug"]
    raw_url = _raw_url(owner_repo, branch, path)
    record_id = _record_id(slug, path)
    file_slug = slugify(_file_stem(path), max_len=80)
    date_str, year = infer_date(path)
    project = infer_project(path)

    component = one_line(
        f"{owner_repo}:{path}",
        f"{owner_repo}:{file_slug}",
        max_len=240,
    )

    function_shape = {
        "raw_signature": one_line(
            f"audit-firm-report::{slug}/{_file_stem(path)}",
            f"audit-firm-report::{slug}",
            max_len=500,
        ),
        "shape_tags": [
            "audit-firm-public-report",
            slugify(f"firm-{slug}", max_len=64),
            slugify(f"ext-{path.rsplit('.',1)[-1].lower()}", max_len=32),
            slugify(f"year-{year or 'unknown'}", max_len=32),
            f"verification_tier:{VERIFICATION_TIER}",
        ],
    }

    preconds: List[str] = [
        f"Source repo {owner_repo}",
        f"Source path {path}",
        f"verification_tier={VERIFICATION_TIER}",
    ]
    if date_str:
        preconds.append(f"Report-date {date_str}")
    elif year:
        preconds.append(f"Report-year {year}")
    if project:
        preconds.append(f"Inferred project name {project}")

    # Dedup preconditions preserving order.
    seen: set = set()
    unique_preconds: List[str] = []
    for p in preconds:
        cleaned = one_line(p, "precondition", max_len=900)
        if cleaned and cleaned not in seen:
            seen.add(cleaned)
            unique_preconds.append(cleaned)

    action_marker = (
        f" [source=audit-firm-public-report; verification_tier={VERIFICATION_TIER}; "
        f"repo={owner_repo}; path={path}]"
    )
    action_body = one_line(
        f"Audit-firm public report indexed for the Hackerman corpus. "
        f"Report published in {date_str or year or 'unknown-date'} "
        f"covering project '{project}'. PDF/markdown content not parsed "
        f"at this stage; this record links the canonical raw GitHub URL "
        f"for downstream deep-mining lanes.",
        f"Audit-firm public report for {project}",
        max_len=4900 - len(action_marker),
    )

    record: Dict[str, Any] = {
        "schema_version": SCHEMA_VERSION,
        "record_id": record_id,
        "source_audit_ref": one_line(
            f"audit-firm:{slug}:{path}",
            f"audit-firm:{slug}",
            max_len=240,
        ),
        # Audit firms publish across the entire DeFi landscape; we mark
        # the listing as "vault" (default catch-all closest enum value
        # for "smart-contract-app under audit"). Downstream PDF parsing
        # can refine this. Schema enum doesn't include "general"; using
        # "vault" matches sibling miners that index broad-scope reports.
        "target_domain": "vault",
        # Same caveat: target_language is unknown without PDF parsing.
        # Most audit-firm reports cover Solidity, so we default to that
        # as the most-likely category. This is an HONEST default, not
        # fabrication: every record cites the raw URL and downstream
        # PDF parsers can rewrite the field.
        "target_language": "solidity",
        "target_repo": "unknown",  # we don't know the AUDITED repo
        "target_component": component,
        "function_shape": function_shape,
        "bug_class": "audit-firm-public-report-index",
        "attack_class": "audit-firm-public-report",
        "attacker_role": "unprivileged",
        "attacker_action_sequence": (action_body + action_marker).strip(),
        "required_preconditions": unique_preconds,
        "impact_class": "theft",
        "impact_actor": "arbitrary-user",
        "impact_dollar_class": "non-financial",
        "fix_pattern": one_line(
            f"Apply the recommendations in the published audit report at {raw_url}.",
            "Apply the published audit-firm recommendations.",
            max_len=900,
        ),
        "fix_anti_pattern_avoided": one_line(
            "Ignoring published audit-firm recommendations and shipping unreviewed code.",
            "Ignoring published audit-firm recommendations.",
            max_len=900,
        ),
        # Audit-firm public reports don't expose a per-file severity; we
        # mark the index entry as 'info' so it never short-circuits a
        # severity-tier gate downstream. PDF deep-mining will emit
        # per-finding records with real severities.
        "severity_at_finding": "info",
        "year": int(year) if year else 2020,
        "record_tier": "public-corpus",
        "record_quality_score": 3.0,
        "source_extraction_method": "corpus-etl",
        "source_extraction_confidence": 0.70,
        "verification_method": "manual",
        "cross_language_analogues": [],
        "related_records": [],
        "verification_tier": VERIFICATION_TIER,
        "record_source_url": raw_url,
    }
    return record


# ---------------------------------------------------------------------------
# Top-level pipeline.
# ---------------------------------------------------------------------------


def build_records(
    trees: Dict[str, List[Dict[str, Any]]],
    *,
    specs: Tuple[SourceSpec, ...] = SOURCE_SPECS,
) -> List[Dict[str, Any]]:
    out: List[Dict[str, Any]] = []
    seen_ids: set = set()
    for spec in specs:
        entries = trees.get(spec["owner_repo"], [])
        if spec.get("dedup_on_stem"):
            # Keep PDF version when both md+pdf exist for the same stem;
            # otherwise keep whichever is first encountered.
            by_stem: Dict[str, str] = {}
            for entry in entries:
                path = entry.get("path")
                if not isinstance(path, str):
                    continue
                if not _accepts_path(spec, path):
                    continue
                stem_key = _file_stem(path).lower()
                if stem_key not in by_stem:
                    by_stem[stem_key] = path
                else:
                    cur = by_stem[stem_key]
                    if cur.lower().endswith(".md") and path.lower().endswith(".pdf"):
                        by_stem[stem_key] = path
            paths = sorted(by_stem.values())
        else:
            paths = sorted(
                e["path"] for e in entries
                if isinstance(e.get("path"), str) and _accepts_path(spec, e["path"])
            )
        for path in paths:
            rec = _record_from_path(spec, path)
            if rec is None:
                continue
            if rec["record_id"] in seen_ids:
                continue
            seen_ids.add(rec["record_id"])
            out.append(rec)
    return out


def output_dir_for(out_root: Path, record: Dict[str, Any]) -> Path:
    """Records are sharded into ``<out_root>/<repo>__<slug>/record.{json,yaml}``
    where ``<repo>`` is the corpus-side firm slug and ``<slug>`` is the
    file slug.
    """
    # source_audit_ref shape is ``audit-firm:<repo>:<path>``.
    ref = record["source_audit_ref"]
    parts = ref.split(":", 2)
    if len(parts) == 3:
        repo_slug = slugify(parts[1], max_len=80)
        file_slug = slugify(_file_stem(parts[2]), max_len=80)
    else:
        repo_slug = "unknown"
        file_slug = slugify(record["record_id"], max_len=80)
    dir_name = f"{repo_slug}__{file_slug}"
    # Guard against accidental collision by suffixing the record id hash.
    digest = record["record_id"].rsplit(":", 1)[-1]
    if len(digest) >= 6 and digest not in dir_name:
        dir_name = f"{dir_name}-{digest[:12]}"
    return out_root / dir_name


def merge_existing_local_enrichments(record: Dict[str, Any], sub_dir: Path) -> Dict[str, Any]:
    """Preserve local classifier enrichments when refreshing source listings.

    The audit-firm miner owns the source-listing fields. Sibling tools may later
    add local-only classifications such as heuristic attack-class backfills. A
    live refresh must not erase those improvements just because the upstream
    report URL is still present.
    """
    existing_path = sub_dir / "record.yaml"
    if not existing_path.exists():
        return record
    try:
        existing = yaml.safe_load(existing_path.read_text(encoding="utf-8"))
    except (OSError, yaml.YAMLError):
        return record
    if not isinstance(existing, dict):
        return record
    if existing.get("record_id") != record.get("record_id"):
        return record

    extensions = existing.get("record_extensions")
    if isinstance(extensions, dict) and extensions:
        record["record_extensions"] = extensions
        existing_attack_class = existing.get("attack_class")
        if (
            isinstance(existing_attack_class, str)
            and existing_attack_class
            and existing_attack_class != "audit-firm-public-report"
        ):
            record["attack_class"] = existing_attack_class
    return record


def existing_record_semantically_matches(record: Dict[str, Any], sub_dir: Path) -> bool:
    """Return true when the on-disk YAML already represents ``record``.

    This keeps full-source refreshes from rewriting thousands of byte-stable
    records solely because PyYAML chose different line wrapping.
    """
    existing_path = sub_dir / "record.yaml"
    if not existing_path.exists():
        return False
    try:
        existing = yaml.safe_load(existing_path.read_text(encoding="utf-8"))
    except (OSError, yaml.YAMLError):
        return False
    return existing == record


def convert(
    out_dir: Path,
    *,
    dry_run: bool = False,
    limit: Optional[int] = None,
    trees_cache: Optional[Path] = None,
    write_trees_cache_to: Optional[Path] = None,
    specs: Tuple[SourceSpec, ...] = SOURCE_SPECS,
) -> Dict[str, Any]:
    trees = load_or_fetch_trees(
        cache_file=trees_cache,
        write_cache=write_trees_cache_to,
        specs=specs,
    )
    records = build_records(trees, specs=specs)
    if limit is not None:
        records = records[:limit]

    errors: List[str] = []
    files: List[str] = []
    by_repo: Dict[str, int] = {}
    by_year: Dict[str, int] = {}
    sample_urls: List[str] = []

    if not dry_run:
        out_dir.mkdir(parents=True, exist_ok=True)

    for record in records:
        ref = record["source_audit_ref"]
        parts = ref.split(":", 2)
        repo_slug = parts[1] if len(parts) == 3 else "unknown"
        by_repo[repo_slug] = by_repo.get(repo_slug, 0) + 1
        y = str(record.get("year", ""))
        by_year[y] = by_year.get(y, 0) + 1

        sub_dir = output_dir_for(out_dir, record)
        if not dry_run:
            record = merge_existing_local_enrichments(record, sub_dir)
        rendered = yaml_dump(record)
        try:
            doc = yaml.safe_load(rendered)
        except yaml.YAMLError as exc:
            errors.append(f"{record['record_id']}: yaml-parse-error: {exc}")
            continue
        errs = _VALIDATOR.validate_doc(doc)
        if errs:
            errors.extend(f"{record['record_id']}: {err}" for err in errs)
            continue
        files.append(str(sub_dir / "record.yaml"))
        if len(sample_urls) < 5:
            for pre in record["required_preconditions"]:
                if pre.startswith("Reference public audit report at "):
                    sample_urls.append(pre.split(" at ", 1)[1])
                    break
        if not dry_run:
            sub_dir.mkdir(parents=True, exist_ok=True)
            if not existing_record_semantically_matches(record, sub_dir):
                (sub_dir / "record.yaml").write_text(rendered, encoding="utf-8")
                (sub_dir / "record.json").write_text(
                    json.dumps(record, indent=2, sort_keys=True) + "\n",
                    encoding="utf-8",
                )

    return {
        "schema_version": SCHEMA_VERSION,
        "verification_tier": VERIFICATION_TIER,
        "out_dir": str(out_dir),
        "dry_run": dry_run,
        "records_emitted": len(records) - len(errors),
        "records_attempted": len(records),
        "errors": errors,
        "by_repo": by_repo,
        "by_year": dict(sorted(by_year.items())),
        "file_count": len(files),
        "files": files[:50],
        "sample_source_urls": sample_urls,
        "trees_repos_seen": sorted(trees.keys()),
    }


# ---------------------------------------------------------------------------
# CLI.
# ---------------------------------------------------------------------------


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--out-dir",
        required=True,
        help="Output dir. Records land under <out-dir>/<repo>__<slug>/record.{json,yaml}.",
    )
    parser.add_argument("--dry-run", action="store_true")
    parser.add_argument("--limit", type=int)
    parser.add_argument(
        "--trees-cache",
        help="Read previously-saved {owner_repo: [tree_entries]} JSON instead of calling gh api.",
    )
    parser.add_argument(
        "--write-trees-cache",
        help="Save the fetched recursive trees to this path for offline replay.",
    )
    parser.add_argument("--json-summary", action="store_true")
    return parser


def main(argv: Optional[List[str]] = None) -> int:
    args = build_parser().parse_args(argv)
    if args.limit is not None and args.limit < 0:
        print("--limit must be non-negative", file=sys.stderr)
        return 2
    summary = convert(
        Path(args.out_dir).expanduser().resolve(),
        dry_run=args.dry_run,
        limit=args.limit,
        trees_cache=(
            Path(args.trees_cache).expanduser().resolve() if args.trees_cache else None
        ),
        write_trees_cache_to=(
            Path(args.write_trees_cache).expanduser().resolve()
            if args.write_trees_cache
            else None
        ),
    )
    if args.json_summary:
        print(json.dumps(summary, sort_keys=True))
    else:
        print(
            "hackerman audit-firm-public-reports ETL: "
            f"records={summary['records_emitted']}/{summary['records_attempted']} "
            f"verification_tier={summary['verification_tier']} "
            f"by_repo={summary['by_repo']} "
            f"errors={len(summary['errors'])}"
        )
    return 0 if not summary["errors"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
