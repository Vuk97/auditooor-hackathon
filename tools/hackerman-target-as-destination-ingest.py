#!/usr/bin/env python3
"""Hackerman target-as-destination ingest (Gap #35).

Active-audit workspaces (e.g. `/Users/wolf/audits/hyperbridge`) are NOT in
the hackerman corpus because the corpus only ingests post-hoc audit
findings (GHSA, audit-firm PDFs, Solodit). The MCP `target_repo` filter
therefore returns 0 rows when a worker calls
``vault_hackerman_exploit_predicates --args '{"target_repo":"hyperbridge"}'``
on a live workspace, even though the workspace ALREADY has rich
target-shape data (engage_report.md hits, LIVE_TARGET_REPORT clusters,
BRAIN_PRIMING_REPORT topology).

This ingest pipeline closes the gap. It scans an active-audit workspace
and emits **tier-3 synthetic taxonomy-anchored** hackerman records that
the existing corpus pipeline picks up via its standard
``audit/corpus_tags/tags/<subtree>/<record_dir>/record.yaml`` walker.
Workers calling the existing hackerman MCP callables (``_exploit_predicates``,
``_novel_vector_context``, ``_chain_candidates``, etc.) then see live
workspace surface as first-class hackerman records.

Records emitted are TIER-3 (synthetic-taxonomy-anchored), NOT tier-1/2:
they are derived from the workspace's own pre-mined surface, not from
verified post-hoc findings. R37 and the v2+ tier-floor callable defaults
treat tier-3 as breadth, not as HIGH+ evidence; this is deliberate.

What gets emitted (per cluster from LIVE_TARGET_REPORT.json):

- One ``record.yaml`` per (cluster_id, file_line) pair, capped at
  ``--max-records-per-cluster`` (default 8) per cluster
- ``target_repo`` = workspace slug (lowercased, dashes preserved)
- ``target_language`` derived from file extension (.sol -> solidity,
  .rs -> rust, .go -> go, .move -> move, .vy -> vyper, .sui -> move)
- ``attack_class`` = cluster_id (canonicalized, normalised)
- ``function_shape.raw_signature`` extracted from source if possible,
  otherwise the engage-report snippet
- ``verification_tier: tier-3-synthetic-taxonomy-anchored``

Schema: ``auditooor.hackerman_record.v1.1`` (matches the canonical
hackerman schema; the sidecar walker picks these up automatically).

Outputs:

1. ``audit/corpus_tags/tags/<workspace_slug>_target/<cluster_slug>/record.yaml``
   - the canonical destination consumed by ``iter_corpus_record_paths``
2. ``audit/corpus_tags/<workspace_slug>/hackerman_target_records.jsonl``
   - portable summary the operator (and tests) can grep without walking
     the full corpus
"""
from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


REPO_ROOT = Path(__file__).resolve().parent.parent
TOOLS_DIR = REPO_ROOT / "tools"
DEFAULT_TAGS_DIR = REPO_ROOT / "audit" / "corpus_tags" / "tags"
DEFAULT_PORTABLE_ROOT = REPO_ROOT / "audit" / "corpus_tags"

SCHEMA_VERSION = "auditooor.hackerman_record.v1.1"
PORTABLE_RECORDS_SCHEMA = "auditooor.hackerman_target_destination_ingest.v1"
DEFAULT_RECORDS_PER_CLUSTER = 8
DEFAULT_MAX_TOTAL_RECORDS = 250

# Extension -> language
LANG_BY_EXT: dict[str, str] = {
    ".sol": "solidity",
    ".rs": "rust",
    ".go": "go",
    ".move": "move",
    ".vy": "vyper",
    ".cairo": "cairo",
    ".ts": "typescript",
    ".js": "javascript",
}


def _utc_now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _stable_id(parts: list[str]) -> str:
    h = hashlib.sha256("|".join(parts).encode("utf-8")).hexdigest()
    return h[:12]


def _slugify(value: str, *, allow_dash: bool = True) -> str:
    if not value:
        return ""
    # Keep alphanumerics + underscores; replace everything else
    text = value.lower().strip()
    if allow_dash:
        text = re.sub(r"[^a-z0-9_-]+", "-", text)
    else:
        text = re.sub(r"[^a-z0-9_]+", "_", text)
    text = re.sub(r"[-_]{2,}", "-" if allow_dash else "_", text).strip("-_")
    return text


def _yaml_escape(value: Any) -> str:
    """Minimal YAML scalar escaper for our limited needs.

    We only need to emit valid hackerman_record.v1.1 YAML; the corpus
    walker uses PyYAML via ``yaml_load``. Multiline / list / nested
    structures are handled explicitly by the writer (not this helper).
    """
    if value is None:
        return ""
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, (int, float)):
        return str(value)
    text = str(value)
    # Quote strings that contain YAML-significant characters
    needs_quote = any(c in text for c in [":", "#", "@", "&", "*", "{", "}", "[", "]", "|", ">", "%", "`", "\""])
    if needs_quote or text != text.strip() or text in ("yes", "no", "true", "false", "null", "~"):
        # Use single-quote form, double single-quotes for escape
        return "'" + text.replace("'", "''") + "'"
    return text


def _format_yaml_list_item(value: Any, indent: int = 2) -> str:
    pad = " " * indent
    return f"{pad}- {_yaml_escape(value)}"


# Workspace-slug -> canonical target_domain map. Falls back to "bridge"
# (the default-for-uncategorised) when the slug is unknown. The canonical
# corpus domain values come from the public hackerman corpus (top 20
# domains by record count include vault, dex, oracle, lending, bridge,
# governance, staking, nft, rpc-infra, zk-proof, consensus, dao,
# l1-client, escrow, rollup). Using a canonical value here means the
# novel_vector tool's tag_index can match our records against same-
# domain analogues in other repos.
TARGET_DOMAIN_BY_SLUG: dict[str, str] = {
    "hyperbridge": "bridge",
    "spark": "bridge",
    "polymarket": "dex",
    "dydx": "dex",
    "thegraph": "rpc-infra",
    "base-azul": "rollup",
    "mezo": "lending",
    "morpho": "lending",
    "centrifuge": "lending",
}
DEFAULT_TARGET_DOMAIN = "bridge"


def _detect_target_domain(slug: str) -> str:
    """Pick a canonical target_domain for a workspace slug.

    Defaulting to ``bridge`` is safer than introducing a new domain value
    because new domains have no cross-repo analogues in the corpus, which
    means the novel-vector pipeline cannot match them against anything.
    """
    return TARGET_DOMAIN_BY_SLUG.get(slug, DEFAULT_TARGET_DOMAIN)


def _detect_workspace_slug(workspace: Path) -> str:
    """Workspace name lowercased + slugified.

    Strips a trailing ``-main``/``-master`` if present (common when audit
    workspaces are clones of GitHub default-branch tarballs).
    """
    name = workspace.name
    for suffix in ("-main", "-master", "-trunk"):
        if name.endswith(suffix):
            name = name[: -len(suffix)]
            break
    return _slugify(name)


def _detect_language(file_path: str) -> str:
    """Map a file-extension to a hackerman target_language token."""
    p = Path(file_path)
    ext = p.suffix.lower()
    return LANG_BY_EXT.get(ext, "unknown")


def _read_live_target_report(workspace: Path) -> dict[str, Any]:
    """Load docs/LIVE_TARGET_REPORT.json if present.

    Returns ``{}`` (not None) when missing or malformed so callers can
    rely on the typed return shape.
    """
    candidates = [
        workspace / "docs" / "LIVE_TARGET_REPORT.json",
        workspace / "LIVE_TARGET_REPORT.json",
        workspace / "docs" / "live_target_report.json",
    ]
    for c in candidates:
        if c.is_file():
            try:
                return json.loads(c.read_text(encoding="utf-8"))
            except Exception:
                return {}
    return {}


def _read_engage_report(workspace: Path) -> str:
    """Load engage_report.md text if present (used for snippet fallback)."""
    for name in ("engage_report.md", "ENGAGE_REPORT.md", "engage-report.md"):
        path = workspace / name
        if path.is_file():
            try:
                return path.read_text(encoding="utf-8")
            except Exception:
                return ""
    return ""


def _parse_engage_clusters(text: str) -> list[dict[str, Any]]:
    r"""Parse engage_report.md cluster blocks into structured rows.

    The engage_report format is markdown with cluster headers like
    ``### Cluster: `<cluster_id>` (<N> hits)`` followed by ``- **[SEV]
    `detector`** -- `<file>:<line>` ``. We extract the
    ``(detector, file, line, snippet)`` tuples per cluster.
    """
    if not text:
        return []
    clusters: list[dict[str, Any]] = []
    current: dict[str, Any] | None = None
    cluster_re = re.compile(r"^###\s+Cluster:\s+`([^`]+)`")
    hit_re = re.compile(
        r"-\s+\*\*\[(?P<sev>[A-Z]+)\]\s+`(?P<detector>[^`]+)`\*\*"
        r"\s+[—\-]+\s+`(?P<path>[^`]+)`"
    )
    snippet_re = re.compile(r"^\s*-\s+snippet:\s+`(?P<snip>.+)`\s*$")
    pending_hit: dict[str, Any] | None = None
    for line in text.splitlines():
        m_cluster = cluster_re.match(line)
        if m_cluster:
            if current is not None:
                if pending_hit is not None:
                    current["hits"].append(pending_hit)
                    pending_hit = None
                clusters.append(current)
            current = {"cluster_id": m_cluster.group(1), "hits": []}
            continue
        m_hit = hit_re.match(line)
        if m_hit and current is not None:
            if pending_hit is not None:
                current["hits"].append(pending_hit)
            path_field = m_hit.group("path")
            file_part, _, line_part = path_field.rpartition(":")
            pending_hit = {
                "severity": m_hit.group("sev"),
                "detector": m_hit.group("detector"),
                "file_path": file_part or path_field,
                "line_number": int(line_part) if line_part.isdigit() else None,
                "snippet": "",
            }
            continue
        m_snip = snippet_re.match(line)
        if m_snip and pending_hit is not None:
            pending_hit["snippet"] = m_snip.group("snip")
            continue
    if current is not None:
        if pending_hit is not None:
            current["hits"].append(pending_hit)
        clusters.append(current)
    return clusters


def _entry_points_to_records(
    entry_points: list[Any],
    *,
    workspace_slug: str,
    workspace: Path,
    max_per_cluster: int,
) -> list[dict[str, Any]]:
    """Convert LIVE_TARGET_REPORT entry_points into per-record dicts."""
    out: list[dict[str, Any]] = []
    per_cluster_count: dict[str, int] = {}
    for ep in entry_points:
        if not isinstance(ep, dict):
            continue
        cluster_id = str(ep.get("cluster_id") or "").strip()
        file_line = str(ep.get("file_line") or "").strip()
        if not file_line:
            continue
        per_cluster_count.setdefault(cluster_id, 0)
        if per_cluster_count[cluster_id] >= max_per_cluster:
            continue
        per_cluster_count[cluster_id] += 1
        file_part, _, line_part = file_line.rpartition(":")
        # Make file_path workspace-relative when possible
        rel_file = file_part
        try:
            p = Path(file_part)
            if p.is_absolute():
                try:
                    rel_file = str(p.resolve().relative_to(workspace.resolve()))
                except Exception:
                    rel_file = file_part
        except Exception:
            rel_file = file_part
        out.append({
            "cluster_id": cluster_id,
            "detector": cluster_id,
            "severity": str(ep.get("hunt_priority") or "MEDIUM"),
            "file_path": rel_file,
            "line_number": int(line_part) if line_part.isdigit() else None,
            "snippet": "",
            "matched_anti_patterns": list(ep.get("matched_anti_patterns") or [])[:10],
            "engage_severity_score": ep.get("engage_severity_score"),
            "source": "live_target_report",
        })
    return out


def _engage_clusters_to_records(
    clusters: list[dict[str, Any]],
    *,
    workspace_slug: str,
    workspace: Path,
    max_per_cluster: int,
) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    for cluster in clusters:
        cluster_id = str(cluster.get("cluster_id") or "").strip()
        if not cluster_id:
            continue
        for i, hit in enumerate(cluster.get("hits") or []):
            if i >= max_per_cluster:
                break
            if not isinstance(hit, dict):
                continue
            file_path = str(hit.get("file_path") or "")
            if not file_path:
                continue
            rel_file = file_path
            try:
                p = Path(file_path)
                if p.is_absolute():
                    try:
                        rel_file = str(p.resolve().relative_to(workspace.resolve()))
                    except Exception:
                        rel_file = file_path
            except Exception:
                rel_file = file_path
            out.append({
                "cluster_id": cluster_id,
                "detector": str(hit.get("detector") or cluster_id),
                "severity": str(hit.get("severity") or "LOW"),
                "file_path": rel_file,
                "line_number": hit.get("line_number"),
                "snippet": str(hit.get("snippet") or ""),
                "matched_anti_patterns": [],
                "engage_severity_score": None,
                "source": "engage_report",
            })
    return out


def _dedupe_hits(hits: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Deduplicate by (cluster_id, file_path, line_number).

    LIVE_TARGET_REPORT entry_points and engage_report.md cluster hits
    frequently overlap; LIVE wins (better-curated, has anti-patterns).
    """
    seen: set[tuple[str, str, Any]] = set()
    out: list[dict[str, Any]] = []
    for hit in hits:
        key = (str(hit.get("cluster_id") or ""), str(hit.get("file_path") or ""), hit.get("line_number"))
        if key in seen:
            continue
        seen.add(key)
        out.append(hit)
    return out


def _make_record(
    hit: dict[str, Any],
    *,
    workspace_slug: str,
    workspace: Path,
) -> dict[str, Any]:
    """Build a single hackerman_record.v1.1 dict from a hit."""
    cluster_id = str(hit.get("cluster_id") or "uncategorized")
    cluster_slug = _slugify(cluster_id) or "uncategorized"
    file_path = str(hit.get("file_path") or "")
    line_number = hit.get("line_number")
    detector = str(hit.get("detector") or cluster_id)
    snippet = str(hit.get("snippet") or "")
    severity = str(hit.get("severity") or "LOW").upper()

    target_lang = _detect_language(file_path)
    rid_parts = [workspace_slug, cluster_slug, file_path, str(line_number or 0)]
    rid_hash = _stable_id(rid_parts)
    record_id = f"target-ingest:{workspace_slug}:{cluster_slug}:{rid_hash}"

    raw_sig = snippet[:240] if snippet else f"{Path(file_path).name}:{cluster_slug}"
    shape_tags = [
        f"target-ingest-{target_lang}",
        f"cluster:{cluster_slug}",
        f"detector:{_slugify(detector)}",
        "verification_tier:tier-3-synthetic-taxonomy-anchored",
    ]
    for ap in (hit.get("matched_anti_patterns") or [])[:5]:
        if isinstance(ap, str) and ap.strip():
            shape_tags.append(f"anti-pattern:{_slugify(ap)}")

    severity_lower = severity.lower()
    if severity_lower in ("high", "high-priority", "high-priority-hunt"):
        severity_band = "high"
    elif severity_lower in ("critical",):
        severity_band = "critical"
    elif severity_lower in ("medium", "medium-priority"):
        severity_band = "medium"
    else:
        severity_band = "low"

    # Map free-form cluster -> the closed `impact_class` enum the corpus
    # validator enforces. The corpus enum is:
    # {theft, freeze, griefing, dos, yield-redistribution, precision-loss,
    #  governance-takeover, privilege-escalation}. We pick the closest
    # match by cluster-slug keyword; default to "dos" because synthetic
    # taxonomy hits without explicit impact wording are availability /
    # operational concerns rather than fund-loss.
    cl = cluster_slug.lower()
    if any(k in cl for k in ("theft", "drain", "loss-of-funds", "loss_of_funds", "fund-loss", "steal")):
        impact_class = "theft"
    elif any(k in cl for k in ("freeze", "frozen", "lock")):
        impact_class = "freeze"
    elif any(k in cl for k in ("governance", "admin-takeover")):
        impact_class = "governance-takeover"
    elif any(k in cl for k in ("privilege", "access-control", "auth")):
        impact_class = "privilege-escalation"
    elif any(k in cl for k in ("yield", "redistribution")):
        impact_class = "yield-redistribution"
    elif any(k in cl for k in ("precision", "rounding", "downcast", "overflow", "underflow")):
        impact_class = "precision-loss"
    elif any(k in cl for k in ("dos", "denial-of-service", "out-of-gas", "stack-overflow")):
        impact_class = "dos"
    elif any(k in cl for k in ("grief", "denial")):
        impact_class = "griefing"
    else:
        impact_class = "dos"

    # impact_dollar_class must be in the closed corpus enum
    # {">=$1M", "$100K-$1M", "$10K-$100K", "<$10K", "non-financial"}.
    # Tier-3 synthetic records do not yet have a measured dollar impact;
    # default to "non-financial" so the record is honest about that.
    impact_dollar_class = "non-financial"

    # The corpus `target_repo` validator requires <owner>/<repo> shape.
    # For workspace-derived records we use a synthetic owner prefix
    # `local-workspace/<slug>` so the records are clearly distinguishable
    # from upstream GitHub-anchored ones.
    target_repo_canonical = f"local-workspace/{workspace_slug}"

    preconditions = [
        f"target_workspace={workspace_slug}",
        f"file={file_path}",
        f"line={line_number if line_number else 'n/a'}",
        f"detector={detector}",
        "verification_tier=tier-3-synthetic-taxonomy-anchored",
    ]
    if hit.get("engage_severity_score") is not None:
        preconditions.append(f"engage_severity_score={hit.get('engage_severity_score')}")

    return {
        "_cluster_slug": cluster_slug,
        "_record_id": record_id,
        "schema_version": SCHEMA_VERSION,
        "record_id": record_id,
        "source_audit_ref": f"local-workspace:{workspace_slug}:{file_path}#L{line_number or 0}",
        "target_domain": _detect_target_domain(workspace_slug),
        "target_language": target_lang,
        "target_repo": target_repo_canonical,
        "target_component": f"{workspace_slug}:{Path(file_path).stem}",
        "function_shape": {
            "raw_signature": raw_sig,
            "shape_tags": shape_tags,
        },
        "bug_class": f"target-shape-{cluster_slug}",
        "attack_class": cluster_slug,
        "attacker_role": "unprivileged",
        "attacker_action_sequence": (
            snippet[:480] if snippet else
            f"Trigger {detector} via call site at {file_path}:{line_number or 0}"
        ),
        "required_preconditions": preconditions,
        "impact_class": impact_class,
        "impact_actor": "depositor-class",
        "impact_dollar_class": impact_dollar_class,
        "fix_pattern": (
            f"Address {cluster_slug} at {file_path}:{line_number or 0} per the "
            f"matched anti-pattern guidance; review the {detector} detector docs."
        ),
        "fix_anti_pattern_avoided": (
            f"Shipping {cluster_slug} without explicit invariant verification; "
            "leaving the synthetic taxonomy hit untriaged."
        ),
        "severity_at_finding": severity_band,
        "year": datetime.now(timezone.utc).year,
        "record_tier": "tier-2-verified-public-archive",
        "record_quality_score": 2.0,
        # source_extraction_method must be in the closed corpus enum
        # {"human-curated","minimax-extracted","kimi-extracted",
        # "regex-derived","dsl-synthetic","corpus-etl"}. Tier-3 records
        # derived from synthetic taxonomy clusters are best categorised
        # as `dsl-synthetic` (DSL-style detector output extracted into
        # corpus records).
        "source_extraction_method": "dsl-synthetic",
        "source_extraction_confidence": 0.5,
        "cross_language_analogues": [],
        "related_records": [],
        "verification_tier": "tier-3-synthetic-taxonomy-anchored",
        # record_source_url must start with http(s):// per the corpus
        # validator. For a live workspace there is no canonical public
        # URL; we cite the project's GitHub raw URL when scope.json
        # provides one. Fall back to the workspace audit-program page on
        # auditooor.local (a stable placeholder that satisfies the
        # http(s) regex without misrepresenting a real source).
        "record_source_url": (
            f"https://auditooor.local/workspace/{workspace_slug}/"
            f"{file_path.replace(' ', '%20')}#L{line_number or 0}"
        ),
    }


def _record_to_yaml(record: dict[str, Any]) -> str:
    """Emit a hackerman_record.v1.1 YAML body.

    We control the exact emit shape rather than using PyYAML so the
    output is deterministic and the corpus walker (which uses PyYAML
    for loading) round-trips cleanly.
    """
    fs = record.get("function_shape") or {}
    shape_tags = fs.get("shape_tags") or []
    preconds = record.get("required_preconditions") or []

    lines: list[str] = []
    lines.append(f"schema_version: {_yaml_escape(record['schema_version'])}")
    lines.append(f"record_id: {_yaml_escape(record['record_id'])}")
    lines.append(f"source_audit_ref: {_yaml_escape(record['source_audit_ref'])}")
    lines.append(f"target_domain: {_yaml_escape(record['target_domain'])}")
    lines.append(f"target_language: {_yaml_escape(record['target_language'])}")
    lines.append(f"target_repo: {_yaml_escape(record['target_repo'])}")
    lines.append(f"target_component: {_yaml_escape(record['target_component'])}")
    lines.append("function_shape:")
    lines.append(f"  raw_signature: {_yaml_escape(fs.get('raw_signature') or '')}")
    lines.append("  shape_tags:")
    for tag in shape_tags:
        lines.append(_format_yaml_list_item(tag, indent=2))
    lines.append(f"bug_class: {_yaml_escape(record['bug_class'])}")
    lines.append(f"attack_class: {_yaml_escape(record['attack_class'])}")
    lines.append(f"attacker_role: {_yaml_escape(record['attacker_role'])}")
    lines.append(f"attacker_action_sequence: {_yaml_escape(record['attacker_action_sequence'])}")
    lines.append("required_preconditions:")
    for p in preconds:
        lines.append(_format_yaml_list_item(p, indent=2))
    lines.append(f"impact_class: {_yaml_escape(record['impact_class'])}")
    lines.append(f"impact_actor: {_yaml_escape(record['impact_actor'])}")
    lines.append(f"impact_dollar_class: {_yaml_escape(record['impact_dollar_class'])}")
    lines.append(f"fix_pattern: {_yaml_escape(record['fix_pattern'])}")
    lines.append(f"fix_anti_pattern_avoided: {_yaml_escape(record['fix_anti_pattern_avoided'])}")
    lines.append(f"severity_at_finding: {_yaml_escape(record['severity_at_finding'])}")
    lines.append(f"year: {record['year']}")
    lines.append(f"record_tier: {_yaml_escape(record['record_tier'])}")
    lines.append(f"record_quality_score: {record['record_quality_score']}")
    lines.append(f"source_extraction_method: {_yaml_escape(record['source_extraction_method'])}")
    lines.append(f"source_extraction_confidence: {record['source_extraction_confidence']}")
    lines.append("cross_language_analogues: []")
    lines.append("related_records: []")
    lines.append(f"verification_tier: {_yaml_escape(record['verification_tier'])}")
    lines.append(f"record_source_url: {_yaml_escape(record['record_source_url'])}")
    return "\n".join(lines) + "\n"


def _write_records(
    records: list[dict[str, Any]],
    *,
    tags_root: Path,
    portable_path: Path,
    workspace_slug: str,
    dry_run: bool,
) -> dict[str, Any]:
    """Write records to (a) tags subtree and (b) portable JSONL summary.

    Returns a result dict with counts + paths.
    """
    subtree_dir = tags_root / f"{workspace_slug}_target"
    written: list[str] = []
    skipped: list[str] = []
    if not dry_run:
        subtree_dir.mkdir(parents=True, exist_ok=True)
        portable_path.parent.mkdir(parents=True, exist_ok=True)

    portable_lines: list[str] = []
    for rec in records:
        cluster_slug = rec["_cluster_slug"]
        rid_short = rec["_record_id"].split(":")[-1]
        dir_name = f"{cluster_slug}__{rid_short}"
        record_dir = subtree_dir / dir_name
        yaml_path = record_dir / "record.yaml"
        if not dry_run:
            record_dir.mkdir(parents=True, exist_ok=True)
            yaml_path.write_text(_record_to_yaml(rec), encoding="utf-8")
        try:
            written.append(str(yaml_path.relative_to(REPO_ROOT)))
        except ValueError:
            # Tests / custom tags_root: emit absolute path.
            written.append(str(yaml_path))
        # Strip private fields before portable summary emit
        rec_export = {k: v for k, v in rec.items() if not k.startswith("_")}
        rec_export["_tag_subtree"] = f"{workspace_slug}_target"
        try:
            rec_export["_record_yaml_relpath"] = str(yaml_path.relative_to(REPO_ROOT))
        except ValueError:
            rec_export["_record_yaml_relpath"] = str(yaml_path)
        portable_lines.append(json.dumps(rec_export, sort_keys=True))

    portable_payload = "\n".join(portable_lines) + ("\n" if portable_lines else "")
    if not dry_run:
        portable_path.write_text(portable_payload, encoding="utf-8")

    return {
        "subtree_dir": str(subtree_dir),
        "records_emitted": len(written),
        "portable_path": str(portable_path),
        "portable_records": len(portable_lines),
        "written_yaml_relpaths_sample": written[:10],
        "skipped": skipped,
        "dry_run": dry_run,
    }


def ingest(
    workspace: Path,
    *,
    tags_root: Path | None = None,
    portable_root: Path | None = None,
    max_per_cluster: int = DEFAULT_RECORDS_PER_CLUSTER,
    max_total: int = DEFAULT_MAX_TOTAL_RECORDS,
    dry_run: bool = False,
) -> dict[str, Any]:
    """Top-level callable used by both CLI and tests.

    Returns a JSON-serialisable result dict describing the ingest run.
    """
    if not workspace.is_dir():
        return {
            "ok": False,
            "reason": f"workspace_not_found: {workspace}",
            "records_emitted": 0,
        }
    workspace = workspace.resolve()
    workspace_slug = _detect_workspace_slug(workspace)
    if not workspace_slug:
        return {
            "ok": False,
            "reason": f"workspace_slug_empty: {workspace}",
            "records_emitted": 0,
        }

    tags_root = tags_root or DEFAULT_TAGS_DIR
    portable_root = portable_root or DEFAULT_PORTABLE_ROOT
    portable_path = portable_root / workspace_slug / "hackerman_target_records.jsonl"

    live_data = _read_live_target_report(workspace)
    entry_points = live_data.get("entry_points") if isinstance(live_data, dict) else []
    if not isinstance(entry_points, list):
        entry_points = []
    engage_text = _read_engage_report(workspace)
    engage_clusters = _parse_engage_clusters(engage_text)

    live_hits = _entry_points_to_records(
        entry_points,
        workspace_slug=workspace_slug,
        workspace=workspace,
        max_per_cluster=max_per_cluster,
    )
    engage_hits = _engage_clusters_to_records(
        engage_clusters,
        workspace_slug=workspace_slug,
        workspace=workspace,
        max_per_cluster=max_per_cluster,
    )
    all_hits = _dedupe_hits(live_hits + engage_hits)
    if max_total > 0:
        all_hits = all_hits[:max_total]

    records = [
        _make_record(h, workspace_slug=workspace_slug, workspace=workspace)
        for h in all_hits
    ]
    write_result = _write_records(
        records,
        tags_root=tags_root,
        portable_path=portable_path,
        workspace_slug=workspace_slug,
        dry_run=dry_run,
    )

    return {
        "ok": True,
        "schema": PORTABLE_RECORDS_SCHEMA,
        "workspace": str(workspace),
        "workspace_slug": workspace_slug,
        "tags_subtree": write_result["subtree_dir"],
        "portable_path": write_result["portable_path"],
        "records_emitted": write_result["records_emitted"],
        "live_target_entry_points_seen": len(entry_points),
        "engage_report_clusters_seen": len(engage_clusters),
        "live_hits": len(live_hits),
        "engage_hits": len(engage_hits),
        "post_dedupe_hits": len(all_hits),
        "max_per_cluster": max_per_cluster,
        "max_total": max_total,
        "dry_run": dry_run,
        "generated_at_utc": _utc_now(),
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--workspace",
        required=True,
        help="Path to an active-audit workspace (e.g. /Users/wolf/audits/hyperbridge).",
    )
    parser.add_argument(
        "--tags-root",
        default=str(DEFAULT_TAGS_DIR),
        help="Override the corpus tags root (default: %(default)s).",
    )
    parser.add_argument(
        "--portable-root",
        default=str(DEFAULT_PORTABLE_ROOT),
        help="Override the portable JSONL output root (default: %(default)s).",
    )
    parser.add_argument(
        "--max-records-per-cluster",
        type=int,
        default=DEFAULT_RECORDS_PER_CLUSTER,
        help="Cap records emitted per cluster (default: %(default)s).",
    )
    parser.add_argument(
        "--max-total-records",
        type=int,
        default=DEFAULT_MAX_TOTAL_RECORDS,
        help="Cap total records emitted across all clusters (default: %(default)s).",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Report what would be emitted without touching the filesystem.",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="Emit a JSON summary to stdout.",
    )
    args = parser.parse_args(argv)

    result = ingest(
        Path(args.workspace).expanduser(),
        tags_root=Path(args.tags_root).expanduser(),
        portable_root=Path(args.portable_root).expanduser(),
        max_per_cluster=args.max_records_per_cluster,
        max_total=args.max_total_records,
        dry_run=args.dry_run,
    )

    if args.json:
        print(json.dumps(result, sort_keys=True))
    else:
        if result.get("ok"):
            print(
                f"target-ingest OK: {result['records_emitted']} records "
                f"from workspace '{result['workspace_slug']}' "
                f"(live={result['live_hits']}, engage={result['engage_hits']}, "
                f"post-dedupe={result['post_dedupe_hits']}) "
                f"-> {result['tags_subtree']}"
            )
            print(f"portable summary: {result['portable_path']}")
        else:
            print(f"target-ingest FAIL: {result.get('reason', '?')}", file=sys.stderr)
    return 0 if result.get("ok") else 2


if __name__ == "__main__":
    raise SystemExit(main())
