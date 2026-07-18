#!/usr/bin/env python3
"""Wave-1 hackerman capability lift (PR #726) - attack-class taxonomy inventory.

Walks ``audit/corpus_tags/tags/**/record.{json,yaml}`` and emits a taxonomy
inventory of distinct ``attack_class`` values, with per-class:

- total record count
- corpus subtrees that the class appears in (e.g. ``lending_protocols`` /
  ``audit_firm_public_reports`` / ``dex_fix_history``)
- verification-tier coverage (tier-1 / tier-2 / tier-3 / tier-4 / tier-5
  quarantine / no-tier counts)
- tier-1+2 ("verified-real-source") coverage percentage

Outputs

- Machine-readable JSON to ``--out-json`` (default
  ``audit/corpus_tags/derived/attack_class_taxonomy.json``).
- Human-readable markdown to ``--out-md`` (default
  ``docs/HACKERMAN_ATTACK_CLASS_TAXONOMY_<YYYY-MM-DD>.md``). The markdown is
  what the MCP callable links to as a source_ref.

The markdown structure follows the task spec:

- Top-50 attack classes by record count (table)
- Orphan classes (only in tier-3/4/5 - candidates for real-source backfill)
- Well-covered classes (>=50 records across >=3 corpus subtrees, >=80% tier-1/2)

The tool is read-only against the corpus tree; safe to run on a worktree that
has parallel writers (it does not mutate any tagged record). It uses an
explicit glob (``record.yaml`` preferred, ``record.json`` as fallback when
the YAML is missing) so it ignores the loose flat ``corpus-mined-*.yaml``
files at the ``tags/`` root.
"""
from __future__ import annotations

import argparse
import datetime
import json
import math
import os
import re
import sys
from collections import defaultdict
from pathlib import Path
from typing import Any, Iterable

# YAML is optional - prefer json if available.
try:  # pragma: no cover - import guarded for test envs without PyYAML.
    import yaml  # type: ignore[import-not-found]
except Exception:  # noqa: BLE001 - degrade to minimal subset parser.
    yaml = None  # type: ignore[assignment]


REPO_ROOT = Path(__file__).resolve().parent.parent
DEFAULT_TAGS_DIR = REPO_ROOT / "audit" / "corpus_tags" / "tags"
DEFAULT_OUT_JSON = REPO_ROOT / "audit" / "corpus_tags" / "derived" / "attack_class_taxonomy.json"
SCHEMA = "auditooor.hackerman_attack_class_taxonomy.v1"

VERIFICATION_TIER_TAG_RE = re.compile(r"^verification_tier:tier-([1-5])-[a-z0-9-]+$")
VERIFICATION_TIER_QUARANTINE = 5

TOP_N_DEFAULT = 50
WELL_COVERED_MIN_RECORDS = 50
WELL_COVERED_MIN_SUBTREES = 3
WELL_COVERED_MIN_TIER12_PCT = 80.0

# --- P45 corpus origin-skew metric -----------------------------------------
# Advisory-first behind a NAMED env flag, DEFAULT OFF. When unset, the tool
# still EMITS the additive ``origin``/``origin_skew`` keys (read-only, no
# reader breaks), but prints NO advisory warnings and takes NO strict action -
# so flag-unset stdout/exit behavior is identical to the pre-P45 baseline
# aside from those additive JSON keys. When set, the tool emits stderr WARN
# advisories on high skew / insufficient SELF sample. It is intentionally NOT
# on any blocking path (never changes the process exit code).
SKEW_STRICT_ENV = "AUDITOOOR_CORPUS_SKEW_STRICT"

# Origin buckets. SELF == an own-confirmed audit finding record; INDEPENDENT ==
# everything else (solodit / prior-audit / etl-from-* / synthetic corpus).
ORIGIN_SELF = "self"
ORIGIN_INDEPENDENT = "independent"

# The SELF corpus is tiny (~0.4% of records); a JSD/slope skew over a
# near-empty SELF distribution is statistically degenerate. Below this floor
# of SELF records we emit an ``insufficient-SELF-sample`` sentinel instead of
# a misleading number.
ORIGIN_SKEW_MIN_SELF_RECORDS = 30

# Advisory thresholds (only surfaced as stderr WARN when the strict flag is
# set). JSD is in [0, 1] (log base 2).
ORIGIN_SKEW_WARN_JSD = 0.30


def _record_origin(record: dict[str, Any] | None) -> str:
    """Bucket a record as SELF (own-confirmed finding) vs INDEPENDENT.

    Mirrors the SELF mechanic used by
    ``tools/recurrence-as-promotion-signal.py`` (record_extensions.
    confirmed_finding + own-finding: id prefix) - NOT a non-existent
    ``provenance.kind`` (no corpus record carries such a block; keying on it
    would mis-bucket every SELF record, which is the exact bug this build
    exists to fix).

    SELF iff ANY of:
      - ``record_extensions.confirmed_finding`` is truthy, OR
      - ``record_id`` starts with ``own-finding:``, OR
      - ``source_audit_ref`` starts with ``own-finding:``.

    INDEPENDENT is the strict complement (any record failing the SELF signal),
    so no third origin can leak in.
    """
    if not isinstance(record, dict):
        return ORIGIN_INDEPENDENT
    ext = record.get("record_extensions")
    if isinstance(ext, dict):
        confirmed = ext.get("confirmed_finding")
        # Accept python bool True, or string "true"/"True" (YAML fallback
        # parser yields strings for scalar values).
        if confirmed is True or str(confirmed).strip().lower() == "true":
            return ORIGIN_SELF
    for key in ("record_id", "source_audit_ref"):
        val = record.get(key)
        if isinstance(val, str) and val.strip().lower().startswith("own-finding:"):
            return ORIGIN_SELF
    return ORIGIN_INDEPENDENT


def _jensen_shannon_divergence(
    p: dict[str, float], q: dict[str, float]
) -> float:
    """Jensen-Shannon divergence (base-2, so range [0, 1]) between two
    categorical distributions given as ``{category: probability}`` maps.

    Missing keys are treated as probability 0. Distributions are re-normalized
    defensively so callers can pass raw counts (they are normalized here).
    Returns 0.0 for identical distributions, 1.0 for maximally disjoint.
    """
    keys = set(p) | set(q)
    if not keys:
        return 0.0
    sp = sum(max(0.0, float(p.get(k, 0.0))) for k in keys)
    sq = sum(max(0.0, float(q.get(k, 0.0))) for k in keys)
    if sp <= 0.0 or sq <= 0.0:
        return 0.0
    pn = {k: max(0.0, float(p.get(k, 0.0))) / sp for k in keys}
    qn = {k: max(0.0, float(q.get(k, 0.0))) / sq for k in keys}

    def _kl(a: dict[str, float], b: dict[str, float]) -> float:
        total = 0.0
        for k in keys:
            ak = a[k]
            bk = b[k]
            if ak > 0.0 and bk > 0.0:
                total += ak * math.log2(ak / bk)
        return total

    m = {k: 0.5 * (pn[k] + qn[k]) for k in keys}
    jsd = 0.5 * _kl(pn, m) + 0.5 * _kl(qn, m)
    # Clamp tiny negative FP noise / >1 overshoot into [0, 1].
    if jsd < 0.0:
        return 0.0
    if jsd > 1.0:
        return 1.0
    return jsd


def build_origin_skew(inv_classes: list[dict[str, Any]]) -> dict[str, Any]:
    """Compute the SELF-vs-INDEPENDENT origin-skew metric over the per-class
    inventory.

    Builds two categorical distributions over attack_class - one from the SELF
    (own-confirmed-finding) records, one from the INDEPENDENT records - and
    reports:

    - ``jensen_shannon_divergence``: how differently the two origins spread
      across attack classes (0 = identical spread, 1 = disjoint). ``None`` when
      the SELF sample is below the floor.
    - ``slope``: SELF-share slope across attack classes ranked by INDEPENDENT
      volume (a positive slope means SELF findings concentrate in the high-
      volume-independent classes; negative means SELF explores the long tail).
      ``None`` when the SELF sample is below the floor.
    - ``self_records`` / ``independent_records`` totals.
    - ``sufficient_self_sample`` bool + ``sentinel`` string when insufficient.
    - ``top_self_skew_classes``: per-class SELF over-/under-representation vs
      the INDEPENDENT baseline (ranked), always emitted (advisory).

    Never re-sorts ``inv_classes`` - reads it and returns a standalone block.
    """
    self_by_class: dict[str, int] = {}
    indep_by_class: dict[str, int] = {}
    self_total = 0
    indep_total = 0
    for row in inv_classes:
        ac = str(row.get("attack_class") or "")
        if not ac or ac == "<missing-attack-class>":
            continue
        origin = row.get("origin") or {}
        s = int(origin.get(ORIGIN_SELF, 0)) if isinstance(origin, dict) else 0
        i = int(origin.get(ORIGIN_INDEPENDENT, 0)) if isinstance(origin, dict) else 0
        if s:
            self_by_class[ac] = s
            self_total += s
        if i:
            indep_by_class[ac] = i
            indep_total += i

    sufficient = self_total >= ORIGIN_SKEW_MIN_SELF_RECORDS

    # Per-class SELF over/under representation vs INDEPENDENT baseline. Always
    # emitted (advisory; harmless when SELF is tiny).
    self_share = {
        k: (v / self_total) for k, v in self_by_class.items()
    } if self_total else {}
    indep_share = {
        k: (v / indep_total) for k, v in indep_by_class.items()
    } if indep_total else {}
    skew_rows: list[dict[str, Any]] = []
    for ac in sorted(set(self_share) | set(indep_share)):
        s_sh = self_share.get(ac, 0.0)
        i_sh = indep_share.get(ac, 0.0)
        skew_rows.append(
            {
                "attack_class": ac,
                "self_count": int(self_by_class.get(ac, 0)),
                "independent_count": int(indep_by_class.get(ac, 0)),
                "self_share": round(s_sh, 6),
                "independent_share": round(i_sh, 6),
                "over_representation": round(s_sh - i_sh, 6),
            }
        )
    # Rank by absolute over-representation desc, then attack_class asc.
    skew_rows.sort(key=lambda r: (-abs(r["over_representation"]), r["attack_class"]))

    out: dict[str, Any] = {
        "self_records": self_total,
        "independent_records": indep_total,
        "min_self_records_floor": ORIGIN_SKEW_MIN_SELF_RECORDS,
        "sufficient_self_sample": bool(sufficient),
        "distinct_self_classes": len(self_by_class),
        "distinct_independent_classes": len(indep_by_class),
        "top_self_skew_classes": skew_rows[:30],
    }

    if not sufficient:
        out["jensen_shannon_divergence"] = None
        out["slope"] = None
        out["sentinel"] = "insufficient-SELF-sample"
        return out

    out["sentinel"] = None
    out["jensen_shannon_divergence"] = round(
        _jensen_shannon_divergence(self_by_class, indep_by_class), 6
    )

    # Slope: least-squares slope of SELF-share (y) against the rank of the
    # class by INDEPENDENT volume (x). Ranks are dense 0..n-1, high-volume
    # independent classes first. A positive slope => SELF findings are
    # over-concentrated where INDEPENDENT volume is already high.
    ranked = sorted(
        set(self_by_class) | set(indep_by_class),
        key=lambda a: (-indep_by_class.get(a, 0), a),
    )
    xs = list(range(len(ranked)))
    ys = [self_share.get(a, 0.0) for a in ranked]
    out["slope"] = round(_least_squares_slope(xs, ys), 8)
    return out


def _least_squares_slope(xs: list[int], ys: list[float]) -> float:
    """Ordinary least-squares slope of ys on xs. Returns 0.0 for <2 points or
    a degenerate (zero-variance) x."""
    n = len(xs)
    if n < 2:
        return 0.0
    mean_x = sum(xs) / n
    mean_y = sum(ys) / n
    num = sum((x - mean_x) * (y - mean_y) for x, y in zip(xs, ys))
    den = sum((x - mean_x) ** 2 for x in xs)
    if den == 0.0:
        return 0.0
    return num / den


def _yaml_load(text: str) -> dict[str, Any]:
    """Best-effort YAML load. Falls back to a minimal key:value parser
    when PyYAML is unavailable - the corpus uses a small subset on the
    fields we care about (``attack_class`` + ``function_shape.shape_tags``)."""
    if yaml is not None:
        try:
            data = yaml.safe_load(text)
            return data if isinstance(data, dict) else {}
        except Exception:  # noqa: BLE001
            return {}
    # Minimal fallback - good enough for the two fields we read.
    out: dict[str, Any] = {}
    current_list_key: str | None = None
    current_subkey: str | None = None
    in_function_shape = False
    shape_tags: list[str] = []
    for raw in text.splitlines():
        line = raw.rstrip()
        if not line or line.startswith("#"):
            continue
        if line.startswith("function_shape:"):
            in_function_shape = True
            current_list_key = None
            continue
        if in_function_shape and line.startswith("  ") and not line.startswith("    "):
            current_subkey = line.strip().rstrip(":")
            if current_subkey == "shape_tags":
                current_list_key = "shape_tags"
            else:
                current_list_key = None
            continue
        if in_function_shape and current_list_key == "shape_tags" and line.startswith("    - "):
            shape_tags.append(line[6:].strip().strip("\"'"))
            continue
        if not line.startswith(" "):
            in_function_shape = False
            current_list_key = None
            if ":" in line:
                k, _, v = line.partition(":")
                out[k.strip()] = v.strip().strip("\"'")
    if shape_tags:
        out["function_shape"] = {"shape_tags": shape_tags}
    return out


def _load_record(path: Path) -> dict[str, Any]:
    """Load one record.{json,yaml}. Returns {} on any I/O or parse error."""
    try:
        text = path.read_text(encoding="utf-8")
    except OSError:
        return {}
    if path.suffix == ".json":
        try:
            data = json.loads(text)
            return data if isinstance(data, dict) else {}
        except json.JSONDecodeError:
            return {}
    return _yaml_load(text)


def _extract_verification_tier(record: dict[str, Any] | None) -> int | None:
    """Return tier int from function_shape.shape_tags, or None.

    Defensive on bad inputs (None / non-dict) so callers can pass raw
    parse results without pre-validating.
    """
    if not isinstance(record, dict):
        return None
    shape = record.get("function_shape")
    if not isinstance(shape, dict):
        return None
    tags = shape.get("shape_tags")
    if not isinstance(tags, list):
        return None
    for tag in tags:
        text = str(tag or "").strip()
        m = VERIFICATION_TIER_TAG_RE.match(text)
        if m:
            try:
                return int(m.group(1))
            except ValueError:
                continue
    return None


def _walk_records(tags_dir: Path) -> Iterable[tuple[Path, dict[str, Any]]]:
    """Walk ``tags_dir/**/record.{yaml,json}`` and yield (path, record)
    pairs. YAML preferred over JSON when both exist in the same dir."""
    seen_dirs: set[Path] = set()
    for path in sorted(tags_dir.rglob("record.yaml")):
        seen_dirs.add(path.parent)
        rec = _load_record(path)
        if rec:
            yield path, rec
    for path in sorted(tags_dir.rglob("record.json")):
        if path.parent in seen_dirs:
            continue
        rec = _load_record(path)
        if rec:
            yield path, rec


def _subtree_of(path: Path, tags_dir: Path) -> str:
    """Return the top-level corpus subtree under ``tags_dir`` for a record path.
    e.g. ``tags/lending_protocols/foo/record.yaml`` -> ``lending_protocols``."""
    try:
        rel = path.relative_to(tags_dir)
    except ValueError:
        return "_unknown"
    parts = rel.parts
    if not parts:
        return "_unknown"
    return parts[0]


def build_per_subtree_breakdown(
    tags_dir: Path,
) -> dict[str, dict[str, Any]]:
    """Second-pass aggregation: per-subtree class diversity + tier coverage.

    Returns ``{subtree: {total_records, distinct_classes, tier_counts}}``.
    """
    out: dict[str, dict[str, Any]] = defaultdict(
        lambda: {
            "total_records": 0,
            "classes": set(),
            "tier_counts": defaultdict(int),
        }
    )
    for path, record in _walk_records(tags_dir):
        subtree = _subtree_of(path, tags_dir)
        ac = str(record.get("attack_class") or "<missing-attack-class>").strip()
        tier = _extract_verification_tier(record)
        tier_key = f"tier-{tier}" if isinstance(tier, int) else "no-tier"
        entry = out[subtree]
        entry["total_records"] += 1
        entry["classes"].add(ac)
        entry["tier_counts"][tier_key] += 1
    finished: dict[str, dict[str, Any]] = {}
    for s, entry in out.items():
        tc = entry["tier_counts"]
        tier1 = int(tc.get("tier-1", 0))
        tier2 = int(tc.get("tier-2", 0))
        total = int(entry["total_records"])
        finished[s] = {
            "total_records": total,
            "distinct_classes": len(entry["classes"]),
            "tier_counts": {k: int(v) for k, v in sorted(tc.items())},
            "tier1_count": tier1,
            "tier2_count": tier2,
            "tier12_count": tier1 + tier2,
            "tier12_pct": round(((tier1 + tier2) / total) * 100.0, 2) if total else 0.0,
        }
    return finished


def build_inventory(tags_dir: Path) -> dict[str, Any]:
    """Walk the tags dir and aggregate per-attack-class statistics.

    Returns a dict with:

    - ``schema``: schema id
    - ``tags_dir``: absolute tags dir path
    - ``total_records``: count of records walked
    - ``subtrees``: list of corpus subtree names seen
    - ``classes``: list of per-class records sorted by total count desc

    Each ``classes[i]`` entry has:

    - ``attack_class`` (str)
    - ``total_records`` (int)
    - ``subtrees`` (list[str], sorted)
    - ``tier_counts``: dict[str, int] keyed ``tier-1``..``tier-5``, ``no-tier``
    - ``tier1_count``, ``tier2_count`` (ints, for table convenience)
    - ``tier12_count`` (int)
    - ``tier12_pct`` (float, 0..100, two decimals)
    """
    classes: dict[str, dict[str, Any]] = defaultdict(
        lambda: {
            "total_records": 0,
            "subtrees": set(),
            "tier_counts": defaultdict(int),
            # P45: per-class origin counts (SELF vs INDEPENDENT), folded here
            # alongside tier_counts so a single walk produces both.
            "origin_counts": defaultdict(int),
        }
    )
    total = 0
    subtrees_seen: set[str] = set()

    for path, record in _walk_records(tags_dir):
        ac = str(record.get("attack_class") or "").strip()
        if not ac:
            ac = "<missing-attack-class>"
        subtree = _subtree_of(path, tags_dir)
        subtrees_seen.add(subtree)
        tier = _extract_verification_tier(record)
        tier_key = f"tier-{tier}" if isinstance(tier, int) else "no-tier"
        origin = _record_origin(record)

        entry = classes[ac]
        entry["total_records"] += 1
        entry["subtrees"].add(subtree)
        entry["tier_counts"][tier_key] += 1
        entry["origin_counts"][origin] += 1
        total += 1

    out_classes: list[dict[str, Any]] = []
    for ac, entry in classes.items():
        tc = entry["tier_counts"]
        tier1 = int(tc.get("tier-1", 0))
        tier2 = int(tc.get("tier-2", 0))
        total_for_class = int(entry["total_records"])
        tier12 = tier1 + tier2
        tier12_pct = round((tier12 / total_for_class) * 100.0, 2) if total_for_class else 0.0
        oc = entry["origin_counts"]
        origin_self = int(oc.get(ORIGIN_SELF, 0))
        origin_indep = int(oc.get(ORIGIN_INDEPENDENT, 0))
        out_classes.append(
            {
                "attack_class": ac,
                "total_records": total_for_class,
                "subtrees": sorted(entry["subtrees"]),
                "tier_counts": {k: int(v) for k, v in sorted(tc.items())},
                "tier1_count": tier1,
                "tier2_count": tier2,
                "tier12_count": tier12,
                "tier12_pct": tier12_pct,
                # P45 additive per-class key. SELF == own-confirmed-finding
                # records; INDEPENDENT == the complement.
                "origin": {
                    ORIGIN_SELF: origin_self,
                    ORIGIN_INDEPENDENT: origin_indep,
                },
            }
        )
    # Stable sort: total_records desc, then attack_class asc. (Origin keys do
    # NOT participate in the sort - class ordering is byte-stable vs baseline.)
    out_classes.sort(key=lambda r: (-r["total_records"], r["attack_class"]))

    per_subtree = build_per_subtree_breakdown(tags_dir)

    # P45 additive top-level block. Standalone; does not perturb classes[].
    origin_skew = build_origin_skew(out_classes)

    return {
        "schema": SCHEMA,
        "tags_dir": str(tags_dir),
        "total_records": total,
        "subtrees": sorted(subtrees_seen),
        "classes": out_classes,
        "per_subtree": per_subtree,
        "origin_skew": origin_skew,
    }


def _orphan_classes(inv: dict[str, Any]) -> list[dict[str, Any]]:
    """Classes with zero tier-1/2 coverage (only tier-3/4/5 or no-tier)."""
    out: list[dict[str, Any]] = []
    for row in inv["classes"]:
        if row["attack_class"] == "<missing-attack-class>":
            continue
        if row["tier12_count"] == 0 and row["total_records"] > 0:
            out.append(row)
    return out


def _well_covered_classes(inv: dict[str, Any]) -> list[dict[str, Any]]:
    """Classes that pass: >=50 records, >=3 subtrees, >=80% tier-1+2."""
    out: list[dict[str, Any]] = []
    for row in inv["classes"]:
        if row["attack_class"] == "<missing-attack-class>":
            continue
        if (
            row["total_records"] >= WELL_COVERED_MIN_RECORDS
            and len(row["subtrees"]) >= WELL_COVERED_MIN_SUBTREES
            and row["tier12_pct"] >= WELL_COVERED_MIN_TIER12_PCT
        ):
            out.append(row)
    return out


def _render_markdown(inv: dict[str, Any], top_n: int = TOP_N_DEFAULT) -> str:
    today = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%d")
    lines: list[str] = []
    lines.append(f"# Hackerman attack-class taxonomy inventory ({today})")
    lines.append("")
    lines.append(
        "Wave-1 hackerman capability lift (PR #726) - cross-corpus attack-class "
        "taxonomy. Aggregated from "
        f"`{inv['tags_dir']}` by walking `**/record.{{json,yaml}}` "
        "(YAML preferred when both exist)."
    )
    lines.append("")
    lines.append(
        "The inventory powers cross-corpus attack-class similarity queries "
        "(MCP callable `vault_attack_class_taxonomy`, schema "
        "`auditooor.vault_attack_class_taxonomy.v1`). It is the front door "
        "for picking real-source backfill targets - classes that only show "
        "up in tier-3/4/5 (synthetic / fixture / quarantine) corpora need "
        "tier-1/2 (verified real-source) anchors before they can carry HIGH+ "
        "filings under Rule 27 / Rule 30 / R32 evidence-class discipline."
    )
    lines.append("")
    lines.append(f"- Total records walked: **{inv['total_records']}**")
    lines.append(f"- Distinct attack_class values: **{len(inv['classes'])}**")
    lines.append(
        "- Corpus subtrees: "
        + ", ".join(f"`{s}`" for s in inv["subtrees"])
    )
    lines.append("")

    # Section 1: Top-N table.
    lines.append(f"## Top-{top_n} attack classes by record count")
    lines.append("")
    lines.append(
        "| # | attack_class | count | subtrees | tier-1 | tier-2 | tier-1+2 % |"
    )
    lines.append("|---|--------------|------:|----------|------:|------:|----------:|")
    for i, row in enumerate(inv["classes"][:top_n], 1):
        subs = ", ".join(row["subtrees"]) if row["subtrees"] else "-"
        lines.append(
            f"| {i} | `{row['attack_class']}` | {row['total_records']} | "
            f"{subs} | {row['tier1_count']} | {row['tier2_count']} | "
            f"{row['tier12_pct']:.2f}% |"
        )
    lines.append("")

    # Section 2: Orphans.
    orphans = _orphan_classes(inv)
    lines.append("## Orphan classes (zero tier-1/2 coverage)")
    lines.append("")
    lines.append(
        "Classes with no tier-1 (verified-realtime-API) or tier-2 "
        "(verified-public-archive) records. These are real-source backfill "
        "candidates - the corpus already has structural evidence but no "
        "verifiable upstream anchor."
    )
    lines.append("")
    if not orphans:
        lines.append("_No orphans - every class has at least one tier-1/2 anchor._")
    else:
        lines.append(
            "| # | attack_class | total | subtrees | tier-3 | tier-4 | tier-5 | no-tier |"
        )
        lines.append(
            "|---|--------------|------:|----------|------:|------:|------:|--------:|"
        )
        for i, row in enumerate(orphans[:100], 1):
            tc = row["tier_counts"]
            subs = ", ".join(row["subtrees"]) if row["subtrees"] else "-"
            lines.append(
                f"| {i} | `{row['attack_class']}` | {row['total_records']} | "
                f"{subs} | {tc.get('tier-3', 0)} | {tc.get('tier-4', 0)} | "
                f"{tc.get('tier-5', 0)} | {tc.get('no-tier', 0)} |"
            )
        if len(orphans) > 100:
            lines.append("")
            lines.append(
                f"_({len(orphans) - 100} more orphan classes elided; see JSON output for the full list.)_"
            )
    lines.append("")

    # Section 3: Well-covered.
    well = _well_covered_classes(inv)
    lines.append("## Well-covered classes")
    lines.append("")
    lines.append(
        f"Classes with **>={WELL_COVERED_MIN_RECORDS}** records across "
        f"**>={WELL_COVERED_MIN_SUBTREES}** subtrees, **>="
        f"{WELL_COVERED_MIN_TIER12_PCT:.0f}%** tier-1+2 coverage. Safe to "
        "cite as cross-corpus similarity anchors for HIGH+ filings without "
        "additional real-source backfill."
    )
    lines.append("")
    if not well:
        lines.append("_No classes meet the well-covered threshold yet._")
    else:
        lines.append(
            "| # | attack_class | count | subtrees | tier-1+2 | tier-1+2 % |"
        )
        lines.append(
            "|---|--------------|------:|----------|---------:|----------:|"
        )
        for i, row in enumerate(well, 1):
            subs = ", ".join(row["subtrees"]) if row["subtrees"] else "-"
            lines.append(
                f"| {i} | `{row['attack_class']}` | {row['total_records']} | "
                f"{subs} | {row['tier12_count']} | {row['tier12_pct']:.2f}% |"
            )
    lines.append("")

    # Section 4: per-subtree coverage.
    lines.append("## Per-subtree coverage")
    lines.append("")
    lines.append(
        "Distribution of records, distinct attack_class values, and "
        "verification-tier breakdown per top-level corpus subtree. Use this "
        "to spot subtrees that are bulk-tagged with a single class "
        "(low signal-per-record) vs subtrees with class diversity "
        "(high signal-per-record)."
    )
    lines.append("")
    lines.append(
        "| subtree | records | distinct classes | tier-1 | tier-2 | tier-3 | "
        "tier-4 | tier-5 | no-tier | tier-1+2 % |"
    )
    lines.append(
        "|---------|--------:|-----------------:|------:|------:|------:|"
        "------:|------:|--------:|----------:|"
    )
    per_subtree = inv.get("per_subtree", {})
    for subtree in inv["subtrees"]:
        s = per_subtree.get(subtree, {})
        tc = s.get("tier_counts", {})
        lines.append(
            f"| `{subtree}` | {s.get('total_records', 0)} | "
            f"{s.get('distinct_classes', 0)} | "
            f"{tc.get('tier-1', 0)} | {tc.get('tier-2', 0)} | "
            f"{tc.get('tier-3', 0)} | {tc.get('tier-4', 0)} | "
            f"{tc.get('tier-5', 0)} | {tc.get('no-tier', 0)} | "
            f"{s.get('tier12_pct', 0.0):.2f}% |"
        )
    lines.append("")

    # Section 5: aggregate tier histogram across the corpus.
    lines.append("## Aggregate verification-tier histogram")
    lines.append("")
    agg = defaultdict(int)
    for row in inv["classes"]:
        for k, v in row["tier_counts"].items():
            agg[k] += int(v)
    total = inv["total_records"] or 1
    lines.append("| tier | records | share |")
    lines.append("|------|--------:|------:|")
    for tier_key in ("tier-1", "tier-2", "tier-3", "tier-4", "tier-5", "no-tier"):
        n = int(agg.get(tier_key, 0))
        pct = (n / total) * 100.0
        lines.append(f"| `{tier_key}` | {n} | {pct:.2f}% |")
    lines.append("")
    lines.append(
        "Tier semantics (see `tools/hackerman-apply-verification-tier.py`):"
    )
    lines.append("")
    lines.append(
        "- **tier-1** verified-realtime-API (e.g. GHSA REST, live CVE feed)"
    )
    lines.append("- **tier-2** verified-public-archive (e.g. fixed git commit / DEX fix-history diff)")
    lines.append("- **tier-3** synthetic-taxonomy-anchored (DSL pattern lifted to schema, anchor stable)")
    lines.append("- **tier-4** bundled-fixture (test-only, no production anchor)")
    lines.append("- **tier-5** quarantine (fabricated / non-reproducible; excluded from MCP by default)")
    lines.append("")

    # Section 5b: real-source backfill priority ranking.
    lines.append("## Real-source backfill priority")
    lines.append("")
    lines.append(
        "Ranked list of orphan classes weighted by record volume - the larger "
        "the orphan, the higher the leverage of adding even one tier-1/tier-2 "
        "anchor (the entire family of structural matches gets a credible "
        "anchor at once). Top entries are the natural targets for the next "
        "wave of `tools/hackerman-etl-from-*` real-source miners."
    )
    lines.append("")
    backfill = sorted(
        orphans,
        key=lambda r: (-r["total_records"], r["attack_class"]),
    )[:30]
    if not backfill:
        lines.append("_No orphans - real-source coverage is already complete._")
    else:
        lines.append("| rank | attack_class | orphan records | dominant subtree |")
        lines.append("|-----:|--------------|---------------:|------------------|")
        for i, row in enumerate(backfill, 1):
            dom = row["subtrees"][0] if row["subtrees"] else "-"
            lines.append(
                f"| {i} | `{row['attack_class']}` | {row['total_records']} | `{dom}` |"
            )
    lines.append("")

    # Section 5c: per-subtree top-5 attack classes (signal-density view).
    lines.append("## Top-5 attack classes per subtree")
    lines.append("")
    lines.append(
        "For each corpus subtree, the five highest-volume attack_class "
        "values present, with their tier-1+2 coverage. This surfaces which "
        "subtrees are concentrated in a single class (e.g. "
        "`audit_firm_public_reports` is 100% `audit-firm-public-report`) "
        "vs which spread across many."
    )
    lines.append("")
    # Reconstruct per-subtree top classes by scanning the classes list.
    subtree_to_classes: dict[str, list[tuple[str, int, float]]] = defaultdict(list)
    for row in inv["classes"]:
        for sub in row["subtrees"]:
            # Approximate: assume the whole class lives in `sub` if it is the
            # only subtree. For multi-subtree classes we still surface the
            # class name in each subtree (record-precise per-subtree counts
            # would require a second-pass walk; the per_subtree table above
            # already gives the exact tier histogram per subtree).
            subtree_to_classes[sub].append(
                (row["attack_class"], row["total_records"], row["tier12_pct"])
            )
    for subtree in inv["subtrees"]:
        entries = sorted(
            subtree_to_classes.get(subtree, []),
            key=lambda x: (-x[1], x[0]),
        )[:5]
        if not entries:
            continue
        lines.append(f"### `{subtree}`")
        lines.append("")
        lines.append("| attack_class | (class total) records | tier-1+2 % |")
        lines.append("|--------------|----------------------:|----------:|")
        for ac, cnt, pct in entries:
            lines.append(f"| `{ac}` | {cnt} | {pct:.2f}% |")
        lines.append("")

    # Section 5d (P45): corpus origin skew (SELF vs INDEPENDENT).
    skew = inv.get("origin_skew") or {}
    lines.append("## Corpus origin skew (SELF vs INDEPENDENT)")
    lines.append("")
    lines.append(
        "Split of the corpus by record origin. **SELF** records are "
        "own-confirmed audit findings (`record_extensions.confirmed_finding` "
        "or an `own-finding:` id); **INDEPENDENT** records are everything else "
        "(solodit / prior-audit / `etl-from-*` / synthetic). The Jensen-Shannon "
        "divergence (base-2, `[0, 1]`) measures how differently the two origins "
        "spread across attack classes; the slope measures whether SELF findings "
        "concentrate in the high-volume INDEPENDENT classes (positive) or "
        "explore the long tail (negative)."
    )
    lines.append("")
    lines.append(
        f"- SELF records: **{int(skew.get('self_records', 0))}** "
        f"(min-sample floor **{int(skew.get('min_self_records_floor', 0))}**)"
    )
    lines.append(f"- INDEPENDENT records: **{int(skew.get('independent_records', 0))}**")
    if not skew.get("sufficient_self_sample", False):
        lines.append(
            f"- Skew metric: _{skew.get('sentinel') or 'insufficient-SELF-sample'}_ "
            "(SELF sample below floor; JSD / slope suppressed as statistically "
            "degenerate)"
        )
    else:
        jsd = skew.get("jensen_shannon_divergence")
        slope = skew.get("slope")
        lines.append(
            f"- Jensen-Shannon divergence: **{jsd:.6f}**"
            if isinstance(jsd, (int, float))
            else "- Jensen-Shannon divergence: _n/a_"
        )
        lines.append(
            f"- SELF-share slope over INDEPENDENT-rank: **{slope:.8f}**"
            if isinstance(slope, (int, float))
            else "- SELF-share slope: _n/a_"
        )
    lines.append("")
    top_skew = skew.get("top_self_skew_classes") or []
    if top_skew:
        lines.append(
            "Top classes by SELF over-/under-representation vs the INDEPENDENT "
            "baseline (positive = SELF over-represented):"
        )
        lines.append("")
        lines.append(
            "| attack_class | SELF | INDEP | SELF share | INDEP share | over-rep |"
        )
        lines.append(
            "|--------------|-----:|------:|-----------:|------------:|---------:|"
        )
        for r in top_skew[:20]:
            lines.append(
                f"| `{r['attack_class']}` | {r['self_count']} | "
                f"{r['independent_count']} | {r['self_share']:.4f} | "
                f"{r['independent_share']:.4f} | {r['over_representation']:+.4f} |"
            )
    else:
        lines.append("_No SELF (own-confirmed-finding) records in the corpus yet._")
    lines.append("")

    # Section 6: methodology + reproducibility.
    lines.append("## Methodology")
    lines.append("")
    lines.append(
        "1. Walk `audit/corpus_tags/tags/**/record.{yaml,json}` (YAML preferred when both exist). "
        "Loose flat `corpus-mined-*.yaml` / `solodit-spec:*.yaml` files at the "
        "`tags/` root are intentionally **excluded** - this inventory is "
        "scoped to the curated subtree-of-record convention, where each "
        "record has its own directory."
    )
    lines.append(
        "2. For each record, read `attack_class` (top-level field) and "
        "`function_shape.shape_tags[]`. Verification tier is extracted from "
        "the first shape_tag matching `verification_tier:tier-([1-5])-[a-z0-9-]+`."
    )
    lines.append(
        "3. The top-level dir under `tags/` is the corpus subtree (e.g. "
        "`lending_protocols`, `audit_firm_public_reports`)."
    )
    lines.append(
        "4. Aggregation is stable: tied counts sort by `attack_class` ascending."
    )
    lines.append("")
    lines.append(
        "Reproduce: `python3 tools/hackerman-attack-class-inventory.py`. JSON "
        "output lives at `audit/corpus_tags/derived/attack_class_taxonomy.json` "
        "and is what the MCP callable `vault_attack_class_taxonomy` reads."
    )
    lines.append("")

    # Section 7: integration hooks.
    lines.append("## MCP integration")
    lines.append("")
    lines.append(
        "The MCP callable `vault_attack_class_taxonomy` exposes the taxonomy "
        "as a context envelope. It takes `{workspace_path, limit, "
        "min_records, min_tier_coverage_pct}` and returns:"
    )
    lines.append("")
    lines.append("- `schema` (`auditooor.vault_attack_class_taxonomy.v1`)")
    lines.append("- `context_pack_id` + `context_pack_hash` (MCP receipt envelope)")
    lines.append("- `classes[]` filtered + sorted by `total_records` desc")
    lines.append("- `orphans[]` (zero tier-1/2 coverage)")
    lines.append("- `well_covered[]` (>=50 records, >=3 subtrees, >=80% tier-1/2)")
    lines.append("- `per_subtree{}` coverage breakdown")
    lines.append("- `source_refs[]` pointing back at this markdown and the JSON.")
    lines.append("")
    lines.append(
        "Filter knobs: `min_records` (drop low-volume classes) and "
        "`min_tier_coverage_pct` (drop classes whose tier-1+2 share falls "
        "below the threshold) let lane workers focus their similarity "
        "queries on the cross-corpus subset that is safe to cite."
    )
    lines.append("")

    # Footer.
    lines.append("---")
    lines.append("")
    lines.append(
        f"Generated by `tools/hackerman-attack-class-inventory.py`. Schema "
        f"`{inv['schema']}`. See PR #726 for the wave-1 hackerman capability "
        "lift roadmap."
    )
    lines.append("")
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--tags-dir", default=str(DEFAULT_TAGS_DIR))
    p.add_argument("--out-json", default=str(DEFAULT_OUT_JSON))
    # Default to UTC today; ``AUDITOOOR_TAXONOMY_DATE`` env var pins a stable date
    # for the wave-1 deliverable so the markdown filename is reproducible across
    # operator timezones.
    import os
    today = os.environ.get(
        "AUDITOOOR_TAXONOMY_DATE",
        datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%d"),
    )
    default_md = str(REPO_ROOT / "docs" / f"HACKERMAN_ATTACK_CLASS_TAXONOMY_{today}.md")
    p.add_argument("--out-md", default=default_md)
    p.add_argument("--top-n", type=int, default=TOP_N_DEFAULT)
    p.add_argument("--no-md", action="store_true", help="Skip markdown emission.")
    p.add_argument("--quiet", action="store_true")
    args = p.parse_args(argv)

    tags_dir = Path(args.tags_dir).expanduser()
    if not tags_dir.exists():
        print(f"error: tags-dir not found: {tags_dir}", file=sys.stderr)
        return 2

    inv = build_inventory(tags_dir)

    # P45: advisory-first origin-skew warnings, gated behind a NAMED env flag
    # (default OFF). When unset this block is a no-op, so flag-unset stdout /
    # stderr / exit behavior is byte-identical to the pre-P45 baseline (aside
    # from the additive JSON/markdown keys). Never changes the exit code.
    if os.environ.get(SKEW_STRICT_ENV):
        skew = inv.get("origin_skew") or {}
        if not skew.get("sufficient_self_sample", False):
            print(
                f"WARN[{SKEW_STRICT_ENV}]: corpus origin-skew SELF sample "
                f"below floor ({int(skew.get('self_records', 0))} < "
                f"{int(skew.get('min_self_records_floor', 0))}); JSD/slope "
                f"suppressed ({skew.get('sentinel') or 'insufficient-SELF-sample'}).",
                file=sys.stderr,
            )
        else:
            jsd = skew.get("jensen_shannon_divergence")
            if isinstance(jsd, (int, float)) and jsd >= ORIGIN_SKEW_WARN_JSD:
                print(
                    f"WARN[{SKEW_STRICT_ENV}]: high SELF-vs-INDEPENDENT origin "
                    f"skew (Jensen-Shannon divergence {jsd:.4f} >= "
                    f"{ORIGIN_SKEW_WARN_JSD}); SELF findings spread differently "
                    "from the independent corpus across attack classes.",
                    file=sys.stderr,
                )

    out_json = Path(args.out_json).expanduser()
    out_json.parent.mkdir(parents=True, exist_ok=True)
    out_json.write_text(json.dumps(inv, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    if not args.quiet:
        print(
            f"wrote {out_json} "
            f"({inv['total_records']} records / {len(inv['classes'])} classes / "
            f"{len(inv['subtrees'])} subtrees)"
        )

    if not args.no_md:
        md = _render_markdown(inv, top_n=int(args.top_n))
        out_md = Path(args.out_md).expanduser()
        out_md.parent.mkdir(parents=True, exist_ok=True)
        out_md.write_text(md, encoding="utf-8")
        if not args.quiet:
            print(f"wrote {out_md} ({len(md.splitlines())} lines)")

    return 0


if __name__ == "__main__":
    sys.exit(main())
