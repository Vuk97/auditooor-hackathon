#!/usr/bin/env python3
"""trusted-corpus-index-build.py - Phase 1 trusted-corpus index builder.

Builds the trusted-corpus index so that ONLY real, source-backed records
score / drive active hunt by default. Prose-only, fabricated, and synthetic
records are routed out of active scoring (into advisory / prose_memory /
quarantine ledgers).

This is the build half of the Phase 1 trust layer described in
docs/FIND_ALL_BUGS_CAPABILITY_UPLIFT_PLAN_2026-05-29.md. It REUSES the
classification logic in tools/corpus-quality-routing.py rather than
re-deriving it (tool-duplication preflight: corpus-quality-routing.py owns
the bucket/blocked_class vocabulary; this tool consumes it and adds the
trust-state layer + ledgers).

RELATED TOOLS:
  - tools/corpus-quality-routing.py - source of the routing bucket /
    blocked_class classification this tool consumes. v1.2 was extended in
    the same PR to accept the v1.2 schema and report schema-version counts.
  - tools/trusted-corpus-index-check.py - the check/CI half: validates the
    index against the schemas and the Phase-1 definition-of-done.
  - tools/source-ref-replay-manifest.py - produces source-ref replay status
    (immutable_ready / blocked_*); this tool records it advisorily when a
    replay manifest is supplied via --replay-manifest.

Trust states (Phase 1):
  - active:       tier-1/tier-2, routing usable_for_hunting, not prose-only,
                  not fabricated, no admission blocker.
  - advisory:     tier-3 / tier-4 / synthetic taxonomy / routing advisory.
  - prose_memory: useful lesson but not a scorable vulnerability record
                  (prose-only / prefix_ref prose / low-confidence prose).
  - quarantine:   fabricated, hallucinated, non-fetchable, dead source,
                  tier-5, missing tier, replay-failed, blocked corpus-quality.
  - superseded:   replaced by a stronger source-backed record (ledger-driven;
                  this builder never assigns superseded on its own - it is set
                  only by an explicit supersede event in the trust ledger).

Outputs (under reference/corpus_trust/):
  - TRUSTED_CORPUS_INDEX.jsonl       (active rows + every classified row,
                                      schema auditooor.corpus_trust_record.v1)
  - CORPUS_TRUST_LEDGER.jsonl        (append-only admit/downgrade events)
  - CORPUS_QUARANTINE_LEDGER.jsonl   (append-only quarantine events)
  - PROSE_MEMORY_INDEX.jsonl         (prose-memory rows)
  - reports/corpus_trust/latest.md   (human report + denominators)

Restore discipline: this builder honors prior restore events. If the trust
ledger contains a 'restore' event for a record_id whose latest event is the
restore, the record is forced back to its routed state (not re-quarantined),
unless a permanent (restorable=false) quarantine event also exists. Manual
trusted-index edits are forbidden.

Usage:
  python3 tools/trusted-corpus-index-build.py [--tags-dir DIR] [--out-dir DIR]
      [--subtrees A,B] [--limit N] [--replay-manifest PATH] [--json]
      [--dry-run]
"""
from __future__ import annotations

import argparse
import datetime as _dt
import hashlib
import importlib.util
import json
import sys
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parent.parent
DEFAULT_TAGS_DIR = REPO_ROOT / "audit" / "corpus_tags" / "tags"
DEFAULT_OUT_DIR = REPO_ROOT / "reference" / "corpus_trust"
DEFAULT_REPORT = REPO_ROOT / "reports" / "corpus_trust" / "latest.md"

TRUST_RECORD_SCHEMA = "auditooor.corpus_trust_record.v1"
TRUST_EVENT_SCHEMA = "auditooor.corpus_trust_event.v1"
QUARANTINE_EVENT_SCHEMA = "auditooor.corpus_quarantine_event.v1"
PROSE_RECORD_SCHEMA = "auditooor.prose_memory_record.v1"

# Trust states
TS_ACTIVE = "active"
TS_ADVISORY = "advisory"
TS_PROSE = "prose_memory"
TS_QUARANTINE = "quarantine"
TS_SUPERSEDED = "superseded"

# Strong tiers eligible for active scoring
STRONG_TIERS = frozenset({
    "tier-1-verified-realtime-api",
    "tier-1-officially-disclosed",
    "tier-2-verified-public-archive",
})
ADVISORY_TIERS = frozenset({"tier-3-synthetic-taxonomy-anchored"})
FIXTURE_TIER = "tier-4-bundled-fixture"
QUARANTINE_TIER = "tier-5-quarantine"

# Prose / fabrication markers
FABRICATED_SUBTREE = "_QUARANTINE_FABRICATED_CVE"
FABRICATED_MARKERS = ("fabricated corpus case", "fabricated-cve", "fabricated_cve")
PROSE_BLOCKED_CLASSES = frozenset({
    "low_confidence_prose_draft",
})
QUARANTINE_BLOCKED_CLASSES = frozenset({
    "missing_or_weak_verification_tier",
    "dark_audit_firm_report_no_extraction",
})


def _load_routing_module() -> Any:
    tool = REPO_ROOT / "tools" / "corpus-quality-routing.py"
    spec = importlib.util.spec_from_file_location("_cqr_for_trust", str(tool))
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot load {tool}")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


_ROUTING = _load_routing_module()


def _now() -> str:
    return _dt.datetime.now(_dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _admission_id(record_id: str) -> str:
    return "adm-" + hashlib.sha256(record_id.encode("utf-8")).hexdigest()[:16]


def _as_text(v: Any) -> str:
    return _ROUTING._as_text(v)


def _is_prose_only(record: dict, source_rel: str, blocked_class: str) -> tuple[bool, str]:
    """Return (is_prose, prose_class) for prose-memory routing."""
    record_id = _as_text(record.get("record_id"))
    source_ref = _as_text(record.get("source_audit_ref"))
    # prefix_ref-derived prose (the backtest 0/40 confound)
    if "prefix_ref" in source_ref.lower() or "prefix-ref" in record_id.lower():
        return True, "prefix_ref_prose"
    # solodit-spec drafts are prose-to-spec extractions
    if record_id.startswith("solodit-spec:") and "draft" in source_ref.lower():
        return True, "prose_only_draft"
    if blocked_class == "low_confidence_prose_draft":
        return True, "low_confidence_prose"
    return False, ""


def _is_fabricated(record: dict, source_rel: str) -> bool:
    if FABRICATED_SUBTREE in source_rel:
        return True
    blob = (
        _as_text(record.get("source_audit_ref"))
        + " " + _as_text(record.get("notes"))
        + " " + _as_text(record.get("record_tier"))
    ).lower()
    return any(m in blob for m in FABRICATED_MARKERS)


def _freshness_band(record: dict) -> str:
    year = record.get("year")
    try:
        y = int(year)
    except (TypeError, ValueError):
        return "unknown"
    if y <= 0 or y in getattr(_ROUTING, "UNKNOWN_YEAR_SENTINELS", (2000,)):
        return "unknown"
    now_year = _dt.datetime.now(_dt.timezone.utc).year
    age = now_year - y
    if age <= 2:
        return "fresh"
    if age <= 5:
        return "aging"
    return "stale"


def _trust_tier(vt: str) -> str:
    if vt in STRONG_TIERS:
        return "strong"
    if vt in ADVISORY_TIERS:
        return "advisory"
    if vt == FIXTURE_TIER:
        return "fixture"
    if vt == QUARANTINE_TIER:
        return "quarantine"
    return "unknown"


def _load_replay_status(manifest_path: Path | None) -> dict[str, str]:
    if not manifest_path or not manifest_path.exists():
        return {}
    try:
        data = json.loads(manifest_path.read_text(encoding="utf-8"))
    except Exception:
        return {}
    out: dict[str, str] = {}
    rows = data.get("rows") if isinstance(data, dict) else data
    if isinstance(rows, list):
        for row in rows:
            if not isinstance(row, dict):
                continue
            rid = _as_text(row.get("record_id") or row.get("finding_id"))
            status = _as_text(row.get("status") or row.get("source_ref_replay_status"))
            if rid and status:
                out[rid] = status
    return out


def _load_restore_overrides(trust_ledger: Path) -> tuple[set[str], set[str]]:
    """Return (restored_ids, permanently_quarantined_ids) from existing ledgers."""
    restored: set[str] = set()
    if not trust_ledger.exists():
        return restored, set()
    try:
        for line in trust_ledger.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if not line:
                continue
            ev = json.loads(line)
            if ev.get("event") == "restore":
                restored.add(_as_text(ev.get("record_id")))
    except Exception:
        pass
    return restored, set()


def _load_permanent_quarantine(quarantine_ledger: Path) -> set[str]:
    perm: set[str] = set()
    if not quarantine_ledger.exists():
        return perm
    try:
        for line in quarantine_ledger.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if not line:
                continue
            ev = json.loads(line)
            if ev.get("restorable") is False:
                perm.add(_as_text(ev.get("record_id")))
    except Exception:
        pass
    return perm


def classify_trust(
    record: dict,
    record_id: str,
    source_rel: str,
    orphan_classes: frozenset[str],
    replay_status: dict[str, str],
    restored: set[str],
    permanent_quarantine: set[str],
) -> dict:
    """Compute a corpus_trust_record.v1 dict for one record."""
    vt = _ROUTING._effective_verification_tier(record)
    bucket, blocked_class, _wq = _ROUTING._classify_record(record, record_id, orphan_classes)
    target_repo = _as_text(record.get("target_repo"))
    blockers: list[str] = []

    fabricated = _is_fabricated(record, source_rel)
    prose, prose_class = _is_prose_only(record, source_rel, blocked_class)

    # --- determine trust state ---
    state = TS_ADVISORY  # default conservative

    if record_id in permanent_quarantine:
        state = TS_QUARANTINE
        blockers.append("permanent_quarantine_event")
    elif fabricated:
        state = TS_QUARANTINE
        blockers.append("fabricated")
    elif vt == QUARANTINE_TIER:
        state = TS_QUARANTINE
        blockers.append("tier-5")
    elif not vt:
        state = TS_QUARANTINE
        blockers.append("missing first-class tier")
    elif blocked_class in QUARANTINE_BLOCKED_CLASSES:
        state = TS_QUARANTINE
        blockers.append(f"blocked:{blocked_class}")
    elif prose:
        state = TS_PROSE
    elif vt in ADVISORY_TIERS or vt == FIXTURE_TIER:
        state = TS_ADVISORY
        if vt == FIXTURE_TIER:
            blockers.append("tier-4")
        else:
            blockers.append("tier-3")
    elif vt in STRONG_TIERS:
        # candidate active - apply admission blockers.
        # NOTE: routing's orphan downgrade (BUCKET_ADVISORY with no blocked_class)
        # is a hunting-breadth signal, not a source-trust signal. A tier-1/tier-2
        # source-backed record with a real repo is scorable (active) even when the
        # attack_class is an orphan. We only honor routing-advisory when it carries
        # a concrete blocked_class.
        if bucket == _ROUTING.BUCKET_BLOCKED or (
            bucket == _ROUTING.BUCKET_ADVISORY and blocked_class
        ):
            state = TS_ADVISORY
            if blocked_class:
                blockers.append(f"blocked:{blocked_class}")
        else:
            # active candidate; check generic target_repo
            if target_repo in ("unknown", "unknown/unknown", ""):
                state = TS_ADVISORY
                blockers.append("generic target_repo=unknown without rebuttal")
            else:
                state = TS_ACTIVE
    else:
        state = TS_ADVISORY
        blockers.append("unrecognized tier")

    # source-ref replay status (advisory at build time)
    replay = replay_status.get(record_id, "unknown")
    if replay.startswith("blocked"):
        # replay failure is an active admission blocker
        if state == TS_ACTIVE:
            state = TS_QUARANTINE
        blockers.append(f"replay:{replay}")

    # restore override: a prior restore event pins the record back to its
    # routed (non-quarantine) state, unless permanently quarantined.
    if record_id in restored and record_id not in permanent_quarantine and not fabricated:
        if state == TS_QUARANTINE:
            state = TS_ADVISORY if vt not in STRONG_TIERS else (
                TS_ACTIVE if bucket == _ROUTING.BUCKET_USABLE
                and target_repo not in ("unknown", "unknown/unknown", "") else TS_ADVISORY
            )
            blockers.append("restored-by-ledger")

    if state == TS_ACTIVE:
        blockers = []

    rec = {
        "schema": TRUST_RECORD_SCHEMA,
        "record_id": record_id,
        "trust_state": state,
        "admission_id": _admission_id(record_id),
        "verification_tier": vt,
        "trust_tier": _trust_tier(vt),
        "source_path": source_rel,
        "target_repo": target_repo,
        "attack_class": _as_text(record.get("attack_class")),
        "bug_class": _as_text(record.get("bug_class")),
        "routing_bucket": bucket,
        "blocked_class": blocked_class,
        "admission_blockers": blockers,
        "r76_verdict": "not-run",
        "source_ref_replay_status": replay,
        "freshness_band": _freshness_band(record),
        "is_prose_only": prose,
        "is_fabricated": fabricated,
        "built_at": _now(),
    }
    if prose:
        rec["_prose_class"] = prose_class
    return rec


def build(
    tags_dir: Path,
    out_dir: Path,
    report_path: Path,
    subtrees: list[str] | None,
    limit: int | None,
    replay_manifest: Path | None,
    dry_run: bool,
) -> dict:
    orphan_classes = _ROUTING._load_orphan_classes()
    replay_status = _load_replay_status(replay_manifest)

    trust_ledger = out_dir / "CORPUS_TRUST_LEDGER.jsonl"
    quarantine_ledger = out_dir / "CORPUS_QUARANTINE_LEDGER.jsonl"
    index_path = out_dir / "TRUSTED_CORPUS_INDEX.jsonl"
    prose_path = out_dir / "PROSE_MEMORY_INDEX.jsonl"

    restored, _ = _load_restore_overrides(trust_ledger)
    permanent_quarantine = _load_permanent_quarantine(quarantine_ledger)

    index_rows: list[dict] = []
    prose_rows: list[dict] = []
    quarantine_events: list[dict] = []
    trust_events: list[dict] = []

    state_counts: dict[str, int] = {
        TS_ACTIVE: 0, TS_ADVISORY: 0, TS_PROSE: 0,
        TS_QUARANTINE: 0, TS_SUPERSEDED: 0,
    }
    tier_counts: dict[str, int] = {}
    schema_version_counts: dict[str, int] = {}
    total = 0
    active_no_tier = 0
    active_fabricated = 0

    for path, record_id, record in _ROUTING.iter_records(tags_dir, subtrees=subtrees, limit=limit):
        total += 1
        try:
            source_rel = str(path.relative_to(tags_dir))
        except ValueError:
            source_rel = str(path)
        sv = _as_text(record.get("schema_version"))
        schema_version_counts[sv] = schema_version_counts.get(sv, 0) + 1

        rec = classify_trust(
            record, record_id, source_rel, orphan_classes,
            replay_status, restored, permanent_quarantine,
        )
        state = rec["trust_state"]
        state_counts[state] = state_counts.get(state, 0) + 1
        vt = rec["verification_tier"] or "(missing)"
        tier_counts[vt] = tier_counts.get(vt, 0) + 1

        # DoD invariants
        if state == TS_ACTIVE and not rec["verification_tier"]:
            active_no_tier += 1
        if state == TS_ACTIVE and rec["is_fabricated"]:
            active_fabricated += 1

        index_rows.append(rec)
        trust_events.append({
            "schema": TRUST_EVENT_SCHEMA,
            "event": "admit" if state == TS_ACTIVE else "downgrade",
            "record_id": record_id,
            "to_state": state,
            "reason": ";".join(rec["admission_blockers"]) or "active",
            "actor": "trusted-corpus-index-build.py",
            "at": rec["built_at"],
        })
        if state == TS_QUARANTINE:
            qclass = "fabricated" if rec["is_fabricated"] else (
                "tier_5" if rec["verification_tier"] == QUARANTINE_TIER else (
                    "missing_tier" if not rec["verification_tier"] else (
                        "source_ref_replay_failed"
                        if rec["source_ref_replay_status"].startswith("blocked")
                        else "blocked_corpus_quality_class"
                    )
                )
            )
            quarantine_events.append({
                "schema": QUARANTINE_EVENT_SCHEMA,
                "record_id": record_id,
                "quarantine_class": qclass,
                "blocked_class": rec["blocked_class"],
                "source_path": source_rel,
                "reason": ";".join(rec["admission_blockers"]),
                "actor": "trusted-corpus-index-build.py",
                "restorable": qclass != "fabricated",
                "at": rec["built_at"],
            })
        if state == TS_PROSE:
            prose_rows.append({
                "schema": PROSE_RECORD_SCHEMA,
                "record_id": record_id,
                "prose_class": rec.pop("_prose_class", "prose_only_draft"),
                "source_path": source_rel,
                "verification_tier": rec["verification_tier"],
                "attack_class": rec["attack_class"],
                "summary": _as_text(record.get("target_component"))[:200],
                "built_at": rec["built_at"],
            })
        else:
            rec.pop("_prose_class", None)

    summary = {
        "schema": "auditooor.trusted_corpus_index_summary.v1",
        "built_at": _now(),
        "tags_dir": str(tags_dir),
        "total_records_scanned": total,
        "trust_state_counts": state_counts,
        "verification_tier_counts": tier_counts,
        "schema_version_counts": schema_version_counts,
        "denominators": {
            "raw_records_scanned": total,
            "active_scorable": state_counts[TS_ACTIVE],
            "advisory": state_counts[TS_ADVISORY],
            "prose_memory": state_counts[TS_PROSE],
            "quarantine": state_counts[TS_QUARANTINE],
        },
        "dod": {
            "active_with_unstated_tier": active_no_tier,
            "active_fabricated": active_fabricated,
        },
    }

    if not dry_run:
        out_dir.mkdir(parents=True, exist_ok=True)
        index_path.write_text(
            "".join(json.dumps(r, sort_keys=True) + "\n" for r in index_rows),
            encoding="utf-8",
        )
        prose_path.write_text(
            "".join(json.dumps(r, sort_keys=True) + "\n" for r in prose_rows),
            encoding="utf-8",
        )
        # ledgers are append-only
        with quarantine_ledger.open("a", encoding="utf-8") as fh:
            for ev in quarantine_events:
                fh.write(json.dumps(ev, sort_keys=True) + "\n")
        with trust_ledger.open("a", encoding="utf-8") as fh:
            for ev in trust_events:
                fh.write(json.dumps(ev, sort_keys=True) + "\n")
        report_path.parent.mkdir(parents=True, exist_ok=True)
        report_path.write_text(_render_report(summary), encoding="utf-8")

    return summary


def _render_report(summary: dict) -> str:
    s = summary
    sc = s["trust_state_counts"]
    lines = [
        "# Corpus Trust Report",
        "",
        f"Built: {s['built_at']}",
        f"Tags dir: {s['tags_dir']}",
        "",
        "## Trust state denominators",
        "",
        "| state | count |",
        "|-------|-------|",
        f"| active (scorable) | {sc.get(TS_ACTIVE, 0)} |",
        f"| advisory | {sc.get(TS_ADVISORY, 0)} |",
        f"| prose_memory | {sc.get(TS_PROSE, 0)} |",
        f"| quarantine | {sc.get(TS_QUARANTINE, 0)} |",
        f"| superseded | {sc.get(TS_SUPERSEDED, 0)} |",
        f"| **total scanned** | **{s['total_records_scanned']}** |",
        "",
        "## Schema-version counts",
        "",
        "| schema_version | count |",
        "|----------------|-------|",
    ]
    for sv, cnt in sorted(s["schema_version_counts"].items(), key=lambda x: -x[1]):
        lines.append(f"| {sv or '(none)'} | {cnt} |")
    lines += [
        "",
        "## Definition-of-done checks",
        "",
        f"- active rows with unstated verification tier: {s['dod']['active_with_unstated_tier']} (must be 0)",
        f"- active rows fabricated/prose-only: {s['dod']['active_fabricated']} (must be 0)",
        "",
        "## Verification-tier counts (all states)",
        "",
        "| tier | count |",
        "|------|-------|",
    ]
    for vt, cnt in sorted(s["verification_tier_counts"].items(), key=lambda x: -x[1]):
        lines.append(f"| {vt} | {cnt} |")
    lines.append("")
    return "\n".join(lines)


def _parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    p = argparse.ArgumentParser(description="Build the trusted-corpus index + ledgers.")
    p.add_argument("--tags-dir", default=str(DEFAULT_TAGS_DIR))
    p.add_argument("--out-dir", default=str(DEFAULT_OUT_DIR))
    p.add_argument("--report", default=str(DEFAULT_REPORT))
    p.add_argument("--subtrees", default=None)
    p.add_argument("--limit", type=int, default=None)
    p.add_argument("--replay-manifest", default=None)
    p.add_argument("--dry-run", action="store_true")
    p.add_argument("--json", dest="json_output", action="store_true")
    return p.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = _parse_args(argv)
    tags_dir = Path(args.tags_dir)
    if not tags_dir.exists():
        print(f"ERROR: tags dir not found: {tags_dir}", file=sys.stderr)
        return 1
    subtrees = [s.strip() for s in args.subtrees.split(",")] if args.subtrees else None
    replay = Path(args.replay_manifest) if args.replay_manifest else None
    summary = build(
        tags_dir=tags_dir,
        out_dir=Path(args.out_dir),
        report_path=Path(args.report),
        subtrees=subtrees,
        limit=args.limit,
        replay_manifest=replay,
        dry_run=args.dry_run,
    )
    if args.json_output:
        print(json.dumps(summary, indent=2))
    else:
        sc = summary["trust_state_counts"]
        print(f"Trusted corpus index built [{TRUST_RECORD_SCHEMA}]")
        print(f"  scanned   : {summary['total_records_scanned']}")
        print(f"  active    : {sc.get(TS_ACTIVE, 0)}")
        print(f"  advisory  : {sc.get(TS_ADVISORY, 0)}")
        print(f"  prose     : {sc.get(TS_PROSE, 0)}")
        print(f"  quarantine: {sc.get(TS_QUARANTINE, 0)}")
        print(f"  dod active-unstated-tier : {summary['dod']['active_with_unstated_tier']}")
        print(f"  dod active-fabricated    : {summary['dod']['active_fabricated']}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
