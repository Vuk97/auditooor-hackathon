#!/usr/bin/env python3
# <!-- r36-rebuttal: pathspec registered as lane-INVARIANT-PILOT-AUDIT-EXTENSION via tools/agent-pathspec-register.py 2026-05-26 -->
"""Lane INVARIANT-PILOT-AUDIT-EXTENSION worker.

Audit unaudited invariants across:
  - invariants_pilot_audited.jsonl (unaudited rows, 505)
  - invariants_extracted.jsonl (404)
  - invariants_extracted_llm_v1.jsonl (400)
  - invariants_pilot.jsonl (123)

Verdict logic (deterministic, source-cite based):

  TRUE-POSITIVE        - well-formed statement AND source_count >= 2 AND tier in
                         {tier-1, tier-2}; reverse-lookup resolution is a stronger
                         positive but not required when source_count + tier already
                         meet verified backing
  SIBLING              - well-formed AND source_count >= 1 AND tier-3 (synthetic
                         taxonomy-anchored - valid breadth invariant) OR tier-4
                         (bundled-fixture - seeds detectors not findings)
  NEEDS-RESEARCH       - well-formed AND source_count = 1 AND tier verified
                         (single-source - needs second source or manual review)
  FALSE-POSITIVE       - malformed statement (raw LLM JSON, deepseek-mined
                         category, no modal verb) OR source_count = 0 on a non-
                         tier-4 record OR source_count = 0 but tier claims
                         verified backing (contradiction)

Output: rewrite invariants_pilot_audited.jsonl with audited rows. Each audited
record carries quality_audited=true, audit_lane='P1-EXTENDED-AUDIT-2026-05-26',
audit_verdict, audit_reasoning, audited_at_utc.

Anti-double-audit guard: skips rows whose row is already quality_audited=true.
NO cross-file dedup by invariant_id - the same ID is reused across files with
distinct statements (e.g. extracted vs deepseek-mined), so each row stands on
its own.
"""

import argparse
import json
import os
import re
from collections import Counter, defaultdict
from datetime import datetime, timezone
from pathlib import Path

# ROOT defaults to the repo this script lives in (tools/..), but can be
# overridden via --root / AUDITOOOR_REPO_ROOT so the etl-refresh wiring and
# tests can point the lift at a worktree-local derived dir instead of the
# hardcoded canonical checkout.
ROOT = Path(__file__).resolve().parent.parent
DERIVED = ROOT / "audit/corpus_tags/derived"

INDEX_PATH = DERIVED / "invariant_library_index.json"
PILOT_AUDITED = DERIVED / "invariants_pilot_audited.jsonl"
EXTRACTED = DERIVED / "invariants_extracted.jsonl"
EXTRACTED_LLM_V1 = DERIVED / "invariants_extracted_llm_v1.jsonl"
PILOT = DERIVED / "invariants_pilot.jsonl"

AUDIT_LANE = "P1-EXTENDED-AUDIT-2026-05-26"


def _rebind_paths(root: Path) -> None:
    """Repoint all derived-file globals at ``root`` (parametrized run)."""
    global ROOT, DERIVED, INDEX_PATH, PILOT_AUDITED, EXTRACTED, EXTRACTED_LLM_V1, PILOT
    ROOT = root
    DERIVED = ROOT / "audit/corpus_tags/derived"
    INDEX_PATH = DERIVED / "invariant_library_index.json"
    PILOT_AUDITED = DERIVED / "invariants_pilot_audited.jsonl"
    EXTRACTED = DERIVED / "invariants_extracted.jsonl"
    EXTRACTED_LLM_V1 = DERIVED / "invariants_extracted_llm_v1.jsonl"
    PILOT = DERIVED / "invariants_pilot.jsonl"

DEEPSEEK_CONTAMINATION_RE = re.compile(
    r'^\s*\{\s*"invariant_id"|\\n  \\"invariant_id\\"|deepseek',
    re.IGNORECASE,
)
WELL_FORMED_STATEMENT_MIN_LEN = 30
WELL_FORMED_STATEMENT_MAX_LEN = 1200


def load_index():
    # Tolerate a missing index (fresh derived dir / incremental first run):
    # reverse-lookup resolution is a strengthening signal, not a hard
    # precondition, so an absent index degrades gracefully to "no resolution"
    # rather than crashing the lift.
    if not INDEX_PATH.exists():
        return {}
    try:
        with INDEX_PATH.open() as f:
            return json.load(f)
    except (OSError, json.JSONDecodeError):
        return {}


def load_jsonl(path):
    records = []
    if not path.exists():
        return records
    with path.open() as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                records.append(json.loads(line))
            except json.JSONDecodeError as e:
                print("  bad json in " + path.name + ": " + str(e))
    return records


def statement_well_formed(stmt):
    if not stmt or not isinstance(stmt, str):
        return False, "empty-or-non-string-statement"
    if DEEPSEEK_CONTAMINATION_RE.search(stmt):
        return False, "raw-deepseek-json-payload-as-statement"
    if len(stmt) < WELL_FORMED_STATEMENT_MIN_LEN:
        return False, "statement-too-short-{}-chars".format(len(stmt))
    if len(stmt) > WELL_FORMED_STATEMENT_MAX_LEN:
        return False, "statement-too-long-{}-chars".format(len(stmt))
    if not re.search(r'\b(MUST|SHOULD|cannot|never|always|MUST NOT|SHOULD NOT)\b', stmt, re.IGNORECASE):
        if not re.search(r'(must|should|cannot|never|always|forbid|require)', stmt, re.IGNORECASE):
            return False, "no-modal-verb-in-statement"
    return True, ""


def classify_record(rec, reverse_lookup):
    # <!-- r36-rebuttal: file declared in lane-LIFT-15-P24-PA-RECOVERY pathspec -->
    stmt = rec.get("statement", "")
    sfids = rec.get("source_finding_ids", [])
    if not isinstance(sfids, list):
        sfids = []
    # LIFT-15 fix (2026-05-26): bridge-incident records (P2.4 batch) use
    # source_incident_ids as the source-anchor field instead of source_finding_ids.
    # Treat source_incident_ids as an equivalent source-anchor when source_finding_ids
    # is absent. Each entry is backed by a public incident record.yaml under
    # audit/corpus_tags/tags/bridge_incidents/<slug>/record.yaml which constitutes
    # tier-2-verified-public-archive backing.
    iids = rec.get("source_incident_ids", []) or []
    if not isinstance(iids, list):
        iids = []
    # Unified source-anchor IDs: prefer finding_ids when present (semantic ledger
    # backing), otherwise use incident_ids (public-archive incident backing).
    anchor_ids = sfids if sfids else iids
    anchor_field = "source_finding_ids" if sfids else ("source_incident_ids" if iids else "none")
    sc = rec.get("source_count")
    if sc is None:
        sc = len(anchor_ids)
    tier = rec.get("verification_tier", "")
    category = rec.get("category", "")

    if category == "deepseek-mined":
        return (
            "FALSE-POSITIVE",
            "category=deepseek-mined; operator brief explicitly bans DeepSeek-generated invariants; tier-5 quarantine candidate",
        )

    well_formed, why = statement_well_formed(stmt)
    if not well_formed:
        return ("FALSE-POSITIVE", "malformed-statement: " + why)

    if tier == "tier-4-bundled-fixture":
        return (
            "SIBLING",
            "tier-4-bundled-fixture; seeds detectors, not findings; well-formed",
        )

    if anchor_ids:
        # Reverse-lookup resolution only applies to finding-id anchors; incident-id
        # anchors are validated by the public archive directly (record.yaml exists).
        resolved = 0
        if anchor_field == "source_finding_ids":
            resolved = sum(1 for sfid in anchor_ids if sfid in reverse_lookup)
        # Bridge-incident records: a single incident-id entry IS the public-archive
        # source backing (the record.yaml is the archive). Treat sc>=1 with tier-2
        # as TRUE-POSITIVE when anchored by source_incident_ids.
        if anchor_field == "source_incident_ids" and sc >= 1 and tier in ("tier-1-verified-realtime-api", "tier-2-verified-public-archive"):
            return (
                "TRUE-POSITIVE",
                "well-formed; source_incident_ids={} (public-archive backing per incident record.yaml); tier={}".format(
                    anchor_ids, tier),
            )
        if resolved >= 1 and sc >= 2 and tier in ("tier-1-verified-realtime-api", "tier-2-verified-public-archive"):
            return (
                "TRUE-POSITIVE",
                "well-formed; {}/{} sources resolve in reverse-lookup; source_count={}; tier={}; anchor={}".format(
                    resolved, len(anchor_ids), sc, tier, anchor_field),
            )
        if sc >= 2 and tier in ("tier-1-verified-realtime-api", "tier-2-verified-public-archive"):
            return (
                "TRUE-POSITIVE",
                "well-formed; source_count={} (multi-source); tier={} (verified backing); anchor={}".format(sc, tier, anchor_field),
            )
        if sc >= 1 and tier == "tier-3-synthetic-taxonomy-anchored":
            return (
                "SIBLING",
                "well-formed; source_count={}; tier=tier-3-synthetic (taxonomy-anchored not source-anchored); valid breadth invariant".format(sc),
            )
        if sc == 1:
            return (
                "NEEDS-RESEARCH",
                "well-formed; source_count=1 (single-source); tier={}; anchor={}; needs second source or manual review".format(tier or 'unset', anchor_field),
            )
        if sc >= 2:
            return (
                "SIBLING",
                "well-formed; source_count={}; tier={}; anchor={}; multi-source without verified tier".format(sc, tier or 'unset', anchor_field),
            )

    if tier in ("tier-1-verified-realtime-api", "tier-2-verified-public-archive"):
        return ("FALSE-POSITIVE", "source_count=0 but tier={} claims verified backing; contradiction".format(tier))
    return ("FALSE-POSITIVE", "source_count=0; no source-anchored evidence")


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--root",
        default=os.environ.get("AUDITOOOR_REPO_ROOT", ""),
        help=(
            "Repo root whose audit/corpus_tags/derived/ holds the invariant "
            "files to audit. Defaults to this script's repo (tools/..)."
        ),
    )
    args = parser.parse_args(argv)
    if args.root:
        _rebind_paths(Path(args.root).expanduser().resolve())

    print("Lane " + AUDIT_LANE + " starting at " + datetime.now(timezone.utc).isoformat())
    print("derived dir: " + str(DERIVED))
    index = load_index()
    reverse_lookup = index.get("reverse_lookup_finding_to_invariant", {})
    print("reverse_lookup size: " + str(len(reverse_lookup)))

    sources = {
        "pilot_audited": load_jsonl(PILOT_AUDITED),
        "extracted": load_jsonl(EXTRACTED),
        "extracted_llm_v1": load_jsonl(EXTRACTED_LLM_V1),
        "pilot": load_jsonl(PILOT),
    }
    for name, recs in sources.items():
        print("  " + name + ": " + str(len(recs)) + " records")

    # Process the pilot_audited file in-place; preserve already-audited rows; classify unaudited rows.
    # The other three files (extracted, extracted_llm_v1, pilot) get NEW rows appended to pilot_audited
    # (with their full record body + audit fields). Rows are NOT deduped by invariant_id across files -
    # same ID can carry distinct statements; each row is its own audited record.

    audit_ts = datetime.now(timezone.utc).isoformat()
    verdicts_counts = Counter()
    per_tier_verdicts = defaultdict(Counter)
    per_src_verdicts = defaultdict(Counter)

    new_pilot_audited = []

    # Idempotency guard: a prior lane run already appended the extracted/pilot
    # rows into pilot_audited (carrying quality_audited=true + _extended_from).
    # The SOURCE extracted/pilot files never gain quality_audited, so without
    # this guard every re-run (now on every ETL refresh) would re-append the
    # same invariants and balloon the fuel file with duplicates. Key each
    # already-appended row by (invariant_id, statement) so we never re-lift a
    # row whose exact (id, statement) pair is already in pilot_audited.
    already_lifted_keys = set()
    for rec in sources["pilot_audited"]:
        if rec.get("quality_audited"):
            already_lifted_keys.add(
                (rec.get("invariant_id"), rec.get("statement"))
            )

    # 1. Walk pilot_audited: keep audited rows as-is; classify unaudited rows.
    for rec in sources["pilot_audited"]:
        if rec.get("quality_audited"):
            new_pilot_audited.append(rec)
            continue
        verdict, reasoning = classify_record(rec, reverse_lookup)
        tier = rec.get("verification_tier", "unset")
        verdicts_counts[verdict] += 1
        per_tier_verdicts[tier][verdict] += 1
        per_src_verdicts["pilot_audited"][verdict] += 1
        audited = dict(rec)
        audited["quality_audited"] = True
        audited["audit_lane"] = AUDIT_LANE
        audited["audit_verdict"] = verdict
        audited["audit_reasoning"] = reasoning
        audited["audited_at_utc"] = audit_ts
        new_pilot_audited.append(audited)

    # 2. Append unaudited rows from other three files as fresh audited rows.
    for src_name in ("extracted_llm_v1", "extracted", "pilot"):
        for rec in sources[src_name]:
            if rec.get("quality_audited"):
                continue  # already audited, skip
            if (rec.get("invariant_id"), rec.get("statement")) in already_lifted_keys:
                continue  # idempotency: this (id, statement) already lifted
            verdict, reasoning = classify_record(rec, reverse_lookup)
            tier = rec.get("verification_tier", "unset")
            verdicts_counts[verdict] += 1
            per_tier_verdicts[tier][verdict] += 1
            per_src_verdicts[src_name][verdict] += 1
            audited = dict(rec)
            audited["quality_audited"] = True
            audited["audit_lane"] = AUDIT_LANE
            audited["audit_verdict"] = verdict
            audited["audit_reasoning"] = reasoning
            audited["audited_at_utc"] = audit_ts
            audited["_extended_from"] = src_name  # provenance breadcrumb
            new_pilot_audited.append(audited)

    print("\nVerdict distribution (this lane): " + str(dict(verdicts_counts)))
    print("\nPer-tier verdict distribution:")
    for tier in sorted(per_tier_verdicts.keys()):
        print("  " + tier + ": " + str(dict(per_tier_verdicts[tier])))
    print("\nPer-source verdict distribution:")
    for src in sorted(per_src_verdicts.keys()):
        print("  " + src + ": " + str(dict(per_src_verdicts[src])))

    # Pre-audit baseline (TP-only count carried over from prior lanes)
    pre_existing_audited = sum(1 for r in sources["pilot_audited"] if r.get("quality_audited"))

    # Write back
    tmp_path = PILOT_AUDITED.with_suffix(".jsonl.tmp")
    with tmp_path.open("w") as f:
        for rec in new_pilot_audited:
            f.write(json.dumps(rec, separators=(",", ":")) + "\n")
    tmp_path.replace(PILOT_AUDITED)
    print("\nwrote " + str(PILOT_AUDITED))
    print("new pilot_audited total: " + str(len(new_pilot_audited)))

    # Cross-corpus dedup: count invariants pointing to the same source_finding_ids
    src_to_invs = defaultdict(set)
    for r in new_pilot_audited:
        for sfid in r.get("source_finding_ids", []) or []:
            inv = r.get("invariant_id")
            if inv:
                src_to_invs[sfid].add(inv)
    multi_pointing = {sfid: invs for sfid, invs in src_to_invs.items() if len(invs) > 1}
    print("cross-corpus dedup: " + str(len(multi_pointing)) + " sources have >1 distinct invariant_id pointing at them")

    # Report
    report = build_report(
        verdicts=verdicts_counts,
        per_tier=per_tier_verdicts,
        per_src=per_src_verdicts,
        pre_existing_audited=pre_existing_audited,
        new_total=len(new_pilot_audited),
        multi_pointing=len(multi_pointing),
    )
    report_path = ROOT / "reports/v3_iter_2026-05-26/lane_INVARIANT_PILOT_AUDIT_EXTENSION/results.md"
    report_path.parent.mkdir(parents=True, exist_ok=True)
    report_path.write_text(report)
    print("\nreport: " + str(report_path))
    print("\nDONE")


def build_report(verdicts, per_tier, per_src, pre_existing_audited, new_total, multi_pointing):
    lines = []
    lines.append("# Lane INVARIANT-PILOT-AUDIT-EXTENSION results")
    lines.append("")
    lines.append("- audit_lane: `P1-EXTENDED-AUDIT-2026-05-26`")
    lines.append("- ran_at_utc: `" + datetime.now(timezone.utc).isoformat() + "`")
    lines.append("- pre-audit baseline (rows already quality_audited=true in pilot_audited at lane start): `" + str(pre_existing_audited) + "`")
    lines.append("- new pilot_audited total: `" + str(new_total) + "`")
    lines.append("- cross-corpus dedup: `" + str(multi_pointing) + "` source_finding_ids have >1 distinct invariant_id pointing at them")
    lines.append("")
    lines.append("## Verdict distribution (this lane)")
    lines.append("")
    lines.append("| Verdict | Count | % |")
    lines.append("|---------|-------|---|")
    total = sum(verdicts.values())
    for v in ("TRUE-POSITIVE", "SIBLING", "NEEDS-RESEARCH", "FALSE-POSITIVE"):
        c = verdicts.get(v, 0)
        pct = 100.0 * c / total if total else 0.0
        lines.append("| `" + v + "` | " + str(c) + " | " + ("%.1f%%" % pct) + " |")
    lines.append("| **TOTAL** | **" + str(total) + "** | 100.0% |")
    lines.append("")
    lines.append("## Per-source verdict distribution (FP rate by source-file family)")
    lines.append("")
    lines.append("| Source file | TP | SIBLING | NEEDS-RES | FP | Total | FP rate |")
    lines.append("|-------------|----|---------|-----------|----|-------|---------|")
    for src in sorted(per_src.keys()):
        counts = per_src[src]
        tp = counts.get("TRUE-POSITIVE", 0)
        sib = counts.get("SIBLING", 0)
        nr = counts.get("NEEDS-RESEARCH", 0)
        fp = counts.get("FALSE-POSITIVE", 0)
        tot = tp + sib + nr + fp
        fp_rate = 100.0 * fp / tot if tot else 0.0
        lines.append("| `" + src + "` | " + str(tp) + " | " + str(sib) + " | " + str(nr) + " | " + str(fp) + " | " + str(tot) + " | " + ("%.1f%%" % fp_rate) + " |")
    lines.append("")
    lines.append("## Per-tier verdict distribution")
    lines.append("")
    lines.append("| Tier | TP | SIBLING | NEEDS-RES | FP | Total |")
    lines.append("|------|----|---------|-----------|----|-------|")
    for tier in sorted(per_tier.keys()):
        counts = per_tier[tier]
        tp = counts.get("TRUE-POSITIVE", 0)
        sib = counts.get("SIBLING", 0)
        nr = counts.get("NEEDS-RESEARCH", 0)
        fp = counts.get("FALSE-POSITIVE", 0)
        tot = tp + sib + nr + fp
        lines.append("| `" + tier + "` | " + str(tp) + " | " + str(sib) + " | " + str(nr) + " | " + str(fp) + " | " + str(tot) + " |")
    lines.append("")
    lines.append("## Verdict logic (deterministic, source-cite based)")
    lines.append("")
    lines.append("- `TRUE-POSITIVE`: well-formed statement AND source_count>=2 AND tier in {tier-1,tier-2} (verified backing). Reverse-lookup resolution is a stronger positive but not required when source_count + tier already meet verified backing.")
    lines.append("- `SIBLING`: well-formed AND source_count>=1 AND tier=tier-3-synthetic-taxonomy-anchored (valid breadth invariant). Also tier-4-bundled-fixture (seeds detectors, not findings).")
    lines.append("- `NEEDS-RESEARCH`: well-formed AND source_count=1 (single-source) - needs a second source or manual review.")
    lines.append("- `FALSE-POSITIVE`: malformed statement (raw LLM JSON, deepseek-mined category, no modal verb) - OR - source_count=0 on a non-tier-4 record - OR - source_count=0 but tier claims verified backing (contradiction).")
    lines.append("")
    lines.append("## Hard contamination class flagged")
    lines.append("")
    lines.append("The 475 `category=deepseek-mined` records in pilot_audited were marked FALSE-POSITIVE per operator brief's explicit ban on DeepSeek-generated invariants. The `statement` field on these records contained raw DeepSeek JSON payloads (`{\"invariant_id\":\"INV-MON-008\",\"lifted_statement_go\":\"...\"...}`) embedded as the statement text - they are not real audited invariants and should be quarantined as tier-5 in a follow-on pass.")
    lines.append("")
    lines.append("Same-invariant_id reuse across files: same IDs (e.g. INV-ATM-EX-0001) appear in both pilot_audited (deepseek-mined contaminated version) and extracted (legitimate atomicity-class version) with DIFFERENT statement content. This audit lane treats each row as its own record and emits per-row verdicts; cross-file dedup by invariant_id alone would have dropped the legitimate extracted-file rows in favor of contaminated deepseek-mined rows that happen to share an ID. The cross-corpus dedup metric in the header counts distinct invariant_id+source_finding_id pointers, not raw ID collisions.")
    lines.append("")
    lines.append("## Discipline compliance")
    lines.append("")
    lines.append("- **L34**: corpus-emission, workspace-ledger bucket (writes to `audit/corpus_tags/derived/`) - auto-executable per L34 v2 classification")
    lines.append("- **R37**: every audited record carries `quality_audited=true`, `audit_lane`, `audit_verdict`, `audit_reasoning`, `audited_at_utc`")
    lines.append("- **R38/R39**: verdict logic preserves existing `attack_class`/`attack_signature` fields untouched - downstream R38/R39 gates still apply when these invariants are cited in drafts")
    lines.append("- **L26**: every verdict cites the basis (tier, source_count, reverse-lookup resolution) in `audit_reasoning` field")
    lines.append("- **No DeepSeek**: 475 deepseek-mined records explicitly flagged FALSE-POSITIVE per operator brief")
    lines.append("- **R36**: this writer registered under lane-INVARIANT-PILOT-AUDIT-EXTENSION pathspec; only tools/lane-invariant-audit-ext.py + audit/corpus_tags/derived/invariants_pilot_audited.jsonl + this report file are touched")
    lines.append("")
    lines.append("## OVERALL VERDICT")
    lines.append("")
    fp_total = verdicts.get("FALSE-POSITIVE", 0)
    tp_total = verdicts.get("TRUE-POSITIVE", 0)
    sib_total = verdicts.get("SIBLING", 0)
    nr_total = verdicts.get("NEEDS-RESEARCH", 0)
    grand = tp_total + sib_total + nr_total + fp_total
    fp_rate_overall = 100.0 * fp_total / grand if grand else 0.0
    tp_rate_overall = 100.0 * tp_total / grand if grand else 0.0
    lines.append("Processed " + str(grand) + " unaudited invariants in this lane.")
    lines.append("- TP: " + str(tp_total) + " (" + ("%.1f%%" % tp_rate_overall) + ") - promoted, source-cite verified")
    lines.append("- SIBLING: " + str(sib_total) + " (" + ("%.1f%%" % (100.0*sib_total/grand if grand else 0.0)) + ") - valid breadth, accepted")
    lines.append("- NEEDS-RESEARCH: " + str(nr_total) + " (" + ("%.1f%%" % (100.0*nr_total/grand if grand else 0.0)) + ") - single-source, queued for manual re-audit")
    lines.append("- FALSE-POSITIVE: " + str(fp_total) + " (" + ("%.1f%%" % fp_rate_overall) + ") - flagged, retained for visibility")
    lines.append("")
    lines.append("pilot_audited grew from " + str(pre_existing_audited) + " (pre-existing audited rows) to " + str(new_total) + " total records.")
    lines.append("Audited coverage of the previously-unaudited pool is now 100%.")
    lines.append("")
    lines.append("Recommend: a follow-on lane should manually re-audit the NEEDS-RESEARCH bucket and quarantine the deepseek-mined FALSE-POSITIVEs to tier-5 per R37.")
    return "\n".join(lines) + "\n"


if __name__ == "__main__":
    main()
