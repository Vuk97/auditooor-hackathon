#!/usr/bin/env python3
"""recall-feedback-aggregator.py - verdict-to-recall learning feedback loop.

LANE W5-A4 (merges Section 05 M4 + Section 02 H5-5 outcome re-weighting).

The auditooor toolchain ACCUMULATES verdicts (every session appends FP/TP
verdict ledger rows, submission outcome rows, and worker verdict markdown)
but never LEARNS from them: a confirmed TP / FP / NEGATIVE outcome never
re-weights what future recall surfaces first. This tool closes that loop.

It ingests the recorded verdict ledgers, aggregates per-attack-class and
per-pattern outcome counts, and emits ``recall_weights.json`` - a weight
table reflecting historical hit-rate. A downstream relevance scorer / context
pack ranker (lane W5-E1) and the bug-class prioritizer multiply their score
by the per-class weight so classes behind confirmed TPs rank UP and classes
behind consecutive NEGATIVEs rank DOWN.

Input ledgers (all OPTIONAL - the tool aggregates whatever exists):

  1. FP verdict ledger - ``audit/fp_verdict_ledger.jsonl``
     schema ``auditooor.fp_verdict_ledger.v1``, one JSON object per line.
     Fields used: ``fp_id`` (pattern key), ``verdict`` (TP|FP|NEGATIVE).
     The newest record per ``(fp_id, workspace, file, line)`` key wins
     (mirrors fp_tp_feedback_loop.py dedupe semantics).

  2. Submission outcome ledger - ``reference/outcomes.jsonl``
     schema ``auditooor.outcomes.v*``. Fields used: ``lane``, ``severity``,
     ``outcome`` / ``outcome_class``, optional ``attack_class``.
     Outcome -> verdict mapping (see OUTCOME_TO_VERDICT).

  3. Legacy aggregate outcome JSON - ``tools/outcomes.json`` (JSON array).
     Same mapping; consumed only for rows not already in (2) keyed by
     ``submission_id`` to avoid double counting.

  4. Worker verdict markdown - ``agent_outputs/**/*verdict*.md``.
     The ``## Aggregate verdict`` section's bold lead token is parsed
     (``**NEGATIVE**``, ``**TP**``, ``**KEY FINDING**``, ``**DROP-...``).
     The lane / attack-class is derived from the file's ``**Lane:**`` line
     when present, else the filename slug.

Verdict vocabulary (canonical, after normalisation):
  * ``TP``       - confirmed real / fileable / accepted issue.
  * ``FP``       - false positive (detector / shape misfired).
  * ``NEGATIVE`` - reviewed, not an issue, not a misfire (by-design / OOS /
                   dropped / dupe). Counted as a miss for hit-rate.

Weight formula (per attack class OR per pattern key, identical math):

    hits   = TP
    misses = FP + NEGATIVE
    n      = hits + misses
    hit_rate = hits / n                       (n > 0)
    # Laplace-smoothed so a single verdict does not swing the weight hard:
    smoothed = (hits + ALPHA) / (n + 2 * ALPHA)
    # Map smoothed hit-rate in [0,1] onto a multiplier in
    # [MIN_WEIGHT, MAX_WEIGHT] centred on NEUTRAL_WEIGHT at hit_rate 0.5:
    weight = NEUTRAL_WEIGHT + (smoothed - 0.5) * 2 * (SPAN)

M14-trap discipline: a class / pattern with NO recorded verdict history
(n == 0) is OMITTED from the weights table entirely. Consumers treat a
missing key as NEUTRAL_WEIGHT (1.0). The tool NEVER invents a weight for a
class it has no evidence for.

Idempotent: re-running with the same ledgers produces byte-identical output
(sorted keys, deterministic ``generated_at`` only when ``--now`` omitted is
replaced by a stable hash-free field; the envelope carries a content hash so
callers can detect change). Stdlib only.

Output schema: ``auditooor.recall_weights.v1``.

CONSUMPTION CONTRACT (documented for W5-E1 ranked context packs and the
bug-class prioritizer - see also the module docstring of
``tools/audit/bug-class-prioritizer.py``):

  recall_weights.json::

    {
      "schema": "auditooor.recall_weights.v1",
      "content_hash": "<sha256 of canonical weights body>",
      "params": { "alpha": 1.0, "neutral_weight": 1.0,
                  "min_weight": 0.5, "max_weight": 1.5 },
      "attack_class_weights": {
        "<attack_class>": {
          "weight": 1.23, "hits": 4, "misses": 1, "n": 5,
          "hit_rate": 0.8, "smoothed_hit_rate": 0.714,
          "sources": ["fp_verdict_ledger", "outcomes_jsonl"]
        }, ...
      },
      "pattern_weights": { "<fp_id-or-pattern>": { ... same shape ... } },
      "verdict_totals": {"TP": N, "FP": N, "NEGATIVE": N}
    }

  A consumer (relevance scorer / context-pack ranker / bug-class
  prioritizer) MUST:
    - Look up the candidate's attack class in ``attack_class_weights`` and
      the candidate's detector / FP-shape in ``pattern_weights``.
    - Multiply its own relevance / priority score by the ``weight`` field.
    - Treat a MISSING key as weight 1.0 (NEUTRAL_WEIGHT) - never as 0 and
      never extrapolate. This preserves the M14-trap invariant: no verdict
      history => no opinion => neutral.
    - Optionally surface ``hits`` / ``misses`` / ``n`` in its ``ranking``
      provenance block so a worker can see WHY a class was re-weighted.
  A consumer MUST NOT write to recall_weights.json; this tool is the sole
  producer. Consumers re-read it each run (it is regenerated cheaply).
"""
from __future__ import annotations

import argparse
import datetime
import hashlib
import json
import re
import sys
from pathlib import Path

SCHEMA = "auditooor.recall_weights.v1"

# Weight model parameters.
ALPHA = 1.0            # Laplace smoothing pseudo-count.
NEUTRAL_WEIGHT = 1.0   # multiplier for hit_rate 0.5 / no strong signal.
MIN_WEIGHT = 0.5       # floor: a class behind only misses still gets recall.
MAX_WEIGHT = 1.5       # ceiling: a class behind only TPs is boosted, bounded.
SPAN = MAX_WEIGHT - NEUTRAL_WEIGHT  # symmetric span (== NEUTRAL - MIN).

# Submission-outcome -> verdict normalisation. Outcomes absent from this map
# (e.g. "pending", "in_review", "withdrawn") carry no learning signal and are
# skipped - we only learn from RESOLVED outcomes (M14-trap: no guessing).
OUTCOME_TO_VERDICT = {
    "accepted": "TP",
    "confirmed": "TP",
    "paid": "TP",
    "resolved": "TP",
    "rejected": "NEGATIVE",
    "duplicate": "NEGATIVE",
    "duplicate_of_accepted": "NEGATIVE",
    "duplicate_of_rejected": "NEGATIVE",
    "false_positive": "FP",
    "invalid": "NEGATIVE",
    "spam": "NEGATIVE",
    "out_of_scope": "NEGATIVE",
    "oos": "NEGATIVE",
}

# Verdict-md aggregate-line lead token -> verdict.
MD_TOKEN_TO_VERDICT = {
    "TP": "TP",
    "KEY FINDING": "TP",
    "CONFIRMED": "TP",
    "FP": "FP",
    "FALSE POSITIVE": "FP",
    "NEGATIVE": "NEGATIVE",
    "DROP": "NEGATIVE",
    "VERDICT HOLDS": "NEGATIVE",
}

VALID_VERDICTS = {"TP", "FP", "NEGATIVE"}


# --------------------------------------------------------------------------
# ledger ingestion
# --------------------------------------------------------------------------
def _norm_class(raw):
    """Normalise an attack-class / lane label to a stable lowercase key."""
    if not raw:
        return None
    s = str(raw).strip().lower()
    s = re.sub(r"[\s_]+", "-", s)
    s = re.sub(r"[^a-z0-9.\-]", "", s)
    return s or None


def ingest_fp_ledger(path, events):
    """FP verdict ledger -> per-pattern events (keyed by fp_id)."""
    if not path.is_file():
        return 0
    # newest record per hit key wins.
    latest = {}
    for ln in path.read_text(encoding="utf-8", errors="replace").splitlines():
        ln = ln.strip()
        if not ln or ln.startswith("#"):
            continue
        try:
            rec = json.loads(ln)
        except json.JSONDecodeError:
            continue
        fp_id = rec.get("fp_id")
        verdict = str(rec.get("verdict", "")).strip().upper()
        if not fp_id or verdict not in VALID_VERDICTS:
            continue
        key = (
            rec.get("fp_id"),
            rec.get("workspace"),
            rec.get("file"),
            rec.get("line"),
        )
        rec_at = rec.get("recorded_at", "")
        prev = latest.get(key)
        if prev is None or rec_at >= prev[0]:
            latest[key] = (rec_at, fp_id, verdict, rec.get("attack_class"))
    n = 0
    for _, fp_id, verdict, attack_class in latest.values():
        # one ledger row = one counted verdict. The pattern-scope event
        # carries count_total=True; the optional attack_class event derived
        # from the SAME row carries count_total=False so verdict_totals is
        # not double-counted when one row fans out to two scopes.
        events.append({
            "scope": "pattern",
            "key": _norm_class(fp_id),
            "verdict": verdict,
            "source": "fp_verdict_ledger",
            "count_total": True,
        })
        ac = _norm_class(attack_class)
        if ac:
            events.append({
                "scope": "attack_class",
                "key": ac,
                "verdict": verdict,
                "source": "fp_verdict_ledger",
                "count_total": False,
            })
        n += 1
    return n


def _outcome_verdict(rec):
    """Resolve a submission row's verdict, or None if not a learning signal."""
    for field in ("outcome", "outcome_class", "final_triager_outcome", "status"):
        val = rec.get(field)
        if not val:
            continue
        v = OUTCOME_TO_VERDICT.get(str(val).strip().lower())
        if v:
            return v
    return None


def _outcome_class_key(rec):
    """Best per-row attack-class key for a submission row."""
    return _norm_class(rec.get("attack_class")) or _norm_class(rec.get("lane"))


def ingest_outcomes_jsonl(path, events, seen_ids):
    if not path.is_file():
        return 0
    n = 0
    for ln in path.read_text(encoding="utf-8", errors="replace").splitlines():
        ln = ln.strip()
        if not ln or ln.startswith("#"):
            continue
        try:
            rec = json.loads(ln)
        except json.JSONDecodeError:
            continue
        sid = rec.get("submission_id") or rec.get("finding_id") or rec.get("report_id")
        if sid:
            seen_ids.add(str(sid))
        verdict = _outcome_verdict(rec)
        key = _outcome_class_key(rec)
        if not verdict or not key:
            continue
        events.append({
            "scope": "attack_class",
            "key": key,
            "verdict": verdict,
            "source": "outcomes_jsonl",
            "count_total": True,
        })
        n += 1
    return n


def ingest_outcomes_json(path, events, seen_ids):
    """Legacy tools/outcomes.json (JSON array). Skip rows already seen."""
    if not path.is_file():
        return 0
    try:
        rows = json.loads(path.read_text(encoding="utf-8", errors="replace"))
    except json.JSONDecodeError:
        return 0
    if not isinstance(rows, list):
        return 0
    n = 0
    for rec in rows:
        if not isinstance(rec, dict):
            continue
        sid = rec.get("submission_id") or rec.get("finding_id")
        if sid and str(sid) in seen_ids:
            continue
        if sid:
            seen_ids.add(str(sid))
        verdict = _outcome_verdict(rec)
        key = _outcome_class_key(rec)
        if not verdict or not key:
            continue
        events.append({
            "scope": "attack_class",
            "key": key,
            "verdict": verdict,
            "source": "outcomes_json",
            "count_total": True,
        })
        n += 1
    return n


_MD_AGG_RE = re.compile(r"##\s*Aggregate verdict", re.IGNORECASE)
_MD_LANE_RE = re.compile(r"\*\*Lane:?\*\*\s*`?([A-Za-z0-9._\-]+)", re.IGNORECASE)
_MD_BOLD_RE = re.compile(r"\*\*([A-Z][A-Z \-]+?)\*\*")


def ingest_verdict_md(root, events):
    """Worker verdict markdown under agent_outputs/**/*verdict*.md."""
    if not root.is_dir():
        return 0
    n = 0
    for md in sorted(root.rglob("*verdict*.md")):
        text = md.read_text(encoding="utf-8", errors="replace")
        # lane / attack-class label.
        lane_m = _MD_LANE_RE.search(text)
        lane = lane_m.group(1) if lane_m else md.stem
        key = _norm_class(lane)
        if not key:
            continue
        # aggregate-verdict section's lead bold token.
        agg = _MD_AGG_RE.search(text)
        verdict = None
        if agg:
            tail = text[agg.end():agg.end() + 400]
            for bm in _MD_BOLD_RE.finditer(tail):
                tok = bm.group(1).strip()
                # match longest known token prefix.
                for known, vd in MD_TOKEN_TO_VERDICT.items():
                    if tok == known or tok.startswith(known + " ") or tok.startswith(known + "-"):
                        verdict = vd
                        break
                if verdict:
                    break
        if not verdict:
            continue
        events.append({
            "scope": "attack_class",
            "key": key,
            "verdict": verdict,
            "source": "verdict_md",
            "count_total": True,
        })
        n += 1
    return n


# --------------------------------------------------------------------------
# weight computation
# --------------------------------------------------------------------------
def compute_weights(events):
    """Fold events into per-scope weight tables. M14-trap: n==0 keys omitted."""
    buckets = {}  # (scope, key) -> {"TP":n,"FP":n,"NEGATIVE":n,"sources":set}
    totals = {"TP": 0, "FP": 0, "NEGATIVE": 0}
    for ev in events:
        if ev["key"] is None:
            continue
        bk = (ev["scope"], ev["key"])
        b = buckets.setdefault(
            bk, {"TP": 0, "FP": 0, "NEGATIVE": 0, "sources": set()})
        b[ev["verdict"]] += 1
        b["sources"].add(ev["source"])
        # verdict_totals counts each ledger row ONCE even when a row fans
        # out to both a pattern-scope and an attack_class-scope event.
        if ev.get("count_total", True):
            totals[ev["verdict"]] += 1

    attack_class = {}
    pattern = {}
    for (scope, key), b in buckets.items():
        hits = b["TP"]
        misses = b["FP"] + b["NEGATIVE"]
        n = hits + misses
        if n == 0:                       # M14-trap: never invent a weight.
            continue
        hit_rate = hits / n
        smoothed = (hits + ALPHA) / (n + 2 * ALPHA)
        weight = NEUTRAL_WEIGHT + (smoothed - 0.5) * 2 * SPAN
        weight = max(MIN_WEIGHT, min(MAX_WEIGHT, weight))
        entry = {
            "weight": round(weight, 4),
            "hits": hits,
            "misses": misses,
            "n": n,
            "hit_rate": round(hit_rate, 4),
            "smoothed_hit_rate": round(smoothed, 4),
            "sources": sorted(b["sources"]),
        }
        (attack_class if scope == "attack_class" else pattern)[key] = entry
    return attack_class, pattern, totals


def build_envelope(attack_class, pattern, totals):
    body = {
        "params": {
            "alpha": ALPHA,
            "neutral_weight": NEUTRAL_WEIGHT,
            "min_weight": MIN_WEIGHT,
            "max_weight": MAX_WEIGHT,
        },
        "attack_class_weights": dict(sorted(attack_class.items())),
        "pattern_weights": dict(sorted(pattern.items())),
        "verdict_totals": totals,
    }
    canon = json.dumps(body, sort_keys=True, separators=(",", ":"))
    content_hash = hashlib.sha256(canon.encode("utf-8")).hexdigest()
    return {"schema": SCHEMA, "content_hash": content_hash, **body}


# --------------------------------------------------------------------------
# cli
# --------------------------------------------------------------------------
def main(argv=None):
    ap = argparse.ArgumentParser(
        description="Aggregate recorded verdicts into recall_weights.json.")
    ap.add_argument(
        "--repo-root", default=".",
        help="auditooor repo root (default: cwd).")
    ap.add_argument(
        "--fp-ledger", default=None,
        help="FP verdict ledger JSONL (default: <root>/audit/fp_verdict_ledger.jsonl).")
    ap.add_argument(
        "--outcomes-jsonl", default=None,
        help="Submission outcome ledger JSONL (default: <root>/reference/outcomes.jsonl).")
    ap.add_argument(
        "--outcomes-json", default=None,
        help="Legacy outcome JSON array (default: <root>/tools/outcomes.json).")
    ap.add_argument(
        "--verdict-md-root", default=None,
        help="Root scanned for *verdict*.md (default: <root>/agent_outputs).")
    ap.add_argument(
        "--out", default=None,
        help="Output path (default: <root>/recall_weights.json).")
    ap.add_argument(
        "--quiet", action="store_true", help="Suppress the summary line.")
    args = ap.parse_args(argv)

    root = Path(args.repo_root).resolve()
    fp_ledger = Path(args.fp_ledger) if args.fp_ledger else root / "audit" / "fp_verdict_ledger.jsonl"
    outcomes_jsonl = Path(args.outcomes_jsonl) if args.outcomes_jsonl else root / "reference" / "outcomes.jsonl"
    outcomes_json = Path(args.outcomes_json) if args.outcomes_json else root / "tools" / "outcomes.json"
    md_root = Path(args.verdict_md_root) if args.verdict_md_root else root / "agent_outputs"
    out_path = Path(args.out) if args.out else root / "recall_weights.json"

    events = []
    seen_ids = set()
    counts = {
        "fp_verdict_ledger": ingest_fp_ledger(fp_ledger, events),
        "outcomes_jsonl": ingest_outcomes_jsonl(outcomes_jsonl, events, seen_ids),
        "outcomes_json": ingest_outcomes_json(outcomes_json, events, seen_ids),
        "verdict_md": ingest_verdict_md(md_root, events),
    }

    attack_class, pattern, totals = compute_weights(events)
    envelope = build_envelope(attack_class, pattern, totals)

    out_path.write_text(
        json.dumps(envelope, indent=2, sort_keys=True) + "\n", encoding="utf-8")

    if not args.quiet:
        print(
            "recall-feedback-aggregator: "
            f"events={len(events)} "
            f"attack_classes={len(attack_class)} patterns={len(pattern)} "
            f"verdicts(TP/FP/NEG)={totals['TP']}/{totals['FP']}/{totals['NEGATIVE']} "
            f"ingested={counts} "
            f"-> {out_path} hash={envelope['content_hash'][:12]}",
            file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
