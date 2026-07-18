#!/usr/bin/env python3
"""FP/TP feedback learning loop (Wave-4 W4.7 capability uplift).

The universal FP runner (``tools/audit/universal_fp_runner.py``)
fires FP-01..FP-06 regex shapes against a target workspace and
emits an ``auditooor.universal_fp_runner.v1`` JSON envelope with a
flat ``hits`` list (each hit keyed by ``fp_id`` + ``file`` +
``line``). On large targets it produces hundreds of hits (645 on
Graph, 1042 on Centrifuge).

What was missing: a feedback loop that records, per hit, whether
the operator's later triage judged it a true-positive, a
false-positive, or a negative non-finding, and feeds that verdict
history back to tune which FP shapes are worth firing.

This tool closes that loop. It:

  1. Ingests one or more universal-fp-runner JSON envelopes
     (``--runner-output``) and a verdict ledger
     (``--ledger``, JSONL, schema ``auditooor.fp_verdict_ledger.v1``).
  2. Joins runner hits to verdict records on the hit key
     ``(fp_id, file_basename, line)`` so a verdict survives a
     re-run of the FP runner from a different absolute path.
  3. Computes per-FP-shape precision = TP / (TP + FP) across all
     workspaces that have verdict coverage.
  4. Emits a tuning report classifying each FP shape:
       * keep / promote   - precision >= --promote-threshold
       * refine           - precision < --refine-threshold and
                            >= 1 FP verdict (needs a refinement
                            predicate or blacklist extension)
       * insufficient     - fewer than --min-verdicts verdicts
       * never-fires      - 0 runner hits across all envelopes
  5. Is idempotent + append-safe: the ledger is a JSONL where the
     newest record per hit key wins; re-running this tool never
     mutates the ledger and never double-counts a hit.

Schema for the JSON output: ``auditooor.fp_tp_feedback_loop.v1``.

Verdict ledger record schema (``auditooor.fp_verdict_ledger.v1``),
one JSON object per line:

  {
    "schema": "auditooor.fp_verdict_ledger.v1",
    "fp_id": "FP-01",                  # which FP shape fired
    "workspace": "graph",              # short workspace label
    "file": "contracts/Staking.sol",   # path as the runner saw it
    "line": 412,                       # 1-based line of the hit
    "verdict": "TP",                   # TP | FP | NEGATIVE
    "function": "withdraw",            # optional, runner-reported
    "note": "real missing-guard",      # optional free-text
    "recorded_at": "2026-05-16T00:00:00Z",  # ISO-8601 UTC
    "recorded_by": "operator"          # who triaged it
  }

Verdict vocabulary (exact values):
  * ``TP``       - the hit was a real, fileable / confirmed issue.
  * ``FP``       - the hit was a false positive (shape misfired).
  * ``NEGATIVE`` - reviewed, not an issue, but also not a shape
                   misfire (e.g. by-design, acknowledged, OOS).
                   NEGATIVE is excluded from the precision
                   denominator: precision = TP / (TP + FP).

CLI surface:

  --runner-output P[,P...]  One or more universal-fp-runner JSON
                            envelopes (repeatable / comma-list).
  --ledger PATH             Verdict ledger JSONL (created empty if
                            absent).
  --json                    Emit JSON to stdout (default: on).
  --markdown                Also emit a human-readable report.
  --output PATH             Write JSON to file instead of stdout.
  --markdown-output PATH     Write markdown report to file.
  --promote-threshold F     Precision >= F => keep/promote
                            (default 0.70).
  --refine-threshold F      Precision < F => refine (default 0.50).
  --min-verdicts N          Need >= N verdicts to score a shape
                            (default 3).
  --strict                  Exit 1 if any FP shape is classified
                            ``refine`` (noisy shapes block).

Stdlib only. No network. No mutation of the ledger or of any
runner output. Per Rule 37 this tool is a CONSUMER of corpus /
runner records and does not emit tier-bearing corpus records, so
emit-time tier discipline is not in scope. Per Rule 36 the tool
makes no git-state changes; it is invoked under explicit pathspec.
"""
from __future__ import annotations

import argparse
import json
import os
import sys
from dataclasses import dataclass, field
from pathlib import Path


OUTPUT_SCHEMA = "auditooor.fp_tp_feedback_loop.v1"
LEDGER_SCHEMA = "auditooor.fp_verdict_ledger.v1"
VALID_VERDICTS = {"TP", "FP", "NEGATIVE"}


# ---------------------------------------------------------------------------
# Hit key normalisation.
#
# The FP runner records absolute file paths. A verdict recorded on
# one machine / worktree must still join when the runner is re-run
# from a different absolute root. We therefore key on
# (fp_id, file_basename, line). The basename is a deliberate
# trade-off: it tolerates path drift at the cost of conflating two
# same-named files in different directories. The full path is
# retained in the output for operator disambiguation.
# ---------------------------------------------------------------------------


def hit_key(fp_id: str, file_path: str, line) -> tuple:
    """Stable join key for a hit / verdict, tolerant of path drift."""
    base = os.path.basename(str(file_path).strip())
    try:
        line_i = int(line)
    except (TypeError, ValueError):
        line_i = 0
    return (str(fp_id).strip(), base, line_i)


# ---------------------------------------------------------------------------
# Ledger I/O.
# ---------------------------------------------------------------------------


@dataclass
class VerdictRecord:
    fp_id: str
    workspace: str
    file: str
    line: int
    verdict: str
    function: str = ""
    note: str = ""
    recorded_at: str = ""
    recorded_by: str = ""

    @property
    def key(self) -> tuple:
        return hit_key(self.fp_id, self.file, self.line)


def load_ledger(ledger_path: Path) -> list:
    """Read a JSONL verdict ledger.

    Returns a list of VerdictRecord. Malformed lines are skipped
    with a stderr note (never fatal). An absent ledger is treated
    as empty - this tool is the bootstrap for a fresh ledger.

    Idempotency / append-safety: the ledger is append-only on the
    write side (future hunts append one line per triaged hit).
    On the read side, the NEWEST record per hit key wins, so a
    re-triage that flips FP -> TP simply appends a newer line and
    the loop honours it without any in-place mutation. A re-run of
    this tool against the same ledger therefore produces identical
    counts (no double-count) because dedupe is by key, not by line.
    """
    out = []
    if not ledger_path.is_file():
        return out
    for lineno, raw in enumerate(
        ledger_path.read_text(encoding="utf-8").splitlines(), start=1
    ):
        raw = raw.strip()
        if not raw or raw.startswith("#"):
            continue
        try:
            doc = json.loads(raw)
        except json.JSONDecodeError as exc:
            sys.stderr.write(
                "[fp-tp-loop] skip malformed ledger line %d: %s\n"
                % (lineno, exc)
            )
            continue
        verdict = str(doc.get("verdict", "")).strip().upper()
        if verdict not in VALID_VERDICTS:
            sys.stderr.write(
                "[fp-tp-loop] skip ledger line %d: bad verdict %r\n"
                % (lineno, doc.get("verdict"))
            )
            continue
        fp_id = str(doc.get("fp_id", "")).strip()
        if not fp_id:
            sys.stderr.write(
                "[fp-tp-loop] skip ledger line %d: missing fp_id\n" % lineno
            )
            continue
        try:
            line_i = int(doc.get("line", 0))
        except (TypeError, ValueError):
            line_i = 0
        out.append(
            VerdictRecord(
                fp_id=fp_id,
                workspace=str(doc.get("workspace", "")).strip(),
                file=str(doc.get("file", "")).strip(),
                line=line_i,
                verdict=verdict,
                function=str(doc.get("function", "")).strip(),
                note=str(doc.get("note", "")).strip(),
                recorded_at=str(doc.get("recorded_at", "")).strip(),
                recorded_by=str(doc.get("recorded_by", "")).strip(),
            )
        )
    return out


def dedupe_verdicts(records: list) -> dict:
    """Collapse to one verdict per hit key (newest record wins).

    Newest is decided by ``recorded_at`` ISO-8601 string ordering;
    records with no timestamp sort earliest, so a later explicit
    timestamp always supersedes an undated bootstrap row.
    """
    by_key: dict = {}
    for rec in records:
        prev = by_key.get(rec.key)
        if prev is None or rec.recorded_at >= prev.recorded_at:
            by_key[rec.key] = rec
    return by_key


# ---------------------------------------------------------------------------
# Runner-envelope ingest.
# ---------------------------------------------------------------------------


def load_runner_hits(paths: list) -> list:
    """Read universal-fp-runner JSON envelopes -> flat hit dicts.

    Each returned dict carries the runner hit fields plus a
    ``workspace`` label derived from the envelope's
    ``target_workspace`` basename and the join ``key``.
    """
    hits = []
    for raw_path in paths:
        path = Path(raw_path).expanduser()
        if not path.is_file():
            sys.stderr.write(
                "[fp-tp-loop] runner-output not found: %s\n" % path
            )
            continue
        try:
            doc = json.loads(path.read_text(encoding="utf-8"))
        except json.JSONDecodeError as exc:
            sys.stderr.write(
                "[fp-tp-loop] skip malformed runner-output %s: %s\n"
                % (path, exc)
            )
            continue
        schema = str(doc.get("schema", ""))
        if schema != "auditooor.universal_fp_runner.v1":
            sys.stderr.write(
                "[fp-tp-loop] warn %s: unexpected schema %r (continuing)\n"
                % (path, schema)
            )
        ws_label = os.path.basename(
            str(doc.get("target_workspace", "")).rstrip("/")
        )
        for h in doc.get("hits", []) or []:
            fp_id = str(h.get("fp_id", "")).strip()
            file_path = str(h.get("file", "")).strip()
            line = h.get("line", 0)
            hits.append(
                {
                    "fp_id": fp_id,
                    "workspace": ws_label,
                    "file": file_path,
                    "line": line,
                    "function": str(h.get("function", "")),
                    "confidence": str(h.get("confidence", "")),
                    "key": hit_key(fp_id, file_path, line),
                }
            )
    return hits


# ---------------------------------------------------------------------------
# Core: join + precision + classification.
# ---------------------------------------------------------------------------


@dataclass
class FPScore:
    fp_id: str
    runner_hits: int = 0
    tp: int = 0
    fp: int = 0
    negative: int = 0
    matched_hits: int = 0  # runner hits that had a verdict
    orphan_verdicts: int = 0  # verdicts with no matching runner hit
    workspaces: set = field(default_factory=set)

    @property
    def scored(self) -> int:
        return self.tp + self.fp

    @property
    def precision(self):
        if self.scored == 0:
            return None
        return self.tp / self.scored

    @property
    def coverage(self):
        """Fraction of runner hits that carry a verdict."""
        if self.runner_hits == 0:
            return None
        return self.matched_hits / self.runner_hits


def compute_scores(
    runner_hits: list,
    verdicts: dict,
    all_fp_ids: set,
) -> dict:
    """Join runner hits to deduped verdicts and tally per FP.

    ``verdicts`` is the key->VerdictRecord map from
    ``dedupe_verdicts``. The precision tally uses every deduped
    verdict (so a shape with verdict data but no runner envelope
    is still scored - orphan verdicts count toward precision).
    Runner-hit counts come from the envelopes.
    """
    scores: dict = {}
    for fp_id in all_fp_ids:
        scores[fp_id] = FPScore(fp_id=fp_id)

    # Runner-hit side: count hits, mark which carry a verdict.
    verdict_keys_seen: set = set()
    for h in runner_hits:
        sc = scores.setdefault(h["fp_id"], FPScore(fp_id=h["fp_id"]))
        sc.runner_hits += 1
        if h["workspace"]:
            sc.workspaces.add(h["workspace"])
        if h["key"] in verdicts:
            sc.matched_hits += 1
            verdict_keys_seen.add(h["key"])

    # Verdict side: tally TP/FP/NEGATIVE per FP from deduped ledger.
    for key, rec in verdicts.items():
        sc = scores.setdefault(rec.fp_id, FPScore(fp_id=rec.fp_id))
        if rec.verdict == "TP":
            sc.tp += 1
        elif rec.verdict == "FP":
            sc.fp += 1
        elif rec.verdict == "NEGATIVE":
            sc.negative += 1
        if rec.workspace:
            sc.workspaces.add(rec.workspace)
        if key not in verdict_keys_seen:
            sc.orphan_verdicts += 1

    return scores


def classify(
    score: FPScore,
    promote_threshold: float,
    refine_threshold: float,
    min_verdicts: int,
) -> tuple:
    """Return (classification, rationale).

    Classifications:
      * never-fires   - 0 runner hits across all envelopes AND
                        0 verdicts (the shape produced nothing).
      * insufficient  - fewer than min_verdicts scored verdicts
                        (TP+FP) - cannot judge precision yet.
      * keep-promote  - precision >= promote_threshold.
      * refine        - precision < refine_threshold.
      * monitor       - refine_threshold <= precision <
                        promote_threshold (acceptable but watch).
    """
    if score.runner_hits == 0 and (score.tp + score.fp + score.negative) == 0:
        return ("never-fires", "0 runner hits and 0 verdicts recorded")
    if score.scored < min_verdicts:
        return (
            "insufficient",
            "only %d scored verdict(s) (TP+FP); need >= %d"
            % (score.scored, min_verdicts),
        )
    prec = score.precision
    if prec >= promote_threshold:
        return (
            "keep-promote",
            "precision %.2f >= promote threshold %.2f"
            % (prec, promote_threshold),
        )
    if prec < refine_threshold:
        return (
            "refine",
            "precision %.2f < refine threshold %.2f - needs a "
            "refinement predicate or blacklist extension"
            % (prec, refine_threshold),
        )
    return (
        "monitor",
        "precision %.2f in [%.2f, %.2f) - acceptable, keep watching"
        % (prec, refine_threshold, promote_threshold),
    )


# ---------------------------------------------------------------------------
# Output builders.
# ---------------------------------------------------------------------------


def build_output(
    scores: dict,
    ledger_path: Path,
    runner_outputs: list,
    promote_threshold: float,
    refine_threshold: float,
    min_verdicts: int,
) -> dict:
    fp_rows = []
    for fp_id in sorted(scores.keys()):
        sc = scores[fp_id]
        classification, rationale = classify(
            sc, promote_threshold, refine_threshold, min_verdicts
        )
        prec = sc.precision
        cov = sc.coverage
        fp_rows.append(
            {
                "fp_id": fp_id,
                "runner_hits": sc.runner_hits,
                "tp": sc.tp,
                "fp": sc.fp,
                "negative": sc.negative,
                "scored_verdicts": sc.scored,
                "precision": round(prec, 4) if prec is not None else None,
                "matched_hits": sc.matched_hits,
                "orphan_verdicts": sc.orphan_verdicts,
                "verdict_coverage": round(cov, 4) if cov is not None else None,
                "workspaces": sorted(sc.workspaces),
                "classification": classification,
                "rationale": rationale,
            }
        )

    totals = {
        "fp_shapes": len(fp_rows),
        "runner_hits": sum(r["runner_hits"] for r in fp_rows),
        "tp": sum(r["tp"] for r in fp_rows),
        "fp": sum(r["fp"] for r in fp_rows),
        "negative": sum(r["negative"] for r in fp_rows),
    }
    scored_total = totals["tp"] + totals["fp"]
    totals["overall_precision"] = (
        round(totals["tp"] / scored_total, 4) if scored_total else None
    )

    buckets: dict = {}
    for r in fp_rows:
        buckets.setdefault(r["classification"], []).append(r["fp_id"])

    return {
        "schema": OUTPUT_SCHEMA,
        "ledger": str(ledger_path.resolve()),
        "ledger_schema": LEDGER_SCHEMA,
        "runner_outputs": [str(Path(p).expanduser()) for p in runner_outputs],
        "thresholds": {
            "promote": promote_threshold,
            "refine": refine_threshold,
            "min_verdicts": min_verdicts,
        },
        "totals": totals,
        "classification_buckets": {
            k: sorted(v) for k, v in sorted(buckets.items())
        },
        "fp_shapes": fp_rows,
    }


def render_markdown(out: dict) -> str:
    lines = []
    lines.append("# fp_tp_feedback_loop tuning report")
    lines.append("")
    lines.append("- schema: " + out["schema"])
    lines.append("- ledger: " + out["ledger"])
    lines.append(
        "- runner outputs: %d" % len(out["runner_outputs"])
    )
    t = out["totals"]
    lines.append(
        "- totals: %d shapes, %d runner hits, %d TP / %d FP / %d NEGATIVE"
        % (t["fp_shapes"], t["runner_hits"], t["tp"], t["fp"], t["negative"])
    )
    op = t["overall_precision"]
    lines.append(
        "- overall precision: %s"
        % ("%.2f" % op if op is not None else "n/a (no scored verdicts)")
    )
    lines.append("")
    lines.append("## per-FP-shape scoring")
    lines.append("")
    lines.append(
        "| fp_id | runner hits | TP | FP | NEG | precision | "
        "coverage | classification |"
    )
    lines.append(
        "| --- | ---:| ---:| ---:| ---:| ---:| ---:| --- |"
    )
    for r in out["fp_shapes"]:
        prec = (
            "%.2f" % r["precision"] if r["precision"] is not None else "-"
        )
        cov = (
            "%.0f%%" % (r["verdict_coverage"] * 100)
            if r["verdict_coverage"] is not None
            else "-"
        )
        lines.append(
            "| %s | %d | %d | %d | %d | %s | %s | %s |"
            % (
                r["fp_id"],
                r["runner_hits"],
                r["tp"],
                r["fp"],
                r["negative"],
                prec,
                cov,
                r["classification"],
            )
        )
    lines.append("")
    lines.append("## tuning actions")
    lines.append("")
    buckets = out["classification_buckets"]
    action_text = {
        "keep-promote": "high-precision shapes - keep / promote",
        "monitor": "acceptable precision - keep watching",
        "refine": (
            "NOISY - add a refinement predicate or extend the "
            "test/mock blacklist"
        ),
        "insufficient": (
            "not enough verdicts - future hunts must triage hits "
            "into the ledger"
        ),
        "never-fires": (
            "0 runner hits and 0 verdicts - dead shape, candidate "
            "for removal"
        ),
    }
    for cls in [
        "keep-promote",
        "monitor",
        "refine",
        "insufficient",
        "never-fires",
    ]:
        ids = buckets.get(cls, [])
        if not ids:
            continue
        lines.append(
            "- **%s** (%s): %s"
            % (cls, action_text.get(cls, ""), ", ".join(ids))
        )
    lines.append("")
    lines.append("## per-shape rationale")
    lines.append("")
    for r in out["fp_shapes"]:
        lines.append("- `%s`: %s" % (r["fp_id"], r["rationale"]))
    lines.append("")
    return "\n".join(lines) + "\n"


# ---------------------------------------------------------------------------
# CLI.
# ---------------------------------------------------------------------------


def _split_paths(values: list) -> list:
    out = []
    for v in values:
        out.extend(x.strip() for x in str(v).split(",") if x.strip())
    return out


def main(argv: list) -> int:
    p = argparse.ArgumentParser(
        description=(
            "FP/TP feedback learning loop: score universal-fp "
            "shapes by precision against a verdict ledger and emit "
            "a tuning report."
        )
    )
    p.add_argument(
        "--runner-output",
        action="append",
        default=[],
        help="universal-fp-runner JSON envelope (repeatable / comma-list)",
    )
    p.add_argument(
        "--ledger",
        required=True,
        help="verdict ledger JSONL (auditooor.fp_verdict_ledger.v1)",
    )
    p.add_argument("--json", action="store_true", default=True)
    p.add_argument("--markdown", action="store_true")
    p.add_argument("--output", default="", help="write JSON to this file")
    p.add_argument(
        "--markdown-output", default="", help="write markdown to this file"
    )
    p.add_argument(
        "--promote-threshold",
        type=float,
        default=0.70,
        help="precision >= this => keep/promote (default 0.70)",
    )
    p.add_argument(
        "--refine-threshold",
        type=float,
        default=0.50,
        help="precision < this => refine (default 0.50)",
    )
    p.add_argument(
        "--min-verdicts",
        type=int,
        default=3,
        help="need >= N scored verdicts to judge a shape (default 3)",
    )
    p.add_argument(
        "--strict",
        action="store_true",
        help="exit 1 if any FP shape is classified 'refine'",
    )
    args = p.parse_args(argv)

    if args.refine_threshold > args.promote_threshold:
        sys.stderr.write(
            "[fp-tp-loop] refine-threshold must be <= promote-threshold\n"
        )
        return 2

    ledger_path = Path(args.ledger).expanduser()
    verdict_records = load_ledger(ledger_path)
    verdicts = dedupe_verdicts(verdict_records)

    runner_outputs = _split_paths(args.runner_output)
    runner_hits = load_runner_hits(runner_outputs)

    all_fp_ids = {h["fp_id"] for h in runner_hits if h["fp_id"]}
    all_fp_ids |= {r.fp_id for r in verdict_records if r.fp_id}

    scores = compute_scores(runner_hits, verdicts, all_fp_ids)
    out = build_output(
        scores,
        ledger_path,
        runner_outputs,
        args.promote_threshold,
        args.refine_threshold,
        args.min_verdicts,
    )

    txt = json.dumps(out, indent=2, sort_keys=True)
    if args.output:
        Path(args.output).expanduser().write_text(
            txt + "\n", encoding="utf-8"
        )
    else:
        sys.stdout.write(txt + "\n")
    if args.markdown or args.markdown_output:
        md = render_markdown(out)
        if args.markdown_output:
            Path(args.markdown_output).expanduser().write_text(
                md, encoding="utf-8"
            )
        else:
            sys.stdout.write(md)

    if args.strict:
        refine_ids = out["classification_buckets"].get("refine", [])
        if refine_ids:
            sys.stderr.write(
                "[fp-tp-loop] strict: %d noisy shape(s) need refinement: %s\n"
                % (len(refine_ids), ", ".join(refine_ids))
            )
            return 1
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
