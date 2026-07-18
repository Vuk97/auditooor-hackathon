#!/usr/bin/env python3
"""Signal-density hit ranker for the universal FP runner (Wave-5 W5-C1).

The universal FP runner (``tools/audit/universal_fp_runner.py``) emits a
high-volume, UNORDERED hit list - 645 hits on Graph, 1042 on Centrifuge.
A triager who reads that list works in O(all hits). This ranker scores
every hit by a transparent, no-ML composite and emits a ranked top-N view
so the triager reads the signal-dense hits first - O(top_n).

INPUTS (all reused, nothing re-implemented):
  --runner-output  JSON envelope from universal_fp_runner.py
                   (schema auditooor.universal_fp_runner.v1). Carries the
                   per-hit ``path_classification`` field from CAP-D7 and
                   each hit's ``confidence`` prior and ``fp_id``.
  --feedback       OPTIONAL JSON envelope from fp_tp_feedback_loop.py
                   (schema auditooor.fp_tp_feedback_loop.v1). Supplies
                   measured per-FP precision. When absent or sparse, the
                   ranker degrades gracefully to the ``confidence`` prior.

SCORE FORMULA (each term in [0,1]; weights sum to 1.0):

  score = w_prec * PREC + w_path * PATH + w_sev * SEV + w_rare * RARE

  PREC (a) measured precision of the hit's FP shape, read from the
       feedback-loop envelope (TP/(TP+FP)). When the shape has fewer than
       --min-verdicts scored verdicts, PREC falls back to the static
       ``confidence`` prior baked into the hit (high=0.85 / medium=0.55 /
       low=0.30). Default-neutral (0.5) only when neither is available.

  PATH (b) path-class weight, reusing the CAP-D7 path_classification.
       production hits rank far above test / mock noise:
         production 1.0, lib 0.45, script 0.30, unknown 0.50,
         test 0.10, mock 0.05.

  SEV  (c) severity weight of the FP shape's attack class, reusing the
       SEVERITY_PRIOR keyword table from bug-class-prioritizer.py
       (theft/freeze rank above griefing/precision-loss).

  RARE (d) rarity - a shape firing 3x ranks above one firing 900x.
       RARE = 1 / (1 + log10(production_hits_for_this_fp)). A 3-hit
       shape scores ~0.68; a 900-hit shape scores ~0.25.

The formula is fully transparent and printed in the JSON envelope's
``score_formula`` block. No ML, no opaque model.

OUTPUT: a ranked JSON envelope (schema auditooor.fp_hit_signal_ranker.v1)
plus an optional human-readable markdown table. Hits are ranked highest
score first; --top-n caps the human view.

Stdlib only.
"""
from __future__ import annotations

import argparse
import json
import math
import sys
from pathlib import Path


SCHEMA_VERSION = "auditooor.fp_hit_signal_ranker.v1"
RUNNER_SCHEMA = "auditooor.universal_fp_runner.v1"
FEEDBACK_SCHEMA = "auditooor.fp_tp_feedback_loop.v1"

# --- score weights (sum to 1.0) -------------------------------------------
DEFAULT_WEIGHTS = {
    "prec": 0.35,  # (a) measured precision (or confidence fallback)
    "path": 0.30,  # (b) production vs test/mock path class
    "sev": 0.20,   # (c) attack-class severity
    "rare": 0.15,  # (d) shape rarity
}

# (b) path-class weight. Reuses the CAP-D7 path_classification vocabulary
# (production / test / mock / lib / script / unknown).
PATH_WEIGHT = {
    "production": 1.0,
    "lib": 0.45,
    "script": 0.30,
    "unknown": 0.50,
    "test": 0.10,
    "mock": 0.05,
}
DEFAULT_PATH_WEIGHT = 0.50

# (a) static confidence prior - the fallback when the ledger is sparse.
CONFIDENCE_PRIOR = {"high": 0.85, "medium": 0.55, "low": 0.30}
DEFAULT_CONFIDENCE_PRIOR = 0.50

# (c) impact-keyword severity prior. Copied verbatim from
# tools/audit/bug-class-prioritizer.py SEVERITY_PRIOR so the two tools
# agree on attack-class severity. theft/freeze rank above griefing.
SEVERITY_PRIOR = {
    "theft": 1.0, "drain": 1.0, "steal": 1.0, "loss-of-funds": 1.0,
    "fund-loss": 1.0, "insolvency": 1.0, "mint": 0.95, "inflation": 0.95,
    "supply": 0.9, "permafreeze": 0.9, "freeze": 0.9, "frozen": 0.9,
    "takeover": 0.95, "governance": 0.85, "privilege-escalation": 0.85,
    "admin-bypass": 0.8, "auth": 0.8, "bypass": 0.75, "replay": 0.7,
    "reentrancy": 0.8, "oracle": 0.75, "misprice": 0.75, "manipulation": 0.75,
    "overflow": 0.65, "underflow": 0.65, "rounding": 0.55, "precision": 0.5,
    "dos": 0.45, "griefing": 0.4, "degradation": 0.45, "liveness": 0.6,
}
DEFAULT_SEVERITY_PRIOR = 0.55


# --------------------------------------------------------------------------
# Input loaders.
# --------------------------------------------------------------------------
def load_runner_output(path: Path) -> dict:
    """Load and shallow-validate a universal_fp_runner.py JSON envelope."""
    doc = json.loads(path.read_text(encoding="utf-8"))
    schema = str(doc.get("schema", ""))
    if schema != RUNNER_SCHEMA:
        sys.stderr.write(
            "[fp-hit-ranker] warn: %s schema is %r, expected %r (continuing)\n"
            % (path, schema, RUNNER_SCHEMA)
        )
    return doc


def load_feedback_output(path: Path) -> dict:
    """Load an fp_tp_feedback_loop.py JSON envelope. Returns {} on absence."""
    if not path or not path.is_file():
        return {}
    doc = json.loads(path.read_text(encoding="utf-8"))
    schema = str(doc.get("schema", ""))
    if schema != FEEDBACK_SCHEMA:
        sys.stderr.write(
            "[fp-hit-ranker] warn: %s schema is %r, expected %r (continuing)\n"
            % (path, schema, FEEDBACK_SCHEMA)
        )
    return doc


def fp_precision_map(feedback: dict, min_verdicts: int) -> dict:
    """fp_id -> measured precision, only for shapes with >= min_verdicts.

    Sparse shapes are intentionally omitted so the ranker falls back to
    the confidence prior. Returns {} when no feedback is supplied.
    """
    out: dict = {}
    for row in feedback.get("per_fp", []) or []:
        fp_id = row.get("fp_id")
        prec = row.get("precision")
        scored = int(row.get("scored_verdicts") or 0)
        if fp_id and prec is not None and scored >= min_verdicts:
            out[fp_id] = float(prec)
    return out


def attack_class_map(runner: dict) -> dict:
    """fp_id -> attack_class string, from the runner's fps_evaluated block."""
    out: dict = {}
    for fp in runner.get("fps_evaluated", []) or []:
        out[str(fp.get("fp_id"))] = str(
            fp.get("attack_class") or fp.get("bug_class") or ""
        )
    return out


# --------------------------------------------------------------------------
# Score terms.
# --------------------------------------------------------------------------
def severity_prior_for(name: str) -> float:
    """Max impact-keyword severity prior matching an attack/bug-class name.

    Mirrors bug-class-prioritizer.py severity_prior_for.
    """
    if not name:
        return DEFAULT_SEVERITY_PRIOR
    low = name.lower()
    best = 0.0
    hit = False
    for token, prior in SEVERITY_PRIOR.items():
        if token in low and prior > best:
            best = prior
            hit = True
    return best if hit else DEFAULT_SEVERITY_PRIOR


def prec_term(fp_id: str, confidence: str, measured: dict) -> tuple:
    """(a) precision term. Returns (value, source) where source is one of
    'measured' / 'confidence' / 'neutral'."""
    if fp_id in measured:
        return measured[fp_id], "measured"
    conf = (confidence or "").strip().lower()
    if conf in CONFIDENCE_PRIOR:
        return CONFIDENCE_PRIOR[conf], "confidence"
    return DEFAULT_CONFIDENCE_PRIOR, "neutral"


def path_term(classification: str) -> float:
    """(b) path-class term. production >> test/mock."""
    return PATH_WEIGHT.get(
        (classification or "unknown").strip().lower(), DEFAULT_PATH_WEIGHT
    )


def rare_term(production_hit_count: int) -> float:
    """(d) rarity term. A shape firing 3x outranks one firing 900x.

    RARE = 1 / (1 + log10(max(count, 1))). count=1 -> 1.0, count=3 ->
    0.68, count=100 -> 0.33, count=900 -> 0.25.
    """
    n = max(int(production_hit_count), 1)
    return 1.0 / (1.0 + math.log10(n))


# --------------------------------------------------------------------------
# Core ranking.
# --------------------------------------------------------------------------
def rank_hits(runner: dict, feedback: dict, weights: dict,
              min_verdicts: int) -> dict:
    """Score and rank every hit in the runner envelope."""
    hits = list(runner.get("hits", []) or [])
    measured = fp_precision_map(feedback, min_verdicts)
    ac_map = attack_class_map(runner)

    # (d) rarity input: count PRODUCTION hits per fp_id. test/mock noise
    # is excluded so a shape that is loud only in test files is still
    # treated as rare in production.
    prod_count_per_fp: dict = {}
    for h in hits:
        if (h.get("path_classification") or "").strip().lower() == "production":
            fid = h.get("fp_id")
            prod_count_per_fp[fid] = prod_count_per_fp.get(fid, 0) + 1

    ranked = []
    for h in hits:
        fp_id = h.get("fp_id", "")
        classification = h.get("path_classification", "unknown")
        confidence = h.get("confidence", "")
        attack_class = ac_map.get(fp_id, "")

        prec_v, prec_src = prec_term(fp_id, confidence, measured)
        path_v = path_term(classification)
        sev_v = severity_prior_for(attack_class)
        rare_v = rare_term(prod_count_per_fp.get(fp_id, 1))

        score = (
            weights["prec"] * prec_v
            + weights["path"] * path_v
            + weights["sev"] * sev_v
            + weights["rare"] * rare_v
        )
        ranked.append(
            {
                "fp_id": fp_id,
                "file": h.get("file", ""),
                "line": h.get("line", 0),
                "function": h.get("function", ""),
                "path_classification": classification,
                "attack_class": attack_class,
                "confidence": confidence,
                "snippet": h.get("snippet", ""),
                "score": round(score, 6),
                "terms": {
                    "prec": round(prec_v, 4),
                    "prec_source": prec_src,
                    "path": round(path_v, 4),
                    "sev": round(sev_v, 4),
                    "rare": round(rare_v, 4),
                },
            }
        )

    # Stable, deterministic order: score desc, then fp_id, file, line.
    ranked.sort(
        key=lambda r: (-r["score"], r["fp_id"], r["file"], r["line"])
    )
    for idx, r in enumerate(ranked, start=1):
        r["rank"] = idx

    return {
        "schema": SCHEMA_VERSION,
        "runner_output": str(runner.get("target_workspace", "")),
        "total_hits": len(ranked),
        "feedback_used": bool(measured),
        "measured_fp_shapes": sorted(measured.keys()),
        "min_verdicts": min_verdicts,
        "weights": dict(weights),
        "score_formula": (
            "score = w_prec*PREC + w_path*PATH + w_sev*SEV + w_rare*RARE; "
            "PREC = measured precision (ledger) or confidence prior; "
            "PATH = CAP-D7 path-class weight (production>>test/mock); "
            "SEV = attack-class severity keyword prior; "
            "RARE = 1/(1+log10(production_hits_for_fp))"
        ),
        "ranked_hits": ranked,
    }


# --------------------------------------------------------------------------
# Markdown rendering.
# --------------------------------------------------------------------------
def render_markdown(output: dict, top_n: int) -> str:
    lines = []
    lines.append("# fp-hit-signal-ranker report")
    lines.append("")
    lines.append("- schema: " + output["schema"])
    lines.append("- workspace: " + output["runner_output"])
    lines.append("- total hits: %d" % output["total_hits"])
    lines.append(
        "- feedback ledger used: %s"
        % ("yes" if output["feedback_used"] else "no (confidence fallback)")
    )
    if output["measured_fp_shapes"]:
        lines.append(
            "- measured FP shapes: " + ", ".join(output["measured_fp_shapes"])
        )
    w = output["weights"]
    lines.append(
        "- weights: prec=%.2f path=%.2f sev=%.2f rare=%.2f"
        % (w["prec"], w["path"], w["sev"], w["rare"])
    )
    lines.append("- formula: " + output["score_formula"])
    lines.append("")
    shown = output["ranked_hits"][:top_n]
    lines.append("## Top %d hits by signal density" % len(shown))
    lines.append("")
    lines.append(
        "| # | score | FP | path | attack_class | conf | file:line |"
    )
    lines.append("|---|-------|----|----|----|----|----|")
    for r in shown:
        loc = "%s:%s" % (r["file"], r["line"])
        lines.append(
            "| %d | %.4f | %s | %s | %s | %s | %s |"
            % (
                r["rank"],
                r["score"],
                r["fp_id"],
                r["path_classification"],
                r["attack_class"] or "-",
                r["confidence"] or "-",
                loc,
            )
        )
    lines.append("")
    remaining = output["total_hits"] - len(shown)
    if remaining > 0:
        lines.append(
            "_%d lower-ranked hits omitted from this view; see JSON for "
            "the full ranked list._" % remaining
        )
        lines.append("")
    return "\n".join(lines)


# --------------------------------------------------------------------------
# CLI.
# --------------------------------------------------------------------------
def parse_weights(spec: str) -> dict:
    """Parse a 'prec=0.4,path=0.3,...' override; missing keys keep default."""
    weights = dict(DEFAULT_WEIGHTS)
    if not spec:
        return weights
    for part in spec.split(","):
        part = part.strip()
        if not part:
            continue
        if "=" not in part:
            raise ValueError("bad weight spec fragment: %r" % part)
        key, val = part.split("=", 1)
        key = key.strip()
        if key not in weights:
            raise ValueError("unknown weight key: %r" % key)
        weights[key] = float(val)
    total = sum(weights.values())
    if total <= 0:
        raise ValueError("weights sum to %r, must be > 0" % total)
    # Normalise so the score stays in [0,1].
    return {k: v / total for k, v in weights.items()}


def main(argv: list) -> int:
    ap = argparse.ArgumentParser(
        description="Signal-density ranker for universal_fp_runner hits."
    )
    ap.add_argument(
        "--runner-output", required=True,
        help="JSON envelope from universal_fp_runner.py",
    )
    ap.add_argument(
        "--feedback", default=None,
        help="Optional JSON envelope from fp_tp_feedback_loop.py "
             "(supplies measured per-FP precision).",
    )
    ap.add_argument(
        "--min-verdicts", type=int, default=3,
        help="Min scored verdicts before a measured precision is trusted "
             "(below this, fall back to the confidence prior).",
    )
    ap.add_argument(
        "--weights", default="",
        help="Override weights, e.g. 'prec=0.4,path=0.3,sev=0.2,rare=0.1'. "
             "Re-normalised to sum to 1.0.",
    )
    ap.add_argument(
        "--top-n", type=int, default=20,
        help="Rows shown in the markdown table (JSON always has all).",
    )
    ap.add_argument("--json-out", default=None, help="Write ranked JSON here.")
    ap.add_argument("--md-out", default=None, help="Write markdown table here.")
    args = ap.parse_args(argv)

    try:
        weights = parse_weights(args.weights)
    except ValueError as exc:
        sys.stderr.write("[fp-hit-ranker] %s\n" % exc)
        return 2

    runner_path = Path(args.runner_output).expanduser()
    if not runner_path.is_file():
        sys.stderr.write(
            "[fp-hit-ranker] runner output not found: %s\n" % runner_path
        )
        return 2
    runner = load_runner_output(runner_path)

    feedback = {}
    if args.feedback:
        feedback = load_feedback_output(Path(args.feedback).expanduser())

    output = rank_hits(runner, feedback, weights, args.min_verdicts)

    if args.json_out:
        Path(args.json_out).expanduser().write_text(
            json.dumps(output, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
    md = render_markdown(output, args.top_n)
    if args.md_out:
        Path(args.md_out).expanduser().write_text(md + "\n", encoding="utf-8")

    if not args.json_out and not args.md_out:
        print(json.dumps(output, indent=2, sort_keys=True))
    else:
        sys.stderr.write(
            "[fp-hit-ranker] ranked %d hits; top score %.4f\n"
            % (
                output["total_hits"],
                output["ranked_hits"][0]["score"]
                if output["ranked_hits"] else 0.0,
            )
        )
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
