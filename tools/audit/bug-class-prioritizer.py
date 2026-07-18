#!/usr/bin/env python3
"""bug-class-prioritizer.py - rank attack classes to hunt first for a target.

LANE W4.13. The toolchain fires hundreds of detectors against a new workspace
but never says WHICH attack classes to hunt FIRST. This tool produces a ranked
list, scored from four corpus-derived signals - no re-mining.

Score (per attack class):

    priority = w_sev * SEV + w_dens * DENS + w_conc * CONC + w_prec * PREC

  SEV  (a) historical payout/severity weight for the class. Read from the
       corpus taxonomy's tier-1/2 confirmed-record ratio (a confirmed,
       source-anchored bug is worth more than a synthetic taxonomy seed)
       combined with an impact-keyword severity prior (theft/freeze/drain
       rank above griefing/precision-loss).
  DENS (b) corpus density of the class for the workspace's language mix:
       total_records for the class, language-filtered, log-scaled.
  CONC (c) the workspace's own detector-hit concentration: how many of the
       workspace's detector hits map onto this attack class (from the
       profile's detector_hits map), normalised to the busiest class.
  PREC (d) FP-runner precision for the class: 1 - false_positive_rate, read
       from the universal-FP tag corpus (source_extraction_confidence) and,
       when present, the live fp_verdict_ledger TP/(TP+FP) ratio.

Each term is in [0,1]; weights sum to 1.0; therefore priority is in [0,1].
Transparent, defensible, and every term carries its provenance into the
output JSON so a worker dispatch can see WHY a class ranked where it did.

Input: a workspace profile JSON (see --profile / bug_class_priority schema):

    {
      "workspace": "<name>",
      "languages": {"solidity": 0.8, "go": 0.2},   # language mix, weights
      "protocol_category": "lending",               # optional, advisory
      "detector_hits": {"reentrancy": 14, "...": 3} # attack-class -> hit count
    }

The detector_hits keys are matched against corpus attack-class names; a key
that does not resolve is still scored on (a)(b)(d) and flagged unresolved.

Output: auditooor.bug_class_priority.v1 JSON envelope + a human-readable
ranked brief (--brief) suitable for feeding worker dispatch.

Stdlib + PyYAML only. Reuses existing corpus indexes; does not re-mine.
"""
from __future__ import annotations

import argparse
import datetime
import hashlib
import json
import math
import sys
from pathlib import Path
from typing import Any

try:
    import yaml  # type: ignore
except ImportError:  # pragma: no cover - yaml is a hard dep across the repo
    yaml = None

SCHEMA = "auditooor.bug_class_priority.v1"

# --- repo-relative corpus index locations (reused, never re-mined) ----------
ROOT = Path(__file__).resolve().parents[2]
TAXONOMY_PATH = ROOT / "audit" / "corpus_tags" / "derived" / "attack_class_taxonomy.json"
FP_TAGS_DIR = ROOT / "audit" / "corpus_tags" / "tags"
FP_LEDGER_PATH = ROOT / "audit" / "fp_verdict_ledger.jsonl"

# --- default score weights (sum to 1.0) ------------------------------------
DEFAULT_WEIGHTS = {
    "sev": 0.35,   # (a) historical payout/severity
    "dens": 0.20,  # (b) corpus density for the language mix
    "conc": 0.30,  # (c) the workspace's own detector-hit concentration
    "prec": 0.15,  # (d) FP-runner precision
}

# Impact-keyword severity prior. A class name / impact_class containing one of
# these tokens earns the listed prior; the max matching token wins. This is a
# small, hand-set, fully transparent table - not an ML model.
SEVERITY_PRIOR = {
    # high-value: direct fund movement
    "theft": 1.0, "drain": 1.0, "steal": 1.0, "loss-of-funds": 1.0,
    "fund-loss": 1.0, "insolvency": 1.0, "mint": 0.95, "inflation": 0.95,
    "supply": 0.9, "permafreeze": 0.9, "freeze": 0.9, "frozen": 0.9,
    "takeover": 0.95, "governance": 0.85, "privilege-escalation": 0.85,
    "admin-bypass": 0.8, "auth": 0.8, "bypass": 0.75, "replay": 0.7,
    "reentrancy": 0.8, "oracle": 0.75, "misprice": 0.75, "manipulation": 0.75,
    "overflow": 0.65, "underflow": 0.65, "rounding": 0.55, "precision": 0.5,
    "dos": 0.45, "griefing": 0.4, "degradation": 0.45, "liveness": 0.6,
}
DEFAULT_SEVERITY_PRIOR = 0.55  # class with no recognisable impact keyword

# language -> corpus subtree hints (a subtree counts toward a language if its
# name carries the hint). Used to language-filter the density signal.
LANGUAGE_SUBTREE_HINTS = {
    "solidity": ("sol", "evm", "erc", "dex", "defi", "uniswap", "morpho"),
    "go": ("go", "cosmos", "ibc", "tendermint", "cometbft", "geth"),
    "rust": ("rust", "anchor", "solana", "substrate", "near", "cairo_rust"),
    "move": ("move", "aptos", "sui"),
    "cairo": ("cairo", "starknet"),
    "vyper": ("vyper",),
    "zk": ("zk", "circuit", "snark", "plonk", "halo2"),
}


# ---------------------------------------------------------------------------
# corpus loaders (read-only, reuse existing indexes)
# ---------------------------------------------------------------------------
def load_taxonomy(path: Path) -> list[dict[str, Any]]:
    """Load attack_class_taxonomy.json -> list of per-class records."""
    if not path.exists():
        return []
    try:
        doc = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return []
    classes = doc.get("classes")
    return classes if isinstance(classes, list) else []


def load_fp_precision(tags_dir: Path, ledger_path: Path) -> dict[str, float]:
    """Build attack-class -> precision[0,1] from the universal-FP corpus.

    Two sources, ledger wins when present:
      - universal-FP tag YAMLs carry source_extraction_confidence (a curator
        precision estimate). Keyed by the tag's attack_class.
      - fp_verdict_ledger.jsonl carries live TP/FP verdicts; precision is
        TP/(TP+FP) per attack class.
    """
    precision: dict[str, float] = {}
    # source 1: universal-FP tag YAMLs
    if yaml is not None and tags_dir.is_dir():
        for fp_yaml in sorted(tags_dir.glob("dsl_pattern_universal_fp_*.yaml")):
            try:
                rec = yaml.safe_load(fp_yaml.read_text(encoding="utf-8"))
            except (OSError, yaml.YAMLError):  # type: ignore[attr-defined]
                continue
            if not isinstance(rec, dict):
                continue
            cls = rec.get("attack_class") or rec.get("bug_class")
            conf = rec.get("source_extraction_confidence")
            if isinstance(cls, str) and isinstance(conf, (int, float)):
                # keep the best (most confident) estimate per class
                precision[cls] = max(precision.get(cls, 0.0), float(conf))
    # source 2: live fp_verdict_ledger (TP/FP counts) - overrides estimates
    counts: dict[str, list[int]] = {}
    if ledger_path.exists():
        for line in ledger_path.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            try:
                rec = json.loads(line)
            except json.JSONDecodeError:
                continue
            cls = rec.get("attack_class") or rec.get("bug_class")
            verdict = str(rec.get("verdict", "")).lower()
            if not isinstance(cls, str):
                continue
            tp_fp = counts.setdefault(cls, [0, 0])
            if verdict in ("tp", "true-positive", "confirmed"):
                tp_fp[0] += 1
            elif verdict in ("fp", "false-positive", "rejected"):
                tp_fp[1] += 1
    for cls, (tp, fp) in counts.items():
        if tp + fp > 0:
            precision[cls] = tp / (tp + fp)
    return precision


# ---------------------------------------------------------------------------
# scoring
# ---------------------------------------------------------------------------
def severity_prior_for(name: str) -> float:
    """Max impact-keyword severity prior matching a class/impact name."""
    low = (name or "").lower()
    best = 0.0
    hit = False
    for token, prior in SEVERITY_PRIOR.items():
        if token in low:
            best = max(best, prior)
            hit = True
    return best if hit else DEFAULT_SEVERITY_PRIOR


def language_subtree_match(subtrees: list[str], languages: dict[str, float]) -> float:
    """Fraction of the workspace's language weight whose hints touch a
    class's corpus subtrees. 1.0 = the class lives entirely in the
    workspace's language(s); 0.0 = no overlap.
    """
    if not languages:
        return 1.0
    sub_low = " ".join(s.lower() for s in subtrees)
    matched = 0.0
    for lang, weight in languages.items():
        hints = LANGUAGE_SUBTREE_HINTS.get(lang.lower(), (lang.lower(),))
        if any(h in sub_low for h in hints):
            matched += weight
    total = sum(languages.values()) or 1.0
    return matched / total


def confirmed_ratio(rec: dict[str, Any]) -> float:
    """tier-1/2 confirmed-record ratio for a class (already a [0,1] pct/100)."""
    pct = rec.get("tier12_pct")
    if isinstance(pct, (int, float)):
        return max(0.0, min(1.0, float(pct) / 100.0))
    return 0.0


def score_classes(
    taxonomy: list[dict[str, Any]],
    fp_precision: dict[str, float],
    profile: dict[str, Any],
    weights: dict[str, float],
) -> list[dict[str, Any]]:
    """Score every corpus attack class against the workspace profile."""
    languages = profile.get("languages") or {}
    detector_hits = {
        str(k): float(v)
        for k, v in (profile.get("detector_hits") or {}).items()
        if isinstance(v, (int, float))
    }
    max_hits = max(detector_hits.values(), default=0.0)
    max_records = max(
        (float(c.get("total_records", 0)) for c in taxonomy), default=1.0
    )
    log_max = math.log1p(max_records) or 1.0

    rows: list[dict[str, Any]] = []
    for rec in taxonomy:
        cls = rec.get("attack_class")
        if not isinstance(cls, str):
            continue
        subtrees = [s for s in (rec.get("subtrees") or []) if isinstance(s, str)]
        total_records = float(rec.get("total_records", 0))

        # (a) SEV: severity prior blended with confirmed-record ratio.
        # A class with a high-value impact keyword AND a high tier-1/2 ratio
        # is the gold case (e.g. diff-derived-pattern at 100% tier12).
        sev_prior = severity_prior_for(cls)
        conf = confirmed_ratio(rec)
        sev = 0.6 * sev_prior + 0.4 * conf

        # (b) DENS: log-scaled, language-filtered corpus density.
        lang_match = language_subtree_match(subtrees, languages)
        dens = (math.log1p(total_records) / log_max) * lang_match

        # (c) CONC: the workspace's own detector-hit concentration.
        hits = detector_hits.get(cls, 0.0)
        conc = (hits / max_hits) if max_hits > 0 else 0.0

        # (d) PREC: FP-runner precision; neutral 0.5 when no corpus signal.
        prec = fp_precision.get(cls, 0.5)

        priority = (
            weights["sev"] * sev
            + weights["dens"] * dens
            + weights["conc"] * conc
            + weights["prec"] * prec
        )
        rows.append(
            {
                "attack_class": cls,
                "priority": round(priority, 4),
                "components": {
                    "sev": round(sev, 4),
                    "dens": round(dens, 4),
                    "conc": round(conc, 4),
                    "prec": round(prec, 4),
                },
                "evidence": {
                    "corpus_records": int(total_records),
                    "tier12_confirmed_ratio": round(conf, 4),
                    "severity_prior": round(sev_prior, 4),
                    "language_match": round(lang_match, 4),
                    "workspace_detector_hits": int(hits),
                    "fp_precision_source": (
                        "ledger-or-tag" if cls in fp_precision else "default-0.5"
                    ),
                    "corpus_subtrees": subtrees,
                },
            }
        )

    # detector-hit keys that did not resolve onto any corpus class - the
    # worker should still know about them (custom / project-specific class).
    corpus_names = {r["attack_class"] for r in rows}
    for key, hits in detector_hits.items():
        if key not in corpus_names:
            sev = severity_prior_for(key) * 0.6  # no confirmed-ratio available
            conc = (hits / max_hits) if max_hits > 0 else 0.0
            prec = fp_precision.get(key, 0.5)
            priority = (
                weights["sev"] * sev
                + weights["dens"] * 0.0
                + weights["conc"] * conc
                + weights["prec"] * prec
            )
            rows.append(
                {
                    "attack_class": key,
                    "priority": round(priority, 4),
                    "components": {
                        "sev": round(sev, 4),
                        "dens": 0.0,
                        "conc": round(conc, 4),
                        "prec": round(prec, 4),
                    },
                    "evidence": {
                        "corpus_records": 0,
                        "tier12_confirmed_ratio": 0.0,
                        "severity_prior": round(severity_prior_for(key), 4),
                        "language_match": 0.0,
                        "workspace_detector_hits": int(hits),
                        "fp_precision_source": (
                            "ledger-or-tag" if key in fp_precision else "default-0.5"
                        ),
                        "corpus_subtrees": [],
                        "unresolved_corpus_class": True,
                    },
                }
            )

    rows.sort(key=lambda r: (-r["priority"], r["attack_class"]))
    for i, r in enumerate(rows, start=1):
        r["rank"] = i
    return rows


# ---------------------------------------------------------------------------
# envelope + brief
# ---------------------------------------------------------------------------
def build_envelope(
    profile: dict[str, Any],
    ranked: list[dict[str, Any]],
    weights: dict[str, float],
    top_n: int,
) -> dict[str, Any]:
    top = ranked[:top_n]
    payload = {
        "schema": SCHEMA,
        "kind": "bug_class_priority",
        "generated_utc": datetime.datetime.now(datetime.timezone.utc).strftime(
            "%Y-%m-%dT%H:%M:%SZ"
        ),
        "workspace": profile.get("workspace", "unknown"),
        "protocol_category": profile.get("protocol_category"),
        "languages": profile.get("languages") or {},
        "score_weights": weights,
        "score_formula": (
            "priority = w_sev*SEV + w_dens*DENS + w_conc*CONC + w_prec*PREC; "
            "SEV=historical payout/severity, DENS=corpus density (language-"
            "filtered), CONC=workspace detector-hit concentration, "
            "PREC=FP-runner precision; all terms in [0,1]"
        ),
        "classes_scored": len(ranked),
        "top_n": len(top),
        "ranked_attack_classes": top,
        "source_refs": [
            "audit/corpus_tags/derived/attack_class_taxonomy.json",
            "audit/corpus_tags/tags/dsl_pattern_universal_fp_*.yaml",
            "audit/fp_verdict_ledger.jsonl",
        ],
    }
    digest = hashlib.sha256(
        json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()
    payload["context_pack_id"] = f"{SCHEMA}:{digest[:16]}"
    payload["context_pack_hash"] = digest
    return payload


def render_brief(env: dict[str, Any]) -> str:
    lines: list[str] = []
    lines.append(f"# Bug-class hunt priority - {env['workspace']}")
    lines.append("")
    cat = env.get("protocol_category") or "(uncategorised)"
    langs = ", ".join(
        f"{k} {v}" for k, v in (env.get("languages") or {}).items()
    ) or "(unspecified)"
    lines.append(f"- Protocol category: {cat}")
    lines.append(f"- Language mix: {langs}")
    lines.append(f"- Classes scored: {env['classes_scored']}")
    lines.append(f"- Generated: {env['generated_utc']}")
    lines.append("")
    lines.append("Score = w_sev*SEV + w_dens*DENS + w_conc*CONC + w_prec*PREC")
    w = env["score_weights"]
    lines.append(
        f"  weights: sev={w['sev']} dens={w['dens']} "
        f"conc={w['conc']} prec={w['prec']}"
    )
    lines.append("")
    lines.append("## Hunt these attack classes first")
    lines.append("")
    lines.append("| # | attack class | priority | SEV | DENS | CONC | PREC | corpus | hits |")
    lines.append("|---|--------------|----------|-----|------|------|------|--------|------|")
    for r in env["ranked_attack_classes"]:
        c = r["components"]
        e = r["evidence"]
        flag = " (custom)" if e.get("unresolved_corpus_class") else ""
        lines.append(
            f"| {r['rank']} | `{r['attack_class']}`{flag} | "
            f"{r['priority']:.3f} | {c['sev']:.2f} | {c['dens']:.2f} | "
            f"{c['conc']:.2f} | {c['prec']:.2f} | "
            f"{e['corpus_records']} | {e['workspace_detector_hits']} |"
        )
    lines.append("")
    lines.append("## Dispatch rationale (top 3)")
    lines.append("")
    for r in env["ranked_attack_classes"][:3]:
        c, e = r["components"], r["evidence"]
        drivers = sorted(c.items(), key=lambda kv: -kv[1])
        top_driver = drivers[0][0]
        lines.append(
            f"- **{r['attack_class']}** (priority {r['priority']:.3f}) - "
            f"primary driver `{top_driver}`. "
            f"{e['corpus_records']} corpus records, "
            f"tier-1/2 confirmed {e['tier12_confirmed_ratio']:.0%}, "
            f"{e['workspace_detector_hits']} detector hits in this workspace, "
            f"FP precision {c['prec']:.2f}."
        )
    lines.append("")
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# cli
# ---------------------------------------------------------------------------
def load_profile(args: argparse.Namespace) -> dict[str, Any]:
    if args.profile:
        return json.loads(Path(args.profile).read_text(encoding="utf-8"))
    if args.profile_json:
        return json.loads(args.profile_json)
    raise SystemExit("error: one of --profile / --profile-json is required")


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--profile", help="path to a workspace profile JSON")
    ap.add_argument("--profile-json", help="inline workspace profile JSON string")
    ap.add_argument(
        "--taxonomy", default=str(TAXONOMY_PATH),
        help="attack_class_taxonomy.json path (corpus density index)",
    )
    ap.add_argument(
        "--fp-tags-dir", default=str(FP_TAGS_DIR),
        help="dir holding dsl_pattern_universal_fp_*.yaml",
    )
    ap.add_argument(
        "--fp-ledger", default=str(FP_LEDGER_PATH),
        help="fp_verdict_ledger.jsonl path",
    )
    ap.add_argument("--top-n", type=int, default=15)
    ap.add_argument("--json", action="store_true", help="emit JSON to stdout")
    ap.add_argument("--brief", action="store_true", help="emit markdown brief")
    ap.add_argument("--out-json", help="write JSON envelope to this path")
    ap.add_argument("--out-brief", help="write markdown brief to this path")
    ap.add_argument(
        "--weight-sev", type=float, default=DEFAULT_WEIGHTS["sev"])
    ap.add_argument(
        "--weight-dens", type=float, default=DEFAULT_WEIGHTS["dens"])
    ap.add_argument(
        "--weight-conc", type=float, default=DEFAULT_WEIGHTS["conc"])
    ap.add_argument(
        "--weight-prec", type=float, default=DEFAULT_WEIGHTS["prec"])
    args = ap.parse_args(argv)

    weights = {
        "sev": args.weight_sev,
        "dens": args.weight_dens,
        "conc": args.weight_conc,
        "prec": args.weight_prec,
    }
    wsum = sum(weights.values())
    if wsum <= 0:
        raise SystemExit("error: score weights must sum to a positive value")
    if abs(wsum - 1.0) > 1e-6:  # normalise so priority stays in [0,1]
        weights = {k: v / wsum for k, v in weights.items()}

    profile = load_profile(args)
    taxonomy = load_taxonomy(Path(args.taxonomy))
    fp_precision = load_fp_precision(
        Path(args.fp_tags_dir), Path(args.fp_ledger)
    )
    ranked = score_classes(taxonomy, fp_precision, profile, weights)
    env = build_envelope(profile, ranked, weights, args.top_n)

    if args.out_json:
        Path(args.out_json).write_text(
            json.dumps(env, indent=2) + "\n", encoding="utf-8"
        )
    if args.out_brief:
        Path(args.out_brief).write_text(render_brief(env), encoding="utf-8")

    if args.json or not (args.brief or args.out_json or args.out_brief):
        print(json.dumps(env, indent=2))
    if args.brief:
        print(render_brief(env))
    return 0


if __name__ == "__main__":
    sys.exit(main())
