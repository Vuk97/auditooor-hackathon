#!/usr/bin/env python3
"""detector-catch-rate-backtest.py - honest catch-rate backtest of the auditooor
detector library against its own known-vulnerable fixture corpus.

Problem this answers
--------------------
The repo ships ~1,500 DSL detector patterns (reference/patterns.dsl/*.yaml) and
~830 of them carry a checked-in fixture PAIR: a known-vulnerable .sol contract
and a clean .sol contract. Nobody has measured, across the whole library, how
many of those known vulnerabilities the detectors actually catch, nor how often
they false-positive on the clean variant.

This tool measures exactly that, with no inflation:

  * TRUE POSITIVE  - the pattern's own detector fires on its vulnerable fixture.
  * FALSE NEGATIVE - the detector stays silent on its vulnerable fixture (MISS).
  * FALSE POSITIVE - the detector fires on the clean fixture.
  * TRUE NEGATIVE  - the detector stays silent on the clean fixture.

It runs each DSL pattern against ONLY its own fixture pair (the honest
self-test: a detector should at minimum catch the exact contract it was
written for). Recall is then aggregated per attack_class so the WEAK classes
(low recall) surface as the next detector-writing priority.

Method notes (read before trusting the number)
----------------------------------------------
* The detector logic is the DSL preconditions/match evaluated by
  detectors/_predicate_engine.py - the same engine tools/pattern-compile.py
  bakes into every compiled Slither detector. We evaluate it directly so the
  backtest does not depend on the compiled wave* tree being in sync.
* AUDITOOOR_FIXTURE_SMOKE_MODE=1 is forced so is_vendored_or_test_contract()
  does not suppress hits on fixture-named contracts (the fixtures live under
  detectors/fixtures/, a path the vendored-filter would otherwise skip).
* attack_class is DERIVED from the pattern slug via a keyword taxonomy
  (ATTACK_CLASS_KEYWORDS below), refined by the optional `tags:` field.
  This is a heuristic; the per-class numbers are only as good as that map.
  The OVERALL catch rate does not depend on the taxonomy.
* This is a SELF-TEST against checked-in fixtures, NOT a backtest against
  independent third-party audit findings. It measures "does the library
  catch the bugs it claims to catch". A detector that passes here can still
  miss real-world variants. Do not over-read the headline number.

Output
------
  * <workspace>/.audit_logs/detector_catch_rate.json  (schema
    auditooor.detector_catch_rate.v1)
  * human-readable report on stdout, attack classes ranked by recall.

Usage
-----
  python3 tools/audit/detector-catch-rate-backtest.py [--limit N]
      [--patterns-dir DIR] [--output PATH] [--json-only] [--quiet]

Stdlib + pyyaml + slither-analyzer. Exits 0 always (measurement tool).
"""

import argparse
import json
import os
import re
import sys
import time
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
DETECTORS_DIR = REPO_ROOT / "detectors"
DEFAULT_PATTERNS_DIR = REPO_ROOT / "reference" / "patterns.dsl"
DEFAULT_CLASS_MAP = REPO_ROOT / "reference" / "detector_class_map_complete.yaml"
SCHEMA = "auditooor.detector_catch_rate.v1"
CANONICAL_MAP_SCHEMA = "auditooor.detector_class_map_complete.v1"
CANONICAL_MAP_CONFIDENCES = {"high", "medium", "low"}

# Force fixture-smoke mode so detectors are not suppressed on fixture-named
# contracts. Must be set before _template_utils is imported.
os.environ["AUDITOOOR_FIXTURE_SMOKE_MODE"] = "1"

sys.path.insert(0, str(DETECTORS_DIR))


# --------------------------------------------------------------------------
# attack_class taxonomy - keyword -> canonical class. First match in iteration
# order wins, so order from most-specific to most-generic.
# --------------------------------------------------------------------------
ATTACK_CLASS_KEYWORDS = [
    ("reentrancy", ["reentran", "cei-violation", "cei_violation", "callback-reentran",
                    "readonly-reentran", "read-only-reentran"]),
    ("access-control", ["access-control", "access_control", "onlyowner", "only-owner",
                        "missing-access", "unauthorized", "privileged", "role-",
                        "role_", "authorizeupgrade", "ownership-transfer",
                        "permission", "auth-", "auth_"]),
    ("signature-replay", ["replay", "signature", "ecrecover", "ecdsa", "eip712",
                          "eip-712", "eip_712", "permit2", "permit-", "nonce",
                          "domain-separator", "sig-", "intent-hash"]),
    ("oracle-manipulation", ["oracle", "price-manip", "spot-price", "twap",
                             "pricepershare", "chainlink", "stale-price",
                             "deviation-band", "feed-decimal"]),
    ("flashloan", ["flashloan", "flash-loan", "flash_loan"]),
    ("bridge-cross-chain", ["bridge", "cross-chain", "cross_chain", "layerzero",
                            "lzcompose", "omnibridge", "ccip", "eid-collision",
                            "chain-comparison", "l1-sender", "l2-sequencer"]),
    ("erc4626-vault", ["erc4626", "erc-4626", "first-depositor", "first_depositor",
                       "share-price", "inflation-attack", "vault-share"]),
    ("liquidation", ["liquidat", "bad-debt", "baddebt", "collateral-remainder",
                     "health-check", "undercollateral"]),
    ("reward-accounting", ["reward", "staking", "emission", "reward-debt",
                           "reward-index", "reward-per-token", "yield",
                           "checkpoint", "gauge"]),
    ("matching-engine-misprice", ["matching-engine", "matching_engine", "clob",
                                  "orderbook", "order-book", "fill-or-kill",
                                  "fok", "reduce-only", "reduce_only",
                                  "open-interest", "open_interest",
                                  "misprice", "mispricing"]),
    ("rounding-precision", ["rounding", "precision", "truncat", "division",
                            "off-by-one", "off_by_one", "integer-division",
                            "overflow", "underflow", "mispricing"]),
    ("dos-griefing", ["dos", "denial-of-service", "denial_of_service", "griefing",
                      "permanently-stall", "block-", "unliquidatable",
                      "front-run", "frontrun", "front_run"]),
    ("upgradeability", ["upgrade", "uups", "proxy", "delegatecall", "initiali",
                        "phantom-init", "implementation"]),
    ("governance", ["governance", "governor", "quorum", "voting", "proposal",
                    "timelock", "dao-", "fork-"]),
    ("token-transfer", ["transferfrom", "transfer-from", "safe-transfer",
                        "safetransfer", "erc20", "erc-20", "rebasing",
                        "fee-on-transfer", "return-value", "unchecked-return",
                        "unchecked-erc20"]),
    ("input-validation", ["zero-address", "zero_address", "zero-check",
                          "input-valid", "unvalidated", "missing-validation",
                          "not-asserted", "bounds", "unchecked"]),
    ("mev-ordering", ["mev", "sandwich", "slippage", "order-block", "tie-payout"]),
    ("nft-asset", ["nft", "erc721", "erc-721", "erc1155", "erc-1155", "erc6909",
                   "token-id", "tokenid", "seaport"]),
    ("zk-crypto", ["zk-", "zk_", "fiat-shamir", "constraint", "merkle",
                   "threshold-sign", "frost", "schnorr", "proof-"]),
    ("accounting-state", ["accounting", "state-write", "stale", "asymmetr",
                          "self-assignment", "self-referencing", "memory-copy",
                          "snapshot", "double-", "duplicate"]),
    ("fee-handling", ["fee-", "fee_", "protocol-fee", "premium"]),
]

# Canonical attack-class aliases used when the content-derived detector map is
# present. The old 21-class slug heuristic is kept as a fallback, but both
# scoreboards should compare classes in the same canonical namespace.
LEGACY_ATTACK_CLASS_ALIASES = {
    "reentrancy": "reentrancy-cross-contract",
    "access-control": "admin-bypass",
    "signature-replay": "signature-replay-cross-domain",
    "oracle-manipulation": "oracle-price-manipulation",
    "flashloan": "callback-hook-exploit",
    "bridge-cross-chain": "bridge-proof-domain-bypass",
    "erc4626-vault": "first-depositor-inflation",
    "liquidation": "liquidation-trigger-poison",
    "reward-accounting": "rewards-distribution-skew",
    "rounding-precision": "rounding-direction-attack",
    "dos-griefing": "dos-cap-weakening",
    "upgradeability": "proxy-hijack",
    "governance": "gov-param-injection",
    "token-transfer": "missing-recipient-validation",
    "input-validation": "missing-recipient-validation",
    "mev-ordering": "rounding-direction-attack",
    "nft-asset": "callback-hook-exploit",
    "zk-crypto": "signature-forgery",
    "accounting-state": "fund-loss-via-arithmetic",
    "fee-handling": "fee-redirect",
}


def _legacy_attack_class(slug: str, tags) -> str:
    """Original 21-class slug/tag heuristic, retained as a fallback."""
    hay = (slug or "").lower().replace("_", "-")
    tag_hay = " ".join(str(t).lower() for t in (tags or []))
    # tags first - if a tag is itself a recognized class keyword, prefer it.
    for cls, kws in ATTACK_CLASS_KEYWORDS:
        for kw in kws:
            if kw in tag_hay:
                return cls
    for cls, kws in ATTACK_CLASS_KEYWORDS:
        for kw in kws:
            if kw in hay:
                return cls
    return "uncategorized"


def normalize_attack_class(attack_class: str) -> str:
    """Normalize legacy attack-class labels into the canonical map namespace."""
    cls = str(attack_class or "").strip().lower().replace("_", "-")
    if not cls:
        return "uncategorized"
    return LEGACY_ATTACK_CLASS_ALIASES.get(cls, cls)


def _load_detector_class_map(path: Path = DEFAULT_CLASS_MAP):
    """Load the shared detector -> canonical attack_class map if available."""
    if not path.exists():
        return {}
    try:
        import yaml
        payload = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    except Exception:
        return {}
    if not isinstance(payload, dict):
        return {}
    if payload.get("schema") != CANONICAL_MAP_SCHEMA:
        return {}
    mappings = payload.get("mappings") or {}
    if not isinstance(mappings, dict):
        return {}

    out = {}
    for slug, row in mappings.items():
        if not isinstance(row, dict):
            continue
        cls = normalize_attack_class(row.get("attack_class"))
        confidence = str(row.get("confidence") or "").lower()
        if cls == "uncategorized" or confidence not in CANONICAL_MAP_CONFIDENCES:
            continue
        aliases = []
        raw_aliases = row.get("attack_class_aliases") or []
        if isinstance(raw_aliases, str):
            raw_aliases = [raw_aliases]
        if isinstance(raw_aliases, list):
            for item in raw_aliases:
                alias = normalize_attack_class(item)
                if alias and alias not in {"uncategorized", cls}:
                    aliases.append(alias)
        out[str(slug)] = {
            "primary": cls,
            "aliases": sorted(set(aliases)),
        }
    return out


DETECTOR_CLASS_MAP = _load_detector_class_map()


def derive_attack_class(slug: str, tags) -> str:
    """Derive a canonical attack_class from the shared map, then fallback.

    `reference/detector_class_map_complete.yaml` is the source/taxonomy-based
    classifier shared by the self-test and real-world scoreboards. The old
    slug/tag heuristic remains only as a deterministic fallback for missing or
    unavailable map rows.
    """
    slug = str(slug or "")
    mapped = DETECTOR_CLASS_MAP.get(slug)
    if mapped:
        if isinstance(mapped, dict):
            return mapped["primary"]
        return mapped
    legacy = _legacy_attack_class(slug, tags)
    if DETECTOR_CLASS_MAP:
        return normalize_attack_class(legacy)
    return legacy


def derive_attack_classes(slug: str, tags) -> set[str]:
    """Return the primary canonical class plus explicit secondary aliases.

    Most detectors are single-class. Explicit aliases are reserved for audited
    multi-class mechanics so same-class recall can count a legitimate sibling
    detector without cloning a broad or noisy rule under another class name.
    """
    slug = str(slug or "")
    mapped = DETECTOR_CLASS_MAP.get(slug)
    if mapped and isinstance(mapped, dict):
        classes = {mapped["primary"], *mapped.get("aliases", [])}
        return {c for c in classes if c and c != "uncategorized"}
    primary = derive_attack_class(slug, tags)
    return {primary} if primary and primary != "uncategorized" else set()


# --------------------------------------------------------------------------
# Detector evaluation - drive the predicate engine directly.
# --------------------------------------------------------------------------
def _import_engine():
    from _predicate_engine import eval_preconditions, eval_function_match
    from _template_utils import is_leaf_helper, is_vendored_or_test_contract
    return eval_preconditions, eval_function_match, is_leaf_helper, is_vendored_or_test_contract


def run_pattern_on_file(spec, sol_path, engine):
    """Return number of detector hits for one DSL pattern on one .sol file.

    Returns (hit_count, error_str_or_None). hit_count is 0 if the detector
    stayed silent; error is set if compilation/eval failed.
    """
    eval_pre, eval_match, is_leaf, is_vendored = engine
    preconds = spec.get("preconditions") or []
    matches = spec.get("match") or []
    include_leaf = bool(spec.get("include_leaf_helpers", False))
    try:
        from slither import Slither
    except ImportError as e:
        return 0, f"slither-import-error: {e}"
    try:
        sl = Slither(str(sol_path))
    except Exception as e:
        return 0, f"compile-error: {type(e).__name__}: {str(e)[:160]}"
    hits = 0
    try:
        for c in sl.contracts:
            # fixture-smoke mode neutralizes is_vendored; keep the call for parity.
            if is_vendored(c):
                continue
            if not eval_pre(c, preconds):
                continue
            for fn in c.functions_and_modifiers_declared:
                if not include_leaf and is_leaf(fn):
                    continue
                if eval_match(fn, matches):
                    hits += 1
    except Exception as e:
        return 0, f"eval-error: {type(e).__name__}: {str(e)[:160]}"
    return hits, None


# --------------------------------------------------------------------------
# Corpus discovery
# --------------------------------------------------------------------------
def discover_corpus(patterns_dir: Path):
    """Yield dicts for every DSL pattern that has BOTH fixture files on disk."""
    import yaml
    items = []
    for yf in sorted(patterns_dir.glob("*.yaml")):
        try:
            spec = yaml.safe_load(yf.read_text())
        except Exception:
            continue
        if not isinstance(spec, dict):
            continue
        slug = spec.get("pattern") or yf.stem
        fx = spec.get("fixtures") or {}
        vuln = fx.get("vuln")
        clean = fx.get("clean")
        if not vuln or not clean:
            continue
        vp = (REPO_ROOT / vuln) if not os.path.isabs(vuln) else Path(vuln)
        cp = (REPO_ROOT / clean) if not os.path.isabs(clean) else Path(clean)
        if not vp.exists() or not cp.exists():
            continue
        items.append({
            "pattern": slug,
            "yaml": yf,
            "spec": spec,
            "vuln_path": vp,
            "clean_path": cp,
            "severity": str(spec.get("severity", "")).upper() or "UNKNOWN",
            "attack_class": derive_attack_class(slug, spec.get("tags")),
        })
    return items


# --------------------------------------------------------------------------
# Backtest
# --------------------------------------------------------------------------
def run_backtest(items, engine, quiet=False):
    results = []
    n = len(items)
    t0 = time.time()
    for i, it in enumerate(items, 1):
        vuln_hits, vuln_err = run_pattern_on_file(it["spec"], it["vuln_path"], engine)
        clean_hits, clean_err = run_pattern_on_file(it["spec"], it["clean_path"], engine)
        # outcome classification
        compile_failed = bool(vuln_err) or bool(clean_err)
        true_positive = (vuln_hits > 0)
        false_negative = (vuln_hits == 0) and not vuln_err
        false_positive = (clean_hits > 0)
        true_negative = (clean_hits == 0) and not clean_err
        rec = {
            "pattern": it["pattern"],
            "attack_class": it["attack_class"],
            "severity": it["severity"],
            "vuln_hits": vuln_hits,
            "clean_hits": clean_hits,
            "true_positive": true_positive,
            "false_negative": false_negative,
            "false_positive": false_positive,
            "true_negative": true_negative,
            "compile_failed": compile_failed,
            "vuln_error": vuln_err,
            "clean_error": clean_err,
        }
        results.append(rec)
        if not quiet and (i % 25 == 0 or i == n):
            elapsed = time.time() - t0
            rate = i / elapsed if elapsed else 0
            sys.stderr.write(
                f"  [{i}/{n}] {elapsed:.0f}s ({rate:.1f}/s)\n")
            sys.stderr.flush()
    return results


def aggregate(results):
    """Compute overall and per-attack-class catch-rate statistics."""
    # only patterns where the vuln fixture actually compiled count toward recall
    scorable = [r for r in results if not r["vuln_error"]]
    tp = sum(1 for r in scorable if r["true_positive"])
    fn = sum(1 for r in scorable if r["false_negative"])
    # FP rate measured on clean fixtures that compiled
    clean_scorable = [r for r in results if not r["clean_error"]]
    fp = sum(1 for r in clean_scorable if r["false_positive"])
    tn = sum(1 for r in clean_scorable if r["true_negative"])
    compile_fail = sum(1 for r in results if r["compile_failed"])

    overall = {
        "patterns_total": len(results),
        "patterns_compile_failed": compile_fail,
        "vuln_fixtures_scorable": len(scorable),
        "clean_fixtures_scorable": len(clean_scorable),
        "true_positives": tp,
        "false_negatives": fn,
        "false_positives": fp,
        "true_negatives": tn,
        "recall_catch_rate": round(tp / len(scorable), 4) if scorable else 0.0,
        "false_positive_rate": round(fp / len(clean_scorable), 4) if clean_scorable else 0.0,
        # precision: of all fires (TP + FP), how many were on real vulns
        "precision": round(tp / (tp + fp), 4) if (tp + fp) else 0.0,
    }

    per_class = {}
    for r in scorable:
        c = r["attack_class"]
        d = per_class.setdefault(c, {"tp": 0, "fn": 0, "fp": 0, "n": 0})
        d["n"] += 1
        if r["true_positive"]:
            d["tp"] += 1
        if r["false_negative"]:
            d["fn"] += 1
    for r in clean_scorable:
        c = r["attack_class"]
        d = per_class.setdefault(c, {"tp": 0, "fn": 0, "fp": 0, "n": 0})
        if r["false_positive"]:
            d["fp"] += 1
    class_rows = []
    for c, d in per_class.items():
        n = d["n"]
        class_rows.append({
            "attack_class": c,
            "patterns": n,
            "true_positives": d["tp"],
            "false_negatives": d["fn"],
            "false_positives": d["fp"],
            "recall": round(d["tp"] / n, 4) if n else 0.0,
        })
    # rank by recall ascending - weakest first
    class_rows.sort(key=lambda x: (x["recall"], -x["patterns"]))
    return overall, class_rows


def build_report(overall, class_rows):
    L = []
    L.append("=" * 72)
    L.append("auditooor detector library - catch-rate backtest")
    L.append("=" * 72)
    L.append("")
    L.append("METHOD: each DSL pattern run against its OWN vuln+clean fixture")
    L.append("pair. TP=detector fires on vuln fixture. FP=detector fires on")
    L.append("clean fixture. This is a SELF-TEST, not an independent backtest.")
    L.append("")
    L.append("OVERALL")
    L.append("-" * 72)
    L.append(f"  DSL patterns with fixture pair : {overall['patterns_total']}")
    L.append(f"  patterns w/ compile failure    : {overall['patterns_compile_failed']}")
    L.append(f"  vuln fixtures scorable         : {overall['vuln_fixtures_scorable']}")
    L.append(f"  true positives (caught)        : {overall['true_positives']}")
    L.append(f"  false negatives (MISSED)       : {overall['false_negatives']}")
    L.append(f"  false positives (clean fired)  : {overall['false_positives']}")
    L.append("")
    L.append(f"  >>> CATCH RATE (recall)        : {overall['recall_catch_rate']*100:.1f}%")
    L.append(f"  >>> FALSE POSITIVE RATE        : {overall['false_positive_rate']*100:.1f}%")
    L.append(f"  >>> PRECISION                  : {overall['precision']*100:.1f}%")
    L.append("")
    L.append("ATTACK CLASSES RANKED BY RECALL (weakest first = next priority)")
    L.append("-" * 72)
    L.append(f"  {'recall':>7}  {'pats':>5}  {'TP':>4}  {'FN':>4}  {'FP':>4}  attack_class")
    for row in class_rows:
        L.append(
            f"  {row['recall']*100:6.1f}%  {row['patterns']:5}  "
            f"{row['true_positives']:4}  {row['false_negatives']:4}  "
            f"{row['false_positives']:4}  {row['attack_class']}")
    L.append("")
    weak = [r for r in class_rows if r["patterns"] >= 3][:5]
    L.append("WEAKEST 5 ATTACK CLASSES (>=3 patterns) - DETECTOR-WRITING PRIORITY")
    L.append("-" * 72)
    for r in weak:
        L.append(f"  {r['attack_class']:24} recall={r['recall']*100:.1f}% "
                 f"({r['true_positives']}/{r['patterns']})")
    L.append("=" * 72)
    return "\n".join(L)


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--patterns-dir", default=str(DEFAULT_PATTERNS_DIR))
    ap.add_argument("--limit", type=int, default=0,
                    help="cap number of patterns (0 = all). For smoke/CI.")
    ap.add_argument("--output", default=None,
                    help="JSON output path (default <repo>/.audit_logs/detector_catch_rate.json)")
    ap.add_argument("--json-only", action="store_true")
    ap.add_argument("--quiet", action="store_true")
    args = ap.parse_args()

    patterns_dir = Path(args.patterns_dir)
    if not patterns_dir.exists():
        sys.stderr.write(f"patterns dir not found: {patterns_dir}\n")
        return 0

    engine = _import_engine()
    items = discover_corpus(patterns_dir)
    if args.limit:
        items = items[:args.limit]
    if not args.quiet:
        sys.stderr.write(f"[backtest] {len(items)} DSL patterns with fixture pairs\n")

    results = run_backtest(items, engine, quiet=args.quiet)
    overall, class_rows = aggregate(results)

    out = {
        "schema": SCHEMA,
        "generated_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "patterns_dir": str(patterns_dir),
        "method": "dsl-pattern-self-test-against-own-fixture-pair",
        "fixture_smoke_mode": True,
        "overall": overall,
        "attack_classes": class_rows,
        "per_pattern": results,
    }
    output_path = Path(args.output) if args.output else (
        REPO_ROOT / ".audit_logs" / "detector_catch_rate.json")
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(json.dumps(out, indent=2))

    if not args.json_only:
        print(build_report(overall, class_rows))
        print(f"\n[json] {output_path}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
