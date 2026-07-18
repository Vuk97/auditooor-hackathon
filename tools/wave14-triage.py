#!/usr/bin/env python3
"""wave14-triage.py — classify wave14 auto-mined detectors into 3 buckets.

wave14/ contains hundreds of auto-mined Solodit detectors. Most are silent or
false-positive on their own fixtures. Rather than refine 1000+ broken
detectors, triage them:

  alive                     — predicates non-trivial, smoke passes (vh>=1, ch=0)
  fp_cleanup_candidate      — fires but FPs (vh>=1, ch>=1); existing fp-repair
                              queue handles these
  placeholder               — predicates trivially permissive (.*, empty, or
                              only common Solidity tokens); recommend tier=PAPER
  leave_alone               — silent with non-trivial predicates (predicates
                              may work on different fixtures), parse_error,
                              skipped_no_fix, etc.

Algorithm per detector:
  1. Read inventory_smoke status from inventory_smoke_summary.json.
  2. Read its YAML spec (drafts_audit_text/<arg>.yaml) — extract regex predicates.
  3. Bucket by status + placeholder heuristic.

Output: /private/tmp/auditooor-inventory/wave14_triage.json
"""
from __future__ import annotations

import argparse
import datetime
import json
import re
import sys
from pathlib import Path

import yaml

REPO = Path(__file__).resolve().parents[1]
INV = Path("/private/tmp/auditooor-inventory/inventory_smoke_summary.json")
SPEC_DIRS = [
    REPO / "detectors" / "_specs" / "drafts_audit_text",
    REPO / "detectors" / "_specs" / "drafts",
    REPO / "detectors" / "_specs" / "drafts_glider",
    REPO / "detectors" / "_specs" / "drafts_glider_ast",
    REPO / "detectors" / "_specs" / "drafts_code4rena_rust",
    REPO / "detectors" / "_specs" / "drafts_cyfrin_rust",
    REPO / "detectors" / "_specs" / "drafts_defihacklabs",
    REPO / "detectors" / "_specs" / "drafts_halborn-k2-2025-09",
    REPO / "detectors" / "_specs" / "drafts_halborn_soroban_general",
    REPO / "detectors" / "_specs" / "drafts_ottersec_solana",
]

# Tokens that match too many real Solidity functions to discriminate anything.
COMMON_TOKENS = {
    "transfer", "approve", "balance", "amount", "total", "supply", "reserve",
    "owner", "sender", "receiver", "from", "to", "value", "data", "call",
    "send", "set", "get", "update", "add", "remove", "init", "token",
    "user", "admin", "role", "mint", "burn", "deposit", "withdraw", "swap",
    "price", "fee", "rate",
}

PREDICATE_KEYS = (
    "fn_name_regex", "write_var_regex", "guard_var_regex", "read_var_regex",
    "required_call_regex", "tracking_var_regex", "trigger_sig_regex",
    "required_sibling_regex", "source_regex", "contract_regex",
    "target_regex", "call_regex",
)


def find_spec_yaml(arg: str) -> Path | None:
    for d in SPEC_DIRS:
        p = d / f"{arg}.yaml"
        if p.exists():
            return p
    return None


def extract_alternation_tokens(rx: str) -> list[str]:
    """Extract `tok1|tok2|...` from a `.*(tok1|tok2|...).*` regex; returns []
    for plain `.*`/empty/non-anchored shapes."""
    if not rx:
        return []
    m = re.match(r"\.\*\(([^)]+)\)\.\*\??$", rx.strip())
    if not m:
        return []
    return [t for t in m.group(1).split("|") if t]


def is_trivial_regex(rx: str) -> bool:
    """A regex is trivial if it's empty, `.*`, or `.*(<empty>).*`."""
    if not rx:
        return True
    s = rx.strip()
    if s in (".*", ".*?", ".+", "(.*)"):
        return True
    toks = extract_alternation_tokens(s)
    if toks == []:
        # not the alternation shape — assume non-trivial (literal regex)
        return False
    if not toks:
        return True
    return False


def predicates_are_placeholder(spec: dict) -> tuple[bool, list[str]]:
    """Return (is_placeholder, reasons).

    Heuristic — a detector is a placeholder if its primary discriminator
    (fn_name_regex or the only present predicate) is trivially permissive:
      - empty / `.*`
      - alternation contains only tokens of length <=3
      - alternation contains only tokens from COMMON_TOKENS
    """
    reasons: list[str] = []
    fn_re = (spec.get("fn_name_regex") or "").strip()
    # If no predicate keys at all, mark placeholder.
    has_any_predicate = any(spec.get(k) for k in PREDICATE_KEYS)
    if not has_any_predicate:
        reasons.append("no_predicate_keys")
        return True, reasons

    if is_trivial_regex(fn_re):
        # If fn_name_regex is trivial, we need at least one OTHER non-trivial
        # predicate to consider the detector real.
        other = [k for k in PREDICATE_KEYS if k != "fn_name_regex"
                 and spec.get(k) and not is_trivial_regex(str(spec.get(k)))]
        if not other:
            reasons.append("fn_name_regex_trivial_no_other_predicate")
            return True, reasons
        return False, []

    toks = extract_alternation_tokens(fn_re)
    if toks:
        if all(len(t) <= 3 for t in toks):
            reasons.append("fn_tokens_too_short")
            return True, reasons
        if all(t.lower() in COMMON_TOKENS for t in toks):
            reasons.append("fn_tokens_all_common")
            return True, reasons
    return False, []


def classify(row: dict, spec: dict | None) -> tuple[str, list[str]]:
    status = row.get("status", "")
    if status == "smoke_pass":
        return "alive", ["smoke_pass"]
    if status == "false_positive":
        return "fp_cleanup_candidate", ["vuln+clean both fired"]
    if status in ("parse_error", "skipped_no_fix", "skipped_docs", "duplicate"):
        return "leave_alone", [f"status={status}"]
    if status == "silent":
        if spec is None:
            return "leave_alone", ["silent_no_yaml"]
        is_ph, why = predicates_are_placeholder(spec)
        if is_ph:
            return "placeholder", why
        return "leave_alone", ["silent_nontrivial"]
    return "leave_alone", [f"unknown_status={status}"]


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument(
        "--out",
        default="/private/tmp/auditooor-inventory/wave14_triage.json",
    )
    ap.add_argument("--wave", default="wave14")
    args = ap.parse_args()

    if not INV.exists():
        print(f"[wave14-triage] missing inventory: {INV}", file=sys.stderr)
        return 2

    inv = json.loads(INV.read_text())
    rows = [r for r in inv.get("results", []) if r.get("wave") == args.wave]

    triaged: list[dict] = []
    buckets: dict[str, int] = {
        "alive": 0,
        "fp_cleanup_candidate": 0,
        "placeholder": 0,
        "leave_alone": 0,
    }

    for r in rows:
        arg = r.get("argument", "")
        yp = find_spec_yaml(arg)
        spec: dict | None = None
        spec_path: str | None = None
        if yp is not None:
            try:
                spec = yaml.safe_load(yp.read_text(encoding="utf-8")) or {}
                spec_path = str(yp.relative_to(REPO))
            except Exception as e:  # malformed YAML
                spec = None
                spec_path = f"<error: {e}>"
        bucket, reasons = classify(r, spec)
        buckets[bucket] = buckets.get(bucket, 0) + 1
        triaged.append({
            "argument": arg,
            "py_path": r.get("py_path"),
            "spec_path": spec_path,
            "smoke_status": r.get("status"),
            "vuln_hits": r.get("vuln_hits"),
            "clean_hits": r.get("clean_hits"),
            "bucket": bucket,
            "reasons": reasons,
            "fn_name_regex": (spec or {}).get("fn_name_regex"),
        })

    summary = {
        "schema": "auditooor.wave14_triage.v1",
        "ran_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "wave": args.wave,
        "total_detectors": len(rows),
        "buckets": buckets,
        "detectors": triaged,
    }
    Path(args.out).write_text(json.dumps(summary, indent=2))
    print(f"[wave14-triage] wave={args.wave} total={len(rows)}")
    for k, v in buckets.items():
        print(f"  {k:24s}: {v}")
    print(f"  output -> {args.out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
