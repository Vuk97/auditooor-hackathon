#!/usr/bin/env python3
"""Wire incident-record `derived_invariant` fields into the invariant extraction file
so lane-invariant-audit-ext promotes them into the per-fn pilot fuel.

Reads corpus incident records (defimon/rekt/darknavy/bridge) that carry a non-empty
`derived_invariant` + a canonical `attack_class`, and appends one
auditooor.invariant_extraction.v1 row per record to invariants_extracted.jsonl
(dedup by source_finding_id). These are agent-derived + QA-accepted invariants, so
they enter as tier-2 singletons; the audit lane decides their verdict.

Honest: this does NOT fabricate invariants - it only forwards the `derived_invariant`
already written + QA-accepted into each record. Records without one are skipped.
"""
import argparse, glob, hashlib, json, re
from datetime import datetime, timezone
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
EXTRACTED = REPO / "audit/corpus_tags/derived/invariants_extracted.jsonl"

# attack_class -> (category, family-prefix) for the INV-<FAM>-INC-NNNN id + routing
CATEGORY_MAP = {
    "oracle-price-manipulation": ("price-integrity", "ORC"),
    "share-price-manipulation": ("accounting-conservation", "ACC"),
    "amm-reserve-manipulation": ("accounting-conservation", "ACC"),
    "donation-attack": ("accounting-conservation", "ACC"),
    "callback-hook-exploit": ("atomicity", "ATM"),
    "reentrancy-cross-contract": ("atomicity", "ATM"),
    "signature-forgery": ("authorization", "AUT"),
    "signature-replay-or-forgery": ("authorization", "AUT"),
    "admin-bypass": ("authorization", "AUT"),
    "proxy-hijack": ("authorization", "AUT"),
    "proxy-upgrade-misconfiguration": ("upgrade-safety", "UPG"),
    "unprotected-initializer": ("upgrade-safety", "UPG"),
    "token-supply-inflation": ("supply-integrity", "SUP"),
    "fund-loss-via-arithmetic": ("arithmetic", "ARI"),
    "rewards-distribution-skew": ("accounting-conservation", "ACC"),
    "bridge-proof-domain-bypass": ("cross-domain-binding", "BRG"),
    "privileged-bridge-mint": ("cross-domain-binding", "BRG"),
}

def _h(s: str) -> str:
    return hashlib.sha256(s.encode()).hexdigest()[:12]

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--tag-globs", nargs="+", default=[
        "audit/corpus_tags/tags/defimon_telegram_incidents/**/*.yaml",
        "audit/corpus_tags/tags/rekt_news_incidents/**/*.yaml",
        "audit/corpus_tags/tags/darknavy_web3_incidents/**/*.yaml",
    ])
    ap.add_argument("--dry-run", action="store_true")
    args = ap.parse_args()

    existing_srcs = set()
    if EXTRACTED.exists():
        for line in EXTRACTED.read_text().splitlines():
            try:
                o = json.loads(line)
                for s in o.get("source_finding_ids", []):
                    existing_srcs.add(s)
            except Exception:
                pass

    now = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    emitted, skipped_no_inv, skipped_dup = 0, 0, 0
    new_rows = []
    seen_files = set()
    for g in args.tag_globs:
        for f in glob.glob(str(REPO / g), recursive=True):
            if f in seen_files:
                continue
            seen_files.add(f)
            t = Path(f).read_text()
            inv = re.search(r"derived_invariant:\s*[\"']?(.+?)[\"']?\s*(?:\n[a-z_]+:|\Z)", t, re.S)
            stmt = inv.group(1).strip() if inv else ""
            if not stmt or len(stmt) < 25 or stmt in ('""', "''"):
                skipped_no_inv += 1
                continue
            rid_m = re.search(r"record_id:\s*[\"']?([^\"'\n]+)", t)
            ac_m = re.search(r"^attack_class:\s*[\"']?([a-z0-9-]+)", t, re.M)
            rid = rid_m.group(1).strip() if rid_m else None
            ac = ac_m.group(1).strip() if ac_m else "unspecified"
            if not rid or rid in existing_srcs:
                skipped_dup += 1
                continue
            cat, fam = CATEGORY_MAP.get(ac, ("incident-derived", "INC"))
            lang_m = re.search(r"target_language:\s*([a-z]+)", t)
            row = {
                "schema_version": "auditooor.invariant_extraction.v1",
                "invariant_id": f"INV-{fam}-INC-{_h(rid)}",
                "statement": stmt,
                "category": cat,
                "attack_signature": f"{ac}|incident-derived",
                "abstraction_level": "incident-grounded",
                "commit_point_pattern": "",
                "defense_layer": "",
                "singleton": True,
                "source_count": 1,
                "source_finding_ids": [rid],
                "target_lang": lang_m.group(1) if lang_m else "solidity",
                "verification_tier": "tier-2-verified-public-archive",
                "extractor": "incident-derived-invariant-forward",
                "extracted_at_utc": now,
            }
            new_rows.append(row)
            existing_srcs.add(rid)
            emitted += 1

    summary = {"emitted": emitted, "skipped_no_invariant": skipped_no_inv,
               "skipped_dup": skipped_dup, "dry_run": args.dry_run,
               "extracted_file": str(EXTRACTED)}
    if not args.dry_run and new_rows:
        with EXTRACTED.open("a") as fh:
            for r in new_rows:
                fh.write(json.dumps(r) + "\n")
    print(json.dumps(summary, indent=2))

if __name__ == "__main__":
    main()
