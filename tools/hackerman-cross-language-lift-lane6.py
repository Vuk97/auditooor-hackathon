#!/usr/bin/env python3
"""hackerman-cross-language-lift-lane6.py -- Lane 6: Cross-Language Analogue Lift.

HACKERMAN_V2 Lane 6 deliverable (2026-05-19).

Extends cross-language analogue records with normalized invariant fields from
the plan (lines ~628-637) and emits exploit-queue-ingestable rows for verified
cross-language analogues.

Normalized invariant fields produced per analogue:
  - asset_custody
  - authority_check
  - source_domain_proof
  - destination_settlement
  - share_mint_burn_conservation
  - price_nav_conversion
  - queue_finalization
  - withdrawal_freeze_state
  - nonce_domain_binding
  - replay_uniqueness

Cross-language query packets supported (plan lines ~638-642):
  - solidity->go (Cosmos SDK analogue)
  - go->solidity (reverse)
  - rust->solidity (Solana->EVM)
  - solidity->rust
  - bridge proof-domain across languages

Usage
-----
  python3 tools/hackerman-cross-language-lift-lane6.py [options]

  # Emit enriched analogue records from the derived sidecar:
  python3 tools/hackerman-cross-language-lift-lane6.py \\
      --sidecar audit/corpus_tags/derived/cross_language_analogues.jsonl \\
      --out reports/lane6_enriched_analogues.jsonl

  # Emit exploit-queue-ingestable rows only:
  python3 tools/hackerman-cross-language-lift-lane6.py \\
      --sidecar audit/corpus_tags/derived/cross_language_analogues.jsonl \\
      --exploit-queue-only \\
      --min-confidence 0.9 \\
      --out reports/lane6_exploit_queue_candidates.jsonl

  # Load a specific analogue record JSON (Lane 6 record format):
  python3 tools/hackerman-cross-language-lift-lane6.py \\
      --analogue-record reports/lane6_cross_language_analogue_share_inflation.json \\
      --out -
"""
from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path
from typing import Any

# ---------------------------------------------------------------------------
# Rule 37: this tool emits at tier-2-verified-public-archive for sidecar-derived
# rows and tier-3-synthetic-taxonomy-anchored for taxonomy-only analogues.
# ---------------------------------------------------------------------------

SCHEMA = "auditooor.hackerman.cross_language_lift_lane6.v1"

# Invariant field detection: maps attack_class family -> which invariant fields apply
_INVARIANT_FIELD_MAP: dict[str, list[str]] = {
    "accounting-drift": [
        "asset_custody",
        "share_mint_burn_conservation",
        "price_nav_conversion",
    ],
    "share-inflation": [
        "asset_custody",
        "share_mint_burn_conservation",
        "price_nav_conversion",
    ],
    "first-deposit": [
        "asset_custody",
        "share_mint_burn_conservation",
        "price_nav_conversion",
    ],
    "replay-domain": [
        "nonce_domain_binding",
        "replay_uniqueness",
        "source_domain_proof",
    ],
    "signature-replay": [
        "nonce_domain_binding",
        "replay_uniqueness",
        "source_domain_proof",
    ],
    "access-control": [
        "authority_check",
    ],
    "bridge": [
        "source_domain_proof",
        "destination_settlement",
        "asset_custody",
    ],
    "withdrawal": [
        "withdrawal_freeze_state",
        "asset_custody",
        "destination_settlement",
    ],
    "queue": [
        "queue_finalization",
        "withdrawal_freeze_state",
    ],
    "oracle": [
        "price_nav_conversion",
        "source_domain_proof",
    ],
    "stale": [
        "price_nav_conversion",
        "source_domain_proof",
    ],
    "freeze": [
        "withdrawal_freeze_state",
        "asset_custody",
    ],
    "consensus": [
        "source_domain_proof",
        "destination_settlement",
    ],
}

# Cross-language query packet definitions
_QUERY_PACKETS: list[dict[str, str]] = [
    {
        "packet_id": "sol-to-go",
        "source_language": "solidity",
        "target_language": "go",
        "description": "Solidity pattern to Go/Cosmos-SDK analogue",
        "translation_frame": "EVM msg-sender/modifier -> Cosmos keeper authority check",
        "attack_classes": "access-control, accounting-drift, replay-domain, oracle",
    },
    {
        "packet_id": "go-to-sol",
        "source_language": "go",
        "target_language": "solidity",
        "description": "Go/Cosmos-SDK pattern to Solidity analogue",
        "translation_frame": "Cosmos keeper authority check -> EVM msg-sender/modifier",
        "attack_classes": "access-control, accounting-drift, consensus-state",
    },
    {
        "packet_id": "rust-to-sol",
        "source_language": "rust",
        "target_language": "solidity",
        "description": "Rust/Solana pattern to EVM/Solidity analogue",
        "translation_frame": "Solana account validation -> EVM address/balance check",
        "attack_classes": "access-control, accounting-drift, bridge",
    },
    {
        "packet_id": "sol-to-rust",
        "source_language": "solidity",
        "target_language": "rust",
        "description": "Solidity pattern to Rust/Solana analogue",
        "translation_frame": "EVM storage slot accounting -> Solana account data accounting",
        "attack_classes": "accounting-drift, withdrawal, oracle",
    },
    {
        "packet_id": "bridge-proof-domain",
        "source_language": "solidity",
        "target_language": "go",
        "description": "Bridge proof-domain pattern across EVM and Cosmos",
        "translation_frame": "EVM proof verification -> Cosmos IBC channel proof",
        "attack_classes": "bridge, replay-domain, source_domain_proof",
    },
]


def _infer_invariant_fields(attack_class: str, pattern_translation: str) -> list[str]:
    """Infer which invariant fields apply based on attack_class and pattern_translation."""
    fields: set[str] = set()
    ac = (attack_class or "").lower()
    pt = (pattern_translation or "").lower()
    combined = ac + " " + pt

    for key, field_list in _INVARIANT_FIELD_MAP.items():
        if key in combined:
            fields.update(field_list)

    # Defaults: every record gets asset_custody if it touches value
    value_terms = ("share", "asset", "token", "balance", "fund", "pool", "vault", "deposit")
    if any(t in combined for t in value_terms):
        fields.add("asset_custody")

    return sorted(fields)


def _infer_query_packet(source_language: str, target_language: str) -> str:
    """Return the packet_id for a given source->target language pair."""
    src = (source_language or "").lower()
    tgt = (target_language or "").lower()
    for pkt in _QUERY_PACKETS:
        if pkt["source_language"] == src and pkt["target_language"] == tgt:
            return pkt["packet_id"]
    return f"{src}-to-{tgt}" if src and tgt else "unknown"


def _verification_tier_for_row(row: dict[str, Any]) -> str:
    """Determine verification tier for a sidecar analogue row."""
    confidence = float(row.get("confidence") or 0.0)
    reason = str(row.get("reason") or "")
    if confidence >= 0.95 and ("tier-1" in reason or "verified" in reason.lower()):
        return "tier-1-verified-realtime-api"
    if confidence >= 0.88:
        return "tier-2-verified-public-archive"
    return "tier-3-synthetic-taxonomy-anchored"


def enrich_sidecar_row(row: dict[str, Any]) -> dict[str, Any]:
    """Enrich a cross_language_analogues sidecar row with Lane 6 invariant fields."""
    attack_class = str(row.get("attack_class") or "")
    pattern_translation = str(row.get("pattern_translation") or "")
    source_language = str(row.get("source_language") or "")
    target_language = str(row.get("target_language") or "")

    invariant_fields = _infer_invariant_fields(attack_class, pattern_translation)
    query_packet = _infer_query_packet(source_language, target_language)
    verification_tier = _verification_tier_for_row(row)

    return {
        **row,
        "schema": SCHEMA,
        "invariant_fields": invariant_fields,
        "query_packet": query_packet,
        "verification_tier": verification_tier,
        "exploit_queue_ingestable": bool(invariant_fields) and float(row.get("confidence") or 0) >= 0.88,
        "lane": "lane6-cross-language-analogue-lift",
    }


def enrich_analogue_record(record: dict[str, Any]) -> dict[str, Any]:
    """Enrich a Lane 6 analogue record JSON with normalized invariant fields."""
    attack_class = str(record.get("attack_class") or "")
    bug_class = str(record.get("bug_class") or "")
    analogue_mapping = str(record.get("analogue_mapping") or "")

    # Extract source and target languages from analogue_mapping (e.g. "solidity->go->rust")
    parts = [p.strip() for p in analogue_mapping.split("->") if p.strip()]
    source_language = parts[0] if parts else str(record.get("source_language") or "")
    target_languages = parts[1:] if len(parts) > 1 else (record.get("target_languages") or [])

    combined_class = attack_class + " " + bug_class
    invariant_fields = _infer_invariant_fields(combined_class, analogue_mapping)

    query_packets = [_infer_query_packet(source_language, tgt) for tgt in target_languages]

    return {
        **record,
        "schema": SCHEMA,
        "invariant_fields": invariant_fields,
        "query_packets": query_packets,
        "lane": "lane6-cross-language-analogue-lift",
    }


def build_exploit_queue_row(enriched: dict[str, Any]) -> dict[str, Any] | None:
    """Convert an enriched sidecar row into an exploit-queue-ingestable row if eligible."""
    if not enriched.get("exploit_queue_ingestable"):
        return None

    source_id = str(enriched.get("source_record_id") or "")
    analogue_id = str(enriched.get("analogue_record_id") or "")
    attack_class = str(enriched.get("attack_class") or "")
    confidence = float(enriched.get("confidence") or 0.0)
    source_lang = str(enriched.get("source_language") or "")
    target_lang = str(enriched.get("target_language") or "")
    translation = str(enriched.get("pattern_translation") or "")
    invariant_fields = enriched.get("invariant_fields") or []
    tier = str(enriched.get("verification_tier") or "tier-3-synthetic-taxonomy-anchored")

    lead_id = f"lane6-eq-{re.sub(r'[^a-z0-9]+', '-', attack_class.lower())[:30]}-{source_lang[:4].lower()}-{target_lang[:4].lower()}"

    return {
        "lead_id": lead_id,
        "title": f"{attack_class} cross-language analogue: {translation}",
        "source_refs": [source_id, analogue_id],
        "source_artifacts_complete": tier in ("tier-1-verified-realtime-api", "tier-1-officially-disclosed", "tier-2-verified-public-archive"),
        "source_artifact_gaps": (
            [] if tier.startswith("tier-1") or tier.startswith("tier-2")
            else ["tier-3 only: no individual source anchor; verify against public archive before filing"]
        ),
        "quality_gate_status": "PENDING_LOCAL_VERIFICATION",
        "attack_class": attack_class,
        "likely_severity": "HIGH" if confidence >= 0.95 else "MEDIUM",
        "severity_confidence": confidence,
        "attacker_control": f"exploitable via {source_lang} pattern; analogue in {target_lang}",
        "impact_path": f"{translation}",
        "proof_path": "",
        "proof_artifact_precedent_refs": [],
        "metric_integrity_refs": invariant_fields,
        "learning_route": "cross-language-analogue-lift-lane6",
        "next_command": f"# Verify {source_lang}->{target_lang} analogue fires on local target",
        "blockers": ["local verification not yet run", "no fixture for target language"],
        "dupe_risk": "UNKNOWN",
        "priority_score": round(confidence * 100),
    }


def _load_sidecar(path: Path, *, min_confidence: float) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    if not path.is_file():
        return rows
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            row = json.loads(line)
        except json.JSONDecodeError:
            continue
        if not isinstance(row, dict):
            continue
        if float(row.get("confidence") or 0.0) < min_confidence:
            continue
        rows.append(row)
    return rows


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument(
        "--sidecar",
        default=str(Path(__file__).resolve().parents[1] / "audit" / "corpus_tags" / "derived" / "cross_language_analogues.jsonl"),
        help="Path to cross_language_analogues.jsonl sidecar (default: derived/ sidecar)",
    )
    parser.add_argument(
        "--analogue-record",
        default="",
        help="Path to a single Lane 6 analogue record JSON to enrich and emit",
    )
    parser.add_argument(
        "--out",
        default="-",
        help="Output file path or - for stdout",
    )
    parser.add_argument(
        "--exploit-queue-only",
        action="store_true",
        help="Emit only exploit-queue-ingestable rows (skips non-eligible analogues)",
    )
    parser.add_argument(
        "--min-confidence",
        type=float,
        default=0.9,
        help="Minimum confidence threshold for sidecar rows (default: 0.9)",
    )
    parser.add_argument(
        "--limit",
        type=int,
        default=0,
        help="Maximum number of rows to emit (0 = all)",
    )
    parser.add_argument(
        "--query-packets",
        action="store_true",
        help="Emit the query packet definitions instead of analogue records",
    )
    args = parser.parse_args(argv)

    if args.query_packets:
        out_rows = _QUERY_PACKETS
    elif args.analogue_record:
        record_path = Path(args.analogue_record)
        if not record_path.is_file():
            print(json.dumps({"error": f"analogue-record not found: {args.analogue_record}"}), file=sys.stderr)
            return 1
        record = json.loads(record_path.read_text(encoding="utf-8"))
        out_rows = [enrich_analogue_record(record)]
    else:
        sidecar_path = Path(args.sidecar)
        raw_rows = _load_sidecar(sidecar_path, min_confidence=args.min_confidence)
        enriched = [enrich_sidecar_row(r) for r in raw_rows]
        if args.exploit_queue_only:
            out_rows = []
            for row in enriched:
                eq_row = build_exploit_queue_row(row)
                if eq_row is not None:
                    out_rows.append(eq_row)
        else:
            out_rows = enriched

    if args.limit > 0:
        out_rows = out_rows[: args.limit]

    if args.out == "-":
        for row in out_rows:
            print(json.dumps(row, sort_keys=True))
    else:
        out_path = Path(args.out)
        out_path.parent.mkdir(parents=True, exist_ok=True)
        out_path.write_text(
            "\n".join(json.dumps(r, sort_keys=True) for r in out_rows) + ("\n" if out_rows else ""),
            encoding="utf-8",
        )
        print(f"lane6: wrote {len(out_rows)} rows -> {args.out}", file=sys.stderr)

    return 0


if __name__ == "__main__":
    sys.exit(main())
