#!/usr/bin/env python3
"""hackerman-etl-from-zk-verifier-reports.py - ETL miner for Solidity ZK verifier-side bug classes.

RELATED TOOLS:
  - tools/hackerman-etl-from-zk-bugs.py        : circuit-side ETL (zksecurity/zkbugs + 0xPARC)
  - tools/hackerman-etl-from-zk-auditor-reports.py : general ZK auditor report ETL
  - tools/hackerman-etl-from-zk-contests.py    : ZK contest archive ETL
  Gap filled: verifier-CONTRACT-side ETL (Solidity BaseHonkVerifier patterns). None of the 5
  existing ZK ETLs target the on-chain verifier contract surface; they all target circuit
  prover/witness logic or general ZK audit prose.

# Rule 37: this miner emits at tier-3-synthetic-taxonomy-anchored
# (records are derived from the 8-class taxonomy defined in zk-verifier-bugclass-checklist.py,
# not from individually verified external sources; each record carries a explicit
# verification_tier field per Rule 37 mandate)

Emits hackerman_record v1 YAML records for verifier-side ZK bug classes.
Source: the 8-class taxonomy in this file (grounded in barretenberg cross-impl evidence
as cited in the `oracle_check` field of each class).

CLI:
    python3 tools/hackerman-etl-from-zk-verifier-reports.py \\
        --out-dir audit/corpus_tags/tags/zk_verifier_bugs \\
        [--dry-run] \\
        [--json]

Exit codes:
    0  records emitted
    1  dry-run or no records
    2  argument error
"""
from __future__ import annotations

import argparse
import datetime
import json
import sys
from pathlib import Path
from typing import Any

SCHEMA = "auditooor.hackerman_record.v1"
VERIFICATION_TIER = "tier-3-synthetic-taxonomy-anchored"

# Eight verifier-side classes grounded in barretenberg cross-impl evidence
VERIFIER_CLASSES: list[dict[str, Any]] = [
    {
        "class_id": "transcript-absorb-completeness",
        "attack_class": "missing-transcript-absorption",
        "name": "Incomplete Fiat-Shamir transcript absorption",
        "description": (
            "On-chain Honk verifier omits absorbing one or more public inputs or "
            "the verification key hash before squeezing a challenge. A malicious "
            "prover can substitute an alternate vk or public-input vector while "
            "producing a valid challenge."
        ),
        "target_language": "solidity",
        "proof_system": "honk",
        "severity_class": "HIGH-1",
        "oracle_check": "barretenberg verifier.cpp: absorb(public_inputs_hash) before every squeeze",
        "fn_patterns": ["absorb", "squeezeChallenge", "getChallenge", "Transcript"],
    },
    {
        "class_id": "fs-challenge-domain-separation",
        "attack_class": "fiat-shamir-domain-collision",
        "name": "Fiat-Shamir challenge domain collision",
        "description": (
            "Multiple Fiat-Shamir challenges use the same or reused domain label, "
            "allowing a prover to predict one challenge from another across sumcheck "
            "and KZG domains."
        ),
        "target_language": "solidity",
        "proof_system": "honk",
        "severity_class": "MEDIUM",
        "oracle_check": "barretenberg: each get_challenge<FF>(label) uses a unique string label",
        "fn_patterns": ["splitChallenge", "getChallenge"],
    },
    {
        "class_id": "curve-membership-check",
        "attack_class": "missing-curve-membership-check",
        "name": "Missing BN254 curve membership check on proof points",
        "description": (
            "The on-chain verifier does not reject the point-at-infinity (or "
            "off-curve points) on individual proof elements before batch "
            "multiplication. An attacker can inject the identity point to trivially "
            "satisfy the final pairing equation."
        ),
        "target_language": "solidity",
        "proof_system": "honk",
        "severity_class": "HIGH-1",
        "oracle_check": "barretenberg batchMulAndAddPoint: rejectPointAtInfinity on EVERY input",
        "fn_patterns": ["batchMul", "pairing", "staticcall"],
    },
    {
        "class_id": "field-inversion-zero-check",
        "attack_class": "division-by-zero-finite-field",
        "name": "Missing zero-check before field inversion",
        "description": (
            "The verifier inverts a field element without checking it is non-zero. "
            "In Solidity the `invert` precompile returns 0 for input 0; in C++ it "
            "is undefined behavior. Either path allows a prover to trivially satisfy "
            "the verification equation."
        ),
        "target_language": "solidity",
        "proof_system": "honk",
        "severity_class": "HIGH-1",
        "oracle_check": "barretenberg Fr::invert checks != Fr::zero() and uses std::optional",
        "fn_patterns": ["invert", "modInverse"],
    },
    {
        "class_id": "public-input-delta-fiat-shamir-binding",
        "attack_class": "unbound-public-input-fiat-shamir",
        "name": "Public inputs not bound into Fiat-Shamir before challenge",
        "description": (
            "The public-input-delta hash is absorbed into the transcript AFTER "
            "the first challenge is squeezed, decoupling the challenge from the "
            "public inputs. A prover can fix the challenge then craft matching "
            "public inputs."
        ),
        "target_language": "solidity",
        "proof_system": "honk",
        "severity_class": "HIGH-1",
        "oracle_check": "barretenberg: publicInputHash absorbed in FIRST transcript.absorb call",
        "fn_patterns": ["publicInputDelta", "verifyProof"],
    },
    {
        "class_id": "sumcheck-round-count-enforcement",
        "attack_class": "sumcheck-round-undercount",
        "name": "Sumcheck round count not enforced to log2(circuit_size)",
        "description": (
            "The verifier does not assert that the number of sumcheck rounds equals "
            "log2 of the circuit size. A prover can terminate sumcheck early, "
            "skipping expensive polynomial relations and forging a proof."
        ),
        "target_language": "solidity",
        "proof_system": "honk",
        "severity_class": "MEDIUM",
        "oracle_check": "barretenberg: round_idx < CONST_PROOF_SIZE_LOG_N asserted in round loop",
        "fn_patterns": ["verifySumcheck", "Sumcheck"],
    },
    {
        "class_id": "recursion-aggregation-object-skip",
        "attack_class": "asymmetric-guard-recursion-aggregation",
        "name": "Recursion aggregation object absent in non-ZK verifier path",
        "description": (
            "BaseHonkVerifier.sol lacks the IPA aggregation-object processing "
            "present in BaseZKHonkVerifier.sol. A recursive proof that expects "
            "the aggregation accumulator to be folded can bypass this check by "
            "routing through the non-ZK verifier."
        ),
        "target_language": "solidity",
        "proof_system": "honk",
        "severity_class": "HIGH-1",
        "oracle_check": "diff BaseHonkVerifier.sol BaseZKHonkVerifier.sol for aggregation_object block",
        "fn_patterns": ["BaseHonkVerifier", "BaseZKHonkVerifier", "aggregation"],
    },
    {
        "class_id": "shplemini-opening-proof-binding",
        "attack_class": "unbound-evaluation-point-shplemini",
        "name": "Shplemini evaluation point not committed before opening query",
        "description": (
            "The KZG evaluation challenge `r` is derived after the opening "
            "polynomial is constructed, allowing a prover to choose a convenient "
            "evaluation point. The evaluation point must be squeezed from the "
            "transcript before constructing the opening polynomial."
        ),
        "target_language": "solidity",
        "proof_system": "honk",
        "severity_class": "HIGH-1",
        "oracle_check": "barretenberg Shplemini.hpp: evaluation_challenge_r squeezed BEFORE opening",
        "fn_patterns": ["verifyShplemini", "KZG", "Shplemini"],
    },
]


def _emit_record(cls: dict[str, Any], ts: str) -> dict[str, Any]:
    """Emit a hackerman_record v1 dict for one verifier class."""
    return {
        "schema": SCHEMA,
        "record_id": f"zk-verifier-{cls['class_id']}",
        "verification_tier": VERIFICATION_TIER,
        "attack_class": cls["attack_class"],
        "target_language": cls["target_language"],
        "proof_system": cls.get("proof_system", ""),
        "name": cls["name"],
        "description": cls["description"],
        "severity_class": cls["severity_class"],
        "oracle_check": cls["oracle_check"],
        "fn_patterns": cls["fn_patterns"],
        "circuit_dsl": "solidity-honk",
        "generated_at": ts,
        "source": "zk-verifier-bugclass-checklist-taxonomy",
    }


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(
        description="ETL miner: Solidity ZK verifier-side bug classes -> hackerman_record YAML"
    )
    ap.add_argument("--out-dir", default="audit/corpus_tags/tags/zk_verifier_bugs",
                    help="Output directory for emitted records")
    ap.add_argument("--dry-run", action="store_true", help="Print records but do not write")
    ap.add_argument("--json", action="store_true", help="Print JSON summary to stdout")
    args = ap.parse_args(argv)

    ts = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    records = [_emit_record(cls, ts) for cls in VERIFIER_CLASSES]

    if args.dry_run:
        print(f"[zk-etl-verifier] DRY-RUN: {len(records)} records (not writing)")
        if args.json:
            print(json.dumps({"count": len(records), "records": records}, indent=2))
        return 1

    out_dir = Path(args.out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)

    written = 0
    for rec in records:
        rid = rec["record_id"]
        out_path = out_dir / f"{rid}.json"
        out_path.write_text(json.dumps(rec, indent=2) + "\n", encoding="utf-8")
        written += 1

    print(f"[zk-etl-verifier] emitted {written} records -> {out_dir}")
    if args.json:
        print(json.dumps({"count": written, "out_dir": str(out_dir)}, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
