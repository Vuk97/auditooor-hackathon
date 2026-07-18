#!/usr/bin/env python3
"""zk-verifier-bugclass-checklist.py - per-function bug-class checklist for Solidity-Honk verifiers.

RELATED TOOLS:
  - tools/zk-function-mindset.py  : circuit-side sibling (circom/halo2 template body extractor)
  - tools/function-mindset.py     : generic per-function hunt orchestrator
  Gap filled: verifier-side (Solidity BaseHonkVerifier/BaseZKHonkVerifier), which neither
  of the above tools covers. The circuit-side tools look at prover witness logic; this tool
  looks at the on-chain VERIFIER contract for soundness gaps.

Stage 2 of `make zk-hunt`. Consumes <ws>/.auditooor/zk_surface.json (written by
zk-engagement-probe.py --emit-surface) and emits
<ws>/.auditooor/zk_hunt_queue.jsonl - one predicate per verifier function.

Eight canonical verifier-side bug classes checked:
  1. transcript-absorb-completeness
  2. fs-challenge-domain-separation
  3. curve-membership-check
  4. field-inversion-zero-check
  5. public-input-delta-fiat-shamir-binding
  6. sumcheck-round-count-enforcement
  7. recursion-aggregation-object-skip
  8. shplemini-opening-proof-binding

CLI:
    python3 tools/zk-verifier-bugclass-checklist.py \\
        --workspace <ws> \\
        [--surface-file <path>]
        [--out <path>]
        [--framework solidity-honk|all]
        [--dry-run]
        [--json]

Exit codes:
    0  queue written (>=1 predicate)
    1  no verifier surface found
    2  argument error
"""
from __future__ import annotations

import argparse
import datetime
import json
import re
import sys
from pathlib import Path
from typing import Any

SCHEMA = "auditooor.zk_hunt_queue.v1"
SKIP_DIRS = {
    ".auditooor",
    ".git",
    ".venv",
    "__pycache__",
    "build",
    "cache",
    "dist",
    "node_modules",
    "out",
    "poc-tests",
    "target",
    "test",
    "tests",
}

VERIFIER_TOKENS: list[str] = [
    r"function\s+verify\b",
    r"\bpairing\s*\(",
    r"\bstaticcall\s*\(\s*gas\(\)\s*,\s*7\b",
    r"\.invert\s*\(",
    r"\bTranscript\b",
    r"\bsplitChallenge\b",
    r"\brejectPointAtInfinity\b",
    r"\bBaseHonkVerifier\b",
    r"\bBaseZKHonkVerifier\b",
    r"\bShplemini\b",
    r"\bSumcheck\b",
    r"\bpublicInputDelta\b",
    r"\bverifySumcheck\b",
    r"\bverifyShplemini\b",
    r"\bKZG\.verify\b",
    r"\bbatchMul\b",
    r"\bgetChallenge\b",
    r"\bsqueezeChallenge\b",
]

VERIFIER_PATTERN = re.compile("|".join(VERIFIER_TOKENS), re.IGNORECASE)

BUG_CLASS_PREDICATES: list[dict[str, Any]] = [
    {
        "bug_class": "transcript-absorb-completeness",
        "fn_role_keywords": ["absorb", "squeeze", "getChallenge", "squeezeChallenge", "Transcript"],
        "question": (
            "Are ALL public inputs and vkHash absorbed into the transcript "
            "BEFORE any challenge is squeezed? Missing absorption means a "
            "prover can substitute a different vk or public-input vector."
        ),
        "oracle_check": (
            "barretenberg verifier.cpp: transcript.absorb('public_inputs', "
            "publicInputsHash) precedes every transcript.get_challenge() call."
        ),
        "severity_hint": "HIGH",
    },
    {
        "bug_class": "fs-challenge-domain-separation",
        "fn_role_keywords": ["splitChallenge", "getChallenge", "squeezeChallenge", "challenge"],
        "question": (
            "Does each Fiat-Shamir challenge domain use a unique label so "
            "challenges cannot collide across domains (e.g. sumcheck vs KZG)?"
        ),
        "oracle_check": (
            "barretenberg Transcript::get_challenge<FF>(label) passes a string "
            "label; each call site uses a distinct non-reused label string."
        ),
        "severity_hint": "MEDIUM",
    },
    {
        "bug_class": "curve-membership-check",
        "fn_role_keywords": ["batchMul", "batchVerify", "pairing", "staticcall", "ecAdd", "ecMul"],
        "question": (
            "Is curve membership + point-at-infinity rejection enforced on ALL "
            "proof-element points before accumulation, not only the final pairing? "
            "A single un-checked point breaks soundness."
        ),
        "oracle_check": (
            "barretenberg batchMulAndAddPoint() calls rejectPointAtInfinity() "
            "on EVERY input G1/G2 point individually before the accumulation loop."
        ),
        "severity_hint": "HIGH",
    },
    {
        "bug_class": "field-inversion-zero-check",
        "fn_role_keywords": ["invert", "modInverse", "inverse", "divmod"],
        "question": (
            "Is the input to every .invert() / modular-inverse call checked != 0 "
            "before inversion? Division-by-zero in a finite field produces 0 "
            "or reverts depending on the implementation; either breaks soundness."
        ),
        "oracle_check": (
            "barretenberg Fr::invert() asserts input != Fr::zero() and returns "
            "std::optional; call sites in verifier.cpp check has_value() before use."
        ),
        "severity_hint": "HIGH",
    },
    {
        "bug_class": "public-input-delta-fiat-shamir-binding",
        "fn_role_keywords": ["publicInputDelta", "verifyProof", "verify"],
        "question": (
            "Are public inputs hashed into the Fiat-Shamir transcript BEFORE "
            "the first challenge is emitted (not post-hoc)? Late absorption "
            "means the challenge is independent of the public inputs."
        ),
        "oracle_check": (
            "barretenberg absorbs publicInputHash in the first transcript.absorb "
            "call before any squeeze; verify with grep absorb.*publicInput "
            "barretenberg/src/honk/verifier.cpp."
        ),
        "severity_hint": "HIGH",
    },
    {
        "bug_class": "sumcheck-round-count-enforcement",
        "fn_role_keywords": ["verifySumcheck", "Sumcheck", "sumcheckRound", "logN", "numRounds"],
        "question": (
            "Is the number of sumcheck rounds asserted == log2(circuit_size)? "
            "A prover that can reduce the round count skips expensive polynomial "
            "relations, enabling false proofs for under-constrained circuits."
        ),
        "oracle_check": (
            "barretenberg sumcheck verifier asserts "
            "round_idx < CONST_PROOF_SIZE_LOG_N throughout the round loop; "
            "check the Solidity port enforces the same bound."
        ),
        "severity_hint": "MEDIUM",
    },
    {
        "bug_class": "recursion-aggregation-object-skip",
        "fn_role_keywords": [
            "verifyZKProof", "verifyRecursive", "verifyAggregation",
            "BaseZKHonkVerifier", "BaseHonkVerifier", "aggregation",
        ],
        "question": (
            "Does the non-ZK path (BaseHonkVerifier) skip aggregation-object "
            "processing that the ZK path (BaseZKHonkVerifier) includes? "
            "Asymmetric guard creates a soundness bypass on the non-ZK path."
        ),
        "oracle_check": (
            "Diff BaseHonkVerifier.sol vs BaseZKHonkVerifier.sol for any "
            "aggregation_object / pairing accumulator block present in ZK but "
            "absent in non-ZK. The ZK verifier adds IPA accumulation "
            "that the non-ZK verifier does not; verify this is intentional."
        ),
        "severity_hint": "HIGH",
    },
    {
        "bug_class": "shplemini-opening-proof-binding",
        "fn_role_keywords": ["verifyShplemini", "verifyOpeningProof", "KZG", "Shplemini", "evaluation_challenge"],
        "question": (
            "Is the evaluation point `r` committed into the Fiat-Shamir "
            "transcript BEFORE the opening query is constructed? A free `r` "
            "lets a prover choose a convenient evaluation point."
        ),
        "oracle_check": (
            "barretenberg Shplemini.hpp squeezes evaluation_challenge_r from "
            "the transcript BEFORE constructing the opening polynomial; "
            "verify the Solidity CommitmentScheme.sol does the same."
        ),
        "severity_hint": "HIGH",
    },
]


def utc_now() -> str:
    return datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _find_sol_files(workspace: Path) -> list[Path]:
    found: list[Path] = []
    for p in workspace.rglob("*.sol"):
        if any(part in SKIP_DIRS for part in p.parts):
            continue
        try:
            if p.stat().st_size > 2 * 1024 * 1024:
                continue
        except OSError:
            continue
        found.append(p)
    return found


def _is_verifier_file(path: Path) -> bool:
    try:
        text = path.read_text(encoding="utf-8", errors="ignore")
    except OSError:
        return False
    return bool(VERIFIER_PATTERN.search(text))


def _is_audit_source_file(path: Path) -> bool:
    return not any(part in SKIP_DIRS for part in path.parts)


def _extract_function_names(text: str) -> list[str]:
    return re.findall(r"\bfunction\s+(\w+)\s*\(", text)


def _map_fn_to_bug_classes(fn_name: str, text: str) -> list[dict[str, Any]]:
    fn_name_lower = fn_name.lower()
    matched: list[dict[str, Any]] = []
    for pred in BUG_CLASS_PREDICATES:
        for kw in pred["fn_role_keywords"]:
            if kw.lower() in fn_name_lower or kw.lower() in text.lower():
                matched.append(pred)
                break
    return matched


def _resolve_file_line(path: Path, fn_name: str) -> str:
    try:
        lines = path.read_text(encoding="utf-8", errors="ignore").splitlines()
    except OSError:
        return f"{path}:?"
    pat = re.compile(rf"\bfunction\s+{re.escape(fn_name)}\s*\(")
    for idx, line in enumerate(lines, 1):
        if pat.search(line):
            return f"{path}:{idx}"
    return f"{path}:?"


def build_queue(
    workspace: Path,
    surface_file: Path | None = None,
    framework_filter: str = "all",
) -> list[dict[str, Any]]:
    sol_files: list[Path] = []
    if surface_file and surface_file.is_file():
        try:
            surface = json.loads(surface_file.read_text(encoding="utf-8"))
            for entry in surface.get("verifier_files", []):
                p = Path(entry.get("path", ""))
                if p.is_file() and _is_audit_source_file(p):
                    sol_files.append(p)
        except (json.JSONDecodeError, KeyError):
            pass

    if not sol_files:
        sol_files = [f for f in _find_sol_files(workspace) if _is_verifier_file(f)]

    queue: list[dict[str, Any]] = []
    for sol_path in sol_files:
        try:
            text = sol_path.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue
        fn_names = _extract_function_names(text)
        for fn_name in fn_names:
            preds = _map_fn_to_bug_classes(fn_name, text)
            for pred in preds:
                file_line = _resolve_file_line(sol_path, fn_name)
                item: dict[str, Any] = {
                    "fn": fn_name,
                    "file_line": file_line,
                    "bug_class": pred["bug_class"],
                    "question": pred["question"],
                    "oracle_check": pred["oracle_check"],
                    "severity_hint": pred["severity_hint"],
                    "framework": "solidity-honk",
                    "generated_at": utc_now(),
                }
                queue.append(item)

    seen: set[tuple[str, str]] = set()
    deduped: list[dict[str, Any]] = []
    for item in queue:
        key = (item["file_line"], item["bug_class"])
        if key not in seen:
            seen.add(key)
            deduped.append(item)
    return deduped


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="ZK verifier bug-class checklist generator (Stage 2)")
    ap.add_argument("--workspace", required=True, help="Path to workspace root")
    ap.add_argument("--surface-file", help="Path to zk_surface.json (default: <ws>/.auditooor/zk_surface.json)")
    ap.add_argument("--out", help="Output path for zk_hunt_queue.jsonl")
    ap.add_argument("--framework", default="all", choices=["solidity-honk", "all"],
                    help="Framework filter (default: all)")
    ap.add_argument("--dry-run", action="store_true", help="Print queue but do not write")
    ap.add_argument("--json", action="store_true", help="Print JSON summary to stdout")
    args = ap.parse_args(argv)

    ws = Path(args.workspace).resolve()
    if not ws.is_dir():
        sys.stderr.write(f"error: workspace not found: {ws}\n")
        return 2

    surface_file = Path(args.surface_file).resolve() if args.surface_file else ws / ".auditooor" / "zk_surface.json"
    out_path = Path(args.out).resolve() if args.out else ws / ".auditooor" / "zk_hunt_queue.jsonl"

    queue = build_queue(ws, surface_file, args.framework)

    if not queue:
        sys.stderr.write("[zk-vbc] no verifier functions matched any bug-class predicate\n")
        if not args.dry_run:
            out_path.parent.mkdir(parents=True, exist_ok=True)
            out_path.write_text("", encoding="utf-8")
        if args.json:
            print(json.dumps({"schema": SCHEMA, "count": 0, "items": []}))
        return 1

    summary = {
        "schema": SCHEMA,
        "workspace": str(ws),
        "generated_at": utc_now(),
        "count": len(queue),
        "bug_classes": sorted({item["bug_class"] for item in queue}),
        "items": queue,
    }

    if args.dry_run:
        print(f"[zk-vbc] DRY-RUN: {len(queue)} predicates (not writing)")
        if args.json:
            print(json.dumps(summary, indent=2))
        else:
            for item in queue:
                print(f"  {item['file_line']:60s} {item['bug_class']}")
        return 0

    out_path.parent.mkdir(parents=True, exist_ok=True)
    with out_path.open("w", encoding="utf-8") as fh:
        for item in queue:
            fh.write(json.dumps(item) + "\n")

    print(f"[zk-vbc] wrote {len(queue)} predicates -> {out_path}")
    if args.json:
        print(json.dumps(summary, indent=2))
    else:
        for item in queue[:10]:
            print(f"  {item['file_line']:60s} {item['bug_class']}")
        if len(queue) > 10:
            print(f"  ... ({len(queue) - 10} more)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
