#!/usr/bin/env python3
"""mimo-sidecar-metadata-backfill.py - rescue lost metadata from saved batch files.

r36-rebuttal: lane sidecar-backfill-2026-05-28 pathspec-registered

WHY THIS EXISTS (operator pain anchor, 2026-05-28):
  6,558 existing MIMO sidecars have status=ok but are missing:
    - workspace
    - source_question_id
    - function_anchor
    - attack_class
  because the llm-fanout-dispatcher (was deepseek-fanout-dispatcher, pre-2026-05-28 patch) dropped
  these fields when emitting per-task sidecars. Result: mimo-corpus-miner
  collapsed all attack_class to "generic", chain_candidates=0, and
  brain_prime_priors=0.

THE FIX:
  The dispatcher's INPUT batch JSONLs are still on disk at
  /tmp/mimo_harness_*_batch.jsonl. Each batch row has all the fields
  (task_id, workspace, workspace_path, source_question_id, prompt).
  We JOIN sidecar.task_id -> batch_row and write the metadata back to
  the sidecar IN-PLACE (additive; existing fields preserved).

  Bonus: we also extract attack_class from the prompt's hypothesis text
  using the same class-keyword bags shipped in mimo-class-keyword-prefilter.

RELATED TOOLS:
  - tools/mimo-corpus-miner.py: consumes the backfilled sidecars and
    emits chain_candidates + brain_prime_priors using the rescued
    attack_class / workspace / function_anchor.
  - tools/mimo-class-keyword-prefilter.py: shares CLASS_KEYWORD_BAGS
    constant (imported lazily).

USAGE:
  python3 tools/mimo-sidecar-metadata-backfill.py \\
    [--batch-glob '/tmp/mimo_harness_*_batch.jsonl'] \\
    [--sidecar-glob 'audit/corpus_tags/derived/mimo_harness_*/*.json'] \\
    [--dry-run] [--json]

Schema: auditooor.mimo_sidecar_metadata_backfill.v1
"""
from __future__ import annotations

import argparse
import glob
import json
import re
import sys
from datetime import datetime, timezone
from pathlib import Path

SCHEMA = "auditooor.mimo_sidecar_metadata_backfill.v1"
REPO_ROOT = Path(__file__).resolve().parent.parent


def iso_now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


# Same class-keyword bags as the prefilter — extract attack_class from prompt
# r36-rebuttal: kept inline rather than importing across tool boundary so this
# tool is self-contained for forensic backfill use.
CLASS_KEYWORD_BAGS_REVERSE = [
    # (attack_class, regex over prompt)
    ("flashloan", re.compile(r"flash[- ]?loan|onFlashLoan|IERC3156", re.IGNORECASE)),
    ("oracle", re.compile(r"\boracle\b|chainlink|getPrice|latestAnswer|stale.?price", re.IGNORECASE)),
    ("price-manipulation", re.compile(r"price[- ]manipulation|TWAP|twap manipulation", re.IGNORECASE)),
    ("reentrancy", re.compile(r"reentran|nonReentrant|ReentrancyGuard", re.IGNORECASE)),
    ("signature", re.compile(r"\becrecover\b|EIP[-_]?712|EIP[-_]?1271|signature[ ]?(replay|forge)", re.IGNORECASE)),
    ("permit", re.compile(r"EIP[-_]?2612|\bpermit\(|permit signature", re.IGNORECASE)),
    ("uninitialized-impl", re.compile(r"uninitialized[- ]?implementation|_disableInitializers|initializer\(\)", re.IGNORECASE)),
    ("uups", re.compile(r"\bUUPS\b|_authorizeUpgrade|upgradeTo\(", re.IGNORECASE)),
    ("access-control", re.compile(r"access[- ]control|onlyOwner|onlyRole|hasRole|AccessControl", re.IGNORECASE)),
    ("rounding", re.compile(r"rounding|round[- ]?down|round[- ]?up|integer division|mulDiv", re.IGNORECASE)),
    ("overflow", re.compile(r"overflow|underflow|SafeMath|\bunchecked\b", re.IGNORECASE)),
    ("decimals", re.compile(r"decimal[s ]?mismatch|10\*\*|decimal precision", re.IGNORECASE)),
    ("liquidation", re.compile(r"liquidat|seize.*collateral|absorb", re.IGNORECASE)),
    ("lending", re.compile(r"borrow|repay|collateral.*ratio|LTV|debt.*ratio", re.IGNORECASE)),
    ("bridge", re.compile(r"\bbridge\b|cross[- ]chain|relay\b|message passing", re.IGNORECASE)),
    ("replay", re.compile(r"\breplay\b|nonce.*reuse|signature replay|processed.?hashes", re.IGNORECASE)),
    ("merkle", re.compile(r"merkle|MerkleProof|merkle root", re.IGNORECASE)),
    ("light-client", re.compile(r"light[- ]?client|light client verification|header validation", re.IGNORECASE)),
    ("threshold-sig", re.compile(r"threshold[- ]?sig|FROST|shamir|partial signature", re.IGNORECASE)),
    ("dkg", re.compile(r"\bDKG\b|distributed key|key generation", re.IGNORECASE)),
    ("key-rotation", re.compile(r"key[- ]rotation|resharing|key reshare", re.IGNORECASE)),
    ("mpc", re.compile(r"\bMPC\b|multi[- ]party computation|threshold.*party", re.IGNORECASE)),
    ("delegatecall", re.compile(r"\bdelegatecall\b|delegate[- ]?call", re.IGNORECASE)),
    ("front-running", re.compile(r"front[- ]run|MEV|sandwich|deadline.*missing|missing.*deadline", re.IGNORECASE)),
    ("slippage", re.compile(r"slippage|minOut|minAmountOut|maxIn", re.IGNORECASE)),
    ("denial-of-service", re.compile(r"\bDoS\b|denial[- ]of[- ]service|unbounded loop|gas griefing", re.IGNORECASE)),
    ("storage-collision", re.compile(r"storage[- ]collision|storage slot|sstore.*sload|eternal storage", re.IGNORECASE)),
    ("fee-on-transfer", re.compile(r"fee[- ]on[- ]transfer|deflationary token|rebase token", re.IGNORECASE)),
    ("wasm-host", re.compile(r"wasm|host function|memory bound", re.IGNORECASE)),
    ("callback", re.compile(r"\bcallback\b|onERC721|onERC1155|tokensReceived", re.IGNORECASE)),
]


def extract_attack_class(prompt: str, source_question_id: str) -> str:
    """Best-effort attack_class extraction from the hypothesis text."""
    # First-pass: the hypothesis block (everything between
    # 'HYPOTHESIS' and '=== PROJECT CONTEXT' usually carries the keyword.
    m = re.search(r"HYPOTHESIS\s*\(source:[^)]+\):\s*(.*?)===\s*PROJECT CONTEXT",
                  prompt, re.DOTALL)
    hypothesis = m.group(1) if m else prompt[:2000]
    for klass, pat in CLASS_KEYWORD_BAGS_REVERSE:
        if pat.search(hypothesis):
            return klass
    # Fallback: scan whole prompt
    for klass, pat in CLASS_KEYWORD_BAGS_REVERSE:
        if pat.search(prompt[:4000]):
            return klass
    # Last resort: use source_question_id slug (e.g., hacker_q_expand_01299-0)
    return source_question_id.split("-")[0] if source_question_id else "generic"


def extract_function_anchor(prompt: str) -> dict | None:
    """Pull file:line from the prompt context block, if present."""
    # Match patterns like "src/contracts/Foo.sol:123" or "file: foo.sol line 42"
    file_line = re.search(r"\b([a-zA-Z0-9_/.-]+\.(?:sol|rs|go|ts|move|cairo|js)):(\d+)",
                          prompt[:6000])
    if file_line:
        return {"file": file_line.group(1), "line_start": int(file_line.group(2))}
    return None


def build_batch_index(batch_paths: list[Path]) -> dict:
    """task_id -> {workspace, source_question_id, attack_class, function_anchor}."""
    idx = {}
    for bp in batch_paths:
        try:
            with bp.open() as fh:
                for line in fh:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        t = json.loads(line)
                    except json.JSONDecodeError:
                        continue
                    tid = t.get("task_id")
                    if not tid:
                        continue
                    prompt = t.get("prompt", "")
                    sqid = t.get("source_question_id", "")
                    idx[tid] = {
                        "workspace": t.get("workspace", ""),
                        "workspace_path": t.get("workspace_path", ""),
                        "source_question_id": sqid,
                        "attack_class": extract_attack_class(prompt, sqid),
                        "function_anchor": extract_function_anchor(prompt),
                        "task_type": t.get("task_type", ""),
                        "_source_batch": bp.name,
                    }
        except OSError as e:
            sys.stderr.write(f"[backfill] skip {bp}: {e}\n")
    return idx


def backfill_sidecar(sidecar_path: Path, meta: dict, dry_run: bool) -> str:
    """Merge metadata into sidecar JSON (additive). Returns action label."""
    try:
        d = json.loads(sidecar_path.read_text(encoding="utf-8"))
    except Exception:
        return "parse_error"
    # Detect whether already backfilled (idempotent)
    if d.get("_backfilled_at_utc"):
        return "already_backfilled"
    # Add missing fields (do NOT overwrite if they exist)
    added = []
    for k in ("workspace", "workspace_path", "source_question_id",
              "task_type", "function_anchor"):
        if k not in d and meta.get(k) is not None:
            d[k] = meta[k]
            added.append(k)
    # attack_class is special: stored in a top-level field for miner consumption
    if "attack_class" not in d and meta.get("attack_class"):
        d["attack_class"] = meta["attack_class"]
        added.append("attack_class")
    if not added:
        return "no_new_fields"
    d["_backfilled_at_utc"] = iso_now()
    d["_backfill_source_batch"] = meta.get("_source_batch", "?")
    d["_backfill_fields_added"] = added
    if dry_run:
        return f"would_add[{','.join(added)}]"
    try:
        sidecar_path.write_text(json.dumps(d, indent=2 if len(d) < 30 else None))
        return f"backfilled[{','.join(added)}]"
    except OSError as e:
        return f"write_error: {e}"


def main(argv: list[str]) -> int:
    p = argparse.ArgumentParser()
    p.add_argument("--batch-glob", default="/tmp/mimo_harness_*_batch.jsonl")
    p.add_argument("--sidecar-glob",
                   default=str(REPO_ROOT / "audit/corpus_tags/derived/mimo_harness_*/*.json"))
    p.add_argument("--dry-run", action="store_true")
    p.add_argument("--json", action="store_true")
    args = p.parse_args(argv)

    batch_paths = [Path(b) for b in sorted(glob.glob(args.batch_glob))]
    sys.stderr.write(f"[backfill] found {len(batch_paths)} batch files\n")
    if not batch_paths:
        sys.stderr.write(f"[backfill] no batch files match {args.batch_glob}\n")
        return 2

    idx = build_batch_index(batch_paths)
    sys.stderr.write(f"[backfill] built task_id index: {len(idx)} entries\n")
    # Per-attack-class histogram on the index for sanity
    from collections import Counter
    class_hist = Counter(v.get("attack_class", "?") for v in idx.values())
    sys.stderr.write(f"[backfill] attack_class distribution in batch: "
                     f"{class_hist.most_common(10)}\n")

    sidecars = sorted(glob.glob(args.sidecar_glob))
    sys.stderr.write(f"[backfill] {len(sidecars)} sidecars to scan\n")

    action_counts = Counter()
    matched_no_meta = 0
    for sc in sidecars:
        sc_path = Path(sc)
        try:
            d = json.loads(sc_path.read_text(encoding="utf-8"))
        except Exception:
            action_counts["parse_error"] += 1
            continue
        tid = d.get("task_id")
        if not tid:
            action_counts["no_task_id"] += 1
            continue
        meta = idx.get(tid)
        if not meta:
            matched_no_meta += 1
            action_counts["no_batch_meta"] += 1
            continue
        action = backfill_sidecar(sc_path, meta, args.dry_run)
        # Bucket actions
        if action.startswith("backfilled") or action.startswith("would_add"):
            action_counts["backfilled"] += 1
        else:
            action_counts[action] += 1

    summary = {
        "schema_version": SCHEMA,
        "generated_at_utc": iso_now(),
        "dry_run": args.dry_run,
        "batch_files": len(batch_paths),
        "batch_task_index_size": len(idx),
        "sidecars_scanned": len(sidecars),
        "actions": dict(action_counts),
        "attack_class_top10_in_batch": class_hist.most_common(10),
        "matched_no_meta": matched_no_meta,
    }
    if args.json:
        print(json.dumps(summary, indent=2))
    else:
        print(f"Batch files: {len(batch_paths)}")
        print(f"Task index size: {len(idx)}")
        print(f"Sidecars scanned: {len(sidecars)}")
        print("Actions:")
        for k, v in sorted(action_counts.items(), key=lambda x: -x[1]):
            print(f"  {k}: {v}")
        print("Top 10 attack_class in batch:")
        for k, v in class_hist.most_common(10):
            print(f"  {k}: {v}")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
