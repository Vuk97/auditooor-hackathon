#!/usr/bin/env python3
"""LLM sweep tool for P1 invariant library - CAP-015 semantic fix.

Reads invariants_extracted.jsonl (heuristic-template statements) and
generates semantically-specific MUST/MUST-NOT statements using claude-haiku-4-5.

Usage:
    python3 tools/llm-sweep-invariants-mvp.py --cohort-size 500 \
        --output audit/corpus_tags/derived/invariants_extracted_llm_v1.jsonl \
        --report reports/v3_iter_2026-05-24/lane_P1_LLM_SWEEP_MVP/sweep_log.jsonl

Rule 37: every emitted record carries verification_tier from source record.
Hard $-cap: $5 (stops before exceeding).
"""
from __future__ import annotations

import argparse
import datetime as _dt
import importlib.util
import json
import os
import random
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parent.parent
DEFAULT_INPUT = REPO_ROOT / "audit" / "corpus_tags" / "derived" / "invariants_extracted.jsonl"
DEFAULT_OUTPUT = REPO_ROOT / "audit" / "corpus_tags" / "derived" / "invariants_extracted_llm_v1.jsonl"
DEFAULT_LOG = REPO_ROOT / "reports" / "v3_iter_2026-05-24" / "lane_P1_LLM_SWEEP_MVP" / "sweep_log.jsonl"

# Haiku pricing (claude-haiku-4-5)
# Input: $0.80/MTok, Output: $4.00/MTok
PRICE_INPUT_PER_TOK = 0.80 / 1_000_000
PRICE_OUTPUT_PER_TOK = 4.00 / 1_000_000

HARD_SPEND_CAP_USD = 5.0
MIN_PROMOTION_Y_RATE = 0.90

CATEGORIES_10 = [
    "uniqueness", "ordering", "monotonicity", "custody", "atomicity",
    "conservation", "authorization", "freshness", "bounds", "determinism",
]


def _load_extractor_module() -> Any:
    path = REPO_ROOT / "tools" / "llm-extract-invariants.py"
    spec = importlib.util.spec_from_file_location("llm_extract_invariants_shared", path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"unable to load extractor module from {path}")
    module = importlib.util.module_from_spec(spec)
    sys.modules.setdefault("llm_extract_invariants_shared", module)
    spec.loader.exec_module(module)
    return module


EXTRACTOR = _load_extractor_module()

SYSTEM_PROMPT = """You are a security protocol invariant specialist. Your task is to write precise, semantic MUST/MUST-NOT invariant statements from smart-contract and blockchain security findings.

Rules:
1. Output ONLY a JSON object with exactly these fields: {"statement": "...", "commit_point_pattern": "...", "defense_layer": "..."}
2. The statement MUST start with "A ", "An ", "Every ", "No " or the subject name, and contain MUST or MUST-NOT.
3. Make the statement SPECIFIC to the attack pattern described - not generic. Include the actual mechanism (e.g. "permit-frontrun", "flash-loan readonly reentrancy", "EIP-712 domain separator", etc.).
4. commit_point_pattern: a short code/keyword pattern (10-60 chars) that marks the commit point where the invariant must hold.
5. defense_layer: a short description (10-80 chars) of the defense mechanism.
6. Do NOT include protocol names or specific project names - keep domain-neutral but mechanism-specific.
7. Max statement length: 200 characters."""

def get_api_key() -> str:
    """Get API key from environment.

    Keep this aligned with the shared LLM preflight surfaces while preserving
    the older ANTHROPIC_TOKEN compatibility path.
    """
    key = os.environ.get("ANTHROPIC_API_KEY", "").strip()
    if not key:
        key = os.environ.get("ANTHROPIC_AUTH_TOKEN", "").strip()
    if not key:
        key = os.environ.get("ANTHROPIC_TOKEN", "").strip()
    return key


def call_haiku(prompt: str, api_key: str, max_retries: int = 3) -> tuple[str, int, int]:
    """Call claude-haiku-4-5. Returns (response_text, input_tokens, output_tokens)."""
    payload = json.dumps({
        "model": "claude-haiku-4-5",
        "max_tokens": 300,
        "messages": [{"role": "user", "content": prompt}],
        "system": SYSTEM_PROMPT,
        "temperature": 0.3,
    }).encode("utf-8")

    # Try x-api-key first, then Bearer
    auth_headers = [
        {"x-api-key": api_key},
        {"Authorization": f"Bearer {api_key}"},
    ]

    for auth_h in auth_headers:
        headers = {
            "anthropic-version": "2023-06-01",
            "content-type": "application/json",
        }
        headers.update(auth_h)

        for attempt in range(max_retries):
            req = urllib.request.Request(
                "https://api.anthropic.com/v1/messages",
                data=payload,
                headers=headers,
            )
            try:
                with urllib.request.urlopen(req, timeout=30) as resp:
                    data = json.loads(resp.read())
                    text = data.get("content", [{}])[0].get("text", "")
                    usage = data.get("usage", {})
                    in_tok = usage.get("input_tokens", 0)
                    out_tok = usage.get("output_tokens", 0)
                    return text, in_tok, out_tok
            except urllib.error.HTTPError as e:
                body = e.read().decode("utf-8")
                if e.code == 401:
                    break  # Try next auth header
                if e.code == 429:
                    wait = min(30, 5 * (2 ** attempt))
                    time.sleep(wait)
                    continue
                if e.code >= 500:
                    time.sleep(5 * (attempt + 1))
                    continue
                raise RuntimeError(f"API error {e.code}: {body[:200]}")
            except Exception as ex:
                if attempt == max_retries - 1:
                    raise
                time.sleep(5)

    raise RuntimeError("All auth methods exhausted")


def build_prompt(entry: dict[str, Any]) -> str:
    """Build a prompt from entry fields."""
    cat = entry.get("category", "")
    sig = entry.get("attack_signature", "")
    src_ids = entry.get("source_finding_ids", [])
    current_stmt = entry.get("statement", "")
    target_lang = entry.get("target_lang", "any")
    verification_tier = entry.get("verification_tier", "")
    source_count = entry.get("source_count", 0)

    # Parse attack_signature: attack_type|bug_class|repo_slug
    sig_parts = sig.split("|")
    attack_type = sig_parts[0] if sig_parts else ""
    bug_class = sig_parts[1] if len(sig_parts) > 1 else ""
    repo_slug = sig_parts[2] if len(sig_parts) > 2 else ""

    # Sample source IDs for context
    src_sample = src_ids[:4] if src_ids else []

    lines = [
        f"Category: {cat}",
        f"Attack type: {attack_type}",
        f"Bug class: {bug_class}",
        f"Context/repo: {repo_slug[:50]}",
        f"Target language: {target_lang}",
        f"Source findings count: {source_count}",
    ]
    if src_sample:
        lines.append(f"Source IDs (sample): {', '.join(str(s)[:60] for s in src_sample)}")
    lines.append(f"Current generic statement: {current_stmt}")
    lines.append("")
    lines.append(
        f"Write a SEMANTICALLY SPECIFIC statement for this '{cat}' invariant "
        f"that captures the specific mechanism '{attack_type}' / '{bug_class}'. "
        f"The current statement is too generic - improve it."
    )

    return "\n".join(lines)


def parse_llm_response(text: str, entry: dict[str, Any]) -> dict[str, Any] | None:
    """Parse LLM JSON response. Returns None if unparseable."""
    # Try to extract JSON from response
    text = text.strip()
    # Find JSON object
    start = text.find("{")
    end = text.rfind("}") + 1
    if start == -1 or end <= start:
        return None
    try:
        parsed = json.loads(text[start:end])
    except json.JSONDecodeError:
        return None

    stmt = str(parsed.get("statement", "")).strip()
    if not stmt or len(stmt) < 20:
        return None
    if "MUST" not in stmt.upper():
        return None

    commit_pt = str(parsed.get("commit_point_pattern", "")).strip()
    defense_l = str(parsed.get("defense_layer", "")).strip()

    if not commit_pt:
        commit_pt = entry.get("commit_point_pattern", "")
    if not defense_l:
        defense_l = entry.get("defense_layer", "")

    return {
        "statement": stmt,
        "commit_point_pattern": commit_pt,
        "defense_layer": defense_l,
    }


def spot_check_entry(entry: dict[str, Any]) -> tuple[bool, list[str]]:
    """Quality check shared with the invariant extractor path."""
    return EXTRACTOR.spot_check_entry(entry)


def run_spot_check_on_entries(entries: list[dict[str, Any]], sample_size: int, seed: int = 42) -> dict[str, Any]:
    return EXTRACTOR.run_spot_check(entries, sample_size, seed=seed)


def evaluate_paid_sweep_gate(
    entries: list[dict[str, Any]],
    sample_size: int,
    *,
    seed: int = 42,
    min_y_rate: float = MIN_PROMOTION_Y_RATE,
) -> dict[str, Any]:
    return EXTRACTOR.evaluate_spot_check_gate(
        entries,
        sample_size,
        seed=seed,
        min_y_rate=min_y_rate,
        disallow_template_or_broad=True,
    )


def select_sweep_cohort(
    entries: list[dict[str, Any]],
    requested_cohort_size: int,
    *,
    seed: int = 42,
) -> tuple[list[dict[str, Any]], dict[str, list[dict[str, Any]]], str]:
    """Select the paid-sweep cohort and preserve full-input runs exactly."""
    if not entries:
        return [], {}, "empty"
    rng = random.Random(seed)
    cohort_size = min(requested_cohort_size, len(entries))
    by_cat: dict[str, list[dict[str, Any]]] = {}
    for entry in entries:
        cat = entry.get("category", "unknown")
        by_cat.setdefault(cat, []).append(entry)
    if cohort_size >= len(entries):
        return list(entries), by_cat, "full input"

    per_cat = max(1, cohort_size // len(by_cat))
    cohort: list[dict[str, Any]] = []
    for cat_entries in by_cat.values():
        sample = rng.sample(cat_entries, min(per_cat, len(cat_entries)))
        cohort.extend(sample)
    rng.shuffle(cohort)
    return cohort[:cohort_size], by_cat, f"{per_cat} per cat"


def main() -> int:
    parser = argparse.ArgumentParser(description="LLM sweep for P1 invariant library (CAP-015 fix)")
    parser.add_argument("--cohort-size", type=int, default=500, help="Number of entries to sweep")
    parser.add_argument("--input", default=str(DEFAULT_INPUT), help="Input JSONL")
    parser.add_argument("--output", default=str(DEFAULT_OUTPUT), help="Output JSONL (sibling, not overwrite)")
    parser.add_argument("--log", default=str(DEFAULT_LOG), help="Per-call log JSONL")
    parser.add_argument("--seed", type=int, default=42, help="Random seed for sampling")
    parser.add_argument("--dry-run", action="store_true", help="Skip actual API calls, sample only")
    parser.add_argument("--spot-check-before", type=int, default=30, help="Spot-check sample size before sweep")
    parser.add_argument("--spot-check-after", type=int, default=30, help="Spot-check sample size after sweep")
    parser.add_argument("--min-promotion-y-rate", type=float, default=MIN_PROMOTION_Y_RATE, help="Minimum post-sweep Y-rate required for promotion")
    parser.add_argument("--max-spend-usd", type=float, default=HARD_SPEND_CAP_USD, help="Hard spend cap in USD")
    args = parser.parse_args()

    api_key = get_api_key()
    if not api_key and not args.dry_run:
        print("ERROR: No API key found (ANTHROPIC_API_KEY or ANTHROPIC_TOKEN)", file=sys.stderr)
        return 1

    input_path = Path(args.input)
    output_path = Path(args.output)
    log_path = Path(args.log)
    log_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.parent.mkdir(parents=True, exist_ok=True)

    # Load existing entries
    entries: list[dict[str, Any]] = []
    with input_path.open(encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                entries.append(json.loads(line))
            except json.JSONDecodeError:
                pass

    print(f"Loaded {len(entries)} entries from {input_path}")

    # BEFORE spot-check
    before_check = run_spot_check_on_entries(entries, args.spot_check_before, seed=args.seed)
    print(f"BEFORE spot-check: Y-rate={before_check['y_rate']:.1%} ({before_check['y_count']}/{before_check['sample_size']})")
    print(f"  Fail reasons: {before_check['fail_reasons']}")

    cohort, by_cat, cohort_mode = select_sweep_cohort(entries, args.cohort_size, seed=args.seed)
    print(f"Cohort: {len(cohort)} entries across {len(by_cat)} categories ({cohort_mode})")

    if args.dry_run:
        print("DRY RUN: skipping API calls")
        return 0

    # Run sweep
    total_spend_usd = 0.0
    total_input_tok = 0
    total_output_tok = 0
    swept_entries: list[dict[str, Any]] = []
    failed_count = 0
    log_rows: list[dict[str, Any]] = []

    print(f"\nStarting sweep... hard cap ${args.max_spend_usd}")

    for i, entry in enumerate(cohort):
        if total_spend_usd >= args.max_spend_usd:
            print(f"\nHard spend cap hit at ${total_spend_usd:.4f} after {i} entries")
            break

        prompt = build_prompt(entry)

        try:
            text, in_tok, out_tok = call_haiku(prompt, api_key)
            cost = in_tok * PRICE_INPUT_PER_TOK + out_tok * PRICE_OUTPUT_PER_TOK
            total_spend_usd += cost
            total_input_tok += in_tok
            total_output_tok += out_tok

            parsed = parse_llm_response(text, entry)

            if parsed:
                new_entry = dict(entry)
                old_stmt = new_entry.get("statement", "")
                new_entry["statement"] = parsed["statement"]
                new_entry["commit_point_pattern"] = parsed["commit_point_pattern"]
                new_entry["defense_layer"] = parsed["defense_layer"]
                new_entry["schema_version"] = EXTRACTOR.SCHEMA_VERSION
                new_entry["extractor"] = "llm-sweep"
                new_entry["llm_model"] = "claude-haiku-4-5"
                new_entry["llm_sweep_at_utc"] = _dt.datetime.now(_dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
                swept_entries.append(new_entry)

                log_rows.append({
                    "invariant_id": entry.get("invariant_id"),
                    "category": entry.get("category"),
                    "attack_signature": entry.get("attack_signature", "")[:80],
                    "old_statement": old_stmt[:120],
                    "new_statement": parsed["statement"][:120],
                    "in_tok": in_tok,
                    "out_tok": out_tok,
                    "cost_usd": round(cost, 6),
                    "status": "ok",
                })
            else:
                failed_count += 1
                log_rows.append({
                    "invariant_id": entry.get("invariant_id"),
                    "category": entry.get("category"),
                    "raw_response": text[:200],
                    "status": "parse_failed",
                    "in_tok": in_tok,
                    "out_tok": out_tok,
                    "cost_usd": round(cost, 6),
                })

        except Exception as ex:
            failed_count += 1
            log_rows.append({
                "invariant_id": entry.get("invariant_id"),
                "category": entry.get("category"),
                "error": str(ex)[:200],
                "status": "error",
            })

        # Progress
        if (i + 1) % 50 == 0:
            print(f"  [{i+1}/{len(cohort)}] spend=${total_spend_usd:.4f} ok={len(swept_entries)} fail={failed_count}")

    print(f"\nSweep complete: {len(swept_entries)} ok, {failed_count} failed")
    print(f"Total spend: ${total_spend_usd:.4f} ({total_input_tok} in-tok, {total_output_tok} out-tok)")

    # Write output JSONL (sibling file, not overwrite)
    with output_path.open("w", encoding="utf-8") as f:
        for e in swept_entries:
            f.write(json.dumps(e, sort_keys=True))
            f.write("\n")
    print(f"Output written: {output_path} ({len(swept_entries)} entries)")

    # Write log
    with log_path.open("w", encoding="utf-8") as f:
        for row in log_rows:
            f.write(json.dumps(row, sort_keys=True))
            f.write("\n")
    print(f"Log written: {log_path} ({len(log_rows)} rows)")

    # AFTER spot-check
    after_check = evaluate_paid_sweep_gate(
        swept_entries,
        args.spot_check_after,
        seed=args.seed,
        min_y_rate=args.min_promotion_y_rate,
    )
    print(f"\nAFTER spot-check: Y-rate={after_check['y_rate']:.1%} ({after_check['y_count']}/{after_check['sample_size']})")
    print(f"  Fail reasons: {after_check['fail_reasons']}")
    print(f"  Promotion allowed: {after_check['promotion_allowed']} blockers={after_check['promotion_blockers']}")

    # Summary
    summary = {
        "provider": "anthropic claude-haiku-4-5",
        "auth": "Bearer",
        "cohort_size": len(cohort),
        "swept_ok": len(swept_entries),
        "swept_failed": failed_count,
        "total_spend_usd": round(total_spend_usd, 4),
        "total_input_tokens": total_input_tok,
        "total_output_tokens": total_output_tok,
        "before_spot_check": before_check,
        "after_spot_check": after_check,
        "tp_rate_before": before_check["y_rate"],
        "tp_rate_after": after_check["y_rate"],
        "min_promotion_y_rate": args.min_promotion_y_rate,
        "promotion_allowed": after_check["promotion_allowed"],
        "promotion_blockers": after_check["promotion_blockers"],
        "cap_015_verdict": "SWEEP-SUCCESS" if after_check["promotion_allowed"] else "SWEEP-FAILED",
    }

    summary_path = log_path.parent / "sweep_summary.json"
    with summary_path.open("w", encoding="utf-8") as f:
        json.dump(summary, f, indent=2)
    print(f"Summary: {summary_path}")
    print(f"Verdict: {summary['cap_015_verdict']}")

    return 0


if __name__ == "__main__":
    sys.exit(main())
