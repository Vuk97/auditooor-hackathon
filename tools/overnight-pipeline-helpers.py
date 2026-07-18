#!/usr/bin/env python3
"""overnight-pipeline-helpers.py — Phase 2/3/4/5 helpers for overnight-pipeline.sh.

Phase 2 (--mode promote-tier-e):
  Read Minimax adversarial-review JSONs (tier_e_*.json) from <reviews-dir>,
  update detectors/_tier_registry.yaml in-place: tier='E' rows where the
  review verdict is promote_to_B / hold_E / demote_to_D / demote_to_C.
  Emit a JSON summary of changes.

Phase 3 (--mode build-phase3-queue):
  Read newly-extracted DSL YAMLs (catalog_dsl_*.yaml) from <catalog-dsl-dir>,
  emit a JSONL queue of Kimi tasks asking for clean+vulnerable Solidity
  fixture pair + Slither-compatible detector spec for each. Same shape as
  the catalog→DSL→fixture pipeline already running.

Phase 4 (--mode build-phase4-queue):
  Read fixture-pair JSONs (dsl_to_fixture_*.json AND phase3_fixture_*.json)
  from <fixture-dir>, emit a JSONL queue of Minimax adversarial-review tasks
  for each. Same shape as the existing tier-E review pipeline but applied
  to NEW fixture pairs.

Phase 5 (--mode promote-phase4):
  Read phase4 review JSONs, register the surviving (promote_to_B+) DSL
  patterns into the tier registry as new Tier-B detectors. Emit summary.

All operations are idempotent + atomic-ish (write to .tmp, move).
"""
from __future__ import annotations

import argparse
import datetime
import json
import re
import sys
import textwrap
from pathlib import Path

import yaml

REPO = Path(__file__).resolve().parents[1]
TIER_REGISTRY = REPO / "detectors" / "_tier_registry.yaml"


def _slug(s: str) -> str:
    return re.sub(r"[^a-z0-9]+", "-", s.lower()).strip("-")[:80]


_FENCE_RE = re.compile(r"^\s*```(?:json|JSON)?\s*\n(.*?)\n\s*```\s*$", re.DOTALL)


def _load_json_strip_fences(path: Path):
    """json.loads but tolerant of LLM ```json fences and leading/trailing prose."""
    raw = path.read_text(encoding="utf-8").strip()
    # Direct parse first.
    try:
        return json.loads(raw)
    except json.JSONDecodeError:
        pass
    # Strip ```json ... ``` fences.
    m = _FENCE_RE.match(raw)
    if m:
        try:
            return json.loads(m.group(1))
        except json.JSONDecodeError:
            pass
    # Last resort: extract widest {...} or [...] span.
    for opener, closer in [("{", "}"), ("[", "]")]:
        i = raw.find(opener)
        j = raw.rfind(closer)
        if i >= 0 and j > i:
            try:
                return json.loads(raw[i : j + 1])
            except json.JSONDecodeError:
                continue
    raise json.JSONDecodeError(f"could not parse {path}", raw, 0)


def _load_registry() -> dict:
    with TIER_REGISTRY.open() as f:
        return yaml.safe_load(f)


def _save_registry(reg: dict) -> None:
    tmp = TIER_REGISTRY.with_suffix(".yaml.tmp")
    with tmp.open("w") as f:
        yaml.safe_dump(reg, f, default_flow_style=False, sort_keys=False)
    tmp.replace(TIER_REGISTRY)


# ---------------------------------------------------------------------------
# Phase 2: auto-promote existing Tier-E based on Minimax verdicts
# ---------------------------------------------------------------------------

def promote_tier_e(reviews_dir: Path, summary_out: Path) -> int:
    reg = _load_registry()
    promotions: list[dict] = []
    review_files = sorted(reviews_dir.glob("tier_e_*.json"))

    for rf in review_files:
        try:
            review = _load_json_strip_fences(rf)
        except json.JSONDecodeError:
            continue
        if not isinstance(review, dict):
            continue
        det_id = review.get("detector_id")
        verdict = review.get("verdict")
        if not det_id or not verdict:
            continue
        entry = reg.get("tiers", {}).get(det_id)
        if not entry or entry.get("tier") != "E":
            continue

        before_tier = entry.get("tier")
        new_tier = before_tier
        if verdict == "promote_to_B":
            new_tier = "B"
        elif verdict == "demote_to_D":
            new_tier = "D"
        elif verdict == "demote_to_C":
            new_tier = "C"
        elif verdict == "hold_E":
            new_tier = "E"
        else:
            continue

        if new_tier == before_tier:
            continue

        entry["tier"] = new_tier
        entry["last_promoted"] = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%d")
        existing_reason = entry.get("reason", "")
        precision = review.get("precision_estimate", "n/a")
        rationale = review.get("rationale", "")[:240]
        entry["reason"] = f"auto-promote {before_tier}→{new_tier} (Minimax review precision={precision}; {rationale})"
        promotions.append({
            "detector_id": det_id,
            "tier_before": before_tier,
            "tier_after": new_tier,
            "verdict": verdict,
            "precision_estimate": precision,
            "review_file": str(rf),
        })

    if promotions:
        _save_registry(reg)

    summary = {
        "schema": "auditooor.overnight.tier_promotion.v1",
        "ran_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "reviews_dir": str(reviews_dir),
        "reviews_processed": len(review_files),
        "promotions": promotions,
        "promotion_count": len(promotions),
        "by_action": {
            "promote_to_B": sum(1 for p in promotions if p["verdict"] == "promote_to_B"),
            "demote_to_D": sum(1 for p in promotions if p["verdict"] == "demote_to_D"),
            "demote_to_C": sum(1 for p in promotions if p["verdict"] == "demote_to_C"),
        },
    }
    summary_out.write_text(json.dumps(summary, indent=2), encoding="utf-8")
    return 0


# ---------------------------------------------------------------------------
# Phase 3: build queue for DSL → fixture-pair generation
# ---------------------------------------------------------------------------

def build_phase3_queue(catalog_dsl_dir: Path, queue_out: Path, work_dir: Path) -> int:
    yaml_files = sorted(catalog_dsl_dir.glob("catalog_dsl_*.yaml"))
    queue_out.parent.mkdir(parents=True, exist_ok=True)
    prompts_dir = work_dir / "phase3_prompts"
    outputs_dir = work_dir / "phase3_outputs"
    prompts_dir.mkdir(parents=True, exist_ok=True)
    outputs_dir.mkdir(parents=True, exist_ok=True)

    tasks: list[dict] = []
    for yf in yaml_files:
        try:
            spec = yaml.safe_load(yf.read_text(encoding="utf-8"))
        except Exception:
            continue
        if not spec or not isinstance(spec, dict):
            continue
        if spec.get("language") not in (None, "solidity"):
            continue  # Phase 3 focuses on Solidity (Slither-compatible)
        slug = _slug(spec.get("id", yf.stem))
        spec_text = yf.read_text(encoding="utf-8")[:6000]

        prompt = textwrap.dedent(f"""\
            You are converting a structured Solidity bug-pattern DSL spec into
            a Foundry-runnable fixture pair AND Slither-compatible detector
            specification, suitable for our automated tier-promotion pipeline.

            === DSL SPEC START ===
            {spec_text}
            === DSL SPEC END ===

            OUTPUT FORMAT — STRICT:
            Return ONLY a single JSON object. No markdown fence. No prose.
            Begin with `{{` and end with `}}`. Required fields:

              "spec_id": "{slug}"
              "fixture_pair_clean_sol": "<full Solidity 0.8.x source string,
                ~50–150 LOC, self-contained, NO external imports. Should NOT
                trigger the bug pattern. Use bare interface stubs only.>"
              "fixture_pair_vulnerable_sol": "<full Solidity 0.8.x source
                string, same shape as clean but exhibiting the exact bug.
                Should compile under solc 0.8.20+.>"
              "fixture_discriminator_explanation": "<2–3 sentence summary of
                what changed.>"
              "detector_spec": {{
                "pattern_id": "<kebab-case>",
                "slither_or_dsl": "slither" or "ast-grep" or "regex",
                "detector_indicators": ["<specific>", "<specific>"],
                "expected_clean_hits": 0,
                "expected_vulnerable_hits_min": 1,
                "expected_vulnerable_hits_max": 5,
                "false_positive_avoidance_notes": "<short>"
              }}

            Constraints:
            - Both .sol files must be self-contained AND compile.
            - The detector should fire ONLY on the bug pattern, not on
              syntactically similar but semantically different code.
            - Do NOT use OpenZeppelin or external imports. Use minimal
              inline interface stubs.
            - All Solidity strings must be valid JSON-escaped (newlines as
              \\n, double-quotes as \\"). Triple-quote NOT permitted in JSON.
            """).strip()

        prompt_path = prompts_dir / f"phase3_fixture_{slug}.txt"
        output_path = outputs_dir / f"phase3_fixture_{slug}.json"
        prompt_path.write_text(prompt, encoding="utf-8")

        tasks.append({
            "task_id": f"phase3-fixture-{slug}",
            "provider": "kimi",
            "task_type": "fixture-map",
            "prompt_path": str(prompt_path),
            "output_path": str(output_path),
            "max_tokens": 8000,
        })

    with queue_out.open("w") as f:
        for t in tasks:
            f.write(json.dumps(t) + "\n")

    print(f"phase3 queue: {queue_out} tasks={len(tasks)}")
    return 0


# ---------------------------------------------------------------------------
# Phase 4: build queue for adversarial review of new fixture pairs
# ---------------------------------------------------------------------------

def build_phase4_queue(fixture_dir: Path, queue_out: Path, work_dir: Path) -> int:
    fixture_files = sorted(fixture_dir.glob("phase3_fixture_*.json"))
    queue_out.parent.mkdir(parents=True, exist_ok=True)
    prompts_dir = work_dir / "phase4_prompts"
    outputs_dir = work_dir / "phase4_outputs"
    prompts_dir.mkdir(parents=True, exist_ok=True)
    outputs_dir.mkdir(parents=True, exist_ok=True)

    tasks: list[dict] = []
    for ff in fixture_files:
        try:
            blob = _load_json_strip_fences(ff)
        except json.JSONDecodeError:
            continue
        if not isinstance(blob, dict):
            continue
        spec_id = blob.get("spec_id") or ff.stem.replace("phase3_fixture_", "")
        slug = _slug(spec_id)
        clean_sol = blob.get("fixture_pair_clean_sol", "")[:6000]
        vuln_sol = blob.get("fixture_pair_vulnerable_sol", "")[:6000]
        if not clean_sol or not vuln_sol:
            continue

        prompt = textwrap.dedent(f"""\
            ROLE: Hostile detector reviewer. Decide whether the detector
            spec below should be PROMOTED to Tier-B (real signal),
            HELD at Tier-E (ambiguous), or DEMOTED to Tier-D (no signal).

            Detector spec id: {spec_id}
            Detector spec JSON:
            {json.dumps(blob.get("detector_spec", {}), indent=2)[:2000]}

            === CLEAN VARIANT (should NOT trigger) ===
            {clean_sol}

            === VULNERABLE VARIANT (should trigger) ===
            {vuln_sol}

            OUTPUT FORMAT — STRICT:
            Return ONLY a single-line JSON object. No markdown fence. No prose.

              {{"detector_id": "{slug}",
                "verdict": "promote_to_B" or "hold_E" or "demote_to_D",
                "precision_estimate": 0.0..1.0,
                "clean_variant_quality": "good" or "weak" or "broken",
                "vulnerable_variant_quality": "good" or "weak" or "broken",
                "fixture_discriminates_real_bug": true or false,
                "rationale": "<2-3 sentences>",
                "recommended_fixture_additions": ["<short>", "<short>"]}}

            Be strict. Reject fixtures that vary only by comment, naming,
            or trivial syntax. The vulnerable variant MUST exhibit the
            actual bug pattern, not a syntactic placeholder.
            """).strip()

        prompt_path = prompts_dir / f"phase4_review_{slug}.txt"
        output_path = outputs_dir / f"phase4_review_{slug}.json"
        prompt_path.write_text(prompt, encoding="utf-8")

        tasks.append({
            "task_id": f"phase4-review-{slug}",
            "provider": "minimax",
            "task_type": "adversarial-kill",
            "prompt_path": str(prompt_path),
            "output_path": str(output_path),
            "max_tokens": 2500,
        })

    with queue_out.open("w") as f:
        for t in tasks:
            f.write(json.dumps(t) + "\n")
    print(f"phase4 queue: {queue_out} tasks={len(tasks)}")
    return 0


# ---------------------------------------------------------------------------
# Phase 5: register surviving phase4 detectors into tier registry
# ---------------------------------------------------------------------------

def promote_phase4(reviews_dir: Path, summary_out: Path) -> int:
    reg = _load_registry()
    review_files = sorted(reviews_dir.glob("phase4_review_*.json"))
    new_registrations: list[dict] = []
    skips: list[dict] = []

    for rf in review_files:
        try:
            review = _load_json_strip_fences(rf)
        except json.JSONDecodeError:
            skips.append({"file": str(rf), "reason": "invalid-json"})
            continue
        if not isinstance(review, dict):
            skips.append({"file": str(rf), "reason": "not-object"})
            continue
        det_id = review.get("detector_id")
        verdict = review.get("verdict")
        if not det_id or not verdict:
            skips.append({"file": str(rf), "reason": "missing-fields"})
            continue
        if verdict != "promote_to_B":
            skips.append({"file": str(rf), "reason": f"verdict={verdict}"})
            continue
        if det_id in reg.get("tiers", {}):
            skips.append({"file": str(rf), "reason": "id-already-registered"})
            continue

        reg.setdefault("tiers", {})[det_id] = {
            "tier": "B",
            "reason": f"phase4 minimax review precision={review.get('precision_estimate', 'n/a')}; {review.get('rationale', '')[:200]}",
            "waves": ["phase4-overnight"],
            "first_added": datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%d"),
            "last_promoted": datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%d"),
            "fixture_pair": f"phase4-overnight/{det_id}",
        }
        new_registrations.append({
            "detector_id": det_id,
            "tier": "B",
            "precision_estimate": review.get("precision_estimate"),
            "review_file": str(rf),
        })

    if new_registrations:
        _save_registry(reg)

    summary = {
        "schema": "auditooor.overnight.phase5_promotion.v1",
        "ran_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "reviews_dir": str(reviews_dir),
        "reviews_processed": len(review_files),
        "new_registrations": new_registrations,
        "registration_count": len(new_registrations),
        "skipped": skips[:50],  # cap log
        "skipped_count": len(skips),
    }
    summary_out.write_text(json.dumps(summary, indent=2), encoding="utf-8")
    return 0


# ---------------------------------------------------------------------------
# Phase 6: build queue to REWRITE bad (demote_to_D) Tier-E detectors using
# Minimax's recommended_fixture_additions feedback. Rejection-sampling
# loop: rewrite → review → promote-or-confirm-demote.
# ---------------------------------------------------------------------------

def build_phase6_queue(reviews_dir: Path, queue_out: Path, work_dir: Path) -> int:
    review_files = sorted(reviews_dir.glob("tier_e_*.json"))
    queue_out.parent.mkdir(parents=True, exist_ok=True)
    prompts_dir = work_dir / "phase6_prompts"
    outputs_dir = work_dir / "phase6_outputs"
    prompts_dir.mkdir(parents=True, exist_ok=True)
    outputs_dir.mkdir(parents=True, exist_ok=True)

    tasks: list[dict] = []
    reg = _load_registry()

    for rf in review_files:
        try:
            review = _load_json_strip_fences(rf)
        except json.JSONDecodeError:
            continue
        if not isinstance(review, dict):
            continue
        det_id = review.get("detector_id")
        verdict = review.get("verdict")
        if not det_id or verdict != "demote_to_D":
            continue
        # Only rewrite detectors that HAD fixtures (otherwise nothing to rewrite).
        rationale = review.get("rationale", "")
        if "fixtures missing" in rationale.lower() or "<missing>" in rationale.lower():
            continue
        recommendations = review.get("recommended_fixture_additions", [])
        if not recommendations:
            continue
        # Skip if not in registry.
        entry = reg.get("tiers", {}).get(det_id)
        if not entry:
            continue
        slug = _slug(det_id)

        prompt = textwrap.dedent(f"""\
            ROLE: Rewrite a previously-demoted Solidity bug detector + its
            fixture pair using the hostile reviewer's specific feedback.
            GOAL: turn a Tier-D demote into a Tier-B promote by addressing
            the precise weakness called out below.

            Detector ID: {det_id}
            Reviewer's reason for demotion: {rationale[:600]}

            Reviewer's recommended fixture additions:
            {json.dumps(recommendations, indent=2)[:1200]}

            OUTPUT FORMAT — STRICT:
            Return ONLY a single JSON object. No markdown fence. No prose.
            Begin with `{{` and end with `}}`. Required fields:

              "detector_id": "{det_id}"
              "fixture_pair_clean_sol": "<full Solidity 0.8.x source —
                ~80–200 LOC, self-contained, NO external imports. Must
                NOT exhibit the bug. Use bare interface stubs only.>"
              "fixture_pair_vulnerable_sol": "<full Solidity 0.8.x source —
                same shape as clean but exhibiting the EXACT bug pattern.
                Must compile under solc 0.8.20+.>"
              "fixture_discriminator_explanation": "<2–3 sentences naming
                what concretely changed between clean and vulnerable, and
                how that addresses the reviewer's recommendations.>"
              "detector_spec": {{
                "pattern_id": "{slug}",
                "slither_or_dsl": "slither" or "ast-grep" or "regex",
                "detector_indicators": ["<specific indicator>", "<another>"],
                "expected_clean_hits": 0,
                "expected_vulnerable_hits_min": 1,
                "expected_vulnerable_hits_max": 5,
                "false_positive_avoidance_notes": "<what makes this version
                  tighter than the previous>"
              }}
              "improvements_addressed": ["<recommendation 1 -> change made>",
                                          "<recommendation 2 -> change made>"]

            Constraints:
            - Address each recommended_fixture_additions item explicitly.
            - The discriminator must be SEMANTICALLY tied to the bug, not
              superficial (no comment-only or naming-only differences).
            - The vulnerable variant must show realistic bug-ridden code,
              NOT a placeholder or trivial syntactic change.
            - Both .sol files must be self-contained and compile.
            - Indicators must be tighter than the original detector
              (which was demoted for over-fitting / weak signal).
            """).strip()

        prompt_path = prompts_dir / f"phase6_rewrite_{slug}.txt"
        output_path = outputs_dir / f"phase6_rewrite_{slug}.json"
        prompt_path.write_text(prompt, encoding="utf-8")

        tasks.append({
            "task_id": f"phase6-rewrite-{slug}",
            "provider": "kimi",
            "task_type": "fixture-map",
            "prompt_path": str(prompt_path),
            "output_path": str(output_path),
            "max_tokens": 8000,
        })

    with queue_out.open("w") as f:
        for t in tasks:
            f.write(json.dumps(t) + "\n")
    print(f"phase6 queue: {queue_out} tasks={len(tasks)}")
    return 0


# ---------------------------------------------------------------------------
# Phase 6b: review the rewritten detectors with Minimax
# ---------------------------------------------------------------------------

def build_phase6b_queue(rewrites_dir: Path, queue_out: Path, work_dir: Path) -> int:
    rewrites = sorted(rewrites_dir.glob("phase6_rewrite_*.json"))
    queue_out.parent.mkdir(parents=True, exist_ok=True)
    prompts_dir = work_dir / "phase6b_prompts"
    outputs_dir = work_dir / "phase6b_outputs"
    prompts_dir.mkdir(parents=True, exist_ok=True)
    outputs_dir.mkdir(parents=True, exist_ok=True)

    tasks: list[dict] = []
    for rw in rewrites:
        try:
            blob = _load_json_strip_fences(rw)
        except json.JSONDecodeError:
            continue
        det_id = blob.get("detector_id")
        if not det_id:
            continue
        slug = _slug(det_id)
        clean_sol = blob.get("fixture_pair_clean_sol", "")[:6000]
        vuln_sol = blob.get("fixture_pair_vulnerable_sol", "")[:6000]
        if not clean_sol or not vuln_sol:
            continue

        prompt = textwrap.dedent(f"""\
            ROLE: Re-review a previously-demoted detector that has been
            REWRITTEN based on your earlier feedback. Decide if the rewrite
            addressed your concerns enough to PROMOTE_TO_B.

            Detector ID: {det_id}
            Improvements claimed:
            {json.dumps(blob.get("improvements_addressed", []), indent=2)[:1200]}

            === CLEAN VARIANT (should NOT trigger) ===
            {clean_sol}

            === VULNERABLE VARIANT (should trigger) ===
            {vuln_sol}

            OUTPUT FORMAT — STRICT:
            Single-line JSON object. No markdown fence. No prose.

              {{"detector_id": "{slug}",
                "verdict": "promote_to_B" or "hold_E" or "demote_to_D",
                "precision_estimate": 0.0..1.0,
                "improvements_addressed_satisfactorily": true or false,
                "fixture_discriminates_real_bug": true or false,
                "rationale": "<2-3 sentences>",
                "remaining_weaknesses": ["<short>", "<short>"]}}

            Be strict but fair. The rewrite gets credit for addressing
            specific recommendations. If the bug pattern is now correctly
            discriminated by the fixture, promote_to_B is appropriate.
            If superficial changes only, demote_to_D.
            """).strip()

        prompt_path = prompts_dir / f"phase6b_review_{slug}.txt"
        output_path = outputs_dir / f"phase6b_review_{slug}.json"
        prompt_path.write_text(prompt, encoding="utf-8")

        tasks.append({
            "task_id": f"phase6b-review-{slug}",
            "provider": "minimax",
            "task_type": "adversarial-kill",
            "prompt_path": str(prompt_path),
            "output_path": str(output_path),
            "max_tokens": 2000,
        })

    with queue_out.open("w") as f:
        for t in tasks:
            f.write(json.dumps(t) + "\n")
    print(f"phase6b queue: {queue_out} tasks={len(tasks)}")
    return 0


# ---------------------------------------------------------------------------
# Phase 6c: promote rewrites that survived re-review
# ---------------------------------------------------------------------------

def promote_phase6(reviews_dir: Path, summary_out: Path) -> int:
    reg = _load_registry()
    review_files = sorted(reviews_dir.glob("phase6b_review_*.json"))
    promotions: list[dict] = []
    confirms: list[dict] = []

    for rf in review_files:
        try:
            review = _load_json_strip_fences(rf)
        except json.JSONDecodeError:
            continue
        if not isinstance(review, dict):
            continue
        det_id = review.get("detector_id")
        verdict = review.get("verdict")
        if not det_id or not verdict:
            continue

        # Find the original detector by reverse-lookup. Phase 6b uses slug
        # form; original may differ. Try both.
        entry = reg.get("tiers", {}).get(det_id)
        if not entry:
            # Try original form
            for name, e in reg.get("tiers", {}).items():
                if _slug(name) == det_id:
                    det_id = name
                    entry = e
                    break
        if not entry:
            continue

        before_tier = entry.get("tier")
        if verdict == "promote_to_B" and before_tier in ("D", "E"):
            entry["tier"] = "B"
            entry["last_promoted"] = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%d")
            entry["reason"] = (
                f"phase6 rewrite + re-review promote {before_tier}→B "
                f"(precision={review.get('precision_estimate', 'n/a')}; "
                f"{review.get('rationale', '')[:200]})"
            )
            promotions.append({
                "detector_id": det_id,
                "tier_before": before_tier,
                "tier_after": "B",
                "precision_estimate": review.get("precision_estimate"),
                "review_file": str(rf),
            })
        else:
            confirms.append({
                "detector_id": det_id,
                "verdict": verdict,
                "precision_estimate": review.get("precision_estimate"),
            })

    if promotions:
        _save_registry(reg)

    summary = {
        "schema": "auditooor.overnight.phase6_promotion.v1",
        "ran_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "reviews_dir": str(reviews_dir),
        "reviews_processed": len(review_files),
        "promotions": promotions,
        "promotion_count": len(promotions),
        "confirmed_demotions": confirms[:50],
        "confirmed_demotion_count": len(confirms),
    }
    summary_out.write_text(json.dumps(summary, indent=2), encoding="utf-8")
    return 0


# ---------------------------------------------------------------------------
# Phase 7a: build queue for Rust DSL → fixture-pair generation. The 270 Rust
# patterns in reference/patterns.dsl.r94_solodit_*/ have NEVER been compiled
# to runnable Rust detectors. This phase asks Kimi to author cargo-test
# fixture pairs (vulnerable.rs + clean.rs) + tree-sitter-rust query patterns.
# ---------------------------------------------------------------------------

def build_phase7_queue(queue_out: Path, work_dir: Path, max_tasks: int) -> int:
    pattern_dirs = sorted((REPO / "reference").glob("patterns.dsl.r94_solodit_*"))
    yaml_files: list[Path] = []
    for pd in pattern_dirs:
        yaml_files.extend(sorted(pd.glob("*.yaml")))

    queue_out.parent.mkdir(parents=True, exist_ok=True)
    prompts_dir = work_dir / "phase7_prompts"
    outputs_dir = work_dir / "phase7_outputs"
    prompts_dir.mkdir(parents=True, exist_ok=True)
    outputs_dir.mkdir(parents=True, exist_ok=True)

    tasks: list[dict] = []
    enrolled = 0
    for yf in yaml_files:
        if enrolled >= max_tasks:
            break
        try:
            spec = yaml.safe_load(yf.read_text(encoding="utf-8"))
        except Exception:
            continue
        if not spec or spec.get("language") != "rust":
            continue
        slug = _slug(spec.get("id", yf.stem))
        spec_text = yf.read_text(encoding="utf-8")[:6000]
        platform = spec.get("platform", "multi-chain")

        prompt = textwrap.dedent(f"""\
            ROLE: Convert a structured Rust bug-pattern DSL spec into a
            cargo-runnable fixture pair AND tree-sitter-rust query patterns,
            suitable for our Rust detector pipeline (tools/rust-detect.py).

            === DSL SPEC START ===
            {spec_text}
            === DSL SPEC END ===

            Target platform: {platform}

            OUTPUT FORMAT — STRICT:
            Single JSON object. No markdown fence. No prose. Begin with `{{`,
            end with `}}`. Required fields:

              "spec_id": "{slug}"
              "language": "rust"
              "platform": "{platform}"
              "fixture_pair_clean_rs": "<full Rust source —
                ~50–200 LOC, self-contained, NO external crate imports
                except std/alloy/etc that are pinned in Base Cargo.lock.
                Should NOT exhibit the bug pattern. Must compile under
                rustc 1.78+.>"
              "fixture_pair_vulnerable_rs": "<full Rust source —
                same shape as clean but exhibiting the EXACT bug pattern.
                Must compile.>"
              "fixture_discriminator_explanation": "<2–3 sentences>"
              "detector_spec": {{
                "pattern_id": "{slug}",
                "engine": "tree-sitter-rust" or "regex" or "ast-grep",
                "tree_sitter_query": "<S-expression query if engine=tree-sitter-rust, else empty>",
                "regex_indicators": ["<regex 1>", "<regex 2>"],
                "expected_clean_hits": 0,
                "expected_vulnerable_hits_min": 1,
                "false_positive_avoidance_notes": "<short>"
              }}

            Constraints:
            - Use `std`, `alloy_primitives`, `alloy_consensus`, or `serde`
              for imports. AVOID Solana-specific or Substrate-specific
              imports unless the pattern requires them and the platform is
              that ecosystem.
            - All Rust strings must be valid JSON-escaped (\\n for newlines,
              \\" for double-quotes).
            - The detector should fire on the bug pattern, NOT on
              superficially similar code.
            - tree_sitter_query (if used) must be valid s-expression syntax.
            """).strip()

        prompt_path = prompts_dir / f"phase7_rust_fixture_{slug}.txt"
        output_path = outputs_dir / f"phase7_rust_fixture_{slug}.json"
        prompt_path.write_text(prompt, encoding="utf-8")

        tasks.append({
            "task_id": f"phase7-rust-fixture-{slug}",
            "provider": "kimi",
            "task_type": "fixture-map",
            "prompt_path": str(prompt_path),
            "output_path": str(output_path),
            "max_tokens": 8000,
        })
        enrolled += 1

    with queue_out.open("w") as f:
        for t in tasks:
            f.write(json.dumps(t) + "\n")
    print(f"phase7 queue: {queue_out} tasks={len(tasks)}")
    return 0


# ---------------------------------------------------------------------------
# Phase 7b: review the Rust fixture pairs with Minimax
# ---------------------------------------------------------------------------

def build_phase7b_queue(rust_dir: Path, queue_out: Path, work_dir: Path) -> int:
    fixture_files = sorted(rust_dir.glob("phase7_rust_fixture_*.json"))
    queue_out.parent.mkdir(parents=True, exist_ok=True)
    prompts_dir = work_dir / "phase7b_prompts"
    outputs_dir = work_dir / "phase7b_outputs"
    prompts_dir.mkdir(parents=True, exist_ok=True)
    outputs_dir.mkdir(parents=True, exist_ok=True)

    tasks: list[dict] = []
    for ff in fixture_files:
        try:
            blob = _load_json_strip_fences(ff)
        except json.JSONDecodeError:
            continue
        spec_id = blob.get("spec_id") or ff.stem.replace("phase7_rust_fixture_", "")
        slug = _slug(spec_id)
        clean_rs = blob.get("fixture_pair_clean_rs", "")[:6000]
        vuln_rs = blob.get("fixture_pair_vulnerable_rs", "")[:6000]
        if not clean_rs or not vuln_rs:
            continue

        prompt = textwrap.dedent(f"""\
            ROLE: Hostile Rust detector reviewer. Decide if this fixture
            pair + detector spec deserves PROMOTION to Tier-B Rust.

            Detector spec: {json.dumps(blob.get("detector_spec", {}), indent=2)[:1500]}

            === CLEAN VARIANT (should NOT trigger) ===
            {clean_rs}

            === VULNERABLE VARIANT (should trigger) ===
            {vuln_rs}

            OUTPUT FORMAT — STRICT:
            Single-line JSON object. No markdown fence. No prose.

              {{"detector_id": "{slug}",
                "language": "rust",
                "verdict": "promote_to_B" or "hold_E" or "demote_to_D",
                "precision_estimate": 0.0..1.0,
                "fixture_compiles_likely": true or false,
                "fixture_discriminates_real_bug": true or false,
                "tree_sitter_query_valid_syntax": true or false or "n/a",
                "rationale": "<2-3 sentences>",
                "remaining_weaknesses": ["<short>", "<short>"]}}

            Be strict. Reject fixtures with superficial differences,
            non-compiling Rust, malformed tree-sitter queries, or detector
            indicators that would fire on benign code.
            """).strip()

        prompt_path = prompts_dir / f"phase7b_rust_review_{slug}.txt"
        output_path = outputs_dir / f"phase7b_rust_review_{slug}.json"
        prompt_path.write_text(prompt, encoding="utf-8")

        tasks.append({
            "task_id": f"phase7b-rust-review-{slug}",
            "provider": "minimax",
            "task_type": "adversarial-kill",
            "prompt_path": str(prompt_path),
            "output_path": str(output_path),
            "max_tokens": 2000,
        })

    with queue_out.open("w") as f:
        for t in tasks:
            f.write(json.dumps(t) + "\n")
    print(f"phase7b queue: {queue_out} tasks={len(tasks)}")
    return 0


# ---------------------------------------------------------------------------
# Phase 8: register surviving Rust detectors
# ---------------------------------------------------------------------------

def promote_phase7(reviews_dir: Path, summary_out: Path) -> int:
    reg = _load_registry()
    review_files = sorted(reviews_dir.glob("phase7b_rust_review_*.json"))
    new_registrations: list[dict] = []
    skips: list[dict] = []

    for rf in review_files:
        try:
            review = _load_json_strip_fences(rf)
        except json.JSONDecodeError:
            skips.append({"file": str(rf), "reason": "invalid-json"})
            continue
        if not isinstance(review, dict):
            continue
        det_id = review.get("detector_id")
        verdict = review.get("verdict")
        if not det_id or verdict != "promote_to_B":
            skips.append({"file": str(rf), "reason": f"verdict={verdict}"})
            continue
        # Add `rust-` prefix so Rust detectors are namespace-distinct in the registry.
        registry_key = det_id if det_id.startswith("rust-") else f"rust-{det_id}"
        if registry_key in reg.get("tiers", {}):
            skips.append({"file": str(rf), "reason": "id-already-registered"})
            continue

        reg.setdefault("tiers", {})[registry_key] = {
            "tier": "B",
            "language": "rust",
            "reason": (
                f"phase7 minimax review precision={review.get('precision_estimate', 'n/a')}; "
                f"{review.get('rationale', '')[:200]}"
            ),
            "waves": ["phase7-overnight"],
            "first_added": datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%d"),
            "last_promoted": datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%d"),
            "fixture_pair": f"phase7-overnight/{registry_key}",
            "needs_cargo_validation": True,
        }
        new_registrations.append({
            "detector_id": registry_key,
            "tier": "B",
            "precision_estimate": review.get("precision_estimate"),
        })

    if new_registrations:
        _save_registry(reg)

    summary = {
        "schema": "auditooor.overnight.phase7_rust_promotion.v1",
        "ran_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "reviews_processed": len(review_files),
        "new_registrations": new_registrations,
        "registration_count": len(new_registrations),
        "skipped_count": len(skips),
        "note": "All registered Rust detectors flagged needs_cargo_validation=True; run tools/run-detector.py against fixture pairs to gate Tier-S.",
    }
    summary_out.write_text(json.dumps(summary, indent=2), encoding="utf-8")
    return 0


# ---------------------------------------------------------------------------
# Phase 10: GitHub fix-commit refinement. For each Solodit URL enrichment
# output that named a real commit, prefetch the diff via `gh api` and feed
# Kimi the diff to author tighter detector indicators.
# ---------------------------------------------------------------------------

def build_phase10_queue(enrich_dir: Path, queue_out: Path, work_dir: Path) -> int:
    import subprocess
    enrich_files = sorted(enrich_dir.glob("solodit_url_*.json"))
    queue_out.parent.mkdir(parents=True, exist_ok=True)
    prompts_dir = work_dir / "phase10_prompts"
    outputs_dir = work_dir / "phase10_outputs"
    diffs_dir = work_dir / "phase10_diffs"
    prompts_dir.mkdir(parents=True, exist_ok=True)
    outputs_dir.mkdir(parents=True, exist_ok=True)
    diffs_dir.mkdir(parents=True, exist_ok=True)

    tasks: list[dict] = []
    for ef in enrich_files:
        try:
            blob = _load_json_strip_fences(ef)
        except json.JSONDecodeError:
            continue
        if not isinstance(blob, dict):
            continue
        repo = blob.get("protocol_repo_url", "")
        sha = blob.get("public_fix_commit_sha", "")
        confidence = blob.get("confidence", "unknown")
        if not repo or not sha or confidence == "unknown":
            continue
        # Parse owner/repo from URL.
        m = re.search(r"github\.com[:/]([^/]+)/([^/.]+)", repo)
        if not m:
            continue
        owner, name = m.group(1), m.group(2)
        spec_id = blob.get("spec_id", ef.stem.replace("solodit_url_", ""))
        slug = _slug(spec_id)

        # Pre-fetch the diff. 5s timeout; skip on failure.
        diff_path = diffs_dir / f"{slug}.diff"
        if not diff_path.exists():
            try:
                result = subprocess.run(
                    ["gh", "api", f"repos/{owner}/{name}/commits/{sha}",
                     "--jq", ".files | map(select(.patch != null) | .filename + \"\\n\" + .patch) | join(\"\\n\\n\")"],
                    capture_output=True, text=True, timeout=15,
                )
                if result.returncode == 0 and result.stdout.strip():
                    diff_path.write_text(result.stdout[:8000], encoding="utf-8")
                else:
                    continue
            except Exception:
                continue
        diff_text = diff_path.read_text(encoding="utf-8")[:6000]

        prompt = textwrap.dedent(f"""\
            ROLE: Refine a detector specification using the ACTUAL public-fix
            commit diff (not just the prose Solodit description). The diff
            below is what the protocol team committed to fix the bug.

            spec_id: {spec_id}
            repo: {repo}
            commit_sha: {sha}

            === FIX COMMIT DIFF (truncated) ===
            {diff_text}
            === END DIFF ===

            OUTPUT FORMAT — STRICT:
            Single JSON object. No markdown fence. No prose.

              "spec_id": "{slug}"
              "fix_pattern_summary": "<1-2 line shape of what was added/removed>"
              "tightened_detector_indicators": ["<specific>", "<specific>"]
              "tree_sitter_query_or_regex": "<actual query or regex>"
              "fixture_pair_diff_inspired_clean": "<short Solidity or Rust
                snippet showing the FIXED code shape>"
              "fixture_pair_diff_inspired_vulnerable": "<short Solidity or
                Rust snippet showing the BUG that was fixed>"
              "confidence": "high" or "medium" or "low"
              "fix_actually_addresses_solodit_finding": true or false

            Use the diff to ground the indicators in the ACTUAL fix shape,
            not in any guesses about the bug pattern.
            """).strip()

        prompt_path = prompts_dir / f"phase10_diff_{slug}.txt"
        output_path = outputs_dir / f"phase10_diff_{slug}.json"
        prompt_path.write_text(prompt, encoding="utf-8")

        tasks.append({
            "task_id": f"phase10-diff-{slug}",
            "provider": "kimi",
            "task_type": "source-extract",
            "prompt_path": str(prompt_path),
            "output_path": str(output_path),
            "max_tokens": 4000,
        })

    with queue_out.open("w") as f:
        for t in tasks:
            f.write(json.dumps(t) + "\n")
    print(f"phase10 queue: {queue_out} tasks={len(tasks)} (diffs prefetched in {diffs_dir})")
    return 0


def main() -> int:
    p = argparse.ArgumentParser()
    p.add_argument("--mode", required=True,
                   choices=("promote-tier-e", "build-phase3-queue",
                            "build-phase4-queue", "promote-phase4",
                            "build-phase6-queue", "build-phase6b-queue",
                            "promote-phase6", "build-phase7-queue",
                            "build-phase7b-queue", "promote-phase7",
                            "build-phase10-queue"))
    p.add_argument("--reviews-dir", type=Path)
    p.add_argument("--catalog-dsl-dir", type=Path)
    p.add_argument("--fixture-dir", type=Path)
    p.add_argument("--queue-out", type=Path)
    p.add_argument("--work-dir", type=Path)
    p.add_argument("--summary-out", type=Path)
    args = p.parse_args()

    if args.mode == "promote-tier-e":
        return promote_tier_e(args.reviews_dir, args.summary_out)
    if args.mode == "build-phase3-queue":
        return build_phase3_queue(args.catalog_dsl_dir, args.queue_out, args.work_dir)
    if args.mode == "build-phase4-queue":
        return build_phase4_queue(args.fixture_dir, args.queue_out, args.work_dir)
    if args.mode == "promote-phase4":
        return promote_phase4(args.reviews_dir, args.summary_out)
    if args.mode == "build-phase6-queue":
        return build_phase6_queue(args.reviews_dir, args.queue_out, args.work_dir)
    if args.mode == "build-phase6b-queue":
        return build_phase6b_queue(args.fixture_dir, args.queue_out, args.work_dir)
    if args.mode == "promote-phase6":
        return promote_phase6(args.reviews_dir, args.summary_out)
    if args.mode == "build-phase7-queue":
        # No reviews-dir — Phase 7 reads from the master r94 DSL on-disk corpus directly.
        max_tasks = 270
        return build_phase7_queue(args.queue_out, args.work_dir, max_tasks)
    if args.mode == "build-phase7b-queue":
        return build_phase7b_queue(args.fixture_dir, args.queue_out, args.work_dir)
    if args.mode == "promote-phase7":
        return promote_phase7(args.reviews_dir, args.summary_out)
    if args.mode == "build-phase10-queue":
        return build_phase10_queue(args.fixture_dir, args.queue_out, args.work_dir)
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
