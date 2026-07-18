#!/usr/bin/env python3
# R36 pathspec discipline: lane-CAP-GAP-99-SALVAGE-QUESTION-ENUMERATOR
# <!-- r36-rebuttal: lane-CAP-GAP-99-SALVAGE-QUESTION-ENUMERATOR registered for tools/salvage-question-enumerator.py -->
"""salvage-question-enumerator.py - CAP-GAP-99 R63 implementation.

For any HIGH+ finding being walked back to NOT-SALVAGEABLE, this tool
enumerates N>=10 semantically-distinct question framings that an LLM should
explore in PARALLEL before the NOT-SALVAGEABLE verdict is accepted.

Empirical anchor: Spark LEAD 1 Critical save 2026-05-27. Prior 10 salvage
rounds iterated SERIALLY on operator-suggested angles ("can attacker race the
receiver claim?"). This session's mimo batch of 10 distinct framings surfaced
V1 (mobile-OS-suspend) + V2 (watchtower silent-broadcast) - both source-verified
- in one shot. The lever was the question taxonomy, not the LLM provider.

CLI
---
python3 tools/salvage-question-enumerator.py \
    --draft <walk-back-doc>.md \
    --workspace <ws> \
    --output-jsonl /tmp/<draft-slug>_salvage_batch.jsonl

The output JSONL is compatible with tools/llm-fanout-dispatcher.py and
can be dispatched on ANY provider: mimo, deepseek-flash, anthropic-haiku,
kimi, minimax. The output sidecar dir is the per-workspace
.auditooor/salvage_enumerations/<draft-slug>/ folder.

Verdicts:
- ok - 10+ framings emitted, batch ready to dispatch
- fail-draft-not-found
- fail-output-dir-not-writable
- fail-draft-not-walked-back - draft doesn't contain NOT-SALVAGEABLE or walk-back markers

Schema: auditooor.r63_salvage_question_enumerator.v1
"""
from __future__ import annotations
import argparse, datetime, json, pathlib, re, sys, hashlib
from typing import Dict, List, Optional, Any

SCHEMA_ID = "auditooor.r63_salvage_question_enumerator.v1"
GENERATOR = "salvage-question-enumerator"
VERSION = "v1"
DEFAULT_FRAMING_COUNT = 10

# The 10 standard semantic framings. Each is designed to explore a DIFFERENT
# attack-surface dimension of the contested behavior. Operators can extend
# via --extra-framing or env AUDITOOOR_R63_EXTRA_FRAMINGS.
STANDARD_FRAMINGS = [
    {
        "id": "F1-source-init-silent-failure",
        "question": "Is there any init/bootstrap code path that swallows an exception, fails silently, or short-circuits before the protective handler is registered?",
        "focus": "init-code error-swallowing patterns, exception handlers that catch-and-continue, early-return paths before registration completes",
    },
    {
        "id": "F2-periodic-loop-os-suspension",
        "question": "Does the protective action depend on a setInterval/setTimeout/poll loop that platform-canonical OS behavior (mobile background, browser visibility, system sleep, Doze mode, low-memory) can suspend or throttle?",
        "focus": "setInterval, setTimeout, schedule.every, asyncio.sleep loops + missing wake/resume listeners (AppState, visibilitychange, applicationDidBecomeActive, Network online/offline)",
    },
    {
        "id": "F3-rpc-retry-budget-exceeds-bound",
        "question": "If the protective RPC/network call fails transiently, does the retry-with-backoff budget (max_retries * backoff_sum) exceed the protocol's time bound (refund maturity, challenge window, finalization deadline)?",
        "focus": "retry-max + backoff-base + per-task-timeout combinations, exponential backoff math, total worst-case wall-clock vs time-bound",
    },
    {
        "id": "F4-server-db-commit-before-side-effect",
        "question": "Does the server-side handler commit state to DB before the load-bearing side-effect (broadcast, finalize, propagate) is confirmed? Does it return success to client even if the side-effect failed?",
        "focus": "DB transaction commit ordering vs network-call success-check ordering, defer-success-on-error patterns",
    },
    {
        "id": "F5-legacy-flag-off-secure-path",
        "question": "Is there a legacy code path or feature flag that, when off OR when the call routes through a deprecated version, skips the secure-by-default branch?",
        "focus": "feature flags, version checks, legacy function variants, gradual-rollout gates, A/B configuration switches",
    },
    {
        "id": "F6-defer-on-missing-prerequisite",
        "question": "Does any component defer the protective action while waiting for a prerequisite (connector parent, oracle quorum, multisig threshold, peer count)? Can the prerequisite never arrive in normal conditions?",
        "focus": "wait-loops with no escalation, missing-prerequisite checks that block forever, peer-count thresholds in degraded networks",
    },
    {
        "id": "F7-network-layer-retry-caps",
        "question": "Does the network transport (xhr-transport, websocket, gRPC client) cap retries below the application-level retry budget, causing transport-level give-up before app-level escalation?",
        "focus": "xhr-transport.ts retry config, fetch retry-limit, websocket-reconnect-attempts, http.Client Timeout, gRPC dial backoff",
    },
    {
        "id": "F8-cross-protocol-analogue",
        "question": "Are there KNOWN INCIDENTS in similar protocols (Lightning, IBC, MPC, Optimism, ZkRollup, Mercury statechain) where the analogous protective component failed under production-realistic conditions?",
        "focus": "Lightning watchtower BLAST 2023, Wormhole guardian missed-attestation, Hermes IBC packet-drop, RGB watchtower miss, MPC participant-offline-window, ERC-4337 paymaster bundler-restart, L2 sequencer-down windows",
    },
    {
        "id": "F9-production-trigger-taxonomy",
        "question": "Enumerate 10 production-realistic conditions (not adversarial-only) where the protective action fails. Each should occur in NORMAL user/operator workflow without manual disable or abnormal behavior.",
        "focus": "user-foregrounds-then-backgrounds app (mobile), high-fee mempool congestion (BTC), L1 reorg (sequencer), peer churn (P2P), DNS failure, certificate expiry, OS update reboot, RAM-pressure swap, daylight-savings-time clock skew, leap-second handling",
    },
    {
        "id": "F10-synthetic-attack-model",
        "question": "Construct a synthetic attack model where the attacker manipulates ENVIRONMENTAL conditions (not protocol state) to trigger the protective action failure. Sender chooses TIMING, network conditions, or fee-environment to maximize gap probability.",
        "focus": "attacker chooses backgrounded-time of victim (weekday business hours), exploits during congestion, races mempool-min-fee-rise, exit during scheduled-maintenance windows, attack during global news event drawing user attention away from app",
    },
]

PROMPT_TEMPLATE = """You are a senior security researcher investigating whether a previously-walked-back HIGH+ finding can be SAVED via a specific semantic framing.

Original finding draft excerpt:
{draft_excerpt}

The walk-back conclusion was: NOT-SALVAGEABLE because the gates require receiver to use normal production behavior.

Apply ONLY this semantic framing to surface a new save vector:

  Framing ID: {framing_id}
  Question: {framing_question}
  Focus areas: {framing_focus}

Output ONLY a JSON object:
- "framing_id": "{framing_id}"
- "escape_vector_found": "yes" | "partial" | "no"
- "vector_description": one paragraph (<= 5 sentences)
- "production_realism_1_to_5": int (5=common-real-user-scenario, 1=adversarial-only)
- "source_line_anchors": list of 3-5 specific file:line citations supporting the vector
- "regtest_harness_steps": list of 5-8 step strings that would prove this end-to-end
- "matches_all_5_acceptance_gates": "yes" | "no" with one-sentence reason for each gate
- "estimated_likelihood_to_save_critical_1_to_5": int
- "recommended_next_lane": short string describing what additional investigation would close this out

No prose outside JSON. No markdown fences."""


def find_workspace_for_draft(draft_path: pathlib.Path) -> Optional[pathlib.Path]:
    """Walk up from draft to find workspace root (contains submissions/ or .auditooor/)."""
    cur = draft_path.parent
    for _ in range(8):
        if (cur / "submissions").is_dir() or (cur / ".auditooor").is_dir():
            return cur
        if cur.parent == cur:
            break
        cur = cur.parent
    return None


def extract_walk_back_signals(text: str) -> List[str]:
    """Find walk-back markers in the draft text."""
    signals = []
    for pattern in [
        r"NOT[-\s]*SALVAGEABLE",
        r"closed\s+as\s+(spam|known-issue|won't\s*fix|risk-acknowledged|by\s+design)",
        r"walk[-\s]*back",
        r"honest\s+concession",
        r"DROP[-\s]*CONFIRMED",
    ]:
        if re.search(pattern, text, re.IGNORECASE):
            signals.append(pattern)
    return signals


def build_framing_tasks(
    draft_path: pathlib.Path,
    workspace: pathlib.Path,
    framings: List[Dict[str, str]],
) -> List[Dict[str, Any]]:
    """Build the dispatch-ready JSONL tasks."""
    draft_text = draft_path.read_text(encoding="utf-8", errors="replace")
    draft_excerpt = draft_text[:5000]
    draft_slug = draft_path.stem.replace(" ", "-")[:80]

    tasks = []
    for f in framings:
        task = {
            "task_id": f"salvage_q_enum_{draft_slug}_{f['id']}"[:120],
            "task_type": "salvage_question_enumeration",
            "prompt": PROMPT_TEMPLATE.format(
                draft_excerpt=draft_excerpt,
                framing_id=f["id"],
                framing_question=f["question"],
                framing_focus=f["focus"],
            ),
            "max_input_tokens": 9000,
            "max_output_tokens": 2000,
            "verification_tier_target": "tier-3-synthetic-taxonomy-anchored",
            "meta": {
                "framing_id": f["id"],
                "draft_path": str(draft_path),
                "draft_slug": draft_slug,
                "workspace": str(workspace),
                "generator": GENERATOR,
                "generator_version": VERSION,
                "schema_id": SCHEMA_ID,
            },
        }
        tasks.append(task)
    return tasks


def write_batch(tasks: List[Dict[str, Any]], out_path: pathlib.Path) -> None:
    out_path.parent.mkdir(parents=True, exist_ok=True)
    with open(out_path, "w", encoding="utf-8") as fh:
        for t in tasks:
            fh.write(json.dumps(t, sort_keys=True) + "\n")


def main() -> int:
    p = argparse.ArgumentParser(
        prog="salvage-question-enumerator",
        description="CAP-GAP-99 / R63: enumerate N>=10 semantically-distinct question framings before NOT-SALVAGEABLE verdict",
    )
    p.add_argument("--draft", required=True, help="Walk-back draft .md path")
    p.add_argument("--workspace", default=None, help="Workspace root (auto-detected if omitted)")
    p.add_argument("--output-jsonl", default=None, help="Output JSONL path (default: /tmp/<draft-slug>_salvage_batch.jsonl)")
    p.add_argument("--extra-framing-json", default=None, help="Path to JSON file with extra framings (extends standard 10)")
    p.add_argument("--json", action="store_true", help="Emit JSON status verdict")
    p.add_argument("--strict", action="store_true", help="Refuse to emit if draft has no walk-back markers")
    args = p.parse_args()

    draft = pathlib.Path(args.draft)
    if not draft.is_file():
        verdict = {"schema_id": SCHEMA_ID, "verdict": "fail-draft-not-found", "draft": str(draft)}
        print(json.dumps(verdict) if args.json else f"FAIL: {verdict}")
        return 1

    ws = pathlib.Path(args.workspace) if args.workspace else find_workspace_for_draft(draft)
    if ws is None:
        ws = draft.parent

    # Check walk-back signals
    text = draft.read_text(encoding="utf-8", errors="replace")
    signals = extract_walk_back_signals(text)
    if not signals and args.strict:
        verdict = {"schema_id": SCHEMA_ID, "verdict": "fail-draft-not-walked-back", "draft": str(draft)}
        print(json.dumps(verdict) if args.json else f"FAIL: {verdict}")
        return 1

    # Build framings (standard + extras)
    framings = list(STANDARD_FRAMINGS)
    if args.extra_framing_json:
        try:
            extras = json.load(open(args.extra_framing_json))
            if isinstance(extras, list):
                framings.extend(extras)
        except Exception as e:
            print(f"WARN: failed to load --extra-framing-json: {e}", file=sys.stderr)

    if len(framings) < DEFAULT_FRAMING_COUNT:
        verdict = {"schema_id": SCHEMA_ID, "verdict": "fail-too-few-framings", "count": len(framings)}
        print(json.dumps(verdict) if args.json else f"FAIL: {verdict}")
        return 1

    # Build + write tasks
    out_jsonl = pathlib.Path(args.output_jsonl) if args.output_jsonl else \
        pathlib.Path(f"/tmp/{draft.stem.replace(' ','-')}_salvage_batch.jsonl")
    tasks = build_framing_tasks(draft, ws, framings)
    write_batch(tasks, out_jsonl)

    # Also create the sidecar output dir reservation
    sidecar_dir = ws / ".auditooor" / "salvage_enumerations" / draft.stem
    sidecar_dir.mkdir(parents=True, exist_ok=True)

    verdict = {
        "schema_id": SCHEMA_ID,
        "verdict": "ok",
        "draft": str(draft),
        "workspace": str(ws),
        "framings_emitted": len(tasks),
        "walk_back_signals": signals,
        "output_jsonl": str(out_jsonl),
        "sidecar_dir": str(sidecar_dir),
        "dispatch_hint": f"AUDITOOOR_LLM_NETWORK_CONSENT=1 python3 tools/llm-fanout-dispatcher.py --task-batch {out_jsonl} --output-dir {sidecar_dir} --provider deepseek-flash --concurrency 4",
    }
    if args.json:
        print(json.dumps(verdict))
    else:
        print(f"OK: emitted {len(tasks)} framings -> {out_jsonl}")
        print(f"Sidecar dir: {sidecar_dir}")
        print(f"Dispatch with: {verdict['dispatch_hint']}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
