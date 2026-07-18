#!/usr/bin/env python3
"""HACKERMAN_V3 Lane D2 - runnable chain composition.

A bug chain is only "proven" when the COMPOSED harness runs:

  * hop B's harness must START from the state hop A produced - it must not
    reset to a fresh fixture, it chains from hop A's post-state;
  * the composed sequence must survive defense-in-depth (ante handlers,
    access controls, block-execution path) - a composition that bypasses
    those is not a real exploit even if each hop's unit test passes.

This tool is the runnable-composition piece that sits on top of the rest of
Lane D:

  * D1 (``source-evidence-chain-bridge.py``) mints ``LIVE-<id>`` bridge rows
    when hop A's source-confirmed ``produces_state`` token matches hop B's
    source-confirmed ``requires_state`` token. That promotes a chain plan from
    ``causal_evidence_level: metadata_overlap_only_unproven`` to
    ``distinct_bridge_signal_present``.
  * D3 (``hackerman-exploit-predicates.py``) is what gives predicates the
    semantic ``produces_state[]`` / ``requires_state[]`` fields D1 pairs on.
  * D4 (the chain-promotion gate) blocks any exploit-queue row sourced from a
    chain candidate until it has source anchors + a harness/source-proof
    artifact.

D2 plugs in BETWEEN D1 and D4: given a chain plan whose hops are D1-bridged,
D2 emits the COMPOSED harness task descriptor that D4 then treats as the
"harness artifact" a promoted row needs. D2 does NOT re-plan chains and does
NOT mint bridges; it READS the planner output (which already carries the D1
bridge state) and composes it into a runnable descriptor.

Offline-safe: D2 emits the composed descriptor + a concrete runnable command.
It does not RUN the harness. Running is the operator/CI step.

Verdicts (per composed chain):
  * ``composition_runnable``        - every hop has a D1 LIVE bridge AND a
                                      composed harness command exists AND the
                                      defense-in-depth traversal is evidenced.
  * ``needs_defense_traversal``     - hops are D1-bridged and a command exists
                                      but the composed run skips / has not
                                      shown ante-handler / access-control /
                                      block-execution traversal.
  * ``non_runnable``                - hops are only metadata-overlap (no D1
                                      LIVE bridge) OR no composed command can
                                      be generated. A metadata-only chain
                                      stays non-runnable by construction.

Exit code is always 0 (advisory tool); the per-chain verdict carries the
gate decision. ``--strict`` makes the process exit 1 if any emitted chain is
``non_runnable`` so a CI lane can fail closed.
"""
from __future__ import annotations

import argparse
import importlib.util
import json
import re
import sys
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parent
SCHEMA = "auditooor.chain_composition_harness.v1"

# A chain hop is only runnable-composable when its causal evidence is at least
# a distinct bridge signal. ``metadata_overlap_only_unproven`` chains are, by
# the D1/D4 contract, never runnable.
RUNNABLE_CAUSAL_LEVELS = {"distinct_bridge_signal_present"}
NON_RUNNABLE_CAUSAL_LEVELS = {"metadata_overlap_only_unproven"}

# ---------------------------------------------------------------------------
# Defense-in-depth gate. D2 does NOT invent a parallel defense mechanism: it
# reuses the R25 defense-in-depth-traversal and R26 ante-handler-traversal
# regex vocabularies. The tool prefers to IMPORT the live regexes from the
# R25/R26 check tools; the literals below are an exact-copy fallback so D2 stays
# usable if those modules cannot be imported (kept byte-identical on purpose).
# ---------------------------------------------------------------------------
_R25_TRAVERSAL_FALLBACK = re.compile(
    r"mempool admission|ante decorators?|ProcessProposal|PrepareProposal|"
    r"DeliverTx|FinalizeBlock|BroadcastTxSync|BaseApp\.CheckTx|BaseApp\.FinalizeBlock|"
    r"\bapp\.RunTx\(|AdvanceToBlock\(|network\.New\(|multi-validator|"
    r"RequestFinalizeBlock|ResponseFinalizeBlock|real ante chain|real block execution|"
    r"attack tx .* reaches|reaches (?:matching engine|FinalizeBlock|DeliverTx|block)",
    re.IGNORECASE,
)
_R25_WALKBACK_FALLBACK = re.compile(
    r"defense-in-depth ceiling|structurally rejected at ante|never reaches block|"
    r"categorically rejected|downgraded from HIGH to MEDIUM|downgraded from Critical to Medium|"
    r"walk(?:ed)? back to Medium|MaxTxBytes|ValidateNestedMsg|Invalid nested msg",
    re.IGNORECASE,
)
# Access-control traversal: an exploit that needs a privileged-call hop must
# show it either holds the role or bypasses the check on a reachable path.
_ACCESS_CONTROL_RE = re.compile(
    r"access control|onlyOwner|onlyRole|hasRole|require\([^)]*msg\.sender|"
    r"authoriz|permission check|capability check|role[- ]gated|"
    r"signer check|authority check|unauthenticated entry|bypass.*(?:role|auth|guard)",
    re.IGNORECASE,
)


def _load_module(path: Path, name: str):
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:  # pragma: no cover - defensive
        return None
    module = importlib.util.module_from_spec(spec)
    try:
        spec.loader.exec_module(module)
    except Exception:  # pragma: no cover - defensive: any import error -> fallback
        return None
    return module


def _r25_regexes() -> tuple[re.Pattern[str], re.Pattern[str]]:
    """Return (traversal_re, walkback_re) - prefer the live R25 module."""
    mod = _load_module(ROOT / "defense-in-depth-traversal-check.py", "_d2_r25_defense")
    if mod is not None:
        traversal = getattr(mod, "TRAVERSAL_RE", None)
        walkback = getattr(mod, "WALKBACK_RE", None)
        if isinstance(traversal, re.Pattern) and isinstance(walkback, re.Pattern):
            return traversal, walkback
    return _R25_TRAVERSAL_FALLBACK, _R25_WALKBACK_FALLBACK


def _harness_command_generator():
    """Return the C2 ``_generate_harness_command`` + ``_choose_harness_type``.

    D2 reuses the Lane C2 harness-command generation pattern from
    ``detector-hit-action-graph.py`` instead of re-deriving it. If that module
    cannot be imported, ``_compose_command`` falls back to a generic pattern.
    """
    mod = _load_module(ROOT / "detector-hit-action-graph.py", "_d2_c2_action_graph")
    if mod is None:  # pragma: no cover - defensive
        return None, None
    return (
        getattr(mod, "_generate_harness_command", None),
        getattr(mod, "_choose_harness_type", None),
    )


# ---------------------------------------------------------------------------
# small helpers
# ---------------------------------------------------------------------------
def _as_text(value: Any) -> str:
    return str(value or "").strip()


def _as_list(value: Any) -> list[Any]:
    return value if isinstance(value, list) else []


def _live_rows(values: Any) -> list[str]:
    """LIVE-<id> bridge rows only (D1's deterministic bridge IDs)."""
    out: list[str] = []
    for item in _as_list(values):
        text = _as_text(item)
        if text.upper().startswith("LIVE-"):
            out.append(text)
    return sorted(set(out))


def _live_signals(values: Any) -> list[str]:
    """live-* causal bridge signals (the lower-cased signal form)."""
    out: list[str] = []
    for item in _as_list(values):
        text = _as_text(item)
        if text.lower().startswith("live-"):
            out.append(text)
    return sorted(set(out))


def _plan_text_blob(plan: dict[str, Any]) -> str:
    """Flatten every prose-bearing field of a plan into one searchable blob."""
    parts: list[str] = []
    for key in (
        "composition_rationale",
        "material_distinction_required",
        "attempted_stronger_impact",
        "recommended_next_step",
        "escalation_result",
    ):
        parts.append(_as_text(plan.get(key)))
    for step in _as_list(plan.get("chain_steps")):
        if isinstance(step, dict):
            parts.append(_as_text(step.get("summary")))
            parts.append(_as_text(step.get("evidence_required")))
            parts.append(_as_text(step.get("prerequisite")))
    for item in _as_list(plan.get("proof_steps")):
        parts.append(_as_text(item))
    for item in _as_list(plan.get("shared_evidence")):
        parts.append(_as_text(item))
    for item in _as_list(plan.get("source_refs")):
        parts.append(_as_text(item))
    for req in _as_list(plan.get("composition_harness_requirements")):
        if isinstance(req, dict):
            for value in req.values():
                if isinstance(value, str):
                    parts.append(value)
                elif isinstance(value, list):
                    parts.extend(_as_text(v) for v in value)
    return "\n".join(p for p in parts if p)


# ---------------------------------------------------------------------------
# hop derivation - hop A is the producer, hop B the consumer
# ---------------------------------------------------------------------------
def _composition_requirement(plan: dict[str, Any]) -> dict[str, Any] | None:
    """Return the planner-emitted composition requirement, if any.

    The planner already emits ``composition_harness_requirements`` for
    source-artifact pairs (see ``_source_artifact_composition_requirement``).
    D2 consumes that row directly - it does not recompute the producer /
    consumer split.
    """
    for req in _as_list(plan.get("composition_harness_requirements")):
        if isinstance(req, dict):
            return req
    return None


def _hop_b_setup_from_hop_a(
    requirement: dict[str, Any],
    bridge_ids: list[str],
) -> dict[str, Any]:
    """Build hop B's setup so it consumes hop A's POST-state.

    The defining property of a runnable composition: hop B does NOT reset to a
    fresh fixture. Its setup is a directive to load hop A's produced state.
    """
    bridging = requirement.get("bridging_state")
    if isinstance(bridging, list):
        bridging_tokens = [_as_text(t) for t in bridging if _as_text(t)]
    else:
        bridging_tokens = [_as_text(bridging)] if _as_text(bridging) else []
    producer_artifact = (
        _as_text(requirement.get("producer_state_artifact"))
        or _as_text(requirement.get("producer_source_artifact"))
    )
    return {
        # The contract: hop B starts FROM hop A's post-state, not a fixture.
        "fixture_mode": "chained_from_hop_a_post_state",
        "resets_to_fresh_fixture": False,
        "consumes_post_state_of": "hop_a",
        "post_state_source_artifact": producer_artifact or None,
        "bridging_state_tokens": bridging_tokens,
        "bridge_ids": bridge_ids,
        "consumer_entrypoint": _as_text(requirement.get("consumer_entrypoint")) or None,
        "setup_directive": (
            "Do NOT call a fresh-fixture setup for hop B. Load hop A's "
            "post-state "
            + (f"from {producer_artifact} " if producer_artifact else "")
            + (
                "(bridging state: " + ", ".join(bridging_tokens) + ") "
                if bridging_tokens
                else ""
            )
            + "then invoke hop B's entrypoint against that carried state."
        ),
    }


# ---------------------------------------------------------------------------
# defense-in-depth gate
# ---------------------------------------------------------------------------
def _defense_in_depth_gate(plan: dict[str, Any]) -> dict[str, Any]:
    """Decide whether the composed sequence survives defense-in-depth.

    Reuses the R25 defense-in-depth-traversal regexes and an access-control
    pattern. The composed run is only ``traversed`` when the plan prose carries
    traversal evidence (ante decorators / FinalizeBlock / RunTx / block
    execution / access-control reasoning) or an honest R25 walk-back.
    """
    traversal_re, walkback_re = _r25_regexes()
    blob = _plan_text_blob(plan)

    traversal_hits = sorted(set(traversal_re.findall(blob)))
    walkback_hits = sorted(set(walkback_re.findall(blob)))
    access_hits = sorted(set(_ACCESS_CONTROL_RE.findall(blob)))

    # A plan that explicitly carries an R25 honest walk-back ("never reaches
    # block", "structurally rejected at ante") has DONE the traversal analysis
    # - that is the safety signal R25 rewards. It still counts as traversed.
    traversed = bool(traversal_hits) or bool(walkback_hits) or bool(access_hits)

    missing: list[str] = []
    if not (traversal_hits or walkback_hits):
        missing.append("ante-handler / block-execution traversal")
    if not access_hits:
        missing.append("access-control traversal")

    return {
        "traversed": traversed,
        "reuses": "R25-defense-in-depth-traversal + R26-ante-handler concepts",
        "traversal_signals": traversal_hits,
        "honest_walkback_signals": walkback_hits,
        "access_control_signals": access_hits,
        "missing_defense_layers": [] if traversed else missing,
        "remediation": (
            ""
            if traversed
            else (
                "Compose the harness through the real ante decorator chain / "
                "FinalizeBlock-or-RunTx block-execution path and exercise the "
                "access-control check from an unprivileged caller; or add an "
                "honest R25 walk-back disclosure if a defense layer blocks the "
                "composed sequence."
            )
        ),
    }


# ---------------------------------------------------------------------------
# composed harness command
# ---------------------------------------------------------------------------
def _harness_type_for_plan(
    plan: dict[str, Any],
    requirement: dict[str, Any],
    choose_harness_type,
) -> str:
    """Pick a harness type for the composed run using the C2 chooser."""
    blob = _plan_text_blob(plan).lower()
    # Derive a source file hint from the requirement / source refs.
    source_hint = (
        _as_text(requirement.get("consumer_entrypoint"))
        or _as_text(requirement.get("producer_source_artifact"))
    )
    if not source_hint:
        for ref in _as_list(plan.get("source_refs")):
            text = _as_text(ref)
            if text:
                source_hint = text
                break
    attack_class = ""
    for item in _as_list(plan.get("shared_evidence")):
        text = _as_text(item)
        if text.startswith("shared_attack_classes:"):
            attack_class = text.split(":", 1)[1].split(",")[0]
            break
    # Language hint from blob.
    language = ""
    for lang in ("cosmos", "solidity", "rust", "solana", "go"):
        if lang in blob or lang in source_hint.lower():
            language = lang
            break
    if choose_harness_type is not None:
        try:
            return choose_harness_type(language, source_hint, attack_class)
        except Exception:  # pragma: no cover - defensive
            pass
    return "go-unit"


def _compose_command(
    chain_id: str,
    plan: dict[str, Any],
    requirement: dict[str, Any],
    workspace: Path | None,
) -> dict[str, Any]:
    """Generate a concrete composed-harness command using the C2 pattern.

    Reuses ``_generate_harness_command`` from ``detector-hit-action-graph.py``.
    The composed test runs hop A then hop B in one test function, so the
    detector_slug/attack_class are folded into the chain id.
    """
    generate_cmd, choose_type = _harness_command_generator()
    harness_type = _harness_type_for_plan(plan, requirement, choose_type)

    # Prefer an existing planner-supplied composed command if one is present.
    planner_cmd = _as_text(requirement.get("harness_command"))
    consumer_entrypoint = _as_text(requirement.get("consumer_entrypoint"))
    source_file = (
        consumer_entrypoint
        or _as_text(requirement.get("producer_source_artifact"))
    )

    if generate_cmd is not None:
        try:
            command, status = generate_cmd(
                harness_type,
                # task_id - the chain id makes the composed test name stable.
                chain_id or "CHAIN-000",
                # detector_slug - tag the composed run as a chain composition.
                "chain-composition",
                # attack_class - fold the bridging state in so the slug differs
                # per chain.
                "composed",
                source_file,
                workspace,
            )
        except Exception:  # pragma: no cover - defensive
            command, status = "", "unresolvable"
    else:  # pragma: no cover - defensive fallback
        command, status = "", "unresolvable"

    # If C2 could not resolve a command but the planner already carried one,
    # use the planner command (still a concrete runnable string).
    if not command and planner_cmd:
        command, status = planner_cmd, "command_ready_test_missing"

    return {
        "harness_type": harness_type,
        "composed_harness_command": command or None,
        "harness_status": status,
        "command_present": bool(command),
        "reuses": "C2 _generate_harness_command pattern (detector-hit-action-graph.py)",
        "runs": "hop A then hop B in a single composed test; hop B starts from hop A post-state",
    }


# ---------------------------------------------------------------------------
# per-chain composition
# ---------------------------------------------------------------------------
def compose_chain(plan: dict[str, Any], workspace: Path | None) -> dict[str, Any]:
    """Compose a single chain plan into a runnable-composition descriptor."""
    chain_id = _as_text(plan.get("chain_id")) or "CHAIN-000"
    causal_level = _as_text(plan.get("causal_evidence_level"))
    metadata_overlap_only = bool(plan.get("metadata_overlap_only"))

    bridge_ids = _live_rows(plan.get("paired_live_row_ids"))
    bridge_signals = _live_signals(plan.get("causal_bridge_signals"))
    has_d1_bridge = (
        causal_level in RUNNABLE_CAUSAL_LEVELS
        and not metadata_overlap_only
        and bool(bridge_ids or bridge_signals)
    )

    requirement = _composition_requirement(plan)

    # ----- non-runnable: metadata-only chain has no D1 LIVE bridge -----------
    if not has_d1_bridge:
        return {
            "schema": SCHEMA,
            "chain_id": chain_id,
            "verdict": "non_runnable",
            "causal_evidence_level": causal_level or "metadata_overlap_only_unproven",
            "has_d1_live_bridge": False,
            "composition_runnable": False,
            "bridge_ids": bridge_ids,
            "bridge_signals": bridge_signals,
            "reason": (
                "chain hops are metadata-overlap only (no D1 LIVE bridge); a "
                "metadata-only chain stays non-runnable by construction"
            ),
            "composed_harness": None,
            "advisory_only": True,
        }

    # ----- D1-bridged: build the composed descriptor ------------------------
    if requirement is None:
        # Bridged but the planner emitted no composition requirement (e.g. the
        # pair is not a source_artifact_state_evidence pair). Cannot compose a
        # runnable harness without the producer/consumer split.
        return {
            "schema": SCHEMA,
            "chain_id": chain_id,
            "verdict": "non_runnable",
            "causal_evidence_level": causal_level,
            "has_d1_live_bridge": True,
            "composition_runnable": False,
            "bridge_ids": bridge_ids,
            "bridge_signals": bridge_signals,
            "reason": (
                "chain is D1-bridged but carries no composition_harness_requirements "
                "row (no producer/consumer state split) - cannot compose a runnable harness"
            ),
            "composed_harness": None,
            "advisory_only": True,
        }

    command_info = _compose_command(chain_id, plan, requirement, workspace)
    defense = _defense_in_depth_gate(plan)
    hop_b_setup = _hop_b_setup_from_hop_a(requirement, bridge_ids)

    composed_harness = {
        "binding_scope": "composed_chain_harness",
        "chain_id": chain_id,
        "hop_a": {
            "role": "producer",
            "lead_id": _as_text(requirement.get("producer_lead_id")) or None,
            "source_artifact": _as_text(requirement.get("producer_source_artifact")) or None,
            "produces_post_state": hop_b_setup["bridging_state_tokens"],
        },
        "hop_b": {
            "role": "consumer",
            "lead_id": _as_text(requirement.get("consumer_lead_id")) or None,
            "entrypoint": hop_b_setup["consumer_entrypoint"],
            "setup": hop_b_setup,
        },
        "bridge_ids": bridge_ids,
        "bridge_signals": bridge_signals,
        "primitive_pair_ids": _as_list(requirement.get("primitive_pair_ids")),
        "command": command_info,
        "defense_in_depth": defense,
    }
    impact_contract_id = _as_text(requirement.get("impact_contract_id"))
    if impact_contract_id:
        composed_harness["impact_contract_id"] = impact_contract_id

    command_present = bool(command_info.get("command_present"))

    # ----- verdict ----------------------------------------------------------
    if not command_present:
        verdict = "non_runnable"
        reason = (
            "chain is D1-bridged but no composed harness command could be "
            "generated - not runnable"
        )
        composition_runnable = False
    elif not defense["traversed"]:
        verdict = "needs_defense_traversal"
        reason = (
            "composed harness command exists and hop B chains from hop A "
            "post-state, but the composed run has not shown it survives "
            "defense-in-depth ("
            + ", ".join(defense["missing_defense_layers"])
            + ")"
        )
        composition_runnable = False
    else:
        verdict = "composition_runnable"
        reason = (
            "every hop has a D1 LIVE bridge, hop B chains from hop A post-state, "
            "a composed harness command exists, and the composed sequence "
            "survives defense-in-depth"
        )
        composition_runnable = True

    return {
        "schema": SCHEMA,
        "chain_id": chain_id,
        "verdict": verdict,
        "causal_evidence_level": causal_level,
        "has_d1_live_bridge": True,
        "composition_runnable": composition_runnable,
        "bridge_ids": bridge_ids,
        "bridge_signals": bridge_signals,
        "reason": reason,
        "composed_harness": composed_harness,
        "advisory_only": True,
    }


def compose_plans(payload: dict[str, Any], workspace: Path | None) -> dict[str, Any]:
    """Compose every plan in a chained-attack-plans payload."""
    plans = _as_list(payload.get("plans"))
    composed = [compose_chain(plan, workspace) for plan in plans if isinstance(plan, dict)]
    counts = {
        "composition_runnable": 0,
        "needs_defense_traversal": 0,
        "non_runnable": 0,
    }
    for row in composed:
        verdict = row.get("verdict")
        if verdict in counts:
            counts[verdict] += 1
    return {
        "schema": SCHEMA,
        "workspace": str(workspace) if workspace else None,
        "source_plan_count": len(plans),
        "composed_count": len(composed),
        "verdict_counts": counts,
        "all_runnable": counts["non_runnable"] == 0 and counts["needs_defense_traversal"] == 0,
        "composed_chains": composed,
    }


# ---------------------------------------------------------------------------
# cli
# ---------------------------------------------------------------------------
def _load_json(path: Path) -> Any:
    with path.open(encoding="utf-8") as fh:
        return json.load(fh)


def run(argv: list[str] | None = None) -> dict[str, Any]:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--workspace",
        default=None,
        help="Workspace root. Used to resolve the default chain-plan path and "
        "to check whether composed test files already exist on disk.",
    )
    parser.add_argument(
        "--chain-plan",
        default=None,
        help="chained_attack_plans.json path. Defaults to "
        "<ws>/swarm/chained_attack_plans.json",
    )
    parser.add_argument("--out", default=None, help="Write the composition summary JSON here")
    parser.add_argument("--print-json", action="store_true", help="Print the summary JSON to stdout")
    parser.add_argument(
        "--strict",
        action="store_true",
        help="Exit 1 if any composed chain is non_runnable",
    )
    args = parser.parse_args(argv)

    workspace = Path(args.workspace).expanduser().resolve() if args.workspace else None
    if args.chain_plan:
        plan_path = Path(args.chain_plan).expanduser().resolve()
    elif workspace is not None:
        plan_path = workspace / "swarm" / "chained_attack_plans.json"
    else:
        raise SystemExit("one of --workspace or --chain-plan is required")

    if not plan_path.is_file():
        raise SystemExit(f"chain plan not found: {plan_path}")

    payload = _load_json(plan_path)
    if not isinstance(payload, dict):
        raise SystemExit(f"chain plan is not a JSON object: {plan_path}")

    summary = compose_plans(payload, workspace)
    summary["chain_plan_path"] = str(plan_path)

    if args.out:
        out_path = Path(args.out).expanduser().resolve()
        out_path.parent.mkdir(parents=True, exist_ok=True)
        out_path.write_text(json.dumps(summary, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    if args.print_json:
        print(json.dumps(summary, indent=2, sort_keys=True))
    return summary


def main(argv: list[str] | None = None) -> int:
    summary = run(argv)
    args_strict = "--strict" in (argv if argv is not None else sys.argv[1:])
    if args_strict and summary.get("verdict_counts", {}).get("non_runnable", 0) > 0:
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
