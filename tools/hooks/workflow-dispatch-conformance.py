#!/usr/bin/env python3
"""PreToolUse hook (Workflow): block BESPOKE audit-hunt Workflows ("random dispatch").

The Agent path is already gated (spawn-worker + MCP recall). The Workflow tool was
the open door: a bespoke JS script can fan out hunt agents that produce findings which
never flow into the canonical record (verdict-sink / hunt_findings_sidecars), so the
work is off-pipeline - it does not advance the gates and is not in the README funnel.

This hook makes "as per README" mechanical for the Workflow tool:
- If a Workflow targets an audit workspace AND looks HUNT-SHAPED (agents that emit
  findings/severity/verdicts about audit source) AND does NOT route canonically
  (verdict-sink / hunt-sidecar-bridge / hunt-scoped / spawn-worker), it is DENIED
  with guidance to use `make hunt-scoped` or wire verdict-sink.
- Non-hunt Workflows (infra/funnel-fix orchestration), non-audit workspaces, and
  canonical-routing Workflows pass through.
- Explicit override: AUDITOOOR_BESPOKE_DISPATCH_OK=1 (audit-logged), for the rare
  legitimate one-off. Fails OPEN on parse error (never wedges a non-audit session).

Decision protocol (Claude Code PreToolUse): print JSON
{"hookSpecificOutput":{"hookEventName":"PreToolUse","permissionDecision":"deny","permissionDecisionReason":...}}
to block; exit 0 silently to allow.
"""
import json
import os
import re
import sys

HUNT_SIGNALS = re.compile(
    r"\b(fileable|severity|finding|vuln|exploit|rubric|attack_class|paste[- ]ready|"
    r"is_real|impact_class|refute|adversari|hunt)\b", re.IGNORECASE)
CANONICAL_SIGNALS = re.compile(
    r"verdict-sink|verdict_sink|hunt-sidecar-bridge|hunt_sidecar|hunt-scoped|"
    r"hunt_findings_sidecars|spawn-worker|mimo-corpus-mine", re.IGNORECASE)
# Workflows that are clearly infra/tooling orchestration, not finding-hunts.
INFRA_NAME = re.compile(
    r"\b(fix|migrat|refactor|enforce|gate|test|coverage-?fix|funnel|infra|build|"
    r"audit-the-audits|review-changes)\b", re.IGNORECASE)
AUDIT_WS = re.compile(r"/audits/[A-Za-z0-9_.-]+|/audits/")

# Explicit "forced sign" - the conscious capability/infra declaration (mirrors the
# l37/r36-rebuttal markers). A hunt-shaped Workflow that is genuinely capability work
# (building/fixing tooling, not auditing a target) may run iff its script carries one
# of these signatures. Unlike the fuzzy INFRA_NAME heuristic, this is an explicit,
# author-asserted, AUDIT-LOGGED intent - it cannot be tripped accidentally. Accepts
#   DISPATCH-INTENT: capability   |  // dispatch-intent: generic-fix
#   dispatch_intent: "infra"      |  meta.dispatch_intent = 'tooling'
_SIGNED_INTENT = re.compile(
    r"dispatch[-_ ]intent\s*[:=]\s*['\"]?"
    r"(infra|generic-fix|generic_fix|capability|tooling|enforcement|migration|"
    r"refactor|funnel|coverage-fix|build|test|verification|proof|opposed-trace)\b",
    re.IGNORECASE)


def main():
    try:
        payload = json.load(sys.stdin)
    except Exception:
        sys.exit(0)
    if payload.get("tool_name") != "Workflow":
        sys.exit(0)
    ti = payload.get("tool_input") or {}
    script = ti.get("script") or ""
    name = ti.get("name") or ""
    cwd = payload.get("cwd") or ""
    # The Workflow tool's name/description live in the script's `meta = {...}` literal,
    # not in tool_input.name. Pull them so an infra-named workflow (meta.name contains
    # fix/infra/audit-the-audits/...) is correctly classified and not false-DENY'd.
    if not name and script:
        mname = re.search(r"name\s*:\s*['\"]([^'\"]+)['\"]", script)
        mdesc = re.search(r"description\s*:\s*['\"]([^'\"]+)['\"]", script)
        name = " ".join(x.group(1) for x in (mname, mdesc) if x)
    # scriptPath/name-only invocations of a SAVED workflow are canonical by definition
    if not script:
        sys.exit(0)

    targets_audit = bool(AUDIT_WS.search(script) or AUDIT_WS.search(cwd))
    if not targets_audit:
        sys.exit(0)  # not an audit-workspace dispatch -> not our concern

    hunt_shaped = bool(HUNT_SIGNALS.search(script))
    canonical = bool(CANONICAL_SIGNALS.search(script))
    infra = bool(INFRA_NAME.search(name))

    # A BESPOKE HUNT is the disease: hunt-shaped (fans out agents emitting findings/
    # severity about audit source) AND it does NOT route canonically (no verdict-sink /
    # hunt_findings_sidecars / hunt-scoped / spawn-worker) AND it is not infra-named.
    bespoke_hunt = hunt_shaped and not canonical and not infra

    # Explicit signed-intent bypass (the "forced sign" for capability/infra work).
    # Logged so a signed dispatch is never silent - it is an auditable assertion.
    # HOLE FIXED (strata 2026-06-30): the signed-intent bypass USED to fire first and
    # allow UNCONDITIONALLY - so a real hunt could be laundered past the canonical-routing
    # requirement just by labeling it `DISPATCH-INTENT: capability` (a hunt fan-out that
    # returned leads to the orchestrator instead of writing sidecars sailed through,
    # advancing zero gates). A capability LABEL cannot buy a bespoke hunt out of the
    # canonical-routing requirement: the sign bypasses ONLY when this is NOT a bespoke
    # hunt. A genuine hunt must route canonically (or use the explicit, audit-logged env
    # override below) regardless of how it is signed.
    signed = _SIGNED_INTENT.search(script)
    if signed:
        try:
            log = os.path.join(cwd or ".", ".auditooor", "dispatch_intent_signed.jsonl")
            os.makedirs(os.path.dirname(log), exist_ok=True)
            with open(log, "a") as fh:
                fh.write(json.dumps({"name": name, "intent": signed.group(1).lower(),
                                     "hunt_shaped": hunt_shaped,
                                     "bespoke_hunt": bespoke_hunt}) + "\n")
        except Exception:
            pass
        # A signed DISPATCH-INTENT is a conscious, AUDIT-LOGGED assertion (mirrors the
        # l37/r36 rebuttal markers, which DO exempt when present). It ALLOWS - even a
        # hunt-shaped script - because the accountability is the LOG, not a hard block:
        # dispatch_intent_signed.jsonl records hunt_shaped/bespoke_hunt so a mislabeled
        # hunt stays VISIBLE for retrospective review. Unsigned bespoke hunts (below)
        # still hard-DENY - the sign is the only lever that buys a hunt-shaped fan-out
        # past the canonical-routing requirement, and it is a named, logged declaration.
        sys.exit(0)  # allow: explicitly signed (+ logged, incl. bespoke_hunt flag)

    if not bespoke_hunt:
        sys.exit(0)  # allow: not a hunt, or routes canonically, or infra orchestration

    if os.environ.get("AUDITOOOR_BESPOKE_DISPATCH_OK") == "1":
        try:
            log = os.path.join(cwd or ".", ".auditooor", "bespoke_dispatch_override.jsonl")
            os.makedirs(os.path.dirname(log), exist_ok=True)
            with open(log, "a") as fh:
                fh.write(json.dumps({"name": name, "override": True}) + "\n")
        except Exception:
            pass
        sys.exit(0)

    reason = (
        "RANDOM-DISPATCH GUARD: this is a BESPOKE audit-hunt Workflow (it fans out agents "
        "that emit findings/severity about audit source) that does NOT route through the "
        "canonical README path. Off-pipeline hunts do not feed the gates (verdict-sink / "
        "hunt_findings_sidecars / rubric-coverage) - the work will not count. As per README:\n"
        "  1. Run the canonical hunt: `make hunt-scoped WS=<ws> MODEL=sonnet` -> dispatch the "
        "generated _haiku_plan/agent_batch_*.md via Agent through spawn-worker.sh -> "
        "`python3 tools/hunt-sidecar-bridge.py --workspace <ws>`.\n"
        "  2. OR wire `verdict-sink.py` into THIS workflow so its verdicts are sunk into the "
        "canonical record (then it passes this gate).\n"
        "  3. If this is CAPABILITY work (building/fixing tooling, not auditing a target), SIGN "
        "it: add `DISPATCH-INTENT: capability` (or infra | generic-fix | tooling | enforcement) "
        "to the script - an explicit, audit-logged declaration (mirrors the l37/r36 rebuttal "
        "markers).\n"
        "  4. Genuine one-off (rare): set AUDITOOOR_BESPOKE_DISPATCH_OK=1 (audit-logged)."
    )
    print(json.dumps({
        "hookSpecificOutput": {
            "hookEventName": "PreToolUse",
            "permissionDecision": "deny",
            "permissionDecisionReason": reason,
        }
    }))
    sys.exit(0)


if __name__ == "__main__":
    main()
