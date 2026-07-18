#!/usr/bin/env python3
"""Lane 4 / Lane 10 - PoC Falsification Runner.

Proves, disproves, or bounds a serious exploit lead BEFORE a paste-ready
draft is written.

Lane 10 extends this with a ``--draft <draft.md>`` mode that reads the
severity claim directly from a paste-ready or staging draft, enforces all
Lane-10 required checks, emits the Lane-10 artifact shape, and optionally
runs a MiniMax adversarial-kill provider challenge (Task 4).

Inputs
------
- ``--queue-row <row.json>``   Lane 2 exploit-queue row (minimum shape).
- ``--draft <draft.md>``       Draft markdown file (Lane 10 mode). When
                               supplied, queue-row is optional (synthesised
                               from draft metadata if absent).
- ``--cmd '<shell command>'``  Optional harness command to run.
- ``--source-refs <refs>``     Optional comma-separated source references.
- ``--severity-oracle <oracle.json>``  Optional severity/scope oracle output.
- ``--provider-challenge``     Run a MiniMax adversarial-kill challenge on
                               the draft (requires AUDITOOOR_LLM_NETWORK_CONSENT=1).

Output JSON shape (emitted with ``--json``)
-------------------------------------------
Standard shape (queue-row mode):
{
  "candidate_id": str,
  "verdict": "proved|disproved|inconclusive|needs_harness|not_in_scope",
  "commands_run": [],
  "transcript_paths": [],
  "negative_controls": [],
  "production_path_checks": [],
  "restart_checks": [],
  "multi_validator_checks": [],
  "synthetic_state_status": "none|waived|detected",
  "open_blockers": []
}

Lane-10 artifact shape (--draft mode, additional fields):
{
  "proof_claim": str,
  "mechanism": str,
  "controls": {
    "clean_negative_control": bool,
    "adjacent_condition_control": bool,
    "production_path_proof": bool,
    "no_synthetic_state_seeding": bool,
    "no_private_field_reflection": bool,
    "restart_behavior": bool,
    "multi_validator_network_claims": bool,
    "real_backend_db_storage": bool,
    "no_teardown_contamination": bool,
    "exact_command_and_transcript": bool,
    "commit_hash_or_config": bool,
    "inline_poc_body": bool
  },
  "falsification_result": "proved|disproved|inconclusive|needs_harness|not_in_scope",
  "remaining_triager_questions": [],
  "provider_challenge": {}   // present when --provider-challenge was requested
}

Required controls by class (the gate that keeps verdicts honest)
----------------------------------------------------------------
- High/Critical: negative control OR explicit ``NO_CONTROL_REASON``.
- Any timing/persistence/liveness claim: production path AND restart checks.
- Cosmos/app-chain network claim (network-level liveness/halt):
  real app block path, GoLevelDB/PebbleDB, no MemDB, multi-validator.
- EVM accounting/share claim: actor-separated sequence PoC plus alternative
  cause control.
- Bridge proof-domain claim: source/destination chain/domain controls,
  replay/finality control, recipient/control leaf fields.

Composed tools (called as subprocesses, never reimplemented)
------------------------------------------------------------
- tools/control-test-discipline-check.py  (Rule 34)
- tools/production-profile-preflight-check.py  (Rule 30)
- tools/panic-context-audit.py
- tools/deep-counterexample-record.py
- tools/deep-counterexample-replay-scaffold.py
- tools/fuzz-sequence-to-poc.py
- tools/symbolic-execution-validator.py
- tools/recon-log-bridge.py

Exit codes
----------
0 - verdict in {proved, disproved, inconclusive, needs_harness}
1 - not_in_scope or input error
2 - argument error
"""
from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import sys
import tempfile
import time
from pathlib import Path
from typing import Any

SCHEMA_VERSION = "auditooor.poc_falsification_runner.v1"
SCHEMA_VERSION_LANE10 = "auditooor.poc_falsification_runner.lane10.v1"

VERDICTS = {"proved", "disproved", "inconclusive", "needs_harness", "not_in_scope"}

# Empty-run / zero-tests-executed markers ---------------------------------
# If any of these patterns match (case-insensitively) in the harness
# combined stdout+stderr, the harness ran zero tests even though it may
# have exited 0.  A zero-test run MUST NOT yield verdict='proved'.
#
# Each entry is (pattern_re, human_label).
_EMPTY_RUN_MARKERS: list[tuple[re.Pattern[str], str]] = [
    # forge / foundry
    (re.compile(r"no tests found", re.IGNORECASE), "forge: no tests found"),
    (re.compile(r"no tests to run", re.IGNORECASE), "forge/go: no tests to run"),
    (re.compile(r"no tests match", re.IGNORECASE), "forge: no tests match"),
    # go test
    (re.compile(r"no test files", re.IGNORECASE), "go: no test files"),
    (re.compile(r"\[no test files\]", re.IGNORECASE), "go: [no test files]"),
    (re.compile(r"testing: warning: no tests to run", re.IGNORECASE),
     "go: testing: warning: no tests to run"),
    # cargo test
    (re.compile(r"running 0 tests", re.IGNORECASE), "cargo: running 0 tests"),
    (re.compile(r"\b0 passed;\s*0 failed\b", re.IGNORECASE), "cargo: 0 passed; 0 failed"),
    # pytest
    (re.compile(r"no tests ran", re.IGNORECASE), "pytest: no tests ran"),
    (re.compile(r"collected 0 items", re.IGNORECASE), "pytest: collected 0 items"),
]


def _detect_empty_run(combined_output: str) -> str | None:
    """Return a human-readable label if combined stdout+stderr shows zero tests ran.

    Returns None when the output does not match any empty-run marker (i.e. at
    least one real test executed, or the output is unrecognised).
    """
    for pattern, label in _EMPTY_RUN_MARKERS:
        if pattern.search(combined_output):
            return label
    return None

SEVERITY_RANK: dict[str, int] = {
    "low": 1,
    "medium": 2,
    "high": 3,
    "critical": 4,
    "unknown": 0,
}

# Claim-class keyword matchers -------------------------------------------

_TIMING_PERSISTENCE_RE = re.compile(
    r"\b(timing|persistent|permanen|liveness|liveness[- ]fail|liveness[- ]claim"
    r"|halt|chain[- ]halt|freeze|permanent|persist|block[- ]produc"
    r"|consensus|appHash|AppHash|validator[- ]halt|network[- ]level)\b",
    re.IGNORECASE,
)

_COSMOS_NETWORK_RE = re.compile(
    r"\b(cosmos|cometbft|comet|tendermint|dydx|app[- ]chain"
    r"|network[- ]level|multi[- ]validator|block[- ]execut|FinalizeBlock"
    r"|BaseApp|state[- ]machine|matching[- ]engine|validator[- ]halt)\b",
    re.IGNORECASE,
)

_EVM_ACCOUNTING_RE = re.compile(
    r"\b(evm|solidity|foundry|share[s]?|vault|erc[- ]?4626"
    r"|accounting|rounding|price[- ]manipulation|reentr)\b",
    re.IGNORECASE,
)

_BRIDGE_RE = re.compile(
    r"\b(bridge|proof[- ]domain|cross[- ]chain|relay|merkle[- ]proof"
    r"|finality|destination[- ]chain|source[- ]chain|replay|leaf|receipt)\b",
    re.IGNORECASE,
)

# Lane-10 draft parsing -------------------------------------------------

# Patterns used to extract fields from a markdown draft file.
_DRAFT_SEVERITY_RE = re.compile(
    r"^\s*[-*]?\s*[Ss]everity[:\s]+([A-Za-z]+)", re.MULTILINE
)
_DRAFT_TITLE_RE = re.compile(r"^#\s+(.+)$", re.MULTILINE)
_DRAFT_SUMMARY_RE = re.compile(
    r"##\s+Summary\s*\n+([\s\S]+?)(?=\n##|\Z)", re.IGNORECASE
)
_DRAFT_ROOT_CAUSE_RE = re.compile(
    r"##\s+Root\s+Cause\s*\n+([\s\S]+?)(?=\n##|\Z)", re.IGNORECASE
)
_DRAFT_PoC_RE = re.compile(
    r"##\s+[Pp]roof[\s\-_][Oo]f[\s\-_][Cc]oncept\s*\n+([\s\S]+?)(?=\n##|\Z)",
    re.IGNORECASE,
)
_DRAFT_ATTACK_CLASS_RE = re.compile(
    r"\b(reentrancy|price[- ]manipulation|flash[- ]loan|overflow|underflow"
    r"|access[- ]control|missing[- ]validation|missing[- ]guard"
    r"|apphash[- ]divergence|liveness[- ]fail|dos|denial[- ]of[- ]service"
    r"|integer[- ]overflow|precision[- ]loss|governance[- ]takeover"
    r"|front[- ]running|sandwich|manipulation|theft|drain|freeze|bypass)\b",
    re.IGNORECASE,
)

# Commit-hash or config-reference in a draft
_COMMIT_HASH_RE = re.compile(r"\b[0-9a-f]{7,40}\b")
_CONFIG_REF_RE = re.compile(
    r"\b(config\.json|\.toml|\.yaml|audit[- ]pin|version[=:\s])\b", re.IGNORECASE
)

# Inline PoC body patterns (forge test body, go test func, cargo test fn)
_INLINE_POC_BODY_RE = re.compile(
    r"(function\s+test[A-Z_]|func\s+Test[A-Z_]|#\[test\]|def\s+test_)", re.IGNORECASE
)

# Teardown-contamination patterns (panic/deadlock in teardown is a false positive)
_TEARDOWN_CONTAMINATION_RE = re.compile(
    r"(t\.Cleanup|defer\s+\w+\s*\(|AfterEach|afterAll|teardown|TearDown)\s*\{[^}]*"
    r"(panic|deadlock|FAIL)",
    re.IGNORECASE,
)

# Adjacent-condition control patterns
_ADJACENT_CONDITION_RE = re.compile(
    r"(adjacent|boundary|off[- ]by[- ]one|edge[- ]case|condition[- ]control"
    r"|adjacent[- ]control|alternate[- ]path|path[- ]control"
    r"|r34[- ]rebuttal|adjacent_control)",
    re.IGNORECASE,
)

# Private-field reflection patterns
_REFLECTION_RE = re.compile(
    r"(reflect\.ValueOf|unsafe\.Pointer|nodeDB\.legacy|\.legacyLatest"
    r"|unexported|private[- ]field|internal[- ]field|r30[- ]rebuttal)",
    re.IGNORECASE,
)


def _parse_draft(draft_path: Path) -> dict[str, Any]:
    """Parse a markdown draft file and return a structured metadata dict."""
    text = draft_path.read_text(encoding="utf-8", errors="replace")

    title = ""
    m = _DRAFT_TITLE_RE.search(text)
    if m:
        title = m.group(1).strip()

    severity = "unknown"
    m = _DRAFT_SEVERITY_RE.search(text)
    if m:
        severity = m.group(1).strip().lower()

    summary = ""
    m = _DRAFT_SUMMARY_RE.search(text)
    if m:
        summary = m.group(1).strip()[:500]

    root_cause = ""
    m = _DRAFT_ROOT_CAUSE_RE.search(text)
    if m:
        root_cause = m.group(1).strip()[:500]

    poc_section = ""
    m = _DRAFT_PoC_RE.search(text)
    if m:
        poc_section = m.group(1).strip()[:1000]

    attack_classes = list({
        ac.lower() for ac in _DRAFT_ATTACK_CLASS_RE.findall(text)
    })[:5]

    has_commit_hash = bool(_COMMIT_HASH_RE.search(text))
    has_config_ref = bool(_CONFIG_REF_RE.search(text))
    has_inline_poc = bool(_INLINE_POC_BODY_RE.search(text))
    has_adjacent_condition = bool(_ADJACENT_CONDITION_RE.search(text))
    has_reflection = bool(_REFLECTION_RE.search(text))
    has_teardown_contamination = bool(_TEARDOWN_CONTAMINATION_RE.search(text))
    has_exact_command = bool(
        re.search(
            r"```\s*(bash|sh|console|forge|go|cargo|pytest)", text, re.IGNORECASE
        )
    )

    return {
        "title": title,
        "severity": severity,
        "summary": summary,
        "root_cause": root_cause,
        "poc_section": poc_section,
        "attack_classes": attack_classes,
        "has_commit_hash": has_commit_hash,
        "has_config_ref": has_config_ref,
        "has_inline_poc": has_inline_poc,
        "has_adjacent_condition": has_adjacent_condition,
        "has_reflection": has_reflection,
        "has_teardown_contamination": has_teardown_contamination,
        "has_exact_command": has_exact_command,
        "full_text": text,
        "char_count": len(text),
    }


def _draft_to_queue_row(meta: dict[str, Any], draft_path: Path) -> dict[str, Any]:
    """Synthesise a minimal queue-row from draft metadata."""
    return {
        "lead_id": draft_path.stem,
        "title": meta["title"],
        "attack_class": (meta["attack_classes"][0] if meta["attack_classes"] else "unknown"),
        "likely_severity": meta["severity"],
        "severity_confidence": "medium",
        "attacker_control": "unknown",
        "impact_path": meta["summary"][:200],
        "proof_path": "draft",
        "next_command": "",
        "blockers": [],
        "dupe_risk": "unknown",
        "priority_score": 0.5,
    }


# Lane-10 control evaluation --------------------------------------------

def _eval_lane10_controls(
    draft_meta: dict[str, Any],
    combined_transcript: str,
    queue_row: dict[str, Any],
    severity_oracle: dict[str, Any] | None,
) -> dict[str, bool]:
    """Evaluate all 12 Lane-10 required controls from draft content + transcript."""
    full_text = draft_meta.get("full_text", "")
    combined_probe = (full_text + " " + combined_transcript + " " + json.dumps(queue_row)).lower()

    # 1. clean_negative_control
    nc, _ = _check_negative_controls(queue_row, full_text + combined_transcript, severity_oracle)
    clean_negative_control = bool(nc)

    # 2. adjacent_condition_control
    adjacent_condition_control = (
        draft_meta.get("has_adjacent_condition", False)
        or bool(_ADJACENT_CONDITION_RE.search(combined_transcript))
    )

    # 3. production_path_proof (only required for cosmos/timing/liveness claims)
    claim_classes = _detect_claim_classes(queue_row)
    if claim_classes["timing_persistence_liveness"] or claim_classes["cosmos_network"]:
        pp, _ = _check_production_path(queue_row, full_text + combined_transcript)
        production_path_proof = bool(pp)
    else:
        production_path_proof = True  # N/A for EVM/bridge findings

    # 4. no_synthetic_state_seeding
    synth = _check_synthetic_state(full_text + combined_transcript)
    no_synthetic_state_seeding = synth != "detected"

    # 5. no_private_field_reflection
    reflection_in_draft = draft_meta.get("has_reflection", False)
    reflection_in_transcript = bool(_REFLECTION_RE.search(combined_transcript))
    # Disclosed if rebuttal marker present
    disclosed = bool(re.search(r"r30[- ]rebuttal", combined_probe, re.IGNORECASE))
    no_private_field_reflection = not (reflection_in_draft or reflection_in_transcript) or disclosed

    # 6. restart_behavior (only required for persistence/permanent claims)
    if claim_classes["timing_persistence_liveness"]:
        rs, _ = _check_restart(queue_row, full_text + combined_transcript)
        restart_behavior = bool(rs)
    else:
        restart_behavior = True  # N/A for EVM/bridge findings

    # 7. multi_validator_network_claims (only required when cosmos/network claim)
    if claim_classes["cosmos_network"] or claim_classes["timing_persistence_liveness"]:
        mv, _ = _check_multi_validator(queue_row, full_text + combined_transcript)
        multi_validator_network_claims = bool(mv)
    else:
        multi_validator_network_claims = True  # N/A, counts as pass

    # 8. real_backend_db_storage (only for DB/storage/timing claims)
    if claim_classes["timing_persistence_liveness"]:
        real_backend_db_storage = production_path_proof
    else:
        real_backend_db_storage = True  # N/A

    # 9. no_teardown_contamination
    no_teardown_contamination = not draft_meta.get("has_teardown_contamination", False)

    # 10. exact_command_and_transcript
    exact_command_and_transcript = (
        draft_meta.get("has_exact_command", False)
        or bool(re.search(r"```\s*(bash|sh|console|forge|go|cargo|pytest)", combined_transcript, re.IGNORECASE))
    )

    # 11. commit_hash_or_config
    commit_hash_or_config = (
        draft_meta.get("has_commit_hash", False)
        or draft_meta.get("has_config_ref", False)
    )

    # 12. inline_poc_body (for paste-ready reports)
    inline_poc_body = draft_meta.get("has_inline_poc", False)

    return {
        "clean_negative_control": clean_negative_control,
        "adjacent_condition_control": adjacent_condition_control,
        "production_path_proof": production_path_proof,
        "no_synthetic_state_seeding": no_synthetic_state_seeding,
        "no_private_field_reflection": no_private_field_reflection,
        "restart_behavior": restart_behavior,
        "multi_validator_network_claims": multi_validator_network_claims,
        "real_backend_db_storage": real_backend_db_storage,
        "no_teardown_contamination": no_teardown_contamination,
        "exact_command_and_transcript": exact_command_and_transcript,
        "commit_hash_or_config": commit_hash_or_config,
        "inline_poc_body": inline_poc_body,
    }


def _lane10_remaining_triager_questions(
    controls: dict[str, bool],
    draft_meta: dict[str, Any],
    queue_row: dict[str, Any],
    open_blockers: list[str],
) -> list[str]:
    """Generate a list of remaining triager questions from failed controls."""
    questions: list[str] = []

    if not controls["clean_negative_control"]:
        questions.append(
            "Provide a clean negative control: a run without the exploit applied that "
            "confirms the outcome is absent under normal conditions."
        )
    if not controls["adjacent_condition_control"]:
        questions.append(
            "Add an adjacent-condition control: demonstrate the bug does NOT fire under "
            "a boundary condition just outside the trigger envelope."
        )
    if not controls["production_path_proof"]:
        questions.append(
            "Supply production-path evidence: use a real DB backend (GoLevelDB/PebbleDB), "
            "no MemDB or timing shims. Show the path through the real ABCI/node surface."
        )
    if not controls["no_synthetic_state_seeding"]:
        questions.append(
            "Remove synthetic state seeding (MemDB, fake-time shims, private-field reflection). "
            "Rebuild on a real persistent backend with no injected delay."
        )
    if not controls["no_private_field_reflection"]:
        questions.append(
            "Disclose and justify any private-field reflection or unsafe writes. "
            "Use a Rule-30 rebuttal marker if the access is read-only inspection only."
        )
    if not controls["restart_behavior"]:
        questions.append(
            "Demonstrate restart/survival behavior: show the state persists across a node "
            "restart, confirming the claim is not ephemeral."
        )
    if not controls["multi_validator_network_claims"]:
        questions.append(
            "Add a multi-validator demonstration: network-level liveness/consensus claims "
            "require >=2 validators or equivalent subprocess/binary nodes."
        )
    if not controls["real_backend_db_storage"]:
        questions.append(
            "Use a real persistent backend (goleveldb, pebbledb, rocksdb on a filesystem "
            "tempdir). No MemDB for DB/storage/timing claims at High+."
        )
    if not controls["no_teardown_contamination"]:
        questions.append(
            "Fix teardown contamination: a panic or deadlock in t.Cleanup/AfterEach "
            "is not the bug - isolate the defect from test-framework cleanup."
        )
    if not controls["exact_command_and_transcript"]:
        questions.append(
            "Include the exact command to reproduce (bash/forge/go/cargo code block) "
            "and the full test transcript with PASS/FAIL lines."
        )
    if not controls["commit_hash_or_config"]:
        questions.append(
            "Pin the audit commit hash or config version so the reviewer can reproduce "
            "at the exact codebase state."
        )
    if not controls["inline_poc_body"]:
        questions.append(
            "Inline the full PoC body in the report. Pointer-only ('see attached file') "
            "is not accepted; paste the complete test function."
        )

    # Add any open blockers not already covered by a question above
    for b in open_blockers:
        short = b.split(":")[0].replace("_", " ").upper()
        # Skip LANE10_MISSING_* blockers - they are already covered by control questions
        if "LANE10_MISSING" in b.upper():
            continue
        if not any(short[:20] in q.upper() for q in questions):
            questions.append(f"Resolve gate blocker: {b}")

    return questions


# Provider challenge (MiniMax adversarial-kill) --------------------------

def _run_provider_challenge(
    draft_path: Path,
    draft_meta: dict[str, Any],
    controls: dict[str, bool],
    open_blockers: list[str],
    workspace_path: Path,
) -> dict[str, Any]:
    """Run a MiniMax adversarial-kill challenge against the draft.

    Requires AUDITOOOR_LLM_NETWORK_CONSENT=1 in the environment.
    Returns a challenge result dict (advisory only).
    """
    consent = os.environ.get("AUDITOOOR_LLM_NETWORK_CONSENT", "")
    if consent != "1":
        return {
            "skipped": True,
            "reason": "AUDITOOOR_LLM_NETWORK_CONSENT not set to 1; provider challenge skipped",
        }

    # Build the falsification challenge prompt (adversarial-kill template format)
    failed_controls = [k for k, v in controls.items() if not v]
    title = draft_meta.get("title", draft_path.stem)
    severity = draft_meta.get("severity", "unknown")
    summary = draft_meta.get("summary", "")
    attack_classes = draft_meta.get("attack_classes", [])
    draft_excerpt = draft_meta.get("full_text", "")[:2000]

    candidate_list_lines = [
        f"- Proposal A: \"{title}\" (severity: {severity}) - "
        f"attack_class: {', '.join(attack_classes) or 'unknown'}"
    ]
    if failed_controls:
        candidate_list_lines.append(
            f"  Failed controls detected locally: {', '.join(failed_controls)}"
        )

    open_blockers_text = "\n".join(f"  - {b}" for b in open_blockers) or "  (none)"

    prompt_text = f"""\
workspace_path: {workspace_path}
memory_context: |
  context_pack_id: lane10_falsification_challenge:{draft_path.stem}
  context_pack_hash: 0aaf0913b0a441c2c3ca55fd04c2942dc419024cefbf7a102a99d7100a3ef02c
  source_refs:
    - {draft_path}
candidate_list: |
{chr(10).join('  ' + l for l in candidate_list_lines)}
oos_text: none
truncation_flag: complete
target_files:
  - {draft_path}
hypotheses:
  - "The PoC may not include a clean negative control (without exploit applied)."
  - "The mechanism claim may not be precisely backed by source evidence at the cited line."
  - "Adjacent-condition control may be missing (boundary just outside trigger envelope)."
prior_failed_attempts: none
expected_output_shape: |
  Respond with a JSON object:
  {{
    "verdict": "KILL" or "WEAKEN" or "KEEP",
    "kill_reason": str or null,
    "keep_reason": str or null,
    "missing_proof_artifacts": [str],
    "severity_downgrade_argument": str,
    "duplicate_oos_argument": str or null,
    "minimal_falsification_test": str,
    "source_citation_requirements": [str],
    "open_blockers_assessment": [str]
  }}

---

# Task: Lane-10 PoC Falsification Challenge

You are a skeptical triager reviewing a High/Critical draft finding.
Your task is to adversarially challenge this PoC. NEVER invent new candidates.

## Draft Title
{title}

## Severity Claimed
{severity.capitalize()}

## Summary
{summary}

## Failed Controls (detected locally)
{chr(10).join('- ' + c for c in failed_controls) or "(none)"}

## Open Blockers
{open_blockers_text}

## Draft Excerpt (first 2000 chars)
{draft_excerpt}

## Output: JSON only, no prose before or after the JSON block.
"""

    # Write prompt to agent_outputs
    agent_out_dir = workspace_path / "agent_outputs"
    agent_out_dir.mkdir(parents=True, exist_ok=True)
    slug = re.sub(r"[^a-z0-9_]", "_", draft_path.stem.lower())[:40]
    ts = int(time.time())
    prompt_path = agent_out_dir / f"lane10_minimax_challenge_{slug}_{ts}_prompt.md"
    output_path = agent_out_dir / f"lane10_minimax_challenge_{slug}_{ts}_output.txt"
    prompt_path.write_text(prompt_text, encoding="utf-8")

    # Dispatch via dispatch-preflight (dry-run first, then live)
    dispatch_tool = workspace_path / "tools" / "dispatch-preflight.py"
    if not dispatch_tool.exists():
        return {
            "skipped": True,
            "reason": "dispatch-preflight.py not found; provider challenge skipped",
            "prompt_path": str(prompt_path),
        }

    # Dry-run to validate
    dry_run_args = [
        sys.executable, str(dispatch_tool),
        "--template", "adversarial-kill",
        "--task-type", "adversarial-kill",
        "--provider", "minimax",
        "--prompt-file", str(prompt_path),
        "--workspace", str(workspace_path),
        "--dry-run",
    ]
    try:
        dr_result = subprocess.run(
            dry_run_args, capture_output=True, text=True, timeout=30
        )
        dry_run_ok = dr_result.returncode == 0
        dry_run_output = (dr_result.stdout + dr_result.stderr).strip()
    except Exception as exc:  # noqa: BLE001
        return {
            "skipped": True,
            "reason": f"dispatch-preflight dry-run error: {exc}",
            "prompt_path": str(prompt_path),
        }

    if not dry_run_ok:
        return {
            "skipped": True,
            "reason": f"dispatch-preflight dry-run failed: {dry_run_output[:300]}",
            "prompt_path": str(prompt_path),
        }

    # Live dispatch
    live_args = [
        sys.executable, str(dispatch_tool),
        "--template", "adversarial-kill",
        "--task-type", "adversarial-kill",
        "--provider", "minimax",
        "--prompt-file", str(prompt_path),
        "--workspace", str(workspace_path),
        "--output-file", str(output_path),
    ]
    try:
        live_result = subprocess.run(
            live_args, capture_output=True, text=True, timeout=120
        )
        live_rc = live_result.returncode
        live_output = (live_result.stdout + live_result.stderr).strip()
    except subprocess.TimeoutExpired:
        return {
            "skipped": False,
            "rc": -1,
            "reason": "dispatch timeout after 120s",
            "prompt_path": str(prompt_path),
        }
    except Exception as exc:  # noqa: BLE001
        return {
            "skipped": False,
            "rc": -1,
            "reason": f"dispatch error: {exc}",
            "prompt_path": str(prompt_path),
        }

    # Read raw output if written
    raw_output = ""
    if output_path.exists():
        raw_output = output_path.read_text(encoding="utf-8", errors="replace")

    # Attempt to parse JSON response from the provider
    parsed: dict[str, Any] = {}
    json_match = re.search(r"\{[\s\S]*\}", raw_output or live_output)
    if json_match:
        try:
            parsed = json.loads(json_match.group(0))
        except json.JSONDecodeError:
            pass

    # Normalize via provider-output-normalizer if available
    normalizer_tool = workspace_path / "tools" / "provider-output-normalizer.py"
    normalized_entry: dict[str, Any] | None = None
    if normalizer_tool.exists() and (raw_output or live_output):
        token_est = len(prompt_text.split()) + len((raw_output or live_output).split())
        norm_args = [
            sys.executable, str(normalizer_tool),
            "--provider", "minimax",
            "--model", "MiniMax-M2.7",
            "--task-type", "adversarial-kill",
            "--prompt-path", str(prompt_path),
            "--output-path", str(output_path) if output_path.exists() else str(prompt_path),
            "--token-estimate", str(token_est),
            "--json",
        ]
        try:
            norm_result = subprocess.run(
                norm_args, capture_output=True, text=True, timeout=30
            )
            if norm_result.returncode == 0 and norm_result.stdout.strip():
                norm_data = json.loads(norm_result.stdout.strip())
                normalized_entry = norm_data
                # Append to provider_normalized_work_queue.jsonl
                queue_file = workspace_path / "reports" / "provider_normalized_work_queue.jsonl"
                queue_file.parent.mkdir(parents=True, exist_ok=True)
                with queue_file.open("a", encoding="utf-8") as qf:
                    qf.write(json.dumps(normalized_entry, sort_keys=True) + "\n")
        except Exception:  # noqa: BLE001
            pass

    return {
        "skipped": False,
        "rc": live_rc,
        "provider": "minimax",
        "model": "MiniMax-M2.7",
        "task_type": "adversarial-kill",
        "prompt_path": str(prompt_path),
        "output_path": str(output_path),
        "dry_run_ok": dry_run_ok,
        "parsed_response": parsed or None,
        "raw_excerpt": (raw_output or live_output)[:500],
        "normalized_entry": normalized_entry,
        "advisory": True,
    }


# Repo root detection ----------------------------------------------------

def _repo_root() -> Path:
    p = Path(__file__).resolve().parent.parent
    return p


def _tool(name: str) -> Path:
    return _repo_root() / "tools" / name


# Harness execution ------------------------------------------------------

def _run_cmd(
    cmd: str,
    timeout: int = 120,
) -> tuple[int, str, str]:
    """Run shell command; return (returncode, stdout, stderr)."""
    try:
        result = subprocess.run(
            cmd,
            shell=True,
            capture_output=True,
            text=True,
            timeout=timeout,
        )
        return result.returncode, result.stdout, result.stderr
    except subprocess.TimeoutExpired:
        return -1, "", f"TIMEOUT after {timeout}s"
    except Exception as exc:  # noqa: BLE001
        return -1, "", f"ERROR: {exc}"


# Composed-tool helpers --------------------------------------------------

def _call_tool(
    tool_path: Path,
    extra_args: list[str],
    *,
    input_text: str | None = None,
    timeout: int = 60,
) -> tuple[int, str, str]:
    """Call a sibling tool as a subprocess.  Degrades gracefully if absent."""
    if not tool_path.exists():
        return -2, "", f"TOOL_ABSENT: {tool_path.name}"
    cmd_parts = [sys.executable, str(tool_path)] + extra_args
    try:
        result = subprocess.run(
            cmd_parts,
            capture_output=True,
            text=True,
            timeout=timeout,
            input=input_text,
        )
        return result.returncode, result.stdout, result.stderr
    except subprocess.TimeoutExpired:
        return -1, "", f"TIMEOUT {tool_path.name}"
    except Exception as exc:  # noqa: BLE001
        return -1, "", f"ERROR calling {tool_path.name}: {exc}"


# Claim-class detection --------------------------------------------------

def _detect_claim_classes(row: dict[str, Any]) -> dict[str, bool]:
    """Return a mapping of claim class flags based on queue-row content."""
    probe_text = " ".join([
        str(row.get("title", "")),
        str(row.get("attack_class", "")),
        str(row.get("impact_path", "")),
        str(row.get("next_command", "")),
        " ".join(str(b) for b in row.get("blockers", [])),
        str(row.get("proof_path", "")),
    ])

    return {
        "timing_persistence_liveness": bool(_TIMING_PERSISTENCE_RE.search(probe_text)),
        "cosmos_network": bool(_COSMOS_NETWORK_RE.search(probe_text)),
        "evm_accounting": bool(_EVM_ACCOUNTING_RE.search(probe_text)),
        "bridge": bool(_BRIDGE_RE.search(probe_text)),
    }


# Severity helpers -------------------------------------------------------

def _severity_rank(row: dict[str, Any], oracle: dict[str, Any] | None) -> int:
    raw = "unknown"
    if oracle:
        raw = str(oracle.get("likely_severity", oracle.get("severity", "unknown"))).lower()
    if raw == "unknown":
        raw = str(row.get("likely_severity", "unknown")).lower()
    return SEVERITY_RANK.get(raw, 0)


# Control checks ---------------------------------------------------------

def _check_negative_controls(
    row: dict[str, Any],
    transcript: str,
    oracle: dict[str, Any] | None,
) -> tuple[list[str], str | None]:
    """Return (controls_found, blocker_or_None)."""
    controls: list[str] = []
    probe = (transcript + " " + json.dumps(row)).lower()

    control_patterns = [
        r"control[_ ]?test",
        r"negative[_ ]?control",
        r"baseline[_ ]?(run|test|scenario)",
        r"without[_ ]?(bug|exploit|flaw|attack|patch)",
        r"sanity[_ ]?check",
        r"alternative[_ ]?cause",
        r"no[_ ]?control[_ ]?reason",
        r"no_control_reason",
        r"r34[- ]rebuttal",
        r"control_rebuttal",
    ]
    for pat in control_patterns:
        if re.search(pat, probe, re.IGNORECASE):
            controls.append(pat)

    if controls:
        return controls, None

    # Check oracle for explicit waiver
    if oracle and oracle.get("no_control_reason"):
        controls.append("oracle:no_control_reason")
        return controls, None

    return [], "High/Critical requires a negative control or NO_CONTROL_REASON; none found"


def _check_production_path(
    row: dict[str, Any],
    transcript: str,
) -> tuple[list[str], str | None]:
    """Check production-path evidence for timing/persistence/liveness claims."""
    found: list[str] = []
    probe = (transcript + " " + json.dumps(row)).lower()

    prod_signals = [
        r"goleveldb|pebbledb|rocksdb",
        r"production.?(db|backend|storage)",
        r"real.?(db|node|validator|backend)",
        r"simapp\.setup",
        r"node\.newnode",
        r"network\.new",
        r"cometbft.start",
        r"applyblock|finalizeblock",
        r"broadcasttxsync|broadcasttxasync",
        r"exec\.command",
        r"production.profile",
        r"r30.rebuttal",
        r"<!-- r30",
    ]
    for pat in prod_signals:
        if re.search(pat, probe, re.IGNORECASE):
            found.append(pat)

    if found:
        return found, None
    return [], "timing/persistence/liveness claim requires production-path evidence; none found"


def _check_restart(
    row: dict[str, Any],
    transcript: str,
) -> tuple[list[str], str | None]:
    """Check restart/survival evidence for persistence claims."""
    found: list[str] = []
    probe = (transcript + " " + json.dumps(row)).lower()

    restart_signals = [
        r"restart",
        r"surviv(e|al|ed)",
        r"after.{0,20}(reboot|restart|recovery)",
        r"persist.{0,30}(across|after|through)",
        r"r22.rebuttal",
        r"<!-- r22",
        r"permanent.{0,30}(proof|verified|confirmed)",
    ]
    for pat in restart_signals:
        if re.search(pat, probe, re.IGNORECASE):
            found.append(pat)

    if found:
        return found, None
    return [], "persistence/permanent claim requires restart-survival evidence; none found"


def _check_multi_validator(
    row: dict[str, Any],
    transcript: str,
) -> tuple[list[str], str | None]:
    """Check multi-validator evidence for cosmos/network-level claims."""
    found: list[str] = []
    probe = (transcript + " " + json.dumps(row)).lower()

    mv_signals = [
        r"multi.?validator",
        r">=\s*2\s*validator",
        r"4.?validator",
        r"network.{0,20}(level|wide|global)",
        r"two.?validator",
        r"second.?validator",
        r"validator.{0,10}(set|mesh|cluster)",
        r"r30.rebuttal",
        r"<!-- r30",
    ]
    for pat in mv_signals:
        if re.search(pat, probe, re.IGNORECASE):
            found.append(pat)

    if found:
        return found, None
    return [], "cosmos/network-level claim requires multi-validator evidence; none found"


def _check_synthetic_state(transcript: str) -> str:
    """Detect MemDB / fake-time / reflection shims in the transcript."""
    probe = transcript.lower()
    shim_patterns = [
        r"memdb|mem_db|newmemdb",
        r"slowbatchdb|timing.?shim|delay.?shim",
        r"reflect\.valueof|unsafe\.pointer",
        r"fake.?(time|clock)",
    ]
    detected = any(re.search(p, probe) for p in shim_patterns)
    return "detected" if detected else "none"


# Composed-tool dispatch -------------------------------------------------

def _run_control_test_discipline(
    draft_md_path: Path,
    severity: str,
    poc_dir: Path | None,
) -> tuple[int, dict[str, Any] | None]:
    """Call control-test-discipline-check.py; return (rc, json_payload)."""
    tool = _tool("control-test-discipline-check.py")
    args = [str(draft_md_path), "--severity", severity, "--json"]
    if poc_dir and poc_dir.exists():
        args += ["--poc-dir", str(poc_dir)]
    rc, stdout, _ = _call_tool(tool, args)
    try:
        return rc, json.loads(stdout)
    except (json.JSONDecodeError, ValueError):
        return rc, None


def _run_production_profile_preflight(draft_md_path: Path) -> tuple[int, str]:
    """Call production-profile-preflight-check.py; return (rc, stdout)."""
    tool = _tool("production-profile-preflight-check.py")
    rc, stdout, stderr = _call_tool(tool, [str(draft_md_path)])
    return rc, (stdout + stderr).strip()


def _run_panic_context_audit(
    draft_md_path: Path,
    severity: str,
) -> tuple[int, dict[str, Any] | None]:
    """Call panic-context-audit.py; return (rc, json_payload)."""
    tool = _tool("panic-context-audit.py")
    args = [str(draft_md_path), "--severity", severity, "--json"]
    rc, stdout, _ = _call_tool(tool, args)
    try:
        return rc, json.loads(stdout)
    except (json.JSONDecodeError, ValueError):
        return rc, None


# Verdict computation ----------------------------------------------------

def _compute_verdict(
    cmd_rc: int | None,
    cmd_ran: bool,
    open_blockers: list[str],
    oracle: dict[str, Any] | None,
    row: dict[str, Any],
) -> str:
    """Determine the final verdict from evidence."""
    # not_in_scope if oracle says so
    if oracle:
        scope = str(oracle.get("scope", "in_scope")).lower()
        if scope in ("out_of_scope", "not_in_scope", "oos"):
            return "not_in_scope"

    proof_path = str(row.get("proof_path", "missing")).lower()
    if proof_path == "missing" and not cmd_ran:
        return "needs_harness"

    if cmd_ran:
        if cmd_rc is None or cmd_rc < 0:
            # harness could not run
            if open_blockers:
                return "needs_harness"
            return "inconclusive"
        if cmd_rc == 0:
            # harness passed - still need controls
            if open_blockers:
                # controls missing - cannot claim proved
                return "inconclusive"
            return "proved"
        # harness failed (non-zero exit)
        return "disproved"

    # No command ran, no harness
    if open_blockers:
        return "needs_harness"
    return "inconclusive"


# Main runner ------------------------------------------------------------

def run(
    queue_row: dict[str, Any],
    *,
    cmd: str | None = None,
    source_refs: list[str] | None = None,
    severity_oracle: dict[str, Any] | None = None,
    transcript_dir: Path | None = None,
    poc_dir: Path | None = None,
) -> dict[str, Any]:
    """Execute the falsification pipeline and return the result dict."""
    candidate_id = str(
        queue_row.get("lead_id") or queue_row.get("candidate_id") or "UNKNOWN"
    )
    severity_raw = str(
        (severity_oracle or {}).get("likely_severity")
        or (severity_oracle or {}).get("severity")
        or queue_row.get("likely_severity", "unknown")
    ).lower()
    sev_rank = SEVERITY_RANK.get(severity_raw, 0)
    claim_classes = _detect_claim_classes(queue_row)

    result: dict[str, Any] = {
        "schema": SCHEMA_VERSION,
        "candidate_id": candidate_id,
        "verdict": "inconclusive",
        "commands_run": [],
        "transcript_paths": [],
        "negative_controls": [],
        "production_path_checks": [],
        "restart_checks": [],
        "multi_validator_checks": [],
        "synthetic_state_status": "none",
        "open_blockers": [],
    }

    # ---- Step 1: run the harness command ---------------------------------
    cmd_rc: int | None = None
    cmd_ran = False
    combined_transcript = ""

    if cmd:
        t_start = time.monotonic()
        cmd_rc, stdout, stderr = _run_cmd(cmd)
        elapsed = time.monotonic() - t_start
        combined_transcript = stdout + "\n" + stderr
        cmd_ran = True

        result["commands_run"].append({
            "cmd": cmd,
            "returncode": cmd_rc,
            "elapsed_s": round(elapsed, 3),
        })

        # --- Empty-run guard -----------------------------------------------
        # Detect zero-tests-executed even when the process exits 0.
        # A forge/go/cargo/pytest run that executed no tests must not be
        # treated as a passing harness.
        empty_run_label = _detect_empty_run(combined_transcript)
        if empty_run_label is not None:
            # Override exit code so _compute_verdict cannot reach 'proved'
            cmd_rc = -3  # sentinel: empty run (not a real failure)
            result["commands_run"][-1]["empty_run"] = True
            result["open_blockers"].append(
                f"EMPTY_RUN: harness command ran but executed zero tests "
                f"({empty_run_label}); verdict cannot be 'proved'"
            )

        # Write transcript to file if a dir is available
        if transcript_dir:
            ts = int(time.time())
            t_path = transcript_dir / f"transcript_{candidate_id}_{ts}.txt"
            t_path.write_text(combined_transcript, encoding="utf-8")
            result["transcript_paths"].append(str(t_path))

        # Detect synthetic-state shims from transcript
        result["synthetic_state_status"] = _check_synthetic_state(combined_transcript)

    # ---- Step 2: build a minimal draft for composed-tool calls -----------
    with tempfile.NamedTemporaryFile(
        mode="w",
        suffix=".md",
        prefix=f"falsif_{candidate_id}_",
        delete=False,
        encoding="utf-8",
    ) as tf:
        draft_path = Path(tf.name)
        draft_content = (
            f"# Falsification draft: {candidate_id}\n\n"
            f"Severity: {severity_raw.capitalize()}\n\n"
            f"Attack class: {queue_row.get('attack_class', '')}\n\n"
            f"Title: {queue_row.get('title', '')}\n\n"
            f"Impact path: {queue_row.get('impact_path', '')}\n\n"
            f"Proof path: {queue_row.get('proof_path', '')}\n\n"
            f"## Transcript\n\n{combined_transcript}\n\n"
            f"## Source refs\n\n{', '.join(source_refs or [])}\n"
        )
        tf.write(draft_content)

    composed_notes: list[str] = []

    try:
        # ---- Step 3: control-test discipline check (Rule 34) -----------
        if sev_rank >= 3:  # High or Critical
            r34_rc, r34_payload = _run_control_test_discipline(
                draft_path, severity_raw, poc_dir
            )
            if r34_payload:
                verdict_r34 = r34_payload.get("verdict", "")
                # Extract control signals
                if "control" in str(r34_payload).lower():
                    # Parse controls found from the payload
                    for key in ("control_signals", "controls_found", "controls"):
                        if isinstance(r34_payload.get(key), list):
                            result["negative_controls"].extend(r34_payload[key])
            elif r34_rc == -2:
                composed_notes.append("control-test-discipline-check.py absent; skipped")
            # Also scan the transcript directly
            nc, nc_blocker = _check_negative_controls(
                queue_row, combined_transcript, severity_oracle
            )
            result["negative_controls"].extend(nc)
        else:
            # Low/Medium - still check transcript for controls (informational)
            nc, _ = _check_negative_controls(
                queue_row, combined_transcript, severity_oracle
            )
            result["negative_controls"].extend(nc)

        # ---- Step 4: production-profile preflight (Rule 30) -----------
        if claim_classes["timing_persistence_liveness"] or claim_classes["cosmos_network"]:
            r30_rc, r30_out = _run_production_profile_preflight(draft_path)
            if r30_rc == -2:
                composed_notes.append("production-profile-preflight-check.py absent; skipped")
            # Regardless of tool result, also scan transcript
            pp_found, pp_blocker = _check_production_path(queue_row, combined_transcript)
            result["production_path_checks"].extend(pp_found)

            # Restart checks for persistence claims
            rs_found, rs_blocker = _check_restart(queue_row, combined_transcript)
            result["restart_checks"].extend(rs_found)

        # ---- Step 5: panic-context audit for liveness claims ----------
        if claim_classes["timing_persistence_liveness"] and sev_rank >= 3:
            panic_rc, panic_payload = _run_panic_context_audit(draft_path, severity_raw)
            if panic_rc == -2:
                composed_notes.append("panic-context-audit.py absent; skipped")

        # ---- Step 6: multi-validator check for cosmos network claims --
        if claim_classes["cosmos_network"]:
            mv_found, mv_blocker = _check_multi_validator(queue_row, combined_transcript)
            result["multi_validator_checks"].extend(mv_found)

    finally:
        draft_path.unlink(missing_ok=True)

    # ---- Step 7: synthesize open blockers ---------------------------------
    if sev_rank >= 3:  # High or Critical
        # Require negative control
        if not result["negative_controls"]:
            result["open_blockers"].append(
                "MISSING_NEGATIVE_CONTROL: High/Critical requires a negative control "
                "or explicit NO_CONTROL_REASON"
            )

    if claim_classes["timing_persistence_liveness"]:
        if not result["production_path_checks"]:
            result["open_blockers"].append(
                "MISSING_PRODUCTION_PATH: timing/persistence/liveness claim requires "
                "production-path evidence (real DB, no MemDB/timing shims)"
            )
        if not result["restart_checks"]:
            result["open_blockers"].append(
                "MISSING_RESTART_EVIDENCE: timing/persistence/liveness claim requires "
                "restart/survival evidence for permanent-class impact"
            )

    if claim_classes["cosmos_network"] and not result["multi_validator_checks"]:
        result["open_blockers"].append(
            "MISSING_MULTI_VALIDATOR: cosmos/app-chain network-level claim requires "
            "multi-validator evidence (>=2 validators or subprocess nodes)"
        )

    if result["synthetic_state_status"] == "detected":
        result["open_blockers"].append(
            "SYNTHETIC_STATE_DETECTED: MemDB/timing-shim/reflection detected in "
            "transcript; production-profile evidence required for High/Critical"
        )

    if composed_notes:
        result["open_blockers"].extend(
            [f"COMPOSED_TOOL_NOTE: {n}" for n in composed_notes]
        )

    # ---- Step 8: final verdict -------------------------------------------
    result["verdict"] = _compute_verdict(
        cmd_rc, cmd_ran, result["open_blockers"], severity_oracle, queue_row
    )

    # Deduplicate lists
    result["negative_controls"] = list(dict.fromkeys(result["negative_controls"]))
    result["production_path_checks"] = list(dict.fromkeys(result["production_path_checks"]))
    result["restart_checks"] = list(dict.fromkeys(result["restart_checks"]))
    result["multi_validator_checks"] = list(dict.fromkeys(result["multi_validator_checks"]))

    return result


# Lane-10 draft runner --------------------------------------------------

def run_draft(
    draft_path: Path,
    *,
    queue_row: dict[str, Any] | None = None,
    cmd: str | None = None,
    source_refs: list[str] | None = None,
    severity_oracle: dict[str, Any] | None = None,
    transcript_dir: Path | None = None,
    poc_dir: Path | None = None,
    provider_challenge: bool = False,
    workspace_path: Path | None = None,
) -> dict[str, Any]:
    """Lane-10 entry point: parse a draft.md and run all Lane-10 required checks.

    Returns the Lane-10 artifact shape (a superset of the standard shape).
    """
    draft_meta = _parse_draft(draft_path)

    # Synthesise queue-row from draft if not provided
    if queue_row is None:
        queue_row = _draft_to_queue_row(draft_meta, draft_path)

    # Derive severity from draft if not in oracle/row
    if severity_oracle is None and draft_meta["severity"] != "unknown":
        severity_oracle = {"likely_severity": draft_meta["severity"], "scope": "in_scope"}

    # Run the standard falsification pipeline
    base_result = run(
        queue_row,
        cmd=cmd,
        source_refs=source_refs,
        severity_oracle=severity_oracle,
        transcript_dir=transcript_dir,
        poc_dir=poc_dir,
    )

    # Extract combined transcript (from commands_run)
    combined_transcript = ""
    for cr in base_result.get("commands_run", []):
        combined_transcript += str(cr.get("cmd", "")) + " "

    # Evaluate all 12 Lane-10 controls
    controls = _eval_lane10_controls(
        draft_meta, combined_transcript, queue_row, severity_oracle
    )

    # Propagate synthetic-state status from draft scan into base_result
    # (base_result only scanned the harness transcript, not the draft body)
    if base_result["synthetic_state_status"] == "none":
        draft_synth = _check_synthetic_state(draft_meta.get("full_text", ""))
        if draft_synth == "detected":
            base_result["synthetic_state_status"] = "detected"
            base_result["open_blockers"].append(
                "SYNTHETIC_STATE_DETECTED: MemDB/timing-shim/reflection detected in "
                "draft body; production-profile evidence required for High/Critical"
            )

    # Severity rank
    sev_raw = str(
        (severity_oracle or {}).get("likely_severity")
        or queue_row.get("likely_severity", "unknown")
    ).lower()
    sev_rank = SEVERITY_RANK.get(sev_raw, 0)

    # Derive proof_claim and mechanism from draft
    proof_claim = (
        draft_meta["title"]
        or queue_row.get("title", "")
        or draft_path.stem
    )
    mechanism = (
        draft_meta["root_cause"]
        or draft_meta["summary"]
        or queue_row.get("impact_path", "")
    )[:500]

    # Block weak High/Critical proofs: any failed CRITICAL control for High+
    # adds a blocker that prevents 'proved'
    critical_controls_for_high = [
        "clean_negative_control",
        "no_synthetic_state_seeding",
        "exact_command_and_transcript",
        "commit_hash_or_config",
        "inline_poc_body",
    ]
    if sev_rank >= 3:  # High or Critical
        for ctrl_name in critical_controls_for_high:
            if not controls[ctrl_name]:
                blocker = f"LANE10_MISSING_{ctrl_name.upper()}: High/Critical requires '{ctrl_name}'"
                if blocker not in base_result["open_blockers"]:
                    base_result["open_blockers"].append(blocker)

    # Generate remaining triager questions
    remaining_questions = _lane10_remaining_triager_questions(
        controls, draft_meta, queue_row, base_result["open_blockers"]
    )

    # Re-compute verdict with updated blockers
    falsification_result = base_result["verdict"]
    if base_result["open_blockers"] and falsification_result == "proved":
        falsification_result = "inconclusive"
    base_result["verdict"] = falsification_result

    # Build Lane-10 artifact
    lane10_artifact: dict[str, Any] = {
        **base_result,
        "schema": SCHEMA_VERSION_LANE10,
        "draft_path": str(draft_path),
        "proof_claim": proof_claim,
        "mechanism": mechanism,
        "controls": controls,
        "falsification_result": falsification_result,
        "remaining_triager_questions": remaining_questions,
    }

    # Provider challenge (optional, advisory)
    if provider_challenge:
        ws = workspace_path or _repo_root()
        challenge_result = _run_provider_challenge(
            draft_path, draft_meta, controls, base_result["open_blockers"], ws
        )
        lane10_artifact["provider_challenge"] = challenge_result

    return lane10_artifact


# CLI --------------------------------------------------------------------

def _build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="poc-falsification-runner",
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    # Queue-row mode (original; now optional when --draft is used)
    p.add_argument(
        "--queue-row",
        default=None,
        metavar="<row.json>",
        help="Path to a Lane-2 exploit-queue row JSON file. Optional when --draft is used.",
    )
    # Lane-10 draft mode (new)
    p.add_argument(
        "--draft",
        default=None,
        metavar="<draft.md>",
        help="Path to a paste-ready or staging draft markdown file (Lane 10 mode). "
             "When supplied, severity/claim-class are parsed from the draft.",
    )
    p.add_argument(
        "--cmd",
        default=None,
        metavar="'<shell command>'",
        help="Optional harness command to execute (e.g. 'forge test -vvv').",
    )
    p.add_argument(
        "--source-refs",
        default=None,
        metavar="<refs>",
        help="Comma-separated source references (file:line or URLs).",
    )
    p.add_argument(
        "--severity-oracle",
        default=None,
        metavar="<oracle.json>",
        help="Path to a severity/scope oracle JSON file.",
    )
    p.add_argument(
        "--poc-dir",
        default=None,
        metavar="<dir>",
        help="PoC directory to pass to composed tools.",
    )
    p.add_argument(
        "--transcript-dir",
        default=None,
        metavar="<dir>",
        help="Directory to write transcript files. Defaults to a temp dir.",
    )
    p.add_argument(
        "--provider-challenge",
        action="store_true",
        help="Run a MiniMax adversarial-kill challenge (requires AUDITOOOR_LLM_NETWORK_CONSENT=1). "
             "Only active in --draft mode. Advisory only.",
    )
    p.add_argument(
        "--workspace",
        default=None,
        metavar="<dir>",
        help="Workspace root for provider dispatch. Defaults to repo root.",
    )
    p.add_argument("--json", action="store_true", help="Emit JSON output.")
    p.add_argument("--timeout", type=int, default=120, help="Harness command timeout (seconds).")
    return p


def main(argv: list[str] | None = None) -> int:
    parser = _build_parser()
    args = parser.parse_args(argv)

    # Validate: at least one of --queue-row or --draft must be provided
    if not args.queue_row and not args.draft:
        sys.stderr.write("ERROR: one of --queue-row or --draft is required\n")
        parser.print_usage(sys.stderr)
        return 2

    # Load optional oracle
    severity_oracle: dict[str, Any] | None = None
    if args.severity_oracle:
        try:
            severity_oracle = json.loads(
                Path(args.severity_oracle).read_text(encoding="utf-8")
            )
        except (FileNotFoundError, json.JSONDecodeError) as exc:
            sys.stderr.write(f"WARN: could not load --severity-oracle: {exc}\n")

    source_refs: list[str] = []
    if args.source_refs:
        source_refs = [r.strip() for r in args.source_refs.split(",") if r.strip()]

    transcript_dir: Path | None = None
    if args.transcript_dir:
        transcript_dir = Path(args.transcript_dir)
        transcript_dir.mkdir(parents=True, exist_ok=True)

    poc_dir: Path | None = Path(args.poc_dir) if args.poc_dir else None
    workspace_path: Path | None = Path(args.workspace) if args.workspace else None

    # --- Lane-10 draft mode ---
    if args.draft:
        draft_path = Path(args.draft)
        if not draft_path.exists():
            sys.stderr.write(f"ERROR: --draft file not found: {draft_path}\n")
            return 2

        # Optionally load queue-row to augment draft metadata
        queue_row: dict[str, Any] | None = None
        if args.queue_row:
            try:
                queue_row = json.loads(Path(args.queue_row).read_text(encoding="utf-8"))
            except (FileNotFoundError, json.JSONDecodeError) as exc:
                sys.stderr.write(f"WARN: could not load --queue-row: {exc}\n")

        result = run_draft(
            draft_path,
            queue_row=queue_row,
            cmd=args.cmd,
            source_refs=source_refs,
            severity_oracle=severity_oracle,
            transcript_dir=transcript_dir,
            poc_dir=poc_dir,
            provider_challenge=args.provider_challenge,
            workspace_path=workspace_path,
        )

        if args.json:
            print(json.dumps(result, indent=2, sort_keys=True))
        else:
            verdict = result.get("falsification_result", result["verdict"])
            cid = result["candidate_id"]
            blockers = result["open_blockers"]
            questions = result.get("remaining_triager_questions", [])
            print(f"[poc-falsification-runner] Lane-10 draft: {cid} -> {verdict}")
            if blockers:
                print("Open blockers:")
                for b in blockers:
                    print(f"  - {b}")
            if questions:
                print("Remaining triager questions:")
                for q in questions[:5]:
                    print(f"  ? {q}")

        return 1 if result.get("falsification_result", result["verdict"]) == "not_in_scope" else 0

    # --- Standard queue-row mode ---
    try:
        queue_row = json.loads(Path(args.queue_row).read_text(encoding="utf-8"))
    except (FileNotFoundError, json.JSONDecodeError) as exc:
        sys.stderr.write(f"ERROR loading --queue-row: {exc}\n")
        return 2

    result = run(
        queue_row,
        cmd=args.cmd,
        source_refs=source_refs,
        severity_oracle=severity_oracle,
        transcript_dir=transcript_dir,
        poc_dir=poc_dir,
    )

    if args.json:
        print(json.dumps(result, indent=2, sort_keys=True))
    else:
        verdict = result["verdict"]
        cid = result["candidate_id"]
        blockers = result["open_blockers"]
        print(f"[poc-falsification-runner] {cid} -> {verdict}")
        if blockers:
            print("Open blockers:")
            for b in blockers:
                print(f"  - {b}")

    # Exit code: 0 for proved/disproved/inconclusive/needs_harness, 1 for not_in_scope
    return 1 if result["verdict"] == "not_in_scope" else 0


if __name__ == "__main__":
    raise SystemExit(main())
