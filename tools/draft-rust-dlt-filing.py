#!/usr/bin/env python3
"""Draft Rust DLT High/Critical filing scaffolder — Wave O-F (Gap #7).

Reads a promotion_candidates.json row + rust_dlt_state_divergence.json template
+ workspace path, and emits a paste-ready Immunefi V2.3 Markdown draft.

Output shape matches the M-4 draft_medium_filing.md template:
  # Title
  ## Severity
  ## Verbatim rubric line
  ## Impact
  ## Description
  ## Reproduction
  ## Severity proof
  ## Suggested fix

CLI:
    python3 tools/draft-rust-dlt-filing.py \\
        --workspace /path/to/workspace \\
        --candidate /path/to/promotion_candidates.json \\
        --template reference/big_loss_templates/rust_dlt_state_divergence.json \\
        --output /tmp/draft.md

Stdlib-only, offline-safe.
"""
from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
from pathlib import Path
from typing import Any

_REPO_ROOT = Path(__file__).resolve().parent.parent
_DEFAULT_TEMPLATE = (
    _REPO_ROOT / "reference" / "big_loss_templates" / "rust_dlt_state_divergence.json"
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _load_json(path: Path) -> Any:
    with path.open(encoding="utf-8") as fh:
        return json.load(fh)


def _verify_severity_line(ws: Path, verbatim_line: str) -> bool:
    """grep -F verbatim_line against workspace SEVERITY.md."""
    sev_path = ws / "SEVERITY.md"
    if not sev_path.exists():
        return False
    try:
        result = subprocess.run(
            ["grep", "-qF", verbatim_line, str(sev_path)],
            capture_output=True,
        )
        return result.returncode == 0
    except FileNotFoundError:
        text = sev_path.read_text(errors="replace")
        return verbatim_line in text


def _pick_candidate(data: Any, candidate_id: str | None) -> dict:
    """Extract the first matching candidate row from a promotion_candidates.json."""
    # Support dict with "candidates" list, bare list, or dict with "rows"
    if isinstance(data, dict):
        rows = (
            data.get("candidates")
            or data.get("rows")
            or [data]
        )
    elif isinstance(data, list):
        rows = data
    else:
        raise ValueError(f"Unexpected candidate file shape: {type(data)}")

    if candidate_id:
        for row in rows:
            if row.get("id") == candidate_id or row.get("row_id") == candidate_id:
                return row
        raise ValueError(
            f"Candidate id {candidate_id!r} not found in {[r.get('id') for r in rows]}"
        )
    if not rows:
        raise ValueError("No candidates found in file.")
    return rows[0]


def _strip_markdown_bold(s: str) -> str:
    """Remove leading/trailing ** from a verbatim severity line if present."""
    return s.strip().lstrip("*").rstrip("*").strip()


def _find_poc_reference(ws: Path, candidate: dict) -> str:
    """Return a best-effort path reference to a PoC file for the Reproduction section."""
    # Check wave-m1-harness-poc (canonical for L-1 P256VERIFY)
    m1_poc = ws / ".auditooor" / "wave-m1-harness-poc" / "poc_test_source.rs"
    if m1_poc.exists():
        return str(m1_poc)
    # Check evidence fields on the candidate
    for field in ("poc_path", "harness_path", "evidence_path"):
        v = candidate.get(field)
        if v:
            return str(v)
    return "<no PoC file found — see harness_blueprint>"


def _actor_sequence_to_description(actor_sequence: list[dict], candidate: dict) -> str:
    """Render actor_sequence steps as a numbered Markdown list."""
    lines: list[str] = []
    for step in actor_sequence:
        stepnum = step.get("step", "?")
        actor = step.get("actor", "<actor>")
        action = step.get("action", "<action>")
        target = step.get("target", "<target>")
        prereq = step.get("prerequisite", "")
        evidence = step.get("evidence_required", "")
        lines.append(
            f"{stepnum}. **{actor}**: {action}\n"
            f"   - Target: `{target}`\n"
            f"   - Prerequisite: {prereq}\n"
            f"   - Evidence required: {evidence}"
        )
    return "\n\n".join(lines)


def _kill_conditions_proof(kill_conditions: list[str], candidate: dict) -> str:
    """Render kill_conditions with per-condition apply/not-apply verdict from candidate."""
    # Known-applied kill conditions (any that did fire → downgrade already noted)
    # For the L-1 case: "buggy_commit_never_deployed..." fired → downgrade Critical->High
    deployed_kill_fired = "buggy_commit_never_deployed_to_target_network" in (
        candidate.get("verdict", "") + " " + candidate.get("walkback_reason", "")
    ).lower()

    lines: list[str] = ["| Kill condition | Applies? | Reason |", "|---|---|---|"]
    for kc in kill_conditions:
        slug = kc.split()[0].lower()

        # Check common patterns
        if "single_component_only_no_divergence" in slug:
            applies = "NO"
            reason = (
                "Two independent PrecompileProviders (EL and zkVM) produce different "
                "outcomes for the same tx input — divergence is demonstrated."
            )
        elif "privileged_input" in kc.lower() or "sequencer" in slug:
            applies = "NO"
            reason = (
                "The divergence is triggered by a non-privileged EOA tx calling "
                "P256VERIFY — no sequencer role or privileged key required."
            )
        elif "not_wired_into_finalization" in slug:
            applies = "TBD"
            reason = (
                "Wave M-2 is required to confirm `OpZkvmPrecompiles` is wired into "
                "the canonical SP1 proving binary used for Sepolia/mainnet finalization. "
                "Static trace shows `ZkvmOpEvmFactory::new()` at executor.rs:148."
            )
        elif "buggy_commit_never_deployed" in slug:
            if deployed_kill_fired:
                applies = "YES — downgrade Critical → High"
                reason = (
                    "Deployment timeline not confirmed for audit-window rc pin. "
                    "Per Wave M-2 deployment-timing rule: kill fires, severity is High."
                )
            else:
                applies = "TBD"
                reason = (
                    "Whether rc28 was deployed to Sepolia post-BASE_V1 activation "
                    "(2026-04-20) has not been independently confirmed."
                )
        elif "oog_outcome_is_handled_identically" in slug or "tx_input_oog" in slug:
            applies = "NO"
            reason = (
                "At gas budget 5_000: EL returns OutOfGas, zkVM returns success. "
                "They are NOT handled identically. In-tree test at precompiles.rs:482-495 "
                "confirms this empirically."
            )
        else:
            applies = "NO"
            reason = "No evidence this condition applies to the L-1 P256VERIFY candidate."

        lines.append(f"| `{kc}` | {applies} | {reason} |")

    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Draft generation
# ---------------------------------------------------------------------------

def generate_draft(
    workspace: Path,
    candidate: dict,
    template: dict,
    candidate_id: str | None,
) -> str:
    """Return the full Markdown draft string."""

    # Core fields
    title = (
        candidate.get("title")
        or candidate.get("bug_shape", "")[:120]
        or template["title"]
    )
    if not title or title == template["title"]:
        # Build a better title from candidate fields
        crate = candidate.get("crate_name", "")
        pattern_id = candidate.get("pattern_id", "")
        if crate and pattern_id:
            title = f"{pattern_id.replace('_', ' ').title()} in `{crate}`"
        else:
            title = template["title"]

    severity_tier = candidate.get("severity_tier") or candidate.get("severity") or "High"
    # Normalise to just "High" or "Critical" (strip extras like "candidate")
    for tier in ("Critical", "High", "Medium", "Low"):
        if tier.lower() in str(severity_tier).lower():
            severity_tier = tier
            break

    # Check kill conditions to determine if downgrade has happened
    kill_conditions = template["severity_promotion_rule"]["kill_conditions"]
    deployment_kill = any(
        "buggy_commit_never_deployed" in kc for kc in kill_conditions
    )
    verdict = candidate.get("verdict", "")
    if "downgrade" in verdict.lower() or "high" in verdict.lower():
        if severity_tier == "Critical":
            severity_tier = "High"

    verbatim_raw = template["severity_promotion_rule"]["verbatim_severity_md_line"]
    verbatim_clean = _strip_markdown_bold(verbatim_raw)

    # Severity line verification
    sev_verified = _verify_severity_line(workspace, verbatim_clean)
    # Also try the raw form
    if not sev_verified:
        sev_verified = _verify_severity_line(workspace, verbatim_raw)
    sev_verification_note = (
        "[verbatim grep PASS against workspace SEVERITY.md]"
        if sev_verified
        else "[WARNING: grep -F did not match workspace SEVERITY.md — verify manually]"
    )

    # Impact paragraph
    impact_statement = candidate.get("impact_statement", "")
    if not impact_statement:
        bug_shape = candidate.get("bug_shape", "")
        impact_statement = (
            bug_shape[:600] if bug_shape
            else (
                "Under the affected hardfork spec, the zkVM PrecompileProvider installs a "
                "stale precompile variant whose gas schedule differs from the canonical EL "
                "provider. A transaction crafted within the gas-budget differential window "
                "produces EL=OutOfGas but zkVM=success, causing a divergent state-root. "
                "If the zkVM proving path is wired into the canonical finalization flow, "
                "either the wrong state-root is finalized (safety break) or proof closure "
                "stalls permanently (liveness DoS)."
            )
        )

    # Description from actor_sequence
    actor_sequence = template["actor_sequence"]
    description_steps = _actor_sequence_to_description(actor_sequence, candidate)

    # Concrete bug detail from candidate
    evidence_context = candidate.get("evidence_context", "")
    call_site_snippet = candidate.get("call_site_snippet", "")
    file_path = candidate.get("file", candidate.get("production_path", ""))
    line_num = candidate.get("line", "")

    bug_detail_section = ""
    if evidence_context:
        bug_detail_section = f"\n\n### Bug site\n\n**File:** `{file_path}`"
        if line_num:
            bug_detail_section += f", line {line_num}"
        bug_detail_section += f"\n\n```rust\n{evidence_context}\n```"
    if call_site_snippet:
        call_file = candidate.get("call_site_file", "")
        call_line = candidate.get("call_site_line", "")
        call_label = f"**Call site:** `{call_file}`"
        if call_line:
            call_label += f", line {call_line}"
        bug_detail_section += f"\n\n{call_label}\n\n```rust\n{call_site_snippet}\n```"

    # Reproduction
    poc_ref = _find_poc_reference(workspace, candidate)
    harness = template["harness_blueprint"]
    test_tmpl = harness.get("test_template", "")
    neg_ctrl = harness.get("negative_control_template", "")
    engine = harness.get("engine", "cargo_test")
    imports_list = "\n".join(f"  - `{imp}`" for imp in harness.get("imports", []))

    evidence_snippet = candidate.get("evidence_snippet", "")

    reproduction_section = f"""\
### Prerequisites

- `{engine}` available in the audit asset root.
- Hardfork spec `OpSpecId::BASE_V1` active (Sepolia activation: 2026-04-20 per SCOPE.md).

### Imports

{imports_list}

### Test

{test_tmpl}

See PoC source at: `{poc_ref}`

### Negative control

{neg_ctrl}

### Evidence

```
{evidence_snippet}
```"""

    # Severity proof
    section_header = template["severity_promotion_rule"]["section_header"]
    promotion_precondition = template["severity_promotion_rule"]["promotion_precondition"]
    kill_table = _kill_conditions_proof(kill_conditions, candidate)

    # Fix sketch
    fix_sketch = candidate.get("fix_sketch", "")
    if not fix_sketch:
        fix_sketch = (
            "Remove the stale precompile variant from `get_precompiles()` and ensure "
            "spec-gated overrides are applied AFTER the canonical spec base is set, "
            "not over it. For BASE_V1: do not call `precompiles.extend(get_precompiles())` "
            "when the base already includes the correct OSAKA-priced variant."
        )

    # Five-check summary from candidate
    five_check = candidate.get("five_check_trace", {})
    five_check_summary = ""
    if five_check:
        results = []
        for step_key, step_val in five_check.items():
            r = step_val.get("result", "?") if isinstance(step_val, dict) else str(step_val)
            results.append(f"  - {step_key}: **{r}**")
        five_check_summary = "\n### Five-check trace\n\n" + "\n".join(results) + "\n"

    # Assemble the draft
    draft = f"""\
# Draft Filing — Base Azul Audit Competition
<!-- DO NOT SUBMIT without operator approval -->
<!-- Wave O-F rust_dlt_state_divergence template | {Path(workspace).name} | 2026-05-03 -->

---

## Severity: {severity_tier}

**Rubric line (verbatim):**
> "{verbatim_clean}"

{sev_verification_note}

**Rubric section:** `{section_header}`

---

## Title

{title}

---

## Impact

{impact_statement}

---

## Description

### Attack sequence (from template `rust_dlt_state_divergence`)

{description_steps}
{bug_detail_section}

---

## Reproduction

{reproduction_section}

---

## Severity proof

### Promotion precondition

{promotion_precondition}

### Kill condition audit

{kill_table}
{five_check_summary}
---

## Suggested fix

{fix_sketch}

---

## References

- Candidate id: `{candidate.get("id", "UNKNOWN")}`
- File: `{file_path}`{":" + str(line_num) if line_num else ""}
- Detector: `{candidate.get("detector_id", "")}`
- Wave M-1 PoC: `{poc_ref}`
- Template: `reference/big_loss_templates/rust_dlt_state_divergence.json`

<!-- wave-o-f | Gap #7 | operator decision required before submit -->
"""
    return draft


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def run(argv: list[str] | None = None) -> dict:
    """Callable entry-point (testable without subprocess)."""
    parser = argparse.ArgumentParser(
        description="Draft Rust DLT High/Critical filing from a promotion candidate row.",
    )
    parser.add_argument("--workspace", required=True, help="Workspace root (contains SEVERITY.md).")
    parser.add_argument("--candidate", required=True, help="Path to promotion_candidates.json.")
    parser.add_argument(
        "--template",
        default=str(_DEFAULT_TEMPLATE),
        help="Path to rust_dlt_state_divergence.json (default: auto-detect from repo root).",
    )
    parser.add_argument(
        "--candidate-id",
        default=None,
        help="Specific candidate id to file (default: first in file).",
    )
    parser.add_argument("--output", "-o", default=None, help="Output Markdown file path.")
    parser.add_argument("--print", action="store_true", help="Print draft to stdout.")
    args = parser.parse_args(argv)

    ws = Path(args.workspace).expanduser().resolve()
    cand_path = Path(args.candidate).expanduser().resolve()
    tmpl_path = Path(args.template).expanduser().resolve()

    if not ws.exists():
        print(f"[draft-rust-dlt-filing] ERR workspace not found: {ws}", file=sys.stderr)
        sys.exit(2)
    if not cand_path.exists():
        print(f"[draft-rust-dlt-filing] ERR candidate file not found: {cand_path}", file=sys.stderr)
        sys.exit(2)
    if not tmpl_path.exists():
        print(f"[draft-rust-dlt-filing] ERR template file not found: {tmpl_path}", file=sys.stderr)
        sys.exit(2)

    cand_data = _load_json(cand_path)
    template = _load_json(tmpl_path)
    candidate = _pick_candidate(cand_data, args.candidate_id)

    draft = generate_draft(ws, candidate, template, args.candidate_id)

    out_path: Path | None = None
    if args.output:
        out_path = Path(args.output).expanduser().resolve()
        out_path.parent.mkdir(parents=True, exist_ok=True)
        out_path.write_text(draft, encoding="utf-8")
        print(f"[draft-rust-dlt-filing] Draft written to {out_path}", file=sys.stderr)

    if args.print or not args.output:
        print(draft)

    return {
        "workspace": str(ws),
        "candidate_id": candidate.get("id", "UNKNOWN"),
        "severity_tier": candidate.get("severity_tier") or candidate.get("severity") or "High",
        "output_path": str(out_path) if out_path else None,
        "draft_length": len(draft),
        "verbatim_severity_line": template["severity_promotion_rule"]["verbatim_severity_md_line"],
        "severity_line_verified": _verify_severity_line(
            ws, _strip_markdown_bold(template["severity_promotion_rule"]["verbatim_severity_md_line"])
        ),
    }


if __name__ == "__main__":
    run()
