#!/usr/bin/env python3
"""impact-contract-scaffolder.py — emit operator-fillable impact-contract spec
skeletons for harness-plan rows that are blocked on a missing impact contract.

Solves the H-03 / PR603 § Gate 2 blocker: 71 harness-plan rows are
``blocked_missing_impact_contract``. Each one needs a human-authored impact
contract spec before ``make harness-scaffold`` can produce a runnable scaffold.

This tool generates *skeletons* — markdown files structured so a human
operator (or follow-up agent) can fill them out in 30-45 min per row. It
NEVER fills in operator-decision content.

Skeleton structure per row (FN2-lesson aligned):
  - Title following the T-02 schema:
        ``<Class> in <component> leads to <Impact>``
  - Severity / Likelihood / Impact (placeholders)
  - Production-precondition section
  - Adversarial-control section
  - Measured-state-delta section (with placeholder ``assertEq`` line)
  - Borrowed-asset list
  - Test command placeholder
  - Operator decision required marker

Reference tools (read first, do not duplicate):
  - tools/high-impact-impact-contract-skeletons.py — emits *fail-closed JSON*
    skeletons for the high-impact-harness-queue (different artifact).
  - tools/dispatch-brief.sh — brief shape (markdown, mandatory-reading
    sections, operator-fillable placeholders).
  - tools/pre-submit-check.sh check 34 — title-schema enforcement (T-02).

Usage:
  python3 tools/impact-contract-scaffolder.py \\
      --workspace /Users/wolf/audits/base-azul \\
      [--plans-json <path>] \\
      [--out-dir <path>] \\
      [--statuses blocked,blocked_missing_impact_contract] \\
      [--row <row_id>] \\
      [--dry-run]

Exit codes:
  0 — skeletons emitted (or --dry-run completed)
  1 — input artifact missing / malformed
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any, Iterable

SCHEMA_VERSION = "auditooor.impact_contract_scaffolder.v1"
DEFAULT_BLOCKED_STATUSES = ("blocked", "blocked_missing_impact_contract")
TODO = "<TODO_OPERATOR>"


def slug(value: str) -> str:
    out: list[str] = []
    prev_dash = False
    for ch in value.strip().lower():
        if ch.isalnum() or ch in "._":
            out.append(ch)
            prev_dash = False
            continue
        if not prev_dash:
            out.append("-")
            prev_dash = True
    result = "".join(out).strip("-")
    return result or "row"


def load_plans(plans_path: Path) -> dict[str, Any]:
    if not plans_path.is_file():
        raise SystemExit(
            f"[impact-contract-scaffolder] ERR plans file not found: {plans_path}\n"
            f"Run `make harness-plan WS=<workspace>` first to populate harness_plans.json."
        )
    try:
        return json.loads(plans_path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise SystemExit(
            f"[impact-contract-scaffolder] ERR malformed plans JSON: {plans_path}: {exc}"
        )


def select_blocked_rows(
    plans: list[dict[str, Any]],
    statuses: Iterable[str],
    only_row: str | None,
) -> list[dict[str, Any]]:
    status_set = {s.strip() for s in statuses if s.strip()}
    out: list[dict[str, Any]] = []
    for plan in plans:
        row_id = str(plan.get("row_id") or "").strip()
        if not row_id:
            continue
        if only_row and row_id != only_row:
            continue
        status = str(plan.get("source_row_status") or "").strip()
        # Match on either source_row_status or an explicit status field if
        # operator-side schema later adds one.
        explicit = str(plan.get("status") or "").strip()
        if status in status_set or explicit in status_set:
            out.append(plan)
    return out


def derive_title(plan: dict[str, Any]) -> str:
    """Build a placeholder title in the T-02 schema:
        `<Class> in <component> leads to <Impact>`
    All three slots are TODO_OPERATOR; the harness_family + invariant_family
    are surfaced as hints so the operator knows where the row originated.
    """
    family = (plan.get("harness_family") or "").strip() or TODO
    invariant = (plan.get("source_invariant_family") or "").strip()
    component = invariant or family
    return f"{TODO}_class in {component} leads to {TODO}_impact"


def render_skeleton(plan: dict[str, Any], workspace: Path) -> str:
    row_id = str(plan.get("row_id") or "").strip()
    family = plan.get("harness_family") or ""
    invariant = plan.get("source_invariant_family") or ""
    reason = plan.get("reason") or ""
    target = plan.get("target_entrypoint") or ""
    surface = plan.get("minimal_proof_surface") or ""
    fixtures = plan.get("required_fixtures") or []
    compile_cmd = plan.get("compile_command") or ""
    expected_log = plan.get("expected_log_string") or ""
    stop_cond = plan.get("stop_condition") or ""
    first_neg = plan.get("first_negative_control") or ""

    title = derive_title(plan)

    fixture_lines = "\n".join(f"  - `{fx}`" for fx in fixtures) or f"  - {TODO}"

    sections: list[str] = [
        f"# Impact Contract Skeleton — {row_id}",
        "",
        f"> Auto-generated by `tools/impact-contract-scaffolder.py` for the H-03 /",
        f"> PR603 § Gate 2 unblock. This is a SKELETON — fill in every",
        f"> `{TODO}` marker before this row can drive `make harness-scaffold`.",
        f"> Estimated time-to-fill: 30–45 min per row.",
        "",
        "## Identity",
        "",
        f"| Field | Value |",
        f"|---|---|",
        f"| Row ID | `{row_id}` |",
        f"| Harness family | `{family}` |",
        f"| Source invariant family | `{invariant or '(none)'}` |",
        f"| Plan reason | {reason or '(none)'} |",
        f"| Target entrypoint (from plan) | `{target or TODO}` |",
        f"| Status | `blocked_missing_impact_contract` |",
        "",
        "## Title (T-02 schema)",
        "",
        f"Required shape: `<Class> in <component> leads to <Impact>` (or",
        f"`allows` / `causes` / `results in` / `enables` / `permits`).",
        f"Enforced by `pre-submit-check.sh` Check 34 (D-08).",
        "",
        f"**Proposed title (PLACEHOLDER):**",
        "",
        f"> {title}",
        "",
        f"**Operator decision required:** replace each `{TODO}_*` slot with",
        f"the concrete vulnerability class, in-scope component path, and exact",
        f"listed-impact sentence from `SEVERITY.md`.",
        "",
        "## Severity / Likelihood / Impact",
        "",
        f"- **Severity tier:** `{TODO}` (Critical / High / Medium / Low)",
        f"- **Likelihood:** `{TODO}` (High / Medium / Low — adversary cost vs reward)",
        f"- **Listed-impact sentence (verbatim from SEVERITY.md):**",
        f"  > {TODO}",
        f"- **SEVERITY.md citation:** `{TODO}` (e.g. `SEVERITY.md:55`)",
        "",
        "## Production-precondition",
        "",
        "What MUST hold for the bug to be triggerable on mainnet. Each",
        "precondition needs a verifiable on-chain or contract-state",
        "citation. Branch-invariant PoC discipline (see memory:",
        "`feedback_branch_invariant_precondition_check`): a clean PoC is",
        "necessary but **not sufficient** — every precondition below must",
        "be externally reachable under the in-scope contract surface.",
        "",
        f"- {TODO} — Precondition #1 (state / role / config / fork-time)",
        f"- {TODO} — Precondition #2",
        f"- {TODO} — Precondition #3",
        "",
        f"**Reachability note:** {TODO} (explain why each precondition is",
        f"reachable by an unprivileged caller, or cite the in-scope role that",
        f"can satisfy it).",
        "",
        "## Adversarial-control",
        "",
        "Exactly what the attacker controls. Anything outside this list is",
        "an OOS trust assumption.",
        "",
        f"- **Attacker EOA / contract-call surface:** {TODO}",
        f"- **Inputs the attacker chooses:** {TODO}",
        f"- **Timing the attacker controls:** {TODO} (e.g. block.timestamp",
        f"  bracketing a fork-activation, sequencer-window position)",
        f"- **State the attacker can pre-stage:** {TODO}",
        "",
        f"**OOS traps to avoid:** {TODO} (privileged-key compromise,",
        f"Security Council mandate, off-chain infra compromise, etc — see",
        f"`OOS_CHECKLIST.md`).",
        "",
        "## Measured-state-delta (FN2 lesson)",
        "",
        "Financial / state impact must be **MEASURED**, not implied.",
        "Soft-claim phrases (\"structural implication\", \"would result in\",",
        "\"could allow\") without a backing `assertEq` are blocked by",
        "`pre-submit-check.sh` Check 35 (D-09 / T-03).",
        "",
        "Required PoC assertion shape (placeholder):",
        "",
        "```solidity",
        f"// TODO_OPERATOR: replace with row-specific delta",
        f"uint256 victimBalanceBefore = victim.balanceOf({TODO}_account);",
        f"// ... attacker exercises the vulnerable path ...",
        f"uint256 victimBalanceAfter = victim.balanceOf({TODO}_account);",
        f"assertEq(victimBalanceAfter - victimBalanceBefore, {TODO}_expected_delta);",
        "```",
        "",
        "For Rust harnesses, use `assert_eq!` / `expect_eq!` with the same",
        "before/after capture pattern (see `harness_plans.json`",
        f"`compile_command` for the row's existing toolchain hint:",
        f"`{compile_cmd or TODO}`).",
        "",
        f"**Quantified expected delta:** `{TODO}` (e.g. `1e18 wei`,",
        f"`+1 invalid block accepted`, `+1 unauthorized verifier upgrade`).",
        "",
        "## Borrowed-asset list",
        "",
        "Which production contracts / state slots / fork heights this",
        "harness must borrow (clone / fork / state-load) before it is",
        "faithful to mainnet. Stub-only PoCs are gated by",
        "`tools/poc-stub-coverage-checker.py` (T-04).",
        "",
        f"- **Production contracts to borrow:** {TODO}",
        f"- **Storage slots / role assignments to mirror:** {TODO}",
        f"- **Fork height / block timestamp to fork at:** {TODO}",
        f"- **Fixtures already declared in plan:**",
        f"{fixture_lines}",
        "",
        f"**Stub-vs-faithful coverage table (T-04 requirement):**",
        "",
        f"| Production check | Faithfully modeled? | Notes |",
        f"|---|---|---|",
        f"| {TODO} | {TODO} | {TODO} |",
        "",
        "## Test command",
        "",
        f"- **Compile / run command (from plan):** `{compile_cmd or TODO}`",
        f"- **Expected log string (from plan):** `{expected_log or TODO}`",
        f"- **First negative control (from plan):** {first_neg or TODO}",
        f"- **Stop condition (from plan):** {stop_cond or TODO}",
        "",
        "Operator must confirm the above survive when the harness is wired",
        "to the actual borrowed-asset set.",
        "",
        "## Plan-derived proof surface (for context only)",
        "",
        f"> {surface or TODO}",
        "",
        "## Operator decision required",
        "",
        f"**This skeleton is NOT submission-ready and does NOT prove the listed",
        f"impact.** A human operator must complete every `{TODO}` marker, then:",
        "",
        f"1. Re-run `make harness-plan WS={workspace}` to confirm this row",
        f"   moves out of `blocked` status.",
        f"2. Run `make harness-scaffold WS={workspace} ROW={row_id}` to",
        f"   generate the runnable scaffold.",
        f"3. Bind the completed contract into `impact_contracts.json` (the",
        f"   canonical source).",
        f"4. Verify `pre-submit-check.sh` checks 34 (title), 35 (financial",
        f"   gate), and the OOS gate all rc=0 before any submission.",
        "",
        "---",
        "",
        f"*Skeleton generated by `tools/impact-contract-scaffolder.py` /",
        f"schema `{SCHEMA_VERSION}`.*",
    ]
    return "\n".join(sections) + "\n"


def render_index(
    workspace: Path,
    out_dir: Path,
    rows: list[dict[str, Any]],
    skeleton_paths: list[Path],
) -> str:
    lines = [
        "# Impact-Contract Skeleton Index",
        "",
        f"Generated by `tools/impact-contract-scaffolder.py` for workspace",
        f"`{workspace}`.",
        "",
        f"- Total skeletons emitted: **{len(rows)}**",
        f"- Output directory: `{out_dir}`",
        f"- Schema version: `{SCHEMA_VERSION}`",
        "",
        "Each row below is a harness-plan entry blocked on a missing",
        "impact contract. Open the linked skeleton, fill in every",
        f"`{TODO}` marker (estimated 30–45 min per row), then re-run",
        "`make harness-plan` to clear the block.",
        "",
        "## Rows",
        "",
        "| # | Row ID | Harness family | Invariant family | Skeleton |",
        "|---|---|---|---|---|",
    ]
    for idx, (plan, path) in enumerate(zip(rows, skeleton_paths), start=1):
        rid = str(plan.get("row_id") or "")
        fam = str(plan.get("harness_family") or "")
        inv = str(plan.get("source_invariant_family") or "")
        rel = path.name
        lines.append(f"| {idx} | `{rid}` | `{fam}` | `{inv or '(none)'}` | [`{rel}`](./{rel}) |")
    lines.extend(
        [
            "",
            "## Operator next steps",
            "",
            f"1. Pick the highest-severity row first (consult `SEVERITY.md`",
            f"   listed-impacts).",
            f"2. Fill every `{TODO}` marker in the skeleton.",
            f"3. Re-run `make harness-plan WS={workspace}` and confirm the",
            f"   row moves out of `blocked`.",
            f"4. Re-run `make harness-scaffold WS={workspace} ROW=<row_id>`",
            f"   to generate the runnable scaffold.",
            f"5. Bind the completed contract into `impact_contracts.json`.",
            "",
            "## Proof boundary",
            "",
            f"These skeletons are advisory unblocker artifacts only. They do",
            f"NOT prove any listed impact, do NOT unblock harness work on",
            f"their own, and are NOT submit-ready. The canonical impact",
            f"contract source remains `impact_contracts.json`.",
            "",
        ]
    )
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--workspace", required=True, type=Path)
    parser.add_argument(
        "--plans-json",
        type=Path,
        default=None,
        help="Path to harness_plans.json (default: <workspace>/.auditooor/harness_plans.json)",
    )
    parser.add_argument(
        "--out-dir",
        type=Path,
        default=None,
        help="Output dir (default: <workspace>/.auditooor/impact_contracts/)",
    )
    parser.add_argument(
        "--statuses",
        default=",".join(DEFAULT_BLOCKED_STATUSES),
        help=(
            "Comma-separated list of source_row_status values that count as "
            f"blocked-on-impact-contract. Default: {','.join(DEFAULT_BLOCKED_STATUSES)}"
        ),
    )
    parser.add_argument(
        "--row",
        default=None,
        help="If set, emit a skeleton only for this row_id (otherwise: all matching rows).",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Don't write files; just print what would be emitted.",
    )
    parser.add_argument(
        "--print-json",
        action="store_true",
        help="Emit a JSON summary on stdout instead of human-readable.",
    )
    args = parser.parse_args(argv)

    workspace = args.workspace.expanduser().resolve()
    plans_path = (
        args.plans_json.expanduser().resolve()
        if args.plans_json
        else workspace / ".auditooor" / "harness_plans.json"
    )
    out_dir = (
        args.out_dir.expanduser().resolve()
        if args.out_dir
        else workspace / ".auditooor" / "impact_contracts"
    )

    plans_doc = load_plans(plans_path)
    plans = plans_doc.get("plans") or []
    if not isinstance(plans, list):
        raise SystemExit(
            f"[impact-contract-scaffolder] ERR plans field is not a list in {plans_path}"
        )

    statuses = [s.strip() for s in str(args.statuses).split(",") if s.strip()]
    rows = select_blocked_rows(plans, statuses, args.row)

    skeleton_paths: list[Path] = []
    if not args.dry_run:
        out_dir.mkdir(parents=True, exist_ok=True)

    for plan in rows:
        row_id = str(plan.get("row_id") or "").strip()
        target = out_dir / f"{slug(row_id)}.md"
        skeleton_paths.append(target)
        if args.dry_run:
            continue
        target.write_text(render_skeleton(plan, workspace), encoding="utf-8")

    index_path = out_dir / "INDEX.md"
    if not args.dry_run and rows:
        index_path.write_text(
            render_index(workspace, out_dir, rows, skeleton_paths),
            encoding="utf-8",
        )

    summary = {
        "schema_version": SCHEMA_VERSION,
        "workspace": str(workspace),
        "plans_path": str(plans_path),
        "out_dir": str(out_dir),
        "statuses_filter": statuses,
        "row_filter": args.row,
        "matched_rows": len(rows),
        "skeleton_paths": [str(p) for p in skeleton_paths],
        "index_path": str(index_path) if rows else None,
        "dry_run": bool(args.dry_run),
        "proof_boundary": (
            "Skeletons are advisory unblocker artifacts only; they do not "
            "prove the listed impact and are not submit-ready."
        ),
    }

    if args.print_json:
        print(json.dumps(summary, indent=2, sort_keys=True))
    else:
        first = rows[0] if rows else None
        sample_title = derive_title(first) if first else "(none)"
        sample_row_id = str(first.get("row_id") or "") if first else "(none)"
        verb = "would emit" if args.dry_run else "emitted"
        print(
            f"[impact-contract-scaffolder] OK {verb} {len(rows)} skeleton(s) "
            f"under {out_dir}"
        )
        if rows:
            print(f"  sample row_id: {sample_row_id}")
            print(f"  sample title:  {sample_title}")
            print(f"  index:         {index_path}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
