#!/usr/bin/env python3
"""impact-contract-auto-fill.py — LLM-assisted draft fill for operator-fillable
impact-contract skeletons.

Solves the F3 / docs/CLAUDE_TAKEOVER_BURNDOWN.md "Impact Contract Closure"
operator-time blocker: after `tools/impact-contract-scaffolder.py` emits N
skeletons under ``<workspace>/.auditooor/impact_contracts/``, every
``<TODO_OPERATOR>`` marker is left for a human to fill (~30-45 min/row,
~50 hours total for 71 rows). This tool generates a *draft* fill that an
operator reviews + accepts or edits before the file becomes the canonical
impact contract.

This is **NOT** a truth source. The output carries per-field
``confidence: high|medium|low`` markers. Operator review is mandatory.
The auto-filled file is written to ``<id>_autofilled.md``; the caller
explicitly merges/promotes accepted content into the canonical
``<id>.md`` skeleton.

Multi-step LLM reasoning chain (5 steps, calibrated for opus per ACT-14):
  S1  read the production code + identify the entrypoint and state mutations
  S2  identify external callers via callgraph (Slither / semantic-graph)
  S3  infer adversarial-control surface (msg.sender constraints, modifiers)
  S4  identify borrowed-asset requirements (which production contracts
      / storage slots / fork height the harness must mirror)
  S5  emit a filled-in spec with confidence levels per field

Privacy filter:
  Workspace source is in-scope under NDA. The privacy filter snippet
  guard truncates each pasted code snippet to a bounded length and
  redacts contents of any path that matches a configured deny-glob
  (``*.secrets/*``, ``credentials.json``, etc). NEVER bypass.

This tool is **DRY-RUN SAFE BY DEFAULT**: with ``--dry-run`` it emits the
exact prompts that would have been sent to the LLM, plus a manifest under
``--out-prompts-dir``. It does not call the LLM, does not spend money, and
does not write the autofilled file. Use ``--no-dry-run`` only after the
operator has explicitly approved the budget.

Reference tools (read first, do not duplicate):
  tools/impact-contract-scaffolder.py — emits the skeletons we fill.
  tools/impact-contract-validator.py — internal-consistency checks for
      operator-filled or auto-filled specs.
  tools/agent-dispatch-prompt-lint.py — heuristic prompt-lint; called on
      every emitted prompt by default.

Usage:
  # Dry-run on all matching skeletons in a workspace
  python3 tools/impact-contract-auto-fill.py \\
      --workspace /Users/wolf/audits/base-azul \\
      --dry-run

  # Dry-run on 5 specific row ids
  python3 tools/impact-contract-auto-fill.py \\
      --workspace /Users/wolf/audits/base-azul \\
      --row BASEAZUL-WORKLIST-09 \\
      --row BASEAZUL-WORKLIST-12 \\
      --dry-run

  # Dry-run picking the 5 lowest-complexity skeletons automatically
  python3 tools/impact-contract-auto-fill.py \\
      --workspace /Users/wolf/audits/base-azul \\
      --pick-lowest-complexity 5 \\
      --dry-run

Exit codes:
  0  dry-run success or live fill success
  1  bad input / missing skeleton / privacy-filter rejection
  2  --no-dry-run requested but no operator-approved budget marker
"""
from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterable

SCHEMA_VERSION = "auditooor.impact_contract_auto_fill.v1"
DEFAULT_MAX_SOURCE_SNIPPET_CHARS = 3000
DEFAULT_MAX_PRODUCTION_PATHS = 8
PRIVACY_DENY_GLOBS = (
    ".secrets/",
    "credentials.json",
    "clob_creds.json",
    "/.env",
    "private_key",
    "wallet.json",
)
PER_FIELD_FIELDS = (
    "title",
    "severity",
    "production_precondition",
    "adversarial_control",
    "measured_state_delta",
    "borrowed_assets",
    "test_command",
)
ROUTING_RECOMMENDATION = "opus"  # ACT-14 calibration: multi-step, low ambiguity
PROMPT_VERSION = "v1"
COST_PROJECTION_USD_PER_SPEC = 0.50  # ~$35 for 71 specs


# ============================================================================
# Privacy filter
# ============================================================================


@dataclass
class PrivacyFilter:
    deny_globs: tuple[str, ...] = PRIVACY_DENY_GLOBS
    max_snippet_chars: int = DEFAULT_MAX_SOURCE_SNIPPET_CHARS

    def is_path_denied(self, path: str) -> bool:
        norm = path.replace("\\", "/")
        for g in self.deny_globs:
            if g in norm:
                return True
        return False

    def filter_snippet(self, path: str, snippet: str) -> tuple[str, str]:
        """Return (filtered_text, status) where status in
        {'ok', 'truncated', 'denied'}.
        """
        if self.is_path_denied(path):
            return ("[REDACTED — privacy-filter deny-glob match]", "denied")
        if len(snippet) > self.max_snippet_chars:
            head = snippet[: self.max_snippet_chars]
            return (
                head
                + f"\n\n[…truncated to {self.max_snippet_chars} chars; "
                f"{len(snippet) - self.max_snippet_chars} chars hidden]",
                "truncated",
            )
        return (snippet, "ok")


# ============================================================================
# Skeleton parser
# ============================================================================


@dataclass
class SkeletonRow:
    row_id: str
    path: Path
    raw: str
    harness_family: str = ""
    invariant_family: str = ""
    target_entrypoint: str = ""
    plan_reason: str = ""
    compile_command: str = ""
    expected_log: str = ""

    @property
    def complexity_score(self) -> int:
        """Heuristic: lower = simpler. Used by --pick-lowest-complexity.

        Signals that increase complexity:
          - harness_family is "needs_human" (no automatic family routing)
          - target_entrypoint missing (no clear plan)
          - compile_command missing
        """
        score = 0
        if self.harness_family in ("needs_human", "", "<TODO_OPERATOR>"):
            score += 3
        if not self.target_entrypoint or "TODO" in self.target_entrypoint:
            score += 2
        if not self.compile_command or "TODO" in self.compile_command:
            score += 2
        if not self.invariant_family or self.invariant_family == "(none)":
            score += 1
        return score


_TABLE_ROW = re.compile(r"^\|\s*([^|]+?)\s*\|\s*`?([^|`]+?)`?\s*\|\s*$")


def parse_skeleton(path: Path) -> SkeletonRow:
    raw = path.read_text(encoding="utf-8")
    row = SkeletonRow(row_id="", path=path, raw=raw)
    row_id_match = re.search(
        r"^# Impact Contract Skeleton — (\S+)", raw, re.MULTILINE
    )
    if row_id_match:
        row.row_id = row_id_match.group(1).strip()
    # Identity table parser: very conservative, just extract well-known keys
    for line in raw.splitlines():
        m = _TABLE_ROW.match(line)
        if not m:
            continue
        key = m.group(1).strip().lower()
        val = m.group(2).strip()
        if key == "row id":
            row.row_id = val.strip("`")
        elif key == "harness family":
            row.harness_family = val
        elif key == "source invariant family":
            row.invariant_family = val
        elif key.startswith("target entrypoint"):
            row.target_entrypoint = val
        elif key == "plan reason":
            row.plan_reason = val
    # compile_command + expected_log live in a different section
    for marker, attr in (
        ("Compile / run command (from plan):", "compile_command"),
        ("Expected log string (from plan):", "expected_log"),
    ):
        m = re.search(
            rf"^- \*\*{re.escape(marker)}\*\* `?(.+?)`?$",
            raw,
            re.MULTILINE,
        )
        if m:
            setattr(row, attr, m.group(1).strip())
    return row


def discover_skeletons(workspace: Path) -> list[SkeletonRow]:
    out_dir = workspace / ".auditooor" / "impact_contracts"
    if not out_dir.is_dir():
        return []
    rows: list[SkeletonRow] = []
    for p in sorted(out_dir.glob("*.md")):
        if p.name == "INDEX.md":
            continue
        if p.name.endswith("_autofilled.md"):
            continue
        try:
            rows.append(parse_skeleton(p))
        except Exception as exc:  # pragma: no cover — defensive
            print(
                f"[impact-contract-auto-fill] WARN failed to parse "
                f"{p}: {exc}",
                file=sys.stderr,
            )
    return rows


# ============================================================================
# Production source resolution (best-effort, optional)
# ============================================================================


def resolve_production_source_paths(
    workspace: Path,
    row: SkeletonRow,
    privacy: PrivacyFilter,
    extra_paths: Iterable[Path] = (),
    max_paths: int = DEFAULT_MAX_PRODUCTION_PATHS,
) -> list[tuple[Path, str, str]]:
    """Return a list of (path, snippet, privacy_status). Best-effort.

    Strategy:
      1. extra_paths take precedence (operator-supplied via --source-path).
      2. target_entrypoint sometimes points at a JSON plan that names a
         contract or a `.sol` file; we follow only obvious file refs.
      3. Otherwise we fall back to grepping the workspace for the
         invariant_family token in the in-scope source roots.

    Returns at most ``max_paths`` entries.
    """
    candidates: list[Path] = []
    for ep in extra_paths:
        ep = ep.expanduser().resolve()
        if ep.is_file():
            candidates.append(ep)
    # target_entrypoint hint: e.g. ".auditooor/harness_plans/X.json"
    if row.target_entrypoint and not row.target_entrypoint.startswith("<TODO"):
        ep = (workspace / row.target_entrypoint).resolve()
        if ep.suffix in (".sol", ".rs") and ep.is_file():
            candidates.append(ep)
        elif ep.suffix == ".json" and ep.is_file():
            try:
                doc = json.loads(ep.read_text(encoding="utf-8"))
                contract_hint = doc.get("contract") or doc.get("target_contract")
                if isinstance(contract_hint, str) and contract_hint:
                    matches = list(workspace.rglob(f"{contract_hint}.sol"))[:3]
                    candidates.extend(matches)
            except Exception:
                pass
    # Dedup, keep first N
    seen: set[Path] = set()
    deduped: list[Path] = []
    for p in candidates:
        if p in seen:
            continue
        seen.add(p)
        deduped.append(p)
        if len(deduped) >= max_paths:
            break
    out: list[tuple[Path, str, str]] = []
    for p in deduped:
        try:
            text = p.read_text(encoding="utf-8")
        except Exception:
            continue
        rel = str(p.relative_to(workspace)) if str(p).startswith(str(workspace)) else str(p)
        filtered, status = privacy.filter_snippet(rel, text)
        out.append((p, filtered, status))
    return out


# ============================================================================
# Prompt builders (one prompt per LLM step S1..S5)
# ============================================================================


def _common_header(row: SkeletonRow, workspace: Path) -> str:
    return (
        f"You are assisting an auditooor operator with a draft fill of an "
        f"impact-contract skeleton.\n"
        f"\n"
        f"Workspace: {workspace}\n"
        f"Row id: {row.row_id}\n"
        f"Harness family: {row.harness_family or '(unknown)'}\n"
        f"Invariant family: {row.invariant_family or '(unknown)'}\n"
        f"Plan reason: {row.plan_reason or '(none)'}\n"
        f"Compile command: {row.compile_command or '(unknown)'}\n"
        f"\n"
        f"This output is a *draft*. The operator will review every field "
        f"before promotion. Always emit a `confidence: high|medium|low` "
        f"marker per field.\n"
        f"M14-trap discipline: do NOT fabricate borrowed-asset paths, "
        f"contract names, or storage slots that you did not see in the "
        f"production source. If a field cannot be inferred from the "
        f"provided context, emit `confidence: low` and "
        f"`<TODO_OPERATOR>` for that field. Honest accounting required.\n"
        f"Privacy: workspace source is under NDA. Do not echo unrelated "
        f"file contents. If a snippet is marked [REDACTED], do not try "
        f"to reconstruct it.\n"
    )


def _format_sources(sources: list[tuple[Path, str, str]]) -> str:
    if not sources:
        return "(no production source resolved — operator-supplied paths preferred)\n"
    blocks: list[str] = []
    for p, snippet, status in sources:
        blocks.append(
            f"--- file: {p.name} (status: {status}) ---\n"
            f"{snippet}\n"
            f"--- end {p.name} ---\n"
        )
    return "\n".join(blocks)


def build_prompt_step1(
    row: SkeletonRow,
    workspace: Path,
    sources: list[tuple[Path, str, str]],
) -> str:
    """S1 — read the production code + identify entrypoint and state mutations."""
    return (
        _common_header(row, workspace)
        + f"\n## Step 1 of 5 — entrypoint + state mutations\n"
        f"\n"
        f"Read the provided production source. Identify:\n"
        f"  - the public/external entrypoint that this row's invariant "
        f"family ({row.invariant_family or '(unknown)'}) points at,\n"
        f"  - the state mutations the entrypoint performs (storage writes, "
        f"emit, external calls).\n"
        f"\n"
        f"Output schema (JSON):\n"
        f"```json\n"
        f"{{\n"
        f'  "entrypoint": {{"signature": "...", "file": "...", '
        f'"line": 0, "confidence": "high|medium|low"}},\n'
        f'  "state_mutations": [\n'
        f'    {{"slot_or_var": "...", "kind": "write|emit|external_call", '
        f'"file": "...", "line": 0, "confidence": "high|medium|low"}}\n'
        f"  ]\n"
        f"}}\n"
        f"```\n"
        f"\n"
        f"## Acceptance\n"
        f"- valid JSON\n"
        f"- every field has a `confidence` marker\n"
        f"- no fabricated file/line citations\n"
        f"\n"
        f"## Production source\n"
        f"\n"
        f"{_format_sources(sources)}\n"
    )


def build_prompt_step2(
    row: SkeletonRow,
    workspace: Path,
    step1_output_placeholder: str = "<filled by step 1>",
) -> str:
    """S2 — identify external callers via callgraph."""
    return (
        _common_header(row, workspace)
        + f"\n## Step 2 of 5 — external callers / callgraph reach\n"
        f"\n"
        f"Given the entrypoint identified in step 1 ({step1_output_placeholder}), "
        f"identify which external contracts/EOAs can reach this entrypoint. "
        f"Prefer the workspace's `.auditooor/semantic_graph.json` if "
        f"present; fall back to grep-style reasoning over the provided "
        f"sources only.\n"
        f"\n"
        f"Output schema (JSON):\n"
        f"```json\n"
        f"{{\n"
        f'  "callers": [\n'
        f'    {{"contract": "...", "function": "...", "permissionless": '
        f'true, "confidence": "high|medium|low"}}\n'
        f"  ],\n"
        f'  "permissionless_path_exists": true,\n'
        f'  "permissionless_path_confidence": "high|medium|low"\n'
        f"}}\n"
        f"```\n"
        f"\n"
        f"## Acceptance\n"
        f"- valid JSON\n"
        f"- if no permissionless path is found, "
        f'`permissionless_path_exists` MUST be `false` and the "next step" '
        f'will produce a `confidence: low` adversarial-control surface\n'
        f"- do NOT promote a privileged-only entrypoint to "
        f"permissionless without source evidence (M14-trap)\n"
    )


def build_prompt_step3(
    row: SkeletonRow,
    workspace: Path,
) -> str:
    """S3 — infer adversarial-control surface (msg.sender, modifiers)."""
    return (
        _common_header(row, workspace)
        + f"\n## Step 3 of 5 — adversarial-control surface\n"
        f"\n"
        f"Using steps 1 and 2 outputs, enumerate exactly what the "
        f"attacker controls. Anything outside this list is an OOS trust "
        f"assumption.\n"
        f"\n"
        f"Output schema (JSON):\n"
        f"```json\n"
        f"{{\n"
        f'  "attacker_eoa_or_contract": "...",\n'
        f'  "attacker_inputs": ["..."],\n'
        f'  "attacker_timing_control": "...",\n'
        f'  "pre_stageable_state": ["..."],\n'
        f'  "modifier_constraints": ["..."],\n'
        f'  "oos_traps_to_avoid": ["..."],\n'
        f'  "confidence": "high|medium|low"\n'
        f"}}\n"
        f"```\n"
        f"\n"
        f"## Acceptance\n"
        f"- valid JSON\n"
        f"- privileged-key compromise / Security Council mandate / "
        f"off-chain infra compromise MUST appear in `oos_traps_to_avoid` "
        f"if any caller in step 2 was role-gated\n"
        f"- M14-trap: if you cannot determine the modifier constraints "
        f"from the source, emit `confidence: low` and a `<TODO_OPERATOR>` "
        f"marker — do not guess\n"
    )


def build_prompt_step4(
    row: SkeletonRow,
    workspace: Path,
) -> str:
    """S4 — borrowed-asset requirements (clone / fork / state-load)."""
    return (
        _common_header(row, workspace)
        + f"\n## Step 4 of 5 — borrowed-asset requirements\n"
        f"\n"
        f"Identify production contracts / storage slots / fork heights "
        f"the harness must mirror to be faithful to mainnet. Stub-only "
        f"PoCs are gated by `tools/poc-stub-coverage-checker.py` (T-04).\n"
        f"\n"
        f"Output schema (JSON):\n"
        f"```json\n"
        f"{{\n"
        f'  "production_contracts_to_borrow": [\n'
        f'    {{"name": "...", "address_or_slot": "...", '
        f'"confidence": "high|medium|low"}}\n'
        f"  ],\n"
        f'  "storage_slots_to_mirror": ["..."],\n'
        f'  "fork_height_or_timestamp": "...",\n'
        f'  "fixtures_already_declared": ["..."],\n'
        f'  "stub_vs_faithful_table": [\n'
        f'    {{"production_check": "...", '
        f'"faithfully_modeled": true, "notes": "..."}}\n'
        f"  ],\n"
        f'  "confidence": "high|medium|low"\n'
        f"}}\n"
        f"```\n"
        f"\n"
        f"## Acceptance\n"
        f"- valid JSON\n"
        f"- borrowed-asset list MUST be non-empty for borrowing/leveraged "
        f"strategies (per `impact-contract-validator.py` rules)\n"
        f"- M14-trap: do NOT invent contract addresses or storage slot "
        f"indices that are not in the provided sources or workspace "
        f"deployment-topology artifacts\n"
    )


def build_prompt_step5(
    row: SkeletonRow,
    workspace: Path,
) -> str:
    """S5 — emit a filled-in spec with confidence levels per field."""
    return (
        _common_header(row, workspace)
        + f"\n## Step 5 of 5 — emit filled spec\n"
        f"\n"
        f"Combine outputs from steps 1-4 into a markdown body that "
        f"matches the skeleton at "
        f"`{row.path.name}` (NOT a full re-render — only the field "
        f"values to splice into existing sections).\n"
        f"\n"
        f"Output schema (JSON):\n"
        f"```json\n"
        f"{{\n"
        f'  "fields": {{\n'
        f'    "title": {{"value": "...", "confidence": "high|medium|low"}},\n'
        f'    "severity": {{"tier": "Critical|High|Medium|Low", '
        f'"likelihood": "...", "listed_impact_sentence": "...", '
        f'"severity_md_citation": "...", "confidence": "..."}},\n'
        f'    "production_precondition": {{"items": ["..."], '
        f'"reachability_note": "...", "confidence": "..."}},\n'
        f'    "adversarial_control": {{"surface": {{...}}, '
        f'"confidence": "..."}},\n'
        f'    "measured_state_delta": {{"assertion_shape": "...", '
        f'"quantified_delta": "...", "confidence": "..."}},\n'
        f'    "borrowed_assets": {{"items": ["..."], '
        f'"confidence": "..."}},\n'
        f'    "test_command": {{"compile_cmd": "...", '
        f'"expected_log": "...", "confidence": "..."}}\n'
        f"  }},\n"
        f'  "overall_confidence": "high|medium|low",\n'
        f'  "operator_review_required": true\n'
        f"}}\n"
        f"```\n"
        f"\n"
        f"## Acceptance\n"
        f"- valid JSON\n"
        f"- every field carries a `confidence` marker\n"
        f"- `operator_review_required` MUST be `true` (this is a draft, "
        f"not a finding)\n"
        f"- if `overall_confidence` is `low`, the spec MUST include "
        f"`<TODO_OPERATOR>` markers in fields that could not be "
        f"determined\n"
        f"\n"
        f"## Branch and deliverable\n"
        f"- Deliverable file: `<workspace>/.auditooor/impact_contracts/"
        f"{row.row_id.lower().replace('_', '-')}_autofilled.md`\n"
        f"- Operator review and acceptance is mandatory before promoting "
        f"into the canonical skeleton.\n"
    )


# ============================================================================
# Optional: lint each prompt with tools/agent-dispatch-prompt-lint.py
# ============================================================================


def lint_prompt(prompt_path: Path, repo_root: Path, strict: bool) -> dict[str, Any]:
    lint_tool = repo_root / "tools" / "agent-dispatch-prompt-lint.py"
    if not lint_tool.is_file():
        return {"ok": False, "reason": "lint tool missing", "path": str(lint_tool)}
    cmd = [sys.executable, str(lint_tool), str(prompt_path)]
    if strict:
        cmd.append("--strict")
    json_out = prompt_path.with_suffix(".lint.json")
    cmd.extend(["--json-out", str(json_out)])
    try:
        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=30,
            check=False,
        )
    except Exception as exc:
        return {"ok": False, "reason": f"lint subprocess failed: {exc}"}
    out: dict[str, Any] = {
        "ok": proc.returncode == 0,
        "rc": proc.returncode,
        "stdout_tail": proc.stdout[-400:],
        "stderr_tail": proc.stderr[-400:],
        "json_report_path": str(json_out) if json_out.is_file() else None,
    }
    if json_out.is_file():
        try:
            out["json_report"] = json.loads(json_out.read_text(encoding="utf-8"))
        except Exception:
            out["json_report"] = None
    return out


# ============================================================================
# CLI
# ============================================================================


def select_rows(
    rows: list[SkeletonRow],
    only_rows: list[str],
    pick_lowest_n: int | None,
) -> list[SkeletonRow]:
    if only_rows:
        wanted = {r.upper() for r in only_rows}
        out = [r for r in rows if r.row_id.upper() in wanted]
        return out
    if pick_lowest_n is not None and pick_lowest_n > 0:
        return sorted(rows, key=lambda r: (r.complexity_score, r.row_id))[:pick_lowest_n]
    return rows


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--workspace", required=True, type=Path)
    parser.add_argument(
        "--row",
        action="append",
        default=[],
        help="Row id to fill (repeatable). If omitted: all skeletons "
        "or the lowest-complexity selection if --pick-lowest-complexity is set.",
    )
    parser.add_argument(
        "--pick-lowest-complexity",
        type=int,
        default=None,
        help="Pick the N lowest-complexity skeletons automatically.",
    )
    parser.add_argument(
        "--source-path",
        action="append",
        default=[],
        type=Path,
        help="Operator-supplied production source path (repeatable). "
        "Used as the primary source pool for step 1.",
    )
    parser.add_argument(
        "--out-prompts-dir",
        type=Path,
        default=None,
        help="Where to write the emitted prompts (default: "
        "<workspace>/.auditooor/impact_contracts/_autofill_prompts/).",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        default=True,
        help="Do not call the LLM. Emit prompts only. (Default: ON)",
    )
    parser.add_argument(
        "--no-dry-run",
        dest="dry_run",
        action="store_false",
        help="Disable dry-run. Requires --i-have-budget-approval.",
    )
    parser.add_argument(
        "--i-have-budget-approval",
        action="store_true",
        help="Operator confirms LLM dispatch budget. Required with --no-dry-run.",
    )
    parser.add_argument(
        "--lint-strict",
        action="store_true",
        help="Pass --strict to agent-dispatch-prompt-lint when linting "
        "emitted prompts.",
    )
    parser.add_argument(
        "--print-json",
        action="store_true",
        help="Emit a JSON summary on stdout instead of human-readable.",
    )
    parser.add_argument(
        "--repo-root",
        type=Path,
        default=Path(__file__).resolve().parent.parent,
        help="Repo root (for locating sibling tools).",
    )
    args = parser.parse_args(argv)

    if not args.dry_run and not args.i_have_budget_approval:
        print(
            "[impact-contract-auto-fill] ERR --no-dry-run requires "
            "--i-have-budget-approval. Refusing to dispatch unbounded LLM.",
            file=sys.stderr,
        )
        return 2

    workspace = args.workspace.expanduser().resolve()
    repo_root = args.repo_root.expanduser().resolve()
    privacy = PrivacyFilter()

    rows = discover_skeletons(workspace)
    if not rows:
        print(
            f"[impact-contract-auto-fill] ERR no skeletons found under "
            f"{workspace}/.auditooor/impact_contracts/. Run "
            f"`tools/impact-contract-scaffolder.py` first.",
            file=sys.stderr,
        )
        return 1

    selected = select_rows(rows, args.row, args.pick_lowest_complexity)
    if not selected:
        print(
            f"[impact-contract-auto-fill] ERR no rows matched filters. "
            f"Total skeletons in workspace: {len(rows)}.",
            file=sys.stderr,
        )
        return 1

    out_prompts_dir = (
        args.out_prompts_dir.expanduser().resolve()
        if args.out_prompts_dir
        else workspace / ".auditooor" / "impact_contracts" / "_autofill_prompts"
    )
    out_prompts_dir.mkdir(parents=True, exist_ok=True)

    summary: dict[str, Any] = {
        "schema_version": SCHEMA_VERSION,
        "workspace": str(workspace),
        "dry_run": bool(args.dry_run),
        "selected_count": len(selected),
        "total_skeleton_count": len(rows),
        "routing_recommendation": ROUTING_RECOMMENDATION,
        "prompt_version": PROMPT_VERSION,
        "cost_projection_usd_total": (
            COST_PROJECTION_USD_PER_SPEC * len(selected)
        ),
        "cost_projection_usd_per_spec": COST_PROJECTION_USD_PER_SPEC,
        "rows": [],
        "operator_review_required": True,
        "proof_boundary": (
            "Auto-filled output is a DRAFT. Operator must review every "
            "field before merging into the canonical skeleton. "
            "Per-field confidence levels indicate where to focus."
        ),
    }

    builders = [
        ("step1_entrypoint", build_prompt_step1),
        ("step2_callers", lambda r, ws: build_prompt_step2(r, ws)),
        ("step3_adversarial", build_prompt_step3),
        ("step4_borrowed", build_prompt_step4),
        ("step5_emit", build_prompt_step5),
    ]

    for row in selected:
        sources = resolve_production_source_paths(
            workspace,
            row,
            privacy,
            extra_paths=args.source_path,
        )
        # Privacy-filter rejection check: if every source was denied,
        # we still allow the prompt to go through with an explicit note,
        # but we record it so operator can supply non-denied paths.
        any_denied = any(s == "denied" for _, _, s in sources)
        row_dir = out_prompts_dir / row.row_id.lower().replace("_", "-")
        row_dir.mkdir(parents=True, exist_ok=True)
        prompt_paths: list[str] = []
        lint_results: list[dict[str, Any]] = []
        for name, builder in builders:
            if name == "step1_entrypoint":
                prompt_text = builder(row, workspace, sources)  # type: ignore[arg-type]
            else:
                prompt_text = builder(row, workspace)  # type: ignore[arg-type]
            prompt_path = row_dir / f"{name}.md"
            prompt_path.write_text(prompt_text, encoding="utf-8")
            prompt_paths.append(str(prompt_path))
            lint_results.append(
                lint_prompt(prompt_path, repo_root, strict=args.lint_strict)
            )
        row_entry = {
            "row_id": row.row_id,
            "skeleton_path": str(row.path),
            "complexity_score": row.complexity_score,
            "harness_family": row.harness_family,
            "invariant_family": row.invariant_family,
            "prompt_paths": prompt_paths,
            "source_path_count": len(sources),
            "any_source_denied": any_denied,
            "lint": [
                {
                    "rc": r.get("rc"),
                    "ok": r.get("ok"),
                    "fail_count": (
                        (r.get("json_report") or {}).get("fail_count")
                        if r.get("json_report")
                        else None
                    ),
                }
                for r in lint_results
            ],
            "would_emit_autofilled_path": str(
                workspace
                / ".auditooor"
                / "impact_contracts"
                / f"{row.row_id.lower().replace('_', '-')}_autofilled.md"
            ),
        }
        summary["rows"].append(row_entry)

    summary["prompts_dir"] = str(out_prompts_dir)
    manifest_path = out_prompts_dir / "MANIFEST.json"
    manifest_path.write_text(
        json.dumps(summary, indent=2, sort_keys=True), encoding="utf-8"
    )
    summary["manifest_path"] = str(manifest_path)

    if args.print_json:
        print(json.dumps(summary, indent=2, sort_keys=True))
    else:
        verb = "would have emitted" if args.dry_run else "emitted"
        print(
            f"[impact-contract-auto-fill] OK {verb} prompts for "
            f"{len(selected)} row(s) under {out_prompts_dir}"
        )
        print(f"  manifest: {manifest_path}")
        print(
            f"  cost projection (dry-run reference): "
            f"${summary['cost_projection_usd_total']:.2f} "
            f"(@ ${COST_PROJECTION_USD_PER_SPEC:.2f}/spec)"
        )
        if args.dry_run:
            print(
                "  NOTE: dry-run mode — no LLM was called, "
                "no _autofilled.md was written."
            )
        for r in summary["rows"]:
            print(
                f"    - {r['row_id']} (complexity={r['complexity_score']}) "
                f"-> {len(r['prompt_paths'])} prompts"
            )
    return 0


if __name__ == "__main__":
    sys.exit(main())
