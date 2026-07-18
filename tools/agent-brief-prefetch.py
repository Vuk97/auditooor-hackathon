#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""agent-brief-prefetch.py

Pre-fetch a META-1 enrichment block (Section 15a + 15b + recent empirical
anchors + busywork-to-refuse) so it can be PASTED into an Agent-tool prompt
BEFORE the orchestrator spawns the worker.

Why this exists (operator-caught iter12 VVV + iter13 EEEE finding):

The existing `tools/agent-prompt-hacker-augmenter.py` already builds a rich
META-1 enrichment block (Section 15a from `vault_codified_rules_digest`,
Section 15b from `vault_lane_skeleton_filler`), but it is wired only into
the provider-dispatch pipeline. When the orchestrator spawns a worker via
Claude Code's `Agent` tool, the prompt is written INLINE - the augmenter
never runs. The result: 0/16 post-META-1 agent outputs cited Section 15a/15b
even though the templates exist on disk, and R-rule compliance regressed in
iter11 vs iter2 (R42 5->15 fails, R29 4->14, R40 4->13).

The fix is mechanical: a standalone CLI the orchestrator runs BEFORE writing
the Agent-tool prompt:

  $ python3 tools/agent-brief-prefetch.py \\
        --lane-type dispute --severity HIGH \\
        --workspace /Users/wolf/audits/spark

  # ... markdown block emitted to stdout, paste into Agent prompt ...

Reuses the same MCP callables the augmenter does, so the output is
identical to what the augmenter would inject in the provider-dispatch
path. Adds two NEW sections beyond Section 15a/15b:

  - Section 15c: recent empirical anchors (last 5 git-tracked lane reports
    summarized)
  - Section 15d: busywork-to-refuse (hardcoded from JJ iter5 + QQQ iter11
    findings; optional file-source via --busywork-file)

Hard rule: this script NEVER writes to drafts (L34). It only emits stdout
and exits 0 / non-zero.
"""

from __future__ import annotations

import argparse
import json
import pathlib
import subprocess
import sys
from typing import Any, Dict, List, Optional, Tuple

REPO = pathlib.Path(__file__).resolve().parent.parent
SCHEMA = "auditooor.agent_brief_prefetch.v1"

# Lane types accepted (mirror tools/lane_skeleton_templates/_lane_rule_map.json).
VALID_LANE_TYPES = (
    "dispute",
    "mediation",
    "filing",
    "hunt",
    "opposed-trace-harness",
    "escalation",
)

# Severity vocabulary accepted by vault_codified_rules_digest (lowercase ok).
VALID_SEVERITIES = ("LOW", "MEDIUM", "HIGH", "CRITICAL", "any")

# Busywork-to-refuse list. Sourced from:
#   - reports/v3_iter_2026-05-23_iter11/lane_QQQ_honest_assessment/are_we_at_the_wall.md
#   - Lane JJ iter5 ranked-rule recommendations (R49 / R50 / R51 / R54
#     deferred or dropped).
# Each entry: (pattern, reason). The orchestrator pastes this so workers
# don't burn cycles re-proposing already-ruled-out work.
BUSYWORK_DEFAULTS: Tuple[Tuple[str, str], ...] = (
    (
        "Propose R49 panic-recovered as a separate rule/gate",
        "deferred Lane JJ iter5 - folded into R18 doctrine; separate gate "
        "worsens rule-budget per Lane MCP-audit-3.",
    ),
    (
        "Propose R50 privileged-lifecycle as a separate rule/gate",
        "deferred Lane JJ iter5 - folded into R24 doctrine.",
    ),
    (
        "Propose R51 parallel-external-reporter rule",
        "deferred Lane JJ iter5+iter7 - need >=3 anchors; only 1 anchor "
        "exists today.",
    ),
    (
        "Propose R54 DiD-not-primary rule",
        "dropped Lane JJ iter5 - duplicate of R29 field c.",
    ),
    (
        "Propose R55+ new rules from yet-uncodified ideation",
        "Lane QQQ iter11 - past 95% coverage; marginal value <= cost.",
    ),
    (
        "Run iterative pre-submit-check hotfix loops for case-sens / "
        "variable-binding bugs",
        "Lane QQQ iter11 - write-once-test-once items, not loop-grade work.",
    ),
    (
        "Re-run brain-prime / brain calibration without a fresh anchor",
        "Lane EEEE iter13 - callable requires a pre-run receipt; cold-start "
        "rerun produces metadata-only output.",
    ),
    (
        "Add 'operator action required' framing to your reply",
        "AFK-rule (~/.claude/CLAUDE.md) - banned phrasing; the loop auto-"
        "executes every plan-prescribed op except findings-submission, "
        "force-push, and scope/severity changes.",
    ),
    (
        "Modify drafts under submissions/{paste_ready,staging,filed,held,"
        "superseded,_killed,_oos_rejected}/",
        "L34 (draft-modification-doctrine) - drafts are operator-controlled "
        "artifacts; tooling work must not touch them.",
    ),
    (
        "Touch Sei or Hyperbridge audit-tree source files",
        "Out-of-scope for V3 tooling lanes; modify only auditooor-mcp tools/"
        " and docs/.",
    ),
)


# ---------------------------------------------------------------------------
# Output helpers
# ---------------------------------------------------------------------------

def _emit_warn(msg: str) -> None:
    print(f"[agent-brief-prefetch] WARN: {msg}", file=sys.stderr)


def _emit_err(msg: str) -> None:
    print(f"[agent-brief-prefetch] ERROR: {msg}", file=sys.stderr)


# ---------------------------------------------------------------------------
# MCP callable wrappers (re-use the same subprocess pattern as the augmenter
# so behaviour matches and we don't have to import a hyphenated module).
# ---------------------------------------------------------------------------

def _call_mcp(
    call: str,
    args: Dict[str, Any],
    *,
    timeout: int = 30,
    server_path: Optional[pathlib.Path] = None,
) -> Optional[Dict[str, Any]]:
    """Invoke the local vault-mcp-server CLI and return parsed JSON."""
    server = server_path or (REPO / "tools" / "vault-mcp-server.py")
    if not server.is_file():
        _emit_warn(f"MCP server tool not found at {server}")
        return None
    try:
        proc = subprocess.run(
            [
                sys.executable,
                str(server),
                "--call",
                call,
                "--args",
                json.dumps(args, sort_keys=True),
            ],
            capture_output=True,
            text=True,
            timeout=timeout,
        )
    except subprocess.TimeoutExpired:
        _emit_warn(f"{call} timed out after {timeout}s")
        return None
    except Exception as exc:
        _emit_warn(f"{call} subprocess failed: {exc!r}")
        return None
    if proc.returncode != 0:
        _emit_warn(
            f"{call} returned rc={proc.returncode}; stderr head: "
            f"{(proc.stderr or '').splitlines()[:1]}"
        )
        return None
    out = (proc.stdout or "").strip()
    if not out:
        return None
    # The server emits a small banner line on stderr; stdout is JSON.
    # Some callables wrap the payload in a single JSON document, others
    # emit a JSON object followed by a newline. Try to be lenient.
    try:
        return json.loads(out)
    except json.JSONDecodeError:
        # Recover by extracting the last JSON object on stdout.
        for line in reversed(out.splitlines()):
            line = line.strip()
            if line.startswith("{") and line.endswith("}"):
                try:
                    return json.loads(line)
                except json.JSONDecodeError:
                    continue
        return None


# ---------------------------------------------------------------------------
# Section builders
# ---------------------------------------------------------------------------

def _build_sec15a(
    lane_type: str,
    severity: str,
    workspace: pathlib.Path,
) -> Tuple[str, Dict[str, Any]]:
    """Section 15a - lane-specific rules to address."""
    lines = [
        "## Section 15a - Lane-specific R-rules you MUST address",
        "",
        f"_Lane type: `{lane_type}`. Severity: `{severity}`._",
        "",
    ]
    payload = _call_mcp(
        "vault_codified_rules_digest",
        {
            "workspace_path": str(workspace),
            "lane": lane_type,
            "severity": severity,
        },
    )
    meta: Dict[str, Any] = {
        "source": "vault_codified_rules_digest",
        "lane_type": lane_type,
        "severity": severity,
        "mcp_unavailable": payload is None,
    }
    if payload is None:
        lines.append(
            "_(warn: vault_codified_rules_digest unavailable - paste section "
            "verbatim and supplement from CLAUDE.md if R-rule context is "
            "needed)_"
        )
        lines.append("")
        return "\n".join(lines), meta

    digest: List[Dict[str, Any]] = payload.get("digest") or []
    must_address: List[str] = payload.get("lane_specific_must_address") or []
    warnings_top: List[Dict[str, Any]] = (
        payload.get("routine_violation_warnings") or []
    )
    pack_id = str(payload.get("context_pack_id") or "")

    if pack_id:
        lines.append(f"_Source: `vault_codified_rules_digest` | pack `{pack_id}`_")
        lines.append("")

    if must_address:
        lines.append(
            f"**Lane-mandated rules** ({len(must_address)} must be addressed):"
        )
        lines.append("")
        rule_lookup = {
            str(r.get("rule_id", "")): r
            for r in digest
            if isinstance(r, dict)
        }
        for rid in must_address:
            rule = rule_lookup.get(str(rid), {})
            name = str(rule.get("name", ""))[:80] or "(no name in digest)"
            override = str(rule.get("override_marker", "") or "(none)")[:40]
            lines.append(f"- **{rid}**: {name} | override: `{override}`")
        lines.append("")

    if warnings_top:
        lines.append("**Top routine-violation warnings** (highest failure rate):")
        lines.append("")
        for w in warnings_top[:5]:
            wid = str(w.get("rule_id", "?"))
            remediation = str(w.get("one_line_remediation", ""))[:120]
            lines.append(f"- **{wid}**: {remediation}")
        lines.append("")

    if not digest and not must_address:
        lines.append(
            f"_(no rules returned for lane `{lane_type}` severity `{severity}`)_"
        )
        lines.append("")

    lines.append(
        "Cite each rule by ID in your reply OR include the override marker. "
        "Non-zero pre-submit-check.sh exit = NOT paste-ready."
    )
    lines.append("")
    meta.update(
        {
            "context_pack_id": pack_id,
            "must_address": must_address,
            "digest_count": len(digest),
            "warnings_count": len(warnings_top),
        }
    )
    return "\n".join(lines), meta


def _build_sec15b(
    lane_type: str,
    severity: str,
    workspace: pathlib.Path,
    target_finding_class: str = "",
) -> Tuple[str, Dict[str, Any]]:
    """Section 15b - fill-in-blank skeleton templates."""
    lines = [
        "## Section 15b - Rule-section skeleton templates (fill in <<placeholders>>)",
        "",
        f"_Lane type: `{lane_type}`. Severity: `{severity}`._",
        "",
    ]
    args: Dict[str, Any] = {
        "lane_type": lane_type,
        "severity": severity,
        "workspace_path": str(workspace),
    }
    if target_finding_class:
        args["target_finding_class"] = target_finding_class
    payload = _call_mcp("vault_lane_skeleton_filler", args)
    meta: Dict[str, Any] = {
        "source": "vault_lane_skeleton_filler",
        "lane_type": lane_type,
        "severity": severity,
        "target_finding_class": target_finding_class,
        "mcp_unavailable": payload is None,
    }
    if payload is None:
        lines.append(
            "_(warn: vault_lane_skeleton_filler unavailable - no skeleton "
            "templates injected; see `tools/lane_skeleton_templates/*.tmpl` "
            "for the on-disk copies)_"
        )
        lines.append("")
        return "\n".join(lines), meta

    if payload.get("error"):
        err = str(payload.get("error", ""))
        valid = payload.get("valid_lane_types", [])
        lines.append(
            f"_(warn: vault_lane_skeleton_filler returned error `{err}`; "
            f"valid lane types: {valid}; no skeleton templates injected)_"
        )
        lines.append("")
        meta["error"] = err
        return "\n".join(lines), meta

    pack_id = str(payload.get("context_pack_id") or "")
    applicable_rules: List[str] = payload.get("applicable_rules") or []
    skeleton_sections: Dict[str, str] = payload.get("skeleton_sections") or {}
    placeholders: Dict[str, List[str]] = payload.get("placeholders_to_resolve") or {}
    workspace_anchors: Dict[str, str] = payload.get("workspace_anchors") or {}
    usage_note = str(payload.get("usage_note") or "")

    if pack_id:
        lines.append(f"_Source: `vault_lane_skeleton_filler` | pack `{pack_id}`_")
        lines.append("")

    if applicable_rules:
        lines.append(
            f"**Applicable rules for this lane** ({len(applicable_rules)}): "
            + ", ".join(f"`{r}`" for r in applicable_rules)
        )
        lines.append("")

    if usage_note:
        lines.append(f"_{usage_note}_")
        lines.append("")

    if not skeleton_sections:
        lines.append(
            f"_(no skeleton templates for lane `{lane_type}` at severity "
            f"`{severity}`; this is expected for hunt lanes which have no "
            "`.tmpl` files)_"
        )
        lines.append("")
    else:
        for rid, skeleton_text in skeleton_sections.items():
            lines.append(f"### Skeleton for {rid}")
            lines.append("")
            lines.append("```")
            lines.append(skeleton_text.rstrip())
            lines.append("```")
            lines.append("")
            phs = placeholders.get(rid, [])
            if phs:
                lines.append(f"**Placeholders to resolve** ({len(phs)}):")
                for ph in phs:
                    lines.append(f"- `{ph}`")
                lines.append("")
            anchor = workspace_anchors.get(rid, "")
            if anchor:
                lines.append(f"_Workspace anchor_: `{anchor}`")
                lines.append("")

    meta.update(
        {
            "context_pack_id": pack_id,
            "applicable_rules": applicable_rules,
            "skeleton_rule_ids": list(skeleton_sections.keys()),
            "skeleton_count": len(skeleton_sections),
        }
    )
    return "\n".join(lines), meta


def _build_sec15c_empirical_anchors(
    workspace: pathlib.Path,
    limit: int = 5,
) -> Tuple[str, Dict[str, Any]]:
    """Section 15c - recent empirical anchors.

    Walks `reports/v3_iter_*/lane_*` directories in REPO and surfaces the
    most-recent `limit` lane reports' top-line bottom-line verdict.
    """
    lines = [
        f"## Section 15c - Recent empirical anchors (last {limit} lane reports)",
        "",
    ]
    reports_root = REPO / "reports"
    items: List[Dict[str, Any]] = []
    if reports_root.is_dir():
        candidates: List[Tuple[float, pathlib.Path]] = []
        # Walk one level under reports/ for iteration dirs; one level deeper
        # for lane dirs. Find `results.md` (preferred) or any *.md.
        for iter_dir in reports_root.iterdir():
            if not iter_dir.is_dir():
                continue
            for lane_dir in iter_dir.iterdir():
                if not lane_dir.is_dir():
                    continue
                preferred = lane_dir / "results.md"
                md_files: List[pathlib.Path] = []
                if preferred.is_file():
                    md_files.append(preferred)
                else:
                    md_files.extend(sorted(lane_dir.glob("*.md")))
                for md in md_files[:1]:  # one per lane
                    try:
                        mtime = md.stat().st_mtime
                    except OSError:
                        continue
                    candidates.append((mtime, md))
        candidates.sort(key=lambda t: t[0], reverse=True)
        for _, md in candidates[:limit]:
            head_lines: List[str] = []
            try:
                with md.open("r", encoding="utf-8", errors="replace") as fp:
                    for _i, line in enumerate(fp):
                        if _i >= 40:
                            break
                        head_lines.append(line.rstrip())
            except OSError:
                continue
            title = ""
            verdict = ""
            for ln in head_lines:
                if not title and ln.startswith("# "):
                    title = ln[2:].strip()[:120]
                lower = ln.lower()
                if not verdict and (
                    "verdict" in lower
                    or "bottom-line" in lower
                    or "**at-wall" in lower
                ):
                    verdict = ln.strip()[:240]
                if title and verdict:
                    break
            try:
                rel = md.relative_to(REPO)
            except ValueError:
                rel = md
            items.append(
                {
                    "path": str(rel),
                    "title": title or md.parent.name,
                    "verdict": verdict,
                }
            )

    if not items:
        lines.append(
            "_(no recent lane reports found under `reports/v3_iter_*/`; this is "
            "expected on a freshly-cloned workspace)_"
        )
        lines.append("")
    else:
        for it in items:
            lines.append(f"- **{it['title']}** (`{it['path']}`)")
            if it["verdict"]:
                lines.append(f"  - {it['verdict']}")
        lines.append("")
        lines.append(
            "_Use these as calibration anchors: do NOT re-derive their "
            "findings; cite them and move past._"
        )
        lines.append("")

    meta: Dict[str, Any] = {
        "source": "reports_scan",
        "items_count": len(items),
        "items": items,
    }
    return "\n".join(lines), meta


def _load_busywork_from_file(path: pathlib.Path) -> List[Tuple[str, str]]:
    """Load extra busywork lines from a 2-column tsv file (pattern\\treason)."""
    out: List[Tuple[str, str]] = []
    try:
        with path.open("r", encoding="utf-8", errors="replace") as fp:
            for line in fp:
                line = line.rstrip("\n")
                if not line.strip() or line.lstrip().startswith("#"):
                    continue
                parts = line.split("\t", 1)
                if len(parts) == 2:
                    out.append((parts[0].strip(), parts[1].strip()))
                else:
                    out.append((line.strip(), ""))
    except OSError as exc:
        _emit_warn(f"could not read busywork file {path}: {exc!r}")
    return out


def _build_sec15d_busywork(
    extra: Optional[List[Tuple[str, str]]] = None,
) -> Tuple[str, Dict[str, Any]]:
    """Section 15d - busywork-to-refuse."""
    lines = [
        "## Section 15d - Busywork to REFUSE (cite source, don't re-derive)",
        "",
        "_Source: Lane JJ iter5 ranked-rule recommendations + Lane QQQ iter11 "
        "at-the-wall assessment + AFK-rule (`~/.claude/CLAUDE.md`) + L34 "
        "draft-modification-doctrine._",
        "",
    ]
    rows: List[Tuple[str, str]] = list(BUSYWORK_DEFAULTS)
    if extra:
        rows.extend(extra)
    for pattern, reason in rows:
        if reason:
            lines.append(f"- {pattern}")
            lines.append(f"  - REASON: {reason}")
        else:
            lines.append(f"- {pattern}")
    lines.append("")
    lines.append(
        "If a worker asks you to do any of the above, REPLY with an "
        "honest verdict citing the source and refuse the busywork."
    )
    lines.append("")
    meta: Dict[str, Any] = {
        "source": "BUSYWORK_DEFAULTS+extra",
        "default_count": len(BUSYWORK_DEFAULTS),
        "extra_count": len(extra or []),
    }
    return "\n".join(lines), meta


# ---------------------------------------------------------------------------
# Top-level assembly
# ---------------------------------------------------------------------------

def build_prefetch_block(
    *,
    lane_type: str,
    severity: str,
    workspace: Optional[pathlib.Path],
    target_finding_class: str = "",
    busywork_extra: Optional[List[Tuple[str, str]]] = None,
    anchor_limit: int = 5,
    include_anchors: bool = True,
    include_busywork: bool = True,
) -> Tuple[str, Dict[str, Any]]:
    """Build the full META-1 enrichment block (15a + 15b + optional 15c/15d)."""
    if lane_type not in VALID_LANE_TYPES:
        raise ValueError(
            f"invalid lane_type {lane_type!r}; expected one of {VALID_LANE_TYPES}"
        )
    if severity not in VALID_SEVERITIES and severity.upper() not in VALID_SEVERITIES:
        raise ValueError(
            f"invalid severity {severity!r}; expected one of {VALID_SEVERITIES}"
        )
    ws = workspace or REPO

    header = [
        "<!-- BEGIN agent-brief-prefetch META-1 block -->",
        "",
        f"_Pre-fetched by `tools/agent-brief-prefetch.py` at lane "
        f"`{lane_type}` severity `{severity}` workspace `{ws.name}`. "
        "Paste this block into the Agent-tool prompt verbatim - it "
        "supplies Section 15a/15b/15c/15d that the Agent tool does NOT "
        "auto-inject._",
        "",
    ]
    sections_meta: Dict[str, Any] = {
        "lane_type": lane_type,
        "severity": severity,
        "workspace": str(ws),
        "target_finding_class": target_finding_class,
    }

    sec_15a_text, sec_15a_meta = _build_sec15a(lane_type, severity, ws)
    sec_15b_text, sec_15b_meta = _build_sec15b(
        lane_type, severity, ws, target_finding_class
    )
    sections_meta["sec15a"] = sec_15a_meta
    sections_meta["sec15b"] = sec_15b_meta

    parts: List[str] = ["\n".join(header), sec_15a_text, sec_15b_text]

    if include_anchors:
        sec_15c_text, sec_15c_meta = _build_sec15c_empirical_anchors(
            ws, limit=anchor_limit
        )
        sections_meta["sec15c"] = sec_15c_meta
        parts.append(sec_15c_text)

    if include_busywork:
        sec_15d_text, sec_15d_meta = _build_sec15d_busywork(busywork_extra)
        sections_meta["sec15d"] = sec_15d_meta
        parts.append(sec_15d_text)

    parts.append("<!-- END agent-brief-prefetch META-1 block -->\n")
    text = "\n".join(parts)
    return text, sections_meta


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def _build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="agent-brief-prefetch",
        description=(
            "Pre-fetch a META-1 enrichment block (Section 15a + 15b + recent "
            "empirical anchors + busywork-to-refuse) for pasting into an "
            "Agent-tool prompt. Re-uses vault_codified_rules_digest + "
            "vault_lane_skeleton_filler MCP callables so the output matches "
            "what tools/agent-prompt-hacker-augmenter.py would inject in the "
            "provider-dispatch path. See "
            "docs/AGENT_DISPATCH_PATTERN.md for the orchestrator workflow."
        ),
    )
    p.add_argument(
        "--lane-type",
        required=True,
        choices=list(VALID_LANE_TYPES),
        help="Lane type; mirrors tools/lane_skeleton_templates/_lane_rule_map.json.",
    )
    p.add_argument(
        "--severity",
        required=True,
        help="Severity filter for Section 15a/15b "
        "(LOW | MEDIUM | HIGH | CRITICAL | any).",
    )
    p.add_argument(
        "--workspace",
        default=None,
        help="Workspace path (default: auditooor-mcp REPO root).",
    )
    p.add_argument(
        "--target-finding-class",
        default="",
        help="Optional finding-class hint passed to vault_lane_skeleton_filler "
        "for workspace-anchor injection.",
    )
    p.add_argument(
        "--anchor-limit",
        type=int,
        default=5,
        help="Max number of recent lane reports to include in Section 15c "
        "(default: 5).",
    )
    p.add_argument(
        "--no-anchors",
        action="store_true",
        help="Omit Section 15c (recent empirical anchors).",
    )
    p.add_argument(
        "--no-busywork",
        action="store_true",
        help="Omit Section 15d (busywork-to-refuse).",
    )
    p.add_argument(
        "--busywork-file",
        default=None,
        help="Optional tab-separated extra busywork file (pattern\\treason per "
        "line). Lines starting with `#` are comments.",
    )
    p.add_argument(
        "--json",
        action="store_true",
        help="Emit JSON metadata (sections + counts + sources) to stderr after "
        "the markdown block on stdout. Useful for tooling integration.",
    )
    p.add_argument(
        "--quiet",
        action="store_true",
        help="Suppress the initial CLI invocation echo on stderr.",
    )
    return p


def main(argv: Optional[List[str]] = None) -> int:
    parser = _build_parser()
    args = parser.parse_args(argv)

    workspace: Optional[pathlib.Path] = None
    if args.workspace:
        workspace = pathlib.Path(args.workspace).expanduser().resolve()
        if not workspace.exists():
            _emit_warn(f"workspace {workspace} does not exist; falling back to REPO root")
            workspace = None

    busywork_extra: Optional[List[Tuple[str, str]]] = None
    if args.busywork_file:
        busywork_extra = _load_busywork_from_file(
            pathlib.Path(args.busywork_file).expanduser().resolve()
        )

    try:
        text, meta = build_prefetch_block(
            lane_type=args.lane_type,
            severity=args.severity,
            workspace=workspace,
            target_finding_class=args.target_finding_class,
            busywork_extra=busywork_extra,
            anchor_limit=args.anchor_limit,
            include_anchors=not args.no_anchors,
            include_busywork=not args.no_busywork,
        )
    except ValueError as exc:
        _emit_err(str(exc))
        return 2

    if not args.quiet:
        _emit_warn(
            f"emitting prefetch block: lane={args.lane_type} severity="
            f"{args.severity} workspace={(workspace or REPO).name}"
        )

    sys.stdout.write(text)
    if not text.endswith("\n"):
        sys.stdout.write("\n")
    sys.stdout.flush()

    if args.json:
        payload = {
            "schema": SCHEMA,
            "lane_type": args.lane_type,
            "severity": args.severity,
            "workspace": str(workspace or REPO),
            "sections": meta,
        }
        sys.stderr.write(json.dumps(payload, sort_keys=True) + "\n")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
