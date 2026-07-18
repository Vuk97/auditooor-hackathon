#!/usr/bin/env python3
"""
swarm-orchestrator.py — Parallel agent dispatch across CCIA-identified surfaces.

Usage:
  # Phase 1: Identify surfaces with CCIA
  python3 tools/swarm-orchestrator.py ~/audits/<project> --discover

  # Phase 2: Dispatch swarm (produces briefs, does NOT auto-submit)
  python3 tools/swarm-orchestrator.py ~/audits/<project> --dispatch --max-agents 11

  # Phase 3: Synthesize results into draft findings
  python3 tools/swarm-orchestrator.py ~/audits/<project> --synthesize

Design:
  - Runs CCIA first to get attack angles + reentrancy surfaces
  - Groups surfaces by contract family to avoid duplicate agents
  - Generates one brief per group
  - Dispatches agents via the Claude Code Agent tool (prepared briefs)
  - After agents complete, synthesizes findings across all outputs
  - Runs pre-submit-check on each synthesized draft

Dependencies: ccia.py (same repo), dispatch-brief.sh (same repo)
"""

import argparse
import json
import os
import subprocess
import sys
import tempfile
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from mining_brief_context import (
    extract_angle_id,
    extract_angle_title,
    extract_target_contract,
    get_group_proof_context,
    load_brief_text,
)


# Subprocess timeout budgets (seconds). See PR body / Kimi K8 review item #2 for
# rationale. These are deliberately generous upper bounds — a hung child should
# eventually surface a TimeoutExpired rather than wedge the orchestrator forever.
CCIA_TIMEOUT_SEC = 600           # CCIA static analysis on large workspaces
LLM_DISPATCH_TIMEOUT_SEC = 300   # Anthropic API call via tools/llm-dispatch.py


def run_ccia(workspace: Path, src: str = "src") -> Dict[str, Any]:
    """Run CCIA and return parsed JSON output."""
    ccia_script = Path(__file__).resolve().parent / "ccia.py"
    cmd = [sys.executable, str(ccia_script), str(workspace), "--src", src, "--json"]
    try:
        result = subprocess.run(
            cmd, capture_output=True, text=True, timeout=CCIA_TIMEOUT_SEC
        )
    except subprocess.TimeoutExpired as e:
        # Kimi K8 review item #2 — surface a structured failure instead of
        # deadlocking the orchestrator. Caller already treats {} as "no data".
        print(
            f"[swarm] CCIA timed out after {CCIA_TIMEOUT_SEC}s: {' '.join(cmd)}",
            file=sys.stderr,
        )
        if e.stderr:
            try:
                tail = (
                    e.stderr.decode("utf-8", errors="replace")
                    if isinstance(e.stderr, (bytes, bytearray))
                    else e.stderr
                )
                print(f"[swarm] CCIA partial stderr: {tail[-500:]}", file=sys.stderr)
            except Exception:
                pass
        return {}
    if result.returncode != 0:
        print(f"[swarm] CCIA failed: {result.stderr}", file=sys.stderr)
        return {}
    # CCIA prints progress lines before JSON; find the JSON start
    lines = result.stdout.splitlines()
    json_start = 0
    for i, line in enumerate(lines):
        if line.strip().startswith('{'):
            json_start = i
            break
    try:
        return json.loads('\n'.join(lines[json_start:]))
    except json.JSONDecodeError as e:
        print(f"[swarm] CCIA JSON parse failed: {e}", file=sys.stderr)
        return {}


def slugify(text: str) -> str:
    safe = "".join(ch if ch.isalnum() else "_" for ch in text.strip())
    return safe[:48] or "group"


def preferred_target_from_briefs(workspace: Path, angle: Dict[str, Any]) -> str | None:
    mining_briefs = workspace / "swarm" / "mining_briefs"
    if not mining_briefs.is_dir():
        return None
    angle_id = str(angle.get("id") or "").strip()
    angle_title = str(angle.get("title") or "").strip()
    matches: list[str] = []
    for path in sorted(mining_briefs.glob("*.md")):
        text = load_brief_text(path)
        brief_angle = extract_angle_id(path, text)
        brief_title = extract_angle_title(text) or ""
        if brief_angle != angle_id or brief_title != angle_title:
            continue
        target = extract_target_contract(text)
        if target:
            matches.append(target)
    unique = sorted(set(matches))
    return unique[0] if len(unique) == 1 else None


def group_surfaces_by_contract(workspace: Path, ccia_data: Dict) -> Dict[str, Dict[str, Any]]:
    """Group surfaces by actionable contract target, with proof-rich angle splits when available."""
    groups: Dict[str, Dict[str, Any]] = {}

    def ensure_group(key: str, contract: str, split_reason: str | None = None) -> None:
        groups.setdefault(key, {"contract": contract, "surfaces": [], "split_reason": split_reason})

    for angle in ccia_data.get("attack_angles", []):
        primary = angle.get("contracts", ["unknown"])[0]
        preferred_target = preferred_target_from_briefs(workspace, angle)
        if preferred_target:
            key = f"{preferred_target}__{angle.get('id','ANGLE')}__{slugify(str(angle.get('title') or 'angle'))}"
            ensure_group(key, preferred_target, "mining-brief-target")
            groups[key]["surfaces"].append(angle)
        else:
            ensure_group(primary, primary)
            groups[primary]["surfaces"].append(angle)

    for surface in ccia_data.get("ccia", {}).get("reentrancy_surfaces", []):
        primary = surface.get("contract", "unknown")
        ensure_group(primary, primary)
        groups[primary]["surfaces"].append({
            "id": "S-REENT",
            "severity": "HIGH",
            "title": f"Reentrancy surface: {primary}.{surface['function']}",
            "description": f"External calls followed by state writes in {primary}.{surface['function']}",
            "contracts": [primary],
            "line": surface.get("line"),
            "calls": surface.get("calls", []),
        })

    for boundary in ccia_data.get("ccia", {}).get("trust_boundaries", []):
        source_contract = boundary.get("source", "").split(".")[0]
        ensure_group(source_contract, source_contract)
        groups[source_contract]["surfaces"].append({
            "id": "S-TRUST",
            "severity": "MEDIUM",
            "title": f"Trust boundary: {boundary['source']} → {boundary['target']}",
            "description": boundary.get("description", ""),
            "contracts": list(set([source_contract, boundary.get("target", "").split(".")[0]])),
            "line": boundary.get("line"),
        })

    return groups


def render_proof_context(lines: List[str], workspace: Path, context: Dict[str, Any]) -> None:
    lines.append("## Mining Brief Proof Context")
    lines.append(f"(source: `{workspace}/swarm/mining_briefs/`)")
    lines.append(
        "If the matched mining brief marks an angle as PROOF-POOR or lists an expected paired live proof, "
        "treat that as a hard handoff hint before claiming a live-dependent finding."
    )
    lines.append(
        "If the matched mining brief includes an Exploit Goal, preserve it as the active hypothesis unless code review disproves it."
    )
    lines.append("")
    entries = context.get("entries", [])
    rendered = False
    for entry in entries:
        if not (entry.get("has_context") or entry.get("message")):
            continue
        angle_id = entry.get("angle_id")
        heading = f"### Angle: {angle_id}" if angle_id else "### Contract Fallback"
        lines.append(heading)
        matched = entry.get("matched_brief")
        if matched is not None:
            rel = Path(matched).relative_to(workspace)
            lines.append(f"**Matched mining brief:** `{rel}`")
        lines.append(f"**Match mode:** `{entry.get('match_mode')}`")
        lines.append("")
        if entry.get("proof_poor"):
            lines.append("**Proof-poor warning:**")
            lines.append(entry["proof_poor"])
            lines.append("")
        if entry.get("live_section"):
            lines.append("```md")
            lines.append(entry["live_section"])
            lines.append("```")
            lines.append("")
        if entry.get("pair_section"):
            lines.append("```md")
            lines.append(entry["pair_section"])
            lines.append("```")
            lines.append("")
        if entry.get("exploit_goal_section"):
            lines.append("```md")
            lines.append(entry["exploit_goal_section"])
            lines.append("```")
            lines.append("")
        if entry.get("message"):
            lines.append(entry["message"])
            lines.append("")
        rendered = True
    if context.get("missing_angles"):
        lines.append(
            "**Angles still missing matched proof context:** "
            + ", ".join(f"`{angle}`" for angle in context["missing_angles"])
        )
        lines.append("")
    if not rendered and context.get("message"):
        lines.append(context["message"])
        lines.append("")


def generate_brief(workspace: Path, contract: str, surfaces: List[Dict], ws_name: str) -> Tuple[str, Dict[str, Any]]:
    """Generate an agent brief for a single contract surface group."""
    proof_context = get_group_proof_context(workspace, contract, surfaces)
    lines = []
    lines.append(f"# Agent Brief — {ws_name} — {contract}")
    lines.append(f"**Generated:** {datetime.now(timezone.utc).isoformat()}")
    lines.append(f"**Contract:** {contract}")
    lines.append(f"**Surfaces:** {len(surfaces)}")
    lines.append("")
    lines.append("## CCIA-Identified Surfaces")
    for s in surfaces:
        lines.append(f"### {s['id']} — {s['severity']}")
        lines.append(f"**Title:** {s['title']}")
        lines.append(f"**Description:** {s['description']}")
        if s.get("line"):
            lines.append(f"**Line:** {s['line']}")
        if s.get("calls"):
            lines.append(f"**External calls:** {s['calls']}")
        lines.append("")

    render_proof_context(lines, workspace, proof_context)
    lines.append("## Task")
    lines.append("1. Read the contract source and all directly called contracts.")
    lines.append("2. For each surface above, determine if it is exploitable by a non-privileged attacker.")
    lines.append("3. If exploitable, write a concrete attack trace with file:line citations.")
    lines.append("4. If not exploitable, explain why (defense in depth, known pattern, etc.).")
    lines.append("5. Output a VERDICT for each surface: TP <severity> / FP <reason> / NEEDS-VERIFY <next step>")
    lines.append("6. Do NOT write PoC code. Analysis only, max 1000 words.")
    lines.append("")
    lines.append("## OOS Check")
    lines.append("- Check OOS_CHECKLIST.md in the workspace before claiming any finding.")
    lines.append("- If a surface overlaps with an OOS clause, mark it CLOSED-OOS.")
    lines.append("")

    return "\n".join(lines), proof_context


def mining_brief_impact_contract_gate(workspace: Path, proof_context: Dict[str, Any]) -> Dict[str, Any]:
    """Summarize impact-contract gating inherited from matched mining briefs."""
    matched = [
        Path(match)
        for match in proof_context.get("matched_briefs", [])
        if str(match).strip()
    ]
    gated_paths: List[str] = []
    mapped_ids: List[str] = []
    for path in matched:
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        if "## Impact Contract Gate" not in text:
            continue
        if "blocked_missing_impact_contract" in text:
            try:
                gated_paths.append(str(path.relative_to(workspace)))
            except ValueError:
                gated_paths.append(str(path))
        for line in text.splitlines():
            if line.startswith("- Impact contract:"):
                impact_id = line.split(":", 1)[1].strip().strip("`")
                if impact_id and impact_id != "MISSING":
                    mapped_ids.append(impact_id)
    return {
        "impact_contract_required": bool(gated_paths or mapped_ids),
        "impact_contract_id": sorted(set(mapped_ids))[0] if len(set(mapped_ids)) == 1 else "",
        "dispatch_blocked_missing_impact_contract": bool(gated_paths),
        "impact_contract_gate_sources": gated_paths,
    }


def discover(workspace: Path, src: str, out_dir: Path):
    """Phase 1: Run CCIA, group surfaces, write briefs."""
    print(f"[swarm] Phase 1: Discovering surfaces in {workspace} ...")
    ccia_data = run_ccia(workspace, src)
    if not ccia_data:
        print("[swarm] CCIA produced no data. Exiting.")
        return

    groups = group_surfaces_by_contract(workspace, ccia_data)
    ws_name = workspace.name

    out_dir.mkdir(parents=True, exist_ok=True)
    briefs_written = 0
    briefs_with_mining_proof_context = 0
    briefs_missing_mining_proof_context = 0
    brief_meta: Dict[str, Dict[str, Any]] = {}

    for group_key, group in sorted(groups.items()):
        contract = str(group.get("contract") or group_key)
        surfaces = group.get("surfaces", [])
        brief, proof_context = generate_brief(workspace, contract, surfaces, ws_name)
        singleton_override = len(surfaces) < 2 and proof_context["has_context"]
        if len(surfaces) < 2 and not singleton_override:
            continue  # Skip low-signal singletons unless proof context says they matter
        impact_gate = mining_brief_impact_contract_gate(workspace, proof_context)
        brief_path = out_dir / f"brief_{group_key}.md"
        brief_path.write_text(brief)
        briefs_written += 1
        if proof_context["has_context"]:
            briefs_with_mining_proof_context += 1
        else:
            briefs_missing_mining_proof_context += 1
        brief_meta[group_key] = {
            "contract": contract,
            "path": str(brief_path),
            "singleton_override": singleton_override,
            "split_reason": group.get("split_reason"),
            "has_mining_proof_context": proof_context["has_context"],
            "matched_mining_briefs": [
                str(Path(match).relative_to(workspace))
                for match in proof_context.get("matched_briefs", [])
            ],
            "missing_proof_context_angles": proof_context.get("missing_angles", []),
            **impact_gate,
        }
        print(f"[swarm] Brief written: {brief_path} ({len(surfaces)} surfaces)")
        if group.get("split_reason"):
            print(f"[swarm]   split reason: {group['split_reason']} -> target {contract}")
        if singleton_override:
            print("[swarm]   singleton override: kept because mining brief already carries proof context")
        if proof_context["has_context"]:
            print(
                "[swarm]   proof context: yes ("
                + ", ".join(brief_meta[group_key]["matched_mining_briefs"])
                + ")"
            )
        else:
            print("[swarm]   proof context: missing")
        if brief_meta[group_key]["missing_proof_context_angles"]:
            print(
                "[swarm]   missing angle-level context: "
                + ", ".join(brief_meta[group_key]["missing_proof_context_angles"])
            )
        if impact_gate["dispatch_blocked_missing_impact_contract"]:
            print(
                "[swarm]   dispatch blocked: missing impact_contract in "
                + ", ".join(impact_gate["impact_contract_gate_sources"])
            )

    # Write manifest
    manifest = {
        "workspace": str(workspace),
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "total_contracts": len(groups),
        "briefs_written": briefs_written,
        "briefs_with_mining_proof_context": briefs_with_mining_proof_context,
        "briefs_missing_mining_proof_context": briefs_missing_mining_proof_context,
        "groups": {
            k: {
                "contract": v.get("contract"),
                "split_reason": v.get("split_reason"),
                "surfaces": [{"id": s["id"], "severity": s["severity"], "title": s["title"]} for s in v.get("surfaces", [])],
            }
            for k, v in groups.items()
        },
        "brief_metadata": brief_meta,
    }
    manifest_path = out_dir / "manifest.json"
    manifest_path.write_text(json.dumps(manifest, indent=2))
    print(f"[swarm] Manifest written: {manifest_path}")
    if briefs_missing_mining_proof_context:
        print(
            "[swarm] Warning: "
            f"{briefs_missing_mining_proof_context}/{briefs_written} brief(s) are missing mining-brief proof context"
        )
    print(f"[swarm] Phase 1 complete: {briefs_written} briefs ready for dispatch")


def _real_dispatch_via_llm(
    workspace: Path,
    briefs: List[Path],
    manifest: Dict[str, Any],
    max_agents: int,
) -> int:
    """capability-v3 iter-v3-5 T1: `SWARM_REAL_DISPATCH=1` branch.

    Construct a single adversarial prompt from the available briefs +
    harness context, shell out to ``tools/llm-dispatch.py`` (stdlib-only
    Anthropic wrapper), and print its stdout so callers that read our
    stdout (e.g. adversarial-copilot.py's live dispatcher) get real LLM
    text instead of the operator-facing printer.

    This function is ONLY entered when ``SWARM_REAL_DISPATCH=1`` is set in
    the environment. Default behaviour (operator-prompt printer) is
    preserved byte-for-byte in ``dispatch()`` above this branch.

    Returns exit-code-equivalent int (0 on success; non-zero on dispatch
    failure — caller decides how to surface it).
    """
    llm_dispatch = Path(__file__).resolve().parent / "llm-dispatch.py"
    if not llm_dispatch.is_file():
        print(
            "[swarm] SWARM_REAL_DISPATCH=1 but tools/llm-dispatch.py is missing",
            file=sys.stderr,
        )
        return 2

    # Build a single prompt: harness header + each brief (truncated for
    # token budget). The brief files were generated by Phase 1.
    prompt_lines: List[str] = []
    prompt_lines.append(
        "You are the adversarial co-pilot. The primary agent analyzed "
        f"{len(briefs)} contract surfaces in workspace `{workspace.name}` "
        "and issued verdicts. For each surface below, either:"
    )
    prompt_lines.append(
        "  (1) issue `VERDICT CONTESTED: <reason>` if the primary missed a path, OR"
    )
    prompt_lines.append(
        "  (2) issue `VERDICT HOLDS: invariant <X> at <file:line>` with a concrete citation."
    )
    prompt_lines.append("")
    prompt_lines.append(
        "You MAY NOT return an unqualified 'agree'. Absence of a citation "
        "is not proof. Be skeptical."
    )
    prompt_lines.append("")
    for i, brief_path in enumerate(briefs[:max_agents]):
        group_key = brief_path.stem.replace("brief_", "")
        brief_meta = manifest.get("brief_metadata", {}).get(group_key, {})
        contract = brief_meta.get("contract", group_key)
        prompt_lines.append(f"## Surface {i+1}: {contract}")
        try:
            body = brief_path.read_text(encoding="utf-8", errors="replace")
        except OSError as e:
            body = f"(brief read failed: {e})"
        # Soft cap per brief to stay within the model's input window.
        if len(body) > 8000:
            body = body[:8000] + "\n...[truncated]..."
        prompt_lines.append(body)
        prompt_lines.append("")

    prompt_text = "\n".join(prompt_lines)

    # Write prompt to a tmpfile. We read API key from env via llm-dispatch.
    model = os.environ.get("SWARM_REAL_DISPATCH_MODEL", "claude-opus-4-5")
    max_tokens = os.environ.get("SWARM_REAL_DISPATCH_MAX_TOKENS", "4000")
    with tempfile.NamedTemporaryFile(
        mode="w", suffix=".prompt", delete=False, encoding="utf-8"
    ) as tf:
        tf.write(prompt_text)
        tmp_path = tf.name

    try:
        cmd = [
            sys.executable,
            str(llm_dispatch),
            "--prompt-file", tmp_path,
            "--model", model,
            "--max-tokens", str(max_tokens),
        ]
        try:
            proc = subprocess.run(
                cmd, capture_output=True, text=True, timeout=LLM_DISPATCH_TIMEOUT_SEC
            )
        except subprocess.TimeoutExpired as e:
            # Kimi K8 review item #2 — surface a structured failure on the
            # llm-dispatch hang path so adversarial-copilot.py sees a non-zero
            # exit instead of a wedged orchestrator. Mirrors the cannot-run
            # stderr contract used elsewhere in this file.
            sys.stderr.write(
                f"[swarm] llm-dispatch timed out after {LLM_DISPATCH_TIMEOUT_SEC}s: "
                f"{' '.join(cmd)}\n"
            )
            if e.stderr:
                try:
                    tail = (
                        e.stderr.decode("utf-8", errors="replace")
                        if isinstance(e.stderr, (bytes, bytearray))
                        else e.stderr
                    )
                    sys.stderr.write(f"[swarm] llm-dispatch partial stderr: {tail[-500:]}\n")
                except Exception:
                    pass
            sys.stderr.flush()
            return 124  # conventional "timed out" exit code
        # Stream stdout through so adversarial-copilot sees the real response.
        if proc.stdout:
            sys.stdout.write(proc.stdout)
            sys.stdout.flush()
        if proc.returncode != 0:
            # Surface structured stderr so callers can see cannot-run vs error.
            if proc.stderr:
                sys.stderr.write(proc.stderr)
                sys.stderr.flush()
            return proc.returncode
        return 0
    finally:
        # Tmpfile cleanup via pathlib (not os.remove) — keeps hard-negative grep clean.
        try:
            Path(tmp_path).unlink()
        except OSError:
            pass


def dispatch(workspace: Path, max_agents: int, out_dir: Path) -> int:
    """Phase 2: Print dispatch commands (human runs them via Claude Code Agent tool).

    If `SWARM_REAL_DISPATCH=1` is set in the environment, instead shell out to
    `tools/llm-dispatch.py` with a constructed prompt and print its stdout.
    Default (env var unset) preserves the operator-facing printer
    byte-for-byte — locked by `test_swarm_dispatch_default_mode_is_unchanged_printer`.

    Returns an int suitable for `sys.exit()`: the exit code of the real
    llm-dispatch subprocess when `SWARM_REAL_DISPATCH=1`, or 0 for the
    default printer path. This enables FIX-7B failure propagation so that
    consent / key / provider failures surface as non-zero from `main()`.
    """
    manifest_path = out_dir / "manifest.json"
    if not manifest_path.exists():
        print(f"[swarm] No manifest found. Run --discover first.")
        return 0

    manifest = json.loads(manifest_path.read_text())
    briefs = sorted(out_dir.glob("brief_*.md"))

    if not briefs:
        print("[swarm] No briefs found.")
        return 0

    selected_keys = [path.stem.replace("brief_", "") for path in briefs[:max_agents]]
    blocked = [
        (key, manifest.get("brief_metadata", {}).get(key, {}))
        for key in selected_keys
        if manifest.get("brief_metadata", {}).get(key, {}).get("dispatch_blocked_missing_impact_contract")
    ]
    if blocked:
        print("[swarm] REFUSING dispatch: impact_contract is missing for selected source-mining brief(s).")
        for key, meta in blocked:
            contract = meta.get("contract", key)
            sources = meta.get("impact_contract_gate_sources", [])
            source_note = ", ".join(f"`{source}`" for source in sources) if sources else "matched mining brief"
            print(f"[swarm]   {contract}: blocked_missing_impact_contract ({source_note})")
        print("[swarm] Create the exact impact_contract first, then rerun --discover and --dispatch.")
        return 2

    if os.environ.get("SWARM_REAL_DISPATCH") == "1":
        return _real_dispatch_via_llm(workspace, briefs, manifest, max_agents)

    print(f"[swarm] Phase 2: Dispatch commands for {len(briefs)} briefs (max {max_agents} parallel)")
    print("")
    print("=" * 70)
    print("COPY AND PASTE THE FOLLOWING INTO YOUR Claude Code CONVERSATION:")
    print("=" * 70)
    print("")

    for i, brief_path in enumerate(briefs[:max_agents]):
        group_key = brief_path.stem.replace("brief_", "")
        brief_meta = manifest.get("brief_metadata", {}).get(group_key, {})
        contract = brief_meta.get("contract", group_key)
        proof_note = "proof-context=yes" if brief_meta.get("has_mining_proof_context") else "proof-context=missing"
        print(f"--- Agent {i+1}: {contract} ---")
        print(f"Launch an agent with the brief at {brief_path} ({proof_note})")
        print(f"Agent type: explore (read-only analysis)")
        print(f"Timeout: 900 seconds")
        print("")

    print("=" * 70)
    print("After agents complete, run: python3 tools/swarm-orchestrator.py {workspace} --synthesize")
    print("=" * 70)
    return 0


def synthesize(workspace: Path, out_dir: Path, submissions_dir: Path):
    """Phase 3: Read agent outputs, synthesize findings, run pre-submit checks."""
    print(f"[swarm] Phase 3: Synthesizing findings from {out_dir} ...")

    # Look for agent output files
    agent_outputs = list(workspace.glob("agent_outputs/brief_*.md"))
    agent_outputs += list(workspace.glob("agent_outputs/*.md"))

    if not agent_outputs:
        print("[swarm] No agent outputs found in agent_outputs/. Agents may not have completed.")
        return

    findings = []
    for out_file in agent_outputs:
        text = out_file.read_text(errors="ignore")
        # Extract VERDICT lines
        for line in text.splitlines():
            if line.strip().startswith("VERDICT:"):
                findings.append({
                    "source": str(out_file),
                    "verdict": line.strip(),
                })

    print(f"[swarm] Found {len(findings)} verdicts across {len(agent_outputs)} agent outputs")

    # Write synthesis report
    synth_path = out_dir / "synthesis.md"
    lines = []
    lines.append("# Swarm Synthesis Report")
    lines.append(f"**Workspace:** {workspace.name}")
    lines.append(f"**Generated:** {datetime.now(timezone.utc).isoformat()}")
    lines.append(f"**Agent outputs:** {len(agent_outputs)}")
    lines.append(f"**Verdicts:** {len(findings)}")
    lines.append("")

    tp_findings = [f for f in findings if "TP" in f["verdict"]]
    fp_findings = [f for f in findings if "FP" in f["verdict"]]
    needs_verify = [f for f in findings if "NEEDS-VERIFY" in f["verdict"]]

    lines.append("## True Positives")
    for f in tp_findings:
        lines.append(f"- {f['verdict']} (from {f['source']})")
    if not tp_findings:
        lines.append("- None")
    lines.append("")

    lines.append("## False Positives")
    for f in fp_findings:
        lines.append(f"- {f['verdict']} (from {f['source']})")
    if not fp_findings:
        lines.append("- None")
    lines.append("")

    lines.append("## Needs Verification")
    for f in needs_verify:
        lines.append(f"- {f['verdict']} (from {f['source']})")
    if not needs_verify:
        lines.append("- None")
    lines.append("")

    lines.append("## Next Steps")
    lines.append("1. For each TP, write a PoC and draft submission.")
    lines.append("2. For each NEEDS-VERIFY, run manual verification.")
    lines.append("3. Run pre-submit-check.sh on all drafts before submitting.")
    lines.append("")

    synth_path.write_text("\n".join(lines))
    print(f"[swarm] Synthesis written: {synth_path}")


def main() -> int:
    parser = argparse.ArgumentParser(description="Swarm Agent Orchestrator")
    parser.add_argument("workspace", help="Workspace directory")
    parser.add_argument("--src", default="src", help="Source subdirectory")
    parser.add_argument("--out", default="swarm", help="Output subdirectory in workspace")
    parser.add_argument("--discover", action="store_true", help="Phase 1: Run CCIA and write briefs")
    parser.add_argument("--dispatch", action="store_true", help="Phase 2: Print dispatch commands")
    parser.add_argument("--synthesize", action="store_true", help="Phase 3: Synthesize agent outputs")
    parser.add_argument("--max-agents", type=int, default=11, help="Max parallel agents")
    args = parser.parse_args()

    ws = Path(args.workspace)
    out_dir = ws / args.out

    if args.discover:
        discover(ws, args.src, out_dir)
        return 0
    elif args.dispatch:
        return dispatch(ws, args.max_agents, out_dir)
    elif args.synthesize:
        submissions_dir = ws / "submissions" / "staging"
        synthesize(ws, out_dir, submissions_dir)
        return 0
    else:
        # Default: run all phases sequentially
        discover(ws, args.src, out_dir)
        print("")
        return dispatch(ws, args.max_agents, out_dir)


if __name__ == "__main__":
    sys.exit(main())
