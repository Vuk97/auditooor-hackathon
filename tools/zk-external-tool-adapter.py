#!/usr/bin/env python3
# r36-rebuttal: lane zk-external-tool-adapter registered in .auditooor/agent_pathspec.json
"""ZK external-tool adapter (zkbugs.com/tools + zkhydra family).

Phase-1 zkbugs/zkhydra integration: this adapter INVOKES a real external ZK
analysis tool (circomspect / picus / zkhydra) against a target and parses its
output into the auditooor MIMO-sidecar shape so any findings flow into the
learning loop (r76-hallucination-guard.scan_mimo_dir,
triage-kill-promoter.parse_mimo_sidecar, workspace-coverage-heatmap).

DESIGN CONSTRAINTS (no fabrication):
  (a) Detect availability  - if the tool binary is not on PATH, emit a clear
      'tool-not-installed' verdict and exit 0 (graceful, never invents output).
  (b) Run when available    - shell out to the real binary with a bounded
      timeout and capture stdout/stderr/returncode.
  (c) Not-applicable verdict - the three supported tools are Circom/R1CS
      analyzers. They CANNOT analyze a Solidity honk verifier (a .sol file
      with no circom source). When the target is not analyzable by the chosen
      tool we emit 'tool-not-applicable' rather than pretend a clean run.

WHY NOT SOLIDITY HONK VERIFIERS DIRECTLY:
  circomspect parses .circom; picus consumes Circom/R1CS; zkhydra fuzzes
  circom/R1CS circuits. A Solidity honk/plonk verifier contract is the
  *on-chain* artifact - the upstream circuit DSL (circom) is what these tools
  read. If the workspace ships circom sources, point --target at them. If it
  only ships .sol verifiers, the adapter honestly reports 'tool-not-applicable'.

RELATED TOOLS (tool-duplication preflight, per CLAUDE.md operational anchor):
  - tools/zkbugs-ingest.py        - farms the zkbugs *corpus* (static dataset);
                                     does NOT invoke any analyzer. Different job.
  - tools/zkbugs-provider-loop.py - drives LLM providers over zkbugs briefs;
                                     LLM-based, not a static-analyzer adapter.
  - tools/zk-engagement-probe.py  - heuristic ZK-surface probe over source text;
                                     pattern-grep, does NOT shell out to an
                                     external binary. This adapter fills the gap:
                                     it is the ONLY tool that invokes the real
                                     circomspect/picus/zkhydra binaries and maps
                                     their output to the MIMO-sidecar shape.

CLI:
  python3 tools/zk-external-tool-adapter.py --tool {zkhydra,circomspect,picus} \\
      --target <path> [--json] [--timeout SECS] [--out <sidecar.json>] \\
      [--workspace <ws>]

Exit codes:
  0 = adapter ran cleanly (the *tool* verdict is in the payload; a finding or a
      not-installed / not-applicable verdict are all exit-0 outcomes)
  2 = adapter usage / IO error
"""
from __future__ import annotations

import argparse
import json
import re
import shutil
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

SCHEMA = "auditooor.zk_external_tool_adapter.v1"
TOOL_ID = "ZK-EXTERNAL-TOOL-ADAPTER"

# Map each supported tool -> the binary name + the file kinds it can analyze.
# All three are Circom/R1CS analyzers; none reads a Solidity verifier directly.
SUPPORTED_TOOLS: dict[str, dict[str, Any]] = {
    "circomspect": {
        "binary": "circomspect",
        "applicable_suffixes": [".circom"],
        "argv": lambda target: ["circomspect", str(target)],
        "vendor": "trailofbits",
    },
    "picus": {
        "binary": "picus",
        "applicable_suffixes": [".circom", ".r1cs"],
        "argv": lambda target: ["picus", str(target)],
        "vendor": "veridise",
    },
    "zkhydra": {
        "binary": "zkhydra",
        "applicable_suffixes": [".circom", ".r1cs"],
        "argv": lambda target: ["zkhydra", "analyze", str(target)],
        "vendor": "zkbugs.com",
    },
}

# Tool-output heuristics: a non-empty match means the tool flagged something.
# Conservative, line-based; the raw output is always preserved in the sidecar
# so a human / downstream loop can re-inspect. We never synthesize file:line.
WARNING_RE = re.compile(
    r"\b(warning|underconstrained|under-constrained|non[- ]?deterministic|"
    r"unconstrained|vulnerab|error|unsound|counterexample|violat)\w*",
    re.IGNORECASE,
)


def _now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def tool_available(tool: str) -> bool:
    """Return True if the tool binary is resolvable on PATH."""
    spec = SUPPORTED_TOOLS.get(tool)
    if not spec:
        return False
    return shutil.which(spec["binary"]) is not None


def target_applicable(tool: str, target: Path) -> bool:
    """Return True if this tool can analyze this target kind.

    Directory targets are considered applicable if they contain at least one
    file with an applicable suffix.
    """
    spec = SUPPORTED_TOOLS[tool]
    suffixes = spec["applicable_suffixes"]
    if target.is_dir():
        for suf in suffixes:
            if any(target.rglob(f"*{suf}")):
                return True
        return False
    return target.suffix.lower() in suffixes


def _classify_findings(stdout: str, stderr: str) -> list[dict[str, Any]]:
    """Extract candidate finding lines from tool output (no fabrication).

    Each finding is a real line from the tool's own output. We do NOT invent
    file:line. If the tool prints a file:line, it is preserved verbatim in the
    'raw_line' field; downstream gates (r76) still grep-verify before promotion.
    """
    findings: list[dict[str, Any]] = []
    for stream_name, blob in (("stdout", stdout), ("stderr", stderr)):
        for line in blob.splitlines():
            line = line.rstrip()
            if not line.strip():
                continue
            if WARNING_RE.search(line):
                findings.append({"stream": stream_name, "raw_line": line[:500]})
    return findings


def run_tool(tool: str, target: Path, timeout: int) -> dict[str, Any]:
    """Invoke the real tool binary. Returns the raw execution record."""
    spec = SUPPORTED_TOOLS[tool]
    argv = spec["argv"](target)
    started = _now()
    try:
        proc = subprocess.run(
            argv, capture_output=True, text=True, timeout=timeout,
        )
        return {
            "argv": argv,
            "returncode": proc.returncode,
            "stdout": proc.stdout,
            "stderr": proc.stderr,
            "timed_out": False,
            "started_at_utc": started,
            "ended_at_utc": _now(),
            "exec_error": None,
        }
    except subprocess.TimeoutExpired as exc:
        return {
            "argv": argv, "returncode": None,
            "stdout": (exc.stdout or b"").decode("utf-8", "replace")
            if isinstance(exc.stdout, bytes) else (exc.stdout or ""),
            "stderr": (exc.stderr or b"").decode("utf-8", "replace")
            if isinstance(exc.stderr, bytes) else (exc.stderr or ""),
            "timed_out": True, "started_at_utc": started,
            "ended_at_utc": _now(), "exec_error": "timeout",
        }
    except (FileNotFoundError, OSError) as exc:
        return {
            "argv": argv, "returncode": None, "stdout": "", "stderr": "",
            "timed_out": False, "started_at_utc": started,
            "ended_at_utc": _now(), "exec_error": f"{type(exc).__name__}: {exc}",
        }


def _build_result_payload(verdict: str, tool: str, target: Path,
                          findings: list[dict[str, Any]],
                          notes: str) -> dict[str, Any]:
    """Build the inner candidate-finding payload (serialized as a JSON string
    into the MIMO sidecar 'result' field).

    The MIMO sidecar contract requires 'result' to be a JSON *string*, mirroring
    the LLM-provider sidecars so r76-hallucination-guard / triage-kill-promoter
    parse it identically.
    """
    confirmed = verdict == "findings-emitted" and bool(findings)
    return {
        "applies_to_target": "yes" if confirmed else "no",
        "confidence": "medium" if confirmed else "low",
        "candidate_finding": (
            f"{tool} flagged {len(findings)} candidate line(s) on {target.name}"
            if confirmed else f"{tool}: {verdict}"
        ),
        # No fabrication: only real file:line from the tool output, else NA.
        "file_path_hint": str(target),
        "severity_estimate": "NA",
        "rubric_row_cited": "NA",
        "tool_verdict": verdict,
        "external_tool": tool,
        "tool_findings": findings,
        "novel_angle_score": 1 if confirmed else 0,
        "chain_with": [],
        "notes": notes,
    }


def build_sidecar(tool: str, target: Path, verdict: str,
                  findings: list[dict[str, Any]], exec_record: dict[str, Any],
                  notes: str, workspace: str | None) -> dict[str, Any]:
    """Assemble the full MIMO-sidecar-shaped record.

    Mirrors the LLM-provider sidecar shape (provider/result/status/task_id/
    attack_class/verification_tier/...) so the existing learning-loop readers
    ingest it with no special-casing.
    """
    spec = SUPPORTED_TOOLS[tool]
    result_payload = _build_result_payload(verdict, tool, target, findings, notes)
    task_id = f"zk_ext_{tool}_{target.name}".replace(" ", "_")[:120]
    return {
        "schema_version": SCHEMA,
        "provider": f"zk-external-tool:{tool}",
        "model_id": None,
        "task_id": task_id,
        "task_type": "zk_external_tool_scan",
        "status": "ok" if exec_record.get("exec_error") is None else "error",
        "error": exec_record.get("exec_error"),
        # result is a JSON STRING (MIMO sidecar contract), not a dict.
        "result": json.dumps(result_payload, ensure_ascii=False),
        "verdict": verdict,
        "attack_class": "zk-underconstrained",
        # Tool output is tier-2 (verified public-archive class: real tool run),
        # but a 'not-installed'/'not-applicable' record carries no evidence,
        # so it is tier-3 (synthetic / no source anchor).
        "verification_tier": (
            "tier-2-verified-public-archive"
            if verdict == "findings-emitted"
            else "tier-3-synthetic-taxonomy-anchored"
        ),
        "workspace": workspace or "",
        "workspace_path": str(workspace) if workspace else "",
        "external_tool": tool,
        "external_tool_vendor": spec["vendor"],
        "target": str(target),
        "exec_record": exec_record,
        "started_at_utc": exec_record.get("started_at_utc"),
        "ended_at_utc": exec_record.get("ended_at_utc"),
    }


def adapt(tool: str, target: Path, timeout: int,
          workspace: str | None) -> dict[str, Any]:
    """Top-level adapter flow: availability -> applicability -> run -> parse."""
    if tool not in SUPPORTED_TOOLS:
        # Should be caught by argparse choices, but be defensive.
        return build_sidecar(
            tool if tool in SUPPORTED_TOOLS else "circomspect", target,
            "error-unknown-tool", [],
            {"exec_error": f"unknown tool {tool!r}", "started_at_utc": _now(),
             "ended_at_utc": _now()},
            f"Unknown tool {tool!r}; supported: {sorted(SUPPORTED_TOOLS)}",
            workspace,
        )

    # (a) availability detection
    if not tool_available(tool):
        return build_sidecar(
            tool, target, "tool-not-installed", [],
            {"exec_error": None, "argv": None, "returncode": None,
             "stdout": "", "stderr": "", "started_at_utc": _now(),
             "ended_at_utc": _now()},
            (f"{tool} binary is not installed on PATH. Install it to enable "
             f"real analysis ({SUPPORTED_TOOLS[tool]['vendor']}). No output "
             f"was fabricated."),
            workspace,
        )

    # target must exist for an applicability decision
    if not target.exists():
        return build_sidecar(
            tool, target, "error-target-missing", [],
            {"exec_error": "target does not exist", "started_at_utc": _now(),
             "ended_at_utc": _now()},
            f"Target path does not exist: {target}",
            workspace,
        )

    # (c) applicability: these tools cannot read Solidity honk verifiers
    if not target_applicable(tool, target):
        suffixes = ", ".join(SUPPORTED_TOOLS[tool]["applicable_suffixes"])
        return build_sidecar(
            tool, target, "tool-not-applicable", [],
            {"exec_error": None, "argv": None, "returncode": None,
             "stdout": "", "stderr": "", "started_at_utc": _now(),
             "ended_at_utc": _now()},
            (f"{tool} analyzes Circom/R1CS sources ({suffixes}); target "
             f"{target.name} is not an analyzable kind (e.g. a Solidity honk "
             f"verifier .sol has no circom source). Point --target at the "
             f"upstream circom circuit. No clean-run claim fabricated."),
            workspace,
        )

    # (b) run the real tool
    exec_record = run_tool(tool, target, timeout)
    if exec_record.get("exec_error") == "timeout":
        return build_sidecar(
            tool, target, "tool-timeout", [],
            exec_record,
            f"{tool} exceeded the {timeout}s timeout on {target}.",
            workspace,
        )
    if exec_record.get("exec_error"):
        return build_sidecar(
            tool, target, "tool-exec-error", [],
            exec_record,
            f"{tool} failed to execute: {exec_record['exec_error']}",
            workspace,
        )

    findings = _classify_findings(exec_record["stdout"], exec_record["stderr"])
    if findings:
        verdict = "findings-emitted"
        notes = (f"{tool} produced {len(findings)} candidate finding line(s). "
                 f"Each raw_line is verbatim tool output; downstream r76 "
                 f"grep-verifies before promotion.")
    else:
        verdict = "clean-no-findings"
        notes = (f"{tool} ran to completion (rc="
                 f"{exec_record['returncode']}) and reported no flagged lines.")
    return build_sidecar(tool, target, verdict, findings, exec_record, notes,
                         workspace)


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(
        description="Adapter that invokes a real external ZK analysis tool and "
                    "maps its output to the MIMO-sidecar shape.")
    ap.add_argument("--tool", required=True, choices=sorted(SUPPORTED_TOOLS),
                    help="External ZK tool to invoke.")
    ap.add_argument("--target", required=True,
                    help="Path to analyze (circom source / R1CS / directory).")
    ap.add_argument("--timeout", type=int, default=300,
                    help="Per-tool execution timeout in seconds (default 300).")
    ap.add_argument("--workspace", default=None,
                    help="Workspace label/path recorded in the sidecar.")
    ap.add_argument("--out", default=None,
                    help="Write the MIMO sidecar JSON to this path.")
    ap.add_argument("--json", action="store_true",
                    help="Print the full sidecar JSON to stdout.")
    args = ap.parse_args(argv)

    target = Path(args.target)
    sidecar = adapt(args.tool, target, args.timeout, args.workspace)

    if args.out:
        try:
            out_path = Path(args.out)
            out_path.parent.mkdir(parents=True, exist_ok=True)
            out_path.write_text(json.dumps(sidecar, indent=2, ensure_ascii=False))
        except OSError as exc:
            print(f"error: could not write --out {args.out}: {exc}",
                  file=sys.stderr)
            return 2

    if args.json:
        print(json.dumps(sidecar, indent=2, ensure_ascii=False))
    else:
        print(f"[{TOOL_ID}] tool={args.tool} target={target.name} "
              f"verdict={sidecar['verdict']} "
              f"findings={len(json.loads(sidecar['result']).get('tool_findings', []))}")
        if sidecar["verdict"] in ("tool-not-installed", "tool-not-applicable"):
            payload = json.loads(sidecar["result"])
            print(f"  note: {payload['notes']}")

    return 0


if __name__ == "__main__":
    sys.exit(main())
