#!/usr/bin/env python3
"""Continuously runnable submission-gate watchdog.

The watchdog is the lightweight always-on surface for draft edits. In quick
mode it runs only the hard doctrine gates that are cheap and structured, then
writes a per-draft gate-status sidecar under `.auditooor/gate-status/`.

It never edits drafts, never submits findings, and never uses network or git.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


SCHEMA = "auditooor.pre_submit_watchdog.v1"
REPO_ROOT = Path(__file__).resolve().parents[1]

SUBMISSION_DIRS = ("paste_ready", "staging", "held", "packaged")
SEVERITY_RE = re.compile(
    r"(?im)^\s*(?:\*\*)?\s*Severity(?:\s+rating)?(?:\*\*)?\s*[:\-]\s*(?:\*\*)?"
    r"(Critical|High|Medium|Low)\b"
)
FILENAME_SEVERITY_RE = re.compile(r"(?:^|[-_])(critical|high|medium|low)(?:[-_.]|$)", re.IGNORECASE)

MISSING_GUARD_RE = re.compile(
    r"\b(?:missing|omitted|lacks?|without)\s+(?:guard|validation|check|modifier|access\s+control|"
    r"reentrancy\s+guard|pause\s+check|bounds?\s+check)|"
    r"\b(?:asymmetric|unpaired|inconsistent)\s+(?:guard|validation|check|path)|"
    r"\b(?:guard|validation|check)\s+(?:asymmetry|gap)",
    re.IGNORECASE,
)
ENUMERATION_RE = re.compile(
    r"(?im)^\s{0,3}#{1,6}\s+Enumerated\s+Call\s+Sites\b|"
    r"<!--\s*l30-rebuttal:\s*.*?-->",
    re.IGNORECASE | re.DOTALL,
)


def _utc_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def _read(path: Path) -> str:
    return path.read_text(encoding="utf-8", errors="replace")


def infer_severity(path: Path, text: str) -> str | None:
    match = SEVERITY_RE.search(text)
    if match:
        return match.group(1).capitalize()
    name_match = FILENAME_SEVERITY_RE.search(path.name)
    if name_match:
        return name_match.group(1).capitalize()
    return None


def discover_drafts(workspace: Path) -> list[Path]:
    submissions = workspace / "submissions"
    drafts: list[Path] = []
    for dirname in SUBMISSION_DIRS:
        root = submissions / dirname
        if root.is_dir():
            drafts.extend(path for path in root.rglob("*.md") if path.is_file())
    root = submissions / "paste_ready"
    if root.is_dir():
        drafts.extend(path for path in root.glob("*.md") if path.is_file())
    return sorted(set(path.resolve() for path in drafts))


def resolve_workspace_from_draft(draft: Path) -> Path:
    cur = draft.resolve().parent
    for parent in [cur, *cur.parents]:
        if (parent / "submissions").is_dir() or (parent / "poc-tests").is_dir():
            return parent
    return draft.resolve().parent


def sidecar_path(out_dir: Path, workspace: Path, draft: Path) -> Path:
    try:
        rel = draft.resolve().relative_to(workspace.resolve())
    except ValueError:
        rel = draft.resolve()
    digest = hashlib.sha256(str(rel).encode("utf-8")).hexdigest()[:12]
    slug = re.sub(r"[^A-Za-z0-9_.-]+", "_", str(rel))[-140:]
    return out_dir / f"{slug}.{digest}.gate-status.json"


def _json_summary(payload: dict[str, Any]) -> str:
    verdict = payload.get("verdict") or payload.get("decision", {}).get("code") or "unknown"
    reason = payload.get("reason") or payload.get("decision", {}).get("summary")
    if reason:
        return f"{verdict}: {reason}"
    return str(verdict)


def run_json_command(name: str, argv: list[str], *, fail_rcs: set[int] | None = None) -> dict[str, Any]:
    proc = subprocess.run(argv, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False)
    payload: dict[str, Any] | None = None
    try:
        payload = json.loads(proc.stdout)
    except Exception:
        payload = None

    fail_rcs = fail_rcs if fail_rcs is not None else {1, 2}
    failed = proc.returncode in fail_rcs
    if payload is not None and name == "L27-IMPACT-CONTRACT":
        failed = bool(payload.get("decision", {}).get("blocked"))
    if payload is not None and name == "R62-TRIAGER-MINDSET":
        # the simulator exits 0 regardless; surface a flag when it matched any
        # triager-rejection pattern (incl. the R24-R27 hardening-not-vulnerability
        # patterns) so the agent sees the predicted closure at write-time.
        failed = bool(payload.get("matched_patterns"))
    return {
        "gate": name,
        "argv": argv,
        "exit_code": proc.returncode,
        "failed": failed,
        "summary": _json_summary(payload or {}) if payload else (proc.stderr.strip() or proc.stdout.strip()[:300]),
        "payload": payload,
        "stderr": proc.stderr.strip(),
    }


def l30_check(draft: Path, text: str) -> dict[str, Any]:
    trigger = bool(MISSING_GUARD_RE.search(text))
    enumerated = bool(ENUMERATION_RE.search(text))
    failed = trigger and not enumerated
    return {
        "gate": "L30-MISSING-GUARD-ENUMERATION",
        "exit_code": 1 if failed else 0,
        "failed": failed,
        "summary": (
            "missing-guard framing lacks Enumerated Call Sites or l30 rebuttal"
            if failed
            else ("missing-guard framing bounded" if trigger else "no missing-guard framing")
        ),
        "payload": {
            "file": str(draft),
            "trigger": trigger,
            "enumerated_or_rebutted": enumerated,
            "verdict": "fail-missing-enumeration" if failed else "pass",
        },
    }


def quick_gate_commands(draft: Path, workspace: Path, severity: str | None) -> list[tuple[str, list[str], set[int] | None]]:
    py = sys.executable or "python3"
    sev_args = ["--severity", severity] if severity else []
    commands: list[tuple[str, list[str], set[int] | None]] = [
        ("L27-IMPACT-CONTRACT", [py, str(REPO_ROOT / "tools/impact-contract-preflight.py"), str(draft), "--route", "filing"], {2, 1}),
        (
            "L31-DUPE-PREFLIGHT",
            [
                py,
                str(REPO_ROOT / "tools/duplicate-preflight-check.py"),
                str(draft),
                "--workspace",
                str(workspace),
                "--platform",
                "auto",
                "--strict",
                "--json",
                "--self-skip-same-family",
            ],
            {1},
        ),
        ("R18-R19-IN-PROCESS-VS-NODE", [py, str(REPO_ROOT / "tools/in-process-vs-node-level-check.py"), str(draft), "--strict", "--json", *sev_args], {1, 2}),
        ("R27-ADJACENT-FINDING-DISCLOSURE", [py, str(REPO_ROOT / "tools/adjacent-finding-disclosure-check.py"), str(draft), "--strict", "--json", *sev_args], {1, 2}),
        ("R20-NO-FAULT-INJECTION", [py, str(REPO_ROOT / "tools/no-fault-injection-check.py"), str(draft), "--strict", "--json", *sev_args], {1, 2}),
        ("R22-RESTART-SURVIVAL", [py, str(REPO_ROOT / "tools/restart-survival-check.py"), str(draft), "--json"], {1, 2}),
        ("R24-NON-SELF-IMPACT", [py, str(REPO_ROOT / "tools/non-self-impact-check.py"), str(draft), "--strict", *sev_args], {1, 2}),
        ("R25-DEFENSE-IN-DEPTH", [py, str(REPO_ROOT / "tools/defense-in-depth-traversal-check.py"), str(draft), "--strict", "--json", *sev_args], {1, 2}),
        ("R26-ANTE-HANDLER", [py, str(REPO_ROOT / "tools/ante-handler-traversal-check.py"), str(draft), "--strict", "--json", *sev_args], {1, 2}),
        ("R23-COMPARATIVE-BASELINE", [py, str(REPO_ROOT / "tools/comparative-baseline-check.py"), str(draft), "--strict", "--json", *sev_args], {1, 2}),
        ("R21-PERMANENT-IMPACT-5-ASK", [py, str(REPO_ROOT / "tools/permanent-impact-five-ask-template-check.py"), str(draft), "--strict", "--json"], {1, 2}),
        ("R30-PRODUCTION-PROFILE", [py, str(REPO_ROOT / "tools/production-profile-preflight-check.py"), str(draft)], {1, 2}),
        # R83: hardening-vs-vulnerability composite (resource/cap/rate-limit/keying
        # findings must establish P1 reachable-on-default / P2 survives-defense /
        # P3 non-self / P4 crosses-threshold). exit 1 = blocked.
        ("R83-HARDENING-VS-VULN", [py, str(REPO_ROOT / "tools/hardening-vs-vulnerability-check.py"), str(draft), "--json", *sev_args], {1}),
        # R62: triager-mindset pre-filing simulator over the whole triager-pattern
        # library (incl. the R24-R27 hardening-not-vulnerability patterns). exit 2 =
        # patterns matched / guards not addressed -> surfaced at write-time.
        ("R62-TRIAGER-MINDSET", [py, str(REPO_ROOT / "tools/triager-pre-filing-simulator.py"), str(draft), "--workspace", str(workspace)], set()),
        # The UNIVERSAL exploitability logic: every HIGH+ finding must affirmatively
        # establish all five axes (REACH/TRAVERSE/IMPACT/ORIGINAL/PROVEN) with cited
        # evidence. The family gates above are the per-axis lie-detectors; this is
        # the composite that every other rule is a fragment of. exit 1 = not yet a
        # fileable vulnerability (which axis is named in the verdict).
        ("EXPLOITABILITY-LEDGER", [py, str(REPO_ROOT / "tools/exploitability-ledger.py"), str(draft), "--json", *sev_args], {1}),
    ]
    return commands


def run_quick(draft: Path, workspace: Path) -> dict[str, Any]:
    text = _read(draft)
    severity = infer_severity(draft, text)
    gates: list[dict[str, Any]] = [l30_check(draft, text)]
    for name, argv, fail_rcs in quick_gate_commands(draft, workspace, severity):
        tool = Path(argv[1])
        if not tool.is_file():
            gates.append(
                {
                    "gate": name,
                    "exit_code": None,
                    "failed": False,
                    "skipped": True,
                    "summary": f"tool missing: {tool}",
                }
            )
            continue
        gates.append(run_json_command(name, argv, fail_rcs=fail_rcs))
    failures = [gate for gate in gates if gate.get("failed")]
    return {
        "schema": SCHEMA,
        "mode": "quick",
        "workspace": str(workspace),
        "file": str(draft),
        "severity": severity,
        "generated_at": _utc_now(),
        "status": "fail" if failures else "pass",
        "failed_count": len(failures),
        "failures": [
            {
                "gate": gate.get("gate"),
                "summary": gate.get("summary"),
                "exit_code": gate.get("exit_code"),
            }
            for gate in failures
        ],
        "gates": gates,
    }


def run_full(draft: Path, workspace: Path) -> dict[str, Any]:
    argv = ["bash", str(REPO_ROOT / "tools/pre-submit-check.sh"), str(draft)]
    text = _read(draft)
    severity = infer_severity(draft, text)
    if severity:
        argv.extend(["--severity", severity])
    proc = subprocess.run(argv, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False)
    failed_match = re.search(r"([0-9]+)\s+check\(s\)\s+failed", proc.stdout)
    failed_count = int(failed_match.group(1)) if failed_match else (1 if proc.returncode else 0)
    return {
        "schema": SCHEMA,
        "mode": "full",
        "workspace": str(workspace),
        "file": str(draft),
        "severity": severity,
        "generated_at": _utc_now(),
        "status": "fail" if proc.returncode else "pass",
        "failed_count": failed_count,
        "failures": [],
        "command": argv,
        "exit_code": proc.returncode,
        "stdout": proc.stdout,
        "stderr": proc.stderr,
    }


def write_status(status: dict[str, Any], out_dir: Path, workspace: Path, draft: Path) -> Path:
    out = sidecar_path(out_dir, workspace, draft)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(status, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return out


def run_once(
    workspace: Path,
    *,
    mode: str,
    changed: list[Path],
    out_dir: Path | None,
) -> dict[str, Any]:
    workspace = workspace.expanduser().resolve()
    drafts = [path.expanduser().resolve() for path in changed] if changed else discover_drafts(workspace)
    drafts = [path for path in drafts if path.is_file() and path.suffix.lower() == ".md"]
    if out_dir is None:
        out_dir = workspace / ".auditooor" / "gate-status"
    else:
        out_dir = out_dir.expanduser().resolve()

    statuses = []
    for draft in drafts:
        ws = workspace if (workspace / "submissions").is_dir() else resolve_workspace_from_draft(draft)
        status = run_full(draft, ws) if mode == "full" else run_quick(draft, ws)
        status_path = write_status(status, out_dir, ws, draft)
        statuses.append(
            {
                "file": str(draft),
                "status_path": str(status_path),
                "status": status["status"],
                "failed_count": status["failed_count"],
                "failures": status.get("failures", []),
            }
        )

    failed = [item for item in statuses if item["status"] == "fail"]
    return {
        "schema": SCHEMA,
        "workspace": str(workspace),
        "mode": mode,
        "generated_at": _utc_now(),
        "draft_count": len(statuses),
        "failed_count": len(failed),
        "status": "fail" if failed else "pass",
        "statuses": statuses,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("workspace", type=Path, help="Audit workspace root, or a parent with submissions/")
    parser.add_argument("--mode", choices=("quick", "full"), default="quick")
    parser.add_argument("--changed", action="append", default=[], type=Path, help="Specific changed draft path to check")
    parser.add_argument("--out-dir", type=Path)
    parser.add_argument("--json", action="store_true", help="Emit JSON summary to stdout")
    parser.add_argument("--advisory", action="store_true", help="Always exit 0 after writing sidecars")
    parser.add_argument("--poll-interval", type=float, default=0.0, help="If >0, rescan periodically instead of once")
    parser.add_argument("--max-loops", type=int, default=1, help="Number of polling loops; 0 means forever")
    args = parser.parse_args(argv)

    last_summary: dict[str, Any] | None = None
    loops = 0
    while True:
        last_summary = run_once(args.workspace, mode=args.mode, changed=args.changed, out_dir=args.out_dir)
        loops += 1
        if args.poll_interval <= 0 or (args.max_loops and loops >= args.max_loops):
            break
        time.sleep(args.poll_interval)

    assert last_summary is not None
    if args.json:
        print(json.dumps(last_summary, indent=2, sort_keys=True))
    else:
        print(
            f"pre-submit-watchdog {last_summary['status']}: "
            f"{last_summary['draft_count']} draft(s), {last_summary['failed_count']} failing"
        )
        for item in last_summary["statuses"]:
            print(f"- {item['status']} {item['file']} -> {item['status_path']}")
            for failure in item.get("failures") or []:
                print(f"  - {failure.get('gate')}: {failure.get('summary')}")

    return 0 if args.advisory or last_summary["status"] == "pass" else 1


if __name__ == "__main__":
    raise SystemExit(main())
