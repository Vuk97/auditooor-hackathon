#!/usr/bin/env python3
"""operator-status-surface.py — H-01 of PR603 § Gate 2.

Single-command, read-only operator status page that satisfies PR603 § Gate 2
acceptance criterion #1: "fresh operator has one control-plane path that shows
current workspace state, source truth, dirty-worktree truth, candidate board,
known-limitation blockers, next actions by priority, workpack pointers, runner
cmds, submission readiness, evidence links, and exact resume instructions."

Usage:
    python3 tools/operator-status-surface.py --workspace /path/to/audit-ws
    python3 tools/operator-status-surface.py --workspace ... --json
    python3 tools/operator-status-surface.py --workspace ... --skip-gates
    python3 tools/operator-status-surface.py --workspace ... --out /tmp/status.md

Read-only. Does not mutate any workspace artifact (except a transient cache file
under .auditooor/operator_status_gate_cache.json to keep surface 9 fast).
"""
from __future__ import annotations

import argparse
import datetime as _dt
import json
import os
import re
import subprocess
import sys
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parents[1]
PR603_CHECKLIST = REPO_ROOT / "docs" / "PR603_EXECUTION_CHECKLIST_2026-05-04.md"
KNOWN_LIM_MAP = REPO_ROOT / "docs" / "KNOWN_LIMITATIONS_BURNDOWN_MAP.json"
OOS_GATE_SH = REPO_ROOT / "tools" / "oos-pre-answer-gate.sh"

SOURCE_TRUTH_FILES = [
    "SCOPE.md",
    "SEVERITY.md",
    "RUBRIC_COVERAGE.md",
    "OOS_PASTED.md",
    "INTAKE_BASELINE.json",
]


# ---------------------------------------------------------------------------
# small helpers
# ---------------------------------------------------------------------------

def _run(cmd: list[str], cwd: Path | None = None, timeout: int = 60) -> tuple[int, str, str]:
    try:
        p = subprocess.run(
            cmd,
            cwd=str(cwd) if cwd else None,
            capture_output=True,
            text=True,
            timeout=timeout,
        )
        return p.returncode, p.stdout, p.stderr
    except subprocess.TimeoutExpired:
        return 124, "", "timeout"
    except Exception as exc:  # pragma: no cover
        return 1, "", str(exc)


def _mtime(path: Path) -> str:
    try:
        ts = path.stat().st_mtime
        return _dt.datetime.fromtimestamp(ts).strftime("%Y-%m-%d %H:%M:%S")
    except OSError:
        return "?"


def _read_json(path: Path) -> dict | list | None:
    try:
        with path.open() as fh:
            return json.load(fh)
    except (OSError, json.JSONDecodeError):
        return None


def _is_git_repo(path: Path) -> bool:
    return (path / ".git").exists()


# ---------------------------------------------------------------------------
# surfaces
# ---------------------------------------------------------------------------

def s1_workspace_state(ws: Path) -> dict:
    out: dict[str, Any] = {"path": str(ws), "is_git": _is_git_repo(ws)}
    if out["is_git"]:
        rc, br, _ = _run(["git", "branch", "--show-current"], cwd=ws)
        out["branch"] = br.strip() if rc == 0 else "?"
        rc, st, _ = _run(["git", "status", "--short"], cwd=ws)
        out["short_status_lines"] = len(st.strip().splitlines()) if rc == 0 and st.strip() else 0
    else:
        out["branch"] = None
        out["short_status_lines"] = None
    manifest = ws / ".audit_logs" / "audit_deep_all_manifest.json"
    if manifest.exists():
        m = _read_json(manifest) or {}
        out["audit_deep_manifest"] = {
            "path": str(manifest),
            "timestamp_utc": m.get("timestamp_utc"),
            "profiles_ok": sum(1 for p in m.get("profiles", []) if p.get("exit_code") == 0),
            "profiles_total": len(m.get("profiles", [])),
        }
    else:
        out["audit_deep_manifest"] = None
    return out


def s2_source_truth(ws: Path) -> dict:
    items = []
    for name in SOURCE_TRUTH_FILES:
        p = ws / name
        items.append(
            {
                "name": name,
                "exists": p.exists(),
                "mtime": _mtime(p) if p.exists() else None,
                "size_bytes": p.stat().st_size if p.exists() else None,
            }
        )
    return {"files": items}


def s3_dirty_worktree(ws: Path) -> dict:
    repos = []
    if _is_git_repo(ws):
        rc, st, _ = _run(["git", "status", "--short"], cwd=ws)
        repos.append({"path": str(ws), "short_status": st.strip(), "dirty": bool(st.strip())})
    ext = ws / "external"
    if ext.is_dir():
        for sub in sorted(ext.iterdir()):
            if not sub.is_dir() or not _is_git_repo(sub):
                continue
            rc, st, _ = _run(["git", "status", "--short"], cwd=sub)
            rc2, br, _ = _run(["git", "branch", "--show-current"], cwd=sub)
            repos.append(
                {
                    "path": str(sub),
                    "branch": br.strip(),
                    "short_status": st.strip(),
                    "dirty": bool(st.strip()),
                }
            )
    return {"repos": repos}


_RE_BOARD_ROW = re.compile(r"^\|\s*([^|]+?)\s*\|\s*`?([A-Z][A-Z0-9_\.\-]*\.md)`?\s*\|", re.M)


def s4_candidate_board(ws: Path) -> dict:
    fd = ws / "submissions" / "final_dispositions"
    out: dict[str, Any] = {"dir": str(fd), "exists": fd.is_dir()}
    if not fd.is_dir():
        return out
    submit, kill, hold = [], [], []
    for entry in sorted(fd.iterdir()):
        if not entry.is_file() or entry.suffix != ".md":
            continue
        nm = entry.name
        if nm.startswith("SUBMIT_"):
            submit.append(nm)
        elif nm.startswith("KILL_"):
            kill.append(nm)
        elif nm.startswith("HOLD_"):
            hold.append(nm)
    out["submit"] = submit
    out["kill"] = kill
    out["hold"] = hold
    out["counts"] = {"submit": len(submit), "kill": len(kill), "hold": len(hold)}
    readme = fd / "README.md"
    out["readme"] = {"exists": readme.exists(), "mtime": _mtime(readme) if readme.exists() else None}
    audits = sorted(fd.glob("CANDIDATE_BOARD_AUDIT_*.md"))
    out["candidate_audits"] = [{"path": str(p), "mtime": _mtime(p)} for p in audits]
    return out


def s5_known_limitation_blockers(ws: Path) -> dict:
    bd_path = ws / ".auditooor" / "known_limitations_burndown.json"
    map_path = KNOWN_LIM_MAP
    out: dict[str, Any] = {
        "burndown_path": str(bd_path),
        "burndown_present": bd_path.exists(),
        "map_path": str(map_path),
        "map_present": map_path.exists(),
    }
    bd = _read_json(bd_path) if bd_path.exists() else None
    if bd and isinstance(bd, dict):
        rows = bd.get("rows", [])
        priority_counts: dict[str, dict[str, int]] = {}
        open_rows: list[dict] = []
        for r in rows:
            pg = r.get("priority_group", "?")
            term = r.get("terminal_state", "?")
            priority_counts.setdefault(pg, {"total": 0, "open": 0, "closed": 0})
            priority_counts[pg]["total"] += 1
            if r.get("stop_condition_met"):
                priority_counts[pg]["closed"] += 1
            else:
                priority_counts[pg]["open"] += 1
                open_rows.append(
                    {
                        "priority_group": pg,
                        "limitation_id": r.get("limitation_id"),
                        "title": r.get("title"),
                        "terminal_state": term,
                        "next_command": r.get("next_command"),
                    }
                )
        out["status"] = bd.get("status")
        out["row_total"] = len(rows)
        out["priority_counts"] = priority_counts
        out["strict_blockers"] = len(bd.get("strict_blockers", []))

        prio_order = ["current_priority", "P0", "P1", "P2", "cross_cut"]

        def _key(r: dict) -> tuple[int, str]:
            pg = r.get("priority_group") or "zzz"
            return (prio_order.index(pg) if pg in prio_order else 99, r.get("limitation_id") or "")

        out["open_rows_by_priority"] = sorted(open_rows, key=_key)
    return out


_RE_CHECKBOX = re.compile(r"^- \[ \] \*\*([A-Z]-\d+[a-z]?)\*\*", re.M)


def s6_next_actions(ws: Path, surface5: dict) -> dict:
    out: dict[str, Any] = {}
    open_rows = surface5.get("open_rows_by_priority") or []
    if open_rows:
        top = open_rows[0]
        out["top_blocker"] = {
            "priority_group": top.get("priority_group"),
            "limitation_id": top.get("limitation_id"),
            "next_command": (top.get("next_command") or "").replace("<workspace>", str(ws)),
        }
    else:
        out["top_blocker"] = None
    # Parse PR603 checklist for unchecked items, with focus on V-01..V-06
    open_items: list[dict] = []
    v_items: list[dict] = []
    if PR603_CHECKLIST.exists():
        text = PR603_CHECKLIST.read_text()
        for m in _RE_CHECKBOX.finditer(text):
            tag = m.group(1)
            line_start = text.rfind("\n", 0, m.start()) + 1
            line_end = text.find("\n", m.end())
            line = text[line_start:line_end if line_end > 0 else None].strip()
            entry = {"tag": tag, "line": line[:160]}
            open_items.append(entry)
            if tag.startswith("V-"):
                v_items.append(entry)
    out["unchecked_v_items"] = v_items
    out["unchecked_count_total"] = len(open_items)
    out["unchecked_first_5"] = open_items[:5]
    return out


def s7_workpacks(ws: Path) -> dict:
    wp = ws / "workpacks"
    items: list[dict] = []
    if wp.is_dir():
        for p in sorted(wp.glob("*.md")):
            items.append({"path": str(p), "mtime": _mtime(p), "size": p.stat().st_size})
    out: dict[str, Any] = {
        "workpacks_dir": str(wp),
        "workpacks_present": wp.is_dir(),
        "workpack_files": items,
    }
    run_gate = REPO_ROOT / "tools" / "control" / "run_gate.py"
    out["run_gate_py"] = {"path": str(run_gate), "exists": run_gate.exists()}
    return out


def s8_runner_commands(ws: Path) -> dict:
    return {
        "commands": [
            f"make scan WORKSPACE={ws}",
            f"make audit WS={ws}",
            f"make audit-deep WS={ws} DEEP_PROFILE=all",
            f"make audit-closeout WS={ws} JSON=1",
            f"make known-limitations-burndown WS={ws} JSON=1 STRICT=1",
        ]
    }


def s9_submission_readiness(ws: Path, skip: bool = False) -> dict:
    cur = ws / "submissions" / "paste_ready" / "current"
    out: dict[str, Any] = {"dir": str(cur), "exists": cur.is_dir(), "files": []}
    if not cur.is_dir():
        return out
    files = sorted(p for p in cur.iterdir() if p.suffix == ".md")
    if skip or not OOS_GATE_SH.exists():
        for p in files:
            out["files"].append({"path": str(p), "fileable_signal": "skipped" if skip else "gate_missing"})
        return out
    cache_path = ws / ".auditooor" / "operator_status_gate_cache.json"
    cache: dict = _read_json(cache_path) or {} if cache_path.exists() else {}
    new_cache: dict = {}
    for p in files:
        try:
            mtime = p.stat().st_mtime
        except OSError:
            mtime = 0
        cache_key = f"{p.name}:{int(mtime)}"
        prior = cache.get(cache_key)
        if prior:
            new_cache[cache_key] = prior
            out["files"].append({"path": str(p), **prior})
            continue
        # Infer severity from filename heuristically
        sev = "High"
        nm = p.name.upper()
        for tag in ("CRITICAL", "HIGH", "MEDIUM", "LOW"):
            if tag in nm:
                sev = tag.capitalize()
                break
        rc, stdout, stderr = _run(
            ["bash", str(OOS_GATE_SH), "--workspace", str(ws), "--finding", str(p), "--severity", sev],
            timeout=60,
        )
        signal = "unknown"
        try:
            # Gate emits a single multi-line JSON object on stdout.
            payload = json.loads(stdout) if stdout.strip() else {}
            signal = payload.get("fileable_signal", "unknown")
        except json.JSONDecodeError:
            # Fallback: try last balanced JSON object in stream.
            try:
                start = stdout.rfind("{")
                if start >= 0:
                    payload = json.loads(stdout[start:])
                    signal = payload.get("fileable_signal", "unknown")
            except json.JSONDecodeError:
                pass
        record = {"fileable_signal": signal, "severity_used": sev, "gate_rc": rc}
        new_cache[cache_key] = record
        out["files"].append({"path": str(p), **record})
    try:
        cache_path.parent.mkdir(parents=True, exist_ok=True)
        with cache_path.open("w") as fh:
            json.dump(new_cache, fh, indent=2)
    except OSError:
        pass
    return out


_RE_PATHISH = re.compile(r"([\./\w\-]+/[\w\-./]+\.(?:json|md|sol|t\.sol))", re.I)
_RE_URL = re.compile(r"https?://[\w\-./?#&=:%+~]+")


def s10_evidence_links(ws: Path, surface4: dict) -> dict:
    fd = Path(surface4.get("dir", ""))
    items: list[dict] = []
    candidates = (
        [n for n in surface4.get("submit", [])]
        + [n for n in surface4.get("hold", [])]
        + [n for n in surface4.get("kill", [])]
    )
    for nm in candidates:
        p = fd / nm
        if not p.exists():
            continue
        try:
            text = p.read_text()
        except OSError:
            continue
        kw = ("fork_replay", "poc_execution", "deployment_timeline", "manifest", "evidence", "execution_proof")
        paths = sorted({m.group(1) for m in _RE_PATHISH.finditer(text) if any(k in m.group(1).lower() for k in kw)})
        urls = sorted({m.group(0) for m in _RE_URL.finditer(text)})
        if paths or urls:
            items.append({"candidate": nm, "paths": paths[:6], "urls": urls[:4]})
    return {"items": items}


def s12_vault_status() -> dict:
    """Surface 12 — Obsidian vault freshness."""
    vault = REPO_ROOT / "obsidian-vault"
    stamp_path = vault / ".last_sync.json"
    if not stamp_path.exists():
        return {
            "vault_path": str(vault),
            "status": "never_built",
            "last_sync": None,
            "total_notes": 0,
            "stale_source_count": None,
            "refresh_command": "make vault-refresh",
        }
    try:
        stamp = json.loads(stamp_path.read_text())
    except Exception:
        stamp = {}
    last_sync = stamp.get("generated", "unknown")
    total_notes = stamp.get("total_notes", 0)
    stats = stamp.get("stats", {})
    # Lightweight staleness: check if tier registry is newer than last sync
    stale_sections: list[str] = []
    try:
        last_ts = _dt.datetime.strptime(last_sync, "%Y-%m-%dT%H:%MZ").replace(
            tzinfo=_dt.timezone.utc
        ).timestamp()
    except Exception:
        last_ts = 0.0
    reg_path = REPO_ROOT / "detectors" / "_tier_registry.yaml"
    try:
        if reg_path.stat().st_mtime > last_ts:
            stale_sections.append("detectors")
    except OSError:
        pass
    return {
        "vault_path": str(vault),
        "status": "stale" if stale_sections else "fresh",
        "last_sync": last_sync,
        "total_notes": total_notes,
        "stats_by_section": stats,
        "stale_sections_hint": stale_sections,
        "refresh_command": "make vault-refresh" if stale_sections else None,
    }


def s11_resume(ws: Path, surface1: dict, surface6: dict) -> dict:
    branch = surface1.get("branch") or "<branch>"
    top = surface6.get("top_blocker") or {}
    next_cmd = top.get("next_command") or "(no open priority blockers — see surface 6 V-items)"
    block = (
        f"# Resume Base Azul / current workspace\n"
        f"cd {ws}\n"
        f"git checkout {branch}\n"
        f"git pull --ff-only\n"
        f"# (env) source .venv/bin/activate  if present\n"
        f"# Top-priority next command:\n"
        f"{next_cmd}\n"
    )
    return {"resume_block": block}


# ---------------------------------------------------------------------------
# rendering
# ---------------------------------------------------------------------------

def render_markdown(payload: dict) -> str:
    ws = payload["workspace"]
    lines: list[str] = []
    lines.append(f"# Operator Status Surface — `{ws}`")
    lines.append(f"Generated: {payload['generated_at']} (read-only)")
    lines.append("")

    # 1
    s = payload["surfaces"]["1_workspace_state"]
    lines.append("## 1. Workspace state")
    lines.append(f"- path: `{s['path']}`  is_git: `{s['is_git']}`  branch: `{s.get('branch')}`")
    lines.append(f"- working tree: {s.get('short_status_lines')} dirty lines")
    m = s.get("audit_deep_manifest")
    if m:
        lines.append(f"- audit_deep manifest: {m['timestamp_utc']}, profiles ok={m['profiles_ok']}/{m['profiles_total']}")
    else:
        lines.append("- audit_deep manifest: (not present — run `make audit-deep WS=<ws> DEEP_PROFILE=all`)")
    lines.append("")

    # 2
    s = payload["surfaces"]["2_source_truth"]
    lines.append("## 2. Source truth")
    for f in s["files"]:
        if f["exists"]:
            lines.append(f"- {f['name']}: present, mtime {f['mtime']}, {f['size_bytes']}b")
        else:
            lines.append(f"- {f['name']}: (not present)")
    lines.append("")

    # 3
    s = payload["surfaces"]["3_dirty_worktree"]
    lines.append("## 3. Dirty-worktree truth")
    if not s["repos"]:
        lines.append("- (no git repos discovered under workspace or external/)")
    for r in s["repos"]:
        marker = "DIRTY" if r["dirty"] else "clean"
        br = r.get("branch") or "-"
        lines.append(f"- [{marker}] {r['path']} (branch: `{br}`)")
        if r["dirty"]:
            for ln in r["short_status"].splitlines()[:5]:
                lines.append(f"    {ln}")
            extra = max(0, len(r["short_status"].splitlines()) - 5)
            if extra:
                lines.append(f"    (+{extra} more)")
    lines.append("")

    # 4
    s = payload["surfaces"]["4_candidate_board"]
    lines.append("## 4. Candidate board")
    if not s.get("exists"):
        lines.append(f"- (not present — expected `{s.get('dir')}`)")
    else:
        c = s["counts"]
        lines.append(f"- counts: SUBMIT={c['submit']}  KILL={c['kill']}  HOLD={c['hold']}")
        lines.append(f"- README: {'present' if s['readme']['exists'] else 'missing'}, mtime {s['readme'].get('mtime')}")
        for nm in s["submit"]:
            lines.append(f"  - SUBMIT: {nm}")
        for nm in s["hold"]:
            lines.append(f"  - HOLD: {nm}")
        for nm in s["kill"][:6]:
            lines.append(f"  - KILL: {nm}")
        if len(s["kill"]) > 6:
            lines.append(f"  - KILL: (+{len(s['kill']) - 6} more)")
        for a in s.get("candidate_audits", []):
            lines.append(f"- audit memo: {a['path']} (mtime {a['mtime']})")
    lines.append("")

    # 5
    s = payload["surfaces"]["5_known_limitation_blockers"]
    lines.append("## 5. Known-limitation blockers")
    if not s.get("burndown_present"):
        lines.append(f"- burndown JSON not present at `{s['burndown_path']}` — run `make known-limitations-burndown WS=<ws> JSON=1 STRICT=1`")
    else:
        lines.append(f"- status: `{s.get('status')}`  total rows: {s.get('row_total')}  strict_blockers: {s.get('strict_blockers')}")
        for pg, c in (s.get("priority_counts") or {}).items():
            lines.append(f"- {pg}: open={c['open']} / closed={c['closed']} / total={c['total']}")
        opens = s.get("open_rows_by_priority") or []
        for r in opens[:6]:
            cmd = (r.get("next_command") or "")[:90]
            lines.append(f"  - [{r['priority_group']}] {r['limitation_id']}: `{cmd}`")
        if len(opens) > 6:
            lines.append(f"  - (+{len(opens) - 6} more open rows)")
    lines.append("")

    # 6
    s = payload["surfaces"]["6_next_actions"]
    lines.append("## 6. Next actions by priority")
    top = s.get("top_blocker")
    if top:
        lines.append(f"- TOP: [{top['priority_group']}] {top['limitation_id']}")
        lines.append(f"      `{top['next_command']}`")
    else:
        lines.append("- (no open priority rows)")
    v_items = s.get("unchecked_v_items") or []
    if v_items:
        lines.append(f"- unchecked V-* in PR603 checklist: {len(v_items)}")
        for it in v_items[:6]:
            lines.append(f"  - {it['tag']}: {it['line']}")
    else:
        lines.append("- unchecked V-* in PR603 checklist: 0")
    lines.append(f"- total unchecked items in PR603 checklist: {s.get('unchecked_count_total')}")
    lines.append("")

    # 7
    s = payload["surfaces"]["7_workpacks"]
    lines.append("## 7. Workpack pointers")
    if not s["workpacks_present"]:
        lines.append(f"- (not present — `{s['workpacks_dir']}` does not exist; H-02 workpack generator may not have been run)")
    else:
        for w in s["workpack_files"]:
            lines.append(f"- {w['path']} (mtime {w['mtime']}, {w['size']}b)")
        if not s["workpack_files"]:
            lines.append("- (workpacks/ exists but is empty)")
    rg = s["run_gate_py"]
    lines.append(f"- tools/control/run_gate.py: {'present' if rg['exists'] else 'NOT installed (run H-04 / control plane bootstrap)'}")
    lines.append("")

    # 8
    s = payload["surfaces"]["8_runner_commands"]
    lines.append("## 8. Runner commands")
    lines.append("```")
    for cmd in s["commands"]:
        lines.append(cmd)
    lines.append("```")
    lines.append("")

    # 9
    s = payload["surfaces"]["9_submission_readiness"]
    lines.append("## 9. Submission readiness")
    if not s["exists"]:
        lines.append(f"- (paste_ready/current not present at `{s['dir']}`)")
    else:
        for f in s["files"]:
            sig = f.get("fileable_signal", "?")
            extra = ""
            if "severity_used" in f:
                extra = f" (severity={f['severity_used']}, gate_rc={f['gate_rc']})"
            lines.append(f"- [{sig}] {Path(f['path']).name}{extra}")
        if not s["files"]:
            lines.append("- (paste_ready/current is empty)")
    lines.append("")

    # 10
    s = payload["surfaces"]["10_evidence_links"]
    lines.append("## 10. Evidence links")
    if not s["items"]:
        lines.append("- (no fork-replay / poc-execution / deployment-timeline references found in disposition artifacts)")
    else:
        for it in s["items"][:10]:
            lines.append(f"- {it['candidate']}")
            for p in it["paths"]:
                lines.append(f"    path: {p}")
            for u in it["urls"]:
                lines.append(f"    url:  {u}")
    lines.append("")

    # 11
    s = payload["surfaces"]["11_resume_instructions"]
    lines.append("## 11. Resume instructions")
    lines.append("```bash")
    lines.append(s["resume_block"].rstrip())
    lines.append("```")
    lines.append("")

    # 12
    s = payload["surfaces"].get("12_vault_status", {})
    lines.append("## 12. Obsidian vault status")
    status = s.get("status", "unknown")
    last_sync = s.get("last_sync") or "never"
    total_notes = s.get("total_notes", 0)
    stale = s.get("stale_sections_hint", [])
    lines.append(f"- **Status:** {status}")
    lines.append(f"- **Last sync:** {last_sync}")
    lines.append(f"- **Total notes:** {total_notes}")
    if stale:
        lines.append(f"- **Stale sections:** {', '.join(stale)}")
    refresh_cmd = s.get("refresh_command")
    if refresh_cmd:
        lines.append(f"- **Refresh:** `{refresh_cmd}`")
    stats = s.get("stats_by_section", {})
    if stats:
        lines.append("")
        lines.append("| Section | Notes |")
        lines.append("|---------|-------|")
        for sec, n in sorted(stats.items()):
            lines.append(f"| {sec} | {n} |")
    lines.append("")

    return "\n".join(lines)


# ---------------------------------------------------------------------------
# main
# ---------------------------------------------------------------------------

def build_payload(ws: Path, skip_gates: bool) -> dict:
    s1 = s1_workspace_state(ws)
    s2 = s2_source_truth(ws)
    s3 = s3_dirty_worktree(ws)
    s4 = s4_candidate_board(ws)
    s5 = s5_known_limitation_blockers(ws)
    s6 = s6_next_actions(ws, s5)
    s7 = s7_workpacks(ws)
    s8 = s8_runner_commands(ws)
    s9 = s9_submission_readiness(ws, skip=skip_gates)
    s10 = s10_evidence_links(ws, s4)
    s11 = s11_resume(ws, s1, s6)
    s12 = s12_vault_status()
    return {
        "schema": "auditooor.operator_status_surface.v1",
        "generated_at": _dt.datetime.now(_dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "workspace": str(ws),
        "skip_gates": skip_gates,
        "surfaces": {
            "1_workspace_state": s1,
            "2_source_truth": s2,
            "3_dirty_worktree": s3,
            "4_candidate_board": s4,
            "5_known_limitation_blockers": s5,
            "6_next_actions": s6,
            "7_workpacks": s7,
            "8_runner_commands": s8,
            "9_submission_readiness": s9,
            "10_evidence_links": s10,
            "11_resume_instructions": s11,
            "12_vault_status": s12,
        },
    }


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="Fresh-operator status surface (PR603 Gate 2 H-01)")
    ap.add_argument("--workspace", required=True, help="Path to audit workspace, e.g. /Users/wolf/audits/base-azul")
    ap.add_argument("--out", default=None, help="Output file (default: stdout)")
    ap.add_argument("--json", dest="emit_json", action="store_true", help="Emit JSON instead of markdown")
    ap.add_argument("--skip-gates", action="store_true", help="Skip surface 9 OOS-pre-answer gate runs")
    args = ap.parse_args(argv)

    ws = Path(args.workspace).expanduser().resolve()
    if not ws.is_dir():
        print(f"workspace not found: {ws}", file=sys.stderr)
        return 2

    payload = build_payload(ws, skip_gates=args.skip_gates)
    body = json.dumps(payload, indent=2) if args.emit_json else render_markdown(payload)

    if args.out:
        Path(args.out).write_text(body)
    else:
        sys.stdout.write(body)
        if not body.endswith("\n"):
            sys.stdout.write("\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())
