#!/usr/bin/env python3
# r36-rebuttal: lane-HUNT-DEDUP-FIRST-ORCH registered in .auditooor/agent_pathspec.json
"""fork-upstream-resolve.py - detect a fork/vendored workspace and resolve its
upstream ``owner/repo`` so the deterministic hunt orchestrator can AUTO-wire
the fork-divergence probe and Tier-6 upstream commit-mining (no manual
``UPSTREAM=`` argument needed).

This is the auto-detect half of the fork-divergence auto-wire (Task: make hunt
deterministic). It is a PURE detector + resolver: it never runs git mining or
the probe itself, it only answers two questions, both offline-first:

  1. Is this workspace a fork / vendored / pinned-upstream target?  The
     heuristics deliberately MIRROR ``audit-completeness-check.py``'s
     ``_detect_fork`` (the master-gate "MechanizeGate #5" signal) so a target
     the master gate considers a fork is also a fork here.
  2. If so, what is the canonical upstream ``owner/repo`` on GitHub?  Resolved,
     in priority order, from:
       a. an explicit marker file (``.auditooor/fork_target.json`` ``upstream``
          field, or ``FORK_OF.txt`` first non-comment line);
       b. a Cargo.toml ``git = "https://github.com/<owner>/<repo>"`` dep;
       c. a go.mod ``replace ... => github.com/<owner>/<repo> ...`` directive;
       d. the workspace git ``origin`` remote URL (read-only ``git config``).

CLI
---
    python3 tools/fork-upstream-resolve.py --workspace <ws> [--json]

Exit codes: 0 = resolved (fork + upstream found), 0 with verdict
``not-a-fork`` when the workspace is not a fork (non-fork is not an error -
the orchestrator simply skips the fork lane), 1 = fork detected but upstream
could NOT be resolved (the orchestrator records this so the master gate can
see the probe could not auto-run), 2 = bad args / missing workspace.
"""
from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import sys
from pathlib import Path

SCHEMA = "auditooor.fork_upstream_resolve.v1"
GATE = "FORK-UPSTREAM-RESOLVE"

# Mirror audit-completeness-check.py::_detect_fork pinned-rev markers.
_CARGO_GIT_REV_RE = re.compile(r"""\brev\s*=\s*["'][0-9a-f]{7,40}["']""", re.IGNORECASE)
_CARGO_GIT_DEP_RE = re.compile(r"""\bgit\s*=\s*["']https?://""", re.IGNORECASE)
_GOMOD_REPLACE_RE = re.compile(r"^\s*replace\s+\S+\s+=>\s+\S+", re.MULTILINE)
_GOMOD_PSEUDO_RE = re.compile(r"-[0-9]{14}-[0-9a-f]{12}\b")

# owner/repo extraction from a github URL of any common shape.
_GH_URL_RE = re.compile(
    r"github\.com[/:]([A-Za-z0-9_.-]+)/([A-Za-z0-9_.-]+?)(?:\.git)?(?:[/#?].*)?$",
    re.IGNORECASE,
)
# Cargo `git = "https://github.com/<owner>/<repo>"`
_CARGO_GIT_URL_RE = re.compile(
    r"""\bgit\s*=\s*["'](https?://github\.com/[^"']+)["']""", re.IGNORECASE
)
# go.mod replace target: `replace <mod> => github.com/<owner>/<repo>[/...] <ver>`
_GOMOD_REPLACE_TARGET_RE = re.compile(
    r"^\s*replace\s+\S+\s+(?:[^\s]+\s+)?=>\s+(github\.com/[A-Za-z0-9_./-]+)",
    re.MULTILINE,
)


def _read_text(p: Path) -> str | None:
    try:
        return p.read_text(encoding="utf-8", errors="replace")
    except (OSError, UnicodeError):
        return None


def _exists(p: Path) -> bool:
    try:
        return p.exists()
    except OSError:
        return False


def detect_fork(ws: Path) -> tuple[bool, list[str]]:
    """Mirror audit-completeness-check.py::_detect_fork. (is_fork, reasons)."""
    reasons: list[str] = []
    for cargo in (ws / "Cargo.toml", ws / "src" / "Cargo.toml"):
        txt = _read_text(cargo)
        if txt is None:
            continue
        if _CARGO_GIT_REV_RE.search(txt):
            reasons.append(f"{cargo.name}: pinned git rev")
        elif _CARGO_GIT_DEP_RE.search(txt):
            reasons.append(f"{cargo.name}: git dependency")
    for gomod in (ws / "go.mod", ws / "src" / "go.mod"):
        txt = _read_text(gomod)
        if txt is None:
            continue
        if _GOMOD_REPLACE_RE.search(txt):
            reasons.append("go.mod: replace directive (fork)")
        elif _GOMOD_PSEUDO_RE.search(txt):
            reasons.append("go.mod: pseudo-version pin")
    for vend in ("vendor", "third_party", "external"):
        d = ws / vend
        if _exists(d) and d.is_dir():
            try:
                if any(True for _ in d.iterdir()):
                    reasons.append(f"vendored upstream tree: {vend}/")
            except OSError:
                pass
    for marker in ("FORK_OF.txt", ".auditooor/fork_target.json", "FORK.md"):
        if _exists(ws / marker):
            reasons.append(f"explicit fork marker: {marker}")
    diff_reason = _same_family_unproven_differential_seed_reason(ws)
    if diff_reason:
        reasons.append(diff_reason)
    return (len(reasons) > 0, reasons)


def _same_family_unproven_differential_seed_reason(ws: Path) -> str | None:
    txt = _read_text(ws / ".auditooor" / "differential_seed_queue.json")
    if not txt:
        return None
    try:
        obj = json.loads(txt)
    except (json.JSONDecodeError, TypeError):
        return None
    if not isinstance(obj, dict):
        return None
    if obj.get("schema") != "auditooor.cross_workspace_differential_seed.v1":
        return None
    target_families = {
        str(fam).strip().lower()
        for fam in obj.get("target_families", [])
        if str(fam).strip()
    }
    if not target_families:
        return None
    same_family_siblings: set[str] = set()
    selected = obj.get("selected_siblings")
    if isinstance(selected, list):
        for sibling in selected:
            if not isinstance(sibling, dict):
                continue
            sibling_families = {
                str(fam).strip().lower()
                for fam in sibling.get("families", [])
                if str(fam).strip()
            }
            if target_families & sibling_families:
                workspace_name = str(sibling.get("workspace") or "").strip()
                if workspace_name:
                    same_family_siblings.add(workspace_name)
    if not same_family_siblings:
        return None
    unresolved_statuses = {"", "open", "todo", "unproven", "unknown", "needs_source", "needs_proof"}
    unresolved_count = 0
    hypotheses = obj.get("hypotheses")
    if isinstance(hypotheses, list):
        for row in hypotheses:
            if not isinstance(row, dict):
                continue
            prior_workspace = str(row.get("prior_workspace") or "").strip()
            if prior_workspace and prior_workspace not in same_family_siblings:
                continue
            verdict = str(row.get("verdict") or "").strip().lower()
            if verdict in unresolved_statuses:
                unresolved_count += 1
    if unresolved_count == 0:
        return None
    families = ",".join(sorted(target_families))
    siblings = ",".join(sorted(same_family_siblings))
    return (
        "same-family differential seed has unproven hypotheses "
        f"(families={families}; siblings={siblings}; unproven={unresolved_count})"
    )


def _owner_repo_from_url(url: str) -> str | None:
    m = _GH_URL_RE.search(url.strip())
    if not m:
        return None
    owner, repo = m.group(1), m.group(2)
    repo = repo.removesuffix(".git")
    if not owner or not repo:
        return None
    return f"{owner}/{repo}"


def _owner_repo_from_gomod_target(target: str) -> str | None:
    # target like github.com/<owner>/<repo>[/subpath]
    t = target.strip().removeprefix("github.com/")
    parts = t.split("/")
    if len(parts) >= 2 and parts[0] and parts[1]:
        return f"{parts[0]}/{parts[1].removesuffix('.git')}"
    return None


def _resolve_from_marker(ws: Path) -> tuple[str | None, str]:
    j = ws / ".auditooor" / "fork_target.json"
    txt = _read_text(j)
    if txt:
        try:
            data = json.loads(txt)
            up = data.get("upstream") or data.get("upstream_repo") or data.get("owner_repo")
            if isinstance(up, str) and up.strip():
                cand = up.strip()
                if cand.startswith("http") or "github.com" in cand:
                    rr = _owner_repo_from_url(cand)
                    if rr:
                        return rr, "marker:.auditooor/fork_target.json"
                # already owner/repo shape
                if re.fullmatch(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+", cand):
                    return cand, "marker:.auditooor/fork_target.json"
        except (json.JSONDecodeError, AttributeError):
            pass
    fof = _read_text(ws / "FORK_OF.txt")
    if fof:
        for line in fof.splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            rr = _owner_repo_from_url(line) if "github.com" in line else (
                line if re.fullmatch(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+", line) else None
            )
            if rr:
                return rr, "marker:FORK_OF.txt"
            break
    return None, ""


def _resolve_from_cargo(ws: Path) -> tuple[str | None, str]:
    for cargo in (ws / "Cargo.toml", ws / "src" / "Cargo.toml"):
        txt = _read_text(cargo)
        if not txt:
            continue
        m = _CARGO_GIT_URL_RE.search(txt)
        if m:
            rr = _owner_repo_from_url(m.group(1))
            if rr:
                return rr, f"cargo:{cargo.name} git dep"
    return None, ""


def _resolve_from_gomod(ws: Path) -> tuple[str | None, str]:
    for gomod in (ws / "go.mod", ws / "src" / "go.mod"):
        txt = _read_text(gomod)
        if not txt:
            continue
        m = _GOMOD_REPLACE_TARGET_RE.search(txt)
        if m:
            rr = _owner_repo_from_gomod_target(m.group(1))
            if rr:
                return rr, f"gomod:{gomod.name} replace target"
    return None, ""


def _git_toplevel(cwd: Path) -> Path | None:
    try:
        proc = subprocess.run(
            ["git", "-C", str(cwd), "rev-parse", "--show-toplevel"],
            capture_output=True, text=True, timeout=15,
        )
    except (OSError, subprocess.SubprocessError):
        return None
    if proc.returncode != 0 or not proc.stdout.strip():
        return None
    return Path(proc.stdout.strip()).resolve(strict=False)


def _candidate_git_checkouts(ws: Path) -> list[Path]:
    candidates = [ws / "src", ws]
    src = ws / "src"
    try:
        if _exists(src):
            candidates.extend(child for child in src.iterdir() if child.is_dir())
    except OSError:
        pass

    checkouts: list[Path] = []
    seen: set[str] = set()
    for candidate in candidates:
        top = _git_toplevel(candidate)
        if top is None:
            continue
        key = str(top)
        if key in seen:
            continue
        seen.add(key)
        checkouts.append(top)
    return checkouts


def _resolve_from_git_remote(ws: Path) -> tuple[str | None, str]:
    # Read-only git remote inspection. Never mutates the repo.
    for cwd in _candidate_git_checkouts(ws):
        try:
            proc = subprocess.run(
                ["git", "-C", str(cwd), "config", "--get", "remote.origin.url"],
                capture_output=True, text=True, timeout=15,
            )
        except (OSError, subprocess.SubprocessError):
            continue
        if proc.returncode == 0 and proc.stdout.strip():
            rr = _owner_repo_from_url(proc.stdout.strip())
            if rr:
                return rr, "git:origin remote"
    return None, ""


def resolve_upstream(ws: Path) -> tuple[str | None, str]:
    """Resolve upstream owner/repo in priority order. (owner_repo, source)."""
    for resolver in (
        _resolve_from_marker,
        _resolve_from_cargo,
        _resolve_from_gomod,
        _resolve_from_git_remote,
    ):
        rr, src = resolver(ws)
        if rr:
            return rr, src
    return None, ""


def _lang_hint(ws: Path) -> str:
    if _exists(ws / "Cargo.toml") or _exists(ws / "src" / "Cargo.toml"):
        return "rust"
    if _exists(ws / "go.mod") or _exists(ws / "src" / "go.mod"):
        return "go"
    # any .sol under the tree => solidity
    try:
        for p in ws.rglob("*.sol"):
            _ = p
            return "solidity"
    except OSError:
        pass
    return "go"


def _probe_workspace(ws: Path) -> str:
    checkouts = _candidate_git_checkouts(ws)
    if checkouts:
        return str(checkouts[0])
    return str(ws)


def evaluate(ws: Path) -> dict:
    is_fork, reasons = detect_fork(ws)
    if not is_fork:
        return {
            "schema": SCHEMA, "gate": GATE, "workspace": str(ws),
            "verdict": "not-a-fork", "is_fork": False, "fork_reasons": [],
            "upstream": None, "upstream_source": "", "lang_hint": _lang_hint(ws),
        }
    upstream, src = resolve_upstream(ws)
    verdict = "resolved" if upstream else "fork-upstream-unresolved"
    return {
        "schema": SCHEMA, "gate": GATE, "workspace": str(ws),
        "verdict": verdict, "is_fork": True, "fork_reasons": reasons,
        "upstream": upstream, "upstream_source": src, "lang_hint": _lang_hint(ws),
        "probe_workspace": _probe_workspace(ws),
    }


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(
        prog="fork-upstream-resolve.py",
        description="Detect a fork/vendored workspace and resolve its upstream owner/repo.",
    )
    p.add_argument("--workspace", "--ws", dest="workspace", required=True)
    p.add_argument("--json", action="store_true", help="Emit JSON payload.")
    args = p.parse_args(argv)

    ws = Path(os.path.expanduser(args.workspace)).resolve()
    if not _exists(ws) or not ws.is_dir():
        payload = {"schema": SCHEMA, "gate": GATE, "workspace": str(ws),
                   "verdict": "error", "reason": "workspace not found or not a directory"}
        print(json.dumps(payload, indent=2) if args.json else f"[{GATE}] verdict=error")
        return 2

    payload = evaluate(ws)
    if args.json:
        print(json.dumps(payload, indent=2))
    else:
        print(f"[{GATE}] verdict={payload['verdict']} is_fork={payload['is_fork']} "
              f"upstream={payload['upstream']} source={payload['upstream_source']}")
        if payload["fork_reasons"]:
            for r in payload["fork_reasons"]:
                print(f"  fork-reason: {r}")

    if payload["verdict"] == "fork-upstream-unresolved":
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
