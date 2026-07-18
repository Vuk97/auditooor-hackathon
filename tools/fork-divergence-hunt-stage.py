#!/usr/bin/env python3
# r36-rebuttal: PR8b lane owns only this file + its test; orchestrator commits.
"""fork-divergence-hunt-stage.py - a NAMED hunt stage that turns "this target
is a fork that lags an upstream security-fix series" into queued, not-yet-
backported leads in the proof-obligation queue.

This is the *hunt-stage* half of the fork-divergence auto-wire. It is distinct
from every existing fork tool (see RELATED TOOLS below): the existing prober
keys off pinned-dependency MANIFESTS plus an offline advisory cache, and the
ancestry checks do pin-version ancestry math. NONE of them diff the upstream
post-fork SECURITY commits against the fork tree at the git-commit level and
emit the not-backported ones as leads. That is the dYdX cometbft fork-lag
class, and that is exactly the gap this stage fills.

Pipeline (one named stage, deterministic, offline-first)
--------------------------------------------------------
  1. AUTO-DETECT upstream owner/repo by reusing fork-upstream-resolve.py
     (no manual UPSTREAM= argument needed). If the workspace is not a fork,
     the stage no-ops with verdict `not-a-fork`.
  2. Resolve the fork-pin SHA the workspace is pinned at (from the same
     manifests fork-upstream-resolve reads: marker file, go.mod replace /
     pseudo-version, Cargo.lock git source, Cargo.toml rev=).
  3. Enumerate upstream commits AFTER the pin that look SECURITY-relevant
     (commit-subject heuristics: fix/security/vuln/CVE/GHSA/panic/overflow/
     auth/oob/dos/...). Offline: against a locally-cloned upstream mirror
     (`--upstream-clone <dir>` or auto from a sibling clone). Online (opt-in):
     `gh api repos/<owner>/<repo>/commits?since=` when GH_TOKEN is present and
     `--allow-network` is set.
  4. For each candidate security commit, check whether it has been BACKPORTED
     into the fork tree. Backport-presence is detected by (a) subject-line
     match against the fork's own git log, (b) cherry-pick trailer match
     (`(cherry picked from commit <sha>)`), or (c) patch-id equivalence when
     both trees are available locally. Commits with NO backport evidence are
     the leads.
  5. EMIT each not-backported security commit as a proof-obligation-queue task
     (shape: {"tasks": [...]}, the same shape exploit-queue.py consumes), so
     the prove lanes pick them up. Merge is additive; a pre-existing queue is
     backed up once before the merge.

RELATED TOOLS (tool-duplication preflight - codified 2026-05-28)
----------------------------------------------------------------
  - tools/fork-upstream-resolve.py        : REUSED here for upstream detection.
                                            That tool only ANSWERS "is this a
                                            fork + what is upstream"; it does no
                                            commit diffing. This stage imports
                                            its detector + resolver.
  - tools/fork-divergence-prober.py       : MANIFEST + offline-advisory-cache
                                            prober. Emits 5-stage leads from a
                                            *pin-version-vulnerable* signal, not
                                            from upstream SECURITY-commit diffing.
                                            No git-commit-level backport check.
  - tools/gomod-fork-ancestry-check.py /
    tools/cargo-fork-ancestry-check.py    : pin-ancestry math (which pins
                                            diverge). Stop at "diverged".
  - tools/upstream-equivalent-gate.py     : promotion gate for an *already*
                                            drafted candidate (5-check). Walks
                                            back over-claims; does not discover.
  - tools/git-commits-mining.py           : generic bidirectional commit miner
                                            (forward/backward window). Not
                                            scoped to upstream-vs-fork backport
                                            differential and does not key off
                                            the fork-pin SHA as the cut point.

The genuine new capability: a NAMED stage that ties (upstream resolve) ->
(pin cut-point) -> (post-pin SECURITY commit enumeration) -> (per-commit
backport-presence check) -> (proof-queue emit). It composes the resolver and
shells `git log`/`gh api`; it re-implements none of the ancestry math.

Offline-safe
------------
With a local upstream clone and the workspace's own git tree, the stage needs
no network. `gh api` enumeration is strictly opt-in (`--allow-network`).

CLI
---
    --workspace PATH        workspace root (fork target)
    --upstream-clone DIR    local clone of upstream (offline commit source)
    --upstream OWNER/REPO   override auto-detected upstream owner/repo
    --pin SHA               override auto-detected fork-pin SHA
    --window N              max upstream commits after pin to scan (default 400)
    --allow-network         permit `gh api` enumeration when no local clone
    --emit-queue            merge leads into <ws>/.auditooor/proof_obligation_queue.json
    --out PATH              write the stage plan JSON here
    --json                  print the plan JSON to stdout
    --strict                exit 2 when >=1 not-backported security lead found

Exit codes
----------
    0  no not-backported security leads (or no-op when not-a-fork)
    1  harness error (missing workspace, upstream unresolved, bad input)
    2  >=1 not-backported security lead AND --strict
"""
from __future__ import annotations

import argparse
import datetime as _dt
import hashlib
import importlib.util
import json
import os
import re
import subprocess
import sys
from pathlib import Path
from typing import Any, Optional

SCHEMA = "auditooor.fork_divergence_hunt_stage.v1"
TOOL_NAME = "fork-divergence-hunt-stage"
GATE = "FORK-DIVERGENCE-HUNT-STAGE"

# Security-relevant commit-subject heuristics (case-insensitive). These mirror
# the dYdX cometbft fork-lag anchor (silently-shipped blocksync hardening) and
# the general "security commit" shape.
_SECURITY_SUBJECT_TERMS = [
    r"\bsecurit", r"\bvuln", r"\bCVE-\d", r"\bGHSA-", r"\bexploit",
    r"\bpanic\b", r"\boverflow", r"\bunderflow", r"\boob\b", r"\bout[- ]of[- ]bounds",
    r"\bauth(?:z|n|orization|entication)?\b", r"\bbypass", r"\bDoS\b", r"\bdenial[- ]of[- ]service",
    r"\bhardening", r"\bsanit", r"\bvalidat", r"\bmalicious", r"\battack",
    r"\bnil[- ]deref", r"\bnull[- ]deref", r"\bdouble[- ]free", r"\buse[- ]after[- ]free",
    r"\bconsensus\b", r"\bhalt\b", r"\bcrash", r"\binteger[- ]overflow",
    r"\breplay\b", r"\bspoof", r"\bforge", r"\bunsafe\b", r"\bRCE\b",
]
_SECURITY_RE = re.compile("|".join(_SECURITY_SUBJECT_TERMS), re.IGNORECASE)

# A plain "fix" only counts as security-relevant when it co-occurs with a
# security-adjacent noun, to avoid flooding on routine "fix typo" commits.
_FIX_RE = re.compile(r"\bfix(?:e[sd])?\b", re.IGNORECASE)
_FIX_SECURITY_CONTEXT_RE = re.compile(
    r"\b(check|guard|verif|valid|bound|len(?:gth)?|size|cap|limit|nonce|"
    r"signature|sig|hash|proof|state|sync|block|tx|message|decode|encode|"
    r"parse|alloc|memory|access|owner|permission)\b",
    re.IGNORECASE,
)

_CHERRY_PICK_RE = re.compile(
    r"cherry[- ]picked from commit\s+([0-9a-f]{7,40})", re.IGNORECASE
)
_SUBJECT_PR_RE = re.compile(r"\(#\d+\)\s*$")


def _utc_now() -> str:
    return _dt.datetime.now(_dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _exists(p: Path) -> bool:
    try:
        return p.exists()
    except OSError:
        return False


# ---------------------------------------------------------------------------
# Reuse fork-upstream-resolve.py (load by file path; hyphenated module name)
# ---------------------------------------------------------------------------
def _load_resolver() -> Any:
    here = Path(__file__).resolve().parent
    target = here / "fork-upstream-resolve.py"
    spec = importlib.util.spec_from_file_location("fork_upstream_resolve", target)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot load resolver at {target}")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


# ---------------------------------------------------------------------------
# Fork-pin SHA discovery (the cut point for "commits AFTER the pin")
# ---------------------------------------------------------------------------
_GOMOD_PSEUDO_SHA_RE = re.compile(r"-[0-9]{14}-([0-9a-f]{12})\b")
_CARGO_REV_RE = re.compile(r"""\brev\s*=\s*["']([0-9a-f]{7,40})["']""", re.IGNORECASE)
_CARGO_LOCK_SHA_RE = re.compile(r"git\+[^#\"']+#([0-9a-f]{7,40})")


def _read_text(p: Path) -> Optional[str]:
    try:
        return p.read_text(encoding="utf-8", errors="replace")
    except (OSError, UnicodeError):
        return None


def resolve_pin_sha(ws: Path) -> tuple[Optional[str], str]:
    """Resolve the upstream SHA the fork is pinned at. (sha, source)."""
    # 1. explicit marker
    j = ws / ".auditooor" / "fork_target.json"
    txt = _read_text(j)
    if txt:
        try:
            data = json.loads(txt)
            for key in ("pin", "pin_sha", "upstream_sha", "rev", "audit_pin"):
                v = data.get(key)
                if isinstance(v, str) and re.fullmatch(r"[0-9a-f]{7,40}", v.strip()):
                    return v.strip(), f"marker:fork_target.json:{key}"
        except (json.JSONDecodeError, AttributeError):
            pass
    # 2. Cargo.lock git source
    for lock in (ws / "Cargo.lock", ws / "src" / "Cargo.lock"):
        t = _read_text(lock)
        if t:
            m = _CARGO_LOCK_SHA_RE.search(t)
            if m:
                return m.group(1), f"cargo.lock:{lock.name}"
    # 3. Cargo.toml rev=
    for cargo in (ws / "Cargo.toml", ws / "src" / "Cargo.toml"):
        t = _read_text(cargo)
        if t:
            m = _CARGO_REV_RE.search(t)
            if m:
                return m.group(1), f"cargo.toml:{cargo.name} rev="
    # 4. go.mod pseudo-version 12-char SHA (last one wins; usually the fork dep)
    for gomod in (ws / "go.mod", ws / "src" / "go.mod"):
        t = _read_text(gomod)
        if t:
            shas = _GOMOD_PSEUDO_SHA_RE.findall(t)
            if shas:
                return shas[-1], f"go.mod:{gomod.name} pseudo-version"
    return None, ""


# ---------------------------------------------------------------------------
# git / gh helpers (read-only)
# ---------------------------------------------------------------------------
def _run(cmd: list[str], cwd: Optional[Path] = None, timeout: int = 60) -> subprocess.CompletedProcess:
    return subprocess.run(
        cmd, cwd=str(cwd) if cwd else None,
        capture_output=True, text=True, timeout=timeout,
    )


def _is_git_repo(d: Path) -> bool:
    try:
        r = _run(["git", "-C", str(d), "rev-parse", "--is-inside-work-tree"])
        return r.returncode == 0 and r.stdout.strip() == "true"
    except (OSError, subprocess.SubprocessError):
        return False


def _short(sha: str) -> str:
    return sha[:12]


def enumerate_upstream_security_commits_local(
    clone: Path, pin_sha: str, window: int
) -> tuple[list[dict[str, Any]], Optional[str]]:
    """git log <pin>..HEAD, filter to security-relevant subjects.

    Returns (commits, error). Each commit: {sha, subject, body, security_reason}.
    """
    # Verify pin is reachable in the clone.
    chk = _run(["git", "-C", str(clone), "cat-file", "-e", f"{pin_sha}^{{commit}}"])
    if chk.returncode != 0:
        return [], (
            f"pin {_short(pin_sha)} not found in upstream clone {clone}; "
            f"fetch the upstream history that includes the pin"
        )
    # Full body so cherry-pick trailers survive. %x1e between records, %x1f between fields.
    fmt = "%H%x1f%s%x1f%b%x1e"
    r = _run(
        ["git", "-C", str(clone), "log", f"{pin_sha}..HEAD",
         f"--max-count={window}", f"--format={fmt}"],
        timeout=120,
    )
    if r.returncode != 0:
        return [], f"git log failed: {r.stderr.strip()[:200]}"
    commits: list[dict[str, Any]] = []
    for rec in r.stdout.split("\x1e"):
        rec = rec.strip("\n")
        if not rec.strip():
            continue
        parts = rec.split("\x1f")
        if len(parts) < 2:
            continue
        sha = parts[0].strip()
        subject = parts[1].strip()
        body = parts[2].strip() if len(parts) > 2 else ""
        reason = _security_reason(subject, body)
        if reason:
            commits.append({"sha": sha, "subject": subject, "body": body,
                            "security_reason": reason})
    return commits, None


def enumerate_upstream_security_commits_gh(
    owner_repo: str, since_iso: str, window: int
) -> tuple[list[dict[str, Any]], Optional[str]]:
    """gh api repos/<owner>/<repo>/commits?since=... (opt-in network path)."""
    env = dict(os.environ)
    if env.get("GITHUB_TOKEN") and not env.get("GH_TOKEN"):
        env["GH_TOKEN"] = env["GITHUB_TOKEN"]
    commits: list[dict[str, Any]] = []
    page = 1
    per_page = 100
    while len(commits) < window:
        path = (f"repos/{owner_repo}/commits?since={since_iso}"
                f"&per_page={per_page}&page={page}")
        r = subprocess.run(
            ["gh", "api", path], capture_output=True, text=True, timeout=60, env=env,
        )
        if r.returncode != 0:
            if page == 1:
                return [], f"gh api failed: {r.stderr.strip()[:200]}"
            break
        try:
            arr = json.loads(r.stdout)
        except json.JSONDecodeError:
            break
        if not isinstance(arr, list) or not arr:
            break
        for c in arr:
            sha = str(c.get("sha", ""))
            msg = str((c.get("commit") or {}).get("message", ""))
            subject = msg.splitlines()[0] if msg else ""
            body = "\n".join(msg.splitlines()[1:]) if msg else ""
            reason = _security_reason(subject, body)
            if reason and sha:
                commits.append({"sha": sha, "subject": subject, "body": body,
                                "security_reason": reason})
        if len(arr) < per_page:
            break
        page += 1
    return commits[:window], None


def _security_reason(subject: str, body: str) -> str:
    """Return a short reason string if the commit looks security-relevant, else ''."""
    hay = f"{subject}\n{body}"
    m = _SECURITY_RE.search(hay)
    if m:
        return f"security-term:{m.group(0).strip()}"
    if _FIX_RE.search(subject) and _FIX_SECURITY_CONTEXT_RE.search(hay):
        return "fix+security-context"
    return ""


# ---------------------------------------------------------------------------
# Backport-presence detection in the fork tree
# ---------------------------------------------------------------------------
def _normalize_subject(s: str) -> str:
    """Strip trailing PR-number suffix and collapse whitespace for matching."""
    s = _SUBJECT_PR_RE.sub("", s).strip()
    s = re.sub(r"\s+", " ", s).strip().lower()
    return s


def fork_backport_index(fork_repo: Path, window: int) -> tuple[dict[str, str], set[str], Optional[str]]:
    """Build (subject->sha map, set of cherry-picked upstream shas) for the fork.

    Returns ({normalized_subject: fork_sha}, {cherry_picked_sha_prefixes}, error).
    """
    fmt = "%H%x1f%s%x1f%b%x1e"
    r = _run(
        ["git", "-C", str(fork_repo), "log", f"--max-count={max(window * 3, 600)}",
         f"--format={fmt}"],
        timeout=120,
    )
    if r.returncode != 0:
        return {}, set(), f"fork git log failed: {r.stderr.strip()[:200]}"
    subj_map: dict[str, str] = {}
    cherry: set[str] = set()
    for rec in r.stdout.split("\x1e"):
        rec = rec.strip("\n")
        if not rec.strip():
            continue
        parts = rec.split("\x1f")
        if len(parts) < 2:
            continue
        sha = parts[0].strip()
        subject = parts[1].strip()
        body = parts[2].strip() if len(parts) > 2 else ""
        norm = _normalize_subject(subject)
        if norm and norm not in subj_map:
            subj_map[norm] = sha
        for cm in _CHERRY_PICK_RE.finditer(f"{subject}\n{body}"):
            cherry.add(cm.group(1).lower())
    return subj_map, cherry, None


def is_backported(commit: dict[str, Any], subj_map: dict[str, str],
                  cherry: set[str]) -> tuple[bool, str]:
    """Return (backported, evidence)."""
    up_sha = commit["sha"].lower()
    # cherry-pick trailer in fork referencing the upstream sha
    for c in cherry:
        if up_sha.startswith(c) or c.startswith(up_sha[: len(c)]):
            return True, f"cherry-pick-trailer:{_short(up_sha)}"
    # subject match
    norm = _normalize_subject(commit["subject"])
    if norm and norm in subj_map:
        return True, f"subject-match:{_short(subj_map[norm])}"
    return False, ""


# ---------------------------------------------------------------------------
# Workspace fork-repo discovery (for the backport index)
# ---------------------------------------------------------------------------
def discover_fork_repo(ws: Path) -> Optional[Path]:
    for cand in (ws, ws / "src"):
        if _is_git_repo(cand):
            return cand
    # vendored upstream tree under the workspace
    for vend in ("vendor", "third_party", "external"):
        d = ws / vend
        if _exists(d) and d.is_dir():
            for sub in sorted(d.iterdir()) if _exists(d) else []:
                if _is_git_repo(sub):
                    return sub
    return None


def discover_upstream_clone(ws: Path, owner_repo: Optional[str]) -> Optional[Path]:
    """Best-effort offline upstream-clone discovery (siblings / common caches)."""
    if not owner_repo:
        return None
    repo_name = owner_repo.split("/")[-1]
    candidates: list[Path] = []
    parent = ws.parent
    candidates += [parent / repo_name, parent / f"{repo_name}-upstream",
                   ws / ".upstream" / repo_name, ws / "upstream"]
    home = Path(os.path.expanduser("~"))
    candidates += [home / "audits" / repo_name, home / "src" / repo_name,
                   home / "clones" / repo_name]
    for c in candidates:
        if _exists(c) and _is_git_repo(c):
            return c
    return None


# ---------------------------------------------------------------------------
# Proof-queue task emit (shape: {"tasks": [...]} - exploit-queue.py consumes)
# ---------------------------------------------------------------------------
def _task_id(upstream: str, sha: str) -> str:
    h = hashlib.sha1(f"{upstream}:{sha}".encode()).hexdigest()[:8]
    return f"fork-divergence-{_short(sha)}-{h}"


def lead_to_task(lead: dict[str, Any], upstream: str, fork_repo: Optional[Path]) -> dict[str, Any]:
    sha = lead["sha"]
    subj = lead["subject"]
    replay = (
        f"git -C <upstream-clone> show {_short(sha)}  "
        f"# inspect the not-backported upstream security fix, then map its "
        f"changed path into the fork tree and confirm in-scope reachability"
    )
    return {
        "task_id": _task_id(upstream, sha),
        "advisory_only": True,
        "proof_needed": (
            f"Upstream {upstream} security commit {_short(sha)} "
            f"(\"{subj[:80]}\") is NOT backported into the fork at audit-pin. "
            f"Prove the unpatched code path is reachable in-scope and map to "
            f"the rubric impact."
        )[:300],
        "blocker": (
            "confirm-in-scope-reachability-of-unpatched-path"
        ),
        "source_ref": f"upstream:{upstream}@{_short(sha)}",
        "chain_id": "fork-divergence-not-backported",
        "fork_divergence": {
            "upstream_repo": upstream,
            "upstream_commit": sha,
            "subject": subj,
            "security_reason": lead.get("security_reason", ""),
            "replay_command": replay,
            "fork_repo": str(fork_repo) if fork_repo else None,
        },
    }


def emit_to_proof_queue(ws: Path, tasks: list[dict[str, Any]]) -> dict[str, Any]:
    """Additive merge into <ws>/.auditooor/proof_obligation_queue.json."""
    qdir = ws / ".auditooor"
    qdir.mkdir(parents=True, exist_ok=True)
    qpath = qdir / "proof_obligation_queue.json"
    existing: dict[str, Any] = {"schema": "auditooor.proof_obligation_queue.v1", "tasks": []}
    if _exists(qpath):
        t = _read_text(qpath)
        if t:
            try:
                loaded = json.loads(t)
                if isinstance(loaded, dict):
                    existing = loaded
                    existing.setdefault("tasks", [])
            except json.JSONDecodeError:
                pass
        # back up once before mutating
        bak = qdir / "proof_obligation_queue.json.pre-fork-divergence.bak"
        if not _exists(bak):
            bak.write_text(t or "", encoding="utf-8")
    seen = {str(x.get("task_id")) for x in existing.get("tasks", []) if isinstance(x, dict)}
    added = 0
    for task in tasks:
        if task["task_id"] in seen:
            continue
        existing["tasks"].append(task)
        seen.add(task["task_id"])
        added += 1
    existing["fork_divergence_last_run"] = _utc_now()
    qpath.write_text(json.dumps(existing, indent=2) + "\n", encoding="utf-8")
    return {"queue_path": str(qpath), "tasks_added": added,
            "tasks_total": len(existing.get("tasks", []))}


# ---------------------------------------------------------------------------
# Stage driver
# ---------------------------------------------------------------------------
def run_stage(
    ws: Path,
    upstream_clone: Optional[Path],
    upstream_override: Optional[str],
    pin_override: Optional[str],
    window: int,
    allow_network: bool,
    emit_queue: bool,
) -> dict[str, Any]:
    payload: dict[str, Any] = {
        "schema": SCHEMA, "gate": GATE, "tool": TOOL_NAME,
        "workspace": str(ws), "generated_at": _utc_now(),
        "verdict": "", "upstream": None, "pin_sha": None,
        "security_commits_scanned": 0, "not_backported_leads": [],
        "backported_count": 0, "queue": None, "warnings": [],
    }

    # 1. upstream detect (reuse resolver)
    upstream = upstream_override
    if not upstream:
        resolver = _load_resolver()
        res = resolver.evaluate(ws)
        if not res.get("is_fork"):
            payload["verdict"] = "not-a-fork"
            return payload
        upstream = res.get("upstream")
        if not upstream:
            payload["verdict"] = "fork-upstream-unresolved"
            payload["warnings"].append(
                "fork detected but upstream owner/repo could not be resolved; "
                "supply --upstream OWNER/REPO"
            )
            return payload
    payload["upstream"] = upstream

    # 2. pin SHA
    pin_sha = pin_override
    pin_src = "override" if pin_override else ""
    if not pin_sha:
        pin_sha, pin_src = resolve_pin_sha(ws)
    if not pin_sha:
        payload["verdict"] = "pin-unresolved"
        payload["warnings"].append(
            "fork-pin SHA could not be resolved from manifests; supply --pin SHA"
        )
        return payload
    payload["pin_sha"] = pin_sha
    payload["pin_source"] = pin_src

    # 3. enumerate upstream security commits after the pin
    clone = upstream_clone or discover_upstream_clone(ws, upstream)
    security_commits: list[dict[str, Any]] = []
    if clone and _is_git_repo(clone):
        payload["upstream_clone"] = str(clone)
        commits, err = enumerate_upstream_security_commits_local(clone, pin_sha, window)
        if err:
            payload["warnings"].append(err)
        security_commits = commits
        payload["enumeration_source"] = "local-clone"
    elif allow_network:
        # without the pin date we cannot anchor `since=`; derive from clone if any,
        # else fall back to a wide window. Online path is best-effort.
        since = "1970-01-01T00:00:00Z"
        commits, err = enumerate_upstream_security_commits_gh(upstream, since, window)
        if err:
            payload["warnings"].append(err)
        security_commits = commits
        payload["enumeration_source"] = "gh-api"
        payload["warnings"].append(
            "gh-api path cannot cut at the pin SHA precisely; results may include "
            "pre-pin commits. Prefer --upstream-clone for an exact pin..HEAD cut."
        )
    else:
        payload["verdict"] = "no-upstream-source"
        payload["warnings"].append(
            "no local upstream clone found and --allow-network not set; "
            "supply --upstream-clone DIR or pass --allow-network"
        )
        return payload

    payload["security_commits_scanned"] = len(security_commits)

    # 4. backport-presence in fork tree
    fork_repo = discover_fork_repo(ws)
    subj_map: dict[str, str] = {}
    cherry: set[str] = set()
    if fork_repo:
        payload["fork_repo"] = str(fork_repo)
        subj_map, cherry, err = fork_backport_index(fork_repo, window)
        if err:
            payload["warnings"].append(err)
    else:
        payload["warnings"].append(
            "no fork git tree found in workspace; cannot verify backport "
            "presence - all security commits reported as candidate leads"
        )

    not_backported: list[dict[str, Any]] = []
    backported = 0
    for c in security_commits:
        if fork_repo:
            done, ev = is_backported(c, subj_map, cherry)
        else:
            done, ev = False, ""
        if done:
            backported += 1
        else:
            row = dict(c)
            row["backport_evidence"] = ""
            not_backported.append(row)
    payload["backported_count"] = backported
    payload["not_backported_leads"] = not_backported

    # 5. emit
    tasks = [lead_to_task(c, upstream, fork_repo) for c in not_backported]
    payload["candidate_tasks"] = tasks
    if emit_queue and tasks:
        payload["queue"] = emit_to_proof_queue(ws, tasks)

    payload["verdict"] = (
        "not-backported-leads-found" if not_backported else "fork-current-no-leads"
    )
    return payload


def main(argv: Optional[list[str]] = None) -> int:
    p = argparse.ArgumentParser(
        prog="fork-divergence-hunt-stage.py",
        description="Named hunt stage: emit not-backported upstream security "
                    "commits as proof-queue leads for a fork target.",
    )
    p.add_argument("--workspace", "--ws", dest="workspace", required=True)
    p.add_argument("--upstream-clone", dest="upstream_clone", default="")
    p.add_argument("--upstream", dest="upstream", default="")
    p.add_argument("--pin", dest="pin", default="")
    p.add_argument("--window", type=int, default=400)
    p.add_argument("--allow-network", action="store_true")
    p.add_argument("--emit-queue", action="store_true")
    p.add_argument("--out", default="")
    p.add_argument("--json", action="store_true")
    p.add_argument("--strict", action="store_true")
    args = p.parse_args(argv)

    ws = Path(os.path.expanduser(args.workspace)).resolve()
    if not _exists(ws) or not ws.is_dir():
        payload = {"schema": SCHEMA, "gate": GATE, "verdict": "error",
                   "reason": "workspace not found or not a directory",
                   "workspace": str(ws)}
        out = json.dumps(payload, indent=2)
        print(out if args.json else f"[{GATE}] verdict=error (workspace missing)")
        if args.out:
            Path(args.out).write_text(out + "\n", encoding="utf-8")
        return 1

    clone = Path(os.path.expanduser(args.upstream_clone)).resolve() if args.upstream_clone else None

    try:
        payload = run_stage(
            ws=ws, upstream_clone=clone,
            upstream_override=args.upstream or None,
            pin_override=args.pin or None,
            window=args.window, allow_network=args.allow_network,
            emit_queue=args.emit_queue,
        )
    except (OSError, subprocess.SubprocessError, RuntimeError) as exc:
        payload = {"schema": SCHEMA, "gate": GATE, "verdict": "error",
                   "reason": str(exc)[:300], "workspace": str(ws)}
        out = json.dumps(payload, indent=2)
        print(out if args.json else f"[{GATE}] verdict=error ({exc})")
        if args.out:
            Path(args.out).write_text(out + "\n", encoding="utf-8")
        return 1

    out = json.dumps(payload, indent=2)
    if args.out:
        Path(args.out).write_text(out + "\n", encoding="utf-8")
    if args.json:
        print(out)
    else:
        print(f"[{GATE}] verdict={payload['verdict']} upstream={payload.get('upstream')} "
              f"pin={(payload.get('pin_sha') or '')[:12]} "
              f"scanned={payload.get('security_commits_scanned', 0)} "
              f"not_backported={len(payload.get('not_backported_leads', []))} "
              f"backported={payload.get('backported_count', 0)}")
        for w in payload.get("warnings", []):
            print(f"  warn: {w}")
        for lead in payload.get("not_backported_leads", [])[:20]:
            print(f"  LEAD {_short(lead['sha'])} [{lead.get('security_reason','')}] {lead['subject'][:80]}")
        if payload.get("queue"):
            q = payload["queue"]
            print(f"  queue: +{q['tasks_added']} tasks -> {q['queue_path']} (total {q['tasks_total']})")

    if args.strict and payload.get("not_backported_leads"):
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
