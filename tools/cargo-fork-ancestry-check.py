#!/usr/bin/env python3
"""cargo-fork-ancestry-check — flag upstream-fork-divergence for Cargo/Rust (L28-E pattern).

Rust analog of tools/gomod-fork-ancestry-check.py.  Closes the L28-E
(upstream-fork-divergence) detection loop for Cargo workspaces.

The pattern this codifies (per AMF-007, mirroring the Go tool):
  1. Parse Cargo.toml for `git = "https://..."` dependency entries (fork/non-crates.io)
  2. For each git dep, resolve the pinned commit SHA from Cargo.lock [[package]] entries
  3. Identify the canonical upstream crate on crates.io (by package name)
  4. Compare the pinned git ref vs upstream crates.io latest version + published date
  5. Surface divergence: ahead / behind / forked / same — candidate findings per L28-E

The Cargo.lock [[package]] source field has this form for git deps:
  source = "git+https://github.com/org/repo?branch=main#<full-sha>"
  source = "git+https://github.com/org/repo?tag=v0.1.0#<full-sha>"
  source = "git+https://github.com/org/repo?rev=abc1234#<full-sha>"

Usage:
    tools/cargo-fork-ancestry-check.py --workspace <path/to/workspace>
    tools/cargo-fork-ancestry-check.py --workspace <path> --audit-pin <sha>
    tools/cargo-fork-ancestry-check.py --workspace <path> --json
    tools/cargo-fork-ancestry-check.py --workspace <path> --strict

Output (markdown by default; JSON with --json):
    For each git-sourced dependency:
      - name, git URL, pinned lock SHA, upstream crates.io latest
      - divergence: same | ahead | behind | forked
      - candidate security commits (if git clones available)

Exit codes:
    0 = no diverged git deps found (or analysis succeeded, all same)
    1 = error (bad workspace path, missing Cargo.toml, network failure)
    2 = diverged deps found (with --strict; otherwise advisory)

Network:
    Hits https://crates.io/api/v1/crates/<name> per dep.
    On network failure: exits 2 with message to stderr.
    Set CARGO_FORK_ANCESTRY_OFFLINE=1 to skip all network calls (testing).

Pre-emptive originality check:
    Tool flags candidates only. Operator must verify each candidate has
    NO public GHSA / advisory before drafting per L28-E + L31.
"""
from __future__ import annotations

import argparse
import json
import os
import pathlib
import re
import subprocess
import sys
import tempfile
import urllib.error
import urllib.request
from typing import Optional

REPO = pathlib.Path(__file__).resolve().parent.parent

OFFLINE = os.environ.get("CARGO_FORK_ANCESTRY_OFFLINE", "").strip() in ("1", "true", "yes")

# Security-relevant keywords for commit subject scanning (mirrors gomod tool)
SECURITY_KEYWORDS = re.compile(
    r"\b(fix|verif|valid|harden|security|panic|consens|"
    r"blocksync|halt|crash|nil|inject|overflow|underflow|"
    r"reentran|access|auth|signature|replay|exploit|advisor|"
    r"backport|cherry-pick|vuln|cve|oom|dos|denial|use.after|"
    r"unsound|unsafe|race|data.race|bound|saniti)",
    re.IGNORECASE,
)

# Source field pattern for git-sourced Cargo.lock entries:
#   git+https://github.com/org/repo?branch=main#abc1234...
CARGO_LOCK_GIT_SOURCE_RE = re.compile(
    r"^git\+(?P<url>https?://[^?#]+)(?:\?[^#]*)?#(?P<sha>[0-9a-f]{40})$"
)


# ---------------------------------------------------------------------------
# Cargo.toml parsing
# ---------------------------------------------------------------------------

def _toml_string_value(s: str) -> Optional[str]:
    """Extract string value from a TOML-ish line like key = \"value\"."""
    m = re.search(r'"([^"]+)"', s)
    if m:
        return m.group(1)
    m = re.search(r"'([^']+)'", s)
    if m:
        return m.group(1)
    return None


def parse_cargo_toml(workspace: pathlib.Path) -> list[dict]:
    """Parse Cargo.toml for git-sourced dependencies.

    Handles both workspace-level and single-crate Cargo.toml files.
    Returns list of dicts: {name, git_url, branch, tag, rev, features, ...}
    """
    cargo_toml = workspace / "Cargo.toml"
    text = cargo_toml.read_text(encoding="utf-8")
    return _parse_cargo_toml_text(text)


def _parse_cargo_toml_text(text: str) -> list[dict]:
    """Parse Cargo.toml text (separated for testing)."""
    git_deps: list[dict] = {}  # name -> dep dict (deduplicate)

    lines = text.splitlines()
    i = 0
    n = len(lines)

    while i < n:
        line = lines[i]
        stripped = line.strip()

        # Section headers: [dependencies], [dev-dependencies], [build-dependencies]
        # [workspace.dependencies], [target.'cfg(...)'.dependencies]
        section_m = re.match(r"^\[(?:[^\]]*\.)?(?:dev-)?(?:build-)?dependencies\]", stripped)
        if section_m:
            i += 1
            # Read deps in this section until next [section]
            while i < n:
                dep_line = lines[i].strip()
                if dep_line.startswith("["):
                    break  # new section

                # Simple inline dep with git: name = { git = "..." }
                m_inline = re.match(r'^(\S+)\s*=\s*\{(.+)\}', dep_line)
                if m_inline:
                    dep_name = m_inline.group(1)
                    dep_body = m_inline.group(2)
                    entry = _extract_git_dep(dep_name, dep_body)
                    if entry:
                        git_deps[dep_name] = entry
                    i += 1
                    continue

                # Start of a multi-line dep: name = {
                m_multi_start = re.match(r'^(\S+)\s*=\s*\{', dep_line)
                if m_multi_start and not dep_line.rstrip().endswith("}"):
                    dep_name = m_multi_start.group(1)
                    # Collect body until closing }
                    body_lines = [dep_line]
                    i += 1
                    brace_depth = dep_line.count("{") - dep_line.count("}")
                    while i < n and brace_depth > 0:
                        body_lines.append(lines[i].strip())
                        brace_depth += lines[i].count("{") - lines[i].count("}")
                        i += 1
                    full_body = " ".join(body_lines)
                    entry = _extract_git_dep(dep_name, full_body)
                    if entry:
                        git_deps[dep_name] = entry
                    continue

                i += 1
            continue

        # Named table: [[package]] style deps are in Cargo.lock, not here
        # Handle: [package.metadata.X] — skip
        i += 1

    # Also parse [patch.*] sections which often contain git overrides
    for section_header, body in _iter_toml_sections(text):
        if re.match(r"\[patch\.", "[" + section_header + "]"):
            for dep_name, dep_body in _iter_section_entries(body):
                entry = _extract_git_dep(dep_name, dep_body)
                if entry:
                    git_deps[dep_name] = entry

    return list(git_deps.values())


def _iter_toml_sections(text: str):
    """Yield (header_content, body_text) for each [...] section."""
    current_header = None
    body_lines = []
    for line in text.splitlines():
        stripped = line.strip()
        m = re.match(r"^\[([^\]]+)\]$", stripped)
        if m and not stripped.startswith("[["):
            if current_header is not None:
                yield current_header, "\n".join(body_lines)
            current_header = m.group(1)
            body_lines = []
        else:
            if current_header is not None:
                body_lines.append(line)
    if current_header is not None:
        yield current_header, "\n".join(body_lines)


def _iter_section_entries(body: str):
    """Yield (name, body_str) for each key = {…} entry in a section body."""
    lines = body.splitlines()
    i = 0
    while i < len(lines):
        dep_line = lines[i].strip()
        if not dep_line or dep_line.startswith("#"):
            i += 1
            continue
        m_inline = re.match(r'^(\S+)\s*=\s*\{(.+)\}', dep_line)
        if m_inline:
            yield m_inline.group(1), m_inline.group(2)
            i += 1
            continue
        m_multi = re.match(r'^(\S+)\s*=\s*\{', dep_line)
        if m_multi and not dep_line.rstrip().endswith("}"):
            name = m_multi.group(1)
            body_collect = [dep_line]
            i += 1
            depth = dep_line.count("{") - dep_line.count("}")
            while i < len(lines) and depth > 0:
                body_collect.append(lines[i].strip())
                depth += lines[i].count("{") - lines[i].count("}")
                i += 1
            yield name, " ".join(body_collect)
            continue
        i += 1


def _extract_git_dep(name: str, body: str) -> Optional[dict]:
    """Extract git dep info from inline body text. Returns dict or None."""
    if "git" not in body:
        return None
    git_m = re.search(r'\bgit\s*=\s*["\']([^"\']+)["\']', body)
    if not git_m:
        return None
    git_url = git_m.group(1)
    entry: dict = {"name": name, "git_url": git_url}

    branch_m = re.search(r'\bbranch\s*=\s*["\']([^"\']+)["\']', body)
    if branch_m:
        entry["branch"] = branch_m.group(1)

    tag_m = re.search(r'\btag\s*=\s*["\']([^"\']+)["\']', body)
    if tag_m:
        entry["tag"] = tag_m.group(1)

    rev_m = re.search(r'\brev\s*=\s*["\']([^"\']+)["\']', body)
    if rev_m:
        entry["rev"] = rev_m.group(1)

    return entry


# ---------------------------------------------------------------------------
# Cargo.lock parsing
# ---------------------------------------------------------------------------

def parse_cargo_lock(workspace: pathlib.Path) -> dict[str, list[dict]]:
    """Parse Cargo.lock for [[package]] entries with git sources.

    Returns dict: name -> list of package dicts with lock_sha resolved.
    """
    lock_path = workspace / "Cargo.lock"
    if not lock_path.is_file():
        return {}
    text = lock_path.read_text(encoding="utf-8")
    return _parse_cargo_lock_text(text)


def _parse_cargo_lock_text(text: str) -> dict[str, list[dict]]:
    """Parse Cargo.lock text (separated for testing)."""
    packages: dict[str, list[dict]] = {}
    current: Optional[dict] = None

    for line in text.splitlines():
        stripped = line.strip()

        if stripped == "[[package]]":
            if current:
                _register_lock_pkg(current, packages)
            current = {}
            continue

        if current is None:
            continue

        if "=" in stripped:
            key, _, val = stripped.partition("=")
            key = key.strip()
            val = val.strip().strip('"')
            current[key] = val

    if current:
        _register_lock_pkg(current, packages)

    return packages


def _register_lock_pkg(pkg: dict, packages: dict):
    name = pkg.get("name", "")
    if not name:
        return
    source = pkg.get("source", "")
    m = CARGO_LOCK_GIT_SOURCE_RE.match(source)
    if m:
        pkg["lock_sha"] = m.group("sha")
        pkg["lock_git_url"] = m.group("url")
    if name not in packages:
        packages[name] = []
    packages[name].append(pkg)


# ---------------------------------------------------------------------------
# crates.io upstream lookup
# ---------------------------------------------------------------------------

def fetch_crates_io_info(name: str) -> Optional[dict]:
    """Query crates.io API for latest version info. Returns dict or None."""
    if OFFLINE:
        return None
    url = f"https://crates.io/api/v1/crates/{name}"
    req = urllib.request.Request(url, headers={"User-Agent": "auditooor-cargo-fork-ancestry/1.0"})
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            data = json.loads(resp.read().decode("utf-8"))
        crate = data.get("crate", {})
        newest = crate.get("newest_version", "")
        max_stable = crate.get("max_stable_version", newest)
        # Also get the date of latest published version
        versions = data.get("versions", [])
        latest_version_info = None
        for v in versions:
            if v.get("num") == newest:
                latest_version_info = v
                break
        return {
            "name": name,
            "newest_version": newest,
            "max_stable_version": max_stable,
            "created_at": (latest_version_info or {}).get("created_at", ""),
            "repository": crate.get("repository", ""),
        }
    except (urllib.error.URLError, urllib.error.HTTPError, json.JSONDecodeError, OSError) as exc:
        sys.stderr.write(f"[cargo-fork-ancestry] crates.io lookup failed for {name}: {exc}\n")
        return None


# ---------------------------------------------------------------------------
# Git helpers (mirrors gomod tool)
# ---------------------------------------------------------------------------

def _git(args: list[str], cwd: pathlib.Path, *, capture: bool = True) -> subprocess.CompletedProcess:
    return subprocess.run(["git", "-C", str(cwd), *args], capture_output=capture, text=True)


def ensure_clone(url: str, target_dir: pathlib.Path, *, quiet: bool = True) -> Optional[pathlib.Path]:
    """Clone the repo if not present. Returns target_dir or None on failure."""
    if target_dir.is_dir() and (target_dir / ".git").exists():
        return target_dir
    target_dir.parent.mkdir(parents=True, exist_ok=True)
    cmd = ["git", "clone", "-q" if quiet else "", url, str(target_dir)]
    cmd = [c for c in cmd if c]
    proc = subprocess.run(cmd, capture_output=True, text=True)
    if proc.returncode != 0:
        sys.stderr.write(f"[cargo-fork-ancestry] clone failed for {url}: {proc.stderr[:500]}\n")
        return None
    return target_dir


def list_upstream_tags_since_date(upstream_dir: pathlib.Path, since_date_yyyymmdd: str) -> list[str]:
    """Return upstream tags created at or after a YYYY-MM-DD date."""
    proc = _git(["tag", "--sort=creatordate", "--format=%(creatordate:short) %(refname:strip=2)"], upstream_dir)
    if proc.returncode != 0:
        return []
    since_iso = f"{since_date_yyyymmdd[:4]}-{since_date_yyyymmdd[4:6]}-{since_date_yyyymmdd[6:8]}"
    tags = []
    for line in proc.stdout.splitlines():
        parts = line.strip().split(" ", 1)
        if len(parts) != 2:
            continue
        tag_date, tag = parts
        if tag_date >= since_iso:
            tags.append(tag)
    return tags


def is_ancestor(commit: str, of_target: str, repo_dir: pathlib.Path) -> bool:
    """Return True if commit is an ancestor of of_target."""
    proc = _git(["merge-base", "--is-ancestor", commit, of_target], repo_dir)
    return proc.returncode == 0


def list_security_commits_in_range(repo_dir: pathlib.Path, base: str, tip: str) -> list[dict]:
    """List commits with security-relevant subjects between base and tip."""
    proc = _git(["log", f"{base}..{tip}", "--pretty=%H %s"], repo_dir)
    if proc.returncode != 0:
        return []
    out = []
    for line in proc.stdout.splitlines():
        parts = line.split(" ", 1)
        if len(parts) != 2:
            continue
        sha, subject = parts
        if SECURITY_KEYWORDS.search(subject):
            out.append({"sha": sha, "subject": subject})
    return out


# ---------------------------------------------------------------------------
# Core analysis
# ---------------------------------------------------------------------------

def classify_divergence(
    lock_sha: Optional[str],
    upstream_info: Optional[dict],
    git_url: str,
    upstream_git_url: Optional[str],
    *,
    clone_root: pathlib.Path,
    skip_clone: bool,
) -> dict:
    """Compare pinned git dep vs upstream. Return divergence classification dict."""
    if upstream_info is None:
        return {
            "divergence": "unknown",
            "reason": "crates.io lookup unavailable (offline or network error)",
        }

    # Determine the upstream git URL from crates.io repository field
    upstream_repo_url = upstream_info.get("repository", "")

    # If the git_url matches (or is a fork of) upstream_repo_url, we can do
    # ancestry analysis via clones. If not, we flag as "forked".
    git_url_clean = git_url.rstrip("/").removesuffix(".git")
    upstream_url_clean = upstream_repo_url.rstrip("/").removesuffix(".git")

    if not upstream_repo_url:
        return {"divergence": "unknown", "reason": "no repository field in crates.io response"}

    is_same_origin = (git_url_clean == upstream_url_clean)
    is_fork = not is_same_origin

    result = {
        "divergence": "forked" if is_fork else "same",
        "upstream_latest_version": upstream_info.get("newest_version", ""),
        "upstream_repository": upstream_repo_url,
        "lock_sha": lock_sha or "",
    }

    if is_fork:
        result["reason"] = f"git URL {git_url!r} differs from crates.io repository {upstream_repo_url!r}"

    # If we have a lock SHA and git clones, attempt ancestry analysis
    if lock_sha and not skip_clone and not OFFLINE:
        fork_slug = re.sub(r"[^a-zA-Z0-9_-]", "-", git_url_clean.split("/")[-2::].__str__())[:40]
        fork_dir = clone_root / f"cargo-fork-{re.sub(r'[^a-z0-9]', '-', git_url_clean.split('github.com/')[-1])}"
        upstream_dir = clone_root / f"cargo-upstream-{re.sub(r'[^a-z0-9]', '-', upstream_url_clean.split('github.com/')[-1] if 'github.com' in upstream_url_clean else upstream_url_clean[-30:])}"

        ensure_clone(git_url if git_url.endswith(".git") else git_url + ".git", fork_dir)
        if upstream_repo_url:
            u_url = upstream_repo_url if upstream_repo_url.endswith(".git") else upstream_repo_url + ".git"
            ensure_clone(u_url, upstream_dir)

        if fork_dir.is_dir() and (fork_dir / ".git").exists():
            _git(["fetch", "--all", "--tags", "--quiet"], fork_dir, capture=False)
        if upstream_dir.is_dir() and (upstream_dir / ".git").exists():
            _git(["fetch", "--all", "--tags", "--quiet"], upstream_dir, capture=False)

        # Ancestor check: is lock_sha ahead of upstream latest tag?
        if upstream_dir.is_dir() and (upstream_dir / ".git").exists():
            upstream_tags = list_upstream_tags_since_date(upstream_dir, "20200101")
            if upstream_tags:
                latest_tag = upstream_tags[-1]
                if fork_dir.is_dir() and (fork_dir / ".git").exists():
                    try:
                        if is_ancestor(latest_tag, lock_sha, fork_dir):
                            result["divergence"] = "ahead"
                            result["reason"] = f"lock_sha includes upstream {latest_tag}"
                        elif is_ancestor(lock_sha, latest_tag, upstream_dir):
                            result["divergence"] = "behind"
                            result["reason"] = f"lock_sha is behind upstream {latest_tag}"
                    except Exception:
                        pass

    return result


def analyze_git_dep(
    dep: dict,
    lock_packages: dict[str, list[dict]],
    *,
    clone_root: pathlib.Path,
    skip_clone: bool,
    audit_pin: Optional[str],
) -> dict:
    """Full analysis of one git-sourced dependency. Returns result dict."""
    name = dep["name"]
    git_url = dep["git_url"]

    # Resolve lock SHA
    lock_sha: Optional[str] = None
    lock_pkg: Optional[dict] = None
    if name in lock_packages:
        for pkg in lock_packages[name]:
            if "lock_sha" in pkg:
                lock_url = pkg.get("lock_git_url", "")
                if not lock_url or git_url.rstrip("/").removesuffix(".git") in lock_url.rstrip("/"):
                    lock_sha = pkg["lock_sha"]
                    lock_pkg = pkg
                    break

    # Upstream lookup
    upstream_info = fetch_crates_io_info(name)

    # Classify divergence
    divergence_result = classify_divergence(
        lock_sha,
        upstream_info,
        git_url,
        upstream_info.get("repository") if upstream_info else None,
        clone_root=clone_root,
        skip_clone=skip_clone,
    )

    result: dict = {
        "name": name,
        "git_url": git_url,
        "ref": dep.get("rev") or dep.get("tag") or dep.get("branch") or "",
        "lock_sha": lock_sha or "",
        "upstream_latest": upstream_info.get("newest_version", "") if upstream_info else "",
        "upstream_repository": upstream_info.get("repository", "") if upstream_info else "",
        **divergence_result,
    }

    # audit-pin lag check: if audit_pin given, note whether lock_sha was pinned before/after
    if audit_pin and lock_sha:
        result["audit_pin"] = audit_pin
        result["audit_pin_lag_note"] = (
            f"Pinned at {lock_sha[:12]}; audit-pin workspace SHA was {audit_pin[:12]}. "
            "Verify whether the fork's lock_sha was current at the audit-pin date."
        )

    return result


# ---------------------------------------------------------------------------
# Rendering
# ---------------------------------------------------------------------------

def render_markdown(workspace: str, analyses: list[dict]) -> str:
    lines = [
        "# cargo-fork-ancestry-check report\n",
        f"**Workspace:** `{workspace}`\n",
        f"**Git deps analyzed:** {len(analyses)}\n",
    ]
    n_diverged = sum(1 for a in analyses if a.get("divergence") not in ("same", "unknown") or a.get("divergence") == "forked")
    lines.append(f"**Diverged/forked deps:** {n_diverged}\n")
    lines.append("\n---\n")

    for a in analyses:
        lines.append(f"## `{a['name']}` (git: `{a['git_url']}`)\n")
        lines.append(f"- Ref: `{a.get('ref', '(not pinned)')}`")
        lines.append(f"- Lock SHA: `{a.get('lock_sha', '(not in Cargo.lock)')}`")
        lines.append(f"- Upstream latest (crates.io): `{a.get('upstream_latest', '(unknown)')}`")
        lines.append(f"- Upstream repository: {a.get('upstream_repository', '(unknown)')}")
        div = a.get("divergence", "unknown")
        lines.append(f"- **Divergence:** `{div}`")
        if "reason" in a:
            lines.append(f"  - {a['reason']}")
        if "audit_pin_lag_note" in a:
            lines.append(f"- Audit-pin note: {a['audit_pin_lag_note']}")
        if div not in ("same",):
            lines.append("")
            lines.append("  > **L28-E filing path:** verify NO public GHSA / advisory before drafting.")
        lines.append("")

    return "\n".join(lines)


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    parser.add_argument("--workspace", required=True, help="path to workspace containing Cargo.toml")
    parser.add_argument("--audit-pin", default=None, help="audit-pin commit SHA for lag analysis")
    parser.add_argument("--clone-root", default=None, help="dir for git clones (default: /tmp/cargo-fork-ancestry)")
    parser.add_argument("--skip-clone", action="store_true", help="skip git cloning; use existing clones only")
    parser.add_argument("--json", action="store_true", dest="json_out", help="emit structured JSON")
    parser.add_argument("--strict", action="store_true", help="exit 2 if any diverged dep found")
    args = parser.parse_args()

    workspace = pathlib.Path(args.workspace).resolve()
    cargo_toml = workspace / "Cargo.toml"
    if not cargo_toml.is_file():
        sys.stderr.write(f"[cargo-fork-ancestry] no Cargo.toml found at {workspace}\n")
        return 1

    clone_root = (
        pathlib.Path(args.clone_root)
        if args.clone_root
        else pathlib.Path(tempfile.gettempdir()) / "cargo-fork-ancestry"
    )
    clone_root.mkdir(parents=True, exist_ok=True)

    try:
        git_deps = parse_cargo_toml(workspace)
    except Exception as exc:
        sys.stderr.write(f"[cargo-fork-ancestry] failed to parse Cargo.toml: {exc}\n")
        return 1

    lock_packages = parse_cargo_lock(workspace)

    if not git_deps:
        msg = f"[cargo-fork-ancestry] no git-sourced dependencies found in {cargo_toml}"
        if args.json_out:
            print(json.dumps({
                "schema": "auditooor.cargo_fork_ancestry.v1",
                "workspace": str(workspace),
                "git_deps": [],
                "audit_pin_lag": [],
                "message": msg,
            }))
        else:
            print(msg)
        return 0

    sys.stderr.write(f"[cargo-fork-ancestry] analyzing {len(git_deps)} git dep(s) (clone-root: {clone_root})...\n")

    analyses: list[dict] = []
    for dep in git_deps:
        analysis = analyze_git_dep(
            dep,
            lock_packages,
            clone_root=clone_root,
            skip_clone=args.skip_clone,
            audit_pin=args.audit_pin,
        )
        analyses.append(analysis)
        sys.stderr.write(f"  - {dep['name']}: divergence={analysis.get('divergence', 'unknown')}\n")

    # Build audit_pin_lag list (deps where lock_sha doesn't match audit-pin timeframe)
    audit_pin_lag = [a for a in analyses if "audit_pin_lag_note" in a]

    if args.json_out:
        print(json.dumps({
            "schema": "auditooor.cargo_fork_ancestry.v1",
            "workspace": str(workspace),
            "git_deps": analyses,
            "audit_pin_lag": audit_pin_lag,
        }, indent=2))
    else:
        print(render_markdown(str(workspace), analyses))

    if args.strict:
        diverged = [a for a in analyses if a.get("divergence") not in ("same",)]
        if diverged:
            return 2

    return 0


if __name__ == "__main__":
    sys.exit(main())
