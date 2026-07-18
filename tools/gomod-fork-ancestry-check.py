#!/usr/bin/env python3
"""gomod-fork-ancestry-check — flag upstream-fork-divergence (L28-E pattern).

Lane 5 of MCP harness review (PR #658) commit 5. Closes the agent-found-
tool-missed regression loop for both filed dydx wins:
  - LEAD-CMTBFT-FORK-LAG (cometbft v0.38.22 silently-shipped patches)
  - LEAD-COSMOS-SDK-CONSENSUS-PARAMS (cosmos-sdk v0.50.7 PR #20381)

The pattern this codifies (per AMF-007):
  1. Parse go.mod for `replace` directives pointing at <org>-controlled forks
  2. For each fork, identify the audit-pin SHA from the pseudo-version
  3. Identify upstream releases AFTER the fork-pin date
  4. Run `git merge-base --is-ancestor <upstream-tag> <fork-HEAD>` for each
  5. Surface tags / commits NOT in fork ancestry as candidate findings

Usage:
    tools/gomod-fork-ancestry-check.py <path/to/go.mod>
    tools/gomod-fork-ancestry-check.py <path/to/go.mod> --fork-org dydxprotocol
    tools/gomod-fork-ancestry-check.py <path/to/go.mod> --json
    tools/gomod-fork-ancestry-check.py <path/to/go.mod> --skip-clone  # use existing /tmp clones

Output (markdown by default; JSON with --json):
    For each forked dependency:
      - fork URL + audit-pin SHA + base version
      - upstream tags after fork-pin: {in_fork: [...], not_in_fork: [...]}
      - candidate fileable commits: list of {tag, commit_subject}

Exit codes:
    0 = no candidates found (or analysis succeeded)
    1 = error reading go.mod / git operations failed
    2 = candidates found (with --strict; otherwise advisory)

Pre-emptive originality check:
    Tool flags candidates only. Operator must verify each candidate has
    NO public GHSA / advisory before drafting per L28-E + L31.
"""
from __future__ import annotations

import argparse
import json
import pathlib
import re
import subprocess
import sys
import tempfile
from typing import Optional

REPO = pathlib.Path(__file__).resolve().parent.parent

# Pseudo-version pattern: vX.Y.Z-<pre>.<timestamp>-<short-sha>
# Standard Go pseudo-version format. Examples:
#   v0.38.6-0.20260428184537-904204b11c9e        (base v0.38.6, no upstream tag)
#   v0.50.6-0.20260428191449-a212821dc2c3        (base v0.50.6)
#   v8.0.0-rc.0.0.20250312180215-8733b3edf43a    (base v8.0.0-rc.0)
#   v1.1.1-0.20240509161911-1c8b8e787e85         (base v1.1.1)
# The `<pre>.` part is `0.` for "no upstream tag at this commit" or a tagged-prerelease.
PSEUDO_VERSION_RE = re.compile(
    r"^(?P<base>v[\d]+\.[\d]+\.[\d]+(?:-(?:[\w]+\.[\d]+|rc\.[\d]+(?:\.[\d]+)?))?)"
    r"-(?:[\w.]+\.)?(?P<timestamp>\d{14})-(?P<sha>[a-f0-9]{12})$"
)

# Default keyword filter for security-relevant commits in upstream.
# Word-stem matching: match the stem at word-start; rest of word may continue.
SECURITY_KEYWORDS = re.compile(
    r"\b(fix|verif|valid|harden|security|panic|consens|"
    r"blocksync|halt|crash|nil|inject|overflow|underflow|"
    r"reentran|access|auth|signature|replay|exploit|advisor|"
    r"backport|cherry-pick)",
    re.IGNORECASE,
)


def parse_gomod(path):
    """Parse go.mod for `replace` directives. Returns list of dicts."""
    text = pathlib.Path(path).read_text(encoding="utf-8")
    replaces = []
    in_replace_block = False
    for line in text.splitlines():
        stripped = line.strip()
        if stripped.startswith("replace ("):
            in_replace_block = True
            continue
        if in_replace_block and stripped == ")":
            in_replace_block = False
            continue

        # Single-line replace: `replace X => Y vN.M.K`
        m = re.match(r"replace\s+(\S+)\s+=>\s+(\S+)\s+(\S+)", stripped)
        if m:
            replaces.append({
                "from": m.group(1),
                "to": m.group(2),
                "version": m.group(3),
            })
            continue

        # In-block replace
        if in_replace_block:
            m = re.match(r"(\S+)\s+=>\s+(\S+)\s+(\S+)", stripped)
            if m:
                replaces.append({
                    "from": m.group(1),
                    "to": m.group(2),
                    "version": m.group(3),
                })
    return replaces


def is_org_controlled_fork(replace, org="dydxprotocol"):
    """Returns True if the `to` field points at an org-controlled fork."""
    return f"github.com/{org}/" in replace.get("to", "")


def parse_pseudo_version(version):
    """Parse a Go pseudo-version. Returns dict or None."""
    # Strip trailing /v<N> (module suffix)
    clean = version
    m = PSEUDO_VERSION_RE.match(clean)
    if not m:
        # Try without the .0 between base and timestamp
        m = re.match(r"^(?P<base>v[\d.\-\w]+)\.\d+\.(?P<timestamp>\d{14})-(?P<sha>[a-f0-9]{12})$", clean)
    if not m:
        return None
    return {
        "base_version": m.group("base"),
        "timestamp": m.group("timestamp"),
        "fork_sha": m.group("sha"),
        "fork_date": m.group("timestamp")[:8],  # YYYYMMDD
    }


def _git(args, cwd, *, capture=True):
    proc = subprocess.run(["git", "-C", str(cwd), *args], capture_output=capture, text=True)
    return proc


def ensure_clone(url, target_dir, *, quiet=True):
    """Clone the repo if not present. Returns target_dir path."""
    target = pathlib.Path(target_dir)
    if target.is_dir() and (target / ".git").exists():
        return target
    if not target.parent.exists():
        target.parent.mkdir(parents=True, exist_ok=True)
    cmd = ["git", "clone", "-q" if quiet else "", url, str(target)]
    cmd = [c for c in cmd if c]  # filter empty
    proc = subprocess.run(cmd, capture_output=True, text=True)
    if proc.returncode != 0:
        sys.stderr.write(f"[gomod-fork-ancestry] clone failed for {url}: {proc.stderr[:500]}\n")
        return None
    return target


def list_upstream_tags_after(upstream_dir, fork_date_yyyymmdd, *, base_version_prefix=None):
    """List upstream tags created after fork date. Returns list of tag names."""
    proc = _git(["tag", "--sort=creatordate", "--format=%(creatordate:short) %(refname:strip=2)"], upstream_dir)
    if proc.returncode != 0:
        return []
    tags = []
    fork_date_iso = f"{fork_date_yyyymmdd[:4]}-{fork_date_yyyymmdd[4:6]}-{fork_date_yyyymmdd[6:8]}"
    for line in proc.stdout.splitlines():
        parts = line.strip().split(" ", 1)
        if len(parts) != 2:
            continue
        tag_date, tag = parts
        if tag_date < fork_date_iso:
            continue
        if base_version_prefix and not tag.startswith(base_version_prefix):
            # Allow same minor line: e.g. base v0.38.5 -> tags v0.38.x
            base_minor = ".".join(base_version_prefix.split(".")[:2])  # v0.38
            if not tag.startswith(base_minor):
                continue
        tags.append(tag)
    return tags


def is_ancestor(commit_or_tag, of_target, repo_dir):
    """Check whether commit_or_tag is an ancestor of of_target."""
    proc = _git(["merge-base", "--is-ancestor", commit_or_tag, of_target], repo_dir)
    return proc.returncode == 0


def list_security_commits_in_tag_range(upstream_dir, prev_tag, this_tag):
    """List commits with security-relevant subjects between two upstream tags."""
    proc = _git(["log", f"{prev_tag}..{this_tag}", "--pretty=%H %s"], upstream_dir)
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


def analyze_fork(replace, upstream_url_for, *, clone_root, skip_clone=False):
    """Analyze one forked dependency. Returns analysis dict."""
    fork_to = replace["to"]  # e.g. github.com/dydxprotocol/cometbft
    version = replace["version"]
    parsed = parse_pseudo_version(version)
    if not parsed:
        return {"replace": replace, "error": f"unparseable pseudo-version: {version}"}

    fork_org_repo = fork_to.replace("github.com/", "")
    fork_url = f"https://github.com/{fork_org_repo}.git"
    upstream_url = upstream_url_for(replace["from"])
    if not upstream_url:
        return {"replace": replace, "fork_sha": parsed["fork_sha"], "error": f"no upstream URL inferable for {replace['from']}"}

    fork_dir = clone_root / f"{fork_org_repo.replace('/', '-')}-fork"
    upstream_dir = clone_root / f"{fork_org_repo.replace('/', '-')}-upstream"

    if not skip_clone:
        ensure_clone(fork_url, fork_dir, quiet=True)
        ensure_clone(upstream_url, upstream_dir, quiet=True)

    if not (fork_dir / ".git").exists() or not (upstream_dir / ".git").exists():
        return {"replace": replace, "fork_sha": parsed["fork_sha"], "error": "clone unavailable; pass --skip-clone false to retry"}

    # Try to checkout fork at audit-pin SHA
    proc = _git(["fetch", "--all", "--quiet"], fork_dir, capture=False)
    proc = _git(["checkout", parsed["fork_sha"]], fork_dir)
    fork_head_ok = proc.returncode == 0

    proc = _git(["fetch", "--all", "--tags", "--quiet"], upstream_dir, capture=False)
    upstream_tags = list_upstream_tags_after(
        upstream_dir,
        parsed["fork_date"],
        base_version_prefix=parsed["base_version"],
    )

    # Ancestry test each tag against fork HEAD
    in_fork = []
    not_in_fork = []
    for tag in upstream_tags:
        if is_ancestor(tag, parsed["fork_sha"], fork_dir):
            in_fork.append(tag)
        else:
            not_in_fork.append(tag)

    # For each not_in_fork tag, list its security commits
    candidates = []
    if len(not_in_fork) > 0:
        # Sort tags
        not_in_fork_sorted = sorted(not_in_fork)
        prev = parsed["base_version"]
        for tag in not_in_fork_sorted[:5]:  # cap to prevent runaway
            commits = list_security_commits_in_tag_range(upstream_dir, prev, tag)
            for c in commits:
                # Check if specific commit is in fork
                if not is_ancestor(c["sha"], parsed["fork_sha"], fork_dir):
                    candidates.append({
                        "tag": tag,
                        "commit_sha": c["sha"][:12],
                        "subject": c["subject"],
                    })
            prev = tag

    return {
        "replace": replace,
        "fork_sha": parsed["fork_sha"],
        "fork_date": parsed["fork_date"],
        "base_version": parsed["base_version"],
        "fork_head_checkout_ok": fork_head_ok,
        "upstream_tags_after_fork_date": upstream_tags,
        "in_fork": in_fork,
        "not_in_fork": not_in_fork,
        "candidate_security_commits": candidates,
    }


# Default upstream URL inferer — extend as new forks discovered
UPSTREAM_URL_OVERRIDES = {
    "github.com/cosmos/cosmos-sdk": "https://github.com/cosmos/cosmos-sdk.git",
    "github.com/cometbft/cometbft": "https://github.com/cometbft/cometbft.git",
    "github.com/cosmos/iavl": "https://github.com/cosmos/iavl.git",
    "github.com/cosmos/ibc-go/v8": "https://github.com/cosmos/ibc-go.git",
    "github.com/cosmos/ibc-go": "https://github.com/cosmos/ibc-go.git",
    "cosmossdk.io/store": "https://github.com/cosmos/cosmos-sdk.git",
    "github.com/skip-mev/slinky": "https://github.com/skip-mev/slinky.git",
}


def upstream_url_for(from_pkg):
    if from_pkg in UPSTREAM_URL_OVERRIDES:
        return UPSTREAM_URL_OVERRIDES[from_pkg]
    if from_pkg.startswith("github.com/"):
        # Strip /v<N> suffix
        clean = re.sub(r"/v\d+$", "", from_pkg)
        return f"https://{clean}.git"
    return None


def render_markdown(analyses):
    out = ["# gomod-fork-ancestry-check report\n"]
    n_candidates = sum(len(a.get("candidate_security_commits", [])) for a in analyses if "error" not in a)
    out.append(f"**Forks analyzed:** {len(analyses)}\n")
    out.append(f"**Candidate security commits NOT in fork:** {n_candidates}\n")
    out.append("\n---\n")
    for a in analyses:
        out.append(f"## `{a['replace']['from']}` -> `{a['replace']['to']}`\n")
        if "error" in a:
            out.append(f"**Error:** {a['error']}\n")
            continue
        out.append(f"- Fork-pin SHA: `{a['fork_sha']}` (date {a['fork_date']})")
        out.append(f"- Base version: `{a['base_version']}`")
        out.append(f"- Upstream tags after fork-pin: {len(a['upstream_tags_after_fork_date'])} ({', '.join(a['upstream_tags_after_fork_date'][:5])}{', ...' if len(a['upstream_tags_after_fork_date']) > 5 else ''})")
        out.append(f"- In fork: {len(a['in_fork'])}; **NOT in fork:** {len(a['not_in_fork'])}")
        if a['not_in_fork']:
            out.append(f"  - Missing tags: {', '.join(a['not_in_fork'][:8])}")
        candidates = a.get('candidate_security_commits', [])
        if candidates:
            out.append(f"- **Candidate fileable commits:** {len(candidates)}")
            for c in candidates[:10]:
                out.append(f"  - `{c['commit_sha']}` (in `{c['tag']}`): {c['subject']}")
            out.append("")
            out.append("  > **L28-E filing path:** for each candidate, verify NO public GHSA / advisory")
            out.append("  > before drafting. Silently-shipped commits = fileable per L28-E.")
        out.append("")
    return "\n".join(out)


def main():
    parser = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    parser.add_argument("gomod", help="path to go.mod file")
    parser.add_argument("--fork-org", default="dydxprotocol", help="GitHub org of forks to analyze (default: dydxprotocol)")
    parser.add_argument("--clone-root", default=None, help="dir for fork+upstream clones (default: /tmp/gomod-fork-ancestry)")
    parser.add_argument("--skip-clone", action="store_true", help="don't clone if missing; use existing")
    parser.add_argument("--json", action="store_true", help="emit structured JSON")
    parser.add_argument("--strict", action="store_true", help="exit code 2 if any candidates found")
    args = parser.parse_args()

    gomod_path = pathlib.Path(args.gomod).resolve()
    if not gomod_path.is_file():
        sys.stderr.write(f"[gomod-fork-ancestry] not a file: {gomod_path}\n")
        return 1

    clone_root = pathlib.Path(args.clone_root) if args.clone_root else pathlib.Path(tempfile.gettempdir()) / "gomod-fork-ancestry"
    clone_root.mkdir(parents=True, exist_ok=True)

    replaces = parse_gomod(gomod_path)
    forks = [r for r in replaces if is_org_controlled_fork(r, args.fork_org)]

    if not forks:
        msg = f"[gomod-fork-ancestry] no {args.fork_org}-controlled forks in {gomod_path}"
        if args.json:
            print(json.dumps({"schema": "auditooor.gomod_fork_ancestry.v1", "forks": [], "message": msg}))
        else:
            print(msg)
        return 0

    sys.stderr.write(f"[gomod-fork-ancestry] analyzing {len(forks)} fork(s) (clone-root: {clone_root})...\n")
    analyses = []
    for replace in forks:
        analysis = analyze_fork(replace, upstream_url_for, clone_root=clone_root, skip_clone=args.skip_clone)
        analyses.append(analysis)
        sys.stderr.write(f"  - {replace['to']}: {len(analysis.get('candidate_security_commits', []))} candidate(s)\n")

    if args.json:
        print(json.dumps({"schema": "auditooor.gomod_fork_ancestry.v1", "forks": analyses}, indent=2))
    else:
        print(render_markdown(analyses))

    n_candidates = sum(len(a.get("candidate_security_commits", [])) for a in analyses if "error" not in a)
    if args.strict and n_candidates > 0:
        return 2
    return 0


if __name__ == "__main__":
    sys.exit(main())
