#!/usr/bin/env python3
"""Run the mandatory non-semantic awareness producers inside canonical Step 0d."""
from __future__ import annotations

import argparse
import importlib.util
import json
import re
import subprocess
import sys
from pathlib import Path
from typing import Any


REPO_ROOT = Path(__file__).resolve().parents[1]
GITHUB_REPO_RE = re.compile(r"(?:https://github\.com/|git@github\.com:)([^/\s]+)/([^/\s]+?)(?:\.git)?$")


class BootstrapError(ValueError):
    pass


def github_repositories(targets: Path) -> list[str]:
    if not targets.is_file():
        raise BootstrapError("step_0d_targets_missing")
    repositories: set[str] = set()
    for raw in targets.read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        fields = line.split("\t")
        if len(fields) < 2:
            raise BootstrapError("step_0d_targets_malformed")
        match = GITHUB_REPO_RE.match(fields[0].strip())
        if not match:
            raise BootstrapError("step_0d_target_not_github")
        repositories.add(f"{match.group(1)}/{match.group(2)}")
    if not repositories:
        raise BootstrapError("step_0d_targets_empty")
    return sorted(repositories)


def _source_comment_scan(workspace: Path) -> None:
    path = REPO_ROOT / "tools" / "acknowledged-wont-fix-check.py"
    spec = importlib.util.spec_from_file_location("step_0d_source_comment_scan", path)
    if spec is None or spec.loader is None:
        raise BootstrapError("source_comment_scanner_unavailable")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    # Pending semantic review is expected here; the semantic ledger gate enforces
    # that review later in the same step.
    module.scan_workspace_source_comments(workspace)


def _run(command: list[str]) -> None:
    result = subprocess.run(command, cwd=REPO_ROOT, text=True, capture_output=True, check=False)
    if result.returncode:
        raise BootstrapError(f"step_0d_awareness_producer_failed:{Path(command[1]).name}:{result.stderr.strip() or result.stdout.strip()}")


def _commit_history(workspace: Path, audit_pin: str, repositories: list[str]) -> list[Path]:
    """Materialize the commit-history input required by awareness discovery.

    Discovery intentionally refuses to infer commit coverage from a missing report.
    Step 0d therefore owns the existing bidirectional GitHub miner, just as it owns
    the GitHub issue/PR snapshot.  The miner is a source enumerator only: semantic
    review and awareness disposition remain downstream responsibilities.
    """
    audit_dir = workspace / ".auditooor"
    local_repo = workspace / "src"
    reports: list[Path] = []
    for repository in repositories:
        output = audit_dir / f"git_commits_mining_{repository.replace('/', '_')}.json"
        command = [
            sys.executable,
            str(REPO_ROOT / "tools" / "git-commits-mining.py"),
            "--workspace",
            workspace.name,
            "--upstream",
            repository,
            "--audit-pin",
            audit_pin,
            "--mode",
            "bidirectional",
            "--out",
            str(output),
        ]
        if local_repo.is_dir() and not local_repo.is_symlink():
            command.extend(["--local-repo", str(local_repo)])
        _run(command)
        reports.append(output)
    return reports


def run(workspace: Path, audit_pin: str) -> dict[str, Any]:
    repositories = github_repositories(workspace / "targets.tsv")
    _source_comment_scan(workspace)
    audit_dir = workspace / ".auditooor"
    audit_dir.mkdir(parents=True, exist_ok=True)
    commit_reports = _commit_history(workspace, audit_pin, repositories)
    histories: list[Path] = []
    for repo in repositories:
        output = audit_dir / f"github_awareness_history_{repo.replace('/', '_')}.json"
        _run([sys.executable, str(REPO_ROOT / "tools" / "github-awareness-history.py"), "--repo", repo, "--audit-pin", audit_pin, "--output", str(output)])
        histories.append(output)
    command = [sys.executable, str(REPO_ROOT / "tools" / "awareness-source-discovery.py"), "--workspace", str(workspace), "--audit-pin", audit_pin]
    for path in histories:
        command.extend(["--github-history", str(path)])
    _run(command)
    return {
        "schema": "auditooor.step_0d_awareness_bootstrap.v1",
        "repositories": repositories,
        "audit_pin": audit_pin,
        "commit_reports": [str(path) for path in commit_reports],
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--workspace", required=True, type=Path)
    parser.add_argument("--audit-pin", required=True)
    args = parser.parse_args()
    try:
        print(json.dumps({"ok": True, **run(args.workspace.expanduser().resolve(), args.audit_pin)}, sort_keys=True))
    except (BootstrapError, OSError) as exc:
        print(json.dumps({"ok": False, "error": str(exc)}, sort_keys=True), file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
