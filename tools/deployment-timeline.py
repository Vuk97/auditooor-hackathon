#!/usr/bin/env python3
"""deployment-timeline.py — answer "was commit X live at time T on network N?"

Usage:
  deployment-timeline.py --asset-repo <path> --deployments-dir <path> --commit <sha>
                          [--network <name>] [--print-json]

Outputs auditooor.deployment_timeline.v1 JSON.
"""

import argparse
import json
import os
import re
import subprocess
import sys
from datetime import datetime, timezone


SCHEMA_VERSION = "auditooor.deployment_timeline.v1"

ISO_DATE_PREFIX_RE = re.compile(r"^(\d{4}-\d{2}-\d{2})")


def run_git(asset_repo: str, *args: str) -> str:
    """Run a git command in the asset repo and return stdout.  Raises on failure."""
    result = subprocess.run(
        ["git", "-C", asset_repo] + list(args),
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    if result.returncode != 0:
        raise RuntimeError(
            f"git -C {asset_repo!r} {' '.join(args)!r} failed:\n{result.stderr.strip()}"
        )
    return result.stdout.strip()


def get_repo_head(asset_repo: str) -> str:
    return run_git(asset_repo, "rev-parse", "HEAD")


def get_commit_info(asset_repo: str, commit: str) -> tuple[str, str, str]:
    """Return (resolved_sha, author_date_iso8601, first_line_subject)."""
    raw = run_git(asset_repo, "show", "-s", "--format=%H%n%aI%n%s", commit)
    lines = raw.splitlines()
    if len(lines) < 3:
        raise RuntimeError(f"Unexpected git show output for {commit!r}: {raw!r}")
    sha, author_date, subject = lines[0], lines[1], lines[2]
    return sha, author_date, subject


def get_tags_containing(asset_repo: str, commit: str) -> list[str]:
    raw = run_git(asset_repo, "tag", "--contains", commit)
    if not raw:
        return []
    return [t for t in raw.splitlines() if t]


def parse_iso_date(date_str: str) -> datetime:
    """Parse an ISO 8601 date string to a timezone-aware datetime (UTC)."""
    # Python 3.7+ fromisoformat doesn't handle the 'Z' suffix; normalise first.
    normalised = date_str.replace("Z", "+00:00")
    try:
        return datetime.fromisoformat(normalised)
    except ValueError:
        # Fallback: treat as UTC date only.
        return datetime.strptime(date_str[:10], "%Y-%m-%d").replace(tzinfo=timezone.utc)


def parse_dir_date(dirname: str) -> datetime | None:
    """Extract YYYY-MM-DD prefix from a directory name and return as UTC datetime."""
    m = ISO_DATE_PREFIX_RE.match(dirname)
    if not m:
        return None
    try:
        return datetime.strptime(m.group(1), "%Y-%m-%d").replace(tzinfo=timezone.utc)
    except ValueError:
        return None


def analyse_network(
    deployments_dir: str,
    network: str,
    commit_date: datetime,
) -> dict:
    """Return the per-network analysis block."""
    net_path = os.path.join(deployments_dir, network)
    if not os.path.isdir(net_path):
        return {"error": f"directory not found: {net_path}"}

    entries = []
    for name in sorted(os.listdir(net_path)):
        full = os.path.join(net_path, name)
        if os.path.isdir(full) and ISO_DATE_PREFIX_RE.match(name):
            entries.append(name)

    if not entries:
        return {
            "deployment_directories": [],
            "earliest_dir_date": None,
            "latest_dir_date": None,
            "deployment_at_or_after_commit": None,
            "verdict_contribution": "no_deployments",
        }

    dates = []
    for e in entries:
        d = parse_dir_date(e)
        if d:
            dates.append((e, d))

    if not dates:
        return {
            "deployment_directories": entries,
            "earliest_dir_date": None,
            "latest_dir_date": None,
            "deployment_at_or_after_commit": None,
            "verdict_contribution": "no_parseable_dates",
        }

    earliest = min(dates, key=lambda x: x[1])
    latest = max(dates, key=lambda x: x[1])

    dirs_before = [name for name, d in dates if d < commit_date]
    dirs_after = [name for name, d in dates if d >= commit_date]

    # "deployment_at_or_after_commit": means a deployment OCCURRED after the bug commit,
    # i.e. it COULD have shipped the buggy binary.
    any_after = bool(dirs_after)
    any_before = bool(dirs_before)

    if any_after and not any_before:
        vc = "pre_commit_deployment_exists"  # only post-commit deployments exist
    elif not any_after:
        vc = "post_commit_no_deployment_yet"  # all dirs pre-date the commit
    else:
        vc = "mixed"

    return {
        "deployment_directories": [name for name, _ in dates],
        "earliest_dir_date": earliest[0][:10],
        "latest_dir_date": latest[0][:10],
        "dirs_before_commit": dirs_before,
        "dirs_at_or_after_commit": dirs_after,
        "deployment_at_or_after_commit": any_after,
        "verdict_contribution": vc,
    }


def compute_verdict(networks_info: dict) -> str:
    contribs = [v.get("verdict_contribution") for v in networks_info.values()]
    contribs = [c for c in contribs if c and c not in ("no_deployments", "no_parseable_dates")]
    if not contribs:
        return "no_deployments"
    unique = set(contribs)
    if unique == {"post_commit_no_deployment_yet"}:
        return "post_commit_no_deployment_yet"
    if unique == {"pre_commit_deployment_exists"}:
        return "pre_commit_deployment_exists"
    return "mixed"


def build_report(
    asset_repo: str,
    deployments_dir: str,
    commit: str,
    networks: list[str] | None,
) -> dict:
    head_sha = get_repo_head(asset_repo)
    resolved_sha, author_date, subject = get_commit_info(asset_repo, commit)
    tags = get_tags_containing(asset_repo, resolved_sha)
    commit_date = parse_iso_date(author_date)

    # Determine which network subdirs to analyse.
    if networks:
        network_names = networks
    else:
        network_names = sorted(
            n for n in os.listdir(deployments_dir)
            if os.path.isdir(os.path.join(deployments_dir, n)) and not n.startswith(".")
        )

    networks_info = {}
    for net in network_names:
        info = analyse_network(deployments_dir, net, commit_date)
        info["tags_containing_commit"] = tags
        networks_info[net] = info

    verdict = compute_verdict(networks_info)

    return {
        "schema_version": SCHEMA_VERSION,
        "asset_repo": os.path.abspath(asset_repo),
        "asset_repo_head": head_sha,
        "queried_commit": resolved_sha,
        "queried_commit_short": commit,
        "queried_commit_author_date": author_date,
        "queried_commit_message": subject,
        "networks": networks_info,
        "verdict": verdict,
    }


def print_human(report: dict) -> None:
    print(f"schema  : {report['schema_version']}")
    print(f"commit  : {report['queried_commit'][:12]}  ({report['queried_commit_author_date']})")
    print(f"message : {report['queried_commit_message']}")
    print()
    for net, info in report["networks"].items():
        print(f"  [{net}]")
        if "error" in info:
            print(f"    ERROR: {info['error']}")
            continue
        dirs = info.get("deployment_directories", [])
        print(f"    dirs        : {len(dirs)} total")
        if dirs:
            print(f"    earliest    : {info.get('earliest_dir_date')}")
            print(f"    latest      : {info.get('latest_dir_date')}")
        after = info.get("dirs_at_or_after_commit", [])
        before = info.get("dirs_before_commit", [])
        print(f"    before bug  : {before}")
        print(f"    after  bug  : {after}")
        tags = info.get("tags_containing_commit", [])
        print(f"    tags w/commit: {tags}")
    print()
    print(f"VERDICT : {report['verdict']}")


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Determine if a commit was ever deployed to a live network."
    )
    parser.add_argument("--asset-repo", required=True, help="Path to audit asset git clone")
    parser.add_argument("--deployments-dir", required=True, help="Path to contract-deployments tree")
    parser.add_argument("--commit", required=True, help="Commit SHA or tag to query")
    parser.add_argument("--network", action="append", dest="networks", metavar="NET",
                        help="Network subdir to include (repeat for multiple; default: all)")
    parser.add_argument("--print-json", action="store_true", help="Emit JSON output")
    args = parser.parse_args()

    if not os.path.isdir(args.asset_repo):
        print(f"ERROR: --asset-repo does not exist: {args.asset_repo}", file=sys.stderr)
        sys.exit(1)
    if not os.path.isdir(os.path.join(args.asset_repo, ".git")):
        print(f"ERROR: --asset-repo is not a git repository: {args.asset_repo}", file=sys.stderr)
        sys.exit(1)
    if not os.path.isdir(args.deployments_dir):
        print(f"ERROR: --deployments-dir does not exist: {args.deployments_dir}", file=sys.stderr)
        sys.exit(1)

    report = build_report(
        asset_repo=args.asset_repo,
        deployments_dir=args.deployments_dir,
        commit=args.commit,
        networks=args.networks,
    )

    if args.print_json:
        print(json.dumps(report, indent=2))
    else:
        print_human(report)


if __name__ == "__main__":
    main()
