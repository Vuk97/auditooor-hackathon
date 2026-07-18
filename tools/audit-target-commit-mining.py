#!/usr/bin/env python3
"""Run bidirectional commit mining for every pinned target in a workspace.

This is the audit-flow wrapper around tools/git-commits-mining.py.  It keeps the
"did we mine GitHub around the audit pin?" evidence workspace-local and
deterministic: each target writes one JSON report plus a manifest under
<workspace>/mining_rounds/<date>-bidirectional-commit-mining/.
"""

from __future__ import annotations

import argparse
import datetime as dt
import json
import re
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any


REPO_ROOT = Path(__file__).resolve().parents[1]
MINER = REPO_ROOT / "tools" / "git-commits-mining.py"
READONLY_GIT = "/usr/bin/git"
PIN_RE = re.compile(r"^[0-9a-fA-F]{40}$")
LOCAL_TARGET_PREFIXES = {
    ".",
    "..",
    "audit",
    "app",
    "apps",
    "contracts",
    "contracts-v2",
    "crates",
    "external",
    "lib",
    "module",
    "modules",
    "packages",
    "pallet",
    "pallets",
    "protocol",
    "runtime",
    "src",
    "vendor",
}
FLATTENED_SNAPSHOT_THRESHOLD = 30
FLATTENED_SNAPSHOT_STRATEGY = "flattened-snapshot-prior-audit-pivot"
FLATTENED_SNAPSHOT_STATUS = "flattened_snapshot_prior_audit_pivot"
ORDINARY_TIER6_STRATEGY = "tier6-bidirectional-commit-mining"
PRIOR_AUDIT_SHA_RE = re.compile(r"(?<![0-9A-Fa-f])[0-9A-Fa-f]{7,40}(?![0-9A-Fa-f])")


@dataclass(frozen=True)
class Target:
    repo_url: str
    pin: str
    local_name: str

    @property
    def owner_repo(self) -> str:
        return repo_url_to_owner_repo(self.repo_url)


def repo_url_to_owner_repo(repo_url: str) -> str:
    value = repo_url.strip()
    if "@" in value and not value.startswith("git@"):
        maybe_repo, maybe_ref = value.rsplit("@", 1)
        if maybe_ref.strip():
            value = maybe_repo
    value = value.removesuffix(".git")
    if value.startswith("git@github.com:"):
        value = value.split(":", 1)[1]
    elif "github.com/" in value:
        value = value.split("github.com/", 1)[1]
    value = value.split("?", 1)[0].split("#", 1)[0].strip("/")
    parts = value.split("/")
    if len(parts) < 2 or not parts[0] or not parts[1]:
        raise ValueError(f"not a GitHub owner/repo URL: {repo_url!r}")
    return f"{parts[0]}/{parts[1]}"


def _split_inline_pin(value: str) -> tuple[str, str]:
    if "@" not in value or value.startswith("git@"):
        return value, ""
    repo, ref = value.rsplit("@", 1)
    if ref.strip():
        return repo, ref.strip()
    return value, ""


def _looks_github_target(value: str, pin: str = "") -> bool:
    text = value.strip().lower()
    if "github.com" in text or text.startswith("git@github.com:"):
        return True
    if text.startswith(("/", "./", "../")):
        return False
    parts = text.strip("/").split("/")
    return len(parts) == 2 and parts[0] not in LOCAL_TARGET_PREFIXES


def _scope_target_value(row: dict[str, Any]) -> str:
    for key in (
        "repo_url",
        "github_url",
        "url",
        "repo",
        "target_repo",
        "owner_repo",
        "target",
        "name",
    ):
        value = row.get(key)
        if isinstance(value, str) and value.strip():
            return value.strip()
    return ""


def _scope_target_pin(row: dict[str, Any], global_pin: str = "") -> str:
    for key in ("audit_pin_sha", "pin", "commit", "sha", "ref", "pinned_commit", "commit_sha", "audit_pin"):
        value = row.get(key)
        if isinstance(value, str) and value.strip():
            return value.strip()
    return global_pin


def _target_from_value(value: str, pin: str, local_name: str = "") -> Target | None:
    repo_url, inline_pin = _split_inline_pin(value)
    if inline_pin and (not pin or PIN_RE.fullmatch(inline_pin)):
        pin = inline_pin
    if not repo_url or not pin or not _looks_github_target(repo_url, pin):
        return None
    local_name = local_name.strip()
    if not repo_url or not pin:
        return None
    if not local_name:
        try:
            local_name = repo_url_to_owner_repo(repo_url).split("/", 1)[1]
        except ValueError:
            return None
    try:
        repo_url_to_owner_repo(repo_url)
    except ValueError:
        return None
    return Target(repo_url=repo_url, pin=pin, local_name=local_name)


def _target_from_dict(row: dict[str, Any], global_pin: str = "") -> Target | None:
    repo_url = _scope_target_value(row)
    pin = _scope_target_pin(row, global_pin)
    local_name = str(row.get("local_name") or row.get("name") or "").strip()
    return _target_from_value(repo_url, pin, local_name)


def load_targets_tsv(workspace: Path) -> list[Target]:
    targets: list[Target] = []
    seen: set[tuple[str, str]] = set()
    tsv_path = workspace / "targets.tsv"
    if not tsv_path.exists():
        return targets
    for raw in tsv_path.read_text(encoding="utf-8", errors="replace").splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        cols = [c.strip() for c in raw.split("\t")]
        repo_url = cols[0]
        raw_repo_url, inline_pin = _split_inline_pin(repo_url)
        repo_url = raw_repo_url
        pin = inline_pin or (cols[1] if len(cols) >= 2 else "")
        local_name = cols[2] if len(cols) >= 3 and cols[2].strip() else ""
        try:
            target = Target(
                repo_url=repo_url,
                pin=pin,
                local_name=local_name or repo_url_to_owner_repo(repo_url).split("/", 1)[1],
            )
            # owner_repo is a property that re-parses repo_url and can raise on a
            # malformed/header/non-GitHub row (construction may NOT raise when a
            # local_name was supplied, so the row reaches here). Compute the key
            # INSIDE the try so such a row is SKIPPED, never crashing the whole
            # `make audit` at the commit-mining preflight (a stray header line like
            # "repo<TAB>url<TAB>pinned_commit" must not abort the audit).
            key = (target.owner_repo, target.pin)
        except ValueError:
            continue
        if key not in seen:
            seen.add(key)
            targets.append(target)
    return targets


def load_targets(workspace: Path) -> list[Target]:
    targets: list[Target] = []
    seen: set[tuple[str, str]] = set()

    scope_path = workspace / "scope.json"
    if scope_path.exists():
        try:
            payload = json.loads(scope_path.read_text(encoding="utf-8"))
        except json.JSONDecodeError:
            payload = {}
        if isinstance(payload, dict):
            global_pin = _scope_target_pin(payload, "")
            rows_before = len(targets)
            for key_name in ("target_repos", "targets", "repositories", "repos", "github_targets"):
                entries = payload.get(key_name)
                if not isinstance(entries, list):
                    continue
                for row in entries:
                    if isinstance(row, dict):
                        target = _target_from_dict(row, global_pin)
                    elif isinstance(row, str):
                        target = _target_from_value(row.strip(), global_pin)
                    else:
                        continue
                    if target:
                        key = (target.owner_repo, target.pin)
                        if key not in seen:
                            seen.add(key)
                            targets.append(target)
            if len(targets) == rows_before:
                target = _target_from_dict(payload, global_pin)
                if target:
                    key = (target.owner_repo, target.pin)
                    if key not in seen:
                        seen.add(key)
                        targets.append(target)

    for target in load_targets_tsv(workspace):
        key = (target.owner_repo, target.pin)
        if key not in seen:
            seen.add(key)
            targets.append(target)

    return targets


def targets_tsv_preflight(workspace: Path) -> tuple[bool, str]:
    tsv_path = workspace / "targets.tsv"
    if not tsv_path.is_file():
        return (
            False,
            "targets.tsv missing; populate it with at least one in-scope "
            "GitHub repo row before running audit-target-commit-mining",
        )
    if not load_targets_tsv(workspace):
        return (
            False,
            "targets.tsv is empty or contains no mineable GitHub repo rows; "
            "expected repo_url, pinned_commit, local_name",
        )
    return True, "ok"


def stale_empty_manifest(path: Path) -> bool:
    if not path.is_file():
        return False
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return False
    if not isinstance(payload, dict):
        return False
    rows = payload.get("rows")
    summary = payload.get("summary")
    return (
        payload.get("schema") == "auditooor.audit_target_commit_mining_manifest.v1"
        and isinstance(rows, list)
        and len(rows) == 0
        and int(payload.get("targets_seen") or 0) == 0
        and isinstance(summary, dict)
        and int(summary.get("ran") or 0) == 0
    )


def _git_toplevel(repo_dir: Path) -> Path | None:
    if not repo_dir.is_dir():
        return None
    try:
        proc = subprocess.run(
            [READONLY_GIT, "-C", str(repo_dir), "rev-parse", "--show-toplevel"],
            text=True,
            capture_output=True,
            check=False,
        )
    except OSError:
        return None
    if proc.returncode != 0:
        return None
    value = proc.stdout.strip()
    return Path(value).resolve() if value else None


def _git_origin_owner_repo(repo_dir: Path) -> str | None:
    if not repo_dir.is_dir():
        return None
    try:
        proc = subprocess.run(
            [READONLY_GIT, "-C", str(repo_dir), "config", "--get", "remote.origin.url"],
            text=True,
            capture_output=True,
            check=False,
        )
    except OSError:
        return None
    if proc.returncode != 0:
        return None
    raw = proc.stdout.strip()
    if not raw:
        return None
    try:
        return repo_url_to_owner_repo(raw)
    except ValueError:
        return None


def inscope_owner_repos(workspace: Path) -> dict[str, dict[str, Any]]:
    """Resolve every scope.json ``in_scope`` source root to its upstream owner/repo.

    PROBLEM (gapA-multirepo-mining): the mine-set is derived ONLY from
    ``targets.tsv`` rows and scope.json target_repos/targets/... keys. It never
    reconciles against the scope.json ``in_scope`` SOURCE ROOTS, so a workspace
    whose in_scope roots span genuinely separate git checkouts silently mines
    only the targets.tsv subset.

    For each in_scope root: resolve the abs path, walk up to its enclosing git
    toplevel, resolve that toplevel's origin owner/repo. Roots that cannot
    resolve to an owner/repo go into ``unresolved_roots`` with a concrete reason
    (NO SILENT CAP). Reuses the file's existing ``_git_toplevel`` /
    ``_git_origin_owner_repo`` helpers - no new git plumbing.

    Returns a dict::

        {
          "owner_repos": {ow/repo: {roots:[...], toplevel:str, resolved:True}},
          "unresolved_roots": [{root:str, reason:str}],
        }
    """
    result: dict[str, Any] = {"owner_repos": {}, "unresolved_roots": []}
    owner_repos: dict[str, dict[str, Any]] = result["owner_repos"]
    unresolved: list[dict[str, str]] = result["unresolved_roots"]

    scope_path = workspace / "scope.json"
    if not scope_path.is_file():
        return result
    try:
        payload = json.loads(scope_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return result
    if not isinstance(payload, dict):
        return result
    in_scope = payload.get("in_scope")
    if not isinstance(in_scope, list):
        return result

    for raw_root in in_scope:
        if not isinstance(raw_root, str) or not raw_root.strip():
            continue
        rel = raw_root.strip()
        abs_root = (workspace / rel).resolve()
        if not abs_root.exists():
            unresolved.append({"root": rel, "reason": "in_scope root path does not exist"})
            continue
        # Walk up to the enclosing git toplevel (the root itself need not be the
        # toplevel - in_scope roots are typically deep source dirs).
        top = _git_toplevel(abs_root if abs_root.is_dir() else abs_root.parent)
        if top is None:
            unresolved.append({"root": rel, "reason": "no git toplevel"})
            continue
        owner_repo = _git_origin_owner_repo(top)
        if owner_repo is None:
            unresolved.append(
                {"root": rel, "reason": "no origin remote / origin not a GitHub owner/repo URL"}
            )
            continue
        entry = owner_repos.setdefault(
            owner_repo, {"roots": [], "toplevel": str(top), "resolved": True}
        )
        if rel not in entry["roots"]:
            entry["roots"].append(rel)
    return result


def reconcile_targets_with_inscope(
    workspace: Path, targets: list[Target] | None = None
) -> dict[str, Any]:
    """Union the target mine-set with the in-scope-derived owner/repos.

    Returns a dict with::

        required_owner_repos : set  (target ∪ in_scope-derived)
        target_owner_repos   : set  (from load_targets())
        inscope_owner_repos  : set  (resolved from scope.json in_scope)
        missing_from_targets : set  (in_scope-derived NOT in the target set)
        unresolved_roots     : list[dict]

    ``missing_from_targets`` is the silent-skip bug surface: in-scope source
    roots that map to an upstream owner/repo the driver would never mine.
    """
    if targets is None:
        targets = load_targets(workspace)
    target_set: set[str] = set()
    for tgt in targets:
        try:
            target_set.add(tgt.owner_repo)
        except ValueError:
            continue
    resolved = inscope_owner_repos(workspace)
    inscope_set: set[str] = set(resolved["owner_repos"].keys())
    missing = inscope_set - target_set
    required = target_set | inscope_set
    return {
        "required_owner_repos": required,
        "target_owner_repos": target_set,
        "inscope_owner_repos": inscope_set,
        "missing_from_targets": missing,
        "unresolved_roots": list(resolved["unresolved_roots"]),
        "_inscope_detail": resolved["owner_repos"],
    }


def synthesize_missing_targets(
    workspace: Path, targets: list[Target], reconcile: dict[str, Any], global_pin: str
) -> list[Target]:
    """Append a synthetic Target for every owner/repo in ``missing_from_targets``.

    Closes the silent-skip at mine time: an in-scope source root whose upstream
    owner/repo is absent from the target mine-set gets a synthesized Target
    (repo_url=https://github.com/<owner_repo>, pin=global scope pin, local_name
    from the in_scope root basename) so run_miner mines it too. Additive: when
    ``missing_from_targets`` is empty the input list is returned unchanged
    (back-compat with single-repo workspaces).
    """
    out = list(targets)
    have = set()
    for tgt in out:
        try:
            have.add(tgt.owner_repo)
        except ValueError:
            continue
    detail = reconcile.get("_inscope_detail", {})
    for owner_repo in sorted(reconcile.get("missing_from_targets") or []):
        if owner_repo in have:
            continue
        roots = (detail.get(owner_repo) or {}).get("roots") or []
        local_name = ""
        if roots:
            local_name = Path(str(roots[0])).name
        if not local_name:
            local_name = owner_repo.split("/", 1)[-1]
        synth = _target_from_value(
            f"https://github.com/{owner_repo}", global_pin, local_name
        )
        if synth is not None:
            out.append(synth)
            have.add(owner_repo)
    return out


def resolve_target_repo_dir(workspace: Path, target: Target) -> Path:
    default = workspace / "src" / target.local_name
    if default.is_dir():
        return default
    expected_owner_repo = target.owner_repo
    for candidate in (workspace / "src", workspace):
        top = _git_toplevel(candidate)
        if top is None:
            continue
        try:
            if top != candidate.resolve():
                continue
        except OSError:
            continue
        if _git_origin_owner_repo(candidate) == expected_owner_repo:
            return candidate
    src_dir = workspace / "src"
    if src_dir.is_dir():
        try:
            children = sorted(p for p in src_dir.iterdir() if p.is_dir())
        except OSError:
            children = []
        for child in children:
            top = _git_toplevel(child)
            if top is None:
                continue
            try:
                if top != child.resolve():
                    continue
            except OSError:
                continue
            if _git_origin_owner_repo(child) == expected_owner_repo:
                return child
    return default


def local_git_commit_count(repo_dir: Path) -> int | None:
    """Return commit count only when repo_dir is itself a git checkout."""
    top = _git_toplevel(repo_dir)
    if top is None:
        return None
    try:
        if top != repo_dir.resolve():
            return None
    except OSError:
        return None
    try:
        proc = subprocess.run(
            [READONLY_GIT, "-C", str(repo_dir), "rev-list", "--count", "HEAD"],
            text=True,
            capture_output=True,
            check=False,
        )
    except OSError:
        return None
    if proc.returncode != 0:
        return None
    try:
        return int(proc.stdout.strip())
    except ValueError:
        return None


def _pivot_recommendation(commit_count: int) -> str:
    return (
        f"Local git history has only {commit_count} commits, which is below "
        f"the {FLATTENED_SNAPSHOT_THRESHOLD} commit flattened-snapshot threshold. "
        "Do not treat ordinary Tier-6 bidirectional history mining as complete. "
        "Pivot to prior-audit SHA extraction, symptom-only fix enumeration, "
        "rejected recommendation tracking, fix-confirmation gap checks, and "
        "L30 sibling callsite enumeration."
    )


def _ordinary_recommendation(commit_count: int | None) -> str:
    if commit_count is None:
        return (
            "Local git history was not available for this target. Run ordinary "
            "Tier-6 mining through the configured upstream and verify the local "
            "clone before relying on backward-window coverage."
        )
    return "Local git history is sufficient for ordinary Tier-6 bidirectional commit mining."


def infer_languages(repo_dir: Path) -> list[str]:
    langs: list[str] = []
    if (repo_dir / "Cargo.toml").exists() or any(repo_dir.rglob("*.rs")):
        langs.append("rust")
    if (repo_dir / "foundry.toml").exists() or (repo_dir / "hardhat.config.js").exists():
        langs.append("solidity")
    if any((repo_dir / "src").rglob("*.sol")) if (repo_dir / "src").exists() else False:
        langs.append("solidity")
    if any(repo_dir.rglob("*.sol")):
        langs.append("solidity")
    if (repo_dir / "go.mod").exists() or any(repo_dir.rglob("*.go")):
        langs.append("go")
    seen: set[str] = set()
    out = [lang for lang in langs if not (lang in seen or seen.add(lang))]
    return out or ["go"]


def infer_language(repo_dir: Path) -> str:
    """Backward-compatible single-language helper used by older tests."""
    langs = infer_languages(repo_dir)
    if "solidity" in langs and "rust" in langs and (repo_dir / "foundry.toml").exists() and not (repo_dir / "Cargo.toml").exists():
        return "solidity"
    return langs[0]


def safe_slug(owner_repo: str) -> str:
    return re.sub(r"[^A-Za-z0-9._-]+", "_", owner_repo.replace("/", "_")).strip("_")


def build_rows(
    workspace: Path,
    out_dir: Path,
    targets: list[Target],
    window: int,
    force: bool,
) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for target in targets:
        owner_repo = target.owner_repo
        repo_dir = resolve_target_repo_dir(workspace, target)
        languages = infer_languages(repo_dir) if repo_dir.exists() else ["go"]
        commit_count = local_git_commit_count(repo_dir)
        if commit_count is not None and commit_count < FLATTENED_SNAPSHOT_THRESHOLD:
            strategy = FLATTENED_SNAPSHOT_STRATEGY
            recommendation = _pivot_recommendation(commit_count)
        else:
            strategy = ORDINARY_TIER6_STRATEGY
            recommendation = _ordinary_recommendation(commit_count)
        for lang in languages:
            out_path = out_dir / f"{safe_slug(owner_repo)}_{lang}_git_commits_mining.json"
            rows.append({
                "repo_url": target.repo_url,
                "owner_repo": owner_repo,
                "pin": target.pin,
                "local_name": target.local_name,
                "repo_dir": str(repo_dir),
                "language": lang,
                "output_path": str(out_path),
                "exists": out_path.exists(),
                "commit_count": commit_count,
                "flattened_snapshot_threshold": FLATTENED_SNAPSHOT_THRESHOLD,
                "strategy": strategy,
                "recommendation": recommendation,
                # A low local commit count changes the recommendation, not the
                # authenticated remote work obligation. Real runs must still
                # attempt the GitHub mine so issue/PR discussions can be read.
                "will_run": force or not out_path.exists(),
            })
    return rows


def _group_strategy_rows(rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    grouped: dict[tuple[str, str, str], dict[str, Any]] = {}
    for row in rows:
        key = (
            str(row.get("owner_repo") or ""),
            str(row.get("local_name") or ""),
            str(row.get("repo_dir") or ""),
        )
        if key not in grouped:
            grouped[key] = {
                "owner_repo": key[0],
                "local_name": key[1],
                "repo_dir": key[2],
                "pin": str(row.get("pin") or ""),
                "commit_count": row.get("commit_count"),
                "flattened_snapshot_threshold": FLATTENED_SNAPSHOT_THRESHOLD,
                "strategy": str(row.get("strategy") or ORDINARY_TIER6_STRATEGY),
                "recommendation": str(row.get("recommendation") or ""),
                "languages": [],
            }
        language = str(row.get("language") or "")
        if language and language not in grouped[key]["languages"]:
            grouped[key]["languages"].append(language)
    return list(grouped.values())


def write_repo_strategy(workspace: Path, rows: list[dict[str, Any]]) -> dict[str, Any]:
    targets = _group_strategy_rows(rows)
    flattened = [row for row in targets if row.get("strategy") == FLATTENED_SNAPSHOT_STRATEGY]
    primary = flattened[0] if flattened else (targets[0] if targets else {})
    if flattened:
        strategy = FLATTENED_SNAPSHOT_STRATEGY
        recommendation = str(flattened[0].get("recommendation") or "")
    else:
        strategy = ORDINARY_TIER6_STRATEGY
        recommendation = str(primary.get("recommendation") or "")
    payload = {
        "schema": "auditooor.repo_strategy.v1",
        "generated_at_utc": dt.datetime.now(dt.UTC).replace(microsecond=0).isoformat(),
        "workspace": str(workspace),
        "strategy": strategy,
        "owner_repo": str(primary.get("owner_repo") or ""),
        "local_name": str(primary.get("local_name") or ""),
        "commit_count": primary.get("commit_count"),
        "flattened_snapshot_threshold": FLATTENED_SNAPSHOT_THRESHOLD,
        "recommendation": recommendation,
        "targets": targets,
        "summary": {
            "targets_seen": len(targets),
            "flattened_snapshot_targets": len(flattened),
        },
    }
    out_path = workspace / ".auditooor" / "repo_strategy.json"
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return payload


def _sha_like_token(value: str) -> bool:
    return any("a" <= ch.lower() <= "f" for ch in value)


def extract_prior_audit_fix_rows(workspace: Path) -> tuple[list[dict[str, Any]], int]:
    prior_dir = workspace / "prior_audits"
    if not prior_dir.is_dir():
        return [], 0
    rows: list[dict[str, Any]] = []
    audit_files = sorted(path for path in prior_dir.glob("*.txt") if path.is_file())
    seen: set[tuple[str, int, str]] = set()
    for path in audit_files:
        try:
            lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
        except OSError:
            continue
        rel_path = _workspace_rel_str(path, workspace)
        for idx, line in enumerate(lines):
            line_no = idx + 1
            for match in PRIOR_AUDIT_SHA_RE.finditer(line):
                token = match.group(0)
                if not _sha_like_token(token):
                    continue
                key = (rel_path, line_no, token.lower())
                if key in seen:
                    continue
                seen.add(key)
                context_start = max(0, idx - 1)
                context_end = min(len(lines), idx + 2)
                context = " ".join(lines[context_start:context_end])
                context = re.sub(r"\s+", " ", context).strip()[:600]
                rows.append(
                    {
                        "audit": path.stem,
                        "audit_path": rel_path,
                        "line": line_no,
                        "fix_sha": token.lower(),
                        "context": context,
                        "classification": "prior-audit-sha-reference",
                        "sibling_check_recommendation": (
                            "Use this prior-audit SHA reference as a proxy Tier-6 "
                            "candidate; inspect the cited finding, confirm the fix "
                            "at audit pin, and run L30 sibling callsite enumeration."
                        ),
                    }
                )
    return rows, len(audit_files)


def write_prior_audit_fix_index(workspace: Path) -> dict[str, Any]:
    rows, audit_file_count = extract_prior_audit_fix_rows(workspace)
    payload = {
        "schema": "auditooor.prior_audit_fix_index.v1",
        "generated_at_utc": dt.datetime.now(dt.UTC).replace(microsecond=0).isoformat(),
        "workspace": str(workspace),
        "source_glob": "prior_audits/*.txt",
        "rows": rows,
        "summary": {
            "audit_files": audit_file_count,
            "sha_references": len(rows),
        },
    }
    out_path = workspace / ".auditooor" / "prior_audit_fix_index.json"
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return payload


def write_manifest(out_dir: Path, manifest: dict[str, Any]) -> None:
    out_dir.mkdir(parents=True, exist_ok=True)
    json_path = out_dir / "commit_mining_manifest.json"
    md_path = out_dir / "commit_mining_manifest.md"
    json_path.write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8")

    lines = [
        "# Target Commit Mining Manifest",
        "",
        f"Workspace: `{manifest['workspace']}`",
        f"Generated: `{manifest['generated_at_utc']}`",
        f"Mode: `{manifest['mode']}`",
        f"Window: `{manifest['window']}`",
        f"Rows: `{len(manifest['rows'])}`",
        "",
        "| Target | Pin | Lang | Status | Output |",
        "|---|---|---|---|---|",
    ]
    for row in manifest["rows"]:
        lines.append(
            "| `{owner_repo}` | `{pin}` | `{language}` | `{status}` | `{output}` |".format(
                owner_repo=row["owner_repo"],
                pin=str(row["pin"])[:12],
                language=row["language"],
                status=row["status"],
                output=Path(row["output_path"]).name,
            )
        )
    md_path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def _load_report_summary(path: Path) -> dict[str, Any]:
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {}
    if not isinstance(payload, dict):
        return {}
    shaped = payload.get("shaped_commits_index")
    if not isinstance(shaped, list):
        shaped = []
    return {
        "audit_pin_sha": str(payload.get("audit_pin_sha") or ""),
        "generated_at": str(payload.get("generated_at") or ""),
        "commits_scanned": int(payload.get("commits_scanned") or 0),
        "security_fix_count": int(payload.get("security_fix_count") or 0),
        "shaped_commits": [
            {
                "sha": str(row.get("sha") or "")[:80],
                "subject": str(row.get("subject") or "")[:240],
                "date": str(row.get("date") or "")[:80],
            }
            for row in shaped[:20]
            if isinstance(row, dict)
        ],
    }


def _git_head(repo_dir: Path) -> str:
    if not repo_dir.is_dir():
        return ""
    try:
        proc = subprocess.run(
            [READONLY_GIT, "-C", str(repo_dir), "rev-parse", "HEAD"],
            text=True,
            capture_output=True,
            check=False,
        )
    except OSError:
        return ""
    return proc.stdout.strip() if proc.returncode == 0 else ""


def _workspace_rel_str(path: Path, workspace: Path) -> str:
    try:
        return str(path.resolve().relative_to(workspace.resolve()))
    except (OSError, ValueError):
        return str(path)


def write_commit_lifecycle_ledger(workspace: Path, manifest: dict[str, Any]) -> None:
    """Write the MCP-readable workspace commit-mining ledger.

    Older recall tooling reads ``.auditooor/commit_lifecycle_ledger.json`` before
    looking at narrative closeouts.  Keep that contract current so every audit
    session can verify target commit mining without knowing the newest manifest
    filename.
    """
    target_rows: list[dict[str, Any]] = []
    lanes_residual: list[dict[str, str]] = []
    generated_at = str(manifest.get("generated_at_utc") or "")
    audit_pins: list[str] = []
    head_shas: list[str] = []
    total_scanned = 0
    total_security_shaped = 0

    for row in manifest.get("rows", []):
        if not isinstance(row, dict):
            continue
        output_path = Path(str(row.get("output_path") or ""))
        summary = _load_report_summary(output_path) if output_path.is_file() else {}
        repo_dir = Path(str(row.get("repo_dir") or ""))
        head_sha = _git_head(repo_dir)
        pin = str(row.get("pin") or summary.get("audit_pin_sha") or "")
        if pin and pin not in audit_pins:
            audit_pins.append(pin)
        if head_sha and head_sha not in head_shas:
            head_shas.append(head_sha)

        commits_scanned = int(summary.get("commits_scanned") or 0)
        security_fix_count = int(summary.get("security_fix_count") or 0)
        total_scanned += commits_scanned
        total_security_shaped += security_fix_count
        report_generated_at = str(summary.get("generated_at") or "")
        if report_generated_at > generated_at:
            generated_at = report_generated_at

        target_rows.append(
            {
                "owner_repo": str(row.get("owner_repo") or "")[:120],
                "language": str(row.get("language") or "")[:40],
                "pin": pin[:80],
                "head_sha": head_sha[:80],
                "status": str(row.get("status") or "")[:40],
                "commit_count": row.get("commit_count"),
                "strategy": str(row.get("strategy") or "")[:80],
                "commits_scanned": commits_scanned,
                "security_fix_count": security_fix_count,
                "output_path": _workspace_rel_str(output_path, workspace)
                if output_path.exists()
                else str(row.get("output_path") or ""),
            }
        )
        for shaped in summary.get("shaped_commits") or []:
            if not isinstance(shaped, dict):
                continue
            lanes_residual.append(
                {
                    "sha": str(shaped.get("sha") or "")[:80],
                    "classification": "security_shaped_commit",
                    "hint": f"{row.get('owner_repo')} {row.get('language')}: {shaped.get('subject', '')}"[:240],
                }
            )

    ledger = {
        "schema": "auditooor.commit_lifecycle_ledger.v1",
        "audit_pin_sha": ",".join(audit_pins)[:240],
        "head_sha": ",".join(head_shas)[:240],
        "last_mined_at": generated_at[:80],
        "forward_window": {"count": total_scanned},
        "backward_window": {
            "count": int(manifest.get("window") or 0) * len(target_rows)
            if str(manifest.get("mode") or "") == "bidirectional"
            else 0
        },
        "lanes_triaged": [],
        "lanes_residual": lanes_residual[:200],
        "target_rows": target_rows,
        "manifest_path": "mining_rounds",
        "source_artifacts": [
            _workspace_rel_str(Path(str(row["output_path"])), workspace)
            for row in manifest.get("rows", [])
            if isinstance(row, dict)
            and row.get("output_path")
            and Path(str(row["output_path"])).is_file()
        ][:100],
        "summary": {
            "targets_seen": int(manifest.get("targets_seen") or 0),
            "rows": len(target_rows),
            "commits_scanned": total_scanned,
            "security_fix_count": total_security_shaped,
            "failed": int((manifest.get("summary") or {}).get("failed") or 0),
            "flattened_snapshot_prior_audit_pivot": int(
                (manifest.get("summary") or {}).get("flattened_snapshot_prior_audit_pivot") or 0
            ),
        },
    }
    out_path = workspace / ".auditooor" / "commit_lifecycle_ledger.json"
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps(ledger, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def validate_github_history(workspace: Path) -> tuple[int, dict[str, Any]]:
    """Require issue/PR discussion reconciliation for each GitHub target.

    A local commit mine or flattened-snapshot pivot is useful substrate, but it
    does not reconcile GitHub issues, PR state, reviews, or comments. Missing
    discussion metadata is therefore blocking for an applicable GitHub target.
    An available API with zero matching records is valid and is recorded as an
    explicit empty result rather than silently treated as not applicable.
    """
    targets = load_targets_tsv(workspace)
    if not targets:
        return 0, {
            "schema": "auditooor.github_history_reconciliation.v1",
            "workspace": str(workspace),
            "verdict": "pass-not-applicable",
            "targets": 0,
            "rows_checked": 0,
            "blocking": [],
        }

    manifests = sorted(
        (workspace / "mining_rounds").glob("*/commit_mining_manifest.json"),
        key=lambda p: p.stat().st_mtime,
    )
    manifest = None
    if manifests:
        try:
            parsed = json.loads(manifests[-1].read_text(encoding="utf-8"))
            manifest = parsed if isinstance(parsed, dict) else None
        except (OSError, json.JSONDecodeError):
            manifest = None
    rows = manifest.get("rows", []) if isinstance(manifest, dict) else []
    rows_by_repo: dict[str, list[dict[str, Any]]] = {}
    for row in rows:
        if isinstance(row, dict):
            rows_by_repo.setdefault(str(row.get("owner_repo") or ""), []).append(row)

    blocking: list[dict[str, Any]] = []
    analysis_path = workspace / ".auditooor" / "github_history_analysis.json"
    try:
        analysis_payload = json.loads(analysis_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        analysis_payload = {}
    analysis_rows = analysis_payload.get("targets", []) if isinstance(analysis_payload, dict) else []
    analysis_by_repo = {
        str(row.get("owner_repo")): row
        for row in analysis_rows
        if isinstance(row, dict) and row.get("owner_repo")
    }
    review_queue: list[dict[str, Any]] = []
    checked = 0
    for target in targets:
        owner_repo = target.owner_repo
        candidates = rows_by_repo.get(owner_repo, [])
        if not candidates:
            blocking.append({"owner_repo": owner_repo, "reason": "missing-manifest-row"})
            continue
        for row in candidates:
            checked += 1
            output_path = Path(str(row.get("output_path") or ""))
            if not output_path.is_absolute():
                output_path = workspace / output_path
            if row.get("status") == FLATTENED_SNAPSHOT_STATUS or not output_path.is_file():
                blocking.append({
                    "owner_repo": owner_repo,
                    "reason": "commit-mine-without-github-discussion-report",
                    "status": row.get("status"),
                })
                continue
            try:
                report = json.loads(output_path.read_text(encoding="utf-8"))
            except (OSError, json.JSONDecodeError):
                report = None
            metadata = report.get("discussion_metadata") if isinstance(report, dict) else None
            if isinstance(report, dict):
                review_queue.append({
                    "review_id": f"{owner_repo}:{output_path.name}",
                    "owner_repo": owner_repo,
                    "report_path": str(output_path),
                    "report": report,
                    "analysis_status": "pending-agent-analysis",
                })
            if not isinstance(metadata, dict) or metadata.get("status") != "available":
                blocking.append({
                    "owner_repo": owner_repo,
                    "reason": "github-issue-metadata-unavailable",
                    "status": row.get("status"),
                    "discussion_status": metadata.get("status") if isinstance(metadata, dict) else None,
                    "discussion_reason": metadata.get("reason") if isinstance(metadata, dict) else "missing",
                })
                continue
            review = analysis_by_repo.get(owner_repo)
            if not isinstance(review, dict) or review.get("status") != "complete":
                blocking.append({
                    "owner_repo": owner_repo,
                    "reason": "github-history-agent-analysis-pending",
                    "analysis_path": str(analysis_path),
                    "analysis_status": review.get("status") if isinstance(review, dict) else "missing",
                })
            elif (
                not str(review.get("issue_pr_comment_disposition") or "").strip()
                or review.get("commit_dispositions") is None
                or review.get("commit_dispositions") == ""
            ):
                blocking.append({
                    "owner_repo": owner_repo,
                    "reason": "github-history-analysis-unclassified",
                    "analysis_path": str(analysis_path),
                    "required": ["issue_pr_comment_disposition", "commit_dispositions"],
                })

    queue_path = workspace / ".auditooor" / "github_history_review_queue.json"
    queue_path.parent.mkdir(parents=True, exist_ok=True)
    queue_path.write_text(json.dumps({
        "schema_version": "auditooor.github_history_review_queue.v1",
        "workspace": str(workspace),
        "reviews": review_queue,
        "policy": "Read commit messages, diffs, issue/PR state, reviews, and comments in context before assigning OOS or fixed status.",
    }, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    result = {
        "schema": "auditooor.github_history_reconciliation.v1",
        "workspace": str(workspace),
        "verdict": "pass-github-discussion-reconciled" if not blocking else "fail-github-discussion-reconciliation",
        "targets": len(targets),
        "rows_checked": checked,
        "blocking": blocking,
        "analysis_path": str(analysis_path),
        "review_queue_path": str(queue_path),
        "manifest": str(manifests[-1]) if manifests else "",
    }
    evidence_path = workspace / ".auditooor" / "github_history_reconciliation.json"
    evidence_path.parent.mkdir(parents=True, exist_ok=True)
    result["evidence_path"] = str(evidence_path)
    evidence_path.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return (1 if blocking else 0), result


def run_miner(row: dict[str, Any], workspace: Path, window: int) -> tuple[int, str, str]:
    cmd = [
        sys.executable,
        str(MINER),
        "--workspace",
        str(workspace),
        "--upstream",
        row["owner_repo"],
        "--lang",
        row["language"],
        "--audit-pin",
        row["pin"],
        "--mode",
        "bidirectional",
        "--window",
        str(window),
        "--out",
        row["output_path"],
    ]
    # Pass the local checkout so the miner uses its local-git-only mode when
    # gh auth/token is unavailable. Without this the miner sees no checkout and
    # exits 3 (skipped_no_gh_auth) even when full local history is present.
    # Generic: applies to any workspace whose src/ is a real git checkout.
    repo_dir = row.get("repo_dir")
    if repo_dir and Path(str(repo_dir)).is_dir():
        cmd += ["--local-repo", str(repo_dir)]
    proc = subprocess.run(cmd, text=True, capture_output=True, check=False)
    return proc.returncode, proc.stdout, proc.stderr


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--workspace", required=True)
    ap.add_argument("--date", default=dt.date.today().isoformat())
    ap.add_argument("--window", type=int, default=90)
    ap.add_argument("--out-dir")
    ap.add_argument("--force", action="store_true")
    ap.add_argument("--dry-run", action="store_true")
    ap.add_argument("--json", action="store_true")
    ap.add_argument(
        "--validate-history",
        action="store_true",
        help="validate GitHub issue/PR discussion reconciliation for existing mining artifacts",
    )
    args = ap.parse_args(argv)

    workspace = Path(args.workspace).expanduser().resolve()
    if not workspace.is_dir():
        print(f"[audit-target-commit-mining] ERR workspace not found: {workspace}", file=sys.stderr)
        return 2

    if args.validate_history:
        rc, result = validate_github_history(workspace)
        if args.json:
            print(json.dumps(result, indent=2, sort_keys=True))
        elif result["verdict"] == "pass-not-applicable":
            print("[github-history-reconciliation] pass-not-applicable: no GitHub targets")
        elif rc:
            label = (
                "fail-unknown-github-history"
                if any(item.get("reason") == "missing-manifest-row" for item in result["blocking"])
                else "fail-github-discussion-reconciliation"
            )
            print(
                f"[github-history-reconciliation] {label}: "
                + json.dumps(result["blocking"], sort_keys=True),
                file=sys.stderr,
            )
        else:
            print(
                "[github-history-reconciliation] pass-github-discussion-reconciled: "
                f"{result['rows_checked']} row(s)"
            )
        return rc

    out_dir = Path(args.out_dir).expanduser().resolve() if args.out_dir else (
        workspace / "mining_rounds" / f"{args.date}-bidirectional-commit-mining"
    )
    ok, preflight_reason = targets_tsv_preflight(workspace)
    if not ok:
        print(
            "[audit-target-commit-mining] ERR "
            f"{preflight_reason}. Tier-6 bidirectional commit mining is "
            "canonical first-pass audit workflow; fix targets.tsv and rerun.",
            file=sys.stderr,
        )
        return 2

    old_empty_manifest = stale_empty_manifest(out_dir / "commit_mining_manifest.json")
    targets = load_targets(workspace)

    # gapA-multirepo-mining: reconcile the targets.tsv / scope.json target mine-set
    # against the scope.json in_scope SOURCE ROOTS. Any in-scope root that maps to
    # an upstream owner/repo absent from the target set is synthesized into the
    # mine list (closing the silent-skip), and unresolved roots are logged
    # explicitly (no silent cap). Additive: single-repo workspaces are unchanged.
    global_scope_pin = ""
    scope_path_for_pin = workspace / "scope.json"
    if scope_path_for_pin.is_file():
        try:
            _scope_payload = json.loads(scope_path_for_pin.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            _scope_payload = {}
        if isinstance(_scope_payload, dict):
            global_scope_pin = _scope_target_pin(_scope_payload, "")
    if not global_scope_pin and targets:
        global_scope_pin = targets[0].pin
    reconcile = reconcile_targets_with_inscope(workspace, targets)
    targets = synthesize_missing_targets(workspace, targets, reconcile, global_scope_pin)

    rows = build_rows(
        workspace,
        out_dir,
        targets,
        args.window,
        args.force or old_empty_manifest,
    )
    out_dir.mkdir(parents=True, exist_ok=True)
    repo_strategy = write_repo_strategy(workspace, rows)
    prior_audit_fix_index: dict[str, Any] | None = None
    if repo_strategy.get("strategy") == FLATTENED_SNAPSHOT_STRATEGY:
        prior_audit_fix_index = write_prior_audit_fix_index(workspace)

    for row in rows:
        if row.get("strategy") == FLATTENED_SNAPSHOT_STRATEGY and args.dry_run:
            # Dry-run records the pivot without doing network work. A real run
            # must still attempt authenticated remote mining; otherwise a short
            # local snapshot silently prevents GitHub issue/PR discussion review.
            row["status"] = FLATTENED_SNAPSHOT_STATUS
            continue
        if args.dry_run:
            row["status"] = "dry_run"
            continue
        if not row["will_run"]:
            row["status"] = "skipped_existing"
            continue
        rc, stdout, stderr = run_miner(row, workspace, args.window)
        row["status"] = "ok" if rc == 0 else ("skipped_no_gh_auth" if rc == 3 else "failed")
        row["returncode"] = rc
        if stdout:
            row["stdout_tail"] = stdout[-2000:]
        if stderr:
            row["stderr_tail"] = stderr[-2000:]

    # gapA-multirepo-mining: log every unresolved in_scope root as an explicit
    # skipped_unresolved_upstream row (logged, never silently dropped).
    for unresolved in reconcile.get("unresolved_roots") or []:
        rows.append({
            "repo_url": "",
            "owner_repo": "",
            "pin": global_scope_pin,
            "local_name": Path(str(unresolved.get("root") or "")).name,
            "repo_dir": str(workspace / str(unresolved.get("root") or "")),
            "language": "n/a",
            "output_path": "",
            "exists": False,
            "commit_count": None,
            "strategy": "skipped_unresolved_upstream",
            "recommendation": (
                "in_scope root could not be resolved to an upstream owner/repo: "
                f"{unresolved.get('reason', '')}"
            ),
            "inscope_root": str(unresolved.get("root") or ""),
            "reason": str(unresolved.get("reason") or ""),
            "status": "skipped_unresolved_upstream",
            "will_run": False,
        })

    mined_owner_repos = sorted({
        str(r.get("owner_repo") or "")
        for r in rows
        if str(r.get("owner_repo") or "") and r.get("status") not in (None, "skipped_unresolved_upstream")
    })

    manifest = {
        "schema": "auditooor.audit_target_commit_mining_manifest.v1",
        "generated_at_utc": dt.datetime.now(dt.UTC).replace(microsecond=0).isoformat(),
        "workspace": str(workspace),
        "mode": "bidirectional",
        "window": args.window,
        "dry_run": bool(args.dry_run),
        "force": bool(args.force),
        "stale_empty_manifest_rerun": bool(old_empty_manifest),
        "inscope_owner_repos": sorted(reconcile.get("inscope_owner_repos") or []),
        "target_owner_repos": sorted(reconcile.get("target_owner_repos") or []),
        "mined_owner_repos": mined_owner_repos,
        "unresolved_inscope_roots": list(reconcile.get("unresolved_roots") or []),
        "repo_strategy_path": str(workspace / ".auditooor" / "repo_strategy.json"),
        "prior_audit_fix_index_path": str(workspace / ".auditooor" / "prior_audit_fix_index.json")
        if prior_audit_fix_index is not None
        else "",
        "targets_seen": len(targets),
        "rows": rows,
        "summary": {
            "ok": sum(
                1
                for r in rows
                if r.get("status")
                in {"ok", "skipped_existing", "dry_run", "skipped_no_gh_auth", FLATTENED_SNAPSHOT_STATUS}
            ),
            "failed": sum(1 for r in rows if r.get("status") == "failed"),
            "skipped_no_gh_auth": sum(1 for r in rows if r.get("status") == "skipped_no_gh_auth"),
            "ran": sum(1 for r in rows if r.get("status") == "ok"),
            "skipped_existing": sum(1 for r in rows if r.get("status") == "skipped_existing"),
            "dry_run": sum(1 for r in rows if r.get("status") == "dry_run"),
            "flattened_snapshot_prior_audit_pivot": sum(
                1 for r in rows if r.get("status") == FLATTENED_SNAPSHOT_STATUS
            ),
            "prior_audit_fix_sha_references": int(
                ((prior_audit_fix_index or {}).get("summary") or {}).get("sha_references") or 0
            ),
        },
    }
    write_manifest(out_dir, manifest)
    write_commit_lifecycle_ledger(workspace, manifest)

    if args.json:
        print(json.dumps(manifest, indent=2, sort_keys=True))
    else:
        print(
            "[audit-target-commit-mining] "
            f"targets={len(targets)} ran={manifest['summary']['ran']} "
            f"skipped={manifest['summary']['skipped_existing']} "
            f"failed={manifest['summary']['failed']} "
            f"pivot={manifest['summary']['flattened_snapshot_prior_audit_pivot']} "
            f"stale_empty_manifest_rerun={int(old_empty_manifest)} "
            f"manifest={out_dir / 'commit_mining_manifest.json'}"
        )
    return 1 if manifest["summary"]["failed"] else 0


if __name__ == "__main__":
    raise SystemExit(main())
