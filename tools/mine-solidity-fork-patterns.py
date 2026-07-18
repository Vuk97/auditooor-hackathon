#!/usr/bin/env python3
"""Seed Solidity fork pattern markdown from upstream mining artifacts.

This is a Phase-A skeleton for seeding pattern docs from upstream protocol
reports. In replay/no-network mode it consumes local fixture/report JSON and
emits:

  patterns/<family>/<pattern-slug>.md
  patterns/INDEX.md

It also supports a production path that may invoke:
  - tools/reverted-guard-mine.py
  - tools/changelog-source-drift-miner.py
  - tools/git-commits-mining.py

Unavailable tools are handled as structured skipped artifacts.
"""

from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import json
import os
import re
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parent.parent
SCHEMA = "auditooor.mine_solidity_fork_patterns.v1"


@dataclass(frozen=True)
class UpstreamTarget:
    owner: str
    repo: str
    family: str

    @property
    def key(self) -> str:
        return f"{self.owner}/{self.repo}"

    @property
    def mirror_slug(self) -> str:
        return f"{self.owner}-{self.repo}"


DEFAULT_TARGETS: tuple[UpstreamTarget, ...] = (
    UpstreamTarget("liquity", "dev", "liquity-fork"),
    UpstreamTarget("liquity", "bold", "liquity-fork"),
    UpstreamTarget("Threshold-Network", "tbtc-v2", "stability-pool"),
    UpstreamTarget("MakerDAO", "dss", "cdp"),
    UpstreamTarget("aave", "aave-v3-core", "aave-collateral"),
    UpstreamTarget("curvefi", "curve-contract", "curve-stableswap"),
    UpstreamTarget("balancer-labs", "balancer-v2-monorepo", "balancer-pool"),
    UpstreamTarget("compound-finance", "compound-protocol", "compound-comptroller"),
    UpstreamTarget("OpenZeppelin", "openzeppelin-contracts", "oz-upgrade"),
)

DEFAULT_OWNER_BY_REPO = {target.repo: target.owner for target in DEFAULT_TARGETS}
DEFAULT_FAMILY_BY_KEY = {target.key: target.family for target in DEFAULT_TARGETS}

MINER_TOOLS = {
    "reverted_guard_mine": REPO_ROOT / "tools" / "reverted-guard-mine.py",
    "changelog_source_drift_miner": REPO_ROOT / "tools" / "changelog-source-drift-miner.py",
    "git_commits_mining": REPO_ROOT / "tools" / "git-commits-mining.py",
}


def _now_utc() -> str:
    return dt.datetime.now(tz=dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _slugify(value: str, max_len: int = 56) -> str:
    slug = re.sub(r"[^a-zA-Z0-9]+", "-", value).strip("-").lower()
    slug = re.sub(r"-{2,}", "-", slug)
    if not slug:
        return "pattern"
    if slug[0].isdigit():
        slug = f"p-{slug}"
    return slug[:max_len].strip("-") or "pattern"


def _norm_text(value: str) -> str:
    return re.sub(r"\s+", " ", (value or "").strip())


def stable_pattern_slug(
    family: str,
    trigger_shape: str,
    fix_shape: str,
    detector_regex: str,
    origin_commit_sha: str,
    source_report_reference: str,
) -> str:
    base = _slugify(
        trigger_shape
        or fix_shape
        or detector_regex
        or source_report_reference
        or family
        or "pattern",
        max_len=48,
    )
    seed = "|".join(
        (
            family.lower(),
            _norm_text(trigger_shape).lower(),
            _norm_text(fix_shape).lower(),
            _norm_text(detector_regex).lower(),
            (origin_commit_sha or "").lower(),
            source_report_reference.lower(),
        )
    )
    digest = hashlib.sha1(seed.encode("utf-8")).hexdigest()[:10]
    return f"{base}-{digest}"


def parse_target(raw: str) -> tuple[str, str]:
    text = (raw or "").strip()
    if not text:
        raise ValueError("empty target")
    if "/" in text:
        owner, repo = text.split("/", 1)
        owner = owner.strip()
        repo = repo.strip()
        if not owner or not repo:
            raise ValueError(f"invalid target {raw!r}; expected owner/repo")
        return owner, repo
    owner = DEFAULT_OWNER_BY_REPO.get(text)
    if owner:
        return owner, text
    raise ValueError(f"invalid target {raw!r}; expected owner/repo")


def resolve_targets(raw_targets: list[str] | None) -> list[UpstreamTarget]:
    if not raw_targets:
        return list(DEFAULT_TARGETS)
    resolved: list[UpstreamTarget] = []
    for raw in raw_targets:
        owner, repo = parse_target(raw)
        key = f"{owner}/{repo}"
        family = DEFAULT_FAMILY_BY_KEY.get(key, _slugify(repo, max_len=32))
        resolved.append(UpstreamTarget(owner=owner, repo=repo, family=family))
    return resolved


def _read_json(path: Path) -> dict[str, Any] | None:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None


def _discover_report(reports_dir: Path, prefixes: list[str]) -> Path | None:
    candidates: list[Path] = []
    for prefix in prefixes:
        candidates.extend(reports_dir.glob(f"**/{prefix}*.json"))
    if not candidates:
        return None
    return sorted(candidates)[-1]


def _build_detector_regex_from_pattern_id(pattern_id: str) -> str:
    parts = [p for p in re.split(r"[^A-Za-z0-9]+", pattern_id or "") if p]
    if not parts:
        return r"security|invariant|guard"
    return r".*".join(re.escape(p) for p in parts[:6])


def _extract_markdown_field(text: str, field: str) -> str:
    match = re.search(rf"(?m)^-\s+{re.escape(field)}:\s*(.*)$", text)
    if not match:
        return ""
    value = match.group(1).strip()
    if len(value) >= 2 and value[0] == "`" and value[-1] == "`":
        value = value[1:-1]
    return value.strip()


def _load_canonical_patterns(canonical_patterns_dir: Path, families: set[str] | None = None) -> list[dict[str, Any]]:
    if not canonical_patterns_dir.is_dir():
        return []
    patterns: list[dict[str, Any]] = []
    for md_path in sorted(canonical_patterns_dir.glob("*/*.md")):
        if md_path.name == "INDEX.md":
            continue
        family = md_path.parent.name
        if families and family not in families:
            continue
        try:
            text = md_path.read_text(encoding="utf-8")
        except OSError:
            continue
        source_ref = _extract_markdown_field(text, "source report reference")
        patterns.append(
            {
                "family": _extract_markdown_field(text, "family") or family,
                "target": _extract_markdown_field(text, "target") or "canonical",
                "source_tool": "canonical_patterns",
                "source": "canonical",
                "slug": md_path.stem,
                "origin_commit_sha": _extract_markdown_field(text, "origin commit SHA") or "canonical",
                "source_report_reference": source_ref or f"canonical:{md_path.relative_to(canonical_patterns_dir)}",
                "trigger_shape": _extract_markdown_field(text, "trigger-shape") or md_path.stem,
                "fix_shape": _extract_markdown_field(text, "fix-shape") or "See canonical pattern markdown.",
                "detector_regex": _extract_markdown_field(text, "detector-regex") or _build_detector_regex_from_pattern_id(md_path.stem),
                "applicability_heuristic": _extract_markdown_field(text, "applicability heuristic")
                or "Canonical repo pattern for replay/no-network workspaces.",
            }
        )
    return patterns


def _has_pattern_markdown(path: Path) -> bool:
    if not path.is_dir():
        return False
    return any(candidate.name != "INDEX.md" for candidate in path.glob("*/*.md"))


def _canonical_pattern_candidates(env: dict[str, str] | None = None) -> list[Path]:
    env = env or os.environ
    candidates: list[Path] = []

    for env_name in ("AUDITOOOR_CANONICAL_PATTERNS_DIR", "AUDITOOOR_SHARED_PATTERNS_DIR"):
        raw = env.get(env_name, "").strip()
        if raw:
            candidates.append(Path(raw).expanduser())

    auditooor_repo = env.get("AUDITOOOR_REPO", "").strip()
    if auditooor_repo:
        candidates.append(Path(auditooor_repo).expanduser() / "patterns")

    candidates.append(Path("~/auditooor-shared/patterns").expanduser())

    tool_dir = Path(__file__).resolve().parent
    for parent in (tool_dir, *tool_dir.parents):
        candidates.append(parent / "patterns")

    candidates.append(REPO_ROOT / "patterns")

    out: list[Path] = []
    seen: set[str] = set()
    for candidate in candidates:
        resolved = candidate.resolve() if candidate.exists() else candidate
        key = str(resolved)
        if key in seen:
            continue
        seen.add(key)
        out.append(resolved)
    return out


def resolve_canonical_patterns_dir(explicit: str | Path | None = None, env: dict[str, str] | None = None) -> Path:
    if explicit:
        return Path(explicit).expanduser().resolve()
    candidates = _canonical_pattern_candidates(env)
    for candidate in candidates:
        if _has_pattern_markdown(candidate):
            return candidate
    return candidates[0] if candidates else REPO_ROOT / "patterns"


def _extract_rows(report: dict[str, Any], keys: list[str]) -> list[dict[str, Any]]:
    for key in keys:
        rows = report.get(key)
        if isinstance(rows, list):
            return [row for row in rows if isinstance(row, dict)]
    return []


def _extract_patterns_from_reverted_guard(
    report: dict[str, Any],
    target: UpstreamTarget,
    source_ref: str,
) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    rows = _extract_rows(report, ["candidates", "rows", "findings"])
    for row in rows:
        is_candidate = bool(row.get("candidate_finding") or row.get("any_removed_guard_uncovered_at_pin"))
        if not is_candidate:
            continue
        removed = row.get("removed_function_signatures") or []
        removed = [str(item) for item in removed if item]
        removed_text = ", ".join(removed) if removed else "unknown guard surface"
        sha = str(row.get("sha") or report.get("audit_pin") or "unknown")
        detector = "|".join(re.escape(name) for name in removed[:6]) or r"revert|trust mitigations|guard"
        out.append(
            {
                "family": target.family,
                "target": target.key,
                "source_tool": "reverted_guard_mine",
                "origin_commit_sha": sha,
                "source_report_reference": source_ref,
                "trigger_shape": f"Revert-class commit removed protective guard(s): {removed_text}.",
                "fix_shape": "Re-introduce invariant guard/modifier checks on the affected state-transition path.",
                "detector_regex": detector,
                "applicability_heuristic": "High signal for fork derivatives with historical guard rollback commits.",
            }
        )
    return out


def _extract_patterns_from_git_commits(
    report: dict[str, Any],
    target: UpstreamTarget,
    source_ref: str,
) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    rows: list[dict[str, Any]] = []
    for key in ("commits", "rows", "findings", "items", "shaped_commits_index"):
        value = report.get(key)
        if isinstance(value, list):
            rows.extend(row for row in value if isinstance(row, dict))
    for row in rows:
        sha = str(row.get("sha") or row.get("commit_sha") or "unknown")
        subject = _norm_text(str(row.get("subject") or row.get("title") or "upstream security fix"))
        patterns = row.get("patterns")
        if isinstance(patterns, list) and patterns:
            for pattern in patterns:
                if not isinstance(pattern, dict):
                    continue
                shape = _norm_text(str(pattern.get("shape") or subject))
                pattern_id = str(pattern.get("id") or "")
                confidence = str(pattern.get("confidence") or "unknown")
                out.append(
                    {
                        "family": target.family,
                        "target": target.key,
                        "source_tool": "git_commits_mining",
                        "origin_commit_sha": sha,
                        "source_report_reference": source_ref,
                        "trigger_shape": shape,
                        "fix_shape": f"Adopt upstream hardening from commit: {subject}.",
                        "detector_regex": _build_detector_regex_from_pattern_id(pattern_id),
                        "applicability_heuristic": (
                            "Applicable to forked implementations sharing upstream architecture "
                            f"(pattern confidence: {confidence})."
                        ),
                    }
                )
            continue
        derivable = row.get("derivable_pattern")
        if isinstance(derivable, str) and derivable.strip():
            out.append(
                {
                    "family": target.family,
                    "target": target.key,
                    "source_tool": "git_commits_mining",
                    "origin_commit_sha": sha,
                    "source_report_reference": source_ref,
                    "trigger_shape": _norm_text(derivable),
                    "fix_shape": f"Apply the upstream fix semantics from commit: {subject}.",
                    "detector_regex": r"fix|guard|check|validate",
                    "applicability_heuristic": "Applicable when downstream fork keeps the same control/data-flow shape.",
                }
            )
            continue
        affected_paths = row.get("affected_solidity_paths") or []
        keywords = row.get("solidity_keywords_matched") or []
        score = row.get("solidity_score")
        if affected_paths or keywords:
            keyword_text = ", ".join(str(item) for item in keywords[:8]) if isinstance(keywords, list) else ""
            path_text = ", ".join(str(item) for item in affected_paths[:4]) if isinstance(affected_paths, list) else ""
            detector_seed = keyword_text or path_text or subject
            out.append(
                {
                    "family": target.family,
                    "target": target.key,
                    "source_tool": "git_commits_mining",
                    "origin_commit_sha": sha,
                    "source_report_reference": source_ref,
                    "trigger_shape": (
                        f"Security-shaped Solidity upstream commit touches {path_text or 'Solidity protocol code'}; "
                        f"subject: {subject}."
                    ),
                    "fix_shape": f"Replay the upstream semantic fix and verify fork code does not preserve the pre-fix behavior.",
                    "detector_regex": _build_detector_regex_from_pattern_id(detector_seed),
                    "applicability_heuristic": (
                        "Applicable to fork derivatives retaining the same protocol module or invariant surface "
                        f"(solidity_score={score})."
                    ),
                }
            )
    return out


def _extract_patterns_from_drift(
    report: dict[str, Any],
    target: UpstreamTarget,
    source_ref: str,
) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    claim_by_id = {
        str(claim.get("claim_id")): claim
        for claim in _extract_rows(report, ["claims"])
        if claim.get("claim_id")
    }
    exposed_call_sites = _extract_rows(report, ["ranked_exposed_call_sites"])
    for site in exposed_call_sites:
        claim = claim_by_id.get(str(site.get("claim_id")), {})
        primitive_values = site.get("matched_primitives") or claim.get("primitives") or []
        primitive = ", ".join(str(item) for item in primitive_values[:4]) if isinstance(primitive_values, list) else str(primitive_values)
        assumption_terms = site.get("matched_assumption_terms") or claim.get("assumption_terms") or []
        assumption_text = ", ".join(str(item) for item in assumption_terms[:8]) if isinstance(assumption_terms, list) else str(assumption_terms)
        claim_text = _norm_text(str(claim.get("text") or claim.get("claim") or claim.get("summary") or primitive))
        function_sig = _norm_text(str(site.get("signature") or site.get("function") or "current consumer"))
        sha = str(claim.get("commit_sha") or report.get("audit_pin") or "unknown")
        detector = _build_detector_regex_from_pattern_id(primitive or assumption_text or function_sig)
        out.append(
            {
                "family": target.family,
                "target": target.key,
                "source_tool": "changelog_source_drift_miner",
                "origin_commit_sha": sha,
                "source_report_reference": source_ref,
                "trigger_shape": f"Changelog claim remains exposed at {site.get('file_path')}:{site.get('line')} in {function_sig}: {claim_text}.",
                "fix_shape": "Update the fork consumer to match the upstream invariant change before relying on legacy ordering or accounting assumptions.",
                "detector_regex": detector,
                "applicability_heuristic": "High signal when a fork has changelog-described invariant drift and current exposed consumers.",
            }
        )
    rows = _extract_rows(report, ["claims", "drifts", "findings", "rows", "items"])
    for row in rows:
        if "claim_id" in row and str(row.get("claim_id")) in claim_by_id and exposed_call_sites:
            continue
        verdict = str(row.get("verdict") or row.get("status") or row.get("outcome") or "")
        verdict_low = verdict.lower()
        if verdict_low and "exposed" not in verdict_low and "not-updated" not in verdict_low:
            continue
        primitive = _norm_text(str(row.get("primitive") or row.get("symbol") or "upstream primitive"))
        claim = _norm_text(str(row.get("claim") or row.get("summary") or row.get("title") or primitive))
        remediation = _norm_text(
            str(row.get("remediation") or row.get("suggested_fix") or "Update downstream consumers to match upstream invariant changes.")
        )
        sha = str(row.get("commit_sha") or row.get("sha") or report.get("audit_pin") or "unknown")
        detector = _build_detector_regex_from_pattern_id(primitive)
        out.append(
            {
                "family": target.family,
                "target": target.key,
                "source_tool": "changelog_source_drift_miner",
                "origin_commit_sha": sha,
                "source_report_reference": source_ref,
                "trigger_shape": claim,
                "fix_shape": remediation,
                "detector_regex": detector,
                "applicability_heuristic": "Applicable where upstream changelog semantics changed but downstream consumers preserved legacy assumptions.",
            }
        )
    return out


def _run_command(cmd: list[str], cwd: Path | None = None) -> tuple[int, str, str]:
    proc = subprocess.run(
        cmd,
        cwd=str(cwd) if cwd else None,
        capture_output=True,
        text=True,
        check=False,
    )
    return proc.returncode, proc.stdout or "", proc.stderr or ""


def _git(cmd: list[str], cwd: Path | None = None) -> tuple[int, str, str]:
    return _run_command(["git", *cmd], cwd=cwd)


def _remote_default_ref(mirror_dir: Path) -> str:
    rc, stdout, _stderr = _git(["symbolic-ref", "-q", "--short", "refs/remotes/origin/HEAD"], cwd=mirror_dir)
    if rc == 0 and stdout.strip():
        return stdout.strip()
    for candidate in ("origin/main", "origin/master"):
        rc, _stdout, _stderr = _git(["rev-parse", "--verify", "--quiet", candidate], cwd=mirror_dir)
        if rc == 0:
            return candidate
    return "FETCH_HEAD"


def _ensure_mirror(target: UpstreamTarget, mirror_root: Path) -> dict[str, Any]:
    mirror_root.mkdir(parents=True, exist_ok=True)
    mirror_dir = mirror_root / target.mirror_slug
    url = f"https://github.com/{target.key}.git"
    if not mirror_dir.exists():
        rc, stdout, stderr = _git(["clone", "--depth", "180", "--no-single-branch", url, str(mirror_dir)])
        if rc != 0:
            return {
                "target": target.key,
                "tool": "mirror_refresh",
                "status": "skipped",
                "reason": "clone_failed",
                "exit_code": rc,
                "stderr_tail": stderr[-400:],
                "stdout_tail": stdout[-400:],
            }
    else:
        rc, stdout, stderr = _git(["fetch", "--tags", "--depth", "180", "origin"], cwd=mirror_dir)
        if rc != 0:
            return {
                "target": target.key,
                "tool": "mirror_refresh",
                "status": "skipped",
                "reason": "fetch_failed",
                "exit_code": rc,
                "stderr_tail": stderr[-400:],
                "stdout_tail": stdout[-400:],
            }
    default_ref = _remote_default_ref(mirror_dir)
    rc, stdout, stderr = _git(["checkout", "--detach", default_ref], cwd=mirror_dir)
    if rc != 0:
        return {
            "target": target.key,
            "tool": "mirror_refresh",
            "status": "skipped",
            "reason": "checkout_failed",
            "exit_code": rc,
            "stderr_tail": stderr[-400:],
            "stdout_tail": stdout[-400:],
            "ref": default_ref,
        }
    return {"target": target.key, "tool": "mirror_refresh", "status": "ok", "mirror_dir": str(mirror_dir), "ref": default_ref}


def _audit_pin_for_mirror(mirror_dir: Path, window: int = 60) -> tuple[str, str]:
    rc, stdout, _stderr = _git(["rev-parse", f"HEAD~{window}"], cwd=mirror_dir)
    if rc != 0 or not stdout.strip():
        rc, stdout, _stderr = _git(["rev-parse", "HEAD"], cwd=mirror_dir)
    audit_pin = stdout.strip() if rc == 0 and stdout.strip() else "HEAD"
    rc, stdout, _stderr = _git(["show", "-s", "--format=%cs", audit_pin], cwd=mirror_dir)
    since_date = stdout.strip() if rc == 0 and stdout.strip() else dt.datetime.now(tz=dt.timezone.utc).strftime("%Y-%m-%d")
    return audit_pin, since_date


def _write_git_report_markdown(json_path: Path) -> Path | None:
    payload = _read_json(json_path)
    if payload is None:
        return None
    if "solidity" not in str(payload.get("schema", "")).lower() and "solidity" not in str(payload.get("schema_version", "")).lower():
        return None
    rows = payload.get("shaped_commits_index")
    if not isinstance(rows, list):
        rows = []
    md_path = json_path.with_suffix(".md")
    lines = [
        f"# Git Commits Mining: {payload.get('upstream_repo', json_path.stem)}",
        "",
        f"- schema: {payload.get('schema', 'unknown')}",
        f"- workspace: {payload.get('workspace', 'unknown')}",
        f"- audit pin: {payload.get('audit_pin_sha', 'unknown')}",
        f"- since date: {payload.get('since_date', 'unknown')}",
        f"- mode: {payload.get('mode', 'unknown')}",
        f"- window: {payload.get('window', 'unknown')}",
        f"- commits scanned: {payload.get('commits_scanned', 0)}",
        f"- security-shaped commits: {payload.get('security_fix_count', len(rows))}",
        "",
        "## Shaped Commits",
        "",
    ]
    if not rows:
        lines.append("- None surfaced by the bounded miner.")
    for row in rows:
        subject = _norm_text(str(row.get("subject") or row.get("title") or "unknown"))
        sha = str(row.get("sha") or "unknown")
        url = str(row.get("url") or "")
        paths = row.get("affected_solidity_paths") or []
        keywords = row.get("solidity_keywords_matched") or []
        lines.append(f"- `{sha[:12]}` {subject}")
        if url:
            lines.append(f"  - url: {url}")
        if paths:
            lines.append(f"  - affected Solidity paths: {', '.join(str(path) for path in paths[:8])}")
        if keywords:
            lines.append(f"  - matched keywords: {', '.join(str(item) for item in keywords[:12])}")
        if row.get("solidity_score") is not None:
            lines.append(f"  - solidity score: {row.get('solidity_score')}")
    md_path.write_text("\n".join(lines).rstrip() + "\n", encoding="utf-8")
    return md_path


def _run_miners_for_target(
    target: UpstreamTarget,
    workspace: Path,
    mirror_root: Path,
    reports_dir: Path,
    no_network: bool,
    tool_paths: dict[str, Path],
) -> list[dict[str, Any]]:
    artifacts: list[dict[str, Any]] = []
    timestamp = dt.datetime.now(tz=dt.timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    mirror_dir = mirror_root / target.mirror_slug

    if no_network:
        for tool_name in ("reverted_guard_mine", "changelog_source_drift_miner", "git_commits_mining"):
            artifacts.append(
                {
                    "target": target.key,
                    "tool": tool_name,
                    "status": "skipped",
                    "reason": "no_network",
                }
            )
        return artifacts

    missing_tools = [tool_name for tool_name, path in tool_paths.items() if tool_name in MINER_TOOLS and not path.exists()]
    if len(missing_tools) == len(MINER_TOOLS):
        for tool_name in ("reverted_guard_mine", "changelog_source_drift_miner", "git_commits_mining"):
            artifacts.append(
                {
                    "target": target.key,
                    "tool": tool_name,
                    "status": "skipped",
                    "reason": "tool_missing",
                    "tool_path": str(tool_paths.get(tool_name, "")),
                }
            )
        return artifacts

    mirror_status = _ensure_mirror(target, mirror_root)
    artifacts.append(mirror_status)
    if mirror_status.get("status") != "ok":
        return artifacts

    audit_pin, since_date = _audit_pin_for_mirror(mirror_dir, window=60)

    command_specs = [
        (
            "reverted_guard_mine",
            [
                "python3",
                str(tool_paths["reverted_guard_mine"]),
                "--workspace",
                str(mirror_dir),
                "--repo-dir",
                str(mirror_dir),
                "--audit-pin",
                audit_pin,
                "--backward-window",
                "60",
                "--lang",
                "sol",
                "--out",
                str(reports_dir / f"reverted_guard_mine_{target.mirror_slug}_{timestamp}.json"),
            ],
        ),
        (
            "changelog_source_drift_miner",
            [
                "python3",
                str(tool_paths["changelog_source_drift_miner"]),
                str(mirror_dir),
                "--json",
                "--output",
                str(reports_dir / f"changelog_source_drift_miner_{target.mirror_slug}_{timestamp}.json"),
            ],
        ),
        (
            "git_commits_mining",
            [
                "python3",
                str(tool_paths["git_commits_mining"]),
                "--workspace",
                target.mirror_slug,
                "--upstream",
                target.key,
                "--lang",
                "sol",
                "--mode",
                "bidirectional",
                "--window",
                "60",
                "--audit-pin",
                audit_pin,
                "--since",
                since_date,
                "--bounded-forward-window",
                "--out",
                str(reports_dir / f"git_commits_mining_{target.mirror_slug}_{timestamp}.json"),
            ],
        ),
    ]

    for tool_name, cmd in command_specs:
        tool_path = tool_paths[tool_name]
        if not tool_path.exists():
            artifacts.append(
                {
                    "target": target.key,
                    "tool": tool_name,
                    "status": "skipped",
                    "reason": "tool_missing",
                    "tool_path": str(tool_path),
                }
            )
            continue
        rc, stdout, stderr = _run_command(cmd, cwd=workspace)
        if rc != 0:
            artifacts.append(
                {
                    "target": target.key,
                    "tool": tool_name,
                    "status": "skipped",
                    "reason": "tool_run_failed",
                    "exit_code": rc,
                    "stderr_tail": stderr[-400:],
                    "stdout_tail": stdout[-400:],
                }
            )
            continue
        out_index = cmd.index("--out") + 1 if "--out" in cmd else cmd.index("--output") + 1 if "--output" in cmd else None
        out_path = Path(cmd[out_index]) if out_index is not None else None
        if out_path is not None and not out_path.exists():
            artifacts.append(
                {
                    "target": target.key,
                    "tool": tool_name,
                    "status": "skipped",
                    "reason": "report_not_written",
                    "stdout_tail": stdout[-400:],
                }
            )
            continue
        artifacts.append(
            {
                "target": target.key,
                "tool": tool_name,
                "status": "ok",
                "audit_pin": audit_pin,
                "since_date": since_date,
                "report_path": str(out_path) if out_path is not None else "",
            }
        )
    return artifacts


def _build_pattern_markdown(pattern: dict[str, Any]) -> str:
    source_line = f"- source: {pattern['source']}\n" if pattern.get("source") else ""
    return (
        f"# {pattern['slug']}\n\n"
        f"- family: {pattern['family']}\n"
        f"- target: {pattern['target']}\n"
        f"{source_line}"
        f"- trigger-shape: {pattern['trigger_shape']}\n"
        f"- fix-shape: {pattern['fix_shape']}\n"
        f"- detector-regex: `{pattern['detector_regex']}`\n"
        f"- applicability heuristic: {pattern['applicability_heuristic']}\n"
        f"- origin commit SHA: {pattern['origin_commit_sha']}\n"
        f"- source report reference: {pattern['source_report_reference']}\n"
    )


def _write_patterns(patterns_dir: Path, patterns: list[dict[str, Any]]) -> list[str]:
    written: list[str] = []
    for pattern in sorted(patterns, key=lambda row: (row["family"], row["slug"], row["target"])):
        out_dir = patterns_dir / pattern["family"]
        out_dir.mkdir(parents=True, exist_ok=True)
        out_path = out_dir / f"{pattern['slug']}.md"
        out_path.write_text(_build_pattern_markdown(pattern), encoding="utf-8")
        written.append(str(out_path))
    return written


def _write_index(patterns_dir: Path, patterns: list[dict[str, Any]], families: list[str] | None = None) -> Path:
    by_family: dict[str, list[dict[str, Any]]] = {}
    for pattern in patterns:
        by_family.setdefault(pattern["family"], []).append(pattern)
    for family in families or []:
        by_family.setdefault(family, [])
    lines = [
        "# Solidity Fork Pattern Index",
        "",
        f"Generated: {_now_utc()}",
        "",
        f"Total patterns: {len(patterns)}",
        "",
    ]
    for family in sorted(by_family):
        lines.append(f"## {family}")
        lines.append("")
        rows = sorted(by_family[family], key=lambda row: row["slug"])
        family_lines = [
            f"# Solidity Fork Patterns: {family}",
            "",
            f"Generated: {_now_utc()}",
            "",
            f"Total patterns: {len(rows)}",
            "",
        ]
        if not rows:
            lines.append("- No patterns surfaced by the available reports.")
            family_lines.append("- No patterns surfaced by the available reports.")
        else:
            for row in rows:
                rel = f"{family}/{row['slug']}.md"
                lines.append(
                    f"- [{row['slug']}]({rel}) - target `{row['target']}` - origin `{row['origin_commit_sha']}`"
                )
                family_lines.append(
                    f"- [{row['slug']}]({row['slug']}.md) - target `{row['target']}` - origin `{row['origin_commit_sha']}`"
                )
        lines.append("")
        (patterns_dir / family).mkdir(parents=True, exist_ok=True)
        (patterns_dir / family / "INDEX.md").write_text("\n".join(family_lines).rstrip() + "\n", encoding="utf-8")
    index_path = patterns_dir / "INDEX.md"
    index_path.write_text("\n".join(lines).rstrip() + "\n", encoding="utf-8")
    return index_path


def seed_solidity_fork_patterns(
    workspace: Path,
    mirror_root: Path,
    reports_dir: Path,
    patterns_dir: Path,
    targets: list[UpstreamTarget],
    replay: bool,
    no_network: bool,
    canonical_patterns_dir: Path | None = None,
    tool_paths: dict[str, Path] | None = None,
) -> dict[str, Any]:
    tool_paths = dict(tool_paths or MINER_TOOLS)
    reports_dir.mkdir(parents=True, exist_ok=True)
    patterns_dir.mkdir(parents=True, exist_ok=True)

    artifacts: list[dict[str, Any]] = []
    extracted: list[dict[str, Any]] = []

    for target in targets:
        if not replay:
            artifacts.extend(
                _run_miners_for_target(
                    target=target,
                    workspace=workspace,
                    mirror_root=mirror_root,
                    reports_dir=reports_dir,
                    no_network=no_network,
                    tool_paths=tool_paths,
                )
            )

        report_specs = [
            (
                "reverted_guard_mine",
                [f"reverted_guard_mine_{target.mirror_slug}", f"reverted_guard_mine_{target.repo}"],
                _extract_patterns_from_reverted_guard,
            ),
            (
                "changelog_source_drift_miner",
                [
                    f"changelog_source_drift_miner_{target.mirror_slug}",
                    f"changelog_source_drift_miner_{target.repo}",
                    f"changelog_source_drift_{target.mirror_slug}",
                    f"changelog_source_drift_{target.repo}",
                ],
                _extract_patterns_from_drift,
            ),
            (
                "git_commits_mining",
                [f"git_commits_mining_{target.mirror_slug}", f"git_commits_mining_{target.repo}"],
                _extract_patterns_from_git_commits,
            ),
        ]
        for source_tool, prefixes, extractor in report_specs:
            report_path = _discover_report(reports_dir, prefixes)
            if report_path is None:
                artifacts.append(
                    {
                        "target": target.key,
                        "tool": source_tool,
                        "status": "skipped",
                        "reason": "report_missing",
                    }
                )
                continue
            payload = _read_json(report_path)
            if payload is None:
                artifacts.append(
                    {
                        "target": target.key,
                        "tool": source_tool,
                        "status": "skipped",
                        "reason": "invalid_report_json",
                        "report_path": str(report_path),
                    }
                )
                continue
            source_ref = str(report_path.relative_to(workspace)) if workspace in report_path.parents else str(report_path)
            extracted.extend(extractor(payload, target, source_ref))

    canonical_patterns: list[dict[str, Any]] = []
    if replay or no_network:
        canonical_dir = canonical_patterns_dir or resolve_canonical_patterns_dir()
        target_families = {target.family for target in targets}
        canonical_patterns = _load_canonical_patterns(canonical_dir, families=target_families)
        if canonical_patterns:
            extracted.extend(canonical_patterns)
            artifacts.append(
                {
                    "tool": "canonical_patterns",
                    "status": "ok",
                    "source": "canonical",
                    "patterns_dir": str(canonical_dir),
                    "pattern_count": len(canonical_patterns),
                }
            )
        else:
            artifacts.append(
                {
                    "tool": "canonical_patterns",
                    "status": "skipped",
                    "reason": "canonical_patterns_missing",
                    "patterns_dir": str(canonical_dir),
                }
            )

    deduped_by_slug: dict[str, dict[str, Any]] = {}
    for pattern in extracted:
        slug = str(pattern.get("slug") or "") or stable_pattern_slug(
            family=str(pattern["family"]),
            trigger_shape=str(pattern["trigger_shape"]),
            fix_shape=str(pattern["fix_shape"]),
            detector_regex=str(pattern["detector_regex"]),
            origin_commit_sha=str(pattern["origin_commit_sha"]),
            source_report_reference=str(pattern["source_report_reference"]),
        )
        pattern = dict(pattern)
        pattern["slug"] = slug
        deduped_by_slug.setdefault(f"{pattern['family']}/{slug}", pattern)
    patterns = list(deduped_by_slug.values())
    canonical_pattern_count = sum(1 for pattern in patterns if pattern.get("source") == "canonical")

    written_paths = _write_patterns(patterns_dir, patterns)
    index_path = _write_index(patterns_dir, patterns, families=sorted({target.family for target in targets}))
    git_json_paths = [
        Path(str(artifact["report_path"]))
        for artifact in artifacts
        if artifact.get("tool") == "git_commits_mining"
        and artifact.get("status") == "ok"
        and artifact.get("report_path")
    ]
    if not git_json_paths and replay:
        git_json_paths = sorted(reports_dir.glob("**/git_commits_mining_*.json"))
    git_markdown_paths = [
        str(path)
        for path in sorted(
            filter(
                None,
                (_write_git_report_markdown(path) for path in git_json_paths),
            )
        )
    ]

    return {
        "schema": SCHEMA,
        "generated_at": _now_utc(),
        "workspace": str(workspace),
        "mirror_root": str(mirror_root),
        "reports_dir": str(reports_dir),
        "patterns_dir": str(patterns_dir),
        "no_network": no_network,
        "replay": replay,
        "targets": [
            {"owner": target.owner, "repo": target.repo, "family": target.family, "key": target.key}
            for target in targets
        ],
        "pattern_count": len(patterns),
        "canonical_pattern_count": canonical_pattern_count,
        "workspace_pattern_count": len(patterns) - canonical_pattern_count,
        "patterns": patterns,
        "pattern_paths": written_paths,
        "index_path": str(index_path),
        "git_markdown_paths": git_markdown_paths,
        "artifacts": artifacts,
    }


def _parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Seed Solidity fork pattern markdown from upstream miner outputs.")
    parser.add_argument("--workspace", default=str(REPO_ROOT), help="Workspace root path.")
    parser.add_argument(
        "--mirror-root",
        default=str(Path("~/auditooor-shared/upstream-mirrors").expanduser()),
        help="Root directory for upstream mirrors (<owner>-<repo>).",
    )
    parser.add_argument("--reports-dir", default="", help="Directory for miner reports (defaults to <workspace>/reports).")
    parser.add_argument("--patterns-dir", default="", help="Pattern output directory (defaults to <workspace>/patterns).")
    parser.add_argument(
        "--canonical-patterns-dir",
        default="",
        help=(
            "Canonical pattern markdown directory to merge in replay/no-network mode. "
            "Defaults to AUDITOOOR_CANONICAL_PATTERNS_DIR, AUDITOOOR_REPO/patterns, "
            "~/auditooor-shared/patterns, then the nearest checked-out patterns/ directory."
        ),
    )
    parser.add_argument("--target", action="append", default=[], help="Upstream target owner/repo (repeatable).")
    parser.add_argument("--replay", action="store_true", help="Replay existing reports only; do not invoke miners.")
    parser.add_argument("--no-network", action="store_true", help="Disable network-dependent behavior; consume local reports only.")
    parser.add_argument("--json", action="store_true", help="Print JSON summary to stdout.")
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = _parse_args(argv)
    workspace = Path(args.workspace).expanduser().resolve()
    mirror_root = Path(args.mirror_root).expanduser().resolve()
    reports_dir = Path(args.reports_dir).expanduser().resolve() if args.reports_dir else workspace / "reports"
    patterns_dir = Path(args.patterns_dir).expanduser().resolve() if args.patterns_dir else workspace / "patterns"
    canonical_patterns_dir = resolve_canonical_patterns_dir(args.canonical_patterns_dir)

    try:
        targets = resolve_targets(args.target)
    except ValueError as exc:
        print(f"[mine-solidity-fork-patterns] {exc}", file=sys.stderr)
        return 2

    payload = seed_solidity_fork_patterns(
        workspace=workspace,
        mirror_root=mirror_root,
        reports_dir=reports_dir,
        patterns_dir=patterns_dir,
        targets=targets,
        replay=bool(args.replay),
        no_network=bool(args.no_network),
        canonical_patterns_dir=canonical_patterns_dir,
    )

    if args.json:
        print(json.dumps(payload, indent=2, sort_keys=True))
    else:
        print(f"[mine-solidity-fork-patterns] targets={len(payload['targets'])} patterns={payload['pattern_count']}")
        print(f"[mine-solidity-fork-patterns] index={payload['index_path']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
