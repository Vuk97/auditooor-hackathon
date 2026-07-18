#!/usr/bin/env python3
"""Wave-1 Hackerman ETL: Code4rena / Sherlock audit-contest findings.

Pulls REAL per-finding records from public contest-platform findings /
judging repos via the GitHub REST API and emits one
``auditooor.hackerman_record.v1`` per finding.

Hard rules (M14-trap discipline, per ``~/.claude/CLAUDE.md``):

* Real-source only. Every contest slug, every finding ID, every URL
  emitted comes from a live ``gh api /repos/<owner>/<repo>/contents/<path>``
  call (or a cached replay of one).
* No memory-recalled contest names. The miner LISTS the org and FILTERS
  by repo-name pattern (Code4rena: ``.*-findings$``; Sherlock:
  ``.*-judging$``).
* No invented severities. Severity is derived from the on-disk artifact:
  Code4rena uses a ``risk`` integer field (``1``=low, ``2``=med,
  ``3``=high) inside the per-finding JSON; Sherlock encodes severity in
  the per-issue directory name suffix (``-H`` / ``-M``).
* Contests / repos that return zero findings are recorded in
  ``contests_with_zero_findings``, never fabricated.
* Records validate against
  ``audit/corpus_tags/schemas/auditooor.hackerman_record.v1.schema.json``.

Per-source ``verification_tier`` is encoded into ``required_preconditions``
(schema's ``additionalProperties: false`` forbids new top-level fields):

* ``verification_tier=tier-2-verified-public-archive`` - live gh-api pull
* ``verification_tier=tier-2-verified-public-archive-cache`` - cache replay

Cantina is intentionally NOT covered here: Cantina hosts contests on its
own platform (cantina.xyz) and does NOT publish per-finding artifacts to
a public GitHub org. Cantina coverage is delegated to other tag
namespaces (e.g. operator-pasted cantina:<contest>:<id> records). The
miner records this as a documented skip in the summary's
``platforms_intentionally_skipped`` list.

Sampling rule (documented per brief):

* Code4rena has ~880+ public repos. Sherlock has ~460+. Full enumeration
  would balloon record counts beyond the 500-2000 honest target. The
  miner therefore samples the top-N most-recently-updated findings repos
  per platform (default N=50). Skipped contests are emitted to the
  summary's ``contests_skipped_by_sampling`` for the operator to
  decide if a follow-up wave is warranted.

Output: one ``record.json`` + mirror ``record.yaml`` per finding under
``audit/corpus_tags/tags/contest_platform_findings/<platform>__<contest_slug>__<finding_id>/``.

CLI:

    # Live pull (default; samples top-50 contests per platform):
    python3 tools/hackerman-etl-from-contest-platforms.py \\
        --out-dir audit/corpus_tags/tags/contest_platform_findings

    # Smaller sample for a fast pass:
    python3 tools/hackerman-etl-from-contest-platforms.py \\
        --sample-size 10 --out-dir audit/corpus_tags/tags/contest_platform_findings

    # Offline replay of a cached payload:
    python3 tools/hackerman-etl-from-contest-platforms.py \\
        --cache-file /tmp/contest-platforms-cache.json \\
        --out-dir audit/corpus_tags/tags/contest_platform_findings

Shape anchor: ``tools/hackerman-etl-from-restaking-lrt-advisories.py``.
"""
from __future__ import annotations

import argparse
import base64
import hashlib
import importlib.util
import json
import re
import subprocess
import sys
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Tuple

import yaml


REPO_ROOT = Path(__file__).resolve().parent.parent
SCHEMA_VERSION = "auditooor.hackerman_record.v1"
SUMMARY_SCHEMA = "auditooor.hackerman_etl.contest_platform_findings.summary.v1"

DEFAULT_SAMPLE_SIZE = 50
# Findings-per-contest hard cap (defensive: avoid 10k+ explosion).
DEFAULT_PER_CONTEST_CAP = 200


def _load_validator() -> Any:
    spec = importlib.util.spec_from_file_location(
        "_hackerman_record_validate_contest_platforms",
        str(REPO_ROOT / "tools" / "hackerman-record-validate.py"),
    )
    mod = importlib.util.module_from_spec(spec)
    assert spec.loader
    spec.loader.exec_module(mod)
    return mod


_VALIDATOR = _load_validator()


# Platform definitions. Each is (platform_id, org, repo_name_pattern,
# default_lang, default_domain).
PLATFORMS: Tuple[Tuple[str, str, str, str, str], ...] = (
    ("code4rena", "code-423n4", r".+-findings$", "solidity", "lending"),
    ("sherlock", "sherlock-audit", r".+-judging$", "solidity", "lending"),
)


# Platforms with no public-github finding archive. Recorded as honest
# skip in the summary so the operator sees we considered them.
PLATFORMS_INTENTIONALLY_SKIPPED: Tuple[Tuple[str, str], ...] = (
    (
        "cantina",
        "Cantina contests are hosted on cantina.xyz; no public per-finding "
        "GitHub archive is published. Coverage delegated to operator-"
        "pasted cantina:<contest>:<id> records under a separate tag.",
    ),
)


# ---------------------------------------------------------------------------
# YAML / slug helpers (byte-stable, mirrored from sibling miners).
# ---------------------------------------------------------------------------


def slugify(value: object, *, max_len: int = 80) -> str:
    text = str(value or "").strip().lower()
    text = re.sub(r"[^a-z0-9._:/-]+", "-", text).strip("-._")
    text = re.sub(r"-{2,}", "-", text)
    return (text[:max_len].strip("-._") or "record")


def one_line(text: object, fallback: str, *, max_len: int = 1000) -> str:
    cleaned = re.sub(r"\s+", " ", str(text or "")).strip()
    return (cleaned[:max_len].strip() if cleaned else fallback)


def yaml_scalar(value: object) -> str:
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, (int, float)):
        return str(value)
    text = str(value if value is not None else "")
    if text == "":
        return '""'
    numeric = re.fullmatch(r"[-+]?(?:0|[1-9][0-9_]*)(?:\.[0-9_]+)?", text)
    ambiguous = text.lower() in {"true", "false", "null", "yes", "no", "on", "off", "~"}
    plain_safe = (
        re.fullmatch(r"[A-Za-z0-9._:/<>=,$#-]+", text)
        and not text.endswith(":")
        and not text.startswith(("#", "-", "?", ":", "<", ">", "@", "`", "&", "*", "!", "|", "%", "{", "}", "[", "]", ","))
    )
    if plain_safe and not numeric and not ambiguous:
        return text
    return json.dumps(text, ensure_ascii=False)


def yaml_dump(data: Dict[str, Any]) -> str:
    lines: List[str] = []
    for key, value in data.items():
        if isinstance(value, dict):
            lines.append(f"{key}:")
            for subkey, subvalue in value.items():
                if isinstance(subvalue, list):
                    lines.append(f"  {subkey}:")
                    for item in subvalue:
                        lines.append(f"    - {yaml_scalar(item)}")
                else:
                    lines.append(f"  {subkey}: {yaml_scalar(subvalue)}")
        elif isinstance(value, list):
            if not value:
                lines.append(f"{key}: []")
            else:
                lines.append(f"{key}:")
                for item in value:
                    if isinstance(item, dict):
                        first = True
                        for subkey, subvalue in item.items():
                            lines.append(
                                f"{'  -' if first else '  '} {subkey}: {yaml_scalar(subvalue)}"
                            )
                            first = False
                    else:
                        lines.append(f"  - {yaml_scalar(item)}")
        else:
            lines.append(f"{key}: {yaml_scalar(value)}")
    return "\n".join(lines) + "\n"


# ---------------------------------------------------------------------------
# gh api helpers.
# ---------------------------------------------------------------------------


def _gh_api(path: str, *, timeout: int = 60) -> Optional[Any]:
    """Call ``gh api <path>`` and return decoded JSON (or None on error)."""
    try:
        proc = subprocess.run(
            ["gh", "api", path],
            check=False,
            capture_output=True,
            text=True,
            timeout=timeout,
        )
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return None
    if proc.returncode != 0:
        return None
    try:
        return json.loads(proc.stdout)
    except json.JSONDecodeError:
        return None


def list_org_findings_repos(
    org: str,
    pattern: str,
    *,
    max_pages: int = 12,
) -> List[Dict[str, Any]]:
    """List `<org>` repos and filter by repo-name regex.

    Returns the raw repo dicts (with ``name`` + ``updated_at``).
    Up to ``max_pages`` pages of 100 (default 12 = 1200 repos scanned).
    """
    out: List[Dict[str, Any]] = []
    rx = re.compile(pattern)
    for page in range(1, max_pages + 1):
        data = _gh_api(
            f"/orgs/{org}/repos?per_page=100&type=public"
            f"&sort=updated&page={page}"
        )
        if not isinstance(data, list) or not data:
            break
        for repo in data:
            if not isinstance(repo, dict):
                continue
            name = repo.get("name") or ""
            if isinstance(name, str) and rx.match(name):
                out.append(repo)
        if len(data) < 100:
            break
    return out


def list_contest_findings_dir(
    org: str, repo: str, *, path: str = "data"
) -> List[Dict[str, Any]]:
    """List the contents of a contest findings/judging dir."""
    data = _gh_api(f"/repos/{org}/{repo}/contents/{path}?per_page=200")
    if not isinstance(data, list):
        return []
    return [x for x in data if isinstance(x, dict)]


def list_sherlock_issue_dirs(org: str, repo: str) -> List[Dict[str, Any]]:
    """List the per-issue directories at the repo root (Sherlock judging layout)."""
    data = _gh_api(f"/repos/{org}/{repo}/contents?per_page=200")
    if not isinstance(data, list):
        return []
    dirs = [
        x for x in data
        if isinstance(x, dict)
        and x.get("type") == "dir"
        and re.match(r"^\d+-[HMhm]$", str(x.get("name", "")))
    ]
    return dirs


def fetch_file_content(org: str, repo: str, path: str) -> Optional[str]:
    """Fetch a single file's decoded text content via gh api."""
    data = _gh_api(f"/repos/{org}/{repo}/contents/{path}")
    if not isinstance(data, dict):
        return None
    enc = data.get("encoding")
    content = data.get("content")
    if enc == "base64" and isinstance(content, str):
        try:
            return base64.b64decode(content).decode("utf-8", errors="replace")
        except Exception:
            return None
    if isinstance(content, str):
        return content
    return None


# ---------------------------------------------------------------------------
# Fetch entrypoints: live or cached.
# ---------------------------------------------------------------------------


def discover_already_mined(
    out_dir: Path,
) -> Dict[str, set]:
    """Inspect ``out_dir`` for existing wave-1 record subdirs and return
    ``{platform_id: {contest_slug, ...}}``.

    Record subdirs are named ``<platform>__<contest_slug>__<finding_id>``
    (see ``slug_for_record``). Any directory under ``out_dir`` matching
    that shape contributes to the skip set.

    Returns an empty mapping if ``out_dir`` does not exist or contains
    no matching subdirs. Never raises.
    """
    mined: Dict[str, set] = {}
    try:
        entries = list(out_dir.iterdir())
    except (FileNotFoundError, NotADirectoryError):
        return mined
    for entry in entries:
        if not entry.is_dir():
            continue
        name = entry.name
        parts = name.split("__", 2)
        if len(parts) < 3:
            continue
        platform_id, contest_slug, _finding = parts
        if not platform_id or not contest_slug:
            continue
        mined.setdefault(platform_id, set()).add(contest_slug)
    return mined


def fetch_all(
    platforms: Iterable[Tuple[str, str, str, str, str]],
    *,
    sample_size: int = DEFAULT_SAMPLE_SIZE,
    per_contest_cap: int = DEFAULT_PER_CONTEST_CAP,
    cache_file: Optional[Path] = None,
    write_cache_file: Optional[Path] = None,
    sample_all: bool = False,
    skip_already_mined: Optional[Dict[str, set]] = None,
    sample_offset: int = 0,
    max_contests: Optional[int] = None,
) -> Tuple[Dict[str, Any], str]:
    """Return ``({platform: {repo: {meta, findings}}}, verification_tier)``.

    ``findings`` is a list of per-finding dicts in a small uniform shape:
        {"id": str, "severity_raw": str, "title": str, "url": str,
         "body": str, "handle": Optional[str]}

    The cache file is a JSON dump of the same structure.

    Wave-2 hooks:

    * ``sample_all=True`` selects every matched repo (ignores
      ``sample_size``). Pairs with ``skip_already_mined`` for a follow-up
      pass that catches the contests parked under
      ``contests_skipped_by_sampling`` in the wave-1 summary.
    * ``skip_already_mined``: mapping ``{platform_id: {contest_slug,...}}``.
      Matching repos are recorded under
      ``platform_block["skipped_already_mined"]`` and NOT re-fetched.
    * ``sample_offset``: skip the first N repos per platform (after
      sorting by recency, descending). Useful for paging through the
      sampled-out tail without re-mining wave-1's first N.
    """
    if cache_file is not None:
        payload = json.loads(cache_file.read_text(encoding="utf-8"))
        if not isinstance(payload, dict):
            raise ValueError("cache-file root must be a mapping")
        return payload, "tier-2-verified-public-archive-cache"

    skip_map = skip_already_mined or {}
    fetched: Dict[str, Any] = {}
    for platform_id, org, pattern, _lang, _domain in platforms:
        platform_block: Dict[str, Any] = {
            "org": org,
            "pattern": pattern,
            "repos": {},
            "skipped_by_sampling": [],
            "skipped_already_mined": [],
        }
        repos = list_org_findings_repos(org, pattern)
        repos.sort(key=lambda r: r.get("updated_at") or "", reverse=True)
        if sample_offset > 0:
            offset_skipped = repos[:sample_offset]
            repos = repos[sample_offset:]
            for skip in offset_skipped:
                platform_block["skipped_by_sampling"].append(
                    skip.get("name") or ""
                )
        if sample_all:
            sampled = repos
            skipped: List[Dict[str, Any]] = []
        else:
            sampled = repos[:sample_size]
            skipped = repos[sample_size:]
        for skip in skipped:
            platform_block["skipped_by_sampling"].append(skip.get("name") or "")
        platform_skips = skip_map.get(platform_id) or set()
        # Apply max_contests AFTER skip-already-mined so the cap counts
        # NEW contests, not repos we'd skip anyway. Walk sampled in order
        # (already sorted by recency), counting only repos we'd actually
        # fetch.
        if max_contests is not None and max_contests >= 0:
            kept: List[Dict[str, Any]] = []
            kept_count = 0
            for repo in sampled:
                name = repo.get("name") or ""
                if not name:
                    kept.append(repo)
                    continue
                if name in platform_skips:
                    kept.append(repo)
                    continue
                if kept_count >= max_contests:
                    platform_block["skipped_by_sampling"].append(name)
                    continue
                kept.append(repo)
                kept_count += 1
            sampled = kept
        for repo in sampled:
            name = repo.get("name") or ""
            if not name:
                continue
            if name in platform_skips:
                platform_block["skipped_already_mined"].append(name)
                continue
            findings = _fetch_contest_findings(
                platform_id, org, name, per_contest_cap=per_contest_cap
            )
            platform_block["repos"][name] = {
                "updated_at": repo.get("updated_at") or "",
                "html_url": repo.get("html_url")
                or f"https://github.com/{org}/{name}",
                "findings": findings,
            }
        fetched[platform_id] = platform_block

    if write_cache_file is not None:
        write_cache_file.parent.mkdir(parents=True, exist_ok=True)
        write_cache_file.write_text(
            json.dumps(fetched, indent=2, sort_keys=True), encoding="utf-8"
        )
    return fetched, "tier-2-verified-public-archive"


def _fetch_contest_findings(
    platform_id: str,
    org: str,
    repo: str,
    *,
    per_contest_cap: int,
) -> List[Dict[str, Any]]:
    if platform_id == "code4rena":
        return _fetch_code4rena_findings(org, repo, cap=per_contest_cap)
    if platform_id == "sherlock":
        return _fetch_sherlock_findings(org, repo, cap=per_contest_cap)
    return []


def _fetch_code4rena_findings(
    org: str, repo: str, *, cap: int
) -> List[Dict[str, Any]]:
    entries = list_contest_findings_dir(org, repo, path="data")
    out: List[Dict[str, Any]] = []
    json_entries = [e for e in entries if str(e.get("name", "")).endswith(".json")]
    json_entries.sort(key=lambda e: str(e.get("name", "")))
    for entry in json_entries[:cap]:
        name = str(entry.get("name", ""))
        text = fetch_file_content(org, repo, f"data/{name}")
        if not text:
            continue
        try:
            obj = json.loads(text)
        except json.JSONDecodeError:
            continue
        if not isinstance(obj, dict):
            continue
        out.append(
            {
                "id": str(obj.get("issueId") or name.rsplit(".", 1)[0]),
                "severity_raw": str(obj.get("risk") or ""),
                "title": str(obj.get("title") or ""),
                "url": str(
                    obj.get("issueUrl")
                    or f"https://github.com/{org}/{repo}/blob/main/data/{name}"
                ),
                "body": "",
                "handle": obj.get("handle"),
                "filename": name,
            }
        )
    return out


def _fetch_sherlock_findings(
    org: str, repo: str, *, cap: int
) -> List[Dict[str, Any]]:
    issue_dirs = list_sherlock_issue_dirs(org, repo)
    out: List[Dict[str, Any]] = []
    issue_dirs.sort(key=lambda d: str(d.get("name", "")))
    for entry in issue_dirs[:cap]:
        dir_name = str(entry.get("name", ""))
        m = re.match(r"^(\d+)-([HMhm])$", dir_name)
        if not m:
            continue
        issue_id = m.group(1)
        sev = m.group(2).upper()
        children = list_contest_findings_dir(org, repo, path=dir_name)
        md_children = [
            c for c in children if str(c.get("name", "")).endswith(".md")
        ]
        if not md_children:
            continue
        # Take the first md file alphabetically.
        md_children.sort(key=lambda c: str(c.get("name", "")))
        first = md_children[0]
        md_name = str(first.get("name", ""))
        body = fetch_file_content(org, repo, f"{dir_name}/{md_name}") or ""
        title_match = re.search(r"^#\s+(.+?)$", body, flags=re.MULTILINE)
        title = title_match.group(1).strip() if title_match else md_name
        out.append(
            {
                "id": issue_id,
                "severity_raw": sev,
                "title": title,
                "url": (
                    f"https://github.com/{org}/{repo}/blob/main/"
                    f"{dir_name}/{md_name}"
                ),
                "body": body[:4000],
                "handle": None,
                "filename": f"{dir_name}/{md_name}",
            }
        )
    return out


# ---------------------------------------------------------------------------
# Severity / impact mapping.
# ---------------------------------------------------------------------------


# Code4rena: "risk" field: 1=Low, 2=Med, 3=High. QA reports are "Q".
_C4_SEVERITY: Dict[str, str] = {
    "3": "high",
    "2": "medium",
    "1": "low",
    "q": "info",
    "g": "info",
    "": "info",
}

# Sherlock dirs encoded as H/M.
_SHERLOCK_SEVERITY: Dict[str, str] = {
    "H": "high",
    "M": "medium",
}


def _normalize_severity(platform_id: str, raw: str) -> str:
    raw_norm = str(raw or "").strip().lower()
    if platform_id == "code4rena":
        return _C4_SEVERITY.get(raw_norm, "info")
    if platform_id == "sherlock":
        return _SHERLOCK_SEVERITY.get(raw_norm.upper(), "info")
    return "info"


def _dollar_class(severity: str) -> str:
    sev = severity.lower()
    if sev == "critical":
        return ">=$1M"
    if sev == "high":
        return "$100K-$1M"
    if sev == "medium":
        return "$10K-$100K"
    if sev == "low":
        return "<$10K"
    return "non-financial"


# Impact keyword routing (mirrors sibling miners, ordered most-specific first).
_IMPACT_KEYWORDS: Tuple[Tuple[str, str], ...] = (
    ("reentrancy", "theft"),
    ("flash loan", "theft"),
    ("flashloan", "theft"),
    ("price manipulation", "theft"),
    ("oracle manipulation", "theft"),
    ("steal", "theft"),
    ("theft", "theft"),
    ("drain", "theft"),
    ("siphon", "theft"),
    ("loss of funds", "theft"),
    ("freeze", "freeze"),
    ("locked", "freeze"),
    ("frozen", "freeze"),
    ("stuck", "freeze"),
    ("griefing", "griefing"),
    ("governance", "governance-takeover"),
    ("admin takeover", "governance-takeover"),
    ("voting", "governance-takeover"),
    ("privilege escalation", "privilege-escalation"),
    ("access control", "privilege-escalation"),
    ("authorization", "privilege-escalation"),
    ("denial of service", "dos"),
    ("denial-of-service", "dos"),
    ("dos", "dos"),
    ("rounding", "precision-loss"),
    ("precision", "precision-loss"),
    ("overflow", "precision-loss"),
    ("underflow", "precision-loss"),
    ("rebase", "yield-redistribution"),
    ("yield", "yield-redistribution"),
    ("reward", "yield-redistribution"),
    ("interest rate", "yield-redistribution"),
)


def _infer_impact_class(text: str) -> str:
    hay = text.lower()
    for kw, impact in _IMPACT_KEYWORDS:
        if kw in hay:
            return impact
    return "theft"


def _infer_impact_actor(impact_class: str) -> str:
    if impact_class in {"governance-takeover", "privilege-escalation"}:
        return "protocol-treasury"
    if impact_class == "yield-redistribution":
        return "yield-recipient"
    if impact_class == "dos":
        return "arbitrary-user"
    return "arbitrary-user"


# ---------------------------------------------------------------------------
# Contest slug -> domain heuristic (very rough; "lending" stays default).
# ---------------------------------------------------------------------------


_DOMAIN_KEYWORDS: Tuple[Tuple[str, str], ...] = (
    ("dex", "dex"),
    ("amm", "dex"),
    ("uniswap", "dex"),
    ("curve", "dex"),
    ("perp", "dex"),
    ("bridge", "bridge"),
    ("hop", "bridge"),
    ("oracle", "oracle"),
    ("chainlink", "oracle"),
    ("vault", "vault"),
    ("erc4626", "vault"),
    ("staking", "staking"),
    ("restaking", "staking"),
    ("lst", "staking"),
    ("rollup", "rollup"),
    ("optimism", "rollup"),
    ("arbitrum", "rollup"),
    ("zksync", "zk-proof"),
    ("zk", "zk-proof"),
    ("dao", "dao"),
    ("governance", "governance"),
    ("escrow", "escrow"),
    ("nft", "nft"),
    ("marketplace", "nft"),
    ("lend", "lending"),
    ("aave", "lending"),
    ("compound", "lending"),
    ("borrow", "lending"),
)


def _infer_domain(contest_slug: str) -> str:
    s = contest_slug.lower()
    for kw, domain in _DOMAIN_KEYWORDS:
        if kw in s:
            return domain
    return "lending"


# ---------------------------------------------------------------------------
# Finding -> record.
# ---------------------------------------------------------------------------


def _record_id(platform_id: str, contest_slug: str, finding_id: str) -> str:
    payload = f"{platform_id}|{contest_slug}|{finding_id}"
    digest = hashlib.sha256(payload.encode("utf-8")).hexdigest()[:12]
    contest_slug_short = slugify(contest_slug, max_len=60)
    fid_slug = slugify(finding_id, max_len=24) or "0"
    return f"{platform_id}:{contest_slug_short}:{fid_slug}:{digest}"


def _function_shape(
    platform_id: str, finding: Dict[str, Any], lang: str
) -> Dict[str, Any]:
    title = finding.get("title") or ""
    raw_signature = one_line(
        title, f"{platform_id}-finding-{finding.get('id','?')}", max_len=500
    )
    shape_tags: List[str] = [
        slugify(f"{platform_id}-{lang}", max_len=64),
        slugify(f"finding-{finding.get('id','0')}", max_len=64),
    ]
    if platform_id == "code4rena":
        risk = str(finding.get("severity_raw") or "")
        shape_tags.append(slugify(f"c4-risk-{risk}", max_len=64))
    elif platform_id == "sherlock":
        sev = str(finding.get("severity_raw") or "")
        shape_tags.append(slugify(f"sherlock-{sev}", max_len=64))
    # Dedup, preserve order.
    seen: set = set()
    unique: List[str] = []
    for tag in shape_tags:
        if tag and tag not in seen:
            seen.add(tag)
            unique.append(tag)
    if not unique:
        unique = [f"{platform_id}-finding"]
    return {"raw_signature": raw_signature, "shape_tags": unique}


def _required_preconditions(
    platform_id: str,
    contest_slug: str,
    finding: Dict[str, Any],
    verification_tier: str,
) -> List[str]:
    url = finding.get("url") or ""
    out: List[str] = []
    if url:
        out.append(f"Reference finding at {url}")
    out.append(f"Contest slug {contest_slug} on platform {platform_id}")
    out.append(f"Finding id {finding.get('id','?')}")
    handle = finding.get("handle")
    if handle:
        out.append(f"Reported by handle {handle}")
    out.append(f"verification_tier={verification_tier}")
    seen: set = set()
    unique: List[str] = []
    for item in out:
        cleaned = one_line(item, "precondition", max_len=900)
        if cleaned and cleaned not in seen:
            seen.add(cleaned)
            unique.append(cleaned)
    return unique


def _year_for(contest_slug: str) -> int:
    m = re.match(r"^(\d{4})-", contest_slug)
    if m:
        try:
            y = int(m.group(1))
            if 2000 <= y <= 2100:
                return y
        except ValueError:
            pass
    return 2024


def _attacker_action_sequence(
    finding: Dict[str, Any], verification_tier: str
) -> str:
    title = finding.get("title") or ""
    body = finding.get("body") or ""
    text = f"{title}. {body}".strip(". ").strip()
    if not text:
        text = "Contest-finding attacker action sequence; see referenced URL."
    state_marker = (
        f" [source=public-contest-archive; "
        f"verification_tier={verification_tier}]"
    )
    body_max = 4900 - len(state_marker)
    body_text = one_line(text, "contest-finding attacker action sequence", max_len=body_max)
    return (body_text + state_marker).strip()


def finding_to_record(
    platform_id: str,
    contest_slug: str,
    lang: str,
    finding: Dict[str, Any],
    verification_tier: str,
) -> Dict[str, Any]:
    severity = _normalize_severity(platform_id, finding.get("severity_raw") or "")
    text_for_impact = " ".join(
        [str(finding.get("title") or ""), str(finding.get("body") or "")]
    )
    impact_class = _infer_impact_class(text_for_impact)
    impact_actor = _infer_impact_actor(impact_class)
    domain = _infer_domain(contest_slug)
    finding_id = str(finding.get("id") or "0")
    source_url = finding.get("url") or (
        f"https://github.com/contest-platforms/{platform_id}/{contest_slug}/{finding_id}"
    )
    record_id = _record_id(platform_id, contest_slug, finding_id)
    return {
        "schema_version": SCHEMA_VERSION,
        "record_id": record_id,
        "source_audit_ref": one_line(
            f"{platform_id}:{contest_slug}:{finding_id}",
            f"{platform_id}:{contest_slug}:{finding_id}",
            max_len=240,
        ),
        "target_domain": domain,
        "target_language": lang,
        "target_repo": "unknown",
        "target_component": one_line(
            f"{platform_id}:{contest_slug}:finding-{finding_id}",
            f"{platform_id}:{contest_slug}:finding",
            max_len=240,
        ),
        "function_shape": _function_shape(platform_id, finding, lang),
        "bug_class": f"audit-contest-finding-{platform_id}",
        "attack_class": f"contest-platform-finding-{platform_id}",
        "attacker_role": "unprivileged",
        "attacker_action_sequence": _attacker_action_sequence(
            finding, verification_tier
        ),
        "required_preconditions": _required_preconditions(
            platform_id, contest_slug, finding, verification_tier
        ),
        "impact_class": impact_class,
        "impact_actor": impact_actor,
        "impact_dollar_class": _dollar_class(severity),
        "fix_pattern": one_line(
            f"Apply remediation per the {platform_id} contest finding "
            f"thread; verify mitigation via post-contest mitigation review "
            f"at {source_url}.",
            "Apply contest-finding remediation per upstream report.",
            max_len=900,
        ),
        "fix_anti_pattern_avoided": one_line(
            f"Shipping the {platform_id}-flagged {severity}-severity "
            f"finding to mainnet without mitigation review.",
            f"Shipping an unmitigated {platform_id} contest finding.",
            max_len=900,
        ),
        "severity_at_finding": severity,
        "year": _year_for(contest_slug),
        "record_tier": "public-corpus",
        "record_quality_score": 3.5,
        "source_extraction_method": "corpus-etl",
        "source_extraction_confidence": 0.85,
        "cross_language_analogues": [],
        "related_records": [],
    }


# ---------------------------------------------------------------------------
# Pipeline.
# ---------------------------------------------------------------------------


def build_records(
    fetched: Dict[str, Any],
    platforms: Iterable[Tuple[str, str, str, str, str]],
    verification_tier: str,
) -> List[Dict[str, Any]]:
    records: List[Dict[str, Any]] = []
    seen_ids: set = set()
    plat_lookup = {p[0]: p for p in platforms}
    for platform_id, block in fetched.items():
        if platform_id not in plat_lookup:
            continue
        _, _org, _pattern, lang, _domain = plat_lookup[platform_id]
        if not isinstance(block, dict):
            continue
        repos = block.get("repos") or {}
        if not isinstance(repos, dict):
            continue
        for contest_slug, repo_block in repos.items():
            if not isinstance(repo_block, dict):
                continue
            findings = repo_block.get("findings") or []
            if not isinstance(findings, list):
                continue
            for finding in findings:
                if not isinstance(finding, dict):
                    continue
                record = finding_to_record(
                    platform_id, contest_slug, lang, finding, verification_tier
                )
                if record["record_id"] in seen_ids:
                    continue
                seen_ids.add(record["record_id"])
                records.append(record)
    return records


def slug_for_record(record: Dict[str, Any]) -> str:
    component = record["target_component"]
    parts = component.split(":")
    if len(parts) >= 3:
        platform_id = parts[0]
        contest = parts[1]
        finding = parts[2].replace("finding-", "")
    else:
        platform_id = "unknown"
        contest = "unknown"
        finding = "0"
    return slugify(
        f"{platform_id}__{contest}__{finding}", max_len=140
    )


def convert(
    out_dir: Path,
    *,
    dry_run: bool = False,
    limit: Optional[int] = None,
    sample_size: int = DEFAULT_SAMPLE_SIZE,
    per_contest_cap: int = DEFAULT_PER_CONTEST_CAP,
    platforms: Optional[List[Tuple[str, str, str, str, str]]] = None,
    cache_file: Optional[Path] = None,
    write_cache_file: Optional[Path] = None,
    filter_platform: Optional[str] = None,
    sample_all: bool = False,
    skip_already_mined: bool = False,
    skip_already_mined_dir: Optional[Path] = None,
    sample_offset: int = 0,
    max_contests: Optional[int] = None,
) -> Dict[str, Any]:
    selected = list(platforms or PLATFORMS)
    if filter_platform:
        selected = [p for p in selected if p[0] == filter_platform]
    skip_map: Optional[Dict[str, set]] = None
    if skip_already_mined:
        # Default to the out_dir itself; allows callers to point at a
        # sibling dir (e.g. wave-1's tag dir if running wave-2 into a
        # staging area).
        scan_dir = skip_already_mined_dir or out_dir
        skip_map = discover_already_mined(scan_dir)
    fetched, verification_tier = fetch_all(
        selected,
        sample_size=sample_size,
        per_contest_cap=per_contest_cap,
        cache_file=cache_file,
        write_cache_file=write_cache_file,
        sample_all=sample_all,
        skip_already_mined=skip_map,
        sample_offset=sample_offset,
        max_contests=max_contests,
    )
    records = build_records(fetched, selected, verification_tier)
    if limit is not None:
        records = records[:limit]

    schema = _VALIDATOR.load_schema()
    errors: List[str] = []
    files: List[str] = []
    sample_urls: List[str] = []
    by_platform: Dict[str, int] = {}
    by_contest: Dict[str, int] = {}
    by_severity: Dict[str, int] = {}
    by_impact: Dict[str, int] = {}

    if not dry_run:
        out_dir.mkdir(parents=True, exist_ok=True)

    contests_with_zero: Dict[str, List[str]] = {}
    contests_skipped: Dict[str, List[str]] = {}
    contests_skipped_already_mined: Dict[str, List[str]] = {}
    for platform_id, block in fetched.items():
        if not isinstance(block, dict):
            continue
        zero: List[str] = []
        repos = block.get("repos") or {}
        if isinstance(repos, dict):
            for contest_slug, repo_block in repos.items():
                if (
                    isinstance(repo_block, dict)
                    and not (repo_block.get("findings") or [])
                ):
                    zero.append(contest_slug)
        contests_with_zero[platform_id] = sorted(zero)
        skipped = block.get("skipped_by_sampling") or []
        if isinstance(skipped, list):
            contests_skipped[platform_id] = [str(x) for x in skipped if x]
        already = block.get("skipped_already_mined") or []
        if isinstance(already, list):
            contests_skipped_already_mined[platform_id] = [
                str(x) for x in already if x
            ]

    for record in records:
        by_severity[record["severity_at_finding"]] = (
            by_severity.get(record["severity_at_finding"], 0) + 1
        )
        by_impact[record["impact_class"]] = (
            by_impact.get(record["impact_class"], 0) + 1
        )
        # platform/contest from source_audit_ref ("platform:contest:fid").
        parts = record["source_audit_ref"].split(":")
        if len(parts) >= 2:
            platform_id = parts[0]
            contest = parts[1]
            by_platform[platform_id] = by_platform.get(platform_id, 0) + 1
            ckey = f"{platform_id}:{contest}"
            by_contest[ckey] = by_contest.get(ckey, 0) + 1

        rendered_yaml = yaml_dump(record)
        try:
            doc = yaml.safe_load(rendered_yaml)
        except yaml.YAMLError as exc:
            errors.append(f"{record['record_id']}: yaml-parse-error: {exc}")
            continue
        errs = _VALIDATOR.validate_doc(doc, schema)
        if errs:
            errors.extend(f"{record['record_id']}: {err}" for err in errs)
            continue

        slug = slug_for_record(record)
        rec_subdir = out_dir / slug
        json_path = rec_subdir / "record.json"
        yaml_path = rec_subdir / "record.yaml"
        files.append(str(json_path))
        if len(sample_urls) < 5:
            # surface the underlying URL from required_preconditions.
            ref_lines = [
                p for p in record["required_preconditions"]
                if p.startswith("Reference finding at ")
            ]
            if ref_lines:
                sample_urls.append(
                    ref_lines[0].removeprefix("Reference finding at ")
                )
        if not dry_run:
            rec_subdir.mkdir(parents=True, exist_ok=True)
            json_path.write_text(
                json.dumps(record, indent=2, sort_keys=True) + "\n",
                encoding="utf-8",
            )
            yaml_path.write_text(rendered_yaml, encoding="utf-8")

    return {
        "schema_version": SUMMARY_SCHEMA,
        "out_dir": str(out_dir),
        "dry_run": dry_run,
        "verification_tier": verification_tier,
        "sample_size": sample_size,
        "per_contest_cap": per_contest_cap,
        "records_emitted": len(records) - len(errors),
        "records_attempted": len(records),
        "errors": errors,
        "by_platform": by_platform,
        "by_contest": by_contest,
        "by_severity": by_severity,
        "by_impact_class": by_impact,
        "file_count": len(files),
        "platforms_queried": [p[0] for p in selected],
        "platforms_intentionally_skipped": [
            {"platform": p, "reason": one_line(r, r, max_len=900)}
            for p, r in PLATFORMS_INTENTIONALLY_SKIPPED
        ],
        "contests_with_zero_findings": contests_with_zero,
        "contests_skipped_by_sampling": contests_skipped,
        "contests_skipped_already_mined": contests_skipped_already_mined,
        "sample_source_urls": sample_urls,
        "files": files[:50],
    }


# ---------------------------------------------------------------------------
# CLI.
# ---------------------------------------------------------------------------


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out-dir", required=True)
    parser.add_argument("--dry-run", action="store_true")
    parser.add_argument("--limit", type=int)
    parser.add_argument(
        "--sample-size",
        type=int,
        default=DEFAULT_SAMPLE_SIZE,
        help=(
            "Number of most-recent contests to sample per platform. Default "
            f"{DEFAULT_SAMPLE_SIZE}; sibling contests are recorded in "
            "contests_skipped_by_sampling, not silently dropped."
        ),
    )
    parser.add_argument(
        "--per-contest-cap",
        type=int,
        default=DEFAULT_PER_CONTEST_CAP,
        help=(
            "Maximum findings to pull per contest (defensive against 10k+ "
            "explosion). Default {0}.".format(DEFAULT_PER_CONTEST_CAP)
        ),
    )
    parser.add_argument(
        "--cache-file",
        help="Read fetched payload from a JSON cache instead of calling gh api.",
    )
    parser.add_argument(
        "--write-cache-file",
        help="Save the fetched gh-api payload to this path for later offline replay.",
    )
    parser.add_argument(
        "--filter-platform",
        choices=[p[0] for p in PLATFORMS],
        help="Restrict to a single platform.",
    )
    parser.add_argument(
        "--all",
        dest="sample_all",
        action="store_true",
        help=(
            "Wave-2: process EVERY matched repo (overrides --sample-size). "
            "Combine with --skip-already-mined to avoid re-fetching the "
            "wave-1 sample."
        ),
    )
    parser.add_argument(
        "--skip-already-mined",
        action="store_true",
        help=(
            "Wave-2: scan --out-dir (or --skip-already-mined-dir if set) "
            "for existing <platform>__<contest>__<finding> subdirs and "
            "skip those contests during fetch (no gh-api calls + no "
            "record collisions)."
        ),
    )
    parser.add_argument(
        "--skip-already-mined-dir",
        help=(
            "Optional explicit dir to scan for already-mined contests. "
            "Defaults to --out-dir when --skip-already-mined is set."
        ),
    )
    parser.add_argument(
        "--sample-offset",
        type=int,
        default=0,
        help=(
            "Skip the first N most-recently-updated repos before sampling. "
            "Useful for paging through older contests without re-mining the "
            "wave-1 sample. Default 0."
        ),
    )
    parser.add_argument(
        "--max-contests",
        type=int,
        default=None,
        help=(
            "Wave-2: cap the number of NEW contests fetched per platform "
            "(already-mined skips don't count). Pairs with --all to bound "
            "total runtime when the long-tail is large. Default unlimited."
        ),
    )
    parser.add_argument("--json-summary", action="store_true")
    return parser


def main(argv: Optional[List[str]] = None) -> int:
    args = build_parser().parse_args(argv)
    if args.limit is not None and args.limit < 0:
        print("--limit must be non-negative", file=sys.stderr)
        return 2
    if args.sample_size < 0:
        print("--sample-size must be non-negative", file=sys.stderr)
        return 2
    if args.per_contest_cap < 0:
        print("--per-contest-cap must be non-negative", file=sys.stderr)
        return 2
    if args.sample_offset < 0:
        print("--sample-offset must be non-negative", file=sys.stderr)
        return 2
    summary = convert(
        Path(args.out_dir).expanduser().resolve(),
        dry_run=args.dry_run,
        limit=args.limit,
        sample_size=args.sample_size,
        per_contest_cap=args.per_contest_cap,
        cache_file=Path(args.cache_file).expanduser().resolve()
        if args.cache_file
        else None,
        write_cache_file=(
            Path(args.write_cache_file).expanduser().resolve()
            if args.write_cache_file
            else None
        ),
        filter_platform=args.filter_platform,
        sample_all=args.sample_all,
        skip_already_mined=args.skip_already_mined,
        skip_already_mined_dir=(
            Path(args.skip_already_mined_dir).expanduser().resolve()
            if args.skip_already_mined_dir
            else None
        ),
        sample_offset=args.sample_offset,
        max_contests=args.max_contests,
    )
    if args.json_summary:
        print(json.dumps(summary, sort_keys=True))
    else:
        print(
            "hackerman contest-platform ETL: "
            f"records={summary['records_emitted']}/{summary['records_attempted']} "
            f"verification_tier={summary['verification_tier']} "
            f"platforms={summary['platforms_queried']} "
            f"by_platform={summary['by_platform']} "
            f"by_severity={summary['by_severity']} "
            f"errors={len(summary['errors'])}"
        )
    return 0 if not summary["errors"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
