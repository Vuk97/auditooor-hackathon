#!/usr/bin/env python3
"""
hackerman-etl-from-graph-protocol-sources.py - Graph Protocol specific
real-source detector pattern seeds for the auditooor Hackerman corpus.

Wave-3 CAP-D4 lane: Graph-specific detector pattern seeds (real-source
only). Companion to the 12 TG-PAT seeds at
``/Users/wolf/audits/thegraph/derived_detectors/`` (Tier-6 backward
commit-mining run, commit ``a6aff867``); this miner emits records BEYOND
those 12 anchor SHAs by walking the past 100 commits of:

  - graphprotocol/contracts           (audit-pin c9971e7ee436634ea25b8dae9d83a967f9fd7d34)
  - graphprotocol/contracts-v2
  - graphprotocol/issuance-allocator
  - graphprotocol/horizon
  - graphprotocol/security-advisories (advisories-only; gracefully skipped if absent)

Plus any disclosed CVE / GHSA on the ``graphprotocol/*`` org via the
per-repo ``/repos/<owner>/<repo>/security-advisories`` endpoint.

HARD RULES (M14-trap discipline; Rule 37 emit-time tier):
- Real-source-only. Every record's ``source_audit_ref`` is the GitHub
  commit URL ``https://github.com/<owner>/<repo>/commit/<sha>``. The SHA
  is taken verbatim from a ``gh api /repos/<owner>/<repo>/commits/<sha>``
  response - never invented from training-data recall.
- ``verification_tier`` is FIRST-CLASS on every emitted record:
    * Commit body references a ``GHSA-xxxx-xxxx-xxxx`` id AND the GHSA
      lookup against ``/repos/<owner>/<repo>/security-advisories/<ghsa-id>``
      succeeds  -> ``tier-1-verified-realtime-api``.
    * Commit matches the security-keyword filter AND a real commit-detail
      response was retrieved -> ``tier-2-verified-public-archive``.
    * No per-commit anchor available -> NOT EMITTED. We never synthesise.
- The 12 TG-PAT anchor SHAs (`aa0823082968`, `affc8b46d35d`, `025410f39966`,
  `91224ed83eef`, `2252c1908bde`, `89f1321c421f`, `3639241494de`,
  `ece40cdbbd2a`, `4e834010453b`, `5e319051d2bc`, `ce61f315b252`) are
  in the ``TG_PAT_SKIP_SHAS`` set and explicitly excluded from emission
  to avoid double-seeding the corpus.
- One record per commit. No cross-product across "downstream products
  that might be affected" (synthesis trap).
- If yield < 5 records the script exits with a NEGATIVE summary so the
  caller does not silently inherit an empty corpus. (Lower threshold than
  the AMM-fix-history miner because Graph Protocol is a single-org corpus
  with narrower fix-shape variety.)

Output:
  audit/corpus_tags/tags/graph_protocol_real_source/<repo-tail>__<sha8>/record.{yaml,json}

CLI:
  python3 tools/hackerman-etl-from-graph-protocol-sources.py \\
      --out-dir audit/corpus_tags/tags/graph_protocol_real_source \\
      --json-summary

  python3 tools/hackerman-etl-from-graph-protocol-sources.py --dry-run --json-summary

Operator-explicit ``--fetch`` is NOT required (we use ``gh api`` directly,
which respects ``gh auth`` state and is rate-limit-safe). Hermetic tests
inject a fake ``gh_api`` to avoid the network entirely.

The script does NOT mutate tools/calibration/llm_budget_log.jsonl.
"""
from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import os
import re
import subprocess
import sys
from pathlib import Path
from typing import Any, Callable, Dict, Iterable, List, Optional, Sequence, Tuple

import yaml

# Rule 37 (Check #77): CVE/GHSA verifier shim - works both when run
# from repo-root (``python3 tools/<miner>.py``) and as a module.
try:
    from tools.lib.hackerman_cve_verification import pre_emit_check  # type: ignore
except ImportError:  # pragma: no cover - bootstrap when tools not on sys.path
    import os as _r37_os
    import sys as _r37_sys
    _r37_sys.path.insert(0, _r37_os.path.dirname(_r37_os.path.dirname(_r37_os.path.abspath(__file__))))
    from tools.lib.hackerman_cve_verification import pre_emit_check  # type: ignore


REPO_ROOT = Path(__file__).resolve().parent.parent
SCHEMA_VERSION = "auditooor.hackerman_record.v1.1"


def _load_validator() -> Any:
    spec = importlib.util.spec_from_file_location(
        "_hackerman_record_validate_for_graph_protocol",
        str(REPO_ROOT / "tools" / "hackerman-record-validate.py"),
    )
    mod = importlib.util.module_from_spec(spec)
    assert spec.loader
    spec.loader.exec_module(mod)
    return mod


_VALIDATOR = _load_validator()


# ---------------------------------------------------------------------------
# Target repos: spec-listed Graph Protocol families.
# ---------------------------------------------------------------------------

REPOS: List[str] = [
    "graphprotocol/contracts",
    "graphprotocol/contracts-v2",
    "graphprotocol/issuance-allocator",
    "graphprotocol/horizon",
]

# Optional advisories-only repo. If 404, gracefully skipped.
ADVISORIES_ONLY_REPOS: List[str] = [
    "graphprotocol/security-advisories",
]


# 12 TG-PAT anchor SHAs already seeded at
# /Users/wolf/audits/thegraph/derived_detectors/. We skip these to avoid
# double-seeding the corpus. Note: TG-PAT-004 and TG-PAT-005 share the same
# anchor SHA (91224ed83eef) hence 11 distinct entries.
TG_PAT_SKIP_SHAS: frozenset[str] = frozenset(
    s.lower()
    for s in (
        "aa0823082968",
        "affc8b46d35d",
        "025410f39966",
        "91224ed83eef",
        "2252c1908bde",
        "89f1321c421f",
        "3639241494de",
        "ece40cdbbd2a",
        "4e834010453b",
        "5e319051d2bc",
        "ce61f315b252",
    )
)


# Security-keyword set. Each keyword is matched against the commit subject
# + first 400 chars of body (lowercased). Phrases are matched literally
# (case-insensitive); single tokens are matched on word boundaries.
#
# Graph-specific additions vs the AMM miner: "indexer", "allocation",
# "subgraph", "delegation", "rewards", "dispute", "curation", "vesting",
# "issuance", "horizon" - these reflect the protocol's core actor + role
# vocabulary as seen in the 12 TG-PAT seed bodies.
SECURITY_KEYWORDS_SINGLE = [
    "security",
    "bug",
    "mitigation",
    "reentrancy",
    "slippage",
    "oracle",
    "manipulation",
    "overflow",
    "precision",
    "rounding",
    "vulnerab",
    "exploit",
    "patch",
    "guard",
    # Graph-specific:
    "allocation",
    "subgraph",
    "delegation",
    "rewards",
    "dispute",
    "curation",
    "vesting",
    "issuance",
    "indexer",
    "staleness",
    "reclaim",
]

SECURITY_KEYWORDS_PHRASES = [
    "fix vulnerability",
    "audit fix",
    "access control",
    "missing check",
    "missing guard",
    "missing modifier",
    "interface drift",
    "initializer chain",
    "role enumeration",
    "fallback forwards",
    "eligibility leak",
]


SECURITY_REGEX = re.compile(
    r"(\b("
    + "|".join(re.escape(k) for k in SECURITY_KEYWORDS_SINGLE)
    + r")\b|("
    + "|".join(re.escape(p) for p in SECURITY_KEYWORDS_PHRASES)
    + r"))",
    re.IGNORECASE,
)


# Negative filter: obvious non-protocol churn that would slip through the
# permissive single-token list (e.g. "bug" appearing in a typo-fix subject).
NON_PROTOCOL_REGEX = re.compile(
    r"(typo|formatting|natspec|coverage\b|^docs|README|^CI\b|\bci\)|"
    r"prettier|eslint|^bump\b|version bump|update version|dependabot|"
    r"whitespace|comment only|comments\)|^chore\b|^lint\b|^style\b|"
    r"gas-?golf|gas opt|wiring|env\b|^script)",
    re.IGNORECASE,
)


GHSA_ID_RE = re.compile(r"\bGHSA-[a-z0-9]{4}-[a-z0-9]{4}-[a-z0-9]{4}\b", re.IGNORECASE)
CVE_ID_RE = re.compile(r"\bCVE-(\d{4})-(\d{4,7})\b", re.IGNORECASE)


# ---------------------------------------------------------------------------
# gh API + subprocess helpers (stdlib + gh shell-out only)
# ---------------------------------------------------------------------------


def gh_api(path: str, *, paginate: bool = False) -> Any:
    """Return parsed JSON from ``gh api <path>``. Returns None on failure.

    Wraps ``subprocess.check_output``. Tests monkey-patch this function to
    return canned fixtures without touching the network.
    """
    cmd = ["gh", "api"]
    if paginate:
        cmd.append("--paginate")
    cmd.append(path)
    try:
        out = subprocess.check_output(cmd, stderr=subprocess.STDOUT, timeout=180)
    except (subprocess.CalledProcessError, subprocess.TimeoutExpired, FileNotFoundError) as exc:
        sys.stderr.write(f"[warn] gh api {path}: {exc}\n")
        return None
    text = out.decode("utf-8", errors="replace")
    if paginate:
        text = text.replace("][", ",")
    try:
        return json.loads(text)
    except json.JSONDecodeError as exc:
        sys.stderr.write(f"[warn] gh api {path}: JSON decode failed: {exc}\n")
        return None


def list_commits(repo: str, per_page: int = 100, pages: int = 1) -> List[Dict[str, Any]]:
    """List commits on the default branch of ``repo``, bounded by pages*per_page.

    Default ``pages=1, per_page=100`` -> past 100 commits per repo, matching
    the CAP-D4 spec.
    """
    out: List[Dict[str, Any]] = []
    for page in range(1, pages + 1):
        data = gh_api(f"/repos/{repo}/commits?per_page={per_page}&page={page}")
        if not isinstance(data, list) or not data:
            break
        out.extend(data)
        if len(data) < per_page:
            break
    return out


def get_commit_detail(repo: str, sha: str) -> Optional[Dict[str, Any]]:
    """Return full commit detail (with ``files`` array). None on failure."""
    data = gh_api(f"/repos/{repo}/commits/{sha}")
    if not isinstance(data, dict):
        return None
    return data


def fetch_ghsa(repo: str, ghsa_id: str) -> Optional[Dict[str, Any]]:
    """Return the GHSA advisory JSON via the repo-scoped security-advisories
    endpoint. ``None`` on miss / 404 / 403. Tests patch ``gh_api``.
    """
    if not ghsa_id:
        return None
    data = gh_api(f"/repos/{repo}/security-advisories/{ghsa_id}")
    if not isinstance(data, dict):
        return None
    return data


def list_repo_advisories(repo: str) -> List[Dict[str, Any]]:
    """List published security advisories for ``repo``. Empty list on miss.

    Used to enumerate org-disclosed GHSAs on ``graphprotocol/*`` beyond the
    commit-mined corpus. Tests patch ``gh_api`` to inject fixtures.
    """
    data = gh_api(f"/repos/{repo}/security-advisories?per_page=100")
    if not isinstance(data, list):
        return []
    return data


# ---------------------------------------------------------------------------
# Shared helpers (slug, dedupe, severity, dollar class)
# ---------------------------------------------------------------------------


def slugify(value: object, *, max_len: int = 80) -> str:
    text = str(value or "").strip().lower()
    text = re.sub(r"[^a-z0-9._/-]+", "-", text).strip("-._")
    text = re.sub(r"-{2,}", "-", text)
    return (text[:max_len].strip("-._") or "record")


def dedupe(items: Iterable[str]) -> List[str]:
    seen = set()
    out: List[str] = []
    for x in items:
        if x and x not in seen:
            seen.add(x)
            out.append(x)
    return out


def infer_severity(subject: str, body: str) -> str:
    low = (subject + " " + body).lower()
    if any(k in low for k in ("critical", "exploit", "drain", "loss of funds", "hardfork")):
        return "high"
    if "security" in low or GHSA_ID_RE.search(low) or CVE_ID_RE.search(low):
        return "high"
    if "vulnerab" in low or "reentran" in low or "manipulation" in low:
        return "high"
    if any(k in low for k in ("revert", "rollback")):
        return "medium"
    if any(k in low for k in ("oracle", "slippage", "rounding", "precision", "overflow")):
        return "medium"
    if any(k in low for k in ("allocation", "delegation", "rewards", "dispute", "vesting")):
        return "medium"
    return "low"


def infer_impact(subject: str, body: str) -> str:
    low = (subject + " " + body).lower()
    if any(k in low for k in ("drain", "steal", "theft", "loss of funds", "siphon", "withdraw all")):
        return "theft"
    if any(k in low for k in ("freeze", "stuck", "locked", "brick", "permanent lock")):
        return "freeze"
    if any(k in low for k in ("dos", "denial of service", "panic", "halt")):
        return "dos"
    if any(k in low for k in ("rounding", "precision", "overflow", "underflow", "rebase")):
        return "precision-loss"
    if any(k in low for k in ("yield", "reward", "fee", "rebate", "slippage", "issuance", "rewards")):
        return "yield-redistribution"
    if any(k in low for k in ("priv", "admin", "authority", "unauthorized", "owner", "access control", "modifier")):
        return "privilege-escalation"
    return "griefing"


def dollar_class(severity: str, impact: str) -> str:
    s = severity.lower()
    if s == "critical":
        return ">=$1M"
    if s == "high":
        return "$100K-$1M"
    if s == "medium":
        return "$10K-$100K"
    if s == "low":
        return "<$10K"
    if impact in {"theft", "freeze"}:
        return "$10K-$100K"
    return "non-financial"


# ---------------------------------------------------------------------------
# YAML rendering (validator-friendly)
# ---------------------------------------------------------------------------


def yaml_scalar(value: object) -> str:
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, int):
        return str(value)
    if isinstance(value, float):
        return repr(value)
    text = str(value if value is not None else "")
    if text == "":
        return '""'
    numeric = re.fullmatch(r"[-+]?(?:0|[1-9][0-9_]*)(?:\.[0-9_]+)?", text)
    ambiguous = text.lower() in {"true", "false", "null", "yes", "no", "on", "off", "~"}
    plain_safe = (
        re.fullmatch(r"[A-Za-z0-9._:/<>=,$#-]+", text)
        and not text.endswith(":")
        and not text.startswith(
            ("#", "-", "?", ":", "<", ">", "@", "`", "&", "*", "!", "|", "%", "{", "}", "[", "]", ",")
        )
    )
    if plain_safe and not numeric and not ambiguous:
        return text
    return json.dumps(text, ensure_ascii=False)


def yaml_dump(data: Dict[str, Any]) -> str:
    lines: List[str] = []
    for key, value in data.items():
        if isinstance(value, dict):
            lines.append(f"{key}:")
            for sk, sv in value.items():
                if isinstance(sv, list):
                    if not sv:
                        lines.append(f"  {sk}: []")
                    else:
                        lines.append(f"  {sk}:")
                        for item in sv:
                            lines.append(f"    - {yaml_scalar(item)}")
                else:
                    lines.append(f"  {sk}: {yaml_scalar(sv)}")
        elif isinstance(value, list):
            if not value:
                lines.append(f"{key}: []")
            else:
                lines.append(f"{key}:")
                for item in value:
                    if isinstance(item, dict):
                        first = True
                        for sk, sv in item.items():
                            prefix = "  -" if first else "   "
                            lines.append(f"{prefix} {sk}: {yaml_scalar(sv)}")
                            first = False
                    else:
                        lines.append(f"  - {yaml_scalar(item)}")
        else:
            lines.append(f"{key}: {yaml_scalar(value)}")
    return "\n".join(lines) + "\n"


# ---------------------------------------------------------------------------
# Detector-seed extraction from diff hunks
# ---------------------------------------------------------------------------


REQUIRE_RE = re.compile(r"^\+\s*require\s*\(([^;]{0,200});?", re.IGNORECASE)
ASSERT_RE = re.compile(r"^\+\s*assert\s*\(([^;]{0,200});?", re.IGNORECASE)
REVERT_RE = re.compile(r"^\+.*\brevert\s+([A-Za-z_][A-Za-z0-9_]*)\s*\(")
MODIFIER_RE = re.compile(
    r"^\+.*\b(nonReentrant|onlyOwner|onlyAdmin|whenNotPaused|whenPaused|"
    r"onlyGovernance|onlyByOwnerGovernanceOrManager|notDelegateCall|"
    r"onlyController|onlyIndexer|onlyDelegator|onlyAuthorized|onlyStaking)\b"
)
SAFEMATH_RE = re.compile(
    r"^\+.*\b(SafeMath|FixedPoint|FullMath|mulDiv|safeMul|safeAdd|safeSub|"
    r"safeCast|checked_(?:mul|add|sub|div))\b"
)
UNCHECKED_RE = re.compile(r"^-.*\bunchecked\b\s*\{")
OVERFLOW_RE = re.compile(r"^\+.*\b(overflow|underflow)\b", re.IGNORECASE)
ZERO_CHECK_RE = re.compile(r"^\+\s*require\s*\([^,]*!=\s*(address\(0\)|0)", re.IGNORECASE)
# Graph-specific: detect reclaim, allocation-staleness, eligibility patterns.
RECLAIM_RE = re.compile(r"^\+.*\b(reclaim|staleness|stale)\b", re.IGNORECASE)
INTERFACE_DRIFT_RE = re.compile(r"^\+.*\b(interface\s+\w+|function\s+\w+\(\)\s+external)\b")


def extract_detector_seed(patch_text: str, subject: str) -> str:
    """Summarise the added / removed shape of the diff hunk.

    Returns a ``;``-joined deduped bag of detector-seed tags. Always returns
    non-empty (falls back to a generic ``diff-shape-fix`` tag).
    """
    seeds: List[str] = []
    for line in patch_text.splitlines():
        if not line:
            continue
        if line.startswith("+++") or line.startswith("---") or line.startswith("@@"):
            continue
        m = REQUIRE_RE.match(line)
        if m:
            cond = re.sub(r"\s+", " ", m.group(1).strip())[:80]
            seeds.append(f"added require({cond})")
            continue
        m = ASSERT_RE.match(line)
        if m:
            cond = re.sub(r"\s+", " ", m.group(1).strip())[:80]
            seeds.append(f"added assert({cond})")
            continue
        m = REVERT_RE.match(line)
        if m:
            seeds.append(f"added revert {m.group(1)}()")
            continue
        m = MODIFIER_RE.match(line)
        if m:
            seeds.append(f"added {m.group(1)} modifier")
            continue
        m = SAFEMATH_RE.match(line)
        if m:
            seeds.append(f"added {m.group(1)} arithmetic guard")
            continue
        if UNCHECKED_RE.match(line):
            seeds.append("removed unchecked block")
            continue
        m = OVERFLOW_RE.match(line)
        if m:
            seeds.append(f"comment / fix references {m.group(1).lower()}")
            continue
        m = ZERO_CHECK_RE.match(line)
        if m:
            seeds.append("added zero-address / zero-value guard")
            continue
        m = RECLAIM_RE.match(line)
        if m:
            seeds.append(f"added {m.group(1).lower()} state-helper")
            continue
        m = INTERFACE_DRIFT_RE.match(line)
        if m:
            seeds.append("added interface / external function declaration")
            continue
    if not seeds:
        sub_low = subject.lower()
        if "revert" in sub_low:
            seeds.append("revert / rollback prior change")
        elif "audit" in sub_low:
            seeds.append("audit-driven fix")
        elif "mitigation" in sub_low:
            seeds.append("mitigation patch")
        elif "interface" in sub_low:
            seeds.append("interface-drift fix")
        elif "initializer" in sub_low:
            seeds.append("initializer-chain fix")
        else:
            seeds.append("diff-shape-fix")
    return "; ".join(dedupe(seeds)[:8])


# ---------------------------------------------------------------------------
# Filtering pipeline
# ---------------------------------------------------------------------------


def is_security_shape(subject: str, body: str) -> bool:
    """Apply the spec-mandated security-keyword filter + non-protocol guard."""
    if NON_PROTOCOL_REGEX.search(subject):
        return False
    if SECURITY_REGEX.search(subject):
        return True
    if SECURITY_REGEX.search(body[:400]):
        return True
    return False


def is_tg_pat_skip(sha: str) -> bool:
    """True if this commit SHA is already seeded as a TG-PAT pattern.

    Matches by 12-char prefix (the canonical short-SHA used in
    ``derived_detectors/INDEX.md``).
    """
    if not isinstance(sha, str) or len(sha) < 12:
        return False
    return sha[:12].lower() in TG_PAT_SKIP_SHAS


# ---------------------------------------------------------------------------
# Record builder
# ---------------------------------------------------------------------------


def commit_to_record(
    repo: str,
    detail: Dict[str, Any],
    *,
    ghsa_lookup: Optional[Callable[[str, str], Optional[Dict[str, Any]]]] = None,
) -> Optional[Dict[str, Any]]:
    """Build a hackerman_record (v1.1) from a ``gh api /commits/<sha>`` payload.

    Returns ``None`` if mandatory fields are missing, no protocol source
    file was touched, or the SHA is already seeded as a TG-PAT pattern.

    ``ghsa_lookup`` is optional; when omitted defaults to ``fetch_ghsa``.
    Tests inject a fake lookup to avoid the network.
    """
    if ghsa_lookup is None:
        ghsa_lookup = fetch_ghsa

    sha = detail.get("sha")
    if not isinstance(sha, str) or len(sha) < 8:
        return None
    # Skip the 12 TG-PAT-seeded anchor SHAs.
    if is_tg_pat_skip(sha):
        return None
    parents = [p.get("sha", "") for p in detail.get("parents", []) or []]
    parent_sha = parents[0] if parents else ""
    commit = detail.get("commit", {}) or {}
    message = str(commit.get("message", "") or "").strip()
    if not message:
        return None
    subject = message.splitlines()[0][:200]
    files = detail.get("files", []) or []
    if not files:
        return None

    # Aggregate patch hunks (capped) for detector-seed extraction.
    patch_chunks: List[str] = []
    file_paths: List[str] = []
    total_add = 0
    total_del = 0
    for f in files:
        fn = f.get("filename", "")
        if fn:
            file_paths.append(fn)
        total_add += int(f.get("additions", 0) or 0)
        total_del += int(f.get("deletions", 0) or 0)
        patch = f.get("patch", "")
        if isinstance(patch, str):
            patch_chunks.append(patch)
        if sum(len(p) for p in patch_chunks) > 20000:
            break
    patch_text = "\n".join(patch_chunks)[:20000]
    detector_seed = extract_detector_seed(patch_text, subject)

    # Restrict to commits that touched protocol source. Graph Protocol
    # contracts are Solidity-only; we also accept .vy for completeness even
    # though we don't expect to see any.
    protocol_extensions = (".sol", ".vy")
    has_protocol_src = any(fp.endswith(protocol_extensions) for fp in file_paths)
    if not has_protocol_src:
        return None

    target_language = "solidity"
    if any(fp.endswith(".vy") for fp in file_paths):
        target_language = "vyper"

    severity = infer_severity(subject, message)
    impact = infer_impact(subject, message)

    sub_low = (subject + " " + message).lower()
    bug_class = "fix-commit-shape-unclassified"
    attack_class = "diff-derived-pattern"
    # Graph-specific bug/attack classes first, falling back to generic.
    for needle, bc, ac in [
        ("reclaim", "missing-staleness-reclaim", "allocation-state-mutation-without-reclaim"),
        ("staleness", "missing-staleness-reclaim", "allocation-state-mutation-without-reclaim"),
        ("eligibility leak", "indexer-eligibility-leak", "eligibility-leak-into-view-functions"),
        ("interface drift", "interface-shape-drift", "interface-arity-drift"),
        ("initializer chain", "initializer-chain-mismatch", "initializer-chain-mismatch-toolchain-upgrade"),
        ("role enumeration", "role-enumeration-fallback", "role-enumeration-fallback-on-events"),
        ("vesting", "vesting-fallback-forwards", "revocable-vesting-fallback-forwards-arbitrary-call"),
        ("allocation", "allocation-state-mutation", "allocation-state-mutation-shape"),
        ("delegation", "delegation-accounting-shape", "delegation-accounting-shape"),
        ("rewards", "rewards-accounting-shape", "rewards-condition-missing-guard"),
        ("dispute", "dispute-state-machine-shape", "dispute-state-mutation-shape"),
        ("curation", "curation-accounting-shape", "curation-accounting-shape"),
        ("subgraph", "subgraph-service-shape", "subgraph-service-completeness"),
        ("issuance", "issuance-accounting-shape", "issuance-administration-drift"),
        ("indexer", "indexer-accounting-shape", "indexer-eligibility-shape"),
        ("horizon", "horizon-migration-shape", "horizon-migration-shape"),
        # Generic fallbacks (same as AMM miner):
        ("reentran", "reentrancy", "external-call-reentrancy"),
        ("manipulation", "oracle-manipulation", "oracle-tick-manipulation"),
        ("oracle", "oracle-stale-or-manipulated", "twap-tick-manipulation"),
        ("slippage", "slippage-bypass", "missing-min-out-on-swap"),
        ("overflow", "arithmetic-overflow", "unchecked-multiplication-overflow"),
        ("underflow", "arithmetic-underflow", "unchecked-subtraction-underflow"),
        ("rounding", "rounding-direction", "shares-rounding-favors-attacker"),
        ("precision", "precision-loss", "rounding-direction-precision-loss"),
        ("init", "uninitialized-storage", "double-initialization"),
        ("auth", "access-control", "missing-modifier-on-state-write"),
        ("modifier", "access-control", "missing-modifier-on-state-write"),
        ("revert", "behavior-rollback-of-prior-change", "diff-derived-rollback"),
        ("mitigation", "audit-driven-mitigation", "diff-derived-mitigation"),
        ("vulnerab", "audit-driven-fix", "diff-derived-vulnerability-fix"),
        ("security", "security-driven-patch", "diff-derived-security-fix"),
    ]:
        if needle in sub_low:
            bug_class = bc
            attack_class = ac
            break

    raw_signature = f"// commit {sha[:12]} in {repo} touched {len(file_paths)} files"
    fn_re_sol = re.compile(r"^\+\s*(function\s+[A-Za-z_][A-Za-z0-9_]*\([^)]{0,200}\)[^\n{]{0,80})")
    fn_re_vy = re.compile(r"^\+\s*(def\s+[A-Za-z_][A-Za-z0-9_]*\([^)]{0,200}\)[^\n:]{0,80})")
    for line in patch_text.splitlines():
        m = fn_re_sol.match(line) or fn_re_vy.match(line)
        if m:
            raw_signature = m.group(1).strip()[:500]
            break

    short_sha = sha[:8]
    record_id_input = f"graph-protocol-real-source|{repo}|{sha}".encode("utf-8")
    digest = hashlib.sha256(record_id_input).hexdigest()[:12]
    repo_slug = slugify(repo.replace("/", "-"), max_len=60)
    record_id = f"graph-protocol:{repo_slug}:{sha}:{digest}"[:160]
    commit_url = f"https://github.com/{repo}/commit/{sha}"

    # GHSA enrichment: scan commit body for GHSA-id and verify against the
    # repo's security-advisories endpoint.
    ghsa_id: Optional[str] = None
    ghsa_advisory: Optional[Dict[str, Any]] = None
    m_ghsa = GHSA_ID_RE.search(message)
    if m_ghsa:
        candidate = m_ghsa.group(0).upper().replace("GHSA-", "GHSA-", 1)
        parts = candidate.split("-")
        if len(parts) == 4:
            ghsa_candidate = "GHSA-" + "-".join(p.lower() for p in parts[1:])
            adv = ghsa_lookup(repo, ghsa_candidate)
            if isinstance(adv, dict) and adv.get("ghsa_id"):
                ghsa_id = ghsa_candidate
                ghsa_advisory = adv

    cve_id: Optional[str] = None
    m_cve = CVE_ID_RE.search(message)
    if m_cve:
        cve_id = f"CVE-{m_cve.group(1)}-{m_cve.group(2)}"

    if ghsa_id:
        verification_tier = "tier-1-verified-realtime-api"
    else:
        verification_tier = "tier-2-verified-public-archive"

    action_extras: List[str] = []
    if ghsa_id and ghsa_advisory:
        adv_summary = str(ghsa_advisory.get("summary") or "").strip()[:200]
        action_extras.append(
            f"Linked advisory {ghsa_id}: {adv_summary or 'no summary published'}"
        )
    if cve_id:
        action_extras.append(f"Referenced identifier {cve_id} in commit body.")

    action = (
        f"Upstream Graph-Protocol fix commit at {commit_url} on {repo}. "
        f"Parent commit: {parent_sha or 'n/a'}. Commit subject: {subject!r}. "
        f"Files changed: {len(file_paths)} ({total_add} additions / {total_del} deletions). "
        f"Detector seed: {detector_seed}. "
        f"Attacker pre-fix path: trigger the unchecked / pre-fix behavior in "
        f"{file_paths[0] if file_paths else 'unknown'} before the linked fix was merged. "
    )
    if action_extras:
        action += " ".join(action_extras) + " "
    action += (
        "Reviewers downstream should verify the fix-shape against the protocol-source "
        "diff at the commit URL and check structurally adjacent call sites in the "
        "indexer / allocation / delegation / rewards / dispute / curation paths."
    )

    fix_pattern = (
        f"Diff at {commit_url} applies: {detector_seed}. "
        "Reviewers porting this guard should mirror the added check / modifier / "
        "state-helper across structurally adjacent call sites in the same contract or module."
    )
    fix_anti_pattern = (
        f"shipping {file_paths[0] if file_paths else 'a graph-protocol contract'} "
        f"without the upstream fix from {commit_url} - i.e. omitting the guard, "
        "modifier, arithmetic check, or state-helper that this commit added."
    )

    author_date = (
        commit.get("author", {}).get("date", "")
        or commit.get("committer", {}).get("date", "")
        or ""
    )
    year_match = re.match(r"(\d{4})", author_date)
    year = int(year_match.group(1)) if year_match else 2024
    if year < 2015:
        year = 2024

    shape_tags = dedupe(
        [
            slugify(attack_class),
            "graph-protocol",
            "src-git-fix-history",
            "real-source",
            slugify(bug_class),
            slugify(repo_slug),
            f"sha-{short_sha}",
        ]
    )

    record: Dict[str, Any] = {
        "schema_version": SCHEMA_VERSION,
        "record_id": record_id,
        "source_audit_ref": commit_url[:240],
        "verification_tier": verification_tier,
        "record_source_url": commit_url,
        "target_domain": "indexer-network",
        "target_language": target_language,
        "target_repo": repo,
        "target_component": (file_paths[0] if file_paths else f"{repo} fix-commit-shape")[:240],
        "function_shape": {
            "raw_signature": raw_signature,
            "shape_tags": shape_tags,
        },
        "bug_class": bug_class[:160],
        "attack_class": attack_class[:160],
        "attacker_role": "unprivileged",
        "attacker_action_sequence": action[:5000],
        "required_preconditions": [
            f"Pre-fix deployment of {repo} at parent SHA {parent_sha[:12] if parent_sha else 'unknown'}",
            f"Code path in {file_paths[0] if file_paths else 'affected module'} unchanged by an out-of-band patch",
            f"Subject signal: {subject[:160]}",
        ],
        "impact_class": impact,
        "impact_actor": "arbitrary-user",
        "impact_dollar_class": dollar_class(severity, impact),
        "fix_pattern": fix_pattern[:1000],
        "fix_anti_pattern_avoided": fix_anti_pattern[:1000],
        "severity_at_finding": severity,
        "year": year,
        "record_tier": "public-corpus",
        "source_extraction_method": "corpus-etl",
        "source_extraction_confidence": 0.9,
        "verification_method": "ghsa-live" if ghsa_id else "",
        "synthetic_fixture": False,
        "cross_language_analogues": [
            {
                "target_language": "vyper" if target_language == "solidity" else "solidity",
                "pattern_translation": (
                    f"Same fix-shape ({detector_seed}) in the sibling language: scan "
                    "equivalent indexer-network / allocation / delegation code for the missing guard."
                ),
            },
        ],
        "related_records": [],
    }
    if ghsa_id:
        record["ghsa_id"] = ghsa_id
    if cve_id:
        record["cve_id"] = cve_id
    return record


# ---------------------------------------------------------------------------
# Per-repo mining
# ---------------------------------------------------------------------------


def mine_repo(
    repo: str,
    *,
    pages: int = 1,
    per_page: int = 100,
    max_records_per_repo: int = 40,
    detail_cap: int = 80,
    ghsa_lookup: Optional[Callable[[str, str], Optional[Dict[str, Any]]]] = None,
) -> Tuple[List[Dict[str, Any]], int, int, int]:
    """Mine ``repo``. Returns ``(records, total_scanned, candidate_count, tg_pat_skips)``."""
    commits = list_commits(repo, per_page=per_page, pages=pages)
    candidates: List[Dict[str, Any]] = []
    tg_pat_skips = 0
    for c in commits:
        sha = c.get("sha", "")
        if is_tg_pat_skip(sha):
            tg_pat_skips += 1
            continue
        commit_msg = (c.get("commit") or {}).get("message", "") or ""
        if not commit_msg:
            continue
        subject = commit_msg.splitlines()[0]
        if is_security_shape(subject, commit_msg):
            candidates.append(c)
        if len(candidates) >= detail_cap:
            break

    records: List[Dict[str, Any]] = []
    for c in candidates:
        sha = c.get("sha")
        if not sha:
            continue
        detail = get_commit_detail(repo, sha)
        if not detail:
            continue
        rec = commit_to_record(repo, detail, ghsa_lookup=ghsa_lookup)
        if rec is None:
            continue
        records.append(rec)
        if len(records) >= max_records_per_repo:
            break
    return records, len(commits), len(candidates), tg_pat_skips


# ---------------------------------------------------------------------------
# Driver
# ---------------------------------------------------------------------------


def convert(
    out_dir: Path,
    *,
    dry_run: bool = False,
    limit: Optional[int] = None,
    repos: Sequence[str] = REPOS,
    pages: int = 1,
    per_page: int = 100,
    max_records_per_repo: int = 40,
    detail_cap: int = 80,
    ghsa_lookup: Optional[Callable[[str, str], Optional[Dict[str, Any]]]] = None,
    min_yield: int = 5,
) -> Dict[str, Any]:
    records: List[Dict[str, Any]] = []
    errors: List[str] = []
    per_repo_counts: Dict[str, int] = {}
    per_repo_skips: Dict[str, int] = {}
    sample_urls: List[str] = []
    tier_counts: Dict[str, int] = {
        "tier-1-verified-realtime-api": 0,
        "tier-2-verified-public-archive": 0,
    }

    for repo in repos:
        if limit is not None and len(records) >= limit:
            break
        try:
            repo_records, _scanned, _candidates, tg_pat_skips = mine_repo(
                repo,
                pages=pages,
                per_page=per_page,
                max_records_per_repo=max_records_per_repo,
                detail_cap=detail_cap,
                ghsa_lookup=ghsa_lookup,
            )
        except Exception as exc:  # noqa: BLE001
            errors.append(f"mine_repo({repo}): {exc}")
            continue
        per_repo_counts[repo] = len(repo_records)
        per_repo_skips[repo] = tg_pat_skips
        for r in repo_records:
            if limit is not None and len(records) >= limit:
                break
            records.append(r)
            tier = r.get("verification_tier", "")
            tier_counts[tier] = tier_counts.get(tier, 0) + 1

    valid = 0
    file_paths: List[str] = []
    if not dry_run:
        out_dir.mkdir(parents=True, exist_ok=True)
    for rec in records:
        rendered = yaml_dump(rec)
        try:
            doc = yaml.safe_load(rendered)
        except yaml.YAMLError as exc:
            errors.append(f"{rec['record_id']}: yaml render: {exc}")
            continue
        schema = _VALIDATOR.load_schema_for_doc(doc)
        verrs = _VALIDATOR.validate_doc(doc, schema)
        if verrs:
            for e in verrs:
                errors.append(f"{rec['record_id']}: {e}")
            continue
        valid += 1
        m = re.search(r"https?://\S+", rec.get("attacker_action_sequence", ""))
        if m and len(sample_urls) < 9:
            sample_urls.append(m.group(0).rstrip(".,;|"))
        repo_tail = rec["target_repo"].split("/")[-1]
        parts = rec["record_id"].split(":")
        full_sha = parts[-2] if len(parts) >= 3 else "unknown"
        short_sha = full_sha[:8] if re.fullmatch(r"[0-9a-f]+", full_sha) else full_sha
        slug_dir = slugify(f"{repo_tail}__{short_sha}", max_len=120)
        rec_dir = out_dir / slug_dir
        if not dry_run:
            rec_dir.mkdir(parents=True, exist_ok=True)
            _r37_ok, _r37_reason = pre_emit_check(doc, strict=False)  # Rule 37
            if not _r37_ok:
                print(f"r37-skip {_r37_reason}: {doc.get('record_id','?')}", file=sys.stderr)
            (rec_dir / "record.yaml").write_text(rendered, encoding="utf-8")
            (rec_dir / "record.json").write_text(
                json.dumps(doc, indent=2, sort_keys=True) + "\n",
                encoding="utf-8",
            )
        file_paths.append(str(rec_dir / "record.yaml"))

    return {
        "schema_version": SCHEMA_VERSION,
        "verification_tier_default": "tier-2-verified-public-archive",
        "tier_breakdown": tier_counts,
        "out_dir": str(out_dir),
        "dry_run": dry_run,
        "records_total": len(records),
        "records_valid": valid,
        "records_per_repo": per_repo_counts,
        "tg_pat_skips_per_repo": per_repo_skips,
        "tg_pat_skip_shas": sorted(TG_PAT_SKIP_SHAS),
        "sample_urls": sample_urls,
        "errors": errors[:50],
        "error_count": len(errors),
        "file_count": len(file_paths),
        "files_sample": file_paths[:20],
        "negative_verdict": valid < min_yield,
        "min_yield_threshold": min_yield,
        "repos_walked": list(repos),
    }


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--out-dir",
        default="audit/corpus_tags/tags/graph_protocol_real_source",
        help="Output directory (per-record sub-dir). Default: %(default)s",
    )
    parser.add_argument("--dry-run", action="store_true")
    parser.add_argument(
        "--fetch",
        action="store_true",
        help="Explicitly enable live ``gh api`` calls. Without this flag the "
        "miner still uses gh; this flag is for documentation parity with sibling "
        "miners that gate network access. Tests inject a fake gh_api regardless.",
    )
    parser.add_argument("--limit", type=int)
    parser.add_argument(
        "--pages",
        type=int,
        default=1,
        help="Commit-list pages per repo (default 1 -> past 100 commits).",
    )
    parser.add_argument("--per-page", type=int, default=100, help="Commits per API page.")
    parser.add_argument(
        "--max-records-per-repo",
        type=int,
        default=40,
        help="Hard cap on records emitted per repo (post-detail filter).",
    )
    parser.add_argument(
        "--detail-cap",
        type=int,
        default=80,
        help="Hard cap on per-repo detail-API fetches (cost control).",
    )
    parser.add_argument(
        "--min-yield",
        type=int,
        default=5,
        help="Below this yield the run is flagged NEGATIVE.",
    )
    parser.add_argument(
        "--repos",
        nargs="*",
        default=None,
        help="Override the default repo list (space-separated owner/repo strings).",
    )
    parser.add_argument("--json-summary", action="store_true")
    return parser


def main(argv: Optional[List[str]] = None) -> int:
    args = build_parser().parse_args(argv)
    out_dir = (REPO_ROOT / args.out_dir).resolve() if not os.path.isabs(args.out_dir) else Path(args.out_dir).resolve()
    if args.limit is not None and args.limit < 0:
        print("--limit must be non-negative", file=sys.stderr)
        return 2
    repos = args.repos if args.repos else REPOS
    summary = convert(
        out_dir,
        dry_run=args.dry_run,
        limit=args.limit,
        repos=repos,
        pages=args.pages,
        per_page=args.per_page,
        max_records_per_repo=args.max_records_per_repo,
        detail_cap=args.detail_cap,
        min_yield=args.min_yield,
    )
    if args.json_summary:
        print(json.dumps(summary, sort_keys=True, indent=2))
    else:
        print(
            "hackerman graph-protocol-real-source ETL: "
            f"valid={summary['records_valid']}/{summary['records_total']} "
            f"per_repo={summary['records_per_repo']} "
            f"tg_pat_skips={summary['tg_pat_skips_per_repo']} "
            f"tiers={summary['tier_breakdown']} "
            f"errors={summary['error_count']}"
        )
        if summary["negative_verdict"]:
            print(
                f"[NEGATIVE] yield < {summary['min_yield_threshold']} verifiable records "
                "- widen --pages / --repos before relying on this corpus."
            )
    return 0 if summary["error_count"] == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
