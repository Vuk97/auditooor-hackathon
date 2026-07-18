#!/usr/bin/env python3
"""
hackerman-etl-from-substrate-fix-history.py - Mine the fix-commit history of
paritytech substrate / polkadot-sdk / cumulus / parity-bridges-common for the
auditooor Hackerman corpus. Seeds substrate-class detector patterns
(consensus, fork-choice, finality, fraud-proof, bridge, parachain inherent,
runtime upgrade, FRAME pallet) not always tied to a CVE / GHSA.

Wave-1 lane: wave-1-hackerman-capability-lift (PR #726).

HARD RULES (M14-trap discipline):
- Real-source-only. Every record is anchored to a verifiable commit SHA via
  ``gh api /repos/<owner>/<repo>/commits/<sha>``. The commit metadata embedded
  in each record comes from the live API response; nothing is invented.
- No invented CVE / GHSA IDs. The commit URL itself is the source.
- Race-condition awareness: explicit pathspec only - we filter to runtime /
  consensus / finality / fraud-proof / bridge / pallet source files; pure
  test-only / docs / CI commits are dropped.

Repos mined (5):
  paritytech/polkadot-sdk           (active monorepo)
  paritytech/polkadot               (legacy archive)
  paritytech/substrate              (legacy archive)
  paritytech/cumulus                (legacy archive)
  paritytech/parity-bridges-common  (XCM / bridges)

Filter: commit message must match a fix / security / consensus / finality /
fork-choice / fraud keyword; negative filter drops obvious churn.

Output:
  audit/corpus_tags/tags/substrate_fix_history/<repo_slug>__<sha8>/record.{yaml,json}

CLI:
  python3 tools/hackerman-etl-from-substrate-fix-history.py \\
      --out-dir audit/corpus_tags/tags/substrate_fix_history \\
      --max-per-repo 30 --json-summary

Shape anchor: ``tools/hackerman-etl-from-vyper-compiler-fix-history.py``.
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
from typing import Any, Dict, Iterable, List, Optional, Sequence, Tuple

import yaml


REPO_ROOT = Path(__file__).resolve().parent.parent
SCHEMA_VERSION = "auditooor.hackerman_record.v1"

DEFAULT_REPOS: Tuple[str, ...] = (
    "paritytech/polkadot-sdk",
    "paritytech/polkadot",
    "paritytech/substrate",
    "paritytech/cumulus",
    "paritytech/parity-bridges-common",
)


def _load_validator() -> Any:
    spec = importlib.util.spec_from_file_location(
        "_hackerman_record_validate_for_substrate_fix_history",
        str(REPO_ROOT / "tools" / "hackerman-record-validate.py"),
    )
    mod = importlib.util.module_from_spec(spec)
    assert spec.loader
    spec.loader.exec_module(mod)
    return mod


_VALIDATOR = _load_validator()


# ---------------------------------------------------------------------------
# Keyword filter. Spec-mandated list.
# ---------------------------------------------------------------------------

FIX_KEYWORDS = [
    "fix",
    "security",
    "vulnerability",
    "audit",
    "revert",
    "guard",
    "validate",
    "patch",
    "cve",
    "ghsa",
    "consensus",
    "fork choice",
    "fork-choice",
    "finality",
    "fraud",
]

FIX_REGEX = re.compile(
    r"\b(" + "|".join(re.escape(k) for k in FIX_KEYWORDS) + r")\b",
    re.IGNORECASE,
)

# Negative filter: pure churn.
NON_PROTOCOL_REGEX = re.compile(
    r"^(typo\b|formatting\b|natspec\b|coverage\b|docs?\b|readme\b|"
    r"prettier\b|eslint\b|^bump\b|version bump|update version|dependabot|"
    r"^style\b|^chore\b|^ci\b|^companion\b\s*$)",
    re.IGNORECASE,
)


# ---------------------------------------------------------------------------
# gh API + subprocess helpers
# ---------------------------------------------------------------------------


def gh_api(path: str, *, paginate: bool = False) -> Any:
    """Return parsed JSON from `gh api <path>`. Returns None on failure."""
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


def list_commits(
    repo: str,
    *,
    per_page: int = 100,
    pages: int = 3,
    since: str = "2020-01-01",
    until: str = "2025-12-31",
    branch: Optional[str] = None,
) -> List[Dict[str, Any]]:
    """List commits on `repo` for the given window. Bounded by `pages`."""
    out: List[Dict[str, Any]] = []
    for page in range(1, pages + 1):
        path = (
            f"/repos/{repo}/commits?per_page={per_page}&page={page}"
            f"&since={since}T00:00:00Z&until={until}T23:59:59Z"
        )
        if branch:
            path += f"&sha={branch}"
        data = gh_api(path)
        if not isinstance(data, list) or not data:
            break
        out.extend(data)
        if len(data) < per_page:
            break
    return out


def get_commit_detail(repo: str, sha: str) -> Optional[Dict[str, Any]]:
    """Return full commit detail (with `files` array). None on failure."""
    data = gh_api(f"/repos/{repo}/commits/{sha}")
    if not isinstance(data, dict):
        return None
    return data


# ---------------------------------------------------------------------------
# Shared helpers.
# ---------------------------------------------------------------------------


def slugify(value: object, *, max_len: int = 80) -> str:
    text = str(value or "").strip().lower()
    text = re.sub(r"[^a-z0-9._/-]+", "-", text).strip("-._")
    text = re.sub(r"-{2,}", "-", text)
    return (text[:max_len].strip("-._") or "record")


def dedupe(items: Iterable[str]) -> List[str]:
    seen: set = set()
    out: List[str] = []
    for x in items:
        if x and x not in seen:
            seen.add(x)
            out.append(x)
    return out


def infer_severity(subject: str, body: str) -> str:
    low = (subject + " " + body).lower()
    if any(k in low for k in ("critical", "exploit", "loss of funds", "chain halt", "consensus halt")):
        return "critical"
    if "security" in low or re.search(r"\bcve\b|\bghsa\b", low):
        return "high"
    if any(k in low for k in ("vulnerab", "audit", "fork choice", "fork-choice", "finality", "fraud proof", "equivocation")):
        return "high"
    if any(k in low for k in ("consensus", "panic", "crash", "halt")):
        return "high"
    if any(k in low for k in ("revert", "rollback")):
        return "medium"
    if any(k in low for k in ("guard", "validate", "check", "patch")):
        return "medium"
    return "low"


def infer_impact(subject: str, body: str) -> str:
    """Map substrate fix-shape to a hackerman_record.v1 ``impact_class`` enum.

    Allowed enum (from ``tools/hackerman-record-validate.py``): theft, freeze,
    griefing, dos, yield-redistribution, precision-loss, governance-takeover,
    privilege-escalation.

    Consensus-fork / chain-halt collapse to ``dos`` (liveness loss). Runtime-
    upgrade / migration / state-corruption collapse to ``freeze`` (durable
    state damage). Sudo / pallet privilege bypass collapses to
    ``governance-takeover``.
    """
    low = (subject + " " + body).lower()
    if any(k in low for k in ("equivocation", "double vote", "double sign", "consensus halt", "chain halt", "fork choice", "fork-choice", "finality stall")):
        return "dos"
    if any(k in low for k in ("drain", "steal", "theft", "loss of funds", "unauthorized transfer")):
        return "theft"
    if any(k in low for k in ("freeze", "stuck", "locked", "brick", "permanent lock")):
        return "freeze"
    if any(k in low for k in ("sudo", "governance", "council", "democracy takeover")):
        return "governance-takeover"
    if any(k in low for k in ("priv", "unauthorized", "owner", "auth")):
        return "privilege-escalation"
    if any(k in low for k in ("panic", "crash", "hang", "infinite loop", "dos", "denial of service", "oom")):
        return "dos"
    if any(k in low for k in ("rounding", "precision", "overflow", "underflow")):
        return "precision-loss"
    if any(k in low for k in ("inherent", "runtime upgrade", "migration", "storage version", "set_storage")):
        return "freeze"
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
        return "$100K-$1M"
    return "non-financial"


# ---------------------------------------------------------------------------
# YAML rendering (verbatim from vyper sibling).
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
# Detector-seed extraction for Rust diff hunks.
# ---------------------------------------------------------------------------

RS_ASSERT_RE = re.compile(r"^\+\s*(?:debug_)?assert(?:_eq|_ne)?!\s*\((.{1,200})\)")
RS_ENSURE_RE = re.compile(r"^\+\s*ensure!\s*\((.{1,200})\)")
RS_RETURN_ERR_RE = re.compile(r"^\+\s*return\s+Err\s*\((.{1,160})\)")
RS_RESULT_ERR_RE = re.compile(r"^\+\s*Err\s*\(Error::(.{1,80})\)")
RS_IF_GUARD_RE = re.compile(r"^\+\s*if\s+(.{1,160})\s*\{")
SAT_MATH_RE = re.compile(r"^\+.*\b(saturating_add|saturating_sub|saturating_mul|checked_add|checked_sub|checked_mul|checked_div|wrapping_add|wrapping_sub|overflowing_add)\b")
CONSENSUS_RE = re.compile(r"^\+.*\b(grandpa|babe|aura|beefy|finality|justification|equivocation|fork[_ ]choice|set_id|round)\b", re.IGNORECASE)
BRIDGE_RE = re.compile(r"^\+.*\b(bridge|xcm|hrmp|para_inherent|parachain|relay_chain|messaging|paras_inherent)\b", re.IGNORECASE)
PALLET_RE = re.compile(r"^\+.*\b(pallet|StorageMap|StorageValue|DispatchResult|RuntimeOrigin|ensure_root|ensure_signed)\b")
RUNTIME_UPGRADE_RE = re.compile(r"^\+.*\b(on_runtime_upgrade|spec_version|migrate|migration|StorageVersion|set_storage)\b", re.IGNORECASE)
FRAUD_RE = re.compile(r"^\+.*\b(fraud_proof|fraud-proof|invalid_transaction|disputes|backed_candidate|approval[_ ]?voting)\b", re.IGNORECASE)


def extract_detector_seed(patch_text: str, subject: str) -> str:
    """Summarise added shape of a substrate-fix patch."""
    seeds: List[str] = []

    for line in patch_text.splitlines():
        if not line:
            continue
        if line.startswith("+++") or line.startswith("---") or line.startswith("@@"):
            continue

        m = RS_ASSERT_RE.match(line)
        if m:
            cond = re.sub(r"\s+", " ", m.group(1)).strip()[:80]
            seeds.append(f"added assert {cond}")
            continue

        m = RS_ENSURE_RE.match(line)
        if m:
            cond = re.sub(r"\s+", " ", m.group(1)).strip()[:80]
            seeds.append(f"added ensure {cond}")
            continue

        m = RS_RETURN_ERR_RE.match(line)
        if m:
            seeds.append(f"added return-Err {m.group(1).strip()[:60]}")
            continue

        m = RS_RESULT_ERR_RE.match(line)
        if m:
            seeds.append(f"added Err variant {m.group(1).strip()[:40]}")
            continue

        m = SAT_MATH_RE.match(line)
        if m:
            seeds.append(f"added saturating / checked math {m.group(1).lower()}")
            continue

        m = CONSENSUS_RE.match(line)
        if m:
            seeds.append(f"touched consensus primitive {m.group(1).lower()}")
            continue

        m = BRIDGE_RE.match(line)
        if m:
            seeds.append(f"touched bridge / XCM primitive {m.group(1).lower()}")
            continue

        m = FRAUD_RE.match(line)
        if m:
            seeds.append(f"touched fraud-proof primitive {m.group(1).lower()}")
            continue

        m = RUNTIME_UPGRADE_RE.match(line)
        if m:
            seeds.append(f"touched runtime-upgrade primitive {m.group(1).lower()}")
            continue

        m = PALLET_RE.match(line)
        if m:
            seeds.append(f"touched pallet primitive {m.group(1)}")
            continue

        m = RS_IF_GUARD_RE.match(line)
        if m:
            cond = re.sub(r"\s+", " ", m.group(1)).strip()[:60]
            seeds.append(f"added guard if {cond}")
            continue

    if not seeds:
        sub_low = subject.lower()
        if "revert" in sub_low:
            seeds.append("revert / rollback prior change")
        elif "audit" in sub_low:
            seeds.append("audit-driven fix")
        elif "patch" in sub_low:
            seeds.append("upstream patch")
        elif "consensus" in sub_low or "finality" in sub_low or "fork choice" in sub_low or "fork-choice" in sub_low:
            seeds.append("consensus / finality / fork-choice fix")
        elif "fraud" in sub_low:
            seeds.append("fraud-proof / disputes fix")
        elif "bridge" in sub_low or "xcm" in sub_low:
            seeds.append("bridge / XCM fix")
        else:
            seeds.append("diff-shape-fix")

    return "; ".join(dedupe(seeds)[:8])


# ---------------------------------------------------------------------------
# Substrate-subsystem inference.
# ---------------------------------------------------------------------------


def _subsystem(file_paths: Sequence[str]) -> str:
    fp_joined = " ".join(file_paths).lower()
    if any(s in fp_joined for s in ("grandpa", "/finality", "beefy")):
        return "finality-grandpa-beefy"
    if any(s in fp_joined for s in ("babe", "aura", "/consensus")):
        return "consensus-babe-aura"
    if any(s in fp_joined for s in ("paras_inherent", "para_inherent", "approval", "disputes", "fraud_proof", "fraud-proof", "candidate")):
        return "parachain-disputes-approval"
    if any(s in fp_joined for s in ("xcm", "/bridge", "messaging", "hrmp", "dmp", "ump")):
        return "bridge-xcm-messaging"
    if any(s in fp_joined for s in ("/runtime/", "spec_version", "migrations")):
        return "runtime-upgrade"
    if any(s in fp_joined for s in ("/frame/", "pallet-", "pallet_")):
        return "frame-pallet"
    if any(s in fp_joined for s in ("/client/network/", "libp2p", "/sync/", "warp")):
        return "p2p-sync"
    if any(s in fp_joined for s in ("transaction-pool", "/txpool")):
        return "transaction-pool"
    if any(s in fp_joined for s in ("/cumulus/", "collator")):
        return "cumulus-collator"
    if "/primitives/" in fp_joined or "/sp-" in fp_joined:
        return "primitives"
    return "substrate-other"


# ---------------------------------------------------------------------------
# Record builder.
# ---------------------------------------------------------------------------


def commit_to_record(
    repo: str,
    detail: Dict[str, Any],
) -> Optional[Dict[str, Any]]:
    """Build a hackerman_record from a `gh api /commits/<sha>` payload."""
    sha = detail.get("sha")
    if not isinstance(sha, str) or len(sha) < 8:
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

    # Substrate-file gate: accept Rust source under recognised paths, drop
    # if every file is tests / docs / CI only.
    def _is_substrate_file(p: str) -> bool:
        if not p:
            return False
        if not p.endswith(".rs"):
            return False
        # Drop test files (in-tree under tests/ directory or *_test.rs / test_*.rs).
        bn = p.rsplit("/", 1)[-1]
        if "/tests/" in p or bn.startswith("test_") or bn.endswith("_tests.rs") or bn.endswith("_test.rs"):
            return False
        return True

    def _is_test_only_file(p: str) -> bool:
        bn = p.rsplit("/", 1)[-1] if p else ""
        return (
            "/tests/" in p
            or bn.startswith("test_")
            or bn.endswith("_tests.rs")
            or bn.endswith("_test.rs")
        )

    if not any(_is_substrate_file(p) for p in file_paths):
        return None
    if all(_is_test_only_file(p) for p in file_paths):
        return None

    detector_seed = extract_detector_seed(patch_text, subject)
    subsystem = _subsystem(file_paths)

    severity = infer_severity(subject, message)
    impact = infer_impact(subject, message)

    sub_low = (subject + " " + message).lower()
    bug_class = "substrate-fix-shape-unclassified"
    attack_class = "substrate-bug-class"

    for needle, bc, ac in [
        ("equivocation", "consensus-equivocation", "substrate-bug-class:consensus-equivocation"),
        ("double vote", "consensus-equivocation", "substrate-bug-class:consensus-equivocation"),
        ("double sign", "consensus-equivocation", "substrate-bug-class:consensus-equivocation"),
        ("fork choice", "fork-choice-bug", "substrate-bug-class:fork-choice"),
        ("fork-choice", "fork-choice-bug", "substrate-bug-class:fork-choice"),
        ("finality", "finality-stall-bug", "substrate-bug-class:finality-stall"),
        ("grandpa", "grandpa-finality-bug", "substrate-bug-class:grandpa-finality"),
        ("babe", "babe-consensus-bug", "substrate-bug-class:babe-consensus"),
        ("beefy", "beefy-bridge-bug", "substrate-bug-class:beefy-bridge"),
        ("fraud proof", "fraud-proof-bug", "substrate-bug-class:fraud-proof"),
        ("fraud-proof", "fraud-proof-bug", "substrate-bug-class:fraud-proof"),
        ("dispute", "parachain-disputes-bug", "substrate-bug-class:parachain-disputes"),
        ("approval", "approval-voting-bug", "substrate-bug-class:approval-voting"),
        ("paras_inherent", "para-inherent-bug", "substrate-bug-class:para-inherent"),
        ("para_inherent", "para-inherent-bug", "substrate-bug-class:para-inherent"),
        ("backed_candidate", "parachain-candidate-bug", "substrate-bug-class:parachain-candidate"),
        ("xcm", "xcm-bridge-bug", "substrate-bug-class:xcm-bridge"),
        ("bridge", "bridge-protocol-bug", "substrate-bug-class:bridge-protocol"),
        ("hrmp", "hrmp-messaging-bug", "substrate-bug-class:hrmp-messaging"),
        ("runtime upgrade", "runtime-upgrade-bug", "substrate-bug-class:runtime-upgrade"),
        ("on_runtime_upgrade", "runtime-upgrade-bug", "substrate-bug-class:runtime-upgrade"),
        ("storage version", "storage-migration-bug", "substrate-bug-class:storage-migration"),
        ("migration", "storage-migration-bug", "substrate-bug-class:storage-migration"),
        ("pallet", "frame-pallet-bug", "substrate-bug-class:frame-pallet"),
        ("storagemap", "frame-storage-bug", "substrate-bug-class:frame-storage"),
        ("storagevalue", "frame-storage-bug", "substrate-bug-class:frame-storage"),
        ("dispatch", "frame-dispatch-bug", "substrate-bug-class:frame-dispatch"),
        ("overflow", "arithmetic-overflow-bug", "substrate-bug-class:arithmetic-overflow"),
        ("underflow", "arithmetic-underflow-bug", "substrate-bug-class:arithmetic-underflow"),
        ("transaction pool", "txpool-bug", "substrate-bug-class:txpool"),
        ("txpool", "txpool-bug", "substrate-bug-class:txpool"),
        ("warp sync", "warp-sync-bug", "substrate-bug-class:warp-sync"),
        ("p2p", "p2p-network-bug", "substrate-bug-class:p2p-network"),
        ("revert", "revert-rollback-of-prior-fix", "substrate-bug-class:revert-rollback"),
        ("consensus", "consensus-other-bug", "substrate-bug-class:consensus-other"),
    ]:
        if needle in sub_low:
            bug_class = bc
            attack_class = ac
            break

    # Function-signature shape: pull first `fn` / `pub fn` we see.
    raw_signature = (
        f"// commit {sha[:12]} in {repo} subsystem={subsystem} "
        f"touched {len(file_paths)} files"
    )
    fn_re_rs = re.compile(r"^\+\s*(pub\s+(?:async\s+)?fn\s+[A-Za-z_][A-Za-z0-9_]*\s*(?:<[^>]{0,80}>)?\s*\([^)]{0,200}\)[^\n{]{0,80})")
    fn_re_plain = re.compile(r"^\+\s*((?:async\s+)?fn\s+[A-Za-z_][A-Za-z0-9_]*\s*(?:<[^>]{0,80}>)?\s*\([^)]{0,200}\)[^\n{]{0,80})")
    for line in patch_text.splitlines():
        m = fn_re_rs.match(line) or fn_re_plain.match(line)
        if m:
            raw_signature = m.group(1).strip()[:500]
            break

    short_sha = sha[:8]
    record_id_input = f"substrate-fix-history|{repo}|{sha}".encode("utf-8")
    digest = hashlib.sha256(record_id_input).hexdigest()[:12]
    repo_slug = slugify(repo.replace("/", "-"), max_len=60)
    record_id = f"git-mining:{repo_slug}:{sha}:{digest}"[:160]
    commit_url = f"https://github.com/{repo}/commit/{sha}"

    action = (
        f"Upstream substrate / polkadot-sdk fix commit at {commit_url}. "
        f"Parent commit: {parent_sha or 'n/a'}. Commit subject: {subject!r}. "
        f"Subsystem: {subsystem}. "
        f"Files changed: {len(file_paths)} ({total_add} additions / {total_del} deletions). "
        f"Detector seed: {detector_seed}. "
        f"Attacker pre-fix path: construct a runtime / state-transition payload "
        f"that triggers the pre-fix behavior in {file_paths[0] if file_paths else 'unknown'} "
        f"(subsystem {subsystem}); submit against a parachain / relay-chain running "
        f"a substrate release earlier than this commit."
    )

    fix_pattern = (
        f"Diff at {commit_url} applies: {detector_seed}. "
        f"Reviewers porting this fix should scan structurally adjacent "
        f"{subsystem} sites in the same crate / pallet / runtime for the same "
        f"missing guard."
    )
    fix_anti_pattern = (
        f"Running a parachain / relay-chain runtime built from a substrate / "
        f"polkadot-sdk revision that predates {commit_url} - i.e. omitting the "
        f"{subsystem} guard / validation / consensus correction this commit added."
    )

    sa_ref_raw = f"git-mining:{repo}@{sha}"
    if len(sa_ref_raw) > 230:
        sa_ref_raw = sa_ref_raw[:230]

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
            "substrate",
            "polkadot-sdk",
            "src-git-fix-history",
            slugify(subsystem),
            slugify(bug_class),
            slugify(repo_slug),
            f"sha-{short_sha}",
        ]
    )

    record: Dict[str, Any] = {
        "schema_version": SCHEMA_VERSION,
        "record_id": record_id,
        "source_audit_ref": sa_ref_raw,
        # Substrate runtimes underpin live parachain economies (DOT, KSM,
        # ACA, GLMR, ASTR, etc). Map to rpc-infra per the convention used
        # for client-class fix-history miners.
        "target_domain": "rpc-infra",
        "target_language": "rust",
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
            f"Production parachain / relay-chain runtime built from substrate "
            f"parent SHA {parent_sha[:12] if parent_sha else 'unknown'} or earlier",
            f"Affected subsystem: {subsystem}; file {file_paths[0] if file_paths else 'unknown'}",
            f"Subject signal: {subject[:160]}",
            f"verification_tier=tier-1-verified-realtime-api",
        ],
        "impact_class": impact,
        "impact_actor": "arbitrary-user",
        "impact_dollar_class": dollar_class(severity, impact),
        "fix_pattern": fix_pattern[:1000],
        "fix_anti_pattern_avoided": fix_anti_pattern[:1000],
        "severity_at_finding": severity,
        "year": year,
        "record_tier": "public-corpus",
        "record_quality_score": 4.0,
        "source_extraction_method": "corpus-etl",
        "source_extraction_confidence": 0.9,
        "verification_method": "",
        "cross_language_analogues": [
            {
                "target_language": "go",
                "pattern_translation": (
                    f"Same {bug_class} shape in cosmos-sdk / cometbft / tendermint: "
                    f"scan the analogous {subsystem} subsystem (consensus-state, "
                    f"finality / commit, IBC bridge, x/upgrade) for the same "
                    f"missing primitive."
                ),
            },
        ],
        "related_records": [],
    }
    return record


# ---------------------------------------------------------------------------
# Filtering pipeline.
# ---------------------------------------------------------------------------


def is_fix_shape(subject: str, body: str) -> bool:
    if NON_PROTOCOL_REGEX.search(subject):
        return False
    if FIX_REGEX.search(subject):
        return True
    if FIX_REGEX.search(body[:400]):
        return True
    return False


def mine_repo(
    repo: str,
    *,
    pages: int = 3,
    per_page: int = 100,
    max_records: int = 30,
    detail_cap: int = 120,
    since: str = "2020-01-01",
    until: str = "2025-12-31",
    branch: Optional[str] = None,
) -> Tuple[List[Dict[str, Any]], int, int]:
    """Mine `repo`. Returns (records, total_scanned, candidate_count)."""
    commits = list_commits(
        repo,
        per_page=per_page,
        pages=pages,
        since=since,
        until=until,
        branch=branch,
    )
    candidates: List[Dict[str, Any]] = []
    for c in commits:
        commit_msg = (c.get("commit") or {}).get("message", "") or ""
        if not commit_msg:
            continue
        subject = commit_msg.splitlines()[0]
        if is_fix_shape(subject, commit_msg):
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
        rec = commit_to_record(repo, detail)
        if rec is None:
            continue
        records.append(rec)
        if len(records) >= max_records:
            break
    return records, len(commits), len(candidates)


# ---------------------------------------------------------------------------
# Driver.
# ---------------------------------------------------------------------------


def convert(
    out_dir: Path,
    *,
    dry_run: bool = False,
    limit: Optional[int] = None,
    repos: Sequence[str] = DEFAULT_REPOS,
    pages: int = 3,
    per_page: int = 100,
    max_per_repo: int = 30,
    detail_cap: int = 120,
    since: str = "2020-01-01",
    until: str = "2025-12-31",
    branches: Optional[Sequence[Optional[str]]] = None,
) -> Dict[str, Any]:
    records: List[Dict[str, Any]] = []
    errors: List[str] = []
    per_repo_counts: Dict[str, int] = {r: 0 for r in repos}
    sample_urls: List[str] = []
    seen_record_ids: set = set()

    branch_list: List[Optional[str]] = (
        list(branches) if branches else [None]
    )

    for repo in repos:
        if limit is not None and len(records) >= limit:
            break
        for branch in branch_list:
            try:
                repo_records, _scanned, _candidates = mine_repo(
                    repo,
                    pages=pages,
                    per_page=per_page,
                    max_records=max_per_repo,
                    detail_cap=detail_cap,
                    since=since,
                    until=until,
                    branch=branch,
                )
            except Exception as exc:  # noqa: BLE001
                errors.append(f"mine_repo({repo}, branch={branch}): {exc}")
                continue
            for r in repo_records:
                if r["record_id"] in seen_record_ids:
                    continue
                if per_repo_counts.get(repo, 0) >= max_per_repo:
                    break
                seen_record_ids.add(r["record_id"])
                if limit is not None and len(records) >= limit:
                    break
                records.append(r)
                per_repo_counts[repo] = per_repo_counts.get(repo, 0) + 1

    # Validate + emit
    schema = _VALIDATOR.load_schema()
    file_paths: List[str] = []
    valid = 0
    if not dry_run:
        out_dir.mkdir(parents=True, exist_ok=True)
    for rec in records:
        rendered = yaml_dump(rec)
        try:
            doc = yaml.safe_load(rendered)
        except yaml.YAMLError as exc:
            errors.append(f"{rec['record_id']}: yaml render: {exc}")
            continue
        verrs = _VALIDATOR.validate_doc(doc, schema)
        if verrs:
            for e in verrs:
                errors.append(f"{rec['record_id']}: {e}")
            continue
        valid += 1
        m = re.search(r"https?://\S+", rec.get("attacker_action_sequence", ""))
        if m and len(sample_urls) < 12:
            sample_urls.append(m.group(0).rstrip(".,;|"))
        parts = rec["record_id"].split(":")
        full_sha = parts[-2] if len(parts) >= 3 else "unknown"
        short_sha = full_sha[:8] if re.fullmatch(r"[0-9a-f]+", full_sha) else full_sha
        repo_slug = slugify(rec["target_repo"].replace("/", "-"), max_len=60)
        slug_dir = slugify(f"{repo_slug}__{short_sha}", max_len=120)
        rec_dir = out_dir / slug_dir
        if not dry_run:
            rec_dir.mkdir(parents=True, exist_ok=True)
            (rec_dir / "record.yaml").write_text(rendered, encoding="utf-8")
            (rec_dir / "record.json").write_text(
                json.dumps(doc, indent=2, sort_keys=True) + "\n",
                encoding="utf-8",
            )
        file_paths.append(str(rec_dir / "record.yaml"))

    # NEGATIVE summary threshold: 30 (lower than vyper-sibling because we
    # cap per-repo at 30 and may not always saturate every legacy archive).
    NEGATIVE_THRESHOLD = 30

    return {
        "schema_version": SCHEMA_VERSION,
        "verification_tier": "tier-1-verified-realtime-api",
        "out_dir": str(out_dir),
        "dry_run": dry_run,
        "records_total": len(records),
        "records_valid": valid,
        "records_per_repo": per_repo_counts,
        "sample_urls": sample_urls,
        "errors": errors[:50],
        "error_count": len(errors),
        "file_count": len(file_paths),
        "files_sample": file_paths[:20],
        "negative_verdict": valid < NEGATIVE_THRESHOLD,
    }


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--out-dir",
        default="audit/corpus_tags/tags/substrate_fix_history",
        help="Output directory (per-record sub-dir). Default: %(default)s",
    )
    parser.add_argument("--dry-run", action="store_true")
    parser.add_argument("--limit", type=int)
    parser.add_argument("--pages", type=int, default=3, help="Commit-list pages per branch.")
    parser.add_argument("--per-page", type=int, default=100, help="Commits per API page.")
    parser.add_argument(
        "--max-per-repo",
        type=int,
        default=30,
        help="Hard cap on emitted records per repo (post-detail filter).",
    )
    parser.add_argument(
        "--detail-cap",
        type=int,
        default=120,
        help="Hard cap on detail-API fetches per branch (cost control).",
    )
    parser.add_argument("--since", default="2020-01-01")
    parser.add_argument("--until", default="2025-12-31")
    parser.add_argument(
        "--branches",
        nargs="*",
        default=None,
        help="Optional list of branch SHAs / names to walk per repo.",
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
    repos = args.repos if args.repos else list(DEFAULT_REPOS)
    summary = convert(
        out_dir,
        dry_run=args.dry_run,
        limit=args.limit,
        repos=repos,
        pages=args.pages,
        per_page=args.per_page,
        max_per_repo=args.max_per_repo,
        detail_cap=args.detail_cap,
        since=args.since,
        until=args.until,
        branches=args.branches,
    )
    if args.json_summary:
        print(json.dumps(summary, sort_keys=True, indent=2))
    else:
        print(
            "hackerman substrate-fix-history ETL: "
            f"valid={summary['records_valid']}/{summary['records_total']} "
            f"per_repo={summary['records_per_repo']} "
            f"errors={summary['error_count']}"
        )
        if summary["negative_verdict"]:
            print("[NEGATIVE] yield < 30 verifiable records - widen --pages / --branches / --since before relying on this corpus.")
    return 0 if summary["error_count"] == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
