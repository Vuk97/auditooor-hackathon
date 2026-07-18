#!/usr/bin/env python3
"""
hackerman-etl-from-vyper-compiler-fix-history.py — Mine the fix-commit
history of the Vyper compiler (vyperlang/vyper) for the auditooor
Hackerman corpus. Seeds compiler-class detector patterns (codegen
miscompiles, optimizer bugs, ABI / storage-layout bugs, frontend
type-system bugs, IR/Venom bugs) not always tied to a GHSA.

Wave-1 lane: wave-1-hackerman-capability-lift (PR #726).

HARD RULES (M14-trap discipline):
- Real-source-only. Every record is anchored to a verifiable commit SHA via
  `gh api /repos/vyperlang/vyper/commits/<sha>`. The commit metadata embedded
  in each record comes from the live API response; nothing is invented.
- No invented CVE / GHSA IDs. The commit URL itself is the source. If the
  upstream maintainers chose to attach a GHSA, fine - we surface it from the
  commit body if present, otherwise the GHSA / CVE fields are omitted.
- If yield < 50 records the script exits with a NEGATIVE summary.

Repos mined (1):
  vyperlang/vyper  (main + any user-supplied release branches via --branch).

Filter: commit message must match one of the fix-shape keywords; negative
filter drops obvious non-compiler churn (docs / CI / tests / formatting).

Output:
  audit/corpus_tags/tags/vyper_compiler_fix_history/<sha8>/record.{yaml,json}

CLI:
  python3 tools/hackerman-etl-from-vyper-compiler-fix-history.py \\
      --out-dir audit/corpus_tags/tags/vyper_compiler_fix_history \\
      --json-summary

Shape anchor: ``tools/hackerman-etl-from-dex-fix-history.py``.
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
TARGET_REPO = "vyperlang/vyper"


def _load_validator() -> Any:
    spec = importlib.util.spec_from_file_location(
        "_hackerman_record_validate_for_vyper_compiler_fix_history",
        str(REPO_ROOT / "tools" / "hackerman-record-validate.py"),
    )
    mod = importlib.util.module_from_spec(spec)
    assert spec.loader
    spec.loader.exec_module(mod)
    return mod


_VALIDATOR = _load_validator()


# ---------------------------------------------------------------------------
# Keyword filter. Tailored to the compiler / IR / codegen / optimizer
# vocabulary the Vyper team uses in their commit messages.
# ---------------------------------------------------------------------------

FIX_KEYWORDS = [
    "compiler bug",
    "ice",
    "internal compiler error",
    "miscompile",
    "miscompilation",
    "incorrect",
    "wrong codegen",
    "wrong bytecode",
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
]

FIX_REGEX = re.compile(
    r"\b(" + "|".join(re.escape(k) for k in FIX_KEYWORDS) + r")\b",
    re.IGNORECASE,
)

# Negative filter: pure churn. Note: we MUST allow "fix[ci]" through if it
# touches an actual compiler file (later filter). The negative regex below
# only catches *subjects that have no compiler intent at all*.
NON_PROTOCOL_REGEX = re.compile(
    r"^(typo\b|formatting\b|natspec\b|coverage\b|docs?\b|readme\b|"
    r"prettier\b|eslint\b|^bump\b|version bump|update version|dependabot|"
    r"^style\b|^chore\b)",
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
    pages: int = 5,
    since: str = "2020-01-01",
    until: str = "2024-12-31",
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
# Shared helpers (slugify / dedupe / dollar_class) mirrored from sibling ETLs.
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
    if any(k in low for k in ("critical", "exploit", "loss of funds", "miscompile", "miscompilation")):
        return "high"
    if "security" in low or re.search(r"\bcve\b|\bghsa\b", low):
        return "high"
    if "vulnerab" in low or "audit" in low or "wrong codegen" in low or "wrong bytecode" in low:
        return "high"
    if "incorrect" in low or "internal compiler error" in low or "ice" in low.split():
        return "medium"
    if any(k in low for k in ("revert", "rollback")):
        return "medium"
    if any(k in low for k in ("guard", "validate", "check", "patch")):
        return "medium"
    return "low"


def infer_impact(subject: str, body: str) -> str:
    low = (subject + " " + body).lower()
    if any(k in low for k in ("miscompile", "miscompilation", "wrong codegen", "wrong bytecode")):
        return "theft"
    if any(k in low for k in ("drain", "steal", "theft", "loss of funds")):
        return "theft"
    if any(k in low for k in ("freeze", "stuck", "locked", "brick", "permanent lock")):
        return "freeze"
    if any(k in low for k in ("ice", "internal compiler error", "panic", "crash", "hang", "infinite loop")):
        return "dos"
    if any(k in low for k in ("dos", "denial of service")):
        return "dos"
    if any(k in low for k in ("rounding", "precision", "overflow", "underflow")):
        return "precision-loss"
    if any(k in low for k in ("storage layout", "abi", "calldata", "selector")):
        return "theft"
    if any(k in low for k in ("priv", "unauthorized", "owner", "auth")):
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
# YAML rendering
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
# Detector-seed extraction from Vyper / Python diff hunks.
#
# Compiler bugs cluster in a few well-known shapes:
#   - added range/overflow check on an integer conversion
#   - fixed storage-layout offset
#   - added type-check / signature-validation in the frontend
#   - corrected codegen sequence (push/pop/dup ordering)
#   - added optimizer pass guard / disabled buggy optimization
#   - fixed ABI encoding / decoding edge case
# ---------------------------------------------------------------------------


PY_ASSERT_RE = re.compile(r"^\+\s*assert\s+(.{1,200})$")
PY_RAISE_RE = re.compile(r"^\+\s*raise\s+([A-Za-z_][A-Za-z0-9_]*)")
PY_IF_GUARD_RE = re.compile(r"^\+\s*if\s+(.{1,160}):\s*$")
TYPE_CHECK_RE = re.compile(r"^\+.*\b(check_assign|validate|validate_expected_type|type_check|TypeMismatch|check_kwargable|ensure_)\b")
OVERFLOW_GUARD_RE = re.compile(r"^\+.*\b(SafeMath|safe_add|safe_sub|safe_mul|safe_div|clamp|clampge|clample|self_destruct_check|bounds_check|overflow|underflow)\b", re.IGNORECASE)
IR_OP_RE = re.compile(r"^\+.*\b(IRnode|IRnode\.from_list|push|pop|swap|dup|jump|jumpi|mload|mstore|sload|sstore|calldataload|returndatacopy)\b")
VENOM_RE = re.compile(r"^\+.*\b(venom|basicblock|store_elimination|sccp|dft|dce|simplifier)\b", re.IGNORECASE)
ABI_RE = re.compile(r"^\+.*\b(abi_encode|abi_decode|abi_type|abi.encode|method_id|selector|signature)\b")
STORAGE_LAYOUT_RE = re.compile(r"^\+.*\b(storage_layout|storage_slot|immutable|transient|reentrancy_key|nonreentrant)\b")
REVERT_PUSH_RE = re.compile(r"^\+.*\b(revert|self_assert|invalid|panic_with)\b")


def extract_detector_seed(patch_text: str, subject: str) -> str:
    """Summarise added/removed shape of a compiler-fix patch.

    Returns a comma-separated bag of seed tags. Always returns something
    non-empty (falls back to "diff-shape-fix").
    """
    seeds: List[str] = []

    for line in patch_text.splitlines():
        if not line:
            continue
        if line.startswith("+++") or line.startswith("---") or line.startswith("@@"):
            continue

        m = PY_ASSERT_RE.match(line)
        if m:
            cond = re.sub(r"\s+", " ", m.group(1)).strip()[:80]
            seeds.append(f"added assert {cond}")
            continue

        m = PY_RAISE_RE.match(line)
        if m:
            seeds.append(f"added raise {m.group(1)}")
            continue

        m = TYPE_CHECK_RE.match(line)
        if m:
            seeds.append(f"added frontend type-check {m.group(1)}")
            continue

        m = OVERFLOW_GUARD_RE.match(line)
        if m:
            seeds.append(f"added overflow / range guard {m.group(1).lower()}")
            continue

        m = STORAGE_LAYOUT_RE.match(line)
        if m:
            seeds.append(f"touched storage-layout {m.group(1)}")
            continue

        m = ABI_RE.match(line)
        if m:
            seeds.append(f"touched ABI codec {m.group(1)}")
            continue

        m = IR_OP_RE.match(line)
        if m:
            seeds.append(f"touched IR op {m.group(1).lower()}")
            continue

        m = VENOM_RE.match(line)
        if m:
            seeds.append(f"touched Venom pass {m.group(1).lower()}")
            continue

        m = REVERT_PUSH_RE.match(line)
        if m:
            seeds.append(f"added revert / panic {m.group(1).lower()}")
            continue

        m = PY_IF_GUARD_RE.match(line)
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
        elif "miscompile" in sub_low or "miscompilation" in sub_low:
            seeds.append("codegen miscompile fix")
        elif "ice" in sub_low or "internal compiler error" in sub_low:
            seeds.append("ICE-class compiler crash fix")
        else:
            seeds.append("diff-shape-fix")

    return "; ".join(dedupe(seeds)[:8])


# ---------------------------------------------------------------------------
# Compiler-subsystem inference. The Vyper source tree segments cleanly:
# ---------------------------------------------------------------------------


def _compiler_subsystem(file_paths: Sequence[str]) -> str:
    fp_joined = " ".join(file_paths).lower()
    if "venom" in fp_joined:
        return "venom-ir"
    if "/codegen/" in fp_joined or "compile_ir" in fp_joined:
        return "codegen"
    if "/ir/" in fp_joined or "ir_node" in fp_joined:
        return "ir-frontend"
    if "/semantics/" in fp_joined:
        return "semantic-analysis"
    if "/ast/" in fp_joined or "annotation" in fp_joined:
        return "ast-frontend"
    if "/abi/" in fp_joined or "abi_t" in fp_joined or "abi.py" in fp_joined:
        return "abi-codec"
    if "/stdlib/" in fp_joined or "builtins" in fp_joined or "/builtin_functions/" in fp_joined:
        return "stdlib-builtin"
    if "/parser/" in fp_joined:
        return "parser"
    if "/cli/" in fp_joined or "vyper_json" in fp_joined:
        return "cli-frontend"
    if "/optimizer/" in fp_joined or "optimize" in fp_joined:
        return "optimizer"
    if "/storage" in fp_joined:
        return "storage-layout"
    return "compiler-other"


# ---------------------------------------------------------------------------
# Record builder
# ---------------------------------------------------------------------------


def commit_to_record(
    repo: str,
    detail: Dict[str, Any],
) -> Optional[Dict[str, Any]]:
    """Build a hackerman_record from a `gh api /commits/<sha>` payload.

    Returns None if mandatory fields are missing or the commit touches no
    compiler source file.
    """
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

    # Compiler-file gate. The Vyper repo organises compiler source under
    # `vyper/`. We accept commits that touch ANY .py file under vyper/
    # OR a top-level .py compiler file. Pure-test-only commits (only
    # touching tests/) are dropped because they don't seed a detector
    # pattern (they may exercise one, but the pattern lives in the fix).
    def _is_compiler_file(p: str) -> bool:
        if not p:
            return False
        if p.startswith("vyper/") and p.endswith(".py"):
            return True
        # Top-level compiler driver e.g. setup.py / pyproject.toml are NOT
        # compiler source; only vyper/<...>.py is.
        return False

    def _is_test_only_file(p: str) -> bool:
        return p.startswith("tests/") or "/tests/" in p

    if not any(_is_compiler_file(p) for p in file_paths):
        return None
    # If EVERY file is a test, we still drop (no detector seed possible).
    if all(_is_test_only_file(p) for p in file_paths):
        return None

    detector_seed = extract_detector_seed(patch_text, subject)
    subsystem = _compiler_subsystem(file_paths)

    severity = infer_severity(subject, message)
    impact = infer_impact(subject, message)

    # Bug-class inference for compiler bugs.
    #
    # Subsystem-prefix subjects like "fix[venom]: ..." should win over
    # generic compiler-class needles like "miscompile" - the bug is more
    # specifically classified by subsystem when the team marks one.
    # The subject prefix in square brackets is the canonical signal.
    sub_low = (subject + " " + message).lower()
    bug_class = "compiler-fix-shape-unclassified"
    attack_class = "vyper-compiler-bug-class"

    # Subsystem-prefix override (priority).
    prefix_match = re.match(r"^[a-z]+\[([a-z]+)\]", subject.lower().strip())
    prefix_tag = prefix_match.group(1) if prefix_match else ""

    for needle, bc, ac in [
        # Subsystem-prefix-anchored (highest priority).
        ("__prefix__venom", "venom-ir-bug", "vyper-compiler-bug-class:venom-ir"),
        ("__prefix__codegen", "codegen-miscompilation", "vyper-compiler-bug-class:codegen-miscompile"),
        ("__prefix__stdlib", "stdlib-builtin-bug", "vyper-compiler-bug-class:stdlib-builtin"),
        ("__prefix__abi", "abi-codec-bug", "vyper-compiler-bug-class:abi-codec"),
        ("__prefix__parser", "parser-frontend-bug", "vyper-compiler-bug-class:parser-frontend"),
        ("__prefix__ast", "ast-frontend-bug", "vyper-compiler-bug-class:ast-frontend"),
        ("__prefix__semantics", "semantic-analysis-bug", "vyper-compiler-bug-class:semantic-analysis"),
        ("__prefix__type", "type-system-bug", "vyper-compiler-bug-class:type-system"),
        ("__prefix__ir", "ir-frontend-bug", "vyper-compiler-bug-class:ir-frontend"),
        # Body-text needles (fallback).
        ("miscompile", "codegen-miscompilation", "vyper-compiler-bug-class:codegen-miscompile"),
        ("miscompilation", "codegen-miscompilation", "vyper-compiler-bug-class:codegen-miscompile"),
        ("wrong codegen", "codegen-miscompilation", "vyper-compiler-bug-class:codegen-miscompile"),
        ("wrong bytecode", "codegen-miscompilation", "vyper-compiler-bug-class:codegen-miscompile"),
        ("storage layout", "storage-layout-bug", "vyper-compiler-bug-class:storage-layout"),
        ("optimizer", "optimizer-pass-bug", "vyper-compiler-bug-class:optimizer-pass"),
        ("venom", "venom-ir-bug", "vyper-compiler-bug-class:venom-ir"),
        ("reentran", "reentrancy-key-bug", "vyper-compiler-bug-class:reentrancy-key"),
        ("nonreentrant", "reentrancy-key-bug", "vyper-compiler-bug-class:reentrancy-key"),
        ("abi", "abi-codec-bug", "vyper-compiler-bug-class:abi-codec"),
        ("selector", "abi-codec-bug", "vyper-compiler-bug-class:abi-codec"),
        ("calldata", "calldata-decoding-bug", "vyper-compiler-bug-class:calldata-decoding"),
        ("overflow", "arithmetic-overflow-bug", "vyper-compiler-bug-class:arithmetic-overflow"),
        ("underflow", "arithmetic-underflow-bug", "vyper-compiler-bug-class:arithmetic-underflow"),
        ("immutable", "immutable-init-bug", "vyper-compiler-bug-class:immutable-init"),
        ("transient", "transient-storage-bug", "vyper-compiler-bug-class:transient-storage"),
        ("internal compiler error", "internal-compiler-error", "vyper-compiler-bug-class:ice"),
        (" ice ", "internal-compiler-error", "vyper-compiler-bug-class:ice"),
        ("ice]", "internal-compiler-error", "vyper-compiler-bug-class:ice"),
        ("type", "type-system-bug", "vyper-compiler-bug-class:type-system"),
        ("ast", "ast-frontend-bug", "vyper-compiler-bug-class:ast-frontend"),
        ("parser", "parser-frontend-bug", "vyper-compiler-bug-class:parser-frontend"),
        ("stdlib", "stdlib-builtin-bug", "vyper-compiler-bug-class:stdlib-builtin"),
        ("builtin", "stdlib-builtin-bug", "vyper-compiler-bug-class:stdlib-builtin"),
        ("revert", "revert-rollback-of-prior-fix", "vyper-compiler-bug-class:revert-rollback"),
    ]:
        if needle.startswith("__prefix__"):
            wanted = needle.removeprefix("__prefix__")
            if prefix_tag == wanted:
                bug_class = bc
                attack_class = ac
                break
            continue
        if needle in sub_low:
            bug_class = bc
            attack_class = ac
            break

    # Function-signature shape: pull the first `def <name>(...)` we see.
    raw_signature = (
        f"// commit {sha[:12]} in {repo} subsystem={subsystem} "
        f"touched {len(file_paths)} files"
    )
    fn_re_py = re.compile(r"^\+\s*(def\s+[A-Za-z_][A-Za-z0-9_]*\([^)]{0,200}\)[^\n:]{0,80})")
    fn_re_class = re.compile(r"^\+\s*(class\s+[A-Za-z_][A-Za-z0-9_]*\([^)]{0,200}\))")
    for line in patch_text.splitlines():
        m = fn_re_py.match(line) or fn_re_class.match(line)
        if m:
            raw_signature = m.group(1).strip()[:500]
            break

    short_sha = sha[:8]
    record_id_input = f"vyper-compiler-fix-history|{repo}|{sha}".encode("utf-8")
    digest = hashlib.sha256(record_id_input).hexdigest()[:12]
    repo_slug = slugify(repo.replace("/", "-"), max_len=60)
    record_id = f"git-mining:{repo_slug}:{sha}:{digest}"[:160]
    commit_url = f"https://github.com/{repo}/commit/{sha}"

    action = (
        f"Upstream Vyper compiler fix commit at {commit_url}. "
        f"Parent commit: {parent_sha or 'n/a'}. Commit subject: {subject!r}. "
        f"Subsystem: {subsystem}. "
        f"Files changed: {len(file_paths)} ({total_add} additions / {total_del} deletions). "
        f"Detector seed: {detector_seed}. "
        f"Attacker pre-fix path: emit Vyper source that triggers the pre-fix "
        f"behavior in {file_paths[0] if file_paths else 'unknown'} (subsystem {subsystem}); "
        f"deploy resulting bytecode against a mainnet target compiled with a "
        f"Vyper release earlier than the commit's release tag."
    )

    fix_pattern = (
        f"Diff at {commit_url} applies: {detector_seed}. "
        f"Reviewers porting this fix should scan structurally adjacent "
        f"{subsystem} sites in the same module for the same missing guard."
    )
    fix_anti_pattern = (
        f"Compiling production Vyper contracts with a release that predates "
        f"{commit_url} - i.e. omitting the {subsystem} guard / check / codegen "
        f"correction that this commit added."
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
            "vyper-compiler",
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
        # Vyper compiler bugs ultimately impact on-chain contracts compiled
        # by the buggy release. Map to rpc-infra (dev tooling) per the
        # convention in hackerman-etl-from-evm-tooling-advisories.py.
        "target_domain": "rpc-infra",
        "target_language": "vyper",
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
            f"Production deployment compiled with a Vyper release built from "
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
                "target_language": "solidity",
                "pattern_translation": (
                    f"Same compiler bug shape ({bug_class}) in solc: scan "
                    f"solc's {subsystem} subsystem fix-history for sibling "
                    "patches addressing the same primitive."
                ),
            },
        ],
        "related_records": [],
    }
    return record


# ---------------------------------------------------------------------------
# Filtering pipeline
# ---------------------------------------------------------------------------


def is_fix_shape(subject: str, body: str) -> bool:
    if NON_PROTOCOL_REGEX.search(subject):
        # Even subjects like "chore: bump version" are dropped here. But
        # "fix[ci]" or "fix[venom]" don't match NON_PROTOCOL_REGEX (the
        # regex is anchored to ^ on the subject).
        return False
    if FIX_REGEX.search(subject):
        return True
    if FIX_REGEX.search(body[:400]):
        return True
    return False


def mine_repo(
    repo: str,
    *,
    pages: int = 5,
    per_page: int = 100,
    max_records: int = 200,
    detail_cap: int = 250,
    since: str = "2020-01-01",
    until: str = "2024-12-31",
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
# Driver
# ---------------------------------------------------------------------------


def convert(
    out_dir: Path,
    *,
    dry_run: bool = False,
    limit: Optional[int] = None,
    repos: Sequence[str] = (TARGET_REPO,),
    pages: int = 5,
    per_page: int = 100,
    max_records: int = 200,
    detail_cap: int = 250,
    since: str = "2020-01-01",
    until: str = "2024-12-31",
    branches: Optional[Sequence[Optional[str]]] = None,
) -> Dict[str, Any]:
    records: List[Dict[str, Any]] = []
    errors: List[str] = []
    per_repo_counts: Dict[str, int] = {}
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
                    max_records=max_records,
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
                seen_record_ids.add(r["record_id"])
                if limit is not None and len(records) >= limit:
                    break
                records.append(r)
        per_repo_counts[repo] = sum(
            1 for r in records if r["target_repo"] == repo
        )

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
        if m and len(sample_urls) < 9:
            sample_urls.append(m.group(0).rstrip(".,;|"))
        parts = rec["record_id"].split(":")
        full_sha = parts[-2] if len(parts) >= 3 else "unknown"
        short_sha = full_sha[:8] if re.fullmatch(r"[0-9a-f]+", full_sha) else full_sha
        slug_dir = slugify(short_sha, max_len=120)
        rec_dir = out_dir / slug_dir
        if not dry_run:
            rec_dir.mkdir(parents=True, exist_ok=True)
            (rec_dir / "record.yaml").write_text(rendered, encoding="utf-8")
            (rec_dir / "record.json").write_text(
                json.dumps(doc, indent=2, sort_keys=True) + "\n",
                encoding="utf-8",
            )
        file_paths.append(str(rec_dir / "record.yaml"))

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
        "negative_verdict": valid < 50,
    }


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--out-dir",
        default="audit/corpus_tags/tags/vyper_compiler_fix_history",
        help="Output directory (per-record sub-dir). Default: %(default)s",
    )
    parser.add_argument("--dry-run", action="store_true")
    parser.add_argument("--limit", type=int)
    parser.add_argument("--pages", type=int, default=5, help="Commit-list pages per branch.")
    parser.add_argument("--per-page", type=int, default=100, help="Commits per API page.")
    parser.add_argument(
        "--max-records",
        type=int,
        default=200,
        help="Hard cap on total emitted records (post-detail filter).",
    )
    parser.add_argument(
        "--detail-cap",
        type=int,
        default=250,
        help="Hard cap on detail-API fetches per branch (cost control).",
    )
    parser.add_argument("--since", default="2020-01-01")
    parser.add_argument("--until", default="2024-12-31")
    parser.add_argument(
        "--branches",
        nargs="*",
        default=None,
        help=(
            "Optional list of branch SHAs / names to walk in addition to "
            "the default branch (e.g. master v0.3 v0.4). Default: just the "
            "default branch."
        ),
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
    repos = args.repos if args.repos else [TARGET_REPO]
    summary = convert(
        out_dir,
        dry_run=args.dry_run,
        limit=args.limit,
        repos=repos,
        pages=args.pages,
        per_page=args.per_page,
        max_records=args.max_records,
        detail_cap=args.detail_cap,
        since=args.since,
        until=args.until,
        branches=args.branches,
    )
    if args.json_summary:
        print(json.dumps(summary, sort_keys=True, indent=2))
    else:
        print(
            "hackerman vyper-compiler-fix-history ETL: "
            f"valid={summary['records_valid']}/{summary['records_total']} "
            f"per_repo={summary['records_per_repo']} "
            f"errors={summary['error_count']}"
        )
        if summary["negative_verdict"]:
            print("[NEGATIVE] yield < 50 verifiable records - widen --pages / --branches / --since before relying on this corpus.")
    return 0 if summary["error_count"] == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
