#!/usr/bin/env python3
"""
hackerman-etl-from-solc-bugs.py - Mine the Solidity compiler (solc) bug-fix
history for the auditooor Hackerman corpus.

Two real-source streams are mined:

1. ``docs/bugs.json`` on ethereum/solidity (raw.githubusercontent.com). This is
   the canonical list of solc compiler bugs maintained by the Solidity team;
   each entry carries uid / name / summary / description / link / introduced /
   fixed / severity / conditions.

2. ``gh api /repos/ethereum/solidity/commits`` filtered for fix-class commit
   subjects (`fix.*compiler bug`, `fix.*ICE`, `fix.*miscompile`, `bug-fix`,
   `fixed-in`, ...). Each commit becomes a separate record so the corpus
   captures fixes the team chose NOT to formalize in bugs.json.

Wave-1 lane: wave-1-hackerman-capability-lift (PR #726).

HARD RULES (M14-trap discipline):
- Real-source-only. Every record is anchored either to the live bugs.json
  entry (uid + link) or to a verifiable commit SHA via ``gh api``.
- No invented CVE / GHSA IDs. We surface what is in the blog/issue link.
- If yield < 60 records the script exits with a NEGATIVE summary.

Output:
  audit/corpus_tags/tags/solc_compiler_bugs/<name>/record.{yaml,json}

CLI:
  python3 tools/hackerman-etl-from-solc-bugs.py \\
      --out-dir audit/corpus_tags/tags/solc_compiler_bugs \\
      --json-summary

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
TARGET_REPO = "ethereum/solidity"

BUGS_JSON_URL = (
    "https://raw.githubusercontent.com/ethereum/solidity/develop/docs/bugs.json"
)
BUGS_BY_VERSION_URL = (
    "https://raw.githubusercontent.com/ethereum/solidity/develop/docs/"
    "bugs_by_version.json"
)


def _load_validator() -> Any:
    spec = importlib.util.spec_from_file_location(
        "_hackerman_record_validate_for_solc_bugs",
        str(REPO_ROOT / "tools" / "hackerman-record-validate.py"),
    )
    mod = importlib.util.module_from_spec(spec)
    assert spec.loader
    spec.loader.exec_module(mod)
    return mod


_VALIDATOR = _load_validator()


# ---------------------------------------------------------------------------
# Network helpers (curl subprocess for raw.githubusercontent.com,
# `gh api` for the GitHub REST surface).
# ---------------------------------------------------------------------------


def fetch_url(url: str, *, timeout: int = 45) -> str:
    """Return text body for ``url`` or empty string on failure."""
    try:
        proc = subprocess.run(
            ["curl", "-sL", "--max-time", "30", url],
            check=False,
            capture_output=True,
            text=True,
            timeout=timeout,
        )
    except (FileNotFoundError, subprocess.TimeoutExpired) as exc:
        sys.stderr.write(f"[warn] curl {url}: {exc}\n")
        return ""
    if proc.returncode != 0:
        sys.stderr.write(f"[warn] curl {url}: rc={proc.returncode}\n")
        return ""
    return proc.stdout


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


# ---------------------------------------------------------------------------
# Shared helpers
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


# Map the Solidity team's coarse severity tags to the schema enum.
_SEVERITY_NORMALIZE = {
    "high": "high",
    "medium/high": "high",
    "medium": "medium",
    "low/medium": "medium",
    "low": "low",
    "very low": "info",
}


def normalize_severity(raw: str) -> str:
    s = (raw or "").strip().lower()
    return _SEVERITY_NORMALIZE.get(s, "low")


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


def year_from_uid(uid: str) -> int:
    m = re.match(r"SOL-(\d{4})-", uid or "")
    if m:
        return int(m.group(1))
    return 2024


# ---------------------------------------------------------------------------
# YAML rendering (mirrors sibling miners).
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
# Bug-class inference for bugs.json entries.
# ---------------------------------------------------------------------------


def classify_bugs_json_entry(name: str, summary: str, description: str) -> Tuple[str, str, str]:
    """Return (bug_class, attack_class, subsystem)."""
    text = " ".join([name or "", summary or "", description or ""]).lower()

    # Bug-class needles ordered most-specific first.
    table: List[Tuple[str, str, str, str]] = [
        ("transient storage", "transient-storage-bug", "solc-compiler-bug-class:transient-storage", "transient-storage"),
        ("yul optimizer", "yul-optimizer-bug", "solc-compiler-bug-class:yul-optimizer", "yul-optimizer"),
        ("constant optimizer", "constant-optimizer-bug", "solc-compiler-bug-class:constant-optimizer", "constant-optimizer"),
        ("optimizer", "optimizer-pass-bug", "solc-compiler-bug-class:optimizer-pass", "optimizer"),
        ("inliner", "inliner-pass-bug", "solc-compiler-bug-class:inliner-pass", "yul-optimizer"),
        ("verbatim", "verbatim-codegen-bug", "solc-compiler-bug-class:verbatim-codegen", "yul-codegen"),
        ("via ir", "via-ir-codegen-bug", "solc-compiler-bug-class:via-ir-codegen", "via-ir-codegen"),
        ("ir-based", "via-ir-codegen-bug", "solc-compiler-bug-class:via-ir-codegen", "via-ir-codegen"),
        ("ir code generator", "via-ir-codegen-bug", "solc-compiler-bug-class:via-ir-codegen", "via-ir-codegen"),
        ("storage layout", "storage-layout-bug", "solc-compiler-bug-class:storage-layout", "storage-layout"),
        ("storage array", "storage-array-codegen-bug", "solc-compiler-bug-class:storage-array-codegen", "codegen"),
        ("immutable", "immutable-init-bug", "solc-compiler-bug-class:immutable-init", "codegen"),
        ("user defined value type", "user-defined-value-type-bug", "solc-compiler-bug-class:user-defined-value-type", "type-system"),
        ("abi.encodecall", "abi-encodecall-bug", "solc-compiler-bug-class:abi-encodecall", "abi-codec"),
        ("abi encoder v2", "abi-encoder-v2-bug", "solc-compiler-bug-class:abi-encoder-v2", "abi-codec"),
        ("abi reencod", "abi-reencoding-bug", "solc-compiler-bug-class:abi-reencoding", "abi-codec"),
        ("abi", "abi-codec-bug", "solc-compiler-bug-class:abi-codec", "abi-codec"),
        ("calldata", "calldata-decoding-bug", "solc-compiler-bug-class:calldata-decoding", "abi-codec"),
        ("event signature", "event-signature-bug", "solc-compiler-bug-class:event-signature", "codegen"),
        ("event", "event-emission-bug", "solc-compiler-bug-class:event-emission", "codegen"),
        ("keccak", "keccak-caching-bug", "solc-compiler-bug-class:keccak-caching", "yul-optimizer"),
        ("ecrecover", "ecrecover-input-bug", "solc-compiler-bug-class:ecrecover-input", "codegen"),
        ("function pointer", "function-pointer-init-bug", "solc-compiler-bug-class:function-pointer-init", "codegen"),
        ("selector", "function-selector-bug", "solc-compiler-bug-class:function-selector", "codegen"),
        ("constructor", "constructor-codegen-bug", "solc-compiler-bug-class:constructor-codegen", "codegen"),
        ("delegatecall", "delegatecall-return-bug", "solc-compiler-bug-class:delegatecall-return", "codegen"),
        ("library", "library-call-bug", "solc-compiler-bug-class:library-call", "codegen"),
        ("private", "private-visibility-override-bug", "solc-compiler-bug-class:private-visibility-override", "semantic-analysis"),
        ("tuple", "tuple-assignment-bug", "solc-compiler-bug-class:tuple-assignment", "codegen"),
        ("array slice", "array-slice-bug", "solc-compiler-bug-class:array-slice", "codegen"),
        ("memory array", "memory-array-overflow-bug", "solc-compiler-bug-class:memory-array-overflow", "codegen"),
        ("byte array", "byte-array-copy-bug", "solc-compiler-bug-class:byte-array-copy", "codegen"),
        ("dynamic array", "dynamic-array-cleanup-bug", "solc-compiler-bug-class:dynamic-array-cleanup", "codegen"),
        ("inline assembly", "inline-assembly-side-effect-bug", "solc-compiler-bug-class:inline-assembly-side-effect", "yul-codegen"),
        ("free function", "free-function-redefinition-bug", "solc-compiler-bug-class:free-function-redefinition", "semantic-analysis"),
        ("using for", "using-for-calldata-bug", "solc-compiler-bug-class:using-for-calldata", "semantic-analysis"),
        ("exp", "exp-cleanup-bug", "solc-compiler-bug-class:exp-cleanup", "codegen"),
        ("shift", "shift-overflow-bug", "solc-compiler-bug-class:shift-overflow", "codegen"),
        ("byte instruction", "byte-instruction-optimization-bug", "solc-compiler-bug-class:byte-instruction-optimization", "optimizer"),
        ("clean", "higher-order-byte-cleanup-bug", "solc-compiler-bug-class:higher-order-byte-cleanup", "codegen"),
        ("identity precompile", "identity-precompile-bug", "solc-compiler-bug-class:identity-precompile", "codegen"),
        ("send", "send-zero-ether-bug", "solc-compiler-bug-class:send-zero-ether", "codegen"),
        ("ancient compiler", "ancient-compiler", "solc-compiler-bug-class:ancient-compiler", "compiler-meta"),
        ("escaping", "string-escaping-bug", "solc-compiler-bug-class:string-escaping", "codegen"),
        ("override", "override-resolution-bug", "solc-compiler-bug-class:override-resolution", "semantic-analysis"),
    ]
    for needle, bc, ac, subsys in table:
        if needle in text:
            return bc, ac, subsys
    return ("solc-compiler-bug-unclassified", "solc-compiler-bug-class:other", "compiler-other")


def impact_for_bugs_json(name: str, summary: str, description: str, severity: str) -> str:
    text = " ".join([name or "", summary or "", description or ""]).lower()
    if any(k in text for k in ("loss of funds", "drain", "steal", "theft")):
        return "theft"
    if any(k in text for k in ("freeze", "lock", "stuck", "brick")):
        return "freeze"
    if "miscompile" in text or "miscompilation" in text or "wrong" in text or "incorrect" in text:
        # Miscompiles by default route to theft (downstream the resulting
        # bytecode lets a non-owner take an action the source forbids).
        return "theft"
    if "denial of service" in text or "dos" in text or "infinite loop" in text:
        return "dos"
    if "overflow" in text or "underflow" in text or "rounding" in text or "precision" in text:
        return "precision-loss"
    if "selector" in text or "abi" in text or "calldata" in text or "storage layout" in text:
        return "theft"
    if "override" in text or "private" in text:
        return "privilege-escalation"
    if severity == "high":
        return "theft"
    return "griefing"


# ---------------------------------------------------------------------------
# Record builder: bugs.json entry -> hackerman record
# ---------------------------------------------------------------------------


def bugs_json_entry_to_record(entry: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    name = str(entry.get("name") or "").strip()
    uid = str(entry.get("uid") or "").strip()
    if not name or not uid:
        return None
    summary = str(entry.get("summary") or "").strip()
    description = str(entry.get("description") or "").strip()
    link = str(entry.get("link") or "").strip()
    introduced = str(entry.get("introduced") or "").strip()
    fixed = str(entry.get("fixed") or "").strip()
    severity_raw = str(entry.get("severity") or "low").strip()
    conditions = entry.get("conditions") or {}

    severity = normalize_severity(severity_raw)
    bug_class, attack_class, subsystem = classify_bugs_json_entry(name, summary, description)
    impact = impact_for_bugs_json(name, summary, description, severity)
    year = year_from_uid(uid)

    # Canonical URLs. bugs.json itself is always a real source; ``link`` is
    # optional (older entries point at issues/PRs, very old ones omit it).
    bugs_json_anchor = (
        f"https://github.com/ethereum/solidity/blob/develop/docs/bugs.json#{uid}"
    )
    canonical_link = link or bugs_json_anchor

    # record_id from uid + name (stable across reruns).
    record_id_input = f"solc-bugs-json|{uid}|{name}".encode("utf-8")
    digest = hashlib.sha256(record_id_input).hexdigest()[:12]
    record_id = f"solc-compiler:{slugify(uid)}:{slugify(name, max_len=80)}:{digest}"[:160]

    source_audit_ref = f"solc-bugs-json:{uid}:{name}"[:240]

    summary_short = (summary or description[:200] or name)[:400]
    action = (
        f"Solidity team bug record {uid} ({name}). Severity: {severity_raw}. "
        f"Introduced: {introduced or 'unknown'}. Fixed in: {fixed}. "
        f"Summary: {summary_short} "
        f"Canonical bugs.json entry: {bugs_json_anchor}. "
        f"Disclosure / writeup: {canonical_link}. "
        f"Attacker pre-fix path: compile a victim's Solidity source with a "
        f"solc release <= {fixed} (and > {introduced or '0.0.0'}); deploy "
        f"resulting bytecode; trigger the miscompiled behavior path documented "
        f"in the bugs.json entry to break invariants the source assumes hold."
    )
    fix_pattern = (
        f"Solidity {fixed} introduces the fix for {name}. Reviewers porting "
        f"this fix should scan structurally adjacent {subsystem} sites for "
        f"the same primitive (see disclosure: {canonical_link})."
    )
    fix_anti_pattern = (
        f"Compiling production Solidity contracts with a solc release older "
        f"than {fixed} - i.e. omitting the {subsystem} guard / check / codegen "
        f"correction documented in {uid}."
    )

    preconds: List[str] = [
        f"Production deployment compiled with a solc release between "
        f"{introduced or '0.0.0'} (inclusive) and {fixed} (exclusive)",
        f"Affected subsystem: {subsystem}",
        f"Bug uid: {uid}; name: {name}",
        f"verification_tier=tier-1-verified-realtime-api",
    ]
    if conditions:
        cond_str = ", ".join(f"{k}={v}" for k, v in conditions.items())
        preconds.append(f"Trigger conditions: {cond_str}")

    shape_tags = dedupe(
        [
            slugify(attack_class),
            "solc-compiler",
            "src-solc-bugs-json",
            slugify(subsystem),
            slugify(bug_class),
            slugify(uid),
            f"introduced-{slugify(introduced or 'unknown')}",
            f"fixed-{slugify(fixed)}",
        ]
    )

    raw_signature = (
        f"// solc bug {uid} {name} subsystem={subsystem} "
        f"introduced<={introduced or 'pre-0.1.0'} fixed_in={fixed}"
    )[:500]

    record: Dict[str, Any] = {
        "schema_version": SCHEMA_VERSION,
        "record_id": record_id,
        "source_audit_ref": source_audit_ref,
        # solc compiler bugs ultimately impact on-chain contracts compiled
        # with the buggy release. Same mapping convention as Vyper miner.
        "target_domain": "rpc-infra",
        "target_language": "solidity",
        "target_repo": TARGET_REPO,
        "target_component": f"docs/bugs.json#{uid} {name} [{subsystem}]"[:240],
        "function_shape": {
            "raw_signature": raw_signature,
            "shape_tags": shape_tags,
        },
        "bug_class": bug_class[:160],
        "attack_class": attack_class[:160],
        "attacker_role": "unprivileged",
        "attacker_action_sequence": action[:5000],
        "required_preconditions": preconds,
        "impact_class": impact,
        "impact_actor": "arbitrary-user",
        "impact_dollar_class": dollar_class(severity, impact),
        "fix_pattern": fix_pattern[:1000],
        "fix_anti_pattern_avoided": fix_anti_pattern[:1000],
        "severity_at_finding": severity,
        "year": year,
        "record_tier": "public-corpus",
        "record_quality_score": 4.5,
        "source_extraction_method": "corpus-etl",
        "source_extraction_confidence": 0.95,
        "verification_method": "",
        "cross_language_analogues": [
            {
                "target_language": "vyper",
                "pattern_translation": (
                    f"Same compiler-bug class ({bug_class}) in vyper: scan "
                    f"the vyper {subsystem} subsystem fix-history for sibling "
                    "patches addressing the same primitive."
                ),
            },
        ],
        "related_records": [],
    }
    return record


# ---------------------------------------------------------------------------
# Commit-history mining (sibling to vyper miner).
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
    "bug-fix",
    "bug fix",
    "fixed-in",
    "security",
    "vulnerability",
    "audit",
    "patch",
    "cve",
    "ghsa",
]

FIX_REGEX = re.compile(
    r"\b(" + "|".join(re.escape(k) for k in FIX_KEYWORDS) + r")\b",
    re.IGNORECASE,
)
# A more permissive "fix" prefix regex (anchored to the start of subject OR
# directly after a subsystem-prefix like "SSA-CFG: Fix ...") so bare "Fix ..."
# subjects also match without over-matching the word "fix" everywhere.
FIX_PREFIX_REGEX = re.compile(
    r"(^\s*|:\s+|]\s+|\)\s+)(fix|fixes|fixed)\b", re.IGNORECASE
)

# Subsystem / compiler-domain keywords that, when present in a non-merge
# subject, indicate the commit likely belongs in the compiler-bug corpus
# (e.g. SSA-CFG codegen work, ABI encoder fixes, Yul optimizer tweaks).
COMPILER_DOMAIN_REGEX = re.compile(
    r"\b(codegen|yul|ssa[- ]cfg|abi[- ]encoder|abi[- ]coder|abi[- ]reencoding|"
    r"optimizer|inliner|verbatim|via[- ]ir|ir[- ]gen|irgenerator|smt[- ]encoder|"
    r"storage[- ]layout|stack[- ]layout|stack[- ]adjustment|sccp|"
    r"typesystem|typechecker|type[- ]check)\b",
    re.IGNORECASE,
)

NON_PROTOCOL_REGEX = re.compile(
    r"^(typo\b|formatting\b|natspec\b|coverage\b|docs?\b|readme\b|"
    r"prettier\b|eslint\b|^bump\b|version bump|update version|dependabot|"
    r"^style\b|^chore\b)",
    re.IGNORECASE,
)


def is_fix_shape(subject: str, body: str) -> bool:
    # Drop merge commits and pure-churn subjects.
    if subject.lower().startswith("merge "):
        return False
    if NON_PROTOCOL_REGEX.search(subject):
        return False
    if FIX_REGEX.search(subject):
        return True
    if FIX_PREFIX_REGEX.search(subject):
        return True
    # Codegen / SSA-CFG / Yul / ABI / optimizer domain commits land in the
    # compiler-bug corpus as long as they touch a compiler file (the file
    # filter later in ``commit_to_record`` enforces that).
    if COMPILER_DOMAIN_REGEX.search(subject):
        return True
    if FIX_REGEX.search(body[:400]):
        return True
    return False


def list_commits(
    repo: str,
    *,
    per_page: int = 100,
    pages: int = 5,
    since: str = "2018-01-01",
    until: str = "2026-12-31",
    branch: Optional[str] = None,
) -> List[Dict[str, Any]]:
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
    data = gh_api(f"/repos/{repo}/commits/{sha}")
    if not isinstance(data, dict):
        return None
    return data


def _solc_subsystem(file_paths: Sequence[str]) -> str:
    fp_joined = " ".join(file_paths).lower()
    # ABI codec (highest priority - ABI work is its own subsystem even when
    # it lives under codegen/).
    if "abifunctions" in fp_joined or "abicoder" in fp_joined or "abiencoder" in fp_joined:
        return "abi-codec"
    if "/yul" in fp_joined or "yul/" in fp_joined or "yuloptimizer" in fp_joined:
        return "yul-optimizer"
    if "/codegen/ir" in fp_joined or "irgenerator" in fp_joined or "ir/" in fp_joined:
        return "via-ir-codegen"
    if "/codegen/" in fp_joined or "compilerstack" in fp_joined or "expressioncompiler" in fp_joined:
        return "codegen"
    if "/analysis/" in fp_joined or "typechecker" in fp_joined:
        return "semantic-analysis"
    if "/ast/" in fp_joined:
        return "ast-frontend"
    if "/parsing/" in fp_joined or "parser" in fp_joined:
        return "parser"
    if "/abi" in fp_joined or "abi" in fp_joined:
        return "abi-codec"
    if "/optimizer/" in fp_joined or "optimize" in fp_joined:
        return "optimizer"
    if "/solc/" in fp_joined or "commandline" in fp_joined:
        return "cli-frontend"
    return "compiler-other"


def infer_commit_bug_class(subject: str, body: str, subsystem: str) -> Tuple[str, str]:
    low = (subject + " " + body).lower()
    table = [
        ("miscompile", "codegen-miscompilation", "solc-compiler-bug-class:codegen-miscompile"),
        ("miscompilation", "codegen-miscompilation", "solc-compiler-bug-class:codegen-miscompile"),
        ("wrong codegen", "codegen-miscompilation", "solc-compiler-bug-class:codegen-miscompile"),
        ("wrong bytecode", "codegen-miscompilation", "solc-compiler-bug-class:codegen-miscompile"),
        ("internal compiler error", "internal-compiler-error", "solc-compiler-bug-class:ice"),
        (" ice ", "internal-compiler-error", "solc-compiler-bug-class:ice"),
        ("ice:", "internal-compiler-error", "solc-compiler-bug-class:ice"),
        ("storage layout", "storage-layout-bug", "solc-compiler-bug-class:storage-layout"),
        ("yul optimizer", "yul-optimizer-bug", "solc-compiler-bug-class:yul-optimizer"),
        ("yul", "yul-codegen-bug", "solc-compiler-bug-class:yul-codegen"),
        ("via-ir", "via-ir-codegen-bug", "solc-compiler-bug-class:via-ir-codegen"),
        ("optimizer", "optimizer-pass-bug", "solc-compiler-bug-class:optimizer-pass"),
        ("immutable", "immutable-init-bug", "solc-compiler-bug-class:immutable-init"),
        ("transient", "transient-storage-bug", "solc-compiler-bug-class:transient-storage"),
        ("abi", "abi-codec-bug", "solc-compiler-bug-class:abi-codec"),
        ("selector", "function-selector-bug", "solc-compiler-bug-class:function-selector"),
        ("calldata", "calldata-decoding-bug", "solc-compiler-bug-class:calldata-decoding"),
        ("overflow", "arithmetic-overflow-bug", "solc-compiler-bug-class:arithmetic-overflow"),
        ("underflow", "arithmetic-underflow-bug", "solc-compiler-bug-class:arithmetic-underflow"),
        ("type", "type-system-bug", "solc-compiler-bug-class:type-system"),
        ("parser", "parser-frontend-bug", "solc-compiler-bug-class:parser-frontend"),
        ("ast", "ast-frontend-bug", "solc-compiler-bug-class:ast-frontend"),
    ]
    for needle, bc, ac in table:
        if needle in low:
            return bc, ac
    # subsystem fallback
    return f"{subsystem}-fix-shape", f"solc-compiler-bug-class:{subsystem}"


def infer_commit_severity(subject: str, body: str) -> str:
    low = (subject + " " + body).lower()
    if any(k in low for k in ("critical", "loss of funds", "miscompile", "miscompilation")):
        return "high"
    if "security" in low or re.search(r"\bcve\b|\bghsa\b", low):
        return "high"
    if "wrong codegen" in low or "wrong bytecode" in low or "audit" in low:
        return "high"
    if "incorrect" in low or "internal compiler error" in low:
        return "medium"
    if any(k in low for k in ("guard", "validate", "check", "patch")):
        return "medium"
    return "low"


def infer_commit_impact(subject: str, body: str) -> str:
    low = (subject + " " + body).lower()
    if any(k in low for k in ("miscompile", "miscompilation", "wrong codegen", "wrong bytecode")):
        return "theft"
    if any(k in low for k in ("drain", "steal", "theft", "loss of funds")):
        return "theft"
    if any(k in low for k in ("freeze", "stuck", "locked", "brick")):
        return "freeze"
    if any(k in low for k in ("ice", "internal compiler error", "panic", "crash", "hang", "infinite loop")):
        return "dos"
    if any(k in low for k in ("rounding", "precision", "overflow", "underflow")):
        return "precision-loss"
    if any(k in low for k in ("storage layout", "abi", "calldata", "selector")):
        return "theft"
    return "griefing"


_CPP_ASSERT_RE = re.compile(r"^\+\s*(solAssert|solUnimplemented|solRequire|require|assert)\(")
_CPP_THROW_RE = re.compile(r"^\+\s*throw\s+\w+")
_CPP_GUARD_RE = re.compile(r"^\+\s*if\s*\(.{1,160}\)\s*$")


def extract_commit_detector_seed(patch_text: str, subject: str) -> str:
    seeds: List[str] = []
    for line in patch_text.splitlines():
        if not line or line.startswith("+++") or line.startswith("---") or line.startswith("@@"):
            continue
        m = _CPP_ASSERT_RE.match(line)
        if m:
            seeds.append(f"added {m.group(1)} guard")
            continue
        m = _CPP_THROW_RE.match(line)
        if m:
            seeds.append("added throw guard")
            continue
        m = _CPP_GUARD_RE.match(line)
        if m:
            seeds.append("added if-guard")
            continue
    if not seeds:
        sub_low = subject.lower()
        if "miscompile" in sub_low:
            seeds.append("codegen miscompile fix")
        elif "ice" in sub_low:
            seeds.append("ICE-class compiler crash fix")
        elif "yul" in sub_low:
            seeds.append("yul-pass fix")
        elif "abi" in sub_low:
            seeds.append("abi-codec fix")
        else:
            seeds.append("diff-shape-fix")
    return "; ".join(dedupe(seeds)[:8])


def commit_to_record(repo: str, detail: Dict[str, Any]) -> Optional[Dict[str, Any]]:
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

    def _is_compiler_file(p: str) -> bool:
        if not p:
            return False
        # solc compiler tree is rooted at libsolidity/, libyul/, libsolc/,
        # libevmasm/, solc/. Anything under those is a compiler source file.
        roots = ("libsolidity/", "libyul/", "libsolc/", "libevmasm/", "solc/")
        if any(p.startswith(r) for r in roots):
            return p.endswith((".cpp", ".h", ".hpp", ".cc"))
        return False

    def _is_test_only_file(p: str) -> bool:
        return p.startswith("test/") or "/test/" in p or p.startswith("tests/")

    if not any(_is_compiler_file(p) for p in file_paths):
        return None
    if all(_is_test_only_file(p) for p in file_paths):
        return None

    subsystem = _solc_subsystem(file_paths)
    detector_seed = extract_commit_detector_seed(patch_text, subject)
    severity = infer_commit_severity(subject, message)
    impact = infer_commit_impact(subject, message)
    bug_class, attack_class = infer_commit_bug_class(subject, message, subsystem)

    short_sha = sha[:8]
    record_id_input = f"solc-compiler-fix-history|{repo}|{sha}".encode("utf-8")
    digest = hashlib.sha256(record_id_input).hexdigest()[:12]
    repo_slug = slugify(repo.replace("/", "-"), max_len=60)
    record_id = f"git-mining:{repo_slug}:{sha}:{digest}"[:160]
    commit_url = f"https://github.com/{repo}/commit/{sha}"

    raw_signature = (
        f"// commit {sha[:12]} in {repo} subsystem={subsystem} "
        f"touched {len(file_paths)} files"
    )[:500]
    fn_re_cpp = re.compile(r"^\+\s*([A-Za-z_][A-Za-z0-9_]*\s+[A-Za-z_][A-Za-z0-9_:]*\([^)]{0,200}\))")
    fn_re_class = re.compile(r"^\+\s*(class\s+[A-Za-z_][A-Za-z0-9_]*[^\n{]{0,80})")
    for line in patch_text.splitlines():
        m = fn_re_cpp.match(line) or fn_re_class.match(line)
        if m:
            raw_signature = m.group(1).strip()[:500]
            break

    action = (
        f"Upstream solc compiler fix commit at {commit_url}. "
        f"Parent commit: {parent_sha or 'n/a'}. Commit subject: {subject!r}. "
        f"Subsystem: {subsystem}. "
        f"Files changed: {len(file_paths)} ({total_add} additions / {total_del} deletions). "
        f"Detector seed: {detector_seed}. "
        f"Attacker pre-fix path: emit Solidity source that triggers the pre-fix "
        f"behavior in {file_paths[0] if file_paths else 'unknown'} (subsystem {subsystem}); "
        f"deploy resulting bytecode against a mainnet target compiled with a "
        f"solc release earlier than the commit's release tag."
    )
    fix_pattern = (
        f"Diff at {commit_url} applies: {detector_seed}. "
        f"Reviewers porting this fix should scan structurally adjacent "
        f"{subsystem} sites in the same module for the same missing guard."
    )
    fix_anti_pattern = (
        f"Compiling production Solidity contracts with a solc release that "
        f"predates {commit_url} - i.e. omitting the {subsystem} guard / check "
        f"/ codegen correction that this commit added."
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
            "solc-compiler",
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
        "target_domain": "rpc-infra",
        "target_language": "solidity",
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
            f"Production deployment compiled with a solc release built from "
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
                "target_language": "vyper",
                "pattern_translation": (
                    f"Same compiler bug shape ({bug_class}) in vyper: scan "
                    f"vyper's {subsystem} subsystem fix-history for sibling "
                    "patches addressing the same primitive."
                ),
            },
        ],
        "related_records": [],
    }
    return record


# ---------------------------------------------------------------------------
# Pipeline
# ---------------------------------------------------------------------------


def mine_bugs_json(*, override_text: Optional[str] = None) -> List[Dict[str, Any]]:
    """Fetch bugs.json (or use ``override_text`` for tests) and convert entries."""
    text = override_text if override_text is not None else fetch_url(BUGS_JSON_URL)
    if not text:
        return []
    try:
        data = json.loads(text)
    except json.JSONDecodeError as exc:
        sys.stderr.write(f"[warn] bugs.json decode failed: {exc}\n")
        return []
    if not isinstance(data, list):
        return []
    records: List[Dict[str, Any]] = []
    seen_ids: set = set()
    for entry in data:
        if not isinstance(entry, dict):
            continue
        rec = bugs_json_entry_to_record(entry)
        if rec is None:
            continue
        if rec["record_id"] in seen_ids:
            continue
        seen_ids.add(rec["record_id"])
        records.append(rec)
    return records


def mine_commits(
    repo: str,
    *,
    pages: int = 5,
    per_page: int = 100,
    max_records: int = 200,
    detail_cap: int = 250,
    since: str = "2018-01-01",
    until: str = "2026-12-31",
    branch: Optional[str] = None,
) -> Tuple[List[Dict[str, Any]], int, int]:
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


def convert(
    out_dir: Path,
    *,
    dry_run: bool = False,
    limit: Optional[int] = None,
    pages: int = 5,
    per_page: int = 100,
    max_records: int = 200,
    detail_cap: int = 250,
    since: str = "2018-01-01",
    until: str = "2026-12-31",
    branches: Optional[Sequence[Optional[str]]] = None,
    skip_commits: bool = False,
    skip_bugs_json: bool = False,
    bugs_json_override: Optional[str] = None,
) -> Dict[str, Any]:
    records: List[Dict[str, Any]] = []
    errors: List[str] = []
    counts_by_source: Dict[str, int] = {"bugs_json": 0, "commit_history": 0}
    sample_urls: List[str] = []
    seen_record_ids: set = set()

    # 1. bugs.json
    if not skip_bugs_json:
        try:
            bugs_recs = mine_bugs_json(override_text=bugs_json_override)
        except Exception as exc:  # noqa: BLE001
            errors.append(f"mine_bugs_json: {exc}")
            bugs_recs = []
        for r in bugs_recs:
            if r["record_id"] in seen_record_ids:
                continue
            seen_record_ids.add(r["record_id"])
            if limit is not None and len(records) >= limit:
                break
            records.append(r)
            counts_by_source["bugs_json"] += 1

    # 2. commit history
    if not skip_commits and (limit is None or len(records) < limit):
        branch_list: List[Optional[str]] = list(branches) if branches else [None]
        for branch in branch_list:
            try:
                commit_recs, _scanned, _candidates = mine_commits(
                    TARGET_REPO,
                    pages=pages,
                    per_page=per_page,
                    max_records=max_records,
                    detail_cap=detail_cap,
                    since=since,
                    until=until,
                    branch=branch,
                )
            except Exception as exc:  # noqa: BLE001
                errors.append(f"mine_commits(branch={branch}): {exc}")
                continue
            for r in commit_recs:
                if r["record_id"] in seen_record_ids:
                    continue
                seen_record_ids.add(r["record_id"])
                if limit is not None and len(records) >= limit:
                    break
                records.append(r)
                counts_by_source["commit_history"] += 1

    # 3. Validate + emit
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

        # sub-dir name: prefer human-readable name from bugs.json record_id
        # (`solc-compiler:SOL-2026-1:transientstorage...:abc`) else short sha.
        parts = rec["record_id"].split(":")
        if rec["record_id"].startswith("solc-compiler:") and len(parts) >= 3:
            slug_dir = slugify(parts[2], max_len=120) or slugify(parts[1], max_len=120)
        else:
            full_sha = parts[-2] if len(parts) >= 3 else "unknown"
            slug_dir = (
                full_sha[:12]
                if re.fullmatch(r"[0-9a-f]+", full_sha)
                else slugify(full_sha, max_len=120)
            )
        # Disambiguate collisions defensively.
        rec_dir = out_dir / slug_dir
        suffix = 2
        while not dry_run and rec_dir.exists():
            rec_dir = out_dir / f"{slug_dir}-{suffix}"
            suffix += 1
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
        "records_by_source": counts_by_source,
        "sample_urls": sample_urls,
        "errors": errors[:50],
        "error_count": len(errors),
        "file_count": len(file_paths),
        "files_sample": file_paths[:20],
        "negative_verdict": valid < 60,
    }


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--out-dir",
        default="audit/corpus_tags/tags/solc_compiler_bugs",
        help="Output directory (per-record sub-dir). Default: %(default)s",
    )
    parser.add_argument("--dry-run", action="store_true")
    parser.add_argument("--limit", type=int)
    parser.add_argument("--pages", type=int, default=5)
    parser.add_argument("--per-page", type=int, default=100)
    parser.add_argument("--max-records", type=int, default=200)
    parser.add_argument("--detail-cap", type=int, default=250)
    parser.add_argument("--since", default="2018-01-01")
    parser.add_argument("--until", default="2026-12-31")
    parser.add_argument(
        "--branches",
        nargs="*",
        default=None,
        help="Optional branch SHAs / names to walk (default: just the default branch).",
    )
    parser.add_argument("--skip-commits", action="store_true",
                        help="Skip commit-history mining (bugs.json only).")
    parser.add_argument("--skip-bugs-json", action="store_true",
                        help="Skip bugs.json mining (commit-history only).")
    parser.add_argument("--json-summary", action="store_true")
    return parser


def main(argv: Optional[List[str]] = None) -> int:
    args = build_parser().parse_args(argv)
    out_dir = (REPO_ROOT / args.out_dir).resolve() if not os.path.isabs(args.out_dir) else Path(args.out_dir).resolve()
    if args.limit is not None and args.limit < 0:
        print("--limit must be non-negative", file=sys.stderr)
        return 2
    summary = convert(
        out_dir,
        dry_run=args.dry_run,
        limit=args.limit,
        pages=args.pages,
        per_page=args.per_page,
        max_records=args.max_records,
        detail_cap=args.detail_cap,
        since=args.since,
        until=args.until,
        branches=args.branches,
        skip_commits=args.skip_commits,
        skip_bugs_json=args.skip_bugs_json,
    )
    if args.json_summary:
        print(json.dumps(summary, sort_keys=True, indent=2))
    else:
        print(
            "hackerman solc-compiler-bugs ETL: "
            f"valid={summary['records_valid']}/{summary['records_total']} "
            f"by_source={summary['records_by_source']} "
            f"errors={summary['error_count']}"
        )
        if summary["negative_verdict"]:
            print("[NEGATIVE] yield < 60 verifiable records - widen --pages / --branches / --since before relying on this corpus.")
    return 0 if summary["error_count"] == 0 else 1


if __name__ == "__main__":
    raise SystemExit(main())
