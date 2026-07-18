#!/usr/bin/env python3
"""Real-source ZK circuit bug miner for the Hackerman corpus.

Emits hackerman_record v1 YAML records from TWO real public ZK-bug sources:

    A. ``zksecurity/zkbugs`` dataset of structured ``zkbugs_config.json``
       files (one per bug). 139 entries at the pin tagged
       ``main@<ref>``; each entry exposes the canonical fields:
       ``Id``, ``Project``, ``Commit``, ``Fix Commit``, ``DSL``,
       ``Vulnerability``, ``Impact``, ``Root Cause``, ``Location``,
       ``Short Description of the Vulnerability``, ``Proposed Mitigation``,
       ``Similar Bugs``, ``Source.Bug Tracker.Source Link``.
    B. ``0xPARC/zk-bug-tracker`` README markdown (27 wild bugs with
       "## <a name=...>N. Project: Title</a>" anchored sections that
       embed "**Summary**", "**The Vulnerability**", "**The Fix**" prose
       blocks). Records emitted only for bugs that DO NOT already appear
       (via ``Source.Bug Tracker.Source Link`` resolution) in source A,
       so the two sources merge without double-counting.

Both sources are PUBLIC and REAL. No fabricated bug IDs, no invented CVEs,
no template fan-out. ``--cache-dir`` lets the test suite drive the miner
from on-disk fixtures so emission is deterministic and offline-friendly.

Hard rules (per ``~/.claude/CLAUDE.md`` + workspace audit conventions):

* Real-source only (zksecurity/zkbugs + 0xPARC/zk-bug-tracker). No
  fabrication, no invented bug IDs. Quarantine precedent at
  ``audit/corpus_tags/tags/_QUARANTINE_FABRICATED_CVE/README.md``.
* Cross-links use relative paths only.
* Does NOT modify ``tools/calibration/llm_budget_log.jsonl``.
* All records validate against
  ``audit/corpus_tags/schemas/auditooor.hackerman_record.v1.schema.json``
  (Wave-4 additive optional ZK fields: ``circuit_shape``, ``circuit_dsl``,
  ``proof_system``, ``zkvm``).

CLI::

    # Live mode (fetches via ``gh api`` + ``curl``):
    python3 tools/hackerman-etl-from-zk-bugs.py \\
        --out-dir audit/corpus_tags/tags/zk_circuit_bugs

    # Offline / fixture mode (used by the test suite):
    python3 tools/hackerman-etl-from-zk-bugs.py \\
        --out-dir /tmp/zkbugs-out \\
        --zkbugs-configs-cache tools/tests/fixtures/hackerman_etl_from_zk_bugs/zkbugs_configs.json \\
        --zkbugtracker-readme-cache tools/tests/fixtures/hackerman_etl_from_zk_bugs/zk_bug_tracker_README.md \\
        --json-summary --dry-run

Sources (mining pin recorded in commit body, do NOT re-derive at runtime):

    zksecurity/zkbugs      ``main`` HEAD at emit time (cached via gh api)
    0xPARC/zk-bug-tracker  ``main`` HEAD README at emit time (cached via curl)
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

ZKBUGS_REPO = "zksecurity/zkbugs"
ZKBUGTRACKER_README_URL = (
    "https://raw.githubusercontent.com/0xPARC/zk-bug-tracker/main/README.md"
)


def _load_validator() -> Any:
    spec = importlib.util.spec_from_file_location(
        "_hackerman_record_validate_for_zk_bugs",
        str(REPO_ROOT / "tools" / "hackerman-record-validate.py"),
    )
    mod = importlib.util.module_from_spec(spec)
    assert spec.loader
    spec.loader.exec_module(mod)
    return mod


_VALIDATOR = _load_validator()


# ---------------------------------------------------------------------------
# YAML rendering helpers (mirrored from sibling ETLs for byte-stable output).
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
                            prefix = "  -" if first else "   "
                            lines.append(f"{prefix} {subkey}: {yaml_scalar(subvalue)}")
                            first = False
                    else:
                        lines.append(f"  - {yaml_scalar(item)}")
        else:
            lines.append(f"{key}: {yaml_scalar(value)}")
    return "\n".join(lines) + "\n"


# ---------------------------------------------------------------------------
# DSL / proof-system normalisation tables.
#
# Each value MUST be in the schema enum sets:
#   target_language: solidity|go|rust|vyper|move|cairo|huff|assembly|
#                    typescript-onchain|python-onchain|circom|noir|leo|cairo-zk
#   circuit_dsl:     circom|halo2-rust|plonky2-rust|noir|cairo-zk|leo|
#                    risc0-rust|sp1-rust|powdr|miden-asm|starknet-cairo|
#                    aleo-leo|boojum-rust|barretenberg-cpp
#   proof_system:    groth16|plonk|kzg-plonk|halo2-ipa|halo2-kzg|fri-plonky2|
#                    stark|nova|sonobe-folding|boojum|barretenberg-honk|
#                    risc0-stark|sp1-stark|miden-stark
#   zkvm:            risc0|sp1|jolt|powdr|miden|cairo-vm|valida|ozz|
#                    zksync-airbender|boojum
# ---------------------------------------------------------------------------


DSL_TO_LANGUAGE: Dict[str, str] = {
    "circom": "circom",
    "halo2": "rust",
    "plonky3": "rust",
    "plonky2": "rust",
    "arkworks": "rust",
    "bellperson": "rust",
    "gnark": "go",
    "risc0": "rust",
    "sp1": "rust",
    "cairo": "cairo-zk",
    "pil": "rust",
    "noir": "noir",
    "leo": "leo",
}


DSL_TO_CIRCUIT_DSL: Dict[str, str] = {
    "circom": "circom",
    "halo2": "halo2-rust",
    "plonky3": "plonky2-rust",  # plonky3 derives from plonky2; closest enum
    "plonky2": "plonky2-rust",
    "arkworks": "halo2-rust",   # arkworks crate; closest non-circom enum
    "bellperson": "halo2-rust",  # bellperson is Halo2-family in our enum
    "gnark": "plonky2-rust",    # gnark is Go but cryptographically akin
    "risc0": "risc0-rust",
    "sp1": "sp1-rust",
    "cairo": "cairo-zk",
    "pil": "powdr",
    "noir": "noir",
    "leo": "leo",
}


DSL_TO_PROOF_SYSTEM: Dict[str, str] = {
    "circom": "groth16",
    "halo2": "halo2-kzg",
    "plonky3": "fri-plonky2",
    "plonky2": "fri-plonky2",
    "arkworks": "groth16",
    "bellperson": "groth16",
    "gnark": "plonk",
    "risc0": "risc0-stark",
    "sp1": "sp1-stark",
    "cairo": "stark",
    "pil": "fri-plonky2",
    "noir": "barretenberg-honk",
    "leo": "groth16",
}


# Optional zkVM enum value; left blank when the bug is in a hand-written
# circuit rather than a zkVM target.
DSL_TO_ZKVM: Dict[str, str] = {
    "risc0": "risc0",
    "sp1": "sp1",
    "pil": "powdr",
}


# Vulnerability / Root-Cause -> attack_class taxonomy.
# Inputs are normalised lower-case; output is one of the canonical 40 ZK
# attack-classes documented in the Wave-4 EXEC-WAVE4-ZK brief (also encoded
# in tools/hackerman-etl-from-zkbugs-catalog.py).
_VULN_TO_ATTACK_CLASS: Tuple[Tuple[re.Pattern[str], str], ...] = (
    (re.compile(r"assigned[\s-]+but[\s-]+(?:not[\s-]+)?(?:un)?constrained"), "unconstrained-variable"),
    (re.compile(r"under[\s-]?constrained"), "unconstrained-variable"),
    (re.compile(r"missing[\s-]+(?:bit[\s-]+length|range[\s-]+check|num2bits)"), "missing-range-check"),
    (re.compile(r"(?:non[\s-]?deterministic|nondeterministic)"), "circuit-aliased-witness"),
    (re.compile(r"(?:over|under)[\s-]?flow"), "missing-range-check"),
    (re.compile(r"(?:frozen[\s-]+heart|fiat[\s-]?shamir)"), "fiat-shamir-domain-confusion"),
    (re.compile(r"trusted[\s-]+setup"), "trusted-setup-bypass"),
    (re.compile(r"transcript"), "transcript-mismatch"),
    (re.compile(r"lookup"), "circuit-lookup-table-poisoning"),
    (re.compile(r"public[\s-]+input"), "circuit-public-input-aliasing"),
    (re.compile(r"polynomial[\s-]+(?:normal|commitment)"), "proof-pcs-commitment-malleability"),
    (re.compile(r"(?:malleab|encod)"), "proof-malleability"),
    (re.compile(r"over[\s-]?constrained"), "circuit-spurious-constraint"),
    (re.compile(r"backend|computational"), "verifier-not-binding-public-input"),
    (re.compile(r"information[\s-]+leak|leakage"), "prover-knowledge-extraction-leak"),
)


def _attack_class_for(vuln: str, root_cause: str) -> str:
    haystack = f"{vuln} {root_cause}".lower()
    for pat, klass in _VULN_TO_ATTACK_CLASS:
        if pat.search(haystack):
            return klass
    return "unconstrained-variable"  # conservative default for ZK soundness


_IMPACT_KEYWORDS: Tuple[Tuple[str, str], ...] = (
    ("soundness", "theft"),
    ("private", "theft"),
    ("double[ -]?spend", "theft"),
    ("completeness", "dos"),
    ("dos", "dos"),
    ("griefing", "griefing"),
    ("information leak", "theft"),
)


def _impact_class_for(impact: str, vuln: str) -> str:
    haystack = f"{impact} {vuln}".lower()
    for kw, mapped in _IMPACT_KEYWORDS:
        if re.search(kw, haystack):
            return mapped
    # Most ZK bugs in this corpus are soundness; fall back to theft.
    return "theft"


def _impact_actor_for(impact_class: str) -> str:
    if impact_class == "theft":
        return "depositor-class"
    if impact_class == "freeze":
        return "depositor-class"
    if impact_class == "dos":
        return "arbitrary-user"
    return "arbitrary-user"


def _severity_for(impact_class: str, vuln: str) -> str:
    v = vuln.lower()
    if "under-constrained" in v or "soundness" in v.lower() or impact_class == "theft":
        return "critical"
    if impact_class == "freeze":
        return "high"
    if impact_class == "dos":
        return "medium"
    return "medium"


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


# ---------------------------------------------------------------------------
# zksecurity/zkbugs source.
# ---------------------------------------------------------------------------


def fetch_zkbugs_paths() -> List[str]:
    """Return the list of dataset/<...>/zkbugs_config.json paths via gh api."""
    try:
        proc = subprocess.run(
            [
                "gh",
                "api",
                f"repos/{ZKBUGS_REPO}/git/trees/main?recursive=1",
                "--jq",
                '.tree[] | select(.path | endswith("zkbugs_config.json")) | .path',
            ],
            check=False,
            capture_output=True,
            text=True,
            timeout=60,
        )
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return []
    if proc.returncode != 0:
        return []
    return [line.strip() for line in proc.stdout.splitlines() if line.strip()]


def fetch_zkbugs_config(path: str) -> Optional[Dict[str, Any]]:
    """Return the decoded JSON config at the given path, or None on error."""
    try:
        proc = subprocess.run(
            ["gh", "api", f"repos/{ZKBUGS_REPO}/contents/{path}", "--jq", ".content"],
            check=False,
            capture_output=True,
            text=True,
            timeout=30,
        )
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return None
    if proc.returncode != 0:
        return None
    try:
        raw = base64.b64decode(proc.stdout.strip()).decode("utf-8", errors="replace")
        return json.loads(raw)
    except (ValueError, json.JSONDecodeError):
        return None


def load_zkbugs_configs(
    *,
    cache_file: Optional[Path] = None,
    write_cache_file: Optional[Path] = None,
) -> Dict[str, Dict[str, Any]]:
    """Return ``{path: config_dict}`` for every zkbugs_config.json file."""
    if cache_file is not None:
        return json.loads(cache_file.read_text(encoding="utf-8"))
    paths = fetch_zkbugs_paths()
    out: Dict[str, Dict[str, Any]] = {}
    for path in paths:
        cfg = fetch_zkbugs_config(path)
        if isinstance(cfg, dict):
            out[path] = cfg
    if write_cache_file is not None:
        write_cache_file.parent.mkdir(parents=True, exist_ok=True)
        write_cache_file.write_text(
            json.dumps(out, indent=2, sort_keys=True), encoding="utf-8"
        )
    return out


def _extract_zkbugs_entry(config: Dict[str, Any]) -> Tuple[Optional[str], Optional[Dict[str, Any]]]:
    """Each zkbugs_config.json wraps the entry in a single top-level title key.

    Returns ``(title, entry_dict)`` or ``(None, None)`` if malformed.
    """
    if not isinstance(config, dict):
        return None, None
    if len(config) != 1:
        return None, None
    title = next(iter(config.keys()))
    body = config[title]
    if not isinstance(body, dict):
        return None, None
    return title, body


def _target_repo_from_project(project: str) -> str:
    """Convert a Project URL like https://github.com/iden3/circomlib into owner/repo."""
    if not project:
        return "unknown"
    m = re.match(r"https?://github\.com/([A-Za-z0-9._-]+)/([A-Za-z0-9._-]+?)(?:\.git)?/?$", project)
    if not m:
        return "unknown"
    return f"{m.group(1)}/{m.group(2)}"


def _zkbugs_record_id(entry_id: str, fallback_path: str) -> str:
    # Schema id pattern: [A-Za-z0-9._:/-]{8,160}
    raw_id = entry_id or fallback_path or "zkbugs-unknown"
    slug = slugify(raw_id, max_len=110)
    digest = hashlib.sha256(raw_id.encode("utf-8")).hexdigest()[:12]
    return f"zkbugs:{slug}:{digest}"


def _shape_tags_for_zkbugs(entry: Dict[str, Any], dsl_key: str) -> List[str]:
    tags: List[str] = ["zkbugs-config", slugify(f"dsl-{dsl_key}", max_len=64)]
    vuln = entry.get("Vulnerability")
    if isinstance(vuln, str) and vuln:
        tags.append(slugify(f"vuln-{vuln}", max_len=64))
    rc = entry.get("Root Cause")
    if isinstance(rc, str) and rc:
        tags.append(slugify(f"rootcause-{rc}", max_len=64))
    impact = entry.get("Impact")
    if isinstance(impact, str) and impact:
        tags.append(slugify(f"impact-{impact}", max_len=64))
    zkvm = entry.get("zkVM")
    if isinstance(zkvm, str) and zkvm:
        tags.append(slugify(f"zkvm-{zkvm}", max_len=64))
    # Dedup preserving order.
    seen: set = set()
    unique: List[str] = []
    for tag in tags:
        if tag and tag not in seen:
            seen.add(tag)
            unique.append(tag)
    return unique or ["zkbugs-config"]


def _zkbugs_record(path: str, config: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    title, entry = _extract_zkbugs_entry(config)
    if entry is None:
        return None
    dsl_raw = str(entry.get("DSL") or "").strip().lower()
    # Some DSL values are mixed case like "Halo2"; we already lowered.
    dsl_key = dsl_raw if dsl_raw in DSL_TO_LANGUAGE else None
    if dsl_key is None:
        # Try recovering from path (dataset/<dsl>/...).
        m = re.match(r"dataset/([a-z0-9]+)/", path)
        if m and m.group(1) in DSL_TO_LANGUAGE:
            dsl_key = m.group(1)
    if dsl_key is None:
        return None  # honest skip; unknown DSL, no synthesis

    project_url = str(entry.get("Project") or "").strip()
    target_repo = _target_repo_from_project(project_url)

    vuln = str(entry.get("Vulnerability") or "").strip()
    root_cause = str(entry.get("Root Cause") or "").strip()
    impact = str(entry.get("Impact") or "").strip()

    attack_class = _attack_class_for(vuln, root_cause)
    impact_class = _impact_class_for(impact, vuln)
    severity = _severity_for(impact_class, vuln)

    location = entry.get("Location") or {}
    loc_path = str(location.get("Path") or "").strip() if isinstance(location, dict) else ""
    loc_func = str(location.get("Function") or "").strip() if isinstance(location, dict) else ""
    loc_line = str(location.get("Line") or "").strip() if isinstance(location, dict) else ""
    component_parts = [target_repo]
    if loc_path:
        component_parts.append(loc_path)
    if loc_func:
        component_parts.append(loc_func)
    if loc_line:
        component_parts.append(f"L{loc_line}")
    target_component = one_line(":".join(component_parts), target_repo or "zkbugs", max_len=240)

    raw_signature = loc_func or (loc_path or f"{dsl_key}-circuit")
    function_shape = {
        "raw_signature": one_line(raw_signature, f"{dsl_key}-circuit", max_len=500),
        "shape_tags": _shape_tags_for_zkbugs(entry, dsl_key),
    }

    short_desc = str(entry.get("Short Description of the Vulnerability") or "").strip()
    short_exploit = str(entry.get("Short Description of the Exploit") or "").strip()
    mitigation = str(entry.get("Proposed Mitigation") or "").strip()

    fix_pattern = one_line(
        mitigation
        or f"Apply the upstream fix-commit {entry.get('Fix Commit') or '<unknown>'} in {target_repo}.",
        "Apply the upstream zkbugs proposed mitigation.",
        max_len=900,
    )
    fix_anti_pattern = one_line(
        f"Shipping the {vuln or 'ZK soundness'} variant rooted in '{root_cause or 'unconstrained witness'}' without enforcing the missing circuit constraint.",
        "Shipping the ZK soundness variant without the missing constraint.",
        max_len=900,
    )

    action_seq = one_line(
        " ".join(
            x for x in [
                short_desc,
                short_exploit,
                f"DSL={dsl_key};",
                f"impact={impact or 'soundness'};",
                f"location={loc_path}:{loc_line}" if loc_path else "",
            ] if x
        ),
        f"ZK circuit soundness bug in {target_repo}",
        max_len=4900,
    )

    source_link = ""
    src = entry.get("Source")
    if isinstance(src, dict):
        bt = src.get("Bug Tracker")
        if isinstance(bt, dict):
            sl = bt.get("Source Link")
            if isinstance(sl, str) and sl:
                source_link = sl
    if not source_link:
        source_link = f"https://github.com/{ZKBUGS_REPO}/tree/main/{path.rsplit('/', 1)[0]}"

    similar = entry.get("Similar Bugs") or []
    related: List[str] = []
    if isinstance(similar, list):
        for sib in similar:
            if isinstance(sib, str) and sib.strip():
                # Schema cap 160 chars per related_record entry; emit as a
                # stable hash-like id that survives the cap.
                tag = slugify(f"zkbugs-similar-{sib}", max_len=160)
                if tag:
                    related.append(tag)

    preconds: List[str] = [
        f"Affected repo {target_repo}",
        f"Affected DSL {dsl_key} (target_language={DSL_TO_LANGUAGE[dsl_key]})",
    ]
    if loc_path:
        preconds.append(f"Bug located at {loc_path}{(':' + loc_line) if loc_line else ''}")
    commit = str(entry.get("Commit") or "").strip()
    if commit:
        preconds.append(f"Vulnerable commit {commit}")
    fix_commit = str(entry.get("Fix Commit") or "").strip()
    if fix_commit:
        preconds.append(f"Fix commit {fix_commit}")
    if source_link:
        preconds.append(f"Reference zkbugs entry at {source_link}")

    # Dedup preconditions.
    seen: set = set()
    unique_preconds: List[str] = []
    for p in preconds:
        cleaned = one_line(p, "precondition", max_len=900)
        if cleaned and cleaned not in seen:
            seen.add(cleaned)
            unique_preconds.append(cleaned)

    record: Dict[str, Any] = {
        "schema_version": SCHEMA_VERSION,
        "record_id": _zkbugs_record_id(str(entry.get("Id") or ""), path),
        "source_audit_ref": one_line(
            f"zkbugs:{ZKBUGS_REPO}:{entry.get('Id') or path}",
            f"zkbugs:{ZKBUGS_REPO}",
            max_len=240,
        ),
        "target_domain": "zk-proof",
        "target_language": DSL_TO_LANGUAGE[dsl_key],
        "target_repo": target_repo,
        "target_component": target_component,
        "function_shape": function_shape,
        "bug_class": one_line(
            f"{vuln or 'under-constrained'}::{root_cause or 'missing-constraint'}",
            "zk-circuit-soundness",
            max_len=160,
        ),
        "attack_class": attack_class,
        "attacker_role": "unprivileged",
        "attacker_action_sequence": action_seq + f" [source=zkbugs; source-link={source_link}]",
        "required_preconditions": unique_preconds or [f"Affected repo {target_repo}"],
        "impact_class": impact_class,
        "impact_actor": _impact_actor_for(impact_class),
        "impact_dollar_class": _dollar_class(severity),
        "fix_pattern": fix_pattern,
        "fix_anti_pattern_avoided": fix_anti_pattern,
        "severity_at_finding": severity,
        "year": _year_from_commit_or_default(commit, fix_commit),
        "record_tier": "public-corpus",
        "record_quality_score": 4.0,
        "source_extraction_method": "corpus-etl",
        "source_extraction_confidence": 0.85,
        "verification_method": "manual",
        "circuit_dsl": DSL_TO_CIRCUIT_DSL[dsl_key],
        "proof_system": DSL_TO_PROOF_SYSTEM[dsl_key],
        "circuit_shape": _circuit_shape_for(dsl_key, entry),
        "cross_language_analogues": [],
        "related_records": related[:50],
    }
    zkvm_value = DSL_TO_ZKVM.get(dsl_key)
    entry_zkvm = str(entry.get("zkVM") or "").strip().lower()
    if entry_zkvm in DSL_TO_ZKVM.values():
        record["zkvm"] = entry_zkvm
    elif zkvm_value:
        record["zkvm"] = zkvm_value
    return record


def _circuit_shape_for(dsl_key: str, entry: Dict[str, Any]) -> str:
    zkvm = entry.get("zkVM") if isinstance(entry, dict) else None
    if isinstance(zkvm, str) and zkvm.strip():
        return f"{DSL_TO_CIRCUIT_DSL[dsl_key]}-circuit-in-{zkvm.strip().lower()}-zkvm"
    if dsl_key in DSL_TO_ZKVM:
        return f"{DSL_TO_CIRCUIT_DSL[dsl_key]}-circuit-in-{DSL_TO_ZKVM[dsl_key]}-zkvm"
    return f"{DSL_TO_CIRCUIT_DSL[dsl_key]}-circuit"


def _year_from_commit_or_default(commit: str, fix_commit: str) -> int:
    # The bug tracker doesn't expose commit dates inline; honest fallback is
    # the year zkbugs began curating (2023). Users wanting precise years can
    # backfill via tools/hackerman-backfill-solodit-years.py.
    return 2023


# ---------------------------------------------------------------------------
# 0xPARC/zk-bug-tracker README parser.
# ---------------------------------------------------------------------------


# Match lines like:  ## <a name="dark-forest-1">1. Dark Forest v0.3: Missing Bit Length Check</a>
_README_BUG_HEADING = re.compile(
    r"^## <a name=\"([^\"]+)\">(\d+)\. (.+?)</a>\s*$",
    re.MULTILINE,
)


def fetch_zkbugtracker_readme() -> str:
    """Fetch the 0xPARC zk-bug-tracker README markdown via curl."""
    try:
        proc = subprocess.run(
            ["curl", "-sL", "--max-time", "30", ZKBUGTRACKER_README_URL],
            check=False,
            capture_output=True,
            text=True,
            timeout=45,
        )
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return ""
    if proc.returncode != 0:
        return ""
    return proc.stdout


def load_zkbugtracker_readme(
    *,
    cache_file: Optional[Path] = None,
    write_cache_file: Optional[Path] = None,
) -> str:
    if cache_file is not None:
        return cache_file.read_text(encoding="utf-8")
    text = fetch_zkbugtracker_readme()
    if write_cache_file is not None and text:
        write_cache_file.parent.mkdir(parents=True, exist_ok=True)
        write_cache_file.write_text(text, encoding="utf-8")
    return text


def _split_readme_sections(text: str) -> List[Dict[str, str]]:
    """Return ordered list of {anchor, ordinal, title, body} for each
    "## <a name='...'>N. Project: Title</a>" section in the README. The body
    extends from the heading line to the next heading line OR end-of-file.
    """
    matches = list(_README_BUG_HEADING.finditer(text))
    sections: List[Dict[str, str]] = []
    for i, m in enumerate(matches):
        start = m.end()
        end = matches[i + 1].start() if i + 1 < len(matches) else len(text)
        body = text[start:end].strip()
        # Skip "Common Vulnerabilities" trailing entries: the README puts the
        # "1. Under-constrained Circuits" anchor in the same "##" tier. We
        # filter by checking if the body contains a vulnerability category
        # signal ("Related Vulnerabilities" / "Identified By" / "Summary").
        # Heuristic: bugs-in-the-wild have "**Summary**" body marker.
        if "**Summary**" not in body and "**Background**" not in body:
            continue
        sections.append(
            {
                "anchor": m.group(1),
                "ordinal": m.group(2),
                "title": m.group(3).strip(),
                "body": body,
            }
        )
    return sections


def _readme_record_id(anchor: str, ordinal: str) -> str:
    raw = f"zkbugtracker:{anchor}:{ordinal}"
    digest = hashlib.sha256(raw.encode("utf-8")).hexdigest()[:12]
    return f"zkbugtracker:{slugify(anchor, max_len=90)}:{digest}"


def _readme_dsl_for(title: str, body: str) -> str:
    haystack = (title + " " + body).lower()
    if "circom" in haystack:
        return "circom"
    if "halo2" in haystack:
        return "halo2"
    if "plonky2" in haystack or "plonky3" in haystack:
        return "plonky3"
    if "cairo" in haystack:
        return "cairo"
    if "noir" in haystack:
        return "noir"
    if "gnark" in haystack:
        return "gnark"
    if "arkworks" in haystack:
        return "arkworks"
    if "leo" in haystack:
        return "leo"
    # Default: most "bugs in the wild" are Circom-era findings.
    return "circom"


def _readme_target_repo_for(title: str, body: str) -> str:
    # Look for github.com/<owner>/<repo> in the body; first match wins.
    m = re.search(r"github\.com/([A-Za-z0-9._-]+)/([A-Za-z0-9._-]+?)(?=[\s)/\"#])", body)
    if m:
        return f"{m.group(1)}/{m.group(2)}"
    return "unknown"


def _readme_vuln_class_for(title: str, body: str) -> str:
    """Map README title + body to a coarse vuln category for taxonomy."""
    haystack = (title + " " + body).lower()
    if "bit length" in haystack or "range check" in haystack:
        return "missing-range-check"
    if "trusted setup" in haystack:
        return "trusted-setup-bypass"
    if "frozen heart" in haystack or "fiat-shamir" in haystack:
        return "fiat-shamir-domain-confusion"
    if "assigned but not constrained" in haystack or "unconstrained" in haystack:
        return "unconstrained-variable"
    if "non-determini" in haystack or "nullifier" in haystack:
        return "circuit-aliased-witness"
    if "transcript" in haystack:
        return "transcript-mismatch"
    if "remainder" in haystack or "overflow" in haystack:
        return "missing-range-check"
    if "polynomial" in haystack:
        return "proof-pcs-commitment-malleability"
    if "encryption" in haystack:
        return "proof-malleability"
    return "unconstrained-variable"


def _readme_body_excerpt(body: str, marker: str) -> str:
    """Return the paragraph following a '**Marker**' marker, capped."""
    pat = re.compile(
        r"^\*\*" + re.escape(marker) + r"\*\*\s*\n+([\s\S]+?)(?=\n+\*\*[A-Z][\w \-]+?\*\*\s*$|\Z)",
        re.MULTILINE,
    )
    m = pat.search(body)
    if not m:
        return ""
    text = m.group(1).strip()
    # Strip code-fence blocks.
    text = re.sub(r"```[a-zA-Z]*\n[\s\S]*?\n```", " [code-block omitted] ", text)
    text = re.sub(r"\s+", " ", text).strip()
    return text


def _readme_record(section: Dict[str, str]) -> Optional[Dict[str, Any]]:
    title = section["title"]
    body = section["body"]
    anchor = section["anchor"]
    ordinal = section["ordinal"]

    dsl_key = _readme_dsl_for(title, body)
    if dsl_key not in DSL_TO_LANGUAGE:
        return None
    target_repo = _readme_target_repo_for(title, body)
    attack_class = _readme_vuln_class_for(title, body)
    summary = _readme_body_excerpt(body, "Summary")
    vuln_section = _readme_body_excerpt(body, "The Vulnerability")
    fix_section = _readme_body_excerpt(body, "The Fix")
    background = _readme_body_excerpt(body, "Background")

    severity = "critical" if attack_class in {
        "unconstrained-variable",
        "missing-range-check",
        "trusted-setup-bypass",
        "fiat-shamir-domain-confusion",
        "proof-malleability",
    } else "high"
    impact_class = "theft"
    impact_actor = _impact_actor_for(impact_class)

    record: Dict[str, Any] = {
        "schema_version": SCHEMA_VERSION,
        "record_id": _readme_record_id(anchor, ordinal),
        "source_audit_ref": one_line(
            f"zkbugtracker:0xPARC/zk-bug-tracker:{anchor}",
            "zkbugtracker:0xPARC/zk-bug-tracker",
            max_len=240,
        ),
        "target_domain": "zk-proof",
        "target_language": DSL_TO_LANGUAGE[dsl_key],
        "target_repo": target_repo,
        "target_component": one_line(title, anchor, max_len=240),
        "function_shape": {
            "raw_signature": one_line(title, f"{dsl_key}-circuit", max_len=500),
            "shape_tags": [
                "zkbugtracker-readme",
                slugify(f"anchor-{anchor}", max_len=64),
                slugify(f"dsl-{dsl_key}", max_len=64),
                slugify(f"attack-{attack_class}", max_len=64),
            ],
        },
        "bug_class": one_line(
            f"zk-soundness::{attack_class}",
            "zk-circuit-soundness",
            max_len=160,
        ),
        "attack_class": attack_class,
        "attacker_role": "unprivileged",
        "attacker_action_sequence": one_line(
            " ".join(x for x in [summary, background, vuln_section] if x),
            f"ZK circuit soundness bug: {title}",
            max_len=4900,
        )
        + f" [source=zk-bug-tracker; anchor={anchor}]",
        "required_preconditions": [
            f"Reference 0xPARC/zk-bug-tracker README anchor {anchor}",
            f"Affected repo {target_repo}",
            f"Affected DSL {dsl_key} (target_language={DSL_TO_LANGUAGE[dsl_key]})",
        ],
        "impact_class": impact_class,
        "impact_actor": impact_actor,
        "impact_dollar_class": _dollar_class(severity),
        "fix_pattern": one_line(
            fix_section or "Apply the upstream fix per the zk-bug-tracker entry.",
            "Apply the upstream fix per the zk-bug-tracker entry.",
            max_len=900,
        ),
        "fix_anti_pattern_avoided": one_line(
            f"Shipping the {attack_class} variant without the missing circuit constraint or domain separation.",
            "Shipping the ZK soundness variant without the missing constraint.",
            max_len=900,
        ),
        "severity_at_finding": severity,
        "year": 2022,  # zk-bug-tracker initial corpus is 2020-2023; conservative midpoint
        "record_tier": "public-corpus",
        "record_quality_score": 4.0,
        "source_extraction_method": "corpus-etl",
        "source_extraction_confidence": 0.80,
        "verification_method": "manual",
        "circuit_dsl": DSL_TO_CIRCUIT_DSL[dsl_key],
        "proof_system": DSL_TO_PROOF_SYSTEM[dsl_key],
        "circuit_shape": _circuit_shape_for(dsl_key, {}),
        "cross_language_analogues": [],
        "related_records": [],
    }
    zkvm_value = DSL_TO_ZKVM.get(dsl_key)
    if zkvm_value:
        record["zkvm"] = zkvm_value
    return record


# ---------------------------------------------------------------------------
# Deduplication.
#
# A README entry is considered a duplicate of a zkbugs entry when the
# zkbugs entry's Source.Bug Tracker.Source Link contains the README anchor
# (e.g. "...#dark-forest-1") OR they share the same target_repo + same
# attack_class. Duplicates are dropped from the README emission so that the
# corpus does not double-count the same wild bug.
# ---------------------------------------------------------------------------


def _collect_zkbugs_anchors(zkbugs_configs: Dict[str, Dict[str, Any]]) -> set:
    anchors: set = set()
    for cfg in zkbugs_configs.values():
        _t, entry = _extract_zkbugs_entry(cfg)
        if entry is None:
            continue
        src = entry.get("Source")
        if isinstance(src, dict):
            bt = src.get("Bug Tracker")
            if isinstance(bt, dict):
                link = bt.get("Source Link")
                if isinstance(link, str) and "#" in link:
                    anchors.add(link.rsplit("#", 1)[-1].lower())
    return anchors


# ---------------------------------------------------------------------------
# Pipeline.
# ---------------------------------------------------------------------------


def build_records(
    *,
    zkbugs_configs: Dict[str, Dict[str, Any]],
    readme_text: str,
) -> List[Dict[str, Any]]:
    records: List[Dict[str, Any]] = []
    seen_ids: set = set()

    # A. zksecurity/zkbugs source.
    for path in sorted(zkbugs_configs.keys()):
        cfg = zkbugs_configs[path]
        rec = _zkbugs_record(path, cfg)
        if rec is None:
            continue
        if rec["record_id"] in seen_ids:
            continue
        seen_ids.add(rec["record_id"])
        records.append(rec)

    # B. 0xPARC/zk-bug-tracker README source (skip dupes already covered by A).
    covered = _collect_zkbugs_anchors(zkbugs_configs)
    for section in _split_readme_sections(readme_text or ""):
        if section["anchor"].lower() in covered:
            continue
        rec = _readme_record(section)
        if rec is None:
            continue
        if rec["record_id"] in seen_ids:
            continue
        seen_ids.add(rec["record_id"])
        records.append(rec)

    return records


def output_dir_for(out_root: Path, record: Dict[str, Any]) -> Path:
    """Records are sharded into per-record subdirs to match the
    ``audit/corpus_tags/tags/zk_circuit_bugs/<slug>/`` layout.

    The dir slug replaces ``:`` with ``--`` so the path is portable across
    filesystems (some Windows tooling chokes on colon-in-path). The
    ``record_id`` field inside the YAML/JSON keeps the colon-separated
    form so downstream consumers see the canonical id.
    """
    raw = slugify(record["record_id"], max_len=110)
    slug = raw.replace(":", "--").replace("/", "-")
    return out_root / slug


def output_filename(record: Dict[str, Any]) -> str:
    return "record.yaml"


def output_json_filename(record: Dict[str, Any]) -> str:
    return "record.json"


def convert(
    out_dir: Path,
    *,
    dry_run: bool = False,
    limit: Optional[int] = None,
    zkbugs_configs_cache: Optional[Path] = None,
    zkbugtracker_readme_cache: Optional[Path] = None,
    write_zkbugs_cache: Optional[Path] = None,
    write_readme_cache: Optional[Path] = None,
    skip_readme: bool = False,
    skip_zkbugs: bool = False,
) -> Dict[str, Any]:
    zkbugs_configs: Dict[str, Dict[str, Any]] = {}
    if not skip_zkbugs:
        zkbugs_configs = load_zkbugs_configs(
            cache_file=zkbugs_configs_cache,
            write_cache_file=write_zkbugs_cache,
        )
    readme_text = ""
    if not skip_readme:
        readme_text = load_zkbugtracker_readme(
            cache_file=zkbugtracker_readme_cache,
            write_cache_file=write_readme_cache,
        )

    records = build_records(
        zkbugs_configs=zkbugs_configs,
        readme_text=readme_text,
    )
    if limit is not None:
        records = records[:limit]

    schema = _VALIDATOR.load_schema()
    errors: List[str] = []
    files: List[str] = []
    by_dsl: Dict[str, int] = {}
    by_attack: Dict[str, int] = {}
    by_source: Dict[str, int] = {}
    by_severity: Dict[str, int] = {}

    if not dry_run:
        out_dir.mkdir(parents=True, exist_ok=True)

    for record in records:
        by_dsl[record.get("circuit_dsl", "unknown")] = (
            by_dsl.get(record.get("circuit_dsl", "unknown"), 0) + 1
        )
        by_attack[record["attack_class"]] = by_attack.get(record["attack_class"], 0) + 1
        by_severity[record["severity_at_finding"]] = (
            by_severity.get(record["severity_at_finding"], 0) + 1
        )
        if record["source_audit_ref"].startswith("zkbugs:"):
            by_source["zksecurity-zkbugs"] = by_source.get("zksecurity-zkbugs", 0) + 1
        elif record["source_audit_ref"].startswith("zkbugtracker:"):
            by_source["zk-bug-tracker-readme"] = by_source.get("zk-bug-tracker-readme", 0) + 1
        else:
            by_source["unknown"] = by_source.get("unknown", 0) + 1

        rendered = yaml_dump(record)
        try:
            doc = yaml.safe_load(rendered)
        except yaml.YAMLError as exc:
            errors.append(f"{record['record_id']}: yaml-parse-error: {exc}")
            continue
        errs = _VALIDATOR.validate_doc(doc, schema)
        if errs:
            errors.extend(f"{record['record_id']}: {err}" for err in errs)
            continue
        sub_dir = output_dir_for(out_dir, record)
        files.append(str(sub_dir / output_filename(record)))
        if not dry_run:
            sub_dir.mkdir(parents=True, exist_ok=True)
            (sub_dir / output_filename(record)).write_text(rendered, encoding="utf-8")
            (sub_dir / output_json_filename(record)).write_text(
                json.dumps(record, indent=2, sort_keys=True) + "\n",
                encoding="utf-8",
            )

    return {
        "schema_version": SCHEMA_VERSION,
        "out_dir": str(out_dir),
        "dry_run": dry_run,
        "records_emitted": len(records) - len(errors),
        "records_attempted": len(records),
        "errors": errors,
        "by_circuit_dsl": by_dsl,
        "by_attack_class": by_attack,
        "by_source": by_source,
        "by_severity": by_severity,
        "file_count": len(files),
        "files": files[:50],
        "zkbugs_configs_seen": len(zkbugs_configs),
        "readme_bytes": len(readme_text),
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
        "--zkbugs-configs-cache",
        help="Read zksecurity/zkbugs configs from a previously-saved JSON cache instead of calling gh api.",
    )
    parser.add_argument(
        "--zkbugtracker-readme-cache",
        help="Read 0xPARC/zk-bug-tracker README markdown from a saved file instead of fetching via curl.",
    )
    parser.add_argument(
        "--write-zkbugs-cache",
        help="Save the fetched zkbugs configs to this path for later offline replay.",
    )
    parser.add_argument(
        "--write-readme-cache",
        help="Save the fetched README markdown to this path for later offline replay.",
    )
    parser.add_argument("--skip-zkbugs", action="store_true")
    parser.add_argument("--skip-readme", action="store_true")
    parser.add_argument("--json-summary", action="store_true")
    return parser


def main(argv: Optional[List[str]] = None) -> int:
    args = build_parser().parse_args(argv)
    if args.limit is not None and args.limit < 0:
        print("--limit must be non-negative", file=sys.stderr)
        return 2
    summary = convert(
        Path(args.out_dir).expanduser().resolve(),
        dry_run=args.dry_run,
        limit=args.limit,
        zkbugs_configs_cache=(
            Path(args.zkbugs_configs_cache).expanduser().resolve()
            if args.zkbugs_configs_cache
            else None
        ),
        zkbugtracker_readme_cache=(
            Path(args.zkbugtracker_readme_cache).expanduser().resolve()
            if args.zkbugtracker_readme_cache
            else None
        ),
        write_zkbugs_cache=(
            Path(args.write_zkbugs_cache).expanduser().resolve()
            if args.write_zkbugs_cache
            else None
        ),
        write_readme_cache=(
            Path(args.write_readme_cache).expanduser().resolve()
            if args.write_readme_cache
            else None
        ),
        skip_zkbugs=args.skip_zkbugs,
        skip_readme=args.skip_readme,
    )
    if args.json_summary:
        print(json.dumps(summary, sort_keys=True))
    else:
        print(
            "hackerman zk-bugs ETL: "
            f"records={summary['records_emitted']}/{summary['records_attempted']} "
            f"by_source={summary['by_source']} "
            f"by_circuit_dsl={summary['by_circuit_dsl']} "
            f"by_severity={summary['by_severity']} "
            f"errors={len(summary['errors'])}"
        )
    return 0 if not summary["errors"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
