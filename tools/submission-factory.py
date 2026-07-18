#!/usr/bin/env python3
"""Submission factory — build `cantina_ready.md` per packaged bundle.

Capability v3 iter-001 T5 (Codex #6). Plan anchor `2014a539`.

Goal: collapse the ~20 min/row manual Cantina/HackenProof upload checklist
into a single operator-facing markdown by extracting data that the
`submission-packager.py` already wrote into a bundle. No data fabrication.
Every field must trace to a real source file; missing inputs degrade to
the literal string "(not available — manual fill required)".

Inputs (read-only):
  <bundle>/source-draft.md               required
  <bundle>/evidence-matrix.json          optional (summary+rows preferred)
  <bundle>/manifest.json                 optional (gates.variant + fork_replay)
  <bundle>/fork_replay/manifest.json     optional
  <bundle>/fork_replay/...               optional (files)
  <bundle>/live_topology_checks.json     optional
  <bundle>/live-proof/                   optional (dir)
  <bundle>/scope_review/source-draft.heuristic-review.md    optional
  <bundle>/scope_review/source-draft.agent-review.md        optional

Output: `<bundle>/cantina_ready.md` (overridable via --out). The filename
is `cantina_ready.md` regardless of platform — the section content is the
same across platforms; only the wording of section 1 flexes.

Hard rules (from plan):
  - No platform API calls. The tool writes markdown, operator uploads.
  - No ledger writes. Tool produces artifacts only.
  - Triager-risk classifier is pattern-matching, not ML. Patterns are
    derived verbatim from docs/TRIAGER_OUTCOMES_POST_ITER13.md (POLY-45,
    POLY-46, POLY-49, SNOW R67-F001 rejection classes).
  - Every emitted field is grep-able from a real source file in the bundle.

Offline, stdlib-only. Safe to re-run (idempotent: overwrites `--out`).
"""
from __future__ import annotations

import argparse
import importlib.util
import json
import os
import re
import shlex
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

_MISSING = "(not available — manual fill required)"
_NOT_PROVIDED = "Not provided in the bundle."

# Known platforms accepted on --platform. Default comes from the bundle
# manifest if present, else falls back to "other".
_PLATFORMS = {"hackenproof", "cantina", "sherlock", "immunefi", "code4rena", "other"}
_PIM_LIB_CACHE_KEY = "_submission_factory_program_impact_mapping_lib"
_HARNESS_EXECUTION_CONTRACT_SCHEMA = "auditooor.harness_execution_contract.v1"
_EXACT_COMMAND_PLACEHOLDERS = ("tbd", "todo", "needs_human", "<fixture", "<workspace", "must emit", "should emit")

# Per-platform paste-ready packets the factory can emit. Each maps to a
# `_render_<target>` function that consumes the same bundle inputs as the
# original cantina render and reorders / relabels for the platform's web
# form schema. `cantina` is the default and the legacy emit; `all` fans
# out to every per-platform packet under the bundle dir.
_TARGETS = ("cantina", "immunefi", "sherlock", "c4", "hackerone", "spearbit", "all")


# ─── File readers (all tolerate absence — never raise on missing) ─────────

def _read_text(path: Path) -> Optional[str]:
    try:
        return path.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError):
        return None


def _read_json(path: Path) -> Optional[Dict[str, Any]]:
    raw = _read_text(path)
    if raw is None:
        return None
    try:
        return json.loads(raw)
    except json.JSONDecodeError:
        return None


def _load_impact_mapping_lib() -> Optional[Any]:
    cached = sys.modules.get(_PIM_LIB_CACHE_KEY)
    if cached is not None:
        return cached
    spec_path = Path(__file__).resolve().parent / "lib" / "program_impact_mapping.py"
    if not spec_path.is_file():
        return None
    spec = importlib.util.spec_from_file_location(_PIM_LIB_CACHE_KEY, spec_path)
    if spec is None or spec.loader is None:
        return None
    module = importlib.util.module_from_spec(spec)
    sys.modules[_PIM_LIB_CACHE_KEY] = module
    try:
        spec.loader.exec_module(module)  # type: ignore[union-attr]
    except Exception:
        sys.modules.pop(_PIM_LIB_CACHE_KEY, None)
        return None
    return module


# ─── Draft parsing ────────────────────────────────────────────────────────

# Title shape from packager examples:
#   "## ✅ Submission 10 — #R77-06 — Medium — VERIFIED PoC"
#   "## ✅ Submission — #R67-F001 — High — VERIFIED PoC"
#   "# NegRiskFeeModule CTF token transfers revert — fee refunds and ..."
# The canonical "Finding Title" block is more reliable when present:
_H1_OR_H2_RE = re.compile(r"^(#{1,2})\s+(.+?)\s*$", re.MULTILINE)
_FINDING_TITLE_RE = re.compile(
    r"###\s+Finding\s+Title.*?\n```[^\n]*\n(.+?)\n```", re.DOTALL | re.IGNORECASE
)
_SEVERITY_INLINE_RE = re.compile(
    r"(?:^|\n)\s*(?:-\s*)?\*{0,2}Severity(?:\s*:|\s*=>\s*Severity\s*:)\s*\*{0,2}\s*([A-Za-z]+)",
    re.IGNORECASE,
)
_SEVERITY_HDR_RE = re.compile(r"^\s*\*\*Severity:\*\*\s*([A-Za-z]+)", re.MULTILINE)
# Header title pattern includes severity between em-dashes.
_TITLE_SEV_RE = re.compile(r"—\s*(Critical|High|Medium|Low|Informational)\b", re.IGNORECASE)


def parse_draft_title(draft_text: str) -> str:
    """Return the best-effort finding title; never fabricate."""
    # Prefer explicit "Finding Title" code-block (packager convention).
    m = _FINDING_TITLE_RE.search(draft_text)
    if m:
        return m.group(1).strip()
    # Fall back to first H1/H2. Strip leading checkmark + "Submission" noise.
    first = _H1_OR_H2_RE.search(draft_text)
    if first:
        raw = first.group(2).strip()
        # Drop leading emoji-checkmark + "Submission ..." framing if present.
        cleaned = re.sub(r"^[^\w]*Submission\s*\d*\s*—\s*", "", raw).strip()
        return cleaned or raw
    return _MISSING


def parse_draft_severity(draft_text: str) -> str:
    m = _SEVERITY_HDR_RE.search(draft_text)
    if m:
        return m.group(1).strip().capitalize()
    m = _TITLE_SEV_RE.search(draft_text)
    if m:
        return m.group(1).strip().capitalize()
    m = _SEVERITY_INLINE_RE.search(draft_text)
    if m:
        return m.group(1).strip().capitalize()
    return _MISSING


def parse_draft_impact(draft_text: str) -> str:
    """Extract the first paragraph under `## Impact` (or `### Impact`).

    Returns `_MISSING` if no Impact section, even if the word "impact"
    appears inline. No fabrication.
    """
    m = re.search(
        r"(?:^|\n)#{1,4}\s+Impact\b[^\n]*\n+(.+?)(?:\n#{1,4}\s|\Z)",
        draft_text, re.DOTALL,
    )
    if not m:
        return _MISSING
    block = m.group(1).strip()
    # Trim to ~60 lines to keep output compact; operator can consult
    # source-draft.md for the full block.
    lines = block.splitlines()
    if len(lines) > 60:
        lines = lines[:60] + ["", "… (truncated — see source-draft.md for full text)"]
    return "\n".join(lines).strip() or _MISSING


def parse_attack_trace(draft_text: str) -> str:
    """Extract Attack flow / Attack path / numbered exploit sequence."""
    # Packager drafts use various headings: "Attack flow", "Attack path",
    # or numbered list under Impact. Try each.
    for header in ("Attack flow", "Attack path", "Attack Path", "Attack Trace"):
        m = re.search(
            rf"(?:^|\n)#{{1,4}}\s+{re.escape(header)}\b[^\n]*\n+(.+?)(?:\n#{{1,4}}\s|\Z)",
            draft_text, re.DOTALL,
        )
        if m:
            return m.group(1).strip()
    # Fall back: first numbered list found inside the Impact block
    # (packager convention — "1. ... 2. ... 3. ..."). We scan within the
    # Impact section body rather than requiring the numbered list to be the
    # first thing after the header.
    impact_m = re.search(
        r"(?:^|\n)#{1,4}\s+Impact\b[^\n]*\n+(.+?)(?:\n#{1,4}\s|\Z)",
        draft_text, re.DOTALL,
    )
    if impact_m:
        body = impact_m.group(1)
        list_m = re.search(r"((?:^|\n)\s*1\.\s+[^\n]+(?:\n\s*\d+\.\s+[^\n]+)+)", body)
        if list_m:
            return list_m.group(1).strip()
    return _MISSING


def parse_dollar_impact(draft_text: str) -> str:
    """Grep a `$N` figure from Impact / Severity block. Returns first hit."""
    for section in ("Impact", "Severity"):
        m = re.search(
            rf"(?:^|\n)#{{1,4}}\s+{section}\b[^\n]*\n+(.+?)(?:\n#{{1,4}}\s|\Z)",
            draft_text, re.DOTALL,
        )
        if not m:
            continue
        dollar = re.search(r"\$[0-9][0-9,.]*\s*(?:k|K|M|m)?(?:\+)?", m.group(1))
        if dollar:
            return dollar.group(0)
    return _MISSING


# ─── PoC command derivation ───────────────────────────────────────────────

_CONTRACT_RE = re.compile(r"^\s*contract\s+([A-Za-z_][A-Za-z0-9_]*)\b", re.MULTILINE)


def find_poc_files(bundle: Path) -> List[Path]:
    """Return all `*.t.sol` files anywhere inside the bundle."""
    return sorted(p for p in bundle.rglob("*.t.sol") if p.is_file())


def derive_poc_command(bundle: Path) -> Tuple[str, List[str]]:
    """Return (`forge test --match-contract X`, [poc-rel-paths]).

    Pattern follows packager convention: the first `contract X is Test`
    (or similar) inside `<bundle>/poc.t.sol` is the intended match target.
    If multiple `.t.sol` files exist, the one literally named `poc.t.sol`
    wins; otherwise the alphabetically-first path wins. If no contract
    declaration is grep-able, returns `_MISSING` for the command so the
    operator fills it by hand.
    """
    pocs = find_poc_files(bundle)
    if not pocs:
        return _MISSING, []
    # Prefer the conventional filename.
    primary = next((p for p in pocs if p.name == "poc.t.sol"), pocs[0])
    src = _read_text(primary) or ""
    m = _CONTRACT_RE.search(src)
    if not m:
        return _MISSING, [str(p.relative_to(bundle)) for p in pocs]
    contract_name = m.group(1)
    cmd = f"forge test --match-contract {contract_name} -vvv"
    return cmd, [str(p.relative_to(bundle)) for p in pocs]


def _quote_execution_part(part: str) -> str:
    """Quote shell tokens while preserving documented env-var expansion."""
    if (
        part in {"${AUDITOOOR_DIR}", "${BUNDLE_ROOT}"}
        or part.startswith("${AUDITOOOR_DIR}/")
        or part.startswith("${BUNDLE_ROOT}/")
    ):
        return f'"{part}"'
    return shlex.quote(part)


def _load_harness_binding_manifest(bundle: Path) -> Tuple[Optional[Dict[str, Any]], Optional[str]]:
    """Load the harness binding manifest if present, else `(None, None)`."""
    manifest_path = bundle / "harness-binding-manifest.json"
    if not manifest_path.is_file():
        return (None, None)
    raw = _read_json(manifest_path)
    if raw is None:
        return (None, "harness-binding-manifest.json is not valid JSON")
    if not isinstance(raw.get("entries"), list) or not isinstance(raw.get("unresolved_angles"), list):
        return (
            None,
            "harness-binding-manifest.json must contain list fields "
            "`entries` and `unresolved_angles`",
        )
    return (raw, None)


def harness_execution_contract_lines(bundle: Path) -> List[str]:
    """Render exact harness execution contracts or an honest blocked state."""
    manifest_path = bundle / "harness-binding-manifest.json"
    harnesses = sorted((bundle / "harnesses").glob("*.t.sol"))
    manifest, error = _load_harness_binding_manifest(bundle)
    if manifest is None and error:
        return [f"- BLOCKED — {error}"]
    if manifest is None:
        if harnesses:
            return ["- BLOCKED — `harness-binding-manifest.json` missing for bundled harnesses"]
        return ["- (not present in bundle)"]

    lines: List[str] = [f"- Binding manifest: `{manifest_path.name}`"]
    entries = manifest.get("entries", [])
    executable_entries = 0
    for entry in entries:
        if not isinstance(entry, dict):
            lines.append("- BLOCKED — manifest contains a non-object entry")
            continue
        angle = str(entry.get("angle_id") or "").strip()
        rel_path = str(entry.get("bundle_harness") or "").strip()
        contract_name = str(entry.get("contract_name") or "").strip()
        execution_contract = entry.get("execution_contract")
        contract_commands, contract_blockers = _validated_harness_execution_contract(execution_contract)
        if not angle or not rel_path or not contract_name:
            lines.append("- BLOCKED — manifest entry missing `angle_id`, `bundle_harness`, or `contract_name`")
            continue
        if contract_blockers:
            lines.append(
                f"- `{angle}`: BLOCKED — missing exact runnable harness execution contract "
                f"({', '.join(contract_blockers)})"
            )
            lines.append(f"  - selector: `{rel_path}` / contract `{contract_name}`")
            continue
        lines.append(f"- `{angle}`: runnable only after exact gate + harness commands pass")
        lines.append(f"  - gating_test: `{contract_commands['gating_test']}`")
        lines.append(f"  - harness_command: `{contract_commands['harness_command']}`")
        lines.append(f"  - selector: `{rel_path}` / contract `{contract_name}`")
        executable_entries += 1

    for item in manifest.get("unresolved_angles", []):
        if not isinstance(item, dict):
            continue
        angle = str(item.get("angle_id") or "").strip() or "unknown-angle"
        reason = str(item.get("reason") or "unknown").strip() or "unknown"
        lines.append(f"- `{angle}`: BLOCKED — {reason}")

    if executable_entries == 0 and not manifest.get("unresolved_angles"):
        lines.append("- BLOCKED — manifest has no executable harness bindings")
    return lines


def _is_exact_execution_command(value: Any) -> bool:
    text = str(value or "").strip()
    if not text:
        return False
    lowered = text.lower()
    return not any(token in lowered for token in _EXACT_COMMAND_PLACEHOLDERS)


def _validated_harness_execution_contract(execution_contract: Any) -> Tuple[Dict[str, str], List[str]]:
    """Return exact command pair or blockers for a runnable harness contract."""
    commands_out: Dict[str, str] = {}
    blockers: List[str] = []
    if not isinstance(execution_contract, dict):
        return commands_out, ["missing_execution_contract"]

    if execution_contract.get("schema") != _HARNESS_EXECUTION_CONTRACT_SCHEMA:
        blockers.append("invalid_or_legacy_execution_contract_schema")
    if execution_contract.get("claim") != "runnable_harness":
        blockers.append("execution_contract_not_runnable_harness")
    if execution_contract.get("runnable") is not True:
        blockers.append("execution_contract_not_marked_runnable")
    if execution_contract.get("advisory_only") is True:
        blockers.append("execution_contract_marked_advisory_only")
    if execution_contract.get("fail_closed") is not True:
        blockers.append("execution_contract_not_fail_closed")

    commands = execution_contract.get("commands")
    if not isinstance(commands, dict):
        blockers.append("execution_contract_missing_commands")
        commands = {}

    harness_command = str(commands.get("harness_command") or "").strip()
    gating_test = str(commands.get("gating_test") or "").strip()
    if not _is_exact_execution_command(harness_command):
        blockers.append("missing_exact_harness_command")
    else:
        commands_out["harness_command"] = harness_command
    if not _is_exact_execution_command(gating_test):
        blockers.append("missing_exact_gating_test")
    else:
        commands_out["gating_test"] = gating_test

    missing_inputs = execution_contract.get("missing_inputs")
    if isinstance(missing_inputs, list) and missing_inputs:
        blockers.append("execution_contract_has_missing_inputs")
    contract_blockers = execution_contract.get("blockers")
    if isinstance(contract_blockers, list) and contract_blockers:
        blockers.append("execution_contract_has_blockers")

    if blockers:
        return {}, list(dict.fromkeys(blockers))
    return commands_out, []


# ─── Evidence matrix summary ──────────────────────────────────────────────

def evidence_matrix_summary_lines(em: Optional[Dict[str, Any]]) -> List[str]:
    if em is None:
        return ["- No evidence matrix was supplied in the bundle."]
    rows = em.get("rows") or []
    summary = em.get("summary") or {}
    lines: List[str] = []
    verdict = summary.get("ready_verdict")
    if verdict:
        lines.append(f"**Verdict:** `{verdict}`")
        lines.append("")
    if not rows:
        lines.append("- Evidence matrix was present but contained no rows.")
        return lines
    for row in rows:
        label = row.get("label") or row.get("key") or "?"
        status = row.get("status") or "?"
        notes = (row.get("notes") or "").strip()
        if notes:
            lines.append(f"- `{label}`: **{status}** — {notes}")
        else:
            lines.append(f"- `{label}`: **{status}**")
    return lines


# ─── Fork-replay section ──────────────────────────────────────────────────

def fork_replay_section_lines(bundle: Path, manifest: Optional[Dict[str, Any]]) -> List[str]:
    """Describe fork-replay artifacts if any, else say so honestly."""
    fr_dir = bundle / "fork_replay"
    fr_dir_exists = fr_dir.is_dir()
    fr_manifest = None
    if fr_dir_exists:
        fr_manifest = _read_json(fr_dir / "manifest.json")
    # Manifest-packager may also embed a fork_replay summary.
    embedded = None
    if manifest and isinstance(manifest.get("fork_replay"), dict):
        embedded = manifest["fork_replay"]

    lines: List[str] = []
    if not fr_dir_exists and not embedded:
        lines.append("- No fork-replay evidence was supplied in the bundle.")
        return lines
    if fr_dir_exists:
        lines.append(f"- Fork-replay bundle: `fork_replay/` (present)")
        if fr_manifest and isinstance(fr_manifest.get("entries"), list):
            for entry in fr_manifest["entries"]:
                if not isinstance(entry, dict):
                    continue
                path = entry.get("path") or entry.get("rel_path") or "?"
                status = entry.get("status") or entry.get("result") or "?"
                lines.append(f"  - `{path}` — `{status}`")
    if embedded:
        resolved = embedded.get("resolved") or []
        missing = embedded.get("missing") or []
        malformed = embedded.get("malformed") or []
        referenced = embedded.get("referenced") or []
        lines.append(
            f"- Packager summary: {len(resolved)} resolved, "
            f"{len(missing)} missing, {len(malformed)} malformed, "
            f"{len(referenced)} referenced"
        )
        if not resolved and not referenced and not fr_dir_exists:
            lines.append("- No fork-replay entries resolved. Source-only rationale required.")
    if not lines:
        lines.append("- No fork-replay evidence was supplied in the bundle.")
    return lines


# ─── Dupe-defense (cites Check #7 variant-detector verbatim) ──────────────

def dupe_defense_lines(manifest: Optional[Dict[str, Any]]) -> List[str]:
    """Cite the packager's variant-detector output verbatim.

    If manifest.gates.variant is absent, emit the literal string
    "dupe risk unknown" — this is intentionally NOT fabricated as "LOW".
    """
    if not manifest:
        return ["- dupe risk unknown (manifest.json absent from bundle)"]
    variant = (manifest.get("gates") or {}).get("variant")
    if not isinstance(variant, dict):
        return ["- dupe risk unknown (manifest.json has no `gates.variant` block)"]
    risk = variant.get("risk_level") or "unknown"
    top_score = variant.get("top_score")
    comparison = variant.get("comparison_source") or "(source unspecified)"
    lines: List[str] = [
        f"- Variant-detector risk: **`{risk}`** (Check #7)",
        f"- Comparison source: `{comparison}`",
    ]
    if top_score is not None:
        lines.append(f"- Top-match score: `{top_score}`")
    matches = variant.get("matches") or []
    if matches:
        lines.append("- Top matches:")
        for m in matches[:5]:
            if not isinstance(m, dict):
                continue
            title = (m.get("title") or "")[:110]
            status = m.get("status") or "?"
            score = m.get("score") or "?"
            lines.append(f"  - `{status}` (score=`{score}`): {title}")
    return lines


# ─── Triager-risk classifier (pattern-match, NOT ML) ──────────────────────
#
# Patterns derived verbatim from docs/TRIAGER_OUTCOMES_POST_ITER13.md.
# Each entry: (class_id, detector_fn, push-back string, pre-emptive response).


_UINT_BOUNDS_PATTERNS = [
    r"uint248",
    r"uint256\.max",
    r"type\(uint256\)\.max",
    r"2\s*\*\*\s*248",
    r"2\s*\^\s*248",
    r"2\^248",
    r"2\*\*256",
    r"2\^256",
]

_EVENT_ONLY_HINTS = [
    r"\bemit[s]?\b",
    r"\bwrong\s+(?:index|arg|argument|parameter|topic)\b",
    r"\bevent[- ]only\b",
    r"\bwrong\s+event\b",
    r"\bindexed\s+wrong\b",
]

_STATE_CORRUPTION_HINTS = [
    r"\bstate\s+corruption\b",
    r"\bfund\s+loss\b",
    r"\btheft\b",
    r"\bdrained?\b",
    r"\bstale\s+storage\b",
    r"\bbalance.*overwritten\b",
    r"\bwrong\s+balance\b",
]

_ATTRIBUTION_PATTERNS = [
    r"\battribution\b.*\bwrong\b",
    r"\bmisattributes?\b",
    r"\bindex(?:es|ed)?\s+(?:the\s+)?wrong\s+user\b",
    r"\bevent\s+emits\s+wrong\s+(?:address|user|operator|caller)\b",
]

_CROSS_CHAIN_PATTERNS = [
    r"\bbridge\b",
    r"\bcross[- ]chain\b",
    r"\bL1\s*(?:↔|<->|<-|->)\s*L2\b",
    r"\bPolkadot\b",
    r"\bSnowbridge\b",
    r"\brelayer\b",
    r"\bxcm\b",
]


def _any_match(text: str, patterns: List[str]) -> bool:
    for p in patterns:
        if re.search(p, text, re.IGNORECASE):
            return True
    return False


def classify_triager_risks(draft_text: str) -> List[Tuple[str, str, str]]:
    """Return list of (class_id, pushback, response) triples.

    Classes (verbatim from TRIAGER_OUTCOMES_POST_ITER13.md):
      - POLY-45: unrealistic bounds (uint248/2^248/uint256.max claims).
      - POLY-46: event-only finding with no state-corruption claim.
      - POLY-49: attribution reconstructible from sibling events.
      - SNOW-R67-F001: OOS cross-chain atomicity (bridge protocols).
    """
    flags: List[Tuple[str, str, str]] = []
    text = draft_text  # keep original case for regex matching in some rules

    # POLY-45: extreme uint bounds without realistic-bounds justification.
    if _any_match(text, _UINT_BOUNDS_PATTERNS):
        flags.append((
            "POLY-45",
            "unrealistic bounds",
            "Cite realistic token supply / bounds that make the extreme value "
            "achievable in practice, or downgrade severity to Informational. "
            "See Check #12 in pre-submit-check.sh.",
        ))

    # POLY-46: event-only claim. Heuristic — mentions of wrong/emitted events
    # without a paired state-corruption claim fires the flag.
    has_event_hint = _any_match(text, _EVENT_ONLY_HINTS)
    has_state_hint = _any_match(text, _STATE_CORRUPTION_HINTS)
    if has_event_hint and not has_state_hint:
        flags.append((
            "POLY-46",
            "event-only cosmetic",
            "Demonstrate that a downstream indexer, accounting system, or "
            "on-chain consumer actually reads the wrong event and ends up in "
            "a wrong state — else triagers will classify as cosmetic. "
            "See Check #13 in pre-submit-check.sh.",
        ))

    # POLY-49: attribution-reconstructible. Keyword pattern dedicated to the
    # "wrong index / misattributes user" shape.
    if _any_match(text, _ATTRIBUTION_PATTERNS):
        flags.append((
            "POLY-49",
            "attribution reconstructible from sibling events",
            "Explicitly argue why the user identity cannot be reconstructed "
            "from sibling events in the same transaction (ERC1155.TransferBatch, "
            "TransferSingle, etc.). If it can be reconstructed, downgrade "
            "severity or drop.",
        ))

    # SNOW R67-F001: cross-chain atomicity OOS.
    if _any_match(text, _CROSS_CHAIN_PATTERNS):
        flags.append((
            "SNOW-R67-F001",
            "OOS cross-chain atomicity",
            "Explicitly verify that the bridge / cross-chain step does NOT "
            "atomically compose the attacker-visible state transition "
            "end-to-end (Polkadot-origin + Ethereum-side). Cite the "
            "scope-review sub-agent's bridge semantics analysis. Without "
            "this, triagers will reject as out-of-scope.",
        ))

    return flags


def triager_risk_section_lines(draft_text: str) -> List[str]:
    flags = classify_triager_risks(draft_text)
    if not flags:
        return ["- No known rejection-class matches."]
    lines: List[str] = []
    for class_id, pushback, response in flags:
        lines.append(f"- **[{class_id}]** Likely triager pushback: {pushback}.")
        lines.append(f"  Pre-emptive response: {response}")
    return lines


# ─── Scope-review pull-through ────────────────────────────────────────────

def scope_review_lines(bundle: Path) -> List[str]:
    lines: List[str] = []
    sr = bundle / "scope_review"
    heuristic = sr / "source-draft.heuristic-review.md"
    agent = sr / "source-draft.agent-review.md"
    if heuristic.is_file():
        lines.append(f"- Heuristic scope review: `scope_review/{heuristic.name}`")
    else:
        lines.append("- Heuristic scope review: (not present in bundle)")
    if agent.is_file():
        lines.append(f"- Agent scope review: `scope_review/{agent.name}`")
    else:
        lines.append("- Agent scope review: (not present in bundle — heuristic-only path)")
    return lines


# ─── Section 1 platform framing ───────────────────────────────────────────

def platform_framing(platform: str) -> str:
    blurbs = {
        "cantina": "Paste into the Cantina submission form fields.",
        "hackenproof": "Paste into the HackenProof submission form fields.",
        "sherlock": "Paste into the Sherlock submission form fields.",
        "immunefi": "Paste into the Immunefi submission form fields.",
        "code4rena": "Paste into the Code4rena submission form fields.",
        "other": "Paste into the platform submission form fields (platform not recognized).",
    }
    return blurbs.get(platform, blurbs["other"])


def pick_platform(cli_platform: Optional[str], manifest: Optional[Dict[str, Any]]) -> str:
    if cli_platform:
        return cli_platform
    if manifest:
        # Packager doesn't stamp `platform` today; fall back to workspace
        # heuristic. This is purely a label; operator can override via --platform.
        ws = manifest.get("workspace")
        # snowbridge uses hackenproof; polymarket uses Cantina/other.
        if ws == "snowbridge":
            return "hackenproof"
        if ws == "polymarket":
            return "other"
    return "other"


def _resolve_workspace_for_bundle(bundle: Path) -> Optional[Path]:
    """Find the audit workspace root that owns a packaged bundle."""
    cur = bundle.resolve()
    root = Path(cur.anchor or "/")
    severity_only_candidate: Optional[Path] = None
    while cur != root:
        if (cur / "OOS_CHECKLIST.md").exists() or (cur / "SCOPE.md").exists():
            return cur
        if severity_only_candidate is None and any(
            p.name.lower().startswith("severity") and p.name.lower().endswith(".md")
            for p in cur.glob("*.md")
        ):
            severity_only_candidate = cur
        cur = cur.parent
    return severity_only_candidate


def impact_contract_refusal(bundle: Path) -> Optional[str]:
    """Return a fail-closed refusal reason for missing/unproved impact lock."""
    draft_path = bundle / "source-draft.md"
    draft_text = _read_text(draft_path) or ""
    pim_lib = _load_impact_mapping_lib()
    if pim_lib is None:
        return "impact_contract_helper_unavailable"
    workspace = _resolve_workspace_for_bundle(bundle)
    try:
        summary = pim_lib.validate_impact_contract_text(
            draft_text,
            workspace=workspace,
            require_contract=True,
        )
    except Exception as exc:  # pragma: no cover - defensive fail closed
        return f"impact_contract_validation_error:{exc}"
    if not bool(summary.get("ok")):
        reasons = summary.get("reasons") or ["impact_contract_invalid"]
        return "impact_contract_invalid:" + ",".join(str(r) for r in reasons)
    if not bool(summary.get("listed_impact_proven")):
        return "impact_contract_invalid:listed_impact_not_proven"
    proof_artifact = str((summary.get("fields") or {}).get("proof_artifact") or "").strip()
    if not proof_artifact:
        return "impact_contract_invalid:proof_artifact_missing"
    proof_path = Path(proof_artifact).expanduser()
    if proof_path.is_absolute():
        candidate_paths = [proof_path]
    else:
        candidate_paths = [bundle / proof_path]
        if workspace is not None:
            candidate_paths.append(workspace / proof_path)
    if not any(path.is_file() for path in candidate_paths):
        return "impact_contract_invalid:proof_artifact_not_found"
    selected = str(summary.get("selected_impact") or "").strip()
    matched_tier = str(summary.get("matched_rubric_tier") or "").strip()
    if not selected or not matched_tier:
        return "impact_contract_invalid:selected_impact_not_exact_listed_sentence"
    claimed_severity = parse_draft_severity(draft_text)
    if claimed_severity in {"Critical", "High", "Medium"} and claimed_severity != matched_tier:
        return "impact_contract_invalid:severity_claim_not_backed_by_selected_impact_tier"
    return None


# ─── Appendix — raw evidence paths ────────────────────────────────────────

def appendix_paths(bundle: Path) -> List[str]:
    def rel(path: Path) -> str:
        try:
            return str(path.relative_to(bundle))
        except ValueError:
            return path.name

    lines = [
        "- Bundle root: `.`",
        "- Source draft: `source-draft.md`",
    ]
    if (bundle / "evidence-matrix.json").is_file():
        lines.append("- Evidence matrix JSON: `evidence-matrix.json`")
    if (bundle / "manifest.json").is_file():
        lines.append("- Packager manifest: `manifest.json`")
    if (bundle / "harness-binding-manifest.json").is_file():
        lines.append("- Harness binding manifest: `harness-binding-manifest.json`")
    for poc in find_poc_files(bundle):
        lines.append(f"- PoC test file: `{rel(poc)}`")
    fr_dir = bundle / "fork_replay"
    if fr_dir.is_dir():
        lines.append("- Fork-replay dir: `fork_replay/`")
    live_dir = bundle / "live-proof"
    if live_dir.is_dir():
        lines.append("- Live-proof dir: `live-proof/`")
    live_topology = bundle / "live_topology_checks.json"
    if live_topology.is_file():
        lines.append("- Live topology: `live_topology_checks.json`")
    sr = bundle / "scope_review"
    if sr.is_dir():
        lines.append("- Scope review dir: `scope_review/`")
    return lines


# ─── Builder ──────────────────────────────────────────────────────────────

def _collect_render_inputs(bundle: Path) -> Dict[str, Any]:
    """Read all bundle inputs once and hand the same dict to every renderer.

    Per-platform packets re-use the same parsed fields; they only differ
    in section ordering / header wording / framing. Pulling parsing out
    of the per-platform render functions keeps them as ~30-60 LOC of
    pure markdown emission and guarantees every platform sees identical
    facts (no drift between cantina_ready.md and immunefi_ready.md).
    """
    draft_path = bundle / "source-draft.md"
    draft_text = _read_text(draft_path) or ""
    manifest = _read_json(bundle / "manifest.json")
    em = _read_json(bundle / "evidence-matrix.json")

    def paste_value(value: str) -> str:
        return _NOT_PROVIDED if value == _MISSING else value

    return {
        "bundle": bundle,
        "draft_text": draft_text,
        "manifest": manifest,
        "em": em,
        "title": paste_value(parse_draft_title(draft_text) if draft_text else _MISSING),
        "severity": paste_value(parse_draft_severity(draft_text) if draft_text else _MISSING),
        "impact_block": paste_value(parse_draft_impact(draft_text) if draft_text else _MISSING),
        "dollar": paste_value(parse_dollar_impact(draft_text) if draft_text else _MISSING),
        "attack_trace": paste_value(parse_attack_trace(draft_text) if draft_text else _MISSING),
        "poc": derive_poc_command(bundle),  # (cmd, [paths])
        "em_lines": evidence_matrix_summary_lines(em),
        "fr_lines": fork_replay_section_lines(bundle, manifest),
        "dupe_lines": dupe_defense_lines(manifest),
        # Classify once so both the triager-risk section AND the
        # honest-zero disambiguation header (capv3 iter-007 T1 FIX-7
        # note-2) read from the same classification.
        "rebuttal_classes": classify_triager_risks(draft_text or ""),
        "triager_lines": triager_risk_section_lines(draft_text or ""),
        "scope_lines": scope_review_lines(bundle),
        "appendix": appendix_paths(bundle),
    }


def _render_cantina(inputs: Dict[str, Any], platform: str) -> str:
    """Legacy Cantina/HackenProof packet — section ordering frozen for
    backwards compat with operator workflow."""
    bundle = inputs["bundle"]
    title = inputs["title"]
    severity = inputs["severity"]
    impact_block = inputs["impact_block"]
    dollar = inputs["dollar"]
    attack_trace = inputs["attack_trace"]
    poc_cmd, poc_paths = inputs["poc"]
    em_lines = inputs["em_lines"]
    fr_lines = inputs["fr_lines"]
    dupe_lines = inputs["dupe_lines"]
    rebuttal_classes = inputs["rebuttal_classes"]
    triager_lines = inputs["triager_lines"]
    scope_lines = inputs["scope_lines"]
    appendix = inputs["appendix"]

    expected_output = (
        "Expected: `Suite result: ok.` with at least one `[PASS]` line "
        "matching the target contract."
    )
    harness_lines = harness_execution_contract_lines(bundle)

    out_lines: List[str] = []
    out_lines.append("---")
    out_lines.append(f"title: {title}")
    out_lines.append(f"severity: {severity}")
    out_lines.append(f"platform: {platform}")
    out_lines.append("bundle: .")
    out_lines.append("generated_by: tools/submission-factory.py (v3 iter1 T5)")
    out_lines.append("---")
    out_lines.append("")
    out_lines.append(f"# Cantina-ready: {title}")
    out_lines.append("")
    out_lines.append(platform_framing(platform))
    out_lines.append("")

    out_lines.append("## 1. Title + Severity")
    out_lines.append("")
    out_lines.append(f"- **Title:** {title}")
    out_lines.append(f"- **Severity:** {severity}")
    out_lines.append("")

    out_lines.append("## 2. Impact")
    out_lines.append("")
    out_lines.append(f"- **Dollar figure:** {dollar}")
    out_lines.append("")
    out_lines.append("**Impact narrative (from draft):**")
    out_lines.append("")
    out_lines.append(impact_block)
    out_lines.append("")

    out_lines.append("## 3. Attack trace")
    out_lines.append("")
    out_lines.append("**Victim / attacker / protocol + step-by-step** (from draft):")
    out_lines.append("")
    out_lines.append(attack_trace)
    out_lines.append("")

    out_lines.append("## 4. PoC command")
    out_lines.append("")
    out_lines.append("```sh")
    out_lines.append(f"{poc_cmd}")
    out_lines.append("```")
    out_lines.append("")
    if poc_paths:
        out_lines.append(f"- PoC files in bundle: {', '.join(f'`{p}`' for p in poc_paths)}")
    else:
        out_lines.append("- PoC files in bundle: none supplied")
    out_lines.append(f"- {expected_output}")
    out_lines.append("")
    out_lines.append("**Harness execution queue:**")
    out_lines.append("")
    out_lines.extend(harness_lines)
    out_lines.append("")

    out_lines.append("## 5. Evidence matrix summary")
    out_lines.append("")
    out_lines.extend(em_lines)
    out_lines.append("")

    out_lines.append("## 6. Fork-replay evidence")
    out_lines.append("")
    out_lines.extend(fr_lines)
    out_lines.append("")

    out_lines.append("## 7. Dupe defense (Check #7 variant-detector)")
    out_lines.append("")
    out_lines.extend(dupe_lines)
    out_lines.append("")

    out_lines.append("## 8. Triager-risk section (iter13 rejection classifier)")
    out_lines.append("")
    out_lines.extend(triager_lines)
    out_lines.append("")
    out_lines.append("**Scope review artifacts:**")
    out_lines.append("")
    out_lines.extend(scope_lines)
    out_lines.append("")

    out_lines.append("## 9. Appendix — raw evidence paths")
    out_lines.append("")
    out_lines.extend(appendix)
    out_lines.append("")

    return "\n".join(out_lines) + "\n"


def build_cantina_ready(bundle: Path, platform: str) -> str:
    """Backwards-compat wrapper; legacy callers (tests, packager) use this."""
    return _render_cantina(_collect_render_inputs(bundle), platform)


# ─── Per-platform renderers (paste into web-form fields) ──────────────────
#
# Each renderer reads the same `inputs` dict assembled by
# `_collect_render_inputs`. They differ only in section ordering /
# header wording / framing, mirroring each platform's submission-form
# schema as documented publicly:
#
#   - Immunefi: bug bounty form has discrete fields Title, Severity,
#     Description, Proof of Concept, Impact, Recommendation. Severity
#     appears immediately after Title in the form.
#     (https://immunefi.com/explore/ — "Submit Report" form schema.)
#   - Sherlock: report template uses Description / Vulnerability Detail
#     / Impact / Code Snippet / Tool Used / Recommendation. The watson
#     dashboard groups submissions into "pools" and links primary →
#     duplicates; severity is encoded inline (`H-01`, `M-02`).
#     (https://docs.sherlock.xyz/audits/judging/judging.)
#   - Code4rena: GitHub-issue body with H1/M1/Q template; severity
#     mapped to numeric tiers (3 = High, 2 = Medium, 1 = QA).
#     (code-423n4/org issue templates, public on GitHub.)
#   - HackerOne: web-form fields Title, Severity (CVSS), Asset, Weakness,
#     Description, Steps to Reproduce, Impact, Suggested Fix.
#     (HackerOne report submission docs.)
#   - Spearbit: direct-to-team markdown — no web form. Convention is
#     `[Severity] Title`, then Context, Description, Impact, Recommendation.
#     (Spearbit reporting standards.)
#
# All renderers preserve the honest-zero rebuttal-classifier comment and
# emit `_MISSING` when source fields are absent — never fabricate.


def _emit_yaml_frontmatter(title: str, severity: str, platform: str,
                            bundle: Path, rebuttal_classes: List[Any]) -> List[str]:
    """Shared YAML/disambiguation header used by every per-platform packet."""
    out: List[str] = []
    out.append("---")
    out.append(f"title: {title}")
    out.append(f"severity: {severity}")
    out.append(f"platform: {platform}")
    out.append("bundle: .")
    out.append("generated_by: tools/submission-factory.py (v3 iter1 T5 + per-platform fan-out)")
    out.append("---")
    out.append("")
    return out


def _emit_poc_block(poc: Tuple[str, List[str]]) -> List[str]:
    poc_cmd, poc_paths = poc
    out = ["```sh", poc_cmd, "```", ""]
    if poc_paths:
        out.append(f"- PoC files in bundle: {', '.join(f'`{p}`' for p in poc_paths)}")
    else:
        out.append("- PoC files in bundle: none supplied")
    out.append(
        "- Expected: `Suite result: ok.` with at least one `[PASS]` line "
        "matching the target contract."
    )
    return out


def _render_immunefi(inputs: Dict[str, Any]) -> str:
    """Immunefi web-form ordering: Title → Severity → Description → PoC → Impact → Recommendation."""
    bundle = inputs["bundle"]
    title = inputs["title"]
    severity = inputs["severity"]
    out = _emit_yaml_frontmatter(title, severity, "immunefi", bundle, inputs["rebuttal_classes"])
    out.append(f"# Immunefi-ready: {title}")
    out.append("")
    out.append("Paste each section into the matching field of the Immunefi bug-bounty submission form.")
    out.append("")
    out.append("## Title")
    out.append("")
    out.append(title)
    out.append("")
    out.append("## Severity")
    out.append("")
    out.append(severity)
    out.append("")
    out.append("## Description")
    out.append("")
    out.append(inputs["impact_block"])
    out.append("")
    out.append("## Proof of Concept")
    out.append("")
    out.extend(_emit_poc_block(inputs["poc"]))
    out.append("")
    out.append("**Attack trace:**")
    out.append("")
    out.append(inputs["attack_trace"])
    out.append("")
    out.append("## Impact")
    out.append("")
    out.append(f"- **Dollar figure:** {inputs['dollar']}")
    out.append("")
    out.append(inputs["impact_block"])
    out.append("")
    out.append("## Recommendation")
    out.append("")
    out.append("No recommendation was supplied in the bundle. Add the remediation from the source draft before filing.")
    out.append("")
    out.append("## Triager-risk pre-emptive responses")
    out.append("")
    out.extend(inputs["triager_lines"])
    out.append("")
    out.append("## Appendix — evidence paths")
    out.append("")
    out.extend(inputs["appendix"])
    out.append("")
    return "\n".join(out) + "\n"


def _render_sherlock(inputs: Dict[str, Any]) -> str:
    """Sherlock dashboard format: severity-coded title + Vulnerability Detail / Impact / Code Snippet / Tool Used / Recommendation.

    The watson-pool dedup is referenced via the existing variant-detector
    output — Sherlock judges expect a primary/dupe linkage statement.
    """
    bundle = inputs["bundle"]
    title = inputs["title"]
    severity = inputs["severity"]
    sev_code = {"Critical": "C", "High": "H", "Medium": "M", "Low": "L", "Informational": "I"}.get(severity, "?")
    coded_title = f"[{sev_code}] {title}"
    out = _emit_yaml_frontmatter(coded_title, severity, "sherlock", bundle, inputs["rebuttal_classes"])
    out.append(f"# Sherlock-ready: {coded_title}")
    out.append("")
    out.append("Paste into the Sherlock judging-pool submission form. Severity prefix in title follows watson convention (H-/M-/L-).")
    out.append("")
    out.append("## Description")
    out.append("")
    out.append(inputs["impact_block"])
    out.append("")
    out.append("## Vulnerability Detail")
    out.append("")
    out.append(inputs["attack_trace"])
    out.append("")
    out.append("## Impact")
    out.append("")
    out.append(f"- **Dollar figure:** {inputs['dollar']}")
    out.append("")
    out.append(inputs["impact_block"])
    out.append("")
    out.append("## Code Snippet")
    out.append("")
    poc_cmd, poc_paths = inputs["poc"]
    if poc_paths:
        out.append("PoC files referenced in bundle:")
        for p in poc_paths:
            out.append(f"- `{p}`")
    else:
        out.append("No PoC file was supplied in the bundle.")
    out.append("")
    out.append("## Tool Used")
    out.append("")
    out.append("Manual review + Foundry (`forge test`).")
    out.append("")
    out.append("## Recommendation")
    out.append("")
    out.append("No recommendation was supplied in the bundle. Add the remediation from the source draft before filing.")
    out.append("")
    out.append("## PoC command")
    out.append("")
    out.extend(_emit_poc_block(inputs["poc"]))
    out.append("")
    out.append("## Watson-pool dedup linkage (variant-detector output)")
    out.append("")
    out.extend(inputs["dupe_lines"])
    out.append("")
    out.append("## Triager-risk pre-emptive responses")
    out.append("")
    out.extend(inputs["triager_lines"])
    out.append("")
    out.append("## Appendix — evidence paths")
    out.append("")
    out.extend(inputs["appendix"])
    out.append("")
    return "\n".join(out) + "\n"


def _render_c4(inputs: Dict[str, Any]) -> str:
    """Code4rena GitHub-issue body. Severity mapped to numeric tier:
    3 = High, 2 = Medium, 1 = QA / Low / Informational."""
    bundle = inputs["bundle"]
    title = inputs["title"]
    severity = inputs["severity"]
    sev_num = {"Critical": "3", "High": "3", "Medium": "2", "Low": "1", "Informational": "1"}.get(severity, "?")
    out = _emit_yaml_frontmatter(title, severity, "code4rena", bundle, inputs["rebuttal_classes"])
    out.append(f"# C4-ready: {title}")
    out.append("")
    out.append(f"Paste body into a Code4rena GitHub issue. Apply label `{sev_num} ({severity})` per c4 issue template.")
    out.append("")
    out.append("## Lines of code")
    out.append("")
    poc_cmd, poc_paths = inputs["poc"]
    if poc_paths:
        for p in poc_paths:
            out.append(f"- `{p}`")
    else:
        out.append("No PoC file was supplied in the bundle.")
    out.append("")
    out.append("## Vulnerability details")
    out.append("")
    out.append(inputs["impact_block"])
    out.append("")
    out.append("## Impact")
    out.append("")
    out.append(f"- **Severity tier:** `{sev_num}` ({severity})")
    out.append(f"- **Dollar figure:** {inputs['dollar']}")
    out.append("")
    out.append(inputs["impact_block"])
    out.append("")
    out.append("## Proof of Concept")
    out.append("")
    out.extend(_emit_poc_block(inputs["poc"]))
    out.append("")
    out.append("**Attack trace:**")
    out.append("")
    out.append(inputs["attack_trace"])
    out.append("")
    out.append("## Tools Used")
    out.append("")
    out.append("Manual review, Foundry (`forge test`).")
    out.append("")
    out.append("## Recommended Mitigation Steps")
    out.append("")
    out.append("No recommendation was supplied in the bundle. Add the remediation from the source draft before filing.")
    out.append("")
    out.append("## Triager-risk pre-emptive responses")
    out.append("")
    out.extend(inputs["triager_lines"])
    out.append("")
    out.append("## Appendix — evidence paths")
    out.append("")
    out.extend(inputs["appendix"])
    out.append("")
    return "\n".join(out) + "\n"


def _render_hackerone(inputs: Dict[str, Any]) -> str:
    """HackerOne web-form fields: Title, Severity, Asset, Weakness, Description, Steps to Reproduce, Impact, Suggested Fix."""
    bundle = inputs["bundle"]
    title = inputs["title"]
    severity = inputs["severity"]
    out = _emit_yaml_frontmatter(title, severity, "hackerone", bundle, inputs["rebuttal_classes"])
    out.append(f"# H1-ready: {title}")
    out.append("")
    out.append("Paste each section into the matching field of the HackerOne report submission form.")
    out.append("")
    out.append("## Title")
    out.append("")
    out.append(title)
    out.append("")
    out.append("## Severity")
    out.append("")
    out.append(f"{severity} (map to CVSS in the H1 form severity selector)")
    out.append("")
    out.append("## Asset")
    out.append("")
    out.append("Asset was not supplied in the bundle. Select the in-scope asset from the program page before filing.")
    out.append("")
    out.append("## Weakness")
    out.append("")
    out.append("Weakness was not supplied in the bundle. Select the closest CWE class before filing.")
    out.append("")
    out.append("## Description")
    out.append("")
    out.append(inputs["impact_block"])
    out.append("")
    out.append("## Steps to Reproduce")
    out.append("")
    out.append(inputs["attack_trace"])
    out.append("")
    out.append("**PoC command:**")
    out.append("")
    out.extend(_emit_poc_block(inputs["poc"]))
    out.append("")
    out.append("## Impact")
    out.append("")
    out.append(f"- **Dollar figure:** {inputs['dollar']}")
    out.append("")
    out.append(inputs["impact_block"])
    out.append("")
    out.append("## Suggested Fix")
    out.append("")
    out.append("No recommendation was supplied in the bundle. Add the remediation from the source draft before filing.")
    out.append("")
    out.append("## Triager-risk pre-emptive responses")
    out.append("")
    out.extend(inputs["triager_lines"])
    out.append("")
    out.append("## Appendix — evidence paths")
    out.append("")
    out.extend(inputs["appendix"])
    out.append("")
    return "\n".join(out) + "\n"


def _render_spearbit(inputs: Dict[str, Any]) -> str:
    """Spearbit direct-to-team markdown. No web form — sent as a single
    file. Convention: `[Severity] Title` then Context / Description /
    Impact / Recommendation."""
    bundle = inputs["bundle"]
    title = inputs["title"]
    severity = inputs["severity"]
    coded_title = f"[{severity}] {title}"
    out = _emit_yaml_frontmatter(coded_title, severity, "spearbit", bundle, inputs["rebuttal_classes"])
    out.append(f"# Spearbit-ready: {coded_title}")
    out.append("")
    out.append("Direct-to-team markdown. Paste as a single finding inside the engagement report doc.")
    out.append("")
    out.append("## Context")
    out.append("")
    out.extend(inputs["scope_lines"])
    out.append("")
    out.append("## Description")
    out.append("")
    out.append(inputs["impact_block"])
    out.append("")
    out.append("## Attack trace")
    out.append("")
    out.append(inputs["attack_trace"])
    out.append("")
    out.append("## Proof of Concept")
    out.append("")
    out.extend(_emit_poc_block(inputs["poc"]))
    out.append("")
    out.append("## Impact")
    out.append("")
    out.append(f"- **Severity:** {severity}")
    out.append(f"- **Dollar figure:** {inputs['dollar']}")
    out.append("")
    out.append(inputs["impact_block"])
    out.append("")
    out.append("## Recommendation")
    out.append("")
    out.append("No recommendation was supplied in the bundle. Add the remediation from the source draft before filing.")
    out.append("")
    out.append("## Evidence matrix")
    out.append("")
    out.extend(inputs["em_lines"])
    out.append("")
    out.append("## Fork-replay")
    out.append("")
    out.extend(inputs["fr_lines"])
    out.append("")
    out.append("## Triager-risk pre-emptive responses")
    out.append("")
    out.extend(inputs["triager_lines"])
    out.append("")
    out.append("## Appendix — evidence paths")
    out.append("")
    out.extend(inputs["appendix"])
    out.append("")
    return "\n".join(out) + "\n"


# Per-target renderer dispatch. Each entry: (filename, render_fn).
_TARGET_RENDERERS: Dict[str, Tuple[str, Any]] = {
    "cantina":   ("cantina_ready.md",   None),  # special-cased below; needs platform arg
    "immunefi":  ("immunefi_ready.md",  _render_immunefi),
    "sherlock":  ("sherlock_ready.md",  _render_sherlock),
    "c4":        ("c4_ready.md",        _render_c4),
    "hackerone": ("hackerone_ready.md", _render_hackerone),
    "spearbit":  ("spearbit_ready.md",  _render_spearbit),
}


def _render_one_target(target: str, inputs: Dict[str, Any], platform: str) -> Tuple[str, str]:
    """Return (output_filename, body) for `target`. Cantina uses the
    legacy renderer with the platform label; others ignore platform."""
    fname, fn = _TARGET_RENDERERS[target]
    if target == "cantina":
        body = _render_cantina(inputs, platform)
    else:
        body = fn(inputs)
    return fname, body


_HTML_COMMENT_RE = re.compile(r"<!--.*?-->", re.DOTALL)
_LOCAL_ABSOLUTE_PATH_RE = re.compile(r"`(?:/Users/[^`]+|/private/[^`]+|/tmp/[^`]+)`")
_MANUAL_FILL_RE = re.compile(
    r"(?:<TODO_OPERATOR>|manual fill required|not available\s+[—-]\s+manual fill required)",
    re.IGNORECASE,
)
_PATH_ONLY_POC_RE = re.compile(
    r"PoC files? (?:in bundle|referenced in bundle):[^\n]+(?:\n(?!\n).*){0,4}\Z",
    re.IGNORECASE,
)
_COMMAND_SIGNAL_RE = re.compile(
    r"\b(?:forge|go|cargo|pnpm|npm|yarn|python3?|bash|make)\s+[^\n`]+",
    re.IGNORECASE,
)
_PASS_SIGNAL_RE = re.compile(r"\b(?:PASS|PASSED|Suite result: ok|\[PASS\]|ok\s+github\.com/)", re.IGNORECASE)


def _operator_paste_hygiene_blockers(body: str) -> List[str]:
    blockers: List[str] = []
    if _HTML_COMMENT_RE.search(body):
        blockers.append("internal_html_comment")
    if _LOCAL_ABSOLUTE_PATH_RE.search(body):
        blockers.append("local_absolute_path")
    if _MANUAL_FILL_RE.search(body):
        blockers.append("manual_fill_placeholder")

    poc_section = ""
    m = re.search(r"(?:^|\n)##\s+(?:4\. PoC command|Proof of Concept)\b[^\n]*\n(?P<body>.*?)(?:\n##\s|\Z)", body, re.DOTALL)
    if m:
        poc_section = m.group("body")
    if poc_section:
        if _MISSING in poc_section or _PATH_ONLY_POC_RE.search(poc_section.strip()):
            blockers.append("poc_path_only_or_missing_command")
        if "PoC files" in poc_section and not _COMMAND_SIGNAL_RE.search(poc_section):
            blockers.append("poc_missing_runnable_command")
        if "PoC files" in poc_section and not _PASS_SIGNAL_RE.search(poc_section):
            blockers.append("poc_missing_pass_signal")
    else:
        blockers.append("poc_section_missing")

    return list(dict.fromkeys(blockers))


# ─── CLI ──────────────────────────────────────────────────────────────────

def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(
        prog="submission-factory",
        description="Build operator-ready paste-ready packets from a packaged bundle. "
                    "Default emits cantina_ready.md; --target <platform> emits the "
                    "matching <platform>_ready.md packet; --target all emits every "
                    "supported platform variant in one run.",
    )
    # Bundle path may be given positionally (as the verification CLI in the
    # capability-extension plan calls it) or via the legacy `--bundle` flag
    # (used by existing tests / packager callers). We accept both.
    parser.add_argument("bundle_pos", nargs="?", type=Path, default=None,
                        help="Packaged bundle directory (positional). "
                             "Equivalent to --bundle.")
    parser.add_argument("--bundle", dest="bundle_flag", type=Path, default=None,
                        help="Path to packaged bundle directory (input). "
                             "Mutually compatible with the positional form.")
    parser.add_argument("--platform", choices=sorted(_PLATFORMS), default=None,
                        help=f"Submission platform label embedded in the cantina "
                             f"packet's framing line. Default: inferred from bundle "
                             f"manifest (snowbridge→hackenproof, polymarket→other).")
    parser.add_argument("--target", choices=_TARGETS, default="cantina",
                        help="Which paste-ready packet(s) to emit. Default: cantina "
                             "(legacy cantina_ready.md). Use 'all' to emit every "
                             "platform variant under the bundle dir.")
    parser.add_argument("--out", type=Path, default=None,
                        help="Output path for the emitted packet. Only honored when "
                             "--target is a single platform (not 'all'). Default: "
                             "<bundle>/<target>_ready.md.")
    parser.add_argument("--dry-run", action="store_true", default=False,
                        help="Validate-only mode: run all validators and renderers "
                             "but do NOT write any files. Print a summary of what "
                             "WOULD be written to stdout. Returns rc=0 on success.")
    parser.add_argument(
        "--scaffold-missing-impact-contract",
        action="store_true",
        default=False,
        help="When the bundle is missing impact_contract.json (or it is "
             "structurally incomplete), emit a stub impact_contract.json with "
             "<TODO_OPERATOR> markers for the 7 required fields instead of "
             "refusing. The stub must be filled in by the operator before "
             "paste-ready output is produced. Default behavior (REFUSE) is "
             "unchanged when this flag is absent.",
    )
    args = parser.parse_args(argv)

    raw_bundle = args.bundle_pos or args.bundle_flag
    if raw_bundle is None:
        parser.error("bundle path required (positional or via --bundle)")
    bundle: Path = raw_bundle.resolve()
    if args.bundle_pos is not None and args.bundle_flag is not None:
        # Operator passed both — keep behavior unambiguous.
        if args.bundle_pos.resolve() != args.bundle_flag.resolve():
            parser.error("positional bundle and --bundle disagree")
    if not bundle.is_dir():
        print(f"[submission-factory] ERROR: bundle directory not found: {bundle}",
              file=sys.stderr)
        return 2
    if not (bundle / "source-draft.md").is_file():
        print(f"[submission-factory] ERROR: source-draft.md missing in bundle: {bundle}",
              file=sys.stderr)
        return 2

    manifest = _read_json(bundle / "manifest.json")
    platform = pick_platform(args.platform, manifest)

    refusal = impact_contract_refusal(bundle)
    if refusal:
        if args.scaffold_missing_impact_contract:
            stub_path = bundle / "impact_contract.json"
            stub = {
                "_note": (
                    "Auto-scaffolded stub — fill in every <TODO_OPERATOR> field "
                    "before running submission-factory without --scaffold-missing-impact-contract."
                ),
                "impact_contract_missing": "<TODO_OPERATOR: describe the impact contract or leave empty if not applicable>",
                "selected_impact": "<TODO_OPERATOR: exact sentence from the rubric describing the selected impact>",
                "severity_tier": "<TODO_OPERATOR: Critical | High | Medium | Low | Informational>",
                "listed_impact_proven": "<TODO_OPERATOR: true | false — set true only after proof artifact is verified>",
                "evidence_class": "<TODO_OPERATOR: e.g. exploit_poc | forge_test | live_tx | static_analysis>",
                "oos_traps": "<TODO_OPERATOR: list any OOS clauses that were reviewed and cleared, or 'none'>",
                "stop_condition": "<TODO_OPERATOR: one-sentence description of what proves the listed impact is real>",
                "_scaffold_refusal_reason": refusal,
            }
            stub_path.write_text(json.dumps(stub, indent=2), encoding="utf-8")
            print(
                f"[submission-factory] SCAFFOLD: emitted stub impact_contract.json at {stub_path} "
                f"(refusal was: {refusal}). Fill in <TODO_OPERATOR> fields and re-run.",
                file=sys.stderr,
            )
            return 3
        print(
            "[submission-factory] REFUSE: cantina_ready.md requires an exact "
            f"locked/proved listed-impact contract before paste-ready output ({refusal})",
            file=sys.stderr,
        )
        return 2

    inputs = _collect_render_inputs(bundle)

    targets = list(_TARGET_RENDERERS.keys()) if args.target == "all" else [args.target]
    if args.out is not None and args.target == "all":
        parser.error("--out cannot be used with --target all (multiple files emitted)")

    written: List[Path] = []
    dry_run_summary: List[Dict[str, Any]] = []
    for target in targets:
        fname, body = _render_one_target(target, inputs, platform)
        if args.out is not None and len(targets) == 1:
            out_path = args.out.resolve()
        else:
            out_path = bundle / fname
        if args.dry_run:
            dry_run_summary.append({
                "target": target,
                "platform": platform,
                "would_write": str(out_path),
                "bytes": len(body.encode("utf-8")),
                "title": inputs.get("title", _MISSING),
                "severity": inputs.get("severity", _MISSING),
            })
            print(f"[submission-factory] DRY-RUN: would write {out_path} "
                  f"({len(body.encode('utf-8'))} bytes) "
                  f"for target={target} platform={platform}")
        else:
            hygiene_blockers = _operator_paste_hygiene_blockers(body)
            if hygiene_blockers:
                print(
                    "[submission-factory] REFUSE: final operator paste hygiene "
                    f"failed for {target} ({', '.join(hygiene_blockers)})",
                    file=sys.stderr,
                )
                return 1
            out_path.parent.mkdir(parents=True, exist_ok=True)
            out_path.write_text(body, encoding="utf-8")
            written.append(out_path)
            print(f"[submission-factory] wrote {out_path} ({len(body)} bytes) "
                  f"for target={target} platform={platform}")
    if args.dry_run:
        print(json.dumps({"dry_run": True, "would_write": dry_run_summary}, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
