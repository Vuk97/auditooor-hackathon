#!/usr/bin/env python3
"""Rule 57 exhaustive-defense-chain-enumeration preflight (Check #104).

GENERAL RULE - applies to any HIGH+ submission whose argument depends on
defeating a defender's enforcement (the draft states "the defender cannot
stop the attack" or "the defense does not apply"). The draft MUST include
an "Exhaustive Defense Chain Enumeration" section that enumerates, for each
protection module in the defender's codebase, every code path that could
fire defensively in the attack scenario, with per-path ruling (ruled-in or
ruled-out) and a source citation (file:line).

Three layers of mechanical verification, in increasing strictness:

Layer 1 (always-required): the draft must contain the Exhaustive Defense
Chain Enumeration section header AND a table with at least 2 data rows AND
each row must contain a file:line citation.

Layer 2 (HIGH+ severity): the tool greps every --protection-module-dir for
canonical defense-action patterns (target-specific) and compares the count
of unique call sites against the count of distinct file:line citations in
the draft table. If code_path_count > table_row_count, emit
fail-defense-paths-missing-from-enumeration listing the unaccounted call
sites.

Layer 3 (--strict only): the tool resolves each file:line citation in the
table against the workspace and verifies (a) the file exists, (b) the line
range exists.

Verdict vocabulary:
  pass-out-of-scope                       severity below HIGH or no defender narrative
  pass-no-defense-narrative               HIGH+ but draft doesn't argue against defender
  pass-all-defense-paths-enumerated       section complete, grep matches table
  ok-rebuttal                             valid r57-rebuttal marker (<=200 chars)
  fail-no-enumeration-section             section header missing
  fail-table-missing                      section present but no table
  fail-row-without-citation               table present but >=1 row lacks file:line
  fail-defense-paths-missing-from-enumeration  grep found unaccounted defense call sites
  fail-ruling-without-source-citation     (--strict) row cites a path that doesn't resolve
  error                                   input error / unparseable severity

Exit codes:
  0 - pass, out-of-scope, no defender narrative, or accepted rebuttal
  1 - Rule 57 violation
  2 - input error

Schema: auditooor.r57_exhaustive_defense_chain_enumeration.v1

Empirical anchor: Spark LEAD 1 v8 (2026-05-23) addressed Defense 1 (SSP
broadcasts tx-real) and Defense 2 (SSP watchtower + DirectTimelockOffset);
missed Defense 3 (root-tx-CPFP-based intermediate refund). R25/R29/R43/R44/R45
all passed because they verify named defenses, not codebase exhaustiveness.
R57 closes that gap.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
from pathlib import Path
from typing import Any

SCHEMA_VERSION = "auditooor.r57_exhaustive_defense_chain_enumeration.v1"
GATE = "R57-EXHAUSTIVE-DEFENSE-CHAIN-ENUMERATION"

SEVERITY_RANK = {"low": 1, "medium": 2, "high": 3, "critical": 4}
REBUTTAL_MAX_CHARS = 200

# ---------------------------------------------------------------------------
# Defender-narrative trigger patterns
#
# Fires when a draft argues against a defender's enforcement: phrases like
# "the defender cannot", "the defense does not apply", "the watchtower cannot
# broadcast", "the SSP has no capacity", "no defensive transaction", etc.
# Env-extendable via AUDITOOOR_R57_DEFENDER_NARRATIVE_PATTERNS.
# ---------------------------------------------------------------------------
DEFAULT_DEFENDER_NARRATIVE_PATTERNS: list[str] = [
    # generic defender-cannot phrasing
    r"\bthe\s+(?:defender|defense|defender's)\s+(?:cannot|can\s+not|has\s+no\s+capacity|never|does\s+not)\b",
    r"\bno\s+defensive\s+(?:transaction|broadcast|action|path)\b",
    r"\bdefense(?:s)?\s+(?:does|do)\s+not\s+apply\b",
    r"\bdefensive\s+path\s+is\s+unreachable\b",
    r"\bevery\s+defensive\s+(?:path|broadcast)\s+is\s+(?:gated|unreachable|blocked)\b",
    r"\b(?:defender|defense)\s+has\s+no\s+(?:way|capacity|mechanism)\b",
    # Bitcoin/Lightning/Spark defender actors
    r"\bSSP\s+(?:has\s+no|cannot|never\s+broadcasts?|cannot\s+broadcast)\b",
    r"\bwatchtower(?:s)?\s+(?:cannot|never)\s+(?:fire|broadcast|trigger)\b",
    r"\bchain[- ]?watcher\s+(?:cannot|never)\b",
    r"\bbreach[- ]?arbiter\s+(?:cannot|never)\b",
    # Cosmos / app-chain defender actors
    r"\bvalidator(?:s)?\s+(?:cannot|never)\s+(?:reject|stop|block)\b",
    r"\bante\s+(?:decorator|handler)\s+(?:does\s+not|never)\s+(?:fire|block|reject)\b",
    r"\bProcessProposal\s+(?:never|does\s+not)\s+(?:reject|block)\b",
    # EVM / Solidity defender actors
    r"\b(?:modifier|require|onlyOwner|onlyRole|access[- ]?control)\s+(?:does\s+not|never)\s+(?:block|revert|stop)\b",
    r"\b(?:nonReentrant|whenNotPaused)\s+(?:does\s+not|never)\s+(?:block|fire)\b",
    # L2 / rollup defender actors
    r"\b(?:challenger|sequencer|prover|fisherman)\s+(?:cannot|never)\s+(?:challenge|dispute|stop)\b",
    r"\b(?:dispute\s+game|fault\s+proof|validity\s+proof)\s+(?:does\s+not|never)\b",
    # explicit triager / dispute / mediation framing
    r"\bdefense\s+(?:is\s+)?unreachable\b",
    r"\bevery\s+defensive\s+watchtower\s+path\b",
]


def _build_defender_narrative_re() -> re.Pattern[str]:
    extras_raw = os.environ.get("AUDITOOOR_R57_DEFENDER_NARRATIVE_PATTERNS", "")
    extras = [line.strip() for line in extras_raw.splitlines() if line.strip()]
    all_pats = DEFAULT_DEFENDER_NARRATIVE_PATTERNS + extras
    combined = "|".join(f"(?:{p})" for p in all_pats)
    return re.compile(combined, re.IGNORECASE)


# ---------------------------------------------------------------------------
# Enumeration section header
# ---------------------------------------------------------------------------
SECTION_HEADER_RE = re.compile(
    r"(?im)^#{1,6}\s*exhaustive\s+defense\s+chain\s+enumeration\s*:?\s*$",
)

# ---------------------------------------------------------------------------
# Citation pattern (file:line or file:line-range)
# ---------------------------------------------------------------------------
FILE_LINE_RE = re.compile(
    r"[A-Za-z0-9_./\-]+\.(?:go|rs|sol|ts|tsx|js|mjs|py|move|cairo|vy|ml)(?::\d+(?:-\d+)?)",
)


# ---------------------------------------------------------------------------
# Defense-action pattern library (per-target)
#
# Each pattern set is target-aware. The tool uses the workspace's
# .auditooor/r57_defense_patterns.json (when present) plus env-var overrides
# (AUDITOOOR_R57_DEFENSE_PATTERNS_<TARGET>) to extend defaults.
# ---------------------------------------------------------------------------
DEFENSE_PATTERNS_BITCOIN_LIGHTNING_SPARK: list[str] = [
    r"SendRawTransaction",
    r"BroadcastTransaction",
    r"broadcastTx",
    r"broadcastRefund",
    r"constructCPFP",
    r"constructDirect",
    r"construct[A-Za-z]*Refund",
    r"signRefund",
    r"publishExit",
    r"publishCommitment",
    r"signCommitment",
    r"watchtower\.Broadcast",
    r"watchtower\.Publish",
    r"watchtower\.Attempt",
    r"SettleReceiverKeyTweak",
    r"ClaimTransferSignRefunds",
    r"FinalizeTransfer",
    r"tweakKeysForCoopExit",
    r"MarkReceiversClaimPending",
    r"SetStatus\(",
    r"BroadcastJustice",
    r"breach.*broadcast",
    r"chain_arbitrator",
    r"onchain_action",
    r"revoke_and_ack",
    r"penalty_tx",
    r"justice_tx",
    r"checkAndBroadcastNodeTx",
    r"BroadcastTransferLeafRefund",
]

DEFENSE_PATTERNS_COSMOS_SDK: list[str] = [
    r"ante\.[A-Z][a-zA-Z]+Decorator",
    r"NewAnteHandler",
    r"ValidateBasic",
    r"MsgServer\.",
    r"PrepareProposal",
    r"ProcessProposal",
    r"EndBlocker",
    r"BeginBlocker",
    r"abci\.Response",
    r"x/gov.*[Mm]sgVote",
    r"x/upgrade.*Plan",
]

DEFENSE_PATTERNS_EVM: list[str] = [
    r"require\(",
    r"revert\s+[A-Z]",
    r"emit\s+[A-Z]",
    r"modifier\s+[a-z]",
    r"nonReentrant",
    r"onlyOwner",
    r"onlyRole",
    r"_beforeTokenTransfer",
    r"_afterTokenTransfer",
    r"pause\(",
    r"whenNotPaused",
    r"circuitBreaker",
    r"liquidate",
    r"liquidationCall",
    r"seize",
    r"forceClose",
    r"isValidSignature",
]

DEFENSE_PATTERNS_SUBSTRATE: list[str] = [
    r"ensure!",
    r"ensure_signed",
    r"ensure_root",
    r"SignedExtension",
    r"TransactionExtension",
    r"on_initialize",
    r"on_finalize",
    r"on_idle",
    r"pallet::weight",
    r"validate_unsigned",
]

DEFENSE_PATTERNS_L2_ROLLUP: list[str] = [
    r"challengeBlock",
    r"disputeOutput",
    r"withdrawBond",
    r"fraudProof",
    r"validityProof",
    r"forceInclude",
    r"forceWithdraw",
    r"escapeHatch",
    r"FaultDisputeGame",
    r"L2OutputOracle\..*propose",
]

DEFENSE_PATTERNS_SOLANA: list[str] = [
    r"invoke\(",
    r"invoke_signed\(",
    r"require_keys_eq",
    r"require_eq",
    r"program::id\(\)",
    r"cpi::",
    r"ProgramError::",
    r"anchor_lang::error",
]

TARGET_PATTERN_LIBS: dict[str, list[str]] = {
    "bitcoin_lightning_spark": DEFENSE_PATTERNS_BITCOIN_LIGHTNING_SPARK,
    "cosmos_sdk": DEFENSE_PATTERNS_COSMOS_SDK,
    "evm": DEFENSE_PATTERNS_EVM,
    "substrate": DEFENSE_PATTERNS_SUBSTRATE,
    "l2_rollup": DEFENSE_PATTERNS_L2_ROLLUP,
    "solana": DEFENSE_PATTERNS_SOLANA,
}


def _load_workspace_defense_patterns(workspace: Path) -> dict[str, list[str]]:
    """Workspace-scoped pattern override at .auditooor/r57_defense_patterns.json"""
    cfg = workspace / ".auditooor" / "r57_defense_patterns.json"
    if not cfg.is_file():
        return {}
    try:
        return json.loads(cfg.read_text(encoding="utf-8"))
    except Exception:
        return {}


def _build_combined_defense_re(workspace: Path | None) -> re.Pattern[str]:
    """Compile a single combined regex from all target libraries + env + workspace overrides."""
    all_patterns: list[str] = []
    for target, patterns in TARGET_PATTERN_LIBS.items():
        all_patterns.extend(patterns)
        env_name = f"AUDITOOOR_R57_DEFENSE_PATTERNS_{target.upper()}"
        extras_raw = os.environ.get(env_name, "")
        all_patterns.extend(line.strip() for line in extras_raw.splitlines() if line.strip())
    if workspace is not None:
        ws_overrides = _load_workspace_defense_patterns(workspace)
        for patterns in ws_overrides.values():
            if isinstance(patterns, list):
                all_patterns.extend(str(p) for p in patterns)
    combined = "|".join(f"(?:{p})" for p in all_patterns)
    return re.compile(combined)


# ---------------------------------------------------------------------------
# Override / rebuttal
# ---------------------------------------------------------------------------
REBUTTAL_HTML_RE = re.compile(
    r"<!--\s*r57-rebuttal\s*:\s*(.{1,300}?)\s*-->",
    re.IGNORECASE | re.DOTALL,
)
REBUTTAL_INLINE_RE = re.compile(
    r"(?im)^r57-rebuttal\s*:\s*(.{1,300}?)$",
)


def _parse_rebuttal(text: str) -> str | None:
    m = REBUTTAL_HTML_RE.search(text)
    if not m:
        m = REBUTTAL_INLINE_RE.search(text)
    if not m:
        return None
    reason = " ".join(m.group(1).split())
    if not reason or len(reason) > REBUTTAL_MAX_CHARS:
        return None
    return reason


# ---------------------------------------------------------------------------
# Severity parsing
# ---------------------------------------------------------------------------
SEVERITY_LINE_RE = re.compile(
    r"(?im)"
    r"^\s*[*-]?\s*[*_]*\s*severity\s*[*_]*\s*:\s*([a-z]+)"
    r"|^\s*##\s*Severity\s*\n\s*([a-z]+)"
    r"|\*\*severity\*\*\s*:\s*([a-z]+)",
)


def _detect_severity(text: str, cli_severity: str, draft: Path) -> str:
    if cli_severity != "auto":
        return cli_severity.lower()
    m = SEVERITY_LINE_RE.search(text)
    if m:
        val = (m.group(1) or m.group(2) or m.group(3) or "").lower().strip()
        if val in SEVERITY_RANK:
            return val
    # fall back to filename hint (matches sibling tools)
    for severity in ("critical", "high", "medium", "low"):
        if re.search(rf"(?:^|[-_]){severity}(?:[-_.]|$)", draft.name.lower()):
            return severity
    return "unknown"


def _is_in_scope(severity: str) -> bool:
    """Only HIGH and CRITICAL are in-scope for R57."""
    return SEVERITY_RANK.get(severity, 0) >= SEVERITY_RANK["high"]


# ---------------------------------------------------------------------------
# Workspace resolution
# ---------------------------------------------------------------------------
def _workspace_root(draft: Path) -> Path:
    cur = draft.resolve().parent
    for parent in [cur, *cur.parents]:
        if (parent / "poc-tests").is_dir() or (parent / "submissions").is_dir():
            return parent
    return draft.resolve().parent


# ---------------------------------------------------------------------------
# Section + table parsing
# ---------------------------------------------------------------------------
def _extract_enumeration_section(text: str) -> tuple[str | None, int]:
    """Return (section_text, section_start_offset) or (None, -1)."""
    m = SECTION_HEADER_RE.search(text)
    if not m:
        return None, -1
    start = m.end()
    nxt = re.search(r"(?m)^#{1,6}\s+\w", text[start:])
    end = start + nxt.start() if nxt else len(text)
    return text[start:end], start


TABLE_ROW_RE = re.compile(r"^\s*\|.+\|\s*$", re.MULTILINE)
TABLE_SEPARATOR_RE = re.compile(r"^\s*\|?[\s:|\-]+\|[\s:|\-]+\|?\s*$", re.MULTILINE)


def _parse_table_rows(section_text: str) -> list[str]:
    """Return data rows (non-header, non-separator) from any markdown tables in section."""
    rows = TABLE_ROW_RE.findall(section_text)
    data_rows: list[str] = []
    seen_separator = False
    for row in rows:
        # Skip the header row (first row before separator) and the separator itself
        if TABLE_SEPARATOR_RE.match(row):
            seen_separator = True
            continue
        if not seen_separator:
            # treat as header row; skip
            continue
        # skip empty rows
        if not row.strip().strip("|").strip():
            continue
        data_rows.append(row)
    return data_rows


def _row_has_citation(row: str) -> bool:
    return bool(FILE_LINE_RE.search(row))


def _extract_table_citations(rows: list[str]) -> list[str]:
    """Return unique file:line citations from table rows (preserves order)."""
    seen: set[str] = set()
    out: list[str] = []
    for row in rows:
        for m in FILE_LINE_RE.finditer(row):
            cit = m.group(0)
            # Strip optional line range -> keep file:firstline for uniqueness
            base = cit.split("-", 1)[0]
            if base not in seen:
                seen.add(base)
                out.append(cit)
    return out


# ---------------------------------------------------------------------------
# Protection-module resolution
# ---------------------------------------------------------------------------
def _resolve_protection_modules(
    workspace: Path,
    explicit_dirs: list[str],
) -> list[Path]:
    """Resolve --protection-module-dir flags + .auditooor/r57_protection_modules.json registry."""
    out: list[Path] = []
    for raw in explicit_dirs:
        candidate = Path(raw)
        if not candidate.is_absolute():
            candidate = (workspace / raw).resolve()
        if candidate.is_dir():
            out.append(candidate)
    cfg = workspace / ".auditooor" / "r57_protection_modules.json"
    if cfg.is_file():
        try:
            data = json.loads(cfg.read_text(encoding="utf-8"))
            for entry in data.get("modules", []):
                if isinstance(entry, str):
                    candidate = Path(entry)
                    if not candidate.is_absolute():
                        candidate = (workspace / entry).resolve()
                    if candidate.is_dir() and candidate not in out:
                        out.append(candidate)
                elif isinstance(entry, dict) and "path" in entry:
                    candidate = Path(entry["path"])
                    if not candidate.is_absolute():
                        candidate = (workspace / entry["path"]).resolve()
                    if candidate.is_dir() and candidate not in out:
                        out.append(candidate)
        except Exception:
            pass
    return out


CODE_SUFFIXES = {".go", ".rs", ".sol", ".ts", ".tsx", ".js", ".mjs", ".py", ".move", ".cairo", ".vy"}

# Per-file scan cap to keep runtime bounded under perpetual-loop budget
MAX_SCAN_FILES_PER_MODULE = 400
MAX_LINE_LENGTH = 2000


def _grep_defense_call_sites(
    modules: list[Path],
    defense_re: re.Pattern[str],
) -> list[dict[str, Any]]:
    """Walk each module, scan code files for defense-action patterns, return [{file, line, token}]."""
    hits: list[dict[str, Any]] = []
    for module in modules:
        scanned = 0
        for fp in sorted(module.rglob("*")):
            if scanned >= MAX_SCAN_FILES_PER_MODULE:
                break
            if not fp.is_file() or fp.suffix not in CODE_SUFFIXES:
                continue
            scanned += 1
            try:
                content = fp.read_text(encoding="utf-8", errors="replace")
            except Exception:
                continue
            for idx, line in enumerate(content.splitlines(), start=1):
                if len(line) > MAX_LINE_LENGTH:
                    continue
                m = defense_re.search(line)
                if m:
                    hits.append({
                        "file": str(fp),
                        "line": idx,
                        "token": m.group(0),
                        "preview": line.strip()[:200],
                    })
    return hits


def _normalize_citation_to_basename(citation: str) -> tuple[str, int]:
    """Convert 'path/to/file.go:123' (or :123-145) -> ('file.go', 123)."""
    base = citation.split("-", 1)[0]
    parts = base.rsplit(":", 1)
    if len(parts) != 2:
        return (citation, 0)
    file_part, line_part = parts
    try:
        line = int(line_part)
    except ValueError:
        line = 0
    return (Path(file_part).name, line)


def _hit_accounted_for(
    hit: dict[str, Any],
    cited_basenames: set[str],
    cited_pairs: set[tuple[str, int]],
    line_tolerance: int = 60,
) -> bool:
    """A grep hit is 'accounted for' if EITHER:
       - its file basename matches a cited basename AND a cited line is within +/- N lines, OR
       - its file basename matches a cited basename when no cited line is given.
    """
    hit_basename = Path(hit["file"]).name
    hit_line = hit["line"]
    if hit_basename not in cited_basenames:
        return False
    # Check pairs first
    for cited_base, cited_line in cited_pairs:
        if cited_base == hit_basename and cited_line > 0:
            if abs(cited_line - hit_line) <= line_tolerance:
                return True
    # Basename alone is enough if no specific line citations exist for that file
    has_line_cite = any(b == hit_basename and ln > 0 for b, ln in cited_pairs)
    if not has_line_cite:
        return True
    return False


# ---------------------------------------------------------------------------
# Layer 3: per-row file:line existence check (--strict)
# ---------------------------------------------------------------------------
def _resolve_citation_in_workspace(citation: str, workspace: Path) -> bool:
    """Return True if `path/to/file.go:123` resolves to an existing file with line >= 1."""
    base = citation.split("-", 1)[0]
    parts = base.rsplit(":", 1)
    if len(parts) != 2:
        return False
    file_part, line_part = parts
    try:
        line = int(line_part)
    except ValueError:
        return False
    if line < 1:
        return False
    # try several roots in the workspace
    candidates = [
        workspace / file_part,
        workspace / "external" / file_part,
    ]
    # also search by basename
    bn = Path(file_part).name
    try:
        rg = subprocess.run(
            ["find", str(workspace), "-name", bn, "-type", "f"],
            capture_output=True, text=True, timeout=5,
        )
        for match in rg.stdout.splitlines():
            candidates.append(Path(match))
    except Exception:
        pass
    for c in candidates:
        if c.is_file():
            try:
                with c.open(encoding="utf-8", errors="replace") as fh:
                    count = sum(1 for _ in fh)
                if count >= line:
                    return True
            except Exception:
                continue
    return False


# ---------------------------------------------------------------------------
# Core check
# ---------------------------------------------------------------------------
def run(
    draft: Path,
    *,
    workspace: Path | None = None,
    severity_override: str = "auto",
    protection_module_dirs: list[str] | None = None,
    strict: bool = False,
) -> tuple[int, dict[str, Any]]:
    try:
        text = draft.read_text(encoding="utf-8", errors="replace")
    except Exception as exc:
        return 2, {
            "schema_version": SCHEMA_VERSION,
            "gate": GATE,
            "file": str(draft),
            "verdict": "error",
            "error": str(exc),
        }

    severity = _detect_severity(text, severity_override, draft)
    ws = workspace.resolve() if workspace else _workspace_root(draft)

    payload: dict[str, Any] = {
        "schema_version": SCHEMA_VERSION,
        "gate": GATE,
        "file": str(draft),
        "severity": severity,
        "workspace": str(ws),
        "strict": strict,
        "evidence": {},
        "remediation_options": [
            "Add an 'Exhaustive Defense Chain Enumeration' section with a markdown table.",
            "Each row needs file:line citation + ruled-in/ruled-out + source-cited reason.",
            "Enumerate every defense call site via grep of the protection-module dirs.",
            "Use <!-- r57-rebuttal: <reason up to 200 chars> --> for a bounded exception.",
        ],
    }

    # --- Rebuttal check (before everything else) ---
    rebuttal = _parse_rebuttal(text)
    if rebuttal:
        payload["verdict"] = "ok-rebuttal"
        payload["rebuttal"] = rebuttal
        return 0, payload

    # --- Severity scope: HIGH+ only ---
    if not _is_in_scope(severity):
        payload["verdict"] = "pass-out-of-scope"
        payload["reason"] = f"severity '{severity}' below HIGH"
        return 0, payload

    # --- Defender-narrative trigger ---
    defender_re = _build_defender_narrative_re()
    narrative_hits = []
    for idx, line in enumerate(text.splitlines(), start=1):
        m = defender_re.search(line)
        if m:
            narrative_hits.append({"line": idx, "token": m.group(0), "text": line.strip()[:200]})
            if len(narrative_hits) >= 16:
                break
    payload["evidence"]["defender_narrative_hits"] = narrative_hits
    if not narrative_hits:
        payload["verdict"] = "pass-no-defense-narrative"
        payload["reason"] = "no defender-narrative trigger phrases found"
        return 0, payload

    # --- Layer 1: section + table presence + per-row citation ---
    section_text, section_offset = _extract_enumeration_section(text)
    if section_text is None:
        payload["verdict"] = "fail-no-enumeration-section"
        payload["reason"] = (
            "draft argues against a defender narrative but lacks the required "
            "'Exhaustive Defense Chain Enumeration' section header"
        )
        return 1, payload

    table_rows = _parse_table_rows(section_text)
    payload["evidence"]["table_row_count"] = len(table_rows)
    if len(table_rows) < 2:
        payload["verdict"] = "fail-table-missing"
        payload["reason"] = (
            "section present but no markdown table with >=2 data rows "
            "(rows form: | module | file:line | ruled-in/out | reason |)"
        )
        return 1, payload

    rows_without_cit = [r for r in table_rows if not _row_has_citation(r)]
    if rows_without_cit:
        payload["verdict"] = "fail-row-without-citation"
        payload["reason"] = f"{len(rows_without_cit)} of {len(table_rows)} rows lack file:line citation"
        payload["evidence"]["rows_without_citation"] = rows_without_cit[:8]
        return 1, payload

    cited_citations = _extract_table_citations(table_rows)
    payload["evidence"]["table_citations"] = cited_citations

    # --- Layer 3: per-row source-citation existence (--strict only) ---
    if strict:
        unresolved: list[str] = []
        for cit in cited_citations:
            if not _resolve_citation_in_workspace(cit, ws):
                unresolved.append(cit)
        if unresolved:
            payload["verdict"] = "fail-ruling-without-source-citation"
            payload["reason"] = f"{len(unresolved)} cited path(s) do not resolve in workspace"
            payload["evidence"]["unresolved_citations"] = unresolved[:8]
            return 1, payload

    # --- Layer 2: grep-derived defense call sites vs table count (HIGH+) ---
    protection_dirs = _resolve_protection_modules(ws, protection_module_dirs or [])
    payload["evidence"]["protection_module_dirs"] = [str(d) for d in protection_dirs]

    if not protection_dirs:
        # Warn-only fallback: no registry, no flags. Layer 1 passed; trust it.
        payload["verdict"] = "pass-all-defense-paths-enumerated"
        payload["reason"] = (
            "section + table + citations present; no protection-module registry "
            "configured at .auditooor/r57_protection_modules.json so Layer-2 count "
            "comparison skipped (warn-fallback per design §3.3)"
        )
        payload["warn"] = "configure .auditooor/r57_protection_modules.json or pass --protection-module-dir to enable Layer-2 grep verification"
        return 0, payload

    defense_re = _build_combined_defense_re(ws)
    hits = _grep_defense_call_sites(protection_dirs, defense_re)
    payload["evidence"]["grep_defense_call_site_count"] = len(hits)

    cited_basenames = set()
    cited_pairs: set[tuple[str, int]] = set()
    for cit in cited_citations:
        bn, ln = _normalize_citation_to_basename(cit)
        cited_basenames.add(bn)
        cited_pairs.add((bn, ln))
    payload["evidence"]["cited_basenames"] = sorted(cited_basenames)

    unaccounted = [
        h for h in hits
        if not _hit_accounted_for(h, cited_basenames, cited_pairs)
    ]
    payload["evidence"]["unaccounted_call_sites"] = unaccounted[:16]

    if unaccounted:
        payload["verdict"] = "fail-defense-paths-missing-from-enumeration"
        payload["reason"] = (
            f"grep found {len(hits)} defense call sites across protection modules; "
            f"{len(unaccounted)} are not accounted for in the enumeration table"
        )
        return 1, payload

    payload["verdict"] = "pass-all-defense-paths-enumerated"
    payload["reason"] = (
        f"section + table + citations present; {len(hits)} grep-found defense call sites "
        f"all accounted for in {len(table_rows)} enumeration rows"
    )
    return 0, payload


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("draft", type=Path)
    parser.add_argument("--workspace", type=Path, default=None)
    parser.add_argument(
        "--protection-module-dir",
        action="append",
        default=[],
        help="Repeatable. Path to a defender protection module (relative to workspace).",
    )
    parser.add_argument(
        "--severity",
        choices=["auto", "Critical", "High", "Medium", "Low", "critical", "high", "medium", "low", "CRITICAL", "HIGH", "MEDIUM", "LOW"],
        default="auto",
    )
    parser.add_argument("--strict", action="store_true")
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args(argv)
    rc, payload = run(
        args.draft,
        workspace=args.workspace,
        severity_override=args.severity,
        protection_module_dirs=args.protection_module_dir,
        strict=args.strict,
    )
    print(json.dumps(payload, indent=2, sort_keys=True))
    return rc


if __name__ == "__main__":
    raise SystemExit(main())
