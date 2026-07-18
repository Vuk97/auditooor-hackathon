#!/usr/bin/env python3
"""paste-ready-generator.py - turn a staging draft into clean Immunefi paste.

PR #526 gap 2 (Wave 7 ww2). Input: a staging draft in
`<workspace>/submissions/staging/<draft>.md` (optionally a packaged bundle
directory with `source-draft.md`). Output: a paste-ready file under
`<workspace>/submissions/paste_ready/<slug>/<slug>.md` containing the cleaned-up
structure expected by Immunefi-style triagers.

The generator NEVER auto-submits and NEVER edits the source draft. It either
emits the paste-ready text or refuses with a clear reason.

Cleaned structure emitted (sections in order):

  1. Title (severity + 1-line summary)
  2. ## Program Impact Mapping  (cited verbatim from the draft)
  3. ## Source-only Justification  (why this is not artifact-only)
  4. ## Production Path  (from the draft / lib helper, hard fail if absent)
  5. ## Real-component Precondition  (claim-precondition manifest if present)
  6. ## Originality Reference  (sherlock/code4rena/cantina de-dup citation)
  7. ## Not Proven  (verbatim from mapping block's `not_proven_impacts:` list - PR #535 PR 1)
  8. ## Warning Summary  (any pre-submit warnings the operator must ack)

Refusal rules (exit 1):
  - `tools/pre-submit-check.sh <draft>` reports hard FAILs.
  - `## Program Impact Mapping` block is missing or empty.
  - Production Path is absent (per tools/lib/production_path.py).
  - Dossier (`<ws>/.auditooor/<slug>_dossier.json` if present) has unresolved
    blockers.

Warning-only (still emits, but warnings appended inline):
  - pre-submit-check.sh exits 0 with `warning(s)`.

Exit codes:
  0 - paste-ready file written, safe to copy/paste
  1 - refused (hard failure surfaced; original draft untouched)

Usage:
  paste-ready-generator.py <workspace> <draft.md>
  paste-ready-generator.py <workspace> --all-staging
  paste-ready-generator.py --bundle <packaged-bundle-dir>

Stdlib-only.
"""
from __future__ import annotations

import argparse
import importlib.util
import json
import os
import re
import subprocess
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterable, List, Optional, Tuple

AUDITOOOR_DIR = Path(__file__).resolve().parent.parent

# PR #535 PR 1: shared Program Impact Mapping helper. Used to extract the
# `not_proven_impacts:` field from the draft's mapping block and render
# it into a dedicated `## Not Proven` section so triagers see what is NOT
# claimed.
_PIM_LIB_CACHE_KEY = "_paste_ready_impact_mapping_lib"


def _load_impact_mapping_lib():
    cached = sys.modules.get(_PIM_LIB_CACHE_KEY)
    if cached is not None:
        return cached
    spec_path = AUDITOOOR_DIR / "tools" / "lib" / "program_impact_mapping.py"
    if not spec_path.is_file():
        return None
    try:
        spec = importlib.util.spec_from_file_location(_PIM_LIB_CACHE_KEY, spec_path)
        if spec is None or spec.loader is None:
            return None
        module = importlib.util.module_from_spec(spec)
        sys.modules[_PIM_LIB_CACHE_KEY] = module
        spec.loader.exec_module(module)
        return module
    except Exception:
        sys.modules.pop(_PIM_LIB_CACHE_KEY, None)
        return None

# ---------------------------------------------------------------------------
# Shared production-path lib (re-uses the canonical parser; matches
# submission-packager.py loading idiom for Python 3.14 dataclass safety).
# ---------------------------------------------------------------------------
_PP_CACHE_KEY = "_paste_ready_production_path_lib"


def _load_production_path_lib():
    cached = sys.modules.get(_PP_CACHE_KEY)
    if cached is not None:
        return cached
    spec_path = AUDITOOOR_DIR / "tools" / "lib" / "production_path.py"
    if not spec_path.is_file():
        return None
    try:
        spec = importlib.util.spec_from_file_location(_PP_CACHE_KEY, spec_path)
        if spec is None or spec.loader is None:
            return None
        module = importlib.util.module_from_spec(spec)
        sys.modules[_PP_CACHE_KEY] = module
        spec.loader.exec_module(module)
        return module
    except Exception:
        sys.modules.pop(_PP_CACHE_KEY, None)
        return None


# ---------------------------------------------------------------------------
# Section parsing helpers (stdlib regex; deterministic).
# ---------------------------------------------------------------------------

# Heading regex (H2+): `## Foo`, `### Foo`, `## **Foo**`.
HEADING_RE = re.compile(r"^(#{2,6})\s+\**\s*(.+?)\s*\**\s*$", re.MULTILINE)
# Heading regex (any level, including H1) - used by title detection.
ANY_HEADING_RE = re.compile(r"^(#{1,6})\s+\**\s*(.+?)\s*\**\s*$", re.MULTILINE)


def _normalize_heading(name: str) -> str:
    """Lowercase, strip emoji-ish punctuation, collapse whitespace."""
    cleaned = re.sub(r"[^a-z0-9 ]+", " ", name.lower())
    cleaned = re.sub(r"\s+", " ", cleaned).strip()
    return cleaned


def find_section(text: str, *targets: str) -> Tuple[Optional[int], Optional[int], Optional[str]]:
    """Locate the first heading whose normalized name matches one of `targets`.

    Returns (start_offset_of_body, end_offset_of_body, raw_heading_line).
    Body excludes the heading line itself. End is the start of the next heading
    of <= the matched level, or end-of-text.
    """
    targets_n = [t.lower() for t in targets]
    matches = list(HEADING_RE.finditer(text))
    for idx, m in enumerate(matches):
        name = _normalize_heading(m.group(2))
        if any(name == t or name.startswith(t + " ") or t in name.split() for t in targets_n):
            level = len(m.group(1))
            body_start = m.end() + 1  # skip newline after heading
            body_end = len(text)
            for n in matches[idx + 1:]:
                if len(n.group(1)) <= level:
                    body_end = n.start()
                    break
            return body_start, body_end, m.group(0).rstrip()
    return None, None, None


def extract_section(text: str, *targets: str) -> Optional[str]:
    """Return the body of a section (without the heading), or None if absent."""
    start, end, _ = find_section(text, *targets)
    if start is None:
        return None
    body = text[start:end].strip("\n")
    return body if body.strip() else None


# ---------------------------------------------------------------------------
# Severity + title
# ---------------------------------------------------------------------------

SEVERITY_RE = re.compile(
    r"\b(critical|high|medium|low|informational)\b",
    re.IGNORECASE,
)
REPORTABLE_SEVERITIES = {"Critical", "High", "Medium"}
DIRECT_SUBMIT_RE = re.compile(
    r"\b(in_scope_direct_submit|direct[-_ ]submit|submit[-_ ]ready|paste[-_ ]ready)\b",
    re.IGNORECASE,
)
LOCAL_OR_INTERNAL_PATH_RE = re.compile(
    r"(/Users/|/private/|/var/folders/|\.auditooor/|impact_contracts\.json|"
    r"poc_execution/|manual_proofs/|submissions/(?:staging|packaged|paste-ready|cantina_paste)/|"
    r"\boriginality\b)",
    re.IGNORECASE,
)
POC_COMMAND_RE = re.compile(
    r"\b(forge\s+test|cargo\s+test|npm\s+test|yarn\s+test|pnpm\s+test|pytest|go\s+test)\b",
    re.IGNORECASE,
)
POC_PASS_RE = re.compile(
    r"\b(PASS|passed|ok\b|Result:\s*proved|RESULT=proved|exploit_impact|test result:\s*ok)\b",
    re.IGNORECASE,
)


def detect_severity_and_title(text: str) -> Tuple[str, str]:
    """Detect severity + first non-empty H1/H2 title line.

    Falls back to ("Unknown", "Untitled finding") if no heading found.
    """
    title = "Untitled finding"
    severity = "Unknown"
    # First-heading title - prefer H1, else fall back to first H2.
    h1 = None
    h2 = None
    for m in ANY_HEADING_RE.finditer(text):
        level = len(m.group(1))
        if level == 1 and h1 is None:
            h1 = m.group(2).strip()
            break
        if level == 2 and h2 is None:
            h2 = m.group(2).strip()
    if h1:
        title = h1
    elif h2:
        title = h2
    # Strip a leading "<Severity> - " or "<Severity>: " prefix so the rendered
    # paste-ready heading does not double the severity word.
    title_severity_re = re.compile(
        "^(critical|high|medium|low|informational)\\s*[\\u2014:\\-]\\s*",
        re.IGNORECASE,
    )
    title = title_severity_re.sub("", title).strip() or "Untitled finding"
    # Severity recommendation lines (matches the staging draft convention).
    for line in text.splitlines()[:60]:
        if "severity" in line.lower():
            sm = SEVERITY_RE.search(line)
            if sm:
                severity = sm.group(1).capitalize()
                break
    return severity, title


# ---------------------------------------------------------------------------
# Pre-submit gate
# ---------------------------------------------------------------------------


@dataclass
class PreSubmitResult:
    rc: int
    fails: int
    warns: int
    raw: str

    @property
    def hard_fail(self) -> bool:
        return self.rc != 0


def run_pre_submit(draft: Path) -> PreSubmitResult:
    """Invoke `tools/pre-submit-check.sh` and parse its summary line."""
    script = AUDITOOOR_DIR / "tools" / "pre-submit-check.sh"
    if not script.is_file():
        return PreSubmitResult(rc=2, fails=0, warns=0,
                               raw="[error] pre-submit-check.sh not found")
    # Rank-1 (NUVA presubmit friction): the paste-ready / filing lane IS the
    # strict filing gate, so arm the PoC-first fail-fast block (Check #10p)
    # inside pre-submit-check.sh. It is default-off for a bare CLI lint run and
    # only fires here (and via `make audit-complete STRICT=1`). Without this the
    # "default-on under STRICT" intent is inert -- no STRICT env reaches the
    # script otherwise.
    _env = dict(os.environ)
    _env.setdefault("AUDITOOOR_POC_FIRST_STRICT", "1")
    proc = subprocess.run(
        ["bash", str(script), str(draft)],
        capture_output=True,
        text=True,
        cwd=str(AUDITOOOR_DIR),
        timeout=900,
        env=_env,
    )
    raw = proc.stdout + proc.stderr
    fails = 0
    warns = 0
    for line in raw.splitlines():
        m = re.search(r"(\d+)\s+check\(s\) failed,\s+(\d+)\s+warning", line)
        if m:
            fails = int(m.group(1))
            warns = int(m.group(2))
            break
        m = re.match(r"\s*[^\d]*(\d+)\s+warning", line)
        if "warning(s)" in line and m:
            warns = int(m.group(1))
    return PreSubmitResult(rc=proc.returncode, fails=fails, warns=warns, raw=raw)


# ---------------------------------------------------------------------------
# Dossier blocker check
# ---------------------------------------------------------------------------


def find_dossier(workspace: Path, draft: Path) -> Optional[Path]:
    """Locate a dossier JSON for this draft, if one exists.

    Searches `<ws>/.auditooor/` for files matching `*<slug>*dossier*.json` or
    a packaged bundle's `manifest.json` with a `dossier` block.
    """
    ws_meta = workspace / ".auditooor"
    if not ws_meta.is_dir():
        return None
    slug = draft.stem.lower()
    # Strip common suffixes (`_draft`, `-draft`, `_scaffold`, `-scaffold`).
    for suf in ("_draft", "-draft", "_scaffold", "-scaffold"):
        if slug.endswith(suf):
            slug = slug[: -len(suf)]
    candidates: List[Path] = []
    for p in ws_meta.glob("*dossier*.json"):
        candidates.append(p)
    if not candidates:
        return None
    # Prefer the closest slug match; otherwise return the first.
    candidates.sort(key=lambda p: (slug not in p.stem.lower(), p.name))
    return candidates[0]


def dossier_blockers(dossier_path: Path) -> List[str]:
    try:
        data = json.loads(dossier_path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return []
    if not isinstance(data, dict):
        return []
    blockers = data.get("blockers")
    if isinstance(blockers, list):
        return [str(b) for b in blockers if str(b).strip()]
    # Sometimes nested under per-finding entries
    findings = data.get("findings") or data.get("candidates")
    if isinstance(findings, list):
        out: List[str] = []
        for entry in findings:
            if isinstance(entry, dict):
                bs = entry.get("blockers")
                if isinstance(bs, list):
                    out.extend(str(b) for b in bs if str(b).strip())
        return out
    return []


# ---------------------------------------------------------------------------
# Claim-precondition citation
# ---------------------------------------------------------------------------


CLAIM_PRECONDITION_RE = re.compile(
    r"<!--\s*claim-precondition\s*:\s*([^>]+?)-->",
    re.IGNORECASE | re.DOTALL,
)


def extract_claim_preconditions(text: str) -> List[str]:
    return [m.group(1).strip() for m in CLAIM_PRECONDITION_RE.finditer(text)]


# ---------------------------------------------------------------------------
# Originality reference detection
# ---------------------------------------------------------------------------


ORIGINALITY_HOSTS = (
    "sherlock", "code4rena", "c4", "cantina", "immunefi",
    "spearbit", "trail of bits", "consensys", "openzeppelin",
)


def extract_originality_lines(text: str) -> List[str]:
    body = extract_section(text, "originality", "originality reference",
                           "duplicate check", "dupe check") or ""
    if body:
        return [ln.strip("- ").strip() for ln in body.splitlines() if ln.strip()]
    # Fallback: scan whole draft for known host references.
    out: List[str] = []
    for ln in text.splitlines():
        lower = ln.lower()
        if any(h in lower for h in ORIGINALITY_HOSTS) and "http" in lower:
            out.append(ln.strip("- ").strip())
    return out[:8]


def _extract_field_value(text: str, *names: str) -> str:
    wanted = {re.sub(r"[^a-z0-9]+", "", name.lower()) for name in names}
    for line in text.splitlines():
        match = re.match(r"^\s*(?:[-*]\s*)?\**\s*([A-Za-z][A-Za-z0-9 _/-]+?)\s*\**\s*:\s*(.+?)\s*$", line)
        if not match:
            continue
        key = re.sub(r"[^a-z0-9]+", "", match.group(1).lower())
        if key in wanted:
            value = re.sub(r"\*\*", "", match.group(2)).strip()
            return value.strip("` ")
    return ""


def _extract_likelihood(text: str) -> str:
    section = extract_section(text, "likelihood", "exploit likelihood")
    if section:
        return re.sub(r"\s+", " ", section.strip().splitlines()[0]).strip("- ")
    return _extract_field_value(text, "likelihood", "exploit likelihood")


def _extract_impact(text: str) -> str:
    pim_lib = _load_impact_mapping_lib()
    if pim_lib is not None:
        try:
            contract = pim_lib.validate_impact_contract_text(text, require_contract=False)
            selected = str(contract.get("selected_impact") or "").strip()
            if selected:
                return selected
        except Exception:
            pass
    section = extract_section(text, "impact", "impact summary")
    if section:
        return re.sub(r"\s+", " ", section.strip().splitlines()[0]).strip("- ")
    return _extract_field_value(text, "impact", "selected impact", "selected_impact")


def _extract_proof_block(text: str) -> str:
    proof = extract_section(
        text,
        "poc", "proof", "test proof", "poc test proof",
        "reproduction", "proof and reproduction", "poc commands",
    )
    if proof:
        return proof.strip()
    lines = [
        line.rstrip()
        for line in text.splitlines()
        if POC_COMMAND_RE.search(line) or POC_PASS_RE.search(line)
    ]
    return "\n".join(lines).strip()


def _extract_severity_justification(text: str) -> str:
    """Return the full ``Severity Justification`` section body, if present.

    L27 known-issue fix: the canonical Cantina template mandates a verbatim
    ``## Severity Justification`` section (rubric-row mapping + parity
    argument). The triager-paste renderer used to discard it entirely, so we
    surface the whole section body here so the canonical paste can re-emit it.
    """
    section = extract_section(
        text,
        "severity justification", "severity rationale",
        "rubric justification",
    )
    return section.strip() if section else ""


def _extract_likelihood_block(text: str) -> str:
    """Return the full ``Likelihood`` section body (not just its first line).

    ``_extract_likelihood`` collapses the section to a single summary line for
    the Triager Summary bullet. This returns the entire section body so the
    canonical paste preserves the author's full likelihood reasoning per L27.
    """
    section = extract_section(text, "likelihood", "exploit likelihood")
    return section.strip() if section else ""


def _extract_impact_contract_block(text: str) -> str:
    """Return the Impact-Contract directives block, if present.

    L27 mandates that the 6 Impact-Contract directives survive into the
    canonical paste. The directives may live under several heading aliases
    (``Impact Contract`` / ``Program Impact Mapping`` / ``Impact Mapping`` /
    ``Pre-Harness Impact Contract`` / ``Program Impact Contract``).
    """
    section = extract_section(
        text,
        "impact contract", "program impact mapping", "impact mapping",
        "pre harness impact contract", "program impact contract",
    )
    return section.strip() if section else ""


def _render_triager_paste(
    *,
    source_text: str,
    severity: str,
    title: str,
    pp_body: str,
    source_only: str,
) -> Tuple[str, List[str]]:
    """Render a platform-facing paste body and fail closed on internal leakage."""
    reasons: List[str] = []
    likelihood = _extract_likelihood(source_text)
    impact = _extract_impact(source_text)
    proof_block = _extract_proof_block(source_text)
    vulnerable_code = extract_section(
        source_text,
        "vulnerable code", "affected code", "code references", "source references",
    ) or source_only
    # L27 known-issue fix: preserve the canonical-template sections the
    # renderer used to discard - Severity Justification, the full Likelihood
    # reasoning, and the Impact-Contract directives. These are emitted as
    # first-class sections below so the triager paste is not a stripped paste.
    severity_justification = _extract_severity_justification(source_text)
    likelihood_block = _extract_likelihood_block(source_text)
    impact_contract_block = _extract_impact_contract_block(source_text)

    if not severity or severity == "Unknown":
        reasons.append("triager-paste requires explicit Severity")
    if not likelihood:
        reasons.append("triager-paste requires explicit Likelihood")
    if not impact:
        reasons.append("triager-paste requires explicit Impact")
    if not proof_block:
        reasons.append("triager-paste requires PoC/test reproduction proof")
    elif not POC_COMMAND_RE.search(proof_block) or not POC_PASS_RE.search(proof_block):
        reasons.append("triager-paste requires PoC/test command and observed pass output")

    lines = [
        f"# {severity} - {title}",
        "",
        "## Triager Summary",
        "",
        f"- Severity: {severity}",
        f"- Likelihood: {likelihood}",
        f"- Impact: {impact}",
        "",
        "## Severity Justification",
        "",
        severity_justification or (
            "_Severity Justification not authored in the source draft; "
            "operator must supply the rubric-row mapping before filing._"
        ),
        "",
        "## Likelihood",
        "",
        likelihood_block or likelihood,
        "",
        "## Source-Only Justification",
        "",
        source_only.strip(),
        "",
        "## Impact Contract",
        "",
        impact_contract_block or (
            "_Impact-Contract directives not authored in the source draft; "
            "operator must supply the 6 directives before filing._"
        ),
        "",
        "## Attack Flow",
        "",
        pp_body.strip(),
        "",
        "## Vulnerable Code",
        "",
        vulnerable_code.strip(),
        "",
        "## PoC / Test Proof",
        "",
        proof_block.strip(),
        "",
        "## Proof Meaning",
        "",
        "The reproduced test demonstrates the claimed impact on the production "
        "code path described above; it is not presented as a local workspace "
        "manifest or internal triage artifact.",
        "",
    ]
    rendered = re.sub(r"\n{3,}", "\n\n", "\n".join(lines)).rstrip() + "\n"
    leaked = sorted({m.group(0) for m in LOCAL_OR_INTERNAL_PATH_RE.finditer(rendered)})
    if leaked:
        reasons.append(
            "triager-paste output still contains local/internal-only references: "
            + ", ".join(leaked)
        )
    return rendered, reasons


# ---------------------------------------------------------------------------
# Generation
# ---------------------------------------------------------------------------


def _resolve_severity_and_rubric(
    pim_lib,
    draft: Path,
    text: str,
    fallback_severity: str,
    workspace: Path,
):
    """Return ``(severity_implied, rubric_tiers_dict_or_None)`` for F4 tier check.

    ``severity_implied`` is taken from the parsed mapping block when
    present, falling back to the draft's banner severity. ``rubric_tiers``
    is loaded via the canonical gate's ``_load_rubric_text`` /
    ``_parse_rubric_tiers`` so paste-ready uses the same parser the
    closeout/promotion surfaces use - no forked logic.

    Returns ``("", None)`` if the gate cannot be loaded; render falls back
    to the legacy verbatim emission in that case.
    """
    sev = ""
    rubric_tiers = None
    try:
        gate = pim_lib._load_gate()  # noqa: SLF001 - shared parser
    except Exception:
        gate = None
    if gate is None:
        return sev, rubric_tiers
    # Severity from parsed block.
    try:
        found, inner, _level = gate._extract_block(text)  # noqa: SLF001
        if found:
            block = gate._parse_block(inner)  # noqa: SLF001
            sev_clean = (block.severity_implied or "").strip().rstrip(".,:;").strip()
            if sev_clean:
                sev = sev_clean.capitalize()
    except Exception:
        pass
    if not sev and fallback_severity:
        sev = str(fallback_severity).strip().rstrip(".,:;").strip().capitalize()
    # Rubric tiers from workspace.
    try:
        rubric_found, rubric_text = gate._load_rubric_text(workspace)  # noqa: SLF001
        if rubric_found:
            rubric_tiers = gate._parse_rubric_tiers(rubric_text)  # noqa: SLF001
    except Exception:
        rubric_tiers = None
    return sev, rubric_tiers


def _norm_sentence(value: object) -> str:
    if not isinstance(value, str):
        return ""
    return re.sub(r"\s+", " ", value.strip().strip('"').strip("'").lower())


def _coerce_bool(value: object) -> bool:
    if isinstance(value, bool):
        return value
    if isinstance(value, (int, float)):
        return bool(value)
    if isinstance(value, str):
        return value.strip().lower() in {"1", "true", "yes", "y", "proved", "proven"}
    return False


def _json_payload(path: Path) -> object:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (FileNotFoundError, OSError, ValueError):
        return {}


def _records_from_payload(payload: object) -> List[dict]:
    if isinstance(payload, list):
        return [row for row in payload if isinstance(row, dict)]
    if not isinstance(payload, dict):
        return []
    for key in ("contracts", "impact_contracts", "rows", "candidates", "items"):
        value = payload.get(key)
        if isinstance(value, list):
            return [row for row in value if isinstance(row, dict)]
    return []


def _selected_impact_from_row(row: dict) -> str:
    for key in ("listed_impact_selected", "selected_impact", "original_selected_impact", "impact"):
        value = row.get(key)
        if isinstance(value, str) and value.strip():
            return value.strip()
    return ""


def _severity_from_row(row: dict) -> str:
    for key in ("raw_severity", "severity", "severity_tier", "severity_implied"):
        value = row.get(key)
        if isinstance(value, str) and value.strip():
            return value.strip().rstrip(".,:;").capitalize()
    return ""


def _row_has_exact_flag(row: dict) -> bool:
    return any(
        _coerce_bool(row.get(key))
        for key in (
            "exact_impact_row",
            "exact_listed_impact",
            "selected_impact_exact",
            "listed_impact_exact",
        )
    )


def _listed_impact_sentences(workspace: Path) -> List[str]:
    out: List[str] = []
    seen: set[str] = set()

    def add(value: object) -> None:
        if not isinstance(value, str) or not value.strip():
            return
        norm = _norm_sentence(value)
        if norm and norm not in seen:
            seen.add(norm)
            out.append(value.strip())

    matrix = _json_payload(workspace / ".auditooor" / "program_impact_matrix.json")
    for row in _records_from_payload(matrix):
        add(row.get("impact"))
    if isinstance(matrix, dict):
        for key in (
            "listed_impacts",
            "listed_critical_impacts",
            "listed_high_impacts",
            "listed_medium_impacts",
            "listed_low_impacts",
            "listed_informational_impacts",
        ):
            value = matrix.get(key)
            if isinstance(value, list):
                for item in value:
                    add(item)

    pim_lib = _load_impact_mapping_lib()
    if pim_lib is not None:
        try:
            gate = pim_lib._load_gate()  # noqa: SLF001
            found, rubric_text = gate._load_rubric_text(workspace)  # noqa: SLF001
            if found:
                tiers = gate._parse_rubric_tiers(rubric_text)  # noqa: SLF001
                for rows in tiers.values():
                    for item in rows or []:
                        add(item)
        except Exception:
            pass
    return out


def _impact_contract_refusal_reasons(
    *,
    workspace: Path,
    text: str,
    selected_impact: str,
    severity: str,
) -> List[str]:
    """Require a matching proven exact impact_contract before paste output."""
    sev = (severity or "").strip().rstrip(".,:;").capitalize()
    requires_contract = sev in REPORTABLE_SEVERITIES or bool(DIRECT_SUBMIT_RE.search(text))
    if not requires_contract:
        return []

    payload = _json_payload(workspace / ".auditooor" / "impact_contracts.json")
    rows = _records_from_payload(payload)
    if not rows:
        return ["impact_contract_missing"]

    selected_norm = _norm_sentence(selected_impact)
    matching = [
        row for row in rows
        if selected_norm and _norm_sentence(_selected_impact_from_row(row)) == selected_norm
    ]
    if not matching:
        return ["impact_contract_missing_matching_selected_impact"]

    listed = {_norm_sentence(item) for item in _listed_impact_sentences(workspace)}
    reasons: List[str] = []
    for row in matching:
        row_selected = _selected_impact_from_row(row)
        row_sev = _severity_from_row(row)
        exact = (
            _norm_sentence(row_selected) in listed
            if listed else _row_has_exact_flag(row)
        )
        row_reasons: List[str] = []
        if row_sev and sev and row_sev != sev:
            row_reasons.append("severity_tier_mismatch")
        if not exact:
            row_reasons.append("selected_impact_not_exact_listed_sentence")
        if not _coerce_bool(row.get("listed_impact_proven")):
            row_reasons.append("listed_impact_not_proven")
        if not row_reasons:
            return []
        reasons.extend(row_reasons)
    return sorted(set(reasons))


def _draft_contract_tier_refusal(
    *,
    draft_severity: str,
    contract: dict,
) -> List[str]:
    """Return reasons when visible draft severity outruns the locked tier."""
    sev = (draft_severity or "").strip().rstrip(".,:;").capitalize()
    if sev not in REPORTABLE_SEVERITIES:
        return []
    matched_tier = str(contract.get("matched_rubric_tier") or "").strip()
    contract_tier = str(contract.get("severity_tier") or "").strip()
    locked_tier = matched_tier or contract_tier
    if locked_tier and sev != locked_tier:
        return ["severity_claim_not_backed_by_selected_impact_tier"]
    return []


@dataclass
class GenerationResult:
    paste_ready_path: Optional[Path]
    refused: bool = False
    refusal_reasons: List[str] = field(default_factory=list)
    warnings: List[str] = field(default_factory=list)
    duplicate_root_block: str = ""


# ---------------------------------------------------------------------------
# PR 9 (wave 8) - duplicate-root surfacing
# ---------------------------------------------------------------------------

# Loaded lazily from `tools/track-submissions.py` via importlib because the
# filename has a hyphen.
_TS_CACHE_KEY = "_paste_ready_track_submissions_lib"


def _load_track_submissions_lib():
    cached = sys.modules.get(_TS_CACHE_KEY)
    if cached is not None:
        return cached
    spec_path = AUDITOOOR_DIR / "tools" / "track-submissions.py"
    if not spec_path.is_file():
        return None
    try:
        spec = importlib.util.spec_from_file_location(_TS_CACHE_KEY, spec_path)
        if spec is None or spec.loader is None:
            return None
        module = importlib.util.module_from_spec(spec)
        sys.modules[_TS_CACHE_KEY] = module
        spec.loader.exec_module(module)
        return module
    except Exception:
        sys.modules.pop(_TS_CACHE_KEY, None)
        return None


def _resolve_central_ledger() -> Optional[Path]:
    candidate = AUDITOOOR_DIR / "reference" / "outcomes.jsonl"
    return candidate if candidate.is_file() else None


def _matching_outcome_rows(
    workspace: Path, draft: Path
) -> List[dict]:
    """Return outcome rows tied to this draft.

    Match heuristics (cheap, deterministic):

      * Title overlap: any non-trivial token in the draft's first H1/H2
        present in the row's `title` field counts as a match.
      * Workspace name: row['workspace'] == workspace.name.

    The match is best-effort. If the draft has no recognizable title we
    return an empty list and the surfacing block is empty.
    """
    ts = _load_track_submissions_lib()
    if ts is None:
        return []
    ledger = _resolve_central_ledger()
    if ledger is None:
        return []
    rows = ts._iter_outcomes(ledger)
    latest = ts._latest_rows_by_report_id(rows)
    text = draft.read_text(encoding="utf-8", errors="replace")
    # Pull the first heading as a coarse identity probe.
    head_match = ANY_HEADING_RE.search(text)
    if not head_match:
        return []
    headline = head_match.group(2).lower()
    tokens = {t for t in re.split(r"[^a-z0-9]+", headline) if len(t) >= 5}
    matches: List[dict] = []
    for row in latest.values():
        if str(row.get("workspace", "")) != workspace.name:
            continue
        title = str(row.get("title", "")).lower()
        if not title:
            continue
        title_tokens = {
            t for t in re.split(r"[^a-z0-9]+", title) if len(t) >= 5
        }
        if tokens & title_tokens:
            matches.append(row)
    return matches


def _render_duplicate_root_block_for_draft(
    workspace: Path, draft: Path
) -> str:
    """Emit the PR 9 dup-root surfacing block for this draft, or empty.

    Empty result is the common case; the block is only non-empty when the
    operator has back-filled a `duplicate_of_<accepted|rejected>` row that
    matches this draft.
    """
    ts = _load_track_submissions_lib()
    if ts is None:
        return ""
    rows = _matching_outcome_rows(workspace, draft)
    return ts.render_duplicate_root_summary(rows)


def generate_paste_ready(
    workspace: Path,
    draft: Path,
    *,
    out_dir: Optional[Path] = None,
    skip_pre_submit: bool = False,
    platform: str = "",
    triager_paste: bool = False,
    verify_commands: bool = False,
) -> GenerationResult:
    """Build the paste-ready output for a single draft, or refuse with reasons."""
    text = draft.read_text(encoding="utf-8")
    refusal: List[str] = []
    warnings: List[str] = []

    # --- Refusal #1: pre-submit-check.sh hard fail ---
    if not skip_pre_submit:
        psr = run_pre_submit(draft)
        if psr.hard_fail:
            refusal.append(
                f"pre-submit-check hard FAIL ({psr.fails} failed, {psr.warns} warn)"
            )
        elif psr.warns > 0:
            warnings.append(
                f"pre-submit-check passed with {psr.warns} warning(s); "
                f"operator must acknowledge before paste"
            )

    # --- Refusal #2: Program Impact Mapping block is required ---
    #
    # PR #541 follow-up F5 fix: the prior implementation only checked that
    # a ``## Program Impact Mapping`` heading with a non-empty body
    # existed. A draft with body ``placeholder\n`` passed Refusal #2 and
    # never invoked the canonical Check #31 gate. We now route the
    # paste-ready refusal through the shared lib's ``summarize_draft`` so
    # paste-ready and closeout enforce the same contract.
    pim_body = extract_section(text, "program impact mapping",
                                "program impact map", "impact mapping")
    if not pim_body or not pim_body.strip():
        refusal.append(
            "missing `## Program Impact Mapping` block (gap 0 / TT2 gate)"
        )
    else:
        pim_lib_for_refusal = _load_impact_mapping_lib()
        if pim_lib_for_refusal is None:
            refusal.append(
                "impact-contract validator unavailable; refusing paste-ready output"
            )
        else:
            try:
                summary = pim_lib_for_refusal.summarize_draft(
                    draft, workspace=workspace
                )
            except Exception:
                summary = None
            if summary is not None:
                status = str(summary.get("status") or "")
                if status and not pim_lib_for_refusal.is_clean(status):
                    err_blob = "; ".join(summary.get("errors") or [])
                    if err_blob:
                        refusal.append(
                            f"`## Program Impact Mapping` block fails the "
                            f"canonical gate (status={status}): {err_blob}"
                        )
                    else:
                        refusal.append(
                            f"`## Program Impact Mapping` block fails the "
                            f"canonical gate (status={status})"
                        )
            contract = pim_lib_for_refusal.validate_impact_contract_text(
                text,
                workspace=workspace,
                require_contract=True,
            )
            if not contract.get("ok"):
                reasons = ", ".join(str(r) for r in contract.get("reasons", []))
                refusal.append(
                    "impact contract is not locked before report generation: "
                    f"{reasons}"
                )
            draft_severity, _draft_title = detect_severity_and_title(text)
            proof_reasons = _draft_contract_tier_refusal(
                draft_severity=draft_severity,
                contract=contract,
            )
            proof_reasons.extend(_impact_contract_refusal_reasons(
                workspace=workspace,
                text=text,
                selected_impact=str(contract.get("selected_impact") or ""),
                severity=draft_severity,
            ))
            if proof_reasons:
                refusal.append(
                    "matching workspace impact_contract proof is missing or "
                    "not locked before paste-ready output: "
                    + ", ".join(proof_reasons)
                )

    # --- Refusal #3: Production Path is required ---
    pp_body: Optional[str] = None
    pp_lib = _load_production_path_lib()
    if pp_lib is not None:
        pp_section = pp_lib.extract_production_path_section(text)
        if pp_section.present:
            pp_body = "\n".join(
                f"{n}. {pp_section.item(n)}" for n in range(1, 11)
                if pp_section.item(n)
            ) or pp_section.raw
        else:
            refusal.append("missing `## Production Path` section")
    else:
        # Fallback: simple heading scan.
        pp_body = extract_section(text, "production path")
        if not pp_body:
            refusal.append("missing `## Production Path` section")

    # --- Refusal #4: dossier blockers ---
    dossier_path = find_dossier(workspace, draft)
    blockers: List[str] = []
    if dossier_path is not None:
        blockers = dossier_blockers(dossier_path)
        if blockers:
            refusal.append(
                f"dossier {dossier_path.name} has unresolved blockers: "
                + ", ".join(sorted(set(blockers)))
            )

    if refusal:
        return GenerationResult(
            paste_ready_path=None,
            refused=True,
            refusal_reasons=refusal,
            warnings=warnings,
        )

    # --- Build the paste-ready output ---
    severity, title = detect_severity_and_title(text)

    source_only = extract_section(
        text, "source only justification", "source-only justification",
        "source only", "source-only", "why source only",
    )
    if not source_only:
        # Default justification when the gate accepts the draft but the author
        # forgot to spell it out - emit a placeholder that calls it out.
        source_only = (
            "The finding cites in-tree source paths (file:line) and a runnable "
            "PoC harness; live deployment proof is not required for the "
            "claim. Triagers should review the cited code excerpts directly."
        )

    claim_preconditions = extract_claim_preconditions(text)
    if claim_preconditions:
        rc_block = "\n".join(f"- `{p}`" for p in claim_preconditions)
    else:
        # Look for an explicit Real-component precondition section.
        rc_section = extract_section(
            text, "real component precondition", "real-component precondition",
            "claim precondition", "live proof",
        )
        rc_block = rc_section or "_No real-component precondition cited; finding is source-only._"

    originality_lines = extract_originality_lines(text)
    if originality_lines:
        originality_block = "\n".join(f"- {ln}" for ln in originality_lines)
    else:
        originality_block = "_No originality citation detected; operator must paste the de-dup grep output before filing._"

    # PR #535 PR 1: Not Proven section sourced from the mapping block's
    # `not_proven_impacts:` list. The point is to publish exactly what the
    # author is NOT claiming so triagers don't need to infer scope.
    #
    # PR #541 follow-up F4 fix: the prior implementation copied every
    # ``not_proven_impacts:`` entry verbatim with no tier validation. A
    # High-claim draft listing Critical-tier rubric phrases under Not
    # Proven would publish the Critical phrases prominently, inverting
    # the contract's intent. We now classify each entry's tier via the
    # canonical rubric and prefix higher-tier impacts with a clear
    # disclaimer so triagers cannot misread the listed phrase as part of
    # the severity claim.
    pim_lib = _load_impact_mapping_lib()
    if pim_lib is not None:
        not_proven_items = pim_lib.extract_not_proven_lines(text)
        sev_implied, rubric_tiers_for_not_proven = _resolve_severity_and_rubric(
            pim_lib, draft, text, severity, workspace
        )
        not_proven_block = pim_lib.render_not_proven_section(
            not_proven_items,
            severity_implied=sev_implied,
            rubric_tiers=rubric_tiers_for_not_proven,
        )
    else:
        not_proven_items = []
        not_proven_block = (
            "_program_impact_mapping helper missing; operator must paste the "
            "Not Proven list manually before filing._"
        )

    if warnings:
        warning_block = "\n".join(f"- {w}" for w in warnings)
    else:
        warning_block = "_None (pre-submit gate clean)._"

    out_lines: List[str] = []
    out_lines.append(f"# {severity} - {title}")
    out_lines.append("")
    out_lines.append("## Program Impact Mapping")
    out_lines.append("")
    out_lines.append(pim_body.strip())
    out_lines.append("")
    out_lines.append("## Source-only Justification")
    out_lines.append("")
    out_lines.append(source_only.strip())
    out_lines.append("")
    out_lines.append("## Production Path")
    out_lines.append("")
    out_lines.append((pp_body or "").strip())
    out_lines.append("")
    out_lines.append("## Real-component Precondition")
    out_lines.append("")
    out_lines.append(rc_block.strip())
    out_lines.append("")
    out_lines.append("## Originality Reference")
    out_lines.append("")
    out_lines.append(originality_block.strip())
    out_lines.append("")
    out_lines.append("## Not Proven")
    out_lines.append("")
    out_lines.append(not_proven_block.strip())
    out_lines.append("")

    # PR 9 (wave 8): if the central outcome ledger has a back-filled
    # duplicate_of_<accepted|rejected> row that matches this draft, surface
    # it before the warning summary so the operator pasting into the triager
    # form sees the hidden-parent state up front. The block is empty when no
    # dup-root row matches - surface unconditionally (no extra branch).
    duplicate_root_block = _render_duplicate_root_block_for_draft(
        workspace, draft
    )
    if duplicate_root_block:
        out_lines.append(duplicate_root_block.strip())
        out_lines.append("")

    out_lines.append("## Warning Summary")
    out_lines.append("")
    out_lines.append(warning_block.strip())
    out_lines.append("")

    rendered = "\n".join(out_lines)
    # Deterministic: collapse trailing blank-line clusters.
    rendered = re.sub(r"\n{3,}", "\n\n", rendered).rstrip() + "\n"

    if triager_paste:
        if platform and platform.lower() != "cantina":
            refusal.append(
                f"triager-paste mode currently supports --platform cantina, got {platform!r}"
            )
        rendered, triager_reasons = _render_triager_paste(
            source_text=text,
            severity=severity,
            title=title,
            pp_body=pp_body or "",
            source_only=source_only,
        )
        refusal.extend(triager_reasons)
        if verify_commands and not POC_PASS_RE.search(rendered):
            refusal.append(
                "triager-paste --verify-commands requires observed passing proof output"
            )
        if refusal:
            return GenerationResult(
                paste_ready_path=None,
                refused=True,
                refusal_reasons=refusal,
                warnings=warnings,
            )

    if out_dir:
        target_dir = out_dir
        target_path = target_dir / draft.name
    else:
        slug = draft.parent.name if draft.name == "source-draft.md" else draft.stem
        target_dir = workspace / "submissions" / "paste_ready" / slug
        target_path = target_dir / f"{slug}.md"
    target_dir.mkdir(parents=True, exist_ok=True)
    target_path.write_text(rendered, encoding="utf-8")
    return GenerationResult(
        paste_ready_path=target_path,
        refused=False,
        refusal_reasons=[],
        warnings=warnings,
        duplicate_root_block=duplicate_root_block,
    )


# ---------------------------------------------------------------------------
# Bundle support
# ---------------------------------------------------------------------------


def resolve_bundle(bundle: Path) -> Tuple[Path, Path]:
    """Return (workspace, draft_path) for a packaged bundle directory."""
    src = bundle / "source-draft.md"
    if not src.is_file():
        raise SystemExit(f"[error] bundle missing source-draft.md: {bundle}")
    # workspace = bundle.parent.parent.parent  (.../<ws>/submissions/packaged/<slug>/)
    ws = bundle.parent.parent.parent
    return ws, src


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


def _emit_human(result: GenerationResult, draft: Path) -> int:
    if result.refused:
        sys.stderr.write(f"[refused] {draft}\n")
        for r in result.refusal_reasons:
            sys.stderr.write(f"  - {r}\n")
        return 1
    sys.stdout.write(f"[ok] paste-ready: {result.paste_ready_path}\n")
    for w in result.warnings:
        sys.stdout.write(f"  warn: {w}\n")
    return 0


def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(
        description="Generate paste-ready Immunefi text from a staging draft."
    )
    parser.add_argument("workspace", nargs="?",
                        help="Workspace root (e.g. ~/audits/<project>)")
    parser.add_argument("draft", nargs="?",
                        help="Path to the staging draft .md")
    parser.add_argument("--bundle",
                        help="Path to a packaged bundle directory (alternative to workspace+draft)")
    parser.add_argument("--all-staging", action="store_true",
                        help="Sweep every *.md under <ws>/submissions/staging/")
    parser.add_argument("--skip-pre-submit", action="store_true",
                        help="Skip pre-submit-check.sh (ONLY for tests/CI fixture mode)")
    parser.add_argument("--out-dir",
                        help="Override output directory (default: <ws>/submissions/paste_ready/<slug>/)")
    parser.add_argument("--platform", default="",
                        help="Target platform for specialized paste formatting (currently: cantina)")
    parser.add_argument("--triager-paste", action="store_true",
                        help="Emit triager-facing paste text with no local/internal artifact references")
    parser.add_argument("--verify-commands", action="store_true",
                        help="In --triager-paste mode, require observed passing PoC/test output")
    args = parser.parse_args(argv)

    if args.bundle:
        ws, draft = resolve_bundle(Path(args.bundle).expanduser().resolve())
        out_dir = Path(args.out_dir).expanduser().resolve() if args.out_dir else None
        result = generate_paste_ready(ws, draft, out_dir=out_dir,
                                      skip_pre_submit=args.skip_pre_submit,
                                      platform=args.platform,
                                      triager_paste=args.triager_paste,
                                      verify_commands=args.verify_commands)
        return _emit_human(result, draft)

    if not args.workspace:
        parser.print_help(sys.stderr)
        return 2
    workspace = Path(args.workspace).expanduser().resolve()
    out_dir = Path(args.out_dir).expanduser().resolve() if args.out_dir else None

    if args.all_staging:
        staging = workspace / "submissions" / "staging"
        if not staging.is_dir():
            sys.stderr.write(f"[error] no staging dir: {staging}\n")
            return 1
        drafts = sorted(p for p in staging.glob("*.md") if not p.name.endswith(".bak"))
        if not drafts:
            sys.stderr.write(f"[error] no staging drafts under {staging}\n")
            return 1
        rc = 0
        for d in drafts:
            r = generate_paste_ready(workspace, d, out_dir=out_dir,
                                     skip_pre_submit=args.skip_pre_submit,
                                     platform=args.platform,
                                     triager_paste=args.triager_paste,
                                     verify_commands=args.verify_commands)
            rc = max(rc, _emit_human(r, d))
        return rc

    if not args.draft:
        parser.print_help(sys.stderr)
        return 2
    draft = Path(args.draft).expanduser().resolve()
    if not draft.is_file():
        sys.stderr.write(f"[error] draft not found: {draft}\n")
        return 1
    result = generate_paste_ready(workspace, draft, out_dir=out_dir,
                                  skip_pre_submit=args.skip_pre_submit,
                                  platform=args.platform,
                                  triager_paste=args.triager_paste,
                                  verify_commands=args.verify_commands)
    return _emit_human(result, draft)


if __name__ == "__main__":
    raise SystemExit(main())
