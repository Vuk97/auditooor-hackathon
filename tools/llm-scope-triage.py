#!/usr/bin/env python3
"""llm-scope-triage.py — dual-LLM OOS / in-scope triage for finding drafts.

Background
----------
Today the OOS (out-of-scope) check happens via ``tools/extract-oos.sh``
plus a per-engagement ``OOS_CHECKLIST.md`` — pure grep, no LLM. The
PR-review pipeline (``tools/llm-pr-review.py``) reviews CODE diffs but
never looks at finding/submission scope. This tool fills that gap: it
runs Kimi + Minimax against a candidate finding draft and the engagement
context (``OOS_CHECKLIST.md`` + ``SEVERITY_CAPS.md``), parses a structured
scope/severity verdict from each, and computes consensus.

The pipeline is intentionally NOT wired into the engage loop yet — this
PR delivers the standalone tool and a smoke-run; promotion to a CI gate
follows once the calibration ledger has enough rows for ``scope-triage``
to cite real accuracy (today the disclaimer falls back to "no data").

Behaviour
---------
For each candidate finding the tool:

  1. Loads the draft markdown, the engagement's ``OOS_CHECKLIST.md`` and
     ``SEVERITY_CAPS.md``.
  2. Builds a STABLE prompt (deterministic ordering) so identical inputs
     hash to the same ``prompt_hash`` — that's the dedupe key the
     calibration ledger uses.
  3. Asks Kimi and Minimax for a structured verdict
     ``SCOPE: <tag> | SEVERITY: <tier> | CONFIDENCE: <h/m/l>`` plus a
     short rationale.
  4. Re-prompts once (per provider) when the schema didn't match.
  5. Computes consensus: HIGH (both LLMs agree on scope AND severity AND
     both report HIGH/MEDIUM-or-better confidence), MEDIUM (scope agrees
     but severity differs by one tier or one side reported LOW), or
     DISAGREED (scope tags differ).
  6. Writes a per-finding JSON artefact to ``--output-dir``.
  7. Optionally appends one ``scope-triage`` row per provider to the
     calibration ledger via ``tools/llm-calibration-log.py log``. The
     verdict written is ``INDETERMINATE`` until human verification (this
     tool intentionally does NOT mark TRUE/FALSE — that's an outcome
     measurement, not a triage call).

Subcommands
-----------
::

    llm-scope-triage.py <finding-path> --engagement <name>
    llm-scope-triage.py --batch <dir> --engagement <name>
    llm-scope-triage.py --auto-from-engage [--engage-root <path>]

Implementation notes
--------------------
- Stdlib + subprocess only. NO new pip deps.
- Reuses ``tools/llm-dispatch.py`` for transport (consent, audit trail,
  Anthropic Messages API).
- Reuses the calibration-log helper via importlib (same pattern as
  ``tools/llm-pr-review.py``).
- The engagement directory is resolved against ``--engage-root`` (default
  ``~/audits``). It must contain at minimum ``OOS_CHECKLIST.md``;
  ``SEVERITY_CAPS.md`` is optional.

Hard rules followed
-------------------
- Stdlib only (argparse, json, os, hashlib, pathlib, subprocess, sys, time, re).
- No standalone .md docs (rationale lives here + in the commit message).
- No comment-leakage in fixtures (tests use neutral synthesised drafts).
- No mutation of submissions/, no direct git/gh writes.
"""
from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import os
import pathlib
import re
import subprocess
import sys
import time
from typing import Any, Dict, Iterable, List, Optional, Tuple

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

REPO_ROOT = pathlib.Path(__file__).resolve().parents[1]
LLM_DISPATCH = REPO_ROOT / "tools" / "llm-dispatch.py"
CALIBRATION_TOOL = REPO_ROOT / "tools" / "llm-calibration-log.py"

DEFAULT_ENGAGE_ROOT = pathlib.Path.home() / "audits"

SEVERITY_TIERS = ("Critical", "High", "Medium", "Low", "Informational")

# Scope tag is either IN_SCOPE or OOS_<KEY>_<N> where KEY is a short
# uppercase token derived from the engagement name (KI for Kiln, MO for
# Morpho, PO for Polymarket, etc.) and N is the OOS-N bullet number.
# We accept any IN_SCOPE/OOS_*_N tag here — the prompt steers the model
# to the right vocabulary by listing the engagement's bullets verbatim.
SCOPE_RE = re.compile(
    r"\bSCOPE\s*[:=]\s*(IN[_-]SCOPE|OOS[_-][A-Z]{1,8}[_-]\d+)\b",
    re.IGNORECASE,
)
SEVERITY_RE = re.compile(
    r"\bSEVERITY\s*[:=]\s*(Critical|High|Medium|Low|Informational)\b",
    re.IGNORECASE,
)
CONFIDENCE_RE = re.compile(
    r"\bCONFIDENCE\s*[:=]\s*(HIGH|MEDIUM|LOW)\b",
    re.IGNORECASE,
)

# V4 Phase P1 (Workstream A3): structured production-path verdict block.
# The LLM is asked to emit a fenced ```json block named PRODUCTION_PATH after
# the legacy four lines. The block is OPTIONAL (older drafts/responses still
# parse), but when present we capture the structured verdict for the
# calibration ledger and downstream telemetry. Per V4 §2 A3 the LLM verdict
# stays ADVISORY until calibration has 20 verified production-path verdicts
# at <10% false-block rate — see ``compute_production_path_consensus``.
PRODUCTION_PATH_FENCE_RE = re.compile(
    r"```\s*json\s*(?:\bPRODUCTION_PATH\b)?\s*\n(?P<body>.*?)\n```",
    re.IGNORECASE | re.DOTALL,
)
# Fallback: a bare PRODUCTION_PATH: { ... } object on one or more lines.
PRODUCTION_PATH_INLINE_RE = re.compile(
    r"\bPRODUCTION_PATH\s*[:=]\s*(?P<body>\{.*?\})",
    re.IGNORECASE | re.DOTALL,
)

# Allowed values for the four enum fields. Used by the parser to clamp the
# LLM's free-text into the V4 schema vocabulary.
PRODUCTION_PATH_VERDICTS = {"PROVEN", "PARTIAL", "MISSING", "CONTRADICTED"}
SCOPE_VERDICTS = {"IN_SCOPE", "OOS", "UNCLEAR"}
SEVERITY_VERDICTS = {"SUPPORTED", "OVERCLAIMED", "UNDERCLAIMED", "UNCLEAR"}
MOCK_CONTAMINATION_VERDICTS = {"NONE", "DISCLOSED", "UNDISCLOSED"}

MAX_DRAFT_CHARS = 30_000  # finding drafts rarely exceed this, but guard.
MAX_OOS_CHARS = 8_000
MAX_CAPS_CHARS = 4_000

TRIAGE_PROMPT_TEMPLATE = """You are triaging a smart-contract audit finding draft against a
specific engagement's out-of-scope checklist and severity caps. Reply in
EXACTLY this format — first the four key:value lines, then the
PRODUCTION_PATH JSON block:

    SCOPE: <IN_SCOPE | OOS_<KEY>_<N>>
    SEVERITY: <Critical | High | Medium | Low | Informational>
    CONFIDENCE: <HIGH | MEDIUM | LOW>
    RATIONALE: <2-6 sentences justifying the verdict, citing the OOS bullet
                number when applicable and the part of the draft that drives
                the severity tier>

    ```json PRODUCTION_PATH
    {{
      "production_path_verdict": "PROVEN|PARTIAL|MISSING|CONTRADICTED",
      "scope_verdict": "IN_SCOPE|OOS|UNCLEAR",
      "severity_verdict": "SUPPORTED|OVERCLAIMED|UNDERCLAIMED|UNCLEAR",
      "mock_contamination": "NONE|DISCLOSED|UNDISCLOSED",
      "blocking_quotes": ["quoted prose from draft that drives the verdict"],
      "required_fix": "<one-sentence fix the author should make to ship>"
    }}
    ```

Tag semantics:
  IN_SCOPE          - The finding does NOT match any OOS bullet.
  OOS_<KEY>_<N>     - The finding semantically matches OOS-<N> from the
                      engagement's checklist. <KEY> is the engagement
                      shortcode given below; <N> is the bullet number.

Confidence semantics:
  HIGH    - You are >90% sure of both scope and severity.
  MEDIUM  - You are confident on scope but less so on severity tier
            (or vice versa).
  LOW     - The draft is ambiguous, or the OOS checklist is silent on
            the relevant area, or the engagement context is too thin.

Production-path verdict semantics (V4 §2 A3 — ADVISORY, not hard-blocking
until calibration matures):
  PROVEN        - Draft proves an in-scope production code path: an in-scope
                  asset, reachable function, attacker-controlled trigger,
                  no mock-bypass shortcut, OOS clauses checked.
  PARTIAL       - Some elements proven, others missing or weakly cited.
  MISSING       - Draft does not prove a production path (no `## Production
                  Path` section, or section missing critical items).
  CONTRADICTED  - Draft contradicts the engagement's scope/OOS rules
                  (e.g. claims forged-proof Critical when the program
                  explicitly downgrades invalid-proof assumptions).

mock_contamination semantics:
  NONE         - No suspicious mocks in PoC, OR mocks are deployment
                 conveniences only (MockERC20, MockSystemConfig).
  DISCLOSED    - Draft uses a verifier/oracle/portal/etc. mock AND
                 explicitly states the real-component replacement and the
                 residual severity if the real component blocks the path.
  UNDISCLOSED  - Draft uses a suspicious mock without disclosing the
                 real-component replacement (this is the FN-5 anti-pattern).

Engagement: {engagement}
Engagement key: {key}

OOS_CHECKLIST.md (truncated to {max_oos_chars} chars):
---
{oos}
---

SEVERITY_CAPS.md (truncated to {max_caps_chars} chars):
---
{caps}
---

Finding draft (path: {draft_path}, truncated to {max_draft_chars} chars):
---
{draft}
---

Reply with the four required lines AND the PRODUCTION_PATH JSON block.
Do not add other prose.
"""

CALIBRATION_DISCLAIMER_FALLBACK = (
    "Calibration ledger has no rows yet for kimi/minimax scope-triage. "
    "**Verify before adopting** — neither model alone is authoritative. "
    "Dual-agreement is a high-confidence signal; disagreement is a Claude "
    "triage signal."
)


# ---------------------------------------------------------------------------
# Calibration helper (same import pattern as llm-pr-review.py)
# ---------------------------------------------------------------------------

def _load_calibration_module():
    """Import ``tools/llm-calibration-log.py`` as a module via importlib.

    The file uses a hyphenated name, which is not importable via the
    normal ``import`` statement. Cached on ``sys.modules``. Returns
    ``None`` if the tool is missing — caller falls back to the static
    disclaimer.
    """
    cache_key = "_llm_scope_triage_calibration_log"
    if cache_key in sys.modules:
        return sys.modules[cache_key]
    if not CALIBRATION_TOOL.is_file():
        return None
    try:
        spec = importlib.util.spec_from_file_location(
            cache_key, CALIBRATION_TOOL
        )
        if spec is None or spec.loader is None:
            return None
        module = importlib.util.module_from_spec(spec)
        sys.modules[cache_key] = module
        spec.loader.exec_module(module)
        return module
    except Exception:
        return None


def build_calibration_disclaimer() -> str:
    """1-line calibration string for both providers on scope-triage."""
    cal = _load_calibration_module()
    if cal is None:
        return CALIBRATION_DISCLAIMER_FALLBACK
    fb_kimi = "kimi scope-triage accuracy: (no data)"
    fb_minimax = "minimax scope-triage accuracy: (no data)"
    kimi_line = cal.cite_calibration("kimi", "scope-triage", fallback=fb_kimi)
    minimax_line = cal.cite_calibration(
        "minimax", "scope-triage", fallback=fb_minimax
    )
    return (
        f"Calibration (live): {kimi_line}; {minimax_line}. "
        "Verify before adopting; neither LLM alone is authoritative."
    )


# ---------------------------------------------------------------------------
# Provider plumbing (mirror llm-pr-review.py)
# ---------------------------------------------------------------------------

def _settings_minimax_token() -> Optional[str]:
    """Pull ``ANTHROPIC_AUTH_TOKEN`` from ``~/.claude/settings.json``."""
    path = pathlib.Path.home() / ".claude" / "settings.json"
    if not path.is_file():
        return None
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None
    env = data.get("env") or {}
    token = env.get("ANTHROPIC_AUTH_TOKEN")
    return token if isinstance(token, str) and token else None


def _build_provider_env(provider: str) -> Dict[str, str]:
    env = dict(os.environ)
    env["AUDITOOOR_LLM_NETWORK_CONSENT"] = env.get(
        "AUDITOOOR_LLM_NETWORK_CONSENT", "1"
    )
    if provider == "minimax" and not env.get("MINIMAX_API_KEY"):
        token = _settings_minimax_token()
        if token:
            env["MINIMAX_API_KEY"] = token
    return env


def _invoke_llm_dispatch(
    provider: str,
    prompt_text: str,
    *,
    max_tokens: int,
    timeout: float,
) -> Tuple[int, str, str]:
    """Run ``tools/llm-dispatch.py`` for a single provider."""
    tmp = pathlib.Path(
        "/tmp/llm-scope-triage-prompt-"
        + hashlib.sha256(prompt_text.encode()).hexdigest()[:16]
    )
    tmp.write_text(prompt_text, encoding="utf-8")
    cmd = [
        sys.executable,
        str(LLM_DISPATCH),
        "--prompt-file", str(tmp),
        "--provider", provider,
        "--max-tokens", str(max_tokens),
        "--timeout", str(timeout),
    ]
    try:
        proc = subprocess.run(
            cmd,
            env=_build_provider_env(provider),
            capture_output=True,
            text=True,
            timeout=timeout + 30,
        )
        return proc.returncode, proc.stdout, proc.stderr
    except subprocess.TimeoutExpired as e:
        return 124, "", f"subprocess-timeout: {e}"
    finally:
        try:
            tmp.unlink()
        except OSError:
            pass


def kimi_triage(
    prompt: str, *, max_tokens: int = 600, timeout: float = 60.0
) -> str:
    rc, out, err = _invoke_llm_dispatch(
        "kimi", prompt, max_tokens=max_tokens, timeout=timeout
    )
    if rc != 0:
        raise RuntimeError(f"kimi-dispatch-failed (rc={rc}): {err.strip()[:300]}")
    return out.strip()


def minimax_triage(
    prompt: str, *, max_tokens: int = 600, timeout: float = 60.0
) -> str:
    rc, out, err = _invoke_llm_dispatch(
        "minimax", prompt, max_tokens=max_tokens, timeout=timeout
    )
    if rc != 0:
        raise RuntimeError(f"minimax-dispatch-failed (rc={rc}): {err.strip()[:300]}")
    return out.strip()


# ---------------------------------------------------------------------------
# Engagement / draft loaders
# ---------------------------------------------------------------------------

def engagement_key(name: str) -> str:
    """Short uppercase shortcode for an engagement name.

    Used as the ``<KEY>`` segment in ``OOS_<KEY>_<N>`` tags. Stable: same
    name -> same key. Implementation: take the first letter of every
    ``[A-Za-z]+`` token in the name, uppercase, max 8 chars; if that
    yields fewer than 2 chars, fall back to the first 2 letters.
    """
    name = name.strip()
    if not name:
        return "X"
    tokens = re.findall(r"[A-Za-z]+", name)
    initials = "".join(t[0] for t in tokens).upper()
    if len(initials) >= 2:
        return initials[:8]
    # Fallback: first two letters of first alphabetic run, uppercase.
    first = tokens[0] if tokens else name
    return (first[:2] or "X").upper()


def load_engagement_context(
    engagement: str,
    *,
    engage_root: pathlib.Path,
) -> Dict[str, str]:
    """Load OOS_CHECKLIST.md and (optional) SEVERITY_CAPS.md for an engagement.

    Returns a dict with keys ``oos``, ``caps``, ``engagement_dir``.
    Raises ``FileNotFoundError`` when the engagement directory or
    ``OOS_CHECKLIST.md`` is missing.
    """
    eng_dir = engage_root / engagement
    if not eng_dir.is_dir():
        raise FileNotFoundError(f"engagement directory not found: {eng_dir}")
    oos_path = eng_dir / "OOS_CHECKLIST.md"
    if not oos_path.is_file():
        raise FileNotFoundError(f"missing OOS_CHECKLIST.md in {eng_dir}")
    caps_path = eng_dir / "SEVERITY_CAPS.md"
    oos_text = oos_path.read_text(encoding="utf-8")
    caps_text = (
        caps_path.read_text(encoding="utf-8")
        if caps_path.is_file()
        else "(no SEVERITY_CAPS.md present)"
    )
    return {
        "oos": oos_text[:MAX_OOS_CHARS],
        "caps": caps_text[:MAX_CAPS_CHARS],
        "engagement_dir": str(eng_dir),
    }


def load_draft(path: pathlib.Path) -> str:
    """Load a finding-draft markdown file (truncated to MAX_DRAFT_CHARS)."""
    if not path.is_file():
        raise FileNotFoundError(f"draft not found: {path}")
    return path.read_text(encoding="utf-8")[:MAX_DRAFT_CHARS]


# ---------------------------------------------------------------------------
# Prompt construction & verdict parsing
# ---------------------------------------------------------------------------

def build_prompt(
    *,
    engagement: str,
    draft_path: str,
    draft_text: str,
    oos_text: str,
    caps_text: str,
) -> str:
    """Build the triage prompt deterministically.

    The output is byte-stable for identical inputs so the SHA-256 of the
    prompt is a usable dedupe key for the calibration ledger.
    """
    return TRIAGE_PROMPT_TEMPLATE.format(
        engagement=engagement,
        key=engagement_key(engagement),
        oos=oos_text,
        caps=caps_text,
        draft_path=draft_path,
        draft=draft_text,
        max_oos_chars=MAX_OOS_CHARS,
        max_caps_chars=MAX_CAPS_CHARS,
        max_draft_chars=MAX_DRAFT_CHARS,
    )


def _clamp_enum(value: Optional[str], allowed: set, default: str = "UNCLEAR") -> str:
    """Force ``value`` into ``allowed`` (uppercase comparison), else ``default``.

    Used by the production-path block parser so a model that emits
    ``"proven"`` or ``"forged-proof contradicted"`` still lands on a
    canonical V4 verdict tag without crashing the calibration ledger.
    """
    if not value:
        return default
    upper = str(value).strip().upper()
    if upper in allowed:
        return upper
    # Tolerant prefix match: "PROVEN: ..." -> "PROVEN".
    for tag in allowed:
        if upper.startswith(tag):
            return tag
    return default


def _parse_production_path_block(text: str) -> Optional[Dict[str, Any]]:
    """Extract the PRODUCTION_PATH JSON block from an LLM response.

    Tries the fenced ``\\`\\`\\`json PRODUCTION_PATH`` form first, then the
    bare ``PRODUCTION_PATH: { ... }`` inline form. Returns a dict with
    canonical V4 §2 A3 keys clamped to the allowed enum vocabulary, or
    ``None`` when no block is present / parseable.

    The block is OPTIONAL — a response that only emits the legacy four
    lines still parses cleanly via ``parse_triage_verdict``.
    """
    if not text:
        return None
    body: Optional[str] = None
    fence = PRODUCTION_PATH_FENCE_RE.search(text)
    if fence:
        body = fence.group("body")
    else:
        inline = PRODUCTION_PATH_INLINE_RE.search(text)
        if inline:
            body = inline.group("body")
    if not body:
        return None
    body = body.strip()
    try:
        raw = json.loads(body)
    except (ValueError, json.JSONDecodeError):
        # Sometimes models wrap with single quotes or trailing commas.
        # Apply a permissive cleanup before giving up.
        cleaned = re.sub(r",\s*([\}\]])", r"\1", body)
        cleaned = cleaned.replace("'", '"')
        try:
            raw = json.loads(cleaned)
        except (ValueError, json.JSONDecodeError):
            return None
    if not isinstance(raw, dict):
        return None
    blocking = raw.get("blocking_quotes") or []
    if not isinstance(blocking, list):
        blocking = [str(blocking)]
    blocking = [str(item).strip() for item in blocking if str(item).strip()]
    return {
        "production_path_verdict": _clamp_enum(
            raw.get("production_path_verdict"),
            PRODUCTION_PATH_VERDICTS,
            default="UNCLEAR" if "UNCLEAR" in PRODUCTION_PATH_VERDICTS else "MISSING",
        ),
        "scope_verdict": _clamp_enum(
            raw.get("scope_verdict"), SCOPE_VERDICTS, default="UNCLEAR"
        ),
        "severity_verdict": _clamp_enum(
            raw.get("severity_verdict"), SEVERITY_VERDICTS, default="UNCLEAR"
        ),
        "mock_contamination": _clamp_enum(
            raw.get("mock_contamination"),
            MOCK_CONTAMINATION_VERDICTS,
            default="NONE",
        ),
        "blocking_quotes": blocking,
        "required_fix": str(raw.get("required_fix") or "").strip(),
    }


def parse_triage_verdict(text: str) -> Dict[str, Optional[str]]:
    """Parse SCOPE/SEVERITY/CONFIDENCE/RATIONALE plus the optional
    PRODUCTION_PATH JSON block from an LLM response.

    Missing fields come back as ``None``. Scope is normalised to
    ``IN_SCOPE`` (canonical underscore form) or ``OOS_<KEY>_<N>``.
    Severity is title-cased; confidence is upper-cased. The
    ``production_path`` key is a dict (when the V4 block parsed) or
    ``None`` (when the LLM omitted the block — backwards-compatible
    with calibration ledger rows from before this PR).
    """
    out: Dict[str, Optional[str]] = {
        "scope": None,
        "severity": None,
        "confidence": None,
        "rationale": None,
        "production_path": None,
    }
    if not text:
        return out
    m = SCOPE_RE.search(text)
    if m:
        raw = m.group(1).upper().replace("-", "_")
        out["scope"] = raw
    m = SEVERITY_RE.search(text)
    if m:
        out["severity"] = m.group(1).title()
    m = CONFIDENCE_RE.search(text)
    if m:
        out["confidence"] = m.group(1).upper()
    # Rationale = whatever follows "RATIONALE:" up to the next blank
    # line / fenced block / end-of-text. Capturing to end-of-text would
    # swallow the JSON block; so we stop at the first ``` fence.
    rm = re.search(
        r"\bRATIONALE\s*[:=]\s*(.+?)(?=\n\s*```|$)",
        text,
        re.IGNORECASE | re.DOTALL,
    )
    if rm:
        out["rationale"] = rm.group(1).strip()
    out["production_path"] = _parse_production_path_block(text)
    return out


def compute_production_path_consensus(
    kimi: Optional[Dict[str, Any]],
    minimax: Optional[Dict[str, Any]],
) -> Dict[str, Any]:
    """Compute a consensus dict for the production-path verdict.

    V4 §2 A3 explicit: this verdict stays ADVISORY. The function returns
    the dual-LLM agreement view; downstream code (engage.py) is expected
    to surface it as a SUCCESS_WARN row, not a hard block. Hard-block
    promotion happens only after calibration has 20 verified
    production-path verdicts at <10% false-block rate (V4 §2 A3 + §9).

    Output schema:
        {
          "advisory": True,                     # always — never hard-block
          "production_path_verdict": <enum>,    # majority OR "DISAGREED"
          "mock_contamination": <enum>,         # majority OR "DISAGREED"
          "scope_verdict": <enum>,
          "severity_verdict": <enum>,
          "agreement": "BOTH" | "ONE_SIDE" | "DISAGREED" | "ABSENT",
          "blocking_quotes": [...],             # union of both sides
        }
    """
    out: Dict[str, Any] = {
        "advisory": True,
        "production_path_verdict": "UNCLEAR",
        "mock_contamination": "NONE",
        "scope_verdict": "UNCLEAR",
        "severity_verdict": "UNCLEAR",
        "agreement": "ABSENT",
        "blocking_quotes": [],
    }
    if not kimi and not minimax:
        return out
    if kimi and not minimax:
        out.update({
            "production_path_verdict": kimi.get("production_path_verdict", "UNCLEAR"),
            "mock_contamination": kimi.get("mock_contamination", "NONE"),
            "scope_verdict": kimi.get("scope_verdict", "UNCLEAR"),
            "severity_verdict": kimi.get("severity_verdict", "UNCLEAR"),
            "agreement": "ONE_SIDE",
            "blocking_quotes": list(kimi.get("blocking_quotes") or []),
        })
        return out
    if minimax and not kimi:
        out.update({
            "production_path_verdict": minimax.get("production_path_verdict", "UNCLEAR"),
            "mock_contamination": minimax.get("mock_contamination", "NONE"),
            "scope_verdict": minimax.get("scope_verdict", "UNCLEAR"),
            "severity_verdict": minimax.get("severity_verdict", "UNCLEAR"),
            "agreement": "ONE_SIDE",
            "blocking_quotes": list(minimax.get("blocking_quotes") or []),
        })
        return out
    # Both sides present.
    fields = (
        "production_path_verdict",
        "mock_contamination",
        "scope_verdict",
        "severity_verdict",
    )
    agreed = True
    for fld in fields:
        kv = kimi.get(fld)  # type: ignore[union-attr]
        mv = minimax.get(fld)  # type: ignore[union-attr]
        if kv == mv:
            out[fld] = kv
        else:
            out[fld] = "DISAGREED"
            agreed = False
    quotes = list(kimi.get("blocking_quotes") or [])  # type: ignore[union-attr]
    for q in (minimax.get("blocking_quotes") or []):  # type: ignore[union-attr]
        if q not in quotes:
            quotes.append(q)
    out["blocking_quotes"] = quotes
    out["agreement"] = "BOTH" if agreed else "DISAGREED"
    return out


def is_oos_tag(scope: Optional[str]) -> bool:
    if not scope:
        return False
    return scope.upper().startswith("OOS_")


def compute_consensus(
    kimi: Dict[str, Optional[str]],
    minimax: Dict[str, Optional[str]],
) -> Dict[str, Optional[str]]:
    """Reduce two parsed verdicts to a consensus dict.

    Rules
    -----
    - Either side missing scope -> ``confidence=DISAGREED``,
      ``scope=None``, ``severity=None`` (the LLM-failure case).
    - Scopes disagree -> ``confidence=DISAGREED``, scope/severity
      reported as the kimi side for inspection but explicitly flagged.
    - Scopes agree:
        * Severities also agree AND both providers reported HIGH
          confidence -> ``confidence=HIGH``.
        * Severities also agree but at least one side reported MEDIUM/LOW
          confidence -> ``confidence=MEDIUM``.
        * Severities differ by one tier and both confident -> MEDIUM.
        * Severities differ by 2+ tiers OR one side reported LOW
          confidence -> ``confidence=LOW``.
    """
    if not kimi.get("scope") or not minimax.get("scope"):
        return {
            "scope": None,
            "severity": None,
            "confidence": "DISAGREED",
            "reason": "one-or-both-providers-missing-scope-tag",
        }
    k_scope = kimi["scope"]
    m_scope = minimax["scope"]
    if k_scope != m_scope:
        return {
            "scope": k_scope,  # for inspection only
            "severity": kimi.get("severity"),
            "confidence": "DISAGREED",
            "reason": f"scope-mismatch:kimi={k_scope},minimax={m_scope}",
        }
    # Scopes agree from here on.
    k_sev = kimi.get("severity")
    m_sev = minimax.get("severity")
    sev_tier_gap = _severity_gap(k_sev, m_sev)
    confs = {kimi.get("confidence"), minimax.get("confidence")}
    if "LOW" in confs:
        return {
            "scope": k_scope,
            "severity": k_sev if k_sev == m_sev else None,
            "confidence": "LOW",
            "reason": "one-or-both-providers-reported-LOW",
        }
    if k_sev == m_sev:
        if confs == {"HIGH"}:
            return {
                "scope": k_scope,
                "severity": k_sev,
                "confidence": "HIGH",
                "reason": "scope-and-severity-agreed-with-HIGH-on-both-sides",
            }
        return {
            "scope": k_scope,
            "severity": k_sev,
            "confidence": "MEDIUM",
            "reason": "scope-and-severity-agreed-but-non-HIGH-confidence",
        }
    # Severities differ.
    if sev_tier_gap == 1:
        return {
            "scope": k_scope,
            "severity": None,
            "confidence": "MEDIUM",
            "reason": (
                f"scope-agreed-but-severity-tier-off-by-one:"
                f"kimi={k_sev},minimax={m_sev}"
            ),
        }
    return {
        "scope": k_scope,
        "severity": None,
        "confidence": "LOW",
        "reason": (
            f"scope-agreed-but-severity-tier-gap={sev_tier_gap}:"
            f"kimi={k_sev},minimax={m_sev}"
        ),
    }


def _severity_gap(a: Optional[str], b: Optional[str]) -> int:
    """Distance between two severity tiers (Critical=0, ..., Informational=4).

    Returns a large number if either input is unknown.
    """
    if not a or not b:
        return 99
    try:
        ia = SEVERITY_TIERS.index(a)
        ib = SEVERITY_TIERS.index(b)
    except ValueError:
        return 99
    return abs(ia - ib)


# ---------------------------------------------------------------------------
# Per-finding pipeline
# ---------------------------------------------------------------------------

def triage_one(
    draft_path: pathlib.Path,
    *,
    engagement: str,
    engage_root: pathlib.Path,
    providers: List[str],
    max_tokens: int,
    timeout: float,
    output_dir: pathlib.Path,
    log_to_calibration: bool,
) -> Dict[str, Any]:
    record: Dict[str, Any] = {
        "finding_path": str(draft_path),
        "engagement": engagement,
        "providers": providers,
        "verdicts": {},
        "raw_outputs": {},
        "consensus": None,
        "errors": [],
    }
    try:
        ctx = load_engagement_context(engagement, engage_root=engage_root)
    except FileNotFoundError as e:
        record["errors"].append(f"engagement-load-failed: {e}")
        return record
    try:
        draft_text = load_draft(draft_path)
    except FileNotFoundError as e:
        record["errors"].append(f"draft-load-failed: {e}")
        return record
    record["draft_chars"] = len(draft_text)
    record["engagement_dir"] = ctx["engagement_dir"]

    prompt = build_prompt(
        engagement=engagement,
        draft_path=str(draft_path),
        draft_text=draft_text,
        oos_text=ctx["oos"],
        caps_text=ctx["caps"],
    )
    record["prompt_hash"] = hashlib.sha256(prompt.encode("utf-8")).hexdigest()

    runners = {"kimi": kimi_triage, "minimax": minimax_triage}
    for prov in providers:
        runner = runners.get(prov)
        if runner is None:
            record["errors"].append(f"unknown-provider: {prov}")
            record["verdicts"][prov] = None
            record["raw_outputs"][prov] = ""
            continue
        try:
            out = runner(prompt, max_tokens=max_tokens, timeout=timeout)
        except Exception as e:
            record["errors"].append(f"{prov}-failed: {e}")
            record["verdicts"][prov] = None
            record["raw_outputs"][prov] = ""
            continue
        record["raw_outputs"][prov] = out
        parsed = parse_triage_verdict(out)
        if parsed["scope"] is None:
            nudge = (
                prompt
                + "\n\nReminder: your previous reply did not match the schema. "
                "Reply with EXACTLY four lines: SCOPE, SEVERITY, CONFIDENCE, "
                "RATIONALE. No other prose."
            )
            try:
                out2 = runner(nudge, max_tokens=max_tokens, timeout=timeout)
                record["raw_outputs"][prov + "_retry"] = out2
                parsed = parse_triage_verdict(out2)
            except Exception as e:
                record["errors"].append(f"{prov}-retry-failed: {e}")
        record["verdicts"][prov] = parsed

    record["consensus"] = compute_consensus(
        record["verdicts"].get("kimi") or {},
        record["verdicts"].get("minimax") or {},
    )
    # V4 Phase P1 (Workstream A3): compute the production-path consensus
    # alongside the legacy scope/severity consensus. The verdict stays
    # ADVISORY (V4 §2 A3 explicit) — engage.py is expected to surface it as
    # SUCCESS_WARN, never as a hard block, until the calibration ledger
    # has 20 verified production-path verdicts at <10% false-block rate.
    kimi_pp = (record["verdicts"].get("kimi") or {}).get("production_path")
    minimax_pp = (record["verdicts"].get("minimax") or {}).get("production_path")
    record["production_path_consensus"] = compute_production_path_consensus(
        kimi_pp, minimax_pp
    )

    # Persist the artefact.
    output_dir.mkdir(parents=True, exist_ok=True)
    art_name = (
        f"triage-{engagement}-"
        f"{draft_path.stem}-"
        f"{record['prompt_hash'][:12]}.json"
    )
    artefact_path = output_dir / art_name
    artefact_path.write_text(
        json.dumps(record, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    record["artefact_path"] = str(artefact_path)

    if log_to_calibration:
        _log_calibration_rows(record)

    return record


def _log_calibration_rows(record: Dict[str, Any]) -> None:
    """Append one ``scope-triage`` row per provider that returned a verdict.

    The verdict written is ``INDETERMINATE`` (this tool does not know
    ground truth). ``--evidence`` includes the consensus summary so a
    human reviewer can later upgrade the row to TRUE/FALSE in place by
    logging a fresh event with the same ``prompt_hash``.

    If the consensus side reports DISAGREED, we still write
    ``INDETERMINATE`` rows but include ``DISAGREED`` in the evidence so
    aggregate stats can split it out.
    """
    consensus = record.get("consensus") or {}
    cons_label = consensus.get("confidence") or "UNKNOWN"
    cons_scope = consensus.get("scope") or "UNKNOWN"
    cons_sev = consensus.get("severity") or "UNKNOWN"
    finding_id = pathlib.Path(record["finding_path"]).stem
    task_ref = f"{record['engagement']}/{finding_id}"
    prompt_hash = record.get("prompt_hash", "")
    for prov, parsed in (record.get("verdicts") or {}).items():
        if not parsed:
            continue
        scope = parsed.get("scope") or "UNPARSED"
        severity = parsed.get("severity") or "UNPARSED"
        evidence = (
            f"scope={scope},severity={severity},"
            f"consensus={cons_label}({cons_scope}/{cons_sev})"
        )
        cmd = [
            sys.executable,
            str(CALIBRATION_TOOL),
            "log",
            prov,
            "scope-triage",
            task_ref,
            "INDETERMINATE",
            "--evidence", evidence,
            "--operator", "llm-scope-triage",
        ]
        if prompt_hash:
            cmd += ["--prompt-hash", prompt_hash]
        try:
            subprocess.run(cmd, capture_output=True, text=True, timeout=30, check=False)
        except Exception:
            # Best-effort logging — never block the triage pipeline on a
            # ledger write.
            pass


# ---------------------------------------------------------------------------
# Batch / auto-from-engage drivers
# ---------------------------------------------------------------------------

def list_drafts(directory: pathlib.Path) -> List[pathlib.Path]:
    """Return every ``*.md`` under ``directory`` (non-recursive)."""
    if not directory.is_dir():
        return []
    return sorted(p for p in directory.iterdir() if p.is_file() and p.suffix == ".md")


def discover_engagements(engage_root: pathlib.Path) -> List[str]:
    """Return engagement names under ``engage_root`` that have an OOS_CHECKLIST.md."""
    if not engage_root.is_dir():
        return []
    out = []
    for child in sorted(engage_root.iterdir()):
        if not child.is_dir():
            continue
        if (child / "OOS_CHECKLIST.md").is_file():
            out.append(child.name)
    return out


def discover_draft_dirs(engage_root: pathlib.Path, engagement: str) -> List[pathlib.Path]:
    """Return likely draft directories for one engagement.

    Searched in order: ``submissions/drafts``, ``drafts``,
    ``agent_outputs``. Only directories that exist are returned.
    """
    base = engage_root / engagement
    candidates = [
        base / "submissions" / "drafts",
        base / "drafts",
        base / "agent_outputs",
    ]
    return [c for c in candidates if c.is_dir()]


# ---------------------------------------------------------------------------
# Telemetry
# ---------------------------------------------------------------------------

def summarise(records: Iterable[Dict[str, Any]]) -> Dict[str, int]:
    tally = {
        "triaged": 0,
        "high": 0,
        "medium": 0,
        "low": 0,
        "disagreed": 0,
        "errors": 0,
    }
    for r in records:
        tally["triaged"] += 1
        c = (r.get("consensus") or {}).get("confidence")
        if c == "HIGH":
            tally["high"] += 1
        elif c == "MEDIUM":
            tally["medium"] += 1
        elif c == "LOW":
            tally["low"] += 1
        elif c == "DISAGREED":
            tally["disagreed"] += 1
        if r.get("errors"):
            tally["errors"] += 1
    return tally


def print_summary(tally: Dict[str, int]) -> None:
    sys.stdout.write(
        "\n=== llm-scope-triage summary ===\n"
        f"{tally['triaged']} drafts triaged: "
        f"{tally['high']} HIGH, {tally['medium']} MEDIUM, "
        f"{tally['low']} LOW, {tally['disagreed']} DISAGREED, "
        f"{tally['errors']} with errors.\n"
    )
    sys.stdout.flush()


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def _parse_providers(s: str) -> List[str]:
    out = []
    for p in (x.strip().lower() for x in s.split(",")):
        if not p:
            continue
        if p not in ("kimi", "minimax"):
            raise argparse.ArgumentTypeError(f"unknown provider: {p}")
        out.append(p)
    if not out:
        raise argparse.ArgumentTypeError("must specify at least one provider")
    return out


def build_arg_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="llm-scope-triage.py",
        description=(
            "Dual-LLM OOS / in-scope triage for finding drafts. Reuses "
            "tools/llm-dispatch.py (Kimi+Minimax) and writes per-finding "
            "JSON artefacts. Optionally appends scope-triage rows to the "
            "calibration ledger."
        ),
    )
    target = p.add_mutually_exclusive_group(required=True)
    target.add_argument("finding", nargs="?", type=pathlib.Path,
                        help="Path to a single finding-draft markdown file.")
    target.add_argument("--batch", type=pathlib.Path, metavar="DIR",
                        help="Triage every .md in DIR.")
    target.add_argument("--auto-from-engage", action="store_true",
                        help="Walk every engagement under --engage-root.")
    p.add_argument("--engagement", default=None,
                   help="Engagement name (required for single + --batch).")
    p.add_argument("--engage-root", type=pathlib.Path, default=DEFAULT_ENGAGE_ROOT,
                   help=f"Engagement root (default: {DEFAULT_ENGAGE_ROOT}).")
    p.add_argument("--providers", type=_parse_providers,
                   default=["kimi", "minimax"],
                   help="Comma-separated providers (default: kimi,minimax).")
    p.add_argument("--max-tokens", type=int, default=600,
                   help="Per-LLM max_tokens (default: 600).")
    p.add_argument("--timeout", type=float, default=60.0,
                   help="Per-LLM call timeout in seconds (default: 60).")
    p.add_argument("--output-dir", type=pathlib.Path,
                   default=pathlib.Path("/tmp/llm-scope-triage"),
                   help="Per-finding artefact directory (default: /tmp/llm-scope-triage/).")
    p.add_argument("--log-to-calibration", action="store_true", default=True,
                   help="(default) Append INDETERMINATE rows to the calibration ledger.")
    p.add_argument("--no-log-to-calibration", action="store_true",
                   help="Skip ledger writes (artefact-only mode).")
    return p


def main(argv: Optional[List[str]] = None) -> int:
    args = build_arg_parser().parse_args(argv)
    log_to_calibration = (
        args.log_to_calibration and not args.no_log_to_calibration
    )

    pairs: List[Tuple[pathlib.Path, str]] = []
    if args.finding is not None:
        if not args.engagement:
            sys.stderr.write("--engagement is required when triaging a single finding\n")
            return 2
        pairs.append((args.finding, args.engagement))
    elif args.batch is not None:
        if not args.engagement:
            sys.stderr.write("--engagement is required with --batch\n")
            return 2
        for d in list_drafts(args.batch):
            pairs.append((d, args.engagement))
    elif args.auto_from_engage:
        for eng in discover_engagements(args.engage_root):
            for ddir in discover_draft_dirs(args.engage_root, eng):
                for d in list_drafts(ddir):
                    pairs.append((d, eng))

    if not pairs:
        sys.stdout.write("no drafts to triage\n")
        return 0

    records: List[Dict[str, Any]] = []
    for draft, eng in pairs:
        sys.stdout.write(f"[llm-scope-triage] {eng} :: {draft} ...\n")
        sys.stdout.flush()
        rec = triage_one(
            draft,
            engagement=eng,
            engage_root=args.engage_root,
            providers=args.providers,
            max_tokens=args.max_tokens,
            timeout=args.timeout,
            output_dir=args.output_dir,
            log_to_calibration=log_to_calibration,
        )
        records.append(rec)
        c = (rec.get("consensus") or {}).get("confidence")
        s = (rec.get("consensus") or {}).get("scope")
        sv = (rec.get("consensus") or {}).get("severity")
        sys.stdout.write(
            f"  -> consensus={c} scope={s} severity={sv}  "
            f"artefact={rec.get('artefact_path')}\n"
        )
        if rec.get("errors"):
            for e in rec["errors"]:
                sys.stdout.write(f"     ! {e}\n")
        sys.stdout.flush()

    tally = summarise(records)
    print_summary(tally)
    sys.stdout.write(build_calibration_disclaimer() + "\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())
