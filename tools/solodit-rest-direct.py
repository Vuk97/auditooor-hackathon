#!/usr/bin/env python3
"""solodit-rest-direct.py - Wave-3 direct-REST Solodit ingest bypass.

The Solodit MCP wrapper `@marchev/claudit` v0.1.19 has 6 documented defects
(commit 480ffff66f) and the cursor has been stuck at id=65673 since
2026-05-10. This tool bypasses the MCP wrapper and talks to the upstream
Cyfrin REST API directly:

    POST https://solodit.cyfrin.io/api/v1/solodit/findings
    Header X-Cyfrin-API-Key: $SOLODIT_API_KEY
    Body   {"page": N, "pageSize": M, "filters": {...}}

For each finding past --cursor-id, this tool emits a YAML record at
<out-dir>/solodit-finding-<id>.yaml that conforms to schema
auditooor.hackerman_record.v1.1 (the v1 schema plus 5 provenance fields:
verification_tier, record_source_url, cve_id, ghsa_id, record_extensions).

verification_tier is set to tier-2-verified-public-archive because every
record sources from solodit.cyfrin.io (public, stable URL, no
hand-verification step before ingestion).

DESIGN INVARIANTS (honest verdict protocol):
    1. If SOLODIT_API_KEY is missing the tool emits a NEGATIVE verdict
       and exits 0 (not a synthetic-fixture run - just a no-op).
    2. The cursor file is NEVER mutated unless at least one real finding
       was ingested successfully. Dry-run or API-error paths leave it
       untouched.
    3. Synthetic fixtures used by tests carry `synthetic_fixture: true`
       inside record_extensions.

USAGE
    # Live run (requires SOLODIT_API_KEY in env)
    python3 tools/solodit-rest-direct.py \\
        --out-dir /private/tmp/solodit-direct \\
        --min-severity HIGH --page-size 100 --max-pages 10

    # Dry-run with synthetic fixture (no network)
    python3 tools/solodit-rest-direct.py \\
        --out-dir /private/tmp/solodit-direct \\
        --dry-run --inject-json /tmp/fixture.json

    # JSON-only verdict (no YAML emission)
    python3 tools/solodit-rest-direct.py --json-only --dry-run \\
        --inject-json /tmp/fixture.json
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import sys
import time
import urllib.error
import urllib.request
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

TOOL_VERSION = "wave3-1.0.0"
TOOL_NAME = "solodit-rest-direct"

SCHEMA_VERSION = "auditooor.hackerman_record.v1.1"
VERIFICATION_TIER = "tier-2-verified-public-archive"

REPO_ROOT = Path(__file__).resolve().parent.parent
DEFAULT_CURSOR_FILE = REPO_ROOT / "reference" / "solodit_ingest_cursor.json"

# R36 lane: solodit-rate-limit-tighten-2026-05-26 (registered via
# tools/agent-pathspec-register.py; rebuttal marker N/A - declared pathspec
# scoped to this file + docs/MCP_ENV_SHELL_EXPORT_CHECKLIST.md).
# <!-- r36-rebuttal: solodit-rate-limit-tighten-2026-05-26 lane; registered pathspec covers tools/solodit-rest-direct.py + docs/MCP_ENV_SHELL_EXPORT_CHECKLIST.md only -->

API_BASE = "https://solodit.cyfrin.io/api/v1/solodit"
API_ENDPOINT_FINDINGS = f"{API_BASE}/findings"

# Upstream API enum (verified 2026-05-16 via direct probe): HIGH, MEDIUM, LOW, GAS.
# The API does NOT accept "CRITICAL" - critical findings are tagged HIGH upstream.
# This is one of the MCP-wrapper-papered-over surprises that motivated direct REST.
API_VALID_IMPACT_VALUES = {"HIGH", "MEDIUM", "LOW", "GAS"}
VALID_SEVERITIES = {"HIGH", "CRITICAL", "MEDIUM"}

# Cyfrin Solodit REST upstream rate limit (operator-confirmed 2026-05-26 during
# the SOLODIT_API_KEY rotation - verbatim: "Rate Limit / 20/min (60s window)").
# The upstream X-RateLimit-Remaining / X-RateLimit-Reset headers carry the live
# state and the client reacts when remaining<=1, but we also need a proactive
# floor to avoid bursting into the limit. 60.0 / 20 = 3.0s is the precise
# ceiling; we add a 0.1s safety margin so wall-clock drift does not put us
# above the limit. Callers that need a faster cadence (e.g. unit tests with
# stubbed urlopen) can pass min_request_interval_seconds=0 explicitly.
RATE_LIMIT_REQ_PER_MIN = 20
RATE_LIMIT_WINDOW_SECONDS = 60.0
RATE_LIMIT_MIN_INTERVAL_SECONDS = round(RATE_LIMIT_WINDOW_SECONDS / RATE_LIMIT_REQ_PER_MIN + 0.1, 2)  # 3.1

VALID_TARGET_LANGUAGES = {
    "solidity",
    "go",
    "rust",
    "vyper",
    "move",
    "cairo",
    "huff",
    "assembly",
    "typescript-onchain",
    "python-onchain",
    "circom",
    "sway",
    "noir",
    "leo",
    "cairo-zk",
}

API_VERIFIED_LANGUAGE_VALUES = {
    "solidity": "Solidity",
    "go": "Go",
    "rust": "Rust",
    "vyper": "Vyper",
    "move": "Move",
    "cairo": "Cairo",
    "typescript-onchain": "TypeScript",
    "python-onchain": "Python",
    "circom": "Circom",
    "sway": "Sway",
    "noir": "Noir",
    # Solodit indexes EVM assembly-family findings under "Yul"; keep the
    # corpus-facing target language as "assembly" and only translate at the
    # API boundary.
    "assembly": "Yul",
}

SOLODIT_LANGUAGE_ENUM_BLOCKER_ID = "BLK-V3-SOURCE-SOLODIT-LANGUAGE-ENUM-PROOF"

SOLODIT_ADDITIONAL_LANGUAGE_BACKLOG = (
    "huff",
    "assembly",
    "leo",
    "cairo-zk",
)

SOLODIT_LANGUAGE_ENUM_PROOF_REQUIREMENT = (
    "checked-in Solodit API enum source evidence or operator-approved positive live probe evidence"
)


def _normalize_impact_for_api(severity: str) -> str:
    """Map our user-facing severity to the upstream API's impact enum.

    Upstream accepts {HIGH, MEDIUM, LOW, GAS} only. We map CRITICAL -> HIGH
    because critical-tier findings are tagged HIGH upstream (verified
    2026-05-16 by probing the API). Callers wanting a true critical filter
    should post-filter by parsing the title prefix (e.g. [C-XX]).
    """
    s = (severity or "HIGH").upper()
    if s == "CRITICAL":
        return "HIGH"
    if s in API_VALID_IMPACT_VALUES:
        return s
    return "HIGH"

# Keyword filter field-name variants to A/B test which the upstream API accepts.
# The MCP wrapper's defects include silently ignoring filter fields, so the
# direct path tries several plausible spellings and records which one returned
# the smallest result-set (= most filter-effective).
KEYWORD_FIELD_VARIANTS = ("keyword", "keywords", "search", "q", "query", "text")


def _parse_language_filter(value: Optional[str]) -> List[str]:
    """Parse a comma-separated target_language filter into schema enum values."""
    if not value:
        return []
    out: List[str] = []
    for part in re.split(r"[, ]+", value):
        lang = part.strip().lower()
        if not lang:
            continue
        if lang == "golang":
            lang = "go"
        if lang == "typescript":
            lang = "typescript-onchain"
        if lang == "python":
            lang = "python-onchain"
        if lang not in VALID_TARGET_LANGUAGES:
            raise ValueError(f"unsupported target language: {part!r}")
        if lang not in out:
            out.append(lang)
    return out


def _api_language_filters(languages: List[str]) -> List[Dict[str, str]]:
    unsupported = [lang for lang in languages if lang not in API_VERIFIED_LANGUAGE_VALUES]
    if unsupported:
        raise ValueError(
            "Solodit API language filter has no checked-in source evidence for: "
            + ", ".join(unsupported)
        )
    return [{"value": API_VERIFIED_LANGUAGE_VALUES[lang]} for lang in languages]


def _language_filter_support(languages: List[str]) -> Dict[str, Any]:
    safe = [lang for lang in languages if lang in API_VERIFIED_LANGUAGE_VALUES]
    unsupported = [lang for lang in languages if lang not in API_VERIFIED_LANGUAGE_VALUES]
    return {
        "safe_api_filter_languages": safe,
        "unsupported_api_filter_languages": unsupported,
        "safe_for_live_api": not unsupported,
        "source_evidence": "checked-in Solodit cursor registry, live enum probes, and existing REST tests",
    }


def _language_blocker_resolution(support: Dict[str, Any]) -> Dict[str, Any]:
    residual = list(support["unsupported_api_filter_languages"])
    safe = list(support["safe_api_filter_languages"])
    return {
        "blocker_id": SOLODIT_LANGUAGE_ENUM_BLOCKER_ID,
        "requested_scope_can_close": not residual,
        "requested_scope_can_narrow": bool(safe) or bool(residual),
        "safe_api_filter_languages": safe,
        "remaining_external_state_required": residual,
        "remaining_evidence_requirement": SOLODIT_LANGUAGE_ENUM_PROOF_REQUIREMENT,
        "boundary": (
            "Zero-result language probes do not prove an enum value: checked-in "
            "control probes show arbitrary strings can return HTTP 200 with zero "
            "results. A residual language becomes safe only after source evidence "
            "or a positive live probe returns distinguishable matching findings."
        ),
    }


def build_language_planning_manifest(languages: Optional[List[str]] = None) -> Dict[str, Any]:
    requested = languages or list(SOLODIT_ADDITIONAL_LANGUAGE_BACKLOG)
    support = _language_filter_support(requested)
    rows = []
    for lang in requested:
        if lang in API_VERIFIED_LANGUAGE_VALUES:
            rows.append(
                {
                    "target_language": lang,
                    "api_filter_supported": True,
                    "api_filter_value": API_VERIFIED_LANGUAGE_VALUES[lang],
                    "recommended_action": "live_filter_allowed_with_operator_key",
                    "reason": "language filter value is already represented in checked-in Solodit cursor/test coverage",
                }
            )
        else:
            rows.append(
                {
                    "target_language": lang,
                    "api_filter_supported": False,
                    "api_filter_value": None,
                    "recommended_action": "backlog_until_source_evidence_or_operator_probe",
                    "reason": "valid corpus target_language, but no checked-in Solodit API enum evidence; refusing to invent a REST filter value",
                }
            )
    return {
        "schema": "auditooor.solodit_language_planning.v1",
        "tool": TOOL_NAME,
        "tool_version": TOOL_VERSION,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "network_performed": False,
        "planning_only": True,
        "source_evidence": support["source_evidence"],
        "safe_api_filter_languages": support["safe_api_filter_languages"],
        "unsupported_api_filter_languages": support["unsupported_api_filter_languages"],
        "blocker_resolution": _language_blocker_resolution(support),
        "rows": rows,
    }


def _raw_language_text(raw: Dict[str, Any]) -> str:
    value = raw.get("language") or raw.get("languages") or raw.get("target_language") or ""
    if isinstance(value, list):
        parts: List[str] = []
        for item in value:
            if isinstance(item, dict):
                parts.append(str(item.get("value") or item.get("title") or item.get("name") or ""))
            else:
                parts.append(str(item))
        return " ".join(parts).strip()
    if isinstance(value, dict):
        return str(value.get("value") or value.get("title") or value.get("name") or "").strip()
    return str(value).strip()


UNKNOWN_TAXONOMY_VALUES = {
    "",
    "unknown",
    "unknown-attack",
    "unknown-class",
    "unclassified",
    "uncategorized",
    "n/a",
    "na",
    "none",
    "null",
}


def _is_unknown_taxonomy(value: Any) -> bool:
    normalized = str(value or "").strip().lower()
    slug = re.sub(r"[^a-z0-9]+", "-", normalized).strip("-")
    compact = re.sub(r"[^a-z0-9]+", "", normalized)
    return (
        normalized in UNKNOWN_TAXONOMY_VALUES
        or slug in UNKNOWN_TAXONOMY_VALUES
        or compact in {"unknownattack", "unknownclass", "unclassified", "uncategorized"}
    )


def _first_narrative_text(raw: Dict[str, Any], *, max_chars: int = 2400) -> str:
    """Return bounded prose from the first non-code text field.

    Solodit REST rows may carry large markdown blobs. The fallback classifiers
    should look at the finding title plus narrative prose, not Solidity/Rust
    snippets that happen to contain misleading identifiers.
    """
    for key in ("description", "summary", "body", "content", "details", "recommendation", "fix"):
        value = raw.get(key)
        if not isinstance(value, str) or not value.strip():
            continue
        text = re.sub(r"```.*?```", "\n", value, flags=re.DOTALL)
        paragraphs: List[str] = []
        current: List[str] = []
        in_html_code = False
        for line in text.splitlines():
            stripped = line.strip()
            lower = stripped.lower()
            if "<pre" in lower or "<code" in lower:
                in_html_code = True
                continue
            if "</pre" in lower or "</code" in lower:
                in_html_code = False
                continue
            if in_html_code:
                continue
            if not stripped:
                if current:
                    paragraphs.append(" ".join(current))
                    current = []
                continue
            if (
                line.startswith(("    ", "\t"))
                or stripped.startswith(("pragma ", "contract ", "function ", "fn ", "pub fn ", "let ", "use ", "import "))
                or stripped.startswith(("//", "#", "/*", "*", "*/"))
                or stripped.endswith(("{", "};"))
            ):
                continue
            current.append(stripped)
        if current:
            paragraphs.append(" ".join(current))
        for paragraph in paragraphs:
            words = paragraph.split()
            if len(words) >= 5:
                return paragraph[:max_chars]
    return ""


def _matches_language_filter(raw: Dict[str, Any], languages: List[str], *, trust_unlabeled_single_filter: bool = False) -> bool:
    if not languages:
        return True
    if not _raw_language_text(raw):
        if trust_unlabeled_single_filter and len(languages) == 1:
            return True
        return False
    return _infer_language(raw) in set(languages)


def _record_raw_with_trusted_language(raw: Dict[str, Any], languages: List[str]) -> Dict[str, Any]:
    if len(languages) == 1 and not _raw_language_text(raw):
        annotated = dict(raw)
        annotated["language"] = languages[0]
        return annotated
    return raw


# ---------------------------------------------------------------------------
# Cursor management
# ---------------------------------------------------------------------------

def load_cursor(cursor_file: Path) -> int:
    """Return the last-seen finding id (0 if missing or unparseable)."""
    if not cursor_file.exists():
        return 0
    try:
        data = json.loads(cursor_file.read_text(encoding="utf-8"))
        return int(data.get("last_id", 0))
    except (json.JSONDecodeError, ValueError, KeyError, OSError):
        return 0


def save_cursor(cursor_file: Path, last_id: int, written: int, extra: Optional[Dict[str, Any]] = None) -> None:
    cursor_file.parent.mkdir(parents=True, exist_ok=True)
    payload: Dict[str, Any] = {
        "last_id": last_id,
        "updated_at": datetime.now(timezone.utc).isoformat(),
        "run_date": datetime.now(timezone.utc).strftime("%Y-%m-%d"),
        "written": written,
        "tool": TOOL_NAME,
        "tool_version": TOOL_VERSION,
    }
    if extra:
        payload.update(extra)
    cursor_file.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")


# ---------------------------------------------------------------------------
# REST client (stdlib-only; no external deps)
# ---------------------------------------------------------------------------

class SoloditRESTError(Exception):
    pass


class SoloditRESTClient:
    """Direct REST client for solodit.cyfrin.io. Stdlib-only."""

    # r36-rebuttal: solodit-rate-limit-tighten-2026-05-26 lane registered via tools/agent-pathspec-register.py; pathspec covers tools/solodit-rest-direct.py
    def __init__(self, api_key: str, timeout_seconds: int = 30, sleep_fn=time.sleep, min_request_interval_seconds: Optional[float] = None):
        """Solodit REST client.

        ``min_request_interval_seconds``:
        - ``None`` (default) -> use the proactive floor
          ``RATE_LIMIT_MIN_INTERVAL_SECONDS`` (=3.1s) so live callers respect
          the upstream 20/min ceiling without coordination.
        - ``0`` (or any value <=0) -> disable the proactive floor (still
          reacts when ``X-RateLimit-Remaining`` drops to 1). Use in tests
          that stub urlopen and need synchronous fan-out without sleeps.
        - ``float > 0`` -> explicit override (e.g. ``3.2`` for safety margin
          on the 20/min limit, or larger for politeness on shared keys).
        """
        if not api_key:
            raise SoloditRESTError("api_key is required (set SOLODIT_API_KEY)")
        self.api_key = api_key
        self.timeout = timeout_seconds
        self._sleep = sleep_fn
        if min_request_interval_seconds is None:
            min_request_interval_seconds = RATE_LIMIT_MIN_INTERVAL_SECONDS
        self.min_request_interval_seconds = max(0.0, float(min_request_interval_seconds))
        self.last_request_at = 0.0
        self.remaining = 20
        self.reset_at = 0
        # `urlopen` is monkey-patchable for tests.
        self._urlopen = urllib.request.urlopen

    def _post_json(self, url: str, body: Dict[str, Any]) -> Tuple[Dict[str, Any], Dict[str, str]]:
        data = json.dumps(body).encode("utf-8")
        req = urllib.request.Request(
            url,
            data=data,
            method="POST",
            headers={
                "Content-Type": "application/json",
                "X-Cyfrin-API-Key": self.api_key,
                "User-Agent": f"{TOOL_NAME}/{TOOL_VERSION}",
            },
        )
        try:
            with self._urlopen(req, timeout=self.timeout) as resp:
                raw = resp.read()
                headers = {k.lower(): v for k, v in resp.headers.items()}
                if resp.status >= 400:
                    raise SoloditRESTError(f"HTTP {resp.status}: {raw[:200]!r}")
                return json.loads(raw.decode("utf-8")), headers
        except urllib.error.HTTPError as exc:
            body_preview = exc.read()[:200] if hasattr(exc, "read") else b""
            if exc.code == 429:
                raise SoloditRESTError(f"rate-limited (429): {body_preview!r}")
            raise SoloditRESTError(f"HTTP {exc.code}: {body_preview!r}") from exc
        except urllib.error.URLError as exc:
            raise SoloditRESTError(f"network error: {exc.reason}") from exc

    def _update_limits(self, headers: Dict[str, str]) -> None:
        rem = headers.get("x-ratelimit-remaining")
        reset = headers.get("x-ratelimit-reset")
        try:
            if rem is not None:
                self.remaining = int(rem)
            if reset is not None:
                self.reset_at = int(reset)
        except (TypeError, ValueError):
            pass

    def _wait_if_needed(self) -> None:
        if self.min_request_interval_seconds > 0 and self.last_request_at > 0:
            interval_wait = self.min_request_interval_seconds - (time.time() - self.last_request_at)
            if interval_wait > 0:
                self._sleep(interval_wait)
        if self.remaining > 1:
            return
        now = time.time()
        wait = max(self.reset_at - now + 1, 3)
        self._sleep(min(wait, 60))

    def fetch_page(
        self,
        page: int,
        page_size: int,
        severity: str,
        keyword: Optional[str] = None,
        keyword_field: Optional[str] = None,
        language_filter: Optional[List[str]] = None,
        sort_field: str = "Quality",
        sort_direction: str = "Desc",
    ) -> Dict[str, Any]:
        """Fetch a page of findings. severity is HIGH or CRITICAL (CRITICAL maps to HIGH upstream)."""
        language_filters = _api_language_filters(language_filter) if language_filter else []
        self._wait_if_needed()
        api_impact = _normalize_impact_for_api(severity)
        filters: Dict[str, Any] = {
            "impact": [api_impact],
            "sortField": sort_field,
            "sortDirection": sort_direction,
        }
        if keyword and keyword_field:
            filters[keyword_field] = keyword
        if language_filters:
            filters["languages"] = language_filters
        body = {
            "page": page,
            "pageSize": page_size,
            "filters": filters,
        }
        data, headers = self._post_json(API_ENDPOINT_FINDINGS, body)
        self.last_request_at = time.time()
        self._update_limits(headers)
        return data


# ---------------------------------------------------------------------------
# Normalization helpers
# ---------------------------------------------------------------------------

DOMAIN_KEYWORDS: List[Tuple[str, str]] = [
    ("lending", "lending"),
    ("loan", "lending"),
    ("borrow", "lending"),
    ("amm", "dex"),
    ("swap", "dex"),
    ("uniswap", "dex"),
    ("curve", "dex"),
    ("bridge", "bridge"),
    ("oracle", "oracle"),
    ("chainlink", "oracle"),
    ("governance", "governance"),
    ("dao", "dao"),
    ("staking", "staking"),
    ("vault", "vault"),
    ("erc4626", "vault"),
    ("erc-4626", "vault"),
    ("rollup", "rollup"),
    ("zk", "zk-proof"),
    ("zero-knowledge", "zk-proof"),
    ("consensus", "consensus"),
    ("validator", "consensus"),
    ("rpc", "rpc-infra"),
    ("escrow", "escrow"),
    ("nft", "nft"),
    ("erc721", "nft"),
    ("game", "gaming"),
]


def _infer_domain(text: str) -> str:
    t = text.lower()
    for kw, domain in DOMAIN_KEYWORDS:
        if kw in t:
            return domain
    return "vault"  # broad neutral default


def _infer_language(raw: Dict[str, Any]) -> str:
    lang = _raw_language_text(raw).lower()
    explicit = _language_from_text(lang, require_strong_signal=False)
    if explicit:
        return explicit

    text = _language_inference_text(raw)
    inferred = _language_from_text(text, require_strong_signal=True)
    if inferred:
        return inferred
    return "solidity"


def _language_inference_text(raw: Dict[str, Any]) -> str:
    parts = [
        str(raw.get("title") or raw.get("name") or ""),
        _first_narrative_text(raw),
        str(raw.get("protocol_name") or ""),
        str(raw.get("source_link") or ""),
        str(raw.get("github_link") or ""),
        str(raw.get("contest_link") or ""),
    ]
    return "\n".join(part for part in parts if part).lower()


def _language_from_text(text: str, *, require_strong_signal: bool) -> Optional[str]:
    t = f" {str(text or '').lower()} "
    if not t.strip():
        return None
    if "typescript" in t or re.search(r"\bts-sdk\b|\bts client\b", t):
        return "typescript-onchain"
    if "python" in t:
        return "python-onchain"
    if "cairo-zk" in t or (re.search(r"\bcairo\b", t) and re.search(r"\bzk\b", t)):
        return "cairo-zk"
    if re.search(r"\bcircom\b", t):
        return "circom"
    if re.search(r"\bvyper\b", t):
        return "vyper"
    if re.search(r"\byul\b|\bevm\s+assembly\b|\binline\s+assembly\b", t):
        return "assembly"
    if re.search(r"\bhuff\b", t):
        return "huff"
    if re.search(r"\bnoir\b", t):
        return "noir"
    if re.search(r"\bleo\b|\baleo\b", t):
        return "leo"
    if re.search(r"\bsway\b|\bfuel\b", t):
        return "sway"
    if re.search(r"\bcairo\b|\bstarknet\b", t):
        return "cairo"
    if require_strong_signal:
        if re.search(r"\bsui\s+move\b|\baptos\s+move\b|\bmove\s+(module|package|contract|bytecode)\b|\.move\b|\bsui\b|\baptos\b", t):
            return "move"
    elif re.search(r"\bmove\b|\bsui\b|\baptos\b", t):
        return "move"
    if re.search(r"\brust\b", t):
        return "rust"
    if re.search(r"\bsolana\b|\banchor\b|\bpda\b|\bcpi\b|\bpubkey\b|\.rs\b", t):
        return "rust"
    if re.search(r"\bgolang\b|\bcosmos-sdk\b|\bcosmwasm\b|\btendermint\b", t) or t.strip() == "go":
        return "go"
    if re.search(r"\bgo\b", t) and not require_strong_signal:
        return "go"
    if re.search(r"\bassembly\b", t):
        return "assembly"
    if re.search(r"\bsolidity\b|\bevm\b", t):
        return "solidity"
    return None


def _infer_severity(raw: Dict[str, Any]) -> str:
    sev = str(raw.get("severity") or raw.get("impact") or "").lower().strip()
    if sev in {"critical", "high", "medium", "low", "info"}:
        return sev
    return "high"


def _infer_impact_class(text: str) -> str:
    t = text.lower()
    if "theft" in t or "drain" in t or "stolen" in t:
        return "theft"
    if "freeze" in t or "frozen" in t or "locked" in t or "stuck" in t:
        return "freeze"
    if "dos" in t or "denial of service" in t or "denial-of-service" in t:
        return "dos"
    if "griefing" in t or "grief" in t:
        return "griefing"
    if "rounding" in t or "precision" in t:
        return "precision-loss"
    if "yield" in t or "redistribut" in t:
        return "yield-redistribution"
    if "takeover" in t:
        return "governance-takeover"
    if "privilege" in t or "access control" in t:
        return "privilege-escalation"
    return "theft"


TAXONOMY_FALLBACK_RULES: List[Dict[str, Any]] = [
    {
        "attack_class": "reentrancy",
        "bug_class": "reentrancy",
        "confidence": "high",
        "groups": (("reentrancy", "re-entrancy", "reentrant", "reenter", "re-enter"),),
    },
    {
        "attack_class": "access-control-bypass",
        "bug_class": "access-control",
        "confidence": "high",
        "groups": (
            ("missing access control", "unauthorized", "anyone can call", "arbitrary caller", "unprotected admin", "onlyowner bypass"),
            ("owner", "admin", "governance", "role", "privileged"),
        ),
    },
    {
        "attack_class": "signature-replay",
        "bug_class": "signature-validation",
        "confidence": "high",
        "groups": (
            ("signature", "eip-712", "permit", "signed message"),
            ("replay", "nonce", "domain separator", "chain id", "malleability"),
        ),
    },
    {
        "attack_class": "oracle-price-manipulation",
        "bug_class": "oracle",
        "confidence": "high",
        "groups": (
            ("oracle", "price feed", "twap", "chainlink", "pyth"),
            ("manipulat", "sandwich", "flash loan", "spot price"),
        ),
    },
    {
        "attack_class": "stale-or-manipulated-oracle",
        "bug_class": "oracle",
        "confidence": "medium",
        "groups": (
            ("oracle", "price feed", "twap", "chainlink", "pyth"),
            ("stale", "heartbeat", "outdated", "wrong price", "incorrect price", "depeg"),
        ),
    },
    {
        "attack_class": "rounding-precision-loss",
        "bug_class": "precision-loss",
        "confidence": "high",
        "groups": (("rounding", "precision", "truncation", "decimal", "division before multiplication"),),
    },
    {
        "attack_class": "first-deposit-share-inflation",
        "bug_class": "share-inflation",
        "confidence": "high",
        "groups": (
            ("share inflation", "inflation attack", "first depositor", "first deposit", "empty vault"),
            ("share", "vault", "deposit"),
        ),
    },
    {
        "attack_class": "denial-of-service",
        "bug_class": "denial-of-service",
        "confidence": "medium",
        "groups": (("denial of service", "denial-of-service", "dos", "permanent revert", "blocked withdrawals", "griefing"),),
    },
    {
        "attack_class": "bridge-proof-bypass",
        "bug_class": "bridge-verification",
        "confidence": "medium",
        "groups": (
            ("bridge", "cross-chain", "message", "merkle proof", "proof"),
            ("bypass", "forg", "verify", "validation", "replay"),
        ),
    },
    {
        "attack_class": "liquidation-bypass",
        "bug_class": "liquidation",
        "confidence": "medium",
        "groups": (("liquidation", "liquidate", "health factor", "collateral"), ("bypass", "avoid", "incorrect", "bad debt")),
    },
    {
        "attack_class": "staking-reward-theft",
        "bug_class": "staking-rewards",
        "confidence": "medium",
        "groups": (("staking", "reward", "claim"), ("steal", "theft", "drain", "overclaim", "overpay")),
    },
    {
        "attack_class": "state-accounting-drift",
        "bug_class": "accounting",
        "confidence": "medium",
        "groups": (("accounting", "stale balance", "incorrect balance", "wrong balance", "solvency"),),
    },
]

CANONICAL_CATEGORY_ALIASES: Dict[str, tuple[str, str]] = {
    "access-control": ("access-control-bypass", "access-control"),
    "access-control-bypass": ("access-control-bypass", "access-control"),
    "accounting": ("state-accounting-drift", "accounting"),
    "bridge-proof-bypass": ("bridge-proof-bypass", "bridge-verification"),
    "bridge-verification": ("bridge-proof-bypass", "bridge-verification"),
    "denial-of-service": ("denial-of-service", "denial-of-service"),
    "dos": ("denial-of-service", "denial-of-service"),
    "first-deposit-share-inflation": ("first-deposit-share-inflation", "share-inflation"),
    "liquidation": ("liquidation-bypass", "liquidation"),
    "liquidation-bypass": ("liquidation-bypass", "liquidation"),
    "oracle": ("stale-or-manipulated-oracle", "oracle"),
    "oracle-price-manipulation": ("oracle-price-manipulation", "oracle"),
    "precision-loss": ("rounding-precision-loss", "precision-loss"),
    "reentrancy": ("reentrancy", "reentrancy"),
    "rounding-precision-loss": ("rounding-precision-loss", "precision-loss"),
    "signature-replay": ("signature-replay", "signature-validation"),
    "signature-validation": ("signature-replay", "signature-validation"),
    "stale-or-manipulated-oracle": ("stale-or-manipulated-oracle", "oracle"),
    "staking-rewards": ("staking-reward-theft", "staking-rewards"),
}


def _canonical_category(value: Any) -> tuple[str, str] | None:
    raw = str(value or "").strip().lower()
    if not raw:
        return None
    normalized = re.sub(r"[^a-z0-9]+", "-", raw).strip("-")
    return CANONICAL_CATEGORY_ALIASES.get(normalized)


def _taxonomy_text(raw: Dict[str, Any], title: str) -> str:
    return (title + "\n" + _first_narrative_text(raw)).lower()


def _classify_taxonomy_fallback(raw: Dict[str, Any], title: str) -> Dict[str, Any]:
    text = _taxonomy_text(raw, title)
    if not text.strip():
        return {
            "attack_class": "unknown-attack",
            "bug_class": "unknown-class",
            "source": "unknown",
            "confidence": "none",
            "rule": None,
        }
    for rule in TAXONOMY_FALLBACK_RULES:
        groups = rule["groups"]
        if all(any(keyword in text for keyword in group) for group in groups):
            return {
                "attack_class": rule["attack_class"],
                "bug_class": rule["bug_class"],
                "source": "fallback-title-narrative",
                "confidence": rule["confidence"],
                "rule": rule["attack_class"],
            }
    return {
        "attack_class": "unknown-attack",
        "bug_class": "unknown-class",
        "source": "unknown",
        "confidence": "none",
        "rule": None,
    }


def _resolve_taxonomy(raw: Dict[str, Any], title: str) -> Dict[str, Any]:
    raw_attack = raw.get("attack_class")
    raw_category = raw.get("category")
    raw_bug = raw.get("bug_class")

    if not _is_unknown_taxonomy(raw_attack):
        attack_class = str(raw_attack)[:160]
        bug_class = str(raw_bug if not _is_unknown_taxonomy(raw_bug) else raw_category if not _is_unknown_taxonomy(raw_category) else attack_class)[:160]
        return {"attack_class": attack_class, "bug_class": bug_class, "source": "upstream-attack_class", "confidence": "high", "rule": None}
    if not _is_unknown_taxonomy(raw_category):
        canonical = _canonical_category(raw_category)
        if canonical:
            attack_class, canonical_bug = canonical
            bug_class = str(raw_bug if not _is_unknown_taxonomy(raw_bug) else canonical_bug)[:160]
            return {
                "attack_class": attack_class[:160],
                "bug_class": bug_class,
                "source": "upstream-category-canonical",
                "confidence": "high",
                "rule": None,
            }

    fallback = _classify_taxonomy_fallback(raw, title)
    if not _is_unknown_taxonomy(raw_bug) and fallback["bug_class"] == "unknown-class":
        fallback["bug_class"] = str(raw_bug)[:160]
    return fallback


_SAFE_ID_RE = re.compile(r"[^A-Za-z0-9._:/-]+")


def _safe_record_id(finding_id: str, slug_hint: str = "") -> str:
    base = f"solodit:{finding_id}:{slug_hint}".strip(":")
    base = _SAFE_ID_RE.sub("-", base).strip("-:")
    # min length 8 per schema
    if len(base) < 8:
        base = (base + "-" + hashlib.sha1(base.encode()).hexdigest())[:24]
    return base[:160]


def _slug_from_title(title: str) -> str:
    s = re.sub(r"[^A-Za-z0-9]+", "-", title or "").strip("-").lower()
    return s[:60] or "finding"


def _emitted_record_filename(finding_id: int | str, language_filter: Optional[List[str]] = None) -> str:
    suffix = ""
    if language_filter:
        language_slug = "-".join(_slug_from_title(str(language)) for language in language_filter if language)
        if language_slug:
            suffix = f"-{language_slug[:80]}"
    return f"solodit-finding-{finding_id or 'unknown'}{suffix}.yaml"


def _validate_record_id(rid: str) -> bool:
    return bool(re.fullmatch(r"[A-Za-z0-9._:/-]{8,160}", rid))


def _source_url_from_finding(raw: Dict[str, Any]) -> str:
    """Try multiple field-name variants to find the canonical solodit URL."""
    for key in ("url", "source_url", "link", "issue_url", "permalink", "source_link"):
        val = raw.get(key)
        if isinstance(val, str) and val.startswith("http"):
            return val
    # Construct fallback from id + title slug
    fid = raw.get("id") or raw.get("finding_id") or ""
    title = raw.get("title") or raw.get("name") or ""
    slug = _slug_from_title(str(title))
    if fid and slug:
        return f"https://solodit.cyfrin.io/issues/{slug}-{fid}"
    return "https://solodit.cyfrin.io/"


def _attacker_role(raw: Dict[str, Any]) -> str:
    text = (str(raw.get("description") or "") + " " + str(raw.get("title") or "")).lower()
    if "governance" in text or "owner-only" in text or "admin-only" in text:
        return "privileged-trusted"
    if "validator" in text:
        return "validator"
    if "sequencer" in text:
        return "sequencer"
    return "unprivileged"


def _impact_actor(raw: Dict[str, Any]) -> str:
    text = (str(raw.get("description") or "") + " " + str(raw.get("title") or "")).lower()
    if "treasury" in text or "protocol owns" in text:
        return "protocol-treasury"
    if "depositor" in text or "lp " in text or "lps" in text:
        return "depositor-class"
    if "yield" in text:
        return "yield-recipient"
    if "validator" in text:
        return "validator-set"
    return "arbitrary-user"


def _impact_dollar_class(raw: Dict[str, Any]) -> str:
    sev = _infer_severity(raw)
    if sev == "critical":
        return ">=$1M"
    if sev == "high":
        return "$100K-$1M"
    if sev == "medium":
        return "$10K-$100K"
    if sev == "low":
        return "<$10K"
    return "non-financial"


def _bounded_multiline_text(text: str, max_chars: int = 4900) -> str:
    normalized_lines = [line.rstrip().replace("\t", "  ") for line in str(text or "").splitlines()]
    normalized = "\n".join(normalized_lines).strip()
    return normalized[:max_chars]


# ---------------------------------------------------------------------------
# Record builder
# ---------------------------------------------------------------------------

def build_v11_record(
    raw: Dict[str, Any],
    *,
    fetch_meta: Dict[str, Any],
    synthetic_fixture: bool = False,
) -> Dict[str, Any]:
    finding_id = str(raw.get("id") or raw.get("finding_id") or raw.get("solodit_id") or "unknown")
    title = str(raw.get("title") or raw.get("name") or "untitled")
    description = str(raw.get("description") or raw.get("body") or raw.get("content") or raw.get("summary") or "")
    full_text = title + "\n" + description

    severity = _infer_severity(raw)
    language = _infer_language(raw)
    domain = _infer_domain(full_text)
    impact_class = _infer_impact_class(full_text)
    taxonomy = _resolve_taxonomy(raw, title)

    slug_hint = _slug_from_title(title)
    fetch_languages = fetch_meta.get("language_filter") or []
    if isinstance(fetch_languages, list) and fetch_languages:
        language_hint = "-".join(str(lang) for lang in fetch_languages if lang)
        if language_hint:
            slug_hint = f"{language_hint}:{slug_hint}"

    record_id = _safe_record_id(finding_id, slug_hint)
    if not _validate_record_id(record_id):
        record_id = f"solodit-finding-{finding_id}"[:160]

    year_raw = raw.get("year") or raw.get("published_year") or raw.get("date")
    try:
        if isinstance(year_raw, str) and len(year_raw) >= 4:
            year = int(year_raw[:4])
        elif isinstance(year_raw, int):
            year = year_raw if year_raw > 1000 else 2024
        else:
            year = 2024
    except (TypeError, ValueError):
        year = 2024
    if year < 2000:
        year = 2024

    function_signature = str(raw.get("function") or raw.get("function_name") or "function unknown()")
    if "(" not in function_signature:
        function_signature += "()"

    # v1.1 schema: cve_id pattern ^CVE-\d{4}-\d{4,}$ (NO empty-string match).
    # ghsa_id pattern ^GHSA-[A-Za-z0-9]{4}-[A-Za-z0-9]{4}-[A-Za-z0-9]{4}$ (case-insensitive).
    # Both fields are OPTIONAL in the schema - omit when no valid value is available
    # rather than emit empty string (which would fail schema validation).
    cve_id_raw = str(raw.get("cve_id") or raw.get("cve") or "").strip()
    cve_id = cve_id_raw if re.match(r"^CVE-\d{4}-\d{4,}$", cve_id_raw) else None
    ghsa_id_raw = str(raw.get("ghsa_id") or raw.get("ghsa") or "").strip()
    ghsa_id = (
        ghsa_id_raw
        if re.match(r"^GHSA-[A-Za-z0-9]{4}-[A-Za-z0-9]{4}-[A-Za-z0-9]{4}$", ghsa_id_raw)
        else None
    )

    record_extensions: Dict[str, Any] = {
        "source_method": "solodit-rest-direct",
        "tool_version": TOOL_VERSION,
        "ingested_at": datetime.now(timezone.utc).isoformat(),
        "upstream_finding_id": finding_id,
        "upstream_severity_raw": str(raw.get("severity") or raw.get("impact") or ""),
        "taxonomy_source": taxonomy["source"],
        "taxonomy_confidence": taxonomy["confidence"],
        "fetch_page": fetch_meta.get("page"),
        "fetch_page_size": fetch_meta.get("page_size"),
        "fetch_keyword_field_used": fetch_meta.get("keyword_field_used"),
        "fetch_keyword": fetch_meta.get("keyword"),
        "fetch_language_filter": fetch_languages,
    }
    if taxonomy.get("rule"):
        record_extensions["taxonomy_rule"] = taxonomy["rule"]
    for raw_key in ("attack_class", "bug_class", "category"):
        value = raw.get(raw_key)
        if value not in (None, "", {}, []):
            record_extensions[f"upstream_{raw_key}_raw"] = value
    for raw_key in (
        "source_link",
        "pdf_link",
        "github_link",
        "contest_link",
        "protocol_name",
        "firm_name",
        "kind",
        "slug",
        "category",
        "attack_class",
        "bug_class",
    ):
        value = raw.get(raw_key)
        if value not in (None, "", {}, []):
            record_extensions[f"upstream_{raw_key}"] = value
    if synthetic_fixture:
        record_extensions["synthetic_fixture"] = True

    record: Dict[str, Any] = {
        "schema_version": SCHEMA_VERSION,
        "record_id": record_id,
        "source_audit_ref": f"solodit:{finding_id}",
        "verification_tier": VERIFICATION_TIER,
        "record_source_url": _source_url_from_finding(raw),
        "record_extensions": record_extensions,
        "target_domain": domain,
        "target_language": language,
        "target_repo": "unknown/solodit",
        "target_component": title[:240] or "untitled",
        "function_shape": {
            "raw_signature": function_signature[:500],
            "shape_tags": ["solodit-rest-direct", f"severity-{severity}"],
        },
        "bug_class": str(taxonomy["bug_class"])[:160],
        "attack_class": str(taxonomy["attack_class"])[:160],
        "attacker_role": _attacker_role(raw),
        "attacker_action_sequence": (_bounded_multiline_text(description) or "See source URL for full description."),
        "required_preconditions": [
            "Attacker can interact with the affected contract per the source finding.",
        ],
        "impact_class": impact_class,
        "impact_actor": _impact_actor(raw),
        "impact_dollar_class": _impact_dollar_class(raw),
        "fix_pattern": str(raw.get("recommendation") or raw.get("fix") or "See source URL for recommended fix.")[:1000],
        "fix_anti_pattern_avoided": "shipping unverified state-change without invariant check",
        "severity_at_finding": severity,
        "year": year,
        "cross_language_analogues": [],
        "related_records": [],
    }
    # cve_id / ghsa_id are optional in v1.1 schema; only emit when valid.
    if cve_id:
        record["cve_id"] = cve_id
    if ghsa_id:
        record["ghsa_id"] = ghsa_id
    return record


# ---------------------------------------------------------------------------
# YAML emission (stdlib-only)
# ---------------------------------------------------------------------------

def _yaml_scalar(val: Any) -> str:
    if isinstance(val, bool):
        return "true" if val else "false"
    if val is None:
        return "null"
    if isinstance(val, (int, float)):
        return str(val)
    s = str(val)
    needs_block = "\n" in s
    if needs_block:
        out = "|"
        for line in s.split("\n"):
            out += "\n  " + line
        return out
    # Quote scalars that contain special chars
    if any(ch in s for ch in [":", "#", "'", '"', "{", "}", "[", "]", ",", "&", "*", "!", "|", ">", "%", "@", "`"]) or s.startswith(("-", "?")) or s == "":
        escaped = s.replace("\\", "\\\\").replace('"', '\\"')
        return f'"{escaped}"'
    return s


def _yaml_dump(obj: Any, indent: int = 0) -> str:
    pad = "  " * indent
    if isinstance(obj, dict):
        if not obj:
            return pad + "{}\n"
        out = ""
        for k, v in obj.items():
            if isinstance(v, (dict, list)) and v:
                out += f"{pad}{k}:\n{_yaml_dump(v, indent + 1)}"
            else:
                out += f"{pad}{k}: {_yaml_scalar(v) if not isinstance(v, (dict, list)) else ('{}' if isinstance(v, dict) else '[]')}\n"
        return out
    if isinstance(obj, list):
        if not obj:
            return pad + "[]\n"
        out = ""
        for item in obj:
            if isinstance(item, (dict, list)):
                # Render block scalar with first key prefixed by "- "
                rendered = _yaml_dump(item, indent + 1)
                # Pull the first line and prepend "- "
                lines = rendered.splitlines(True)
                if lines:
                    out += pad + "- " + lines[0].lstrip()
                    for ln in lines[1:]:
                        out += ln
                else:
                    out += pad + "-\n"
            else:
                out += f"{pad}- {_yaml_scalar(item)}\n"
        return out
    return pad + _yaml_scalar(obj) + "\n"


def yaml_dump_record(record: Dict[str, Any]) -> str:
    return _yaml_dump(record)


# ---------------------------------------------------------------------------
# Ingest orchestrator
# ---------------------------------------------------------------------------

def _extract_findings(response: Dict[str, Any]) -> List[Dict[str, Any]]:
    for key in ("findings", "issues", "results", "data"):
        v = response.get(key)
        if isinstance(v, list):
            return v
    return []


def _extract_meta(response: Dict[str, Any]) -> Dict[str, Any]:
    return response.get("metadata") or response.get("meta") or {}


def ingest_pages(
    client: SoloditRESTClient,
    *,
    cursor_id: int,
    page_size: int,
    severity: str,
    out_dir: Path,
    max_pages: int,
    keyword: Optional[str],
    keyword_field: Optional[str],
    language_filter: Optional[List[str]],
    sort_field: str = "Quality",
    sort_direction: str = "Desc",
    json_only: bool,
) -> Dict[str, Any]:
    out_dir.mkdir(parents=True, exist_ok=True)
    written = 0
    skipped = 0
    skipped_language = 0
    highest_id = cursor_id
    pages_fetched = 0
    last_page_meta: Dict[str, Any] = {}

    for page in range(1, max_pages + 1):
        try:
            response = client.fetch_page(
                page=page,
                page_size=page_size,
                severity=severity,
                keyword=keyword,
                keyword_field=keyword_field,
                language_filter=language_filter,
                sort_field=sort_field,
                sort_direction=sort_direction,
            )
        except SoloditRESTError as exc:
            return {
                "verdict": "NEGATIVE",
                "reason": f"REST error on page {page}: {exc}",
                "pages_fetched": pages_fetched,
                "written": written,
                "skipped": skipped,
                "highest_id_seen": highest_id,
            }
        pages_fetched += 1
        findings = _extract_findings(response)
        last_page_meta = _extract_meta(response)

        for raw in findings:
            try:
                fid = int(raw.get("id") or raw.get("finding_id") or 0)
            except (TypeError, ValueError):
                fid = 0
            if fid and fid <= cursor_id:
                skipped += 1
                continue
            if not _matches_language_filter(raw, language_filter or [], trust_unlabeled_single_filter=True):
                skipped_language += 1
                continue
            if fid > highest_id:
                highest_id = fid

            raw_for_record = _record_raw_with_trusted_language(raw, language_filter or [])
            fetch_meta = {
                "page": page,
                "page_size": page_size,
                "keyword": keyword,
                "keyword_field_used": keyword_field,
                "language_filter": language_filter or [],
            }
            record = build_v11_record(raw_for_record, fetch_meta=fetch_meta)
            if not json_only:
                target = out_dir / _emitted_record_filename(fid or "unknown", language_filter)
                target.write_text(yaml_dump_record(record), encoding="utf-8")
            written += 1

        total_pages = last_page_meta.get("totalPages") or last_page_meta.get("total_pages")
        if isinstance(total_pages, int) and page >= total_pages:
            break
        if not findings:
            break

    verdict = "POSITIVE" if written > 0 else "NEGATIVE-EMPTY"
    return {
        "verdict": verdict,
        "pages_fetched": pages_fetched,
        "written": written,
        "skipped": skipped,
        "skipped_language": skipped_language,
        "language_filter": language_filter or [],
        "highest_id_seen": highest_id,
        "last_page_metadata": last_page_meta,
    }


def ingest_from_injected_fixture(
    fixture_path: Path,
    *,
    cursor_id: int,
    out_dir: Path,
    json_only: bool,
    page_size: int,
    language_filter: Optional[List[str]] = None,
) -> Dict[str, Any]:
    if not fixture_path.exists():
        return {"verdict": "NEGATIVE", "reason": f"fixture not found: {fixture_path}", "written": 0, "highest_id_seen": cursor_id}
    try:
        data = json.loads(fixture_path.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError) as exc:
        return {"verdict": "NEGATIVE", "reason": f"fixture parse error: {exc}", "written": 0, "highest_id_seen": cursor_id}

    pages = data if isinstance(data, list) else [data]
    out_dir.mkdir(parents=True, exist_ok=True)
    written = 0
    skipped = 0
    skipped_language = 0
    highest_id = cursor_id

    for page_idx, response in enumerate(pages, start=1):
        findings = _extract_findings(response if isinstance(response, dict) else {"findings": response if isinstance(response, list) else []})
        for raw in findings:
            try:
                fid = int(raw.get("id") or raw.get("finding_id") or 0)
            except (TypeError, ValueError):
                fid = 0
            if fid and fid <= cursor_id:
                skipped += 1
                continue
            if not _matches_language_filter(raw, language_filter or []):
                skipped_language += 1
                continue
            if fid > highest_id:
                highest_id = fid
            fetch_meta = {
                "page": page_idx,
                "page_size": page_size,
                "keyword": None,
                "keyword_field_used": None,
                "language_filter": language_filter or [],
            }
            record = build_v11_record(raw, fetch_meta=fetch_meta, synthetic_fixture=True)
            if not json_only:
                target = out_dir / _emitted_record_filename(fid or "unknown", language_filter)
                target.write_text(yaml_dump_record(record), encoding="utf-8")
            written += 1

    return {
        "verdict": "POSITIVE-DRY-RUN" if written > 0 else "NEGATIVE-EMPTY-DRY-RUN",
        "written": written,
        "skipped": skipped,
        "skipped_language": skipped_language,
        "language_filter": language_filter or [],
        "highest_id_seen": highest_id,
        "dry_run": True,
    }


# ---------------------------------------------------------------------------
# CLI entrypoint
# ---------------------------------------------------------------------------

def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--cursor-id", type=int, default=None, help="Override last-id cursor (default: read from cursor file)")
    parser.add_argument("--cursor-file", default=str(DEFAULT_CURSOR_FILE), help=f"Cursor file path (default: {DEFAULT_CURSOR_FILE})")
    parser.add_argument("--page-size", type=int, default=100, help="REST API pageSize (default: 100)")
    parser.add_argument("--min-severity", choices=["HIGH", "CRITICAL", "MEDIUM"], default="HIGH", help="Minimum severity (default: HIGH). MEDIUM fetches MEDIUM-tier (API impact=MEDIUM).")
    parser.add_argument("--out-dir", default="/private/tmp/solodit-rest-direct", help="YAML emit dir")
    parser.add_argument("--max-pages", type=int, default=10, help="Maximum pages to fetch (default: 10)")
    parser.add_argument("--keyword", default=None, help="Optional keyword filter")
    parser.add_argument("--keyword-field", default=None, choices=KEYWORD_FIELD_VARIANTS, help="Override keyword field name to A/B test")
    parser.add_argument("--language", "--target-language", dest="language", default=None, help="Comma-separated target_language filter (e.g. rust,go,move)")
    parser.add_argument("--plan-language-backlog", action="store_true", help="Emit offline planning manifest for additional Solodit language slices; no network")
    parser.add_argument("--planning-manifest-out", default=None, help="Optional path to write --plan-language-backlog JSON")
    parser.add_argument("--sort-field", default="Quality", help="Solodit sort field (default: Quality; use Recency for cursor freshness)")
    parser.add_argument("--sort-direction", default="Desc", choices=["Asc", "Desc"], help="Solodit sort direction (default: Desc)")
    parser.add_argument(
        "--min-request-interval",
        type=float,
        default=RATE_LIMIT_MIN_INTERVAL_SECONDS,
        help=(
            f"Proactive floor (seconds) between live API requests (default: "
            f"{RATE_LIMIT_MIN_INTERVAL_SECONDS}s = 20/min ceiling + 0.1s "
            f"safety margin). Pass 0 to disable; reactive header-driven wait "
            f"still applies when X-RateLimit-Remaining drops to 1. "
            f"r36-rebuttal: solodit-rate-limit-tighten-2026-05-26"
        ),
    )
    parser.add_argument("--dry-run", action="store_true", help="No network; consumes --inject-json instead")
    parser.add_argument("--inject-json", default=None, help="Path to JSON fixture (used with --dry-run)")
    parser.add_argument("--json-only", action="store_true", help="Print verdict JSON, do NOT write YAML files")
    parser.add_argument("--no-update-cursor", action="store_true", help="Never mutate cursor file")
    args = parser.parse_args(argv)

    out_dir = Path(args.out_dir).expanduser().resolve()
    try:
        language_filter = _parse_language_filter(args.language)
    except ValueError as exc:
        verdict = {
            "verdict": "NEGATIVE",
            "reason": str(exc),
            "tool": TOOL_NAME,
            "tool_version": TOOL_VERSION,
        }
        print(json.dumps(verdict, indent=2))
        return 0

    if args.plan_language_backlog:
        plan = build_language_planning_manifest(language_filter or None)
        if args.planning_manifest_out:
            manifest_path = Path(args.planning_manifest_out).expanduser().resolve()
            manifest_path.parent.mkdir(parents=True, exist_ok=True)
            manifest_path.write_text(json.dumps(plan, indent=2) + "\n", encoding="utf-8")
            plan["planning_manifest_out"] = str(manifest_path)
        print(json.dumps(plan, indent=2, default=str))
        return 0

    cursor_file = Path(args.cursor_file).expanduser().resolve()
    if args.cursor_file == str(DEFAULT_CURSOR_FILE) and language_filter:
        suffix = "-".join(language_filter)
        cursor_file = DEFAULT_CURSOR_FILE.with_name(f"{DEFAULT_CURSOR_FILE.stem}_{suffix}{DEFAULT_CURSOR_FILE.suffix}")

    if args.cursor_id is not None:
        cursor_id = args.cursor_id
    else:
        cursor_id = load_cursor(cursor_file)

    # Dry-run path
    if args.dry_run:
        if not args.inject_json:
            verdict = {
                "verdict": "NEGATIVE",
                "reason": "--dry-run requires --inject-json",
                "tool": TOOL_NAME,
                "tool_version": TOOL_VERSION,
            }
            print(json.dumps(verdict, indent=2))
            return 0
        result = ingest_from_injected_fixture(
            Path(args.inject_json),
            cursor_id=cursor_id,
            out_dir=out_dir,
            json_only=args.json_only,
            page_size=args.page_size,
            language_filter=language_filter,
        )
        result["tool"] = TOOL_NAME
        result["tool_version"] = TOOL_VERSION
        result["cursor_id_in"] = cursor_id
        # NEVER update cursor on dry-run
        print(json.dumps(result, indent=2, default=str))
        return 0

    language_support = _language_filter_support(language_filter)
    if not language_support["safe_for_live_api"]:
        verdict = {
            "verdict": "NEGATIVE",
            "reason": (
                "Solodit API language filters lack checked-in source evidence for: "
                + ", ".join(language_support["unsupported_api_filter_languages"])
            ),
            "tool": TOOL_NAME,
            "tool_version": TOOL_VERSION,
            "cursor_id_in": cursor_id,
            "language_filter": language_filter,
            "network_performed": False,
            "remediation": "run --plan-language-backlog for an offline backlog manifest, or add source evidence before enabling live filters",
        }
        print(json.dumps(verdict, indent=2))
        return 0

    # Live path - require API key
    api_key = os.environ.get("SOLODIT_API_KEY", "").strip()
    if not api_key:
        verdict = {
            "verdict": "NEGATIVE",
            "reason": "SOLODIT_API_KEY env var is missing or empty; no live ingest performed",
            "tool": TOOL_NAME,
            "tool_version": TOOL_VERSION,
            "cursor_id_in": cursor_id,
            "remediation": "export SOLODIT_API_KEY via an external secret manager; do not commit the key",
        }
        print(json.dumps(verdict, indent=2))
        return 0

    client = SoloditRESTClient(api_key=api_key, min_request_interval_seconds=args.min_request_interval)
    result = ingest_pages(
        client,
        cursor_id=cursor_id,
        page_size=args.page_size,
        severity=args.min_severity,
        out_dir=out_dir,
        max_pages=args.max_pages,
        keyword=args.keyword,
        keyword_field=args.keyword_field,
        language_filter=language_filter,
        sort_field=args.sort_field,
        sort_direction=args.sort_direction,
        json_only=args.json_only,
    )
    result["tool"] = TOOL_NAME
    result["tool_version"] = TOOL_VERSION
    result["cursor_id_in"] = cursor_id

    # Only mutate cursor if real findings ingested AND cursor moved forward.
    if (
        not args.no_update_cursor
        and result.get("written", 0) > 0
        and isinstance(result.get("highest_id_seen"), int)
        and result["highest_id_seen"] > cursor_id
    ):
        save_cursor(
            cursor_file,
            last_id=result["highest_id_seen"],
            written=result["written"],
            extra={
                "tool": TOOL_NAME,
                "tool_version": TOOL_VERSION,
                "pages_fetched": result.get("pages_fetched", 0),
                "previous_cursor_id": cursor_id,
                "language_filter": language_filter,
            },
        )
        result["cursor_updated"] = True
    else:
        result["cursor_updated"] = False

    print(json.dumps(result, indent=2, default=str))
    return 0


if __name__ == "__main__":
    sys.exit(main())
