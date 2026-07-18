#!/usr/bin/env python3
"""Rule 54 External-URL-liveness preflight check (Check #101).

# Rule 54: this tool emits no corpus record.

GENERAL RULE - applies to ANY draft (LOW+) before promotion to
`submissions/paste_ready/` or `submissions/filed/` that cites external URLs
(gist.github.com/*, github.com/*/pull/*, /blob/*, docs.*, etherscan.io/*,
*.pdf, third-party post-mortems, blog posts, archive.org links, etc.).

Every cited external URL must be LIVE at the time of promotion. A dead URL
(HTTP 404 / 410 / 5xx) in a HIGH+ dispute/triager-response/finding draft is
load-bearing evidence the triager will attempt to verify; if the URL 404s,
the disputed claim collapses on first click.

Trigger: ANY draft (LOW+) that cites at least one external URL outside the
local audit-pin tree. URLs matched: gist.github.com/<user>/<sha>,
github.com/<owner>/<repo>/(pull|blob|tree|commit|issues)/<n>, docs.*,
etherscan.io/*, *.pdf, *.io/*, *.com/*, *.dev/*, *.xyz/* etc.

For each cited URL the tool runs an HTTP HEAD probe (with GET fallback on
405/501) with a configurable timeout (default 8s). 200/2xx/3xx = live;
404/410/5xx = dead; network failure = warn (--strict promotes to fail).

Verdict vocabulary:
  pass-no-external-urls            - draft cites no external URLs
  pass-all-urls-live               - every cited URL returned 200/2xx/3xx
  ok-rebuttal                      - valid r54-rebuttal marker present
  fail-dead-url-cited              - at least one URL returned 404 / 410 / 5xx
  fail-network-validation-failed-strict
                                   - network failure under --strict mode
  error                            - input error

Exit codes:
  0 - pass, out-of-scope, or accepted rebuttal
  1 - Rule 54 violation (fail-dead-url-cited; under --strict also network failure)
  2 - input error

Schema: auditooor.r54_external_url_liveness.v1

Empirical anchor: 2026-05-23 iter16 MMMMM caught the Hyperbridge OP dispute
draft (`hb-optimism-l2oracle-dispute-v2-SHORT.md`) citing a DEAD gist URL
(`gist.github.com/Vuk97/9d055289dd81f2d48ad192580b7aa7fb`, HTTP 404). The
operator-confirmed live evidence gist was `3904db90824e1a3b990bfee1e9b684c0`
(HTTP 200). The operator manually fixed the URL at HackenProof paste time,
but a future lane could be less alert. R54 codifies "validate external URLs
in HIGH+ disputes before promotion to paste_ready/filed".
"""

from __future__ import annotations

import argparse
import json
import os
import re
import socket
import sys
from pathlib import Path
from typing import Any
from urllib import error as url_error
from urllib import request as url_request
from urllib.parse import urlparse

SCHEMA_VERSION = "auditooor.r54_external_url_liveness.v1"
GATE = "R54-EXTERNAL-URL-LIVENESS"

SEVERITY_RANK = {"low": 1, "medium": 2, "high": 3, "critical": 4}
REBUTTAL_MAX_CHARS = 200
DEFAULT_TIMEOUT_S = 8.0

# ---------------------------------------------------------------------------
# URL detection
# ---------------------------------------------------------------------------
# Match http:// and https:// URLs. Stop at whitespace, closing markdown
# parens/brackets/quotes/backticks, trailing punctuation that is unlikely
# to be part of the URL.
_URL_RE = re.compile(
    r"""
    (?P<url>
        https?://
        [^\s\)\]\}\>\<\"\'`]+
    )
    """,
    re.VERBOSE | re.IGNORECASE,
)

# Trailing characters to strip from a captured URL (markdown / sentence
# punctuation that is almost never part of a real URL).
_TRAILING_STRIP_CHARS = ".,;:!?)]}>"

# Hosts to SKIP probing (mailto, .local, internal, known anti-bot guards
# that return 403 on HEAD even when content is live).
_SKIP_HOST_PATTERNS = [
    r"^localhost$",
    r"^127\.",
    r"^192\.168\.",
    r"^10\.",
    r"^172\.(?:1[6-9]|2[0-9]|3[01])\.",
    r"\.local$",
    r"^example\.(?:com|org|net)$",
    r"^test\.(?:com|org|net)$",
]
_SKIP_HOST_RE = re.compile("|".join(f"(?:{p})" for p in _SKIP_HOST_PATTERNS), re.IGNORECASE)

# Schemes to SKIP entirely.
_SKIP_SCHEMES = ("mailto", "tel", "javascript", "data", "file", "ftp")

# User-agent string that is more likely to get a normal response than the
# default urllib UA (which many sites 403 on HEAD).
_USER_AGENT = (
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) "
    "AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/120.0.0.0 Safari/537.36 "
    "(auditooor R54 liveness gate)"
)

# Status codes that are considered DEAD.
_DEAD_STATUSES = {404, 410}
_DEAD_STATUS_RANGES = (range(500, 600),)

# Status codes that are considered LIVE (2xx and 3xx).
_LIVE_STATUS_RANGES = (range(200, 400),)

# Status codes that are AMBIGUOUS (treat as live unless HEAD-vs-GET mismatch).
# 401/403/429 frequently fire on HEAD against live content (anti-bot, login walls).
_AMBIGUOUS_STATUSES = {401, 403, 429}

# Rebuttal patterns.
_REBUTTAL_HTML_RE = re.compile(
    r"<!--\s*r54-rebuttal\s*:\s*(.{1,300}?)\s*-->",
    re.IGNORECASE | re.DOTALL,
)
_REBUTTAL_INLINE_RE = re.compile(
    r"(?im)^\s*[-*]?\s*r54-rebuttal\s*:\s*(.{1,300}?)\s*$",
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
def _read_text(path: Path) -> str:
    return path.read_text(encoding="utf-8", errors="replace")


def _detect_severity(text: str, cli_severity: str) -> str:
    if cli_severity != "auto":
        return cli_severity.lower()
    for pattern in (
        r"(?im)^\s*\**\s*Severity\s*:\**\s*(Critical|High|Medium|Low)\b",
        r"(?im)^\s*severity_tier\s*:\s*(Critical|High|Medium|Low)\b",
        r"(?im)^\s*selected_severity\s*:\s*(Critical|High|Medium|Low)\b",
        r"\*\*severity\*\*\s*:\s*(Critical|High|Medium|Low)\b",
    ):
        m = re.search(pattern, text)
        if m:
            return m.group(1).lower()
    return "unknown"


def _parse_rebuttal(text: str) -> str | None:
    m = _REBUTTAL_HTML_RE.search(text)
    if not m:
        m = _REBUTTAL_INLINE_RE.search(text)
    if not m:
        return None
    reason = " ".join(m.group(1).split())
    if not reason or len(reason) > REBUTTAL_MAX_CHARS:
        return None
    return reason


def _extract_urls(text: str) -> list[str]:
    """Return de-duplicated list of external URLs cited in the draft."""
    raw_urls: list[str] = []
    seen: set[str] = set()
    for m in _URL_RE.finditer(text):
        url = m.group("url")
        # Strip trailing punctuation
        while url and url[-1] in _TRAILING_STRIP_CHARS:
            url = url[:-1]
        # Markdown link suffix: ![alt](url) - already handled by regex stop chars
        if not url:
            continue
        if url in seen:
            continue
        seen.add(url)
        raw_urls.append(url)
    return raw_urls


def _should_skip(url: str) -> tuple[bool, str | None]:
    """Return (skip?, reason)."""
    try:
        parsed = urlparse(url)
    except Exception as exc:
        return True, f"unparseable: {exc}"
    if parsed.scheme.lower() in _SKIP_SCHEMES:
        return True, f"scheme-skipped: {parsed.scheme}"
    host = (parsed.hostname or "").lower()
    if not host:
        return True, "no-host"
    if _SKIP_HOST_RE.search(host):
        return True, f"host-skipped: {host}"
    return False, None


def _probe_url(
    url: str,
    timeout: float,
    *,
    method: str = "HEAD",
) -> dict[str, Any]:
    """Probe a single URL. Return dict with status/error/method-used."""
    req = url_request.Request(url, method=method)
    req.add_header("User-Agent", _USER_AGENT)
    req.add_header("Accept", "*/*")
    try:
        with url_request.urlopen(req, timeout=timeout) as resp:
            code = resp.getcode()
            return {"status": code, "method": method, "error": None}
    except url_error.HTTPError as exc:
        code = exc.code
        # Some servers return 405 / 501 on HEAD; retry GET (range probe).
        if method == "HEAD" and code in (405, 501):
            return _probe_url(url, timeout, method="GET")
        return {"status": code, "method": method, "error": f"HTTP {code}"}
    except url_error.URLError as exc:
        reason = getattr(exc, "reason", exc)
        # Network unreachable / DNS failure / timeout
        return {"status": None, "method": method, "error": f"url-error: {reason}"}
    except socket.timeout:
        return {"status": None, "method": method, "error": "timeout"}
    except (ConnectionError, OSError) as exc:
        return {"status": None, "method": method, "error": f"connection: {exc}"}
    except Exception as exc:  # noqa: BLE001 - defensive
        return {"status": None, "method": method, "error": f"unexpected: {exc}"}


def _classify(status: int | None) -> str:
    """Classify a HTTP status code. Returns: live | dead | ambiguous | unknown."""
    if status is None:
        return "unknown"
    if status in _DEAD_STATUSES:
        return "dead"
    for r in _DEAD_STATUS_RANGES:
        if status in r:
            return "dead"
    if status in _AMBIGUOUS_STATUSES:
        return "ambiguous"
    for r in _LIVE_STATUS_RANGES:
        if status in r:
            return "live"
    return "unknown"


# ---------------------------------------------------------------------------
# Core check
# ---------------------------------------------------------------------------
def check(
    draft_path: Path,
    *,
    severity_cli: str = "auto",
    strict: bool = False,
    timeout: float = DEFAULT_TIMEOUT_S,
    probe_fn=None,  # injectable for tests
) -> dict[str, Any]:
    """Run R54 against a draft. Returns verdict dict."""
    try:
        text = _read_text(draft_path)
    except OSError as exc:
        return {
            "verdict": "error",
            "reason": f"cannot read draft: {exc}",
            "gate": GATE,
            "schema": SCHEMA_VERSION,
        }

    severity = _detect_severity(text, severity_cli)

    # Rebuttal short-circuit (before URL scan).
    rebuttal = _parse_rebuttal(text)
    if rebuttal:
        return {
            "verdict": "ok-rebuttal",
            "reason": f"r54-rebuttal accepted: {rebuttal}",
            "gate": GATE,
            "schema": SCHEMA_VERSION,
            "severity": severity,
            "strict": strict,
        }

    urls = _extract_urls(text)
    payload: dict[str, Any] = {
        "gate": GATE,
        "schema": SCHEMA_VERSION,
        "severity": severity,
        "strict": strict,
        "timeout_s": timeout,
        "total_urls_extracted": len(urls),
    }

    if not urls:
        payload["verdict"] = "pass-no-external-urls"
        payload["reason"] = "draft cites no external URLs"
        return payload

    if probe_fn is None:
        probe_fn = _probe_url

    probe_results: list[dict[str, Any]] = []
    skipped: list[dict[str, str]] = []
    dead: list[dict[str, Any]] = []
    ambiguous: list[dict[str, Any]] = []
    live: list[dict[str, Any]] = []
    network_failures: list[dict[str, Any]] = []

    for url in urls:
        skip, skip_reason = _should_skip(url)
        if skip:
            skipped.append({"url": url, "reason": skip_reason or "skipped"})
            continue
        probe = probe_fn(url, timeout)
        record = {
            "url": url,
            "status": probe.get("status"),
            "method": probe.get("method"),
            "error": probe.get("error"),
        }
        probe_results.append(record)
        cls = _classify(probe.get("status"))
        record["classification"] = cls
        if cls == "dead":
            dead.append(record)
        elif cls == "ambiguous":
            ambiguous.append(record)
        elif cls == "live":
            live.append(record)
        else:  # unknown / network failure
            network_failures.append(record)

    payload["urls"] = probe_results
    payload["skipped"] = skipped
    payload["counts"] = {
        "live": len(live),
        "dead": len(dead),
        "ambiguous": len(ambiguous),
        "network_failures": len(network_failures),
        "skipped": len(skipped),
        "probed": len(probe_results),
    }

    # Decision tree
    if dead:
        payload["verdict"] = "fail-dead-url-cited"
        first = dead[0]
        payload["reason"] = (
            f"{len(dead)} dead URL(s) cited; first: {first['url']} -> HTTP {first['status']}. "
            "Replace with a live URL or add 'r54-rebuttal: <reason>' (<=200 chars) explaining "
            "why the dead URL is intentional (e.g. archival reference to a removed gist)."
        )
        payload["dead_urls"] = dead
        return payload

    if network_failures and strict:
        payload["verdict"] = "fail-network-validation-failed-strict"
        first = network_failures[0]
        payload["reason"] = (
            f"{len(network_failures)} URL(s) failed network validation under --strict; "
            f"first: {first['url']} -> {first['error']}. "
            "Re-run later or override with r54-rebuttal."
        )
        payload["network_failures"] = network_failures
        return payload

    # All probed URLs are live or ambiguous (treated as live).
    payload["verdict"] = "pass-all-urls-live"
    msg_parts = [f"probed {len(probe_results)} URL(s)", f"live={len(live)}"]
    if ambiguous:
        msg_parts.append(f"ambiguous={len(ambiguous)} (treated as live)")
    if network_failures:
        msg_parts.append(f"network-failures={len(network_failures)} (warn-only, no --strict)")
    if skipped:
        msg_parts.append(f"skipped={len(skipped)}")
    payload["reason"] = ", ".join(msg_parts)
    return payload


# ---------------------------------------------------------------------------
# Batch-URL mode (Lane FFFFFF stretch, 2026-05-23)
# ---------------------------------------------------------------------------
def _load_urls_from_batch_file(path: Path) -> list[dict[str, Any]]:
    """Load a list of URLs from a file.

    Accepted formats (auto-detected per-line):
      1. Plain text - one URL per line. Comment lines start with '#'.
      2. JSONL - each line is a JSON object with at least a 'url' or
         'record_source_url' key. Other keys preserved as metadata.
      3. TSV - first column is the URL; rest is metadata.
    """
    entries: list[dict[str, Any]] = []
    for raw_line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        url = None
        meta: dict[str, Any] = {}
        if line.startswith("{") and line.endswith("}"):
            try:
                obj = json.loads(line)
                url = obj.get("url") or obj.get("record_source_url")
                meta = {k: v for k, v in obj.items() if k not in ("url", "record_source_url")}
            except json.JSONDecodeError:
                url = line
        elif "\t" in line:
            parts = line.split("\t")
            url = parts[0].strip()
            if len(parts) > 1:
                meta["extra"] = parts[1:]
        else:
            url = line
        if not url:
            continue
        entries.append({"url": url, "meta": meta})
    return entries


def batch_check(
    urls_file: Path,
    *,
    strict: bool = False,
    timeout: float = DEFAULT_TIMEOUT_S,
    probe_fn=None,
) -> dict[str, Any]:
    """Run R54 against a batch URL file. Returns aggregate verdict + per-URL detail."""
    if probe_fn is None:
        probe_fn = _probe_url
    try:
        entries = _load_urls_from_batch_file(urls_file)
    except OSError as exc:
        return {
            "verdict": "error",
            "reason": f"cannot read batch file: {exc}",
            "gate": GATE,
            "schema": SCHEMA_VERSION,
        }

    payload: dict[str, Any] = {
        "gate": GATE,
        "schema": SCHEMA_VERSION,
        "mode": "batch",
        "input_file": str(urls_file),
        "strict": strict,
        "timeout_s": timeout,
        "total_urls_in_file": len(entries),
    }

    if not entries:
        payload["verdict"] = "pass-no-external-urls"
        payload["reason"] = "batch file is empty (no URLs to probe)"
        payload["counts"] = {"live": 0, "dead": 0, "ambiguous": 0,
                             "network_failures": 0, "skipped": 0, "probed": 0}
        return payload

    probe_results: list[dict[str, Any]] = []
    skipped: list[dict[str, str]] = []
    dead: list[dict[str, Any]] = []
    ambiguous: list[dict[str, Any]] = []
    live: list[dict[str, Any]] = []
    network_failures: list[dict[str, Any]] = []

    for entry in entries:
        url = entry["url"]
        meta = entry.get("meta", {})
        skip, skip_reason = _should_skip(url)
        if skip:
            skipped.append({"url": url, "reason": skip_reason or "skipped", "meta": meta})
            continue
        probe = probe_fn(url, timeout)
        record = {
            "url": url,
            "status": probe.get("status"),
            "method": probe.get("method"),
            "error": probe.get("error"),
            "meta": meta,
        }
        cls = _classify(probe.get("status"))
        record["classification"] = cls
        probe_results.append(record)
        if cls == "dead":
            dead.append(record)
        elif cls == "ambiguous":
            ambiguous.append(record)
        elif cls == "live":
            live.append(record)
        else:
            network_failures.append(record)

    payload["urls"] = probe_results
    payload["skipped"] = skipped
    payload["counts"] = {
        "live": len(live),
        "dead": len(dead),
        "ambiguous": len(ambiguous),
        "network_failures": len(network_failures),
        "skipped": len(skipped),
        "probed": len(probe_results),
    }

    if dead:
        payload["verdict"] = "fail-dead-url-cited"
        first = dead[0]
        payload["reason"] = (
            f"{len(dead)} dead URL(s) in batch; first: {first['url']} -> HTTP {first['status']}"
        )
        payload["dead_urls"] = dead
        return payload

    if network_failures and strict:
        payload["verdict"] = "fail-network-validation-failed-strict"
        first = network_failures[0]
        payload["reason"] = (
            f"{len(network_failures)} URL(s) failed network validation under --strict; "
            f"first: {first['url']} -> {first['error']}"
        )
        payload["network_failures"] = network_failures
        return payload

    payload["verdict"] = "pass-all-urls-live"
    msg_parts = [f"probed {len(probe_results)} URL(s)", f"live={len(live)}"]
    if ambiguous:
        msg_parts.append(f"ambiguous={len(ambiguous)} (treated as live)")
    if network_failures:
        msg_parts.append(f"network-failures={len(network_failures)} (warn-only)")
    if skipped:
        msg_parts.append(f"skipped={len(skipped)}")
    payload["reason"] = ", ".join(msg_parts)
    return payload


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------
def main() -> int:
    parser = argparse.ArgumentParser(
        description="Rule 54 External-URL-liveness preflight check (Check #101)",
    )
    parser.add_argument(
        "draft",
        type=Path,
        nargs="?",
        default=None,
        help="Path to draft .md file (omit when using --batch-urls)",
    )
    parser.add_argument(
        "--batch-urls",
        type=Path,
        default=None,
        help=(
            "Path to a batch URL file (plain text one-per-line, JSONL with "
            "'url' or 'record_source_url' key, or TSV with URL in column 1). "
            "Lane FFFFFF stretch (2026-05-23): enables corpus-wide URL "
            "validation as a one-shot operation."
        ),
    )
    parser.add_argument(
        "--severity",
        choices=["auto", "low", "medium", "high", "critical"],
        default="auto",
        help="Override severity detection (default: auto). Ignored in --batch-urls mode.",
    )
    parser.add_argument(
        "--strict",
        action="store_true",
        help="Promote network-failure to fail (default: warn-only)",
    )
    parser.add_argument(
        "--timeout",
        type=float,
        default=DEFAULT_TIMEOUT_S,
        help=f"HTTP probe timeout in seconds (default: {DEFAULT_TIMEOUT_S})",
    )
    parser.add_argument(
        "--json",
        dest="json_out",
        action="store_true",
        help="Emit result as JSON",
    )
    args = parser.parse_args()

    if args.batch_urls is not None:
        if args.draft is not None:
            print(
                "ERROR: cannot use positional draft and --batch-urls together",
                file=sys.stderr,
            )
            return 2
        if not args.batch_urls.exists():
            err = {
                "verdict": "error",
                "reason": f"batch file not found: {args.batch_urls}",
                "gate": GATE,
                "schema": SCHEMA_VERSION,
            }
            if args.json_out:
                print(json.dumps(err))
            else:
                print(f"ERROR: {err['reason']}", file=sys.stderr)
            return 2
        result = batch_check(
            args.batch_urls,
            strict=args.strict,
            timeout=args.timeout,
        )
    else:
        if args.draft is None:
            print(
                "ERROR: must supply either a draft path or --batch-urls",
                file=sys.stderr,
            )
            return 2
        if not args.draft.exists():
            err = {
                "verdict": "error",
                "reason": f"File not found: {args.draft}",
                "gate": GATE,
                "schema": SCHEMA_VERSION,
            }
            if args.json_out:
                print(json.dumps(err))
            else:
                print(f"ERROR: {err['reason']}", file=sys.stderr)
            return 2
        result = check(
            args.draft,
            severity_cli=args.severity,
            strict=args.strict,
            timeout=args.timeout,
        )

    if args.json_out:
        print(json.dumps(result, indent=2, default=str))
    else:
        verdict = result["verdict"]
        reason = result.get("reason", "")
        counts = result.get("counts", {})
        print(f"[{GATE}] {verdict}: {reason}")
        if counts:
            print(
                f"  counts: live={counts.get('live',0)} dead={counts.get('dead',0)} "
                f"ambiguous={counts.get('ambiguous',0)} "
                f"network-failures={counts.get('network_failures',0)} "
                f"skipped={counts.get('skipped',0)}"
            )
        for d in result.get("dead_urls", [])[:5]:
            print(f"  DEAD: {d['url']} -> HTTP {d['status']}")

    verdict = result["verdict"]
    if verdict == "error":
        return 2
    if verdict.startswith("fail"):
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
