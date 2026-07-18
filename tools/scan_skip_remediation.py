#!/usr/bin/env python3
"""scan_skip_remediation.py — extract skip/error rows + remediation hints
from raw scan logs (slither / semgrep / 4naly3er / crytic-compile / etc).

Background
----------
Closes P2-3 from ``docs/KNOWN_LIMITATIONS.md`` and item #17 of the V5
overnight handover plan: scan-skip *counts* and detector environment
manifests already surface in close-out, but the operator still has to read
through raw ``run_custom.log`` / ``apply_queries.log`` to learn *which*
modules failed and *why*. This module parses the raw text and produces a
deterministic list of ``SkipRow`` records:

    SkipRow(tool=..., module=..., error_class=..., error_excerpt=..., hint=...)

The hint is human-readable and operator-actionable. Common patterns:

  * "no compiler version matches" / "Source file requires different compiler"
    → ``solc-select install <version> && solc-select use <version>`` hint
  * "ParserError" / "SyntaxError" → file path + line + edit/upgrade hint
  * "ImportError: file not found" / "Source <X> not found" → remappings.txt
    advisory
  * Anything else → "unknown — see scan log <path>" placeholder so a row is
    still surfaced.

Discipline
----------
Stdlib only. Pure parsing — no I/O beyond ``parse_log_file`` (which is just
a thin wrapper around ``Path.read_text``), no network. The orchestrator
and the closeout tool share this module, so the parsing surface is
exercised by a single unit-test set
(``tools/tests/test_scan_skip_remediation.py``).

Schema
------
``SkipRow.to_dict()`` is JSON-safe and stable. ``audit_closeout_manifest
.json`` and ``detector_environment_manifest.json`` embed top-N rows under
``skipped_modules`` with ``schema_version`` ``auditooor.scan_skip
_remediation.v1``.

Stricter mode
-------------
Callers (the closeout gate) can flip ``REQUIRE_NO_SCAN_SKIPS=1`` in the
environment to promote >N skip rows from WARN to FAIL. The threshold is
configurable via ``REQUIRE_NO_SCAN_SKIPS_THRESHOLD`` (default 0 — *any*
skip row fails). The module itself doesn't read the env eagerly; it only
exposes ``promote_to_fail(rows, *, threshold)`` so the closeout integrates
cleanly.
"""
from __future__ import annotations

import os
import re
from dataclasses import dataclass, asdict
from pathlib import Path
from typing import Iterable


SCHEMA_VERSION = "auditooor.scan_skip_remediation.v1"

# Top-N rows we surface in the human closeout / manifest. Anything beyond
# this stays in the raw log files (the operator can grep). 5 is a balance
# between "operator sees the foot-gun shape" and "report stays one screen".
DEFAULT_TOP_N = 5


# ---- error class taxonomy --------------------------------------------------

# Each tuple: (error_class, regex, hint_template). The first matching row
# wins — order matters. ``hint_template`` may use ``{module}`` and
# ``{detail}`` placeholders that we substitute at parse time.

_ERROR_CLASSES: list[tuple[str, "re.Pattern[str]", str]] = [
    # solc version mismatches — both crytic-compile and forge surface this.
    (
        "solc-version-mismatch",
        re.compile(
            r"(?:no compiler version matches"
            r"|Source file requires different compiler version"
            r"|Try using --solc-select"
            r"|solc-select install"
            r"|solc.*not installed"
            r"|Couldn't compile.*requires.*solc.*version)",
            re.IGNORECASE,
        ),
        "run `solc-select install {detail} && solc-select use {detail}` "
        "(detected from `{module}`); rerun the scan after install",
    ),
    # ImportError / file-not-found — usually a missing remapping.
    (
        "missing-remapping",
        re.compile(
            r"(?:Source\s+\"?[^\"]+\"?\s+not found"
            r"|ImportError:.*file not found"
            r"|File not found:"
            r"|could not resolve import"
            r"|Source not found:"
            r"|@.*\":\s+File not found)",
            re.IGNORECASE,
        ),
        "missing import in `{module}` — add a remapping entry "
        "(see `remappings.txt` / `foundry.toml [profile.*].remappings`) "
        "for `{detail}` and rerun",
    ),
    # ParserError / SyntaxError — file:line in the body.
    (
        "parser-error",
        re.compile(
            r"(?:ParserError"
            r"|SyntaxError"
            r"|TypeError:.*not implemented"
            r"|DeclarationError"
            r"|FatalError)",
            re.IGNORECASE,
        ),
        "syntax/parser failure in `{module}`{detail}; "
        "open the file and either upgrade pragma, fix the syntax, or "
        "exclude the path from the scan",
    ),
    # crytic-compile orchestration failures — usually wrap one of the above.
    (
        "crytic-compile-failed",
        re.compile(
            r"(?:crytic[- ]compile failed"
            r"|Slither compile failed"
            r"|compilation failed"
            r"|Compilation aborted"
            r"|Failed to compile)",
            re.IGNORECASE,
        ),
        "crytic-compile/Slither could not produce IR for `{module}`; "
        "check `forge build` against the same root, then rerun",
    ),
    # Generic FAILED exit / SKIPPED markers from scan-per-module.sh.
    (
        "scan-runner-failed",
        re.compile(
            r"(?:FAILED exit=\d+"
            r"|SKIPPED \(rc=\d+\)"
            r"|\[SKIPPED\]"
            r"|\[ERROR\])",
            re.IGNORECASE,
        ),
        "scan runner reported a non-zero exit for `{module}`; "
        "see the per-tool log for the underlying error",
    ),
]


# Module name extraction. Lines vary by tool; we accept any of:
#   "=== module: <name> (FAILED exit=2 ...) ==="    # scan-per-module.sh
#   "=== Running <det> on <name>"                    # run_custom.py
#   "[<file.sol>:LINE:COL]"                          # slither
#   "Couldn't compile <path>"                        # crytic-compile
_MODULE_PREFIX = re.compile(
    r"(?:===\s*module:\s*(?P<a>[^\s\(]+)"
    r"|===\s*Running\s+\S+\s+on\s+(?P<b>\S+)"
    r"|Couldn't compile\s+(?P<c>\S+)"
    r"|Failed to compile\s+(?P<d>\S+))",
    re.IGNORECASE,
)

# solc version inside an error message: "pragma solidity ^0.8.20" or
# "requires versions matching ^0.8.0" or "Source requires 0.8.13".
_SOLC_VER = re.compile(
    r"(?:requires.*?(\d+\.\d+\.\d+)"
    r"|matching\s+\^?(\d+\.\d+\.\d+)"
    r"|\bsolc[- ](\d+\.\d+\.\d+)"
    r"|pragma solidity\s+\^?(\d+\.\d+\.\d+))"
)

# file:line:col extractor for parser errors.
_FILE_LINE = re.compile(r"(?P<path>[\w./\-]+\.sol):(?P<line>\d+)(?::(?P<col>\d+))?")

# Bare quoted import target for the missing-remapping hint.
_IMPORT_TARGET = re.compile(r"\"([^\"]+\.sol)\"|'([^']+\.sol)'|@[\w/\-]+/[\w/\-]+")


@dataclass
class SkipRow:
    tool: str
    module: str
    error_class: str
    error_excerpt: str
    hint: str
    log_path: str = ""

    def to_dict(self) -> dict:
        return asdict(self)


# ---- parsers ---------------------------------------------------------------


def _extract_module(window_lines: list[str], default: str) -> str:
    """Walk a small window around an error line and pick the most recent
    module marker. Falls back to ``default`` (usually the tool name).
    """
    for ln in reversed(window_lines):
        m = _MODULE_PREFIX.search(ln)
        if m:
            for grp in ("a", "b", "c", "d"):
                val = m.group(grp)
                if val:
                    return val
    return default


def _solc_version_from(text: str) -> str:
    m = _SOLC_VER.search(text)
    if not m:
        return ""
    for grp in m.groups():
        if grp:
            return grp
    return ""


def _file_line_from(text: str) -> str:
    m = _FILE_LINE.search(text)
    if not m:
        return ""
    if m.group("col"):
        return f" at {m.group('path')}:{m.group('line')}:{m.group('col')}"
    return f" at {m.group('path')}:{m.group('line')}"


def _import_target_from(text: str) -> str:
    m = _IMPORT_TARGET.search(text)
    if not m:
        return ""
    return m.group(1) or m.group(2) or m.group(0)


def _classify_line(line: str) -> tuple[str, "re.Pattern[str] | None"] | None:
    for cls, pattern, _hint in _ERROR_CLASSES:
        if pattern.search(line):
            return cls, pattern
    return None


def _hint_for(error_class: str, *, module: str, line: str) -> str:
    template = next(
        (h for cls, _re, h in _ERROR_CLASSES if cls == error_class),
        "unknown error class — see scan log",
    )
    detail = ""
    if error_class == "solc-version-mismatch":
        detail = _solc_version_from(line) or "<solc-version>"
    elif error_class == "missing-remapping":
        detail = _import_target_from(line) or "<import-target>"
    elif error_class == "parser-error":
        detail = _file_line_from(line) or ""
    return template.format(module=module or "<module>", detail=detail)


def parse_log_text(
    text: str,
    *,
    tool: str,
    log_path: str = "",
    default_module: str = "",
) -> list[SkipRow]:
    """Return one ``SkipRow`` per distinct (module, error_class) pair
    found in ``text``. Same module + same class is deduplicated (the
    operator needs the example, not 200 copies).
    """
    if not text:
        return []
    rows: list[SkipRow] = []
    seen: set[tuple[str, str]] = set()
    lines = text.splitlines()
    for idx, line in enumerate(lines):
        cls = _classify_line(line)
        if cls is None:
            continue
        error_class, _pat = cls
        # Look back up to 30 lines for a module marker. Many tools emit
        # the marker, some blank lines, then the error.
        window_start = max(0, idx - 30)
        window = lines[window_start: idx + 1]
        module = _extract_module(window, default=default_module or tool)
        key = (module, error_class)
        if key in seen:
            continue
        seen.add(key)
        # Capture excerpt: the error line itself, trimmed.
        excerpt = line.strip()
        if len(excerpt) > 240:
            excerpt = excerpt[:237] + "..."
        # If the error_class is "unknown" we still emit a row with a
        # placeholder hint so the operator sees coverage.
        hint = _hint_for(error_class, module=module, line=line)
        rows.append(
            SkipRow(
                tool=tool,
                module=module,
                error_class=error_class,
                error_excerpt=excerpt,
                hint=hint,
                log_path=log_path,
            )
        )
    return rows


def parse_log_file(
    path: "Path | str",
    *,
    tool: str,
    default_module: str = "",
) -> list[SkipRow]:
    """Read a log file from disk and run ``parse_log_text``. Returns an
    empty list if the file is unreadable — callers tolerate missing logs.
    """
    p = Path(path)
    try:
        text = p.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return []
    return parse_log_text(
        text,
        tool=tool,
        log_path=str(p),
        default_module=default_module,
    )


def synthesize_unknown(
    *,
    tool: str,
    module: str,
    log_path: str = "",
    excerpt: str = "",
) -> SkipRow:
    """Manufacture a ``SkipRow`` for an opaque failure (no recognised
    pattern in the log). The hint is the placeholder requested in P2-3
    so the operator still sees a row pointing at the raw log.
    """
    return SkipRow(
        tool=tool,
        module=module or tool,
        error_class="unknown",
        error_excerpt=(excerpt or "(no recognised error pattern)").strip(),
        hint=(
            f"unknown — see scan log {log_path}"
            if log_path
            else "unknown — see scan log"
        ),
        log_path=log_path,
    )


# ---- aggregation -----------------------------------------------------------


def aggregate(rows: Iterable[SkipRow], *, top_n: int = DEFAULT_TOP_N) -> dict:
    """Roll up a list of ``SkipRow`` into a JSON-safe summary suitable
    for embedding in ``detector_environment_manifest.json`` /
    ``audit_closeout_manifest.json``.

    Returned shape::

        {
          "schema_version": "auditooor.scan_skip_remediation.v1",
          "row_count": <int>,
          "top_n": <int>,
          "by_error_class": {<class>: <count>, ...},
          "by_tool": {<tool>: <count>, ...},
          "rows": [<row.to_dict()>, ...]   # truncated to top_n, deterministic
        }
    """
    rows_list = list(rows)
    by_class: dict[str, int] = {}
    by_tool: dict[str, int] = {}
    for r in rows_list:
        by_class[r.error_class] = by_class.get(r.error_class, 0) + 1
        by_tool[r.tool] = by_tool.get(r.tool, 0) + 1
    # Deterministic ordering: tool, then error_class (so report rows are
    # grouped sensibly), then module name as a tie-breaker.
    rows_sorted = sorted(
        rows_list,
        key=lambda r: (r.tool, r.error_class, r.module),
    )
    truncated = [r.to_dict() for r in rows_sorted[: top_n]]
    return {
        "schema_version": SCHEMA_VERSION,
        "row_count": len(rows_list),
        "top_n": top_n,
        "by_error_class": dict(sorted(by_class.items())),
        "by_tool": dict(sorted(by_tool.items())),
        "rows": truncated,
    }


# ---- markdown rendering ----------------------------------------------------


def render_markdown_table(rows: Iterable[SkipRow]) -> str:
    """Render a ``| tool | module | error class | hint |`` markdown
    table. Returns an empty string when there are no rows — callers
    should branch on truthiness.
    """
    rows_list = list(rows)
    if not rows_list:
        return ""
    lines = [
        "| tool | module | error class | remediation hint |",
        "|------|--------|-------------|------------------|",
    ]
    for r in rows_list:
        # Pipes inside cells would break markdown rendering; replace.
        def _cell(s: str) -> str:
            return (s or "").replace("|", "\\|")

        lines.append(
            f"| `{_cell(r.tool)}` | `{_cell(r.module)}` | "
            f"{_cell(r.error_class)} | {_cell(r.hint)} |"
        )
    return "\n".join(lines)


# ---- strict-mode promotion -------------------------------------------------


def promote_to_fail(
    rows: Iterable[SkipRow] | int,
    *,
    threshold: int | None = None,
    require_no_skips: bool | None = None,
) -> bool:
    """Return True iff the close-out gate should treat this row set as a
    hard FAIL (not a WARN).

    ``rows`` may be either an iterable of ``SkipRow`` (we count them) or
    a precomputed integer count. ``require_no_skips`` mirrors the
    ``REQUIRE_NO_SCAN_SKIPS=1`` env var; when None we read it from
    ``os.environ``. ``threshold`` defaults to the
    ``REQUIRE_NO_SCAN_SKIPS_THRESHOLD`` env value, or 0 if unset
    (i.e. *any* skip row fails when strict mode is on).
    """
    if require_no_skips is None:
        require_no_skips = os.environ.get("REQUIRE_NO_SCAN_SKIPS", "").strip() in {
            "1", "true", "TRUE", "yes", "YES",
        }
    if not require_no_skips:
        return False
    if threshold is None:
        raw = os.environ.get("REQUIRE_NO_SCAN_SKIPS_THRESHOLD", "").strip()
        try:
            threshold = int(raw) if raw else 0
        except ValueError:
            threshold = 0
    count = rows if isinstance(rows, int) else sum(1 for _ in rows)
    return count > threshold
