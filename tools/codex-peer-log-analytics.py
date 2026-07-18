#!/usr/bin/env python3
"""capability-v3 iter-v3-8 T2 — Codex peer-log analytics.

Read-only, stdlib-only parser for ``docs/CAPABILITY_V3_CODEX_LOG.md`` (the
log bootstrapped in iter-v3-5 T4 and appended by the cron-wired
``tools/codex-peer-poll.py --log-append`` every 10 min, per iter-v3-7 T5).

This tool is *strictly* a telemetry parser:

- It never issues network requests.
- It never shells out to ``gh``, ``git``, or any other binary.
- It never mutates the log file (or any other file in the repo).

CLI
---
``python3 tools/codex-peer-log-analytics.py --log <path> [--since <ISO>]
[--format {json,text,v2-text}]``

Defaults: ``--log docs/CAPABILITY_V3_CODEX_LOG.md``, ``--format json``.

JSON output fields
------------------
- ``ticks``: count of ``## <ts>`` section headers in the log (after
  optional ``--since`` filtering).
- ``time_span``: ``{first_tick: <iso>, last_tick: <iso>}``, or ``null``
  if zero ticks are in scope.
- ``events_per_tick``: ``{mean, median, max, min}`` over the per-tick
  event counts. All zeros when there are no ticks.
- ``by_class``: map of classification → count, spanning the 7 classes
  documented in ``codex-peer-poll.py`` plus any unexpected class
  encountered (folded under ``unclassified`` for robustness).
- ``by_author``: map of author login → count.
- ``by_route``: map of suggested route → count (routes are free-form
  planning hints per the schema in CAPABILITY_V3_CODEX_LOG.md).
- ``honest_zero_ticks``: count of ticks whose section contains the
  marker line ``_No peer events in window._`` (including bootstrap).
- ``total_events``: sum of per-tick event counts across all ticks.

v2 extension (iter-v3-9 T3)
---------------------------
Added under a top-level ``v2`` key — v1 keys above are preserved
byte-for-byte so iter-v3-8 T2 + FIX-8A regression outputs are
unchanged. The ``v2`` object carries:

- ``rate_limit_events``: int — count of event rows whose
  ``body_preview`` contains any of the substrings ``"rate limit"``,
  ``"rate-limit"``, ``"429"``, ``"429 Too Many"``, ``"rate_limit"``
  (case-insensitive match).
- ``rate_limit_by_author``: dict[author → count] — same events
  broken down by author.
- ``event_rate_trend``: dict with:
  - ``slope_per_tick``: float — simple linear-regression slope of
    (tick_index, total_events) over the last N ticks (N=5 default).
  - ``window_ticks``: int — actual ticks used (may be < N when the
    log is short).
  - ``direction``: ``"up"`` if slope > +0.5, ``"down"`` if < -0.5,
    ``"flat"`` if |slope| <= 0.5, ``"unknown"`` if
    ``window_ticks < 3`` (honest-zero for short windows).

Text output: a compact 10-line summary meant for operator eyeballing;
no machine parsing guarantees. ``v2-text`` renders a 6-8 line v2-only
summary.

Honest-zero semantics
---------------------
- Empty log (e.g. a fresh bootstrap with zero ticks that parse) →
  ``ticks: 0, total_events: 0, time_span: null``; this is *not* an
  error, mirroring the read-only-poller contract that a zero-event
  window is a valid observation.
- A tick that prints ``_No peer events in window._`` is parsed as
  ``events=0`` and contributes ``+1`` to ``honest_zero_ticks``.
"""
from __future__ import annotations

import argparse
import datetime as _dt
import json
import re
import sys
from pathlib import Path


# The 7 classifications emitted by tools/codex-peer-poll.py (iter-v3-3 T5).
_KNOWN_CLASSES = (
    "review-feedback",
    "suggestion",
    "new-task-proposal",
    "question",
    "commit-push",
    "new-pr",
    "unclassified",
)

# Regex for a section header of the form "## <ISO-ts> — ..." (em-dash
# style as emitted by codex-peer-poll.py). We keep the capture loose:
# anything after "## " up to the first whitespace is treated as the
# timestamp candidate, then validated via fromisoformat.
_SECTION_RE = re.compile(r"^##\s+(\S+)(?:\s.*)?$")

_HONEST_ZERO_MARKER = "_No peer events in window._"

# iter-v3-9 T3 v2: case-insensitive needles for rate-limit detection in
# event body previews. Kept as a tuple of lowercase strings so the match
# is a simple ``needle in preview.lower()`` loop — stdlib-only, no regex
# dependency. Ordering is not load-bearing; duplicate hits on the same
# preview count as one event (not one per needle).
_RATE_LIMIT_NEEDLES = (
    "rate limit",
    "rate-limit",
    "rate_limit",
    "429 too many",
    "429",
)

# Default window for the event-rate trend linear regression. Plan spec
# says N=5; honest-zero when the log has fewer than 3 ticks total.
_TREND_DEFAULT_WINDOW = 5
_TREND_MIN_WINDOW = 3
_TREND_FLAT_THRESHOLD = 0.5


def _parse_iso(ts: str) -> _dt.datetime | None:
    """Parse an ISO-8601 timestamp; tolerate trailing ``Z``.

    Returns ``None`` on failure (so callers can treat the candidate
    header as "not a tick" without raising).
    """
    if not ts:
        return None
    candidate = ts[:-1] + "+00:00" if ts.endswith("Z") else ts
    try:
        return _dt.datetime.fromisoformat(candidate)
    except (TypeError, ValueError):
        return None


def _split_sections(text: str) -> list[tuple[str, list[str]]]:
    """Split the log into (timestamp, section_body_lines) tuples.

    Non-tick ``##`` headers (e.g. the legend ``## Append-only contract``
    at the top of the log) are skipped — they fail ISO parsing and are
    not counted as ticks.
    """
    sections: list[tuple[str, list[str]]] = []
    current_ts: str | None = None
    current_body: list[str] = []

    for line in text.splitlines():
        m = _SECTION_RE.match(line)
        if m is not None:
            candidate = m.group(1)
            if _parse_iso(candidate) is not None:
                # Close out the prior section (if any) before starting a new one.
                if current_ts is not None:
                    sections.append((current_ts, current_body))
                current_ts = candidate
                current_body = []
                continue
            # Non-ISO ``##`` header: if we are inside a tick, absorb
            # the line as body content; otherwise ignore legend.
            if current_ts is not None:
                current_body.append(line)
            continue
        if current_ts is not None:
            current_body.append(line)

    if current_ts is not None:
        sections.append((current_ts, current_body))
    return sections


_TABLE_ROW_RE = re.compile(r"^\|\s*(.+?)\s*\|$")
_TABLE_SEP_RE = re.compile(r"^\|\s*:?-+:?\s*(\|\s*:?-+:?\s*)+\|$")

# Split on ``|`` that is *not* preceded by a backslash. This mirrors the
# producer escape in tools/codex-peer-poll.py (see L657-658: body preview
# pipes are escaped as ``\|`` so the pipe char survives in-row). A raw
# ``split("|")`` would over-shard any body preview that contains a
# literal pipe and silently drop the row on the ``len(cells) !=
# len(columns)`` defensive guard below (FIX-8A regression from
# iter-v3-8 T2; see docs/FIX8A_PEER_LOG_ESCAPED_PIPE.md).
_ESCAPED_PIPE_SPLIT_RE = re.compile(r"(?<!\\)\|")


def _split_table_row(row_content: str) -> list[str]:
    """Split a markdown table row on unescaped pipes, then un-escape.

    ``row_content`` is the inside of the row (outer ``|`` already
    stripped). Returns a list of cell strings with ``\\|`` → ``|``
    reversed so downstream consumers see the original preview bytes.
    """
    parts = _ESCAPED_PIPE_SPLIT_RE.split(row_content)
    return [p.replace("\\|", "|").strip() for p in parts]


def _parse_events_metadata(body: list[str]) -> int | None:
    """Extract the ``- events: N`` metadata count from a section body.

    Returns the integer count if present and parseable, otherwise
    ``None``. Used for the row-count cross-check (FIX-8A): if the
    parsed row count disagrees with this, the parser emits a warning.
    """
    for line in body:
        stripped = line.strip()
        if stripped.startswith("- events:"):
            tail = stripped.split(":", 1)[1].strip()
            try:
                return int(tail)
            except ValueError:
                return None
    return None


def _parse_events_table(
    body: list[str], *, warnings: list[str] | None = None, tick_ts: str = ""
) -> list[dict[str, str]]:
    """Parse the per-tick markdown event table.

    Returns a list of dict rows with keys ``type``, ``class``,
    ``author``, ``route``, ``preview``. If no table is present (e.g.
    honest-zero tick), returns ``[]``.

    If ``warnings`` is supplied, a mismatch between parsed row count
    and the ``- events: N`` metadata line (when present) appends a
    human-readable message to it; the caller is responsible for
    aggregation and/or stderr emission.
    """
    rows: list[dict[str, str]] = []
    header_seen = False
    columns: list[str] = []

    for line in body:
        stripped = line.strip()
        if not stripped.startswith("|"):
            # We allow non-table text between the section header and the
            # table (the tool emits a prelude with ``- since:`` etc.).
            # Once we've seen the header we stop parsing at the first
            # non-table line to avoid sweeping unrelated content.
            if header_seen:
                break
            continue
        if _TABLE_SEP_RE.match(stripped):
            continue
        # Strip the outer pipes before escaped-pipe-aware split. We use
        # the regex-driven splitter so a ``\|`` inside a body preview
        # survives as a single cell (producer escapes pipes at
        # codex-peer-poll.py:657-658).
        cells = _split_table_row(stripped.strip("|"))
        if not header_seen:
            columns = [c.lower() for c in cells]
            header_seen = True
            continue
        if len(cells) != len(columns):
            # Malformed row — skip defensively rather than crashing.
            if warnings is not None:
                warnings.append(
                    f"tick={tick_ts or '<unknown>'}: malformed row "
                    f"(got {len(cells)} cells, expected {len(columns)}): "
                    f"{stripped!r}"
                )
            continue
        rows.append(dict(zip(columns, cells)))
    return rows


def _median(values: list[int]) -> int:
    if not values:
        return 0
    srt = sorted(values)
    mid = len(srt) // 2
    if len(srt) % 2 == 1:
        return srt[mid]
    # Conventional integer-floor median for even counts — the plan spec
    # types ``median`` as int.
    return (srt[mid - 1] + srt[mid]) // 2


def _mean(values: list[int]) -> float:
    if not values:
        return 0.0
    return sum(values) / len(values)


def _row_is_rate_limit(row: dict[str, str]) -> bool:
    """Return True iff the row's ``preview`` cell hits a rate-limit needle.

    Matches against the body-preview cell only (not class/route) so
    unrelated hits on e.g. the literal string "rate-limit" appearing in
    a route label don't inflate the count. Matching is case-insensitive
    and substring-based.
    """
    preview = row.get("preview", "")
    if not preview:
        return False
    lowered = preview.lower()
    return any(needle in lowered for needle in _RATE_LIMIT_NEEDLES)


def _linear_regression_slope(xs: list[int], ys: list[int]) -> float:
    """Simple least-squares slope of y on x. Returns 0.0 if variance=0.

    Stdlib-only: no ``statistics.linear_regression`` (added 3.10 but we
    keep the hand-rolled form so older interpreters still parse the
    tool). xs and ys must have equal, non-zero length — the caller
    guarantees this (window >= 3).
    """
    n = len(xs)
    if n == 0:
        return 0.0
    mean_x = sum(xs) / n
    mean_y = sum(ys) / n
    num = 0.0
    den = 0.0
    for x, y in zip(xs, ys):
        dx = x - mean_x
        num += dx * (y - mean_y)
        den += dx * dx
    if den == 0.0:
        return 0.0
    return num / den


def compute_v2_fields(
    summary_v1: dict,
    ticks: list[tuple[str, list[dict[str, str]]]],
    *,
    window_n: int = _TREND_DEFAULT_WINDOW,
) -> dict:
    """Compute v2 analytics fields.

    Parameters
    ----------
    summary_v1
        The v1 summary dict (currently only consulted for robustness;
        the per-tick info comes from ``ticks``). Accepted to keep the
        spec'd signature and to make callers explicit about the v1
        dependency.
    ticks
        An ordered list of ``(tick_ts, event_rows)`` pairs matching the
        ``analyze`` internal per-tick state. ``event_rows`` is the
        list-of-dicts already parsed from the markdown table (or an
        empty list for honest-zero ticks).
    window_n
        Size of the trailing window used for the event-rate-trend
        regression. Defaults to 5; honest-zero to ``"unknown"`` if
        fewer than ``_TREND_MIN_WINDOW`` ticks are available.
    """
    # Accept summary_v1 to match the plan signature; not currently
    # consulted beyond this (ticks carry everything we need). Coercion
    # avoids an unused-arg lint.
    _ = summary_v1

    rate_limit_events = 0
    rate_limit_by_author: dict[str, int] = {}

    for _ts, rows in ticks:
        for row in rows:
            if _row_is_rate_limit(row):
                rate_limit_events += 1
                author = row.get("author", "").strip() or "<unknown>"
                rate_limit_by_author[author] = (
                    rate_limit_by_author.get(author, 0) + 1
                )

    # Event-rate trend: regress (tick_index, tick_event_count) over the
    # trailing window_n ticks. Honest-zero for window_ticks < 3.
    event_counts = [len(rows) for _ts, rows in ticks]
    window = event_counts[-window_n:] if window_n > 0 else []
    window_ticks = len(window)

    if window_ticks < _TREND_MIN_WINDOW:
        slope = 0.0
        direction = "unknown"
    else:
        xs = list(range(window_ticks))
        slope = _linear_regression_slope(xs, window)
        if slope > _TREND_FLAT_THRESHOLD:
            direction = "up"
        elif slope < -_TREND_FLAT_THRESHOLD:
            direction = "down"
        else:
            direction = "flat"

    return {
        "rate_limit_events": rate_limit_events,
        "rate_limit_by_author": rate_limit_by_author,
        "event_rate_trend": {
            "slope_per_tick": round(float(slope), 4),
            "window_ticks": window_ticks,
            "direction": direction,
        },
    }


def analyze(text: str, since: _dt.datetime | None = None) -> dict:
    """Compute analytics over the given log text.

    ``since`` is inclusive: ticks with timestamp ``>= since`` are kept.
    """
    sections = _split_sections(text)

    # Optional --since filter.
    if since is not None:
        filtered: list[tuple[str, list[str]]] = []
        for ts, body in sections:
            parsed = _parse_iso(ts)
            if parsed is None:
                continue
            # Compare as naive UTC to avoid tz-aware/naive mix.
            parsed_naive = parsed.replace(tzinfo=None)
            since_naive = since.replace(tzinfo=None) if since.tzinfo else since
            if parsed_naive >= since_naive:
                filtered.append((ts, body))
        sections = filtered

    ticks = len(sections)
    if ticks == 0:
        v1_empty = {
            "ticks": 0,
            "time_span": None,
            "events_per_tick": {"mean": 0.0, "median": 0, "max": 0, "min": 0},
            "by_class": {cls: 0 for cls in _KNOWN_CLASSES},
            "by_author": {},
            "by_route": {},
            "honest_zero_ticks": 0,
            "total_events": 0,
            "parse_warnings": 0,
        }
        v1_empty["v2"] = compute_v2_fields(v1_empty, [])
        return v1_empty

    timestamps = [ts for ts, _ in sections]
    events_per_tick: list[int] = []
    by_class: dict[str, int] = {cls: 0 for cls in _KNOWN_CLASSES}
    by_author: dict[str, int] = {}
    by_route: dict[str, int] = {}
    honest_zero_ticks = 0
    total_events = 0
    warnings: list[str] = []
    # v2 feed: (tick_ts, parsed_rows) preserved in log order so
    # compute_v2_fields sees the same view analyze() did.
    per_tick_rows: list[tuple[str, list[dict[str, str]]]] = []

    for _ts, body in sections:
        joined = "\n".join(body)
        is_honest_zero = _HONEST_ZERO_MARKER in joined
        rows = _parse_events_table(body, warnings=warnings, tick_ts=_ts)
        n_events = len(rows)
        per_tick_rows.append((_ts, rows))

        # FIX-8A: cross-check parsed row count against the tick's
        # ``- events: N`` metadata line (when present). Mismatches
        # surface as parse_warnings rather than silent drops.
        meta_count = _parse_events_metadata(body)
        if meta_count is not None and meta_count != n_events and not is_honest_zero:
            warnings.append(
                f"tick={_ts}: events metadata says {meta_count} but parsed {n_events} rows"
            )

        if is_honest_zero:
            honest_zero_ticks += 1
            # By contract, honest-zero ticks contribute 0 events even
            # if a stray table appears — but the real emitter omits the
            # table in that case. We still defer to the parsed count if
            # non-zero, so fixture anomalies surface rather than hide.
        events_per_tick.append(n_events)
        total_events += n_events

        for row in rows:
            cls = row.get("class", "").strip() or "unclassified"
            if cls not in by_class:
                by_class["unclassified"] += 1
            else:
                by_class[cls] += 1
            author = row.get("author", "").strip()
            if author:
                by_author[author] = by_author.get(author, 0) + 1
            route = row.get("route", "").strip()
            if route and route != "—":
                by_route[route] = by_route.get(route, 0) + 1

    # Surface warnings on stderr for operator visibility, but do not
    # raise — the analytics tool stays read-only and best-effort.
    for w in warnings:
        print(f"warning: {w}", file=sys.stderr)

    summary = {
        "ticks": ticks,
        "time_span": {"first_tick": timestamps[0], "last_tick": timestamps[-1]},
        "events_per_tick": {
            "mean": round(_mean(events_per_tick), 4),
            "median": _median(events_per_tick),
            "max": max(events_per_tick),
            "min": min(events_per_tick),
        },
        "by_class": by_class,
        "by_author": by_author,
        "by_route": by_route,
        "honest_zero_ticks": honest_zero_ticks,
        "total_events": total_events,
        "parse_warnings": len(warnings),
    }
    # iter-v3-9 T3: attach v2 fields under a dedicated top-level key
    # so v1 consumers keep byte-for-byte compatibility when they strip
    # the ``v2`` key (see test_v1_keys_unchanged_byte_for_byte).
    summary["v2"] = compute_v2_fields(summary, per_tick_rows)
    return summary


def format_text(summary: dict) -> str:
    """Render a 10-line-ish human-readable summary."""
    lines = []
    lines.append("Peer log analytics — Codex peer-poll telemetry")
    span = summary["time_span"]
    if span is None:
        lines.append("  time_span: <no ticks>")
    else:
        lines.append(f"  time_span: {span['first_tick']} → {span['last_tick']}")
    lines.append(f"  ticks: {summary['ticks']}  total_events: {summary['total_events']}")
    lines.append(f"  honest_zero_ticks: {summary['honest_zero_ticks']}")
    ept = summary["events_per_tick"]
    lines.append(
        "  events_per_tick: mean={mean} median={median} max={max} min={min}".format(**ept)
    )
    top_classes = sorted(summary["by_class"].items(), key=lambda kv: -kv[1])[:5]
    lines.append("  top_classes: " + ", ".join(f"{k}={v}" for k, v in top_classes))
    top_authors = sorted(summary["by_author"].items(), key=lambda kv: -kv[1])[:3]
    if top_authors:
        lines.append("  top_authors: " + ", ".join(f"{k}={v}" for k, v in top_authors))
    else:
        lines.append("  top_authors: <none>")
    top_routes = sorted(summary["by_route"].items(), key=lambda kv: -kv[1])[:3]
    if top_routes:
        lines.append("  top_routes:  " + ", ".join(f"{k}={v}" for k, v in top_routes))
    else:
        lines.append("  top_routes:  <none>")
    lines.append("  (read-only parse; no network/git/gh calls)")
    return "\n".join(lines)


def format_v2_text(summary: dict) -> str:
    """Render a 6-8 line human-readable v2 summary.

    Defensive re: missing v2 key (e.g. hand-built summaries from tests)
    — emits a one-line marker rather than raising.
    """
    v2 = summary.get("v2")
    if not isinstance(v2, dict):
        return "Peer log analytics (v2) — no v2 data available"
    trend = v2.get("event_rate_trend", {}) or {}
    lines = []
    lines.append("Peer log analytics (v2) — Codex peer-poll telemetry")
    lines.append(f"  rate_limit_events: {v2.get('rate_limit_events', 0)}")
    by_author = v2.get("rate_limit_by_author", {}) or {}
    if by_author:
        top = sorted(by_author.items(), key=lambda kv: -kv[1])[:3]
        lines.append(
            "  rate_limit_by_author: "
            + ", ".join(f"{k}={v}" for k, v in top)
        )
    else:
        lines.append("  rate_limit_by_author: <none>")
    lines.append(
        "  event_rate_trend: direction={direction} "
        "slope_per_tick={slope_per_tick} window_ticks={window_ticks}".format(
            direction=trend.get("direction", "unknown"),
            slope_per_tick=trend.get("slope_per_tick", 0.0),
            window_ticks=trend.get("window_ticks", 0),
        )
    )
    lines.append(f"  ticks: {summary.get('ticks', 0)}  total_events: {summary.get('total_events', 0)}")
    lines.append("  (v1 keys preserved above; read-only parse)")
    return "\n".join(lines)


def _build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="codex-peer-log-analytics",
        description=(
            "Stdlib-only, read-only parser for "
            "docs/CAPABILITY_V3_CODEX_LOG.md. Emits structured JSON "
            "(default) or a text summary of Codex peer-cadence trends."
        ),
    )
    p.add_argument(
        "--log",
        default="docs/CAPABILITY_V3_CODEX_LOG.md",
        help="Path to the peer-poll log (default: docs/CAPABILITY_V3_CODEX_LOG.md).",
    )
    p.add_argument(
        "--since",
        default=None,
        help="Inclusive ISO-8601 cutoff — only ticks at or after this timestamp are counted.",
    )
    p.add_argument(
        "--format",
        choices=("json", "text", "v2-text"),
        default="json",
        help="Output format (default: json). ``v2-text`` renders a 6-8 line summary of v2 fields only.",
    )
    return p


def main(argv: list[str] | None = None) -> int:
    parser = _build_parser()
    args = parser.parse_args(argv)

    log_path = Path(args.log)
    if not log_path.is_file():
        print(f"error: log not found: {log_path}", file=sys.stderr)
        return 2

    since: _dt.datetime | None = None
    if args.since is not None:
        parsed = _parse_iso(args.since)
        if parsed is None:
            print(f"error: --since is not a valid ISO-8601 timestamp: {args.since!r}", file=sys.stderr)
            return 2
        since = parsed

    text = log_path.read_text(encoding="utf-8")
    summary = analyze(text, since=since)

    if args.format == "json":
        print(json.dumps(summary, indent=2, sort_keys=True))
    elif args.format == "v2-text":
        print(format_v2_text(summary))
    else:
        print(format_text(summary))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
