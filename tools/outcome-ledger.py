#!/usr/bin/env python3
"""outcome-ledger.py — central submission outcome telemetry.

Per Kimi's external roadmap (priority #7, top-of-list 10/10 → 20/10):

    "Outcome telemetry is the real gate (PR 201): 18 Polymarket submissions
    tracked, but resolved signal is thin. No proven accept-rate lift from
    the new infrastructure. Fix: This is the #1 priority in the roadmap.
    Run 3 live engagements, file findings, record triager outcomes.
    Everything else is speculation until this data exists."

This tool is the *central* outcome ledger. Per-engagement SUBMISSIONS.md
files exist already (parsed by ``tools/engagement-retro.py`` for the
lessons-learned loop and by ``tools/outcome-telemetry.py`` for the
dashboard), but neither produces a stable cross-engagement, row-per-
submission ledger that future sessions can diff against to *prove* an
accept-rate lift.

The artefact this tool maintains, ``tools/outcomes.json``, is that
ledger. One row per (engagement, submission_id), schema documented
under :data:`SCHEMA_FIELDS`. Refresh re-parses the upstream
SUBMISSIONS.md files but **preserves manual annotations** on
already-known rows (payout_usd, dupe_pointer, rejection_reason,
session_id, shipped_via) — the parser cannot reliably derive these
from the markdown today, so they are operator-edited per row.

Subcommands::

    outcome-ledger.py refresh                       # re-parse all engagements
    outcome-ledger.py stats                         # aggregate counts + $ won
    outcome-ledger.py session-delta <session-id>    # vs prior session
    outcome-ledger.py validate                      # schema-check rows

Canonical ledger location (v3 Slice 6): ``reference/outcomes.jsonl``.
The historical aggregate JSON file at ``tools/outcomes.json`` is
retained for backwards compatibility with consumers that still read
the JSON-array form, but is no longer the source of truth. Pass
``--format=json`` (or ``--ledger=tools/outcomes.json``) to operate on
the legacy artifact instead.

Backwards-compat note for consumers: tools that historically read
``tools/outcomes.json`` should fall back to ``reference/outcomes.jsonl``
when the JSON file is absent. ``load_ledger`` does this automatically
when called with the default path.

Stdlib only. No new pip deps. Reuses ``engagement-retro.py``'s parser
via importlib so the three layout dispatchers (table / line_item /
section_header) stay single-source-of-truth.
"""

from __future__ import annotations

import argparse
import importlib.util
import json
import os
import re
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Tuple


# ---------------------------------------------------------------------------
# Paths & constants
# ---------------------------------------------------------------------------

THIS_FILE = Path(__file__).resolve()
TOOLS_DIR = THIS_FILE.parent
REPO_ROOT = TOOLS_DIR.parent

# Canonical ledger path per v3 Slice 6 — the JSONL stream is the source
# of truth, written one JSON object per line. ``LEDGER_PATH_JSON`` points
# at the legacy JSON-array form retained for backwards compat (writers
# opt in via ``--format=json``; readers fall back to it when JSONL is
# absent).
LEDGER_PATH = REPO_ROOT / "reference" / "outcomes.jsonl"
LEDGER_PATH_JSON = TOOLS_DIR / "outcomes.json"

# Output format identifiers used by ``save_ledger`` and the CLI.
FORMAT_JSONL = "jsonl"
FORMAT_JSON = "json"
DEFAULT_FORMAT = FORMAT_JSONL
NEW_RULE_CODIFIED_FIELD = "new_rule_codified"

# Default engagement workspaces. Each entry is (engagement_slug, workspace_dir).
# The tool scans for SUBMISSIONS.md at workspace/SUBMISSIONS.md and
# workspace/submissions/SUBMISSIONS.md (preferring the latter when both
# exist — same fallback order as engagement-retro.py).
DEFAULT_ENGAGEMENTS: Tuple[Tuple[str, str], ...] = (
    ("polymarket", "~/audits/polymarket"),
    ("morpho", "~/audits/morpho"),
    ("centrifuge", "~/audits/centrifuge-v3"),
    ("base-azul", "~/audits/base-azul"),
)


SCHEMA_FIELDS = (
    "submission_id",
    "engagement",
    "submitted_date",
    "title",
    "severity_claimed",
    "severity_awarded",
    "status",
    "outcome_class",
    "payout_usd",
    "rejection_reason",
    "dupe_pointer",
    "session_id",
    "shipped_via",
    "new_rule_codified",
    "last_updated",
)

# Fields that the parser sets on every refresh (re-derived from
# SUBMISSIONS.md). Anything NOT in this set is preserved across
# refresh calls so the operator can hand-annotate without losing
# data on the next ``refresh``.
PARSER_OWNED_FIELDS = frozenset({
    "engagement",
    "submitted_date",
    "title",
    "severity_claimed",
    "status",
    "outcome_class",
    "last_updated",
})


# ---------------------------------------------------------------------------
# Parser import (reuse engagement-retro.py)
# ---------------------------------------------------------------------------


def _load_engagement_retro():
    """Import ``engagement-retro.py`` as a module.

    The file uses a hyphenated name, which is not importable via the
    normal ``import`` statement, so go via ``importlib.util``. We cache
    on ``sys.modules`` to avoid re-executing the module on every call.
    """
    cache_key = "_outcome_ledger_engagement_retro"
    if cache_key in sys.modules:
        return sys.modules[cache_key]
    path = TOOLS_DIR / "engagement-retro.py"
    if not path.exists():
        raise RuntimeError(f"engagement-retro.py not found at {path}")
    spec = importlib.util.spec_from_file_location(cache_key, path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"failed to build importlib spec for {path}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[cache_key] = module
    spec.loader.exec_module(module)
    return module


# ---------------------------------------------------------------------------
# SUBMISSIONS.md helpers
# ---------------------------------------------------------------------------


def find_submissions_file(workspace: Path) -> Optional[Path]:
    """Return the SUBMISSIONS.md path for a workspace, or None.

    Preference order matches engagement-retro.py:
      1. ``<ws>/submissions/SUBMISSIONS.md``  (Polymarket / Morpho / base-azul)
      2. ``<ws>/SUBMISSIONS.md``              (Centrifuge legacy root layout)
    """
    nested = workspace / "submissions" / "SUBMISSIONS.md"
    if nested.exists():
        return nested
    root = workspace / "SUBMISSIONS.md"
    if root.exists():
        return root
    return None


_DATE_RE = re.compile(r"\b(\d{4}-\d{2}-\d{2})\b")


def extract_date(*texts: str) -> Optional[str]:
    """Pull the first ISO-8601 date (YYYY-MM-DD) from any of the inputs."""
    for t in texts:
        if not t:
            continue
        m = _DATE_RE.search(t)
        if m:
            return m.group(1)
    return None


def normalise_severity(raw: str) -> Optional[str]:
    """Map a freeform severity string to a canonical bucket.

    Returns one of ``Critical | High | Medium | Low | Info`` or ``None`` if
    no recognisable token is present. The match is case-insensitive and
    looks for the bare word as a substring (matches "Medium", "MEDIUM",
    "filing at Medium", etc.).
    """
    if not raw:
        return None
    low = raw.lower()
    # Order matters: check Critical before High so "High Critical" maps
    # to Critical (the more severe label dominates).
    for canonical in ("Critical", "High", "Medium", "Low", "Info"):
        if re.search(rf"\b{canonical.lower()}\b", low):
            return canonical
    return None


# Strip Cantina-style ID prefixes ("**209**", "#418", "S-001") off the
# front of a column to recover the bare numeric/string id.
_ID_STRIP_RE = re.compile(r"^[\*#]+|[\*]+$")


def normalise_id(raw: str) -> str:
    """Canonical lower-case id without surrounding markdown fluff."""
    if not raw:
        return ""
    return _ID_STRIP_RE.sub("", raw.strip()).strip()


# ---------------------------------------------------------------------------
# Per-engagement extraction
# ---------------------------------------------------------------------------


def _row_id_from_table(row: Dict[str, Any], engagement: str, idx: int) -> str:
    """Build the ledger ``submission_id`` for a parsed table row.

    Polymarket / Base-Azul use a ``Cantina #`` or ``Immunefi #`` column.
    When present we use that. Otherwise we fall back to a sequential
    ``<engagement>-Nidx`` slug so the row still has a stable key.
    """
    for k in (
        "cantina #",
        "cantina id",
        "immunefi #",
        "immunefi id",
        "report-id",
        "report id",
        "id",
        "#",
    ):
        if k in row and row[k]:
            stripped = normalise_id(row[k])
            if stripped:
                return f"{engagement}-{stripped}"
    return f"{engagement}-row{idx}"


def _row_id_from_line_item(title: str, engagement: str, idx: int) -> str:
    """Build a ledger id for a Centrifuge S-NNN / #NNN row.

    The Centrifuge parser stores the section heading in ``title`` *after*
    stripping the leading id, so we don't have direct access to "S-001"
    here. The section regex is recoverable from the original heading,
    but the test fixture and engagement-retro both drop it. As a
    pragmatic compromise we look for an explicit id token *inside* the
    title, otherwise fall back to a hash of the title for stability.
    """
    m = re.match(r"^(?:S-\d+|#?\d+)\s*[—-]?\s*(.*)$", title)
    if m and m.group(0) != m.group(1):
        # The title was prefixed with an id like "S-001 — ...".
        prefix = title[: title.index(m.group(1))].strip().strip("—-").strip()
        if prefix:
            return f"{engagement}-{normalise_id(prefix)}"
    # Engagement-retro strips the id prefix already, so titles arrive
    # bare. Use a deterministic short slug from the title instead.
    slug = re.sub(r"[^a-z0-9]+", "-", title.lower())[:48].strip("-")
    if not slug:
        slug = f"row{idx}"
    return f"{engagement}-{slug}"


def _row_id_from_section_header(title: str, engagement: str, idx: int) -> str:
    """Build a ledger id for a Morpho ``# Submission N — title`` row.

    Morpho uses operator labels like "#I2.B" or "#I2.A" in the title
    column itself. When such a label is present, use it as the id.
    Otherwise fall back to a slugified title.
    """
    m = re.match(r"^(#[A-Za-z0-9.\-]+)", title.strip())
    if m:
        return f"{engagement}-{normalise_id(m.group(1))}"
    slug = re.sub(r"[^a-z0-9]+", "-", title.lower())[:48].strip("-")
    if not slug:
        slug = f"row{idx}"
    return f"{engagement}-{slug}"


def parse_engagement(engagement: str, workspace: Path) -> List[Dict[str, Any]]:
    """Parse the SUBMISSIONS.md for one engagement into ledger rows.

    Returns a list of dicts populated for the parser-owned fields only.
    Operator-owned fields (payout_usd, dupe_pointer, rejection_reason,
    session_id, shipped_via, severity_awarded) are left ``None`` and
    must be filled in either via a manual edit or a future "annotate"
    subcommand. ``last_updated`` is set to today's date in ISO-8601.

    On any unexpected failure (file unreadable, layout unrecognised),
    the function logs to stderr and returns an empty list — never
    raises — so a single broken workspace can't take down the refresh.
    """
    sub_file = find_submissions_file(workspace)
    if sub_file is None:
        print(f"[ledger] {engagement}: no SUBMISSIONS.md under {workspace}", file=sys.stderr)
        return []

    try:
        text = sub_file.read_text(encoding="utf-8", errors="replace")
    except OSError as exc:
        print(f"[ledger] {engagement}: failed to read {sub_file}: {exc}", file=sys.stderr)
        return []

    retro = _load_engagement_retro()
    try:
        rows, layout = retro.parse_submissions(text)
    except Exception as exc:  # pragma: no cover — defensive, parser is known-good
        print(f"[ledger] {engagement}: parser raised {exc!r}; skipping", file=sys.stderr)
        return []

    if not rows:
        print(f"[ledger] {engagement}: no submissions parsed (layout=none)", file=sys.stderr)
        return []

    today = datetime.now(timezone.utc).strftime("%Y-%m-%d")
    out: List[Dict[str, Any]] = []

    for idx, row in enumerate(rows, start=1):
        title = (row.get("title") or "").strip()
        status = (row.get("status") or "").strip()

        if layout == "table":
            sub_id = _row_id_from_table(row, engagement, idx)
            sev_raw = row.get("severity") or status or title
            submitted_date = extract_date(row.get("date") or "", status, title)
        elif layout == "line_item":
            sub_id = _row_id_from_line_item(title, engagement, idx)
            sev_raw = row.get("severity") or status or title
            submitted_date = extract_date(row.get("date") or "", status, title)
        elif layout == "section_header":
            sub_id = _row_id_from_section_header(title, engagement, idx)
            sev_raw = row.get("severity") or status or title
            submitted_date = extract_date(status, title)
        else:
            # Unknown layout — engagement-retro should never return one
            # we don't recognise, but stay defensive.
            sub_id = f"{engagement}-row{idx}"
            sev_raw = row.get("severity") or status or title
            submitted_date = extract_date(status, title)

        outcome_class = retro.extract_outcome_class(status).lower()
        # Map the engagement-retro buckets onto the ledger schema.
        # PAID/DUPE/REJECTED/PENDING -> real/dupe/rejected/pending
        outcome_map = {
            "paid": "real",
            "dupe": "dupe",
            "rejected": "rejected",
            "pending": "pending",
            "unknown": "pending",
        }
        outcome_norm = outcome_map.get(outcome_class, "pending")

        out.append({
            "submission_id": sub_id,
            "engagement": engagement,
            "submitted_date": submitted_date,
            "title": title,
            "severity_claimed": normalise_severity(sev_raw or ""),
            "severity_awarded": None,
            "status": status,
            "outcome_class": outcome_norm,
            "payout_usd": None,
            "rejection_reason": None,
            "dupe_pointer": None,
            "session_id": None,
            "shipped_via": None,
            "new_rule_codified": False,
            "last_updated": today,
        })
    return out


# ---------------------------------------------------------------------------
# Ledger I/O + merge
# ---------------------------------------------------------------------------


def _detect_format(path: Path) -> str:
    """Pick a serialisation format based on filename suffix.

    ``.jsonl`` -> ``FORMAT_JSONL``; everything else (``.json`` and bare
    paths used in tests) -> ``FORMAT_JSON``. Callers can override
    explicitly via the ``fmt`` argument on ``load_ledger``/``save_ledger``.
    """
    if path.suffix.lower() == ".jsonl":
        return FORMAT_JSONL
    return FORMAT_JSON


def _is_ledger_row(rec: Dict[str, Any]) -> bool:
    """Return True iff ``rec`` looks like a rich-schema ledger row.

    The JSONL canonical file may also carry adjacent telemetry rows in
    a different schema (e.g. legacy ``track-submissions.py`` rows with
    keys ``finding_id``/``workspace`` instead of ``submission_id``/
    ``engagement``). The ledger only owns rows that carry the
    rich-schema ``submission_id`` key; everything else is passed
    through verbatim on rewrite so we don't clobber other tools'
    telemetry.
    """
    return isinstance(rec, dict) and bool(rec.get("submission_id"))


def _with_schema_defaults(row: Dict[str, Any]) -> Dict[str, Any]:
    normalized = dict(row)
    normalized.setdefault(NEW_RULE_CODIFIED_FIELD, False)
    return normalized


def _read_jsonl(path: Path) -> List[Dict[str, Any]]:
    rows: List[Dict[str, Any]] = []
    for lineno, line in enumerate(path.read_text(encoding="utf-8").splitlines(), start=1):
        stripped = line.strip()
        if not stripped:
            continue
        try:
            rec = json.loads(stripped)
        except json.JSONDecodeError as exc:
            raise SystemExit(
                f"[ledger] {path}:{lineno} is not valid JSON: {exc}"
            )
        if not isinstance(rec, dict):
            raise SystemExit(
                f"[ledger] {path}:{lineno} must be a JSON object, "
                f"got {type(rec).__name__}"
            )
        rows.append(rec)
    return rows


def load_ledger(
    path: Path = LEDGER_PATH,
    fmt: Optional[str] = None,
) -> List[Dict[str, Any]]:
    """Read the ledger from disk, returning [] when absent.

    Format is auto-detected from the path suffix unless ``fmt`` is
    given. For the canonical JSONL path, when the file is missing but
    the legacy ``tools/outcomes.json`` exists, fall back to it
    transparently — this preserves backwards compatibility for one
    release while consumers migrate.

    Only rich-schema ledger rows (``submission_id``-keyed) are
    returned; non-ledger rows in a heterogeneous JSONL stream are
    skipped here but preserved by ``save_ledger``.
    """
    fmt = fmt or _detect_format(path)
    if not path.exists():
        # Backwards-compat fallback: canonical JSONL missing, but the
        # legacy JSON ledger exists -> read from JSON. This keeps tools
        # that hard-coded ``tools/outcomes.json`` working until they
        # migrate.
        if fmt == FORMAT_JSONL and LEDGER_PATH_JSON.exists():
            return load_ledger(LEDGER_PATH_JSON, fmt=FORMAT_JSON)
        return []

    if fmt == FORMAT_JSONL:
        all_rows = _read_jsonl(path)
        return [_with_schema_defaults(r) for r in all_rows if _is_ledger_row(r)]

    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise SystemExit(f"[ledger] {path} is not valid JSON: {exc}")
    if not isinstance(data, list):
        raise SystemExit(f"[ledger] {path} must contain a JSON array, got {type(data).__name__}")
    return [_with_schema_defaults(r) for r in data]


def _sort_rows(rows: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    return sorted(
        rows,
        key=lambda r: (
            r.get("submitted_date") or "",
            r.get("engagement") or "",
            r.get("submission_id") or "",
        ),
    )


def save_ledger(
    rows: List[Dict[str, Any]],
    path: Path = LEDGER_PATH,
    fmt: Optional[str] = None,
) -> None:
    """Write rows sorted by (submitted_date, engagement, id).

    JSONL output emits one JSON object per line with sorted keys for
    stable diffs. When the destination file already contains
    non-ledger rows (foreign schemas like ``finding_id``/``workspace``
    streams), those rows are preserved verbatim and re-emitted ahead
    of the rewritten ledger rows.

    JSON output (legacy ``tools/outcomes.json``) emits a pretty-
    printed, sorted JSON array — unchanged from the pre-Slice-6
    behaviour.
    """
    fmt = fmt or _detect_format(path)
    sortable = _sort_rows([_with_schema_defaults(r) for r in rows])

    path.parent.mkdir(parents=True, exist_ok=True)

    if fmt == FORMAT_JSONL:
        preserved: List[Dict[str, Any]] = []
        if path.exists():
            existing = _read_jsonl(path)
            preserved = [r for r in existing if not _is_ledger_row(r)]
        with path.open("w", encoding="utf-8") as fh:
            for rec in preserved:
                fh.write(json.dumps(rec, sort_keys=True) + "\n")
            for rec in sortable:
                fh.write(json.dumps(rec, sort_keys=True) + "\n")
        return

    path.write_text(
        json.dumps(sortable, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )


def merge_rows(
    existing: List[Dict[str, Any]],
    fresh: List[Dict[str, Any]],
) -> List[Dict[str, Any]]:
    """Combine the existing ledger with freshly parsed rows.

    Behaviour:

    * Rows new to ``fresh`` (no matching submission_id in ``existing``)
      are added verbatim.
    * Rows in both: parser-owned fields (PARSER_OWNED_FIELDS) are taken
      from ``fresh``; operator-owned fields (payout_usd, dupe_pointer,
      rejection_reason, session_id, shipped_via, severity_awarded) are
      kept from ``existing``. This preserves manual annotations.
    * Rows present in ``existing`` but not in ``fresh`` are kept (they
      may be from an engagement temporarily unavailable on this run).
    """
    by_id = {r["submission_id"]: dict(r) for r in existing if r.get("submission_id")}
    for f in fresh:
        sid = f.get("submission_id")
        if not sid:
            continue
        if sid in by_id:
            merged = dict(by_id[sid])
            for field in PARSER_OWNED_FIELDS:
                if field in f:
                    merged[field] = f[field]
            by_id[sid] = merged
        else:
            by_id[sid] = dict(f)
    return [_with_schema_defaults(r) for r in by_id.values()]


# ---------------------------------------------------------------------------
# Subcommands
# ---------------------------------------------------------------------------


def cmd_refresh(args: argparse.Namespace) -> int:
    engagements = list(DEFAULT_ENGAGEMENTS)
    if args.engagement:
        # Restrict to specific engagement(s)
        wanted = set(args.engagement)
        engagements = [(s, p) for (s, p) in engagements if s in wanted]
        if not engagements:
            print(f"[ledger] no known engagement matches {sorted(wanted)}", file=sys.stderr)
            return 2

    fresh: List[Dict[str, Any]] = []
    counts: Dict[str, int] = {}
    for slug, ws_path in engagements:
        ws = Path(os.path.expanduser(ws_path)).resolve()
        rows = parse_engagement(slug, ws)
        counts[slug] = len(rows)
        fresh.extend(rows)
        print(f"[ledger] {slug}: {len(rows)} submission(s) parsed")

    existing = load_ledger(args.ledger, fmt=args.format)
    merged = merge_rows(existing, fresh)
    save_ledger(merged, args.ledger, fmt=args.format)
    print(f"[ledger] wrote {len(merged)} row(s) to {args.ledger} (format={args.format or _detect_format(args.ledger)})")
    return 0


def aggregate_stats(rows: Iterable[Dict[str, Any]]) -> Dict[str, Any]:
    rows = list(rows)
    total = len(rows)
    by_outcome: Dict[str, int] = {"real": 0, "dupe": 0, "rejected": 0, "pending": 0}
    by_engagement: Dict[str, Dict[str, int]] = {}
    payout_total = 0
    payout_count = 0
    for r in rows:
        oc = r.get("outcome_class") or "pending"
        if oc not in by_outcome:
            oc = "pending"
        by_outcome[oc] += 1
        eng = r.get("engagement") or "unknown"
        bucket = by_engagement.setdefault(eng, {"total": 0, "real": 0, "dupe": 0, "rejected": 0, "pending": 0})
        bucket["total"] += 1
        bucket[oc] = bucket.get(oc, 0) + 1
        payout = r.get("payout_usd")
        if isinstance(payout, (int, float)):
            payout_total += int(payout)
            payout_count += 1

    resolved = by_outcome["real"] + by_outcome["dupe"] + by_outcome["rejected"]
    accept_rate = (by_outcome["real"] / resolved) if resolved else 0.0
    avg_payout = (payout_total / payout_count) if payout_count else 0
    return {
        "total": total,
        "by_outcome": by_outcome,
        "by_engagement": by_engagement,
        "resolved": resolved,
        "accept_rate": accept_rate,
        "payout_total_usd": payout_total,
        "payout_count": payout_count,
        "avg_payout_usd": avg_payout,
    }


def cmd_stats(args: argparse.Namespace) -> int:
    rows = load_ledger(args.ledger, fmt=args.format)
    stats = aggregate_stats(rows)
    if args.json:
        print(json.dumps(stats, indent=2, sort_keys=True))
        return 0

    print(f"Outcome ledger: {args.ledger}")
    print(f"Total submissions tracked: {stats['total']}")
    bo = stats["by_outcome"]
    print(
        "  real (paid):     "
        f"{bo['real']:>3}    dupe: {bo['dupe']:>3}    "
        f"rejected: {bo['rejected']:>3}    pending: {bo['pending']:>3}"
    )
    print(f"  resolved:        {stats['resolved']:>3} (real + dupe + rejected)")
    print(f"  accept-rate:     {stats['accept_rate']:.1%}  (real / resolved)")
    print(f"  $ won total:     ${stats['payout_total_usd']:,}")
    print(f"  $ avg per paid:  ${int(stats['avg_payout_usd']):,}")
    print()
    print("Per-engagement:")
    for eng, b in sorted(stats["by_engagement"].items()):
        eng_resolved = b.get("real", 0) + b.get("dupe", 0) + b.get("rejected", 0)
        eng_rate = (b.get("real", 0) / eng_resolved) if eng_resolved else 0.0
        print(
            f"  {eng:<14} total={b['total']:>3}  real={b.get('real', 0):>2}  "
            f"dupe={b.get('dupe', 0):>2}  rejected={b.get('rejected', 0):>2}  "
            f"pending={b.get('pending', 0):>2}  accept-rate={eng_rate:.1%}"
        )
    return 0


def cmd_session_delta(args: argparse.Namespace) -> int:
    """Show what changed for a given session id.

    Compares rows whose ``session_id`` equals ``args.session_id`` against
    rows that pre-date that session. We define ``status flip`` as a row
    that exists in both buckets (was already in the ledger before the
    session and is also tagged with this session) and whose status
    differs from the prior session.

    With the current schema, session attribution is operator-owned —
    the parser does not know which session shipped which finding. The
    delta therefore relies on ``session_id`` being filled in by the
    operator (or by a future ``annotate`` subcommand). When the field
    is empty for every row, the delta still works as a "new since the
    given date" report by falling back to ``submitted_date``.
    """
    rows = load_ledger(args.ledger, fmt=args.format)
    sid = args.session_id

    by_session = [r for r in rows if r.get("session_id") == sid]
    other = [r for r in rows if r.get("session_id") != sid]

    # Fallback: if no rows are explicitly tagged for the session, treat
    # the session id as a date and pick rows submitted on or after it.
    if not by_session and re.match(r"^\d{4}-\d{2}-\d{2}$", sid or ""):
        by_session = [r for r in rows if (r.get("submitted_date") or "") >= sid]
        other = [r for r in rows if (r.get("submitted_date") or "") < sid]

    new_real = sum(1 for r in by_session if r.get("outcome_class") == "real")
    new_pending = sum(1 for r in by_session if r.get("outcome_class") == "pending")
    new_rejected = sum(1 for r in by_session if r.get("outcome_class") == "rejected")
    new_dupe = sum(1 for r in by_session if r.get("outcome_class") == "dupe")
    delta_payout = sum(
        int(r["payout_usd"]) for r in by_session
        if isinstance(r.get("payout_usd"), (int, float))
    )

    payload = {
        "session_id": sid,
        "total_rows_in_session": len(by_session),
        "prior_rows": len(other),
        "new_real": new_real,
        "new_pending": new_pending,
        "new_rejected": new_rejected,
        "new_dupe": new_dupe,
        "payout_delta_usd": delta_payout,
        "submissions": [
            {
                "submission_id": r["submission_id"],
                "engagement": r.get("engagement"),
                "title": r.get("title"),
                "outcome_class": r.get("outcome_class"),
                "payout_usd": r.get("payout_usd"),
            }
            for r in by_session
        ],
    }
    if args.json:
        print(json.dumps(payload, indent=2, sort_keys=True))
        return 0

    print(f"Session: {sid}")
    print(f"  rows in this session:  {len(by_session)}")
    print(f"  prior rows in ledger:  {len(other)}")
    print(
        f"  new outcomes — real={new_real}  pending={new_pending}  "
        f"rejected={new_rejected}  dupe={new_dupe}"
    )
    print(f"  payout delta:          ${delta_payout:,}")
    if not by_session:
        print("  (no rows match this session id; "
              "annotate ledger rows with session_id to populate)")
    return 0


def validate_rows(rows: List[Dict[str, Any]]) -> List[str]:
    """Return a list of human-readable validation errors."""
    errors: List[str] = []
    seen_ids: Dict[str, int] = {}
    for i, r in enumerate(rows):
        prefix = f"row[{i}]"
        sid = r.get("submission_id")
        if not sid:
            errors.append(f"{prefix}: missing submission_id")
        else:
            if sid in seen_ids:
                errors.append(
                    f"{prefix}: duplicate submission_id {sid!r} "
                    f"(also at row[{seen_ids[sid]}])"
                )
            else:
                seen_ids[sid] = i
        for required in ("engagement", "title", "status", "outcome_class"):
            if not r.get(required):
                errors.append(f"{prefix} ({sid}): missing {required}")
        oc = r.get("outcome_class")
        if oc not in (None, "real", "dupe", "rejected", "pending"):
            errors.append(f"{prefix} ({sid}): outcome_class {oc!r} not in real|dupe|rejected|pending")
        if "new_rule_codified" in r and not isinstance(r.get("new_rule_codified"), bool):
            errors.append(f"{prefix} ({sid}): new_rule_codified must be boolean")
        sev = r.get("severity_claimed")
        if sev is not None and sev not in ("Critical", "High", "Medium", "Low", "Info"):
            errors.append(f"{prefix} ({sid}): severity_claimed {sev!r} not canonical")
        date = r.get("submitted_date")
        if date is not None and not _DATE_RE.fullmatch(date):
            errors.append(f"{prefix} ({sid}): submitted_date {date!r} not ISO-8601")
        for f in SCHEMA_FIELDS:
            if f not in r:
                if f == NEW_RULE_CODIFIED_FIELD:
                    continue
                errors.append(f"{prefix} ({sid}): missing schema field {f!r}")
    return errors


def cmd_validate(args: argparse.Namespace) -> int:
    rows = load_ledger(args.ledger, fmt=args.format)
    errs = validate_rows(rows)
    if not errs:
        print(f"[ledger] {args.ledger} — {len(rows)} row(s) all valid")
        return 0
    for e in errs:
        print(e)
    print(f"[ledger] {len(errs)} error(s) across {len(rows)} row(s)", file=sys.stderr)
    return 1


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Central submission outcome telemetry ledger",
    )
    parser.add_argument(
        "--ledger",
        type=Path,
        default=LEDGER_PATH,
        help=(
            f"Path to the ledger (default: {LEDGER_PATH}). "
            f"Legacy JSON-array form: {LEDGER_PATH_JSON}"
        ),
    )
    parser.add_argument(
        "--format",
        choices=(FORMAT_JSONL, FORMAT_JSON),
        default=None,
        help=(
            "Serialisation format. Defaults to inferring from the "
            f"--ledger path suffix ('.jsonl' -> {FORMAT_JSONL}, "
            f"otherwise {FORMAT_JSON}). Pass --format=json explicitly "
            "to write the legacy tools/outcomes.json format."
        ),
    )

    subparsers = parser.add_subparsers(dest="cmd", required=True)

    p_refresh = subparsers.add_parser(
        "refresh",
        help="re-parse all SUBMISSIONS.md and update the ledger",
    )
    p_refresh.add_argument(
        "--engagement",
        action="append",
        default=None,
        help="restrict refresh to a single engagement slug (repeatable)",
    )
    p_refresh.set_defaults(func=cmd_refresh)

    p_stats = subparsers.add_parser(
        "stats",
        help="aggregate counts, accept-rate, $ won",
    )
    p_stats.add_argument("--json", action="store_true", help="emit JSON instead of human text")
    p_stats.set_defaults(func=cmd_stats)

    p_delta = subparsers.add_parser(
        "session-delta",
        help="show deltas vs prior session",
    )
    p_delta.add_argument("session_id", help="session id (e.g. 2026-04-25)")
    p_delta.add_argument("--json", action="store_true", help="emit JSON instead of human text")
    p_delta.set_defaults(func=cmd_session_delta)

    p_val = subparsers.add_parser(
        "validate",
        help="schema-check the ledger; flag rows without status, missing date, etc.",
    )
    p_val.set_defaults(func=cmd_validate)

    return parser


def main(argv: Optional[List[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
