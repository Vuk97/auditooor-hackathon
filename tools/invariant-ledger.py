#!/usr/bin/env python3
"""
invariant-ledger.py — workspace invariant ledger tooling (PR #511 Slice 2).

Purpose
=======
The ledger is the mandatory bridge between scope/spec understanding and
runnable harnesses. `make audit-deep` runs the engines we have wired,
but it does NOT synthesize every protocol-specific invariant. A Critical
can be invisible if the property is semantic rather than a code smell.
This tool makes that gap explicit, machine-checkable, and closeout-gated.

Two artifacts per workspace
---------------------------
    <ws>/INVARIANT_LEDGER.md            human-readable Markdown table
    <ws>/.auditooor/invariant_ledger.json  machine-readable JSON store

Both are kept in sync. The JSON store is the source of truth; the
Markdown is regenerated from it. Editing either is supported (round-trip
is best-effort — see `parse_markdown_ledger` for the supported subset).

Schema (14 + owner = 15 fields, but per the plan section
"Recommended row fields" the canonical 14-field schema is the one
operators are expected to fill — `owner` is the 15th field and is
always required too):

    id                  Stable ID (e.g. BASE-DLT-I01, POLY-CLOB-I03)
    scope_asset         Asset/subsystem this protects
    invariant_family    Protocol family (cl_el_parity, ctf_order_lifecycle, ...)
    statement           Human-readable claim that should always hold
    source_citations    Scope/spec/report/source citations (list, non-empty
                        for High/Critical rows)
    attacker_capability What a non-privileged attacker can control
    trusted_boundary    Admin/prover/operator/sequencer/trusted-service
                        assumptions
    oos_boundary        Why the row is in scope or what would make it OOS
    production_path     Exact code/deployment path that exercises it
    harness_target      Foundry/Cargo/live-check/differential target
    required_engine     Either a known engine token (forge | cargo |
                        live-check | differential | halmos | medusa |
                        slither | manual) OR a descriptive string whose
                        leading whitespace/`+`/`(`-delimited token is one
                        of those engines (e.g. "forge + halmos",
                        "live-check (cast call)",
                        "differential (revm-oracle vs in-tree)"). Pure
                        descriptive strings with no engine token still
                        WARN.
    negative_test       Concrete invalid state/input the harness must reject
    status              missing_harness | scaffolded | executed_clean |
                        counterexample | killed | blocked
    artifacts           Paths to tests, manifests, logs, replay evidence.
                        Accepted forms:
                          <path>                          plain
                          <path> (<annotation>)           inline note
                          EXPECTED:<path> (<annotation>)  planned target
                            (skips on-disk existence check)
                          blocker: <name>                 free-form note
                            (skipped by path-shape filter)
    owner               Claude | Kimi | Minimax | Codex | human | <name>

CLI
===
    --init                          Create empty ledger scaffold
    --from-scope                    Seed candidate rows from scope/spec/intel
                                    (heuristic; rows are drafts). Sources:
                                      SCOPE.md, README, SEVERITY*.md,
                                      submissions/SUBMISSIONS.md, Solidity
                                      factory/pool heuristics, registry P1-7,
                                      engage_report.json (attack-class clusters)
      --dry-run                     Print candidates without writing to disk
      --json                        Also emit a JSON diff block to stdout
    --diff-accepted                 Compare freshly-generated scope invariants
                                    against operator-accepted ledger rows.
                                    Emits 4-bucket report:
                                      newly_generated_rows
                                      accepted_unchanged_rows
                                      accepted_drifted_rows
                                      accepted_orphaned_rows
                                    Output: .auditooor/invariant_ledger_scope_diff.{json,md}
                                    Read-only: does NOT mutate the ledger.
    --check                         Schema + artifact-reference validation
    --require-high-impact-harness   Promote High/Critical rows without a
                                    runnable harness/replay/blocker to FAIL
    --emit-closeout                 Write
                                    <ws>/.audit_logs/invariant_ledger_manifest.json

Discipline
----------
- stdlib-only (no PyYAML).
- Idempotent: --init on an existing ledger merges (it does NOT clobber).
- --from-scope only ADDS candidate rows; never mutates existing rows.
- --from-scope --dry-run is safe to run on live workspaces; it does not
  write any file (ledger, markdown, or generated_invariants.json sidecar).
- Severity inference from `scope_asset` defaults to None (Medium); a row
  is treated as High/Critical only when the optional `severity` hint is
  set in the JSON store. We do not silently invent severities.
"""
from __future__ import annotations

import argparse
import dataclasses
import datetime as _dt
import json
import os
import re
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Tuple

# ---------------------------------------------------------------------------
# Schema
# ---------------------------------------------------------------------------

SCHEMA_VERSION = "auditooor.invariant_ledger.v1"
GENERATED_INVARIANTS_SCHEMA = "auditooor.generated_invariants.v1"

# The 15 required row fields. The plan calls out 14 "recommended row
# fields"; we add `owner` (already in the plan table) as required so the
# accountability column never goes missing in CI. If the operator does
# not know yet, they should put `unknown` rather than dropping the field.
REQUIRED_FIELDS: Tuple[str, ...] = (
    "id",
    "scope_asset",
    "invariant_family",
    "statement",
    "source_citations",
    "attacker_capability",
    "trusted_boundary",
    "oos_boundary",
    "production_path",
    "harness_target",
    "required_engine",
    "negative_test",
    "status",
    "artifacts",
    "owner",
)

VALID_STATUS: Tuple[str, ...] = (
    "missing_harness",
    "scaffolded",
    "executed_clean",
    "counterexample",
    "killed",
    "blocked",
)

VALID_ENGINES: Tuple[str, ...] = (
    "forge",
    "cargo",
    "live-check",
    "differential",
    "halmos",
    "medusa",
    "slither",
    "manual",
    "go",
    "unknown",
)

# Open-prefix engine acceptance. Real ledger authors write descriptive
# `required_engine` strings such as `"forge + halmos"`,
# `"live-check (cast call)"`, `"differential (revm-oracle vs in-tree)"`.
# We accept any string whose first whitespace/`+`/`(`-delimited token is
# one of the known engines above. Pure-descriptive strings whose leading
# token is not a known engine still WARN (e.g. `"random gibberish"`).
_ENGINE_PREFIX_TOKEN_RE = re.compile(r"^([A-Za-z][A-Za-z0-9._-]*)")


def _required_engine_ok(value: str) -> bool:
    """Accept a known engine token, OR a descriptive string starting with
    a known engine prefix (`forge + halmos`, `live-check (cast call)`).

    Returns True for accepted forms, False for pure-descriptive strings
    with no recognised engine token at all.
    """
    if not isinstance(value, str) or not value:
        return False
    if value in VALID_ENGINES:
        return True
    m = _ENGINE_PREFIX_TOKEN_RE.match(value.strip())
    if not m:
        return False
    head = m.group(1).lower()
    return head in VALID_ENGINES


# Artifact path matcher. KK's Base ledger encodes meta-info inline:
# `"differential_fuzz/state_root_parity/ (Wave 3 PR #494 scaffold; ...)"`
# and `"EXPECTED: poc-tests/fn7_engine_tree_e2e.rs (NOT YET WRITTEN)"`.
# The substantive part is the path; the parenthetical is annotation.
# We accept either `<path>` or `<path> (<annotation>)`, optionally
# prefixed with the `EXPECTED:` sentinel which means "the path is the
# planned target — skip existence check, keep the value".
_ARTIFACT_PATH_RE = re.compile(
    r"""^
    (?:EXPECTED:\s*)?              # optional planned-target sentinel
    (?P<path>[^()\s]+)             # the path: any non-whitespace, non-paren run
    (?:\s+\([^)]*\))?              # optional ` (annotation)`
    \s*$
    """,
    re.VERBOSE,
)


def _artifact_path_present(ws: Path, path: str) -> bool:
    """Return True if `path` exists under `ws`.

    Resolution rules:
      1. Absolute path -> direct existence check.
      2. Plain relative path -> `ws / path` existence check.
      3. Path containing a glob char (`*`, `?`, `[`) -> glob from `ws`,
         True if any match. Real ledgers shorthand `corpus/01-10*.json`
         to refer to a corpus block — we accept that.
      4. Fallback for relative paths whose direct join missed: search
         `ws.rglob(<basename>)` and accept the first hit. This covers
         the common KK-ledger pattern where the operator writes the
         file's basename and the annotation tells the human reader
         where to find it (e.g. `DEPLOYMENT_REALITY_CHECK.md (under
         submissions/)`). We are lenient here on purpose — the goal is
         "operator referenced a real file", not "operator typed the
         exact relative path".
    """
    p_obj = Path(path)
    if p_obj.is_absolute():
        return p_obj.exists()
    direct = ws / path
    if direct.exists():
        return True
    if any(ch in path for ch in "*?["):
        try:
            for _hit in ws.glob(path):
                return True
        except (OSError, ValueError):
            pass
        # Lenient fallback: real ledgers shorthand a numeric range with
        # a hyphen, e.g. `corpus/01-10*.json` — not a shell glob. We
        # accept it when the parent dir exists and contains at least
        # one file whose name matches the extension/suffix part.
        try:
            parent = direct.parent
            if parent.is_dir():
                # Extract the suffix after the last `*` or `?`.
                tail = path
                for sep in ("*", "?"):
                    if sep in tail:
                        tail = tail.rsplit(sep, 1)[-1]
                if tail and any(
                    f.name.endswith(tail) for f in parent.iterdir() if f.is_file()
                ):
                    return True
        except (OSError, ValueError):
            pass
        return False
    # Fallback: rglob by basename. Skip when the path has too many
    # path components (indicates the operator did intend a specific
    # relative location and got it wrong).
    if "/" in path and path.count("/") > 0:
        # Multi-segment relative path the operator typed deliberately.
        # Still try basename rglob as a courtesy when the dir is the
        # only thing that's wrong.
        pass
    base = p_obj.name
    if base and base not in ("", ".", ".."):
        try:
            for hit in ws.rglob(base):
                # Skip hidden dirs, build outputs.
                rel = hit.relative_to(ws)
                if any(part.startswith(".") for part in rel.parts):
                    continue
                if "target" in rel.parts or "node_modules" in rel.parts:
                    continue
                return True
        except (OSError, ValueError):
            pass
    return False


def _split_artifact(art: str) -> Tuple[Optional[str], bool]:
    """Split an artifact entry into (path, expected_only).

    Returns (None, False) if the entry is not parseable as a path —
    callers should treat that as a free-form blocker note.
    `expected_only=True` means the operator marked the path with
    `EXPECTED:` (skip on-disk existence check).
    """
    if not isinstance(art, str) or not art.strip():
        return None, False
    s = art.strip()
    expected_only = s.startswith("EXPECTED:")
    m = _ARTIFACT_PATH_RE.match(s)
    if not m:
        return None, expected_only
    path = m.group("path")
    # The path must look like a path (`/` or known suffix). Free-form
    # `blocker: missing-rpc` notes still pass through this path-shape
    # filter and are correctly classified as non-path entries.
    return path, expected_only

# Optional row fields. We accept them in JSON but they are not part of
# the closeout schema check — they are operator hints only.
OPTIONAL_FIELDS: Tuple[str, ...] = ("severity", "notes", "created", "updated")

HIGH_IMPACT_SEVERITIES: Tuple[str, ...] = ("High", "Critical")

# Statuses that satisfy "this High/Critical invariant has a runnable
# harness/replay or an explicit blocker". `missing_harness` does NOT
# satisfy. `executed_clean`, `counterexample`, `killed` all satisfy
# because they imply the harness existed and ran. `scaffolded` satisfies
# because a harness target is committed. `blocked` satisfies because the
# row names the blocker (the closeout will check that artifacts contain
# a non-empty blocker note).
HIGH_IMPACT_OK_STATUS: Tuple[str, ...] = (
    "scaffolded",
    "executed_clean",
    "counterexample",
    "killed",
    "blocked",
)

# Heuristic: invariant_family or statement keywords that imply
# High-severity impact. Documented in docs/INVARIANT_LEDGER.md. Per-row
# explicit `severity` always wins; this only fires when severity is
# unset. Patterns are intentionally conservative — they map to the
# Immunefi DLT/SC Critical buckets (state-root divergence, finalisation
# bypass, fund drain, theft, theft of yield, oracle manipulation).
_HIGH_SEVERITY_FAMILY_TOKENS: Tuple[str, ...] = (
    "-DLT-",
    "-CRITICAL",
    "_root",
    "_finality",
    "_finalization",
    "_resolution",
    "PROOF-DOMAIN",
    "TEE-ZK-AGREEMENT",
    "STATE-ROOT",
    "WITHDRAWALS-ROOT",
    "PARITY",
    "DRAIN",
)
_HIGH_SEVERITY_STATEMENT_TOKENS: Tuple[str, ...] = (
    "drain",
    "finaliz",  # finalize / finalization
    "state-root",
    "state root",
    "divergence",
    " loss ",
    "theft",
    "withdrawals_root",
    "withdrawals root",
)


def _infer_severity(r: "Row") -> Optional[str]:
    """Return inferred severity for a row.

    Explicit `severity` always wins. Otherwise, check the family token
    list and the statement-keyword list. Returns "High" if any match,
    None otherwise.
    """
    if r.severity:
        return r.severity
    family = (r.invariant_family or "").upper()
    for tok in _HIGH_SEVERITY_FAMILY_TOKENS:
        if tok.upper() in family:
            return "High"
    statement = (r.statement or "").lower()
    for tok in _HIGH_SEVERITY_STATEMENT_TOKENS:
        if tok in statement:
            return "High"
    return None


def _row_effective_severity(row: "Row") -> Optional[str]:
    """Return the *effective* severity for a row.

    The closeout manifest, the deep-summary, and any operator-facing
    high-impact counter must use the same severity that the validation
    gate uses. Validation calls `_infer_severity`, which combines the
    explicit `severity` field with the family/statement heuristics.
    Reading `row.severity` directly silently drops every inferred-High
    row (PR #511 follow-up — Required Pre-Merge Fix for #521).
    """
    return _infer_severity(row)


@dataclass
class Row:
    id: str
    scope_asset: str
    invariant_family: str
    statement: str
    source_citations: List[str] = field(default_factory=list)
    attacker_capability: str = ""
    trusted_boundary: str = ""
    oos_boundary: str = ""
    production_path: str = ""
    harness_target: str = ""
    required_engine: str = "unknown"
    negative_test: str = ""
    status: str = "missing_harness"
    artifacts: List[str] = field(default_factory=list)
    owner: str = "unknown"
    # Optional hints (not in REQUIRED_FIELDS):
    severity: Optional[str] = None
    notes: str = ""
    created: str = ""
    updated: str = ""

    def to_dict(self) -> Dict[str, Any]:
        d = dataclasses.asdict(self)
        # Drop empty optional fields for compactness, but keep all required.
        for opt in OPTIONAL_FIELDS:
            if d.get(opt) in (None, "", []):
                d.pop(opt, None)
        return d


# ---------------------------------------------------------------------------
# Path helpers
# ---------------------------------------------------------------------------

def md_path(ws: Path) -> Path:
    return ws / "INVARIANT_LEDGER.md"


def json_path(ws: Path) -> Path:
    return ws / ".auditooor" / "invariant_ledger.json"


def manifest_path(ws: Path) -> Path:
    return ws / ".audit_logs" / "invariant_ledger_manifest.json"


def generated_invariants_path(ws: Path) -> Path:
    return ws / ".auditooor" / "generated_invariants.json"


# ---------------------------------------------------------------------------
# IO
# ---------------------------------------------------------------------------

def _read_text(path: Path) -> str:
    try:
        return path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return ""


class LedgerError(Exception):
    """Raised on a structural ledger problem (malformed JSON, wrong shape).

    Distinct from a per-row schema CheckIssue: a LedgerError means we
    cannot even parse the ledger at the top level. `cmd_check` catches
    these and exits non-zero with a named reason. Tests assert the
    exit code and the failure reason.
    """


def _read_json(path: Path) -> Optional[Any]:
    """Read JSON. Returns None when file is missing; RAISES LedgerError
    when the file exists but is not valid JSON.

    The pre-fix behaviour swallowed `ValueError` and returned `None`,
    which let garbage-JSON ledgers pass `--check` silently — the silent
    zero pattern this PR exists to defend against. We now distinguish:
      - missing file -> None (caller decides)
      - unreadable / IO error -> None (caller decides)
      - valid file, malformed JSON -> LedgerError (always loud)
    """
    try:
        text = path.read_text(encoding="utf-8")
    except OSError:
        return None
    try:
        return json.loads(text)
    except ValueError as e:
        raise LedgerError(
            f"ledger is not valid JSON: {path} ({e.__class__.__name__}: {e})"
        ) from e


def _now_iso() -> str:
    return _dt.datetime.now(_dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


# ---------------------------------------------------------------------------
# JSON store: load / save
# ---------------------------------------------------------------------------

def load_rows(ws: Path) -> List[Row]:
    """Load rows from the JSON store. Returns [] if file missing.

    Loose loader: this function is used by `--init`, `--from-scope`,
    and `--emit-closeout` where missing fields should be tolerated and
    defaulted. The structural validator `validate_ledger_payload` is
    the strict one used by `--check`.

    Tolerates both legacy `[<row>, ...]` shape and current
    `{"schema_version": ..., "rows": [...]}` shape. Saves always use
    the latter.
    """
    p = json_path(ws)
    try:
        payload = _read_json(p)
    except LedgerError:
        # Loose load swallows malformed JSON the same way it always
        # has, so callers like --init / --from-scope can recover.
        # `--check` calls `validate_ledger_payload` directly and surfaces
        # the LedgerError loudly.
        return []
    if payload is None:
        return []
    if isinstance(payload, list):
        raw_rows = payload
    elif isinstance(payload, dict):
        raw_rows = payload.get("rows", [])
        if not isinstance(raw_rows, list):
            raw_rows = []
    else:
        raw_rows = []
    out: List[Row] = []
    for raw in raw_rows:
        if not isinstance(raw, dict):
            continue
        kwargs: Dict[str, Any] = {}
        for fname in REQUIRED_FIELDS:
            # Accept inv_id as a legacy alias for id so that ledger files
            # produced by older tooling (e.g. llm-invariant-extractor.py)
            # that used the key "inv_id" are loaded without silent data loss.
            if fname == "id" and "id" not in raw and "inv_id" in raw:
                kwargs[fname] = raw["inv_id"]
            else:
                kwargs[fname] = raw.get(fname, _default_for(fname))
        for fname in OPTIONAL_FIELDS:
            if fname in raw:
                kwargs[fname] = raw[fname]
        try:
            out.append(Row(**kwargs))
        except TypeError:
            # Unknown fields in the raw dict — fall back to constructing
            # only with known fields.
            keep = {
                k: v for k, v in kwargs.items()
                if k in REQUIRED_FIELDS or k in OPTIONAL_FIELDS
            }
            out.append(Row(**keep))
    return out


def validate_ledger_payload(ws: Path) -> Tuple[Any, List[Row]]:
    """Strict structural validator used by `--check`.

    Returns (raw_payload, rows). Raises LedgerError when the ledger:
      - is malformed JSON
      - is an empty `[]` array
      - is `{"rows": []}` (zero rows)
      - is a dict missing the `rows` key entirely
      - has a top-level dict that lacks BOTH `schema_version` and
        `schema` fields (a rows-only dict is a structural anomaly we
        will not silently accept)

    Per-row required-field enforcement happens in `validate_rows`. This
    function only enforces the top-level shape.
    """
    p = json_path(ws)
    payload = _read_json(p)
    if payload is None:
        # Caller should already have checked file presence — this path
        # means the file vanished between is_file() and read.
        raise LedgerError(f"ledger missing or unreadable: {p}")
    if isinstance(payload, list):
        if not payload:
            raise LedgerError(
                "ledger has zero rows (empty `[]`); run `--init` to "
                "scaffold or `--from-scope` to seed candidate rows"
            )
        rows_payload = payload
        # Legacy list shape: tolerate but warn-shape — we still load
        # rows. The structural-key check below only fires on dicts.
    elif isinstance(payload, dict):
        if "rows" not in payload:
            raise LedgerError(
                "ledger top-level dict is missing required `rows` key; "
                "expected `{\"schema_version\": ..., \"rows\": [...]}`"
            )
        if not (
            "schema_version" in payload
            or "schema" in payload  # legacy / KK ledger uses `schema`
        ):
            raise LedgerError(
                "ledger top-level dict is missing required schema "
                "identifier; expected `schema_version` (or legacy `schema`) "
                "alongside `rows`"
            )
        rows_payload = payload["rows"]
        if not isinstance(rows_payload, list):
            raise LedgerError(
                f"ledger `rows` field must be a JSON array; got "
                f"{type(rows_payload).__name__}"
            )
        if not rows_payload:
            raise LedgerError(
                "ledger has zero rows (`rows: []`); run `--init` to "
                "scaffold or `--from-scope` to seed candidate rows"
            )
    else:
        raise LedgerError(
            f"ledger top-level JSON must be array or object; got "
            f"{type(payload).__name__}"
        )
    # Re-use the loose loader to materialise Row objects so we share
    # the field-defaulting and unknown-field tolerance logic.
    return payload, load_rows(ws)


def _raw_rows_from_payload(payload: Any) -> List[Dict[str, Any]]:
    """Extract the raw row dicts (pre-defaulting) from a parsed JSON
    payload. Used by `validate_rows` to detect *missing* fields vs
    fields that were present-but-empty.
    """
    if isinstance(payload, list):
        return [r for r in payload if isinstance(r, dict)]
    if isinstance(payload, dict):
        rs = payload.get("rows", []) or []
        return [r for r in rs if isinstance(r, dict)]
    return []


def _default_for(field_name: str) -> Any:
    if field_name in ("source_citations", "artifacts"):
        return []
    if field_name == "required_engine":
        return "unknown"
    if field_name == "status":
        return "missing_harness"
    if field_name == "owner":
        return "unknown"
    return ""


def save_rows(ws: Path, rows: List[Row], *, write_md: bool = True) -> None:
    """Persist rows to JSON (and optionally regenerate the Markdown).

    Top-level keys: `schema_version` (canonical) is written, plus the
    legacy `schema` alias for back-compat with PR #513 readers. Both
    are accepted by `validate_ledger_payload`.
    """
    j = json_path(ws)
    j.parent.mkdir(parents=True, exist_ok=True)
    payload = {
        "schema_version": SCHEMA_VERSION,
        "schema": SCHEMA_VERSION,  # legacy alias; validator accepts either
        "workspace": str(ws),
        "updated": _now_iso(),
        "rows": [r.to_dict() for r in rows],
    }
    j.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
    if write_md:
        md_path(ws).write_text(render_markdown(rows, ws), encoding="utf-8")


# ---------------------------------------------------------------------------
# Markdown rendering / parsing (round-trip subset)
# ---------------------------------------------------------------------------

_MD_HEADER = (
    "# Invariant Ledger\n"
    "\n"
    "This file is the human-readable mirror of\n"
    "`.auditooor/invariant_ledger.json`. Every scoped subsystem capable of\n"
    "High or Critical impact must have at least one row. Every High/Critical\n"
    "row must either reference a runnable harness/replay/blocker, or carry\n"
    "an explicit `blocked` status with the blocker named in `artifacts`.\n"
    "\n"
    "Schema: `auditooor.invariant_ledger.v1` — see `docs/INVARIANT_LEDGER.md`.\n"
    "\n"
    "Statuses: `missing_harness` | `scaffolded` | `executed_clean` |\n"
    "`counterexample` | `killed` | `blocked`.\n"
    "\n"
)


def render_markdown(rows: List[Row], ws: Path) -> str:
    """Render the ledger to Markdown. Round-trip parser is `parse_markdown_ledger`."""
    lines: List[str] = [_MD_HEADER]
    if not rows:
        lines.append("_No rows yet. Run `--from-scope` to seed candidate rows._\n")
        return "".join(lines)
    # Per-row block (round-trip-friendly, one row per stanza).
    for r in rows:
        lines.append(f"## {r.id}\n\n")
        lines.append(f"- scope_asset: {r.scope_asset}\n")
        lines.append(f"- invariant_family: {r.invariant_family}\n")
        lines.append(f"- statement: {r.statement}\n")
        lines.append("- source_citations:\n")
        for c in r.source_citations:
            lines.append(f"  - {c}\n")
        lines.append(f"- attacker_capability: {r.attacker_capability}\n")
        lines.append(f"- trusted_boundary: {r.trusted_boundary}\n")
        lines.append(f"- oos_boundary: {r.oos_boundary}\n")
        lines.append(f"- production_path: {r.production_path}\n")
        lines.append(f"- harness_target: {r.harness_target}\n")
        lines.append(f"- required_engine: {r.required_engine}\n")
        lines.append(f"- negative_test: {r.negative_test}\n")
        lines.append(f"- status: {r.status}\n")
        lines.append("- artifacts:\n")
        for a in r.artifacts:
            lines.append(f"  - {a}\n")
        lines.append(f"- owner: {r.owner}\n")
        if r.severity:
            lines.append(f"- severity: {r.severity}\n")
        if r.notes:
            lines.append(f"- notes: {r.notes}\n")
        lines.append("\n")
    return "".join(lines)


_MD_HEADING_RE = re.compile(r"^##\s+(\S.*)$")
_MD_KEY_RE = re.compile(r"^-\s+([a-zA-Z_]+)\s*:\s*(.*)$")
_MD_LIST_ITEM_RE = re.compile(r"^\s+-\s+(.*)$")


def parse_markdown_ledger(text: str) -> List[Row]:
    """Best-effort Markdown parser (round-trip with `render_markdown`)."""
    rows: List[Row] = []
    cur: Optional[Dict[str, Any]] = None
    cur_listkey: Optional[str] = None
    for raw in text.splitlines():
        line = raw.rstrip()
        if not line:
            cur_listkey = None
            continue
        m = _MD_HEADING_RE.match(line)
        if m:
            if cur is not None:
                rows.append(_dict_to_row(cur))
            cur = {"id": m.group(1).strip()}
            cur_listkey = None
            continue
        if cur is None:
            continue
        m = _MD_KEY_RE.match(line)
        if m:
            key = m.group(1)
            val = m.group(2).strip()
            if key in ("source_citations", "artifacts"):
                cur[key] = []
                cur_listkey = key
                if val:  # inline `- key: value` (single-item shorthand)
                    cur[key].append(val)
                continue
            cur[key] = val
            cur_listkey = None
            continue
        m = _MD_LIST_ITEM_RE.match(line)
        if m and cur_listkey:
            cur.setdefault(cur_listkey, []).append(m.group(1).strip())
            continue
    if cur is not None:
        rows.append(_dict_to_row(cur))
    return rows


def _dict_to_row(d: Dict[str, Any]) -> Row:
    kwargs: Dict[str, Any] = {}
    for fname in REQUIRED_FIELDS:
        # Accept inv_id as a legacy alias for id (same alias as load_rows).
        if fname == "id" and "id" not in d and "inv_id" in d:
            kwargs[fname] = d["inv_id"]
        else:
            kwargs[fname] = d.get(fname, _default_for(fname))
    for fname in OPTIONAL_FIELDS:
        if fname in d:
            kwargs[fname] = d[fname]
    return Row(**kwargs)


# ---------------------------------------------------------------------------
# --init: scaffold (idempotent)
# ---------------------------------------------------------------------------

def cmd_init(ws: Path) -> int:
    """Create empty ledger scaffold. Idempotent: existing rows are kept."""
    ws.mkdir(parents=True, exist_ok=True)
    existing = load_rows(ws)
    save_rows(ws, existing)  # writes both files; preserves existing rows
    print(f"[invariant-ledger] init OK: {md_path(ws)}")
    print(f"[invariant-ledger] init OK: {json_path(ws)}")
    print(f"[invariant-ledger] rows kept: {len(existing)}")
    return 0


# ---------------------------------------------------------------------------
# --from-scope: heuristic seeding
# ---------------------------------------------------------------------------

# Source priority order — first hit per category wins. Documented in
# docs/INVARIANT_LEDGER.md and surfaced in --help.
FROM_SCOPE_SOURCES: Tuple[str, ...] = (
    "SCOPE.md",
    "README.md",
    "README",
    "SEVERITY.md",
    "SEVERITY_SMART_CONTRACTS.md",
    "SEVERITY_BLOCKCHAIN_DLT.md",
    "RUBRIC_COVERAGE.md",
    ".auditooor/impact_family_worklists.json",
    "INTAKE_BASELINE.json",
    "deployment_topology.json",
    "live_topology_checks.json",
    "submissions/SUBMISSIONS.md",
)

# Canonical path to the tier registry (relative to repo root = parent of tools/).
_REPO_ROOT = Path(__file__).resolve().parent.parent
_TIER_REGISTRY_PATH = _REPO_ROOT / "detectors" / "_tier_registry.yaml"

# Stateful-gate fields declared on factory->pool->liveness registry rows
# (mirrored from detector-promote.py so invariant-ledger stays in sync).
_FACTORY_STATEFUL_FIELDS: Tuple[str, ...] = (
    "entrypoint",
    "invalid_config",
    "tracked_pool",
    "liquidity_acceptance",
    "downstream_liveness",
    "conservative_severity_state",
)


_SCOPE_HEADING_RE = re.compile(
    r"^(?:#{1,6})\s+(.+?)\s*$"
)


def _slugify(s: str) -> str:
    s = re.sub(r"[^A-Za-z0-9]+", "-", s).strip("-").upper()
    return s[:32] if s else "ROW"


@dataclass
class GeneratedInvariant:
    row: Row
    generated_from: str
    source_file: str
    source_id: str


@dataclass
class SolidityParam:
    name: str
    typ: str


@dataclass
class SolidityFunction:
    name: str
    visibility: str
    params: List[SolidityParam]
    body: str
    line: int
    contract: str


_SEVERITY_HEADING_RE = re.compile(r"^#{1,6}\s+(critical|high|medium|low)\b.*$", re.I)
_BULLET_RE = re.compile(r"^\s*(?:[-*]|\d+[.)])\s+(.+?)\s*$")
_SOL_FUNCTION_RE = re.compile(
    r"\bfunction\s+(?P<name>[A-Za-z_][A-Za-z0-9_]*)\s*"
    r"\((?P<params>.*?)\)\s*(?P<tail>[^;{}]*)\{",
    re.S,
)
_SOL_CONTRACT_RE = re.compile(
    r"\b(?:contract|abstract\s+contract|library)\s+([A-Za-z_][A-Za-z0-9_]*)\b"
)
_SOL_CREATE_RE = re.compile(r"^(?:create|deploy|clone|launch|make|new)", re.I)
_SOL_POOL_ACTION_RE = re.compile(
    r"(?:add|remove|increase|decrease|modify)?liquidity|mint|burn|swap|"
    r"donate|collect|settle|take|before(?:swap|addliquidity|removeliquidity)|"
    r"after(?:swap|addliquidity|removeliquidity)|hook",
    re.I,
)
_SOL_CONFIG_NAME_TOKENS: Tuple[str, ...] = (
    "token",
    "currency",
    "asset",
    "fee",
    "tick",
    "spacing",
    "hook",
    "salt",
    "config",
    "domain",
    "key",
    "manager",
    "oracle",
    "owner",
    "controller",
    "implementation",
    "template",
    "factory",
    "strategy",
)
_SOL_CONFIG_TYPE_TOKENS: Tuple[str, ...] = (
    "poolkey",
    "poolconfig",
    "config",
    "params",
    "domain",
    "hook",
)
_SOL_SKIP_DIRS: Tuple[str, ...] = (
    ".git",
    ".auditooor",
    ".audit_logs",
    "node_modules",
    "lib",
    "vendor",
    "out",
    "cache",
    "artifacts",
    "broadcast",
    "test",
    "tests",
)


def _clean_inline_markdown(text: str) -> str:
    text = re.sub(r"`([^`]+)`", r"\1", text)
    text = re.sub(r"\[([^\]]+)\]\([^)]+\)", r"\1", text)
    return re.sub(r"\s+", " ", text).strip()


def _impact_family_for_text(text: str) -> str:
    t = text.lower()
    if any(tok in t for tok in ("fund", "theft", "steal", "drain", "loss of", "locked")):
        return "impact_funds_safety"
    if any(tok in t for tok in ("state root", "state-root", "root mismatch", "fork", "divergence")):
        return "impact_state_root_integrity"
    if any(tok in t for tok in ("bridge", "withdrawal", "finalization", "finalisation", "proof", "dispute")):
        return "impact_bridge_finalization"
    if any(tok in t for tok in ("node", "resource", "cpu", "memory", "shutdown", "network")):
        return "impact_node_liveness"
    if any(tok in t for tok in ("oracle", "price", "feed")):
        return "impact_oracle_integrity"
    if any(tok in t for tok in ("admin", "governance", "upgrade", "permission")):
        return "impact_authorization_boundary"
    return "impact_contract_linkage"


def _engine_for_family(family: str) -> str:
    if family in ("impact_state_root_integrity", "impact_node_liveness"):
        return "cargo"
    if family in ("impact_bridge_finalization", "impact_oracle_integrity"):
        return "differential"
    if family == "impact_funds_safety":
        return "forge"
    return "manual"


def _candidate_row_for_impact(
    *,
    rid: str,
    impact: str,
    citation: str,
    severity: Optional[str],
    scope_asset: str,
) -> Row:
    family = _impact_family_for_text(impact)
    statement = f"Listed program impact must remain unreachable: {impact}"
    slug = _slugify(rid.lower())
    return Row(
        id=rid,
        scope_asset=scope_asset,
        invariant_family=family,
        statement=statement[:240],
        source_citations=[citation],
        attacker_capability="Generated advisory: fill exact non-privileged attacker input/control before promotion.",
        trusted_boundary="Generated advisory: map trusted actors/providers from topology before promotion.",
        oos_boundary="Generated advisory: run OOS and exact impact-contract checks before promotion.",
        production_path="Generated advisory: map caller -> parser/provider/cache -> validation -> state/proof path.",
        harness_target=f"EXPECTED:.auditooor/harness_plans/{slug}.json (generated advisory)",
        required_engine=_engine_for_family(family),
        negative_test=f"Generated advisory: construct a counterexample that would prove this exact impact: {impact[:160]}",
        status="missing_harness",
        artifacts=[],
        owner="unknown",
        severity=severity,
        notes="generated_from_scope=true; advisory_only=true",
        created=_now_iso(),
    )


def _row_match_key(row: Row) -> str:
    def norm(value: str) -> str:
        return re.sub(r"\W+", " ", (value or "").lower()).strip()

    return "|".join((
        norm(row.scope_asset),
        norm(row.invariant_family),
        norm(row.statement),
    ))


def _accepted_lookup(rows: List[Row]) -> Tuple[Dict[str, str], Dict[str, str]]:
    by_id = {r.id: r.id for r in rows}
    by_key = {_row_match_key(r): r.id for r in rows}
    return by_id, by_key


def _write_generated_invariants(
    ws: Path,
    generated: List[GeneratedInvariant],
    accepted_before: List[Row],
    sources_present: List[str],
    added_ids: Iterable[str],
) -> None:
    by_id, by_key = _accepted_lookup(accepted_before)
    added = set(added_ids)
    generated_rows: List[Dict[str, Any]] = []
    accepted: List[Dict[str, Any]] = []
    missing: List[Dict[str, Any]] = []

    for item in generated:
        row = item.row
        accepted_row_id = by_id.get(row.id) or by_key.get(_row_match_key(row))
        diff_status = "accepted" if accepted_row_id else "missing"
        rec = row.to_dict()
        rec.update({
            "advisory": True,
            "generated_from": item.generated_from,
            "source_file": item.source_file,
            "source_id": item.source_id,
            "diff_status": diff_status,
            "accepted_row_id": accepted_row_id,
            "added_to_ledger_by_this_run": row.id in added,
        })
        generated_rows.append(rec)
        summary = {
            "generated_id": row.id,
            "accepted_row_id": accepted_row_id,
            "scope_asset": row.scope_asset,
            "invariant_family": row.invariant_family,
            "statement": row.statement,
            "source_file": item.source_file,
            "source_id": item.source_id,
        }
        if accepted_row_id:
            accepted.append(summary)
        else:
            missing.append(summary)

    payload = {
        "schema_version": GENERATED_INVARIANTS_SCHEMA,
        "schema": GENERATED_INVARIANTS_SCHEMA,
        "workspace": str(ws),
        "generated_at": _now_iso(),
        "advisory": True,
        "source_files": sources_present,
        "generated_count": len(generated_rows),
        "accepted_before_count": len(accepted),
        "missing_before_count": len(missing),
        "added_to_ledger_count": len(added),
        "generated_rows": generated_rows,
        "diff": {
            "accepted": accepted,
            "missing": missing,
        },
        "next_command": (
            "Review diff.missing, edit accepted rows in INVARIANT_LEDGER.md, "
            "then run `python3 tools/invariant-ledger.py --workspace <ws> --check`."
        ),
    }
    out = generated_invariants_path(ws)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")


def _seed_from_scope_md(text: str, prefix: str) -> List[Row]:
    rows: List[Row] = []
    seen: set = set()
    n = 0
    for line in text.splitlines():
        m = _SCOPE_HEADING_RE.match(line)
        if not m:
            continue
        title = m.group(1).strip()
        # Skip the document title (top-level "# Scope" etc.) — we want
        # subsystem-level subheadings.
        if line.startswith("# ") and not line.startswith("## "):
            continue
        if title.lower() in seen:
            continue
        seen.add(title.lower())
        n += 1
        rid = f"{prefix}-SCOPE-{n:02d}"
        slug = _slugify(rid.lower())
        rows.append(Row(
            id=rid,
            scope_asset=title,
            invariant_family="scope_seeded",
            statement=f"TODO: define invariant for `{title}`.",
            source_citations=[f"SCOPE.md::{title}"],
            attacker_capability=(
                "Generated scope seed: fill the exact non-privileged "
                "attacker capability before promotion."
            ),
            trusted_boundary=(
                "Generated scope seed: map the trusted admin/operator/"
                "sequencer/prover boundary before promotion."
            ),
            oos_boundary=(
                "Generated scope seed: run OOS and exact impact-contract "
                "checks before promotion."
            ),
            production_path=(
                f"Generated scope seed: map the production path for `{title}` "
                "before harness work."
            ),
            harness_target=(
                f"EXPECTED:.auditooor/harness_plans/{slug}.json "
                "(generated scope seed)"
            ),
            required_engine="manual",
            negative_test=(
                f"Generated scope seed: define the concrete invalid state or "
                f"input for `{title}` before harness work."
            ),
            status="missing_harness",
            artifacts=[],
            owner="unknown",
            notes="generated_from_scope_md=true; advisory_only=true",
            created=_now_iso(),
        ))
    return rows


def _seed_from_submissions(text: str, prefix: str) -> List[Row]:
    rows: List[Row] = []
    n = 0
    # Match plausible submission rows: any non-blank line under a
    # "## " heading that is not a meta block.
    for line in text.splitlines():
        m = re.match(r"^[-*]\s+(.+?)\s*$", line)
        if not m:
            continue
        title = m.group(1).strip()
        # Skip checklist-only lines.
        if title.lower().startswith(("[", "todo", "see ")):
            continue
        n += 1
        rid = f"{prefix}-PRIOR-{n:02d}"
        slug = _slugify(rid.lower())
        rows.append(Row(
            id=rid,
            scope_asset="(prior submission)",
            invariant_family="prior_finding_anti_regression",
            statement=f"Prior finding must remain non-regressed: {title[:120]}",
            source_citations=[f"submissions/SUBMISSIONS.md::{title[:80]}"],
            attacker_capability=(
                "Generated prior-finding seed: recover the original attacker "
                "capability from the cited submission before promotion."
            ),
            trusted_boundary=(
                "Generated prior-finding seed: recover the original trusted "
                "boundary from the cited submission before promotion."
            ),
            oos_boundary=(
                "Generated prior-finding seed: re-run OOS and exact "
                "impact-contract checks before promotion."
            ),
            production_path=(
                "Generated prior-finding seed: recover the original production "
                f"path for `{title[:80]}` before harness work."
            ),
            harness_target=(
                f"EXPECTED:.auditooor/harness_plans/{slug}.json "
                "(generated prior-finding seed)"
            ),
            required_engine="manual",
            negative_test=(
                "Generated prior-finding seed: encode the historical failing "
                "sequence as a negative regression test before harness work."
            ),
            status="missing_harness",
            artifacts=[],
            owner="unknown",
            notes="generated_from_submissions=true; advisory_only=true",
            created=_now_iso(),
        ))
        if n >= 32:  # cap to avoid floods
            break
    return rows


def _seed_from_severity_md(text: str, prefix: str, rel: str) -> List[GeneratedInvariant]:
    rows: List[GeneratedInvariant] = []
    severity: Optional[str] = None
    n = 0
    for lineno, line in enumerate(text.splitlines(), start=1):
        heading = _SEVERITY_HEADING_RE.match(line)
        if heading:
            severity = heading.group(1).capitalize()
            continue
        bullet = _BULLET_RE.match(line)
        if not bullet or not severity:
            continue
        impact = _clean_inline_markdown(bullet.group(1))
        if not impact or impact.lower().startswith(("[", "todo", "n/a")):
            continue
        n += 1
        rel_slug = _slugify(rel.replace(".", "-"))[:12]
        rid = f"{prefix}-IMPACT-{rel_slug}-{n:02d}"
        row = _candidate_row_for_impact(
            rid=rid,
            impact=impact,
            citation=f"{rel}:L{lineno}",
            severity=severity,
            scope_asset=f"{severity} program impact",
        )
        rows.append(GeneratedInvariant(
            row=row,
            generated_from="severity_markdown",
            source_file=rel,
            source_id=f"L{lineno}",
        ))
        if n >= 64:
            break
    return rows


def _seed_from_impact_worklists(ws: Path, prefix: str, rel: str) -> List[GeneratedInvariant]:
    path = ws / rel
    try:
        data = _read_json(path)
    except LedgerError as e:
        print(f"[invariant-ledger] WARN from-scope: could not parse {rel}: {e}", file=sys.stderr)
        return []
    if not isinstance(data, dict):
        return []
    worklists = data.get("worklists")
    if not isinstance(worklists, list):
        return []

    rows: List[GeneratedInvariant] = []
    for idx, item in enumerate(worklists, start=1):
        if not isinstance(item, dict):
            continue
        impact = _clean_inline_markdown(str(item.get("impact") or item.get("impact_sentence") or ""))
        if not impact:
            continue
        impact_id = str(item.get("impact_id") or item.get("id") or f"worklist-{idx}")
        severity = item.get("severity")
        severity_s = str(severity).capitalize() if severity else None
        scoped_assets = item.get("scoped_assets")
        if isinstance(scoped_assets, list) and scoped_assets:
            scope_asset = ", ".join(str(a) for a in scoped_assets[:3])
        else:
            scope_asset = str(item.get("asset_category") or item.get("scope_asset") or "impact family")
        rid = f"{prefix}-WORKLIST-{idx:02d}"
        row = _candidate_row_for_impact(
            rid=rid,
            impact=impact,
            citation=f"{rel}::{impact_id}",
            severity=severity_s,
            scope_asset=scope_asset,
        )
        if item.get("required_evidence_class"):
            row.notes = (
                f"{row.notes}; required_evidence_class="
                f"{str(item.get('required_evidence_class'))[:120]}"
            )
        rows.append(GeneratedInvariant(
            row=row,
            generated_from="impact_family_worklist",
            source_file=rel,
            source_id=impact_id,
        ))
        if len(rows) >= 64:
            break
    return rows


def _strip_solidity_comments(text: str) -> str:
    def _block_repl(match: re.Match) -> str:
        return "\n" * match.group(0).count("\n")

    text = re.sub(r"/\*.*?\*/", _block_repl, text, flags=re.S)
    return re.sub(r"//.*", "", text)


def _split_solidity_params(params: str) -> List[SolidityParam]:
    out: List[SolidityParam] = []
    for raw in params.split(","):
        part = re.sub(r"\s+", " ", raw.strip())
        if not part:
            continue
        tokens = part.split(" ")
        if len(tokens) < 2:
            continue
        name = tokens[-1]
        if name in ("memory", "calldata", "storage", "payable"):
            continue
        if not re.match(r"^[A-Za-z_][A-Za-z0-9_]*$", name):
            continue
        out.append(SolidityParam(name=name, typ=" ".join(tokens[:-1])))
    return out


def _matching_brace_index(text: str, open_idx: int) -> Optional[int]:
    depth = 0
    for idx in range(open_idx, len(text)):
        ch = text[idx]
        if ch == "{":
            depth += 1
        elif ch == "}":
            depth -= 1
            if depth == 0:
                return idx
    return None


def _nearest_solidity_contract(text: str, offset: int) -> str:
    name = "(unknown contract)"
    for m in _SOL_CONTRACT_RE.finditer(text[:offset]):
        name = m.group(1)
    return name


def _parse_solidity_functions(text: str) -> List[SolidityFunction]:
    stripped = _strip_solidity_comments(text)
    functions: List[SolidityFunction] = []
    for m in _SOL_FUNCTION_RE.finditer(stripped):
        tail = m.group("tail") or ""
        vis = ""
        vis_match = re.search(r"\b(public|external)\b", tail)
        if vis_match:
            vis = vis_match.group(1)
        else:
            continue
        open_idx = stripped.find("{", m.end() - 1)
        if open_idx < 0:
            continue
        close_idx = _matching_brace_index(stripped, open_idx)
        if close_idx is None:
            continue
        functions.append(SolidityFunction(
            name=m.group("name"),
            visibility=vis,
            params=_split_solidity_params(m.group("params") or ""),
            body=stripped[open_idx + 1:close_idx],
            line=stripped.count("\n", 0, m.start()) + 1,
            contract=_nearest_solidity_contract(stripped, m.start()),
        ))
    return functions


def _iter_solidity_source_paths(ws: Path) -> List[Path]:
    paths: List[Path] = []
    try:
        candidates = sorted(ws.rglob("*.sol"))
    except OSError:
        return paths
    for path in candidates:
        try:
            rel = path.relative_to(ws)
        except ValueError:
            continue
        if any(part in _SOL_SKIP_DIRS or part.startswith(".") for part in rel.parts[:-1]):
            continue
        try:
            if path.stat().st_size > 750_000:
                continue
        except OSError:
            continue
        paths.append(path)
        if len(paths) >= 96:
            break
    return paths


def _solidity_config_param_names(fn: SolidityFunction) -> List[str]:
    names: List[str] = []
    for param in fn.params:
        lname = param.name.lower()
        ltyp = param.typ.lower().replace(" ", "")
        if (
            any(tok in lname for tok in _SOL_CONFIG_NAME_TOKENS)
            or any(tok in ltyp for tok in _SOL_CONFIG_TYPE_TOKENS)
        ):
            names.append(param.name)
    return names


def _solidity_shared_config_args(create_fn: SolidityFunction, action_fn: SolidityFunction) -> List[str]:
    action_param_names = {p.name.lower() for p in action_fn.params}
    action_body = action_fn.body
    shared: List[str] = []
    for name in _solidity_config_param_names(create_fn):
        lname = name.lower()
        if lname in action_param_names or re.search(rf"\b{re.escape(name)}\b", action_body):
            shared.append(name)
    return shared


def _high_confidence_solidity_reuse(shared: List[str]) -> bool:
    lowered = {s.lower() for s in shared}
    if len(lowered) >= 2:
        return True
    return bool(lowered & {"config", "params", "key", "poolkey", "poolconfig"})


def _solidity_invariant_row(
    *,
    rid: str,
    rel: str,
    create_fn: SolidityFunction,
    action_fn: SolidityFunction,
    shared_args: List[str],
    family: str,
) -> Row:
    contract = create_fn.contract
    shared = ", ".join(shared_args)
    slug = _slugify(f"{contract}-{family}")[:48].lower()
    path = (
        f"{rel}:L{create_fn.line}::{contract}.{create_fn.name} -> "
        f"{rel}:L{action_fn.line}::{action_fn.contract}.{action_fn.name}"
    )
    if family == "factory_created_pool_liveness_after_liquidity":
        statement = (
            f"Pools/hooks created through `{contract}.{create_fn.name}` with "
            f"config args `{shared}` must remain live after "
            f"`{action_fn.contract}.{action_fn.name}` liquidity/pool action."
        )
        negative = (
            f"Create a pool/hook with boundary config `{shared}`, then run "
            f"`{action_fn.name}` and assert user liquidity/action state is not "
            "bricked or stranded."
        )
    else:
        statement = (
            f"Factory config/domain args `{shared}` reused by "
            f"`{action_fn.contract}.{action_fn.name}` must stay inside the "
            "factory-defined valid domain before pool/hook state changes."
        )
        negative = (
            f"Attempt out-of-domain `{shared}` values through `{create_fn.name}` "
            f"and `{action_fn.name}`; the factory/action path must reject before "
            "state or user funds move."
        )
    return Row(
        id=rid,
        scope_asset=f"{contract} factory/pool lifecycle",
        invariant_family=family,
        statement=statement,
        source_citations=[f"{rel}:L{create_fn.line}", f"{rel}:L{action_fn.line}"],
        attacker_capability=(
            "non-privileged caller of public/external factory create/deploy "
            "and pool/liquidity/hook action paths"
        ),
        trusted_boundary=(
            "factory config validation, pool implementation, hook contract, "
            "and any admin-selected templates are trusted to enforce bounds"
        ),
        oos_boundary=(
            "OOS if exploit requires privileged template changes or admin-only "
            "configuration after deployment"
        ),
        production_path=path,
        harness_target=f"EXPECTED:poc-tests/{slug}.t.sol (generated advisory)",
        required_engine="forge",
        negative_test=negative,
        status="missing_harness",
        artifacts=[],
        owner="unknown",
        notes=(
            "generated_from_solidity=true; advisory_only=true; "
            f"shared_config_args={shared}"
        ),
        created=_now_iso(),
    )


def _derive_subsystem_from_slug(slug: str) -> str:
    """Derive a human-readable subsystem name from a detector slug.

    Examples:
      go.crypto.race.unsynchronized_concurrent_access -> crypto/race
      lock-extension-griefing                          -> lock-extension
      erc4626-balanceOf-this-in-share-calc             -> erc4626
    """
    # Dot-namespaced slugs: take the middle segment(s)
    if "." in slug:
        parts = slug.split(".")
        # Skip the language prefix (go, sol, rust) if it's a single token
        if len(parts) >= 3:
            return "/".join(parts[1:3])
        if len(parts) == 2:
            return parts[1]
        return parts[0]
    # Hyphen-namespaced slugs: use the first meaningful token(s)
    parts = slug.split("-")
    if len(parts) >= 2:
        return "-".join(parts[:2])
    return slug


def _attack_class_for_slug(slug: str) -> str:
    """Map a detector slug to an invariant attack class label."""
    t = slug.lower()
    if any(k in t for k in ("drain", "theft", "loss", "griefing", "fee-on-transfer")):
        return "impact_funds_safety"
    if any(k in t for k in ("state.root", "state-root", "fork", "divergence")):
        return "impact_state_root_integrity"
    if any(k in t for k in ("bridge", "withdrawal", "finalization", "proof", "dispute")):
        return "impact_bridge_finalization"
    if any(k in t for k in ("node", "resource", "cpu", "memory", "shutdown", "panic", "race")):
        return "impact_node_liveness"
    if any(k in t for k in ("oracle", "price", "feed", "chainlink", "stale")):
        return "impact_oracle_integrity"
    if any(k in t for k in ("admin", "governance", "upgrade", "permission", "authorize",
                             "unprotected", "initialize", "access")):
        return "impact_authorization_boundary"
    if any(k in t for k in ("erc4626", "erc20", "erc2771", "eip712", "eip-712",
                             "permit", "signature", "nonce", "ecdsa", "ecrecover")):
        return "impact_contract_linkage"
    return "impact_contract_linkage"


def _engine_for_engage_slug(slug: str) -> str:
    """Infer a harness engine from the detector slug language prefix."""
    if slug.startswith("go."):
        return "go"
    if slug.startswith("rust."):
        return "cargo"
    # Solidity-ish
    return "forge"


def _seed_from_engage_report(
    ws: Path,
    prefix: str,
    existing_ids: set,
) -> List["GeneratedInvariant"]:
    """Seed one missing_harness row per unique subsystem derived from engage_report.json.

    The function reads:
      1. <ws>/engage_report.json  (primary)
      2. <ws>/engage_report.md    (fallback - presence-only, slugs extracted from
         lines matching "## <slug>" or "| <slug> |")

    For each cluster whose detector_slug has not yet been mapped to an accepted
    ledger row, it derives:
      - A subsystem label  (from the slug's namespace prefix)
      - An attack class    (heuristic mapping to impact_* family)
      - An engine          (from slug language prefix)
      - Source citations   (engage_report.json::<slug>)

    Idempotent: existing_ids is passed in so already-accepted subsystem rows
    are not re-emitted.

    Returns a list of GeneratedInvariant items (empty on missing input; never
    raises).
    """
    # --- Try JSON first ---
    json_p = ws / "engage_report.json"
    clusters: List[Dict[str, Any]] = []
    source_file = "engage_report.json"
    if json_p.is_file():
        try:
            data = _read_json(json_p)
        except LedgerError as exc:
            print(
                f"[invariant-ledger] WARN from-scope engage_report: "
                f"could not parse {json_p}: {exc}",
                file=sys.stderr,
            )
            data = None
        if isinstance(data, dict):
            raw_clusters = data.get("clusters")
            if isinstance(raw_clusters, list):
                clusters = [c for c in raw_clusters if isinstance(c, dict)]
    # --- Fallback: parse .md for slug lines ---
    if not clusters:
        md_p = ws / "engage_report.md"
        if md_p.is_file():
            source_file = "engage_report.md"
            text = _read_text(md_p)
            # Extract detector slugs from headings or table rows
            slug_re = re.compile(r"(?:^##\s+|^\|\s*)([a-z][a-z0-9._-]+(?:\.[a-z0-9._-]+)+|[a-z][a-z0-9_-]+-[a-z][a-z0-9_-]+[^\|\s]*)")
            seen_md: set = set()
            for line in text.splitlines():
                m = slug_re.search(line)
                if m:
                    slug = m.group(1).strip().rstrip("|").strip()
                    if slug and slug not in seen_md:
                        seen_md.add(slug)
                        clusters.append({"detector_slug": slug, "hit_count": 1, "hits": []})

    if not clusters:
        return []

    # Derive subsystems and deduplicate
    # key = (subsystem_label, attack_class)  ->  aggregate cluster info
    subsystem_map: Dict[str, Dict[str, Any]] = {}
    for cluster in clusters:
        slug = str(cluster.get("detector_slug", "")).strip()
        if not slug:
            continue
        subsystem = _derive_subsystem_from_slug(slug)
        attack_class = _attack_class_for_slug(slug)
        key = f"{subsystem}::{attack_class}"
        if key not in subsystem_map:
            subsystem_map[key] = {
                "subsystem": subsystem,
                "attack_class": attack_class,
                "engine": _engine_for_engage_slug(slug),
                "slugs": [],
                "hit_counts": [],
            }
        subsystem_map[key]["slugs"].append(slug)
        subsystem_map[key]["hit_counts"].append(int(cluster.get("hit_count", 0)))

    generated: List["GeneratedInvariant"] = []
    n = 0
    for key, info in sorted(subsystem_map.items()):
        n += 1
        rid = f"{prefix}-ENG-{n:02d}"
        # Always generate the row and append to `generated` so the
        # generated-vs-accepted diff counter in cmd_from_scope can see it.
        # The caller's own `if r.id in existing_ids: continue` guard prevents
        # already-accepted rows from being added to candidates.  Removing the
        # early-exit here fixes the diff-count accounting bug where run-2
        # always showed already_accepted=0 for engage-report rows.
        subsystem = info["subsystem"]
        attack_class = info["attack_class"]
        engine = info["engine"]
        slugs = info["slugs"]
        total_hits = sum(info["hit_counts"])
        slug_list = ", ".join(slugs[:4]) + ("..." if len(slugs) > 4 else "")
        slug = _slugify(f"{prefix}-eng-{n:02d}").lower()

        row = Row(
            id=rid,
            scope_asset=subsystem,
            invariant_family=attack_class,
            statement=(
                f"Subsystem `{subsystem}` must not expose the "
                f"`{attack_class}` invariant family: engage-report detectors "
                f"`{slug_list}` fired ({total_hits} hit(s))."
            )[:240],
            source_citations=[f"{source_file}::{slugs[0]}"],
            attacker_capability=(
                "Generated engage-report seed: fill the exact non-privileged "
                "attacker input/control before promotion."
            ),
            trusted_boundary=(
                "Generated engage-report seed: map trusted admin/operator/"
                "sequencer/prover boundary before promotion."
            ),
            oos_boundary=(
                "Generated engage-report seed: run OOS and exact impact-contract "
                "checks before promotion."
            ),
            production_path=(
                f"Generated engage-report seed: map the production path for "
                f"`{subsystem}` ({slug_list}) before harness work."
            ),
            harness_target=(
                f"EXPECTED:.auditooor/harness_plans/{slug}.json "
                "(generated engage-report seed)"
            ),
            required_engine=engine,
            negative_test=(
                f"Generated engage-report seed: construct a counterexample "
                f"that proves `{attack_class}` via `{subsystem}` "
                f"(detectors: {slug_list})."
            ),
            status="missing_harness",
            artifacts=[],
            owner="unknown",
            notes=(
                f"generated_from_engage_report=true; advisory_only=true; "
                f"detector_slugs={','.join(slugs[:8])}; "
                f"total_hits={total_hits}"
            ),
            created=_now_iso(),
        )
        generated.append(GeneratedInvariant(
            row=row,
            generated_from="engage_report",
            source_file=source_file,
            source_id=key,
        ))
        if n >= 64:
            break
    return generated


def _seed_from_solidity_factory_pool_liveness(
    ws: Path,
    prefix: str,
) -> Tuple[List[GeneratedInvariant], List[str]]:
    rows: List[GeneratedInvariant] = []
    sources_present: List[str] = []
    n = 0
    for path in _iter_solidity_source_paths(ws):
        try:
            rel = str(path.relative_to(ws))
        except ValueError:
            continue
        sources_present.append(rel)
        text = _read_text(path)
        if not text:
            continue
        functions = _parse_solidity_functions(text)
        create_fns = [
            fn for fn in functions
            if _SOL_CREATE_RE.search(fn.name) and len(_solidity_config_param_names(fn)) >= 2
        ]
        action_fns = [
            fn for fn in functions
            if _SOL_POOL_ACTION_RE.search(fn.name) and not _SOL_CREATE_RE.search(fn.name)
        ]
        for create_fn in create_fns:
            for action_fn in action_fns:
                shared = _solidity_shared_config_args(create_fn, action_fn)
                if not _high_confidence_solidity_reuse(shared):
                    continue
                n += 1
                source_id = f"{create_fn.contract}.{create_fn.name}->{action_fn.contract}.{action_fn.name}"
                live_row = _solidity_invariant_row(
                    rid=f"{prefix}-SOL-LIVE-{n:02d}",
                    rel=rel,
                    create_fn=create_fn,
                    action_fn=action_fn,
                    shared_args=shared,
                    family="factory_created_pool_liveness_after_liquidity",
                )
                config_row = _solidity_invariant_row(
                    rid=f"{prefix}-SOL-CONFIG-{n:02d}",
                    rel=rel,
                    create_fn=create_fn,
                    action_fn=action_fn,
                    shared_args=shared,
                    family="config_domain_bounds",
                )
                rows.append(GeneratedInvariant(
                    row=live_row,
                    generated_from="solidity_factory_pool_liveness",
                    source_file=rel,
                    source_id=source_id,
                ))
                rows.append(GeneratedInvariant(
                    row=config_row,
                    generated_from="solidity_factory_pool_liveness",
                    source_file=rel,
                    source_id=source_id,
                ))
                break
            if n >= 32:
                break
        if n >= 32:
            break
    return rows, sources_present


# ---------------------------------------------------------------------------
# P1-7: registry stateful-gate -> pool-liveness invariant row seeding
# ---------------------------------------------------------------------------

def _load_registry_tiers() -> Dict[str, Any]:
    """Load detectors/_tier_registry.yaml tiers dict.  Returns {} on any error.

    Uses PyYAML when available (it is a project dependency per requirements.txt).
    Degrades to an empty dict — emitting a stderr warning — if PyYAML is absent
    or the file is missing/corrupt.  The caller must handle an empty result
    gracefully (zero rows seeded = backward-compatible no-op).
    """
    if not _TIER_REGISTRY_PATH.is_file():
        return {}
    try:
        import yaml as _yaml  # noqa: PLC0415
        raw = _yaml.safe_load(_TIER_REGISTRY_PATH.read_text(encoding="utf-8")) or {}
    except ImportError:
        print(
            "[invariant-ledger] WARN P1-7: PyYAML not available — "
            "skipping registry pool-liveness seeding (pip install pyyaml).",
            file=sys.stderr,
        )
        return {}
    except Exception as exc:
        print(
            f"[invariant-ledger] WARN P1-7: could not parse {_TIER_REGISTRY_PATH}: {exc}",
            file=sys.stderr,
        )
        return {}
    tiers = raw.get("tiers") if isinstance(raw, dict) else None
    return tiers if isinstance(tiers, dict) else {}


def _registry_row_is_full_stateful(row: Dict[str, Any]) -> bool:
    """Return True only when all 6 stateful-gate fields are present and well-typed.

    Mirrors the type-checking in detector-promote._check_factory_pool_state_flow
    but returns a bool rather than a decision string.
    """
    if not isinstance(row, dict):
        return False
    for fld in _FACTORY_STATEFUL_FIELDS:
        val = row.get(fld)
        if val is None:
            return False
        if fld == "liquidity_acceptance":
            if not isinstance(val, bool):
                return False
        elif fld == "downstream_liveness":
            if not (isinstance(val, list) and val
                    and all(isinstance(x, str) and x for x in val)):
                return False
        else:
            if not (isinstance(val, str) and val.strip()):
                return False
    sev = str(row.get("conservative_severity_state") or "").strip().lower()
    return sev in ("medium", "med", "low", "informational", "info")


def _pool_liveness_invariant_row(
    detector_name: str,
    reg_row: Dict[str, Any],
    prefix: str,
    n: int,
) -> "Row":
    """Synthesise one pool-liveness invariant Row from a populated registry entry.

    - id           = <PREFIX>-REGSVC-<nn>
    - invariant_family = factory_created_pool_liveness_after_liquidity
    - status       = missing_harness  (honest: no harness exists yet)
    - notes        mark P1-7 auto-seed provenance
    """
    entrypoint: str = reg_row["entrypoint"]
    tracked_pool: str = reg_row["tracked_pool"]
    downstream: List[str] = reg_row["downstream_liveness"]
    invalid_cfg: str = reg_row["invalid_config"]
    sev_state: str = reg_row["conservative_severity_state"]
    downstream_str = " -> ".join(downstream)
    slug = _slugify(f"{detector_name}-pool-liveness")[:48].lower()
    return Row(
        id=f"{prefix}-REGSVC-{n:02d}",
        scope_asset=f"{tracked_pool} pool lifecycle (factory: {entrypoint})",
        invariant_family="factory_created_pool_liveness_after_liquidity",
        statement=(
            f"Pools created via `{entrypoint}` must remain live after "
            f"liquidity actions — downstream call chain "
            f"`{downstream_str}` must not brick or strand user funds when "
            f"factory config `{invalid_cfg}` is supplied."
        ),
        source_citations=[
            f"detectors/_tier_registry.yaml::{detector_name}",
            "detector-promote.py::_check_factory_pool_state_flow",
        ],
        attacker_capability=(
            "non-privileged caller of the public factory entrypoint and "
            "pool liquidity/action paths"
        ),
        trusted_boundary=(
            "factory config validation, pool implementation, and any "
            "admin-selected templates are trusted to enforce domain bounds"
        ),
        oos_boundary=(
            "OOS if exploit requires privileged template changes or "
            "admin-only configuration after deployment"
        ),
        production_path=(
            f"detectors/_tier_registry.yaml::{detector_name} "
            f"entrypoint={entrypoint} tracked_pool={tracked_pool} "
            f"downstream={downstream_str}"
        ),
        harness_target=f"EXPECTED:poc-tests/{slug}.t.sol (P1-7 advisory)",
        required_engine="forge",
        negative_test=(
            f"Create a pool via `{entrypoint}` with boundary config "
            f"`{invalid_cfg}`, then call `{downstream_str}` and assert "
            "user liquidity/action state is not bricked or stranded."
        ),
        status="missing_harness",
        artifacts=[],
        owner="unknown",
        severity=sev_state,
        notes=(
            f"generated_from_registry_stateful=true; advisory_only=true; "
            f"detector={detector_name}; "
            f"conservative_severity_state={sev_state}; "
            f"P1-7=pool_liveness_auto_seed"
        ),
        created=_now_iso(),
    )


def _seed_from_registry_stateful(
    prefix: str,
    existing_ids: set,
) -> Tuple[List["GeneratedInvariant"], int]:
    """Emit one invariant Row per registry entry that has all 6 stateful-gate
    fields set and passes the conservative-severity-state check.

    Returns (generated_list, total_stateful_rows_in_registry).
    P1-7 bridge: reads detectors/_tier_registry.yaml stateful fields and
    projects them into pool-liveness invariant rows (status=missing_harness).
    """
    tiers = _load_registry_tiers()
    if not tiers:
        return [], 0
    generated: List[GeneratedInvariant] = []
    n = 0
    for detector_name, reg_row in sorted(tiers.items()):
        if not _registry_row_is_full_stateful(reg_row):
            continue
        n += 1
        row = _pool_liveness_invariant_row(detector_name, reg_row, prefix, n)
        source_id = (
            f"{detector_name}::{reg_row['entrypoint']}->"
            f"{reg_row['tracked_pool']}->"
            f"{'|'.join(reg_row['downstream_liveness'])}"
        )
        generated.append(GeneratedInvariant(
            row=row,
            generated_from="registry_stateful_pool_liveness",
            source_file=str(_TIER_REGISTRY_PATH.relative_to(_REPO_ROOT)),
            source_id=source_id,
        ))
    return generated, n


def cmd_from_scope(
    ws: Path,
    *,
    dry_run: bool = False,
    print_json: bool = False,
) -> int:
    """Seed candidate rows from scope sources + engage_report.

    Parameters
    ----------
    dry_run:
        If True, print candidates to stdout but do NOT write to disk.
        The generated_invariants.json sidecar is also not written.
    print_json:
        If True, also print a JSON summary block to stdout (after the
        normal human-readable output).  Safe to combine with dry_run.

    The generated-vs-accepted diff block is always printed (both modes),
    showing:
      - generated_total   : rows emitted by all seeders this run
      - already_accepted  : generated rows whose id/key already in ledger
      - newly_added       : rows written to the ledger (0 in dry-run mode)
      - still_missing     : generated rows not yet accepted (gap to close)
    """
    if not ws.exists():
        print(f"[invariant-ledger] error: workspace not found: {ws}", file=sys.stderr)
        return 2
    prefix = ws.name.upper().replace("-", "")[:8] or "WS"
    existing = load_rows(ws)
    existing_ids = {r.id for r in existing}
    candidates: List[Row] = []
    generated: List[GeneratedInvariant] = []
    sources_present: List[str] = []

    for rel in FROM_SCOPE_SOURCES:
        p = ws / rel
        if not p.is_file():
            continue
        sources_present.append(rel)
        if rel == ".auditooor/impact_family_worklists.json":
            seeded = _seed_from_impact_worklists(ws, prefix, rel)
            generated.extend(seeded)
            for item in seeded:
                r = item.row
                if r.id in existing_ids:
                    continue
                existing_ids.add(r.id)
                candidates.append(r)
            continue
        text = _read_text(p)
        if not text:
            continue
        if rel.endswith("SUBMISSIONS.md"):
            for r in _seed_from_submissions(text, prefix):
                generated.append(GeneratedInvariant(
                    row=r,
                    generated_from="submission_anti_regression",
                    source_file=rel,
                    source_id=r.source_citations[0] if r.source_citations else r.id,
                ))
                if r.id in existing_ids:
                    continue
                existing_ids.add(r.id)
                candidates.append(r)
        elif rel.startswith("SEVERITY") or rel == "RUBRIC_COVERAGE.md":
            seeded = _seed_from_severity_md(text, prefix, rel)
            generated.extend(seeded)
            for item in seeded:
                r = item.row
                if r.id in existing_ids:
                    continue
                existing_ids.add(r.id)
                candidates.append(r)
        elif rel.endswith(".md") or rel == "README":
            for r in _seed_from_scope_md(text, prefix):
                generated.append(GeneratedInvariant(
                    row=r,
                    generated_from="scope_markdown",
                    source_file=rel,
                    source_id=r.source_citations[0] if r.source_citations else r.id,
                ))
                if r.id in existing_ids:
                    continue
                existing_ids.add(r.id)
                candidates.append(r)
        # JSON sources (intake/topology) are not row-seeded here; they're
        # consumed by --check artifact validation. The plan calls for
        # _reading_ them; we surface their presence in the closeout.

    solidity_generated, solidity_sources = _seed_from_solidity_factory_pool_liveness(ws, prefix)
    for rel in solidity_sources:
        if rel not in sources_present:
            sources_present.append(rel)
    generated.extend(solidity_generated)
    for item in solidity_generated:
        r = item.row
        if r.id in existing_ids:
            continue
        existing_ids.add(r.id)
        candidates.append(r)

    # P1-7: seed pool-liveness invariant rows from registry stateful-gate fields.
    # Only run when the workspace is the repo root itself (or a workspace that
    # contains its own detector/_tier_registry.yaml).  The registry lives at
    # _REPO_ROOT / detectors / _tier_registry.yaml and is a global resource;
    # injecting registry rows into arbitrary external workspaces (temp dirs,
    # client engagements) was unintentional and caused:
    #   - Tests 15/18: registry rows with required_engine="forge" polluted
    #     workspaces expected to contain only "manual" scope-seeded rows.
    #   - Tests 17/h1_only/solidity_no_config: registry rows provided
    #     candidates that bypassed the rc=2 advisory path for empty/partial
    #     workspaces.
    _ws_registry = ws / "detectors" / "_tier_registry.yaml"
    _run_registry = _ws_registry.is_file() or ws.resolve() == _REPO_ROOT.resolve()
    registry_generated, registry_total = (
        _seed_from_registry_stateful(prefix, existing_ids)
        if _run_registry else ([], 0)
    )
    generated.extend(registry_generated)
    registry_new = 0
    for item in registry_generated:
        r = item.row
        if r.id in existing_ids:
            continue
        existing_ids.add(r.id)
        candidates.append(r)
        registry_new += 1
    if registry_total > 0:
        src_key = str(_TIER_REGISTRY_PATH.relative_to(_REPO_ROOT))
        if src_key not in sources_present:
            sources_present.append(src_key)
        print(
            f"[invariant-ledger] P1-7 pool-liveness: {registry_total} registry "
            f"stateful row(s) scanned, {registry_new} new invariant row(s) seeded."
        )

    # Engage-report seeding: read engage_report.json (or .md fallback) and
    # emit one missing_harness row per unique subsystem / attack-class cluster
    # not already present in the ledger. This is the --from-scope engage_report
    # extension that closes KLBQ item #5 (invariant discovery completeness).
    engage_generated = _seed_from_engage_report(ws, prefix, existing_ids)
    engage_new = 0
    for item in engage_generated:
        r = item.row
        generated.append(item)
        if r.id in existing_ids:
            continue
        existing_ids.add(r.id)
        candidates.append(r)
        engage_new += 1
    if engage_new > 0 or engage_generated:
        er_src = "engage_report.json" if (ws / "engage_report.json").is_file() else "engage_report.md"
        if er_src not in sources_present:
            sources_present.append(er_src)
        print(
            f"[invariant-ledger] engage-report: {len(engage_generated)} subsystem cluster(s) "
            f"derived, {engage_new} new missing_harness row(s) seeded."
        )

    # -----------------------------------------------------------------------
    # Generated-vs-accepted diff: compute before mutating the ledger.
    # This is the "diffable candidate ledger" the KLBQ item requires:
    # how many candidate rows are newly generated vs already accepted.
    # -----------------------------------------------------------------------
    by_id, by_key = _accepted_lookup(existing)
    diff_already_accepted = 0
    diff_newly_added = 0      # will be updated below (0 in dry-run mode)
    diff_still_missing = 0

    for item in generated:
        row = item.row
        if by_id.get(row.id) or by_key.get(_row_match_key(row)):
            diff_already_accepted += 1
        else:
            diff_still_missing += 1

    # In non-dry-run mode, candidates that pass the id-dedup above are written
    # to the ledger; those are the "newly_added" rows.
    diff_newly_added_rows = candidates  # will be 0 in dry_run path

    # Write generated_invariants.json sidecar (unless dry_run).
    if not dry_run:
        _write_generated_invariants(
            ws,
            generated,
            existing,
            sources_present,
            [r.id for r in candidates],
        )

    if not candidates:
        # Distinguish "no sources matched" (informational) from
        # "sources matched but yielded zero rows" (silent-zero advisory).
        # The latter is the case where a SCOPE.md exists but only has
        # an H1 — pre-fix this returned rc=0 silently. We now emit a
        # WARN to stderr listing what `--from-scope` looked for and
        # exit 2 (advisory).
        if existing:
            # Operator already has rows; new run found nothing — that
            # is fine (additive semantics).
            print(
                "[invariant-ledger] from-scope: no NEW candidate rows seeded "
                f"({len(existing)} existing row(s) preserved)."
            )
            if not dry_run:
                save_rows(ws, existing)
            _print_diff_block(
                generated_total=len(generated),
                already_accepted=diff_already_accepted,
                newly_added=0,
                still_missing=diff_still_missing,
                dry_run=dry_run,
                print_json=print_json,
                candidates=candidates,
            )
            return 0
        if sources_present:
            print(
                "[invariant-ledger] WARN from-scope: sources present but "
                f"yielded zero candidate rows. Looked for: "
                f"{', '.join(FROM_SCOPE_SOURCES)}. Sources matched: "
                f"{', '.join(sources_present)}. Markdown sources need at "
                f"least one `## Subsystem` heading; Solidity sources need "
                f"a public/external create/deploy-style function whose "
                f"config args are reused by a pool/liquidity/hook action. "
                f"H1-only docs are intentionally skipped (the H1 is treated "
                f"as the document title, not a subsystem). Edit the source "
                f"or hand-author rows in INVARIANT_LEDGER.md.",
                file=sys.stderr,
            )
            if not dry_run:
                save_rows(ws, existing)
            return 2  # advisory: not a hard error, but caller should notice
        print(
            "[invariant-ledger] from-scope: no scope/spec files matched. "
            f"Looked for: {', '.join(FROM_SCOPE_SOURCES)}, engage_report.json, "
            "and Solidity source files.",
            file=sys.stderr,
        )
        if not dry_run:
            save_rows(ws, existing)
        return 2
    pool_liveness_count = sum(
        1 for r in candidates
        if r.invariant_family == "factory_created_pool_liveness_after_liquidity"
        and "registry_stateful_pool_liveness" in (r.notes or "")
    )
    engage_count = sum(
        1 for r in candidates
        if "generated_from_engage_report=true" in (r.notes or "")
    )
    parts_seeded = []
    if pool_liveness_count:
        parts_seeded.append(f"pool-liveness from registry: {pool_liveness_count}")
    if engage_count:
        parts_seeded.append(f"engage-report subsystems: {engage_count}")
    summary_suffix = (
        f"  ({'; '.join(parts_seeded)})"
        if parts_seeded else ""
    )

    if dry_run:
        # Print candidates without writing
        print(
            f"[invariant-ledger] from-scope DRY-RUN: {len(candidates)} candidate "
            f"row(s) would be seeded (not written).{summary_suffix}"
        )
        for r in candidates:
            print(
                f"  [{r.id}] scope_asset={r.scope_asset!r} "
                f"family={r.invariant_family} engine={r.required_engine}"
            )
    else:
        print(
            f"[invariant-ledger] from-scope: seeded {len(candidates)} candidate row(s)."
            f"{summary_suffix}"
        )
        merged = existing + candidates
        save_rows(ws, merged)

    # Print the generated-vs-accepted diff block (always, both modes)
    diff_written = 0 if dry_run else len(candidates)
    _print_diff_block(
        generated_total=len(generated),
        already_accepted=diff_already_accepted,
        newly_added=diff_written,
        still_missing=diff_still_missing,
        dry_run=dry_run,
        print_json=print_json,
        candidates=candidates,
    )
    return 0


def _print_diff_block(
    *,
    generated_total: int,
    already_accepted: int,
    newly_added: int,
    still_missing: int,
    dry_run: bool,
    print_json: bool,
    candidates: List["Row"],
) -> None:
    """Print the generated-vs-accepted diff summary block.

    This is the "diffable candidate ledger" the KLBQ item #5 requires.
    Always printed (both dry_run and normal mode).
    """
    mode = "DRY-RUN" if dry_run else "WRITTEN"
    lines = [
        "",
        "=== from-scope generated-vs-accepted diff ===",
        f"  generated_total   : {generated_total}",
        f"  already_accepted  : {already_accepted}",
        f"  newly_added ({mode}): {newly_added}",
        f"  still_missing     : {still_missing}",
        "==============================================",
    ]
    print("\n".join(lines))
    if print_json:
        payload: Dict[str, Any] = {
            "schema": "auditooor.invariant_ledger_from_scope_diff.v1",
            "generated_total": generated_total,
            "already_accepted": already_accepted,
            "newly_added": newly_added,
            "still_missing": still_missing,
            "dry_run": dry_run,
            "candidates": [
                {
                    "id": r.id,
                    "scope_asset": r.scope_asset,
                    "invariant_family": r.invariant_family,
                    "required_engine": r.required_engine,
                    "status": r.status,
                    "notes": r.notes,
                }
                for r in candidates
            ],
        }
        print(json.dumps(payload, indent=2))


# ---------------------------------------------------------------------------
# --from-scope --diff-accepted: 4-bucket scope-vs-ledger drift report
# ---------------------------------------------------------------------------

SCOPE_DIFF_SCHEMA = "auditooor.invariant_ledger_scope_diff.v1"


def scope_diff_path(ws: Path) -> Path:
    return ws / ".auditooor" / "invariant_ledger_scope_diff.json"


def scope_diff_md_path(ws: Path) -> Path:
    return ws / ".auditooor" / "invariant_ledger_scope_diff.md"


def _severity_line_for_row(row: Row, severity_text: str) -> Optional[str]:
    """Return the SEVERITY.md bullet that best matches the row's statement,
    or None if no match is found.

    Used to detect accepted_drifted_rows: if the row has a selected_impact
    note referencing a specific SEVERITY.md line, we verify it still appears
    verbatim in the current severity_text.
    """
    if not severity_text:
        return None
    notes = getattr(row, "notes", "") or ""
    # Extract a referenced SEVERITY.md line from notes, e.g.:
    #   "severity_line:Unauthorized verifier / dispute-game implementation upgrade."
    m = re.search(r"severity_line:(.+?)(?:;|$)", notes)
    if m:
        claimed_line = m.group(1).strip()
        if claimed_line in severity_text:
            return claimed_line
        # Line referenced in notes is no longer in SEVERITY.md → drifted
        return None
    return None  # no claimed line → cannot check drift


def _row_derivable_from_scope(row: Row, generated_ids: set, generated_keys: set) -> bool:
    """Return True if the row can be re-derived from the current scope run.

    A row is 'derivable' if its id OR its normalised match-key appears in
    the freshly-generated set. This is the criterion for
    accepted_unchanged_rows vs accepted_orphaned_rows.
    """
    return (row.id in generated_ids) or (_row_match_key(row) in generated_keys)


def cmd_diff_accepted(ws: Path) -> int:
    """--from-scope --diff-accepted: generate scope-derived invariants,
    then compare against the existing operator-accepted ledger to produce
    a 4-bucket drift report written to .auditooor/invariant_ledger_scope_diff.*
    """
    if not ws.exists():
        print(f"[invariant-ledger] error: workspace not found: {ws}", file=sys.stderr)
        return 2

    # 1. Load the current accepted ledger
    accepted_rows: List[Row] = load_rows(ws)
    if not accepted_rows:
        print(
            "[invariant-ledger] diff-accepted: ledger has no accepted rows. "
            "Run --from-scope first to seed the ledger, then --diff-accepted.",
            file=sys.stderr,
        )
        return 2

    # 2. Generate a fresh set of candidate invariants from scope sources
    #    (same logic as cmd_from_scope, but we do NOT write to the ledger)
    prefix = ws.name.upper().replace("-", "")[:8] or "WS"
    generated: List[GeneratedInvariant] = []
    sources_present: List[str] = []

    for rel in FROM_SCOPE_SOURCES:
        p = ws / rel
        if not p.is_file():
            continue
        sources_present.append(rel)
        if rel == ".auditooor/impact_family_worklists.json":
            seeded = _seed_from_impact_worklists(ws, prefix, rel)
            generated.extend(seeded)
            continue
        text = _read_text(p)
        if not text:
            continue
        if rel.endswith("SUBMISSIONS.md"):
            for r in _seed_from_submissions(text, prefix):
                generated.append(GeneratedInvariant(
                    row=r,
                    generated_from="submission_anti_regression",
                    source_file=rel,
                    source_id=r.source_citations[0] if r.source_citations else r.id,
                ))
        elif rel.startswith("SEVERITY") or rel == "RUBRIC_COVERAGE.md":
            generated.extend(_seed_from_severity_md(text, prefix, rel))
        elif rel.endswith(".md") or rel == "README":
            for r in _seed_from_scope_md(text, prefix):
                generated.append(GeneratedInvariant(
                    row=r,
                    generated_from="scope_markdown",
                    source_file=rel,
                    source_id=r.source_citations[0] if r.source_citations else r.id,
                ))

    solidity_generated, solidity_sources = _seed_from_solidity_factory_pool_liveness(ws, prefix)
    generated.extend(solidity_generated)
    for rel in solidity_sources:
        if rel not in sources_present:
            sources_present.append(rel)

    # 3. Build lookup sets for generated rows
    generated_ids: set = {item.row.id for item in generated}
    generated_keys: set = {_row_match_key(item.row) for item in generated}

    # Load current SEVERITY.md text for drift detection
    severity_text = _read_text(ws / "SEVERITY.md") or _read_text(ws / "SEVERITY_BLOCKCHAIN_DLT.md") or ""

    # 4. Classify the accepted rows into 4 buckets
    newly_generated_rows: List[Dict[str, Any]] = []
    accepted_unchanged_rows: List[Dict[str, Any]] = []
    accepted_drifted_rows: List[Dict[str, Any]] = []
    accepted_orphaned_rows: List[Dict[str, Any]] = []

    # Build accepted lookup for cross-checking
    accepted_ids = {r.id for r in accepted_rows}
    accepted_keys = {_row_match_key(r) for r in accepted_rows}

    # Classify each generated row: newly_generated vs already_accepted
    for item in generated:
        row = item.row
        if (row.id in accepted_ids) or (_row_match_key(row) in accepted_keys):
            # This generated row IS in the accepted ledger — it's unchanged
            # (classified below from the accepted_rows side)
            pass
        else:
            newly_generated_rows.append({
                "generated_id": row.id,
                "scope_asset": row.scope_asset,
                "invariant_family": row.invariant_family,
                "statement": row.statement[:200],
                "generated_from": item.generated_from,
                "source_file": item.source_file,
                "recommendation": "Review and add to ledger via --from-scope or hand-author.",
            })

    # Classify each accepted row
    for row in accepted_rows:
        derivable = _row_derivable_from_scope(row, generated_ids, generated_keys)
        if not derivable:
            # No longer derivable from scope → orphaned
            accepted_orphaned_rows.append({
                "accepted_id": row.id,
                "scope_asset": row.scope_asset,
                "invariant_family": row.invariant_family,
                "statement": row.statement[:200],
                "status": row.status,
                "recommendation": (
                    "Row no longer derivable from scope sources. Verify scope reduction "
                    "or manually re-anchor to updated SCOPE.md/SEVERITY.md section."
                ),
            })
        else:
            # Derivable — check for severity drift
            claimed_line = _severity_line_for_row(row, severity_text)
            notes = getattr(row, "notes", "") or ""
            has_severity_ref = bool(re.search(r"severity_line:", notes))
            if has_severity_ref and claimed_line is None:
                # Had a severity anchor that no longer matches current SEVERITY.md
                accepted_drifted_rows.append({
                    "accepted_id": row.id,
                    "scope_asset": row.scope_asset,
                    "invariant_family": row.invariant_family,
                    "statement": row.statement[:200],
                    "status": row.status,
                    "drift_reason": (
                        "Row's severity_line note no longer matches current SEVERITY.md. "
                        "Re-verify the impact classification."
                    ),
                    "recommendation": "Update the severity_line note or reclassify.",
                })
            else:
                accepted_unchanged_rows.append({
                    "accepted_id": row.id,
                    "scope_asset": row.scope_asset,
                    "invariant_family": row.invariant_family,
                    "statement": row.statement[:200],
                    "status": row.status,
                })

    # 5. Build and write the diff payload (JSON + Markdown)
    payload: Dict[str, Any] = {
        "schema_version": SCOPE_DIFF_SCHEMA,
        "workspace": str(ws),
        "generated_at": _now_iso(),
        "scope_sources_matched": sources_present,
        "summary": {
            "newly_generated_count": len(newly_generated_rows),
            "accepted_unchanged_count": len(accepted_unchanged_rows),
            "accepted_drifted_count": len(accepted_drifted_rows),
            "accepted_orphaned_count": len(accepted_orphaned_rows),
        },
        "newly_generated_rows": newly_generated_rows,
        "accepted_unchanged_rows": accepted_unchanged_rows,
        "accepted_drifted_rows": accepted_drifted_rows,
        "accepted_orphaned_rows": accepted_orphaned_rows,
    }

    out_json = scope_diff_path(ws)
    out_json.parent.mkdir(parents=True, exist_ok=True)
    out_json.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")

    # Markdown summary
    md_lines = [
        "# Invariant Ledger Scope Diff",
        "",
        f"Generated: {payload['generated_at']}  ",
        f"Workspace: `{ws}`  ",
        f"Sources matched: {', '.join(sources_present) or '(none)'}",
        "",
        "## Summary",
        "",
        f"| Bucket | Count |",
        f"|--------|-------|",
        f"| `newly_generated_rows` | {len(newly_generated_rows)} |",
        f"| `accepted_unchanged_rows` | {len(accepted_unchanged_rows)} |",
        f"| `accepted_drifted_rows` | {len(accepted_drifted_rows)} |",
        f"| `accepted_orphaned_rows` | {len(accepted_orphaned_rows)} |",
        "",
    ]

    if newly_generated_rows:
        md_lines += ["## Newly Generated Rows (not yet in ledger)", ""]
        for r in newly_generated_rows[:20]:
            md_lines.append(
                f"- **{r['generated_id']}** `{r['scope_asset']}` — "
                f"{r['statement'][:120]} *(from {r['source_file']})*"
            )
        if len(newly_generated_rows) > 20:
            md_lines.append(f"- … and {len(newly_generated_rows) - 20} more (see JSON)")
        md_lines.append("")

    if accepted_drifted_rows:
        md_lines += ["## Accepted Drifted Rows (severity anchor no longer valid)", ""]
        for r in accepted_drifted_rows:
            md_lines.append(
                f"- **{r['accepted_id']}** `{r['scope_asset']}` — "
                f"{r['drift_reason']}"
            )
        md_lines.append("")

    if accepted_orphaned_rows:
        md_lines += ["## Accepted Orphaned Rows (no longer derivable from scope)", ""]
        for r in accepted_orphaned_rows[:20]:
            md_lines.append(
                f"- **{r['accepted_id']}** `{r['scope_asset']}` — "
                f"{r['statement'][:100]}"
            )
        if len(accepted_orphaned_rows) > 20:
            md_lines.append(f"- … and {len(accepted_orphaned_rows) - 20} more (see JSON)")
        md_lines.append("")

    md_lines += [
        "## Accepted Unchanged Rows",
        "",
        f"_{len(accepted_unchanged_rows)} row(s) present in both scope derivation and accepted ledger._",
        "",
    ]

    out_md = scope_diff_md_path(ws)
    out_md.write_text("\n".join(md_lines), encoding="utf-8")

    print(
        f"[invariant-ledger] diff-accepted: "
        f"newly_generated={len(newly_generated_rows)} "
        f"accepted_unchanged={len(accepted_unchanged_rows)} "
        f"accepted_drifted={len(accepted_drifted_rows)} "
        f"accepted_orphaned={len(accepted_orphaned_rows)}"
    )
    print(f"[invariant-ledger] diff-accepted: wrote {out_json}")
    print(f"[invariant-ledger] diff-accepted: wrote {out_md}")
    return 0


# ---------------------------------------------------------------------------
# --check: schema + artifact-reference validation
# ---------------------------------------------------------------------------

@dataclass
class CheckIssue:
    row_id: str
    severity: str  # "error" | "warn"
    message: str

    def to_dict(self) -> Dict[str, Any]:
        return dataclasses.asdict(self)


def validate_rows(
    rows: List[Row],
    ws: Path,
    *,
    require_high_impact_harness: bool = False,
    raw_rows: Optional[List[Dict[str, Any]]] = None,
) -> List[CheckIssue]:
    """Run all schema + artifact + high-impact checks. Returns list of issues.

    `raw_rows` is the pre-defaulting list of dicts as parsed from JSON.
    When supplied, we use it to distinguish missing-from-source vs
    present-but-defaulted fields, so an operator who omits `owner`
    or `required_engine` entirely from a row gets a hard error rather
    than a silent default. When `raw_rows` is None we fall back to the
    materialised `Row` objects (best-effort; some "missing" cases
    cannot be distinguished from "present and empty default").
    """
    issues: List[CheckIssue] = []
    seen_ids: set = set()
    raw_rows = raw_rows or [None] * len(rows)
    if len(raw_rows) < len(rows):
        # Pad — defensive, should not happen because both come from
        # the same JSON store.
        raw_rows = list(raw_rows) + [None] * (len(rows) - len(raw_rows))
    for r, raw in zip(rows, raw_rows):
        # Per-row required-field enforcement (all 15). For LIST fields
        # we accept an empty list — `source_citations` is enforced
        # non-empty only for High/Critical (separate check below) and
        # `artifacts` is enforced based on status. For SCALAR fields
        # we require the field be present in the raw JSON AND have a
        # non-empty value. When `raw` is None we can only enforce
        # presence-as-non-empty on the materialised Row, which means
        # missing-key-with-default-value silently passes — exactly the
        # silent-zero pattern we are closing.
        for fname in REQUIRED_FIELDS:
            # inv_id is accepted as a legacy alias for id.  A raw row that
            # carries inv_id but not id satisfies the id-presence check so
            # that ledger files produced by older tooling do not flood the
            # error list with spurious "required field missing: id" entries.
            if raw is not None and fname not in raw:
                if fname == "id" and "inv_id" in raw:
                    pass  # alias present; skip the missing-field error
                else:
                    issues.append(CheckIssue(
                        row_id=r.id or "?",
                        severity="error",
                        message=f"required field missing: {fname}",
                    ))
                    continue
            val = getattr(r, fname, None)
            if fname in ("source_citations", "artifacts"):
                # List required-presence: empty list is allowed at this
                # gate — High/Critical citations and status=blocked
                # artifacts are enforced separately below.
                if not isinstance(val, list):
                    issues.append(CheckIssue(
                        row_id=r.id or "?",
                        severity="error",
                        message=f"required field wrong type (list expected): {fname}",
                    ))
                continue
            # Scalar must be a non-empty string. We treat the
            # placeholder defaults `"unknown"` and `""` as missing so
            # an operator who never filled the field is forced to.
            if not isinstance(val, str) or not val.strip():
                issues.append(CheckIssue(
                    row_id=r.id or "?",
                    severity="error",
                    message=f"required field empty: {fname}",
                ))
                continue
            # `unknown` is the default for `required_engine`/`owner`
            # when the operator omits the field. When raw_rows is
            # available the missing-key check above caught that. When
            # raw_rows is None (legacy callers) we still want to flag
            # the placeholder so a stale ledger surfaces.
            if raw is None and fname in ("required_engine", "owner") and val == "unknown":
                issues.append(CheckIssue(
                    row_id=r.id or "?",
                    severity="error",
                    message=f"required field has placeholder default 'unknown': {fname}",
                ))
        # Status enum.
        if r.status not in VALID_STATUS:
            issues.append(CheckIssue(
                row_id=r.id,
                severity="error",
                message=(
                    f"invalid status: {r.status!r}; expected one of "
                    f"{', '.join(VALID_STATUS)}"
                ),
            ))
        # Required-engine: accept known token OR descriptive string
        # whose leading token is a known engine. Pure-descriptive
        # strings (no engine prefix) still WARN.
        if not _required_engine_ok(r.required_engine):
            issues.append(CheckIssue(
                row_id=r.id,
                severity="warn",
                message=(
                    f"unrecognised required_engine: {r.required_engine!r}; "
                    f"expected a known engine token (one of "
                    f"{', '.join(VALID_ENGINES)}) or a descriptive string "
                    f"starting with one (e.g. 'forge + halmos', "
                    f"'live-check (cast call)')"
                ),
            ))
        # ID uniqueness.
        if r.id in seen_ids:
            issues.append(CheckIssue(
                row_id=r.id,
                severity="error",
                message=f"duplicate id: {r.id}",
            ))
        seen_ids.add(r.id)
        # Source citations: required non-empty for High/Critical
        # (explicit-or-inferred).
        sev = _infer_severity(r)
        if sev in HIGH_IMPACT_SEVERITIES and not r.source_citations:
            issues.append(CheckIssue(
                row_id=r.id,
                severity="error",
                message=(
                    f"row severity={sev} (explicit or inferred) but "
                    "source_citations is empty; High/Critical rows must "
                    "cite scope/spec/source"
                ),
            ))
        # Artifact reference check: each parseable path under <ws>/
        # must exist on disk, EXCEPT entries flagged with the
        # `EXPECTED:` sentinel which signal a planned-but-not-yet-
        # written target.
        for art in r.artifacts:
            if not art:
                continue
            path, expected_only = _split_artifact(art)
            if path is None:
                # Free-form note (e.g. `blocker: missing-rpc`) — not a
                # path. Leave it alone.
                continue
            if expected_only:
                # Planned target; do not existence-check.
                continue
            # Only existence-check things that look like paths: contain
            # `/` or end in a known suffix. Free-form descriptive
            # entries (e.g. `auditooor PR #494 (codex/wave3-...)`) that
            # do not look like a path are skipped — operators encode
            # context that does not map to a file on disk.
            if "/" in path or path.endswith(
                (".md", ".json", ".rs", ".sol", ".log", ".jsonl", ".py", ".toml")
            ):
                if not _artifact_path_present(ws, path):
                    issues.append(CheckIssue(
                        row_id=r.id,
                        severity="error",
                        message=f"dangling artifact path: {path}",
                    ))
        # Non-`missing_harness` and non-`blocked` rows MUST have at
        # least one artifact entry. `scaffolded`/`executed_clean`/
        # `counterexample`/`killed` all imply the harness target exists
        # — empty artifacts contradicts the status. `blocked` is
        # special-cased separately because it requires either a path
        # or an explicit `blocker:` note.
        if r.status not in ("missing_harness", "blocked") and not r.artifacts:
            issues.append(CheckIssue(
                row_id=r.id,
                severity="error",
                message=(
                    f"status={r.status} requires at least one artifacts "
                    "entry; status implies a harness target exists"
                ),
            ))
        # `blocked` status should have at least one artifact entry naming
        # the blocker (a path or a `blocker:` note).
        if r.status == "blocked" and not r.artifacts:
            issues.append(CheckIssue(
                row_id=r.id,
                severity="error",
                message=(
                    "status=blocked requires at least one artifacts entry "
                    "naming the blocker (e.g. 'blocker: missing-rpc')"
                ),
            ))
        # High-impact harness gate.
        if require_high_impact_harness and sev in HIGH_IMPACT_SEVERITIES:
            if r.status not in HIGH_IMPACT_OK_STATUS:
                issues.append(CheckIssue(
                    row_id=r.id,
                    severity="error",
                    message=(
                        f"row severity={sev} (explicit or inferred) but "
                        f"status={r.status}; High/Critical rows must be "
                        "scaffolded/executed/blocked"
                    ),
                ))
    return issues


def cmd_check(
    ws: Path,
    *,
    require_high_impact_harness: bool = False,
) -> int:
    j = json_path(ws)
    if not j.is_file():
        print(
            f"[invariant-ledger] check: ledger missing at {j}; "
            "run `--init` first.",
            file=sys.stderr,
        )
        return 2
    try:
        payload, rows = validate_ledger_payload(ws)
    except LedgerError as e:
        # Loud: malformed JSON, empty rows, missing top-level keys,
        # wrong shape. All return rc=1 with a named reason.
        print(f"[invariant-ledger] ERROR: {e}", file=sys.stderr)
        return 1
    raw = _raw_rows_from_payload(payload)
    issues = validate_rows(
        rows, ws,
        require_high_impact_harness=require_high_impact_harness,
        raw_rows=raw,
    )
    errors = [i for i in issues if i.severity == "error"]
    warns = [i for i in issues if i.severity == "warn"]
    for i in issues:
        print(f"[invariant-ledger] {i.severity.upper()} {i.row_id}: {i.message}")
    print(
        f"[invariant-ledger] check: {len(rows)} rows, "
        f"{len(errors)} error(s), {len(warns)} warn(s)"
    )
    if errors:
        return 1
    return 0


# ---------------------------------------------------------------------------
# --require-high-impact-harness: same as --check but exit code differs
# ---------------------------------------------------------------------------

def cmd_require_high_impact_harness(ws: Path) -> int:
    j = json_path(ws)
    if not j.is_file():
        print(
            f"[invariant-ledger] require-high-impact-harness: ledger missing at {j}",
            file=sys.stderr,
        )
        return 2
    try:
        payload, rows = validate_ledger_payload(ws)
    except LedgerError as e:
        print(f"[invariant-ledger] ERROR: {e}", file=sys.stderr)
        return 1
    raw = _raw_rows_from_payload(payload)
    issues = validate_rows(rows, ws, require_high_impact_harness=True, raw_rows=raw)
    high_impact_issues = [
        i for i in issues
        if i.severity == "error" and "severity=" in i.message
    ]
    other_errors = [
        i for i in issues
        if i.severity == "error" and "severity=" not in i.message
    ]
    for i in issues:
        print(f"[invariant-ledger] {i.severity.upper()} {i.row_id}: {i.message}")
    if high_impact_issues:
        print(
            f"[invariant-ledger] FAIL: {len(high_impact_issues)} High/Critical "
            "row(s) lack a runnable harness/replay/blocker."
        )
        return 1
    if other_errors:
        # Hard schema errors are still fail (rc=1).
        return 1
    # No High/Critical gap. Emit WARN exit code only when there was at
    # least one row with a status of `missing_harness` regardless of
    # severity (operator hint that the ledger is incomplete).
    incomplete = [r for r in rows if r.status == "missing_harness"]
    if incomplete:
        print(
            f"[invariant-ledger] WARN: {len(incomplete)} row(s) still in "
            "missing_harness status (no severity hint set; not a blocker)."
        )
        return 2
    return 0


# ---------------------------------------------------------------------------
# --emit-closeout: manifest writer
# ---------------------------------------------------------------------------

def build_closeout_manifest(
    ws: Path,
    rows: List[Row],
    issues: List[CheckIssue],
) -> Dict[str, Any]:
    status_counts: Dict[str, int] = {s: 0 for s in VALID_STATUS}
    for r in rows:
        if r.status in status_counts:
            status_counts[r.status] += 1
        else:
            status_counts.setdefault("unknown", 0)
            status_counts["unknown"] += 1
    # Use *effective* severity (explicit-or-inferred) so the manifest
    # counters agree with the --require-high-impact-harness validation
    # gate. Reading `r.severity` directly silently drops every
    # inferred-High row, producing high_impact_total=0 even when the
    # same manifest's `issues` array reports inferred-High failures
    # (PR #511 follow-up — Required Pre-Merge Fix for #521).
    high_impact_total = sum(
        1 for r in rows
        if _row_effective_severity(r) in HIGH_IMPACT_SEVERITIES
    )
    high_impact_ok = sum(
        1 for r in rows
        if _row_effective_severity(r) in HIGH_IMPACT_SEVERITIES
        and r.status in HIGH_IMPACT_OK_STATUS
    )
    return {
        "schema": "auditooor.invariant_ledger_manifest.v1",
        "ledger_schema": SCHEMA_VERSION,
        "workspace": str(ws),
        "generated": _now_iso(),
        "row_count": len(rows),
        "status_counts": status_counts,
        "high_impact_total": high_impact_total,
        "high_impact_ok": high_impact_ok,
        "high_impact_missing": high_impact_total - high_impact_ok,
        "issues": [i.to_dict() for i in issues],
        "rows": [
            {
                "id": r.id,
                "scope_asset": r.scope_asset,
                "invariant_family": r.invariant_family,
                "status": r.status,
                # Surface effective severity when the explicit field is
                # absent but the heuristics infer High; explicit always
                # wins (see `_infer_severity`).
                "severity": (
                    r.severity
                    if r.severity
                    else (
                        _row_effective_severity(r)
                        if _row_effective_severity(r) in HIGH_IMPACT_SEVERITIES
                        else None
                    )
                ),
                "owner": r.owner,
                "required_engine": r.required_engine,
            }
            for r in rows
        ],
    }


def cmd_emit_closeout(ws: Path) -> int:
    j = json_path(ws)
    if not j.is_file():
        print(
            f"[invariant-ledger] emit-closeout: ledger missing at {j}",
            file=sys.stderr,
        )
        return 2
    try:
        payload, rows = validate_ledger_payload(ws)
    except LedgerError as e:
        print(f"[invariant-ledger] ERROR: {e}", file=sys.stderr)
        return 1
    raw = _raw_rows_from_payload(payload)
    issues = validate_rows(rows, ws, require_high_impact_harness=True, raw_rows=raw)
    payload = build_closeout_manifest(ws, rows, issues)
    out = manifest_path(ws)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
    print(f"[invariant-ledger] closeout manifest: {out}")
    print(f"[invariant-ledger]   rows={payload['row_count']} "
          f"high_impact_ok={payload['high_impact_ok']}/{payload['high_impact_total']}")
    return 0


# ---------------------------------------------------------------------------
# P5: State-Coupling Graph -> invariant ledger + cross-language lift
# ---------------------------------------------------------------------------

def _load_scg_edges(ws: Path) -> List[Dict[str, Any]]:
    """Read PROMOTABLE (semantic-ssa) or probe-confirmed SCG edges. Never syntactic /
    non-promotable - a coupling only enters the durable ledger once it is citable."""
    import importlib.util as _il
    here = Path(__file__).resolve().parent
    spec = _il.spec_from_file_location("state_coupling_schema",
                                       here / "state_coupling_schema.py")
    m = _il.module_from_spec(spec)
    sys.modules["state_coupling_schema"] = m
    spec.loader.exec_module(m)
    _NEG = ("negative", "ruled-out", "ruled_out", "oos", "dupe", "guarded",
            "false-positive", "not-reachable")
    out: List[Dict[str, Any]] = []
    for e in m.read_edges(ws):
        ev = e.get("evidence") or {}
        verdict = str(ev.get("probe_verdict") or "").strip().lower()
        probed_ok = bool(verdict) and not any(n in verdict for n in _NEG)
        if verdict and not probed_ok:
            continue
        citable = (ev.get("promotable") and e.get("confidence") == "semantic-ssa") \
            or probed_ok
        if citable:
            out.append(e)
    return out


def ingest_state_couplings(ws: Path, *, source_ws_name: Optional[str] = None,
                           now: Optional[str] = None) -> int:
    """P5 (LAST box): fold citable SCG couplings into the durable invariant ledger AND
    a cross-language-lift sidecar, so vault_cross_language_pattern_lift can carry a
    coupling learned on ws A to ws B. ADVISORY / opt-in - never auto-run in the
    pipeline; gated to PROMOTABLE semantic-ssa + probe-confirmed edges only. Returns
    the number of NEW ledger rows added (idempotent: existing SCG-* rows are updated,
    not duplicated). Also writes .auditooor/state_coupling_lift.jsonl."""
    ts = now or _now_iso()
    src_name = source_ws_name or ws.name
    edges = _load_scg_edges(ws)
    existing = load_rows(ws)
    by_id = {r.id: r for r in existing}
    lift: List[Dict[str, Any]] = []
    added = 0
    for e in edges:
        rid = f"SCG-{e.get('edge_id')}"
        vio = (e.get("violators") or [{}])[0]
        cite = [str(vio.get("file") or ""), f"state_coupling_edges.jsonl:{e.get('edge_id')}"]
        statement = (
            f"{e.get('kind')} coupling: cells {{{e.get('cell_a')}, {e.get('cell_b')}}} "
            f"must move together; a writer of {e.get('cell_b')} that omits "
            f"{e.get('cell_a')} breaks {e.get('obligation') or 'the coupling'}")
        row = Row(
            id=rid,
            scope_asset=str(vio.get("file") or e.get("language") or "state-coupling"),
            invariant_family="state-coupling-completeness",
            statement=statement[:600],
            source_citations=[c for c in cite if c],
            status="missing_harness",
            owner="scg",
            severity=None,
            notes=(f"kind={e.get('kind')} impact={e.get('impact_class')} "
                   f"lang={e.get('language')} confidence={e.get('confidence')}"),
            created=(by_id[rid].created if rid in by_id and by_id[rid].created else ts),
            updated=ts,
        )
        if rid not in by_id:
            added += 1
        by_id[rid] = row
        lift.append({
            "schema_version": "auditooor.state_coupling_lift.v1",
            "edge_id": e.get("edge_id"), "language": e.get("language"),
            "kind": e.get("kind"), "impact_class": e.get("impact_class"),
            "cell_a": e.get("cell_a"), "cell_b": e.get("cell_b"),
            "statement": statement[:600], "source_ws": src_name,
            "confidence": e.get("confidence"), "recorded": ts,
        })
    save_rows(ws, list(by_id.values()), write_md=False)
    liftp = ws / ".auditooor" / "state_coupling_lift.jsonl"
    liftp.parent.mkdir(parents=True, exist_ok=True)
    liftp.write_text(
        "\n".join(json.dumps(r, sort_keys=True) for r in lift) + ("\n" if lift else ""),
        encoding="utf-8")
    return added


def cmd_ingest_state_couplings(ws: Path) -> int:
    n = ingest_state_couplings(ws)
    print(f"[invariant-ledger] ingested {n} new state-coupling row(s) + "
          f"{ (ws / '.auditooor' / 'state_coupling_lift.jsonl') } lift sidecar")
    return 0


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def _build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="invariant-ledger.py",
        description=(
            "Workspace invariant ledger (PR #511 Slice 2). Bridges scope/spec "
            "understanding to runnable harnesses. See docs/INVARIANT_LEDGER.md."
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Source priority for --from-scope (first hit per category seeds rows):\n"
            "  1. SCOPE.md\n"
            "  2. README.md / README\n"
            "  3. SEVERITY*.md (SEVERITY_SMART_CONTRACTS.md, SEVERITY_BLOCKCHAIN_DLT.md)\n"
            "  4. RUBRIC_COVERAGE.md\n"
            "  5. INTAKE_BASELINE.json (presence-only — not row-seeded)\n"
            "  6. deployment_topology.json (presence-only)\n"
            "  7. live_topology_checks.json (presence-only)\n"
            "  8. submissions/SUBMISSIONS.md (anti-regression rows)\n"
            "  9. Solidity sources (public create/deploy + pool/hook config reuse)\n"
            " 10. detectors/_tier_registry.yaml (P1-7: pool-liveness rows from\n"
            "     registry stateful-gate fields — always scanned, workspace-agnostic)\n"
            " 11. engage_report.json (or .md fallback): one missing_harness row per\n"
            "     unique subsystem / attack-class cluster not already in the ledger\n"
            "\n"
            "Status enum: missing_harness | scaffolded | executed_clean |\n"
            "             counterexample | killed | blocked\n"
            "\n"
            "Required engines: forge, cargo, live-check, differential, halmos,\n"
            "                  medusa, manual, unknown\n"
        ),
    )
    p.add_argument(
        "--workspace", "--ws",
        type=Path, required=True,
        help="Audit workspace root.",
    )
    g = p.add_mutually_exclusive_group(required=True)
    g.add_argument(
        "--init", action="store_true",
        help="Create empty INVARIANT_LEDGER.md + .auditooor/invariant_ledger.json "
             "scaffold. Idempotent: existing rows are kept.",
    )
    g.add_argument(
        "--from-scope", action="store_true",
        help="Seed candidate invariant rows from SCOPE.md, README, SEVERITY*.md, "
             "RUBRIC_COVERAGE.md, INTAKE_BASELINE.json, deployment_topology.json, "
             "live_topology_checks.json, submissions/SUBMISSIONS.md, bounded "
             "Solidity factory/pool liveness heuristics, "
             "detectors/_tier_registry.yaml stateful-gate rows (P1-7), and "
             "engage_report.json (one missing_harness row per unique subsystem / "
             "attack-class cluster). Use --dry-run to preview without writing; "
             "--json to emit a machine-readable diff block.",
    )
    g.add_argument(
        "--diff-accepted", action="store_true",
        help="Compare freshly-derived scope invariants against the operator-accepted "
             "ledger. Emits a 4-bucket report to "
             ".auditooor/invariant_ledger_scope_diff.{json,md}: "
             "newly_generated_rows / accepted_unchanged_rows / "
             "accepted_drifted_rows / accepted_orphaned_rows. "
             "Requires an existing --from-scope ledger. Read-only: does NOT mutate "
             "the ledger.",
    )
    g.add_argument(
        "--check", action="store_true",
        help="Validate schema (15 fields, status enum, source_citations non-empty "
             "for High/Critical, artifact paths exist). Exit 1 on errors.",
    )
    g.add_argument(
        "--ingest-state-couplings", action="store_true",
        help="ADVISORY / opt-in (P5): fold citable State-Coupling Graph edges "
             "(.auditooor/state_coupling_edges.jsonl, PROMOTABLE semantic-ssa + "
             "probe-confirmed only) into the ledger as state-coupling-completeness "
             "rows + write .auditooor/state_coupling_lift.jsonl for "
             "vault_cross_language_pattern_lift. Idempotent; never syntactic.",
    )
    g.add_argument(
        "--require-high-impact-harness", action="store_true",
        help="Run --check with the High/Critical harness gate enabled. "
             "Exit 1 when any High/Critical row has no harness/replay/blocker; "
             "Exit 2 (WARN) when any row is still in missing_harness status.",
    )
    g.add_argument(
        "--emit-closeout", action="store_true",
        help="Write <ws>/.audit_logs/invariant_ledger_manifest.json with status "
             "counts + per-row summary (consumed by tools/audit-closeout-check.py).",
    )
    # Optional modifiers for --from-scope (usable alongside it, not exclusive).
    p.add_argument(
        "--dry-run", action="store_true", default=False,
        help="(--from-scope modifier) Print candidate rows and the "
             "generated-vs-accepted diff block without writing anything to disk. "
             "Combines with --json.",
    )
    p.add_argument(
        "--json", action="store_true", default=False,
        help="(--from-scope modifier) Also print a JSON summary of the "
             "generated-vs-accepted diff and the candidate row list to stdout. "
             "Combines with --dry-run.",
    )
    return p


def main(argv: Optional[List[str]] = None) -> int:
    args = _build_parser().parse_args(argv)
    ws = args.workspace.expanduser()
    # --init may be called on a not-yet-existing directory — create it.
    if args.init:
        return cmd_init(ws)
    if not ws.exists():
        print(f"[invariant-ledger] error: workspace not found: {ws}", file=sys.stderr)
        return 2
    if args.from_scope:
        return cmd_from_scope(
            ws,
            dry_run=args.dry_run,
            print_json=args.json,
        )
    if args.diff_accepted:
        return cmd_diff_accepted(ws)
    if args.ingest_state_couplings:
        return cmd_ingest_state_couplings(ws)
    if args.check:
        return cmd_check(ws)
    if args.require_high_impact_harness:
        return cmd_require_high_impact_harness(ws)
    if args.emit_closeout:
        return cmd_emit_closeout(ws)
    return 2  # unreachable: argparse guards


if __name__ == "__main__":
    sys.exit(main())
