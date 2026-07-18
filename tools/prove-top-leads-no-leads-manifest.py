#!/usr/bin/env python3
"""prove-top-leads-no-leads-manifest.py

Real producer for the ``prove_top_leads_no_leads.json`` manifest (schema
``auditooor.prove_top_leads_no_leads.v1``) consumed by
``tools/audit-completeness-check.py`` (``check_prove_top_leads`` /
``check_evm_0day_proof``) and ``tools/audit-closeout-check.py``.

Why this tool exists
--------------------
The completeness gate accepts a structured no-leads manifest as the honest-0 path
for ``prove-top-leads`` (a large corpus-driven-hunt queue where every eligible TOP
lead is already terminal/adjudicated and nothing is submit-ready). Until now NO
tool WROTE that manifest - only validators read it - so the only way to green the
gate was to hand-author the JSON, which the audit doctrine forbids (a hand-written
gate marker is the #1 sin). This closes the gap: the manifest is now TOOL-PRODUCED
and grounded in the live queue + the UN-FAKEABLE prefiling-stress corroboration.

Anti-fabrication guarantee
--------------------------
This producer CANNOT manufacture a passing manifest. It refuses to emit unless one
of the same two conditions the validator enforces holds:

  (a) EMPTY queue  - every queue in ``PROVE_TOP_LEADS_QUEUE_RELS`` has 0 rows, OR
  (b) ALL-TERMINAL - the prefiling-stress producer
      (``tools/prefiling-stress-test.py``, run by ``make prove-top-leads``)
      independently reported a real ``top_n>0`` window, ``rows_assessed==0`` and
      ``terminal_rows_skipped > 0`` in
      ``.auditooor/prove_top_leads_prefiling_stress_test.json``.

The prefiling artifact is recomputed from the LIVE queue on every audit-deep /
prove-top-leads run; this producer only TRANSCRIBES its verdict into the manifest
with the live counts. If the prefiling corroboration is absent, this tool exits
non-zero and writes NOTHING - it can never green the gate on its own.

The emitted manifest declares ``current_queue_rows`` read from the live queue at
emit time, so the validator's freshness check (declared==live) passes only while
the queue is unchanged; a later queue mutation invalidates the manifest, exactly
as intended.

Usage
-----
    python3 tools/prove-top-leads-no-leads-manifest.py --workspace <ws> \
        [--rationale "<one line grounding the honest-0>"] [--json]

Stdlib-only, read-only over the workspace except the single manifest it writes.
"""
from __future__ import annotations

import argparse
import importlib.util
import json
import sys
from pathlib import Path
from typing import Any


SCHEMA = "auditooor.prove_top_leads_no_leads.v1"

# Kept identical to audit-completeness-check.py: PROVE_TOP_LEADS_QUEUE_RELS +
# PROVE_TOP_LEADS_NO_LEADS_PATTERNS. The validator recomputes live counts from
# these exact rels, so the producer must use the same set.
QUEUE_RELS = (
    ".auditooor/exploit_queue.json",
    ".auditooor/exploit_queue.source_mined.json",
    ".auditooor/exploit_queue.zero_day_admitted.json",
)
MANIFEST_REL = ".auditooor/prove_top_leads_no_leads.json"
PREFILING_REL = ".auditooor/prove_top_leads_prefiling_stress_test.json"
TYPED_ADMITTED_REL = ".auditooor/exploit_queue.zero_day_admitted.json"
_TYPED_ENVELOPE_TOOL = Path(__file__).with_name("zero-day-proof-envelope-verify.py")
_TYPED_ENVELOPE_MOD: Any | None = None

_TERMINAL_PROOF_STATUSES = {
    "proved", "confirmed", "filed", "promoted_to_poc", "promoted_to_chain",
    "poc_pass", "killed", "refuted", "disqualified", "disproved",
    "closed_negative", "false_positive", "not_exploitable", "drop", "dropped",
}
_TERMINAL_QUALITY_STATUSES = {
    "filed", "promoted", "disqualified", "closed_negative_source_proof",
    "closed_negative", "blocked_r76_hallucinated_source_claim",
}


def _load_typed_envelope_tool() -> Any:
    """Load the canonical admitted-proof identity verifier once."""
    global _TYPED_ENVELOPE_MOD
    if _TYPED_ENVELOPE_MOD is not None:
        return _TYPED_ENVELOPE_MOD
    spec = importlib.util.spec_from_file_location(
        "prove_top_leads_no_leads_typed_envelope", _TYPED_ENVELOPE_TOOL,
    )
    if spec is None or spec.loader is None:
        raise ValueError("typed_proof_envelope_tool_unavailable")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    _TYPED_ENVELOPE_MOD = module
    return module


def _load_json(path: Path) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8", errors="replace"))
    except (OSError, ValueError):
        return None


def _queue_row_count(obj: Any) -> int:
    if isinstance(obj, list):
        return len(obj)
    if not isinstance(obj, dict):
        return 0
    for key in ("queue", "items", "candidates", "rows", "leads"):
        value = obj.get(key)
        if isinstance(value, list):
            return len(value)
    return 0


def _live_queue_counts(ws: Path) -> dict[str, int]:
    counts: dict[str, int] = {}
    for rel in QUEUE_RELS:
        path = ws / rel
        counts[rel] = _queue_row_count(_load_json(path)) if path.is_file() else 0
    return counts


def _row_has_terminal_status(row: dict[str, Any]) -> bool:
    proof_status = str(row.get("proof_status") or "").strip().lower()
    quality_status = str(row.get("quality_gate_status") or "").strip().lower()
    return (
        proof_status in _TERMINAL_PROOF_STATUSES
        or quality_status in _TERMINAL_QUALITY_STATUSES
    )


def _typed_admitted_terminal_state(ws: Path) -> tuple[bool, bool, int, str]:
    """Return whether a typed queue is present and all its rows close exactly.

    A canonical admitted queue is not a legacy discovery queue. Its terminal
    rows must preserve the immutable envelope parent and source-cited record;
    a prefiling count can corroborate that result but cannot replace it.
    """
    path = ws / TYPED_ADMITTED_REL
    if not path.is_file():
        return False, True, 0, ""
    payload = _load_json(path)
    if not isinstance(payload, dict) or "zero_day_proof_admission" not in payload:
        return True, False, 0, "typed_proof_queue_missing_admission"
    if payload.get("entries") not in (None, []):
        return True, False, 0, "typed_proof_envelope_legacy_entries_present"
    rows = payload.get("queue")
    if not isinstance(rows, list) or any(not isinstance(row, dict) for row in rows):
        return True, False, 0, "typed_proof_queue_rows_invalid"
    try:
        verifier = _load_typed_envelope_tool()
        verifier.verify_persisted(ws, path)
        envelope = verifier.build_envelope(payload)
    except Exception as exc:
        return True, False, len(rows), f"typed_proof_envelope_invalid:{exc}"
    entries = {
        entry.get("lead_id"): entry
        for entry in envelope.get("entries", [])
        if isinstance(entry, dict) and isinstance(entry.get("lead_id"), str)
    }
    if len(entries) != len(rows):
        return True, False, len(rows), "typed_proof_envelope_row_set_invalid"
    for row in rows:
        lead_id = row.get("lead_id")
        entry = entries.get(lead_id) if isinstance(lead_id, str) else None
        if entry is None:
            return True, False, len(rows), "typed_proof_envelope_row_missing"
        if not _row_has_terminal_status(row):
            return True, False, len(rows), f"typed_terminal_status_missing:{lead_id}"
        if not _load_typed_envelope_tool().terminal_record_matches(entry, row):
            return True, False, len(rows), f"typed_terminal_record_missing_or_mismatched:{lead_id}"
    return True, True, len(rows), ""


def _prefiling_confirms_all_terminal(ws: Path) -> tuple[bool, dict[str, int]]:
    """Mirror of audit-completeness-check._prefiling_confirms_all_terminal: a
    NON-EMPTY assessment window (top_n > 0) assessed 0 NON-TERMINAL top leads
    (rows_assessed==0) while >=1 queue row was skipped as already-terminal.
    (`top_n` is the WINDOW size, not the non-terminal count; demanding top_n>0
    accepts the strong --top-n 10 evidence and rejects the --top-n 0 empty-window
    loophole that yields rows_assessed==0 even with non-terminal leads present.)"""
    obj = _load_json(ws / PREFILING_REL)
    if not isinstance(obj, dict):
        return False, {}
    try:
        top_n = int(obj.get("top_n") or 0)
        rows_assessed = int(obj.get("rows_assessed") or 0)
        terminal_skipped = int(obj.get("terminal_rows_skipped") or 0)
    except (TypeError, ValueError):
        return False, {}
    ok = top_n > 0 and rows_assessed == 0 and terminal_skipped > 0
    return ok, {
        "top_n": top_n,
        "rows_assessed": rows_assessed,
        "terminal_rows_skipped": terminal_skipped,
    }


def build_manifest(ws: Path, rationale: str) -> tuple[dict[str, Any] | None, str]:
    """Return (manifest, ""); or (None, refusal_reason) when neither honest-0
    condition holds. NEVER emit a manifest that would fail the validator."""
    counts = _live_queue_counts(ws)
    empty_queue = all(c == 0 for c in counts.values())
    prefiling_ok, prefiling = _prefiling_confirms_all_terminal(ws)
    typed_present, typed_all_terminal, typed_count, typed_error = _typed_admitted_terminal_state(ws)

    if typed_present and not typed_all_terminal:
        return None, (
            "REFUSE: admitted typed proof queue cannot close through prefiling alone "
            f"({typed_error}). Every typed row needs a terminal status and an exact, "
            "source-cited terminal record bound to its immutable envelope."
        )

    if not empty_queue and not prefiling_ok:
        return None, (
            "REFUSE: queue is non-empty ("
            + ", ".join(f"{k}={v}" for k, v in counts.items())
            + ") and the prefiling-stress producer does NOT confirm all-terminal "
            f"(need top_n>0 (real window), rows_assessed==0, terminal_rows_skipped>0; got {prefiling}). "
            "Run `make prove-top-leads WS=<ws> TOP_N=10` first, or drive the open top "
            "leads to a terminal verdict. This producer will not fabricate a no-leads "
            "manifest."
        )

    manifest: dict[str, Any] = {
        "schema": SCHEMA,
        "no_leads": True,
        "no_provable_leads": True,
        "lead_count": 0,
        "current_queue_rows": counts,
        "produced_by": "tools/prove-top-leads-no-leads-manifest.py",
        "rationale": rationale,
    }
    if not empty_queue:
        # Non-empty processed queue: the load-bearing claim is corroborated by the
        # prefiling producer (un-fakeable; recomputed from the live queue).
        manifest["all_top_leads_terminal"] = True
        manifest["prefiling_corroboration"] = prefiling
    if typed_present:
        manifest["typed_terminal_binding"] = {
            "queue": TYPED_ADMITTED_REL,
            "entry_count": typed_count,
            "all_entries_exact_terminal": True,
        }
    return manifest, ""


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Emit a grounded prove_top_leads_no_leads.json (honest-0 manifest)."
    )
    parser.add_argument("--workspace", required=True, type=Path)
    parser.add_argument(
        "--rationale",
        default="",
        help="One-line grounding for the honest-0 (cite the one confirmed lead / "
        "paste-ready finding, if any).",
    )
    parser.add_argument("--out", type=Path, default=None,
                        help=f"Default <ws>/{MANIFEST_REL}")
    parser.add_argument("--json", action="store_true",
                        help="Print the emitted manifest (or refusal) as JSON.")
    args = parser.parse_args(argv)

    ws = args.workspace.expanduser().resolve()
    if not ws.is_dir():
        print(f"[no-leads-manifest] ERR workspace not found: {ws}", file=sys.stderr)
        return 2

    rationale = args.rationale.strip() or (
        "Genuine no-provable-leads honest-0: the corpus-driven-hunt exploit queue is "
        "fully PROCESSED - the prefiling-stress producer found 0 non-terminal top "
        "leads in a real window (top_n>0, rows_assessed=0) with terminal rows skipped, and no NEW "
        "provable lead remains to PoC-convert beyond the already-filed/paste-ready set."
    )

    manifest, refusal = build_manifest(ws, rationale)
    if manifest is None:
        print(refusal, file=sys.stderr)
        if args.json:
            print(json.dumps({"emitted": False, "reason": refusal}, indent=2))
        return 1

    out = args.out.expanduser().resolve() if args.out else (ws / MANIFEST_REL)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(manifest, indent=2, sort_keys=False) + "\n", encoding="utf-8")
    if args.json:
        print(json.dumps({"emitted": True, "path": str(out), "manifest": manifest}, indent=2))
    else:
        print(f"[no-leads-manifest] wrote {out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
