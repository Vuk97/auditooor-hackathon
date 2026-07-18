#!/usr/bin/env python3
"""verification-receipt-check.py - VERIFICATION RECEIPT VALIDATOR for converted
load-bearing gates (impact / scope / severity / dedup / reachability / guard /
permanence).

WHY THIS EXISTS (the operator's core thesis)
--------------------------------------------
Most audit gates check for the PRESENCE of prose - a claimed impact, a required
section, a "<rule>-rebuttal: <reason>" marker - NOT the TRUTH of it. An agent's
path of least resistance is therefore to WRITE THE WORDS that green the gate
(assert an impact, paste a section, add a rebuttal marker) instead of DOING the
verification the gate is a proxy for. Observed failure (predmkt driver): the
impact was "greened" by asserting "clears $1000 comfortably" - pure prose, no
asset-identity / price / market-size computation, citing a sweep artifact that
did not exist. A gate satisfied by prose would have accepted that too.

THE FIX this tool enforces
--------------------------
For a CONVERTED load-bearing gate, a claim is no longer greened by the author's
own words. It is greened only by an INDEPENDENT-VERIFICATION RECEIPT: an artifact
emitted by a DISTINCT verifier session that was handed the exact claim + the exact
files/artifacts + context, and that returns a non-forgeable adjudication
(CONFIRMED / REFUTED + cited evidence). This tool validates that receipt:

  (a) FIND       - locate the receipt id the draft references for the gate.
  (b) SCHEMA     - the receipt carries all required fields and is self-consistent
                   (claim_hash == sha256(claim); task_hash == canonical(gate,claim_hash)).
  (c) INDEPENDENCE - receipt.verifier_lane != receipt.author_lane, and the verifier
                   lane is a REAL dispatched lane found in the dispatch log
                   (.auditooor/spawn_worker_log.jsonl or a workspace dispatch log).
  (d) ANTI-FORGERY - the receipt's task_hash BINDS to an emitted verification task:
                   there must be a dispatch-log entry for verifier_lane whose
                   task_hash / verification_task_hash / prompt_sha256 equals
                   receipt.task_hash. A hand-written receipt with no matching
                   dispatch-log entry is REJECTED (the author does not write the
                   dispatch log; the dispatch harness does).
  (e) RIGHT CLAIM - the receipt's claim is the SAME claim the draft currently
                   asserts (receipt.claim_hash == sha256(draft claim)), so a stale
                   receipt minted for a different/earlier claim cannot be reused.
  (f) VERDICT    - receipt.verdict == CONFIRMED.

If only a prose sentence or a "<gate>-rebuttal:" marker is present with no valid
receipt, the gate does NOT green (that is exactly the gaming path we are closing).

ADVISORY-FIRST + NEVER-RETRO-RED
--------------------------------
Default verdict is WARN (warn-verification-missing-receipt); it HARD-FAILS
(fail-verification-missing-receipt) only under the tool's OWN named strict env
AUDITOOOR_VERIFICATION_DISPATCH_STRICT (or the umbrella AUDITOOOR_L37_STRICT).
Byte-compatible by default: nothing that passed before turns red unless the
operator opts in to strict. A per-gate honest walk-back is possible with a
"verification-receipt-rebuttal: <reason>" marker in the draft (operator-acked).

LIMITATIONS - what this receipt does NOT prove (read this, do not overclaim)
---------------------------------------------------------------------------
The anti-forgery guarantee here is NOT cryptographic. In a single-OS-user sandbox
the same user is both author and (potentially) verifier and OWNS every file this
tool reads, so a DETERMINED SELF-FORGER is not stopped by this check alone:

  - the task-hash is deterministic from public inputs (gate, claim) - anyone can
    recompute it; secrecy is not the barrier (see task_hash() docstring);
  - the dispatch log (.auditooor/spawn_worker_log.jsonl / verification_dispatch_log.jsonl)
    is a plain file the author can append to, and a session token can be minted
    locally via auditooor_mcp_token.py. An author who WANTS to forge a receipt can
    write a matching dispatch entry and a two-lane receipt by hand.

What the receipt DOES buy is a RAISED BAR, not a proof of independence:
  - it kills the lazy path - a bare prose rebuttal or a self-certified
    "<gate>-rebuttal: <reason>" no longer greens a converted gate;
  - it catches the three obvious forgeries mechanically: (1) author_lane ==
    verifier_lane (self-authored), (2) a receipt with no matching dispatch entry
    (forged-no-dispatch), (3) a fabricated / stale task-hash (task-hash-mismatch,
    stale-receipt-for-other-claim).
  - it forces the forger to CONSTRUCT a consistent multi-file lie instead of
    typing one sentence, which is exactly the friction that makes lazy gaming fail.

The TRUE independence guarantee is ORCHESTRATION-LEVEL, not enforced by this file:
it holds only when the operator / main audit loop actually dispatches a DISTINCT
verifier session (a real spawn-worker verify lane) that writes the dispatch log and
returns the receipt. This tool validates the SHAPE of that hand-off; it cannot, on
its own, prove a distinct mind did the work. Treat a passing receipt as "the lazy
and the obvious-forgery paths are closed", not as "independence is cryptographically
guaranteed".

Usage
-----
  # validate a single converted gate against a draft
  python3 tools/verification-receipt-check.py --workspace <ws> --draft <finding.md> --gate impact

  # auto-scan: evaluate every load-bearing gate that the draft puts in play
  python3 tools/verification-receipt-check.py --workspace <ws> --draft <finding.md>

  # emitter helper: print the canonical claim_hash + task_hash for a claim
  python3 tools/verification-receipt-check.py --gate impact --claim "..." --print-descriptor

Schema: auditooor.verification_receipt_check.v1
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
from pathlib import Path

SCHEMA = "auditooor.verification_receipt_check.v1"
RECEIPT_SCHEMA_PREFIX = "auditooor.verification_receipt"
TASK_DOMAIN = "auditooor.verification_task.v1"

# Load-bearing gates that a converted gate id may name. This tool does NOT decide
# which gates are load-bearing FOR A GIVEN FINDING (that is the impact/scope
# gate's job) - it only validates the receipt once a converted gate is in play.
LOAD_BEARING_GATES = (
    "impact", "scope", "severity", "dedup", "reachability", "guard", "permanence",
)

REQUIRED_RECEIPT_FIELDS = (
    "gate_id", "claim", "claim_hash", "task_hash",
    "author_lane", "verifier_lane", "verdict", "evidence",
)

# dispatch-log fields that may carry the task-binding hash
_TASK_HASH_KEYS = ("task_hash", "verification_task_hash", "prompt_sha256")
# dispatch-log fields that may carry the lane identity
_LANE_KEYS = ("lane_id", "lane", "verifier_lane", "worker_lane")

REBUTTAL_MARKER = "verification-receipt-rebuttal"

# passing status
STATUS_OK = "ok"


# ---------------------------------------------------------------------------
# hashing / normalization primitives (the emitter MUST use the same functions)
# ---------------------------------------------------------------------------

def _sha256(s: str) -> str:
    return hashlib.sha256(s.encode("utf-8")).hexdigest()


def _norm_claim(claim: str) -> str:
    """Canonical claim normalization: strip, collapse internal whitespace."""
    return re.sub(r"\s+", " ", (claim or "").strip())


def claim_hash(claim: str) -> str:
    return _sha256(_norm_claim(claim))


def task_hash(gate: str, claim_h: str) -> str:
    """Canonical binding hash: ties a verification task to (gate, claim). The
    emitter computes exactly this and records it in the dispatch log; the verifier
    echoes it into the receipt. Deterministic + reproducible from public inputs,
    so the ANTI-FORGERY guarantee is NOT that the hash is secret - it is that the
    matching dispatch-log entry can only be produced by a real dispatch."""
    return _sha256(f"{TASK_DOMAIN}\x1f{(gate or '').strip().lower()}\x1f{claim_h}")


# ---------------------------------------------------------------------------
# env / strictness
# ---------------------------------------------------------------------------

def _env_truthy(name: str) -> bool:
    return os.environ.get(name, "").strip().lower() not in ("", "0", "false", "no")


def _strict() -> bool:
    return _env_truthy("AUDITOOOR_VERIFICATION_DISPATCH_STRICT") or _env_truthy("AUDITOOOR_L37_STRICT")


# ---------------------------------------------------------------------------
# dispatch-log loading (the authority the author does not write)
# ---------------------------------------------------------------------------

def _repo_root() -> Path:
    return Path(__file__).resolve().parent.parent


def default_dispatch_logs(ws: Path) -> list[Path]:
    ws = ws.expanduser().resolve()
    return [
        _repo_root() / ".auditooor" / "spawn_worker_log.jsonl",
        ws / ".auditooor" / "spawn_worker_log.jsonl",
        ws / ".auditooor" / "verification_dispatch_log.jsonl",
    ]


def load_dispatch_entries(paths: list[Path]) -> list[dict]:
    entries: list[dict] = []
    for p in paths:
        try:
            if not p.is_file():
                continue
            with p.open("r", encoding="utf-8", errors="replace") as fh:
                for line in fh:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        obj = json.loads(line)
                    except ValueError:
                        continue
                    if isinstance(obj, dict):
                        entries.append(obj)
        except OSError:
            continue
    return entries


def _entry_lane(entry: dict) -> str:
    for k in _LANE_KEYS:
        v = entry.get(k)
        if isinstance(v, str) and v.strip():
            return v.strip()
    return ""


def _entry_task_hashes(entry: dict) -> set[str]:
    out: set[str] = set()
    for k in _TASK_HASH_KEYS:
        v = entry.get(k)
        if isinstance(v, str) and v.strip():
            out.add(v.strip())
    return out


def dispatch_binds(entries: list[dict], verifier_lane: str, want_task_hash: str,
                   ws: Path) -> bool:
    """True iff SOME dispatch-log entry proves the verification task was really
    emitted for THIS verifier lane and THIS task hash. If an entry records a
    `workspace`, it must match ws (scoping); absent workspace field = not
    disqualifying (older schema)."""
    ws_res = str(ws.expanduser().resolve())
    for e in entries:
        if _entry_lane(e) != verifier_lane:
            continue
        if want_task_hash not in _entry_task_hashes(e):
            continue
        wsf = e.get("workspace")
        if isinstance(wsf, str) and wsf.strip():
            try:
                if str(Path(wsf).expanduser().resolve()) != ws_res:
                    continue
            except (OSError, ValueError):
                # unresolvable path - fall back to raw compare
                if wsf.strip() != ws_res:
                    continue
        return True
    return False


# ---------------------------------------------------------------------------
# draft parsing
# ---------------------------------------------------------------------------

def _marker_value(text: str, marker: str, gate: str) -> str | None:
    """Find `marker: <gate>=<value>` (optionally inside an HTML comment). Returns
    the value string, or None if absent."""
    # e.g. verification-receipt: impact=rcpt_ab12   /   verification-claim: impact=...
    pat = re.compile(
        r"%s\s*:\s*%s\s*=\s*(.+?)\s*(?:-->|$)" % (re.escape(marker), re.escape(gate)),
        re.IGNORECASE | re.MULTILINE,
    )
    m = pat.search(text)
    if m:
        return m.group(1).strip().strip("`\"'")
    return None


def _has_gate_rebuttal_marker(text: str, gate: str) -> bool:
    # a self-certified prose override, e.g. `impact-rebuttal: clears $1000`
    return re.search(r"\b%s-rebuttal\s*:" % re.escape(gate), text, re.IGNORECASE) is not None


def _has_receipt_rebuttal(text: str) -> bool:
    return re.search(r"\b%s\s*:" % re.escape(REBUTTAL_MARKER), text, re.IGNORECASE) is not None


def gate_in_play(text: str, gate: str) -> bool:
    """A gate is in play (its receipt is expected) when the draft references it via
    a receipt marker, a verification-claim marker, or a self-certified
    <gate>-rebuttal marker."""
    if _marker_value(text, "verification-receipt", gate) is not None:
        return True
    if _marker_value(text, "verification-claim", gate) is not None:
        return True
    if _has_gate_rebuttal_marker(text, gate):
        return True
    return False


# ---------------------------------------------------------------------------
# receipt discovery + loading
# ---------------------------------------------------------------------------

def _receipt_search_dirs(ws: Path, draft_path: Path | None,
                         extra: list[Path] | None) -> list[Path]:
    ws = ws.expanduser().resolve()
    dirs: list[Path] = []
    if extra:
        dirs.extend(Path(d).expanduser() for d in extra)
    dirs.append(ws / ".auditooor" / "verification_receipts")
    dirs.append(ws / "verification_receipts")
    if draft_path is not None:
        dp = draft_path.expanduser().resolve()
        dirs.append(dp.parent / "verification_receipts")
        dirs.append(dp.parent)
    # de-dup preserving order
    seen: set[str] = set()
    out: list[Path] = []
    for d in dirs:
        key = str(d)
        if key not in seen:
            seen.add(key)
            out.append(d)
    return out


def find_receipt_file(receipt_id: str, dirs: list[Path]) -> Path | None:
    names = [receipt_id]
    if not receipt_id.endswith(".json"):
        names.append(receipt_id + ".json")
    for d in dirs:
        for name in names:
            cand = d / name
            if cand.is_file():
                return cand
    return None


def _load_json(p: Path):
    try:
        return json.loads(p.read_text(encoding="utf-8", errors="replace"))
    except (OSError, ValueError):
        return None


# ---------------------------------------------------------------------------
# per-gate evaluation
# ---------------------------------------------------------------------------

def evaluate_gate(text: str, ws: Path, gate: str, *,
                  draft_path: Path | None,
                  claim_override: str | None,
                  receipts_dirs: list[Path],
                  dispatch_entries: list[dict]) -> dict:
    gate = gate.strip().lower()
    row: dict = {"gate": gate, "status": None, "detail": ""}

    if _has_receipt_rebuttal(text):
        row["status"] = "rebutted"
        row["detail"] = "verification-receipt-rebuttal present (operator-acked walk-back)"
        return row

    # --- what claim does the draft currently assert for this gate?
    draft_claim = claim_override if claim_override is not None else \
        _marker_value(text, "verification-claim", gate)

    # --- receipt reference
    receipt_id = _marker_value(text, "verification-receipt", gate)
    if not receipt_id:
        row["status"] = "receipt-missing"
        why = []
        if _has_gate_rebuttal_marker(text, gate):
            why.append("only a self-certified %s-rebuttal prose marker is present" % gate)
        if draft_claim:
            why.append("a claim is asserted but no independent-verification receipt is referenced")
        if not why:
            why.append("no `verification-receipt: %s=<id>` marker in the draft" % gate)
        row["detail"] = ("load-bearing gate '%s' requires an independent-verification "
                         "receipt; %s" % (gate, "; ".join(why)))
        return row

    row["receipt_id"] = receipt_id
    rf = find_receipt_file(receipt_id, receipts_dirs)
    if rf is None:
        row["status"] = "receipt-file-missing"
        row["detail"] = ("receipt id '%s' referenced but no matching file found under %s"
                         % (receipt_id, ", ".join(str(d) for d in receipts_dirs)))
        return row
    row["receipt_file"] = str(rf)

    obj = _load_json(rf)
    if not isinstance(obj, dict):
        row["status"] = "schema-invalid"
        row["detail"] = "receipt is not a JSON object"
        return row

    # --- schema completeness
    missing = [f for f in REQUIRED_RECEIPT_FIELDS
               if (obj.get(f) is None) or (isinstance(obj.get(f), str) and not obj.get(f).strip())
               or (f == "evidence" and not obj.get(f))]
    schema_val = str(obj.get("schema") or "")
    if not schema_val.startswith(RECEIPT_SCHEMA_PREFIX):
        row["status"] = "schema-invalid"
        row["detail"] = ("receipt schema '%s' is not a %s* receipt" % (schema_val, RECEIPT_SCHEMA_PREFIX))
        return row
    if missing:
        row["status"] = "schema-invalid"
        row["detail"] = "receipt missing required field(s): %s" % ", ".join(missing)
        return row

    r_gate = str(obj["gate_id"]).strip().lower()
    r_claim = str(obj["claim"])
    r_claim_hash = str(obj["claim_hash"]).strip()
    r_task_hash = str(obj["task_hash"]).strip()
    r_author = str(obj["author_lane"]).strip()
    r_verifier = str(obj["verifier_lane"]).strip()
    r_verdict = str(obj["verdict"]).strip().upper()
    row.update({
        "author_lane": r_author, "verifier_lane": r_verifier,
        "receipt_claim_hash": r_claim_hash, "receipt_task_hash": r_task_hash,
        "verdict": r_verdict,
    })

    # --- receipt internal consistency (self-authored fields cannot lie about
    #     their own hashes without being caught)
    if r_gate != gate:
        row["status"] = "gate-mismatch"
        row["detail"] = "receipt gate_id '%s' != requested gate '%s'" % (r_gate, gate)
        return row
    if claim_hash(r_claim) != r_claim_hash:
        row["status"] = "schema-invalid"
        row["detail"] = "receipt claim_hash does not match sha256(claim) (tampered/malformed receipt)"
        return row

    # --- INDEPENDENCE: author lane must differ from verifier lane
    if not r_author or not r_verifier or r_author == r_verifier:
        row["status"] = "self-authored-receipt"
        row["detail"] = ("verifier_lane '%s' == author_lane '%s': a self-authored receipt is "
                         "not an independent verification" % (r_verifier, r_author))
        return row

    # --- VERDICT must be CONFIRMED
    if r_verdict != "CONFIRMED":
        row["status"] = "verdict-not-confirmed"
        row["detail"] = "receipt verdict is '%s' (need CONFIRMED)" % r_verdict
        return row

    # --- RIGHT CLAIM: the receipt must be about the claim the draft asserts NOW
    if draft_claim is not None:
        d_hash = claim_hash(draft_claim)
        row["draft_claim_hash"] = d_hash
        if d_hash != r_claim_hash:
            row["status"] = "stale-receipt-for-other-claim"
            row["detail"] = ("receipt was minted for a different claim (claim_hash %s) than the "
                             "draft now asserts (claim_hash %s); a stale receipt cannot be reused"
                             % (r_claim_hash[:12], d_hash[:12]))
            return row
    else:
        row["draft_claim_source"] = "receipt"  # no independent draft claim to cross-check

    # --- TASK-HASH binding: receipt.task_hash must be the canonical hash of
    #     (gate, claim). A fudged token is caught here.
    expected = task_hash(gate, r_claim_hash)
    row["expected_task_hash"] = expected
    if r_task_hash != expected:
        row["status"] = "task-hash-mismatch"
        row["detail"] = ("receipt task_hash %s != canonical task_hash %s for (gate=%s, claim); the "
                         "receipt is not bound to this gate+claim" % (r_task_hash[:12], expected[:12], gate))
        return row

    # --- ANTI-FORGERY: the task must actually have been dispatched to the verifier
    if not dispatch_binds(dispatch_entries, r_verifier, r_task_hash, ws):
        row["status"] = "forged-no-dispatch"
        row["detail"] = ("no dispatch-log entry binds verifier_lane '%s' to task_hash %s; a "
                         "hand-written receipt with no matching dispatch is rejected"
                         % (r_verifier, r_task_hash[:12]))
        return row

    row["status"] = STATUS_OK
    row["detail"] = ("independent-verification receipt CONFIRMED by lane '%s' (author '%s'), "
                     "task-hash + dispatch bound" % (r_verifier, r_author))
    return row


# ---------------------------------------------------------------------------
# top-level check
# ---------------------------------------------------------------------------

_NONCOMPLIANT = {
    "receipt-missing", "receipt-file-missing", "schema-invalid", "gate-mismatch",
    "self-authored-receipt", "verdict-not-confirmed", "stale-receipt-for-other-claim",
    "task-hash-mismatch", "forged-no-dispatch", "claim-missing",
}


def check(ws, *, draft=None, draft_text=None, gate=None, claim=None,
          receipts_dirs=None, dispatch_logs=None, include_default_dispatch=True) -> dict:
    ws = Path(ws).expanduser().resolve()
    draft_path = Path(draft).expanduser().resolve() if draft else None
    if draft_text is None:
        if draft_path is None:
            raise ValueError("check() needs draft path or draft_text")
        try:
            draft_text = draft_path.read_text(encoding="utf-8", errors="replace")
        except OSError as exc:
            draft_text = ""
            _read_err = str(exc)

    # dispatch entries (authority)
    log_paths: list[Path] = []
    if dispatch_logs:
        log_paths.extend(Path(p).expanduser() for p in dispatch_logs)
    if include_default_dispatch:
        log_paths.extend(default_dispatch_logs(ws))
    dispatch_entries = load_dispatch_entries(log_paths)

    rdirs = _receipt_search_dirs(ws, draft_path, receipts_dirs)

    # which gates to evaluate?
    if gate:
        gates = [gate.strip().lower()]
        forced = True
    else:
        gates = [g for g in LOAD_BEARING_GATES if gate_in_play(draft_text, g)]
        forced = False

    items: list[dict] = []
    for g in gates:
        # in auto mode, only forced=False; a gate that is not in play is skipped.
        row = evaluate_gate(
            draft_text, ws, g,
            draft_path=draft_path,
            claim_override=claim if (forced or gate) else None,
            receipts_dirs=rdirs,
            dispatch_entries=dispatch_entries,
        )
        items.append(row)

    bad = [i for i in items if i["status"] in _NONCOMPLIANT]
    strict = _strict()
    if not gates:
        verdict = "pass-verification-receipt"  # no converted gate in play
    elif not bad:
        verdict = "pass-verification-receipt"
    elif strict:
        verdict = "fail-verification-missing-receipt"
    else:
        verdict = "warn-verification-missing-receipt"

    return {
        "schema": SCHEMA,
        "workspace": str(ws),
        "draft": str(draft_path) if draft_path else "<text>",
        "verdict": verdict,
        "strict": strict,
        "forced_gate": gate.strip().lower() if gate else None,
        "gates_evaluated": gates,
        "noncompliant_count": len(bad),
        "dispatch_entries_loaded": len(dispatch_entries),
        "items": items,
    }


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def _print_human(r: dict) -> None:
    print("verification-receipt-check: %s (%d noncompliant / %d gate(s))"
          % (r["verdict"], r["noncompliant_count"], len(r["gates_evaluated"])))
    for i in r["items"]:
        flag = "  " if i["status"] in (STATUS_OK, "rebutted") else "  <-- "
        print("  [%-28s] gate=%s%s%s" % (i["status"], i["gate"], flag, i.get("detail", "")))


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--workspace", type=Path, help="workspace root (for receipt + dispatch-log discovery)")
    ap.add_argument("--draft", type=Path, help="the finding draft (.md) to validate")
    ap.add_argument("--gate", help="a single converted load-bearing gate id to validate (forces it in play)")
    ap.add_argument("--claim", help="explicit claim text for the gate (overrides the draft verification-claim marker)")
    ap.add_argument("--receipts-dir", action="append", default=[], help="extra receipt search dir (repeatable)")
    ap.add_argument("--dispatch-log", action="append", default=[], help="extra dispatch log to cross-check (repeatable)")
    ap.add_argument("--no-default-dispatch", action="store_true", help="do not auto-include default dispatch logs")
    ap.add_argument("--print-descriptor", action="store_true",
                    help="emitter helper: print canonical claim_hash + task_hash for --gate/--claim and exit")
    ap.add_argument("--json", action="store_true")
    a = ap.parse_args(argv)

    if a.print_descriptor:
        if not a.gate or a.claim is None:
            ap.error("--print-descriptor needs --gate and --claim")
        ch = claim_hash(a.claim)
        th = task_hash(a.gate, ch)
        out = {"gate": a.gate.strip().lower(), "claim_hash": ch, "task_hash": th,
               "task_domain": TASK_DOMAIN}
        print(json.dumps(out, indent=2) if a.json else
              "claim_hash=%s\ntask_hash=%s" % (ch, th))
        return 0

    if not a.workspace or not a.draft:
        ap.error("--workspace and --draft are required (unless --print-descriptor)")

    r = check(a.workspace, draft=a.draft, gate=a.gate, claim=a.claim,
              receipts_dirs=a.receipts_dir or None,
              dispatch_logs=a.dispatch_log or None,
              include_default_dispatch=not a.no_default_dispatch)
    if a.json:
        print(json.dumps(r, indent=2))
    else:
        _print_human(r)
    return 1 if r["verdict"] == "fail-verification-missing-receipt" else 0


if __name__ == "__main__":
    raise SystemExit(main())
