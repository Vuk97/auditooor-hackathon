#!/usr/bin/env python3
"""Hunt-dispatch PROVENANCE guard (Rule 3 enforcement).

The per-function hunt (README step-3) MUST be dispatched through
tools/spawn-worker.sh, which logs every dispatch to
.auditooor/spawn_worker_log.jsonl (lane ledger + prior-lane dedup scan +
RANDOM-DISPATCH-GUARD signing). A raw Agent/Workflow fan-out that reads the
batch files directly BYPASSES that ledger + guard - the hunt findings are still
canonical (the batch briefs come from haiku-fanout-dispatcher) but the dispatch
is unlogged and unguarded, so future off-pipeline drift goes undetected.

This guard ties a workspace's CURRENT scoped-hunt plan to the dispatch ledger:
when the plan exists AND it was clearly dispatched (fresh hunt sidecars produced,
or the obligation marked completed) BUT NO ledger entry references that plan ->
fail-hunt-dispatch-unlogged. It is plan-specific, so an older logged hunt cannot
mask a newer unlogged one.

Verdicts (default, plan-level ``check``):
  pass-hunt-dispatch-logged       enough ledger entries reference the current plan
  fail-hunt-dispatch-unlogged     plan dispatched (sidecars/obligation) but 0 ledger entries
  warn-hunt-dispatch-partial      some but < half the batches were logged
  not-applicable                  no scoped-hunt plan for this workspace
rc: 0 on pass / NA / warn ; 1 on fail.

-------------------------------------------------------------------------------
PER-SIDECAR PROVENANCE AUTHENTICITY (``--sidecars`` mode)  [E4]
-------------------------------------------------------------------------------
The plan-level ``check`` above catches a hunt dispatched OUTSIDE spawn-worker.sh.
It does NOT catch the finer failure: an INDIVIDUAL per-function hunt sidecar that
CLAIMS a real hunt (source-read / agent dispatch) but was actually INLINE-AUTHORED
(never dispatched to any subagent) - a SYNTHETIC sidecar. These synthetic sidecars
green the per-function function-coverage gate (function-coverage-completeness.py
credits a function as ``real-attack`` on any sidecar carrying a file_line, without
checking provenance). Evidence: NUVA had 437 tier-3-synthetic-taxonomy-anchored
sidecars that were inline-authored (``grep opus-via-agent tools/*.py = 0``) yet
credited full per-fn coverage.

*** THE TOKEN==0 TRAP (do NOT key on tokens): tools/haiku-fanout-dispatcher.py
HARDCODES input_tokens=0 / output_tokens=0 / cost_usd=0 for ALL genuine
haiku/sonnet-via-agent sidecars (the subagent cannot self-report token usage). So
``input_tokens==0`` is TRUE for BOTH ~142 genuine dispatched sidecars AND the
inline-authored synthetic ones. Keying on tokens would false-flag every genuine
haiku hunt.

The RELIABLE discriminator is the INLINE-AUTHORING signature, NOT the token count:
a genuinely dispatched subagent fills REAL iso8601 started/ended timestamps and a
REAL duration_s (>0, started != ended); an inline-authored synthetic sidecar sets
``duration_s`` to 0/None with ``started_at_utc == ended_at_utc`` (or omits both).
A sidecar is reclassified ``synthetic-lead: needs real hunt`` when it (a) CLAIMS a
real hunt (claims coverage credit: has a file_line/code_excerpt OR a tier-1/tier-2
source-read tier OR an agent/LLM provider) AND (b) has NO dispatch provenance -
the inline-authoring signature above AND no spawn_worker dispatch receipt links it.
A genuine zero-token haiku sidecar has a real duration (or a dispatch receipt) and
is NEVER flagged.

Sidecar-mode verdicts:
  pass-sidecar-provenance-authentic     no unprovenanced claimed-hunt sidecar
  warn-sidecar-provenance-unverified    >=1 synthetic-lead (advisory; rc 0)
  fail-sidecar-provenance-unverified    >=1 synthetic-lead AND strict
STRICT is now DEFAULT-ON under the L37 umbrella (operator decision 2026-07-03):
a synthetic-lead ELEVATES to FAIL + rc 1 under ``--strict``, an explicit
``AUDITOOOR_SIDECAR_PROVENANCE_STRICT`` opt-in, OR (the new default) whenever
``AUDITOOOR_L37_STRICT`` is set with the named env UNSET. An explicit
``AUDITOOOR_SIDECAR_PROVENANCE_STRICT`` in {0,false,no} opts OUT (advisory even
under L37), and a bare non-strict caller with BOTH envs unset stays WARN + rc 0
(byte-identical to no-check; never-retro-red). The hunt-coverage-gate consumes
this scan advisory-only and never derives its COVERAGE verdict from it.
"""
from __future__ import annotations

import argparse
import json
import os
import re
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
LEDGER = REPO_ROOT / ".auditooor" / "spawn_worker_log.jsonl"
DERIVED = REPO_ROOT / "audit" / "corpus_tags" / "derived"
PROVIDER_RECEIPT = ".auditooor/provider_dispatch_receipt.json"
PROVIDER_RECEIPT_SCHEMA = "auditooor.provider_fanout_receipt.v1"

V_PASS = "pass-hunt-dispatch-logged"
V_FAIL = "fail-hunt-dispatch-unlogged"
V_WARN = "warn-hunt-dispatch-partial"
V_NA = "not-applicable"

# ---- per-sidecar provenance authenticity (E4) --------------------------------
SIDECAR_STRICT_ENV = "AUDITOOOR_SIDECAR_PROVENANCE_STRICT"
SC_V_PASS = "pass-sidecar-provenance-authentic"
SC_V_WARN = "warn-sidecar-provenance-unverified"
SC_V_FAIL = "fail-sidecar-provenance-unverified"
SC_RECLASS = "synthetic-lead: needs real hunt"


def _sidecar_provenance_strict_enabled() -> bool:
    """Uniform gate predicate for AUDITOOOR_SIDECAR_PROVENANCE_STRICT.
    GRADUATED TO DEFAULT-ON under the L37 strict umbrella (operator decision
    2026-07-03):
      explicit opt-out : {0,false,no}  -> advisory (WARN, escape hatch)
      explicit opt-in  : any other value -> strict (a synthetic-lead FAILs)
      unset (new default): strict iff AUDITOOOR_L37_STRICT is truthy (what
        `make audit-complete STRICT=1` exports); a bare non-strict / library
        caller with L37 unset stays advisory (byte-identical to no-check).
    NOTE: this only flips the per-sidecar PROVENANCE sub-verdict (WARN->FAIL). The
    hunt-coverage-gate's `--sidecar-provenance` attaches this result advisory-only
    and NEVER derives its COVERAGE verdict/exit from it, so the coverage gate's
    advisory envelope is preserved."""
    v = os.environ.get(SIDECAR_STRICT_ENV, "").strip().lower()
    if v in ("0", "false", "no"):
        return False                        # explicit opt-out
    if v:                                    # any other explicit value
        return True                          # explicit opt-in
    # unset -> default-ON under the L37 strict umbrella; advisory otherwise.
    return os.environ.get("AUDITOOOR_L37_STRICT", "").strip().lower() not in (
        "", "0", "false", "no")

# Provider strings that CLAIM an agent/LLM dispatch (a "real hunt"). A sidecar
# authored by a genuine dispatcher carries one of these; so does an inline-authored
# synthetic that copies the haiku-fanout template - the provider alone cannot
# distinguish them (that is the whole point: use the inline-authoring signature).
_DISPATCH_PROVIDER_RE = re.compile(
    r"(via-agent|via-orchestrator|claude|opus|sonnet|haiku|gpt|deepseek|mimo|gemini)",
    re.IGNORECASE,
)
# verification_tier prefixes that CLAIM a real source-read (tier-1 / tier-2). These
# are the tiers function-coverage-completeness credits as genuine per-fn coverage.
_SOURCE_READ_TIER_RE = re.compile(r"^tier-[12]\b", re.IGNORECASE)


def _newest_plan_dir(wsname: str) -> Path | None:
    """Newest haiku_harness_<wsname>_scoped_n*/_haiku_plan dir with batch files."""
    cands = []
    for d in DERIVED.glob(f"haiku_harness_{wsname}_scoped_n*"):
        plan = d / "_haiku_plan"
        if plan.is_dir() and any(plan.glob("agent_batch_*.md")):
            cands.append(plan)
    if not cands:
        return None
    return max(cands, key=lambda p: p.stat().st_mtime)


def _ledger_entries():
    if not LEDGER.is_file():
        return []
    out = []
    for line in LEDGER.read_text(encoding="utf-8", errors="replace").splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            d = json.loads(line)
        except ValueError:
            continue
        if isinstance(d, dict):
            out.append(d)
    return out


def _dispatched_evidence(ws: Path, plan_mtime: float) -> bool:
    """True if there is evidence the plan was actually dispatched: a hunt sidecar
    newer than the plan, OR the hunt obligation marked completed."""
    sc_dir = ws / ".auditooor" / "hunt_findings_sidecars"
    if sc_dir.is_dir():
        for p in sc_dir.glob("*.json"):
            try:
                if p.stat().st_mtime >= plan_mtime - 1:
                    return True
            except OSError:
                continue
    oblig = ws / ".auditooor" / "hunt_provider_obligation.json"
    if oblig.is_file():
        try:
            d = json.loads(oblig.read_text(encoding="utf-8", errors="replace"))
            if str(d.get("status")) == "completed":
                return True
        except (OSError, ValueError):
            pass
    return False


def _valid_provider_receipt(ws: Path, plan_token: str) -> tuple[bool, str]:
    """Validate the explicit canonical provider-dispatch receipt."""
    path = ws / PROVIDER_RECEIPT
    try:
        receipt = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return False, "missing or invalid provider receipt"
    required = ("workspace", "output_dir", "plan_token", "provider", "task_count",
                "terminal_counts", "started_at_utc", "ended_at_utc")
    if receipt.get("schema") != PROVIDER_RECEIPT_SCHEMA or any(k not in receipt for k in required):
        return False, "provider receipt has wrong schema or missing fields"
    if str(receipt["workspace"]) != str(ws) or str(receipt["plan_token"]) != plan_token:
        return False, "provider receipt is for a different workspace or plan"
    if not str(receipt["provider"]).strip() or not str(receipt["output_dir"]).strip():
        return False, "provider receipt has empty provider or output"
    if not isinstance(receipt["task_count"], int) or receipt["task_count"] < 1:
        return False, "provider receipt task_count is invalid"
    counts = receipt["terminal_counts"]
    if not isinstance(counts, dict) or any(not isinstance(v, int) or v < 0 for v in counts.values()):
        return False, "provider receipt terminal_counts is invalid"
    if sum(counts.values()) != receipt["task_count"]:
        return False, "provider receipt terminal_counts do not reconcile"
    incomplete = {
        str(status): count
        for status, count in counts.items()
        if str(status).strip().lower() != "ok" and count
    }
    if incomplete:
        return False, (
            "provider dispatch is incomplete: terminal task counts contain "
            + json.dumps(incomplete, sort_keys=True)
            + "; every planned task must finish with status=ok"
        )
    started = _parse_iso_ts(receipt["started_at_utc"])
    ended = _parse_iso_ts(receipt["ended_at_utc"])
    if started is None or ended is None or ended < started:
        return False, "provider receipt timestamps are invalid"
    return True, str(path)


def check(ws: Path) -> dict:
    wsname = ws.name
    plan = _newest_plan_dir(wsname)
    if plan is None:
        return {"verdict": V_NA, "reason": f"no scoped-hunt plan for {wsname}"}
    batches = sorted(plan.glob("agent_batch_*.md"))
    n_batches = len(batches)
    plan_token = plan.parent.name  # haiku_harness_<wsname>_scoped_nNNN
    ws_str = str(ws)

    logged = 0
    logged_refs: list[str] = []
    for e in _ledger_entries():
        if str(e.get("workspace", "")) != ws_str:
            continue
        refs = (str(e.get("prompt_file") or "") + " "
                + str(e.get("enriched_file") or ""))
        if plan_token in refs:
            logged += 1
            logged_refs.append(refs)

    unique_logged_refs = set(logged_refs)
    duplicate_dispatches = max(
        logged - len(unique_logged_refs),
        logged - n_batches,
    )

    detail = {
        "plan": plan_token, "batches": n_batches,
        "logged_dispatches_for_plan": logged,
        "unique_logged_dispatches_for_plan": len(unique_logged_refs),
        "duplicate_dispatches_for_plan": duplicate_dispatches,
        "ledger": str(LEDGER),
    }
    provider_ok, provider_reason = _valid_provider_receipt(ws, plan_token)
    detail["provider_receipt"] = provider_reason
    if duplicate_dispatches:
        return {
            "verdict": V_FAIL,
            "reason": (f"plan {plan_token} has {duplicate_dispatches} duplicate dispatch "
                       "ledger entr(ies); every batch must be dispatched exactly once"),
            "detail": detail,
        }
    if provider_ok:
        return {"verdict": V_PASS, "reason":
                f"provider fanout receipt {provider_reason} proves canonical provider dispatch",
                "detail": detail}
    # A provider receipt is the terminal authority for a dispatched plan.  Do
    # not let a matching spawn ledger green an incomplete, skipped, or
    # malformed provider run.  The ledger is provenance, not completion.
    receipt_path = ws / PROVIDER_RECEIPT
    if receipt_path.exists():
        return {
            "verdict": V_FAIL,
            "reason": f"provider dispatch receipt invalid: {provider_reason}",
            "detail": detail,
        }
    dispatched = _dispatched_evidence(ws, plan.stat().st_mtime)
    detail["dispatched_evidence"] = dispatched

    if logged == 0:
        if dispatched:
            return {
                "verdict": V_FAIL,
                "reason": (f"plan {plan_token} ({n_batches} batches) was dispatched "
                           "(fresh hunt sidecars / completed obligation) but ZERO "
                           "spawn_worker_log entries reference it - the hunt bypassed "
                           "tools/spawn-worker.sh (Rule 3: no dispatch ledger / "
                           "prior-lane-scan / RANDOM-DISPATCH-GUARD). Route every batch "
                           "through spawn-worker.sh (or `make hunt-dispatch`)."),
                "detail": detail,
            }
        return {"verdict": V_NA,
                "reason": f"plan {plan_token} present but not yet dispatched (no evidence)",
                "detail": detail}
    if logged < max(1, n_batches // 2):
        return {"verdict": V_WARN,
                "reason": (f"only {logged}/{n_batches} batches of {plan_token} were "
                           "dispatched via spawn-worker (partial canonical dispatch)"),
                "detail": detail}
    return {"verdict": V_PASS,
            "reason": (f"{logged} spawn-worker dispatch(es) reference {plan_token} "
                       f"({n_batches} batches) - canonical dispatch path used"),
            "detail": detail}


# =============================================================================
# PER-SIDECAR PROVENANCE AUTHENTICITY  (E4)
# =============================================================================


def _claims_real_hunt(sc: dict) -> bool:
    """True iff the sidecar CLAIMS a real per-fn hunt (so it would be credited as
    genuine per-function coverage). This is the ``needs-provenance`` predicate: a
    sidecar that does not claim coverage credit is not subject to the guard.

    A sidecar claims a real hunt when ANY of:
      - it carries a ``file_line`` / ``code_excerpt`` (function-coverage-completeness
        credits a ``real-attack`` on that), OR
      - its ``verification_tier`` claims a tier-1/tier-2 SOURCE-READ, OR
      - its ``provider`` claims an agent/LLM dispatch.
    A ``result`` payload embedding a file_line/code_excerpt also counts (the per-fn
    MIMO/haiku nested schema stores the verdict as a JSON string in ``result``).
    """
    for k in ("file_line", "code_excerpt", "source_line", "source_refs"):
        if sc.get(k):
            return True
    tier = str(sc.get("verification_tier") or "")
    if _SOURCE_READ_TIER_RE.match(tier):
        return True
    # NOTE: a tier-3-synthetic-taxonomy-anchored sidecar (the NUVA 437 case) STILL
    # claims per-fn coverage credit when it carries a via-agent provider (checked
    # next) or a file_line (checked above) - it is not exempt just because it labels
    # itself synthetic; that self-label is precisely what makes it a synthetic-lead.
    prov = str(sc.get("provider") or "")
    if _DISPATCH_PROVIDER_RE.search(prov):
        return True
    result = sc.get("result")
    if isinstance(result, str) and ("file_line" in result or "code_excerpt" in result):
        return True
    if isinstance(result, dict) and (result.get("file_line") or result.get("code_excerpt")):
        return True
    return False


def _inline_authored_signature(sc: dict) -> bool:
    """The token-INDEPENDENT, POSITIVE synthetic signature.

    A genuinely dispatched subagent fills REAL iso8601 started/ended timestamps and
    a REAL duration_s (>0, started != ended). An inline-authored synthetic sidecar
    that copies the haiku-fanout template sets ``duration_s`` to exactly 0/None WITH
    the timing fields PRESENT but degenerate (started_at_utc == ended_at_utc). That
    degenerate-but-present pair is the POSITIVE marker of inline authoring.

    We DELIBERATELY do NOT look at input_tokens/output_tokens: haiku-fanout-
    dispatcher.py hardcodes tokens=0 for GENUINE via-agent sidecars, so a token==0
    test would false-flag ~142 real hunts (the build trap).

    NEVER-FALSE-FLAG: this returns True ONLY on the degenerate-but-PRESENT timing
    pair. A sidecar that simply OMITS all timing fields is AMBIGUOUS (an older
    dispatcher variant may not emit them) and is NOT treated as inline-authored by
    this signal alone - it can still be flagged via the explicit tier-3-synthetic
    self-declaration, but never on absent-timing alone.
    """
    dur = sc.get("duration_s", "MISSING")
    # A real dispatch produced a positive, non-degenerate duration -> genuine.
    if isinstance(dur, (int, float)) and dur > 0:
        return False
    has_dur = "duration_s" in sc
    started = sc.get("started_at_utc")
    ended = sc.get("ended_at_utc")
    has_ts = ("started_at_utc" in sc) or ("ended_at_utc" in sc)
    # If timing is entirely absent -> ambiguous, not a positive signal here.
    if not has_dur and not has_ts:
        return False
    # If timestamps are present and DIFFER, the run was measured -> genuine.
    if started and ended and started != ended:
        return False
    # duration present and <=0/None, AND (started==ended OR one ts present with
    # no differing pair) -> degenerate-but-present inline-authoring signature.
    return True


def _self_declared_synthetic(sc: dict) -> bool:
    """A sidecar whose verification_tier openly labels itself taxonomy-anchored /
    synthetic (NOT a real source-read). This is an explicit self-admission that the
    verdict was reasoned from a taxonomy, not produced by reading the CUT - so if it
    is nonetheless being credited as per-fn coverage it is a synthetic-lead. Both the
    genuine haiku-fanout template AND inline copies carry this label, so it is a
    synthetic signal ONLY when paired (in the caller) with no real duration and no
    dispatch receipt.
    """
    tier = str(sc.get("verification_tier") or "").lower()
    return tier.startswith("tier-3-synthetic") or "taxonomy-anchored" in tier


# Lane types that spawn-worker.sh logs for a genuine PER-FUNCTION / IMPACT hunt
# dispatch. A sidecar written in the mtime window of one of these lanes (and only
# when that lane's brief is ALSO confirmed by a sibling sidecar's dispatch_receipt,
# see _ws_confirmed_dispatch_windows) is dispatch-verified. Non-hunt lanes (filing,
# tool-build, capability, dispute, ...) never open a hunt-provenance window.
_HUNT_LANE_TYPES = frozenset(("hunt", "drill", "depth", "invariant-harness", "harness"))

# Bounded forward window (seconds) after a CONFIRMED dispatch lane during which a
# freshly-authored sidecar is credited as dispatch-verified. A genuine dispatched
# subagent runs then writes its sidecar minutes-to-hours after the lane's dispatch
# timestamp (observed ~2h on the NUVA rehunt batch). The window ONLY extends
# FORWARD from a real, receipt-confirmed dispatch, so it can NEVER retroactively
# credit a synthetic authored BEFORE that dispatch (the historical NUVA 437). A
# generous-but-bounded default (12h) tolerates long agent fleets; env-overridable.
_DISPATCH_WINDOW_SECS_DEFAULT = 12 * 3600
_DISPATCH_WINDOW_ENV = "AUDITOOOR_DISPATCH_WINDOW_SECS"


def _dispatch_window_secs() -> float:
    v = os.environ.get(_DISPATCH_WINDOW_ENV, "").strip()
    if v:
        try:
            n = float(v)
            if n > 0:
                return n
        except ValueError:
            pass
    return float(_DISPATCH_WINDOW_SECS_DEFAULT)


def _parse_iso_ts(s) -> float | None:
    """Parse an iso8601 spawn_worker_log ``ts`` (e.g. 2026-07-03T19:54:03.678435Z)
    to an epoch. Returns None on absent/unparseable input (which contributes NO
    window - a lane with no timestamp can never open a provenance window)."""
    if not s:
        return None
    txt = str(s).strip()
    if txt.endswith("Z"):
        txt = txt[:-1] + "+00:00"
    try:
        from datetime import datetime
        return datetime.fromisoformat(txt).timestamp()
    except (ValueError, TypeError):
        return None


def _ws_ledger_for(ws: Path):
    """spawn_worker_log entries whose workspace is THIS ws (path or basename match)."""
    ws_str = str(ws).rstrip("/")
    ws_name = ws.name
    for e in _ledger_entries():
        w = str(e.get("workspace", "")).rstrip("/")
        if w == ws_str or w.endswith("/" + ws_name):
            yield e


def _sidecar_dispatch_brief_basenames(ws: Path) -> set[str]:
    """Brief basenames self-reported by ANY sidecar's ``dispatch_receipt`` block
    for this ws. A genuine dispatched hunt sidecar carries
    ``dispatch_receipt.dispatch_brief_file`` = the exact per-lane enriched brief
    filename spawn-worker.sh wrote at dispatch time (it embeds the lane_id + the
    dispatch PID). This basename is the load-bearing JOIN key: it is matched against
    the ledger's own ``enriched_file`` basename below. Not forgeable inline: an
    inline synthetic would have to both name a real per-lane brief AND have a real
    ledger entry for it (which only exists if spawn-worker.sh actually dispatched)."""
    briefs: set[str] = set()
    for _p, sc in _iter_sidecars(ws):
        dr = sc.get("dispatch_receipt")
        if isinstance(dr, dict):
            b = dr.get("dispatch_brief_file") or dr.get("enriched_file")
            if b:
                briefs.add(os.path.basename(str(b)))
    return briefs


def _ws_confirmed_dispatch_windows(ws: Path) -> list[tuple[float, float]]:
    """Bounded forward mtime windows for GENUINE dispatched hunt lanes on this ws.

    A lane opens a window ONLY when BOTH hold:
      1. it is a hunt-class lane (``lane_type in _HUNT_LANE_TYPES``) for this ws, AND
      2. its brief basename (``enriched_file`` / ``durable_brief_path`` /
         ``prompt_file``) is CONFIRMED by a sibling sidecar's ``dispatch_receipt``
         (i.e. we have independent evidence this exact lane produced a real
         dispatched sidecar).

    Requiring the receipt-confirmation is what keeps this NEVER-FALSE-PASS: an
    arbitrary logged hunt lane is NOT enough (the ws had genuine hunt lanes running
    the whole time the 437 synthetics were inline-authored, so a bare "any hunt
    lane" window would false-credit them). Only a lane we can PROVE produced a
    real dispatched sidecar (via that sidecar's own brief-file receipt) anchors a
    window, and the window extends strictly FORWARD from the lane's dispatch ts, so
    pre-dispatch synthetics are never covered.

    Returns [] when no lane is receipt-confirmed (advisory-safe: no windows -> the
    window signal never fires, falling back to the receipt-link + inline-signature
    logic exactly as before)."""
    confirmed = _sidecar_dispatch_brief_basenames(ws)
    if not confirmed:
        return []
    w = _dispatch_window_secs()
    windows: list[tuple[float, float]] = []
    for e in _ws_ledger_for(ws):
        if str(e.get("lane_type", "")) not in _HUNT_LANE_TYPES:
            continue
        lane_briefs = {
            os.path.basename(str(e.get(k) or ""))
            for k in ("enriched_file", "durable_brief_path", "prompt_file")
        }
        lane_briefs.discard("")
        if not (lane_briefs & confirmed):
            continue
        ts = _parse_iso_ts(e.get("ts"))
        if ts is None:
            continue
        windows.append((ts, ts + w))
    return windows


def _mtime_in_windows(path: Path, windows: list[tuple[float, float]]) -> bool:
    if not windows:
        return False
    try:
        mt = path.stat().st_mtime
    except OSError:
        return False
    return any(start <= mt <= end for start, end in windows)


def _ws_dispatch_receipt_tokens(ws: Path) -> set[str]:
    """Plan/batch/lane tokens referenced by spawn_worker_log receipts for THIS ws.
    Presence of a receipt is a PASS signal (belt-and-suspenders): a sidecar whose
    run identity matches a logged dispatch is provenanced even if its timing looks
    degenerate. Never a FLAG trigger.
    """
    toks: set[str] = set()
    for e in _ws_ledger_for(ws):
        blob = " ".join(str(e.get(k) or "") for k in (
            "prompt_file", "enriched_file", "durable_brief_path", "lane_id"))
        for m in re.findall(r"[A-Za-z0-9_.-]{6,}", blob):
            toks.add(m)
    return toks


def _sidecar_run_identity(path: Path, sc: dict) -> set[str]:
    """Run/plan identity tokens for a sidecar (used to match against receipts)."""
    cand: set[str] = set()
    for k in ("task_id", "source_question_id", "run_id", "batch_id", "plan"):
        v = str(sc.get(k) or "")
        if len(v) >= 6:
            cand.add(v)
    # The dispatch_receipt block (when present) names the exact per-lane brief
    # spawn-worker.sh wrote; its basename token-matches the ledger enriched_file.
    dr = sc.get("dispatch_receipt")
    if isinstance(dr, dict):
        for k in ("dispatch_brief_file", "enriched_file", "lane"):
            v = os.path.basename(str(dr.get(k) or ""))
            if len(v) >= 6:
                cand.add(v)
    stem = path.name[:-5] if path.name.endswith(".json") else path.name
    if len(stem) >= 6:
        cand.add(stem)
    return cand


def _has_receipt_link(run_ids: set[str], receipt_tokens: set[str]) -> bool:
    if not run_ids or not receipt_tokens:
        return False
    for rid in run_ids:
        for rt in receipt_tokens:
            if rid == rt or rid in rt or rt in rid:
                return True
    return False


def classify_sidecar_provenance(
    path: Path,
    sc: dict,
    receipt_tokens: set[str],
    dispatch_windows: list[tuple[float, float]] | None = None,
) -> dict:
    """Classify ONE sidecar as provenance-authentic or a synthetic-lead.

    Returns a dict with ``status`` in {"authentic", "synthetic-lead",
    "not-coverage-claiming"} plus the reason and the signals used. NEVER-FALSE-FLAG:
    only a sidecar that BOTH claims a real hunt AND lacks dispatch provenance is a
    synthetic-lead. NEVER-FALSE-PASS: a self-declared tier-3-synthetic sidecar that
    IS being credited (claims a hunt) with the inline signature is flagged even
    though it carries a via-agent provider.

    ``dispatch_windows`` (optional) are the bounded forward mtime windows of
    RECEIPT-CONFIRMED hunt dispatch lanes for this ws (from
    ``_ws_confirmed_dispatch_windows``). A sidecar written INSIDE such a window is
    dispatch-verified even when it hand-writes ``duration_s==0`` and self-labels
    tier-3-synthetic - it was produced by the same genuine dispatch batch as the
    receipt-carrying sibling sidecar that confirmed the window. This is the JOIN
    that lets a genuinely-dispatched hand-written sidecar (duration_s==0, no own
    receipt block) be recognized authentic without crediting a pre-dispatch inline
    synthetic (whose mtime falls in NO forward window). Passing ``None`` preserves
    the pre-window behavior byte-for-byte (no window signal ever fires).
    """
    if not _claims_real_hunt(sc):
        return {"status": "not-coverage-claiming", "sidecar": str(path)}

    run_ids = _sidecar_run_identity(path, sc)
    if _has_receipt_link(run_ids, receipt_tokens):
        return {"status": "authentic", "reason": "dispatch-receipt-linked",
                "sidecar": str(path)}

    # DISPATCH-WINDOW JOIN: written inside a receipt-confirmed hunt lane's forward
    # window -> a genuine dispatched sidecar from that batch (even with duration==0
    # and a tier-3-synthetic self-label). The window is anchored ONLY to lanes we
    # PROVED produced a real dispatched sidecar and extends strictly forward, so a
    # synthetic authored BEFORE any dispatch is never covered (NEVER-FALSE-PASS).
    if _mtime_in_windows(path, dispatch_windows or []):
        return {"status": "authentic", "reason": "dispatch-window-verified",
                "sidecar": str(path)}

    dur = sc.get("duration_s", None)
    real_duration = isinstance(dur, (int, float)) and dur > 0
    if real_duration:
        # real, non-degenerate duration -> genuinely dispatched (THE HAIKU TRAP CASE
        # lands HERE: input_tokens==0/output_tokens==0 but the subagent filled a real
        # duration_s>0, so it is authentic and NEVER flagged on the token count).
        return {"status": "authentic", "reason": "real-duration",
                "sidecar": str(path)}

    inline_sig = _inline_authored_signature(sc)
    self_synth = _self_declared_synthetic(sc)
    if not inline_sig and not self_synth:
        # no real duration but no POSITIVE synthetic signal either (e.g. timing simply
        # absent, tier is a real source-read) -> ambiguous; give benefit of the doubt.
        return {"status": "authentic", "reason": "no-positive-synthetic-signal",
                "sidecar": str(path)}

    # claims a hunt + (inline-authoring signature OR self-declared synthetic) + no
    # real duration + no receipt link -> provenance-unverified synthetic-lead.
    tier = str(sc.get("verification_tier") or "")
    signals = []
    if inline_sig:
        signals.append("inline-authoring(duration_s<=0/None & started==ended)")
    if self_synth:
        signals.append("self-declared tier-3-synthetic-taxonomy-anchored")
    return {
        "status": "synthetic-lead",
        "reclass": SC_RECLASS,
        "sidecar": str(path),
        "reason": (
            "sidecar claims a per-fn hunt (source-read tier / agent provider / "
            "file_line) but has no dispatch provenance ["
            + " + ".join(signals)
            + "] and no spawn_worker dispatch receipt links it - provenance-"
            "unverified; must NOT satisfy the per-unit coverage obligation under strict"
        ),
        "signals": signals,
        "verification_tier": tier,
        "provider": str(sc.get("provider") or ""),
        "function_anchor": sc.get("function_anchor"),
    }


def _iter_sidecars(ws: Path):
    for sub in (".auditooor/hunt_findings_sidecars", "hunt_findings_sidecars"):
        d = ws / sub
        if not d.is_dir():
            continue
        for p in sorted(d.rglob("*.json")):
            try:
                data = json.loads(p.read_text(encoding="utf-8", errors="replace"))
            except (OSError, ValueError):
                continue
            if isinstance(data, dict):
                yield p, data


def scan_workspace_sidecars(ws: Path, *, strict: bool | None = None) -> dict:
    """Advisory-first per-sidecar provenance scan over a workspace.

    strict=None -> env-driven via _sidecar_provenance_strict_enabled()
    (AUDITOOOR_SIDECAR_PROVENANCE_STRICT, now DEFAULT-ON under AUDITOOOR_L37_STRICT).
    A bare non-strict caller (both envs unset/falsey) => WARN + rc0 (byte-identical
    to no-check); explicit opt-out ({0,false,no}) stays advisory even under L37;
    strict elevates a synthetic-lead to FAIL.
    """
    if strict is None:
        strict = _sidecar_provenance_strict_enabled()

    receipt_tokens = _ws_dispatch_receipt_tokens(ws)
    dispatch_windows = _ws_confirmed_dispatch_windows(ws)
    total = 0
    coverage_claiming = 0
    authentic = 0
    synthetic: list[dict] = []
    for p, sc in _iter_sidecars(ws):
        total += 1
        res = classify_sidecar_provenance(p, sc, receipt_tokens, dispatch_windows)
        st = res["status"]
        if st == "not-coverage-claiming":
            continue
        coverage_claiming += 1
        if st == "authentic":
            authentic += 1
        elif st == "synthetic-lead":
            synthetic.append(res)

    if not synthetic:
        verdict = SC_V_PASS
    elif strict:
        verdict = SC_V_FAIL
    else:
        verdict = SC_V_WARN

    return {
        "mode": "sidecars",
        "verdict": verdict,
        "strict": strict,
        "strict_env": SIDECAR_STRICT_ENV,
        "workspace": str(ws),
        "total_sidecars": total,
        "coverage_claiming": coverage_claiming,
        "authentic": authentic,
        "synthetic_lead_count": len(synthetic),
        "dispatch_receipts_seen": bool(receipt_tokens),
        "dispatch_windows_seen": len(dispatch_windows),
        "synthetic_leads": synthetic[:200],
    }


def main(argv: list[str]) -> int:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("workspace")
    p.add_argument("--json", action="store_true")
    p.add_argument("--sidecars", action="store_true",
                   help="per-sidecar provenance authenticity scan (E4) instead of "
                        "the plan-level dispatch-log check")
    p.add_argument("--strict", action="store_true",
                   help=f"(--sidecars) elevate unverified sidecars to FAIL "
                        f"(or set {SIDECAR_STRICT_ENV}=1)")
    a = p.parse_args(argv)

    if a.sidecars:
        strict = True if a.strict else None  # None -> env-driven default
        res = scan_workspace_sidecars(Path(a.workspace), strict=strict)
        if a.json:
            print(json.dumps(res, indent=2, default=str))
        else:
            print(f"[sidecar-provenance] verdict={res['verdict']} "
                  f"strict={res['strict']}")
            print(f"  coverage-claiming: {res['coverage_claiming']} / "
                  f"{res['total_sidecars']} sidecars")
            print(f"  authentic: {res['authentic']}  "
                  f"synthetic-lead: {res['synthetic_lead_count']}")
            for s in res["synthetic_leads"][:25]:
                print(f"    - {SC_RECLASS}: {s['sidecar']}")
        return 1 if res["verdict"] == SC_V_FAIL else 0

    res = check(Path(a.workspace))
    if a.json:
        print(json.dumps(res, indent=2))
    else:
        print(f"[hunt-dispatch-provenance] verdict={res['verdict']}")
        print(f"  reason: {res['reason']}")
        for k, v in (res.get("detail") or {}).items():
            print(f"    {k}: {v}")
    return 1 if res["verdict"] == V_FAIL else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
