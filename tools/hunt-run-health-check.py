#!/usr/bin/env python3
"""hunt-run-health-check.py - HUNT-RUN-HEALTH detector.

A coverage number is only honest if the hunt behind it actually RAN. This tool
scans a workspace's hunt-record dirs (LLM hunt sidecars under
audit/corpus_tags/derived/mega*<ws>*/, mimo_harness_<ws>*/, mimo_hunt_<ws>*/)
and classifies every record by whether the hunt produced a real, anchored
result or silently failed (rate-limited / timed-out / never anchored).

Motivating finding (dydx, 2026-05-28): a per-function MIMO run produced 299
records that were ALL status=failed / error="retry-max-exhausted: rate-limited"
with function_anchor.file=="?" - i.e. 0 real anchors. The coverage dashboard
treated those functions as "looked at" when in fact the hunt never ran. A
silently-failed hunt must be FLAGGED for re-hunt, not counted as coverage.

RELATED TOOLS (Rule: tool-duplication preflight, 2026-05-28):
  - vault_mining_health (tools/vault-mcp-server.py): per-workspace mining
    telemetry - coverage heatmap summary, hacker-q reweight ledger snapshot,
    known-dead-end count, and an R76 *hallucination* signal count. It does NOT
    compute the success-vs-failed/rate-limited RATIO of hunt records. This tool
    adds exactly that orthogonal signal (HUNT-RUN-HEALTH). Its per-workspace
    report is shaped to feed straight into vault_mining_health as a new
    "hunt_run_health" sub-block (see the wire note printed by --wire-note).
  - tools/r76-hallucination-guard.py: catches records whose CONFIRMED result
    cites a code_excerpt that does not exist in source (hallucination). This
    tool catches the opposite failure: records that produced NO result at all.
    The two are complementary - hallucination vs. silent non-execution.
  - tools/workspace-coverage-heatmap.py (NOT edited): aggregates per-contract
    hypothesis density. It answers "which contracts were covered"; this tool
    answers "were the covering hunts real or rate-limited shells".
  - tools/mining-coverage-dashboard.py: coverage rollup; does not gate on
    run-health.

What is genuinely NEW here: the per-workspace success_fraction over hunt
RECORDS, and an explicit failed-run verdict (success ~0 despite many records ->
NEEDS RE-HUNT) with an env-tunable threshold.

Schema: auditooor.hunt_run_health.v1
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import sys
from pathlib import Path
from typing import Any

SCHEMA = "auditooor.hunt_run_health.v1"

# --- env-tunable thresholds ----------------------------------------------
# A run is "failed-run / NEEDS RE-HUNT" when it has many records but almost
# none succeeded. Both conditions must hold.
FAILED_RUN_SUCCESS_FRACTION = float(
    os.environ.get("HUNT_RUN_HEALTH_FAILED_FRACTION", "0.05")
)
# Minimum record count before we are willing to call a run "failed-run".
# Below this we say insufficient-data rather than condemn a tiny run.
FAILED_RUN_MIN_RECORDS = int(
    os.environ.get("HUNT_RUN_HEALTH_MIN_RECORDS", "20")
)
# A run is "healthy" at/above this success fraction.
HEALTHY_SUCCESS_FRACTION = float(
    os.environ.get("HUNT_RUN_HEALTH_HEALTHY_FRACTION", "0.50")
)
# REASONED-SUCCESS floor for the STRONG "healthy" verdict. The "healthy" label is
# the tool's strongest trust claim: it asserts the hunt anchored REAL findings
# across the surface. It is keyed on the RECORD-LEVEL success_fraction (fraction
# of ALL hunt records that anchored a real finding), NOT on unit-engagement.
# Rationale (axelar-dlt / nuva, 2026-07-13): the per-UNIT best-record rollup can
# read high engagement (unit_engaged_fraction ~0.82) while the record-level
# reasoned-success is near-zero (success_fraction ~0.037) - almost every record
# was an engaged-clean DECLINE, not a finding. Keying "healthy" on unit-engagement
# let a 0-finding audit wear the strong "healthy" badge. We therefore require the
# record-level success_fraction to clear this floor before emitting "healthy";
# below it the verdict is keyed on ENGAGEMENT (healthy-clean when the surface was
# reasoned-and-clean, degraded/failed-run when it was not). Floor default = the
# healthy fraction (0.5): to be called strong-"healthy" at least half of ALL hunt
# records must anchor a real finding. This is a REAL bar, not a rubber stamp - a
# clean 0-finding audit does NOT get "healthy", it gets the honest "healthy-clean"
# (which still certifies). unit_engaged_fraction stays REPORTED for context but is
# not load-bearing for the healthy claim.
REASONED_SUCCESS_FRACTION = float(
    os.environ.get("HUNT_RUN_HEALTH_REASONED_FRACTION", str(HEALTHY_SUCCESS_FRACTION))
)

# error substrings that mark a record as a failed (never-ran) hunt
_FAILURE_ERR_PATTERNS = [
    p.strip().lower()
    for p in os.environ.get(
        "HUNT_RUN_HEALTH_FAILURE_PATTERNS",
        "rate-limit,ratelimit,rate limit,timeout,timed out,exhaust,"
        "max-retries,retry-max,connection,429,503,unavailable,overloaded,"
        # credential/infra aborts: the dispatch NEVER reached the model (no key,
        # unauthorized, provider halted before inference). Semantically identical
        # to a rate-limit for trust purposes - "the hunt never ran for this
        # record" - so it belongs in the rate_limited (never-ran) bucket, NOT
        # "empty" (which means the model ran and honestly anchored nothing). On a
        # keyless mimo/deepseek env these dominate; misfiling them as "empty"
        # made the record-based success_fraction read as if the surface was
        # barely engaged when it was simply never dispatched.
        "auth-failed,auth failed,authentication,unauthorized,401,403,"
        "no-api-key,no api key,missing key,missing api key,invalid api key,"
        "api key not,api_key,apikey,credential,forbidden",
    ).split(",")
    if p.strip()
]

# values that mean "no real anchor"
_EMPTY_ANCHOR = {"", "?", "na", "n/a", "none", "null", "unknown"}

# default hunt-record dir glob templates, keyed off workspace name.
# {ws} is substituted with the workspace's basename.
_DIR_GLOB_TEMPLATES = [
    "mega*{ws}*",
    "mega*{ws}",
    "mimo_harness_{ws}",
    "mimo_harness_{ws}_*",
    "mimo_hunt_{ws}",
    "mimo_hunt_{ws}_*",
    # Haiku-via-Agent hunt sidecars (MIMO replacement) land in haiku_harness_<ws>_nNNNN/
    "haiku_harness_{ws}",
    "haiku_harness_{ws}_*",
]


def _is_failure_error(err: str) -> bool:
    e = (err or "").lower()
    return any(p in e for p in _FAILURE_ERR_PATTERNS)


def _real_anchor(value: Any) -> bool:
    """True if value is a non-empty, non-placeholder file reference."""
    if not isinstance(value, str):
        return False
    v = value.strip().lower()
    if v in _EMPTY_ANCHOR:
        return False
    # reject synthetic / conceptual placeholders
    if any(
        bad in v
        for bad in ("conceptual", "unavailable", "not found", "hypothetical",
                    "illustrative", "generic", "typical")
    ):
        return False
    return True


def _result_anchor_from_payload(result: Any) -> tuple[bool, str]:
    """Extract a (has_real_anchor, file_ref) from a record's result payload.

    The result is often a fenced JSON string emitted by the LLM with fields
    like file_line / file_path_hint / applies_to_target. Returns whether the
    result carries a usable anchor and the raw file ref found (for reporting).
    """
    if result is None:
        return (False, "")
    text = result if isinstance(result, str) else json.dumps(result)
    # applies_to_target=no means the model explicitly could not anchor.
    m_ato = re.search(r'"applies_to_target"\s*:\s*"([^"]+)"', text)
    applies = (m_ato.group(1).strip().lower() if m_ato else "")
    # pull any file reference field
    file_ref = ""
    for key in ("file_line", "file_path_hint", "file", "file_path"):
        m = re.search(r'"%s"\s*:\s*"([^"]*)"' % key, text)
        if m and m.group(1).strip():
            file_ref = m.group(1).strip()
            if _real_anchor(file_ref):
                break
    has_real_file = _real_anchor(file_ref)
    # A result is "anchored" if it explicitly applies to the target with a real
    # file, OR (when applies_to_target is absent) it carries a real file ref.
    if applies == "no":
        return (False, file_ref)
    if applies in ("yes", "maybe") and has_real_file:
        return (True, file_ref)
    if not applies and has_real_file:
        return (True, file_ref)
    return (has_real_file, file_ref)


# Class strength for per-unit best-verdict rollup: a unit (file::function) is as
# trustworthy as its BEST record. success > engaged (clean decline) > empty (ran,
# no anchor) > failed > rate_limited (never ran).
_KLASS_RANK = {"success": 4, "engaged": 3, "empty": 2, "failed": 1, "rate_limited": 0}

# Native-schema `verdict` values that denote a REAL finding (record classified
# "success"); anything else with a real file anchor is an engaged-clean decline
# ("engaged"). A NEGATIVE/clean verdict stays engaged, never success.
_FINDING_VERDICTS = {
    "confirmed", "positive", "finding", "true", "yes",
    "exploitable", "vulnerable", "affected",
}

# Native-schema `verdict` values (or top-level applies_to_target) that denote an
# explicit CLEAN DECLINE: the model looked and declined to anchor a finding. A
# declined record is engaged-clean (trustworthy coverage), NEVER a success - even
# when it carries a real file anchor. Prior bug (axelar-dlt/nuva 2026-07-13): a
# declined record with a real function_anchor.file was mislabeled "success",
# inflating units_success and letting a 0-finding audit read the strong "healthy".
_DECLINE_VERDICTS = {
    "negative", "negative-oos", "refuted", "kill", "killed", "clean",
    "declined", "not-applicable", "not_applicable", "na", "no",
    "false-positive", "false_positive", "fp", "unaffected", "safe", "rejected",
}


def _unit_key(rec: dict[str, Any]) -> str | None:
    """A stable per-unit key (file::function) so trust can be computed per UNIT,
    not per RECORD. Redundant failed/empty dispatches (e.g. a dead-provider run
    that halted on a missing API key) on a unit that ANOTHER provider hunted with
    a real verdict must NOT drag that unit's trust down. Returns None when no
    function anchor is resolvable."""
    fa = rec.get("function_anchor")
    f = fn = ""
    if isinstance(fa, dict):
        f = str(fa.get("file") or fa.get("file_path") or "")
        fn = str(fa.get("fn") or fa.get("function") or "")
    elif isinstance(fa, str):
        f = fa
    if not f:
        f = str(rec.get("file_anchor") or rec.get("file_path_hint") or "")
    # Native per-fn mechanism-verdict sidecar schema (SEI hunt_findings_sidecars /
    # agent_mechanism_verdicts): {unit, file, lines, verdict, cited_excerpt} at the
    # TOP LEVEL, no function_anchor wrapper. Resolve the unit from `file` + `unit`
    # so these records contribute a unit key (else they drop out of the per-unit
    # trust rollup entirely). Mirrors the unhunted-surface-adjudicate.py file_line
    # schema fix (2026-07-06).
    if not f:
        f = str(rec.get("file") or rec.get("file_path") or "")
    if not fn:
        fn = str(rec.get("unit") or rec.get("function") or "")
    f = f.split("/")[-1].split(":")[0].strip()
    fn = fn.split("(")[0].strip()
    return (f + "::" + fn) if f else None


def classify_record(rec: dict[str, Any]) -> tuple[str, str]:
    """Return (klass, file_ref). klass in {success, failed, rate_limited, empty}.

    - rate_limited: status failed AND error matches a failure pattern (or
      explicit rate-limit). The hunt never ran for this record.
    - failed: status failed for any other reason, or result is null/empty.
    - success: a real result with a real function anchor.
    - empty: produced output but no usable anchor (e.g. applies_to_target=no,
      file=="?") - the hunt mechanically ran but anchored nothing.
    """
    status = str(rec.get("status") or "").strip().lower()
    err = str(rec.get("error") or "")

    # explicit failed status
    if status in ("failed", "error", "fail"):
        if _is_failure_error(err):
            return ("rate_limited", "")
        return ("failed", "")

    # status ok (or anything else) - inspect the payload
    result = rec.get("result")
    if result is None or (isinstance(result, str) and not result.strip()):
        # Native per-fn mechanism-verdict sidecar schema (SEI hunt_findings_sidecars
        # / agent_mechanism_verdicts): {unit, file, lines, verdict, cited_excerpt}
        # at the TOP LEVEL, NO nested `result` wrapper. A `verdict` + a real `file`
        # anchor means the model mechanically ENGAGED this function and returned a
        # per-function verdict: engaged-clean on a NEGATIVE/declined verdict,
        # success on a real finding. Without this fallback ~70% of SEI's hunt
        # records (native schema, 3305/4949) were misfiled "empty", collapsing
        # units_engaged (0.46) and false-redding the hunt-trust `degraded` STRICT
        # gate. Mirrors the unhunted-surface-adjudicate.py top-level schema fix
        # (2026-07-06).
        _v = str(rec.get("verdict") or "").strip().lower()
        _ap = str(rec.get("applies_to_target") or "").strip().lower()
        # Resolve the anchor from EVERY native anchor field, not just `file`:
        # entrypoint-corpus / per-fn terminal-negative sidecars carry the anchor
        # in `file_line` or in a STRING `function_anchor` (no nested result, no
        # `file`). Prior bug (axelar-dlt 2026-07-13): 5133 genuinely-reasoned
        # NEGATIVE records with a real file_line + verdict were misfiled "empty"
        # purely because this branch only read `file`/`file_path`, deflating the
        # record-level engaged fraction toward a false failed-run.
        _f = ""
        _fa = rec.get("function_anchor")
        for _cand in (rec.get("file"), rec.get("file_path"), rec.get("file_line"),
                      _fa if isinstance(_fa, str) else
                      (_fa.get("file") or _fa.get("file_path")
                       if isinstance(_fa, dict) else None)):
            if isinstance(_cand, str) and _real_anchor(_cand):
                _f = _cand
                break
        if (_v or _ap) and _real_anchor(_f):
            # A finding verdict (and NOT an explicit decline) is a success; a
            # NEGATIVE/refuted/kill verdict or applies_to_target=no is an
            # engaged-clean decline.
            if _v in _FINDING_VERDICTS and _ap != "no" and _v not in _DECLINE_VERDICTS:
                return ("success", _f)
            return ("engaged", _f)
        # ran but produced nothing usable
        if _is_failure_error(err):
            return ("rate_limited", "")
        return ("empty", "")

    # function_anchor first (structured), then dig into result payload
    fa = rec.get("function_anchor") or {}
    fa_file = ""
    if isinstance(fa, dict):
        fa_file = fa.get("file") or fa.get("file_path") or ""
    elif isinstance(fa, str):
        fa_file = fa
    hint = rec.get("file_path_hint") or ""

    # EXPLICIT clean decline takes precedence over any anchor. A record whose
    # result says applies_to_target=no (or whose native verdict is a
    # NEGATIVE/refuted/kill decline) is the model DECLINING to anchor a finding
    # after looking - an engaged-CLEAN record, NEVER a success, even when it
    # carries a real function_anchor.file. Prior bug (axelar-dlt/nuva 2026-07-13):
    # every "success" record was actually applies_to_target=no with a real
    # function_anchor, so units_success was inflated and a 0-FINDING clean audit
    # read the strong "healthy" verdict. The decline is engaged-clean regardless
    # of whether a real anchor is present (the dydx "299" shape: function_anchor
    # {file:"?"} + applies_to_target=no is still an engaged-clean decline).
    _text = result if isinstance(result, str) else json.dumps(result)
    _declined = (
        bool(re.search(r'"applies_to_target"\s*:\s*"no"', _text, re.I))
        or str(rec.get("applies_to_target") or "").strip().lower() == "no"
        or str(rec.get("verdict") or "").strip().lower() in _DECLINE_VERDICTS
    )
    if _declined:
        for _cand in (fa_file, hint, rec.get("file_line"),
                      _result_anchor_from_payload(result)[1]):
            if isinstance(_cand, str) and _real_anchor(_cand):
                return ("engaged", _cand)
        return ("engaged", "")

    if _real_anchor(fa_file):
        return ("success", fa_file)
    if _real_anchor(hint):
        return ("success", hint)

    has_anchor, file_ref = _result_anchor_from_payload(result)
    if has_anchor:
        return ("success", file_ref)
    # The model produced a structured result but anchored no finding. If that
    # result carries an EXPLICIT applies_to_target verdict (yes/no/maybe) the
    # hunt mechanically RAN: the model engaged this function and (correctly, on
    # a clean target, often steered by the non-self / designed-as-intended /
    # rubric-fit kill-rules) declined to anchor a finding. That is a healthy
    # engaged-clean record, NOT a silent failure. Only a result with NO
    # structured verdict at all stays "empty" (the genuine never-ran / garbage
    # signal). This stops a fully-executed hunt on a 0-finding clean workspace
    # from being mislabelled "failed-run" purely because it honestly found
    # nothing.
    text = result if isinstance(result, str) else json.dumps(result)
    # ONLY an explicit applies_to_target="no" counts as engaged-clean: it is the
    # model definitively DECLINING to anchor a finding after looking - the clean
    # signal. An applies_to_target="yes" without a real anchor (handled above)
    # is an R76 hallucination (model claims a bug but cites a conceptual / fake
    # location) and MUST stay "empty" so it is not trusted; a bare "maybe" with
    # no anchor is unresolved and also stays "empty".
    if re.search(r'"applies_to_target"\s*:\s*"no"', text, re.I):
        return ("engaged", file_ref)
    return ("empty", file_ref)


def find_hunt_dirs(derived_root: Path, ws_name: str, ws_path: str | None = None) -> list[Path]:
    seen: dict[str, Path] = {}
    for tmpl in _DIR_GLOB_TEMPLATES:
        for p in derived_root.glob(tmpl.format(ws=ws_name)):
            if p.is_dir():
                seen[str(p)] = p
    # CANONICAL sidecar dirs: `python3 tools/hunt-sidecar-bridge.py --workspace <ws>` writes per-fn hunt records
    # to <ws>/.auditooor/hunt_findings_sidecars/ (bodypack_*.json). The name-keyed
    # templates above miss it, which read as a false HUNT NO-RECORDS. Include it +
    # any sibling *sidecar* dir under <ws>/.auditooor so the gate sees the real hunt.
    if ws_path:
        adir = Path(ws_path) / ".auditooor"
        cand = [adir / "hunt_findings_sidecars"]
        try:
            cand += [p for p in adir.glob("*sidecar*") if p.is_dir()]
            cand += [p for p in adir.glob("haiku_harness*") if p.is_dir()]
        except OSError:
            pass
        for p in cand:
            if p.is_dir() and any(p.glob("*.json")):
                seen[str(p)] = p
    return sorted(seen.values())


def scan_dir(d: Path) -> dict[str, Any]:
    counts = {"success": 0, "failed": 0, "rate_limited": 0, "empty": 0, "engaged": 0}
    anchored_files: set[str] = set()
    unit_best: dict[str, str] = {}
    total = 0
    for f in sorted(d.glob("*.json")):
        try:
            rec = json.loads(f.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            continue
        if not isinstance(rec, dict):
            continue
        total += 1
        klass, file_ref = classify_record(rec)
        counts[klass] += 1
        if klass == "success" and file_ref:
            anchored_files.add(file_ref)
        u = _unit_key(rec)
        if u and _KLASS_RANK.get(klass, 0) > _KLASS_RANK.get(unit_best.get(u, ""), -1):
            unit_best[u] = klass
    return {
        "dir": d.name,
        "total_records": total,
        "counts": counts,
        "distinct_anchored_files": sorted(anchored_files),
        "unit_best": unit_best,
    }


def verdict_for(total: int, success: int, engaged: int = 0,
                distinct_units: int = 0, units_engaged: int = 0,
                units_success: int = 0) -> str:
    if total == 0:
        return "no-records"
    # PER-UNIT trust (preferred when function anchors are resolvable): a unit
    # (file::function) is trustworthy if ANY of its records is success/engaged.
    # This stops a REDUNDANT failed/empty dispatch run (e.g. a dead provider that
    # halted on a missing API key) from condemning units that ANOTHER provider
    # already hunted with a real verdict. Record-based ran_frac double-penalizes
    # such units. Strata 2026-07-01: 318 halted-mimo records over 135 functions,
    # ALL 135 also carrying a real Sonnet verdict -> per-record ran_frac=0.18
    # (degraded) but per-unit ran_frac=1.0 (healthy-clean), which is the truth
    # (function-coverage independently = 135/135). Falls back to record-based when
    # no unit anchors are resolvable, so legacy behavior is unchanged.
    # RECORD-LEVEL reasoned-success (fraction of ALL hunt records that anchored a
    # real FINDING). This - NOT unit-engagement - is what keys the strong
    # "healthy" verdict. A per-unit best-record rollup can read high engagement
    # while almost every record produced no finding (axelar-dlt/nuva 2026-07-13:
    # unit_engaged_fraction ~0.82 while success_fraction ~0.037). Load-bearing.
    record_success_fraction = success / total
    if distinct_units > 0:
        u_ran = units_engaged / distinct_units
        u_find = units_success / distinct_units
        if distinct_units < FAILED_RUN_MIN_RECORDS and units_engaged == 0:
            return "insufficient-data"
        if u_ran <= FAILED_RUN_SUCCESS_FRACTION and distinct_units >= FAILED_RUN_MIN_RECORDS:
            return "failed-run"
        # "healthy" (STRONG: the hunt anchored real findings across the surface)
        # requires BOTH a per-unit find-rate AND the RECORD-LEVEL reasoned-success
        # to clear their floors. unit_engaged_fraction alone can NOT buy a
        # "healthy" badge for a 0-finding audit; such an audit lands at the honest
        # "healthy-clean" (engaged + clean, still certifies) below.
        if u_find >= HEALTHY_SUCCESS_FRACTION and \
                record_success_fraction >= REASONED_SUCCESS_FRACTION:
            return "healthy"
        if u_ran >= HEALTHY_SUCCESS_FRACTION:
            return "healthy-clean"
        return "degraded"
    find_frac = record_success_fraction
    # "ran" = the model mechanically engaged the function: it either anchored a
    # finding (success) or returned an explicit applies_to_target verdict
    # (engaged). A hunt that engaged the surface is TRUSTWORTHY coverage even
    # when it anchors few/no findings - that is what a clean 0-finding audit
    # looks like. failed-run is reserved for hunts that did NOT mechanically
    # run (rate-limited / empty / garbage results), not hunts that ran clean.
    ran = success + engaged
    ran_frac = ran / total
    if total < FAILED_RUN_MIN_RECORDS and ran == 0:
        return "insufficient-data"
    # Genuine silent-failure: the surface was barely engaged at all.
    if ran_frac <= FAILED_RUN_SUCCESS_FRACTION and total >= FAILED_RUN_MIN_RECORDS:
        return "failed-run"
    # Strong find-rate -> healthy. find_frac IS the record-level reasoned-success
    # here, so this branch is already keyed on reasoned-success (belt-and-braces
    # with the explicit floor for the env-tunable case where the two differ).
    if find_frac >= HEALTHY_SUCCESS_FRACTION and find_frac >= REASONED_SUCCESS_FRACTION:
        return "healthy"
    # Engaged the surface but anchored few/no findings: a trustworthy clean /
    # low-yield run. NOT failed-run - the model processed the functions.
    if ran_frac >= HEALTHY_SUCCESS_FRACTION:
        return "healthy-clean"
    return "degraded"


def build_report(derived_root: Path, ws_name: str, ws_path: str) -> dict[str, Any]:
    dirs = find_hunt_dirs(derived_root, ws_name, ws_path)
    per_dir = [scan_dir(d) for d in dirs]
    total = sum(x["total_records"] for x in per_dir)
    success = sum(x["counts"]["success"] for x in per_dir)
    failed = sum(x["counts"]["failed"] for x in per_dir)
    rate_limited = sum(x["counts"]["rate_limited"] for x in per_dir)
    empty = sum(x["counts"]["empty"] for x in per_dir)
    engaged = sum(x["counts"].get("engaged", 0) for x in per_dir)
    anchored_files: set[str] = set()
    for x in per_dir:
        anchored_files.update(x["distinct_anchored_files"])

    # Per-UNIT rollup: merge each dir's best-verdict-per-unit, taking the strongest
    # class seen for a unit across ALL dirs/providers (a Sonnet success beats a
    # halted-mimo empty for the same function).
    unit_best: dict[str, str] = {}
    for x in per_dir:
        for u, k in (x.get("unit_best") or {}).items():
            if _KLASS_RANK.get(k, 0) > _KLASS_RANK.get(unit_best.get(u, ""), -1):
                unit_best[u] = k
    distinct_units = len(unit_best)
    units_success = sum(1 for k in unit_best.values() if k == "success")
    units_engaged = sum(1 for k in unit_best.values() if k in ("success", "engaged"))

    success_fraction = round(success / total, 4) if total else 0.0
    engaged_fraction = round((success + engaged) / total, 4) if total else 0.0
    unit_engaged_fraction = round(units_engaged / distinct_units, 4) if distinct_units else 0.0
    verdict = verdict_for(total, success, engaged,
                          distinct_units=distinct_units,
                          units_engaged=units_engaged,
                          units_success=units_success)

    payload: dict[str, Any] = {
        "schema": SCHEMA,
        "kind": "hunt_run_health",
        "workspace": ws_path,
        "ws_name": ws_name,
        "hunt_dirs_scanned": [d.name for d in dirs],
        "total_records": total,
        "success": success,
        "failed": failed,
        "rate_limited": rate_limited,
        "empty_or_unanchored": empty,
        "engaged_clean": engaged,
        "success_fraction": success_fraction,
        "engaged_fraction": engaged_fraction,
        "distinct_units": distinct_units,
        "units_success": units_success,
        "units_engaged": units_engaged,
        # unit_engaged_fraction is REPORTED for context but is deliberately NOT
        # load-bearing for the strong "healthy" verdict (see verdict_for): a
        # per-unit best-record rollup can read high while record-level
        # reasoned-success is near-zero.
        "unit_engaged_fraction": unit_engaged_fraction,
        "verdict_keyed_on": "record_level_reasoned_success (success_fraction)",
        "distinct_anchored_files": len(anchored_files),
        "thresholds": {
            "failed_run_success_fraction": FAILED_RUN_SUCCESS_FRACTION,
            "failed_run_min_records": FAILED_RUN_MIN_RECORDS,
            "healthy_success_fraction": HEALTHY_SUCCESS_FRACTION,
            "reasoned_success_fraction": REASONED_SUCCESS_FRACTION,
        },
        "verdict": verdict,
        "needs_re_hunt": verdict == "failed-run",
        "per_dir": per_dir,
    }
    digest = hashlib.sha256(
        json.dumps(payload, sort_keys=True).encode("utf-8")
    ).hexdigest()
    return {
        "context_pack_id": f"{SCHEMA}:{digest[:16]}",
        "context_pack_hash": digest,
        **payload,
    }


WIRE_NOTE = """\
RECOMMENDED vault_mining_health WIRE (for the orchestrator; do NOT let a worker
edit tools/vault-mcp-server.py - it is shared/sensitive):

Inside HunterVault.vault_mining_health(), after computing hallucination_count,
add a hunt_run_health sub-block by importing the build_report() function from
this tool (or shelling out to it with --workspace <ws> --json) and embedding:

    from importlib import import_module  # or subprocess to hunt-run-health-check.py
    hrh = build_report(self.repo_root / "audit/corpus_tags/derived",
                       ws_name, workspace)
    payload["hunt_run_health"] = {
        "total_records": hrh["total_records"],
        "success": hrh["success"],
        "rate_limited": hrh["rate_limited"],
        "success_fraction": hrh["success_fraction"],
        "verdict": hrh["verdict"],
        "needs_re_hunt": hrh["needs_re_hunt"],
    }

This makes vault_mining_health surface "this workspace's last hunt was
rate-limited - re-hunt before trusting coverage" alongside the existing
hallucination / coverage / dead-end signals. Bump the schema to
auditooor.vault_mining_health.v2 when wired.
"""


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="HUNT-RUN-HEALTH detector")
    ap.add_argument("--workspace", help="workspace path or name")
    ap.add_argument(
        "--all-workspaces",
        action="store_true",
        help="scan every workspace under --audits-root",
    )
    ap.add_argument(
        "--audits-root",
        default=str(Path.home() / "audits"),
        help="root of audit workspaces (default ~/audits)",
    )
    ap.add_argument(
        "--derived-root",
        default=None,
        help="override the corpus derived dir "
        "(default <repo>/audit/corpus_tags/derived)",
    )
    ap.add_argument("--json", action="store_true", help="emit JSON")
    ap.add_argument(
        "--wire-note",
        action="store_true",
        help="print the recommended vault_mining_health wire and exit",
    )
    args = ap.parse_args(argv)

    if args.wire_note:
        print(WIRE_NOTE)
        return 0

    repo_root = Path(__file__).resolve().parents[1]
    derived_root = (
        Path(args.derived_root)
        if args.derived_root
        else repo_root / "audit" / "corpus_tags" / "derived"
    )

    targets: list[tuple[str, str]] = []  # (ws_name, ws_path)
    if args.all_workspaces:
        audits = Path(args.audits_root)
        names: set[str] = set()
        for p in derived_root.glob("mimo_harness_*"):
            if p.is_dir():
                n = p.name[len("mimo_harness_"):]
                # strip common suffixes
                n = re.sub(r"_(full|KEY6|perfn.*|pilot)$", "", n)
                names.add(n)
        for p in derived_root.glob("mega*"):
            if p.is_dir():
                m = re.search(r"mega(?:_perfn)?_([a-z0-9]+)", p.name)
                if m:
                    names.add(m.group(1))
        for n in sorted(names):
            targets.append((n, str(audits / n)))
    elif args.workspace:
        ws_name = Path(args.workspace).name
        targets.append((ws_name, args.workspace))
    else:
        ap.error("provide --workspace <path|name> or --all-workspaces")

    reports = [build_report(derived_root, n, p) for (n, p) in targets]

    if args.json:
        out = reports[0] if len(reports) == 1 else {"reports": reports}
        print(json.dumps(out, indent=2))
        return 0

    rc = 0
    for r in reports:
        flag = "  <-- NEEDS RE-HUNT" if r["needs_re_hunt"] else ""
        print(
            f"[{r['verdict']:>16}] {r['ws_name']:<16} "
            f"records={r['total_records']:<5} "
            f"success={r['success']:<5} "
            f"rate_limited={r['rate_limited']:<5} "
            f"empty={r['empty_or_unanchored']:<5} "
            f"frac={r['success_fraction']:<6} "
            f"anchored_files={r['distinct_anchored_files']}{flag}"
        )
        if r["needs_re_hunt"]:
            rc = 2
    return rc


if __name__ == "__main__":
    sys.exit(main())
