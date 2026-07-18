#!/usr/bin/env python3
# <!-- r36-rebuttal: lane L37-AUDIT-DONE-GUARD registered in .auditooor/agent_pathspec.json -->
"""Canonical mechanical "is this workspace DONE?" judge.

The #1 failure mode is an agent narrating "audited / done / honest 0" before
`make audit-complete WS=<ws> STRICT=1` actually returned `pass-audit-complete`.
This tool is the single source of truth that CLAUDE.md, a Stop hook, and the
universal-action hook (paste-ready promotion) all consult. It does NOT trust
prose; it reads the on-disk audit-complete evidence.

DONE (rc 0) requires BOTH:
  1. `.auditooor/audit_completion.json` (or the L37 marker) shows
     verdict `pass-audit-complete` STRICT, generated recently (<= TTL, default
     6h) - i.e. a FRESH pass in this work session, not a stale one.
  2. EITHER >= 1 file under `submissions/paste_ready/` (a real candidate to
     file) OR an explicit honest-0 marker (`.auditooor/honest_zero.json` with
     all gates green) - paste-ready-or-nothing.

NOT DONE (rc 1) prints the precise reason + the FAIL gates if available.
rc 2 = usage / workspace error.

CLI: python3 tools/audit-done-guard.py <workspace> [--json] [--ttl-hours N]
"""
from __future__ import annotations

import argparse
import json
import os
import re
import sys
import time
from pathlib import Path

_MARKER_CANDIDATES = (
    ".auditooor/audit_completion.json",
    ".audit_logs/audit_completion.json",
    ".auditooor/audit_complete_last_result.json",
)
# audit_complete_last_result.json is the file written by audit-completeness-check.py
# (the gate tool itself). It is the authoritative marker: prefer it unconditionally
# over older marker candidates so a stale pass in another marker cannot outrank a
# fresh fail that the gate recomputed.
_AUTHORITATIVE_MARKER_REL = ".auditooor/audit_complete_last_result.json"
_PASS_TOKENS = ("pass-audit-complete",)


def _load_json(p: Path):
    try:
        return json.loads(p.read_text(encoding="utf-8", errors="replace"))
    except (OSError, ValueError):
        return None


def _mtime(p: Path) -> float:
    try:
        return p.stat().st_mtime
    except OSError:
        return 0.0


def _find_marker(ws: Path):
    # r36-rebuttal: lane L37-AUDIT-DONE-GUARD registered in .auditooor/agent_pathspec.json
    # Pick the first candidate that actually CARRIES a verdict - some workspaces
    # also have a `.audit_logs/audit_completion.json` that is a toolchain-hash
    # record with no verdict field; returning that (just because it exists first)
    # would mask the real verdict marker. Among verdict-bearing markers prefer
    # the freshest. Fall back to the first existing file if none carries a verdict.
    #
    # STALE-MARKER PRIORITY: audit_complete_last_result.json is the file written by
    # audit-completeness-check.py (the gate tool itself) and is the authoritative
    # marker. When it exists and carries a verdict, prefer it unconditionally over
    # all other candidates regardless of mtime - a stale pass in another marker
    # file must NOT outrank a fresh recomputed verdict from the gate.
    authoritative = ws / _AUTHORITATIVE_MARKER_REL
    if authoritative.is_file():
        blob = _verdict_blob(_load_json(authoritative))
        if blob.strip():
            return authoritative

    verdict_bearing = []
    existing = []
    for rel in _MARKER_CANDIDATES:
        p = ws / rel
        if not p.is_file():
            continue
        existing.append(p)
        blob = _verdict_blob(_load_json(p))
        if blob.strip():
            verdict_bearing.append(p)
    if verdict_bearing:
        return max(verdict_bearing, key=_mtime)
    return existing[0] if existing else None


def _verdict_blob(obj) -> str:
    # STALE-MARKER FIX: do NOT include "l37_verdict" here. That field appears in
    # production_pipeline_manifest.json as a cached copy of the L37 verdict at the
    # time the pipeline manifest was last written - it can be stale. Including it
    # allowed a stale l37_verdict="pass-audit-complete" to be treated as a pass
    # even when the authoritative "verdict" field was a fail. Only "verdict" and
    # its direct synonyms used by legacy marker schemas are accepted.
    if isinstance(obj, dict):
        return " ".join(str(obj.get(k) or "") for k in
                        ("verdict", "status", "result", "audit_complete_verdict",
                         "overall")).lower()
    return str(obj or "").lower()


def _fail_gates(obj) -> list:
    if not isinstance(obj, dict):
        return []
    out = []
    for key in ("fail_gates", "failed_signals", "failures", "fail"):
        v = obj.get(key)
        if isinstance(v, list):
            out.extend(str(x) for x in v)
    sigs = obj.get("signals") or obj.get("gates")
    if isinstance(sigs, list):
        for s in sigs:
            if isinstance(s, dict) and str(s.get("verdict") or s.get("status") or "").lower().startswith("fail"):
                out.append(str(s.get("name") or s.get("signal") or s.get("id") or "?"))
    return out


def _load_dead_end_ledger_lib():
    """Load dead-end-ledger.py as a module (it carries the canonical ruled-out
    classifier + sidecar globs). Returns the module or None on any error."""
    import importlib.util as _ilu
    p = Path(__file__).resolve().with_name("dead-end-ledger.py")
    spec = _ilu.spec_from_file_location("_del_done", str(p))
    mod = _ilu.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def _current_capability_set_hash():
    """The live capability_set_hash (T1), or None on any error. Delegates to the
    ONE shared source in capability-wiring-integrity-check so this re-computation
    matches the hash the gate stamped into the marker byte-for-byte. None =>
    cannot verify => the caller grandfathers (never a spurious stale)."""
    try:
        import importlib.util as _ilu
        p = Path(__file__).resolve().with_name("capability-wiring-integrity-check.py")
        spec = _ilu.spec_from_file_location("_capset_done", str(p))
        if spec is None or spec.loader is None:
            return None
        mod = _ilu.module_from_spec(spec)
        spec.loader.exec_module(mod)
        fn = getattr(mod, "current_capability_set_hash", None)
        if fn is None:
            return None
        return fn()
    except Exception:
        return None


def _count_ruled_out_verdicts(ws: Path) -> int:
    """Ruled-out/OOS verdict rows on disk for this ws, via the shared dead-end
    classifier (hunt_findings_sidecars/*.jsonl + depth_probes*/*.jsonl)."""
    mod = _load_dead_end_ledger_lib()
    n = 0
    for src in mod._source_files(ws):
        for raw in mod._iter_jsonl(src):
            if mod._is_ruled_out(raw):
                n += 1
    return n


def _count_banked_dead_ends(ws: Path) -> int:
    """Rows in the known-dead-ends store attributable to this workspace.

    Two stores count: the repo-root reports/known_dead_ends.jsonl (filtered to
    this ws via its `workspace` field, which is recorded as either the ws name
    or its full path) and the per-ws <ws>/.auditooor/known_dead_ends.jsonl
    (entirely this ws). A dead_end_ledger.jsonl (the per-ws unified ledger that
    dead-end-ledger.py writes) also counts as banked.
    """
    ws_name = ws.name
    ws_str = str(ws)
    n = 0
    # repo-root global store, filtered to this ws
    try:
        repo_root = Path(__file__).resolve().parents[1]
        global_store = repo_root / "reports" / "known_dead_ends.jsonl"
        if global_store.is_file():
            for line in global_store.read_text(encoding="utf-8", errors="replace").splitlines():
                line = line.strip()
                if not line:
                    continue
                try:
                    obj = json.loads(line)
                except ValueError:
                    continue
                if not isinstance(obj, dict):
                    continue
                w = str(obj.get("workspace", ""))
                if w == ws_name or w == ws_str or Path(w).name == ws_name:
                    n += 1
    except Exception:
        pass
    # per-ws stores (everything in them is this ws by construction)
    for rel in (".auditooor/known_dead_ends.jsonl", ".auditooor/dead_end_ledger.jsonl"):
        p = ws / rel
        if not p.is_file():
            continue
        try:
            for line in p.read_text(encoding="utf-8", errors="replace").splitlines():
                if line.strip():
                    n += 1
        except Exception:
            pass
    return n


# r36-rebuttal: lane FIX-F2-DONE-GATE registered in .auditooor/agent_pathspec.json
# F2 E2.2: mirror the audit-completeness-check open-obligation check here so the
# un-fakeable guard fails-closed on the OPEN hacker-Q backlog. An obligation is
# genuinely resolved only when it carries a terminal state AND an R76-verified
# per-question verdict sidecar (a hand-written state=resolved with no sidecar
# counts as OPEN). The guard RECOMPUTES this rather than trusting any written
# status, mirroring how it recomputes the honest-0 via honest-zero-verify.
_OBLIGATION_TERMINAL_STATES = frozenset(
    {"resolved", "closed", "answered", "killed", "promoted_to_chain", "promoted_to_poc"}
)


def _read_obligations_jsonl(ws: Path) -> list[dict]:
    """Read .auditooor/hacker_question_obligations.jsonl -> list of row dicts.
    Returns [] on absence / unreadable / no rows (fail-open: no debt to gate)."""
    p = ws / ".auditooor" / "hacker_question_obligations.jsonl"
    try:
        txt = p.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return []
    rows: list[dict] = []
    for line in txt.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            obj = json.loads(line)
        except (json.JSONDecodeError, ValueError):
            continue
        if isinstance(obj, dict):
            rows.append(obj)
    return rows


def _verified_sidecar_index(ws: Path):
    """Return (by_qid, by_file_fn) of VERIFIED verdict sidecars via the resolver's
    own index builder so a terminal-status row is only credited when a real
    R76-verified sidecar backs it. On any error returns ({}, {}) - the row-state
    check then stands alone (still honest: terminal rows need a real state)."""
    try:
        import importlib.util as _ilu
        _p = Path(__file__).resolve().with_name("hacker-question-obligation-resolve.py")
        _s = _ilu.spec_from_file_location("_hqor_done", str(_p))
        _m = _ilu.module_from_spec(_s)
        _s.loader.exec_module(_m)
        by_qid, by_file_fn, _acc, _rej = _m._build_sidecar_index(ws, None)
        return by_qid, by_file_fn
    except Exception:
        return {}, {}


def _corpus_hunt_grounded(ws: Path) -> bool:
    """True iff a non-vacuous corpus-driven-hunt ran (corpus_driven_hunt.json with
    >=1 in-target-evidence hypothesis) - the DESIGNED resolution path for ADVISORY
    corpus_mined_finding obligations (their `file` is the corpus artifact, never a
    source unit, so a per-question sidecar can never match). No grounding -> they
    stay OPEN (not a free pass)."""
    p = ws / ".auditooor" / "corpus_driven_hunt.json"
    try:
        d = json.loads(p.read_text(encoding="utf-8", errors="replace"))
    except (OSError, json.JSONDecodeError, ValueError):
        return False
    hyps = d.get("hypotheses") if isinstance(d, dict) else (d if isinstance(d, list) else [])
    if not isinstance(hyps, list):
        return False
    return any(isinstance(h, dict) and h.get("in_target_evidence") for h in hyps)


def _count_open_obligations(ws: Path) -> dict:
    """Return {"open": N, "rows": M, "open_by_language": {...}, "ids": [...]}.

    An obligation is OPEN when its state is non-terminal OR it claims a terminal
    state but has no verified verdict sidecar (un-fakeable). EXCEPTION: an advisory
    corpus_mined_finding obligation is resolved by a non-vacuous corpus-driven-hunt
    (grounding), not a per-question sidecar - counted resolved when the grounding
    ran, OPEN otherwise."""
    rows = _read_obligations_jsonl(ws)
    out = {"open": 0, "rows": len(rows), "open_by_language": {}, "ids": []}
    if not rows:
        return out
    by_qid, by_file_fn = _verified_sidecar_index(ws)
    grounded = _corpus_hunt_grounded(ws)
    for ob in rows:
        state = str(ob.get("state") or ob.get("status") or "open").strip().lower()
        is_terminal = state in _OBLIGATION_TERMINAL_STATES
        oid = str(ob.get("obligation_id", "")).strip()
        f = str(ob.get("file", "")).strip()
        fn = str(ob.get("function_name", "")).strip() or str(ob.get("function_signature", "")).strip()
        # Serving-join parity with audit-completeness-check._obligation_has_verified_sidecar
        # (commits 4913a9be20 + 97bcc917bf): match by obligation_id, then (file, fn) tried
        # EXACT then by BASENAME (the sidecar index keys by_file_fn under (abs,fn)+(basename,fn)
        # and obligations anchor RELATIVE paths while sidecars anchor ABSOLUTE), AND credit a
        # GENUINE per-fn obligation regardless of the lagging `state` field (the pipeline
        # regenerates obligations state=open each run; the verified sidecar IS the resolution).
        # Without this the done-guard counted rows OPEN that audit-complete + the resolver both
        # credited - a false-red divergence blocking done (nuva 2026-07-12: guard 5 open, resolver
        # 0 open). NEVER-FALSE-PASS: only R76-verified sidecars are indexed.
        _base = f.replace("\\", "/").split("/")[-1] if f else ""
        has_sidecar = bool(
            (oid and oid in by_qid)
            or (f and fn and (f, fn) in by_file_fn)
            or (_base and fn and (_base, fn) in by_file_fn)
        )
        _genuine_perfn = (
            not ob.get("advisory_only")
            and str(ob.get("source_kind", "")) not in (
                "corpus_mined_finding", "agent_artifact_lesson_candidate")
        )
        if has_sidecar and (is_terminal or _genuine_perfn):
            continue
        # ADVISORY artifact-derived lessons (corpus_mined_finding AND
        # agent_artifact_lesson_candidate) resolve via the corpus-driven-hunt
        # grounding, never a per-question source sidecar - their `file` is an
        # artifact (.auditooor/*.json), not a source unit. Mirror
        # audit-completeness-check.check_hacker_questions_resolved (near-intents
        # 2026-06-26: 36 agent-artifact lessons were false-open under the
        # corpus_mined_finding-only allowlist). Gated on advisory_only + a non-source
        # artifact file + grounded so a genuine source obligation is never excused.
        _of = f.replace("\\", "/")
        _is_artifact = (
            "/.auditooor/" in _of or _of.startswith("<workspace>")
            or "mined_findings" in _of
            or not re.search(r"\.(rs|sol|go|cairo|move|circom|ts|js|py)$", _of)
        )
        if (ob.get("advisory_only") is True
                and str(ob.get("source_kind", "")) in (
                    "corpus_mined_finding", "agent_artifact_lesson_candidate")
                and _is_artifact and grounded):
            continue
        # NOT-APPLICABLE auto-disposition (serving-join parity with
        # audit-completeness-check.check_hacker_questions_resolved, commit ddca1c1f6f):
        # an obligation auto-resolved by hacker-question-obligation-resolve because its
        # anchored function/file is ABSENT from this workspace (a cross-engagement
        # corpus function-shape mis-anchor, e.g. a dYdX-derived question whose symbol
        # does not exist in NUVA source). It is terminal-by-design and a SOURCE sidecar
        # can NEVER anchor (the code is not here to verify). Without this branch the
        # guard counted such rows OPEN forever while audit-complete already credited
        # them - a false-red divergence between the two readers of the SAME obligations
        # file. NEVER-FALSE-PASS: credited ONLY when the terminal state carries the
        # resolver's documented auto-disposition note (only the resolver writes it, and
        # only for an absent-from-workspace anchor).
        if is_terminal and "auto-resolved not-applicable" in str(ob.get("operator_notes", "")):
            continue
        lang = str(ob.get("language") or "unknown").strip().lower() or "unknown"
        out["open"] += 1
        out["open_by_language"][lang] = out["open_by_language"].get(lang, 0) + 1
        if len(out["ids"]) < 20:
            out["ids"].append(oid or f or "<unknown>")
    return out


def _verdict_feedback_noop(ws: Path, *, min_verdicts: int | None = None) -> dict | None:
    """Detect the feedback-noop state: many ruled-out verdicts on disk, 0 banked.

    Returns a dict {"noop": bool, "ruled_out": int, "banked": int, "threshold": int}
    or None if it cannot be computed (caller fail-opens). noop is True ONLY when
    ruled_out >= threshold AND banked == 0 - below threshold or >= 1 banked passes.
    """
    if min_verdicts is None:
        try:
            min_verdicts = int(os.environ.get("AUDIT_DONE_VERDICT_NOOP_MIN", "50"))
        except ValueError:
            min_verdicts = 50
    ruled_out = _count_ruled_out_verdicts(ws)
    banked = _count_banked_dead_ends(ws)
    return {
        "noop": ruled_out >= min_verdicts and banked == 0,
        "ruled_out": ruled_out,
        "banked": banked,
        "threshold": min_verdicts,
    }


# ---------------------------------------------------------------------------
# P52: tamper-evident marker verify (ADVISORY) + canary.
#
# ADVISORY-FIRST behind AUDITOOOR_MARKER_TAMPER_STRICT (default OFF). When the
# flag is unset the verify + canary NEVER change `done` / `fail_gates`; they only
# attach a read-only `tamper_advisory` block. Only under the strict env does a
# FORGED_VERDICT / failed-canary set done=false + a fail_gate.
#
# REUSE: the signature primitives live in audit-completion-marker.py
# (compute/verify_marker_signature, _audit_toolchain_hash). We load that module
# by path and call verify_marker_signature - no hashing re-implemented here.
# ---------------------------------------------------------------------------
MARKER_TAMPER_STRICT_ENV = "AUDITOOOR_MARKER_TAMPER_STRICT"
_COMPLETION_MARKER_REL = ".audit_logs/audit_completion.json"


def _load_completion_marker_lib():
    """Load audit-completion-marker.py as a module (hyphenated name). Returns the
    module or None on any error (the caller then fail-opens advisory-clean)."""
    import importlib.util as _ilu
    p = Path(__file__).resolve().with_name("audit-completion-marker.py")
    spec = _ilu.spec_from_file_location("_acm_done", str(p))
    if spec is None or spec.loader is None:
        return None
    mod = _ilu.module_from_spec(spec)
    sys.modules["_acm_done"] = mod
    spec.loader.exec_module(mod)
    return mod


def _tamper_advisory(ws: Path) -> dict:
    """Verify the completion-marker's tamper-signature block ADVISORY and run the
    canary. Returns a dict {"checked", "signed", "verify_ok", "reasons",
    "canary_ok", "self_coverage_ok", "verdict"}. NEVER raises; NEVER blocks -
    the caller decides advisory-vs-strict.

    strict:false on the marker is an HONEST state, not a tamper - the verify does
    not consult the audit-complete strict flag at all; it only checks that the
    signature chain recomputes and (best-effort) that the enforcer_hash has not
    been swapped under a frozen verdict."""
    out = {
        "checked": True,
        "signed": False,
        "verify_ok": None,
        "reasons": [],
        "canary_ok": None,
        "self_coverage_ok": None,
        "verdict": None,
    }
    mod = _load_completion_marker_lib()
    if mod is None:
        out["reasons"] = ["completion-marker-lib-unavailable"]
        out["checked"] = False
        return out

    # --- Canary: a forged-but-plausible signature MUST be caught. We take a
    # legitimately-computed block, mutate a bound input (enforcer_hash) WITHOUT
    # recomputing the chain digest, and assert verify flags it. This exercises
    # the tamper-DETECTION path (not just verdict parsing) so a canary pass means
    # the verifier actually rejects a doctored marker.
    try:
        legit = mod.compute_marker_signature(
            verdict="pass-audit-complete",
            repo_root=Path(__file__).resolve().parents[1],
            toolchain_hash="canary-enforcer",
            toolchain_inventory=[
                {"path": rel, "size": 1, "sha256": "0" * 64}
                for rel in mod._SELF_DEF_FILES
            ],
            workspace_state_hash="canary-ws",
            nonce="canary-nonce",
        )
        # sanity: the legit block itself must verify ok
        legit_v = mod.verify_marker_signature(legit)
        forged = dict(legit)
        forged["enforcer_hash"] = "forged-enforcer"  # edit a bound field, keep digest
        forged_v = mod.verify_marker_signature(forged)
        out["canary_ok"] = bool(legit_v.get("ok") and not forged_v.get("ok"))
        if not out["canary_ok"]:
            out["reasons"].append("canary-did-not-catch-forgery")
    except Exception as exc:
        out["canary_ok"] = False
        out["reasons"].append(f"canary-error:{type(exc).__name__}")

    # --- Real marker verify (ADVISORY). Absent block = unsigned (not a tamper).
    try:
        payload = mod.load_marker(ws)
        sig = payload.get("tamper_signature") if isinstance(payload, dict) else None
        if not isinstance(sig, dict):
            out["signed"] = False
            out["reasons"].append("marker-unsigned")
            return out
        out["signed"] = True
        cur_enforcer, _inv = mod._audit_toolchain_hash(
            Path(__file__).resolve().parents[1]
        )
        v = mod.verify_marker_signature(sig, current_enforcer_hash=cur_enforcer)
        out["verify_ok"] = bool(v.get("ok"))
        out["self_coverage_ok"] = bool(v.get("self_coverage_ok"))
        out["verdict"] = v.get("verdict")
        out["reasons"].extend(v.get("reasons", []))
    except Exception as exc:
        out["reasons"].append(f"verify-error:{type(exc).__name__}")
        out["checked"] = False
    return out


def _marker_tamper_warning(tv: dict) -> dict | None:
    """Pure decision (ADVISORY-FIRST surfacing): given a tamper_advisory block,
    return a loud warning dict when the marker shows a GENUINE tamper - a SIGNED
    marker that failed verification (FORGED_VERDICT), or a broken canary (the
    tamper-detector itself is not catching forgery). Returns None otherwise.

    An UNSIGNED / absent / legacy marker is NOT a tamper and yields None, so this
    never fires on a parked audit that simply predates marker signing. This is the
    default-mode (flag-unset) surfacing so the #1 sin - a hand-edited marker - is
    never silent even when the hard-block env is off."""
    reasons: list[str] = []
    if tv.get("signed") and tv.get("verify_ok") is False:
        reasons.append("FORGED_VERDICT (signed marker failed verification)")
    if tv.get("canary_ok") is False:
        reasons.append("marker-canary-broken (tamper-detector not catching forgery)")
    if not reasons:
        return None
    return {
        "reasons": reasons,
        "signature_reasons": tv.get("reasons"),
        "note": ("ADVISORY (not blocking): set AUDITOOOR_MARKER_TAMPER_STRICT=1 to "
                 "hard-fail; re-run `make audit-complete WS=<ws> STRICT=1` to "
                 "regenerate a correctly-signed completion marker"),
    }


def _tamper_strict_verdict(tv: dict, env: dict | None = None) -> tuple[bool, list, str]:
    """Pure decision: given a tamper_advisory block + env, return
    (should_block, fail_gates, reason_suffix). BLOCKS only when
    AUDITOOOR_MARKER_TAMPER_STRICT is set AND (the canary failed OR a SIGNED
    marker failed verification). An UNSIGNED marker never blocks; strict:false is
    not consulted (it is an HONEST audit-complete state, handled earlier). This
    is the single source of truth for the advisory-vs-strict split so it can be
    unit-tested without scaffolding a full DONE-path workspace."""
    if env is None:
        env = dict(os.environ)
    # ADVISORY by default (default-OFF): the graduation to default-ON (2026-07-03) was
    # REVERTED the same day. The enforcer_hash is a content-hash of the ENTIRE toolchain
    # tree (_audit_toolchain_hash over Makefile + all tools + detector fixtures); a
    # `make audit-complete` run writes files INTO that tree, so the hash at marker-WRITE
    # time never stably equals the hash at done-guard VERIFY time on an actively-developed
    # or make-mutated repo -> a legitimately-regenerated marker false-positives as
    # FORGED_VERDICT (enforcer-hash-mismatch). NUVA was the first audit to actually REACH
    # this block (all other L37 gates pass) and exposed it; the parked-audit graduation
    # test missed it because parked audits fail earlier and never reach the marker check.
    # The LOUD advisory surfacing (_marker_tamper_warning) still fires on a genuine forgery;
    # set MARKER_TAMPER_STRICT=1 to opt IN to the hard block on a frozen toolchain.
    if env.get(MARKER_TAMPER_STRICT_ENV, "").strip().lower() not in ("1", "true", "yes", "on"):
        return False, [], ""
    why: list[str] = []
    if tv.get("canary_ok") is False:
        why.append("canary-failed")
    if tv.get("signed") and tv.get("verify_ok") is False:
        why.append("FORGED_VERDICT")
    if not why:
        return False, [], ""
    gates = (["fail-marker-forged-verdict"] if "FORGED_VERDICT" in why
             else ["fail-marker-canary"])
    reason = (
        "marker tamper-evidence FAIL (STRICT): "
        f"{', '.join(why)} - signature reasons: {tv.get('reasons')}; "
        "re-run `make audit-complete WS=<ws> STRICT=1` to regenerate a "
        "correctly-signed completion marker (or unset "
        f"{MARKER_TAMPER_STRICT_ENV} to treat as advisory)"
    )
    return True, gates, reason


def evaluate(ws: Path, ttl_hours: float = 6.0, *, now: float | None = None) -> dict:
    now = now if now is not None else time.time()
    res = {"workspace": str(ws), "done": False, "reason": "", "fail_gates": []}
    if not ws.is_dir():
        res["reason"] = f"workspace not found: {ws}"
        return res

    marker = _find_marker(ws)
    if marker is None:
        res["reason"] = ("no audit-complete marker found - run "
                         "`make audit-complete WS=<ws> STRICT=1` first")
        return res
    obj = _load_json(marker)
    blob = _verdict_blob(obj)
    if not any(t in blob for t in _PASS_TOKENS):
        res["reason"] = f"audit-complete marker is NOT pass-audit-complete ({marker.name})"
        res["fail_gates"] = _fail_gates(obj)
        return res
    # strict flag, if recorded, must be truthy
    if isinstance(obj, dict):
        strict = obj.get("strict")
        if strict is not None and str(strict).lower() in ("0", "false", "no", "none"):
            res["reason"] = "audit-complete passed but NOT under STRICT=1"
            return res
    age_h = (now - _mtime(marker)) / 3600.0
    if ttl_hours and age_h > ttl_hours:
        res["reason"] = (f"audit-complete pass is STALE ({age_h:.1f}h > {ttl_hours}h TTL); "
                         "re-run `make audit-complete STRICT=1` this session")
        return res

    # T1: stale-done-on-capability-set-hash-change. A pass is only trustworthy
    # relative to the capability set that PRODUCED it - once new detectors/screens
    # are wired, that pass never had a chance to surface what the new caps find,
    # so it must be re-confirmed. The marker stamps the hash it was produced under
    # (see audit-completeness-check._live_capability_set_hash); here we re-compare.
    #   - marker has no hash (legacy pass, or unreadable inventory) => grandfather,
    #     never a spurious stale (advisory-first; cannot-verify != stale).
    #   - hash present AND differs from the live set => STALE, but only hard-fail
    #     under AUDITOOOR_CAPSET_STALENESS_STRICT=1 (opt-in ramp, symmetric with
    #     the needs-llm-depth strict flag). Otherwise surface a soft warning and
    #     continue, so shipping this does not flip the whole parked fleet at once.
    if isinstance(obj, dict):
        marker_hash = obj.get("capability_set_hash")
        if marker_hash:
            current_hash = _current_capability_set_hash()
            if current_hash and current_hash != marker_hash:
                res["capset_stale_warn"] = (
                    f"capability set changed since this pass "
                    f"(marker={str(marker_hash)[:12]} != live={str(current_hash)[:12]}); "
                    "re-run `make audit-complete STRICT=1` so new capabilities hunt this workspace")
                if os.environ.get("AUDITOOOR_CAPSET_STALENESS_STRICT") == "1":
                    res["reason"] = ("audit-complete pass is STALE against the current capability "
                                     f"set (marker={str(marker_hash)[:12]} != live="
                                     f"{str(current_hash)[:12]}); new capabilities were wired since "
                                     "this pass - re-run `make audit-complete STRICT=1`")
                    return res

    # paste-ready-or-nothing
    pr = ws / "submissions" / "paste_ready"
    pr_files = [p for p in pr.rglob("*") if p.is_file() and p.suffix in (".md", ".sol")] if pr.is_dir() else []
    # A FILED finding (submissions/filed/) is a DELIVERED candidate - strictly STRONGER than a
    # paste_ready one (it passed pre-submit and was submitted upstream). Count it toward
    # paste-ready-or-nothing so a workspace that ALREADY submitted its finding(s) is not forced
    # onto the honest-0 path (which would wrongly demand >=3 real-CUT economic invariants / deep
    # fuzz for a workspace that DID find + file a real bug). Operator-observed 2026-07-06, SEI:
    # audit-complete passed + 1 filed Medium (evmrpc DoS) but the guard defaulted to honest-0
    # because paste_ready/ was empty after the finding moved to filed/.
    filed_dir = ws / "submissions" / "filed"
    filed_files = ([p for p in filed_dir.rglob("*") if p.is_file() and p.suffix in (".md", ".sol")]
                   if filed_dir.is_dir() else [])
    pr_files = pr_files + filed_files
    # r36-rebuttal: lane FIX-HONEST-ZERO-VERIFY registered in .auditooor/agent_pathspec.json
    # An honest-0 is NOT a hand-writeable file: RECOMPUTE it from real evidence
    # via honest-zero-verify so a static honest_zero.json cannot fake "done".
    honest_zero_ok = False
    honest_zero_reason = "no paste_ready and honest-0 not checked"
    if not pr_files:
        try:
            import importlib.util as _ilu
            _p = Path(__file__).resolve().with_name("honest-zero-verify.py")
            _s = _ilu.spec_from_file_location("_hzv_done", str(_p))
            _m = _ilu.module_from_spec(_s)
            _s.loader.exec_module(_m)
            _hz = _m.verify(ws, ttl_hours=ttl_hours)
            honest_zero_ok = bool(_hz.get("ok"))
            honest_zero_reason = _hz.get("reason", "")
        except Exception as exc:  # tool missing/error => cannot certify a 0
            honest_zero_ok = False
            honest_zero_reason = f"honest-zero-verify unavailable: {exc}"
    if not pr_files and not honest_zero_ok:
        res["reason"] = ("audit-complete passed but NO submissions/paste_ready/* and the "
                         f"honest-0 is NOT verifiable from evidence ({honest_zero_reason})")
        return res

    # Hunt-verdict persistence: a hunt workflow that ran but whose verdicts were
    # never sunk into canonical hunt_findings_sidecars (an unresolved obligation)
    # means genuine coverage is missing from the gates + the learning loop. Block
    # the done claim until tools/verdict-sink.py has been run on every such run.
    try:
        import importlib.util as _ilu2
        _pg = Path(__file__).resolve().with_name("hunt-verdict-persistence-gate.py")
        _s2 = _ilu2.spec_from_file_location("_hvpg_done", str(_pg))
        _m2 = _ilu2.module_from_spec(_s2)
        _s2.loader.exec_module(_m2)
        _opens = _m2.open_obligations(str(ws))
        if _opens:
            res["reason"] = ("un-sunk hunt-workflow verdicts for this workspace ("
                             f"{len(_opens)} open run(s): {[o.get('run_id') for o in _opens]}); "
                             "run tools/verdict-sink.py --journal <run>/journal.jsonl on each before "
                             "claiming done")
            res["fail_gates"] = [f"unsunk-verdicts:{o.get('run_id')}" for o in _opens]
            return res
    except Exception:
        pass  # gate unavailable -> fail-open (do not brick done on a tool error)

    # r36-rebuttal: lane FIX-F2-DONE-GATE registered in .auditooor/agent_pathspec.json
    # Open-hacker-Q-obligation gate (F2 E2.2): a per-fn hacker-question hunt that
    # emitted obligations but never drove them to a terminal, sidecar-backed verdict
    # means the genuine per-fn coverage is missing from the gates + learning loop -
    # exactly the un-sunk-verdict failure mode above, in the hacker-Q lane. Block
    # the done claim while ANY obligation is open (state non-terminal OR terminal-
    # without-verified-sidecar). Absence / 0 rows -> fail-open (no debt to gate).
    # Recomputed here (not read from a written status) so a hand-edited
    # state=resolved cannot fake done. Sits with the un-sunk-verdict gate (the two
    # hunt-coverage-missing gates) ahead of the README-conformance / step-integrity
    # gates so an OPEN backlog surfaces as the precise reason.
    try:
        _obl = _count_open_obligations(ws)
        if _obl.get("open", 0) > 0:
            _lang = ", ".join(f"{k}={v}" for k, v in sorted(_obl["open_by_language"].items()))
            res["reason"] = (
                "open hacker-question obligations FAIL: "
                f"{_obl['open']} of {_obl['rows']} obligation(s) still OPEN (no terminal "
                f"verified verdict sidecar) by language: {_lang}; run "
                "`python3 tools/hacker-question-obligation-resolve.py --workspace "
                f"{ws}` after a real per-fn hunt produces verdict sidecars before "
                "claiming done"
            )
            res["fail_gates"] = [f"open-hacker-questions:{i}" for i in _obl["ids"]] or [
                f"open-hacker-questions:{_obl['open']}-open"
            ]
            res["open_hacker_questions_detail"] = _obl
            return res
    except Exception:
        pass  # cannot count -> fail-open (do not brick done on a tool error)

    # README runbook conformance gate.  This call is always strict so a text
    # waiver can never certify DONE.  Missing, broken, malformed, and non-pass
    # checker results are all hard failures with explicit machine-readable gates.
    import importlib.util as _ilu3
    _pc = Path(__file__).resolve().with_name("readme-conformance-check.py")
    if not _pc.is_file():
        res["reason"] = f"README runbook conformance checker missing: {_pc}"
        res["fail_gates"] = ["readme-conformance-checker-missing"]
        return res
    try:
        _s3 = _ilu3.spec_from_file_location("_rcc_done", str(_pc))
        if _s3 is None or _s3.loader is None:
            raise ImportError(f"cannot load conformance checker: {_pc}")
        _m3 = _ilu3.module_from_spec(_s3)
        _s3.loader.exec_module(_m3)
        _conf = _m3.evaluate(ws, strict=True)
    except Exception as exc:
        _gate = f"readme-conformance-engine-error:{type(exc).__name__}"
        res["reason"] = f"README runbook conformance checker error: {exc}"
        res["fail_gates"] = [_gate]
        res["conformance_detail"] = {
            "conformance_pass": False,
            "diagnostics": [f"{type(exc).__name__}: {exc}"],
            "fail_gates": [_gate],
        }
        return res

    if (
        not isinstance(_conf, dict)
        or type(_conf.get("conformance_pass")) is not bool
        or not isinstance(_conf.get("red_step_ids"), list)
        or not isinstance(_conf.get("steps"), list)
    ):
        res["reason"] = "README runbook conformance checker returned a malformed result"
        res["fail_gates"] = ["readme-conformance-malformed-result"]
        res["conformance_detail"] = _conf
        return res

    res["conformance_detail"] = _conf
    if not _conf["conformance_pass"]:
        _red = _conf["red_step_ids"]
        _gates = list(_conf.get("fail_gates", []))
        _gates.extend(f"readme-conformance:{sid}" for sid in _red)
        if not _gates:
            _gates.append("readme-conformance:non-pass")
        res["reason"] = (
            f"README runbook conformance FAIL: {len(_red)} applicable step(s) RED "
            f"({_red}); run `python3 tools/readme-conformance-check.py {ws} --strict` "
            "for per-step detail and complete the failing steps"
        )
        res["fail_gates"] = sorted(set(_gates))
        return res

    # Skipped-test disposition gate: the discovery scanner mines the project's
    # OWN skipped/disabled tests (t.Skip / #[ignore] / it.skip / vm.skip) as
    # developer-confessed seeds; this gate enforces that every such seed was
    # carried into the per-function hunt or explicitly rebutted. Absence of the
    # scan artifact is a fail (silent-0 != clean), and any undisposed seed blocks
    # the done claim. Fail-open on a tool import error (a missing tool != a
    # failed gate), fail-closed on a loaded non-pass result - exact mirror of
    # the readme-conformance block above.
    try:
        import importlib.util as _ilu4
        _ps = Path(__file__).resolve().with_name("skipped-test-disposition-gate.py")
        _s4 = _ilu4.spec_from_file_location("_stdg_done", str(_ps))
        _m4 = _ilu4.module_from_spec(_s4)
        _s4.loader.exec_module(_m4)
        _std = _m4.evaluate(ws)
        if not _std.get("conformance_pass", True):
            _open = _std.get("open_rows", [])
            res["reason"] = (
                "skipped-test disposition FAIL: "
                f"{_std.get('verdict')} - "
                f"{_std.get('n_open', len(_open))} undisposed developer-confessed "
                f"skipped test(s); run "
                f"`python3 tools/skipped-test-disposition-gate.py --ws {ws}` for detail "
                "(carry each into the hunt or add a `rebut: <file>:<line>: <reason>` line "
                "to .auditooor/skipped_test_rebuttals.txt)"
            )
            if _open:
                res["fail_gates"] = [
                    f"skipped-test-disposition:{r.get('file')}:{r.get('line')}" for r in _open
                ]
            else:
                res["fail_gates"] = [f"skipped-test-disposition:{_std.get('verdict')}"]
            res["skipped_test_detail"] = _std
            return res
    except Exception:
        pass  # tool unavailable -> fail-open (do not brick done on a missing tool)

    # Incomplete-guard self-acknowledgement gate (Gap B): the IGAL scanner mines
    # in-tree developer-confessed-incompleteness markers (FIXME/TODO/HACK/skip-
    # return) CO-LOCATED with a guard/sink as candidate seeds; this gate enforces
    # that every HIGH-bucket self-acknowledged incomplete guard was dispositioned
    # (filed | not-fileable+reason | igal-rebuttal). This is the exact class that
    # let optimism op-reth engine.rs:135 (a FIXME that `return Ok(())`-skips
    # verify_withdrawals_root_prehashed) fall through every Step-1/2 net. Fail-open
    # on a tool import error; fail-closed on a loaded fail-* verdict.
    try:
        import importlib.util as _ilu5
        _pg = Path(__file__).resolve().with_name("incomplete-guard-ack-gate.py")
        _s5 = _ilu5.spec_from_file_location("_igal_done", str(_pg))
        _m5 = _ilu5.module_from_spec(_s5)
        _s5.loader.exec_module(_m5)
        _igrc, _igp = _m5.evaluate(ws)
        if _igrc != 0:
            _uh = _igp.get("unaddressed_high", [])
            res["reason"] = (
                "incomplete-guard self-acknowledgement FAIL: "
                f"{_igp.get('verdict')} - {_igp.get('high_bucket', len(_uh))} high-bucket "
                "developer-confessed incomplete guard(s) undisposed; run "
                f"`python3 tools/incomplete-guard-ack-gate.py --workspace {ws}` for detail "
                "(file each, mark not-fileable+reason, or add an igal-rebuttal)"
            )
            res["fail_gates"] = (
                [f"incomplete-guard-ack:{r.get('file_line') or r.get('file')}" for r in _uh]
                if _uh else [f"incomplete-guard-ack:{_igp.get('verdict')}"]
            )
            res["incomplete_guard_ack_detail"] = _igp
            return res
    except Exception:
        pass  # tool unavailable -> fail-open (do not brick done on a missing tool)

    # Multi-repo commit-mining coverage gate (Gap A): on a workspace whose
    # scope.json in_scope roots span more than one upstream git repo, the mining
    # step must have covered EVERY in-scope owner/repo (or logged an explicit
    # skip). A silently-unmined repo is a discovery blind spot (no silent caps).
    # Fail-open on import error; fail-closed on a fail-* verdict.
    try:
        import importlib.util as _ilu6
        _pm = Path(__file__).resolve().with_name("multi-repo-mining-coverage-check.py")
        _s6 = _ilu6.spec_from_file_location("_mrmc_done", str(_pm))
        _m6 = _ilu6.module_from_spec(_s6)
        _s6.loader.exec_module(_m6)
        _mrp = _m6.evaluate(ws)
        _mrv = str(_mrp.get("verdict", ""))
        if _mrv.startswith("fail"):
            _unc = _mrp.get("uncovered", [])
            res["reason"] = (
                "multi-repo commit-mining coverage FAIL: "
                f"{_mrv} - in-scope upstream repo(s) unmined: {_unc}; run "
                f"`python3 tools/multi-repo-mining-coverage-check.py --workspace {ws}` for detail"
            )
            res["fail_gates"] = [f"multi-repo-mining-coverage:{r}" for r in _unc] or [f"multi-repo-mining-coverage:{_mrv}"]
            res["multi_repo_mining_detail"] = _mrp
            return res
    except Exception:
        pass  # tool unavailable -> fail-open (do not brick done on a missing tool)

    # README step-integrity gate (FULL-vs-DEGRADED): readme-conformance-check
    # (above) only proves a required step is PRESENT/attested - it does NOT prove
    # the step ran in FULL mode. A step can be green-by-presence while it actually
    # ran DEGRADED (the 6-day local-git-only commit-mining miss). readme-step-
    # integrity classifies each canonical step FULL / DEGRADED / SKIPPED / MISSING
    # from its on-disk artifact. Only DEGRADED ("ran but incomplete", e.g. the
    # local-git-only commit-mining miss) BLOCKS done - it is unfinished work.
    # SKIPPED is NOT blocking: it means legitimately-not-applicable (a
    # language/scope-gated step, e.g. scan-rust on a Go workspace, or pin-freshness
    # on a multi-repo RELEASE-pinned scope whose single-repo develop-HEAD model
    # does not apply). Blocking on SKIPPED would false-fail those workspaces.
    # Wire it here so the done-guard notices DEGRADED. Fail-open on a
    # missing/erroring tool (an import error != a degraded step).
    try:
        import importlib.util as _ilu7
        _pi = Path(__file__).resolve().with_name("readme-step-integrity.py")
        _s7 = _ilu7.spec_from_file_location("_rsi_done", str(_pi))
        _m7 = _ilu7.module_from_spec(_s7)
        _s7.loader.exec_module(_m7)
        _rsi_results = []
        for _name, _fn in _m7.STEPS:
            try:
                _status, _reason = _fn(str(ws))
            except Exception as _exc:  # mirror the tool: a probe crash != FULL
                _status, _reason = _m7.DEGRADED, f"probe error: {type(_exc).__name__}: {_exc}"
            _rsi_results.append({"step": _name, "status": _status, "reason": _reason})
        _bad = [r for r in _rsi_results if r["status"] == _m7.DEGRADED]
        if _bad:
            res["reason"] = (
                "README step-integrity FAIL: "
                f"{len(_bad)} required step(s) ran DEGRADED "
                f"({[r['step'] for r in _bad]}); run "
                f"`python3 tools/readme-step-integrity.py --workspace {ws} --strict` "
                "for per-step detail - a degraded step is unfinished work, complete "
                "it (e.g. re-run commit-mining with GH_TOKEN, re-run the hunt) before "
                "claiming done"
            )
            res["fail_gates"] = [
                f"readme-step-integrity:{r['step']}:{r['status']}" for r in _bad
            ]
            res["step_integrity_detail"] = _rsi_results
            return res
    except Exception:
        pass  # tool unavailable -> fail-open (do not brick done on a missing tool)

    # README per-step attestation gate: the conformance + step-integrity gates
    # prove a step PRESENT/attested-thinly and ran in FULL mode - but neither
    # proves the agent actually READ the runbook. This gate forces a FAITHFUL
    # VERBATIM quote of each EXECUTED step's canonical what_must_be_done +
    # how_to_verify_done into .auditooor/readme_step_attestations.jsonl; a missing
    # row OR a reworded paraphrase fails. "Executed" reuses the SAME signal as the
    # conformance gate (a step is executed iff readme-conformance reports it
    # status=='done'), so the gate is BOUNDED: a fresh workspace with zero executed
    # steps never false-fails, and it never weakens an existing gate. Waivable via
    # .auditooor/readme_attestation_rebuttal.md (non-empty reason -> downgrade to
    # warn), mirroring the codified-rules rebuttal pattern. Fail-open on a missing/
    # erroring tool (an import error != a missing attestation), fail-closed on a
    # loaded fail-readme-attestation-missing verdict.
    try:
        import importlib.util as _ilu8
        _pa = Path(__file__).resolve().with_name("readme-attestation-check.py")
        _s8 = _ilu8.spec_from_file_location("_rac_done", str(_pa))
        _m8 = _ilu8.module_from_spec(_s8)
        sys.modules["_rac_done"] = _m8  # py3.14: register before exec_module
        _s8.loader.exec_module(_m8)
        _att = _m8.verify(ws)
        # Fail-OPEN on a tool/manifest error: verify() returns
        # attestation_pass=False on an error too, but an error is NOT a missing
        # attestation (e.g. manifest absent) so it must not brick done. Only a
        # real verdict with executed-but-unattested steps fails-closed below.
        if _att.get("error"):
            raise RuntimeError(_att["error"])  # routed to the fail-open except
        if not _att.get("attestation_pass", True):
            _afail = _att.get("failing_step_ids", [])
            res["reason"] = (
                "README per-step attestation FAIL: "
                f"{len(_afail)} executed step(s) lack a faithful verbatim attestation "
                f"({_afail}); run `python3 tools/readme-attestation-check.py --verify "
                f"--ws {ws}` for per-step detail - attest each executed step verbatim "
                "via `python3 tools/readme-attestation-check.py --attest --ws "
                f"{ws} --step <id>` (or add a non-empty waiver to "
                ".auditooor/readme_attestation_rebuttal.md) before claiming done"
            )
            res["fail_gates"] = [f"readme-attestation-missing:{sid}" for sid in _afail] or [
                "fail-readme-attestation-missing"
            ]
            res["readme_attestation_detail"] = _att
            return res
    except Exception:
        pass  # tool unavailable -> fail-open (do not brick done on a missing tool)

    # Manual-step preflight grounding (advisory by default; hard-fails only under
    # AUDITOOOR_MANUAL_STEP_STRICT=1). Complements the attestation-PRESENCE gate
    # above: it verifies each manual step's attestation was preceded by a full-text
    # read-ack (re-forced on README drift) and cites an artifact that exists on
    # disk. Fail-open on a missing/erroring tool.
    try:
        import importlib.util as _ilu9
        _pm = Path(__file__).resolve().with_name("manual-step-preflight.py")
        _s9 = _ilu9.spec_from_file_location("_msp_done", str(_pm))
        _m9 = _ilu9.module_from_spec(_s9)
        sys.modules["_msp_done"] = _m9
        _s9.loader.exec_module(_m9)
        _mani = _m9._load_manifest(None)
        if _mani:
            _msp = _m9.check(ws, _mani)
            res["manual_step_preflight_detail"] = _msp
            if _msp.get("verdict", "").startswith("fail-"):  # only under strict
                res["reason"] = (
                    "Manual-step preflight FAIL (STRICT): "
                    f"{len(_msp.get('findings', []))} manual step attestation(s) are "
                    "ungrounded / not read-acked / drifted; run `python3 tools/"
                    f"manual-step-preflight.py render --ws {ws} --step <id>` then re-attest "
                    "with read_ack + evidence_refs")
                res["fail_gates"] = ["fail-manual-step-ungrounded"]
                return res
    except Exception:
        pass  # tool unavailable -> fail-open

    # Commit-adjudication completeness (advisory by default; hard-fails only under
    # AUDITOOOR_COMMIT_ADJUDICATION_STRICT=1). Backward commit-mining CLASSIFIES
    # security-shaped commits into commit_lifecycle_ledger.json lanes_residual, but
    # nothing forced those touching an IN-SCOPE file to a terminal adjudication
    # (FINDING/COMPLETE/OOS) - strata passed honest-0 with 32 un-adjudicated. This
    # closes that false-green. Fail-open on a missing/erroring tool or absent ledger.
    try:
        import importlib.util as _ilu10
        _pc = Path(__file__).resolve().with_name("commit-adjudication-completeness-check.py")
        _s10 = _ilu10.spec_from_file_location("_caj_done", str(_pc))
        _m10 = _ilu10.module_from_spec(_s10)
        sys.modules["_caj_done"] = _m10
        _s10.loader.exec_module(_m10)
        _caj = _m10.check(ws)
        res["commit_adjudication_detail"] = _caj
        if _caj.get("verdict", "").startswith("fail-") and _m10._rebuttal(ws) is None:
            res["reason"] = (
                "Commit-adjudication INCOMPLETE (STRICT): "
                f"{len(_caj.get('violations', []))} security-shaped in-scope commit(s) were "
                "classified by backward mining but never adjudicated to a terminal verdict; run "
                f"`python3 tools/commit-adjudication-completeness-check.py --ws {ws}` and record "
                "each in .auditooor/commit_adjudications.jsonl (verdict=finding|complete|oos)")
            res["fail_gates"] = ["fail-commit-adjudication-incomplete"]
            return res
    except Exception:
        pass  # tool unavailable / no ledger -> fail-open

    # Fuzz-target-worklist completeness (advisory by default; hard-fails only under
    # AUDITOOOR_FUZZ_TARGET_STRICT=1). The fuzz-target corpus emitter produced
    # run-RESULT rows but nothing enumerated which in-scope value-moving assets still
    # NEED a campaign - the worklist (<ws>/.auditooor/fuzz_targets.jsonl, built by
    # `fuzz-target-corpus.py --from-inscope`) was orphaned. This consumer fails on any
    # worklist row without a terminal verdict (a fuzz_campaign_receipt.json campaign, an
    # mvc_sidecar mutation-verified harness, or a typed disposition). Fail-open on a
    # missing/erroring tool or absent worklist under non-strict (an import error / a
    # never-built worklist is not a hard done-blocker), fail-closed on a loaded fail-*
    # verdict (only under the strict env). Mirrors the commit-adjudication block above.
    try:
        import importlib.util as _ilu11
        _pf = Path(__file__).resolve().with_name("fuzz-target-completeness-check.py")
        _s11 = _ilu11.spec_from_file_location("_ftc_done", str(_pf))
        _m11 = _ilu11.module_from_spec(_s11)
        sys.modules["_ftc_done"] = _m11
        _s11.loader.exec_module(_m11)
        _ftc = _m11.check(ws)
        res["fuzz_target_completeness_detail"] = _ftc
        if str(_ftc.get("verdict", "")).startswith("fail-") and _m11._rebuttal(ws) is None:
            _fopen = _ftc.get("open", [])
            res["reason"] = (
                "Fuzz-target-worklist INCOMPLETE (STRICT): "
                f"{len(_fopen)} value-moving in-scope target(s) on the worklist lack a "
                "terminal fuzz verdict (no campaign receipt / mvc sidecar / typed "
                f"disposition); run `python3 tools/fuzz-target-completeness-check.py --ws {ws}` "
                "for detail (run a >=1M campaign, mutation-verify a harness, or record a "
                "typed row in .auditooor/fuzz_target_dispositions.jsonl)")
            res["fail_gates"] = (
                [f"fuzz-target-incomplete:{r.get('target_id')}" for r in _fopen]
                if _fopen else [f"fuzz-target-incomplete:{_ftc.get('verdict')}"]
            )
            return res
    except Exception:
        pass  # tool unavailable / no worklist -> fail-open

    # Guard/access-control completeness (advisory by default; hard-fails only
    # under AUDITOOOR_GUARD_COMPLETENESS_STRICT=1). wibjbh2e8 headline gap #5:
    # nothing STRUCTURALLY enumerated every external/public state-mutating
    # function and asked "does it carry a correct guard?" - the per-fn hunt
    # reasoned about guards ad hoc, so an entirely UNGUARDED external mutator
    # could slip past every net (the question was never asked for that fn). This
    # consumer enumerates every in-scope external mutator (source-regex, no
    # compiled Slither required; language-generic) and fails on any that is
    # UNGUARDED and undispositioned - a permissionless-by-design function passes
    # WITH a typed disposition in .auditooor/guard_dispositions.jsonl. Mirrors
    # the fuzz-target / commit-adjudication advisory blocks: fail_gate ONLY when
    # the verdict starts with fail- (i.e. under the strict env) AND no rebuttal;
    # fail-open on a missing/erroring tool.
    try:
        import importlib.util as _ilu12
        _pg = Path(__file__).resolve().with_name("guard-completeness-check.py")
        _s12 = _ilu12.spec_from_file_location("_gcc_done", str(_pg))
        _m12 = _ilu12.module_from_spec(_s12)
        sys.modules["_gcc_done"] = _m12
        _s12.loader.exec_module(_m12)
        _gcc = _m12.check(ws)
        res["guard_completeness_detail"] = _gcc
        if str(_gcc.get("verdict", "")).startswith("fail-") and _m12._rebuttal(ws) is None:
            _gopen = _gcc.get("unguarded", [])
            res["reason"] = (
                "Guard/access-control completeness FAIL (STRICT): "
                f"{_gcc.get('unguarded_count', len(_gopen))} external/public state-mutating "
                "in-scope function(s) are UNGUARDED and undispositioned (no modifier / "
                "access-control require / typed disposition); run "
                f"`python3 tools/guard-completeness-check.py --workspace {ws}` for detail "
                "(add a guard, or record a permissionless-by-design row in "
                ".auditooor/guard_dispositions.jsonl, or add a guard_completeness_rebuttal.md)")
            res["fail_gates"] = (
                [f"unguarded-mutator:{r.get('file')}::{r.get('function')}" for r in _gopen]
                if _gopen else [f"guard-completeness:{_gcc.get('verdict')}"]
            )
            return res
    except Exception:
        pass  # tool unavailable -> fail-open (do not brick done on a missing tool)

    # 100%-terminal-adjudication completeness axes (advisory by default; hard-fails
    # ONLY under AUDITOOOR_COMPLETENESS_ALL_AXES_STRICT=1 or the global
    # AUDITOOOR_L37_STRICT=1). The audit-done-guard is the mechanical STRICT verifier,
    # so it re-runs the three axes the audit-complete driver enforces under STRICT and
    # fail-closes if ANY is non-terminal - so a marker written by a NON-strict run (or
    # a stale marker) cannot certify done while a completeness axis was left an
    # advisory WARN. Fail-open on a missing tool / report (never brick done on a tool
    # error). Mirrors the fuzz-target / guard-completeness advisory blocks.
    #   (1) mechanism plane: an UNSCANNED [impact x mechanism] cell with no detector /
    #       agent-cleared-with-citation / disposition,
    #   (2) swept-surface: an uncovered unit with no terminal verdict,
    #   (3) rubric: an unattempted impact row with no candidate / N-A-with-reason.
    try:
        import importlib.util as _ilu_ca
        _pca = Path(__file__).resolve().with_name("audit-completeness-check.py")
        _sca = _ilu_ca.spec_from_file_location("_acc_done", str(_pca))
        _mca = _ilu_ca.module_from_spec(_sca)
        sys.modules["_acc_done"] = _mca
        _sca.loader.exec_module(_mca)
        # This guard verifies a STRICT audit; enforce the terminal axes here even when
        # invoked standalone (do not clobber an operator-set value).
        for _k in ("AUDITOOOR_COMPLETENESS_ALL_AXES_STRICT",
                   "AUDITOOOR_RUBRIC_ATTEMPT_STRICT",
                   "AUDITOOOR_SWEPT_TERMINAL_STRICT",
                   "AUDITOOOR_MECHANISM_AXIS_ENFORCE"):
            os.environ.setdefault(_k, "1")
        _rebuttals = _mca._load_rebuttal(ws)
        _axis_fails: list[str] = []
        for _sig, _fn in (("coverage-map", _mca.check_coverage_map),
                          ("rubric-coverage", _mca.check_rubric_coverage)):
            try:
                _sr = _fn(ws)
            except Exception:
                continue  # tool sub-error on one axis -> fail-open for that axis
            if not _sr.ok and _mca._rebuttal_for(_rebuttals, _sig) is None:
                _n = (_sr.detail.get("swept_non_terminal_uncovered")
                      if _sig == "coverage-map"
                      else _sr.detail.get("rubric_non_terminal_rows"))
                _axis_fails.append(f"{_sig}-non-terminal:{_n}")
        res["completeness_all_axes_detail"] = {"axis_fails": _axis_fails}
        if _axis_fails:
            res["reason"] = (
                "100%-terminal completeness FAIL (STRICT): "
                f"{len(_axis_fails)} completeness axis(es) non-terminal "
                f"({', '.join(_axis_fails)}); every uncovered swept unit / "
                "unattempted rubric row must be covered, dispositioned-with-reason, "
                "or waived. Run `make audit-complete WS=" + str(ws) + " STRICT=1` and "
                "close each axis (see the FAIL reason for the disposition path)")
            res["fail_gates"] = _axis_fails
            return res
    except Exception:
        pass  # tool unavailable / no report -> fail-open (do not brick done)

    # Verdict-feedback-noop gate: a run that ruled MANY units OUT (verdicts on disk
    # in hunt_findings_sidecars/*.jsonl + depth_probes*/*.jsonl) but banked ZERO of
    # them into the known-dead-ends store is the exact polygon pre-fix state - the
    # producers ran but the learning-loop sink (verdict-sink / dead-end-ledger) never
    # closed, so next engagement silently re-hunts every dead end. Block done when
    # >= N (default 50, env AUDIT_DONE_VERDICT_NOOP_MIN) ruled-out verdicts exist but
    # the KDE store has 0 rows for this workspace. Below threshold OR >= 1 banked ->
    # pass. Fail-open on a tool error (cannot count -> do not brick done).
    try:
        _noop = _verdict_feedback_noop(ws)
        if _noop is not None and _noop.get("noop"):
            res["reason"] = (
                "verdict-feedback-noop FAIL: "
                f"{_noop['ruled_out']} ruled-out/OOS verdict(s) on disk but 0 banked "
                "into the known-dead-ends store (the producers ran, the learning-loop "
                "sink never closed); run `python3 tools/verdict-sink.py --journal "
                "<run>/journal.jsonl` (or `python3 tools/dead-end-ledger.py --workspace "
                f"{ws}`) to bank them before claiming done"
            )
            res["fail_gates"] = [f"verdict-feedback-noop:{_noop['ruled_out']}-ruled-out-0-banked"]
            res["verdict_feedback_noop_detail"] = _noop
            return res
    except Exception:
        pass  # cannot count -> fail-open (do not brick done on a tool error)

    # P52 tamper-evident marker verify + canary (ADVISORY by default; hard-fails
    # ONLY under AUDITOOOR_MARKER_TAMPER_STRICT=1). Attaches a read-only
    # `tamper_advisory` block on every run. When the flag is set, a caught
    # forgery (verify_ok False on a signed marker with a chain-digest mismatch)
    # or a failed canary blocks the done claim with a FORGED_VERDICT fail_gate.
    # An UNSIGNED marker is NOT a tamper (older markers / write-order) and never
    # blocks. strict:false on the marker is an HONEST state and is not consulted
    # here. Fail-open on any tool error (a lib error != a forged marker).
    try:
        _tv = _tamper_advisory(ws)
        res["tamper_advisory"] = _tv
        _block, _gates, _reason = _tamper_strict_verdict(_tv)
        if _block:
            res["reason"] = _reason
            res["fail_gates"] = _gates
            return res
        # ADVISORY-FIRST surfacing (the #1-sin defense): even when NOT blocking
        # (AUDITOOOR_MARKER_TAMPER_STRICT unset), a genuine tamper - a SIGNED
        # marker that FAILS verification, or a broken canary - must not pass
        # SILENTLY. Attach a loud, visible warning so audit-next-step / the
        # operator sees it every run; the hard-block stays opt-in via the named
        # env. An unsigned/absent/legacy marker never triggers this (not a tamper).
        _mtw = _marker_tamper_warning(_tv)
        if _mtw:
            res["marker_tamper_warning"] = _mtw
    except Exception:
        pass  # advisory tool error -> never brick done

    # Disposition-distinctness (Track B anti-false-negative sweep): the four-axis
    # guard on NEGATIVE dispositions was ORPHANED (only reachable via `make
    # disposition-sweep`), so shallow kills (dedup/OOS/known-issue closed WITHOUT a
    # four-axis proof - the false-negative machine) never surfaced at DONE. Wired
    # ADVISORY-FIRST: attach a read-only advisory on every run; hard-fail ONLY under
    # AUDITOOOR_DONE_DISPOSITION_STRICT. Fail-open on any tool error.
    try:
        import subprocess as _sp
        _dd_tool = Path(__file__).resolve().parent / "disposition-distinctness-guard.py"
        if _dd_tool.is_file():
            _dd = _sp.run([sys.executable, str(_dd_tool), "--sweep", str(ws), "--json"],
                          capture_output=True, text=True, timeout=120)
            _shallow = 0
            try:
                _ddj = json.loads(_dd.stdout or "{}")
                _shallow = int(_ddj.get("shallow_count") or _ddj.get("shallow") or 0)
            except (ValueError, TypeError):
                _shallow = 0
            res["disposition_distinctness_advisory"] = {
                "shallow_kills": _shallow, "guarded": (_ddj.get("guarded") if isinstance(_ddj, dict) else None),
                "kills_total": (_ddj.get("kills_total") if isinstance(_ddj, dict) else None)}
            _dd_strict = os.environ.get("AUDITOOOR_DONE_DISPOSITION_STRICT", "").strip().lower() in ("1", "true", "yes", "on")
            if _shallow > 0 and _dd_strict:
                res["reason"] = (f"disposition-distinctness FAIL (STRICT): {_shallow} NEGATIVE "
                                 "disposition(s) closed WITHOUT four-axis proof (shallow kill = "
                                 "false-negative risk); prove each with all four axes or run "
                                 "`python3 tools/disposition-distinctness-guard.py --sweep <ws>`")
                res["fail_gates"] = [f"disposition-distinctness-shallow-kills:{_shallow}"]
                return res
    except Exception:
        pass  # advisory tool error -> never brick done

    # E5 (enforcement id22, 2026-07-03): attestation-count integrity + KILL
    # disposition-distinctness. A step-0f attestation that claims "N obligations,
    # all resolved" whose N does not match the recomputed hacker_question_obligations
    # total, OR a KILL-only verdict cluster with a large fraction of EMPTY reasons,
    # is a credit-leak the verbatim attestation gate never catches (NUVA: step-0f
    # claimed 647, artifact holds 1147; 264/575 KILLs reasonless). Wired at the DONE
    # boundary via the SAME check the completeness gate uses (no logic fork).
    # DEFAULT-ON graduation (2026-07-03): AUDITOOOR_ATTESTATION_COUNT_STRICT now
    # defaults ENFORCED under the L37 strict umbrella (the done-guard is the
    # mechanical STRICT verifier), with a per-gate OPT-OUT via
    # AUDITOOOR_ATTESTATION_COUNT_STRICT=0. A bare non-strict `make audit-done-guard`
    # run with L37 unset stays advisory (attach-only) so nothing routine breaks.
    # Delegates the predicate to the completeness-check's shared helper (no fork).
    # Fail-open on tool error.
    try:
        _e5 = _mca.check_attestation_count_integrity(ws) if "_mca" in dir() else None
        if _e5 is not None:
            _e5_mismatch = _e5.detail.get("attestation_count_mismatches") or []
            _e5_kill = _e5.detail.get("kill_cluster") or {}
            res["attestation_count_integrity_advisory"] = {
                "recomputed_obligation_rows": _e5.detail.get("recomputed_obligation_rows"),
                "attestation_count_mismatches": _e5_mismatch,
                "kill_only_flagged": bool(_e5_kill.get("flagged")),
                "kill_empty_reason": _e5_kill.get("empty_reason"),
                "kill_total": _e5_kill.get("kill"),
            }
            _e5_strict = _mca._gate_default_on_strict(
                "AUDITOOOR_ATTESTATION_COUNT_STRICT")
            if _e5_strict and not _e5.ok:
                res["reason"] = "attestation-count-integrity FAIL (STRICT): " + _e5.reason
                _fg = [f"attestation-count-mismatch:step-{m.get('step')}"
                       for m in _e5_mismatch]
                if _e5_kill.get("flagged"):
                    _fg.append(
                        f"kill-only-no-reason:{_e5_kill.get('empty_reason')}-of-"
                        f"{_e5_kill.get('kill')}")
                res["fail_gates"] = _fg or ["attestation-count-integrity"]
                return res
    except Exception:
        pass  # advisory tool error -> never brick done

    # D1 (enforcement id15/20, 2026-07-03): conversion-throughput delivery-leak.
    # The audit passes while ~0% of the non-vacuous corpus/hacker-Q lead corpus
    # reaches a terminal work-backed verdict (NUVA 134/7814). This is a THROUGHPUT
    # gap, NOT a false-green (operator flagged the severity as overstated), so it is
    # ATTACH-ONLY here: emit the undriven count loudly on the done result but NEVER
    # return / brick done in this wave. The hard gate lives at the completeness
    # signal under the dedicated AUDITOOOR_CONVERSION_THROUGHPUT_STRICT; done=True
    # is deliberately left byte-identical. Reuses the completeness-check helper.
    try:
        if "_mca" in dir():
            _d1 = _mca.check_conversion_throughput(ws)
            res["conversion_throughput_advisory"] = {
                "nonvacuous_leads": _d1.detail.get("nonvacuous_leads"),
                "terminal_work_backed": _d1.detail.get("terminal_work_backed"),
                "undriven": _d1.detail.get("undriven"),
                "terminal_fraction": _d1.detail.get("terminal_fraction"),
                "note": ("throughput gap, not a false-green; hard-gate under "
                         "AUDITOOOR_CONVERSION_THROUGHPUT_STRICT at audit-complete, "
                         "not wired into done=True this wave"),
            }
    except Exception:
        pass  # advisory tool error -> never brick done

    # R8 (enforcement-gap 2026-07-03): prior-audit COMPLETENESS was ORPHANED - a
    # known-published audit for an in-scope product that is NOT on disk in
    # prior_audits/ is an R47/R53 dedup BLIND SPOT (a candidate that audit already
    # disclosed silently passes). Wired ADVISORY-FIRST at the DONE boundary: attach a
    # read-only advisory; a FLAG (product expected but ZERO prior_audits on disk)
    # hard-fails ONLY under AUDITOOOR_DONE_PRIOR_AUDIT_STRICT. Fail-open on tool error.
    try:
        import subprocess as _sp2
        _pa_tool = Path(__file__).resolve().parent / "prior-audit-completeness-check.py"
        if _pa_tool.is_file():
            _pa = _sp2.run([sys.executable, str(_pa_tool), str(ws), "--json"],
                           capture_output=True, text=True, timeout=120)
            _pav = "error"
            _gaps = 0
            try:
                _paj = json.loads(_pa.stdout or "{}")
                _pav = str(_paj.get("verdict") or "error")
                _gaps = len(_paj.get("gaps") or [])
            except (ValueError, TypeError):
                _paj = {}
            res["prior_audit_completeness_advisory"] = {
                "verdict": _pav, "gaps": _gaps,
                "disk_audit_count": (_paj.get("disk_audit_count") if isinstance(_paj, dict) else None),
                "expected_count": (_paj.get("expected_count") if isinstance(_paj, dict) else None)}
            _pa_strict = os.environ.get("AUDITOOOR_DONE_PRIOR_AUDIT_STRICT", "").strip().lower() in ("1", "true", "yes", "on")
            if _pav in ("FLAG", "fail") and _pa_strict:
                res["reason"] = ("prior-audit-completeness FLAG (STRICT): a known-published audit "
                                 "for an in-scope product is NOT on disk in prior_audits/ - an R47/R53 "
                                 "dedup blind spot; pull the missing audit(s) or run "
                                 "`python3 tools/prior-audit-completeness-check.py <ws>`")
                res["fail_gates"] = [f"prior-audit-completeness-dedup-gap:{_gaps}"]
                return res
    except Exception:
        pass  # advisory tool error -> never brick done

    # R007 (enforcement-gap 2026-07-03): no gate compared the local src/<repo> git HEAD
    # to the declared audit pin (pin_policy.json / SCOPE.md), so a stale/drifted checkout
    # could pass every coverage gate while the audit ran against DIFFERENT code than it
    # claims. Wired ADVISORY-FIRST at the DONE boundary: attach a read-only advisory; a
    # FLAG (a src repo at NO declared pin) hard-fails ONLY under AUDITOOOR_DONE_STALE_PIN_STRICT.
    try:
        import subprocess as _sp3
        _sp_tool = Path(__file__).resolve().parent / "stale-pin-check.py"
        if _sp_tool.is_file():
            _sp_r = _sp3.run([sys.executable, str(_sp_tool), str(ws), "--json"],
                             capture_output=True, text=True, timeout=60)
            _spv = "error"
            _mism: list = []
            try:
                _spj = json.loads(_sp_r.stdout or "{}")
                _spv = str(_spj.get("verdict") or "error")
                _mism = _spj.get("mismatched") or []
            except (ValueError, TypeError):
                _spj = {}
            res["stale_pin_advisory"] = {"verdict": _spv, "mismatched": _mism,
                                          "repos": (_spj.get("repos") if isinstance(_spj, dict) else None)}
            _sp_strict = os.environ.get("AUDITOOOR_DONE_STALE_PIN_STRICT", "").strip().lower() in ("1", "true", "yes", "on")
            if _spv in ("FLAG", "fail") and _sp_strict:
                res["reason"] = ("stale-pin FLAG (STRICT): a src/ git checkout is NOT at any declared "
                                 f"pin (audit scoped to different code): {_mism}; re-pin + re-clone or "
                                 "run `python3 tools/stale-pin-check.py <ws>`")
                res["fail_gates"] = [f"stale-pin-checkout-mismatch:{len(_mism)}"]
                return res
    except Exception:
        pass  # advisory tool error -> never brick done

    # closure-degrade (enforcement-gap 2026-07-03): the D-CONNECT closure-aware
    # `unguarded` correction stamps closure_consulted/closure_degraded per dataflow
    # record, but NO gate read them - so a run where the closure DEGRADED on every
    # record (predicates unimportable) is indistinguishable from clean (slice-local
    # `unguarded` over-reports on role-gated code; negative-space leads unreliable).
    # Wired ADVISORY-FIRST at the DONE boundary; a FLAG hard-fails ONLY under
    # AUDITOOOR_DONE_CLOSURE_DEGRADE_STRICT.
    try:
        import subprocess as _sp4
        _ch_tool = Path(__file__).resolve().parent / "closure-health-check.py"
        if _ch_tool.is_file():
            _ch = _sp4.run([sys.executable, str(_ch_tool), str(ws), "--json"],
                           capture_output=True, text=True, timeout=60)
            _chv = "error"
            try:
                _chj = json.loads(_ch.stdout or "{}")
                _chv = str(_chj.get("verdict") or "error")
            except (ValueError, TypeError):
                _chj = {}
            res["closure_health_advisory"] = {
                "verdict": _chv,
                "degrade_fraction": (_chj.get("degrade_fraction") if isinstance(_chj, dict) else None),
                "closure_consulted": (_chj.get("closure_consulted") if isinstance(_chj, dict) else None),
                "closure_degraded": (_chj.get("closure_degraded") if isinstance(_chj, dict) else None)}
            _ch_strict = os.environ.get("AUDITOOOR_DONE_CLOSURE_DEGRADE_STRICT", "").strip().lower() in ("1", "true", "yes", "on")
            if _chv in ("FLAG", "fail") and _ch_strict:
                res["reason"] = ("closure-degrade FLAG (STRICT): the inter-procedural closure "
                                 "correction DEGRADED on all/most dataflow records (predicates "
                                 "unimportable) - unguarded/negative-space results are unreliable; "
                                 "fix the closure toolchain + re-slice, or run "
                                 "`python3 tools/closure-health-check.py <ws>`")
                res["fail_gates"] = ["closure-pass-degraded"]
                return res
    except Exception:
        pass  # advisory tool error -> never brick done

    # R21/R27 native-suite result (ADVISORY-FIRST): a Go/Rust ws whose CORE native
    # `go test` / `cargo test` suite FAILED must not green audit-complete (the arms
    # WARN-continue and no gate read the result - a failing native test is R27
    # "failing native test = finding"). Reads the producer artifact
    # <ws>/.auditooor/native_suite_result.json. PRODUCER-CONDITIONAL + FAIL-OPEN:
    # an absent/skipped artifact (non-Go/Rust ws, suite not captured) never FLAGs.
    # A FLAG hard-fails ONLY under AUDITOOOR_DONE_NATIVE_SUITE_STRICT.
    try:
        import subprocess as _sp5
        _ns_tool = Path(__file__).resolve().parent / "native-suite-result-check.py"
        if _ns_tool.is_file():
            _ns = _sp5.run([sys.executable, str(_ns_tool), str(ws), "--json"],
                           capture_output=True, text=True, timeout=60)
            _nsv = "pass"
            try:
                _nsj = json.loads(_ns.stdout or "{}")
                _nsv = str(_nsj.get("verdict") or "pass")
            except (ValueError, TypeError):
                _nsj = {}
            res["native_suite_advisory"] = {
                "verdict": _nsv,
                "total_failed": (_nsj.get("total_failed") if isinstance(_nsj, dict) else None),
                "failing": (_nsj.get("failing") if isinstance(_nsj, dict) else None)}
            _ns_strict = os.environ.get("AUDITOOOR_DONE_NATIVE_SUITE_STRICT", "").strip().lower() in ("1", "true", "yes", "on")
            if _nsv == "FLAG" and _ns_strict:
                res["reason"] = ("native-suite FLAG (STRICT): the Go/Rust core native test suite has "
                                 "FAILING test(s) over the CUT; resolve or file the failure, do not "
                                 "green the audit over it (run "
                                 "`python3 tools/native-suite-result-check.py <ws>`)")
                res["fail_gates"] = ["native-suite-failing-tests"]
                return res
    except Exception:
        pass  # advisory tool error -> never brick done

    res["done"] = True
    res["reason"] = (f"DONE: pass-audit-complete (STRICT) {age_h:.1f}h old; "
                     f"paste_ready={len(pr_files)} honest_zero_verified={honest_zero_ok}")
    res["paste_ready_count"] = len(pr_files)
    res["age_hours"] = round(age_h, 2)
    return res


def main(argv) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("workspace")
    ap.add_argument("--json", action="store_true")
    ap.add_argument("--ttl-hours", type=float, default=float(os.environ.get("AUDIT_DONE_TTL_HOURS", "6")))
    args = ap.parse_args(argv)
    ws = Path(os.path.expanduser(args.workspace)).resolve()
    r = evaluate(ws, ttl_hours=args.ttl_hours)
    if args.json:
        print(json.dumps(r, indent=2))
    else:
        print(("DONE" if r["done"] else "NOT-DONE") + ": " + r["reason"])
        if r.get("fail_gates"):
            for g in r["fail_gates"]:
                print("  FAIL:", g)
    # Loud advisory surfacing of a genuine marker tamper, on stdout AND stderr, in
    # BOTH json and text modes - a forged marker (the #1 sin) must never be silent.
    _mtw = r.get("marker_tamper_warning")
    if _mtw:
        for _rz in _mtw.get("reasons", []):
            print(f"  WARN: marker-tamper-advisory: {_rz}", file=sys.stderr)
    # T1 advisory (capability set changed since the pass). When NOT strict this is
    # a non-blocking WARN so a still-DONE pass is not silently trusted against a
    # newer capability set; under AUDITOOOR_CAPSET_STALENESS_STRICT=1 it already
    # became the NOT-DONE reason above, so only surface it here when still DONE.
    _csw = r.get("capset_stale_warn")
    if _csw and r.get("done"):
        print(f"  WARN: capability-set-staleness-advisory: {_csw}", file=sys.stderr)
    if not ws.is_dir():
        return 2
    return 0 if r["done"] else 1


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
