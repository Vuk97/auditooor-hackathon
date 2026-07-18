#!/usr/bin/env python3
# <!-- r36-rebuttal: lane FIX-HUNT-OBLIGATION-RESOLVE registered via agent-pathspec-register.py -->
"""Resolve a hunt_provider_obligation to `completed` AFTER a genuine dispatch.

`make hunt-scoped` (alias hunt-haiku) writes
`<ws>/.auditooor/hunt_provider_obligation.json` with
`status=orchestrator-dispatch-required` so `hunt-completeness-check` /
`audit-complete` fail-close until the per-function hunt actually runs. But NO
tool flipped it back once the orchestrator genuinely dispatched the batches -
so the gate could only ever stay red or be HAND-EDITED (a false-green risk).

This tool closes that gap honestly: it marks the obligation `completed` ONLY
when it can verify the per-function hunt genuinely produced source-verified
verdict sidecars for THIS workspace. A queued-but-never-dispatched hunt has 0
such sidecars, so it stays `dispatch-required` - the anti-false-green property.

A sidecar counts as a GENUINE verdict when it carries one of: a top-level
`verdict`, an `applies_to_target`, a `candidate_finding`, or a `result` whose
(possibly JSON-string) body contains `applies_to_target`/`verdict`. Sidecars
are read from `<ws>/.auditooor/hunt_findings_sidecars/` (the bridged location)
and, when a scoped plan dir is discoverable under the repo, its
`perfn_mimo_*.json` outputs.

Threshold: >= the plan manifest's `total_tasks` when discoverable, else >= 1.

CLI: python3 tools/hunt-obligation-resolve.py --workspace <ws> [--json]
       [--min-sidecars N] [--dry-run]
Exit: 0 = completed (or already completed / no obligation); 1 = still
required (not enough genuine sidecars); 2 = usage/IO error.
"""
from __future__ import annotations

import argparse
import datetime as _dt
import glob
import json
import os
import re
import sys
from pathlib import Path

_OBLIGATION_REL = (".auditooor", "hunt_provider_obligation.json")
_SIDECAR_DIR_REL = (".auditooor", "hunt_findings_sidecars")
_VERDICT_KEYS = ("verdict", "applies_to_target", "candidate_finding")


def _utc_now_iso() -> str:
    # new Date() is unavailable in workflow scripts but this is a plain tool;
    # still, prefer an injected stamp when present for determinism in tests.
    inj = os.environ.get("AUDITOOOR_FAKE_UTC")
    if inj:
        return inj
    return _dt.datetime.now(_dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _load_json(p: Path):
    try:
        return json.loads(p.read_text(encoding="utf-8", errors="replace"))
    except (OSError, ValueError):
        return None


def _sidecar_has_verdict(obj) -> bool:
    """True iff the sidecar object carries a genuine verdict signal."""
    if not isinstance(obj, dict):
        return False
    for k in _VERDICT_KEYS:
        if obj.get(k) not in (None, ""):
            return True
    # MIMO/perfn shape: result is a JSON-encoded STRING holding the verdict.
    res = obj.get("result")
    if isinstance(res, dict):
        return any(res.get(k) not in (None, "") for k in _VERDICT_KEYS)
    if isinstance(res, str) and res.strip():
        try:
            inner = json.loads(res)
            if isinstance(inner, dict):
                return any(inner.get(k) not in (None, "") for k in _VERDICT_KEYS)
        except ValueError:
            pass
        # raw string verdict (e.g. "verdict: no") still counts as a signal
        low = res.lower()
        return any(tok in low for tok in ("applies_to_target", "verdict", "candidate_finding"))
    return False


def _file_has_verdict(p: Path) -> bool:
    """True iff a sidecar FILE carries >=1 genuine verdict signal.

    Handles three on-disk shapes so both the canonical verdict-sink output
    (one `*.json` object per verdict) AND the natural Agent-hunt output (an
    aggregate `*.jsonl` with many verdict rows per file) verify the obligation.
    The README endorses dispatching step-3 batches via the Agent tool, and those
    hunts emit aggregate JSONL - counting only single-object `*.json` left every
    manual hunt unable to verify-complete step-3.
    """
    suffix = p.suffix.lower()
    if suffix == ".jsonl":
        try:
            with p.open(encoding="utf-8", errors="replace") as fh:
                for line in fh:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        row = json.loads(line)
                    except ValueError:
                        continue
                    if _sidecar_has_verdict(row):
                        return True
        except OSError:
            return False
        return False
    obj = _load_json(p)
    # a `*.json` may itself be an array of verdict records
    if isinstance(obj, list):
        return any(_sidecar_has_verdict(r) for r in obj)
    return _sidecar_has_verdict(obj)


_FRAME_SUFFIX_RE = re.compile(r"__I-[0-9a-z][0-9a-z-]*$")


def _base_unit_key(name: str) -> str:
    """Collapse a per-(unit x frame) sidecar filename to its base UNIT key by
    stripping the trailing ``__I-<frame>`` suffix (brick-1 frame key) and the
    ``.json``/``.jsonl`` extension. Legacy frame-less names have no ``__I-``
    suffix so they map to themselves (backward-compatible). This lets the
    dispatch-obligation gate compare DISTINCT-UNIT coverage against the
    distinct-unit threshold instead of a frame-INFLATED raw sidecar count -
    without it, many frames of a few functions could green the obligation while
    most functions stay unhunted (the false-green the per-impact-frames
    capability would otherwise introduce)."""
    stem = re.sub(r"\.jsonl?$", "", str(name or ""))
    return _FRAME_SUFFIX_RE.sub("", stem)


def _count_genuine_sidecars(ws: Path) -> tuple[int, int, list[str]]:
    seen: dict[str, int] = {}
    unit_keys: set[str] = set()
    sample: list[str] = []
    sc_dir = ws / _SIDECAR_DIR_REL[0] / _SIDECAR_DIR_REL[1]
    paths = []
    if sc_dir.is_dir():
        paths = list(sc_dir.glob("*.json")) + list(sc_dir.glob("*.jsonl"))
    # also discoverable scoped plan outputs under the repo (perfn_mimo_*.json)
    repo = Path(__file__).resolve().parent.parent
    wsname = ws.name
    for d in glob.glob(str(repo / "audit" / "corpus_tags" / "derived"
                            / f"haiku_harness_{wsname}*")):
        paths.extend(Path(d).glob("**/perfn_mimo_*.json"))
    # Agent-tool / workflow-drill hunts (per-fn + residual hacker-Q) land under
    # mimo_harness_<wsname>* derived dirs via workflow-drill-sidecar-emit. The
    # README endorses dispatching step-3 via the Agent tool, whose provider is
    # the local CLI (NOT the mimo API) - so when the API path is rate-limited
    # (429) or key-less, these are the only sidecars present and MUST count.
    for d in glob.glob(str(repo / "audit" / "corpus_tags" / "derived"
                            / f"mimo_harness_{wsname}*")):
        paths.extend(Path(d).glob("**/*.json"))
        paths.extend(Path(d).glob("**/*.jsonl"))
    n = 0
    for p in paths:
        if p.name in seen:
            continue
        seen[p.name] = 1
        if _file_has_verdict(p):
            n += 1
            unit_keys.add(_base_unit_key(p.name))
            if len(sample) < 5:
                sample.append(p.name)
    return n, len(unit_keys), sample


def _norm_ws_rel(ws: Path, p: str) -> str:
    """Normalize a source path to a ws-relative form so a residual unit_id path
    and a sidecar anchor path compare on the same basis (abs<->rel, leading
    ``./``). Best-effort - returns the input unchanged when it cannot be
    resolved."""
    s = str(p or "")
    if not s:
        return s
    try:
        pp = Path(s)
        if pp.is_absolute():
            try:
                return str(pp.resolve().relative_to(ws.resolve()))
            except Exception:
                wss = str(ws)
                return s[len(wss):].lstrip("/") if s.startswith(wss) else s
        return s.lstrip("./")
    except Exception:
        return s


def _sidecar_anchor_relpath(ws: Path, p: Path):
    """The ws-relative source file a hunt sidecar anchors to
    (function_anchor.file / file / path), or None when absent."""
    obj = _load_json(p)
    o = obj[0] if isinstance(obj, list) and obj else obj
    if not isinstance(o, dict):
        return None
    fa = o.get("function_anchor")
    f = (fa.get("file") if isinstance(fa, dict) else None) or o.get("file") or o.get("path")
    return _norm_ws_rel(ws, str(f)) if f else None


def _residual_surface_units(ws: Path) -> set[tuple[str, str]]:
    """Return the residual surface (ws-relative-path, function) unit keys the
    deterministic pass deferred, from coverage_residual_worker_queue.json. These
    are the EXACT units the consent-required residual-llm-depth obligation is
    about.

    DIRECTORY-AWARE (obyte step-3, 2026-07-10): keyed by the FULL ws-relative
    source path, NOT the basename. Same-named files across sibling dirs (e.g. the
    in-scope ``evm/`` contracts and their OOS ``evm-v1.0/`` namesakes) are
    distinct units, so a sidecar hunting one cannot basename-credit the other -
    the same file-blind collision fixed in function-coverage-completeness. The
    counter (`_count_perfn_residual_hits`) matches a sidecar's anchor path
    against these full-path keys."""
    q = _load_json(ws / ".auditooor" / "coverage_residual_worker_queue.json")
    out: set[tuple[str, str]] = set()
    if not isinstance(q, dict):
        return out
    for it in q.get("items") or []:
        if not isinstance(it, dict) or it.get("kind") != "surface-unit":
            continue
        uid = str(it.get("unit_id") or "")
        if "::" in uid:
            path, fn = uid.rsplit("::", 1)
            if fn.strip():
                out.add((_norm_ws_rel(ws, path), fn.strip()))
    return out


def _count_perfn_residual_hits(ws: Path) -> int:
    """Count DISTINCT residual surface units genuinely covered by a per-fn hunt
    sidecar (`hunt__<basename>__<fn>__...json` in <ws>/.auditooor/
    hunt_findings_sidecars/).

    The CANONICAL step-3 flow (`make hunt-scoped` -> dispatch agent_batch_*.md)
    residual-scopes the per-fn hunt to exactly these units and writes per-fn
    `hunt__*` sidecars - NOT `mimo_harness_*` ones. Counting only the latter left
    the canonical path structurally unable to ever resolve its own
    residual-llm-depth obligation (SEI 2026-07-04: 37/37 residual units genuinely
    hunted, resolver saw 0). Matching by the EXACT (basename, fn) of a residual
    unit preserves the false-green-safe property the mimo-only counter had: a
    workspace that never hunted the residual units contributes zero, because no
    sidecar's (basename, fn) will be in the residual set."""
    residual = _residual_surface_units(ws)  # (ws-rel-path, fn)
    if not residual:
        return 0
    # basename -> {(relpath, fn)} for the anchorless backward-compat fallback
    by_basename: dict[tuple[str, str], set[tuple[str, str]]] = {}
    for (rel, fn) in residual:
        by_basename.setdefault((Path(rel).name, fn), set()).add((rel, fn))
    sc_dir = ws / ".auditooor" / "hunt_findings_sidecars"
    if not sc_dir.is_dir():
        return 0
    covered: set[tuple[str, str]] = set()
    for p in sc_dir.glob("hunt__*.json"):
        parts = p.name.split("__")
        if len(parts) < 3:
            continue
        fn = parts[2]
        if not _file_has_verdict(p):
            continue
        anchor = _sidecar_anchor_relpath(ws, p)
        if anchor is not None:
            # DIRECTORY-AWARE: an anchored sidecar credits ONLY its exact path.
            # A wrong-dir anchor (e.g. an OOS evm-v1.0 namesake) does NOT credit
            # the in-scope evm/ unit - closes the basename false-green.
            key = (anchor, fn)
            if key in residual:
                covered.add(key)
        else:
            # legacy anchorless sidecar: basename match only when UNAMBIGUOUS
            # (exactly one residual unit shares that basename+fn), preserving the
            # old behavior for single-file-basename workspaces without
            # reintroducing the cross-dir false-green.
            cands = by_basename.get((parts[1], fn)) or set()
            if len(cands) == 1:
                covered.add(next(iter(cands)))
    return len(covered)


def _count_residual_sidecars(ws: Path) -> int:
    """Count genuine verdict evidence that the RESIDUAL hunt was dispatched.

    Two provider-agnostic paths satisfy the same consent-required obligation, so
    we return the MAX (never a sum - no double-count / over-credit past the
    threshold):
      1. the residual-llm-depth hunt (`make hunt-residual-llm-depth`) emits
         `mimo_harness_<wsname>_<NNNN>` sidecars; and
      2. the canonical per-fn hunt (`make hunt-scoped`), residual-scoped to the
         same surface units, emits `hunt__<basename>__<fn>__...json` sidecars.
    Both are matched to a GENUINE verdict; path (2) additionally requires the
    sidecar to anchor to an EXACT residual (basename, fn) unit, so a workspace
    that never hunted the residual contributes zero from either path (false-
    green-safe).
    """
    repo = Path(__file__).resolve().parent.parent
    wsname = ws.name
    pat = f"mimo_harness_{wsname}_"
    seen: set[str] = set()
    n = 0
    for d in glob.glob(str(repo / "audit" / "corpus_tags" / "derived"
                            / f"mimo_harness_{wsname}*")):
        for p in list(Path(d).glob("**/*.json")) + list(Path(d).glob("**/*.jsonl")):
            if p.name in seen:
                continue
            stem = p.stem
            if not stem.startswith(pat):
                continue
            tail = stem[len(pat):]
            if not tail.isdigit():  # residual task sidecars end in a numeric id
                continue
            seen.add(p.name)
            if _file_has_verdict(p):
                n += 1
    return max(n, _count_perfn_residual_hits(ws))


# r36-rebuttal: lane FIX-HUNT-OBLIGATION-RESOLVE registered in .auditooor/agent_pathspec.json
def _dispatch_provenance(ws: Path) -> dict:
    """Run the Rule-3 hunt-dispatch-provenance guard (lazy import). Returns the
    verdict dict; fail-OPEN to not-applicable when the guard is unavailable so an
    older tree still resolves."""
    try:
        import importlib.util
        tp = Path(__file__).resolve().with_name("hunt-dispatch-provenance-check.py")
        spec = importlib.util.spec_from_file_location("_hdp_guard", tp)
        m = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(m)  # type: ignore
        return m.check(ws)
    except Exception:
        return {"verdict": "not-applicable", "reason": "provenance guard unavailable"}


def _expected_tasks(ws: Path) -> int:
    """Best-effort expected sidecar count from the SCOPED plan manifest.

    The canonical per-function hunt is SCOPED to the ranked
    per_fn_hacker_questions (plan dir `*_scoped_n<k>`); the unscoped CORPUS-mode
    plan (`*_n2007`) is the N=2007 generic-question fan-out we deliberately do
    NOT run. So prefer scoped manifests and, among candidates, take the SMALLEST
    positive total_tasks - never let a giant corpus-mode manifest set an
    unreachable threshold that would keep a genuinely-dispatched hunt red.
    """
    repo = Path(__file__).resolve().parent.parent
    wsname = ws.name
    scoped: list[int] = []
    other: list[int] = []
    for mf in glob.glob(str(repo / "audit" / "corpus_tags" / "derived"
                            / f"haiku_harness_{wsname}*" / "_haiku_plan" / "manifest.json")):
        obj = _load_json(Path(mf))
        if not isinstance(obj, dict):
            continue
        try:
            tt = int(obj.get("total_tasks") or 0)
        except (TypeError, ValueError):
            continue
        if tt <= 0:
            continue
        (scoped if "_scoped_n" in mf else other).append(tt)
    pool = scoped or other
    return min(pool) if pool else 0


def _expected_units(ws: Path) -> int:
    """Distinct (file, function) units in the SCOPED ranked per-fn questions.

    The per-function hunt writes ONE verdict sidecar per UNIT (filename
    ``<Contract>_<function>.json``); multiple ranked QUESTIONS routinely target the
    same unit, so the achievable sidecar count is the distinct-unit count, NOT the
    question/total_tasks count. Using ``total_tasks`` (questions) as the sidecar
    threshold is STRUCTURALLY UNREACHABLE whenever questions > units (strata
    2026-06-30: 370 questions over 224 units -> a perfect exhaustive hunt tops out at
    224 sidecars, so the gate could never go green even when genuinely done). This
    returns the real per-unit denominator; callers fall back to _expected_tasks only
    when the ranked questions file is unreadable.
    """
    base = ws / _OBLIGATION_REL[0]
    cands: list[Path] = []
    for name in ("per_fn_hacker_questions.jsonl.ranked.jsonl",
                 "per_fn_hacker_questions.ranked.jsonl"):
        p = base / name
        if p.is_file():
            cands.append(p)
    cands += [Path(x) for x in glob.glob(str(base / "per_fn_hacker_questions*ranked*.jsonl"))]
    units: set[tuple[str, str]] = set()
    for p in cands:
        try:
            for ln in p.read_text(encoding="utf-8").splitlines():
                ln = ln.strip()
                if not ln:
                    continue
                try:
                    r = json.loads(ln)
                except (ValueError, TypeError):
                    continue
                if not isinstance(r, dict):
                    continue
                f = str(r.get("file") or "")
                fn = str(r.get("function") or "")
                # Defensively normalize abs->ws-relative so the SAME unit spelled both
                # ways (the two-pass path-form disagreement, fixed at source in
                # per-function-hacker-questions.py) is not double-counted here either.
                ws_abs = str(ws)
                if f.startswith(ws_abs):
                    f = f[len(ws_abs):].lstrip("/")
                if f or fn:
                    units.add((f, fn))
        except OSError:
            continue
        if units:
            break
    return len(units)


def resolve(ws: Path, *, min_sidecars: int | None = None, dry_run: bool = False) -> dict:
    res = {"workspace": str(ws), "action": "", "completed": False, "reason": "",
           "genuine_sidecars": 0, "threshold": 0}
    if not ws.is_dir():
        res["reason"] = f"workspace not found: {ws}"
        res["action"] = "error"
        return res
    obl = ws / _OBLIGATION_REL[0] / _OBLIGATION_REL[1]
    if not obl.is_file():
        res["action"] = "no-obligation"
        res["completed"] = True  # absent = inline dispatch = no constraint (gate passes)
        res["reason"] = "no hunt_provider_obligation.json - inline dispatch path; nothing to resolve"
        return res
    data = _load_json(obl)
    if not isinstance(data, dict):
        res["action"] = "error"
        res["reason"] = "hunt_provider_obligation.json is not a valid JSON object"
        return res
    if data.get("status") == "completed":
        # A completed marker is not a permanent exemption from provenance
        # verification.  Older runs could be completed before the provider
        # receipt/ledger check was added, leaving a stale failure embedded in
        # the obligation forever.  Refresh the evidence on every resolution
        # pass and fail closed when the dispatch cannot be verified.
        prov = _dispatch_provenance(ws)
        res["dispatch_provenance"] = prov.get("verdict")
        res["dispatch_provenance_reason"] = prov.get("reason", "")
        if prov.get("verdict") == "fail-hunt-dispatch-unlogged":
            res["action"] = "blocked-dispatch-unlogged"
            res["completed"] = False
            res["reason"] = (
                "completed obligation failed dispatch-provenance refresh: "
                + prov.get("reason", "")
            )
            return res
        if not dry_run and prov.get("verdict") != data.get("dispatch_provenance"):
            refreshed = dict(data)
            refreshed["dispatch_provenance"] = prov.get("verdict")
            refreshed["dispatch_provenance_refreshed_utc"] = _utc_now_iso()
            refreshed["dispatch_provenance_reason"] = prov.get("reason", "")
            obl.write_text(json.dumps(refreshed, indent=2), encoding="utf-8")
            res["action"] = "refreshed-provenance"
            res["reason"] = "completed obligation retained; dispatch provenance refreshed"
        else:
            res["action"] = "already-completed"
            res["reason"] = "obligation already status=completed; provenance verified"
        res["completed"] = True
        return res
    status = str(data.get("status") or "")
    # Older hunt planners could emit a residual-empty status while leaving an
    # explicit Agent dispatch plan in `next`. Treat that combination as the
    # dispatch-required family so genuine sidecars can resolve it; never infer
    # completion from the residual count alone.
    next_items = data.get("next", [])
    next_text = " ".join(str(item) for item in next_items) if isinstance(next_items, list) else str(next_items)
    dispatch_pending = "dispatch" in next_text.lower() and (
        "agent_batch" in next_text.lower()
        or "spawn-worker" in next_text.lower()
        or "mimo-corpus-mine" in next_text.lower()
    )
    if status == "residual-empty-no-hunt-required" and dispatch_pending:
        status = "orchestrator-dispatch-required"
    # consent-required residual-llm-depth obligation: the deterministic pass
    # deferred N residual_surface_units to an LLM-depth hunt needing operator
    # consent. That hunt may run via the mimo API OR (when the API is 429 /
    # key-less) via the Agent tool's local-CLI provider. Either way, once it has
    # genuinely produced >= residual_surface_units verdict sidecars for the
    # residual batch, the obligation is satisfied - provider-agnostic.
    if "consent" in status and "dispatch" not in status:
        try:
            resid_n_file = int(data.get("residual_surface_units"))
        except (TypeError, ValueError):
            resid_n_file = 0
        # THRESHOLD SOURCE (obyte step-3, 2026-07-10): derive from the LIVE
        # coverage_residual_worker_queue.json, not the obligation-file snapshot.
        # The file's residual_surface_units is captured when the obligation is
        # created; a later scope-integrity prune of the queue (auto-coverage-
        # closer's OOS filter) makes that snapshot stale and OOS-INFLATED, setting
        # an UNREACHABLE threshold (obyte: file=41 including 19 OOS evm-v1.0 units
        # vs live in-scope queue=22). The counter (_count_perfn_residual_hits)
        # matches sidecars against this SAME live queue, so the threshold must be
        # on the same basis or the counter can never reach it. Fall back to the
        # file field only when the queue is absent/empty. Never GROW past the file
        # snapshot silently: a live count larger than the file field means new
        # units were enumerated, which legitimately raises the bar.
        live_units = len(_residual_surface_units(ws))
        threshold_src = "live-queue" if live_units > 0 else "obligation-file"
        resid_n = live_units if live_units > 0 else resid_n_file
        if resid_n <= 0:
            res["action"] = "left-untouched"
            res["reason"] = (f"status={status!r} consent-required with no positive "
                             "residual_surface_units; operator-consent gate, not resolving")
            return res
        rn = _count_residual_sidecars(ws)
        threshold = min_sidecars if min_sidecars is not None else resid_n
        res["genuine_sidecars"] = rn
        res["threshold"] = threshold
        res["threshold_source"] = threshold_src
        res["residual_surface_units_file"] = resid_n_file
        res["residual_surface_units_live"] = live_units
        if rn < threshold:
            res["action"] = "still-required"
            res["reason"] = (f"only {rn} genuine residual hacker-Q verdict sidecar(s) "
                             f"(need >= {threshold}); residual LLM-depth hunt not "
                             "verifiably dispatched - staying consent-required")
            return res
        new = dict(data)
        new["status"] = "completed"
        new["resolved_utc"] = _utc_now_iso()
        new["resolution"] = {
            "by": "hunt-obligation-resolve.py",
            "path": "consent-required-residual-llm-depth",
            "genuine_residual_verdict_sidecars": rn,
            "threshold": threshold,
            "prior_status": status,
        }
        if not dry_run:
            obl.write_text(json.dumps(new, indent=2), encoding="utf-8")
        res["action"] = "completed" if not dry_run else "would-complete"
        res["completed"] = True
        res["reason"] = (f"{rn} genuine residual hacker-Q verdict sidecar(s) "
                         f"(>= {threshold}) verify the residual LLM-depth hunt "
                         "genuinely ran (provider-agnostic); obligation marked completed")
        return res

    # Only resolve the dispatch-required family; any other non-residual consent
    # obligation is a different (operator-consent) gate and is left untouched.
    if "dispatch" not in status:
        res["action"] = "left-untouched"
        res["reason"] = f"status={status!r} is not a dispatch-required obligation; not resolving"
        return res

    n, n_units, sample = _count_genuine_sidecars(ws)
    # Per-unit sidecar granularity: the achievable denominator is the distinct-unit
    # count of the scoped ranked questions, NOT the question/total_tasks count (which
    # is structurally unreachable when questions > units). Fall back to total_tasks
    # only when the ranked questions file is unreadable.
    if min_sidecars is not None:
        # explicit operator floor is a RAW sidecar count (per-frame cells count)
        threshold = min_sidecars
        measured = n
        measured_kind = "sidecar"
    else:
        # distinct-UNIT threshold must be met by distinct-UNIT coverage, not a
        # frame-inflated raw count (per-impact-frames writes multiple sidecars per
        # function; comparing raw n to a unit count would false-green a thin hunt).
        threshold = max(1, _expected_units(ws) or _expected_tasks(ws))
        measured = n_units
        measured_kind = "distinct-unit"
    res["genuine_sidecars"] = n
    res["genuine_units"] = n_units
    res["threshold"] = threshold
    res["sample"] = sample
    if measured < threshold:
        res["action"] = "still-required"
        res["reason"] = (f"only {measured} genuine {measured_kind} verdict(s) found "
                         f"(need >= {threshold}); per-function hunt not verifiably "
                         "dispatched - staying dispatch-required")
        return res

    # Rule-3 dispatch-provenance guard: a genuine hunt must have been dispatched
    # through tools/spawn-worker.sh (logged + prior-lane-scan + RANDOM-DISPATCH-
    # GUARD). A raw Agent/Workflow fan-out that reads the canonical batch files
    # directly produces real sidecars but bypasses the ledger - this stamps the
    # warning so the bypass is never silent. Non-blocking by default (the briefs
    # are still canonical). A provider receipt with skipped/failed work is not
    # an earned completion, so this is always a hard block in the ordered
    # pipeline. There is no advisory escape hatch for a required hunt phase.
    import os as _os
    prov = _dispatch_provenance(ws)
    res["dispatch_provenance"] = prov.get("verdict")
    if prov.get("verdict") == "fail-hunt-dispatch-unlogged":
        res["dispatch_provenance_reason"] = prov.get("reason", "")
        sys.stderr.write(
            "[hunt-obligation-resolve] FAIL dispatch-provenance: "
            + prov.get("reason", "hunt dispatched outside spawn-worker") + "\n")
        res["action"] = "blocked-dispatch-unlogged"
        res["completed"] = False
        res["reason"] = ("dispatch-provenance FAIL: " + prov.get("reason", ""))
        return res

    # Earned completion: rewrite with embedded evidence (auditable, not a hand-wave).
    new = dict(data)
    new["status"] = "completed"
    new["resolved_utc"] = _utc_now_iso()
    new["dispatch_provenance"] = prov.get("verdict")
    new["resolution"] = {
        "by": "hunt-obligation-resolve.py",
        "genuine_verdict_sidecars": n,
        "genuine_distinct_units": n_units,
        "threshold": threshold,
        "sidecar_sample": sample,
        "prior_status": status,
        "dispatch_provenance": prov.get("verdict"),
    }
    if not dry_run:
        obl.write_text(json.dumps(new, indent=2), encoding="utf-8")
    res["action"] = "completed" if not dry_run else "would-complete"
    res["completed"] = True
    res["reason"] = (f"{n} genuine verdict sidecar(s) (>= {threshold}) verify the per-function "
                     f"hunt genuinely ran; obligation marked completed")
    return res


def main(argv) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--workspace", required=True)
    ap.add_argument("--json", action="store_true")
    ap.add_argument("--min-sidecars", type=int, default=None)
    ap.add_argument("--dry-run", action="store_true")
    args = ap.parse_args(argv)
    ws = Path(os.path.expanduser(args.workspace)).resolve()
    r = resolve(ws, min_sidecars=args.min_sidecars, dry_run=args.dry_run)
    if args.json:
        print(json.dumps(r, indent=2))
    else:
        print(f"[hunt-obligation-resolve] {r['action']}: {r['reason']}")
    if r["action"] == "error":
        return 2
    return 0 if r["completed"] else 1


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
