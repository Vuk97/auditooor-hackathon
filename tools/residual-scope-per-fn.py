#!/usr/bin/env python3
"""residual-scope-per-fn.py - RESIDUAL-scope a ranked per-fn hunt worklist.

WHY (FIX C.1): ``make hunt-scoped`` used to regenerate a FULL per-function batch
plan (e.g. N=844) even when the hunt-coverage gate already credited most units as
covered, so the operator re-hunted the whole surface when the TRUE residual was
only the uncovered / detector-only units (e.g. ~116). This tool reads the
hunt-coverage-gate residual and keeps ONLY the per-fn units that residual still
lists as UNCOVERED, so the scoped hunt spends dispatch budget on the surface that
genuinely needs depth - it NEVER weakens coverage (it only removes ALREADY-covered
units; residual-only is a strict subset of full).

RESIDUAL SOURCES (read-only; first present wins, then unioned):
  1. ``<ws>/.auditooor/coverage_residual_worker_queue.json`` (schema
     ``auditooor.coverage_residual_worker_queue.v1`` written by
     auto-coverage-closer.py) - ``items[]`` with ``kind == "surface-unit"``
     carrying ``unit_id`` (``file::fn``) + ``source_path``.
  2. ``<ws>/.auditooor/g15_hunt_coverage_gate_last_result.json`` (written by
     hunt-coverage-gate.py) - ``unlogged_uncovered`` (list of contract basenames,
     present on the FAIL payload) + ``verdict``.

MATCHING: a per-fn worklist row (``file``/``source_path``/``source`` + ``fn`` or a
``file::fn`` ``unit``) is kept when EITHER its exact ``file::fn`` unit_id is in the
residual surface-unit set, OR (looser) its file basename is in the residual
basename set. Basename normalization mirrors per-fn-mimo-batch-gen._norm_file_line
so absolute / ws-relative / bare-basename spellings all match.

FAIL-OPEN (never weaken coverage): if the gate has NOT run (no residual sidecar at
all) OR the coverage gate PASSED with an EMPTY residual, the residual is UNKNOWN /
everything-still-open, so we KEEP the full worklist (exit 0, no filtering). Only a
gate result that genuinely enumerates a residual subset narrows the plan.

Exit 0 always (advisory); writes the filtered worklist to --output and prints a
one-line summary + a JSON stats line to stderr.
"""
from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path

_HERE = Path(__file__).resolve().parent
if str(_HERE / "lib") not in sys.path:
    sys.path.insert(0, str(_HERE / "lib"))
try:  # fork-modified artifact loader (materialize-fork-modified.py output)
    from lib.fork_modified import (  # type: ignore
        fork_modified_keep_set,
        load_fork_modified_artifact,
    )
except Exception:  # pragma: no cover - degrade to no-op fork drop
    fork_modified_keep_set = None  # type: ignore
    load_fork_modified_artifact = None  # type: ignore

RESIDUAL_QUEUE_REL = ".auditooor/coverage_residual_worker_queue.json"
G15_LAST_RESULT_REL = ".auditooor/g15_hunt_coverage_gate_last_result.json"
FORK_MODIFIED_DIR_REL = ".auditooor/fork_modified"
# Per-unit coverage verdicts written by auto-coverage-closer._run_unit_deterministic_hunt
# (the strict-worklist-drain contract). A worker-queue surface-unit that already
# carries one of these has been driven through the deterministic arsenal (its
# _unit_already_processed==True) and MUST NOT be re-reported as residual - else the
# obligation can never reach terminal after a genuine closer pass. See below.
COVERAGE_UNIT_VERDICT_DIR_REL = ".auditooor/coverage_unit_verdicts"


_HCG_MOD: object | None = None


def _hcg_mod():
    """Load tools/hunt-coverage-gate.py by path (cached). Returns the module or
    None on any absence/error so the needs-llm-depth demotion degrades to a no-op
    (byte-identical to the pre-fix residual scoper)."""
    global _HCG_MOD
    if _HCG_MOD is not None:
        return _HCG_MOD or None
    import importlib.util
    p = _HERE / "hunt-coverage-gate.py"
    if not p.is_file():
        _HCG_MOD = False  # type: ignore[assignment]
        return None
    try:
        spec = importlib.util.spec_from_file_location("_rsp_hunt_coverage_gate", p)
        if spec is None or spec.loader is None:
            _HCG_MOD = False  # type: ignore[assignment]
            return None
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)  # type: ignore[union-attr]
        _HCG_MOD = mod
        return mod
    except Exception:
        _HCG_MOD = False  # type: ignore[assignment]
        return None


def _needs_llm_depth_demoted_units(ws: Path) -> set[str]:
    """Set of ``unit_id`` strings whose ONLY coverage provenance is a
    ``needs-llm-depth`` coverage_unit_verdict AND which are demoted under strict.

    EMPTY in advisory mode (no strict env / not L37) so the residual scoper is
    byte-identical to today. Reuses the hunt-coverage-gate demotion primitive
    verbatim so the residual scoper and the coverage gate share ONE definition of
    "needs-llm-depth-only" (no fork, same never-false-demote carve-out: a unit ALSO
    covered by a genuine dispatched hunt sidecar or a mechanical-hunt-no-finding
    verdict is NOT in this set)."""
    mod = _hcg_mod()
    if mod is None or not hasattr(mod, "needs_llm_depth_only_units"):
        return set()
    try:
        return set(mod.needs_llm_depth_only_units(ws))
    except Exception:
        return set()


def _slug_unit(unit: str) -> str:
    """Slug a ``file::fn`` unit id -> coverage_unit_verdicts filename stem.
    IDENTICAL to auto-coverage-closer._slug_unit so the drain-contract read here
    keys the same way the writer did."""
    return (
        (unit or "")
        .replace("/", "-")
        .replace("\\", "-")
        .replace("::", "--")
        .replace(".", "-")
    )[:120]


def _covered_by_unit_verdict(
    ws: Path,
    src: str,
    uid: str,
    fn: str,
    demoted_unit_ids: set[str] | None = None,
) -> bool:
    """True when a coverage_unit_verdicts/<slug>.json exists for THIS unit under
    any of its equivalent id spellings.

    SERVING-JOIN FIX (false-red): auto-coverage-closer keys per-unit verdicts by
    the fcc worklist's WS-RELATIVE ``src/.../file.go::Fn`` id, but the worker
    queue stores an ABSOLUTE ``source_path`` + a bare-basename ``unit_id``. The
    two never matched, so units the closer genuinely processed (verdict on disk)
    were re-reported as residual forever. Credit the verdict under: (a) the
    ws-relative source path, (b) the raw absolute/relative source path, (c) the
    bare basename. FAIL-CLOSED: a unit with NO verdict on disk still counts as
    residual (never a false green).

    needs-llm-depth demotion (NUVA 2026-07-11): a ``needs-llm-depth`` verdict is a
    hunt OBLIGATION the closer EXPLICITLY deferred to an LLM-depth lane, NOT a
    satisfied coverage. When ``demoted_unit_ids`` (the hunt-coverage-gate strict
    demotion set) contains the matched verdict's ``unit_id``, this unit's ONLY
    coverage provenance is that needs-llm-depth verdict, so it is NOT credited - it
    stays in the residual so ``make hunt-scoped`` dispatches the deferred hunt.
    ``demoted_unit_ids`` is empty unless strict is enforced, so advisory/non-strict
    flows are byte-identical. A ``mechanical-hunt-no-finding`` verdict, or a
    needs-llm-depth unit ALSO covered by a genuine hunt sidecar, is NEVER in the
    demoted set (never-false-demote), so it still credits here."""
    vdir = ws / COVERAGE_UNIT_VERDICT_DIR_REL
    if not fn or not vdir.is_dir():
        return False
    cands: list[str] = []
    for base in (src, uid):
        b = (base or "").strip()
        if not b:
            continue
        # strip a trailing ::fn if the caller passed a full unit id as src
        if "::" in b:
            b = b.rsplit("::", 1)[0]
        cands.append(b)
        # ws-relative spelling of an absolute source path
        try:
            cands.append(str(Path(b).resolve().relative_to(ws.resolve())))
        except Exception:
            pass
        # bare basename spelling
        cands.append(b.replace("\\", "/").rstrip("/").rsplit("/", 1)[-1])
    for path_part in cands:
        if not path_part:
            continue
        vf = vdir / (_slug_unit(f"{path_part}::{fn}") + ".json")
        if vf.is_file():
            if demoted_unit_ids:
                data = _load_json(vf)
                if isinstance(data, dict):
                    uid_v = str(data.get("unit_id") or "").strip()
                    if uid_v and uid_v in demoted_unit_ids:
                        # needs-llm-depth-only under strict -> NOT covered.
                        return False
            return True
    return False


def _norm_file_line(s: str) -> str:
    """Basename-lowercase a 'path/to/file.rs:42' surface. IDENTICAL to
    per-fn-mimo-batch-gen._norm_file_line so residual + worklist paths key the
    same way regardless of absolute / ws-relative / bare-basename spelling."""
    s = (s or "").strip()
    if not s:
        return ""
    s = re.sub(r":\d+(?::\d+)?$", "", s)
    s = s.replace("\\", "/").rstrip("/")
    base = s.rsplit("/", 1)[-1]
    return base.lower()


def _unit_id(file_path: str, fn: str) -> str:
    """Normalized ``basename::fn`` key for exact unit matching."""
    return f"{_norm_file_line(file_path)}::{(fn or '').strip()}"


def _load_json(path: Path) -> dict | None:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return None


def load_residual(ws: Path) -> tuple[set[str], set[str], str]:
    """Return (residual_unit_ids, residual_basenames, source_status).

    source_status is one of:
      'residual-queue'   - surface units read from the residual worker queue
      'g15-uncovered'    - basenames read from the G15 fail payload
      'both'             - union of the two above
      'gate-pass-empty'  - a gate result exists but residual is empty (covered)
      'no-gate'          - no residual sidecar at all (gate never ran)
    """
    unit_ids: set[str] = set()
    basenames: set[str] = set()
    saw_queue = False
    saw_g15 = False
    residual_nonempty = False

    # needs-llm-depth-only demotion (NUVA 2026-07-11): compute ONCE (empty unless
    # strict is enforced). A surface-unit whose only coverage provenance is a
    # needs-llm-depth verdict must NOT be treated as covered - it re-enters the
    # residual so the deferred LLM hunt is dispatched.
    demoted_unit_ids = _needs_llm_depth_demoted_units(ws)

    q = _load_json(ws / RESIDUAL_QUEUE_REL)
    if isinstance(q, dict):
        saw_queue = True
        for it in q.get("items") or []:
            if not isinstance(it, dict) or it.get("kind") != "surface-unit":
                continue
            uid = str(it.get("unit_id") or "")
            src = str(it.get("source_path") or "")
            # unit_id is 'file::fn'; split so we can build a normalized basename::fn
            if "::" in uid:
                fpart, fn = uid.rsplit("::", 1)
                fpath = src or fpart
            else:
                fpath, fn = (src or uid), ""
            # SERVING-JOIN FIX: a surface-unit the closer already drove through
            # its deterministic arsenal (coverage_unit_verdicts/<slug>.json on
            # disk) is genuinely covered - do NOT re-report it as residual, or
            # the obligation can never reach terminal after a real closer pass.
            # Fail-closed: no verdict on disk => still residual.
            if fn.strip() and _covered_by_unit_verdict(
                ws, src, uid, fn.strip(), demoted_unit_ids
            ):
                continue
            bn = _norm_file_line(fpath)
            if bn:
                basenames.add(bn)
                residual_nonempty = True
            if fn.strip():
                unit_ids.add(_unit_id(fpath, fn))

    g = _load_json(ws / G15_LAST_RESULT_REL)
    if isinstance(g, dict):
        saw_g15 = True
        for u in g.get("unlogged_uncovered") or []:
            bn = _norm_file_line(str(u))
            if bn:
                basenames.add(bn)
                residual_nonempty = True
        # SERVING-JOIN FIX: the gate emits its unit-level residual under
        # 'queued_not_scanned' (list of 'file::fn' unit ids) on the
        # fail-queued-not-scanned verdict, NOT 'unlogged_uncovered'. Reading only
        # the latter made this scoper declare 'gate-pass-empty' (residual=0) while
        # the gate was RED with N unscanned units, so `make hunt-scoped` could not
        # self-heal the residual. Fold that unit-level residual in too.
        for u in g.get("queued_not_scanned") or []:
            uid = str(u)
            if "::" in uid:
                fpart, fn = uid.rsplit("::", 1)
            else:
                fpart, fn = uid, ""
            bn = _norm_file_line(fpart)
            if bn:
                basenames.add(bn)
                residual_nonempty = True
            if fn.strip():
                unit_ids.add(_unit_id(fpart, fn))

    if not saw_queue and not saw_g15:
        return set(), set(), "no-gate"
    if not residual_nonempty:
        return set(), set(), "gate-pass-empty"
    if saw_queue and saw_g15:
        return unit_ids, basenames, "both"
    return unit_ids, basenames, "residual-queue" if saw_queue else "g15-uncovered"


def _row_keys(rec: dict) -> tuple[str, str]:
    """(unit_id, basename) for a per-fn worklist row. Mirrors the field order
    per-fn-mimo-batch-gen consumes: file / source_path / source for the path,
    fn (or the tail of a 'file::fn' unit) for the function name."""
    file_path = (
        rec.get("file")
        or rec.get("source_path")
        or rec.get("source")
        or ""
    )
    fn = str(rec.get("fn") or rec.get("fn_name") or "").strip()
    unit = str(rec.get("unit") or "")
    if (not fn) and "::" in unit:
        fn = unit.split("::")[-1].strip()
    if not file_path and "::" in unit:
        file_path = unit.split("::")[0]
    return _unit_id(str(file_path), fn), _norm_file_line(str(file_path))


def load_fork_keep_sets(ws: Path) -> dict[str, set[str] | None]:
    """Read every materialized fork_modified artifact under
    ``<ws>/.auditooor/fork_modified/`` and return
    ``{local_name: keep_set_or_None}`` where keep_set is the IN-SCOPE (modified
    UNION added) repo-relative file set, or None when the fork's upstream was
    UNRESOLVED (verdict != scoped -> keep-all for that fork, never under-scope).
    Empty dict when no artifacts / lib unavailable (fork drop is a no-op)."""
    out: dict[str, set[str] | None] = {}
    if load_fork_modified_artifact is None or fork_modified_keep_set is None:
        return out
    d = ws / FORK_MODIFIED_DIR_REL
    if not d.is_dir():
        return out
    for p in sorted(d.glob("*.json")):
        name = p.stem
        art = load_fork_modified_artifact(ws, name)
        if art is None:
            continue
        out[name] = fork_modified_keep_set(art)  # set (scoped) or None (keep-all)
    return out


def _fork_rel(file_path: str, local_name: str) -> str | None:
    """If ``file_path`` is under ``src/<local_name>/`` return its repo-relative
    path (the part after ``src/<local_name>/``), else None. Matches both a
    leading ``src/<name>/`` prefix and an embedded ``/src/<name>/`` segment."""
    prefix = f"src/{local_name}/"
    seg = f"/src/{local_name}/"
    if file_path.startswith(prefix):
        return file_path[len(prefix):]
    if seg in file_path:
        return file_path.split(seg, 1)[1]
    return None


def _row_is_unmodified_upstream(rec: dict, fork_keep: dict[str, set[str] | None]) -> bool:
    """True iff this worklist row belongs to a resolved fork AND its repo-relative
    file is NOT in that fork's IN-SCOPE (modified+added) keep-set - i.e. it is
    UNMODIFIED-UPSTREAM and OUT OF SCOPE. A fork whose keep-set is None (upstream
    unresolved) NEVER drops (completeness-safe). Rows outside every fork tree, and
    Sei-added / Sei-modified rows, return False (kept)."""
    if not fork_keep:
        return False
    file_path = str(
        rec.get("file") or rec.get("source_path") or rec.get("source") or ""
    )
    if not file_path:
        unit = str(rec.get("unit") or "")
        if "::" in unit:
            file_path = unit.split("::")[0]
    if not file_path:
        return False
    for name, keep in fork_keep.items():
        rel = _fork_rel(file_path, name)
        if rel is None:
            continue
        if keep is None:
            return False  # keep-all for this fork (unresolved upstream)
        return rel not in keep  # unmodified-upstream (OOS) when not in keep-set
    return False


def scope_worklist(
    ranked_path: Path,
    output_path: Path,
    unit_ids: set[str],
    basenames: set[str],
    fork_keep: dict[str, set[str] | None] | None = None,
) -> tuple[int, int, int]:
    """Filter ranked_path -> output_path keeping only residual rows. Returns
    (kept, total, fork_dropped).

    A row is DROPPED when it is unmodified-upstream for a resolved fork
    (``fork_keep``) - regardless of the coverage residual - because unmodified
    upstream is OUT OF SCOPE and must never reach an agent. Otherwise a row is
    KEPT when it is in the coverage residual set."""
    fork_keep = fork_keep or {}
    kept_lines: list[str] = []
    total = 0
    fork_dropped = 0
    for line in ranked_path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line:
            continue
        total += 1
        try:
            rec = json.loads(line)
        except Exception:
            # Unparseable row: keep it (fail-open) rather than silently dropping.
            kept_lines.append(line)
            continue
        # FORK-DELTA DROP: unmodified-upstream units are OOS; never hunt them.
        if _row_is_unmodified_upstream(rec, fork_keep):
            fork_dropped += 1
            continue
        uid, bn = _row_keys(rec)
        if (uid and uid in unit_ids) or (bn and bn in basenames):
            kept_lines.append(line)
    output_path.write_text(
        "\n".join(kept_lines) + ("\n" if kept_lines else ""),
        encoding="utf-8",
    )
    return len(kept_lines), total, fork_dropped


def build_obligation(ws: Path) -> dict:
    """FIX C.2: build the hunt_provider_obligation payload carrying the
    coverage-gate residual. The old obligation hardcoded status
    'orchestrator-dispatch-required' (reads like 'not planned'); this reflects
    the ACTUAL residual: 'residual-hunt-required' with residual_surface_units:N
    when uncovered units remain, or 'complete' when the coverage gate is green."""
    unit_ids, basenames, status = load_residual(ws)
    residual_n = len(basenames)
    if status in ("no-gate", "gate-pass-empty") or residual_n == 0:
        # Coverage gate green (or not yet run). If it ran and passed with empty
        # residual -> complete; if it never ran, residual is unknown -> keep the
        # dispatch-required posture (an honest 'we have not measured' state).
        if status == "gate-pass-empty":
            ob_status = "residual-empty-no-hunt-required"
            reason = (
                "hunt-coverage gate residual is empty - all surface units covered; "
                "no residual per-function hunt remains"
            )
        else:
            ob_status = "residual-unknown-dispatch-required"
            reason = (
                "hunt-coverage gate has not produced a residual sidecar yet; the "
                "per-function hunt runs via the orchestrator Agent tool "
                "(defaults to model=sonnet), then re-measure the coverage residual"
            )
        residual_n = 0
    else:
        ob_status = "residual-hunt-required"
        reason = (
            f"hunt-coverage gate leaves {residual_n} surface unit(s) uncovered "
            f"(source={status}); the residual-scoped per-function hunt runs via the "
            "orchestrator Agent tool (defaults to model=sonnet), then "
            "make mimo-corpus-mine"
        )
    return {
        "schema": "auditooor.hunt_provider_obligation.v1",
        "hunt_provider": "agent-via-orchestrator",
        "model_default": "sonnet",
        "status": ob_status,
        "residual_surface_units": residual_n,
        "residual_source": status,
        "reason": reason,
        "next": [
            "dispatch each _haiku_plan/agent_batch_*.md via Agent(model=sonnet) "
            "(route through tools/spawn-worker.sh)",
            "make mimo-corpus-mine WS=<ws>",
        ],
    }


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(
        description="Residual-scope a ranked per-fn hunt worklist to the "
        "hunt-coverage-gate residual (uncovered/detector-only units).",
    )
    p.add_argument("--workspace", required=True, help="Workspace path.")
    p.add_argument("--ranked", help="Ranked per-fn worklist jsonl (input).")
    p.add_argument("--output", help="Filtered worklist jsonl (output).")
    p.add_argument(
        "--emit-obligation",
        metavar="PATH",
        help="Instead of filtering a worklist, write the hunt_provider_obligation "
        "JSON (carrying the coverage residual) to PATH and exit.",
    )
    args = p.parse_args(argv)

    ws = Path(args.workspace).expanduser()

    if args.emit_obligation:
        ob = build_obligation(ws)
        ob_path = Path(args.emit_obligation).expanduser()
        ob_path.parent.mkdir(parents=True, exist_ok=True)
        ob_path.write_text(json.dumps(ob) + "\n", encoding="utf-8")
        print(
            f"[residual-scope-per-fn] obligation status={ob['status']} "
            f"residual_surface_units={ob['residual_surface_units']} -> {ob_path}",
        )
        return 0

    if not args.ranked or not args.output:
        print(
            "[residual-scope-per-fn] ERR --ranked and --output required "
            "(or use --emit-obligation)",
            file=sys.stderr,
        )
        return 0
    ranked = Path(args.ranked).expanduser()
    out = Path(args.output).expanduser()

    if not ranked.is_file():
        print(f"[residual-scope-per-fn] ERR ranked worklist not found: {ranked}", file=sys.stderr)
        return 0  # advisory: never fatal

    unit_ids, basenames, status = load_residual(ws)
    # FORK-DELTA: load the materialized fork-modified keep-sets. Even when the
    # coverage residual is UNKNOWN (keep-full), unmodified-upstream units are OOS
    # and must be dropped - so the fork drop applies on EVERY path.
    fork_keep = load_fork_keep_sets(ws)
    fork_forks_scoped = sum(1 for v in fork_keep.values() if v is not None)

    if status in ("no-gate", "gate-pass-empty"):
        # Residual UNKNOWN or everything-covered-per-gate: KEEP full worklist so
        # we never weaken coverage by dropping an as-yet-unjudged unit - BUT still
        # drop unmodified-upstream fork units (OOS regardless of coverage).
        fork_dropped = 0
        if fork_forks_scoped:
            kept_lines: list[str] = []
            for line in ranked.read_text(encoding="utf-8").splitlines():
                line = line.strip()
                if not line:
                    continue
                try:
                    rec = json.loads(line)
                except Exception:
                    kept_lines.append(line)
                    continue
                if _row_is_unmodified_upstream(rec, fork_keep):
                    fork_dropped += 1
                    continue
                kept_lines.append(line)
            out.write_text(
                "\n".join(kept_lines) + ("\n" if kept_lines else ""),
                encoding="utf-8",
            )
            total = len(kept_lines) + fork_dropped
            kept = len(kept_lines)
        else:
            out.write_text(ranked.read_text(encoding="utf-8"), encoding="utf-8")
            total = sum(1 for _l in ranked.read_text(encoding="utf-8").splitlines() if _l.strip())
            kept = total
        reason = (
            "no coverage-gate residual sidecar (gate not run)"
            if status == "no-gate"
            else "coverage gate residual is empty (covered)"
        )
        print(
            f"[residual-scope-per-fn] {reason}; keeping FULL worklist minus "
            f"fork-OOS ({kept} units; dropped {fork_dropped} unmodified-upstream "
            f"across {fork_forks_scoped} scoped fork(s)).",
        )
        print(
            json.dumps(
                {
                    "residual_source": status,
                    "kept": kept,
                    "total": total,
                    "residual_surface_units": 0,
                    "fork_dropped_unmodified_upstream": fork_dropped,
                    "narrowed": fork_dropped > 0,
                }
            ),
            file=sys.stderr,
        )
        return 0

    kept, total, fork_dropped = scope_worklist(
        ranked, out, unit_ids, basenames, fork_keep=fork_keep
    )
    print(
        f"[residual-scope-per-fn] residual source={status}: kept {kept}/{total} "
        f"per-fn units (residual surface={len(basenames)} basenames / "
        f"{len(unit_ids)} exact units); dropped {total - kept} not-in-residual "
        f"(of which {fork_dropped} unmodified-upstream fork-OOS across "
        f"{fork_forks_scoped} scoped fork(s)).",
    )
    print(
        json.dumps(
            {
                "residual_source": status,
                "kept": kept,
                "total": total,
                "residual_surface_units": len(basenames),
                "fork_dropped_unmodified_upstream": fork_dropped,
                "narrowed": kept < total,
            }
        ),
        file=sys.stderr,
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
