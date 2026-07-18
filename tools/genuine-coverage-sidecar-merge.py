#!/usr/bin/env python3
"""Merge DURABLE per-function mutation-KILL proofs into genuine_coverage_manifest.

WHY (serving-join, wiring-not-supply): the ``genuine-coverage`` recipe builds its
manifest ONLY from the per-function harnesses it auto-GENERATES (the assert-true
sentinel scaffolds emitted by per-function-invariant-gen). When an operator or a
dispatched agent HAND-AUTHORS a real per-function invariant harness and proves it
non-vacuous via tools/mutation-verify-coverage.py, that proof is auto-persisted to
``.auditooor/mvc_sidecar/mvc-<srcbase>-<fn>.json`` (see _persist_durable_sidecar) -
but the genuine_coverage_manifest builder never READS that dir. Result: 12 real
mutation-verified harnesses on disk, manifest still says ``0/N genuine`` and the
dispatch brief lists every function as a non-genuine target. This is the same
class as the core-coverage / engine-harness-proof / audit-honesty cluster-schema
credit gap: a new durable schema needs EVERY independent reader taught.

This tool is that reader for the per-FUNCTION genuine_coverage_manifest. It is
ADDITIVE and IDEMPOTENT: it upgrades a manifest verdict row to ``non-vacuous`` iff
a durable per-function sidecar proves that function, recomputes the counts from the
verdict rows, and rewrites the manifest. Re-running credits the same set (no dupes,
no Date/random).

JOIN (deliberately function-name-first, NOT source-path):
  the worklist commonly enumerates a delegation-PROXY facade (e.g. SSVNetwork.sol),
  so every worklist row carries the facade source while the real logic + the
  hand-authored harness live in a MODULE contract (SSVClusters/SSVOperators/...).
  A source-path join would therefore miss every legitimate proof. We match on the
  NORMALISED function name (leading underscores stripped, lowercased) - so an
  internal ``_bulkRegisterValidator`` proof credits the facade ``bulkRegisterValidator``
  entrypoint. When a name is AMBIGUOUS in the worklist (>1 row), we disambiguate by
  source basename if the sidecar carries one; if still ambiguous we SKIP and report
  it (never false-credit).

Only ``mvc-*.json`` per-function sidecars are ingested; cross-function / core
invariant sidecars (different filename convention) are out of scope for this
per-function manifest. Opt out entirely with AUDITOOOR_GC_NO_SIDECAR_MERGE=1.
"""
from __future__ import annotations

import argparse
import json
import os
import re
import sys
from pathlib import Path

GENUINE_VERDICTS = frozenset(
    {"non-vacuous", "nonvacuous", "genuine", "mutation-verified", "killed"}
)


def _norm_fn(name: str | None) -> str:
    """Normalise a function name for cross-unit matching: drop leading underscores
    (internal-impl vs facade entrypoint), lowercase, keep alnum only."""
    s = str(name or "")
    s = s.lstrip("_")
    return re.sub(r"[^a-z0-9]+", "", s.lower())


def _norm_src(src: str | None) -> str:
    """Normalise a source identifier to its contract/file basename, lowercased."""
    s = str(src or "")
    s = s.split(":")[0]  # drop :line
    s = Path(s).stem  # drop dir + .sol
    return re.sub(r"[^a-z0-9]+", "", s.lower())


def _sidecar_srcbase(record: dict, sidecar_path: Path) -> str:
    """Best-effort source basename for a durable per-fn sidecar.

    Prefer the record's own source/contract; else parse it from the deterministic
    filename ``mvc-<srcbase>-<fnlower>.json`` by stripping the ``mvc-`` prefix and
    the trailing ``-<fnlower>`` segment (fn taken from the record)."""
    for key in ("source_file", "source", "contract"):
        v = record.get(key)
        if v:
            return _norm_src(v)
    stem = sidecar_path.stem  # mvc-ssvoperators-declareoperatorfee
    if stem.startswith("mvc-"):
        stem = stem[4:]
    fn_norm = _norm_fn(record.get("function"))
    if fn_norm and stem.endswith("-" + fn_norm):
        return re.sub(r"[^a-z0-9]+", "", stem[: -(len(fn_norm) + 1)].lower())
    if fn_norm and stem.endswith(fn_norm):
        return re.sub(r"[^a-z0-9]+", "", stem[: -len(fn_norm)].rstrip("-").lower())
    return re.sub(r"[^a-z0-9]+", "", stem.lower())


def load_durable_per_fn_proofs(ws: Path) -> list[dict]:
    """Return [{function, fn_norm, srcbase, verdict, sidecar}] for every non-vacuous
    per-function (mvc-*.json) durable sidecar in the workspace."""
    sidecar_dir = ws / ".auditooor" / "mvc_sidecar"
    out: list[dict] = []
    if not sidecar_dir.is_dir():
        return out
    for p in sorted(sidecar_dir.glob("mvc-*.json")):
        try:
            rec = json.loads(p.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            continue
        if str(rec.get("verdict")) not in GENUINE_VERDICTS:
            continue
        fn = rec.get("function")
        if not fn:
            continue
        out.append(
            {
                "function": fn,
                "fn_norm": _norm_fn(fn),
                "srcbase": _sidecar_srcbase(rec, p),
                "verdict": "non-vacuous",
                "sidecar": str(p),
            }
        )
    return out


def merge(manifest: dict, proofs: list[dict]) -> dict:
    """Upgrade manifest verdict rows credited by a durable proof. Returns a report
    dict. Mutates ``manifest`` in place (verdicts + counts + summary)."""
    verdicts = manifest.get("verdicts") or []
    # index worklist rows by normalised fn name
    by_name: dict[str, list[dict]] = {}
    for row in verdicts:
        by_name.setdefault(_norm_fn(row.get("function")), []).append(row)

    credited, already, ambiguous, unmatched = [], [], [], []
    for pr in proofs:
        rows = by_name.get(pr["fn_norm"]) or []
        if not rows:
            unmatched.append(pr["function"])
            continue
        # already-genuine rows for this name need no credit
        candidates = [r for r in rows if str(r.get("verdict")) not in GENUINE_VERDICTS]
        if not candidates:
            already.append(pr["function"])
            continue
        target = None
        if len(candidates) == 1:
            target = candidates[0]
        else:
            # disambiguate by source basename when available
            src_matches = [
                r for r in candidates if _norm_src(r.get("source")) == pr["srcbase"]
            ]
            if len(src_matches) == 1:
                target = src_matches[0]
            else:
                ambiguous.append(pr["function"])
                continue
        target["verdict"] = "non-vacuous"
        target["credited_via"] = "durable-sidecar"
        target["sidecar"] = pr["sidecar"]
        target.setdefault("reason", "credited from durable mutation-verified harness proof")
        credited.append(pr["function"])

    # recompute counts from the (mutated) verdict rows - single source of truth
    total = len(verdicts)
    genuine = sum(1 for r in verdicts if str(r.get("verdict")) in GENUINE_VERDICTS)
    vacuous = sum(1 for r in verdicts if str(r.get("verdict")) == "vacuous")
    nobaseline = sum(1 for r in verdicts if str(r.get("verdict")) == "no-baseline")
    errored = sum(1 for r in verdicts if str(r.get("verdict")) == "error")
    skipped = sum(1 for r in verdicts if str(r.get("verdict")) == "skipped")
    checkable = sum(
        1
        for r in verdicts
        if str(r.get("verdict")) not in ("skipped", "error", "no-baseline")
    )
    manifest["counts"] = {
        "total": total,
        "non_vacuous_genuine": genuine,
        "vacuous": vacuous,
        "no_baseline": nobaseline,
        "error": errored,
        "skipped": skipped,
    }
    manifest["mutation_verified_genuine_count"] = genuine
    manifest["vacuous_count"] = vacuous
    manifest["checkable_count"] = checkable
    manifest["summary"] = (
        "%d/%d per-function harnesses are mutation-verified genuine, %d vacuous "
        "(%d credited from durable sidecars)"
        % (genuine, total, vacuous, len(credited))
    )
    manifest["sidecar_merge"] = {
        "credited": credited,
        "already_genuine": already,
        "ambiguous": ambiguous,
        "unmatched_sidecars": unmatched,
    }
    return manifest["sidecar_merge"]


def run(ws: Path, manifest_path: Path) -> dict:
    if os.environ.get("AUDITOOOR_GC_NO_SIDECAR_MERGE"):
        return {"status": "disabled", "reason": "AUDITOOOR_GC_NO_SIDECAR_MERGE=1"}
    if not manifest_path.is_file():
        return {"status": "no-manifest", "reason": str(manifest_path)}
    try:
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        return {"status": "manifest-parse-error", "reason": str(exc)}
    proofs = load_durable_per_fn_proofs(ws)
    if not proofs:
        return {"status": "no-durable-proofs", "credited": []}
    report = merge(manifest, proofs)
    manifest_path.write_text(
        json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    report["status"] = "ok"
    report["durable_proofs"] = len(proofs)
    return report


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--workspace", required=True)
    ap.add_argument(
        "--manifest",
        default=None,
        help="genuine_coverage_manifest.json (default: <ws>/.auditooor/genuine_coverage_manifest.json)",
    )
    ap.add_argument("--json", action="store_true")
    args = ap.parse_args(argv)
    ws = Path(args.workspace).resolve()
    manifest_path = (
        Path(args.manifest)
        if args.manifest
        else ws / ".auditooor" / "genuine_coverage_manifest.json"
    )
    report = run(ws, manifest_path)
    if args.json:
        print(json.dumps(report, indent=2))
    else:
        st = report.get("status")
        cred = report.get("credited") or []
        print(
            "[gc-sidecar-merge] %s: credited %d (%s); ambiguous %d; unmatched %d"
            % (
                st,
                len(cred),
                ", ".join(cred) if cred else "-",
                len(report.get("ambiguous") or []),
                len(report.get("unmatched_sidecars") or []),
            )
        )
    return 0


if __name__ == "__main__":
    sys.exit(main())
