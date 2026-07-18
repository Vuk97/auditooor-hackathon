#!/usr/bin/env python3
"""tools/lib/credit_evidence.py - narrow-waist credit-evidence loader (P26).

ONE typed record that normalizes the ~three credit-sidecar schema FAMILIES a
workspace accumulates so a single reader (tools/credit-plane-lint.py) can answer
"on-disk evidence exists but a downstream reader did NOT credit it" - the #1
audit-complete false-red (the serving-join false-red, per memory
methodology_serving_join_falsered_class).

THREE families are normalized (schema producers cited, not sampled on-disk):
  (1) mvc_sidecar   - per-function / cluster mutation-verified harness proofs at
                      ``<ws>/.auditooor/mvc_sidecar/mvc-*.json`` (+ cluster
                      variants). GROUND TRUTH = tools/lib/mutation_kill.py
                      ``sidecar_is_genuine`` (the CANONICAL cross-schema credit
                      predicate; auto-producer / manual / cluster). We REUSE it
                      verbatim - never re-derive kill-genuineness here.
                      CREDITED-VIEW = the genuine rows in
                      ``<ws>/.auditooor/genuine_coverage_manifest.json`` (built by
                      the genuine-coverage recipe + upgraded by
                      genuine-coverage-sidecar-merge.py). A genuine sidecar with
                      NO matching genuine manifest row is an UNCREDITED serving-join.
  (2) hunt          - per-task LLM-hunt sidecars written to the repo derived dir
                      ``<repo>/audit/corpus_tags/derived/`` keyed by
                      ``workspace_path``/``workspace``. GROUND TRUTH = the sidecars
                      that BELONG to this ws (same belongs-check as
                      hunt-sidecar-bridge.py). CREDITED-VIEW = the bridged copies
                      in ``<ws>/.auditooor/hunt_findings_sidecars/``. A ws-owned
                      derived sidecar not present in the bridge dir is UNCREDITED.
  (3) coverage_plane- ``<ws>/.auditooor/coverage_plane.jsonl`` +
                      ``coverage_plane_summary.json`` (schema
                      ``auditooor.coverage_plane.v1``, producer
                      coverage-plane-build.py). Normalized for completeness / lint
                      context (a plane that is entirely not-enumerated while
                      mvc/hunt evidence exists is a signal the plane never rebuilt).

DESIGN CONTRACT (P26 wave-1):
  - READ-ONLY. This module reads on-disk artifacts and returns a record. It never
    writes, migrates, or mutates any manifest / sidecar / gate output.
  - ADDITIVE. It introduces a NEW schema (``auditooor.credit_evidence.v1``) that
    nobody else reads yet; it changes no existing field of any existing reader.
  - REUSE, NOT FORK. mvc genuineness = mutation_kill.sidecar_is_genuine;
    genuine-manifest normalization = genuine_coverage_sidecar_merge helpers;
    hunt belongs-check mirrors hunt-sidecar-bridge. We do not re-implement any of
    these normalizers (do-not #10 tool-duplication preflight).
  - FAIL-CLOSED / TOLERANT reads. A missing/corrupt artifact yields an empty view
    for that family, never a crash and never a false "credited".
"""
from __future__ import annotations

import importlib.util
import json
import os
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

_REPO = Path(__file__).resolve().parent.parent.parent  # <repo>/tools/lib -> <repo>
_TOOLS = _REPO / "tools"

SCHEMA = "auditooor.credit_evidence.v1"


# ---------------------------------------------------------------------------
# Reuse (never fork): import the canonical helpers from sibling modules.
# mutation_kill is a pure-stdlib leaf; genuine-coverage-sidecar-merge is a
# hyphenated tool loaded by path so we can reuse its _norm_fn / _norm_src /
# GENUINE_VERDICTS without re-deriving them.
# ---------------------------------------------------------------------------

def _load_module(path: Path, name: str):
    import sys as _sys

    spec = importlib.util.spec_from_file_location(name, str(path))
    if spec is None or spec.loader is None:
        return None
    mod = importlib.util.module_from_spec(spec)
    # Register before exec so a @dataclass inside the loaded module can resolve
    # cls.__module__ (Python 3.12+/3.14 dataclasses reads sys.modules[__module__]).
    _sys.modules.setdefault(name, mod)
    try:
        spec.loader.exec_module(mod)  # type: ignore[union-attr]
    except Exception:
        _sys.modules.pop(name, None)
        return None
    return mod


_mutation_kill = _load_module(_TOOLS / "lib" / "mutation_kill.py", "credit_evidence_mutation_kill")
_gcsm = _load_module(
    _TOOLS / "genuine-coverage-sidecar-merge.py", "credit_evidence_gcsm"
)


def _sidecar_is_genuine(d: dict) -> bool:
    """CANONICAL mvc credit predicate. Reuses mutation_kill.sidecar_is_genuine so
    producer + every consumer + this loader agree on 'genuine'. Fail-closed if the
    module could not load."""
    if _mutation_kill is None:
        return False
    try:
        return bool(_mutation_kill.sidecar_is_genuine(d))
    except Exception:
        return False


def _norm_fn(name: str | None) -> str:
    if _gcsm is not None:
        try:
            return _gcsm._norm_fn(name)  # type: ignore[attr-defined]
        except Exception:
            pass
    s = str(name or "").lstrip("_")
    return re.sub(r"[^a-z0-9]+", "", s.lower())


def _norm_src(src: str | None) -> str:
    if _gcsm is not None:
        try:
            return _gcsm._norm_src(src)  # type: ignore[attr-defined]
        except Exception:
            pass
    s = str(src or "").split(":")[0]
    s = Path(s).stem
    return re.sub(r"[^a-z0-9]+", "", s.lower())


_GENUINE_VERDICTS = frozenset(
    getattr(_gcsm, "GENUINE_VERDICTS", None)
    or {"non-vacuous", "nonvacuous", "genuine", "mutation-verified", "killed"}
)


# ---------------------------------------------------------------------------
# Typed record
# ---------------------------------------------------------------------------

@dataclass
class MvcEvidence:
    """One genuine mvc_sidecar proof on disk + whether it is credited in the
    genuine_coverage manifest view."""
    function: str
    fn_norm: str
    srcbase: str
    sidecar: str
    credited: bool  # a genuine manifest row exists for this fn


@dataclass
class HuntEvidence:
    """One ws-owned hunt sidecar in the repo derived dir + whether a bridged copy
    exists in the ws bridge dir."""
    name: str
    derived_path: str
    credited: bool  # a bridged copy exists in <ws>/.auditooor/hunt_findings_sidecars/


@dataclass
class CreditEvidenceRecord:
    """The single narrow-waist record. Additive schema auditooor.credit_evidence.v1.

    Every field is read-only and independently .get()-able so a future wave-2
    reader can consume it without a migration."""
    schema: str
    ws_name: str
    ws_path: str

    # mvc family
    mvc_on_disk_genuine: list[MvcEvidence] = field(default_factory=list)
    mvc_manifest_present: bool = False
    mvc_manifest_genuine_fn_norms: set[str] = field(default_factory=set)

    # hunt family
    hunt_derived_owned: list[HuntEvidence] = field(default_factory=list)
    hunt_bridge_dir_present: bool = False
    hunt_bridge_count: int = 0

    # coverage plane family
    coverage_plane_present: bool = False
    coverage_plane_summary: dict[str, Any] = field(default_factory=dict)

    notes: list[str] = field(default_factory=list)

    # --- derived views (read-only convenience) -----------------------------
    @property
    def mvc_uncredited(self) -> list[MvcEvidence]:
        return [m for m in self.mvc_on_disk_genuine if not m.credited]

    @property
    def hunt_uncredited(self) -> list[HuntEvidence]:
        return [h for h in self.hunt_derived_owned if not h.credited]

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema": self.schema,
            "ws_name": self.ws_name,
            "ws_path": self.ws_path,
            "mvc": {
                "on_disk_genuine": [vars(m) for m in self.mvc_on_disk_genuine],
                "manifest_present": self.mvc_manifest_present,
                "manifest_genuine_fn_norms": sorted(self.mvc_manifest_genuine_fn_norms),
                "uncredited": [vars(m) for m in self.mvc_uncredited],
            },
            "hunt": {
                "derived_owned": [vars(h) for h in self.hunt_derived_owned],
                "bridge_dir_present": self.hunt_bridge_dir_present,
                "bridge_count": self.hunt_bridge_count,
                "uncredited": [vars(h) for h in self.hunt_uncredited],
            },
            "coverage_plane": {
                "present": self.coverage_plane_present,
                "summary": self.coverage_plane_summary,
            },
            "notes": self.notes,
        }


# ---------------------------------------------------------------------------
# Family loaders (tolerant; a missing artifact -> empty view + note, never crash)
# ---------------------------------------------------------------------------

def _load_json(p: Path) -> Any:
    try:
        return json.loads(p.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None


def _load_mvc(ws: Path, rec: CreditEvidenceRecord) -> None:
    """Populate the mvc family: genuine on-disk sidecars (via sidecar_is_genuine)
    + the genuine fn-norm set from the genuine_coverage_manifest (the CREDITED view)."""
    sidecar_dir = ws / ".auditooor" / "mvc_sidecar"
    if sidecar_dir.is_dir():
        for p in sorted(sidecar_dir.glob("mvc-*.json")):
            d = _load_json(p)
            if not isinstance(d, dict):
                continue
            if not _sidecar_is_genuine(d):
                continue
            fn = d.get("function")
            if not fn:
                continue
            fn_norm = _norm_fn(fn)
            srcbase = ""
            if _gcsm is not None:
                try:
                    srcbase = _gcsm._sidecar_srcbase(d, p)  # type: ignore[attr-defined]
                except Exception:
                    srcbase = _norm_src(d.get("source_file") or d.get("source") or d.get("contract"))
            rec.mvc_on_disk_genuine.append(
                MvcEvidence(
                    function=str(fn),
                    fn_norm=fn_norm,
                    srcbase=srcbase,
                    sidecar=str(p),
                    credited=False,  # filled after manifest load below
                )
            )
    else:
        rec.notes.append("mvc: no mvc_sidecar dir")

    manifest_path = ws / ".auditooor" / "genuine_coverage_manifest.json"
    manifest = _load_json(manifest_path)
    if isinstance(manifest, dict):
        rec.mvc_manifest_present = True
        for row in manifest.get("verdicts") or []:
            if not isinstance(row, dict):
                continue
            if str(row.get("verdict") or "").strip().lower() in _GENUINE_VERDICTS:
                rec.mvc_manifest_genuine_fn_norms.add(_norm_fn(row.get("function")))
    else:
        rec.notes.append("mvc: no genuine_coverage_manifest.json (credited-view empty)")

    # Fill credited flag now that the manifest genuine set is known.
    for m in rec.mvc_on_disk_genuine:
        m.credited = m.fn_norm in rec.mvc_manifest_genuine_fn_norms


def _default_derived_root() -> Path:
    return _REPO / "audit" / "corpus_tags" / "derived"


def _sidecar_belongs(d: dict, ws: Path) -> bool:
    """Mirror hunt-sidecar-bridge.py belongs-check: workspace_path resolves to ws,
    or workspace name matches (exact or normalized >=5-char prefix alias)."""
    if not isinstance(d, dict):
        return False
    wpath = d.get("workspace_path")
    if wpath:
        try:
            if Path(wpath).resolve() == ws:
                return True
        except (OSError, ValueError):
            pass
    wname = d.get("workspace")
    if wname:
        if wname == ws.name:
            return True
        n1 = re.sub(r"[^a-z0-9]", "", str(wname).lower())
        n2 = re.sub(r"[^a-z0-9]", "", ws.name.lower())
        if len(n1) >= 5 and (n1 == n2 or n2.startswith(n1) or n1.startswith(n2)):
            return True
    return False


def _load_hunt(ws: Path, rec: CreditEvidenceRecord, derived_root: Path | None) -> None:
    """Populate the hunt family: ws-owned sidecars in the repo derived dir + whether
    a bridged copy is present in the ws bridge dir (the CREDITED view)."""
    bridge_dir = ws / ".auditooor" / "hunt_findings_sidecars"
    bridged_names: set[str] = set()
    if bridge_dir.is_dir():
        rec.hunt_bridge_dir_present = True
        for p in bridge_dir.glob("*.json"):
            bridged_names.add(p.name)
        rec.hunt_bridge_count = len(bridged_names)
    else:
        rec.notes.append("hunt: no bridge dir (hunt_findings_sidecars absent)")

    root = derived_root or _default_derived_root()
    if not root.is_dir():
        rec.notes.append(f"hunt: derived root absent ({root})")
        return

    # Same candidate globs as the bridge (harness-dir *.json + loose prefixes).
    candidates: set[Path] = set()
    for dpat in ("mimo_harness_*/*.json", "haiku_harness_*/*.json"):
        candidates.update(root.glob(dpat))
    for glob_pat in ("mimo_harness_*.json", "haiku_harness_*.json", "hunt_*.json",
                     "*_sidecar.json", "perfn_mimo_*.json"):
        candidates.update(root.rglob(glob_pat))
    _skip = {"_haiku_plan", "engage_report.json", "intake_baseline.json",
             "detector_environment_manifest.json", "manifest.json"}
    for f in sorted(candidates):
        if not f.is_file() or f.name in _skip:
            continue
        if any(part in _skip for part in f.parts):
            continue
        d = _load_json(f)
        if not isinstance(d, dict):
            continue
        if not _sidecar_belongs(d, ws):
            continue
        # Bridge dst key logic: base name, or parent__name on collision. We
        # conservatively treat EITHER key form as credited so a de-collided copy
        # is not mis-flagged as uncredited.
        credited = f.name in bridged_names or f"{f.parent.name}__{f.name}" in bridged_names
        rec.hunt_derived_owned.append(
            HuntEvidence(name=f.name, derived_path=str(f), credited=credited)
        )


def _load_coverage_plane(ws: Path, rec: CreditEvidenceRecord) -> None:
    summary_path = ws / ".auditooor" / "coverage_plane_summary.json"
    plane_path = ws / ".auditooor" / "coverage_plane.jsonl"
    summary = _load_json(summary_path)
    if isinstance(summary, dict):
        rec.coverage_plane_present = plane_path.is_file()
        rec.coverage_plane_summary = summary
    else:
        rec.notes.append("coverage_plane: no summary (plane not built)")


def load_credit_evidence(
    workspace: str | Path,
    *,
    derived_root: str | Path | None = None,
) -> CreditEvidenceRecord:
    """Normalize the credit-sidecar schema families for ``workspace`` into ONE
    typed CreditEvidenceRecord. Read-only; tolerant of missing artifacts.

    ``derived_root`` overrides the hunt-sidecar derived dir (defaults to
    ``<repo>/audit/corpus_tags/derived``) - used by tests to point at a fixture.
    """
    ws = Path(workspace).expanduser().resolve()
    rec = CreditEvidenceRecord(schema=SCHEMA, ws_name=ws.name, ws_path=str(ws))
    _load_mvc(ws, rec)
    _load_hunt(ws, rec, Path(derived_root).expanduser().resolve() if derived_root else None)
    _load_coverage_plane(ws, rec)
    return rec


# ---------------------------------------------------------------------------
# CLI (inspection only)
# ---------------------------------------------------------------------------

def _main(argv: list[str] | None = None) -> int:
    import argparse

    ap = argparse.ArgumentParser(
        description="Load + print the narrow-waist credit-evidence record for a workspace."
    )
    ap.add_argument("--workspace", required=True)
    ap.add_argument("--derived-root", default=None)
    ap.add_argument("--json", action="store_true")
    args = ap.parse_args(argv)
    rec = load_credit_evidence(args.workspace, derived_root=args.derived_root)
    if args.json:
        print(json.dumps(rec.to_dict(), indent=2, sort_keys=True))
    else:
        print(f"credit-evidence ({rec.schema}) ws={rec.ws_name}")
        print(f"  mvc genuine on-disk : {len(rec.mvc_on_disk_genuine)} "
              f"(uncredited {len(rec.mvc_uncredited)})")
        print(f"  hunt derived owned  : {len(rec.hunt_derived_owned)} "
              f"(uncredited {len(rec.hunt_uncredited)})")
        print(f"  coverage plane      : present={rec.coverage_plane_present}")
    return 0


if __name__ == "__main__":
    import sys

    sys.exit(_main())
