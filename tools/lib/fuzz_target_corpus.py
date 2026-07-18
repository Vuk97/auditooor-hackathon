from __future__ import annotations

import json
import re
import subprocess
from pathlib import Path
from typing import Any


SCHEMA_VERSION = "auditooor.fuzz_target.v1"
DEFAULT_TIER_WITH_SHA = "tier-2-verified-public-archive"
DEFAULT_TIER_NO_SHA = "tier-3-synthetic-taxonomy-anchored"
RESULTS_SCHEMA = "auditooor.fuzz_campaign_results.v1"

# Schema of a worklist row emitted from the in-scope surface (the "which assets
# still need a campaign" worklist). Distinct from the run-result schema above:
# a worklist row is an OBLIGATION (a value-moving in-scope asset+fn cluster that
# needs a fuzz campaign), not a finished run. The completeness-check reads these.
WORKLIST_SCHEMA_VERSION = "auditooor.fuzz_target_worklist.v1"


def workspace_slug(value: str) -> str:
    text = Path(value).name if value.strip().startswith("/") else value.strip()
    slug = re.sub(r"[^A-Za-z0-9_.-]+", "-", text)
    return slug.strip("-") or "workspace"


def fuzz_target_output_path(repo_root: Path, ws: str | None = None) -> Path:
    slug = workspace_slug(ws or repo_root.name)
    return repo_root / "audit" / "corpus_tags" / slug / "fuzz_targets.jsonl"


def _read_json(path: Path) -> dict[str, Any]:
    payload = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(payload, dict):
        raise ValueError(f"{path} did not parse to a JSON object")
    return payload


def _candidate_fuzz_results_paths(root: Path) -> list[Path]:
    candidates: list[Path] = []
    direct = root / "fuzz_results.json"
    if direct.is_file():
        candidates.append(direct)
    if (root / "fuzz_runs").is_dir():
        candidates.extend(
            sorted(
                path
                for path in root.glob("fuzz_runs/**/fuzz_results.json")
                if path.is_file()
            )
        )
    if (root / "reports").is_dir():
        candidates.extend(
            sorted(
                path
                for path in root.glob("reports/v3_iter_*/lane_*FUZZ*CAMPAIGN/fuzz_results.json")
                if path.is_file()
            )
        )
    return candidates


def discover_latest_fuzz_results(repo_root: Path, ws: str) -> Path | None:
    slug = workspace_slug(ws).lower()
    candidates: list[tuple[float, Path]] = []
    search_roots: list[Path] = []
    ws_path = Path(ws).expanduser()
    if ws_path.exists():
        search_roots.append(ws_path)
    if repo_root not in search_roots:
        search_roots.append(repo_root)
    seen: set[Path] = set()
    for root in search_roots:
        for path in _candidate_fuzz_results_paths(root):
            try:
                resolved = path.resolve()
            except OSError:
                resolved = path
            if resolved in seen:
                continue
            seen.add(resolved)
            payload = None
            try:
                payload = _read_json(path)
            except Exception:
                continue
            lane = str(payload.get("lane") or "").lower()
            workspace = str(payload.get("workspace") or "").lower()
            payload_names_workspace = bool(lane or workspace)
            if payload_names_workspace and slug not in lane and slug != workspace:
                continue
            try:
                mtime = path.stat().st_mtime
            except OSError:
                mtime = 0.0
            candidates.append((mtime, path))
    if not candidates:
        return None
    candidates.sort(key=lambda item: item[0], reverse=True)
    return candidates[0][1]


def _git_head_for_path(path_value: str) -> str:
    if not path_value:
        return ""
    path = Path(path_value).expanduser()
    probe = path if path.is_dir() else path.parent
    if not probe.exists():
        return ""
    toplevel = subprocess.run(
        ["git", "-C", str(probe), "rev-parse", "--show-toplevel"],
        capture_output=True,
        text=True,
        check=False,
    )
    if toplevel.returncode != 0:
        return ""
    repo_root = Path(toplevel.stdout.strip())
    result = subprocess.run(
        ["git", "-C", str(repo_root), "rev-parse", "HEAD"],
        capture_output=True,
        text=True,
        check=False,
    )
    if result.returncode != 0:
        return ""
    sha = result.stdout.strip()
    return sha if re.fullmatch(r"[0-9a-f]{40}", sha) else ""


def _harness_type(row: dict[str, Any]) -> str:
    tool = str(row.get("tool") or "").lower()
    forge_path = str(row.get("forge_path") or "")
    cargo_path = str(row.get("cargo_path") or "")
    if forge_path.endswith(".t.sol") or "foundry" in tool or "forge" in tool:
        return "foundry-forge"
    if cargo_path or "proptest" in tool:
        return "rust-proptest"
    return "unknown"


def _target_path(row: dict[str, Any]) -> str:
    for key in ("forge_path", "cargo_path", "test_dir"):
        value = str(row.get(key) or "").strip()
        if value:
            return value
    return ""


def _invariant_violated(row: dict[str, Any]) -> str:
    verdict = str(row.get("verdict") or "").upper()
    if "VIOLATED" not in verdict:
        return ""
    ids = row.get("invariants_violated")
    if isinstance(ids, list):
        parts = [str(item).strip() for item in ids if str(item).strip()]
        if parts:
            return "; ".join(parts)
    return str(row.get("invariant") or "").strip()


def _recommendation(row: dict[str, Any], payload: dict[str, Any]) -> str:
    if row.get("fileable_finding"):
        title = str(row.get("title_candidate") or "").strip()
        drill = str(
            ((payload.get("compose_queue_updates") or {}).get("DRILL-4_update"))
            if isinstance(payload.get("compose_queue_updates"), dict)
            else ""
        ).strip()
        if title and drill:
            return f"{title}. {drill}"
        if title:
            return title
    for key in ("observations", "notes", "result"):
        value = row.get(key)
        if isinstance(value, list):
            for item in value:
                text = str(item).strip()
                if text:
                    return text
        text = str(value or "").strip()
        if text:
            return text
    return ""


def extract_fuzz_target_rows(
    payload: dict[str, Any],
    source_path: Path,
    ws: str | None = None,
    limit: int | None = None,
) -> list[dict[str, Any]]:
    if str(payload.get("schema") or "") != RESULTS_SCHEMA:
        raise ValueError(
            f"{source_path} schema mismatch: expected {RESULTS_SCHEMA}, "
            f"got {payload.get('schema')!r}"
        )
    target_rows = payload.get("fuzz_targets")
    if not isinstance(target_rows, list):
        raise ValueError(f"{source_path} missing fuzz_targets[]")
    source_workspace = ws or str(payload.get("workspace") or "")
    out: list[dict[str, Any]] = []
    for item in target_rows[: limit if limit and limit > 0 else None]:
        if not isinstance(item, dict):
            continue
        target_path = _target_path(item)
        last_run_sha = _git_head_for_path(target_path)
        invariant_violated = _invariant_violated(item)
        verification_tier = (
            DEFAULT_TIER_WITH_SHA if last_run_sha else DEFAULT_TIER_NO_SHA
        )
        out.append(
            {
                "schema_version": SCHEMA_VERSION,
                "workspace": workspace_slug(source_workspace),
                "source_lane": str(payload.get("lane") or "").strip(),
                "source_artifact": str(source_path),
                "target_id": str(item.get("id") or "").strip(),
                "target_name": str(item.get("name") or "").strip(),
                "target_path": target_path,
                "harness_type": _harness_type(item),
                "invariant_violated_in_run": invariant_violated,
                "last_run_sha": last_run_sha,
                "recommendation": _recommendation(item, payload),
                "verification_tier": verification_tier,
                "verdict": str(item.get("verdict") or "").strip(),
                "fileable_finding": bool(item.get("fileable_finding")),
            }
        )
    return out


def extract_fuzz_target_rows_from_file(
    path: Path,
    ws: str | None = None,
    limit: int | None = None,
) -> list[dict[str, Any]]:
    return extract_fuzz_target_rows(_read_json(path), path, ws=ws, limit=limit)


def emit_fuzz_targets(output_path: Path, rows: list[dict[str, Any]]) -> dict[str, Any]:
    if not rows:
        return {
            "path": str(output_path),
            "targets_found": 0,
            "rows_appended": 0,
            "rows_existing": 0,
        }
    existing: set[tuple[str, str, str, str]] = set()
    existing_count = 0
    if output_path.exists():
        with output_path.open("r", encoding="utf-8") as fh:
            for raw in fh:
                raw = raw.strip()
                if not raw:
                    continue
                try:
                    row = json.loads(raw)
                except json.JSONDecodeError:
                    continue
                if not isinstance(row, dict):
                    continue
                existing_count += 1
                existing.add(
                    (
                        str(row.get("source_lane") or ""),
                        str(row.get("target_id") or ""),
                        str(row.get("target_path") or ""),
                        str(row.get("last_run_sha") or ""),
                    )
                )
    output_path.parent.mkdir(parents=True, exist_ok=True)
    appended = 0
    with output_path.open("a", encoding="utf-8") as fh:
        for row in rows:
            key = (
                str(row.get("source_lane") or ""),
                str(row.get("target_id") or ""),
                str(row.get("target_path") or ""),
                str(row.get("last_run_sha") or ""),
            )
            if key in existing:
                continue
            fh.write(json.dumps(row, sort_keys=True) + "\n")
            existing.add(key)
            appended += 1
    return {
        "path": str(output_path),
        "targets_found": len(rows),
        "rows_appended": appended,
        "rows_existing": existing_count,
    }


# ---------------------------------------------------------------------------
# In-scope worklist generator: <ws>/.auditooor/fuzz_targets.jsonl
#
# WHY (orphaned-worklist fix, 2026-07-02, generic/all-language): the run-result
# emitter above only produces rows once a campaign has RUN. Nothing told the
# auditor which in-scope assets still NEED a campaign. This generator joins the
# authoritative in-scope surface (inscope_units.jsonl) against the value-moving
# function set (value_moving_functions.json) and emits one obligation row per
# value-moving in-scope (asset x fn-cluster) needing a campaign, so the auditor
# has a KNOWN worklist to drain. Language-agnostic: it keys on file+function
# records, never on a Solidity idiom.
# ---------------------------------------------------------------------------

def worklist_output_path(ws_root: Path) -> Path:
    """Per-workspace fuzz_targets.jsonl (the worklist), NOT the corpus_tags copy.

    This is the artifact the completeness-check + runbook step read. ``ws_root``
    is the workspace directory itself (e.g. .../strata), not the auditooor repo.
    """
    return Path(ws_root) / ".auditooor" / "fuzz_targets.jsonl"


def _fn_cluster_key(function: str) -> str:
    """Cluster key for a function name (language-neutral).

    Groups by the lowercased alphanumeric function name so a value-moving unit is
    one obligation regardless of overload/signature noise. Empty -> 'file-level'.
    """
    key = re.sub(r"[^a-z0-9]+", "", str(function or "").lower())
    return key or "file-level"


def _read_jsonl(path: Path) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return rows
    for line in text.splitlines():
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


def _inscope_basenames_and_relpaths(ws_root: Path) -> tuple[set[str], set[str], bool]:
    """(basenames, relpaths, present) from <ws>/.auditooor/inscope_units.jsonl.

    ``present`` is False when the manifest is absent/empty so a caller can
    fail-open (no worklist to build) rather than treating an empty authority as
    "nothing is in scope" in a misleading way.
    """
    rows = _read_jsonl(ws_root / ".auditooor" / "inscope_units.jsonl")
    basenames: set[str] = set()
    relpaths: set[str] = set()
    for rec in rows:
        f = str(rec.get("file", "") or "").replace("\\", "/").strip().lstrip("./")
        if not f:
            continue
        relpaths.add(f)
        basenames.add(Path(f).name)
    return basenames, relpaths, bool(basenames)


def _load_value_moving(ws_root: Path, vmf_path: Path | None = None) -> list[dict[str, Any]]:
    path = vmf_path or (ws_root / ".auditooor" / "value_moving_functions.json")
    try:
        payload = json.loads(path.read_text(encoding="utf-8", errors="replace"))
    except (OSError, json.JSONDecodeError, ValueError):
        return []
    if isinstance(payload, dict):
        fns = payload.get("functions")
        return [f for f in fns if isinstance(f, dict)] if isinstance(fns, list) else []
    if isinstance(payload, list):
        return [f for f in payload if isinstance(f, dict)]
    return []


def build_inscope_worklist_rows(
    ws_root: Path,
    ws_slug: str,
    vmf_path: Path | None = None,
) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    """Join inscope_units.jsonl x value_moving_functions.json -> worklist rows.

    Returns (rows, diagnostics). One row per value-moving IN-SCOPE (file x
    fn-cluster) that needs a campaign. A value-moving function whose file is NOT
    in the in-scope manifest is dropped (out of scope). Completeness-safe: if the
    in-scope manifest is ABSENT it returns [] + a diagnostic reason (no worklist
    can be asserted) rather than emitting every value-mover unfiltered.
    """
    basenames, relpaths, present = _inscope_basenames_and_relpaths(ws_root)
    vmf = _load_value_moving(ws_root, vmf_path)
    diag = {
        "inscope_present": present,
        "value_moving_count": len(vmf),
        "dropped_out_of_scope": 0,
        "clusters": 0,
    }
    if not present:
        diag["reason"] = "inscope_units.jsonl absent/empty - cannot assert a worklist"
        return [], diag
    if not vmf:
        diag["reason"] = "value_moving_functions.json empty - no value-moving surface"
        return [], diag
    # cluster by (relpath-or-basename, fn-cluster-key)
    clusters: dict[tuple[str, str], dict[str, Any]] = {}
    dropped = 0
    for rec in vmf:
        f = str(rec.get("file", "") or "").replace("\\", "/").strip().lstrip("./")
        if not f:
            continue
        bn = Path(f).name
        in_scope = (f in relpaths) or (bn in basenames)
        if not in_scope:
            dropped += 1
            continue
        fn = str(rec.get("function", "") or "").strip()
        ckey = _fn_cluster_key(fn)
        anchor = f if f in relpaths else bn
        key = (anchor, ckey)
        entry = clusters.get(key)
        if entry is None:
            entry = {
                "asset_path": anchor,
                "asset_basename": bn,
                "fn_cluster": ckey,
                "functions": [],
                "languages": set(),
            }
            clusters[key] = entry
        if fn and fn not in entry["functions"]:
            entry["functions"].append(fn)
        lang = str(rec.get("language", "") or "").strip().lower()
        if lang:
            entry["languages"].add(lang)
    diag["dropped_out_of_scope"] = dropped
    diag["clusters"] = len(clusters)
    rows: list[dict[str, Any]] = []
    for (anchor, ckey), entry in sorted(clusters.items()):
        target_id = f"{anchor}::{ckey}"
        rows.append(
            {
                "schema_version": WORKLIST_SCHEMA_VERSION,
                "workspace": ws_slug,
                "target_id": target_id,
                "asset_path": entry["asset_path"],
                "asset_basename": entry["asset_basename"],
                "fn_cluster": entry["fn_cluster"],
                "functions": sorted(entry["functions"]),
                "languages": sorted(entry["languages"]),
                "needs_campaign": True,
                "verdict": "campaign-pending",
            }
        )
    return rows, diag


def emit_inscope_worklist(
    ws_root: Path,
    ws_slug: str,
    vmf_path: Path | None = None,
    out_path: Path | None = None,
) -> dict[str, Any]:
    """Write the worklist to <ws>/.auditooor/fuzz_targets.jsonl (overwrite).

    Overwrite (not append) semantics: the worklist is a DERIVED view of the
    current in-scope x value-moving surface, so a fresh emit reflects the latest
    scope. Idempotent for a fixed input.
    """
    rows, diag = build_inscope_worklist_rows(ws_root, ws_slug, vmf_path)
    out = out_path or worklist_output_path(ws_root)
    if not rows:
        # Do NOT create an empty file when there is no worklist to assert; leave
        # the artifact absent so the completeness-check/runbook see "not built".
        return {
            "path": str(out),
            "rows_written": 0,
            "written": False,
            **diag,
        }
    out.parent.mkdir(parents=True, exist_ok=True)
    with out.open("w", encoding="utf-8") as fh:
        for row in rows:
            fh.write(json.dumps(row, sort_keys=True) + "\n")
    return {
        "path": str(out),
        "rows_written": len(rows),
        "written": True,
        **diag,
    }
