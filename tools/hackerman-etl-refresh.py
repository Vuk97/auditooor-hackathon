#!/usr/bin/env python3
"""Safely refresh hackerman_record v1 corpus records and indices.

The refresh always writes ETL output to a staging directory first, validates
that staged YAML, checks filename collisions against the live tag directory,
then copies only new files and rebuilds indices. Existing same-content files
are treated as idempotent; existing different-content files fail the run.
"""
from __future__ import annotations

import argparse
import importlib.util
import json
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Any


REPO_ROOT = Path(__file__).resolve().parent.parent
DEFAULT_TAG_DIR = REPO_ROOT / "audit" / "corpus_tags" / "tags"
DEFAULT_INDEX_DIR = REPO_ROOT / "audit" / "corpus_tags" / "index"
DEFAULT_QUALITY_OUT = REPO_ROOT / "audit" / "corpus_tags" / "derived" / "record_quality.jsonl"
DEFAULT_CROSS_LANGUAGE_OUT = REPO_ROOT / "audit" / "corpus_tags" / "derived" / "cross_language_analogues.jsonl"
DEFAULT_PROOF_HARDENING_OUT = REPO_ROOT / "audit" / "corpus_tags" / "derived" / "proof_hardening.jsonl"
DEFAULT_REPORTS_DIR = REPO_ROOT / "reports"
DEFAULT_CORPUS_DIR = REPO_ROOT / "reference" / "corpus_mined"
DEFAULT_AUDITS_ROOT = Path("~/audits").expanduser()
DEFAULT_PATTERNS_DIR = REPO_ROOT / "patterns"
DEFAULT_DSL_DIR = REPO_ROOT / "reference" / "patterns.dsl"
DEFAULT_FINDINGS_GO_PATHS = tuple(sorted((REPO_ROOT / "reference").glob("findings_go*.jsonl")))
DEFAULT_SOLODIT_SPEC_DIRS = (
    REPO_ROOT / "detectors" / "_specs" / "drafts_solodit",
    REPO_ROOT / "detectors" / "_specs" / "drafts_solodit_move",
    REPO_ROOT / "detectors" / "_specs" / "drafts_code4rena_rust",
    REPO_ROOT / "detectors" / "_specs" / "drafts_cyfrin_rust",
    REPO_ROOT / "detectors" / "_specs" / "drafts_sherlock_rust",
    REPO_ROOT / "detectors" / "_specs" / "drafts_trailofbits_rust",
    REPO_ROOT / "detectors" / "_specs" / "drafts_rust_soroban",
    REPO_ROOT / "detectors" / "_specs" / "drafts_ottersec_solana",
)
SCHEMA_VERSION = "auditooor.hackerman_record.v1"


def _load_validator() -> Any:
    spec = importlib.util.spec_from_file_location(
        "_hackerman_refresh_validator",
        str(REPO_ROOT / "tools" / "hackerman-record-validate.py"),
    )
    mod = importlib.util.module_from_spec(spec)
    assert spec.loader
    spec.loader.exec_module(mod)
    return mod


_VALIDATOR = _load_validator()


def _run_json(cmd: list[str]) -> dict[str, Any]:
    proc = subprocess.run(
        cmd,
        cwd=REPO_ROOT,
        capture_output=True,
        text=True,
        check=False,
    )
    if proc.returncode != 0:
        raise RuntimeError(
            f"command failed ({proc.returncode}): {' '.join(cmd)}\n"
            f"stdout:\n{proc.stdout[-2000:]}\n"
            f"stderr:\n{proc.stderr[-2000:]}"
        )
    try:
        return json.loads(proc.stdout or "{}")
    except json.JSONDecodeError as exc:
        raise RuntimeError(f"command did not emit JSON: {' '.join(cmd)}\n{proc.stdout[-2000:]}") from exc


def _run(cmd: list[str]) -> None:
    proc = subprocess.run(
        cmd,
        cwd=REPO_ROOT,
        capture_output=True,
        text=True,
        check=False,
    )
    if proc.returncode != 0:
        raise RuntimeError(
            f"command failed ({proc.returncode}): {' '.join(cmd)}\n"
            f"stdout:\n{proc.stdout[-2000:]}\n"
            f"stderr:\n{proc.stderr[-2000:]}"
        )


def discover_workspaces(audits_root: Path, explicit: list[str]) -> list[Path]:
    if explicit:
        return [Path(item).expanduser().resolve() for item in explicit]
    if not audits_root.is_dir():
        return []
    workspaces: list[Path] = []
    for path in sorted(audits_root.iterdir()):
        if not path.is_dir():
            continue
        if (path / "prior_audits").is_dir() or (path / "extracted_audits").is_dir():
            workspaces.append(path.resolve())
    return workspaces


def staged_yaml(stage_dir: Path) -> list[Path]:
    return sorted(list(stage_dir.glob("*.yaml")) + list(stage_dir.glob("*.yml")))


def load_hackerman_identity(path: Path) -> dict[str, str]:
    try:
        doc = _VALIDATOR.load_yaml(path)
    except Exception:
        return {}
    if not isinstance(doc, dict) or doc.get("schema_version") != SCHEMA_VERSION:
        return {}
    return {
        "record_id": str(doc.get("record_id") or ""),
        "source_audit_ref": str(doc.get("source_audit_ref") or ""),
    }


def collision_report(stage_dir: Path, tag_dir: Path) -> dict[str, Any]:
    same: list[str] = []
    different: list[str] = []
    new: list[str] = []
    for staged in staged_yaml(stage_dir):
        live = tag_dir / staged.name
        if not live.exists():
            new.append(staged.name)
            continue
        if live.read_bytes() == staged.read_bytes():
            same.append(staged.name)
        else:
            different.append(staged.name)
    return {
        "new": len(new),
        "same_content_existing": len(same),
        "different_content_collisions": len(different),
        "different_collision_files": different[:50],
    }


def identity_collision_report(stage_dir: Path, tag_dir: Path) -> dict[str, Any]:
    stage_files = staged_yaml(stage_dir)
    live_files = staged_yaml(tag_dir) if tag_dir.is_dir() else []
    staged_by_field: dict[str, dict[str, list[str]]] = {"record_id": {}, "source_audit_ref": {}}
    live_by_field: dict[str, dict[str, list[str]]] = {"record_id": {}, "source_audit_ref": {}}

    for path in stage_files:
        identity = load_hackerman_identity(path)
        for field in staged_by_field:
            value = identity.get(field, "")
            if value:
                staged_by_field[field].setdefault(value, []).append(path.name)
    for path in live_files:
        identity = load_hackerman_identity(path)
        for field in live_by_field:
            value = identity.get(field, "")
            if value:
                live_by_field[field].setdefault(value, []).append(path.name)

    staged_duplicates: list[str] = []
    live_conflicts: list[str] = []
    for field, values in staged_by_field.items():
        for value, filenames in values.items():
            if len(filenames) > 1:
                staged_duplicates.append(f"{field}:{value}:{','.join(sorted(filenames)[:5])}")
            for live_name in live_by_field[field].get(value, []):
                if live_name not in filenames:
                    live_conflicts.append(
                        f"{field}:{value}:staged={','.join(sorted(filenames)[:5])}:live={live_name}"
                    )
    return {
        "staged_duplicate_identities": len(staged_duplicates),
        "live_identity_conflicts": len(live_conflicts),
        "staged_duplicate_identity_files": staged_duplicates[:50],
        "live_identity_conflict_files": live_conflicts[:50],
    }


def copy_new_records(stage_dir: Path, tag_dir: Path) -> int:
    tag_dir.mkdir(parents=True, exist_ok=True)
    copied = 0
    for staged in staged_yaml(stage_dir):
        live = tag_dir / staged.name
        if live.exists():
            continue
        shutil.copy2(staged, live)
        copied += 1
    return copied


def count_index_rows(index_dir: Path) -> dict[str, int]:
    counts: dict[str, int] = {}
    for path in sorted(index_dir.glob("by_*.jsonl")):
        with path.open("r", encoding="utf-8") as fh:
            counts[path.name] = sum(1 for _ in fh)
    return counts


def _run_json_best_effort(cmd: list[str]) -> dict[str, Any]:
    """Run a sub-stage that should not abort the whole refresh on failure.

    Returns the parsed JSON summary on success, or a ``{"status": ...}``
    breadcrumb on failure. The findings->invariant lift is a downstream
    enrichment, not a corpus-integrity step, so a transient failure must not
    discard the freshly-rebuilt indices.
    """
    proc = subprocess.run(
        cmd,
        cwd=REPO_ROOT,
        capture_output=True,
        text=True,
        check=False,
    )
    if proc.returncode != 0:
        return {
            "status": "failed",
            "returncode": proc.returncode,
            "stderr_tail": proc.stderr[-1000:],
            "stdout_tail": proc.stdout[-1000:],
        }
    try:
        return {"status": "ok", **json.loads(proc.stdout or "{}")}
    except json.JSONDecodeError:
        return {"status": "ok", "raw_stdout_tail": proc.stdout[-1000:]}


def findings_to_invariants(
    *,
    index_dir: Path,
    derived_dir: Path,
    repo_root: Path,
    records_cap: int,
) -> dict[str, Any]:
    """Incremental findings->invariant fuel lift (thin, resumable).

    Step A: ``llm-extract-invariants.py --mode hand-extract --incremental``
    over the freshly-rebuilt ``by_attack_class.jsonl`` index, scoped by a
    watermark so only NEW findings are lifted into
    ``invariants_extracted.jsonl``. Deterministic (no LLM); a watermark is
    emitted so the run is resumable.

    Step A2: ``incident-derived-invariant-to-extracted.py`` forwards the
    QA-accepted ``derived_invariant`` fields from the curated incident corpus
    into the same ``invariants_extracted.jsonl`` (canonical layout only), so
    incident-grounded invariants are lifted into fuel by the same audit-ext pass.

    Step B: ``lane-invariant-audit-ext.py`` lifts the audited (non-quarantine)
    rows into ``invariants_pilot_audited.jsonl`` - the file
    ``corpus-driven-hunt.py`` loads as per-fn invariant fuel. The audit-ext
    quarantine classifier is the R80 guard: vacuous / malformed invariants are
    marked FALSE-POSITIVE and never become fuel.
    """
    index_path = index_dir / "by_attack_class.jsonl"
    extracted_out = derived_dir / "invariants_extracted.jsonl"
    failed_out = derived_dir / "invariants_failed_extract.jsonl"
    watermark = derived_dir / ".invariant_extract_watermark"
    summary: dict[str, Any] = {
        "index_path": str(index_path),
        "extracted_out": str(extracted_out),
        "watermark": str(watermark),
    }
    if not index_path.is_file():
        summary["status"] = "skipped"
        summary["reason"] = "missing_by_attack_class_index"
        return summary
    summary["extract"] = _run_json_best_effort(
        [
            sys.executable,
            "tools/llm-extract-invariants.py",
            "--mode",
            "hand-extract",
            "--incremental",
            "--records",
            str(records_cap),
            "--index",
            str(index_path),
            "--output",
            str(extracted_out),
            "--failed",
            str(failed_out),
            "--watermark",
            str(watermark),
        ]
    )
    # Step A2: forward QA-accepted `derived_invariant` fields from the curated
    # incident corpus (defimon/rekt/darknavy) into the SAME
    # invariants_extracted.jsonl, BEFORE the audit-ext lift, so incident-grounded
    # invariants become per-fn fuel alongside the findings-derived ones. The
    # producer is otherwise wired nowhere even though its output file is heavily
    # consumed (evm-engine-harness-author, novel-vector-invariant-miner,
    # batch-shape-cluster-predicates, semantic-predicate-gate, vault MCP). It
    # writes ONLY the canonical repo's derived/invariants_extracted.jsonl, so it
    # is gated to the canonical layout - a non-canonical test/bespoke root is
    # skipped rather than scribbling the shared corpus. Best-effort: a transient
    # failure here must not discard the freshly-rebuilt indices.
    canonical_extracted = REPO_ROOT / "audit" / "corpus_tags" / "derived" / "invariants_extracted.jsonl"
    if extracted_out.resolve() == canonical_extracted.resolve():
        summary["incident_derived"] = _run_json_best_effort(
            [
                sys.executable,
                "tools/incident-derived-invariant-to-extracted.py",
            ]
        )
    else:
        summary["incident_derived"] = {
            "status": "skipped",
            "reason": "non_canonical_derived_dir_producer_writes_canonical_only",
            "extracted_out": str(extracted_out),
            "canonical_extracted": str(canonical_extracted),
        }
    summary["audit_ext"] = _run_json_best_effort(
        [
            sys.executable,
            "tools/lane-invariant-audit-ext.py",
            "--root",
            str(repo_root),
        ]
    )
    summary["status"] = "ok"
    return summary


def refresh(args: argparse.Namespace) -> dict[str, Any]:
    tag_dir = Path(args.tag_dir).expanduser().resolve()
    index_dir = Path(args.index_dir).expanduser().resolve()
    quality_out = Path(args.quality_out).expanduser().resolve()
    cross_language_out = Path(args.cross_language_out).expanduser().resolve()
    proof_hardening_out = Path(args.proof_hardening_out).expanduser().resolve()
    reports_dir = Path(args.reports_dir).expanduser().resolve()
    corpus_dir = Path(args.corpus_dir).expanduser().resolve()
    audits_root = Path(args.audits_root).expanduser().resolve()
    patterns_dirs = [Path(item).expanduser().resolve() for item in args.patterns_dir]
    dsl_dirs = [Path(item).expanduser().resolve() for item in args.dsl_dir]
    solodit_spec_dirs = [Path(item).expanduser().resolve() for item in args.solodit_spec_dir]
    findings_go_paths = [Path(item).expanduser().resolve() for item in args.findings_go_path]
    stage_root = Path(args.stage_dir).expanduser().resolve() if args.stage_dir else Path(tempfile.mkdtemp(prefix="hackerman-refresh."))
    stage_root.mkdir(parents=True, exist_ok=True)

    summaries: dict[str, Any] = {}
    if not args.skip_verdict_tags:
        summaries["verdict_tags"] = _run_json(
            [
                sys.executable,
                "tools/hackerman-etl-from-verdict-tags.py",
                "--tag-dir",
                str(tag_dir),
                "--out-dir",
                str(stage_root),
                "--json-summary",
            ]
        )
    if not args.skip_git_mining:
        # Wave-2 #3: backfill the REAL diff for every shaped commit BEFORE the ETL, so
        # git-mining classifies from changed-lines instead of the commit subject (which
        # dumped ~75% of records into generic security-shaped-commit and ingested noise as
        # theft vulns). Best-effort: idempotent (skips rows that already carry a diff) and
        # skips private/unreachable repos with a logged reason - never aborts the refresh.
        if not args.skip_git_mining_diff_backfill:
            summaries["git_mining_diff_backfill"] = _run_json_best_effort(
                [
                    sys.executable,
                    "tools/git-mining-diff-backfill.py",
                    "--all",
                ]
            )
        summaries["git_mining"] = _run_json(
            [
                sys.executable,
                "tools/hackerman-etl-from-git-mining.py",
                "--reports-dir",
                str(reports_dir),
                "--out-dir",
                str(stage_root),
                "--json-summary",
            ]
        )
    if not args.skip_corpus_mined:
        summaries["corpus_mined"] = _run_json(
            [
                sys.executable,
                "tools/hackerman-etl-from-corpus-mined.py",
                "--corpus-dir",
                str(corpus_dir),
                "--out-dir",
                str(stage_root),
                "--json-summary",
            ]
        )
    if not args.skip_solodit_specs:
        cmd = [
            sys.executable,
            "tools/hackerman-etl-from-solodit-specs.py",
            "--out-dir",
            str(stage_root),
            "--json-summary",
        ]
        for spec_dir in solodit_spec_dirs or DEFAULT_SOLODIT_SPEC_DIRS:
            cmd.extend(["--spec-dir", str(spec_dir)])
        summaries["solodit_specs"] = _run_json(cmd)
    if not args.skip_findings_go:
        cmd = [
            sys.executable,
            "tools/hackerman-etl-from-findings-go.py",
            "--out-dir",
            str(stage_root),
            "--json-summary",
        ]
        for path in findings_go_paths or DEFAULT_FINDINGS_GO_PATHS:
            cmd.extend(["--path", str(path)])
        summaries["findings_go"] = _run_json(cmd)
    if not args.skip_solidity_fork_patterns:
        cmd = [
            sys.executable,
            "tools/hackerman-etl-from-solidity-fork-patterns.py",
            "--out-dir",
            str(stage_root),
            "--json-summary",
        ]
        for patterns_dir in patterns_dirs or [DEFAULT_PATTERNS_DIR]:
            cmd.extend(["--patterns-dir", str(patterns_dir)])
        for dsl_dir in dsl_dirs or [DEFAULT_DSL_DIR]:
            cmd.extend(["--dsl-dir", str(dsl_dir)])
        if args.include_pattern_dsl:
            cmd.append("--include-dsl")
        summaries["solidity_fork_patterns"] = _run_json(cmd)
    workspaces = []
    if not args.skip_prior_audits:
        workspaces = discover_workspaces(audits_root, args.workspace or [])
        if workspaces:
            cmd = [
                sys.executable,
                "tools/hackerman-etl-from-prior-audits.py",
                "--out-dir",
                str(stage_root),
                "--json-summary",
            ]
            for workspace in workspaces:
                cmd.extend(["--workspace", str(workspace)])
            summaries["prior_audits"] = _run_json(cmd)
        else:
            summaries["prior_audits"] = {
                "records_emitted": 0,
                "documents_scanned": 0,
                "segments_seen": 0,
            }

    _run(
        [
            sys.executable,
            "tools/hackerman-record-validate.py",
            "--validate-dir",
            str(stage_root),
            "--quiet",
        ]
    )
    collisions = collision_report(stage_root, tag_dir)
    if collisions["different_content_collisions"]:
        raise RuntimeError(
            "staged records collide with different live content: "
            + ", ".join(collisions["different_collision_files"])
        )
    identity_collisions = identity_collision_report(stage_root, tag_dir)
    if identity_collisions["staged_duplicate_identities"] or identity_collisions["live_identity_conflicts"]:
        raise RuntimeError(
            "staged records collide by record_id/source_audit_ref: "
            + ", ".join(
                identity_collisions["staged_duplicate_identity_files"]
                + identity_collisions["live_identity_conflict_files"]
            )
        )

    copied = 0
    index_counts: dict[str, int] = {}
    if args.dry_run:
        with tempfile.TemporaryDirectory(prefix="hackerman-refresh-index.") as td:
            tmp_index = Path(td)
            if index_dir.is_dir():
                for path in index_dir.glob("*.jsonl"):
                    shutil.copy2(path, tmp_index / path.name)
            _run(
                [
                    sys.executable,
                    "tools/hackerman-index-build.py",
                    "--tag-dir",
                    str(stage_root),
                    "--index-dir",
                    str(tmp_index),
                    "--quiet",
                    *([] if args.preserve_existing else ["--no-preserve-existing"]),
                ]
            )
            index_counts = count_index_rows(tmp_index)
    else:
        copied = copy_new_records(stage_root, tag_dir)
        _run(
            [
                sys.executable,
                "tools/hackerman-record-validate.py",
                "--validate-dir",
                str(tag_dir),
                "--quiet",
            ]
        )
        _run(
            [
                sys.executable,
                "tools/hackerman-index-build.py",
                "--tag-dir",
                str(tag_dir),
                "--index-dir",
                str(index_dir),
                "--quiet",
                *([] if args.preserve_existing else ["--no-preserve-existing"]),
            ]
        )
        quality_summary = _run_json(
            [
                sys.executable,
                "tools/hackerman-record-quality.py",
                "--tag-dir",
                str(tag_dir),
                "--out",
                str(quality_out),
                "--json-summary",
            ]
        )
        _run(
            [
                sys.executable,
                "tools/hackerman-cross-language-analogues.py",
                "--tags-dir",
                str(tag_dir),
                "--out",
                str(cross_language_out),
            ]
        )
        proof_hardening_summary = _run_json(
            [
                sys.executable,
                "tools/hackerman-proof-hardening.py",
                "--tag-dir",
                str(tag_dir),
                "--out",
                str(proof_hardening_out),
                "--json-summary",
            ]
        )
        index_counts = count_index_rows(index_dir)

    findings_to_invariants_summary: dict[str, Any] = {}
    if not args.dry_run and not args.skip_findings_to_invariants:
        # Derive the repo root whose audit/corpus_tags/derived/ holds the fuel
        # files. In the canonical layout index_dir == <root>/audit/corpus_tags/
        # index, so its third parent is the root and the derived dir is its
        # sibling. When the index lives in a non-canonical place (tests /
        # bespoke runs) we REFUSE to guess the root - defaulting to REPO_ROOT
        # would scribble the canonical corpus from an unrelated --index-dir
        # run. The operator must then pin it explicitly via
        # --findings-invariants-root.
        fi_root: Path | None = None
        if args.findings_invariants_root:
            fi_root = Path(args.findings_invariants_root).expanduser().resolve()
        elif index_dir.name == "index" and index_dir.parent.name == "corpus_tags":
            fi_root = index_dir.parent.parent.parent
        if fi_root is None:
            findings_to_invariants_summary = {
                "status": "skipped",
                "reason": "non_canonical_index_dir_no_explicit_root",
                "index_dir": str(index_dir),
                "remediation": (
                    "pass --findings-invariants-root <repo-root> to lift "
                    "findings into a non-canonical layout's derived dir"
                ),
            }
        else:
            derived_dir = fi_root / "audit" / "corpus_tags" / "derived"
            findings_to_invariants_summary = findings_to_invariants(
                index_dir=index_dir,
                derived_dir=derived_dir,
                repo_root=fi_root,
                records_cap=int(args.findings_invariants_records_cap),
            )

    payload = {
        "schema": "auditooor.hackerman_etl_refresh.v1",
        "dry_run": bool(args.dry_run),
        "stage_dir": str(stage_root),
        "tag_dir": str(tag_dir),
        "index_dir": str(index_dir),
        "quality_out": str(quality_out),
        "cross_language_out": str(cross_language_out),
        "proof_hardening_out": str(proof_hardening_out),
        "workspaces": [str(path) for path in workspaces],
        "summaries": summaries,
        "staged_yaml": len(staged_yaml(stage_root)),
        "collisions": collisions,
        "identity_collisions": identity_collisions,
        "copied": copied,
        "preserve_existing": bool(args.preserve_existing),
        "index_counts": index_counts,
    }
    if not args.dry_run:
        payload["record_quality"] = quality_summary
        payload["proof_hardening"] = proof_hardening_summary
        payload["findings_to_invariants"] = findings_to_invariants_summary
    return payload


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--tag-dir", default=str(DEFAULT_TAG_DIR))
    parser.add_argument("--index-dir", default=str(DEFAULT_INDEX_DIR))
    parser.add_argument("--quality-out", default=str(DEFAULT_QUALITY_OUT))
    parser.add_argument("--cross-language-out", default=str(DEFAULT_CROSS_LANGUAGE_OUT))
    parser.add_argument("--proof-hardening-out", default=str(DEFAULT_PROOF_HARDENING_OUT))
    parser.add_argument("--reports-dir", default=str(DEFAULT_REPORTS_DIR))
    parser.add_argument("--corpus-dir", default=str(DEFAULT_CORPUS_DIR))
    parser.add_argument("--audits-root", default=str(DEFAULT_AUDITS_ROOT))
    parser.add_argument("--patterns-dir", action="append", default=[])
    parser.add_argument("--dsl-dir", action="append", default=[])
    parser.add_argument("--solodit-spec-dir", action="append", default=[])
    parser.add_argument("--findings-go-path", action="append", default=[])
    parser.add_argument("--workspace", action="append", default=[])
    parser.add_argument("--stage-dir", default="")
    parser.add_argument("--dry-run", action="store_true")
    parser.add_argument("--no-preserve-existing", dest="preserve_existing", action="store_false", default=True)
    parser.add_argument("--skip-verdict-tags", action="store_true")
    parser.add_argument("--skip-git-mining", action="store_true")
    parser.add_argument("--skip-git-mining-diff-backfill", action="store_true",
                        help="skip the pre-ETL diff backfill (wave-2 #3); the ETL then "
                             "classifies from commit subjects only (degraded)")
    parser.add_argument("--skip-corpus-mined", action="store_true")
    parser.add_argument("--skip-solodit-specs", action="store_true")
    parser.add_argument("--skip-findings-go", action="store_true")
    parser.add_argument("--skip-solidity-fork-patterns", action="store_true")
    parser.add_argument("--include-pattern-dsl", action="store_true")
    parser.add_argument("--skip-prior-audits", action="store_true")
    parser.add_argument(
        "--skip-findings-to-invariants",
        action="store_true",
        help=(
            "Skip the incremental findings->invariant fuel lift that runs "
            "after the index rebuild."
        ),
    )
    parser.add_argument(
        "--findings-invariants-root",
        default="",
        help=(
            "Repo root whose audit/corpus_tags/derived/ receives the lifted "
            "invariants. Defaults to the root inferred from --index-dir."
        ),
    )
    parser.add_argument(
        "--findings-invariants-records-cap",
        type=int,
        default=50000,
        help=(
            "Safety cap on index rows scanned per incremental lift run "
            "(watermark makes it resumable across runs)."
        ),
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        payload = refresh(args)
    except Exception as exc:  # noqa: BLE001 - CLI should return actionable text.
        print(f"hackerman-etl-refresh: {exc}", file=sys.stderr)
        return 1
    print(json.dumps(payload, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
