#!/usr/bin/env python3
"""Mutating runner for the v1 -> v1.1 hackerman schema migration (Wave-2 W2.1).

Companion to the read-only ``tools/hackerman-schema-migration-dry-run.py``.
Walks ``audit/corpus_tags/tags/`` (both JSON and YAML records), calls
``migrate_record()`` from ``tools/hackerman-schema-v1-to-v1.1-migrator.py`` for
each parsed v1 hackerman record, and writes the migrated record back to the
same path using an atomic ``tempfile + os.replace`` strategy.

Safety posture (per WAVE2_W21_SCHEMA_MIGRATION_RUNNER_SPEC_2026-05-16.md):

  * Default mode is **dry-run** -- no writes occur unless the operator passes
    ``--apply`` (subtree-scoped) or ``--ready-for-full`` (full corpus).
  * Writes are atomic per-file. A SIGKILL between writes leaves either the
    pre-migration v1 file or the post-migration v1.1 file on disk; never a
    half-written record.
  * No git operations. The runner is filesystem-only. The operator stages
    and commits the corpus diff under an explicit pathspec.
  * Idempotent. Re-running the runner over an already-migrated corpus is a
    no-op (counts ``already_v11`` for each previously-migrated record).

Phased rollout (operator-driven):

  Phase 1 (re-confirm preview, no mutation)::

      python3 tools/hackerman-schema-v1-to-v1.1-runner.py \\
          --tags-dir audit/corpus_tags/tags

      # equivalent: --dry-run (which is the default when --apply and
      # --ready-for-full are both absent).

  Phase 2 (pilot subtree, smallest first)::

      python3 tools/hackerman-schema-v1-to-v1.1-runner.py \\
          --tags-dir audit/corpus_tags/tags \\
          --subtree erc4337_smart_wallet_advisories \\
          --apply \\
          --report-out docs/HACKERMAN_SCHEMA_V1_1_MIGRATION_RUN_PHASE2_2026-05-16.md

  Phase 3 (full corpus)::

      python3 tools/hackerman-schema-v1-to-v1.1-runner.py \\
          --tags-dir audit/corpus_tags/tags \\
          --ready-for-full \\
          --report-out docs/HACKERMAN_SCHEMA_V1_1_MIGRATION_RUN_PHASE3_2026-05-16.md

Exit code conventions:

  Harmonized with ``tools/wave2-w21-post-migration-validator.py`` so a single
  exit-code branch in a wrapper script can route both tools' outcomes:

  * ``0`` PASS - clean run (or dry-run with nothing to do); no validation
    failures.
  * ``1`` FAIL - records were processed but post-migration validation
    failed for at least one (records found, validation failed).
  * ``2`` ERROR - tool / input error: missing ``scan_root`` (the resolved
    tags-dir / subtree does not exist), CLI flag conflict, an unparseable
    input record, or a filesystem write failure. The error is structural
    (the operator must fix the invocation or the inputs), not a verdict
    on the corpus content.

  Pre-harmonization (Wave-2 PR-A, before this fix) the runner returned
  ``0`` for missing ``scan_root`` and ``2`` for post-migration validation
  failure, which diverged from the validator's semantics. See the
  WAVE-2 PR-A capability-gap #2 fix commit body for the migration note.
"""
from __future__ import annotations

import argparse
import datetime as _dt
import importlib.util
import io
import json
import os
import shutil
import sys
import tempfile
from pathlib import Path
from typing import Any, Callable, Dict, Iterable, List, Optional, Tuple

REPO_ROOT = Path(__file__).resolve().parent.parent
SCHEMA_VERSION_V1 = "auditooor.hackerman_record.v1"
SCHEMA_VERSION_V11 = "auditooor.hackerman_record.v1.1"
DEFAULT_TAGS_DIR = REPO_ROOT / "audit" / "corpus_tags" / "tags"


def _load_module(name: str, path: Path) -> Any:
    spec = importlib.util.spec_from_file_location(name, str(path))
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot load {path}")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


_MIGRATOR: Any = None
_VTS: Any = None
_VALIDATOR: Any = None


def _migrator() -> Any:
    global _MIGRATOR
    if _MIGRATOR is None:
        _MIGRATOR = _load_module(
            "_hackerman_schema_v1_to_v1_1_migrator_runner",
            REPO_ROOT / "tools" / "hackerman-schema-v1-to-v1.1-migrator.py",
        )
    return _MIGRATOR


def _vts() -> Any:
    global _VTS
    if _VTS is None:
        _VTS = _load_module(
            "_verdict_tag_schema_runner",
            REPO_ROOT / "tools" / "verdict-tag-schema.py",
        )
    return _VTS


def _validator() -> Any:
    global _VALIDATOR
    if _VALIDATOR is None:
        _VALIDATOR = _load_module(
            "_hackerman_record_validate_runner",
            REPO_ROOT / "tools" / "hackerman-record-validate.py",
        )
    return _VALIDATOR


# ---------------------------------------------------------------------------
# Record IO
# ---------------------------------------------------------------------------


def load_record(path: Path) -> Tuple[Optional[Dict[str, Any]], Optional[str]]:
    """Return (record_dict, error_message). One is always None.

    Supports .json and .yaml/.yml suffixes. Non-mapping top-level documents
    return an error string.
    """
    try:
        if path.suffix == ".json":
            with path.open("r", encoding="utf-8") as fh:
                doc = json.load(fh)
        else:
            doc = _vts()._load_yaml(path)
    except Exception as exc:
        return None, f"{path}: parse error: {exc}"
    if not isinstance(doc, dict):
        return None, f"{path}: top-level document must be a mapping, got {type(doc).__name__}"
    return doc, None


def is_v1_record(doc: Dict[str, Any]) -> bool:
    return doc.get("schema_version") == SCHEMA_VERSION_V1


def is_v11_record(doc: Dict[str, Any]) -> bool:
    return doc.get("schema_version") == SCHEMA_VERSION_V11


def serialize_json(record: Dict[str, Any]) -> str:
    """Canonical JSON serialization: sorted keys, indent=2, trailing newline.

    Matches the format used by the single-file migrator CLI so re-runs of
    the runner over already-canonical files produce byte-identical output.
    """
    return json.dumps(record, indent=2, sort_keys=True, ensure_ascii=False) + "\n"


def serialize_yaml(record: Dict[str, Any]) -> str:
    """Canonical YAML serialization: insertion-order keys, block style,
    unicode preserved, no line wrapping.

    Python ``dict`` preserves insertion order from 3.7+, and the migrator
    appends new fields after existing ones, so this preserves the v1 file's
    original ordering with the v1.1 additions tacked on the end. PyYAML is
    required for YAML output; an ImportError is fatal because the corpus
    contains YAML records the minimal verdict-tag fallback cannot emit.
    """
    import yaml  # type: ignore

    return yaml.safe_dump(
        record,
        sort_keys=False,
        default_flow_style=False,
        allow_unicode=True,
        width=1 << 30,
    )


def discover_records(tags_dir: Path, *, extensions: Iterable[str] = (".json", ".yaml", ".yml")) -> List[Path]:
    """Recursively walk ``tags_dir``; return a sorted deterministic list of
    candidate record paths."""
    out: List[Path] = []
    if not tags_dir.is_dir():
        return out
    exts = tuple(extensions)
    for root, _dirs, files in os.walk(tags_dir):
        for fname in files:
            if fname.endswith(exts):
                out.append(Path(root) / fname)
    out.sort()
    return out


# ---------------------------------------------------------------------------
# Atomic write
# ---------------------------------------------------------------------------


def atomic_write(path: Path, content: str) -> None:
    """Write ``content`` to ``path`` atomically.

    A NamedTemporaryFile is created in the same directory as the target,
    written, fsync'd, closed, then os.replace'd over the target. A failure
    at any point leaves the original file on disk (or, if the tempfile was
    already linked but the replace failed, the tempfile remains as
    orphaned state -- inspect it manually).
    """
    parent = path.parent
    parent.mkdir(parents=True, exist_ok=True)
    fd = None
    tmp_path: Optional[str] = None
    try:
        fd, tmp_path = tempfile.mkstemp(
            prefix=path.name + ".",
            suffix=".tmp",
            dir=str(parent),
        )
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            fd = None  # closed via the with-block
            fh.write(content)
            fh.flush()
            try:
                os.fsync(fh.fileno())
            except OSError:
                # fsync may fail on some filesystems (tmpfs); not fatal.
                pass
        os.replace(tmp_path, str(path))
        tmp_path = None
    finally:
        if fd is not None:
            try:
                os.close(fd)
            except OSError:
                pass
        if tmp_path is not None and os.path.exists(tmp_path):
            try:
                os.unlink(tmp_path)
            except OSError:
                pass


# ---------------------------------------------------------------------------
# Per-record migration
# ---------------------------------------------------------------------------


_OUTCOMES = (
    "migrated",
    "already_v11",
    "not_v1",
    "unparseable",
    "byte_identical_skip",
    "write_failed",
    "validation_failed_after",
)


def _serialize_for_path(record: Dict[str, Any], path: Path) -> str:
    if path.suffix == ".json":
        return serialize_json(record)
    return serialize_yaml(record)


def _record_byte_identical_after_migration(
    before: Dict[str, Any], after: Dict[str, Any], path: Path
) -> bool:
    """Did migrate_record() actually change anything serialisation-relevant?

    A byte-identical re-serialisation of the input vs output means
    migrate_record() produced no observable change; we skip the write to
    avoid mtime churn.
    """
    try:
        return _serialize_for_path(before, path) == _serialize_for_path(after, path)
    except Exception:
        # If serialisation fails we cannot prove identity; force the write
        # so the failure surfaces downstream.
        return False


def _validate_after(record: Dict[str, Any]) -> List[str]:
    v = _validator()
    schema = v.load_schema_for_doc(record)
    return list(v.validate_doc(record, schema))


def migrate_path(
    path: Path,
    *,
    apply: bool,
    validate_after: bool,
) -> Dict[str, Any]:
    """Process a single record file. Returns a structured outcome dict.

    Keys:
      outcome: one of _OUTCOMES.
      path: relative-to-repo path string.
      record_id: declared record_id or None.
      errors: list of human-readable error strings (may be empty).
    """
    try:
        rel = path.relative_to(REPO_ROOT) if path.is_absolute() else path
    except ValueError:
        rel = path
    out: Dict[str, Any] = {
        "outcome": "unparseable",
        "path": str(rel),
        "record_id": None,
        "errors": [],
    }
    doc, err = load_record(path)
    if doc is None:
        out["outcome"] = "unparseable"
        out["errors"].append(err or f"{path}: failed to load")
        return out
    out["record_id"] = doc.get("record_id")
    if is_v11_record(doc):
        out["outcome"] = "already_v11"
        return out
    if not is_v1_record(doc):
        out["outcome"] = "not_v1"
        return out
    migrated = _migrator().migrate_record(doc)
    if _record_byte_identical_after_migration(doc, migrated, path):
        # Effectively a no-op even though schema_version may have bumped if
        # the input was already v1.1; for a true v1 the bump alone makes the
        # serialisations diverge so this branch is rare for v1 input.
        out["outcome"] = "byte_identical_skip"
        return out
    if not apply:
        out["outcome"] = "migrated"
        out["dry_run"] = True
        return out
    try:
        content = _serialize_for_path(migrated, path)
    except Exception as exc:
        out["outcome"] = "write_failed"
        out["errors"].append(f"{path}: serialise failure: {exc}")
        return out
    try:
        atomic_write(path, content)
    except Exception as exc:
        out["outcome"] = "write_failed"
        out["errors"].append(f"{path}: write failure: {exc}")
        return out
    out["outcome"] = "migrated"
    if validate_after:
        verrors = _validate_after(migrated)
        if verrors:
            out["outcome"] = "validation_failed_after"
            out["errors"].extend(verrors)
    return out


# ---------------------------------------------------------------------------
# Subtree resolution + corpus walk
# ---------------------------------------------------------------------------


def resolve_scope(
    tags_dir: Path, subtree: Optional[str]
) -> Tuple[Path, str]:
    """Return (scan_root, scope_label)."""
    if subtree:
        scope = tags_dir / subtree
        return scope, subtree
    return tags_dir, "_full_corpus"


def _subtree_of(path: Path, tags_dir: Path) -> str:
    """Return the top-level subtree name (immediately under ``tags_dir``)
    for a record path. Returns ``"_root"`` if the path lives directly in
    ``tags_dir``."""
    try:
        rel = path.resolve().relative_to(tags_dir.resolve())
    except Exception:
        return "_unscoped"
    parts = rel.parts
    if not parts:
        return "_root"
    if len(parts) == 1:
        return "_root"
    return parts[0]


def run(
    tags_dir: Path,
    *,
    subtree: Optional[str] = None,
    apply: bool = False,
    validate_after: bool = True,
    limit: Optional[int] = None,
    on_outcome: Optional[Callable[[Dict[str, Any]], None]] = None,
) -> Dict[str, Any]:
    """Walk the (subtree of the) corpus and migrate records.

    Returns a structured summary dict; per-record outcomes are streamed
    through ``on_outcome`` when provided so callers can render a live
    report without holding all outcomes in memory.
    """
    scan_root, scope_label = resolve_scope(tags_dir, subtree)
    if not scan_root.is_dir():
        return {
            "tags_dir": str(tags_dir),
            "subtree": subtree,
            "scope": scope_label,
            "apply": apply,
            "scan_root": str(scan_root),
            "error": "scan_root not found",
            "totals": {k: 0 for k in _OUTCOMES},
            "totals_overall": 0,
            "per_subtree": {},
            "errors": [],
        }
    paths = discover_records(scan_root)
    totals: Dict[str, int] = {k: 0 for k in _OUTCOMES}
    per_subtree: Dict[str, Dict[str, int]] = {}
    error_log: List[Dict[str, Any]] = []
    processed = 0
    for p in paths:
        if limit is not None and processed >= limit:
            break
        outcome = migrate_path(p, apply=apply, validate_after=validate_after)
        processed += 1
        sub = _subtree_of(p, tags_dir)
        sub_counters = per_subtree.setdefault(
            sub, {k: 0 for k in _OUTCOMES}
        )
        oc = outcome["outcome"]
        totals[oc] = totals.get(oc, 0) + 1
        sub_counters[oc] = sub_counters.get(oc, 0) + 1
        if outcome.get("errors"):
            error_log.append(outcome)
        if on_outcome is not None:
            on_outcome(outcome)
    return {
        "tags_dir": str(tags_dir),
        "subtree": subtree,
        "scope": scope_label,
        "apply": apply,
        "validate_after": validate_after,
        "scan_root": str(scan_root),
        "totals": totals,
        "totals_overall": processed,
        "per_subtree": per_subtree,
        "errors": error_log,
    }


# ---------------------------------------------------------------------------
# Report rendering
# ---------------------------------------------------------------------------


def render_report(
    summary: Dict[str, Any],
    *,
    generated_at: Optional[str] = None,
) -> str:
    if generated_at is None:
        generated_at = _dt.datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ")
    totals = summary.get("totals", {})
    per_sub = summary.get("per_subtree", {}) or {}
    errors = summary.get("errors", []) or []
    lines: List[str] = []
    mode = "apply" if summary.get("apply") else "dry-run"
    lines.append(
        "# Hackerman schema v1 -> v1.1 migration: runner report"
    )
    lines.append("")
    lines.append(f"_generated_at: `{generated_at}`_")
    lines.append("")
    lines.append(f"- Mode: `{mode}`")
    lines.append(f"- Tags dir: `{summary.get('tags_dir')}`")
    lines.append(f"- Scope: `{summary.get('scope')}`")
    lines.append(f"- Records scanned: {summary.get('totals_overall', 0)}")
    lines.append(
        f"- Post-mutation validation: "
        f"{'enabled' if summary.get('validate_after') else 'disabled'}"
    )
    lines.append("")
    lines.append("## Outcome counts")
    lines.append("")
    lines.append("| Outcome | Count |")
    lines.append("| --- | ---: |")
    for k in _OUTCOMES:
        lines.append(f"| `{k}` | {totals.get(k, 0)} |")
    lines.append("")
    if per_sub:
        lines.append("## Per-subtree breakdown")
        lines.append("")
        lines.append(
            "| Subtree | migrated | already_v11 | not_v1 | unparseable | "
            "byte_identical_skip | write_failed | validation_failed_after |"
        )
        lines.append(
            "| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |"
        )
        for sub in sorted(per_sub.keys()):
            c = per_sub[sub]
            lines.append(
                "| `{sub}` | {mig} | {a} | {nv} | {up} | {bi} | {wf} | {vf} |".format(
                    sub=sub,
                    mig=c.get("migrated", 0),
                    a=c.get("already_v11", 0),
                    nv=c.get("not_v1", 0),
                    up=c.get("unparseable", 0),
                    bi=c.get("byte_identical_skip", 0),
                    wf=c.get("write_failed", 0),
                    vf=c.get("validation_failed_after", 0),
                )
            )
        lines.append("")
    if errors:
        lines.append("## Errors (first 25)")
        lines.append("")
        for ent in errors[:25]:
            lines.append(
                f"- `{ent.get('path')}` ({ent.get('outcome')}): "
                f"{ent.get('record_id')}"
            )
            for err in (ent.get("errors") or [])[:3]:
                lines.append(f"  - {err}")
        lines.append("")
    else:
        lines.append("_No errors._\n")
    return "\n".join(lines) + "\n"


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


def _decide_apply(args: argparse.Namespace) -> Tuple[bool, Optional[str]]:
    """Return (apply, error_message).

    Safety rule (per spec section 3): default mode is dry-run. ``--apply``
    enables writes ONLY when restricted by ``--subtree``. ``--ready-for-full``
    enables writes over the full corpus (no subtree). The two are mutually
    exclusive with ``--dry-run`` (which forces dry-run regardless).
    """
    if args.dry_run:
        if args.apply or args.ready_for_full:
            return False, (
                "--dry-run conflicts with --apply / --ready-for-full"
            )
        return False, None
    if args.ready_for_full:
        if args.apply:
            return False, "--ready-for-full implies apply; do not also pass --apply"
        if args.subtree:
            return False, (
                "--ready-for-full is for full-corpus writes; do not combine "
                "with --subtree (use --apply --subtree <name> instead)"
            )
        return True, None
    if args.apply:
        if not args.subtree:
            return False, (
                "--apply requires --subtree <name>; full-corpus writes "
                "require --ready-for-full"
            )
        return True, None
    # Neither --apply nor --ready-for-full: implicit dry-run.
    return False, None


def main(argv: Optional[List[str]] = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument(
        "--tags-dir",
        default=str(DEFAULT_TAGS_DIR),
        help="Directory to scan recursively for hackerman records.",
    )
    ap.add_argument(
        "--subtree",
        default=None,
        help="Restrict the migration to a single top-level subtree under --tags-dir.",
    )
    ap.add_argument(
        "--limit",
        type=int,
        default=None,
        help="Stop after processing N candidate files (debug).",
    )
    ap.add_argument(
        "--no-validate-after",
        action="store_true",
        help="Skip post-migration validation (default: validate every written record).",
    )
    ap.add_argument(
        "--report-out",
        default=None,
        help="Optional markdown report sink.",
    )
    ap.add_argument(
        "--dry-run",
        action="store_true",
        help="Explicitly request dry-run mode (also the default when --apply / --ready-for-full are absent).",
    )
    ap.add_argument(
        "--apply",
        action="store_true",
        help="Apply the migration in-place. Requires --subtree.",
    )
    ap.add_argument(
        "--ready-for-full",
        action="store_true",
        help="Apply the migration in-place across the full corpus (no --subtree).",
    )
    ap.add_argument(
        "--generated-at",
        default=None,
        help="Override report timestamp for deterministic tests.",
    )
    ap.add_argument(
        "--quiet",
        action="store_true",
        help="Suppress JSON summary on stdout.",
    )
    args = ap.parse_args(argv)

    apply, err = _decide_apply(args)
    if err is not None:
        print(f"error: {err}", file=sys.stderr)
        return 2

    summary = run(
        Path(args.tags_dir),
        subtree=args.subtree,
        apply=apply,
        validate_after=not args.no_validate_after,
        limit=args.limit,
    )

    if args.report_out:
        rep = render_report(summary, generated_at=args.generated_at)
        rp = Path(args.report_out)
        rp.parent.mkdir(parents=True, exist_ok=True)
        rp.write_text(rep, encoding="utf-8")
        summary["report_out"] = str(rp)

    if not args.quiet:
        json.dump(summary, sys.stdout, indent=2, sort_keys=True)
        sys.stdout.write("\n")

    # Harmonized exit codes with wave2-w21-post-migration-validator.py.
    # 2 = tool/input error (structural problem the operator must fix):
    #     - resolved scan_root does not exist
    #     - record file was unparseable (malformed JSON/YAML on disk)
    #     - atomic write failure during apply
    # 1 = FAIL (records found, post-migration validation failed)
    # 0 = PASS (clean run, including dry-runs with nothing to do)
    if summary.get("error"):
        # run() emits {"error": "scan_root not found", ...} when the
        # resolved scan_root is missing. Surface as a tool error, not
        # as a silently-clean exit-0.
        return 2
    totals = summary.get("totals", {})
    if totals.get("unparseable", 0) > 0 or totals.get("write_failed", 0) > 0:
        return 2
    if totals.get("validation_failed_after", 0) > 0:
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
