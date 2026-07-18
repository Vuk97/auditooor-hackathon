#!/usr/bin/env python3
"""regression-sentinel-runner — auto-fire held / closed PoCs when their
trigger-conditions change.

Wave-7 BIG_PLAN A5 deliverable (deferred from PR #675). Walks
``submissions/held/``, ``submissions/superseded/``, and registered
``audit/regression_sentinels_registry.yaml`` entries, parses the
``regression-sentinel-condition`` header(s), evaluates each condition
against the live workspace + external scope, and re-fires the PoC test
when the condition is violated.

Sentinel condition vocabulary (see ``docs/REGRESSION_SENTINELS.md``):

  file_line_present <path>:<line>
      Bug-anchor file:line is still present. Violation = file or line
      gone (refactor / fix shipped). Re-fire because the protection
      may have moved without the test catching it.

  middleware_absent <middleware-name>
      A protective middleware is absent. Violation = middleware now
      installed (good — but check the test for false negatives).
      Re-fire (bug should now be blocked; if it isn't, the middleware
      is mis-wired).

  gov_config_unchanged <param>=<value>
      A governance / parameter value matches the safe baseline.
      Violation = value drifted off the safe value. Re-fire because
      the threat model changed.

  fork_pin_unchanged <repo>:<sha>
      The upstream fork pin matches the audit-pin. Violation = fork
      bumped to a new SHA. Re-fire to confirm whether the bump
      shipped the missing patch.

  detector_silent <detector-id>
      Detector ID has produced ZERO hits in the latest engage report.
      Violation = detector now fires somewhere. Re-fire (detector
      went hot — sentinel is the smoke alarm).

For each sentinel:
  1. Parse the trigger condition from the header.
  2. Evaluate the condition (file:line still present? middleware
     composition unchanged? gov-config still safe?).
  3. If condition VIOLATED → re-fire the PoC test (vanilla ``go
     test`` / ``forge test``).
  4. If test now PASSES (bug live) → emit
     ``<ws>/regression_sentinel_FIRED_<slug>_<ts>.md`` with
     operator-attention flag.

The runner is read-only against the workspace until it emits a FIRED
report; it never edits source files or paste-ready submissions.
"""
from __future__ import annotations

import argparse
import datetime as _dt
import json
import os
import re
import subprocess
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Tuple

try:
    import yaml  # type: ignore
except Exception:  # pragma: no cover - yaml is on all auditooor hosts
    yaml = None  # type: ignore


SENTINEL_HEADER_RE = re.compile(
    r"^\s*(?://|#)\s*regression-sentinel-condition:\s*(?P<body>.+?)\s*$",
    re.MULTILINE,
)


CONDITION_CLASSES = {
    "file_line_present",
    "middleware_absent",
    "gov_config_unchanged",
    "fork_pin_unchanged",
    "detector_silent",
}


@dataclass
class SentinelCondition:
    """Parsed sentinel condition with its raw body."""

    cls: str
    body: str

    @classmethod
    def parse(cls, raw: str) -> "SentinelCondition":
        # raw form: "<class> <arg> [<arg> ...]"
        parts = raw.split(None, 1)
        if not parts:
            raise ValueError(f"empty sentinel condition: {raw!r}")
        klass = parts[0].strip()
        body = parts[1].strip() if len(parts) > 1 else ""
        if klass not in CONDITION_CLASSES:
            raise ValueError(
                f"unknown sentinel condition class {klass!r}; "
                f"valid: {sorted(CONDITION_CLASSES)}"
            )
        return cls(cls=klass, body=body)


@dataclass
class SentinelRecord:
    """One registered (or parsed-inline) sentinel."""

    sentinel_id: str
    poc_path: Path
    condition: SentinelCondition
    severity_if_fires: str = "UNKNOWN"
    notes: str = ""
    source: str = "header"  # 'header' or 'registry'

    def as_dict(self) -> Dict[str, Any]:
        return {
            "sentinel_id": self.sentinel_id,
            "poc_path": str(self.poc_path),
            "condition_class": self.condition.cls,
            "condition_body": self.condition.body,
            "severity_if_fires": self.severity_if_fires,
            "source": self.source,
        }


@dataclass
class EvaluationResult:
    """Output of evaluating a single sentinel condition."""

    sentinel_id: str
    condition_holds: bool
    detail: str
    rerun_required: bool
    rerun_command: Optional[List[str]] = None
    rerun_passed: Optional[bool] = None
    rerun_stdout_tail: str = ""
    fired_artifact_path: Optional[Path] = None

    def as_dict(self) -> Dict[str, Any]:
        d = {
            "sentinel_id": self.sentinel_id,
            "condition_holds": self.condition_holds,
            "detail": self.detail,
            "rerun_required": self.rerun_required,
            "rerun_command": self.rerun_command,
            "rerun_passed": self.rerun_passed,
        }
        if self.fired_artifact_path is not None:
            d["fired_artifact_path"] = str(self.fired_artifact_path)
        return d


# ---------------------------------------------------------------------------
# Header parsing
# ---------------------------------------------------------------------------


def parse_sentinel_headers(text: str) -> List[SentinelCondition]:
    """Return every ``regression-sentinel-condition`` line found in ``text``."""
    out: List[SentinelCondition] = []
    for m in SENTINEL_HEADER_RE.finditer(text):
        body = m.group("body").strip()
        out.append(SentinelCondition.parse(body))
    return out


def walk_pocs_for_headers(roots: Iterable[Path]) -> List[SentinelRecord]:
    """Scan PoC directories for files containing sentinel headers."""
    seen: List[SentinelRecord] = []
    suffixes = {".go", ".rs", ".sol", ".py", ".ts", ".md"}
    for root in roots:
        if not root.exists():
            continue
        for path in root.rglob("*"):
            if not path.is_file():
                continue
            if path.suffix not in suffixes:
                continue
            try:
                text = path.read_text(encoding="utf-8", errors="ignore")
            except OSError:
                continue
            for cond in parse_sentinel_headers(text):
                seen.append(
                    SentinelRecord(
                        sentinel_id=f"{path.parent.name}::{path.name}",
                        poc_path=path,
                        condition=cond,
                        severity_if_fires="UNKNOWN",
                        source="header",
                    )
                )
    return seen


# ---------------------------------------------------------------------------
# Registry parsing
# ---------------------------------------------------------------------------


def load_registry(registry_path: Path) -> List[SentinelRecord]:
    """Load registered sentinels from YAML. Returns [] if file is missing."""
    if not registry_path.exists():
        return []
    if yaml is None:
        raise RuntimeError("PyYAML not installed; required to read registry")
    raw = yaml.safe_load(registry_path.read_text(encoding="utf-8")) or {}
    out: List[SentinelRecord] = []
    for row in raw.get("sentinels", []) or []:
        try:
            cond = SentinelCondition.parse(row["condition"])
        except Exception as exc:
            raise ValueError(
                f"registry entry {row.get('id')!r}: {exc}"
            ) from exc
        poc_path = Path(os.path.expanduser(row["poc_path"]))
        out.append(
            SentinelRecord(
                sentinel_id=row["id"],
                poc_path=poc_path,
                condition=cond,
                severity_if_fires=row.get("severity_if_fires", "UNKNOWN"),
                notes=row.get("notes", "") or "",
                source="registry",
            )
        )
    return out


# ---------------------------------------------------------------------------
# Condition evaluators
# ---------------------------------------------------------------------------


def _eval_file_line_present(body: str, ctx: "EvalContext") -> Tuple[bool, str]:
    """Returns (condition_holds, detail).

    condition_holds == True  → file:line exists → safe; no re-fire.
    condition_holds == False → file or line gone → violated → re-fire.
    """
    if ":" not in body:
        return False, f"malformed body (expected <path>:<line>): {body!r}"
    path_part, line_part = body.rsplit(":", 1)
    try:
        line_no = int(line_part)
    except ValueError:
        return False, f"non-integer line number in {body!r}"
    full = (ctx.resolve_root / path_part).expanduser() if not Path(path_part).is_absolute() else Path(path_part)
    if not full.exists():
        return False, f"file missing: {full}"
    try:
        lines = full.read_text(encoding="utf-8", errors="ignore").splitlines()
    except OSError as exc:
        return False, f"read error on {full}: {exc}"
    if line_no < 1 or line_no > len(lines):
        return False, f"line {line_no} out of range (file has {len(lines)} lines)"
    return True, f"file:line still present at {full}:{line_no}"


def _eval_middleware_absent(body: str, ctx: "EvalContext") -> Tuple[bool, str]:
    """condition_holds == True → middleware still absent → safe (bug still
    blocked by absence). condition_holds == False → middleware now installed
    → violated → re-fire to confirm bug is now blocked OR mis-wired."""
    name = body.strip()
    if not name:
        return False, "empty middleware name"
    # Grep the workspace external/ tree for the middleware name.
    search_roots = [
        ctx.resolve_root / "external",
        ctx.resolve_root,
    ]
    hits: List[str] = []
    for root in search_roots:
        if not root.exists():
            continue
        try:
            res = subprocess.run(
                ["grep", "-rln", "--include=*.go", "--include=*.rs",
                 "--include=*.sol", "--include=*.ts", name, str(root)],
                capture_output=True, text=True, timeout=ctx.grep_timeout,
            )
            if res.stdout.strip():
                hits.extend(res.stdout.strip().splitlines())
        except (subprocess.TimeoutExpired, FileNotFoundError):
            continue
        if hits:
            break
    if not hits:
        return True, f"middleware {name!r} still absent (no source hits)"
    return False, f"middleware {name!r} now installed in {len(hits)} file(s); first: {hits[0]}"


def _eval_gov_config_unchanged(body: str, ctx: "EvalContext") -> Tuple[bool, str]:
    """body: ``<param>=<value>``. Holds iff a code-level constant matching
    ``<param>`` literally equals ``<value>``. Best-effort grep."""
    if "=" not in body:
        return False, f"malformed body (expected <param>=<value>): {body!r}"
    param, value = body.split("=", 1)
    param = param.strip()
    value = value.strip()
    patt = f"{param}.*{re.escape(value)}"
    try:
        res = subprocess.run(
            ["grep", "-rnE", "--include=*.go", "--include=*.rs",
             "--include=*.sol", "--include=*.toml", "--include=*.yaml",
             patt, str(ctx.resolve_root)],
            capture_output=True, text=True, timeout=ctx.grep_timeout,
        )
        if res.stdout.strip():
            return True, f"param {param!r} = {value!r} still present"
        return False, f"param {param!r} = {value!r} NOT found"
    except (subprocess.TimeoutExpired, FileNotFoundError) as exc:
        return False, f"grep failed: {exc}"


def _eval_fork_pin_unchanged(body: str, ctx: "EvalContext") -> Tuple[bool, str]:
    """body: ``<repo>:<sha>``. Holds iff workspace's commit_lifecycle_ledger
    or audit-pin metadata still references ``<sha>`` for ``<repo>``."""
    if ":" not in body:
        return False, f"malformed body (expected <repo>:<sha>): {body!r}"
    repo, sha = body.rsplit(":", 1)
    sha = sha.strip()
    ledger = ctx.resolve_root / ".auditooor" / "commit_lifecycle_ledger.json"
    if not ledger.exists():
        # fall back to grep across .auditooor and SCOPE/AUDIT pin docs
        candidates = [
            ctx.resolve_root / "SCOPE.md",
            ctx.resolve_root / ".auditooor",
        ]
        for c in candidates:
            if c.is_file():
                if sha in c.read_text(encoding="utf-8", errors="ignore"):
                    return True, f"fork pin {sha[:12]} for {repo} still present in {c}"
            elif c.is_dir():
                try:
                    res = subprocess.run(
                        ["grep", "-rln", sha, str(c)],
                        capture_output=True, text=True,
                        timeout=ctx.grep_timeout,
                    )
                    if res.stdout.strip():
                        return True, f"fork pin {sha[:12]} found in {res.stdout.splitlines()[0]}"
                except (subprocess.TimeoutExpired, FileNotFoundError):
                    pass
        return False, f"fork pin {sha[:12]} for {repo} NOT found (no ledger, no doc reference)"
    text = ledger.read_text(encoding="utf-8", errors="ignore")
    if sha in text:
        return True, f"fork pin {sha[:12]} for {repo} still in commit_lifecycle_ledger.json"
    return False, f"fork pin {sha[:12]} for {repo} bumped (not in ledger)"


def _eval_detector_silent(body: str, ctx: "EvalContext") -> Tuple[bool, str]:
    """body: ``<detector-id>``. Holds iff the workspace's latest
    ``engage_report.md`` shows ZERO hits for that detector id."""
    det = body.strip()
    if not det:
        return False, "empty detector id"
    engage = ctx.resolve_root / "engage_report.md"
    if not engage.exists():
        return False, "engage_report.md missing; cannot evaluate detector_silent"
    text = engage.read_text(encoding="utf-8", errors="ignore")
    if det not in text:
        return True, f"detector {det!r} silent in engage_report.md (no mention)"
    # Count hits — naive heuristic: number of lines that mention the id.
    hit_lines = [
        ln for ln in text.splitlines()
        if det in ln and any(tok in ln for tok in (".sol:", ".go:", ".rs:", ".ts:"))
    ]
    if not hit_lines:
        return True, f"detector {det!r} mentioned but no file:line hits"
    return False, f"detector {det!r} now firing with {len(hit_lines)} file:line hits"


EVALUATORS = {
    "file_line_present": _eval_file_line_present,
    "middleware_absent": _eval_middleware_absent,
    "gov_config_unchanged": _eval_gov_config_unchanged,
    "fork_pin_unchanged": _eval_fork_pin_unchanged,
    "detector_silent": _eval_detector_silent,
}


@dataclass
class EvalContext:
    """Shared state for one sentinel-evaluation pass."""

    resolve_root: Path
    grep_timeout: int = 60
    rerun_enabled: bool = True
    test_command_override: Optional[List[str]] = None


def evaluate(rec: SentinelRecord, ctx: EvalContext) -> Tuple[bool, str]:
    evaluator = EVALUATORS.get(rec.condition.cls)
    if evaluator is None:
        return False, f"no evaluator for {rec.condition.cls}"
    return evaluator(rec.condition.body, ctx)


# ---------------------------------------------------------------------------
# PoC re-firing
# ---------------------------------------------------------------------------


def derive_test_command(poc_path: Path) -> Optional[List[str]]:
    """Best-effort guess at how to re-fire the PoC test.

    The PoC dir is either:
      * a Go module (go.mod present) → ``go test ./...``
      * a Foundry project (foundry.toml present) → ``forge test``
      * a Python test file (*.py) → ``python3 -m unittest <file>``
      * a Markdown harness pointer (*.md) → not directly re-fireable
    """
    if poc_path.is_file():
        target_dir = poc_path.parent
        if poc_path.suffix == ".py":
            return ["python3", "-m", "unittest", str(poc_path)]
    else:
        target_dir = poc_path
    if not target_dir.exists():
        return None
    if (target_dir / "go.mod").exists():
        return ["go", "test", "-run", ".", "./..."]
    if (target_dir / "foundry.toml").exists():
        return ["forge", "test"]
    # walk one level up if PoC test sits inside a project
    parent = target_dir.parent
    if (parent / "go.mod").exists():
        return ["go", "test", "-run", ".", "./..."]
    return None


def rerun_poc(poc_path: Path, cmd_override: Optional[List[str]] = None) -> Tuple[Optional[bool], str, List[str]]:
    """Returns (passed, stdout_tail, command). passed=None if not runnable."""
    cmd = cmd_override or derive_test_command(poc_path)
    if cmd is None:
        return None, "no runnable command derived for PoC", []
    cwd = poc_path if poc_path.is_dir() else poc_path.parent
    try:
        res = subprocess.run(
            cmd, cwd=str(cwd), capture_output=True, text=True, timeout=600,
        )
    except (subprocess.TimeoutExpired, FileNotFoundError) as exc:
        return None, f"rerun failed: {exc}", cmd
    stdout = (res.stdout or "") + (res.stderr or "")
    passed = res.returncode == 0
    tail = "\n".join(stdout.splitlines()[-40:])
    return passed, tail, cmd


# ---------------------------------------------------------------------------
# FIRED artifact emission
# ---------------------------------------------------------------------------


def _slugify(s: str) -> str:
    s = re.sub(r"[^A-Za-z0-9_-]+", "-", s).strip("-")
    return s[:80] or "sentinel"


def emit_fired_artifact(
    ws: Path,
    rec: SentinelRecord,
    detail: str,
    rerun: EvaluationResult,
) -> Path:
    ts = _dt.datetime.now(_dt.timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    slug = _slugify(rec.sentinel_id)
    path = ws / f"regression_sentinel_FIRED_{slug}_{ts}.md"
    rerun_status = (
        "PASS (bug live)" if rerun.rerun_passed
        else "FAIL (bug not reproducing — sentinel mis-armed?)"
        if rerun.rerun_passed is False
        else "NOT RUN"
    )
    body = (
        f"# REGRESSION SENTINEL FIRED — operator-attention\n\n"
        f"- sentinel_id: `{rec.sentinel_id}`\n"
        f"- poc_path: `{rec.poc_path}`\n"
        f"- condition_class: `{rec.condition.cls}`\n"
        f"- condition_body: `{rec.condition.body}`\n"
        f"- severity_if_fires: `{rec.severity_if_fires}`\n"
        f"- source: `{rec.source}`\n"
        f"- fired_at_utc: `{_dt.datetime.now(_dt.timezone.utc).isoformat()}`\n\n"
        f"## Why it fired\n\n"
        f"Condition `{rec.condition.cls} {rec.condition.body}` evaluated to "
        f"VIOLATED. Detail:\n\n"
        f"```\n{detail}\n```\n\n"
        f"## Rerun status\n\n"
        f"- status: {rerun_status}\n"
        f"- command: `{' '.join(rerun.rerun_command or [])}`\n\n"
        f"### Last 40 lines of rerun output\n\n"
        f"```\n{rerun.rerun_stdout_tail}\n```\n\n"
        f"## Operator action\n\n"
        f"1. If rerun PASS: bug is LIVE under current pin; promote PoC to\n"
        f"   `submissions/staging/` and run pre-submit-check.\n"
        f"2. If rerun FAIL: sentinel may be mis-armed; review the condition\n"
        f"   and either re-arm with a stricter shape or close as healed.\n"
        f"3. If rerun NOT RUN: PoC has no derivable test command; inspect\n"
        f"   `{rec.poc_path}` manually.\n"
    )
    if rec.notes:
        body += f"\n## Registry notes\n\n{rec.notes}\n"
    path.write_text(body, encoding="utf-8")
    return path


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


def collect_sentinels(
    workspace: Path,
    extra_poc_dirs: Iterable[Path],
    registry_path: Optional[Path],
) -> List[SentinelRecord]:
    out: List[SentinelRecord] = []
    if registry_path is not None:
        out.extend(load_registry(registry_path))
    poc_roots: List[Path] = []
    held = workspace / "submissions" / "held"
    superseded = workspace / "submissions" / "superseded"
    paste_ready = workspace / "submissions" / "paste_ready"
    poc_roots.extend([held, superseded, paste_ready])
    poc_roots.extend(workspace / "poc-tests" / sub for sub in [])
    poc_root_pocs = workspace / "poc-tests"
    if poc_root_pocs.exists():
        poc_roots.append(poc_root_pocs)
    poc_roots.extend(Path(p) for p in extra_poc_dirs)
    out.extend(walk_pocs_for_headers(poc_roots))
    return out


def run(
    workspace: Path,
    registry_path: Optional[Path],
    extra_poc_dirs: List[Path],
    rerun_enabled: bool = True,
    emit_root: Optional[Path] = None,
    grep_timeout: int = 60,
) -> List[EvaluationResult]:
    sentinels = collect_sentinels(workspace, extra_poc_dirs, registry_path)
    ctx = EvalContext(
        resolve_root=workspace,
        rerun_enabled=rerun_enabled,
        grep_timeout=grep_timeout,
    )
    results: List[EvaluationResult] = []
    emit_root = emit_root or workspace
    for rec in sentinels:
        holds, detail = evaluate(rec, ctx)
        res = EvaluationResult(
            sentinel_id=rec.sentinel_id,
            condition_holds=holds,
            detail=detail,
            rerun_required=(not holds),
        )
        if not holds and rerun_enabled:
            passed, tail, cmd = rerun_poc(rec.poc_path)
            res.rerun_command = cmd or None
            res.rerun_passed = passed
            res.rerun_stdout_tail = tail
            if passed:
                res.fired_artifact_path = emit_fired_artifact(
                    emit_root, rec, detail, res,
                )
        results.append(res)
    return results


def main(argv: Optional[List[str]] = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--workspace", required=True, type=Path,
                    help="Engagement workspace root (e.g. ~/audits/dydx).")
    ap.add_argument("--registry", type=Path, default=None,
                    help="Path to regression_sentinels_registry.yaml "
                         "(defaults to audit/regression_sentinels_registry.yaml "
                         "in the worktree).")
    ap.add_argument("--extra-poc-dir", action="append", default=[], type=Path,
                    help="Additional PoC directory to scan for sentinel "
                         "headers. Repeatable.")
    ap.add_argument("--no-rerun", action="store_true",
                    help="Evaluate conditions only; do not re-fire any PoC.")
    ap.add_argument("--emit-root", type=Path, default=None,
                    help="Directory to write FIRED artifacts (default: "
                         "workspace root).")
    ap.add_argument("--json", action="store_true",
                    help="Emit JSON summary to stdout.")
    ap.add_argument("--grep-timeout", type=int, default=60)
    args = ap.parse_args(argv)

    ws = args.workspace.expanduser().resolve()
    registry = args.registry
    if registry is None:
        repo_root = Path(__file__).resolve().parents[1]
        default_reg = repo_root / "audit" / "regression_sentinels_registry.yaml"
        if default_reg.exists():
            registry = default_reg

    results = run(
        workspace=ws,
        registry_path=registry,
        extra_poc_dirs=[Path(os.path.expanduser(str(p))) for p in args.extra_poc_dir],
        rerun_enabled=not args.no_rerun,
        emit_root=args.emit_root,
        grep_timeout=args.grep_timeout,
    )

    summary = {
        "workspace": str(ws),
        "registry": str(registry) if registry else None,
        "evaluated": len(results),
        "violations": sum(1 for r in results if not r.condition_holds),
        "fired_artifacts": [
            str(r.fired_artifact_path) for r in results if r.fired_artifact_path
        ],
        "results": [r.as_dict() for r in results],
    }
    if args.json:
        print(json.dumps(summary, indent=2))
    else:
        print(f"regression-sentinel-runner: workspace={ws}")
        print(f"  evaluated={len(results)} violations={summary['violations']} "
              f"fired={len(summary['fired_artifacts'])}")
        for r in results:
            tag = "HOLDS " if r.condition_holds else "VIOLAT"
            print(f"  [{tag}] {r.sentinel_id}: {r.detail}")
            if r.fired_artifact_path:
                print(f"          FIRED → {r.fired_artifact_path}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
