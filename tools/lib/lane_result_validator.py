"""tools/lib/lane_result_validator.py

Lane-result validation: extract claimed MCP-callable wiring (R69) and
claimed file paths (R70) from a lane result text (markdown / JSON /
shell-style block) and invoke the respective verifiers to confirm the
claims actually hold against the live ``tools/vault-mcp-server.py`` (R69)
and the live git index (R70).

This module is intentionally lightweight: it does NOT replace any
existing lane-result validation pipeline. It is the R69 + R70 *additive*
check intended to be called from a future ``tools/lane-result-validator.py``
or directly from lane-orchestration scripts.

The validator emits WARN (not FAIL) by default; orchestrators can
elevate to FAIL by passing ``strict=True`` or setting the matching env
var (``AUDITOOOR_R69_LANE_VALIDATOR_STRICT=1`` /
``AUDITOOOR_R70_LANE_VALIDATOR_STRICT=1``).

r36-rebuttal: lane LANE-217-R69-CALLABLE-WIRING-VERIFIER (R69) +
LANE-218-R70-FILE-TRACKED-VERIFIER (R70) declared via
tools/agent-pathspec-register.py. agent_pathspec.json carries both.

Schema: ``auditooor.r69_lane_result_validator.v1`` (R69 payload),
``auditooor.r70_lane_result_validator.v1`` (R70 payload). The top-level
``validate_lane_result`` envelope returns both under ``r69`` and ``r70``
keys when both checks are enabled.
"""
from __future__ import annotations

import json
import os
import re
import subprocess
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterable


SCHEMA = "auditooor.r69_lane_result_validator.v1"


# Claim-phrase patterns that signal a worker is asserting an MCP-callable
# was wired. We extract the callable name from each match.
_CALLABLE_NAME_RE = re.compile(r"\bvault_[a-zA-Z0-9_]+")

_CLAIM_PATTERNS: tuple[re.Pattern[str], ...] = (
    # "vault_X callable wired" / "vault_X is wired" / "vault_X now wired"
    re.compile(r"\b(vault_[a-zA-Z0-9_]+)\b[^.\n]*\b(?:callable\s+)?(?:is\s+)?(?:now\s+)?wired\b", re.IGNORECASE),
    # "MCP callable vault_X registered" / "registered MCP callable vault_X"
    re.compile(r"\bMCP\s+callable\s+(vault_[a-zA-Z0-9_]+)\b", re.IGNORECASE),
    re.compile(r"\bcallable\s+(vault_[a-zA-Z0-9_]+)\s+registered\b", re.IGNORECASE),
    # "TOOL_SCHEMAS updated for vault_X"
    re.compile(r"\bTOOL_SCHEMAS\s+(?:updated|extended|added)\s+for\s+(vault_[a-zA-Z0-9_]+)\b", re.IGNORECASE),
    # "Added vault_X to dispatcher" / "dispatcher branch for vault_X"
    re.compile(r"\bdispatcher\s+(?:branch\s+)?(?:for\s+)?(vault_[a-zA-Z0-9_]+)\b", re.IGNORECASE),
    # "Phase 3 LANDED: vault_X" / "LANDED vault_X"
    re.compile(r"\bLANDED\b[^.\n]*\b(vault_[a-zA-Z0-9_]+)\b", re.IGNORECASE),
)


@dataclass
class ClaimedCallable:
    name: str
    snippets: list[str] = field(default_factory=list)


def extract_claimed_callables(text: str) -> list[ClaimedCallable]:
    """Return the de-duplicated list of vault_X names claimed to be wired.

    Each entry carries up to 3 source snippets (<=160 chars each) for
    operator-readability in the validator output.
    """
    by_name: dict[str, ClaimedCallable] = {}
    if not text:
        return []
    for pat in _CLAIM_PATTERNS:
        for m in pat.finditer(text):
            # Each match captures the callable name in group 1 if the
            # pattern has a capture group; otherwise we fall back to the
            # broader name regex inside the matched window.
            captured: str | None = None
            if m.groups():
                captured = m.group(1)
            else:
                inner = _CALLABLE_NAME_RE.search(m.group(0))
                if inner:
                    captured = inner.group(0)
            if not captured or not captured.startswith("vault_"):
                continue
            entry = by_name.setdefault(captured, ClaimedCallable(name=captured))
            if len(entry.snippets) < 3:
                start = max(0, m.start() - 40)
                end = min(len(text), m.end() + 40)
                snippet = text[start:end].replace("\n", " ").strip()
                if snippet and snippet not in entry.snippets:
                    entry.snippets.append(snippet[:160])
    return list(by_name.values())


def run_r69_verifier(
    callables: Iterable[str],
    *,
    verifier_path: Path,
    server_path: Path | None = None,
    no_live_call: bool = False,
    timeout: int = 60,
) -> dict[str, Any]:
    """Invoke ``tools/r69-callable-wiring-verifier.py`` and parse the JSON.

    Returns a dict with ``ok`` (bool), ``payload`` (dict|None),
    ``stdout`` and ``stderr`` heads.
    """
    callables = [c for c in callables if c]
    if not callables:
        return {"ok": True, "payload": None, "stdout": "", "stderr": "", "skipped": "no-claims"}
    if not verifier_path.exists():
        return {
            "ok": False,
            "payload": None,
            "stdout": "",
            "stderr": "",
            "error": f"verifier-not-found: {verifier_path}",
        }
    cmd = [
        sys.executable,
        str(verifier_path),
        "--claimed-callables",
        ",".join(callables),
        "--json",
    ]
    if server_path is not None:
        cmd.extend(["--server", str(server_path)])
    if no_live_call:
        cmd.append("--no-live-call")
    try:
        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )
    except subprocess.TimeoutExpired:
        return {"ok": False, "payload": None, "stdout": "", "stderr": "", "error": "timeout"}
    except OSError as exc:
        return {"ok": False, "payload": None, "stdout": "", "stderr": "", "error": f"os-error: {exc}"}
    payload: dict[str, Any] | None = None
    try:
        payload = json.loads(proc.stdout)
    except json.JSONDecodeError:
        payload = None
    return {
        "ok": proc.returncode == 0,
        "payload": payload,
        "stdout": (proc.stdout or "")[:400],
        "stderr": (proc.stderr or "")[:400],
        "returncode": proc.returncode,
    }


# ---------------------------------------------------------------------------
# R70: claimed-file-path extraction + verifier invocation
# r36-rebuttal: lane LANE-218-R70-FILE-TRACKED-VERIFIER declared via
# tools/agent-pathspec-register.py with this file in the pathspec.
# ---------------------------------------------------------------------------

R70_SCHEMA = "auditooor.r70_lane_result_validator.v1"
# no-op-no-persistent-changes: agent only touched /tmp/ paths or had 0 git
# diff - treat as pass, not fail. Introduced Lane 231 (2026-05-26).
R70_VERDICT_NO_OP = "no-op-no-persistent-changes"

# Match a canonical-tree file path. Mirrors the same regex used by the R70
# CLI tool (jsonl before json, tsx before ts, yaml before yml).
_R70_PATH_RE = re.compile(
    r"\b((?:tools|docs|audit|reports|reference|obsidian-vault|agent_outputs|"
    r"submissions|patterns|detectors|skills|\.auditooor)/[^\s,;\"'`)]+"
    r"\.(?:jsonl|json|yaml|yml|tsx|ts|toml|md|py|sh|txt|sol|rs|go|cfg|ini))",
    re.IGNORECASE,
)


def extract_claimed_paths(text: str) -> list[str]:
    """Return a de-duplicated list of canonical-tree file paths cited in
    the lane result body. Same extraction logic as the R70 CLI verifier
    in --draft mode; replicated here so callers can do path extraction
    without invoking the CLI when they only want the candidate list.
    """
    if not text:
        return []
    seen: set[str] = set()
    out: list[str] = []
    for m in _R70_PATH_RE.finditer(text):
        p = m.group(1).rstrip(".,;:)\"'`")
        if p not in seen:
            seen.add(p)
            out.append(p)
    return out


def run_r70_verifier(
    paths: Iterable[str],
    *,
    verifier_path: Path,
    repo_root: Path | None = None,
    strict: bool = False,
    require_committed: bool = False,
    timeout: int = 30,
) -> dict[str, Any]:
    """Invoke ``tools/r70-file-tracked-verifier.py`` and parse the JSON.

    Returns a dict with ``ok`` (bool), ``payload`` (dict|None), and
    truncated ``stdout`` / ``stderr`` heads. When no paths are claimed
    the verifier is skipped and ``skipped: 'no-claims'`` is set.
    """
    paths = [p for p in paths if p]
    if not paths:
        return {"ok": True, "payload": None, "stdout": "", "stderr": "", "skipped": "no-claims"}
    if not verifier_path.exists():
        return {
            "ok": False,
            "payload": None,
            "stdout": "",
            "stderr": "",
            "error": f"verifier-not-found: {verifier_path}",
        }
    cmd = [
        sys.executable,
        str(verifier_path),
        "--claimed-paths",
        ",".join(paths),
        "--json",
    ]
    if repo_root is not None:
        cmd.extend(["--repo-root", str(repo_root)])
    if strict:
        cmd.append("--strict")
    if require_committed:
        cmd.append("--require-committed")
    try:
        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )
    except subprocess.TimeoutExpired:
        return {"ok": False, "payload": None, "stdout": "", "stderr": "", "error": "timeout"}
    except OSError as exc:
        return {"ok": False, "payload": None, "stdout": "", "stderr": "", "error": f"os-error: {exc}"}
    payload: dict[str, Any] | None = None
    try:
        payload = json.loads(proc.stdout)
    except json.JSONDecodeError:
        payload = None
    return {
        "ok": proc.returncode == 0,
        "payload": payload,
        "stdout": (proc.stdout or "")[:400],
        "stderr": (proc.stderr or "")[:400],
        "returncode": proc.returncode,
    }


def validate_paths_r70(
    text: str,
    *,
    repo_root: Path | None = None,
    strict: bool | None = None,
) -> dict[str, Any]:
    """R70 file-tracking validation for a lane result text.

    Verdicts:
        no-paths-found
        pass-all-tracked-and-committed
        no-op-no-persistent-changes    (all claimed paths under /tmp/ - pass)
        warn-some-uncommitted          (tracked but not committed)
        warn-untracked-or-missing      (default for untracked/missing)
        fail-untracked-or-missing      (strict=True or env elevated)
        error
    """
    repo_root = (repo_root or Path(__file__).resolve().parent.parent.parent).resolve()
    verifier_path = repo_root / "tools" / "r70-file-tracked-verifier.py"
    if strict is None:
        strict = os.environ.get("AUDITOOOR_R70_LANE_VALIDATOR_STRICT", "") in {
            "1", "true", "yes",
        }

    paths = extract_claimed_paths(text)
    if not paths:
        return {
            "schema": R70_SCHEMA,
            "verdict": "no-paths-found",
            "strict": strict,
            "paths": [],
        }

    invoke = run_r70_verifier(
        paths,
        verifier_path=verifier_path,
        repo_root=repo_root,
        strict=False,
    )
    payload = invoke.get("payload")
    if payload is None:
        return {
            "schema": R70_SCHEMA,
            "verdict": "error",
            "strict": strict,
            "paths": paths,
            "verifier_error": invoke.get("error") or "no-json-output",
            "verifier_stderr": invoke.get("stderr"),
        }

    overall = payload.get("verdict", "")
    if overall in {
        "pass-all-tracked-and-committed",
        "pass-no-paths-claimed",
        "ok-rebuttal",
        R70_VERDICT_NO_OP,  # no-op lane: /tmp/-only paths = pass, not fail
    }:
        lane_verdict = "pass-all-tracked-and-committed"
    elif overall == "warn-some-uncommitted":
        lane_verdict = "warn-some-uncommitted"
    elif overall in {"fail-untracked-or-missing", "fail-strict"}:
        lane_verdict = "fail-untracked-or-missing" if strict else "warn-untracked-or-missing"
    else:
        lane_verdict = "error"

    failed_paths: list[dict[str, Any]] = []
    for row in payload.get("per_path", []):
        if row.get("verdict") not in {"tracked-and-committed"}:
            failed_paths.append({
                "path": row.get("path"),
                "verdict": row.get("verdict"),
            })

    return {
        "schema": R70_SCHEMA,
        "verdict": lane_verdict,
        "strict": strict,
        "paths": paths,
        "non_committed_paths": failed_paths,
        "verifier_payload_summary": {
            "claimed_path_count": payload.get("claimed_path_count"),
            "overall_verdict": overall,
        },
    }


# ---------------------------------------------------------------------------
# Top-level (R69 + R70 combined)
# ---------------------------------------------------------------------------

def validate_lane_result(
    text: str,
    *,
    repo_root: Path | None = None,
    strict: bool | None = None,
    no_live_call: bool = False,
) -> dict[str, Any]:
    """Top-level validator. Returns a JSON-serializable dict.

    Verdicts:
        no-claims-found
        pass-all-wired
        warn-claims-not-wired (default)
        fail-claims-not-wired (when strict=True or env elevated)
        error
    """
    repo_root = (repo_root or Path(__file__).resolve().parent.parent.parent).resolve()
    verifier_path = repo_root / "tools" / "r69-callable-wiring-verifier.py"
    server_path = repo_root / "tools" / "vault-mcp-server.py"
    if strict is None:
        strict = os.environ.get("AUDITOOOR_R69_LANE_VALIDATOR_STRICT", "") in {
            "1", "true", "yes",
        }

    claims = extract_claimed_callables(text)
    # agent_pathspec.json declares LANE-218 for the R70 sub-result block.
    if not claims:
        return {
            "schema": SCHEMA,
            "verdict": "no-claims-found",
            "strict": strict,
            "claims": [],
            "r70": validate_paths_r70(text, repo_root=repo_root, strict=strict),
        }

    invoke = run_r69_verifier(
        [c.name for c in claims],
        verifier_path=verifier_path,
        server_path=server_path if server_path.exists() else None,
        no_live_call=no_live_call,
    )
    payload = invoke.get("payload")
    if payload is None:
        return {
            "schema": SCHEMA,
            "verdict": "error",
            "strict": strict,
            "claims": [c.name for c in claims],
            "verifier_error": invoke.get("error") or "no-json-output",
            "verifier_stderr": invoke.get("stderr"),
            # agent_pathspec.json declares LANE-218 for the R70 sub-result.
            "r70": validate_paths_r70(text, repo_root=repo_root, strict=strict),
        }

    pass_set = {"wired-and-callable", "wired-but-degraded"}
    fail_callables: list[dict[str, Any]] = []
    for row in payload.get("callables", []):
        if row.get("verdict") not in pass_set:
            fail_callables.append({
                "name": row.get("name"),
                "verdict": row.get("verdict"),
            })

    if not fail_callables:
        verdict = "pass-all-wired"
    elif strict:
        verdict = "fail-claims-not-wired"
    else:
        verdict = "warn-claims-not-wired"

    snippets_by_name = {c.name: c.snippets for c in claims}
    out: dict[str, Any] = {
        "schema": SCHEMA,
        "verdict": verdict,
        "strict": strict,
        "claims": [
            {"name": c.name, "snippets": snippets_by_name.get(c.name, [])}
            for c in claims
        ],
        "failed_callables": fail_callables,
        "verifier_payload_summary": {
            "fail_count": payload.get("fail_count"),
            "total_count": payload.get("total_count"),
        },
    }
    # R70 file-tracking validation runs alongside R69 callable-wiring
    # validation. agent_pathspec.json declares LANE-218-R70-FILE-TRACKED-
    # VERIFIER; the R70 verifier is invoked through validate_paths_r70.
    # The R69 envelope is preserved verbatim for backward compatibility;
    # R70 results are attached under the "r70" key.
    out["r70"] = validate_paths_r70(text, repo_root=repo_root, strict=strict)
    return out


# --------------------------------------------------------------------------
# CLI entrypoint - run directly to validate a lane result file
# --------------------------------------------------------------------------


def _main(argv: list[str] | None = None) -> int:
    import argparse

    parser = argparse.ArgumentParser(
        description=(
            "Validate R69 callable-wiring claims in a lane result file. "
            "Extracts vault_X callable names from claim phrases and invokes "
            "tools/r69-callable-wiring-verifier.py."
        )
    )
    parser.add_argument(
        "lane_result_file",
        nargs="?",
        type=Path,
        help="Path to a lane-result markdown / JSON. If omitted, reads stdin.",
    )
    parser.add_argument("--strict", action="store_true")
    parser.add_argument("--no-live-call", action="store_true")
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args(argv)

    if args.lane_result_file is not None:
        try:
            text = args.lane_result_file.read_text(encoding="utf-8")
        except OSError as exc:
            print(f"ERROR: cannot read {args.lane_result_file}: {exc}", file=sys.stderr)
            return 1
    else:
        text = sys.stdin.read()

    result = validate_lane_result(
        text,
        strict=args.strict,
        no_live_call=args.no_live_call,
    )

    if args.json:
        json.dump(result, sys.stdout, indent=2, sort_keys=True)
        sys.stdout.write("\n")
    else:
        print(f"R69 lane-result validation (schema {SCHEMA})")
        print(f"  verdict     : {result['verdict']}")
        print(f"  strict      : {result.get('strict')}")
        if result.get("claims"):
            print(f"  claims      : {len(result['claims'])}")
            for c in result["claims"]:
                print(f"    - {c['name']}")
        if result.get("failed_callables"):
            print("  FAILED      :")
            for f in result["failed_callables"]:
                print(f"    - {f['name']}: {f['verdict']}")
        # R70 sub-result print. agent_pathspec.json declares LANE-218.
        r70 = result.get("r70") or {}
        if r70:
            print(f"R70 file-tracked validation (schema {R70_SCHEMA})")
            print(f"  verdict     : {r70.get('verdict')}")
            print(f"  paths       : {len(r70.get('paths') or [])}")
            for npath in r70.get("non_committed_paths") or []:
                print(f"    - {npath.get('path')}: {npath.get('verdict')}")

    # FAIL-promotion: either R69 fail OR R70 fail under strict.
    if result["verdict"] == "fail-claims-not-wired":
        return 1
    r70 = result.get("r70") or {}
    if r70.get("verdict") == "fail-untracked-or-missing":
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(_main())
