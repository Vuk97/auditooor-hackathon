#!/usr/bin/env python3
"""toolchain-probe.py - detect + record the language toolchains a workspace needs.

GENERIC, all-language, all-workspace. This is the MECHANICAL artifact for
README step-0e ("Install language toolchain"). Before this existed, step-0e had
attestation_required=true but artifact_checks=[] - a required step that greened on
a self-written attestation with ZERO on-disk proof. This tool captures a real,
inspectable record of which toolchains the workspace needs and what versions (if
any) are installed, so the gate can key on a file, not just prose.

Detection is language-agnostic. A tool is "required" if EITHER of:
  - the workspace's .auditooor/inscope_units.jsonl lists that tool's language, OR
  - a canonical manifest for that toolchain is present anywhere in the tree
    (foundry.toml -> forge, Cargo.toml -> cargo, go.mod -> go, package.json ->
    node, pyproject.toml/setup.py -> python, hardhat.config.* -> node, etc.)

For every required tool it runs `<tool> --version` (or the tool's version idiom)
and captures stdout verbatim. Legacy mode records absence without failing. Strict
mode is the canonical Step 0e gate: it still writes the artifact, but exits
non-zero when a required executable is absent, or when its version command does
not return a usable version.

Artifact: <ws>/.auditooor/toolchain_probe.json
Schema: auditooor.toolchain_probe.v1
  {
    "schema": "auditooor.toolchain_probe.v1",
    "generated_at": "<ISO-8601 UTC>",
    "workspace": "<abs path>",
    "languages_detected": ["solidity", ...],
    "tools": [
      {"tool": "forge", "required": true, "present": true,
       "version_stdout": "forge Version: 1.7.1\n..."},
      ...
    ]
  }
"""
from __future__ import annotations

import argparse
import datetime as _dt
import json
import shutil
import subprocess
import sys
from pathlib import Path

SCHEMA = "auditooor.toolchain_probe.v1"
ARTIFACT_REL = ".auditooor/toolchain_probe.json"

# tool -> version invocation. Each entry: the executable name (also the value of
# the "tool" field) mapped to the argv used to print its version. Language-generic;
# do NOT assume Solidity. Adding a new toolchain = one row here + a manifest/lang
# mapping below.
VERSION_CMDS: dict[str, list[str]] = {
    "forge": ["forge", "--version"],
    "cargo": ["cargo", "--version"],
    "go": ["go", "version"],
    "node": ["node", "--version"],
    "npm": ["npm", "--version"],
    "python3": ["python3", "--version"],
    "solc": ["solc", "--version"],
    "rustc": ["rustc", "--version"],
}

# canonical build/manifest filenames -> the tool(s) they imply. Presence of ANY
# of these anywhere in the tree (excluding vendored dirs) marks the tool required.
MANIFEST_TOOL: dict[str, list[str]] = {
    "foundry.toml": ["forge"],
    "Cargo.toml": ["cargo"],
    "go.mod": ["go"],
    "go.work": ["go"],
    "package.json": ["node", "npm"],
    "package-lock.json": ["node", "npm"],
    "npm-shrinkwrap.json": ["node", "npm"],
    "yarn.lock": ["node", "npm"],
    "pnpm-lock.yaml": ["node", "npm"],
    "bun.lock": ["node", "npm"],
    "bun.lockb": ["node", "npm"],
    "hardhat.config.js": ["node"],
    "hardhat.config.ts": ["node"],
    "hardhat.config.cjs": ["node"],
    "hardhat.config.mjs": ["node"],
    "tsconfig.json": ["node"],
    "pyproject.toml": ["python3"],
    "setup.py": ["python3"],
    "requirements.txt": ["python3"],
}

# inscope_units.jsonl `lang` value -> tool(s) that language needs to build. This
# is the primary, language-agnostic signal (a repo can declare a language with no
# manifest yet checked in). Keys are lower-cased before lookup.
LANG_TOOL: dict[str, list[str]] = {
    "solidity": ["forge"],
    "sol": ["forge"],
    "evm": ["forge"],
    "ethereum": ["forge"],
    "rust": ["cargo"],
    "rs": ["cargo"],
    "go": ["go"],
    "golang": ["go"],
    "javascript": ["node"],
    "js": ["node"],
    "node": ["node"],
    "nodejs": ["node"],
    "typescript": ["node"],
    "ts": ["node"],
    "oscript": ["node"],
    "aa": ["node"],
    "obyte": ["node"],
    "autonomousagent": ["node"],
    "autonomousagents": ["node"],
    "python": ["python3"],
    "py": ["python3"],
    "cairo": ["cargo"],  # scarb often via cargo toolchain; recorded best-effort
    "move": ["cargo"],
}

SUPPORTED_TOOLS = tuple(sorted(VERSION_CMDS))

# directories never worth descending into when scanning for manifests.
_PRUNE_DIRS = {
    "node_modules", ".git", "lib", "out", "target", "cache", "dependencies",
    ".auditooor", "vendor", "build", "artifacts", "__pycache__", ".venv", "venv",
}


def _now_utc() -> str:
    return _dt.datetime.now(_dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _detect_languages(ws: Path) -> list[str]:
    """Return sorted, de-duped lower-cased `lang` values from inscope_units.jsonl.

    Missing/empty file -> empty list (manifest scan still drives detection)."""
    langs: set[str] = set()
    inscope = ws / ".auditooor" / "inscope_units.jsonl"
    if inscope.is_file():
        for line in inscope.read_text(encoding="utf-8", errors="replace").splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                obj = json.loads(line)
            except json.JSONDecodeError:
                continue
            if not isinstance(obj, dict):
                continue
            lang = obj.get("lang")
            if isinstance(lang, str) and lang.strip():
                langs.add(lang.strip().lower())
    return sorted(langs)


def _inventory_diagnostics(ws: Path) -> tuple[bool, list[str]]:
    """Validate the authoritative inventory without changing legacy parsing."""
    inscope = ws / ".auditooor" / "inscope_units.jsonl"
    if not inscope.is_file():
        return False, []
    try:
        lines = inscope.read_text(encoding="utf-8").splitlines()
    except (OSError, UnicodeError) as exc:
        return True, [f"inventory_unreadable: {exc}"]
    if not lines or not any(line.strip() for line in lines):
        return True, ["inventory_empty: .auditooor/inscope_units.jsonl has no rows"]

    diagnostics: list[str] = []
    for line_no, text in enumerate(lines, start=1):
        if not text.strip():
            diagnostics.append(f"inventory_malformed: blank row at line {line_no}")
            continue
        try:
            row = json.loads(text)
        except json.JSONDecodeError as exc:
            diagnostics.append(f"inventory_malformed: line {line_no}: {exc.msg}")
            continue
        if not isinstance(row, dict):
            diagnostics.append(f"inventory_malformed: line {line_no}: row is not an object")
            continue
        lang = row.get("lang")
        if not isinstance(lang, str) or not lang.strip():
            diagnostics.append(
                f"inventory_malformed: line {line_no}: missing non-empty lang"
            )
            continue
        if lang.strip().lower() not in LANG_TOOL:
            diagnostics.append(
                f"inventory_unsupported_language: line {line_no}: {lang.strip()}"
            )
    return True, diagnostics


def _scan_manifests(ws: Path) -> set[str]:
    """Walk the tree (pruning vendored dirs) and return the set of manifest
    filenames present."""
    found: set[str] = set()
    targets = set(MANIFEST_TOOL)
    # os.walk-style prune via manual stack to skip vendored subtrees cheaply.
    stack = [ws]
    while stack:
        d = stack.pop()
        try:
            entries = list(d.iterdir())
        except (PermissionError, OSError):
            continue
        for e in entries:
            name = e.name
            if e.is_dir():
                if name in _PRUNE_DIRS or name.startswith("."):
                    # still descend into the workspace root's own dotdirs? No -
                    # inscope handles .auditooor; skip all dotdirs for manifests.
                    continue
                stack.append(e)
            elif name in targets:
                found.add(name)
    return found


def _required_tools(langs: list[str], manifests: set[str]) -> set[str]:
    req: set[str] = set()
    for lang in langs:
        for t in LANG_TOOL.get(lang, []):
            req.add(t)
    for m in manifests:
        for t in MANIFEST_TOOL.get(m, []):
            req.add(t)
    return req


def _probe_tool_status(tool: str) -> dict[str, object]:
    """Return a non-raising, inspectable result for one executable."""
    if shutil.which(tool) is None:
        return {
            "present": False,
            "version_stdout": "",
            "usable_version": False,
            "version_error": "executable not found on PATH",
        }
    cmd = VERSION_CMDS.get(tool, [tool, "--version"])
    try:
        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=30,
        )
    except (OSError, subprocess.SubprocessError):
        return {
            "present": True,
            "version_stdout": "",
            "usable_version": False,
            "version_error": "version command failed to execute",
        }
    out = (proc.stdout or "") + (proc.stderr or "")
    output = out.strip()
    returncode = getattr(proc, "returncode", 0)
    usable = returncode == 0 and bool(output)
    return {
        "present": True,
        "version_stdout": output,
        "usable_version": usable,
        "version_error": None if usable else "version command failed or returned no output",
    }


def _probe_tool(tool: str) -> tuple[bool, str]:
    """Legacy two-field wrapper retained for callers of the old helper."""
    result = _probe_tool_status(tool)
    return bool(result["present"]), str(result["version_stdout"])


def probe(ws: Path, *, strict: bool = False) -> dict:
    langs = _detect_languages(ws)
    manifests = _scan_manifests(ws)
    required = _required_tools(langs, manifests)
    inventory_present, inventory_diagnostics = _inventory_diagnostics(ws)

    tools_out: list[dict] = []
    for tool in SUPPORTED_TOOLS:
        if tool not in required:
            tools_out.append(
                {
                    "tool": tool,
                    "required": False,
                    "present": None,
                    "usable_version": None,
                    "version_stdout": "",
                    "version_error": None,
                    "status": "not_required",
                }
            )
            continue
        status = _probe_tool_status(tool)
        status_name = "ready" if status["usable_version"] else (
            "missing" if not status["present"] else "unusable_version"
        )
        tools_out.append(
            {
                "tool": tool,
                "required": True,
                **status,
                "status": status_name,
            }
        )

    strict_failures = list(inventory_diagnostics)
    for row in tools_out:
        if row["required"] and row["status"] != "ready":
            strict_failures.append(
                f"required_toolchain_{row['status']}: {row['tool']}"
            )
    strict_failures = sorted(strict_failures)

    return {
        "schema": SCHEMA,
        "generated_at": _now_utc(),
        "workspace": str(ws.resolve()),
        "languages_detected": langs,
        "manifests_detected": sorted(manifests),
        "inventory": {
            "path": ".auditooor/inscope_units.jsonl",
            "present": inventory_present,
            "valid": not inventory_diagnostics,
        },
        "tools": tools_out,
        "strict": strict,
        "strict_pass": not strict_failures,
        "strict_failures": strict_failures,
    }


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(
        description="Detect + record the language toolchains a workspace needs "
        "(mechanical artifact for README step-0e)."
    )
    ap.add_argument(
        "--workspace",
        "--ws",
        dest="workspace",
        required=True,
        help="Path to the audit workspace root.",
    )
    ap.add_argument(
        "--out",
        default=None,
        help="Override artifact path (default: <ws>/.auditooor/toolchain_probe.json).",
    )
    ap.add_argument(
        "--print",
        action="store_true",
        help="Also print the artifact JSON to stdout.",
    )
    ap.add_argument(
        "--strict",
        action="store_true",
        help="Fail after writing the report when inventory or required toolchains are not ready.",
    )
    args = ap.parse_args(argv)

    ws = Path(args.workspace).expanduser()
    if not ws.is_dir():
        print(f"toolchain-probe: workspace not a directory: {ws}", file=sys.stderr)
        return 2

    result = probe(ws, strict=args.strict)

    out_path = Path(args.out).expanduser() if args.out else ws / ARTIFACT_REL
    try:
        out_path.parent.mkdir(parents=True, exist_ok=True)
        out_path.write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
    except OSError as e:
        print(f"toolchain-probe: failed to write {out_path}: {e}", file=sys.stderr)
        return 3

    n_present = sum(
        1 for t in result["tools"] if t["required"] and t["status"] == "ready"
    )
    n_req = sum(1 for t in result["tools"] if t["required"])
    print(
        f"toolchain-probe: wrote {out_path} "
        f"({n_present}/{n_req} required tools present; "
        f"langs={result['languages_detected']})"
    )
    if args.print:
        print(json.dumps(result, indent=2))
    if args.strict and not result["strict_pass"]:
        print(
            "toolchain-probe: strict failure: "
            + "; ".join(result["strict_failures"]),
            file=sys.stderr,
        )
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
