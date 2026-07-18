#!/usr/bin/env python3
"""Generate per-function invariant scaffolds across audit workspaces.

For Solidity (the default `--lang solidity` path) the generator uses a
lightweight Solidity surface parser to find public/external non-view
functions, then emits one advisory Halmos harness per function plus a
manifest of matching Halmos invocations.

The additive language-aware path (`--lang {rust,go,move,cairo,vyper,cadence}`)
emits idiomatic per-function harness scaffolds for each target language
instead. All supported languages: solidity, rust, go, move, cairo, vyper,
cadence.

The generated harnesses are starting points for workers, not proof artifacts.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import shutil
import sys
import tomllib
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterable


SCHEMA = "auditooor.per_function_invariant_gen.v1"


# ---------------------------------------------------------------------------
# Fail-closed VACUITY GATE: a freshly emitted scaffold whose only assertion is
# a sentinel tautology (assert(true)/assert!(true)/assert True/...) must NEVER be
# counted as coverage. We stamp every emitted manifest row with `is_sentinel`
# (computed from the harness body via the shared tools/lib/harness_vacuity.py
# predicate) + add a manifest-level `sentinel_count`, so the genuine-coverage
# stage / cross-function-harness-producer / mutation-verify oracle that consume
# this manifest can refuse to credit a sentinel harness. Import-by-path because
# the package layout has no namespace package.
# ---------------------------------------------------------------------------
def _load_sentinel_predicate():
    import importlib.util as _ilu

    tool = Path(__file__).resolve().parent / "lib" / "harness_vacuity.py"
    if not tool.is_file():
        return None
    try:
        spec = _ilu.spec_from_file_location("harness_vacuity", str(tool))
        mod = _ilu.module_from_spec(spec)
        spec.loader.exec_module(mod)
        return mod.is_sentinel_only_harness
    except Exception:  # noqa: BLE001
        return None


_IS_SENTINEL = _load_sentinel_predicate()


# ---------------------------------------------------------------------------
# FIX-3 adversary-GOAL invariant axis (additive). The goal synthesizer routes a
# function through its matched impact_id(s) and emits GOAL-oriented relational
# templates, BOUND against the function source. Below the existing per-function
# invariant comment we inject one authoring comment per GOAL-BOUND template so a
# worker knows the exact adversary relation to assert. The sentinel body itself
# stays assert(true) - a goal COMMENT never inflates coverage; harness_vacuity
# still rejects the un-filled scaffold. Imported by path (tools/lib has no
# namespace package); graceful-None when unavailable.
# ---------------------------------------------------------------------------
def _load_goal_synth():
    import importlib.util as _ilu

    tool = Path(__file__).resolve().parent / "lib" / "goal_invariant_synth.py"
    if not tool.is_file():
        return None
    try:
        spec = _ilu.spec_from_file_location("goal_invariant_synth", str(tool))
        mod = _ilu.module_from_spec(spec)
        spec.loader.exec_module(mod)
        return mod
    except Exception:  # noqa: BLE001
        return None


_GOAL_SYNTH = _load_goal_synth()


def _extract_sol_fn_body(contract_file: Path, function_name: str) -> str:
    """Best-effort balanced-brace body of *function_name* in *contract_file*.

    Used only to BIND goal-invariant roles (accrual/balance/auth/...) against
    the real source. Returns "" on any read/parse miss (graceful - an empty
    body simply binds fewer roles, never a false credit)."""
    try:
        text = contract_file.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return ""
    m = re.search(r"function\s+" + re.escape(function_name) + r"\b", text)
    if not m:
        return ""
    body_start = text.find("{", m.end())
    if body_start < 0:
        return ""
    depth = 0
    for i in range(body_start, min(body_start + 20000, len(text))):
        if text[i] == "{":
            depth += 1
        elif text[i] == "}":
            depth -= 1
            if depth == 0:
                return text[body_start:i + 1]
    return text[body_start:body_start + 20000]


def _goal_comment_block(records: list[dict]) -> str:
    """Render one `// GOAL [<impact_id>]: <goal_statement>` authoring line per
    GOAL-BOUND record. Returns "" when there is no bound goal (additive)."""
    lines = [
        f"// GOAL [{r.get('impact_id')}]: {r.get('goal_statement')}"
        for r in records
        if r.get("status") == "goal-bound"
    ]
    return "\n".join(lines)


def _solidity_goal_invariants(fn: "SolidityFunction") -> list[dict]:
    """Resolve goal-invariant records for a Solidity function (additive, []-safe)."""
    if _GOAL_SYNTH is None:
        return []
    try:
        body = _extract_sol_fn_body(fn.contract_file, fn.function_name)
        return _GOAL_SYNTH.goal_invariants_for(
            fn.function_name, fn.args or "",
            language="solidity",
            scope_text=str(fn.contract_file),
            source_body=body,
            file_line=f"{fn.relative_file}:{fn.line}",
            # attrs is the signature TAIL (visibility + mutability + applied
            # modifiers) - the correct input for the caller_auth_guard role.
            auth_sig_tail=fn.attrs or "",
        )
    except Exception:  # noqa: BLE001
        return []


def _stamp_sentinel(rows: list[dict], bodies: dict[str, str]) -> int:
    """Stamp each row's `is_sentinel` from its rendered harness body.

    `bodies` maps harness_path -> rendered harness source. A row with no body
    (should not happen) is conservatively marked sentinel (fail-closed). Returns
    the count of sentinel rows.
    """
    count = 0
    for row in rows:
        body = bodies.get(str(row.get("harness_path") or ""), "")
        if _IS_SENTINEL is None:
            # Predicate unavailable: do not silently green-light. Mark every row
            # sentinel=None so downstream gates know the check did not run, and
            # do not count it as a real-property credit.
            row["is_sentinel"] = None
            continue
        sentinel = bool(_IS_SENTINEL(body))
        row["is_sentinel"] = sentinel
        if sentinel:
            count += 1
    return count


FUNCTION_RE = re.compile(
    r"\bfunction\s+([A-Za-z_][A-Za-z0-9_]*)\s*"
    r"\((?P<args>[^)]*)\)\s*"
    r"(?P<attrs>[^{;]*)"
    r"(?:\{|;)",
    re.MULTILINE | re.DOTALL,
)
CONTRACT_RE = re.compile(
    r"\b(?:abstract\s+)?(?:contract|library|interface)\s+([A-Za-z_][A-Za-z0-9_]*)\b"
)
COMMENT_RE = re.compile(r"//.*?$|/\*.*?\*/", re.MULTILINE | re.DOTALL)
PRAGMA_RE = re.compile(r"pragma\s+solidity\s+([^;]+);")
PUBLICISH_RE = re.compile(r"\b(public|external)\b")
READ_ONLY_RE = re.compile(r"\b(view|pure)\b")
CONSTRUCTOR_NAMES = {"constructor", "receive", "fallback"}


@dataclass(frozen=True)
class SolidityFunction:
    contract_name: str
    function_name: str
    contract_file: Path
    relative_file: str
    line: int
    attrs: str
    args: str

    @property
    def harness_contract(self) -> str:
        return f"Halmos_{self.contract_name}_{self.function_name}"

    @property
    def harness_file_name(self) -> str:
        return f"{self.harness_contract}.t.sol"

    @property
    def selector(self) -> str:
        return f"{self.contract_name}.{self.function_name}"


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def strip_comments(text: str) -> str:
    return COMMENT_RE.sub(lambda m: "\n" * m.group(0).count("\n"), text)


def line_number(text: str, offset: int) -> int:
    return text.count("\n", 0, offset) + 1


def is_pre_0_8_pragma(text: str) -> bool:
    """True when the file's solidity pragma pins a major.minor below 0.8.

    The generated harnesses are `pragma solidity ^0.8.13`; importing a <0.8
    contract produces a "Found incompatible versions" compile error and a
    halmos engine-error. We skip those functions so the per-function build
    is clean (e.g. Polymarket ProxyFactory ships solc 0.5.x contracts). Files
    with no pragma, or a >=0.8 pragma, are NOT skipped.
    """
    matches = PRAGMA_RE.findall(text)
    if not matches:
        return False
    saw_any_version = False
    for raw in matches:
        for vm in re.finditer(r"(\d+)\.(\d+)(?:\.(\d+))?", raw):
            saw_any_version = True
            major = int(vm.group(1))
            minor = int(vm.group(2))
            if (major, minor) >= (0, 8):
                return False
    # Every parsed version was below 0.8 (and at least one was seen).
    return saw_any_version


def infer_contract_name(clean_text: str, offset: int, fallback: str) -> str:
    last = None
    for match in CONTRACT_RE.finditer(clean_text, 0, offset):
        last = match.group(1)
    return last or fallback


def should_include(attrs: str, include_internal: bool, include_read_only: bool = False) -> bool:
    normalized = " ".join(attrs.split())
    if READ_ONLY_RE.search(normalized) and not include_read_only:
        return False
    if include_internal:
        return True
    return bool(PUBLICISH_RE.search(normalized))


# CAP-GAP-99: universal scope-exclusion filter (mirrors
# mimo-per-file-batch-gen.py EXCLUDE_PATH_PARTS). Without this the orchestrator
# walked Foundry build artifacts (out/<Contract>.sol/ DIRECTORIES) and forge-std
# test framework (Vm.sol, console.sol, StdStyle.sol), wasting hours and emitting
# "Is a directory" warnings. Applies to all workspaces. Env override:
# AUDITOOOR_PREFLIGHT_EXTRA_EXCLUDES (newline-separated extra "/part/" tokens).
import os as _os

EXCLUDE_PATH_PARTS = {
    "/test/", "/tests/", "/mock/", "/mocks/", "/lib/",
    "/out/", "/cache/", "/node_modules/", "/.git/",
    "/dependencies/", "/forge-std/", "/_archive/",
    "/script/", "/scripts/", "/build/", "/artifacts/",
    # CAP-GAP-101: duplicate-named OOS fork copies (e.g. Hyperbridge ships an
    # out-of-scope Tron fork of IntentGatewayV2 under evm/tron/). Without this
    # the orchestrator anchored packs to the wrong copy of same-named contracts.
    "/tron/", "/.foundry/", "/typechain/", "/typechain-types/",
    "/poc-tests/", "/poc_tests/", "/fuzz_runs/", "/symbolic_runs/",
    "/.auditooor/",
    # P1-e / taxonomy mode 19 (wrong-CUT / OOS-target enumeration): deployed
    # re-implementation / verified-source mirror trees are NOT the in-scope CUT.
    # beanstalk emitted 13/41 per-fn harnesses against
    # reference/instascope_deployed_zip/* (a deployed reimpl + bundled
    # @openzeppelin interfaces). Authoritative scope is still the post-parse
    # inscope_units.jsonl filter; these markers are a cheap path-level guard so
    # an OOS mirror never becomes a coverage unit even when no manifest exists.
    "/reference/", "/instascope_deployed_zip/", "/deployed_zip/",
    "/verified_sources/", "/verified-sources/",
}
for _extra in (_os.environ.get("AUDITOOOR_PREFLIGHT_EXTRA_EXCLUDES", "") or "").splitlines():
    _extra = _extra.strip()
    if _extra:
        EXCLUDE_PATH_PARTS.add(_extra if _extra.startswith("/") else f"/{_extra}/")


def discover_solidity_files(workspace: Path, contract_filter: str | None) -> list[Path]:
    candidates: list[Path] = []
    roots = [workspace / "src", workspace / "contracts", workspace]
    seen: set[Path] = set()
    for root in roots:
        if not root.exists():
            continue
        for path in root.rglob("*.sol"):
            if path in seen:
                continue
            seen.add(path)
            posix = path.as_posix()
            # CAP-GAP-99: skip build artifacts / deps / test framework / mocks.
            if any(part in posix for part in EXCLUDE_PATH_PARTS):
                continue
            # Skip Foundry test files and the artifact-dir trap (out/X.sol/ is a dir).
            if posix.endswith(".t.sol") or not path.is_file():
                continue
            if contract_filter and contract_filter not in {path.stem, path.name, path.as_posix()}:
                continue
            candidates.append(path)
    return sorted(candidates)


def parse_functions(
    workspace: Path,
    files: Iterable[Path],
    include_internal: bool,
    function_filter: str | None,
    include_read_only: bool = False,
) -> list[SolidityFunction]:
    rows: list[SolidityFunction] = []
    for path in files:
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError as exc:
            print(f"[per-function-invariant-gen] WARN cannot read {path}: {exc}", file=sys.stderr)
            continue
        if is_pre_0_8_pragma(text):
            # Harnesses are pragma ^0.8.13; a <0.8 source can't be imported.
            continue
        clean = strip_comments(text)
        fallback_contract = path.stem
        try:
            rel = path.relative_to(workspace).as_posix()
        except ValueError:
            rel = path.as_posix()
        for match in FUNCTION_RE.finditer(clean):
            name = match.group(1)
            if name in CONSTRUCTOR_NAMES:
                continue
            if function_filter and function_filter != name:
                continue
            attrs = match.group("attrs") or ""
            if not should_include(attrs, include_internal=include_internal, include_read_only=include_read_only):
                continue
            contract_name = infer_contract_name(clean, match.start(), fallback_contract)
            rows.append(
                SolidityFunction(
                    contract_name=contract_name,
                    function_name=name,
                    contract_file=path,
                    relative_file=rel,
                    line=line_number(clean, match.start()),
                    attrs=" ".join(attrs.split()),
                    args=" ".join((match.group("args") or "").split()),
                )
            )
    return rows


def sanitize_identifier(value: str) -> str:
    cleaned = re.sub(r"[^A-Za-z0-9_]", "_", value)
    if not cleaned or cleaned[0].isdigit():
        cleaned = f"_{cleaned}"
    return cleaned


def import_path_for_harness(fn: SolidityFunction, output_dir: Path,
                            source_path: Path | None = None) -> str:
    rel = os.path.relpath(source_path or fn.contract_file, output_dir)
    return Path(rel).as_posix()


def find_scaffold_root(contract_file: Path, workspace: Path) -> Path | None:
    """Find the nearest ancestor dir of contract_file that owns a foundry.toml.

    For block-explorer-fetched verified source, each contract dir is scaffolded
    with its own foundry.toml + remappings + populated lib/ (see
    tools/foundry-scaffold-verified-source.py). A harness placed in that dir's
    `test/` builds against the scaffolded contracts. We walk UP from the source
    file to the first ancestor with a foundry.toml, stopping at (and not above)
    the workspace root unless the workspace itself owns the foundry.toml.

    Returns None when no ancestor foundry.toml exists below/at the workspace
    (git-cloned projects with a single workspace-root foundry.toml fall through
    to the legacy workspace-root path so behavior is a NO-OP for them).
    """
    try:
        contract_file = contract_file.resolve()
        ws = workspace.resolve()
    except OSError:
        return None
    # The contract file must live inside the workspace; otherwise no scaffold.
    try:
        contract_file.relative_to(ws)
    except ValueError:
        return None
    current = contract_file.parent
    while True:
        if (current / "foundry.toml").is_file():
            # Treat the workspace-root foundry.toml as "no per-contract scaffold"
            # so existing git-cloned/single-project workspaces are unchanged.
            if current == ws:
                return None
            return current
        if current == ws:
            return None
        parent = current.parent
        if parent == current:
            return None
        current = parent


def find_engine_harness_root(contract_name: str, workspace: Path) -> Path | None:
    """Find a matching pre-existing Foundry engine-harness project.

    Some workspaces keep the CUT in the workspace source tree while the
    runnable Foundry project lives at
    ``poc-tests/<Contract>-engine-harness``.  In that layout there is no
    source ancestor ``foundry.toml`` to discover, so the generated harness
    would otherwise be placed under ``.auditooor/per_function_invariants``
    and Forge would be invoked from the wrong project root.

    Only the exact contract-named directory is accepted.  This avoids
    accidentally binding a function to a neighboring harness or to a
    ``*-real-engine-harness`` variant with different setup.
    """
    try:
        workspace = workspace.resolve()
    except OSError:
        return None
    candidate = workspace / "poc-tests" / f"{contract_name}-engine-harness"
    try:
        candidate.relative_to(workspace)
    except ValueError:
        return None
    if candidate.is_dir() and (candidate / "foundry.toml").is_file():
        return candidate
    return None


def ensure_engine_harness_root(contract_name: str, workspace: Path,
                               *, dry_run: bool) -> Path | None:
    """Create a minimal Foundry root when a CUT has no exact engine root."""
    existing = find_engine_harness_root(contract_name, workspace)
    if existing is not None:
        return existing
    candidate = workspace / "poc-tests" / f"{contract_name}-engine-harness"
    donor = next(
        (p for p in sorted((workspace / "poc-tests").glob("*-engine-harness"))
         if p.is_dir() and (p / "foundry.toml").is_file()
         and ((p / "lib" / "forge-std").is_dir() or (p / "lib" / "forge-std").is_symlink())),
        None,
    )
    if donor is None:
        return None
    if dry_run:
        return candidate
    try:
        candidate.mkdir(parents=True, exist_ok=True)
        (candidate / "test").mkdir(exist_ok=True)
        if not (candidate / "foundry.toml").exists():
            shutil.copy2(donor / "foundry.toml", candidate / "foundry.toml")
        if (donor / "remappings.txt").is_file() and not (candidate / "remappings.txt").exists():
            shutil.copy2(donor / "remappings.txt", candidate / "remappings.txt")
        lib = candidate / "lib"
        donor_lib = donor / "lib"
        if not lib.exists():
            try:
                lib.symlink_to(donor_lib, target_is_directory=True)
            except OSError:
                shutil.copytree(donor_lib, lib, dirs_exist_ok=True)
        return candidate if (candidate / "foundry.toml").is_file() else None
    except OSError:
        return None


def foundry_test_root(scaffold_root: Path) -> Path:
    """Return the configured Foundry test directory for a project root.

    Foundry defaults to ``test``, but audited repositories commonly configure
    ``test = "tests"``.  Harness generation must follow that setting or Forge
    silently discovers zero generated tests.
    """
    config_path = scaffold_root / "foundry.toml"
    try:
        with config_path.open("rb") as handle:
            config = tomllib.load(handle)
        configured = config.get("profile", {}).get("default", {}).get("test", "test")
        if isinstance(configured, str) and configured.strip():
            return (scaffold_root / configured).resolve()
    except (OSError, tomllib.TOMLDecodeError, AttributeError):
        pass
    return scaffold_root / "test"


def _source_project_root(contract_file: Path, workspace: Path) -> Path | None:
    """Return the nearest source project carrying installed dependencies."""
    try:
        ws = workspace.resolve()
        current = contract_file.resolve().parent
    except OSError:
        return None
    while True:
        if (current / "node_modules").is_dir() or (current / "package.json").is_file():
            return current
        if current == ws or current.parent == current:
            return None
        try:
            current.relative_to(ws)
        except ValueError:
            return None
        current = current.parent


def _engine_source_path(contract_file: Path, workspace: Path,
                        engine_root: Path) -> Path | None:
    """Expose an external CUT source tree inside a reusable Foundry root.

    Engine roots are often self-contained model projects.  A per-function
    harness must instead compile the real CUT, while Forge rejects imports that
    escape the project root.  A symlink keeps mutation-verify edits on the
    original pinned source without copying or mutating the CUT layout.
    """
    try:
        ws = workspace.resolve()
        source = contract_file.resolve()
        rel = source.relative_to(ws)
    except (OSError, ValueError):
        return None
    # Link the source's containing directory, preserving its workspace-relative
    # import topology (for example src/foo/contracts plus sibling local imports).
    source_dir = source.parent
    rel_dir = rel.parent
    destination = engine_root / rel_dir
    try:
        destination.parent.mkdir(parents=True, exist_ok=True)
        if destination.is_symlink():
            if destination.resolve() != source_dir:
                return None
        elif destination.exists():
            return None
        else:
            destination.symlink_to(source_dir, target_is_directory=True)
        return engine_root / rel
    except OSError:
        return None


def _ensure_engine_remappings(contract_file: Path, workspace: Path,
                              engine_root: Path) -> None:
    """Add package remappings needed by the linked CUT, without clobbering them."""
    project = _source_project_root(contract_file, workspace)
    if project is None or not (project / "node_modules").is_dir():
        return
    remap_file = engine_root / "remappings.txt"
    try:
        existing = remap_file.read_text(encoding="utf-8") if remap_file.is_file() else ""
        existing_lines = []
        prefixes = set()
        for line in existing.splitlines():
            prefix = line.split("=", 1)[0].strip().rstrip("/") if "=" in line else ""
            if prefix and prefix in prefixes:
                continue
            existing_lines.append(line)
            if prefix:
                prefixes.add(prefix)
        imports = set()
        source_dir = contract_file.resolve().parent
        for path in source_dir.rglob("*.sol"):
            try:
                text = path.read_text(encoding="utf-8", errors="replace")
            except OSError:
                continue
            imports.update(re.findall(r"(?:import|from)\s+['\"]([^'\"]+)['\"]", text))
        additions = []
        for spec in sorted(imports):
            if spec.startswith("."):
                continue
            parts = spec.split("/")
            package = "/".join(parts[:2]) if spec.startswith("@") and len(parts) >= 2 else parts[0]
            if package in prefixes:
                continue
            target = project / "node_modules" / package
            if target.is_dir():
                additions.append(f"{package}/={target.resolve()}/")
                prefixes.add(package)
        if additions:
            text = "\n".join(existing_lines).rstrip() + ("\n" if existing_lines else "")
            remap_file.write_text(text + "\n".join(additions) + "\n", encoding="utf-8")
        elif existing_lines != existing.splitlines():
            remap_file.write_text("\n".join(existing_lines) + "\n", encoding="utf-8")
    except OSError:
        return


def load_preflight_pack(workspace: Path, preflight_dir: Path | None, fn: SolidityFunction) -> dict | None:
    candidates: list[Path] = []
    if preflight_dir is not None:
        candidates.append(preflight_dir)
    candidates.append(workspace / ".auditooor" / "pre_flight_packs")
    seen: set[Path] = set()
    for directory in candidates:
        if directory in seen:
            continue
        seen.add(directory)
        if not directory.is_dir():
            continue
        for path in sorted(directory.glob("pre_flight_pack_*.json")):
            try:
                payload = json.loads(path.read_text(encoding="utf-8"))
            except (OSError, json.JSONDecodeError):
                continue
            target = payload.get("target") if isinstance(payload.get("target"), dict) else {}
            if (
                payload.get("contract") == fn.contract_name
                and payload.get("function") == fn.function_name
            ) or (
                target.get("contract") == fn.contract_name
                and target.get("function") == fn.function_name
            ):
                payload["_pack_path"] = str(path)
                return payload
    return None


def invariant_ids_from_pack(pack: dict | None) -> list[str]:
    if not pack:
        return []
    touched = pack.get("invariants_touched")
    if isinstance(touched, dict):
        values = touched.get("invariant_ids")
        if isinstance(values, list):
            return [str(value) for value in values if str(value).strip()][:20]
    return []


def render_harness(fn: SolidityFunction, workspace: Path, output_dir: Path,
                   pack: dict | None, source_path: Path | None = None) -> str:
    rel_import = import_path_for_harness(fn, output_dir, source_path)
    check_name = sanitize_identifier(f"check_{fn.function_name}_does_not_break_core_invariant")
    # Dual-prefix scaffold: halmos discovers `check_`/`invariant_`; `forge test`
    # (the genuine-coverage mutation-verify runner) discovers ONLY `test*`/
    # `invariant*`. Emitting only `check_` made forge run 0 tests -> baseline
    # "no-execution" -> the harness could NEVER be classified (no-property-discovered)
    # even after a genuine fill, so live-engines/hollow stayed red on every
    # forge-engine workspace. Emit a `test_` twin so BOTH engines discover the
    # scaffold; an agent fills whichever the workspace's engine runs.
    test_name = sanitize_identifier(f"test_{fn.function_name}_does_not_break_core_invariant")
    invariants = invariant_ids_from_pack(pack)
    invariant_comment = "\n".join(f"// Candidate invariant: {item}" for item in invariants) or "// Candidate invariant: derive from pre-flight pack or hunter brief."
    # FIX-3: inject one authoring comment per GOAL-BOUND template BELOW the
    # invariant comment so a worker knows the exact adversary relation to assert.
    # The sentinel body stays assert(true) (the goal comment never inflates
    # coverage). Empty when no goal binds (additive).
    goal_records = _solidity_goal_invariants(fn)
    goal_comment = _goal_comment_block(goal_records)
    if goal_comment:
        invariant_comment = invariant_comment + "\n" + goal_comment
    pack_path = pack.get("_pack_path") if isinstance(pack, dict) else None
    pack_comment = f"// Pre-flight pack: {pack_path}" if pack_path else "// Pre-flight pack: not found at generation time."
    return f"""// SPDX-License-Identifier: UNLICENSED
pragma solidity >=0.8.0;

// Auto-generated by tools/per-function-invariant-gen.py.
// Function under test: {fn.selector} at {fn.relative_file}:{fn.line}
{pack_comment}
{invariant_comment}
// This advisory scaffold is not proof. Replace the sentinel assertion with
// a source-grounded property before using the harness as evidence.
import "{rel_import}";

contract {fn.harness_contract} {{
    // halmos symbolic entry (check_/invariant_ prefix)
    function {check_name}() public {{
        assert(true);
    }}
    // forge concrete entry (test_ prefix) - so `forge test` actually executes
    // this scaffold; replace BOTH bodies with a source-grounded property.
    function {test_name}() public {{
        assert(true);
    }}
}}
"""


def write_harnesses(
    workspace: Path,
    functions: Iterable[SolidityFunction],
    output_dir: Path,
    overwrite: bool,
    dry_run: bool,
    preflight_dir: Path | None,
) -> list[dict]:
    rows: list[dict] = []
    if not dry_run:
        output_dir.mkdir(parents=True, exist_ok=True)
    for fn in functions:
        # Per-contract scaffold root (block-explorer-fetched verified source):
        # if the source file has a nearest-ancestor foundry.toml below the
        # workspace, place the harness in <scaffold_root>/test/ so it builds
        # against the scaffolded contracts + populated lib/. Falls back to the
        # legacy workspace-root output dir (single-project / git-cloned repos).
        scaffold_root = find_scaffold_root(fn.contract_file, workspace)
        if scaffold_root is None:
            scaffold_root = ensure_engine_harness_root(
                fn.contract_name, workspace, dry_run=dry_run
            )
        if scaffold_root is not None:
            harness_dir = foundry_test_root(scaffold_root)
            halmos_root: str | None = str(scaffold_root)
            linked_source = None
            if find_scaffold_root(fn.contract_file, workspace) is None:
                if dry_run:
                    try:
                        linked_source = scaffold_root / fn.contract_file.resolve().relative_to(workspace.resolve())
                    except (OSError, ValueError):
                        linked_source = None
                else:
                    linked_source = _engine_source_path(fn.contract_file, workspace, scaffold_root)
                if linked_source is not None and not dry_run:
                    _ensure_engine_remappings(fn.contract_file, workspace, scaffold_root)
        else:
            harness_dir = output_dir
            halmos_root = None
            linked_source = None
        if not dry_run:
            harness_dir.mkdir(parents=True, exist_ok=True)
        harness_path = harness_dir / fn.harness_file_name
        import_path = import_path_for_harness(fn, harness_dir, linked_source)
        pack = load_preflight_pack(workspace, preflight_dir, fn)
        body = render_harness(fn, workspace, harness_dir, pack, linked_source)
        # P1-b no-clobber (taxonomy mode 13): a regeneration MUST NEVER overwrite
        # a harness a worker has filled with a real (non-sentinel) property, even
        # under --overwrite. ssv lost 11 genuine VMF harnesses (clobbered back to
        # assert(true) scaffolds) while banked mvc_sidecar records still pointed
        # at them. Read any existing file; if it is NOT sentinel-only (a real
        # harness per the shared tools/lib/harness_vacuity.py predicate), keep it
        # verbatim and record status='preserved-existing-real-harness'. The
        # banked body/hash are taken from the PRESERVED file so the manifest row
        # describes the on-disk harness, not the discarded scaffold.
        if harness_path.exists() and _is_real_existing_harness(harness_path):
            try:
                body = harness_path.read_text(encoding="utf-8", errors="replace")
            except OSError:
                pass
            body_hash = hashlib.sha256(body.encode("utf-8")).hexdigest()
            rows.append(
                _solidity_row(fn, harness_path, import_path, halmos_root, pack,
                              status="preserved-existing-real-harness",
                              body=body, body_hash=body_hash, workspace=workspace)
            )
            continue
        body_hash = hashlib.sha256(body.encode("utf-8")).hexdigest()
        # P1-e non-empty-spec assertion (taxonomy mode 18): never write a 0-byte
        # / whitespace-only spec. A render that collapses to empty is a silent
        # spec-layer skip; fail-closed by skipping the unit (status=
        # 'skipped-empty-render') and writing NO file rather than a dead stub.
        if not (body and body.strip()):
            rows.append(
                _solidity_row(fn, harness_path, import_path, halmos_root, pack,
                              status="skipped-empty-render",
                              body="", body_hash=body_hash, workspace=workspace)
            )
            continue
        status = "would-write" if dry_run else "written"
        if harness_path.exists() and not overwrite:
            status = "exists"
        elif not dry_run:
            harness_path.write_text(body, encoding="utf-8")
        rows.append(
            _solidity_row(fn, harness_path, import_path, halmos_root, pack,
                          status=status, body=body, body_hash=body_hash,
                          workspace=workspace)
        )
    return rows


def _is_real_existing_harness(path: Path) -> bool:
    """True iff *path* exists and holds a REAL (non-sentinel) harness.

    P1-b no-clobber predicate (taxonomy mode 13). Reads the file and consults the
    shared tools/lib/harness_vacuity.py predicate. Conservative / fail-closed in
    the no-clobber direction: if the predicate is unavailable or the file cannot
    be read, return False so the generator falls through to its normal write path
    (we only PRESERVE on a confirmed real harness).
    """
    if _IS_SENTINEL is None:
        return False
    try:
        existing = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return False
    if not existing.strip():
        return False
    try:
        return not bool(_IS_SENTINEL(existing))
    except Exception:  # noqa: BLE001
        return False


def _solidity_row(fn, harness_path, import_path, halmos_root, pack, *,
                  status, body, body_hash, workspace) -> dict:
    """Build a single Solidity manifest row (factored out so the normal-write,
    preserved-existing-real-harness and skipped-empty-render paths emit a
    consistent row shape)."""
    halmos_args = ["--match-contract", fn.harness_contract]
    # The workspace arg passed to halmos-runner.sh is the build root: the
    # scaffold root when present (so $PWD/foundry.toml resolves the
    # scaffolded project), else the workspace.
    runner_root = halmos_root or str(workspace)
    halmos_invocation = {
        "runner": "tools/halmos-runner.sh",
        "workspace_arg": runner_root,
        "match_contract": fn.harness_contract,
        "args": halmos_args,
        "command": " ".join(["bash", "tools/halmos-runner.sh", runner_root, *halmos_args]),
        "working_directory": runner_root,
    }
    # FIX-3: stamp the manifest row with the matched goal impact_ids + the count
    # of GOAL-BOUND templates. goal_bound_count counts ONLY bound goals - an
    # unbound goal is never credited (never-false-pass). Additive: the existing
    # row shape is untouched.
    _goal_records = _solidity_goal_invariants(fn)
    _goal_impact_ids = sorted({
        str(r.get("impact_id")) for r in _goal_records if r.get("impact_id")
    })
    _goal_bound_count = sum(
        1 for r in _goal_records if r.get("status") == "goal-bound"
    )
    return {
        "contract": fn.contract_name,
        "function": fn.function_name,
        "selector": fn.selector,
        "source": f"{fn.relative_file}:{fn.line}",
        "attrs": fn.attrs,
        "args": fn.args,
        "goal_impact_ids": _goal_impact_ids,
        "goal_bound_count": _goal_bound_count,
        "harness_contract": fn.harness_contract,
        "harness_path": str(harness_path),
        "import_path": import_path,
        "halmos_root": halmos_root,
        "preflight_pack_path": pack.get("_pack_path") if isinstance(pack, dict) else None,
        "invariants_touched": invariant_ids_from_pack(pack),
        "halmos_args": halmos_args,
        "halmos_invocation": halmos_invocation,
        "status": status,
        "sha256": body_hash,
        # Fail-closed vacuity gate: True when this scaffold's only
        # assertion is a sentinel tautology (assert(true)). Stamped from
        # the rendered body via tools/lib/harness_vacuity.py so the
        # genuine-coverage stage cannot credit it as real coverage. A
        # preserved real harness is_sentinel=False (it is a real property).
        "is_sentinel": (
            bool(_IS_SENTINEL(body)) if _IS_SENTINEL is not None and body else None
        ),
    }


def cleanup_stale_generated_harnesses(output_dir: Path, rows: list[dict]) -> list[str]:
    """Delete stale auto-generated harnesses that are absent from the new manifest."""
    keep = {str(Path(row["harness_path"]).resolve()) for row in rows if row.get("harness_path")}
    removed: list[str] = []
    if not output_dir.is_dir():
        return removed
    for path in sorted(output_dir.glob("Halmos_*.t.sol")):
        if str(path.resolve()) in keep:
            continue
        try:
            body = path.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue
        if "Auto-generated by tools/per-function-invariant-gen.py" not in body:
            continue
        path.unlink()
        removed.append(str(path))
    return removed


def _load_inscope_file_set(ws: Path):
    """Return the AUTHORITATIVE in-scope file set from ``.auditooor/inscope_units.jsonl``
    (the manifest the hunt-worklist + heatmap gates already treat as scope truth), or
    ``None`` when no manifest exists (then no filtering - preserves legacy behavior).

    WHY: ``discover_solidity_files`` / ``discover_generic_files`` walk the whole workspace
    src_roots, so on a multi-package monorepo (OP Stack: contracts-bedrock/src + op-node +
    op-dispute-mon + in-scope op-reth crates) the denominator was polluted with
    OUT-OF-SCOPE packages (kona, cannon, op-batcher, op-devstack, upstream reth crates, ...),
    inflating the function count ~5x. Honoring the in-scope manifest restores a
    scope-correct denominator. Disable with AUDITOOOR_FCC_NO_SCOPE_FILTER=1.
    """
    if os.environ.get("AUDITOOOR_FCC_NO_SCOPE_FILTER"):
        return None
    manifest = ws / ".auditooor" / "inscope_units.jsonl"
    if not manifest.is_file():
        return None
    files: set = set()
    for line in manifest.read_text(encoding="utf-8", errors="replace").splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            row = json.loads(line)
        except (json.JSONDecodeError, ValueError):
            continue
        f = str(row.get("file") or "").strip().lstrip("./").replace("\\", "/")
        if f:
            files.add(f)
    return files or None


def _norm_inscope_path(p: str) -> str:
    return str(p or "").strip().lstrip("./").replace("\\", "/")


def build_manifest(workspace: Path, output_dir: Path, rows: list[dict]) -> dict:
    return {
        "schema": SCHEMA,
        "generated_at": utc_now(),
        "workspace": str(workspace),
        "output_dir": str(output_dir),
        "function_count": len(rows),
        # Fail-closed vacuity gate: how many emitted harnesses are sentinel-only
        # scaffolds (assert(true)) that MUST NOT be counted as coverage until a
        # worker replaces the sentinel with a real source-grounded property.
        "sentinel_count": sum(1 for r in rows if r.get("is_sentinel") is True),
        "non_sentinel_count": sum(1 for r in rows if r.get("is_sentinel") is False),
        "halmos_invocations": [row["halmos_invocation"] for row in rows],
        "functions": rows,
    }


# ===========================================================================
# LANGUAGE-AWARE generalization (additive; Solidity path above is UNCHANGED).
#
# `--lang {solidity,rust,go,move,cairo}` (default solidity). For the non-Solidity
# languages this emits per-function HARNESS SCAFFOLDS in the target language's
# idiomatic test form (Rust = #[test]/proptest scaffold, Go = `func TestX` /
# `func FuzzX` scaffold) plus a manifest whose `functions[]` rows carry the SAME
# keys the genuine-coverage stage + cross-function-harness-producer consume
# (`function`, `source`, `harness_contract`, `harness_path`). The scaffolds are
# advisory starting points (sentinel-asserting), exactly like the Solidity ones;
# a worker replaces the sentinel with a source-grounded property before the
# harness counts as evidence.
# ===========================================================================

_GEN_LANG_EXT = {"rust": ".rs", "go": ".go", "move": ".move", "cairo": ".cairo",
                 "vyper": ".vy", "cadence": ".cdc"}

_GEN_FN_RES = {
    "rust": re.compile(r"^\s*(?:pub(?:\s*\([^)]*\))?\s+)?(?:async\s+)?fn\s+([A-Za-z_]\w*)\s*[<(]", re.MULTILINE),
    "go": re.compile(r"^\s*func\s*(?:\([^)]*\)\s*)?([A-Za-z_]\w*)\s*[\[(]", re.MULTILINE),
    "move": re.compile(r"^\s*(?:public\s+)?(?:entry\s+)?fun\s+([A-Za-z_]\w*)\s*[<(]", re.MULTILINE),
    "cairo": re.compile(r"^\s*(?:pub\s+)?fn\s+([A-Za-z_]\w*)\s*[<(]", re.MULTILINE),
    # Vyper: `def name(...)` / `@external` `def name(...)`. The @decorators sit
    # on their own lines above the def, so the regex anchors on the def itself.
    "vyper": re.compile(r"^\s*def\s+([A-Za-z_]\w*)\s*\(", re.MULTILINE),
    # Cadence: `fun name(...)`, `access(all) fun name(...)`, `pub fun name(...)`.
    "cadence": re.compile(r"^\s*(?:access\s*\([^)]*\)\s+|pub\s+|priv\s+)?fun\s+([A-Za-z_]\w*)\s*[<(]", re.MULTILINE),
}

_GEN_SKIP_NAMES = {
    "main", "init", "setup", "setUp", "new", "default", "drop", "clone",
    "fmt", "from", "into", "as_ref", "deref",
}

_GEN_EXCLUDE_PARTS = {
    "/test/", "/tests/", "/mock/", "/mocks/", "/target/", "/vendor/",
    "/node_modules/", "/.git/", "/build/", "/dist/", "/out/", "/.auditooor/",
    "/poc-tests/", "/poc_tests/", "/_archive/", "/examples/", "/benches/",
    # P1-e / taxonomy mode 19: deployed re-implementation / verified-source
    # mirror trees are OOS, never the in-scope CUT.
    "/reference/", "/instascope_deployed_zip/", "/deployed_zip/",
    "/verified_sources/", "/verified-sources/",
}


def _gen_is_test_file(path: Path, language: str) -> bool:
    p = path.as_posix().lower()
    if language == "go":
        return p.endswith("_test.go")
    if language == "rust":
        return p.endswith("/tests.rs") or "/tests/" in p or p.endswith("_test.rs")
    return "/test" in p or "_test" in p


def _resolve_generic_roots(workspace: Path) -> list[Path]:
    """Canonical in-scope source root(s) for the non-Solidity generic path.

    Delegates to tools/lib/source_root_resolver.resolve_src_roots so this tool
    sees the SAME source root the genuine-coverage gate credits (e.g. a Cargo
    workspace's crates/* under ws/src, not a thin src/src stub). Falls back to
    the legacy [ws/src, ws/contracts, ws] root set if the resolver is absent.
    """
    try:
        _here = Path(__file__).resolve().parent
        if str(_here / "lib") not in sys.path:
            sys.path.insert(0, str(_here / "lib"))
        from source_root_resolver import resolve_src_roots  # type: ignore
        roots = resolve_src_roots(workspace)
        if roots:
            return roots
    except Exception:
        pass
    return [workspace / "src", workspace / "contracts", workspace]


def discover_generic_files(workspace: Path, language: str,
                           contract_filter: str | None) -> list[Path]:
    ext = _GEN_LANG_EXT[language]
    roots = _resolve_generic_roots(workspace)
    seen: set[Path] = set()
    out: list[Path] = []
    for root in roots:
        if not root.exists():
            continue
        for path in root.rglob(f"*{ext}"):
            if path in seen or not path.is_file():
                continue
            seen.add(path)
            posix = path.as_posix().lower() + "/"
            if any(part in posix for part in _GEN_EXCLUDE_PARTS):
                continue
            if _gen_is_test_file(path, language):
                continue
            if contract_filter and contract_filter not in {path.stem, path.name, path.as_posix()}:
                continue
            out.append(path)
    return sorted(out)


@dataclass(frozen=True)
class GenericFunction:
    module_name: str
    function_name: str
    source_file: Path
    relative_file: str
    line: int
    language: str

    @property
    def selector(self) -> str:
        return f"{self.module_name}.{self.function_name}"

    @property
    def harness_contract(self) -> str:
        lang_tag = {"rust": "Rust", "go": "Go", "move": "Move", "cairo": "Cairo",
                    "vyper": "Vyper", "cadence": "Cadence"}[self.language]
        return f"{lang_tag}Inv_{self.module_name}_{self.function_name}"


def parse_generic_functions(workspace: Path, files: list[Path], language: str,
                            function_filter: str | None) -> list[GenericFunction]:
    fn_re = _GEN_FN_RES[language]
    rows: list[GenericFunction] = []
    for path in files:
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError as exc:
            print(f"[per-function-invariant-gen] WARN cannot read {path}: {exc}", file=sys.stderr)
            continue
        clean = strip_comments(text)
        try:
            rel = path.relative_to(workspace).as_posix()
        except ValueError:
            rel = path.as_posix()
        for match in fn_re.finditer(clean):
            name = match.group(1)
            if name in _GEN_SKIP_NAMES or name.lower().startswith("test") or name.lower().startswith("fuzz"):
                continue
            if function_filter and function_filter != name:
                continue
            rows.append(GenericFunction(
                module_name=path.stem,
                function_name=name,
                source_file=path,
                relative_file=rel,
                line=line_number(clean, match.start()),
                language=language,
            ))
    return rows


def _generic_goal_invariants(fn: GenericFunction) -> list[dict]:
    """Resolve goal-invariant records for a generic-language function (additive,
    []-safe). Generic source bodies are not extracted by this tool, so most roles
    remain UNBOUND (honest); only impact MATCH + any name-bindable role binds."""
    if _GOAL_SYNTH is None:
        return []
    try:
        body = ""
        try:
            body = fn.source_file.read_text(encoding="utf-8", errors="replace")
        except OSError:
            body = ""
        return _GOAL_SYNTH.goal_invariants_for(
            fn.function_name, "",
            language=fn.language,
            scope_text=str(fn.source_file),
            source_body=body,
            file_line=f"{fn.relative_file}:{fn.line}",
        )
    except Exception:  # noqa: BLE001
        return []


def render_generic_harness(fn: GenericFunction) -> str:
    """Idiomatic, advisory, sentinel-asserting harness scaffold per language.
    A worker replaces the sentinel assertion with a source-grounded property,
    then mutation-verify-coverage.py confirms it non-vacuous.

    FIX-3: one `// GOAL [<impact_id>]: <goal_statement>` authoring comment per
    GOAL-BOUND template is injected after the header so a worker knows the exact
    adversary relation to assert. The sentinel body stays a tautology (a goal
    comment never inflates coverage; harness_vacuity still rejects it)."""
    body = _render_generic_harness_base(fn)
    goal_comment = _goal_comment_block(_generic_goal_invariants(fn))
    if goal_comment:
        # Inject after the first "Function under test:" header line. The comment
        # prefix differs by language (// vs #); reuse the body's own first-line
        # prefix so the goal lines parse as comments in every target language.
        lines = body.splitlines(keepends=True)
        marker = "Function under test:"
        for idx, line in enumerate(lines):
            if marker in line:
                prefix = line[: line.find(marker)].rstrip()
                # prefix is e.g. "// " or "# "; strip trailing space, keep token.
                cprefix = prefix if prefix else "//"
                gc = "".join(
                    f"{cprefix} {g[3:] if g.startswith('// ') else g}\n"
                    for g in goal_comment.splitlines()
                )
                lines.insert(idx + 1, gc)
                return "".join(lines)
        # No header marker found: prepend the comment block verbatim.
        return goal_comment + "\n" + body
    return body


def _render_generic_harness_base(fn: GenericFunction) -> str:
    if fn.language == "rust":
        check = sanitize_identifier(f"prop_{fn.function_name}_preserves_core_invariant")
        return f"""// Auto-generated by tools/per-function-invariant-gen.py --lang rust.
// Function under test: {fn.selector} at {fn.relative_file}:{fn.line}
// Advisory scaffold (NOT proof). Replace the sentinel with a source-grounded
// property over {fn.function_name}, then mutation-verify it is non-vacuous via
// tools/mutation-verify-coverage.py --language rust.
//
// Suggested proptest form (uncomment + wire the real call):
//   use proptest::prelude::*;
//   proptest! {{
//       #[test]
//       fn {check}(/* inputs */) {{
//           // let out = {fn.function_name}(/* inputs */);
//           // prop_assert!(/* invariant over out */);
//       }}
//   }}
#[cfg(test)]
mod {sanitize_identifier(fn.harness_contract.lower())} {{
    #[test]
    fn {check}() {{
        // SENTINEL: replace with a real source-grounded property of {fn.function_name}.
        assert!(true);
    }}
}}
"""
    if fn.language == "go":
        test_name = "Test" + sanitize_identifier(f"{fn.module_name}_{fn.function_name}_Invariant").replace("_", "")
        fuzz_name = "Fuzz" + sanitize_identifier(f"{fn.module_name}_{fn.function_name}").replace("_", "")
        pkg = sanitize_identifier(fn.module_name + "_inv")
        return f"""// Auto-generated by tools/per-function-invariant-gen.py --lang go.
// Function under test: {fn.selector} at {fn.relative_file}:{fn.line}
// Advisory scaffold (NOT proof). Replace the sentinel with a source-grounded
// property over {fn.function_name}, then mutation-verify it is non-vacuous via
// tools/mutation-verify-coverage.py --language go.
package {pkg}

import "testing"

func {test_name}(t *testing.T) {{
    // SENTINEL: replace with a real source-grounded property of {fn.function_name}.
    // out := {fn.function_name}(/* inputs */)
    // if /* invariant violated */ {{ t.Fatalf("invariant broken: %v", out) }}
    _ = t
}}

func {fuzz_name}(f *testing.F) {{
    // Suggested fuzz harness; seed corpus + assert the same invariant.
    f.Fuzz(func(t *testing.T, _ []byte) {{
        // out := {fn.function_name}(/* derived inputs */)
        // if /* invariant violated */ {{ t.Fatalf("invariant broken") }}
        _ = t
    }})
}}
"""
    if fn.language == "move":
        modname = sanitize_identifier(f"{fn.module_name}_{fn.function_name}_inv")
        return f"""// Auto-generated by tools/per-function-invariant-gen.py --lang move.
// Function under test: {fn.selector} at {fn.relative_file}:{fn.line}
// Advisory scaffold (NOT proof). Replace the sentinel with a source-grounded
// property over {fn.function_name}.
#[test_only]
module 0x0::{modname} {{
    #[test]
    fun test_{sanitize_identifier(fn.function_name)}_invariant() {{
        // SENTINEL: replace with a real property of {fn.function_name}.
        assert!(true, 0);
    }}
}}
"""
    if fn.language == "vyper":
        check = sanitize_identifier(f"test_{fn.function_name}_invariant")
        return f"""# Auto-generated by tools/per-function-invariant-gen.py --lang vyper.
# Function under test: {fn.selector} at {fn.relative_file}:{fn.line}
# Advisory scaffold (NOT proof). Replace the sentinel with a source-grounded
# property over {fn.function_name} (e.g. a boa / hypothesis property test that
# drives {fn.function_name} and asserts the invariant it must preserve).
#
# Suggested titanoboa form (uncomment + wire the real call):
#   import boa
#   def {check}():
#       c = boa.load("{fn.relative_file}")
#       # out = c.{fn.function_name}(...)
#       # assert <invariant over out>
#
# SENTINEL: replace with a real source-grounded property of {fn.function_name}.
def {check}():
    assert True  # placeholder
"""
    if fn.language == "cadence":
        check = sanitize_identifier(f"test_{fn.function_name}_invariant")
        return f"""// Auto-generated by tools/per-function-invariant-gen.py --lang cadence.
// Function under test: {fn.selector} at {fn.relative_file}:{fn.line}
// Advisory scaffold (NOT proof). Replace the sentinel with a source-grounded
// property over {fn.function_name}.
import Test

access(all) fun {check}() {{
    // SENTINEL: replace with a real property of {fn.function_name}.
    Test.assert(true)
}}
"""
    check = sanitize_identifier(f"test_{fn.function_name}_invariant")
    return f"""// Auto-generated by tools/per-function-invariant-gen.py --lang cairo.
// Function under test: {fn.selector} at {fn.relative_file}:{fn.line}
// Advisory scaffold (NOT proof). Replace the sentinel with a source-grounded
// property over {fn.function_name}.
#[cfg(test)]
mod {sanitize_identifier(fn.harness_contract.lower())} {{
    #[test]
    fn {check}() {{
        // SENTINEL: replace with a real property of {fn.function_name}.
        assert(true, 'invariant placeholder');
    }}
}}
"""


def write_generic_harnesses(workspace: Path, functions: list[GenericFunction],
                            output_dir: Path, overwrite: bool, dry_run: bool) -> list[dict]:
    rows: list[dict] = []
    if not dry_run:
        output_dir.mkdir(parents=True, exist_ok=True)
    for fn in functions:
        ext = _GEN_LANG_EXT[fn.language]
        harness_name = f"{fn.harness_contract}{ext}"
        harness_path = output_dir / harness_name
        body = render_generic_harness(fn)
        # P1-b no-clobber (taxonomy mode 13): never overwrite a worker-filled real
        # (non-sentinel) harness, even under --overwrite. Bank the PRESERVED body.
        if harness_path.exists() and _is_real_existing_harness(harness_path):
            try:
                body = harness_path.read_text(encoding="utf-8", errors="replace")
            except OSError:
                pass
            body_hash = hashlib.sha256(body.encode("utf-8")).hexdigest()
            rows.append(_generic_row(fn, harness_path, "preserved-existing-real-harness",
                                     body, body_hash))
            continue
        body_hash = hashlib.sha256(body.encode("utf-8")).hexdigest()
        # P1-e non-empty-spec assertion (taxonomy mode 18): fail-closed on an
        # empty / whitespace-only render; skip the unit, write NO 0-byte file.
        if not (body and body.strip()):
            rows.append(_generic_row(fn, harness_path, "skipped-empty-render", "", body_hash))
            continue
        status = "would-write" if dry_run else "written"
        if harness_path.exists() and not overwrite:
            status = "exists"
        elif not dry_run:
            harness_path.write_text(body, encoding="utf-8")
        rows.append(_generic_row(fn, harness_path, status, body, body_hash))
    return rows


def _generic_row(fn, harness_path, status, body, body_hash) -> dict:
    """Build a single generic (non-Solidity) manifest row (factored out so the
    normal-write, preserved-existing-real-harness and skipped-empty-render paths
    emit a consistent row shape)."""
    # FIX-3: stamp goal impact_ids + GOAL-BOUND count (additive, []-safe).
    _goal_records = _generic_goal_invariants(fn)
    _goal_impact_ids = sorted({
        str(r.get("impact_id")) for r in _goal_records if r.get("impact_id")
    })
    _goal_bound_count = sum(
        1 for r in _goal_records if r.get("status") == "goal-bound"
    )
    return {
        "contract": fn.module_name,
        "function": fn.function_name,
        "selector": fn.selector,
        "source": f"{fn.relative_file}:{fn.line}",
        "language": fn.language,
        "goal_impact_ids": _goal_impact_ids,
        "goal_bound_count": _goal_bound_count,
        "harness_contract": fn.harness_contract,
        "harness_path": str(harness_path),
        "halmos_root": None,
        "status": status,
        "sha256": body_hash,
        # Fail-closed vacuity gate (see Solidity path): sentinel scaffolds
        # (assert!(true)/assert True/Test.assert(true)/go-stub) are flagged so
        # they are never credited as coverage.
        "is_sentinel": (
            bool(_IS_SENTINEL(body)) if _IS_SENTINEL is not None and body else None
        ),
    }


def build_generic_manifest(workspace: Path, output_dir: Path, language: str,
                           rows: list[dict]) -> dict:
    return {
        "schema": SCHEMA,
        "generated_at": utc_now(),
        "workspace": str(workspace),
        "language": language,
        "output_dir": str(output_dir),
        "function_count": len(rows),
        # Fail-closed vacuity gate (see Solidity build_manifest).
        "sentinel_count": sum(1 for r in rows if r.get("is_sentinel") is True),
        "non_sentinel_count": sum(1 for r in rows if r.get("is_sentinel") is False),
        "functions": rows,
    }


def _run_generic(args: argparse.Namespace, workspace: Path, language: str) -> int:
    output_dir = (
        Path(args.output_dir).expanduser().resolve()
        if args.output_dir
        else workspace / "poc-tests" / "per_function_invariants"
    )
    files = discover_generic_files(workspace, language, args.contract)
    functions = parse_generic_functions(workspace, files, language, args.function)
    # SCOPE-AUTHORITATIVE filter: when an in-scope manifest exists, drop OOS
    # functions walked from src_roots (mirrors function-coverage-completeness.py).
    _inscope = _load_inscope_file_set(workspace)
    _scope_dropped = 0
    if _inscope is not None:
        _before = len(functions)
        functions = [f for f in functions if _norm_inscope_path(f.relative_file) in _inscope]
        _scope_dropped = _before - len(functions)
        if _scope_dropped:
            print(
                f"[per-function-invariant-gen] scope-filter: dropped {_scope_dropped} OOS functions"
                f" (inscope_units.jsonl: {len(_inscope)} files)",
                file=sys.stderr,
            )
    rows = write_generic_harnesses(
        workspace, functions, output_dir,
        overwrite=args.overwrite, dry_run=args.dry_run,
    )
    manifest = build_generic_manifest(workspace, output_dir, language, rows)
    manifest["scope_filter"] = {
        "applied": _inscope is not None,
        "source": ".auditooor/inscope_units.jsonl" if _inscope is not None else None,
        "in_scope_files": (len(_inscope) if _inscope is not None else None),
        "out_of_scope_dropped": _scope_dropped,
    }
    if not args.dry_run:
        output_dir.mkdir(parents=True, exist_ok=True)
        (output_dir / "manifest.json").write_text(
            json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    if getattr(args, "emit_goal_audit", False):
        audit_path = emit_goal_audit(workspace, rows)
        print(f"[per-function-invariant-gen] goal-audit -> {audit_path}", file=sys.stderr)
    if args.json:
        print(json.dumps(manifest, indent=2, sort_keys=True))
    else:
        print(f"[per-function-invariant-gen] lang={language} functions={len(rows)} output_dir={output_dir}")
    return 0


def emit_goal_audit(workspace: Path, rows: list[dict]) -> Path:
    """Write a per-function goal-binding audit so step-2c/step-4b operators can
    SEE goal coverage without hand-parsing the manifest.

    Writes ``<ws>/.auditooor/per_function_goal_bindings.jsonl`` - one JSON row per
    function carrying:
      function         function name
      file             source location (file:line, from the manifest row)
      goal_impact_ids  the impact_ids matched to this function
      goal_bound_count number of GOAL-BOUND invariant templates (already stamped
                       on the manifest row by FIX-3)
      goal_unbound     the impact_ids with 0 bound invariants (matched but the
                       relational roles never bound against the real source) -
                       this is the operator's actionable "still needs work" set.

    A function with goal_bound_count >= 1 has at least one bound goal but MAY still
    carry unbound impacts (a multi-impact function partially bound); goal_unbound
    is therefore computed per-impact, not derived from the aggregate count. The
    goal synthesizer does not expose per-impact bound counts on the manifest row,
    so goal_unbound is the conservative set: when goal_bound_count == 0 every
    matched impact is unbound; when goal_bound_count >= 1 we cannot attribute the
    bound count to specific impacts from the row alone, so goal_unbound is [] (no
    over-claim of unbound work). Additive: never mutates the manifest rows.
    """
    out_dir = workspace / ".auditooor"
    out_dir.mkdir(parents=True, exist_ok=True)
    out_path = out_dir / "per_function_goal_bindings.jsonl"
    lines: list[str] = []
    for row in rows:
        impact_ids = [str(i) for i in (row.get("goal_impact_ids") or [])]
        bound_count = int(row.get("goal_bound_count") or 0)
        # Conservative unbound set (see docstring): only fully-unbound functions
        # surface every matched impact; partially-bound rows under-report rather
        # than guess which specific impact remained unbound.
        goal_unbound = impact_ids if bound_count == 0 else []
        lines.append(json.dumps({
            "function": row.get("function"),
            "file": row.get("source"),
            "goal_impact_ids": impact_ids,
            "goal_bound_count": bound_count,
            "goal_unbound": goal_unbound,
        }, sort_keys=True))
    out_path.write_text(("\n".join(lines) + "\n") if lines else "", encoding="utf-8")
    return out_path


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--workspace", required=True, help="Audit workspace root.")
    parser.add_argument(
        "--lang", "--language", dest="lang", default="solidity",
        choices=["solidity", "rust", "go", "move", "cairo", "vyper", "cadence"],
        help="Target language. Default solidity (unchanged Halmos path). "
             "rust/go/move/cairo/vyper/cadence emit idiomatic per-function "
             "harness scaffolds.",
    )
    parser.add_argument("--contract", help="Optional contract filename/stem filter.")
    parser.add_argument("--function", help="Optional function name filter.")
    parser.add_argument(
        "--output-dir",
        help="Output directory. Default: <workspace>/poc-tests/per_function_invariants",
    )
    parser.add_argument(
        "--preflight-dir",
        help="Optional pre-flight pack directory. Default: <workspace>/.auditooor/pre_flight_packs",
    )
    parser.add_argument("--include-internal", action="store_true", help="Include internal/private functions.")
    parser.add_argument("--include-read-only", action="store_true", help="Include view/pure functions.")
    parser.add_argument("--overwrite", action="store_true", help="Overwrite existing harness files.")
    parser.add_argument("--dry-run", action="store_true", help="Emit manifest without writing harness files.")
    parser.add_argument("--json", action="store_true", help="Print manifest JSON to stdout.")
    parser.add_argument(
        "--emit-goal-audit", action="store_true",
        help="Additionally write <workspace>/.auditooor/per_function_goal_bindings.jsonl "
             "(one row per function: goal_impact_ids, goal_bound_count, goal_unbound) "
             "so step-2c/step-4b operators can see goal coverage without hand-parsing.",
    )
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    workspace = Path(args.workspace).expanduser().resolve()
    if not workspace.is_dir():
        print(f"[per-function-invariant-gen] workspace not found: {workspace}", file=sys.stderr)
        return 2
    # Language routing: Solidity keeps the unchanged Halmos path below; the
    # other languages route through the generic per-language scaffolder.
    if getattr(args, "lang", "solidity") != "solidity":
        return _run_generic(args, workspace, args.lang)
    output_dir = (
        Path(args.output_dir).expanduser().resolve()
        if args.output_dir
        else workspace / "poc-tests" / "per_function_invariants"
    )
    preflight_dir = Path(args.preflight_dir).expanduser().resolve() if args.preflight_dir else None
    files = discover_solidity_files(workspace, args.contract)
    functions = parse_functions(
        workspace,
        files,
        include_internal=args.include_internal,
        function_filter=args.function,
        include_read_only=args.include_read_only,
    )
    # SCOPE-AUTHORITATIVE filter: when an in-scope manifest exists, drop OOS
    # functions walked from src_roots (mirrors function-coverage-completeness.py).
    _inscope = _load_inscope_file_set(workspace)
    _scope_dropped = 0
    if _inscope is not None:
        _before = len(functions)
        functions = [f for f in functions if _norm_inscope_path(f.relative_file) in _inscope]
        _scope_dropped = _before - len(functions)
        if _scope_dropped:
            print(
                f"[per-function-invariant-gen] scope-filter: dropped {_scope_dropped} OOS functions"
                f" (inscope_units.jsonl: {len(_inscope)} files)",
                file=sys.stderr,
            )
    rows = write_harnesses(
        workspace,
        functions,
        output_dir,
        overwrite=args.overwrite,
        dry_run=args.dry_run,
        preflight_dir=preflight_dir,
    )
    removed_stale_harnesses = (
        cleanup_stale_generated_harnesses(output_dir, rows)
        if args.overwrite and not args.dry_run
        else []
    )
    manifest = build_manifest(workspace, output_dir, rows)
    manifest["removed_stale_harnesses"] = removed_stale_harnesses
    manifest["scope_filter"] = {
        "applied": _inscope is not None,
        "source": ".auditooor/inscope_units.jsonl" if _inscope is not None else None,
        "in_scope_files": (len(_inscope) if _inscope is not None else None),
        "out_of_scope_dropped": _scope_dropped,
    }
    if not args.dry_run:
        output_dir.mkdir(parents=True, exist_ok=True)
        (output_dir / "manifest.json").write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    if getattr(args, "emit_goal_audit", False):
        audit_path = emit_goal_audit(workspace, rows)
        print(f"[per-function-invariant-gen] goal-audit -> {audit_path}", file=sys.stderr)
    if args.json:
        print(json.dumps(manifest, indent=2, sort_keys=True))
    else:
        print(f"[per-function-invariant-gen] functions={len(rows)} output_dir={output_dir}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
