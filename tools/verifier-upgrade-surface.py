#!/usr/bin/env python3
"""Verifier / dispute-game upgrade-surface scanner (PR #546 Wave 10 Lane B).

Scans Solidity sources under a workspace for the implementation-upgrade
attack surface that maps to OP1 ("Unauthorized verifier / dispute-game
implementation upgrade"). Lane G's Wave 9 hypothesis review identified
OP1 as the top missing-Critical hypothesis with zero detector / zero
invariant / zero harness; this tool is the first piece of harness coverage.

Inputs (best-effort, all optional):
  <ws>/external/**/*.sol         OP-stack / contracts-bedrock sources
  <ws>/src/**/*.sol              Project-local sources
  <ws>/contracts/**/*.sol        Truffle-flavoured layouts
  <ws>/lib/**/*.sol              Foundry submodules

Outputs (under ``<ws>/critical_hunt/``):
  verifier_upgrade_surface.json
  verifier_upgrade_surface.md

Each row is compatible with `tools/base-critical-candidate-matrix.py` (Lane H,
PR #545). Default-to-kill: candidates without an explicit listed Critical
impact mapping are emitted with ``candidate_status="kill_or_reframe"``. The
operator must explicitly upgrade a row to ``executable`` after the impact
mapping passes the rubric verbatim check.

Patterns detected (modifier + state-field + target-type extracted per match):
  * setImplementation / upgradeTo / upgradeToAndCall / _authorizeUpgrade
  * setVerifier / setProxy / setProxyImplementation / setRegistry
  * addGameType / setGameImpl / setRespectedGameType
  * setGameType / replaceGameType / rotateGameType (registry rotators)
  * addVerifyRoute / setVerifyRoute / addVerifierRoute (route override)
  * proxiableUUID
  * LibClone.deployERC1967 / Clones.cloneDeterministic / Clones.clone

Stdlib-only. Idempotent. Offline-safe.
"""
from __future__ import annotations

import argparse
import json
import re
import sys
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Iterable


SCHEMA_VERSION = "auditooor.verifier_upgrade_surface.v1"
DEFAULT_STATUS = "kill_or_reframe"

# Source roots scanned, in order.
SCAN_ROOTS = ("external", "src", "contracts", "lib")

# Pattern catalogue. Each entry: (pattern_id, regex, pattern_class,
# default_target_type, severity_hint).
PATTERNS: tuple[tuple[str, re.Pattern[str], str, str, str], ...] = (
    (
        "set_implementation",
        re.compile(r"\bfunction\s+(setImplementation|setImpl|setLogic)\s*\("),
        "implementation_setter",
        "implementation",
        "critical",
    ),
    (
        "upgrade_to",
        re.compile(r"\bfunction\s+(upgradeTo|upgradeToAndCall)\s*\("),
        "uups_upgrade",
        "implementation",
        "critical",
    ),
    (
        "authorize_upgrade",
        re.compile(r"\bfunction\s+_authorizeUpgrade\s*\("),
        "uups_authorize",
        "implementation",
        "critical",
    ),
    (
        "proxiable_uuid",
        re.compile(r"\bfunction\s+proxiableUUID\s*\("),
        "uups_uuid",
        "implementation",
        "high",
    ),
    (
        "set_verifier",
        re.compile(r"\bfunction\s+(setVerifier|setVerifierAddress)\s*\("),
        "verifier_setter",
        "verifier",
        "critical",
    ),
    (
        "set_proxy",
        re.compile(r"\bfunction\s+(setProxy|setProxyImplementation|setProxyAdmin)\s*\("),
        "proxy_setter",
        "proxy_admin",
        "critical",
    ),
    (
        "add_game_type",
        re.compile(r"\bfunction\s+(addGameType|setGameImpl|setRespectedGameType)\s*\("),
        "game_type_registry",
        "game_implementation",
        "critical",
    ),
    (
        "game_type_rotator",
        re.compile(
            r"\bfunction\s+(setGameType|replaceGameType|rotateGameType|swapGameType)\s*\("
        ),
        "game_type_rotator",
        "game_type_pointer",
        "high",
    ),
    (
        "add_verify_route",
        re.compile(
            r"\bfunction\s+(addVerifyRoute|setVerifyRoute|addVerifierRoute|setVerifierRoute|addVerifyTarget)\s*\("
        ),
        "verifier_route_override",
        "verifier_route",
        "critical",
    ),
    (
        "set_registry",
        re.compile(r"\bfunction\s+(setRegistry|setFactory|setDisputeGameFactory)\s*\("),
        "registry_setter",
        "registry",
        "high",
    ),
    (
        "lib_clone",
        re.compile(r"\bLibClone\.(deployERC1967|cloneDeterministic|clone)\s*\("),
        "lib_clone_deploy",
        "implementation",
        "high",
    ),
    (
        "clones_clone",
        re.compile(r"\bClones\.(clone|cloneDeterministic|predictDeterministicAddress)\s*\("),
        "clones_factory",
        "implementation",
        "high",
    ),
)

# Modifier extraction: scans the function header from the match column to the
# next ``{`` opening brace.
#
# We collect every identifier-shaped token from the header, then strip out:
#  - the ``function`` / ``returns`` keywords
#  - the function name (first identifier after ``function``)
#  - parameter type annotations and parameter names
#  - visibility / mutability / state mutability keywords
#
# Whatever survives is treated as a modifier name. This catches custom
# project-specific modifiers like ``proxyCallIfNotAdmin`` (OP-Stack
# ``Proxy.sol:60``) which are not on any literal allow-list. PR Wave 4
# Priority 4 fix for the false-negative reported in BA-C5 audit row #2.
VISIBILITY_RE = re.compile(r"\b(public|external|internal|private)\b")
_MUTABILITY_TOKENS = {"view", "pure", "payable", "constant"}
_HEADER_KEYWORDS = {
    "function",
    "returns",
    "virtual",
    "override",
    "abstract",
}
# Solidity primitive types that may appear as parameter types.
_SOL_PRIM_PREFIXES = (
    "uint",
    "int",
    "bytes",
    "string",
    "bool",
    "address",
    "mapping",
    "memory",
    "calldata",
    "storage",
)
_IDENT_RE = re.compile(r"[A-Za-z_][A-Za-z0-9_]*")

# Inline access-guard detection: Wave H-2A BA-C5 hunt found that
# ``AnchorStateRegistry.setRespectedGameType`` calls ``_assertOnlyGuardian()``
# as the first statement in the body instead of using a Solidity ``modifier``.
# The modifier extractor (which only scans the function header) misses this
# class of access guard entirely.
#
# We match call-statement patterns at the start of the function body:
#   _assertOnly<Role>(...)   _check<Role>(...)   _require<Role>(...)
#   _ensure<Role>(...)       _validate<Role>(...)
# restricted to a leading underscore so we don't accidentally catch
# business-logic calls like ``_setImplementation()``.
#
# Matching rules (applied to the first ``_INLINE_GUARD_SCAN_LINES`` non-blank
# lines of the function body):
#   - The call must start with one of the recognised prefixes.
#   - We extract only the callee name, not the arguments.
#   - Multiple guards on adjacent lines are all collected.
_INLINE_GUARD_PREFIXES = re.compile(
    r"^\s*(_assert[A-Za-z0-9_]+|_check[A-Za-z0-9_]+|_require[A-Za-z0-9_]+"
    r"|_ensure[A-Za-z0-9_]+|_validate[A-Za-z0-9_]+)\s*\(",
    re.MULTILINE,
)
_INLINE_GUARD_SCAN_LINES = 5  # check at most this many non-blank body lines


# State field heuristic: look for an ``address`` storage variable referenced in
# the function body that the function writes to.
STATE_FIELD_RE = re.compile(
    r"\b(implementation|impl|logic|verifier|verifiers|verifierRoute|"
    r"_zkVerifierRoutes|zkVerifier|proxy|registry|factory|gameImpl|"
    r"gameImplementation|gameImplementations|respectedGameType|gameType)\b",
    re.IGNORECASE,
)


@dataclass
class SurfaceRow:
    candidate_id: str
    scope_asset: str
    pattern_id: str
    pattern_class: str
    file: str
    line: int
    function: str
    modifier: str
    visibility: str
    state_field: str
    target_type: str
    severity_hint: str
    candidate_status: str = DEFAULT_STATUS
    impact_mapping: str = ""
    production_path: str = ""
    required_proof: str = (
        "Demonstrate unauthorized actor can change implementation/verifier "
        "and a downstream state-corrupting call lands"
    )
    artifact_refs: list[str] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)
    inline_access_guards: list[str] = field(default_factory=list)


def iter_solidity_files(workspace: Path) -> Iterable[Path]:
    seen: set[Path] = set()
    for root in SCAN_ROOTS:
        base = workspace / root
        if not base.is_dir():
            continue
        for path in base.rglob("*.sol"):
            try:
                resolved = path.resolve()
            except OSError:
                continue
            if resolved in seen:
                continue
            seen.add(resolved)
            yield path


def _extract_function_header(text: str, start: int) -> tuple[str, int]:
    """Return (header_substring, brace_offset) for a function declaration.

    The header runs from ``start`` up to the first ``{`` (function body) or
    ``;`` (interface / abstract declaration), whichever is closer. This
    bounds the modifier-extraction window so we don't bleed into the next
    function's NatSpec block — important for interface files where
    declarations end with ``;``.
    """
    brace = text.find("{", start)
    semi = text.find(";", start)
    candidates = [c for c in (brace, semi) if c != -1]
    if not candidates:
        # Fall back to a 400-char window (covers multi-line headers).
        return text[start : start + 400], min(start + 400, len(text))
    end = min(candidates)
    return text[start:end], end


def _extract_function_body(text: str, brace_offset: int) -> str:
    """Best-effort balanced-brace extraction starting at ``brace_offset``."""
    if brace_offset >= len(text) or text[brace_offset] != "{":
        return ""
    depth = 0
    i = brace_offset
    while i < len(text):
        ch = text[i]
        if ch == "{":
            depth += 1
        elif ch == "}":
            depth -= 1
            if depth == 0:
                return text[brace_offset : i + 1]
        i += 1
    return text[brace_offset:]


def _extract_modifier(header: str) -> tuple[str, str]:
    """Return ``(modifier, visibility)`` using token scan.

    Strategy: drop the parameter list ``(...)`` and any ``returns (...)``
    block, then walk the remaining identifier tokens. Whatever is not a
    visibility / mutability / structural keyword and not the function name
    is treated as a modifier (``onlyOwner``, ``proxyCallIfNotAdmin``, ...).

    This is the PR Wave 4 Priority 4 fix for the BA-C5 audit row #2
    false-negative where ``proxyCallIfNotAdmin`` was not on the literal
    allow-list and the scanner reported ``modifier=none``.
    """
    # Strip parameter list: function name(...). The header begins at
    # ``function`` and runs to the opening brace of the body.
    stripped = _strip_paren_groups(header)

    visibility = ""
    seen_function_kw = False
    skip_next_ident = False
    modifier_tokens: list[str] = []

    for tok in _IDENT_RE.findall(stripped):
        if tok == "function":
            seen_function_kw = True
            skip_next_ident = True  # next identifier is the function name
            continue
        if not seen_function_kw:
            continue
        if skip_next_ident:
            skip_next_ident = False
            continue
        if VISIBILITY_RE.fullmatch(tok):
            visibility = tok
            continue
        if tok in _MUTABILITY_TOKENS or tok in _HEADER_KEYWORDS:
            continue
        # Drop primitive-type tokens that may have leaked from a missing
        # paren-group strip (defensive — should not normally fire).
        if any(tok.startswith(p) and tok[len(p):].isdigit() for p in _SOL_PRIM_PREFIXES):
            continue
        if tok in {"address", "bool", "string", "bytes", "uint", "int"}:
            continue
        if tok in modifier_tokens:
            continue
        modifier_tokens.append(tok)

    modifier = ",".join(modifier_tokens) if modifier_tokens else "none"
    return modifier, (visibility or "unspecified")


def _strip_paren_groups(text: str) -> str:
    """Remove ``(...)`` groups (balanced, depth-aware) from ``text``.

    Used to drop a function's parameter list and any ``returns (...)``
    annotation before we walk header tokens for modifier detection.
    """
    out: list[str] = []
    depth = 0
    for ch in text:
        if ch == "(":
            depth += 1
            continue
        if ch == ")":
            if depth > 0:
                depth -= 1
            continue
        if depth == 0:
            out.append(ch)
    return "".join(out)


def _extract_inline_guards(body: str) -> list[str]:
    """Scan the first few non-blank lines of a function body for inline
    access-guard calls such as ``_assertOnlyGuardian()`` or ``_checkRole()``.

    These are semantically equivalent to Solidity modifiers but cannot be
    found by header-token scanning — they live in the body.  We restrict the
    scan to ``_INLINE_GUARD_SCAN_LINES`` non-blank lines so we don't
    accidentally collect guards buried deep in the function logic.

    Returns a deduplicated list of guard names in order of appearance, e.g.
    ``["_assertOnlyGuardian", "_requireNonZero"]``.
    """
    if not body:
        return []
    # Skip the opening ``{`` and scan only the first non-blank lines.
    lines = body.splitlines()
    non_blank: list[str] = []
    for ln in lines[1:]:  # skip line 0 which is just "{"
        stripped = ln.strip()
        if stripped:
            non_blank.append(ln)
        if len(non_blank) >= _INLINE_GUARD_SCAN_LINES:
            break
    scan_text = "\n".join(non_blank)
    seen: list[str] = []
    for m in _INLINE_GUARD_PREFIXES.finditer(scan_text):
        name = m.group(1)
        if name not in seen:
            seen.append(name)
    return seen


def _extract_state_field(body: str) -> str:
    match = STATE_FIELD_RE.search(body or "")
    if match:
        return match.group(1)
    return ""


def _function_name(header: str) -> str:
    m = re.search(r"function\s+([A-Za-z_][A-Za-z0-9_]*)", header)
    return m.group(1) if m else "?"


def _line_of(text: str, offset: int) -> int:
    return text.count("\n", 0, offset) + 1


def scan_file(path: Path, workspace: Path) -> list[SurfaceRow]:
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return []
    rel = str(path.relative_to(workspace)) if path.is_relative_to(workspace) else str(path)
    asset = path.stem
    rows: list[SurfaceRow] = []
    seen_keys: set[tuple[str, int, str]] = set()
    for pattern_id, regex, pattern_class, target_type, severity in PATTERNS:
        for match in regex.finditer(text):
            offset = match.start()
            line = _line_of(text, offset)
            header, brace_offset = _extract_function_header(text, offset)
            body = ""
            inline_guards: list[str] = []
            if pattern_class in {
                "lib_clone_deploy",
                "clones_factory",
            }:
                # These patterns may match call sites instead of declarations.
                fn_name = "<call-site>"
                modifier = "n/a"
                visibility = "call_site"
                state_field = _extract_state_field(text[max(0, offset - 200) : offset + 200])
            else:
                body = _extract_function_body(text, brace_offset)
                fn_name = _function_name(header)
                modifier, visibility = _extract_modifier(header)
                state_field = _extract_state_field(body)
                inline_guards = _extract_inline_guards(body)
            key = (rel, line, pattern_id)
            if key in seen_keys:
                continue
            seen_keys.add(key)
            cand_id = f"OP1::{asset}::{pattern_id}::{line}"
            row = SurfaceRow(
                candidate_id=cand_id,
                scope_asset=asset,
                pattern_id=pattern_id,
                pattern_class=pattern_class,
                file=rel,
                line=line,
                function=fn_name,
                modifier=modifier,
                visibility=visibility,
                state_field=state_field,
                target_type=target_type,
                severity_hint=severity,
                production_path=f"{rel}:{line}",
                artifact_refs=[rel],
                notes=[
                    "default-to-kill: explicit impact_mapping required before promotion",
                ],
                inline_access_guards=inline_guards,
            )
            rows.append(row)
    return rows


def render_md(rows: list[SurfaceRow]) -> str:
    lines = [
        "# Verifier / Dispute-Game Upgrade Surface",
        "",
        "Generated by `tools/verifier-upgrade-surface.py` (PR #546 Lane B).",
        "",
        f"Schema: `{SCHEMA_VERSION}`. Default status: `{DEFAULT_STATUS}`.",
        "",
        "| Candidate | File:Line | Pattern | Function | Modifier | InlineGuards | Visibility | State | Target | Severity | Status |",
        "|-----------|-----------|---------|----------|----------|--------------|------------|-------|--------|----------|--------|",
    ]
    for r in rows:
        guard_str = (
            "+".join(r.inline_access_guards) if r.inline_access_guards else "-"
        )
        lines.append(
            f"| `{r.candidate_id}` | `{r.file}:{r.line}` | {r.pattern_id} | "
            f"{r.function} | {r.modifier} | {guard_str} | {r.visibility} | "
            f"{r.state_field or '-'} | {r.target_type} | {r.severity_hint} | "
            f"{r.candidate_status} |"
        )
    lines.append("")
    lines.append(
        "Promotion gate: each row stays at `kill_or_reframe` until the "
        "operator confirms the listed Critical impact mapping verbatim."
    )
    return "\n".join(lines) + "\n"


def write_outputs(workspace: Path, rows: list[SurfaceRow]) -> tuple[Path, Path]:
    out_dir = workspace / "critical_hunt"
    out_dir.mkdir(parents=True, exist_ok=True)
    json_path = out_dir / "verifier_upgrade_surface.json"
    md_path = out_dir / "verifier_upgrade_surface.md"
    payload = {
        "schema": SCHEMA_VERSION,
        "tool": "tools/verifier-upgrade-surface.py",
        "default_status": DEFAULT_STATUS,
        "row_count": len(rows),
        "rows": [asdict(r) for r in rows],
    }
    json_path.write_text(
        json.dumps(payload, indent=2, sort_keys=False) + "\n", encoding="utf-8"
    )
    md_path.write_text(render_md(rows), encoding="utf-8")
    return json_path, md_path


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Scan a workspace for verifier/dispute-game upgrade surface."
    )
    parser.add_argument("--workspace", required=True, help="Workspace root.")
    parser.add_argument(
        "--print-json",
        action="store_true",
        help="Print the JSON payload to stdout in addition to writing files.",
    )
    parser.add_argument(
        "--strict",
        action="store_true",
        help="Exit 1 if any candidate is emitted at default kill_or_reframe (smoke).",
    )
    args = parser.parse_args(argv)

    workspace = Path(args.workspace).expanduser().resolve()
    if not workspace.is_dir():
        print(f"[verifier-upgrade-surface] ERR workspace not a dir: {workspace}", file=sys.stderr)
        return 2

    rows: list[SurfaceRow] = []
    for path in iter_solidity_files(workspace):
        rows.extend(scan_file(path, workspace))
    rows.sort(key=lambda r: (r.file, r.line, r.pattern_id))

    json_path, md_path = write_outputs(workspace, rows)
    print(f"[verifier-upgrade-surface] wrote {json_path}")
    print(f"[verifier-upgrade-surface] wrote {md_path}")
    print(f"[verifier-upgrade-surface] rows={len(rows)}")

    if args.print_json:
        json.dump(
            {"schema": SCHEMA_VERSION, "rows": [asdict(r) for r in rows]},
            sys.stdout,
            indent=2,
        )
        sys.stdout.write("\n")

    if args.strict and any(r.candidate_status == DEFAULT_STATUS for r in rows):
        print(
            "[verifier-upgrade-surface] STRICT: rows still default-to-kill; "
            "operator must explicit-upgrade after impact mapping",
            file=sys.stderr,
        )
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
