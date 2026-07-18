#!/usr/bin/env python3
"""init-upgrade-lane.py  (IUL) - Unprotected Initializer / Upgrade Authorizer Lane.

WHAT THIS TOOL DOES
===================
IUL scans for two closely-related vulnerability shapes that are exclusive to
upgradeable-contract codebases (UUPS / Transparent proxy / OZ Initializable):

SHAPE 1 - UNPROTECTED INITIALIZER
-----------------------------------
A function is flagged when ALL of the following hold:

1. Function name matches ``/^(initialize|init|reinitialize)(\b|[A-Z_0-9])/``
   (case-sensitive, avoids false-hits on e.g. ``initializeHelper`` leaf fns
   that are already guarded by a different mechanism).
2. Visibility is ``public`` or ``external`` (interface / internal inits are OOS).
3. Function does NOT carry any modifier whose name matches
   ``initializer|reinitializer|onlyInitializing``.
4. Function does NOT call ``_disableInitializers()`` - checked by scanning the
   function body for the literal string ``_disableInitializers``.
5. No ``initialized``/``_initialized`` bool state variable is written in the
   function body (the manual ``bool inited`` guard pattern - matched by
   ``initialized = true`` or ``_initialized = true``).

NOT flagged:
- Any fn with the ``initializer`` or ``reinitializer`` modifier.
- Any fn that calls ``_disableInitializers()``.
- Any fn that writes ``initialized = true`` or ``_initialized = true``.
- Constructors (``f.is_constructor``: function names "constructor" in Solidity).
- Any fn whose body is empty or whitespace-only (EMPTY-BODY suppressor).
- Any fn in an EIP-2535 Diamond init-contract context (DIAMOND DISCRIMINATOR);
  instead a single aggregate hypothesis is emitted per workspace (see below).

DIAMOND DISCRIMINATOR (EIP-2535 / Diamond Proxy)
--------------------------------------------------
Init contracts in Diamond proxies are exclusively invoked by owner-gated
``diamondCut()``; protection is one layer up, not inside the fn.  Flagging
them individually is noise.

A file is a Diamond init-contract context when EITHER:
  1. The file path contains a path segment named exactly ``init``
     (e.g. ``contracts/beanstalk/init/InitFoo.sol``).
  2. The file defines a contract whose name starts with ``Init`` followed by
     an uppercase letter or underscore (EIP-2535 naming convention).

When N such contracts are found in a workspace, ``run_iul`` emits ONE aggregate
hypothesis with a L30-compliant enumeration of all N contracts.  This follows
the enumerate-all-callsites discipline (L30).

FP RISKS (documented, not suppressed):
- Manual boolean guard using a differently-named variable (e.g. ``_ready``,
  ``setup_done``) will be flagged; only the ``initialized``/``_initialized``
  naming convention is suppressed.
- Clone-factory patterns where ``initialize`` is intentionally callable
  multiple times will be flagged; no suppression unless they carry an explicit
  OZ modifier.

SHAPE 2 - UNGUARDED UPGRADE AUTHORIZER
----------------------------------------
A function is flagged when ALL of the following hold:

1. Function name matches ``_authorizeUpgrade|upgradeTo|upgradeToAndCall|
   setImplementation|setBeacon`` (exact or regex match on Solidity ``f.name``).
2. Function has no modifiers AND no ``require``/``assert``/``onlyOwner``/
   ``onlyRole``/``hasRole``/``msg.sender`` access check in the body.
3. Function is declared in the contract under analysis (not merely inherited).
   Approximated by: the function definition appears in the same ``.sol`` file
   as the contract declaration being scanned.
4. The contract (or a base contract named in the ``is ...`` clause) has a name
   matching ``*Upgradeable*``, ``*UUPS*``, or ``*Proxy*``.

NOT flagged:
- Any fn whose modifier list is non-empty.
- Any fn whose body contains a ``require(msg.sender ==``/``hasRole``/
  ``onlyOwner``/``_checkOwner``/``_checkRole`` pattern.

FP RISKS (documented, not suppressed):
- Diamond / EIP-2535 proxies often lack ``_authorizeUpgrade`` entirely; the
  ``inherits *Upgradeable*`` discriminator partially mitigates but does not
  eliminate hits on non-standard diamonds.
- OZ TransparentUpgradeableProxy routes upgrades through the ProxyAdmin; the
  implementation contract never overrides ``_authorizeUpgrade``, so the shape
  does NOT fire on those (correct behaviour, not a FP).

NO FALSE-GREEN RULE
===================
IUL NEVER auto-confirms a finding. Every emitted record carries
``verdict="needs-fuzz"``.

INIT/UPGRADE vs VALUE-MOVING FUNCTIONS
=======================================
Init/upgrade functions are security-critical regardless of whether they appear
in ``value_moving_functions.json`` (they often do not transfer tokens directly).
IUL therefore performs TWO scan passes:

  Pass A: scan functions in ``value_moving_functions.json`` (if it exists).
  Pass B: scan ALL ``.sol`` files in the workspace for init/upgrade function
          shapes, regardless of VMF membership.

Both passes apply the same OOS guard. The union is deduplicated by
(file, function_name, init_or_upgrade).

OUTPUT
======
``<ws>/.auditooor/init_upgrade_hypotheses.jsonl``

HYPOTHESIS SCHEMA
=================
Normal record:
{
  "workspace":        "<abs-path>",
  "file":             "<rel-path>",
  "function":         "<fn-name>",
  "language":         "sol",
  "init_or_upgrade":  "init|upgrade",
  "missing_guard":    "<description of the absent protection>",
  "attack_class":     "unprotected-initialization-or-upgrade",
  "source":           "IUL",
  "verdict":          "needs-fuzz",
  "fuzz_oracle_hint": "<invariant spec for fuzzer>"
}

Diamond aggregate record (one per workspace when Diamond init contracts found):
{
  "workspace":                "<abs-path>",
  "file":                     "__diamond_aggregate__",
  "function":                 "__all_Init_contracts__",
  "language":                 "sol",
  "init_or_upgrade":          "init",
  "missing_guard":            "[IUL] Verify diamondCut owner-gates all N Init* contracts ...",
  "attack_class":             "unprotected-initialization-or-upgrade",
  "source":                   "IUL",
  "verdict":                  "needs-fuzz",
  "fuzz_oracle_hint":         "<invariant spec>",
  "diamond_contracts":        ["<rel-path-1>", ...],
  "diamond_candidate_count":  N
}

CLI
===
  python3 tools/init-upgrade-lane.py <workspace> [--out <path>]
  --vmf-json:   override value_moving_functions.json path
  --regen-vmf:  re-run value-moving-functions.py even if JSON exists

Returns rc=0 on success (even if 0 hypotheses emitted), rc=1 on error.
"""
from __future__ import annotations

import argparse
import importlib.util
import json
import re
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

# ---------------------------------------------------------------------------
# OOS guard (single source of truth).
# ---------------------------------------------------------------------------
try:
    from tools.lib.scope_exclusion import is_oos  # type: ignore
except Exception:
    _HERE = Path(__file__).resolve().parent
    _LIB = _HERE / "lib"
    if str(_LIB) not in sys.path:
        sys.path.insert(0, str(_LIB))
    try:
        from scope_exclusion import is_oos  # type: ignore
    except Exception:
        def is_oos(rel: str, **_) -> bool:  # type: ignore[misc]
            n = ("/" + rel.replace("\\", "/")).lower()
            for marker in (
                "/test/", "/tests/", "_test.", ".t.sol", "/vendor/", "/lib/",
                "/node_modules/", "/out/", "/build/", "/target/",
            ):
                if marker in n:
                    return True
            return False

# ---------------------------------------------------------------------------
# Lazy-load value-moving-functions module.
# ---------------------------------------------------------------------------
_VMF_MOD_NAME = "value_moving_functions_iul_import"
_VMF_PATH = Path(__file__).resolve().parent / "value-moving-functions.py"


def _load_vmf_module():
    spec = importlib.util.spec_from_file_location(_VMF_MOD_NAME, _VMF_PATH)
    mod = importlib.util.module_from_spec(spec)
    sys.modules[_VMF_MOD_NAME] = mod
    spec.loader.exec_module(mod)
    return mod


_VMF: Any = None


def _vmf() -> Any:
    global _VMF
    if _VMF is None:
        _VMF = _load_vmf_module()
    return _VMF


# ---------------------------------------------------------------------------
# SHAPE 1: UNPROTECTED INITIALIZER detection patterns.
# ---------------------------------------------------------------------------

# Function name prefix matching (case-sensitive). Must be "initialize", "init",
# or "reinitialize" at a word boundary, OR followed immediately by an uppercase
# letter / digit / underscore (e.g. "initializeV2" is in-scope, but
# "initializer" is NOT an init function - it is a modifier name).
_INIT_FN_NAME_RE: re.Pattern = re.compile(
    r"^(initialize|init|reinitialize)(\b|[A-Z_0-9])"
)

# ---------------------------------------------------------------------------
# DIAMOND DISCRIMINATOR helpers.
#
# EIP-2535 Diamond facet init contracts follow the convention:
#   - Contract name starts with "Init" (e.g. InitBipMiscImprovements,
#     InitEmpty, InitDistribution ...), OR
#   - Source file lives under a path segment named exactly "init"
#     (e.g. ".../beanstalk/init/...").
#
# These contracts are exclusively called via owner-gated diamondCut(); their
# individual init() functions are protected one layer up.  Flagging them
# individually produces noise; instead the workspace runner emits ONE
# aggregate hypothesis listing all N such contracts.
# ---------------------------------------------------------------------------

_DIAMOND_INIT_PATH_RE: re.Pattern = re.compile(
    r"(?:^|/)init/"
)

_DIAMOND_INIT_CONTRACT_NAME_RE: re.Pattern = re.compile(
    r"\bcontract\s+(Init[A-Z_]\w*)\b"
)


def _is_diamond_init_context(source: str, file_rel: str) -> bool:
    """Return True if this file is an EIP-2535 Diamond init-contract.

    Criteria (OR):
      1. The file path contains a path segment named exactly "init"
         (e.g. "contracts/beanstalk/init/InitFoo.sol").
      2. The file defines at least one contract whose name starts with
         "Init" followed by an uppercase letter or underscore
         (e.g. "contract InitBipMiscImprovements").

    Both criteria are required to have no anchor into unrelated files; either
    one being true is sufficient for the Diamond context.
    """
    norm = file_rel.replace("\\", "/")
    if _DIAMOND_INIT_PATH_RE.search(norm):
        return True
    if _DIAMOND_INIT_CONTRACT_NAME_RE.search(source):
        return True
    return False

# Detects modifier names that constitute valid OZ initialization guards.
_INIT_MODIFIER_NAMES: re.Pattern = re.compile(
    r"\b(initializer|reinitializer|onlyInitializing)\b"
)

# Detects a call to _disableInitializers() anywhere in the function body.
_DISABLE_INITIALIZERS_RE: re.Pattern = re.compile(
    r"\b_disableInitializers\s*\("
)

# Detects the manual boolean guard pattern: ``initialized = true`` or
# ``_initialized = true`` (the two OZ-conventional variable names).
_MANUAL_BOOL_GUARD_RE: re.Pattern = re.compile(
    r"\b_?initialized\s*=\s*true\b"
)

# ---------------------------------------------------------------------------
# SHAPE 2: UNGUARDED UPGRADE AUTHORIZER detection patterns.
# ---------------------------------------------------------------------------

# Function names that constitute upgrade entry points (UUPS / Transparent /
# Beacon proxy).
_UPGRADE_FN_NAME_RE: re.Pattern = re.compile(
    r"^(_authorizeUpgrade|upgradeTo|upgradeToAndCall|setImplementation|setBeacon)$"
)

# Access control patterns - if ANY of these appear in the function body, the
# upgrade function is considered GUARDED and is NOT flagged.
_UPGRADE_ACCESS_CTRL_RE: list[re.Pattern] = [
    re.compile(r"\bonlyOwner\b"),
    re.compile(r"\bonlyRole\b"),
    re.compile(r"\bonlyAdmin\b"),
    re.compile(r"\b_checkOwner\s*\("),
    re.compile(r"\b_checkRole\s*\("),
    re.compile(r"\bhasRole\s*\("),
    re.compile(r"\brequire\s*\(.*\bmsg\.sender\b", re.S),
    re.compile(r"\brequire\s*\(.*\bonlyOwner\b", re.S),
    re.compile(r"\bassert\s*\(.*\bmsg\.sender\b", re.S),
    # OZ AccessControl-style _requireCallerHasRole / _requireOwner
    re.compile(r"\b_requireOwner\s*\("),
    re.compile(r"\b_requireCallerHasRole\s*\("),
    re.compile(r"\b_onlyOwner\s*\("),
    # Delegated-guard pattern: the wrapper body calls _authorizeUpgrade() which
    # carries the actual guard. This is the UUPS override pattern where upgradeTo /
    # upgradeToAndCall delegate to _authorizeUpgrade internally.
    re.compile(r"\b_authorizeUpgrade\s*\("),
]

# Contracts that are upgrade-proxy-aware: only apply the upgrade shape when
# the containing contract (or one of its bases) has one of these name patterns.
_UPGRADEABLE_CONTRACT_NAME_RE: re.Pattern = re.compile(
    r"\b\w*(Upgradeable|UUPS|Proxy)\w*\b"
)

# ---------------------------------------------------------------------------
# Solidity function extractor.
#
# Returns a list of dicts:
#   { name, visibility, modifiers: [str], body, start_line, is_constructor }
# ---------------------------------------------------------------------------

# Regex to match a Solidity function signature line.
# Group 1 = function name.
_SOL_FN_SIG_RE: re.Pattern = re.compile(
    r"\bfunction\s+([A-Za-z_]\w*)\s*\("
)

# Regex to match the special constructor keyword (Solidity 0.5+).
_SOL_CONSTRUCTOR_RE: re.Pattern = re.compile(r"\bconstructor\s*\(")

# Visibility keywords extracted from the header section.
_SOL_VISIBILITY_RE: re.Pattern = re.compile(
    r"\b(public|external|internal|private)\b"
)

# Modifier call in the function header: any identifier following the visibility
# and mutability keywords and preceding the ``{`` or ``;``.
# We extract the header text (between ``function foo(`` and the opening ``{``)
# and scan it for non-keyword identifiers as modifier names.
_SOL_MODIFIERS_STOP_WORDS: frozenset[str] = frozenset({
    "public", "external", "internal", "private",
    "pure", "view", "payable", "virtual", "override",
    "returns", "memory", "calldata", "storage",
})


def _extract_sol_fn_header(source: str, sig_match: re.Match) -> str:
    """Return the header text from the function signature to the opening brace."""
    start = sig_match.start()
    brace_pos = source.find("{", sig_match.end())
    semi_pos = source.find(";", sig_match.end())
    if brace_pos == -1:
        end = semi_pos if semi_pos != -1 else min(start + 1000, len(source))
    else:
        end = brace_pos
    return source[start:end]


def _extract_modifiers_from_header(header: str) -> list[str]:
    """Return a list of modifier names from a Solidity function header."""
    # Strip function name + params: everything after the closing ')' of the
    # parameter list, up to '{'.
    # Heuristic: find the first ')' that closes the param list.
    depth = 0
    param_end = -1
    for i, ch in enumerate(header):
        if ch == "(":
            depth += 1
        elif ch == ")":
            depth -= 1
            if depth == 0:
                param_end = i
                break
    if param_end == -1:
        return []
    after_params = header[param_end + 1:]
    # Collect bare identifiers (not keywords, not return type tuple,
    # not numbers).
    raw_tokens = re.findall(r"\b([A-Za-z_]\w*)\b", after_params)
    mods: list[str] = []
    skip_next = False
    for tok in raw_tokens:
        if skip_next:
            skip_next = False
            continue
        if tok in _SOL_MODIFIERS_STOP_WORDS:
            if tok == "returns":
                # everything in the returns(...) clause is a type, skip it
                skip_next = False  # handled by stripping via regex below
            continue
        mods.append(tok)
    # The crude token scan above may include return-type names.  Re-filter:
    # strip the returns(...) clause entirely.
    returns_stripped = re.sub(r"\breturns\s*\([^)]*\)", "", after_params)
    raw_tokens2 = re.findall(r"\b([A-Za-z_]\w*)\b", returns_stripped)
    mods2 = [t for t in raw_tokens2 if t not in _SOL_MODIFIERS_STOP_WORDS]
    return mods2


def _extract_fn_body(source: str, sig_match: re.Match) -> tuple[str, int, str]:
    """Return (full_text, start_line_1indexed, inner_body) for a Solidity function.

    - full_text    : from the function keyword to the closing brace (inclusive)
    - start_line   : 1-indexed line where the function keyword starts
    - inner_body   : text INSIDE the braces only (post-opening-brace); used for
                     access-control pattern matching to avoid hitting the fn's own
                     name in the signature text.
    """
    start = sig_match.start()
    start_line = source[:start].count("\n") + 1
    brace_pos = source.find("{", sig_match.end())
    if brace_pos == -1:
        end_pos = source.find(";", sig_match.end())
        if end_pos == -1:
            end_pos = min(start + 500, len(source))
        return source[start:end_pos], start_line, ""
    depth = 1
    pos = brace_pos + 1
    while pos < len(source) and depth > 0:
        ch = source[pos]
        if ch == "{":
            depth += 1
        elif ch == "}":
            depth -= 1
        pos += 1
    inner = source[brace_pos + 1: pos - 1]  # content between { and }
    return source[start:pos], start_line, inner


def _is_upgradeable_contract(source: str) -> bool:
    """Return True if the source declares or inherits an upgradeable contract."""
    # Look for: contract Foo is Bar, Baz { where any base matches
    # *Upgradeable*/*UUPS*/*Proxy*.
    contract_decl_re = re.compile(
        r"\bcontract\s+\w+\s+is\s+([^{]+)\{"
    )
    for m in contract_decl_re.finditer(source):
        bases = m.group(1)
        if _UPGRADEABLE_CONTRACT_NAME_RE.search(bases):
            return True
    # Also check the contract name itself.
    contract_name_re = re.compile(r"\bcontract\s+(\w+)")
    for m in contract_name_re.finditer(source):
        if _UPGRADEABLE_CONTRACT_NAME_RE.search(m.group(1)):
            return True
    return False


# ---------------------------------------------------------------------------
# Core detection functions (unit-testable entry points).
# ---------------------------------------------------------------------------

def detect_unprotected_initializers(
    source: str,
    file_rel: str = "fixture.sol",
    ws_abs: str = "/tmp/iul_fixture_ws",
    diamond_sink: "list[dict[str, Any]] | None" = None,
) -> list[dict[str, Any]]:
    """Detect unprotected initializer functions in a Solidity source string.

    Returns a list of hypothesis dicts (may be empty).
    This is the primary unit-testable entry point for Shape 1.

    SUPPRESSOR 1 - EMPTY-BODY:
      Any init/initialize fn whose body is empty or whitespace-only is skipped.
      An empty body performs no privileged action and cannot be exploited.

    SUPPRESSOR 2 - DIAMOND DISCRIMINATOR:
      If this file is an EIP-2535 Diamond init-contract context
      (``_is_diamond_init_context(source, file_rel)`` returns True), each
      matching init fn is collected into ``diamond_sink`` instead of being
      returned as an individual hypothesis.  The workspace runner (``run_iul``)
      then emits ONE aggregate hypothesis for all N such contracts.
      Pass ``diamond_sink=[]`` from tests to capture these candidates.
      If ``diamond_sink`` is None, diamond-context files are silently excluded
      (no individual hypotheses, no aggregate at function level).
    """
    results: list[dict[str, Any]] = []
    seen: set[str] = set()  # dedup by function name within a file

    # Determine once per file whether Diamond-init context applies.
    diamond_ctx = _is_diamond_init_context(source, file_rel)

    for sig_match in _SOL_FN_SIG_RE.finditer(source):
        fn_name = sig_match.group(1)

        # Skip constructors by name (Solidity older style: function Foo()).
        # Also skip a function named exactly "constructor" (shouldn't match
        # _SOL_FN_SIG_RE but belt-and-suspenders).
        if fn_name == "constructor":
            continue

        # Check the function name against the initializer pattern.
        if not _INIT_FN_NAME_RE.match(fn_name):
            continue

        # Extract header and body.
        header = _extract_sol_fn_header(source, sig_match)
        _full, start_line, inner_body = _extract_fn_body(source, sig_match)

        # Check visibility: must be public or external.
        vis_match = _SOL_VISIBILITY_RE.search(header)
        if vis_match is None:
            # Default visibility in Solidity pre-0.5 is public, but we require
            # explicit declaration to be conservative.
            continue
        visibility = vis_match.group(1)
        if visibility not in ("public", "external"):
            continue

        # Check modifiers: if any modifier name matches the guard pattern, skip.
        modifiers = _extract_modifiers_from_header(header)
        modifier_names_str = " ".join(modifiers)
        if _INIT_MODIFIER_NAMES.search(modifier_names_str):
            continue

        # SUPPRESSOR 1 - EMPTY-BODY: body is empty or whitespace-only.
        # An empty init fn performs no privileged action; nothing to flag.
        if not inner_body.strip():
            continue

        # Check function body for _disableInitializers() call.
        if _DISABLE_INITIALIZERS_RE.search(inner_body):
            continue

        # Check function body for manual bool guard (initialized = true).
        if _MANUAL_BOOL_GUARD_RE.search(inner_body):
            continue

        # Dedup within file.
        if fn_name in seen:
            continue
        seen.add(fn_name)

        # SUPPRESSOR 2 - DIAMOND DISCRIMINATOR: this is a Diamond init-contract
        # context.  Do not emit individual hypotheses; collect the candidate
        # into diamond_sink for aggregate emission by the workspace runner.
        if diamond_ctx:
            if diamond_sink is not None:
                diamond_sink.append({
                    "file": file_rel,
                    "function": fn_name,
                    "start_line": start_line,
                })
            continue

        missing_guard = (
            "public/external initializer function carries no OZ `initializer`/"
            "`reinitializer` modifier, no `_disableInitializers()` call, and no "
            "manual `initialized = true` bool guard - any caller can run this "
            "function after deployment and overwrite critical state."
        )

        fuzz_oracle_hint = (
            f"Invariant: calling `{fn_name}()` a second time (after the "
            "legitimate first call) MUST revert. If it succeeds, the "
            "initializer is unprotected and an attacker can re-initialize "
            "critical contract state."
        )

        results.append({
            "workspace":       ws_abs,
            "file":            file_rel,
            "function":        fn_name,
            "language":        "sol",
            "init_or_upgrade": "init",
            "missing_guard":   missing_guard,
            "attack_class":    "unprotected-initialization-or-upgrade",
            "source":          "IUL",
            "verdict":         "needs-fuzz",
            "fuzz_oracle_hint": fuzz_oracle_hint,
        })

    return results


def detect_unguarded_upgrade_authorizers(
    source: str,
    file_rel: str = "fixture.sol",
    ws_abs: str = "/tmp/iul_fixture_ws",
) -> list[dict[str, Any]]:
    """Detect unguarded upgrade-authorizer functions in a Solidity source string.

    Returns a list of hypothesis dicts (may be empty).
    This is the primary unit-testable entry point for Shape 2.
    """
    # Discriminator: skip files whose contracts don't inherit from an
    # upgradeable base - avoids flagging random setters named setImplementation
    # in non-proxy contracts.
    if not _is_upgradeable_contract(source):
        return []

    results: list[dict[str, Any]] = []
    seen: set[str] = set()

    for sig_match in _SOL_FN_SIG_RE.finditer(source):
        fn_name = sig_match.group(1)

        if not _UPGRADE_FN_NAME_RE.match(fn_name):
            continue

        header = _extract_sol_fn_header(source, sig_match)
        _full, start_line, inner_body = _extract_fn_body(source, sig_match)

        # Check modifiers: if non-empty, the fn is guarded.
        modifiers = _extract_modifiers_from_header(header)
        # Filter out common non-guard keywords that leak through.
        guard_mods = [
            m for m in modifiers
            if m not in (
                "virtual", "override", "internal", "external",
                "public", "private",
            )
        ]
        if guard_mods:
            continue

        # Check inner_body (content between braces) for access-control patterns.
        # Using inner_body (not the full text including signature) avoids
        # false-suppression where the function's own name in the signature
        # matches a body-pattern (e.g. the _authorizeUpgrade delegated-guard
        # pattern would otherwise match the name of _authorizeUpgrade itself).
        guarded = any(pat.search(inner_body) for pat in _UPGRADE_ACCESS_CTRL_RE)
        if guarded:
            continue

        # Dedup within file.
        if fn_name in seen:
            continue
        seen.add(fn_name)

        missing_guard = (
            f"upgrade function `{fn_name}` has no access-control modifier "
            "(onlyOwner/onlyRole) and no inline require/assert check on "
            "`msg.sender` - any address can trigger an upgrade and point the "
            "proxy at a malicious implementation."
        )

        fuzz_oracle_hint = (
            f"Invariant: a call to `{fn_name}(maliciousImpl)` from a "
            "non-privileged address MUST revert. If it succeeds, any caller "
            "can replace the implementation contract."
        )

        results.append({
            "workspace":       ws_abs,
            "file":            file_rel,
            "function":        fn_name,
            "language":        "sol",
            "init_or_upgrade": "upgrade",
            "missing_guard":   missing_guard,
            "attack_class":    "unprotected-initialization-or-upgrade",
            "source":          "IUL",
            "verdict":         "needs-fuzz",
            "fuzz_oracle_hint": fuzz_oracle_hint,
        })

    return results


# ---------------------------------------------------------------------------
# Workspace-level runner.
# ---------------------------------------------------------------------------

def run_iul(
    workspace: str | Path,
    vmf_json_path: str | Path | None = None,
    out_path: str | Path | None = None,
    regen_vmf: bool = False,
) -> int:
    """Run IUL over the workspace.

    Two-pass scan:
      Pass A: files referenced in value_moving_functions.json (if present).
      Pass B: ALL .sol files in the workspace (init/upgrade fns are security-
              critical even when they are not value-moving).

    Returns rc=0 on success, rc=1 on error.
    """
    ws = Path(workspace).resolve()
    audit_dir = ws / ".auditooor"
    audit_dir.mkdir(parents=True, exist_ok=True)

    # --- Optional VMF JSON pass (pass A) ---
    vmf_path = Path(vmf_json_path) if vmf_json_path else audit_dir / "value_moving_functions.json"

    vmf_files: set[str] = set()  # relative paths from VMF JSON
    if regen_vmf or not vmf_path.exists():
        # Attempt lazy regen; if it fails, skip pass A silently.
        try:
            vmf_mod = _vmf()
            vmf_mod.run(str(ws), out_path=str(vmf_path))
        except Exception:
            pass

    if vmf_path.exists():
        try:
            with vmf_path.open() as f:
                vmf_data = json.load(f)
            for rec in vmf_data.get("functions", []):
                rel = rec.get("file", "")
                if rel and not is_oos(rel):
                    vmf_files.add(rel)
        except Exception:
            pass

    # --- Build the set of .sol files to scan (union of VMF files + all .sol) ---
    all_sol_files: set[Path] = set()

    # Pass A: VMF files (Solidity only for this lane).
    for rel in vmf_files:
        if rel.endswith(".sol"):
            abs_path = ws / rel
            if abs_path.exists():
                all_sol_files.add(abs_path)

    # Pass B: walk workspace for all .sol files.
    for sol_path in ws.rglob("*.sol"):
        try:
            rel = str(sol_path.relative_to(ws))
        except ValueError:
            continue
        if is_oos(rel):
            continue
        all_sol_files.add(sol_path)

    out = Path(out_path) if out_path else audit_dir / "init_upgrade_hypotheses.jsonl"

    total_hypotheses = 0
    # Dedup across files by (file, function, init_or_upgrade).
    seen_globally: set[tuple[str, str, str]] = set()

    # Collect Diamond init-contract candidates for L30 aggregate hypothesis.
    # Each entry: {"file": rel, "function": fn_name, "start_line": n}
    diamond_candidates: list[dict[str, Any]] = []
    # Track unique contract files (not fn instances) for the aggregate count.
    diamond_contract_files: list[str] = []

    with out.open("w") as fh:
        for abs_path in sorted(all_sol_files):
            try:
                rel = str(abs_path.relative_to(ws))
            except ValueError:
                rel = str(abs_path)

            if is_oos(rel):
                continue

            try:
                source = abs_path.read_text(encoding="utf-8", errors="replace")
            except OSError:
                continue

            # Shape 1: unprotected initializers.
            file_diamond_sink: list[dict[str, Any]] = []
            for hyp in detect_unprotected_initializers(
                source=source,
                file_rel=rel,
                ws_abs=str(ws),
                diamond_sink=file_diamond_sink,
            ):
                key = (hyp["file"], hyp["function"], hyp["init_or_upgrade"])
                if key in seen_globally:
                    continue
                seen_globally.add(key)
                fh.write(json.dumps(hyp) + "\n")
                total_hypotheses += 1

            if file_diamond_sink:
                diamond_candidates.extend(file_diamond_sink)
                if rel not in diamond_contract_files:
                    diamond_contract_files.append(rel)

            # Shape 2: unguarded upgrade authorizers.
            for hyp in detect_unguarded_upgrade_authorizers(
                source=source, file_rel=rel, ws_abs=str(ws)
            ):
                key = (hyp["file"], hyp["function"], hyp["init_or_upgrade"])
                if key in seen_globally:
                    continue
                seen_globally.add(key)
                fh.write(json.dumps(hyp) + "\n")
                total_hypotheses += 1

        # L30 aggregate: emit ONE hypothesis for all Diamond init-contract
        # candidates found in this workspace.  This follows the enumerate-
        # all-callsites discipline: one report covering N contracts is more
        # actionable than N individual noise items.
        if diamond_candidates:
            n = len(diamond_contract_files)
            contract_names = sorted({
                c["file"].rsplit("/", 1)[-1].replace(".sol", "")
                for c in diamond_candidates
            })
            contract_list = ", ".join(contract_names)
            aggregate_hyp: dict[str, Any] = {
                "workspace":       str(ws),
                "file":            "__diamond_aggregate__",
                "function":        "__all_Init_contracts__",
                "language":        "sol",
                "init_or_upgrade": "init",
                "missing_guard":   (
                    f"[IUL] Verify diamondCut owner-gates all {n} Init* contracts "
                    f"(N={n}); a directly-callable init that mutates Diamond storage "
                    "would be unprotected. "
                    f"Contracts: {contract_list}"
                ),
                "attack_class":    "unprotected-initialization-or-upgrade",
                "source":          "IUL",
                "verdict":         "needs-fuzz",
                "fuzz_oracle_hint": (
                    f"Invariant: for each of the {n} Init* contracts, calling "
                    "init() directly (without going through diamondCut) MUST "
                    "revert or be a no-op due to owner-only diamondCut enforcement. "
                    "Fuzz: deploy Diamond + InitX; call InitX.init() directly from "
                    "a non-owner address; assert the Diamond state is unchanged."
                ),
                "diamond_contracts": diamond_contract_files,
                "diamond_candidate_count": len(diamond_candidates),
            }
            fh.write(json.dumps(aggregate_hyp) + "\n")
            total_hypotheses += 1

    ts = datetime.now(timezone.utc).isoformat()
    print(
        f"IUL complete: {total_hypotheses} init/upgrade hypotheses "
        f"-> {out}  [{ts}]"
    )
    return 0


# ---------------------------------------------------------------------------
# CLI entry point.
# ---------------------------------------------------------------------------

def _main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="IUL: detect unprotected initializers and unguarded upgrade authorizers."
    )
    parser.add_argument("workspace", help="Workspace root path")
    parser.add_argument("--out", default=None, help="Override .jsonl output path")
    parser.add_argument("--vmf-json", default=None, help="Override value_moving_functions.json path")
    parser.add_argument("--regen-vmf", action="store_true", help="Re-run VMF even if JSON exists")
    args = parser.parse_args(argv)

    return run_iul(
        workspace=args.workspace,
        vmf_json_path=args.vmf_json,
        out_path=args.out,
        regen_vmf=args.regen_vmf,
    )


if __name__ == "__main__":
    sys.exit(_main())
