#!/usr/bin/env python3
"""readme-conformance-check.py - FAIL-CLOSED README runbook conformance gate.

Reports per-step status {done|skipped|waived|n/a-for-language|RED} for a
workspace against the canonical step manifest at
tools/readme_runbook_steps.json.

A step is RED unless ONE of these is true:
  (a) All its artifact_checks pass AND (attestation_required=false OR a valid
      attestation file exists at attestation_path).
  (b) In nonstrict mode, a waiver line exists in
      .auditooor/readme_step_waivers.txt in the form "waive: <step_id>:
      <non-empty reason>". A waiver with a blank reason is treated as absent
      (RED). Strict mode rejects text waivers.
  (c) The step's language_filter is non-null AND the workspace's detected
      language set does not intersect it (status = n/a-for-language).

Mechanical steps (class=mechanical, conditional-mechanical) are verified
entirely by artifact checks. Manual/manual-judgment steps additionally require
an attestation file.

Wire into audit-done-guard.py: call evaluate(strict=True) and check
result["conformance_pass"]. Any applicable step status RED causes
conformance_pass=False, which MUST block a done claim.

CLI: python3 tools/readme-conformance-check.py <workspace> [--json] [--strict]
     [--manifest tools/readme_runbook_steps.json]

rc 0 = all applicable steps done, waived (nonstrict), or n/a
rc 1 = one or more applicable steps are RED
rc 2 = usage/workspace error
"""
from __future__ import annotations

import argparse
import importlib.util
import json
import os
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

_REPO_ROOT = Path(__file__).resolve().parent.parent
_STRICT_PIPELINE_STATE_REL = Path(".auditooor") / "pipeline" / "state.json"
_STRICT_EXPECTED_STEP_COUNT = 69


def _load_json(p: Path) -> Any:
    try:
        return json.loads(p.read_text(encoding="utf-8", errors="replace"))
    except (OSError, ValueError):
        return None


def _load_module(name: str, filename: str) -> Any:
    path = _REPO_ROOT / "tools" / filename
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise ImportError(f"cannot load {path}")
    module = importlib.util.module_from_spec(spec)
    sys.modules.setdefault(name, module)
    spec.loader.exec_module(module)
    return module


def _mtime_hours_ago(p: Path) -> float:
    try:
        return (time.time() - p.stat().st_mtime) / 3600.0
    except OSError:
        return float("inf")


# ---------------------------------------------------------------------------
# Language detection (best-effort, no external deps)
# ---------------------------------------------------------------------------

# These are directory names whose contents are generated, cached, or vendored
# copies of code.  They are pruned from the complete walk so copied dependencies
# cannot make an otherwise unrelated workspace look applicable to a language.
_PRUNED_LANGUAGE_DIRS = frozenset({
    ".auditooor", ".cache", ".git", "__pycache__", "node_modules",
    "third_party", "third-party", "vendor", "vendors",
})


def _load_source_extension_registry() -> dict[str, str]:
    """Load the repository SSOT without duplicating its extension table."""
    path = _REPO_ROOT / "tools" / "lib" / "source_extensions.py"
    spec = importlib.util.spec_from_file_location("_readme_source_extensions", path)
    if spec is None or spec.loader is None:
        raise ImportError(f"cannot load source extension registry: {path}")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    ext_to_lang = getattr(mod, "EXT_TO_LANG", None)
    if not isinstance(ext_to_lang, dict):
        raise ValueError(f"source extension registry has no EXT_TO_LANG: {path}")
    return {str(ext).lower(): str(lang).lower() for ext, lang in ext_to_lang.items()}


_CANONICAL_EXT_TO_LANG = _load_source_extension_registry()

# Interim fallback only for source extensions absent from the canonical SSOT.
_INTERIM_EXT_TO_LANG = {
    ".c": "c", ".h": "c", ".cc": "cpp", ".cpp": "cpp", ".cxx": "cpp",
    ".hpp": "cpp", ".java": "java",
    ".oscript": "oscript", ".aa": "oscript",
}

# Manifest names are deliberately explicit.  Extensions come only from the
# canonical registry above.  This is conformance applicability detection only;
# source contents and source-comment text are never inspected.
_MANIFEST_MARKERS: dict[str, list[str]] = {
    "solidity": ["foundry.toml", "hardhat.config.js", "hardhat.config.ts", "truffle-config.js", "remappings.txt"],
    "evm": ["foundry.toml", "hardhat.config.js", "hardhat.config.ts", "truffle-config.js", "remappings.txt"],
    "go": ["go.mod", "go.sum", "go.work"],
    "rust": ["cargo.toml", "cargo.lock"],
    "javascript": ["package.json", "package-lock.json", "yarn.lock", "pnpm-lock.yaml", "bun.lockb"],
    "js": ["package.json", "package-lock.json", "yarn.lock", "pnpm-lock.yaml", "bun.lockb"],
    "typescript": ["tsconfig.json", "deno.json", "deno.jsonc"],
    "vyper": ["vyper.toml", "brownie-config.yaml", "brownie-config.yml"],
    "move": ["move.toml", "move.lock"],
    "cairo": ["scarb.toml", "cairo_project.toml"],
    "noir": ["nargo.toml"],
    "zk": ["nargo.toml"],
    "python": ["pyproject.toml", "setup.py", "setup.cfg", "requirements.txt", "pipfile"],
    "c": ["cmakelists.txt", "meson.build"],
    "cpp": ["cmakelists.txt", "meson.build"],
    "java": ["pom.xml", "build.gradle", "build.gradle.kts", "settings.gradle", "gradlew"],
}

_LANG_MARKERS: dict[str, list[str]] = {}
for _extension, _language in _CANONICAL_EXT_TO_LANG.items():
    _LANG_MARKERS.setdefault(_language, []).append(_extension)
for _extension, _language in _INTERIM_EXT_TO_LANG.items():
    _LANG_MARKERS.setdefault(_language, []).append(_extension)
for _language, _markers in _MANIFEST_MARKERS.items():
    _LANG_MARKERS.setdefault(_language, []).extend(_markers)

# Compatibility aliases used by existing conformance consumers.  They point at
# canonical extensions and do not define a second source-extension registry.
_LANG_MARKERS["evm"] = list(_LANG_MARKERS.get("solidity", []))
_LANG_MARKERS["js"] = list(_LANG_MARKERS.get("javascript", []))
_LANG_MARKERS["zk"] = list(dict.fromkeys(
    _LANG_MARKERS.get("zk", [])
    + [ext for ext, lang in _CANONICAL_EXT_TO_LANG.items() if lang in {"circom", "noir", "zokrates"}]
))


def _detect_languages(ws: Path) -> set[str]:
    """Walk the workspace for deterministic extension/manifest markers.

    The walk is complete apart from generated/vendor directories.  No source
    text is read, and there is intentionally no file-count cutoff.
    """
    detected: set[str] = set()
    for root, dirs, files in os.walk(ws, topdown=True, followlinks=False):
        dirs[:] = sorted(
            d for d in dirs
            if d.casefold() not in _PRUNED_LANGUAGE_DIRS
        )
        for name in sorted(files, key=str.casefold):
            lower_name = name.casefold()
            suffix = Path(lower_name).suffix
            for lang, markers in _LANG_MARKERS.items():
                if suffix in markers or lower_name in markers:
                    detected.add(lang)
    return detected


# ---------------------------------------------------------------------------
# Waiver loader
# ---------------------------------------------------------------------------

def _load_waivers(ws: Path, manifest: dict) -> dict[str, str]:
    """Return {step_id: reason} for all valid waiver lines."""
    waiver_rel = manifest.get("waiver_file", ".auditooor/readme_step_waivers.txt")
    waiver_path = ws / waiver_rel
    waivers: dict[str, str] = {}
    if not waiver_path.is_file():
        return waivers
    for raw_line in waiver_path.read_text(encoding="utf-8", errors="replace").splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        # Format: waive: <step_id>: <reason>
        if not line.startswith("waive:"):
            continue
        rest = line[len("waive:"):].strip()
        parts = rest.split(":", 1)
        if len(parts) != 2:
            continue
        step_id = parts[0].strip()
        reason = parts[1].strip()
        if step_id and reason:  # blank reason = RED, do not store
            waivers[step_id] = reason
    return waivers


# ---------------------------------------------------------------------------
# Attestation schema (single source of truth)
# ---------------------------------------------------------------------------

# Fallback base required-fields set. The AUTHORITATIVE list lives in the
# manifest under attestation_format.required_fields_always; this tuple is only
# used when the manifest omits it (older manifests). Kept in sync with
# tools/readme_runbook_steps.json.
_FALLBACK_REQUIRED_FIELDS_ALWAYS: tuple[str, ...] = ("completed_at", "attested_by", "summary")


def required_fields_always(manifest: dict | None) -> list[str]:
    """The base attestation fields every attestation must carry, per the
    manifest's attestation_format.required_fields_always (single source of
    truth). Falls back to the historical hardcoded tuple if the manifest does
    not declare it. Reused by manual-step-preflight's schema-validate gate so
    both readers agree on the schema and never drift."""
    if isinstance(manifest, dict):
        fmt = manifest.get("attestation_format")
        if isinstance(fmt, dict):
            fields = fmt.get("required_fields_always")
            if isinstance(fields, list) and all(isinstance(f, str) for f in fields) and fields:
                return list(fields)
    return list(_FALLBACK_REQUIRED_FIELDS_ALWAYS)


def attestation_schema_missing_fields(obj: dict, step: dict, manifest: dict | None) -> list[str]:
    """Return the list of schema-required attestation fields that are missing
    (or empty) from `obj` for `step`. Combines the always-required base fields
    (from the manifest attestation_format) with the step-specific
    attestation_fields declared in how_to_verify_done. Empty list == schema OK.

    Reusable helper so manual-step-preflight can run the SAME schema check
    BEFORE its grounding (read-ack/evidence) check, closing the gap where a
    missing required field (e.g. attested_by) slipped through the preflight
    lane silently (NUVA step-1b evidence)."""
    missing: list[str] = []
    base = required_fields_always(manifest)
    for field in base:
        # base fields must be present AND truthy (an empty string is missing)
        if not obj.get(field):
            missing.append(field)
    extra_fields = step.get("how_to_verify_done", {}).get("attestation_fields", []) or []
    for field in extra_fields:
        if field in base:
            continue  # already checked above
        # step fields may legitimately be a falsy-but-present value (e.g. an
        # empty list forks_pruned==[]); only a truly-absent key is a violation.
        if obj.get(field) is None:
            missing.append(field)
    return missing


# ---------------------------------------------------------------------------
# Attestation check
# ---------------------------------------------------------------------------

def _check_attestation(ws: Path, step: dict, manifest: dict | None = None) -> tuple[bool, str]:
    """Return (ok, detail). ok=True if attestation is valid or not required."""
    if not step.get("how_to_verify_done", {}).get("attestation_required", False):
        return True, "not-required"
    rel_path = step["how_to_verify_done"].get("attestation_path")
    if not rel_path:
        return False, "attestation_required but no attestation_path in manifest"
    apath = ws / rel_path
    if not apath.is_file():
        return False, f"attestation file missing: {rel_path}"
    obj = _load_json(apath)
    if not isinstance(obj, dict):
        return False, f"attestation file is not valid JSON: {rel_path}"
    # Schema validation via the shared helper (base required_fields_always from
    # the manifest attestation_format + step-specific attestation_fields).
    missing = attestation_schema_missing_fields(obj, step, manifest)
    if missing:
        return False, f"attestation missing required field '{missing[0]}': {rel_path}"
    return True, f"valid attestation at {rel_path}"


# ---------------------------------------------------------------------------
# Artifact checks
# ---------------------------------------------------------------------------

def _resolve(ws: Path, rel: str) -> Path:
    return ws / rel


_screen_coverage_mod = None


def _load_screen_coverage_module():
    """Lazy-load tools/capability-screen-language-coverage.py (hyphenated
    filename; cached after first import so repeated checks in one process
    don't re-parse capability-inventory-build.py's CURATED_FULL_WIRING)."""
    global _screen_coverage_mod
    if _screen_coverage_mod is not None:
        return _screen_coverage_mod
    import importlib.util
    path = _REPO_ROOT / "tools" / "capability-screen-language-coverage.py"
    spec = importlib.util.spec_from_file_location("_rcc_screen_coverage", path)
    mod = importlib.util.module_from_spec(spec)  # type: ignore[arg-type]
    sys.modules["_rcc_screen_coverage"] = mod
    spec.loader.exec_module(mod)  # type: ignore[union-attr]
    _screen_coverage_mod = mod
    return mod


def _run_artifact_checks(
    ws: Path, checks: list[dict], languages: set[str] | None = None
) -> tuple[bool, list[str]]:
    """Return (all_pass, list_of_failures)."""
    failures: list[str] = []
    for chk in checks:
        ctype = chk.get("type", "")
        note = chk.get("note", "")

        if ctype == "dir_exists":
            p = _resolve(ws, chk["path"])
            if not p.is_dir():
                failures.append(f"dir_exists FAIL: {chk['path']}{' ('+note+')' if note else ''}")

        elif ctype == "dir_nonempty":
            p = _resolve(ws, chk["path"])
            if not p.is_dir():
                failures.append(f"dir_nonempty FAIL (missing): {chk['path']}")
            elif not any(True for _ in p.iterdir()):
                failures.append(f"dir_nonempty FAIL (empty): {chk['path']}")

        elif ctype == "file_exists":
            p = _resolve(ws, chk["path"])
            if not p.is_file():
                failures.append(f"file_exists FAIL: {chk['path']}{' ('+note+')' if note else ''}")

        elif ctype == "file_nonempty":
            p = _resolve(ws, chk["path"])
            if not p.is_file():
                failures.append(f"file_nonempty FAIL (missing): {chk['path']}")
            else:
                min_b = chk.get("min_bytes", 1)
                size = p.stat().st_size
                if size < min_b:
                    failures.append(f"file_nonempty FAIL ({size}B < {min_b}B): {chk['path']}")

        elif ctype == "file_min_data_rows":
            # PASS if the file has >= min_rows DATA rows (non-blank lines that do
            # NOT start with the comment prefix). Distinguishes a real, populated
            # file from a bootstrap stub that is byte-nonempty but all-comment
            # (e.g. targets.tsv left as the TBD header). comment_prefix defaults
            # to "#"; min_rows defaults to 1.
            p = _resolve(ws, chk["path"])
            if not p.is_file():
                failures.append(f"file_min_data_rows FAIL (missing): {chk['path']}")
            else:
                prefix = chk.get("comment_prefix", "#")
                min_rows = chk.get("min_rows", 1)
                rows = [ln for ln in p.read_text(encoding="utf-8", errors="replace").splitlines()
                        if ln.strip() and not ln.lstrip().startswith(prefix)]
                if len(rows) < min_rows:
                    failures.append(
                        f"file_min_data_rows FAIL ({len(rows)} data rows < {min_rows}): {chk['path']}"
                        f"{' ('+note+')' if note else ''}")

        elif ctype == "file_executable":
            # For repo-relative tools, resolve from repo root
            rel = chk.get("path") or chk.get("path_from_repo_root")
            p = _REPO_ROOT / rel if chk.get("path_from_repo_root") else _resolve(ws, rel)
            if not p.is_file():
                failures.append(f"file_executable FAIL (missing): {rel}{' ('+note+')' if note else ''}")
            elif not os.access(p, os.X_OK):
                failures.append(f"file_executable FAIL (not executable): {rel}")

        elif ctype == "file_exists_any":
            paths = chk.get("paths", [])
            found = any(_resolve(ws, r).is_file() for r in paths)
            if not found:
                failures.append(f"file_exists_any FAIL: none of {paths}{' ('+note+')' if note else ''}")

        elif ctype == "file_nonempty_any":
            # PASS if ANY of the candidate paths exists AND is >= min_bytes.
            # Used where a canonical artifact may live in >1 location (e.g.
            # LIVE_TARGET_REPORT.md is written to docs/ by make audit, but a
            # ws-root copy is also valid).
            paths = chk.get("paths", [])
            min_b = chk.get("min_bytes", 1)
            ok = any(_resolve(ws, r).is_file() and _resolve(ws, r).stat().st_size >= min_b
                     for r in paths)
            if not ok:
                failures.append(
                    f"file_nonempty_any FAIL: none of {paths} exists with >={min_b}B"
                    f"{' ('+note+')' if note else ''}")

        elif ctype == "file_nonempty_by_language":
            # A language-specific receipt cannot satisfy another language's
            # evidence contract. Unmapped languages retain the existing default.
            paths_by_language = chk.get("paths_by_language", {})
            default_paths = chk.get("default_paths", [])
            min_b = chk.get("min_bytes", 1)
            selected = sorted(languages or ()) or ["default"]
            for language in selected:
                configured = paths_by_language.get(language, default_paths)
                paths = [configured] if isinstance(configured, str) else configured
                ok = any(
                    isinstance(candidate, str)
                    and _resolve(ws, candidate).is_file()
                    and _resolve(ws, candidate).stat().st_size >= min_b
                    for candidate in paths
                )
                if not ok:
                    failures.append(
                        f"file_nonempty_by_language FAIL ({language}): none of {paths} "
                        f"exists with >={min_b}B"
                        f"{' ('+note+')' if note else ''}"
                    )

        elif ctype == "file_absent_or_field_equals":
            p = _resolve(ws, chk["path"])
            if p.is_file():
                obj = _load_json(p)
                jp = chk.get("json_pointer", "").lstrip("/")
                actual = obj.get(jp) if isinstance(obj, dict) else None
                ok_vals = chk.get("ok_values", [])
                if actual not in ok_vals:
                    failures.append(
                        f"file_absent_or_field_equals FAIL: {chk['path']}[{jp}]={actual!r} not in {ok_vals}"
                        + (f" ({note})" if note else "")
                    )
            # absent = ok

        elif ctype == "file_contains_any":
            p = _resolve(ws, chk["path"])
            if not p.is_file():
                failures.append(f"file_contains_any FAIL (missing): {chk['path']}")
            else:
                text = p.read_text(encoding="utf-8", errors="replace")
                patterns = chk.get("patterns", [])
                if not any(pat in text for pat in patterns):
                    failures.append(
                        f"file_contains_any FAIL: {chk['path']} missing any of {patterns}"
                        + (f" ({note})" if note else "")
                    )

        elif ctype == "json_field_not_equals":
            p = _resolve(ws, chk["path"])
            if p.is_file():
                obj = _load_json(p)
                jp = chk.get("json_pointer", "").lstrip("/")
                actual = obj.get(jp) if isinstance(obj, dict) else None
                bad_val = chk.get("bad_value")
                if actual == bad_val:
                    failures.append(
                        f"json_field_not_equals FAIL: {chk['path']}[{jp}]={actual!r} (forbidden value)"
                        + (f" ({note})" if note else "")
                    )
            # file absent = skip this check (file_exists check handles absence)

        elif ctype == "json_field_contains":
            p = _resolve(ws, chk["path"])
            if p.is_file():
                obj = _load_json(p)
                jp = chk.get("json_pointer", "").lstrip("/")
                actual = str(obj.get(jp) or "") if isinstance(obj, dict) else ""
                must = chk.get("must_contain", "")
                if must not in actual:
                    failures.append(
                        f"json_field_contains FAIL: {chk['path']}[{jp}]={actual!r} missing {must!r}"
                        + (f" ({note})" if note else "")
                    )
            else:
                failures.append(f"json_field_contains FAIL (file missing): {chk['path']}")

        elif ctype == "json_field_not_falsy":
            p = _resolve(ws, chk["path"])
            if p.is_file():
                obj = _load_json(p)
                jp = chk.get("json_pointer", "").lstrip("/")
                val = obj.get(jp) if isinstance(obj, dict) else None
                if not val or str(val).lower() in ("0", "false", "no", "none", ""):
                    failures.append(
                        f"json_field_not_falsy FAIL: {chk['path']}[{jp}]={val!r}"
                        + (f" ({note})" if note else "")
                    )
            else:
                failures.append(f"json_field_not_falsy FAIL (file missing): {chk['path']}")

        elif ctype == "file_age_hours_lt":
            p = _resolve(ws, chk["path"])
            if p.is_file():
                age = _mtime_hours_ago(p)
                max_h = chk.get("max_hours", 6)
                if age > max_h:
                    failures.append(
                        f"file_age_hours_lt FAIL: {chk['path']} is {age:.1f}h old > {max_h}h limit"
                        + (f" ({note})" if note else "")
                    )
            # absence handled by file_exists check

        elif ctype == "any_of":
            # Composite: PASS iff AT LEAST ONE nested check-group passes. Each
            # entry of `groups` is itself a list of checks that are ANDed; the
            # any_of passes if any one group fully passes. Used to model peer
            # evidence alternatives - e.g. step-2c is satisfied by EITHER the EVM
            # campaign cluster (chimera_harnesses dir + fuzz_campaign_receipt) OR
            # a mutation-verified Go economic-invariant sidecar - without weakening
            # either arm. Generic and language-agnostic.
            groups = chk.get("groups", [])
            group_fails: list[str] = []
            passed_any = not groups  # empty groups -> vacuous pass (no-op)
            for gi, grp in enumerate(groups):
                g_ok, g_fails = _run_artifact_checks(ws, grp, languages)
                if g_ok:
                    passed_any = True
                    break
                group_fails.append(f"[alt {gi}: " + "; ".join(g_fails) + "]")
            if not passed_any:
                failures.append(
                    f"any_of FAIL: no alternative satisfied {' '.join(group_fails)}"
                    + (f" ({note})" if note else ""))

        elif ctype == "go_mvc_sidecar_verified":
            # PASS iff >=1 mutation-verified Go economic-invariant sidecar exists
            # under `dir` (default .auditooor/mvc_sidecar): a *.json whose
            # baseline_result==PASS, mutation_verified is truthy, and
            # mutants_killed>=min_mutants (default 1). This credits the Go/Cosmos
            # step-2c arm (a native go-test conservation/authz harness bound to the
            # real keeper, mutation-verified non-vacuous) the SAME way the EVM arm
            # is credited by a fuzz_campaign_receipt - the sidecar IS the "campaign
            # ran, non-vacuously" evidence for a chain with no medusa/echidna
            # equivalent (NUVA/SEI precedent). Generic: no workspace hard-coding;
            # a producer-less workspace simply fails this check and falls through
            # to the Solidity artifact alternatives.
            d = _resolve(ws, chk.get("dir", ".auditooor/mvc_sidecar"))
            min_mut = int(chk.get("min_mutants", 1))
            credited = False
            reason = ""
            if not d.is_dir():
                reason = f"no {chk.get('dir', '.auditooor/mvc_sidecar')} dir"
            else:
                for sc in sorted(d.glob("*.json")):
                    obj = _load_json(sc)
                    if not isinstance(obj, dict):
                        continue
                    if str(obj.get("lang", "")).lower() != "go":
                        continue
                    baseline = str(obj.get("baseline_result", "")).upper()
                    mv = obj.get("mutation_verified")
                    try:
                        killed = int(obj.get("mutants_killed", 0) or 0)
                    except (TypeError, ValueError):
                        killed = 0
                    if baseline == "PASS" and bool(mv) and killed >= min_mut:
                        credited = True
                        break
                if not credited and not reason:
                    reason = (f"no go sidecar with baseline_result==PASS + "
                              f"mutation_verified + mutants_killed>={min_mut}")
            if not credited:
                failures.append(
                    f"go_mvc_sidecar_verified FAIL: {reason}"
                    + (f" ({note})" if note else ""))

        elif ctype == "capability_screen_language_coverage":
            # ENFORCEMENT-HOLE FIX (axelar-sc 2026-07-12): fail-closed check that
            # the language-applicable phase-2 (audit-deep) capability SCREEN pass
            # actually emitted >=1 hypotheses artifact per in-scope language
            # bucket, not merely that SOME aggregate audit-deep manifest exists.
            # Language-aware and generic: reuses
            # tools/capability-screen-language-coverage.py, which derives the
            # 77-screen registry from capability-inventory-build.py's
            # CURATED_FULL_WIRING (single source of truth, no re-derivation) and
            # only requires a bucket when the workspace's OWN detected language
            # set triggers it - a pure-Solidity ws is never blocked for a
            # missing go-*/rust-*/js-oscript-*/zk-* bucket, and vice versa.
            cslc = _load_screen_coverage_module()
            res = cslc.evaluate(ws, languages or set())
            if not isinstance(res, dict) or type(res.get("ok")) is not bool:
                failures.append(
                    "capability_screen_language_coverage FAIL: malformed checker result"
                )
            elif not res["ok"]:
                checker_failures = res.get("failures", [])
                if isinstance(checker_failures, list):
                    failures.extend(str(f) for f in checker_failures)
                if not checker_failures:
                    failures.append(
                        "capability_screen_language_coverage FAIL: checker returned ok=false"
                    )

        else:
            failures.append(
                f"unknown artifact check type FAIL: {ctype or '<missing>'}"
                + (f" ({note})" if note else "")
            )

    return len(failures) == 0, failures


# ---------------------------------------------------------------------------
# Per-step evaluation
# ---------------------------------------------------------------------------

StatusType = str  # "done" | "red" | "waived" | "n/a-for-language"


def _evaluate_step(
    ws: Path,
    step: dict,
    waivers: dict[str, str],
    languages: set[str],
    manifest: dict | None = None,
    strict: bool = False,
) -> dict:
    step_id = step["step_id"]
    label = step.get("label", step_id)
    required = step.get("required", True)

    result: dict[str, Any] = {
        "step_id": step_id,
        "label": label,
        "class": step.get("class", "unknown"),
        "required": required,
        "status": "red",  # default: fail-closed
        "failures": [],
        "waiver_reason": None,
        "waiver_rejected": False,
        "attestation_detail": None,
        "diagnostics": [],
        "fail_gates": [],
    }

    # 1. Language filter - n/a if language not applicable
    lang_filter = step.get("language_filter")
    if lang_filter:
        filter_set = set(lang_filter) if isinstance(lang_filter, list) else {lang_filter}
        if not languages.intersection(filter_set):
            result["status"] = "n/a-for-language"
            result["failures"] = []
            return result

    # 2. Waiver check
    if step_id in waivers:
        result["waiver_reason"] = waivers[step_id]
        if not strict:
            result["status"] = "waived"
            result["failures"] = []
            return result
        result["waiver_rejected"] = True
        result["failures"].append(
            "waiver REJECTED in strict mode: text waivers do not satisfy conformance"
        )
        result["fail_gates"].append(f"readme-conformance-waiver-rejected:{step_id}")

    # 3. Artifact checks
    how = step.get("how_to_verify_done", {})
    artifact_checks = how.get("artifact_checks", [])
    condition_checks = how.get("condition_checks", [])
    all_checks = artifact_checks + condition_checks

    art_pass, art_failures = _run_artifact_checks(ws, all_checks, languages)
    result["failures"].extend(art_failures)

    # 4. Attestation check
    att_ok, att_detail = _check_attestation(ws, step, manifest)
    result["attestation_detail"] = att_detail
    if not att_ok:
        result["failures"].append(f"attestation FAIL: {att_detail}")

    if art_pass and att_ok and not result["waiver_rejected"]:
        result["status"] = "done"
    else:
        result["status"] = "red"

    return result


def _strict_step_result_template(step: dict) -> dict[str, Any]:
    step_id = step["step_id"]
    return {
        "step_id": step_id,
        "label": step.get("label", step_id),
        "class": step.get("class", "unknown"),
        "required": step.get("required", True),
        "status": "red",
        "failures": [],
        "waiver_reason": None,
        "waiver_rejected": False,
        "attestation_detail": None,
        "diagnostics": [],
        "fail_gates": [],
    }


def _strict_manifest_result(manifest: dict, validator: Any) -> tuple[bool, list[str], list[str]]:
    result = validator.validate_manifest(manifest)
    if not isinstance(result, dict) or type(result.get("valid")) is not bool:
        return False, ["strict manifest validator returned a malformed result"], ["strict-manifest-validator-malformed"]
    if result.get("valid"):
        if manifest.get("schema") != "auditooor.pipeline_manifest.v2":
            return False, ["strict manifest schema mismatch"], ["strict-manifest-schema-mismatch"]
        if manifest.get("expected_step_count") != _STRICT_EXPECTED_STEP_COUNT:
            return False, ["strict manifest expected_step_count mismatch"], ["strict-manifest-step-count-mismatch"]
        return True, [], []
    diagnostics = result.get("diagnostics", [])
    messages = []
    codes = []
    for item in diagnostics:
        if isinstance(item, dict):
            code = str(item.get("code") or "strict-manifest-invalid")
            message = str(item.get("message") or code)
        else:
            code = "strict-manifest-invalid"
            message = str(item)
        codes.append(code)
        messages.append(message)
    return False, messages or ["strict manifest invalid"], codes or ["strict-manifest-invalid"]


def _current_receipt_archive_path(ws: Path, step_id: str, attempt: int) -> Path:
    return ws / ".auditooor" / "pipeline" / "receipts" / step_id / f"attempt-{attempt}.json"


def _verify_current_receipt_archive(
    ws: Path,
    step: dict[str, Any],
    entry: dict[str, Any],
    state: dict[str, Any],
    machine: Any,
    receipt_mod: Any,
    contracts: dict[str, dict[str, Any]],
    executor: Any,
) -> list[str]:
    current_id = entry.get("current_receipt_id")
    record = machine._history_record(entry, current_id) if isinstance(current_id, str) else None
    if record is None:
        return ["missing_current_receipt_history"]
    attempt = record.get("attempt")
    if isinstance(attempt, bool) or not isinstance(attempt, int) or attempt < 1:
        return ["invalid_current_receipt_attempt"]
    archive = _current_receipt_archive_path(ws, step["step_id"], attempt)
    if not archive.is_file():
        return [f"receipt_archive_missing:{archive.relative_to(ws)}"]
    receipt = _load_json(archive)
    ok, receipt_errors = receipt_mod.validate_terminal_receipt(receipt)
    if not ok or not isinstance(receipt, dict):
        return [f"receipt_archive_invalid:{err}" for err in receipt_errors] or ["receipt_archive_invalid"]
    errors: list[str] = []
    for field in ("receipt_id", "self_hash"):
        if receipt.get(field) != current_id:
            errors.append(f"{field}_mismatch")
    for field in ("run_id", *receipt_mod.PROVENANCE_FIELDS):
        if receipt.get(field) != state.get(field):
            errors.append(f"receipt_{field}_mismatch")
    if receipt.get("step_id") != step["step_id"]:
        errors.append("receipt_step_id_mismatch")
    if receipt.get("order_index") != step.get("order_index"):
        errors.append("receipt_order_index_mismatch")
    if receipt.get("attempt") != attempt:
        errors.append("receipt_attempt_mismatch")
    if receipt.get("status") != record.get("status") or receipt.get("status") != entry.get("state"):
        errors.append("receipt_status_mismatch")
    if receipt_mod.stable_hash(receipt.get("output_artifacts", [])) != record.get("output_fingerprint"):
        errors.append("receipt_output_fingerprint_mismatch")
    if receipt.get("output_artifacts") != record.get("output_artifacts"):
        errors.append("receipt_output_artifacts_history_mismatch")
    if receipt.get("output_artifacts") != entry.get("current_output_artifacts"):
        errors.append("receipt_output_artifacts_state_mismatch")
    expected_contract_ids = [
        contract_id for contract_id in step.get("produces", []) if isinstance(contract_id, str) and contract_id
    ]
    receipt_artifacts = receipt.get("output_artifacts", [])
    artifacts_by_contract: dict[str, dict[str, Any]] = {}
    for index, artifact in enumerate(receipt_artifacts):
        if not isinstance(artifact, dict):
            errors.append(f"receipt_output_artifact_{index}_invalid")
            continue
        contract_id = artifact.get("artifact_contract")
        if not isinstance(contract_id, str) or not contract_id:
            errors.append(f"receipt_output_artifact_{index}_missing_contract")
            continue
        if contract_id in artifacts_by_contract:
            errors.append(f"receipt_output_artifact_duplicate_contract:{contract_id}")
            continue
        artifacts_by_contract[contract_id] = artifact
    for contract_id in artifacts_by_contract:
        if contract_id not in expected_contract_ids:
            errors.append(f"receipt_output_artifact_unexpected_contract:{contract_id}")
    for contract_id in expected_contract_ids:
        contract = contracts.get(contract_id)
        if contract is None:
            errors.append(f"receipt_output_artifact_missing_manifest_contract:{contract_id}")
            continue
        artifact = artifacts_by_contract.get(contract_id)
        if artifact is None:
            errors.append(f"receipt_output_artifact_missing_contract:{contract_id}")
            continue
        actual_row, diagnostics = executor._artifact_row(contract, ws)
        if diagnostics or actual_row is None:
            errors.extend(f"receipt_output_artifact_missing:{contract['id']}:{item}" for item in diagnostics or ["missing"])
            continue
        if artifact.get("artifact_contract") != actual_row.get("artifact_contract"):
            errors.append(f"receipt_output_artifact_contract_mismatch:{contract['id']}")
        if artifact.get("path") != actual_row.get("path"):
            errors.append(f"receipt_output_artifact_path_mismatch:{contract['id']}")
        if artifact.get("sha256") != actual_row.get("sha256"):
            errors.append(f"receipt_output_artifact_sha256_mismatch:{actual_row.get('path')}")
        if artifact.get("size") != actual_row.get("size"):
            errors.append(f"receipt_output_artifact_size_mismatch:{actual_row.get('path')}")
        if artifact.get("semantic_validator_results") != actual_row.get("semantic_validator_results"):
            errors.append(f"receipt_output_artifact_validators_mismatch:{contract['id']}")
    return errors


def _evaluate_strict_state(ws: Path, manifest: dict, manifest_path: Path) -> dict:
    waivers = _load_waivers(ws, manifest)
    machine = _load_module("_readme_conformance_state_machine", "pipeline-state-machine.py")
    applicability = _load_module("_readme_conformance_applicability", "pipeline-applicability.py")
    validator = _load_module("_readme_conformance_manifest_validate", "pipeline-manifest-validate.py")
    receipt_mod = _load_module("_readme_conformance_receipt", "pipeline-receipt.py")
    executor = _load_module("_readme_conformance_executor", "pipeline-executor.py")
    manifest_ok, manifest_messages, manifest_codes = _strict_manifest_result(manifest, validator)
    state_path = ws / _STRICT_PIPELINE_STATE_REL
    state, state_errors = machine.read_state(state_path)
    closeout_result = {"valid": False, "diagnostics": ["state_unavailable"], "current_receipt_count": 0}
    contracts: dict[str, dict[str, Any]] = {}
    if manifest_ok and state is not None:
        contracts = executor._artifact_contracts(manifest, ws)
        closeout_result = machine.closeout(state, manifest)

    step_results = []
    red_steps: list[str] = []
    diagnostics: list[str] = []
    fail_gates: list[str] = []
    global_errors = list(state_errors)
    if not manifest_ok:
        global_errors.extend(manifest_codes)
        diagnostics.extend(f"strict-manifest error: {item}" for item in manifest_messages)
        fail_gates.extend(f"readme-conformance-manifest:{item}" for item in manifest_codes)
    if state_errors:
        diagnostics.extend(f"strict-state error: {item}" for item in state_errors)
        fail_gates.extend(f"readme-conformance-state:{item}" for item in state_errors)
    if not closeout_result.get("valid", False):
        closeout_diags = closeout_result.get("diagnostics", []) or ["closeout_invalid"]
        diagnostics.extend(f"strict-state closeout error: {item}" for item in closeout_diags)
        fail_gates.extend(f"readme-conformance-closeout:{item}" for item in closeout_diags)

    state_steps = state.get("steps", {}) if isinstance(state, dict) else {}
    receipt_errors_by_step: dict[str, list[str]] = {}
    if manifest_ok and state is not None:
        for step in manifest.get("steps", []):
            if not isinstance(step, dict) or not isinstance(step.get("step_id"), str):
                continue
            entry = state_steps.get(step["step_id"])
            if isinstance(entry, dict) and machine._has_current_terminal_receipt(entry):
                receipt_errors_by_step[step["step_id"]] = _verify_current_receipt_archive(
                    ws, step, entry, state, machine, receipt_mod, contracts, executor
                )
    for step in manifest["steps"]:
        result = _strict_step_result_template(step)
        step_id = step["step_id"]
        if step_id in waivers:
            result["waiver_reason"] = waivers[step_id]
        try:
            applicability_result = applicability.evaluate_probe(manifest, step.get("applicability_probe"), ws)
            applicable = bool(applicability_result.get("result"))
            result["attestation_detail"] = "state-receipt-driven"
            result["applicability_detail"] = applicability_result
        except Exception as exc:
            applicable = True
            message = f"strict applicability error: {type(exc).__name__}: {exc}"
            result["failures"].append(message)
            result["diagnostics"].append(message)
            result["fail_gates"].append(f"readme-conformance-applicability:{step_id}")
            diagnostics.append(message)
            fail_gates.append(f"readme-conformance-applicability:{step_id}")

        expected_state = "succeeded" if applicable else "not_applicable"
        entry = state_steps.get(step_id)
        if not manifest_ok:
            result["failures"].append("strict-manifest invalid")
        if state_errors:
            result["failures"].append("strict-state invalid")
        if global_errors and not isinstance(entry, dict):
            result["failures"].append("strict-state unavailable")
        elif not manifest_ok:
            pass
        elif not isinstance(entry, dict):
            result["failures"].append("strict-state missing step entry")
        elif entry.get("state") != expected_state:
            result["failures"].append(
                f"strict-state mismatch: expected {expected_state} receipt, got {entry.get('state')!r}"
            )
        elif not machine._has_current_terminal_receipt(entry):
            result["failures"].append("strict-state missing current terminal receipt")
        else:
            receipt_errors = receipt_errors_by_step.get(step_id, [])
            if receipt_errors:
                result["failures"].extend(f"strict-receipt error: {item}" for item in receipt_errors)
                result["fail_gates"].extend(
                    f"readme-conformance-receipt:{step_id}:{item}" for item in receipt_errors
                )
            elif applicable:
                result["status"] = "done"
            else:
                result["status"] = "n/a-for-language"
        if result["status"] == "red":
            result["status"] = "red"
            result["fail_gates"].append(f"readme-conformance-state-step:{step_id}")
            red_steps.append(step_id)
        step_results.append(result)
        diagnostics.extend(result.get("diagnostics", []))
        fail_gates.extend(result.get("fail_gates", []))

    return {
        "workspace": str(ws),
        "conformance_pass": len(red_steps) == 0 and not fail_gates,
        "red_step_ids": red_steps,
        "detected_languages": [],
        "waivers_loaded": list(waivers.keys()),
        "steps": step_results,
        "manifest_path": str(manifest_path),
        "strict": True,
        "diagnostics": sorted(set(diagnostics)),
        "fail_gates": sorted(set(fail_gates)),
        "strict_state_detail": {
            "state_path": str(state_path),
            "manifest_path": str(manifest_path),
            "manifest_valid": manifest_ok,
            "manifest_errors": manifest_codes,
            "state_present": state is not None,
            "state_errors": state_errors,
            "closeout": closeout_result,
            "receipt_errors_by_step": receipt_errors_by_step,
        },
    }


# ---------------------------------------------------------------------------
# Main evaluate
# ---------------------------------------------------------------------------

def evaluate(ws: Path, manifest_path: Path | None = None, strict: bool = False) -> dict:
    """Return conformance result dict, failing closed on every applicable RED step."""
    ws = ws.resolve()
    if not ws.is_dir():
        return {
            "workspace": str(ws),
            "conformance_pass": False,
            "error": f"workspace not found: {ws}",
            "red_step_ids": [],
            "steps": [],
            "diagnostics": [f"conformance engine error: workspace not found: {ws}"],
            "fail_gates": ["readme-conformance-engine:workspace-missing"],
        }

    # Load manifest
    if manifest_path is None:
        manifest_path = _REPO_ROOT / "tools" / "readme_runbook_steps.json"
    manifest = _load_json(manifest_path)
    if not isinstance(manifest, dict) or "steps" not in manifest:
        return {
            "workspace": str(ws),
            "conformance_pass": False,
            "error": f"manifest not found or invalid: {manifest_path}",
            "red_step_ids": [],
            "steps": [],
            "diagnostics": [f"conformance engine error: invalid manifest {manifest_path}"],
            "fail_gates": ["readme-conformance-engine:invalid-manifest"],
        }

    steps = manifest["steps"]
    if not isinstance(steps, list):
        return {
            "workspace": str(ws),
            "conformance_pass": False,
            "error": f"manifest steps is not a list: {manifest_path}",
            "red_step_ids": [],
            "steps": [],
            "diagnostics": ["conformance engine error: manifest steps is not a list"],
            "fail_gates": ["readme-conformance-engine:malformed-steps"],
        }
    if strict:
        try:
            return _evaluate_strict_state(ws, manifest, manifest_path)
        except Exception as exc:
            diagnostic = f"strict state engine error: {type(exc).__name__}: {exc}"
            return {
                "workspace": str(ws),
                "conformance_pass": False,
                "error": diagnostic,
                "red_step_ids": [
                    step["step_id"]
                    for step in steps
                    if isinstance(step, dict) and isinstance(step.get("step_id"), str)
                ],
                "steps": [],
                "diagnostics": [diagnostic],
                "fail_gates": ["readme-conformance-engine:strict-state"],
                "manifest_path": str(manifest_path),
                "strict": True,
            }
    try:
        waivers = _load_waivers(ws, manifest)
        languages = _detect_languages(ws)
    except Exception as exc:
        diagnostic = f"conformance engine error during workspace detection: {type(exc).__name__}: {exc}"
        return {
            "workspace": str(ws),
            "conformance_pass": False,
            "error": diagnostic,
            "red_step_ids": [],
            "steps": [],
            "diagnostics": [diagnostic],
            "fail_gates": ["readme-conformance-engine:language-detection"],
        }

    step_results = []
    red_steps = []
    diagnostics: list[str] = []
    fail_gates: list[str] = []
    for index, step in enumerate(steps):
        if not isinstance(step, dict) or not isinstance(step.get("step_id"), str):
            diagnostic = f"conformance engine error: malformed step at index {index}"
            diagnostics.append(diagnostic)
            fail_gates.append(f"readme-conformance-engine:step-{index}")
            step_results.append({
                "step_id": f"<index-{index}>", "label": "malformed step",
                "class": "unknown", "required": True, "status": "red",
                "failures": [diagnostic], "waiver_reason": None,
                "waiver_rejected": False, "attestation_detail": None,
                "diagnostics": [diagnostic],
                "fail_gates": [f"readme-conformance-engine:step-{index}"],
            })
            red_steps.append(f"<index-{index}>")
            continue
        try:
            r = _evaluate_step(ws, step, waivers, languages, manifest, strict)
        except Exception as exc:
            diagnostic = (
                f"conformance engine error while evaluating {step['step_id']}: "
                f"{type(exc).__name__}: {exc}"
            )
            diagnostics.append(diagnostic)
            gate = f"readme-conformance-engine:{step['step_id']}"
            fail_gates.append(gate)
            r = {
                "step_id": step["step_id"], "label": step.get("label", step["step_id"]),
                "class": step.get("class", "unknown"), "required": True,
                "status": "red", "failures": [diagnostic],
                "waiver_reason": None, "waiver_rejected": False,
                "attestation_detail": None, "diagnostics": [diagnostic],
                "fail_gates": [gate],
            }
        step_results.append(r)
        if r["status"] == "red":
            red_steps.append(step["step_id"])
        diagnostics.extend(r.get("diagnostics", []))
        fail_gates.extend(r.get("fail_gates", []))

    conformance_pass = len(red_steps) == 0
    return {
        "workspace": str(ws),
        "conformance_pass": conformance_pass,
        "red_step_ids": red_steps,
        "detected_languages": sorted(languages),
        "waivers_loaded": list(waivers.keys()),
        "steps": step_results,
        "manifest_path": str(manifest_path),
        "strict": strict,
        "diagnostics": diagnostics,
        "fail_gates": sorted(set(fail_gates)),
    }


# ---------------------------------------------------------------------------
# Formatting
# ---------------------------------------------------------------------------

_STATUS_SYMBOL = {
    "done": "PASS",
    "red": "RED ",
    "waived": "WAIV",
    "n/a-for-language": "N/A ",
}


def _print_human(result: dict) -> None:
    ws = result.get("workspace", "?")
    cp = result.get("conformance_pass", False)
    langs = result.get("detected_languages", [])
    red = result.get("red_step_ids", [])

    print(f"readme-conformance-check  workspace: {ws}")
    print(f"detected languages: {langs if langs else '(none detected)'}")
    print(f"waivers loaded: {result.get('waivers_loaded', [])}")
    print()

    for sr in result.get("steps", []):
        sym = _STATUS_SYMBOL.get(sr["status"], "????")
        waiver_suffix = f"  [waiver: {sr['waiver_reason']}]" if sr.get("waiver_reason") else ""
        print(f"  [{sym}] {sr['step_id']:12s}  {sr['class']:40s}  {sr['label']}{waiver_suffix}")
        for f in sr.get("failures", []):
            print(f"           FAIL: {f}")
        if sr["status"] == "red" and sr.get("attestation_detail") and "FAIL" in sr.get("attestation_detail", ""):
            print(f"           attestation: {sr['attestation_detail']}")

    print()
    if cp:
        print("readme-conformance: PASS - all applicable steps done/waived/n-a")
    else:
        print(f"readme-conformance: FAIL - {len(red)} applicable step(s) RED: {red}")


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def main(argv: list[str]) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("workspace")
    ap.add_argument("--json", action="store_true")
    ap.add_argument("--strict", action="store_true", help="Reject text waivers")
    ap.add_argument("--manifest", default=None, help="Path to readme_runbook_steps.json (default: auto)")
    args = ap.parse_args(argv)

    ws = Path(os.path.expanduser(args.workspace)).resolve()
    mpath = Path(args.manifest) if args.manifest else None
    result = evaluate(ws, manifest_path=mpath, strict=args.strict)

    if args.json:
        print(json.dumps(result, indent=2))
    else:
        if result.get("error"):
            print(f"ERROR: {result['error']}")
        else:
            _print_human(result)

    if not ws.is_dir():
        return 2
    return 0 if result.get("conformance_pass") else 1


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
