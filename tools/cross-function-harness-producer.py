#!/usr/bin/env python3
"""cross-function-harness-producer.py - the PRODUCER that writes the ONE
canonical mutation-coverage artifact every L37 coverage gate reads.

WHY THIS TOOL EXISTS (the missing producer)
-------------------------------------------
Two L37 completeness gates READ ``<ws>/.auditooor/mutation_verify_coverage.json``:

  - ``tools/function-coverage-completeness.py`` (per-function axis) - "did every
    in-scope FUNCTION get a REAL, mutation-verified attack?".
  - ``tools/cross-function-invariant-coverage.py`` (composition axis) - "is there
    a MUTATION-VERIFIED test asserting each cross-function / round-trip /
    state-machine invariant?".

Both consumers parse that file via a tolerant ``_records_from_payload`` that
looks for a top-level list under one of
``results/verdicts/harnesses/functions/mutations/records/rows``. But NOTHING
PRODUCED that file in the canonical SHARED-CONTRACT shape carrying BOTH
per-function AND cross-function verdicts. The per-function mutation pass
(Makefile ``_audit-deep-solidity-genuine-coverage``) writes
``genuine_coverage_manifest.json`` (per-function only); the cross-function
mutation pass had no producer at all. So a workspace could pass the gates
VACUOUSLY (no file -> backend-unavailable -> conservative downgrade) or never
reach a genuine PASS even when the real harnesses existed.

This tool closes the loop. It:

  (1) AGGREGATES per-function verdicts from
      ``<ws>/.auditooor/genuine_coverage_manifest.json`` (the existing
      genuine-coverage producer's output), normalizing each row to a
      per-function record.
  (2) For the cross-function axis: if cross-function harnesses exist in the
      workspace, it RUNS ``tools/mutation-verify-coverage.py`` on each (reusing
      the existing mutation oracle - never re-implementing mutation testing per
      the tool-duplication charter) and records a cross-function verdict; if no
      cross-function harnesses exist yet, it emits the agentic-harness-build
      DISPATCH BRIEF (same pattern as the genuine-coverage stage) and records
      the requirements as ``pending`` so the gate stays fail-closed (REACHABLE
      when the real work runs, never vacuously PASS).
  (3) WRITES the canonical artifact
      ``<ws>/.auditooor/mutation_verify_coverage.json`` in the SHARED-CONTRACT
      schema::

        {
          "schema": "auditooor.mutation_verify_coverage.v1",
          "generated_at": "<iso8601>",
          "run_id": "<id|null>",
          "per_function":  [{"function","file_line","mutation_verified","clean_result", ...}],
          "cross_function":[{"requirement","test","mutation_verified", ...}],
          "verdicts":      [ ...flattened per-function + cross-function records... ],
          "counts": {...}
        }

      The top-level ``per_function`` / ``cross_function`` lists satisfy the
      SHARED CONTRACT. The flattened ``verdicts`` list (carrying ``function`` /
      ``verdict`` / ``harness`` / ``killed`` per record) is what the consumers'
      ``_records_from_payload`` actually iterates - so the SAME file feeds both
      the contract readers AND the legacy record readers with zero ambiguity.

OFFLINE-SAFE / GENERIC
----------------------
- ``--workspace`` only; zero workspace hardcoding (morpho appears only in the
  test + smoke anchor).
- LANGUAGE-AWARE: the per-function aggregation is language-agnostic (it reads
  the manifest). The cross-function harness discovery + mutation-run is
  language-aware via the same extension table the sibling gates use, and reuses
  ``mutation-verify-coverage.py``'s per-language runner table (halmos/forge for
  Solidity, ``cargo test`` for Rust, ``go test`` for Go, ``--harness`` literal
  for Move/Cairo) - so a Go/Rust workspace produces the same canonical file a
  Solidity workspace does.
- Each sub-step degrades to a recorded skip when its input / toolchain is
  absent. The cross-function mutation run is SKIPPED (not failed) when the
  toolchain (``forge`` / ``cargo`` / ``go``) is absent, recorded as
  ``toolchain-absent`` so the gate is REACHABLE when the toolchain is present
  and never silently green when it is not.

RELATED TOOLS (tool-dedup rule, codified 2026-05-28)
----------------------------------------------------
``find tools/ -iname '*harness-producer*'`` returned nothing; this is a NEW
producer. Adjacent tools and the gap each leaves:
  - tools/mutation-verify-coverage.py: the ORACLE (mutate->re-run->restore).
    REUSED here for cross-function harnesses; never re-implemented.
  - tools/cross-function-invariant-coverage.py: the GATE (reads the canonical
    file). Does NOT produce it. This tool produces what that gate reads.
  - tools/function-coverage-completeness.py: the per-function GATE. Also reads
    the canonical file (preferring it over a live mutation run). This tool gives
    it the cached artifact so the per-function gate is fast + deterministic.
  - Makefile ``_audit-deep-solidity-genuine-coverage``: produces
    ``genuine_coverage_manifest.json`` (per-function ONLY). This tool CONSUMES
    that manifest and FOLDS it into the canonical file together with the
    cross-function axis - the missing half.

CLI
---
    python3 tools/cross-function-harness-producer.py --workspace <ws> \
        [--language {auto,solidity,rust,go,move,cairo}] \
        [--max-mutants N] [--mutant-timeout S] [--max-requirements N] \
        [--emit-brief-only] [--json]

Exit code
---------
- 0 always on a successful write (the gate, not the producer, decides PASS/FAIL).
- 2 on an unreadable workspace / internal error.

Dependency-free (stdlib only). Never commits; never executes target code except
through the existing mutation oracle (which restores the tree byte-for-byte).
"""
from __future__ import annotations

import argparse
import importlib.util
import json
import os
import sys
from datetime import datetime, timezone
from pathlib import Path

SCHEMA = "auditooor.mutation_verify_coverage.v1"
GATE = "CROSS-FUNCTION-HARNESS-PRODUCER"

_HERE = Path(__file__).resolve().parent

_LANG_BY_EXT = {".sol": "solidity", ".rs": "rust", ".go": "go", ".move": "move", ".cairo": "cairo"}

# Test/harness path heuristics (mirrors cross-function-invariant-coverage._TEST_HINTS).
_TEST_HINTS = ("/test/", "/tests/", "_test.go", ".t.sol", "test_", "/mock", "/mocks/",
               "_test.rs", "tests.rs", ".spec.", "/spec/", "/harness", "echidna",
               "halmos", "medusa", "/poc", "poc_", "_poc")
# Cross-function harnesses are specifically those that exercise >=2 functions /
# a round-trip. We accept any test/harness file but tag the ones whose name
# hints at composition.
# r36-rebuttal: lane XFN-HARNESS-DISCOVERY registered in .auditooor/agent_pathspec.json
# "xfn" / "xfn_" is the common shorthand for cross-function composition harnesses
# (e.g. XFn_<requirement>.t.sol); without it the producer skips authored
# composition harnesses and mutation-verifies only the older invariant specs,
# yielding a spurious 0/N cross-function coverage. Generic across workspaces.
_CROSS_FN_HINTS = ("roundtrip", "round_trip", "round-trip", "composition",
                   "invariant", "statemachine", "state_machine", "_xfi", "cross_function",
                   "cross-function", "crossfunction", "conservation",
                   "xfn", "xfn_", "siblingpair", "sibling_pair")

_SKIP_DIRS = {
    ".git", "node_modules", "vendor", "target", "dist", "build", "out",
    "lib", "cache", ".audit_logs", "submissions", "prior_audits",
    "mining_rounds", "reports", "docs",
}
_GENERATED_NON_HARNESS_DIRS = {
    ".auditooor/per_function_invariants",
    ".auditooor/pre_flight_packs",
    ".auditooor/worker_packets",
}


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


# ---------------------------------------------------------------------------
# Reuse the mutation oracle + the cross-function requirement enumerator by path
# (hyphenated filenames -> load by spec).
# ---------------------------------------------------------------------------
def _load_module(filename: str, modname: str):
    tool = _HERE / filename
    if not tool.is_file():
        return None
    spec = importlib.util.spec_from_file_location(modname, str(tool))
    if spec is None or spec.loader is None:
        return None
    mod = importlib.util.module_from_spec(spec)
    sys.modules[modname] = mod
    try:
        spec.loader.exec_module(mod)
    except Exception:  # noqa: BLE001 - resilient to a broken sibling tool
        return None
    return mod


# ---------------------------------------------------------------------------
# Per-function aggregation from genuine_coverage_manifest.json.
# ---------------------------------------------------------------------------
_GENUINE_VERDICT_TO_VERIFIED = {
    "non-vacuous": True,
    "vacuous": False,
    "no-baseline": False,
    "skipped": False,
    "error": False,
}


def _read_genuine_manifest(ws: Path) -> dict | None:
    for cand in (
        ws / ".auditooor" / "genuine_coverage_manifest.json",
        ws / ".auditooor" / "genuine-coverage-manifest.json",
    ):
        if cand.is_file() and cand.stat().st_size > 0:
            try:
                return json.loads(cand.read_text(encoding="utf-8", errors="replace"))
            except (OSError, ValueError):
                return None
    return None


def _aggregate_per_function(manifest: dict | None) -> list[dict]:
    """Normalize each genuine-coverage verdict row into a SHARED-CONTRACT
    per-function record carrying BOTH the contract fields
    (function/file_line/mutation_verified/clean_result) AND the legacy
    record fields (verdict/source/harness) so both consumers parse it."""
    if not isinstance(manifest, dict):
        return []
    rows = manifest.get("verdicts") or manifest.get("functions") or []
    out: list[dict] = []
    for row in rows:
        if not isinstance(row, dict):
            continue
        verdict = str(row.get("verdict") or "error").strip().lower()
        fn = row.get("function") or row.get("fn") or row.get("name")
        source = row.get("source") or row.get("file_line") or row.get("file")
        harness = (row.get("harness_contract") or row.get("harness")
                   or row.get("harness_path") or row.get("test"))
        verified = _GENUINE_VERDICT_TO_VERIFIED.get(verdict, False)
        # IMPORTANT: emit an UNAMBIGUOUS verdict token for the consumers'
        # normalizer. function-coverage-completeness._normalize_mut_verdict
        # checks the vacuous-token set BEFORE the killed-token set, and
        # "non-vacuous" contains the substring "vacuous" - so passing the raw
        # genuine string "non-vacuous" would be MISCLASSIFIED as vacuous. We map
        # to the consumer's own canonical tokens (killed / vacuous / no-baseline)
        # and preserve the original string under genuine_verdict.
        if verdict == "no-baseline":
            consumer_verdict = "no-baseline"
        elif verified:
            consumer_verdict = "killed"
        else:
            consumer_verdict = "vacuous"
        rec = {
            # SHARED-CONTRACT per-function fields:
            "function": fn,
            "file_line": source,
            "mutation_verified": bool(verified),
            "clean_result": "pass" if verdict != "no-baseline" else "fail",
            # legacy record fields (consumed by _records_from_payload + verdict
            # / function-key / harness-name extractors):
            "verdict": consumer_verdict,
            "genuine_verdict": verdict,
            "source": source,
            "file": source,
            "harness": harness,
            "killed": bool(verified),
            "axis": "per-function",
        }
        out.append(rec)
    return out


def _aggregate_mvc_sidecars(ws: Path) -> list[dict]:
    """Normalize the durable per-function mutation-KILL sidecars under
    ``.auditooor/mvc_sidecar/*.json`` (written by mutation-verify-coverage.py's
    auto-persist) into SHARED-CONTRACT per-function records.

    These are GENUINE mutation-verified kills (real baseline PASS on the in-scope
    CUT + a behaviour-changing mutant killed) but were ORPHANED: per_function was
    built only from genuine_coverage_manifest and cross_function_sidecars read a
    DIFFERENT dir (cross-function-coverage/), so 14 real kills (ts_*/btc_*/
    mvc-omnibridge-fintransfer) earned 0 per_function_verified credit on near-intents
    2026-06-26. Credit a record only when verdict is non-vacuous/killed AND the
    baseline genuinely PASSed AND a mutant was actually killed (killed flag OR
    killed_count>0) - vacuous/no-baseline/errored sidecars do NOT count (no
    false-green)."""
    out: list[dict] = []
    d = ws / ".auditooor" / "mvc_sidecar"
    if not d.is_dir():
        return out
    for path in sorted(d.glob("*.json")):
        try:
            p = json.loads(path.read_text(encoding="utf-8", errors="replace"))
        except (OSError, ValueError):
            continue
        if not isinstance(p, dict):
            continue
        verdict = str(p.get("verdict") or "").strip().lower()
        baseline = p.get("baseline") if isinstance(p.get("baseline"), dict) else {}
        baseline_ok = str(baseline.get("status") or "").strip().lower() in ("pass", "passed", "ok")
        killed = (p.get("killed") is True) or (int(p.get("killed_count") or 0) > 0)
        verified = verdict in ("non-vacuous", "nonvacuous", "killed") and baseline_ok and killed
        if not verified:
            continue
        fn = p.get("function") or p.get("function_name") or path.stem
        src = str(p.get("file_line") or p.get("source_file") or p.get("source") or "")
        out.append({
            "function": fn,
            "file_line": src,
            "mutation_verified": True,
            "clean_result": "pass",
            "verdict": "killed",
            "genuine_verdict": verdict,
            "source": src,
            "file": src,
            "harness": p.get("harness") or path.name,
            "killed": True,
            "sidecar": str(path),
            "axis": "per-function",
        })
    return out


# ---------------------------------------------------------------------------
# Cross-function harness discovery + mutation run.
# ---------------------------------------------------------------------------
def _is_test_path(rel: str) -> bool:
    low = rel.lower()
    return any(h in low for h in _TEST_HINTS)


def _discover_cross_function_harnesses(ws: Path, language: str = "auto") -> list[Path]:
    """Find test/harness files in the workspace that LOOK cross-function
    (name hints at a round-trip / composition / conservation invariant). These
    are the artifacts we mutation-verify for the cross-function axis."""
    found: list[Path] = []
    seen: set[str] = set()
    for p in sorted(ws.rglob("*")):
        if not p.is_file():
            continue
        detected_lang = _LANG_BY_EXT.get(p.suffix)
        if detected_lang is None:
            continue
        if language != "auto" and detected_lang != language:
            continue
        parts = set(p.parts)
        # Allow .auditooor (generated harnesses live there) but prune vendored.
        if (parts & _SKIP_DIRS) - {".auditooor"}:
            continue
        try:
            rel = str(p.relative_to(ws))
        except ValueError:
            rel = str(p)
        rel_posix = rel.replace("\\", "/")
        if any(rel_posix.startswith(prefix + "/") for prefix in _GENERATED_NON_HARNESS_DIRS):
            continue
        if not _is_test_path(rel):
            continue
        low = rel.lower()
        if not any(h in low for h in _CROSS_FN_HINTS):
            continue
        if rel in seen:
            continue
        seen.add(rel)
        found.append(p)
    return found


def _toolchain_present_for(language: str) -> bool:
    import shutil

    if language == "solidity":
        return shutil.which("forge") is not None or shutil.which("halmos") is not None
    if language == "rust":
        return shutil.which("cargo") is not None
    if language == "go":
        return shutil.which("go") is not None
    # move / cairo: rely on an explicit runner; treat as absent for default run.
    return False


def _is_interface_like(p: Path) -> bool:
    """A Solidity interface / abstract-only file (function declarations with no
    bodies) is a poor mutation target - the oracle finds no mutable operators.
    Heuristic: path under /interfaces/ OR stem like I<Upper> OR <suffix>.sol body
    whose only function decls are `;`-terminated."""
    low = p.as_posix().lower()
    if "/interfaces/" in low or "/interface/" in low:
        return True
    stem = p.stem
    if p.suffix == ".sol" and len(stem) >= 2 and stem[0] == "I" and stem[1].isupper():
        return True
    return False


def _mutation_target_source_for(harness: Path, ws: Path) -> Path | None:
    """Best-effort: a cross-function harness mutates a referenced in-scope
    source file. Prefer a CONCRETE implementation file whose name shares a token
    with the harness; deprioritize interface/abstract-only files (no mutable
    body). Returns None when no concrete source is found (run skipped/recorded).
    The mutation oracle needs a concrete --source with a mutable function."""
    roots = [ws / "src", ws / "contracts", ws]
    base_tokens = {t.lower() for t in _split_ident(harness.stem) if len(t) > 2}
    token_concrete: Path | None = None
    token_iface: Path | None = None
    any_concrete: Path | None = None
    any_iface: Path | None = None
    for root in roots:
        if not root.is_dir():
            continue
        for p in sorted(root.rglob(f"*{harness.suffix}")):
            if not p.is_file():
                continue
            if _is_test_path(str(p)):
                continue
            parts = set(p.parts)
            if (parts & _SKIP_DIRS) - {".auditooor"}:
                continue
            # r36-rebuttal: bugfix-inventory-claude-20260610
            # Mirror the non-production path exclusion from _harness_driven_target
            # so both resolvers reject the same dirs.  Without this the fallback
            # selects src/certora/ helpers as any_concrete, producing a false-green
            # mutation_verified=True for the wrong file.
            sp = str(p).replace("\\", "/").lower()
            if any(x in sp for x in ("/certora/", "/mock", "/lib/",
                                      "/interfaces/", "/interface/",
                                      "/node_modules/", "/forge-std/")):
                continue
            iface = _is_interface_like(p)
            src_tokens = {t.lower() for t in _split_ident(p.stem)}
            shares = bool(base_tokens & src_tokens)
            if shares and not iface and token_concrete is None:
                token_concrete = p
            elif shares and iface and token_iface is None:
                token_iface = p
            elif not iface and any_concrete is None:
                any_concrete = p
            elif iface and any_iface is None:
                any_iface = p
    # Preference order: name-matched concrete > any concrete > name-matched
    # interface > any interface.
    return token_concrete or any_concrete or token_iface or any_iface


def _split_ident(name: str) -> list[str]:
    import re as _re
    # split camelCase + snake + non-alnum
    parts = _re.split(r"[^A-Za-z0-9]+", name)
    out: list[str] = []
    for p in parts:
        out.extend(_re.findall(r"[A-Z]+(?=[A-Z][a-z])|[A-Z]?[a-z]+|[A-Z]+|[0-9]+", p))
    return [o for o in out if o]


# r36-rebuttal: lane XFN-PRIORITIZE-REAL-HARNESS registered in .auditooor/agent_pathspec.json
# Cheat-codes / assertion helpers / framework calls that are NOT the function
# under test - excluded when inferring which protocol function a harness drives.
_CHEAT_OR_HELPER_CALLS = frozenset({
    "prank", "startprank", "stopprank", "deal", "expectrevert", "expectemit",
    "expectcall", "label", "warp", "roll", "assume", "bound", "log", "logstring",
    "addr", "makeaddr", "record", "accesses", "load", "store", "mockcall",
    "etch", "fee", "chainid", "coinbase", "prevrandao", "sign", "tostring",
    "envor", "setup", "run", "push", "pop", "length", "encode", "encodepacked",
    "decode", "abi", "keccak256", "max", "min", "concat", "wrap", "unwrap",
})


def _harness_driven_target(harness: Path, ws: Path, language: str):
    """Return (source_path, function_line) for the in-scope PROTOCOL function the
    harness most prominently DRIVES, parsed from its ``<instance>.<fn>(`` calls.

    The mutation oracle must mutate a function the harness actually exercises;
    the older name-token guess (``_mutation_target_source_for``) frequently falls
    back to the first concrete file it finds - e.g. a src/certora/ helper with no
    mutable operators - producing a spurious ``vacuous`` for a genuinely-binding
    harness. This resolver instead reads the harness body, extracts the called
    function names (minus cheatcodes/assertions), and picks the in-scope source
    (excluding certora/test/mock/lib/interface) that DEFINES the most of them.
    Generic across EVM workspaces. Returns (None, None) on no match (caller falls
    back to the legacy resolver)."""
    if language != "solidity":
        return None, None
    import re  # r36-rebuttal: lane XFN-PRIORITIZE-REAL-HARNESS registered
    try:
        text = harness.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return None, None
    called = {
        m.group(1).lower()
        for m in re.finditer(r"\.([A-Za-z_]\w*)\s*\(", text)
        if m.group(1).lower() not in _CHEAT_OR_HELPER_CALLS and len(m.group(1)) > 2
    }
    if not called:
        return None, None
    best = None  # (match_count, source_path, fn_line)
    for root in (ws / "src", ws / "contracts", ws):
        if not root.is_dir():
            continue
        for p in sorted(root.rglob("*.sol")):
            sp = str(p).replace("\\", "/").lower()
            if any(x in sp for x in ("/certora/", "/test/", "/tests/", "/mock",
                                     "/lib/", "/interfaces/", "/interface/",
                                     "/node_modules/", "/forge-std/")):
                continue
            if _is_interface_like(p):
                continue
            try:
                src_text = p.read_text(encoding="utf-8", errors="replace")
            except OSError:
                continue
            matches = 0
            first_line = None
            for fm in re.finditer(r"\bfunction\s+([A-Za-z_]\w*)\s*\(", src_text):
                if fm.group(1).lower() in called:
                    matches += 1
                    if first_line is None:
                        first_line = src_text[:fm.start()].count("\n") + 1
            if matches and (best is None or matches > best[0]):
                best = (matches, p, first_line)
    if best:
        return best[1], best[2]
    return None, None


def _run_cross_function_mutations(
    ws: Path, harnesses: list[Path], language: str, max_mutants: int,
    mutant_timeout: int, max_requirements: int,
) -> tuple[list[dict], str]:
    """Run mutation-verify-coverage on each discovered cross-function harness.
    Returns (records, status). Each record carries requirement/test/
    mutation_verified plus legacy fields. status in
    {ok, toolchain-absent, no-harnesses, oracle-absent}."""
    if not harnesses:
        return [], "no-harnesses"
    oracle = _load_module("mutation-verify-coverage.py", "_xfhp_mvc")
    if oracle is None or not hasattr(oracle, "verify"):
        return [], "oracle-absent"

    # r36-rebuttal: lane XFN-PRIORITIZE-REAL-HARNESS registered in .auditooor/agent_pathspec.json
    # Prioritize REAL authored composition harnesses over auto-generated vacuous
    # specs. The discovery returns harnesses in path-sorted order, so the
    # auto-generated per_function_invariants/Halmos_* specs (which model a
    # *correct* contract and pass on every mutant -> vacuous) sort BEFORE the
    # real XFn_*/composition harnesses and consume the whole max_requirements
    # budget, leaving the binding harnesses never mutation-verified (spurious
    # 0/N coverage). Sort key: real authored harnesses first (lower rank), known
    # auto-generated vacuous spec families last. Stable within each tier.
    def _harness_rank(p: Path) -> int:
        s = str(p).replace("\\", "/").lower()
        # auto-generated vacuous spec families (model-only, no real CUT drive)
        if "/per_function_invariants/" in s or "halmos_" in p.name.lower() \
                or "_halmosspec" in s or "_fuzzprops" in s:
            return 2
        # real authored composition harnesses (drive the deployed contract)
        if "/poc-tests/" in s and any(h in p.name.lower() for h in ("xfn", "xfn_", "roundtrip", "composition", "siblingpair")):
            return 0
        return 1
    harnesses = sorted(harnesses, key=lambda p: (_harness_rank(p), str(p)))

    records: list[dict] = []
    any_run = False
    for harness in harnesses[:max_requirements]:
        lang = _LANG_BY_EXT.get(harness.suffix) or (language if language != "auto" else "solidity")
        try:
            rel = str(harness.relative_to(ws))
        except ValueError:
            rel = str(harness)
        if not _toolchain_present_for(lang):
            records.append(_xfn_record(rel, "skipped",
                                        reason=f"toolchain absent for {lang}", verified=False))
            continue
        # Prefer the function the harness actually DRIVES (parsed from its calls)
        # so the mutation targets exercised code, not a name-guessed certora
        # helper. Fall back to the legacy name-token resolver.
        # r36-rebuttal: lane XFN-PRIORITIZE-REAL-HARNESS registered
        src, fn_line = _harness_driven_target(harness, ws, lang)
        if src is None:
            src = _mutation_target_source_for(harness, ws)
            if src is None:
                records.append(_xfn_record(rel, "skipped",
                                            reason="no in-scope source target found to mutate", verified=False))
                continue
            fn_name, fn_line = _first_function_in(src, lang)
            if fn_name is None:
                records.append(_xfn_record(rel, "skipped",
                                            reason=f"no mutable function found in {src.name}", verified=False))
                continue
        any_run = True
        harness_arg = _harness_command_for(harness, ws, lang)
        try:
            rec = oracle.verify(
                workspace=ws,
                source_file=src,
                # Pass file:LINE so the oracle uses its line_hint path (walks up
                # to the nearest decl) - more robust than name-matching, which
                # depends on the engine's per-language decl regex agreeing with
                # ours on multi-line signatures.
                function=f"{src}:{fn_line}",
                harness=harness_arg,
                language=lang,
                max_mutants=max_mutants,
                timeout=mutant_timeout,
            )
        except Exception as exc:  # noqa: BLE001
            records.append(_xfn_record(rel, "error", reason=f"oracle raised: {exc}", verified=False))
            continue
        verdict = str(rec.get("verdict") or "error").strip().lower()
        verified = verdict in ("non-vacuous",)
        records.append(_xfn_record(
            rel, verdict,
            reason=rec.get("reason"),
            verified=verified,
            source=f"{src}:{fn_line}",
            killed_count=rec.get("killed_count"),
            mutant_count=rec.get("mutant_count"),
        ))
    status = "ok" if any_run else "toolchain-absent"
    return records, status


def _aggregate_cross_function_sidecars(ws: Path) -> list[dict]:
    """Normalize existing cross-function mutation sidecars into canonical rows.

    These sidecars are produced by mutation-verify-coverage.py during manual or
    lane-driven harness work. They are valid accounting inputs only when the
    oracle shows a non-vacuous mutation kill. Vacuous, errored, and baseline
    failure rows remain visible to the source sidecar consumers but do not
    become verified canonical coverage.
    """
    sidecar_dir = ws / ".auditooor" / "cross-function-coverage"
    if not sidecar_dir.is_dir():
        return []
    out: list[dict] = []
    seen: set[tuple[str, str, str]] = set()
    for path in sorted(sidecar_dir.glob("mutation*.json")):
        if not path.is_file() or path.stat().st_size == 0:
            continue
        try:
            payload = json.loads(path.read_text(encoding="utf-8", errors="replace"))
        except (OSError, ValueError):
            continue
        verdict = str(payload.get("verdict") or "").strip().lower()
        killed_count = int(payload.get("killed_count") or 0)
        baseline = payload.get("baseline") if isinstance(payload.get("baseline"), dict) else {}
        baseline_status = str(baseline.get("status") or "").strip().lower()
        verified = verdict in ("non-vacuous", "nonvacuous", "killed") and killed_count > 0
        if not verified or baseline_status not in ("pass", "passed", "ok"):
            continue
        fn = payload.get("function") or payload.get("function_name") or payload.get("target_function")
        source_file = payload.get("source_file") or payload.get("source") or payload.get("file")
        source = str(source_file or "")
        span = payload.get("function_span") if isinstance(payload.get("function_span"), dict) else {}
        start_line = span.get("start_line")
        if source and start_line and ":" not in Path(source).name:
            source = f"{source}:{start_line}"
        harness = payload.get("harness") or payload.get("runner_command") or payload.get("test")
        key = (str(fn or ""), source, str(harness or ""))
        if key in seen:
            continue
        seen.add(key)
        out.append(_xfn_record(
            Path(path).stem,
            "non-vacuous",
            reason=payload.get("reason"),
            verified=True,
            source=source or None,
            killed_count=killed_count,
            mutant_count=payload.get("mutant_count"),
        ) | {
            "function": fn or Path(path).stem,
            "harness": harness or Path(path).name,
            "sidecar": str(path),
            "oracle_verdict": verdict,
        })
    return out


def _xfn_record(test: str, verdict: str, *, reason=None, verified: bool,
                source=None, killed_count=None, mutant_count=None) -> dict:
    return {
        # SHARED-CONTRACT cross-function fields:
        "requirement": Path(test).stem,
        "test": test,
        "mutation_verified": bool(verified),
        # legacy record fields. Emit the consumer's canonical token (killed /
        # vacuous / no-baseline / skipped / error) so the normalizer is never
        # tripped by the "non-vacuous"-contains-"vacuous" substring trap; keep
        # the raw oracle verdict under oracle_verdict.
        "verdict": _consumer_verdict_token(verdict, verified),
        "oracle_verdict": verdict,
        "harness": test,
        "function": Path(test).stem,
        "source": source,
        "killed": bool(verified),
        "reason": reason,
        "killed_count": killed_count,
        "mutant_count": mutant_count,
        "axis": "cross-function",
    }


def _consumer_verdict_token(verdict: str, verified: bool) -> str:
    """Map an oracle/genuine verdict + verified-flag to the consumer gates'
    canonical token set so _normalize_mut_verdict classifies it correctly."""
    v = (verdict or "").strip().lower()
    if v in ("no-baseline", "nobaseline", "no baseline"):
        return "no-baseline"
    if v in ("skipped", "no-property-discovered", "no property discovered"):
        # A typed silent-skip (the oracle ran but no property over the function
        # was ever observed): NOT killed, NOT a proven-vacuous executed result,
        # NOT a hard engine error. Surface it as a "skipped" token so it is
        # never credited as coverage and never mislabeled vacuous/error.
        return "skipped"
    if v in ("error",):
        return "error"
    return "killed" if verified else "vacuous"


_FN_RES = {
    "solidity": r"\bfunction\s+([A-Za-z_]\w*)\s*\(",
    "rust": r"\bfn\s+([A-Za-z_]\w*)\s*[<(]",
    "go": r"\bfunc\s*(?:\([^)]*\)\s*)?([A-Za-z_]\w*)\s*\(",
    "move": r"\bfun\s+([A-Za-z_]\w*)\s*[<(]",
    "cairo": r"\bfn\s+([A-Za-z_]\w*)\s*[<(]",
}


def _forge_bin() -> str:
    """Resolve forge via tools/lib/forge-resolve.sh if present, else PATH."""
    import subprocess
    resolver = _HERE / "lib" / "forge-resolve.sh"
    if resolver.is_file():
        try:
            out = subprocess.run(["bash", str(resolver)], capture_output=True,
                                 text=True, timeout=30)
            for line in (out.stdout or "").splitlines():
                line = line.strip()
                if line and Path(line).name == "forge" and Path(line).exists():
                    return line
        except Exception:  # noqa: BLE001
            pass
    import shutil
    return shutil.which("forge") or "forge"


def _foundry_root_for(harness: Path, ws: Path) -> Path:
    """Nearest ancestor dir of the harness that owns a foundry.toml; falls back
    to the workspace. Used as the cwd for `forge test`."""
    cur = harness.parent
    try:
        ws_res = ws.resolve()
    except OSError:
        ws_res = ws
    while True:
        if (cur / "foundry.toml").is_file():
            return cur
        if cur.resolve() == ws_res or cur.parent == cur:
            return ws
        cur = cur.parent


def _solidity_contract_name(harness: Path) -> str | None:
    """First `contract X` declared in a Solidity harness file."""
    try:
        for line in harness.read_text(encoding="utf-8", errors="ignore").splitlines():
            s = line.strip()
            if s.startswith("contract ") or s.startswith("abstract contract "):
                toks = s.split()
                idx = toks.index("contract")
                if idx + 1 < len(toks):
                    return toks[idx + 1].rstrip("{").split("(")[0].split(":")[0]
    except OSError:
        return None
    return None


def _harness_command_for(harness: Path, ws: Path, language: str) -> str:
    """Return the literal shell command the mutation oracle should run to
    exercise this cross-function harness. For Solidity, drive `forge test
    --match-contract <Contract>` from the harness's foundry root (cross-function
    harnesses are forge tests, not halmos property contracts). For other
    languages, hand the oracle the harness FILE path so it uses its per-language
    default runner (cargo test / go test)."""
    if language == "solidity":
        import shlex as _shlex

        contract = _solidity_contract_name(harness) or harness.stem
        root = _foundry_root_for(harness, ws)
        forge = _forge_bin()
        # The mutation oracle runs literal harness commands via subprocess WITHOUT
        # a shell (it shlex.splits the string), so a bare `cd X && forge ...`
        # would exec `cd` as a program. Wrap in `bash -lc` so the cd + && are
        # honored and forge runs in the foundry root.
        inner = f"cd {_shlex.quote(str(root))} && {_shlex.quote(forge)} test --match-contract {_shlex.quote(contract)}"
        return f"bash -lc {_shlex.quote(inner)}"
    return str(harness)


def _first_function_in(src: Path, language: str):
    """Return (function_name, line_1based) of the first mutable function (real
    body) in src, or (None, None) when none found."""
    import re as _re
    pat = _FN_RES.get(language)
    if not pat:
        return None, None
    try:
        text = src.read_text(encoding="utf-8", errors="replace")
    except (OSError, UnicodeError):
        return None, None
    skip = {"constructor", "receive", "fallback", "main", "init", "test", "setUp"}
    for m in _re.finditer(pat, text):
        name = m.group(1)
        if name.lower() in skip or name.lower().startswith("test"):
            continue
        # Prefer a function with a real BODY ({...}) over a declaration-only
        # (interface `;`-terminated) signature, so the mutation oracle has
        # mutable operators to work with.
        tail = text[m.end():m.end() + 400]
        brace = tail.find("{")
        semi = tail.find(";")
        if semi != -1 and (brace == -1 or semi < brace):
            continue  # declaration-only; skip
        line = text.count("\n", 0, m.start()) + 1
        return name, line
    return None, None


# ---------------------------------------------------------------------------
# Cross-function dispatch brief (pending requirements -> agentic build).
# ---------------------------------------------------------------------------
def _emit_cross_function_brief(ws: Path, status: str) -> Path | None:
    """When no cross-function harness exists, emit the agentic-build brief and
    enumerate the cross-function requirements (via the sibling enumerator) so
    a worker knows exactly which composition invariants need a harness."""
    enumerator = _load_module("cross-function-invariant-coverage.py", "_xfhp_xfi")
    requirements: list[dict] = []
    if enumerator is not None and hasattr(enumerator, "evaluate"):
        try:
            res = enumerator.evaluate(ws)
            requirements = res.get("requirements") or []
        except Exception:  # noqa: BLE001
            requirements = []
    brief = {
        "schema": "auditooor.cross_function_harness_dispatch_brief.v1",
        "generated_at": _utc_now(),
        "workspace": str(ws),
        "status": status,
        "mission": (
            "Write a MUTATION-VERIFIED test for each cross-function / round-trip "
            "/ state-machine invariant below. A test is genuine ONLY if "
            "tools/mutation-verify-coverage.py classifies it non-vacuous (it "
            "FAILS on >=1 injected mutant of a function in the requirement)."
        ),
        "requirements": requirements,
        "definition_of_done": (
            "Re-run tools/cross-function-harness-producer.py; the canonical "
            "mutation_verify_coverage.json shows mutation_verified=true for each "
            "cross_function requirement, OR each residual carries a source-cited "
            "ruled-out reason."
        ),
        "steps": [
            "For each requirement, write a test exercising ALL its functions together.",
            "Assert the composition/round-trip/conservation invariant.",
            "Run tools/mutation-verify-coverage.py against it; iterate until non-vacuous.",
            "Re-run this producer to refresh the canonical file.",
        ],
    }
    out_dir = ws / ".auditooor" / "cross-function-coverage"
    try:
        out_dir.mkdir(parents=True, exist_ok=True)
        out_path = out_dir / "dispatch_brief.json"
        out_path.write_text(json.dumps(brief, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        return out_path
    except OSError:
        return None


# ---------------------------------------------------------------------------
# Produce the canonical file.
# ---------------------------------------------------------------------------
def produce(
    ws,
    *,
    language: str = "auto",
    max_mutants: int = 6,
    mutant_timeout: int = 300,
    max_requirements: int = 40,
    emit_brief_only: bool = False,
) -> dict:
    ws = Path(ws)
    if not ws.exists() or not ws.is_dir():
        return {"schema": SCHEMA, "verdict": "error",
                "reason": f"workspace not a directory: {ws}"}

    # (1) per-function aggregation: genuine_coverage_manifest verdicts UNION the
    # durable mvc_sidecar/ mutation-kills (the latter were orphaned - no aggregator
    # read that dir, so genuine per-fn kills earned 0 credit). Dedup by (function,
    # source); a sidecar-backed verified record supersedes an unverified manifest row.
    manifest = _read_genuine_manifest(ws)
    _pf_manifest = _aggregate_per_function(manifest)
    _pf_sidecar = _aggregate_mvc_sidecars(ws)
    _pf_by_key: dict[tuple, dict] = {}
    for rec in _pf_manifest + _pf_sidecar:
        k = (str(rec.get("function") or ""), str(rec.get("source") or ""))
        prev = _pf_by_key.get(k)
        # keep the verified record when there is a conflict
        if prev is None or (rec.get("mutation_verified") and not prev.get("mutation_verified")):
            _pf_by_key[k] = rec
    per_function = list(_pf_by_key.values())
    per_function_status = "ok" if (manifest is not None or _pf_sidecar) else "no-genuine-manifest"

    # (2) cross-function axis.
    cross_function: list[dict] = []
    cross_status = "no-harnesses"
    brief_path = None
    if emit_brief_only:
        brief_path = _emit_cross_function_brief(ws, "brief-only")
        cross_status = "brief-only"
    else:
        harnesses = _discover_cross_function_harnesses(ws, language)
        if harnesses:
            cross_function, cross_status = _run_cross_function_mutations(
                ws, harnesses, language, max_mutants, mutant_timeout, max_requirements
            )
        else:
            cross_function = _aggregate_cross_function_sidecars(ws)
            brief_path = _emit_cross_function_brief(ws, "no-cross-function-harness")
            cross_status = (
                "sidecar-evidence-imported"
                if cross_function else "no-harnesses-brief-emitted"
            )

    # (3) build the canonical payload.
    pf_verified = sum(1 for r in per_function if r.get("mutation_verified"))
    xf_verified = sum(1 for r in cross_function if r.get("mutation_verified"))
    counts = {
        "per_function_total": len(per_function),
        "per_function_verified": pf_verified,
        "cross_function_total": len(cross_function),
        "cross_function_verified": xf_verified,
    }
    verdicts = list(per_function) + list(cross_function)
    payload = {
        "schema": SCHEMA,
        "generated_at": _utc_now(),
        "run_id": os.environ.get("AUDITOOOR_AUDIT_RUN_FULL_ID") or None,
        "workspace": str(ws),
        "language": language,
        "per_function": per_function,
        "cross_function": cross_function,
        # flattened list the consumers' _records_from_payload iterates:
        "verdicts": verdicts,
        "counts": counts,
        "per_function_status": per_function_status,
        "cross_function_status": cross_status,
        "cross_function_dispatch_brief": str(brief_path) if brief_path else None,
        "summary": (
            f"per-function {pf_verified}/{len(per_function)} mutation-verified; "
            f"cross-function {xf_verified}/{len(cross_function)} mutation-verified "
            f"({cross_status})"
        ),
    }
    return payload


def _write_canonical(ws: Path, payload: dict, out_path: Path | None = None) -> Path:
    if out_path is None:
        out_path = ws / ".auditooor" / "mutation_verify_coverage.json"
    out_dir = out_path.parent
    out_dir.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return out_path


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(
        description="Produce the canonical mutation_verify_coverage.json (per-"
                    "function + cross-function) that the L37 coverage gates read.")
    ap.add_argument("--workspace", required=True, help="audit workspace path")
    ap.add_argument("--language", "--lang", dest="language", default="auto",
                    choices=["auto", "solidity", "rust", "go", "move", "cairo"])
    ap.add_argument("--out", default=None,
                    help="compatibility alias for the canonical output path")
    ap.add_argument("--project-root", default=None,
                    help="accepted for Makefile compatibility; workspace remains the audit workspace")
    ap.add_argument("--strict", action="store_true",
                    help="accepted for wrapper compatibility; consumers decide pass or fail")
    ap.add_argument("--max-mutants", type=int, default=6, help="cap mutants per cross-function harness")
    ap.add_argument("--mutant-timeout", type=int, default=300, help="per-run timeout seconds")
    ap.add_argument("--max-requirements", type=int, default=40,
                    help="cap cross-function harnesses to mutation-verify")
    ap.add_argument("--emit-brief-only", action="store_true",
                    help="only emit the cross-function dispatch brief; do not run mutations")
    ap.add_argument("--json", action="store_true", help="emit full JSON payload")
    args = ap.parse_args(argv)

    ws = Path(args.workspace).expanduser()
    payload = produce(
        ws,
        language=args.language,
        max_mutants=args.max_mutants,
        mutant_timeout=args.mutant_timeout,
        max_requirements=args.max_requirements,
        emit_brief_only=args.emit_brief_only,
    )
    if payload.get("verdict") == "error":
        print(f"[{GATE}] ERROR {payload.get('reason')}", file=sys.stderr)
        if args.json:
            print(json.dumps(payload, indent=2, sort_keys=True))
        return 2

    out_arg = Path(args.out).expanduser() if args.out else None
    out_path = _write_canonical(ws, payload, out_arg)
    payload["canonical_path"] = str(out_path)
    if args.json:
        print(json.dumps(payload, indent=2, sort_keys=True))
    else:
        print(f"[{GATE}] wrote {out_path}")
        print(f"[{GATE}] {payload['summary']}")
        if payload.get("cross_function_dispatch_brief"):
            print(f"[{GATE}] cross-function dispatch brief: {payload['cross_function_dispatch_brief']}")

    # R80/R81 hollow-engine signal: if 0 genuine harnesses were mutation-verified
    # but the workspace generated >0 (scaffold-only / vacuous pass), emit an
    # UNMISSABLE banner to stderr and write a marker file so the operator cannot
    # miss that the deep layer ran scaffold-only.  Advisory: does not affect rc.
    _pf_verified = payload.get("counts", {}).get("per_function_verified", 0) or 0
    _xf_verified = payload.get("counts", {}).get("cross_function_verified", 0) or 0
    _total_genuine = _pf_verified + _xf_verified
    _pf_total = len(payload.get("per_function") or [])
    _xf_total = len(payload.get("cross_function") or [])
    _total_generated = _pf_total + _xf_total
    if _total_genuine == 0 and _total_generated > 0:
        _flag_path = ws / ".auditooor" / "DEEP_AUDIT_HOLLOW.flag"
        _flag_lines = [
            "scaffold-only: 0 genuine mutation-verified harnesses",
            "out of %d generated (per_function=%d, cross_function=%d)" % (
                _total_generated, _pf_total, _xf_total),
            "workspace: %s" % ws,
            "summary: %s" % payload.get("summary", "n/a"),
            "next step: run make genuine-coverage WS=<ws> and fill in"
            " non-vacuous invariant assertions",
            "",
        ]
        try:
            _flag_path.write_text("\n".join(_flag_lines), encoding="utf-8")
        except OSError:
            pass
        _banner = "!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!"
        _msg_lines = [
            "",
            _banner,
            "[DEEP-AUDIT-HOLLOW] deep engines ran SCAFFOLD-ONLY / 0 genuine",
            "  0 / %d generated harnesses are mutation-verified genuine" % _total_generated,
            "  This workspace is NOT genuinely deep-audited.",
            "  Marker written: %s" % _flag_path,
            "  Next step: make genuine-coverage WS=%s" % ws,
            "             Fill each harness with a SOURCE-GROUNDED assertion",
            "             that FAILS on at least one injected mutant.",
            _banner,
            "",
        ]
        print("\n".join(_msg_lines), file=sys.stderr)

    return 0


if __name__ == "__main__":
    sys.exit(main())
