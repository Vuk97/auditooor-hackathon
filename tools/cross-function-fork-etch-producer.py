#!/usr/bin/env python3
"""cross-function-fork-etch-producer.py - GENERIC fork+etch mutation-verified
cross-function harness producer for live Diamond / L2 workspaces.

WHY THIS MODE EXISTS (the source-recompile producer gets 0/N on bean)
---------------------------------------------------------------------
``cross-function-harness-producer.py`` mutation-verifies a harness by RECOMPILING
the source and RE-RUNNING the harness in-process. That works when the function
pair is exercisable from a freshly deployed contract. It gets 0/113 on Beanstalk
because the in-scope facets:
  (a) read LIVE Diamond storage a from-scratch deploy cannot reconstruct, and
  (b) link external libraries by ``delegatecall``.
The ONLY mechanic proven to kill a bean cross-function mutant is FORK + ``vm.etch``
over the live Diamond (``chimera_harnesses/XfnForkFeasibility``: 5/5 pass, clean
PASS -> mutant FAIL on the live Arbitrum fork).

This tool generifies that proven recipe so the same fork+etch path closes the
cross-function gate for ANY Diamond/L2 workspace, NOT just bean. It is the
``--fork-etch`` MODE for the cross-function gate (kept as a separate tool so the
in-process source-recompile producer is untouched and non-regressing).

WHAT IT DOES (per requirement, mechanically)
--------------------------------------------
1. Reads the workspace fork config (``.auditooor/fork_rpc_url.txt``: RPC env,
   DIAMOND, facet, token) and a per-workspace RECIPE REGISTRY
   (``.auditooor/fork_etch_recipes.json``). The recipe ties a cross-function
   REQUIREMENT LABEL to: the foundry root, the facet source to (re)build with
   ``--evm-version paris``, the ONE-LINE mutation anchor (Step-4b human input),
   the external libs to dump, and the authored differential harness + test.
2. (Re)BUILDS clean + mutant deployedBytecode from the PINNED source via
   ``forge build --evm-version <paris>``, then OFFLINE-LINKS the external-library
   placeholders to fixed fork addresses using the GENERIC linker
   (``tools/lib/fork_etch_link.py``) - the same byte-surgery the proven one-off
   did, now reusable + unit-tested. The mutated source is RESTORED byte-for-byte
   (git diff stays clean).
3. RUNS the authored fork+etch differential test. ``mutation_verified=true`` is
   written ONLY when the test reports a REAL clean-PASS -> mutant-FAIL flip
   (``test_03c_differential_*`` style). A non-flip / vacuous invariant records
   ``mutation_verified=false``.
4. WRITES canonical ``mutation_verify_coverage.json`` cross_function entries in
   the SAME shared-contract schema the gate reads (reuses the sibling producer's
   ``_xfn_record`` so both axes interleave cleanly), merging with any existing
   per-function rows already in the file.

HONESTY (un-fakeable)
---------------------
- ``mutation_verified=true`` is written ONLY on a real observed flip parsed from
  forge output. Never hand-written; never inferred from file presence.
- The CUT is the REAL pinned source recompiled (paris) + etched on the live
  fork; the mutant is a one-line source mutation, rebuilt + relinked, restored.
- Requirements WITHOUT a recipe are recorded ``pending`` (fail-closed): the gate
  stays reachable, never vacuously green.
- Offline-safe: missing forge / missing RPC / missing recipe -> recorded skip,
  never a silent PASS.

CLI
---
    python3 tools/cross-function-fork-etch-producer.py --workspace <ws> \
        [--evm-version paris] [--only <requirement-label>] \
        [--rebuild-bytecode] [--timeout S] [--json] [--dry-run]

Exit code: 0 on a successful write; 2 on unreadable workspace / internal error.
Dependency-free (stdlib + the local fork_etch_link lib). Never commits.
"""
from __future__ import annotations

import argparse
import importlib.util
import json
import os
import re
import shlex
import shutil
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

_HERE = Path(__file__).resolve().parent
SCHEMA = "auditooor.mutation_verify_coverage.v1"
GATE = "XFN-FORK-ETCH-PRODUCER"

# ---------------------------------------------------------------------------
# Reuse the generic linker + the sibling producer's canonical record builder
# (tool-dedup charter: never re-implement the link surgery or the record shape).
# ---------------------------------------------------------------------------
sys.path.insert(0, str(_HERE / "lib"))
import fork_etch_link as fxl  # noqa: E402


def _load_sibling_producer():
    tool = _HERE / "cross-function-harness-producer.py"
    if not tool.is_file():
        return None
    spec = importlib.util.spec_from_file_location("_xfep_sibling", str(tool))
    if spec is None or spec.loader is None:
        return None
    mod = importlib.util.module_from_spec(spec)
    sys.modules["_xfep_sibling"] = mod
    try:
        spec.loader.exec_module(mod)
    except Exception:  # noqa: BLE001
        return None
    return mod


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


# ---------------------------------------------------------------------------
# Fork config + recipe registry.
# ---------------------------------------------------------------------------
def parse_fork_config(ws: Path) -> dict:
    """Parse ``.auditooor/fork_rpc_url.txt`` (KEY=VALUE lines, '#'-comments).
    Returns a dict with at least RPC url + DIAMOND when present. Tolerant of the
    bean format (ARBITRUM_RPC / DIAMOND / SiloFacet / BEAN)."""
    cfg: dict = {}
    p = ws / ".auditooor" / "fork_rpc_url.txt"
    if not p.is_file():
        return cfg
    for raw in p.read_text(encoding="utf-8", errors="replace").splitlines():
        line = raw.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        k, _, v = line.partition("=")
        cfg[k.strip()] = v.strip()
    return cfg


def fork_rpc_url(cfg: dict) -> str | None:
    """First value whose key ends in _RPC (e.g. ARBITRUM_RPC), else any RPC-ish
    https URL."""
    for k, v in cfg.items():
        if k.upper().endswith("_RPC") and v.startswith(("http://", "https://")):
            return v
    for v in cfg.values():
        if v.startswith(("http://", "https://")):
            return v
    return None


def read_recipes(ws: Path) -> list[dict]:
    """Read the per-workspace fork-etch recipe registry. Each recipe binds a
    cross-function REQUIREMENT label to the build+harness inputs needed to
    mutation-verify it via fork+etch.

    Recipe schema (one object per requirement)::

        {
          "requirement": "deposit|withdraw@silo/SiloFacet",
          "foundry_root": "src/beanstalk/protocol",      # cwd for forge build
          "harness_root": "chimera_harnesses/XfnForkFeasibility",  # cwd for forge test
          "facet_source": "contracts/.../SiloFacet.sol", # --contracts target
          "facet_artifact": "out/SiloFacet.sol/SiloFacet.json",
          "evm_version": "paris",
          "libraries": ["LibSilo","LibSiloPermit","LibTokenSilo"],
          "mutation": {
             "file": "contracts/.../TokenSilo.sol",
             "anchor": "<exact source line to drop/replace>",
             "replacement": "<optional; default = comment-out the anchor>"
          },
          "out_dir": "mutants",   # relative to harness_root; where hex is written
          "clean_hex": "mutants/SiloFacet_clean_linked.hex",
          "mutant_hex": "mutants/SiloFacet_mutant_linked.hex",
          "lib_hex": {"LibSilo":"mutants/LibSilo.deployed.hex", ...},
          "rpc_env": "ARB_RPC",
          "differential_test": "test_03c_differential_clean_vs_mutant",
          "match_contract": "XfnForkFeasibility"
        }
    """
    p = ws / ".auditooor" / "fork_etch_recipes.json"
    if not p.is_file() or p.stat().st_size == 0:
        return []
    try:
        data = json.loads(p.read_text(encoding="utf-8", errors="replace"))
    except (OSError, ValueError):
        return []
    if isinstance(data, dict):
        data = data.get("recipes") or []
    return [r for r in data if isinstance(r, dict)]


# ---------------------------------------------------------------------------
# forge resolution (reuse the canonical resolver).
# ---------------------------------------------------------------------------
def forge_bin() -> str | None:
    resolver = _HERE / "lib" / "forge-resolve.sh"
    if resolver.is_file():
        try:
            out = subprocess.run(["bash", "-c", f"source {shlex.quote(str(resolver))} && echo $FORGE_BIN"],
                                 capture_output=True, text=True, timeout=30)
            cand = (out.stdout or "").strip().splitlines()
            for line in cand:
                line = line.strip()
                if line and Path(line).name == "forge" and Path(line).exists():
                    return line
        except Exception:  # noqa: BLE001
            pass
    return shutil.which("forge")


# ---------------------------------------------------------------------------
# Build clean + mutant linked deployedBytecode (the generified build_mutants.sh).
# ---------------------------------------------------------------------------
def _resolve(root: Path, rel) -> Path:
    rp = Path(rel)
    return rp if rp.is_absolute() else (root / rp)


def build_linked_bytecode(ws: Path, recipe: dict, forge: str, evm_version: str,
                          timeout: int, dry_run: bool) -> dict:
    """Recompile clean + mutant facet (paris), offline-link external libs to
    fixed fork addresses via the GENERIC linker, write the hex files the harness
    etches, RESTORE the mutated source. Returns a status dict; raises nothing -
    failures are reported in the dict so the caller records a typed skip."""
    foundry_root = _resolve(ws, recipe["foundry_root"])
    harness_root = _resolve(ws, recipe.get("harness_root", recipe["foundry_root"]))
    facet_source = recipe["facet_source"]
    facet_artifact = _resolve(foundry_root, recipe["facet_artifact"])
    out_dir = _resolve(harness_root, recipe.get("out_dir", "mutants"))
    lib_names = recipe.get("libraries") or []
    lib_addrs = fxl.assign_lib_addresses(lib_names) if lib_names else {}

    mut = recipe.get("mutation") or {}
    mut_file = _resolve(foundry_root, mut["file"]) if mut.get("file") else None
    anchor = mut.get("anchor")
    replacement = mut.get("replacement")

    status = {"foundry_root": str(foundry_root), "evm_version": evm_version,
              "lib_addrs": lib_addrs, "built": False}

    if dry_run:
        status["dry_run"] = True
        return status
    if not foundry_root.is_dir() or not (foundry_root / "foundry.toml").is_file():
        status["error"] = f"foundry root not found: {foundry_root}"
        return status
    if not mut_file or not mut_file.is_file() or not anchor:
        status["error"] = "recipe missing a valid mutation.{file,anchor}"
        return status

    out_dir.mkdir(parents=True, exist_ok=True)

    def _forge_build():
        cmd = [forge, "build", "--evm-version", evm_version,
               "--contracts", facet_source]
        return subprocess.run(cmd, cwd=str(foundry_root), capture_output=True,
                              text=True, timeout=timeout)

    # ---- 1. CLEAN build + link + dump libs ----
    r0 = _forge_build()
    if r0.returncode != 0:
        status["error"] = f"clean build failed: {(r0.stderr or r0.stdout)[-400:]}"
        return status
    if not facet_artifact.is_file():
        status["error"] = f"clean artifact not found: {facet_artifact}"
        return status
    try:
        clean_linked = fxl.link_artifact(facet_artifact, lib_addrs)
    except ValueError as exc:
        status["error"] = f"clean link failed: {exc}"
        return status
    clean_hex_path = _resolve(harness_root, recipe.get("clean_hex", out_dir / "facet_clean_linked.hex"))
    clean_hex_path.write_text(clean_linked, encoding="utf-8")
    status["clean_hex"] = str(clean_hex_path)

    # dump each library's own deployedBytecode to the hex the harness etches.
    lib_hex_map = recipe.get("lib_hex") or {}
    for lib in lib_names:
        art = _find_artifact(foundry_root, lib)
        if art is None:
            status["error"] = f"library artifact not found for {lib}"
            return status
        try:
            lib_bc = fxl.dump_library_bytecode(art)
        except ValueError as exc:
            status["error"] = f"library {lib} dump failed: {exc}"
            return status
        dst = _resolve(harness_root, lib_hex_map.get(lib, out_dir / f"{lib}.deployed.hex"))
        dst.write_text(lib_bc, encoding="utf-8")

    # ---- 2. MUTANT build + link (restore source in finally) ----
    pristine = mut_file.read_text(encoding="utf-8")
    if pristine.count(anchor) != 1:
        status["error"] = (f"mutation anchor not unique in {mut_file.name} "
                           f"(count={pristine.count(anchor)})")
        return status
    new_line = replacement if replacement is not None else (
        "// XFN-MUTANT dropped: " + anchor.strip())
    try:
        mut_file.write_text(pristine.replace(anchor, new_line, 1), encoding="utf-8")
        r1 = _forge_build()
        if r1.returncode != 0:
            status["error"] = f"mutant build failed: {(r1.stderr or r1.stdout)[-400:]}"
            return status
        try:
            mutant_linked = fxl.link_artifact(facet_artifact, lib_addrs)
        except ValueError as exc:
            status["error"] = f"mutant link failed: {exc}"
            return status
        mutant_hex_path = _resolve(harness_root, recipe.get("mutant_hex", out_dir / "facet_mutant_linked.hex"))
        mutant_hex_path.write_text(mutant_linked, encoding="utf-8")
        status["mutant_hex"] = str(mutant_hex_path)
    finally:
        # ALWAYS restore the source byte-for-byte (git diff clean).
        mut_file.write_text(pristine, encoding="utf-8")

    # honesty self-check: clean != mutant (a no-op mutation cannot kill).
    if status.get("clean_hex") and status.get("mutant_hex"):
        if clean_hex_path.read_text() == mutant_hex_path.read_text():
            status["error"] = "mutant bytecode identical to clean (anchor had no effect)"
            return status
    status["built"] = True
    status["source_restored"] = (mut_file.read_text(encoding="utf-8") == pristine)
    return status


def _find_artifact(foundry_root: Path, name: str) -> Path | None:
    """Locate <name>.json under the foundry out/ dir."""
    out = foundry_root / "out"
    if not out.is_dir():
        return None
    for p in out.rglob(f"{name}.json"):
        if p.is_file():
            return p
    return None


# ---------------------------------------------------------------------------
# BINDING + IDENTITY checks (false-green resistance).
#
# Two ways the producer could be tricked into crediting a kill that the recipe's
# bytecode did NOT actually cause:
#   (B) DECOUPLED HARNESS: the recipe builds clean/mutant hex to path P, but the
#       differential test hardcodes a DIFFERENT path Q (e.g. pre-built kill hex
#       from a prior run). The test PASSES on Q's real kill while P is never
#       etched -> false-green for P's (possibly no-op) mutation.
#   (I) NO-OP MUTATION: a comment-only anchor change yields IDENTICAL bytecode;
#       clean==mutant cannot flip anything. (Also caught at build time, but we
#       re-check here so reused-existing-hex is covered too.)
# Both are fail-closed: the requirement is recorded as an error (NOT credited).
# ---------------------------------------------------------------------------
def check_binding_and_identity(ws: Path, recipe: dict) -> dict:
    """Verify the differential harness ACTUALLY etches the recipe's clean/mutant
    (and lib) hex, and that clean != mutant. Returns {ok: bool, reason: str}."""
    harness_root = _resolve(ws, recipe.get("harness_root", recipe.get("foundry_root", ".")))
    clean_rel = recipe.get("clean_hex")
    mutant_rel = recipe.get("mutant_hex")
    if not clean_rel or not mutant_rel:
        return {"ok": False, "reason": "recipe missing clean_hex/mutant_hex paths"}
    clean_path = _resolve(harness_root, clean_rel)
    mutant_path = _resolve(harness_root, mutant_rel)
    if not clean_path.is_file() or not mutant_path.is_file():
        return {"ok": False, "reason": "clean/mutant hex not on disk (build did not run?)"}

    # (I) identity: clean must differ from mutant.
    if clean_path.read_text(encoding="utf-8").strip() == mutant_path.read_text(encoding="utf-8").strip():
        return {"ok": False,
                "reason": "clean hex == mutant hex (no-op mutation; cannot kill)"}

    # (B) binding: the harness sources must reference BOTH recipe hex paths (the
    # exact relative strings the recipe declares), so the test etches what the
    # producer built - not unrelated pre-built hex.
    harness_texts = _harness_source_texts(harness_root, recipe)
    if harness_texts is None:
        return {"ok": False, "reason": "no harness sources found to verify binding"}
    blob = "\n".join(harness_texts)
    refs = _referenced_hex_paths(blob)
    # Compare by basename + relative tail so "mutants/X.hex" in the recipe matches
    # vm.readFile("mutants/X.hex") in the harness regardless of cwd nuances.
    want = {_norm_hex_ref(clean_rel), _norm_hex_ref(mutant_rel)}
    have = {_norm_hex_ref(r) for r in refs}
    missing = sorted(want - have)
    if missing:
        return {"ok": False,
                "reason": (f"differential harness does NOT etch the recipe's hex "
                           f"{missing} (it reads {sorted(have)}); build is DECOUPLED "
                           f"from the test -> a PASS would not be caused by the "
                           f"recipe's mutation")}
    return {"ok": True, "reason": "harness etches recipe clean+mutant hex; clean!=mutant"}


def _norm_hex_ref(ref: str) -> str:
    """Normalize a hex path reference to its workspace-relative tail (basename +
    one parent dir) so recipe vs harness references compare cleanly."""
    parts = Path(ref).parts
    return "/".join(parts[-2:]) if len(parts) >= 2 else parts[-1]


# Any ".hex" string literal in the harness source is binding evidence: the path
# may reach vm.readFile directly (vm.readFile("X.hex")) OR via a helper call
# (e.g. _etchFacet("X.hex") -> vm.readFile(hexFile)). Both mean the harness
# etches that hex, so we match the literal anywhere, not only inside readFile(.
_HEX_REF_RE = re.compile(r"""["']([^"']+\.hex)["']""")


def _referenced_hex_paths(blob: str) -> list[str]:
    return _HEX_REF_RE.findall(blob)


def _harness_source_texts(harness_root: Path, recipe: dict) -> list[str] | None:
    """Collect the Solidity test source(s) for the requirement's differential
    harness. Prefer files whose contract matches recipe.match_contract; fall back
    to all .t.sol / test .sol under the harness root."""
    contract = recipe.get("match_contract")
    texts: list[str] = []
    test_dirs = [harness_root / "test", harness_root / "tests", harness_root]
    seen: set[Path] = set()
    for d in test_dirs:
        if not d.is_dir():
            continue
        for p in sorted(d.rglob("*.sol")):
            if p in seen or not p.is_file():
                continue
            seen.add(p)
            try:
                t = p.read_text(encoding="utf-8", errors="replace")
            except OSError:
                continue
            if contract and f"contract {contract}" not in t and f"is {contract}" not in t \
                    and f"abstract contract {contract}" not in t:
                # keep non-matching files too (base contract may hold the readFile
                # calls), but only if they look like a harness/base.
                if "vm.etch" not in t and "readFile" not in t:
                    continue
            texts.append(t)
    return texts or None


# ---------------------------------------------------------------------------
# Run the authored fork+etch differential test; parse a REAL flip.
# ---------------------------------------------------------------------------
_PASS_RE = re.compile(r"^\s*\[PASS\]\s+(\S+?)\s*\(", re.M)
_FAIL_RE = re.compile(r"^\s*\[FAIL[:\]]", re.M)
_SUITE_RE = re.compile(r"(\d+)\s+passed;\s+(\d+)\s+failed", re.I)


def run_differential(ws: Path, recipe: dict, forge: str, rpc_url: str,
                     timeout: int) -> dict:
    """Run the authored fork+etch DIFFERENTIAL test and decide a REAL kill.

    A kill (mutation_verified=true) requires the differential test to PASS: that
    test internally asserts clean=HOLD and mutant=BREAK in one run, so its PASS
    is the observed flip. We additionally require the suite to report 0 failures.
    Any other outcome -> mutation_verified=false with a typed reason.
    """
    harness_root = _resolve(ws, recipe.get("harness_root", recipe["foundry_root"]))
    rpc_env = recipe.get("rpc_env", "ARB_RPC")
    test = recipe.get("differential_test")
    match_contract = recipe.get("match_contract")
    cmd = [forge, "test"]
    if match_contract:
        cmd += ["--match-contract", match_contract]
    if test:
        cmd += ["--match-test", test]
    cmd += ["-vv"]
    env = dict(os.environ)
    env[rpc_env] = rpc_url
    try:
        proc = subprocess.run(cmd, cwd=str(harness_root), capture_output=True,
                              text=True, timeout=timeout, env=env)
    except subprocess.TimeoutExpired:
        return {"flip": False, "reason": f"differential test timed out after {timeout}s"}
    out = (proc.stdout or "") + "\n" + (proc.stderr or "")
    passed = set(_PASS_RE.findall(out))
    has_fail = bool(_FAIL_RE.search(out))
    suite = _SUITE_RE.search(out)
    n_pass = int(suite.group(1)) if suite else len(passed)
    n_fail = int(suite.group(2)) if suite else (1 if has_fail else 0)
    # The differential test name (if specified) must be among the PASS set and
    # there must be ZERO failures.
    test_passed = (test in passed) if test else (n_pass > 0 and n_fail == 0)
    flip = bool(test_passed and n_fail == 0 and not has_fail and proc.returncode == 0)
    return {
        "flip": flip,
        "reason": (f"differential PASS ({n_pass} passed, {n_fail} failed)"
                   if flip else
                   f"NO flip (rc={proc.returncode}, {n_pass} passed, {n_fail} failed, "
                   f"has_fail={has_fail})"),
        "passed_tests": sorted(passed),
        "n_pass": n_pass,
        "n_fail": n_fail,
        "tail": out[-1200:],
    }


# ---------------------------------------------------------------------------
# Per-requirement orchestration.
# ---------------------------------------------------------------------------
def process_requirement(ws: Path, recipe: dict, *, forge: str | None,
                        rpc_url: str | None, evm_version: str, timeout: int,
                        rebuild: bool, dry_run: bool) -> dict:
    label = recipe.get("requirement") or recipe.get("label") or recipe.get("match_contract") or "unknown"
    rec_base = {"requirement": label}
    if forge is None:
        return {**rec_base, "verdict": "skipped", "mutation_verified": False,
                "reason": "forge toolchain absent"}
    if rpc_url is None:
        return {**rec_base, "verdict": "skipped", "mutation_verified": False,
                "reason": "no fork RPC url in .auditooor/fork_rpc_url.txt"}

    harness_root = _resolve(ws, recipe.get("harness_root", recipe.get("foundry_root", ".")))
    clean_hex = _resolve(harness_root, recipe.get("clean_hex", "")) if recipe.get("clean_hex") else None
    mutant_hex = _resolve(harness_root, recipe.get("mutant_hex", "")) if recipe.get("mutant_hex") else None
    have_hex = bool(clean_hex and mutant_hex and clean_hex.is_file() and mutant_hex.is_file())

    build_status = None
    if rebuild or not have_hex:
        build_status = build_linked_bytecode(ws, recipe, forge, evm_version, timeout, dry_run)
        if dry_run:
            return {**rec_base, "verdict": "dry-run", "mutation_verified": False,
                    "reason": "dry-run: would build+link+run", "build": build_status}
        if build_status.get("error"):
            return {**rec_base, "verdict": "error", "mutation_verified": False,
                    "reason": f"bytecode build/link failed: {build_status['error']}",
                    "build": build_status}

    if dry_run:
        return {**rec_base, "verdict": "dry-run", "mutation_verified": False,
                "reason": "dry-run: hex present, would run differential"}

    # FALSE-GREEN GUARD: the differential harness must actually etch the recipe's
    # clean+mutant hex (binding), and clean must differ from mutant (no no-op).
    # Otherwise a harness PASS could be caused by unrelated pre-built kill hex.
    bind = check_binding_and_identity(ws, recipe)
    if not bind["ok"]:
        return {**rec_base, "verdict": "error", "mutation_verified": False,
                "reason": f"binding/identity check failed: {bind['reason']}",
                "binding": bind}

    diff = run_differential(ws, recipe, forge, rpc_url, timeout)
    verified = bool(diff.get("flip"))
    return {
        **rec_base,
        "verdict": "non-vacuous" if verified else "vacuous",
        "mutation_verified": verified,
        "reason": diff.get("reason"),
        "differential": {k: diff[k] for k in ("n_pass", "n_fail", "passed_tests") if k in diff},
        "harness": str(harness_root),
        "clean_hex": str(clean_hex) if clean_hex else None,
        "mutant_hex": str(mutant_hex) if mutant_hex else None,
        "build": ({"built": build_status.get("built"),
                   "source_restored": build_status.get("source_restored")}
                  if build_status else "reused-existing-hex"),
        "evm_version": evm_version,
    }


# ---------------------------------------------------------------------------
# Canonical file merge (reuse sibling _xfn_record; preserve per-function rows).
# ---------------------------------------------------------------------------
def _canonical_record(sibling, label: str, result: dict) -> dict:
    """Build a canonical cross-function record via the sibling producer's
    _xfn_record so the gate's normalizer reads the same shape from both axes."""
    verdict = result.get("verdict", "vacuous")
    verified = bool(result.get("mutation_verified"))
    rec = sibling._xfn_record(
        label, verdict,
        reason=result.get("reason"),
        verified=verified,
        source=result.get("clean_hex"),
    )
    # Tag the fork-etch provenance + the real differential evidence.
    rec["requirement"] = label
    rec["mode"] = "fork-etch"
    rec["differential"] = result.get("differential")
    rec["harness"] = result.get("harness")
    rec["clean_hex"] = result.get("clean_hex")
    rec["mutant_hex"] = result.get("mutant_hex")
    rec["evm_version"] = result.get("evm_version")
    rec["build"] = result.get("build")
    return rec


def merge_into_canonical(ws: Path, cross_records: list[dict], cross_status: str) -> dict:
    """Merge fork-etch cross_function records into the existing canonical file,
    preserving per_function rows already produced by the source-recompile path."""
    canonical = ws / ".auditooor" / "mutation_verify_coverage.json"
    existing = {}
    if canonical.is_file() and canonical.stat().st_size > 0:
        try:
            existing = json.loads(canonical.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            existing = {}
    per_function = existing.get("per_function") or []
    # Merge fork-etch results into the existing cross_function records BY
    # REQUIREMENT LABEL. A `--only <req>` invocation (or a per-pair parallel
    # fan-out) processes a SUBSET of the recipe set; the prior REPLACE semantics
    # wiped every other pair's already-verified record, so the last writer won
    # and genuine kills for the un-processed pairs vanished (race regression
    # 2026-06-14: an `--only convert` run clobbered the silo/market/field kills
    # from a full pass). New records WIN for the labels this run processed
    # (freshest truth, incl. an honest vacuous downgrade); existing records for
    # labels NOT processed this run are PRESERVED. Requirement label is the join
    # key (the same label cross-function-invariant-coverage enumerates).
    def _req_key(rec: dict) -> str:
        return (rec.get("requirement") or rec.get("test") or rec.get("function") or "").strip()

    by_label: dict = {}
    for rec in (existing.get("cross_function") or []):
        k = _req_key(rec)
        if k:
            by_label[k] = rec
    for rec in cross_records:
        k = _req_key(rec)
        if k:
            by_label[k] = rec  # this run's result wins for the labels it processed
    cross_function = list(by_label.values())
    pf_verified = sum(1 for r in per_function if r.get("mutation_verified"))
    xf_verified = sum(1 for r in cross_function if r.get("mutation_verified"))
    payload = {
        "schema": SCHEMA,
        "generated_at": _utc_now(),
        "run_id": os.environ.get("AUDITOOOR_AUDIT_RUN_FULL_ID") or existing.get("run_id"),
        "workspace": str(ws),
        "language": existing.get("language", "solidity"),
        "per_function": per_function,
        "cross_function": cross_function,
        "verdicts": list(per_function) + list(cross_function),
        "counts": {
            "per_function_total": len(per_function),
            "per_function_verified": pf_verified,
            "cross_function_total": len(cross_function),
            "cross_function_verified": xf_verified,
        },
        "per_function_status": existing.get("per_function_status", "preserved"),
        "cross_function_status": cross_status,
        "cross_function_mode": "fork-etch",
        "summary": (
            f"per-function {pf_verified}/{len(per_function)} mutation-verified; "
            f"cross-function {xf_verified}/{len(cross_function)} mutation-verified "
            f"(fork-etch, {cross_status})"
        ),
    }
    return payload


def produce(ws, *, evm_version: str = "paris", only: str | None = None,
            rebuild: bool = False, timeout: int = 900, dry_run: bool = False) -> dict:
    ws = Path(ws)
    if not ws.exists() or not ws.is_dir():
        return {"schema": SCHEMA, "verdict": "error",
                "reason": f"workspace not a directory: {ws}"}
    sibling = _load_sibling_producer()
    if sibling is None:
        return {"schema": SCHEMA, "verdict": "error",
                "reason": "cannot load sibling cross-function-harness-producer.py"}

    cfg = parse_fork_config(ws)
    rpc_url = fork_rpc_url(cfg)
    recipes = read_recipes(ws)
    if only:
        recipes = [r for r in recipes
                   if (r.get("requirement") or r.get("label")) == only]
    forge = forge_bin()

    if not recipes:
        return {"schema": SCHEMA, "verdict": "no-recipes",
                "reason": "no .auditooor/fork_etch_recipes.json recipes "
                          "(fail-closed: nothing to mutation-verify via fork-etch)",
                "fork_config": cfg, "rpc_url": rpc_url}

    results: list[dict] = []
    cross_records: list[dict] = []
    for recipe in recipes:
        res = process_requirement(
            ws, recipe, forge=forge, rpc_url=rpc_url, evm_version=evm_version,
            timeout=timeout, rebuild=rebuild, dry_run=dry_run)
        results.append(res)
        label = res.get("requirement", "unknown")
        cross_records.append(_canonical_record(sibling, label, res))

    n_verified = sum(1 for r in results if r.get("mutation_verified"))
    cross_status = "ok" if any(r.get("verdict") in ("non-vacuous", "vacuous")
                               for r in results) else "skipped"
    payload = merge_into_canonical(ws, cross_records, cross_status)
    payload["fork_etch_results"] = results
    payload["fork_config"] = {"rpc_url": rpc_url, **{k: v for k, v in cfg.items()
                                                     if not k.upper().endswith("_RPC")}}
    payload["verified_count"] = n_verified
    payload["dry_run"] = dry_run
    return payload


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(
        description="Produce fork+etch mutation-verified cross-function coverage "
                    "(the --fork-etch MODE for live Diamond/L2 workspaces).")
    ap.add_argument("--workspace", required=True)
    ap.add_argument("--evm-version", default="paris",
                    help="solc evm version for the recompile (paris matches most "
                         "pre-PUSH0 live deployments; load-bearing for etch fidelity)")
    ap.add_argument("--only", default=None, help="process only this requirement label")
    ap.add_argument("--rebuild-bytecode", action="store_true",
                    help="force a fresh clean+mutant build+link even if hex exists")
    ap.add_argument("--timeout", type=int, default=900, help="per-step timeout seconds")
    ap.add_argument("--dry-run", action="store_true",
                    help="report what would build/run; touch no source, run no test")
    ap.add_argument("--no-write", action="store_true",
                    help="do not write the canonical file (report only)")
    ap.add_argument("--json", action="store_true")
    args = ap.parse_args(argv)

    ws = Path(args.workspace).expanduser()
    payload = produce(ws, evm_version=args.evm_version, only=args.only,
                      rebuild=args.rebuild_bytecode, timeout=args.timeout,
                      dry_run=args.dry_run)
    if payload.get("verdict") == "error":
        print(f"[{GATE}] ERROR {payload.get('reason')}", file=sys.stderr)
        if args.json:
            print(json.dumps(payload, indent=2, sort_keys=True))
        return 2

    if payload.get("verdict") == "no-recipes":
        print(f"[{GATE}] {payload['reason']}")
        if args.json:
            print(json.dumps(payload, indent=2, sort_keys=True))
        return 0

    if not args.no_write and not args.dry_run:
        out_path = ws / ".auditooor" / "mutation_verify_coverage.json"
        out_path.parent.mkdir(parents=True, exist_ok=True)
        # Strip the verbose debug keys from the persisted file (keep them in JSON
        # stdout for the operator) so the canonical artifact stays the contract.
        persist = {k: v for k, v in payload.items()
                   if k not in ("fork_etch_results", "fork_config", "verified_count", "dry_run")}
        out_path.write_text(json.dumps(persist, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        payload["canonical_path"] = str(out_path)

    if args.json:
        print(json.dumps(payload, indent=2, sort_keys=True))
    else:
        print(f"[{GATE}] {payload['summary']}")
        for r in payload.get("fork_etch_results", []):
            mark = "KILL" if r.get("mutation_verified") else r.get("verdict")
            print(f"[{GATE}]   {r.get('requirement')}: {mark} - {r.get('reason')}")
        if payload.get("canonical_path"):
            print(f"[{GATE}] wrote {payload['canonical_path']}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
