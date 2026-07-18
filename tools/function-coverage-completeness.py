#!/usr/bin/env python3
"""function-coverage-completeness.py - the REAL per-function attack coverage gate.

Background / root cause
-----------------------
The audit pipeline could declare a workspace "complete" while in-scope
external/public/entry functions were never actually ATTACKED. Two hollow
mechanisms manufactured the illusion of coverage:

  (a) CCIA (``tools/ccia-*.py``) is a shallow heuristic that emits noise
      attack-angles. On morpho-midnight it flagged a TEST-helper callback
      (``FlashLiquidateCallback.onLiquidate``) as a "MEDIUM unauthenticated
      state write". A heuristic angle is NOT a real attack with a verdict.

  (b) Per-function harnesses are generated but VACUOUS. morpho-midnight has
      78 ``Halmos_*_*.t.sol`` per-function scaffolds whose entire body is
      ``assert(true)`` (the generator even writes "This advisory scaffold is
      not proof"). A sentinel harness is NOT a real attack with a verdict.

Neither mechanism is a real per-function attack tied to a concrete verdict,
yet both let "coverage" pass. This gate makes that impossible: it enumerates
EVERY in-scope external/public/entry function and classifies each as
``real-attack`` / ``hollow`` / ``untouched``. ``--check`` passes
(``pass-fully-covered``) ONLY when every in-scope function is ``real-attack``.

What counts as a REAL attack (vs hollow)
----------------------------------------
A function is ``real-attack`` only if a workspace artifact ties a CONCRETE
attack / PoC / source-traced verdict to THAT function:
  - a finding sidecar / dead-end record whose ``file_line`` / ``source_refs``
    name the function's file AND (line-range OR function name), with a real
    verdict (CONFIRMED / FP-DEFENDED / source-traced reason), OR
  - a per-function attack record keyed to the function, OR
  - an adversarial PoC test that names the function AND carries a real
    assertion (not ``assert(true)`` / no-assertion sentinel).

A function is ``hollow`` if the ONLY thing referencing it is:
  - a vacuous harness (body is ``assert(true)`` / no real assertion / a
    generator "not proof" scaffold), OR
  - a CCIA heuristic attack-angle (``ccia_attack_angles.json``).

A function with no reference at all is ``untouched``.

Anti-stub rule (the core honesty rule): a harness whose body is
``assert(true)`` / no real assertion counts as HOLLOW, never real - even if
it names the function. This is the R80 finding-evidence-honesty discipline
applied at the coverage-gate level.

Mutation-verification bar (``--mutation-verify``, opt-in)
---------------------------------------------------------
The syntactic anti-stub rule above catches a harness whose body is literally
``assert(true)``. It does NOT catch a harness whose body LOOKS real
(``assert(prop)``, an echidna ``invariant_*``, a halmos ``check_*``, an
agent attack) yet is SEMANTICALLY VACUOUS - it passes both with AND without
an injected bug. Such a harness still counts as "covered" today, which is
the morpho-midnight bug this flag closes: 32 Halmos harnesses "passed"
vacuously and counted as covered.

``--mutation-verify`` (or env ``AUDITOOOR_FCC_MUTATION_VERIFY=1``) UPGRADES
the real-attack bar: a function whose ONLY real-attack evidence is a harness
(Pass 2) counts as ``real-attack`` ONLY if that harness is mutation-verified
NON-VACUOUS - i.e. a mutation-kill exists (inject a bug into the function,
the harness must now FAIL). This bar is the language-agnostic catch for
vacuous halmos / echidna / forge / agent harnesses.

The mutation verdicts are produced by the SIBLING tool
``tools/mutation-verify-coverage.py`` (invoked BY PATH, not imported, so
this gate stays decoupled). A verdict of ``vacuous`` or ``no-baseline``
(harness passes even with the bug, or the harness never had a passing
baseline) is treated as HOLLOW, not real. The flag is graceful/opt-in:
without it, current behavior holds (so existing fast runs are unchanged);
with it, if the sibling tool is absent or errors, harness-derived
real-attack classifications are CONSERVATIVELY downgraded to ``hollow``
(``unverified``) so a missing mutation backend can never silently PASS a
harness it could not verify. Finding/PoC-derived real-attack evidence
(Pass 1) is unaffected - mutation-verification only gates harness-derived
coverage (Pass 2), which is where the vacuous-harness illusion lives.

Generality (non-negotiable per the tooling charter)
---------------------------------------------------
  1. Generic: ``--workspace`` accepts ANY workspace. ZERO target hardcoding
     in this tool body (morpho appears only in the unit test as a smoke
     anchor).
  2. Language-aware: Solidity (.sol, incl. MULTI-LINE function signatures
     ``function repay(...)\n external\n{``), Rust (.rs), Go (.go), Move
     (.move), Cairo (.cairo). Extensible via the per-language pattern tables
     and env hooks below.
  3. Excludes test/lib/mock/interface/script from the in-scope surface
     (path-based AND filename-suffix based, e.g. ``FooTest.sol``), plus
     vendored forge-std / common deps.
  4. Additive: emits its own artifact + verdict; does not mutate other
     tools' logic.

Env hooks (all newline-separated, appended to defaults)
-------------------------------------------------------
  AUDITOOOR_FCC_EXTRA_TEST_HINTS       extra path substrings treated as test
  AUDITOOOR_FCC_EXTRA_ENTRY_KEYWORDS   extra entrypoint visibility keywords
  AUDITOOOR_FCC_EXTRA_EVIDENCE_GLOBS   extra workspace globs scanned for
                                       real-attack evidence (relative to ws)
  AUDITOOOR_FCC_EXTRA_VACUOUS_RES      extra regexes that mark a harness body
                                       vacuous
  AUDITOOOR_FCC_EXTRA_BOILERPLATE_NAMES  extra exact fn NAMES excluded as
                                       non-attack-surface boilerplate (appended
                                       to the conservative built-in set)
  AUDITOOOR_FCC_MUTATION_VERIFY        when "1"/"true"/"yes", default-enables
                                       the --mutation-verify bar
  AUDITOOOR_FCC_MUTATION_TOOL          override path to the sibling
                                       mutation-verify-coverage.py
  AUDITOOOR_FCC_MUTATION_TIMEOUT       per-invocation timeout seconds (mutation
                                       runs can be slow); default 1800

CLI
---
    function-coverage-completeness.py --workspace <ws> [--check]
                                      [--emit-worklist] [--json]
                                      [--mutation-verify]

Exit code
---------
  --check:   0 on pass-fully-covered / pass-no-source; 1 on
             fail-functions-untouched-or-hollow; 2 on error.
  default / --emit-worklist: 0 unless error (2).

Dependency-free: stdlib only, offline-safe, never executes target code.
"""
from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import sys
from dataclasses import dataclass, field
from pathlib import Path

# Shared sentinel-only-harness detector (the canonical cross-tool vacuity
# predicate; per-language testify/const-fold/zk aware). E3.2: fcc consults it on
# every harness body BEFORE crediting a real-attack so a semantically-vacuous
# harness can never be credited offline (no toolchain required). Kept as a
# supplement to the local _VACUOUS_RES syntactic pre-filter.
sys.path.insert(0, str(Path(__file__).resolve().parent / "lib"))
try:
    from harness_vacuity import is_sentinel_only_harness as _is_sentinel_only_harness
except Exception:  # pragma: no cover - lib must be importable; fail-open to local
    _is_sentinel_only_harness = None

# Go/Cosmos external-entry-surface classifier (sibling module in tools/). Used to
# narrow the Go attack-surface denominator from "every exported fn" (Go's export is
# a linkage property, NOT external reachability - the wrong Solidity analog) to the
# TRUE external entry points (msg-server / ABCI / precompile / ante / IBC / RPC).
# Fail-open: absent import OR a non-Cosmos-Go workspace keeps every-exported (the
# larger/stricter denominator) so narrowing can never silently pass a workspace.
sys.path.insert(0, str(Path(__file__).resolve().parent))
try:
    import go_entrypoint_surface as _go_entry
except Exception:  # pragma: no cover - fail-open to every-exported behavior
    _go_entry = None


def _load_fork_scope_fn():
    """Import ``_apply_fork_scope`` from workspace-coverage-heatmap.py (hyphenated
    module -> importlib). REUSE, not reimplement, the clone+diff fork-scope logic.
    Returns the callable or None (fail-open: absent helper -> lever-2 no-op, larger
    denominator kept). Cached on the function object."""
    if getattr(_load_fork_scope_fn, "_cached", "unset") != "unset":
        return _load_fork_scope_fn._cached  # type: ignore[attr-defined]
    fn = None
    try:
        import importlib.util as _ilu
        _tool = Path(__file__).resolve().with_name("workspace-coverage-heatmap.py")
        if _tool.is_file():
            _spec = _ilu.spec_from_file_location(
                "_fcc_workspace_coverage_heatmap", _tool)
            _mod = _ilu.module_from_spec(_spec)
            _spec.loader.exec_module(_mod)  # type: ignore[union-attr]
            fn = getattr(_mod, "_apply_fork_scope", None)
    except Exception:  # pragma: no cover - fail-open
        fn = None
    _load_fork_scope_fn._cached = fn  # type: ignore[attr-defined]
    return fn


def _load_go_dataflow_paths(ws: Path) -> list:
    """Read parsed Go DefUsePath records from <ws>/.auditooor/dataflow_paths.jsonl
    for lever-3 closure crediting. Returns [] on any absence/error (=> closure
    no-op, the safe direction). Only the go-language records are consumed by the
    edge builder; reading all rows here is fine (the builder filters)."""
    p = ws / ".auditooor" / "dataflow_paths.jsonl"
    if not p.is_file():
        return []
    out = []
    try:
        for ln in p.read_text(encoding="utf-8", errors="replace").splitlines():
            ln = ln.strip()
            if not ln:
                continue
            try:
                rec = json.loads(ln)
            except ValueError:
                continue
            if isinstance(rec, dict):
                out.append(rec)
    except OSError:
        return []
    return out


def _l37_strict() -> bool:
    """STRICT mode: AUDITOOOR_L37_STRICT=1 (the canonical global strict flag)."""
    return os.environ.get("AUDITOOOR_L37_STRICT", "").strip() == "1"

SCHEMA = "auditooor.function_coverage_completeness.v1"
GATE = "FUNCTION-COVERAGE-COMPLETENESS"

# --------------------------------------------------------------------------
# Language support
# --------------------------------------------------------------------------
_LANG_BY_EXT = {
    ".sol": "sol",
    ".rs": "rs",
    ".go": "go",
    ".move": "move",
    ".cairo": "cairo",
    # Declarative / DSL languages that CANNOT be recovered by a `function NAME(`
    # source-regex walk (there is no _FN_RE extractor below): their in-scope
    # units are seeded DIRECTLY from the inscope-manifest instead (see
    # _MANIFEST_SEED_LANGS / _seed_manifest_declarative_units). Obyte Oscript
    # Autonomous Agents (.oscript / .aa) are the first such arm; registering the
    # extension here makes the file RECOGNIZED as in-scope source (not dropped as
    # unknown-lang) and is the generic hook for any future declarative language.
    ".oscript": "oscript",
    ".aa": "oscript",
}

# E3.4 - mutation-runner backing per language.
# Languages with a built-in mutation runner in mutation-verify-coverage.py
# (solidity halmos/forge, rust cargo, go go-test): an ABSENT backend under
# STRICT is FATAL. Languages with NO built-in circuit/resource mutation runner
# (move/cairo/circom/noir) get a TYPED <lang>-mutation-runner-absent verdict +
# a waiver path rather than a hard brick (cross-cutting rule 3).
_MUT_RUNNER_LANGS = {"sol", "rs", "go"}
_MUT_RUNNER_ABSENT_LANGS = {"move", "cairo", "circom", "noir"}
_RUNNER_ABSENT_VERDICT = {
    "move": "move-mutation-runner-absent",
    "cairo": "cairo-mutation-runner-absent",
    "circom": "circom-mutation-runner-absent",
    "noir": "noir-mutation-runner-absent",
}
_RUNNER_WAIVER_ENV = {
    "move": "AUDITOOOR_MVC_RUNNER_MOVE",
    "cairo": "AUDITOOOR_MVC_RUNNER_CAIRO",
    "circom": "AUDITOOOR_MVC_RUNNER_CIRCOM",
    "noir": "AUDITOOOR_MVC_RUNNER_NOIR",
}
_RUNNER_WAIVER_HINT = {
    "move": "set AUDITOOOR_MVC_RUNNER_MOVE to an aptos/sui move-test command, "
            "or supply a clean static-soundness substitute run",
    "cairo": "set AUDITOOOR_MVC_RUNNER_CAIRO, or supply a clean "
             "static-soundness substitute run",
    "circom": "supply a clean circomspect/picus static-soundness run, or set "
              "AUDITOOOR_MVC_RUNNER_CIRCOM",
    "noir": "supply a clean static-soundness run, or set AUDITOOOR_MVC_RUNNER_NOIR",
}

# Directories never part of the in-scope surface.
_SKIP_DIRS = {
    ".git", "node_modules", "vendor", "target", "dist", "build", "out",
    "lib", "libs", "cache", ".auditooor", "mocks", "mock", "test", "tests",
    "script", "scripts", "interface", "interfaces", "poc-tests",
    "chimera_harnesses", "forge-std", "ds-test", "openzeppelin-contracts",
    "solmate", "node-modules",
    # Non-audited REFERENCE material: a top-level reference/ dir conventionally
    # ships deployed-bytecode dumps / decompiled snapshots / vendored
    # @openzeppelin copies for cross-checking - never in-scope protocol source
    # (coverage-map's scope-file mode already excludes it; the strict gate must
    # match so it does not count reference/*.sol as in-scope-untouched and emit
    # a permanent false-red). "@openzeppelin" catches a flattened OZ vendor copy
    # under any path. r36-rebuttal: lane L37-FCC-REFERENCE-SCOPE-FIX registered in .auditooor/agent_pathspec.json
    "reference", "@openzeppelin",
    # Formal-verification scaffolding: the Certora Prover convention ships
    # specs + helper/harness contracts (havoc shims, mock callbacks) under a
    # top-level certora/ dir. These are verification-only, never in-scope
    # protocol code (analogous to test/mock). Universal across DeFi repos.
    # r36-rebuttal: lane L37-CERTORA-SCOPE-FIX registered in .auditooor/agent_pathspec.json
    "certora",
    # Cosmos-SDK OOS sim/test infrastructure: a module ships its randomized
    # operation generators under x/<module>/simulation/ and the integration
    # wiring under simapp/ - both are simulation/test harness, never in-scope
    # protocol code (same class as test/mocks/certora). testutil/testutils hold
    # shared test fixtures. Universal across Cosmos repos. Mirrors the markers
    # already in tools/lib/scope_exclusion.py so this gate's denominator matches
    # the canonical scope classifier (NUVA 2026-06-30: 35 sim/simapp fns -
    # simulation/operations.go + simapp/app.go + simapp/provenance.go - were
    # over-counted as in-scope-untouched, a permanent false-red).
    # r36-rebuttal: lane L37-FCC-COSMOS-SIM-SCOPE-FIX registered in .auditooor/agent_pathspec.json
    "simulation", "simapp", "testutil", "testutils",
}

# Path substrings that mark a file as test / mock / interface / script / lib.
_TEST_HINTS = (
    "/test/", "/tests/", "_test.go", ".t.sol", "test_", "_test.rs",
    "/mock", "/mocks/", "/interface", "/interfaces/", "/script/",
    "/scripts/", "/lib/", "/libs/", "/vendor/", "/forge-std/",
    "/poc-tests", "/chimera_harnesses",
    "/certora/",  # r36-rebuttal: lane L37-CERTORA-SCOPE-FIX registered
    # r36-rebuttal: lane L37-FCC-REFERENCE-SCOPE-FIX registered in .auditooor/agent_pathspec.json
    "/reference/", "/@openzeppelin/",
    # Cosmos-SDK OOS sim/test dirs (see _SKIP_DIRS note above). Path-substring
    # form catches them even when nested under x/<module>/.
    # r36-rebuttal: lane L37-FCC-COSMOS-SIM-SCOPE-FIX registered in .auditooor/agent_pathspec.json
    "/simulation/", "/simapp/", "/testutil/", "/testutils/",
)

# Filename-suffix (before extension) that marks the file itself as a test
# helper even when the path looks in-scope, e.g. ``FooTest.sol``,
# ``Halmos_Bar.t.sol`` (caught by .t.sol above), ``baz_test.rs``.
_TEST_FILE_SUFFIXES = ("test", "_test", "mock", "_mock", "harness", "_harness")

# Vendored / dependency filenames that are never in-scope even if flattened
# into a src tree (forge-std + common boilerplate).
_VENDORED_FILE_STEMS = {
    "vm", "stdjson", "stdstorage", "stdinvariant", "stdcheats", "stderror",
    "stdmath", "stdutils", "stdstyle", "stdassertions", "stdchains",
    "stdtoml", "console", "console2", "safeconsole", "script", "test",
    "ds-test", "basetest", "commonbase", "stdtoml",
}

# --------------------------------------------------------------------------
# Non-attack-surface boilerplate exclusion (trivial-fn-exclusion)
# --------------------------------------------------------------------------
# ROOT CAUSE this closes: the gate enumerated EVERY external/public/exported
# function as an attack-coverage unit. On a Cosmos-SDK chain (injective) that is
# ~29k functions, ~75% of which are protoc/abigen-GENERATED marshaling +
# Cosmos-SDK CLI/codec/module boilerplate (``Marshal``/``Unmarshal``/``String``/
# ``Reset``/``RegisterCodec``/``NewTxCmd``/``ModuleRootCommand``/...). These have
# NO attack surface - demanding a per-function adversarial verdict on a
# protoc-generated ``XXX_Unmarshal`` or a cobra ``GetTxCmd`` is meaningless and
# floods the hunt with nonsense (generic Solidity-reentrancy questions on a CLI
# ``Execute``).
#
# The exclusion is CONSERVATIVE by design: it fires only on (a) machine-generated
# files (the canonical ``// Code generated ... DO NOT EDIT.`` Go marker + known
# generated suffixes), and (b) functions whose NAME unambiguously denotes
# Cosmos/CLI/codec/proto boilerplate. A function that mutates state / handles a
# Msg / moves funds / verifies sigs is NEVER excluded - when a name is at all
# ambiguous it is KEPT (e.g. ``ValidateBasic`` = first input-validation defense,
# ``InitGenesis`` = state-writing, ``Transfer`` in a hand-written keeper). This is
# an HONESTY fix (boilerplate is not an attack surface), NOT a gate weakening:
# every function it removes is non-security generated/scaffolding code.

# (a) GENERATED-FILE markers. The Go toolchain stamps every generated file with
# a ``// Code generated <by-X> DO NOT EDIT.`` line (the canonical ``go generate``
# convention, regex per the Go source: ``^// Code generated .* DO NOT EDIT\.$``).
# protoc-gen-gogo, protoc-gen-grpc-gateway and go-ethereum abigen all emit it.
# Such a file is never hand-written audited surface.
_GENERATED_HEADER_RE = re.compile(
    r"^//\s*Code generated\b.*\bDO NOT EDIT\.", re.MULTILINE
)
# Fast-path generated filename suffixes (caught even if a header is stripped).
_GENERATED_FILE_SUFFIXES = (
    ".pb.go", ".pb.gw.go", ".abigen.go", ".abi.go", "_gen.go",
    ".gen.go", "_generated.go", ".cosmos_orm.go",
)
# How many bytes of a file head to scan for the generated marker (the marker
# always precedes the package clause; 4 KiB is ample and keeps the scan cheap).
_GENERATED_HEADER_SCAN_BYTES = 4096

# (b) Exact boilerplate function NAMES (any language; matched case-sensitively
# against the captured fn name). Each is pure proto/codec/CLI/module scaffolding
# with no per-function attack surface. KEEP list (NOT here on purpose):
# ValidateBasic (input-validation defense), InitGenesis/ExportGenesis (mutate
# state), GetSigners/GetSignBytes/Route/Type (signer-set/routing metadata =
# auth-relevant), NewKeeper, and anything in a keeper/msg_server.
_BOILERPLATE_FN_NAMES = frozenset({
    # gogo-proto Message marshaling / reflection boilerplate.
    "Marshal", "MarshalTo", "MarshalToSizedBuffer", "MarshalJSON",
    "Unmarshal", "UnmarshalJSON", "Size", "Reset", "String", "ProtoMessage",
    "Descriptor", "Equal", "ProtoReflect", "GetCachedSize",
    # Cosmos-SDK AppModule / module.go boilerplate (no state surface).
    "Name", "DefaultGenesis", "ValidateGenesis", "ConsensusVersion",
    "RegisterCodec", "RegisterInterfaces", "RegisterLegacyAminoCodec",
    "RegisterGRPCGatewayRoutes", "RegisterRESTRoutes", "RegisterInvariants",
    "RegisterServices", "RegisterStoreDecoder", "GetTxCmd", "GetQueryCmd",
    "IsOnePerModuleType", "IsAppModule", "NewAppModule", "DefaultGenesisState",
    "GenerateGenesisState", "RegisterStoreDecoders", "WeightedOperations",
    "ProposalContents", "RandomizedParams",
    # Cobra CLI flag/command boilerplate.
    "AddQueryFlagsToCmd", "AddTxFlagsToCmd", "ModuleRootCommand",
    # Proposal/Msg constant-metadata getters (return constants, not state).
    "ProposalRoute", "ProposalType",
    # Go ``error`` interface methods - a custom error type's Error()/Unwrap()/
    # Cause() are pure accessors over a wrapped error, never an attack surface.
    "Error", "Unwrap", "Cause", "GRPCStatus",
    # Cosmos-SDK depinject / autocli module-wiring boilerplate (DI container
    # plumbing + CLI option tables, no protocol logic / state surface). Mirrors
    # the AppModule/cobra scaffolding already excluded above. NUVA 2026-06-30.
    "ProvideModule", "AutoCLIOptions", "IsTxModule", "ProvideKeeper",
})
# Boilerplate NAME PATTERNS (regex, fullmatch against the fn name).
_BOILERPLATE_FN_RES = (
    # protoc XXX_* hooks (XXX_Unmarshal / XXX_Marshal / XXX_Size / XXX_Merge /
    # XXX_DiscardUnknown / XXX_MessageName / XXX_WellKnownType ...).
    re.compile(r"XXX_\w+"),
    # Cobra command builders: NewTxCmd / NewQueryCmd / GetTxCmd, and the
    # ubiquitous ``New<Foo>TxCmd`` / ``<Foo>TxCmd`` / ``Cmd<Foo>`` / ``<Foo>Cmd``
    # constructors that only assemble a cobra.Command (no protocol logic).
    re.compile(r"New[A-Z]\w*(?:Tx|Query)Cmd"),
    re.compile(r"\w*(?:Tx|Query)Cmd"),
    re.compile(r"Cmd[A-Z]\w*"),
    re.compile(r"New[A-Z]\w*Command"),
    # Generated gRPC-gateway / query-client handler registrars.
    re.compile(r"Register\w*(?:HandlerClient|HandlerServer|HandlerFromEndpoint|Handler)"),
)


def _is_generated_file(path: Path, rel: str) -> bool:
    """True iff this file is machine-generated (never hand-written attack
    surface): a known generated filename suffix OR a canonical
    ``// Code generated ... DO NOT EDIT.`` header in the file head."""
    low = rel.replace("\\", "/").lower()
    if any(low.endswith(suf) for suf in _GENERATED_FILE_SUFFIXES):
        return True
    try:
        with open(path, "rb") as fh:
            head = fh.read(_GENERATED_HEADER_SCAN_BYTES)
    except OSError:
        return False
    try:
        head_text = head.decode("utf-8", errors="replace")
    except Exception:
        return False
    return _GENERATED_HEADER_RE.search(head_text) is not None


def _boilerplate_fn_names() -> frozenset:
    extra = _env_list("AUDITOOOR_FCC_EXTRA_BOILERPLATE_NAMES")
    if not extra:
        return _BOILERPLATE_FN_NAMES
    return _BOILERPLATE_FN_NAMES | frozenset(extra)


# Read-only (non-mutating) function exclusion. A function that CANNOT mutate state
# or move funds has no per-function attack surface of its own: it can only be a
# COMPONENT of an exploit via its (separately-enumerated) consumer. Demanding a
# mutation-verified harness for it is wrong (there is no state change to break) and
# inflates the coverage denominator with views/getters/pure helpers. Documented in
# the README runbook (Step-2/genuine-coverage methodology).
#   - Solidity/Vyper: ``view``/``pure``/``constant`` is COMPILER-GUARANTEED read-only
#     (the EVM reverts on a state write), so the sig keyword alone is sufficient + safe.
#   - Go: NO compiler guarantee, so require BOTH a getter-name AND a body with ZERO
#     state-write / fund-move tokens. CONSERVATIVE: any write token KEEPS the function
#     (a false-positive in write-detection only over-includes, never drops a mutator).
_SOL_READONLY_RE = re.compile(r"\b(view|pure|constant)\b")
# Read-only / compute / constructor verbs. A Go function whose name starts with
# one of these AND whose body has ZERO state-write/fund-move tokens (the AND-gate
# below) is provably non-mutating: a getter (Get/Has/Is/Query/List/...), a pure
# computation (Estimate/Compute/Calculate/Preview/Quote/Find/Fetch/Read), a
# read-only iterator (Walk/Range/Scan), a struct constructor/wiring (New), or a
# codec/Stringer (Format/Marshal/String/Export). NUVA 2026-06-30: EstimateSwapIn,
# WalkByVault, NewQueryServer were over-counted as in-scope-untouched because the
# old name set only matched Get-style getters, so every compute/iterator/ctor
# (provably zero-write) inflated the coverage denominator on every Cosmos repo.
# CONSERVATIVE: the zero-write AND-gate still KEEPS any function with a write
# token, so a mutator that happens to carry a read-ish name is never dropped.
_GO_GETTER_NAME_RE = re.compile(
    r"^(Get|Has|Is|Query|List|Iterate|Lookup|Load|Peek|Estimate|Walk|Range|Scan"
    r"|Compute|Calculate|Calc|Preview|Quote|Find|Fetch|Read|New|Format|Marshal"
    r"|Unmarshal|String|Export)[A-Z0-9_]")
# State-write / fund-move tokens. Includes the Cosmos `collections` API writes
# (bare ``.Set(`` on a Map/IndexedMap, ``.Push(``/``.Pop(``/``.Replace(``/
# ``.Clear(``) - NUVA 2026-06-30: without the bare ``.Set(`` token the
# write-detector missed Enqueue/Dequeue (p.IndexedMap.Set), so the getter-name
# relaxation above would have wrongly dropped them. Over-detecting writes only
# OVER-KEEPS (never drops a mutator), so widening this set is always safe.
# NOTE: ``.Next(`` is deliberately EXCLUDED - it is overwhelmingly the read-only
# iterator advance ``iter.Next()`` (e.g. WalkByVault); a Sequence.Next() write is
# always paired with a ``.Set(`` store, which IS detected, so no mutator escapes.
# gRPC Query-service handler return-type signal (Cosmos convention): a handler
# returns ``(*types.Query<X>Response, error)``. Matches the ``Query...Response``
# pointer return regardless of the leading package alias.
_GO_QUERY_RPC_RE = re.compile(r"\*[\w.]*Query\w*Response\b")
_GO_STATE_WRITE_RE = re.compile(
    r"(store\.Set|store\.Delete|\.Set[A-Z]\w*\(|\.Set\(|\.Delete\(|\.Remove\("
    r"|\.Append\(|\.Push\(|\.Pop\(|\.Replace\(|\.Clear\("
    r"|SendCoins|SpendableCoins|\bTransfer\b|\bMint\b|\bBurn\b|AddBalance|SubBalance"
    r"|SetBalance|setSupply|\.Write\(|\.Put\(|\bCommit\b|SaveVersion|\.Update\(|\.Insert\()"
)
# Rust: NO compiler `view` keyword, but a method with a SHARED receiver `&self`
# (not `&mut self`) cannot persist NEAR contract state. To be CONSERVATIVE like
# Go (never drop a fund-mover), require BOTH a getter-ish NAME and a body free of
# state-write / fund-move / cross-contract-Promise tokens. A `&mut self` receiver,
# any write/insert/remove, or a Promise/transfer/ext_ call KEEPS the function.
# This keeps security validators (verify / assert_* - not getter-named) and every
# mutator in scope; it only drops pure read accessors (get_/is_/has_/view_/query_).
_RUST_GETTER_NAME_RE = re.compile(r"^(get_|is_|has_|view_|query_|peek_|len_|num_)")
_RUST_STATE_WRITE_RE = re.compile(
    r"&mut\s+self|\.insert\(|\.set\b|\.set_[a-z]|\.remove\(|\.push\(|\.pop\(|\.write\(|"
    r"\.put\(|\.clear\(|\.append\(|\.extend\(|Promise::|promise_|\bext_[a-z]|"
    r"\.transfer\(|\.deposit\(|\.withdraw\(|env::promise|\.emit_transfer\(|\.burn\(|\.mint\("
)


def _is_read_only(name: str, sig: str, lang: str, body: str) -> bool:
    """True iff the function has no state-mutation / fund-movement surface (a
    view/getter/pure helper). See the block comment above for the per-language rule."""
    low = (lang or "").lower()
    # NOTE: the enumerator passes the _LANG_BY_EXT token ("sol"), NOT the long
    # name "solidity". Accept BOTH (+ vyper "vy") so the documented Solidity
    # view/pure read-only drop actually fires - before 2026-06-27 only the long
    # names were matched, so the Solidity exclusion was dead and every view/pure
    # getter inflated the coverage denominator on every .sol workspace.
    if low in ("solidity", "sol", "vyper", "vy"):
        return bool(_SOL_READONLY_RE.search(sig or ""))
    if low == "go":
        # gRPC Query-service handler: signature returns ``*types.Query<X>Response``
        # (the Cosmos query RPC convention). These are read-only by design - they
        # answer a QueryXRequest from state and never write. Detected by the return
        # type so they are caught regardless of name (Vaults / PendingSwapOuts /
        # EstimateSwapIn are entity-named, not Get-prefixed). Still AND-gated on the
        # zero-write body check below, so a (non-conventional) writing query handler
        # is kept. NUVA 2026-06-30.
        is_query_rpc = bool(_GO_QUERY_RPC_RE.search(sig or ""))
        if not is_query_rpc and not _GO_GETTER_NAME_RE.match(name or ""):
            return False
        return not _GO_STATE_WRITE_RE.search(body or "")
    if low in ("rust", "rs"):
        # Conservative (mirrors Go): getter-ish name AND a shared `&self` receiver
        # AND no state-write / fund-move / Promise tokens. Keeps verify/assert_*
        # validators (not getter-named) and every mutator (`&mut self` / writes).
        if not _RUST_GETTER_NAME_RE.match(name or ""):
            return False
        if "&self" not in (sig or "") and "& self" not in (sig or ""):
            return False
        if "&mut self" in (sig or ""):
            return False
        return not _RUST_STATE_WRITE_RE.search(body or "")
    return False


def _is_nonattack_boilerplate(name: str, sig: str, lang: str = "", body: str = "") -> bool:
    """True iff a function NAME unambiguously denotes Cosmos/CLI/codec/proto
    boilerplate OR is a read-only view/getter/pure helper - in either case it has
    no per-function attack surface. CONSERVATIVE: when in doubt KEEP (return False).
    Only the exact-name set + narrow regex patterns + the compiler-/token-guarded
    read-only check fire; a real security function (state mutation / Msg handler /
    fund movement / sig verification) is never silently dropped. Generic across
    Cosmos-SDK chains and Go/Solidity/Rust."""
    if name in _boilerplate_fn_names():
        return True
    for rx in _BOILERPLATE_FN_RES:
        if rx.fullmatch(name):
            return True
    if _is_read_only(name, sig, lang, body):
        return True
    return False


def _env_list(name: str) -> list:
    raw = os.environ.get(name, "")
    return [s.strip() for s in raw.splitlines() if s.strip()]


def _test_hints() -> tuple:
    return tuple(_TEST_HINTS) + tuple(
        h.lower() for h in _env_list("AUDITOOOR_FCC_EXTRA_TEST_HINTS")
    )


# Entrypoint visibility keywords per language. A function is "in-scope
# surface" only if it is externally reachable (external/public/entry).
_ENTRY_KEYWORDS = {
    # Solidity: external | public visibility on the decl. (internal/private
    # are NOT directly attackable surface.)
    "sol": ("external", "public"),
    # Rust: ``pub fn`` (incl. ``pub(crate)``) is the reachable surface; we
    # also treat ``#[entry]`` / ``extern`` decorated fns (handled separately).
    "rs": ("pub",),
    # Go: exported identifiers start uppercase (handled by name-case below);
    # the keyword set is unused for Go.
    "go": (),
    # Move: ``public`` / ``public(friend)`` / ``entry``.
    "move": ("public", "entry"),
    # Cairo: ``#[external]`` / ``#[view]`` decorators (handled separately) +
    # ``pub fn``.
    "cairo": ("pub", "external", "view"),
}


def _entry_keywords(lang: str) -> tuple:
    base = _ENTRY_KEYWORDS.get(lang, ())
    return tuple(base) + tuple(_env_list("AUDITOOOR_FCC_EXTRA_ENTRY_KEYWORDS"))


# Function declaration extractors per language. Each captures the function
# NAME. Decl may be multi-line; visibility may appear on a later line for
# Solidity (``function repay(...)\n external\n {``).
_FN_RE = {
    "sol": re.compile(r"\bfunction\s+([A-Za-z_]\w*)\s*\("),
    "rs": re.compile(r"\bfn\s+([A-Za-z_]\w*)\s*[<(]"),
    "go": re.compile(r"\bfunc\s*(?:\([^)]*\)\s*)?([A-Za-z_]\w*)\s*\("),
    "move": re.compile(r"\bfun\s+([A-Za-z_]\w*)\s*[<(]"),
    "cairo": re.compile(r"\bfn\s+([A-Za-z_]\w*)\s*[<(]"),
}

# Common long-form language aliases -> the short _LANG_BY_EXT / _FN_RE token, so a
# manifest row that stores lang="solidity"/"rust"/"golang" is normalized before we
# decide whether it needs a source-regex extractor or a manifest seed.
_LANG_ALIAS = {
    "solidity": "sol", "vyper": "vy", "rust": "rs", "golang": "go",
}


def _norm_lang(raw: object) -> str:
    low = str(raw or "").strip().lower()
    return _LANG_ALIAS.get(low, low)


# Languages that are REGISTERED (have a _LANG_BY_EXT extension) but have NO
# source-regex extractor in _FN_RE - i.e. declarative / DSL languages (Obyte
# Oscript AAs). Their units cannot be recovered by a `function NAME(` walk, so
# they are seeded DIRECTLY from the inscope-manifest (which the language-specific
# enumerator already parsed into file+function+lang rows). GENERIC: register a
# new declarative language by adding its extension to _LANG_BY_EXT (with no
# _FN_RE entry) and its manifest units auto-seed here. The extractable languages
# (sol/rs/go/move/cairo) are NOT in this set, so their source-walk behavior is
# byte-identical.
_MANIFEST_SEED_LANGS = frozenset(set(_LANG_BY_EXT.values()) - set(_FN_RE.keys()))
# The file extensions that map to a declarative-seed language (e.g. .oscript/.aa).
_DECL_EXTS = frozenset(
    ext for ext, lang in _LANG_BY_EXT.items() if lang in _MANIFEST_SEED_LANGS
)

# How many lines after the decl to scan for the visibility keyword / body
# brace (covers multi-line signatures).
_SIG_WINDOW = 16

# Vacuous-harness body markers (anti-stub). A harness body that matches any
# of these (and carries no other real assertion) is HOLLOW.
_VACUOUS_RES = [
    re.compile(r"\bassert\s*\(\s*true\s*\)"),
    re.compile(r"\bassertTrue\s*\(\s*true\s*\)"),
    re.compile(r"\brequire\s*\(\s*true\s*\)"),
    re.compile(r"not\s+proof", re.IGNORECASE),
    re.compile(r"advisory\s+scaffold", re.IGNORECASE),
    re.compile(r"sentinel\s+assertion", re.IGNORECASE),
    re.compile(r"replace\s+the\s+sentinel", re.IGNORECASE),
    re.compile(r"\bTODO\b.*assert", re.IGNORECASE),
]

# A "real assertion" signal in a harness body (presence => NOT vacuous,
# unless the only assertion is one of the vacuous forms above).
_REAL_ASSERT_RES = [
    re.compile(r"\bassert(?:Eq|Lt|Gt|Le|Ge|True|False|Approx)?\s*\("),
    re.compile(r"\brequire\s*\("),
    re.compile(r"\bvm\.expectRevert"),
    re.compile(r"\bproptest!"),
    re.compile(r"\bassert!"),
    re.compile(r"\bassert_eq!"),
]


def _vacuous_res():
    res = list(_VACUOUS_RES)
    for pat in _env_list("AUDITOOOR_FCC_EXTRA_VACUOUS_RES"):
        try:
            res.append(re.compile(pat))
        except re.error:
            pass
    return res


# --------------------------------------------------------------------------
# Mutation-verification adapter (calls the sibling tool BY PATH; opt-in)
# --------------------------------------------------------------------------
# This gate does NOT re-implement mutation testing. It DELEGATES to the
# sibling tool tools/mutation-verify-coverage.py (per the tooling charter:
# extend/reuse, do not duplicate). The adapter is intentionally tolerant of
# the sibling's exact output shape so it stays decoupled: it accepts a list
# of per-harness/per-function verdict records under several common keys and
# normalizes each to one of {killed, vacuous, no-baseline, error}.
#
# Verdict semantics (the ONLY load-bearing distinction):
#   killed      -> the harness FAILED once a bug was injected => NON-VACUOUS,
#                  may credit a harness-derived real-attack.
#   vacuous     -> the harness PASSED even WITH the injected bug => HOLLOW.
#   no-baseline -> the harness had no passing baseline to mutate against
#                  => HOLLOW (cannot prove the harness ever asserted anything).
#   error/<other> -> could not verify => treated as UNVERIFIED (HOLLOW under
#                  the conservative --mutation-verify bar).
#
# A sentinel string is returned from _load_mutation_verdicts when the sibling
# backend is unavailable (absent / crashed / timed out / unparseable) so the
# caller can apply the conservative downgrade instead of silently passing.
_MUTATION_BACKEND_UNAVAILABLE = "__mutation_backend_unavailable__"

# Verdict-token normalization. Each token (lowercased substring match against
# the record's verdict/status/disposition field) maps to a normalized class.
_MUT_KILLED_TOKENS = (
    "killed", "mutation-killed", "non-vacuous", "nonvacuous", "real",
    "verified", "kill", "caught", "detected",
)
_MUT_VACUOUS_TOKENS = (
    "vacuous", "survived", "not-killed", "not killed", "hollow", "passes-both",
    "passed-both", "survivor",
)
_MUT_NO_BASELINE_TOKENS = (
    "no-baseline", "no baseline", "nobaseline", "no-passing-baseline",
    "baseline-fail", "baseline-failed", "broken-baseline",
)


def _mutation_tool_path() -> Path:
    """Resolve the sibling mutation-verify-coverage.py path (env override
    first, else next to this tool)."""
    override = os.environ.get("AUDITOOOR_FCC_MUTATION_TOOL", "").strip()
    if override:
        return Path(override).expanduser()
    return Path(__file__).resolve().parent / "mutation-verify-coverage.py"


def _normalize_mut_verdict(raw: str) -> str:
    low = str(raw or "").strip().lower()
    if not low:
        return "error"
    # Order matters: no-baseline is a sub-case that must not be swallowed by a
    # generic "fail"; and "non-vacuous" must be treated as killed before the
    # generic vacuous-token check sees the substring "vacuous".
    if any(t in low for t in _MUT_NO_BASELINE_TOKENS):
        return "no-baseline"
    if any(t in low for t in _MUT_KILLED_TOKENS):
        return "killed"
    if any(t in low for t in _MUT_VACUOUS_TOKENS):
        return "vacuous"
    return "error"


def _records_from_payload(payload) -> list:
    """Extract a flat list of per-harness/per-function verdict dicts from the
    sibling tool's JSON, tolerant of several container shapes."""
    if isinstance(payload, list):
        return [r for r in payload if isinstance(r, dict)]
    if not isinstance(payload, dict):
        return []
    for key in ("results", "verdicts", "harnesses", "functions", "mutations",
                "records", "rows"):
        v = payload.get(key)
        if isinstance(v, list):
            return [r for r in v if isinstance(r, dict)]
    if payload.get("verdict") is not None and payload.get("function") is not None:
        return [payload]
    return []


def _record_verdict(rec: dict) -> str:
    # r36-rebuttal: lane-funcov-clean-credit
    # An explicit kill always wins.
    for key in ("killed", "mutation_killed", "non_vacuous"):
        if key in rec and rec[key]:
            return "killed"
    # INCONCLUSIVE != VACUOUS. "no-mutants" means the generator produced 0
    # mutants (no mutable operators in the body) so vacuousness CANNOT be
    # proven - the upstream tool mislabels this as verdict="vacuous". A simple
    # setter / access-control body legitimately has nothing to mutate; a
    # reasoned PoC rule-out for it is the ceiling of what is verifiable, not a
    # failure. Proven-vacuous (mutants WERE generated and the harness survived
    # them) stays "vacuous". "no-baseline" (harness never produced a passing
    # baseline = it did not really run) stays a downgrade.
    ov = str(rec.get("oracle_verdict") or "").lower().replace("_", "-")
    mc = rec.get("mutant_count")
    if ov == "no-mutants" or (isinstance(mc, int) and mc == 0 and ov != "no-baseline"):
        return "inconclusive"
    for key in ("mutation_verdict", "verdict", "status", "disposition",
                "classification", "result"):
        if key in rec and rec[key] is not None:
            return _normalize_mut_verdict(rec[key])
    # Some tools emit a boolean killed flag instead of a string verdict.
    for key in ("killed", "mutation_killed", "non_vacuous"):
        if key in rec:
            return "killed" if rec[key] else "vacuous"
    return "error"


def _record_function_key(rec: dict) -> str | None:
    """Best-effort (file_basename, function_name) key for a verdict record."""
    name = None
    for key in ("function", "fn", "name", "function_name", "target"):
        if rec.get(key):
            name = str(rec[key]).split(".")[-1].split("(")[0].strip()
            break
    fileref = None
    for key in ("file", "file_line", "source_file", "source", "path", "src", "contract_file"):
        if rec.get(key):
            fileref = str(rec[key])
            break
    if not name:
        return None
    base = Path(_norm_file(fileref)).name if fileref else ""
    return f"{base}::{name}" if base else f"::{name}"


def _record_harness_name(rec: dict) -> str | None:
    for key in ("harness", "harness_file", "harness_name", "test", "test_file",
                "poc", "poc_path"):
        if rec.get(key):
            return Path(_norm_file(str(rec[key]))).name
    return None


# r36-rebuttal: lane FIX-FCC-SRCLINE-MUT-CREDIT registered in .auditooor/agent_pathspec.json
def _record_source_line(rec: dict) -> tuple[str, int] | None:
    """Resolve a record's SOURCE-under-test ``(basename, line)`` from its
    ``source``/``file_line`` field. A per-function/cross-function mutation
    record's ``function`` field is frequently a HARNESS ALIAS (e.g.
    ``XFn_account.t``) whose name component is junk (``t``), so the
    function-name key silently fails to credit the real function. The
    ``source`` field (``Midnight.sol:502``) set by the mutation engine is the
    AUTHORITATIVE subject: a mutant injected at that line that the harness
    detected (killed) IS genuine per-function attack evidence for the function
    whose decl span starts at that line. Return None if no line resolves."""
    for key in ("source", "file_line", "source_line", "source_file", "src", "file"):
        raw = rec.get(key)
        if not raw:
            continue
        m = _FILE_LINE_RE.search(str(raw))
        if m:
            return Path(_norm_file(m.group(1))).name, int(m.group(2))
    return None


def _load_mutation_verdicts(ws: Path, *, allow_live: bool = True):
    """Invoke the sibling mutation-verify-coverage.py BY PATH and return a
    pair of lookups: (by_fn_key, by_harness_name) mapping to normalized
    verdicts. Returns the sentinel ``_MUTATION_BACKEND_UNAVAILABLE`` when the
    backend cannot be used (absent / crash / timeout / unparseable) so the
    caller applies the conservative downgrade.

    First preference: a pre-computed workspace artifact
    ``.auditooor/mutation_verify_coverage.json`` (so a slow mutation run can be
    cached out-of-band). Falls back to invoking the tool live."""
    payloads = []
    # (1) cached artifact paths (cheap, offline).
    candidates = [
        ws / ".auditooor" / "mutation_verify_coverage.json",
        ws / ".auditooor" / "mutation-verify-coverage.json",
    ]
    # Durable mutation sidecars live under BOTH cross-function-coverage/ AND
    # mvc_sidecar/, and carry operator names (e.g. liqctl_mint_premade_mutant.json)
    # that do NOT match 'mutation*'. A fresh audit-deep-solidity run CLOBBERS the
    # top-level mutation_verify_coverage.json, so these durable sidecars are the
    # real record. Mirror the sibling readers (core-coverage-completeness.py:354 +
    # cross-function-invariant-coverage.py:1012) which both glob '*.json' across
    # both dirs - globbing only 'mutation*.json' under one dir silently dropped
    # genuine kills -> false-red function-coverage. Discovery only; the downstream
    # kill-required verdict bar is unchanged (never-false-pass).
    for _sd in ("cross-function-coverage", "mvc_sidecar"):
        sidecar_dir = ws / ".auditooor" / _sd
        if sidecar_dir.is_dir():
            candidates.extend(sorted(sidecar_dir.glob("*.json")))
    for cand in candidates:
        if cand.is_file() and cand.stat().st_size > 0:
            try:
                payloads.append(json.loads(cand.read_text(encoding="utf-8", errors="replace")))
            except (OSError, ValueError):
                pass
    # (2) live invocation of the sibling tool.
    if not payloads:
        if not allow_live:
            return {}, {}
        tool = _mutation_tool_path()
        if not tool.is_file():
            return _MUTATION_BACKEND_UNAVAILABLE
        try:
            timeout = int(os.environ.get("AUDITOOOR_FCC_MUTATION_TIMEOUT", "1800"))
        except ValueError:
            timeout = 1800
        try:
            proc = subprocess.run(
                [sys.executable, str(tool), "--workspace", str(ws), "--json"],
                capture_output=True, text=True, timeout=timeout,
            )
        except (subprocess.TimeoutExpired, OSError):
            return _MUTATION_BACKEND_UNAVAILABLE
        out = proc.stdout or ""
        # Tolerate leading log noise: parse from the first '{' or '['.
        for opener in ("{", "["):
            idx = out.find(opener)
            if idx >= 0:
                try:
                    payloads.append(json.loads(out[idx:]))
                    break
                except ValueError:
                    pass
        if not payloads:
            return _MUTATION_BACKEND_UNAVAILABLE

    records = []
    for payload in payloads:
        records.extend(_records_from_payload(payload))
    by_fn: dict = {}
    by_harness: dict = {}
    for rec in records:
        verdict = _record_verdict(rec)
        fk = _record_function_key(rec)
        if fk is not None:
            # Prefer the strongest verdict if a function appears twice.
            prev = by_fn.get(fk)
            by_fn[fk] = _stronger_mut(prev, verdict)
        hn = _record_harness_name(rec)
        if hn is not None:
            prev = by_harness.get(hn)
            by_harness[hn] = _stronger_mut(prev, verdict)
        # r36-rebuttal: lane FIX-FCC-SRCLINE-MUT-CREDIT registered in .auditooor/agent_pathspec.json
        # ALSO index by the source-under-test line so a mutation-killed record
        # whose ``function`` field is a harness alias (name-key fails) still
        # credits the real function via its decl line. ``_stronger_mut`` keeps a
        # kill dominant over sibling vacuous/no-baseline records at the same line.
        sl = _record_source_line(rec)
        if sl is not None:
            base, line = sl
            sk = f"{base}::L{line}"
            by_fn[sk] = _stronger_mut(by_fn.get(sk), verdict)
    return by_fn, by_harness


def _stronger_mut(a, b) -> str:
    """A function/harness is mutation-verified if ANY of its records is a
    kill. So 'killed' dominates; otherwise prefer the more-informative
    non-error verdict."""
    order = {"killed": 3, "vacuous": 2, "no-baseline": 2,
             "inconclusive": 1.5, "error": 1}  # r36-rebuttal: lane-funcov-clean-credit
    if a is None:
        return b
    return a if order.get(a, 0) >= order.get(b, 0) else b


def _harness_mutation_ok(by_fn, by_harness, fn, harness_basename: str) -> tuple:
    """Decide whether a harness-derived real-attack for ``fn`` survives the
    mutation-verify bar. Returns (ok: bool, reason: str). ``ok`` is True ONLY
    on a confirmed kill keyed to either the function or the harness."""
    fn_base = Path(_norm_file(fn.file)).name
    fk = f"{fn_base}::{fn.name}"
    fv = by_fn.get(fk)
    if fv is None:
        # try a name-only key (records without file refs)
        fv = by_fn.get(f"::{fn.name}")
    hv = by_harness.get(harness_basename) if harness_basename else None
    # r36-rebuttal: lane FIX-FCC-SRCLINE-MUT-CREDIT registered in .auditooor/agent_pathspec.json
    # source-line-anchored kill (harness-alias name-key missed the real fn).
    slv = by_fn.get(f"{fn_base}::L{fn.line}")
    # A kill from ANY keying (fn-name / harness / source-line) suffices.
    if fv == "killed" or hv == "killed" or slv == "killed":
        return True, "mutation-killed"
    # Explicit vacuous / no-baseline => hollow with a precise reason.
    for v, src in ((fv, "fn"), (hv, "harness")):
        if v in ("vacuous", "no-baseline"):
            return False, f"mutation-{v}"
    # No verdict at all for this harness/fn under the conservative bar.
    return False, "mutation-unverified"


def _apply_cached_mutation_records(ws: Path, fns: list) -> None:
    loaded = _load_mutation_verdicts(ws, allow_live=False)
    if loaded is _MUTATION_BACKEND_UNAVAILABLE:
        return
    by_fn, _by_harness = loaded
    for fn in fns:
        fn_base = Path(_norm_file(fn.file)).name
        verdict = by_fn.get(f"{fn_base}::{fn.name}") or by_fn.get(f"::{fn.name}")
        # r36-rebuttal: lane FIX-FCC-SRCLINE-MUT-CREDIT registered in .auditooor/agent_pathspec.json
        # A kill source-anchored to this fn's decl line credits it even when the
        # name-key missed (harness-alias function field). Kill is required - a
        # vacuous/no-baseline at the line never promotes (no false-green).
        if verdict != "killed" and by_fn.get(f"{fn_base}::L{fn.line}") == "killed":
            verdict = "killed"
        if verdict == "killed":
            fn.classification = "real-attack"
            fn.evidence.append(f"mutation-killed:{fn_base}:{fn.name}:{fn.line}")


# --------------------------------------------------------------------------
# Data model
# --------------------------------------------------------------------------
@dataclass
class Fn:
    name: str
    file: str  # ws-relative
    line: int  # 1-based decl line
    lang: str
    end_line: int = 0  # 1-based last line of the function body (best effort)
    classification: str = "untouched"  # real-attack | hollow | untouched
    evidence: list = field(default_factory=list)  # human-readable refs
    entry_point: bool = True  # Go/Cosmos: True=external entry surface, False=internal helper

    def key(self) -> str:
        return f"{self.file}:{self.name}"

    def to_record(self) -> dict:
        # Surface the load-bearing evidence first: a real-attack function's
        # displayed evidence must show the finding-attack/harness record that
        # justified the classification, not an analysis-only sibling that
        # merely also references the function.
        ev = sorted(
            self.evidence,
            key=lambda e: 0 if (e.startswith("finding-attack")
                                or (e.startswith("harness:") and "vacuous" not in e)
                                or e.startswith("mutation-killed")
                                or e.startswith("confirmed")) else 1,
        )
        return {
            "name": self.name,
            "file": self.file,
            "line": self.line,
            "lang": self.lang,
            "classification": self.classification,
            "evidence": ev[:6],
        }


# --------------------------------------------------------------------------
# Source enumeration (multi-line-sig + exclusion aware)
# --------------------------------------------------------------------------
def _is_test_path(rel: str) -> bool:
    low = rel.replace("\\", "/").lower()
    if any(h in low for h in _test_hints()):
        return True
    stem = Path(low).stem
    # filename-suffix test markers, e.g. ``footest`` / ``foo_test`` /
    # ``foomock``. Endswith check after stripping common separators.
    for suf in _TEST_FILE_SUFFIXES:
        if stem.endswith(suf):
            return True
    return False


def _is_vendored(rel: str) -> bool:
    stem = Path(rel.replace("\\", "/")).stem.lower()
    return stem in _VENDORED_FILE_STEMS


def _iter_source_files(root: Path):
    for p in sorted(root.rglob("*")):
        if not p.is_file():
            continue
        # Consider only the path RELATIVE to the source root for skip/test
        # decisions, so an unrelated ancestor directory (e.g. a temp dir or a
        # user path literally containing "test_") cannot over-exclude.
        try:
            rel_parts = p.relative_to(root).parts
            rel = str(p.relative_to(root))
        except ValueError:
            rel_parts = p.parts
            rel = str(p)
        if any(part in _SKIP_DIRS for part in rel_parts):
            continue
        if p.suffix not in _LANG_BY_EXT:
            continue
        if _is_test_path(rel) or _is_vendored(rel):
            continue
        # trivial-fn-exclusion: machine-generated files (protoc-gen-gogo,
        # grpc-gateway, abigen) are never hand-written attack surface - skip
        # them at the file level so their thousands of Marshal/Unmarshal/String
        # boilerplate fns never enter the per-function worklist.
        if _is_generated_file(p, rel):
            continue
        yield p, _LANG_BY_EXT[p.suffix]


def _sig_text(lines: list, decl_idx: int) -> str:
    """Return the signature window text (decl line through the body-opening
    brace or ``{``/``;``), to detect visibility keywords on later lines."""
    n = len(lines)
    chunk = []
    for i in range(decl_idx, min(decl_idx + _SIG_WINDOW, n)):
        chunk.append(lines[i])
        if "{" in lines[i] or ";" in lines[i]:
            break
    return "\n".join(chunk)


def _body_end(lines: list, decl_idx: int) -> int:
    """Best-effort 1-based last line of the function body, brace-balanced
    from the first ``{`` at/after the decl. For interface/abstract decls
    that end in ``;`` with no body, returns the decl line."""
    n = len(lines)
    open_idx = None
    for i in range(decl_idx, min(decl_idx + _SIG_WINDOW + 4, n)):
        if "{" in lines[i]:
            open_idx = i
            break
        if ";" in lines[i]:
            return decl_idx + 1  # bodiless decl
    if open_idx is None:
        return decl_idx + 1
    depth = 0
    started = False
    for i in range(open_idx, n):
        for ch in lines[i]:
            if ch == "{":
                depth += 1
                started = True
            elif ch == "}":
                depth -= 1
        if started and depth <= 0:
            return i + 1
    return n


def _is_bodiless_decl(lines: list, decl_idx: int) -> bool:
    """True for a bodiless function DECLARATION - an interface / abstract / trait
    method whose signature window reaches ``;`` before any ``{``. These are not
    implementations (the real body is enumerated at its own definition site);
    counting the bare decl as an in-scope function leaves a permanently-hollow
    phantom with no body to hunt. A genuine one-line body (``... external { ... }``)
    has ``{`` on/within the signature window and is NOT bodiless."""
    n = len(lines)
    for i in range(decl_idx, min(decl_idx + _SIG_WINDOW + 4, n)):
        if "{" in lines[i]:
            return False  # has a body
        if ";" in lines[i]:
            return True   # ';' before any '{' -> declaration only
    return False  # no terminator found in window - be conservative, keep it


def _is_entry(lang: str, sig: str, name: str, file_stem: str) -> bool:
    """Is this declaration an externally reachable entrypoint?"""
    low = sig.lower()
    kws = _entry_keywords(lang)
    if lang == "go":
        # Exported = capitalized identifier.
        return bool(name) and name[0].isupper()
    if lang == "sol":
        # external | public visibility anywhere in the signature window.
        # Solidity defaults to public for state vars but functions must
        # declare; treat presence of the keyword as entry.
        return any(re.search(r"\b" + re.escape(k) + r"\b", low) for k in kws)
    if lang in ("rs", "cairo"):
        # pub fn (incl pub(crate)) OR a #[external]/#[view]/#[entry] attr in
        # the signature window.
        if re.search(r"\bpub(?:\s*\([^)]*\))?\s+fn\b", low):
            return True
        if re.search(r"#\[\s*(external|view|entry|payable|abi)\b", low):
            return True
        return False
    if lang == "move":
        return any(re.search(r"\b" + re.escape(k) + r"\b", low) for k in kws)
    # Unknown language: be permissive (count it) so the gate never silently
    # under-reports surface on a language it doesn't fully model.
    return True


def _extract_entry_fns(path: Path, lang: str, rel: str,
                       go_entry_scope: bool = False) -> list:
    """Extract externally-reachable functions from a source file.

    ``go_entry_scope`` (Cosmos/Go-L1 only, computed once per-workspace in
    ``evaluate``): when True, each Go Fn is tagged ``entry_point`` = is it a TRUE
    external entry point (msg-server/ABCI/precompile/ante/IBC/RPC/genesis/...) vs
    an internal helper (the Go analog of a Solidity ``internal`` fn). Internal
    helpers are excluded from the coverage denominator downstream. Fail-open: when
    the classifier is unavailable this stays False and every exported Go fn keeps
    ``entry_point=True`` (every-exported, the pre-existing behavior)."""
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except (OSError, UnicodeError):
        return []
    lines = text.splitlines()
    fn_re = _FN_RE.get(lang)
    if fn_re is None:
        return []
    file_stem = Path(rel).stem
    out: list = []
    seen: set = set()
    for i, ln in enumerate(lines):
        m = fn_re.search(ln)
        if not m:
            continue
        name = m.group(1)
        sig = _sig_text(lines, i)
        if not _is_entry(lang, sig, name, file_stem):
            continue
        # Bodiless interface/abstract/trait declaration (sig ends ';' before any
        # '{') is a DECLARATION, not an implementation - the real impl is
        # enumerated at its own definition site (e.g. FieldFacet's IBS interface
        # re-declares cancelPodListing, whose body lives in MarketplaceFacet).
        # Counting the bare decl leaves a permanently-hollow phantom. Exclude it.
        if _is_bodiless_decl(lines, i):
            continue
        # trivial-fn-exclusion: drop hand-written Cosmos/CLI/codec/proto
        # boilerplate (RegisterCodec / NewTxCmd / module Name/DefaultGenesis /
        # ProtoMessage ...) by name. CONSERVATIVE - only unambiguous boilerplate
        # names fire; a state-mutating / Msg-handling / fund-moving / sig-
        # verifying fn is KEPT. Generated FILES are already skipped upstream in
        # _iter_source_files; this catches the hand-written boilerplate.
        end_line = _body_end(lines, i)
        # body text (decl through close brace) for the Go read-only state-write check.
        body = "\n".join(lines[i:end_line + 1]) if end_line >= i else ""
        if _is_nonattack_boilerplate(name, sig, lang, body):
            continue
        k = (name, i + 1)
        if k in seen:
            continue
        seen.add(k)
        # Go/Cosmos entry-surface tag (fail-open: default True = surface). A Go
        # function that is NOT a true external entry point is an internal helper
        # (reached only through an entry point, covered transitively) and is
        # excluded from the coverage denominator downstream in evaluate().
        entry_point = True
        if go_entry_scope and lang == "go" and _go_entry is not None:
            receiver = _go_entry.extract_go_receiver(ln)
            entry_point = _go_entry.is_go_entry_point(name, receiver, rel, sig)
        out.append(Fn(name=name, file=rel, line=i + 1, lang=lang,
                      end_line=end_line, entry_point=entry_point))
    return out


# --------------------------------------------------------------------------
# Evidence model: tie real attacks / hollow markers to functions
# --------------------------------------------------------------------------
# Real-attack evidence sources (workspace-relative globs). A finding /
# dead-end / poc-record whose source ref names a function's file+line/name
# with a real verdict marks that function real-attack.
_REAL_EVIDENCE_GLOBS = (
    # hunt_findings_sidecars: recursive + BOTH the .auditooor/-rooted and the
    # workspace-root location (hunt-completeness-check treats both as valid and
    # rglobs them). Non-recursive .auditooor-only globbing missed a real
    # CONFIRMED/executed-PoC per-fn sidecar that landed at the root or nested.
    ".auditooor/hunt_findings_sidecars/**/*.json",
    "hunt_findings_sidecars/**/*.json",
    ".auditooor/known_dead_ends.jsonl",
    ".auditooor/deep-engine-findings/**/*.json",
    ".auditooor/poc_execution_records*.json*",
    ".auditooor/per_function_attack_records*.json*",
    ".auditooor/per_function_attacks/*.json",
    "submissions/**/*.md",
)

# Vacuous-harness directories (per-function scaffolds + generated PoC tests).
_HARNESS_GLOBS = (
    "poc-tests/per_function_invariants/*.sol",
    "poc-tests*/**/*.t.sol",
    ".auditooor/per_function_invariants/*.sol",
    "**/Halmos_*.t.sol",
)

# CCIA heuristic angle artifacts (hollow).
_CCIA_GLOBS = (
    ".auditooor/ccia_attack_angles.json",
    ".auditooor/ccia_*.json",
)

# A record is EVIDENCE OF A REAL DRIVEN ATTACK only if it carries a concrete
# attack verdict (a confirmed exploit, or an executed PoC that drove the
# function and ruled it out). An analysis-only prose sidecar that merely
# DROPs a hypothesis without an executed-and-bound PoC is NOT a driven
# attack - it is hollow analysis, treated like a CCIA heuristic angle.
#
# real-attack verdict tokens: a CONFIRMED exploit, OR a defended/false-
# positive verdict that was reached by an EXECUTED, function-bound PoC
# (poc_result / PASS transcript / executed harness). We detect the
# executed-PoC signal separately so a bare "FALSE-POSITIVE - dropped by
# reasoning" sidecar does NOT count.
_CONFIRMED_RE = re.compile(
    r"\b(CONFIRMED|EXPLOITABLE|TRUE-POSITIVE|exploit\s+confirmed)\b",
    re.IGNORECASE,
)
# Executed-PoC signal: the record cites a real test TRANSCRIPT (an actually-
# run suite), not merely the PRESENCE of a poc field. A sidecar that has a
# ``poc_evidence_lines`` key but whose verdict is FALSE-POSITIVE / DROP and
# whose body shows no PASS/FAIL transcript line is analysis-only, NOT a
# driven attack. We therefore require a concrete transcript token.
_EXECUTED_POC_RE = re.compile(
    r"(--- PASS:|--- FAIL:|\bSuite result:\s*ok\b|\[PASS\]|\[FAIL\]|"
    r"\bran \d+ tests?\b|\bcounterexample\b|"
    r"\bPASS\b[^\n]{0,40}\(\d+ (?:ms|gas)\)|"
    r"\b\d+ passed\b|\b\d+ passing\b)",
    re.IGNORECASE,
)
# Any verdict token at all (used only to know a record is a finding record).
# r36-rebuttal: funnel-generic-fixes-wave3
# `applies_to_target` / `function_anchor` admit the per-fn MIMO/haiku nested-schema
# sidecars (engaged-clean records carry neither "verdict" nor "severity" at the top
# level - their disposition lives inside a nested JSON `result` string). Without them
# the gate skips a real nested sidecar before the function_anchor fallback can credit
# the function, under-reporting coverage on every workspace that uses that schema.
# The fallback (_parse_nested_sidecar_result) still gates what actually counts, so
# this only lets the right sidecars REACH the fallback - it does not inflate coverage.
_ANY_VERDICT_RE = re.compile(
    r"\b(verdict|disposition|FALSE-POSITIVE|FP-DEFENDED|CONFIRMED|"
    r"EXPLOITABLE|severity|applies_to_target|function_anchor)\b", re.IGNORECASE,
)
# A "discarded hypothesis" disposition: the finding was DROPPED as a
# false-positive on REASONING (not via a substantive defense trace). Such a
# record is analysis noise - the function was not genuinely held to a driven
# adversarial result. Records whose disposition matches this are NEVER
# real-attack evidence even if they carry an executed-PoC transcript token
# (the PoC merely confirmed the NEGATIVE control). A substantive
# ``FP-DEFENDED`` (ruled out by a real source-traced defense) is NOT
# discarded - only the plain DROP / FALSE-POSITIVE-by-reasoning forms are.
_DISCARDED_DISPOSITION_RE = re.compile(
    r"\"?(?:disposition|verdict)\"?\s*[:=]\s*\"?\s*"
    r"(?:DROP\b|FALSE-?POSITIVE|FP-designed-as-intended|FP-by-reasoning|"
    r"not\s+a\s+bug|no\s+impact|INFO\b|INFORMATIONAL)",
    re.IGNORECASE,
)

_FILE_LINE_RE = re.compile(r"([\w./\\-]+\.\w+):(\d+)(?:-(\d+))?")
# Whole-word identifier tokens. Used to tokenize a CCIA angle title ONCE so a
# function-name match is an O(1) set lookup instead of a per-function dynamic
# ``\b<re.escape(name)>\b`` regex (which thrashed the regex cache on 29k fns).
_WORD_TOKEN_RE = re.compile(r"\w+")
_PER_FUNCTION_RECORD_GLOBS = (
    ".auditooor/per_function_attack_worklist.jsonl",
    ".auditooor/per_function_attack_records*.json*",
    ".auditooor/per_function_attacks/*.json",
    ".auditooor/per_function_attacks/*.jsonl",
)
_TERMINAL_ATTACK_STATUSES = {"real-attack", "holds", "finding"}
_TERMINAL_CLEAN_STATUSES = {"no-exploit", "clean", "ruled-out", "no-finding"}
_TERMINAL_STATUSES = _TERMINAL_ATTACK_STATUSES | _TERMINAL_CLEAN_STATUSES
_STATUS_ALIASES = {
    "confirmed": "finding",
    "exploit-confirmed": "finding",
    "true-positive": "finding",
    "true-positive-finding": "finding",
    "tp": "finding",
    "hold": "holds",
    "held": "holds",
    "real-attack": "real-attack",
    "attack-driven": "real-attack",
    "no-exploit": "no-exploit",
    "no-exploitable-path": "no-exploit",
    "clean": "clean",
    "clean-no-confirmed-finding": "clean",
    "clean-no-finding": "clean",
    "ruled-out": "ruled-out",
    "source-ruled-out": "ruled-out",
    "fp-defended": "ruled-out",
    "false-positive-defended": "ruled-out",
    # FC-FALSE-RED fix (hyperlane step-3, 2026-06-21): the canonical per-fn hunt
    # vocabulary (workflow-drill-sidecar-emit / inscope-hunt-batch-builder) emits
    # verdict=CONFIRMED|KILL. "confirmed" already maps to "finding"; "kill" had NO
    # alias, so it normalized to the unmapped token "kill" (not in _TERMINAL_STATUSES)
    # and every clean per-fn rule-out was dropped -> the function fell through to the
    # vacuous-harness Pass and was false-downgraded to "hollow". KILL = examined +
    # ruled out (clean terminal verdict). NOTE: this is the per-fn SIDECAR normalizer
    # (_STATUS_ALIASES); the mutation-verdict normalizer is separate (where killed =
    # non-vacuous), so this does not affect mutation crediting.
    "kill": "ruled-out",
    "killed": "ruled-out",
    # FC-FALSE-RED fix (near-intents step-3, 2026-06-24): the sonnet per-fn hunt
    # fan-out (spawn-worker hunt agents) emits verdict=NEGATIVE for a source-
    # verified clean rule-out (examined the function at real source, no exploit).
    # Like "kill" before its fix, "negative" had NO alias, so it normalized to the
    # unmapped token "negative" (not in _TERMINAL_STATUSES) and every clean per-fn
    # rule-out was dropped -> the function fell through to the vacuous-harness Pass
    # and was false-downgraded to "hollow". NEGATIVE = examined + ruled out (clean
    # terminal verdict), identical semantics to KILL/ruled-out. The body-trivial +
    # R80 gating downstream is UNCHANGED, so a non-trivial function still requires
    # real PoC/harness evidence (never-false-pass): this only lets the recognized
    # clean verdict be READ as terminal so trivial accessors/getters credit.
    "negative": "ruled-out",
    "negative-source-verified": "ruled-out",
    "source-verified-negative": "ruled-out",
    "no-finding": "no-finding",
    "no-confirmed-finding": "no-finding",
}
_TERMINAL_EVIDENCE_FIELDS = (
    "poc_path", "poc_evidence_lines", "pass_evidence_lines",
    "source_ref", "source_refs", "source_line", "source_lines",
    "evidence", "evidence_ref", "evidence_refs", "verdict_detail",
    "reason", "why_no_exploit", "why_no_gap_or_exploit",
)


def _normalize_terminal_status(raw: object) -> str:
    val = str(raw or "").strip().strip('"').strip("'")
    if not val:
        return ""
    key = re.sub(r"[\s_]+", "-", val.lower())
    key = re.sub(r"[^a-z0-9-]+", "-", key).strip("-")
    return _STATUS_ALIASES.get(key, key)


def _text_value(value: object) -> str:
    if value is None:
        return ""
    if isinstance(value, (dict, list, tuple)):
        return json.dumps(value, sort_keys=True)
    return str(value)


# r36-rebuttal: lane L37-CERTORA-SCOPE-FIX registered in .auditooor/agent_pathspec.json
# NOTE: `return` is deliberately NOT in this control-flow set. A lone
# `return <expr>;` is the canonical TRIVIAL getter/delegation body. A genuine
# early-return GUARD always co-occurs with an `if`/`while` (still matched here),
# so flagging bare `return` only mis-classified one-line accessors as
# non-trivial and blocked prose-clean credit on them. The statement-count cap in
# `_body_is_trivial` keeps a long LINEAR body (many statements, no control flow)
# non-trivial so this does not weaken the R80 prose-is-not-coverage bar.
_NONTRIVIAL_BODY_RE = re.compile(r"\b(?:if|while|for|loop|match|unsafe)\b|\?[\s;.)]")


def _strip_code_noise(code: str) -> str:
    code = re.sub(r"//[^\n]*", "", code)
    code = re.sub(r"/\*.*?\*/", "", code, flags=re.S)
    code = re.sub(r'"(?:\\.|[^"\\])*"', '""', code)
    return code


def _body_is_trivial(ws, file_line: str) -> bool:
    """True iff the function at file_line has a GENUINELY trivial body (a one-line
    accessor / constructor / direct delegation) - no control-flow branch, loop,
    match, unsafe block, early-return guard, or ?-propagation. A non-trivial body
    (the part an auditor must actually attack) returns False, so a prose-only
    'clean' verdict cannot credit it without real test/PoC evidence (R80: prose is
    not coverage for non-trivial code). Generic / language-agnostic; lenient when
    the body cannot be resolved (returns True) so it never blocks a genuine
    workspace, strict when the body resolves and is non-trivial (kills the
    signature-only-trivial-clean false-pass)."""
    try:
        m = _FILE_LINE_RE.search(file_line)
        if not m:
            return True
        rel, ln = m.group(1), int(m.group(2))
        cand = None
        for c in (ws / rel, ws / "src" / rel, ws / "src" / "src" / rel):
            if c.is_file():
                cand = c
                break
        if cand is None:
            return True
        lines = cand.read_text(encoding="utf-8", errors="replace").splitlines()
        if ln < 1 or ln > len(lines):
            return True
        # find the opening brace of this fn (decl may span lines), then brace-match
        start = ln - 1
        depth = 0
        opened = False
        body_chars = []
        for i in range(start, min(start + 400, len(lines))):
            for ch in lines[i]:
                if ch == "{":
                    depth += 1
                    opened = True
                    if depth == 1:
                        continue
                if opened and depth >= 1:
                    body_chars.append(ch)
                if ch == "}":
                    depth -= 1
                    if opened and depth == 0:
                        # r36-rebuttal: lane L37-CERTORA-SCOPE-FIX registered
                        body = _strip_code_noise("".join(body_chars))
                        if _NONTRIVIAL_BODY_RE.search(body) is not None:
                            return False
                        # r36-rebuttal: lane L37-CERTORA-SCOPE-FIX registered
                        # Statement-count cap: a genuinely trivial body is a
                        # SINGLE accessor / delegation / direct return (one
                        # statement). Anything with >1 statement - a guarded
                        # setter (`require(...); require(...); x = v;`), a
                        # multi-step computation, etc. - is real code an auditor
                        # must attack, so it needs test/PoC evidence, not a
                        # prose-clean stamp. (Empirical anchor: morpho-midnight
                        # one-line getters = 1 `;`; fee-setters >= 2 `;`.)
                        if body.count(";") > 1:
                            return False
                        return True
        return True  # no closed body found within window - lenient
    except Exception:
        return True


def _row_has_terminal_evidence(row: dict, status: str, ws=None) -> bool:
    if status in _TERMINAL_ATTACK_STATUSES:
        return True
    file_line = str(row.get("file_line") or "")
    file_part = file_line.rsplit(":", 1)[0] if ":" in file_line else file_line
    function = str(row.get("function") or row.get("fn") or row.get("name") or "")
    # TEST/PoC-backed clean verdict is genuine regardless of body shape.
    for field in ("poc_path", "poc_evidence_lines", "pass_evidence_lines"):
        if _text_value(row.get(field)).strip():
            return True
    # R80 anti-false-pass: a PROSE-ONLY clean verdict (verdict_detail/source_refs
    # naming the function) credits the function ONLY if the body is genuinely
    # trivial. A non-trivial function (control-flow/loop/unsafe/guard) asserted
    # "clean" with no test/PoC is NOT coverage - it reverts to untouched until it
    # gets real evidence. This kills the signature-only "trivial-clean" stamp.
    if ws is not None and file_line and not _body_is_trivial(Path(ws), file_line):
        return False
    for field in _TERMINAL_EVIDENCE_FIELDS:
        text = _text_value(row.get(field)).strip()
        if not text:
            continue
        if file_line and file_line in text:
            return True
        if file_part and function and file_part in text and re.search(
            r"\b" + re.escape(function) + r"\b", text
        ):
            return True
    return False


def _evidence_globs() -> tuple:
    return _REAL_EVIDENCE_GLOBS + tuple(
        _env_list("AUDITOOOR_FCC_EXTRA_EVIDENCE_GLOBS")
    )


def _pass1_evidence_paths(ws: Path):
    """All Pass-1 evidence files: the workspace-relative _evidence_globs PLUS the
    repo-side derived ``mimo_harness_<ws>*`` dirs where the canonical per-function /
    residual hunt lands its workflow-drill sidecars. The anchor-crediting pass
    historically read only ``ws/.auditooor/``, so a per-fn KILL emitted to the
    derived dir (carrying an authoritative function_anchor) was never anchor-
    credited unless separately bridged into the workspace - the SAME serving-join
    gap Pass-2 (core harness coverage, line ~2340) already closes by globbing the
    derived dir. The span/anchor + verdict checks downstream are unchanged, so
    widening discovery cannot create a false-green: a record without a real
    verdict/anchor is still skipped."""
    # G3: exclude synthetic-lead hunt sidecars at the single evidence-path source,
    # so EVERY Pass-1 / function_anchor crediting loop that consumes this enumerator
    # is uniformly protected. A synthetic-lead sidecar CLAIMS a per-fn hunt but was
    # never dispatched (no receipt); crediting it as real-attack coverage is the
    # NUVA-437 false-green E4 kills on the hunt-coverage plane - closed here on the
    # function-coverage plane. Fail-open (empty set) when the classifier is absent.
    _synth_lead = _synthetic_lead_sidecar_paths(ws)
    seen: set = set()
    for pattern in _evidence_globs():
        for p in _iter_glob(ws, pattern):
            rp = str(p)
            if rp in _synth_lead:
                continue
            if rp not in seen:
                seen.add(rp)
                yield p
    try:
        derived = Path(__file__).resolve().parent.parent / "audit" / "corpus_tags" / "derived"
        if derived.is_dir():
            for d in derived.glob(f"mimo_harness_*{ws.name}*"):
                if d.is_dir():
                    for p in list(d.glob("*.json")) + list(d.glob("*.jsonl")):
                        rp = str(p)
                        if rp in _synth_lead:
                            continue
                        if rp not in seen:
                            seen.add(rp)
                            yield p
    except (OSError, ValueError):
        return


def _norm_file(s: str) -> str:
    return s.replace("\\", "/").lstrip("./")


def _iter_glob(ws: Path, pattern: str):
    try:
        for p in ws.glob(pattern):
            if p.is_file():
                yield p
    except (OSError, ValueError):
        return


def _iter_json_records(path: Path):
    try:
        raw = path.read_text(encoding="utf-8", errors="replace")
    except (OSError, UnicodeError):
        return
    if path.suffix == ".jsonl":
        for line in raw.splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            try:
                obj = json.loads(line)
            except json.JSONDecodeError:
                continue
            if isinstance(obj, dict):
                yield obj
        return
    try:
        obj = json.loads(raw)
    except json.JSONDecodeError:
        return
    if isinstance(obj, list):
        for item in obj:
            if isinstance(item, dict):
                yield item
        return
    if not isinstance(obj, dict):
        return
    yielded = False
    for key in ("records", "results", "verdicts", "functions", "attacks", "rows"):
        items = obj.get(key)
        if isinstance(items, list):
            for item in items:
                if isinstance(item, dict):
                    yielded = True
                    yield item
    if not yielded:
        yield obj


def _parse_nested_sidecar_result(obj: dict) -> tuple:
    """Extract (applies_to_target, inner_dict) from a per-fn MIMO sidecar whose
    ``result`` field is a nested JSON string (the scoped-hunt schema).  Returns
    (None, None) when the field is absent, null, not a string, or not valid JSON.
    A failed sidecar (outer status != 'ok' or inner dict empty) also returns
    (None, None) - a rate-limited/errored task is NOT coverage of any kind.

    r36-rebuttal: funnel-generic-fixes-wave3
    """
    result_raw = obj.get("result")
    # r36-rebuttal: lane L37-FCC-REFERENCE-SCOPE-FIX registered in .auditooor/agent_pathspec.json
    # Accept ``result`` as EITHER a nested JSON string (the MIMO/haiku scoped-
    # hunt schema) OR an already-parsed dict (the spawn-worker Sonnet residual
    # schema emits {"result": {"applies_to_target": ...}} as a real object, not
    # a string). Previously a dict-form result returned (None, None), so a
    # source-cited verdict whose prose pointed at a DEFENDING line in another
    # file (e.g. getBarnPlan defended in LibReceiving.sol) could not be credited
    # via its function_anchor and stayed UNTOUCHED - a false-red.
    if isinstance(result_raw, dict):
        inner = result_raw
    elif isinstance(result_raw, str) and result_raw.strip():
        try:
            inner = json.loads(result_raw)
        except (json.JSONDecodeError, ValueError):
            return None, None
    else:
        return None, None
    if not isinstance(inner, dict):
        return None, None
    # Only credit sidecars from successful outer tasks.
    outer_status = str(obj.get("status") or "").lower()
    if outer_status not in ("ok", "success", ""):
        return None, None
    applies = str(inner.get("applies_to_target") or "").lower().strip()
    return applies or None, inner


def _structured_status_from_raw(raw: str) -> str:
    # r36-rebuttal: funnel-generic-fixes-wave3
    try:
        obj = json.loads(raw)
    except json.JSONDecodeError:
        return ""
    if not isinstance(obj, dict):
        return ""
    # Check top-level fields first (flat sidecar schema).
    for key in ("status", "verdict", "disposition"):
        status = _normalize_terminal_status(obj.get(key))
        if status in _TERMINAL_STATUSES:
            return status
    # Nested-result sidecar schema: result is a JSON string carrying the real
    # verdict inside an ``applies_to_target`` / ``severity_estimate`` payload.
    # A bare ``obj.get("result")`` call returns the raw string which
    # _normalize_terminal_status cannot parse as a terminal status token.
    applies, inner = _parse_nested_sidecar_result(obj)
    if inner is not None:
        # Extract the real verdict from the inner dict.
        for key in ("verdict", "disposition", "severity_estimate"):
            status = _normalize_terminal_status(inner.get(key))
            if status in _TERMINAL_STATUSES:
                return status
        # applies_to_target="no" with no explicit verdict = examined + ruled out.
        if applies == "no":
            return "ruled-out"
        # applies_to_target="yes" with no explicit terminal verdict is a live
        # candidate finding, not a clean verdict - return empty to let the
        # CONFIRMED_RE / EXECUTED_POC_RE scan below decide.
    return ""


def _harness_is_vacuous(text: str) -> bool:
    """A harness body is vacuous if it matches a vacuous marker AND has no
    OTHER real assertion. (assert(true) plus a real assert => not vacuous.)"""
    vac = any(rx.search(text) for rx in _vacuous_res())
    if not vac:
        return False
    # Count real assertions that are NOT the vacuous forms.
    real = 0
    for rx in _REAL_ASSERT_RES:
        for m in rx.finditer(text):
            seg = text[max(0, m.start() - 4): m.end() + 40]
            if re.search(r"\(\s*true\s*\)", seg):
                continue
            real += 1
    return real == 0


_UNDER_TEST_RE = re.compile(
    r"under test[:\s]+\S*?\b([A-Za-z_]\w*)\b\s+at\s+([\w./\\-]+\.\w+):(\d+)",
    re.IGNORECASE,
)


# Per-function entry marker: ``check_<name>`` / ``test_<name>`` /
# ``invariant_<name>`` / ``prove_<name>``. Compiled ONCE; the captured
# ``<name>`` group is collected into a set so a harness text is scanned a
# SINGLE time (not re.escape(name)-searched once per candidate function -
# that O(fns) re-scan was the 6399-unit/319-harness timeout: 9M+ full-text
# regex passes). See _harness_target_index.
_HARNESS_MARKER_RE = re.compile(r"\b(?:check|test|invariant|prove)_([A-Za-z_]\w*)\b")


def _harness_target_index(text: str):
    """Scan a harness body ONCE and return its target index:

      (explicit_pairs, marker_names)

    where ``explicit_pairs`` is the set of ``(name, file_basename)`` from any
    explicit ``Function under test: Type.name at file:line`` headers, and
    ``marker_names`` is the set of names referenced by a
    ``check_/test_/invariant_/prove_<name>`` entry.

    The membership semantics mirror _harness_targets_function exactly:
      - if explicit_pairs is non-empty, ONLY those (name, file_base) pairs are
        targeted (an explicit header that names no matching fn credits none);
      - otherwise a fn is targeted iff its name is in marker_names.

    Computing this once per harness file (instead of re-running both regexes
    over the full text for every one of N functions) turns Pass 2 from
    O(harness x fns x len(text)) into O(harness x len(text)).
    """
    explicit_pairs = set()
    for m in _UNDER_TEST_RE.finditer(text):
        explicit_pairs.add((m.group(1), Path(_norm_file(m.group(2))).name))
    marker_names = set()
    if not explicit_pairs:
        for m in _HARNESS_MARKER_RE.finditer(text):
            marker_names.add(m.group(1))
    return explicit_pairs, marker_names


def _index_targets_function(index, fn: Fn) -> bool:
    """O(1) replacement for _harness_targets_function using a precomputed
    (explicit_pairs, marker_names) index from _harness_target_index."""
    explicit_pairs, marker_names = index
    if explicit_pairs:
        return (fn.name, Path(_norm_file(fn.file)).name) in explicit_pairs
    return fn.name in marker_names


def _harness_targets_function(text: str, fn: Fn) -> bool:
    """Does this harness target fn? Prefer an explicit 'Function under test:
    Type.name at file:line' header and require BOTH the name AND the file to
    match fn (so an interface-targeted harness does not credit the impl, and
    vice versa). Falls back to a name-in-harness-context heuristic.

    NOTE: this single-fn form is retained for callers/tests that check one fn.
    The hot Pass-2 loop uses _harness_target_index + _index_targets_function so
    the harness text is scanned ONCE, not once per candidate function.
    """
    return _index_targets_function(_harness_target_index(text), fn)


def _record_file_line(row: dict) -> tuple[str, int | None]:
    raw = str(row.get("file_line") or row.get("source_line") or "")
    m = _FILE_LINE_RE.search(raw)
    if not m:
        return "", None
    return _norm_file(m.group(1)), int(m.group(2))


def _record_function(row: dict) -> str:
    raw = row.get("function") or row.get("fn") or row.get("name") or ""
    text = str(raw).strip()
    if "." in text:
        text = text.rsplit(".", 1)[-1]
    return text


def _record_matches_fn(row: dict, fn: Fn) -> bool:
    ref_file, ref_line = _record_file_line(row)
    if not ref_file or ref_line is None:
        return False
    if Path(ref_file).name != Path(_norm_file(fn.file)).name:
        return False
    fn_file = _norm_file(fn.file)
    if not (fn_file.endswith(ref_file) or ref_file.endswith(fn_file) or Path(ref_file).name == Path(fn_file).name):
        return False
    row_fn = _record_function(row)
    if row_fn != fn.name:
        return False
    return fn.line <= ref_line <= max(fn.end_line, fn.line)


def _load_provenance_module():
    """Load hunt-dispatch-provenance-check.py (the E4 synthetic-lead classifier).
    Returns the module or None. REUSE, never reimplement, the classifier."""
    try:
        import importlib.util as _ilu
        p = Path(__file__).resolve().with_name("hunt-dispatch-provenance-check.py")
        spec = _ilu.spec_from_file_location("_fcc_provenance", str(p))
        if spec is None or spec.loader is None:
            return None
        mod = _ilu.module_from_spec(spec)
        spec.loader.exec_module(mod)
        return mod if hasattr(mod, "classify_sidecar_provenance") else None
    except Exception:
        return None


# Per-workspace cache of the synthetic-lead sidecar-path set (computed once).
_SYNTH_LEAD_PATHS_CACHE: dict = {}


def _synthetic_lead_sidecar_paths(ws: Path) -> set:
    """G3: the set of sidecar-file paths (as str) classified ``synthetic-lead`` by
    the E4 provenance gate - an inline-authored / never-dispatched sidecar that
    CLAIMS a per-fn hunt but has NO spawn_worker dispatch receipt (the NUVA-437
    class). function-coverage must NOT grant real-attack credit from these:
    crediting a fabricated hunt as coverage is the exact false-green E4 was built
    to kill on the hunt-coverage plane; here we close the SAME leak on the
    function-coverage plane.

    FAIL-OPEN: if the classifier is unavailable (old checkout / import error) this
    returns an EMPTY set, so absence never demotes (byte-identical to pre-G3 on a
    workspace without the provenance lib). NEVER-FALSE-FLAG: a non-hunt artifact
    classifies as ``not-coverage-claiming`` (not synthetic-lead) and is never
    demoted; a file ALSO backed by a genuine sibling is protected at the per-row
    level (a function credited by ANY authentic sidecar row stays credited).
    Default-ON (no env gate) per operator decision 2026-07-11."""
    key = str(ws.resolve())
    if key in _SYNTH_LEAD_PATHS_CACHE:
        return _SYNTH_LEAD_PATHS_CACHE[key]
    synth: set = set()
    mod = _load_provenance_module()
    if mod is None:
        _SYNTH_LEAD_PATHS_CACHE[key] = synth
        return synth
    try:
        receipt_tokens = mod._ws_dispatch_receipt_tokens(ws)
    except Exception:
        receipt_tokens = set()
    try:
        dispatch_windows = mod._ws_confirmed_dispatch_windows(ws)
    except Exception:
        dispatch_windows = []
    for scdir in (ws / ".auditooor" / "hunt_findings_sidecars",
                  ws / "hunt_findings_sidecars"):
        if not scdir.is_dir():
            continue
        # RECURSIVE (rglob) to mirror the recursive `**` evidence globs
        # (_REAL_EVIDENCE_GLOBS) and the canonical E4 rglob: a synthetic-lead
        # sidecar placed in a SUBDIR is yielded by the credit loops, so the
        # exclusion set must be a superset of every path they can yield.
        for path in sorted(scdir.rglob("*.json")):
            try:
                data = json.loads(path.read_text(encoding="utf-8", errors="replace"))
            except (OSError, ValueError):
                continue
            if not isinstance(data, dict):
                continue
            try:
                cls = mod.classify_sidecar_provenance(
                    path, data, receipt_tokens, dispatch_windows)
            except TypeError:
                cls = mod.classify_sidecar_provenance(path, data, receipt_tokens)
            except Exception:
                cls = {"status": "authentic"}
            if str(cls.get("status")) == "synthetic-lead":
                synth.add(str(path))
    _SYNTH_LEAD_PATHS_CACHE[key] = synth
    return synth


def _apply_per_function_terminal_records(ws: Path, fns: list) -> None:
    if not fns:
        return
    _synth_lead = _synthetic_lead_sidecar_paths(ws)
    for pattern in _PER_FUNCTION_RECORD_GLOBS:
        for path in _iter_glob(ws, pattern):
            # G3: a synthetic-lead sidecar (claims a hunt, no dispatch receipt) must
            # not grant real-attack credit. Skip it; a function ALSO backed by a
            # genuine sidecar is still credited by that genuine row.
            if str(path) in _synth_lead:
                continue
            for row in _iter_json_records(path) or ():
                if row.get("schema") == "auditooor.per_function_attack_worklist.v1" and "function" not in row:
                    continue
                status = _normalize_terminal_status(
                    row.get("status") or row.get("verdict") or row.get("disposition") or row.get("result")
                )
                if status not in _TERMINAL_STATUSES:
                    continue
                if not _row_has_terminal_evidence(row, status, ws):
                    continue
                for fn in fns:
                    if not _record_matches_fn(row, fn):
                        continue
                    fn.classification = "real-attack"
                    label = "terminal-clean" if status in _TERMINAL_CLEAN_STATUSES else "terminal-attack"
                    fn.evidence.append(f"per-function-{label}:{path.name}:{status}:{fn.line}")


# --------------------------------------------------------------------------
# Declarative-language (Oscript AA) sidecar credit
# --------------------------------------------------------------------------
# Extractable languages credit a per-fn hunt sidecar via a file:line / anchor-LINE
# span match (the Pass-1 + function_anchor loops in _classify). Declarative-language
# units seeded from the manifest carry NO decl line (the AA enumerator emits
# line=null), so a line-span match is structurally impossible - a hunt sidecar for
# them names the case/getter by its free-text LABEL instead. This pass credits a
# seeded declarative unit when a hunt sidecar (a) anchors the SAME file AND (b)
# tolerantly names the unit's fn, applying the SAME verdict->classification policy
# the .sol function_anchor loop uses:
#   applies=no  + source-cited file_line (not R76-flagged) -> real-attack (examined + ruled-out)
#   applies=yes + CONFIRMED / executed-PoC transcript       -> real-attack
#   otherwise (bare-prose / dropped disposition)            -> hollow
# A declarative unit NOT named by any sidecar stays untouched (no over-credit).
_DECL_FL_CITE_RE = re.compile(r"\.\w+:L?\d+")

# Leading canonical case token. The separator between ``case`` and the number is
# tolerant: a space (``case 17``), an underscore (``case_12``, ``case_16_edit``),
# or a bracket (``messages.cases[0]``). ``re.search`` returns the FIRST (leading)
# match scanning left-to-right, so a trailing digit inside a descriptive suffix
# (e.g. the ``2`` in ``case_1_stake_2_tokens``) is never picked. The ``\b`` guard
# stops ``usecase5`` etc. from matching.
_CANON_CASE_RE = re.compile(r"\bcases?[\s_]*\[?\s*(\d+)")
# Leading getter token: a ``$identifier`` at the head of the (parenthetical-
# stripped) name. Getter unit keys are ``$name``.
_CANON_GETTER_RE = re.compile(r"^\$([a-z_][a-z0-9_]*)")
# A bare single-identifier keyword unit (``init`` / ``messages`` / ``set_nickname``).
_CANON_KEYWORD_RE = re.compile(r"^[a-z_][a-z0-9_]*$")


def _canonical_decl_key(raw: str):
    """Reduce a declarative unit key OR a free-text hunt-sidecar function anchor
    to a single comparable canonical token, so a DESCRIPTIVE anchor and the
    canonical unit key compare equal. Two sides are matched iff their canonical
    tokens are equal (see ``_declarative_unit_matches_anchor``).

    Mappings::

        'case_12 (end rental, called by anyone)' -> 'case_12'
        'case 17 (edit user)'                    -> 'case_17'
        'case_16_edit_plot'                      -> 'case_16'
        'messages.cases[0] (define ...)'         -> 'case_0'
        '$get_variables'                         -> '$get_variables'
        'init' / 'set_nickname'                  -> 'init' / 'set_nickname'

    FAIL-SAFE: a name that reduces to neither a ``case_N`` nor a ``$getter`` nor
    a single bare identifier keyword returns ``None`` and is therefore NEVER
    credited (a multi-word prose blob, a slash-list, an empty string). The
    leading-token rule guarantees NO over-credit: ``case_12`` never yields
    ``13``, so it can never canonically equal unit ``case_13``."""
    if not raw:
        return None
    s = raw.strip().lower()
    # strip a trailing ' (...)' parenthetical / descriptive tail before the
    # getter/keyword reductions (the case regex tolerates the tail itself).
    s_nop = re.sub(r"\s*\(.*$", "", s).strip()
    m = _CANON_CASE_RE.search(s)
    if m:
        return f"case_{int(m.group(1))}"
    m = _CANON_GETTER_RE.match(s_nop)
    if m:
        return f"${m.group(1)}"
    if _CANON_KEYWORD_RE.match(s_nop):
        return s_nop
    return None


def _declarative_unit_matches_anchor_canonical(fn_name: str, anchor_text: str) -> bool:
    """Strict canonical-equality match: canonical(unit) == canonical(anchor).
    Fail-safe - if either side is uncanonicalizable, no match (never credit)."""
    cu = _canonical_decl_key(fn_name)
    if cu is None:
        return False
    ca = _canonical_decl_key(anchor_text)
    return ca is not None and cu == ca


def _declarative_anchor_tokens(anchor_text: str) -> tuple:
    """Extract tolerant match tokens from a free-text declarative function_anchor.
    Anchors are short case/getter LABELS (a slash-separated list), e.g.
    ``$get_rewards / $are_eligible``, ``messages.cases[8] (mint or redeem tokens)``,
    ``has_attestation / distribute``. Returns (case_nums, identifier_words, segments)."""
    al = (anchor_text or "").lower()
    cases = set(m.group(1) for m in re.finditer(r"cases?\s*\[?\s*(\d+)", al))
    words = set(re.findall(r"[a-z_][a-z0-9_]*", al))
    segs = set(re.sub(r"[^a-z0-9_]+", " ", s).strip() for s in al.split("/"))
    return cases, words, segs


def _declarative_unit_matches_anchor(fn_name: str, tokens: tuple) -> bool:
    cases, words, segs = tokens
    m = re.match(r"^case_(\d+)$", fn_name)
    if m:
        # message-case unit ``case_N`` <- a ``messages.cases[N]`` reference (exact N).
        return m.group(1) in cases
    if fn_name.startswith("$"):
        # getter unit ``$name`` <- the bare identifier ``name`` appears as a whole
        # word (authors write it with OR without the ``$``). Getter names are unique
        # multi-char identifiers, so a whole-word identifier match is precise.
        return fn_name[1:].lower() in words
    # init / message-handler / other: require an exact slash-SEGMENT (avoids a
    # short-word substring false credit like ``init`` inside "init error checks").
    return fn_name.lower() in segs


def _apply_declarative_sidecar_credit(ws: Path, fns: list) -> None:
    decl_fns = [fn for fn in fns if _norm_lang(fn.lang) in _MANIFEST_SEED_LANGS]
    if not decl_fns:
        return
    by_base: dict = {}
    for fn in decl_fns:
        by_base.setdefault(Path(_norm_file(fn.file)).name, []).append(fn)
    for p in _pass1_evidence_paths(ws):
        try:
            raw = p.read_text(encoding="utf-8", errors="replace")
        except (OSError, UnicodeError):
            continue
        try:
            obj = json.loads(raw)
        except (json.JSONDecodeError, ValueError):
            continue
        if not isinstance(obj, dict):
            continue
        anchor = obj.get("function_anchor")
        if isinstance(anchor, str):
            try:
                anchor = json.loads(anchor)
            except (json.JSONDecodeError, ValueError):
                anchor = None
        if not isinstance(anchor, dict):
            continue
        anc_file = _norm_file(str(anchor.get("file") or ""))
        if Path(anc_file).suffix.lower() not in _DECL_EXTS:
            continue
        group = by_base.get(Path(anc_file).name)
        if not group:
            continue
        # R-DECL-SAME-FILE: the module docstring above promises a declarative
        # sidecar credits a unit only when it "anchors the SAME file", but the
        # basename-only bucket above is blind to directory - sibling AA dirs
        # that reuse an identical filename (e.g. src/{city,coop,friend}-aa/
        # governance.oscript, or src/{perpetual,prediction-markets}-aa/
        # factory.oscript) collide in the same bucket, so a sidecar correctly
        # anchored at one dir's unit can mis-credit a same-named unit in a
        # SIBLING dir instead (confirmed: oscriptaa-lane4-friend-aa-case_0_
        # commit_new_value_friend_governance.json anchors src/friend-aa/
        # governance.oscript:case_0 but ended up crediting src/city-aa/
        # governance.oscript's case_0, leaving the actually-analyzed friend-aa
        # unit untouched - a false-green/false-negative pair). When the anchor
        # supplies a real directory-qualified path (not a bare basename),
        # narrow the bucket to the fn(s) whose OWN file exactly matches it
        # first; this can only SHRINK the candidate set (never grows it), so
        # a legacy bare-basename anchor (no "/") keeps its old tolerant
        # behavior byte-identical. r36-rebuttal: n/a - additive precision only.
        if "/" in anc_file:
            exact = [fn for fn in group
                     if _norm_file(fn.file) == anc_file
                     or _norm_file(fn.file).endswith("/" + anc_file)
                     or anc_file.endswith("/" + _norm_file(fn.file))]
            if exact:
                group = exact
        anchor_fn = str(anchor.get("fn") or anchor.get("function") or "")
        tokens = _declarative_anchor_tokens(anchor_fn)
        try:
            anchor_line = int(anchor.get("line"))
        except (TypeError, ValueError):
            anchor_line = None
        applies, inner = _parse_nested_sidecar_result(obj)
        if inner is None:
            continue
        fp_dropped = bool(_DISCARDED_DISPOSITION_RE.search(raw))
        inner_term = _normalize_terminal_status(
            inner.get("verdict") or inner.get("disposition")
            or inner.get("severity_estimate"))
        inner_clean = inner_term in _TERMINAL_CLEAN_STATUSES
        if applies == "yes" and not inner_clean:
            inner_confirmed = bool(_CONFIRMED_RE.search(json.dumps(inner))
                                   or _EXECUTED_POC_RE.search(raw))
            credit = "real-attack" if (inner_confirmed and not fp_dropped) else "hollow"
        else:
            # applies=no OR a clean terminal verdict: covered iff the rule-out is
            # source-cited (a file_line, not R76-hallucinated) and not FP-dropped.
            cited_fl = str(inner.get("file_line") or "")
            r76_fail = bool(inner.get("r76_source_existence_fail"))
            has_cite = bool(_DECL_FL_CITE_RE.search(cited_fl))
            credit = ("real-attack"
                      if ((not fp_dropped) and (not r76_fail) and has_cite)
                      else "hollow")
        # Resolve the set of unit fns this sidecar credits. Two match paths,
        # UNIONed (a match by either credits - so already-matching clean names
        # keep their credit, behavior-preserving):
        #   (1) legacy tolerant token match (getter word / slash-segment /
        #       space+bracket case forms) - unchanged.
        #   (2) NEW strict canonical-equality match (canonical(unit) ==
        #       canonical(anchor)). This closes the descriptive-anchor join gap:
        #       'case_12 (end rental...)' / 'case_16_edit_plot' now credit unit
        #       case_12 / case_16, which the underscore-blind legacy regex missed.
        # Over-credit safety: the canonical token is the LEADING case_N only, so
        # 'case_12 ...' can never equal unit case_13. Fail-safe: an
        # uncanonicalizable anchor contributes nothing via path (2).
        targets = {fn.name: fn for fn in group
                   if _declarative_unit_matches_anchor(fn.name, tokens)}
        canon_hits = [fn for fn in group
                      if _declarative_unit_matches_anchor_canonical(fn.name, anchor_fn)]
        if canon_hits:
            # Line-proximity tiebreak: when >1 units canonicalize to this
            # anchor's key in the same file (rare; keys are ~unique), credit only
            # the one whose decl line is closest to the sidecar's anchor line. If
            # there is no anchor line to disambiguate an ambiguous >1 set, fail
            # safe and skip path (2) for it (never spray credit across units).
            if len(canon_hits) == 1:
                targets.setdefault(canon_hits[0].name, canon_hits[0])
            elif anchor_line is not None:
                best = min(canon_hits,
                           key=lambda fn: abs((fn.line or 0) - anchor_line))
                targets.setdefault(best.name, best)
        for fn in targets.values():
            if credit == "real-attack":
                if fn.classification != "real-attack":
                    fn.classification = "real-attack"
                fn.evidence.append(f"decl-sidecar-covered:{p.name}:{fn.name}")
            else:
                if fn.classification == "untouched":
                    fn.classification = "hollow"
                fn.evidence.append(f"decl-sidecar-hollow:{p.name}:{fn.name}")


# --------------------------------------------------------------------------
# Classification
# --------------------------------------------------------------------------
def _classify(ws: Path, fns: list, *, mutation_verify: bool = False,
              strict: bool = False) -> dict:
    """Classify each fn. Returns a small meta dict (mutation-backend status)
    so the caller can surface it in the report. ``mutation_verify`` upgrades
    the harness-derived real-attack bar to require a mutation-kill. ``strict``
    (AUDITOOOR_L37_STRICT) makes the default (no-mutation) bar refuse to stamp
    real-attack on a sentinel-only harness body (E3.1)."""
    meta: dict = {"mutation_verify": bool(mutation_verify),
                  "strict": bool(strict),
                  "mutation_backend": "not-requested"}
    if not fns:
        return meta

    # Load mutation verdicts up-front (once) when the bar is enabled.
    mut_by_fn: dict = {}
    mut_by_harness: dict = {}
    mut_available = False
    if mutation_verify:
        loaded = _load_mutation_verdicts(ws)
        if loaded is _MUTATION_BACKEND_UNAVAILABLE:
            meta["mutation_backend"] = "unavailable"
        else:
            mut_by_fn, mut_by_harness = loaded
            mut_available = True
            meta["mutation_backend"] = "available"
            meta["mutation_verdicts"] = {
                "functions": len(mut_by_fn), "harnesses": len(mut_by_harness),
            }
        # E3.4 - backend-unavailable handling, per language sub-tree.
        # solidity/rust/go ship a built-in mutation runner: an absent backend
        # under STRICT is FATAL (a real producer should exist). move/cairo/
        # circom/noir have NO built-in circuit/resource mutation runner: emit a
        # TYPED <lang>-mutation-runner-absent verdict + a waiver path (never a
        # silent pass, never an un-waivable brick). Distinguish the two so a
        # buildable language never blanket-greens and an unbuilt one never bricks.
        if not mut_available:
            present = {fn.lang for fn in fns}
            runner_langs = sorted(present & _MUT_RUNNER_LANGS)
            absent_langs = sorted(present & _MUT_RUNNER_ABSENT_LANGS)
            meta["mutation_runner"] = {
                "languages_present": sorted(present),
                "with_builtin_runner": runner_langs,
                "without_builtin_runner": absent_langs,
            }
            if runner_langs and strict:
                # A backed language with no producer is a hard error under STRICT.
                meta["mutation_backend_verdict"] = "fail-mutation-backend-unavailable"
                meta["mutation_backend_fatal_langs"] = runner_langs
            if absent_langs:
                # Typed absent verdict + waiver path (cross-cutting rule 3).
                meta["mutation_runner_absent"] = [
                    {
                        "lang": lang,
                        "verdict": f"{_RUNNER_ABSENT_VERDICT.get(lang, lang)}",
                        "waiver_env": _RUNNER_WAIVER_ENV.get(
                            lang, f"AUDITOOOR_MVC_RUNNER_{lang.upper()}"),
                        "waiver_substitute": _RUNNER_WAIVER_HINT.get(lang, ""),
                    }
                    for lang in absent_langs
                ]
    by_file: dict = {}
    for fn in fns:
        by_file.setdefault(_norm_file(fn.file), []).append(fn)
    name_index: dict = {}
    for fn in fns:
        name_index.setdefault(fn.name, []).append(fn)

    # r36-rebuttal: lane FCC-ANCHOR-FILELINE-FALLBACK registered in .auditooor/agent_pathspec.json
    # Per-basename sorted decl lines, for line-only anchor ownership. Body-pack /
    # residual hunt sidecars cite a BODY line with an empty function_anchor.fn,
    # and fn records often carry NO end_line, so strict span containment misses a
    # cite one line past the decl. The owning fn for a cited line is the one with
    # the greatest decl line <= cite in the same file, bounded by the next fn's
    # decl line (so a cite between two fns is NOT mis-credited to either).
    _base_decls: dict = {}
    for fn in fns:
        _base_decls.setdefault(Path(_norm_file(fn.file)).name, []).append((fn.line, fn))
    for _b in _base_decls:
        _base_decls[_b].sort(key=lambda t: t[0])

    def _owning_fn_for_line(base: str, line: int):
        arr = _base_decls.get(base)
        if not arr:
            return None
        owner = None
        for i, (dl, fn) in enumerate(arr):
            if dl <= line:
                nxt = arr[i + 1][0] if i + 1 < len(arr) else None
                if nxt is None or line < nxt:
                    owner = fn
            elif dl > line:
                break
        return owner

    _apply_cached_mutation_records(ws, fns)
    _apply_per_function_terminal_records(ws, fns)
    # Declarative-language (Oscript AA) per-fn hunt-sidecar credit. No-op unless the
    # workspace has manifest-seeded declarative units (fn.lang in _MANIFEST_SEED_LANGS);
    # extractable-language (.sol/.go/.rs/...) fns are never in that set, so this is
    # byte-identical for them.
    _apply_declarative_sidecar_credit(ws, fns)

    def _file_matches(norm: str, ref_file: str) -> bool:
        # refs may be ws-relative, repo-relative, or bare basenames. Match by
        # basename equality OR path-suffix containment.
        if Path(norm).name != Path(ref_file).name:
            return False
        return norm.endswith(ref_file) or ref_file.endswith(norm) or True

    # --- Pass 1: per-function attack evidence (findings / dead-ends / poc). ---
    # Span-precise: a cited file:line marks ONLY the function whose body span
    # [decl_line, end_line] contains the cited line. A record is REAL-ATTACK
    # evidence only if it carries a CONFIRMED verdict OR an executed-PoC
    # signal; an analysis-only FP/DROP prose sidecar is HOLLOW (it references
    # the function but drove no executed, function-bound attack).
    for _combined_pass in (1,):  # single pass over combined ws + derived evidence
        for p in _pass1_evidence_paths(ws):
            try:
                raw = p.read_text(encoding="utf-8", errors="replace")
            except (OSError, UnicodeError):
                continue
            if not _ANY_VERDICT_RE.search(raw):
                continue
            structured_status = _structured_status_from_raw(raw)
            discarded = bool(_DISCARDED_DISPOSITION_RE.search(raw))
            if structured_status in _TERMINAL_CLEAN_STATUSES:
                discarded = True
            # A record is REAL-ATTACK evidence only if it is NOT a discarded
            # (DROP / FALSE-POSITIVE / informational) disposition AND it
            # carries either a CONFIRMED-exploit verdict or an executed-PoC
            # transcript. The discarded gate comes FIRST so a free-text
            # "...is confirmed but non-weaponizable" prose sentence in a
            # DROP sidecar cannot smuggle the record to real-attack
            # (the R76-style false-signal failure mode).
            if structured_status:
                is_real = (
                    structured_status in _TERMINAL_ATTACK_STATUSES
                    and not discarded
                    and bool(_EXECUTED_POC_RE.search(raw) or structured_status == "finding")
                )
            else:
                is_real = (not discarded) and bool(
                    _CONFIRMED_RE.search(raw) or _EXECUTED_POC_RE.search(raw)
                )
            tag = "attack" if is_real else "analysis-only"
            # r36-rebuttal: funnel-generic-fixes-wave4
            # A real-attack credit is GENUINE (survives the mutation_verify
            # over-credit downgrade) only when backed by an executed-PoC transcript
            # (_EXECUTED_POC_RE: --- PASS:/[PASS]/counterexample/...) or a structured
            # terminal-ATTACK finding - NOT a prose-only _CONFIRMED_RE claim (the
            # morpho-midnight false-green class: prose "confirmed" with no PoC).
            poc_backed = bool(_EXECUTED_POC_RE.search(raw))  # r36-rebuttal: funnel-generic-fixes-wave4
            # r36-rebuttal: lane-funcov-clean-trivial-credit (near-intents step-3, 2026-06-24)
            # A STRUCTURED clean terminal verdict (ruled-out/no-finding/clean/no-exploit,
            # e.g. from a source-verified per-fn hunt KILL/NEGATIVE) that is NOT a
            # DROP/FP-by-reasoning disposition is adequate coverage for a GENUINELY
            # TRIVIAL one-line body (accessor / direct delegation) - you cannot
            # meaningfully attack a `&self.x` getter. This matches the tool's own
            # _row_has_terminal_evidence (which already credits clean+trivial) and the
            # morpho-midnight one-line-getter precedent, fixing the Pass-1 inconsistency
            # where clean verdicts were UNCONDITIONALLY downgraded to hollow. NEVER a
            # false-pass: a NON-trivial body (control-flow/loop/guard/>1 statement) with
            # a clean prose verdict still falls to hollow (R80 preserved) - it needs real
            # PoC/harness evidence.
            is_clean_terminal = (
                structured_status in _TERMINAL_CLEAN_STATUSES
                and not bool(_DISCARDED_DISPOSITION_RE.search(raw))
            )
            # MIMO flat-schema serving-join (axelar-dlt 2026-07-12): a per-fn hunt
            # sidecar that carries its rule-out as a TOP-LEVEL applies_to_target="no"
            # + source-cited file_line but NO nested function_anchor dict and NO
            # explicit verdict/disposition field lands here with structured_status=''
            # (empty), so is_real=False and is_clean_terminal=False -> it would fall
            # to hollow even though it is a genuine source-cited FP-defended per-fn
            # rule-out. Mirror the SAME policy the nested-anchor path applies
            # (applies=no + source-cited file_line, not R76-flagged, not a DROP ->
            # real-attack). Guarded to a SINGLE-RECORD dict file (avoids a JSONL
            # worklist where one row's applies=no cross-contaminates another row's
            # file_line cite). R80-safe: needs applies=no AND a same-file file_line
            # cite (matched below) AND fn-name-in-record AND not a DROP/R76-flag.
            _flat_rec = None
            try:
                _fp = json.loads(raw)
                if isinstance(_fp, dict):
                    _flat_rec = _fp
            except Exception:
                _flat_rec = None
            _top_applies_no = bool(
                _flat_rec
                and str(_flat_rec.get("applies_to_target") or "").strip().lower() == "no"
            )
            _top_r76_fail = bool(_flat_rec and _flat_rec.get("r76_source_existence_fail"))
            matched_by_file_line = False
            for fm in _FILE_LINE_RE.finditer(raw):
                ref_file = _norm_file(fm.group(1))
                lo = int(fm.group(2))
                hi = int(fm.group(3)) if fm.group(3) else lo
                for norm, group in by_file.items():
                    if not _file_matches(norm, ref_file):
                        continue
                    for fn in group:
                        # Declarative-language units (line=0) are credited only by
                        # _apply_declarative_sidecar_credit (line-span is N/A).
                        if _norm_lang(fn.lang) in _MANIFEST_SEED_LANGS:
                            continue
                        span_end = max(fn.end_line, fn.line)
                        # the cited span overlaps this function's body span
                        if not (lo <= span_end and hi >= fn.line):
                            continue
                        matched_by_file_line = True
                        if is_real:
                            if fn.classification != "real-attack":
                                fn.classification = "real-attack"
                            fn.evidence.append(f"finding-{tag}:{p.name}:{lo}")
                            if poc_backed:  # r36-rebuttal: funnel-generic-fixes-wave4
                                fn.evidence.append(f"finding-genuine:{p.name}:{lo}")
                        elif (
                            is_clean_terminal
                            and re.search(r"\b" + re.escape(fn.name) + r"\b", raw)
                            and _body_is_trivial(ws, f"{norm}:{fn.line}")
                        ):
                            # source-verified PER-FUNCTION clean rule-out on a trivial
                            # one-line accessor IS adequate coverage (R80-safe: trivial
                            # only). The fn-name-in-record guard excludes cluster-level
                            # clean sweeps (no function anchor) from crediting an
                            # individual function on a bare file:line overlap.
                            if fn.classification != "real-attack":
                                fn.classification = "real-attack"
                            fn.evidence.append(
                                f"finding-clean-trivial:{p.name}:{lo}"
                            )
                        elif (
                            _top_applies_no
                            and not _top_r76_fail
                            and not discarded
                            and re.search(r"\b" + re.escape(fn.name) + r"\b", raw)
                        ):
                            # Flat MIMO rule-out: top-level applies_to_target=no +
                            # this same-file source cite (matched above) +
                            # fn-name-in-record. A source-cited FP-defended per-fn
                            # rule-out carried in the flat schema (no function_anchor,
                            # no verdict field). Mirrors the nested-anchor
                            # finding-fp-defended-anchor credit. R80-safe: bare-prose
                            # (no applies=no) and DROP/R76-flagged records fall to
                            # hollow via the else branch below.
                            if fn.classification != "real-attack":
                                fn.classification = "real-attack"
                            fn.evidence.append(
                                f"finding-fp-defended-flat:{p.name}:{lo}"
                            )
                        else:
                            if fn.classification == "untouched":
                                fn.classification = "hollow"
                            fn.evidence.append(f"finding-{tag}:{p.name}:{lo}")

            # --- Nested-result sidecar fallback (function_anchor matching) ---
            # Per-fn MIMO/haiku hunt sidecars carry verdict + applies_to_target
            # inside a nested JSON string in the ``result`` field, and
            # file_line is often "NA" so the _FILE_LINE_RE scan above yields
            # zero matches.  When that happens, use ``function_anchor`` - which
            # carries the exact file path + fn name + line range - to credit the
            # right function directly.
            #
            # applies_to_target=no  -> examined + ruled out -> hollow (not untouched)
            # applies_to_target=yes -> real candidate finding -> real-attack only if
            #                          the inner result carries a CONFIRMED verdict
            #                          or executed-PoC signal.
            #
            # A failed/errored sidecar (outer status != ok) produces
            # (None, None) from _parse_nested_sidecar_result and is skipped.
            # r36-rebuttal: funnel-generic-fixes-wave3
            #
            # r36-rebuttal: lane L37-FCC-REFERENCE-SCOPE-FIX registered in .auditooor/agent_pathspec.json
            # Run the function_anchor credit UNCONDITIONALLY (not only when the
            # file:line scan found nothing). A per-function sidecar's
            # function_anchor is the AUTHORITATIVE subject of the verdict; when
            # its prose cites a DEFENDING line in a different in-scope contract
            # (e.g. getBarnPlan whose defense lives in LibReceiving.sol), the
            # file:line scan matches that OTHER file and previously suppressed
            # the anchor pass, leaving the anchored function UNTOUCHED despite a
            # real on-disk verdict. The anchor loop only ever credits the fn
            # whose name+file match the anchor and never downgrades an existing
            # real-attack, so running it always is safe.
            if True:
                try:
                    outer = json.loads(raw)
                except (json.JSONDecodeError, ValueError):
                    outer = None
                if isinstance(outer, dict):
                    applies, inner = _parse_nested_sidecar_result(outer)
                    if applies is not None and inner is not None:
                        # Resolve function_anchor to a (file, fn_name, lo, hi).
                        anchor = outer.get("function_anchor")
                        if isinstance(anchor, str):
                            # Try to parse as JSON first (some anchors are
                            # JSON-serialised dicts stored as strings).
                            try:
                                anchor = json.loads(anchor)
                            except (json.JSONDecodeError, ValueError):
                                pass
                        anc_file = anc_fn = ""
                        anc_lo = anc_hi = 0
                        if isinstance(anchor, dict):
                            raw_afile = str(anchor.get("file") or "")
                            anc_file = _norm_file(raw_afile)
                            # r36-rebuttal: lane L37-FCC-REFERENCE-SCOPE-FIX registered in .auditooor/agent_pathspec.json
                            # Accept the canonical per-function sidecar schema
                            # keys (function_anchor.{function,line}) in addition
                            # to the older {fn,start_line,end_line}. The residual
                            # coverage sidecars (and the spawn-worker hunt schema)
                            # emit {file, function, line}; without these aliases
                            # the anchor parse yields anc_fn="" and the function
                            # is left UNTOUCHED despite a real source-cited
                            # verdict on disk (false-red).
                            anc_fn = str(anchor.get("fn") or anchor.get("function") or "")
                            try:
                                anc_lo = int(anchor.get("start_line")
                                             or anchor.get("line") or 0)
                                anc_hi = int(anchor.get("end_line")
                                             or anchor.get("line") or anc_lo)
                            except (TypeError, ValueError):
                                pass
                        elif isinstance(anchor, str) and anchor.strip():
                            # String form: "fnName @ File.sol:lo-hi" or
                            # "File.sol:fnName" - best-effort parse.
                            am = re.match(
                                r"(\w[\w.]*)\s*@\s*([\w./\\-]+\.\w+):(\d+)(?:-(\d+))?",
                                anchor.strip(),
                            )
                            if am:
                                anc_fn = am.group(1)
                                anc_file = _norm_file(am.group(2))
                                anc_lo = int(am.group(3))
                                anc_hi = int(am.group(4)) if am.group(4) else anc_lo
                        # r36-rebuttal: lane FCC-ANCHOR-FILELINE-FALLBACK registered in .auditooor/agent_pathspec.json
                        # Body-pack / residual hunt sidecars emit
                        # function_anchor={file, fn:''} with NO line, but carry a
                        # real "file:line" cite at top-level/inner ``file_line``.
                        # Without a line the (anc_fn or anc_lo>0) guard below skips
                        # the whole credit and the source-cited rule-out falls
                        # through to hollow (false-red). Recover the line (and file,
                        # if the anchor lacked it) from the file_line cite. This only
                        # RESOLVES the anchor; the credit policy (has_source_cite,
                        # not-fp-dropped, R76-not-failed) below is unchanged.
                        if anc_lo <= 0:
                            for _fl_src in (outer.get("file_line"),
                                            inner.get("file_line")):
                                _flm = re.search(r"([\w./\\-]+\.\w+):L?(\d+)",
                                                 str(_fl_src or ""))
                                if _flm:
                                    if not anc_file:
                                        anc_file = _norm_file(_flm.group(1))
                                    anc_lo = int(_flm.group(2))
                                    anc_hi = anc_lo
                                    break
                        if anc_file and (anc_fn or anc_lo > 0):
                            anc_base = Path(anc_file).name
                            for fn in fns:
                                # Declarative-language units (line=0) are credited only
                                # by _apply_declarative_sidecar_credit (tolerant fn match);
                                # the name/line anchor logic here does not fit them.
                                if _norm_lang(fn.lang) in _MANIFEST_SEED_LANGS:
                                    continue
                                fn_base = Path(_norm_file(fn.file)).name
                                # Match by exact function NAME, or - when the bridge
                                # synthesized a slugified/absent name - by LINE. The
                                # cited line may be the decl line OR a body line (an
                                # agent commonly cites the guard/require it ruled out,
                                # e.g. Foo.sol:L95 inside a function declared at L91).
                                # So accept any cited line that falls WITHIN the
                                # function's span; the span check below confirms
                                # containment (one non-nested fn per line in Solidity,
                                # so this is unambiguous). Skip only when there is
                                # neither a name match nor any usable line.
                                if fn.name != anc_fn and anc_lo <= 0:
                                    continue
                                if fn_base != anc_base:
                                    continue
                                # Overlapping span check: be lenient when anchor
                                # lines are 0 (unknown) - name match alone is
                                # enough for functions with unique names in
                                # their file.
                                if anc_lo > 0 and anc_hi > 0:
                                    if not anc_fn:
                                        # r36-rebuttal: lane FCC-ANCHOR-FILELINE-FALLBACK registered in .auditooor/agent_pathspec.json
                                        # Line-only anchor (no fn name): credit the
                                        # fn that OWNS the cited line, not strict
                                        # span containment (fn records often lack a
                                        # computed end_line, so a body-line cite one
                                        # past the decl would be missed).
                                        if _owning_fn_for_line(anc_base, anc_lo) is not fn:
                                            continue
                                    else:
                                        fn_span_end = max(fn.end_line, fn.line)
                                        if not (anc_lo <= fn_span_end
                                                and anc_hi >= fn.line):
                                            continue
                                # FC-FALSE-RED fix (hyperlane step-3, 2026-06-21): a
                                # clean terminal verdict (KILL -> ruled-out, no-finding)
                                # means the fn was examined and ruled out, REGARDLESS of
                                # applies_to_target. The canonical per-fn hunt emits
                                # verdict=KILL often WITH applies_to_target=yes (the
                                # hypothesis "applies" i.e. was checked, but is ruled
                                # out). Such records must route to the source-cited
                                # rule-out path below (credits real-attack on a file_line
                                # cite), NOT the "unconfirmed candidate -> hollow" branch.
                                inner_term = _normalize_terminal_status(
                                    inner.get("verdict")
                                    or inner.get("disposition")
                                    or inner.get("severity_estimate")
                                )
                                inner_clean = inner_term in _TERMINAL_CLEAN_STATUSES
                                if applies == "yes" and not inner_clean:
                                    # applies_to_target=yes: only credit as
                                    # real-attack if the inner result carries
                                    # a CONFIRMED exploit verdict. A bare
                                    # "applies=yes" candidate without executed
                                    # PoC is hollow (live hypothesis, not
                                    # driven proof).
                                    inner_raw = json.dumps(inner)
                                    inner_confirmed = bool(
                                        _CONFIRMED_RE.search(inner_raw)
                                        or _EXECUTED_POC_RE.search(inner_raw)
                                    )
                                    if inner_confirmed and not discarded:
                                        if fn.classification != "real-attack":
                                            fn.classification = "real-attack"
                                        fn.evidence.append(
                                            f"finding-attack-anchor:{p.name}:{anc_fn}"
                                        )
                                    else:
                                        # Candidate finding but no executed PoC
                                        # -> hollow (examined, not confirmed).
                                        if fn.classification == "untouched":
                                            fn.classification = "hollow"
                                        fn.evidence.append(
                                            f"finding-analysis-only-anchor:{p.name}:{anc_fn}"
                                        )
                                else:
                                    # applies_to_target=no: the function was
                                    # examined and the hypothesis was ruled out.
                                    # Check whether the inner result carries a
                                    # source-cited file:line in defending_lines.
                                    # If so, this is a FP-DEFENDED / source-traced
                                    # rule-out (the agent cited the exact code
                                    # location that makes the attack inapplicable)
                                    # and counts as real-attack coverage - R80
                                    # preserved because bare prose without a
                                    # file:line cite stays hollow.
                                    #
                                    # Note: do NOT gate on `discarded` here. The
                                    # outer `discarded` flag is True for the
                                    # `ruled-out` structured_status that comes from
                                    # applies_to_target=no itself (by design, to
                                    # prevent the file:line scan above from
                                    # crediting the defending file as real-attack
                                    # on a different function). The anchor pathway
                                    # is independent: function_anchor identifies
                                    # the SUBJECT, defending_lines the EVIDENCE.
                                    # A genuine DROP / FALSE-POSITIVE disposition
                                    # on the outer record still blocks credit -
                                    # re-check via _DISCARDED_DISPOSITION_RE on
                                    # raw (which does NOT match `ruled-out`).
                                    fp_dropped = bool(
                                        _DISCARDED_DISPOSITION_RE.search(raw)
                                    )
                                    defending = str(inner.get("defending_lines") or "")
                                    # The mega / workflow-drill per-fn hunt records its
                                    # source citation in `file_line` (+ code_excerpt), not
                                    # `defending_lines`, and uses an optional 'L' line prefix
                                    # ("file.rs:L57") that _FILE_LINE_RE does not match. Accept
                                    # that cite too. R80 preserved: an R76-flagged-hallucinated
                                    # cite (r76_source_existence_fail, set by hunt-sidecar-bridge)
                                    # stays hollow, and a bare-prose "no" with no file:line in
                                    # either field stays hollow.
                                    cited_fl = str(inner.get("file_line") or "")
                                    r76_fail = bool(inner.get("r76_source_existence_fail"))
                                    fl_has_cite = bool(re.search(r"\.\w+:L?\d+", cited_fl))
                                    # A `defending_lines` cite credits the SUBJECT only when it
                                    # points at the subject's OWN file. A cross-file defending
                                    # cite ("X is safe because of a mechanism in another file")
                                    # does NOT prove the subject itself was source-traced - the
                                    # defending function is credited on its own anchor; crediting
                                    # the subject too off one cross-file cite is a double-credit
                                    # false-green. The subject still counts when it carries its
                                    # OWN file_line cite (fl_has_cite, same-file by construction).
                                    defending_same_file = any(
                                        Path(dm.group(1)).name == anc_base
                                        for dm in _FILE_LINE_RE.finditer(defending)
                                    )
                                    has_source_cite = (
                                        defending_same_file
                                        or (not r76_fail and fl_has_cite)
                                    )
                                    if not fp_dropped and has_source_cite:
                                        # Source-cited FP-defended rule-out: real coverage.
                                        if fn.classification != "real-attack":
                                            fn.classification = "real-attack"
                                        fn.evidence.append(
                                            f"finding-fp-defended-anchor:{p.name}:{anc_fn}"
                                        )
                                    else:
                                        # Bare-prose "no" or dropped: hollow (not
                                        # untouched - the fn was examined but no
                                        # source-traced evidence supports the verdict).
                                        if fn.classification == "untouched":
                                            fn.classification = "hollow"
                                        fn.evidence.append(
                                            f"finding-analysis-only-anchor:{p.name}:{anc_fn}"
                                        )

    # --- Pass 2: hollow markers (vacuous harnesses) ---
    harness_files = []
    seen_paths = set()
    for pattern in _HARNESS_GLOBS:
        for p in _iter_glob(ws, pattern):
            if p in seen_paths:
                continue
            seen_paths.add(p)
            harness_files.append(p)
    for p in harness_files:
        try:
            txt = p.read_text(encoding="utf-8", errors="replace")
        except (OSError, UnicodeError):
            continue
        vacuous = _harness_is_vacuous(txt)
        # E3.2: consult the canonical shared sentinel-only detector on the
        # harness body BEFORE any real-attack credit (both bars). It is
        # per-language aware (testify / const-fold / zk soundness-vacuity) where
        # the local _VACUOUS_RES syntactic pre-filter is not, so it catches a
        # semantically-vacuous harness offline (no toolchain). Treated as an
        # OR-supplement: a body either local-vacuous OR shared-sentinel is hollow.
        sentinel_only = False
        if _is_sentinel_only_harness is not None:
            try:
                sentinel_only = bool(_is_sentinel_only_harness(txt))
            except Exception:  # noqa: BLE001 - detector must never break the gate
                sentinel_only = False
        # Scan the harness body ONCE for its targets, then visit ONLY the
        # candidate functions (looked up by name via name_index) instead of
        # re-running both target regexes over the full text for every one of
        # the ~30k in-scope functions. This is the 319-harness x 29k-fn O(N^2)
        # timeout fix: the index turns Pass 2 into O(harness x text + targets).
        h_index = _harness_target_index(txt)
        explicit_pairs, marker_names = h_index
        candidate_names = (
            {n for (n, _b) in explicit_pairs} if explicit_pairs else marker_names
        )
        candidate_fns = []
        for cname in candidate_names:
            candidate_fns.extend(name_index.get(cname, ()))
        for fn in candidate_fns:
            if fn.classification == "real-attack":
                continue
            if not _index_targets_function(h_index, fn):
                continue
            if vacuous or sentinel_only:
                # Local-vacuous OR shared sentinel-only -> hollow (E3.2). The
                # shared detector adds the per-language semantic catch (testify /
                # const-fold / zk soundness) the local syntactic filter misses.
                if fn.classification != "hollow":
                    fn.classification = "hollow"
                    why_v = "vacuous-harness" if vacuous else "sentinel-only-harness"
                    fn.evidence.append(f"{why_v}:{p.name}")
            else:
                # Syntactically non-vacuous harness that names the fn AND
                # lives in this file's contract. Under the default (fast) bar
                # this is real-attack. Under --mutation-verify the harness must
                # ALSO be mutation-killed (inject a bug -> harness fails);
                # a vacuous / no-baseline / unverified harness is HOLLOW even
                # though its body looks real. This is the language-agnostic
                # catch for semantically-vacuous halmos/echidna/forge/agent
                # harnesses (the morpho-midnight 32-harness bug).
                if mutation_verify:
                    if mut_available:
                        ok, why = _harness_mutation_ok(
                            mut_by_fn, mut_by_harness, fn, p.name)
                    else:
                        # backend unavailable: conservatively downgrade so a
                        # missing mutation tool can never silently pass.
                        ok, why = False, "mutation-backend-unavailable"
                    if ok:
                        fn.classification = "real-attack"
                        fn.evidence.append(f"harness:{p.name}({why})")
                    else:
                        if fn.classification != "hollow":
                            fn.classification = "hollow"
                        fn.evidence.append(f"vacuous-harness:{p.name}({why})")
                elif strict:
                    # E3.1: STRICT default bar (no --mutation-verify requested).
                    # Do NOT unconditionally stamp real-attack. Require EITHER a
                    # killed mutant (mutation-verify-coverage, if available) OR a
                    # shared-detector non-vacuous body. `sentinel_only` is already
                    # False here, so the body is shared-non-vacuous -> credit it.
                    # (If the detector lib is unimportable we credit, matching the
                    # fail-open import guard.) A killed-mutant present is also
                    # honoured when the mutation artifact happens to exist.
                    ok_mut = False
                    if mut_available:
                        ok_mut, _why = _harness_mutation_ok(
                            mut_by_fn, mut_by_harness, fn, p.name)
                    if ok_mut:
                        fn.classification = "real-attack"
                        fn.evidence.append(f"harness:{p.name}(strict-mutation-killed)")
                    elif _is_sentinel_only_harness is None or not sentinel_only:
                        fn.classification = "real-attack"
                        fn.evidence.append(f"harness:{p.name}(strict-non-vacuous)")
                    else:
                        if fn.classification != "hollow":
                            fn.classification = "hollow"
                        fn.evidence.append(f"sentinel-only-harness:{p.name}(strict)")
                else:
                    fn.classification = "real-attack"
                    fn.evidence.append(f"harness:{p.name}")

    # --- Pass 3: CCIA heuristic angles (hollow, never real) ---
    ccia_refs: dict = {}  # (file_basename_lower, fn_name) hint
    for pattern in _CCIA_GLOBS:
        for p in _iter_glob(ws, pattern):
            try:
                data = json.loads(p.read_text(encoding="utf-8", errors="replace"))
            except (OSError, ValueError):
                continue
            angles = data if isinstance(data, list) else data.get("angles") or data.get("attack_angles") or []
            if not isinstance(angles, list):
                continue
            for a in angles:
                if not isinstance(a, dict):
                    continue
                title = str(a.get("title", "")) + " " + str(a.get("description", ""))
                contracts = a.get("contracts") or []
                # Tokenize the title ONCE and visit ONLY functions whose name
                # appears as a whole word in it (via name_index), instead of
                # running ``\b<re.escape(fn.name)>\b`` over the title for every
                # one of the ~30k functions. A bare-identifier ``\bNAME\b``
                # match is exactly "NAME is one of the title's \w+ tokens", so
                # the set-membership form is equivalent (and the per-fn dynamic
                # regex was defeating Python's 512-entry pattern cache -> the
                # ~15s Pass-3 blowup on the 29k-fn injective workspace).
                title_tokens = set(_WORD_TOKEN_RE.findall(title))
                ccia_candidate_fns = []
                for tok in title_tokens:
                    ccia_candidate_fns.extend(name_index.get(tok, ()))
                for fn in ccia_candidate_fns:
                    if fn.classification == "real-attack":
                        continue
                    # CCIA titles look like "...: Contract.fnName"
                    cbase = Path(_norm_file(fn.file)).stem
                    if (not contracts) or any(cbase in str(c) or str(c) in cbase for c in contracts):
                        if fn.classification != "hollow":
                            fn.classification = "hollow"
                        fn.evidence.append(f"ccia-angle:{a.get('id', '?')}")

    # --- Final reconciliation: close the function-coverage OVER-credit false-green ---
    # r36-rebuttal: funnel-generic-fixes-wave4
    # Under mutation_verify (the producer file exists / operator opted in) the README
    # authority is mutation-verification: a function is genuinely "covered" only if a
    # harness KILLED >=1 injected mutant, OR a real finding was demonstrated for it.
    # Pass-2 enforces the kill bar for HARNESS-derived credits, but functions marked
    # real-attack by an EARLIER pass - Pass-1 prose (_CONFIRMED_RE) or terminal
    # "ruled-out" clean records - are skipped by Pass-2's
    # `if fn.classification == "real-attack": continue`, so prose / vacuous-harness
    # credits survived UNVERIFIED (morpho-midnight: 53/53 real-attack with 0/46 mutation
    # kills - a vacuous harness that merely PASSES is NOT a kill). Downgrade any
    # real-attack that lacks a genuine mutation-kill AND is not a demonstrated finding
    # to hollow. Scoped to mutation_verify so the default (no-backend) mode is unchanged.
    if mutation_verify:
        for fn in fns:
            if fn.classification != "real-attack":
                continue
            # r36-rebuttal: lane-funcov-clean-credit
            # Is THIS function's clean PoC proven-vacuous (mutants generated and
            # the harness survived them) or did it never run (no-baseline)? If so
            # the clean rule-out is NOT genuine coverage. "inconclusive"
            # (no mutable operators -> 0 mutants) or no verdict does NOT block the
            # credit - you cannot mutation-verify a body with nothing to mutate.
            fn_base = Path(_norm_file(fn.file)).name
            mv = (mut_by_fn.get(f"{fn_base}::{fn.name}")
                  or mut_by_fn.get(f"::{fn.name}")) if mut_available else None
            clean_is_disproven = mv in ("vacuous", "no-baseline")
            genuine = any(
                e.startswith("mutation-killed:")
                or (e.startswith("harness:") and "mutation-killed" in e)
                or e.startswith("per-function-terminal-attack:")
                # An evidence-gated reasoned RULE-OUT is genuine coverage. A
                # per-function-terminal-clean record only carries this label
                # after passing _row_has_terminal_evidence() (trivial body, or
                # PoC/test-backed: real poc_path + a [PASS] line + a named
                # invariant). The mutation-kill bar exists to kill VACUOUS-harness
                # real-ATTACK over-credits and PROSE _CONFIRMED claims - NOT to
                # force a harness onto every function already analysed clean. Per
                # the README funnel a harness is the PROVE step for a SURVIVING
                # candidate bug, not a precondition for a clean verdict. But a
                # clean PoC DISPROVEN by mutation (survived a real mutant) or that
                # never ran is still not coverage.
                or (e.startswith("per-function-terminal-clean:")
                    and not clean_is_disproven)
                # A source-cited FP-defended rule-out (Pass-1 function_anchor:
                # applies_to_target=no WITH a real file:line in defending_lines)
                # is an evidence-gated reasoned rule-out = genuine coverage, the
                # same class as per-function-terminal-clean. Per this gate's own
                # docstring "Pass 1 is unaffected - mutation-verification only
                # gates harness-derived coverage": you cannot mutation-verify a
                # ruled-out function (no attack/harness to inject a mutant into).
                # Gated on `not clean_is_disproven` so a rule-out a real mutant
                # later DISPROVED (vacuous/no-baseline) is still blocked - no
                # false-green; bare-prose rule-outs (finding-analysis-only-anchor)
                # were never credited real-attack in Pass 1 and stay hollow.
                or (e.startswith("finding-fp-defended-anchor:")
                    and not clean_is_disproven)
                # The FLAT-schema sibling of finding-fp-defended-anchor (top-level
                # applies_to_target=no + same-file source cite, no function_anchor
                # dict). Same evidence class - a source-cited reasoned rule-out you
                # cannot mutation-verify (no attack/harness to inject a mutant into).
                # Gated on `not clean_is_disproven` identically, so a rule-out a real
                # mutant later disproved stays blocked (no false-green). axelar-dlt
                # 2026-07-12: ValidateBasic (flat KILL) was downgraded to hollow under
                # mutation_verify because this label was missing from the allowlist.
                or (e.startswith("finding-fp-defended-flat:")
                    and not clean_is_disproven)
                # A source-verified TRIVIAL one-line accessor rule-out is genuine
                # coverage of the same class as per-function-terminal-clean. The
                # `finding-clean-trivial:` label is ONLY emitted after _body_is_trivial()
                # confirms a genuinely trivial body (a field getter / one-liner with no
                # control flow), and you cannot mutation-verify a body with nothing to
                # mutate (`fn k(&self) -> Scalar { self.k }`). The mutation-kill bar
                # exists to kill VACUOUS-harness over-credits and non-trivial value-moving
                # functions - not to force a harness onto a field accessor. Gated on
                # `not clean_is_disproven` so a (theoretical) mutant-disproven trivial
                # credit is still blocked - no false-green. near-intents 2026-06-26: 22
                # trivial FROST/channel/getter accessors were wrongly downgraded to hollow
                # under mutation_verify because this label was missing from the allowlist.
                or (e.startswith("finding-clean-trivial:")
                    and not clean_is_disproven)
                or e.startswith("finding-genuine:")  # executed-PoC / structured finding
                for e in (fn.evidence or [])
            )
            if not genuine:
                fn.classification = "hollow"
                fn.evidence.append("over-credit-downgrade-no-mutation-kill(wave4)")

    return meta


# --------------------------------------------------------------------------
# Evaluate
# --------------------------------------------------------------------------
def _resolve_src_roots(ws: Path) -> list:
    # Canonical source-root resolution: pick the DEEPEST candidate dir that
    # contains ALL the workspace source, so a Cargo workspace (crates/*) is not
    # mis-resolved to a thin src/src stub. See tools/lib/source_root_resolver.py.
    import importlib.util as _ilu
    _p = Path(__file__).resolve().parent / "lib" / "source_root_resolver.py"
    _s = _ilu.spec_from_file_location("auditooor_source_root_resolver", _p)
    _m = _ilu.module_from_spec(_s)
    _s.loader.exec_module(_m)
    return list(_m.resolve_src_roots(ws))


# r36-rebuttal: lane FIX-FCC-SCOPE-AUTHORITATIVE registered in .auditooor/agent_pathspec.json
def _load_inscope_file_set(ws: Path):
    """Return the AUTHORITATIVE in-scope file set from ``.auditooor/inscope_units.jsonl``
    (the manifest the hunt-worklist + heatmap gates already treat as scope truth), or
    ``None`` when no manifest exists (then no filtering - preserves legacy behavior).

    WHY: ``_resolve_src_roots`` walks the whole workspace, so on a multi-package monorepo
    with an authoritative scope (OP Stack: contracts-bedrock/src + op-node + op-dispute-mon
    + in-scope op-reth crates) the denominator was polluted with OUT-OF-SCOPE packages
    (kona, cannon, op-batcher, op-devstack, upstream reth crates, ...), inflating the
    'untouched' count ~5x and making the gate unwinnable for the wrong reason. Honoring the
    in-scope manifest restores a scope-correct denominator. Disable with
    AUDITOOOR_FCC_NO_SCOPE_FILTER=1.
    """
    import os as _os
    if _os.environ.get("AUDITOOOR_FCC_NO_SCOPE_FILTER"):
        return None
    manifest = ws / ".auditooor" / "inscope_units.jsonl"
    if not manifest.is_file():
        return None
    files = set()
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


def _load_scope_oos_fns():
    """Lazily import tools/lib/scope_oos_globs (load_oos_spec, is_oos).

    Returns ``(load_oos_spec, is_oos)`` or ``(None, None)`` when unavailable or
    disabled via AUDITOOOR_SCOPE_OOS=0. FAIL-OPEN: any import error -> None,None
    (no drops, behavior byte-identical).
    """
    import os as _os
    if _os.environ.get("AUDITOOOR_SCOPE_OOS") == "0":
        return (None, None)
    if getattr(_load_scope_oos_fns, "_cached", "unset") != "unset":
        return _load_scope_oos_fns._cached  # type: ignore[attr-defined]
    fns = (None, None)
    try:
        from tools.lib.scope_oos_globs import load_oos_spec, is_oos  # type: ignore
        fns = (load_oos_spec, is_oos)
    except Exception:  # noqa: BLE001
        try:
            _here = Path(__file__).resolve().parent / "lib"
            if str(_here) not in sys.path:
                sys.path.insert(0, str(_here))
            from scope_oos_globs import load_oos_spec, is_oos  # type: ignore
            fns = (load_oos_spec, is_oos)
        except Exception:  # noqa: BLE001 - fail-open
            fns = (None, None)
    _load_scope_oos_fns._cached = fns  # type: ignore[attr-defined]
    return fns


# r36-rebuttal: lane FIX-FCC-FN-GRANULARITY registered in .auditooor/agent_pathspec.json
def _load_inscope_fn_restrictions(ws: Path):
    """Return ``{norm_file: {fn_name, ...}}`` for files whose manifest rows are
    FUNCTION-LEVEL (carry a non-empty ``function``), restricting the denominator to
    exactly those functions - or ``None`` when no file has function-level scope.

    WHY: ``inscope_units.jsonl`` mixes granularities. The fork-scope step
    (fork-modified-files-scope) emits FILE-only rows for modified fork files
    (bor/cosmos-sdk/cometbft - the whole modified file is in scope), while the
    step-1 SC manifest emits FUNCTION-level rows for the Polygon-authored contracts
    (only the specific in-scope functions). ``_load_inscope_file_set`` collapses
    everything to a file set, so the gate then counts EVERY function in a
    function-scoped file (polygon: 1158 in-scope SC functions ballooned to all
    functions across their 121 files -> a ~6.5x denominator inflation that made the
    gate unwinnable for the wrong reason). This honors the manifest's own per-file
    granularity: a file with function-level rows is restricted to those functions; a
    file with any file-only row (no function) keeps ALL its functions (the fork
    whole-file decision). Backward-compatible: a purely file-level manifest yields
    no restrictions -> identical to the legacy file-set filter. Disable with
    AUDITOOOR_FCC_FILE_LEVEL_SCOPE=1.
    """
    import os as _os
    if _os.environ.get("AUDITOOOR_FCC_FILE_LEVEL_SCOPE"):
        return None
    manifest = ws / ".auditooor" / "inscope_units.jsonl"
    if not manifest.is_file():
        return None
    fn_map: dict = {}
    whole_file: set = set()
    for line in manifest.read_text(encoding="utf-8", errors="replace").splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            row = json.loads(line)
        except (json.JSONDecodeError, ValueError):
            continue
        f = str(row.get("file") or "").strip().lstrip("./").replace("\\", "/")
        if not f:
            continue
        fn = str(row.get("function") or "").strip()
        if fn:
            fn_map.setdefault(f, set()).add(fn)
        else:
            whole_file.add(f)  # any file-only row => whole file in scope
    # A file-only row overrides function-level rows for the SAME file (whole file).
    effective = {f: names for f, names in fn_map.items() if f not in whole_file}
    return effective or None


def _seed_manifest_declarative_units(ws: Path) -> list:
    """Seed Fn units for DECLARATIVE / DSL languages (lang in _MANIFEST_SEED_LANGS)
    directly from ``.auditooor/inscope_units.jsonl``.

    WHY: languages such as Obyte Oscript AAs (.oscript / .aa) have no
    ``function NAME(`` source-regex extractor (_FN_RE), so the source-walk in
    ``evaluate`` yields ZERO units for them and all their in-scope surface is
    silently dropped from the coverage denominator (every unit invisible/hollow).
    The language-specific enumerator already parsed the AA structure into
    ``{file, function, lang}`` manifest rows, so those rows ARE the authoritative
    unit list - seed them here. Only manifest rows whose NORMALIZED lang is a
    declarative-seed language are taken; the extractable languages (sol/rs/go/...)
    keep coming from the source walk, so their behavior is byte-identical.

    Manifest rows carry no reliable decl line for these languages (the AA
    enumerator emits line=null), so ``line``/``end_line`` are 0; crediting for
    these units is by FILE + tolerant fn-name match against hunt sidecars, not by
    line span (see _apply_declarative_sidecar_credit)."""
    manifest = ws / ".auditooor" / "inscope_units.jsonl"
    if not manifest.is_file():
        return []
    if not _MANIFEST_SEED_LANGS:
        return []
    out: list = []
    seen: set = set()
    for line in manifest.read_text(encoding="utf-8", errors="replace").splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            row = json.loads(line)
        except (json.JSONDecodeError, ValueError):
            continue
        lang = _norm_lang(row.get("lang"))
        if lang not in _MANIFEST_SEED_LANGS:
            continue
        f = _norm_file(str(row.get("file") or "").strip())
        name = str(row.get("function") or row.get("fn") or "").strip()
        if not f or not name:
            continue
        key = (f, name)
        if key in seen:
            continue
        seen.add(key)
        try:
            ln = int(row.get("line") or 0)
        except (TypeError, ValueError):
            ln = 0
        out.append(Fn(name=name, file=f, line=ln, lang=lang,
                      end_line=ln, entry_point=True))
    return out


_SRC_EXTS = (".sol", ".rs", ".go", ".vy", ".cairo", ".move")
_SRC_WALK_SKIP = {".git", "node_modules", "out", "cache", "lib", "broadcast", "artifacts",
                  "target", "dependencies", "test", "tests", "mocks", "script", "scripts"}


def _ws_has_source_despite_resolution(ws: Path) -> bool:
    """True if the workspace HAS in-scope source even though the resolver found
    none (so 'no source' is a resolution/scope FAILURE, not an empty workspace).
    Authoritative manifest first; then a bounded raw source-extension walk."""
    manifest = ws / ".auditooor" / "inscope_units.jsonl"
    if manifest.is_file():
        try:
            for ln in manifest.read_text(encoding="utf-8", errors="replace").splitlines():
                if ln.strip():
                    return True
        except OSError:
            pass
    import os as _os
    for dp, dns, fns in _os.walk(ws):
        dns[:] = [d for d in dns if d not in _SRC_WALK_SKIP and not d.startswith(".")]
        for fn in fns:
            if fn.endswith(_SRC_EXTS):
                return True
    return False


def evaluate(ws: Path, *, mutation_verify: bool = False,
             strict: bool = False) -> dict:
    if not ws.exists() or not ws.is_dir():
        return {
            "schema": SCHEMA, "gate": GATE, "verdict": "error",
            "reason": f"workspace not a directory: {ws}",
            "functions": [], "counts": {}, "src_roots": [],
        }
    roots = _resolve_src_roots(ws)
    # Go/Cosmos entry-surface narrowing: compute ONCE per workspace (bounded fs
    # sniff). True only for a CONFIDENTLY-detected Cosmos/Go-L1 ws (fail-open:
    # any other ws, or a missing classifier, keeps every-exported).
    go_entry_scope = bool(_go_entry is not None
                          and _go_entry.is_cosmos_go_workspace(ws))
    fns: list = []
    any_source = False
    for root in roots:
        for path, lang in _iter_source_files(root):
            any_source = True
            try:
                rel = str(path.relative_to(ws))
            except ValueError:
                rel = str(path)
            fns.extend(_extract_entry_fns(path, lang, rel,
                                          go_entry_scope=go_entry_scope))

    # DECLARATIVE-LANGUAGE seed: languages with a registered extension but NO
    # source-regex extractor (_MANIFEST_SEED_LANGS, e.g. Obyte Oscript AAs) cannot be
    # walked into Fn units, so seed them from the authoritative inscope-manifest -
    # otherwise their entire in-scope surface is invisible to the denominator. The
    # extractable languages (sol/rs/go/move/cairo) keep coming from the source walk
    # (nothing is seeded for them), so their behavior is byte-identical. Seeded units
    # flow through the SAME scope/OOS filters below.
    _seeded = _seed_manifest_declarative_units(ws)
    if _seeded:
        fns.extend(_seeded)
        any_source = True

    # SCOPE-AUTHORITATIVE filter: when an in-scope manifest exists, the denominator is the
    # in-scope file set only (drop OOS packages walked from src_roots). r36-rebuttal: lane
    # FIX-FCC-SCOPE-AUTHORITATIVE.
    _inscope = _load_inscope_file_set(ws)
    _inscope_fns = _load_inscope_fn_restrictions(ws)
    scope_filtered_out = 0
    if _inscope is not None:
        def _norm(p: str) -> str:
            return str(p or "").strip().lstrip("./").replace("\\", "/")

        def _keep(f) -> bool:
            nf = _norm(f.file)
            if nf not in _inscope:
                return False
            # Honor function-level granularity: a function-scoped file keeps ONLY
            # its named in-scope functions; a file-level (whole-file) entry keeps all.
            if _inscope_fns is not None and nf in _inscope_fns:
                return f.name in _inscope_fns[nf]
            return True

        kept = [f for f in fns if _keep(f)]
        scope_filtered_out = len(fns) - len(kept)
        fns = kept

    # SCOPE.md OOS-GLOB filter (GENERIC, language-agnostic). Drop functions whose
    # file matches an out-of-scope carve-out documented in <ws>/SCOPE.md (e.g.
    # "Autobahn consensus OUT", "giga packages other than giga/executor OUT",
    # "evmone backend OUT"). FAIL-OPEN: when load_oos_spec finds no OOS section the
    # spec is empty -> zero drops -> behavior byte-identical. Env kill-switch
    # AUDITOOOR_SCOPE_OOS=0. Never drops in-scope code: an OOS glob combined with an
    # include-exception (giga OUT / giga/executor IN) keeps the excepted path.
    scope_oos_exclude_globs: list = []
    scope_oos_dropped_count = 0
    try:
        _load_oos, _is_oos = _load_scope_oos_fns()
        if _load_oos is not None and _is_oos is not None:
            _oos_spec = _load_oos(str(ws))
            scope_oos_exclude_globs = list(_oos_spec.get("exclude_globs") or [])
            if scope_oos_exclude_globs:
                def _oos_keep(f) -> bool:
                    blocked, _reason = _is_oos(str(f.file), _oos_spec, str(ws))
                    return not blocked
                _kept2 = [f for f in fns if _oos_keep(f)]
                scope_oos_dropped_count = len(fns) - len(_kept2)
                fns = _kept2
    except Exception:  # noqa: BLE001 - fail-open, never break the gate on OOS logic
        scope_oos_exclude_globs = []
        scope_oos_dropped_count = 0

    # HISTORICAL VERSION-SNAPSHOT drop (GENERIC, always-on, fail-open). Version-pinned
    # legacy/vNNN (or previousVersions/vNNN) functions are frozen copies dispatched
    # only for historical-block replay - a new tx runs the latest version - so they
    # carry zero live-impact and must not inflate the coverage denominator (the
    # precompile-dedup lever misses non-dispatch legacy fns like Run/RequiredGas).
    # Matches the source-unit denominator (workspace-coverage-heatmap is_oos_dir).
    # Env kill-switch AUDITOOOR_SCOPE_OOS=0. Precise: needs the version-numbered child.
    historical_snapshot_dropped_count = 0
    if os.environ.get("AUDITOOOR_SCOPE_OOS", "1") != "0":
        try:
            from tools.lib.scope_exclusion import is_historical_version_snapshot as _is_hist
        except Exception:  # noqa: BLE001
            try:
                from lib.scope_exclusion import is_historical_version_snapshot as _is_hist
            except Exception:  # noqa: BLE001
                _is_hist = None
        if _is_hist is not None:
            try:
                _kept_h = [f for f in fns if not _is_hist(str(f.file))]
                historical_snapshot_dropped_count = len(fns) - len(_kept_h)
                fns = _kept_h
            except Exception:  # noqa: BLE001 - fail-open
                historical_snapshot_dropped_count = 0

    # GO/COSMOS ENTRY-SURFACE NARROWING (fail-open; applied AFTER scope filtering so
    # it only ever reduces the in-scope surface, never expands it). On a confidently-
    # detected Cosmos/Go-L1 workspace, exclude internal-helper Go functions (the Go
    # analog of Solidity ``internal`` - reached only through an entry point, covered
    # transitively) from the coverage denominator, keeping only true external entry
    # points (msg-server / ABCI / precompile / ante / IBC / RPC / genesis / hooks).
    # This corrects the every-exported over-count; the excluded helpers are surfaced
    # as a visible count (never silently dropped). NON-Go fns are untouched
    # (entry_point defaults True), so Solidity/Rust/Move workspaces are byte-identical.
    go_internal_helpers_excluded = 0
    go_entry_points_kept = 0
    go_precompile_dedup_detail: dict = {"applied": False}
    go_fork_delta_detail: dict = {"applied": False}
    if go_entry_scope and fns:
        _entry = [f for f in fns if getattr(f, "entry_point", True)]
        # SAFETY (never-false-pass): if narrowing empties the surface but there WERE
        # functions, the classifier failed to recognize ANY entry point - do NOT hand
        # the gate a zero denominator (which passes vacuously). Fall back to the full
        # (pre-narrow) surface. Narrowing is only allowed to REDUCE a NON-empty set.
        if _entry:
            go_internal_helpers_excluded = len(fns) - len(_entry)
            go_entry_points_kept = len(_entry)
            fns = _entry

            # LEVER 1 - precompile version-dedup: collapse per-precompile EVM-dispatch
            # surface once, drop per-version legacy duplicates + non-dispatch
            # accessors (EVMKeeper/GetABI/Address/event builders). Go-only.
            try:
                _pc_kept, go_precompile_dedup_detail = \
                    _go_entry.dedup_precompile_entry_points(fns)
                # never-false-pass: only accept a NON-empty reduced set.
                if _pc_kept:
                    fns = _pc_kept
            except Exception:  # noqa: BLE001 - fail-open, keep larger denominator
                go_precompile_dedup_detail = {"applied": False, "reason": "error"}

            # LEVER 2 - go-ethereum (and any resolved fork) fork-delta prune: drop
            # entry fns in PROVEN unmodified-upstream fork files (fail-open when
            # fork-base resolution is unavailable/degraded -> keep all).
            try:
                _fork_scope_fn = _load_fork_scope_fn()
                _fk_kept, go_fork_delta_detail = \
                    _go_entry.prune_unmodified_fork_entry_points(
                        ws, fns, _fork_scope_fn)
                if _fk_kept:
                    fns = _fk_kept
            except Exception:  # noqa: BLE001 - fail-open, keep larger denominator
                go_fork_delta_detail = {"applied": False, "reason": "error"}

    if not any_source:
        # G2 fix (2026-06-27): a FAILED source resolution must not green-pass.
        # If the workspace genuinely HAS source (authoritative manifest non-empty,
        # or a raw source-extension walk finds files) but the resolver returned
        # nothing - code under lib/examples/test the resolver excludes, or a
        # path-prefix mismatch - that is a resolver/scope ERROR, not an empty
        # workspace. Emit error (rc 2) instead of a clean pass-no-source.
        if _ws_has_source_despite_resolution(ws):
            return {
                "schema": SCHEMA, "gate": GATE, "verdict": "error-no-source-resolved",
                "reason": ("source resolution returned 0 functions but the workspace HAS source "
                           "(inscope_units.jsonl non-empty or a raw .sol/.rs/.go/.vy walk found files) "
                           "- resolver/scope mismatch, NOT an empty workspace. Fix the src-root "
                           "resolution / scope globs; do not credit this as covered."),
                "functions": [], "counts": {"total": 0},
                "src_roots": [str(r) for r in roots],
            }
        return {
            "schema": SCHEMA, "gate": GATE, "verdict": "pass-no-source",
            "reason": "no in-scope source found",
            "functions": [], "counts": {"total": 0},
            "src_roots": [str(r) for r in roots],
        }

    meta = _classify(ws, fns, mutation_verify=mutation_verify, strict=strict)

    # ADDITIVE full-path credit pass (basename-collision-safe; UPGRADE-ONLY so it cannot
    # regress). The basename-keyed bridge fn_index + _base_decls miscredit same-named files
    # in different dirs (e.g. op-node/rollup/types.go vs rollup/derive/types.go vs the many
    # */types.go), leaving genuinely-examined fns (the IsX activation-block family etc.)
    # uncredited. This pass scans structured source-cited rule-out sidecars in BOTH the
    # bridged dir AND the MIMO source dir (robust to the bridge skipping them) and credits a
    # still-untouched/hollow fn real-attack ONLY when a sidecar's file_line resolves to it by
    # FULL relative-path suffix + line span. Same credit policy as the existing
    # applies_to_target=no + source-cite path - just full-path instead of basename matching.
    try:
        _sidecar_dirs = [ws / ".auditooor" / "hunt_findings_sidecars"]
        _derived = Path(__file__).resolve().parent.parent / "audit" / "corpus_tags" / "derived"
        if _derived.is_dir():
            _sidecar_dirs += [d for d in _derived.glob(f"mimo_harness_*{ws.name}*") if d.is_dir()]
        _cites: list = []
        # G3: this ADDITIVE full-path pass credits real-attack directly from
        # hunt_findings_sidecars WITHOUT going through _pass1_evidence_paths, so it
        # must apply the same synthetic-lead exclusion or a fabricated (never-
        # dispatched) sidecar manufactures credit here, defeating the filter. The
        # exclusion set covers the hunt_findings_sidecars dir; MIMO-derived dirs are
        # not E4-classified (dispatched workflow-drill output) so membership is a
        # natural no-op for them, matching the E4/hunt-coverage-gate scope.
        _synth_lead = _synthetic_lead_sidecar_paths(ws)
        for _d in _sidecar_dirs:
            if not _d.is_dir():
                continue
            for _p in _d.glob("*.json"):
                if str(_p) in _synth_lead:
                    continue
                try:
                    _rec = json.loads(_p.read_text(encoding="utf-8", errors="replace"))
                except (OSError, ValueError):
                    continue
                if not isinstance(_rec, dict):
                    continue
                _r = _rec.get("result")
                try:
                    _inner = json.loads(_r) if isinstance(_r, str) else (_r if isinstance(_r, dict) else {})
                except (ValueError, TypeError):
                    _inner = {}
                if not isinstance(_inner, dict):
                    continue
                # FC-FALSE-RED fix (hyperlane step-3, 2026-06-21): credit a
                # source-cited rule-out when applies_to_target=="no" OR the inner
                # verdict is a clean terminal status (KILL->ruled-out / no-finding).
                # The canonical per-fn hunt emits verdict=KILL frequently WITH
                # applies_to_target=yes (hypothesis checked, ruled out); gating only
                # on applies=="no" false-downgraded every such rule-out to hollow.
                _applies = str(_inner.get("applies_to_target") or "").strip().lower()
                _vterm = _normalize_terminal_status(
                    _inner.get("verdict") or _inner.get("disposition")
                    or _inner.get("severity_estimate")
                )
                if _applies != "no" and _vterm not in _TERMINAL_CLEAN_STATUSES:
                    continue
                if _inner.get("r76_source_existence_fail"):
                    continue
                _fl = str(_inner.get("file_line") or _rec.get("file_line") or "")
                _m = re.search(r"([\w./\\-]+\.\w+):L?(\d+)", _fl)
                if _m:
                    _cites.append((_norm_file(_m.group(1)), int(_m.group(2))))
        if _cites:
            _by_file: dict = {}
            for _fn in fns:
                _by_file.setdefault(_norm_file(_fn.file), []).append(_fn)
            for _arr in _by_file.values():
                _arr.sort(key=lambda f: f.line)
            for _fn in fns:
                if _fn.classification == "real-attack":
                    continue
                # Declarative-language units (Oscript AAs) carry NO decl line
                # (line=0), so the line-span match below is meaningless for them and
                # would over-credit EVERY unit in a cited file. They are credited
                # exclusively by _apply_declarative_sidecar_credit (tolerant fn match).
                if _norm_lang(_fn.lang) in _MANIFEST_SEED_LANGS:
                    continue
                _fnf = _norm_file(_fn.file)
                _arr = _by_file.get(_fnf, [])
                _nxt = None
                for _i, _g in enumerate(_arr):
                    if _g is _fn:
                        _nxt = _arr[_i + 1].line if _i + 1 < len(_arr) else None
                        break
                _lo = _fn.line
                _eh = getattr(_fn, "end_line", 0) or 0
                _hi = _eh if _eh > 0 else (_nxt - 1 if _nxt else _fn.line + 100000)
                for (_cf, _cl) in _cites:
                    if (_fnf.endswith(_cf) or _cf.endswith(_fnf)) and _lo <= _cl <= _hi:
                        _fn.classification = "real-attack"
                        _fn.evidence.append(f"fullpath-fp-defended:{_cf}:{_cl}")
                        break
        # STICKY genuine-credit floor: a fn credited via a real defended sidecar in a PRIOR
        # persisted result stays credited. The orchestrated audit-complete run recomputes
        # while other steps transiently mutate the MIMO sidecar dir (corpus-refresh), so a
        # genuine credit can flap to hollow for 1-2 fns purely on dir timing. Restoring a
        # prior *defended* credit is monotonic and cannot false-green (it requires a prior
        # genuine source-cited credit to have existed).
        _prior = ws / ".auditooor" / "function_coverage_completeness.json"
        if _prior.is_file():
            try:
                _pd = json.loads(_prior.read_text(encoding="utf-8"))
            except (OSError, ValueError):
                _pd = {}
            _sticky = set()
            for _pf in (_pd.get("functions") or []):
                if _pf.get("classification") == "real-attack" and any(
                    ("fp-defended" in str(_e) or "finding-attack" in str(_e) or "mutation-killed" in str(_e))
                    for _e in (_pf.get("evidence") or [])
                ):
                    _sticky.add((_norm_file(str(_pf.get("file") or "")), _pf.get("name")))
            if _sticky:
                for _fn in fns:
                    if _fn.classification != "real-attack" and (
                            _norm_file(_fn.file), _fn.name) in _sticky:
                        _fn.classification = "real-attack"
                        _fn.evidence.append("sticky-prior-defended-credit")
    except Exception:  # noqa: BLE001 - additive enrichment must never break the gate
        pass

    # LEVER 3 - call-graph closure crediting (Go/Cosmos only). A genuinely-covered
    # (real-attack) entry point's per-fn attack analysis transitively covers the
    # functions it reaches through a REAL Go call path. Credit a still-untouched/
    # hollow entry fn covered iff it is in the closure of a real-attack entry fn
    # over the SSA/CHA-proven call graph (dataflow_paths.jsonl). No graph => no-op.
    # NEVER-FALSE-PASS: only proven edges (never invented); missing edges under-credit.
    go_closure_detail: dict = {"applied": False}
    if go_entry_scope and fns:
        try:
            _dfp = _load_go_dataflow_paths(ws)
            _credited, go_closure_detail = _go_entry.credit_closure_reachable(
                fns, _dfp, lambda f: f.classification == "real-attack")
            for _cf in _credited:
                if _cf.classification != "real-attack":
                    _cf.classification = "real-attack"
                    _cf.evidence.append("go-closure-reachable-from-covered-entry")
        except Exception:  # noqa: BLE001 - additive enrichment must never break gate
            go_closure_detail = {"applied": False, "reason": "error"}

    real = [f for f in fns if f.classification == "real-attack"]
    hollow = [f for f in fns if f.classification == "hollow"]
    untouched = [f for f in fns if f.classification == "untouched"]
    counts = {
        "total": len(fns),
        "real_attack": len(real),
        "hollow": len(hollow),
        "untouched": len(untouched),
    }
    if go_entry_scope:
        # Visible diagnostic: the Go/Cosmos entry-surface narrowing is transparent -
        # the denominator (``total``) is entry points only; the excluded internal
        # helpers are reported so the reclassification is auditable, never silent.
        counts["go_entry_points"] = go_entry_points_kept
        counts["go_internal_helpers_excluded"] = go_internal_helpers_excluded
    fully = (len(fns) > 0 and not hollow and not untouched)
    verdict = "pass-fully-covered" if fully else "fail-functions-untouched-or-hollow"
    reason = (
        "every in-scope external/public/entry function has a real per-function attack verdict"
        if fully else
        f"{len(hollow)} hollow + {len(untouched)} untouched of {len(fns)} in-scope functions "
        f"have no real per-function attack verdict"
    )
    # E3.4 - a STRICT mutation-backend-unavailable on a backed language (sol/rs/go)
    # is FATAL: it escalates a would-be pass to the typed fail verdict (a missing
    # producer must never silently pass). The typed move/cairo/circom/noir absent
    # verdict (with waiver path) does NOT brick the gate - it is surfaced in meta.
    if meta.get("mutation_backend_verdict") == "fail-mutation-backend-unavailable":
        verdict = "fail-mutation-backend-unavailable"
        reason = (
            "mutation backend unavailable under STRICT for backed language(s) "
            f"{meta.get('mutation_backend_fatal_langs')}: a producer (halmos/forge "
            "/cargo/go-test) must exist; absent backend cannot silently pass"
        )
    result_dict = {
        "schema": SCHEMA, "gate": GATE, "verdict": verdict, "reason": reason,
        "counts": counts,
        "scope_filter": {
            "applied": _inscope is not None,
            "source": ".auditooor/inscope_units.jsonl" if _inscope is not None else None,
            "in_scope_files": (len(_inscope) if _inscope is not None else None),
            "out_of_scope_functions_dropped": scope_filtered_out,
        },
        "scope_exclude_globs": scope_oos_exclude_globs,
        "scope_oos_dropped_count": scope_oos_dropped_count,
        "go_entry_surface": {
            "applied": go_entry_scope,
            "rationale": ("Cosmos/Go-L1: denominator narrowed to true external entry "
                          "points (msg-server/ABCI/precompile/ante/IBC/RPC/genesis); "
                          "internal helpers covered transitively (Solidity-internal "
                          "analog). Fail-open; env kill-switch "
                          "AUDITOOOR_FCC_GO_ENTRYPOINT_SCOPE=0."),
            "entry_points": go_entry_points_kept,
            "internal_helpers_excluded": go_internal_helpers_excluded,
            "precompile_dedup": go_precompile_dedup_detail,
            "fork_delta_prune": go_fork_delta_detail,
            "closure_crediting": go_closure_detail,
        } if go_entry_scope else {"applied": False},
        "mutation_verify": meta,
        "src_roots": [str(r) for r in roots],
        "functions": [f.to_record() for f in fns],
        "hollow_or_untouched": [f.to_record() for f in (hollow + untouched)],
    }
    # ADDITIVE ADVISORY: path-coverage block. Only added when a dataflow slice
    # exists; NEVER changes counts/verdict/classification above. Wrapped so an
    # enrichment failure can never break the gate (additive-or-nothing).
    try:
        _pc = _compute_path_coverage(ws, fns)
        if _pc is not None:
            result_dict["path_coverage"] = _pc
    except Exception:  # noqa: BLE001 - advisory enrichment must never break the gate
        pass
    return result_dict


def _compute_path_coverage(ws: Path, fns: list) -> dict | None:
    """ADVISORY path-coverage signal (additive; never gates).

    Reads <ws>/.auditooor/dataflow_paths.jsonl. A DefUsePath is "path-covered" iff
    BOTH its source unit AND its sink unit are real-attack covered functions. An
    unguarded cross-fn path whose endpoints are NOT both hunted is a VISIBLE GAP.

    Returns None when the slice is absent -> the report shape + all existing counts /
    classification are byte-identical to before (this block is simply not added).
    This NEVER changes real_attack/hollow/untouched counts; it is read-only over the
    already-classified `fns` set.
    """
    df = ws / ".auditooor" / "dataflow_paths.jsonl"
    if not df.is_file():
        return None
    # Map (basename, fn-name) -> is real-attack covered. Use basename to bridge the
    # engine's path form vs the coverage tool's enumerated form conservatively.
    covered: set[tuple[str, str]] = set()
    for f in fns:
        if getattr(f, "classification", "") == "real-attack":
            covered.add((Path(str(getattr(f, "file", ""))).name, getattr(f, "name", "")))
    try:
        text = df.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return None
    total = 0
    path_covered = 0
    gaps: list[dict] = []
    degraded = 0
    for line in text.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            p = json.loads(line)
        except (json.JSONDecodeError, ValueError):
            continue
        if p.get("degraded"):
            degraded += 1
            continue
        src = p.get("source") or {}
        snk = p.get("sink") or {}
        src_file = src.get("file")
        snk_file = snk.get("file")
        if not src_file or not snk_file:
            continue
        total += 1
        src_key = (Path(str(src_file)).name, str(src.get("fn") or ""))
        snk_key = (Path(str(snk_file)).name, str(snk.get("fn") or ""))
        src_cov = src_key in covered
        snk_cov = snk_key in covered
        if src_cov and snk_cov:
            path_covered += 1
        else:
            if p.get("unguarded") and len(gaps) < 200:
                # B3: the existing prose `source`/`sink` strings are kept byte-identical
                # for backward compat; ADD machine-parseable fields so a downstream
                # follow-through hunt (inscope-hunt-batch-builder --unit path-followthrough)
                # can construct a per_path_dataflow_hunt task without re-parsing prose.
                gaps.append({
                    "path_id": p.get("path_id"),
                    "source": f"{src_file}:{src.get('line')} ({src.get('fn')})",
                    "sink": f"{snk_file}:{snk.get('line')} ({snk.get('callee')})",
                    "call_depth": p.get("call_depth"),
                    "confidence": p.get("confidence"),
                    "source_covered": src_cov,
                    "sink_covered": snk_cov,
                    # --- additive machine-parseable endpoints (B3 follow-through seed) ---
                    "source_file": str(src_file),
                    "source_line": src.get("line"),
                    "source_fn": str(src.get("fn") or ""),
                    "sink_file": str(snk_file),
                    "sink_line": snk.get("line"),
                    "sink_callee": str(snk.get("callee") or ""),
                    "unguarded": True,
                })
    return {
        "advisory": True,
        "note": ("ADVISORY ONLY - does NOT gate. A path is path-covered iff both its "
                 "source and sink functions are real-attack covered. Unguarded paths with "
                 "an uncovered endpoint are visible cross-function gaps."),
        "total_paths": total,
        "path_covered": path_covered,
        "path_uncovered": total - path_covered,
        "degraded_records_skipped": degraded,
        "uncovered_unguarded_gaps": gaps,
    }


def _emit_worklist(result: dict) -> dict:
    rows = []
    for f in result.get("functions", []):
        if f["classification"] != "real-attack":
            rows.append({
                "file_line": f"{f['file']}:{f['line']}",
                "function": f["name"],
                "lang": f["lang"],
                "classification": f["classification"],
                "why": (f["evidence"][0] if f["evidence"] else "no reference"),
                "task": "drive a real per-function attack and record a concrete verdict",
            })
    return {
        "schema": "auditooor.function_coverage_worklist.v1",
        "gate": GATE,
        "workspace_verdict": result.get("verdict"),
        "counts": result.get("counts", {}),
        "worklist": rows,
        "worklist_size": len(rows),
    }


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(
        description="Real per-function attack coverage gate (generic, language-aware)."
    )
    ap.add_argument("--workspace", required=True, help="audit workspace path")
    ap.add_argument("--check", action="store_true",
                    help="gate mode: exit 1 unless every in-scope function is real-attack")
    ap.add_argument("--emit-worklist", action="store_true",
                    help="emit the untouched/hollow worklist instead of the full report")
    ap.add_argument("--mutation-verify", action="store_true",
                    help="upgrade the real-attack bar: a harness-derived "
                         "real-attack must be mutation-killed (calls the "
                         "sibling tools/mutation-verify-coverage.py by path). "
                         "Catches semantically-vacuous halmos/echidna/forge/"
                         "agent harnesses. Without it, fast behavior holds.")
    ap.add_argument("--strict", action="store_true",
                    help="E3.1: STRICT default bar (or env AUDITOOOR_L37_STRICT=1)."
                         " A syntactically-non-vacuous harness is credited "
                         "real-attack ONLY if a killed mutant exists OR the shared "
                         "sentinel-only detector says the body is non-vacuous; "
                         "else it is hollow. Also makes a backed-language "
                         "(sol/rs/go) mutation-backend-unavailable FATAL.")
    ap.add_argument("--json", action="store_true", help="JSON output")
    ap.add_argument("--write", action="store_true",
                    help="also write <ws>/.auditooor/function_coverage_completeness.json")
    args = ap.parse_args(argv)

    ws = Path(args.workspace).expanduser().resolve()
    # --mutation-verify is opt-in via flag OR env (AUDITOOOR_FCC_MUTATION_VERIFY).
    env_mv = os.environ.get("AUDITOOOR_FCC_MUTATION_VERIFY", "").strip().lower()
    mutation_verify = bool(args.mutation_verify) or env_mv in ("1", "true", "yes", "on")
    strict = bool(args.strict) or _l37_strict()
    result = evaluate(ws, mutation_verify=mutation_verify, strict=strict)

    if args.write and result.get("verdict") not in ("error",):
        try:
            out = ws / ".auditooor" / "function_coverage_completeness.json"
            out.parent.mkdir(parents=True, exist_ok=True)
            out.write_text(json.dumps(result, indent=2), encoding="utf-8")
        except OSError:
            pass

    if args.emit_worklist:
        payload = _emit_worklist(result)
        print(json.dumps(payload, indent=2) if args.json else _fmt_worklist(payload))
        return 2 if result.get("verdict") == "error" else 0

    if args.json:
        print(json.dumps(result, indent=2))
    else:
        print(_fmt_report(result))

    if str(result.get("verdict") or "").startswith("error"):
        return 2
    if args.check:
        if result["verdict"] == "fail-functions-untouched-or-hollow":
            return 1
        return 0
    return 0


def _fmt_report(r: dict) -> str:
    c = r.get("counts", {})
    lines = [
        f"[{GATE}] verdict={r.get('verdict')}",
        f"  src_roots: {', '.join(r.get('src_roots', []))}",
        f"  reason: {r.get('reason')}",
        f"  total={c.get('total', 0)} real-attack={c.get('real_attack', 0)} "
        f"hollow={c.get('hollow', 0)} untouched={c.get('untouched', 0)}",
    ]
    mv = r.get("mutation_verify") or {}
    if mv.get("mutation_verify"):
        lines.append(
            f"  mutation-verify: ON (backend={mv.get('mutation_backend')}; "
            f"verdicts={mv.get('mutation_verdicts', {})})"
        )
    hu = r.get("hollow_or_untouched", [])
    if hu:
        lines.append(f"  hollow/untouched functions ({len(hu)}):")
        for f in hu[:60]:
            ev = f["evidence"][0] if f["evidence"] else "no reference"
            lines.append(f"    - {f['file']}:{f['line']} {f['name']}  "
                         f"[{f['classification']}] ({ev})")
        if len(hu) > 60:
            lines.append(f"    ... and {len(hu) - 60} more")
    return "\n".join(lines)


# Generous safety cap so a pathological multi-thousand-fn workspace does not
# flood a terminal - but NEVER a SILENT cap. If we truncate we emit a LOUD
# trailer naming the hidden count and pointing at --json (anti-pattern class C:
# "no silent caps - log what was dropped"). The full machine-readable list is
# always available via --json (_emit_worklist applies no cap).
_WORKLIST_TEXT_CAP = 1000


def _fmt_worklist(p: dict) -> str:
    rows = p.get("worklist", [])
    lines = [
        f"[{GATE}] worklist verdict={p.get('workspace_verdict')} "
        f"size={p.get('worklist_size')}",
    ]
    for row in rows[:_WORKLIST_TEXT_CAP]:
        lines.append(f"  - {row['file_line']} {row['function']} "
                     f"[{row['classification']}] :: {row['task']}")
    hidden = len(rows) - _WORKLIST_TEXT_CAP
    if hidden > 0:
        lines.append(
            f"  ... {hidden} more uncovered function(s) TRUNCATED from this text "
            f"view (cap={_WORKLIST_TEXT_CAP}); re-run with --json for the full "
            f"machine-readable worklist - the gate counts ALL {len(rows)}.")
    return "\n".join(lines)


if __name__ == "__main__":
    sys.exit(main())
