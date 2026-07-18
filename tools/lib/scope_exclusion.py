"""Single-source-of-truth scope-exclusion / in-scope-membership helpers.

THE PROBLEM THIS FIXES: every coverage / depth / heatmap gate had its OWN copy
of "is this path a test / vendored dep / generated file / in-scope source"
heuristics. They drifted (the morpho-midnight false-red: a top-level
``test/Foo.sol`` was NOT recognised because one tool matched ``/test/`` but the
path had no leading slash; ``latest_state.go`` was wrongly dropped because
another tool matched ``interchaintest`` as a bare substring inside ``latest``).
Drift => either false-green (drop in-scope protocol source = the #1 sin) or
false-red (audit code that is genuinely OOS).

THE FIX: ONE module. Every gate imports from here. The marker tables are the
canonical union mined across 13 workspaces (Go/Cosmos, Solidity, Rust/CosmWasm,
Move, Cairo). Logic is GENERIC - no workspace name ever appears in a decision.

DESIGN INVARIANTS (enforced by the unit tests):
  - Normalise every path with a leading "/" before substring tests, so a
    top-level "test/Foo.sol" matches the "/test/" marker.
  - Whole-dir markers (interchaintest, vendor, lib, ...) match a PATH SEGMENT,
    not a bare substring, so "interchaintest" is dropped but "latest_state.go"
    is KEPT.
  - FAIL-SAFE: any ambiguity -> in-scope (MORE coverage, never less). An
    exclusion that drops in-scope protocol source is a forbidden false-green.
  - MANIFEST-AUTHORITATIVE: when <ws>/.auditooor/inscope_units.jsonl exists, the
    membership question (is_in_scope) trusts it verbatim; otherwise it falls
    back to "not is_oos(rel)".
  - Env hooks APPEND to the defaults (never replace) so an operator can widen
    the OOS set per engagement without losing the canonical union.

Pure stdlib. Composes with tools/lib/source_root_resolver.py for root
re-derivation (never re-walks the tree with its own ext logic).
"""
from __future__ import annotations

import json
from functools import lru_cache
import os
import re
from pathlib import Path

# ---------------------------------------------------------------------------
# Compose, don't duplicate: source-suffix set + root resolver come from the
# canonical resolver. We import lazily-safe (the resolver is pure stdlib too).
# ---------------------------------------------------------------------------
try:  # normal package import
    from tools.lib.source_root_resolver import (  # type: ignore
        SOURCE_EXTS as _RESOLVER_SOURCE_EXTS,
        resolve_src_roots as _resolve_src_roots,
    )
except Exception:  # pragma: no cover - direct-script / odd-sys.path fallback
    import sys as _sys

    _HERE = Path(__file__).resolve().parent
    if str(_HERE) not in _sys.path:
        _sys.path.insert(0, str(_HERE))
    try:
        from source_root_resolver import (  # type: ignore
            SOURCE_EXTS as _RESOLVER_SOURCE_EXTS,
            resolve_src_roots as _resolve_src_roots,
        )
    except Exception:  # last resort - keep this module importable standalone
        _RESOLVER_SOURCE_EXTS = {
            ".rs", ".sol", ".vy", ".go", ".move", ".cairo", ".circom", ".nr", ".zok",
        }
        _resolve_src_roots = None  # type: ignore

# Source suffixes an auditable unit may have. Mirror the resolver's set so the
# two helpers never disagree about "is this a source file at all".
DEFAULT_SOURCE_SUFFIXES: tuple[str, ...] = tuple(sorted(_RESOLVER_SOURCE_EXTS))

# Canonical in-scope manifest contract.
MANIFEST_REL = ".auditooor/inscope_units.jsonl"


# ===========================================================================
# Canonical marker tables (the Map-phase union). Treated as DEFAULTS - env
# hooks append to them. Keep these as ecosystem CONVENTIONS, never a single
# workspace's literal.
# ===========================================================================

# --- VENDORED: third-party deps, build artifacts, well-known library files ---
_VENDORED_MARKERS_DEFAULT = [
    # dependency / vendor dirs
    "node_modules", "/node_modules/", "vendor", "/vendor/",
    "third_party", "/third_party/", "thirdparty", "dependencies",
    "lib", "/lib/", "libs", "/libs/",
    # build / output / cache dirs
    "out", "/out/", "build", "/build/", "dist", "cache", "/cache/",
    "target", "/target/", "artifacts", "/artifacts/", "broadcast",
    "reference", "/reference/",
    # well-known Solidity dependency namespaces / repos
    "@openzeppelin", "/@openzeppelin/", "openzeppelin",
    "openzeppelin-contracts", "openzeppelin-contracts-upgradeable",
    "@uniswap", "@chainlink",
    "solmate", "solmate/src", "solady", "solady/src", "@solady",
    "forge-std", "/forge-std/", "ds-test",
    "chimera_harnesses", "/chimera_harnesses/",
    # Cosmos / Go ecosystem deps
    # Specific vendored package dir names (unambiguous - no in-scope module is
    # named "cosmos-sdk" / "wasmd"). NOTE: bare "tendermint" is DELIBERATELY NOT
    # here - it is a generic component name that in-scope orchestrator code
    # legitimately interfaces with (e.g. peggo/orchestrator/cosmos/tendermint/),
    # so a bare segment match would false-green that in-scope dir. A genuinely
    # vendored CometBFT/Tendermint copy lives under vendor/ and is caught by the
    # "vendor" marker. Fail-safe: when "tendermint" is ambiguous, keep in scope.
    "cosmos-sdk", "cometbft", "ibc-go", "ibc-apps",
    "cosmwasm", "wasmd", "wasmvm", "interchaintest",
    # well-known library *files* (OZ / solmate / forge-std vendored singletons)
    "SafeTransferLib.sol", "SafeCastLib.sol", "FixedPointMathLib.sol",
    "ERC20.sol", "Math.sol", "SignedMath.sol", "ECDSA.sol",
    "MerkleProof.sol", "SafeERC20.sol", "Address.sol", "Strings.sol",
    # forge-std std* helper modules
    "vm", "stdjson", "stdstorage", "stdinvariant", "stdcheats", "stderror",
    "stdmath", "stdutils", "stdstyle", "stdassertions", "stdchains", "stdtoml",
    "console", "console2", "safeconsole", "commonbase",
]

# --- TEST: test files, test dirs, mocks, fixtures, harnesses, scripts ---
_TEST_MARKERS_DEFAULT = [
    # test dirs
    "/test/", "/tests/", "/spec/", "/testdata/", "testdata",
    # Cosmos-SDK test-harness conventions: x/<module>/simulation/ holds simulation
    # operations (test ops, reached only from operations_test.go) and simapp/ is the
    # simulation app for integration tests - both are test infra, never the audited
    # production surface (NUVA 2026-06-30: the cross-function / core / function
    # coverage gates were enumerating deposit|withdraw@vault/simulation as a
    # mutation-verify requirement; SCOPE: "test/config files OOS").
    "/simulation/", "/simapp/", "/testutils/",
    # test file suffixes / infixes
    "tests.rs", "_test.go", "_test.rs", "_test.", "_tests.rs",
    "_test_suite.go", "_test_suite", ".t.sol", ".s.sol", ".test.",
    ".spec.", "test_", "/test_", "testutil",
    # test utility files (e.g. memclob_test_util.go, sign_test_utils.go):
    # "_test_util" is a dot/substring marker (contains "."-like semantics via
    # substring rule) - we express it as a "." marker so _marker_hit uses
    # substring matching even though it has no literal dot.
    # Using the slash-prefix form forces substring mode unambiguously.
    "/_test_util", "/_test_utils",
    # mocks
    "/mock", "/mocks/", "mock", "mocks", "_mock",
    # fixtures
    "fixtures", "fixture",
    # harnesses / fuzz / invariant tooling
    "/harness", "harness", "_harness", "chimera_harnesses",
    "echidna", "halmos", "medusa",
    # PoC / scripts / dev / certora / interfaces
    "/poc", "/poc-tests/", "poc_", "_poc",
    "/script/", "/scripts/", "script", "scripts",
    "/dev/", "certora", "/certora/",
    # NOTE: "/interface" / "/interfaces/" were REMOVED here (strata false-green:
    # IRoundDataOracle.sol + IAccessControlManager.sol under tranches/oracles/
    # interfaces/ are SCOPE.md-enumerated in-scope sources, but the substring
    # markers dropped them as test/mock infra -> expected-19-got-17). interfaces/
    # is a normal PRODUCTION Solidity layout (declared external surface), NOT test
    # infra. Do NOT re-add - genuine test markers (/test/, /mock/, /mocks/) stay.
    # historical / non-production / documentation trees (not the live audited
    # surface): superseded contract versions, deprecated/legacy/archived code,
    # and doc mirrors (e.g. agglayer-contracts/docs/contracts/src/** duplicates
    # the real contracts/ tree). These routinely DOUBLE the unit count and read
    # as OOS noise. Distinctive dir names -> safe as segment/substring markers.
    "/previousVersions/", "previousVersions", "/docs/",
    # benchmark dirs (not protocol source)
    "benches",
    # cross-chain integration-TEST frameworks (test tooling, never the audited
    # protocol surface). These are name markers that must be OOS even via the
    # dir-shape is_oos_dir path - unlike chain-framework names (cosmos-sdk /
    # cometbft) which ARE in-scope when they are the audit target.
    "interchaintest", "/e2e/", "interchain-test",
]

# --- NON-PRODUCTION DIRS (per-language map + a language-agnostic common set) ---
# WHY THIS EXISTS: "is this directory production protocol source?" is NOT a single
# language-agnostic question. Each ecosystem puts non-production code (CLI mains,
# deploy scripts, micro-benchmarks) under a DIFFERENT conventional dir name, and a
# name that is non-production in one language is legitimate protocol source in
# another. The canonical example: ``cmd`` is the Go node-binary convention
# (cmd/geth, cmd/bor, cmd/cometbft) and must drop, but a Solidity
# ``contracts/cmd/Deploy.sol`` is just a dir literally named "cmd" - NOT the Go
# convention - and must stay in scope (dropping it = false-green).
#
# COMMON (every language): dirs that are non-production in EVERY ecosystem - test
# trees, mocks, docs, dependency/vendor/build/cache/artifact dirs, fixtures,
# examples, superseded versions. These fire regardless of file language.
#
# PER-LANGUAGE: a dir name that is non-production ONLY for that language's files.
# It fires ONLY when the path's language (by extension, or an explicit ``lang``
# arg) matches - so it can never drop another language's legit source.
#
# COMPLETENESS-SAFE: an UNKNOWN language (extension not in the lang map) gets the
# COMMON set ONLY and KEEPS everything language-specific (more coverage, never
# less). The single source of these segments. ``is_cli_entrypoint`` (Go ``cmd``)
# is kept as a dedicated helper for back-compat; this map subsumes it generically.
_NONPROD_DIRS_COMMON = frozenset({
    "test", "tests", "mock", "mocks", "docs", "node_modules", "vendor", "lib",
    "out", "cache", "artifacts", "previousVersions", "testdata", "fixtures",
    "examples",
})
_NONPROD_DIRS_BY_LANG: dict[str, frozenset[str]] = {
    "go": frozenset({"cmd"}),
    "rust": frozenset({"benches"}),         # 'src/bin' handled as a path prefix; 'examples' is common
    "solidity": frozenset({"script", "scripts"}),
}

# Map a file extension -> the language key used in _NONPROD_DIRS_BY_LANG.
# F5: the non-Go/Sol/Rust source extensions are mapped too, so is_nonprod_dir can
# RESOLVE their language instead of emitting the "unknown language" ambiguity WARN
# when a Move/Cairo file sits under a language-specific dir (e.g. a Sui Move
# scripts/). They have no language-specific non-production dirs of their own (the
# COMMON test/docs/vendor set still applies), so an empty per-lang set is correct.
_EXT_TO_LANG: dict[str, str] = {
    ".go": "go",
    ".rs": "rust",
    ".sol": "solidity",
    ".vy": "vyper",
    ".move": "move",
    ".cairo": "cairo",
    ".circom": "circom",
    ".nr": "noir",
    ".zok": "zokrates",
}


def _lang_of(norm_path: str, lang: str | None = None) -> str | None:
    """Resolve the language key for a normalised path.

    An explicit ``lang`` arg wins (case-insensitive). Otherwise detect by the
    basename's extension via :data:`_EXT_TO_LANG`. Returns None for an unknown /
    unmapped extension - callers then apply the COMMON set ONLY (completeness-safe:
    no language-specific dir can drop a file we cannot classify)."""
    if lang:
        return lang.strip().lower() or None
    base = _basename(norm_path)
    dot = base.rfind(".")
    if dot < 0:
        return None
    return _EXT_TO_LANG.get(base[dot:].lower())


def is_nonprod_dir(rel: str, *, lang: str | None = None) -> bool:
    """True iff ``rel`` lives under a non-production directory segment.

    Applies the language-agnostic COMMON set ALWAYS, and the language-specific
    set ONLY when the path's language (extension or explicit ``lang``) matches.
    Whole-PATH-SEGMENT matching (never substring), so a file named ``cmd.go`` or
    a dir ``cmdline`` is unaffected, and ``benches`` does not fire on
    ``benchesmark_utils.rs``. The Rust ``src/bin`` binary-target convention is
    matched as a 2-segment path prefix (``bin`` alone is too generic to drop).

    COMPLETENESS-SAFE for an unknown language: only the COMMON set fires, so we
    KEEP everything language-specific rather than risk an under-scope. When a
    language-specific name (e.g. ``cmd``) appears on a path whose language we
    CANNOT resolve, it is KEPT and a loud WARN + one-line manual step is emitted
    so a human can confirm scope - we never silently drop it."""
    norm = _norm(rel)
    segs = _segments(norm)
    seg_set = set(segs)
    if seg_set & _NONPROD_DIRS_COMMON:
        return True
    detected = _lang_of(norm, lang)
    if detected is not None:
        if seg_set & _NONPROD_DIRS_BY_LANG.get(detected, frozenset()):
            return True
        # Rust binary-target convention: src/bin/<name>.rs is a CLI main, not
        # protocol source. 'bin' alone is too generic (many trees have a bin/),
        # so require the 'src/bin' 2-segment prefix.
        if detected == "rust":
            for i in range(len(segs) - 1):
                if segs[i] == "src" and segs[i + 1] == "bin":
                    return True
    else:
        # Unknown language: a language-specific dir name is AMBIGUOUS here. KEEP
        # (completeness-safe) but WARN loudly with a one-line manual step so the
        # under-scope risk is visible rather than silent.
        lang_specific = set().union(*_NONPROD_DIRS_BY_LANG.values())
        ambiguous = seg_set & lang_specific
        if ambiguous:
            import sys as _sys
            print(
                "[scope_exclusion] WARN: path %r sits under a language-specific "
                "non-production dir %s but its language is unknown (unmapped "
                "extension); KEEPING it in scope (completeness-safe). MANUAL STEP: "
                "confirm whether this path is production source or pass an explicit "
                "lang= to is_nonprod_dir/is_oos." % (rel, sorted(ambiguous)),
                file=_sys.stderr,
            )
    return False


# basename regexes for the test class (segment / basename oriented).
_TEST_BASENAME_REGEXES = [
    re.compile(r"^test_.*\.go$"),          # ^test_*.go basename
    re.compile(r".*test\.sol$", re.I),     # FooTest.sol / ...Test.sol basename
    # file-level _test_util / _test_utils suffix (e.g. memclob_test_util.go)
    re.compile(r".*_test_util[s]?\.go$"),
    re.compile(r".*_test_util[s]?\.rs$"),
    # F5: mock/fake/stub BASENAME suffixes. The bare-word markers above match a
    # path segment but not a basename suffix, and this convention is shared by
    # every source language, including Oscript/AA files (for example
    # old-city-mock.oscript). Keep it language-agnostic so a mock cannot enter
    # one workspace's denominator merely because its extension was omitted.
    re.compile(r".*[-_](mock|mocks|fake|fakes|stub|stubs)\.[a-z0-9]+$", re.I),
    # F5: geth/bor SimulatedBackend test scaffolding. "simulated.go" has NO existing
    # marker (no dir, not a *_test.* suffix) yet is pure test infra - it is exactly
    # the file the polygon asymmetry generator paired production code against.
    re.compile(r"^simulated\.go$"),
    re.compile(r".*_simulated\.go$"),
    # F5: Move plural test-file basename. Singular "_test.move" is already caught by
    # the "_test." substring marker; the plural "_tests.move" is not.
    re.compile(r".*_tests?\.move$"),
]
# directory-name regexes for the test class: testdata / testutil / testing-style
# dir names that are conventionally test infra, plus hyphenated e2e/integration
# test dirs such as e2e-test / e2e-tests / integration-test / something-test.
_TEST_DIRNAME_REGEXES = [
    re.compile(r"^test[a-z0-9_]+$"),       # testdata / testutil / testing / testhelpers
    re.compile(r"^e2e[-_].+$"),            # e2e-test / e2e-tests / e2e_tests
    re.compile(r"^.+-tests?$"),            # something-test / something-tests (hyphenated)
    re.compile(r"^integration[-_]tests?$"), # integration-test / integration_tests
]

# --- GENERATED: protoc / abigen / orm / "DO NOT EDIT" header ---
_GENERATED_MARKERS_DEFAULT = [
    ".pb.go", ".pb.gw.go", "_grpc.pb.go",
    ".abigen.go", ".abi.go",
    "_gen.go", ".gen.go", "_generated.go",
    ".cosmos_orm.go",
    # F5: Solidity/EVM toolchain generated artifacts (hardhat debug + codegen). The
    # vendored markers already drop artifacts/ cache/ out/ build/ dirs; these catch
    # the codegen FILES (TypeChain *.g.sol, hardhat *.dbg.json) wherever they land.
    ".g.sol", ".dbg.json",
]
# directory-name marker for generated code.
# F5: typechain-types / typechain are the conventional EVM ABI-codegen output dirs.
_GENERATED_DIRNAMES = {"generated", "typechain-types", "typechain"}
# protoc field/method prefix on a basename, e.g. XXX_Unmarshal.go.
_GENERATED_BASENAME_PREFIXES = ("XXX_",)
# "Code generated ... DO NOT EDIT." header. Two tiers:
#  - strict: the canonical Go form anchored at a comment line.
#  - loose : content-based, case-insensitive, anywhere in the head text.
_GENERATED_HEADER_STRICT = re.compile(r"^//\s*Code generated\b.*\bDO NOT EDIT\.", re.M)
_GENERATED_HEADER_LOOSE = re.compile(r"Code generated .*DO NOT EDIT", re.I)


# ===========================================================================
# Env-hook plumbing (APPEND-only).
# ===========================================================================
def _env_extra(var: str) -> list[str]:
    """Parse a comma/colon separated env var into a list of markers."""
    raw = os.environ.get(var, "") or ""
    if not raw.strip():
        return []
    out: list[str] = []
    for chunk in re.split(r"[,:]", raw):
        tok = chunk.strip()
        if tok:
            out.append(tok)
    return out


def _vendored_markers() -> list[str]:
    return _VENDORED_MARKERS_DEFAULT + _env_extra("AUDITOOOR_EXTRA_VENDORED_MARKERS")


def _test_markers() -> list[str]:
    return _TEST_MARKERS_DEFAULT + _env_extra("AUDITOOOR_EXTRA_TEST_MARKERS")


def _generated_markers() -> list[str]:
    return _GENERATED_MARKERS_DEFAULT + _env_extra("AUDITOOOR_EXTRA_GENERATED_MARKERS")


def _extra_oos_markers() -> list[str]:
    # A catch-all bucket that contributes to the OOS verdict regardless of class.
    return _env_extra("AUDITOOOR_EXTRA_OOS_MARKERS")


# ===========================================================================
# Path normalisation + segment matching.
# ===========================================================================
def _norm(rel: str) -> str:
    """Normalise to forward slashes with a single guaranteed leading slash.

    A leading slash makes "test/Foo.sol" match the "/test/" marker (the
    morpho-midnight false-red). Backslashes (Windows-style manifest rows) are
    normalised to forward slashes.
    """
    s = str(rel or "").strip().replace("\\", "/")
    while "//" in s:
        s = s.replace("//", "/")
    if not s.startswith("/"):
        s = "/" + s
    # collapse "." path segments (e.g. a leading "./" -> "/./" after the slash
    # prefix) so a manifest row "./src/main.rs" matches "src/main.rs".
    if "/./" in s or s.endswith("/."):
        segs = [seg for seg in s.split("/") if seg and seg != "."]
        s = "/" + "/".join(segs)
    return s


def _segments(norm_path: str) -> list[str]:
    return [seg for seg in norm_path.split("/") if seg]


def _basename(norm_path: str) -> str:
    segs = _segments(norm_path)
    return segs[-1] if segs else ""


def _marker_hit(norm_path: str, marker: str) -> bool:
    """Does ``marker`` fire against the normalised path?

    Rules:
      - A marker that itself contains a "/" (e.g. "/test/", "solmate/src",
        "/@openzeppelin/") is matched as a SUBSTRING of the normalised path -
        the author already encoded the boundary they want.
      - A marker that contains a "." (a file-suffix/infix marker, e.g.
        "_test.go", ".pb.go", "SafeERC20.sol", "tests.rs") is matched as a
        SUBSTRING (suffix/infix semantics) - but ALSO honoured as a segment so a
        whole-file marker like "Address.sol" can equal a path segment.
      - Any other marker (a bare word like "vendor", "interchaintest", "mock")
        must match a whole PATH SEGMENT, never a bare substring - so
        "interchaintest" is dropped but "latest_state.go" is KEPT.
    """
    if not marker:
        return False
    m = marker
    if "/" in m:
        return m in norm_path
    segs = _segments(norm_path)
    if "." in m:
        # suffix / infix marker: substring is the intended semantics, but a
        # bare basename equality (Address.sol == segment) also counts.
        if m in norm_path:
            return True
        return any(seg == m for seg in segs)
    # bare word: whole-segment match only (case-sensitive segment, but allow a
    # case-insensitive equality so "Vendor" / "VENDOR" dirs still drop).
    ml = m.lower()
    return any(seg == m or seg.lower() == ml for seg in segs)


# ===========================================================================
# Public classifiers.
# ===========================================================================
def is_vendored(rel: str) -> bool:
    """True iff ``rel`` is a vendored dependency / build artifact / known lib file."""
    norm = _norm(rel)
    for marker in _vendored_markers():
        if _marker_hit(norm, marker):
            return True
    for marker in _extra_oos_markers():
        if _marker_hit(norm, marker):
            return True
    return False


def is_test(rel: str) -> bool:
    """True iff ``rel`` is test / mock / fixture / harness / script infra."""
    norm = _norm(rel)
    for marker in _test_markers():
        if _marker_hit(norm, marker):
            return True
    base = _basename(norm)
    for rx in _TEST_BASENAME_REGEXES:
        if rx.search(base):
            return True
    segs = _segments(norm)
    # Apply dirname regexes only to non-basename segments (i.e. directory names).
    # Basenames like "e2e_contract.rs" contain a dot; real dir segments don't.
    dir_segs = segs[:-1] if len(segs) > 1 else []
    for seg in dir_segs:
        for rx in _TEST_DIRNAME_REGEXES:
            if rx.match(seg):
                return True
    for marker in _extra_oos_markers():
        if _marker_hit(norm, marker):
            return True
    return False


def is_generated(rel: str, *, head: str | None = None) -> bool:
    """True iff ``rel`` is machine-generated code.

    Filename markers always apply. When ``head`` (the leading text of the file)
    is provided, the "Code generated ... DO NOT EDIT" header regex also fires -
    this catches generated files that don't carry a conventional suffix.
    """
    norm = _norm(rel)
    base = _basename(norm)
    for marker in _generated_markers():
        if _marker_hit(norm, marker):
            return True
    for seg in _segments(norm):
        if seg in _GENERATED_DIRNAMES:
            return True
    for pfx in _GENERATED_BASENAME_PREFIXES:
        if base.startswith(pfx):
            return True
    if head:
        if _GENERATED_HEADER_STRICT.search(head) or _GENERATED_HEADER_LOOSE.search(head):
            return True
    for marker in _extra_oos_markers():
        if _marker_hit(norm, marker):
            return True
    return False


# Mutation-testing artifact markers (shared, additive). A seeded differential
# mutant is a deliberately-BROKEN copy of an in-scope contract used only for
# non-vacuity / mutation-verification of a fuzz harness - never a deployed or
# in-scope production surface. Two recognisers, mirroring the local check that
# already lives in workspace-coverage-heatmap.py:
#   - FILENAME: `SSVClustersMutantA.sol`, `SSVEBAccountingMutantB.sol`, bare
#     `Mutant.sol` - i.e. a `[Mm]utant<alnum>*.sol` basename.
#   - HEADER:   `// MUTANT-A: Drop balance-sufficiency guard` or the phrase
#     `mutation-testing artifact` in the file head (content complement that
#     catches un-conventionally named mutants).
# This is intentionally additive: folding it into is_oos / is_oos_dir means the
# ~25 shared consumers (incl. FCC) inherit the exclusion the heatmap already had.
_MUTATION_ARTIFACT_BASENAME_RE = re.compile(r"[Mm]utant[A-Za-z0-9]*\.sol$")
_MUTATION_ARTIFACT_HEADER_RE = re.compile(
    r"\bMUTANT[- ]?[A-Z0-9]\b|mutation[- ]testing artifact", re.IGNORECASE)


def is_mutation_artifact(rel: str, head: str | None = None) -> bool:
    """True iff ``rel`` is a mutation-testing artifact (seeded differential mutant).

    Filename markers always apply (``[Mm]utant<alnum>*.sol`` basename). When
    ``head`` (the leading text of the file) is provided, the mutation-artifact
    header regex also fires - catching un-conventionally named mutants whose
    basename does not carry the ``Mutant`` token.

    Fail-OPEN: any exception (e.g. a bad ``rel`` value) returns False so this
    predicate can never break the callers that fold it into is_oos / is_oos_dir.
    """
    try:
        base = _basename(_norm(rel))
        if _MUTATION_ARTIFACT_BASENAME_RE.search(base):
            return True
        if head and _MUTATION_ARTIFACT_HEADER_RE.search(head):
            return True
    except Exception:
        return False
    return False


def is_tool_artifact(rel: str) -> bool:
    """True iff ``rel`` lives under the auditooor tool's own artifact dir.

    ``<ws>/.auditooor/`` is where the funnel writes its scratch + generated
    harnesses (vcis-harness, mutation copies, hypotheses sidecars, JSON
    manifests). These files are NEVER the code-under-test, so any path with a
    ``.auditooor`` segment is hard out-of-scope. Without this, generated
    harness scaffolds (e.g. ``.auditooor/vcis-harness/src/*Fuzz.sol``) leak
    into value-moving-function enumeration and every downstream lane.
    """
    return ".auditooor" in _segments(_norm(rel))


def is_cli_entrypoint(rel: str) -> bool:
    """True iff ``rel`` is an operator-only CLI entrypoint under a Go ``cmd/`` dir.

    The Go ecosystem convention (and every blockchain fork that ships a node
    binary: bor ``cmd/bor``, geth ``cmd/geth``, cosmos-sdk ``cmd/...``, cometbft
    ``cmd/cometbft``) puts the operator-run CLI/main wiring under a ``cmd`` path
    segment. Those binaries are operator-controlled glue (flag parsing, daemon
    bootstrap) - NOT the protocol consensus/state surface a bounty scopes, and
    their argument/flag guards are operator-only, so they should not leak into
    the in-scope unit set.

    GATED to ``.go`` files ONLY (the convention is Go-specific): this never drops
    a Solidity ``contracts/cmd/Foo.sol`` or any non-Go ``cmd`` dir - those are
    not the Go ``cmd/`` convention and stay in scope (fail-safe). Matches ``cmd``
    as a whole PATH SEGMENT, not a substring, so a file literally named
    ``cmd.go`` or a dir ``cmdline`` is unaffected.
    """
    norm = _norm(rel)
    base = _basename(norm)
    if not base.lower().endswith(".go"):
        return False
    # the cmd segment must be a directory segment (not the basename).
    return "cmd" in _segments(norm)[:-1]


def is_oos(rel: str, *, head: str | None = None, lang: str | None = None) -> bool:
    """True iff ``rel`` is out-of-scope: tool-artifact OR generated OR test OR
    vendored OR under a (language-aware) non-production directory.

    Non-production dir membership is decided by :func:`is_nonprod_dir`, which
    applies a language-agnostic COMMON set always and a per-language set
    (Go ``cmd``, Rust ``benches``/``src/bin``, Solidity ``script``/``scripts``)
    ONLY when the path's language matches - so a Solidity ``contracts/cmd/Deploy.sol``
    is NOT dropped by the Go ``cmd`` convention. ``lang`` overrides extension
    detection. ``is_cli_entrypoint`` is retained (Go ``cmd``) for back-compat and
    is subsumed by the map."""
    return (
        is_tool_artifact(rel)
        or is_generated(rel, head=head)
        or is_test(rel)
        or is_vendored(rel)
        or is_cli_entrypoint(rel)
        or is_mutation_artifact(rel, head=head)
        or is_nonprod_dir(rel, lang=lang)
    )


# Vendored-dependency DIRECTORY segments (shape-only, NOT project-name markers).
# A path under any of these is a vendored copy regardless of project identity.
_OOS_DIR_SEGMENTS = frozenset({
    "node_modules", "lib", "dependencies", "vendor", "out", "cache",
    "artifacts", "deps", "third_party",
})

# Version-pinned HISTORICAL SNAPSHOT dirs: a `legacy/` (or `previousVersions/`)
# segment immediately followed by a version-numbered segment (v552, v6, v6_0_0...).
# These are frozen copies of an implementation at a past chain/upgrade version,
# dispatched ONLY when re-executing already-finalized historical blocks (SEI
# 2026-07-05: precompiles/*/legacy/vNNN - the live map uses GetVersioned(latestUpgrade)
# so a NEW tx never runs a legacy impl; a bug there has zero live-impact reachability).
# Non-live => OOS-by-impact for the coverage denominator. Precise: requires the
# version-numbered child, so a plain dir literally named `legacy` is NOT dropped.
_HISTORICAL_VERSION_SNAPSHOT_RE = re.compile(
    r"(?:^|/)(?:legacy|previousversions|previous_versions)/v[0-9]", re.IGNORECASE
)


def is_historical_version_snapshot(rel: str) -> bool:
    """True iff ``rel`` lives under a version-pinned historical snapshot dir
    (``legacy/vNNN`` or ``previousVersions/vNNN``). These are frozen copies of an
    implementation at a past chain/upgrade version, dispatched ONLY for replay of
    already-finalized historical blocks - a new tx always runs the latest version -
    so a finding there has zero live-impact reachability (OOS-by-impact). Precise:
    requires the version-numbered child, so a plain ``legacy/`` dir is NOT matched.
    Shared by is_oos_dir (structural) and the function-coverage denominator."""
    return bool(_HISTORICAL_VERSION_SNAPSHOT_RE.search(_norm(rel)))


def is_oos_dir(rel: str, *, head: str | None = None) -> bool:
    """OOS by DIRECTORY SHAPE only - vendored-dep DIRS + test/mock/script/docs/
    historical + generated + tool-artifact - WITHOUT the project-NAME vendored
    markers (cosmos-sdk / cometbft / forge-std-as-name / wasmd ...).

    Use this (not :func:`is_oos`) when enumerating IN-SCOPE FORK repos whose
    top-level dir name happens to match a vendored project marker (e.g. an audit
    of 0xPolygon/cosmos-sdk under src/cosmos-sdk): is_oos would drop the ENTIRE
    fork (under-scope, losing in-scope Polygon-modified code), whereas is_oos_dir
    keeps the fork's production source and only drops its dependency/test/historical
    SUBDIRS. The unmodified-upstream-vs-fork distinction is handled separately by
    the fork-modified-files filter, not by name-based vendoring.
    """
    norm = _norm(rel)
    if set(_segments(norm)) & _OOS_DIR_SEGMENTS:
        return True
    if _HISTORICAL_VERSION_SNAPSHOT_RE.search(norm):
        return True
    if "@openzeppelin" in norm:
        return True
    return (
        is_tool_artifact(rel)
        or is_generated(rel, head=head)
        or is_test(rel)
        or is_cli_entrypoint(rel)
        or is_mutation_artifact(rel, head=head)
    )


def is_auditable_source(rel: str, *, suffixes: tuple | None = None) -> bool:
    """True iff ``rel`` is in-scope AND has a recognised source suffix.

    Default suffixes: the resolver's SOURCE_EXTS (.go/.rs/.sol/.move/.cairo/...).
    A file that is OOS (vendored / test / generated) is never auditable source.
    """
    sfx = tuple(suffixes) if suffixes is not None else DEFAULT_SOURCE_SUFFIXES
    norm = _norm(rel)
    base = _basename(norm)
    dot = base.rfind(".")
    suffix = base[dot:].lower() if dot >= 0 else ""
    if suffix not in {s.lower() for s in sfx}:
        return False
    if is_oos(rel):
        return False
    return True


# ===========================================================================
# Manifest-authoritative membership.
# ===========================================================================
def _manifest_path(workspace) -> Path:
    return Path(workspace) / MANIFEST_REL


def _manifest_rel_value(row: dict) -> str | None:
    """Pull the in-scope rel path from a manifest row.

    The ``file`` field is authoritative; a robust reader falls back to ``path``
    (mirrors the orchestrator's ``row.get("file") or row.get("path")``).
    """
    val = row.get("file") or row.get("path")
    if isinstance(val, str) and val.strip():
        return val.strip()
    return None


@lru_cache(maxsize=64)
def _load_inscope_manifest_cached(path_str: str, mtime_ns: int, size: int) -> set[str] | None:
    path = Path(path_str)
    out: set[str] = set()
    try:
        with path.open("r", encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if not line:
                    continue
                try:
                    row = json.loads(line)
                except (ValueError, TypeError):
                    continue
                if not isinstance(row, dict):
                    continue
                rel = _manifest_rel_value(row)
                if rel:
                    out.add(_norm(rel))
    except OSError:
        return None
    return out or None


def load_inscope_manifest(workspace) -> set[str] | None:
    """Read <ws>/.auditooor/inscope_units.jsonl -> set of in-scope rel paths.

    Returns None when the manifest is absent or empty (i.e. the workspace is not
    yet manifest-authoritative); callers then fall back to ``not is_oos(rel)``.
    Paths are normalised to a leading-slash form so membership is robust to
    leading-./ or backslash variants.
    """
    path = _manifest_path(workspace)
    if not path.is_file():
        return None
    try:
        stat = path.stat()
    except OSError:
        return None
    return _load_inscope_manifest_cached(str(path.resolve()), stat.st_mtime_ns, stat.st_size)


def is_in_scope(rel: str, *, workspace=None) -> bool:
    """Is ``rel`` an in-scope auditable unit?

    MANIFEST-AUTHORITATIVE: when a workspace is given and its inscope manifest is
    present and non-empty, membership is decided ONLY by that manifest (in-scope
    iff ``rel`` is one of its rows). The manifest is the curated denominator -
    trusting it verbatim avoids re-deriving (and possibly mis-deriving) scope.

    FALLBACK: when no workspace is given, or the manifest is absent/empty, an
    item is in-scope iff it is not OOS (``not is_oos(rel)``). This is the
    fail-safe direction (more coverage).

    CATEGORICAL-OOS OVERRIDE: vendored / test / generated code is out of scope
    EVEN WHEN an over-collecting intake walked it into the manifest. Real
    intakes do this routinely - e.g. a Cosmos+Solidity workspace's
    inscope_units.jsonl lists ``@openzeppelin/*`` ERC20 rows, ``*.pb.go``
    protobuf rows and ``interchaintest/*`` rows. The marker tables are
    authoritative for EXCLUSION; the manifest is authoritative only for
    INCLUSION of the remaining protocol surface. Intersecting the two makes
    every consumer robust to a polluted manifest without re-deriving scope, and
    never drops genuine protocol source (the markers are conservative).
    """
    norm = _norm(rel)
    if workspace is not None:
        manifest = load_inscope_manifest(workspace)
        if manifest is not None:
            # MANIFEST-AUTHORITATIVE for inclusion. The pollution backstop uses
            # is_oos_DIR (directory-shape: vendored-dep dirs + test/mock/generated/
            # historical), NOT is_oos - because is_oos's project-NAME vendored
            # markers (cosmos-sdk / cometbft / interchaintest ...) would drop an
            # in-scope FORK repo that IS the audit target (src/cosmos-sdk) even
            # though it is a curated, fork-modified-pruned manifest row. The
            # manifest is now emitted with the same is_oos_dir filter, so dir-shape
            # pollution is already gone; this backstop catches any residue.
            if is_oos_dir(rel):
                return False
            return norm in manifest
    # FALLBACK (no manifest): full conservative OOS exclusion incl. name markers.
    if is_oos(rel):
        return False
    return True


# ===========================================================================
# Root re-derivation (compose with the resolver; never re-walk with own logic).
# ===========================================================================
# ---------------------------------------------------------------------------
# Rust inline-test line ranges. ``is_test(rel)`` catches whole test FILES, but a
# Rust ``#[cfg(test)]`` / ``#[test]`` module lives INSIDE an otherwise in-scope
# ``.rs`` file. Any guard/assert in that span is a TEST oracle, not a production
# runtime guard, so every depth/coverage pass over the same file must agree to
# skip those lines. This is the single source of truth both
# guard-context-extract.py (probe-packet emit) and guard-negative-space-analyzer.py
# (worklist emit) use - if they disagree, the cert enumerates guards (1905) that
# the probe never receives (995), and depth_certificate can never leave
# depth-pending. (Measured on optimism op-reth: ~910 of 1905 worklist rows were
# #[cfg(test)] assert_eq! oracles.)
# ---------------------------------------------------------------------------
_RUST_TEST_ATTR = re.compile(
    r"^\s*#\[\s*(cfg\(\s*test\s*\)|test|tokio::test|cfg\(\s*all\([^)]*\btest\b[^)]*\)\s*\))\s*\]"
)
_RUST_TESTABLE_ITEM = re.compile(r"^\s*(pub\s+|pub\(crate\)\s+)?(async\s+)?(mod|fn)\b")


def rust_test_line_ranges(lines: list[str]) -> set[int]:
    """0-based line indices inside a Rust ``#[cfg(test)]`` / ``#[test]`` item.

    The attribute applies to the NEXT item (a ``mod`` or ``fn``); find that item's
    opening ``{`` and brace-match to its close, marking the whole span. A
    ``#[cfg(test)] use ...;`` (non-braced item) is deliberately NOT marked. Brace
    counting is a heuristic (counts braces in strings/comments too) - acceptable
    for a coverage filter that only decides whether to spend probe budget. Returns
    an empty set for non-Rust input (no test attribute matches)."""
    test_idx: set[int] = set()
    n = len(lines)
    i = 0
    while i < n:
        if not _RUST_TEST_ATTR.match(lines[i]):
            i += 1
            continue
        item = i + 1
        while item < n and item <= i + 4 and not _RUST_TESTABLE_ITEM.match(lines[item]):
            if lines[item].lstrip().startswith("#[") or not lines[item].strip():
                item += 1
                continue
            break
        if item >= n or item > i + 4 or not _RUST_TESTABLE_ITEM.match(lines[item]):
            i += 1
            continue
        depth = 0
        opened = False
        j = item
        while j < n:
            for ch in lines[j]:
                if ch == "{":
                    depth += 1
                    opened = True
                elif ch == "}":
                    depth -= 1
            if opened and depth <= 0:
                break
            j += 1
        for k in range(i, min(j + 1, n)):
            test_idx.add(k)
        i = j + 1
    return test_idx


# ---------------------------------------------------------------------------
# Move inline-test line ranges. Move test code is ANNOTATION-based: a `#[test]`,
# `#[test_only]` or `#[expected_failure]` attribute on a `fun` (or `module`) lives
# INSIDE an otherwise in-scope `.move` file (basename markers cannot see it). Any
# assert!/guard in that span is a TEST oracle, not a production guard, so every
# depth/coverage/asymmetry pass over the file must agree to skip those lines -
# mirrors rust_test_line_ranges so the two ecosystems behave identically. Brace
# counting is the same heuristic (good enough for a coverage-budget filter).
# ---------------------------------------------------------------------------
_MOVE_TEST_ATTR = re.compile(
    r"^\s*#\[\s*(test|test_only|expected_failure)\b"
)
_MOVE_TESTABLE_ITEM = re.compile(
    r"^\s*(public\s+|public\(\w+\)\s+|entry\s+|native\s+)*(fun|module)\b"
)


def move_test_line_ranges(lines: list[str]) -> set[int]:
    """0-based line indices inside a Move `#[test]`/`#[test_only]`/`#[expected_failure]`
    item. The attribute applies to the NEXT `fun`/`module` item; brace-match its body
    and mark the whole span (attribute line through the closing brace). Returns an
    empty set for non-Move input (no Move test attribute matches)."""
    test_idx: set[int] = set()
    n = len(lines)
    i = 0
    while i < n:
        if not _MOVE_TEST_ATTR.match(lines[i]):
            i += 1
            continue
        # skip over stacked attribute lines (e.g. #[test] then #[expected_failure])
        item = i + 1
        while item < n and item <= i + 4 and not _MOVE_TESTABLE_ITEM.match(lines[item]):
            stripped = lines[item].lstrip()
            if stripped.startswith("#[") or not lines[item].strip():
                item += 1
                continue
            break
        if item >= n or item > i + 4 or not _MOVE_TESTABLE_ITEM.match(lines[item]):
            i += 1
            continue
        depth = 0
        opened = False
        j = item
        while j < n:
            for ch in lines[j]:
                if ch == "{":
                    depth += 1
                    opened = True
                elif ch == "}":
                    depth -= 1
            if opened and depth <= 0:
                break
            j += 1
        for k in range(i, min(j + 1, n)):
            test_idx.add(k)
        i = j + 1
    return test_idx


def resolve_source_roots(workspace) -> list[Path]:
    """Thin pass-through to source_root_resolver.resolve_src_roots.

    Exposed so a caller that needs the in-scope root(s) for a workspace whose
    manifest is missing can get them WITHOUT re-implementing extension walking.
    Returns [Path(workspace)] when the resolver is unavailable (fail-safe: the
    whole workspace, i.e. MORE coverage).
    """
    if _resolve_src_roots is None:  # pragma: no cover - resolver always present
        return [Path(workspace)]
    return _resolve_src_roots(workspace)


__all__ = [
    "is_generated",
    "is_test",
    "is_vendored",
    "is_cli_entrypoint",
    "is_nonprod_dir",
    "is_oos",
    "is_auditable_source",
    "load_inscope_manifest",
    "is_in_scope",
    "rust_test_line_ranges",
    "move_test_line_ranges",
    "resolve_source_roots",
    "DEFAULT_SOURCE_SUFFIXES",
    "MANIFEST_REL",
]
