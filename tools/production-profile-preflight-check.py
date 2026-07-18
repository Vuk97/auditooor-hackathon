#!/usr/bin/env python3
"""Rule 30 production-profile PoC preflight.

Fails HIGH/CRITICAL blockchain state-machine claims when the cited PoC relies
on weak execution profiles that recent Cantina triage rejected: in-memory-DB
storage, DB timing shims, private-field reflection, single-validator evidence
for network-level claims, missing hardware-envelope disclosure, or undisclosed
backend-dependent bug-shape changes.

The Rule itself is language/ecosystem agnostic. The implementation recognises
weak-backend, real-backend, timing-wrapper, reflection/unsafe-write, and
node-binary equivalents across Go/cosmos-sdk, Rust/Substrate, EVM-clients
(geth/reth) + Foundry, and Solana. The cross-ecosystem defaults are correct
out-of-the-box; each pattern family is also env-extendable:

  AUDITOOOR_R30_REAL_BACKEND_PATTERNS    - real persistent-backend regexes
  AUDITOOOR_R30_MEMDB_PATTERNS           - in-memory / weak-backend regexes
  AUDITOOOR_R30_TIMING_WRAPPER_PATTERNS  - DB timing/fault-shim regexes
  AUDITOOOR_R30_REFLECTION_PATTERNS      - reflection / unsafe-write regexes
  AUDITOOOR_R30_NODE_BINARY_PATTERNS     - node-binary spawn regexes

Each env var is newline-separated regex, appended to the built-in defaults.

Exit codes:
  0 - pass, out-of-scope, or pass-with-rebuttal
  1 - Rule 30 violation
  2 - input / resolution error
"""

from __future__ import annotations

import argparse
import json
import os
import re
import sys
from pathlib import Path
from typing import Any


GATE = "R30-PRODUCTION-PROFILE-PREFLIGHT"

SEVERITY_RANK = {
    "low": 1,
    "medium": 2,
    "high": 3,
    "critical": 4,
}

SCOPE_KEYWORDS = [
    "network-level downtime",
    "liveness failure",
    "liveness failures",
    "halting block production",
    "halt the chain",
    "consensus halt",
    "validator halt",
    "apphash divergence",
    "state-sync",
    "state sync",
    "post-restore",
    "permanent freezing",
    "matching engine degradation",
]

def _compile(defaults: list[str], env_name: str | None = None, flags: int = 0) -> re.Pattern[str]:
    """Compile an alternation of default regexes, appending env-supplied ones.

    Mirrors the sibling-gate pattern in in-process-vs-node-level-check.py.
    The env var is newline-separated; blank lines are ignored.
    """
    merged = list(defaults)
    if env_name and os.environ.get(env_name):
        merged.extend(line.strip() for line in os.environ[env_name].splitlines() if line.strip())
    return re.compile("|".join(f"(?:{pat})" for pat in merged), flags)


# --- Real persistent-backend equivalents (cross-ecosystem) -----------------
# Go/cosmos-sdk: GoLevelDB / PebbleDB / RocksDB.
# Rust/Substrate: kvdb-rocksdb, paritydb, sc_client_db on-disk backend.
# EVM clients: reth_db / MdbxDatabase, geth leveldb/pebble; forked-mainnet
#   test (vm.createFork / --fork-url) is a real-state surface.
# Solana: on-disk AccountsDb with a tempdir ledger.
REAL_BACKEND_DEFAULTS = [
    r"\bdbm\.NewGoLevelDB\b",
    r"\bdbm\.NewPebbleDB\b",
    r"\bdbm\.NewRocksDB\b",
    r"\bcosmos-db\.NewGoLevelDB\b",
    r"\bcosmos-db\.NewPebbleDB\b",
    r"\bcosmos-db\.NewRocksDB\b",
    r"\bdb\.NewGoLevelDB\b",
    r"\bdb\.NewPebbleDB\b",
    r"\bdb\.NewRocksDB\b",
    r"\bGoLevelDBBackend\b",
    r"\bPebbleDBBackend\b",
    r"\bRocksDBBackend\b",
    # Substrate / Rust real backends
    r"\bkvdb[-_]rocksdb\b",
    r"\bkvdb_rocksdb\b",
    r"\bparitydb\b",
    r"\bparity_db\b",
    r"\bsc_client_db\b",
    r"\bsc-client-db\b",
    r"\bDatabaseSettingsSrc::RocksDb\b",
    # EVM-client real backends
    r"\breth_db\b",
    r"\bMdbxDatabase\b",
    r"\bDatabaseEnv\b",
    r"\bleveldb\.OpenFile\b",
    r"\bpebble\.Open\b",
    # Foundry forked-mainnet test == real state surface
    r"\bvm\.createFork\b",
    r"\bvm\.createSelectFork\b",
    r"--fork-url\b",
    r"\bforge\s+test\b[^\n]*--fork",
    # Solana on-disk AccountsDb
    r"\bAccountsDb::new_with_config\b",
    r"\bAccountsDb::new_single_for_tests_with_provider\b",
    r"\bcreate_genesis_config_with_leader\b[^\n]*ledger",
    r"\bnew_from_paths\b",
]
REAL_BACKEND_RE = _compile(REAL_BACKEND_DEFAULTS, "AUDITOOOR_R30_REAL_BACKEND_PATTERNS")

# --- In-memory / weak-backend equivalents (cross-ecosystem) ----------------
# Go/cosmos-sdk: MemDB.
# Substrate: TestExternalities, sp_state_machine::InMemoryBackend, new_test_ext.
# EVM: MemoryDB, EmptyDB, CacheDB::new, an in-memory `forge test` (no fork).
# Solana: AccountsDb::new_for_tests, Bank::new_for_tests.
MEMDB_DEFAULTS = [
    r"\bcosmos-db\.NewMemDB\b",
    r"\bdbm\.NewMemDB\b",
    r"\bdb\.NewMemDB\b",
    r"\bmemdb\.NewDB\b",
    # Substrate / Rust in-memory
    r"\bTestExternalities\b",
    r"\bsp_state_machine::InMemoryBackend\b",
    r"\bInMemoryBackend::\b",
    r"\bnew_test_ext\b",
    r"\bBasicExternalities\b",
    # EVM in-memory
    r"\bMemoryDB\b",
    r"\bEmptyDB\b",
    r"\bEmptyDBTyped\b",
    r"\bCacheDB::new\b",
    r"\bStateProviderTest\b",
    # Solana in-memory test banks
    r"\bAccountsDb::new_for_tests\b",
    r"\bAccountsDb::new_single_for_tests\b",
    r"\bBank::new_for_tests\b",
    r"\bBank::new_with_config_for_tests\b",
]
MEMDB_RE = _compile(MEMDB_DEFAULTS, "AUDITOOOR_R30_MEMDB_PATTERNS")

# --- DB timing / fault-shim equivalents ------------------------------------
TIMING_WRAPPER_DEFAULTS = [
    r"\bslowBatchDB\b",
    r"\bdelayDB\b",
    r"\blatencyShim\b",
    r"\bpanicMockDB\b",
    r"\bfaultyDB\b",
    r"\bfaultyBatch\b",
    r"\b\w*BatchWrapper\w*Sleep\w*\b",
    r"\b\w*DB\w*Sleep\w*\b",
    r"\b\w*Wrapper\w*Delay\w*\b",
    # Rust / generic timing shims
    r"\bSlowDb\b",
    r"\bLatencyDb\b",
    r"\bDelayingBackend\b",
    r"\bThrottledDb\b",
    r"\b\w*Db\w*Sleep\w*\b",
]
TIMING_WRAPPER_RE = _compile(
    TIMING_WRAPPER_DEFAULTS, "AUDITOOOR_R30_TIMING_WRAPPER_PATTERNS", re.IGNORECASE
)

# --- Reflection / unsafe-write equivalents ---------------------------------
# Go: reflect.NewAt, unsafe.Pointer, reflect .Set*.
# Rust: unsafe blocks, std::mem::transmute, raw *mut writes.
# Solidity (Foundry): vm.store cheatcode slot-seeding.
# TS/JS: Object.defineProperty.
REFLECTION_WRITE_DEFAULTS = [
    r"reflect\.NewAt",
    r"unsafe\.Pointer",
    r"\.Set(?:String|Int|Uint|Bytes|Bool)?\s*\(",
    # Rust unsafe / transmute / raw-pointer write
    r"\bunsafe\s*\{",
    r"\bstd::mem::transmute\b",
    r"\bcore::mem::transmute\b",
    r"\*mut\s+\w",
    r"\bptr::write\b",
    r"\bptr::write_unaligned\b",
    # Solidity Foundry slot seeding
    r"\bvm\.store\s*\(",
    # TS/JS private-field override
    r"\bObject\.defineProperty\s*\(",
]
REFLECTION_WRITE_RE = _compile(REFLECTION_WRITE_DEFAULTS, "AUDITOOOR_R30_REFLECTION_PATTERNS")

REFLECTION_TARGET_RE = re.compile(
    r"\b(?:legacyLatestVersion|iavl\.|nodedb\.|rootmulti\.|baseapp\.|"
    r"cosmos-sdk|cosmossdk\.io/store|/store/|store\.)\b",
    re.IGNORECASE,
)

INTERNAL_STATE_WRITE_RE = re.compile(
    r"\b(?:Batch\.Set|batch\.Set|db\.Set|nodeDB\.Set|store\.Set|rootStore\.Set|"
    r"SetSyncInfo|SetLatestVersion|SetLegacyLatestVersion|setLegacyLatestVersion)\s*\(",
    re.IGNORECASE,
)

INTERNAL_STATE_CONTEXT_RE = re.compile(
    r"\b(?:legacyLatestVersion|latestVersion|iavl|nodedb|rootmulti|baseapp|"
    r"commitInfo|orphan|pruning|internal[-_ ]?key|raw[-_ ]?store[-_ ]?key|"
    r"private[-_ ]?state|synthetic[-_ ]?state)\b",
    re.IGNORECASE,
)

PRIVATE_VERSION_ASSIGN_RE = re.compile(
    r"\b(?:legacyLatestVersion|latestVersion)\b\s*(?::=|=)",
    re.IGNORECASE,
)

NETWORK_CLAIM_RE = re.compile(
    r"network-level|multi-validator|consensus halt|chain halt|"
    r"validator-cluster halt|AppHash divergence between",
    re.IGNORECASE,
)

MULTI_VALIDATOR_RE = re.compile(
    r"NumValidators\s*(?:[:=]|=)\s*(?:[2-9]|\d{2,})|"
    r"numValidators\s*(?::=|=)\s*(?:[2-9]|\d{2,})",
)

APP_SETUP_RE = re.compile(r"\b(?:app|testapp)\.\w*Setup\w*\s*\(")

# Node-binary spawn detection. Env-driven default covers cosmos-sdk app
# binaries plus cometbft/geth/reth/op-geth/polkadot/substrate/Solana.
NODE_BINARY_DEFAULTS = [
    r"dydxprotocold",
    r"\bappd\b",
    r"\bsparkd\b",
    r"cometbft",
    r"tendermint",
    r"\bgeth\b",
    r"\breth\b",
    r"op-geth",
    r"op-reth",
    r"\bpolkadot\b",
    r"\bsubstrate\b",
    r"solana-test-validator",
    r"\bsolana-validator\b",
]
NODE_BINARY_RE = _compile(NODE_BINARY_DEFAULTS, "AUDITOOOR_R30_NODE_BINARY_PATTERNS")
# A spawn of any recognised node binary via an exec/spawn primitive.
NODE_COMMAND_RE = re.compile(
    r"(?:exec\.Command|Command::new|child_process\.\w+|subprocess\.\w+|os\.exec)"
    r"[^\n]*?(?:"
    + "|".join(NODE_BINARY_DEFAULTS)
    + r")",
    re.DOTALL | re.IGNORECASE,
)

TIMING_TRIGGER_RE = re.compile(
    r"\b(?:latency|jitter|p99|contention|disk speed|throughput-bound|"
    r"race window)\b",
    re.IGNORECASE,
)

HARDWARE_ENVELOPE_RE = re.compile(
    r"hardware envelope|documented validator hardware|production-profile-disk|"
    r"SSD/NVMe baseline|NVMe baseline|validator hardware envelope",
    re.IGNORECASE,
)

BUG_CLASS_SHIFT_TRIGGER_RE = re.compile(
    r"(?:MemDB[\s\S]{0,400}(?:GoLevelDB|PebbleDB)|"
    r"(?:GoLevelDB|PebbleDB)[\s\S]{0,400}MemDB|"
    r"deadlock[\s\S]{0,400}unlock of unlocked mutex|"
    r"observable failure mode|backend-class sensitivity)",
    re.IGNORECASE,
)

BUG_CLASS_SHIFT_DISCLOSURE_RE = re.compile(
    r"bug class (?:is )?unchanged|same root cause|same call-?site|"
    r"trigger conditions (?:are )?preserved|impact (?:is )?preserved|"
    r"bug-class-shift disclosure|observable shape",
    re.IGNORECASE,
)

REBUTTAL_RE = re.compile(r"<!--\s*r30-rebuttal:\s*(.*?)\s*-->", re.IGNORECASE | re.DOTALL)


def _read_text(path: Path) -> str:
    return path.read_text(encoding="utf-8", errors="replace")


def _line_hits(path: Path, pattern: re.Pattern[str]) -> list[dict[str, Any]]:
    hits: list[dict[str, Any]] = []
    try:
        text = _read_text(path)
    except Exception:
        return hits
    for idx, line in enumerate(text.splitlines(), start=1):
        if pattern.search(line):
            hits.append({"path": str(path), "line": idx, "text": line.strip()[:220]})
    return hits


def _extract_severity(text: str, path: Path) -> tuple[str | None, str]:
    patterns = [
        (r"(?im)^\s*Severity\s*:\s*(Critical|High|Medium|Low)\b", "severity-header"),
        (r"(?im)^\s*severity_implied\s*:\s*(Critical|High|Medium|Low)\b", "program-impact-mapping"),
        (r"(?im)^\s*selected_severity\s*:\s*(Critical|High|Medium|Low)\b", "selected-severity"),
    ]
    for pat, source in patterns:
        m = re.search(pat, text)
        if m:
            return m.group(1).lower(), source
    name = path.name.lower()
    for sev in ("critical", "high", "medium", "low"):
        if re.search(rf"(?:^|[-_]){sev}(?:[-_.]|$)", name):
            return sev, "filename"
    m = re.search(r"\b(?:at|as|is|retained|unchanged at)\s+(CRITICAL|HIGH|MEDIUM|LOW)\b", text)
    if m:
        return m.group(1).lower(), "body"
    return None, "missing"


def _scope_hits(text: str) -> list[str]:
    lower = text.lower()
    return [kw for kw in SCOPE_KEYWORDS if kw.lower() in lower]


def _workspace_root(draft: Path) -> Path:
    cur = draft.resolve().parent
    for parent in [cur, *cur.parents]:
        if (parent / "poc-tests").is_dir() or (parent / "submissions").is_dir():
            return parent
    return draft.resolve().parent


def _clean_ref(ref: str) -> str:
    return ref.strip().strip("`'\"").rstrip(").,;:")


def _resolve_poc_paths(draft: Path, text: str) -> list[Path]:
    root = _workspace_root(draft)
    refs: list[str] = []

    for m in re.finditer(r"<!--\s*poc-dir:\s*([^>]+?)\s*-->", text, re.IGNORECASE):
        refs.append(m.group(1))
    for m in re.finditer(r"(?im)^\s*(?:poc[_ -]?dir|poc[_ -]?path|PoC directory)\s*:\s*(.+?)\s*$", text):
        refs.append(m.group(1))
    for m in re.finditer(r"\bpoc-tests/[A-Za-z0-9_.\-/]+", text):
        refs.append(m.group(0))

    resolved: list[Path] = []
    for raw in refs:
        ref = _clean_ref(raw)
        if not ref or "<" in ref or ">" in ref:
            continue
        candidates = []
        p = Path(ref).expanduser()
        if p.is_absolute():
            candidates.append(p)
        else:
            candidates.extend([root / p, draft.parent / p, Path.cwd() / p])
        for cand in candidates:
            if cand.exists():
                if cand.is_file():
                    cand = cand.parent
                if cand not in resolved:
                    resolved.append(cand)
                break
    return resolved


SOURCE_SUFFIXES = (".go", ".rs", ".sol", ".ts")

# Map a file suffix to the PoC ecosystem it implies.
SUFFIX_LANGUAGE = {
    ".go": "go",
    ".rs": "rust",
    ".sol": "solidity",
    ".ts": "typescript",
}


def _source_files(paths: list[Path]) -> list[Path]:
    """Collect PoC source files across supported ecosystems (.go/.rs/.sol/.ts)."""
    files: list[Path] = []
    for path in paths:
        if path.is_file() and path.suffix in SOURCE_SUFFIXES:
            files.append(path)
        elif path.is_dir():
            for suffix in SOURCE_SUFFIXES:
                files.extend(sorted(path.rglob(f"*{suffix}")))
    return files


def _detect_languages(files: list[Path]) -> list[str]:
    """Distinct ecosystems present in the resolved PoC source set."""
    langs: list[str] = []
    for path in files:
        lang = SUFFIX_LANGUAGE.get(path.suffix)
        if lang and lang not in langs:
            langs.append(lang)
    return langs


def _combined_source_text(files: list[Path]) -> str:
    chunks = []
    for path in files:
        try:
            chunks.append(_read_text(path))
        except Exception:
            pass
    return "\n".join(chunks)


def _rebuttal_text(text: str) -> str | None:
    m = REBUTTAL_RE.search(text)
    if not m:
        return None
    return " ".join(m.group(1).split())


def _covered_by_rebuttal(reason: str | None, clause: str) -> bool:
    if not reason or len(reason) > 200:
        return False
    lower = reason.lower()
    if "all" in lower or "production-profile" in lower:
        return True
    if re.search(rf"(?:\({clause}\)|\bclause\s+{clause}\b|\b{clause}\b)", lower):
        return True
    synonyms = {
        "a": ["backend", "goleveldb", "pebbledb", "persistent"],
        "b": ["timing", "shim", "delay", "sleep"],
        "c": ["reflection", "private field", "unsafe", "state seeding", "batch.set", "db key", "private state"],
        "d": ["multi-validator", "validator", "network-level"],
        "e": ["hardware", "envelope", "nvme", "latency"],
        "f": ["bug-class", "same root", "same call", "observable"],
    }
    return any(token in lower for token in synonyms[clause])


def _check_a(files: list[Path]) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    mem_hits: list[dict[str, Any]] = []
    backend_hits: list[dict[str, Any]] = []
    for path in files:
        mem_hits.extend(_line_hits(path, MEMDB_RE))
        backend_hits.extend(_line_hits(path, REAL_BACKEND_RE))
    if mem_hits and not backend_hits:
        return (
            [{"constraint": "a", "reason": "in-memory-DB-only PoC; no persistent backend signal", "hits": mem_hits[:8]}],
            backend_hits,
        )
    if not mem_hits and not backend_hits:
        # No-silent-skip: a resolved PoC with neither a weak-backend nor a
        # real-backend signal still has zero production-profile evidence for a
        # HIGH+ scoped claim. Flag it instead of silently passing.
        return (
            [{
                "constraint": "a",
                "reason": "no real-backend evidence found in any recognised language; "
                          "production-profile proof is absent",
                "hits": [],
            }],
            backend_hits,
        )
    return ([], backend_hits[:8] or mem_hits[:4])


def _db_wrapper_types(text: str) -> set[str]:
    db_types: set[str] = set()
    for m in re.finditer(r"type\s+(\w+)\s+struct\s*\{([\s\S]*?)\}", text):
        name, body = m.group(1), m.group(2)
        if re.search(r"\b(?:dbm\.DB|db\.DB|DB|Batch|BatchWithFlusher)\b", body):
            db_types.add(name)
    return db_types


def _sleep_in_db_method(path: Path) -> list[dict[str, Any]]:
    hits: list[dict[str, Any]] = []
    text = _read_text(path)
    db_types = _db_wrapper_types(text)
    lines = text.splitlines()
    for idx, line in enumerate(lines):
        if "time.Sleep" not in line:
            continue
        start = max(0, idx - 30)
        context = "\n".join(lines[start : idx + 1])
        m = re.search(r"func\s*\(\s*(?:\w+\s+)?\*?(\w+)\s*\)\s*(\w+)\s*\(", context)
        if not m:
            continue
        recv_type, method = m.group(1), m.group(2)
        if method == "TestMain":
            continue
        if recv_type in db_types or re.search(r"(DB|Batch|Wrapper)", recv_type) or method in {
            "Set",
            "Get",
            "Has",
            "Delete",
            "Write",
            "Commit",
            "NewBatch",
            "NewBatchWithSize",
        }:
            hits.append({"path": str(path), "line": idx + 1, "text": line.strip()[:220]})
    return hits


def _check_b(files: list[Path], draft_text: str) -> list[dict[str, Any]]:
    if re.search(r"no timing shim|real backend, no delay wrappers", draft_text, re.IGNORECASE):
        disclosure = True
    else:
        disclosure = False
    hits: list[dict[str, Any]] = []
    for path in files:
        hits.extend(_line_hits(path, TIMING_WRAPPER_RE))
        try:
            hits.extend(_sleep_in_db_method(path))
        except Exception:
            pass
    if hits:
        return [{"constraint": "b", "reason": "DB timing/fault shim detected", "hits": hits[:10]}]
    if not disclosure:
        return []
    return []


def _internal_state_mutation_hits(path: Path) -> list[dict[str, Any]]:
    hits: list[dict[str, Any]] = []
    text = _read_text(path)
    lines = text.splitlines()
    for idx, line in enumerate(lines):
        context = "\n".join(lines[max(0, idx - 4) : min(len(lines), idx + 5)])
        if PRIVATE_VERSION_ASSIGN_RE.search(line):
            hits.append({"path": str(path), "line": idx + 1, "text": line.strip()[:220]})
            continue
        if INTERNAL_STATE_WRITE_RE.search(line) and INTERNAL_STATE_CONTEXT_RE.search(context):
            hits.append({"path": str(path), "line": idx + 1, "text": line.strip()[:220]})
    return hits


# Non-Go reflection / unsafe-write smells. These are direct PoC-harness
# anti-patterns in their ecosystems (Rust unsafe state pokes, Foundry vm.store
# slot seeding, TS private-field overrides) and do not need the Go-specific
# runtime-target gating that prevents FPs on local-test-type reflection.
NONGO_REFLECTION_RE = re.compile(
    r"\bunsafe\s*\{"
    r"|\bstd::mem::transmute\b"
    r"|\bcore::mem::transmute\b"
    r"|\*mut\s+\w"
    r"|\bptr::write(?:_unaligned)?\b"
    r"|\bvm\.store\s*\("
    r"|\bObject\.defineProperty\s*\(",
)


def _check_c(files: list[Path]) -> list[dict[str, Any]]:
    all_hits: list[dict[str, Any]] = []
    mutation_hits: list[dict[str, Any]] = []
    for path in files:
        text = _read_text(path)
        try:
            mutation_hits.extend(_internal_state_mutation_hits(path))
        except Exception:
            pass
        if path.suffix == ".go":
            # Go: keep the tight cosmos-runtime-target gating intact so
            # cosmos drafts pass/fail exactly as before.
            if REFLECTION_TARGET_RE.search(text):
                if not ("FieldByName" in text or "reflect.NewAt" in text or "unsafe.Pointer" in text):
                    continue
                if not REFLECTION_WRITE_RE.search(text):
                    continue
                all_hits.extend(_line_hits(path, REFLECTION_WRITE_RE))
        else:
            # Rust / Solidity / TypeScript: reflection/unsafe-write smells
            # are flagged directly.
            all_hits.extend(_line_hits(path, NONGO_REFLECTION_RE))
    all_hits.extend(mutation_hits)
    if not all_hits:
        return []
    return [
        {
            "constraint": "c",
            "reason": "reflection/unsafe/private-state write against runtime state detected",
            "hits": all_hits[:8],
        }
    ]


def _check_d(files: list[Path], draft_text: str, go_text: str) -> list[dict[str, Any]]:
    if not NETWORK_CLAIM_RE.search(draft_text):
        return []
    pass_signal = bool(MULTI_VALIDATOR_RE.search(go_text))
    app_spawns = len(APP_SETUP_RE.findall(go_text))
    process_spawns = len(NODE_COMMAND_RE.findall(go_text))
    if app_spawns >= 2 or process_spawns >= 2:
        pass_signal = True
    if pass_signal:
        return []
    return [
        {
            "constraint": "d",
            "reason": "network-level claim without >=2 validator evidence",
            "hits": [{"path": str(path), "line": 0, "text": "no multi-validator signal found"} for path in files[:3]],
        }
    ]


def _check_e(draft_text: str, go_text: str) -> list[dict[str, Any]]:
    if not TIMING_TRIGGER_RE.search(draft_text + "\n" + go_text):
        return []
    if HARDWARE_ENVELOPE_RE.search(draft_text):
        return []
    return [
        {
            "constraint": "e",
            "reason": "timing-dependent claim lacks hardware-envelope comparison",
            "hits": [],
        }
    ]


def _check_f(draft_text: str, go_text: str) -> list[dict[str, Any]]:
    # Clause (f) is about a claimed observable bug-shape delta between weak and
    # production backends. Merely using MemDB for harmless setup while also
    # using GoLevelDB in the production-profile test is covered by clause (a)
    # and must not trigger (f).
    if not BUG_CLASS_SHIFT_TRIGGER_RE.search(draft_text):
        return []
    if BUG_CLASS_SHIFT_DISCLOSURE_RE.search(draft_text):
        return []
    return [
        {
            "constraint": "f",
            "reason": "backend-dependent failure-shape shift lacks bug-class-shift disclosure",
            "hits": [],
        }
    ]


def _payload(
    draft: Path,
    verdict: str,
    failed: list[dict[str, Any]] | None = None,
    evidence: list[dict[str, Any]] | None = None,
    remediation: list[str] | None = None,
    **extra: Any,
) -> dict[str, Any]:
    return {
        "file": str(draft),
        "gate": GATE,
        "verdict": verdict,
        "failed_constraints": failed or [],
        "evidence": evidence or [],
        "remediation_options": remediation or [],
        **extra,
    }


def run(draft: Path) -> tuple[int, dict[str, Any]]:
    if not draft.is_file():
        return 2, _payload(draft, "error", remediation=["provide an existing draft file"], error="draft not found")

    text = _read_text(draft)
    severity, severity_source = _extract_severity(text, draft)
    if severity is None:
        return 0, _payload(draft, "out-of-scope", severity_source=severity_source, reason="no severity signal")
    if SEVERITY_RANK.get(severity, 0) < SEVERITY_RANK["high"]:
        return 0, _payload(draft, "out-of-scope", severity=severity, reason="severity below HIGH")

    hits = _scope_hits(text)
    if not hits:
        return 0, _payload(draft, "out-of-scope", severity=severity, reason="no Rule 30 rubric keyword")

    rebuttal = _rebuttal_text(text)

    poc_paths = _resolve_poc_paths(draft, text)
    if not poc_paths:
        # No-silent-skip: a HIGH+ scoped claim with no resolvable PoC dir has
        # zero production-profile evidence. An accepted r30-rebuttal covers it;
        # otherwise this is a real failure, not a non-blocking error.
        if rebuttal and len(rebuttal) <= 200:
            return 0, _payload(
                draft,
                "pass-with-rebuttal",
                severity=severity,
                severity_source=severity_source,
                scope_keywords=hits,
                covered_by_rebuttal=[{"constraint": "all", "reason": "no PoC dir", "rebuttal": rebuttal}],
            )
        return 1, _payload(
            draft,
            "fail-no-production-profile-evidence",
            failed=[{
                "constraint": "a",
                "reason": "HIGH+ scoped claim with no resolvable PoC directory; "
                          "no production-profile evidence in any language",
                "hits": [],
            }],
            remediation=[
                "add a resolvable PoC directory reference, e.g. `poc-tests/<dir>`",
                "rebuild the PoC on a real persistent backend (GoLevelDB/PebbleDB/RocksDB, "
                "kvdb-rocksdb/paritydb, reth_db/Mdbx, forked-mainnet, on-disk AccountsDb)",
                "or downgrade below HIGH if production-profile proof is not available",
                "or add <!-- r30-rebuttal: <reason> --> for a bounded exception",
            ],
            severity=severity,
            severity_source=severity_source,
            scope_keywords=hits,
            error="PoC dir could not be resolved",
        )

    files = _source_files(poc_paths)
    if not files:
        # No-silent-skip: PoC dir resolved but contains no recognised source
        # file (.go/.rs/.sol/.ts). For a HIGH+ scoped claim this is a real
        # failure - the tool used to return rc=2 here, which pre-submit-check
        # treats as a non-blocking pass.
        if rebuttal and len(rebuttal) <= 200:
            return 0, _payload(
                draft,
                "pass-with-rebuttal",
                severity=severity,
                severity_source=severity_source,
                scope_keywords=hits,
                poc_dirs=[str(p) for p in poc_paths],
                covered_by_rebuttal=[{"constraint": "all", "reason": "no recognised source files", "rebuttal": rebuttal}],
            )
        return 1, _payload(
            draft,
            "fail-no-production-profile-evidence",
            failed=[{
                "constraint": "a",
                "reason": "PoC directory contains no recognised source file "
                          "(.go/.rs/.sol/.ts); no production-profile evidence in any language",
                "hits": [],
            }],
            remediation=[
                "ensure the cited PoC directory contains Go/Rust/Solidity/TypeScript source files",
                "rebuild the PoC on a real persistent backend for the target ecosystem",
                "or downgrade below HIGH if production-profile proof is not available",
                "or add <!-- r30-rebuttal: <reason> --> for a bounded exception",
            ],
            severity=severity,
            severity_source=severity_source,
            scope_keywords=hits,
            poc_dirs=[str(p) for p in poc_paths],
            error="no recognised source files found under PoC dir",
        )

    poc_languages = _detect_languages(files)
    go_text = _combined_source_text(files)
    failures: list[dict[str, Any]] = []
    evidence: list[dict[str, Any]] = []

    a_failures, a_evidence = _check_a(files)
    failures.extend(a_failures)
    evidence.extend({"constraint": "a", **hit} for hit in a_evidence[:6])
    failures.extend(_check_b(files, text))
    failures.extend(_check_c(files))
    failures.extend(_check_d(files, text, go_text))
    failures.extend(_check_e(text, go_text))
    failures.extend(_check_f(text, go_text))

    # rebuttal already extracted above (no-silent-skip branches reuse it).
    uncovered = [
        f
        for f in failures
        if not _covered_by_rebuttal(rebuttal, str(f.get("constraint") or ""))
    ]
    covered = [f for f in failures if f not in uncovered]

    remediation = [
        "rerun the PoC on a real persistent backend for the target ecosystem "
        "(cosmos: GoLevelDB/PebbleDB/RocksDB; Substrate: kvdb-rocksdb/paritydb; "
        "EVM: reth_db/Mdbx or a forked-mainnet test; Solana: on-disk AccountsDb)",
        "remove DB timing/fault shims and private-field reflection/unsafe writes "
        "from HIGH+ evidence",
        "use >=2 validators for network-level claims",
        "add a hardware-envelope comparison for timing-dependent claims",
        "disclose any backend-dependent observable bug-shape shift",
        "or walk back severity below HIGH",
    ]

    if uncovered:
        return 1, _payload(
            draft,
            "fail",
            failed=uncovered,
            evidence=evidence,
            remediation=remediation,
            severity=severity,
            severity_source=severity_source,
            scope_keywords=hits,
            poc_dirs=[str(p) for p in poc_paths],
            poc_languages=poc_languages,
            covered_by_rebuttal=covered,
        )
    if failures:
        return 0, _payload(
            draft,
            "pass-with-rebuttal",
            failed=[],
            evidence=evidence,
            remediation=[],
            severity=severity,
            severity_source=severity_source,
            scope_keywords=hits,
            poc_dirs=[str(p) for p in poc_paths],
            poc_languages=poc_languages,
            covered_by_rebuttal=covered,
        )
    return 0, _payload(
        draft,
        "pass",
        evidence=evidence,
        severity=severity,
        severity_source=severity_source,
        scope_keywords=hits,
        poc_dirs=[str(p) for p in poc_paths],
        poc_languages=poc_languages,
    )


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("draft", type=Path)
    args = parser.parse_args(argv)
    rc, payload = run(args.draft)
    print(json.dumps(payload, indent=2, sort_keys=True))
    return rc


if __name__ == "__main__":
    raise SystemExit(main())
