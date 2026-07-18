#!/usr/bin/env python3
"""Build a cross-protocol contract similarity graph (item G2).

For every Solidity file in the configured roots compute a small bag of
fingerprints — 4-byte function selectors, inheritance parents, function-name
shingles, and import library prefixes — then emit a Jaccard-similarity graph
across files. The graph helps an operator answer "this looks like X protocol
I've audited before" in seconds and is the substrate for
``cross-protocol-bug-transfer.py``.

Design notes
------------
* Stdlib-only. Selector ``keccak256`` is computed via a pure-Python Keccak-f
  implementation lifted from PEP 458 reference / pysha3 fallback so we don't
  need ``pycryptodome`` or web3.
* Fingerprints are intentionally cheap: regex over source. Tree-sitter would
  give nicer parses but adds a large dependency for v1.
* ``--limit-per-root`` lets you cap workspace ingest so an 18k-file workspace
  doesn't dominate the graph.
* Provenance: every edge records which fingerprint contributed and what its
  Jaccard contribution was. ``top_factor`` answers "why are these similar?".

Usage
-----
    python3 tools/protocol-similarity-graph.py \
        --emit-graph reports/protocol_similarity_graph.json

Run with ``--help`` for full options.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import sys
import time
from pathlib import Path
from typing import Any, Iterable

SCHEMA_VERSION = "auditooor.protocol_similarity_graph.v1"

DEFAULT_AUDITS_ROOT = Path.home() / "audits"
REPO_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_CONTEST_CACHE = REPO_ROOT / "reference" / "contest_cache"
DEFAULT_CORPUS_MINED = REPO_ROOT / "reference" / "corpus_mined"
DEFAULT_PATTERNS_DIR = REPO_ROOT / "reference" / "patterns.dsl"

# Excluded path components — typical vendored / generated dirs.
SKIP_DIR_PARTS = {
    "node_modules",
    "out",
    "cache",
    "build",
    "broadcast",
    ".git",
    ".auditooor",
    "forge-artifacts",
    "artifacts",
    "typechain",
    "typechain-types",
    "dist",
    "coverage",
    # NOTE: ``external`` is intentionally NOT skipped — workspaces like
    # base-azul keep the in-scope source under ``external/contracts-...-clean``.
    # We rely on the per-path filters (forge-artifacts, out, etc.) to drop
    # vendored junk. ``external-prior-audits`` is, however, prior-audit Markdown
    # noise we don't want.
    "external-prior-audits",
    "_archive",
    "_archived",
    "deps",
    "vendored",
    "lib",
    # Test / harness / mock / fixture / scanner dirs — these inflate
    # cross-WS similarity with copy-pasted scaffolding rather than real
    # protocol code.
    "test",
    "tests",
    "spec",
    "specs",
    "mocks",
    "mock",
    "fixtures",
    "fixture",
    "test_fixtures",
    "test-fixtures",
    "harness",
    "harnesses",
    "chimera_harnesses",
    "recon",
    "scanners",
    "_slither-tmp",
    "spell",            # deployment scripts — same artifact under multiple chains
    "spells",
    "poc-tests",
    "poc_tests",
    "poc",
    "scanner-out",
    "scratch",
    "_scratch",
    "engage_candidates",
    "evidence",
    "agent_outputs",
}

# Workspaces under ~/audits that are dogfood / mirror / scratch — skip entirely.
SKIP_WORKSPACE_NAMES = {
    "_worklist",
    "--help",
    "auditooor",            # dogfood mirror of this repo
    "test-dogfood-r48",     # centrifuge clone for self-test
    "economic_hypotheses_ir",
    "k2",                   # empty
}

# File-name suffixes we skip — tests, scripts, mocks add noise.
SKIP_SUFFIX = (".t.sol", ".s.sol")
SKIP_FILENAME_PATTERNS = (
    re.compile(r"\.t\.sol$", re.IGNORECASE),
    re.compile(r"\.s\.sol$", re.IGNORECASE),
)

# Per-fingerprint weights (must sum > 0). Higher = bigger pull on edge weight.
FP_WEIGHTS = {
    "selectors": 0.45,
    "inherits": 0.20,
    "shingles": 0.20,
    "imports": 0.15,
}

DEFAULT_THRESHOLD = 0.50
DEFAULT_TOP_K = 50           # cap edges per node to avoid quadratic blowup
DEFAULT_MAX_FILE_BYTES = 2 * 1024 * 1024
SHINGLE_K = 4

# Files with fewer external/public selectors than this are dropped — pure
# interfaces / tiny libs match too easily and don't contribute to the
# "this looks like X protocol" signal we want.
MIN_SELECTORS_FOR_NODE = 3

# ---------------------------------------------------------------------------
# Source parsing — regex-based
# ---------------------------------------------------------------------------

CONTRACT_RE = re.compile(
    r"\b(?:abstract\s+)?(?:contract|interface|library)\s+"
    r"(?P<name>[A-Za-z_][A-Za-z0-9_]*)"
    r"(?:\s+is\s+(?P<parents>[^{]+))?",
    re.MULTILINE,
)
# Only public/external functions can have a 4-byte selector. Constructor/fallback/receive ignored.
FUNCTION_DECL_RE = re.compile(
    r"\bfunction\s+(?P<name>[A-Za-z_][A-Za-z0-9_]*)\s*"
    r"\((?P<args>[^)]*)\)"
    r"(?P<modifiers>[^{;]*)",
    re.MULTILINE | re.DOTALL,
)
IMPORT_RE = re.compile(
    r"""\bimport\b[^"';]*['"](?P<path>[^'"]+)['"]""",
    re.MULTILINE,
)

# ---------------------------------------------------------------------------
# Pure-Python Keccak-256 (function selectors).
# Adapted from the public-domain reference implementation by Renaud Bauvin.
# ---------------------------------------------------------------------------

_KECCAK_RC = [
    0x0000000000000001, 0x0000000000008082, 0x800000000000808A, 0x8000000080008000,
    0x000000000000808B, 0x0000000080000001, 0x8000000080008081, 0x8000000000008009,
    0x000000000000008A, 0x0000000000000088, 0x0000000080008009, 0x000000008000000A,
    0x000000008000808B, 0x800000000000008B, 0x8000000000008089, 0x8000000000008003,
    0x8000000000008002, 0x8000000000000080, 0x000000000000800A, 0x800000008000000A,
    0x8000000080008081, 0x8000000000008080, 0x0000000080000001, 0x8000000080008008,
]
_KECCAK_R = [
    [0, 36, 3, 41, 18],
    [1, 44, 10, 45, 2],
    [62, 6, 43, 15, 61],
    [28, 55, 25, 21, 56],
    [27, 20, 39, 8, 14],
]


def _rotl(x: int, n: int) -> int:
    return ((x << n) | (x >> (64 - n))) & 0xFFFFFFFFFFFFFFFF


def _keccak_f(state: list[list[int]]) -> list[list[int]]:
    for rnd in range(24):
        # Theta
        c = [state[x][0] ^ state[x][1] ^ state[x][2] ^ state[x][3] ^ state[x][4] for x in range(5)]
        d = [c[(x - 1) % 5] ^ _rotl(c[(x + 1) % 5], 1) for x in range(5)]
        for x in range(5):
            for y in range(5):
                state[x][y] ^= d[x]
        # Rho + Pi
        b = [[0] * 5 for _ in range(5)]
        for x in range(5):
            for y in range(5):
                b[y][(2 * x + 3 * y) % 5] = _rotl(state[x][y], _KECCAK_R[x][y])
        # Chi
        for x in range(5):
            for y in range(5):
                state[x][y] = b[x][y] ^ ((~b[(x + 1) % 5][y]) & b[(x + 2) % 5][y]) & 0xFFFFFFFFFFFFFFFF
        # Iota
        state[0][0] ^= _KECCAK_RC[rnd]
    return state


def keccak256(data: bytes) -> bytes:
    """Pure-Python Keccak-256 (Ethereum flavor — pad delim 0x01, NOT SHA-3 0x06)."""
    rate_bytes = 136
    state = [[0] * 5 for _ in range(5)]
    # Pad
    pad = bytearray(data)
    pad.append(0x01)
    while len(pad) % rate_bytes != 0:
        pad.append(0x00)
    pad[-1] |= 0x80
    # Absorb
    for offset in range(0, len(pad), rate_bytes):
        block = pad[offset:offset + rate_bytes]
        for i in range(rate_bytes // 8):
            lane = int.from_bytes(block[i * 8:i * 8 + 8], "little")
            state[i % 5][i // 5] ^= lane
        state = _keccak_f(state)
    # Squeeze (only need first 32 bytes)
    out = bytearray()
    for i in range(4):
        out += state[i % 5][i // 5].to_bytes(8, "little")
    return bytes(out[:32])


_SELECTOR_CACHE: dict[str, str] = {}


def selector_for(signature: str) -> str:
    sig = signature.replace(" ", "")
    cached = _SELECTOR_CACHE.get(sig)
    if cached is not None:
        return cached
    digest = keccak256(sig.encode("utf-8"))
    sel = digest[:4].hex()
    _SELECTOR_CACHE[sig] = sel
    return sel


# ---------------------------------------------------------------------------
# Fingerprint extraction
# ---------------------------------------------------------------------------


def _normalize_args(args: str) -> str:
    """Reduce a raw Solidity arg list to a comma-joined list of Solidity types."""
    args = args.strip()
    if not args:
        return ""
    # Strip line comments, normalize whitespace.
    args = re.sub(r"//.*?$", "", args, flags=re.MULTILINE)
    args = re.sub(r"/\*.*?\*/", "", args, flags=re.DOTALL)
    args = re.sub(r"\s+", " ", args)
    parts: list[str] = []
    for raw in _split_top_level_commas(args):
        raw = raw.strip()
        if not raw:
            continue
        # Drop "memory" / "calldata" / "storage" / parameter name.
        toks = [t for t in raw.split(" ") if t and t not in {"memory", "calldata", "storage", "indexed"}]
        if not toks:
            continue
        # First token is the type unless type itself has spaces (mapping(...) — handled below).
        if toks[0].startswith("mapping"):
            joined = " ".join(toks)
            parts.append(joined.split(")")[0] + ")")
            continue
        # Simple type — possibly + name. Type is just the first token.
        ty = toks[0]
        # Simplify "uint" → "uint256", "int" → "int256" (Solidity ABI normalization).
        if ty == "uint":
            ty = "uint256"
        elif ty == "int":
            ty = "int256"
        parts.append(ty)
    return ",".join(parts)


def _split_top_level_commas(s: str) -> list[str]:
    depth = 0
    cur = []
    out = []
    for ch in s:
        if ch in "([{":
            depth += 1
            cur.append(ch)
        elif ch in ")]}":
            depth -= 1
            cur.append(ch)
        elif ch == "," and depth == 0:
            out.append("".join(cur))
            cur = []
        else:
            cur.append(ch)
    if cur:
        out.append("".join(cur))
    return out


def _is_external_function(modifiers: str) -> bool:
    """Best-effort: function with `public` or `external` visibility (default is `public`)."""
    m = modifiers
    if "private" in m or "internal" in m:
        return False
    # No explicit visibility → defaults to public (pre-0.5) but virtually all 0.8 code is explicit.
    if "public" in m or "external" in m:
        return True
    return False


_LINE_COMMENT_RE = re.compile(r"//[^\n]*")
_BLOCK_COMMENT_RE = re.compile(r"/\*.*?\*/", re.DOTALL)
_STRING_LITERAL_RE = re.compile(r'"(?:\\.|[^"\\])*"|\'(?:\\.|[^\'\\])*\'')


def _strip_comments_and_strings(text: str) -> str:
    """Remove // and /* */ comments and string literals before regex parsing.

    Without this, NatSpec lines containing the words ``contract``/``interface``
    can leak into the contract regex (e.g. ``Vault contract before the mint``).
    """
    text = _BLOCK_COMMENT_RE.sub(" ", text)
    text = _LINE_COMMENT_RE.sub(" ", text)
    text = _STRING_LITERAL_RE.sub('""', text)
    return text


def extract_fingerprints(text: str) -> dict[str, Any]:
    text = _strip_comments_and_strings(text)
    contracts: list[dict[str, Any]] = []
    for m in CONTRACT_RE.finditer(text):
        parents = []
        if m.group("parents"):
            for p in m.group("parents").split(","):
                p = p.strip().split("(")[0].strip()
                if p:
                    parents.append(p)
        contracts.append({"name": m.group("name"), "parents": parents})

    selectors: dict[str, int] = {}
    fn_names: list[str] = []
    fn_count = 0
    for m in FUNCTION_DECL_RE.finditer(text):
        name = m.group("name")
        if not name:
            continue
        fn_count += 1
        fn_names.append(name)
        if not _is_external_function(m.group("modifiers") or ""):
            continue
        args_norm = _normalize_args(m.group("args") or "")
        sig = f"{name}({args_norm})"
        sel = selector_for(sig)
        selectors[sel] = selectors.get(sel, 0) + 1

    imports: list[str] = []
    for m in IMPORT_RE.finditer(text):
        path = m.group("path")
        # Bucket by library prefix for cross-protocol matching.
        if path.startswith("@"):
            # @scope/pkg/...
            parts = path.split("/")
            if len(parts) >= 2:
                imports.append("/".join(parts[:2]) + "/")
            else:
                imports.append(path)
        elif path.startswith("./") or path.startswith("../"):
            # Relative — record only basename to allow cross-tree matches.
            imports.append(Path(path).name)
        else:
            imports.append(path.split("/")[0])

    inherit_set = sorted({p for c in contracts for p in c["parents"]})

    fn_names_sorted = sorted(set(fn_names))
    shingles = []
    if len(fn_names_sorted) >= SHINGLE_K:
        for i in range(0, len(fn_names_sorted) - SHINGLE_K + 1):
            shingles.append("|".join(fn_names_sorted[i:i + SHINGLE_K]))
    elif fn_names_sorted:
        shingles.append("|".join(fn_names_sorted))

    return {
        "contracts": [c["name"] for c in contracts],
        "contract_count": len(contracts),
        "function_count": fn_count,
        "selectors": selectors,
        "inherits": inherit_set,
        "shingles": sorted(set(shingles)),
        "imports": sorted(set(imports)),
        "size_bytes": len(text.encode("utf-8")),
    }


# ---------------------------------------------------------------------------
# Walk roots
# ---------------------------------------------------------------------------


def iter_solidity_files(root: Path, max_files: int | None = None) -> Iterable[Path]:
    if not root.exists():
        return
    seen = 0
    for dirpath, dirnames, filenames in os.walk(root):
        # Prune skip-dirs in-place.
        dirnames[:] = [d for d in dirnames if d not in SKIP_DIR_PARTS]
        for fn in filenames:
            if not fn.endswith(".sol"):
                continue
            if any(p.search(fn) for p in SKIP_FILENAME_PATTERNS):
                continue
            yield Path(dirpath) / fn
            seen += 1
            if max_files is not None and seen >= max_files:
                return


def workspace_label(path: Path, audits_root: Path) -> str:
    try:
        rel = path.relative_to(audits_root)
        return f"audits/{rel.parts[0]}"
    except ValueError:
        pass
    try:
        rel = path.relative_to(REPO_ROOT)
        return f"repo/{rel.parts[0]}/{rel.parts[1]}" if len(rel.parts) > 1 else f"repo/{rel.parts[0]}"
    except ValueError:
        return "external"


# ---------------------------------------------------------------------------
# Patterns DSL — extract known-vulnerable contract names
# ---------------------------------------------------------------------------

CONTRACT_NAME_RE = re.compile(r"[A-Z][A-Za-z0-9_]{3,}")
NAME_REGEX_FIELDS = (
    "function.contract_name_matches_regex",
    "function.name_matches_regex",
    "contract.name_matches_regex",
    "contract.source_matches_regex",
)


def harvest_known_vulnerable_names(patterns_dir: Path, max_files: int | None = None) -> dict[str, list[str]]:
    """Return ``{contract_name -> [pattern_id, ...]}`` from pattern YAMLs.

    Stdlib YAML parsing is awkward; we just regex out the regex bodies and pull
    out CamelCase tokens. Imperfect but good enough for the lookup table.
    """
    out: dict[str, list[str]] = {}
    if not patterns_dir.exists():
        return out
    n = 0
    for path in patterns_dir.rglob("*.yaml"):
        if max_files is not None and n >= max_files:
            break
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        n += 1
        # Pattern ID = first non-comment "pattern: foo" line, else filename stem.
        pid_match = re.search(r"^pattern:\s*(\S+)", text, re.MULTILINE)
        pid = pid_match.group(1) if pid_match else path.stem
        names: set[str] = set()
        for line in text.splitlines():
            if any(field in line for field in NAME_REGEX_FIELDS):
                # Pull regex body out of single/double quotes, then harvest CamelCase tokens.
                body_match = re.search(r"['\"](.*)['\"]", line)
                if not body_match:
                    continue
                body = body_match.group(1)
                for tok in CONTRACT_NAME_RE.findall(body):
                    if tok.lower() in {"erc20", "erc721", "ierc20"}:
                        continue
                    names.add(tok)
        for name in names:
            out.setdefault(name, []).append(pid)
    return out


# ---------------------------------------------------------------------------
# Similarity calculation
# ---------------------------------------------------------------------------


def jaccard(a: set[str], b: set[str]) -> float:
    if not a and not b:
        return 0.0
    inter = len(a & b)
    union = len(a | b)
    return inter / union if union else 0.0


def jaccard_weighted(a: dict[str, int], b: dict[str, int]) -> float:
    """Weighted Jaccard over selector bags (handles repeated selectors)."""
    if not a and not b:
        return 0.0
    keys = set(a) | set(b)
    inter = sum(min(a.get(k, 0), b.get(k, 0)) for k in keys)
    union = sum(max(a.get(k, 0), b.get(k, 0)) for k in keys)
    return inter / union if union else 0.0


def file_similarity(fp_a: dict[str, Any], fp_b: dict[str, Any]) -> dict[str, Any]:
    sel = jaccard_weighted(fp_a["selectors"], fp_b["selectors"])
    inh = jaccard(set(fp_a["inherits"]), set(fp_b["inherits"]))
    sh = jaccard(set(fp_a["shingles"]), set(fp_b["shingles"]))
    imp = jaccard(set(fp_a["imports"]), set(fp_b["imports"]))
    weighted = (
        FP_WEIGHTS["selectors"] * sel
        + FP_WEIGHTS["inherits"] * inh
        + FP_WEIGHTS["shingles"] * sh
        + FP_WEIGHTS["imports"] * imp
    )
    breakdown = {
        "selectors": round(sel, 4),
        "inherits": round(inh, 4),
        "shingles": round(sh, 4),
        "imports": round(imp, 4),
    }
    contributions = {k: round(FP_WEIGHTS[k] * v, 4) for k, v in breakdown.items()}
    top_factor = max(contributions, key=contributions.get) if any(contributions.values()) else None
    return {
        "weight": round(weighted, 4),
        "breakdown": breakdown,
        "contributions": contributions,
        "top_factor": top_factor,
    }


# ---------------------------------------------------------------------------
# Inverted-index acceleration
# ---------------------------------------------------------------------------


def build_candidate_index(node_fps: list[dict[str, Any]]) -> dict[str, set[int]]:
    """Map each selector / inherit / import token to a set of node indices.

    Used so we don't compare every pair O(N^2). Two files only become candidates
    if they share at least one selector/inherits/imports token.
    """
    idx: dict[str, set[int]] = {}
    for i, fp in enumerate(node_fps):
        for sel in fp["selectors"]:
            idx.setdefault(f"sel:{sel}", set()).add(i)
        for inh in fp["inherits"]:
            idx.setdefault(f"inh:{inh}", set()).add(i)
        for imp in fp["imports"]:
            idx.setdefault(f"imp:{imp}", set()).add(i)
    return idx


def candidates_for(i: int, node_fps: list[dict[str, Any]], idx: dict[str, set[int]]) -> set[int]:
    fp = node_fps[i]
    cand: set[int] = set()
    for sel in fp["selectors"]:
        cand |= idx.get(f"sel:{sel}", set())
    for inh in fp["inherits"]:
        cand |= idx.get(f"inh:{inh}", set())
    for imp in fp["imports"]:
        cand |= idx.get(f"imp:{imp}", set())
    cand.discard(i)
    return cand


# ---------------------------------------------------------------------------
# Main builder
# ---------------------------------------------------------------------------


def build_graph(args: argparse.Namespace) -> dict[str, Any]:
    audits_root = Path(args.audits_root).expanduser()
    contest_cache = Path(args.contest_cache).expanduser()
    corpus_mined = Path(args.corpus_mined).expanduser()
    patterns_dir = Path(args.patterns_dir).expanduser()

    print(f"[similarity] audits_root={audits_root}", file=sys.stderr)
    print(f"[similarity] contest_cache={contest_cache}", file=sys.stderr)
    print(f"[similarity] corpus_mined={corpus_mined}", file=sys.stderr)

    # Harvest known-vulnerable contract names from patterns.dsl.
    print("[similarity] harvesting known-vulnerable contract names...", file=sys.stderr)
    t0 = time.time()
    known_vuln = harvest_known_vulnerable_names(patterns_dir, max_files=args.max_pattern_files)
    print(
        f"[similarity]   {sum(len(v) for v in known_vuln.values())} (name, pattern) entries "
        f"across {len(known_vuln)} unique names in {time.time() - t0:.1f}s",
        file=sys.stderr,
    )

    # Walk file roots.
    nodes: list[dict[str, Any]] = []
    node_fps: list[dict[str, Any]] = []
    seen_paths: set[str] = set()

    def ingest(path: Path, root_label: str, ws_label: str) -> None:
        sp = str(path)
        if sp in seen_paths:
            return
        seen_paths.add(sp)
        try:
            stat = path.stat()
        except OSError:
            return
        if stat.st_size > args.max_file_bytes:
            return
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            return
        # Cheap source-shape filter: must declare at least one contract/interface/library.
        if not CONTRACT_RE.search(text):
            return
        fp = extract_fingerprints(text)
        if fp["contract_count"] == 0:
            return
        # Drop trivially-shaped files (interfaces / one-method libs) from the
        # graph. They match everything and tell us nothing.
        if len(fp["selectors"]) < MIN_SELECTORS_FOR_NODE:
            return
        # Touch known-vuln overlap for later annotation.
        vuln_hits: list[dict[str, str]] = []
        for cname in fp["contracts"]:
            for pid in known_vuln.get(cname, []):
                vuln_hits.append({"contract": cname, "pattern_id": pid})
        node_id = hashlib.sha1(sp.encode("utf-8")).hexdigest()[:16]
        try:
            display = str(path.relative_to(REPO_ROOT))
        except ValueError:
            try:
                display = str(path.relative_to(Path.home()))
            except ValueError:
                display = sp
        nodes.append({
            "id": node_id,
            "path": sp,
            "display": display,
            "root": root_label,
            "workspace": ws_label,
            "contracts": fp["contracts"],
            "contract_count": fp["contract_count"],
            "function_count": fp["function_count"],
            "size_bytes": fp["size_bytes"],
            "selectors_count": len(fp["selectors"]),
            "inherits": fp["inherits"][:30],     # truncate to keep JSON small
            "imports": fp["imports"][:30],
            "known_vuln_hits": vuln_hits,
        })
        node_fps.append(fp)

    # 1) Workspace scopes under ~/audits.
    if audits_root.exists():
        for ws_dir in sorted(audits_root.iterdir()):
            if not ws_dir.is_dir():
                continue
            if ws_dir.name in SKIP_WORKSPACE_NAMES:
                # Dogfood mirrors / scratch dirs would crowd out real workspaces.
                continue
            n_before = len(nodes)
            for path in iter_solidity_files(ws_dir, max_files=args.limit_per_root):
                ingest(path, "audits", f"audits/{ws_dir.name}")
            print(
                f"[similarity]   audits/{ws_dir.name}: +{len(nodes) - n_before} files",
                file=sys.stderr,
            )

    # 2) reference/contest_cache.
    n_before = len(nodes)
    for path in iter_solidity_files(contest_cache, max_files=args.limit_per_root):
        ingest(path, "contest_cache", f"contest_cache/{path.parent.name}")
    print(f"[similarity]   contest_cache: +{len(nodes) - n_before} files", file=sys.stderr)

    # 3) reference/corpus_mined — typically markdown slices, but keep as future-proof.
    n_before = len(nodes)
    for path in iter_solidity_files(corpus_mined, max_files=args.limit_per_root):
        ingest(path, "corpus_mined", "corpus_mined")
    print(f"[similarity]   corpus_mined: +{len(nodes) - n_before} files", file=sys.stderr)

    if not nodes:
        print("[similarity] WARNING: zero nodes ingested", file=sys.stderr)

    print(f"[similarity] building candidate index over {len(nodes)} nodes...", file=sys.stderr)
    idx = build_candidate_index(node_fps)

    # Pairwise scoring with inverted-index pruning.
    print("[similarity] scoring edges...", file=sys.stderr)
    edges: list[dict[str, Any]] = []
    threshold = args.threshold
    cap = args.top_k

    t0 = time.time()
    last_progress = t0
    for i in range(len(nodes)):
        if time.time() - last_progress > 5.0:
            print(
                f"[similarity]   ...node {i}/{len(nodes)} "
                f"({len(edges)} edges so far, {time.time() - t0:.0f}s)",
                file=sys.stderr,
            )
            last_progress = time.time()
        cands = candidates_for(i, node_fps, idx)
        # Keep only j > i to avoid double-counting.
        cands = {j for j in cands if j > i}
        if not cands:
            continue
        scored: list[dict[str, Any]] = []
        for j in cands:
            sim = file_similarity(node_fps[i], node_fps[j])
            if sim["weight"] < threshold:
                continue
            scored.append({
                "src": nodes[i]["id"],
                "dst": nodes[j]["id"],
                "src_workspace": nodes[i]["workspace"],
                "dst_workspace": nodes[j]["workspace"],
                "weight": sim["weight"],
                "breakdown": sim["breakdown"],
                "contributions": sim["contributions"],
                "top_factor": sim["top_factor"],
            })
        scored.sort(key=lambda e: e["weight"], reverse=True)
        edges.extend(scored[:cap])

    edges.sort(key=lambda e: e["weight"], reverse=True)

    graph = {
        "schema_version": SCHEMA_VERSION,
        "generated_at": int(time.time()),
        "config": {
            "threshold": threshold,
            "top_k_per_node": cap,
            "fp_weights": FP_WEIGHTS,
            "audits_root": str(audits_root),
            "contest_cache": str(contest_cache),
            "corpus_mined": str(corpus_mined),
            "patterns_dir": str(patterns_dir),
            "limit_per_root": args.limit_per_root,
            "max_file_bytes": args.max_file_bytes,
        },
        "stats": {
            "node_count": len(nodes),
            "edge_count": len(edges),
            "known_vuln_names": len(known_vuln),
            "build_seconds": round(time.time() - t0, 1),
        },
        "nodes": nodes,
        "edges": edges,
    }
    return graph


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    p = argparse.ArgumentParser(description="Build cross-protocol contract similarity graph")
    p.add_argument("--audits-root", default=str(DEFAULT_AUDITS_ROOT),
                   help="Root for ~/audits/<workspace>/ scopes (default: %(default)s)")
    p.add_argument("--contest-cache", default=str(DEFAULT_CONTEST_CACHE),
                   help="reference/contest_cache root")
    p.add_argument("--corpus-mined", default=str(DEFAULT_CORPUS_MINED),
                   help="reference/corpus_mined root")
    p.add_argument("--patterns-dir", default=str(DEFAULT_PATTERNS_DIR),
                   help="reference/patterns.dsl root")
    p.add_argument("--emit-graph", default="reports/protocol_similarity_graph.json",
                   help="Output JSON path")
    p.add_argument("--threshold", type=float, default=DEFAULT_THRESHOLD,
                   help="Minimum edge weight (default: %(default)s)")
    p.add_argument("--top-k", type=int, default=DEFAULT_TOP_K,
                   help="Max edges per node (default: %(default)s)")
    p.add_argument("--limit-per-root", type=int, default=2500,
                   help="Cap files ingested per workspace/root to bound runtime "
                        "(set to 0 to disable)")
    p.add_argument("--max-file-bytes", type=int, default=DEFAULT_MAX_FILE_BYTES,
                   help="Skip files larger than this many bytes")
    p.add_argument("--max-pattern-files", type=int, default=None,
                   help="Cap patterns.dsl YAMLs harvested (debug)")
    args = p.parse_args(argv)
    if args.limit_per_root == 0:
        args.limit_per_root = None
    return args


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    graph = build_graph(args)
    out = Path(args.emit_graph)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(graph, indent=2, sort_keys=False))
    s = graph["stats"]
    print(
        f"[similarity] DONE  nodes={s['node_count']}  edges={s['edge_count']}  "
        f"out={out}",
        file=sys.stderr,
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
