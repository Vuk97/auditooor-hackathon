"""scope_oos_globs.py - GENERIC SCOPE.md out-of-scope (OOS) glob extraction.

MOTIVATION (real failure, 2026-07-05): an audit workspace's SCOPE.md documented
OOS carve-outs (e.g. SEI: Autobahn consensus OUT, non-executor ``giga/`` packages
OUT except ``giga/executor``, evmone backend OUT, StateSync-peer OUT), yet the
hunt-dispatch path had NO scope gate, so the orchestrator dispatched OOS units to
hunters wave after wave. This module turns the free-text OOS section of SCOPE.md
into a machine-checkable {exclude_globs, include_exceptions, reasons} spec that a
dispatch guard / coverage gate can enforce.

DESIGN INVARIANTS (safety-first; the #1 sin is dropping IN-SCOPE code):
  - FAIL-OPEN everywhere. No SCOPE.md, no OOS section, or an unresolvable token ->
    NO exclusion. Under-excluding is always preferred to wrongly excluding
    in-scope code.
  - TREE-VERIFY named components. A noun/dir is only turned into an exclude glob
    when a directory with that basename actually EXISTS in the workspace source
    tree. A noun that resolves to nothing is skipped (logged), never excluded.
  - INCLUDE-EXCEPTIONS win. ``giga`` OUT + ``giga/executor`` IN-exception means a
    path under ``giga/executor`` is NEVER OOS even though ``**/giga/**`` matches.
  - Generic. No workspace name or chain name is ever hard-coded in a decision.

Public API
----------
load_oos_spec(workspace_path) -> dict
    {"exclude_globs": [...], "include_exceptions": [...],
     "reasons": {glob: reason_str}, "skipped": [...]}

is_oos(relpath, spec, workspace_path=None) -> (bool, reason|None)

Pure stdlib.
"""
from __future__ import annotations

import fnmatch
import os
import re
from pathlib import Path
from typing import Optional

# ---------------------------------------------------------------------------
# Tunables
# ---------------------------------------------------------------------------

# Source-ish extensions used to recognise a backtick token as a "path".
_KNOWN_EXTS = {
    ".sol", ".rs", ".go", ".vy", ".move", ".cairo", ".circom", ".nr",
    ".py", ".ts", ".js", ".sw", ".fe", ".yul", ".huff", ".json", ".toml",
    ".md", ".txt", ".yaml", ".yml",
}

# Directory basenames we never treat as an excludable "component" (too generic;
# excluding one of these on a bare-noun match would risk dropping in-scope code).
_GENERIC_DIR_NAMES = {
    "src", "lib", "libs", "contracts", "core", "test", "tests", "node_modules",
    "vendor", "build", "out", "target", "dist", "docs", "doc", "scripts",
    "script", "bin", "pkg", "internal", "cmd", "api", "app", "apps", "x",
    "types", "utils", "util", "common", "config", "main", "code", "packages",
    "package", "modules", "module", "components", "component",
    # Generic infrastructure / networking nouns: excluding one of these on a bare
    # incidental prose mention (e.g. a threat-model paragraph that says "RPC
    # server" or "P2P peer") would wrongly drop in-scope core code. NEVER excludable
    # from a bare-noun match. (SEI 2026-07-05: the StateSync-peer trust paragraph
    # over-excluded go-ethereum/rpc, /node, /p2p, /core/state, sei-cosmos/server.)
    "rpc", "grpc", "rest", "server", "servers", "node", "nodes", "p2p", "peer",
    "peers", "state", "client", "clients", "network", "networks", "data", "db",
    "provider", "providers", "sync", "light", "snapshot", "snapshots", "block",
    "blocks", "transaction", "transactions", "keeper", "keepers", "store", "stores",
    "proto", "spec", "specs", "results", "reports", "files", "roles", "workflow",
    "release", "certora", "ansible", "configs", "contrib", "extensions", "default",
    "cosmos", "ethereum", "geth", "tendermint", "wasmd", "wasm", "evm", "chain",
}
# Threat-model / eligibility markers: a sentence carrying any of these describes
# WHO is trusted / attacker capabilities, NOT a code-directory exclusion. Nouns
# harvested from such a sentence must NOT become exclude globs.
_THREATMODEL_MARKERS = (
    "trusted", "malicious", "compromis", "tamper", "impersonat", "attacker",
    "poisoning", "spoof", "adversar",
)
# A sentence must carry one of these STRUCTURAL exclusion triggers before a bare
# noun in it is treated as an excludable component (kills incidental references
# like a prior-audit line "Sei Cosmos v1.0" that names a dir but excludes nothing).
_EXCLUSION_TRIGGERS = (
    "out of scope", "out-of-scope", "not eligible", "not covered", "excluded",
    "disabled by default", "not in scope", " out ", " out.", " out,", " oos",
)

# Canonical demo / load-test / mock directory basenames. When SCOPE.md documents
# the near-universal "testnet + mock files are NOT covered" carve-out (as PROSE,
# not a backtick path), these dirs - if they EXIST in the tree - are dropped from
# the coverage denominator. Tree-verified so a nonexistent dir never over-excludes
# (the 2026-07-05 over-exclusion foot-gun). `example`/`loadtest` are the load-bearing
# ones (SEI: example/cosmwasm/**, loadtest/contracts/** = ~1k throwaway units that
# inflated the denominator and made the gate demand hunts of demo contracts).
_TESTNET_MOCK_DIR_NAMES = (
    "example", "examples", "loadtest", "loadtests", "load-test", "load_test",
    "testdata", "testutil", "testutils", "e2e", "e2e-tests", "mock", "mocks",
    "fixtures", "demo", "demos", "sample", "samples",
)
# The documented carve-out phrase: a "testnet"/"mock" mention within ~80 chars of a
# not-covered / excluded / out-of-scope trigger. Case-insensitive.
_TESTNET_MOCK_CARVEOUT_RE = re.compile(
    r"(?:testnet|mock)[\s\S]{0,80}?"
    r"(?:not\s+covered|excluded|out[\s\-]of[\s\-]scope|not\s+in\s+scope|not\s+eligible)",
    re.IGNORECASE,
)


def _canonical_testnet_mock_globs(text: str, workspace_path: str,
                                  tree: dict) -> list[str]:
    """If SCOPE.md documents the testnet/mock carve-out, return canonical demo/
    test-dir exclude globs for the ones that ACTUALLY EXIST in the tree. Empty
    list otherwise (FAIL-OPEN: no documented carve-out -> exclude nothing)."""
    if not text or not _TESTNET_MOCK_CARVEOUT_RE.search(text):
        return []
    globs: list[str] = []
    for name in _TESTNET_MOCK_DIR_NAMES:
        resolved = _dir_exists_in_tree(name, tree, workspace_path)
        if not resolved:
            continue
        g = _glob_for_dir(resolved)
        if g not in globs:
            globs.append(g)
    return globs


# Directories we never descend into when tree-verifying a component.
_SKIP_WALK_DIRS = {
    ".git", "node_modules", "target", "build", "out", "dist", ".auditooor",
    "__pycache__", ".venv", "venv",
}

# Section-heading / marker phrases that open an OOS block (case-insensitive).
_OOS_MARKERS = (
    "out of scope",
    "out-of-scope",
    "outofscope",
    "not eligible for rewards",
    "not eligible for reward",
    "excluded from scope",
    "excluded from the scope",
    "outside the scope",
    "outside of scope",
)

# Include-exception clue phrases (a path near one of these is KEPT in scope).
_EXCEPT_RE = re.compile(
    r"(?:other than|except(?:\s+for)?|excluding|apart from|besides)\b",
    re.IGNORECASE,
)
_IN_SCOPE_TAIL_RE = re.compile(
    r"`([^`]+)`[^`\n]{0,40}?\bis\s+in[-\s]?scope\b",
    re.IGNORECASE,
)

# A backtick token that looks like a path (has a separator or a known ext).
_BACKTICK_RE = re.compile(r"`([^`\n]+)`")

# A markdown heading line: leading '#'s -> heading level (0 = not a heading).
def _heading_level(line: str) -> int:
    m = re.match(r"^(#{1,6})\s", line)
    return len(m.group(1)) if m else 0


def _read_scope_text(workspace_path: str) -> Optional[str]:
    ws = Path(workspace_path)
    for name in ("SCOPE.md", "scope.md", "Scope.md"):
        p = ws / name
        if p.is_file():
            try:
                return p.read_text(encoding="utf-8", errors="replace")
            except Exception:  # noqa: BLE001 - fail-open
                return None
    return None


def _extract_oos_sections(text: str) -> list[str]:
    """Return the text of every OOS section.

    A section starts at a line containing an OOS marker and runs until the next
    same-or-higher-level heading (if the marker was itself a heading) or, for a
    non-heading marker line, until the next heading of ANY level. Fail-open: if
    the marker appears but no clean boundary is found, take to end-of-doc.
    """
    lines = text.splitlines()
    n = len(lines)
    out: list[str] = []
    i = 0
    while i < n:
        line = lines[i]
        low = line.lower()
        if any(mk in low for mk in _OOS_MARKERS):
            start_level = _heading_level(line)
            j = i + 1
            body = [line]
            while j < n:
                lvl = _heading_level(lines[j])
                if lvl > 0:
                    if start_level > 0 and lvl <= start_level:
                        break
                    if start_level == 0:
                        # non-heading marker (e.g. a bold/plain line): stop at
                        # the next heading of any level.
                        break
                body.append(lines[j])
                j += 1
            out.append("\n".join(body))
            i = j
            continue
        i += 1
    return out


def _looks_like_path(tok: str) -> bool:
    tok = tok.strip()
    if not tok or " " in tok:
        return False
    if "/" in tok:
        return True
    _, ext = os.path.splitext(tok)
    if ext.lower() in _KNOWN_EXTS:
        return True
    return False


def _tree_dirs(workspace_path: str) -> dict[str, list[str]]:
    """Map lowercase directory basename -> list of relpaths (POSIX) that have it.

    Bounded walk; skips VCS/build/dep dirs. Used to tree-verify components.
    """
    ws = Path(workspace_path)
    out: dict[str, list[str]] = {}
    if not ws.is_dir():
        return out
    for root, dirs, _files in os.walk(ws):
        # prune
        dirs[:] = [d for d in dirs if d not in _SKIP_WALK_DIRS
                   and not d.startswith(".")]
        for d in dirs:
            full = Path(root) / d
            try:
                rel = full.relative_to(ws).as_posix()
            except ValueError:
                continue
            out.setdefault(d.lower(), []).append(rel)
    return out


def _dir_exists_in_tree(rel_or_name: str, tree: dict[str, list[str]],
                        workspace_path: str) -> Optional[str]:
    """If ``rel_or_name`` names a real dir in the tree, return its POSIX relpath.

    Accepts either a full relpath (``giga/executor``) or a bare basename
    (``autobahn``). Returns None if not confidently resolvable to a directory.
    """
    ws = Path(workspace_path)
    rel = rel_or_name.strip().strip("/").replace("\\", "/")
    if not rel:
        return None
    # Full relpath that exists as a directory.
    cand = ws / rel
    if cand.is_dir():
        return rel
    # Bare basename lookup (case-insensitive) via the pre-walked tree.
    if "/" not in rel:
        hits = tree.get(rel.lower())
        if hits:
            # Prefer the shallowest, non-test/legacy hit for determinism.
            def _rank(p: str) -> tuple:
                low = p.lower()
                penalty = 1 if any(seg in low.split("/")
                                   for seg in ("test", "tests", "mock",
                                               "mocks", "legacy", "example",
                                               "examples")) else 0
                return (penalty, p.count("/"), p)
            return sorted(hits, key=_rank)[0]
    else:
        # Multi-segment relpath (e.g. "giga/executor"): the workspace-root join
        # failed (real path is nested, e.g. src/sei-chain/giga/executor). Resolve
        # by SUFFIX-matching the pre-walked tree on the FULL relpath, keyed off the
        # last segment. NEVER fall back to a parent component - for an
        # include-exception that would re-include a whole excluded package
        # (SEI 2026-07-05: "giga/executor" fell back to "giga", re-including
        # giga/deps + giga/storage). Fail-open (return None) if no exact suffix.
        segs = [s for s in rel.split("/") if s]
        if not segs:
            return None
        hits = tree.get(segs[-1].lower()) or []
        suffix = "/" + rel.lower()
        matches = [p for p in hits if p.lower() == rel.lower()
                   or p.lower().endswith(suffix)]
        if matches:
            matches.sort(key=lambda p: (p.count("/"), p))
            return matches[0]
        return None
    return None


def _glob_for_dir(rel: str) -> str:
    return f"**/{rel.strip('/')}/**"


# Extensions that mark a token in the SCOPE.md In-scope section as a source file.
_INSCOPE_FILE_RE = re.compile(
    r"([A-Za-z0-9_./-]+\.(?:sol|rs|go|vy|cairo|move|nr|circom|yul|huff))")


def _inscope_dir_names(text: str) -> set:
    """Basenames of EVERY ancestor directory of a file listed under a SCOPE.md
    'In-scope' heading (a heading that says in-scope and is NOT the out-of-scope
    section).

    Why (Strata 2026-07-07): the OOS-prose noun harvester (section c) turns
    English words in the OUT-OF-SCOPE prose into `**/<dir>/**` exclude globs when
    they coincide with a real tree dir - "Strata" (in "...part of Strata's deployed
    contracts") -> `**/strata/**` (the whole workspace), "governance"/"oracles"
    (centralization + third-party-oracle clauses) -> in-scope dirs. Excluding an
    ancestor dir of an EXPLICITLY in-scope file drops in-scope code, the #1 sin.
    The SCOPE.md in-scope file list is authoritative: any dir on the path to an
    in-scope file can never be OOS. Returns lowercased basenames; fail-open (empty
    set if no in-scope section)."""
    names: set = set()
    in_inscope = False
    for line in text.splitlines():
        h = _heading_level(line)
        if h:
            low = line.lower()
            in_inscope = (("in-scope" in low or "in scope" in low)
                          and "out" not in low and "out-of-scope" not in low)
            continue
        if not in_inscope:
            continue
        for m in _INSCOPE_FILE_RE.finditer(line):
            p = m.group(1).strip().strip("/")
            segs = [s for s in p.split("/")[:-1] if s and s not in (".", "..")]
            for s in segs:
                names.add(s.lower())
    return names


def load_oos_spec(workspace_path: str) -> dict:
    """Parse <ws>/SCOPE.md OOS section(s) into an exclude/include spec.

    FAIL-OPEN: any absence/ambiguity yields fewer (never more) exclusions.
    """
    empty = {"exclude_globs": [], "include_exceptions": [],
             "reasons": {}, "skipped": []}
    text = _read_scope_text(workspace_path)
    if not text:
        return empty
    sections = _extract_oos_sections(text)
    if not sections:
        return empty

    tree = _tree_dirs(workspace_path)

    exclude_globs: list[str] = []
    include_exceptions: list[str] = []
    reasons: dict[str, str] = {}
    skipped: list[str] = []

    def _sentence_of(section: str, tok: str) -> str:
        for raw in re.split(r"(?<=[.;:\n])\s+", section):
            if tok in raw:
                return " ".join(raw.split())[:240]
        return " ".join(section.split())[:160]

    for section in sections:
        # --- (d) include-exceptions FIRST (so we never accidentally exclude
        # an exception path via a broader glob below without recording it) ---
        for m in _EXCEPT_RE.finditer(section):
            tail = section[m.end():m.end() + 160]
            bt = _BACKTICK_RE.search(tail)
            if not bt:
                continue
            tok = bt.group(1).strip()
            resolved = _dir_exists_in_tree(tok, tree, workspace_path)
            if resolved:
                g = _glob_for_dir(resolved)
                if g not in include_exceptions:
                    include_exceptions.append(g)
            else:
                skipped.append(f"include-exception(unresolved):{tok}")
        for m in _IN_SCOPE_TAIL_RE.finditer(section):
            tok = m.group(1).strip()
            resolved = _dir_exists_in_tree(tok, tree, workspace_path)
            if resolved:
                g = _glob_for_dir(resolved)
                if g not in include_exceptions:
                    include_exceptions.append(g)
            else:
                skipped.append(f"include-exception(unresolved):{tok}")

        # --- (b) explicit backtick paths -> exclude glob ---
        for bt in _BACKTICK_RE.finditer(section):
            tok = bt.group(1).strip()
            if not tok:
                continue
            # Skip tokens already claimed as include-exceptions.
            if _looks_like_path(tok):
                ws = Path(workspace_path)
                as_dir = _dir_exists_in_tree(tok, tree, workspace_path)
                if as_dir:
                    g = _glob_for_dir(as_dir)
                    if g not in exclude_globs:
                        exclude_globs.append(g)
                        reasons[g] = _sentence_of(section, tok)
                    continue
                # Not a dir: maybe a file that exists.
                fp = ws / tok.strip("/")
                if fp.is_file():
                    g = tok.strip("/").replace("\\", "/")
                    if g not in exclude_globs:
                        exclude_globs.append(g)
                        reasons[g] = _sentence_of(section, tok)
                    continue
                # A path-shaped token that resolves to nothing in the tree.
                # FAIL-OPEN: bare dir basename may still exist deeper; try that.
                base = tok.strip("/").split("/")[-1]
                if "/" not in tok.strip("/"):
                    r2 = _dir_exists_in_tree(base, tree, workspace_path)
                    if r2:
                        g = _glob_for_dir(r2)
                        if g not in exclude_globs:
                            exclude_globs.append(g)
                            reasons[g] = _sentence_of(section, tok)
                        continue
                skipped.append(f"path(unresolved):{tok}")

        # --- (c) named components: bare-word nouns that map to a real tree dir ---
        # Candidate nouns = capitalised or alnum words in the section that are
        # NOT already handled. We only accept ones whose basename matches a real,
        # non-generic tree directory (tree-verify). This is the SEI-Autobahn /
        # evmone case where the doc says "Autobahn ... OUT" without a backtick.
        words = set(re.findall(r"[A-Za-z][A-Za-z0-9_]{2,}", section))
        for w in words:
            wl = w.lower()
            if wl in _GENERIC_DIR_NAMES:
                continue
            # Skip English filler / marker words.
            if wl in {"scope", "out", "the", "and", "are", "not", "eligible",
                      "rewards", "reward", "excluded", "from", "outside",
                      "other", "than", "except", "excluding", "apart",
                      "besides", "packages", "package", "consensus", "backend",
                      "peer", "code", "this", "that", "these", "those", "for",
                      "any", "all", "with", "which", "such", "will", "may"}:
                continue
            # The SENTENCE that names this noun decides whether it is a real
            # component-exclusion. Two guards (SEI 2026-07-05 over-exclusion fix):
            sent = _sentence_of(section, w)
            sl = sent.lower()
            #  threat-model / eligibility prose (trusted peer, attacker, etc.)
            #  describes WHO is trusted, not a code dir to drop -> skip. (The
            #  broad exclusion-trigger requirement was too strict - it killed
            #  legit bullet items like "The Autobahn ... protocol" whose trigger
            #  lives in the list intro, not the bullet - so we rely on the
            #  threat-model filter + the generic stoplist and fail OPEN otherwise.)
            if any(m in sl for m in _THREATMODEL_MARKERS):
                skipped.append(f"threatmodel-noun:{wl}")
                continue
            resolved = _dir_exists_in_tree(wl, tree, workspace_path)
            if not resolved:
                continue
            g = _glob_for_dir(resolved)
            if g in exclude_globs or g in include_exceptions:
                continue
            exclude_globs.append(g)
            reasons[g] = sent

    # Canonical testnet/mock carve-out (documented as prose, not a backtick path):
    # drop demo/loadtest/mock dirs that exist in the tree. SCOPE.md rule, universal.
    for g in _canonical_testnet_mock_globs(text, workspace_path, tree):
        if g not in exclude_globs and g not in include_exceptions:
            exclude_globs.append(g)
            reasons[g] = "testnet/mock files are NOT covered (SCOPE.md carve-out)"

    # INVARIANT (SEI 2026-07-05): an include-exception must be a strict SUB-path
    # of some exclude glob. An exception equal to (or a parent of) an exclude glob
    # re-includes the whole excluded package and silently neutralises the
    # exclusion (e.g. a bare "giga" exception cancelling the "giga/**" exclude,
    # re-including OOS giga/deps + giga/storage). Keep only genuine carve-outs.
    def _dir_of(glob: str) -> str:
        return glob[len("**/"):-len("/**")] if glob.startswith("**/") and glob.endswith("/**") else glob.strip("/")
    excl_dirs = [_dir_of(g) for g in exclude_globs]
    kept_exc = []
    for exc in include_exceptions:
        ed = _dir_of(exc)
        if any(ed != xd and (ed + "/").startswith(xd + "/") for xd in excl_dirs):
            kept_exc.append(exc)
        else:
            skipped.append(f"include-exception(not-subpath-of-exclude):{exc}")
    include_exceptions = kept_exc

    # RECONCILE parent/exception OVERLAP (SEI 2026-07-05 crown-jewel guard): if an
    # exclude glob is a strict PARENT of an include-exception (e.g. `giga/**` OUT but
    # `giga/executor/**` IN), a raw-glob consumer that only reads exclude_globs would
    # swallow the in-scope exception. Make the two lists DISJOINT and non-overlapping
    # by expanding such a parent into globs for its immediate OOS child dirs (every
    # child except the one on the exception's path), and dropping any exclude glob
    # that is (or is under) an include-exception. Tree-verified; FAIL-OPEN.
    exc_dirs = {_dir_of(x) for x in include_exceptions}
    reconciled: list[str] = []
    ws_root = Path(workspace_path)
    for g in exclude_globs:
        gd = _dir_of(g)
        # Drop an exclude that IS or is UNDER an include-exception (never exclude an
        # in-scope carve-out).
        if any(gd == xd or (gd + "/").startswith(xd + "/") for xd in exc_dirs):
            skipped.append(f"exclude(is-include-exception):{g}")
            continue
        # If this exclude is a strict PARENT of an exception, expand into OOS children.
        child_excs = [xd for xd in exc_dirs if xd != gd and (xd + "/").startswith(gd + "/")]
        if child_excs:
            parent_abs = ws_root / gd
            expanded_any = False
            try:
                for child in sorted(parent_abs.iterdir()):
                    if not child.is_dir() or child.name in _SKIP_WALK_DIRS:
                        continue
                    cd = f"{gd}/{child.name}"
                    # Skip the child that leads to (or IS) an exception branch.
                    if any(xd == cd or (xd + "/").startswith(cd + "/") for xd in exc_dirs):
                        continue
                    cg = _glob_for_dir(cd)
                    if cg not in reconciled and cg not in include_exceptions:
                        reconciled.append(cg)
                        reasons[cg] = reasons.get(g, "OOS (parent of in-scope carve-out)")
                        expanded_any = True
            except OSError:
                pass
            if expanded_any:
                continue
            # Could not expand (unreadable) -> FAIL-OPEN: drop the over-broad parent
            # rather than risk excluding the in-scope exception.
            skipped.append(f"exclude(unexpandable-parent-of-exception):{g}")
            continue
        if g not in reconciled:
            reconciled.append(g)
    exclude_globs = reconciled

    # SCOPE.md-AUTHORITY GUARD (Strata 2026-07-07): the in-scope file list and the
    # workspace root are authoritative and can NEVER be excluded. Drop any exclude
    # glob whose directory basename (a) equals the workspace basename - a bare
    # `**/<wsname>/**` matches the ENTIRE tree - or (b) is an ancestor directory of
    # an explicitly in-scope file. This neutralises the OOS-prose noun-harvest false
    # positives ("Strata"->**/strata/**, "governance"/"oracles"-> in-scope dirs)
    # while leaving genuine bare-noun exclusions (SEI "Autobahn", not an in-scope
    # dir) intact. Fail-open direction (under-exclude), consistent with this module.
    inscope_names = _inscope_dir_names(text)
    ws_base = Path(workspace_path).name.lower()
    protected = inscope_names | {ws_base}
    if protected:
        kept = []
        for g in exclude_globs:
            last = _dir_of(g).strip("/").split("/")[-1].lower()
            if last in protected:
                skipped.append(f"exclude(protected-inscope-or-wsroot):{g}")
                reasons.pop(g, None)
            else:
                kept.append(g)
        exclude_globs = kept

    return {
        "exclude_globs": exclude_globs,
        "include_exceptions": include_exceptions,
        "reasons": reasons,
        "skipped": skipped,
    }


def _norm_rel(relpath: str) -> str:
    return str(relpath or "").strip().lstrip("./").replace("\\", "/").strip("/")


def _match_glob(rel: str, glob: str) -> bool:
    """Match a POSIX relpath against a ``**/dir/**`` or plain-file glob."""
    rel = _norm_rel(rel)
    glob = glob.strip()
    if not rel or not glob:
        return False
    # Directory glob of the form **/<mid>/** -> membership test on path segments.
    m = re.match(r"^\*\*/(.+?)/\*\*$", glob)
    if m:
        mid = m.group(1).strip("/")
        segs = rel.split("/")
        mid_segs = mid.split("/")
        # Sliding-window contiguous segment match anywhere in the path.
        for i in range(0, len(segs) - len(mid_segs) + 1):
            if [s.lower() for s in segs[i:i + len(mid_segs)]] == \
               [s.lower() for s in mid_segs]:
                return True
        return False
    # Plain file / fnmatch glob.
    if fnmatch.fnmatch(rel, glob) or fnmatch.fnmatch(rel, glob.lstrip("/")):
        return True
    # Also allow the glob to match a suffix of the path (file listed w/o full
    # prefix in SCOPE.md).
    return rel.endswith("/" + glob.lstrip("/")) or rel == glob.lstrip("/")


def is_oos(relpath: str, spec: dict,
           workspace_path: Optional[str] = None) -> tuple:
    """Return (True, reason) iff relpath is OUT of scope per spec.

    OOS iff it matches an exclude glob AND matches NO include-exception.
    FAIL-OPEN: an empty spec -> (False, None).
    """
    if not spec:
        return (False, None)
    excludes = spec.get("exclude_globs") or []
    includes = spec.get("include_exceptions") or []
    if not excludes:
        return (False, None)
    rel = _norm_rel(relpath)
    if not rel:
        return (False, None)
    # Include-exception ALWAYS wins.
    for inc in includes:
        if _match_glob(rel, inc):
            return (False, None)
    for exc in excludes:
        if _match_glob(rel, exc):
            reason = (spec.get("reasons") or {}).get(exc) or \
                f"matches OOS glob {exc}"
            return (True, reason)
    return (False, None)


__all__ = ["load_oos_spec", "is_oos"]
