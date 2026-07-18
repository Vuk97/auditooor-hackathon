#!/usr/bin/env python3
"""Per-function REAL-attack worklist driver (generic, language-aware).

ROOT-CAUSE THIS TOOL ADDRESSES
------------------------------
The audit pipeline can declare a workspace "complete" while in-scope functions
are never actually attacked. Two hollow mechanisms create the illusion of
coverage:
  (a) CCIA (tools/ccia-*.py) is a shallow heuristic that emits noise
      attack-angles (e.g. it flagged a TEST-helper callback as
      "MEDIUM unauthenticated").
  (b) Per-function harnesses are generated but vacuous (e.g. morpho: 79
      harnesses yet only 4/179 units real per audit-honesty-check / L37).

Neither is a REAL per-function attack carrying a VERDICT, yet both let
"coverage" pass. This tool is the DRIVER that closes the gap: it emits a
comprehensive per-function ATTACK worklist (one row per in-scope function, with
the attack topics a hunter must work through), and it ingests per-function
attack VERDICTS back into a sidecar that the A1 coverage-attack gate consumes.

WHAT IT IS / IS NOT
-------------------
- It IS a per-function attack work-queue generator + verdict ledger.
- It is NOT itself the attacker (an agent-per-function run produces the
  verdicts). It is the input that run consumes, and the place the verdicts land
  so the A1 gate can certify "every in-scope function was really attacked".

RELATED TOOLS (Rule: tool-duplication preflight):
- tools/per-function-invariant-gen.py - emits advisory Halmos *harnesses* per
  function (Solidity only). DIFFERENT OUTPUT: harness scaffolds, not an
  attack-topic worklist with a verdict-ingest path. This tool reuses its
  Solidity surface-parse idioms but adds (1) a balanced-paren multi-line
  signature parser, (2) per-function ATTACK TOPICS, (3) a verdict ledger,
  (4) language-aware Rust/Go/Move/Cairo support.
- tools/guard-negative-space-analyzer.py / sibling-path-guard-diff.py (R81
  depth layer) - per-GUARD negative space + sibling asymmetry. DIFFERENT UNIT:
  guards, not functions; and depth-not-breadth. This tool is the per-FUNCTION
  breadth driver they sit alongside.
- tools/ccia.py / ccia-rust.py - shallow heuristic attack-angle emitter. This
  tool REPLACES its illusion-of-coverage role with a real per-function
  attack-and-verdict ledger.
- tools/audit-honesty-check.py / audit-completeness-check.py (L37) - the gate
  that reads this tool's ingested verdicts to certify per-function attack
  coverage.

GENERIC CONTRACT
----------------
- Works on ANY workspace via --workspace.
- Language-aware where it parses source (Solidity incl. multi-line signatures,
  plus Rust/Go/Move/Cairo via extensible pattern tables + env hooks).
- Excludes test/ lib/ mock/ interface/ script/ from the in-scope surface.
- ZERO target hardcoding in the tool body (smoke anchors live only in tests).
- ADDITIVE: writes a new sidecar; does not mutate other tools' artifacts.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import sys
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path

SCHEMA = "auditooor.per_function_attack_worklist.v1"
SIDECAR_REL = ".auditooor/per_function_attack_worklist.jsonl"

# Canonical attack-topic taxonomy every in-scope function must be worked through.
ATTACK_TOPICS = [
    "auth/access",
    "oracle/price",
    "rounding/arithmetic",
    "reentrancy/CEI",
    "economic/conservation",
    "cross-function-composition",
]

# Verdict vocabulary the A1 gate recognizes. A function is "really attacked"
# only when its row carries a terminal verdict (not 'pending'). Clean terminal
# verdicts count only with a concrete per-function source or execution anchor.
TERMINAL_ATTACK_VERDICTS = {"real-attack", "holds", "finding"}
TERMINAL_CLEAN_VERDICTS = {"no-exploit", "clean", "ruled-out", "no-finding"}
TERMINAL_VERDICTS = TERMINAL_ATTACK_VERDICTS | TERMINAL_CLEAN_VERDICTS
ALL_VERDICTS = TERMINAL_VERDICTS | {"pending"}

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
    "no-finding": "no-finding",
    "no-confirmed-finding": "no-finding",
}

_EVIDENCE_FIELDS = (
    "poc_path", "poc_evidence_lines", "pass_evidence_lines",
    "source_ref", "source_refs", "source_line", "source_lines",
    "evidence", "evidence_ref", "evidence_refs", "verdict_detail",
    "reason", "why_no_exploit", "why_no_gap_or_exploit",
)


def normalize_status(raw: object) -> str:
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


def _row_has_terminal_evidence(row: dict, status: str) -> bool:
    if status in TERMINAL_ATTACK_VERDICTS:
        return True
    file_line = str(row.get("file_line") or "")
    file_part = file_line.rsplit(":", 1)[0] if ":" in file_line else file_line
    function = str(row.get("function") or "")
    for field in _EVIDENCE_FIELDS:
        value = row.get(field)
        text = _text_value(value).strip()
        if not text:
            continue
        if field in {"poc_path", "poc_evidence_lines", "pass_evidence_lines"}:
            return True
        if file_line and file_line in text:
            return True
        if file_part and function and file_part in text and re.search(
            r"\b" + re.escape(function) + r"\b", text
        ):
            return True
    return False


# --------------------------------------------------------------------------- #
# Scope exclusion (in-scope surface = real protocol-owned code only).
# Mirrors the universal EXCLUDE_PATH_PARTS used across the per-function tools,
# plus interface/ and script/ which are NOT an attack surface.
# Env override: AUDITOOOR_ATTACK_WORKLIST_EXTRA_EXCLUDES (newline-separated).
# --------------------------------------------------------------------------- #
EXCLUDE_PATH_PARTS = {
    "/test/", "/tests/", "/mock/", "/mocks/", "/lib/", "/libs/",
    "/interface/", "/interfaces/", "/script/", "/scripts/",
    "/out/", "/cache/", "/node_modules/", "/.git/", "/dependencies/",
    "/forge-std/", "/_archive/", "/build/", "/artifacts/",
    "/typechain/", "/typechain-types/", "/.foundry/", "/tron/",
    "/poc-tests/", "/poc_tests/", "/fuzz_runs/", "/symbolic_runs/",
    "/.auditooor/", "/target/", "/vendor/", "/third_party/",
    "/examples/", "/example/", "/fixtures/", "/testdata/",
    # Formal-verification scaffolding (Certora / Halmos / Kontrol helpers,
    # specs, and confs) is NOT in-scope protocol code. Without this the
    # surface absorbs harness callbacks like FlashLiquidateCallback / Havoc -
    # exactly the kind of noise CCIA mis-flagged as a "MEDIUM unauthenticated"
    # finding.
    "/certora/", "/helpers/", "/specs/", "/spec/", "/kontrol/", "/halmos/",
    "/invariants/", "/properties/",
    # Coverage-guided fuzz scaffolding (the audit's OWN chimera harnesses, e.g.
    # Echidna/Medusa wrappers landed under a chimera_harnesses/ tree) is NOT
    # in-scope protocol code. Without this the surface absorbs the workspace's
    # own harness functions - exactly the SSV inflation this guard prevents.
    "/chimera_harnesses/",
}
for _extra in (os.environ.get("AUDITOOOR_ATTACK_WORKLIST_EXTRA_EXCLUDES", "") or "").splitlines():
    _extra = _extra.strip()
    if _extra:
        EXCLUDE_PATH_PARTS.add(_extra if _extra.startswith("/") else f"/{_extra}/")

# File-name suffixes that mark non-attack-surface units regardless of dir.
EXCLUDE_NAME_SUFFIXES = (".t.sol", ".test.sol", "_test.go", "_test.rs", ".spec.ts")
# Filename substrings that mark mocks/tests/interfaces even when flat.
# "Mutant" excludes intentionally-unsafe mutation-test contracts (*Mutant*.sol);
# "Echidna"/"Medusa" exclude flat coverage-fuzz harness stems that do not sit
# under a /chimera_harnesses/ dir. These are the audit's OWN artifacts, never an
# in-scope attack surface.
EXCLUDE_NAME_SUBSTR = (
    "mock", "Mock", "harness", "Harness", "Mutant", "Echidna", "Medusa",
)


def _norm_inscope_path(p: str) -> str:
    return str(p or "").strip().lstrip("./").replace("\\", "/")


def _load_inscope_file_set(ws: Path):
    """Return the AUTHORITATIVE in-scope file set from ``.auditooor/inscope_units.jsonl``
    (the manifest the hunt-worklist + heatmap + per-function-invariant-gen gates already
    treat as scope truth), or ``None`` when no manifest exists (then NO filtering -
    preserves legacy behavior, no regression).

    WHY: ``discover_files`` walks the whole workspace src_roots, so the surface absorbs
    OUT-OF-SCOPE units - on SSV ~43/265 rows were the audit's OWN chimera_harnesses +
    an intentionally-unsafe *Mutant*.sol, inflating the worklist and wasting downstream
    hunt/coverage budget. Honoring the in-scope manifest restores a scope-correct surface.
    Mirrors tools/per-function-invariant-gen.py._load_inscope_file_set.
    Disable with AUDITOOOR_ATTACK_WORKLIST_NO_INSCOPE=1.
    """
    if os.environ.get("AUDITOOOR_ATTACK_WORKLIST_NO_INSCOPE"):
        return None
    manifest = ws / ".auditooor" / "inscope_units.jsonl"
    if not manifest.is_file():
        return None
    files: set = set()
    try:
        text = manifest.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return None
    for line in text.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            row = json.loads(line)
        except (json.JSONDecodeError, ValueError):
            continue
        f = _norm_inscope_path(str(row.get("file") or ""))
        if f:
            files.add(f)
    return files or None


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


# --------------------------------------------------------------------------- #
# Per-language parse configuration. Extensible: add a LANGUAGES entry or use the
# env hooks. Each parser yields (contract/module, function, signature, line).
# --------------------------------------------------------------------------- #
@dataclass(frozen=True)
class FunctionRow:
    file_line: str
    function: str
    contract: str
    signature: str
    language: str
    attack_topics: list[str] = field(default_factory=lambda: list(ATTACK_TOPICS))
    status: str = "pending"

    def key(self) -> str:
        return f"{self.contract}.{self.function}@{self.file_line}"

    def to_row(self) -> dict:
        return {
            "file_line": self.file_line,
            "function": self.function,
            "contract": self.contract,
            "signature": self.signature,
            "language": self.language,
            "attack_topics": list(self.attack_topics),
            "status": self.status,
        }


def _line_number(text: str, offset: int) -> int:
    return text.count("\n", 0, offset) + 1


def _strip_sol_comments(text: str) -> str:
    # Replace comments with same-length newlines so offsets/line numbers hold.
    pattern = re.compile(r"//[^\n]*|/\*.*?\*/", re.DOTALL)
    return pattern.sub(lambda m: "\n" * m.group(0).count("\n"), text)


def _strip_hash_comments(text: str) -> str:
    pattern = re.compile(r"//[^\n]*|/\*.*?\*/", re.DOTALL)
    return pattern.sub(lambda m: "\n" * m.group(0).count("\n"), text)


# ---- Solidity ------------------------------------------------------------- #
_SOL_CONTRACT_RE = re.compile(
    r"\b(?P<kind>abstract\s+contract|contract|library|interface)\s+"
    r"(?P<name>[A-Za-z_][A-Za-z0-9_]*)\b"
)
_SOL_FUNC_START_RE = re.compile(r"\bfunction\s+(?P<name>[A-Za-z_][A-Za-z0-9_]*)\s*\(")
_SOL_PRAGMA_RE = re.compile(r"pragma\s+solidity\s+([^;]+);")
_SOL_VIEWPURE_RE = re.compile(r"\b(view|pure)\b")
_SOL_PUBLICISH_RE = re.compile(r"\b(public|external|internal)\b")
_SOL_CONSTRUCTOR = {"constructor", "receive", "fallback"}


def _balanced_paren_end(text: str, open_idx: int) -> int:
    """Return index just past the matching ')' for the '(' at open_idx.

    Handles multi-line signatures and nested parens (struct/tuple args)."""
    depth = 0
    i = open_idx
    n = len(text)
    while i < n:
        c = text[i]
        if c == "(":
            depth += 1
        elif c == ")":
            depth -= 1
            if depth == 0:
                return i + 1
        i += 1
    return -1


def _sol_kind_map(clean: str) -> list[tuple[int, str, str]]:
    """Ordered list of (offset, kind, name) for contract/library/interface."""
    out = []
    for m in _SOL_CONTRACT_RE.finditer(clean):
        kind = "interface" if m.group("kind").startswith("interface") else (
            "library" if m.group("kind") == "library" else "contract"
        )
        out.append((m.start(), kind, m.group("name")))
    return out


def _sol_enclosing(decls: list[tuple[int, str, str]], offset: int) -> tuple[str, str]:
    name, kind = "", "contract"
    for off, k, nm in decls:
        if off <= offset:
            name, kind = nm, k
        else:
            break
    return name, kind


def parse_solidity(text: str) -> list[tuple[str, str, str, int]]:
    """Yield (contract, function, signature, line) for in-scope Sol functions.

    In-scope = public/external/internal, NON view/pure, NOT in an `interface`,
    NOT a constructor/receive/fallback. Multi-line signatures supported via a
    balanced-paren scan. <0.8 pragma files are still parsed (the worklist is
    language-level, not compile-level)."""
    clean = _strip_sol_comments(text)
    decls = _sol_kind_map(clean)
    rows: list[tuple[str, str, str, int]] = []
    for m in _SOL_FUNC_START_RE.finditer(clean):
        name = m.group("name")
        if name in _SOL_CONSTRUCTOR:
            continue
        open_idx = clean.index("(", m.start())
        close_idx = _balanced_paren_end(clean, open_idx)
        if close_idx < 0:
            continue
        # Attribute span runs from ')' up to the body '{' or ';'.
        tail_start = close_idx
        brace = clean.find("{", tail_start)
        semi = clean.find(";", tail_start)
        # pick the nearer terminator
        if brace == -1:
            term = semi
        elif semi == -1:
            term = brace
        else:
            term = min(brace, semi)
        if term == -1:
            continue
        attrs = clean[tail_start:term]
        contract, kind = _sol_enclosing(decls, m.start())
        # Skip interface declarations - they have no implementation to attack.
        if kind == "interface":
            continue
        # view/pure handling diverges by container kind:
        #  - In a CONTRACT, a view/pure function is a read-only getter; it is
        #    not a state-mutation / auth attack surface, so skip it.
        #  - In a LIBRARY, the `internal pure` math helpers (e.g. TickLib
        #    wExp / tickToPrice / priceToTick) ARE the rounding/arithmetic
        #    attack surface and MUST be enumerated. Keep them.
        if _SOL_VIEWPURE_RE.search(attrs) and kind != "library":
            continue
        # Require a visibility keyword in the attribute span; library `internal`
        # functions (TickLib etc.) ARE in-scope.
        if not _SOL_PUBLICISH_RE.search(attrs):
            # function bodies with no visibility keyword default internal in
            # libraries-with-free-functions; include them for libraries.
            if kind != "library":
                continue
        sig = re.sub(r"\s+", " ", clean[m.start():term]).strip()
        rows.append((contract or "", name, sig, _line_number(clean, m.start())))
    return rows


# ---- Rust ----------------------------------------------------------------- #
# Env hooks: AUDITOOOR_ATTACK_WORKLIST_RUST_FN_RE overrides the fn pattern.
_RUST_FN_RE = re.compile(
    os.environ.get(
        "AUDITOOOR_ATTACK_WORKLIST_RUST_FN_RE",
        r"\bpub(?:\s*\([^)]*\))?\s+(?:async\s+)?fn\s+(?P<name>[A-Za-z_][A-Za-z0-9_]*)\s*",
    )
)
_RUST_IMPL_RE = re.compile(r"\bimpl(?:\s*<[^>]*>)?\s+(?:[A-Za-z0-9_:<>]+\s+for\s+)?(?P<name>[A-Za-z_][A-Za-z0-9_:]*)")


def parse_rust(text: str) -> list[tuple[str, str, str, int]]:
    clean = _strip_hash_comments(text)
    impls = [(m.start(), m.group("name")) for m in _RUST_IMPL_RE.finditer(clean)]
    rows = []
    for m in _RUST_FN_RE.finditer(clean):
        name = m.group("name")
        # enclosing impl block
        mod = ""
        for off, nm in impls:
            if off <= m.start():
                mod = nm
            else:
                break
        open_idx = clean.find("(", m.end() - 1)
        if open_idx == -1:
            continue
        close_idx = _balanced_paren_end(clean, open_idx)
        if close_idx == -1:
            continue
        sig = re.sub(r"\s+", " ", clean[m.start():close_idx]).strip()
        rows.append((mod, name, sig, _line_number(clean, m.start())))
    return rows


# ---- Go ------------------------------------------------------------------- #
_GO_FUNC_RE = re.compile(
    os.environ.get(
        "AUDITOOOR_ATTACK_WORKLIST_GO_FN_RE",
        r"\bfunc\s*(?:\((?P<recv>[^)]*)\)\s*)?(?P<name>[A-Z][A-Za-z0-9_]*)\s*\(",
    )
)


def parse_go(text: str) -> list[tuple[str, str, str, int]]:
    clean = _strip_hash_comments(text)
    rows = []
    for m in _GO_FUNC_RE.finditer(clean):
        name = m.group("name")
        recv = (m.group("recv") or "").strip()
        contract = ""
        if recv:
            parts = recv.split()
            contract = parts[-1].lstrip("*") if parts else ""
        open_idx = clean.rfind("(", 0, m.end())
        close_idx = _balanced_paren_end(clean, open_idx)
        if close_idx == -1:
            continue
        sig = re.sub(r"\s+", " ", clean[m.start():close_idx]).strip()
        rows.append((contract, name, sig, _line_number(clean, m.start())))
    return rows


# ---- Move ----------------------------------------------------------------- #
_MOVE_FN_RE = re.compile(
    os.environ.get(
        "AUDITOOOR_ATTACK_WORKLIST_MOVE_FN_RE",
        r"\bpublic(?:\s*\([^)]*\))?\s+(?:entry\s+)?fun\s+(?P<name>[A-Za-z_][A-Za-z0-9_]*)\s*",
    )
)
_MOVE_MOD_RE = re.compile(r"\bmodule\s+(?P<name>[A-Za-z_][A-Za-z0-9_:]*)\s*\{")


def parse_move(text: str) -> list[tuple[str, str, str, int]]:
    clean = _strip_hash_comments(text)
    mods = [(m.start(), m.group("name")) for m in _MOVE_MOD_RE.finditer(clean)]
    rows = []
    for m in _MOVE_FN_RE.finditer(clean):
        name = m.group("name")
        mod = ""
        for off, nm in mods:
            if off <= m.start():
                mod = nm
            else:
                break
        open_idx = clean.find("(", m.end() - 1)
        if open_idx == -1:
            continue
        close_idx = _balanced_paren_end(clean, open_idx)
        if close_idx == -1:
            continue
        sig = re.sub(r"\s+", " ", clean[m.start():close_idx]).strip()
        rows.append((mod, name, sig, _line_number(clean, m.start())))
    return rows


# ---- Cairo ---------------------------------------------------------------- #
_CAIRO_FN_RE = re.compile(
    os.environ.get(
        "AUDITOOOR_ATTACK_WORKLIST_CAIRO_FN_RE",
        r"(?:#\[external[^\]]*\]\s*)?\bfn\s+(?P<name>[A-Za-z_][A-Za-z0-9_]*)\s*\(",
    )
)


def parse_cairo(text: str) -> list[tuple[str, str, str, int]]:
    clean = _strip_hash_comments(text)
    rows = []
    for m in _CAIRO_FN_RE.finditer(clean):
        name = m.group("name")
        open_idx = clean.index("(", m.start())
        close_idx = _balanced_paren_end(clean, open_idx)
        if close_idx == -1:
            continue
        sig = re.sub(r"\s+", " ", clean[m.start():close_idx]).strip()
        rows.append(("", name, sig, _line_number(clean, m.start())))
    return rows


LANGUAGES = {
    ".sol": ("solidity", parse_solidity),
    ".rs": ("rust", parse_rust),
    ".go": ("go", parse_go),
    ".move": ("move", parse_move),
    ".cairo": ("cairo", parse_cairo),
}


# --------------------------------------------------------------------------- #
# Discovery
# --------------------------------------------------------------------------- #
def _excluded(posix: str, name: str) -> bool:
    if any(part in posix for part in EXCLUDE_PATH_PARTS):
        return True
    if name.endswith(EXCLUDE_NAME_SUFFIXES):
        return True
    # Interface files (I*.sol convention) and mock/harness names.
    if any(s in name for s in EXCLUDE_NAME_SUBSTR):
        return True
    return False


def discover_files(workspace: Path) -> list[Path]:
    roots_order = ["src", "contracts", "programs", "sources", "."]
    files: list[Path] = []
    seen: set[Path] = set()
    for rel in roots_order:
        root = workspace / rel if rel != "." else workspace
        if not root.exists():
            continue
        for ext in LANGUAGES:
            for path in root.rglob(f"*{ext}"):
                if path in seen or not path.is_file():
                    continue
                seen.add(path)
                if _excluded(path.as_posix(), path.name):
                    continue
                files.append(path)
    return sorted(set(files))


def build_worklist(workspace: Path) -> list[FunctionRow]:
    rows: list[FunctionRow] = []
    seen_keys: set[str] = set()
    # SCOPE-AUTHORITATIVE filter: when an in-scope manifest exists, keep only files
    # listed in it (mirrors per-function-invariant-gen.py / function-coverage). When
    # absent, _inscope is None and every discovered file is kept (no regression);
    # the EXCLUDE_* guards above still apply as belt-and-suspenders.
    _inscope = _load_inscope_file_set(workspace)
    for path in discover_files(workspace):
        if _inscope is not None:
            try:
                _rel = path.relative_to(workspace).as_posix()
            except ValueError:
                _rel = path.as_posix()
            if _norm_inscope_path(_rel) not in _inscope:
                continue
        lang, parser = LANGUAGES[path.suffix]
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError as exc:
            print(f"[per-function-attack-worklist] WARN cannot read {path}: {exc}", file=sys.stderr)
            continue
        try:
            rel = path.relative_to(workspace).as_posix()
        except ValueError:
            rel = path.as_posix()
        for contract, fn, sig, line in parser(text):
            file_line = f"{rel}:{line}"
            fr = FunctionRow(
                file_line=file_line,
                function=fn,
                contract=contract or path.stem,
                signature=sig,
                language=lang,
            )
            k = fr.key()
            if k in seen_keys:
                continue
            seen_keys.add(k)
            rows.append(fr)
    # GUARD-TRIAGE PRIORITY (early-guard rewire): if guard-triage ran first, hunt
    # the guard-risky functions BEFORE the rest, so the first agents work the
    # missing-guard / sibling-asymmetry surface instead of view proxies. Falls back
    # to the stable (file_line, function) order when no triage artifact exists.
    risk = _guard_risk_scores(workspace)
    return sorted(rows, key=lambda r: (-risk.get(r.function.lower(), 0), r.file_line, r.function))


def _guard_risk_scores(workspace: Path) -> dict:
    """fn-name (lower) -> guard-risk score from .auditooor/guard_triage.json
    (written by tools/guard-triage.py). Empty dict (no prioritization) when the
    early guard-triage has not run - the hunt order is then the prior stable sort."""
    p = workspace / ".auditooor" / "guard_triage.json"
    if not p.is_file():
        return {}
    try:
        data = json.loads(p.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {}
    out: dict[str, int] = {}
    import re as _re
    for u in data.get("risk_units", []):
        unit = str(u.get("unit") or u.get("loc") or "")
        m = _re.search(r"([A-Za-z_]\w*)\s*$", unit.split(":")[-1])
        if m:
            fn = m.group(1).lower()
            out[fn] = max(out.get(fn, 0), int(u.get("score") or 0))
    return out


# --------------------------------------------------------------------------- #
# Emit / Ingest
# --------------------------------------------------------------------------- #
def emit(workspace: Path, as_json: bool) -> int:
    rows = build_worklist(workspace)
    sidecar = workspace / SIDECAR_REL
    # Preserve existing terminal verdicts on re-emit (idempotent, additive).
    existing: dict[str, dict] = {}
    if sidecar.exists():
        for line in sidecar.read_text(encoding="utf-8", errors="replace").splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            try:
                obj = json.loads(line)
            except json.JSONDecodeError:
                continue
            if obj.get("schema") == SCHEMA:
                continue  # header line
            key = f"{obj.get('contract')}.{obj.get('function')}@{obj.get('file_line')}"
            existing[key] = obj

    out_rows = []
    for r in rows:
        row = r.to_row()
        prev = existing.get(r.key())
        if prev:
            status = normalize_status(prev.get("status"))
        else:
            status = ""
        if prev and status in TERMINAL_VERDICTS and _row_has_terminal_evidence(prev, status):
            row["status"] = status
            for carry in ("verdict_detail", "verdict_at", "poc_path", "severity"):
                if carry in prev:
                    row[carry] = prev[carry]
        out_rows.append(row)

    sidecar.parent.mkdir(parents=True, exist_ok=True)
    header = {
        "schema": SCHEMA,
        "workspace": str(workspace),
        "emitted_at": utc_now(),
        "total_functions": len(out_rows),
        "attack_topics": ATTACK_TOPICS,
        "terminal_verdicts": sorted(TERMINAL_VERDICTS),
    }
    with sidecar.open("w", encoding="utf-8") as fh:
        fh.write(json.dumps(header) + "\n")
        for row in out_rows:
            fh.write(json.dumps(row, sort_keys=True) + "\n")

    per_contract: dict[str, int] = {}
    pending = 0
    for row in out_rows:
        per_contract[row["contract"]] = per_contract.get(row["contract"], 0) + 1
        if row["status"] == "pending":
            pending += 1

    summary = {
        "schema": SCHEMA,
        "mode": "emit",
        "workspace": str(workspace),
        "sidecar": str(sidecar),
        "total_functions": len(out_rows),
        "pending": pending,
        "attacked": len(out_rows) - pending,
        "per_contract": dict(sorted(per_contract.items())),
    }
    if as_json:
        print(json.dumps(summary, indent=2))
    else:
        print(f"[emit] {len(out_rows)} in-scope functions -> {sidecar}")
        print(f"[emit] pending={pending} attacked={len(out_rows) - pending}")
        for c, n in sorted(per_contract.items()):
            print(f"  {c}: {n}")
    return 0


def ingest(workspace: Path, verdicts_path: Path, as_json: bool) -> int:
    sidecar = workspace / SIDECAR_REL
    if not sidecar.exists():
        print(f"[ingest] ERROR: no worklist at {sidecar}; run --emit first", file=sys.stderr)
        return 2
    if not verdicts_path.exists():
        print(f"[ingest] ERROR: verdicts file not found: {verdicts_path}", file=sys.stderr)
        return 2

    # Load current worklist (header + rows).
    header = None
    rows: list[dict] = []
    for line in sidecar.read_text(encoding="utf-8", errors="replace").splitlines():
        line = line.strip()
        if not line:
            continue
        obj = json.loads(line)
        if obj.get("schema") == SCHEMA:
            header = obj
            continue
        rows.append(obj)
    index = {f"{r.get('contract')}.{r.get('function')}@{r.get('file_line')}": r for r in rows}
    # Secondary index by file_line + function (verdicts may omit contract).
    fl_index: dict[tuple[str, str], dict] = {}
    for r in rows:
        fl_index[(r.get("file_line"), r.get("function"))] = r

    applied = 0
    unmatched = []
    for raw in verdicts_path.read_text(encoding="utf-8", errors="replace").splitlines():
        raw = raw.strip()
        if not raw or raw.startswith("#"):
            continue
        try:
            v = json.loads(raw)
        except json.JSONDecodeError:
            continue
        if v.get("schema") == SCHEMA:
            continue
        status = normalize_status(v.get("status") or v.get("verdict"))
        if status not in TERMINAL_VERDICTS:
            continue
        target = None
        key = f"{v.get('contract')}.{v.get('function')}@{v.get('file_line')}"
        if key in index:
            target = index[key]
        elif (v.get("file_line"), v.get("function")) in fl_index:
            target = fl_index[(v.get("file_line"), v.get("function"))]
        if target is None:
            unmatched.append(v.get("file_line") or v.get("function") or "?")
            continue
        merged = dict(target)
        merged.update(v)
        if not _row_has_terminal_evidence(merged, status):
            unmatched.append(v.get("file_line") or v.get("function") or "?")
            continue
        target["status"] = status
        for carry in (
            "verdict_detail", "poc_path", "severity", "source_ref",
            "source_refs", "evidence", "evidence_ref", "evidence_refs",
            "poc_evidence_lines", "pass_evidence_lines", "reason",
            "why_no_exploit", "why_no_gap_or_exploit",
        ):
            if carry in v:
                target[carry] = v[carry]
        target["verdict_at"] = v.get("verdict_at") or utc_now()
        applied += 1

    pending = sum(1 for r in rows if r.get("status") == "pending")
    if header is None:
        header = {"schema": SCHEMA, "workspace": str(workspace)}
    header["total_functions"] = len(rows)
    header["ingested_at"] = utc_now()

    with sidecar.open("w", encoding="utf-8") as fh:
        fh.write(json.dumps(header) + "\n")
        for r in rows:
            fh.write(json.dumps(r, sort_keys=True) + "\n")

    summary = {
        "schema": SCHEMA,
        "mode": "ingest",
        "workspace": str(workspace),
        "sidecar": str(sidecar),
        "applied": applied,
        "unmatched": len(unmatched),
        "unmatched_samples": unmatched[:10],
        "total_functions": len(rows),
        "pending": pending,
        "attacked": len(rows) - pending,
        "all_attacked": pending == 0,
    }
    if as_json:
        print(json.dumps(summary, indent=2))
    else:
        print(f"[ingest] applied={applied} unmatched={len(unmatched)} "
              f"pending={pending} attacked={len(rows) - pending}")
        if unmatched:
            print(f"[ingest] unmatched samples: {unmatched[:5]}")
    return 0


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--workspace", required=True, help="Audit workspace root (any workspace).")
    ap.add_argument("--json", action="store_true", help="Emit machine-readable JSON summary.")
    g = ap.add_mutually_exclusive_group(required=True)
    g.add_argument("--emit", action="store_true", help="Build the per-function ATTACK worklist.")
    g.add_argument("--ingest", metavar="VERDICTS.jsonl",
                   help="Fold per-function attack verdicts back into the worklist.")
    args = ap.parse_args(argv)

    workspace = Path(args.workspace).expanduser().resolve()
    if not workspace.exists():
        print(f"ERROR: workspace not found: {workspace}", file=sys.stderr)
        return 2

    if args.emit:
        return emit(workspace, args.json)
    return ingest(workspace, Path(args.ingest).expanduser().resolve(), args.json)


if __name__ == "__main__":
    raise SystemExit(main())
