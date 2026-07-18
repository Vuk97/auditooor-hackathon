#!/usr/bin/env python3
"""compiler-feature-screen.py - E2 compiler-feature-screen (advisory-first).

North-star: the compiler is a TRUSTED ENFORCEMENT (source semantics preserved
in bytecode). This tool enumerates that trust per (file, pinned_version,
feature) and FAILS-CLOSED on an un-screened affected pair.

It is ADVISORY-FIRST and does NO bytecode diff. It:
  1. derives the per-file pinned solc/vyper version (solc pragma + vyper
     ``# @version`` scanner, same map as solc-version-manager.scan_workspace),
  2. loads the on-disk compiler-bug advisories (solc_compiler_bugs +
     vyper_compiler_fix_history), parsing each into a structured
     (introduced, fixed, subsystem) window,
  3. regex-scans each in-scope .sol/.vy for a feature token set,
  4. for every (file, pinned_version, feature) triple emits a verdict:
       FLAG       - an advisory has introduced <= pinned < fixed AND the
                    advisory subsystem maps to the used feature,
       CLEAR      - a matching-feature advisory exists but the pinned version
                    is outside every window,
       UNSCREENED - a (version, feature) pair used in-scope has NO verdict
                    computed (no matching-feature windowed advisory, or the
                    version is unparseable) - fail-closed, NOT clear.

Output: ``.auditooor/compiler_feature_screen.json``
        (schema auditooor.compiler_feature_screen.v1).

Fail-OPEN on missing substrate (0 in-scope contracts).

Usage:
    compiler-feature-screen.py <workspace> [--advisories DIR ...] [--out PATH]
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import sys
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple

SCHEMA = "auditooor.compiler_feature_screen.v1"
# exploit-queue.py:_gather_from_source_mined_queue ingests this file (schema
# auditooor.exploit_queue.v1); this is the dedup namespace for our rows so reruns
# are idempotent and FOREIGN rows are never clobbered.
EXPLOIT_QUEUE_SCHEMA = "auditooor.exploit_queue.v1"
SOURCE_MINED_REL = os.path.join(".auditooor", "exploit_queue.source_mined.json")
DISPOSITIONS_REL = os.path.join(
    ".auditooor", "compiler_feature_screen_dispositions.jsonl"
)
_TERMINAL_DISPOSITION_TYPES = {
    "clean", "covered", "duplicate", "known-issue", "not-applicable",
    "not_applicable", "oos", "out-of-scope", "refuted", "resolved",
}
_STRICT_OPEN_VERDICTS = {"FLAG", "UNSCREENED", "AMBIGUOUS", "UNRESOLVED"}
COMPILER_FEATURE_FLAG_SOURCE = "compiler-feature-flag"
REPO_ROOT = Path(__file__).resolve().parents[1]
_ADV_ROOT = REPO_ROOT / "audit" / "corpus_tags" / "tags"
DEFAULT_ADVISORY_DIRS = (
    _ADV_ROOT / "solc_compiler_bugs",
    _ADV_ROOT / "vyper_compiler_fix_history",
)

# feature token -> the advisory subsystems that materially cover it. E2b WIDEN: each
# screenable feature maps to a PER-FEATURE tag (the feature name itself), NOT a coarse solc
# subsystem (codegen / storage-layout / abi-codec / optimizer). The coarse tags matched
# UNRELATED advisories - measured on morpho as a dominant FP (immutable matched
# loststoragearraywriteonslotoverflow, a storage-array bug, 36x) and a 179x-false FLAG wave
# across lido/etherfi/optimism under a naive coarse map. So a feature is screened ONLY against
# a CURATED per-advisory window (KNOWN_BAD_WINDOWS), never a coarse subsystem bucket.
# FEATURE_SUBSYSTEMS is the advisory-ROW source (which curated windows a feature consults),
# NOT the gate source (see GATE_ELIGIBLE_FEATURES).
FEATURE_SUBSYSTEMS: Dict[str, Set[str]] = {
    "transient-storage": {"transient-storage"},
    "udvt": {"udvt"},
    "abi-nested-dynamic": {"abi-nested-dynamic"},
    "inline-asm": {"inline-asm"},
    "immutable": {"immutable"},
}

# CURATED solc bug-list windows with PER-ADVISORY feature attribution (the coarse corpus
# subsystem tags lack this - e.g. UserDefinedValueTypesBug is tagged subsystem=storage-layout,
# which would also match unrelated storage bugs). Each window carries subsystem=<feature> so
# screen_pair matches PRECISELY (only this window, not the whole coarse bucket) and
# feature_tagged=True so it is eligible to graduate into the L37 gate. Seeded from the real
# narrow windows on disk (audit/corpus_tags/tags/solc_compiler_bugs). inline-asm / immutable
# have NO windowed advisory, so every such pair is UNSCREENED (advisory, never gates).
KNOWN_BAD_WINDOWS: List[dict] = [
    {"feature": "transient-storage", "introduced": "0.8.28", "fixed": "0.8.34",
     "uid": "solc-compiler:sol-2026-1:transientstorageclearinghelpercollision:24a202785af6",
     "feature_tagged": True},
    {"feature": "udvt", "introduced": "0.8.8", "fixed": "0.8.9",
     "uid": "solc-compiler:sol-2021-4:userdefinedvaluetypesbug:4276fff67f9e",
     "feature_tagged": True},
    {"feature": "abi-nested-dynamic", "introduced": "0.5.8", "fixed": "0.8.14",
     "uid": "solc-compiler:sol-2022-2:nestedcalldataarrayabireencodingsizevalidation:68bf16017565",
     "feature_tagged": True},
    {"feature": "abi-nested-dynamic", "introduced": "0.5.8", "fixed": "0.8.16",
     "uid": "solc-compiler:sol-2022-6:abireencodingheadoverflowwithstaticarraycleanup:c96cde7b1de0",
     "feature_tagged": True},
]

# GATE-ELIGIBILITY discriminator (the anti-fleet-RED teeth). A feature graduates into the
# L37 gate ONLY after (a) its advisories carry a per-feature tag (feature_tagged) AND (b) it
# is fleet-validated 1:1 on >=3 workspaces (the same >=3-workspace admission the L37
# global-rule gate requires, per audit-completeness-check.check_enforcement_point).
# transient-storage is the sole graduated feature: its subsystem tag is a verified 1:1 match,
# version-boundary discriminated. Its curated window is [0.8.28, 0.8.34) (introduced 0.8.28
# INCLUSIVE), so a real transient state var is a FLAG at the 0.8.28 boundary: the FLAG count
# on the green EVM fleet is 0 ONLY for ws pinning OUTSIDE [0.8.28, 0.8.34); morpho pins the
# inclusive 0.8.28 boundary and genuinely flags 3x on REAL `transient` state vars
# (Bundler3.initiator/reenterHash + VaultV2.firstTotalAssets) - true-positive advisory rows,
# NOT a fleet-RED. The FP that WOULD fleet-RED a genuinely-green ws (a `transient` in a `//`
# comment or a "transient" string literal at 0.8.28-0.8.33) is killed at the source:
# detect_features strips comments + string literals before the keyword scan. The WIDENED
# features (udvt / abi-nested-dynamic / inline-asm / immutable)
# are ADVISORY - they emit rows + seed the exploit queue as hunt fuel, but NEVER fail the gate
# (their windows are wide/shape-specific, so FLAG-gating them would fleet-RED green ws). To
# add a feature here, re-probe >=3 ws (incl. morpho/spark) for 1:1 per-advisory precision.
GATE_ELIGIBLE_FEATURES: Set[str] = {"transient-storage"}

_SKIP_DIRS = {"lib", "test", "tests", "out", "node_modules", "cache",
              "artifacts", "agent_outputs", ".git", ".auditooor",
              "mocks", "mock", "fixtures", "flattened", "script"}


# --------------------------------------------------------------------------
# version helpers
# --------------------------------------------------------------------------
def parse_ver(v: str) -> Optional[Tuple[int, int, int]]:
    """Parse '0.8.28' -> (0,8,28). 'pre-0.1.0' -> (0,0,0). Else None."""
    if not v:
        return None
    v = v.strip()
    if v.startswith("pre-"):
        return (0, 0, 0)
    m = re.match(r"^(\d+)\.(\d+)\.(\d+)$", v)
    if m:
        return (int(m.group(1)), int(m.group(2)), int(m.group(3)))
    return None


def _first_semver(text: str) -> Optional[str]:
    m = re.search(r"(\d+\.\d+\.\d+)", text)
    return m.group(1) if m else None


def _version_candidates(text: str, vyper: bool) -> List[str]:
    """Return distinct concrete version candidates in source declaration order."""
    pattern = (r"#\s*(?:@version|pragma\s+version)\s+(.+)$" if vyper
               else r"pragma\s+solidity\s+([^;]+);")
    out: List[str] = []
    for line in text.splitlines():
        m = re.search(pattern, line)
        if not m:
            continue
        version = _first_semver(m.group(1))
        if version and version not in out:
            out.append(version)
    return out


# --------------------------------------------------------------------------
# per-file pinned version (solc pragma + vyper @version)
# --------------------------------------------------------------------------
def pinned_solc(text: str) -> Optional[str]:
    """Lowest concrete version a solc pragma pins to (the 'pinned' floor)."""
    best: Optional[str] = None
    for line in text.splitlines():
        m = re.search(r"pragma\s+solidity\s+([^;]+);", line)
        if not m:
            continue
        frag = m.group(1)
        sv = _first_semver(frag)
        if sv:
            best = sv
            break
    return best


def pinned_vyper(text: str) -> Optional[str]:
    """Vyper '# @version' / '# pragma version' scanner -> pinned floor."""
    for line in text.splitlines():
        m = re.search(r"#\s*(?:@version|pragma\s+version)\s+(.+)$", line)
        if m:
            sv = _first_semver(m.group(1))
            if sv:
                return sv
    return None


# --------------------------------------------------------------------------
# feature detection
# --------------------------------------------------------------------------
def _strip_comments_and_strings(text: str) -> str:
    """Blank out Solidity/Vyper comments (`//`, `/* */`, `#`) and string literals
    (`"..."`, `'...'`) BEFORE the feature-keyword scan, PRESERVING length + newlines,
    so a keyword that appears ONLY inside a comment or a string literal is a
    true-negative and never false-FLAGs the L37 gate. Mirrors the comment-strip
    discipline of exploit-class-coverage._strip_comments (R8), extended to string
    literals (a "transient" string literal was the same latent fleet-RED as a
    `// transient` comment).

    Single-pass state machine (NOT a regex chain) so it is immune to the two ordering
    hazards a naive strip has: a `//` inside a string (`"http://x"`) and a quote inside
    a comment (`// "transient"`). An unterminated comment/string blanks to EOF."""
    out: List[str] = []
    i = 0
    n = len(text)
    while i < n:
        c = text[i]
        nxt = text[i + 1] if i + 1 < n else ""
        # `//` line comment -> blank to end-of-line (the newline is preserved).
        if c == "/" and nxt == "/":
            while i < n and text[i] != "\n":
                out.append(" ")
                i += 1
            continue
        # `/* ... */` block comment -> blank the span (interior newlines preserved).
        if c == "/" and nxt == "*":
            out.append("  ")
            i += 2
            while i < n:
                if text[i] == "*" and i + 1 < n and text[i + 1] == "/":
                    out.append("  ")
                    i += 2
                    break
                out.append("\n" if text[i] == "\n" else " ")
                i += 1
            continue
        # `#` line comment (Vyper; `#` is never valid Solidity outside strings/comments).
        if c == "#":
            while i < n and text[i] != "\n":
                out.append(" ")
                i += 1
            continue
        # `"..."` / `'...'` string literal -> blank the span (escapes respected).
        if c == '"' or c == "'":
            quote = c
            out.append(" ")
            i += 1
            while i < n:
                ch = text[i]
                if ch == "\\" and i + 1 < n:
                    out.append(" ")
                    out.append("\n" if text[i + 1] == "\n" else " ")
                    i += 2
                    continue
                if ch == quote:
                    out.append(" ")
                    i += 1
                    break
                out.append("\n" if ch == "\n" else " ")
                i += 1
            continue
        out.append(c)
        i += 1
    return "".join(out)


def detect_features(text: str) -> Set[str]:
    """E2b WIDEN: detect the 5 screenable compiler features. transient-storage is the ONLY
    gate-eligible feature (verified 1:1 advisory tag; morpho pins 0.8.28 and genuinely flags
    3x on REAL transient state vars - a true positive, not a fleet-RED); inline-asm / immutable
    / udvt / abi-nested-dynamic are ADVISORY - they emit rows + seed the exploit queue as hunt
    fuel but NEVER fail the L37 gate (see GATE_ELIGIBLE_FEATURES).

    Comments (`//`, `/* */`, `#`) and string literals are stripped FIRST (see
    _strip_comments_and_strings), so a `transient` in a `// transient ...` comment or a
    "transient" string literal is a true-negative - only a real state-var/keyword `transient`
    (or a `tstore`/`tload` call) flags. This kills the latent fleet-RED where a comment-only
    mention at solc 0.8.28-0.8.33 would set gate_eligible_flagged=1 on a genuinely-green ws."""
    text = _strip_comments_and_strings(text)
    feats: Set[str] = set()
    if re.search(r"\btstore\s*\(", text) or re.search(r"\btload\s*\(", text) \
            or "transient storage" in text.lower() \
            or re.search(r"\btransient\b", text):
        feats.add("transient-storage")
    # inline assembly block (optionally annotated, e.g. `("memory-safe")`). The
    # annotation body is matched loosely (`\([^)]*\)`) because the preceding
    # _strip_comments_and_strings blanks the `"memory-safe"` STRING LITERAL to spaces -
    # keying on the literal token would miss an annotated block after stripping.
    if re.search(r'\bassembly\b\s*(?:\([^)]*\)\s*)?\{', text):
        feats.add("inline-asm")
    # immutable state variable.
    if re.search(r"\bimmutable\b", text):
        feats.add("immutable")
    # user-defined value type: `type X is Y` declaration or a (un)wrap() call.
    if re.search(r"\btype\s+\w+\s+is\s+\w+", text) \
            or re.search(r"\.\s*(?:un)?wrap\s*\(", text):
        feats.add("udvt")
    # ABI (nested / dynamic) encode/decode.
    if re.search(r"\babi\.(?:encode|decode)", text):
        feats.add("abi-nested-dynamic")
    return feats


# --------------------------------------------------------------------------
# advisory loading + window parse
# --------------------------------------------------------------------------
def parse_window(rec: dict) -> Optional[dict]:
    """Extract (introduced, fixed, subsystem, uid) from a hackerman record.

    Reads the structured raw_signature first
    ('subsystem=X introduced<=A fixed_in=B'), else shape_tags
    (introduced-A / fixed-B + subsystem tag). Returns None if no window.
    """
    fs = rec.get("function_shape", {}) or {}
    raw = fs.get("raw_signature", "") or ""
    uid = rec.get("record_id") or rec.get("uid") or ""

    subsystem = None
    introduced = None
    fixed = None

    ms = re.search(r"subsystem=([a-zA-Z0-9-]+)", raw)
    if ms:
        subsystem = ms.group(1)
    mi = re.search(r"introduced<=(\S+)", raw)
    if mi:
        introduced = mi.group(1)
    mf = re.search(r"fixed_in=(\S+)", raw)
    if mf:
        fixed = mf.group(1)

    tags = fs.get("shape_tags", []) or []
    if introduced is None:
        for t in tags:
            m = re.match(r"introduced-(\d+\.\d+\.\d+|pre-\d+\.\d+\.\d+)$", t)
            if m:
                introduced = m.group(1)
                break
    if fixed is None:
        for t in tags:
            m = re.match(r"fixed-(\d+\.\d+\.\d+)$", t)
            if m:
                fixed = m.group(1)
                break

    if parse_ver(introduced) is None or parse_ver(fixed) is None:
        return None
    if not subsystem:
        return None
    return {
        "uid": uid,
        "introduced": introduced,
        "fixed": fixed,
        "subsystem": subsystem,
    }


def load_advisories(dirs) -> List[dict]:
    out: List[dict] = []
    for d in dirs:
        d = Path(d)
        if not d.is_dir():
            continue
        for rec_json in sorted(d.glob("*/record.json")):
            try:
                rec = json.loads(rec_json.read_text())
            except (OSError, ValueError):
                continue
            w = parse_window(rec)
            if w:
                out.append(w)
    return out


def _merge_curated_windows(advisories: List[dict]) -> List[dict]:
    """PREPEND the curated per-feature windows (feature_tagged=True, subsystem=<feature>) to
    the corpus advisory list and DROP any corpus row that shares a curated uid (dedup). The
    curated windows are consulted FIRST by screen_pair, so a transient FLAG matches the
    feature_tagged window (gate-eligible) rather than an untagged corpus duplicate. The
    widened features (udvt / abi-nested-dynamic) screen ONLY against these precise windows -
    the coarse corpus subsystem buckets (storage-layout / abi-codec) no longer match a
    feature (FEATURE_SUBSYSTEMS maps each feature to its own name), which is the FP-kill."""
    merged: List[dict] = []
    seen: Set[str] = set()
    for w in KNOWN_BAD_WINDOWS:
        merged.append({
            "uid": w["uid"],
            "introduced": w["introduced"],
            "fixed": w["fixed"],
            "subsystem": w["feature"],
            "feature_tagged": True,
        })
        seen.add(w["uid"])
    for a in advisories:
        if a.get("uid") in seen:
            continue
        merged.append(a)
    return merged


# --------------------------------------------------------------------------
# the screen
# --------------------------------------------------------------------------
def screen_pair(version: Optional[str], feature: str,
                advisories: List[dict]) -> dict:
    """Return {verdict, matched_advisory_uid, introduced, fixed, subsystem, gate_eligible}."""
    subsystems = FEATURE_SUBSYSTEMS.get(feature, set())
    matching = [a for a in advisories if a["subsystem"] in subsystems]

    pv = parse_ver(version) if version else None
    if pv is None:
        # version unparseable -> cannot compute a verdict -> fail-closed.
        return _verdict("UNSCREENED", None, feature)
    if not matching:
        # feature used but NO matching-feature windowed advisory -> fail-closed.
        return _verdict("UNSCREENED", None, feature)

    for a in matching:
        iv = parse_ver(a["introduced"])
        fv = parse_ver(a["fixed"])
        if iv is None or fv is None:
            continue
        if iv <= pv < fv:
            return _verdict("FLAG", a, feature)
    # matching-feature advisory exists but version outside every window.
    return _verdict("CLEAR", None, feature)


def _stable_id(file_ref: str, language: str, version: Optional[str], feature: str) -> str:
    """Stable identity of one source/version/feature screening obligation."""
    body = "|".join(("compiler-feature-screen", file_ref, language,
                     str(version or ""), feature))
    return "cfs-" + hashlib.sha256(body.encode("utf-8", errors="replace")).hexdigest()[:20]


def _evidence_backed_disposition(row: dict) -> bool:
    """Require typed closure plus explicit evidence; prose alone is not closure."""
    dtype = str(row.get("disposition_type") or "").strip().lower()
    reason = str(row.get("reason") or "").strip()
    if dtype not in _TERMINAL_DISPOSITION_TYPES or not reason:
        return False
    def has_value(value) -> bool:
        if isinstance(value, str):
            return bool(value.strip())
        if isinstance(value, (list, tuple)):
            return any(has_value(item) for item in value)
        if isinstance(value, dict):
            return any(has_value(item) for item in value.values())
        return False

    for key in ("evidence", "evidence_ref", "evidence_refs", "source_ref", "source_refs"):
        value = row.get(key)
        if has_value(value):
            return True
    return False


def _load_dispositions(ws: Path) -> Tuple[Dict[str, dict], Set[str]]:
    """Load valid typed closures and identify conflicting stable IDs."""
    valid: Dict[str, dict] = {}
    ambiguous: Set[str] = set()
    path = ws / DISPOSITIONS_REL
    if not path.is_file():
        return valid, ambiguous
    try:
        lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError:
        return valid, ambiguous
    for line in lines:
        if not line.strip():
            continue
        try:
            row = json.loads(line)
        except (TypeError, ValueError):
            continue
        if not isinstance(row, dict) or not _evidence_backed_disposition(row):
            continue
        stable_id = str(row.get("stable_id") or "").strip()
        if not stable_id:
            continue
        if stable_id in valid and valid[stable_id] != row:
            ambiguous.add(stable_id)
            valid.pop(stable_id, None)
            continue
        if stable_id not in ambiguous:
            valid[stable_id] = row
    return valid, ambiguous


def _scope_accounting(ws: Path, files: List[Path]) -> dict:
    """Record why an empty result is a proven N/A rather than a silent skip."""
    manifest = ws / ".auditooor" / "inscope_units.jsonl"
    manifest_present = manifest.is_file()
    manifest_valid = not manifest_present
    manifest_rows = 0
    if manifest_present:
        try:
            for line in manifest.read_text(encoding="utf-8", errors="replace").splitlines():
                if not line.strip():
                    continue
                obj = json.loads(line)
                if not isinstance(obj, dict):
                    manifest_valid = False
                    continue
                manifest_rows += 1
        except (OSError, TypeError, ValueError):
            manifest_valid = False
    return {
        "workspace_exists": ws.is_dir(),
        "scope_source": "inscope_units.jsonl" if manifest_present else "filtered_source_walk",
        "scope_manifest_present": manifest_present,
        "scope_manifest_valid": manifest_valid,
        "scope_manifest_rows": manifest_rows,
        "files_enumerated": len(files),
        "evidence_backed": bool(ws.is_dir() and manifest_valid),
    }


def _strict_result(result: dict, ws: Path) -> dict:
    dispositions, ambiguous_dispositions = _load_dispositions(ws)
    blockers: List[str] = []
    dispositioned = 0
    open_rows: List[str] = []
    for row in result.get("rows") or []:
        verdict = str(row.get("verdict") or "").upper()
        if verdict not in _STRICT_OPEN_VERDICTS and not row.get("unresolved"):
            continue
        stable_id = str(row.get("stable_id") or "")
        if stable_id in dispositions and stable_id not in ambiguous_dispositions:
            row["disposition"] = dispositions[stable_id].get("disposition_type")
            row["disposition_evidence_backed"] = True
            dispositioned += 1
            continue
        open_rows.append(stable_id or "<missing-stable-id>")
    if open_rows:
        blockers.append("open-rows:" + ",".join(open_rows))
    if ambiguous_dispositions:
        blockers.append("ambiguous-dispositions:" + ",".join(sorted(ambiguous_dispositions)))
    accounting = result.get("accounting") or {}
    if not accounting.get("evidence_backed"):
        blockers.append("missing-evidence-backed-accounting")
    result["strict_dispositioned"] = dispositioned
    result["strict_open_rows"] = open_rows
    result["strict_blockers"] = blockers
    result["strict_verdict"] = "fail-compiler-feature-screen" if blockers else (
        "pass-not-applicable" if not result.get("rows") and not result.get("substrate_present")
        else "pass-compiler-feature-screen"
    )
    result["strict_ok"] = not blockers
    result["verdict"] = result["strict_verdict"]
    return result


def _verdict(verdict: str, adv: Optional[dict], feature: str = "") -> dict:
    # GATE-ELIGIBILITY (anti-fleet-RED teeth): a FLAG only counts toward the L37 gate when
    # the feature has GRADUATED (GATE_ELIGIBLE_FEATURES) AND the matched advisory carries a
    # per-feature tag (feature_tagged). A widened advisory FLAG (abi / udvt / inline-asm /
    # immutable) or any UNSCREENED / CLEAR row is advisory-only - it seeds the exploit queue
    # as hunt fuel but NEVER fails the gate.
    gate_eligible = bool(
        verdict == "FLAG"
        and feature in GATE_ELIGIBLE_FEATURES
        and adv is not None
        and adv.get("feature_tagged")
    )
    return {
        "verdict": verdict,
        "matched_advisory_uid": adv["uid"] if adv else None,
        "introduced": adv["introduced"] if adv else None,
        "fixed": adv["fixed"] if adv else None,
        "subsystem": adv["subsystem"] if adv else None,
        "gate_eligible": gate_eligible,
    }


def find_inscope_files(ws: Path) -> List[Path]:
    # Prefer the authoritative in-scope manifest when present: it excludes generated
    # harnesses (.auditooor/mvc_runner*.sol etc.), mocks, and out-of-scope trees. This
    # is the real scope; the walk below is only a fallback for a ws that has not been
    # enumerated yet.
    manifest = ws / ".auditooor" / "inscope_units.jsonl"
    if manifest.is_file():
        seen: set = set()
        out: List[Path] = []
        try:
            for ln in manifest.read_text(encoding="utf-8").splitlines():
                ln = ln.strip()
                if not ln:
                    continue
                try:
                    rel = json.loads(ln).get("file") or ""
                except (ValueError, TypeError):
                    continue
                if not (rel.endswith(".sol") or rel.endswith(".vy")):
                    continue
                p = Path(str(rel))
                ap = p if p.is_absolute() else ws / str(rel)
                key = str(ap)
                if key not in seen and ap.is_file():
                    seen.add(key)
                    out.append(ap)
        except OSError:
            out = []
        if out:
            return out
    # fallback: filtered walk, never descending into generated / vendor / test dirs.
    out = []
    for root, dirs, files in os.walk(ws):
        dirs[:] = [d for d in dirs if d not in _SKIP_DIRS]
        for f in files:
            if f.endswith(".sol") or f.endswith(".vy"):
                out.append(Path(root) / f)
    return out


def run(ws: Path, advisory_dirs=DEFAULT_ADVISORY_DIRS, strict: bool = False) -> dict:
    advisories = _merge_curated_windows(load_advisories(advisory_dirs))
    files = find_inscope_files(ws)
    rows: List[dict] = []
    read_failures: List[str] = []

    for fp in sorted(files):
        try:
            text = fp.read_text(errors="replace")
        except OSError:
            try:
                rel = str(fp.relative_to(ws))
            except ValueError:
                rel = str(fp)
            read_failures.append(rel)
            rows.append({
                "file": rel,
                "language": "vyper" if fp.suffix == ".vy" else "solidity",
                "pinned_version": None,
                "feature": "<source-read>",
                "verdict": "UNRESOLVED",
                "stable_id": _stable_id(rel, "source", None, "<source-read>"),
                "id": _stable_id(rel, "source", None, "<source-read>"),
                "applicable": True,
                "advisory": True,
            })
            continue
        vy = fp.suffix == ".vy"
        lang = "vyper" if vy else "solidity"
        candidates = _version_candidates(text, vy)
        version = pinned_vyper(text) if vy else pinned_solc(text)
        feats = detect_features(text)
        if not feats:
            continue
        try:
            rel = str(fp.relative_to(ws))
        except ValueError:
            rel = str(fp)
        for feat in sorted(feats):
            v = (_verdict("AMBIGUOUS", None, feat) if len(candidates) > 1
                 else screen_pair(version, feat, advisories))
            stable_id = _stable_id(rel, lang, version, feat)
            rows.append({
                "file": rel,
                "language": lang,
                "pinned_version": version,
                "feature": feat,
                "stable_id": stable_id,
                "id": stable_id,
                "verdict": v["verdict"],
                "matched_advisory_uid": v["matched_advisory_uid"],
                "introduced": v["introduced"],
                "fixed": v["fixed"],
                "subsystem": v["subsystem"],
                # gate_eligible: only a graduated-feature (transient) FLAG on a feature_tagged
                # window; advisory=True for every widened / UNSCREENED / CLEAR row (queue fuel,
                # never gates).
                "gate_eligible": v["gate_eligible"],
                "advisory": not v["gate_eligible"],
                "applicable": v["verdict"] == "FLAG",
            })

    flagged = sum(1 for r in rows if r["verdict"] == "FLAG")
    unscreened = sum(1 for r in rows if r["verdict"] == "UNSCREENED")
    gate_eligible_flagged = sum(
        1 for r in rows if r["verdict"] == "FLAG" and r.get("gate_eligible"))
    substrate_present = len(files) > 0
    result = {
        "schema": SCHEMA,
        "workspace": str(ws),
        "substrate_present": substrate_present,
        "advisory_windows_loaded": len(advisories),
        "rows": rows,
        "accounting": {
            **_scope_accounting(ws, files),
            "files_read": len(files) - len(read_failures),
            "read_failures": read_failures,
            "features_screened": len(rows),
            "advisory_windows_loaded": len(advisories),
        },
        "counts": {
            "screened_pairs": len(rows),
            "flagged": flagged,
            "unscreened": unscreened,
            # the ONLY count the L37 gate reads (transient in-window on a feature_tagged
            # window); widened FLAGs + UNSCREENED are WARN-surface, never gate.
            "gate_eligible_flagged": gate_eligible_flagged,
        },
        "strict": bool(strict),
    }
    if strict:
        return _strict_result(result, ws)
    return result


def _build_flag_queue_row(ws_name: str, row: dict) -> dict:
    """One auditooor.exploit_queue.v1 row for a FLAG screen row.

    Claim-free: target=file, kind=compiler-feature-flag, note=feature@version in
    advisory window (uid). proof_status=open (an open obligation, no proof yet).
    The lead_id is deterministic over (feature, file, version, uid) so reruns
    dedup idempotently."""
    feature = str(row.get("feature") or "")
    file_ref = str(row.get("file") or "")
    version = str(row.get("pinned_version") or "")
    uid = str(row.get("matched_advisory_uid") or "")

    ident = "|".join([feature, file_ref, version, uid])
    ident_hash = hashlib.sha256(ident.encode("utf-8", errors="replace")).hexdigest()[:12]
    slug = (feature + "-" + Path(file_ref.replace("\\", "/")).name).replace(
        "/", "-").replace(".", "-").replace("::", "--")
    lead_id = "F-CFEAT-" + slug[:80] + "-" + ident_hash

    note = feature + "@" + version + " in advisory window (" + uid + ")"
    # title leads with the target file so title[:80] stays UNIQUE per FLAG row
    # (the downstream _deduplicate keys on title[:80]; a shared prefix collapses
    # sibling flags into one).
    return {
        "lead_id": lead_id,
        "title": "compiler-feature flag: " + file_ref + " :: " + note,
        "proof_status": "open",
        "quality_gate_status": "open",
        # the target + the assertion
        "kind": COMPILER_FEATURE_FLAG_SOURCE,
        "target": file_ref,
        "note": note,
        "attack_class": COMPILER_FEATURE_FLAG_SOURCE,
        "feature": feature,
        "pinned_version": version,
        "matched_advisory_uid": uid,
        # source anchor
        "workspace": ws_name,
        "contract": file_ref,
        "file": file_ref,
        "source_path": file_ref,
        "source_ref": file_ref,
        "source_refs": [file_ref] if file_ref else [],
        "broken_invariant_ids": [],
        # provenance (dedup namespace)
        "source": COMPILER_FEATURE_FLAG_SOURCE,
    }


def seed_flags_to_exploit_queue(ws: Path, result: dict) -> dict:
    """UPSERT one exploit-queue.v1 row per FLAG screen row into
    <ws>/.auditooor/exploit_queue.source_mined.json (ADDITIVE - foreign rows are
    preserved, our own rows are refreshed in place).

    Non-vacuous: a real FLAG (feature actually hit + advisory-window match)
    produces a row; 0 FLAGs produce NONE (the file is left untouched)."""
    flags = [r for r in (result.get("rows") or [])
             if r.get("verdict") == "FLAG" and r.get("matched_advisory_uid")]
    if not flags:
        return {"rows_written": 0, "rows_updated": 0, "flags": 0}

    path = ws / SOURCE_MINED_REL
    payload = None
    if path.exists():
        try:
            payload = json.loads(path.read_text(encoding="utf-8", errors="replace"))
        except (OSError, ValueError):
            payload = None
    if not isinstance(payload, dict) or not isinstance(payload.get("queue"), list):
        payload = {"schema": EXPLOIT_QUEUE_SCHEMA, "workspace": str(ws), "queue": []}

    existing = [r for r in payload["queue"] if isinstance(r, dict)]
    index = {}
    for i, r in enumerate(existing):
        if r.get("source") == COMPILER_FEATURE_FLAG_SOURCE and r.get("lead_id"):
            index[r["lead_id"]] = i

    written = updated = 0
    for fr in flags:
        row = _build_flag_queue_row(ws.name, fr)
        lid = row["lead_id"]
        if lid in index:
            existing[index[lid]] = row
            updated += 1
        else:
            existing.append(row)
            index[lid] = len(existing) - 1
            written += 1

    payload["queue"] = existing
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2))
    return {"rows_written": written, "rows_updated": updated, "flags": len(flags)}


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description="E2 compiler-feature-screen")
    ap.add_argument("workspace")
    ap.add_argument("--advisories", action="append", default=None,
                    help="advisory dir(s); default = on-disk corpus tags")
    ap.add_argument("--out", default=None)
    ap.add_argument("--strict", action="store_true",
                    help="fail on open applicable/unscreened/ambiguous rows")
    args = ap.parse_args(argv)

    ws = Path(args.workspace).resolve()
    adv_dirs = args.advisories if args.advisories else DEFAULT_ADVISORY_DIRS
    result = run(ws, adv_dirs, strict=args.strict)

    out = Path(args.out) if args.out else (ws / ".auditooor" /
                                           "compiler_feature_screen.json")
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(result, indent=2))

    # COMPOUND: seed FLAG rows into the source-mined exploit queue so a fired
    # compiler-feature flag flows into the hunt/exploit-conversion pipeline.
    seed = seed_flags_to_exploit_queue(ws, result)
    if seed["rows_written"] or seed["rows_updated"]:
        print(f"[compiler-feature-screen] seeded exploit-queue: "
              f"{seed['rows_written']} new / {seed['rows_updated']} refreshed "
              f"from {seed['flags']} FLAG rows -> {ws / SOURCE_MINED_REL}")

    c = result["counts"]
    if not result["substrate_present"]:
        label = "N/A" if not args.strict else result.get("strict_verdict", "fail")
        print(f"[compiler-feature-screen] {label}: 0 in-scope contracts -> {out}")
        return 1 if args.strict and result.get("strict_blockers") else 0
    print(f"[compiler-feature-screen] screened={c['screened_pairs']} "
          f"flagged={c['flagged']} unscreened={c['unscreened']} "
          f"strict={result.get('strict_verdict', 'advisory')} -> {out}")
    return 1 if args.strict and result.get("strict_blockers") else 0


if __name__ == "__main__":
    sys.exit(main())
