#!/usr/bin/env python3
"""l29_filing_check.py — L29-Filing pre-submit gates (codified 2026-05-08).

Implements the four mechanical filing gates from `docs/CODIFIED_DISCIPLINE_RULES_2026-05-08.md`
L29-Filing section. Each Check is a function that returns ``(passed, message)`` and the CLI
dispatches per ``--check`` selector. ``pre-submit-check.sh`` invokes this once per check.

Checks
------
A: title-claimed-impact ∩ manifest.not_proven_impacts ≠ ∅  → fail closed
B: every ``proven_impact`` has ``poc_path`` (file exists) AND ``pass_evidence_lines``
C: paste-content-hash gate (record at pre-submit, verify at filing)
D: manifest-completeness + test-name verification (cross-cited PoC schema; test-name resolver)

Manifest discovery
------------------
Sibling manifest is searched in this order (first hit wins):

1. ``<paste_dir>/manifest.json``
2. ``<paste_dir>/.auditooor/impact_contracts.json``
3. ``<workspace_root>/.auditooor/impact_contracts.json`` where workspace root is the nearest
   ancestor containing ``.auditooor/`` or ``submissions/``.

If no manifest is found, all checks soft-skip with a clear message — pre-submit-check.sh treats
soft-skip as a warning, not a hard fail (filing is still allowed but the discipline gate is not
exercised). Hard fails are only emitted when the manifest IS present and a check finds a
violation.

Exit codes
----------
0 — passed (or soft-skip)
1 — failed closed
2 — usage error / unparseable input
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import sys
from pathlib import Path
from typing import Any


# Rubric-row prefix words to strip when comparing title tokens against
# manifest.not_proven_impacts entries. These are common impact-row openers
# (e.g. "Permanent freezing of funds") that don't carry semantic weight when
# checking for overlap; the meaningful tokens are the impact phrases themselves
# ("freezing", "loss", "chain split").
RUBRIC_PREFIX_NOISE = {
    "the", "a", "an", "of", "in", "on", "at", "to", "for", "from", "by",
    "with", "as", "is", "are", "be", "been", "being",
    "permanent", "permanently", "temporary", "temporarily",
    "direct", "indirect",
    "total", "partial",
    "user", "users", "user's", "users'",
    "fund", "funds",
    "and", "or",
}

# Whole-phrase tokens that indicate an impact severity claim. When one of
# these appears in the title AND in any not_proven_impacts entry, that's a
# Check A violation.
IMPACT_PHRASES = [
    "chain split",
    "network partition",
    "network shutdown",
    "permanent freezing",
    "permanent freeze",
    "freezing of funds",
    "frozen funds",
    "loss of funds",
    "direct loss",
    "direct theft",
    "theft of funds",
    "drain",
    "fork",
    "halt",
    "liveness fault",
    "double spend",
    "double-spend",
]



def _rglob_sorted(root: Path, base: str, cap: int) -> list[Path]:
    # r36-rebuttal: bugfix-inventory-claude-20260610
    """Return up to *cap* rglob hits sorted by (depth, mock-flag, path).

    Sorting rules (ascending priority):
    1. Fewest path separators first - shallower paths are more likely canonical
       source files than nested test-infra copies.
    2. Paths whose string representation contains any of mock, stub,
       fake, or fixture (case-insensitive) are deprioritised.
    3. Lexicographic tie-break for determinism across filesystems.

    This is a GENERIC helper - it makes no assumptions about workspace layout.
    """
    hits = list(root.rglob(base))
    hits.sort(key=lambda p: (
        str(p).count(os.sep),
        any(s in str(p).lower() for s in ("mock", "stub", "fake", "fixture")),
        str(p),
    ))
    return hits[:cap]


def _read_text(path: Path) -> str:
    return path.read_text(encoding="utf-8", errors="replace")


def _find_sibling_manifest(paste_path: Path) -> Path | None:
    """Walk upward looking for a manifest.json or impact_contracts.json sibling."""
    paste_dir = paste_path.parent
    candidates = [
        paste_dir / "manifest.json",
        paste_dir / ".auditooor" / "impact_contracts.json",
    ]
    for c in candidates:
        if c.is_file():
            return c
    # Walk up to find workspace root (ancestor containing .auditooor/ or submissions/)
    cur = paste_dir
    for _ in range(10):
        if cur == cur.parent:
            break
        manifest = cur / ".auditooor" / "impact_contracts.json"
        if manifest.is_file():
            return manifest
        manifest2 = cur / "manifest.json"
        if manifest2.is_file():
            return manifest2
        if (cur / ".auditooor").is_dir() or (cur / "submissions").is_dir():
            # workspace root reached without finding manifest
            return None
        cur = cur.parent
    return None


def _load_manifest(paste_path: Path) -> tuple[dict[str, Any] | None, Path | None]:
    manifest_path = _find_sibling_manifest(paste_path)
    if manifest_path is None:
        return None, None
    try:
        return json.loads(_read_text(manifest_path)), manifest_path
    except Exception:
        return None, manifest_path


def _extract_title(paste_text: str) -> str:
    """Extract title from front-matter ``title:`` line OR first H1.

    Falls back to first non-empty line if neither is present.
    """
    fm_match = re.search(
        r"^---\s*$(?P<body>.*?)^---\s*$", paste_text, re.MULTILINE | re.DOTALL
    )
    if fm_match:
        body = fm_match.group("body")
        title_match = re.search(r"^\s*title\s*:\s*(.+?)\s*$", body, re.MULTILINE | re.IGNORECASE)
        if title_match:
            return title_match.group(1).strip().strip('"').strip("'")
    h1_match = re.search(r"^#\s+(.+?)\s*$", paste_text, re.MULTILINE)
    if h1_match:
        return h1_match.group(1).strip()
    for line in paste_text.splitlines():
        s = line.strip()
        if s:
            return s
    return ""


def _impact_phrases_in(text: str) -> set[str]:
    """Return whole-phrase impact tokens present in text (case-insensitive)."""
    lower = text.lower()
    found: set[str] = set()
    for phrase in IMPACT_PHRASES:
        if phrase in lower:
            found.add(phrase)
    return found


def _flatten_not_proven(manifest: dict[str, Any]) -> list[str]:
    """Pull `not_proven_impacts` from any nesting level."""
    found: list[str] = []

    def _walk(node: Any) -> None:
        if isinstance(node, dict):
            for k, v in node.items():
                if k == "not_proven_impacts" and isinstance(v, list):
                    for item in v:
                        if isinstance(item, str):
                            found.append(item)
                else:
                    _walk(v)
        elif isinstance(node, list):
            for item in node:
                _walk(item)

    _walk(manifest)
    return found


def _flatten_proven(manifest: dict[str, Any]) -> list[dict[str, Any]]:
    """Pull `proven_impacts` from any nesting level. Each entry expected dict
    with ``poc_path`` + ``pass_evidence_lines`` (per L29-Filing schema)."""
    found: list[dict[str, Any]] = []

    def _walk(node: Any) -> None:
        if isinstance(node, dict):
            for k, v in node.items():
                if k == "proven_impacts" and isinstance(v, list):
                    for item in v:
                        if isinstance(item, dict):
                            found.append(item)
                else:
                    _walk(v)
        elif isinstance(node, list):
            for item in node:
                _walk(item)

    _walk(manifest)
    return found


def _flatten_cross_cited(manifest: dict[str, Any]) -> list[dict[str, Any]]:
    """Pull `cross_cited_proof_artifacts` arrays from any nesting level."""
    found: list[dict[str, Any]] = []

    def _walk(node: Any) -> None:
        if isinstance(node, dict):
            for k, v in node.items():
                if k == "cross_cited_proof_artifacts" and isinstance(v, list):
                    for item in v:
                        if isinstance(item, dict):
                            found.append(item)
                else:
                    _walk(v)
        elif isinstance(node, list):
            for item in node:
                _walk(item)

    _walk(manifest)
    return found


# --- Check A ---------------------------------------------------------------


def check_a_title_overlap(paste_path: Path) -> tuple[bool, str]:
    """Fail closed if title-claimed impact ∩ manifest.not_proven_impacts ≠ ∅."""
    if not paste_path.is_file():
        return False, f"paste-ready not found: {paste_path}"
    paste_text = _read_text(paste_path)
    title = _extract_title(paste_text)
    if not title:
        return True, "soft-skip: no title detectable in paste-ready"

    manifest, manifest_path = _load_manifest(paste_path)
    if manifest is None:
        return True, f"soft-skip: no sibling manifest for {paste_path.name}"

    not_proven = _flatten_not_proven(manifest)
    if not not_proven:
        # Per L29-Filing, `not_proven_impacts: []` is the "explicit empty" form
        # which is allowed; absence entirely is also allowed (soft-skip).
        return True, f"soft-skip: manifest has no not_proven_impacts list ({manifest_path.name})"

    title_phrases = _impact_phrases_in(title)
    if not title_phrases:
        return True, "title contains no rubric impact phrases — no overlap risk"

    overlapping: list[tuple[str, str]] = []
    for not_proven_entry in not_proven:
        np_phrases = _impact_phrases_in(not_proven_entry)
        for ph in title_phrases & np_phrases:
            overlapping.append((ph, not_proven_entry[:80]))

    if overlapping:
        bullets = "; ".join(f"'{ph}' (in not_proven: {snip}…)" for ph, snip in overlapping[:3])
        return False, (
            f"L29-Filing Check A FAILED: title impact phrases overlap "
            f"manifest.not_proven_impacts: {bullets}"
        )
    return True, "L29-Filing Check A passed: title does not overclaim"


# --- Check B ---------------------------------------------------------------


def _find_workspace_root(manifest_path: Path | None, paste_path: Path) -> Path:
    """Walk up from manifest/paste looking for a workspace root marker.

    Markers (any one): ``submissions/`` dir, ``.auditooor/`` dir, ``foundry.toml``,
    ``Cargo.toml``, ``go.mod``. Falls back to manifest's parent dir.
    """
    start = manifest_path.parent if manifest_path else paste_path.parent
    if start.name == ".auditooor":
        start = start.parent
    cur = start
    for _ in range(12):
        if cur == cur.parent:
            break
        for marker in (".auditooor", "submissions", "foundry.toml", "Cargo.toml", "go.mod"):
            if (cur / marker).exists():
                return cur
        cur = cur.parent
    return start


def _resolve_poc_path(raw: str, workspace_root: Path, paste_path: Path) -> Path | None:
    """Try multiple base directories to resolve a relative poc_path."""
    p = Path(raw)
    if p.is_absolute() and p.is_file():
        return p
    candidates: list[Path] = [
        workspace_root / raw,
        paste_path.parent / raw,
        # also try prefix-stripping common workspace-relative roots
    ]
    # If raw starts with "submissions/" but workspace_root doesn't have it,
    # also try stripping the leading dir component
    parts = Path(raw).parts
    if len(parts) > 1:
        candidates.append(workspace_root / Path(*parts[1:]))
    for c in candidates:
        try:
            if c.is_file():
                return c.resolve()
        except OSError:
            continue
    # last resort: rglob from workspace_root by basename (capped)
    base = Path(raw).name
    if base:
        try:
            hits = _rglob_sorted(workspace_root, base, 3)
            if hits:
                return hits[0]
        except OSError:
            pass
    return None


def check_b_proven_evidence(paste_path: Path) -> tuple[bool, str]:
    """Each proven_impact entry must have poc_path (existing file) + pass_evidence_lines."""
    manifest, manifest_path = _load_manifest(paste_path)
    if manifest is None:
        return True, f"soft-skip: no sibling manifest for {paste_path.name}"

    proven = _flatten_proven(manifest)
    if not proven:
        return True, "soft-skip: manifest has no proven_impacts list"

    workspace_root = _find_workspace_root(manifest_path, paste_path)

    failures: list[str] = []
    for idx, entry in enumerate(proven):
        label = entry.get("impact") or entry.get("name") or f"#{idx}"
        poc_path_raw = entry.get("poc_path")
        pass_lines = entry.get("pass_evidence_lines")
        # Check pass_evidence_lines presence first so the missing-evidence
        # failure is reported even when the poc_path resolves cleanly.
        missing_lines = (
            pass_lines is None
            or pass_lines == ""
            or (isinstance(pass_lines, list) and len(pass_lines) == 0)
        )
        if not poc_path_raw:
            failures.append(f"proven_impact[{label}] missing poc_path")
            continue
        # resolve poc_path against workspace_root and a few fallbacks
        resolved = _resolve_poc_path(poc_path_raw, workspace_root, paste_path)
        if resolved is None:
            failures.append(f"proven_impact[{label}] poc_path not found: {poc_path_raw}")
            continue
        if missing_lines:
            failures.append(f"proven_impact[{label}] missing pass_evidence_lines")
            continue

    if failures:
        return False, "L29-Filing Check B FAILED: " + "; ".join(failures[:5])
    return True, f"L29-Filing Check B passed: {len(proven)} proven_impact(s) verified"


# --- Check C ---------------------------------------------------------------
# Implemented in tools/paste_content_hash.py. This wrapper just delegates so that
# pre-submit-check.sh can call l29_filing_check.py for all four checks uniformly.


def check_c_record_hash(paste_path: Path) -> tuple[bool, str]:
    """Record SHA-256 of paste at pre-submit time (writes <paste>.hash)."""
    if not paste_path.is_file():
        return False, f"paste-ready not found: {paste_path}"
    digest = hashlib.sha256(paste_path.read_bytes()).hexdigest()
    hash_path = paste_path.with_suffix(paste_path.suffix + ".hash")
    hash_path.write_text(digest + "\n", encoding="utf-8")
    return True, f"L29-Filing Check C: recorded hash {digest[:12]}… → {hash_path.name}"


def check_c_verify_hash(paste_path: Path) -> tuple[bool, str]:
    """Verify recorded hash matches current paste content (filing-time gate)."""
    if not paste_path.is_file():
        return False, f"paste-ready not found: {paste_path}"
    hash_path = paste_path.with_suffix(paste_path.suffix + ".hash")
    if not hash_path.is_file():
        return False, (
            f"L29-Filing Check C FAILED: no recorded hash at {hash_path.name}; "
            "run pre-submit-check.sh first"
        )
    recorded = hash_path.read_text(encoding="utf-8").strip().split()[0]
    current = hashlib.sha256(paste_path.read_bytes()).hexdigest()
    if recorded != current:
        return False, (
            f"L29-Filing Check C FAILED: hash mismatch (recorded={recorded[:12]}… "
            f"current={current[:12]}…); paste was edited after pre-submit gate"
        )
    return True, f"L29-Filing Check C passed: hash verified ({current[:12]}…)"


# --- Check D ---------------------------------------------------------------

CROSS_CITE_RX = re.compile(
    r"\bcross[-\s]cit(?:e|es|ed|ing)\b", re.IGNORECASE
)
TEST_NAME_RX = re.compile(r"\btest_[A-Za-z0-9_]+")


def check_d_manifest_and_testnames(paste_path: Path) -> tuple[bool, str]:
    """Two-part Check D:

    (a) cross-cited PoC schema: if paste prose mentions cross-cit/cross cited/cross-cited,
        manifest MUST have `cross_cited_proof_artifacts` array with `path`, `test`,
        `primitive`, `shared_with` fields on every entry.
    (b) test-name resolver: every `test_<name>` reference in paste must match a
        ``function test_<name>`` in the cited file.
    """
    if not paste_path.is_file():
        return False, f"paste-ready not found: {paste_path}"
    paste_text = _read_text(paste_path)

    failures: list[str] = []

    # Part (a) — cross-cite schema check
    if CROSS_CITE_RX.search(paste_text):
        manifest, manifest_path = _load_manifest(paste_path)
        if manifest is None:
            failures.append(
                "paste prose mentions cross-citation but no sibling manifest found"
            )
        else:
            cross_cited = _flatten_cross_cited(manifest)
            if not cross_cited:
                failures.append(
                    "paste prose mentions cross-citation but manifest lacks "
                    "`cross_cited_proof_artifacts` array"
                )
            else:
                required_fields = {"path", "test", "primitive", "shared_with"}
                for idx, entry in enumerate(cross_cited):
                    missing = required_fields - set(entry.keys())
                    if missing:
                        failures.append(
                            f"cross_cited_proof_artifacts[{idx}] missing fields: "
                            f"{sorted(missing)}"
                        )

    # Part (b) — test-name resolver
    test_names = sorted(set(TEST_NAME_RX.findall(paste_text)))
    if test_names:
        # Find candidate test files referenced by the paste — any *.t.sol / *_test.go / *.rs / *.py
        # path appearing in the prose. Keep it simple: collect filenames cited and grep each.
        file_refs = re.findall(r"[A-Za-z0-9_/\-.]+\.(?:t\.sol|sol|rs|go|py)", paste_text)
        # Exclude FILE-STEM tokens from the test-name set: a token like
        # `test_foo` extracted from a cited file path `tests/test_foo.rs` (or a
        # cargo `--test test_foo` target selector) is a file/crate-target name,
        # NOT a test function name, and should not be resolved as one. This is a
        # generic false-RED fix (TEST_NAME_RX greedily matches file stems because
        # `\b...` stops at the `.`). Never-false-pass: it only DROPS path tokens
        # from the must-be-defined set, it never marks an undefined fn as defined.
        _stems = {Path(f).stem for f in file_refs}
        # also drop tokens that appear immediately before a cargo --test selector
        # or directly preceding a recognized file extension in the prose.
        _stems |= set(re.findall(r"--test\s+(test_[A-Za-z0-9_]+)", paste_text))
        _stems |= set(re.findall(r"\b(test_[A-Za-z0-9_]+)\.(?:t\.sol|sol|rs|go|py)\b", paste_text))
        test_names = [t for t in test_names if t not in _stems]
        # de-dup but preserve order
        seen: set[str] = set()
        unique_files: list[str] = []
        for f in file_refs:
            if f not in seen:
                seen.add(f)
                unique_files.append(f)

        # Resolve each file ref against workspace root
        manifest, manifest_path = _load_manifest(paste_path)
        if manifest_path:
            workspace_root = manifest_path.parent
            if workspace_root.name == ".auditooor":
                workspace_root = workspace_root.parent
        else:
            workspace_root = paste_path.parent

        # Aggregate function names defined in cited files
        defined: set[str] = set()
        files_checked = 0
        for fref in unique_files:
            # try direct relative + workspace_root + recursive search
            candidates = [
                workspace_root / fref,
                Path(fref) if Path(fref).is_absolute() else None,
            ]
            candidates = [c for c in candidates if c is not None]
            actual: Path | None = None
            for c in candidates:
                if c.is_file():
                    actual = c
                    break
            if actual is None:
                # try recursive find (cap at 5 hits)
                base = Path(fref).name
                hits = _rglob_sorted(workspace_root, base, 5)
                if hits:
                    actual = hits[0]
            if actual is not None and actual.is_file():
                files_checked += 1
                try:
                    body = actual.read_text(encoding="utf-8", errors="replace")
                except Exception:
                    continue
                for m in re.finditer(
                    r"\bfunction\s+(test_[A-Za-z0-9_]+)\s*\(", body
                ):
                    defined.add(m.group(1))
                # Go-style and Python-style detection
                for m in re.finditer(r"\bfunc\s+(Test[A-Za-z0-9_]+)\s*\(", body):
                    defined.add(m.group(1))
                for m in re.finditer(r"\bdef\s+(test_[A-Za-z0-9_]+)\s*\(", body):
                    defined.add(m.group(1))
                # Rust-style detection: `(async) fn <name>(` for test/poc functions
                # (tokio integration tests carry #[tokio::test] + `async fn poc_*`).
                for m in re.finditer(
                    r"\b(?:async\s+)?fn\s+((?:test|poc|prove|invariant)[A-Za-z0-9_]+)\s*\(",
                    body,
                ):
                    defined.add(m.group(1))

        if files_checked > 0:
            missing_tests = [t for t in test_names if t not in defined]
            # Workspace-wide fallback: a missing token that is a VERBATIM reference
            # to a real test defined elsewhere in the in-scope tree (e.g. an inlined
            # PoC body comment "mirrors test_cancel_withdraw2") is a legitimate
            # citation, not a fabricated one. The gate's purpose is to catch
            # NON-EXISTENT / hallucinated test names; a grep-findable real definition
            # satisfies that. Never-false-pass: only resolves tokens that map to an
            # actual `fn`/`func`/`def` test definition on disk.
            if missing_tests:
                still_missing: list[str] = []
                for tok in missing_tests:
                    pat = re.compile(
                        r"\b(?:async\s+)?(?:fn|func|def)\s+" + re.escape(tok) + r"\s*\(",
                    )
                    found = False
                    for ext in ("rs", "go", "py", "sol"):
                        for cand in _rglob_sorted(workspace_root, f"*.{ext}", 4000):
                            try:
                                if pat.search(
                                    cand.read_text(encoding="utf-8", errors="replace")
                                ):
                                    found = True
                                    break
                            except Exception:
                                continue
                        if found:
                            break
                    if not found:
                        still_missing.append(tok)
                missing_tests = still_missing
            if missing_tests:
                failures.append(
                    f"test-name references not found in cited files: "
                    f"{missing_tests[:3]} (defined names sampled: "
                    f"{sorted(defined)[:3]})"
                )

    if failures:
        return False, "L29-Filing Check D FAILED: " + "; ".join(failures[:3])
    return True, "L29-Filing Check D passed"


# --- CLI -------------------------------------------------------------------


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("paste", help="path to paste-ready markdown")
    parser.add_argument(
        "--check",
        choices=["A", "B", "C-record", "C-verify", "D", "all"],
        default="all",
        help="which L29-Filing check to run",
    )
    args = parser.parse_args(argv)

    paste_path = Path(args.paste).resolve()

    runners: list[tuple[str, Any]] = []
    if args.check in ("A", "all"):
        runners.append(("A", check_a_title_overlap))
    if args.check in ("B", "all"):
        runners.append(("B", check_b_proven_evidence))
    if args.check == "C-record" or (args.check == "all"):
        runners.append(("C-record", check_c_record_hash))
    if args.check == "C-verify":
        runners.append(("C-verify", check_c_verify_hash))
    if args.check in ("D", "all"):
        runners.append(("D", check_d_manifest_and_testnames))

    overall = 0
    for name, fn in runners:
        passed, message = fn(paste_path)
        status = "PASS" if passed else "FAIL"
        print(f"[L29-Filing {name}] {status}: {message}")
        if not passed:
            overall = 1
    return overall


if __name__ == "__main__":
    sys.exit(main())
