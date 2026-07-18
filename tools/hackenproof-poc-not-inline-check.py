#!/usr/bin/env python3
# r36-rebuttal: lane TASK-B-HP-POC-NOT-INLINE registered in .auditooor/agent_pathspec.json
"""
hackenproof-poc-not-inline-check.py
Rule 37 emit tier: tool utility (no corpus record emitted)

Gate: a HackenProof .hackenproof-plain.txt submission MUST NOT inline the
full PoC harness source. On HackenProof the PoC code + transcript live in the
ATTACHED <slug>-poc.zip; the .txt PoC section is a CONCISE description that
REFERENCES the attachment.

This catches the failure mode where tools/hackenproof-plain-export.py (or a
hand-edited .txt) leaves the entire Rust/Solidity harness inlined - which both
duplicates the zip content and blows the HackenProof 10000-char section limit.

HACKENPROOF-ONLY: Cantina / Immunefi markdown drafts KEEP inline PoC (the
"never pointer-only" rule). This gate fires only for *.hackenproof-plain.txt.

RELATED TOOLS:
  - tools/hackenproof-plain-export.py: produces the .hackenproof-plain.txt and
    (with --platform hackenproof) summarizes inline PoC source into a zip
    reference. This gate is the independent VERIFIER that a produced/edited .txt
    did not re-inline the harness. The two compose: export transforms, this gate
    enforces.

Usage:
  python3 tools/hackenproof-poc-not-inline-check.py <draft-dir-or-txt> [--json]

Argument:
  - a path to a *.hackenproof-plain.txt file, OR
  - a per-finding folder (the .txt is auto-resolved as <folder>/<slug>.hackenproof-plain.txt
    or the single *.hackenproof-plain.txt inside it).

Verdicts:
  pass-not-hackenproof   : path is not a *.hackenproof-plain.txt (gate N/A)
  pass-no-poc-source     : no inlined PoC source block detected and no over-limit section
  pass-poc-in-zip        : PoC section references the -poc.zip AND the zip contains harness+transcript
  fail-poc-inlined       : a code fence > 25 lines that looks like full PoC source is inlined
  fail-section-over-limit: a section > 10000 chars caused by inlined code
  fail-zip-missing-file  : the .txt references the -poc.zip but a referenced harness/transcript file is absent
  error                  : file not found / unreadable

Exit codes:
  0 = pass-* ; 1 = fail-* ; 2 = error
"""

import argparse
import json
import os
import re
import sys
import zipfile

SCHEMA = "auditooor.hackenproof_poc_not_inline_check.v1"

SECTION_LIMIT = 10000
# A fenced block this many lines or longer is "large" for the source-inline test.
LARGE_FENCE_LINES = 25

# Markers that make a fenced block look like FULL PoC SOURCE (not a transcript).
_SOURCE_MARKERS = [
    r"(?m)^\s*#\[test\]",                       # Rust test attribute
    r"(?m)^\s*#\[cfg\(test\)\]",                # Rust test module
    r"\bfn\s+\w+\s*\(",                         # Rust/other fn definition
    r"\bcontract\s+\w+",                        # Solidity contract
    r"\binterface\s+\w+",                       # Solidity interface
    r"\blibrary\s+\w+",                         # Solidity library
    r"\bpragma\s+solidity",                     # Solidity pragma
    r"\bfunction\s+\w+\s*\(",                   # Solidity function
    r"\bassert_eq!|\bassert!|\bassert\(",       # assertions
    r"\bimpl\s+\w+",                            # Rust impl
    r"\bstruct\s+\w+\s*\{",                     # struct decl
]

# Markers that make a fenced block look like a TRANSCRIPT / invocation (allowed).
_TRANSCRIPT_MARKERS = [
    r"(?m)^\s*\$ ",
    r"(?m)^\s*(cargo|forge|cast|anvil|npm|pnpm|yarn|python|pytest|go test|curl|wget|make)\b",
    r"\brunning \d+ tests?\b",
    r"\btest result:\b",
    r"\bSuite result:\b",
    r"(?m)^\s*ok\b",
    r"\bPASS\b",
]

# Phrases that indicate the PoC section references the attached zip.
_ZIP_REFERENCE_RE = re.compile(
    r"\b[\w./-]*-poc\.zip\b|\battached\b[^\n]*\bzip\b|\bsee\b[^\n]*\.zip\b",
    re.IGNORECASE,
)

# Harness / transcript file extensions we expect inside the zip.
_HARNESS_EXT = (".rs", ".sol", ".go", ".move", ".cairo", ".vy", ".py", ".ts", ".js")
_RUN_SCRIPT_RE = re.compile(r"\b\w+\.sh\b", re.IGNORECASE)
_TRANSCRIPT_FILE_RE = re.compile(
    r"\b[\w./-]*(transcript|poc-transcript)[\w./-]*\.(txt|log)\b", re.IGNORECASE
)


# ---------------------------------------------------------------------------
# Path resolution
# ---------------------------------------------------------------------------

def _is_hackenproof_txt(path: str) -> bool:
    return path.endswith(".hackenproof-plain.txt")


def _resolve_txt(path: str):
    """Resolve a path to a *.hackenproof-plain.txt file, or return None."""
    if os.path.isfile(path):
        return path if _is_hackenproof_txt(path) else None
    if os.path.isdir(path):
        # Prefer <dir>/<dirname>.hackenproof-plain.txt
        slug = os.path.basename(os.path.normpath(path))
        cand = os.path.join(path, f"{slug}.hackenproof-plain.txt")
        if os.path.isfile(cand):
            return cand
        # Fall back to a single *.hackenproof-plain.txt in the folder
        matches = [
            os.path.join(path, f)
            for f in os.listdir(path)
            if f.endswith(".hackenproof-plain.txt")
        ]
        if len(matches) == 1:
            return matches[0]
    return None


def _resolve_zip(txt_path: str, referenced_names):
    """Find the -poc.zip beside the .txt (or matching a referenced name)."""
    folder = os.path.dirname(os.path.abspath(txt_path))
    if not os.path.isdir(folder):
        return None
    # First, any explicitly referenced *.zip basename that exists beside the .txt
    for name in referenced_names:
        cand = os.path.join(folder, os.path.basename(name))
        if os.path.isfile(cand):
            return cand
    # Otherwise the single *-poc.zip beside the .txt
    zips = [
        os.path.join(folder, f)
        for f in os.listdir(folder)
        if f.endswith(".zip")
    ]
    if zips:
        # Prefer a -poc.zip
        poc = [z for z in zips if z.endswith("-poc.zip")]
        return (poc or zips)[0]
    return None


# ---------------------------------------------------------------------------
# Parsing
# ---------------------------------------------------------------------------

def _split_sections(text: str):
    """Split the 4-section HackenProof .txt into (heading, body, char_count)
    by the canonical 'N. Heading' lines."""
    header_re = re.compile(r"(?m)^([1-4])\.\s+(.+?)\s*$")
    matches = list(header_re.finditer(text))
    sections = []
    for i, m in enumerate(matches):
        start = m.end()
        end = matches[i + 1].start() if i + 1 < len(matches) else len(text)
        body = text[start:end]
        sections.append((m.group(2).strip(), body, len(body)))
    return sections


def _extract_fences(text: str):
    """Return list of (lang, body, line_count) for every fenced code block."""
    fences = []
    fence_re = re.compile(r"(?ms)^(```|~~~)([^\n]*)\n(.*?)\n\1\s*$")
    for m in fence_re.finditer(text):
        lang = m.group(2).strip()
        body = m.group(3)
        fences.append((lang, body, body.count("\n") + 1))
    return fences


def _looks_like_full_poc_source(lang: str, body: str) -> bool:
    """A block is full PoC source if it has source markers and is NOT a transcript."""
    lang_l = (lang or "").strip().lower()
    transcript_langs = {"bash", "sh", "shell", "console", "text", "txt", "log"}
    if lang_l in transcript_langs:
        return False
    transcript_like = any(re.search(p, body, re.IGNORECASE) for p in _TRANSCRIPT_MARKERS)
    source_like = any(re.search(p, body) for p in _SOURCE_MARKERS)
    # Source-like AND not transcript-like => full PoC source.
    return source_like and not transcript_like


def _referenced_zip_names(text: str):
    names = set()
    for m in re.finditer(r"\b([\w./-]+\.zip)\b", text, re.IGNORECASE):
        names.add(m.group(1))
    return names


# Filename token, optionally followed by a :line (or :line-line) source-citation suffix.
_HARNESS_NAME_RE = re.compile(
    # The trailing (?![\w]) boundary stops a harness extension matching as a
    # prefix of a longer extension (e.g. `.js` truncating `bridge_invariant.json`
    # to `bridge_invariant.js`, producing a phantom missing-attachment).
    r"(?<![\w/.-])([\w.-]+\.(rs|sol|go|move|cairo|vy|py|ts|js|sh))(?![\w])(:\d+(?:-\d+)?)?",
    re.IGNORECASE,
)

# Attachment-reference contexts: the "(...)" parenthetical right after a zip reference
# (e.g. "see attached <slug>-poc.zip (poc.rs, run.sh, transcript.txt)") and the
# "Supporting files / PoC" section listing. Only filenames in these contexts are
# treated as attachments that must exist in the zip.
_ATTACHMENT_PARENS_RE = re.compile(
    r"(?:attached|see)\b[^\n(]*\.zip[^\n(]*\(([^)]*)\)",
    re.IGNORECASE,
)
_SUPPORTING_FILES_RE = re.compile(
    r"(?ms)^\s*(?:#+\s*)?(?:\d+\.\s*)?Supporting files(?:\s*/\s*PoC)?\b(.*?)(?:\n\s*(?:#+\s*)?\d+\.\s|\Z)",
    re.IGNORECASE,
)


def _names_in(blob: str):
    out = set()
    for m in _HARNESS_NAME_RE.finditer(blob):
        name = m.group(1)
        if m.group(3):          # carries a :line suffix -> source citation, not attachment
            continue
        if "/" in name:         # path-prefixed -> in-tree source path, not attachment
            continue
        out.add(name)
    return out


# r36-rebuttal: lane TASK-D-HP-OPTIMISM-REGEN declared in .auditooor/agent_pathspec.json via tools/agent-pathspec-register.py
def _referenced_harness_files(text: str):
    """Harness/transcript file names presented as ATTACHMENT references in the .txt
    (e.g. poc.rs, run.sh inside a "see attached <zip> (...)" parenthetical, or in the
    "Supporting files / PoC" listing).

    A HackenProof PoC section legitimately also carries inline SOURCE CITATIONS like
    `lib.rs:185-209`, `request.rs:87`, `modules/ismp/.../consensus.rs`, bare prose
    mentions ("consensus.rs stores the forged commitment"), and transcript lines
    ("Running poc_x.rs") - none of those are attachment files that must live in the
    -poc.zip. We must not demand they be in the zip. Required-in-zip filenames are
    therefore collected ONLY from explicit attachment-reference contexts:
      - the "(...)" parenthetical immediately following a zip reference, and
      - the "Supporting files / PoC" section listing.
    Within those contexts, tokens with a `:<line>` suffix or a directory-path prefix
    are still treated as source citations (not attachments) and excluded.
    """
    files = set()
    for m in _ATTACHMENT_PARENS_RE.finditer(text):
        files |= _names_in(m.group(1))
    sf = _SUPPORTING_FILES_RE.search(text)
    if sf:
        files |= _names_in(sf.group(1))
    return files


# ---------------------------------------------------------------------------
# Core check
# ---------------------------------------------------------------------------

def check(path: str) -> dict:
    txt_path = _resolve_txt(path)
    if txt_path is None:
        return {
            "schema": SCHEMA,
            "path": path,
            "verdict": "pass-not-hackenproof",
            "ok": True,
            "detail": "not a *.hackenproof-plain.txt (gate N/A)",
        }

    try:
        with open(txt_path, "r", encoding="utf-8") as f:
            text = f.read()
    except OSError as exc:
        return {
            "schema": SCHEMA,
            "path": txt_path,
            "verdict": "error",
            "ok": False,
            "detail": f"unreadable: {exc}",
        }

    fences = _extract_fences(text)
    sections = _split_sections(text)

    # 1. Inlined full PoC source in a large fence -> hard fail.
    inlined = [
        (lang, lines)
        for (lang, body, lines) in fences
        if lines > LARGE_FENCE_LINES and _looks_like_full_poc_source(lang, body)
    ]
    if inlined:
        worst = max(inlined, key=lambda t: t[1])
        return {
            "schema": SCHEMA,
            "path": txt_path,
            "verdict": "fail-poc-inlined",
            "ok": False,
            "detail": (
                f"inlined PoC source fence ({worst[1]} lines, lang='{worst[0] or 'unlabeled'}') "
                f"exceeds {LARGE_FENCE_LINES}-line threshold; "
                f"move the harness into the attached -poc.zip and reference it"
            ),
            "inlined_fences": [{"lang": l, "lines": n} for (l, n) in inlined],
        }

    # 2. A section over the limit caused by an inlined (non-transcript) code block.
    over = [(h, c) for (h, body, c) in sections if c > SECTION_LIMIT]
    if over:
        # Attribute to inlined code only if some large source-ish fence exists.
        big_code = any(
            lines > LARGE_FENCE_LINES and (lang or "").strip().lower()
            not in {"bash", "sh", "shell", "console", "text", "txt", "log"}
            for (lang, body, lines) in fences
        )
        if big_code:
            h, c = max(over, key=lambda t: t[1])
            return {
                "schema": SCHEMA,
                "path": txt_path,
                "verdict": "fail-section-over-limit",
                "ok": False,
                "detail": (
                    f"section '{h}' is {c} chars (> {SECTION_LIMIT}) due to inlined code; "
                    f"move the harness into the -poc.zip"
                ),
                "over_limit_sections": [{"heading": h2, "chars": c2} for (h2, c2) in over],
            }

    # 3. Does the .txt reference the -poc.zip? If so, verify zip content.
    has_zip_ref = bool(_ZIP_REFERENCE_RE.search(text))
    if has_zip_ref:
        zip_names = _referenced_zip_names(text)
        zip_path = _resolve_zip(txt_path, zip_names)
        if zip_path and os.path.isfile(zip_path):
            try:
                with zipfile.ZipFile(zip_path) as zf:
                    members = zf.namelist()
            except zipfile.BadZipFile:
                members = []
            base_members = [os.path.basename(m) for m in members]
            has_harness = any(m.lower().endswith(_HARNESS_EXT) for m in base_members)
            has_transcript = any(
                _TRANSCRIPT_FILE_RE.search(m) for m in base_members
            ) or any(
                _RUN_SCRIPT_RE.search(m) for m in base_members
            )
            # Any harness/script file explicitly named in the .txt must exist in the zip.
            referenced_files = _referenced_harness_files(text)
            missing = sorted(
                fn for fn in referenced_files
                if (fn.lower().endswith(_HARNESS_EXT) or fn.lower().endswith(".sh"))
                and fn not in base_members
            )
            if missing:
                return {
                    "schema": SCHEMA,
                    "path": txt_path,
                    "verdict": "fail-zip-missing-file",
                    "ok": False,
                    "detail": (
                        f"the .txt references {missing} but they are absent from "
                        f"{os.path.basename(zip_path)} (members: {base_members})"
                    ),
                    "zip": os.path.basename(zip_path),
                    "zip_members": base_members,
                    "missing": missing,
                }
            if has_harness:
                return {
                    "schema": SCHEMA,
                    "path": txt_path,
                    "verdict": "pass-poc-in-zip",
                    "ok": True,
                    "detail": (
                        f"PoC section references {os.path.basename(zip_path)} which contains "
                        f"the harness"
                        + (" + transcript" if has_transcript else "")
                    ),
                    "zip": os.path.basename(zip_path),
                    "zip_members": base_members,
                }
            # Zip exists but no harness inside -> treat as missing-file failure.
            return {
                "schema": SCHEMA,
                "path": txt_path,
                "verdict": "fail-zip-missing-file",
                "ok": False,
                "detail": (
                    f"{os.path.basename(zip_path)} contains no harness source "
                    f"({base_members}); attach the runnable PoC"
                ),
                "zip": os.path.basename(zip_path),
                "zip_members": base_members,
            }
        # Referenced a zip but it is not present beside the .txt.
        return {
            "schema": SCHEMA,
            "path": txt_path,
            "verdict": "fail-zip-missing-file",
            "ok": False,
            "detail": (
                "PoC section references a -poc.zip but no matching zip was found "
                f"beside {os.path.basename(txt_path)}"
            ),
            "zip": None,
        }

    # 4. No inlined source, no over-limit, no zip reference -> nothing to flag.
    return {
        "schema": SCHEMA,
        "path": txt_path,
        "verdict": "pass-no-poc-source",
        "ok": True,
        "detail": "no inlined PoC source block and no over-limit section detected",
    }


def _exit_code(verdict: str) -> int:
    if verdict == "error":
        return 2
    return 0 if verdict.startswith("pass-") else 1


def main():
    parser = argparse.ArgumentParser(
        description="Gate: HackenProof .hackenproof-plain.txt must not inline the full PoC harness."
    )
    parser.add_argument("path", help="Path to a *.hackenproof-plain.txt or its per-finding folder.")
    parser.add_argument("--json", action="store_true", dest="emit_json",
                        help="Emit the result as JSON.")
    args = parser.parse_args()

    result = check(args.path)
    if args.emit_json:
        print(json.dumps(result, indent=2))
    else:
        tag = "PASS" if result["ok"] else ("ERROR" if result["verdict"] == "error" else "FAIL")
        print(f"[{tag}] {result['verdict']}: {result['detail']}")
    sys.exit(_exit_code(result["verdict"]))


if __name__ == "__main__":
    main()
