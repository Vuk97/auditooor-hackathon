#!/usr/bin/env python3
"""Canonical source-file extension registry - THE single source of truth.

WHY THIS EXISTS (Obyte 2026-07-09): ~40 tools each hardcoded their own
`.sol`/`.go`/`.rs` extension list (grep --include allowlists, ext->lang maps,
ext->granularity maps), and every one of them was BLIND to Oscript (Obyte
Autonomous Agents, `.oscript`/`.aa`). Symptom cluster on the Obyte engagement:
the enumerator emitted 382 AA units but hunt-sidecar-bridge matched 0, function-
coverage silently certified over 0 AA functions, coverage-map warn-PASSED
Solidity-only while 63% of scope was invisible, and r76-hallucination-guard
auto-downgraded every CONFIRMED Oscript finding to MAYBE because its grep never
scanned `.oscript`. Fixing each site one-by-one is whack-a-mole; the real fix is
ONE registry every tool imports, so adding a language is a single edit here.

Import this instead of hardcoding an extension list:

    from lib.source_extensions import (
        SOURCE_EXTS, EXT_TO_LANG, lang_of, is_source_file,
        grep_include_globs, is_llm_hunt_only,
    )
"""
from __future__ import annotations

import os

# ext (with leading dot, lowercase) -> canonical language name.
# ADD A NEW LANGUAGE HERE (one line) and every importing tool sees it.
EXT_TO_LANG: dict[str, str] = {
    ".sol": "solidity",
    ".vy": "vyper",
    ".rs": "rust",
    ".go": "go",
    ".ts": "typescript",
    ".js": "javascript",
    ".py": "python",
    ".oscript": "oscript",   # Obyte Autonomous Agents (JSON+formula DSL)
    ".aa": "oscript",        # Obyte AA alt extension (e.g. cascading-donations)
    ".cairo": "cairo",       # Starknet
    ".move": "move",         # Aptos / Sui
    ".circom": "circom",     # ZK circuits
    ".clar": "clarity",      # Stacks
    ".nr": "noir",           # Aztec / Noir
    ".zok": "zokrates",      # ZoKrates
}

# All recognized source extensions (with leading dot), stable order.
SOURCE_EXTS: tuple[str, ...] = tuple(EXT_TO_LANG.keys())

# Languages that HAVE a static-analysis / coverage-guided-fuzz engine in this
# repo (slither/medusa/echidna/dataflow-SSA arms). A finding/unit in one of
# these can be held to a mutation-verified / fuzz-campaign coverage bar.
ENGINE_LANGS: frozenset[str] = frozenset({"solidity", "vyper", "rust", "go"})

# Languages with NO static/fuzz engine here: they are LLM-hunt-only. Coverage /
# depth / invariant gates MUST credit an LLM hunt verdict for these instead of
# demanding a fuzz campaign or mutation-verified harness that cannot exist -
# otherwise the gate either silently-0-passes (false-green) or falsely-blocks.
LLM_HUNT_ONLY_LANGS: frozenset[str] = frozenset(
    set(EXT_TO_LANG.values()) - ENGINE_LANGS
)


def _norm_ext(ext: str) -> str:
    ext = (ext or "").strip().lower()
    if ext and not ext.startswith("."):
        ext = "." + ext
    return ext


def lang_of(path_or_ext: str) -> str | None:
    """Canonical language for a path OR a bare extension. None if unrecognized."""
    s = str(path_or_ext or "")
    ext = s if (s.startswith(".") and "/" not in s and "\\" not in s) else os.path.splitext(s)[1]
    return EXT_TO_LANG.get(_norm_ext(ext))


def is_source_file(path: str) -> bool:
    """True if path has a recognized source extension."""
    return lang_of(path) is not None


def is_llm_hunt_only(path_or_ext_or_lang: str) -> bool:
    """True if the language has NO static/fuzz engine (LLM-hunt-only) - so gates
    must credit LLM hunt verdicts rather than demand a fuzz/mutation campaign.
    Accepts a path, a bare extension, or a canonical language name."""
    s = str(path_or_ext_or_lang or "").strip().lower()
    if s in LLM_HUNT_ONLY_LANGS:
        return True
    if s in ENGINE_LANGS:
        return False
    lang = lang_of(s)
    return lang in LLM_HUNT_ONLY_LANGS if lang else False


def grep_include_globs(exts: tuple[str, ...] | None = None) -> list[str]:
    """`grep --include=*.<ext>` args for every recognized source extension."""
    return [f"--include=*{e}" for e in (exts or SOURCE_EXTS)]
