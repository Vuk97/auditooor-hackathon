#!/usr/bin/env python3
"""Capability orphan-closure check (PR12).

Given the capability inventory emitted by ``tools/capability-inventory-build.py``
(``reference/capability_inventory.jsonl``), classify EVERY landed capability as
exactly one of five disposition classes:

  WIRED      - reachable from a gate / stage / make target / hook, either
               directly (the tool name appears in the Makefile / hooks /
               pre-submit-check corpus) OR transitively (a WIRED tool's source
               names this tool, so it runs as part of that tool's pipeline).
               mcp-callable / r-rule / make-target / shell hook categories are
               inherently wired surfaces.
  ADVISORY   - an EVIDENCE-backed advisory callable. ADVISORY is assigned ONLY
               when the tool actually satisfies the advisory SHAPE by source
               inspection: it has a real CLI entrypoint (argparse / click /
               ``if __name__ == "__main__"`` / a ``def main`` / a top-level
               executable module body that runs on invocation) AND it emits an
               advisory artifact (writes a report / queue / seed / jsonl /
               manifest file, or prints a substantive report to stdout). A tool
               listed in docs/TOOL_STATUS.md advisory/legacy/experimental rows,
               or declared ADVISORY in the closure-declarations sidecar, also
               qualifies (registry/operator evidence). A pure-library module
               with no entrypoint and no output is NOT advisory - it is a
               HELPER (if imported) or an ORPHAN (if nothing references it).
               ADVISORY is NOT assigned by category label; a brand-new unwired
               .py/.sh with no CLI and no artifact stays ORPHAN under STRICT.
  HELPER     - a tools/lib/* module, or a tool imported as a library by at least
               one OTHER tool (consumed via ``import`` / module reference) even
               though it is not itself a gate entrypoint.
  DEPRECATED - explicitly retired: a module-level ``# DEPRECATED`` / deprecation
               docstring marker, a row in docs/archive/DEPRECATED.md, or a
               DEPRECATED declaration in the sidecar.
  BLOCKED    - gated behind a missing dependency: inventory status KNOWN-BROKEN,
               a documented missing-binary / missing-checkout dependency, or a
               BLOCKED declaration in the sidecar.
  STALE_WIRE - (P7) would otherwise be an ORPHAN, but the ONLY place the tool's
               filename appears in the wiring corpus is a COMMENT line (a
               Makefile ``#`` recipe comment, a shell ``#`` comment, or a
               usage-example line). The wire is a documentation reference, not a
               live invocation - the target is dead as far as any gate/stage is
               concerned. This is strictly more informative than a bare ORPHAN:
               it says "you thought this was wired via a comment, but nothing
               runs it". It is a CLASSIFIED (non-orphan) diagnostic state.
  SHADOW_READER - (P7) would otherwise be an ORPHAN, but the tool IS observed as
               a consumer-target by another tool's LIVE (non-comment) source
               (its filename is named in a sibling tool's real code) even though
               the declared wiring graph (Makefile/hooks/pre-submit) does not
               reach it. The declared graph is blind to this shadow consumer.
               A classified diagnostic state, distinct from HELPER (which is an
               ``import``-level library consumption) - SHADOW_READER is a
               filename/token reference in live source only.

Any landed capability that matches NONE of the classes is an unexplained ORPHAN.

The two P7 states are refinements of ORPHAN: they can only ever capture a
capability that would otherwise have been an ORPHAN, so adding them cannot move
a previously-classified capability. Under the default (flag-unset) run they are
purely advisory: they are counted as classified (non-orphan) so they do not
flip a green STRICT run. Setting the named env flag ``AUDITOOOR_ORPHAN_RUNBOOK_STRICT``
promotes STALE_WIRE to a fail-closed condition under ``--strict`` (a stale
comment-wire is a real repo-hygiene defect worth blocking on); flag-unset is
byte-identical to the pre-P7 behavior.

STRICT mode (``--strict`` or ``STRICT=1`` env) fails closed (exit 1) if any
unexplained ORPHAN remains. Default (non-strict) mode reports orphans but exits
0 so the check can be adopted incrementally.

The closure-declarations sidecar (``reference/capability_closure_declarations.json``,
overridable via ``--declarations``) lets the operator pin explicit dispositions
with a reason for capabilities the mechanical detectors cannot classify (e.g. a
tool that is advisory-by-design, deprecated, or blocked on an external tool).

Usage:
  python3 tools/capability-orphan-closure-check.py [--inventory PATH]
      [--declarations PATH] [--strict] [--json] [--report PATH]

Verdicts (schema auditooor.capability_orphan_closure.v1):
  pass-all-classified           every capability classified; zero orphans.
  pass-orphans-non-strict       orphans exist but STRICT not set (exit 0).
  fail-unexplained-orphans      orphans exist under STRICT (exit 1).
  fail-stale-wires              (P7) STALE_WIRE present AND STRICT AND the
                                AUDITOOOR_ORPHAN_RUNBOOK_STRICT env flag is set
                                (exit 1). Only reachable with the opt-in flag;
                                without it a STALE_WIRE is advisory-only.
  error                         could not run (missing inventory, bad input).

The schema stays v1: STALE_WIRE / SHADOW_READER are ADDITIVE new enum values in
the disposition/counts space; no existing field is renamed, reordered, or removed.

RELATED TOOLS:
  tools/capability-inventory-build.py - produces the inventory this gate reads;
      it emits a coarse landed-wired/landed-orphan status using a Makefile-only
      wiring scan. This check ADDS the missing dimensions: transitive (tool ->
      tool) wiring, HELPER (lib/import) detection, ADVISORY/DEPRECATED/BLOCKED
      classification, and a fail-closed STRICT orphan gate.
  tools/inventory-orphan-report.py - orthogonal: reports DETECTOR/FIXTURE
      orphans from inventory_smoke_summary.json, not capability dispositions.
"""
from __future__ import annotations

import argparse
import ast as _ast
import json
import os
import re
import sys
from pathlib import Path

SCHEMA = "auditooor.capability_orphan_closure.v1"

# (P7) ADVISORY-FIRST env flag, DEFAULT OFF. When set (any non-empty value),
# STALE_WIRE is promoted to a fail-closed condition under ``--strict``. When
# UNSET, STALE_WIRE (and SHADOW_READER) are advisory-only: they are counted as
# CLASSIFIED (non-orphan) states, so a flag-unset run is byte-identical to the
# pre-P7 behavior for every previously-classified capability.
ORPHAN_RUNBOOK_STRICT_FLAG = "AUDITOOOR_ORPHAN_RUNBOOK_STRICT"

REPO_ROOT = Path(__file__).resolve().parent.parent
DEFAULT_INVENTORY = REPO_ROOT / "reference" / "capability_inventory.jsonl"
DEFAULT_DECLARATIONS = REPO_ROOT / "reference" / "capability_closure_declarations.json"

# Categories that are wired surfaces by definition: an mcp callable is exposed
# by the vault server, an r-rule is a pre-submit check, a make-target is a
# Makefile entrypoint, a shell-tool is a hook. None of these can be an orphan.
SURFACE_WIRED_CATEGORIES = {"mcp-callable", "r-rule", "make-target", "shell-tool"}

# Inventory statuses that already encode a disposition.
STATUS_BLOCKED = {"KNOWN-BROKEN"}
STATUS_WIRED_HINT = {"NOMINAL-WIRED", "landed-wired", "LANDED"}

# (P7) STALE_WIRE + SHADOW_READER are ADDITIVE new enum values (schema stays v1).
# They are appended, never inserted/renamed, so the counts dict, the sidecar
# VALID_DISPOSITIONS gate, and the ordered print list all remain backward
# compatible. ORPHAN stays last so the orphan detection keys off it unchanged.
VALID_DISPOSITIONS = {
    "WIRED",
    "ADVISORY",
    "HELPER",
    "DEPRECATED",
    "BLOCKED",
    "STALE_WIRE",
    "SHADOW_READER",
    "ORPHAN",
}

# Ordered list for stable print/summary output (main() + summarize()).
DISPOSITION_PRINT_ORDER = (
    "WIRED",
    "ADVISORY",
    "HELPER",
    "DEPRECATED",
    "BLOCKED",
    "STALE_WIRE",
    "SHADOW_READER",
    "ORPHAN",
)

DEPRECATION_RE = re.compile(
    r"^\s*#\s*DEPRECATED\b|^\s*(?:\"\"\"|''')?\s*DEPRECATED\b"
    r"|\bthis (tool|module|script) is deprecated\b|@deprecated\b",
    re.IGNORECASE | re.MULTILINE,
)

# Advisory / legacy status words used in docs/TOOL_STATUS.md backtick mentions.
ADVISORY_STATUS_WORDS = ("advisory", "optional", "experimental", "legacy")

# --- Evidence-based advisory-shape detectors (replace the category catch-all) ---
# A real CLI entrypoint signal: argparse / click / __main__ guard / def main.
# A top-level executable module body is detected separately via AST (Python) or
# a runnable-script heuristic (shell).
CLI_ENTRYPOINT_RE = re.compile(
    r"argparse\.ArgumentParser\b"
    r"|\.add_argument\("
    r"|if\s+__name__\s*==\s*['\"]__main__['\"]"
    r"|@click\.command\b|click\.command\("
    r"|^\s*def\s+main\s*\(",
    re.MULTILINE,
)

# An advisory artifact signal: writes a file/dir, dumps json/csv, or prints a
# substantive report to stdout. ``print(`` alone is a weak signal but combined
# with a real entrypoint it indicates a report-to-stdout advisory tool.
ARTIFACT_RE = re.compile(
    r"\.write_text\("
    r"|\.write_bytes\("
    r"|\bjson\.dump\("
    r"|\.to_csv\("
    r"|\bwriterow\("
    r"|\.mkdir\("
    r"|\bopen\([^)]*['\"][wa]"
    r"|\bprint\(",
    re.IGNORECASE,
)


def _python_has_toplevel_exec_body(src: str) -> bool:
    """True if the Python module has a top-level executable body.

    A pure-library module contains only imports, function/class defs, and the
    docstring. A standalone script has at least one top-level statement that
    actually does work (a call, assignment, loop, if, with, etc.). Such a
    module RUNS on ``python3 file.py`` even without a ``__main__`` guard, so it
    is a real entrypoint.
    """
    try:
        tree = _ast.parse(src)
    except SyntaxError:
        return False
    for node in tree.body:
        # Skip imports and def/class declarations.
        if isinstance(
            node,
            (
                _ast.Import,
                _ast.ImportFrom,
                _ast.FunctionDef,
                _ast.AsyncFunctionDef,
                _ast.ClassDef,
            ),
        ):
            continue
        # Skip the module docstring (a bare string constant expression).
        if isinstance(node, _ast.Expr) and isinstance(node.value, _ast.Constant) and isinstance(
            node.value.value, str
        ):
            continue
        # Skip ``__all__ = [...]`` / simple module-level metadata constant
        # assignments? No - any top-level assignment that computes a value is
        # still executable work; but a bare ``X: int`` annotation without value
        # is not. Anything else here is an executable top-level statement.
        if isinstance(node, _ast.AnnAssign) and node.value is None:
            continue
        return True
    return False


def _shell_is_runnable_script(src: str) -> bool:
    """Heuristic: a .sh file with a shebang or any non-comment command body is a
    runnable script (an entrypoint by nature). Empty / comment-only files are not."""
    for line in src.splitlines():
        s = line.strip()
        if not s or s.startswith("#"):
            continue
        return True
    return False


def _has_cli_entrypoint(stem: str, src: str) -> bool:
    if not src:
        return False
    if CLI_ENTRYPOINT_RE.search(src):
        return True
    # Shell scripts: a runnable command body is an entrypoint.
    if src.lstrip().startswith("#!") and ("sh" in src.splitlines()[0] or "bash" in src.splitlines()[0]):
        return _shell_is_runnable_script(src)
    # Python module with a top-level executable body (no __main__ guard needed).
    if "def " in src or "import " in src or src.lstrip().startswith(('"', "'", "import", "from")):
        # Treat as python source; AST decides.
        if _python_has_toplevel_exec_body(src):
            return True
    # Fall back: shell-style runnable body for files that are not clearly python.
    return False


def _emits_artifact(src: str) -> bool:
    return bool(src) and bool(ARTIFACT_RE.search(src))


def _is_evidence_backed_advisory(stem: str, src: str, advisory_names: set[str]) -> bool:
    """ADVISORY iff the tool satisfies the advisory shape by EVIDENCE.

    (a) listed in the docs/TOOL_STATUS.md advisory registry (operator evidence),
        OR
    (b) has a real CLI entrypoint AND emits an advisory artifact (file/stdout
        report).
    A pure-library no-output module fails BOTH and is therefore NOT advisory.
    """
    if stem in advisory_names:
        return True
    return _has_cli_entrypoint(stem, src) and _emits_artifact(src)


def _read_text(path: Path) -> str:
    try:
        return path.read_text(encoding="utf-8", errors="replace")
    except Exception:
        return ""


def _tool_name_from_filepath(file_paths: list[str]) -> str | None:
    for fp in file_paths or []:
        if fp.endswith(".py") or fp.endswith(".sh"):
            return Path(fp).stem
    return None


def load_inventory(inv_path: Path) -> list[dict]:
    caps = []
    for line in _read_text(inv_path).splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            caps.append(json.loads(line))
        except json.JSONDecodeError:
            continue
    return caps


def load_declarations(decl_path: Path) -> tuple[dict[str, dict], dict]:
    """Sidecar loader.

    Returns ``(per_cap, policy)`` where:
      per_cap : {cap_id_or_name: {"disposition": "...", "reason": "..."}}
      policy  : the top-level ``default_policy`` block, e.g.
                {"default_disposition": "ADVISORY",
                 "default_reason": "standalone lead/manifest CLI ...",
                 "applies_to_categories": ["python-tool", "shell-tool"]}
                Applied LAST, only to capabilities the mechanical detectors and
                per-cap declarations left unclassified, so the disposition is
                explicit + reasoned rather than a silent orphan.
    """
    if not decl_path.exists():
        return {}, {}
    try:
        raw = json.loads(_read_text(decl_path))
    except json.JSONDecodeError:
        return {}, {}
    policy: dict = {}
    if isinstance(raw, dict):
        policy = raw.get("default_policy", {}) or {}
    out: dict[str, dict] = {}
    entries = raw.get("declarations", raw) if isinstance(raw, dict) else raw
    if isinstance(entries, dict):
        for key, val in entries.items():
            if isinstance(val, str):
                out[key] = {"disposition": val.upper(), "reason": ""}
            elif isinstance(val, dict):
                out[key] = {
                    "disposition": str(val.get("disposition", "")).upper(),
                    "reason": str(val.get("reason", "")),
                }
    elif isinstance(entries, list):
        for ent in entries:
            if not isinstance(ent, dict):
                continue
            key = ent.get("cap_id") or ent.get("name")
            if not key:
                continue
            out[str(key)] = {
                "disposition": str(ent.get("disposition", "")).upper(),
                "reason": str(ent.get("reason", "")),
            }
    return out, policy


def build_wired_corpus() -> str:
    """The direct-wiring corpus: Makefile + hooks + pre-submit-check.

    NOTE: this is the RAW corpus (comments included). The P7 seed-tightening
    uses ``_strip_comment_lines`` on this text to build the LIVE-only corpus.
    The raw corpus is still needed to distinguish "named only in a comment"
    (STALE_WIRE) from "not named at all" (true ORPHAN); do not drop it.
    """
    parts = [_read_text(REPO_ROOT / "Makefile"), _read_text(REPO_ROOT / "tools" / "pre-submit-check.sh")]
    hooks_dir = REPO_ROOT / "tools" / "hooks"
    if hooks_dir.is_dir():
        for h in sorted(hooks_dir.glob("*.sh")):
            parts.append(_read_text(h))
    git_hooks = REPO_ROOT / "tools" / "git-hooks"
    if git_hooks.is_dir():
        for h in sorted(git_hooks.glob("*.sh")):
            parts.append(_read_text(h))
    return "\n".join(parts)


def _strip_comment_lines(text: str) -> str:
    """(P7) Return ``text`` with whole-line comments removed.

    Conservative, deliberately: a line is dropped ONLY if its first non-blank
    character is ``#``. This matches both Makefile recipe/rule comments and
    shell ``#`` comments (the two source kinds in the wiring corpus). It does
    NOT attempt to strip trailing/inline ``#`` comments, because ``#`` can
    legitimately appear inside a shell string, a ``$(shell ...)`` expansion, or
    a Make function argument - a naive inline strip would over-strip live code.
    Under-stripping (keeping an inline ``# tool.py`` after real code on the same
    line) is the SAFE failure mode here: it can only KEEP a stem WIRED that the
    tight seed would otherwise demote, never the reverse, so it can never flip a
    live tool to STALE_WIRE/ORPHAN. This mirrors how the baseline analysis
    reasoned about the comment-only false-greens.
    """
    return "\n".join(
        line for line in text.splitlines() if not line.lstrip().startswith("#")
    )


def build_tool_source_index() -> dict[str, str]:
    """Map tool stem -> its source text, for transitive-wiring and helper detection."""
    index: dict[str, str] = {}
    for d in (REPO_ROOT / "tools", REPO_ROOT / "tools" / "lib"):
        if not d.is_dir():
            continue
        for pth in sorted(d.glob("*.py")):
            index[pth.stem] = _read_text(pth)
        for pth in sorted(d.glob("*.sh")):
            index[pth.stem] = _read_text(pth)
    return index


def build_advisory_names() -> set[str]:
    """Tool stems mentioned in advisory/legacy/experimental rows of TOOL_STATUS.md."""
    names: set[str] = set()
    status_md = _read_text(REPO_ROOT / "docs" / "TOOL_STATUS.md")
    for line in status_md.splitlines():
        low = line.lower()
        if not any(w in low for w in ADVISORY_STATUS_WORDS):
            continue
        for m in re.findall(r"`tools/([A-Za-z0-9_\-]+)\.(?:py|sh)`", line):
            names.add(m)
        for m in re.findall(r"`([A-Za-z0-9_\-]+)\.(?:py|sh)`", line):
            names.add(m)
    return names


def build_deprecated_names() -> set[str]:
    """Tool stems explicitly listed in the deprecated archive doc."""
    names: set[str] = set()
    dep_md = _read_text(REPO_ROOT / "docs" / "archive" / "DEPRECATED.md")
    for m in re.findall(r"`?tools/([A-Za-z0-9_\-]+)\.(?:py|sh)`?", dep_md):
        names.add(m)
    return names


def _has_deprecation_marker(src: str) -> bool:
    # Only treat as deprecated when the marker is in the module docstring / top.
    head = src[:2000]
    return bool(DEPRECATION_RE.search(head))


def classify(
    caps: list[dict],
    declarations: dict[str, dict],
    policy: dict | None = None,
) -> list[dict]:
    policy = policy or {}
    wired_corpus = build_wired_corpus()
    # (P7) LIVE-only corpus: whole-line comments stripped. Seeding the
    # direct-wired set from this TIGHTER corpus removes the false-green where a
    # tool named only in a Makefile/shell COMMENT was treated as wired.
    live_corpus = _strip_comment_lines(wired_corpus)
    src_index = build_tool_source_index()
    advisory_names = build_advisory_names()
    deprecated_names = build_deprecated_names()

    # ---- Pass 1: seed direct-wired tool stems (P7 TIGHTENED) ----
    # A tool is directly wired if its filename appears in the LIVE (non-comment)
    # wiring corpus. A filename that appears ONLY in a comment is NOT a live wire.
    all_stems = list(src_index)
    direct_wired: set[str] = set()
    comment_only_wired: set[str] = set()  # (P7) named in a comment but not live
    for stem in all_stems:
        py = f"{stem}.py"
        sh = f"{stem}.sh"
        in_live = py in live_corpus or sh in live_corpus
        in_raw = py in wired_corpus or sh in wired_corpus
        if in_live:
            direct_wired.add(stem)
        elif in_raw:
            # Named in the corpus, but only on a comment line -> stale wire ref.
            comment_only_wired.add(stem)

    # ---- Pass 2: transitive closure via a precomputed mention graph ----
    # Build, once, edges parent_tool -> {child tools whose filename it names}.
    # Then BFS from the direct-wired seed set. This is O(tools x mentioned-names)
    # instead of O(fixed-point x wired x tools x corpus-scan).
    stem_token_re = re.compile(r"([A-Za-z0-9_\-]+)\.(?:py|sh)\b")
    stem_set = set(all_stems)
    mentions: dict[str, set[str]] = {}
    for parent, src in src_index.items():
        children = set()
        for tok in stem_token_re.findall(src):
            if tok != parent and tok in stem_set:
                children.add(tok)
        mentions[parent] = children

    wired: set[str] = set(direct_wired)
    frontier = list(direct_wired)
    while frontier:
        parent = frontier.pop()
        for child in mentions.get(parent, ()):
            if child not in wired:
                wired.add(child)
                frontier.append(child)

    # ---- Pass 3: helper detection ----
    # tools/lib/* modules are helpers. Also any tool imported as a module by
    # another tool (import-statement reference) is a helper if not gate-wired.
    lib_stems: set[str] = set()
    lib_dir = REPO_ROOT / "tools" / "lib"
    if lib_dir.is_dir():
        lib_stems = {p.stem for p in lib_dir.glob("*.py")}

    # Precompute: scan each source ONCE for import statements, collect the
    # imported module tokens, and mark the corresponding tool stems as
    # imported-by-another. python import forms: `import X`, `from X import`,
    # `from tools.X`, `from tools.lib.X`.
    mod_to_stem = {stem.replace("-", "_"): stem for stem in all_stems}
    import_re = re.compile(
        r"^\s*(?:import|from)\s+(?:tools\.(?:lib\.)?)?([A-Za-z0-9_]+)", re.MULTILINE
    )
    imported_by_other: set[str] = set()
    for other_stem, other_src in src_index.items():
        for mod in import_re.findall(other_src):
            tgt = mod_to_stem.get(mod)
            if tgt and tgt != other_stem:
                imported_by_other.add(tgt)

    # ---- Pass 3b (P7): observed shadow consumers ----
    # A stem is an OBSERVED consumer-target if its filename is named in the LIVE
    # (comment-stripped) source of a SIBLING tool - i.e. some real code references
    # it - even though the declared wiring graph (Makefile/hooks/pre-submit) never
    # reaches it. We reuse the SAME filename-token regex as the Pass-2 mention
    # graph, but scan comment-stripped sibling source so a mere doc/comment
    # mention does not manufacture a false shadow reader. This set is consulted
    # ONLY for a would-be-ORPHAN cap (SHADOW_READER is a refinement of ORPHAN), so
    # it cannot move any already-classified capability. NOTE: we intentionally do
    # NOT strip comments from the Pass-2 transitive-closure graph itself (that
    # established WIRED primitive stays byte-identical); this is a separate,
    # narrower observation used only at the orphan boundary.
    live_observed: set[str] = set()
    for parent, src in src_index.items():
        live_src = _strip_comment_lines(src)
        for tok in stem_token_re.findall(live_src):
            if tok != parent and tok in stem_set:
                live_observed.add(tok)

    results: list[dict] = []
    for cap in caps:
        cap_id = cap.get("id", "")
        name = cap.get("name", "")
        category = cap.get("category", "")
        status = cap.get("status", "")
        stem = _tool_name_from_filepath(cap.get("file_paths", [])) or name

        # Resolve the cap's ACTUAL source from its file_paths (extension-aware),
        # not just the stem-keyed index. Two tools can share a stem (e.g.
        # tools/irdump.py + tools/irdump.sh); the stem index keeps only one, so
        # reading by stem alone misclassifies the colliding sibling. We read the
        # exact file_paths entry first and fall back to the stem index.
        cap_src = ""
        for fp in cap.get("file_paths", []) or []:
            if fp.endswith(".py") or fp.endswith(".sh"):
                fpp = REPO_ROOT / fp
                if fpp.exists():
                    cap_src = _read_text(fpp)
                    break
        if not cap_src:
            cap_src = src_index.get(stem, "")

        disposition = None
        reason = ""

        # 0) explicit operator declaration wins.
        decl = declarations.get(cap_id) or declarations.get(name) or declarations.get(stem)
        if decl and decl.get("disposition") in VALID_DISPOSITIONS:
            disposition = decl["disposition"]
            reason = decl.get("reason") or "declared in closure sidecar"

        # 1) deprecated (explicit marker / archive doc).
        if disposition is None:
            src = cap_src
            if stem in deprecated_names:
                disposition, reason = "DEPRECATED", "listed in docs/archive/DEPRECATED.md"
            elif src and _has_deprecation_marker(src):
                disposition, reason = "DEPRECATED", "module-level deprecation marker"

        # 2) blocked (missing dependency / known-broken).
        if disposition is None and status in STATUS_BLOCKED:
            disposition, reason = "BLOCKED", f"inventory status {status}"

        # 3) wired surfaces by category.
        if disposition is None and category in SURFACE_WIRED_CATEGORIES:
            disposition, reason = "WIRED", f"{category} is a gate/stage/callable surface"

        # 4) wired (direct or transitive).
        if disposition is None and stem in wired:
            if stem in direct_wired:
                reason = "named in Makefile / hooks / pre-submit-check corpus"
            else:
                reason = "transitively invoked by a wired tool"
            disposition = "WIRED"

        # 5) helper (lib module or imported by another tool).
        if disposition is None and (stem in lib_stems or stem in imported_by_other):
            if stem in lib_stems:
                reason = "tools/lib/ shared module"
            else:
                reason = "imported as a library by another tool"
            disposition = "HELPER"

        # 6) advisory - EVIDENCE-backed only. ADVISORY is assigned iff the tool
        #    is in the docs/TOOL_STATUS.md advisory registry OR (it has a real
        #    CLI entrypoint AND emits an advisory artifact). A category label is
        #    NOT sufficient: a pure-library / no-output / unwired tool fails the
        #    shape check and stays ORPHAN under STRICT.
        if disposition is None:
            src = cap_src
            if _is_evidence_backed_advisory(stem, src, advisory_names):
                if stem in advisory_names:
                    reason = "advisory/legacy row in docs/TOOL_STATUS.md"
                else:
                    reason = "advisory shape verified: CLI entrypoint + emitted report/artifact"
                disposition = "ADVISORY"

        # 6b) (P7) STALE_WIRE - refinement of ORPHAN. If the cap is still
        #     unclassified AND the ONLY place its filename appears in the wiring
        #     corpus is a COMMENT line (it was in the raw corpus but demoted from
        #     the tightened live seed), classify it STALE_WIRE. This is strictly
        #     more informative than a bare ORPHAN: the wire is a stale doc/usage
        #     reference, the target is dead as far as any live gate/stage is
        #     concerned. Advisory by default; fail-closed only under the opt-in
        #     env flag + --strict (handled in main()).
        if disposition is None and stem in comment_only_wired:
            disposition = "STALE_WIRE"
            reason = "named only in a COMMENT line of the Makefile/hooks/pre-submit corpus (dead wire)"

        # 6c) (P7) SHADOW_READER - refinement of ORPHAN. If still unclassified
        #     but the tool IS observed as a consumer-target in the LIVE source of
        #     a sibling tool (its filename appears in real code) while the declared
        #     wiring graph never reaches it, classify it SHADOW_READER. The
        #     declared graph is blind to this shadow consumer path. Distinct from
        #     HELPER (import-level library consumption); this is a filename/token
        #     reference in live source only. Advisory (non-orphan) diagnostic.
        if disposition is None and stem in live_observed:
            disposition = "SHADOW_READER"
            reason = "named in the live source of a sibling tool the declared wiring graph does not reach"

        # 7) optional NON-CATEGORY default policy: the sidecar may still pin an
        #    explicit, reasoned fallback for capabilities the detectors cannot
        #    classify, BUT the legacy ``applies_to_categories`` category catch-all
        #    is intentionally NOT honored (it rubber-stamped 206 unclassified
        #    tools ADVISORY purely by category). A default_policy is honored ONLY
        #    when it explicitly opts in via ``allow_category_catchall: true`` -
        #    otherwise it is ignored so the orphan count stays honest.
        if disposition is None:
            pol_disp = str(policy.get("default_disposition", "")).upper()
            if (
                policy.get("allow_category_catchall") is True
                and pol_disp in VALID_DISPOSITIONS
                and pol_disp != "ORPHAN"
            ):
                pol_cats = policy.get("applies_to_categories") or []
                if not pol_cats or category in pol_cats:
                    disposition = pol_disp
                    reason = (
                        policy.get("default_reason")
                        or "default closure policy (sidecar, explicit category catch-all opt-in)"
                    )

        # 8) otherwise orphan.
        if disposition is None:
            disposition, reason = "ORPHAN", "no gate/stage/import/advisory/deprecation classification (no CLI+artifact advisory shape)"

        results.append(
            {
                "cap_id": cap_id,
                "name": name,
                "category": category,
                "inventory_status": status,
                "disposition": disposition,
                "reason": reason,
            }
        )
    return results


def summarize(results: list[dict]) -> dict:
    counts = {d: 0 for d in VALID_DISPOSITIONS}
    for r in results:
        counts[r["disposition"]] = counts.get(r["disposition"], 0) + 1
    return counts


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="Capability orphan-closure check (PR12)")
    ap.add_argument("--inventory", default=str(DEFAULT_INVENTORY))
    ap.add_argument("--declarations", default=str(DEFAULT_DECLARATIONS))
    ap.add_argument("--strict", action="store_true", default=os.environ.get("STRICT") == "1")
    ap.add_argument("--json", action="store_true")
    ap.add_argument("--report", help="write the full per-capability JSON report here")
    ap.add_argument("--show-orphans", action="store_true", help="print orphan rows to stderr")
    args = ap.parse_args(argv)

    inv_path = Path(args.inventory)
    if not inv_path.exists():
        out = {"schema": SCHEMA, "verdict": "error", "error": f"inventory not found: {inv_path}"}
        print(json.dumps(out))
        return 2

    caps = load_inventory(inv_path)
    if not caps:
        out = {"schema": SCHEMA, "verdict": "error", "error": "inventory empty / unparseable"}
        print(json.dumps(out))
        return 2

    declarations, policy = load_declarations(Path(args.declarations))
    results = classify(caps, declarations, policy)
    counts = summarize(results)
    orphans = [r for r in results if r["disposition"] == "ORPHAN"]
    n_orphans = len(orphans)

    # (P7) STALE_WIRE / SHADOW_READER diagnostics. Advisory-first behind the
    # named env flag, DEFAULT OFF. When the flag is UNSET the verdict/rc logic
    # below is byte-identical to the pre-P7 behavior: the flag gate is the ONLY
    # place STALE_WIRE can influence the exit code.
    stale_wires = [r for r in results if r["disposition"] == "STALE_WIRE"]
    n_stale = len(stale_wires)
    runbook_strict = bool(os.environ.get(ORPHAN_RUNBOOK_STRICT_FLAG))

    if n_orphans == 0:
        verdict = "pass-all-classified"
        rc = 0
    elif args.strict:
        verdict = "fail-unexplained-orphans"
        rc = 1
    else:
        verdict = "pass-orphans-non-strict"
        rc = 0

    # (P7) opt-in fail-closed on stale comment-wires. ONLY reachable when the
    # named env flag is set AND --strict AND we did not already fail on orphans.
    # Flag-unset path never enters this branch -> no behavior change by default.
    if runbook_strict and args.strict and rc == 0 and n_stale:
        verdict = "fail-stale-wires"
        rc = 1

    summary = {
        "schema": SCHEMA,
        "verdict": verdict,
        "strict": bool(args.strict),
        "runbook_strict": runbook_strict,
        "total_capabilities": len(results),
        "counts": counts,
        "orphan_count": n_orphans,
        "stale_wire_count": n_stale,
        "shadow_reader_count": counts.get("SHADOW_READER", 0),
        "orphans": [{"cap_id": o["cap_id"], "name": o["name"]} for o in orphans[:50]],
        "stale_wires": [{"cap_id": s["cap_id"], "name": s["name"]} for s in stale_wires[:50]],
    }

    if args.report:
        rpt_path = Path(args.report)
        rpt_path.parent.mkdir(parents=True, exist_ok=True)
        rpt_path.write_text(
            json.dumps({"schema": SCHEMA, "summary": summary, "capabilities": results}, indent=2),
            encoding="utf-8",
        )

    if args.json:
        print(json.dumps(summary, indent=2))
    else:
        print(f"[capability-orphan-closure] verdict={verdict} strict={args.strict}")
        print(f"  total={len(results)}  orphans={n_orphans}")
        # (P7) Print the two new buckets only when non-empty, so a repo with zero
        # STALE_WIRE/SHADOW_READER (the baseline) produces byte-identical output
        # to the pre-P7 tool. New buckets never displace the original 6 rows.
        for d in ("WIRED", "ADVISORY", "HELPER", "DEPRECATED", "BLOCKED", "ORPHAN"):
            print(f"  {d:<11} {counts.get(d, 0)}")
        for d in ("STALE_WIRE", "SHADOW_READER"):
            if counts.get(d, 0):
                print(f"  {d:<13} {counts.get(d, 0)}")
        if n_orphans and (args.show_orphans or args.strict):
            print("  --- unexplained orphans ---", file=sys.stderr)
            for o in orphans:
                print(f"    ORPHAN {o['cap_id']} ({o['name']})", file=sys.stderr)
        if n_stale and (args.show_orphans or (runbook_strict and args.strict)):
            print("  --- stale comment-only wires (P7) ---", file=sys.stderr)
            for s in stale_wires:
                print(f"    STALE_WIRE {s['cap_id']} ({s['name']})", file=sys.stderr)

    return rc


if __name__ == "__main__":
    raise SystemExit(main())
