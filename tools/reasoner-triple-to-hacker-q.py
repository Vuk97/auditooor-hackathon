#!/usr/bin/env python3
# <!-- gap55-rebuttal: generic capability fix, operator-authorized -->
"""reasoner-triple-to-hacker-q.py - lift each pre-hunt LOGIC REASONER's docstring
LOGIC TRIPLE / REASONING QUERY into the flat hacker-question library as an OPEN
question, so the corpus-driven hunt (tools/corpus-driven-hunt.py) and the per-fn
briefs can steer on the SAME reasoned obligation the reasoner emits - not just on
mined incident case-studies.

WHY THIS EXISTS
  tools/logic-obligation-resolution-check.py::_REASONER_LEDGERS is the single
  source of truth for the ~40 pre-hunt reasoners (callgraph-set-difference,
  oracle-spot-price-manipulation, crosschain-message-authenticity, the go/rust/zk
  language reasoners, the novelty engines, ...). Each reasoner's module docstring
  carries the LOGIC TRIPLE (ASSUMPTION / INVARIANT / TRUST-BOUNDARY / FINDING) or a
  REASONING QUERY that encodes the reasoned attack it hunts. That reasoning was
  reachable ONLY by reading the tool source; it never fed the flat hacker-question
  corpus (audit/corpus_tags/derived/hacker_questions_library.jsonl) that
  corpus-driven-hunt.py / routing-integrity-check.py / mimo-per-file-batch-gen.py
  consume. This tool bridges that gap: one library row per reasoner, phrased as an
  OPEN question, tagged ``source=reasoner-triple:<name>``.

MECHANICS (append-only, dedup-safe)
  1. Parse ``_REASONER_LEDGERS`` from logic-obligation-resolution-check.py (AST, no
     import) -> (ledger_filename, reasoner_tool, language) rows.
  2. For each reasoner tool, read its module docstring, split into sections, and
     extract the LOGIC TRIPLE / REASONING QUERY (ASSUMPTION / INVARIANT / requires
     / FINDING sub-clauses, or the query block, or a summary fallback).
  3. Render an OPEN question and build a library row whose ``target_languages`` are
     resolved through tools/lib/per_function_target_patterns.py so the row can
     never trip routing-integrity-check.py (stored languages always cover the
     natives the anchor/question imply).
  4. APPEND only the rows whose ``source`` (or ``question_id``) is not already in
     the library. Existing rows are never rewritten (append-only).

CLI:
  python3 tools/reasoner-triple-to-hacker-q.py [--library PATH] [--check-path PATH]
      [--tools-dir DIR] [--dry-run] [--json]
Exit: 0 = ran (rows appended or already-present); 2 = usage / IO error.
"""
from __future__ import annotations

import argparse
import ast
import importlib.util
import json
import re
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
DEFAULT_CHECK = REPO / "tools" / "logic-obligation-resolution-check.py"
DEFAULT_TOOLS = REPO / "tools"
DEFAULT_LIBRARY = (
    REPO / "audit" / "corpus_tags" / "derived" / "hacker_questions_library.jsonl"
)

SOURCE_PREFIX = "reasoner-triple:"
VERIFICATION_TIER = "tier-1-reasoner-derived"

# Ledger language tag -> seed target_languages. `resolve_target_languages` unions
# these with the natives the anchor/question imply, so the row never mis-routes.
_LANG_SEED = {
    "go": ["go"],
    "rust": ["rust"],
    "sol": ["solidity"],
    "both": ["solidity", "go"],
    "zk": ["circom"],
    "any": ["solidity", "vyper", "rust", "go", "move", "cairo", "circom"],
}

# Section-heading tokens, in extraction priority order.
_TRIPLE_HEADINGS = (
    "THE LOGIC TRIPLE", "LOGIC TRIPLE", "THE REASONING QUERY", "REASONING QUERY",
    "THE INVARIANT", "THE SET RELATION", "THE INVARIANT VIOLATED",
)
# Secondary fallback headings (descriptive-body sections) when no triple heading
# is present, preferred over the pre-heading filename blurb.
_FALLBACK_HEADINGS = (
    "WHAT IT DOES", "WHAT THIS DOES", "THE QUERY", "THE LOGIC", "OVERVIEW",
    "SUMMARY", "THE CLASS", "PATTERN",
)
# Sub-field labels inside a chosen block. Case-SENSITIVE + line-anchored so a
# lowercase 'invariant'/'finding' inside an identifier or prose sentence (e.g. the
# tool name 'protocol-invariant-synth...') never false-matches as a label.
_ASSUMPTION_RE = re.compile(r"(?m)^[ \t]*ASSUMPTION\b")
_INVARIANT_RE = re.compile(r"(?m)^[ \t]*INVARIANT\b")
_FINDING_LABEL_RE = re.compile(r"(?m)^[ \t]*(?:TRUST[-\s]?BOUNDARY|THE FINDING|FINDING)\b")
# Inline uppercase result markers (used only when no line-anchored FINDING label).
_FINDING_INLINE_RE = re.compile(r"\bSET[-\s]?DIFFERENCE\b|\bSURVIVORS?\b")
_REQUIRES_RE = re.compile(r"\brequires\b\s+(.+)", re.I)


def _load_target_patterns_lib():
    """Import tools/lib/per_function_target_patterns.py (or None on failure)."""
    lib = REPO / "tools" / "lib" / "per_function_target_patterns.py"
    if not lib.is_file():
        return None
    try:
        spec = importlib.util.spec_from_file_location("pftp_reasoner", lib)
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)  # type: ignore[union-attr]
        return mod
    except Exception:
        return None


def iter_reasoner_ledgers(check_path: Path):
    """Yield (ledger_filename, reasoner_tool, language) from _REASONER_LEDGERS.

    Parsed via AST from the literal tuple - no import of the gate module (which
    pulls heavy deps). Robust to comments interleaved in the tuple.
    """
    src = check_path.read_text(encoding="utf-8")
    tree = ast.parse(src)
    node = None
    for stmt in tree.body:
        targets = getattr(stmt, "targets", None) or (
            [getattr(stmt, "target", None)] if hasattr(stmt, "target") else []
        )
        for t in targets:
            if isinstance(t, ast.Name) and t.id == "_REASONER_LEDGERS":
                node = getattr(stmt, "value", None)
        if node is not None:
            break
    if not isinstance(node, ast.Tuple):
        raise ValueError("_REASONER_LEDGERS tuple not found in " + str(check_path))
    out = []
    for elt in node.elts:
        if not isinstance(elt, ast.Tuple) or len(elt.elts) < 3:
            continue
        try:
            fname = ast.literal_eval(elt.elts[0])
            tool = ast.literal_eval(elt.elts[1])
            lang = ast.literal_eval(elt.elts[2])
        except Exception:
            continue
        out.append((str(fname), str(tool), str(lang)))
    return out


def _extract_docstring(tool_path: Path) -> str:
    try:
        return ast.get_docstring(ast.parse(tool_path.read_text(encoding="utf-8"))) or ""
    except Exception:
        return ""


def _heading_core(stripped: str) -> str:
    """The leading portion of a line before a '(' qualifier or ':' - the part that
    decides whether the line is an upper-case section heading (headings such as
    ``THE INVARIANT (Euler ...):`` carry a lowercase parenthetical we must ignore)."""
    return re.split(r"[(:]", stripped, maxsplit=1)[0].strip()


def _is_heading(line: str, nxt: str) -> bool:
    """A section heading: an rst-underlined line, or an unindented upper-case line."""
    if line != line.lstrip():
        return False  # indented -> not a top-level heading
    stripped = line.strip()
    if not stripped:
        return False
    # rst underline on the following line (---- / ====)
    if nxt and re.fullmatch(r"[-=~^]{3,}", nxt.strip()):
        return True
    core = _heading_core(stripped)
    alpha = [c for c in core if c.isalpha()]
    if len(alpha) < 3:
        return False
    upper = sum(1 for c in alpha if c.isupper())
    if upper / len(alpha) < 0.6:
        return False
    return bool(re.fullmatch(r"[A-Z0-9][A-Z0-9 /,.#%'\"\-]{2,90}", core))


def split_sections(docstring: str):
    """Return ordered [(heading, body_text), ...]; the pre-heading blurb is ('', ...)."""
    lines = docstring.splitlines()
    sections = []
    cur_head = ""
    cur_body: list[str] = []
    i = 0
    while i < len(lines):
        line = lines[i]
        nxt = lines[i + 1] if i + 1 < len(lines) else ""
        if _is_heading(line, nxt):
            sections.append((cur_head, "\n".join(cur_body).strip()))
            cur_head = line.strip()
            cur_body = []
            # skip an rst underline line
            if nxt and re.fullmatch(r"[-=~^]{3,}", nxt.strip()):
                i += 2
                continue
            i += 1
            continue
        cur_body.append(line)
        i += 1
    sections.append((cur_head, "\n".join(cur_body).strip()))
    return sections


def _sanitize(text: str) -> str:
    """Replace em/en dashes (banned in authored output) with a hyphen-minus, and
    strip a leading ``<toolname>.py -`` / ``<toolname>.py:`` self-reference so an
    extracted summary reads as prose, not a filename echo."""
    text = (text or "").replace("—", " - ").replace("–", "-")
    text = re.sub(r"^\s*[\w.\-]+\.py\s*[-:]\s*", "", text)
    return text


def _collapse(text: str) -> str:
    return re.sub(r"\s+", " ", _sanitize(text)).strip()


def _clip(text: str, limit: int) -> str:
    text = _collapse(text)
    if len(text) <= limit:
        return text
    cut = text[:limit]
    sp = cut.rfind(" ")
    if sp > limit * 0.6:
        cut = cut[:sp]
    return cut.rstrip(" ,;:-") + " ..."


def _subfield(block: str, label_re: re.Pattern, others: list[re.Pattern]) -> str:
    """Text following the first `label_re` match up to the next label / block end."""
    m = label_re.search(block)
    if not m:
        return ""
    start = m.end()
    end = len(block)
    for o in others:
        mo = o.search(block, start)
        if mo and mo.start() < end:
            end = mo.start()
    chunk = block[start:end]
    # strip a leading "(qualifier):" or ":" that follows the label
    chunk = re.sub(r"^\s*(\([^)]*\))?\s*:?-?\s*", "", chunk, count=1)
    return _collapse(chunk)


def extract_logic(docstring: str, class_label: str) -> dict:
    """Extract assumption / invariant / requires / finding / query / block."""
    sections = split_sections(docstring)
    heads = {h.upper(): b for h, b in sections}

    block = ""
    matched_head = ""
    for want in _TRIPLE_HEADINGS:
        for h, b in sections:
            if _heading_core(h).upper().startswith(want) and b.strip():
                block, matched_head = b, h
                break
        if block:
            break
    if not block:
        # secondary fallback: a descriptive body section, before the pre-heading blurb.
        for want in _FALLBACK_HEADINGS:
            for h, b in sections:
                if _heading_core(h).upper().startswith(want) and b.strip():
                    block, matched_head = b, h
                    break
            if block:
                break
    if not block:
        # last resort: the SUBSTANTIVE (longest) section body, skipping the bare
        # filename blurb - a heading-less docstring's real content is its meatiest
        # section, not the one-line ``<tool>.py (...)`` self-reference.
        best = None
        for h, b in sections:
            body = _sanitize(b).strip()
            if len(body) < 60:
                continue
            score = len(body)
            if best is None or score > best[0]:
                best = (score, b, h)
        if best is not None:
            block, matched_head = best[1], best[2] or "(summary)"

    boundary = [_ASSUMPTION_RE, _INVARIANT_RE, _FINDING_LABEL_RE]
    assumption = _subfield(block, _ASSUMPTION_RE, [r for r in boundary if r is not _ASSUMPTION_RE])
    invariant = _subfield(block, _INVARIANT_RE, [r for r in boundary if r is not _INVARIANT_RE])
    finding = _subfield(block, _FINDING_LABEL_RE, [])
    if not finding:
        finding = _subfield(block, _FINDING_INLINE_RE, [])

    requires = ""
    rm = _REQUIRES_RE.search(block)
    if rm:
        requires = _collapse(rm.group(1))

    # A query block (goroutine race etc.) has no ASSUMPTION/INVARIANT sub-labels;
    # use its leading prose as the query.
    query = ""
    if not (assumption or invariant) and block:
        query = _collapse(block)

    return {
        "class_label": class_label,
        "heading": matched_head,
        "assumption": _clip(assumption, 240),
        "invariant": _clip(invariant, 240),
        "requires": _clip(requires, 200),
        "finding": _clip(finding, 260),
        "query": _clip(query, 300),
    }


def render_question(parts: dict) -> str:
    """Phrase the extracted logic as a single OPEN (interrogative) question."""
    premises = []
    if parts["assumption"]:
        premises.append("the protocol assumes " + parts["assumption"])
    if parts["requires"]:
        premises.append("the invariant requires " + parts["requires"])
    elif parts["invariant"] and not parts["assumption"]:
        premises.append("the required invariant is " + parts["invariant"])

    if parts["finding"]:
        tail = ("Does any in-scope function fall in the resulting violation set - "
                + parts["finding"] + "?")
    elif parts["query"]:
        tail = ("Applying the reasoning query, does this function yield a survivor: "
                + parts["query"] + "?")
    else:
        tail = ("Could this function be vulnerable to the "
                + parts["class_label"] + " logic class?")

    if premises:
        q = "Given that " + "; and ".join(premises) + ". " + tail
    else:
        q = tail
    q = _collapse(q)
    q = re.sub(r"\s*\.\.+", ".", q)  # collapse ".." / " .." artifacts from clipping
    if not q.endswith("?"):
        q = q.rstrip(".") + "?"
    return q


def _slug(name: str) -> str:
    s = re.sub(r"\.py$", "", name)
    s = re.sub(r"[^A-Za-z0-9]+", "-", s).strip("-")
    return s


def _class_label(name: str) -> str:
    s = re.sub(r"\.py$", "", name)
    s = re.sub(
        r"-(reasoner|check|screen|hunter|scan|search|lane|graph|miner|reachability|"
        r"set-difference|taint|halt|obligation)$",
        "", s,
    )
    return s


def build_row(ledger_fname: str, tool: str, lang: str, parts: dict) -> dict:
    reasoner = _slug(tool)
    slug_upper = reasoner.upper()
    return {
        "question_id": "HQ-REASONER-TRIPLE-" + slug_upper,
        "question_text": render_question(parts),
        "attack_class_anchor": "logic-reasoner-triple",
        "source": SOURCE_PREFIX + reasoner,
        "source_case_study": "tools/" + tool,
        "source_incident_id": "reasoner-triple-" + reasoner,
        "reasoner_tool": tool,
        "reasoner_ledger": ledger_fname,
        "reasoner_heading": parts.get("heading", ""),
        "scope_specificity": "function",
        "grep_patterns": [],
        "linked_invariant_ids": [],
        "target_function_patterns": [],
        "target_contract_patterns": [],
        "target_modifier_patterns": [],
        "target_function_roles": [],
        "verification_tier": VERIFICATION_TIER,
        # target_languages filled by caller (routing-safe resolve).
        "target_languages": [],
        "native_target_languages": [],
        "target_languages_routing_source": "fail-open-default",
        "_lang_tag": lang,
    }


def _resolve_langs(row: dict, lib) -> None:
    seed = list(_LANG_SEED.get(row.pop("_lang_tag", "any"), _LANG_SEED["any"]))
    anchor = row["attack_class_anchor"]
    qtext = row["question_text"]
    if lib is not None and hasattr(lib, "resolve_target_languages"):
        resolved, native, source = lib.resolve_target_languages(anchor, qtext, seed)
        row["target_languages"] = resolved
        row["native_target_languages"] = native
        row["target_languages_routing_source"] = source
    else:
        row["target_languages"] = seed
        row["native_target_languages"] = []
        row["target_languages_routing_source"] = "fail-open-existing"


def load_existing(path: Path):
    """Return (sources, question_ids) already present in the library."""
    sources, qids = set(), set()
    if not path.is_file():
        return sources, qids
    for raw in path.read_text(encoding="utf-8").splitlines():
        raw = raw.strip()
        if not raw:
            continue
        try:
            rec = json.loads(raw)
        except json.JSONDecodeError:
            continue
        s = rec.get("source")
        if isinstance(s, str) and s.startswith(SOURCE_PREFIX):
            sources.add(s)
        qid = rec.get("question_id")
        if isinstance(qid, str):
            qids.add(qid)
    return sources, qids


def build_all_rows(check_path: Path, tools_dir: Path):
    lib = _load_target_patterns_lib()
    rows = []
    skipped = []
    for ledger_fname, tool, lang in iter_reasoner_ledgers(check_path):
        tool_path = tools_dir / tool
        if not tool_path.is_file():
            skipped.append((tool, "missing-file"))
            continue
        ds = _extract_docstring(tool_path)
        if not ds:
            skipped.append((tool, "no-docstring"))
            continue
        parts = extract_logic(ds, _class_label(tool))
        row = build_row(ledger_fname, tool, lang, parts)
        _resolve_langs(row, lib)
        rows.append(row)
    return rows, skipped


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--library", default=str(DEFAULT_LIBRARY))
    ap.add_argument("--check-path", default=str(DEFAULT_CHECK))
    ap.add_argument("--tools-dir", default=str(DEFAULT_TOOLS))
    ap.add_argument("--dry-run", action="store_true",
                    help="Compute + report rows, do NOT append to the library.")
    ap.add_argument("--json", action="store_true", help="Emit a JSON report.")
    args = ap.parse_args()

    check_path = Path(args.check_path)
    tools_dir = Path(args.tools_dir)
    lib_path = Path(args.library)
    if not check_path.is_file():
        print("ERR: check-path not found: " + str(check_path), file=sys.stderr)
        return 2

    rows, skipped = build_all_rows(check_path, tools_dir)
    have_sources, have_qids = load_existing(lib_path)

    new_rows = [r for r in rows
                if r["source"] not in have_sources and r["question_id"] not in have_qids]

    appended = 0
    if new_rows and not args.dry_run:
        lib_path.parent.mkdir(parents=True, exist_ok=True)
        with lib_path.open("a", encoding="utf-8") as fh:
            for r in new_rows:
                fh.write(json.dumps(r, sort_keys=True) + "\n")
                appended += 1

    report = {
        "schema": "auditooor.reasoner_triple_to_hacker_q.v1",
        "library": str(lib_path),
        "reasoners_total": len(rows) + len(skipped),
        "rows_built": len(rows),
        "rows_new": len(new_rows),
        "rows_appended": appended,
        "rows_already_present": len(rows) - len(new_rows),
        "skipped": [{"tool": t, "reason": why} for t, why in skipped],
        "dry_run": bool(args.dry_run),
    }
    if args.json:
        print(json.dumps(report, indent=2))
    else:
        print("[reasoner-triple-to-hacker-q] reasoners=%d built=%d new=%d appended=%d "
              "already-present=%d skipped=%d dry_run=%s"
              % (report["reasoners_total"], report["rows_built"], report["rows_new"],
                 report["rows_appended"], report["rows_already_present"],
                 len(skipped), args.dry_run))
        for r in new_rows[:6]:
            print("  + " + r["source"] + " :: " + _clip(r["question_text"], 150))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
