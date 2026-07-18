#!/usr/bin/env python3
"""oscript-aa-enumerate - enumerate in-scope Obyte Autonomous Agent (AA) units.

WHY THIS EXISTS (obyte 2026-07-09, capability gap):
The in-scope manifest emitter (workspace-coverage-heatmap.py::write_inscope_manifest)
was Solidity/Rust/Go/Move/Cairo/Vyper/Noir-only. On the Obyte workspace it
enumerated 410 .sol units and ZERO of the ~40 in-scope Autonomous Agent files
written in OSCRIPT (`.oscript` / `.aa`), which carry the real value-moving logic
(payments, persistent `state`, asset mint). Those AA files were invisible to the
hunt / coverage / scope-authority layers. This module teaches the pipeline to
enumerate AA units so `.auditooor/inscope_units.jsonl` includes them.

OSCRIPT structure (essentials):
  A `.oscript` / `.aa` file is a top-level object, either a bare ``{...}`` or the
  labelled form ``['autonomous agent', {...}]``. Relevant keys:
    - ``init``     : a backtick formula preamble run on every trigger.
    - ``messages`` : EITHER ``{cases:[ {if,init,messages}, ... ]}`` - a routing
                     table whose cases[] entries are the ENTRY POINTS - OR a
                     plain ``[ {app,payload}, ... ]`` array - a single always-run
                     handler.
    - ``getters``  : a backtick block defining ``$name = ...`` top-level members
                     (constants and ``($args) => {...}`` lambdas).
  Formulas are backtick-delimited strings; they contain ``//`` and ``/* */``
  comments, ``{expr}`` template interpolation, and trailing commas, and are NOT
  strict JSON. This parser is deliberately TOLERANT and STRUCTURAL: it masks
  strings + comments, brace/bracket-matches to find the top-level keys and the
  cases[] / getters members, and never attempts full formula parsing.

Emitted unit rows (one per):
  - each top-level ``messages.cases[]`` entry -> kind="message-case", fn="case_<i>"
  - each ``getters`` ``$name`` definition     -> kind="getter",       fn="$name"
  - a non-trivial top-level ``init``           -> kind="init",          fn="init"
  - a plain-array ``messages``                 -> kind="message-handler",fn="messages"

Row schema (loadable by tools/scope_authority.py load_inscope + _relify):
  {"file": <ws-relative posix>, "fn": <unit>, "function": <unit>, "lang": "oscript",
   "kind": <...>, "file_line": "<file>:<line>", "value_movers": [...],
   "state_writes": [...], "prior_covered": false}
"""
from __future__ import annotations

import argparse
import json
import os
import re
import sys
from pathlib import Path

# Path fragments that mark a file as NOT a first-party in-scope AA (tests, mocks,
# vendored deps). Mirrors the brief's skip set.
_SKIP_SUBSTR = ("/test/", "/tests/", "-mock", ".test.", "node_modules")
_SKIP_DIRNAMES = frozenset({"test", "tests", "node_modules", ".git", ".auditooor",
                            "__pycache__"})

# Value-moving AA app types (per the Oscript spec): payments move coins, state
# writes persistent vars, asset/definition mint or deploy. `data`/`data_feed`/
# `text`/`profile` are informational and NOT value-movers.
_VALUE_MOVER_APPS = ("payment", "state", "asset", "definition")

# A top-level getter member: `$name =` where the `=` is a real assignment (not
# `==`, `>=`, `<=`, `!=`, or the `=>` of a lambda arrow).
_GETTER_ASSIGN_RE = re.compile(r"\$([A-Za-z_]\w*)\s*=(?![=>])")
# `app: 'payment'` / `app: "state"` inside a message body.
_APP_RE = re.compile(r"""\bapp\s*:\s*(['"])([a-z_]+)\1""")
# A persistent state write `var['key'] = / += / -=` (LHS of a state assignment).
_VAR_WRITE_RE = re.compile(r"var\s*\[([^\]]*)\]\s*(?:\+=|-=|=)(?![=>])")


def _skip_plain_string(text: str, i: int) -> int:
    """``text[i]`` opens a plain quoted string (``'`` / ``"`` / ``` ` ```).
    Return the index just past the matching closing quote (or ``len(text)``)."""
    n = len(text)
    q = text[i]
    j = i + 1
    while j < n:
        c = text[j]
        if c == "\\":
            j += 2
            continue
        if c == q:
            return j + 1
        j += 1
    return n


def _skip_formula(text: str, i: int) -> int:
    """``text[i]`` opens an OSCRIPT FORMULA string: a quote/backtick immediately
    followed (past whitespace) by ``{``. Obyte formula strings are delimited by
    ``` `...` ```, ``"..."``, or ``'...'`` and MAY contain nested UNESCAPED
    quotes of the outer kind (e.g. ``"{ bounce("bad") }"``), so a plain
    next-quote scan mis-parses them. We instead brace-match the ``{...}`` body -
    tracking nested strings + comments so their braces do not count - and consume
    the closing outer quote after the matching ``}``. Returns the index just past
    the closing quote (or ``len(text)``)."""
    n = len(text)
    q = text[i]
    j = i + 1
    while j < n and text[j] != "{":
        j += 1
    if j >= n:
        return n
    depth = 0
    st = None  # nested: None | 'line' | 'block' | "'" | '"'
    while j < n:
        c = text[j]
        nxt = text[j + 1] if j + 1 < n else ""
        if st is None:
            if c == "/" and nxt == "/":
                st = "line"
                j += 2
                continue
            if c == "/" and nxt == "*":
                st = "block"
                j += 2
                continue
            if c == "'" or c == '"':
                st = c
                j += 1
                continue
            if c == "{":
                depth += 1
                j += 1
                continue
            if c == "}":
                depth -= 1
                j += 1
                if depth == 0:
                    while j < n and text[j] in " \t\r\n":
                        j += 1
                    if j < n and text[j] == q:
                        return j + 1
                    return j
                continue
            j += 1
            continue
        if st == "line":
            if c == "\n":
                st = None
            j += 1
            continue
        if st == "block":
            if c == "*" and nxt == "/":
                st = None
                j += 2
                continue
            j += 1
            continue
        # nested quoted string ("'" / '"')
        if c == "\\":
            j += 2
            continue
        if c == st:
            st = None
        j += 1
    return n


def mask_code(text: str, backtick_is_string: bool = True) -> str:
    """Return a same-length copy of ``text`` where every character inside a
    string literal, an OSCRIPT formula string, or a comment is replaced by a
    space, while structural code characters (braces, brackets, parens, colons,
    ``$``, ``=``, identifiers) and ALL newlines are preserved. This lets a caller
    brace-match + regex the real structure without formula/comment/string
    contents confusing it. Indices map 1:1 to ``text`` (line numbers agree).

    A FORMULA string (a quote/backtick whose first non-space char is ``{``) is
    masked by brace-matching, not by the next quote, so nested unescaped quotes
    inside the formula body do not flip the string state. ``backtick_is_string``
    is False when masking a formula body itself (formulas never nest backticks)."""
    n = len(text)
    out = ["\n" if ch == "\n" else " " for ch in text]
    i = 0
    while i < n:
        c = text[i]
        nxt = text[i + 1] if i + 1 < n else ""
        if c == "/" and nxt == "/":
            j = text.find("\n", i)
            i = n if j == -1 else j
            continue
        if c == "/" and nxt == "*":
            j = text.find("*/", i)
            i = n if j == -1 else j + 2
            continue
        if c == '"' or c == "'" or (c == "`" and backtick_is_string):
            # formula (quote + `{`) vs plain string
            k = i + 1
            while k < n and text[k] in " \t\r\n":
                k += 1
            if k < n and text[k] == "{":
                i = _skip_formula(text, i)
            else:
                i = _skip_plain_string(text, i)
            continue
        out[i] = c
        i += 1
    return "".join(out)


def _line_of(text: str, pos: int) -> int:
    return text.count("\n", 0, pos) + 1


def _advance_to_value(text: str, i: int, limit: int) -> int:
    """Advance ``i`` past whitespace and ``//`` / ``/* */`` comments in the
    ORIGINAL text, stopping at the first real value character (a structural
    ``{`` / ``[`` / a quote / a backtick / a scalar). We cannot use the masked
    string for this because a string literal is blanked to spaces there, so
    skipping masked-whitespace would leap over the whole value."""
    while i < limit:
        c = text[i]
        if c in " \t\r\n":
            i += 1
            continue
        if c == "/" and i + 1 < limit and text[i + 1] == "/":
            j = text.find("\n", i)
            i = limit if j == -1 else j + 1
            continue
        if c == "/" and i + 1 < limit and text[i + 1] == "*":
            j = text.find("*/", i)
            i = limit if j == -1 else j + 2
            continue
        break
    return i


def _match_bracket(masked: str, open_pos: int) -> int:
    """Given the index of an opening ``{`` / ``[`` / ``(`` in ``masked`` (a code
    string), return the index of the matching close, or -1."""
    pairs = {"{": "}", "[": "]", "(": ")"}
    opener = masked[open_pos]
    closer = pairs.get(opener)
    if closer is None:
        return -1
    depth = 0
    i = open_pos
    n = len(masked)
    while i < n:
        ch = masked[i]
        if ch in "{[(":
            depth += 1
        elif ch in "}])":
            depth -= 1
            if depth == 0:
                return i
        i += 1
    return -1


def _find_aa_object(masked: str) -> tuple[int, int]:
    """Locate the AA body object span ``(open_brace_idx, close_brace_idx)``.
    Handles both the bare ``{...}`` form and the ``['autonomous agent', {...}]``
    form. Returns ``(-1, -1)`` when no object is found."""
    # first structural char
    m = re.search(r"[\[{]", masked)
    if not m:
        return -1, -1
    start = m.start()
    if masked[start] == "{":
        end = _match_bracket(masked, start)
        return start, end
    # array wrapper: find the first object brace inside it
    arr_end = _match_bracket(masked, start)
    ob = masked.find("{", start + 1, arr_end if arr_end != -1 else len(masked))
    if ob == -1:
        return -1, -1
    return ob, _match_bracket(masked, ob)


def _top_level_keys(text: str, masked: str, obj_open: int, obj_close: int) -> dict:
    """Return ``{key_name: (value_start, value_end)}`` for the object's direct
    (depth-1) ``key:`` members. ``value_start`` is the index of the first
    structural char of the value; ``value_end`` is exclusive (the terminating
    top-level ``,`` or the object close). ``text`` is the ORIGINAL source (used
    to locate value starts across string literals); ``masked`` is its
    string/comment-masked twin (used for bracket depth)."""
    masked_text_src = text
    keys: dict[str, tuple[int, int]] = {}
    i = obj_open + 1
    depth = 0  # relative to inside the object
    key_re = re.compile(r"([A-Za-z_]\w*)\s*:")
    while i < obj_close:
        ch = masked[i]
        if ch in "{[(":
            depth += 1
            i += 1
            continue
        if ch in "}])":
            depth -= 1
            i += 1
            continue
        if depth == 0 and (ch.isalpha() or ch == "_"):
            m = key_re.match(masked, i)
            if m:
                name = m.group(1)
                # advance to first real char of the value (whitespace + comments
                # skipped on the ORIGINAL text so a string value is not leapt).
                v_start = _advance_to_value(masked_text_src, m.end(), obj_close)
                # find end: next top-level comma or object close
                j = v_start
                d2 = 0
                while j < obj_close:
                    cj = masked[j]
                    if cj in "{[(":
                        d2 += 1
                    elif cj in "}])":
                        if d2 == 0:
                            break
                        d2 -= 1
                    elif cj == "," and d2 == 0:
                        break
                    j += 1
                keys[name] = (v_start, j)
                i = j
                continue
        i += 1
    return keys


def _count_cases(masked: str, arr_open: int, arr_close: int) -> list[int]:
    """Return the list of opening-brace indices (in ``masked``) of the direct
    (depth-1) object elements of the ``cases`` array."""
    starts: list[int] = []
    i = arr_open + 1
    depth = 0
    while i < arr_close:
        ch = masked[i]
        if ch == "{":
            if depth == 0:
                starts.append(i)
            depth += 1
        elif ch == "[" or ch == "(":
            depth += 1
        elif ch == "}" or ch == "]" or ch == ")":
            depth -= 1
        i += 1
    return starts


def _scan_apps(segment: str) -> list[str]:
    """Ordered-unique value-mover app types present in an original-text
    segment."""
    found: list[str] = []
    for m in _APP_RE.finditer(segment):
        app = m.group(2)
        if app in _VALUE_MOVER_APPS and app not in found:
            found.append(app)
    return found


def _scan_state_writes(segment: str, cap: int = 40) -> list[str]:
    """Ordered-unique ``var[...]`` write keys (raw bracket expressions) in an
    original-text segment. Capped so a huge state block cannot bloat a row."""
    writes: list[str] = []
    for m in _VAR_WRITE_RE.finditer(segment):
        key = m.group(1).strip()
        if key and key not in writes:
            writes.append(key)
            if len(writes) >= cap:
                break
    return writes


def _getter_members(inner_raw: str) -> list[str]:
    """Given the raw text INSIDE a getters backtick block, return the ordered
    list of top-level ``$name`` member names (both constants and lambdas)."""
    masked = mask_code(inner_raw, backtick_is_string=False)
    stripped = masked.lstrip()
    base_depth = 1 if stripped[:1] == "{" else 0
    # precompute depth-before-position
    n = len(masked)
    depth = 0
    depths = [0] * (n + 1)
    for idx in range(n):
        depths[idx] = depth
        ch = masked[idx]
        if ch in "{[(":
            depth += 1
        elif ch in "}])":
            depth -= 1
    depths[n] = depth
    names: list[str] = []
    seen: set[str] = set()
    for m in _GETTER_ASSIGN_RE.finditer(masked):
        if depths[m.start()] != base_depth:
            continue
        nm = "$" + m.group(1)
        if nm not in seen:
            seen.add(nm)
            names.append(nm)
    return names


def _formula_inner(text: str, v_start: int) -> str:
    """Given ``v_start`` = the index of a formula string's opening delimiter
    (``` ` ``` / ``"`` / ``'``), return the RAW code inside the delimiters (the
    ``{...}`` body), delimiter-agnostic. Handles the double/single-quoted formula
    forms some AAs use (e.g. ``init: "{ ... }"``) as well as the backtick form."""
    if v_start < 0 or v_start >= len(text):
        return ""
    q = text[v_start]
    if q not in ("`", '"', "'"):
        # value did not start with a delimiter; return as-is (best effort)
        return text[v_start:]
    end = _skip_formula(text, v_start)
    close_q = end - 1
    if close_q > v_start and text[close_q] == q:
        return text[v_start + 1:close_q]
    return text[v_start + 1:end]


def _init_is_trivial(inner_raw: str) -> bool:
    """True when an init backtick body has no real statement (empty ``{}`` or
    only comments/whitespace)."""
    masked = mask_code(inner_raw, backtick_is_string=False)
    body = re.sub(r"[{}\s;]", "", masked)
    return len(body) == 0


def enumerate_file(path: Path, ws_root: Path) -> list[dict]:
    """Enumerate the AA units in a single ``.oscript`` / ``.aa`` file. Returns a
    list of row dicts (may be empty on a non-AA / unparseable file)."""
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return []
    masked = mask_code(text, backtick_is_string=True)
    obj_open, obj_close = _find_aa_object(masked)
    if obj_open == -1 or obj_close == -1:
        return []
    try:
        rel = str(path.resolve().relative_to(ws_root.resolve())).replace("\\", "/")
    except (ValueError, OSError):
        rel = path.name
    keys = _top_level_keys(text, masked, obj_open, obj_close)
    rows: list[dict] = []

    def _row(fn: str, kind: str, line: int, value_movers=None, state_writes=None,
             extra=None) -> dict:
        r = {
            "file": rel,
            "fn": fn,
            "function": fn,
            "lang": "oscript",
            "kind": kind,
            "file_line": f"{rel}:{line}",
            "value_movers": value_movers or [],
            "state_writes": state_writes or [],
            "prior_covered": False,
        }
        if extra:
            r.update(extra)
        return r

    # --- init ---
    if "init" in keys:
        v_start, v_end = keys["init"]
        body = _formula_inner(text, v_start)
        if not _init_is_trivial(body):
            rows.append(_row("init", "init", _line_of(text, v_start),
                             state_writes=_scan_state_writes(body)))

    # --- messages ---
    if "messages" in keys:
        v_start, v_end = keys["messages"]
        # first structural char of the value (comment/whitespace tolerant)
        vi = _advance_to_value(text, v_start, v_end)
        if vi < v_end and masked[vi] == "{":
            # object form: look for cases[]
            m_open = vi
            m_close = _match_bracket(masked, m_open)
            sub = _top_level_keys(text, masked, m_open, m_close)
            if "cases" in sub:
                cs, ce = sub["cases"]
                # cases value should be an array (comment/whitespace tolerant)
                ai = _advance_to_value(text, cs, ce)
                if ai < len(masked) and masked[ai] == "[":
                    arr_close = _match_bracket(masked, ai)
                    starts = _count_cases(masked, ai, arr_close)
                    for idx, st in enumerate(starts):
                        case_close = _match_bracket(masked, st)
                        seg = text[st:case_close + 1] if case_close != -1 else text[st:st + 400]
                        label = _case_label(text, masked, st, case_close)
                        extra = {"label": label} if label else None
                        rows.append(_row(
                            f"case_{idx}", "message-case", _line_of(text, st),
                            value_movers=_scan_apps(seg),
                            state_writes=_scan_state_writes(seg), extra=extra))
            else:
                # object messages without cases: treat as a single handler
                seg = text[m_open:(m_close + 1) if m_close != -1 else v_end]
                rows.append(_row("messages", "message-handler",
                                 _line_of(text, m_open),
                                 value_movers=_scan_apps(seg),
                                 state_writes=_scan_state_writes(seg)))
        elif vi < v_end and masked[vi] == "[":
            # plain-array form: one always-run handler
            arr_close = _match_bracket(masked, vi)
            seg = text[vi:(arr_close + 1) if arr_close != -1 else v_end]
            rows.append(_row("messages", "message-handler", _line_of(text, vi),
                             value_movers=_scan_apps(seg),
                             state_writes=_scan_state_writes(seg)))

    # --- getters ---
    if "getters" in keys:
        v_start, v_end = keys["getters"]
        body = _formula_inner(text, v_start)
        if body:
            # offset of body[0] within the original text (after the opening
            # delimiter). _formula_inner strips exactly the one opening char.
            body_off = v_start + 1
            for nm in _getter_members(body):
                # anchor the line to the member's first appearance in body
                mm = re.search(re.escape(nm) + r"\s*=(?![=>])", body)
                ln = _line_of(text, body_off + mm.start()) if mm else _line_of(text, v_start)
                rows.append(_row(nm, "getter", ln))

    # Deterministic, line-ordered within the file (mirrors the .sol manifest).
    def _ln(r: dict) -> int:
        try:
            return int(str(r.get("file_line", "")).rsplit(":", 1)[-1])
        except ValueError:
            return 0
    rows.sort(key=_ln)
    return rows


def _case_label(text: str, masked: str, case_open: int, case_close: int) -> str:
    """Best-effort short slug from a case's top-level ``if:`` condition."""
    if case_close == -1:
        case_close = min(len(masked), case_open + 800)
    sub = _top_level_keys(text, masked, case_open, case_close)
    if "if" not in sub:
        return ""
    cs, ce = sub["if"]
    raw = text[cs:ce]
    b0 = raw.find("`")
    b1 = raw.rfind("`")
    if b0 != -1 and b1 > b0:
        cond = raw[b0 + 1:b1]
    else:
        cond = raw.strip().strip("'\"")
    cond = re.sub(r"[{}]", "", cond)
    cond = re.sub(r"\s+", " ", cond).strip()
    return cond[:60]


def _iter_aa_files(ws: Path):
    for root, dirs, files in os.walk(ws):
        # prune skip dirs in-place for speed
        dirs[:] = [d for d in dirs if d not in _SKIP_DIRNAMES]
        for fn in files:
            if not (fn.endswith(".oscript") or fn.endswith(".aa")):
                continue
            full = Path(root) / fn
            rel_posix = str(full).replace("\\", "/")
            low = rel_posix.lower()
            if any(s in low for s in _SKIP_SUBSTR):
                continue
            yield full


def list_aa_files(ws: Path | str) -> list[Path]:
    """Deterministic list of in-scope AA (.oscript/.aa) files under ``ws``
    (skipping test/mock/vendor). Used by the manifest emitter to decide whether
    an existing manifest already covers the AA surface (additive freshness)."""
    return sorted(_iter_aa_files(Path(ws)), key=lambda p: str(p))


def enumerate_workspace(ws: Path) -> list[dict]:
    """Enumerate every in-scope AA unit under ``ws`` (skipping test/mock/vendor).
    Deterministically ordered by (file, line)."""
    rows: list[dict] = []
    for f in sorted(_iter_aa_files(ws), key=lambda p: str(p)):
        rows.extend(enumerate_file(f, ws))
    return rows


def per_file_counts(rows: list[dict]) -> dict:
    """Return ``{relfile: {kind: n, ..., 'total': n}}`` for a row list."""
    out: dict[str, dict] = {}
    for r in rows:
        f = r["file"]
        d = out.setdefault(f, {})
        d[r["kind"]] = d.get(r["kind"], 0) + 1
        d["total"] = d.get("total", 0) + 1
    return out


def main(argv: list[str]) -> int:
    ap = argparse.ArgumentParser(
        description="Enumerate in-scope Obyte Autonomous Agent (Oscript) units.")
    ap.add_argument("--workspace", required=True,
                    help="Workspace root path (walked for *.oscript / *.aa).")
    ap.add_argument("--emit", metavar="PATH",
                    help="Append the enumerated rows as JSONL to PATH.")
    ap.add_argument("--json", action="store_true",
                    help="Emit the rows + per-file counts as JSON to stdout.")
    args = ap.parse_args(argv)

    ws = Path(os.path.expanduser(args.workspace)).resolve()
    if not ws.is_dir():
        sys.stderr.write(f"[oscript-enumerate] workspace not found: {ws}\n")
        return 2
    rows = enumerate_workspace(ws)

    if args.emit:
        out = Path(os.path.expanduser(args.emit))
        out.parent.mkdir(parents=True, exist_ok=True)
        with out.open("a", encoding="utf-8") as fh:
            for r in rows:
                fh.write(json.dumps(r, separators=(", ", ": ")) + "\n")
        sys.stderr.write(
            f"[oscript-enumerate] appended {len(rows)} oscript units -> {out}\n")

    counts = per_file_counts(rows)
    if args.json:
        print(json.dumps({
            "workspace": str(ws),
            "total_units": len(rows),
            "file_count": len(counts),
            "per_file": counts,
            "rows": rows,
        }, indent=2))
    else:
        for f in sorted(counts):
            c = counts[f]
            detail = " ".join(f"{k}={v}" for k, v in sorted(c.items())
                              if k != "total")
            print(f"{c['total']:4d}  {f}  ({detail})")
        print(f"TOTAL: {len(rows)} oscript units across {len(counts)} files")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
