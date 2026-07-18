"""
serde-untagged-enum-first-variant-shadows-all-sibling-variants — generated from reference/patterns.dsl/serde-untagged-enum-first-variant-shadows-all-sibling-variants.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py serde-untagged-enum-first-variant-shadows-all-sibling-variants.yaml
Source: auditooor-R76-c4-rujira-bug-bounty-45
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class SerdeUntaggedEnumFirstVariantShadowsAllSiblingVariants(AbstractDetector):
    ARGUMENT = "serde-untagged-enum-first-variant-shadows-all-sibling-variants"
    HELP = "`#[serde(untagged)]` enum with a first variant of all-Option fields silently captures every other variant's input — slippage / deadline / min_return parameters are dropped and every call executes as the unprotected branch."
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.HIGH
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/serde-untagged-enum-first-variant-shadows-all-sibling-variants.yaml"
    WIKI_TITLE = "`#[serde(untagged)]` with permissive first variant silently drops required fields of all other variants"
    WIKI_DESCRIPTION = "When an enum is deserialised as `untagged`, serde tries each variant in declaration order; the first variant whose fields all parse succeeds. By default `cw_serde` / `#[derive(Deserialize)]` accept extra unknown fields, so a variant with only `Option<>` fields (e.g. `Yolo { to: Option<String>, callback: Option<CallbackData> }`) matches ANY JSON object, and the neighbouring variants' required field"
    WIKI_EXPLOIT_SCENARIO = "User sends `{\"swap\":{\"min_return\":\"1000000\"}}` intending to enforce a 1M minimum return. Serde picks the first variant `Yolo { to: None, callback: None }`; `min_return` is dropped as unknown. The contract executes the swap with NO slippage protection and the user is sandwich-attacked for the full bid-ask spread. Applies to every MIN / EXACT / LIMIT variant for every swap."
    WIKI_RECOMMENDATION = "Remove `#[serde(untagged)]` and use the default tagged representation (`{\"min\":{\"min_return\":...}}` on the wire), OR add `#[serde(deny_unknown_fields)]` per-variant, OR re-design as a single struct `SwapRequest { kind: SwapKind, min_return: Option<Uint128>, ... }` that encodes the mode explicitl"

    _PRECONDITIONS = [{'contract.source_matches_regex': '(?i)\\.rs$'}, {'contract.source_matches_regex': '(?i)#\\[cw_serde\\]|serde::\\{Deserialize|\\#\\[derive\\(.*Deserialize'}]
    _MATCH = [{'function.kind': 'type_definition'}, {'function.body_contains_regex': '(?i)#\\[serde\\s*\\(\\s*untagged\\s*\\)\\]'}, {'function.body_contains_regex': '(?i)enum\\s+\\w*(Swap|Order|Request|Trade|Route|Action)\\w*'}, {'function.body_contains_regex': '(?i)Yolo\\s*\\{|Permissive\\s*\\{|Unchecked\\s*\\{|NoLimit\\s*\\{'}, {'function.body_not_contains_regex': '(?i)deny_unknown_fields|#\\[serde\\s*\\(\\s*tag\\s*='}, {'function.not_in_skip_list': True}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}]

    _INCLUDE_LEAF_HELPERS = False
    _INVERSE_CEI = False

    def _detect(self):
        results = []
        for c in self.contracts:
            if is_vendored_or_test_contract(c):
                continue
            if not eval_preconditions(c, self._PRECONDITIONS):
                continue
            for f in c.functions_and_modifiers_declared:
                if not self._INCLUDE_LEAF_HELPERS and is_leaf_helper(f):
                    continue
                if not eval_function_match(f, self._MATCH):
                    continue
                info = [f, f" — serde-untagged-enum-first-variant-shadows-all-sibling-variants: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results


# ===========================================================================
# RU5 advisory extension (hand-authored; NOT emitted by pattern-compile).
#
# The Slither class above hardcodes the Yolo/Permissive/Unchecked/NoLimit
# variant names on Swap/Order/Request/Trade/Route/Action enums (a STRICT
# subset). It misses:
#   (a) ANY #[serde(untagged)] enum with 2+ struct-shaped variants (the
#       general first-variant-shadows-siblings shape), and
#   (b) the borsh sibling: a persisted/versioned enum where reordering /
#       inserting a variant not-at-end shifts the borsh discriminant of
#       already-stored state (deserializes old state as the wrong variant).
#
# This extension adds both as an ADVISORY axis (default OFF; enable with
# env SERDE_BORSH_CONFUSION_AXIS=1 or --axis). It emits verdict=needs-fuzz
# hypotheses (auto_credit=false, NO-AUTO-CREDIT) into a jsonl. It DEDUPS
# against the base narrow detector by reusing that class's OWN _MATCH
# regexes (A1 lesson: do not re-derive covered_by) - hits the base already
# matches are dropped, only net-new rows are written.
#
# Regenerating the Slither class from the YAML would overwrite this file;
# re-append this block if that happens (see reg_lines in the RU5 note).
# ===========================================================================
import os as _os
import re as _re
import json as _json
import argparse as _argparse

RU5_AXIS_ENV = "SERDE_BORSH_CONFUSION_AXIS"
RU5_BASE_DETECTOR = "serde-untagged-enum-first-variant-shadows-all-sibling-variants"
RU5_SKIP_DIRS = {"target", ".git", "node_modules", "vendor", "_archive",
                 "dist", "build", "out", ".auditooor"}
_WRAPPERS = {"Cow", "Box", "Arc", "Rc", "PanicOnClone", "Option", "Vec"}
_PRIMS = {"u8", "u16", "u32", "u64", "u128", "usize", "i8", "i16", "i32",
          "i64", "i128", "isize", "bool", "String", "str", "char", "f32", "f64"}
_UNTAGGED_RE = _re.compile(r"#\[serde\s*\(\s*untagged\s*\)\]")
_BORSH_RE = _re.compile(r"serializers\s*=\s*\[[^\]]*\bborsh\b|Borsh(?:Serialize|Deserialize)")
_VERSION_VARIANT_RE = _re.compile(r"^(V\d+|Latest|Legacy|V\d+[A-Za-z]|Unversioned)$")
_PERSIST_NAME_RE = _re.compile(r"(?i)(version|legacy|migrat)")
_PERSIST_PATH_RE = _re.compile(r"(?i)(versioned|migrat)")


def _ru5_axis_enabled(flag: bool) -> bool:
    return bool(flag) or _os.environ.get(RU5_AXIS_ENV, "") not in ("", "0", "false", "False")


def _ru5_base_regexes():
    """Pull the exact enum-name / variant / deny regexes out of the compiled
    class _MATCH so covered_by is deduped vs the SAME signal, not re-derived."""
    enum_re = variant_re = deny_re = None
    for clause in SerdeUntaggedEnumFirstVariantShadowsAllSiblingVariants._MATCH:
        rx = clause.get("function.body_contains_regex")
        if rx and "Swap|Order" in rx:
            enum_re = _re.compile(rx)
        if rx and "Yolo" in rx:
            variant_re = _re.compile(rx)
        nrx = clause.get("function.body_not_contains_regex")
        if nrx and "deny_unknown_fields" in nrx:
            deny_re = _re.compile(nrx)
    return enum_re, variant_re, deny_re


def _strip_comments(s: str) -> str:
    s = _re.sub(r"/\*.*?\*/", "", s, flags=_re.DOTALL)
    s = _re.sub(r"//[^\n]*", "", s)
    return s


def _split_top(body: str) -> list:
    """Split on top-level commas, honoring <> {} () [] nesting."""
    out, depth, cur = [], 0, []
    for ch in body:
        if ch in "<{([":
            depth += 1
        elif ch in ">})]":
            depth -= 1
        if ch == "," and depth == 0:
            out.append("".join(cur))
            cur = []
        else:
            cur.append(ch)
    if "".join(cur).strip():
        out.append("".join(cur))
    return out


def _match_braces(text: str, open_idx: int) -> int:
    """Return index just past the matching '}' for the '{' at open_idx."""
    depth = 0
    i = open_idx
    n = len(text)
    while i < n:
        c = text[i]
        if c == "{":
            depth += 1
        elif c == "}":
            depth -= 1
            if depth == 0:
                return i + 1
        i += 1
    return -1


def _unwrap_type(seg: str) -> str:
    """Reduce a tuple-variant inner type to its innermost PascalCase ident."""
    ids = _re.findall(r"[A-Za-z_]\w*", seg)
    ids = [x for x in ids if x not in _WRAPPERS and not x.startswith("'")]
    for x in reversed(ids):
        if x[:1].isupper():
            return x
    return ids[-1] if ids else ""


def _field_is_optional(attrs: str, ftype: str) -> bool:
    if _re.search(r"#\[serde\s*\([^)]*\b(default|skip_serializing_if)\b", attrs):
        return True
    return ftype.strip().startswith("Option<") or ftype.strip().startswith("Option ")


def _parse_struct_fields(body: str):
    """(all_field_names:set, required_field_names:set) from a struct/inline body."""
    body = _strip_comments(body)
    allf, req = set(), set()
    for seg in _split_top(body):
        seg = seg.strip()
        if not seg:
            continue
        attrs = " ".join(_re.findall(r"#\[[^\]]*\]", seg))
        seg_noattr = _re.sub(r"#\[[^\]]*\]", " ", seg).strip()
        m = _re.match(r"(?:pub(?:\s*\([^)]*\))?\s+)?([A-Za-z_]\w*)\s*:\s*(.+)$",
                      seg_noattr, _re.DOTALL)
        if not m:
            continue
        name, ftype = m.group(1), m.group(2)
        allf.add(name)
        if not _field_is_optional(attrs, ftype):
            req.add(name)
    return allf, req


def _build_struct_index(files):
    idx = {}
    for path, text in files:
        t = _strip_comments(text)
        for m in _re.finditer(r"\bstruct\s+([A-Za-z_]\w*)", t):
            name = m.group(1)
            brace = t.find("{", m.end())
            semi = t.find(";", m.end())
            if brace == -1 or (semi != -1 and semi < brace):
                continue  # tuple/unit struct
            end = _match_braces(t, brace)
            if end == -1:
                continue
            allf, req = _parse_struct_fields(t[brace + 1:end - 1])
            idx[name] = (allf, req)
    return idx


def _enum_blocks(text: str):
    """Yield (attr_line, enum_line, name, attrs_text, body_text)."""
    lines = text.split("\n")
    for m in _re.finditer(r"(?m)^[ \t]*(?:pub(?:\s*\([^)]*\))?\s+)?enum\s+([A-Za-z_]\w*)", text):
        name = m.group(1)
        brace = text.find("{", m.end())
        if brace == -1:
            continue
        end = _match_braces(text, brace)
        if end == -1:
            continue
        enum_line = text.count("\n", 0, m.start()) + 1
        # gather contiguous attribute / doc lines directly above the enum
        i = enum_line - 2
        attr_lines = []
        while i >= 0:
            ls = lines[i].strip()
            if ls.startswith("#[") or ls.startswith("///") or ls.startswith("//!") or ls == "":
                attr_lines.append((i + 1, lines[i]))
                i -= 1
                continue
            break
        attr_lines.reverse()
        attrs_text = "\n".join(l for _, l in attr_lines)
        attr_line = enum_line
        for ln, raw in attr_lines:
            if _UNTAGGED_RE.search(raw):
                attr_line = ln
        yield attr_line, enum_line, name, attrs_text, text[brace + 1:end - 1]


def _variants(body: str):
    """Yield (name, kind, inner) where kind in {struct,tuple,unit}."""
    for seg in _split_top(_strip_comments(body)):
        seg = _re.sub(r"#\[[^\]]*\]", " ", seg).strip()
        if not seg:
            continue
        vm = _re.match(r"([A-Za-z_]\w*)\s*(.*)$", seg, _re.DOTALL)
        if not vm:
            continue
        vname, rest = vm.group(1), vm.group(2).lstrip()
        if rest.startswith("{"):
            yield vname, "struct", rest[1:rest.rfind("}")] if "}" in rest else ""
        elif rest.startswith("("):
            yield vname, "tuple", rest[1:rest.rfind(")")] if ")" in rest else ""
        else:
            yield vname, "unit", ""


def _struct_variants(body: str, struct_idx: dict):
    """Return ordered [(name, all_fields|None, req_fields|None)] for struct-shaped
    variants only (inline struct, or tuple wrapping a user struct)."""
    out = []
    for vname, kind, inner in _variants(body):
        if kind == "struct":
            allf, req = _parse_struct_fields(inner)
            out.append((vname, allf, req))
        elif kind == "tuple":
            ty = _unwrap_type(inner)
            if not ty or ty in _PRIMS or not ty[:1].isupper():
                continue  # not a user struct type
            if ty in struct_idx:
                allf, req = struct_idx[ty]
                out.append((vname, allf, req))
            else:
                out.append((vname, None, None))  # struct-shaped, fields unknown
    return out


def _field_overlap(struct_vars: list) -> bool:
    """True if an earlier variant's required set is subset of a later variant's
    full set (earlier can capture a later payload) or an earlier variant is
    all-optional (matches anything)."""
    for a in range(len(struct_vars)):
        _, a_all, a_req = struct_vars[a]
        if a_req is None:
            continue
        if len(a_req) == 0 and a_all is not None:
            return True
        for b in range(a + 1, len(struct_vars)):
            _, b_all, _b_req = struct_vars[b]
            if b_all is None:
                continue
            if a_req.issubset(b_all):
                return True
    return False


def _is_borsh_persisted(name: str, attrs: str, path: str, body: str) -> bool:
    if not _BORSH_RE.search(attrs):
        return False
    if _PERSIST_NAME_RE.search(name) or _PERSIST_PATH_RE.search(path):
        return True
    for vname, _k, _i in _variants(body):
        if _VERSION_VARIANT_RE.match(vname):
            return True
    return False


def ru5_analyze(files, axis_enabled: bool):
    """files: list of (path, text). Returns net-new hypothesis dict list.
    Advisory-first: returns [] when the axis is disabled."""
    if not axis_enabled:
        return []
    enum_re, variant_re, deny_re = _ru5_base_regexes()
    struct_idx = _build_struct_index(files)
    hyps = []
    for path, text in files:
        for attr_line, enum_line, name, attrs, body in _enum_blocks(text):
            full = attrs + "\n" + body
            # ---- serde untagged axis ----
            if _UNTAGGED_RE.search(attrs):
                deny = bool(deny_re and deny_re.search(full))
                svars = _struct_variants(body, struct_idx)
                if not deny and len(svars) >= 2:
                    body_line = attrs + "\nenum " + name + " {" + body + "}"
                    covered = bool(enum_re and variant_re
                                   and enum_re.search(body_line)
                                   and variant_re.search(body_line))
                    if covered:
                        continue  # dedup: base narrow detector already fires
                    hyps.append({
                        "detector": RU5_BASE_DETECTOR,
                        "axis": "serde_untagged_field_overlap",
                        "file": path, "line": attr_line, "enum": name,
                        "variants": [v[0] for v in svars],
                        "field_overlap": _field_overlap(svars),
                        "verdict": "needs-fuzz", "auto_credit": False,
                        "covered_by": None, "severity_hint": "advisory",
                        "evidence": ("#[serde(untagged)] enum with %d struct "
                                     "variants; serde tries variants in order and "
                                     "the first to parse wins - a permissive earlier "
                                     "variant can silently shadow required fields of "
                                     "later ones. field_overlap=%s. Fuzz round-trip "
                                     "each variant's canonical payload."
                                     % (len(svars), _field_overlap(svars))),
                    })
            # ---- borsh reorder-discriminant axis ----
            if _is_borsh_persisted(name, attrs, path, body):
                vs = [v[0] for v in _variants(body)]
                if len(vs) >= 2:
                    hyps.append({
                        "detector": RU5_BASE_DETECTOR,
                        "axis": "borsh_reorder_discriminant",
                        "file": path, "line": enum_line, "enum": name,
                        "variants": vs, "field_overlap": None,
                        "verdict": "needs-fuzz", "auto_credit": False,
                        "covered_by": None, "severity_hint": "advisory",
                        "evidence": ("borsh-serialized persisted/versioned enum: "
                                     "borsh encodes the variant index as the "
                                     "discriminant, so reordering or inserting a "
                                     "variant not-at-end shifts the discriminant of "
                                     "already-stored state and deserializes it as the "
                                     "wrong variant. Fuzz old-bytes -> new-layout "
                                     "round-trip across a variant insert/reorder."),
                    })
    return hyps


def _iter_rs(paths):
    for p in paths:
        if _os.path.isfile(p) and p.endswith(".rs"):
            try:
                with open(p, encoding="utf-8", errors="replace") as fh:
                    yield p, fh.read()
            except OSError:
                continue
            continue
        for dp, dns, fns in _os.walk(p):
            dns[:] = [d for d in dns if d not in RU5_SKIP_DIRS]
            for fn in fns:
                if not fn.endswith(".rs"):
                    continue
                fp = _os.path.join(dp, fn)
                try:
                    with open(fp, encoding="utf-8", errors="replace") as fh:
                        yield fp, fh.read()
                except OSError:
                    continue


def ru5_scan(paths, axis_enabled: bool):
    return ru5_analyze(list(_iter_rs(paths)), axis_enabled)


def _ru5_main(argv=None) -> int:
    ap = _argparse.ArgumentParser(
        description="RU5 advisory: serde/borsh confusion hypotheses (needs-fuzz).")
    ap.add_argument("path", nargs="*", help="file(s)/dir(s) of .rs source")
    ap.add_argument("--axis", action="store_true",
                    help="enable the advisory axis (else honors %s env)" % RU5_AXIS_ENV)
    ap.add_argument("--emit", help="write net-new hypotheses jsonl to this path")
    ap.add_argument("--print-json", action="store_true")
    args = ap.parse_args(argv)
    enabled = _ru5_axis_enabled(args.axis)
    hyps = ru5_scan(args.path, enabled) if args.path else []
    if args.emit:
        with open(args.emit, "w", encoding="utf-8") as fh:
            for h in hyps:
                fh.write(_json.dumps(h, sort_keys=True) + "\n")
    if args.print_json or not args.emit:
        print(_json.dumps({"axis_enabled": enabled, "count": len(hyps),
                           "hypotheses": hyps}, indent=2))
    return 0


if __name__ == "__main__":
    import sys as _sys
    _sys.exit(_ru5_main())
