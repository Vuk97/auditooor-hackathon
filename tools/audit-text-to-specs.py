#!/usr/bin/env python3
"""
audit-text-to-specs.py — mechanical raw-audit-text → draft YAML spec
generator. Walks the three raw corpus directories (Zellic .txt, Hexens
.txt, and Code4rena .txt), finds individual finding sections using
heuristic regex, classifies each finding against one of the 5 skeletons,
and emits draft YAML specs under
`detectors/_specs/drafts_audit_text/<kebab-name>.yaml`.

Usage:
    python3 tools/audit-text-to-specs.py [--all]
    python3 tools/audit-text-to-specs.py <file.txt> [<file.txt> ...]

Zero agent tokens — pure stdlib regex parsing. Structurally ~90%
identical to `tools/slice-to-specs.py`. Fixture identifiers are always
derived from the regex hints so the vulnerable fixture is guaranteed to
match its own detector.

Corpus location:
    - Zellic / Hexens text corpora come from reference/corpus_txt/
    - Code4arena text corpus comes from $AUDITOOOR_C4_DIR if set, otherwise
      reference/corpus_txt/code4arena/
"""
import os
import re
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
ZELLIC_DIR = REPO / "reference" / "corpus_txt" / "zellic"
HEXENS_DIR = REPO / "reference" / "corpus_txt" / "hexens"
C4_DIR = Path(os.environ.get("AUDITOOOR_C4_DIR", REPO / "reference" / "corpus_txt" / "code4arena"))
SPECS_DRAFTS = REPO / "detectors" / "_specs" / "drafts_audit_text"
SPECS_DRAFTS.mkdir(parents=True, exist_ok=True)

# ---------- filtering helpers -------------------------------------------------

NON_EVM_KEYWORDS = (
    "solana", "rust", "cairo", "cosmwasm", "substrate", "near",
    "anza", "bpf", "move", "stylus", "sui", "aptos", "ton-",
    "_ton", "polkadot", "fuel-", "fuel_",
)

INFO_SEVERITIES = {"INFORMATIONAL", "INFO", "GAS", "STYLE", "QA", "NON-CRITICAL", "N/A"}


def _is_non_evm_filename(path: Path) -> bool:
    low = path.name.lower()
    return any(kw in low for kw in NON_EVM_KEYWORDS)


def _kebabize(name: str) -> str:
    s = re.sub(r"[^A-Za-z0-9]+", "-", name).strip("-").lower()
    s = re.sub(r"-+", "-", s)
    # Detectors become Python module names — must start with a letter.
    if s and s[0].isdigit():
        s = "f-" + s
    return s[:70]


def _pascal(name: str) -> str:
    parts = [p for p in _kebabize(name).split("-") if p]
    return "".join(p.capitalize() for p in parts) or "Finding"


# ---------- skeleton classifier ----------------------------------------------

def _classify_skeleton(name: str, desc: str) -> str:
    blob = f"{name} {desc}".lower()

    if (
        ("pair" in blob and ("add" in blob or "remove" in blob))
        or ("inverse" in blob and ("write" in blob or "update" in blob))
        or "not-cascade" in blob
        or ("does not" in blob and "transfer" in blob and ("flag" in blob or "counter" in blob))
        or ("addliquidity" in blob.replace(" ", "") and "removeliquidity" in blob.replace(" ", ""))
    ):
        return "paired_function_divergence"

    if (
        ("calls" in blob and "without" in blob and ("call" in blob or "invok" in blob))
        or "missing-check" in blob
        or "sibling" in blob
        or ("external call" in blob and "without" in blob)
    ):
        return "highlevelcall_missing_sibling"

    if (
        (("require" in blob or "assert" in blob or "check" in blob)
         and ("cap" in blob or "max" in blob or "bound" in blob or "guard" in blob
              or "limit" in blob or "ceiling" in blob or "zero" in blob
              or "valid" in blob or "nonzero" in blob))
        or "uncapped" in blob
        or "unchecked" in blob
        or "missing-validat" in blob
        or "insufficient validation" in blob
        or "lack of check" in blob
        or "lacks" in blob
        or "no check" in blob
    ):
        return "name_match_missing_require"

    if (
        ("sets" in blob and ("not reset" in blob or "not cleared" in blob or "stale" in blob))
        or "stale-flag" in blob
        or "paired field" in blob
        or "semantically paired" in blob
        or ("without updating" in blob)
        or ("does not update" in blob)
    ):
        return "state_write_without_paired_write"

    return "name_match_missing_call"


# ---------- regex hint extractors --------------------------------------------

def _ticked_idents(text: str):
    """Return backticked-code identifiers from a description blob."""
    raw = re.findall(r"`([A-Za-z_][A-Za-z0-9_]*)(?:\([^)]*\))?`", text)
    seen, out = set(), []
    for r in raw:
        if r in seen:
            continue
        if r.startswith("_") or len(r) < 3:
            continue
        if r.lower() in {"true", "false", "this", "msg", "sender", "address"}:
            continue
        seen.add(r)
        out.append(r)
    return out


def _camel_idents(text: str):
    """Find camelCase function-name candidates outside backticks."""
    raw = re.findall(r"\b([a-z][a-zA-Z0-9]*[A-Z][a-zA-Z0-9]+)\b", text)
    seen, out = set(), []
    for r in raw:
        if r in seen:
            continue
        if len(r) < 4 or len(r) > 32:
            continue
        if r.lower() in {"msgsender", "txorigin", "blocktimestamp"}:
            continue
        seen.add(r)
        out.append(r)
    return out


def _guess_fn_regex(name: str, desc: str) -> str:
    blob = f"{desc} {name}"
    ticked = _ticked_idents(blob)
    if ticked:
        return ".*(" + "|".join(re.escape(t) for t in ticked[:3]) + ").*"
    camel = _camel_idents(blob)
    if camel:
        return ".*(" + "|".join(re.escape(t) for t in camel[:3]) + ").*"
    tokens = [t for t in _kebabize(name).split("-")
              if len(t) > 3 and t not in {"missing", "without", "check", "function"}]
    if tokens:
        return ".*(" + "|".join(tokens[:3]) + ").*"
    return ".*"


def _guess_var_regex(desc: str) -> str:
    ticked = _ticked_idents(desc)
    candidates = [t for t in ticked if (t[0].islower())]
    if candidates:
        return ".*(" + "|".join(sorted(set(candidates))[:3]) + ").*"
    return ".*(balance|amount|total|supply|reserve).*"


def _guess_required_call_regex(desc: str) -> str:
    m = re.search(
        r"without\s+(?:a\s+)?(?:call\s+to\s+|calling\s+)`?([A-Za-z_][A-Za-z0-9_]*)`?",
        desc, re.I,
    )
    if m:
        return rf".*{re.escape(m.group(1))}.*"
    m = re.search(
        r"does not (?:contain|have|call) .*?`([A-Za-z_][A-Za-z0-9_]*)`",
        desc, re.I,
    )
    if m:
        return rf".*{re.escape(m.group(1))}.*"
    return ".*(accrue|update|sync|validate|check|refresh).*"


# ---------- severity normalization -------------------------------------------

SEVERITY_MAP = {
    "C": "HIGH", "CRIT": "HIGH", "CRITICAL": "HIGH",
    "H": "HIGH", "HIGH": "HIGH",
    "M": "MEDIUM", "MED": "MEDIUM", "MEDIUM": "MEDIUM",
    "L": "LOW", "LOW": "LOW",
    "INFORMATIONAL": "LOW", "INFO": "LOW",
    "QA": "LOW", "NON-CRITICAL": "LOW",
}


def _norm_sev(raw: str) -> str:
    if not raw:
        return ""
    return SEVERITY_MAP.get(raw.strip().upper(), raw.strip().upper())


# ---------- source parsers ---------------------------------------------------

# Each parser yields (name, severity, desc) tuples.

ZELLIC_HEADING_RE = re.compile(
    r"^\s{0,30}(\d+\.\d+)\.?\s+(?P<title>[^\n]{3,160})$", re.MULTILINE
)
ZELLIC_SEV_RE = re.compile(
    r"Severity[^A-Za-z]{0,20}(Critical|High|Medium|Low|Informational)",
    re.IGNORECASE,
)
ZELLIC_DESC_RE = re.compile(
    r"Description\s*\n(?P<body>.+?)(?:Impact|Recommendations|Remediation|"
    r"^\s*\d+\.\d+\.?\s|\Z)",
    re.DOTALL | re.MULTILINE,
)


def parse_zellic(text: str):
    # Find every 3.x / 4.x / 5.x heading. Zellic reports always put
    # findings under `3. Detailed Findings` so we narrow to headings
    # whose number starts with 3.
    headings = []
    for m in ZELLIC_HEADING_RE.finditer(text):
        num = m.group(1)
        title = m.group("title").strip().rstrip(".")
        if not num.startswith("3."):
            continue
        # Skip obvious TOC lines (lots of dots)
        if title.count(".") >= 5:
            continue
        # Skip if title looks like a page number
        if re.fullmatch(r"\d+", title):
            continue
        headings.append((m.start(), num, title))

    # Deduplicate by (num, title) — TOC + real both exist; keep the later
    # occurrence (real section has content after it).
    by_key = {}
    for start, num, title in headings:
        by_key[(num, title)] = (start, num, title)
    headings = sorted(by_key.values(), key=lambda h: h[0])

    for i, (start, num, title) in enumerate(headings):
        end = headings[i + 1][0] if i + 1 < len(headings) else min(start + 6000, len(text))
        section = text[start:end]
        sev_m = ZELLIC_SEV_RE.search(section)
        sev = _norm_sev(sev_m.group(1)) if sev_m else ""
        desc_m = ZELLIC_DESC_RE.search(section)
        if desc_m:
            desc = desc_m.group("body")
        else:
            # Fallback: take the first 1500 chars after the heading
            desc = section[len(title):][:1500]
        desc = re.sub(r"\s+", " ", desc).strip()
        if len(desc) < 40:
            continue
        yield title, sev, desc


HEXENS_HEADING_RE = re.compile(
    r"^\s{0,10}(\d+)\.\s+(?P<title>[A-Z][A-Z0-9 /\-]{2,160})$", re.MULTILINE
)
HEXENS_SEV_RE = re.compile(
    r"SEVERITY[:\s]+(Critical|High|Medium|Low|Informational)",
    re.IGNORECASE,
)
HEXENS_DESC_RE = re.compile(
    r"DESCRIPTION[:\s]*\n(?P<body>.+?)(?:\n\s*\d+\.\s+[A-Z]|\Z)",
    re.DOTALL,
)


def parse_hexens(text: str):
    headings = []
    for m in HEXENS_HEADING_RE.finditer(text):
        num = int(m.group(1))
        title = m.group("title").strip()
        # Skip "CONTENTS" style lines and TOC
        if len(title) < 4:
            continue
        headings.append((m.start(), num, title))

    # Merge split titles (e.g. "1. CROSS-FUNCTION REENTRANCY\nLEADING TO DOUBLE DELEGATION")
    for i, (start, num, title) in enumerate(headings):
        end = headings[i + 1][0] if i + 1 < len(headings) else min(start + 6000, len(text))
        section = text[start:end]
        # Extend title with continuation lines until we hit SEVERITY
        sev_match = HEXENS_SEV_RE.search(section)
        if sev_match:
            title_blob = section[:sev_match.start()]
            # Strip numbering + leading whitespace
            title_lines = [
                ln.strip() for ln in title_blob.splitlines()[:6] if ln.strip()
            ]
            if title_lines:
                title_lines[0] = re.sub(r"^\d+\.\s*", "", title_lines[0])
                full_title = " ".join(title_lines)[:160]
            else:
                full_title = title
        else:
            full_title = title

        sev = _norm_sev(sev_match.group(1)) if sev_match else ""
        desc_m = HEXENS_DESC_RE.search(section)
        if desc_m:
            desc = desc_m.group("body")
        else:
            desc = section[:1500]
        desc = re.sub(r"\s+", " ", desc).strip()
        if len(desc) < 40:
            continue
        yield full_title, sev, desc


C4_HEADING_RE = re.compile(
    r"^\[(?P<code>[HMLCQ]-?[A-Z]*-\d{1,3})\](?P<rest>[^\n]*)$", re.MULTILINE
)


def parse_code4arena(text: str):
    headings = []
    for m in C4_HEADING_RE.finditer(text):
        code = m.group("code")
        rest = m.group("rest").strip()
        headings.append((m.start(), code, rest))

    # Dedupe: TOC entries + body entries both show the same code.
    # Keep the SECOND occurrence (later in file = full body).
    by_code = {}
    for item in headings:
        code = item[1]
        if code in by_code:
            by_code[code] = item  # overwrite, keep the latest
        else:
            by_code[code] = item
    # Actually we want to keep ALL occurrences in order, but we want to
    # extract body from the LAST occurrence since the first is the TOC.
    first_seen = {}
    last_seen = {}
    for item in headings:
        code = item[1]
        if code not in first_seen:
            first_seen[code] = item
        last_seen[code] = item

    sorted_last = sorted(last_seen.values(), key=lambda h: h[0])
    for i, (start, code, rest) in enumerate(sorted_last):
        end = sorted_last[i + 1][0] if i + 1 < len(sorted_last) else min(start + 8000, len(text))
        section = text[start:end]

        # Build title: heading line + the continuation lines until a
        # blank line OR "Submitted by" OR a URL line.
        title_parts = [rest] if rest else []
        for ln in section.splitlines()[1:12]:
            s = ln.strip()
            if not s:
                break
            if s.lower().startswith("submitted by"):
                break
            if s.startswith("http"):
                break
            if re.match(r"^[a-z0-9_-]{2,}$", s) and len(title_parts) > 0:
                # Likely a warden name list after title; stop.
                break
            title_parts.append(s)
        title = " ".join(title_parts).strip()
        title = re.sub(r"\s+", " ", title)[:200]

        # Severity from code prefix
        code_sev = code[0].upper()
        sev = _norm_sev(code_sev)

        # Description: grab text between "Submitted by" (or last URL)
        # and the next heading's position.
        desc_start = 0
        sub_m = re.search(r"Submitted by[^\n]*\n", section)
        if sub_m:
            desc_start = sub_m.end()
        # Skip URL-only lines
        body = section[desc_start:]
        lines = []
        for ln in body.splitlines():
            s = ln.strip()
            if not s:
                continue
            if s.startswith("http"):
                continue
            if re.match(r"^,$", s):
                continue
            lines.append(s)
            if len(" ".join(lines)) > 2500:
                break
        desc = " ".join(lines)
        desc = re.sub(r"\s+", " ", desc).strip()
        if len(desc) < 60:
            continue
        yield title, sev, desc


# ---------- quality filter ---------------------------------------------------

def _is_high_quality(title: str, sev: str, desc: str) -> bool:
    if not title or len(title) < 6:
        return False
    if sev in INFO_SEVERITIES:
        return False
    # Require at least one backticked identifier OR a camelCase ident
    ticked = _ticked_idents(f"{title} {desc}")
    camel = _camel_idents(f"{title} {desc}")
    if not ticked and not camel:
        return False
    # Generic titles without a function name
    lower = title.lower()
    generic_only = lower.strip() in {
        "reentrancy", "missing validation", "missing check",
        "access control", "dos", "denial of service",
    }
    if generic_only:
        return False
    return True


# ---------- spec rendering ---------------------------------------------------

def _first_alt(rx: str) -> str:
    m = re.search(r"\(([^)]+)\)", rx)
    if m:
        alt = m.group(1).split("|")[0]
        return re.sub(r"[^A-Za-z0-9_]", "", alt)
    return ""


def _render_spec(name: str, severity: str, source_tag: str, desc: str, skeleton: str) -> dict:
    short = _kebabize(name)
    if len(short) < 4:
        return None
    short_short = short if len(short) <= 64 else short[:60] + "-x"
    class_name = _pascal(short_short)
    sev = SEVERITY_MAP.get(severity.upper(), "MEDIUM") if severity else "MEDIUM"

    spec = {
        "skeleton": skeleton,
        "name": short_short,
        "class_name": class_name,
        "wave": 14,
        "severity": sev,
        "confidence": "MEDIUM",
        "source": source_tag,
        "help": desc[:180].strip(),
        "wiki_title": name[:160],
        "wiki_description": desc[:300].strip(),
        "wiki_exploit_scenario": f"Per audit finding: {desc[:200].strip()}",
        "wiki_recommendation": "See source audit report for recommended fix.",
        "contract_name": class_name,
        "state_decl": "mapping(address => uint256) internal balances;",
    }

    if skeleton == "name_match_missing_call":
        fn_regex = _guess_fn_regex(name, desc)
        read_regex = _guess_var_regex(desc)
        req_regex = _guess_required_call_regex(desc)

        fn_alt = _first_alt(fn_regex) or "buggyFn"
        var_alt = _first_alt(read_regex) or "tracked"
        req_alt = _first_alt(req_regex) or "accrue"

        fn_alt = fn_alt if (fn_alt and fn_alt[0].isalpha()) else "buggyFn"
        var_alt = var_alt.lower() if (var_alt and var_alt[0].isalpha()) else "tracked"
        req_alt = req_alt if (req_alt and req_alt[0].isalpha()) else "accrue"
        if len(var_alt) < 2:
            var_alt = "tracked"
        if len(req_alt) < 2:
            req_alt = "accrue"
        if len(fn_alt) < 2:
            fn_alt = "buggyFn"

        spec.update({
            "fn_name_regex": fn_regex,
            "read_var_regex": read_regex,
            "required_call_regex": req_regex,
            "guarded_helper_name": f"_{req_alt}",
            "vuln_fn_name": fn_alt,
            "vuln_fn_params": "",
            "vuln_fn_mutability": "internal",
            "vuln_fn_mutability_clean": "internal",
            "vuln_fn_return": "bool",
            "vuln_fn_body": f"return {var_alt} > 0;",
            "state_decl": f"uint256 internal {var_alt};",
        })
    elif skeleton == "name_match_missing_require":
        fn_regex = _guess_fn_regex(name, desc)
        write_regex = _guess_var_regex(desc)
        fn_alt = _first_alt(fn_regex) or "setParam"
        var_alt = (_first_alt(write_regex) or "tracked").lower()
        if len(var_alt) < 2:
            var_alt = "tracked"
        if not fn_alt[0].isalpha():
            fn_alt = "setParam"
        spec.update({
            "fn_name_regex": fn_regex,
            "write_var_regex": write_regex,
            "guard_var_regex": write_regex,
            "vuln_fn_name": fn_alt,
            "vuln_fn_params": "uint256 newVal",
            "vuln_fn_body_no_require": f"{var_alt} = newVal;",
            "guard_require_line": "require(newVal <= 10000, \"cap\");",
            "state_decl": f"uint256 internal {var_alt};",
        })
    elif skeleton == "paired_function_divergence":
        spec.update({
            "forward_verb": r"add",
            "inverse_verb": r"remove",
            "tracking_var_regex": _guess_var_regex(desc),
            "forward_fn_name": "addThing",
            "inverse_fn_name": "removeThing",
            "fn_params": "address account",
            "forward_body": "balances[account] += 1; counter++;",
            "inverse_body_no_tracker": "balances[account] -= 1; /* counter missing */",
            "inverse_body_with_tracker": "balances[account] -= 1; counter--;",
            "state_decl": "mapping(address => uint256) internal balances;\n    uint256 internal counter;",
        })
    elif skeleton == "highlevelcall_missing_sibling":
        fn_regex = _guess_fn_regex(name, desc)
        spec.update({
            "trigger_sig_regex": fn_regex,
            "required_sibling_regex": _guess_required_call_regex(desc),
            "target_interface_decl": "interface IT { function trigger(uint256) external; function sibling(uint256) external; }",
            "target_iface_name": "IT",
            "vuln_fn_name": "doStuff",
            "vuln_fn_params": "uint256 x",
            "trigger_call": "target.trigger(x)",
            "sibling_call": "target.sibling(x)",
            "post_trigger_body": "balances[msg.sender] = x;",
        })
    elif skeleton == "state_write_without_paired_write":
        spec.update({
            "fn_name_regex": _guess_fn_regex(name, desc),
            "primary_var_regex": _guess_var_regex(desc),
            "paired_var_regex": ".*(flag|isLong|cleared|reset|status).*",
            "vuln_fn_name": "liquidate",
            "vuln_fn_params": "address user",
            "primary_write_line": "balances[user] = 0;",
            "paired_write_line": "flags[user] = false;",
            "state_decl": "mapping(address => uint256) internal balances;\n    mapping(address => bool) internal flags;",
        })

    return spec


def _emit_spec_yaml(spec: dict, path: Path):
    lines = []
    common = ["skeleton", "name", "class_name", "wave", "severity", "confidence",
              "source", "help", "wiki_title", "wiki_description",
              "wiki_exploit_scenario", "wiki_recommendation", "contract_name"]
    for k in common:
        v = spec.get(k)
        if v is None:
            continue
        if isinstance(v, str) and ("\n" in v or len(v) > 100):
            lines.append(f"{k}: |")
            for sl in str(v).splitlines():
                lines.append(f"    {sl}")
        else:
            escaped = str(v).replace('"', '\\"')
            lines.append(f'{k}: "{escaped}"')

    for k, v in spec.items():
        if k in common:
            continue
        if isinstance(v, str) and "\n" in v:
            lines.append(f"{k}: |")
            for sl in v.splitlines():
                lines.append(f"    {sl}")
        elif isinstance(v, str):
            escaped = v.replace('"', '\\"')
            lines.append(f'{k}: "{escaped}"')
        else:
            lines.append(f"{k}: {v}")

    path.write_text("\n".join(lines) + "\n")


# ---------- driver -----------------------------------------------------------

PARSERS = {
    "zellic": parse_zellic,
    "hexens": parse_hexens,
    "code4arena": parse_code4arena,
}


def process_file(path: Path, source_kind: str, emitted_names: set) -> int:
    if _is_non_evm_filename(path):
        return 0
    try:
        text = path.read_text(errors="ignore")
    except Exception:
        return 0

    parser = PARSERS[source_kind]
    count = 0
    for title, sev, desc in parser(text):
        if not _is_high_quality(title, sev, desc):
            continue
        skeleton = _classify_skeleton(title, desc)
        source_tag = f"{source_kind} audit {path.stem}"
        spec = _render_spec(title, sev, source_tag, desc, skeleton)
        if spec is None:
            continue
        short = spec["name"]
        if short in emitted_names:
            continue
        out = SPECS_DRAFTS / f"{short}.yaml"
        if out.exists():
            emitted_names.add(short)
            continue
        _emit_spec_yaml(spec, out)
        emitted_names.add(short)
        count += 1

    return count


def main(argv):
    emitted = set()
    per_source = {"zellic": 0, "hexens": 0, "code4arena": 0}

    if not argv or argv[0] == "--all":
        buckets = [
            ("zellic", sorted(ZELLIC_DIR.glob("*.txt")) if ZELLIC_DIR.exists() else []),
            ("hexens", sorted(HEXENS_DIR.glob("*.txt")) if HEXENS_DIR.exists() else []),
            ("code4arena", sorted(C4_DIR.glob("*.txt")) if C4_DIR.exists() else []),
        ]
    else:
        # explicit file list — infer source from path
        buckets_map = {"zellic": [], "hexens": [], "code4arena": []}
        for a in argv:
            p = Path(a)
            if "zellic" in str(p).lower():
                buckets_map["zellic"].append(p)
            elif "hexens" in str(p).lower():
                buckets_map["hexens"].append(p)
            elif "code4arena" in str(p).lower() or "c4" in str(p).lower():
                buckets_map["code4arena"].append(p)
        buckets = list(buckets_map.items())

    for kind, files in buckets:
        for p in files:
            if not p.exists():
                continue
            n = process_file(p, kind, emitted)
            per_source[kind] += n
            if n:
                print(f"  [{kind}] {p.name}: {n}")

    total = sum(per_source.values())
    print(f"\n[summary] {total} draft specs written to {SPECS_DRAFTS}")
    for k, v in per_source.items():
        print(f"  {k}: {v}")


if __name__ == "__main__":
    main(sys.argv[1:])
