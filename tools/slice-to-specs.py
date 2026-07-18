#!/usr/bin/env python3
"""
slice-to-specs.py — mechanical slice → draft YAML spec generator.

Reads one or more corpus slice `.md` files, parses every `Novel: YES`
finding tagged `Approx: DETECTOR`, pattern-matches the detection hint
against a skeleton classifier, and emits draft YAML specs under
`detectors/_specs/drafts/`.

Usage:
    python3 tools/slice-to-specs.py <slice.md> [<slice.md> ...]
    python3 tools/slice-to-specs.py --all            # all slices in corpus_mined/

Output:
    detectors/_specs/drafts/<short_name>.yaml

Each draft spec is then either:
  1. Piped straight through gen-detector.py (if the heuristic guess is
     good enough) — see `--gen` flag.
  2. Reviewed by a human/LLM and moved to `_specs/` once confirmed.
  3. Discarded if the finding doesn't fit any skeleton.

Skeleton classifier rules (in priority order):
  paired_function_divergence:
    hint contains "pair" + "add" + "remove"
    OR hint contains "inverse" + "write"
    OR name contains "not-cascade" / "not-updated-on-transfer"
  state_write_without_paired_write:
    hint contains "sets" + "does not" + (reset|clear|update)
    OR name contains "stale" + "flag"
  highlevelcall_missing_sibling:
    hint contains "calls" + "without" + "call"
    OR name contains "missing-check"
  name_match_missing_require:
    hint contains "require" + (cap|max|bound|guard)
    OR name contains "uncapped" / "unchecked"
  name_match_missing_call (DEFAULT FALLBACK):
    anything else

Zero agent tokens — pure text processing.
"""
import re
import sys
import os
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
CORPUS = REPO / "reference" / "corpus_mined"
SPECS_DRAFTS = REPO / "detectors" / "_specs" / "drafts"
SPECS_DRAFTS.mkdir(parents=True, exist_ok=True)

# Primary extraction regex for a slice finding line:
#   - **<name>** (<SEVERITY>) [optional `[EVM]`] — <description>. Detect: <hint>. Approx: <APPROX>. Novel: <NOVEL>. [Source: ...]
LINE_RE = re.compile(
    r"\*\*(?P<name>[^*]+)\*\*\s*"
    r"\((?P<severity>CRITICAL|HIGH|MEDIUM|LOW|INFORMATIONAL|C|H|M|L)\)\s*"
    r"(?:`?\[EVM\]`?\s*)?"
    r"[—\-]\s*(?P<desc>.+?)\s*"
    r"(?:Detect(?:ion)?:\s*(?P<detect>.+?)\s*)?"
    r"Approx:\s*(?P<approx>DETECTOR|GREP|DOCS-ONLY|DOCS)\s*\.\s*"
    r"Novel:\s*(?P<novel>YES|NO|MAYBE|UNKNOWN)",
    re.IGNORECASE,
)

SEVERITY_MAP = {
    "C": "CRITICAL", "H": "HIGH", "M": "MEDIUM", "L": "LOW",
    "CRITICAL": "HIGH",   # we cap at HIGH in our rubric mapping
    "HIGH": "HIGH",
    "MEDIUM": "MEDIUM",
    "LOW": "LOW",
    "INFORMATIONAL": "INFORMATIONAL",
}


def _kebabize(name: str) -> str:
    s = re.sub(r"[^A-Za-z0-9]+", "-", name).strip("-").lower()
    s = re.sub(r"-+", "-", s)
    return s


def _pascal(name: str) -> str:
    return "".join(p.capitalize() for p in _kebabize(name).split("-"))


def _classify_skeleton(name: str, desc: str, detect: str) -> str:
    blob = f"{name} {desc} {detect or ''}".lower()

    if ("pair" in blob and ("add" in blob or "remove" in blob)) \
       or ("inverse" in blob and ("write" in blob or "update" in blob)) \
       or "not-cascade" in blob \
       or ("does not" in blob and "transfer" in blob and ("flag" in blob or "counter" in blob)):
        return "paired_function_divergence"

    if ("calls" in blob and "without" in blob and "call" in blob) \
       or "missing-check" in blob \
       or "sibling" in blob:
        return "highlevelcall_missing_sibling"

    if (("require" in blob or "assert" in blob)
        and ("cap" in blob or "max" in blob or "bound" in blob or "guard" in blob
             or "limit" in blob or "ceiling" in blob)) \
       or "uncapped" in blob \
       or "unchecked" in blob \
       or "missing-validat" in blob:
        return "name_match_missing_require"

    if ("sets" in blob and ("not reset" in blob or "not cleared" in blob or "stale" in blob)) \
       or "stale-flag" in blob \
       or "paired field" in blob \
       or "semantically paired" in blob:
        return "state_write_without_paired_write"

    return "name_match_missing_call"


def _guess_fn_regex(name: str, desc: str, detect: str) -> str:
    """Extract a plausible function-name regex from the finding description."""
    # Look for backticked function names first
    ticked = re.findall(r"`([A-Za-z_][A-Za-z0-9_]*)(?:\([^)]*\))?`", f"{desc} {detect or ''}")
    if ticked:
        # First ticked identifier is usually the buggy function
        # Build an alternation of all ticked identifiers (up to 3)
        uniq = []
        for t in ticked:
            if t not in uniq and not t.startswith("_") and len(t) > 2:
                uniq.append(t)
            if len(uniq) >= 3:
                break
        if uniq:
            return ".*(" + "|".join(re.escape(u) for u in uniq) + ").*"
    # Fallback: use the finding name itself as a regex hint (kebab → alt)
    tokens = _kebabize(name).split("-")
    tokens = [t for t in tokens if len(t) > 3 and t not in {"missing", "without", "check"}]
    if tokens:
        return ".*(" + "|".join(tokens[:3]) + ").*"
    return ".*"


def _guess_var_regex(desc: str, detect: str) -> str:
    """Extract a plausible state-var regex from backticked identifiers."""
    ticked = re.findall(r"`([A-Za-z_][A-Za-z0-9_]*)`", f"{desc} {detect or ''}")
    candidates = [t for t in ticked if t.islower() or t[0].islower()]
    candidates = [c for c in candidates if c not in {"true", "false", "msg", "sender", "this"}]
    if candidates:
        return ".*(" + "|".join(sorted(set(candidates))[:3]) + ").*"
    return ".*"


def _guess_required_call_regex(desc: str, detect: str) -> str:
    """Extract the required-call hint: 'without calling X' → X."""
    m = re.search(r"without\s+(?:a\s+)?(?:call\s+to\s+|calling\s+)`?([A-Za-z_][A-Za-z0-9_]*)`?", f"{desc} {detect or ''}", re.I)
    if m:
        return rf".*{re.escape(m.group(1))}.*"
    m = re.search(r"does not (?:contain|have|call) .*?`([A-Za-z_][A-Za-z0-9_]*)`", f"{desc} {detect or ''}", re.I)
    if m:
        return rf".*{re.escape(m.group(1))}.*"
    return ".*(accrue|update|sync|validate|check|refresh).*"


def _render_spec(name: str, severity: str, source_slice: str, desc: str, detect: str, skeleton: str) -> dict:
    short = _kebabize(name)
    short_short = short if len(short) <= 64 else short[:60] + "-x"
    sev = SEVERITY_MAP.get(severity.upper(), "MEDIUM")
    confidence = "MEDIUM"
    class_name = _pascal(short_short)
    spec = {
        "skeleton": skeleton,
        "name": short_short,
        "class_name": class_name,
        "wave": 12,
        "severity": sev,
        "confidence": confidence,
        "source": f"corpus slice {source_slice}",
        "help": desc[:180].strip(),
        "wiki_title": name,
        "wiki_description": desc[:300].strip(),
        "wiki_exploit_scenario": f"Attacker exploits {name} as described: {desc[:200].strip()}",
        "wiki_recommendation": detect.strip() if detect else "See source audit report for recommended fix.",
        "contract_name": class_name,
        "state_decl": "mapping(address => uint256) internal balances;",
    }

    # Skeleton-specific params + fixture bodies.
    # CRITICAL: the fixture must be guaranteed to match its own detector.
    # Derive identifiers directly from the regex hints so the fn name,
    # state var, and required-call-name all align with the detector.
    if skeleton == "name_match_missing_call":
        fn_regex = _guess_fn_regex(name, desc, detect)
        read_regex = _guess_var_regex(desc, detect)
        req_regex = _guess_required_call_regex(desc, detect)
        # Extract the first alternative from each regex for the fixture
        def _first_alt(rx):
            m = re.search(r"\(([^)]+)\)", rx)
            if m:
                alt = m.group(1).split("|")[0]
                return re.sub(r"[^A-Za-z0-9_]", "", alt)
            return ""

        fn_alt = _first_alt(fn_regex) or "buggyFn"
        var_alt = _first_alt(read_regex) or "tracked"
        req_alt = _first_alt(req_regex) or "accrue"

        # Normalize identifiers to valid Solidity
        fn_alt = fn_alt if fn_alt and fn_alt[0].isalpha() else "fn" + fn_alt
        var_alt = var_alt.lower() if var_alt and var_alt[0].isalpha() else "tracked"
        req_alt = req_alt if req_alt and req_alt[0].isalpha() else "accrue"
        if len(var_alt) < 2: var_alt = "tracked"
        if len(req_alt) < 2: req_alt = "accrue"
        if len(fn_alt) < 2: fn_alt = "buggyFn"

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
            "contract_name": spec["contract_name"],
        })
    elif skeleton == "name_match_missing_require":
        spec.update({
            "fn_name_regex": _guess_fn_regex(name, desc, detect),
            "write_var_regex": _guess_var_regex(desc, detect),
            "guard_var_regex": _guess_var_regex(desc, detect),
            "vuln_fn_name": "setParam",
            "vuln_fn_params": "uint256 newVal",
            "vuln_fn_body_no_require": "balances[msg.sender] = newVal;",
            "guard_require_line": "require(newVal <= 10000, \"cap\");",
        })
    elif skeleton == "paired_function_divergence":
        spec.update({
            "forward_verb": r"add",
            "inverse_verb": r"remove",
            "tracking_var_regex": _guess_var_regex(desc, detect),
            "forward_fn_name": "addThing",
            "inverse_fn_name": "removeThing",
            "fn_params": "address account",
            "forward_body": "balances[account] += 1; counter++;",
            "inverse_body_no_tracker": "balances[account] -= 1; /* counter missing */",
            "inverse_body_with_tracker": "balances[account] -= 1; counter--;",
            "state_decl": "mapping(address => uint256) internal balances;\n    uint256 internal counter;",
        })
    elif skeleton == "highlevelcall_missing_sibling":
        spec.update({
            "trigger_sig_regex": _guess_fn_regex(name, desc, detect),
            "required_sibling_regex": _guess_required_call_regex(desc, detect),
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
            "fn_name_regex": _guess_fn_regex(name, desc, detect),
            "primary_var_regex": _guess_var_regex(desc, detect),
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
    for k in ["skeleton", "name", "class_name", "wave", "severity", "confidence",
              "source", "help", "wiki_title", "wiki_description",
              "wiki_exploit_scenario", "wiki_recommendation",
              "contract_name"]:
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

    # Skeleton-specific fields (excluding the common ones above)
    common = {"skeleton", "name", "class_name", "wave", "severity", "confidence",
              "source", "help", "wiki_title", "wiki_description",
              "wiki_exploit_scenario", "wiki_recommendation", "contract_name"}
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


def process_slice(slice_path: Path) -> int:
    text = slice_path.read_text()
    source_slice = slice_path.stem
    count = 0

    for line in text.splitlines():
        if "Novel: YES" not in line and "Novel: MAYBE" not in line and "Novel: UNKNOWN" not in line:
            continue
        if "Approx: DETECTOR" not in line and "Detection: DETECTOR" not in line:
            continue

        m = LINE_RE.search(line)
        if not m:
            continue

        name = m.group("name").strip()
        severity = m.group("severity").strip()
        desc = m.group("desc").strip()
        detect = m.group("detect") or ""

        skeleton = _classify_skeleton(name, desc, detect)

        spec = _render_spec(name, severity, source_slice, desc, detect, skeleton)
        short = spec["name"]
        out = SPECS_DRAFTS / f"{short}.yaml"
        # Dedupe: if a draft with this name already exists, skip
        if out.exists():
            continue
        _emit_spec_yaml(spec, out)
        count += 1

    return count


def main(argv):
    if not argv or argv[0] == "--all":
        slices = sorted(CORPUS.glob("slice_*.md")) + sorted(CORPUS.glob("code4arena_slice_*.md"))
    else:
        slices = [Path(a) if a.endswith(".md") else CORPUS / f"{a}.md" for a in argv]

    total = 0
    for sp in slices:
        if not sp.exists():
            print(f"  [miss] {sp}", file=sys.stderr)
            continue
        n = process_slice(sp)
        print(f"  [scan] {sp.name}: {n} draft spec(s)")
        total += n
    print(f"\n[summary] {total} draft specs written to {SPECS_DRAFTS}")


if __name__ == "__main__":
    main(sys.argv[1:])
