#!/usr/bin/env python3
"""
defihacklabs-to-specs.py — mechanical DeFiHackLabs PoC → draft YAML spec generator.

Walks `<CORPUS>/YYYY-MM/*_exp.sol` for years 2024-2026, parses the header
comment block for Total Lost / Attacker / Attack Contract / Attack Tx /
Vulnerable Contract / Vulnerability, scans the body for telltale function
names, classifies the PoC to one of the 5 skeletons, and emits a draft
YAML spec under `detectors/_specs/drafts_defihacklabs/`.

Usage:
    python3 tools/defihacklabs-to-specs.py [--all | <file.sol> ...]

Corpus location:
    - $AUDITOOOR_DEFIHACKLABS_CORPUS if set
    - otherwise reference/corpus_txt/defihacklabs/ under the repo root

Zero agent tokens — pure text processing, stdlib only.

Skeleton classifier (priority order):
  highlevelcall_missing_sibling   flash loan / oracle / callback without guard
  name_match_missing_call          reentrancy — missing nonReentrant
  name_match_missing_require       access-control / rounding / precision
  name_match_missing_call          fallback

Dedupe: first file that matches a given project-name slug wins; subsequent
PoCs for the same protocol are skipped. Projects obviously tied to stock
Uniswap V2/V3 routers (no custom victim contract) are also skipped.
"""
import os
import re
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
CORPUS = Path(
    os.environ.get(
        "AUDITOOOR_DEFIHACKLABS_CORPUS",
        REPO / "reference" / "corpus_txt" / "defihacklabs",
    )
)
SPECS_DRAFTS = REPO / "detectors" / "_specs" / "drafts_defihacklabs"
SPECS_DRAFTS.mkdir(parents=True, exist_ok=True)

YEARS = {"2024", "2025", "2026"}

# ---- Regex sync with slice-to-specs.py ----
HEADER_TOTAL_LOST = re.compile(r"@KeyInfo\s*-\s*Total\s*Lost\s*:\s*(.+)", re.I)
HEADER_ATTACKER = re.compile(r"Attacker\s*:\s*(?:https?://\S+/(?:address/)?)?(0x[a-fA-F0-9]{40})", re.I)
HEADER_ATTACK_CONTRACT = re.compile(
    r"Attack\s*Contract\s*:\s*(?:https?://\S+/(?:address/)?)?(0x[a-fA-F0-9]{40})", re.I
)
HEADER_VULN_CONTRACT = re.compile(
    r"(?:Vulnerable|Victim)\s*Contract\s*:\s*(?:https?://\S+/(?:address/)?)?(0x[a-fA-F0-9]{40})",
    re.I,
)
HEADER_ATTACK_TX = re.compile(r"Attack\s*Tx\s*:?\s*(?:https?://\S+/)?(0x[a-fA-F0-9]{64})", re.I)
HEADER_VULN_TYPE = re.compile(r"@Vulnerability\s*:\s*(.+)", re.I)

# Body heuristic patterns
BODY_FLASHLOAN_CALLBACK = re.compile(
    r"function\s+(receiveFlashLoan|executeOperation|onFlashLoan|flashLoanCallback|uniswapV2Call|uniswapV3FlashCallback|pancakeCall)\b"
)
BODY_REENTRANT_CALL = re.compile(
    r"(\.call\{[^}]*value\s*:[^}]*\}|\.transfer\(|\.send\(|onERC721Received|onERC1155Received|tokensReceived)"
)
BODY_ORACLE_FN = re.compile(
    r"\b(getPrice|latestAnswer|getReserves|price0CumulativeLast|price1CumulativeLast|consult|quote|getAmountsOut|getTwap|latestRoundData)\b"
)
BODY_ACL_HINT = re.compile(
    r"(onlyOwner|onlyAdmin|onlyRole|_authorize|Ownable|AccessControl)"
)
BODY_SWAP_FN = re.compile(
    r"\b(swap|swapExactTokens|swapTokensForExactTokens|skim|sync)\s*\(",
)
BODY_ROUNDING = re.compile(r"\b(mulDiv|roundDown|roundUp|precision|rounding|dust)\b", re.I)

# Custom victim-contract detection: if the file imports only Uniswap and
# references no custom interface, skip.
BODY_CUSTOM_INTERFACE = re.compile(r"\binterface\s+(I[A-Z][A-Za-z0-9_]*)\b")
BODY_VICTIM_VAR = re.compile(r"\b(victim|target|vulnerable)\s*=\s*0x[a-fA-F0-9]{40}", re.I)
BODY_VICTIM_CONTRACT_CALL = re.compile(r"\bvictim(Contract)?\.[a-zA-Z_][a-zA-Z0-9_]*\s*\(")

# Project-name dedupe: collapse versioned / tokenised suffixes
DEDUPE_SUFFIXES = re.compile(
    r"(?:_first|_second|_third|_1|_2|_3|_v[0-9]+|_exp|_attack|_poc|_hack|_token)+$",
    re.I,
)


def _kebabize(name: str) -> str:
    s = re.sub(r"[^A-Za-z0-9]+", "-", name).strip("-").lower()
    s = re.sub(r"-+", "-", s)
    # Python module names cannot start with a digit — prefix if needed
    if s and s[0].isdigit():
        s = "poc-" + s
    return s[:70] or "unnamed"


def _pascal(name: str) -> str:
    parts = [p for p in _kebabize(name).split("-") if p]
    return "".join(p.capitalize() for p in parts) or "Poc"


def _project_from_filename(fname: str) -> str:
    base = fname
    if base.endswith("_exp.sol"):
        base = base[: -len("_exp.sol")]
    elif base.endswith(".sol"):
        base = base[: -len(".sol")]
    return base


def _dedupe_key(project: str) -> str:
    p = project.lower()
    p = DEDUPE_SUFFIXES.sub("", p)
    p = re.sub(r"[^a-z0-9]+", "", p)
    return p or project.lower()


def parse_header(text: str) -> dict:
    # Take first 80 lines — the comment header sits above the contract body.
    head = "\n".join(text.splitlines()[:80])
    out = {}
    m = HEADER_TOTAL_LOST.search(head)
    if m:
        out["total_lost"] = m.group(1).strip().rstrip("*/ ").strip()
    m = HEADER_ATTACKER.search(head)
    if m:
        out["attacker"] = m.group(1)
    m = HEADER_ATTACK_CONTRACT.search(head)
    if m:
        out["attack_contract"] = m.group(1)
    m = HEADER_VULN_CONTRACT.search(head)
    if m:
        out["vulnerable_contract"] = m.group(1)
    m = HEADER_ATTACK_TX.search(head)
    if m:
        out["attack_tx"] = m.group(1)
    m = HEADER_VULN_TYPE.search(head)
    if m:
        out["vuln_type"] = m.group(1).strip().rstrip("*/ ").strip()
    return out


def analyze_body(text: str) -> dict:
    """Return heuristic flags about the PoC body."""
    flags = {
        "has_flashloan_callback": bool(BODY_FLASHLOAN_CALLBACK.search(text)),
        "has_reentrancy_callback": bool(BODY_REENTRANT_CALL.search(text)),
        "has_oracle_fn": bool(BODY_ORACLE_FN.search(text)),
        "has_acl_hint": bool(BODY_ACL_HINT.search(text)),
        "has_swap_fn": bool(BODY_SWAP_FN.search(text)),
        "has_rounding_hint": bool(BODY_ROUNDING.search(text)),
        "has_custom_victim": bool(BODY_VICTIM_VAR.search(text) or BODY_VICTIM_CONTRACT_CALL.search(text)),
    }
    # First custom interface name — becomes the target hint
    ifaces = BODY_CUSTOM_INTERFACE.findall(text)
    ifaces = [i for i in ifaces if i not in {"IERC20", "IERC721", "IERC1155", "IWETH", "IWBNB"}]
    flags["custom_iface"] = ifaces[0] if ifaces else ""
    # Flash loan callback name
    fm = BODY_FLASHLOAN_CALLBACK.search(text)
    flags["flash_callback_name"] = fm.group(1) if fm else ""
    # First "victim-like" function call: victim.FOO( or victimContract.FOO(
    vm = re.search(r"victim(?:Contract)?\s*\.\s*([a-zA-Z_][a-zA-Z0-9_]*)\s*\(", text)
    flags["victim_fn"] = vm.group(1) if vm else ""
    return flags


def classify_skeleton(project: str, header: dict, body: dict) -> tuple:
    """Return (skeleton_name, bug_class_label)."""
    name_blob = (project + " " + header.get("vuln_type", "")).lower()

    # 1. Flashloan
    if body["has_flashloan_callback"] or "flash" in name_blob or "flashloan" in name_blob:
        return ("highlevelcall_missing_sibling", "flashloan")

    # 2. Reentrancy
    if "reentr" in name_blob or (body["has_reentrancy_callback"] and body["has_custom_victim"]):
        return ("name_match_missing_call", "reentrancy")

    # 3. Oracle manipulation
    if "oracle" in name_blob or "price" in name_blob or body["has_oracle_fn"]:
        return ("highlevelcall_missing_sibling", "oracle")

    # 4. Access control
    if (
        "accesscontrol" in name_blob
        or "acl" in name_blob
        or "unprotected" in name_blob
        or "auth" in name_blob
    ):
        return ("name_match_missing_require", "access-control")

    # 5. Rounding / precision
    if body["has_rounding_hint"] or "round" in name_blob or "precision" in name_blob:
        return ("name_match_missing_require", "rounding")

    # 6. Swap manipulation
    if body["has_swap_fn"]:
        return ("name_match_missing_call", "swap")

    # Fallback
    return ("name_match_missing_call", "generic")


def render_spec(
    project: str,
    year_month: str,
    header: dict,
    body: dict,
    skeleton: str,
    bug_class: str,
) -> dict:
    short = _kebabize(project + "-" + year_month)
    class_name = _pascal(short)
    severity = "HIGH"
    if bug_class in {"rounding"}:
        severity = "MEDIUM"

    loss = header.get("total_lost", "unknown")
    attacker = header.get("attacker", "unknown")
    attack_tx = header.get("attack_tx", "unknown")
    vuln_addr = header.get("vulnerable_contract", "")
    vuln_type = header.get("vuln_type", bug_class)

    wiki_desc = (
        f"Real-world exploit reproduced by DeFiHackLabs ({year_month}): "
        f"{project} lost {loss}. Bug class: {bug_class}. "
        f"Attack tx: {attack_tx}."
    )
    wiki_scen = (
        f"Attacker ({attacker}) exploits {project} via {bug_class}: the victim "
        f"contract {vuln_addr or '(unknown)'} exposes a code path that can be "
        f"triggered without the guard expected by the {skeleton} skeleton."
    )
    wiki_reco = {
        "flashloan": "Validate msg.sender against the trusted flash-loan provider inside the callback; require `initiator == address(this)`; never trust untrusted callers with flash-loan callback dispatch.",
        "reentrancy": "Apply the nonReentrant modifier (OZ ReentrancyGuard) to every externally-callable state-mutating entry point that transfers value, and follow the checks-effects-interactions pattern.",
        "oracle": "Replace spot-price reads with a TWAP wrapper (e.g., Uniswap V3 OracleLibrary.consult) and require a minimum observation window; sanity-check prices against a reference oracle.",
        "access-control": "Restrict the entry point with onlyOwner / onlyRole and require(msg.sender == expected) before performing any privileged state mutation.",
        "rounding": "Use mulDiv with explicit rounding direction; require the resulting amount to stay within tolerance bounds; never round user-withdraw amounts up.",
        "swap": "Validate the full swap path and slippage; require(amountOut >= minAmountOut) and enforce deadlines; reject attacker-controlled tokens in the path.",
        "generic": "Add the missing guard identified by the skeleton; cross-reference the DeFiHackLabs PoC for the exact bug path.",
    }.get(bug_class, "Add the missing guard identified by the skeleton.")

    spec = {
        "skeleton": skeleton,
        "name": short,
        "class_name": class_name,
        "wave": 14,
        "severity": severity,
        "confidence": "MEDIUM",
        "source": f"DeFiHackLabs PoC {year_month}/{project}_exp.sol",
        "help": f"{project} {year_month} — {bug_class} exploit ({loss})",
        "wiki_title": f"{project} ({year_month}) — {bug_class}",
        "wiki_description": wiki_desc[:300],
        "wiki_exploit_scenario": wiki_scen[:400],
        "wiki_recommendation": wiki_reco,
        "contract_name": class_name,
    }

    # Skeleton-specific fields — keep everything self-consistent so the
    # generated fixture matches its own detector. The generated fixture
    # always calls `target.<trigger_name>(x)`, so the `trigger_sig_regex`
    # MUST match the literal trigger name embedded into the interface
    # declaration. Same reasoning for the required sibling regex.
    if skeleton == "highlevelcall_missing_sibling":
        if bug_class == "flashloan":
            trig = body["flash_callback_name"] or "receiveFlashLoan"
            if not re.match(r"^[a-zA-Z_]\w*$", trig):
                trig = "receiveFlashLoan"
            sibling_fn = "validateInitiator"
            spec.update({
                "trigger_sig_regex": f".*({re.escape(trig)}).*",
                "required_sibling_regex": f".*({sibling_fn}).*",
                "target_interface_decl": (
                    f"interface IT {{ function {trig}(uint256) external; "
                    f"function {sibling_fn}(uint256) external; }}"
                ),
                "target_iface_name": "IT",
                "vuln_fn_name": "doFlash",
                "vuln_fn_params": "uint256 x",
                "trigger_call": f"target.{trig}(x)",
                "sibling_call": f"target.{sibling_fn}(x)",
                "post_trigger_body": "balances[msg.sender] = x;",
                "state_decl": "mapping(address => uint256) internal balances;",
            })
        else:  # oracle
            trig = "getPrice"
            sibling_fn = "validatePrice"
            spec.update({
                "trigger_sig_regex": f".*({trig}).*",
                "required_sibling_regex": f".*({sibling_fn}).*",
                "target_interface_decl": (
                    f"interface IT {{ function {trig}(uint256) external; "
                    f"function {sibling_fn}(uint256) external; }}"
                ),
                "target_iface_name": "IT",
                "vuln_fn_name": "readPrice",
                "vuln_fn_params": "uint256 x",
                "trigger_call": f"target.{trig}(x)",
                "sibling_call": f"target.{sibling_fn}(x)",
                "post_trigger_body": "balances[msg.sender] = x;",
                "state_decl": "mapping(address => uint256) internal balances;",
            })
    elif skeleton == "name_match_missing_call":
        # The fixture's helper is called `{GUARDED_HELPER_NAME}()` and the
        # clean variant must match `required_call_regex`. The vulnerable
        # fn body reads a state var whose name must match `read_var_regex`.
        if bug_class == "reentrancy":
            fn_hint = body.get("victim_fn") or "withdraw"
            if not re.match(r"^[a-zA-Z_]\w*$", fn_hint):
                fn_hint = "withdraw"
            spec.update({
                "fn_name_regex": f".*({re.escape(fn_hint)}).*",
                "read_var_regex": r".*(balance).*",
                "required_call_regex": r".*(nonReentrant).*",
                "guarded_helper_name": "nonReentrant",
                "vuln_fn_name": fn_hint,
                "vuln_fn_params": "",
                "vuln_fn_mutability": "internal",
                "vuln_fn_mutability_clean": "internal",
                "vuln_fn_return": "bool",
                "vuln_fn_body": "return balance > 0;",
                "state_decl": "uint256 internal balance;",
            })
        else:
            fn_hint = body.get("victim_fn") or "exploit"
            if not re.match(r"^[a-zA-Z_]\w*$", fn_hint):
                fn_hint = "exploit"
            spec.update({
                "fn_name_regex": f".*({re.escape(fn_hint)}).*",
                "read_var_regex": r".*(balance).*",
                "required_call_regex": r".*(accrueGuard).*",
                "guarded_helper_name": "accrueGuard",
                "vuln_fn_name": fn_hint,
                "vuln_fn_params": "",
                "vuln_fn_mutability": "internal",
                "vuln_fn_mutability_clean": "internal",
                "vuln_fn_return": "bool",
                "vuln_fn_body": "return balance > 0;",
                "state_decl": "uint256 internal balance;",
            })
    elif skeleton == "name_match_missing_require":
        fn_hint = body.get("victim_fn") or ("setAdmin" if bug_class == "access-control" else "withdraw")
        if not re.match(r"^[a-zA-Z_]\w*$", fn_hint):
            fn_hint = "setAdmin"
        spec.update({
            "fn_name_regex": f".*({re.escape(fn_hint)}).*",
            "write_var_regex": r".*(admin|owner|balance|amount).*",
            "guard_var_regex": r".*(admin|owner|balance|amount).*",
            "vuln_fn_name": fn_hint,
            "vuln_fn_params": "uint256 newVal",
            "vuln_fn_body_no_require": "balance = newVal;",
            "guard_require_line": 'require(msg.sender == owner, "!auth");',
            "state_decl": "uint256 internal balance;\n    address internal owner;",
        })

    return spec


def emit_yaml(spec: dict, path: Path):
    lines = []
    common_order = [
        "skeleton", "name", "class_name", "wave", "severity", "confidence",
        "source", "help", "wiki_title", "wiki_description",
        "wiki_exploit_scenario", "wiki_recommendation", "contract_name",
    ]
    for k in common_order:
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
        if k in common_order:
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


def process_file(sol: Path, year_month: str, seen: set) -> tuple:
    """Return (emitted, reason_skipped). emitted=True if spec written."""
    project = _project_from_filename(sol.name)
    key = _dedupe_key(project)
    if key in seen:
        return (False, "dedupe")
    try:
        text = sol.read_text(errors="ignore")
    except Exception:
        return (False, "read-error")

    header = parse_header(text)
    body = analyze_body(text)

    # Skip PoCs that only touch stock Uniswap / have no custom victim
    if not body["has_custom_victim"] and not header.get("vulnerable_contract"):
        # Look for any non-standard interface; if none, skip.
        if not body["custom_iface"]:
            return (False, "no-custom-victim")

    skeleton, bug_class = classify_skeleton(project, header, body)
    spec = render_spec(project, year_month, header, body, skeleton, bug_class)
    out = SPECS_DRAFTS / f"{spec['name']}.yaml"
    if out.exists():
        seen.add(key)
        return (False, "exists")
    emit_yaml(spec, out)
    seen.add(key)
    return (True, bug_class)


def walk_corpus():
    seen = set()
    year_counts = {"2024": 0, "2025": 0, "2026": 0}
    bug_counts = {}
    skip_reasons = {}
    for ym_dir in sorted(CORPUS.iterdir()):
        if not ym_dir.is_dir():
            continue
        name = ym_dir.name
        if len(name) < 4 or name[:4] not in YEARS:
            continue
        year = name[:4]
        for sol in sorted(ym_dir.glob("*_exp.sol")):
            emitted, reason = process_file(sol, name, seen)
            if emitted:
                year_counts[year] += 1
                bug_counts[reason] = bug_counts.get(reason, 0) + 1
            else:
                skip_reasons[reason] = skip_reasons.get(reason, 0) + 1
    return year_counts, bug_counts, skip_reasons


def main(argv):
    if not argv or argv[0] == "--all":
        year_counts, bug_counts, skip_reasons = walk_corpus()
        print("[year counts]")
        for y, n in year_counts.items():
            print(f"  {y}: {n}")
        print("[bug class counts]")
        for b, n in sorted(bug_counts.items(), key=lambda kv: -kv[1]):
            print(f"  {b}: {n}")
        print("[skip reasons]")
        for r, n in sorted(skip_reasons.items(), key=lambda kv: -kv[1]):
            print(f"  {r}: {n}")
        total = sum(year_counts.values())
        print(f"[summary] {total} draft specs written to {SPECS_DRAFTS}")
        return

    seen = set()
    for path in argv:
        p = Path(path)
        if not p.exists():
            print(f"  [miss] {p}", file=sys.stderr)
            continue
        ym = p.parent.name
        emitted, reason = process_file(p, ym, seen)
        print(f"  [{'ok' if emitted else 'skip'}] {p.name} ({reason})")


if __name__ == "__main__":
    main(sys.argv[1:])
