#!/usr/bin/env python3
"""
gen-detector.py — bulk Slither-detector generator from YAML specs.

Usage:
    python3 tools/gen-detector.py <spec.yaml> [<spec.yaml> ...]
    python3 tools/gen-detector.py --all            # regenerate every spec in detectors/_specs/
    python3 tools/gen-detector.py --verify <name>  # emit + run forge/slither, report pass/fail

Each spec describes a detector that fits one of the 5 skeletons in
`detectors/_skeletons/`. The generator emits:
    detectors/wave<N>/<short_name>.py          — the detector source
    detectors/wave<N>/<short_name>.test.snippet — 2-line test harness wiring
    detectors/test_fixtures/<short>_vulnerable.sol
    detectors/test_fixtures/<short>_clean.sol

And appends the test lines to `detectors/test_fixtures/run_tests.sh`.

The 5 skeletons:
    name_match_missing_call          — fn name matches regex, reads state var,
                                        doesn't call a required helper
    name_match_missing_require       — fn name matches regex, writes state var,
                                        doesn't require() on a guard var
    paired_function_divergence       — `addX` and `removeX` write different
                                        state var sets
    highlevelcall_missing_sibling    — calls X.foo() without also calling X.bar()
    state_write_without_paired_write — writes position.a without writing position.b

YAML schema (common to all skeletons):
    skeleton: name_match_missing_call
    name: isdelinquent-missing-accrual   # kebab-case, becomes ARGUMENT
    class_name: IsDelinquentMissingAccrual
    wave: 11
    severity: HIGH | MEDIUM | LOW | INFORMATIONAL
    confidence: HIGH | MEDIUM | LOW
    source: "Zellic slice_aa RFIN-26"
    help: "Debt-health check reads loan.amount without calling accrueInterest"
    wiki_title: "..."
    wiki_description: "..."
    wiki_exploit_scenario: "..."
    wiki_recommendation: "..."

    # Skeleton-specific params:
    fn_name_regex: ".*(isDelinquent|isHealthy|isLiquidatable).*"
    read_var_regex: ".*(loan|debt|borrow).*amount.*"
    required_call_regex: "accrue.*|_?updateIndex.*"

    # Fixture generation:
    contract_name: LoanHealth
    state_decl: |
        struct Loan { uint256 amount; uint256 updatedAt; }
        mapping(uint256 => Loan) internal loans;
        mapping(uint256 => uint256) internal collaterals;
    guarded_helper_name: _accrueInterest
    vuln_fn_name: _isHealthy
    vuln_fn_params: "uint256 id"
    vuln_fn_mutability: "internal view"
    vuln_fn_mutability_clean: "internal"  # clean removes `view` because it calls the helper
    vuln_fn_return: "bool"
    vuln_fn_body: |
        return loans[id].amount * 100 <= collaterals[id] * 80;
"""
import sys
import os
import re
import json
import subprocess
from pathlib import Path

# Stdlib-only minimal YAML reader — supports flat key/value + `|`-block scalars.
# We intentionally avoid pyyaml because the system python is PEP 668 locked.
def _mini_yaml_load(text: str) -> dict:
    out = {}
    lines = text.splitlines()
    i = 0
    while i < len(lines):
        raw = lines[i]
        if not raw.strip() or raw.lstrip().startswith("#"):
            i += 1
            continue
        if raw.startswith(" "):
            i += 1
            continue
        if ":" not in raw:
            i += 1
            continue
        key, _, value = raw.partition(":")
        key = key.strip()
        value = value.strip()
        if value == "|":
            # Block scalar — capture indented lines following
            block_lines = []
            i += 1
            while i < len(lines) and (lines[i].startswith("    ") or lines[i].startswith("\t") or not lines[i].strip()):
                if lines[i].strip() or block_lines:
                    block_lines.append(lines[i][4:] if lines[i].startswith("    ") else lines[i])
                i += 1
            out[key] = "\n".join(block_lines).rstrip()
            continue
        # Strip quotes
        if value.startswith('"') and value.endswith('"'):
            value = value[1:-1]
        elif value.startswith("'") and value.endswith("'"):
            value = value[1:-1]
        out[key] = value
        i += 1
    return out


class yaml:
    @staticmethod
    def safe_load(f):
        return _mini_yaml_load(f.read() if hasattr(f, "read") else f)

REPO = Path(__file__).resolve().parent.parent
SKELETONS = REPO / "detectors" / "_skeletons"
SPECS = REPO / "detectors" / "_specs"
FIXTURES = REPO / "detectors" / "test_fixtures"
RUN_TESTS = FIXTURES / "run_tests.sh"


def _render_template(tmpl_path: Path, vars: dict) -> str:
    text = tmpl_path.read_text()
    # Escape literal braces in the template, but allow {VAR} substitution
    # for known variables. We do a simple str.replace pass to avoid python format
    # conflicts with Solidity/Python brace syntax.
    for k, v in sorted(vars.items(), key=lambda x: -len(x[0])):
        text = text.replace("{" + k + "}", str(v))
    return text


def _py_string_inner(value: str) -> str:
    """Return a value that is safe inside a generated Python string literal.

    The detector templates wrap metadata as `"..."`; Solodit draft specs often
    carry multiline Markdown blocks, quotes, and backslashes. Escape only the
    inserted content so existing templates remain backwards-compatible.
    """
    return json.dumps(str(value))[1:-1]


def _solidity_source(value: str) -> str:
    """Normalize YAML-escaped Solidity snippets before fixture rendering."""
    return str(value).replace(r"\"", '"')


def _kebab_to_pascal(name: str) -> str:
    return "".join(part.capitalize() for part in name.split("-"))


def _avoid_state_function_name_collision(state_decl: str, vuln_fn_name: str, vuln_fn_body: str) -> tuple[str, str]:
    """Rename generated state identifiers that collide with the fixture function.

    Some Solodit draft specs use a compact predicate seed such as
    `uint256 internal burn;` plus `function burn()`. Solidity rejects that
    duplicate identifier before Slither can run. Renaming to `burnState` keeps
    the detector's regex hit (`burn`) while making the generated fixture
    compileable.
    """
    if not vuln_fn_name or not re.search(rf"\b{re.escape(vuln_fn_name)}\b", state_decl):
        return state_decl, vuln_fn_body
    replacement = f"{vuln_fn_name}State"
    pattern = rf"\b{re.escape(vuln_fn_name)}\b"
    return re.sub(pattern, replacement, state_decl), re.sub(pattern, replacement, vuln_fn_body)


def _load_spec(path: Path) -> dict:
    with path.open() as f:
        return yaml.safe_load(f)


def _emit_detector(spec: dict):
    skel_name = spec["skeleton"]
    short = spec["name"]
    wave = int(spec["wave"])
    class_name = spec.get("class_name") or _kebab_to_pascal(short)
    short_py = short.replace("-", "_")

    wave_dir = REPO / "detectors" / f"wave{wave}"
    wave_dir.mkdir(parents=True, exist_ok=True)

    # Prepare substitution vars
    vars = {
        "DETECTOR_NAME": short,
        "CLASS_NAME": class_name,
        "SHORT_NAME": short,
        "ARGUMENT": short,
        "SEVERITY": spec.get("severity", "MEDIUM"),
        "IMPACT": spec.get("severity", "MEDIUM"),
        "CONFIDENCE": spec.get("confidence", "MEDIUM"),
        "SOURCE": _py_string_inner(spec.get("source", "(corpus)")),
        "HELP": _py_string_inner(spec.get("help", short.replace("-", " "))),
        "WIKI_TITLE": _py_string_inner(spec.get("wiki_title", short)),
        "WIKI_DESCRIPTION": _py_string_inner(spec.get("wiki_description", "")),
        "WIKI_EXPLOIT_SCENARIO": _py_string_inner(spec.get("wiki_exploit_scenario", "")),
        "WIKI_RECOMMENDATION": _py_string_inner(spec.get("wiki_recommendation", "")),
        "CONTRACT_NAME": spec.get("contract_name", class_name),
        "STATE_DECL": _solidity_source(spec.get("state_decl", "")),
    }

    # Skeleton-specific vars
    if skel_name == "name_match_missing_call":
        vuln_fn_name = spec.get("vuln_fn_name", "vuln")
        state_decl, vuln_fn_body = _avoid_state_function_name_collision(
            _solidity_source(spec.get("state_decl", "")),
            vuln_fn_name,
            _solidity_source(spec.get("vuln_fn_body", "")),
        )
        vars["STATE_DECL"] = state_decl
        vars.update({
            "FN_NAME_REGEX": spec["fn_name_regex"],
            "READ_VAR_REGEX": spec["read_var_regex"],
            "REQUIRED_CALL_REGEX": spec["required_call_regex"],
            "GUARDED_HELPER_NAME": spec.get("guarded_helper_name", "_helper"),
            "VULN_FN_NAME": vuln_fn_name,
            "VULN_FN_PARAMS": spec.get("vuln_fn_params", ""),
            "VULN_FN_MUTABILITY": spec.get("vuln_fn_mutability", "internal"),
            "VULN_FN_MUTABILITY_CLEAN": spec.get("vuln_fn_mutability_clean", spec.get("vuln_fn_mutability", "internal")),
            "VULN_FN_RETURN": spec.get("vuln_fn_return", ""),
            "VULN_FN_BODY": vuln_fn_body,
        })
    elif skel_name == "name_match_missing_require":
        vars.update({
            "FN_NAME_REGEX": spec["fn_name_regex"],
            "WRITE_VAR_REGEX": spec["write_var_regex"],
            "GUARD_VAR_REGEX": spec["guard_var_regex"],
            "VULN_FN_NAME": spec.get("vuln_fn_name", "vuln"),
            "VULN_FN_PARAMS": spec.get("vuln_fn_params", ""),
            "VULN_FN_BODY_NO_REQUIRE": _solidity_source(spec.get("vuln_fn_body_no_require", "")),
            "GUARD_REQUIRE_LINE": _solidity_source(spec.get("guard_require_line", "")),
        })
    elif skel_name == "paired_function_divergence":
        vars.update({
            "FORWARD_VERB": spec["forward_verb"],
            "INVERSE_VERB": spec["inverse_verb"],
            "TRACKING_VAR_REGEX": spec["tracking_var_regex"],
            "FORWARD_FN_NAME": spec.get("forward_fn_name", "addThing"),
            "INVERSE_FN_NAME": spec.get("inverse_fn_name", "removeThing"),
            "FN_PARAMS": spec.get("fn_params", ""),
            "FORWARD_BODY": _solidity_source(spec.get("forward_body", "")),
            "INVERSE_BODY_NO_TRACKER": _solidity_source(spec.get("inverse_body_no_tracker", "")),
            "INVERSE_BODY_WITH_TRACKER": _solidity_source(spec.get("inverse_body_with_tracker", "")),
        })
    elif skel_name == "highlevelcall_missing_sibling":
        vars.update({
            "TRIGGER_SIG_REGEX": spec["trigger_sig_regex"],
            "REQUIRED_SIBLING_REGEX": spec["required_sibling_regex"],
            "TARGET_INTERFACE_DECL": spec.get("target_interface_decl", ""),
            "TARGET_IFACE_NAME": spec.get("target_iface_name", "IT"),
            "VULN_FN_NAME": spec.get("vuln_fn_name", "vuln"),
            "VULN_FN_PARAMS": spec.get("vuln_fn_params", ""),
            "TRIGGER_CALL": _solidity_source(spec.get("trigger_call", "")),
            "SIBLING_CALL": _solidity_source(spec.get("sibling_call", "")),
            "POST_TRIGGER_BODY": _solidity_source(spec.get("post_trigger_body", "")),
        })
    elif skel_name == "state_write_without_paired_write":
        vars.update({
            "FN_NAME_REGEX": spec["fn_name_regex"],
            "PRIMARY_VAR_REGEX": spec["primary_var_regex"],
            "PAIRED_VAR_REGEX": spec["paired_var_regex"],
            "VULN_FN_NAME": spec.get("vuln_fn_name", "vuln"),
            "VULN_FN_PARAMS": spec.get("vuln_fn_params", ""),
            "PRIMARY_WRITE_LINE": _solidity_source(spec.get("primary_write_line", "")),
            "PAIRED_WRITE_LINE": _solidity_source(spec.get("paired_write_line", "")),
        })
    else:
        raise ValueError(f"Unknown skeleton: {skel_name}")

    # Emit detector .py
    py_tmpl = SKELETONS / f"skeleton_{skel_name}.py.tmpl"
    py_text = _render_template(py_tmpl, vars)
    py_path = wave_dir / f"{short_py}.py"
    py_path.write_text(py_text)

    # Emit test snippet
    snippet_text = (
        f'run_test "{short}" "{short_py}_vulnerable.sol" "{short}"\n'
        f'run_clean_test "{short}" "{short_py}_clean.sol" "{short} (clean)"\n'
    )
    snippet_path = wave_dir / f"{short_py}.test.snippet"
    snippet_path.write_text(snippet_text)

    # Emit fixtures (only for skeletons that have matching fixture templates)
    vuln_tmpl = SKELETONS / f"fixture_{skel_name}_vulnerable.sol.tmpl"
    clean_tmpl = SKELETONS / f"fixture_{skel_name}_clean.sol.tmpl"
    if vuln_tmpl.exists() and clean_tmpl.exists():
        vuln_text = _render_template(vuln_tmpl, vars)
        clean_text = _render_template(clean_tmpl, vars)
        (FIXTURES / f"{short_py}_vulnerable.sol").write_text(vuln_text)
        (FIXTURES / f"{short_py}_clean.sol").write_text(clean_text)
    else:
        print(f"  [warn] no fixture templates for skeleton {skel_name} — hand-author fixtures", file=sys.stderr)

    return {
        "short": short,
        "wave": wave,
        "py_path": py_path,
        "snippet_path": snippet_path,
        "vuln_sol": FIXTURES / f"{short_py}_vulnerable.sol",
        "clean_sol": FIXTURES / f"{short_py}_clean.sol",
    }


def _append_to_run_tests(emissions: list, batch_label: str = None):
    """Append the test snippet lines for each emitted detector to run_tests.sh,
    inserted before the final `echo` / summary block."""
    if not emissions:
        return

    text = RUN_TESTS.read_text()
    # Find the marker — look for `echo ""` followed by `echo "========"` near the end
    marker = 'echo ""\necho "========================================="\necho " Results:'
    if marker not in text:
        # Fallback: append at the very end
        insert_point = len(text)
    else:
        insert_point = text.find(marker)

    existing_lines = set(text.splitlines())
    new_lines = ["\n"]
    if batch_label:
        new_lines.append(f"# {batch_label}\n")
    for em in emissions:
        snippet = (FIXTURES.parent / f"wave{em['wave']}" / f"{em['short'].replace('-','_')}.test.snippet").read_text()
        missing = [line for line in snippet.splitlines() if line and line not in existing_lines]
        if missing:
            new_lines.append("\n".join(missing) + "\n")
    new_block = "".join(new_lines) + "\n"

    if not any(line.strip() and not line.startswith("#") for line in new_block.splitlines()):
        return

    new_text = text[:insert_point] + new_block + text[insert_point:]
    RUN_TESTS.write_text(new_text)


def _verify(em: dict) -> bool:
    """Run the detector against its own fixtures; expect vuln ≥1, clean =0."""
    runner = REPO / "detectors" / "run_custom.py"
    ok = True
    # Make sure foundry bin is on PATH for subprocess
    env = os.environ.copy()
    env["PATH"] = f"{Path.home()}/.foundry/bin:{Path.home()}/.local/bin:{env.get('PATH','')}"
    for fixture, expect_hit in [(em["vuln_sol"], True), (em["clean_sol"], False)]:
        if not fixture.exists():
            print(f"  [skip] fixture not present: {fixture.name}")
            continue
        try:
            out = subprocess.check_output(
                ["python3", str(runner), str(fixture), em["short"]],
                stderr=subprocess.STDOUT,
                cwd=str(REPO / "detectors"),
                timeout=120,
                env=env,
            ).decode()
        except subprocess.CalledProcessError as e:
            print(f"  [fail] runner errored on {fixture.name}: {e.output.decode()[-200:]}")
            ok = False
            continue
        hits_match = re.search(r"total hits:\s*(\d+)", out)
        hits = int(hits_match.group(1)) if hits_match else 0
        if expect_hit and hits < 1:
            print(f"  [fail] {em['short']} vuln={hits} (expected ≥1)")
            ok = False
        elif not expect_hit and hits != 0:
            print(f"  [fail] {em['short']} clean={hits} (expected 0)")
            ok = False
        else:
            print(f"  [ok]   {em['short']} fixture={fixture.name[:40]:40s} hits={hits}")
    return ok


def main(argv):
    if not argv:
        print(__doc__)
        sys.exit(1)

    # Parse flags
    no_verify = False
    profile = None
    clean_argv = []
    i = 0
    while i < len(argv):
        if argv[i] == "--no-verify":
            no_verify = True
            i += 1
        elif argv[i] == "--profile":
            profile = argv[i + 1] if i + 1 < len(argv) else None
            i += 2
        else:
            clean_argv.append(argv[i])
            i += 1

    if not clean_argv:
        print(__doc__)
        sys.exit(1)

    if clean_argv[0] == "--all":
        spec_paths = sorted(SPECS.glob("*.yaml"))
    else:
        spec_paths = [Path(a) if a.endswith(".yaml") else SPECS / f"{a}.yaml" for a in clean_argv]

    # Profile-based filtering: only emit specs whose solodit_tags match the target type
    PROFILE_TAGS = {
        "lending": {"Liquidation", "Oracle", "Stale Price", "ERC4626", "Share Inflation",
                    "First Depositor Issue", "Rounding", "Lending Pool", "Flash Loan",
                    "Wrong Math", "Decimals", "Precision Loss"},
        "vault": {"ERC4626", "Share Inflation", "First Depositor Issue", "Rounding",
                  "Vault", "Deposit/Reward tokens", "Fee On Transfer", "Weird ERC20"},
        "dex": {"Uniswap", "Swap", "Slippage", "Sandwich Attack", "Front-Running",
                "TWAP", "Liquidity", "AMM"},
        "bridge": {"Cross Chain", "Replay Attack", "Chain Reorganization Attack"},
        "bundler": {"Approve", "Allowance", "Reentrancy", "Access Control",
                    "Multicall", "Callback", "ERC20", "SafeTransfer"},
    }

    emissions = []
    skipped_profile = 0
    for sp in spec_paths:
        if not sp.exists():
            print(f"  [miss] {sp}", file=sys.stderr)
            continue

        # Profile filter: read spec's solodit_tags and check overlap
        if profile and profile in PROFILE_TAGS:
            try:
                text = sp.read_text()
                tags_line = [l for l in text.splitlines() if l.startswith("solodit_tags:")]
                if tags_line:
                    tags_str = tags_line[0].split(":", 1)[1].strip().strip('"')
                    spec_tags = {t.strip() for t in tags_str.split(",") if t.strip()}
                    if spec_tags and not spec_tags & PROFILE_TAGS[profile]:
                        skipped_profile += 1
                        continue
            except Exception:
                pass  # if we can't read tags, include the spec

        try:
            spec = _load_spec(sp)
            em = _emit_detector(spec)
            emissions.append(em)
            print(f"  [emit] wave{em['wave']}/{em['short']}")
        except Exception as e:
            print(f"  [err] {sp}: {e}", file=sys.stderr)

    if skipped_profile > 0:
        print(f"  [profile={profile}] skipped {skipped_profile} specs not matching target type")

    # Append batch lines to run_tests.sh ONLY for newly generated detectors that
    # are not already registered. Caller should idempotent-append in a second pass
    # if re-generating.
    if emissions:
        _append_to_run_tests(emissions, batch_label=f"Generated by gen-detector.py — {len(emissions)} detectors")

    if no_verify:
        print(f"\n[summary] {len(emissions)} detector(s) emitted (verification skipped)")
    else:
        # Verify each
        print("\nVerification:")
        all_ok = True
        for em in emissions:
            if not _verify(em):
                all_ok = False
        if not all_ok:
            print("\n[summary] one or more detectors failed verification", file=sys.stderr)
            sys.exit(1)
        print(f"\n[summary] {len(emissions)} detector(s) emitted + verified")


if __name__ == "__main__":
    main(sys.argv[1:])
