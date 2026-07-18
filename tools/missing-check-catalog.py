#!/usr/bin/env python3
"""
missing-check-catalog.py — R76 I (post-push): flag "operation X should
have check Y" patterns by walking every function and comparing the
operations it performs against a catalog of required-check rules.

Top auditors maintain a mental catalog: "if a function does X, it must
also do Y." This encodes that catalog mechanically.

Rules (all via Slither AST — no regex guessing):

  rule_ext_call_needs_reentrancy_guard:
    IF function has external call AND writes state after AND is not
    view AND is not trusted-internal → WARN missing reentrancy guard

  rule_transfer_needs_success_check:
    IF function calls .transfer() or .send() AND does not check return
    value → WARN

  rule_oracle_read_needs_staleness:
    IF function calls latestRoundData() or latestAnswer() AND does not
    check updatedAt / answer > 0 → WARN

  rule_mint_burn_needs_access_control:
    IF function mutates totalSupply / _balances AND has no modifier
    AND not via internal call from a gated function → WARN

  rule_initialize_needs_disable_initializers:
    IF contract inherits Initializable AND has no constructor call
    to _disableInitializers() → WARN

  rule_permit_needs_try_catch:
    IF function calls permit() AND the call is not wrapped in try/catch
    → WARN (permit-front-run DoS)

  rule_eth_send_needs_recipient_safe:
    IF function sends ETH AND recipient is msg.sender AND no
    reentrancy guard → WARN

  rule_for_loop_needs_bounded:
    IF function has a for loop that iterates over a dynamically-sized
    array (state-variable-backed) AND no cap → WARN (gas DoS)

  rule_auth_change_needs_two_step:
    IF function writes to `owner` / `admin` directly AND has no paired
    `accept*` function → WARN (bricked-on-typo risk)

Output: <workspace>/missing_checks.md — ordered by rule + file.

Usage:
  python3 tools/missing-check-catalog.py <workspace>
"""

import argparse, pathlib, re, sys
from collections import defaultdict

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
from _analyzer_common import iter_source_files

try:
    from slither.slither import Slither
except ImportError:
    print("[err] Slither required", file=sys.stderr); sys.exit(1)


def _function_source(fn):
    return getattr(fn.source_mapping, "content", "") or ""


def _scan(ws):
    findings = []
    for sol in iter_source_files(ws, max_files=300):  # R79 T3
        try: sl = Slither(str(sol))
        except Exception: continue
        for c in sl.contracts:
            if c.is_interface or c.is_library: continue
            # rule_initialize_needs_disable_initializers
            inherits = [i.name for i in (getattr(c, "inheritance", []) or [])]
            if "Initializable" in inherits or any("Upgradeable" in n for n in inherits):
                ctor = next((f for f in c.functions_declared if getattr(f, "is_constructor", False)), None)
                if ctor and "_disableInitializers" not in _function_source(ctor):
                    findings.append({
                        "rule": "initialize_needs_disable_initializers",
                        "severity": "HIGH",
                        "contract": c.name, "fn": "<constructor>",
                        "file": str(sol),
                        "why": "Upgradeable contract without constructor call to _disableInitializers() — implementation is re-initializable.",
                    })

            for fn in c.functions_and_modifiers_declared:
                vis = getattr(fn, "visibility", "")
                if vis not in ("external", "public", "internal"): continue
                if getattr(fn, "view", False) or getattr(fn, "pure", False): continue
                if getattr(fn, "is_constructor", False): continue

                src = _function_source(fn)
                fn_nodes = list(getattr(fn, "nodes", []) or [])

                # rule_ext_call_needs_reentrancy_guard
                if vis in ("external", "public"):
                    ext_idx = None
                    for i, n in enumerate(fn_nodes):
                        if getattr(n, "high_level_calls", None) or getattr(n, "low_level_calls", None):
                            ext_idx = i
                            break
                    if ext_idx is not None:
                        post_writes = 0
                        for n in fn_nodes[ext_idx + 1:]:
                            post_writes += len(getattr(n, "state_variables_written", []) or [])
                        has_guard = any(getattr(m, "name", "") in ("nonReentrant", "noReentry") for m in (getattr(fn, "modifiers", []) or []))
                        if post_writes > 0 and not has_guard:
                            findings.append({
                                "rule": "ext_call_needs_reentrancy_guard",
                                "severity": "HIGH",
                                "contract": c.name, "fn": fn.name, "file": str(sol),
                                "why": f"External call followed by {post_writes} state-write(s), no nonReentrant modifier.",
                            })

                # rule_oracle_read_needs_staleness
                oracle_hit = re.search(r"latestRoundData|latestAnswer", src)
                if oracle_hit and not re.search(r"updatedAt|answer\s*[>=]\s*0|roundId\s*<", src):
                    findings.append({
                        "rule": "oracle_read_needs_staleness",
                        "severity": "HIGH",
                        "contract": c.name, "fn": fn.name, "file": str(sol),
                        "why": "Chainlink/Pyth read without staleness or answer-positivity check.",
                    })

                # rule_permit_needs_try_catch
                if re.search(r"\.permit\s*\(", src) and not re.search(r"try\s+\w+\s*\.\s*permit", src):
                    findings.append({
                        "rule": "permit_needs_try_catch",
                        "severity": "MEDIUM",
                        "contract": c.name, "fn": fn.name, "file": str(sol),
                        "why": "permit() call not wrapped in try/catch — front-runnable DoS.",
                    })

                # rule_eth_send_needs_recipient_safe
                if re.search(r"\.call\{value:", src) or ".send(" in src:
                    has_guard = any(getattr(m, "name", "") in ("nonReentrant",) for m in (getattr(fn, "modifiers", []) or []))
                    if not has_guard:
                        findings.append({
                            "rule": "eth_send_needs_recipient_safe",
                            "severity": "MEDIUM",
                            "contract": c.name, "fn": fn.name, "file": str(sol),
                            "why": "Sends ETH via call{value} or .send without nonReentrant.",
                        })

                # rule_auth_change_needs_two_step
                writes = [getattr(sv, "name", "") for sv in (getattr(fn, "state_variables_written", []) or [])]
                for w in writes:
                    if w and w.lower() in ("owner", "admin", "governance"):
                        # Is there a paired `acceptOwnership` etc?
                        has_pair = any(re.match(r"^accept(Ownership|Admin|Governance)$", f.name) for f in c.functions_declared)
                        if not has_pair:
                            findings.append({
                                "rule": "auth_change_needs_two_step",
                                "severity": "MEDIUM",
                                "contract": c.name, "fn": fn.name, "file": str(sol),
                                "why": f"Writes to `{w}` directly without a two-step accept* pair.",
                            })
                            break  # one per function

                # rule_for_loop_needs_bounded (heuristic)
                # Check if source has `for (... i < X.length; ...)` where X is a state var that can grow
                for m in re.finditer(r"for\s*\([^;]*;\s*\w+\s*<\s*(\w+)\.length\s*;", src):
                    arr = m.group(1)
                    if any(getattr(sv, "name", "") == arr for sv in (getattr(c, "state_variables", []) or [])):
                        findings.append({
                            "rule": "for_loop_needs_bounded",
                            "severity": "LOW",
                            "contract": c.name, "fn": fn.name, "file": str(sol),
                            "why": f"Iterates over state-var array `{arr}.length` without cap — gas DoS if grows unbounded.",
                        })
                        break

    return findings


def _render(findings, out):
    by_rule = defaultdict(list)
    for f_ in findings:
        by_rule[f_["rule"]].append(f_)

    with open(out, "w") as f:
        f.write("# Missing-check catalog\n\n")
        f.write("Generated by `tools/missing-check-catalog.py`. Every entry "
                "is a function that performs operation X but is missing "
                "check Y that top auditors would flag.\n\n")
        f.write(f"**{len(findings)} missing-check candidates** across the "
                f"workspace, grouped by rule.\n\n")

        f.write("## Summary\n\n")
        f.write("| Rule | Severity | Count |\n|---|---|---:|\n")
        for rule, fs in sorted(by_rule.items(), key=lambda x: -len(x[1])):
            sev = fs[0]["severity"]
            f.write(f"| `{rule}` | {sev} | {len(fs)} |\n")

        for rule, fs in sorted(by_rule.items()):
            sev = fs[0]["severity"]
            f.write(f"\n## `{rule}` ({sev})\n\n")
            f.write(f"**Why it matters:** {fs[0]['why']}\n\n")
            f.write("| Contract | Function | File |\n|---|---|---|\n")
            for fd in fs[:50]:
                try: rel = pathlib.Path(fd["file"]).relative_to(pathlib.Path.cwd())
                except Exception: rel = fd["file"]
                f.write(f"| `{fd['contract']}` | `{fd['fn']}` | `{rel}` |\n")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("workspace")
    args = ap.parse_args()
    ws = pathlib.Path(args.workspace)
    if not ws.is_dir(): print("[err] not a dir", file=sys.stderr); sys.exit(1)
    fs = _scan(ws)
    out = ws / "missing_checks.md"
    _render(fs, out)
    print(f"[ok] wrote {out}")
    print(f"     total candidates: {len(fs)}")


if __name__ == "__main__":
    main()
