#!/usr/bin/env python3
"""go_ast_msgserver_missing_authority_sibling_asymmetry - UNAUTHORIZED-STATE detector.

Impact-first detector for a permissionless message handler that creates / enqueues /
registers / mutates keeper state with NO authority gate, WHILE at least one SIBLING
handler in the SAME msg_server file DOES gate on an authority check. That sibling
asymmetry is the oracle: the authors demonstrably knew how to gate a handler and left
this one open, so the omission is almost certainly a bug rather than an intended public
entry point.

Grounded in the NUVA/Provenance vault miss (nuva_msgserver_missing_authority_LIVE):
  msgServer.CreateVault -> k.Keeper.CreateVault has NO authority guard, while its
  siblings SetShareDenomMetadata/ToggleSwapIn call vault.ValidateAdmin and the
  Update*/Pause* handlers call vault.ValidateManagementAuthority. A permissionless
  CreateVault is the precondition that upgrades a chain-halt / resource-exhaustion
  from "admin-only, DoS-of-self" to "any user, Critical": it lets an unprivileged
  caller grow the very queues a gas-unmetered consensus hook then walks unbounded.

Scope: scans msg_server*.go files (Cosmos convention: **/keeper/msg_server*.go). This
is a PER-FILE asymmetry check - the sibling oracle must hold within one message server
file so the "the authors gated the neighbor" argument is local and strong.

MECHANISM=missing-authority-gate-sibling-asymmetry
IMPACT=unauthorized-state-creation / resource-exhaustion   severity_hint=high.

Refute-first / never-false-pass: a handler is only flagged when (a) it reaches a
create/enqueue/register/mutate keeper path, (b) it has NO authority guard of any known
form, AND (c) a SIBLING handler in the same file HAS an authority guard. If no sibling
is gated (e.g. an all-public query-ish server) nothing fires - the asymmetry oracle is
what separates a real omission from a legitimately public endpoint.

Language-agnostic where practical (the func-body walker mirrors the Go/Cosmos reference
detector); the regexes are Go/Cosmos-specific by design.
"""
from __future__ import annotations

import argparse
import json
import os
import re
import sys

SCHEMA = "auditooor.mechanism_scan.msgserver_missing_authority_sibling_asymmetry.v1"
MECHANISM = "missing-authority-gate-sibling-asymmetry"
IMPACT = "unauthorized-state-creation / resource-exhaustion"
SOURCE_RECORD_ID = (
    "nuva_msgserver_missing_authority_LIVE:CreateVault-ungated + "
    "cosmos_sdk:msg-handler-authority-omission")

# A message-server handler declaration. Cosmos convention:
#   func (k msgServer) Handler(goCtx context.Context, msg *types.MsgXxxRequest) (...)
# Restrict the receiver to a *msgServer-shaped type so we do not treat arbitrary
# keeper methods as handlers.
FUNC_DECL_RE = re.compile(
    r"^\s*func\s*\(\s*\w+\s+\*?(?P<recv>\w*[mM]sgServer\w*)\s*\)\s*"
    r"(?P<name>[A-Z]\w*)\s*\(")
# Any top-level func (used by the body-walker to bound each handler).
ANY_FUNC_RE = re.compile(r"^\s*func\s*(?:\([^)]*\)\s*)?(?P<name>[A-Za-z_]\w*)\s*\(")

# A keeper create/enqueue/register/mutate path reached in the body. Two shapes:
#   k.Keeper.<Create|Enqueue|Register|Add|Set|Mint|Burn|Remove...>*(
#   k.<Create|Enqueue|Register|Add|Set...>*(
# plus collection mutators on queues/sets:  <recv>.<Enqueue|Push|Insert|Set|Remove>(
_MUTATE_VERBS = (
    r"Create|Enqueue|Register|Add|Set|Insert|Push|Append|Mint|Burn|Remove|Store|Save|Put|Update")
MUTATE_RE = re.compile(
    r"\bk\.(?:Keeper\.)?(?:" + _MUTATE_VERBS + r")\w*\s*\("
    r"|\.(?:Enqueue|Push|Insert|Append)\s*\(")

# Any known authority / permission guard. Covers the NUVA forms + common Cosmos idioms.
AUTHORITY_RE = re.compile(
    r"ValidateAdmin\s*\("
    r"|ValidateManagementAuthority\s*\("
    r"|ValidateAuthority\s*\("
    r"|\bk?\.?GetAuthority\s*\("
    r"|\bonlyGov\b"
    r"|\bhasPermission\s*\("
    r"|\bAssertPermission\s*\("
    r"|\bCheckAuthorization\s*\("
    # explicit equality guards on an authority/signer/admin field
    r"|(?:msg\.)?(?:Authority|Signer|Admin|Sender|Creator)\s*(?:!=|==)"
    r"|\bauthority\s*(?:!=|==)")


def _strip(line: str) -> str:
    """Remove string/rune/backtick literals and // comments (avoid false matches)."""
    out: list[str] = []
    i, in_str = 0, None
    while i < len(line):
        c = line[i]
        if in_str:
            if c == "\\" and i + 1 < len(line):
                i += 2
                continue
            if c == in_str:
                in_str = None
            i += 1
            continue
        if c in ('"', "'", "`"):
            in_str = c
            i += 1
            continue
        if c == "/" and i + 1 < len(line) and line[i + 1] == "/":
            break
        out.append(c)
        i += 1
    return "".join(out)


def _iter_funcs(lines: list[str]):
    """Yield (decl_re_match_or_None_kept_by_caller, name, decl_line, body_start, body_end)
    for every top-level func, using brace-depth over comment/string-stripped lines."""
    i, n = 0, len(lines)
    while i < n:
        m = ANY_FUNC_RE.match(lines[i])
        if not m:
            i += 1
            continue
        name = m.group("name")
        decl_i = i
        depth, opened, body_start, j = 0, False, -1, i
        while j < n:
            for ch in _strip(lines[j]):
                if ch == "{":
                    if not opened:
                        opened, body_start = True, j
                    depth += 1
                elif ch == "}":
                    depth -= 1
                    if opened and depth == 0:
                        yield name, decl_i, body_start, j
                        i = j + 1
                        break
            else:
                j += 1
                continue
            break
        else:
            return


def _msgserver_files(root: str):
    """msg_server*.go files (skip *_test.go)."""
    if os.path.isfile(root):
        base = os.path.basename(root)
        if base.startswith("msg_server") and base.endswith(".go") and not base.endswith("_test.go"):
            yield root
        return
    for dp, dns, fns in os.walk(root):
        dns[:] = [d for d in dns if not d.startswith(".") and d not in (
            "vendor", "node_modules", "testdata")]
        for fn in fns:
            if (fn.startswith("msg_server") and fn.endswith(".go")
                    and not fn.endswith("_test.go")):
                yield os.path.join(dp, fn)


def _scan_file(path: str, root: str) -> list[dict]:
    try:
        lines = open(path, encoding="utf-8", errors="replace").read().splitlines()
    except OSError:
        return []

    # 1. collect every msgServer handler in this file with its guard/mutate facts.
    handlers: list[dict] = []
    for name, decl_i, bs, be in _iter_funcs(lines):
        dm = FUNC_DECL_RE.match(lines[decl_i])
        if not dm:
            continue  # not a msgServer-receiver handler
        body_txt = "\n".join(_strip(l) for l in lines[bs:be + 1])
        has_auth = bool(AUTHORITY_RE.search(body_txt))
        mm = MUTATE_RE.search(body_txt)
        handlers.append({
            "name": dm.group("name"),
            "decl_line": decl_i + 1,
            "has_auth": has_auth,
            "mutate_match": mm,
            "body_txt": body_txt,
        })

    # 2. asymmetry oracle: at least one sibling handler in THIS file is gated.
    any_sibling_gated = any(h["has_auth"] for h in handlers)
    if not any_sibling_gated:
        return []  # legitimately-public server (or a query server) - do not fire

    findings: list[dict] = []
    for h in handlers:
        if h["has_auth"]:
            continue
        if not h["mutate_match"]:
            continue  # read-only / non-mutating handler - not an unauthorized-state risk
        mutate_snippet = h["mutate_match"].group(0).strip().rstrip("(")
        findings.append({
            "schema": SCHEMA,
            "mechanism": MECHANISM,
            "impact": IMPACT,
            "severity_hint": "high",
            "file": os.path.relpath(path, root) if os.path.isdir(root) else os.path.basename(path),
            "line": h["decl_line"],
            "function": h["name"],
            "mutate_call": mutate_snippet,
            "gated_siblings": sorted(
                s["name"] for s in handlers if s["has_auth"])[:8],
            "reason": (
                f"msgServer handler {h['name']} reaches a keeper mutate path "
                f"('{mutate_snippet}') with NO authority guard "
                f"(ValidateAdmin/ValidateManagementAuthority/GetAuthority/authority==), "
                f"while sibling handler(s) in the same file ARE gated -> asymmetry: an "
                f"unprivileged caller can create/enqueue/mutate state; this is the "
                f"permissionless precondition that upgrades a DoS/chain-halt to Critical"),
            "source_record_id": SOURCE_RECORD_ID,
        })
    return findings


def scan_root(root: str) -> dict:
    findings: list[dict] = []
    files: list[str] = []
    for path in _msgserver_files(root):
        files.append(path)
        findings.extend(_scan_file(path, root))
    findings.sort(key=lambda f: (f["file"], f["line"]))
    return {
        "schema": SCHEMA, "mechanism": MECHANISM, "impact": IMPACT, "root": root,
        "files_scanned": [os.path.relpath(p, root) if os.path.isdir(root)
                          else os.path.basename(p) for p in files],
        "findings": findings, "finding_count": len(findings),
    }


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("root", help="Go source tree or a msg_server*.go file to scan")
    ap.add_argument("--json", action="store_true")
    args = ap.parse_args(argv)
    rep = scan_root(args.root)
    if args.json:
        print(json.dumps(rep, indent=2))
    else:
        print(f"[msgserver-missing-authority-sibling-asymmetry] "
              f"files={len(rep['files_scanned'])} findings={rep['finding_count']}")
        for f in rep["findings"]:
            print(f"  [{f['severity_hint'].upper()}] {f['file']}:{f['line']} "
                  f"{f['function']} :: mutate={f['mutate_call']} "
                  f"gated_siblings={f['gated_siblings']} - {f['reason']}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
