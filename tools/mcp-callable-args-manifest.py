#!/usr/bin/env python3
# r36-rebuttal: CAPABILITY-GAP-CLOSURE-2026-05-26 lane (X2 closure)
"""mcp-callable-args-manifest.py - introspect vault MCP callables for required args.

Closes capability gap X2 (codified 2026-05-26 docs/CAPABILITY_GAPS_2026-05-26_ITER_FROM_CHAT.md):
``vault_post_mortem_corpus`` requires ``corpus_dir`` arg but CLAUDE.md Layer-1
recall examples never show this — orchestrators waste 5-15 min discovering the
required-arg surface per session.

This tool walks ``tools/vault-mcp-server.py``'s ``def vault_*`` methods, parses
each docstring + first 200 lines of body for ``kwargs.get("X")`` patterns where
the absence of X leads to ``_degraded("X_required")``, and emits a JSON
manifest of required/optional args per callable.

USAGE
    python3 tools/mcp-callable-args-manifest.py
        # Emit manifest to stdout (JSON).

    python3 tools/mcp-callable-args-manifest.py --check vault_post_mortem_corpus
        # Print just the args for one callable + exit 0 if found, 1 if not.

    python3 tools/mcp-callable-args-manifest.py --out reference/mcp_callable_args_manifest.json
        # Write to file (idempotent).

The output is consumed by:
  - Orchestrator session start (CLAUDE.md Layer-1) to show required args
  - vault_callable_health (X4) to exercise each callable with known-good args
  - r64-prompt-claim-verifier (R64) to validate orchestrator claim shapes
"""
from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional

TOOL_NAME = "mcp-callable-args-manifest"
TOOL_VERSION = "1.0.0"
SCHEMA = "auditooor.mcp_callable_args_manifest.v1"

REPO_ROOT = Path(__file__).resolve().parent.parent
MCP_SERVER = REPO_ROOT / "tools" / "vault-mcp-server.py"

# Patterns that indicate "this kwarg is required and absence -> degraded".
REQUIRED_KWARG_PATTERNS = [
    # _degraded("X_required") or _degraded("missing_X")
    re.compile(r'_degraded\(\s*"([a-z_]+)_required"', re.IGNORECASE),
    re.compile(r'_degraded\(\s*"missing_([a-z_]+)"', re.IGNORECASE),
    # if not raw_X: return _degraded(...)
    re.compile(r'^\s*if\s+not\s+(?:str\()?(\w+)_raw'),
]

# kwargs.get("X") - any kwarg is optional unless required-pattern matched
KWARG_GET_PATTERN = re.compile(r'kwargs\.get\(\s*[\'"]([a-z_]+)[\'"]', re.IGNORECASE)

# Reference-only patterns to find "Args:" docstring section
ARGS_DOC_PATTERN = re.compile(r'^\s+([a-z_]+):\s+(.+?)(?=\n\s+[a-z_]+:|\n\n|\Z)', re.MULTILINE | re.DOTALL)


# r36-rebuttal: CAPABILITY-GAP-CLOSURE-2026-05-26 lane
def extract_callables(server_text: str) -> List[Dict[str, Any]]:
    """Walk vault-mcp-server.py for every def vault_* method.

    Captures the full method body from the def line up to the NEXT method or
    end-of-file. Avoids the 4-space-indent truncation bug from the initial
    implementation that captured 0 kwargs across all 98 callables.
    """
    callables: List[Dict[str, Any]] = []
    def_re = re.compile(
        r'^    def (vault_[a-z_]+)\(self,.*?(?=^    def |\Z)',
        re.MULTILINE | re.DOTALL,
    )
    for m in def_re.finditer(server_text):
        full = m.group(0)
        name = m.group(1)
        # Truncate to first ~8000 chars — enough for arg-parsing region
        body = full[:8000]
        # Extract docstring (between first triple-quote pair)
        doc_m = re.search(r'"""(.+?)"""', body, re.DOTALL)
        docstring = (doc_m.group(1).strip() if doc_m else "")[:2000]
        # Collect kwargs.get(...) calls -> these are the declared kwargs surface
        kwargs_seen = set(KWARG_GET_PATTERN.findall(body))
        # Collect required (absence -> degraded)
        required: set[str] = set()
        for pat in REQUIRED_KWARG_PATTERNS:
            for match in pat.findall(body):
                required.add(match)
        optional = kwargs_seen - required
        # Sometimes the docstring includes Args: section with one-line descriptions
        arg_docs: Dict[str, str] = {}
        for kw in kwargs_seen:
            m2 = re.search(rf'\b{re.escape(kw)}:\s+([^\n]+)', docstring)
            if m2:
                arg_docs[kw] = m2.group(1).strip()[:300]
        callables.append({
            "name": name,
            "required_kwargs": sorted(required),
            "optional_kwargs": sorted(optional),
            "all_kwargs": sorted(kwargs_seen),
            "doc_short": docstring.split("\n\n", 1)[0][:400] if docstring else "",
            "arg_docs": arg_docs,
        })
    return callables


def main() -> int:
    p = argparse.ArgumentParser(prog=TOOL_NAME)
    p.add_argument("--check", help="Print just one callable's args; exit 1 if not found")
    p.add_argument("--out", help="Write manifest to this path (idempotent)")
    p.add_argument("--required-only", action="store_true", help="Only list callables with required kwargs")
    args = p.parse_args()

    if not MCP_SERVER.is_file():
        print(f"error: MCP server not found at {MCP_SERVER}", file=sys.stderr)
        return 3
    text = MCP_SERVER.read_text(encoding="utf-8", errors="replace")
    callables = extract_callables(text)

    if args.required_only:
        callables = [c for c in callables if c["required_kwargs"]]

    manifest = {
        "schema": SCHEMA,
        "tool": TOOL_NAME,
        "tool_version": TOOL_VERSION,
        "mcp_server_path": str(MCP_SERVER.relative_to(REPO_ROOT)),
        "callable_count": len(callables),
        "callables": callables,
    }

    if args.check:
        match = next((c for c in callables if c["name"] == args.check), None)
        if not match:
            print(f"error: callable {args.check!r} not found", file=sys.stderr)
            return 1
        print(json.dumps(match, indent=2))
        return 0

    out_json = json.dumps(manifest, indent=2)
    if args.out:
        out_path = Path(args.out)
        out_path.parent.mkdir(parents=True, exist_ok=True)
        out_path.write_text(out_json + "\n", encoding="utf-8")
        print(f"wrote {len(callables)} callables to {out_path}", file=sys.stderr)
    else:
        print(out_json)
    return 0


if __name__ == "__main__":
    sys.exit(main())
