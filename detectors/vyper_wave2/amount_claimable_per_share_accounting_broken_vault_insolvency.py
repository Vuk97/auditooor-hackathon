"""
amount-claimable-per-share-accounting-broken-vault-insolvency — polyglot skeleton generated from amount-claimable-per-share-accounting-broken-vault-insolvency.yaml
Language: vyper  Bug class: arithmetic
Source: https://solodit.cyfrin.io/issues/h-1-amount_claimable_per_share-accounting-is-broken-and-will-result-in-vault-insolvency-sherlock-fair-funding-fair-funding-by-alchemix-unstoppable-git
Title: amount_claimable_per_share accounting broken — vault insolvency

Real-world example (refine the regex below from this):
  position.amount_claimed not initialized when new deposit made while amount_claimable_per_share != 0. Stale global-accumulator vs per-user baseline.

PORTING GAPS: This skeleton uses regex, NOT AST predicates.
Predicates like function.ast, function.taints_param_to, and
function.post_external_call_mutates_state are NOT available.
Operators should refine the detection logic.

Regenerate via: python3 tools/pattern-compile.py --lang vyper amount-claimable-per-share-accounting-broken-vault-insolvency.yaml
"""

from __future__ import annotations

import argparse
import json
import re
from pathlib import Path

# Indicator: text-pattern: position-amount-claimed-not-initialized-when-new-deposit-mad
_PATTERN_RE = re.compile(
    r"\bposition\b.{0,60}\bamount\b.{0,60}\bclaimed\b",
    re.IGNORECASE | re.DOTALL,
)
_COMMENT_RE = re.compile(r'(?://|#)[^\n]*')


def _line_at(source: str, offset: int) -> int:
    return source.count("\n", 0, offset) + 1


def scan_text(source: str, filepath: str = '<memory>') -> list[dict]:
    clean = _COMMENT_RE.sub('', source)
    hits: list[dict] = []
    for m in _PATTERN_RE.finditer(clean):
        line = _line_at(clean, m.start())
        hits.append({
            "severity": "high",
            "filepath": filepath,
            "line": line,
            "snippet": m.group(0)[:120].strip(),
            "message": "Pattern `amount-claimable-per-share-accounting-broken-vault-insolvency` matched: amount_claimable_per_share accounting broken — vault insolvency (regex skeleton)",
        })
    return hits


def scan_file(path: Path) -> list[dict]:
    return scan_text(path.read_text(encoding='utf-8', errors='replace'), str(path))


def run_text(source: str, filepath: str) -> list[dict]:
    return scan_text(source, filepath)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Detect: amount_claimable_per_share accounting broken — vault insolvency")
    parser.add_argument('paths', nargs='+', type=Path)
    parser.add_argument('--json', action='store_true')
    args = parser.parse_args(argv)
    hits: list[dict] = []
    for p in args.paths:
        if p.is_dir():
            for f in sorted(p.rglob('*.vy')):
                hits.extend(scan_file(f))
        elif p.suffix == '.vy':
            hits.extend(scan_file(p))
    if args.json:
        print(json.dumps(hits, indent=2))
    else:
        for h in hits:
            print(f"{h['filepath']}:{h['line']}: {h['severity']}: {h['message']}")
    return 1 if hits else 0


if __name__ == '__main__':
    raise SystemExit(main())
