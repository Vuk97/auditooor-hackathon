#!/usr/bin/env python3
"""mine-solodit.py — convert structured Solodit findings into staged pattern YAML stubs.

Usage:
    python3 tools/mine-solodit.py --input <json-file> --out-dir <dir> [--language rust|solidity]

The --input JSON must be a list of findings like:
    [
      {
        "id": "65100",
        "title": "Malicious validators can flood stake/unstake",
        "severity": "MEDIUM",
        "firm": "Code4rena",
        "protocol": "Recall",
        "quality": 5,
        "rarity": 5,
        "tags": ["DOS"],
        "url": "https://solodit.cyfrin.io/issues/...",
        "content": "short description of the bug..."
      },
      ...
    ]

This is the structured sibling of mine-audit-to-patterns.py — tailored for
Solodit's API-returned objects. Each emitted stub is D-tier / LOW confidence
(same semantics as the other staged dirs).

You can produce the input JSON by calling the mcp__solodit__search_findings
MCP tool and piping its structured results into a JSON file.
"""
import argparse
import json
import re
import sys
from pathlib import Path

# Reuse the classifier from mine-audit-to-patterns.py
BUG_CLASS_KEYWORDS = {
    "liquidation": ("liquidat", "seize", "health-factor", "close-factor", "bad debt"),
    "oracle-cascade": ("oracle", "price feed", "twap", "chainlink", "pyth", "staleness", "reflector"),
    "rewards-accounting": ("reward", "emission", "incentive", "claim_", "accrual", "checkpoint"),
    "flashloan": ("flash loan", "flashloan", "premium"),
    "signature-auth": ("signature", "ecrecover", "replay", "deadline", "nonce", "eip712", "permit"),
    "access-control": ("auth", "unauthorized", "privileg", "only_owner", "role", "admin", "pause",
                        "permission", "governance", "require_auth", "signer"),
    "input-validation": ("zero address", "zero amount", "missing check", "bound", "range", "validate",
                          "unvalidated", "hardcoded"),
    "arithmetic": ("overflow", "underflow", "unchecked", "wrapping", "truncat", "precision",
                    "rounding", "div by zero", "division-by-zero", "stale"),
    "reentrancy": ("reentran", "cei violation", "callback mid-state", "callback before"),
    "slippage": ("slippage", "min-out", "amount-out-min"),
    "merkle-replay": ("merkle", "proof", "claimed flag"),
    "dex-integration": ("swap", "uniswap", "curve", "balancer", "aggregator", "amm", "pool",
                         "whirlpool", "orca", "raydium", "meteora"),
    "proxy-upgrade": ("proxy", "upgrade", "storage slot", "initializer", "initializ"),
    "governance": ("timelock", "vote", "governor", "dao", "propos"),
    "gas-griefing": ("dos", "gas exhaust", "unbounded", "flood", "queue"),
    "token-standard": ("erc20", "erc4626", "erc721", "erc1155", "sep41", "sep-41", "share"),
    "fee-accounting": ("fee charged", "fee wrong", "fee party", "siphon"),
    "bitmap-bounds": ("bitmap", "reserve id", "off-by-one", "overflow index"),
    "mint-unrestricted": ("unrestricted mint", "infinite mint", "mint no auth"),
    "paired-fn-asymmetry": ("paired function", "add/remove", "add-remove"),
    "anchor-pda": ("pda", "pda seed", "seeds don't bind"),
    "anchor-account": ("anchor account", "accountinfo", "derive(accounts)"),
    "cpi-ordering": ("cpi", "invoke_signed", "cross-program"),
    "ttl-archival": ("ttl", "archiv", "expire", "persistent storage"),
}


def classify(title: str, body: str, tags: list[str]) -> str:
    blob = (title + " " + body + " " + " ".join(tags)).lower()
    for cls, keywords in BUG_CLASS_KEYWORDS.items():
        for kw in keywords:
            if kw in blob:
                return cls
    return "miscellaneous"


def _kebab(name: str, max_len: int = 80) -> str:
    s = re.sub(r"[^A-Za-z0-9]+", "-", name).strip("-").lower()
    s = re.sub(r"-+", "-", s)
    if s and s[0].isdigit():
        s = "f-" + s
    return s[:max_len]


def norm_severity(s: str) -> str:
    s = s.strip().upper()
    return {"CRITICAL": "Critical", "HIGH": "High", "MEDIUM": "Medium",
            "LOW": "Low", "GAS": "Low", "INFO": "Info", "QA": "Low"}.get(s, "Unknown")


def extract_indicators(body: str) -> list[str]:
    """Pull backtick-quoted identifiers as indicators."""
    found = re.findall(r"`([A-Za-z_][A-Za-z0-9_\.]{2,50}(?:\([^)]*\))?)`", body[:2000])
    return [f"references '{ident}'" for ident in found[:6]] or ["text-pattern: " + _kebab(body[:60], 60)]


def emit_yaml(finding: dict, out_dir: Path, language: str, platform: str, source_slug: str) -> Path:
    sid = str(finding.get("id", ""))
    title = finding.get("title", "").strip()
    body = finding.get("content", "") or finding.get("description", "") or ""
    tags = finding.get("tags", []) or []
    severity = norm_severity(str(finding.get("severity", "Unknown")))
    bug_class = classify(title, body, tags)
    url = finding.get("url", "")

    slug = _kebab(title) or _kebab(sid)
    if not slug:
        return None
    yaml_path = out_dir / f"{slug}.yaml"
    if yaml_path.exists():
        yaml_path = out_dir / f"{slug}-{_kebab(sid)}.yaml"

    excerpt = body.strip()[:800].replace("\n", " ").replace('"', "'")
    if len(body) > 800:
        excerpt += "..."

    indicators_yaml = "\n".join(f"  - {i!r}" for i in extract_indicators(body))

    yaml_text = f"""id: {slug}
title: |
  {title[:140]}
severity: {severity}
language: {language}
platform: {platform}
source: {source_slug}
source_id: "{sid}"
source_url: {url}
firm: {finding.get("firm", "unknown")!r}
protocol: {finding.get("protocol", "unknown")!r}
quality_score: {finding.get("quality", 0)}
rarity_score: {finding.get("rarity", 0)}
tags: {tags!r}
bug_class: {bug_class}
indicators:
{indicators_yaml}
victim: tbd
exploit_precondition: tbd
real_world_example: |
  {excerpt}
suggested_remediation: |
  See source report at {url}
cross_refs: []
"""
    yaml_path.write_text(yaml_text)
    return yaml_path


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--input", required=True, type=Path, help="Path to JSON list of findings")
    ap.add_argument("--out-dir", required=True, type=Path, help="Output dir")
    ap.add_argument("--source", default="solodit", help="Source slug (default: solodit)")
    ap.add_argument("--language", default="rust", help="Language tag")
    ap.add_argument("--platform", default="solana", help="Platform tag")
    args = ap.parse_args()

    if not args.input.is_file():
        print(f"[err] input not a file: {args.input}", file=sys.stderr)
        sys.exit(2)

    data = json.loads(args.input.read_text())
    if not isinstance(data, list):
        print(f"[err] input JSON must be a list; got {type(data).__name__}", file=sys.stderr)
        sys.exit(2)

    args.out_dir.mkdir(parents=True, exist_ok=True)

    emitted = 0
    for f in data:
        p = emit_yaml(f, args.out_dir, args.language, args.platform, args.source)
        if p:
            emitted += 1

    print(f"[done] emitted {emitted} YAMLs to {args.out_dir}")
    print(f"[done] source={args.source} language={args.language} platform={args.platform}")


if __name__ == "__main__":
    main()
