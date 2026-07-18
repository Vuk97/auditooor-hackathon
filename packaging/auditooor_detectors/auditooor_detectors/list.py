"""``auditooor-detectors-list`` — print every bundled detector + its tier.

Examples:

    $ auditooor-detectors-list
    $ auditooor-detectors-list --tier B
    $ auditooor-detectors-list --json
    $ auditooor-detectors-list --engine slither
"""

from __future__ import annotations

import argparse
import json
import sys
from typing import Any

from . import __version__, load_registry


def _filter(records: list[dict[str, Any]], tier: str | None, engine: str | None) -> list[dict[str, Any]]:
    out = records
    if tier:
        out = [r for r in out if r.get("tier") == tier.upper()]
    if engine:
        out = [r for r in out if (r.get("engine") or "").lower() == engine.lower()]
    return out


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(
        prog="auditooor-detectors-list",
        description="List every detector bundled in auditooor-detectors.",
    )
    ap.add_argument("--tier", choices=["S", "A", "B"], help="Filter by tier.")
    ap.add_argument("--engine", help="Filter by engine (slither, tree-sitter-rust).")
    ap.add_argument("--json", action="store_true", help="Emit JSON.")
    ap.add_argument("--version", action="version", version=f"auditooor-detectors {__version__}")
    args = ap.parse_args(argv)

    registry = load_registry()
    records = _filter(registry.get("detectors", []), args.tier, args.engine)

    if args.json:
        json.dump(
            {
                "version": __version__,
                "generated_at": registry.get("generated_at"),
                "count": len(records),
                "detectors": records,
            },
            sys.stdout,
            indent=2,
        )
        sys.stdout.write("\n")
        return 0

    print(f"auditooor-detectors {__version__}")
    print(f"generated_at: {registry.get('generated_at')}")
    print(f"count: {len(records)} (of {registry.get('detector_count', '?')} bundled)")
    print()
    print(f"{'TIER':<4}  {'ENGINE':<20}  ARGUMENT")
    print(f"{'-' * 4}  {'-' * 20}  {'-' * 60}")
    for r in records:
        print(f"{r.get('tier', '?'):<4}  {(r.get('engine') or '?'):<20}  {r.get('argument', '?')}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
