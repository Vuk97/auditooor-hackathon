#!/usr/bin/env python3
"""Record an offline-safe Foundry version inventory for a workspace."""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from lib.foundry_version import build_inventory, render_markdown  # noqa: E402


def default_paths(workspace: Path | None) -> tuple[Path | None, Path | None]:
    if not workspace:
        return None, None
    out_dir = workspace.expanduser().resolve() / ".auditooor"
    return out_dir / "foundry_version_inventory.json", out_dir / "foundry_version_inventory.md"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--workspace", type=Path, help="Workspace whose .auditooor/ inventory should be written.")
    parser.add_argument("--out-json", type=Path, help="Override JSON output path.")
    parser.add_argument("--out-md", type=Path, help="Override Markdown output path.")
    parser.add_argument("--timeout", type=float, default=5.0, help="Per-binary version command timeout in seconds.")
    parser.add_argument("--print-json", action="store_true", help="Print the JSON report to stdout.")
    args = parser.parse_args(argv)

    workspace = args.workspace.expanduser().resolve() if args.workspace else None
    if workspace and not workspace.is_dir():
        raise SystemExit(f"[foundry-version] ERR workspace not found: {workspace}")

    report = build_inventory(workspace, timeout=args.timeout)
    default_json, default_md = default_paths(workspace)
    out_json = args.out_json.expanduser().resolve() if args.out_json else default_json
    out_md = args.out_md.expanduser().resolve() if args.out_md else default_md

    if out_json:
        out_json.parent.mkdir(parents=True, exist_ok=True)
        out_json.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    if out_md:
        out_md.parent.mkdir(parents=True, exist_ok=True)
        out_md.write_text(render_markdown(report), encoding="utf-8")

    if args.print_json:
        print(json.dumps(report, indent=2, sort_keys=True))
    if out_json or out_md:
        print(
            "[foundry-version] OK "
            f"target={report['planned_target']['foundry_version']} "
            f"json={out_json or ''} md={out_md or ''}",
            file=sys.stderr,
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
