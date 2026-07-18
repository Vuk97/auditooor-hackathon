#!/usr/bin/env python3
"""big-loss-template-registry-emit — emit/update the big_loss_templates registry row.

Lane 9 corpus-mining commitments (PR #658 Tier-B #15).
Wraps tools/big-loss-template-compose.py (read-only) and updates the
extended_corpora row for slug "big_loss_templates" in corpus_registry.json
with a fresh last_emitted timestamp and content hash of the composed output.

Idempotent: running --apply twice produces the same registry state.

CLI shape matches tools/external-corpus-fetch.py (argparse, stdlib-only).

Usage
-----
    # dry-run: show what would be emitted
    python3 tools/big-loss-template-registry-emit.py --workspace ~/audits/base-azul

    # apply: compose + update registry row
    python3 tools/big-loss-template-registry-emit.py --workspace ~/audits/base-azul --apply

    # also write composed manifest to workspace .auditooor/
    python3 tools/big-loss-template-registry-emit.py --workspace ~/audits/base-azul --apply --write-manifest
"""
from __future__ import annotations

import argparse
import datetime
import hashlib
import importlib.util
import json
import pathlib
import sys

_HERE = pathlib.Path(__file__).resolve().parent
_REPO_ROOT = _HERE.parent
_DEFAULT_REGISTRY = _REPO_ROOT / "reference" / "corpus_registry.json"
_COMPOSE_SCRIPT = _HERE / "big-loss-template-compose.py"


# ---------------------------------------------------------------------------
# Load compose module without modifying it
# ---------------------------------------------------------------------------

def _load_compose_module():
    spec = importlib.util.spec_from_file_location("big_loss_template_compose", _COMPOSE_SCRIPT)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


# ---------------------------------------------------------------------------
# Registry helpers
# ---------------------------------------------------------------------------

def _load_registry(path: pathlib.Path) -> dict:
    if not path.exists():
        print(f"[big-loss-template-registry-emit] ERR registry not found: {path}", file=sys.stderr)
        sys.exit(2)
    with path.open() as fh:
        return json.load(fh)


def _save_registry(path: pathlib.Path, registry: dict) -> None:
    path.write_text(json.dumps(registry, indent=2) + "\n", encoding="utf-8")


def _find_extended_slug(registry: dict, slug: str) -> dict | None:
    for entry in registry.get("extended_corpora", []):
        if entry.get("slug") == slug:
            return entry
    return None


# ---------------------------------------------------------------------------
# Compose + hash
# ---------------------------------------------------------------------------

def _compose(ws: pathlib.Path, compose_mod) -> dict:
    """Run compose for the workspace; return the result dict."""
    try:
        result = compose_mod.run(["--workspace", str(ws), "--print-json"])
        return result
    except SystemExit as exc:
        # compose exits non-zero on --strict; still return the last result
        # by catching the exit and falling through.
        print(
            f"[big-loss-template-registry-emit] WARN compose exited {exc.code}; continuing",
            file=sys.stderr,
        )
        return {}


def _content_hash(data: dict) -> str:
    blob = json.dumps(data, sort_keys=True).encode()
    return hashlib.sha256(blob).hexdigest()[:16]


# ---------------------------------------------------------------------------
# Apply / update registry row
# ---------------------------------------------------------------------------

def _apply(
    registry: dict,
    registry_path: pathlib.Path,
    composed: dict,
    ws: pathlib.Path,
) -> None:
    now_iso = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    chash = _content_hash(composed)

    slug = "big_loss_templates"
    entry = _find_extended_slug(registry, slug)
    if entry is None:
        # Should not happen since corpus_registry.json already has the row,
        # but be defensive — add it if missing.
        entry = {
            "slug": slug,
            "source": "tools/big-loss-template-compose.py",
            "produces": "auditooor.big_loss_template_composed.v1 manifests per workspace",
            "templates": [],
            "staleness": {},
        }
        registry.setdefault("extended_corpora", []).append(entry)

    entry.setdefault("staleness", {})
    entry["staleness"]["last_emitted"] = now_iso
    entry["staleness"]["status"] = "fresh"
    entry["staleness"]["last_content_hash"] = chash
    entry["staleness"]["last_workspace"] = str(ws)
    entry["staleness"]["composed_count"] = composed.get("composed", 0)
    entry["staleness"]["total_rows"] = composed.get("total_rows", 0)

    _save_registry(registry_path, registry)
    print(
        f"[big-loss-template-registry-emit] registry updated: last_emitted={now_iso} "
        f"hash={chash} composed={composed.get('composed', 0)}/{composed.get('total_rows', 0)}",
        file=sys.stderr,
    )


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def _parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    p = argparse.ArgumentParser(
        description="Emit/update the big_loss_templates corpus registry row.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    p.add_argument(
        "--workspace",
        metavar="WS",
        required=True,
        help="Path to workspace root (passed to big-loss-template-compose.py).",
    )
    p.add_argument(
        "--registry",
        metavar="PATH",
        default=str(_DEFAULT_REGISTRY),
        help=f"Path to corpus_registry.json (default: {_DEFAULT_REGISTRY})",
    )
    p.add_argument(
        "--apply",
        action="store_true",
        help="Write updated registry row (default: dry-run, only print).",
    )
    p.add_argument(
        "--write-manifest",
        action="store_true",
        help="Also write composed manifest to <workspace>/.auditooor/big_loss_template_composed.json",
    )
    p.add_argument(
        "--json",
        dest="json_out",
        action="store_true",
        help="Print composed JSON to stdout.",
    )
    return p.parse_args(argv)


def run(argv: list[str] | None = None) -> int:
    args = _parse_args(argv)

    ws = pathlib.Path(args.workspace).expanduser().resolve()
    if not ws.is_dir():
        print(f"[big-loss-template-registry-emit] ERR workspace not found: {ws}", file=sys.stderr)
        sys.exit(2)

    registry_path = pathlib.Path(args.registry).expanduser().resolve()
    registry = _load_registry(registry_path)

    compose_mod = _load_compose_module()
    composed = _compose(ws, compose_mod)

    if args.json_out:
        print(json.dumps(composed, indent=2))

    if args.write_manifest and composed:
        auditooor_dir = ws / ".auditooor"
        auditooor_dir.mkdir(exist_ok=True)
        manifest_path = auditooor_dir / "big_loss_template_composed.json"
        manifest_path.write_text(json.dumps(composed, indent=2) + "\n", encoding="utf-8")
        print(
            f"[big-loss-template-registry-emit] manifest written to {manifest_path}",
            file=sys.stderr,
        )

    if args.apply:
        _apply(registry, registry_path, composed, ws)
    else:
        now_iso = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        chash = _content_hash(composed)
        print(
            f"[big-loss-template-registry-emit] DRY RUN — would update slug=big_loss_templates "
            f"last_emitted={now_iso} hash={chash} "
            f"composed={composed.get('composed', 0)}/{composed.get('total_rows', 0)}"
        )

    return 0


if __name__ == "__main__":
    sys.exit(run())
