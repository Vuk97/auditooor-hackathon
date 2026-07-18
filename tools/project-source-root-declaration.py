#!/usr/bin/env python3
"""Create or validate the project source-root declaration manifest.

The manifest is intentionally operator-declared.  This helper does not discover
arbitrary folders and call them project evidence; it writes the small manifest
that ``project-source-root-readiness.py`` validates before impact/source/harness
reducers may consume roots.
"""

from __future__ import annotations

import argparse
import json
import time
from pathlib import Path
from typing import Any


SCHEMA = "auditooor.project_source_roots.v1"
DEFAULT_MANIFEST = ".auditooor/project_source_roots.json"
PROOF_BOUNDARY = (
    "Declared roots are operator intent only until project-source-root-readiness "
    "accepts them. They do not prove source citation, production path, listed "
    "impact, exploit impact, severity, OOS status, or submission readiness."
)


def load_json(path: Path) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError:
        return {}
    except json.JSONDecodeError as exc:
        raise SystemExit(f"[project-source-root-declaration] ERR invalid JSON in {path}: {exc}") from None


def write_json(path: Path, payload: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def parse_entry(entry: str) -> dict[str, Any]:
    if "=" in entry:
        label, path = entry.split("=", 1)
        label = label.strip()
        path = path.strip()
    else:
        path = entry.strip()
        label = Path(path).name or "project-source-root"
    if not path:
        raise SystemExit("[project-source-root-declaration] ERR empty root path")
    return {
        "label": label or Path(path).name or "project-source-root",
        "path": path,
        "kind": "target_project_source",
        "source": "operator_declaration",
        "expected_languages": [],
        "notes": "Declared for project-source-root-readiness validation and impact/source/harness reducers.",
    }


def normalize_manifest(existing: Any, entries: list[dict[str, Any]]) -> dict[str, Any]:
    roots: list[dict[str, Any]] = []
    if isinstance(existing, dict):
        for item in existing.get("roots") or []:
            if isinstance(item, str):
                roots.append(parse_entry(item))
            elif isinstance(item, dict):
                path = str(item.get("path") or "").strip()
                if path:
                    roots.append(
                        {
                            "label": str(item.get("label") or item.get("name") or Path(path).name or "project-source-root"),
                            "path": path,
                            "kind": str(item.get("kind") or "target_project_source"),
                            "source": str(item.get("source") or "operator_declaration"),
                            "expected_languages": list(item.get("expected_languages") or []),
                            "notes": str(item.get("notes") or ""),
                        }
                    )
    seen: set[tuple[str, str]] = {(root["label"], root["path"]) for root in roots}
    for entry in entries:
        key = (entry["label"], entry["path"])
        if key not in seen:
            roots.append(entry)
            seen.add(key)
    return {
        "schema": SCHEMA,
        "generated_at_unix": int(time.time()),
        "proof_boundary": PROOF_BOUNDARY,
        "roots": roots,
        "next_commands": [
            "make project-source-root-readiness WS=<workspace>",
            "make impact-binding-source-harness-discovery WS=<workspace>",
        ],
    }


def validate_manifest(payload: dict[str, Any]) -> list[str]:
    errors: list[str] = []
    if payload.get("schema") != SCHEMA:
        errors.append("schema_mismatch")
    roots = payload.get("roots")
    if not isinstance(roots, list):
        errors.append("roots_not_list")
        return errors
    for index, root in enumerate(roots):
        if not isinstance(root, dict):
            errors.append(f"root_{index}_not_object")
            continue
        if not str(root.get("path") or "").strip():
            errors.append(f"root_{index}_missing_path")
        if str(root.get("kind") or "") != "target_project_source":
            errors.append(f"root_{index}_invalid_kind")
    return errors


def build_payload(manifest_path: Path, entries: list[str], *, merge_existing: bool) -> dict[str, Any]:
    existing = load_json(manifest_path) if merge_existing else {}
    return normalize_manifest(existing, [parse_entry(entry) for entry in entries])


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--workspace", required=True, type=Path)
    parser.add_argument("--manifest", type=Path)
    parser.add_argument("--entry", action="append", default=[], help="Repeatable label=relative/path declaration")
    parser.add_argument("--replace", action="store_true", help="Replace existing manifest instead of merging")
    parser.add_argument("--check", action="store_true", help="Validate the manifest without writing")
    parser.add_argument("--print-json", action="store_true")
    args = parser.parse_args(argv)

    workspace = args.workspace.expanduser().resolve()
    manifest_path = (args.manifest or workspace / DEFAULT_MANIFEST).expanduser().resolve()

    if args.check:
        payload = load_json(manifest_path)
        errors = validate_manifest(payload if isinstance(payload, dict) else {})
        if args.print_json:
            print(json.dumps({"manifest": str(manifest_path), "errors": errors, "valid": not errors}, indent=2))
        if errors:
            print(f"[project-source-root-declaration] ERR {','.join(errors)}")
            return 1
        print(f"[project-source-root-declaration] OK valid manifest roots={len(payload.get('roots') or [])}")
        return 0

    payload = build_payload(manifest_path, args.entry, merge_existing=not args.replace)
    errors = validate_manifest(payload)
    if errors:
        raise SystemExit(f"[project-source-root-declaration] ERR generated invalid manifest: {','.join(errors)}")
    write_json(manifest_path, payload)
    if args.print_json:
        print(json.dumps(payload, indent=2, sort_keys=True))
    print(f"[project-source-root-declaration] OK wrote {manifest_path} roots={len(payload['roots'])}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
