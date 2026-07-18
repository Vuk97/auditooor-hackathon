#!/usr/bin/env python3
"""dispatch-template.py — pre-dispatch validator for provider prompt files.

Closes gap 6 (provider dispatch quality) from
docs/CLAUDE_KNOWN_LIMITATIONS_STATUS_REPORT_2026-04-29.md: Kimi/Minimax
helped most when prompts included exact files, narrowed hypotheses, prior
failed attempts, and a requested output shape. Sloppy prompts wasted
context windows (96-question off-task tangent etc.).

This validator reads a YAML template under
``reference/dispatch-templates/<name>.yaml`` and checks that a candidate
prompt file declares every ``required_inputs`` key (matched by the
template's per-input ``detect_pattern`` regex). Missing inputs cause a
non-zero exit and emit the matching ``refusal_message``.

Usage
-----
    python3 tools/dispatch-template.py --template <name> --validate <prompt-file>
    python3 tools/dispatch-template.py --list
    python3 tools/dispatch-template.py --show <name>

Exit codes
----------
    0 — prompt is valid (every required_inputs key found)
    1 — prompt missing one or more required_inputs (refusal_messages printed)
    2 — usage / template not found / template malformed

The validator is intentionally STATIC: it does not call any provider, does
not write to ``submissions/``, does not mutate state, and runs offline.
"""
from __future__ import annotations

import argparse
import json
import pathlib
import re
import sys
from typing import Dict, List, Tuple

try:
    import yaml  # type: ignore
except Exception as exc:  # pragma: no cover — yaml is in repo deps
    print(f"dispatch-template: PyYAML required ({exc})", file=sys.stderr)
    sys.exit(2)


REPO_ROOT = pathlib.Path(__file__).resolve().parent.parent
TEMPLATE_DIR = REPO_ROOT / "reference" / "dispatch-templates"


def list_templates(template_dir: pathlib.Path = TEMPLATE_DIR) -> List[str]:
    if not template_dir.is_dir():
        return []
    return sorted(p.stem for p in template_dir.glob("*.yaml"))


def load_template(name: str, template_dir: pathlib.Path = TEMPLATE_DIR) -> Dict:
    path = template_dir / f"{name}.yaml"
    if not path.is_file():
        raise FileNotFoundError(
            f"template '{name}' not found at {path} "
            f"(available: {', '.join(list_templates(template_dir)) or '<none>'})"
        )
    with path.open("r", encoding="utf-8") as fh:
        data = yaml.safe_load(fh)
    if not isinstance(data, dict):
        raise ValueError(f"template '{name}' must be a YAML mapping at top level")
    for required_key in ("name", "provider", "required_inputs", "refusal_rules"):
        if required_key not in data:
            raise ValueError(f"template '{name}' missing top-level key '{required_key}'")
    if data["name"] != name:
        raise ValueError(
            f"template file stem '{name}' does not match declared name '{data['name']}'"
        )
    if not isinstance(data["required_inputs"], list) or not data["required_inputs"]:
        raise ValueError(f"template '{name}' must declare a non-empty required_inputs list")
    for entry in data["required_inputs"]:
        if not isinstance(entry, dict):
            raise ValueError(f"template '{name}' has non-dict required_inputs entry")
        for k in ("name", "refusal_message", "detect_pattern"):
            if k not in entry:
                raise ValueError(
                    f"template '{name}' required_inputs entry missing '{k}': {entry}"
                )
    return data


def validate_prompt(template: Dict, prompt_text: str) -> Tuple[bool, List[Dict]]:
    """Return (ok, missing) where ``missing`` is a list of refusal records."""
    missing: List[Dict] = []
    for entry in template["required_inputs"]:
        pattern = entry["detect_pattern"]
        try:
            compiled = re.compile(pattern)
        except re.error as exc:
            raise ValueError(
                f"required_inputs[{entry['name']}].detect_pattern is not a valid regex: {exc}"
            ) from exc
        if not compiled.search(prompt_text):
            missing.append(
                {
                    "input": entry["name"],
                    "refusal_message": entry["refusal_message"],
                    "description": entry.get("description", ""),
                }
            )
    return (not missing, missing)


def render_template(template: Dict) -> str:
    lines: List[str] = []
    lines.append(f"# {template['name']} ({template.get('provider', '?')})")
    if "specialty" in template:
        lines.append(f"specialty: {template['specialty']}")
    lines.append("")
    lines.append("required_inputs:")
    for entry in template["required_inputs"]:
        lines.append(f"  - {entry['name']}: {entry.get('description', '').strip()}")
        lines.append(f"      refusal_message: {entry['refusal_message']}")
    lines.append("")
    lines.append("refusal_rules:")
    for rule in template.get("refusal_rules", []):
        lines.append(f"  - {rule}")
    if "output_schema" in template:
        lines.append("")
        lines.append("output_schema:")
        for line in template["output_schema"].splitlines():
            lines.append(f"  {line}")
    if "example_invocation" in template:
        lines.append("")
        lines.append("example_invocation:")
        for line in template["example_invocation"].splitlines():
            lines.append(f"  {line}")
    return "\n".join(lines)


def main(argv: List[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="dispatch-template.py",
        description=(
            "Validate provider prompt files against dispatch templates "
            "(reference/dispatch-templates/*.yaml). Exits 0 if every "
            "required input is detected, 1 if any are missing, 2 on usage error."
        ),
    )
    parser.add_argument("--template", help="template name (file stem under reference/dispatch-templates/)")
    parser.add_argument("--validate", help="prompt file to validate")
    parser.add_argument("--list", action="store_true", help="list available templates and exit")
    parser.add_argument("--show", metavar="NAME", help="render the named template and exit")
    parser.add_argument(
        "--template-dir",
        default=str(TEMPLATE_DIR),
        help=f"directory of templates (default: {TEMPLATE_DIR})",
    )
    parser.add_argument("--json", action="store_true", help="emit JSON instead of human-readable text")
    args = parser.parse_args(argv)

    template_dir = pathlib.Path(args.template_dir).resolve()

    if args.list:
        names = list_templates(template_dir)
        if args.json:
            print(json.dumps({"templates": names}, indent=2))
        else:
            for n in names:
                print(n)
        return 0

    if args.show:
        try:
            tpl = load_template(args.show, template_dir)
        except (FileNotFoundError, ValueError) as exc:
            print(f"dispatch-template: {exc}", file=sys.stderr)
            return 2
        print(render_template(tpl))
        return 0

    if not args.template or not args.validate:
        parser.print_usage(sys.stderr)
        print(
            "dispatch-template: --template and --validate are required "
            "(use --list or --show otherwise)",
            file=sys.stderr,
        )
        return 2

    try:
        tpl = load_template(args.template, template_dir)
    except (FileNotFoundError, ValueError) as exc:
        print(f"dispatch-template: {exc}", file=sys.stderr)
        return 2

    prompt_path = pathlib.Path(args.validate)
    if not prompt_path.is_file():
        print(f"dispatch-template: prompt file not found: {prompt_path}", file=sys.stderr)
        return 2
    prompt_text = prompt_path.read_text(encoding="utf-8")

    try:
        ok, missing = validate_prompt(tpl, prompt_text)
    except ValueError as exc:
        print(f"dispatch-template: {exc}", file=sys.stderr)
        return 2

    if args.json:
        payload = {
            "template": tpl["name"],
            "provider": tpl.get("provider"),
            "prompt": str(prompt_path),
            "ok": ok,
            "missing": missing,
        }
        print(json.dumps(payload, indent=2))
    else:
        if ok:
            print(
                f"dispatch-template: OK — prompt {prompt_path} satisfies "
                f"{len(tpl['required_inputs'])} required input(s) for "
                f"template '{tpl['name']}' ({tpl.get('provider', '?')})"
            )
        else:
            print(
                f"dispatch-template: REFUSE — prompt {prompt_path} is missing "
                f"{len(missing)} required input(s) for template '{tpl['name']}':",
                file=sys.stderr,
            )
            for entry in missing:
                print(
                    f"  - missing '{entry['input']}': {entry['refusal_message']}",
                    file=sys.stderr,
                )

    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
