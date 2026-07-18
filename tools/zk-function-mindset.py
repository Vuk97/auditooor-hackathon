#!/usr/bin/env python3
"""zk-function-mindset.py - per-template ZK orchestrator.

Wave-5 Track K-zkBugs Step 8. Given a Circom or Halo2 source file and a
template / chip name, this tool:

  1. Extracts the template / chip body from the source.
  2. Runs all wired Circom / Halo2 detectors against it.
  3. Calls vault_zk_template_lookup for prior zkBugs corpus findings
     matching the framework + template_name.
  4. Calls zkbugs-prior-audit-class-verifier --classify against each
     detector hit AND each prior-finding short_vulnerability blob to
     surface DROP-class-b vs NOVEL-CANDIDATE.
  5. Emits a per-template Markdown brief under
     <workspace>/.auditooor/zk_function_mindset_<framework>_<template>_<ts>.md

Usage:
    python3 tools/zk-function-mindset.py <source.rs|source.circom> \\
        --template <name> [--framework circom|halo2] \\
        [--workspace <path>]

Notes:
  - --framework defaults to inference from the file extension (.circom →
    circom; .rs → halo2). Override explicitly when the heuristic is wrong.
  - --workspace defaults to the current working directory.
  - The Markdown brief is the primary artifact; stdout summarizes status.
"""
from __future__ import annotations

import argparse
import datetime
import importlib.util
import json
import re
import subprocess
import sys
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parent.parent
DEFAULT_DETECTORS = {
    "circom": ROOT / "detectors" / "circom_wave1",
    "halo2": ROOT / "detectors" / "halo2_wave1",
    # Wave-6 Track K-zkBugs additions (step K-Z.10d):
    "plonky2": ROOT / "detectors" / "plonky2_wave1",
    "noir": ROOT / "detectors" / "noir_wave1",
    "cairo": ROOT / "detectors" / "cairo_wave1",
    # Wave-7 Track K-zkBugs minor frameworks:
    "plonky3": ROOT / "detectors" / "plonky3_wave1",
    "bellperson": ROOT / "detectors" / "bellperson_wave1",
    "arkworks": ROOT / "detectors" / "arkworks_wave1",
    "risc0": ROOT / "detectors" / "risc0_wave1",
    "pil": ROOT / "detectors" / "pil_wave1",
    "gnark": ROOT / "detectors" / "gnark_wave1",
}


def _load_module(path: Path, alias: str):
    spec = importlib.util.spec_from_file_location(alias, path)
    assert spec is not None and spec.loader is not None
    mod = importlib.util.module_from_spec(spec)
    sys.modules[alias] = mod
    spec.loader.exec_module(mod)
    return mod


def _extract_template_body(source: str, template_name: str, framework: str) -> tuple[str, int, int]:
    """Return (body_text, body_start, body_end). If extraction fails,
    return (full_source, 0, len(source)) so detectors run on the whole
    file (best-effort)."""
    if framework == "circom":
        pat = re.compile(
            rf"\btemplate\s+{re.escape(template_name)}\s*(?:\([^)]*\))?\s*\{{",
            re.M,
        )
    elif framework in ("solidity", "solidity-honk"):
        # Solidity: `function <name>(...) <modifiers> { ... }`. The signature
        # may span multiple lines and carry visibility / mutability / returns
        # clauses before the opening brace, so match up to the first `{` that
        # is not part of the parameter list. Interface / abstract declarations
        # end in `;` (no body) and are skipped by requiring a `{`.
        pat = re.compile(
            rf"\bfunction\s+{re.escape(template_name)}\s*\([^;{{}}]*?\)"
            rf"[^;{{}}]*?\{{",
            re.M | re.S,
        )
        m = pat.search(source)
        if not m:
            return source, 0, len(source)
        open_brace = m.end() - 1
        depth = 0
        for idx in range(open_brace, len(source)):
            ch = source[idx]
            if ch == "{":
                depth += 1
            elif ch == "}":
                depth -= 1
                if depth == 0:
                    return source[m.start(): idx + 1], m.start(), idx + 1
        return source[m.start():], m.start(), len(source)
    else:  # halo2 / rust
        # Try impl-blocks first (they carry the chip behavior), then
        # fall through to struct / fn definitions.
        for kw in ("impl", "fn", "struct"):
            pat = re.compile(
                rf"\b{kw}(?:\s*<[^>]*>)?\s+"
                rf"(?:[^{{}}]*?\b){re.escape(template_name)}\b"
                rf"[^{{}}]*\{{",
                re.M | re.S,
            )
            m = pat.search(source)
            if m:
                break
        if not m:
            return source, 0, len(source)
        open_brace = m.end() - 1
        depth = 0
        for idx in range(open_brace, len(source)):
            ch = source[idx]
            if ch == "{":
                depth += 1
            elif ch == "}":
                depth -= 1
                if depth == 0:
                    return source[m.start(): idx + 1], m.start(), idx + 1
        return source[m.start():], m.start(), len(source)
    m = pat.search(source)
    if not m:
        return source, 0, len(source)
    open_brace = m.end() - 1
    depth = 0
    for idx in range(open_brace, len(source)):
        ch = source[idx]
        if ch == "{":
            depth += 1
        elif ch == "}":
            depth -= 1
            if depth == 0:
                return source[m.start(): idx + 1], m.start(), idx + 1
    return source[m.start():], m.start(), len(source)


def _load_detectors_for_framework(framework: str) -> list[tuple[str, Any]]:
    """Return list of (detector_name, module) pairs for the framework."""
    det_dir = DEFAULT_DETECTORS.get(framework)
    if det_dir is None or not det_dir.exists():
        return []
    detectors: list[tuple[str, Any]] = []
    init_path = det_dir / "__init__.py"
    declared: list[str] | None = None
    if init_path.exists():
        try:
            init_mod = _load_module(init_path, f"zfm_init_{framework}")
            declared = getattr(init_mod, "DETECTOR_MODULES", None)
        except Exception:
            declared = None
    if declared is None:
        # Auto-discover: take all .py files in dir except __init__ and _util
        declared = []
        for f in sorted(det_dir.glob("*.py")):
            name = f.stem
            if name.startswith("_") or name == "__init__":
                continue
            declared.append(name)
    for name in declared:
        path = det_dir / f"{name}.py"
        if not path.exists():
            continue
        try:
            mod = _load_module(path, f"zfm_det_{framework}_{name}")
        except Exception as exc:
            sys.stderr.write(f"[zfm] warn: failed to load {path}: {exc}\n")
            continue
        if not hasattr(mod, "run_text"):
            continue
        detectors.append((name, mod))
    return detectors


def _lookup_cache_path(workspace: Path | None) -> Path | None:
    if workspace is None:
        return None
    return workspace / ".auditooor" / "zk_template_lookup_cache.json"


def _read_lookup_cache(path: Path | None) -> dict[str, Any]:
    if path is None or not path.exists():
        return {}
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {}
    if not isinstance(data, dict):
        return {}
    return data


def _write_lookup_cache(path: Path | None, data: dict[str, Any]) -> None:
    if path is None:
        return
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        tmp = path.with_suffix(path.suffix + ".tmp")
        tmp.write_text(json.dumps(data, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        tmp.replace(path)
    except OSError:
        return


def _call_mcp_zk_template_lookup(
    framework: str,
    template_name: str,
    limit: int = 8,
    workspace: Path | None = None,
) -> dict[str, Any]:
    """Invoke the MCP server via subprocess (CLI mode) for prior findings."""
    cache_path = _lookup_cache_path(workspace)
    cache = _read_lookup_cache(cache_path)
    cache_key = f"{framework}\t{template_name}\t{limit}"
    cached = cache.get(cache_key)
    if isinstance(cached, dict):
        return cached

    args = json.dumps({"framework": framework, "template_name": template_name, "limit": limit})
    try:
        proc = subprocess.run(
            [
                sys.executable,
                str(ROOT / "tools" / "vault-mcp-server.py"),
                "--call",
                "vault_zk_template_lookup",
                "--args",
                args,
            ],
            capture_output=True,
            text=True,
            timeout=60,
        )
    except subprocess.TimeoutExpired:
        return {"error": "mcp_timeout"}
    if proc.returncode != 0:
        return {"error": "mcp_failed", "stderr": proc.stderr[:500]}
    # Strip any "[vault-mcp-server]" prefix lines
    payload_lines: list[str] = []
    in_json = False
    for line in proc.stdout.splitlines():
        if line.startswith("{"):
            in_json = True
        if in_json:
            payload_lines.append(line)
    blob = "\n".join(payload_lines)
    try:
        result = json.loads(blob)
    except json.JSONDecodeError:
        return {"error": "mcp_unparseable", "raw": blob[:500]}
    if isinstance(result, dict) and "error" not in result:
        cache[cache_key] = result
        _write_lookup_cache(cache_path, cache)
    return result


def _classify_text_via_verifier(text: str, framework: str | None = None) -> dict[str, Any]:
    """Pipe `text` to zkbugs-prior-audit-class-verifier.py --classify-stdin
    and return its JSON output. Returns {} on failure."""
    if not text.strip():
        return {}
    args = [
        sys.executable,
        str(ROOT / "tools" / "zkbugs-prior-audit-class-verifier.py"),
        "--classify-stdin",
        "--json",
    ]
    if framework:
        args.extend(["--framework", framework])
    try:
        proc = subprocess.run(
            args, input=text, capture_output=True, text=True, timeout=30
        )
    except (subprocess.TimeoutExpired, FileNotFoundError):
        return {}
    if proc.returncode not in (0, 1, 2):  # tool may use rc to encode classification
        return {}
    try:
        return json.loads(proc.stdout)
    except json.JSONDecodeError:
        # Fall back to textual capture
        return {"raw_stdout": proc.stdout[:400], "raw_returncode": proc.returncode}


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="ZK per-template mindset orchestrator")
    ap.add_argument(
        "source",
        help=(
            "Path to source file (circom, halo2/rust, noir, plonky2, cairo, "
            "plonky3, bellperson, arkworks, risc0, pil, gnark, or "
            "solidity/solidity-honk on-chain verifier)"
        ),
    )
    ap.add_argument("--template", required=True, help="Template / chip / fn name to focus on")
    ap.add_argument(
        "--framework",
        choices=[
            "circom", "halo2", "plonky2", "noir", "cairo",
            # Wave-7 minor frameworks:
            "plonky3", "bellperson", "arkworks", "risc0", "pil", "gnark",
            # Solidity on-chain ZK verifier (Honk/barretenberg) arm:
            "solidity", "solidity-honk",
        ],
        help="Override framework inference (default: infer from file extension)",
    )
    ap.add_argument("--workspace", default=".", help="Workspace dir for output (default cwd)")
    ap.add_argument("--no-mcp", action="store_true", help="Skip vault_zk_template_lookup call")
    ap.add_argument("--no-verifier", action="store_true", help="Skip prior-audit-class-verifier calls")
    args = ap.parse_args(argv)

    src_path = Path(args.source)
    if not src_path.exists():
        sys.stderr.write(f"error: source file not found: {src_path}\n")
        return 2
    source = src_path.read_text(encoding="utf-8")

    framework = args.framework
    if framework is None:
        ext = src_path.suffix.lower()
        if ext == ".circom":
            framework = "circom"
        elif ext == ".nr":
            framework = "noir"
        elif ext == ".cairo":
            framework = "cairo"
        elif ext == ".pil":
            framework = "pil"
        elif ext == ".sol":
            # Solidity files: default to the on-chain ZK verifier (Honk /
            # barretenberg) arm. zk-hunt Stage 3 dispatches .sol files here.
            framework = "solidity-honk"
        elif ext == ".go":
            # .go files: default to gnark (other Go ZK libs not yet wired)
            framework = "gnark"
        else:
            # .rs files: default to halo2, but plonky2/plonky3/bellperson/
            # arkworks/risc0 are also rust-based.
            # Caller should use --framework <name> explicitly for those.
            framework = "halo2"

    # zk-hunt Stage 3 passes "--framework solidity"; the canonical corpus /
    # MCP tag is "solidity-honk". Normalize the alias so the prior-finding
    # lookup and detector routing both see one value.
    if framework == "solidity":
        framework = "solidity-honk"

    template_body, body_start, body_end = _extract_template_body(
        source, args.template, framework
    )

    # 1. Run detectors against the template body. Prepend the file's
    # imports / module-level lines so framework-detection (e.g.
    # is_halo2_file) succeeds even when the extracted body is only
    # the inner impl/template block.
    imports_prefix = ""
    # For Rust-based frameworks, prepend use/extern crate lines so that
    # framework-detection heuristics (is_halo2_file, is_plonky3_file, etc.)
    # succeed even when the extracted body is just an inner impl/template block.
    _rust_frameworks = {"halo2", "plonky2", "plonky3", "bellperson", "arkworks", "risc0"}
    if framework in _rust_frameworks:
        for line in source.splitlines():
            stripped = line.strip()
            if stripped.startswith("use ") or stripped.startswith("extern crate"):
                imports_prefix += line + "\n"
            elif stripped.startswith("//") or stripped.startswith("#") or not stripped:
                continue
            else:
                break
    elif framework == "gnark":
        # For Go files, prepend the import block so is_gnark_file succeeds.
        in_import = False
        for line in source.splitlines():
            stripped = line.strip()
            if stripped.startswith("import"):
                in_import = True
            if in_import:
                imports_prefix += line + "\n"
                if stripped == ")":
                    break
    detector_input = imports_prefix + template_body
    detectors = _load_detectors_for_framework(framework)
    detector_hits: list[dict[str, Any]] = []
    for name, mod in detectors:
        try:
            hits = mod.run_text(detector_input, str(src_path))
        except Exception as exc:
            sys.stderr.write(f"[zfm] detector {name} raised: {exc}\n")
            continue
        for h in hits:
            h.setdefault("detector_name", name)
            detector_hits.append(h)

    workspace = Path(args.workspace).resolve()

    # 2. Prior-finding lookup
    prior = {}
    if not args.no_mcp:
        prior = _call_mcp_zk_template_lookup(
            framework,
            args.template,
            limit=8,
            workspace=workspace,
        )

    # 3. Classify detector hits + prior findings
    classifications: list[dict[str, Any]] = []
    if not args.no_verifier:
        for h in detector_hits:
            text = f"{h.get('message','')} {h.get('snippet','')}"
            cls = _classify_text_via_verifier(text, framework=framework)
            classifications.append({"source": "detector", "detector_id": h.get("detector_id"), "result": cls})
        for ex in (prior.get("exemplars") or [])[:5]:
            blob = " ".join(
                str(ex.get(k) or "")
                for k in ("title", "short_vulnerability", "proposed_mitigation")
            )
            cls = _classify_text_via_verifier(blob, framework=framework)
            classifications.append({"source": "prior_zkbugs", "bug_id": ex.get("bug_id"), "result": cls})

    # 4. Emit Markdown brief
    ts = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H-%M-%SZ")
    out_dir = workspace / ".auditooor"
    out_dir.mkdir(parents=True, exist_ok=True)
    safe_template = re.sub(r"[^A-Za-z0-9_.-]+", "_", args.template)
    out_path = out_dir / f"zk_function_mindset_{framework}_{safe_template}_{ts}.md"

    lines: list[str] = []
    lines.append(f"# ZK Function-Mindset Brief - {framework} / `{args.template}`")
    lines.append("")
    lines.append(f"- Source file: `{src_path}`")
    lines.append(f"- Framework: `{framework}`")
    lines.append(f"- Template body bytes: `{body_start}..{body_end}` ({body_end - body_start} bytes)")
    lines.append(f"- Generated: `{ts}`")
    if prior.get("context_pack_id"):
        lines.append(f"- MCP context_pack_id: `{prior['context_pack_id']}`")
        lines.append(f"- MCP context_pack_hash: `{prior.get('context_pack_hash','')}`")
    lines.append("")

    lines.append("## (a) Detector hits")
    if not detector_hits:
        lines.append("- _no hits_ (template body did not match any detector pattern)")
    else:
        for h in detector_hits:
            lines.append(
                f"- **{h.get('detector_id','?')}** "
                f"({h.get('severity','?')}) @ line {h.get('line','?')}: "
                f"{(h.get('message','') or '')[:240]}"
            )
    lines.append("")

    lines.append("## (b) Prior-finding collisions (DROP-class-b candidates)")
    exemplars = prior.get("exemplars") or []
    if not exemplars:
        lines.append("- _no matching zkBugs corpus records_ - fresh template surface, no immediate dupe risk")
    else:
        lines.append(f"- {prior.get('total_found', len(exemplars))} prior records in zkBugs corpus matched.")
        for ex in exemplars[:5]:
            lines.append(
                f"  - **{ex.get('bug_id','?')}** "
                f"({ex.get('dsl','?')}): {(ex.get('title','') or '')[:160]}"
            )
            if ex.get("root_cause"):
                lines.append(f"    - root_cause: {ex['root_cause']}")
            if ex.get("proposed_mitigation"):
                lines.append(f"    - mitigation: {(ex['proposed_mitigation'] or '')[:200]}")
    lines.append("")

    lines.append("## (c) Novel hypotheses (NOVEL-CANDIDATE)")
    novel = [c for c in classifications if c.get("source") == "detector" and c.get("result", {}).get("verdict", "") in ("", "NOVEL-CANDIDATE")]
    if not novel:
        lines.append("- _no novel hypotheses surfaced_; review detector hits manually for genuinely-new shapes.")
    else:
        for c in novel:
            lines.append(f"- detector `{c.get('detector_id')}` → {c.get('result', {}).get('verdict', 'UNCLASSIFIED')}")
    lines.append("")

    lines.append("## (d) Recommended next steps")
    if detector_hits and exemplars:
        lines.append("- HIGH-PRIORITY: detector hits AND prior zkBugs corpus matches both present - likely L31 duplicate territory. Run `tools/duplicate-preflight-check.py` against the workspace's existing submissions before drafting.")
    elif detector_hits and not exemplars:
        lines.append("- INVESTIGATE: detector hits without prior corpus collision - candidate novel finding. Build PoC + draft per L17 build-is-default.")
    elif not detector_hits and exemplars:
        lines.append("- ENRICH: no detector hit but prior zkBugs records exist for the template - consider adding a missing-protection detector tuned to the prior root_cause.")
    else:
        lines.append("- NEGATIVE: no detector hit and no prior corpus record. Either the template is well-constrained or the framework has weak detector coverage; consider adding a new detector pattern.")
    lines.append("")
    lines.append(f"- Sources consulted: {', '.join(prior.get('source_refs', [])) or '_(none)_'}")
    lines.append("")
    lines.append("---")
    lines.append(f"_generated by tools/zk-function-mindset.py at {ts}_")

    out_path.write_text("\n".join(lines) + "\n", encoding="utf-8")

    # Stdout summary
    print(f"[zfm] wrote {out_path}")
    print(
        f"[zfm] framework={framework} template={args.template} "
        f"detector_hits={len(detector_hits)} prior_corpus_matches={prior.get('total_found', 0)}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
