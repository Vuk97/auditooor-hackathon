#!/usr/bin/env python3
"""p1-fixture-extractor.py — LLM-assisted detector fixture extraction.

Reads one DSL pattern plus local workspace source context, asks Kimi (or a
test-only mock dispatcher) to author vulnerable/clean Solidity fixtures, then
treats compile + smoke-fire as truth. It never accepts fixtures on model output
alone.
"""
from __future__ import annotations

import argparse
import json
import os
import re
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Optional, Sequence


ROOT = Path(__file__).resolve().parents[1]
DEFAULT_DSL_DIR = ROOT / "reference" / "patterns.dsl"
DEFAULT_FIXTURE_DIR = ROOT / "detectors" / "test_fixtures"
DEFAULT_RUNNER = ROOT / "detectors" / "run_custom.py"
DEFAULT_DISPATCHER = ROOT / "tools" / "llm-dispatch.py"
DEFAULT_RUN_TESTS = DEFAULT_FIXTURE_DIR / "run_tests.sh"
SOURCE_SUFFIXES = {".sol", ".vy", ".rs", ".move", ".cairo", ".ts", ".js", ".md", ".txt"}

EXIT_OK = 0
EXIT_FAIL = 1
EXIT_CANNOT_RUN = 2


def _emit_err(reason: str, **fields: object) -> None:
    payload = {"reason": reason, **fields}
    print(json.dumps(payload, sort_keys=True), file=sys.stderr)


def _consent_granted() -> bool:
    return (
        os.environ.get("AUDITOOOR_LLM_NETWORK_CONSENT") == "1"
        or os.environ.get("ADVERSARIAL_LIVE_CONSENT") == "1"
    )


def _runner_requires_slither(runner: Path) -> bool:
    try:
        return runner.resolve() == DEFAULT_RUNNER.resolve()
    except OSError:
        return runner.name == "run_custom.py"


def _detector_argument_available(argument: str) -> bool:
    if not argument:
        return True
    detectors_dir = DEFAULT_RUNNER.parent
    if not detectors_dir.is_dir():
        return False
    py_files = sorted(detectors_dir.glob("*.py")) + sorted(detectors_dir.glob("wave*/*.py"))
    for py_file in py_files:
        if py_file.name.startswith("_") or py_file.name == "run_custom.py":
            continue
        try:
            text = py_file.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue
        if re.search(rf"\bARGUMENT\s*=\s*['\"]{re.escape(argument)}['\"]", text):
            return True
    return False


def _python_candidates() -> list[str]:
    candidates: list[str] = []
    env_python = os.environ.get("AUDITOOOR_PYTHON_SLITHER")
    if env_python:
        candidates.append(env_python)
    candidates.append(sys.executable)
    for name in ("python3", "python3.14", "python3.13", "python3.12", "python3.11"):
        found = shutil.which(name)
        if found:
            candidates.append(found)
    deduped: list[str] = []
    seen: set[str] = set()
    for candidate in candidates:
        if not candidate or candidate in seen:
            continue
        seen.add(candidate)
        deduped.append(candidate)
    return deduped


def _python_imports_module(python_bin: str, module: str) -> bool:
    try:
        proc = subprocess.run(
            [
                python_bin,
                "-c",
                f"import importlib.util; raise SystemExit(0 if importlib.util.find_spec({module!r}) else 1)",
            ],
            text=True,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            check=False,
            timeout=5,
        )
    except (OSError, subprocess.TimeoutExpired):
        return False
    return proc.returncode == 0


def _slither_python() -> str:
    for python_bin in _python_candidates():
        if _python_imports_module(python_bin, "slither"):
            return python_bin
    return ""


def _slither_available() -> bool:
    return bool(_slither_python())


def _slug_ok(value: str) -> bool:
    return bool(re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]*", value))


def _fixture_slug(pattern: str) -> str:
    return re.sub(r"[^A-Za-z0-9]+", "_", pattern).strip("_").lower()


def _write_failure_report(
    *,
    fixture_dir: Path,
    pattern: str,
    reason: str,
    detail: str,
    attempts: int,
    workdir: Optional[Path] = None,
    vuln_path: Optional[Path] = None,
    clean_path: Optional[Path] = None,
    runner_python: str = "",
) -> None:
    try:
        fixture_dir.mkdir(parents=True, exist_ok=True)
        payload = {
            "schema": "auditooor.p1_fixture_extraction_failure.v1",
            "pattern": pattern,
            "reason": reason,
            "attempts": attempts,
            "detail": detail,
            "workdir": str(workdir or ""),
            "vulnerable_fixture_path": str(vuln_path or ""),
            "clean_fixture_path": str(clean_path or ""),
            "runner_python": runner_python,
            "promotion_allowed": False,
            "submission_posture": "NOT_SUBMIT_READY",
            "next_action": "repair generated fixtures or rerun extraction; require solc success plus vulnerable>=1 and clean==0 smoke before promotion",
        }
        (fixture_dir / "extraction_failure.json").write_text(
            json.dumps(payload, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
    except OSError:
        return


def _read_top_level_scalar(raw: str, key: str) -> Optional[str]:
    m = re.search(rf"^{re.escape(key)}:\s*(.*?)\s*$", raw, re.M)
    if not m:
        return None
    value = m.group(1).strip()
    if (value.startswith('"') and value.endswith('"')) or (
        value.startswith("'") and value.endswith("'")
    ):
        return value[1:-1]
    return value


def load_pattern(dsl_dir: Path, pattern: str) -> dict:
    path = dsl_dir / f"{pattern}.yaml"
    if not path.is_file():
        raise FileNotFoundError(str(path))
    raw = path.read_text(encoding="utf-8")
    return {
        "path": path,
        "raw": raw,
        "pattern": _read_top_level_scalar(raw, "pattern") or pattern,
        "source": _read_top_level_scalar(raw, "source") or "",
    }


def _tokens(value: str) -> list[str]:
    stop = {"source", "solodit", "cluster", "auditooor", "finding", "pattern"}
    toks = []
    for tok in re.findall(r"[A-Za-z][A-Za-z0-9_]{3,}", value):
        low = tok.lower()
        if low not in stop:
            toks.append(low)
    return toks[:16]


def _candidate_files(workspace: Path) -> list[Path]:
    skip_parts = {".git", "node_modules", "out", "cache", "broadcast", "artifacts"}
    out: list[Path] = []
    for path in workspace.rglob("*"):
        if not path.is_file():
            continue
        if any(part in skip_parts for part in path.parts):
            continue
        if path.suffix.lower() in SOURCE_SUFFIXES:
            out.append(path)
    return out


def locate_source(
    workspace: Path,
    *,
    pattern: str,
    source: str,
    explicit: Optional[str],
) -> Path:
    if explicit:
        path = Path(explicit).expanduser()
        if not path.is_absolute():
            path = workspace / path
        if not path.is_file():
            raise FileNotFoundError(str(path))
        return path

    toks = _tokens(source) + _tokens(pattern.replace("-", " "))
    if not toks:
        raise LookupError("pattern/source yielded no useful search tokens")

    scored: list[tuple[int, Path]] = []
    for path in _candidate_files(workspace):
        try:
            text = path.read_text(encoding="utf-8", errors="ignore").lower()
        except OSError:
            continue
        score = sum(1 for tok in toks if tok in text or tok in path.name.lower())
        if source and source.lower() in text:
            score += 10
        if score >= 2:
            scored.append((score, path))
    scored.sort(key=lambda item: (-item[0], str(item[1])))
    if not scored:
        raise LookupError(f"could not locate source for {source!r}")
    if len(scored) > 1 and scored[0][0] == scored[1][0]:
        choices = ", ".join(str(path) for _score, path in scored[:5])
        raise LookupError(f"ambiguous source candidates: {choices}")
    return scored[0][1]


def _excerpt(text: str, limit: int = 18_000) -> str:
    if len(text) <= limit:
        return text
    half = limit // 2
    return text[:half] + "\n\n/* ... snip ... */\n\n" + text[-half:]


def build_prompt(pattern_doc: dict, source_path: Path, feedback: str = "") -> str:
    source_text = source_path.read_text(encoding="utf-8", errors="ignore")
    feedback_block = f"\n\nPrior validation feedback to fix:\n{feedback}\n" if feedback else ""
    return f"""You are authoring auditooor detector fixtures.

Return exactly two labelled Solidity code fences:

VULN:
```solidity
// vulnerable fixture here
```

CLEAN:
```solidity
// clean fixture here
```

Rules:
- Keep fixtures minimal and self-contained.
- Use SPDX + pragma.
- The vulnerable fixture must make the detector fire.
- The clean fixture must compile and must not make the detector fire.
- Do not include markdown outside the two labelled code fences.

Pattern DSL ({pattern_doc['path']}):
```yaml
{pattern_doc['raw']}
```

Source context ({source_path}):
```text
{_excerpt(source_text)}
```
{feedback_block}
"""


def run_dispatcher(
    *,
    prompt: str,
    workdir: Path,
    dispatcher: Path,
    provider: str,
    mock: bool,
) -> tuple[int, str, str]:
    prompt_file = workdir / f"prompt_{provider}.txt"
    prompt_file.write_text(prompt, encoding="utf-8")
    if mock:
        cmd = [str(dispatcher), "--prompt-file", str(prompt_file)]
    else:
        cmd = [
            sys.executable,
            str(dispatcher),
            "--prompt-file",
            str(prompt_file),
            "--provider",
            provider,
        ]
    proc = subprocess.run(
        cmd,
        cwd=str(ROOT),
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )
    return proc.returncode, proc.stdout, proc.stderr


def parse_fixtures(response: str) -> tuple[str, str]:
    blocks: list[tuple[str, str]] = []
    fence_re = re.compile(r"(^|\n)([^\n`]*)```[^\n`]*\n(.*?)\n```", re.S)
    for match in fence_re.finditer(response):
        label = (match.group(2) or "")[-200:].lower()
        code = match.group(3).strip() + "\n"
        blocks.append((label, code))

    vuln: Optional[str] = None
    clean: Optional[str] = None
    for label, code in blocks:
        hay = (label + "\n" + code[:400]).lower()
        if vuln is None and any(word in hay for word in ("vuln", "vulnerable", "_vuln")):
            vuln = code
            continue
        if clean is None and any(word in hay for word in ("clean", "fixed", "_clean")):
            clean = code
    if (vuln is None or clean is None) and len(blocks) >= 2:
        vuln = vuln or blocks[0][1]
        clean = clean or blocks[1][1]

    if vuln is None or clean is None:
        marker = re.search(r"===\s*VULN\s*===\s*(.*?)===\s*CLEAN\s*===\s*(.*)", response, re.I | re.S)
        if marker:
            vuln = marker.group(1).strip() + "\n"
            clean = marker.group(2).strip() + "\n"

    if not vuln or not clean:
        raise ValueError("response did not contain vulnerable and clean fixtures")
    if "pragma solidity" not in vuln or "pragma solidity" not in clean:
        raise ValueError("both fixtures must be Solidity sources with pragma solidity")
    return vuln, clean


def _state_variable_names(code: str) -> set[str]:
    """Best-effort top-level state variable names for minimal LLM fixtures."""
    names: set[str] = set()
    decl_re = re.compile(
        r"^\s*(?:"
        r"address|bool|string|bytes(?:\d+)?|u?int(?:\d+)?|"
        r"mapping\s*\([^;]+?\)|[A-Z][A-Za-z0-9_]*"
        r")\s+(?:(?:public|private|internal|external|constant|immutable)\s+)*"
        r"([A-Za-z_][A-Za-z0-9_]*)\s*(?:=|;)",
        re.M,
    )
    for match in decl_re.finditer(code):
        names.add(match.group(1))
    return names


def _function_names(code: str) -> set[str]:
    return set(re.findall(r"\bfunction\s+([A-Za-z_][A-Za-z0-9_]*)\s*\(", code))


def _contract_names(code: str) -> set[str]:
    return set(re.findall(r"\bcontract\s+([A-Za-z_][A-Za-z0-9_]*)\b", code))


def _rename_state_identifier(code: str, old: str, new: str) -> str:
    # Avoid renaming function declarations/calls. The generated fixtures are
    # small enough that this conservative lexical pass is safer than accepting
    # recurring Solidity identifier collisions from model output.
    return re.sub(rf"\b{re.escape(old)}\b(?!\s*\()", new, code)


def _rename_shadowing_parameters(code: str) -> str:
    function_names = _function_names(code)
    if not function_names:
        return code

    header_re = re.compile(
        r"function\s+[A-Za-z_][A-Za-z0-9_]*\s*\((?P<params>[^()]*)\)"
        r"(?:\s+(?:external|public|internal|private|view|pure|payable|virtual|override))*"
        r"\s*(?:returns\s*\([^{};]*\)\s*)?\{",
        re.S,
    )
    matches = list(header_re.finditer(code))
    if not matches:
        return code
    repaired = code
    replacements: list[tuple[int, int, str]] = []
    for idx, match in enumerate(matches):
        segment_end = matches[idx + 1].start() if idx + 1 < len(matches) else len(code)
        segment = code[match.start():segment_end]
        params = match.group("params")
        param_names = re.findall(r"\b[A-Za-z_][A-Za-z0-9_]*\s+([A-Za-z_][A-Za-z0-9_]*)\b", params)
        collisions = sorted(set(param_names) & function_names)
        if not collisions:
            continue
        updated_segment = segment
        header_len = match.end() - match.start()
        updated_header = updated_segment[:header_len]
        updated_body = updated_segment[header_len:]
        for old in collisions:
            new = f"{old}Arg"
            updated_header = re.sub(rf"\b{re.escape(old)}\b", new, updated_header)
            updated_body = re.sub(rf"\b{re.escape(old)}\b(?!\s*\()", new, updated_body)
        replacements.append((match.start(), segment_end, updated_header + updated_body))
    for start, end, value in reversed(replacements):
        repaired = repaired[:start] + value + repaired[end:]
    return repaired


def _rename_legacy_constructor_like_functions(code: str) -> str:
    repaired = code
    for name in sorted(_contract_names(repaired) & _function_names(repaired)):
        new = f"_{name}Helper"
        repaired = re.sub(rf"\bfunction\s+{re.escape(name)}\s*\(", f"function {new}(", repaired)
        repaired = re.sub(rf"\b{re.escape(name)}\s*\(", f"{new}(", repaired)
        repaired = re.sub(rf"\bcontract\s+_{re.escape(name)}Helper\b", f"contract {name}", repaired)
    return repaired


def repair_generated_solidity(code: str) -> str:
    """Repair common compile-only defects in generated detector fixtures.

    This is deliberately narrow: it does not try to make smoke-fire pass or
    alter detector semantics. It only fixes repeated Solidity generation
    mistakes seen in the P1 extraction queue: state/function identifier
    collisions and `view` functions that call mutating helpers.
    """
    repaired = code
    repaired = _rename_legacy_constructor_like_functions(repaired)
    for name in sorted(_state_variable_names(repaired) & _function_names(repaired)):
        repaired = _rename_state_identifier(repaired, name, f"{name}State")
    repaired = _rename_shadowing_parameters(repaired)

    def fix_header(match: re.Match[str]) -> str:
        header = match.group("header")
        body = match.group("body")
        if " view " not in header and not header.rstrip().endswith(" view"):
            return match.group(0)
        if not re.search(r"\b[A-Za-z_][A-Za-z0-9_]*\s*\([^;{}]*\)\s*;", body):
            return match.group(0)
        updated_header = re.sub(r"\s+view\b", "", header)
        return f"{updated_header}{body}}}"

    function_re = re.compile(
        r"(?P<header>function\s+[A-Za-z_][A-Za-z0-9_]*\s*\([^{};]*\)"
        r"(?:\s+(?:external|public|internal|private|view|pure|payable|virtual|override))*"
        r"\s*(?:returns\s*\([^{};]*\)\s*)?\{)"
        r"(?P<body>[^{}]*)\}",
        re.S,
    )
    repaired = function_re.sub(fix_header, repaired)
    return repaired


def compile_solidity(path: Path, solc: Optional[str]) -> tuple[bool, str]:
    if solc is None:
        return False, "solc not found; install solc or pass --skip-solc for hermetic tests"
    proc = subprocess.run(
        [solc, "--bin", str(path)],
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        check=False,
    )
    return proc.returncode == 0, proc.stdout


def _parse_total_hits(output: str) -> Optional[int]:
    m = re.search(r"total hits:\s*(\d+)", output, re.I)
    return int(m.group(1)) if m else None


def smoke_fire(
    runner: Path,
    pattern: str,
    vuln_path: Path,
    clean_path: Path,
    *,
    tier_filter: str,
    python_bin: str,
) -> tuple[bool, str]:
    problems: list[str] = []
    for mode, path in (("vuln", vuln_path), ("clean", clean_path)):
        proc = subprocess.run(
            [python_bin, str(runner), str(path), pattern, f"--tier={tier_filter}"],
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            check=False,
        )
        hits = _parse_total_hits(proc.stdout)
        if proc.returncode != 0 or hits is None:
            problems.append(f"{mode}: runner failed or omitted total hits\n{proc.stdout}")
        elif mode == "vuln" and hits < 1:
            problems.append(f"vuln: expected >=1 hit, got {hits}\n{proc.stdout}")
        elif mode == "clean" and hits != 0:
            problems.append(f"clean: expected 0 hits, got {hits}\n{proc.stdout}")
    return not problems, "\n".join(problems)


def minimax_review(
    *,
    workdir: Path,
    dispatcher: Path,
    pattern_doc: dict,
    vuln: str,
    clean: str,
    mock: bool,
) -> tuple[bool, str]:
    prompt = f"""Adversarially review this auditooor fixture pair.

Pattern:
```yaml
{pattern_doc['raw']}
```

VULN:
```solidity
{vuln}
```

CLEAN:
```solidity
{clean}
```

Reply with APPROVE if the pair distinguishes the predicate. Otherwise reply
with REJECT and the exact reason.
"""
    rc, out, err = run_dispatcher(
        prompt=prompt,
        workdir=workdir,
        dispatcher=dispatcher,
        provider="minimax",
        mock=mock,
    )
    if rc != 0:
        return False, err or out
    if "APPROVE" not in out.upper():
        return False, out
    return True, out


def append_run_tests_row(run_tests: Path, pattern: str, vuln_name: str, clean_name: str) -> None:
    row = (
        f'run_test "{pattern}" "{vuln_name}" "{pattern}"\n'
        f'run_clean_test "{pattern}" "{clean_name}" "{pattern} (clean)"\n'
    )
    if run_tests.exists():
        existing = run_tests.read_text(encoding="utf-8")
    else:
        existing = "#!/usr/bin/env bash\n"
    if f'"{vuln_name}"' in existing or f'"{clean_name}"' in existing:
        return

    marker = re.search(r"\necho\s*\nTOTAL=\$\(wc -l < \"\$STAGE\"", existing)
    if marker:
        insert_at = marker.start() + 1
        updated = existing[:insert_at] + "\n# P1 fixture extractor\n" + row + existing[insert_at:]
    else:
        updated = existing.rstrip() + "\n\n# P1 fixture extractor\n" + row
    run_tests.write_text(updated, encoding="utf-8")


def parse_args(argv: Optional[Sequence[str]]) -> argparse.Namespace:
    ap = argparse.ArgumentParser(description="Extract and smoke-fire P1 detector fixtures")
    ap.add_argument("--pattern", required=True, help="Pattern name in reference/patterns.dsl")
    ap.add_argument("--workspace", required=True, help="Workspace containing source context")
    ap.add_argument("--source-file", help="Explicit source file, absolute or workspace-relative")
    ap.add_argument("--max-attempts", type=int, default=3)
    ap.add_argument("--strict-smoke-fire", action="store_true", help="Compatibility flag; smoke-fire is always hard-gated")
    ap.add_argument("--no-minimax-review", action="store_true")
    ap.add_argument("--accept", action="store_true", help="Copy validated fixtures into detectors/test_fixtures and wire run_tests.sh")
    ap.add_argument("--dsl-dir", type=Path, default=DEFAULT_DSL_DIR)
    ap.add_argument("--fixture-dir", type=Path, default=DEFAULT_FIXTURE_DIR)
    ap.add_argument("--run-tests", type=Path, default=DEFAULT_RUN_TESTS)
    ap.add_argument("--runner", type=Path, default=DEFAULT_RUNNER)
    ap.add_argument("--smoke-tier", default="ALL", help="Detector tier filter for smoke-fire; defaults to ALL so D-tier P1 queue rows can validate")
    ap.add_argument("--dispatcher", type=Path, default=DEFAULT_DISPATCHER)
    ap.add_argument("--mock-dispatcher", type=Path, help="Test-only dispatcher; bypasses network consent")
    ap.add_argument("--skip-solc", action="store_true", help="Hermetic-test escape hatch; smoke-fire still runs")
    return ap.parse_args(argv)


def main(argv: Optional[Sequence[str]] = None) -> int:
    args = parse_args(argv)
    if not _slug_ok(args.pattern):
        _emit_err("cannot-run: invalid-pattern", pattern=args.pattern)
        return EXIT_CANNOT_RUN

    mock_dispatcher = args.mock_dispatcher or os.environ.get("AUDITOOOR_P1_FIXTURE_MOCK_DISPATCHER")
    mock = bool(mock_dispatcher)
    if _runner_requires_slither(args.runner) and not _detector_argument_available(args.pattern):
        _emit_err(
            "cannot-run: missing-detector-argument",
            detail="No compiled custom detector advertises this ARGUMENT; fixture extraction cannot be smoke-fired safely.",
            pattern=args.pattern,
            runner=str(args.runner),
        )
        return EXIT_CANNOT_RUN
    if not mock and not _consent_granted():
        _emit_err(
            "cannot-run: no-consent",
            detail="Set AUDITOOOR_LLM_NETWORK_CONSENT=1 for real provider calls, or pass --mock-dispatcher in tests.",
        )
        return EXIT_CANNOT_RUN
    slither_python = _slither_python() if _runner_requires_slither(args.runner) else ""
    if _runner_requires_slither(args.runner) and not slither_python:
        _emit_err(
            "cannot-run: missing-slither-analyzer",
            detail="Install/activate slither-analyzer or set AUDITOOOR_PYTHON_SLITHER to a Python that can import slither; this tool will not auto-install it.",
            runner=str(args.runner),
        )
        return EXIT_CANNOT_RUN
    runner_python = slither_python or sys.executable

    workspace = Path(args.workspace).expanduser().resolve()
    if not workspace.is_dir():
        _emit_err("cannot-run: workspace-missing", workspace=str(workspace))
        return EXIT_CANNOT_RUN

    try:
        pattern_doc = load_pattern(args.dsl_dir, args.pattern)
        source_path = locate_source(
            workspace,
            pattern=args.pattern,
            source=str(pattern_doc["source"]),
            explicit=args.source_file,
        )
    except (FileNotFoundError, LookupError) as exc:
        _emit_err("cannot-run: source-unlocatable", detail=str(exc))
        return EXIT_CANNOT_RUN

    workdir = Path(f"/private/tmp/auditooor-extract-{args.pattern}")
    if not str(workdir).startswith("/private/tmp/auditooor-extract-"):
        _emit_err("cannot-run: unsafe-workdir", workdir=str(workdir))
        return EXIT_CANNOT_RUN
    workdir.mkdir(parents=True, exist_ok=True)

    dispatcher = Path(mock_dispatcher) if mock_dispatcher else args.dispatcher
    solc = None if args.skip_solc else shutil.which("solc")
    feedback = ""
    last_error = ""
    slug = _fixture_slug(args.pattern)
    vuln_path = workdir / f"{slug}_vulnerable.sol"
    clean_path = workdir / f"{slug}_clean.sol"

    for attempt in range(1, max(1, args.max_attempts) + 1):
        prompt = build_prompt(pattern_doc, source_path, feedback)
        rc, out, err = run_dispatcher(
            prompt=prompt,
            workdir=workdir,
            dispatcher=dispatcher,
            provider="kimi",
            mock=mock,
        )
        if rc != 0:
            _write_failure_report(
                fixture_dir=args.fixture_dir,
                pattern=args.pattern,
                reason="dispatch-failed",
                detail=err or out[-1000:],
                attempts=attempt,
                workdir=workdir,
                vuln_path=vuln_path,
                clean_path=clean_path,
                runner_python=runner_python,
            )
            _emit_err("error: dispatch-failed", attempt=attempt, stderr=err, stdout=out[-1000:])
            return EXIT_FAIL
        try:
            vuln, clean = parse_fixtures(out)
        except ValueError as exc:
            last_error = str(exc)
            feedback = last_error
            continue
        vuln = repair_generated_solidity(vuln)
        clean = repair_generated_solidity(clean)
        vuln_path.write_text(vuln, encoding="utf-8")
        clean_path.write_text(clean, encoding="utf-8")

        if not args.skip_solc:
            ok_v, solc_v = compile_solidity(vuln_path, solc)
            ok_c, solc_c = compile_solidity(clean_path, solc)
            if not ok_v or not ok_c:
                last_error = f"solc failed\nVULN:\n{solc_v}\nCLEAN:\n{solc_c}"
                feedback = last_error
                continue

        ok_smoke, smoke_detail = smoke_fire(
            args.runner,
            args.pattern,
            vuln_path,
            clean_path,
            tier_filter=args.smoke_tier,
            python_bin=runner_python,
        )
        if not ok_smoke:
            last_error = smoke_detail
            feedback = "Smoke-fire failed; fix the fixture pair:\n" + smoke_detail
            continue

        if not args.no_minimax_review:
            ok_review, review_detail = minimax_review(
                workdir=workdir,
                dispatcher=dispatcher,
                pattern_doc=pattern_doc,
                vuln=vuln,
                clean=clean,
                mock=mock,
            )
            if not ok_review:
                last_error = "minimax review rejected:\n" + review_detail
                feedback = last_error
                continue

        accepted = False
        if args.accept:
            args.fixture_dir.mkdir(parents=True, exist_ok=True)
            final_vuln = args.fixture_dir / f"{slug}_vulnerable.sol"
            final_clean = args.fixture_dir / f"{slug}_clean.sol"
            shutil.copyfile(vuln_path, final_vuln)
            shutil.copyfile(clean_path, final_clean)
            append_run_tests_row(args.run_tests, args.pattern, final_vuln.name, final_clean.name)
            accepted = True

        print(json.dumps({
            "accepted": accepted,
            "clean": str(clean_path),
            "pattern": args.pattern,
            "runner_python": runner_python,
            "status": "ok",
            "vuln": str(vuln_path),
            "workdir": str(workdir),
        }, sort_keys=True))
        return EXIT_OK

    _emit_err(
        "error: extraction-failed",
        attempts=args.max_attempts,
        detail=last_error,
        pattern=args.pattern,
    )
    _write_failure_report(
        fixture_dir=args.fixture_dir,
        pattern=args.pattern,
        reason="extraction-failed",
        detail=last_error,
        attempts=args.max_attempts,
        workdir=workdir,
        vuln_path=vuln_path,
        clean_path=clean_path,
        runner_python=runner_python,
    )
    return EXIT_FAIL


if __name__ == "__main__":
    raise SystemExit(main())
