#!/usr/bin/env python3
"""Opaque-box E2E Hardening Test Runner for Uncrowned King (Tiers 1-4)."""

import argparse
import importlib
import inspect
import json
import os
from pathlib import Path
import subprocess
import sys
import time
import traceback
from typing import Any, Dict, List, Optional, Sequence, Tuple

SCRIPT_DIR = Path(__file__).resolve().parent
REPO_ROOT = SCRIPT_DIR.parent.parent
if str(SCRIPT_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPT_DIR))

from uk_harness import E2ETestCase, TestContext  # noqa: E402

TIER_MODULES: Dict[int, str] = {
    1: "test_tier1_features",
    2: "test_tier2_boundaries",
    3: "test_tier3_pairwise",
    4: "test_tier4_workloads",
}


def _selected_tiers(tier_arg: str) -> List[int]:
    if tier_arg == "all":
        return [1, 2, 3, 4]
    return [int(tier_arg)]


def _discover_module_tests(tier: int, mod_name: str, ctx: TestContext) -> List[E2ETestCase]:
    mod_file = SCRIPT_DIR / f"{mod_name}.py"
    if not mod_file.exists():
        return []

    mod = importlib.import_module(mod_name)
    cases: List[E2ETestCase] = []

    if hasattr(mod, "collect_tests") and callable(mod.collect_tests):
        raw = mod.collect_tests(ctx)
    elif hasattr(mod, "TESTS"):
        raw = getattr(mod, "TESTS")
    else:
        funcs: List[Tuple[int, str, Any]] = []
        prefix = f"t{tier}_"
        for name, obj in vars(mod).items():
            if (
                callable(obj)
                and inspect.isfunction(obj)
                and obj.__module__ == mod.__name__
                and (name.startswith(prefix) or name.startswith("test_"))
            ):
                lineno = obj.__code__.co_firstlineno
                funcs.append((lineno, name, obj))
        funcs.sort(key=lambda item: item[0])
        raw = [obj for _ln, _nm, obj in funcs]

    for item in raw:
        if isinstance(item, E2ETestCase):
            cases.append(item)
        elif callable(item):
            doc = (inspect.getdoc(item) or "").splitlines()
            desc = doc[0] if doc else ""
            cases.append(
                E2ETestCase(
                    name=item.__name__,
                    tier=tier,
                    fn=item,
                    description=desc,
                )
            )
        else:
            raise TypeError(f"unsupported test item in {mod_name}: {item!r}")

    return cases


def discover_tests(
    tiers: Sequence[int], ctx: TestContext, filter_substr: Optional[str] = None
) -> Tuple[List[E2ETestCase], List[str]]:
    cases: List[E2ETestCase] = []
    missing_modules: List[str] = []
    for tier in tiers:
        mod_name = TIER_MODULES[tier]
        mod_file = SCRIPT_DIR / f"{mod_name}.py"
        if not mod_file.exists():
            missing_modules.append(f"{mod_name}.py")
            continue
        cases.extend(_discover_module_tests(tier, mod_name, ctx))
    if filter_substr:
        needle = filter_substr.lower()
        cases = [c for c in cases if needle in c.name.lower()]
    return cases, missing_modules


def _build_binaries(repo_root: Path) -> None:
    print("==> Building uk-server and uk-client via cargo build", flush=True)
    proc = subprocess.run(
        ["cargo", "build", "-p", "uk-server", "-p", "uk-client"],
        cwd=str(repo_root),
        check=False,
    )
    if proc.returncode != 0:
        raise RuntimeError(f"cargo build failed with exit code {proc.returncode}")


def _verify_binaries(ctx: TestContext) -> None:
    missing: List[str] = []
    for b in (ctx.server_bin, ctx.client_bin):
        if not b.is_file() or not os.access(b, os.X_OK):
            missing.append(str(b))
    if missing:
        raise FileNotFoundError(
            "Missing or non-executable binary(ies): " + ", ".join(missing)
        )


def parse_args(argv: Optional[Sequence[str]] = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Uncrowned King opaque-box E2E hardening test runner."
    )
    parser.add_argument(
        "--tier",
        choices=["1", "2", "3", "4", "all"],
        default="all",
        help="Test tier to execute (default: all).",
    )
    parser.add_argument(
        "--bin-dir",
        type=Path,
        default=REPO_ROOT / "target" / "debug",
        help="Directory containing uk-server and uk-client binaries.",
    )
    parser.add_argument(
        "--build",
        action="store_true",
        help="Run `cargo build -p uk-server -p uk-client` before executing tests.",
    )
    parser.add_argument(
        "--keep-artifacts",
        action="store_true",
        help="Preserve per-test temporary config/cert/log directories.",
    )
    parser.add_argument(
        "--verbose",
        action="store_true",
        help="Print detailed failure tracebacks and diagnostics.",
    )
    parser.add_argument(
        "--json-out",
        type=Path,
        default=None,
        help="Optional path to write JSON test summary report.",
    )
    parser.add_argument(
        "--filter",
        type=str,
        default=None,
        help="Only run tests whose name contains this substring.",
    )
    parser.add_argument(
        "--list",
        action="store_true",
        help="List discovered tests without executing them.",
    )
    return parser.parse_args(argv)


def _write_json_summary(
    json_out: Optional[Path],
    *,
    passed: int,
    failed: int,
    errors: int,
    total: int,
    elapsed_s: float,
    bin_dir: Path,
    missing_modules: Sequence[str],
    results: Sequence[Dict[str, Any]],
    error_message: Optional[str] = None,
) -> None:
    if json_out is None:
        return
    json_out.parent.mkdir(parents=True, exist_ok=True)
    payload: Dict[str, Any] = {
        "passed": passed,
        "failed": failed,
        "errors": errors,
        "total": total,
        "elapsed_s": round(elapsed_s, 4),
        "bin_dir": str(bin_dir),
        "missing_modules": list(missing_modules),
        "results": list(results),
    }
    if error_message is not None:
        payload["error"] = error_message
    json_out.write_text(json.dumps(payload, indent=2), encoding="utf-8")


def main(argv: Optional[Sequence[str]] = None) -> int:
    args = parse_args(argv)
    bin_dir = args.bin_dir.resolve()
    ctx = TestContext(
        bin_dir=bin_dir,
        repo_root=REPO_ROOT,
        keep_artifacts=args.keep_artifacts,
        verbose=args.verbose,
    )
    tiers = _selected_tiers(args.tier)
    cases, missing_modules = discover_tests(tiers, ctx, filter_substr=args.filter)

    if args.list:
        for c in cases:
            req = f" [{c.requirement}]" if c.requirement else ""
            print(f"[T{c.tier}] {c.name}{req}")
        print(f"Total discovered: {len(cases)}")
        if missing_modules:
            print(
                f"Note: tier module(s) not present yet: {', '.join(missing_modules)}",
                file=sys.stderr,
            )
        return 0

    if args.build:
        try:
            _build_binaries(REPO_ROOT)
        except Exception as exc:
            print(f"ERROR: {exc}", file=sys.stderr)
            _write_json_summary(
                args.json_out,
                passed=0,
                failed=0,
                errors=1,
                total=len(cases),
                elapsed_s=0.0,
                bin_dir=bin_dir,
                missing_modules=missing_modules,
                results=[],
                error_message=str(exc),
            )
            return 1

    try:
        _verify_binaries(ctx)
    except Exception as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        _write_json_summary(
            args.json_out,
            passed=0,
            failed=0,
            errors=1,
            total=len(cases),
            elapsed_s=0.0,
            bin_dir=bin_dir,
            missing_modules=missing_modules,
            results=[],
            error_message=str(exc),
        )
        return 1

    if not cases:
        msg = "No tests discovered for selected tier"
        if missing_modules:
            msg += f" (missing: {', '.join(missing_modules)})"
        print(f"ERROR: {msg}", file=sys.stderr)
        _write_json_summary(
            args.json_out,
            passed=0,
            failed=0,
            errors=1,
            total=0,
            elapsed_s=0.0,
            bin_dir=bin_dir,
            missing_modules=missing_modules,
            results=[],
            error_message=msg,
        )
        return 1

    if missing_modules:
        print(
            f"WARN: missing tier module(s): {', '.join(missing_modules)}",
            file=sys.stderr,
        )

    results: List[Dict[str, Any]] = []
    passed = 0
    failed = 0
    errors = 0
    suite_t0 = time.monotonic()

    for idx, case in enumerate(cases, 1):
        t0 = time.monotonic()
        status = "PASS"
        detail = ""
        try:
            case.fn(ctx)
            passed += 1
        except AssertionError as exc:
            status = "FAIL"
            failed += 1
            detail = traceback.format_exc() if args.verbose else (str(exc) or "AssertionError")
        except Exception as exc:
            status = "ERROR"
            errors += 1
            detail = (
                traceback.format_exc()
                if args.verbose
                else f"{type(exc).__name__}: {exc}"
            )
        elapsed = time.monotonic() - t0
        print(
            f"[{idx}/{len(cases)}] [T{case.tier}] {status:5s} {case.name} ({elapsed:.2f}s)",
            flush=True,
        )
        if detail:
            for line in detail.rstrip().splitlines():
                print(f"    {line}", flush=True)
        results.append(
            {
                "name": case.name,
                "tier": case.tier,
                "requirement": case.requirement,
                "status": status,
                "elapsed_s": round(elapsed, 4),
                "detail": detail,
            }
        )

    total_elapsed = time.monotonic() - suite_t0
    print(
        f"\nSummary: {passed} passed, {failed} failed, {errors} errors "
        f"(total={len(cases)}, elapsed={total_elapsed:.2f}s)",
        flush=True,
    )

    _write_json_summary(
        args.json_out,
        passed=passed,
        failed=failed,
        errors=errors,
        total=len(cases),
        elapsed_s=total_elapsed,
        bin_dir=bin_dir,
        missing_modules=missing_modules,
        results=results,
    )

    return 0 if (failed == 0 and errors == 0 and len(cases) > 0) else 1


if __name__ == "__main__":
    sys.exit(main())
