#!/usr/bin/env python3
"""Create and verify the isolated Python runtime used by this Skill."""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
from pathlib import Path


SKILL_ROOT = Path(__file__).resolve().parents[1]


def build_bootstrap_plan(
    *,
    skill_root: Path = SKILL_ROOT,
    system_python: str = sys.executable,
    platform_name: str = os.name,
) -> dict:
    venv = skill_root / ".venv"
    runtime_python = venv / ("Scripts/python.exe" if platform_name == "nt" else "bin/python")
    return {
        "venv": str(venv),
        "python": str(runtime_python),
        "steps": [
            [system_python, "-m", "venv", str(venv)],
            [
                str(runtime_python), "-m", "pip", "install",
                "--disable-pip-version-check", "-r", str(skill_root / "requirements.txt"),
            ],
        ],
    }


def check_runtime(*, skill_root: Path = SKILL_ROOT) -> dict:
    plan = build_bootstrap_plan(skill_root=skill_root)
    runtime_python = Path(plan["python"])
    if not runtime_python.is_file():
        return {"status": "missing", "runtime_python": str(runtime_python), "doctor": None}
    result = subprocess.run(
        [str(runtime_python), str(skill_root / "scripts" / "wechat_vault.py"), "doctor"],
        check=False,
        capture_output=True,
        text=True,
    )
    try:
        report = json.loads(result.stdout)
    except json.JSONDecodeError:
        report = {"ok": False, "error": result.stderr.strip() or "doctor returned invalid output"}
    return {
        "status": "ready" if result.returncode == 0 and report.get("ok") else "incomplete",
        "runtime_python": str(runtime_python),
        "doctor": report,
    }


def install_runtime(*, skill_root: Path = SKILL_ROOT) -> dict:
    if sys.version_info < (3, 10):
        raise RuntimeError(f"Python 3.10+ is required; current version is {sys.version.split()[0]}.")
    plan = build_bootstrap_plan(skill_root=skill_root)
    for step in plan["steps"]:
        subprocess.run(step, check=True)
    report = check_runtime(skill_root=skill_root)
    if report["status"] != "ready":
        missing = [name for name, ok in (report.get("doctor") or {}).get("checks", {}).items() if not ok]
        raise RuntimeError(f"Runtime installation finished but doctor is incomplete: {', '.join(missing) or 'unknown'}")
    return report


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    modes = parser.add_mutually_exclusive_group()
    modes.add_argument("--install", action="store_true")
    modes.add_argument("--check", action="store_true")
    modes.add_argument("--dry-run", action="store_true")
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    try:
        if args.dry_run:
            print(json.dumps({"status": "dry-run", **build_bootstrap_plan()}, ensure_ascii=False, indent=2))
            return 0
        report = install_runtime() if args.install else check_runtime()
        print(json.dumps(report, ensure_ascii=False, indent=2))
        return 0 if report["status"] == "ready" else 1
    except (OSError, RuntimeError, subprocess.CalledProcessError) as exc:
        print(json.dumps({"status": "error", "error": str(exc)}, ensure_ascii=False), file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
