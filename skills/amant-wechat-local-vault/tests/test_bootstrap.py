import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from scripts.bootstrap import build_bootstrap_plan, check_runtime


class BootstrapTests(unittest.TestCase):
    def test_requirements_are_exactly_pinned(self):
        requirements = (Path(__file__).resolve().parents[1] / "requirements.txt").read_text().splitlines()
        self.assertEqual(requirements, [
            "frida==17.17.0",
            "pycryptodome==3.23.0",
            "zstandard==0.25.0",
        ])

    def test_bootstrap_creates_an_isolated_runtime_and_installs_locked_requirements(self):
        with tempfile.TemporaryDirectory() as tmp:
            skill_root = Path(tmp)
            plan = build_bootstrap_plan(skill_root=skill_root, system_python="/usr/bin/python3", platform_name="posix")
            self.assertEqual(plan, {
                "venv": str(skill_root / ".venv"),
                "python": str(skill_root / ".venv" / "bin" / "python"),
                "steps": [
                    ["/usr/bin/python3", "-m", "venv", str(skill_root / ".venv")],
                    [
                        str(skill_root / ".venv" / "bin" / "python"), "-m", "pip", "install",
                        "--disable-pip-version-check", "-r", str(skill_root / "requirements.txt"),
                    ],
                ],
            })

    @patch("scripts.bootstrap.subprocess.run")
    def test_runtime_check_probes_dependencies_without_requiring_macos_or_wechat(self, run):
        with tempfile.TemporaryDirectory() as tmp:
            skill_root = Path(tmp)
            runtime_python = skill_root / ".venv" / "bin" / "python"
            runtime_python.parent.mkdir(parents=True)
            runtime_python.write_text("")
            run.return_value.returncode = 0
            run.return_value.stdout = '{"ok": true, "checks": {"frida": true, "pycryptodome": true, "zstandard": true}}'
            run.return_value.stderr = ""

            result = check_runtime(skill_root=skill_root)

            self.assertEqual("ready", result["status"])
            command = run.call_args.args[0]
            self.assertEqual(str(runtime_python), command[0])
            self.assertEqual("-c", command[1])
            self.assertNotIn("doctor", command)


if __name__ == "__main__":
    unittest.main()
