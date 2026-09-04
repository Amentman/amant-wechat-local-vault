import tempfile
import unittest
from pathlib import Path

from scripts.bootstrap import build_bootstrap_plan


class BootstrapTests(unittest.TestCase):
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


if __name__ == "__main__":
    unittest.main()
