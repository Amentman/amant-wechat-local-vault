from __future__ import annotations

import json
import re
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def main() -> None:
    manifest = json.loads((ROOT / ".codex-plugin" / "plugin.json").read_text())
    assert manifest["version"] == "0.2.0"
    assert manifest["author"]["name"] == "Amant"
    assert manifest["skills"] == "./skills/"

    skill_dirs = [path.parent for path in (ROOT / "skills").glob("*/SKILL.md")]
    assert len(skill_dirs) == 1
    skill_text = (skill_dirs[0] / "SKILL.md").read_text()
    assert skill_text.startswith("---\n")
    name = re.search(r"^name:\s*([^\n]+)$", skill_text, re.MULTILINE)
    description = re.search(r"^description:\s*(.+)$", skill_text, re.MULTILINE)
    assert name and name.group(1).strip() == manifest["name"]
    assert description and description.group(1).strip()

    readme = (ROOT / "README.md").read_text()
    assert f"Amentman/{manifest['name']}" in readme
    assert "npx skills add" in readme

    workflow = (ROOT / ".github" / "workflows" / "test.yml").read_text()
    assert "Install and verify the real isolated runtime" in workflow
    assert "bootstrap.py --install" in workflow

    sources = (skill_dirs[0] / "references" / "implementation-sources.md").read_text()
    assert "apple-oss-distributions/CommonCrypto" in sources

    forbidden = [
        "/" + "Users/" + "amant/",
        "space" + "_id:",
        "node" + "_token:",
        "table" + "_id:",
    ]
    ignored = {".git", "node_modules", ".venv", "__pycache__"}
    public_text = "\n".join(
        path.read_text(errors="ignore")
        for path in ROOT.rglob("*")
        if path.is_file() and not ignored.intersection(path.parts)
    )
    for token in forbidden:
        assert token not in public_text, f"private token found: {token}"


if __name__ == "__main__":
    main()
