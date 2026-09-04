from __future__ import annotations

import json
import re
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def assert_relative_markdown_links_exist(markdown_path: Path) -> None:
    text = markdown_path.read_text()
    for target in re.findall(r"\[[^\]]+\]\(([^)]+)\)", text):
        target = target.strip("<>").split("#", 1)[0]
        if not target or "://" in target or target.startswith("#"):
            continue
        assert (markdown_path.parent / target).exists(), f"broken link: {markdown_path}:{target}"


def assert_workflow_docs_complete(readme: str, skill_text: str) -> None:
    required_readme_sections = [
        "## 这个 Skill 解决什么问题",
        "## 整体运行流程",
        "## 开始前准备",
        "## 安装",
        "## 第一次使用",
        "## 每一步会发生什么",
        "## 输入与输出",
        "## 完整示例",
        "## 失败、停止与授权边界",
        "## 如何确认真的完成",
    ]
    for section in required_readme_sections:
        assert section in readme, f"README missing workflow section: {section}"
    assert "```mermaid" in readme, "README missing rendered workflow diagram"
    assert "| 步骤 | 用户提供或决定 | Skill 会做什么 | 可验证产物 |" in readme
    assert "## 总体运行流程" in skill_text, "SKILL.md missing agent execution overview"
    assert "输入 → 处理 → 输出" in skill_text
    assert "cd ~/.agents/skills/amant-wechat-local-vault" in readme
    assert "cd .agents/skills/amant-wechat-local-vault" in readme
    assert "--key-hex" not in readme
    assert "--key-hex" not in skill_text
    assert "--key-fingerprint" in readme
    assert "原子" in readme


def main() -> None:
    manifest = json.loads((ROOT / ".codex-plugin" / "plugin.json").read_text())
    assert manifest["version"] == "0.3.1"
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
    assert_workflow_docs_complete(readme, skill_text)
    for markdown_path in [ROOT / "README.md", skill_dirs[0] / "SKILL.md"]:
        assert_relative_markdown_links_exist(markdown_path)

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
