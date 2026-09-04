# 寂辉微信本地资料库

面向 macOS 微信 4.x 的本地优先工具：在明确授权后自动捕获数据库派生密钥、复制并解密数据库，然后进行搜索、导出和摘要。全部数据留在本机。

> 仅用于处理你本人或你已获明确授权的数据。微信版本更新会改变内部结构；先运行 `doctor`，再在副本上工作。

## 安装 Skill

```bash
npx skills add Amentman/amant-wechat-local-vault@amant-wechat-local-vault -g -y
```

## 安装运行环境

```bash
cd ~/.agents/skills/amant-wechat-local-vault
python3 scripts/bootstrap.py --install
```

## 安全使用

```bash
# 只展示将执行的动作
.venv/bin/python scripts/wechat_vault.py capture-keys --authorized --dry-run

# 真实捕获必须显式声明授权；输出只显示密钥指纹
.venv/bin/python scripts/wechat_vault.py capture-keys --authorized

# 将下面路径和 64 位十六进制密钥替换成你的真实授权数据
.venv/bin/python scripts/wechat_vault.py decrypt --authorized --source-db "/absolute/path/to/encrypted.db" --output "/absolute/path/to/plain.db" --key-hex "REPLACE_WITH_64_HEX_KEY"
.venv/bin/python scripts/wechat_vault.py search "产品反馈" --db "/absolute/path/to/plain.db" --limit 20
.venv/bin/python scripts/wechat_vault.py export --db "/absolute/path/to/plain.db" --query "产品反馈" --format jsonl --output ./exports/result.jsonl
```

工具不发送消息、不操作微信界面、不上传远端，也不会修改 `/Applications/WeChat.app` 原件。公开实现依据见 [implementation-sources.md](skills/amant-wechat-local-vault/references/implementation-sources.md)。许可证：MIT。
