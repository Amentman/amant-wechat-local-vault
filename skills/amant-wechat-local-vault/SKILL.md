---
name: amant-wechat-local-vault
description: Use when a macOS user wants to inspect, decrypt, search, export, or summarize their own or explicitly authorized local WeChat 4.x data, including automatic local key capture with explicit consent.
---

# 寂辉微信本地资料库

当前公开版本：v0.3.3。

只处理当前用户本人或已获明确授权的本机微信数据。默认本地运行，不上传、不发消息、不操作微信聊天界面。

## 总体运行流程

本 Skill 的 `输入 → 处理 → 输出` 是：

1. **输入**：用户对本人或已授权数据的本次明确许可、捕获模式、用户指定的加密数据库绝对路径，以及与源文件不同的输出路径。
2. **环境准备**：bootstrap 锁定依赖，doctor 检查 macOS、微信、codesign 和运行库；环境不完整就停止。
3. **授权与预演**：任何私有数据命令先确认授权并要求 `--authorized`；真实捕获前先执行 dry-run，展示 attach/launch-copy、时长和保存位置。
4. **密钥处理**：限定时间监听本机派生函数，把新候选与已有候选按 key/salt 去重合并到 `0600` 私有文件；终端只显示指纹。候选为零时返回 `no-candidates` 并保留旧 key store，不报成功、不擅自升级权限。
5. **解密处理**：只读用户指定的源 DB，用候选 key 逐页做 HMAC 验证并写入新的 owner-only 明文副本；任何页失败即停止。
6. **本地利用**：先 digest 真实表结构，再只读搜索、浏览候选功能表或导出；默认脱敏，明确要求正文才使用 `--show-content`。
7. **输出**：返回实际本地路径、候选/表/匹配/导出数量和每个阶段状态；密钥、明文 DB 和正文不进入普通日志或远端。
8. **边界**：不发送消息、不操作聊天界面、不修改原 WeChat.app、不上传、不采集他人设备，也不把候选密钥或模糊表名当成完整解析成功。

## 强制安全门

下面所有相对命令都以包含此 `SKILL.md` 的目录为基准，不以用户当前工作目录为基准。

1. 先运行 `python3 scripts/bootstrap.py --check`。返回 `missing` 或 `incomplete`
   时运行 `python3 scripts/bootstrap.py --install`，然后使用返回的
   `runtime_python` 执行 `wechat_vault.py`，不要调用未安装依赖的系统 Python。
2. 在复制 App、重签名、启动 Frida、读取数据库或写出明文前，说明动作与目标，并取得当前用户明确确认。
3. 任何私有数据命令必须带 `--authorized`；不得替用户推定授权。
4. 永不修改 `/Applications/WeChat.app`。需要重新启动时只操作工具目录内的副本。
5. 日志和普通输出只显示密钥、salt、wxid 和正文的指纹或脱敏预览。完整搜索结果只在用户明确要求时用 `--show-content`。

## 工作流

1. `doctor` 检查 macOS、微信、codesign、Python、Frida、PyCryptodome 和 Zstandard。
2. 先用 `capture-keys --authorized --dry-run` 展示计划。
3. 已运行的微信可直接 attach；需要启动工具副本时使用 `--launch-copy`。捕获结果与已有候选去重合并后写入仅当前用户可读的私有文件，终端只显示指纹；零候选不改写旧文件。
4. 用 `decrypt --authorized --source-db ... --output ... --key-fingerprint ...` 从 owner-only `keys.json` 选择候选，在临时文件中验证全部页面后原子写成明文副本。拒绝源/输出同文件，默认拒绝覆盖现有输出；完整 key 不进入命令行。
5. 使用带 `--authorized` 的 `search`、`contacts`、`moments`、`favorites`、`export` 和 `digest` 处理解密后的 SQLite 文件。微信版本与表结构不一致时，先用 `digest` 查看实际表，再选择关键词。

## 重要限制

- 微信更新可能改变 KDF 调用或数据库格式；HMAC 校验失败就停止，不猜 key、不输出伪成功。
- 自动捕获会监听本机进程中的密钥派生函数。只有在微信执行相应派生操作时才会出现候选密钥。
- 本次没有候选时必须报告 `no-candidates`，保留旧 key store，并明确本次捕获未完成；不得把退出码 3 或 `candidate_count: 0` 当成功。
- 解密和导出默认不覆盖已有文件；只有用户明确要求替换时使用 `--overwrite`。任一步失败都不得留下部分输出或损坏旧文件。
- `contacts`、`moments` 和 `favorites` 使用数据库无关的文本检索；它们不会声称理解未知私有表结构。
- 不提供消息发送、账号接管、绕过远程认证、云同步或他人设备采集能力。

公开实现依据和许可证边界见 [implementation-sources.md](references/implementation-sources.md)。
普通使用不需要加载这份维护说明。
