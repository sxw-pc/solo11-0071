# 邮件附采台 (mailatt)

一个**纯本地、完全离线、可复现**的邮件附件采集与归档工具。它扫描本地导出的 `.eml`
文件或 Maildir 目录，解析 MIME，按声明式策略筛选附件，以 SHA-256 内容寻址保存对象，
写入 SQLite 台账，生成 JSON / Markdown / 自包含 HTML 审计报告，并提供仅监听
`127.0.0.1` 的只读复核台。

仓库中的全部邮件、地址、域名和附件都是合成 fixture。示例域名统一为
`demo.invalid`，不含真实邮件、凭据或可执行附件。

## 快速开始

```bash
python -m mailatt demo
pytest -q
python -m mailatt serve --workdir .mailatt-demo
```

`demo` 会采集 `fixtures/` 中的 Maildir、普通 `.eml` 和损坏邮件，输出到
`.mailatt-demo/`，随后自动执行一次完整性校验。首次运行预期结果：

| 指标 | 数值 |
| --- | ---: |
| 邮件 | 11（成功 9，失败隔离 2） |
| 附件判定 | 10 |
| 归档 | 6 |
| 隔离 | 1 |
| 拒绝 | 2 |
| 重复内容 | 1 |
| 内容寻址对象 | 7（归档 6，隔离 1） |

两个损坏 fixture 是刻意准备的失败隔离样例：空文件和错误 MIME 边界。它们会被写入
台账错误记录，但不会中断其余邮件。

再次运行 `demo` 会进行增量扫描：9 封正常邮件被跳过，2 封错误邮件会重试，已有附件和
对象不会重复写入。需要重新评估全部邮件时可加 `--force`。

## 处理流程

```text
本地 .eml / Maildir
        |
        v
稳定排序发现 -> 计算邮件哈希 -> 增量跳过
        |
        v
MIME 解析（嵌套邮件、RFC 2047、损坏降级）
        |
        v
策略门禁（路径、数量、大小、扩展名、MIME、重复内容）
        |
        +--> accepted    -> objects/<sha前2位>/<sha256>
        +--> quarantined -> quarantine/<sha前2位>/<sha256>
        +--> rejected    -> 只记录判定，不写字节
        +--> duplicate   -> 复用已有内容寻址对象
        |
        v
SQLite 台账 -> manifest.json -> reports/report.{json,md,html}
```

原始附件名只作为台账与报告元数据展示，不参与对象磁盘路径。对象写入使用同目录临时
文件加原子替换，附件字节不包含任何原始路径穿越能力。

## 配置

配置使用 YAML，路径相对于配置文件所在目录；`--workdir` 优先于文件内的 `workdir`。

```yaml
version: 1
sources:
  - name: maildir-export
    path: ./export/maildir
    kind: maildir
  - name: eml-export
    path: ./export/eml
    kind: eml
policy:
  allowed_extensions: [.pdf, .txt, .csv, .png]
  allowed_media_types: [application/pdf, text/plain, text/csv, image/png]
  quarantine_extensions: [.exe, .js, .ps1, .bat]
  blocked_extensions: [.lnk, .iso]
  max_file_bytes: 8388608
  min_file_bytes: 0
  max_attachments_per_message: 20
  max_nested_depth: 3
  max_message_bytes: 33554432
  max_filename_length: 120
  allow_nested_messages: true
  allow_inline_attachments: true
  reject_path_traversal: true
  skip_duplicate_content: true
```

完整示例见 `fixtures/policy/demo.yaml`。`kind` 可取 `auto`、`eml`、`maildir`。
`auto` 在存在 `cur/` 或 `new/` 时按 Maildir 处理。数据流与模块边界见
`docs/ARCHITECTURE.md`，门禁顺序见 `docs/POLICY.md`。

## 命令

```bash
# 使用内置 fixture 完整演示（默认 .mailatt-demo）
python -m mailatt demo
python -m mailatt demo --workdir .mailatt-demo --force

# 按配置采集
python -m mailatt run --config fixtures/policy/demo.yaml --workdir .mailatt-demo

# 重算对象哈希并核对 manifest 与 SQLite 台账
python -m mailatt verify --workdir .mailatt-demo
python -m mailatt verify --workdir .mailatt-demo --json

# 仅监听 127.0.0.1 的只读复核台
python -m mailatt serve --workdir .mailatt-demo --port 8766
```

复核台只提供 GET 读取与已归档对象的下载；隔离与拒绝项只显示元数据。POST、PUT、
PATCH、DELETE 均返回 405。服务不允许绑定 `0.0.0.0` 或其他非回环地址。

## 工作目录

```text
.mailatt-demo/
├── ledger.sqlite3
├── manifest.json
├── objects/<ab>/<sha256>       # 归档对象，无原文件名
├── quarantine/<ab>/<sha256>    # 隔离对象，无原文件名
└── reports/
    ├── report.json
    ├── report.md
    └── report.html             # 内联 CSS，无 CDN / 外部资源
```

`manifest.json` 只列出当前实际存在且被台账引用的对象。`verify` 会重算全部对象哈希，
检查缺失、损坏、孤儿对象、manifest 与台账不一致，以及不安全路径。发现问题时退出码为 1。

## 测试

```bash
pytest -q
```

测试覆盖配置校验、稳定发现、增量跳过、MIME 与嵌套邮件、RFC 2047、策略门禁、
内容寻址去重、SQLite 幂等、失败隔离、完整性校验、报告转义、只读 Web 服务和 CLI。
测试不访问网络，全部使用本地合成 fixture。

## 明确不做

- 不连接 IMAP / POP3 / SMTP / Exchange / Graph，不发送、不写回、不删除邮件。
- 不抓取网页，不解析远程 HTML、图片或样式。
- 不做 OCR、附件内容理解、全文检索、预览渲染、病毒查杀或宏检测。
- 不做用户系统、多租户、云存储、分布式调度或通用文件管理。
- 不提供任何写操作 HTTP 接口。

## 合规边界

本项目只应用于使用者本人拥有或已获得明确书面授权的本地邮件导出。请勿把真实邮件、
真实地址、凭据或敏感附件加入仓库。fixture 中的可疑扩展名只包含纯文本占位内容，
不能被当作样本执行。运行期不发起任何外部网络请求。
