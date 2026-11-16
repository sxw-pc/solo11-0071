# 邮件附采台 (mailatt)

一个**纯本地、完全离线、可复现**的邮件附件采集与归档工具。它扫描本地导出的 `.eml`
文件或 Maildir 目录，解析 MIME，按声明式策略筛选附件，以 SHA-256 内容寻址保存对象，
写入 SQLite 台账，生成 JSON / Markdown / 自包含 HTML 审计报告，并提供仅监听
`127.0.0.1` 的只读复核台。

从 0.2 起，它还会离线核验 `multipart/signed`（S/MIME / CMS）邮件证据，并把
**“签名字节有效”** 与 **“签名者受本地信任”** 分成两个独立结论：自签名或未知锚证书
即使签名数学正确，也只报告 `integrity_valid_but_untrusted`，不会被写成可信发件人。

仓库中的全部邮件、地址、域名和附件都是合成 fixture。示例域名统一为
`demo.invalid`，不含真实邮件、凭据或可执行附件。

## 快速开始

```bash
python -m pip install -e '.[test]'
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

### 信任锚（可选）

签名完整性完全由邮件字节与 CMS 签名决定，与配置无关。**信任**则需要本机显式配置的
证书锚；不配置时，所有有效签名都只报告 `integrity_valid_but_untrusted`。信任锚只接受
PEM/DER 证书文件，拒绝私钥、符号链接、非 CA 证书与重复指纹：

```yaml
version: 1
sources:
  - name: signed-mail
    path: ./export/signed
    kind: eml
trust:
  anchors:
    - name: demo-root
      certificate: ./certs/demo-root.pem
policy: {}
```

验证器不联网获取证书、CRL 或 OCSP，也不需要任何私钥。证书有效性按 CMS 中的
`signingTime`（若有）或运行时钟判断；这只会缩小信任范围，不会把未受信证书变成可信。

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

# 离线核验单个签名邮件的来源认证证据
python -m mailatt signature --eml fixtures/signed/mail/0001.trusted.eml \
    --config fixtures/policy/signed.yaml
python -m mailatt signature --eml fixtures/signed/mail/0003.tampered.eml \
    --config fixtures/policy/signed.yaml --json

# 仅监听 127.0.0.1 的只读复核台
python -m mailatt serve --workdir .mailatt-demo --port 8766
```

`signature` 只读取本地 `.eml` 与本地证书，输出 `integrity`、`trust`、`verdict`、
`reason_code` 与签发者证书指纹；不读取邮件服务器、不查询撤销列表、不需要私钥。

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
检查缺失、损坏、孤儿对象、manifest 与台账不一致，以及不安全路径。它还会交叉检查签名
证据：`invalid` 邮件的附件不得以 `accepted` / 可下载对象出现，`trusted` 结论必须带有
本地锚指纹。发现问题时退出码为 1。

## 来源认证结论

| 结论 | 含义 | 可下载 |
| --- | --- | --- |
| `not_signed` | 没有 `multipart/signed` 层 | 按附件策略 |
| `trusted` | 签名字节有效，且签发证书链到本地锚 | 是 |
| `integrity_valid_but_untrusted` | 签名字节有效，但签发者自签或链到未知锚 | 是（响应头标注未受信） |
| `invalid` | 被签 MIME 字节与摘要/签名不匹配 | 否；附件强制进入隔离区 |
| `unverifiable` | 格式不支持、签名材料缺失或结构无法切分 | 按附件策略，页面标注未验证 |

这些结论与当前源邮件摘要是绑定的：台账同时记录 `evidence_hash`（源摘要 + 完整签名
证据）与 `evidence_config_hash`（策略 + 信任锚集合）。源字节或锚集合任一变化，下一次
扫描都会重新验证，而不是沿用旧的 `trusted`。

## 测试

```bash
pytest -q
```

测试覆盖配置校验、稳定发现、增量跳过、MIME 与嵌套邮件、RFC 2047、策略门禁、
内容寻址去重、SQLite 幂等、失败隔离、完整性校验、报告转义、只读 Web 服务和 CLI。
签名测试额外覆盖：可信锚、自签未信任、篡改、缺材料、锚变更重验、台账迁移与完全
离线的执行路径。测试不访问网络，全部使用本地合成 fixture 与运行期内存生成的
合成证书（私钥不落盘、不进仓库）。

## 明确不做

- 不连接 IMAP / POP3 / SMTP / Exchange / Graph，不发送、不写回、不删除邮件。
- 不联网拉取证书、CRL、OCSP 或时间戳；签名验证只使用邮件内嵌证书与本机配置的锚。
- 不验证 PGP / OpenPGP 签名；非 CMS 的签名格式只报告 `unverifiable`。
- 不抓取网页，不解析远程 HTML、图片或样式。
- 不做 OCR、附件内容理解、全文检索、预览渲染、病毒查杀或宏检测。
- 不做用户系统、多租户、云存储、分布式调度或通用文件管理。
- 不提供任何写操作 HTTP 接口。

## 合规边界

本项目只应用于使用者本人拥有或已获得明确书面授权的本地邮件导出。请勿把真实邮件、
真实地址、凭据或敏感附件加入仓库。fixture 中的可疑扩展名只包含纯文本占位内容，
不能被当作样本执行。运行期不发起任何外部网络请求。
