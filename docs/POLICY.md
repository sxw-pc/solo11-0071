# 附件策略说明

策略由 YAML 的 `policy` 段声明，缺省值定义在 `mailatt/config.py`。策略是纯函数式判定，
不会修改输入，也不执行附件内容。

## 判定顺序

以下顺序固定且对每个附件候选执行一次：

1. **路径穿越**：原始文件名含 `/`、`\`、控制字符、盘符或 `..` 路径段时，默认
   `reject_path_traversal=true`，判定为 `rejected / path_traversal`。
2. **数量上限**：候选索引超过 `max_attachments_per_message` 时，
   判定为 `rejected / attachment_count_exceeded`。
3. **inline 开关**：`allow_inline_attachments=false` 时，inline 候选被拒绝。
4. **最小大小**：小于 `min_file_bytes` 时拒绝。
5. **最大大小**：大于 `max_file_bytes` 时拒绝。超过限制的附件不会被写入。
6. **隔离扩展名**：最终扩展名命中 `quarantine_extensions`（如 `.exe`、`.js`）时，
   判定为 `quarantined / suspicious_extension`，字节写入隔离区。
7. **双扩展名链**：`report.exe.txt` 的任一前缀后缀命中隔离集合时，
   判定为 `quarantined / suspicious_extension_chain`。
8. **阻断扩展名**：命中 `blocked_extensions` 时拒绝。
9. **允许扩展名**：不在 `allowed_extensions` 中时拒绝。比较不区分大小写。
10. **允许 MIME**：不在 `allowed_media_types` 中时拒绝。支持 `image/*` 通配。
11. **重复内容**：`skip_duplicate_content=true` 且摘要已存在于已归档集合时，
    判定为 `duplicate / duplicate_content`，复用已有对象。

## 判定结果

| 状态 | 写对象 | 写台账 | 含义 |
| --- | --- | --- | --- |
| `accepted` | `objects/` | 是 | 通过全部门禁 |
| `quarantined` | `quarantine/` | 是 | 可疑扩展名，仅隔离保存 |
| `rejected` | 否 | 是 | 策略未通过 |
| `duplicate` | 否（复用） | 是 | 内容摘要已归档 |

被拒绝的附件仍保留名称、MIME、大小、原因码等元数据，便于审计。隔离对象可从台账和
报告查看，但只读复核台不提供下载。

## 文件名处理

RFC 2047 文件名先解码，再生成仅用于展示/下载的 `safe_filename`：去除控制字符、
Windows 非法字符、目录部分、尾随点与空格，并处理 Windows 保留名。原始文件名与安全
文件名都不会进入对象路径；路径只使用 SHA-256。

## 重复内容

去重集合来自两部分：台账中 `accepted` 的摘要，以及对象目录中实际存在的摘要。相同字节
在不同邮件、不同文件名下只保留一个对象。隔离内容不参与归档去重；但重复隔离内容会复用
同一内容寻址隔离文件。

## fixture 策略

`fixtures/policy/demo.yaml` 设置 8 KiB 附件上限、每封 6 个附件、隔离可执行类扩展名、
拒绝路径穿越、开启重复内容去重。演示包同时包含：

- 正常 PDF、CSV、TXT、PNG；
- RFC 2047 中文文件名；
- 嵌套邮件中的文本附件；
- 重复 PDF 内容；
- 可疑 `.exe`（纯文本占位内容，不可执行）；
- `../../escape.txt` 路径穿越；
- 超过 8 KiB 的文本附件；
- 空邮件与错误 multipart 边界。

## 限制

这不是病毒扫描器。隔离只依据文件名策略与门禁结果，不检查文件真实格式、宏、漏洞或
恶意载荷。不要执行隔离区对象，也不要将真实恶意样本放入仓库或演示目录。
