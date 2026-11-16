# 架构说明

## 范围

`mailatt` 是单机批处理流水线：发现本地邮件导出，解析 MIME，执行附件策略，写入内容
寻址对象与 SQLite 台账，再生成静态审计报告。运行期无网络依赖，Web 仅是回环地址上的
只读视图。

## 数据流

1. `config.py` 读取 YAML，解析相对路径，校验 source / workdir 不互相嵌套。
2. `discovery.py` 稳定排序扫描 `.eml` 树、Maildir 的 `cur/`、`new/` 或 mbox 容器，
   忽略符号链接，计算邮件 SHA-256，并通过回调跳过摘要与策略指纹均未变的成功邮件。
   mbox 容器由 `mbox.py` 按声明方言（`mboxo`/`mboxrd`/`mboxcl`/`mboxcl2`）以字节偏移
   切分为带稳定序号的消息切片；无法证明边界的区域成为隔离段，不参与解析。
3. `mime.py` 使用标准库 `email` 解析 MIME，遍历嵌套 `message/rfc822`，解码 RFC 2047
   文件名与主题，提取附件字节。致命边界缺陷转换为稳定 `MALFORMED_MIME` 错误。
4. `policy.py` 按固定顺序执行路径、数量、inline、大小、扩展名、MIME、重复内容门禁，
   产出 `accepted`、`quarantined`、`rejected` 或 `duplicate`。
5. `storage.py` 以 SHA-256 内容寻址写对象。归档与隔离分目录，使用同目录临时文件、
   `fsync` 和 `os.replace` 原子落盘；已存在同摘要对象时复用。
6. `ledger.py` 以事务写入 `runs`、`messages`、`attachments`。消息唯一键为
   `(source_name, relative_path)`，附件唯一键为 `(message_id, part_id)`，因此重跑不会
   产生重复行。同步附件时保留 `first_seen_run`。
7. `runner.py` 编排单封邮件，捕获每封邮件的全部异常，记录错误后继续；运行结束生成
   `manifest.json` 与三类报告。
8. `verify.py` 只读打开台账，重算对象哈希，核对 manifest、台账引用和实际文件。
9. `web.py` 只读打开台账；GET 页面与 JSON 接口复用同一 SQLite 数据。下载只允许
   `accepted` / `duplicate` 且对象路径经过正则与目录边界校验。

## 模块边界

| 模块 | 职责 | 不负责 |
| --- | --- | --- |
| `discovery` | 枚举、排序、摘要、增量判定 | 解析 MIME |
| `mbox` | 方言边界证明、字节切片、转义还原 | 对象与台账写入 |
| `mime` | 解析与附件候选 | 策略决策 |
| `policy` | 纯函数式门禁 | 磁盘写入 |
| `storage` | 对象字节与路径安全 | 台账事务 |
| `ledger` | SQLite 持久化与查询 | 内存策略 |
| `runner` | 流程编排与错误隔离 | HTTP / 报告模板 |
| `report` | 派生只读视图 | 修改台账 |
| `verify` | 完整性检查 | 修复或删除 |
| `web` | 只读浏览与下载 | 写入、删除、上传 |

## 状态机

邮件：

```text
discovered -> skipped(unchanged, ok) -> done
discovered -> parsed -> ok
discovered -> failed -> error (recorded, batch continues)
```

附件判定：

```text
candidate -> accepted    -> objects/<prefix>/<sha>
          -> quarantined -> quarantine/<prefix>/<sha>
          -> rejected    -> ledger only
          -> duplicate   -> reuse existing object
```

归档对象没有可变状态；其完整性由路径中的 SHA-256、实际内容哈希、manifest 条目和台账
引用四方共同约束。

## 确定性

- 来源按名称排序，文件按 source + POSIX 相对路径排序，附件按 MIME 遍历顺序编号。
- JSON 以 `sort_keys=True` 写出；查询使用显式 `ORDER BY`。
- 对象路径只由内容摘要决定；台账使用唯一约束和 `ON CONFLICT` 更新。
- 运行时间与 `run_id` 会被记录，但同一输入的字段和对象集合稳定可复现。
- 测试通过固定时钟注入，避免时间相关断言。

## 失败隔离与安全

单封坏邮件只产生一条 `messages.status='error'` 记录，并清空该消息的附件记录；不会中断
后续邮件。mbox 容器中无法证明边界的区域以 `MBOX_SEGMENT_QUARANTINED` 错误行计入台账
与运行摘要（`mbox_segments_quarantined`），部分导入的运行状态始终为
`completed_with_errors`，不会显示为完整成功。对象路径只接受规范格式
`objects|quarantine/<2 hex>/<64 hex>`，拒绝符号链接和越界路径。报告与 Web 模板自动
转义不可信邮件头、文件名和错误文本。只读数据库连接使用 SQLite `mode=ro`，Web 不提供
任何写方法。
