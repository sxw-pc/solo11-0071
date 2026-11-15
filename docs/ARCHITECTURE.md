# 架构说明

## 范围

`mailatt` 是单机批处理流水线：发现本地邮件导出，解析 MIME，执行附件策略，写入内容
寻址对象与 SQLite 台账，再生成静态审计报告。运行期无网络依赖，Web 仅是回环地址上的
只读视图。

## 数据流

1. `config.py` 读取 YAML，解析相对路径，校验 source / workdir 不互相嵌套。
2. `discovery.py` 稳定排序扫描 `.eml` 树或 Maildir 的 `cur/`、`new/`，忽略符号链接，
   计算邮件 SHA-256，并通过回调跳过摘要与策略指纹均未变的成功邮件。
3. `mime.py` 使用标准库 `email` 解析 MIME，遍历嵌套 `message/rfc822`，解码 RFC 2047
   文件名与主题，提取附件字节。致命边界缺陷转换为稳定 `MALFORMED_MIME` 错误。
4. `policy.py` 按固定顺序执行路径、数量、inline、大小、扩展名、MIME、重复内容门禁，
   产出 `accepted`、`quarantined`、`rejected` 或 `duplicate`。
5. `storage.py` 以 SHA-256 内容寻址写对象。归档与隔离分目录，使用同目录临时文件、
   `fsync` 和 `os.replace` 原子落盘；已存在同摘要对象时复用。两阶段提交先把字节写入
   `staging/<commit-key>/<sha256>`，再由恢复模块提升到正式路径；无法提交的对象进入
   `uncommitted/<commit-key>/` 并写 tombstone。
6. `ledger.py` 以事务写入 `runs`、`messages`、`attachments`。消息唯一键为
   `(source_name, relative_path)`，附件唯一键为 `(message_id, part_id)`，因此重跑不会
   产生重复行。同步附件时保留 `first_seen_run`。`commit_message` 把消息 upsert 与附件
   替换放进单个 SQLite 事务，配合 journal 构成跨存储两阶段提交的台账侧。
7. `recovery.py` 管理可恢复提交记录。journal 的稳定身份（`commit_key`）由来源路径、
   邮件摘要、MIME `part_id` 与附件摘要派生；恢复时逐项重算原邮件摘要和附件字节摘要，
   再把文件与台账引用驱动到一致终态。`recover_workdir` 默认只产出 dry-run 计划，
   `apply=True` 才执行，支持 `quarantine`（保留未提交对象供追查）与 `cleanup`
   （确认无其它台账引用后删除）两种显式策略。
8. `runner.py` 编排单封邮件：开始时先恢复残留 journal，随后逐封走暂存→提升→台账事务，
   捕获每封邮件的全部异常，记录错误后继续；运行结束生成 `manifest.json` 与三类报告。
9. `verify.py` 只读打开台账，重算对象哈希，核对 manifest、台账引用和实际文件；待提交
   journal 与未提交隔离区分别以 `PENDING_COMMIT`、`UNCOMMITTED_*` 区分于普通孤儿。
10. `web.py` 只读打开台账；GET 页面与 JSON 接口复用同一 SQLite 数据。下载只允许
   `accepted` / `duplicate` 且对象路径经过正则与目录边界校验。

## 模块边界

| 模块 | 职责 | 不负责 |
| --- | --- | --- |
| `discovery` | 枚举、排序、摘要、增量判定 | 解析 MIME |
| `mime` | 解析与附件候选 | 策略决策 |
| `policy` | 纯函数式门禁 | 磁盘写入 |
| `storage` | 对象字节、暂存区与路径安全 | 台账事务 |
| `ledger` | SQLite 持久化与查询 | 内存策略 |
| `recovery` | 提交记录、恢复计划与终态收敛 | MIME 重解析 |
| `manifest` | 从台账与对象存储派生 manifest | 修改台账 |
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

单封邮件的跨存储提交（两阶段，journal 身份由来源路径、邮件摘要、part_id、附件摘要决定）：

```text
parsed -> staged (staging/<key>/<sha> + journal.json)
       -> promoted (objects|quarantine/<prefix>/<sha>)
       -> committed (single SQLite transaction)
       -> done (journal + staging removed)

crash at any point -> recover:
   source digest & every attachment digest match -> commit to consistent state
   source changed/missing or attachment unreproducible
       -> quarantine_uncommitted (preserve in uncommitted/ + tombstone)
       -> clean_uncommitted (delete only when no other ledger reference)
```

归档对象没有可变状态；其完整性由路径中的 SHA-256、实际内容哈希、manifest 条目和台账
引用四方共同约束。暂存与未提交隔离区的对象由 journal / tombstone 单独约束，并在
`verify` 中与正式对象分开报告。

## 确定性

- 来源按名称排序，文件按 source + POSIX 相对路径排序，附件按 MIME 遍历顺序编号。
- JSON 以 `sort_keys=True` 写出；查询使用显式 `ORDER BY`。
- 对象路径只由内容摘要决定；台账使用唯一约束和 `ON CONFLICT` 更新。
- 运行时间与 `run_id` 会被记录，但同一输入的字段和对象集合稳定可复现。
- 测试通过固定时钟注入，避免时间相关断言。

## 失败隔离与安全

单封坏邮件只产生一条 `messages.status='error'` 记录，并清空该消息的附件记录；不会中断
后续邮件。对象路径只接受规范格式 `objects|quarantine/<2 hex>/<64 hex>`，拒绝符号链接
和越界路径；暂存路径限定为 `staging/<64 hex>/<64 hex>`，未提交隔离区限定为
`uncommitted/<64 hex>/`。报告与 Web 模板自动转义不可信邮件头、文件名和错误文本。只读
数据库连接使用 SQLite `mode=ro`，Web 不提供任何写方法。

跨存储提交的崩溃安全：journal 在任何对象提升前原子落盘，记录来源绝对路径、邮件摘要、
每个附件的 part_id 与字节摘要以及完整台账行数据。恢复只信任摘要核对结果——原邮件摘要
变化或附件字节无法重现时绝不把新内容接到旧消息历史。清理动作删除任何对象前都通过
`object_reference_count` 确认无其它台账引用；同一摘要被多封邮件共享时，对象只存一份，
任一消息恢复失败都不会删除仍被引用的对象。恢复计划默认 dry-run，只有显式 `--apply`
才写文件或台账，且单项失败被隔离记录而不中断整批恢复。
