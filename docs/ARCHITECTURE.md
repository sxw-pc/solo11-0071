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
   `fsync` 和 `os.replace` 原子落盘；已存在同摘要对象时复用。
6. `ledger.py` 以事务写入 `runs`、`messages`、`attachments`。消息唯一键为
   `(source_name, relative_path)`，附件唯一键为 `(message_id, part_id)`，因此重跑不会
   产生重复行。同步附件时保留 `first_seen_run`。
7. `runner.py` 编排单封邮件，捕获每封邮件的全部异常，记录错误后继续；运行结束先在内存
   构建 `manifest.json` 载荷，再把运行记为 completed，最后由 `publish.py` 发布四件套。
8. `publish.py` 以代次为单位发布 `manifest.json`、`reports/report.json`、
   `reports/report.md`、`reports/report.html`，每个产物都带相同的 `generation` 与
   `run_id` 标记，并维护 `current.json` 指针与 `generations/<gen>/generation.json`
   摘要。
9. `verify.py` 只读打开台账，重算对象哈希，核对 manifest、台账引用和实际文件。
10. `web.py` 只读打开台账；GET 页面与 JSON 接口复用同一 SQLite 数据。下载只允许
    `accepted` / `duplicate` 且对象路径经过正则与目录边界校验。

## 模块边界

| 模块 | 职责 | 不负责 |
| --- | --- | --- |
| `discovery` | 枚举、排序、摘要、增量判定 | 解析 MIME |
| `mime` | 解析与附件候选 | 策略决策 |
| `policy` | 纯函数式门禁 | 磁盘写入 |
| `storage` | 对象字节与路径安全 | 台账事务 |
| `ledger` | SQLite 持久化与查询 | 内存策略 |
| `runner` | 流程编排与错误隔离 | HTTP / 报告模板 |
| `report` | 派生只读视图（内存构建，不写盘） | 修改台账 / 发布 |
| `publish` | 代次目录、指针与发布契约 | 台账事务 / 模板渲染 |
| `verify` | 完整性检查 | 修复或删除 |
| `web` | 只读浏览与下载 | 写入、删除、上传 |

## 发布契约与代次一致性

一次运行的可交付物固定是四件套：`manifest.json`、`reports/report.json`、
`reports/report.md`、`reports/report.html`。磁盘布局：

```text
<workdir>/
  current.json                         # 指针：contract/generation/run_id/complete
  manifest.json                        # 旧静态路径（仅为兼容，内容与指针代次一致）
  reports/report.{json,md,html}        # 旧静态路径
  generations/
    gen-000011/
      generation.json                  # 代次摘要：四件套文件名与 SHA-256 摘要
      manifest.json
      report.json
      report.md
      report.html
```

JSON 产物在对象内写入 `generation`、`run_id` 字段；Markdown 与 HTML 在首行写入
`<!-- mailatt-generation={...} -->` 标记。`current.json` 通过同目录临时文件
`os.replace` 原子切换，是唯一的可见性开关。

两种契约（`config.publish_contract`，默认 `atomic`）：

- `progressive`：逐文件写入代目录、替换旧静态路径，并在每个产物后推进 `current.json`
  （`complete=false`，四件套全部成功后改为 `true`）。读取器必须以指针代次为准核对四个
  静态路径；任一缺件或代次不一致都判定为本轮不完整，绝不能把不同代次的文件拼成一份
  “可交付报告”。
- `atomic`：先把四件套全部写入独立代目录，逐文件重算哈希并与 `generation.json` 核验，
  然后只切换一次 `current.json`，最后再刷新旧静态路径。切换前任一写入失败时，指针与静态
  路径都仍指向上一完整代次，读取者只看到旧的完整集合。

读取入口（`publish.inspect_publication` / `load_published` /
`resolve_static_paths`）只解析唯一代次：指针缺失、悬空、代次缺件、摘要不符、标记不符或
静态面代次不一致都会返回问题码或抛出 `PUBLICATION_NOT_DELIVERABLE`，不存在逐文件回退。
`verify.py` 与 CLI 的旧静态路径在成功运行时继续可用，但其代次由指针统一担保。

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
后续邮件。对象路径只接受规范格式 `objects|quarantine/<2 hex>/<64 hex>`，拒绝符号链接
和越界路径。报告与 Web 模板自动转义不可信邮件头、文件名和错误文本。只读数据库连接
使用 SQLite `mode=ro`，Web 不提供任何写方法。
