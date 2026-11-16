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
   `multipart/signed` 只遍历被签内容，分离出的签名部分不作为附件候选。
   `rawmime.py` 在**同一份原始字节快照**上按边界切出被签 MIME 与 detached 签名，
   `signature.py` 离线校验 CMS `messageDigest` 与签名值，并与 `config.trust` 的本地
   证书锚比对，分别产出 `integrity` 与 `trust`。
4. `policy.py` 按固定顺序执行路径、数量、inline、大小、扩展名、MIME、重复内容门禁，
   产出 `accepted`、`quarantined`、`rejected` 或 `duplicate`。签名 `invalid` 的邮件
   会把 `accepted` / `duplicate` 附件降级为隔离（`message_signature_invalid`），
   保证无效签名不会被当作可信归档或可下载对象。
5. `storage.py` 以 SHA-256 内容寻址写对象。归档与隔离分目录，使用同目录临时文件、
   `fsync` 和 `os.replace` 原子落盘；已存在同摘要对象时复用。
6. `ledger.py` 以事务写入 `runs`、`messages`、`attachments`。消息唯一键为
   `(source_name, relative_path)`，附件唯一键为 `(message_id, part_id)`，因此重跑不会
   产生重复行。同步附件时保留 `first_seen_run`。`messages` 保存完整性、信任、结论、
   签发者 JSON、证书/签名指纹、`evidence_hash` 与 `evidence_config_hash`；旧库通过
   幂等 `ALTER TABLE` 迁移，历史行标记为 `unverifiable / pre_signature_schema`。
7. `runner.py` 编排单封邮件，捕获每封邮件的全部异常，记录错误后继续；运行结束生成
   `manifest.json` 与三类报告。
8. `verify.py` 只读打开台账，重算对象哈希，核对 manifest、台账引用和实际文件。
9. `web.py` 只读打开台账；GET 页面与 JSON 接口复用同一 SQLite 数据。下载只允许
   `accepted` / `duplicate` 且对象路径经过正则与目录边界校验；签名 `invalid` 邮件的
   附件拒绝下载，`integrity_valid_but_untrusted` 的下载带显式结论响应头。

## 签名证据边界

- `der.py` 是受限 DER 读取器，仅支持 CMS 所需标签，长度、深度与截断均显式校验。
- `rawmime.py` 只按原始边界定位被签字节，不做行尾规范化后再验签；若精确字节不匹配，
  才尝试一次 CRLF 规范化变体，并在 `reason_code` 中披露。
- `signature.py` 支持单签名者 CMS SignedData：RSA PKCS#1 v1.5、RSA-PSS、ECDSA 与
  Ed25519；其余算法或结构返回 `unverifiable`，绝不降级成 `valid`。
- 信任判定顺序：证书在验证时刻有效 → 指纹直接命中本地锚 → 经内嵌/锚证书链到本地锚。
  自签证书与未知锚一律为 `untrusted`；`trusted` 只有本地锚能产生。
- 验证时间取 CMS `signingTime`（若存在）否则运行时钟。该值只影响证书有效期判断，
  不改变锚要求。

## 模块边界

| 模块 | 职责 | 不负责 |
| --- | --- | --- |
| `discovery` | 枚举、排序、摘要、增量判定 | 解析 MIME |
| `mime` | 解析与附件候选 | 策略决策 |
| `rawmime` | 原始字节边界切分被签内容 | 证书信任 |
| `signature` | CMS 摘要/签名验证与锚比对 | 附件策略、联网 |
| `der` | 受限 DER 读取 | 完整 X.509 解析 |
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
后续邮件。对象路径只接受规范格式 `objects|quarantine/<2 hex>/<64 hex>`，拒绝符号链接
和越界路径。报告与 Web 模板自动转义不可信邮件头、文件名和错误文本。只读数据库连接
使用 SQLite `mode=ro`，Web 不提供任何写方法。

签名验证失败不会中断采集：`invalid` 与 `unverifiable` 都是可审计的结论，而不是邮件级
错误。信任锚配置拒绝私钥、符号链接与非 CA 证书，证书内容不写入报告；报告只公开锚的
名称、路径与 SHA-256 指纹。整个验证路径不发起网络请求，测试通过替换 socket 构造函数
断言这一点。
