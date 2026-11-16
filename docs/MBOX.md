# MBOX 来源与方言选择

`mailatt` 可以把离线 mbox 容器作为邮件来源。容器**永远不会**被当作单封邮件：
发现阶段按字节偏移把容器切成若干消息切片，每片携带源容器路径与稳定的消息序号，
逐片进入与 `.eml` / Maildir 完全相同的 MIME、策略、对象和台账流水线。

```yaml
sources:
  - name: thunderbird-export
    path: ./export/mbox
    kind: mboxrd        # mboxo | mboxrd | mboxcl | mboxcl2
    mbox_mode: strict   # strict（默认）| recover
```

- 来源目录递归扫描 `*.mbox`（大小写不敏感），符号链接照常忽略。
- `kind: auto` **不会**猜测 mbox；方言必须显式声明。
- `mbox_mode` 只对四种 mbox 方言有效，写在其他 `kind` 上会被配置校验拒绝。

## 方言规则

四种方言的区别只在两点：**边界如何证明**、**正文 `From ` 行如何还原**。

| 方言 | 边界规则 | 正文 `From ` 转义还原 |
| --- | --- | --- |
| `mboxo` | 行首合法 envelope（`From 发件人 ctime日期`）即边界 | `>*From ` 行去掉一个 `>` |
| `mboxrd` | 同 `mboxo` | 同 `mboxo` |
| `mboxcl` | 仅信 `Content-Length`：声明正文终点必须落在下一个 envelope（可隔一个空行）或容器末尾 | 同 `mboxo` |
| `mboxcl2` | 同 `mboxcl` | **不还原**，容器字节原样保留 |

共同约定：

- envelope 必须完整匹配 `From <非空白发件人> <星期缩写> <月份缩写> <日> <时:分:秒> [时区] <年>`，
  缺少星期或日期的 `From ` 行一律视为正文，不作边界。
- 切片字节范围从 envelope 下一行开始；envelope 行本身与下一个 envelope 前的空行
  分隔行不属于任何切片。LF 与 CRLF 容器都按原字节处理，行尾不会被改写。
- 还原只按声明方言进行：`>*From ` 恰好去掉一个 `>`，其余字节（包括 `>Fromage`、
  `> From `）原样保留。不做任何启发式替换，因此 `mboxcl2` 容器的正文逐字节不变。
- `mboxo` 与 `mboxrd` 在读取侧规则相同；区别在于写出侧（`mboxrd` 会转义裸
  `From ` 行，`mboxo` 不会），所以 `mboxo` 容器中裸 `From ` 行可能是被写坏的正文。

## 如何选择方言

- 现代导出工具（Thunderbird 及大多数 `>` 转义的导出器）：`mboxrd`。
- 老式 Unix 工具写出的、只转义 `>From ` 的容器：`mboxo`。
- 每封邮件都带可信 `Content-Length` 的容器：`mboxcl`（有 `>` 转义）或
  `mboxcl2`（无转义）。Content-Length 方言对正文里形似 envelope 的行免疫：
  只要长度吻合，假 envelope 会被正确吸收进正文。
- 不确定时先用 `mboxrd` 跑 `strict`；如果出现大量隔离段，再检查容器实际格式。

## 边界无法证明时：strict 与 recover

只有边界与声明方言吻合时才会提交完整消息。典型歧义：第一封邮件声明的
`Content-Length` 覆盖了一个形似 envelope 的 `From ` 行，但按声明长度落点既不是
envelope 也不是容器末尾——长度证据与 envelope 证据冲突，无法证明边界。

- `strict`：在第一个无法证明的边界处停止，把当前容器后缀（从无法提交的那封邮件的
  envelope 到容器末尾）整体记为一个隔离段，**不猜拆分**。已证实的前缀消息正常导入。
- `recover`：歧义区同样记为隔离段（绝不并入任一正文），然后继续扫描，直到某个
  envelope 获得方言证据——例如该邮件的 `Content-Length` 恰好落在下一个合法
  envelope 或容器末尾——从该处恢复后续邮件的导入。找不到证据时隔离到容器末尾。

两种模式都会在运行摘要中计入 `mbox_segments_quarantined`，在失败隔离中写入
`MBOX_SEGMENT_QUARANTINED` 记录，运行状态为 `completed_with_errors`：
**部分导入永远不会显示为完整成功**。strict 的详情为
`strict mode stopped at ambiguous boundary ...`，recover 为
`recover mode kept ambiguous region ... and continued with proven suffix`。

## 切片身份、偏移与台账

- 消息切片台账键：`来源名/容器相对路径#序号`，序号为 6 位十进制（如
  `box.mbox#000002`）；隔离段为 `容器相对路径#seg-序号`。消息与段共用同一条
  1 起始的流式序号，因此歧义消除前后，后续消息的序号保持不变。
- 每片记录容器内字节偏移与原始长度；摘要按**还原后**的消息字节计算，因此方言或
  容器内容变化只会让受影响的切片重算，其余切片按既有增量规则跳过。
- 台账唯一键仍是 `(source_name, relative_path)`：重跑、容器追加或修复都只 upsert
  对应切片，不会产生重复行或重复对象。向容器末尾追加邮件时，已有切片身份与摘要
  保持稳定，只有新切片被处理。
- 隔离段以 `status='error'` 的消息行写入台账（不写入对象库），每次运行都会重新
  评估；容器修复后该段自然消失，历史行作为审计轨迹保留。

## 限制

- 容器在发现阶段整体读入内存切分；单个切片仍受 `policy.max_message_bytes` 限制。
- 只识别 `*.mbox` 文件；单文件容器请放入独立目录后再配置来源。
- `mboxcl` / `mboxcl2` 中缺少合法 `Content-Length` 的邮件无法自证边界，会进入
  歧义处理；此类容器应改用 `mboxrd`。
