# multipart/related inline 资源

本文说明 `mailatt` 如何解析由 HTML 正文通过 `cid:` 引用的 inline 资源，以及两种业务
保留路线（`body-dependency` 与 `full-forensics`）的区别。实现位于
`mailatt/related.py`，由 `mailatt/mime.py` 的收集器调用。

## 问题

邮件中的内嵌图片通常长这样：

```text
multipart/related
├── text/html            ← 根正文，含 <img src="cid:logo-1">
└── image/png            ← Content-ID: <logo-1>，无文件名，Disposition: inline
```

这类部件没有 `filename`，也不带 `Content-Disposition: attachment`，因此旧的
`_is_attachment` 判定会直接跳过。若想保留它们，必须解析 HTML 中的 `cid:` 引用并和
部件建立关联。

**关键约束：不能建立全邮件范围的 CID → 部件字典。** 一封邮件可以包含多个
`multipart/related` 子树，每个子树都可能声明相同的 `Content-ID`：

```text
multipart/mixed
├── multipart/related      ← 树 A
│   ├── text/html          ← cid:image-1
│   └── image/png          ← Content-ID: <image-1>
└── multipart/related      ← 树 B
    ├── text/html          ← cid:image-1
    └── image/jpeg         ← Content-ID: <image-1>
```

全局索引会把树 A 的正文绑定到树 B 的图片，导致归档内容错误。同一子树内重复
`Content-ID` 同样不可“取第一个”，否则把歧义伪装成确定关联。

## 解析规则

每个 `multipart/related` 容器独立解析：

1. **选择根节点**
   - 容器带 `start="<cid>"` 时，只在**该容器的直接子节点**中按 Content-ID 查找；
   - 无 `start` 时取第一个子节点；
   - `start` 无匹配 → `related_start_root_missing`，不猜测根；
   - `start` 匹配多个直接子节点 → `related_start_root_ambiguous`，不猜测根。
2. **建立容器内索引** 仅对同一容器内的叶子部件建立 Content-ID → 部件路径索引，
   绝不跨容器共享。
3. **解释引用** 只有根节点是 `text/html` 时才扫描 `cid:`。非 HTML 根一律不解释
   `cid:`，并记录 `related_root_not_html`。
4. **歧义与缺失**
   - 同一容器内重复 Content-ID 且被正文引用 → 每个相关部件标为 `ambiguous`，
     并记录 `related_duplicate_content_id`（携带容器路径与全部部件路径）；
   - 正文引用的 Content-ID 在容器内不存在 → `related_missing_reference`；
   - 以上情况都不产生“确定绑定”。
5. **不跨越作用域**
   - 嵌套的 `multipart/related` 由各自的容器解析；
   - `message/rfc822` 是独立邮件，外层 related 作用域不会绑定其中的部件；
   - 损坏的 related 边界（`StartBoundaryNotFound` 等）不视为整封邮件致命错误，
     而是记录 `related_boundary_damaged` 并隔离该子树。

## 树路径

所有记录使用稳定的 1 起始、点分 MIME 树路径：

- 邮件根为 `/`；
- 第一个子节点为 `1`，第二个为 `2`；
- `1.2` 表示第一个子节点的第二个子节点；
- 排序按数值段比较，`1.2` 在 `1.10` 之前。

候选与问题记录都保存：

| 字段 | 含义 |
| --- | --- |
| `related_container_path` | 所属 `multipart/related` 容器的路径 |
| `related_root_path` | 该容器选定的根节点路径 |
| `related_part_path` | inline 资源部件自身的路径 |
| `content_id` | 资源的 Content-ID（已去掉尖括号） |
| `reference_count` | 根 HTML 中精确匹配该 Content-ID 的 `cid:` 次数 |
| `related_status` | `referenced` / `unreferenced` / `ambiguous` |

## 保留路线

由策略键 `policy.related_retention` 选择，缺省 `body-dependency`。

### `body-dependency`（正文依赖）

只保留“由同一 related 根的 HTML 引用且无歧义”的 inline 资源。

- logo-1 被引用、tracker-2 未引用 → 归档 **1** 份；
- 同容器重复 logo-1 → 相关部件标为 `ambiguous`，策略结果
  `quarantined / related_reference_ambiguous`（隔离，不归档到 `objects/`），
  绝不假装绑定了其中任意一个；
- 非 HTML 根 → 不解释 `cid:`，通常不保留任何资源。

### `full-forensics`（完整取证）

保留该邮件所有 inline 部件，包括未被引用的 tracker，也包括 related 容器之外的
未命名 inline 部件。

- logo-1 被引用、tracker-2 未引用 → 归档 **2** 份；
- 同容器重复 logo-1 → 两个原始部件都保留，但 `related_status` 仍为 `ambiguous`，
  引用问题仍记录；不会把引用错误绑定到某一个部件；
- related 容器外的未命名 inline 部件以 `related_status=unreferenced` 保留。

### 选择建议

| 目标 | 路线 |
| --- | --- |
| 仅还原正文渲染所需资源，减少无关跟踪像素 | `body-dependency` |
| 保全原始邮件全部内嵌证据，允许冗余 | `full-forensics` |

配置示例：

```yaml
policy:
  related_retention: full-forensics
```

策略指纹包含该键，因此切换路线会使依赖旧策略的增量跳过失效，重新解析。

## 与既有策略门禁的关系

关系解析只决定“哪些 inline 部件成为候选”。成为候选之后，扩展名、MIME、大小、
数量、路径穿越、重复内容等既有门禁**照常执行**，顺序不变。未命名资源会按声明
MIME 生成确定性名称，例如：

- `image/png` → `inline-p003.png`
- `image/gif` → `inline-p004.gif`
- 未知类型 → `inline-p005.bin`

这样扩展名门禁仍然对 inline 资源生效。

歧义隔离发生在扩展名/MIME/大小门禁之后、重复内容判定之前，原因码固定为
`related_reference_ambiguous`，字节写入 `quarantine/`。

## 结果模型

`mailatt/models.py`：

- `RelatedReferenceIssue`：`code`、`related_path`、`root_path`、`content_id`、
  `part_paths`、`detail`；
- `AttachmentCandidate` / `AttachmentRecord`：新增上述关系字段；
- `ParsedMessage.related_issues`：消息级问题集合（稳定排序）。

问题代码：

| 代码 | 触发条件 |
| --- | --- |
| `related_container_empty` | related 容器没有子节点 |
| `related_start_root_missing` | `start` 无匹配直接子节点 |
| `related_start_root_ambiguous` | `start` 匹配多个直接子节点 |
| `related_root_not_html` | 根不是 `text/html`，不解释 `cid:` |
| `related_duplicate_content_id` | 同一容器内 Content-ID 重复 |
| `related_missing_reference` | HTML 引用容器内不存在的 Content-ID |
| `related_boundary_damaged` | 容器边界缺失或损坏 |

## 持久化与报表

- `messages.related_issues_json`：消息级问题数组；
- `attachments`：新增 `related_root_path`、`related_part_path`、
  `related_container_path`、`content_id`、`reference_count`、`related_status`；
- `manifest.json` 保持 `objects` 按存储路径唯一（`verify` 依赖此不变式）；对象级条目
  只描述内容寻址对象。逐部件关系审计放在新增的 `parts` 数组（配 `part_count`），按
  `(source_ref, related_part_path, part_id)` 稳定排序，因此两个部件共享同一摘要时也
  不会被合并掉；
- `reports/report.{json,md,html}` 增加“inline 资源关系”和“inline 引用问题”两节；
  `/api/attachments` 也返回关系字段。

旧工作目录的 SQLite 台账在打开时会自动补齐缺失列，已有对象不受影响。

## 边界情形

| 情形 | 行为 |
| --- | --- |
| 多 related 容器含相同 Content-ID | 各自解析，互不影响 |
| `start` 根不在首位 | 按 `start` 选根，其余子节点为资源 |
| `start` 指向不存在的 ID | 不选根，记录问题，该容器不产生候选 |
| 同容器重复 ID | 引用标 `ambiguous`；两条路线都不会错误绑定 |
| 正文引用不存在的 ID | 记录 `related_missing_reference`，其余资源照常解析 |
| 嵌套 `message/rfc822` | 独立作用域，树路径更深，`nested_depth` 加一 |
| 损坏 related 边界 | 记录 `related_boundary_damaged`，不使整封邮件失败 |
| 非 HTML 根 | 不解释 `cid:`；`full-forensics` 仍可保留资源 |
| 资源位于容器的子 multipart 中 | 递归收集其叶子部件 |

## 测试

`tests/test_related.py` 覆盖：多容器重复 CID、`start` 根不在首位、缺失根、缺失引用、
同容器重复 ID、非 HTML 根、嵌套 `message/rfc822`、损坏边界、两种保留路线的端到端
差异、既有门禁叠加、台账迁移、manifest `parts` 与报表稳定排序。
