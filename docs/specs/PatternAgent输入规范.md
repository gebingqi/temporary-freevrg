# PatternAgent 输入规范（修订版）

> **状态**：本地审阅通过版，尚未同步飞书线上文档。  
> **修订依据**：原 `PatternAgent输入规范.md`、`聚类结果-二次修订版`、当前已确认的数据模型与下一阶段目标。  
> **本次修订原则**：只写入已经确定的内容；会议中尚未拍板的随机切分、自动更新机制等内容暂不纳入正式规范。

---

## 当前结论

- 语料单元仍为 **CVE**，不是 SA。
- CVE 作为语料单元，不等于必须强行拆出独立 commit；commit 证据粒度可分为 `single_commit`、`child_commit`、`composite_commit`。
- 实例层做完整分析，类层输出 pattern；正式规则优先从多实例类生成。
- 当前 33 条 train 单 CVE 样本已经形成 27 个细粒度漏洞类，其中 5 个为多实例类，22 个为单实例 draft 类。
- 当前 27 个类暂不立即合并；下一步先基于两个 `PASS_STRICT` 试点跑通 Rule Agent、CodeQL 编译、历史召回和 fixed-version 误报验证，再根据实验结果重组为更粗的漏洞族。
- 第一批 Rule Agent 只使用 `single_commit / exact_patch / PASS_STRICT` 的 pattern，多 CVE 分流结果在 grounding 通过前不进入第一批。

---

## 语料单元与样本范围

### 语料单元

语料单元为 **CVE**。

单 CVE 样本可暂时保留原始 `{sa_id}` 作为文件名或本地样本 ID，但实例分析必须显式记录 `cve` 与 `source_sa`。多 CVE 记录后续按 CVE 建实例，并保留 `source_sa` 用于溯源。

### 当前基线

- v1 基线：62 条单 CVE、extractable C 样本。
- 当前 PatternAgent 已处理训练集：33 条 train≤2021 单 CVE。
- 当前二次修订版输出：33 个实例文件、27 个细粒度漏洞类、5 个多实例 class pattern、2 个第一批 Rule Agent 试点。
- 多 CVE 待分流集合：17 条，已登记在 `data/patterns/_multi_cve_triage.json`，当前状态为 `pending_child_commit_search`。

### 时间切分

当前沿用已确认的时间切分纪律：

- `train ≤ 2021`：33 条，用于模式归纳。
- `val 2022–2024`：20 条，保留用于后续泛化验证。
- `test 2025–2026`：9 条，保留用于最终评估。

`val/test` 不进入正式 pattern 归纳。会议中讨论过随机切分或其他验证策略，但尚未形成最终决策；本版规范不引入新的切分策略。

---

## 证据粒度

### patch_granularity

`patch_granularity` 描述 CVE 与修复 commit 之间的证据关系：

```yaml
patch_granularity: single_commit | child_commit | composite_commit
```

- `single_commit`：一条 CVE 对应一个可直接使用的修复 commit，作为精确 patch 输入。
- `child_commit`：FreeBSD 合并提交下可找到 upstream 或 child commit，使用子 commit 作为精确 patch 输入。
- `composite_commit`：确实找不到子 commit 时，保留综合 commit diff，不伪造独立 commit。

### evidence_mode

`evidence_mode` 描述实例证据的提取方式：

```yaml
evidence_mode: exact_patch | child_commit_exact | cve_guided_composite
```

- `exact_patch`：直接来自单 CVE 精确补丁。
- `child_commit_exact`：来自上游或子 commit 的精确补丁。
- `cve_guided_composite`：使用单个 CVE 描述引导模型，从综合 diff 中定位相关文件、函数、hunk、source、sink、sanitizer。

### requires_review

```yaml
requires_review: true | false
```

- `false`：证据完整，已通过严格 grounding，可作为 Rule Agent 输入候选。
- `true`：需要人工复核，未复核前不能进入第一批 Rule Agent。

当前 33 个 train 实例均为：

```yaml
patch_granularity: single_commit
evidence_mode: exact_patch
requires_review: false
```

未来 `composite_commit / cve_guided_composite` 默认需要人工复核，未通过 grounding 前不进入 Rule Agent。

---

## 两层输出结构

PatternAgent 输出分为两层：

```text
实例层 data/instances/{cve}.md
  每个 CVE 一份实例分析，记录 source / sink / sanitizer / evidence。

类层 data/patterns/{class}.md
  对同类实例进行抽象，形成 class pattern，供 Rule Agent 使用。
```

实例层是证据层，类层是规则生成输入层。

单实例类只作为 draft 保留，标记 `confidence: low`，不进入第一批 Rule Agent。多实例类也必须通过 grounding 后，才允许进入 Rule Agent。

---

## 输入字段

每条样本或实例至少应包含以下字段：

| 字段 | 是否必需 | 用途 |
|---|---:|---|
| `cve` | 是 | CVE 主标识 |
| `id` / `sa_id` | 是 | 原始 SA 或样本 ID |
| `source_sa` | 是 | 多 CVE 或 SA 来源溯源 |
| `subsystem` / `module` | 是 | 模块和子系统提示 |
| `split` | 是 | `train / val / test` |
| `advisory_text` | 是 | 自然语言漏洞描述与 source 依据 |
| `files_changed` | 是 | 受影响文件 |
| `before_code` | 是 | 修复前代码片段 |
| `after_code` | 是 | 修复后代码片段 |
| `diff` | 是 | 精确或综合 patch hunk |
| `fix_commits` | 是 | 修复 commit 列表 |
| `patch_granularity` | 是 | `single_commit / child_commit / composite_commit` |
| `evidence_mode` | 是 | `exact_patch / child_commit_exact / cve_guided_composite` |
| `requires_review` | 是 | 是否需要人工复核 |

当前阶段不强制使用 `context.callers`、`context.callees`、跨函数调用图等字段；这些需要 CodeQL DB 支撑，可留到后续阶段。

---

## 实例层格式

输出路径：

```text
data/instances/{cve}.md
```

模板：

```markdown
# 实例分析：{CVE-ID}

## 基本信息
- CVE: {cve}
- SA: {source_sa}
- 子系统: {subsystem}
- 文件: {files_changed}
- split: {train|val|test}
- source_sa: {source_sa}
- fix_commits: ["{commit}"]
- patch_granularity: {single_commit|child_commit|composite_commit}
- evidence_mode: {exact_patch|child_commit_exact|cve_guided_composite}
- requires_review: {true|false}

## 漏洞类型
- CWE: {可填则填；不臆造}
- vuln_class: {细粒度漏洞类名}
- Root Cause: {1-3 句，说明漏洞根因}

## Source / Sink / Sanitizer
- Source: {外部可控输入来源}
- Sink: {危险操作、危险 API 或危险访问形态}
- Sanitizer: {修复新增或强化的检查；优先逐字摘自 diff + 行}

## 修复模式
- 改动类型: {新增检查 / 边界校验 / 类型收紧 / NULL 检查 / ...}
- 关键代码变化: {关键 diff 行}

## 适用性
- 是否可泛化: {是|否}
- 泛化条件: {该模式脱离当前函数后仍成立的条件}

## 证据
generalizable: {yes|no}
evidence:
  added_lines:
    - `{diff + 行中的新增检查}`
  sink_lines:
    - `{after_code 中仍存在的危险使用点}`
  source_basis:
    - {advisory_text 或 before_code 中的 source 依据}

VULN_CLASS_JSON: {"vuln_class": "...", "sink": "...", "added_guard": "..."}
```

---

## 类层格式

输出路径：

```text
data/patterns/{class}.md
```

模板：

```markdown
# Pattern: {漏洞类名}

## 描述
{该类漏洞的触发条件、危险使用点和修复思路；不绑定任一具体函数}

## Structured Fields
source:
  - {外部可控输入来源}
sink:
  - {危险操作 / API / 访问形态}
sanitizer:
  - {有效守护条件}
severity_hint: {high|medium|low}
confidence: {high|medium|low}
generalizable: {yes|no}
rule_candidate: {pilot|defer|no}

## 历史实例
- {CVE} @ {path::func}

## 检测建议（供 Rule Agent）
vulnerable_indicator: {有 sink 但缺少 sanitizer 的代码形态}
fixed_indicator: {sink 前已有 sanitizer 的代码形态}
target_apis: [{真实 sink、关键函数或稳定宏；不能放普通变量、类型名或弱锚点}]

rule_scope:
  language: c/cpp
  module_scope: {single-module|cross-module}
rule_type: {intra-procedural|inter-procedural|semantic}
source_predicate:
  description: {source 识别建议}
sink_predicate:
  description: {sink 识别建议}
sanitizer_predicate:
  description: {sanitizer 识别建议}
negative_examples:
  - {不应命中的代码形态}
member_anchors:
  {CVE}:
    sink:
      - {sink anchor}
    sanitizer:
      - {sanitizer anchor}
```

---

## 聚类与类重组策略

### 当前聚类策略

当前 27 个细粒度漏洞类来自 33 个 train 实例的实例层分析。初始聚类依据包括：

- source 是否同类，例如网络包字段、VM guest 输入、证书解析结果；
- sink 是否同类，例如数组索引访问、协议长度读取、指针解引用；
- sanitizer 是否同类，例如上界检查、最小长度检查、NULL 检查；
- 修复模式是否能抽象为同一类规则。

聚类不直接按模块、CWE 或文件名合并。

### 后续类重组目标

当前已确认：**27 个类偏细的问题通过实验后重组解决**。

下一步不先验硬合并，而是先使用两个 `PASS_STRICT` 试点完成规则生成和验证闭环。根据 CodeQL 规则生成难度、历史召回效果和 fixed-version 误报情况，再把细粒度类重组为更粗的上位漏洞族。

建议后续形成两层分类：

```text
上位漏洞族
  用于汇报、论文表述和系统能力归纳。

细粒度 pattern / subpattern
  用于 Rule Agent 生成 CodeQL 规则。
```

候选上位漏洞族可在实验后再确认，例如：

- 边界检查与数组索引类
- 协议长度与包解析类
- NULL 检查类
- 路径、字符串与缓冲区处理类
- 权限、状态机与逻辑错误类

以上只是重组方向，不在本版中作为最终分类结论。

---

## Grounding 验收

每个实例和 class pattern 都必须通过 grounding 检查。

### 实例层检查

- `sanitizer` 应优先命中 diff `+` 行或 after_code 中的真实新增检查。
- `sink` 应能在 after_code 中找到。
- `source` 应能从 advisory_text 或 before_code 中找到依据。
- `fix_commits`、`patch_granularity`、`evidence_mode`、`requires_review` 字段必须存在且取值合法。

### 类层检查

- class pattern 的成员 CVE 必须存在于实例层。
- `source / sink / sanitizer` 不能完全依赖单一函数名。
- `target_apis` 只能保留真实 sink、关键函数或稳定宏。
- `PASS_WEAK` 或 `rule_candidate: defer` 不进入第一批 Rule Agent。

### 结果分级

- `PASS_STRICT`：证据完整，可进入第一批 Rule Agent。
- `PASS_WEAK`：证据可解释但不够严格，需要复核或降级。
- `FAIL`：证据缺失或不一致，不能进入 Rule Agent。

---

## 第一批 Rule Agent 试点

第一批只使用以下两个 pattern：

```text
missing-array-bounds-check-on-network-controlled-index
missing-minimum-length-check-on-network-protocol-packet
```

选择条件：

- 来自 train 单 CVE 样本；
- `patch_granularity = single_commit`；
- `evidence_mode = exact_patch`；
- `requires_review = false`；
- grounding 结果为 `PASS_STRICT`；
- 具备跨模块但机制一致的历史实例。

第一批验证流程：

1. 读取 `data/patterns/_rule_candidates.json`。
2. 将两个 `PASS_STRICT` pattern 输入 Rule Agent。
3. 生成 CodeQL `.ql` 查询。
4. 做 CodeQL 编译。
5. 在 vulnerable version 上做历史漏洞召回。
6. 在 fixed version 上做误报验证。
7. 根据结果回修 pattern、Rule Agent prompt 或 QL 模板。

如果失败，优先修 pattern 或规则生成链路，不先扩大样本量。

---

## 多 CVE 处理

多 CVE 记录不能把同一份综合 diff 无区分复制给每个 CVE 后直接出正式规则。

处理顺序：

1. 优先查找 upstream 或 child commit。
2. 找到时使用 `child_commit_exact`。
3. 找不到时使用 `cve_guided_composite`。
4. `cve_guided_composite` 必须有单个 CVE 描述依据、相关文件/函数/hunk 定位、source/sink/sanitizer 证据和置信度标记。
5. 默认 `requires_review: true`。
6. 未通过 grounding 前不进入 Rule Agent。

当前 17 条多 CVE 已登记在：

```text
data/patterns/_multi_cve_triage.json
```

当前状态：

```text
pending_child_commit_search
```

---

## 暂不纳入本版规范的内容

以下内容会议中有讨论，但尚未确定，本版只保留为后续待补方向：

- 是否引入随机切分或混合切分作为补充实验；
- 自动监控官方 SA 并自动生成规则的完整更新机制；
- 新 SA 进入系统后的自动化 review gate 细节；
- 上位漏洞族的最终数量和命名；
- 多 CVE 分流完成后的正式准入标准细节。

---

## 决策状态

| 项 | 当前状态 |
|---|---|
| 语料单元 = CVE | 已确认 |
| CVE 不强制对应独立 commit | 已确认 |
| patch 证据粒度三档：`single_commit / child_commit / composite_commit` | 已确认 |
| evidence mode：`exact_patch / child_commit_exact / cve_guided_composite` | 已确认 |
| 实例层分析、类层 pattern | 已确认 |
| 单实例类先作为 draft，不进第一批 Rule Agent | 已确认 |
| 第一批只跑两个 `PASS_STRICT` 试点 | 已确认 |
| 27 个细类先保留，实验后重组 | 已确认 |
| 随机切分或混合验证策略 | 待确认 |
| 自动更新机制 | 待确认 |
| 上位漏洞族最终分类 | 待实验后确认 |
