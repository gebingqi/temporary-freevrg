# PatternAgent 输入规范

# PatternAgent 输入规范

> **状态**：FINAL。合并 成员 v1 \+ 架构师版，5 项待拍板全部落定（含 ① pattern 粒度 = 类层，已确认）。取代此前所有 v1/v2。 对齐 `technical_design.md` §4\.2 / §4\.3 与 `agents/pattern_agent.py`，只对既有契约做**可选扩展**，不推翻。 配套文件：`corpus_v1_baseline.{json,csv}`（62 条基线清单）、`cluster_a_smoke_task.md`（冒烟执行指令）、`scripts/grounding_check.py`（§8 自查脚本）。
> 
> 

---

## 语料单元与基线

- **单元 = CVE**，非 SA。当前 62 条基线是干净 1:1（1 SA = 1 CVE），`id` 暂保持 `{sa_id}`；B 轮炸开的多 CVE 记录主键改用 `{cve}` \+ `source_sa` 溯源。

- **v1 基线 = 62 条**单 CVE、extractable C 样本（清单见 `corpus_v1_baseline.{json,csv}`，两份 v1 逐条一致）。

- 过滤规则： 

```Python
corpus_v1 = [d for d in all_samples if d.get("extractable") and len(d["cve"]) == 1]   # → 62
```

- **时间切分**（防泄漏，technical\_design 硬要求）： 

    - **train ≤ 2021：33 条** —— 本轮唯一参与模式归纳

    - **val 2022–2024：20 条** —— 盲测，不喂入

    - **test 2025–2026：9 条** —— 盲测，不喂入

- 不在本轮：17 条多 CVE（quarantine）、6 条 medium、70 条 upstream、2 条脚本（etcupdate/bsdinstall）。归 B 轮按 CVE 单元处理。

---

## 核心架构：两层（实例层 → 类层）

`technical_design` §4\.2：「模式粒度应以漏洞类而不是漏洞实例为单位；不建议仅凭单个孤立样本就产出正式规则，优先多实例支撑的模式。」据此，**分析在实例层做（全做），pattern 与规则在类层出（≥2 实例才出正式 pattern）**：

```Plain Text
train 33 条
  └─[实例层] 每条 → 一份「实例分析」 data/instances/{cve}.md   （成员 per-CVE 模板，全做）
        └─ 按 vuln_class 聚类
              └─[类层] 每个 ≥2 实例的类 → 一份 data/patterns/{class}.md  （喂 Rule Agent）
                       单实例类 → 出 draft，标 confidence:low，不进 Rule Agent
```

- 成员的 per\-CVE 模板在此**升格为实例层标准格式**（§4），是类层归纳的输入底座，不是被替换。

- **第一轮价值不押在"聚出很多类"上**：train 仅 33 条散在 \~35 module，多实例类预计只有 2–3 个，大量是单实例——属正常。单实例样本停在实例层 draft，等 B 轮补进 openssl/openssh 实例后类自然变厚。第一轮只要 2–3 个多实例类跑通即算成功。

---

## 每条样本喂入的字段

从 `data/samples/{sa_id}.json` 读取：

**不喂**：`context.callers/callees`（本阶段空数组）、`fix_commits`、`affected_versions`。

**核心信号 = before→after 的 delta**，三要素据此推导（而非凭 advisory 想象）：

- **sanitizer** = 修复**新增**的守护（after 比 before 多出的检查，读 diff 的 `+` 行）

- **sink** = 守护要保护的、仍保留在 after 里的危险操作（分配 / 拷贝 / 解引用 / 长度运算）

- **source** = 流入该危险操作的外部可控输入（advisory 通常点明"来自网络/用户/guest"）

---

## 实例层格式（成员 per\-CVE 模板，formalized）

输出 `data/instances/{cve}.md`，每条 train 样本一份：

```Markdown
# 实例分析：{CVE-ID}

## 基本信息
- CVE: {cve}
- SA: {id}
- 子系统: {subsystem}
- 文件: {files_changed}
- split: {train|val|test}

## 漏洞类型
- CWE: （可填则填，否则留空，不臆造）
- vuln_class: {简短类名，供聚类，如 missing-bounds-check-before-size-arith}
- Root Cause: （1–3 句）

## Source / Sink / Sanitizer
- Source: {外部可控输入来源}
- Sink: {仍保留的危险操作 / API}
- Sanitizer: {修复新增的守护，逐字摘自 diff + 行}

## 修复模式
- 改动类型: {新增检查 / 边界校验 / 类型收紧 / NULL 检查 / ...}
- 关键代码变化: {关键 diff 行}

## 适用性
- 是否可泛化: {是/否}
- 泛化条件: {脱离本函数后，该模式的成立条件}
```

> 与成员 v1 的差异仅两点：①文件名/标题从「漏洞模式」改为「实例分析」以反映其角色；②新增 `vuln_class` 字段供聚类。其余字段保留。
> 
> 

---

## 类层格式（class pattern，对齐 §4\.2）

输出 `data/patterns/{class}.md`，每个 ≥2 实例的类一份，**必须含 §4\.2 全部字段**，并**建议补充** Structured Fields 供 Rule Agent 确定性消费：

```Markdown
# Pattern: {漏洞类名，类粒度}

## 描述
{自然语言，这类漏洞的触发条件与后果，不绑定任一具体函数}

## Structured Fields
source:
  - {外部可控输入来源}
sink:
  - {危险操作 / API 形态}
sanitizer:
  - {有效守护的形态}
severity_hint: {high|medium|low}
confidence: {high | low(single-instance)}

## 历史实例
- {CVE-xxxx-xxxx} @ {path::func}   （一行一个，列全类成员）

## 检测建议（可选扩展，供 Rule Agent）
vulnerable_indicator: {"有 sink 但前缺 sanitizer" 的代码形态}
fixed_indicator:      {"sink 前已有 sanitizer" 的形态}
target_apis:          [{sink 涉及的函数/宏名，供 isSink 起锚}]
```

> 「检测建议」是可选扩展；团队不接受则删该段，不影响 §4\.2 兼容。
> 
> 

---

## 聚类方法

1. 跑完所有 train 实例层，收集每条的 `vuln_class`。

2. 按 `vuln_class` 归并；**同类不同 module 也算一簇**（跨 module 泛化是 FreeVRG 的价值）。

3. ≥2 实例 → 调类层生成；=1 实例 → draft \+ `confidence:low`，不进 Rule Agent。

---

## 两个 prompt 骨架

### ① 实例层 prompt（每条一次，temperature 0\.0，输出 §4 的 \.md；其中 vuln\_class 另抽成 JSON 便于聚类）

```Plain Text
你将看到一个 FreeBSD 历史漏洞的修复前后代码与公告摘要。
严格依据给定材料分析，不得引入材料中不存在的 source/sink/sanitizer。
按【实例分析】模板输出 Markdown，并在末尾附一行：
  VULN_CLASS_JSON: {"vuln_class": "...", "sink": "...", "added_guard": "<逐字摘自 diff + 行>"}
公告摘要：{advisory_text}
修复前：{before_code}
修复后：{after_code}
diff：{diff}
```

### ② 类层 prompt（每簇一次，temperature 0\.2，对齐 §5）

```Plain Text
你将看到同一漏洞类的多个历史实例（每个含 CVE / 实例分析 / before / after / diff）。
提炼其共性，输出一份类级 Pattern（见模板），要求：
- source/sink/sanitizer 抽象到不依赖任一具体函数名
- 历史实例列出全部成员
- 每个 source/sink/sanitizer 必须能在至少一个实例的代码中找到对应（见 grounding 规则）
实例集合：{instances}
```

---

## diff\-grounding 硬验收（机器可查，防幻觉）

对每份产出（实例层与类层都查）：

- `sanitizer` 至少一条能在某实例 `after_code` 的新增行（diff `+`）里**子串命中**

- `sink` 命名的函数/操作能在 `after_code` 里 `grep` 到

- `source` 能在 advisory\_text 或 before\_code 中找到依据

- 任一项命不中 → 标 `grounding: failed`，**该 pattern 不进 Rule Agent**

> 实现成本几行字符串匹配；作用是给 pattern 可信度兜底，禁止 advisory 没有、代码也没有的凭空 source/sink。
> 
> 

---

## 时间切分纪律

- **正式（计分）轮**：严格只用 train≤2021 归纳，val/test 盲测、不喂入。评测后回流。

- **契约冒烟（§10）**：不算计分轮，**不受 hold\-out 约束**——只验方法对不对，不验泛化好不好。正式跑 train 33 条时才严格执行切分。

---

## Cluster A 冒烟（先小后大）

先只跑一个种子簇验证 §2 的类模型，通过再放开到 train 33。

**Cluster A — ****`missing-bounds-check-before-size-arith`**（均 train、均人工核过 before/after）：

- CVE\-2015\-1283  expat  `xmlparse.c::XML_GetBuffer`（SA\-15:20，train）—— 加 `len<0`/`neededSize<0`/`bufferSize<=0`

- CVE\-2018\-17160 bhyve  `fwctl.c::*`（SA\-18:14，train）—— `int len` 收紧为 `uint32_t` \+ `size_t`

> 跨 expat / bhyve 两 module，测跨 module 泛化。zlib CVE\-2018\-25032（`deflatePrime`，val）是同类，**留作 val 泛化检验**——回头看本簇规则能否抓住它，不放进冒烟（避免 hold\-out 泄漏）。
> 
> 

**冒烟唯一验收标准**：产出的类 pattern 的 `sink` 是否抽象成**不含具体函数名**的形态（如"size 运算前缺符号/上界检查 → 分配/拷贝"），而非绑在 `XML_GetBuffer` 上。

- 抽象到了 → 类方法成立 → 放开到 train 33

- 仍绑函数名 → 方法没生效 → 回看 prompt

---

## 全 train 放开后的验收

每份类 pattern：

1. §5 字段完整，source/sink/sanitizer 非空

2. 通过 §8 grounding（未 failed）

3. 历史实例均来自 train、`path::func` 与样本一致

4. ≥2 实例的类，描述与 Structured Fields 不依赖任一具体函数名

5. 单实例类正确标 `confidence:low` 且未进 Rule Agent

产出 `data/instances/*.md` \+ `data/patterns/*.md` \+ 聚类映射，交架构师复核（重点看 Cluster A 是否真跨 module 泛化）。

---

## 不在本轮范围

- Rule Agent / CodeQL 生成（类 pattern 契约确认后才开）

- val/test 的任何使用

- 17 多 CVE / 6 medium / 70 upstream（B 轮）

- `context.callers/callees` 填充（需 CodeQL DB，二阶段）

---

## 决策状态（全部落定）



