# FreeBSD 漏洞规则自动生成项目技术设计说明

## 1. 文档目的

本文档用于在项目 README 之外，补充系统的技术设计细节，说明项目的核心目标、系统模块、数据流、关键约束、验证机制和阶段性落地方式。本文档基于初版《整体设计.md》整理，并结合后续讨论对架构进行了收敛，重点描述当前阶段的原型实现方案。

## 2. 项目定位

本项目面向 FreeBSD 历史安全公告与修复记录，构建一套基于大模型与 CodeQL 的漏洞规则自动生成系统。系统通过分析历史漏洞补丁和源码上下文，自动抽象漏洞模式，并将模式翻译为可执行的静态分析规则，用于在 FreeBSD 当前代码版本中发现与历史漏洞同类的漏洞或漏洞变体。

该项目的关键点在于：

- 大模型主要承担“模式归纳”和“规则生成”工作
- 扫描阶段不依赖在线 LLM 推理，而是依赖生成出的 CodeQL 规则
- 规则必须经过确定性的编译、回放和误报验证后才能进入规则库
- 新发现的真实问题会回流到样本库，支撑下一轮规则优化

因此，本项目本质上是一个“规则生成与验证系统”，而不是一个“直接由 LLM 充当检测器”的系统。

## 3. 当前原型架构

当前阶段不采用过度工程化的模块拆分，而是优先围绕最小闭环组织实现。推荐采用“数据层 + Agent 层 + 控制层”的三段式原型架构。

### 3.1 数据层

职责：

- 保存结构化历史漏洞样本
- 保存 pattern 文档
- 保存 CodeQL 规则
- 保存验证结果和扫描结果

设计原则：

- 优先使用目录和文件组织数据，而不是先引入数据库
- 所有中间产物都应落盘，便于回放、比较和审计
- 数据格式尽量简单稳定，样本优先使用 JSON，pattern 优先使用 Markdown，规则使用 `.ql`

建议目录：

```text
data/
  samples/
  patterns/
  rules/
  results/
```

### 3.2 Agent 层

原型阶段只保留两个 Agent。

#### Pattern Agent

职责：

- 输入历史漏洞样本
- 归纳漏洞触发条件、source、sink、sanitizer 和修复方式
- 输出可复用的 pattern 文档

说明：

- 这是模式抽象模块
- 它的输入质量强依赖样本上下文是否完整

#### Rule Agent

职责：

- 输入 pattern 文档
- 生成对应的 CodeQL 查询规则
- 在收到失败反馈时参与有限轮数的规则修正

说明：

- 这是规则生成模块
- 它的质量依赖 pattern 是否清晰，以及 few-shot 规则示例是否足够好

### 3.3 控制层

控制层只保留一个确定性模块：`Orchestrator / Validator`。

职责：

- 串联样本读取、pattern 生成、规则生成和验证流程
- 负责编译 CodeQL 规则
- 在历史漏洞版本上做召回验证
- 在历史修复版本上做误报验证
- 汇总失败原因，决定是否重试、修正或转人工检查

说明：

- 这是原型阶段最关键的模块
- Agent 可以不稳定，但控制层必须可复现、可追踪、可回放

### 3.4 最小原型目录结构

```text
project/
  data/
    samples/
    patterns/
    rules/
    results/
  agents/
    pattern_agent.py
    rule_agent.py
  core/
    orchestrator.py
    validator.py
  prompts/
  .env
  .env.example
```

其中：

- `agents/` 放两个 Agent 的调用逻辑
- `core/` 放主流程和验证逻辑
- `prompts/` 放提示模板，避免把长提示词直接写进代码
- `.env` 放模型参数和运行配置

### 3.5 配置管理

模型参数和运行参数统一放在 `.env` 中，而不是硬编码在脚本内部。这样做有三个目的：

- 便于切换模型和 API 提供方
- 便于重复实验和记录配置差异
- 避免代码里散落多个不一致的默认值

建议至少包含以下配置：

```dotenv
LLM_API_KEY=
LLM_BASE_URL=

PATTERN_MODEL=gpt-4.1
RULE_MODEL=gpt-4.1

PATTERN_TEMPERATURE=0.2
RULE_TEMPERATURE=0.1

MAX_REPAIR_ROUNDS=2
CODEQL_PATH=codeql

SAMPLES_DIR=data/samples
PATTERNS_DIR=data/patterns
RULES_DIR=data/rules
RESULTS_DIR=data/results
```

建议在代码中提供统一的配置加载模块，由 `Pattern Agent`、`Rule Agent` 和 `Orchestrator` 共享，而不是各自读取环境变量。

## 4. 工作流程

项目的完整工作流程如下。原型阶段仍保留完整目标，但实现优先级应先围绕最小闭环推进。

### 4.1 样本构建阶段

数据来源包括但不限于：

- FreeBSD 官方安全公告
- FreeBSD 源码仓库和 git 历史
- 历史修复 commit
- 可补充的 syzbot FreeBSD 样本
- 后续可接入的文档知识库和 API 语义说明

每条结构化样本建议至少包含如下字段：

```json
{
  "id": "FreeBSD-SA-2024-09",
  "cve": ["CVE-2024-43102"],
  "subsystem": "kern",
  "cwe": ["CWE-416"],
  "affected_versions": ["13.x", "14.x"],
  "fix_commits": ["abc123"],
  "advisory_text": "...",
  "files_changed": ["sys/kern/kern_umtx.c"],
  "diff": "...",
  "before_code": {
    "sys/kern/kern_umtx.c::umtx_shm_destroy_lookup": "..."
  },
  "after_code": {
    "sys/kern/kern_umtx.c::umtx_shm_destroy_lookup": "..."
  },
  "context": {
    "callers": [],
    "callees": []
  }
}
```

数据集切分建议按时间划分，而不是随机划分：

- 训练集：较早年份的历史漏洞
- 验证集：中间年份样本
- 测试集：最新年份样本

原因是该项目的目标是“利用过去的漏洞经验发现未来同类问题”，随机切分会导致样本泄漏，削弱评估可信度。

这里需要特别说明：按时间切分并不意味着验证集和测试集中的漏洞永远不能被用于规则抽取，而是意味着它们在当前这一轮评测中不能提前参与模式归纳和规则生成。这样做的目的，是检验系统能否仅依赖较早年份的历史漏洞，生成对后续年份样本仍然有效的规则。

换句话说：

- 在评测阶段，较新的漏洞样本应被保留，用于验证和测试系统的泛化能力
- 在评测结束后，这些较新的漏洞样本应当回流到样本库中，成为下一轮模式抽象和规则优化的输入

因此，时间切分带来的并不是“放弃新类型漏洞”，而是“先把它们当作盲测样本，再在评测完成后纳入系统迭代”。这也是本项目既要保证评估可信度，又要实现持续演进能力的关键做法。

### 4.2 模式抽象阶段

`Pattern Agent` 读取单个或多个相近样本，提炼其共性，输出统一 pattern 文档。建议 pattern 文档至少包含：

- 模式名称
- 自然语言描述
- source 描述
- sink 描述
- sanitizer 描述
- 严重程度提示
- 历史实例列表

示例：

```markdown
# Pattern: copyin-length-from-user-struct

## 描述
内核代码从用户态结构体中读取长度字段，并直接将其用于 copyin/copyinstr 等危险调用，而缺少有效上界检查时，可能导致越界写入或越界读取。

## Structured Fields
source:
  - user-controlled struct field

sink:
  - copyin
  - copyinstr
  - copyiniov

sanitizer:
  - if (len > MAX) return EINVAL;
  - len = MIN(len, MAX);

severity_hint: high
```

这一阶段需要特别注意两点：

- 模式粒度应以“漏洞类”而不是“漏洞实例”为单位
- 不建议仅凭单个孤立样本就产出正式规则，优先选择至少有多个历史实例支撑的模式

### 4.3 规则生成阶段

`Rule Agent` 根据 pattern 生成 CodeQL 规则。规则通常需要包含：

- `import` 依赖
- `DataFlow::Configuration` 或 `TaintTracking::Configuration`
- `isSource`
- `isSink`
- `isSanitizer`
- 查询主体与元数据标签

示意结构如下：

```ql
import cpp
import semmle.code.cpp.dataflow.TaintTracking

class ExampleConfig extends TaintTracking::Configuration {
  ExampleConfig() { this = "ExampleConfig" }

  override predicate isSource(DataFlow::Node source) {
    ...
  }

  override predicate isSink(DataFlow::Node sink) {
    ...
  }

  override predicate isSanitizer(DataFlow::Node node) {
    ...
  }
}
```

该阶段建议为 LLM 提供以下上下文：

- 历史成功规则 few-shot 示例
- CodeQL 标准库相关 API 用法
- FreeBSD 常见危险函数和安全检查模式
- 样本中的关键调用关系和上下文语义

### 4.4 规则验证阶段

规则生成后必须进入自动验证闭环。验证的目标不是单纯“能编译”，而是确认规则对历史漏洞具有有效召回、对修复版本误报可控。

验证流程建议如下：

1. 编译检查  
   使用 `codeql query compile` 验证语法和依赖。

2. 召回测试  
   在验证集对应的漏洞版本上运行规则，确认是否命中受影响位置。

3. 误报测试  
   在验证集对应的修复版本上运行规则，确认修复后是否仍报同类问题。

4. 失败归因  
   如果规则失败，需要区分：
   - 语法失败
   - source/sink 建模失败
   - sanitizer 建模过宽或过窄
   - 数据流路径不完整
   - 模式本身抽象错误

5. 自动修正  
   将失败日志、失败样例和当前规则反馈给修正规则流程，执行有限轮数的自动修正。

建议的伪代码如下：

```python
def validate_rule(rule_path, val_set):
    compile_result = run_compile(rule_path)
    if compile_result.failed:
        return {"stage": "compile", "error": compile_result.stderr}

    recall_failures = []
    fp_failures = []

    for record in val_set:
        if record.is_vulnerable:
            result = run_query(rule_path, record)
            if not result.hit_expected_location():
                recall_failures.append(record.id)
        else:
            result = run_query(rule_path, record)
            if result.has_unexpected_alert():
                fp_failures.append(record.id)

    return {
        "compile": True,
        "recall_failures": recall_failures,
        "fp_failures": fp_failures
    }
```

### 4.5 扫描与回流阶段

通过验证的规则将用于：

- 测试集质量评估
- FreeBSD 当前代码版本扫描

扫描结果需要人工研判，以区分：

- 真阳性
- 明显误报
- 需要进一步确认的候选问题

对于确认有效的新问题，应回流到样本库中。回流的作用包括：

- 扩充历史样本规模
- 修正原有漏洞模式的边界
- 优化下一轮规则生成质量

这使得系统形成一个持续迭代的闭环，而不是一次性运行的工具。

### 4.6 原型阶段的最小闭环

为了避免一开始就把范围铺得过大，建议先只打通下面这条主流程：

1. 从 `data/samples/` 读取一个或一组历史漏洞样本
2. 调用 `Pattern Agent` 生成 pattern 文档
3. 调用 `Rule Agent` 生成 `rule.ql`
4. 用 `Validator` 做编译检查
5. 在历史漏洞版本上做基本召回验证
6. 记录结果到 `data/results/`

也就是说，原型阶段先不把“测试集评估”“大规模当前代码扫描”“复杂自动修正策略”作为第一优先级，而是先证明最小闭环是通的。

## 5. 关键设计决策

### 5.1 为什么不先训练模型

该项目的核心瓶颈不在于缺少自训练模型，而在于：

- 历史漏洞样本质量是否足够高
- 模式抽象是否足够稳定
- 规则验证闭环是否完备

因此现阶段应优先利用现成强模型，先把规则生成流程跑通，再考虑是否有必要做更深的领域微调。

### 5.2 为什么推荐 2 个 Agent

项目的最小可行架构推荐使用两个 LLM Agent：

- `Pattern Agent`
- `Rule Agent`

原因是：

- 模式抽象与规则生成的任务性质不同，适合拆开
- 若再拆出单独的 `Repair Agent`，系统职责会更清晰，但复杂度也更高
- 对于 MVP 阶段，使用两个 Agent 更容易实现和调试

如果后续系统变复杂，可扩展为：

- Pattern Agent
- Rule Generation Agent
- Rule Repair Agent

### 5.3 为什么必须有确定性控制器

如果没有确定性控制器，大模型生成的规则将缺乏稳定的质量约束，系统容易退化为：

- 规则能写但不能编译
- 能编译但不能召回历史漏洞
- 能召回但误报无法控制

因此 `Validator / Orchestrator` 是系统的核心，不应被视为可选项。

### 5.4 为什么当前不追求更工程化的架构

现阶段如果过早引入复杂分层、数据库、任务队列和过多子模块，收益有限，成本很高。当前更合理的取舍是：

- 先把研究原型跑通
- 先验证样本质量、pattern 质量和规则验证闭环
- 等最小闭环稳定后，再决定是否需要进一步模块化

因此当前架构设计的目标不是“完整平台”，而是“可迭代的研究原型”。

## 6. 推荐的阶段性落地方式

### 阶段一：构建基础样本库

目标：

- 完成历史漏洞样本抓取与结构化
- 明确样本字段和时间切分策略

交付物：

- 结构化 corpus
- 样本抽取脚本

### 阶段二：打通最小规则生成闭环

目标：

- 实现 Pattern Agent 与 Rule Agent
- 选择少量典型漏洞类型
- 打通规则生成、编译和回放验证

交付物：

- 初版 pattern 库
- 第一批可运行规则
- 基础验证脚本

### 阶段三：完善评估与扫描能力

目标：

- 引入误报检测
- 完善结果统计
- 在 FreeBSD 当前代码上运行扫描

交付物：

- 评估报告
- 扫描结果分析
- 初版规则库

## 7. 风险与难点

项目的主要风险包括：

- 样本数量有限，很多漏洞模式实例不足
- 模式抽象可能不稳定，导致规则源头偏差
- CodeQL 规则容易出现语法或语义错误
- 规则在历史样本上有效，但对当前代码泛化能力不足
- 真实扫描结果中误报较多，人工筛选成本高

对应的缓解思路包括：

- 优先从高质量、重复性强的模式入手
- 强化样本上下文提取，避免仅依赖公告文本
- 提供高质量 few-shot 规则示例
- 把验证闭环做成刚性流程
- 控制自动修正轮数，失败后及时转人工审查

## 8. 结论

本项目的核心价值在于：将 FreeBSD 历史漏洞知识转化为可执行、可验证、可迭代的 CodeQL 规则生成流程。系统不依赖训练新模型作为前提，而是通过高质量样本构建、模式抽象、规则生成和确定性验证闭环，逐步沉淀面向 FreeBSD 的漏洞检测能力。

从工程实现角度，最合理的起步方案是“2 个 LLM Agent + 1 个确定性控制器”，先完成最小闭环，再逐步扩展规则种类和评估能力。
