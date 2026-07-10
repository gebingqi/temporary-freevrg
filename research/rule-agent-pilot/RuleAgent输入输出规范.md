# RuleAgent 输入输出规范

## 目标

RuleAgent 的任务是读取一个经过 grounding 的 class pattern 输入，生成一个可编译、可验证、可回放的 CodeQL C/C++ 查询原型。

RuleAgent 不负责重新判断样本是否可信，不负责扩展样本范围，不负责处理未复核的多 CVE 综合 diff。输入可信度由 PatternAgent grounding 与人工审阅保证。

## 输入文件

每个试点使用一个 `rule_input.json`。字段分为 7 类：

| 字段 | 用途 |
|------|------|
| `schema_version` | 输入 schema 版本 |
| `pattern_id` | 漏洞类名称，也是候选规则命名基础 |
| `pilot_status` | 准入状态，第一批必须为 `single_commit/exact_patch/PASS_STRICT` |
| `rule_scope` | 语言、模块范围、规则类型 |
| `pattern` | 类层 source/sink/sanitizer、检测意图、反例 |
| `member_instances` | 支撑该 pattern 的历史实例证据 |
| `validation_plan` | 后续编译、召回、误报验证目标 |

## RuleAgent 必须遵守的约束

1. 只使用 `rule_input.json` 中列出的 source、sink、sanitizer 和实例锚点。
2. 不把规则写死到单一 CVE、单一函数或单一文件路径。
3. 可以使用实例中的函数/API 作为 few-shot anchor，但查询逻辑必须表达漏洞机制。
4. 第一批规则优先做函数内检测，即 `intra-procedural`。
5. 若无法稳定表达跨模块抽象，应输出可解释失败原因，而不是生成看似完整但不可验证的查询。
6. 不把 `PASS_WEAK`、`rule_candidate: defer` 或多 CVE composite 证据纳入第一批规则。

## 输出文件建议

RuleAgent 生成后建议输出：

```text
{pattern_id}.ql
{pattern_id}.metadata.json
{pattern_id}.notes.md
```

其中：

- `.ql` 是候选 CodeQL 查询。
- `.metadata.json` 记录输入 hash、生成模型、生成时间、依赖模板、预期验证目标。
- `.notes.md` 记录 source/sink/sanitizer 建模说明、已知限制和失败修复建议。

## QL 查询元数据要求

候选 `.ql` 顶部至少应包含：

```ql
/**
 * @name Missing bounds or protocol length check before dangerous use
 * @description ...
 * @kind problem
 * @problem.severity warning
 * @precision medium
 * @id freevrg/{pattern_id}
 * @tags security external/cwe/cwe-...
 */
```

具体 `@name`、`@description`、CWE tag 应根据当前 pattern 填写；不知道 CWE 时不臆造。

## Predicate 命名约定

建议统一使用以下 predicate 名称：

```ql
predicate isExternalInteger(Expr e) { ... }
predicate isDangerousUse(Expr e) { ... }
predicate hasRelevantGuard(Expr e, Stmt useSite) { ... }
```

若使用数据流或 taint tracking，可扩展：

```ql
class Config extends TaintTracking::Configuration { ... }
```

第一批优先函数内语法/语义模式，只有必要时再引入完整 taint tracking。

## 查询输出要求

查询应报告缺少 guard 的危险使用点，而不是报告 source。

输出格式建议：

```ql
select useSite, "Externally controlled integer reaches array/protocol-length sensitive use without a matching bounds check."
```

报告位置应尽量落在数组访问、描述符数组访问、循环/指针推进或属性读取位置。

## Sanitizer 建模要求

sanitizer 必须是使用点前同一函数内的有效检查，优先识别：

- 上界检查：`idx >= MAX`、`idx >= capacity`、`n > MAX`
- 零值/无效值拒绝：`idx == 0`
- 双侧检查：`len < MIN || len > buffer_len`
- 非负检查：`len < 0`
- 断言：`assert(n >= 1 && n <= MAX)`

不应把日志、注释、普通赋值、无关宏或远离使用点的弱条件当作 sanitizer。

## 失败反馈格式

若生成失败或验证失败，记录为：

```json
{
  "stage": "compile|recall|false_positive|modeling",
  "failure_type": "syntax|missing_import|source_model|sink_model|sanitizer_too_broad|sanitizer_too_narrow|pattern_error",
  "evidence": "...",
  "suggested_fix": "..."
}
```

## 第一批验收门槛

候选规则进入下一阶段前至少满足：

1. `codeql query compile` 通过。
2. 能在至少一个历史 vulnerable 目标上命中预期位置或等价危险使用点。
3. 在对应 fixed 目标上不再命中同一漏洞位置。
4. 失败和误报均有可解释归因。
