# 聚类结果修订版说明

## 这是什么

`聚类结果-修订版` 是对 33 个 train≤2021 单 CVE 样本做完实例分析、漏洞类聚类和 grounding 校验后的数据包。

它不是最终 CodeQL 规则结果，而是后续 Rule Agent 生成规则的输入数据。

## 目录结构

```text
聚类结果-修订版
├── data
│   ├── instances
│   └── patterns
├── logs
└── scripts
```

## data/instances

`data/instances` 里有 33 个 CVE 文件，每个文件对应一个漏洞实例，例如：

```text
CVE-2020-7461.md
CVE-2021-29629.md
```

这些文件记录单个 CVE 的分析结果，包括：

- `vuln_class`：该 CVE 被分到哪个漏洞类
- `source`：漏洞输入来源
- `sink`：危险使用点
- `added_guard`：修复中新增的关键检查
- `evidence`：证据字段，包括新增代码行、sink 行和证据来源
- `generalizable`：该实例是否适合抽象成更通用的规则

简单理解：`instances` 是“单个 CVE 为什么属于某类漏洞”的证据。

## data/patterns

`data/patterns` 是类层聚类结果，也就是把多个相似 CVE 归纳成漏洞模式。

当前正式 pattern 文件包括：

```text
missing-array-bounds-check-on-network-controlled-index.md
missing-minimum-length-check-on-network-protocol-packet.md
missing-absolute-path-check-in-archive-extraction.md
missing-null-check-in-openssl-certificate-parsing.md
missing-signedness-normalization-on-guest-controlled-length.md
```

这些文件不是单个漏洞，而是一类漏洞的抽象描述，包括：

- 这个漏洞类的 source、sink、sanitizer 特征
- 历史成员 CVE
- 适用范围
- 是否适合作为 Rule Agent 候选
- 负例和 member anchors

## CVE 是否已经分类

是的，33 个 CVE 都已经分类。

分类关系记录在：

```text
data/patterns/_cluster_map.json
```

它的结构是：

```text
漏洞类名 -> 这个类下面有哪些 CVE
```

例如：

```json
"missing-array-bounds-check-on-network-controlled-index": [
  "CVE-2018-17161",
  "CVE-2019-5604",
  "CVE-2021-29631"
]
```

表示这 3 个 CVE 已经被归到同一个漏洞类。

## 为什么有些 CVE 没有对应 pattern 文件

不是所有分类都会生成正式 pattern 文件。

当前分为两类：

### 多实例正式 pattern

这类至少有 2 个 CVE 支撑，并且生成了 `data/patterns/*.md` 文件。

例如：

```text
missing-array-bounds-check-on-network-controlled-index
├── CVE-2018-17161
├── CVE-2019-5604
└── CVE-2021-29631
```

这类可以作为后续规则生成的候选。

### singleton draft

这类只有 1 个 CVE，已经分类，但不生成正式 pattern 文件。

例如：

```text
missing-null-check-after-malloc
└── CVE-2015-7236
```

这类只保留在 `instances` 和 `_cluster_map.json` 中，暂时不进入第一批 Rule Agent。

原因是单个 CVE 只能说明一个具体漏洞，还不足以支撑稳定的通用规则。

## _rule_candidates.json

`data/patterns/_rule_candidates.json` 是第一批 Rule Agent 候选清单。

当前只建议先跑两个 pattern：

```text
missing-array-bounds-check-on-network-controlled-index
missing-minimum-length-check-on-network-protocol-packet
```

原因是这两个 pattern：

- 有多个历史 CVE 支撑
- grounding 结果为 `PASS_STRICT`
- 适合先做小范围 CodeQL 规则生成和召回验证

其他 pattern 虽然保留在数据中，但暂时不建议第一批进入 Rule Agent。

## logs/grounding_train.txt

`logs/grounding_train.txt` 是修订版 grounding 校验日志。

它检查：

- 33 个实例的证据是否能对应到真实样本代码
- 5 个类层 pattern 是否能覆盖成员 CVE
- Rule Agent 试点 pattern 是否达到严格校验要求

当前结果：

```text
33 个实例无 FAIL
两个 Rule Agent 试点 pattern 为 PASS_STRICT
```

其中：

- `PASS_STRICT`：证据较扎实，可以作为规则生成输入
- `PASS_WEAK`：不是错误，但证据或泛化性偏弱，暂缓进入 Rule Agent
- `FAIL`：证据不成立，需要修正

## scripts/grounding_check.py

`scripts/grounding_check.py` 是生成 grounding 日志的检查脚本。

如果后续修改了实例文件或 pattern 文件，可以重新运行该脚本检查修订版数据是否仍然满足 grounding 要求。

## 后续使用建议

后续小范围跑通时，不建议直接把所有 pattern 都送进 Rule Agent。

建议顺序是：

1. 先读取 `data/patterns/_rule_candidates.json`
2. 只选择其中两个 PASS_STRICT pattern
3. 基于这两个 pattern 生成 CodeQL 规则
4. 做 CodeQL 编译
5. 做历史漏洞召回
6. 再做 fixed-version 误报验证

一句话总结：

这套数据里 33 个 CVE 都已经分类；但第一批真正适合进入 Rule Agent 的，只有 `_rule_candidates.json` 里的两个 PASS_STRICT pattern。
