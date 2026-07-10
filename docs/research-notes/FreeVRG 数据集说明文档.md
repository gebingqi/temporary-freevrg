# FreeVRG 数据集说明文档

# FreeVRG 数据集说明文档

**文档版本**：v1\.4
**生成日期**：2026\-06\-21
**对应文件**：`FreeBSD_SA_Dataset_Index.xlsx` / `dataset_index.json` / `dataset_index.csv`
**变更历史**：v1\.0 初版 → v1\.1 合并上游组件来源 → v1\.2 完成 scope\_tier 全量审计与修正 → v1\.3 Opus commit 审计 → v1\.4 commit 分级标注与数据清理

---

## 一、数据集概览

本数据集是 FreeVRG 项目（FreeBSD Vulnerability Rule Generator）的第一阶段产出，即**结构化漏洞索引表**。它是后续 diff 抓取、模式抽象（PatternAgent）和规则生成（RuleAgent）的输入起点，本身不包含代码，只包含索引和元数据。

---

## 二、数据来源说明

### 来源 A：FreeBSD 官方安全公告（FreeBSD\-SA）

**记录数**：236 条（lib\+tool 102 条，kernel 133 条，other 1 条）
**字段标识**：`source` 列为空

FreeBSD 安全团队发布的正式安全公告，存放于 [`freebsd/freebsd-doc`](https://github.com/freebsd/freebsd-doc) 仓库的 `website/static/security/advisories/` 目录下，每条公告是一个 PGP 签名的 `.asc` 纯文本文件。

**采集方式**：通过 GitHub API 获取文件列表，用 `raw.githubusercontent.com` 逐一下载原始 `.asc` 文件，用正则解析以下字段：

- `Topic`、`Category`、`Module`、`Announced`、`Affects` 来自公告头部

- `CVE Name` 来自公告头部的 CVE 字段

- `git_hashes` 来自公告末尾 `Correction details` 章节 

    - 2021 年之后：公告直接提供 12 位 git commit hash

    - 2021 年之前（SVN 时代）：公告只有 SVN 修订号，通过 GitHub Commits API 按日期\+分支\+`MFC rXXXXX` 模式在 [`freebsd/freebsd-src`](https://github.com/freebsd/freebsd-src) 中查找对应 git commit，命中率约 91%

**覆盖范围**：2015—2026 年所有 FreeBSD\-SA，已过滤：

- `ports` 类别（第三方软件包）

- CPU 硬件漏洞缓解类（Spectre、MDS、L1TF 等）

- 外部独立软件包类（bind、ntp 等）

**已知限制**：17 条公告的 commit hash 标注为 Q2，原因有两类：

- 8 条 SVN 时代公告（2015—2016）的 commit hash 因批次 MFC 错误匹配已被清除，待精确补录

- 9 条公告（主要是 2015—2016 早期条目）在 git 历史中未能找到对应 commit

---

### 来源 B：上游组件项目 commit 历史

**记录数**：132 条（全部为 lib\+tool 层）
**字段标识**：`source` 列值为 `upstream_commit`

FreeBSD base system 中打包的核心第三方库，往往通过"版本升级 commit"批量修复多个上游 CVE，但 FreeBSD 安全团队并不为每个 CVE 单独发布 SA。本来源补录了这部分漏洞。

**采集方式**：

1. 遍历以下上游 GitHub 仓库的 commit 历史（2015 年至今）：

1. 提取每条上游 commit message 中出现的 CVE 编号，去除已被 FreeBSD\-SA 覆盖的 CVE（通过 CVE 编号去重）

2. 对每个新 CVE，在 `freebsd/freebsd-src` 对应路径按时间窗口匹配 FreeBSD 集成 commit，命中率约 63%；2025—2026 年新 CVE 多数尚未集成，保留为 Q2

**以 CVE 为粒度**：一次版本升级 commit 可能修复多个 CVE，每个 CVE 单独建一条记录，共享同一个 `git_hashes`——PatternAgent 需要针对每个独立漏洞进行模式分析。

---

## 三、数据质量分级

**Q2 主要构成**：

- 2025—2026 年 openssl/expat 新 CVE，FreeBSD 尚未集成对应版本（约 18 条）

- 2022—2023 年 openssl 批量 CVE，集成 commit 匹配启发式未命中（约 29 条）

- 早期 FreeBSD\-SA（2015—2016）错误 commit 已清除待补（8 条，见附录 A）

- 其他 SVN 时代查找失败（约 9 条）

**下一阶段计划**：优先对 Q3 记录抓取 diff 和 before/after 代码；Q2 记录可通过更精确的版本号匹配逐步升级。

---

## 四、Scope Tier 分层说明

本字段是自定义的分析层次分类，不来自 FreeBSD 官方，用于区分漏洞所在系统层次并指导 pipeline 处理顺序。分类依据是**修复 commit 实际修改的文件路径**，通过 GitHub API 对所有 Q3 记录逐一验证。

**关于 ****`tool`**** 层的范围**：用户态守护进程（daemon）与命令行工具在代码结构、编译方式和漏洞类型上没有本质区别，均编译为用户态二进制，适用相同的 CodeQL 分析模型，因此统一归入 `tool` 层。`lib` 与 `tool` 的区分依据是产物类型：产出 `.so`/`.a` 库文件的归 `lib`，产出可执行文件的归 `tool`。

**关键分类边界说明（易混淆项）**：

**双层修复记录（****`dual_scope`****）**：2 条记录的漏洞同时影响内核和用户态，已在 `note` 字段注明：

- SA\-20:17 usb：`sys/dev/usb/`（内核驱动）\+ `lib/libusbhid/`（用户态库）

- SA\-26:08 rpcsec\_gss：`sys/rpc/rpcsec_gss/`（内核）\+ `lib/librpcsec_gss/`（用户态）

**`is_priority = Yes`** 表示该记录属于 `lib` 或 `tool` 层，即第一阶段 pipeline 的主要处理目标（共 234 条）。`kernel` 层 133 条作为第二阶段。

---

## 五、字段说明

---

## 六、三个文件的使用说明

### 6\.1 `FreeBSD_SA_Dataset_Index.xlsx` — 人工审查与进度追踪

**用途**：给人看，不进 pipeline。

**四个 Sheet**：

**`SA Dataset Index`**（主表，368 行）
 完整数据，支持按任意字段筛选和排序。行背景颜色按 scope\_tier 和数据来源双重编码：

Quality 列独立颜色：绿色\(Q3\) / 黄色\(Q2\) / 红色\(Q1\)。Scope Tier 列字体颜色：绿色\(lib\) / 蓝色\(tool\) / 橙色\(kernel\)。Note 列有内容时以紫色斜体显示。

典型操作：

- 筛选 `Priority = Yes` \+ `Quality = 3` → 177 条可直接进入 diff 抓取

- 筛选 `scope_tier = kernel` → 第二阶段 133 条目标

- 筛选 `source = upstream_commit` → 从上游补录的 132 条

- `GitHub Commit` 列可直接点击验证 commit 内容是否与 SA 相符

**`Priority lib+tool`**（子集，234 行）
 仅包含 `is_priority = Yes` 的记录，第一阶段重点审查用。

**`Kernel Track`**（子集，133 行）
 仅包含 `scope_tier = kernel` 的记录，第二阶段工作参考用，包含 ptrace、ktrace、kldstat、libnv、libalias 等经审计确认在 sys/ 路径下的漏洞。

**`Stats & Legend`**
 总体统计数字 \+ 颜色图例说明，快速了解数据集现状。

---

### 6\.2 `dataset_index.json` — pipeline 直接读取

**用途**：给脚本用，是下一步 diff 抓取和样本构建的直接输入。

**格式**：JSON 数组，每个元素是一个完整记录对象，所有字段保持原生类型（列表就是列表，布尔就是布尔）。

**下一步脚本的典型读取逻辑**：

```Python
import json

records = json.loads(open("dataset_index.json").read())

# 第一阶段目标：lib+tool 且有正确 commit
targets = [
    r for r in records
    if r["is_priority"]
    and r["data_quality"] == 3
    and r["git_hashes"]
]
# → 177 条，可直接用 git_hashes[0] 去 GitHub API 拉 diff

# 第二阶段目标：kernel 层
kernel_targets = [
    r for r in records
    if r["scope_tier"] == "kernel"
    and r["data_quality"] == 3
]
# → 约 123 条
```

每条记录的 `git_hashes` 字段提供 commit hash，下一步的 diff 抓取脚本将：

1. 用 hash 调用 `GET /repos/freebsd/freebsd-src/commits/{hash}` 获取完整 SHA

2. 用 `GET /repos/freebsd/freebsd-src/compare/{parent}...{sha}` 获取 diff

3. 从 diff 中提取受影响文件 → 抓取修复前/后完整函数

4. 输出 `data/samples/FreeBSD-SA-24:09.json`（符合 FreeVRG schema）

**注意**：`source = upstream_commit` 的记录中，`advisory_raw_url` 指向上游 commit 页面，不是 FreeBSD 自己的公告，如需查漏洞背景应结合 CVE 编号查阅 NVD。

---

### 6\.3 `dataset_index.csv` — 辅助分析与版本备份

**用途**：通用格式，任何工具都能读取，主要用于两个场景。

**场景一：快速统计分析**

```Python
import pandas as pd

df = pd.read_csv("dataset_index.csv")

# 各 scope_tier 的 Q3 记录数
df[df["data_quality"] == 3].groupby("scope_tier").size()

# 第一阶段全部目标
stage1 = df[(df["is_priority"] == "Yes") & (df["data_quality"] == 3)]

# 找所有 bhyve 记录（现为 tool 层）
df[df["module"] == "bhyve"][["sa_id","scope_tier","cve","git_hashes"]]
```

**场景二：版本对比和人工补录**
 JSON 在被脚本修改后可能结构变化，CSV 作为快照可随时用来核对或重建 JSON。如果需要手动补填 Q2 记录的正确 git hash，在 CSV 中修改后可重新生成 JSON。

**注意**：列表字段（`cve`、`git_hashes`、`github_commit_urls` 等）在 CSV 中以**分号**分隔，读取时需要 `split("; ")` 还原为列表。`is_priority` 和 `diff_available` 存为字符串 `"Yes"` / `""`，不是布尔值。

---

## 七、时间切分建议（train/val/test）

按项目整体设计，数据集应按**时间**而非随机切分，以模拟"用历史漏洞经验预测未来同类问题"的真实场景。

当前 236 条 FreeBSD\-SA 记录的时间分布建议：

```Plain Text
2015—2021（139 条）→ 训练集（约 59%）
2022—2023（33 条） → 验证集（约 14%）
2024—2026（64 条） → 测试集（约 27%）
```

> 注：2024—2026 年记录较多，原因是 2026 年仍在持续产生新 SA。若测试集比例过高可将截止线调整为 2024，保留 2025—2026 作为实战扫描目标。
> 
> 

Upstream 来源的 136 条记录因其 `announced` 日期代表上游 commit 时间（早于 FreeBSD 集成时间），建议加入训练集使用，或在消融实验中单独评估其对规则质量的增量贡献。

**2025—2026 年的 Q2 记录**（FreeBSD 尚未集成对应上游 CVE）适合作为**实战扫描目标**：用生成的 CodeQL 规则在 FreeBSD\-CURRENT 代码上扫描，验证规则是否能发现尚未修复的同类问题。

---

## 八、后续步骤

```Plain Text
当前（已完成）
  dataset_index.json / .csv / .xlsx
    └─ 漏洞索引表，scope_tier 已通过 commit 文件路径全量审计

第一阶段（下一步）
  data/samples/*.json
    └─ 对 177 条 Q3 lib+tool 记录抓取 diff + before/after 代码
       输出符合 FreeVRG schema 的结构化样本
       重点模块：openssl(110)、expat(38)、openssh(22)、bhyve(11)、libarchive(10)

第二阶段（稳定后）
  data/patterns/*.md      ← PatternAgent 对样本进行漏洞模式抽象
  data/rules/*.ql         ← RuleAgent 生成 CodeQL 检测规则
  data/results/*.json     ← Validator 编译+回放验证结果

第三阶段（可选）
  kernel track (133 条)   ← 用相同 pipeline 处理内核层漏洞
                             需要构建内核 CodeQL 数据库（sys/ 路径）
```

---

## 附录 A：scope\_tier 审计修正记录（v1\.2）

本次审计对全部 228 条有 git commit 的 FreeBSD\-SA 记录通过 GitHub API 拉取 commit 文件路径，与 scope\_tier 对比核验，共修正 48 条记录（50 次字段变更）。

**A 类（11 条）：scope lib/tool → kernel**
 这些模块名称形似用户态组件，但修复代码实际在 `sys/` 下：

**B 类（18 条）：scope kernel → lib/tool**
 这些模块被误判为内核，实际修复在用户态：

**C 类（8 条）：清除错误 commit hash → Q2**
 SVN 时代批次 MFC commit 错误关联（同一 hash 绑定多条无关 SA）：

- `a2e7e7b1c2c0`（NTP 更新 commit）→ 错误关联 SA\-15:04、SA\-15:08

- `b993ace45610`（TCP 修复 commit）→ 错误关联 SA\-15:16

- `7f86e2d39547`（NTP 更新 commit）→ 错误关联 SA\-16:01、03、04、05、06

**D 类（2 条）：增加 dual\_scope 注记**
 SA\-20:17（usb）、SA\-26:08（rpcsec\_gss）：漏洞同时在内核和用户态有修复，`note` 字段已标注。

**Daemon → lib/tool（11 条）**
 用户态守护进程统一归入 `tool` 层（routed、rpcbind、bootpd、dhclient×3、rtsold×2、blocklistd、bsnmpd），`bsnmp` 因修复在 `contrib/bsnmp/lib/` 归入 `lib` 层。

---

## 附录 B：Opus 独立审计结果（v1\.3 补录，2026\-06\-21）

**审计范围**：46 条 2015—2020 年 SVN 时代启发式匹配记录（source 为空、year≤2020、git\_hashes 非空）
**审计方法**：逐一拉取 commit `.patch` 文件，核验 commit message 和修改文件路径与 SA 描述是否吻合
**审计工具**：Claude Opus，开启 web\_fetch，独立执行，未预设答案

**结果：1 条确认错误，45 条确认正确**

**修复记录：**

- **SA\-15:12** \[openssl\]
 错误 hash `56debbc0a935`：指向 "Document r285330, OpenSSL update to 1\.0\.1p\."——仅改 `release/doc/.../article.xml` 一个文件，是配套文档 commit，不含任何代码
 正确 hash `45c1772ea0e3`：指向 "Merge OpenSSL 1\.0\.1p\."——修改 300 个文件，全在 `crypto/openssl/` 下，是真正的代码安全更新
 质量保持 Q3（有 CVE \+ 有正确 commit）

**Opus 建议的防护规则（已录入数据采集 changelog）：**
 未来采集时，凡 commit message 以 "Document r" 开头，或修改文件全部落在 `release/doc/`、`*/man/`、`*/relnotes/` 等非代码路径下的，一律标记复核。

---

## 附录 C：commit 分级标注（v1\.4，2026\-06\-21）

### 背景

下一阶段 diff 抓取需要针对不同类型的 commit 采用不同的提取策略，因此对当时的 182 条 Q3 lib\+tool 记录进行了 commit 分级标注（数据清理后实际剩余 177 条）。分级由 Claude Opus 独立执行，通过 web\_fetch 对 261 个唯一 commit hash 逐一获取文件列表后评分。

### 分级字段：`commit_grade`

新增字段，值域如下：

空值表示该记录不在本次评级范围（kernel 层、Q2/Q1 记录）。

### 分级结果（177 条 Q3 lib\+tool，Corrected 版本，数据清理后）

> 注：Opus 原始评分包含 6 条 noise\_only，但评分后立即执行了修复（见下），因此写入数据集时 noise\_only = 0。
> 
> 

### 本轮数据修复（配合分级结果同步执行）

5. **SA\-21:07 openssl — commit hash 更正（再次发现配套文档 commit 误匹配）**

- 错误 hash：`c9b4e5e9ae39`（"Add UPDATING entry for OpenSSL advisory and bump version"，仅改 UPDATING\+newvers\.sh）

- 正确 hash：`b6c1fdcdf503`（"OpenSSL: Merge OpenSSL 1\.1\.1k"，14 个 `crypto/openssl/` 代码文件，日期 2021\-03\-25T15:45:19Z 与 SA 完全吻合）

- commit\_grade：focused（20 个有效文件，HIGH 集中度）

6. **UPSTREAM\-LIBARCHIVE\-CVE\-2016\-1541 — 降级 Q2**

- hash `430f7286a566`（"Merge ^/user/ngie/release\-pkg\-fix\-tests"）是 test 基础设施 merge，与漏洞无关

- 上游挖掘步骤时间窗口误匹配，已清除 hash

7. **删除 4 条 UPSTREAM\-OPENSSH 记录（CVE 归属根本性错误）**

- 删除：CVE\-2020\-29368、CVE\-2020\-29374、CVE\-2022\-2274、CVE\-2022\-42703

- 原因：这些 CVE 不是 OpenSSH 漏洞。CVE\-2022\-2274 是 OpenSSL 堆内存错误，CVE\-2022\-42703 是 Linux 内核漏洞，CVE\-2020\-29368/74 是 Linux 内核 copy\-on\-write 问题。

- 上游挖掘时，openssh\-portable 的 commit message 中顺带提及了这些 CVE 编号（如描述兼容性要求），导致被误归入 openssh 模块。

- 删除后数据集总量：368 条（原 372 条）

### 发现的映射表修正（供 diff 抓取脚本参考）

Opus 在分级过程中发现以下 module→路径映射与实际不符，已记录供下一阶段使用：

Vendor import commit 的文件按上游源码树布局，不在 FreeBSD 集成路径下，集中度应按单组件判断而非路径匹配。

### 附加噪声规则（扩充 Appendix B 规则集）

在 Appendix B 规则的基础上，补充以下噪声文件类型：

- `newvers.sh`（版本号 bump）

- `FREEBSD-upgrade`（OpenSSH 打包说明文件）

- `FREEBSD-Xlist`（同上）

- `tests/*/Makefile`（仅影响测试构建的 Makefile，不含代码）



