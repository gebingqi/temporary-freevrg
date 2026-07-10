# Smoke Validation Script

## 用途

`run_smoke_validation.sh` 用于在 Linux 上复跑单条候选 QL 的最小验证流程：

```text
compile query -> analyze minimal vulnerable/fixed databases -> summarize -> judge PASS/FAIL
```

它只验证当前包内已有的最小 harness database，不等同于完整 FreeBSD 历史源码验证。

## 依赖

- Linux shell
- `codeql`
- `python3`
- 当前包内已存在的 `minimal-validation-databases/db/*`

如果 `codeql` 不在 `PATH`，用 `CODEQL=/path/to/codeql` 指定。

## 使用

进入验证包目录：

```bash
cd first-ql-validation-package
chmod +x scripts/run_smoke_validation.sh
```

验证数组/描述符上界规则：

```bash
./scripts/run_smoke_validation.sh queries/missing-array-bounds-check-on-network-controlled-index.ql
```

验证协议长度最小值规则：

```bash
./scripts/run_smoke_validation.sh queries/missing-minimum-length-check-on-network-protocol-packet.ql
```

指定 CodeQL 路径：

```bash
CODEQL=$HOME/tools/codeql/codeql \
./scripts/run_smoke_validation.sh queries/missing-array-bounds-check-on-network-controlled-index.ql
```

如需指定额外 pack 路径：

```bash
ADDITIONAL_PACKS=/path/to/codeql-stdlib \
./scripts/run_smoke_validation.sh queries/missing-array-bounds-check-on-network-controlled-index.ql
```

## 判定口径

脚本使用 smoke 级判定：

```text
vulnerable result_count > 0  => hit
vulnerable result_count = 0  => miss
fixed result_count = 0       => clean
fixed result_count > 0       => still_reports
```

只有所有 vulnerable 都 `hit` 且所有 fixed 都 `clean` 时，输出：

```text
SMOKE_RESULT=PASS
```

否则输出：

```text
SMOKE_RESULT=FAIL
```

失败时会打印失败项、SARIF 位置、报告消息和附近源码片段。

## 输出

结果汇总：

```text
validation/smoke-summary.tsv
```

SARIF：

```text
minimal-validation-databases/results/*.sarif
```

analyze 日志：

```text
minimal-validation-databases/logs/analyze-*.log
```

## 支持的 QL

当前脚本只内置这两条规则的验证矩阵：

- `missing-array-bounds-check-on-network-controlled-index.ql`
- `missing-minimum-length-check-on-network-protocol-packet.ql`

新增规则时，需要在 `run_smoke_validation.sh` 的 `case "$QUERY_BASENAME"` 分支中补充对应 CVE 和 vulnerable/fixed database。
