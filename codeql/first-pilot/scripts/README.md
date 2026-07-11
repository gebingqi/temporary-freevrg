# 脚本使用说明

本项目最终验证环境以 Linux 为准。`run_smoke_validation.sh` 是当前推荐入口，用于在任意 Linux 路径下复跑 `first-ql-validation-package` 的最小 smoke 验证流程：

```text
compile query -> analyze minimal vulnerable/fixed databases -> summarize -> judge PASS/FAIL
```

它只验证包内已有的最小 harness database，不等同于完整 FreeBSD 历史源码验证。

脚本每次 analyze 都传入 CodeQL `--rerun`，确保修改 QL 后不会复用数据库中的旧 BQRS。

## 环境要求

- Linux shell。
- `python3`。
- CodeQL CLI。若 `codeql` 不在 `PATH`，用环境变量 `CODEQL=/path/to/codeql` 指定。
- 包内已存在的 `minimal-validation-databases/db/*`。当前 Linux 主脚本只复跑验证，不负责重新建库。

## 常用命令

进入验证包目录：

```bash
cd first-ql-validation-package
chmod +x scripts/run_smoke_validation.sh
```

验证全部内置规则：

```bash
./scripts/run_smoke_validation.sh --all
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
CODEQL=$HOME/tools/codeql/codeql ./scripts/run_smoke_validation.sh --all
```

如果 CodeQL 无法解析 `codeql/cpp-all`，可显式指定 additional packs：

```bash
ADDITIONAL_PACKS=/path/to/codeql-stdlib ./scripts/run_smoke_validation.sh --all
```

## 输出文件

- 结果汇总：`validation/smoke-summary.tsv`
- 失败详情：`validation/smoke-failures.txt`
- SARIF 结果：`minimal-validation-databases/results/*.sarif`
- analyze 日志：`minimal-validation-databases/logs/analyze-*.log`

## 判定口径

```text
vulnerable result_count > 0  => hit
vulnerable result_count = 0  => miss
fixed result_count = 0       => clean
fixed result_count > 0       => still_reports
```

只有所有 vulnerable 都 `hit` 且所有 fixed 都 `clean` 时，脚本返回 `SMOKE_RESULT=PASS`；否则返回 `SMOKE_RESULT=FAIL`，并在 `validation/smoke-failures.txt` 中写入失败位置和附近源码片段。

结果数判定只是第一道门槛。通过后还应审查 vulnerable SARIF 是否落在预期危险使用点，不能以 source 调用、取址参数、协议常量或无关 helper 参数替代召回。

## Windows 备用脚本

目录中保留 PowerShell 脚本，便于在 Windows 上临时复现。`run-smoke-analyze.ps1 -Force` 会覆盖 SARIF 并追加 CodeQL `--rerun`。若本机脚本执行策略阻止启动，可使用进程级 `powershell.exe -NoProfile -ExecutionPolicy Bypass -File <script>`，无需修改系统策略。最终项目环境仍按 Linux Bash 脚本执行。
