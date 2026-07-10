# missing-array-bounds-check-on-network-controlled-index 建模说明

## 输入来源

- `RuleAgent试点包/missing-array-bounds-check-on-network-controlled-index/rule_input.json`
- `RuleAgent试点包/子模板/数组描述符上界检查子模板.md`

## 建模选择

- 第一版只做函数内检测，不引入跨函数 taint tracking。
- source 采用保守启发式：结构体字段、名称中包含 index/epid/htype/count/iov 等语义的表达式，以及 `vq_getchain` 赋值得到的描述符链长度。
- sink 优先报告数组访问、描述符相关调用、描述符相关循环和赋值位置。
- sanitizer 识别使用点前同一函数内的 `if` 范围检查和 `assert` 范围检查。

## 已知限制

- 当前 source 建模仍依赖表达式文本和命名，后续可能产生无关命中。
- 当前 sanitizer 只按同一函数内、按行号先后判断，尚未建控制流支配关系。
- `vq_getchain` 返回值到后续 iovec 使用的建模是轻量近似，需用 CVE-2021-29631 vulnerable/fixed database 验证。

## 修复优先级

1. 如果 vulnerable miss，先补 source 和 sink，而不是扩大到全局 taint。
2. 如果 fixed still reports，先补 `assert(n >= 1 && n <= MAX)` 和双条件 guard。
3. 如果误报多，收紧 source，要求其来自结构体字段、guest/MMIO 语义或 descriptor API。
