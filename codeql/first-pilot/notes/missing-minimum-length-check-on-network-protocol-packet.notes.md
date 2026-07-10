# missing-minimum-length-check-on-network-protocol-packet 建模说明

## 输入来源

- `RuleAgent试点包/missing-minimum-length-check-on-network-protocol-packet/rule_input.json`
- `RuleAgent试点包/子模板/网络协议最小长度检查子模板.md`

## 建模选择

- 第一版只做函数内检测，不引入跨函数 taint tracking。
- source 识别名称中包含 len/length/alen/offset/off/pos/ptr/pointed_len 的表达式，以及 `POS_LENGTH`、`POS_ATTRS`、`MD5_DIGEST_LENGTH` 等协议锚点。
- sink 优先报告循环条件、数组访问、指针/解析位置推进、协议属性读取调用。
- sanitizer 只把最小长度或非负检查视为有效 guard；单纯上界检查不视为修复。

## 已知限制

- 当前 query 不能证明长度一定来自网络包，只能用命名和协议锚点近似。
- 当前 query 尚未区分“统一解码器已保证最小长度”的负例。
- fixed 版本验证尤其重要：`len < POS_ATTRS || len > h->in_len` 必须阻止同一位置报告。

## 修复优先级

1. 如果 CVE-2020-7461 miss，优先补 `pointed_len` 相关循环/回溯 sink。
2. 如果 CVE-2021-29629 miss，优先补 `POS_ATTRS`、`POS_LENGTH` 和属性读取 sink。
3. 如果误报多，要求 sink 必须影响循环、指针推进、解析位置或缓冲区读取。
