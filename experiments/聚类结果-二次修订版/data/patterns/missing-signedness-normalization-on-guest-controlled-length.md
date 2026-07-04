# Pattern: missing-signedness-normalization-on-guest-controlled-length

## 描述
bhyve 设备模型使用有符号整数承载 VM 访客可控的长度字段，负值在后续转换、比较或指针算术中被解释为极大无符号长度，造成越界访问。两个实例均来自 bhyve 设备模型，当前只支撑模块特定规则，不作为跨模块高置信泛化类。

## Structured Fields
source:
  - VM 访客通过设备模型接口、协议长度字段或发送描述符控制的长度值
sink:
  - guest-controlled length 进入缓冲区写入、指针算术或设备模型数据处理函数
sanitizer:
  - 将长度参数类型从 signed int 收紧为 uint32_t/unsigned
  - 在使用前增加协议长度上限或最小结构长度检查
severity_hint: high
confidence: medium
generalizable: local
rule_candidate: defer

## 历史实例
- CVE-2018-17160 @ usr.sbin/bhyve/fwctl.c::errop_start
- CVE-2019-5609 @ usr.sbin/bhyve/pci_e82545.c::e82545_transmit

## 检测建议（供 Rule Agent）
vulnerable_indicator: bhyve 访客可控长度以 signed int 保存，随后进入数据处理、指针运算或缓冲区访问，缺少类型收紧或边界检查。
fixed_indicator: 长度字段改为 unsigned/uint32_t，或使用前存在协议头长度、最大 header 长度等边界检查。
target_apis: [op_data, memcpy]

rule_scope:
  language: c/cpp
  module_scope: module-specific
rule_type: intra-procedural
source_predicate:
  description: 识别 bhyve 设备模型中来自 guest 请求、fwctl 请求或发送描述符的长度字段。
sink_predicate:
  description: 识别以该长度进行的缓冲区写入、指针移动或设备模型数据处理调用。
sanitizer_predicate:
  description: 识别 signed 到 unsigned 的类型收紧，以及使用点前的协议结构长度和最大长度检查。
negative_examples:
  - 长度值只用于日志或错误消息，不参与内存访问。
  - signed 值在使用前已经被显式拒绝负数并验证上界。
member_anchors:
  CVE-2018-17160:
    sink:
      - op_data
      - req_size
    sanitizer:
      - if (rinfo.req_size <= sizeof(uint32_t))
  CVE-2019-5609:
    sink:
      - memcpy
      - hdrlen
    sanitizer:
      - if (hdrlen > 240) {
