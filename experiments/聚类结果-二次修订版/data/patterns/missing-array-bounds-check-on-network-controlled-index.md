# Pattern: missing-array-bounds-check-on-network-controlled-index

## 描述
网络对端或 VM 访客传入的整数字段被用作宿主侧数组索引、数组访问数量或 iovec 描述符数量。漏洞点在于使用前缺少与数组容量或协议上限的比较，导致越界读取或写入。该类可跨 bootpd 与 bhyve 设备模型抽象，核心路径是“外部整数 -> 数组/描述符访问 -> 缺少上界检查”。

## Structured Fields
source:
  - 网络请求或 VM 访客写入的整数字段（BOOTP 请求字段、PCI MMIO 寄存器、VirtIO 描述符环）
sink:
  - 外部整数作为数组索引访问宿主侧数组
  - 外部整数作为 iovec/描述符数组访问数量
sanitizer:
  - 数组访问前检查 index >= capacity 或 index == 0 等无效范围
  - 描述符访问前断言 n >= 1 && n <= MAX_IOV
severity_hint: high
confidence: high
generalizable: yes
rule_candidate: pilot

## 历史实例
- CVE-2018-17161 @ libexec/bootpd/bootpd.c::handle_request
- CVE-2019-5604 @ usr.sbin/bhyve/pci_xhci.c::pci_xhci_device_doorbell
- CVE-2021-29631 @ usr.sbin/bhyve/pci_virtio_9p.c::pci_vt9p_notify

## 检测建议（供 Rule Agent）
vulnerable_indicator: 外部整数字段流入数组索引或描述符数组访问，使用点前缺少与数组容量、MAX 常量或有效区间的比较。
fixed_indicator: 使用点前存在 idx >= MAX、idx == 0、n > MAX 或 assert(n >= 1 && n <= MAX) 等范围守护。
target_apis: [XHCI_MAX_ENDPOINTS, VT9P_MAX_IOV, VTSCSI_MAXSEG, vq_getchain]

rule_scope:
  language: c/cpp
  module_scope: cross-module
rule_type: intra-procedural
source_predicate:
  description: 识别来自网络包字段、MMIO/寄存器字段或 VirtQueue 描述符链长度的整型值。
sink_predicate:
  description: 识别数组下标访问、以外部整数控制的 iovec/描述符数组访问或批量填充。
sanitizer_predicate:
  description: 识别使用点前同一函数内的上界比较、无效零值拒绝或 MAX_IOV 断言。
negative_examples:
  - 索引值来自固定枚举或内部循环计数，且循环边界由数组长度控制。
  - 数组访问前已有等价的 min/max 范围检查。
member_anchors:
  CVE-2018-17161:
    sink:
      - hwinfocnt
      - bp_htype
    sanitizer:
      - if (bp->bp_htype >= hwinfocnt) {
  CVE-2019-5604:
    sink:
      - dev->eps
      - XHCI_MAX_ENDPOINTS
    sanitizer:
      - if (epid == 0 || epid >= XHCI_MAX_ENDPOINTS) {
  CVE-2021-29631:
    sink:
      - vq_getchain
      - VT9P_MAX_IOV
    sanitizer:
      - assert(n >= 1 && n <= VT9P_MAX_IOV);
