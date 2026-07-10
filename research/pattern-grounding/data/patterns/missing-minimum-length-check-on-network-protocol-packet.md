# Pattern: missing-minimum-length-check-on-network-protocol-packet

## 描述
网络协议解析器从 UDP/DHCP/RADIUS 等报文中解码长度、偏移或属性长度字段后，仅检查其是否超过缓冲区上界，未检查协议要求的最小有效长度或非负性。攻击者可构造零、负数或过小长度，使循环、指针推进或属性读取发生越界、下溢或无限回溯。

## Structured Fields
source:
  - 网络报文中的 Length 字段、TLV 属性长度或压缩域名指针偏移
sink:
  - 解码长度控制循环边界、指针推进或缓冲区读取范围
  - 以属性长度推进报文解析位置
sanitizer:
  - 检查 len < MIN_PROTOCOL_LENGTH 或 pointed_len < 0
  - 将单侧上界检查扩展为 len < MIN || len > buffer_len
severity_hint: medium
confidence: high
generalizable: yes
rule_candidate: pilot

## 历史实例
- CVE-2020-7461 @ sbin/dhclient/options.c::find_search_domain_name_len
- CVE-2021-29629 @ lib/libradius/radlib.c::is_valid_response

## 检测建议（供 Rule Agent）
vulnerable_indicator: 从网络包读取的长度或偏移值进入循环、指针推进或缓冲区访问，仅存在上界检查，缺少非负性或协议最小长度检查。
fixed_indicator: 使用点前存在 len < MIN、len < 0、alen < 2 或 len < MIN || len > buffer_len 形式的双侧检查。
target_apis: [POS_ATTRS, POS_LENGTH, MD5_DIGEST_LENGTH]

rule_scope:
  language: c/cpp
  module_scope: cross-module
rule_type: intra-procedural
source_predicate:
  description: 识别从网络报文字节、TLV 字段或压缩指针解码出的整型长度/偏移。
sink_predicate:
  description: 识别以该长度/偏移控制的循环、指针移动、报文属性读取或解析位置推进。
sanitizer_predicate:
  description: 识别同一函数内在 sink 前出现的非负检查、最小协议长度检查或双侧范围检查。
negative_examples:
  - 长度字段来自已验证的固定头部，且调用前已有统一协议解码器保证最小长度。
  - 解析循环每次推进前都检查剩余缓冲区至少包含 TLV 头部和声明长度。
member_anchors:
  CVE-2020-7461:
    sink:
      - pointed_len
      - find_search_domain_name_len
    sanitizer:
      - if (pointed_len < 0)
  CVE-2021-29629:
    sink:
      - POS_ATTRS
      - rad_get_attr
    sanitizer:
      - if (len < POS_ATTRS || len > h->in_len)
