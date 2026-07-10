# Pattern: missing-absolute-path-check-in-archive-extraction

## 描述
归档提取路径规范化逻辑在写入文件系统前未拒绝以 `/` 开头的绝对路径，导致归档条目可覆盖宿主机任意路径。两个历史实例都集中在 libarchive 的 `cleanup_pathname`，更适合作为 library-specific 历史重复模式，而不是跨模块强泛化规则。

## Structured Fields
source:
  - 归档文件中攻击者构造的条目路径名
sink:
  - archive_write_disk 将规范化后的路径写入文件系统
  - libarchive 路径规范化逻辑输出的最终路径
sanitizer:
  - 检测路径首字符为 `/` 并在 ARCHIVE_EXTRACT_SECURE_NOABSOLUTEPATHS 策略下拒绝
  - 检测路径中 `..` 目录穿越并按安全标志拒绝
severity_hint: high
confidence: medium
generalizable: local
rule_candidate: defer

## 历史实例
- CVE-2013-0211 @ contrib/libarchive/libarchive/archive_write_disk.c::cleanup_pathname
- CVE-2015-2304 @ contrib/libarchive/libarchive/archive_write_disk.c::cleanup_pathname

## 检测建议（供 Rule Agent）
vulnerable_indicator: libarchive 路径规范化函数处理归档条目路径时不含对绝对路径首字符 `/` 的显式拒绝。
fixed_indicator: 规范化函数存在 if (*src == '/') 检查并结合 ARCHIVE_EXTRACT_SECURE_NOABSOLUTEPATHS 返回失败。
target_apis: [archive_set_error, ARCHIVE_FAILED, ARCHIVE_EXTRACT_SECURE_NOABSOLUTEPATHS]

rule_scope:
  language: c/cpp
  module_scope: library-specific
rule_type: intra-procedural
source_predicate:
  description: 识别归档条目路径字符串。
sink_predicate:
  description: 识别 libarchive 写盘前的路径规范化或 archive_write_disk 路径设置流程。
sanitizer_predicate:
  description: 识别对路径首字符 `/` 的拒绝和安全提取标志检查。
negative_examples:
  - 仅显示或列出归档路径，不执行写盘。
  - 调用者已经强制设置并验证 no-absolute-path 策略。
member_anchors:
  CVE-2013-0211:
    sink:
      - cleanup_pathname
      - archive_write_disk
    sanitizer:
      - if (a->flags & ARCHIVE_EXTRACT_SECURE_NOABSOLUTEPATHS) {
  CVE-2015-2304:
    sink:
      - cleanup_pathname
      - archive_write_disk
    sanitizer:
      - if (a->flags & ARCHIVE_EXTRACT_SECURE_NOABSOLUTEPATHS) {
