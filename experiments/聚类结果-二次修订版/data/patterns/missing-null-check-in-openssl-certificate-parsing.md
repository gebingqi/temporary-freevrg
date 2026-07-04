# Pattern: missing-null-check-in-openssl-certificate-parsing

## 描述
OpenSSL/TLS 证书和 ASN.1 扩展解析路径中，查找函数或 ASN.1 OPTIONAL 字段可能返回 NULL。原代码在成员访问前缺少 NULL 检查，攻击者可通过构造证书、签名算法或 GeneralName 扩展触发空指针崩溃。该类当前限定在 OpenSSL 证书解析上下文，不命名为通用空指针规则。

## Structured Fields
source:
  - TLS 握手中对端提供的证书、签名算法或 GeneralName 扩展
sink:
  - OpenSSL 查找/解析函数返回的结构体指针被成员访问
  - ASN.1 OPTIONAL 字段子成员被访问
sanitizer:
  - 成员访问前检查 ptr != NULL 或 ptr == NULL 后提前返回
  - 对 ASN.1 OPTIONAL 字段的每个子字段做独立 NULL 保护
severity_hint: medium
confidence: medium
generalizable: local
rule_candidate: defer

## 历史实例
- CVE-2020-1967 @ crypto/openssl/ssl/t1_lib.c::tls1_check_sig_alg
- CVE-2020-1971 @ crypto/openssl/crypto/x509v3/v3_genn.c::GENERAL_NAME_cmp

## 检测建议（供 Rule Agent）
vulnerable_indicator: OpenSSL 证书解析代码中，对可空查找/解析结果或 ASN.1 OPTIONAL 字段成员解引用前缺少 NULL 检查。
fixed_indicator: 访问成员前存在 ptr != NULL、ptr == NULL return/goto 或等价提前返回。
target_apis: [tls1_lookup_sigalg, GENERAL_NAME_cmp, GENERAL_NAME]

rule_scope:
  language: c/cpp
  module_scope: library-specific
rule_type: intra-procedural
source_predicate:
  description: 识别 OpenSSL TLS/ASN.1 证书解析中的外部证书、签名算法和 GeneralName 输入。
sink_predicate:
  description: 识别查找/解析返回结构体指针或 ASN.1 OPTIONAL 字段的成员访问。
sanitizer_predicate:
  description: 识别同一函数内成员访问前的 NULL 检查或提前返回。
negative_examples:
  - 指针来自必填字段且上游解析器保证非空。
  - 成员访问支配路径上已有 NULL 检查。
member_anchors:
  CVE-2020-1967:
    sink:
      - sigandhash
      - tls1_lookup_sigalg
    sanitizer:
      - if (sigalg != NULL && sig_nid == sigalg->sigandhash)
  CVE-2020-1971:
    sink:
      - ediPartyName
      - GENERAL_NAME_cmp
    sanitizer:
      - if (a == NULL || b == NULL) {
