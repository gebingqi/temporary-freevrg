#!/usr/bin/env python3
"""
FreeVRG revised grounding checker.

Checks instance and pattern markdown for Rule Agent readiness:
- instance status: PASS_STRICT / PASS_WEAK / FAIL
- pattern status: PASS_STRICT / PASS_WEAK / FAIL
- auto-builds CVE -> sample mapping by scanning samples/*.json
"""
import argparse
import json
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
DEFAULT_INSTANCES = ROOT / "data" / "instances"
DEFAULT_PATTERNS = ROOT / "data" / "patterns"
DEFAULT_SAMPLES = ROOT.parent / "样本库" / "基线-v1"


def norm(s: str) -> str:
    return re.sub(r"\s+", " ", s or "").strip()


def load_samples(samples_dir: Path):
    out = {}
    for p in sorted(samples_dir.glob("*.json")):
        data = json.loads(p.read_text(encoding="utf-8"))
        cves = data.get("cve") or []
        if len(cves) == 1:
            out[cves[0]] = data
    return out


def added_lines(sample):
    return [ln[1:].rstrip("\r") for ln in sample.get("diff", "").splitlines()
            if ln.startswith("+") and not ln.startswith("+++")]


def added_blob(sample):
    return norm(" ".join(added_lines(sample)))


def after_lines(sample):
    out = []
    for blob in (sample.get("after_code") or {}).values():
        out.extend(blob.splitlines())
    return out


def after_blob(sample):
    return norm(" ".join(after_lines(sample)))


def changed_func_names(sample):
    names = set()
    for key in (sample.get("after_code") or {}):
        func = key.split("::", 1)[-1]
        if func and not func.startswith("<"):
            names.add(func)
    return names


def guard_plausible(guard: str):
    g = norm(guard).strip("`")
    if not g:
        return False, "empty guard"
    low = g.lower()
    if any(x in low for x in ("copyright", "license", "spdx")):
        return False, "license/comment text"
    if g.lstrip().startswith(("/*", "//", "*", "#")):
        return False, "comment/preprocessor line"
    has_guard = bool(
        re.search(r"\b(if|return|goto|break|continue|assert|_static_assert|abort|err|panic)\b", low)
        or re.search(r"(<=|>=|==|!=|&&|\|\||[<>])", g)
        or re.search(r"\b[A-Za-z_][A-Za-z0-9_]*\s*\(", g)
    )
    return (has_guard, "" if has_guard else "not a guard-like code line")


def extract_json_line(md: str):
    m = re.search(r"^VULN_CLASS_JSON:\s*(\{.*\})\s*$", md, re.M)
    if not m:
        return {}
    try:
        return json.loads(m.group(1))
    except json.JSONDecodeError:
        return {}


def extract_field(md: str, label: str):
    m = re.search(rf"^-\s*{re.escape(label)}\s*[:：]\s*(.+)$", md, re.M)
    return m.group(1).strip() if m else ""


def extract_block_items(md: str, label: str):
    m = re.search(rf"^{re.escape(label)}\s*[:：]\s*$", md, re.M | re.I)
    if not m:
        return []
    items = []
    for ln in md[m.end():].splitlines():
        stripped = ln.strip()
        if stripped.startswith("- "):
            items.append(stripped[2:].strip())
        elif stripped and not ln.startswith((" ", "\t")):
            break
    return items


def extract_inline_list(md: str, label: str):
    m = re.search(rf"^{re.escape(label)}\s*[:：]\s*\[([^\]]*)\]", md, re.M)
    if not m:
        return []
    return [x.strip().strip("'\"") for x in m.group(1).split(",") if x.strip()]


def extract_instances(md: str):
    return list(dict.fromkeys(re.findall(r"CVE-\d{4}-\d{3,}", md)))


def extract_scalar(md: str, label: str):
    m = re.search(rf"^{re.escape(label)}\s*[:：]\s*(.+)$", md, re.M)
    return m.group(1).strip() if m else ""


def extract_member_anchors(md: str):
    anchors = {}
    lines = md.splitlines()
    in_block = False
    current = None
    current_kind = None
    for ln in lines:
        stripped = ln.strip()
        if stripped == "member_anchors:":
            in_block = True
            continue
        if in_block and stripped and not ln.startswith((" ", "\t")):
            break
        if not in_block:
            continue
        cve_match = re.match(r"(CVE-\d{4}-\d{3,}):\s*$", stripped)
        if cve_match:
            current = cve_match.group(1)
            anchors.setdefault(current, {"sink": [], "sanitizer": []})
            current_kind = None
            continue
        if stripped in ("sink:", "sanitizer:"):
            current_kind = stripped[:-1]
            continue
        if current and current_kind and stripped.startswith("- "):
            anchors[current][current_kind].append(stripped[2:].strip())
    return anchors


def token_hit(text: str, token: str):
    t = token.strip().strip("`")
    if not t:
        return False
    return norm(t) in text or t in text


def check_instance(path: Path, samples):
    md = path.read_text(encoding="utf-8")
    cve = path.stem
    msgs = []
    weak = False
    sample = samples.get(cve)
    if not sample:
        return "FAIL", cve, ["missing sample JSON"]
    vcj = extract_json_line(md)
    guard = norm(vcj.get("added_guard") or extract_field(md, "Sanitizer")).strip("`")
    source = extract_field(md, "Source")
    sink = vcj.get("sink") or extract_field(md, "Sink")
    adds = added_blob(sample)
    after = after_blob(sample)

    if not source:
        msgs.append("Source is empty")
    if not guard:
        msgs.append("added_guard/Sanitizer is empty")
    else:
        plausible, reason = guard_plausible(guard)
        in_adds = token_hit(adds, guard)
        in_after = token_hit(after, guard)
        if not in_adds:
            if in_after:
                weak = True
                msgs.append("added_guard found in after_code but not exact diff + lines")
            else:
                msgs.append(f"added_guard not grounded in diff + lines: {guard[:80]}")
        if not plausible:
            weak = True
            msgs.append(f"added_guard is code-grounded but weak: {reason}")
    if sink:
        toks = [t for t in re.split(r"[^A-Za-z0-9_]+", sink) if len(t) >= 3]
        if toks and not any(t in after for t in toks):
            weak = True
            msgs.append(f"sink token not directly visible in after_code: {sink}")
    if msgs and any("not grounded" in m or "empty" in m for m in msgs):
        return "FAIL", cve, msgs
    return ("PASS_WEAK" if weak else "PASS_STRICT"), cve, msgs


def pattern_text_fields(md: str):
    parts = []
    for label in ("sink", "vulnerable_indicator", "target_apis"):
        parts.extend(extract_block_items(md, label))
        scalar = extract_scalar(md, label)
        if scalar:
            parts.append(scalar)
    return " ".join(parts)


def check_pattern(path: Path, samples):
    md = path.read_text(encoding="utf-8")
    name = path.stem
    msgs = []
    weak = False
    cves = extract_instances(md)
    candidate = extract_scalar(md, "rule_candidate")
    confidence = extract_scalar(md, "confidence")
    target_apis = extract_inline_list(md, "target_apis")
    anchors = extract_member_anchors(md)

    for field in ("source", "sink", "sanitizer"):
        if not extract_block_items(md, field):
            msgs.append(f"Structured Fields missing {field}")
    if not cves:
        msgs.append("no historical CVE parsed")

    for cve in cves:
        sample = samples.get(cve)
        if not sample:
            msgs.append(f"missing sample for {cve}")
            continue
        after = after_blob(sample)
        adds = added_blob(sample)
        sink_anchors = list(anchors.get(cve, {}).get("sink", [])) + target_apis
        sanitizer_anchors = anchors.get(cve, {}).get("sanitizer", [])
        if not any(token_hit(after, a) for a in sink_anchors):
            msgs.append(f"{cve} has no sink/member anchor hit")
        if sanitizer_anchors and not any(token_hit(adds, a) or token_hit(after, a) for a in sanitizer_anchors):
            msgs.append(f"{cve} has no sanitizer anchor hit")

    leak_text = pattern_text_fields(md)
    leaked = sorted({fn for cve in cves for fn in changed_func_names(samples.get(cve, {})) if fn and re.search(rf"\b{re.escape(fn)}\b", leak_text)})
    if leaked:
        weak = True
        msgs.append(f"function-name leakage warning: {', '.join(leaked)}")
        if confidence == "high" and candidate != "pilot":
            msgs.append("high confidence is not allowed with function-name leakage")

    if msgs and any(m.startswith("Structured") or "no sink" in m or "no sanitizer" in m or "missing sample" in m or "not allowed" in m for m in msgs):
        return "FAIL", name, msgs
    if candidate == "defer":
        weak = True
        msgs.append("rule_candidate: defer")
    return ("PASS_WEAK" if weak else "PASS_STRICT"), name, msgs


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--instances-dir", default=str(DEFAULT_INSTANCES))
    ap.add_argument("--patterns-dir", default=str(DEFAULT_PATTERNS))
    ap.add_argument("--samples", default=str(DEFAULT_SAMPLES))
    ap.add_argument("--instances", nargs="*", default=None)
    ap.add_argument("--patterns", nargs="*", default=None)
    args = ap.parse_args()

    samples = load_samples(Path(args.samples))
    instance_paths = [Path(p) for p in args.instances] if args.instances else sorted(Path(args.instances_dir).glob("CVE-*.md"))
    pattern_paths = [Path(p) for p in args.patterns] if args.patterns else sorted(p for p in Path(args.patterns_dir).glob("*.md") if not p.name.startswith("_") and p.name != ".gitkeep")

    failed = False
    pilot_fail = False
    print("# FreeVRG revised grounding_check")
    print(f"# samples: {Path(args.samples)}")
    print("\n## Instances")
    for p in instance_paths:
        status, name, msgs = check_instance(p, samples)
        print(f"[实例 {status}] {name} ({p.name})")
        for m in msgs:
            print(f"    - {m}")
        failed |= status == "FAIL"

    print("\n## Patterns")
    for p in pattern_paths:
        status, name, msgs = check_pattern(p, samples)
        md = p.read_text(encoding="utf-8")
        candidate = extract_scalar(md, "rule_candidate")
        print(f"[类层 {status}] {name} ({p.name})")
        for m in msgs:
            print(f"    - {m}")
        failed |= status == "FAIL"
        if candidate == "pilot" and status != "PASS_STRICT":
            pilot_fail = True
            print("    - pilot pattern must be PASS_STRICT")

    print("\n## Summary")
    if failed or pilot_fail:
        print("结论: 有 FAIL 或试点 pattern 未严格通过")
        sys.exit(1)
    print("结论: 无 FAIL；Rule Agent 试点 pattern 均 PASS_STRICT")
    sys.exit(0)


if __name__ == "__main__":
    main()
