# -*- coding: utf-8 -*-
"""从「原版文件 → 已打补丁文件」生成字节级补丁描述，并可重放验证（Q6 方案 B 的基础设施）。

为什么要这个：
    Q6 决定 —— 合并器**不分发任何原版二进制**（librooneyj.so / classes.dex 都不发）。
    用户提供原版 APK，合并器**现场对它自己的文件打补丁**。
    前提是补丁能反解成「偏移 + 原字节 + 新字节」，并且**可验证、可重放**。

安全性设计（重要）：
    1. 全量 SHA256 校验：原文件必须等于 `from_sha256`，打完后必须等于 `to_sha256`
    2. 逐区间前置校验：每个区间应用前必须匹配 `before` 字节 —— 不匹配就**中止**，绝不"硬打"
    3. 不做长度变化：只支持**等长原地改写**（本项目的 native 补丁正是如此）
       —— 这样不会破坏 ELF/zip 里任何偏移引用

用法：
    # 生成补丁描述（输出 JSON）
    python make-binary-patch.py gen <原文件> <补丁后文件> <输出.json> [标签]

    # 重放验证：用描述把原文件打成补丁后，与补丁后文件逐字节比对
    python make-binary-patch.py verify <原文件> <补丁后文件> <描述.json>

    # 自检：打印描述摘要
    python make-binary-patch.py info <描述.json>
"""
import hashlib
import json
import sys


def sha256(data):
    return hashlib.sha256(data).hexdigest()


def compute_regions(a, b):
    """返回 [(offset, before_bytes, after_bytes)]，只支持等长。"""
    if len(a) != len(b):
        raise SystemExit(
            "长度不同（%d vs %d）——本工具只支持等长原地改写" % (len(a), len(b)))
    regions = []
    for i in range(len(a)):
        if a[i] != b[i]:
            if regions and i == regions[-1][1] + 1:
                regions[-1][1] = i
            else:
                regions.append([i, i])
    out = []
    for s, e in regions:
        out.append((s, a[s:e + 1], b[s:e + 1]))
    return out


def make_patch(a, b, label=""):
    regions = compute_regions(a, b)
    total = sum(len(r[2]) for r in regions)
    return {
        "format": "kssma-binary-patch/1",
        "label": label,
        "from_sha256": sha256(a),
        "to_sha256": sha256(b),
        "size": len(a),
        "region_count": len(regions),
        "changed_bytes": total,
        "regions": [
            {"offset": s, "before": bef.hex(), "after": aft.hex()}
            for s, bef, aft in regions
        ],
    }


def apply_patch(data, patch, strict=True):
    """把补丁应用到 data，返回新 bytes。strict=True 时逐区间前置校验。"""
    if patch.get("format") != "kssma-binary-patch/1":
        raise ValueError("unknown patch format: %r" % patch.get("format"))
    if len(data) != patch["size"]:
        raise ValueError("size mismatch: input %d, patch expects %d"
                         % (len(data), patch["size"]))
    if strict and sha256(data) != patch["from_sha256"]:
        raise ValueError("source sha256 mismatch:\n  got      %s\n  expected %s"
                         % (sha256(data), patch["from_sha256"]))
    buf = bytearray(data)
    for i, r in enumerate(patch["regions"]):
        off = r["offset"]
        before = bytes.fromhex(r["before"])
        after = bytes.fromhex(r["after"])
        if len(before) != len(after):
            raise ValueError("region %d is not equal-length" % i)
        if strict:
            got = bytes(buf[off:off + len(before)])
            if got != before:
                raise ValueError(
                    "region %d @0x%X does not match expected original bytes\n"
                    "  got      %s\n  expected %s" % (i, off, got.hex(), before.hex()))
        buf[off:off + len(after)] = after
    result = bytes(buf)
    if sha256(result) != patch["to_sha256"]:
        raise ValueError("result sha256 mismatch:\n  got      %s\n  expected %s"
                         % (sha256(result), patch["to_sha256"]))
    return result


def read_file(path):
    if path.lower().endswith(".apk") or path.lower().endswith(".zip"):
        raise SystemExit("请先自行从 APK/zip 里取出目标文件再比较")
    with open(path, "rb") as f:
        return f.read()


def main():
    if len(sys.argv) < 2:
        raise SystemExit(__doc__)
    cmd = sys.argv[1]

    if cmd == "gen":
        if len(sys.argv) < 5:
            raise SystemExit(__doc__)
        src, dst, out = sys.argv[2], sys.argv[3], sys.argv[4]
        label = sys.argv[5] if len(sys.argv) > 5 else ""
        a, b = read_file(src), read_file(dst)
        patch = make_patch(a, b, label)
        with open(out, "w", encoding="utf-8") as f:
            json.dump(patch, f, indent=1, ensure_ascii=False)
        print("生成 %s" % out)
        print("  区间 %d 个 / 改动 %d 字节 / 文件 %d 字节"
              % (patch["region_count"], patch["changed_bytes"], patch["size"]))
        print("  from %s" % patch["from_sha256"])
        print("  to   %s" % patch["to_sha256"])

    elif cmd == "verify":
        if len(sys.argv) < 5:
            raise SystemExit(__doc__)
        src, dst, pj = sys.argv[2], sys.argv[3], sys.argv[4]
        a, b = read_file(src), read_file(dst)
        with open(pj, encoding="utf-8") as f:
            patch = json.load(f)
        got = apply_patch(a, patch)
        ok = got == b
        print("重放结果: %s" % ("逐字节一致 ✓" if ok else "**不一致 ✗**"))
        print("  期望 sha256 %s" % sha256(b))
        print("  实得 sha256 %s" % sha256(got))
        if not ok:
            raise SystemExit(1)

    elif cmd == "info":
        with open(sys.argv[2], encoding="utf-8") as f:
            patch = json.load(f)
        print("标签      : %s" % patch.get("label"))
        print("文件大小  : %d" % patch["size"])
        print("区间数    : %d" % patch["region_count"])
        print("改动字节  : %d (%.4f%%)"
              % (patch["changed_bytes"], 100.0 * patch["changed_bytes"] / patch["size"]))
        print("from      : %s" % patch["from_sha256"])
        print("to        : %s" % patch["to_sha256"])

    else:
        raise SystemExit("unknown command: %s" % cmd)


if __name__ == "__main__":
    main()
