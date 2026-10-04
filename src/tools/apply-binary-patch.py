# -*- coding: utf-8 -*-
"""把一个 kssma-binary-patch 描述应用到目标文件（原地、带三重校验）。

给构建脚本用：
    python apply-binary-patch.py <patch.json> <目标文件>

安全保证（任一不满足即中止，且**不写回**）：
    1. 目标文件大小 == patch.size
    2. 目标文件 SHA256 == patch.from_sha256
    3. 每个区间应用前，原字节 == patch.before
    4. 打完 SHA256 == patch.to_sha256
只有全部通过才落盘（先写临时文件再原子替换）。
"""
import hashlib
import json
import os
import sys


def sha256_file(path, chunk=1 << 20):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        while True:
            b = f.read(chunk)
            if not b:
                break
            h.update(b)
    return h.hexdigest()


def apply_bytes(data, patch):
    if patch.get("format") != "kssma-binary-patch/1":
        raise ValueError("unknown patch format: %r" % patch.get("format"))
    if len(data) != patch["size"]:
        raise ValueError("size mismatch: file %d, patch expects %d"
                         % (len(data), patch["size"]))
    got = hashlib.sha256(data).hexdigest()
    if got != patch["from_sha256"]:
        raise ValueError("source sha256 mismatch:\n  got      %s\n  expected %s"
                         % (got, patch["from_sha256"]))
    buf = bytearray(data)
    for i, r in enumerate(patch["regions"]):
        off = r["offset"]
        before = bytes.fromhex(r["before"])
        after = bytes.fromhex(r["after"])
        if len(before) != len(after):
            raise ValueError("region %d is not equal-length" % i)
        actual = bytes(buf[off:off + len(before)])
        if actual != before:
            raise ValueError(
                "region %d @0x%X 与预期原字节不符（说明目标文件不是预期版本）\n"
                "  got      %s\n  expected %s" % (i, off, actual.hex(), before.hex()))
        buf[off:off + len(after)] = after
    out = bytes(buf)
    got = hashlib.sha256(out).hexdigest()
    if got != patch["to_sha256"]:
        raise ValueError("result sha256 mismatch:\n  got      %s\n  expected %s"
                         % (got, patch["to_sha256"]))
    return out


def main():
    if len(sys.argv) < 3:
        raise SystemExit(__doc__)
    patch_path, target = sys.argv[1], sys.argv[2]

    with open(patch_path, encoding="utf-8") as f:
        patch = json.load(f)

    label = patch.get("label") or os.path.basename(target)
    before = sha256_file(target)
    if before == patch["to_sha256"]:
        print("  %s 已是目标版本，跳过（幂等）" % label)
        return
    if before != patch["from_sha256"]:
        raise SystemExit(
            "%s: 源文件 sha256 不符\n  got      %s\n  expected %s\n"
            "（说明这不是受支持的原版文件）" % (label, before, patch["from_sha256"]))

    with open(target, "rb") as f:
        data = f.read()
    out = apply_bytes(data, patch)

    tmp = target + ".tmp"
    with open(tmp, "wb") as f:
        f.write(out)
    os.replace(tmp, target)

    print("  %s: %s -> %s（%d 区间 / %d 字节）"
          % (label, before[:16], sha256_file(target)[:16],
             patch["region_count"], patch["changed_bytes"]))


if __name__ == "__main__":
    main()
