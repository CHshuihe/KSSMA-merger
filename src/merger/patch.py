# -*- coding: utf-8 -*-
"""字节级补丁的应用逻辑（与 merger/src/tools/apply-binary-patch.py 同规则）。

安全保证（任一不满足即抛异常，**不修改输入**）：
    1. 输入长度 == patch["size"]
    2. 输入 SHA256 == patch["from_sha256"]
    3. 每个区间应用前，原字节 == patch["before"]
    4. 打完 SHA256 == patch["to_sha256"]
"""
import hashlib


class PatchError(Exception):
    pass


def apply_patch_bytes(data, patch):
    if patch.get("format") != "kssma-binary-patch/1":
        raise PatchError("不支持的补丁格式: %r" % patch.get("format"))
    if len(data) != patch["size"]:
        raise PatchError("长度不符：文件 %d 字节，补丁期望 %d 字节"
                         % (len(data), patch["size"]))
    got = hashlib.sha256(data).hexdigest()
    if got != patch["from_sha256"]:
        raise PatchError(
            "源文件指纹不符（说明不是受支持的原版文件）\n  期望 %s\n  实际 %s"
            % (patch["from_sha256"], got))
    buf = bytearray(data)
    for i, r in enumerate(patch["regions"]):
        off = r["offset"]
        before = bytes.fromhex(r["before"])
        after = bytes.fromhex(r["after"])
        if len(before) != len(after):
            raise PatchError("区间 %d 非等长，拒绝应用" % i)
        actual = bytes(buf[off:off + len(before)])
        if actual != before:
            raise PatchError(
                "区间 %d @0x%X 与预期原字节不符\n  got      %s\n  expected %s"
                % (i, off, actual.hex(), before.hex()))
        buf[off:off + len(after)] = after
    out = bytes(buf)
    got = hashlib.sha256(out).hexdigest()
    if got != patch["to_sha256"]:
        raise PatchError("结果指纹不符\n  期望 %s\n  实际 %s"
                         % (patch["to_sha256"], got))
    return out
