# -*- coding: utf-8 -*-
"""检查一个 APK 的 APK Signing Block 实际内容（M22 排障）。

打印：
  * 块在文件中的位置与长度、是否 4 字节对齐
  * 块内的 pair id 列表
  * v2/v3 里记录的**算法 id 与内容摘要**，并与规范复算的摘要比对

用法：
    python tools/inspect-signing-block.py <apk>
"""
import hashlib
import struct
import sys

MAGIC = b"APK Sig Block 42"
ALG_SHA256 = 0x0103


def lp(buf, p):
    n, = struct.unpack_from("<I", buf, p)
    return buf[p + 4:p + 4 + n], p + 4 + n


def seq(buf, p):
    """读一个"长度前缀的序列"，返回 (各元素字节, 结束偏移)。"""
    total, = struct.unpack_from("<I", buf, p)
    end = p + 4 + total
    q = p + 4
    items = []
    while q < end:
        b, q = lp(buf, q)
        items.append(b)
    return items, end


def digest_sections(parts, chunk=1 << 20):
    """v2/v3 内容摘要：1 MiB 分块，每块前缀 0xa5 + u32(长度)，最后一块长度记 0。"""
    h = hashlib.sha256()
    buf = b""
    for kind, val in parts:
        if kind == "bytes":
            buf += val
        else:                       # ("range", path, off, len)
            _, path, off, ln = (kind, val[0], val[1], val[2])
            with open(path, "rb") as f:
                f.seek(off)
                left = ln
                while left > 0:
                    take = min(chunk, left)
                    buf += f.read(take)
                    left -= take
        while len(buf) >= chunk:
            h.update(b"\xa5" + struct.pack("<I", chunk) + buf[:chunk])
            buf = buf[chunk:]
    h.update(b"\xa5" + struct.pack("<I", 0) + buf)
    return h.digest()


def main():
    path = sys.argv[1]
    d = open(path, "rb").read()
    size = len(d)
    eocd_at = d.rfind(b"PK\x05\x06")
    (_s, _d1, _d2, _de, total, cd_size, cd_off, cmt) = \
        struct.unpack_from("<IHHHHIIH", d, eocd_at)
    print("  文件 %d 字节；EOCD cd_off=%d cd_size=%d entries=%d" % (size, cd_off, cd_size, total))
    print("  实际中央目录签名位置: %d" % d.rfind(b"PK\x01\x02", 0, cd_off + 4))
    magic_at = d.rfind(MAGIC)
    if magic_at < 0:
        print("  ** 找不到 APK Sig Block 42（没有 v2/v3 块）**")
        return 1
    blk_end = magic_at + 16
    print("  块尾 = %d；是否等于 cd_off: %s" % (blk_end, blk_end == cd_off))
    sop, = struct.unpack_from("<Q", d, magic_at - 8)
    blk_start = blk_end - 16 - 8 - sop - 8
    v, = struct.unpack_from("<Q", d, blk_start)
    print("  块首 = %d；size_of_block=%d（期望 %d）%s"
          % (blk_start, v, blk_end - blk_start - 8,
             "OK" if v == blk_end - blk_start - 8 else "**不符**"))
    print("  4 字节对齐: start%%4=%d len%%4=%d" % (blk_start % 4, (blk_end - blk_start) % 4))

    pairs = {}
    p = blk_start + 16
    end = blk_start + 16 + sop
    while p < end:
        pid, plen = struct.unpack_from("<II", d, p)
        pairs[pid] = d[p + 8:p + 8 + plen]
        p += 8 + plen
    print("  pair ids: %s" % ["0x%08x (%d B)" % (k, len(v)) for k, v in pairs.items()])

    # 复算内容摘要（分段：entries ‖ CD ‖ EOCD）
    cd_bytes = d[cd_off:cd_off + cd_size]
    eocd_bytes = d[eocd_at:]
    want = digest_sections([("range", (path, 0, blk_start)),
                            ("bytes", cd_bytes), ("bytes", eocd_bytes)])
    print("  复算内容摘要: %s" % want.hex())

    for name, pid in (("v2", 0x7109871A), ("v3", 0xF05368C0)):
        if pid not in pairs:
            print("  [%s] 缺失" % name)
            continue
        val = pairs[pid]
        signers = seq(*lp(val, 0))[0] if False else None
        # value = _lp(signers) ; signers = _lp_seq([signer])
        s_body, _ = lp(val, 0)
        s_items, _ = seq(s_body, 0)
        signer, _ = lp(s_items[0], 0)
        f, _ = seq(signer, 0)
        print("  [%s] signer 字段数=%d 长度=%s" % (name, len(f), [len(x) for x in f]))
        sd_field = f[2] if name == "v2" else f[0]
        sd, _ = lp(sd_field, 0)
        items, _ = seq(sd, 0)
        dgs, _ = seq(items[0], 0)
        alg, _ = lp(dgs[0], 0)
        algo_id, = struct.unpack_from("<I", alg, 0)
        dg, _ = lp(alg, 4)
        print("       algo_id=0x%08x digest=%s %s"
              % (algo_id, dg.hex(), "OK" if dg == want else "**与复算不符**"))
    return 0


if __name__ == "__main__":
    sys.exit(main())
