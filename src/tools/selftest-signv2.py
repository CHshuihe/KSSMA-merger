# -*- coding: utf-8 -*-
"""v2/v3 Signing Block 的独立自测（M22）。

不跑 900 MB 合并，先用 `ApkWriter` 造一个**小 zip**，签 v1+v2+v3，
然后：
  1. 按规范逐字节复算 Signing Block 的结构（magic / pair id / 长度自洽）
  2. **复算内容摘要**（1 MiB 分块）并与块里记录的比对
  3. 用块里的公钥**验签**（RSA PKCS#1 v1.5 + SHA-256）
  4. 检查 EOCD 的 cd_off 是否指向真实的中央目录

真正的权威验证仍是 `apksigner verify`（见 tools/verify-v2v3.py）。

用法：
    python tools/selftest-signv2.py
"""
import hashlib
import os
import struct
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.abspath(os.path.join(HERE, "..", "..", "src")))

from merger import signv2                                   # noqa: E402
from merger.signv2 import (BLOCK_ID_V2, BLOCK_ID_V3, MAGIC, _lp, _lp_seq,
                           build_content_digests)           # noqa: E402
from merger.zipio import ApkWriter, BytesSource, WriteEntry  # noqa: E402


def _rd_lp(buf, p):
    """读一个长度前缀切片，返回 (bytes, 新偏移)。"""
    n, = struct.unpack_from("<I", buf, p)
    return buf[p + 4:p + 4 + n], p + 4 + n


def _rd_seq(buf, p):
    """读一个"序列"：先总长，再依次是各元素的长度前缀切片。"""
    total, = struct.unpack_from("<I", buf, p)
    end = p + 4 + total
    q = p + 4
    items = []
    while q < end:
        b, q = _rd_lp(buf, q)
        items.append(b)
    return items, end


def main():
    tmpdir = os.path.join(HERE, "..", "build", "v2test")
    os.makedirs(tmpdir, exist_ok=True)
    out = os.path.join(tmpdir, "small.zip")

    # 造一个 key + 证书
    from merger import sign as v1
    key, certs = v1.generate_self_signed("v2test")   # certs 是证书对象，Signer 内部转 DER
    signer = signv2.Signer(key, certs, wants_v2=True, v2_min_sdk=24)

    w = ApkWriter(out)
    w.add(WriteEntry("hello.txt", BytesSource(b"hello world\n", 0), 0))
    w.add(WriteEntry("dir/a.bin", BytesSource(os.urandom(3000), 8), 8))
    n = signer.write_v1(w)
    meta = w.close(signing_block=signer.build_block)
    size = os.path.getsize(out)
    print("  小 zip: %d 字节，%d 个条目，v1 覆盖 %d 个文件" % (size, meta["entries"], n))

    # ── 定位 Signing Block ──
    with open(out, "rb") as f:
        data = f.read()
    cd_off = meta["cd_off"]
    eocd = data[cd_off + meta["cd_size"]:]
    assert data[cd_off:cd_off + 4] == b"PK\x01\x02", "CD 起始不对"
    assert eocd[:4] == b"PK\x05\x06", "EOCD 不对"
    assert MAGIC in data, "找不到 APK Sig Block 42"
    magic_at = data.rindex(MAGIC)
    block_end = magic_at + 16
    assert block_end == cd_off, "Signing Block 应紧贴在中央目录之前（end=%d cd_off=%d）" % (
        block_end, cd_off)
    # magic 前 8 字节 = 块尾的 size_of_pairs
    sop_tail, = struct.unpack_from("<Q", data, magic_at - 8)
    # 块首：size_of_block 字段所在处。块紧贴 CD 之前，故块总长 = cd_off - blk_start，
    # 且块首第一个 u64 = 块总长 - 8。扫描定位（对填充/对齐不敏感）。
    blk_start = None
    for p in range(max(0, cd_off - 8 - (8 + 8 + sop_tail + 8 + 16) - 32),
                   cd_off - 8 - (8 + 8 + sop_tail + 8 + 16) + 33):
        v, = struct.unpack_from("<Q", data, p)
        s2, = struct.unpack_from("<Q", data, p + 8)
        if s2 == sop_tail and v == cd_off - p - 8:
            blk_start = p
            break
    assert blk_start is not None, "找不到 Signing Block 首部"
    blk_total = cd_off - blk_start
    print("  Signing Block @%d 块长 %d（含 8 字节 size 字段），size_of_pairs=%d"
          % (blk_start, blk_total, sop_tail))
    assert blk_start % 4 == 0, "块起址没有 4 字节对齐"
    assert blk_total % 4 == 0, "块长不是 4 的倍数"

    # ── 解 pair ──
    pairs = {}
    p = blk_start + 16
    pairs_end = blk_start + 16 + sop_tail   # 跳过 size_of_block(8) + size_of_pairs(8)
    while p < pairs_end:
        pid, plen = struct.unpack_from("<II", data, p)
        pairs[pid] = data[p + 8:p + 8 + plen]
        p += 8 + plen
    assert p == pairs_end, "pair 区域未正好读完"
    print("  pair ids: %s" % ["0x%08x" % k for k in pairs])
    assert BLOCK_ID_V2 in pairs and BLOCK_ID_V3 in pairs, "缺少 v2 或 v3"

    # ── 复算内容摘要 ──
    # 摘要范围 = [0, blk_start) ‖ CD ‖ EOCD
    cd_bytes = data[cd_off:cd_off + meta["cd_size"]]
    want_digest = build_content_digests(
        [(out, 0, blk_start), cd_bytes, eocd])
    print("  复算内容摘要: %s…" % want_digest.hex()[:16])

    def as_seq(buf):
        """把 buf 当作"已去掉外层长度前缀的序列"解。

        返回元素列表（每个元素已去掉自身的长度前缀）。
        注意：这里**不再**调 _rd_lp 去外层，因为调用方传入的已经是
        “去掉一层长度前缀后”的内容（见树形打印）。
        """
        items, end = _rd_seq(buf, 0)
        assert end == len(buf), "序列未正好读完"
        return items

    # v2 结构（实测，见树形打印）：
    #   value(0x7109871a) = _lp( signers )
    #   signers           = _lp_seq([ signer ])
    #   signer            = _lp_seq([ signatures, publickey, signed_data ])
    #   signed_data       = _lp_seq([ digests, certificates, attrs ])
    #   digests           = _lp_seq([ alg+digest ])
    # value = _lp( signers ) ; signers = _lp_seq([signer]) ; signer = _lp_seq([...])
    signers2 = as_seq(_rd_lp(pairs[BLOCK_ID_V2], 0)[0])   # -> [signer]
    p2 = as_seq(signers2[0])                              # signer -> [sig, pub, sd]
    sd2 = p2[2]
    it2 = as_seq(sd2)
    dg_block = as_seq(_rd_lp(it2[0], 0)[0])[0]   # _lp(algo_id + _lp(digest))
    dg2 = _rd_lp(dg_block, 4)[0]
    print("  v2 内容摘要: %s…  %s" % (dg2.hex()[:16],
          "OK" if dg2 == want_digest else "**不符**"))
    assert dg2 == want_digest, "v2 内容摘要不符"

    # v3 signer = _lp_seq([ signed_data, minmax, signatures ])
    signers3 = as_seq(_rd_lp(pairs[BLOCK_ID_V3], 0)[0])
    p3 = as_seq(signers3[0])
    sd3 = p3[0]
    it3 = as_seq(sd3)
    dg_block3 = as_seq(_rd_lp(it3[0], 0)[0])[0]
    dg3 = _rd_lp(dg_block3, 4)[0]
    print("  v3 内容摘要: %s…  %s" % (dg3.hex()[:16],
          "OK" if dg3 == want_digest else "**不符**"))
    assert dg3 == want_digest, "v3 内容摘要不符"
    mn, mx = struct.unpack("<ii", p3[1])
    print("  v3 minSdk=%d maxSdk=%d" % (mn, mx))

    # ── 用块里的公钥验签 ──
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import padding
    from cryptography.hazmat.primitives.serialization import load_der_public_key

    def sig_bytes_of(field):
        body, _ = _rd_lp(field, 0)
        lst, _ = _rd_seq(body, 0)
        alg, _ = _rd_lp(lst[0], 0)
        return _rd_lp(alg, 4)[0]

    pub_der, _ = _rd_lp(p2[1], 0)
    pub = load_der_public_key(pub_der)
    pub.verify(sig_bytes_of(p2[0]), sd2, padding.PKCS1v15(), hashes.SHA256())
    print("  v2 签名验证: OK")

    pub.verify(sig_bytes_of(p3[2]), sd3, padding.PKCS1v15(), hashes.SHA256())
    print("  v3 签名验证: OK")

    print("\n全部自测通过 ✅  (%s)" % out)


if __name__ == "__main__":
    main()
