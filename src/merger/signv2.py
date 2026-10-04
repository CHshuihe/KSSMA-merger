# -*- coding: utf-8 -*-
"""APK Signature Scheme **v2 + v3**（APK Signing Block）实现（KSSMA Merger）。

为什么要自己实现：
    合并器要产出一个**与主 dist 包等价**的 APK。主 dist 包由 `apksigner` 签成
    v1+v2+v3；如果合并器只签 v1，两者行为不一致（虽然当前 APK 未声明
    targetSdkVersion，Android 12 接受 v1-only，但不应依赖这个巧合）。

字节布局（三个块都在**中央目录之前**插入）::

    [entries...]
    [APK Signing Block]        <- 本模块产出
    [Central Directory]
    [EOCD]                     <- cd_off 需回填

    APK Signing Block:
        uint64  size_of_block          // 不含本字段自身
        uint64  size_of_pairs          // 不含本字段与 size_of_block
        (uint32 id, uint32 len, byte[len]) * N
        uint64  size_of_pairs          // 与上面那个相等
        byte[16] "APK Sig Block 42"

v2 的 id = 0x7109871a；v3 的 id = 0xf05368c0。

v2 与 v3 的关键差别：
    v2 的 signed data 里是 (digests, certificates, additional_attributes)；
    v3 的 signed data 里多了 **minSDK / maxSDK**（防止降级替换），
    且 signer 结构里签名之外还带 minSDK / maxSDK。

内容摘要（最重要的一块）：
    把"除本 Signing Block 之外的整个文件"按 **1 MiB** 分块，
    每块前缀 0xa5 + uint32 长度(len=0 表示最后一块)，逐块 SHA-256，
    再对"所有块摘要的拼接"做一次 SHA-256。
"""
import hashlib
import struct

# ── 常量 ─────────────────────────────────────────────
BLOCK_ID_V2 = 0x7109871A
BLOCK_ID_V3 = 0xF05368C0
MAGIC = b"APK Sig Block 42"
CHUNK_SIZE = 1 << 20          # 1 MiB，规范固定值
PROOF_OF_ROTATION_ATTR_ID = 0x3BA06F8C
CHUNK_PREFIX = 0xA5


def _lp(data):
    """uint32 长度前缀 + 数据。"""
    return struct.pack("<I", len(data)) + data


def _lp_seq(items):
    """长度前缀的"序列"：uint32(所有元素字节总长) + 各元素（元素自带长度前缀）。

    注意：序列**不是**逐元素重复长度，而是先给一个总长度，再依次放各元素的
    长度前缀字节。这是 apksig 的 `getLengthPrefixedSlice` 约定。
    """
    body = b"".join(_lp(i) for i in items)
    return struct.pack("<I", len(body)) + body


def build_content_digests(parts, chunk=CHUNK_SIZE, algo="sha256"):
    """对若干字节段**顺序拼起来**做 v2/v3 分块摘要。

    parts 是按文件顺序给出的字节段（如 [entries, cd, eocd]）。
    本项目里 entries 可能非常大（900 MB），所以允许传**文件句柄区间**：
    parts 里的元素可以是 bytes，也可以是 (path, offset, length)。
    """
    h = hashlib.new(algo)
    buf = b""
    left_in_last = False

    def feed(b):
        nonlocal buf
        buf += b
        # 按 chunk 切
        while len(buf) >= chunk:
            _one_chunk(buf[:chunk], is_last=False, h=h)
            buf = buf[chunk:]

    for p in parts:
        if isinstance(p, bytes):
            feed(p)
        else:
            path, off, length = p
            with open(path, "rb") as f:
                f.seek(off)
                remaining = length
                while remaining > 0:
                    feed(f.read(min(chunk, remaining)))
                    remaining -= min(chunk, remaining)
    # 最后一块（可能为空 —— 规范要求：空内容也要有一个"最后一块"）
    _one_chunk(buf, is_last=True, h=h)
    return h.digest()


def _one_chunk(data, is_last, h):
    """单块：0xa5 + uint32(长度；最后一块固定 0) + data 的长度。"""
    n = 0 if is_last else len(data)
    h.update(bytes([CHUNK_PREFIX]))
    h.update(struct.pack("<I", n))
    h.update(data)


# ── signed data ──────────────────────────────────────

def _sign_with(key, data):
    """RSA PKCS#1 v1.5 + SHA-256 签名。"""
    try:
        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.primitives.asymmetric import padding
    except ImportError:                                   # pragma: no cover
        raise RuntimeError("需要 cryptography 才能做 v2/v3 签名")
    return key.sign(data, padding.PKCS1v15(), hashes.SHA256())


def _pkcs7(certs):
    """额外属性里的 proof-of-rotation 占位（本项目无密钥轮换，返回空）。"""
    return b""


def build_signed_data_v2(digest, certs_der, key_algo_id=0x0103):
    """v2 signed data 的**完整字节**（签名时签的就是它）。"""
    digests = _lp_seq([_lp(struct.pack("<I", key_algo_id)) + _lp(digest)])
    certificates = _lp_seq(certs_der)
    attrs = _lp_seq([])                      # additional attributes 为空
    return _lp_seq([digests, certificates, attrs])


def build_signed_data_v3(digest, certs_der, min_sdk, max_sdk, key_algo_id=0x0103):
    """v3 signed data 的完整字节（比 v2 多 minSDK/maxSDK）。"""
    digests = _lp_seq([_lp(struct.pack("<I", key_algo_id)) + _lp(digest)])
    certificates = _lp_seq(certs_der)
    sdk_pair = struct.pack("<ii", min_sdk, max_sdk)
    attrs = _lp_seq([])
    return _lp_seq([digests, certificates, sdk_pair, attrs])


def _signatures_v2(sig, key_algo_id=0x0103):
    sigs = _lp_seq([_lp(struct.pack("<I", key_algo_id)) + _lp(sig)])
    return _lp(sigs)


def _signatures_v3(sig, min_sdk, max_sdk, key_algo_id=0x0103):
    entry = _lp(struct.pack("<I", key_algo_id)) + _lp(sig)
    entry += struct.pack("<ii", min_sdk, max_sdk)
    sigs = _lp_seq([entry])
    return _lp(sigs)


# ── Signing Block ────────────────────────────────────

def build_signing_block(pairs):
    """pairs: [(id, value_bytes)] -> 完整 Signing Block 字节。

    块布局（规范，逐字段）::

        u64  size_of_block      = 本字段之后剩余的全部字节
        u64  size_of_pairs      = 各 pair 的 (id,len,value) 总字节
        (u32 id, u32 len, byte[len]) * N
        u64  size_of_pairs      = 与上面相同
        u64  size_of_block      = 与上面相同
        byte[16] "APK Sig Block 42"

    即 块总长 = 8 + size_of_block，且 size_of_block = size_of_pairs + 8 + 8 + 16。

    踩过的两个坑（都导致 apksigner 认不出块）：
      1. 块尾漏写 size_of_block（只写了 size_of_pairs）
      2. 因此 size_of_block 少了 8

    另外：块总长必须是 **4 的倍数**（否则中央目录失去 4 字节对齐）。
    单个 pair 的值长度不受控（RSA SubjectPublicKeyInfo DER 是 294 ≡ 2 mod 4），
    所以末尾追加一个**验证器不认识的 id** 作填充（未知 id 会被跳过；
    Signing Block 本身不在内容摘要范围内，故不影响 v2/v3 摘要与签名）。
    """
    PAD_ID = 0x4B53534D          # "KSSM"，自定义填充 id

    def pairs_len(with_pad):
        n = sum(8 + len(v) for _pid, v in pairs)
        if with_pad:
            n += 8 + with_pad
        return n

    base = pairs_len(0)
    if base % 4 == 0:
        all_pairs = list(pairs)
    else:
        need = (-(base + 8)) % 4          # 加 8 字节头后还需多少字节凑 4 的倍数
        all_pairs = list(pairs) + [(PAD_ID, b"\x00" * need)]

    body = b"".join(struct.pack("<II", pid, len(v)) + v for pid, v in all_pairs)
    size_of_pairs = len(body)
    assert size_of_pairs % 4 == 0, "size_of_pairs 应为 4 的倍数"
    size_of_block = size_of_pairs + 24
    out = (struct.pack("<Q", size_of_block)
           + struct.pack("<Q", size_of_pairs)
           + body
           + struct.pack("<Q", size_of_pairs)
           + struct.pack("<Q", size_of_block)
           + MAGIC)
    # 块总长 = 8（前置 size_of_block 字段）+ size_of_block
    # 总长 = 8（前置 size_of_block）+ size_of_block + 16（magic）
    assert len(out) == 8 + size_of_block + 16, (
        "块总长应为 8+sob+16：len=%d sob=%d sop=%d"
        % (len(out), size_of_block, size_of_pairs))
    assert len(out) % 4 == 0, "Signing Block 总长应为 4 的倍数"
    return out


class Signer:
    """负责产出签名。`wants_v2` 决定是否追加 v2/v3 Signing Block。

    用法（在 ApkWriter.close 的 hook 里）：

        signer = Signer(key, certs_der, wants_v2=True, min_sdk=24)
        signing_block = signer.build_block(writer)   # 传入 writer 以读 entries 区间
        writer.write_bytes(signing_block)            # hook 内必须先写它，再写 CD
    """

    def __init__(self, private_key, certs, password=None, wants_v2=True,
                 v2_min_sdk=24, log=print):
        self.key = private_key
        # 证书要保留**两种形态**：
        #   v1 的 PKCS#7 需要 cryptography 证书对象（sign.build_meta_inf）
        #   v2/v3 的 SignedData 需要 DER 字节
        self.certs_objs = list(certs)
        self.certs_der = [_to_der(c) for c in certs]
        self.password = password
        self.wants_v2 = wants_v2
        self.v2_min_sdk = v2_min_sdk
        self.log = log

    # ── v1 ──────────────────────────────────────────
    def write_v1(self, writer):
        """用**写入时顺带算好的摘要**生成 META-INF/* 并追加。"""
        entries = []
        fallback = 0
        for r in writer.records:
            n = r["name"]
            if n.startswith("META-INF/"):
                continue
            d = r.get("sha256")
            if d is None:
                d = hashlib.sha256(writer.read_entry(n)).hexdigest()
                r["sha256"] = d
                fallback += 1
            entries.append((n, bytes.fromhex(d)))
        if fallback:
            self.log("  （其中 %d 个条目为回读计算摘要）" % fallback)

        from . import sign as v1mod
        from .zipio import BytesSource, WriteEntry
        meta = v1mod.build_meta_inf(entries, self.key, self.certs_objs)
        for name, blob in meta:
            writer.add(WriteEntry(name, BytesSource(blob, 8), 8))
        return len(entries)

    # ── v2 / v3 ─────────────────────────────────────
    def build_block(self, writer, cd_bytes, eocd_bytes, entries_end=None):
        """构造 Signing Block（由 `ApkWriter.close()` 在写 CD 之前调用）。

        摘要覆盖范围 = **除 Signing Block 之外的整个文件**：
            entries ‖ Central Directory ‖ EOCD
        CD/EOCD 的字节由调用方传入（EOCD 里的 cd_off 已是最终值）；
        entries 部分从输出文件按区间 [0, writer.offset) 读，
        **不把 900 MB 读进内存**。
        """
        if not self.wants_v2:
            return None
        # entries_end = 条目数据 + 块前填充的对齐后位置（由 close() 传定值，避免漂移）
        end = writer.offset if entries_end is None else entries_end
        parts = [(writer.out_path, 0, end), cd_bytes, eocd_bytes]
        digest = build_content_digests(parts)

        pubkey = _public_key_der(self.key)
        max_sdk = 0x7FFFFFFF

        # ---- v2 (0x7109871a) ----
        sd2 = build_signed_data_v2(digest, self.certs_der)
        sig2 = _sign_with(self.key, sd2)
        signer2 = _lp_seq([_lp(_signatures_v2(sig2)), _lp(pubkey), _lp(sd2)])
        v2_val = _lp_seq([signer2])

        # ---- v3 (0xf05368c0)：额外带 minSDK/maxSDK，防降级替换 ----
        sd3 = build_signed_data_v3(digest, self.certs_der, self.v2_min_sdk, max_sdk)
        sig3 = _sign_with(self.key, sd3)
        signer3 = _lp_seq([_lp(sd3),
                           struct.pack("<ii", self.v2_min_sdk, max_sdk),
                           _lp(_signatures_v3(sig3, self.v2_min_sdk, max_sdk))])
        v3_val = _lp_seq([signer3])

        blk = build_signing_block([(BLOCK_ID_V2, v2_val), (BLOCK_ID_V3, v3_val)])
        self.log("  Signing Block: %d 字节（v2+v3，内容摘要 %s…）"
                 % (len(blk), digest.hex()[:16]))
        return blk


def _to_der(cert):
    if isinstance(cert, (bytes, bytearray)):
        return bytes(cert)
    from cryptography.hazmat.primitives.serialization import Encoding
    return cert.public_bytes(Encoding.DER)


def _public_key_der(key):
    from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
    return key.public_key().public_bytes(Encoding.DER, PublicFormat.SubjectPublicKeyInfo)


def make_signer(repo_dir, log=print, password=None, wants_v2=True):
    """从仓库的 keystore/ 目录加载或生成签名密钥。"""
    import os
    from . import sign as v1mod
    keydir = os.path.join(repo_dir, "keystore")
    os.makedirs(keydir, exist_ok=True)
    pw = password or os.environ.get("KSSMA_SIGN_PASS") or "kssma-merger"
    (key, certs), path = v1mod.load_keystore_dir(keydir, pw)
    log("  签名密钥: %s（自签名，仅供本地安装）" % os.path.basename(path))
    return Signer(key, certs, pw, wants_v2=wants_v2, log=log)
