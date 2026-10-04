# -*- coding: utf-8 -*-
"""ZIP 读取与**忠实施重建**（KSSMA Merger 核心）。

为什么自己写而不用 zipfile 写：
    1. **复用压缩流**：原 APK 里绝大多数条目是 STORED、其余是已经压好的 DEFLATED。
       重新压缩既慢又可能与官方产物不一致。我们要做的是"搬运原始压缩字节"。
    2. **4 字节对齐**：Android 要求 STORED 条目数据起始偏移 % 4 == 0。
    3. **可控性**：v2/v3 签名需要在写完 entries 之后拿到精确字节区间。

设计要点：
    - `ZipReader` 只读中央目录；取条目数据时按需 seek，**不整包读入内存**
    - 数据来源统一抽象为 `RawSource`：提供 `crc / file_size / comp_size / stream()`
      —— 于是"搬运"和"新建"在 writer 里是同一套代码
    - STORED 条目的 crc 直接沿用源值，**不做逐字节重算**（省一遍 IO，且恒等于源）
"""
import hashlib
import os
import struct
import zlib

# 让输出可复现：固定为 1980-01-01（DOS 时间戳最小值）
DOS_EPOCH = (0x0021, 0x0021)          # (date, time)
CHUNK = 1 << 20


class ZipEntry:
    """源 zip 里的一个条目（中央目录记录）。"""

    __slots__ = ("name", "method", "crc", "comp_size", "file_size",
                 "local_header_off", "data_off", "flags", "date_time",
                 "external_attr")

    def __init__(self, **kw):
        for k in self.__slots__:
            setattr(self, k, kw.get(k))

    @property
    def is_dir(self):
        return self.name.endswith("/")

    def __repr__(self):
        return "<ZipEntry %s method=%d %d->%d>" % (
            self.name, self.method, self.file_size, self.comp_size)


class ZipReader:
    def __init__(self, path):
        self.path = path
        self.size = os.path.getsize(path)
        self.entries = []
        self.by_name = {}
        self.comment = b""
        self._fh = open(path, "rb")
        try:
            self._read_central_directory()
        except Exception:
            self._fh.close()
            raise

    def close(self):
        if self._fh and not self._fh.closed:
            self._fh.close()

    def __enter__(self):
        return self

    def __exit__(self, *a):
        self.close()

    # ── 解析 ──────────────────────────────────────────
    def _read_central_directory(self):
        fh = self._fh
        tail = min(self.size, 66000)
        fh.seek(self.size - tail)
        buf = fh.read(tail)
        pos = buf.rfind(b"PK\x05\x06")
        if pos < 0:
            raise ValueError("不是有效的 zip（找不到 EOCD）: %s" % self.path)
        (_sig, _d1, _d2, _de, total, cd_size, cd_off, cmt_len) = \
            struct.unpack_from("<IHHHHIIH", buf, pos)
        self.comment = buf[pos + 22:pos + 22 + cmt_len]
        if total == 0xFFFF or cd_off == 0xFFFFFFFF or cd_size == 0xFFFFFFFF:
            raise ValueError("暂不支持 ZIP64 中央目录: %s" % self.path)
        if cd_off + cd_size > self.size:
            raise ValueError("中央目录越界（文件可能被截断）: %s" % self.path)

        fh.seek(cd_off)
        cd = fh.read(cd_size)
        p = 0
        for _ in range(total):
            if cd[p:p + 4] != b"PK\x01\x02":
                raise ValueError("中央目录项签名错误 @%d" % (cd_off + p))
            # 中央目录项固定头 46 字节：
            #   sig(4) ver_made(2) ver_need(2) flags(2) method(2) time(2) date(2)
            #   crc(4) comp(4) size(4) namelen(2) extralen(2) cmtlen(2)
            #   disk(2) intattr(2) extattr(4) lho(4)
            (_sig, _vm, _vn, flags, method, mtime, mdate, crc, comp_size, file_size,
             name_len, extra_len, cmt_len2, _dsk, _ia, ext_attr, lho) = \
                struct.unpack_from("<IHHHHHHIIIHHHHHII", cd, p)
            name = cd[p + 46:p + 46 + name_len].decode("utf-8", "replace")
            extra = cd[p + 46 + name_len:p + 46 + name_len + extra_len]
            if comp_size == 0xFFFFFFFF or file_size == 0xFFFFFFFF or lho == 0xFFFFFFFF:
                comp_size, file_size, lho = _zip64_values(extra, comp_size, file_size, lho)
            e = ZipEntry(name=name, method=method, crc=crc, comp_size=comp_size,
                         file_size=file_size, local_header_off=lho, data_off=None,
                         flags=flags, date_time=(mdate, mtime), external_attr=ext_attr)
            self.entries.append(e)
            self.by_name[name] = e
            p += 46 + name_len + extra_len + cmt_len2

    def data_offset(self, e):
        """条目**压缩数据**在文件中的偏移（解析 local file header）。"""
        if e.data_off is None:
            self._fh.seek(e.local_header_off)
            head = self._fh.read(30)
            if len(head) < 30 or head[:4] != b"PK\x03\x04":
                raise ValueError("local header 无效: %s @%d" % (e.name, e.local_header_off))
            name_len, extra_len = struct.unpack_from("<HH", head, 26)
            e.data_off = e.local_header_off + 30 + name_len + extra_len
        return e.data_off

    def read_raw(self, e_or_name):
        e = self.by_name[e_or_name] if isinstance(e_or_name, str) else e_or_name
        return self._read_raw(e)

    def _read_raw(self, e):
        off = self.data_offset(e)
        self._fh.seek(off)
        return self._fh.read(e.comp_size)

    def read(self, name):
        """读取条目解压后的内容（仅小条目）。"""
        e = self.by_name[name]
        raw = self._read_raw(e)
        if e.method == 0:
            return raw
        if e.method == 8:
            return zlib.decompress(raw, -15)
        raise ValueError("不支持的压缩方式 %d: %s" % (e.method, name))

    def stream_raw(self, e, chunk=CHUNK):
        """流式产出条目原始压缩字节。"""
        off = self.data_offset(e)
        self._fh.seek(off)
        left = e.comp_size
        while left > 0:
            b = self._fh.read(min(chunk, left))
            if not b:
                break
            left -= len(b)
            yield b


def _zip64_values(extra, comp, fsize, lho):
    p = 0
    while p + 4 <= len(extra):
        hid, hsz = struct.unpack_from("<HH", extra, p)
        body = extra[p + 4:p + 4 + hsz]
        if hid == 0x0001:
            q = 0
            if fsize == 0xFFFFFFFF:
                fsize, = struct.unpack_from("<Q", body, q); q += 8
            if comp == 0xFFFFFFFF:
                comp, = struct.unpack_from("<Q", body, q); q += 8
            if lho == 0xFFFFFFFF:
                lho, = struct.unpack_from("<Q", body, q); q += 8
        p += 4 + hsz
    return comp, fsize, lho


# ── 数据来源：统一提供 crc / file_size / comp_size / stream() ──

class RawSource:
    """基类：产出**压缩后**字节流，并给出三项元数据。"""

    def __init__(self, crc, file_size, comp_size):
        self.crc = crc
        self.file_size = file_size
        self.comp_size = comp_size

    def stream(self, chunk=CHUNK):        # pragma: no cover - 接口
        raise NotImplementedError


class CopySource(RawSource):
    """搬运源 zip 里某个条目的压缩字节（元数据直接沿用）。"""

    def __init__(self, reader, entry):
        super().__init__(entry.crc, entry.file_size, entry.comp_size)
        self.reader = reader
        self.entry = entry
        self.sha256 = None            # 流式搬运时无法顺手算（压缩数据），按需回读

    def stream(self, chunk=CHUNK):
        return self.reader.stream_raw(self.entry, chunk)


class BytesSource(RawSource):
    """给定解压内容，按指定方式压缩；元数据在构造时算好（小文件）。"""

    def __init__(self, data, method=0, level=6):
        self.data = data
        self.method = method
        self.level = level
        self._raw = None
        super().__init__(zlib.crc32(data) & 0xFFFFFFFF, len(data), None)
        # 顺带算好明文 SHA-256 —— 签名（MANIFEST.MF）需要，避免二次 IO
        self.sha256 = hashlib.sha256(data).hexdigest()
        if method == 0:
            self._raw = data
            self.comp_size = len(data)
        else:
            co = zlib.compressobj(level, zlib.DEFLATED, -15)
            self._raw = co.compress(data) + co.flush()
            self.comp_size = len(self._raw)

    def stream(self, chunk=CHUNK):
        d = self._raw
        for i in range(0, len(d), chunk):
            yield d[i:i + chunk]


class StreamedDeflate:
    """把"解压内容的分块迭代器"流式压缩（大文件用；需两遍：先算 size）。

    使用方式：先 `prepare()` 走一遍拿到 crc/size，再 `stream()` 输出。
    由于大文件只用于 .so（4.3MB），这里允许常驻内存，简化实现。
    """

    def __init__(self, chunks_factory, method=8, level=6):
        object.__setattr__(self, "chunks_factory", chunks_factory)
        object.__setattr__(self, "method", method)
        object.__setattr__(self, "level", level)
        data = b"".join(chunks_factory())
        object.__setattr__(self, "source", BytesSource(data, method, level))

    def __getattr__(self, k):
        # 只在 source 已存在时才代理，避免 __init__ 期间的递归
        src = self.__dict__.get("source")
        if src is None:
            raise AttributeError(k)
        return getattr(src, k)


# ── 待写条目 ──────────────────────────────────────────

class WriteEntry:
    def __init__(self, name, source, method, date_time=DOS_EPOCH, external_attr=0):
        self.name = name
        self.source = source          # RawSource
        self.method = method
        self.date_time = date_time
        self.external_attr = external_attr


# ── writer ──────────────────────────────────────────

class ApkWriter:
    """流式写 zip；STORED 条目 4 字节对齐；记录条目偏移供 v2 签名使用。"""

    def __init__(self, out_path):
        self.out_path = out_path
        self.fh = open(out_path, "wb")
        self.offset = 0
        self.records = []       # 每个写出的条目：名称/偏移/尺寸/crc
        self._count = 0

    def _write(self, b):
        self.fh.write(b)
        self.offset += len(b)

    def _pad_to_4(self):
        pad = (-self.offset) % 4
        if pad:
            self._write(b"\x00" * pad)

    def add(self, e):
        name_bytes = e.name.encode("utf-8")
        src = e.source
        crc, fsize, csize = src.crc, src.file_size, src.comp_size
        if crc is None or fsize is None or csize is None:
            raise ValueError("条目 %s 的元数据不完整" % e.name)

        lho = self.offset
        self._write(struct.pack("<IHHHHHIIIHH", 0x04034B50, 20, 0, e.method,
                                e.date_time[1], e.date_time[0],
                                crc, csize, fsize, len(name_bytes), 0))
        self._write(name_bytes)
        data_off = self.offset
        for chunk in src.stream():
            self._write(chunk)
        if e.method == 0:
            self._pad_to_4()

        rec = {"name": e.name, "method": e.method, "crc": crc,
               "comp_size": csize, "file_size": fsize,
               "local_header_off": lho, "data_off": data_off,
               "date_time": e.date_time, "external_attr": e.external_attr,
               "sha256": getattr(src, "sha256", None)}
        self.records.append(rec)
        self._count += 1
        return rec

    def add_directory(self, name):
        if not name.endswith("/"):
            name += "/"
        return self.add(WriteEntry(name, BytesSource(b"", 0), 0, external_attr=0x41ED0010))

    def read_entry(self, name):
        """从**已写出的**输出文件回读某条目的明文内容（仅小条目/兜底用）。"""
        rec = next((r for r in self.records if r["name"] == name), None)
        if rec is None:
            raise KeyError(name)
        with open(self.out_path, "rb") as f:
            f.seek(rec["data_off"])
            raw = f.read(rec["comp_size"])
        if rec["method"] == 0:
            return raw
        if rec["method"] == 8:
            return zlib.decompress(raw, -15)
        raise ValueError("不支持的压缩方式 %d: %s" % (rec["method"], name))

    # ── v2/v3 签名支持：写 CD 之前把 Signing Block 插进去 ──
    def _build_central_directory(self, cd_off):
        """产出中央目录的完整字节（不改文件位置）。"""
        buf = bytearray()
        for r in self.records:
            nb = r["name"].encode("utf-8")
            buf += struct.pack(
                "<IHHHHHHIIIHHHHHII", 0x02014B50, 20, 20, 0, r["method"],
                r["date_time"][1], r["date_time"][0],
                r["crc"], r["comp_size"], r["file_size"],
                len(nb), 0, 0, 0, 0, r["external_attr"], r["local_header_off"])
            buf += nb
        return bytes(buf)

    def _build_eocd(self, cd_off, cd_size, comment=b""):
        return struct.pack("<IHHHHIIH", 0x06054B50, 0, 0,
                           len(self.records), len(self.records),
                           cd_size, cd_off, len(comment)) + comment

    def write_bytes(self, b):
        """把已算好的字节写入输出（供 Signing Block 使用）。"""
        self._write(b)

    def close(self, comment=b"", signing_block=None):
        """收尾。

        `signing_block` 非 None 时按规范插入 Signing Block：
            条目数据 → [4 字节对齐填充] → Signing Block → CD → EOCD

        关键点（踩过的坑）：
            Signing Block 的内容/长度依赖 CD/EOCD 的字节，而 CD 的最终偏移
            = 块首 + 块长。**但块长与 cd_off 的数值无关**（cd_off 只是 EOCD 里
            一个 4 字节字段，值的不同不改变长度）。所以：
              1. 用占位 cd_off 产出 CD/EOCD，得到块长
              2. 真实 cd_off = 对齐后块首 + 块长
              3. **用真实 cd_off 重新产出 EOCD**（长度不变 ⇒ 块长不变 ⇒ 不循环）
              4. 写出：填充 → 块 → CD → EOCD
            早期版本漏了第 3 步，导致 EOCD 里的 cd_off 是错的（4776 vs 实际 7786），
            整个 zip 因此不可读。
        """
        if signing_block is None:
            cd_off = self.offset
            cd = self._build_central_directory(cd_off)
            self._write(cd)
            cd_size = len(cd)
            self._write(self._build_eocd(cd_off, cd_size, comment))
        else:
            # 块前可能需要填充到 4 字节对齐（v1 的 META-INF 条目会打乱对齐）。
            # 关键：填充量必须**一次算定**并传给 build_block 用于摘要，
            # 否则块首会随运行漂移，摘要与解析都不稳定。
            aligned = self.offset + ((-self.offset) % 4)
            pad = aligned - self.offset

            # 第 1 步：占位 cd_off 只为确定块长（cd_off 的数值不影响块长度）
            cd_probe = self._build_central_directory(aligned)
            eocd_probe = self._build_eocd(aligned, len(cd_probe), comment)
            blk = signing_block(self, cd_probe, eocd_probe, aligned)
            blen = len(blk)
            if blen % 4 != 0:
                raise ValueError(
                    "Signing Block 长度 %d 不是 4 的倍数，CD 会失去 4 字节对齐" % blen)

            # 第 2 步：真实 cd_off
            cd_off = aligned + blen
            if cd_off % 4 != 0:                            # pragma: no cover
                raise AssertionError("中央目录偏移 %d 未 4 字节对齐" % cd_off)

            # 第 3 步：用真实 cd_off 重建 CD/EOCD（长度不变），并用最终 EOCD 重建块
            cd = self._build_central_directory(cd_off)
            eocd = self._build_eocd(cd_off, len(cd), comment)
            if len(cd) != len(cd_probe) or len(eocd) != len(eocd_probe):
                raise AssertionError("重建 CD/EOCD 改变了长度，块长会失准")
            blk = signing_block(self, cd, eocd, aligned)
            if len(blk) != blen:                           # pragma: no cover
                raise AssertionError("重建 Signing Block 改变了长度（%d -> %d）"
                                     % (blen, len(blk)))

            # 第 4 步：写（填充 → 块 → CD → EOCD）
            if pad:
                self._write(b"\x00" * pad)
            if self.offset != aligned:                     # pragma: no cover
                raise AssertionError("填充后偏移应为 %d，实际 %d" % (aligned, self.offset))
            self._write(blk)
            if self.offset != cd_off:                      # pragma: no cover
                raise AssertionError("写入块后偏移应为 %d，实际 %d" % (cd_off, self.offset))
            self._write(cd)
            cd_size = len(cd)
            self._write(eocd)
        self.fh.flush()
        self.fh.close()
        return {"cd_off": cd_off, "cd_size": cd_size,
                "eocd_off": cd_off + cd_size, "entries": len(self.records)}
