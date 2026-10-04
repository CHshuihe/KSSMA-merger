# -*- coding: utf-8 -*-
"""极简 DEX 解析：提取字符串表 / 方法 id / 类定义，用于比较两个 dex 的**实质差异**。

用途（回答「classes.dex 能不能做现场手术」）：
    两个 dex 的字节级差异可能高达 85%，但那可能只是"索引表膨胀导致全局偏移位移"。
    真正要回答的是：**实质内容改了哪些**。
    本工具把两边的字符串池与方法表列出来做集合比较。

用法：
    python dex-probe.py strings <a.dex> [b.dex]     字符串池比较
    python dex-probe.py header  <a.dex> [b.dex]     头部与各表计数
    python dex-probe.py method  <a.dex> [b.dex]     方法表比较（class::name）
    python dex-probe.py code    <a.dex> <类名> <方法名> [b.dex]   看某方法字节码是否变化
"""
import struct
import sys


class Dex:
    def __init__(self, data):
        self.buf = data
        (self.string_ids_size, self.string_ids_off) = struct.unpack_from("<II", data, 56)
        (self.type_ids_size, self.type_ids_off) = struct.unpack_from("<II", data, 64)
        (self.proto_ids_size, self.proto_ids_off) = struct.unpack_from("<II", data, 72)
        (self.field_ids_size, self.field_ids_off) = struct.unpack_from("<II", data, 80)
        (self.method_ids_size, self.method_ids_off) = struct.unpack_from("<II", data, 88)
        (self.class_defs_size, self.class_defs_off) = struct.unpack_from("<II", data, 96)
        (self.data_size, self.data_off) = struct.unpack_from("<II", data, 104)
        self.file_size, = struct.unpack_from("<I", data, 32)
        self.map_off, = struct.unpack_from("<I", data, 52)

    # ---- 字符串 ----
    def _uleb128(self, off):
        result = 0
        shift = 0
        while True:
            b = self.buf[off]
            off += 1
            result |= (b & 0x7F) << shift
            if not (b & 0x80):
                break
            shift += 7
        return result, off

    def string_at(self, idx):
        off = self.string_ids_off + idx * 4
        data_off, = struct.unpack_from("<I", self.buf, off)
        n, p = self._uleb128(data_off)
        end = self.buf.index(b"\x00", p)
        return self.buf[p:end].decode("utf-8", "replace")

    def strings(self):
        return [self.string_at(i) for i in range(self.string_ids_size)]

    # ---- 方法 ----
    def type_name(self, idx):
        if idx == 0xFFFFFFFF:
            return "?"
        sid, = struct.unpack_from("<I", self.buf, self.type_ids_off + idx * 4)
        return self.string_at(sid)

    def method_name(self, idx):
        """返回 (定义类, 方法名, 原型字符串)"""
        off = self.method_ids_off + idx * 4
        class_idx, proto_idx, name_idx = struct.unpack_from("<HHI", self.buf, off)
        return (self.type_name(class_idx), self.string_at(name_idx), proto_idx)

    def proto_shorty(self, proto_idx):
        off = self.proto_ids_off + proto_idx * 12
        shorty_idx, ret_idx, params_off = struct.unpack_from("<III", self.buf, off)
        return self.string_at(shorty_idx)

    def method_signatures(self):
        """返回 {定义类::方法名 原型: method_idx} 的集合（用于比较"有没有多出方法"）"""
        out = {}
        for i in range(self.method_ids_size):
            cls, name, proto = self.method_name(i)
            out["%s->%s%s" % (cls, name, self.proto_shorty(proto))] = i
        return out

    # ---- 类 ----
    def class_name(self, class_def_idx):
        off = self.class_defs_off + class_def_idx * 32
        class_idx, = struct.unpack_from("<I", self.buf, off)
        return self.type_name(class_idx)

    def find_method(self, class_name, method_name):
        """在 method_ids 里找 (class, name)，返回 method_idx 列表"""
        hits = []
        for i in range(self.method_ids_size):
            cls, name, _p = self.method_name(i)
            if cls == class_name and name == method_name:
                hits.append(i)
        return hits


def cmd_header(a, b=None):
    for tag, d in (("A", a), ("B", b)):
        if d is None:
            continue
        print("[%s] %d 字节  strings=%d types=%d protos=%d fields=%d methods=%d classes=%d data=0x%X"
              % (tag, d.file_size, d.string_ids_size, d.type_ids_size, d.proto_ids_size,
                 d.field_ids_size, d.method_ids_size, d.class_defs_size, d.data_off))


def cmd_strings(a, b):
    sa, sb = a.strings(), b.strings()
    print("A 字符串 %d 个 / B 字符串 %d 个" % (len(sa), len(sb)))
    A, B = set(sa), set(sb)
    onlyB = sorted(B - A)
    onlyA = sorted(A - B)
    print("  仅 B 有 %d 个；仅 A 有 %d 个" % (len(onlyB), len(onlyA)))
    print()
    print("=== 仅 B 有的字符串（合并器新增/改动的常量的证据）===")
    for s in onlyB:
        print("   %r" % s)
    if onlyA:
        print()
        print("=== 仅 A 有的字符串 ===")
        for s in onlyA[:40]:
            print("   %r" % s)


def cmd_method(a, b):
    ma, mb = a.method_signatures(), b.method_signatures()
    A, B = set(ma), set(mb)
    onlyB = sorted(B - A)
    onlyA = sorted(A - B)
    print("A 方法 %d 个 / B 方法 %d 个" % (len(ma), len(mb)))
    print("  仅 B 有 %d 个；仅 A 有 %d 个" % (len(onlyB), len(onlyA)))
    print()
    print("=== 仅在 B 里的方法（前 60）===")
    for s in onlyB[:60]:
        print("   %s" % s)
    if len(onlyB) > 60:
        print("   … 还有 %d 个" % (len(onlyB) - 60))
    if onlyA:
        print()
        print("=== 仅在 A 里的方法（前 30）===")
        for s in onlyA[:30]:
            print("   %s" % s)


def main():
    if len(sys.argv) < 3:
        raise SystemExit(__doc__)
    cmd = sys.argv[1]
    a = Dex(open(sys.argv[2], "rb").read())
    b = Dex(open(sys.argv[3], "rb").read()) if len(sys.argv) > 3 and cmd != "code" else None
    if cmd == "header":
        cmd_header(a, b)
    elif cmd == "strings":
        cmd_strings(a, b)
    elif cmd == "method":
        cmd_method(a, b)
    else:
        raise SystemExit("unknown command: %s" % cmd)


if __name__ == "__main__":
    main()
