# -*- coding: utf-8 -*-
"""用**特征字节**在进程内存里定位 loadScript 的真实运行时地址（M21）。

为什么需要：
    Houdini 把 librooneyj.so 的 .text 切成多个映射，maps 的 off 与 ELF 段头
    对不上，靠"基址+符号偏移"算出来的地址 hook 不到。
    → 改为：从 .so 里取函数开头的原始字节，在进程内存里全量搜索。

同时搜两种形态：
    A) 原始字节（b5 47 46 80 …）—— 若 ARM 代码按原样映射
    B) 半字交换后的字节（f0 46 47 b4 …）—— 若按交换形态映射

用法：
    python tools/frida-sigscan.py
"""
import re, struct, subprocess, sys, time
import frida

# adb 路径与设备地址由 devenv 统一解析（可用环境变量 ADB / KSSMA_DEVICE 覆盖）
from devenv import ADB, DEVICE   # noqa: E402
DEV = DEVICE
PKG = "com.square_enix.million_cn"
SO = r"D:\MyFlie\AI\zcode\workspace\kssma\kssma_apk\build\apkwork\decoded\lib\armeabi\librooneyj.so"

def adb(*a, timeout=180):
    return subprocess.run([ADB, "-s", DEV] + list(a), capture_output=True,
                          text=True, errors="replace", timeout=timeout)

def pid_():
    o = adb("shell", "pidof " + PKG).stdout.strip()
    return int(o.split()[0]) if o else None

def sigs():
    b = open(SO, "rb").read()
    out = {}
    # loadScript / res::exists / getScriptName 的文件偏移 = vaddr（首段 vaddr==0）
    for name, off, n in (("load", 0x373835, 12),
                         ("exists", 0x38F8CD, 10),
                         ("name", 0x1EA729, 10)):
        raw = b[off:off + n]
        sw = bytearray(raw)
        for i in range(0, len(sw) - 1, 2):
            sw[i], sw[i + 1] = sw[i + 1], sw[i]
        out[name] = {"raw": raw.hex(), "swapped": bytes(sw).hex()}
    return out

JS = r"""
var SIGS = %s;
var results = {};

function scan(sigHex, label) {
    var pat = [];
    for (var i = 0; i < sigHex.length; i += 2) pat.push(parseInt(sigHex.substr(i, 2), 16));
    var ranges = Process.enumerateRanges({protection: 'r-x', coalesce: true});
    var hits = [];
    for (var r = 0; r < ranges.length && hits.length < 8; r++) {
        try {
            var m = Memory.scanSync(ranges[r].base, ranges[r].size, pat.map(function(b){
                return ('0' + b.toString(16)).slice(-2);
            }).join(' '));
            for (var k = 0; k < m.length && hits.length < 8; k++) {
                hits.push(m[k].address.toString());
            }
        } catch (e) {}
    }
    results[label] = hits;
}

for (var name in SIGS) {
    scan(SIGS[name].raw, name + ":raw");
    scan(SIGS[name].swapped, name + ":swapped");
}
send({t: "scan", r: results});
"""

def main():
    p = pid_()
    if not p:
        print("应用未运行"); return
    print("pid =", p)
    s = sigs()
    print("签名:")
    for k, v in s.items():
        print("  %-8s raw=%s" % (k, v["raw"]))
        print("  %-8s swap=%s" % ("", v["swapped"]))

    dev = frida.get_device(DEV, timeout=10)
    sess = dev.attach(p)
    sc = sess.create_script(JS % (__import__("json").dumps(s)))
    got = {}
    def on_msg(m, d):
        if m.get("type") == "send":
            got.update(m["payload"])
        elif m.get("type") == "error":
            print("  frida error:", m.get("description"))
    sc.on("message", on_msg)
    sc.load()
    time.sleep(8)
    print()
    print("=== 扫描结果 ===")
    r = got.get("r", {})
    for k in sorted(r):
        hits = r[k]
        print("  %-16s %d 个命中 %s" % (k, len(hits), hits[:4]))
    sess.detach()

if __name__ == "__main__":
    main()
