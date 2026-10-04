# -*- coding: utf-8 -*-
"""attach 到**当前正在跑的**进程，按段映射装 hook，抓 loadScript/res::exists 真值。

用 v6 的段映射逻辑（Houdini 下各段映射地址互不相关，必须按段换算）。
"""
import re, struct, subprocess, time
import frida

# adb 路径与设备地址由 devenv 统一解析（可用环境变量 ADB / KSSMA_DEVICE 覆盖）
from devenv import ADB, DEVICE   # noqa: E402
DEV = DEVICE
PKG = "com.square_enix.million_cn"
SO = r"D:\MyFlie\AI\zcode\workspace\kssma\kssma_apk\build\apkwork\decoded\lib\armeabi\librooneyj.so"
TARGETS = {"res_exists": 0x38F8CD, "loadScript": 0x373835, "getScriptName": 0x1EA729}

def adb(*a, timeout=120):
    return subprocess.run([ADB, "-s", DEV] + list(a), capture_output=True,
                          text=True, errors="replace", timeout=timeout)

def app_pid():
    o = adb("shell", "pidof " + PKG).stdout.strip()
    return int(o.split()[0]) if o else None

def segs():
    b = open(SO, "rb").read()
    e_phoff, = struct.unpack_from("<I", b, 0x1C)
    e_phentsize, e_phnum = struct.unpack_from("<HH", b, 0x2A)
    out = []
    for i in range(e_phnum):
        o = e_phoff + i * e_phentsize
        t, off, va, pa, fsz, msz, fl, al = struct.unpack_from("<IIIIIIII", b, o)
        if t == 1:
            out.append((va, fsz, fl))
    return out

def maps(pid):
    rows = []
    for l in adb("shell", "cat /proc/%d/maps" % pid).stdout.splitlines():
        if "rooneyj" not in l: continue
        m = re.match(r"([0-9a-f]+)-([0-9a-f]+)\s+(\S{4})\s+([0-9a-f]+)", l)
        if m:
            rows.append({"s": int(m.group(1),16), "e": int(m.group(2),16),
                         "p": m.group(3), "o": int(m.group(4),16)})
    return rows

def resolve(se, mp, va):
    for v, fsz, fl in se:
        if v <= va < v + fsz:
            # 找该段的映射：满足 r.o <= v < r.o + (r.e - r.s)
            best = None
            for r in mp:
                span = r["e"] - r["s"]
                if r["o"] <= v < r["o"] + span:
                    cand = r["s"] + (va - v)
                    if best is None: best = cand
            if best is not None: return best
            for r in mp:
                if r["o"] == v: return r["s"] + (va - v)
    return None

JS = r"""
var T = %s;
function rstr(p) {
    if (!p || p.isNull()) return "<null>";
    try { var s = p.readCString(); return (s === null) ? "<unreadable>" : s; }
    catch (e) { return "<err>"; }
}
send({t:"info", m:"地址 " + JSON.stringify(T)});
function hk(n, a, cb) {
    try { Interceptor.attach(ptr(a), cb); send({t:"info", m:"ok " + n + " @0x" + a.toString(16)}); }
    catch (e) { send({t:"err", m:n + ": " + e}); }
}
hk("exists", T.exists, { onEnter: function (a) {
    var o = { t:"exists", a0:a[0].toString() };
    try { o.direct = rstr(a[0]); } catch(e){}
    try { o.p0 = rstr(a[0].readPointer()); } catch(e){}
    try { o.p4 = rstr(a[0].add(4).readPointer()); } catch(e){}
    try { o.hex = hexdump(a[0], {length:48, ansi:false}); } catch(e){}
    send(o);
}});
hk("load", T.load, { onEnter: function (a) {
    var o = { t:"loadScript", idx:a[1].toInt32(), this_:a[0].toString() };
    try { o.m0 = a[0].readPointer().toString(); } catch(e){}
    try { o.m4 = a[0].add(4).readPointer().toString(); } catch(e){}
    try { o.m8 = a[0].add(8).readPointer().toString(); } catch(e){}
    send(o);
}});
hk("name", T.name, {
    onEnter: function (a) { this.sret=a[0]; this.idx=a[2].toInt32(); },
    onLeave: function (r) {
        var o = { t:"getScriptName", idx:this.idx };
        try { o.sret0 = rstr(this.sret.readPointer()); } catch(e){}
        try { o.sret4 = rstr(this.sret.add(4).readPointer()); } catch(e){}
        send(o);
    }
});
send({t:"info", m:"hooks installed"});
"""

def on_message(m, d):
    if m.get("type") == "send":
        p = m["payload"]
        if p.get("t") == "info": print("    [info] %s" % p.get("m"), flush=True)
        elif p.get("t") == "err": print("    [ERR ] %s" % p.get("m"), flush=True)
        else:
            print("    [%s] %s" % (p.get("t"), {k:v for k,v in p.items() if k!="t"}), flush=True)
    elif m.get("type") == "error":
        print("    [frida error] %s" % (m.get("description") or m.get("stack")), flush=True)

def main():
    pid = app_pid()
    if not pid:
        print("应用未运行"); return
    print("pid =", pid)
    se, mp = segs(), maps(pid)
    print("maps 段数:", len(mp))
    addrs = {}
    for k, va in TARGETS.items():
        a = resolve(se, mp, va)
        if a:
            addrs[k] = a
            print("  %-14s vaddr=0x%08X -> 0x%08X" % (k, va, a))
    if len(addrs) != len(TARGETS):
        print("** 地址解析不全 **"); return
    dev = frida.get_device(DEV, timeout=10)
    s = dev.attach(pid)
    sc = s.create_script(JS % ("{exists:0x%X, load:0x%X, name:0x%X}"
                               % (addrs["res_exists"], addrs["loadScript"], addrs["getScriptName"])))
    sc.on("message", on_message)
    sc.load()
    print("观察 40 秒…")
    time.sleep(40)
    s.detach()
    print("完成")

if __name__ == "__main__":
    main()
