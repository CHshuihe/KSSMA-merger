# -*- coding: utf-8 -*-
"""frida 诊断 v6：**按段映射**计算函数地址（M21 最终版）。

v5 的致命错误：
    在 MuMu/Houdini 下，librooneyj.so 的各段被映射到**彼此无关的地址**，
    不是常规的 base+vaddr。实测 maps：
        0c250000-0c43a000 r--p off=00000000   ← ELF 头（真基址）
        0c43a000-0c43b000 r-xp off=001ea000   ← vaddr 0x001EA000
        0c5c3000-0c5c4000 r-xp off=00373000   ← vaddr 0x00373000
        0c5df000-0c5e0000 r-xp off=0038f000   ← vaddr 0x0038F000
    所以必须：读 ELF program header 拿到 (vaddr, filesz)，
    在 maps 里找到 filesz/perms 匹配的段，再算
        addr = seg_start_in_maps + (target_vaddr - seg_vaddr)

本脚本自动完成上述匹配，然后装 hook。
"""
import re, struct, subprocess, sys, threading, time
import frida

# adb 路径与设备地址由 devenv 统一解析（可用环境变量 ADB / KSSMA_DEVICE 覆盖）
from devenv import ADB, DEVICE   # noqa: E402
DEV = DEVICE
PKG = "com.square_enix.million_cn"
SO_LOCAL = r"D:\MyFlie\AI\zcode\workspace\kssma\kssma_apk\build\apkwork\decoded\lib\armeabi\librooneyj.so"

TARGETS = {
    "res_exists": 0x38F8CD,
    "loadScript": 0x373835,
    "getScriptName": 0x1EA729,
}

def adb(*a, timeout=180):
    return subprocess.run([ADB, "-s", DEV] + list(a), capture_output=True,
                          text=True, errors="replace", timeout=timeout)

def app_pid():
    o = adb("shell", "pidof " + PKG).stdout.strip()
    return int(o.split()[0]) if o else None

def elf_load_segments(path):
    """返回 [(vaddr, filesz, flags)]（PT_LOAD）。"""
    b = open(path, "rb").read()
    e_phoff, = struct.unpack_from("<I", b, 0x1C)
    e_phentsize, e_phnum = struct.unpack_from("<HH", b, 0x2A)
    segs = []
    for i in range(e_phnum):
        o = e_phoff + i * e_phentsize
        p_type, p_offset, p_vaddr, p_paddr, p_filesz, p_memsz, p_flags, p_align = \
            struct.unpack_from("<IIIIIIII", b, o)
        if p_type == 1:
            segs.append((p_vaddr, p_filesz, p_flags))
    return segs

def rooneyj_maps(pid):
    out = adb("shell", "cat /proc/%d/maps" % pid).stdout
    rows = []
    for l in out.splitlines():
        if "rooneyj" not in l:
            continue
        m = re.match(r"([0-9a-f]+)-([0-9a-f]+)\s+(\S{4})\s+([0-9a-f]+)", l)
        if m:
            rows.append({
                "start": int(m.group(1), 16),
                "end": int(m.group(2), 16),
                "perms": m.group(3),
                "off": int(m.group(4), 16),
            })
    return rows

def resolve(segs, maps, target_vaddr):
    """把 ELF 里的 vaddr 映射到进程内的实际地址。"""
    # 找到包含 target 的 PT_LOAD
    seg = None
    for vaddr, filesz, flags in segs:
        if vaddr <= target_vaddr < vaddr + filesz:
            seg = (vaddr, filesz, flags)
            break
    if seg is None:
        return None
    vaddr, filesz, flags = seg
    # 在 maps 里找 off 接近该段文件偏移的映射（Houdini 下 off 常等于 vaddr）
    best = None
    for r in maps:
        # 该段的映射：r.off <= vaddr < r.off + (end-start) 大致成立
        if r["off"] <= vaddr < r["off"] + (r["end"] - r["start"]):
            cand = r["start"] + (target_vaddr - vaddr)
            if best is None:
                best = cand
    if best is not None:
        return best
    # 退化：off == vaddr 的映射
    for r in maps:
        if r["off"] == vaddr:
            return r["start"] + (target_vaddr - vaddr)
    return None

JS_TMPL = r"""
var T = %s;
function rstr(p) {
    if (!p || p.isNull()) return "<null>";
    try { var s = p.readCString(); return (s === null) ? "<unreadable>" : s; }
    catch (e) { return "<err>"; }
}
send({t:"info", m:"地址: " + JSON.stringify(T)});
function hook(name, addr, cb) {
    try {
        Interceptor.attach(ptr(addr), cb);
        send({t:"info", m:"hook " + name + " @ 0x" + addr.toString(16)});
    } catch (e) { send({t:"err", m:"hook " + name + " 失败: " + e}); }
}
hook("exists", T.exists, {
    onEnter: function (a) {
        var o = { t: "exists", a0: a[0].toString() };
        try { o.direct = rstr(a[0]); } catch (e) {}
        try { o.p0 = rstr(a[0].readPointer()); } catch (e) {}
        try { o.p4 = rstr(a[0].add(4).readPointer()); } catch (e) {}
        try { o.hex = hexdump(a[0], {length: 32, ansi: false}); } catch (e) {}
        send(o);
    }
});
hook("loadScript", T.load, {
    onEnter: function (a) {
        send({ t: "loadScript", idx: a[1].toInt32(), self: a[0].toString() });
    }
});
hook("getScriptName", T.name, {
    onEnter: function (a) { this.sret = a[0]; this.idx = a[2].toInt32(); },
    onLeave: function (r) {
        var o = { t: "getScriptName", idx: this.idx };
        try { o.sret0 = rstr(this.sret.readPointer()); } catch (e) {}
        try { o.sret4 = rstr(this.sret.add(4).readPointer()); } catch (e) {}
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

def top():
    o = adb("shell", "dumpsys activity activities 2>/dev/null | grep -m1 ResumedActivity").stdout
    m = re.search(r"([\w.]+/[\w.]+)", o)
    return m.group(1) if m else ""

def wait_for(sub, t=150):
    for _ in range(t):
        if sub in top(): return True
        time.sleep(1)
    return False

def ui_thread():
    def tap(x, y, w):
        adb("shell", "input tap %d %d" % (x, y)); time.sleep(w)
    print("    [ui] 等模式选择页", flush=True)
    if wait_for("ModeSelect", 180):
        print("    [ui] 继续游戏", flush=True); tap(960, 420, 6)
    if wait_for("WorldSelect", 60):
        print("    [ui] 选服务器", flush=True); tap(960, 545, 6)
    if wait_for("LoginActivity", 60):
        print("    [ui] 登录", flush=True)
        tap(1432, 369, 2)
        adb("shell", "input text 'testpass123'"); time.sleep(2)
        tap(960, 915, 3)
    print("    [ui] 等引擎", flush=True)
    wait_for("RooneyJActivity", 90)
    print("    [ui] 前台 = %s" % top(), flush=True)

def main():
    segs = elf_load_segments(SO_LOCAL)
    print("[1] ELF PT_LOAD 段:")
    for v, sz, fl in segs:
        print("    vaddr=0x%08X filesz=%8d flags=%d" % (v, sz, fl))

    print("[2] 冷启 + 并行轮询")
    adb("shell", "am force-stop " + PKG); time.sleep(2)
    adb("shell", "am start -n %s/com.test.enter.LogoActivity" % PKG); time.sleep(6)
    th = threading.Thread(target=ui_thread, daemon=True); th.start()

    dev = frida.get_device(DEV, timeout=10)
    session = attached = None
    t0 = time.time()
    while time.time() - t0 < 300:
        pid = app_pid()
        if pid:
            maps = rooneyj_maps(pid)
            if maps and session is None and pid != attached:
                addrs = {}
                for k, va in TARGETS.items():
                    a = resolve(segs, maps, va)
                    if a: addrs[k] = a
                print("    [hit] pid=%d 解析出 %d/%d 个地址（%.0f 秒）"
                      % (pid, len(addrs), len(TARGETS), time.time()-t0), flush=True)
                for k, a in addrs.items():
                    print("        %-14s vaddr=0x%X -> 0x%X" % (k, TARGETS[k], a), flush=True)
                if len(addrs) == len(TARGETS):
                    try:
                        session = dev.attach(pid)
                        sc = session.create_script(JS_TMPL % ("{exists:0x%X, load:0x%X, name:0x%X}"
                                                             % (addrs["res_exists"], addrs["loadScript"],
                                                                addrs["getScriptName"])))
                        sc.on("message", on_message)
                        sc.load()
                        attached = pid
                    except Exception as e:
                        print("    attach 失败: %s" % e, flush=True)
                        session = None
        time.sleep(0.3)

    print("[3] 收尾"); time.sleep(15)
    try:
        if session: session.detach()
    except Exception: pass
    print("完成", flush=True)

if __name__ == "__main__":
    main()
