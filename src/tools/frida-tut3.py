# -*- coding: utf-8 -*-
"""frida 诊断 v3：从 /proc/<pid>/maps 取 librooneyj 基址，attach 装 hook（M21）。

为什么不用 dlopen 的返回值：
    实测在 MuMu/Houdini 下 `android_dlopen_ext` 虽被调用且路径就是
    `.../lib/arm/librooneyj.so`，但**返回 0**（32 位 x86 宿主里 ARM 库不是常规映射）。
    所以基址改为**直接读 /proc/<pid>/maps**。

流程：
    1. 启动应用（普通 am start，不用 spawn，避免 Houdini 在 spawn 下行为不同）
    2. 轮询 /proc/<pid>/maps 等 librooneyj 出现，取其**可执行段**的起始地址作为基址
    3. frida attach(pid) 装 hook（业务 hook 用"基址 + 符号偏移"）
       —— 不需要 frida 自己能枚举到该模块
    4. 自动走 UI 到教程，收集输出

用法：
    python tools/frida-tut3.py
"""
import re
import subprocess
import threading
import time

import frida

# adb 路径与设备地址由 devenv 统一解析（可用环境变量 ADB / KSSMA_DEVICE 覆盖）
from devenv import ADB, DEVICE   # noqa: E402
DEV = DEVICE
PKG = "com.square_enix.million_cn"

OFF_EXISTS = 0x38F8CD
OFF_LOAD = 0x373835
OFF_NAME = 0x1EA729


def adb(*a, timeout=120):
    return subprocess.run([ADB, "-s", DEV] + list(a), capture_output=True,
                          text=True, errors="replace", timeout=timeout)


def app_pid():
    out = adb("shell", "pidof " + PKG).stdout.strip()
    return int(out.split()[0]) if out else None


def lib_base(pid):
    """从 maps 取 librooneyj 的可执行段起始地址（即 ELF 基址）。"""
    maps = adb("shell", "cat /proc/%d/maps" % pid).stdout
    best = None
    for line in maps.splitlines():
        if "rooneyj" not in line:
            continue
        m = re.match(r"([0-9a-f]+)-([0-9a-f]+)\s+(\S+)\s+([0-9a-f]+)", line)
        if not m:
            continue
        start = int(m.group(1), 16)
        perms = m.group(3)
        off = int(m.group(4), 16)
        # 取 offset==0 的段（ELF 头所在），其 start 就是基址
        if off == 0:
            return start
        if best is None or start < best:
            best = start
    return best


def make_js(base):
    return r"""
var BASE = ptr("%d");
function rstr(p) {
    if (!p || p.isNull()) return "<null>";
    try { var s = p.readCString(); return (s === null) ? "<unreadable>" : s; }
    catch (e) { return "<err>"; }
}
send({t:"info", m:"基址 = " + BASE});

Interceptor.attach(BASE.add(0x38F8CD), {
    onEnter: function (a) {
        var o = { t: "exists", a0: a[0].toString() };
        try { o.direct = rstr(a[0]); } catch (e) {}
        try { o.p0 = rstr(a[0].readPointer()); } catch (e) {}
        try { o.p4 = rstr(a[0].add(4).readPointer()); } catch (e) {}
        try { o.p8 = rstr(a[0].add(8).readPointer()); } catch (e) {}
        try { o.hex = hexdump(a[0], {length: 32, ansi: false}); } catch (e) {}
        send(o);
    }
});

Interceptor.attach(BASE.add(0x373835), {
    onEnter: function (a) {
        send({ t: "loadScript", idx: a[1].toInt32(), self: a[0].toString() });
    }
});

Interceptor.attach(BASE.add(0x1EA729), {
    onEnter: function (a) { this.sret = a[0]; this.self = a[1]; this.idx = a[2].toInt32(); },
    onLeave: function (r) {
        var o = { t: "getScriptName", idx: this.idx, ret: r.toString() };
        try { o.sret0 = rstr(this.sret.readPointer()); } catch (e) {}
        try { o.sret4 = rstr(this.sret.add(4).readPointer()); } catch (e) {}
        send(o);
    }
});
send({t:"info", m:"hooks installed"});
""" % base


def top_activity():
    out = adb("shell", "dumpsys activity activities 2>/dev/null | grep -m1 ResumedActivity").stdout
    m = re.search(r"([\w.]+/[\w.]+)", out)
    return m.group(1) if m else ""


def wait_for(substr, timeout=90):
    """等前台 Activity 变成含 substr 的（比死等定时可靠）。"""
    for _ in range(timeout):
        a = top_activity()
        if substr in a:
            return a
        time.sleep(1)
    return ""


def ui_flow():
    def tap(x, y, w):
        adb("shell", "input tap %d %d" % (x, y))
        time.sleep(w)

    print("    [ui] 等模式选择页")
    if not wait_for("ModeSelect", 90):
        print("    [ui] ** 未到模式选择页，当前: %s" % top_activity())
        return
    tap(960, 420, 6)                      # 继续游戏

    print("    [ui] 等服务器选择页")
    if not wait_for("WorldSelect", 60):
        print("    [ui] ** 未到服务器选择页，当前: %s" % top_activity())
        return
    tap(960, 545, 6)                      # 选服务器

    print("    [ui] 等登录页")
    if not wait_for("LoginActivity", 60):
        print("    [ui] ** 未到登录页，当前: %s" % top_activity())
        return
    tap(1432, 369, 2)
    adb("shell", "input text 'testpass123'")
    time.sleep(2)
    tap(960, 915, 3)

    print("    [ui] 等引擎 RooneyJActivity")
    wait_for("RooneyJActivity", 60)
    print("    [ui] 引擎已启动，继续观察 60 秒")
    for i in range(6):
        time.sleep(10)
        print("    [ui] +%ds 前台=%s" % ((i + 1) * 10, top_activity()))


def main():
    print("[1] 启动应用（普通 am start）")
    adb("shell", "am force-stop " + PKG)
    time.sleep(2)
    adb("shell", "monkey -p %s -c android.intent.category.LAUNCHER 1" % PKG)

    print("[2] 等 librooneyj 进 maps（最多 60 秒）")
    pid = base = None
    for i in range(60):
        time.sleep(1)
        pid = app_pid()
        if not pid:
            continue
        base = lib_base(pid)
        if base:
            print("    pid=%d  base=0x%X（第 %d 秒）" % (pid, base, i + 1))
            break
    if not base:
        print("    ** 未等到 librooneyj 加载 **")
        return

    print("[3] attach 并装 hook")
    dev = frida.get_device(DEV, timeout=10)
    session = dev.attach(pid)
    script = session.create_script(make_js(base))

    def on_message(m, d):
        if m.get("type") == "send":
            p = m["payload"]
            t = p.get("t")
            if t == "info":
                print("    [info] %s" % p.get("m"))
            elif t == "err":
                print("    [ERR ] %s" % p.get("m"))
            elif t == "exists":
                print("    [exists] a0=%s" % p.get("a0"))
                for k in ("direct", "p0", "p4", "p8"):
                    if k in p:
                        print("             %-7s = %r" % (k, p[k]))
                if p.get("hex"):
                    print(p["hex"])
            else:
                print("    [%s] %s" % (t, {k: v for k, v in p.items() if k != "t"}))
        elif m.get("type") == "error":
            print("    [frida error] %s" % (m.get("description") or m.get("stack")))

    script.on("message", on_message)
    script.load()

    print("[4] 自动走 UI 到教程")
    th = threading.Thread(target=ui_flow, daemon=True)
    th.start()
    th.join(timeout=160)
    print("[5] 再收集 20 秒")
    time.sleep(20)
    try:
        session.detach()
    except Exception:
        pass
    print("完成")


if __name__ == "__main__":
    main()
