# -*- coding: utf-8 -*-
"""frida 诊断 v4：**attach 到正在运行的引擎**，观察教程资源加载（M21）。

v3 的教训：用 `monkey` 启动时，app 可能**直接恢复到引擎 Activity**（跳过模式选择），
所以"等 ModeSelect"的流程会错过时机。v4 改为：
    1. 应用已经在引擎里（或先由外部脚本走到引擎）
    2. 从 /proc/<pid>/maps 取 librooneyj 基址
    3. attach 装 hook
    4. 触发一次教程加载：直接点主城的"探索"等，或让外面重登
    5. 收集输出

用法：
    python tools/frida-tut4.py [--relogin]
        --relogin : 装好 hook 后自动 force-stop + 重新走登录（触发教程）
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


def adb(*a, timeout=180):
    return subprocess.run([ADB, "-s", DEV] + list(a), capture_output=True,
                          text=True, errors="replace", timeout=timeout)


def app_pid():
    out = adb("shell", "pidof " + PKG).stdout.strip()
    return int(out.split()[0]) if out else None


def lib_base(pid):
    maps = adb("shell", "cat /proc/%d/maps" % pid).stdout
    best = None
    for line in maps.splitlines():
        if "rooneyj" not in line:
            continue
        m = re.match(r"([0-9a-f]+)-([0-9a-f]+)\s+(\S+)\s+([0-9a-f]+)", line)
        if not m:
            continue
        start = int(m.group(1), 16)
        off = int(m.group(4), 16)
        if off == 0:
            return start
        if best is None or start < best:
            best = start
    return best


JS_TMPL = r"""
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
"""


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


def main():
    force = "--force" in __import__("sys").argv
    dev = frida.get_device(DEV, timeout=10)

    # --force: 先用 Intent 直接起 LogoActivity，保证从模式选择开始
    if force:
        print("[0] 冷启到模式选择页")
        adb("shell", "am force-stop " + PKG)
        time.sleep(2)
        adb("shell", "am start -n %s/com.test.enter.LogoActivity" % PKG)
        time.sleep(15)

    print("[1] 找进程")
    pid = None
    for _ in range(120):
        pid = app_pid()
        if pid:
            break
        time.sleep(1)
    if not pid:
        print("    ** 应用未运行 **")
        return
    print("    pid =", pid)

    print("[2] 等 librooneyj 进 maps")
    base = None
    for i in range(240):
        base = lib_base(pid)
        if base:
            print("    base = 0x%X（第 %d 秒）" % (base, i + 1))
            break
        time.sleep(1)
    if not base:
        print("    ** 未加载 **")
        return

    print("[3] attach + 装 hook")
    session = dev.attach(pid)
    script = session.create_script(JS_TMPL % base)
    script.on("message", on_message)
    script.load()

    print("[4] 观察 100 秒（期间会自动走 UI 到教程）")

    def flow():
        def tap(x, y, w):
            adb("shell", "input tap %d %d" % (x, y))
            time.sleep(w)

        def top():
            o = adb("shell", "dumpsys activity activities 2>/dev/null | grep -m1 ResumedActivity").stdout
            m = re.search(r"([\w.]+/[\w.]+)", o)
            return m.group(1) if m else ""

        def wait(sub, t=60):
            for _ in range(t):
                if sub in top():
                    return True
                time.sleep(1)
            return False

        time.sleep(3)
        print("    [ui] 等模式选择页（冷启需等资源释放）")
        if wait("ModeSelect", 120):
            print("    [ui] 模式选择 → 继续游戏")
            tap(960, 420, 6)
        if wait("WorldSelect", 40):
            print("    [ui] 服务器选择")
            tap(960, 545, 6)
        if wait("LoginActivity", 40):
            print("    [ui] 登录页")
            tap(1432, 369, 2)
            adb("shell", "input text 'testpass123'")
            time.sleep(2)
            tap(960, 915, 3)
        print("    [ui] 等引擎")
        wait("RooneyJActivity", 60)
        print("    [ui] 引擎启动，前台=%s" % top())

    th = threading.Thread(target=flow, daemon=True)
    th.start()
    th.join(timeout=120)
    print("[5] 再收集 25 秒")
    time.sleep(25)
    try:
        session.detach()
    except Exception:
        pass
    print("完成")


if __name__ == "__main__":
    main()
