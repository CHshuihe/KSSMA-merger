# -*- coding: utf-8 -*-
"""frida 探测：确认目标进程里 frida 能看到哪些模块（M21 排障用）。

背景：MuMu 是 x86_64 设备，但应用跑在 **app_process32（32 位 x86）**，
`librooneyj.so` 由 Houdini 翻译执行。spawn 时 frida 可能选了 64 位进程，
于是看不到 ARM 库。本脚本用来确认现状。

用法：
    python tools/frida-probe.py [--spawn|--attach]
"""
import subprocess
import sys
import time

import frida

# adb 路径与设备地址由 devenv 统一解析（可用环境变量 ADB / KSSMA_DEVICE 覆盖）
from devenv import ADB, DEVICE   # noqa: E402
DEV = DEVICE
PKG = "com.square_enix.million_cn"
SERVER = "/data/local/tmp/frida-server"

JS = r"""
var out = [];
var mods = Process.enumerateModules();
out.push("arch=" + Process.arch + " pointerSize=" + Process.pointerSize);
out.push("module count=" + mods.length);
for (var i = 0; i < mods.length; i++) {
    if (/rooney|houdini|arm|emu/i.test(mods[i].name)) {
        out.push("  HIT " + mods[i].name + " @" + mods[i].base);
    }
}
// 前 25 个模块名
for (var i = 0; i < Math.min(25, mods.length); i++) {
    out.push("  " + mods[i].name + " @" + mods[i].base);
}
send(out.join("\n"));
"""


def adb(*a, timeout=90):
    return subprocess.run([ADB, "-s", DEV] + list(a), capture_output=True,
                          text=True, errors="replace", timeout=timeout)


def main():
    mode = "attach" if "--attach" in sys.argv else "spawn"
    print("[1] 启动 frida-server")
    adb("shell", "pkill -f frida-server")
    time.sleep(1)
    srv = subprocess.Popen([ADB, "-s", DEV, "shell", SERVER],
                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    time.sleep(8)

    dev = frida.get_device(DEV, timeout=10)
    print("[2] 模式:", mode)

    if mode == "spawn":
        adb("shell", "am force-stop " + PKG)
        time.sleep(2)
        pid = dev.spawn([PKG])
        print("    spawn pid =", pid)
        # spawn 后先看一次（模块还没加载）
        session = dev.attach(pid)
        s = session.create_script(JS)
        got = {}
        s.on("message", lambda m, d: got.update({"v": m.get("payload")}))
        s.load()
        time.sleep(1)
        print("--- spawn 时刻的模块 ---")
        print(got.get("v"))
        session.detach()

        print("[3] resume + 等 45 秒让引擎加载")
        dev.resume(pid)
        time.sleep(45)
        session = dev.attach(pid)
        s = session.create_script(JS)
        got = {}
        s.on("message", lambda m, d: got.update({"v": m.get("payload")}))
        s.load()
        time.sleep(1)
        print("--- 45 秒后的模块 ---")
        print(got.get("v"))
        session.detach()
    else:
        adb("shell", "am force-stop " + PKG)
        time.sleep(2)
        adb("shell", "monkey -p %s -c android.intent.category.LAUNCHER 1" % PKG)
        print("    等 40 秒")
        time.sleep(40)
        pidtxt = adb("shell", "pidof " + PKG).stdout.strip()
        print("    pidof:", pidtxt or "(空)")
        if not pidtxt:
            print("    ** 进程不在，无法 attach **")
            srv.terminate()
            return
        # 32 位进程：frida 按名字找不到，必须用 PID
        pid = int(pidtxt.split()[0])
        print("    attach pid =", pid)
        session = dev.attach(pid)
        s = session.create_script(JS)
        got = {}
        s.on("message", lambda m, d: got.update({"v": m.get("payload")}))
        s.load()
        time.sleep(1)
        print("--- attach 到的模块 ---")
        print(got.get("v"))
        session.detach()

    srv.terminate()


if __name__ == "__main__":
    main()
