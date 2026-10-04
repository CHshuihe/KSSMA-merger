# -*- coding: utf-8 -*-
"""frida 诊断：截获教程脚本加载时客户端真正查找的资源名（M21）。

背景：
    教程进不去 —— 客户端在 `rooney::res::exists(String)` 里 native 崩溃，
    但不知道它查的是什么名字。黑盒试 XML 字段名已多轮不收敛（D2 合成那次也是），
    所以改用运行时插桩拿真值。

为什么做成"全自动一条龙"：
    MuMu 的 toybox **没有 nohup/setsid**，adb shell 一退 frida-server 就被带走
    （实测反复变成僵尸进程）。所以必须在**同一个 Python 进程**里：
      1. subprocess 起 `adb shell frida-server`（保持 shell 存活）
      2. 等 server 就绪
      3. frida spawn 应用 + 装 hook
      4. 用 adb 自动走 UI（模式选择 → 服务器 → 登录）
      5. 收集 hook 输出

用法：
    python tools/frida-tut.py [--keep]     # --keep 时不自动走 UI，只等
"""
import subprocess
import sys
import threading
import time

import frida

# adb 路径与设备地址由 devenv 统一解析（可用环境变量 ADB / KSSMA_DEVICE 覆盖）
from devenv import ADB, DEVICE   # noqa: E402
DEV = DEVICE
PKG = "com.square_enix.million_cn"
SERVER = "/data/local/tmp/frida-server"

JS = r"""
var MOD = "librooneyj.so";

function install(base) {
    send({t:"info", m:"base=" + base});

    function rstr(p) {
        if (!p || p.isNull()) return "<null>";
        try { var s = p.readCString(); return (s === null) ? "<unreadable>" : s; }
        catch (e) { return "<err>"; }
    }

    Interceptor.attach(base.add(0x38F8CD), {      // rooney::res::exists(String)
        onEnter: function (a) {
            var o = { t: "exists", a0: a[0].toString() };
            try { o.direct = rstr(a[0]); } catch (e) {}
            try { o.p0 = rstr(a[0].readPointer()); } catch (e) {}
            try { o.p4 = rstr(a[0].add(4).readPointer()); } catch (e) {}
            try { o.p8 = rstr(a[0].add(8).readPointer()); } catch (e) {}
            // 把 a0 前后 64 字节也 dump 出来，便于判断 String 的真实布局
            try {
                o.hex = hexdump(a[0], {length: 48, ansi: false});
            } catch (e) {}
            send(o);
        }
    });

    Interceptor.attach(base.add(0x373835), {      // _Tutorial::loadScript(int)
        onEnter: function (a) {
            send({ t: "loadScript", idx: a[1].toInt32(), self: a[0].toString() });
        }
    });

    Interceptor.attach(base.add(0x1EA729), {      // _TutorialModel::getScriptName(int)
        onEnter: function (a) { this.sret = a[0]; this.self = a[1]; this.idx = a[2].toInt32(); },
        onLeave: function (r) {
            var o = { t: "getScriptName", idx: this.idx, ret: r.toString() };
            try { o.sret0 = rstr(this.sret.readPointer()); } catch (e) {}
            try { o.sret4 = rstr(this.sret.add(4).readPointer()); } catch (e) {}
            try { o.retStr = rstr(r); } catch (e) {}
            send(o);
        }
    });

    send({t:"info", m:"hooks installed"});
}

function findMod() {
    var mods = Process.enumerateModules();
    for (var i = 0; i < mods.length; i++) {
        if (mods[i].name === MOD) return mods[i].base;
    }
    return null;
}

// librooneyj.so 是延迟加载的（引擎起来才 dlopen）。
// 实测 Process.attachModuleObserver 在这个 Houdini 环境里不触发，改为**轮询**。
var ticks = 0;
var timer = setInterval(function () {
    ticks++;
    var b = findMod();
    if (b) {
        clearInterval(timer);
        install(b);
        return;
    }
    if (ticks % 25 === 0) {
        send({t:"info", m:"仍在等 " + MOD + "（" + (ticks/5).toFixed(0) + " 秒）"});
    }
    if (ticks > 600) {           // 120 秒
        clearInterval(timer);
        send({t:"err", m:"超时：未等到 " + MOD});
    }
}, 200);
"""


def adb(*args, timeout=60):
    return subprocess.run([ADB, "-s", DEV] + list(args),
                          capture_output=True, text=True, timeout=timeout)


def start_server():
    """在后台线程里保持 `adb shell frida-server` 存活。"""
    proc = subprocess.Popen([ADB, "-s", DEV, "shell", SERVER],
                            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    return proc


def ui_flow():
    """自动走：模式选择(继续游戏) → 服务器选择 → 登录。"""
    def tap(x, y, wait):
        adb("shell", "input tap %d %d" % (x, y))
        time.sleep(wait)
    time.sleep(38)                       # 等资源释放 + 到模式选择
    tap(960, 420, 10)                    # 继续游戏
    tap(960, 545, 12)                    # 选服务器
    tap(1432, 369, 2)                    # 密码框
    adb("shell", "input text 'testpass123'")
    time.sleep(2)
    tap(960, 915, 25)                    # 登入


def main():
    keep = "--keep" in sys.argv
    print("[1] 启动 frida-server（子进程保活）")
    adb("shell", "pkill -f frida-server")
    time.sleep(1)
    srv = start_server()
    time.sleep(8)
    ps = adb("shell", "ps -A | grep frida-server | grep -v grep")
    print("    server: %s" % (ps.stdout.strip() or "(未看到)"))
    if "[frida-server]" in ps.stdout or not ps.stdout.strip():
        print("    ** frida-server 未存活，后续会失败 **")

    print("[2] 连接设备")
    dev = frida.get_device(DEV, timeout=10)

    print("[3] spawn %s" % PKG)
    adb("shell", "am force-stop " + PKG)
    time.sleep(2)
    pid = dev.spawn([PKG])
    session = dev.attach(pid)
    script = session.create_script(JS)

    def on_message(msg, data):
        if msg.get("type") == "send":
            p = msg["payload"]
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
            else:
                print("    [%s] %s" % (t, {k: v for k, v in p.items() if k != "t"}))
        elif msg.get("type") == "error":
            print("    [frida error] %s" % (msg.get("description") or msg.get("stack")))

    script.on("message", on_message)
    script.load()
    print("[4] resume")
    dev.resume(pid)

    if not keep:
        print("[5] 自动走 UI 流程（约 90 秒）")
        th = threading.Thread(target=ui_flow, daemon=True)
        th.start()
        th.join(timeout=120)

    print("[6] 再收集 15 秒输出")
    time.sleep(15)
    try:
        session.detach()
    except Exception:
        pass
    srv.terminate()
    print("完成")


if __name__ == "__main__":
    main()
