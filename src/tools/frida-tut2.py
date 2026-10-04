# -*- coding: utf-8 -*-
"""frida 诊断：hook libdl 抓 librooneyj.so 基址，再装教程 hook（M21）。见 notes/M20。"""
import subprocess, threading, time
import frida

# adb 路径与设备地址由 devenv 统一解析（可用环境变量 ADB / KSSMA_DEVICE 覆盖）
from devenv import ADB, DEVICE   # noqa: E402
DEV = DEVICE
PKG = "com.square_enix.million_cn"

JS = r"""
var hooked = false;
function rstr(p) {
    if (!p || p.isNull()) return "<null>";
    try { var s = p.readCString(); return (s === null) ? "<unreadable>" : s; }
    catch (e) { return "<err>"; }
}
function installHooks(base) {
    if (hooked) return;
    hooked = true;
    send({t:"info", m:"librooneyj base = " + base});
    Interceptor.attach(base.add(0x38F8CD), {
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
    Interceptor.attach(base.add(0x373835), {
        onEnter: function (a) {
            send({ t: "loadScript", idx: a[1].toInt32(), self: a[0].toString() });
        }
    });
    Interceptor.attach(base.add(0x1EA729), {
        onEnter: function (a) { this.sret = a[0]; this.self = a[1]; this.idx = a[2].toInt32(); },
        onLeave: function (r) {
            var o = { t: "getScriptName", idx: this.idx, ret: r.toString() };
            try { o.sret0 = rstr(this.sret.readPointer()); } catch (e) {}
            try { o.sret4 = rstr(this.sret.add(4).readPointer()); } catch (e) {}
            send(o);
        }
    });
    send({t:"info", m:"hooks installed"});
}
function findExport(modName, sym) {
    try { return Process.getModuleByName(modName).findExportByName(sym); }
    catch (e) { return null; }
}
var targets = [["libdl.so","android_dlopen_ext"],["libdl.so","dlopen"],
               ["linker","__loader_android_dlopen_ext"]];
var n = 0;
targets.forEach(function (pair) {
    var p = findExport(pair[0], pair[1]);
    if (!p) return;
    n++;
    send({t:"info", m:"hook " + pair[0] + "!" + pair[1] + " @" + p});
    Interceptor.attach(p, {
        onEnter: function (args) { try { this.path = rstr(args[0]); } catch (e) { this.path = null; } },
        onLeave: function (ret) {
            if (this.path && this.path.indexOf("rooneyj") >= 0) {
                send({t:"info", m:"dlopen(" + this.path + ") -> " + ret});
                installHooks(ret);
            }
        }
    });
});
if (n === 0) send({t:"err", m:"没有可 hook 的 dlopen"});
"""

def adb(*a, timeout=120):
    return subprocess.run([ADB, "-s", DEV] + list(a), capture_output=True,
                          text=True, errors="replace", timeout=timeout)

def ui_flow():
    def tap(x, y, w):
        adb("shell", "input tap %d %d" % (x, y)); time.sleep(w)
    time.sleep(38)
    tap(960, 420, 10); tap(960, 545, 12); tap(1432, 369, 2)
    adb("shell", "input text 'testpass123'"); time.sleep(2)
    tap(960, 915, 30)

def main():
    print("[1] 连接设备")
    dev = frida.get_device(DEV, timeout=10)
    print("    进程数 %d" % len(dev.enumerate_processes()))
    print("[2] spawn")
    adb("shell", "am force-stop " + PKG); time.sleep(2)
    pid = dev.spawn([PKG]); print("    pid =", pid)
    session = dev.attach(pid)
    script = session.create_script(JS)
    def on_message(m, d):
        if m.get("type") == "send":
            p = m["payload"]; t = p.get("t")
            if t == "info": print("    [info] %s" % p.get("m"))
            elif t == "err": print("    [ERR ] %s" % p.get("m"))
            elif t == "exists":
                print("    [exists] a0=%s" % p.get("a0"))
                for k in ("direct","p0","p4","p8"):
                    if k in p: print("             %-7s = %r" % (k, p[k]))
                if p.get("hex"): print(p["hex"])
            else: print("    [%s] %s" % (t, {k:v for k,v in p.items() if k!="t"}))
        elif m.get("type") == "error":
            print("    [frida error] %s" % (m.get("description") or m.get("stack")))
    script.on("message", on_message)
    script.load()
    print("[3] resume + 自动走 UI")
    dev.resume(pid)
    th = threading.Thread(target=ui_flow, daemon=True); th.start()
    th.join(timeout=150)
    print("[4] 再收集 20 秒"); time.sleep(20)
    try: session.detach()
    except Exception: pass
    print("完成")

if __name__ == "__main__":
    main()
