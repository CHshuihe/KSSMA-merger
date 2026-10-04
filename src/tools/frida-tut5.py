# -*- coding: utf-8 -*-
"""frida 诊断 v5：**并行**驱动 UI + 轮询库加载，抢在崩溃前装 hook（M21）。

v4 的教训：
    librooneyj.so **只在登录成功后**才被 dlopen。冷启时若干等 maps，
    永远等不到（因为没人驱动 UI 去登录）。所以必须并行：
      - 线程 A：走 UI（模式选择 → 服务器 → 登录）
      - 线程 B（主线程）：高频轮询 /proc/<pid>/maps，
        库一出现立刻 attach 装 hook（每 0.2 秒查一次，抢在崩溃前）
"""
import re, subprocess, sys, threading, time
import frida

# adb 路径与设备地址由 devenv 统一解析（可用环境变量 ADB / KSSMA_DEVICE 覆盖）
from devenv import ADB, DEVICE   # noqa: E402
DEV = DEVICE
PKG = "com.square_enix.million_cn"

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

def adb(*a, timeout=180):
    return subprocess.run([ADB, "-s", DEV] + list(a), capture_output=True,
                          text=True, errors="replace", timeout=timeout)

def app_pid():
    out = adb("shell", "pidof " + PKG).stdout.strip()
    return int(out.split()[0]) if out else None

def lib_base(pid):
    maps = adb("shell", "cat /proc/%d/maps" % pid).stdout
    for line in maps.splitlines():
        if "rooneyj" not in line:
            continue
        m = re.match(r"([0-9a-f]+)-([0-9a-f]+)\s+(\S+)\s+([0-9a-f]+)", line)
        if m and int(m.group(4), 16) == 0:
            return int(m.group(1), 16)
    return None

def on_message(m, d):
    if m.get("type") == "send":
        p = m["payload"]; t = p.get("t")
        if t == "info": print("    [info] %s" % p.get("m"), flush=True)
        elif t == "err": print("    [ERR ] %s" % p.get("m"), flush=True)
        elif t == "exists":
            print("    [exists] a0=%s" % p.get("a0"), flush=True)
            for k in ("direct","p0","p4","p8"):
                if k in p: print("             %-7s = %r" % (k, p[k]), flush=True)
            if p.get("hex"): print(p["hex"], flush=True)
        else: print("    [%s] %s" % (t, {k:v for k,v in p.items() if k!="t"}), flush=True)
    elif m.get("type") == "error":
        print("    [frida error] %s" % (m.get("description") or m.get("stack")), flush=True)

def top():
    o = adb("shell", "dumpsys activity activities 2>/dev/null | grep -m1 ResumedActivity").stdout
    m = re.search(r"([\w.]+/[\w.]+)", o)
    return m.group(1) if m else ""

def wait_for(sub, t=120):
    for _ in range(t):
        if sub in top(): return True
        time.sleep(1)
    return False

def ui_thread():
    def tap(x, y, w):
        adb("shell", "input tap %d %d" % (x, y)); time.sleep(w)
    print("    [ui] 等模式选择页（冷启要等资源释放）", flush=True)
    if wait_for("ModeSelect", 150):
        print("    [ui] 继续游戏", flush=True); tap(960, 420, 6)
    if wait_for("WorldSelect", 60):
        print("    [ui] 选服务器", flush=True); tap(960, 545, 6)
    if wait_for("LoginActivity", 60):
        print("    [ui] 登录", flush=True)
        tap(1432, 369, 2)
        adb("shell", "input text 'testpass123'"); time.sleep(2)
        tap(960, 915, 3)
    print("    [ui] 等引擎 RooneyJActivity", flush=True)
    wait_for("RooneyJActivity", 90)
    print("    [ui] 引擎启动: %s" % top(), flush=True)

def main():
    print("[1] 冷启", flush=True)
    adb("shell", "am force-stop " + PKG); time.sleep(2)
    adb("shell", "am start -n %s/com.test.enter.LogoActivity" % PKG)
    time.sleep(6)

    print("[2] 启动 UI 线程", flush=True)
    th = threading.Thread(target=ui_thread, daemon=True); th.start()

    print("[3] 高频轮询库加载（每 0.2 秒）", flush=True)
    dev = frida.get_device(DEV, timeout=10)
    session = script = None
    t0 = time.time()
    attached_pid = None
    while time.time() - t0 < 300:
        pid = app_pid()
        # 只认"启动之后"的进程：一旦 attach 过某 pid，就盯着它；
        # 没 attach 过时也不能用残留 PID（maps 里还没有 rooneyj 就说明是残留）
        if pid and attached_pid is not None and pid != attached_pid:
            # 进程被重启了，重来
            attached_pid = None
            session = None
        if pid:
            base = lib_base(pid)
            if base and session is None and pid != attached_pid:
                print("    [hit] pid=%d base=0x%X（%.1f 秒）" % (pid, base, time.time()-t0), flush=True)
                try:
                    session = dev.attach(pid)
                    attached_pid = pid
                    script = session.create_script(JS_TMPL % base)
                    script.on("message", on_message)
                    script.load()
                except Exception as e:
                    print("    attach 失败: %s" % e, flush=True)
                    session = None
        time.sleep(0.2)

    print("[4] 收尾", flush=True)
    time.sleep(10)
    try:
        if session: session.detach()
    except Exception: pass
    print("完成", flush=True)

if __name__ == "__main__":
    main()
