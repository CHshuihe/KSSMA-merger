# -*- coding: utf-8 -*-
"""决定性实验 v2：抓 _Tutorial::loadScript 的真实入参（M21）。

修正了 v1 的错误：
  * v1 force-stop 后在"查库加载"时把**上一轮残留 PID** 当成目标，hook 装错进程。
    → 现在：记录 force-stop 之前的 PID，之后**只接受不同的新 PID**。
  * v1 用 monkey 启动，app 可能直接恢复到引擎 Activity 而跳过登录。
    → 现在：用显式 `am start -n .../LogoActivity`。
  * 实测 `loadScript+5` 崩（极早位置）→ 说明是 **this 或参数坏**，
    所以要 dump 该对象的前若干指针与内存。

流程：
  1. 把账号 3 的档重置为全新（tutorial.step=100）→ 制造复现条件
  2. 冷启，UI 线程走：模式选择 → 服务器 → 登录
  3. 主线程轮询 maps，一旦 librooneyj 出现**且是新 PID** → 按段映射装 hook
  4. 登录触发教程 → hook 打印 loadScript 的入参
"""
import re, struct, subprocess, threading, time
import frida

# adb 路径与设备地址由 devenv 统一解析（可用环境变量 ADB / KSSMA_DEVICE 覆盖）
from devenv import ADB, DEVICE   # noqa: E402
DEV = DEVICE
PKG = "com.square_enix.million_cn"
SAVE = "/sdcard/Android/data/%s/files/kssma-save" % PKG
SO = r"D:\MyFlie\AI\zcode\workspace\kssma\kssma_apk\build\apkwork\decoded\lib\armeabi\librooneyj.so"
T = {"exists": 0x38F8CD, "load": 0x373835, "name": 0x1EA729}

def adb(*a, timeout=180):
    return subprocess.run([ADB, "-s", DEV] + list(a), capture_output=True,
                          text=True, errors="replace", timeout=timeout)

def pid_():
    o = adb("shell", "pidof " + PKG).stdout.strip()
    return int(o.split()[0]) if o else None

def segs():
    b = open(SO, "rb").read()
    ph, = struct.unpack_from("<I", b, 0x1C)
    pe, pn = struct.unpack_from("<HH", b, 0x2A)
    r = []
    for i in range(pn):
        o = ph + i * pe
        t, off, va, pa, fsz, msz, fl, al = struct.unpack_from("<IIIIIIII", b, o)
        if t == 1:
            r.append((va, fsz, fl))
    return r

def maps(p):
    r = []
    for l in adb("shell", "cat /proc/%d/maps" % p).stdout.splitlines():
        if "rooneyj" not in l:
            continue
        m = re.match(r"([0-9a-f]+)-([0-9a-f]+)\s+(\S{4})\s+([0-9a-f]+)", l)
        if m:
            r.append({"s": int(m.group(1), 16), "e": int(m.group(2), 16),
                      "o": int(m.group(4), 16)})
    return r

def resolve(se, mp, va):
    for v, fsz, fl in se:
        if v <= va < v + fsz:
            best = None
            for r in mp:
                span = r["e"] - r["s"]
                if r["o"] <= v < r["o"] + span:
                    c = r["s"] + (va - v)
                    if best is None:
                        best = c
            if best is not None:
                return best
    return None

JS = r"""
var T = %s;
function rstr(p){ if(!p||p.isNull()) return "<null>";
  try{var s=p.readCString(); return s===null?"<unreadable>":s;}catch(e){return "<err>";} }

send({t:"info", m:"addr " + JSON.stringify(T)});

// 崩溃点就在 loadScript+5，所以要在 onEnter 立刻取数据并 send
Interceptor.attach(ptr(T.load), { onEnter: function (a) {
    var o = { t:"loadScript", idx:a[1].toInt32(), this_:a[0].toString() };
    try { o.hex_this = hexdump(a[0], {length:64, ansi:false}); } catch(e){}
    // 把 this 当对象读：前 8 个 32 位字
    try {
        var words = [];
        for (var i = 0; i < 8; i++) words.push(a[0].add(i*4).readU32().toString(16));
        o.words = words.join(" ");
    } catch(e){}
    send(o);
}});

// getScriptName 若被调用，看它返回什么
Interceptor.attach(ptr(T.name), {
    onEnter: function (a) { this.sret=a[0]; this.self=a[1]; this.idx=a[2].toInt32(); },
    onLeave: function (r) {
        var o = { t:"getScriptName", idx:this.idx };
        try { o.s0 = rstr(this.sret.readPointer()); } catch(e){}
        try { o.s4 = rstr(this.sret.add(4).readPointer()); } catch(e){}
        try { o.ret = r.toString(); } catch(e){}
        send(o);
    }
});

// res::exists 若被调用，看查询名
Interceptor.attach(ptr(T.exists), { onEnter: function (a) {
    var o = { t:"exists", a0:a[0].toString() };
    try { o.direct = rstr(a[0]); } catch(e){}
    try { o.p0 = rstr(a[0].readPointer()); } catch(e){}
    try { o.p4 = rstr(a[0].add(4).readPointer()); } catch(e){}
    send(o);
}});
send({t:"info", m:"hooks installed"});
"""

def on_msg(m, d):
    if m.get("type") == "send":
        p = m["payload"]
        if p.get("t") == "info":
            print("    [info] %s" % p.get("m"), flush=True)
        else:
            print("    [%s] %s" % (p.get("t"),
                  {k: v for k, v in p.items() if k != "t"}), flush=True)
    elif m.get("type") == "error":
        print("    [frida error] %s" % (m.get("description") or m.get("stack")), flush=True)

def top():
    o = adb("shell", "dumpsys activity activities 2>/dev/null | grep -m1 ResumedActivity").stdout
    m = re.search(r"([\w.]+/[\w.]+)", o)
    return m.group(1) if m else ""

def wait_for(sub, t=200):
    for _ in range(t):
        if sub in top():
            return True
        time.sleep(1)
    return False

def ui():
    def tap(x, y, w):
        adb("shell", "input tap %d %d" % (x, y)); time.sleep(w)
    print("    [ui] 等模式选择页", flush=True)
    if wait_for("ModeSelect", 220):
        print("    [ui] 继续游戏", flush=True); tap(960, 420, 6)
    else:
        print("    [ui] 未到模式选择，当前=%s" % top(), flush=True)
    if wait_for("WorldSelect", 60):
        print("    [ui] 选服务器", flush=True); tap(960, 545, 6)
    else:
        print("    [ui] 未到服务器选择，当前=%s" % top(), flush=True)
    if wait_for("LoginActivity", 60):
        print("    [ui] 登录（账号3）", flush=True)
        tap(717, 369, 2)                       # 手机号框
        adb("shell", "input text '12312312311'"); time.sleep(2)
        tap(1432, 369, 2)                      # 密码框
        adb("shell", "input text 'testpass123'"); time.sleep(2)
        tap(960, 915, 3)
    else:
        print("    [ui] 未到登录页，当前=%s" % top(), flush=True)
    print("    [ui] 等引擎", flush=True)
    wait_for("RooneyJActivity", 90)
    print("    [ui] 前台=%s" % top(), flush=True)

def main():
    se = segs()
    print("[0] 重置账号3为全新（tutorial.step=100）")
    adb("shell", "am force-stop " + PKG); time.sleep(3)
    adb("push", r"D:\MyFlie\AI\zcode\workspace\kssma\kssma_apk\merger\artifacts\kssma-data\game\default-save.json",
        SAVE + "/accounts/user-3.json")
    adb("shell", "chown 10044:1078 %s/accounts/user-3.json; chmod 660 %s/accounts/user-3.json"
        % (SAVE, SAVE))
    print("    已知: 该模板 tutorial=%s" %
          __import__("json").load(open(r"D:\MyFlie\AI\zcode\workspace\kssma\kssma_apk\merger\artifacts\kssma-data\game\default-save.json",
                                       encoding="utf-8")).get("tutorial"))

    print("[1] 冷启（记录旧 PID 以便区分）")
    old = pid_()
    print("    force-stop 前的旧 PID =", old)
    adb("shell", "am force-stop " + PKG); time.sleep(3)
    adb("shell", "am start -n %s/com.test.enter.LogoActivity" % PKG)
    time.sleep(5)
    th = threading.Thread(target=ui, daemon=True); th.start()

    dev = frida.get_device(DEV, timeout=10)
    sess = att = None
    t0 = time.time()
    while time.time() - t0 < 320:
        p = pid_()
        if p and p != old:
            mp = maps(p)
            if mp and sess is None:
                ad = {}
                for k, va in T.items():
                    a = resolve(se, mp, va)
                    if a:
                        ad[k] = a
                if len(ad) == 3:
                    print("    [hit] 新 pid=%d，解析出 3 个地址（%.0f 秒）" % (p, time.time() - t0), flush=True)
                    for k, a in ad.items():
                        print("        %-8s -> 0x%X" % (k, a), flush=True)
                    try:
                        sess = dev.attach(p)
                        sc = sess.create_script(JS % ("{exists:0x%X,load:0x%X,name:0x%X}"
                                                      % (ad["exists"], ad["load"], ad["name"])))
                        sc.on("message", on_msg)
                        sc.load()
                        att = p
                    except Exception as e:
                        print("    attach 失败: %s" % e, flush=True)
                        sess = None
        time.sleep(0.3)

    print("[2] 收集 40 秒（期间会登录 → 触发教程）")
    time.sleep(40)
    try:
        if sess:
            sess.detach()
    except Exception:
        pass
    print("完成")

if __name__ == "__main__":
    main()
