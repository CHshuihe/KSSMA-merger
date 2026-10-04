# -*- coding: utf-8 -*-
"""校验 frida 算出的 librooneyj 基址是否正确（对照 ELF 头与目标函数字节）。"""
import re, subprocess, time
import frida

# adb 路径与设备地址由 devenv 统一解析（可用环境变量 ADB / KSSMA_DEVICE 覆盖）
from devenv import ADB, DEVICE   # noqa: E402
DEV = DEVICE
PKG = "com.square_enix.million_cn"

def adb(*a, timeout=120):
    return subprocess.run([ADB, "-s", DEV] + list(a), capture_output=True,
                          text=True, errors="replace", timeout=timeout)

def app_pid():
    o = adb("shell", "pidof " + PKG).stdout.strip()
    return int(o.split()[0]) if o else None

def all_rooneyj_maps(pid):
    out = adb("shell", "cat /proc/%d/maps" % pid).stdout
    return [l for l in out.splitlines() if "rooneyj" in l]

JS = r"""
var out = [];
var mods = Process.enumerateModules();
out.push("enumerateModules count=" + mods.length);
var found = null;
for (var i = 0; i < mods.length; i++) {
    if (mods[i].name.indexOf("rooneyj") >= 0) { found = mods[i]; break; }
}
out.push("enumerateModules 里找到 rooneyj: " + (found ? (found.name + " @" + found.base + " size=" + found.size) : "没有"));
// 读各候选地址的字节，看哪个像 ELF 头 / 像 THUMB 代码
function dump(addr, n) {
    try { return hexdump(ptr(addr), {length: n, ansi: false}); }
    catch (e) { return "  读失败: " + e; }
}
var cands = %s;
cands.forEach(function (a) {
    out.push("--- 0x" + a.toString(16) + " ---");
    out.push(dump(a, 32));
});
send(out.join("\n"));
""" 

def main():
    # 先确保应用在跑且引擎已加载
    pid = None
    for _ in range(60):
        pid = app_pid()
        if pid: break
        time.sleep(1)
    if not pid:
        print("应用未运行"); return
    print("pid =", pid)
    ms = all_rooneyj_maps(pid)
    print("=== rooneyj 的 maps 行（全部）===")
    for l in ms: print("  " + l)
    # 候选基址：offset==0 的段起点 + 最小地址
    bases = []
    for l in ms:
        m = re.match(r"([0-9a-f]+)-([0-9a-f]+)\s+(\S+)\s+([0-9a-f]+)", l)
        if m:
            s = int(m.group(1), 16)
            bases.append(s)
    if not bases:
        print("maps 里没有 rooneyj"); return
    bases = sorted(set(bases))[:4]
    print("候选基址:", [hex(b) for b in bases])
    dev = frida.get_device(DEV, timeout=10)
    s = dev.attach(pid)
    sc = s.create_script(JS % ("[" + ",".join(hex(b) for b in bases) + "]"))
    got = {}
    sc.on("message", lambda m, d: got.update({"v": m.get("payload")}))
    sc.load(); time.sleep(2)
    print()
    print(got.get("v"))
    s.detach()

if __name__ == "__main__":
    main()
