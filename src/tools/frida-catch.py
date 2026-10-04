# -*- coding: utf-8 -*-
"""决定性实验：先装 hook（按段映射）→ 再重登 → 抓 loadScript 的真实数据。

流程：
  1. 冷启到模式选择（pm 数据保留，账号 2 处于 tutorial.step=100）
  2. 轮询到 librooneyj 进 maps，按段映射算地址并装 hook
  3. 自动走 UI 登录 → 教程加载 → hook 打印
"""
import re, struct, subprocess, threading, time
import frida

# adb 路径与设备地址由 devenv 统一解析（可用环境变量 ADB / KSSMA_DEVICE 覆盖）
from devenv import ADB, DEVICE   # noqa: E402
DEV = DEVICE
PKG = "com.square_enix.million_cn"
SO = r"D:\MyFlie\AI\zcode\workspace\kssma\kssma_apk\build\apkwork\decoded\lib\armeabi\librooneyj.so"
T = {"exists": 0x38F8CD, "load": 0x373835, "name": 0x1EA729}

def adb(*a, timeout=180):
    return subprocess.run([ADB, "-s", DEV] + list(a), capture_output=True,
                          text=True, errors="replace", timeout=timeout)

def pid_():
    o = adb("shell", "pidof " + PKG).stdout.strip()
    return int(o.split()[0]) if o else None

def segs():
    b = open(SO,"rb").read()
    ph, = struct.unpack_from("<I", b, 0x1C)
    pe, pn = struct.unpack_from("<HH", b, 0x2A)
    r=[]
    for i in range(pn):
        o=ph+i*pe
        t,off,va,pa,fsz,msz,fl,al = struct.unpack_from("<IIIIIIII", b, o)
        if t==1: r.append((va,fsz,fl))
    return r

def maps(p):
    r=[]
    for l in adb("shell","cat /proc/%d/maps"%p).stdout.splitlines():
        if "rooneyj" not in l: continue
        m=re.match(r"([0-9a-f]+)-([0-9a-f]+)\s+(\S{4})\s+([0-9a-f]+)", l)
        if m: r.append({"s":int(m.group(1),16),"e":int(m.group(2),16),"o":int(m.group(4),16)})
    return r

def resolve(se,mp,va):
    for v,fsz,fl in se:
        if v<=va<v+fsz:
            best=None
            for r in mp:
                span=r["e"]-r["s"]
                if r["o"]<=v<r["o"]+span:
                    c=r["s"]+(va-v)
                    if best is None: best=c
            if best is not None: return best
    return None

JS = r"""
var T = %s;
function rstr(p){ if(!p||p.isNull())return "<null>";
  try{var s=p.readCString();return s===null?"<unreadable>":s;}catch(e){return "<err>";} }
send({t:"info",m:"addr "+JSON.stringify(T)});
Interceptor.attach(ptr(T.load),{onEnter:function(a){
  var o={t:"loadScript",idx:a[1].toInt32(),self:a[0].toString()};
  try{o.b0=a[0].readPointer().toString();}catch(e){}
  try{o.b4=a[0].add(4).readPointer().toString();}catch(e){}
  try{o.b8=a[0].add(8).readPointer().toString();}catch(e){}
  try{o.hex=hexdump(a[0],{length:64,ansi:false});}catch(e){}
  send(o);
}});
Interceptor.attach(ptr(T.name),{
  onEnter:function(a){this.sret=a[0];this.idx=a[2].toInt32();},
  onLeave:function(r){var o={t:"getScriptName",idx:this.idx};
    try{o.s0=rstr(this.sret.readPointer());}catch(e){}
    try{o.s4=rstr(this.sret.add(4).readPointer());}catch(e){}
    try{o.s8=rstr(this.sret.add(8).readPointer());}catch(e){}
    send(o);}
});
Interceptor.attach(ptr(T.exists),{onEnter:function(a){
  var o={t:"exists",a0:a[0].toString()};
  try{o.direct=rstr(a[0]);}catch(e){}
  try{o.p0=rstr(a[0].readPointer());}catch(e){}
  try{o.p4=rstr(a[0].add(4).readPointer());}catch(e){}
  send(o);
}});
send({t:"info",m:"hooks installed"});
"""

def on_msg(m,d):
    if m.get("type")=="send":
        p=m["payload"]
        if p.get("t")=="info": print("    [info] %s"%p.get("m"),flush=True)
        else:
            print("    [%s] %s"%(p.get("t"),{k:v for k,v in p.items() if k!="t"}),flush=True)
    elif m.get("type")=="error":
        print("    [frida error] %s"%(m.get("description") or m.get("stack")),flush=True)

def top():
    o=adb("shell","dumpsys activity activities 2>/dev/null | grep -m1 ResumedActivity").stdout
    m=re.search(r"([\w.]+/[\w.]+)",o); return m.group(1) if m else ""

def wait_for(sub,t=180):
    for _ in range(t):
        if sub in top(): return True
        time.sleep(1)
    return False

def ui():
    def tap(x,y,w): adb("shell","input tap %d %d"%(x,y)); time.sleep(w)
    print("    [ui] 等模式选择",flush=True)
    if wait_for("ModeSelect",200):
        print("    [ui] 继续游戏",flush=True); tap(960,420,6)
    if wait_for("WorldSelect",60):
        print("    [ui] 服务器",flush=True); tap(960,545,6)
    if wait_for("LoginActivity",60):
        print("    [ui] 登录（账号2/你新建的密码）",flush=True)
        tap(1432,369,2); adb("shell","input text 'testpass123'"); time.sleep(2)
        tap(960,915,3)
    print("    [ui] 等引擎",flush=True); wait_for("RooneyJActivity",90)
    print("    [ui] 前台 = %s"%top(),flush=True)

def main():
    se=segs()
    print("[1] 冷启")
    adb("shell","am force-stop "+PKG); time.sleep(3)
    adb("shell","am start -n %s/com.test.enter.LogoActivity"%PKG); time.sleep(5)
    th=threading.Thread(target=ui,daemon=True); th.start()

    dev=frida.get_device(DEV,timeout=10)
    sess=att=None; t0=time.time()
    while time.time()-t0<300:
        p=pid_()
        if p:
            mp=maps(p)
            if mp and sess is None and p!=att:
                ad={}
                for k,va in T.items():
                    a=resolve(se,mp,va)
                    if a: ad[k]=a
                print("    [hit] pid=%d 解析 %d/3（%.0f 秒）"%(p,len(ad),time.time()-t0),flush=True)
                for k,a in ad.items(): print("        %-8s -> 0x%X"%(k,a),flush=True)
                if len(ad)==3:
                    try:
                        sess=dev.attach(p)
                        sc=sess.create_script(JS % ("{exists:0x%X,load:0x%X,name:0x%X}"
                                                    %(ad["exists"],ad["load"],ad["name"])))
                        sc.on("message",on_msg); sc.load(); att=p
                    except Exception as e:
                        print("    attach 失败: %s"%e,flush=True); sess=None
        time.sleep(0.3)
    print("[2] 收集 30 秒"); time.sleep(30)
    try:
        if sess: sess.detach()
    except Exception: pass
    print("完成",flush=True)

if __name__=="__main__":
    main()
