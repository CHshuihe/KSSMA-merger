# -*- coding: utf-8 -*-
"""教程流程实机验收脚本（M21）。

把"新账号 → 自建名字 → 选自阵营 → 进主城"整条链路自动走一遍，
每步都截图 + 抓日志，用来判断教程到底通没通。

用法：
    python tools/tut-e2e.py [--apk <路径>]     # 不给 --apk 则用已装的包
"""
import os
import re
import subprocess
import sys
import time

# adb 路径与设备地址由 devenv 统一解析（可用环境变量 ADB / KSSMA_DEVICE 覆盖）
from devenv import ADB, DEVICE   # noqa: E402
DEV = DEVICE
PKG = "com.square_enix.million_cn"
SAVE = "/sdcard/Android/data/%s/files/kssma-save" % PKG
ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
SHOT = os.path.join(ROOT, "work", "m21")


def adb(*args, timeout=90):
    return subprocess.run([ADB, "-s", DEV] + list(args),
                          capture_output=True, text=True, timeout=timeout)


def sh(cmd, timeout=90):
    return adb("shell", cmd, timeout=timeout).stdout


def tap(x, y, wait=3):
    adb("shell", "input tap %d %d" % (x, y))
    time.sleep(wait)


def shot(name):
    os.makedirs(SHOT, exist_ok=True)
    p = os.path.join(SHOT, name + ".png")
    with open(p, "wb") as f:
        f.write(adb("exec-out", "screencap", "-p").stdout.encode("latin-1", "ignore"))
    try:
        from PIL import Image
        Image.open(p).resize((1280, 720), Image.LANCZOS).save(
            os.path.join(SHOT, name + "-view.png"))
    except Exception:
        pass
    return p


def alive():
    return PKG in sh("ps -A 2>/dev/null")


def log_tail(n=6):
    return sh("tail -%d %s/logs/requests.log 2>/dev/null" % (n, SAVE)).strip()


def crashes():
    out = sh("logcat -d -t 400 2>/dev/null")
    hits = [l for l in out.splitlines()
            if ("loadScript" in l or "res::exists" in l
                or "VM exiting" in l or "Force finishing" in l)]
    return hits[-4:]


def main():
    apk = None
    if "--apk" in sys.argv:
        apk = sys.argv[sys.argv.index("--apk") + 1]

    print("=" * 60)
    if apk:
        print("[1] 安装 %s" % os.path.basename(apk))
        adb("shell", "am force-stop " + PKG)
        r = adb("install", "-r", apk, timeout=600)
        print("    ", r.stdout.strip().splitlines()[-1] if r.stdout.strip() else r.stderr[-200:])

    print("[2] 把账号 2 重置为全新（tutorial.step=100）")
    adb("shell", "am force-stop " + PKG)
    time.sleep(2)
    adb("push", os.path.join(ROOT, "merger", "artifacts", "kssma-data", "game",
                             "default-save.json"), SAVE + "/accounts/user-2.json")
    sh("chown 10044:1078 %s/accounts/user-2.json; chmod 660 %s/accounts/user-2.json"
       % (SAVE, SAVE))

    print("[3] 冷启")
    adb("shell", "logcat -c")
    adb("shell", "monkey -p %s -c android.intent.category.LAUNCHER 1" % PKG)
    time.sleep(40)
    shot("e2e-01-mode")

    print("[4] 继续游戏")
    tap(960, 420, 10)
    shot("e2e-02-after-continue")

    print("[5] 选服务器")
    tap(960, 545, 12)
    shot("e2e-03-login")

    print("[6] 登录")
    tap(1432, 369, 2)
    adb("shell", "input text 'testpass123'")
    time.sleep(2)
    tap(960, 915, 30)
    shot("e2e-04-tutorial")

    print("[7] 观察 30 秒（教程应开始播放 / 或出现选择界面）")
    for i in range(3):
        time.sleep(10)
        shot("e2e-05-step%d" % i)

    print()
    print("=" * 60)
    print("进程存活: %s" % alive())
    print("请求日志:")
    print("  " + log_tail(8).replace("\n", "\n  "))
    cr = crashes()
    print("退出/崩溃信号: %s" % ("无" if not cr else ""))
    for l in cr:
        print("  " + l.strip())
    print("截图目录: %s" % SHOT)


if __name__ == "__main__":
    main()
