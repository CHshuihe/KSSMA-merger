# -*- coding: utf-8 -*-
"""全流程实机测试：继续游戏 → 服务器 → 登录 → 观察教程场景（M21）。

为什么需要它：
    教程 bug 只在**真实完整流程**（模式选择 → 服务器选择 → 登录）下暴露。
    用 `monkey` 直接启动引擎会跳过这些步骤，得到**假阳性**（曾据此误判"已修好"）。
    所以每次验证必须走这个脚本。

流程：
    1. 安装 APK（可选）
    2. 推送指定存档到账号（默认账号 3 / user-3.json）
    3. 清内部状态（shared_prefs/files），保证走真实流程
    4. 启动 → 等模式选择 → 点「继续游戏」→ 点服务器 → 填账号密码 → 登入
    5. 观察前台 Activity 与崩溃栈，截图

用法：
    python tools/flow-test.py --apk dist/xxx.apk --save work/save.json [--user 3]
"""
import argparse
import os
import re
import subprocess
import sys
import time

# adb 路径与设备地址由 devenv 统一解析（可用环境变量 ADB / KSSMA_DEVICE 覆盖）
from devenv import ADB, DEVICE   # noqa: E402
DEV = DEVICE
PKG = "com.square_enix.million_cn"
EXT = "/sdcard/Android/data/%s/files" % PKG
SAVE = EXT + "/kssma-save"
SHOT = r"D:\MyFlie\AI\zcode\workspace\kssma\kssma_apk\work\m22"

# 已验证的坐标（1920x1080 横屏）
TAP_CONTINUE = (960, 420)     # 模式选择-继续游戏
TAP_SERVER = (960, 545)       # 服务器选择
TAP_ID = (717, 369)           # 手机号输入框
TAP_PW = (1432, 369)          # 密码输入框
TAP_LOGIN = (960, 915)        # 登入
TAP_FACTION = (960, 600)      # 阵营-剑术之城
TAP_CONFIRM = (1620, 150)     # 确定（右上）


def adb(*a, timeout=180, binary=False):
    r = subprocess.run([ADB, "-s", DEV] + list(a), capture_output=True,
                       timeout=timeout)
    if binary:
        return r.stdout
    return r.stdout.decode("utf-8", "replace") + r.stderr.decode("utf-8", "replace")


def top():
    o = adb("shell", "dumpsys activity activities 2>/dev/null | grep -m1 ResumedActivity")
    m = re.search(r"([\w.]+/[\w.]+)", o)
    return m.group(1) if m else ""


def short(a):
    if "million_cn" in a:
        return "million_cn/" + a.split("/")[-1]
    if "lawnchair" in a:
        return "LAUNCHER(崩了)"
    return a or "?"


def wait_for(sub, t=150):
    for _ in range(t):
        if sub in top():
            return True
        time.sleep(1)
    return False


def tap(xy, wait=6):
    adb("shell", "input tap %d %d" % xy)
    time.sleep(wait)


def crashes():
    o = adb("shell", "logcat -d")
    out = []
    for l in o.splitlines():
        if "Fatal signal" in l or ("rooneyj" in l and "+" in l and "pc" in l):
            out.append(l.strip())
    return out[-8:]


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--apk")
    ap.add_argument("--save", required=True)
    ap.add_argument("--user", default="3")
    ap.add_argument("--id", dest="login_id", default="12312312311")
    ap.add_argument("--pw", default="testpass123")
    ap.add_argument("--no-clear", action="store_true")
    ap.add_argument("--tag", default="t")
    args = ap.parse_args()

    if args.apk:
        print("[1] 安装", os.path.basename(args.apk))
        adb("shell", "am force-stop " + PKG)
        out = adb("install", "-r", args.apk, timeout=600)
        print("   ", out.strip().splitlines()[-1] if out.strip() else "?")

    print("[2] 推送存档 -> accounts/user-%s.json" % args.user)
    adb("shell", "am force-stop " + PKG)
    time.sleep(2)
    adb("push", args.save, "%s/accounts/user-%s.json" % (SAVE, args.user))
    adb("shell", "chown 10044:1078 %s/accounts/user-%s.json; chmod 660 %s/accounts/user-%s.json"
        % (SAVE, args.user, SAVE, args.user))

    if not args.no_clear:
        print("[3] 清内部状态（保证走真实流程）")
        adb("shell", "rm -rf /data/data/%s/files /data/data/%s/shared_prefs" % (PKG, PKG))

    adb("shell", "rm -f %s/logs/requests.log" % SAVE)
    adb("shell", "logcat -c")

    print("[4] 启动")
    adb("shell", "monkey -p %s -c android.intent.category.LAUNCHER 1" % PKG)

    # 逐页推进：每页都确认到达再点（不要死等定时）
    def goto(sub, t=150, label=""):
        ok = wait_for(sub, t)
        print("    %-22s %s" % (label or sub, "OK" if ok else "MISS -> " + short(top())))
        return ok

    if not goto("ModeSelect", 150, "模式选择页"):
        return

    print("[5] 继续游戏")
    tap(TAP_CONTINUE)
    if not goto("WorldSelect", 90, "服务器选择页"):
        return

    print("[6] 选服务器")
    tap(TAP_SERVER)
    if not goto("LoginActivity", 90, "登录页"):
        return

    print("[7] 登录 %s" % args.login_id)
    tap(TAP_ID, 2)
    adb("shell", "input text '%s'" % args.login_id)
    time.sleep(2)
    tap(TAP_PW, 2)
    adb("shell", "input text '%s'" % args.pw)
    time.sleep(2)
    tap(TAP_LOGIN, 3)

    print("[8] 观察 40 秒")
    for i in range(5):
        time.sleep(8)
        print("    +%2ds : %s" % ((i + 1) * 8, short(top())))

    print("[9] 请求日志")
    for l in adb("shell", "tail -4 %s/logs/requests.log 2>/dev/null" % SAVE).splitlines():
        print("    " + l)

    print("[10] 崩溃栈")
    for l in crashes():
        print("    " + l[:150])

    shot = os.path.join(SHOT, "flow-%s.png" % args.tag)
    with open(shot, "wb") as f:
        f.write(adb("exec-out", "screencap -p", binary=True))
    print("[11] 截图:", shot)


if __name__ == "__main__":
    main()
