# -*- coding: utf-8 -*-
"""实机调试工具共用的环境解析（不写死任何人的本机路径）。

这些工具（`flow-test.py` / `frida-*.py`）是**开发期实机调试脚本**，
需要 adb 与设备地址。为了让别人也能用，这里按优先级自动查找：

    adb 路径：
        1. 环境变量 `ADB`
        2. 环境变量 `ANDROID_HOME` / `ANDROID_SDK_ROOT` 下的 platform-tools
        3. PATH 里的 adb
        4. 常见默认安装位置

    设备地址：
        环境变量 `KSSMA_DEVICE`，默认 `127.0.0.1:7555`（MuMu 默认端口）

用法：

    from devenv import ADB, DEVICE, adb, shell
"""
import os
import shutil
import subprocess

DEFAULT_DEVICE = os.environ.get("KSSMA_DEVICE", "127.0.0.1:7555")


def find_adb():
    """按优先级找一个可用的 adb.exe，找不到返回 None。"""
    env = os.environ.get("ADB")
    if env and os.path.isfile(env):
        return env
    for var in ("ANDROID_HOME", "ANDROID_SDK_ROOT"):
        root = os.environ.get(var)
        if root:
            for name in ("adb.exe", "adb"):
                p = os.path.join(root, "platform-tools", name)
                if os.path.isfile(p):
                    return p
    p = shutil.which("adb")
    if p:
        return p
    # 常见默认位置（Windows）
    for base in (os.environ.get("LOCALAPPDATA", ""),
                 os.path.join(os.environ.get("USERPROFILE", ""), "AppData", "Local")):
        if not base:
            continue
        p = os.path.join(base, "Android", "Sdk", "platform-tools", "adb.exe")
        if os.path.isfile(p):
            return p
    return None


ADB = find_adb()
DEVICE = DEFAULT_DEVICE


def adb(*args, timeout=180):
    """执行 adb 命令，返回 CompletedProcess（文本模式）。"""
    if not ADB:
        raise RuntimeError(
            "找不到 adb。请设置环境变量 ADB，或安装 Android SDK 的 platform-tools。")
    return subprocess.run([ADB, "-s", DEVICE] + list(args), capture_output=True,
                          text=True, errors="replace", timeout=timeout)


def shell(cmd, timeout=180):
    """执行 `adb shell <cmd>`，返回 stdout 文本。"""
    return adb("shell", cmd, timeout=timeout).stdout


def screenshot(path, timeout=180):
    """截图到本地文件。"""
    r = subprocess.run([ADB, "-s", DEVICE, "exec-out", "screencap", "-p"],
                       capture_output=True, timeout=timeout)
    with open(path, "wb") as f:
        f.write(r.stdout)
    return path


if __name__ == "__main__":                     # 自检
    print("ADB    =", ADB or "(未找到)")
    print("DEVICE =", DEVICE)
    if ADB:
        print("设备列表:")
        print(subprocess.run([ADB, "devices"], capture_output=True,
                             text=True).stdout)
