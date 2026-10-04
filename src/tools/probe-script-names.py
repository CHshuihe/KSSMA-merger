# -*- coding: utf-8 -*-
"""教程脚本名反推：在资源目录里布置候选文件名，反推客户端到底查哪个（M21）。

思路（不依赖 frida）：
    `_Tutorial::loadScript` → `rooney::res::exists(String)` 崩溃，
    说明客户端查了一个**本地不存在的资源名**。
    那我们就把所有**合理的候选名**都造出来（内容用已有的真实脚本），
    再跑一次；如果教程能过，说明候选集里命中了；再二分缩小到确切名字。

候选来源（都是从客户端 .so 字符串池实证推导的）：
    - 模板 `scsc_2001_1_%d.txt`（唯一带 .txt 的教程模板）
    - 模板 `scsc_%d%02d`
    - 磁盘上真实的阶段号：100/1070/2000/...
    - 我们可能下发的 step：0 / 100 / 100 / 1000
    - 是否带 `.txt` / 是否带 `.load` 伴随文件

用法：
    python tools/probe-script-names.py list          # 只列出候选
    python tools/probe-script-names.py apply         # 铺候选（拷贝真实脚本内容）
    python tools/probe-script-names.py clean         # 清掉铺的候选
"""
import os
import subprocess
import sys

# adb 路径与设备地址由 devenv 统一解析（可用环境变量 ADB / KSSMA_DEVICE 覆盖）
from devenv import ADB, DEVICE   # noqa: E402
DEV = DEVICE
SCEN = ("/sdcard/Android/data/com.square_enix.million_cn/files/"
        "save/download/scenario")

# 已有真实脚本（拿它当内容）
SRC_STEP = 100

# 候选文件名（.so 里推导出的各种可能）
CANDIDATES = [
    # 带 .txt（.so 模板就是这么写的）
    "scsc_2001_1_100.txt",
    "scsc_2001_1_0.txt",
    "scsc_2001_1_1000.txt",
    # 不带扩展（磁盘现状）但阶段号不同
    "scsc_2001_1_0",
    "scsc_2001_1_1000",
    # 其它章节/小节组合
    "scsc_2001_100",
    "scsc_200101_100",
    "scsc_2001_1_100.load",
    # 可能的"教程总入口"
    "scsc_2001_1",
    "scsc_2001",
    # 三个国家都要（脚本名含国家号）
    "scsc_2001_2_100", "scsc_2001_3_100",
    "scsc_2001_2_100.txt", "scsc_2001_3_100.txt",
    "scsc_2001_2_0", "scsc_2001_3_0",
]


def adb(*args, timeout=120):
    return subprocess.run([ADB, "-s", DEV] + list(args),
                          capture_output=True, text=True, timeout=timeout,
                          errors="replace")


def sh(cmd):
    return adb("shell", cmd).stdout


def main():
    cmd = sys.argv[1] if len(sys.argv) > 1 else "list"

    if cmd == "list":
        print("候选文件（共 %d 个）：" % len(CANDIDATES))
        for c in CANDIDATES:
            print("   ", c)
        return

    if cmd == "clean":
        for c in CANDIDATES:
            sh("rm -f '%s/%s'" % (SCEN, c))
        print("已清理 %d 个候选" % len(CANDIDATES))
        return

    if cmd == "apply":
        # 1) 把真实脚本拷出来做模板
        sh("cp '%s/scsc_2001_1_%d' /data/local/tmp/tpl.bin" % (SCEN, SRC_STEP))
        made = 0
        for c in CANDIDATES:
            # 用真实脚本内容填充每个候选名
            out = sh("cp /data/local/tmp/tpl.bin '%s/%s' && chown 10044:1078 '%s/%s' "
                     "&& chmod 660 '%s/%s' && echo OK"
                     % (SCEN, c, SCEN, c, SCEN, c))
            if "OK" in out:
                made += 1
            else:
                print("   失败: %s -> %s" % (c, out.strip()[:80]))
        print("已铺 %d/%d 个候选" % (made, len(CANDIDATES)))
        r = sh("ls %s | wc -l" % SCEN)
        print("scenario 目录现有文件数:", r.strip())
        return

    raise SystemExit("unknown command: %s" % cmd)


if __name__ == "__main__":
    main()
