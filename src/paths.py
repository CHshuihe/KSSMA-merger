# -*- coding: utf-8 -*-
"""运行期路径解析（GUI / CLI / 打包后共用一份逻辑）。

为什么需要单独一个模块：
    之前 GUI 和 CLI **各写了一套** artifacts 解析：
        GUI : 环境变量 → exe/源码同级 → `_MEIPASS`          ← 找得到包内的
        CLI : 环境变量 → REPO/artifacts                      ← 打包后找不到
    结果就是 `KSSMA-Merger.exe --apk … --res … --out …` 在打包后
    会报"找不到修正数据"。把解析收到这里，两边都调它。

三个"目录"要分清（打包后尤其容易混）：

    app_dir()     可写目录 = exe 所在目录（源码运行时是 merger/）
                  → `keystore/` 写这里，否则每次运行签名密钥都变

    bundle_dir()  只读资源目录 = `sys._MEIPASS`
                  打包后是 `_internal/`，内置的 `artifacts/` 在这里

    find_artifacts()  修正数据目录，按下面顺序找：
                  1. 环境变量 `KSSMA_ARTIFACTS`
                  2. app_dir()/artifacts      ← 用户想覆盖时放这里
                  3. bundle_dir()/artifacts   ← 打包内置（正常情况走这条）
                  4. 源码树 ../artifacts
"""
import os
import sys


def app_dir():
    """可写目录：exe 所在目录（打包后）/ merger 目录（源码运行）。"""
    if getattr(sys, "frozen", False):
        return os.path.dirname(sys.executable)
    # src/paths.py → 上两级 = merger/
    return os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def bundle_dir():
    """只读资源目录：`_MEIPASS`（打包后）或 merger 目录（源码运行）。"""
    if getattr(sys, "frozen", False):
        return getattr(sys, "_MEIPASS", app_dir())
    return app_dir()


def find_artifacts():
    """定位修正数据目录（`artifacts/`）。找不到时返回**预期路径**，由调用方判断。"""
    env = os.environ.get("KSSMA_ARTIFACTS")
    if env:
        return env                     # 显式指定优先，即便不存在也让调用方报错
    candidates = [
        os.path.join(app_dir(), "artifacts"),      # 用户放在 exe 同级 → 覆盖内置
        os.path.join(bundle_dir(), "artifacts"),   # 打包内置
        os.path.join(os.path.dirname(app_dir()), "artifacts"),   # 源码树
    ]
    for p in candidates:
        if os.path.isdir(p):
            return p
    return candidates[0]


def keystore_dir():
    """签名密钥目录（必须可写 → 放 app_dir）。"""
    return os.path.join(app_dir(), "keystore")


if __name__ == "__main__":             # 自检：打印三项解析结果
    print("frozen       :", getattr(sys, "frozen", False))
    print("app_dir      :", app_dir())
    print("bundle_dir   :", bundle_dir())
    art = find_artifacts()
    print("artifacts    :", art, "（存在:", os.path.isdir(art), "）")
    print("keystore_dir :", keystore_dir())
