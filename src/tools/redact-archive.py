# -*- coding: utf-8 -*-
"""把内部技术档案脱敏成可公开版本（供 GitHub 项目文档使用）。

为什么自己写而不用手工改：
    原文 1800+ 行，手工替换容易漏、也容易误删内容。
    这个脚本做**定点替换**并**校验替换确实发生**，其余正文逐字节保留。

用法：
    python redact-archive.py <输入.md> <输出.md>
"""
import re
import sys
import os

# 定点替换：(说明, 正则, 替换)
RULES = [
    # 1) 个人 Windows 用户名路径
    (r"个人 SDK 路径",
     r"C:\\Users\\64932\\AppData\\Local\\Android\\Sdk",
     r"<Android SDK>"),
    # 2) MuMu 安装路径（保留技术含义，去掉本机绝对路径）
    (r"MuMu 安装路径",
     r"C:\\Program Files\\MuMuVMMVbox\\Hypervisor",
     r"<MuMu 安装目录>\\MuMuVMMVbox\\Hypervisor"),
    # 3) 签名证书标识（别名 / CN / 指纹）——只改"与 keystore 同一句"的，
    #    以免误伤项目名 "KSSMA-Re Java 嵌入式服务器"
    (r"证书别名/CN（keystore 句）",
     r"（CN=KSSMA-Re）",
     r"（证书自行生成，不入任何仓库）"),
    (r"证书指纹",
     r"，SHA-256 `f3e9900a[0-9a-f…]*`",
     r""),
    # 4) 仓库内绝对路径 → 相对路径
    (r"仓库绝对路径",
     r"D:\\MyFlie\\AI\\zcode\\workspace\\kssma\\kssma_apk\\",
     r""),
    # 5) 同级参考项目绝对路径 → 相对描述
    (r"参考项目绝对路径",
     r"D:\\MyFlie\\AI\\zcode\\workspace\\kssma\\",
     r"..\\"),
]

HEADER = """# KSSMA 自建服务器 · 完整技术档案

## 关于本文档

本文档记录 **KSSMA 离线自建服务器**项目的技术实现细节，面向想理解或二次开发的人。

**请先明确以下几点：**

- 本文档**不包含游戏本体**，也**不包含任何 Square Enix 素材**
- 本项目与 **Square Enix / 盛大游戏无任何关联**
- 文档中出现的协议格式、域名、加密常量等，均来自**对客户端的技术分析**，
  仅用于**兼容性目的**（让客户端能与本地服务器通信）
- 本项目**不破解付费内容**，不做任何绕过官方验证的行为；它把客户端指向一个
  **完全本地**的服务器实现，用于在官方服务终止后继续单机游玩
- 请**不要分发**合并后的 APK（含原始素材，属二次分发）
- 若版权方有异议，将立即下架

---

"""


def main():
    if len(sys.argv) < 3:
        raise SystemExit(__doc__)
    src, dst = sys.argv[1], sys.argv[2]
    with open(src, encoding="utf-8") as f:
        text = f.read()

    report = []
    for desc, pattern, repl in RULES:
        new, n = re.subn(pattern, repl, text)
        report.append((desc, n))
        text = new

    # 去掉正文标题里的重复 H1（保留 HEADER 的）
    text = re.sub(r"\A# KSSMA 自建服务器 · 完整技术档案\r?\n", "", text, count=1)
    out = HEADER + text.lstrip("\n")

    with open(dst, "w", encoding="utf-8") as f:
        f.write(out)

    print("输出 %s" % dst)
    print("  输入 %d 行 / 输出 %d 行" % (
        text.count("\n") + 1, out.count("\n") + 1))
    print("  替换统计：")
    for desc, n in report:
        print("    %-24s %d 处" % (desc, n))

    # 校验：不应再有个人路径或证书标识
    left = []
    for pat, label in ((r"64932", "个人用户名"),
                       (r"C:\\Users\\", "Windows 用户路径"),
                       (r"D:\\MyFlie", "本机仓库路径"),
                       (r"CN=KSSMA-Re", "keystore CN"),
                       (r"kssma-re`", "keystore 别名"),
                       (r"f3e9900a", "证书指纹")):
        if re.search(pat, out):
            left.append(label)
    if left:
        print("  **仍残留：%s**" % "、".join(left))
        sys.exit(1)
    print("  脱敏校验通过 ✓")


if __name__ == "__main__":
    main()
