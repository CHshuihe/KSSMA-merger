# -*- coding: utf-8 -*-
"""KSSMA Merger —— 把原版客户端离线化。

模块划分：
    validate.py  输入校验（SHA256 白名单、资源完整性）
    zipio.py     ZIP 读取与忠实施重建（复用压缩流、4 字节对齐）
    patch.py     字节级补丁应用（等长原地改写 + 三重校验）
    apkbuild.py  核心合并流程
    sign.py      v1 签名（JAR 签名）
    signv2.py    v2/v3 签名（APK Signing Block）
    report.py    产出自查报告
"""

__version__ = "0.1.0"
