# -*- mode: python ; coding: utf-8 -*-
"""PyInstaller 打包配置（KSSMA Merger GUI）。

打包策略：**onedir + windowed**（不是 onefile）
--------------------------------------------------
曾用 onefile，实测在本机直接失败：

    [PYI-…:ERROR] Could not create temporary directory!

onefile 每次启动都要把 ~120 MB 自解压到 `%TEMP%`；体积这么大时既慢又容易失败，
而且 105 MB 的 `artifacts` 会被反复解压。改为 onedir 后：

    * 启动是**即时**的（不再自解压），所以也不需要 splash 启动画面
    * 对 100 MB 级的资源更合适

分发方式：把 `dist/KSSMA-Merger/` 整个文件夹打包给用户（exe 必须在文件夹内运行，
不能单独拷出来）。

`keystore/` 不打进包：运行时在 exe 同级生成——不能让每次运行的签名密钥都变。

构建：
    pyinstaller --clean --noconfirm packaging/KSSMA-Merger.spec    （在 merger/ 下执行）
    产物：dist/KSSMA-Merger/KSSMA-Merger.exe
"""
import os

HERE = os.path.abspath(SPECPATH)                 # merger/packaging
REPO = os.path.dirname(HERE)                     # merger/
SRC = os.path.join(REPO, "src")
ART = os.path.join(REPO, "artifacts")

if not os.path.isdir(ART):
    raise SystemExit("找不到 artifacts 目录：%s" % ART)

a = Analysis(
    [os.path.join(SRC, "gui.py")],
    pathex=[SRC],
    binaries=[],
    datas=[(ART, "artifacts")],                  # 运行时 _MEIPASS/artifacts
    hiddenimports=[
        "merger", "merger.apkbuild", "merger.patch", "merger.report",
        "merger.sign", "merger.signv2", "merger.validate", "merger.zipio",
        "cryptography", "cryptography.hazmat.primitives.asymmetric.padding",
        "cryptography.hazmat.primitives.asymmetric.rsa",
        "cryptography.hazmat.primitives.hashes",
        "cryptography.hazmat.primitives.serialization",
        "cryptography.hazmat.primitives.serialization.pkcs12",
        "cryptography.x509",
        "asn1crypto", "asn1crypto.cms", "asn1crypto.x509",
        "asn1crypto.algos", "asn1crypto.core",
    ],
    hookspath=[],
    runtime_hooks=[],
    excludes=[
        "numpy", "pandas", "matplotlib", "PIL", "scipy", "IPython",
        "pytest", "setuptools", "pip", "test", "unittest",
        "tkinter.test", "lib2to3",
    ],
    noarchive=False,
)

pyz = PYZ(a.pure)

exe = EXE(
    pyz,
    a.scripts,
    [],
    exclude_binaries=True,                       # onedir：二进制交给 COLLECT
    name="KSSMA-Merger",
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=False,                                   # UPX 拖慢启动且易被误报
    console=False,                               # 窗口程序，不弹黑框
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
)

coll = COLLECT(
    exe,
    a.binaries,
    a.datas,
    strip=False,
    upx=False,
    upx_exclude=[],
    name="KSSMA-Merger",
)
