# -*- coding: utf-8 -*-
"""核心合并：原版 APK + 资源包 + 修正数据 → 新 APK。

合并顺序（**保留原版条目顺序**，替换项就位，新增项追加）：

    1. 原版全部条目（逐条搬运；被替换的三项在写到该位置时改用新内容）
       - classes.dex          ← 修正数据（成品 dex）
       - AndroidManifest.xml  ← 原版 manifest 打 41 字节补丁后
       - lib/.../librooneyj.so← 原版 .so 打 54 区间补丁后
    2. 移除原版的 META-INF/ 签名文件（必须，否则视为篡改）
    3. 追加 assets/kssma-data/（12）、assets/database/（6）、assets/save/（~6932）
    4. 追加 classes2.dex（本地服务器）
    5. 写 META-INF/ 签名（v1；v2/v3 由 signv2 在之后追加）

为什么替换 `.so`/manifest 而不用修正数据里的成品：那两处是**等长原地补丁**，
对用户自己的文件打，比替换更安全（版本不符会立即失败，而不是产出坏包）。
"""
import hashlib
import json
import os
import posixpath
import zlib

from . import validate
from .zipio import (ApkWriter, BytesSource, CopySource, RawSource, WriteEntry,
                    ZipReader, DOS_EPOCH)
from .patch import apply_patch_bytes

# 原版里会被替换/移除的条目
REPLACED = {
    "classes.dex": "classes.dex",
    "AndroidManifest.xml": "manifest_patch",
    "lib/armeabi/librooneyj.so": "so_patch",
}
DROP_PREFIXES = ("META-INF/",)          # 原签名文件全部丢弃

# 输出里的压缩策略（与已验证的参考版一致）：
#   - AndroidManifest.xml：DEFLATED
#   - 其余全部 STORED（含 classes.dex / .so / 资源）
# 为什么几乎不压缩：引擎直接按偏移读资源，STORED 省掉解压开销；
# 代价是 APK 更大（约 900 MB），但实测参考版就是这么做的，
# 我们保持一致以避免体积/行为差异。
DEFLATED_NAMES = {"AndroidManifest.xml"}


def method_for(name):
    return 8 if name in DEFLATED_NAMES else 0


class MergeError(Exception):
    pass


class Merger:
    def __init__(self, base_apk, res_zip, artifacts, log=print):
        self.base_apk = base_apk
        self.res_zip = res_zip
        self.artifacts = artifacts
        self.log = log
        self.report = {"entries": [], "replaced": [], "dropped": [], "added": []}

    # ── 辅助 ──
    def _load_patch(self, path):
        with open(path, encoding="utf-8") as f:
            return json.load(f)

    # ── 主流程 ──
    def merge(self, out_path, want_hi_op=False, signer=None, on_step=None):
        step = on_step or (lambda *a: None)

        step("校验原版 APK", 0)
        base_info = validate.validate_base_apk(self.base_apk)
        self.log("  原版 APK 校验通过（%d 条目，%.1f MB）"
                 % (base_info["entries"], base_info["size"] / 1048576))

        step("校验资源包", 0)
        res_info = validate.validate_resource_zip(self.res_zip, deep=False)
        self.log("  资源包校验通过（%d 条目，其中 %d 个有效载荷）"
                 % (res_info["entries"], res_info["payload"]))

        step("加载修正数据", 0)
        art = validate.validate_artifacts(self.artifacts)
        so_patch = self._load_patch(art["so_patch"])
        man_patch = self._load_patch(art["manifest_patch"])
        self.log("  修正数据就绪（.so 补丁 %d 区间 / manifest 补丁 %d 区间）"
                 % (so_patch["region_count"], man_patch["region_count"]))

        with ZipReader(self.base_apk) as src, ZipReader(self.res_zip) as res:
            # ── 准备替换内容 ──
            step("准备替换内容", 0)
            new_dex = open(art["classes.dex"], "rb").read()
            new_manifest = apply_patch_bytes(src.read("AndroidManifest.xml"), man_patch)
            new_so = apply_patch_bytes(src.read("lib/armeabi/librooneyj.so"), so_patch)
            for name, blob, want in (
                    ("classes.dex", new_dex, validate.PATCHED["classes.dex"]),
                    ("AndroidManifest.xml", new_manifest, validate.PATCHED["AndroidManifest.xml"]),
                    ("lib/armeabi/librooneyj.so", new_so, validate.PATCHED["lib/armeabi/librooneyj.so"])):
                got = hashlib.sha256(blob).hexdigest()
                if got != want:
                    raise MergeError("替换项 %s 指纹不符\n  期望 %s\n  实际 %s"
                                     % (name, want, got))
            self.log("  替换项指纹全部核对通过（classes.dex / manifest / librooneyj.so）")

            # ── 写新 zip ──
            step("组装 APK", 0)
            w = ApkWriter(out_path)
            replaced_done = set()

            for e in src.entries:
                if e.is_dir:
                    continue
                if any(e.name.startswith(p) for p in DROP_PREFIXES):
                    self.report["dropped"].append(e.name)
                    continue
                if e.name in REPLACED:
                    key = REPLACED[e.name]
                    if key == "classes.dex":
                        blob = new_dex
                    elif key == "manifest_patch":
                        blob = new_manifest
                    else:
                        blob = new_so
                    w.add(WriteEntry(e.name, BytesSource(blob, method_for(e.name)), method_for(e.name),
                                     e.date_time, e.external_attr))
                    self.report["replaced"].append(e.name)
                    replaced_done.add(e.name)
                    continue
                # 原样搬运（压缩方式统一按 method_for 归一化）
                m = method_for(e.name)
                if m == e.method:
                    w.add(WriteEntry(e.name, CopySource(src, e), e.method,
                                     e.date_time, e.external_attr))
                else:
                    # 需要换压缩方式：解压后重压（只涉及少量小文件）
                    w.add(WriteEntry(e.name, BytesSource(src.read(e.name), m), m,
                                     e.date_time, e.external_attr))

            # ── 追加新增内容 ──
            step("写入游戏资源", 0)
            added = self._add_assets(w, res, art, want_hi_op)
            self.log("  新增 %d 个条目" % added)

            # ── 签名（v1：写 META-INF/*）──
            # 必须在写完所有条目、关闭 writer 之前追加；
            # v2/v3 的 Signing Block 必须插在**中央目录之前**，所以通过 close() 的
            # signing_block 回调在写 CD 前插入（见 zipio.ApkWriter.close）。
            if signer is not None:
                step("签名 v1", 0)
                n_sign = signer.write_v1(w)
                self.log("  已写入 v1 签名（%d 个 META-INF 条目，覆盖 %d 个文件）"
                         % (3, n_sign))

            if signer is not None and getattr(signer, "wants_v2", False):
                step("签名 v2/v3", 0)
                meta = w.close(signing_block=signer.build_block)
                self.log("  已插入 v2/v3 Signing Block（中央目录之前）")
            else:
                meta = w.close()

        self.report["meta"] = meta
        self.report["base"] = base_info
        self.report["res"] = res_info
        return self.report

    # ── 新增资源 ──
    def _add_assets(self, w, res, art, want_hi_op):
        added = 0

        # 0) classes2.dex（本地服务器；在 artifacts 根目录）
        c2 = os.path.join(self.artifacts, "classes2.dex")
        if os.path.isfile(c2):
            blob = open(c2, "rb").read()
            w.add(WriteEntry("classes2.dex", BytesSource(blob, method_for("classes2.dex")),
                             method_for("classes2.dex")))
            self.report["added"].append("classes2.dex")
            added += 1

        # 1) assets/kssma-data/（12 个，含 game/ 与 server/；op.mp4 可选）
        kd = art["kssma-data"]
        for dirpath, _dirnames, filenames in os.walk(kd):
            for fn in sorted(filenames):
                p = os.path.join(dirpath, fn)
                rel = os.path.relpath(p, kd).replace(os.sep, "/")
                if rel == "op.mp4" and not want_hi_op:
                    continue                 # 不勾选 → 沿用原版 OP
                blob = open(p, "rb").read()
                name = "assets/kssma-data/" + rel
                m = method_for(name)
                w.add(WriteEntry(name, BytesSource(blob, m), m))
                self.report["added"].append(name)
                added += 1

        # 2) assets/database/（6 张二进制表，各自独立文件）
        db = art["database"]
        for dirpath, _dirnames, filenames in os.walk(db):
            for fn in sorted(filenames):
                p = os.path.join(dirpath, fn)
                rel = os.path.relpath(p, db).replace(os.sep, "/")
                blob = open(p, "rb").read()
                name = "assets/database/" + rel
                w.add(WriteEntry(name, BytesSource(blob, 0), 0))
                self.report["added"].append(name)
                added += 1

        # 3) 补种资源（**关键**）：引擎对缺图零容忍，缺一张就 native 崩溃。
        #    这些图既不在原版 APK、也不在资源包里（当年 CDN 下发，CDN 已死）。
        if "seeds" in art:
            sd = art["seeds"]
            n_seed = 0
            for dirpath, _dirnames, filenames in os.walk(sd):
                for fn in sorted(filenames):
                    p = os.path.join(dirpath, fn)
                    name = os.path.relpath(p, sd).replace(os.sep, "/")
                    blob = open(p, "rb").read()
                    w.add(WriteEntry(name, BytesSource(blob, 0), 0))
                    self.report["added"].append(name)
                    added += 1
                    n_seed += 1
            if n_seed:
                self.log("  补种资源 %d 个（缺图会导致 native 崩溃，必须带上）" % n_seed)

        # 4) assets/save/（从资源包搬运；原样复制，不重压）
        root = validate.RES_ZIP_ROOT
        appdata_written = False
        for e in res.entries:
            if e.is_dir or not e.name.startswith(root):
                continue
            rel = e.name[len(root):]
            if not rel:
                continue
            # ★ appdata/ 必须随包发（M23 实证，别再跳过）：
            #   资源包里这份 save_appdata / save_version 是**非零原版**
            #   （save_appdata 2849 B / 118 非零字节，与主 dist 包同一份，sha256 59c228bf…）。
            #   以前这里 `rel.startswith("appdata/")` 直接跳过，后果是合成器打出的包：
            #     ①客户端 nativeInitialize 读到全零/缺失的 appdata
            #       → 删掉 save/database/master_card（设备日志：削除しました:…/master_card）
            #     ②引擎卡表为空 → 图鉴 _Card::getCountryId() 读 NULL+8 → SIGSEGV（MuMu 实测必崩）
            #     ③KssmaBoot.healZeroSaveAppdata 依赖 assets/save/appdata/save_appdata 自愈，
            #       缺这个 asset 时只能打 "save_appdata heal skipped: asset missing"。
            name = "assets/save/" + rel
            if rel == "appdata/save_appdata":
                appdata_written = True
            m = method_for(name)
            if m == e.method:
                w.add(WriteEntry(name, CopySource(res, e), m, e.date_time,
                                 e.external_attr))
            else:
                # 资源包里部分是 DEFLATED，输出统一归一到 STORED（与参考版一致）
                w.add(WriteEntry(name, BytesSource(res.read(e.name), m), m,
                                 e.date_time, e.external_attr))
            added += 1

        if not appdata_written:
            raise RuntimeError(
                "内部错误：assets/save/appdata/save_appdata 没有写进包里。\n"
                "  它是客户端判断本地卡表是否可用的依据：缺了客户端会删掉 "
                "save/database/master_card，\n"
                "  引擎卡表为空 → 图鉴等卡牌页面 _Card::getCountryId() 读 NULL+8 崩溃（M23 实证）。")

        return added
