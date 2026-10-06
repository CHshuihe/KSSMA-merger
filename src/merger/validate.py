# -*- coding: utf-8 -*-
"""输入校验：原版 APK、资源包、修正数据。

设计原则：**宁可拒绝，也不要产出坏包**。
历史上这个项目吃够了"资源不完整 → 引擎缺图 → native 崩溃"的苦，
所以这里对两边都做严格校验，并且错误信息说人话。
"""
import hashlib
import os
import zipfile

# ── 支持的原版 APK（SHA256 白名单）──────────────────────────
BASE_APK_SHA256 = "4f6a854c49d1af59bb5500828d2bdda0767f4d6a9fcfa8d4d6e46ea9257c58a7"
BASE_APK_SIZE = 304626421
BASE_APK_NAME = "com.square_enix.million_cn-1.0.0.100.0712.M330.apk"
BASE_APK_ENTRIES = 801

# 原版里必须存在的条目
BASE_APK_REQUIRED = [
    "classes.dex",
    "AndroidManifest.xml",
    "resources.arsc",
    "lib/armeabi/librooneyj.so",
    "res/raw/movie_op.mp4",
]

# 修正后的指纹（用于确认补丁打对了）
PATCHED = {
    # 原 4 个 native 补丁 → 36a4826b…；M24 rarity7 修复（首版漏掉 getRarity 调用，M24b 已修正）→ e410d845…
    "lib/armeabi/librooneyj.so":
        "e410d84589e79de193f18c634adfeef76e761ebfbb1e58d4b5c62a0368e8a642",
    "AndroidManifest.xml":
        "6606290528a25a561f93de262b2dbb25614e57cfdaf0cb14903a6daa6024f778",
    "classes.dex":
        "27f840e812d29fa6d93047d0762607f757784b9dc49589893658adc4550a2585",
}

# ── 支持的资源包 ──────────────────────────────────────────
RES_ZIP_SHA256 = "d311c8fc3152be328fa36638f2075f01b95a8aab2dea47f918db3101f18d69f5"
RES_ZIP_SIZE = 501845065
RES_ZIP_ENTRIES = 6932
RES_ZIP_ROOT = "sdcard/Android/data/com.square_enix.million_cn/files/save/"
# 粗略护栏（防"拿错文件"或"包被截断"）；真正权威是下面的 SHA256 校验。
# 实测正确资源包在此前缀下有 6895 个文件项，故留出余量。
RES_ZIP_MIN_FILES = 6800

# 资源包里必须存在的关键路径（相对 files/save/；缺这些会导致崩溃或明显缺图）
# 这些是**实测**存在于 140330 包中的条目族。
RES_ZIP_REQUIRED = [
    "download/rest/",            # 图片/界面素材
    "download/image/card/",      # 卡面
    "download/image/face/",      # 立绘
    "download/scenario/",        # 剧情
    "download/sound/",           # 音效
    "database/",                 # 客户端侧数据表
]


# appdata 载荷（**M23 关键，不能跳过**）：客户端启动时用它判断"本地卡表是否可用"。
# 一旦缺它或它全零，客户端在 GLRenderer.nativeInitialize 里会**删除**
# save/database/master_card，且不会重新下载 → 引擎卡表为空 → 图鉴等卡牌页
# _Card::getCountryId() 读 NULL+8 直接 SIGSEGV（MuMu 实测必崩）。
RES_ZIP_APPDATA = "appdata/save_appdata"
RES_ZIP_SAVE_VERSION = "appdata/save_version"


class ValidationError(Exception):
    """校验失败（带人话说明）。"""


def sha256_file(path, progress=None, chunk=1 << 22):
    h = hashlib.sha256()
    total = os.path.getsize(path)
    done = 0
    with open(path, "rb") as f:
        while True:
            b = f.read(chunk)
            if not b:
                break
            h.update(b)
            done += len(b)
            if progress:
                progress(done, total)
    return h.hexdigest()


def _looks_like_apk(path):
    if not zipfile.is_zipfile(path):
        return False
    with zipfile.ZipFile(path) as z:
        names = set(z.namelist())
    return "AndroidManifest.xml" in names


def validate_base_apk(path, progress=None, strict_hash=True):
    """校验原版 APK；返回 {"sha256":..., "entries": n}。"""
    if not os.path.isfile(path):
        raise ValidationError("找不到原版 APK 文件：%s" % path)
    if not _looks_like_apk(path):
        raise ValidationError(
            "这个文件不像 Android APK（缺少 AndroidManifest.xml）：\n  %s" % path)

    size = os.path.getsize(path)
    if size != BASE_APK_SIZE:
        raise ValidationError(
            "原版 APK 大小不符。\n"
            "  期望 %d 字节（%.1f MB）\n  实际 %d 字节（%.1f MB）\n"
            "本项目只支持特定版本的原版客户端，请确认你用的是未修改过的 "
            "2013 年国服 %s。" % (BASE_APK_SIZE, BASE_APK_SIZE / 1048576,
                                  size, size / 1048576, BASE_APK_NAME))

    with zipfile.ZipFile(path) as z:
        names = set(z.namelist())
    missing = [n for n in BASE_APK_REQUIRED if n not in names]
    if missing:
        raise ValidationError("原版 APK 缺少关键条目（可能被其它工具改过）：\n  "
                              + "\n  ".join(missing))

    digest = sha256_file(path, progress)
    if strict_hash and digest != BASE_APK_SHA256:
        raise ValidationError(
            "原版 APK 指纹不符。\n"
            "  期望 SHA256 %s\n  实际 SHA256 %s\n"
            "说明你手上的不是本项目支持的版本（或已被修改）。\n"
            "出于安全考虑，合并器不做「硬打补丁」——版本不符会产出无法启动的包。"
            % (BASE_APK_SHA256, digest))

    return {"sha256": digest, "entries": len(names), "size": size}


def validate_resource_zip(path, deep=False, progress=None, strict_hash=True):
    """校验资源包；返回 {"sha256":..., "entries":..., "payload": n}。"""
    if not os.path.isfile(path):
        raise ValidationError("找不到资源包文件：%s" % path)
    if not zipfile.is_zipfile(path):
        raise ValidationError("资源包不是有效的 zip：%s" % path)

    with zipfile.ZipFile(path) as z:
        infos = z.infolist()
    names = [i.filename for i in infos]

    root = RES_ZIP_ROOT
    payload = [n for n in names if n.startswith(root) and not n.endswith("/")]
    if len(payload) < RES_ZIP_MIN_FILES:
        # 兼容：也可能用户给的是"已剥掉 sdcard 前缀"的变体
        alt_root = "Android/data/com.square_enix.million_cn/files/save/"
        root = alt_root
        payload = [n for n in names if n.startswith(alt_root) and not n.endswith("/")]
        if len(payload) < RES_ZIP_MIN_FILES:
            raise ValidationError(
                "资源包内容不符（在预期路径下只找到 %d 个文件，至少需要 %d 个）。\n"
                "  期望路径前缀：%s\n"
                "请使用配套的 140330 资源包（约 478 MB、约 6900 个文件）。"
                % (len(payload), RES_ZIP_MIN_FILES, RES_ZIP_ROOT))

    # 关键内容检查（按"是否有文件以该串开头"判断，兼容目录项与文件项）
    marker = "files/save/"
    rel = []
    for n in payload:
        i = n.find(marker)
        if i >= 0:
            rel.append(n[i + len(marker):])
    missing = [r for r in RES_ZIP_REQUIRED if not any(x.startswith(r) for x in rel)]
    if missing:
        raise ValidationError(
            "资源包缺少关键内容（合并后客户端会崩或缺图）：\n  "
            + "\n  ".join(missing))

    info = {"entries": len(names), "payload": len(payload)}

    # ★ appdata 硬门禁（M23）：资源包里必须有非全零的 appdata/save_appdata。
    #   这不是"可选资源"——缺了它客户端会删掉卡表，之后卡牌相关页面必崩。
    appdata_name = root + RES_ZIP_APPDATA
    if appdata_name not in names:
        raise ValidationError(
            "资源包缺少 appdata 载荷：%s\n"
            "  这个文件是客户端判断本地卡表是否可用的依据，缺了它客户端会删掉\n"
            "  save/database/master_card → 引擎卡表为空 → 图鉴等卡牌页面 native 崩溃。\n"
            "  请使用配套的 140330 资源包。" % appdata_name)
    with zipfile.ZipFile(path) as z:
        blob = z.read(appdata_name)
    if not any(b != 0 for b in blob):
        raise ValidationError(
            "资源包里的 appdata 载荷**全为零**（%d 字节）：%s\n"
            "  全零 appdata 同样会让客户端删掉 save/database/master_card。\n"
            "  请使用配套的 140330 资源包（其 save_appdata 有 %d 个非零字节）。"
            % (len(blob), appdata_name, 118))
    info["appdata_bytes"] = len(blob)
    info["appdata_nonzero"] = sum(1 for b in blob if b != 0)
    if (root + RES_ZIP_SAVE_VERSION) not in names:
        info["save_version"] = "missing"
    if strict_hash or deep:
        digest = sha256_file(path, progress)
        info["sha256"] = digest
        if strict_hash and digest != RES_ZIP_SHA256:
            raise ValidationError(
                "资源包指纹不符。\n  期望 SHA256 %s\n  实际 SHA256 %s"
                % (RES_ZIP_SHA256, digest))
    return info


def validate_artifacts(artifacts_dir):
    """校验修正数据目录；返回各文件的绝对路径。"""
    need = {
        "classes2.dex": os.path.join("classes2.dex"),
        "classes.dex": os.path.join("classes-dex", "classes.dex"),
        "manifest": os.path.join("manifest", "AndroidManifest.xml"),
        "so_patch": os.path.join("patches", "librooneyj.so.patch.json"),
        "manifest_patch": os.path.join("patches", "manifest.xml.patch.json"),
    }
    out = {}
    missing = []
    for key, rel in need.items():
        p = os.path.join(artifacts_dir, rel)
        if os.path.isfile(p):
            out[key] = p
        else:
            missing.append(rel)
    for sub in ("kssma-data", "database", "seeds"):
        p = os.path.join(artifacts_dir, sub)
        if os.path.isdir(p):
            out[sub] = p
        elif sub != "seeds":            # seeds 允许缺失（会警告，但不致命）
            missing.append(sub + "/")
    if missing:
        raise ValidationError(
            "修正数据不完整（缺少以下项）：\n  " + "\n  ".join(missing)
            + "\n\n请下载完整的修正数据包，或用 --artifacts 指定正确目录。")
    return out
