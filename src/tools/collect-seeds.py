# -*- coding: utf-8 -*-
"""收集"补种资源"（seeds）——**我方内部工具**，不随合并器分发给用户。

背景（这条是血泪换来的）：
    客户端引擎对缺图**零容忍**：`loadBitmap` 返回 null → native 未判空 → ART JniAbort 崩溃。
    历史上因此出现过"合成/出售时随机闪退"（缺 thumbnail_chara_168）与
    "扭蛋选卡闪退"（缺 5161..5170 缩略图）。
    这些图**既不在原版 APK 里、也不在 140330 资源包里**，是当年 CDN 下发、
    CDN 已死的那一批，必须由我们补种。

本工具从一份**已知可用**的修复版 APK 里，把这类"补种条目"提取出来，
放进 `artifacts/seeds/`（保持 APK 内路径结构），供合并器写回。

定义（seed 的判据）：
    参考 APK 里有、但 (原版 APK ∪ 资源包映射) 里没有的条目，
    且**排除**下列由其它路径处理的类别：
      META-INF/                    —— 签名，合并器自己生成
      assets/database/             —— 由 artifacts/database 提供
      assets/kssma-data/           —— 由 artifacts/kssma-data 提供
      assets/save/appdata/         —— 由资源包直接搬运（**必须带**，见 apkbuild/validate 的 M23 门禁）
      classes2.dex                 —— 由 artifacts/classes2.dex 提供
      assets/kssma-data/op.mp4     —— 可选高清 OP，由 --hi-op 控制

用法：
    python collect-seeds.py <参考APK> <原版APK> <资源包.zip> <输出目录>
"""
import os
import sys
import zipfile

RES_ROOT = "sdcard/Android/data/com.square_enix.million_cn/files/save/"

EXCLUDE_PREFIXES = (
    "META-INF/",
    "assets/database/",
    "assets/kssma-data/",
    "assets/save/appdata/",
)
EXCLUDE_EXACT = ("classes2.dex",)


def map_resource_zip(res_zip):
    """资源包 → APK 内路径集合（与合并器的映射规则一致）。"""
    out = set()
    with zipfile.ZipFile(res_zip) as z:
        for i in z.infolist():
            if i.is_dir() or not i.filename.startswith(RES_ROOT):
                continue
            rel = i.filename[len(RES_ROOT):]
            if rel.startswith("appdata/"):
                continue
            out.add("assets/save/" + rel)
    return out


def collect(ref_apk, base_apk, res_zip, out_dir, log=print):
    with zipfile.ZipFile(ref_apk) as zr:
        ref = {i.filename: i for i in zr.infolist() if not i.is_dir()}
    with zipfile.ZipFile(base_apk) as zb:
        base = set(i.filename for i in zb.infolist() if not i.is_dir())
    mapped = map_resource_zip(res_zip)

    seeds = []
    for name in sorted(ref):
        if name in base or name in mapped:
            continue
        if name.startswith(EXCLUDE_PREFIXES) or name in EXCLUDE_EXACT:
            continue
        seeds.append(name)

    total = 0
    with zipfile.ZipFile(ref_apk) as zr:
        for name in seeds:
            dst = os.path.join(out_dir, name.replace("/", os.sep))
            os.makedirs(os.path.dirname(dst), exist_ok=True)
            blob = zr.read(name)
            with open(dst, "wb") as f:
                f.write(blob)
            total += len(blob)
            log("  + %-62s %9d" % (name, len(blob)))

    log("")
    log("补种条目 %d 个，合计 %.2f MB" % (len(seeds), total / 1048576))
    return seeds


def main():
    if len(sys.argv) < 5:
        raise SystemExit(__doc__)
    ref, base, res, out = sys.argv[1:5]
    os.makedirs(out, exist_ok=True)
    collect(ref, base, res, out)


if __name__ == "__main__":
    main()
