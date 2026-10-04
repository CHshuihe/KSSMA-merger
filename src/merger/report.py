# -*- coding: utf-8 -*-
"""自查报告：把合并产物"逐条目哈希"写出来，便于用户独立核对。

为什么需要它：
    本项目的一致性目标是**内容等价**（每个条目的字节与官方修复版相同），
    而不是整个 zip 逐字节相同（签名与 zip 元数据必然不同）。
    所以给用户一份可核对的清单，比"看起来装上了"更有说服力。
"""
import hashlib
import json
import os
import time
import zipfile

from . import __version__


def hash_zip_entries(apk_path, progress=None):
    """返回 {条目名: sha256}（流式读取，避免整包进内存）。"""
    out = {}
    with zipfile.ZipFile(apk_path) as z:
        infos = [i for i in z.infolist() if not i.is_dir()]
        total = len(infos)
        for n, i in enumerate(infos):
            h = hashlib.sha256()
            with z.open(i) as f:
                while True:
                    b = f.read(1 << 20)
                    if not b:
                        break
                    h.update(b)
            out[i.filename] = h.hexdigest()
            if progress:
                progress(n + 1, total)
    return out


def write_report(path, apk_path, report, base=None, res=None, artifacts=None,
                 hi_op=False, signed=True):
    """写出 merge-report.json。"""
    entries = hash_zip_entries(apk_path)
    doc = {
        "tool": "KSSMA Merger",
        "version": __version__,
        "generated_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "output": {
            "path": os.path.basename(apk_path),
            "size": os.path.getsize(apk_path),
            "sha256": _file_sha256(apk_path),
            "entry_count": len(entries),
        },
        "inputs": {
            "base_apk": base,
            "base_apk_sha256": (report.get("base") or {}).get("sha256"),
            "resource_zip": res,
            "resource_zip_payload": (report.get("res") or {}).get("payload"),
            "artifacts_dir": artifacts,
            "high_quality_op": bool(hi_op),
            "signed": bool(signed),
        },
        "merged": {
            "replaced": report.get("replaced", []),
            "dropped_original_signature": report.get("dropped", []),
            "added_count": len(report.get("added", [])),
        },
        # 全部条目哈希：供用户逐条与官方修复版核对
        "entries": entries,
    }
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(doc, f, indent=1, ensure_ascii=False, sort_keys=True)
    os.replace(tmp, path)
    return doc


def _file_sha256(path, chunk=1 << 22):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        while True:
            b = f.read(chunk)
            if not b:
                break
            h.update(b)
    return h.hexdigest()


def compare_with_reference(apk_a, apk_b, ignore_prefixes=("META-INF/",)):
    """比较两个 APK 的条目内容；返回 (相同数, 不同列表, 仅A, 仅B)。"""
    ha = hash_zip_entries(apk_a)
    hb = hash_zip_entries(apk_b)

    def skip(n):
        return any(n.startswith(p) for p in ignore_prefixes)

    ka = {k for k in ha if not skip(k)}
    kb = {k for k in hb if not skip(k)}
    same = [k for k in ka & kb if ha[k] == hb[k]]
    diff = [k for k in ka & kb if ha[k] != hb[k]]
    only_a = sorted(ka - kb)
    only_b = sorted(kb - ka)
    return len(same), sorted(diff), only_a, only_b
