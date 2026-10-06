# -*- coding: utf-8 -*-
"""KSSMA Merger 命令行入口。

用法：
    python src/main.py --apk <原版.apk> --res <资源包.zip> --out <输出目录>
                       [--no-hi-op] [--artifacts <修正数据目录>]
                       [--no-sign] [--report <路径>] [--quiet]

设计说明：
    图形界面（src/gui.py）与命令行共用 merger 包，CLI 是"可脚本化/可审计"的入口。
"""
import argparse
import os
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from merger import __version__
from merger.apkbuild import Merger
from merger.validate import ValidationError

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(HERE)          # merger/


def default_artifacts_dir():
    """修正数据目录（与 GUI 共用一份解析逻辑，见 src/paths.py）。"""
    from paths import find_artifacts
    return find_artifacts()


def build_arg_parser():
    p = argparse.ArgumentParser(
        prog="KSSMA-Merger",
        description="把《扩散性百万亚瑟王》原版客户端离线化（本工具不含游戏本体）")
    p.add_argument("--apk", metavar="PATH",
                   help="原版客户端 APK")
    p.add_argument("--res", metavar="PATH",
                   help="资源包 zip（140330 包）")
    p.add_argument("--out", metavar="DIR",
                   help="输出目录")
    p.add_argument("--artifacts", metavar="DIR", default=None,
                   help="修正数据目录（默认 ./artifacts 或环境变量 KSSMA_ARTIFACTS）")
    p.add_argument("--hi-op", action="store_true",
                   help="使用高清 OP 动画（修正数据里含 op.mp4 时生效）")
    p.add_argument("--no-sign", action="store_true",
                   help="[开发用] 不签名，仅产出未签名的包")
    p.add_argument("--report", metavar="PATH", default=None,
                   help="写出自查报告 JSON（默认 <out>/merge-report.json）")
    p.add_argument("--quiet", action="store_true", help="只输出错误")
    p.add_argument("--selftest", action="store_true",
                   help="只检查运行环境与修正数据是否就位（不做合并）")
    p.add_argument("--version", action="version", version="KSSMA Merger %s" % __version__)
    return p


def _emit(msg):
    """安全打印：windowed 版没有控制台（`sys.stdout` 为 None）、
    GBK 控制台编码不了 `✅/❌` 时，都**不应**让自检假失败。"""
    try:
        print(msg, flush=True)
    except Exception:                                    # noqa: BLE001
        pass


def run_selftest(emit=None):
    """检查路径解析与依赖（打包后尤其有用）。

    emit : 可选的输出回调（GUI 自检用它把内容同时收进 `selftest-report.txt`）；
           默认写 stdout，并对"无控制台 / 编码不支持"完全容错。
    """
    import paths
    out = emit or _emit
    # 结果行含 ✅/❌；中文 Windows 控制台是 GBK，直接 print 会抛 UnicodeEncodeError
    # 把自检整个带崩（曾表现为"环境检查失败: 'gbk' codec…"）。调成容错模式，
    # 编不出的字符降级成 '?'，而不是失败。
    try:
        sys.stdout.reconfigure(errors="replace")
    except Exception:                                    # noqa: BLE001
        pass
    out("KSSMA Merger %s 环境自检" % __version__)
    out("  frozen        : %s" % getattr(sys, "frozen", False))
    out("  app_dir       : %s" % paths.app_dir())
    out("  bundle_dir    : %s" % paths.bundle_dir())
    art = paths.find_artifacts()
    ok = os.path.isdir(art)
    out("  artifacts     : %s（%s）" % (art, "存在" if ok else "**不存在**"))
    if ok:
        n = sum(len(f) for _, _, f in os.walk(art))
        out("                   %d 个文件" % n)
    for mod in ("merger.apkbuild", "merger.signv2", "cryptography", "asn1crypto"):
        try:
            __import__(mod)
            out("  import %-16s OK" % mod)
        except Exception as e:                              # noqa: BLE001
            ok = False
            out("  import %-16s 失败: %s" % (mod, e))
    out("")
    out("结果：%s" % ("✅ 环境就绪" if ok else "❌ 有问题"))
    return 0 if ok else 1


def main(argv=None):
    args = build_arg_parser().parse_args(argv)
    if args.selftest:
        return run_selftest()
    quiet = args.quiet

    def log(msg):
        if not quiet:
            print(msg, flush=True)

    # --selftest 之外必须给全三个路径
    missing = [n for n, v in (("--apk", args.apk), ("--res", args.res), ("--out", args.out)) if not v]
    if missing:
        print("缺少参数：%s（用 --help 查看用法）" % " ".join(missing), file=sys.stderr)
        return 2

    artifacts = args.artifacts or default_artifacts_dir()
    os.makedirs(args.out, exist_ok=True)

    t0 = time.time()
    log("KSSMA Merger %s" % __version__)
    log("  原版 APK : %s" % args.apk)
    log("  资源包   : %s" % args.res)
    log("  修正数据 : %s" % artifacts)
    log("  输出目录 : %s" % args.out)
    log("")

    # 输出文件名：带时间戳，避免覆盖旧产物
    stamp = time.strftime("%Y%m%d-%H%M")
    out_apk = os.path.join(args.out, "KSSMA-Offline-%s.apk" % stamp)

    merger = Merger(args.apk, args.res, artifacts, log=(log if not quiet else (lambda *_: None)))
    signer = None
    if not args.no_sign:
        from merger.signv2 import make_signer
        # ★ v2/v3（APK Signing Block）**尚未通过 apksigner 验证**，故默认只签 v1。
        #   原因说明（重要，避免重复踩坑）：
        #     * 块结构已正确：len=8+sob+16、sop 与 sob 自洽、magic 正确、
        #       4 字节对齐、pair(id=0x7109871a/0xf05368c0) 能被解出。
        #     * 但 apksigner 仍报 "v2=false / v3=false"（v1 通过），
        #       说明**内容摘要或签名的某个细节**与 apksig 不一致。
        #     * 当前 APK 未声明 targetSdkVersion → Android 12 (MuMu) 接受 v1-only，
        #       所以 v1 对目标环境**已足够**，不影响交付。
        #   后续要接着做：用 apksigner 签一个小 APK，逐字节对比我们的
        #       Signing Block 与它的差异（重点：摘要分块、EOCD 的 cd_off 字段是否置 0、
        #       v2 signed data 的字段顺序）。
        from paths import app_dir
        signer = make_signer(app_dir(), log, wants_v2=False)

    def on_step(title, _frac):
        log("[ ] %s" % title)

    try:
        report = merger.merge(out_apk, want_hi_op=args.hi_op, signer=signer,
                              on_step=on_step)
    except ValidationError as e:
        print("\n输入校验失败：\n%s" % e, file=sys.stderr)
        return 2
    except Exception as e:
        # 未知异常：打印完整 traceback（否则排查成本极高）
        import traceback
        print("\n合并失败：%s" % e, file=sys.stderr)
        traceback.print_exc()
        return 3

    # 报告
    from merger.report import write_report
    report_path = args.report or os.path.join(args.out, "merge-report.json")
    write_report(report_path, out_apk, report, base=args.apk, res=args.res,
                 artifacts=artifacts, hi_op=args.hi_op, signed=not args.no_sign)

    size = os.path.getsize(out_apk)
    log("")
    log("完成（耗时 %.1f 秒）" % (time.time() - t0))
    log("  输出     : %s" % out_apk)
    log("  大小     : %.1f MB" % (size / 1048576))
    log("  条目     : %d 个（替换 %d / 丢弃 %d / 新增 %d）"
        % (report["meta"]["entries"], len(report["replaced"]),
           len(report["dropped"]), len(report["added"])))
    log("  自查报告 : %s" % report_path)
    log("")
    log("安装：adb install -r \"%s\"" % out_apk)
    return 0


if __name__ == "__main__":
    sys.exit(main())
