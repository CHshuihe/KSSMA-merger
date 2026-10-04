# -*- coding: utf-8 -*-
"""KSSMA Merger 图形界面（tkinter）。

设计要点：
    * **合并跑在后台线程**，主线程只更新 UI —— 否则 900 MB 的复制会让窗口假死
    * 线程通过 `queue` 把消息交回主线程，用 `after()` 轮询（tkinter 非线程安全）
    * 打包成 exe 后，`artifacts` 相对**可执行文件**解析（PyInstaller 的 `_MEIPASS`）
    * 不做任何联网行为

用法：
    python src/gui.py
"""
import os
import queue
import subprocess
import sys
import threading
import time

import tkinter as tk
from tkinter import filedialog, messagebox, ttk

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from merger import __version__                      # noqa: E402
from paths import find_artifacts                     # noqa: E402

HERE = os.path.dirname(os.path.abspath(__file__))


from paths import app_dir as _app_dir, bundle_dir as _bundle_dir, find_artifacts


class App:
    POLL_MS = 100

    def __init__(self, root):
        self.root = root
        self.q = queue.Queue()
        self.worker = None
        self.cancel_flag = threading.Event()
        self.out_apk = None

        root.title("KSSMA 离线化合并器 v%s" % __version__)
        root.geometry("760x560")
        root.minsize(680, 500)

        self._build_ui()
        self._prefill()
        self.root.after(self.POLL_MS, self._poll)

    # ── UI ──────────────────────────────────────────
    def _build_ui(self):
        pad = {"padx": 10, "pady": 4}

        head = ttk.Frame(self.root)
        head.pack(fill="x", **pad)
        ttk.Label(head, text="把《扩散性百万亚瑟王》原版客户端离线化",
                  font=("", 13, "bold")).pack(anchor="w")
        ttk.Label(head, foreground="#666",
                  text="本工具不含游戏本体，需要你自备原版 APK 与资源包。"
                       "合并结果仅供个人在自己设备上使用，请勿分发。").pack(anchor="w")

        files = ttk.LabelFrame(self.root, text="输入文件")
        files.pack(fill="x", **pad)
        files.columnconfigure(1, weight=1)

        self.apk_var = tk.StringVar()
        self.res_var = tk.StringVar()
        self.out_var = tk.StringVar()

        self._row(files, 0, "原版 APK", self.apk_var, self._pick_apk)
        self._row(files, 1, "资源包 zip", self.res_var, self._pick_res)
        self._row(files, 2, "输出目录", self.out_var, self._pick_out, is_dir=True)

        opt = ttk.LabelFrame(self.root, text="选项")
        opt.pack(fill="x", **pad)
        self.hi_op_var = tk.BooleanVar(value=False)
        self.sign_var = tk.BooleanVar(value=True)
        ttk.Checkbutton(opt, variable=self.hi_op_var,
                        text="使用高清 OP 动画（+100 MB，逐帧超分）").grid(
            row=0, column=0, sticky="w", padx=10, pady=2)
        ttk.Checkbutton(opt, variable=self.sign_var,
                        text="签名（自签名 v1；不签则需自行签名才能安装）").grid(
            row=1, column=0, sticky="w", padx=10, pady=2)
        ttk.Label(opt, foreground="#666",
                  text="修正数据目录：%s" % find_artifacts()).grid(
            row=2, column=0, sticky="w", padx=10, pady=(2, 6))

        run = ttk.Frame(self.root)
        run.pack(fill="x", **pad)
        self.start_btn = ttk.Button(run, text="开始合并", command=self._start)
        self.start_btn.pack(side="left")
        self.open_btn = ttk.Button(run, text="打开输出目录",
                                   command=self._open_out, state="disabled")
        self.open_btn.pack(side="left", padx=6)
        self.progress = ttk.Progressbar(run, mode="determinate", maximum=100)
        self.progress.pack(side="left", fill="x", expand=True, padx=10)

        logf = ttk.LabelFrame(self.root, text="进度")
        logf.pack(fill="both", expand=True, **pad)
        self.log = tk.Text(logf, height=12, wrap="word", state="disabled",
                           background="#fbfbfb", relief="flat")
        sb = ttk.Scrollbar(logf, command=self.log.yview)
        self.log.configure(yscrollcommand=sb.set)
        sb.pack(side="right", fill="y")
        self.log.pack(side="left", fill="both", expand=True)

    def _row(self, parent, r, label, var, cmd, is_dir=False):
        ttk.Label(parent, text=label).grid(row=r, column=0, sticky="w",
                                           padx=10, pady=3)
        ttk.Entry(parent, textvariable=var).grid(row=r, column=1, sticky="ew",
                                                 pady=3)
        ttk.Button(parent, text="浏览…", width=8,
                   command=lambda: cmd(is_dir)).grid(row=r, column=2,
                                                     padx=8, pady=3)

    def _prefill(self):
        """尽量从常见位置自动填好，减少用户操作。"""
        for cand in ("com.square_enix.million_cn-1.0.0.100.0712.M330.apk",):
            for base in (os.path.join(os.path.expanduser("~"), "Downloads"),
                         os.path.expanduser("~"), _app_dir()):
                p = os.path.join(base, cand)
                if os.path.isfile(p):
                    self.apk_var.set(p)
                    break
        for base in (os.path.join(os.path.expanduser("~"), "Downloads"),
                     os.path.expanduser("~"), _app_dir()):
            try:
                for n in os.listdir(base):
                    if n.endswith(".zip") and "million" in n.lower():
                        self.res_var.set(os.path.join(base, n))
                        break
            except OSError:
                pass
            if self.res_var.get():
                break
        # 默认输出目录：优先用**程序自己所在的文件夹**。
        # 实测依据（2026-10 用户实机复现）：安全软件会拦截本程序"往非程序目录
        # 写 900 MB 大文件"（输出到主目录 / %TEMP% / 任意其它目录都报
        # Permission denied，即使该目录权限完全正常）；而输出到 exe 自身
        # 文件夹可以正常写完 799.8 MB。故默认选它最省事。
        exe_dir = _app_dir()
        default_out = os.path.join(exe_dir, "output")
        try:
            os.makedirs(default_out, exist_ok=True)
            probe = os.path.join(default_out, ".kssma-write-test")
            with open(probe, "wb") as f:
                f.write(b"ok")
            os.remove(probe)
            self.out_var.set(default_out)
        except OSError:
            # 程序目录不可写（例如装在 Program Files）→ 退回用户主目录
            self.out_var.set(os.path.join(os.path.expanduser("~"), "KSSMA-Offline"))

    # ── 选择文件 ────────────────────────────────────
    def _pick_apk(self, _is_dir=False):
        p = filedialog.askopenfilename(title="选择原版 APK",
                                       filetypes=[("APK", "*.apk"), ("所有文件", "*.*")])
        if p:
            self.apk_var.set(p)

    def _pick_res(self, _is_dir=False):
        p = filedialog.askopenfilename(title="选择资源包 zip",
                                       filetypes=[("ZIP", "*.zip"), ("所有文件", "*.*")])
        if p:
            self.res_var.set(p)

    def _pick_out(self, _is_dir=True):
        p = filedialog.askdirectory(title="选择输出目录")
        if p:
            self.out_var.set(p)

    # ── 日志 ────────────────────────────────────────
    def _say(self, msg):
        self.log.configure(state="normal")
        self.log.insert("end", msg + "\n")
        self.log.see("end")
        self.log.configure(state="disabled")

    # ── 推荐输出目录 ────────────────────────────────
    @staticmethod
    def _suggest_out():
        """给一个**实测能写**的输出目录（程序自身文件夹优先）。"""
        cand = os.path.join(_app_dir(), "output")
        try:
            os.makedirs(cand, exist_ok=True)
            probe = os.path.join(cand, ".kssma-write-test")
            with open(probe, "wb") as f:
                f.write(b"ok")
            os.remove(probe)
            return cand
        except OSError:
            return os.path.join(os.path.expanduser("~"), "KSSMA-Offline")

    # ── 输出目录预检 ────────────────────────────────
    def _check_out_dir(self, out):
        """输出目录能不能真写进去？返回错误说明（None = 没问题）。

        为什么必须预检：合并一次要写 900 MB，如果目录不可写（杀软拦截、
        权限不足、选到了只读位置），用户会等很久才拿到一句 PermissionError。
        常见成因见下面每条诊断的提示文本。
        """
        try:
            if os.path.exists(out) and not os.path.isdir(out):
                return ("这个路径是一个**文件**，不是目录：\n%s\n\n"
                        "请选择一个目录（或换一个名字）。" % out)
            os.makedirs(out, exist_ok=True)
        except PermissionError:
            return ("没有权限创建输出目录：\n%s\n\n"
                    "常见原因：\n"
                    "  · 该位置需要管理员权限（如 C:\\ 根目录、Program Files）\n"
                    "  · 被杀毒软件 / 受控文件夹访问拦截（见下）\n"
                    "  · 目标在只读盘或网络盘上\n\n"
                    "建议换成这个目录（实测可写）：\n"
                    "  %s" % (out, self._suggest_out()))
        except OSError as e:
            return "无法创建输出目录：\n%s\n\n%s" % (out, e)

        # 真写一个测试文件（比 os.access 可靠：Windows 上 access 对目录不准）
        probe = os.path.join(out, ".kssma-write-test")
        try:
            with open(probe, "wb") as f:
                f.write(b"ok")
            os.remove(probe)
        except PermissionError:
            # 走到这里说明：目录能进、但**本程序**写不进去。
            # 实测这类情况几乎都是安全软件按"程序"拦截大文件写入，
            # 而不是目录权限问题（同一个目录用别的工具能正常写）。
            good = self._suggest_out()
            return ("输出目录**不可写**：\n%s\n\n"
                    "注意：这个目录本身通常是正常的（别的程序能写），\n"
                    "被拦的是**本程序**往这里写约 900 MB 的 .apk 文件。\n"
                    "常见原因是杀毒软件的「勒索软件防护 / 受控文件夹访问」。\n\n"
                    "★ 最省事的做法：把输出目录改成下面这个（实测可写）\n"
                    "    %s\n\n"
                    "若你想继续用原目录，可以：\n"
                    "  · 把本程序加入杀毒软件白名单，或临时关闭"
                    "「受控文件夹访问 / 勒索防护」后重试；\n"
                    "  · 确认该目录里的旧 .apk 没有被其它程序（播放器、压缩软件）占用。\n\n"
                    "（提示：点「确定」后我会问你要不要直接切到上面那个可用目录）"
                    % (out, good))
        except OSError as e:
            return "输出目录写入测试失败：\n%s\n\n%s" % (out, e)

        # 剩余空间（约需 1 GB）
        try:
            import shutil as _sh
            free = _sh.disk_usage(out).free
            if free < 1100 * 1024 * 1024:
                return ("输出目录所在磁盘空间不足：\n%s\n\n"
                        "剩余 %.1f GB，合并约需 1 GB。请清理后再试。"
                        % (out, free / (1024 ** 3)))
        except OSError:
            pass
        return None

    # ── 启动合并 ────────────────────────────────────
    def _start(self):
        apk = self.apk_var.get().strip()
        res = self.res_var.get().strip()
        out = self.out_var.get().strip()
        if not apk or not os.path.isfile(apk):
            messagebox.showerror("缺少文件", "请选择原版 APK。")
            return
        if not res or not os.path.isfile(res):
            messagebox.showerror("缺少文件", "请选择资源包 zip。")
            return
        if not out:
            messagebox.showerror("缺少文件", "请选择输出目录。")
            return

        artifacts = find_artifacts()
        if not os.path.isdir(artifacts):
            messagebox.showerror(
                "缺少修正数据",
                "找不到 artifacts 目录：\n%s\n\n"
                "请确认它与本程序放在同一目录下。" % artifacts)
            return

        # ★ 输出目录预检：在真正开始（要写 900 MB）之前就把问题说清楚。
        #   之前没有这一步，用户要等合并跑起来才看到一句 PermissionError，
        #   既不知道原因也不知道怎么办。
        out = os.path.abspath(out)
        self.out_var.set(out)
        problem = self._check_out_dir(out)
        if problem:
            messagebox.showerror("输出目录不可用", problem)
            # 若是"目录正常但本程序写不进去"（安全软件拦截），主动提议切换 ——
            # 比让用户自己去别处找目录友好得多
            if "不可写" in problem:
                good = self._suggest_out()
                if os.path.abspath(good) != out and messagebox.askyesno(
                        "改用可写的目录？",
                        "要把输出目录改成下面这个吗？\n\n%s\n\n"
                        "（这是实测能正常写入的位置）" % good):
                    self.out_var.set(good)
                    self._say("输出目录已改为：%s（请再点一次「开始合并」）" % good)
            return

        self.start_btn.configure(state="disabled")
        self.open_btn.configure(state="disabled")
        self.progress.configure(value=0)
        self.out_apk = None
        self.cancel_flag.clear()
        self._say("=" * 60)
        self._say("开始合并")
        self._say("  原版 APK : %s" % apk)
        self._say("  资源包   : %s" % res)
        self._say("  修正数据 : %s" % artifacts)
        self._say("  输出目录 : %s" % out)
        self._say("")

        self.worker = threading.Thread(
            target=self._run, args=(apk, res, out, artifacts,
                                    self.hi_op_var.get(), self.sign_var.get()),
            daemon=True)
        self.worker.start()

    def _run(self, apk, res, out, artifacts, hi_op, sign):
        """后台线程：只往队列里放消息，不碰 UI。"""
        def put(kind, **kw):
            kw["kind"] = kind
            self.q.put(kw)

        try:
            os.makedirs(out, exist_ok=True)
            from merger.apkbuild import Merger
            from merger.report import write_report
            from merger.validate import ValidationError

            stamp = time.strftime("%Y%m%d-%H%M")
            out_apk = os.path.join(out, "KSSMA-Offline-%s.apk" % stamp)

            merger = Merger(apk, res, artifacts,
                            log=lambda m: put("log", text=m))
            signer = None
            if sign:
                from merger.signv2 import make_signer
                # v2/v3 尚未通过 apksigner 验证，故这里只签 v1（详见技术档案 §9b.3）
                signer = make_signer(_app_dir(), lambda m: put("log", text=m),
                                     wants_v2=False)

            def on_step(title, frac):
                put("step", title=title, frac=frac)

            t0 = time.time()
            report = merger.merge(out_apk, want_hi_op=hi_op, signer=signer,
                                  on_step=on_step)

            report_path = os.path.join(out, "merge-report.json")
            write_report(report_path, out_apk, report, base=apk, res=res,
                         artifacts=artifacts, hi_op=hi_op, signed=sign)
            put("done", apk=out_apk, report=report, elapsed=time.time() - t0,
                report_path=report_path)
        except PermissionError as e:
            # PermissionError 几乎总是“被拦”而非“没权限”，给可执行的建议
            put("fail",
                err="写入被拒绝（可能被安全软件拦截）",
                tb=("目标文件：%s\n\n"
                    "本程序会创建约 900 MB 的 .apk。若杀毒软件开启了\n"
                    "「勒索软件防护 / 受控文件夹访问」，这类写入会被拦下"
                    "（哪怕目录权限完全正常）。\n\n"
                    "建议把输出目录改成这个（实测可写）：\n  %s\n\n"
                    "或者把本程序加入杀毒软件白名单后重试。\n\n"
                    "原始错误：%s"
                    % (e.filename or "(未知)", App._suggest_out(), e)))
        except OSError as e:
            put("fail", err="文件操作失败：%s" % e, tb="原始错误：%r" % (e,))
        except Exception as e:                                  # noqa: BLE001
            import traceback
            put("fail", err=str(e), tb=traceback.format_exc())

    # ── 主线程轮询队列 ──────────────────────────────
    def _poll(self):
        try:
            while True:
                m = self.q.get_nowait()
                self._handle(m)
        except queue.Empty:
            pass
        self.root.after(self.POLL_MS, self._poll)

    def _handle(self, m):
        k = m["kind"]
        if k == "log":
            self._say(m["text"])
        elif k == "step":
            self._say("· %s" % m["title"])
            # 步骤进度：按已知步骤数给个粗略百分比
            self.progress.configure(value=min(95, self.progress["value"] + 10))
        elif k == "done":
            self.progress.configure(value=100)
            r = m["report"]
            self.out_apk = m["apk"]
            self._say("")
            self._say("✅ 完成（耗时 %.1f 秒）" % m["elapsed"])
            self._say("  输出 : %s" % m["apk"])
            self._say("  大小 : %.1f MB" % (os.path.getsize(m["apk"]) / 1048576))
            self._say("  条目 : %d 个（替换 %d / 丢弃 %d / 新增 %d）"
                      % (r["meta"]["entries"], len(r["replaced"]),
                         len(r["dropped"]), len(r["added"])))
            self._say("  报告 : %s" % m["report_path"])
            self._say("")
            self._say("安装：adb install -r \"%s\"" % m["apk"])
            self.start_btn.configure(state="normal")
            self.open_btn.configure(state="normal")
        elif k == "fail":
            self.progress.configure(value=0)
            self._say("")
            self._say("❌ 失败：%s" % m["err"])
            self._say(m.get("tb", ""))
            self.start_btn.configure(state="normal")
            messagebox.showerror("合并失败", m["err"])

    def _open_out(self):
        target = os.path.dirname(self.out_apk) if self.out_apk else self.out_var.get()
        if not target or not os.path.isdir(target):
            return
        try:
            if sys.platform.startswith("win"):
                os.startfile(target)                 # noqa: S606
            elif sys.platform == "darwin":
                subprocess.Popen(["open", target])
            else:
                subprocess.Popen(["xdg-open", target])
        except Exception as e:                       # noqa: BLE001
            messagebox.showinfo("打开失败", "请手动打开：\n%s\n\n%s" % (target, e))


def selftest(argv=None):
    """自检：验证打包后的路径解析与依赖是否可用。

    用途：交付给用户后，若不放心可跑
        KSSMA-Merger.exe --selftest
    控制台版会打印结果；windowed 版会把结果写到 selftest-report.txt。

    可选：`--selftest --apk <apk> --res <zip> --out <dir>` 会真的跑一遍合并。
    """
    argv = list(sys.argv[1:] if argv is None else argv)
    lines = []
    art = find_artifacts()

    def say(m):
        lines.append(m)
        try:
            print(m, flush=True)
        except Exception:                                # noqa: BLE001
            pass

    # 环境检查复用 CLI 那份实现（避免 GUI/CLI 两套逻辑再漂移）
    _here = os.path.dirname(os.path.abspath(__file__))
    if _here not in sys.path:
        sys.path.insert(0, _here)
    try:
        from main import run_selftest as _env_check
        ok = _env_check() == 0
    except Exception as e:                                    # noqa: BLE001
        ok = False
        say("  环境检查失败: %s" % e)

    # GUI 特有：顖外验一下 tkinter 能不能真开窗
    try:
        import tkinter as _tk
        r = _tk.Tk()
        r.withdraw()
        r.update()
        r.destroy()
        say("  tkinter 窗口    OK")
    except Exception as e:                                    # noqa: BLE001
        ok = False
        say("  tkinter 窗口    失败: %s" % e)

    if "--apk" in argv and "--res" in argv and "--out" in argv:
        apk = argv[argv.index("--apk") + 1]
        res = argv[argv.index("--res") + 1]
        out = argv[argv.index("--out") + 1]
        say("")
        say("  跑一次真实合并…")
        try:
            from merger.apkbuild import Merger
            from merger.signv2 import make_signer
            os.makedirs(out, exist_ok=True)
            target = os.path.join(out, "selftest-out.apk")
            s = make_signer(_app_dir(), lambda m: say("    " + m), wants_v2=False)
            rep = Merger(apk, res, art, log=lambda m: say("    " + m)).merge(
                target, signer=s, on_step=lambda t, f: say("    · %s" % t))
            say("  合并成功：%.1f MB，%d 条目"
                % (os.path.getsize(target) / 1048576, rep["meta"]["entries"]))
        except Exception as e:                                # noqa: BLE001
            ok = False
            import traceback
            say("  合并失败：%s" % e)
            say(traceback.format_exc())

    say("")
    say("结果：%s" % ("✅ 全部通过" if ok else "❌ 有失败项"))

    # windowed 模式没有控制台，落一份文件方便查看
    try:
        with open(os.path.join(_app_dir(), "selftest-report.txt"), "w",
                  encoding="utf-8") as f:
            f.write("\n".join(lines) + "\n")
    except OSError:
        pass
    return 0 if ok else 1


def main():
    # ── 参数分派 ────────────────────────────────
    # 1) 自检
    if "--selftest" in sys.argv:
        return selftest()
    # 2) 带合并参数时走命令行。
    #    否则这些参数会被**静默忽略**，直接开 GUI 干等——
    #    打包成 exe 后 `--apk … --res … --out …` 就是这样
    #    “跑很久然后什么都没发生”。
    if any(a in sys.argv for a in ("--apk", "--res", "--out", "--artifacts",
                                   "--hi-op", "--no-sign", "--report", "--quiet")):
        from main import main as cli_main
        return cli_main()
    # 3) 否则开图形界面
    root = tk.Tk()
    try:
        root.call("tk", "scaling", 1.2)
    except tk.TclError:
        pass
    App(root)
    root.mainloop()
    return 0


if __name__ == "__main__":
    sys.exit(main())
