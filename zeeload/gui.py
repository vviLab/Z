"""zeeload.gui — 图形界面（参照 docs/gui-preview.png 的黑金版式）。

运行：
    python3 -m zeeload.gui [apk1.apk apk2.apk ...]

设计要点（与 TUI 一致的地方都放在 zeeload.common）：
  * 一轮一进程：每次「开始」都是引擎的一次完整调用，卸 pf / 停 mitmdump 由引擎自己收尾
  * 状态不靠猜：全部来自引擎已经打印的那些前缀（[inject-update] / [replace-apk] / E1x）
  * 需要 root 的动作只在「开始」时提权；提权失败直接说清楚，不静默降级
"""

from __future__ import annotations

import os
import subprocess
import sys
import threading

try:
    import tkinter as tk
    from tkinter import filedialog, messagebox, scrolledtext
except ImportError as _exc:  # 没装 Tk 的解释器（如 Homebrew 3.14）
    tk = None
    _TK_ERROR = _exc
else:
    _TK_ERROR = None

try:
    from . import common
except ImportError:  # 直接跑文件时（python3 zeeload/gui.py）
    import sys as _sys
    _sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    from zeeload import common

# ---------------------------------------------------------------- 配色（与 logo.svg 同源）

BG = "#0B0B0D"          # 页面底
PANEL = "#131215"       # 卡片
FIELD = "#0F0E11"       # 输入框
LOG_BG = "#08080A"      # 日志区
BORDER = "#3B301C"
BORDER_SOFT = "#251F14"
GOLD = "#C79A3F"        # 主按钮填充
GOLD_LIGHT = "#F6DFA6"
GOLD_PALE = "#FFF7E6"
GOLD_DIM = "#8B7A56"
TEXT = "#D8C9A6"
MUTED = "#6B6252"
OK = "#8FD1A0"
WARN = "#E2B457"
ERR = "#E07A6B"

UI_FONT = "PingFang SC"
MONO_FONT = "Menlo"


class ZEEloadApp:
    def __init__(self, root: tk.Tk, apks: list[str]) -> None:
        self.root = root
        self.round = common.Round()
        self.queue: list[str] = []
        self.apk = common.ApkInfo(path="")
        self._closing = False
        self._pending_apk: str = ""

        self.apk_var = tk.StringVar(value="")
        self.info_var = tk.StringVar(value="尚未选择 APK")
        self.pkg_var = tk.StringVar(value="ALL")
        self.out_var = tk.StringVar(value=os.path.join(common.ROOT, "logs"))
        self.status_var = tk.StringVar(value="就绪")
        self.env_var = tk.StringVar(value="正在检测运行环境…")
        self.progress_var = tk.StringVar(value="待开始")

        if apks:
            self._pending_apk = apks[0]
            self.queue = apks[1:]

        self._setup_window()
        self._build_ui()
        self.root.after(120, self._drain)
        if self._pending_apk:
            self._load_apk(self._pending_apk)
        threading.Thread(target=self._detect_env, daemon=True).start()

    # ---------------------------------------------------------------- 外观

    def _setup_window(self) -> None:
        self.root.title("ZEEload · 极载")
        self.root.configure(bg=BG)
        self.root.geometry("1000x880")
        self.root.minsize(860, 700)
        try:
            self.root.tk.call("tk", "scaling", 1.35)
        except tk.TclError:
            pass
        self.root.protocol("WM_DELETE_WINDOW", self._on_close)

    def _card(self, parent: tk.Misc, title: str) -> tuple[tk.Frame, tk.Frame]:
        """带标题的卡片：外框细线 + 内边距，对应预览图里的圆角分区。"""
        outer = tk.Frame(parent, bg=BORDER)
        inner = tk.Frame(outer, bg=PANEL)
        inner.pack(fill="both", expand=True, padx=1, pady=1)
        head = tk.Frame(inner, bg=PANEL)
        head.pack(fill="x", padx=18, pady=(14, 6))
        tk.Label(head, text=title, bg=PANEL, fg=GOLD_LIGHT,
                 font=(UI_FONT, 12, "bold")).pack(side="left")
        body = tk.Frame(inner, bg=PANEL)
        body.pack(fill="both", expand=True, padx=18, pady=(0, 14))
        return outer, body

    def _btn(self, parent: tk.Misc, text: str, command, kind: str = "ghost") -> tk.Button:
        base = dict(text=text, command=command, font=(UI_FONT, 11), relief="flat",
                    bd=0, padx=16, pady=7, cursor="hand2", highlightthickness=0)
        if kind == "primary":
            return tk.Button(parent, bg=GOLD, fg="#1A1206", activebackground=GOLD_LIGHT,
                             activeforeground="#1A1206", **base)
        return tk.Button(parent, bg=FIELD, fg=TEXT, activebackground=BORDER,
                         activeforeground=GOLD_PALE, highlightbackground=BORDER, **base)

    def _entry(self, parent: tk.Misc, var: tk.StringVar, width: int | None = None) -> tk.Entry:
        kw = dict(textvariable=var, bg=FIELD, fg=TEXT, insertbackground=GOLD_LIGHT,
                  relief="flat", bd=0, highlightthickness=1,
                  highlightbackground=BORDER, highlightcolor=GOLD_DIM,
                  font=(UI_FONT, 11))
        if width:
            kw["width"] = width
        return tk.Entry(parent, **kw)

    def _build_ui(self) -> None:
        # ---------- 品牌区 ----------
        header = tk.Frame(self.root, bg=BG)
        header.pack(fill="x", padx=22, pady=(18, 14))
        logo = self._load_logo()
        if logo is not None:
            self._logo = logo
            tk.Label(header, image=logo, bg=BG, bd=0).pack(side="left", padx=(0, 16))
        titles = tk.Frame(header, bg=BG)
        titles.pack(side="left", anchor="w")
        word = tk.Frame(titles, bg=BG)
        word.pack(anchor="w")
        tk.Label(word, text="ZEEload", bg=BG, fg=GOLD_PALE, font=(UI_FONT, 20, "bold")).pack(side="left")
        tk.Label(word, text="极载", bg=BG, fg=GOLD_LIGHT, font=(UI_FONT, 20, "bold")).pack(side="left", padx=(10, 0))
        tk.Label(titles, text="车机 APK 侧载 · 无需 root / adb / 证书",
                 bg=BG, fg=GOLD_DIM, font=(UI_FONT, 9)).pack(anchor="w", pady=(3, 0))
        tk.Label(header, text="MACOS", bg=PANEL, fg=GOLD_LIGHT, font=(MONO_FONT, 8, "bold"),
                 padx=12, pady=5, highlightbackground=BORDER, highlightthickness=1).pack(side="right", anchor="n")
        tk.Frame(self.root, bg=GOLD, height=2).pack(fill="x")

        # ---------- 状态栏（先占底部）----------
        tk.Frame(self.root, bg=BORDER_SOFT, height=1).pack(fill="x", side="bottom")
        bar = tk.Frame(self.root, bg=LOG_BG)
        bar.pack(fill="x", side="bottom")
        tk.Label(bar, textvariable=self.env_var, bg=LOG_BG, fg=GOLD_DIM,
                 font=(UI_FONT, 9), anchor="w").pack(side="left", padx=22, pady=6)
        tk.Label(bar, text="仅限自有车辆的研究 / 自用，请勿用于他人车辆",
                 bg=LOG_BG, fg=MUTED, font=(UI_FONT, 8)).pack(side="right", padx=22)

        body = tk.Frame(self.root, bg=BG)
        body.pack(fill="both", expand=True, padx=22, pady=(16, 4))

        # ---------- 1. APK ----------
        apk_card, apk = self._card(body, "1  选择要安装的 APK")
        apk_card.pack(fill="x")
        row = tk.Frame(apk, bg=PANEL)
        row.pack(fill="x")
        self._entry(row, self.apk_var).pack(side="left", fill="x", expand=True, ipady=8)
        self._btn(row, "浏览…", self._browse_apk).pack(side="left", padx=(10, 0))
        self._btn(row, "队列…", self._browse_queue).pack(side="left", padx=(8, 0))
        tk.Label(apk, textvariable=self.info_var, bg=PANEL, fg=GOLD_DIM,
                 font=(UI_FONT, 9), anchor="w").pack(fill="x", pady=(8, 0))

        # ---------- 2. 运行选项 ----------
        opt_card, opt = self._card(body, "2  运行选项")
        opt_card.pack(fill="x", pady=(14, 0))
        opt.columnconfigure(1, weight=1)
        tk.Label(opt, text="注入包名", bg=PANEL, fg=TEXT, font=(UI_FONT, 10)).grid(row=0, column=0, sticky="w")
        self._entry(opt, self.pkg_var, width=26).grid(row=0, column=1, sticky="w", padx=10, ipady=6)
        tk.Label(opt, text="ALL = 匹配所有应用的更新请求；也可填 com.zeekr.xxx",
                 bg=PANEL, fg=MUTED, font=(UI_FONT, 9)).grid(row=0, column=2, sticky="w")

        tk.Label(opt, text="输出目录", bg=PANEL, fg=TEXT, font=(UI_FONT, 10)).grid(
            row=1, column=0, sticky="w", pady=(10, 0))
        self._entry(opt, self.out_var).grid(row=1, column=1, sticky="ew", padx=10, pady=(10, 0), ipady=6)
        self._btn(opt, "浏览…", self._browse_out).grid(row=1, column=2, sticky="w", pady=(10, 0))

        tk.Label(opt, text="队列（一轮一个，装完可换下一个）", bg=PANEL, fg=TEXT,
                 font=(UI_FONT, 10)).grid(row=2, column=0, sticky="w", pady=(10, 0))
        self.queue_lbl = tk.Label(opt, text=self._queue_text(), bg=PANEL, fg=GOLD_DIM,
                                  font=(UI_FONT, 9), anchor="w", justify="left")
        self.queue_lbl.grid(row=2, column=1, columnspan=2, sticky="w", padx=10, pady=(10, 0))

        # ---------- 操作 ----------
        actions = tk.Frame(body, bg=BG)
        actions.pack(fill="x", pady=(16, 0))
        self.start_btn = self._btn(actions, "开始", self._start, kind="primary")
        self.start_btn.pack(side="left")
        self.stop_btn = self._btn(actions, "停止", self._stop)
        self.stop_btn.pack(side="left", padx=(10, 0))
        self.stop_btn.configure(state="disabled")
        self.next_btn = self._btn(actions, "下一个", self._next)
        self.next_btn.pack(side="left", padx=(10, 0))
        self.next_btn.configure(state="disabled")
        self._btn(actions, "打开输出目录", self._open_out).pack(side="left", padx=(10, 0))
        self._btn(actions, "清空日志", self._clear_log).pack(side="left", padx=(10, 0))
        self._btn(actions, "环境检查", self._diagnose).pack(side="left", padx=(10, 0))
        tk.Label(actions, textvariable=self.status_var, bg=BG, fg=GOLD_DIM,
                 font=(UI_FONT, 10, "bold")).pack(side="right")

        # ---------- 3. 日志 ----------
        log_card, log_inner = self._card(body, "3  运行日志")
        log_card.pack(fill="both", expand=True, pady=(14, 12))
        self.log = scrolledtext.ScrolledText(
            log_inner, height=14, wrap="word", font=(MONO_FONT, 9),
            bg=LOG_BG, fg=TEXT, insertbackground=GOLD_LIGHT, relief="flat", bd=0,
            highlightthickness=0, padx=12, pady=10,
            selectbackground="#3B301C", selectforeground=GOLD_PALE)
        self.log.pack(fill="both", expand=True)
        self.log.configure(state="disabled")
        for tag, color in (("ok", OK), ("warn", WARN), ("err", ERR), ("hi", GOLD_LIGHT), ("dim", GOLD_DIM)):
            self.log.tag_configure(tag, foreground=color)

    def _load_logo(self) -> tk.PhotoImage | None:
        for name in ("logo-128.png", "logo-256.png"):
            path = os.path.join(common.ROOT, "assets", name)
            if os.path.isfile(path):
                try:
                    return tk.PhotoImage(file=path)
                except tk.TclError:
                    pass
        return None

    def _queue_text(self) -> str:
        if not self.queue:
            return "队列为空：装完一个后可以点「下一个」再选；也可一次选多个"
        names = "、".join(os.path.basename(p) for p in self.queue[:4])
        more = f" 等 {len(self.queue)} 个" if len(self.queue) > 4 else ""
        return f"队列还剩 {len(self.queue)} 个：{names}{more}"

    # ---------------------------------------------------------------- 环境
    def _detect_env(self) -> None:
        exe = common.find_mitmdump()
        ver, ok = common.mitmdump_version(exe) if exe else ("未找到", False)
        iface, ip = common.detect_iface()
        car, _mac = common.detect_lease(ip.rsplit(".", 1)[0] + "." if ip else "")
        parts = [
            f"mitmdump {'✓ ' + ver if ok else '✗ 缺少或版本过低'}",
            f"共享接口 {iface or '✗ 未检测到'}",
            f"车机 {car or '未检测到'}",
        ]
        self._post(self.env_var.set, "    |    ".join(parts))

    def _diagnose(self) -> None:
        out = os.path.join(self.out_var.get().strip() or os.path.join(common.ROOT, "logs"), "")
        script = os.path.join(common.ROOT, "scripts", "check-environment.sh")
        if not os.path.isfile(script):
            messagebox.showinfo("环境检查", "找不到 scripts/check-environment.sh")
            return
        self._append("\n=== 环境检查（只读，不需要管理员）===\n")
        try:
            p = subprocess.run(["bash", script], capture_output=True, text=True, timeout=40)
            self._append((p.stdout or "") + (p.stderr or ""))
        except Exception as exc:
            self._append(f"[界面] 环境检查失败：{exc!r}\n")

    # ---------------------------------------------------------------- 交互
    def _browse_apk(self) -> None:
        path = filedialog.askopenfilename(title="选择 APK", filetypes=[("APK", "*.apk"), ("所有文件", "*")])
        if path:
            self._load_apk(path)

    def _browse_queue(self) -> None:
        paths = filedialog.askopenfilenames(title="选择要排队的 APK（按选择顺序）",
                                            filetypes=[("APK", "*.apk"), ("所有文件", "*")])
        if not paths:
            return
        self.queue.extend(p for p in paths if os.path.abspath(p) != os.path.abspath(self.apk.path))
        self.queue_lbl.configure(text=self._queue_text())
        self.next_btn.configure(state="normal")
        self._append(f"[i] 已加入 {len(paths)} 个 APK 到队列\n")

    def _browse_out(self) -> None:
        path = filedialog.askdirectory(title="选择输出目录")
        if path:
            self.out_var.set(path)

    def _load_apk(self, path: str) -> None:
        self.apk = common.ApkInfo(path=path)
        self.apk_var.set(path)
        self.info_var.set("正在读取哈希…")
        common.describe_apk_async(path, self._on_apk)

    def _on_apk(self, info: common.ApkInfo) -> None:
        self.apk = info
        if info.ok:
            self.info_var.set(f"{info.mib}    sha256 {info.sha256[:24]}…")
        else:
            self.info_var.set(f"✗ {info.error}")

    def _open_out(self) -> None:
        path = self.out_var.get().strip() or os.path.join(common.ROOT, "logs")
        subprocess.Popen(["open", path])

    def _clear_log(self) -> None:
        self.log.configure(state="normal")
        self.log.delete("1.0", "end")
        self.log.configure(state="disabled")

    def _append(self, text: str) -> None:
        tag = None
        s = text.lstrip()
        if s.startswith("[ok]"):
            tag = "ok"
        elif s.startswith("警告") or s.startswith("[..]"):
            tag = "warn"
        elif s.startswith("错误") or s.startswith("E1") or s.startswith("E2"):
            tag = "err"
        elif s.startswith("[inject-update]") or s.startswith("[replace-apk]"):
            tag = "hi"
        elif s.startswith("[i]"):
            tag = "dim"
        self.log.configure(state="normal")
        self.log.insert("end", text, tag or ())
        self.log.see("end")
        self.log.configure(state="disabled")

    def _post(self, fn, *args) -> None:
        self.root.after(0, lambda: fn(*args))

    def _drain(self) -> None:
        if self._closing:
            return
        self.root.after(120, self._drain)

    # ---------------------------------------------------------------- 运行
    def _start(self) -> None:
        if self.round.running:
            return
        if not self.apk.path or not self.apk.ok:
            messagebox.showwarning("还没有 APK", "请先选择要安装的 APK。")
            return
        busy = common.port_busy()
        if busy:
            messagebox.showerror("端口被占用", f"{common.PORT} 被 {busy} 占用。\n先点「停止」，或运行『停止并恢复.command』。")
            return
        outdir = self.out_var.get().strip() or os.path.join(common.ROOT, "logs")
        os.makedirs(outdir, exist_ok=True)

        args = common.engine_args(self.apk.path, self.pkg_var.get().strip() or "ALL")
        self._clear_log()
        self._append(f"$ {' '.join(args)}\n\n")
        self._set_running(True, "运行中…")
        self.progress_var.set("启动")
        self.round = common.Round()
        self.round.start(args, self._on_line, self._on_exit)

    def _on_line(self, line: str, rnd: common.Round) -> None:
        self._post(self._append, line + "\n")
        st = rnd.state
        if st.phase:
            self._post(self.progress_var.set, st.phase)
        if st.error:
            self._post(self.status_var.set, st.error)

    def _on_exit(self, code: int, rnd: common.Round) -> None:
        hint = common.EXIT_HINT.get(code, f"引擎退出码 {code}，详情见日志")
        self._post(self._after_round, code, hint)

    def _after_round(self, code: int, hint: str) -> None:
        self._set_running(False, hint)
        self.progress_var.set("待开始")
        done = code in (common.EXIT_OK, common.EXIT_INTERRUPTED)
        if done and self.queue:
            self.next_btn.configure(state="normal")
            self.status_var.set(f"{hint}  还剩 {len(self.queue)} 个，点「下一个」继续")
        else:
            self.next_btn.configure(state="normal" if self.queue else "normal")

    def _next(self) -> None:
        if self.round.running:
            messagebox.showinfo("先停止", "本轮还在跑，先点「停止」再换下一个。")
            return
        if self.queue:
            path = self.queue.pop(0)
        else:
            path = filedialog.askopenfilename(title="选择下一个 APK",
                                              filetypes=[("APK", "*.apk"), ("所有文件", "*")])
            if not path:
                return
        self._load_apk(path)
        self.queue_lbl.configure(text=self._queue_text())
        self.status_var.set(f"已换成 {os.path.basename(path)}，点「开始」")

    def _stop(self) -> None:
        if self.round.running:
            self.round.stop()
            self.status_var.set("已请求停止本轮…")

    def _set_running(self, running: bool, status: str) -> None:
        self.status_var.set(status)
        self.start_btn.configure(state="disabled" if running else "normal")
        self.stop_btn.configure(state="normal" if running else "disabled")

    def _on_close(self) -> None:
        if self.round.running:
            if not messagebox.askyesno("还在运行", "本轮还在跑，退出会停止它并卸载 pf 规则。继续吗？"):
                return
            self.round.stop()
        self._closing = True
        self.root.destroy()


def run(apks: list[str] | None = None) -> int:
    if tk is None:
        print("这个 Python 没带 Tk，图形界面起不来。")
        print("  换带 Tk 的解释器：ZEEKR_PY=/usr/bin/python3 ./zeeload.command")
        print("  或改用终端界面：./zeeload.command --tui")
        return 2
    root = tk.Tk()
    ZEEloadApp(root, apks or [])
    root.mainloop()
    return 0


def main(argv: list[str] | None = None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    apks = [a for a in argv if os.path.isfile(a)]
    return run(apks)


if __name__ == "__main__":
    sys.exit(main())
