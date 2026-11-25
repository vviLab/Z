"""zeeload.tui — 终端界面（零第三方依赖）。

与 GUI 共用 zeeload.common：一线程跑引擎、一行行解析状态。界面只负责画与按键。
配色与 GUI 同源（#0B0B0D 底 / #E9CE93 金），直接写 ANSI，不需要装 rich。
"""

from __future__ import annotations

import curses
import os
import time
from typing import Callable

try:
    from . import common
except ImportError:  # 直接跑文件时（python3 zeeload/tui.py）
    import sys as _sys, os as _os
    _sys.path.insert(0, _os.path.dirname(_os.path.dirname(_os.path.abspath(__file__))))
    from zeeload import common

# 与 assets/logo.svg、GUI 同一套色
PAIRS = {
    "gold": (0xE9, 0xCE, 0x93),
    "gold_light": (0xF6, 0xDF, 0xA6),
    "gold_dim": (0x8B, 0x7A, 0x56),
    "text": (0xD8, 0xC9, 0xA6),
    "muted": (0x6B, 0x62, 0x52),
    "ok": (0x8F, 0xD1, 0xA0),
    "warn": (0xE2, 0xB4, 0x57),
    "err": (0xE0, 0x7A, 0x6B),
    "border": (0x3B, 0x30, 0x1C),
}


def _fit(s: str, width: int) -> str:
    """按显示宽度截断（CJK 记 2 列）。"""
    out, w = "", 0
    for ch in s:
        cw = 2 if ord(ch) > 0x1100 and (
            ch >= "\u1100" and not ("\u2000" <= ch <= "\u206f")
        ) else 1
        if w + cw > width:
            break
        out += ch
        w += cw
    return out + " " * (width - w)


def _dwidth(s: str) -> int:
    return sum(2 if ord(c) > 0x2E7F else 1 for c in s)


class Tui:
    def __init__(self, stdscr, apks: list[str], outdir: str, pkg: str) -> None:
        self.std = stdscr
        self.apk = common.describe_apk(apks[0]) if apks else common.ApkInfo(path="")
        self.queue = apks[1:]
        self.outdir = outdir
        self.pkg = pkg
        self.round = common.Round()
        self.log: list[str] = []
        self.log_scroll = 0
        self.status = "就绪"
        self.status_kind = "gold"
        self.phase = "待开始"
        self.iface = ""
        self.car = ""
        self.injects = 0
        self.replaced = 0
        self.started_at = 0.0
        self.need_next_prompt = False

    # ---------------------------------------------------------------- 绘制
    def _init_colors(self) -> None:
        curses.start_color()
        try:
            curses.use_default_colors()
            bg = -1
        except curses.error:
            bg = curses.COLOR_BLACK
        for i, (name, (r, g, b)) in enumerate(PAIRS.items(), start=1):
            try:
                curses.init_color(i + 100, r * 1000 // 255, g * 1000 // 255, b * 1000 // 255)
                curses.init_pair(i, i + 100, bg)
            except curses.error:
                curses.init_pair(i, i, bg)
        self.c = {name: curses.color_pair(i) for i, name in enumerate(PAIRS, start=1)}

    def _add(self, y: int, x: int, text: str, color: str = "text", width: int | None = None) -> None:
        try:
            if width is not None:
                text = _fit(text, width)
            self.std.addstr(y, x, text, self.c.get(color, 0))
        except curses.error:
            pass

    def _box(self, y: int, x: int, h: int, w: int, title: str) -> None:
        """画边框；窗口比盒子小时整体跳过，不抛异常。"""
        try:
            my, mx = self.std.getmaxyx()
            if h < 3 or w < 4 or y + h > my or x + w > mx:
                return
            col = self.c.get("border", 0)
            # ACS_* 是 window 上的属性，不是模块级常量（模块上取会 AttributeError）
            chal = getattr(self.std, "ACS_HLINE", "-")
            cver = getattr(self.std, "ACS_VLINE", "|")
            cplu = getattr(self.std, "ACS_PLUS", "+")
            self.std.attron(col)
            self.std.hline(y, x, chal, w)
            self.std.hline(y + h - 1, x, chal, w)
            self.std.vline(y, x, cver, h)
            self.std.vline(y, x + w - 1, cver, h)
            for cx, cy in ((x, y), (x + w - 1, y), (x, y + h - 1), (x + w - 1, y + h - 1)):
                self.std.addch(cy, cx, cplu)
            self.std.attroff(col)
            if title:
                self._add(y, x + 2, f" {title} ", "gold_light")
        except Exception:
            pass

    def draw(self) -> None:
        std = self.std
        std.erase()
        h, w = std.getmaxyx()

        # 品牌行
        self._add(0, 1, "ZEEload", "gold_light")
        self._add(0, 9, "极载", "gold")
        self._add(0, 14, "车机 APK 侧载 · 无需 root / adb / 证书", "muted")
        self._add(0, max(0, w - 12), "TUI", "gold_dim")

        # 状态条
        env = f"接口 {self.iface or '未检测'}  车机 {self.car or '未检测'}  注入 {self.injects}  替换 {self.replaced}"
        self._add(1, 1, _fit(env, w - 2), "gold_dim")

        # 主框：APK + 进度
        top = 3
        self._box(top, 0, 5, w, "1  当前 APK")
        if self.apk.path:
            self._add(top + 1, 2, _fit(self.apk.name, w - 6), "text")
            meta = f"{self.apk.mib}  {self.apk.sha256[:16]}…" if self.apk.ok else self.apk.error
            self._add(top + 2, 2, _fit(meta, w - 6), "ok" if self.apk.ok else "err")
        else:
            self._add(top + 1, 2, _fit("没有 APK：把文件拖进终端或按 o 选择", w - 6), "muted")
        if self.queue:
            self._add(top + 3, 2, _fit(f"队列还剩 {len(self.queue)} 个：{' · '.join(os.path.basename(p) for p in self.queue[:3])}", w - 6), "gold_dim")

        # 日志框（占中间）
        log_top = top + 6
        log_h = max(6, h - log_top - 3)
        self._box(log_top, 0, log_h, w, f"2  运行日志   [{self.phase}]")
        inner_h = log_h - 2
        lines = self.log[-inner_h - self.log_scroll:len(self.log) - self.log_scroll or None]
        y = log_top + 1
        for line in lines[-inner_h:]:
            color = "text"
            if line.startswith("[ok]"):
                color = "ok"
            elif line.startswith("警告") or line.startswith("[!!]") or line.startswith("[..]"):
                color = "warn"
            elif line.startswith("错误") or line.startswith("E1"):
                color = "err"
            elif line.startswith("[inject-update]") or line.startswith("[replace-apk]"):
                color = "gold_light"
            self._add(y, 2, _fit(line, w - 4), color)
            y += 1
            if y >= log_top + log_h - 1:
                break

        # 底部：状态 + 按键
        by = h - 2
        self._add(by, 1, _fit(self.status, w - 2), self.status_kind)
        keys = "s 开始  x 停止  o 选 APK  n 下一个  c 清屏  ↑↓ 滚动  q 退出"
        self._add(h - 1, 1, _fit(keys, w - 2), "gold_dim")
        std.refresh()

    # ---------------------------------------------------------------- 行为
    def _log(self, line: str) -> None:
        self.log.append(line)
        if len(self.log) > 2000:
            del self.log[:500]

    def _set_status(self, text: str, kind: str = "gold") -> None:
        self.status, self.status_kind = text, kind

    def start(self) -> None:
        if not self.apk.path or not self.apk.ok:
            self._set_status("没有可用的 APK，先按 o 指定一个", "err")
            return
        if self.round.running:
            self._set_status("已经在一轮里了，先按 x 结束本轮", "warn")
            return
        busy = common.port_busy()
        if busy:
            self._set_status(f"端口 {common.PORT} 被 {busy} 占用，先按 x 或跑『停止并恢复』", "err")
            return
        args = common.engine_args(self.apk.path, self.pkg)
        self.injects = self.replaced = 0
        self.phase = "启动"
        self.started_at = time.time()
        self._log(f"$ {' '.join(args)}")
        self._set_status("本轮进行中：车机上打开商店 → 检查更新 → 点任意更新", "gold")
        self.round = common.Round()
        self.round.start(args, self._on_line, self._on_exit)

    def _on_line(self, line: str, rnd: common.Round) -> None:
        self._log(line)
        st = rnd.state
        self.phase = st.phase
        if st.iface:
            self.iface = st.iface
        if st.car:
            self.car = st.car
        self.injects = st.injects
        self.replaced = len(st.replaced)
        if st.error:
            self._set_status(st.error, "err")

    def _on_exit(self, code: int, rnd: common.Round) -> None:
        hint = common.EXIT_HINT.get(code, f"引擎退出码 {code}，详情见日志")
        kind = "ok" if code in (0, 130) else "err"
        self.phase = "待开始"
        if code in (0, 130) and self.queue:
            self.need_next_prompt = True
            self._set_status(f"{hint}；按 n 装队列里的下一个（{len(self.queue)} 个待装）", "gold")
        else:
            self._set_status(hint, kind)

    def stop(self) -> None:
        if self.round.running:
            self.round.stop()
            self._set_status("已请求停止本轮…", "warn")

    def next_apk(self) -> None:
        if not self.queue:
            self._set_status("队列里没有下一个了，按 o 重新指定", "warn")
            return
        if self.round.running:
            self.round.stop()
            time.sleep(0.5)
        path = self.queue.pop(0)
        self._set_status(f"正在读取 {os.path.basename(path)} 的哈希…", "gold")
        common.describe_apk_async(path, self._on_apk)

    def _on_apk(self, info: common.ApkInfo) -> None:
        self.apk = info
        self.injects = self.replaced = 0
        self._set_status(f"已选 {info.name}，按 s 开始" if info.ok else info.error,
                         "gold" if info.ok else "err")

    # ---------------------------------------------------------------- 主循环
    def run(self) -> int:
        self._init_colors()
        curses.curs_set(0)
        self.std.nodelay(True)
        self.std.keypad(True)
        common.describe_apk_async(self.apk.path, self._on_apk)
        while True:
            self.draw()
            try:
                ch = self.std.get_wch()
            except curses.error:
                ch = None
            except KeyboardInterrupt:
                self.round.stop()
                break
            if ch is not None:
                if ch in ("q", "Q", "\x03"):
                    self.round.stop()
                    break
                if ch in ("s", "S", "\n", "\r"):
                    self.start()
                elif ch in ("x", "X"):
                    self.stop()
                elif ch in ("n", "N"):
                    self.next_apk()
                elif ch in ("c", "C"):
                    self.log.clear()
                elif ch == "KEY_UP":
                    self.log_scroll = min(self.log_scroll + 2, max(0, len(self.log) - 5))
                elif ch == "KEY_DOWN":
                    self.log_scroll = max(0, self.log_scroll - 2)
            time.sleep(0.08)
        return 0


def run(apks: list[str], outdir: str = "", pkg: str = "ALL") -> int:
    outdir = outdir or os.path.join(common.ROOT, "logs")
    os.makedirs(outdir, exist_ok=True)
    return curses.wrapper(lambda std: Tui(std, apks, outdir, pkg).run())


def main(argv: list[str] | None = None) -> int:
    """入口：./zeeload.command --tui [a.apk b.apk ...]

    文件参数当作队列；不存在的路径直接报错，别进到界面里才发现。
    """
    import sys as _sys
    argv = list(_sys.argv[1:] if argv is None else argv)
    apks, bad = [], []
    for a in argv:
        if a.startswith("-"):
            continue
        (apks if os.path.isfile(a) else bad).append(a)
    if bad:
        print("这些路径不存在或不是文件：")
        for b in bad:
            print("  " + b)
        return 2
    if not _sys.stdout.isatty():
        print("当前不是在终端里运行（没有 TTY），请直接执行：./zeeload.command --tui")
        return 2
    try:
        return run(apks)
    except KeyboardInterrupt:
        return 130


if __name__ == "__main__":
    raise SystemExit(main())
