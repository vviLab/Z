"""极载 ZEEload · WebUI 后端。

只用标准库 http.server：这台机器上不需要 pip 装任何东西。
界面是一个单文件 HTML，所有操作走同源的 JSON 接口。

设计约束（和前两个界面一致）：
  * 一轮 = 引擎的一次完整调用（scripts/transparent-test.sh），后端不缓存任何跨轮状态
  * 车机操作需要 root：提权走独立的终端窗口跑一次 `sudo -v`，
    本程序沿用那次 sudo 时间戳（自己从不接触密码）
  * 状态全部由引擎原文解析（zeeload.common.parse_line），前端不猜
"""

from __future__ import annotations

import json
import os
import re
import shutil
import socket
import subprocess
import sys
import threading
import time
import urllib.parse
import webbrowser
from dataclasses import dataclass, field
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from . import common

WEB_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "web")
INDEX = os.path.join(WEB_DIR, "index.html")

# ---------------------------------------------------------------- 会话

@dataclass
class Session:
    apk: common.ApkInfo = field(default_factory=lambda: common.ApkInfo(path=""))
    queue: list[str] = field(default_factory=list)
    pkg: str = "ALL"
    outdir: str = field(default_factory=lambda: os.path.join(common.ROOT, "logs"))
    log: list[str] = field(default_factory=list)
    round: common.Round | None = None
    started_at: float = 0.0
    finished: dict | None = None   # {"code": int, "hint": str, "at": float}
    last_cmd: list[str] = field(default_factory=list)

    def busy(self) -> bool:
        return self.round is not None and self.round.running


def add_to_queue(sess, path: str, front: bool = False) -> bool:
    """把路径放进队列：去重（按绝对路径）、只收真文件。

    同一条 APK 被选两次是常事（先「浏览」当当前任务，又「批量选择」排进去），
    重复项会让同一轮跑两遍，所以这里按绝对路径去重。
    """
    path = os.path.abspath(os.path.expanduser(path))
    if not os.path.isfile(path):
        return False
    if any(os.path.abspath(x) == path for x in sess.queue):
        return False
    if front:
        sess.queue.insert(0, path)
    else:
        sess.queue.append(path)
    return True


class Hub:
    """所有 HTTP 请求共享的一份状态（单用户工具，够用）。"""

    def __init__(self) -> None:
        self.sess = Session()
        self.lock = threading.Lock()
        self.sudo_ok = False
        self.sudo_msg = "未提权"
        self.sudo_pw = ""       # 仅当「记住密码」时才在内存里留一份，进程退出即丢

    # --- 环境 ---------------------------------------------------------
    def env(self) -> dict:
        exe = common.find_mitmdump()
        ver, has = common.mitmdump_version(exe) if exe else ("", False)
        iface, ip = common.detect_iface()
        car, mac = common.detect_lease(ip.rsplit(".", 1)[0] + "." if ip else "")
        busy = common.port_busy()
        return {
            "mitmdump": exe, "version": ver, "emudhra": has,
            "iface": iface, "host_ip": ip, "car": car, "car_mac": mac,
            "port": common.PORT, "port_owner": busy,
            "sudo": self.sudo_ok, "sudo_msg": self.sudo_msg,
            # 向导要用的三项就绪判定（各自独立，前端逐项点灯）
            "want_sudo": sys.platform == "darwin",
            "port_free": not busy,
            "platform": sys.platform,
            "python": sys.version.split()[0],
            "root": common.ROOT,
        }

    # --- 提权 ---------------------------------------------------------
    def prime_sudo(self) -> str:
        """不接触密码：确认「马上要用 sudo」——终端里输过密码的话这里直接成功。"""
        if sys.platform == "darwin":
            try:
                p = subprocess.run(["sudo", "-n", "-v"], capture_output=True, text=True, timeout=8)
                self.sudo_ok = p.returncode == 0
                self.sudo_msg = "已授权（sudo 时间戳有效）" if self.sudo_ok else "未授权：需要先在终端里输一次密码"
            except Exception as exc:
                self.sudo_ok, self.sudo_msg = False, f"检测失败：{exc}"
        else:
            self.sudo_ok, self.sudo_msg = True, "非 macOS，跳过 sudo 检测"
        return self.sudo_msg

    # --- 一轮 ---------------------------------------------------------
    def start(self) -> tuple[bool, str]:
        s = self.sess
        sel = s.apk  # 本轮 APK 快照
        if not sel.ok:
            return False, "还没选定可用的 APK"
        if s.busy():
            return False, "上一轮还在跑，先停止"
        busy = common.port_busy()
        if busy:
            return False, f"端口 {common.PORT} 被 {busy} 占用，先「停止」或跑『停止并恢复』"
        if not self.sudo_ok:
            self.prime_sudo()   # 终端里已经 sudo -v 过的情形，这里会直接放行
        if not self.sudo_ok:
            return False, "还没拿到管理员权限：在第 3 步输入一次密码"
        # 车机应该连在这台 Mac 分享出来的热点上（手机 USB 网络共享 → Mac 互联网共享）
        if not self.env()["iface"]:
            return False, "没检测到共享接口：先打开「互联网共享」并让车机连上这个热点"

        cmd = self._cmd(sel.path)
        s.last_cmd = cmd
        shown = " ".join(cmd).replace(self.sudo_pw, "***") if self.sudo_pw else " ".join(cmd)
        s.log = [f"$ {shown}", ""]
        s.finished = None
        s.started_at = time.time()
        rnd = common.Round()
        s.round = rnd

        def on_line(line: str, r: common.Round) -> None:
            s.log.append(line)

        def on_exit(code: int, r: common.Round) -> None:
            hint = common.EXIT_HINT.get(code, f"引擎退出码 {code}，详情见日志")
            s.finished = {"code": code, "hint": hint, "at": time.time()}
            if code in (common.EXIT_OK, common.EXIT_INTERRUPTED) and s.queue:
                # 队列自动推进：装完一个自动接下一个
                nxt = s.queue.pop(0)
                s.apk = common.ApkInfo(path=nxt)
                common.describe_apk_async(nxt, lambda info: setattr(s, "apk", info))

        rnd.start(cmd, on_line, on_exit, stdin_text=(self.sudo_pw + "\n") if self.sudo_pw else None)
        return True, "已开始"

    def sudo_prefix(self) -> list[str]:
        """引擎必须以 root 跑（第 221 行硬性检查 id -u）。"""
        return ["sudo", "-S", "-p", ""] if self.sudo_pw else ["sudo", "-n"]

    def _cmd(self, apk: str) -> list[str]:
        s = self.sess
        args = ["--all-443", "--intercept-all",
                "--inject-update", s.pkg or "ALL", "--replace-apk", apk]
        return [*self.sudo_prefix(), "bash", common.ENGINE, *args]

    def stop(self) -> str:
        if self.sess.round and self.sess.round.running:
            self.sess.round.stop()
            return "已请求停止"
        return "没有在跑"


HUB = Hub()


# ---------------------------------------------------------------- HTTP

MIME = {".html": "text/html; charset=utf-8", ".css": "text/css; charset=utf-8",
        ".js": "application/javascript; charset=utf-8", ".png": "image/png",
        ".svg": "image/svg+xml", ".ico": "image/x-icon"}


class Handler(BaseHTTPRequestHandler):
    server_version = "ZEEload/1.1"

    def log_message(self, fmt, *args):  # 静音：日志走引擎那一栏
        pass

    # --- 工具 ---------------------------------------------------------
    def _json(self, obj, code: int = 200) -> None:
        body = json.dumps(obj, ensure_ascii=False).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(body)

    def _body(self) -> dict:
        n = int(self.headers.get("Content-Length") or 0)
        if not n:
            return {}
        try:
            return json.loads(self.rfile.read(n).decode() or "{}")
        except Exception:
            return {}

    def _file(self, path: str) -> None:
        try:
            with open(path, "rb") as fh:
                data = fh.read()
        except OSError:
            self.send_error(404)
            return
        ext = os.path.splitext(path)[1].lower()
        self.send_response(200)
        self.send_header("Content-Type", MIME.get(ext, "application/octet-stream"))
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    # --- 路由 ---------------------------------------------------------
    def do_GET(self) -> None:
        u = urllib.parse.urlparse(self.path)
        p = u.path
        if p in ("/", "/index.html"):
            return self._file(INDEX)
        if p.startswith("/api/state"):
            q = urllib.parse.parse_qs(u.query)
            since = int(q.get("since", ["0"])[0] or 0)
            s = HUB.sess
            return self._json({
                "env": HUB.env(),
                "apk": {"name": s.apk.name, "path": s.apk.path, "size": s.apk.size,
                        "mib": s.apk.mib, "sha256": s.apk.sha256, "md5": s.apk.md5,
                        "ok": s.apk.ok, "error": s.apk.error},
                "queue": [os.path.basename(x) for x in s.queue],
                "queue_paths": list(s.queue),
                "queue_len": len(s.queue),
                "pkg": s.pkg, "outdir": s.outdir,
                "running": s.busy(),
                "phase": (s.round.state.phase if s.round else "待开始"),
                "injects": (s.round.state.injects if s.round else 0),
                "replaced": (len(s.round.state.replaced) if s.round else 0),
                "finished": s.finished,
                "log": s.log[since:], "log_len": len(s.log),
            })
        if p.startswith("/assets/"):
            name = os.path.basename(p)
            return self._file(os.path.join(common.ROOT, "assets", name))
        return self.send_error(404)

    def do_POST(self) -> None:
        u = urllib.parse.urlparse(self.path)
        body = self._body()
        s = HUB.sess
        try:
            if u.path == "/api/apk":
                path = body.get("path") or ""
                if body.get("pick"):
                    # 用系统文件选择器（AppleScript），省得自己写上传。
                    # 多选是默认行为：选几个就进几个，取消选择则什么都不变。
                    if sys.platform == "darwin":
                        p = subprocess.run(
                            ["osascript", "-e",
                             'set fs to (choose file with prompt "选择要侧载的 APK（可多选）" of type {"apk","public.zip-archive"} with multiple selections allowed)\n'
                             'set out to ""\nrepeat with f in fs\nset out to out & (POSIX path of f) & linefeed\nend repeat\nreturn out'],
                            capture_output=True, text=True, timeout=300)
                        picked = [l.strip() for l in p.stdout.splitlines() if l.strip()]
                        if not picked:
                            return self._json({"ok": False, "msg": "未选择文件"})
                        for extra in picked[1:]:
                            add_to_queue(s, extra)
                        path = picked[0]
                    else:
                        return self._json({"ok": False, "msg": "这个平台请在输入框里填路径"})
                if not os.path.isfile(path):
                    return self._json({"ok": False, "msg": f"文件不存在：{path}"})
                s.apk = common.ApkInfo(path=path)
                common.describe_apk_async(path, lambda info: setattr(s, "apk", info))
                # 选进来的东西天然属于这一轮的任务清单：同时钉在队首
                if body.get("pick") or body.get("enqueue"):
                    add_to_queue(s, path, front=True)
                return self._json({"ok": True, "msg": "已选，正在算哈希",
                                   "queue": [os.path.basename(x) for x in s.queue]})
            if u.path == "/api/queue":
                act = body.get("action") or "add"
                if act == "move":
                    i, j = int(body.get("from", -1)), int(body.get("to", -1))
                    if 0 <= i < len(s.queue) and 0 <= j < len(s.queue) and i != j:
                        s.queue.insert(j, s.queue.pop(i))
                elif act == "remove":
                    i = int(body.get("index", -1))
                    if 0 <= i < len(s.queue):
                        s.queue.pop(i)
                elif act == "clear":
                    s.queue.clear()
                elif body.get("pick") and sys.platform == "darwin":
                    p = subprocess.run(
                        ["osascript", "-e",
                         'set fs to (choose file with prompt "选择要排队的 APK（可多选）" of type {"apk","public.zip-archive"} with multiple selections allowed)\n'
                         'set out to ""\nrepeat with f in fs\nset out to out & (POSIX path of f) & linefeed\nend repeat\nreturn out'],
                        capture_output=True, text=True, timeout=300)
                    for line in p.stdout.splitlines():
                        line = line.strip()
                        if line:
                            add_to_queue(s, line)
                else:
                    for line in [str(body.get("paths") or "")] + list(body.get("list") or []):
                        for one in str(line).splitlines():
                            one = one.strip()
                            if one:
                                add_to_queue(s, one)
                return self._json({"ok": True, "queue": [os.path.basename(x) for x in s.queue],
                                   "paths": list(s.queue)})
            if u.path == "/api/queue_clear":
                s.queue.clear()
                return self._json({"ok": True})
            if u.path == "/api/options":
                s.pkg = (body.get("pkg") or "ALL").strip() or "ALL"
                out = (body.get("outdir") or "").strip()
                if out:
                    s.outdir = os.path.expanduser(out)
                return self._json({"ok": True, "env": HUB.env()})
            if u.path == "/api/next":
                if s.queue:
                    nxt = s.queue.pop(0)
                    s.apk = common.ApkInfo(path=nxt)
                    common.describe_apk_async(nxt, lambda info: setattr(s, "apk", info))
                    return self._json({"ok": True, "msg": f"下一个：{os.path.basename(nxt)}"})
                return self._json({"ok": False, "msg": "队列空了"})
            if u.path == "/api/start":
                ok, msg = HUB.start()
                return self._json({"ok": ok, "msg": msg, "cmd": HUB.sess.last_cmd})
            if u.path == "/api/stop":
                return self._json({"ok": True, "msg": HUB.stop()})
            if u.path == "/api/clear":
                s.log = []
                return self._json({"ok": True})
            if u.path == "/api/sudo_auth":
                pw = body.get("password") or ""
                remember = bool(body.get("remember"))
                if not pw:
                    return self._json({"ok": False, "msg": "密码为空"})
                try:
                    p = subprocess.run(["sudo", "-S", "-p", "", "-v"], input=pw + "\n",
                                       capture_output=True, text=True, timeout=15)
                except (OSError, PermissionError) as exc:
                    HUB.sudo_ok, HUB.sudo_msg = False, f"无法执行 sudo：{exc}"
                    return self._json({"ok": False, "msg": HUB.sudo_msg})
                if p.returncode != 0:
                    HUB.sudo_ok, HUB.sudo_msg = False, "密码不正确，或该账户没有管理员权限"
                    HUB.sudo_pw = ""
                    return self._json({"ok": False, "msg": HUB.sudo_msg})
                HUB.sudo_ok, HUB.sudo_msg = True, "已授权"
                HUB.sudo_pw = pw if remember else ""
                return self._json({"ok": True, "msg": "已授权" + ("（本次运行内记住）" if remember else "（仅本次）")})
            if u.path == "/api/sudo":
                # 提权：模态地等用户在终端里输密码
                if sys.platform == "darwin":
                    if os.path.exists("/System/Applications/Utilities/Terminal.app"):
                        subprocess.Popen(["open", "-a", "Terminal",
                                          os.path.join(common.ROOT, "scripts", "zeeload-sudo.command")])
                    return self._json({"ok": True, "msg": "已在终端窗口请求授权，输完密码回来点「刷新环境」"})
                return self._json({"ok": False, "msg": "非 macOS 无需提权"})
            if u.path == "/api/diagnose":
                out = ""
                script = os.path.join(common.ROOT, "scripts", "check-environment.sh")
                if os.path.isfile(script):
                    p = subprocess.run(["bash", script], capture_output=True, text=True, timeout=60)
                    out = (p.stdout or "") + (p.stderr or "")
                s.log.append("=== 环境检查 ===")
                s.log.extend(out.splitlines())
                return self._json({"ok": True})
            if u.path == "/api/outdir":
                path = s.outdir
                os.makedirs(path, exist_ok=True)
                subprocess.Popen(["open", path])
                return self._json({"ok": True})
        except Exception as exc:
            return self._json({"ok": False, "msg": f"接口异常：{exc!r}"}, 500)
        return self.send_error(404)


def _free_port(preferred: int = 8765) -> int:
    for port in [preferred, *range(preferred + 1, preferred + 20)]:
        with socket.socket() as sk:
            try:
                sk.bind(("127.0.0.1", port))
                return port
            except OSError:
                continue
    with socket.socket() as sk:
        sk.bind(("127.0.0.1", 0))
        return sk.getsockname()[1]


def main(argv: list[str] | None = None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    apks = [a for a in argv if os.path.isfile(a) and not a.startswith("-")]
    if apks:
        HUB.sess.apk = common.ApkInfo(path=apks[0])
        common.describe_apk_async(apks[0], lambda info: setattr(HUB.sess, "apk", info))
        HUB.sess.queue = apks[1:]
    HUB.prime_sudo()

    port = _free_port()
    url = f"http://127.0.0.1:{port}/"
    srv = ThreadingHTTPServer(("127.0.0.1", port), Handler)
    print(f"极载 ZEEload · WebUI  {url}     (Ctrl-C 结束；界面只监听本机)")
    threading.Timer(0.6, lambda: webbrowser.open(url)).start()
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        print("\n再见。若车机还连着热点，记得运行『停止并恢复.command』。")
    finally:
        if HUB.sess.round and HUB.sess.round.running:
            HUB.sess.round.stop()
        srv.server_close()
    return 0


if __name__ == "__main__":
    sys.exit(main())
