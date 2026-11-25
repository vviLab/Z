"""极载 ZEEload · WebUI 后端。

只用标准库 http.server：这台机器上不需要 pip 装任何东西。
界面是一个单文件 HTML，所有操作走同源的 JSON 接口。

设计约束：
  * 一轮 = 引擎的一次完整调用（scripts/transparent-test.sh），后端不缓存任何跨轮引擎状态
  * 车机操作需要 root：支持网页内通过 sudo -S 授权（仅驻留内存，不落盘），
    运行期间自动续期 sudo 时间戳，也兼容同一终端预先执行 `sudo -v`
  * 状态全部由引擎原文解析（zeeload.common.parse_line），前端不猜
"""

from __future__ import annotations

import hmac
import json
import os
import secrets
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
STOP_SCRIPT = os.path.join(common.ROOT, "scripts", "stop-transparent.sh")

NET_CACHE_TTL = 2.5
SUDO_CHECK_TTL = 5.0


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


def _is_zip_file(path: str) -> bool:
    """快速校验文件存在且具备 zip/APK 文件头（PK）。"""
    if not os.path.isfile(path):
        return False
    try:
        with open(path, "rb") as fh:
            return fh.read(2) == b"PK"
    except OSError:
        return False


def add_to_queue(sess: Session, path: str, front: bool = False) -> bool:
    """把路径放进清单：去重（按绝对路径）、只收真 zip/APK 文件。"""
    path = os.path.abspath(os.path.expanduser(path))
    if not _is_zip_file(path):
        return False
    if any(os.path.abspath(x) == path for x in sess.queue):
        return False
    if front:
        sess.queue.insert(0, path)
    else:
        sess.queue.append(path)
    return True


def _set_apk(sess: Session, path: str, lock: threading.Lock | None = None) -> None:
    """设为当前任务并异步计算哈希。"""
    path = os.path.abspath(os.path.expanduser(path))
    if sess.apk.path == path and sess.apk.ok and sess.apk.sha256:
        return
    sess.apk = common.ApkInfo(path=path)

    def _done(info: common.ApkInfo) -> None:
        if lock:
            with lock:
                if sess.apk.path == path:
                    sess.apk = info
        elif sess.apk.path == path:
            sess.apk = info

    common.describe_apk_async(path, _done)


def sync_head(sess: Session, lock: threading.Lock | None = None) -> None:
    """保持队首与当前任务一致（空闲时同步）。"""
    if sess.busy():
        return
    if sess.queue:
        _set_apk(sess, sess.queue[0], lock=lock)
    else:
        sess.apk = common.ApkInfo(path="")


def remaining_queue(sess: Session) -> list[str]:
    """返回当前任务之后还剩多少待装 APK。"""
    if not sess.apk.path:
        return list(sess.queue)
    return common.queue_next(sess.queue, sess.apk.path)


class Hub:
    """所有 HTTP 请求共享的一份状态（带缓存与并发锁）。"""

    def __init__(self) -> None:
        self.sess = Session()
        self.lock = threading.Lock()
        self.token = secrets.token_urlsafe(24)
        self.sudo_ok = False
        self.sudo_msg = "未提权"
        self.sudo_pw = ""       # 仅当「记住密码」时才在内存里留一份，进程退出即丢
        self._mitm_cache: tuple[str, str, bool] | None = None
        self._net_cache: tuple[float, dict] | None = None
        self._sudo_checked_at: float = 0.0

    def invalidate_cache(self) -> None:
        self._mitm_cache = None
        self._net_cache = None
        self._sudo_checked_at = 0.0

    # --- 环境 ---------------------------------------------------------
    def env(self, force: bool = False) -> dict:
        now = time.monotonic()

        # 1. mitmdump 路径与版本开销最大（~1.3s），静态缓存，仅在显式重检或缺依赖退出时刷新
        if force or self._mitm_cache is None:
            exe = common.find_mitmdump()
            ver, has = common.mitmdump_version(exe) if exe else ("", False)
            self._mitm_cache = (exe, ver, has)
        else:
            exe, ver, has = self._mitm_cache

        # 2. 网络接口与端口占用做短 TTL 缓存（2.5s），避免高频轮询反复 fork ifconfig/lsof
        if force or self._net_cache is None or (now - self._net_cache[0]) > NET_CACHE_TTL:
            iface, ip = common.detect_iface()
            car, mac = common.detect_lease(ip.rsplit(".", 1)[0] + "." if ip else "")
            busy = common.port_busy()
            net = {"iface": iface, "host_ip": ip, "car": car, "car_mac": mac, "port_owner": busy}
            self._net_cache = (now, net)
        else:
            net = self._net_cache[1]

        # 3. 未保存内存密码时，定期用非阻塞 sudo -n -v 复核时间戳是否有效/过期
        if sys.platform == "darwin" and not self.sudo_pw:
            if force or (now - self._sudo_checked_at) > SUDO_CHECK_TTL:
                self.prime_sudo()

        running = self.sess.busy()
        busy_owner = net["port_owner"]
        # 本会话运行期间，18080 本就由当前引擎的 mitmdump 监听，不应判为环境冲突
        port_free = (not busy_owner) or running

        return {
            "mitmdump": exe, "version": ver, "emudhra": has,
            "iface": net["iface"], "host_ip": net["host_ip"],
            "car": net["car"], "car_mac": net["car_mac"],
            "port": common.PORT, "port_owner": busy_owner,
            "port_self": running and bool(busy_owner),
            "sudo": self.sudo_ok, "sudo_msg": self.sudo_msg,
            "want_sudo": sys.platform == "darwin" and os.geteuid() != 0,
            "port_free": port_free,
            "platform": sys.platform,
            "python": sys.version.split()[0],
            "root": common.ROOT,
        }

    # --- 提权 ---------------------------------------------------------
    def prime_sudo(self) -> str:
        """不接触密码：复核当前进程的 sudo 时间戳是否有效。"""
        self._sudo_checked_at = time.monotonic()
        if sys.platform != "darwin" or os.geteuid() == 0:
            self.sudo_ok, self.sudo_msg = True, "无需 sudo"
            return self.sudo_msg
        if self.sudo_pw:
            self.sudo_ok, self.sudo_msg = True, "已授权（本次运行内有效）"
            return self.sudo_msg
        try:
            p = subprocess.run(["sudo", "-n", "-v"], capture_output=True, text=True, timeout=5)
            self.sudo_ok = p.returncode == 0
            self.sudo_msg = "已授权（sudo 时间戳有效）" if self.sudo_ok else "未授权：需要先输入一次密码"
        except Exception as exc:
            self.sudo_ok, self.sudo_msg = False, f"检测失败：{exc}"
        return self.sudo_msg

    def _keepalive_sudo(self, rnd: common.Round) -> None:
        """运行期间每 45 秒续期一次 sudo 时间戳，防止单轮超 5 分钟后无法停止或继续下一轮。"""
        while rnd.running:
            time.sleep(1.0)
            if not rnd.running:
                break
            if sys.platform == "darwin" and os.geteuid() != 0 and not self.sudo_pw:
                if (time.monotonic() - self._sudo_checked_at) >= 45.0:
                    self.prime_sudo()

    # --- 一轮 ---------------------------------------------------------
    def start(self) -> tuple[bool, str]:
        s = self.sess
        with self.lock:
            sel = s.apk
            if not sel.ok:
                return False, "还没选定可用的 APK"
            if s.busy():
                return False, "上一轮还在跑，先停止"

        env = self.env(force=True)
        if not env["port_free"]:
            return False, f"端口 {common.PORT} 被 {env['port_owner']} 占用，先「停止」或跑『停止并恢复』"
        if env["want_sudo"] and not self.sudo_ok:
            return False, "还没拿到管理员权限：在第 3 步输入一次密码"
        if not env["iface"]:
            return False, "没检测到共享接口：先打开「互联网共享」并让车机连上这个热点"

        with self.lock:
            if s.busy():
                return False, "上一轮还在跑，先停止"
            cmd = self._cmd(sel.path)
            s.last_cmd = cmd
            shown = " ".join(cmd).replace(self.sudo_pw, "***") if self.sudo_pw else " ".join(cmd)
            s.log = [f"$ {shown}", ""]
            s.finished = None
            s.started_at = time.time()
            rnd = common.Round(kill_fn=self._sudo_kill)
            s.round = rnd
            pw_stdin = (self.sudo_pw + "\n") if self.sudo_pw else None

        def on_line(line: str, r: common.Round) -> None:
            with self.lock:
                s.log.append(line)
                if len(s.log) > 5000:
                    del s.log[:1000]

        def on_exit(code: int, r: common.Round) -> None:
            if code in (common.EXIT_NO_MITMDUMP, common.EXIT_MITM_VERSION):
                self._mitm_cache = None
            self._net_cache = None
            hint = common.EXIT_HINT.get(code, f"引擎退出码 {code}，详情见日志")
            with self.lock:
                s.finished = {"code": code, "hint": hint, "at": time.time()}
                if code in (common.EXIT_OK, common.EXIT_INTERRUPTED):
                    s.queue = common.queue_next(s.queue, sel.path)
                    if s.queue:
                        _set_apk(s, s.queue[0], lock=self.lock)
                    else:
                        s.apk = common.ApkInfo(path="")

        rnd.start(cmd, on_line, on_exit, stdin_text=pw_stdin)
        threading.Thread(target=self._keepalive_sudo, args=(rnd,), daemon=True).start()
        return True, "已开始"

    def sudo_prefix(self) -> list[str]:
        if sys.platform != "darwin" or os.geteuid() == 0:
            return []
        return ["sudo", "-S", "-p", ""] if self.sudo_pw else ["sudo", "-n"]

    def _run_sudo(self, args: list[str], timeout: float = 8.0) -> bool:
        cmd = [*self.sudo_prefix(), *args]
        try:
            p = subprocess.run(
                cmd,
                input=(self.sudo_pw + "\n") if self.sudo_pw else None,
                capture_output=True, text=True, timeout=timeout,
            )
            return p.returncode == 0
        except Exception:
            return False

    def _sudo_kill(self, pid: int, force: bool) -> bool:
        """优雅停止发 TERM 给 sudo；强制兜底时一并清理子进程并卸载 pf anchor。"""
        if not force:
            return self._run_sudo(["kill", "-TERM", str(pid)])
        self._run_sudo(["pkill", "-KILL", "-P", str(pid)])
        ok = self._run_sudo(["kill", "-KILL", str(pid)])
        if os.path.isfile(STOP_SCRIPT):
            self._run_sudo(["bash", STOP_SCRIPT], timeout=10.0)
        return ok

    def _cmd(self, apk: str) -> list[str]:
        s = self.sess
        args = ["--all-443", "--intercept-all",
                "--inject-update", s.pkg or "ALL", "--replace-apk", apk]
        if s.outdir:
            args += ["--out-dir", s.outdir]
        return [*self.sudo_prefix(), "bash", common.ENGINE, *args]

    def stop(self) -> str:
        rnd = self.sess.round
        if rnd and rnd.running:
            threading.Thread(target=rnd.stop, daemon=True).start()
            return "正在停止…"
        return "没有在跑"


HUB = Hub()


# ---------------------------------------------------------------- HTTP

MIME = {".html": "text/html; charset=utf-8", ".css": "text/css; charset=utf-8",
        ".js": "application/javascript; charset=utf-8", ".png": "image/png",
        ".svg": "image/svg+xml", ".ico": "image/x-icon"}


class Handler(BaseHTTPRequestHandler):
    server_version = "ZEEload/1.2"

    def log_message(self, fmt, *args):  # 静音：日志走引擎那一栏
        pass

    # --- 安全校验 -----------------------------------------------------
    def _check_host(self) -> bool:
        """防御 DNS Rebinding：只接受 127.0.0.1 / localhost 访问。"""
        host = (self.headers.get("Host") or "").split(":", 1)[0].strip().lower()
        return host in ("127.0.0.1", "localhost")

    def _check_csrf(self) -> bool:
        """防御跨站请求伪造：所有 /api/* 必须带同源页面注入的随机 Token。"""
        tok = self.headers.get("X-ZEEload-Token") or ""
        if not hmac.compare_digest(tok, HUB.token):
            return False
        origin = (self.headers.get("Origin") or "").strip().lower()
        if origin and not (origin.startswith("http://127.0.0.1:") or origin.startswith("http://localhost:")):
            return False
        return True

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
        if not n or n > 1024 * 1024:
            return {}
        try:
            return json.loads(self.rfile.read(n).decode() or "{}")
        except Exception:
            return {}

    def _file(self, path: str, inject_token: bool = False) -> None:
        try:
            with open(path, "rb") as fh:
                data = fh.read()
        except OSError:
            self.send_error(404)
            return
        if inject_token:
            meta = f'<meta name="zeeload-token" content="{HUB.token}">'.encode()
            data = data.replace(b"<!--ZEELOAD_TOKEN-->", meta, 1)
        ext = os.path.splitext(path)[1].lower()
        self.send_response(200)
        self.send_header("Content-Type", MIME.get(ext, "application/octet-stream"))
        self.send_header("Content-Length", str(len(data)))
        if inject_token:
            self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(data)

    # --- 路由 ---------------------------------------------------------
    def do_GET(self) -> None:
        if not self._check_host():
            self.send_error(403, "Forbidden Host")
            return
        u = urllib.parse.urlparse(self.path)
        p = u.path
        if p in ("/", "/index.html"):
            return self._file(INDEX, inject_token=True)
        if p.startswith("/api/state"):
            if not self._check_csrf():
                return self._json({"ok": False, "msg": "令牌无效，请刷新页面"}, 403)
            q = urllib.parse.parse_qs(u.query)
            try:
                since = int(q.get("since", ["0"])[0] or 0)
            except ValueError:
                since = 0
            env = HUB.env()
            with HUB.lock:
                s = HUB.sess
                total_log = len(s.log)
                actual_since = since if 0 <= since <= total_log else 0
                log_slice = list(s.log[actual_since:])
                apk_snap = {
                    "name": s.apk.name, "path": s.apk.path, "size": s.apk.size,
                    "mib": s.apk.mib, "sha256": s.apk.sha256, "md5": s.apk.md5,
                    "ok": s.apk.ok, "error": s.apk.error,
                }
                q_paths = list(s.queue)
                q_rem = len(remaining_queue(s))
                rnd = s.round
                running = s.busy()
                payload = {
                    "env": env,
                    "apk": apk_snap,
                    "queue": [os.path.basename(x) for x in q_paths],
                    "queue_paths": q_paths,
                    "queue_len": q_rem,
                    "pkg": s.pkg, "outdir": s.outdir,
                    "running": running,
                    "hooked": (rnd.state.hooked if rnd else False),
                    "phase": (rnd.state.phase if rnd else "待开始"),
                    "injects": (rnd.state.injects if rnd else 0),
                    "replaced": (len(rnd.state.replaced) if rnd else 0),
                    "finished": s.finished,
                    "log": log_slice,
                    "log_base": actual_since,
                    "log_len": total_log,
                }
            return self._json(payload)
        if p.startswith("/assets/"):
            name = os.path.basename(p)
            return self._file(os.path.join(common.ROOT, "assets", name))
        return self.send_error(404)

    def do_POST(self) -> None:
        if not self._check_host():
            self.send_error(403, "Forbidden Host")
            return
        if not self._check_csrf():
            return self._json({"ok": False, "msg": "令牌无效，请刷新页面"}, 403)
        u = urllib.parse.urlparse(self.path)
        body = self._body()
        s = HUB.sess
        try:
            if u.path == "/api/apk":
                path = body.get("path") or ""
                picked_extras: list[str] = []
                if body.get("pick"):
                    if sys.platform == "darwin":
                        p = subprocess.run(
                            ["osascript", "-e",
                             'set fs to (choose file with prompt "选择要侧载的 APK（可多选）" of type {"apk","public.zip-archive"} with multiple selections allowed)\n'
                             'set out to ""\nrepeat with f in fs\nset out to out & (POSIX path of f) & linefeed\nend repeat\nreturn out'],
                            capture_output=True, text=True, timeout=300)
                        picked = [l.strip() for l in p.stdout.splitlines() if l.strip()]
                        if not picked:
                            return self._json({"ok": False, "msg": "未选择文件"})
                        path = picked[0]
                        picked_extras = picked[1:]
                    else:
                        return self._json({"ok": False, "msg": "这个平台请在输入框里填路径"})
                path = os.path.abspath(os.path.expanduser(path))
                if not os.path.isfile(path):
                    return self._json({"ok": False, "msg": f"文件不存在：{path}"})
                if not _is_zip_file(path):
                    with HUB.lock:
                        if not s.busy() and not s.queue:
                            s.apk = common.ApkInfo(path=path, error="不是 APK / zip 文件")
                    return self._json({"ok": False, "msg": "不是 APK / zip 文件"})
                with HUB.lock:
                    if s.busy():
                        # 运行中锁定当前任务：新选文件排进队尾，不篡改正在运行的 s.apk
                        add_to_queue(s, path, front=False)
                        for extra in picked_extras:
                            add_to_queue(s, extra, front=False)
                        return self._json({
                            "ok": True, "queued_only": True,
                            "msg": "当前任务运行中，新 APK 已加入后续队列",
                            "queue": [os.path.basename(x) for x in s.queue],
                        })
                    for extra in picked_extras:
                        add_to_queue(s, extra, front=False)
                    if path in s.queue:
                        s.queue.remove(path)
                    s.queue.insert(0, path)
                    _set_apk(s, path, lock=HUB.lock)
                    q_names = [os.path.basename(x) for x in s.queue]
                return self._json({"ok": True, "msg": "已选，正在算哈希", "queue": q_names})

            if u.path == "/api/queue":
                act = body.get("action") or "add"
                picked_lines: list[str] = []
                if act == "add" and body.get("pick") and sys.platform == "darwin":
                    p = subprocess.run(
                        ["osascript", "-e",
                         'set fs to (choose file with prompt "选择要排队的 APK（可多选）" of type {"apk","public.zip-archive"} with multiple selections allowed)\n'
                         'set out to ""\nrepeat with f in fs\nset out to out & (POSIX path of f) & linefeed\nend repeat\nreturn out'],
                        capture_output=True, text=True, timeout=300)
                    picked_lines = [l.strip() for l in p.stdout.splitlines() if l.strip()]

                with HUB.lock:
                    running = s.busy()
                    if act == "move":
                        i, j = int(body.get("from", -1)), int(body.get("to", -1))
                        min_idx = 1 if running else 0
                        if min_idx <= i < len(s.queue) and min_idx <= j < len(s.queue) and i != j:
                            s.queue.insert(j, s.queue.pop(i))
                            sync_head(s, lock=HUB.lock)
                    elif act == "remove":
                        i = int(body.get("index", -1))
                        min_idx = 1 if running else 0
                        if min_idx <= i < len(s.queue):
                            s.queue.pop(i)
                            sync_head(s, lock=HUB.lock)
                    elif act == "clear":
                        if running and s.queue:
                            del s.queue[1:]
                        else:
                            s.queue.clear()
                            sync_head(s, lock=HUB.lock)
                    elif picked_lines:
                        for line in picked_lines:
                            add_to_queue(s, line)
                        sync_head(s, lock=HUB.lock)
                    else:
                        for line in [str(body.get("paths") or "")] + list(body.get("list") or []):
                            for one in str(line).splitlines():
                                one = one.strip()
                                if one:
                                    add_to_queue(s, one)
                        sync_head(s, lock=HUB.lock)
                    q_names = [os.path.basename(x) for x in s.queue]
                    q_paths = list(s.queue)
                return self._json({"ok": True, "queue": q_names, "paths": q_paths})

            if u.path == "/api/queue_clear":
                with HUB.lock:
                    if s.busy() and s.queue:
                        del s.queue[1:]
                    else:
                        s.queue.clear()
                        sync_head(s, lock=HUB.lock)
                return self._json({"ok": True})

            if u.path == "/api/options":
                with HUB.lock:
                    s.pkg = (body.get("pkg") or "ALL").strip() or "ALL"
                    out = (body.get("outdir") or "").strip()
                    s.outdir = os.path.expanduser(out) if out else os.path.join(common.ROOT, "logs")
                return self._json({"ok": True, "env": HUB.env()})

            if u.path == "/api/next":
                with HUB.lock:
                    if s.busy():
                        return self._json({"ok": False, "msg": "当前任务运行中，请先停止"})
                    rem = remaining_queue(s)
                    if rem:
                        s.queue = rem
                        _set_apk(s, s.queue[0], lock=HUB.lock)
                        return self._json({"ok": True, "msg": f"下一个：{os.path.basename(s.queue[0])}"})
                return self._json({"ok": False, "msg": "队列空了"})

            if u.path == "/api/start":
                ok, msg = HUB.start()
                shown_cmd = [
                    x.replace(HUB.sudo_pw, "***") if HUB.sudo_pw else x
                    for x in HUB.sess.last_cmd
                ]
                return self._json({"ok": ok, "msg": msg, "cmd": shown_cmd})

            if u.path == "/api/stop":
                return self._json({"ok": True, "msg": HUB.stop()})

            if u.path == "/api/clear":
                with HUB.lock:
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
                HUB._sudo_checked_at = time.monotonic()
                HUB.sudo_ok, HUB.sudo_msg = True, "已授权"
                HUB.sudo_pw = pw if remember else ""
                return self._json({"ok": True, "msg": "已授权" + ("（本次运行内记住）" if remember else "（仅本次，运行期间自动续期）")})

            if u.path == "/api/recheck":
                return self._json({"ok": True, "env": HUB.env(force=True)})

            if u.path == "/api/diagnose":
                HUB.invalidate_cache()
                out = ""
                script = os.path.join(common.ROOT, "scripts", "check-environment.sh")
                if os.path.isfile(script):
                    p = subprocess.run(["bash", script], capture_output=True, text=True, timeout=60)
                    out = (p.stdout or "") + (p.stderr or "")
                with HUB.lock:
                    s.log.append("=== 环境检查 ===")
                    s.log.extend(out.splitlines())
                return self._json({"ok": True, "env": HUB.env(force=True)})

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
    for a in apks:
        add_to_queue(HUB.sess, a)
    sync_head(HUB.sess, lock=HUB.lock)
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
