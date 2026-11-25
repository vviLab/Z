"""zeeload.common — GUI 与 TUI 共用的一层。

这里只放「两个界面都要做、且必须做一致」的东西：
  * 调引擎（scripts/transparent-test.sh）并解析它的输出 → 状态机
  * 算 APK 的 sha256/md5/大小
  * 探测共享接口、车机租约、mitmdump 位置（这些不需要 root）
  * 结束一轮后换下一个 APK 的排队逻辑（方案 A 的「多轮」在界面里的形态）

界面层不直接碰 subprocess，也不直接拼引擎参数。
"""

from __future__ import annotations

import hashlib
import os
import re
import shutil
import subprocess
import threading
import time
from dataclasses import dataclass, field
from typing import Callable, Iterable

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
ENGINE = os.path.join(ROOT, "scripts", "transparent-test.sh")
ADDON = os.path.join(ROOT, "addons", "zeekr_log.py")
PORT = int(os.environ.get("ZEEKR_PORT", "18080"))
ANCHOR = os.environ.get("ZEEKR_ANCHOR", "com.apple/zeekr-capture")

# 引擎的结构化退出码（见 scripts/transparent-test.sh）
EXIT_OK = 0
EXIT_INTERRUPTED = 130
EXIT_NO_IFACE = 10
EXIT_PORT_BUSY = 11
EXIT_NO_MITMDUMP = 12
EXIT_MITM_VERSION = 13

EXIT_HINT = {
    EXIT_OK: "本轮正常结束",
    EXIT_INTERRUPTED: "本轮被中断（属于正常收尾）",
    EXIT_NO_IFACE: "车机没连上热点：检查「互联网共享」是否开启，并让车机重连 Wi-Fi",
    EXIT_PORT_BUSY: "端口 %d 被占用：上一次的 mitmdump 可能没退出，先点「停止」或运行『停止并恢复』" % PORT,
    EXIT_NO_MITMDUMP: "找不到 mitmdump：pip3 install mitmproxy（或放进 venv/）",
    EXIT_MITM_VERSION: "mitmproxy 版本过低（缺 --emudhra，需要 12.3+）：pip3 install -U mitmproxy",
}


# ---------------------------------------------------------------- APK

@dataclass
class ApkInfo:
    path: str
    size: int = 0
    sha256: str = ""
    md5: str = ""
    error: str = ""

    @property
    def name(self) -> str:
        return os.path.basename(self.path)

    @property
    def mib(self) -> str:
        return f"{self.size / 1048576:.2f} MiB"

    @property
    def ok(self) -> bool:
        # 没有 path 就是「还没选」，不能当成可用（ApkInfo(path="") 的 error 也是空的）
        return bool(self.path) and not self.error


def describe_apk(path: str) -> ApkInfo:
    """算哈希 + 校验是不是 zip。大文件按块读，不整份进内存。"""
    path = os.path.abspath(os.path.expanduser(path))
    info = ApkInfo(path=path)
    if not os.path.isfile(path):
        info.error = "文件不存在"
        return info
    with open(path, "rb") as fh:
        head = fh.read(4)
        if head[:2] != b"PK":
            info.error = "不是 APK / zip 文件"
            return info
        fh.seek(0)
        h256, md5 = hashlib.sha256(), hashlib.md5()
        n = 0
        for chunk in iter(lambda: fh.read(1024 * 1024), b""):
            h256.update(chunk)
            md5.update(chunk)
            n += len(chunk)
    info.size, info.sha256, info.md5 = n, h256.hexdigest(), md5.hexdigest()
    return info


def describe_apk_async(path: str, done: Callable[[ApkInfo], None]) -> None:
    threading.Thread(target=lambda: done(describe_apk(path)), daemon=True).start()


# ---------------------------------------------------------------- 探测（不需要 root）

def find_mitmdump() -> str:
    venv = os.environ.get("ZEEKR_VENV", "")
    cands = []
    if venv:
        cands.append(os.path.join(venv, "bin", "mitmdump"))
    cands.append(os.path.join(ROOT, "venv", "bin", "mitmdump"))
    found = shutil.which("mitmdump")
    if found:
        cands.append(found)
    cands.append(os.path.expanduser("~/.mitmproxy-venv/bin/mitmdump"))
    for c in cands:
        if c and os.access(c, os.X_OK):
            return c
    return ""


def mitmdump_version(exe: str) -> tuple[str, bool]:
    """返回 (版本字符串, 是否支持 --emudhra)。"""
    if not exe:
        return ("", False)
    try:
        v = subprocess.run([exe, "--version"], capture_output=True, text=True, timeout=10)
        h = subprocess.run([exe, "--help"], capture_output=True, text=True, timeout=10)
    except Exception:
        return ("", False)
    ver = (v.stdout or v.stderr or "").splitlines()
    ver_s = ver[0].strip() if ver else ""
    return (ver_s, "--emudhra" in (h.stdout or h.stderr or ""))


def detect_iface() -> tuple[str, str]:
    """找互联网共享的 bridge 接口，返回 (接口名, IPv4)。"""
    try:
        out = subprocess.run(["ifconfig", "-l"], capture_output=True, text=True, timeout=10).stdout
    except Exception:
        return ("", "")
    best = ""
    for name in out.split():
        if not name.startswith("bridge"):
            continue
        try:
            conf = subprocess.run(["ifconfig", name], capture_output=True, text=True, timeout=10).stdout
        except Exception:
            continue
        m = re.search(r"inet (\d+\.\d+\.\d+\.\d+)", conf)
        if not m:
            continue
        if "status: active" in conf:
            if "member: ap" in conf:
                return (name, m.group(1))
            best = best or f"{name}|{m.group(1)}"
    if best:
        name, ip = best.split("|", 1)
        return (name, ip)
    return ("", "")


def detect_lease(prefix: str = "") -> tuple[str, str]:
    """从 DHCP 租约里找车机，返回 (IP, MAC)。prefix 形如 '192.168.2.'。"""
    path = "/var/db/dhcpd_leases"
    if not os.access(path, os.R_OK):
        return ("", "")
    try:
        with open(path, "r", errors="ignore") as fh:
            text = fh.read()
    except OSError:
        return ("", "")
    want = re.compile(r"(auto|ivt|evb|zeekr|lynk|ecarx|dhu|headunit|hu)", re.I)
    any_hit = ""
    for block in text.split("{"):
        ip = re.search(r"ip_address=(\d+\.\d+\.\d+\.\d+)", block)
        hw = re.search(r"hw_address=[^,]*,[0-9a-f:]+", block)
        nm = re.search(r"name=(.*)", block)
        if not ip or (prefix and not ip.group(1).startswith(prefix)):
            continue
        mac = ""
        if hw:
            mac = ":".join(hw.group(0).split(",")[-1].strip().split(":")[-6:])
        hit = (ip.group(1), mac)
        if nm and want.search(nm.group(1)):
            return hit
        any_hit = any_hit or f"{hit[0]}|{hit[1]}"
    if any_hit:
        ip, mac = any_hit.split("|", 1)
        return (ip, mac)
    return ("", "")


def port_busy() -> str:
    try:
        out = subprocess.run(
            ["lsof", "-nP", f"-iTCP:{PORT}", "-sTCP:LISTEN"],
            capture_output=True, text=True, timeout=10,
        ).stdout.strip().splitlines()
    except Exception:
        return ""
    if len(out) > 1:
        return out[1].split()[0]
    return ""


# ---------------------------------------------------------------- 一轮引擎的状态机

@dataclass
class EngineState:
    phase: str = "待开始"       # 待开始 / 启动 / 注入 / 下载 / 结束
    iface: str = ""
    car: str = ""
    injects: int = 0
    replaced: list[str] = field(default_factory=list)
    warned: int = 0
    hooked: bool = False       # 见过 [ok] mitmdump 已启动
    sign_seen: bool = False    # 见过 [replace-apk] 商店已用…取签名
    passthrough: bool = False  # 见过 [replace-apk] 该下载…（注入没生效）
    exit_code: int | None = None
    error: str = ""


def _clean(line: str) -> str:
    return re.sub(r"\x1b\[[0-9;]*m", "", line).rstrip()


# mitmproxy 会把 addon 里 ctx.log.warn 的输出冠上 addon 文件名前缀，
# 于是真实一行长这样：`zeekr_log: [inject-update] 已为 ALL 注入新版本（…）`。
# 不剥掉它，下面所有 startswith("[inject-update]") 都会落空。
_LOG_PREFIXES = ("zeekr_log: ", "zeeload: ", "[warn] ", "[info] ", "[error] ")


def _strip_prefix(t: str) -> str:
    changed = True
    while changed:
        changed = False
        for p in _LOG_PREFIXES:
            if t.startswith(p):
                t = t[len(p):].lstrip()
                changed = True
    return t


def parse_line(line: str, st: EngineState) -> None:
    """把引擎输出映射成界面状态。

    两类来源混在同一个流里：
      * 引擎脚本自己 say 的行：`[ok] …` / `警告 …` / `E10 …`（无前缀）
      * addon 经 mitmproxy 打的行：`zeekr_log: [inject-update] …`（有前缀，先剥）
    """
    t = _strip_prefix(_clean(line))
    if not t:
        return
    if t.startswith("[ok]") and "=" in t and "接口" not in t:
        m = re.match(r"\[ok\] (bridge\d*) = (\d+\.\d+\.\d+\.\d+)", t)
        if m:
            st.iface = f"{m.group(1)} = {m.group(2)}"
    m = re.search(r"车机：(\d+\.\d+\.\d+\.\d+)", t)
    if m:
        if m.group(1):
            st.car = m.group(1)
    if t.startswith("[ok] mitmdump 已启动"):
        st.hooked = True
    elif t.startswith("[inject-update]"):
        st.injects += 1
        st.hooked = True
    elif t.startswith("[replace-apk] 商店已用"):
        st.sign_seen = True
    elif t.startswith("[replace-apk] 以 "):
        m = re.search(r"以 (\S+?) \(", t)
        if m:
            st.replaced.append(m.group(1))
    elif t.startswith("[replace-apk] 该下载"):
        st.passthrough = True
    elif t.startswith("[replace-apk]"):
        pass
    if t.startswith("警告") or t.startswith("[!!]"):
        st.warned += 1
    m = re.match(r"^E(\d+) (.*)$", t)
    if m:
        st.error = m.group(2)
        st.phase = "环境不满足"
        return
    st.phase = _phase_of(st)


def _phase_of(st: EngineState) -> str:
    """阶段 = 已见里程碑里最靠后的那个。

    早先的写法是「每条日志各写一次 phase」，但引擎输出里
    `[ok] mitmdump 已启动` 之后插件仍会继续打 `zeekr_log:` 行，
    而且碰巧顺序不固定，最后一次赋值会把阶段打回去。改成按里程碑归约。
    """
    if st.passthrough:
        return "透传（注入未生效）"
    if st.replaced:
        return "替换下载中"
    if st.injects:
        return "已注入更新"
    if st.sign_seen:
        return "商店已确认，等待下载"
    if st.hooked:
        return "运行中"
    return st.phase


class Round:
    """一次引擎调用。所有回调都在调用方给的事件循环里触发（界面自己决定线程）。"""

    def __init__(self) -> None:
        self.state = EngineState()
        self.proc: subprocess.Popen | None = None
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None

    # --- 生命周期 -------------------------------------------------------
    def start(self, args: list[str],
              on_line: Callable[[str, "Round"], None],
              on_exit: Callable[[int, "Round"], None],
              stdin_text: str | None = None) -> None:
        """args = 引擎参数（不含 sudo）。界面负责先完成提权。"""
        def _run():
            env = os.environ.copy()
            env["PYTHONUNBUFFERED"] = "1"
            try:
                self.proc = subprocess.Popen(
                    args, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                    stdin=subprocess.PIPE if stdin_text else subprocess.DEVNULL,
                    env=env, bufsize=0,
                )
            except OSError as exc:
                on_line(f"E99 启动引擎失败：{exc}", self)
                on_exit(1, self)
                return
            if stdin_text:
                try:
                    self.proc.stdin.write(stdin_text.encode())  # type: ignore[union-attr]
                    self.proc.stdin.flush()                     # type: ignore[union-attr]
                    self.proc.stdin.close()                     # type: ignore[union-attr]
                except (BrokenPipeError, AttributeError):
                    pass
            assert self.proc.stdout is not None
            for raw in iter(self.proc.stdout.readline, b""):
                text = raw.decode("utf-8", "replace")
                for one in text.splitlines() or [""]:
                    parse_line(one, self.state)
                    on_line(_clean(one), self)
                if self._stop.is_set():
                    self._kill()
                    break
            code = self.proc.wait()
            self.state.exit_code = code
            on_exit(code, self)

        self._thread = threading.Thread(target=_run, daemon=True)
        self._thread.start()

    def stop(self) -> None:
        self._stop.set()
        self._kill()

    def _kill(self) -> None:
        p = self.proc
        if p and p.poll() is None:
            try:
                p.terminate()
                for _ in range(30):
                    if p.poll() is not None:
                        break
                    time.sleep(0.1)
                if p.poll() is None:
                    p.kill()
            except Exception:
                pass

    @property
    def running(self) -> bool:
        return self.proc is not None and self.proc.poll() is None


# ---------------------------------------------------------------- 参数拼装

def engine_args(apk_path: str, pkg: str = "ALL", *, domains: str = "",
                hosts: str = "", reset_states: bool = False,
                allow_quic_proxy: bool = False) -> list[str]:
    """GUI/TUI 共用的默认参数：全量 443 + 全解密 + 注入 + 替换。"""
    args = ["bash", ENGINE, "--all-443", "--intercept-all",
            "--inject-update", pkg or "ALL", "--replace-apk", apk_path]
    if domains:
        args += ["--domains", domains]
    if hosts:
        args += ["--hosts", hosts]
    if reset_states:
        args += ["--reset-states"]
    return args


def queue_next(pending: Iterable[str], done: str) -> list[str]:
    """一轮结束后的队列：把已完成的移出去，保留剩下的（供界面显示「还剩 N 个」）。"""
    return [p for p in pending if os.path.abspath(p) != os.path.abspath(done)]
