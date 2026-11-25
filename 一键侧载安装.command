#!/bin/bash
# 双击运行（或把 APK 拖到这个文件上）：通过车机应用商店的更新通道安装 APK
# 支持一次拖多个 APK；也可以只拖一个，之后在窗口里按提示继续输入下一个。
set -uo pipefail
cd "$(dirname "$0")"
mkdir -p logs
CMDLOG="logs/sideload-$(date +%Y%m%d-%H%M%S).log"
exec > >(tee -a "$CMDLOG") 2>&1
echo "[输出同时保存到 $CMDLOG]"
echo ""

ARGS=()
for f in "$@"; do
  if [ -f "$f" ]; then
    ARGS+=("$f")
  fi
done

if [ "${#ARGS[@]}" -eq 0 ]; then
  echo "把 APK 拖到这个窗口里（可多个，空格分隔），或直接输入路径："
  read -r -p "APK 路径: " LINE
  # 去掉拖入时终端自动加的引号与转义
  LINE=${LINE//\\ / }
  read -r -a ARGS <<< "$LINE"
fi

if [ "${#ARGS[@]}" -eq 0 ]; then
  echo "没有拿到 APK 路径。"
  read -r -p "按回车关闭窗口。" _
  exit 1
fi

# 不需要管理员权限的前置检查：先查完再要密码，别白输一次
preflight() {
  local ok=0
  local md=""
  if [ -n "${ZEEKR_VENV:-}" ]; then
    md=$ZEEKR_VENV/bin/mitmdump
  elif [ -x "venv/bin/mitmdump" ]; then
    md=venv/bin/mitmdump
  else
    md=$(command -v mitmdump 2>/dev/null || true)
  fi
  if [ -z "$md" ] || [ ! -x "$md" ]; then
    echo "[!!] 没找到 mitmdump：先装 mitmproxy"
    echo "     pip3 install mitmproxy"
    echo "     或 python3 -m venv venv && ./venv/bin/pip install mitmproxy"
    ok=1
  elif ! "$md" --help 2>&1 | grep -q -- '--emudhra'; then
    echo "[!!] mitmproxy 版本过低：缺 --emudhra（需要 12.3+）"
    echo "     python3 -m pip install -U mitmproxy"
    ok=1
  else
    echo "[ok] mitmdump: $("$md" --version 2>&1 | head -1)"
  fi
  # 共享接口（不需要 root，bridge 通常有读权限）
  local ifc=""
  ifc=$(ifconfig -l 2>/dev/null | tr ' ' '\n' | grep '^bridge' | while read -r c; do
          ifconfig "$c" 2>/dev/null | grep -q 'status: active' && { echo "$c"; break; }
        done | head -1)
  if [ -z "$ifc" ]; then
    echo "[!!] 没检测到共享接口：请先打开「系统设置 → 通用 → 共享 → 互联网共享」"
    ok=1
  else
    echo "[ok] 共享接口: $ifc"
  fi
  return "$ok"
}

if ! preflight; then
  echo ""
  read -r -p "环境不满足，按回车退出（先修好再重跑）。" _
  exit 1
fi

sudo -p "Mac 管理员密码: " bash scripts/zeekr-sideload.sh --apk "${ARGS[@]}"
status=$?

echo ""
echo "退出状态：$status"
if [ "$status" != 0 ]; then
  echo "若车机网络异常，运行『停止并恢复.command』。"
fi
read -r -p "按回车关闭窗口。" _
