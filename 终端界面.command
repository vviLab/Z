#!/bin/bash
# 终端界面.command — 极载 ZEEload 的终端界面（TUI）
#
#   双击：在「终端」里打开 TUI；要侧载的 APK 直接拖进终端窗口
#   带参数：终端界面.command a.apk b.apk  → 参数直接进队列
#
# 与 ./zeeload.command --tui 等价，单独一个文件只是为了能直接双击。
# 为什么要绕一层开终端：.command 被「终端」双击时偶尔不分配窗口尺寸，
# curses 会以 80x24 启动或直接报错，所以没有 TTY 时由本脚本自己新开一个终端窗口。

set -uo pipefail
cd "$(dirname "$0")"
ROOT=$PWD
SELF="$ROOT/$(basename "$0")"

if [ "${1:-}" = "--in-terminal" ]; then
  shift
elif [ -t 0 ] && [ -n "${TERM:-}" ]; then
  :                                  # 已经在终端里，直接跑
else
  osascript >/dev/null 2>&1 <<OSA && exit 0
tell application "Terminal"
  activate
  do script "cd $(printf %q "$ROOT") && exec $(printf %q "$SELF") --in-terminal"
end tell
OSA
  echo "没能自动打开终端窗口。请打开「终端」，cd 到："
  echo "  $ROOT"
  echo "然后执行：./终端界面.command"
  read -r -p "按回车关闭。" _
  exit 1
fi

PY=""
for p in "${ZEEKR_PY:-}" "$ROOT/venv/bin/python3" "$(command -v python3 || true)" /usr/bin/python3; do
  [ -n "$p" ] && [ -x "$p" ] || continue
  PY=$p; break
done
[ -n "$PY" ] || { echo "找不到可用的 python3"; read -r -p "按回车关闭。" _; exit 1; }

export PYTHONPATH="$ROOT${PYTHONPATH:+:$PYTHONPATH}"
exec "$PY" -m zeeload.tui "$@"
