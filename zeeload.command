#!/bin/bash
# zeeload — 极载 ZEEload 的入口
#
#   ./zeeload.command            # WebUI（推荐）
#   ./zeeload.command --tk       # 旧的原生 Tk 窗口（版式不可靠，仅备用）
#   ./zeeload.command a.apk b.apk
#
# WebUI 只用标准库，任何 python3.9+ 都能跑；
# 只有 --tk 需要带 Tk 的解释器（Homebrew 3.14 没有 _tkinter）。

set -uo pipefail
cd "$(dirname "$0")"
ROOT=$PWD

pick_python() {
  local want_tk=$1 p
  for p in "${ZEEKR_PY:-}" "$ROOT/venv/bin/python3" "$(command -v python3 || true)" /usr/bin/python3; do
    [ -n "$p" ] && [ -x "$p" ] || continue
    if [ "$want_tk" = 1 ]; then
      "$p" -c 'import tkinter' >/dev/null 2>&1 || continue
    fi
    echo "$p"; return 0
  done
  return 1
}

MODE=web
case "${1:-}" in
  --tk)  MODE=tk;  shift ;;
  --web) MODE=web; shift ;;
  "")    MODE=web ;;
esac

if [ "$MODE" = tk ]; then
  PY=$(pick_python 1) || {
    echo "没有找到带 Tk 的 Python，--tk 起不来。"
    echo "用默认的 WebUI 即可：./zeeload.command"
    read -r -p "按回车关闭。" _
    exit 1
  }
else
  PY=$(pick_python 0) || { echo "找不到可用的 python3"; exit 1; }
fi

export PYTHONPATH="$ROOT${PYTHONPATH:+:$PYTHONPATH}"
case "$MODE" in
  tk) exec "$PY" -m zeeload.gui "$@" ;;
  *)  exec "$PY" -m zeeload.webui "$@" ;;
esac
