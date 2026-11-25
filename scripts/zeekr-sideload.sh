#!/bin/bash
# zeekr-sideload.sh — 把任意 APK 通过极氪应用商店的「检查更新」通道安装到车机
#
# 原理：注入假更新（把已安装应用的版本抬高、哈希/大小指向目标 APK）+ 替换下载内容。
# 需要管理员权限（配置 pf 透明转发）。支持连续装多个 APK：一轮装完回车输入下一个，
# 输入 n 回车退出（n 后面可以跟一串 APK 路径，批量排队）。
#
# 用法：
#   sudo bash scripts/zeekr-sideload.sh --apk /path/to/app.apk
#   sudo bash scripts/zeekr-sideload.sh --apk a.apk b.apk c.apk        # 批量
#   sudo bash scripts/zeekr-sideload.sh --apk app.apk --pkg com.zeekr.media.podcast
#   之后每轮结束按提示输入下一个 APK 路径即可；直接回车 = 退出
#
# 每一轮都会重新加载 pf anchor 并重启 mitmdump（约 3–5 秒），车机断网只在这几秒内。

set -uo pipefail
umask 077

SELF_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
BASE=$(cd "$SELF_DIR/.." && pwd)

PKG="ALL"
APKS=()

while [ $# -gt 0 ]; do
  case "$1" in
    --apk)
      [ $# -ge 2 ] || { echo "--apk 需要文件路径" >&2; exit 2; }
      shift
      while [ $# -gt 0 ] && [ "${1#-}" = "$1" ]; do
        APKS+=("$1"); shift
      done ;;
    --pkg)
      [ $# -ge 2 ] || { echo "--pkg 需要包名或 ALL" >&2; exit 2; }
      PKG=$2; shift 2 ;;
    -h|--help)
      sed -n '2,15p' "$0"; exit 0 ;;
    *)
      # 允许直接传 APK 路径（可多个）
      if [ -f "$1" ]; then APKS+=("$1"); shift; else
        echo "未知参数：$1" >&2; exit 2
      fi ;;
  esac
done

# 去掉空串（--apk "" 这种）
clean=()
for a in ${APKS[@]+"${APKS[@]}"}; do [ -n "$a" ] && clean+=("$a"); done
APKS=(${clean[@]+"${clean[@]}"})
if [ "${#APKS[@]}" -lt 1 ]; then
  echo "用法：$0 --apk /path/to/app.apk [more.apk ...] [--pkg 包名|ALL]" >&2
  exit 2
fi

# 启动时先把给定的 APK 校验一遍，别等到第一轮开始才报错
for a in "${APKS[@]}"; do
  [ -f "$a" ] || { echo "错误：APK 不存在：$a" >&2; exit 2; }
  file "$a" | grep -qi 'zip' || { echo "错误：$a 不是 zip/APK 文件（是不是把 .command 或其他文件当成 APK 了？）" >&2; exit 2; }
done

say() { printf '%s\n' "$*"; }
warn() { printf '警告：%s\n' "$*" >&2; }

# 把用户输入（可能带引号、可能一次多个路径）解析成规范化的绝对路径数组
# 用法：parse_input "<原始输入>" -> 结果写进全局数组 PARSED
parse_input() {
  local raw=$1
  PARSED=()
  raw=${raw//\'/}
  raw=${raw//\"/}
  local -a tok
  read -r -a tok <<< "$raw"
  local p abs
  for p in ${tok[@]+"${tok[@]}"}; do
    if [ "$p" = "${p#/}" ] && [ -n "${OLDPWD:-}" ] && [ -f "$OLDPWD/$p" ]; then
      p="$OLDPWD/$p"
    fi
    abs=$(cd "$(dirname "$p")" 2>/dev/null && pwd)/$(basename "$p")
    if [ ! -f "$abs" ]; then
      warn "找不到文件：$p"
      continue
    fi
    if ! file "$abs" | grep -qi 'zip'; then
      warn "不是 zip/APK 文件：$abs（是不是把 .command 当成 APK 了？）"
      continue
    fi
    PARSED+=("$abs")
  done
}

# 调引擎并翻译退出码（引擎用 10/11 等结构化码回报「环境不满足」）
# 返回 0 = 本轮正常结束；非 0 = 环境问题，调用方提示修复后回到「下一个」
run_engine() {
  local apk=$1
  bash "$SELF_DIR/transparent-test.sh" --all-443 --intercept-all \
    --inject-update "$PKG" --replace-apk "$apk"
  local rc=$?
  case "$rc" in
    0)   return 0 ;;
    130) say "[i] 本轮被中断（Ctrl-C），属于正常收尾"; return 0 ;;
    10)
      warn "车机没连上热点：请确认车机 Wi-Fi 已连到本机共享网络"
      warn "  · 系统设置 → 通用 → 共享 → 互联网共享 保持开启"
      warn "  · 车机上「设置 → Wi-Fi」重新连一次"
      return 10 ;;
    11)
      warn "代理端口被占用：可能上一次的 mitmdump 没退出"
      warn "  · 运行『停止并恢复.command』后再继续"
      return 11 ;;
    12)
      warn "找不到 mitmdump：先装 mitmproxy"
      warn "  · pip3 install mitmproxy   或   python3 -m venv venv && ./venv/bin/pip install mitmproxy"
      return 12 ;;
    13)
      warn "mitmproxy 版本过低（缺 --emudhra，需要 12.3+）"
      warn "  · python3 -m pip install -U mitmproxy"
      return 13 ;;
    *)
      warn "本轮失败（退出码 $rc），详情见上面的日志"
      return "$rc" ;;
  esac
}

# 跑一整轮：算哈希 → 调引擎（自己加载/卸载 pf、启停 mitmdump）
run_one() {
  local apk=$1 n=$2 total=$3
  local size sha md5 mib
  size=$(stat -f %z "$apk")
  sha=$(shasum -a 256 "$apk" | awk '{print $1}')
  md5=$(md5 -q "$apk")
  mib=$(awk -v s="$size" 'BEGIN{printf "%.2f", s/1048576}')

  say ""
  say "========================================"
  say "极载 ZEEload · 第 $n/$total 个"
  say "  APK    : $apk"
  say "  大小    : $size 字节（${mib} MiB）"
  say "  sha256 : $sha"
  say "  md5    : $md5"
  say "  注入包  : $PKG"
  say "========================================"
  say ""
  say "车机侧操作（本轮启动后）："
  say "  1) 打开应用商店 → 我的 / 检查更新"
  say "  2) 出现「有更新」后，点任意一个应用的更新"
  say "  3) 进度走完即安装的是上面的 APK，然后在这里按 Ctrl-C 结束本轮"
  say ""
  say "注意：先看终端是否出现 [inject-update] 行。"
  say "  出现  → 商店已取到新元数据，可以点更新"
  say "  没出现 → 商店在用缓存：到 设置 → 应用 → 应用商店 里「强行停止」，"
  say "           或重启车机，再重开商店点「检查更新」"
  say ""

  run_engine "$apk"
  local rc=$?
  if [ "$rc" = 0 ]; then
    say "[ok] 第 $n 个已结束"
  else
    say "[!] 第 $n 个因环境问题提前结束；修好上面提示的问题后回到「下一个」提示继续"
  fi
  return "$rc"
}

# ---------------- 主循环 ----------------

index=0
batch=("${APKS[@]}")
total=${#batch[@]}

while :; do
  if [ "$index" -lt "${#batch[@]}" ]; then
    apk=${batch[$index]}
    index=$((index + 1))
    run_one "$apk" "$index" "$total"
  fi

  # 一轮结束：提示继续
  say ""
  say "----------------------------------------"
  if [ "${#batch[@]}" -gt "$index" ]; then
    say "队列里还剩 $(( ${#batch[@]} - index )) 个："
    li=$index
    while [ "$li" -lt "${#batch[@]}" ]; do
      say "  - $(basename "${batch[$li]}")"
      li=$((li + 1))
    done
    say ""
  fi
  say "回车直接继续下一个；输入 APK 路径（可空格隔开多个，可带引号）继续；"
  say "输入 n 回车结束。"
  read -r -p "下一个: " ans || { say ""; say "输入结束，退出。"; break; }
  if [ "$ans" = "n" ] || [ "$ans" = "N" ]; then
    break
  fi
  if [ -n "${ans// /}" ]; then
    parse_input "$ans"
    if [ "${#PARSED[@]}" -ge 1 ]; then
      batch+=("${PARSED[@]}")
      total=${#batch[@]}
    else
      say "没有可用的 APK，回到提示。"
    fi
  fi
done

say ""
say "[ok] 全部结束。车机侧如需恢复网络，确认『停止并恢复.command』已跑过或车机已断开热点。"
exit 0
