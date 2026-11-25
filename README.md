# 极载 · ZEEload

> **Research Preview · 仅限小范围学术研究与技术交流，禁止公开分发。**
> 禁止转发至微博、小红书、知乎、B 站、抖音、X、V2EX、贴吧、微信群、Telegram 群、公众号、短视频平台、论坛、导航站或 Awesome 列表。本项目用于观察车机应用商店的更新机制与证书信任链设计，避免脱离研究语境产生误解与合规风险。

> **一句话定位**：在无 root、无 adb、车机禁止未知来源安装的前提下，利用透明代理将第三方 APK 伪装为商店应用更新并完成安装。
> **版本与证据口径**：v1.2.0（2026-11-25，macOS 专用）；已在极氪 7X（ZEEKR OS）实测安装 DiPlay、ES 文件浏览器与 MT 管理器；完整技术论证与抓包证据见 [docs/技术路径-车机APK侧载.md](docs/技术路径-车机APK侧载.md)。本项目为 AI 辅助编程产物，代码未经第三方安全审计。

![ZEEload](assets/banner.png)

---

## 目录

- [1. 适用条件与环境要求](#1-适用条件与环境要求)
- [2. 工作原理与组合漏洞](#2-工作原理与组合漏洞)
- [3. 使用方式（WebUI 与命令行）](#3-使用方式webui-与命令行)
- [4. 连续侧载与引擎生命周期](#4-连续侧载与引擎生命周期)
- [5. 已知限制与安全合规](#5-已知限制与安全合规)
- [6. 排障指引](#6-排障指引)
- [附录](#附录)

---

## 1. 适用条件与环境要求

本工具仅运行于 macOS 13+，除 `mitmproxy >= 12.3` 外全部使用系统自带工具与 Python 标准库实现，车机侧无需任何修改或安装证书。

| 类别 | 最低要求 | 实测基线 | 约束说明 |
|---|---|---|---|
| 车机 | Android 车机（仍信任 `emSign` 根） | 极氪 7X（ZEEKR OS） | 国内车机无 GMS，未同步 2026-10-22 之后的吊销列表；后续 OTA 更新信任库后可能失效 |
| 宿主机 | macOS 13+ | macOS 15.6.1（arm64） | 依赖系统自带 `pf` 与「互联网共享」；需管理员权限配置透明转发 |
| Python | 3.12+ | 3.12.7 | `mitmproxy >= 12.3` 的硬性依赖 |
| mitmproxy | 12.3+ | 12.3.1 | `--emudhra` 参数自 12.3 起提供 |
| 网络拓扑 | Mac 开 Wi-Fi 热点共享网络 | 手机 USB 共享 → Mac → 车机 | 车机必须直连运行本工具的 Mac 热点，无远端代理模式 |

安装 `mitmproxy`（二选一，脚本自动探测包内 `venv/` 与系统 `PATH`，见 `[scripts/transparent-test.sh#L76-L86]`）：

```bash
# 方式 A：项目内虚拟环境（推荐，不污染全局）
python3 -m venv venv && ./venv/bin/pip install mitmproxy

# 方式 B：全局安装
pip3 install mitmproxy
```

安装完成后可执行环境自检：

```bash
python3 --version && mitmdump --version && bash scripts/check-environment.sh
```

> **部署要点**：从 [Releases](https://github.com/zhujinle/ZEELoad/releases) 下载的 `ZEELoad-macOS.zip` 不包含 `mitmproxy` 与任何第三方 APK；若遇 Gatekeeper 拦截，执行 `xattr -dr com.apple.quarantine ZEELoad` 解除隔离属性。

---

## 2. 工作原理与组合漏洞

本方案依赖「传输层证书链失信（漏洞 A）」与「应用层更新路径未校验签名（漏洞 B）」的串联组合，单独利用任一缺陷均无法完成安装。

```text
车机 ──> Mac 互联网共享热点（bridge*）
          ├─ 透明转发：pf 独立 anchor 将车机 TCP 443 重定向至 127.0.0.1:18080，阻断目标 IPv6 回退 IPv4
          ├─ 透明解密：mitmdump --mode transparent --emudhra（车机仍信任 emSign 根）
          ├─ 元数据注入：改写 appList / 详情页响应，抬高版本号并覆写 sha256 / apkMd5 / apkSize
          └─ 流式替换：拦截 .apk 下载，按 Range 返回目标 APK 切片（256 KB 分块流式发送）
车机商店：哈希校验通过 → 请求 /app/signature（服务端返回 sign: null，商店不拦截）→ 安装器按新应用安装
```

| 漏洞环节 | 机制缺陷 | 在侧载链中的作用 | 实现与证据位置 |
|---|---|---|---|
| **漏洞 A（传输层）** | eMudhra 中间 CA 私钥泄露（2026-10-17 披露），车机未吊销 `emSign` 根 | 无证书解密并改写 `*.zeekrlife.com` 的 HTTPS 流量 | `[scripts/transparent-test.sh#L450-L466]` |
| **漏洞 B（应用层）** | 服务端对非官方哈希返回 `sign: null`，但商店「更新」路径未拦截空签名 | 以「更新」名义绕过直接安装路径的签名授权门闩 | [技术路径 §4.5](docs/技术路径-车机APK侧载.md#45-两个漏洞的组合核心结论) |
| **元数据注入** | 商店以响应体中的哈希作为本地校验基准，且按版本号缓存 | 用目标 APK 的 SHA-256 前 7 位派生 `apkVersion` 破除缓存，同时武装下载路径 | `[addons/zeekr_log.py#L348-L362]`、`[addons/zeekr_log.py#L504-L543]` |
| **流式替换闸门** | 下载响应在 `responseheaders` 阶段按 `Range` 接管 | 仅在命中已武装路径（30 分钟内）或签名请求匹配替换哈希（15 分钟内）时替换，其余原样透传 | `[addons/zeekr_log.py#L146-L208]`、`[addons/zeekr_log.py#L249-L258]` |

> **关键结论**：本方法未攻破 APK 签名或服务端签名机制，而是绕过了客户端更新路径的校验点；由于目标 APK 与宿主应用包名不同，系统安装器会将其作为**新应用**安装，无法覆盖升级已有应用。

---

## 3. 使用方式（WebUI 与命令行）

项目提供三步向导 WebUI 与一键终端脚本两种入口，底层均调用同一引擎 `[scripts/transparent-test.sh]`，状态与日志完全一致。

| 入口文件 | 命令行等价写法 | 形态 | 适用场景 |
|---|---|---|---|
| `zeeload.command` | `./zeeload.command [a.apk b.apk]` | 浏览器 WebUI（默认） | 可视化三步向导、三态浅深调光、拖拽排序队列、实时进度仪表盘 |
| `一键侧载安装.command` | `sudo bash scripts/zeekr-sideload.sh --apk a.apk ...` | 终端交互脚本 | 直接把一个或多个 APK 拖到图标上即刻执行 |
| `检查环境.command` | `bash scripts/check-environment.sh` | 只读诊断脚本 | 检查共享接口、车机租约与 `mitmdump` 状态 |
| `停止并恢复.command` | `sudo bash scripts/stop-transparent.sh` | 兜底清理脚本 | 异常中断后手动卸载 `pf` 规则并停止残留代理 |

> 备用入口 `./zeeload.command --tk` 保留旧版 Tk 窗口（`zeeload/gui.py`），但 Tk 8.5 在 macOS Retina 上存在版式异常，不推荐使用。

### 3.1 WebUI 三步向导

WebUI 由标准库 `ThreadingHTTPServer`（`zeeload/webui.py`）与无外链单文件页面（`zeeload/web/index.html`）组成，支持**自动 / 浅色 / 深色**三态调光（适应白天车内反光环境），仅监听 `127.0.0.1` 随机空闲端口，通过系统文件选择器读取本机路径，不上传文件。

1. **选择 APK**：支持「选择 APK（设为主任务）」与「+ 追加到队列尾」独立操作，也可手动粘贴本地路径；清单支持按 `⠿` 拖拽排序、单条移除与清空，队首始终与当前任务保持同步，且运行期间自动锁定队首防止篡改（`[zeeload/webui.py#L57-L115]`、`[zeeload/webui.py#L462-L545]`）。
2. **环境与权限**：上半区逐项体检 `mitmdump`（含 `--emudhra`）、共享接口 `bridge*`、车机 DHCP 租约与 `18080` 端口占用（采用分层 TTL 缓存与回环快速探测避免轮询卡顿，见 `[zeeload/webui.py#L139-L185]`）；下半区内联验证管理员权限（密码经 `sudo -S` 校验不落盘，见 `[zeeload/webui.py#L577-L596]`，运行期间后台自动续期时间戳，见 `[zeeload/webui.py#L201-L209]`）。
3. **开始侧载**：顶部常驻显示当前目标 APK 名称与剩余排队数量（运行中刷新页面会自动定位至本步）；点「开始侧载」后按高亮提示条在车机打开应用商店 → **点开任意已安装应用的详情页** → 待状态变为「已注入更新」后点击「更新」→ 待车机屏幕安装完成后点「停止并卸载规则」（自定义日志路径见 `[zeeload/webui.py#L292-L298]`）。

> **进度解析机制**：`common.py` 先剥离 mitmproxy 自动添加的 `zeekr_log: ` 前缀，再按里程碑归约当前阶段（运行中 → 已注入更新 → 商店已确认 → 替换下载中；若遇缓存透传自动告警并在新注入后解除），避免异步日志乱序导致进度回退（`[zeeload/common.py#L235-L312]`）。

### 3.2 一键脚本与高级参数

将 APK 拖至 `一键侧载安装.command`（支持一次拖入多个），或在终端执行：

```bash
# 注入所有已安装应用（默认 ALL）
sudo bash scripts/zeekr-sideload.sh --apk /path/to/app.apk

# 仅针对指定包名注入
sudo bash scripts/zeekr-sideload.sh --apk app.apk --pkg com.zeekr.media.podcast

# 只读预检（不加载 pf 规则、不启代理）
bash scripts/transparent-test.sh --check-only --all-443
```

可用环境变量覆盖自动探测：`ZEEKR_IFACE`、`ZEEKR_CAR_IP`、`ZEEKR_CAR_MAC`、`ZEEKR_VENV`、`ZEEKR_DOMAINS`、`ZEEKR_HOSTS`、`ZEEKR_OUT_BASE`。

> **操作要点**：商店对更新列表存在缓存，必须在车机上**点开应用详情页**触发实时元数据请求，确认日志出现 `[inject-update]` 后再点击更新。

---

## 4. 连续侧载与引擎生命周期

批量安装采用「一轮一进程」架构，每轮独立完成 pf 加载、代理启动与退出清理，避免跨轮状态污染。

```text
WebUI 队列 / zeekr-sideload.sh 循环
  └─ 单轮调用 transparent-test.sh（自洽单元）
       ├─ 加载独立 pf anchor（com.apple/zeekr-capture）+ 阻断目标 IPv6
       ├─ 启动 mitmdump（带 PYTHONDONTWRITEBYTECODE=1，独立输出 logs/<时间戳>/）
       └─ 退出 trap（EXIT / INT / TERM / HUP）：记录 pf 计数器 → 卸载 anchor → 停止 mitmdump → 归还目录属主
```

- **干净隔离**：每轮新建 `mitmdump` 进程，`_armed_paths` 与 `_override_seen_at` 随进程销毁；卸载与重载之间存在约 3–5 秒切网空窗，须待上一个 APK 在车机安装完成后再开始下一轮（`[scripts/transparent-test.sh#L163-L218]`）。
- **队列推进**：WebUI 在单轮正常结束（退出码 `0` / `130`）后自动将已完成 APK 移出清单并切换至队首下一条（`[zeeload/webui.py#L247-L260]`）；命令行脚本按 `Ctrl-C` 仅结束当前轮并回到「下一个」提示，回车继续队列、拖入路径可追加、`n` 退出（`[scripts/zeekr-sideload.sh#L170-L204]`）。
- **可靠停止**：WebUI 点击「停止」时，若普通用户向 `sudo` 子进程发信号遇到 `PermissionError`，自动回退至 `sudo kill -TERM` 优雅退出；超时未退则强杀子进程树并调用 `stop-transparent.sh` 兜底清空 `pf` anchor（`[zeeload/common.py#L374-L401]`、`[zeeload/webui.py#L282-L290]`）。

> **设计结论**：不修改 `/etc/pf.conf` 且每轮重置 anchor，使系统网络状态在正常退出或异常兜底后均可完整恢复。

---

## 5. 已知限制与安全合规

本工具仅适用于自有车辆的技术研究与自用场景，且受限于车机系统策略与当前漏洞窗口期。

### 5.1 已知技术限制

- **仅可安装新包**：无法覆盖或升级车机已有同包名应用（系统安装器校验包名与签名一致性）。
- **仅转发 IPv4**：通过 `block return quick` 阻断目标域名 IPv6 流量以迫使客户端回退 IPv4（`[scripts/transparent-test.sh#L380-L387]`）。
- **全量解密影响范围**：默认开启 `--intercept-all` 时，做了证书固定的个别车机应用可能暂时异常，停止工具后恢复。
- **时效性边界**：车机 OTA 更新根信任库或应用商店修复 `sign: null` 校验后，本路径将失效。

### 5.2 安全与合规声明

- **严禁商业用途**：禁止用于收费代装、付费服务、硬件捆绑销售、付费培训或任何形式的变现。
- **权属与质保责任**：仅限用于本人名下车辆；安装非官方应用可能影响整车或车机质保，相关法律与财产风险由使用者自行承担。
- **数据本地化**：工具不收集、不上传任何数据，运行日志仅保存在本机输出目录；仓库与发布包不含任何第三方 APK。

> **合规要点**：退出工具或执行 `停止并恢复.command` 即可恢复车机直连网络，车机侧不残留任何证书或系统分区改动。

---

## 6. 排障指引

### 6.1 运行异常排查表

| 症状 / 现象 | 机制诱因 | 排查与处置步骤 |
|---|---|---|
| 终端未出现 `[inject-update]` | 应用商店复用本地列表缓存，未发起新的元数据请求 | 在车机商店**点开任意应用的详情页**触发实时请求；若仍无日志，在「设置 → 应用 → 应用商店」强行停止或重启车机后重试 |
| 出现 `[replace-apk] 该下载…按原样透传` | 下载发生前未命中已武装路径或替换哈希签名请求，触发防误替换闸门（`[addons/zeekr_log.py#L154-L163]`） | 先按上一条触发 `[inject-update]`，确认元数据注入成功后再点击更新 |
| 商店提示「下载失败」 | 实际下载内容哈希与元数据不一致（替换未生效或中途断网） | 查看当轮 `logs/<时间戳>/mitm.log` 是否出现 `[replace-apk] 以 xxx.apk 替换下载`；确认车机未切换 Wi-Fi |
| 安装报「包名冲突 / 签名不一致」 | 目标 APK 包名与车机已安装应用相同但签名不同 | 更换不同包名的 APK，无法覆盖官方内置应用 |
| 安装完成但桌面无图标 | 车机桌面启动器过滤非白名单应用 | 重启车机，或从车机「设置 → 应用」中直接启动 |
| 退出后车机无法上网 | 异常中断导致 `pf` anchor 未卸载或 `mitmdump` 残留 | 执行 `停止并恢复.command`（或 `sudo bash scripts/stop-transparent.sh`），核对 `pfctl -a com.apple/zeekr-capture -s rules` 为空 |

### 6.2 引擎结构化退出码

引擎在环境预检阶段返回固定退出码，供 WebUI 与脚本精准翻译提示并允许原地重试（`[scripts/transparent-test.sh#L228-L295]`、`[zeeload/common.py#L31-L45]`）：

| 退出码 | 含义 | 处置方式 |
|---|---|---|
| `0` / `130` | 本轮正常结束 / `Ctrl-C` 正常中断 | 无异常；存在后续队列时可继续下一轮 |
| `10` | 未检测到活跃 `bridge*` 共享接口或车机未连接 | 开启「系统设置 → 通用 → 共享 → 互联网共享」并让车机重连热点 |
| `11` | 代理端口 `18080` 被占用 | 点击「停止」或运行 `停止并恢复.command` 清理残留进程 |
| `12` | 未找到可执行 `mitmdump` | 在项目内建 `venv/` 安装 `mitmproxy`，或通过 `ZEEKR_VENV` 指定路径 |
| `13` | `mitmproxy` 版本低于 12.3（缺少 `--emudhra`） | 执行 `pip3 install -U mitmproxy` 升级至 12.3+ |

---

## 附录

### A. 文件结构

```text
ZEEload/
├── README.md                    项目说明（本文档）
├── zeeload.command              ★ WebUI 入口（默认浏览器三步向导；--tk 备用）
├── 一键侧载安装.command          ★ 命令行拖拽入口（支持一次拖入多个 APK）
├── 停止并恢复.command            兜底清理：卸载 pf anchor、停止代理
├── 检查环境.command              只读环境诊断
├── zeeload/                     界面层（纯 Python 标准库）
│   ├── common.py                引擎调用、状态机解析、APK 哈希、环境探测
│   ├── webui.py                 WebUI 后端（ThreadingHTTPServer + JSON API）
│   ├── web/index.html           WebUI 前端（单文件，无外链）
│   └── gui.py                   旧版 Tk 窗口（降级备用）
├── scripts/
│   ├── zeekr-sideload.sh        CLI 多轮循环入口
│   ├── transparent-test.sh      核心引擎：pf 透明转发 + mitmdump 生命周期
│   ├── stop-transparent.sh      卸载 pf 规则与停止代理
│   ├── check-environment.sh     只读环境自检
│   └── inspect-pf.sh            只读导出 pf 规则（排障用）
├── addons/zeekr_log.py          mitmproxy 插件（注入 / 流式替换 / 脱敏记录）
├── docs/技术路径-车机APK侧载.md  原理、双漏洞论证、实测证据与接口字段
├── assets/                      Logo 与宣传图（svg / png / icns / ico）
└── logs/                        每次运行的输出目录（不入库）
```

### B. 版本演进与修订记录

#### 近期修订留痕（v1.2.0 纠偏与精简）

| 旧版行为 | 新版行为 | 依据与文件行号 |
|---|---|---|
| `/api/state` 每 0.9 秒同步拉起 `mitmdump --version/--help` 与 `lsof`（单次约 1.5 秒），前端无锁并发轮询导致 CPU 飙高且重复追加日志 | 后端对 `mitmdump` 静态缓存、网络探测做 2.5s TTL 缓存并用 `connect_ex` 快速探活（轮询降至 `<1 ms`）；前端改用串行 `setTimeout` 与 `log_base` 幂等对齐 | `[zeeload/webui.py#L139-L185]`、`[zeeload/common.py#L190-L208]`、`[zeeload/web/index.html#L527-L635]` |
| 运行期间 `18080` 被本会话占用误判为环境冲突；`passthrough` 一旦触发永久锁死阶段且遮蔽 `sign_seen` | 运行期识别 `port_self` 不标红阻塞；新注入/签名/替换自动解除 `passthrough`，调整 `_phase_of` 优先级并在前端补齐透传告警 | `[zeeload/webui.py#L168-L183]`、`[zeeload/common.py#L264-L312]`、`[zeeload/web/index.html#L392-L406]` |
| WebUI 点击「停止」向 `sudo` 子进程发信号触发 `PermissionError`；不勾选记住密码时超 5 分钟 `sudo` 过期失效 | 运行期间后台每 45s 自动续期 `sudo -n -v`；停止回退 `sudo kill -TERM`，强杀兜底清理子进程并执行 `stop-transparent.sh` | `[zeeload/common.py#L374-L401]`、`[zeeload/webui.py#L201-L209]`、`[zeeload/webui.py#L282-L290]` |
| WebUI 选文件后首项重复入队、运行中可误改当前包，且本地 HTTP 接口缺少鉴权与 DOM 转义 | 统一队首同步并在运行期锁定队首；注入随机 `X-ZEEload-Token` 与 `Host`/`Origin` 校验防御 CSRF/DNS Rebinding，动态文本全量 HTML 转义 | `[zeeload/webui.py#L57-L115]`、`[zeeload/webui.py#L321-L337]`、`[zeeload/web/index.html#L377-L380]` |
| 高级设置 `outdir` 未透传给引擎；仓库同时维护 WebUI、curses TUI 与备用 Tk | 引擎新增 `--out-dir` 与 `PYTHONDONTWRITEBYTECODE=1`；移除 TUI（`tui.py`、`终端界面.command`、`style.tcss`），收敛为 WebUI + 一键脚本双入口 | `[scripts/transparent-test.sh#L66-L68]`、`[zeeload.command#L27-L48]` |

#### 历史版本摘要

- **v1.2.0（2026-11-25）**：WebUI 重构为四步向导（导入 APK → 检查环境 → 获取权限 → 开始任务）；修复 `zeekr_log: ` 日志前缀导致状态不推进与 `pipefail` 导致 `E13` 误报；后精简移除 TUI 分支并修复上述 WebUI 队列/停止/输出目录缺陷。
- **v1.1.0（2026-11-25）**：新增多轮连续侧载与引擎结构化退出码（`10/11/12/13`）；移除 Windows 实现（`windows/` 目录约 2,900 行，历史版本见 `v1.0.1` 标签）。
- **v1.0.1（2026-10-31）**：补全 Windows ICS 透明劫持与图形界面（已于 v1.1.0 移除）。
- **v1.0.0（2026-10-30）**：首个版本发布，在极氪 7X 验证 `pf` 透明转发 + `mitmproxy --emudhra` + 更新注入 + 流式替换全链路。

### C. 参考资料

- [mitmproxy Transparent Proxying](https://docs.mitmproxy.org/stable/howto/transparent/)
- [mitmproxy Certificates](https://docs.mitmproxy.org/stable/concepts/certificates/)
- [eMudhra Incident Overview](https://emudhra.we-have-a-problem.com/)
