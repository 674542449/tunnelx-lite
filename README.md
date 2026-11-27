# txlite

一个可以单独使用的代理服务：服务器一键安装，复制分享链接，粘贴进 Windows 客户端就能用。没有账号、没有订阅后台。

- **双协议同机自动部署**：
  1. **TCP Vision（`txlite://`）**：纯 TCP（TLS 1.3 + ECH 加密 SNI），自签证书公钥指纹固定，无需域名；默认采用 **TCP 直连 + Vision 零拷贝直通**（握手随机填充消除 TLS 套 TLS 特征，内层 TLS 1.3 建连后剥离外层加密并启用 Linux `splice(2)` 零拷贝）。
  2. **TXPulse（`txpulse://`）**：借鉴 Hysteria 2 优缺点全新纯 Go 重写的自研抗丢包 UDP 协议（零 `quic-go` 依赖）：
     - 独立 20 年**自签 ECDSA P-256 证书 + 公钥指纹固定（`CertPin`）+ X25519 前向保密**，无需域名且彻底杜绝 `insecure=1` 中间人风险；
     - 彻底脱离 QUIC / HTTP/3 与 `233` 特征，结构化伪装前缀 + 每包独立掩码头 + 动态长度填充 + 防重放时间窗，未授权主动探测静默丢弃（0 字节响应）；
     - 自研自适应 **HyBBR** 拥塞控制（免填带宽区分随机丢包与真实拥塞，杜绝原版 Brutal 盲目发包导致的 Bufferbloat 与运营商封杀）；
     - 单连接独立多流复用（按流 SACK / 快速重传 / 流控，无队头阻塞）、原生 UDP 自动分片重组、移动网络无缝连接迁移与可选原生无 iptables UDP 端口跳跃。
- **服务端**：Ubuntu / Debian，**入口可选双栈 / 仅 IPv4 / 仅 IPv6，出站落地固定仅 IPv4**；自带 HTTPS 管理面板和 `txlite` 命令行菜单；安装/更新时自动开启 BBR + fq 与 32 MB 网络缓冲调优。
- **客户端**：Windows 图形界面 + Android 原生免 Root 客户端（~7 MB 精简包），支持绕过大陆、全局代理、TUN 模式、防污染 DNS 覆写与常见网站分流 IP 检查。

## 服务端安装

用 root 执行：

```bash
bash <(curl -fsSL https://raw.githubusercontent.com/674542449/tunnelx-lite/main/scripts/install.sh)
```

安装完成后会打印：

- 面板地址（`https://服务器IP:面板端口/随机路径/`）和面板密码
- IPv4 / IPv6 分享链接（同时生成 `txlite://…` TCP Vision 与 `txpulse://…` 自研类 Hy2 UDP 链接）

云服务器请在安全组放行代理端口的 **TCP**（Vision）、**UDP**（TXPulse，以及可选端口跳跃段）和面板端口的 **TCP**。

端口默认随机。想指定端口或开启 UDP 端口跳跃：

```bash
PORT=443 PULSE_PORT=8444 PULSE_HOP=20000-20031 PANEL_PORT=8443 bash <(curl -fsSL https://raw.githubusercontent.com/674542449/tunnelx-lite/main/scripts/install.sh)
```

入站 / 出站的 IP 版本也可以在安装时指定（之后也能在面板「设置」里改）：

```bash
INBOUND=ipv6 OUTBOUND=ipv6 bash <(curl -fsSL https://raw.githubusercontent.com/674542449/tunnelx-lite/main/scripts/install.sh)
```

| 变量 | 可选值 | 含义 |
|---|---|---|
| `INBOUND` | 留空（双栈）、`ipv4`、`ipv6` | 代理端口接受哪种 IP 的客户端连接；分享链接会跟着只给对应地址 |
| `OUTBOUND` | 留空（自动）、`prefer_ipv4`、`prefer_ipv6`、`ipv4`、`ipv6` | 服务器访问目标网站用哪种 IP |

**云服务器记得在安全组放行这两个 TCP 端口。** 如果系统启用了 ufw，安装脚本会自动放行。

以后在服务器上输入 `txlite` 打开管理菜单：查看面板地址和分享链接、重置面板密码、重启 / 停止 / 启动、查看日志、更新、卸载。

| 命令 | 作用 |
|---|---|
| `txlite` | 管理菜单 |
| `txlite info` | 面板地址与分享链接 |
| `txlite link` | 只看分享链接 |
| `txlite password` | 重置面板密码并重启服务 |

### 管理面板

面板使用服务器自己的自签证书，浏览器提示"不安全"时选择继续访问即可。面板只在随机路径下响应，其他路径一律返回 404。

- 运行时间、当前连接、累计上下行和实时速率、系统负载 / 内存 / 磁盘、拥塞控制
- 分享链接（IPv4 / IPv6 / 自定义地址）、一键复制、二维码
- 设置：名称、代理端口、入站方式（双栈 / 仅 IPv4 / 仅 IPv6）、出站方式、限速、自定义分享地址（例如填域名）
- 安全：修改面板密码、重置密钥（旧链接立即失效）、流量清零
- 运行日志、重启服务

## Windows 客户端

从 [Releases](https://github.com/674542449/tunnelx-lite/releases) 下载 `txlite-windows-x64.zip`，解压后运行 `txlite-client.exe`（需要 Microsoft Edge WebView2 运行时，Windows 10/11 一般已自带）。

1. 在服务器面板点「复制」，回到客户端按 **Ctrl+V**（或点「剪贴板导入」）。
2. 选中服务器，点「立即连接」或双击。
3. 左侧控制面板支持独立切换路由规则（**绕过大陆** / **全局代理**，连接中可实时热切换）与 **TUN 虚拟网卡** 开关（TUN 可与绕过大陆或全局代理任意组合使用）：
   - **绕过大陆**：按本地/私网 → 用户直连例外 → `GEOSITE,private` → `GEOSITE,cn` 与 `GEOSITE,geolocation-!cn` 最长后缀优先匹配 → `GEOIP,CN` 直连，其余走代理。
   - **全局代理**：除局域网/私网和用户直连例外外全部走代理。
   - 非 TUN 模式连接时自动设置 Windows 系统代理，断开时恢复原设置；TUN 模式接管全部 TCP/UDP 并通过物理网卡绑定避免直连回环。
   - **防污染 DNS 覆写**（默认开启，可在「代理设置」自定义）：国内域名默认通过加密阿里云公共 DNS DoH（`223.5.5.5` / `223.6.6.6`）与腾讯 DNSPod DoH（`1.12.12.12`）解析，海外与未知域名通过加密隧道远端 DNS 解析（并配合 GeoIP 校验防污染）。

- 客户端默认以管理员权限启动，可直接开启 TUN 模式接管所有应用的 TCP / UDP，无需重新启动。
- 不认系统代理的程序，可手动把它的代理设为 SOCKS5 `127.0.0.1:1080` 或 HTTP `127.0.0.1:8088`。
- 右键或悬浮节点操作：测试延迟、复制分享链接、重命名、删除。
- 设置里可以选择 TCP 传输方式（TCP 直连多通道 / HTTP/2 多路复用）、填写直连例外域名、配置防污染 DNS 覆写、更新分流规则、恢复系统代理 / TUN、导出脱敏诊断报告。侧边栏显示当前实际使用的传输方式。
- 导入的服务器（含密钥）用 Windows DPAPI 加密保存在 `%LOCALAPPDATA%\txlite`。在程序目录新建 `portable` 文件夹即可改为便携模式。

## 分享链接格式

```
txlite://密钥@地址:端口?sni=内层名称&ech=ECH配置&pin=证书指纹#名称
txpulse://密钥@地址:UDP端口?obfs=混淆种子&pin=自签证书指纹[&hop=起始-结束]#名称
```

- `地址`：IPv4、`[IPv6]` 或域名（域名由客户端在连接时解析）
- `ech`：ECHConfigList，base64url 编码（`txlite://` 使用）
- `obfs`：TXPulse 每节点独立混淆种子，base64url 编码（`txpulse://` 使用）
- `hop`：可选原生 UDP 端口跳跃区间，如 `20000-20031`（`txpulse://` 使用）
- `pin`：服务器自签证书公钥 SHA-256 指纹，base64url 编码；客户端只信任这个指纹（杜绝 `insecure=1` 中间人攻击）

分享链接里包含密钥，等同于账号密码，请只发给信任的人。泄露后在面板「重置密钥」即可让旧链接失效。

## 从源码构建

需要 Go 1.27 和 [Wails v2](https://wails.io)（仅客户端）。依赖已 vendor，构建前需要应用两处 HTTP/2 补丁：

```bash
go mod vendor && python scripts/patch-vendor.py
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -tags=http2legacy -trimpath -ldflags='-s -w' -o txlite ./cmd/txlite
```

完整发布包：`scripts/release.sh`。

## 第三方组件

客户端 TUN 模式使用 [tun2socks](https://github.com/xjasonlyu/tun2socks)（MIT）和 [Wintun](https://www.wintun.net/)，许可证与源码说明在 `gui/runtime`。分流规则使用 [MetaCubeX/meta-rules-dat](https://github.com/MetaCubeX/meta-rules-dat)（与 Clash Verge Rev 相同的 geosite / geoip 数据，GPL-3.0），许可证在 `internal/routing/data`。
