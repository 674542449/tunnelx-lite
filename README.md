# txlite

一个可以单独使用的代理服务：服务器一键安装，复制分享链接，粘贴进 Windows 客户端就能用。没有账号、没有订阅后台。

- **协议**：两种传输，同一个端口号——QUIC（UDP，BBR 拥塞控制，每个连接一条独立的流，丢包时网页仍然很快）和 HTTP/2 CONNECT（TCP）；都用 TLS 1.3 + ECH（加密 SNI），客户端按证书公钥指纹校验服务器，不需要域名。客户端默认「自动」：优先 QUIC，UDP 不通时自动改用 TCP。
- **服务端**：Ubuntu / Debian，入站可选双栈 / 仅 IPv4 / 仅 IPv6，出站可选自动、IPv4 优先、IPv6 优先、仅 IPv4、仅 IPv6；自带 HTTPS 管理面板和 `txlite` 命令行菜单；安装时自动开启 BBR + fq。
- **客户端**：Windows 图形界面（类似 v2rayN），支持绕过大陆、全局代理、TUN 模式。

## 服务端安装

用 root 执行：

```bash
bash <(curl -fsSL https://raw.githubusercontent.com/674542449/tunnelx-lite/main/scripts/install.sh)
```

安装完成后会打印：

- 面板地址（`https://服务器IP:面板端口/随机路径/`）和面板密码
- IPv4 / IPv6 分享链接（`txlite://…`）

云服务器请在安全组放行代理端口的 **TCP 和 UDP**（UDP 用于 QUIC）以及面板端口的 TCP。UDP 没放行也能用，客户端会自动改用 TCP。

端口默认随机。想指定端口：

```bash
PORT=443 PANEL_PORT=8443 bash <(curl -fsSL https://raw.githubusercontent.com/674542449/tunnelx-lite/main/scripts/install.sh)
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

1. 在服务器面板点「复制」，回到客户端按 **Ctrl+V**（或点「从剪贴板导入」）。
2. 选中服务器，点「连接」或双击。
3. 底部状态栏切换路由：**绕过大陆** / **全局代理** / **TUN 模式**；规则与 Clash Verge Rev 一致：绕过大陆按 `GEOSITE,private` → `GEOSITE,geolocation-!cn`（代理）→ `GEOSITE,cn` → `GEOIP,private/CN` 直连，其余走代理；全局代理除局域网外全部走代理；点「连接」会自动设置 Windows 系统代理，点「断开」恢复原来的设置（TUN 模式不设置系统代理）。

- TUN 模式接管所有应用的 TCP / UDP，需要右键「以管理员身份运行」。
- 不认系统代理的程序，可手动把它的代理设为 SOCKS5 `127.0.0.1:1080` 或 HTTP `127.0.0.1:8088`。
- 右键服务器：测试延迟、复制分享链接、重命名、删除。
- 设置里可以选择传输方式（自动 / 仅 QUIC / 仅 TCP）、填写直连例外域名、更新分流规则、恢复系统代理、导出脱敏诊断报告。底部状态栏显示当前实际使用的传输方式。
- 导入的服务器（含密钥）用 Windows DPAPI 加密保存在 `%LOCALAPPDATA%\txlite`。在程序目录新建 `portable` 文件夹即可改为便携模式。

## 分享链接格式

```
txlite://密钥@地址:端口?sni=内层名称&ech=ECH配置&pin=证书指纹#名称
```

- `地址`：IPv4、`[IPv6]` 或域名（域名由客户端在连接时解析）
- `ech`：ECHConfigList，base64url 编码
- `pin`：服务器证书公钥 SHA-256，base64url 编码；客户端只信任这个指纹

分享链接里包含密钥，等同于账号密码，请只发给信任的人。泄露后在面板「重置密钥」即可让旧链接失效。

## 从源码构建

需要 Go 1.27 和 [Wails v2](https://wails.io)（仅客户端）。依赖已 vendor，构建前需要应用两处 HTTP/2 补丁：

```bash
go mod vendor && python scripts/patch-vendor.py
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -tags=http2legacy -trimpath -ldflags='-s -w' -o txlite ./cmd/txlite
```

完整发布包：`scripts/release.sh`。

## 第三方组件

客户端 TUN 模式使用 [tun2socks](https://github.com/xjasonlyu/tun2socks)（MIT）和 [Wintun](https://www.wintun.net/)，许可证与源码说明在 `gui/runtime`。QUIC 使用 [apernet/quic-go](https://github.com/apernet/quic-go)（quic-go 的分支，支持替换拥塞控制，MIT），BBR 拥塞控制复制自 [Hysteria](https://github.com/apernet/hysteria)（MIT，许可证在 `internal/congestion`）。分流规则使用 [MetaCubeX/meta-rules-dat](https://github.com/MetaCubeX/meta-rules-dat)（与 Clash Verge Rev 相同的 geosite / geoip 数据，GPL-3.0），许可证在 `internal/routing/data`。
