#!/usr/bin/env bash
# txlite one-click installer for Ubuntu / Debian.
#   bash <(curl -fsSL https://raw.githubusercontent.com/674542449/tunnelx-lite/main/scripts/install.sh)
#   ... install.sh [install|update|uninstall]
#   Optional: PORT=443 PANEL_PORT=8443 INBOUND=ipv4|ipv6 OUTBOUND=prefer_ipv4|prefer_ipv6|ipv4|ipv6
set -Eeuo pipefail
REPO=674542449/tunnelx-lite
BIN=/usr/local/bin/txlite
DIR=/var/lib/txlite
UNIT=/etc/systemd/system/txlite.service

red(){ printf '\033[31m%s\033[0m\n' "$*"; }
green(){ printf '\033[32m%s\033[0m\n' "$*"; }
die(){ red "错误：$*" >&2; exit 1; }

test "$(id -u)" = 0 || die "请使用 root 运行"
. /etc/os-release
case "${ID:-}" in ubuntu|debian) ;; *) die "仅支持 Ubuntu / Debian";; esac
command -v systemctl >/dev/null || die "需要 systemd"
case "$(uname -m)" in x86_64|amd64) arch=amd64;; aarch64|arm64) arch=arm64;; *) die "不支持的 CPU 架构：$(uname -m)";; esac

download(){
  local base="https://github.com/$REPO/releases/latest/download" work want
  work=$(mktemp -d); trap 'rm -rf "${work:-}"; trap - RETURN' RETURN
  echo "下载 txlite（linux-$arch）……"
  curl -fsSL --retry 3 -o "$work/txlite" "$base/txlite-linux-$arch"
  curl -fsSL --retry 3 -o "$work/SHA256SUMS" "$base/SHA256SUMS"
  want=$(grep -E "[ *]txlite-linux-$arch\$" "$work/SHA256SUMS" | cut -d' ' -f1)
  test -n "$want" && test "$(sha256sum "$work/txlite" | cut -d' ' -f1)" = "$want" || die "下载文件校验失败"
  install -m 755 "$work/txlite" "$BIN.new" && mv -f "$BIN.new" "$BIN"
}

# BBR + fq is best effort: containers and old kernels keep their defaults.
# Clients keep one long-lived connection, so it must not fall back to slow
# start whenever the user pauses between pages (tcp_slow_start_after_idle).
enable_bbr(){
  local conf=/etc/sysctl.d/99-txlite-bbr.conf
  { echo 'net.ipv4.tcp_slow_start_after_idle = 0' >/etc/sysctl.d/99-txlite-tcp.conf && chmod 644 /etc/sysctl.d/99-txlite-tcp.conf; } 2>/dev/null || true
  sysctl -q -w net.ipv4.tcp_slow_start_after_idle=0 >/dev/null 2>&1 || true
  modprobe tcp_bbr >/dev/null 2>&1 || true
  if ! grep -qw bbr /proc/sys/net/ipv4/tcp_available_congestion_control 2>/dev/null; then
    echo "提示：内核不支持 BBR，保持系统默认"; return 0
  fi
  { printf 'net.core.default_qdisc = fq\nnet.ipv4.tcp_congestion_control = bbr\n' >"$conf" && chmod 644 "$conf"; } 2>/dev/null || true
  if modinfo tcp_bbr >/dev/null 2>&1 && test -d /etc/modules-load.d; then
    { echo tcp_bbr >/etc/modules-load.d/txlite-bbr.conf && chmod 644 /etc/modules-load.d/txlite-bbr.conf; } 2>/dev/null || true
  fi
  sysctl -q -w net.core.default_qdisc=fq >/dev/null 2>&1 || true
  sysctl -q -w net.ipv4.tcp_congestion_control=bbr >/dev/null 2>&1 || true
  if test "$(cat /proc/sys/net/ipv4/tcp_congestion_control 2>/dev/null)" = bbr; then echo "已开启 BBR + fq"; else echo "提示：当前环境不允许修改拥塞控制（例如容器），保持默认"; fi
}

write_unit(){
  cat >"$UNIT" <<UNIT
[Unit]
Description=txlite proxy server and panel
After=network-online.target
Wants=network-online.target
[Service]
Type=simple
User=txlite
Group=txlite
ExecStart=$BIN -dir $DIR run
Restart=always
RestartSec=2
AmbientCapabilities=CAP_NET_BIND_SERVICE
CapabilityBoundingSet=CAP_NET_BIND_SERVICE
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=$DIR
LimitNOFILE=65535
[Install]
WantedBy=multi-user.target
UNIT
  chmod 644 "$UNIT"
}

ports(){ python3 -c "import json;c=json.load(open('$DIR/config.json'));print(c['port'],c['panel_port'])" 2>/dev/null || true; }

# iptables_ports insert|delete: images such as Oracle Cloud's end INPUT with a
# REJECT rule, so a new port stays closed until it is accepted before that rule.
iptables_ports(){
  local action=$1 fw p changed=""
  for fw in iptables ip6tables; do
    command -v "$fw" >/dev/null || continue
    for p in $(ports); do
      if test "$action" = insert; then
        "$fw" -S INPUT 2>/dev/null | grep -q -- '-j REJECT' || continue
        "$fw" -C INPUT -p tcp --dport "$p" -m comment --comment txlite -j ACCEPT 2>/dev/null && continue
        "$fw" -I INPUT -p tcp --dport "$p" -m comment --comment txlite -j ACCEPT 2>/dev/null && { echo "$fw 已放行 $p/tcp"; changed=1; }
      else
        while "$fw" -D INPUT -p tcp --dport "$p" -m comment --comment txlite -j ACCEPT 2>/dev/null; do changed=1; done
      fi
    done
  done
  if test -n "$changed" && command -v netfilter-persistent >/dev/null; then netfilter-persistent save >/dev/null 2>&1 || true; fi
}

open_firewall(){
  local port panel
  read -r port panel <<<"$(ports)"
  if command -v ufw >/dev/null && ufw status 2>/dev/null | grep -q "Status: active"; then
    for p in $port $panel; do ufw allow "$p/tcp" >/dev/null && echo "ufw 已放行 $p/tcp"; done
  fi
  iptables_ports insert
  echo "如果使用云服务器，请在安全组放行 TCP $port（代理）和 $panel（面板）。"
}

install_all(){
  export DEBIAN_FRONTEND=noninteractive
  missing=()
  for c in curl python3; do command -v "$c" >/dev/null || missing+=("$c"); done
  if test "${#missing[@]}" -gt 0; then apt-get update -qq; apt-get install -y -qq ca-certificates "${missing[@]}" >/dev/null; fi
  download
  id txlite >/dev/null 2>&1 || useradd --system --home "$DIR" --shell /usr/sbin/nologin txlite
  install -d -m 700 -o txlite -g txlite "$DIR"
  enable_bbr
  if test ! -f "$DIR/config.json"; then
    runuser -u txlite -- "$BIN" -dir "$DIR" -port "${PORT:-0}" -panel-port "${PANEL_PORT:-0}" -inbound "${INBOUND:-}" -outbound "${OUTBOUND:-}" init | tee "$DIR/.first-run"
    chmod 600 "$DIR/.first-run"
  fi
  write_unit
  systemctl daemon-reload
  systemctl enable txlite >/dev/null
  # restart (not enable --now) so a reinstall also loads the replaced binary
  systemctl restart txlite
  sleep 2
  systemctl is-active --quiet txlite || { journalctl -u txlite -n 20 --no-pager; die "服务启动失败"; }
  open_firewall
  green "安装完成。"
  "$BIN" -dir "$DIR" info || true
  if test -f "$DIR/.first-run"; then grep "面板密码" "$DIR/.first-run" || true; rm -f "$DIR/.first-run"; fi
  echo; echo "以后输入 txlite 打开管理菜单。"
}

case "${1:-install}" in
  install) install_all ;;
  update)
    test -x "$BIN" || die "尚未安装"
    download; systemctl restart txlite; green "已更新到 $("$BIN" version)" ;;
  uninstall)
    read -rp "确定卸载 txlite？配置和密钥会一并删除，旧分享链接永久失效 [y/N]: " ok </dev/tty
    case "$ok" in y|Y) ;; *) echo "已取消"; exit 0;; esac
    systemctl disable --now txlite >/dev/null 2>&1 || true
    iptables_ports delete
    rm -f "$UNIT" "$BIN" /etc/sysctl.d/99-txlite-bbr.conf /etc/sysctl.d/99-txlite-tcp.conf /etc/modules-load.d/txlite-bbr.conf
    systemctl daemon-reload
    rm -rf "$DIR"
    userdel txlite 2>/dev/null || true
    green "已卸载。BBR 设置会在重启后恢复系统默认。" ;;
  *) die "用法：install.sh [install|update|uninstall]" ;;
esac
