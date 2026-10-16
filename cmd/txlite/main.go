// txlite is the standalone server: `txlite` opens a menu, `txlite run` is the service.
package main

import (
	"bufio"
	"context"
	"errors"
	"flag"
	"fmt"
	"net"
	"os"
	"os/exec"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/674542449/tunnelx-lite/internal/lite"
)

const service = "txlite"

func main() {
	dir := flag.String("dir", "/var/lib/txlite", "state directory")
	name := flag.String("name", "", "server name for share links (init)")
	port := flag.Int("port", 0, "proxy TCP port (init; 0 picks a random port)")
	panelPort := flag.Int("panel-port", 0, "panel HTTPS port (init; 0 picks a random port)")
	inbound := flag.String("inbound", "", "init: inbound family: empty (dual stack), ipv4 or ipv6")
	outbound := flag.String("outbound", "", "init: outbound policy: empty, prefer_ipv4, prefer_ipv6, ipv4 or ipv6")
	flag.Usage = func() {
		fmt.Fprintln(os.Stderr, "用法：txlite [-dir 目录] [init|run|link|info|password|version]\n不带参数运行时打开管理菜单。")
	}
	flag.Parse()
	d := lite.Dir(*dir)
	var err error
	switch flag.Arg(0) {
	case "":
		err = menu(d)
	case "init":
		err = initialize(d, *name, *port, *panelPort, *inbound, *outbound)
	case "run":
		err = run(d)
	case "link":
		err = printLinks(d)
	case "info":
		err = printInfo(d)
	case "password":
		err = resetPassword(d, true)
	case "version":
		fmt.Println(lite.Version)
	default:
		flag.Usage()
		os.Exit(2)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "错误：", err)
		os.Exit(1)
	}
}

func randomPort(avoid int) int {
	for i := 0; i < 50; i++ {
		l, e := net.Listen("tcp", ":0")
		if e != nil {
			break
		}
		p := l.Addr().(*net.TCPAddr).Port
		l.Close()
		if p >= 10000 && p <= 60000 && p != avoid {
			return p
		}
	}
	return 20000 + int(time.Now().UnixNano()%30000)
}

func initialize(d lite.Dir, name string, port, panelPort int, inbound, outbound string) error {
	probe := lite.Config{Name: "x", Port: 1, PanelPort: 2, PanelPath: "abcdefghij", Token: lite.NewToken(), Inbound: inbound, OutboundIP: outbound}
	if err := probe.Validate(); err != nil {
		return err
	}
	if name == "" {
		host, _ := os.Hostname()
		name = "txlite-" + host
		if len(name) > 48 {
			name = name[:48]
		}
	}
	if port == 0 {
		port = randomPort(panelPort)
	}
	if panelPort == 0 {
		panelPort = randomPort(port)
	}
	c, password, err := lite.Init(d, name, port, panelPort)
	if err != nil {
		return err
	}
	if inbound != "" || outbound != "" {
		c.Inbound, c.OutboundIP = inbound, outbound
		if err = lite.Save(d, c); err != nil {
			return err
		}
	}
	fmt.Println("初始化完成。")
	fmt.Printf("面板密码：%s\n（只显示这一次；忘记后运行 txlite password 重置）\n", password)
	return nil
}

func run(d lite.Dir) error {
	r, err := lite.Open(d)
	if err != nil {
		return err
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	return r.Run(ctx)
}

func panelURLs(c lite.Config, v4, v6 string) []string {
	var out []string
	for _, h := range []string{v4, v6} {
		if h != "" {
			out = append(out, "https://"+net.JoinHostPort(h, strconv.Itoa(c.PanelPort))+"/"+c.PanelPath+"/")
		}
	}
	return out
}

func printLinks(d lite.Dir) error {
	c, err := lite.Load(d)
	if err != nil {
		return err
	}
	id, err := lite.LoadIdentity(d)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	v4, v6 := lite.PublicIPs(ctx)
	links := lite.Links(c, id, v4, v6)
	if len(links) == 0 {
		return errors.New("没有检测到公网地址；请在面板设置里填写自定义分享地址")
	}
	for _, l := range links {
		fmt.Printf("\n【%s 分享链接】\n%s\n", l.Label, l.URL)
	}
	return nil
}

func printInfo(d lite.Dir) error {
	c, err := lite.Load(d)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	v4, v6 := lite.PublicIPs(ctx)
	quic := fmt.Sprintf("，%d/UDP（QUIC）", c.Port)
	if c.NoQUIC {
		quic = "（QUIC 已关闭）"
	}
	fmt.Printf("名称：%s\n代理端口：%d/TCP%s\n面板端口：%d/TCP\n", c.Name, c.Port, quic, c.PanelPort)
	for _, u := range panelURLs(c, v4, v6) {
		fmt.Println("面板地址：" + u)
	}
	fmt.Println("（面板使用自签证书，浏览器提示不安全时选择继续访问）")
	return printLinks(d)
}

func resetPassword(d lite.Dir, restart bool) error {
	c, err := lite.Load(d)
	if err != nil {
		return err
	}
	password := lite.NewToken()[:16]
	if c.PanelHash, err = lite.HashPassword(password); err != nil {
		return err
	}
	if err = lite.Save(d, c); err != nil {
		return err
	}
	fmt.Println("新的面板密码：" + password)
	if restart {
		return systemctl("restart")
	}
	return nil
}

func systemctl(action string) error {
	if _, err := exec.LookPath("systemctl"); err != nil {
		return nil
	}
	c := exec.Command("systemctl", action, service)
	c.Stdout, c.Stderr = os.Stdout, os.Stderr
	return c.Run()
}

func menu(d lite.Dir) error {
	in := bufio.NewReader(os.Stdin)
	for {
		state := "未知"
		if out, err := exec.Command("systemctl", "is-active", service).Output(); err == nil || len(out) > 0 {
			state = map[string]string{"active": "运行中", "inactive": "已停止", "failed": "启动失败"}[strings.TrimSpace(string(out))]
		}
		fmt.Printf("\n==== txlite %s 管理菜单 · 服务状态：%s ====\n", lite.Version, state)
		fmt.Println("  1) 查看面板地址与分享链接")
		fmt.Println("  2) 重置面板密码")
		fmt.Println("  3) 重启服务")
		fmt.Println("  4) 停止服务")
		fmt.Println("  5) 启动服务")
		fmt.Println("  6) 查看最近日志")
		fmt.Println("  7) 更新到最新版本")
		fmt.Println("  8) 卸载")
		fmt.Println("  0) 退出")
		fmt.Print("请选择：")
		line, err := in.ReadString('\n')
		if err != nil {
			return nil
		}
		var e error
		switch strings.TrimSpace(line) {
		case "1":
			e = printInfo(d)
		case "2":
			e = resetPassword(d, true)
		case "3":
			e = systemctl("restart")
		case "4":
			e = systemctl("stop")
		case "5":
			e = systemctl("start")
		case "6":
			c := exec.Command("journalctl", "-u", service, "-n", "40", "--no-pager")
			c.Stdout, c.Stderr = os.Stdout, os.Stderr
			e = c.Run()
		case "7", "8":
			arg := map[string]string{"7": "update", "8": "uninstall"}[strings.TrimSpace(line)]
			c := exec.Command("bash", "-c", "curl -fsSL https://raw.githubusercontent.com/674542449/tunnelx-lite/main/scripts/install.sh | bash -s -- "+arg)
			c.Stdin, c.Stdout, c.Stderr = os.Stdin, os.Stdout, os.Stderr
			e = c.Run()
			if arg == "uninstall" && e == nil {
				return nil
			}
		case "0", "q":
			return nil
		default:
			fmt.Println("无效选项")
		}
		if e != nil {
			fmt.Println("操作失败：", e)
		}
	}
}
