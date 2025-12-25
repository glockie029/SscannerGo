package main

import (
	"SscannerGo/internal/portscan"
	"context"
	"flag"
	"fmt"
	"net"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/fatih/color"
	"github.com/schollz/progressbar/v3"
)

func main() {
	// 1. 参数主要配置
	targetIP := flag.String("ip", "127.0.0.1", "目标IP地址")
	startPort := flag.Int("start", 1, "起始端口")
	endPort := flag.Int("end", 65535, "结束端口")
	concurrency := flag.Int("t", 2000, "并发数 (Connect模式推荐 1000-5000)")
	timeoutMs := flag.Int("timeout", 200, "连接超时(毫秒)")
	mode := flag.String("mode", "connect", "扫描模式: connect (默认), syn (需sudo)")
	iface := flag.String("iface", "", "外网接口名称 (例如 eth0, en0), SYN模式必需")
	gateway := flag.String("gw", "", "网关IP (如果目标在外网，SYN模式通常需要指定)")

	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "SscannerGo - 高性能端口扫描器\n\nUsage:\n")
		flag.PrintDefaults()
	}
	flag.Parse()

	// 2. 参数校验
	if *startPort > *endPort || *startPort < 1 || *endPort > 65535 {
		color.Red("[-] 端口范围无效: %d-%d", *startPort, *endPort)
		return
	}

	// 3. 优雅退出的上下文控制
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-sigChan
		color.Red("\n\n[!] 收到中断信号，正在停止任务...")
		cancel()
	}()

	// 4. 选择扫描模式
	var results <-chan portscan.ScanResult
	var scanType string

	timeout := time.Duration(*timeoutMs) * time.Millisecond
	totalPorts := *endPort - *startPort + 1
	var bar *progressbar.ProgressBar
	startTime := time.Now()

	scanType = fmt.Sprintf("[%s]", *mode)

	// 自动选择接口
	if *mode == "syn" && *iface == "" {
		ifaces, _ := net.Interfaces()
		found := false
		for _, i := range ifaces {
			if i.Flags&net.FlagUp == 0 || i.Flags&net.FlagLoopback != 0 {
				continue
			}
			addrs, _ := i.Addrs()
			for _, addr := range addrs {
				if ipnet, ok := addr.(*net.IPNet); ok && !ipnet.IP.IsLoopback() {
					if ipnet.IP.To4() != nil {
						*iface = i.Name
						found = true
						break
					}
				}
			}
			if found {
				break
			}
		}
		if *iface != "" {
			color.Yellow("[*] 自动选择接口: %s", *iface)
		} else {
			if os.Getenv("GOOS") == "darwin" {
				*iface = "en0"
			} else {
				*iface = "eth0"
			}
			color.Yellow("[!] 未探测到活动接口，回退默认: %s", *iface)
		}
	}

	if *mode == "syn" {
		if os.Geteuid() != 0 {
			color.Red("[!] SYN 扫描必须以 Root 权限运行 (sudo)")
			return
		}

		color.Yellow("[*] 初始化 SYN 扫描器 (gopacket)...")

		// 简单的 IP 解析
		tIP := net.ParseIP(*targetIP)
		if tIP == nil {
			color.Red("[-] 目标 IP 无效")
			return
		}
		tIP = tIP.To4()

		// 确定 ARP 解析目标
		var arpTargetIP net.IP

		// 获取本地接口信息以判断子网
		ifaceObj, err := net.InterfaceByName(*iface)
		if err != nil {
			color.Red("[-] 无法获取接口 %s: %v", *iface, err)
			return
		}
		addrs, _ := ifaceObj.Addrs()
		var localIPNet *net.IPNet
		var localIP net.IP
		for _, a := range addrs {
			if ipnet, ok := a.(*net.IPNet); ok && !ipnet.IP.IsLoopback() && ipnet.IP.To4() != nil {
				localIPNet = ipnet
				localIP = ipnet.IP.To4()
				break
			}
		}

		if localIPNet != nil && localIPNet.Contains(tIP) {
			arpTargetIP = tIP
			color.Green("[*] 目标在本地子网，直接解析目标 MAC")
		} else {
			// 目标在外网，需要发给网关
			if *gateway != "" {
				arpTargetIP = net.ParseIP(*gateway).To4()
			} else {
				// 自动猜测网关: 本机IP所在网段的 .1
				if localIP != nil {
					ipv4 := localIP
					// 假设网关是 x.x.x.1 或者 x.x.x.2 (通常是 .1)
					// 取掩码
					mask := localIPNet.Mask
					network := ipv4.Mask(mask)

					// 构造 网段 IP
					gwIP := make(net.IP, len(network))
					copy(gwIP, network)
					gwIP[3] = gwIP[3] + 1 // 假设最后一位是 x.x.x.1

					arpTargetIP = gwIP
					color.Yellow("[!] 目标在外网，自动推测网关为: %s", gwIP.String())
				} else {
					color.Red("[-] 无法获取本地IP来推测网关，请使用 -gw 指定")
					return
				}
			}
		}

		color.Yellow("[*] 正在解析 MAC 地址: %s...", arpTargetIP)
		dstMac, err := portscan.GetMacByIP(*iface, arpTargetIP)
		if err != nil {
			color.Red("[-] ARP 解析失败: %v (请确认目标/网关可达)", err)
			return
		}
		color.Green("[+] 下一跳 MAC: %s", dstMac)

		synScanner, err := portscan.NewSynScanner(*iface, *targetIP, dstMac)
		if err != nil {
			color.Red("[-] SYN Scanner 初始化失败: %v", err)
			return
		}

		// 启动 SYN 扫描 (Rate Limit: 5000 pps)
		results = synScanner.Start(ctx, *startPort, *endPort, *concurrency)
		scanType = "[SYN]"

	} else {
		// Connect Mode
		scanner := portscan.NewScanner(*targetIP, timeout, *concurrency)
		results = scanner.ScanRange(ctx, *startPort, *endPort)
		scanType = "[Connect]"
	}

	// 5. 界面输出
	color.Cyan(`
   _____                                       ______     
  / ___/______________ _____  ____  ___  _____/ ____/___  
  \__ \/ ___/ ___/ __ '/ __ \/ __ \/ _ \/ ___/ / __/ __ \ 
 ___/ / /__/ /__/ /_/ / / / / / / /  __/ /  / /_/ / /_/ / 
/____/\___/\___/\__,_/_/ /_/_/ /_/\___/_/   \____/\____/  
`)
	color.White("Target: %s | Ports: %d-%d | Mode: %s ", *targetIP, *startPort, *endPort, scanType)
	fmt.Println("---------------------------------------------------------")

	bar = progressbar.NewOptions(totalPorts,
		progressbar.OptionEnableColorCodes(true),
		progressbar.OptionShowBytes(false),
		progressbar.OptionSetWidth(30),
		progressbar.OptionSetDescription("[cyan][扫描中][reset]"),
		progressbar.OptionSetTheme(progressbar.Theme{
			Saucer:        "[green]=[reset]",
			SaucerHead:    "[green]>[reset]",
			SaucerPadding: " ",
			BarStart:      "[",
			BarEnd:        "]",
		}),
	)

	var openPorts []int

	// 7. 处理结果
	for res := range results {
		// 进度条逻辑在流式模式下可能不太好精确控制 (因为 SYN 发包快，回包慢)
		// 简单处理：每次收到结果加 1 (SYN 模式下只会收到 Open 的结果? 不, 我们也处理了发包 loop)
		// 注意: SynScanner 的 results 仅包含 Open 的端口吗? 这里的处理逻辑需要适配
		// 目前 SynScanner 只返回 Open 的端口
		// ConnectScanner 返回所有端口结果

		if *mode == "connect" {
			bar.Add(1)
		} else {
			// SYN 模式下，我们不知道何时结束，除非 sendLoop 结束且等待了一段时间
			// 这里的进度条可能不准确，暂且仅仅作为一个 spinner 使用
			bar.Add(0)
		}

		if res.IsOpen {
			bar.Clear()
			color.Green("\r[+] Found Open Port: %d", res.Port)
			openPorts = append(openPorts, res.Port)
		}
	}

	if *mode == "syn" {
		bar.Finish() // 强制完成
	}

	fmt.Println()
	elapsed := time.Since(startTime)

	// 8. 总结报告
	fmt.Println("\n---------------------------------------------------------")
	color.Cyan("[*] 扫描完成 ! 耗时: %s", elapsed)
	color.Green("[+] 开放端口数量: %d", len(openPorts))
	if len(openPorts) > 0 {
		color.White("[+] 端口列表: %v", openPorts)
	}
}
