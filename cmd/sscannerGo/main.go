package main

import (
	"SscannerGo/internal/portscan"
	"flag"
	"fmt"
	"github.com/fatih/color"
	"github.com/schollz/progressbar/v3"
	"sync"
	"time"
)

func main() {
	targetIP := flag.String("ip", "127.0.0.1", "目标IP地址")
	startPort := flag.Int("start", 1, "起始端口")
	endPort := flag.Int("end", 65535, "结束端口")
	threads := flag.Int("t", 500, "并发数")
	timeoutMs := flag.Int("timeout", 300, "连接超时(毫秒)")
	//verbose := flag.Bool("v", false, "显示详细错误信息")

	flag.Parse()
	if *startPort > *endPort {
		color.Red("[-]起始端口不能大于结束端口")
		return
	}
	color.Cyan("--- 开始扫描 %s [端口 %d-%d] ---\n", *targetIP, *startPort, *endPort)
	color.Cyan("--- 并发数: %d | 超时: %dms ---\n", *threads, *timeoutMs)
	startTime := time.Now()
	// 初始化并发池
	totalPorts := *endPort - *startPort + 1
	jobs := make(chan int, totalPorts)
	results := make(chan portscan.ScanResult, totalPorts)

	var wg sync.WaitGroup
	timeout := time.Duration(*timeoutMs) * time.Millisecond
	//修正并发数
	actualThreads := *threads
	if totalPorts < actualThreads {
		actualThreads = totalPorts
	}
	for i := 0; i < actualThreads; i++ {
		wg.Add(1)
		go portscan.Worker(*targetIP, timeout, jobs, results, &wg)
	}
	//分发任务
	go func() {
		for p := *startPort; p <= *endPort; p++ {
			jobs <- p
		}
		close(jobs)
	}()
	//result
	go func() {
		wg.Wait()
		close(results)
	}()
	bar := progressbar.NewOptions(totalPorts,
		progressbar.OptionEnableColorCodes(true),               // 启用颜色代码支持
		progressbar.OptionShowBytes(false),                     // 我们不是传输文件，不显示字节大小
		progressbar.OptionSetWidth(30),                         // 进度条宽度
		progressbar.OptionSetDescription("[cyan][扫描中][reset]"), // 描述前缀
		progressbar.OptionSetTheme(progressbar.Theme{
			Saucer:        "[green]=[reset]",
			SaucerHead:    "[green]>[reset]",
			SaucerPadding: " ",
			BarStart:      "[",
			BarEnd:        "]",
		}),
	)

	var openPorts []int
	for res := range results {
		bar.Add(1)
		if res.IsOpen {
			bar.Clear()
			color.Green("\r[+]Port: %s:%d Open!\n", *targetIP, res.Port)
			openPorts = append(openPorts, res.Port)
		}
	}
	bar.Finish()
	fmt.Println()
	elapsed := time.Since(startTime)
	fmt.Println("============================")
	color.Cyan("[+]扫描完成!耗时: %s\n", elapsed)
	//fmt.Printf("[+]Open Ports: %d\n[+]Total Ports: %v\n", len(openPorts), openPorts)
}
