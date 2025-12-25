package portscan

import (
	"context"
	"fmt"
	"net"
	"sync"
	"time"
)

// Scanner 配置结构体
type Scanner struct {
	TargetIP    string
	Timeout     time.Duration
	Concurrency int
}

// NewScanner 创建一个新的扫描器实例
func NewScanner(target string, timeout time.Duration, concurrency int) *Scanner {
	return &Scanner{
		TargetIP:    target,
		Timeout:     timeout,
		Concurrency: concurrency,
	}
}

// ScanRange 启动异步流式扫描
// 它返回一个只读通道，实时接收扫描结果
func (s *Scanner) ScanRange(ctx context.Context, startPort, endPort int) <-chan ScanResult {
	results := make(chan ScanResult) // 结果通道

	// 启动核心扫描逻辑
	go func() {
		defer close(results) // 任务全部完成后关闭通道

		var wg sync.WaitGroup
		// 信号量通道，用于控制最大并发数
		sem := make(chan struct{}, s.Concurrency)

		for port := startPort; port <= endPort; port++ {
			// 检查上下文是否已取消（响应 Ctrl+C）
			select {
			case <-ctx.Done():
				return
			default:
				// 获取令牌，如果有空位则继续，否则阻塞等待
				sem <- struct{}{}
			}

			wg.Add(1)
			// 启动轻量级 Goroutine 进行扫描
			go func(p int) {
				defer wg.Done()
				defer func() { <-sem }() // 释放令牌

				// 执行扫描
				isOpen, err := s.scanPort(ctx, p)

				// 只有开放的端口或者有错误时才可能需要发送结果
				// 这里我们将所有结果发送回去，由调用方过滤，或者在此处仅发送开放的
				// 为了灵活性，我们发送所有结果，但可以在后续优化仅发送 Open 的以减少通道压力
				results <- ScanResult{
					Port:   p,
					IsOpen: isOpen,
					Err:    err,
				}
			}(port)
		}

		// 等待所有正在进行的扫描任务完成
		wg.Wait()
	}()

	return results
}

// scanPort 单个端口扫描逻辑
func (s *Scanner) scanPort(ctx context.Context, port int) (bool, error) {
	address := fmt.Sprintf("%s:%d", s.TargetIP, port)

	// 优化 Dialer 配置
	d := net.Dialer{
		Timeout:   s.Timeout,
		KeepAlive: -1, // 禁用 KeepAlive，扫描不需要保持连接
	}

	conn, err := d.DialContext(ctx, "tcp", address)
	if err != nil {
		return false, err
	}
	conn.Close()
	return true, nil
}
