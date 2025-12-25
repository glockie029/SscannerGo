package portscan

// ScanMode 定义扫描模式
type ScanMode int

const (
	ModeConnect ScanMode = iota // TCP 全连接扫描 (默认, 无需 Root)
	ModeSYN                     // TCP SYN 半开放扫描 (需 Root)
)

// ScanResult 扫描结果
type ScanResult struct {
	Port   int
	IsOpen bool
	Err    error
}
