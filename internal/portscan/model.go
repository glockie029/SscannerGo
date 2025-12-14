package portscan

type ScanResult struct {
	Port   int
	IsOpen bool
	Err    error
}
