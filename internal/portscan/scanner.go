package portscan

import (
	"fmt"
	"net"
	"sync"
	"time"
)

func ScanPort(target string, port int, timeout time.Duration) ScanResult {
	address := fmt.Sprintf("%s:%d", target, port)
	conn, err := net.DialTimeout("tcp", address, timeout)
	if err != nil {
		return ScanResult{Port: port, IsOpen: false, Err: err}
	}
	defer conn.Close()
	return ScanResult{Port: port, IsOpen: true, Err: nil}
}

func Worker(target string, timeout time.Duration, jobs <-chan int, results chan<- ScanResult, wg *sync.WaitGroup) {
	defer wg.Done()
	for port := range jobs {
		res := ScanPort(target, port, timeout)
		results <- res
	}
}
