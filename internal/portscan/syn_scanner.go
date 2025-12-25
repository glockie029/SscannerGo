package portscan

import (
	"context"
	"errors"
	"fmt"
	"net"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

// SynScanner 负责处理 SYN 扫描
type SynScanner struct {
	TargetIP        net.IP
	Interface       string
	LocalIP         net.IP
	LocalMac        net.HardwareAddr
	DstMac          net.HardwareAddr // 目标 MAC 或 网关 MAC
	Handle          *pcap.Handle
	Results         chan ScanResult
	TargetPortRange [2]int
}

// NewSynScanner 初始化 SYN 扫描器
// 注意: 这里为了简化逻辑，假设调用者已经解析好了 MAC 地址
// 实际工程中可能需要实现 ARP 解析器
func NewSynScanner(ifaceName string, target string, dstMac net.HardwareAddr) (*SynScanner, error) {
	// 1. 获取网卡信息
	iface, err := net.InterfaceByName(ifaceName)
	if err != nil {
		return nil, fmt.Errorf("无法获取网卡 %s: %v", ifaceName, err)
	}

	// 2. 获取本地 IP
	var localIP net.IP
	addrs, err := iface.Addrs()
	if err != nil {
		return nil, err
	}
	for _, addr := range addrs {
		if ipnet, ok := addr.(*net.IPNet); ok && !ipnet.IP.IsLoopback() {
			if ipnet.IP.To4() != nil {
				localIP = ipnet.IP.To4()
				break
			}
		}
	}
	if localIP == nil {
		return nil, errors.New("无法在网卡上找到 IPv4 地址")
	}

	// 3. 打开 Pcap 句柄
	handle, err := pcap.OpenLive(ifaceName, 65536, true, pcap.BlockForever)
	if err != nil {
		return nil, fmt.Errorf("Pcap 打开失败 (请尝试 sudo): %v", err)
	}

	return &SynScanner{
		TargetIP:  net.ParseIP(target).To4(),
		Interface: ifaceName,
		LocalIP:   localIP,
		LocalMac:  iface.HardwareAddr,
		DstMac:    dstMac,
		Handle:    handle,
		Results:   make(chan ScanResult, 100),
	}, nil
}

// Start 开始捕获和发包
func (s *SynScanner) Start(ctx context.Context, startPort, endPort int, rateLimit int) <-chan ScanResult {
	// 设置过滤器: 只接收来自目标 IP 的 TCP 包
	// 进一步过滤:只接收 SYN+ACK (开放) 或 RST (关闭)
	// (tcp[13] == 0x12) -> SYN+ACK
	bpfFilter := fmt.Sprintf("src host %s and tcp", s.TargetIP.String())
	if err := s.Handle.SetBPFFilter(bpfFilter); err != nil {
		fmt.Printf("[-] 设置 BPF 过滤器失败: %v\n", err)
	}

	// 1. 启动接收协程
	go s.recvLoop(ctx)

	// 2. 启动发包协程
	go s.sendLoop(ctx, startPort, endPort, rateLimit)

	return s.Results
}

func (s *SynScanner) recvLoop(ctx context.Context) {
	packetSource := gopacket.NewPacketSource(s.Handle, s.Handle.LinkType())
	for {
		select {
		case <-ctx.Done():
			return
		case packet := <-packetSource.Packets():
			if packet == nil {
				continue
			}
			// 解析 TCP 层
			tcpLayer := packet.Layer(layers.LayerTypeTCP)
			if tcpLayer != nil {
				tcp, _ := tcpLayer.(*layers.TCP)
				// 检查标志位
				// SYN=1, ACK=1 (0x12) => 端口开放
				if tcp.SYN && tcp.ACK {
					s.Results <- ScanResult{
						Port:   int(tcp.SrcPort),
						IsOpen: true,
					}
				}
				// RST => 端口关闭 (可以忽略，或者用于探测存活)
			}
		}
	}
}

func (s *SynScanner) sendLoop(ctx context.Context, start, end int, rate int) {
	defer close(s.Results)
	defer s.Handle.Close()

	// 简单的限速器 (Ticker)
	ticker := time.NewTicker(time.Second / time.Duration(rate))
	defer ticker.Stop()

	// 预构建 Layer 头部 (不变部分)
	eth := layers.Ethernet{
		SrcMAC:       s.LocalMac,
		DstMAC:       s.DstMac,
		EthernetType: layers.EthernetTypeIPv4,
	}
	ip := layers.IPv4{
		SrcIP:    s.LocalIP,
		DstIP:    s.TargetIP,
		Version:  4,
		TTL:      64,
		Protocol: layers.IPProtocolTCP,
	}
	tcp := layers.TCP{
		SrcPort: layers.TCPPort(45678), // 随机源端口
		Window:  1024,
		SYN:     true,
	}

	// 序列化缓冲区
	opts := gopacket.SerializeOptions{
		FixLengths:       true,
		ComputeChecksums: true,
	}

	for port := start; port <= end; port++ {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			// 发送逻辑
			tcp.DstPort = layers.TCPPort(port)
			tcp.SetNetworkLayerForChecksum(&ip)

			buffer := gopacket.NewSerializeBuffer()
			if err := gopacket.SerializeLayers(buffer, opts, &eth, &ip, &tcp); err != nil {
				continue
			}

			if err := s.Handle.WritePacketData(buffer.Bytes()); err != nil {
				// 发送失败处理
				// fmt.Println(err)
			}
		}
	}
	// 发送完毕后，多等待一会以接收剩余的回包
	time.Sleep(2 * time.Second)
}
