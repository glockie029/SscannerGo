package portscan

import (
	"bytes"
	"errors"
	"net"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

// GetMacByIP 尝试通过 ARP 请求获取指定 IP 的 MAC 地址
// 注意：仅适用于同一局域网
func GetMacByIP(ifaceName string, targetIP net.IP) (net.HardwareAddr, error) {
	// 打开句柄
	handle, err := pcap.OpenLive(ifaceName, 65536, true, pcap.BlockForever)
	if err != nil {
		return nil, err
	}
	defer handle.Close()

	iface, err := net.InterfaceByName(ifaceName)
	if err != nil {
		return nil, err
	}

	// 获取本地 IP 构造 ARP
	var srcIP net.IP
	addrs, _ := iface.Addrs()
	for _, a := range addrs {
		if ipnet, ok := a.(*net.IPNet); ok && !ipnet.IP.IsLoopback() {
			if ipnet.IP.To4() != nil {
				srcIP = ipnet.IP.To4()
				break
			}
		}
	}

	eth := layers.Ethernet{
		SrcMAC:       iface.HardwareAddr,
		DstMAC:       net.HardwareAddr{0xff, 0xff, 0xff, 0xff, 0xff, 0xff},
		EthernetType: layers.EthernetTypeARP,
	}
	arp := layers.ARP{
		AddrType:          layers.LinkTypeEthernet,
		Protocol:          layers.EthernetTypeIPv4,
		HwAddressSize:     6,
		ProtAddressSize:   4,
		Operation:         layers.ARPRequest,
		SourceHwAddress:   []byte(iface.HardwareAddr),
		SourceProtAddress: []byte(srcIP),
		DstHwAddress:      []byte{0, 0, 0, 0, 0, 0},
		DstProtAddress:    []byte(targetIP),
	}

	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}
	gopacket.SerializeLayers(buf, opts, &eth, &arp)

	if err := handle.WritePacketData(buf.Bytes()); err != nil {
		return nil, err
	}

	// 监听 ARP 回复
	start := time.Now()
	for {
		if time.Since(start) > 2*time.Second {
			return nil, errors.New("ARP 请求超时")
		}
		data, _, err := handle.ReadPacketData()
		if err != nil {
			continue
		}
		packet := gopacket.NewPacket(data, layers.LayerTypeEthernet, gopacket.Default)
		if arpLayer := packet.Layer(layers.LayerTypeARP); arpLayer != nil {
			arp := arpLayer.(*layers.ARP)
			if arp.Operation == layers.ARPReply && bytes.Equal(arp.SourceProtAddress, targetIP) {
				return net.HardwareAddr(arp.SourceHwAddress), nil
			}
		}
	}
}
