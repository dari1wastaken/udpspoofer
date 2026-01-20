package main

import (
	"flag"
	"fmt"
	"log"
	"math/rand"
	"net"
	"os"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/google/gopacket/pcapgo"
)

func main() {
	var (
		pcapPath   string
		dstIPStr   string
		dstPort    int
		pps        int
		spoofSrcIP bool
		ifaceName  string
		srcPortOV  int
	)
	flag.StringVar(&pcapPath, "pcap", "", "Path to input pcap file")
	flag.StringVar(&dstIPStr, "dst-ip", "udpspoofer", "Destination IP or hostname to send UDP packets to")
	flag.IntVar(&dstPort, "dst-port", 9999, "Destination UDP port")
	flag.IntVar(&pps, "pps", 1000, "Packets per second throttle (approx)")
	flag.BoolVar(&spoofSrcIP, "spoof-srcip", false, "Enable source IP spoofing (raw packet injection via libpcap)")
	flag.StringVar(&ifaceName, "iface", "eth0", "Interface to inject packets when spoofing")
	flag.IntVar(&srcPortOV, "src-port", 0, "Override UDP source port when spoofing (0 = use from pcap)")
	flag.Parse()

	if pps < 0 {
		pps = 0
	}
	if pcapPath == "" {
		log.Fatalf("pcap path is required (use --pcap)")
	}

	// Resolve destination IPv4
	dstIPs, err := net.LookupIP(dstIPStr)
	if err != nil || len(dstIPs) == 0 {
		log.Fatalf("resolve dst ip: %v", err)
	}
	var dstIP net.IP
	for _, ip := range dstIPs {
		if v4 := ip.To4(); v4 != nil {
			dstIP = v4
			break
		}
	}
	if dstIP == nil {
		log.Fatalf("destination %s has no IPv4 address", dstIPStr)
	}

	// Open pcap file
	f, err := os.Open(pcapPath)
	if err != nil {
		log.Fatalf("opening pcap: %v", err)
	}
	defer f.Close()

	r, err := pcapgo.NewReader(f)
	if err != nil {
		log.Fatalf("reading pcap: %v", err)
	}

	interval := time.Duration(0)
	if pps > 0 {
		interval = time.Second / time.Duration(pps)
	}
	nextSend := time.Time{}

	// Non-spoofing path: send payloads via UDP socket
	if !spoofSrcIP {
		addr := &net.UDPAddr{IP: dstIP, Port: dstPort}
		conn, err := net.DialUDP("udp", nil, addr)
		if err != nil {
			log.Fatalf("dial udp: %v", err)
		}
		defer conn.Close()

		count := 0
		for {
			data, ci, err := r.ReadPacketData()
			if err != nil {
				if err.Error() == "EOF" {
					break
				}
				log.Fatalf("read packet: %v", err)
			}
			pkt := decodeUDP(data)
			if pkt == nil {
				continue
			}
			udp := pkt.Layer(layers.LayerTypeUDP).(*layers.UDP)
			payload := udp.Payload

			if interval > 0 {
				now := time.Now()
				if now.Before(nextSend) {
					time.Sleep(nextSend.Sub(now))
				}
				nextSend = time.Now().Add(interval)
			}

			if _, err := conn.Write(payload); err != nil {
				log.Printf("send error at %s: %v", ci.Timestamp, err)
				continue
			}
			count++
		}
		log.Printf("Done (non-spoof). Sent %d UDP payloads to %s:%d", count, dstIP.String(), dstPort)
		return
	}

	// Spoofing path: craft Ethernet/IPv4/UDP with random source IP and inject via libpcap
	iface, err := net.InterfaceByName(ifaceName)
	if err != nil {
		log.Fatalf("interface %s: %v", ifaceName, err)
	}
	localMAC := iface.HardwareAddr
	localIP := firstIPv4Addr(iface)
	if localIP == nil {
		log.Fatalf("could not determine IPv4 address for %s", ifaceName)
	}

	handle, err := pcap.OpenLive(ifaceName, 65536, true, pcap.BlockForever)
	if err != nil {
		log.Fatalf("pcap open: %v", err)
	}
	defer handle.Close()

	dstMAC, err := arpResolve(handle, iface, localIP, dstIP, 3, 2*time.Second)
	if err != nil {
		log.Fatalf("ARP resolve %s on %s: %v", dstIP.String(), ifaceName, err)
	}

	count := 0
	for {
		data, ci, err := r.ReadPacketData()
		if err != nil {
			if err.Error() == "EOF" {
				break
			}
			log.Fatalf("read packet: %v", err)
		}
		pkt := decodeUDP(data)
		if pkt == nil {
			continue
		}
		udp := pkt.Layer(layers.LayerTypeUDP).(*layers.UDP)

		srcPort := uint16(udp.SrcPort)
		if srcPortOV > 0 && srcPortOV < 65536 {
			srcPort = uint16(srcPortOV)
		}

		// Random non-reserved IPv4 source
		srcIP := randomIPv4()

		eth := &layers.Ethernet{
			SrcMAC:       localMAC,
			DstMAC:       dstMAC,
			EthernetType: layers.EthernetTypeIPv4,
		}
		ip4 := &layers.IPv4{
			Version:  4,
			IHL:      5,
			TTL:      64,
			SrcIP:    srcIP,
			DstIP:    dstIP,
			Protocol: layers.IPProtocolUDP,
			Id:       uint16(rand.Intn(65536)),
		}
		udpl := &layers.UDP{
			SrcPort: layers.UDPPort(srcPort),
			DstPort: layers.UDPPort(dstPort),
		}
		udpl.SetNetworkLayerForChecksum(ip4)

		buf := gopacket.NewSerializeBuffer()
		opts := gopacket.SerializeOptions{
			FixLengths:       true,
			ComputeChecksums: true,
		}
		if err := gopacket.SerializeLayers(buf, opts, eth, ip4, udpl, gopacket.Payload(udp.Payload)); err != nil {
			log.Printf("serialize error at %s: %v", ci.Timestamp, err)
			continue
		}

		if interval > 0 {
			now := time.Now()
			if now.Before(nextSend) {
				time.Sleep(nextSend.Sub(now))
			}
			nextSend = time.Now().Add(interval)
		}

		if err := handle.WritePacketData(buf.Bytes()); err != nil {
			log.Printf("inject error at %s: %v", ci.Timestamp, err)
			continue
		}
		count++
	}
	log.Printf("Done (spoof). Injected %d UDP packets to %s:%d (dst MAC %s) via %s", count, dstIP.String(), dstPort, dstMAC.String(), ifaceName)
}

func decodeUDP(data []byte) gopacket.Packet {
	// Try Ethernet first
	pkt := gopacket.NewPacket(data, layers.LinkTypeEthernet, gopacket.Default)
	if pkt.Layer(layers.LayerTypeUDP) != nil {
		return pkt
	}
	// Try raw IPv4
	pkt = gopacket.NewPacket(data, layers.LayerTypeIPv4, gopacket.Default)
	if pkt.Layer(layers.LayerTypeUDP) != nil {
		return pkt
	}
	return nil
}

func firstIPv4Addr(iface *net.Interface) net.IP {
	addrs, _ := iface.Addrs()
	for _, a := range addrs {
		var ip net.IP
		switch v := a.(type) {
		case *net.IPNet:
			ip = v.IP
		case *net.IPAddr:
			ip = v.IP
		}
		if ip != nil && ip.To4() != nil {
			return ip.To4()
		}
	}
	return nil
}

func arpResolve(handle *pcap.Handle, iface *net.Interface, srcIP, targetIP net.IP, retries int, timeout time.Duration) (net.HardwareAddr, error) {
	srcMAC := iface.HardwareAddr
	bcast := net.HardwareAddr{0xff, 0xff, 0xff, 0xff, 0xff, 0xff}

	eth := &layers.Ethernet{
		SrcMAC:       srcMAC,
		DstMAC:       bcast,
		EthernetType: layers.EthernetTypeARP,
	}
	arp := &layers.ARP{
		AddrType:          layers.LinkTypeEthernet,
		Protocol:          layers.EthernetTypeIPv4,
		HwAddressSize:     6,
		ProtAddressSize:   4,
		Operation:         layers.ARPRequest,
		SourceHwAddress:   []byte(srcMAC),
		SourceProtAddress: []byte(srcIP.To4()),
		DstHwAddress:      []byte{0, 0, 0, 0, 0, 0},
		DstProtAddress:    []byte(targetIP.To4()),
	}

	src := gopacket.NewPacketSource(handle, handle.LinkType())
	src.NoCopy = true

	for i := 0; i < retries; i++ {
		buf := gopacket.NewSerializeBuffer()
		if err := gopacket.SerializeLayers(buf, gopacket.SerializeOptions{FixLengths: true}, eth, arp); err != nil {
			return nil, fmt.Errorf("serialize arp: %w", err)
		}
		if err := handle.WritePacketData(buf.Bytes()); err != nil {
			return nil, fmt.Errorf("send arp: %w", err)
		}

		// Wait for reply
		deadline := time.After(timeout)
		for {
			select {
			case <-deadline:
				goto nextTry
			case p, ok := <-src.Packets():
				if !ok {
					goto nextTry
				}
				lay := p.Layer(layers.LayerTypeARP)
				if lay == nil {
					continue
				}
				reply, _ := lay.(*layers.ARP)
				if reply.Operation != layers.ARPReply {
					continue
				}
				// Expect reply from targetIP to our MAC
				if net.IP(reply.SourceProtAddress).Equal(targetIP.To4()) {
					return net.HardwareAddr(reply.SourceHwAddress), nil
				}
			}
		}
	nextTry:
	}
	return nil, fmt.Errorf("arp timeout for %s", targetIP.String())
}

func randomIPv4() net.IP {
	for {
		a := byte(rand.Intn(256))
		b := byte(rand.Intn(256))
		c := byte(rand.Intn(256))
		d := byte(rand.Intn(256))
		// Skip common special ranges (roughly)
		if a == 0 || a == 10 || a == 127 || a == 169 || a == 172 || a == 192 || a >= 224 {
			continue
		}
		return net.IPv4(a, b, c, d)
	}
}
