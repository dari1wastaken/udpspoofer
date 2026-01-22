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
	flag.StringVar(&dstIPStr, "dst-ip", "udpspoofer", "Destination IP or hostname to send packets to")
	flag.IntVar(&dstPort, "dst-port", 9999, "Destination UDP/TCP port")
	flag.IntVar(&pps, "pps", 1000, "Packets per second throttle (approx)")
	flag.BoolVar(&spoofSrcIP, "spoof-srcip", false, "Enable source IP spoofing (raw packet injection via libpcap)")
	flag.StringVar(&ifaceName, "iface", "eth0", "Interface to inject packets when spoofing or sending TCP")
	flag.IntVar(&srcPortOV, "src-port", 0, "Override UDP/TCP source port when spoofing or injecting (0 = use from pcap)")
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

	// Prepare resources based on mode
	// UDP socket for non-spoof UDP sends
	var udpConn *net.UDPConn
	if !spoofSrcIP {
		laddr := &net.UDPAddr{IP: net.IPv4zero, Port: 0}
		udpConn, err = net.ListenUDP("udp", laddr)
		if err != nil {
			log.Fatalf("listen udp: %v", err)
		}
		defer udpConn.Close()
	}

	// Libpcap injection handle + L2/L3 for TCP and for UDP spoof mode
	var handle *pcap.Handle
	var localMAC net.HardwareAddr
	var localIP net.IP
	var dstMAC net.HardwareAddr

	needRaw := spoofSrcIP // spoof mode uses raw for both UDP and TCP
	// even without spoofing, TCP sending uses raw injection
	if !needRaw {
		needRaw = true
	}
	if needRaw {
		iface, err := net.InterfaceByName(ifaceName)
		if err != nil {
			log.Fatalf("interface %s: %v", ifaceName, err)
		}
		localMAC = iface.HardwareAddr
		localIP = firstIPv4Addr(iface)
		if localIP == nil {
			log.Fatalf("could not determine IPv4 address for %s", ifaceName)
		}
		handle, err = pcap.OpenLive(ifaceName, 65536, true, pcap.BlockForever)
		if err != nil {
			log.Fatalf("pcap open: %v", err)
		}
		defer handle.Close()
		dstMAC, err = arpResolve(handle, iface, localIP, dstIP, 3, 2*time.Second)
		if err != nil {
			log.Fatalf("ARP resolve %s on %s: %v", dstIP.String(), ifaceName, err)
		}
	}

	raddrUDP := &net.UDPAddr{IP: dstIP, Port: dstPort}

	countUDP := 0
	countTCP := 0

	for {
		data, ci, err := r.ReadPacketData()
		if err != nil {
			if err.Error() == "EOF" {
				break
			}
			log.Fatalf("read packet: %v", err)
		}

		// Ethernet decode first, then fallback to IPv4
		pkt := gopacket.NewPacket(data, layers.LinkTypeEthernet, gopacket.Default)
		if pkt.Layer(layers.LayerTypeIPv4) == nil {
			pkt = gopacket.NewPacket(data, layers.LayerTypeIPv4, gopacket.Default)
			if pkt.Layer(layers.LayerTypeIPv4) == nil {
				continue
			}
		}

		udpLay := pkt.Layer(layers.LayerTypeUDP)
		tcpLay := pkt.Layer(layers.LayerTypeTCP)

		if interval > 0 {
			now := time.Now()
			if now.Before(nextSend) {
				time.Sleep(nextSend.Sub(now))
			}
			nextSend = time.Now().Add(interval)
		}

		switch {
		case udpLay != nil:
			udp := udpLay.(*layers.UDP)
			payload := udp.Payload
			srcPort := uint16(udp.SrcPort)
			if srcPortOV > 0 && srcPortOV < 65536 {
				srcPort = uint16(srcPortOV)
			}

			if !spoofSrcIP {
				// Non-spoof UDP via socket
				if _, err := udpConn.WriteToUDP(payload, raddrUDP); err != nil {
					log.Printf("udp send error at %s: %v", ci.Timestamp, err)
					continue
				}
			} else {
				// Spoof UDP via raw injection
				srcIP := randomIPv4()
				if err := injectUDP(handle, localMAC, dstMAC, srcIP, dstIP, srcPort, uint16(dstPort), payload); err != nil {
					log.Printf("udp inject error at %s: %v", ci.Timestamp, err)
					continue
				}
			}
			countUDP++

		case tcpLay != nil:
			tcp := tcpLay.(*layers.TCP)
			payload := tcp.Payload
			srcPort := uint16(tcp.SrcPort)
			if srcPortOV > 0 && srcPortOV < 65536 {
				srcPort = uint16(srcPortOV)
			}

			// Inject TCP frames (always raw), spoof if requested
			srcIP := localIP
			if spoofSrcIP {
				srcIP = randomIPv4()
			}
			err := injectTCP(handle, localMAC, dstMAC, srcIP, dstIP, srcPort, uint16(dstPort),
				tcp.Seq, tcp.Ack,
				tcp.SYN, tcp.ACK, tcp.RST, tcp.FIN, tcp.PSH, tcp.URG, tcp.ECE, tcp.CWR,
				tcp.Window, tcp.Urgent, tcp.Options, payload)
			if err != nil {
				log.Printf("tcp inject error at %s: %v", ci.Timestamp, err)
				continue
			}
			countTCP++

		default:
			// Not UDP/TCP
			continue
		}
	}

	log.Printf("Done. Sent UDP=%d TCP=%d packets to %s:%d (iface %s)", countUDP, countTCP, dstIP.String(), dstPort, ifaceName)
}

func injectUDP(handle *pcap.Handle, localMAC, dstMAC net.HardwareAddr, srcIP, dstIP net.IP, srcPort, dstPort uint16, payload []byte) error {
	eth := &layers.Ethernet{
		SrcMAC:       localMAC,
		DstMAC:       dstMAC,
		EthernetType: layers.EthernetTypeIPv4,
	}
	ip4 := &layers.IPv4{
		Version:  4,
		TTL:      64,
		SrcIP:    srcIP,
		DstIP:    dstIP,
		Protocol: layers.IPProtocolUDP,
		Id:       uint16(rand.Intn(65536)),
	}
	udp := &layers.UDP{
		SrcPort: layers.UDPPort(srcPort),
		DstPort: layers.UDPPort(dstPort),
	}
	udp.SetNetworkLayerForChecksum(ip4)

	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}
	if err := gopacket.SerializeLayers(buf, opts, eth, ip4, udp, gopacket.Payload(payload)); err != nil {
		return err
	}
	return handle.WritePacketData(buf.Bytes())
}

func injectTCP(handle *pcap.Handle, localMAC, dstMAC net.HardwareAddr, srcIP, dstIP net.IP, srcPort, dstPort uint16,
	seq, ack uint32, syn, ackf, rst, fin, psh, urg, ece, cwr bool, window, urgent uint16, options []layers.TCPOption, payload []byte) error {

	eth := &layers.Ethernet{
		SrcMAC:       localMAC,
		DstMAC:       dstMAC,
		EthernetType: layers.EthernetTypeIPv4,
	}
	ip4 := &layers.IPv4{
		Version:  4,
		TTL:      64,
		SrcIP:    srcIP,
		DstIP:    dstIP,
		Protocol: layers.IPProtocolTCP,
		Id:       uint16(rand.Intn(65536)),
	}
	tcp := &layers.TCP{
		SrcPort:    layers.TCPPort(srcPort),
		DstPort:    layers.TCPPort(dstPort),
		Seq:        seq,
		Ack:        ack,
		SYN:        syn,
		ACK:        ackf,
		RST:        rst,
		FIN:        fin,
		PSH:        psh,
		URG:        urg,
		ECE:        ece,
		CWR:        cwr,
		Window:     window,
		Urgent:     urgent,
		Options:    options,
		DataOffset: 0, // let FixLengths compute
	}
	tcp.SetNetworkLayerForChecksum(ip4)

	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}
	if err := gopacket.SerializeLayers(buf, opts, eth, ip4, tcp, gopacket.Payload(payload)); err != nil {
		return err
	}
	return handle.WritePacketData(buf.Bytes())
}

func firstIPv4Addr(iface *net.Interface) net.IP {
	addrs, _ := iface.Addrs()
	for _, a := range addrs {
		switch v := a.(type) {
		case *net.IPNet:
			if v.IP.To4() != nil {
				return v.IP.To4()
			}
		case *net.IPAddr:
			if v.IP.To4() != nil {
				return v.IP.To4()
			}
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
