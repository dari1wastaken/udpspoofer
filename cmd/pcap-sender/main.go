package main

import (
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcapgo"
)

func main() {
	var (
		pcapPath string
		dstIP    string
		dstPort  int
		pps      int
	)
	flag.StringVar(&pcapPath, "pcap", "", "Path to input pcap file")
	flag.StringVar(&dstIP, "dst-ip", "udpspoofer", "Destination IP or hostname to send UDP packets to")
	flag.IntVar(&dstPort, "dst-port", 9999, "Destination UDP port")
	flag.IntVar(&pps, "pps", 1000, "Packets per second throttle (approx)")
	flag.Bool("spoof-srcip", false, "Spoof src_ip of packets")
	flag.Parse()

	if pps < 0 {
		pps = 0
	}
	if pcapPath == "" {
		log.Fatalf("pcap path is required (use --pcap)")
	}

	f, err := os.Open(pcapPath)
	if err != nil {
		log.Fatalf("opening pcap: %v", err)
	}
	defer f.Close()

	r, err := pcapgo.NewReader(f)
	if err != nil {
		log.Fatalf("reading pcap: %v", err)
	}

	addr, err := net.ResolveUDPAddr("udp", fmt.Sprintf("%s:%d", dstIP, dstPort))
	if err != nil {
		log.Fatalf("resolve dst: %v", err)
	}

	conn, err := net.DialUDP("udp", nil, addr)
	if err != nil {
		log.Fatalf("dial udp: %v", err)
	}
	defer conn.Close()

	var interval time.Duration
	if pps > 0 {
		interval = time.Second / time.Duration(pps)
	}
	var nextSend time.Time

	count := 0
	for {
		data, ci, err := r.ReadPacketData()
		if err != nil {
			if err.Error() == "EOF" {
				break
			}
			log.Fatalf("read packet: %v", err)
		}

		pkt := gopacket.NewPacket(data, layers.LinkTypeEthernet, gopacket.Default)
		// Support common link types; fallback to decoding from raw if needed
		if pkt.Layer(layers.LayerTypeUDP) == nil {
			// Try IPv4 and UDP parsing when link layer isn't Ethernet
			pkt = gopacket.NewPacket(data, layers.LayerTypeIPv4, gopacket.Default)
			if pkt.Layer(layers.LayerTypeUDP) == nil {
				continue
			}
		}

		udpLayer := pkt.Layer(layers.LayerTypeUDP)
		udp, _ := udpLayer.(*layers.UDP)
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

	log.Printf("Done. Sent %d UDP payloads to %s", count, addr.String())
}
