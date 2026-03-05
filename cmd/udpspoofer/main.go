package main

import (
	b64 "encoding/base64"
	"encoding/json"
	"math/rand"
	"os"
	"strings"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	zl "github.com/rs/zerolog"
	"github.com/urfave/cli"

	"udpspoofer/internal/config"
	"udpspoofer/internal/db"
	"udpspoofer/internal/log"
	"udpspoofer/internal/netutil"
	udprl "udpspoofer/internal/ratelimit/udp"
)

var l zl.Logger
var packetQueue chan []byte
var staticDropLogSeconds int

const MaxPacketSize = 65536 // Maximum packet size

func main() {
	app := cli.NewApp()
	app.Name = "Packet Capture Client"
	app.Usage = "Capture packets from a network interface and spoof replies"
	app.Flags = []cli.Flag{
		cli.StringFlag{
			Name:  "interface",
			Usage: "Name of the network interface to capture packets from",
			Value: "eth0",
		},
		cli.StringFlag{
			Name:  "subnet",
			Usage: "Addresses to spoof",
		},
		cli.StringFlag{
			Name:  "protocols",
			Usage: "List of comma-separated protocols to send replies for. Supported: [tcp, udp]",
		},
		cli.BoolFlag{
			Name:  "save-clickhouse-db",
			Usage: "Save packets to Clickhouse tables",
		},
		cli.BoolFlag{
			Name:  "save-blocked-udp",
			Usage: "Save UDP packets that have been blocked by the rate limiter (useless without udp spoofing and save-clickhouse-db)",
		},
	}

	app.Action = func(c *cli.Context) error {

		// Setup logger

		if err := config.LoadDotEnvOnce(".env"); err != nil {
			// logger isn't configured yet
			panic("Error loading .env file")
		}

		log.Setup(config.GetString("LOG_LEVEL", ""))
		l = log.Logger()

		staticDropLogSeconds = config.GetInt("STATIC_DROP_LOG_SECS", 30)

		// Parse CLI flags

		interfaceName := c.String("interface")
		if interfaceName == "" {
			l.Warn().Msg(c.App.Usage)
			l.Fatal().Msg("Please provide a subnet to spoof...")
		}

		serverAddrStr := c.String("subnet")
		if serverAddrStr == "" {
			l.Fatal().Msg("Please provide a subnet to spoof...")
		}

		// TODO: these can be two separate bool flags
		protoStr := c.String("protocols")
		protocols := strings.Split(protoStr, ",")

		synspoofing := false
		udpspoofing := false

		for _, proto := range protocols {
			switch proto {
			case "tcp":
				synspoofing = true
				l.Info().Str("protocols", "tcp").Msg("spoofing tcp replies")
			case "udp":
				udpspoofing = true
				l.Info().Str("protocols", "udp").Msg("spoofing udp replies")
			default:
				if proto == "" {
					// darknet, collect both
					l.Info().Str("protocols", "none").Msg("collecting subnet as tcp/udp passive telescope")
				} else {
					l.Warn().Msg(c.App.Usage)
					l.Fatal().Str("protocol", proto).Msg("protocol not supported")
				}
			}
		}

		saveClickhouseDB := c.Bool("save-clickhouse-db")
		if saveClickhouseDB {
			l.Info().Msg("saving data to clickhouse")
		}

		saveBlockedUDP := c.Bool("save-blocked-udp")
		if saveBlockedUDP {
			l.Info().Msg("saving UDP packets blocked by the rate limiter")
		}

		// Build BPF filter
		// - single host vs CIDR
		// - Incoming TCP RST/FIN dropped when reacting
		// - Still collecting either transport regardless

		var filter string
		if strings.Contains(serverAddrStr, "/") {
			filter = "(inbound and net " + serverAddrStr + ")"
		} else {
			filter = "(inbound and host " + serverAddrStr + ")"
		}

		// Init protocol channel sizes and BPF filter

		var tcpQueue chan netutil.TcpPacket
		var udpQueue chan netutil.UdpPacket

		channelSize := config.GetInt("CHANNEL_SIZE", 100000)
		l.Info().Int("size", channelSize).Msg("channel size")

		tcpQueue = make(chan netutil.TcpPacket, channelSize)
		udpQueue = make(chan netutil.UdpPacket, channelSize)

		var tcpBatchSize, udpBatchSize int

		if synspoofing && udpspoofing {
			tcpBatchSize = config.GetInt("TCP_REACTIVE_INSERT_BATCH_SIZE", 50000)
			udpBatchSize = config.GetInt("UDP_REACTIVE_INSERT_BATCH_SIZE", 1000)
			filter += " and ((tcp and (tcp[tcpflags] & (tcp-rst|tcp-fin) == 0)) or udp)"
		} else if synspoofing {
			tcpBatchSize = config.GetInt("TCP_REACTIVE_INSERT_BATCH_SIZE", 50000)
			udpBatchSize = config.GetInt("UDP_PASSIVE_INSERT_BATCH_SIZE", 100)
			filter += " and ((tcp and (tcp[tcpflags] & (tcp-rst|tcp-fin) == 0)) or udp)"
		} else if udpspoofing {
			tcpBatchSize = config.GetInt("TCP_PASSIVE_INSERT_BATCH_SIZE", 500)
			udpBatchSize = config.GetInt("UDP_REACTIVE_INSERT_BATCH_SIZE", 50000)
			filter += " and (tcp or udp)"
		} else {
			tcpBatchSize = config.GetInt("TCP_PASSIVE_INSERT_BATCH_SIZE", 500)
			udpBatchSize = config.GetInt("UDP_PASSIVE_INSERT_BATCH_SIZE", 100)
			filter += " and (tcp or udp)"
		}

		l.Info().Int("size", tcpBatchSize).Msg("TCP batch size")
		l.Info().Int("size", udpBatchSize).Msg("UDP batch size")

		connection, err := db.Connect()
		if err != nil {
			l.Fatal().Err(err).Msg("Couldnt establish connection to database")
		}
		l.Info().Msg("Database connection set up!")

		go db.SaveTCPPackets(connection, tcpQueue, tcpBatchSize)
		go db.SaveUDPPackets(connection, udpQueue, udpBatchSize)

		// Open the network interface for packet capture
		handle, err := pcap.OpenLive(interfaceName, MaxPacketSize, true, pcap.BlockForever)
		if err != nil {
			l.Fatal().Err(err).Msg("fatal: opening interface")
		}
		defer handle.Close()

		// Create outbound thread

		packetQueue = make(chan []byte, channelSize)
		go sendthread(interfaceName, packetQueue)

		if err := handle.SetBPFFilter(filter); err != nil {
			l.Fatal().Err(err).Msg("fatal: setting bpf filter")
		}
		l.Info().Str("filter", filter).Msg("set bpf filter")
		l.Info().Str("interface", interfaceName).Msg("Listening on interface")

		// Start packet capture loop

		udpCfg := udprl.ConfigFromEnv()

		// Make the thread loop infinitely in case it ever fails
		for {
			var udpLimiter *udprl.Limiter
			if udpspoofing {
				udpLimiter = udprl.New(udpCfg)
			}
			var udpReplyCode int

			packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
			for packet := range packetSource.Packets() {
				// Only process IPv4
				ipLayer := packet.Layer(layers.LayerTypeIPv4)
				if ipLayer != nil {
					if tcpLayer := packet.Layer(layers.LayerTypeTCP); tcpLayer != nil {
						l.Trace().Msg("new TCP/IPv4 packet read")
						if synspoofing {
							SendSYNACK(packet, packetQueue)
						}
					} else if udpLayer := packet.Layer(layers.LayerTypeUDP); udpLayer != nil {
						l.Trace().Msg("new UDP/IPv4 packet read")
						if udpspoofing {
							udpReplyCode = SendUDPReply(packet, packetQueue, udpLimiter)
							if udpReplyCode == UDP_REPLY_BLOCKED && saveBlockedUDP {
								savePackets(packet, tcpQueue, udpQueue)
								continue
							}
						}
					} else {
						// Not saving anything else for now
						l.Trace().Msg("new OtherProto/IPv4 packet read")
						continue
					}

					savePackets(packet, tcpQueue, udpQueue)
				}
			}
			l.Warn().Msg("out of packetSource loop, starting again")
		}
	}

	if err := app.Run(os.Args); err != nil {
		l.Fatal().Err(err).Msg("fatal: running app")
	}
}

// Save packet to DB
func savePackets(packet gopacket.Packet, tcpQueue chan (netutil.TcpPacket), udpQueue chan (netutil.UdpPacket)) {
	timestamp := packet.Metadata().Timestamp.Unix() * 1000
	// Get IP layer
	ipLayer := packet.Layer(layers.LayerTypeIPv4)

	staticDropLog := struct {
		last  time.Time
		count int
	}{}

	if ipLayer != nil {
		ip, _ := ipLayer.(*layers.IPv4)

		var ippacket netutil.IpPacket
		ippacket.Timestamp = timestamp
		ippacket.SrcIP = netutil.IPv4ToUint32(ip.SrcIP.To4())
		ippacket.DstIP = netutil.IPv4ToUint32(ip.DstIP.To4())
		ippacket.IHL = ip.IHL
		ippacket.TOS = ip.TOS
		ippacket.Length = ip.Length
		ippacket.IpId = ip.Id
		ippacket.Flags = uint8(ip.Flags)
		ippacket.FragOffset = ip.FragOffset
		ippacket.TTL = ip.TTL
		ippacket.Protocol = uint8(ip.Protocol)
		ippacket.Checksum = ip.Checksum

		if tcpLayer := packet.Layer(layers.LayerTypeTCP); tcpLayer != nil {
			tcp, _ := tcpLayer.(*layers.TCP)

			var tcppacket netutil.TcpPacket
			tcppacket.IpPacket = ippacket
			tcppacket.SrcPort = uint16(tcp.SrcPort)
			tcppacket.DstPort = uint16(tcp.DstPort)
			tcppacket.Seq = tcp.Seq
			tcppacket.Ack = tcp.Ack
			tcppacket.DataOffset = tcp.DataOffset
			tcppacket.SYN = tcp.SYN
			tcppacket.ACK = tcp.ACK
			tcppacket.RST = tcp.RST
			tcppacket.FIN = tcp.FIN
			tcppacket.PSH = tcp.PSH
			tcppacket.URG = tcp.URG
			tcppacket.ECE = tcp.ECE
			tcppacket.CWR = tcp.CWR
			tcppacket.NS = tcp.NS
			tcppacket.Window = tcp.Window
			tcppacket.Checksum = tcp.Checksum
			tcppacket.Urgent = tcp.Urgent
			tcppacket.Options = serializeTCPOptions(tcp.Options)
			tcppacket.Payload = b64.StdEncoding.EncodeToString(tcp.Payload)

			select {
			case tcpQueue <- tcppacket:
			default:
				staticDropLog.count++
				now := time.Now()
				if now.Sub(staticDropLog.last) > time.Duration(staticDropLogSeconds)*time.Second {
					l.Warn().Int("dropped", staticDropLog.count).Msg("tcp queue full, dropping packets to avoid capture stall")
					staticDropLog.count = 0
					staticDropLog.last = now
				}
			}

		} else if udpLayer := packet.Layer(layers.LayerTypeUDP); udpLayer != nil {
			udp, _ := udpLayer.(*layers.UDP)

			var udppacket netutil.UdpPacket
			udppacket.IpPacket = ippacket
			udppacket.SrcPort = uint16(udp.SrcPort)
			udppacket.DstPort = uint16(udp.DstPort)
			udppacket.Checksum = udp.Checksum
			udppacket.Payload = b64.StdEncoding.EncodeToString(udp.Payload)

			select {
			case udpQueue <- udppacket:
			default:
				staticDropLog.count++
				now := time.Now()
				if now.Sub(staticDropLog.last) > time.Duration(staticDropLogSeconds)*time.Second {
					l.Warn().Int("dropped", staticDropLog.count).Msg("udp queue full, dropping packets to avoid capture stall")
					staticDropLog.count = 0
					staticDropLog.last = now
				}
			}
		}
	}
}

// Yeah this is janky, but it works. Not very efficient though
func serializeTCPOptions(options []layers.TCPOption) string {
	// Convert each TCPOption to a map[string]interface{} for JSON encoding
	convertedOptions := make([]map[string]interface{}, len(options))
	for i, opt := range options {
		convertedOptions[i] = map[string]interface{}{
			"OptionType":   opt.OptionType,
			"OptionLength": opt.OptionLength,
			"OptionData":   opt.OptionData,
		}
	}

	// Marshal the converted options to JSON
	tcpOptionsJSON, err := json.Marshal(convertedOptions)
	if err != nil {
		return ""
	}

	return string(tcpOptionsJSON)
}

func sendthread(interfaceName string, packetQueue chan []byte) {

	handle, err := pcap.OpenLive(interfaceName, MaxPacketSize, true, pcap.BlockForever)
	if err != nil {
		l.Fatal().Err(err).Msg("sendthread: error opening interface")
	}
	defer handle.Close()

	l.Info().Str("iface", interfaceName).Msg("sending replies on interface")

	for {
		packet := <-packetQueue

		err = handle.WritePacketData(packet)
		if err != nil {
			l.Error().Err(err).
				Str("packet", string(packet)).
				Msg("error sending packet")
		}
	}
}

// Take the incoming packet, and reply with the values from the packet.
// Reply to a SYN with a SYN/ACK, reply to an ACK with an empty ACK.
func SendSYNACK(packet gopacket.Packet, packetQueue chan []byte) {
	tcpLay := packet.Layer(layers.LayerTypeTCP)
	if tcpLay != nil {
		tcp, _ := tcpLay.(*layers.TCP)
		if tcp.SYN && !tcp.ACK {

			ipLay := packet.Layer(layers.LayerTypeIPv4)
			ethernetLayer := packet.Layer(layers.LayerTypeEthernet)
			if ethernetLayer == nil || ipLay == nil {
				return
			}
			ethernet, _ := ethernetLayer.(*layers.Ethernet)
			ip, _ := ipLay.(*layers.IPv4)

			ethLayer := &layers.Ethernet{
				SrcMAC:       ethernet.DstMAC,
				DstMAC:       ethernet.SrcMAC,
				EthernetType: layers.EthernetTypeIPv4,
			}

			ipLayer := &layers.IPv4{
				Version:  4,
				SrcIP:    ip.DstIP,
				DstIP:    ip.SrcIP,
				Protocol: layers.IPProtocolTCP,
				Id:       uint16(rand.Intn(65536)),
				TTL:      255,
			}
			tcpLayer := &layers.TCP{
				SrcPort: tcp.DstPort,
				DstPort: tcp.SrcPort,
				Seq:     tcp.Ack,
				Ack:     tcp.Seq + 1,
				SYN:     true,
				ACK:     true,
				Window:  14600,
			}
			tcpLayer.SetNetworkLayerForChecksum(ipLayer)

			buffer := gopacket.NewSerializeBuffer()
			if err := gopacket.SerializeLayers(buffer, gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true},
				ethLayer,
				ipLayer,
				tcpLayer,
			); err != nil {
				l.Error().Err(err).Msg("serialize tcp packet error")
				return
			}

			packetQueue <- buffer.Bytes()

			l.Debug().
				Str("src_ip", ipLayer.SrcIP.String()).Str("dst_ip", ipLayer.DstIP.String()).
				Uint16("src_port", uint16(tcpLayer.SrcPort)).Uint16("dst_port", uint16(tcpLayer.DstPort)).
				Msg("SYN-ACK sent")
		}

		if !tcp.SYN && tcp.ACK {

			ipLay := packet.Layer(layers.LayerTypeIPv4)
			ethernetLayer := packet.Layer(layers.LayerTypeEthernet)
			if ethernetLayer == nil || ipLay == nil {
				return
			}
			ethernet, _ := ethernetLayer.(*layers.Ethernet)
			ip, _ := ipLay.(*layers.IPv4)

			ethLayer := &layers.Ethernet{
				SrcMAC:       ethernet.DstMAC,
				DstMAC:       ethernet.SrcMAC,
				EthernetType: layers.EthernetTypeIPv4,
			}

			ipLayer := &layers.IPv4{
				Version:  4,
				SrcIP:    ip.DstIP,
				DstIP:    ip.SrcIP,
				Protocol: layers.IPProtocolTCP,
				Id:       uint16(rand.Intn(65536)),
				TTL:      255,
			}
			tcpLayer := &layers.TCP{
				SrcPort: tcp.DstPort,
				DstPort: tcp.SrcPort,
				Seq:     tcp.Ack,
				Ack:     tcp.Seq + uint32(len(tcp.Payload)),
				SYN:     false,
				ACK:     true,
				Window:  14600,
			}
			tcpLayer.SetNetworkLayerForChecksum(ipLayer)

			buffer := gopacket.NewSerializeBuffer()
			if err := gopacket.SerializeLayers(buffer, gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true},
				ethLayer,
				ipLayer,
				tcpLayer,
			); err != nil {
				l.Error().Err(err).Msg("serialize tcp packet error")
				return
			}

			packetQueue <- buffer.Bytes()

			l.Debug().
				Str("src_ip", ipLayer.SrcIP.String()).Str("dst_ip", ipLayer.DstIP.String()).
				Uint16("src_port", uint16(tcpLayer.SrcPort)).Uint16("dst_port", uint16(tcpLayer.DstPort)).
				Msg("ACK sent")
		}
	}
}

const (
	UDP_REPLY_ERROR   int = -1
	UDP_REPLY_SENT    int = 0
	UDP_REPLY_BLOCKED int = 1
)

// Take the incoming UDP packet, and reply with the values from the packet. Assumes packet is IPv4
// Returns UDP_REPLY_* value
func SendUDPReply(packet gopacket.Packet, packetQueue chan []byte, rl *udprl.Limiter) int {

	udpLay := packet.Layer(layers.LayerTypeUDP)
	ipLay := packet.Layer(layers.LayerTypeIPv4)
	if udpLay == nil || ipLay == nil {
		return UDP_REPLY_ERROR
	}

	ip, _ := ipLay.(*layers.IPv4)
	udp, _ := udpLay.(*layers.UDP)

	// AmpPot-style rate limit
	if !rl.Allow(ip.SrcIP, ip.DstIP, uint16(udp.DstPort)) {
		l.Debug().
			Str("src_ip", ip.SrcIP.String()).Str("dst_ip", ip.DstIP.String()).
			Uint16("src_port", uint16(udp.SrcPort)).Uint16("dst_port", uint16(udp.DstPort)).
			Msg("PACKET BLOCKED")
		return UDP_REPLY_BLOCKED
	}

	ethernetLayer := packet.Layer(layers.LayerTypeEthernet)
	if ethernetLayer == nil {
		return UDP_REPLY_ERROR
	}
	ethernet, _ := ethernetLayer.(*layers.Ethernet)

	ethLayer := &layers.Ethernet{
		SrcMAC:       ethernet.DstMAC,
		DstMAC:       ethernet.SrcMAC,
		EthernetType: layers.EthernetTypeIPv4,
	}

	ipLayer := &layers.IPv4{
		Version:  4,
		SrcIP:    ip.DstIP,
		DstIP:    ip.SrcIP,
		Protocol: layers.IPProtocolUDP,
		Id:       uint16(rand.Intn(65536)),
		TTL:      255,
	}

	udpLayer := &layers.UDP{
		SrcPort: udp.DstPort,
		DstPort: udp.SrcPort,
		Length:  uint16(8),
	}
	udpLayer.SetNetworkLayerForChecksum(ipLayer)

	buffer := gopacket.NewSerializeBuffer()

	if err := gopacket.SerializeLayers(
		buffer,
		gopacket.SerializeOptions{
			FixLengths:       true,
			ComputeChecksums: true,
		},
		ethLayer,
		ipLayer,
		udpLayer,
	); err != nil {
		l.Error().Err(err).Msg("serialize udp packet error")
		return UDP_REPLY_ERROR
	}

	packetQueue <- buffer.Bytes()

	l.Debug().
		Str("src_ip", ipLayer.SrcIP.String()).
		Str("dst_ip", ipLayer.DstIP.String()).
		Uint16("src_port", uint16(udpLayer.SrcPort)).
		Uint16("dst_port", uint16(udpLayer.DstPort)).
		Msg("UDP sent")

	return UDP_REPLY_SENT
}
