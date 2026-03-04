package main

import (
	"context"
	b64 "encoding/base64"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"math/rand"
	"os"
	"strings"
	"time"

	"github.com/ClickHouse/clickhouse-go/v2"
	"github.com/ClickHouse/clickhouse-go/v2/lib/driver"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/urfave/cli"

	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"

	"udpspoofer/internal/config"
	"udpspoofer/internal/netutil"
	udprl "udpspoofer/internal/ratelimit/udp"
)

var logger zerolog.Logger
var packetQueue chan []byte

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
			Name:  "udp-reflect",
			Usage: "Send the same UDP payload back to the source",
		},
	}

	app.Action = func(c *cli.Context) error {
		zerolog.TimeFieldFormat = time.RFC3339Nano

		// Load .env exactly once (matching current behavior: fatal if missing).
		if err := config.LoadDotEnvOnce(".env"); err != nil {
			// logger isn't configured yet; use standard log.Logger default formatting via zerolog/log package.
			log.Fatal().Err(err).Msg("Error loading .env file")
		}

		var level zerolog.Level
		switch strings.ToLower(config.GetString("LOG_LEVEL", "")) {
		case "debug":
			level = zerolog.DebugLevel
		case "info":
			level = zerolog.InfoLevel
		case "warn":
			level = zerolog.WarnLevel
		case "error":
			level = zerolog.ErrorLevel
		case "trace":
			level = zerolog.TraceLevel
		default:
			level = zerolog.InfoLevel
		}

		log.Logger = zerolog.New(os.Stdout).With().Timestamp().Logger().Level(level)
		logger = log.Logger

		interfaceName := c.String("interface")
		serverAddrStr := c.String("subnet")
		synspoofing := false
		udpspoofing := false

		if serverAddrStr == "" {
			logger.Fatal().Msg("Please provide a subnet to spoof...")
		}

		protoStr := c.String("protocols")
		protocols := strings.Split(protoStr, ",")

		connection, err := Connect()
		if err != nil {
			logger.Fatal().Err(err).Msg("Couldnt establish connection to database")
		}
		logger.Info().Msg("Database connection set up!")

		// Build a robust BPF filter depending on host vs CIDR
		var filter string
		if strings.Contains(serverAddrStr, "/") {
			filter = "(inbound and net " + serverAddrStr + ")"
		} else {
			filter = "(inbound and host " + serverAddrStr + ")"
		}

		// Parse proto flags into bools
		for _, proto := range protocols {
			switch proto {
			case "tcp":
				synspoofing = true
				logger.Info().Str("protocols", "tcp").Msg("spoofing tcp replies")
			case "udp":
				udpspoofing = true
				logger.Info().Str("protocols", "udp").Msg("spoofing udp replies")
			default:
				if proto == "" {
					// darknet, collect both
					logger.Info().Str("protocols", "none").Msg("collecting subnet as tcp/udp passive telescope")
				} else {
					logger.Warn().Msg(c.App.Usage)
					logger.Fatal().Str("protocol", proto).Msg("protocol not supported")
				}
			}
		}

		// Init protocol channels and update packet filter
		var tcpQueue chan TcpPacket
		var udpQueue chan UdpPacket

		// Load configurable channel size
		channelSize := config.GetInt("CHANNEL_SIZE", 100000)
		logger.Info().Int("size", channelSize).Msg("CHANNEL_SIZE")

		tcpQueue = make(chan TcpPacket, channelSize)
		udpQueue = make(chan UdpPacket, channelSize)

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

		logger.Info().Int("size", tcpBatchSize).Msg("TCP batch size")
		logger.Info().Int("size", udpBatchSize).Msg("UDP batch size")

		// IMPORTANT: ClickHouse batching should be single-writer per table to avoid pool starvation.
		go SaveTCPPackets(connection, tcpQueue, tcpBatchSize)
		go SaveUDPPackets(connection, udpQueue, udpBatchSize)

		// Open the network interface for packet capture
		handle, err := pcap.OpenLive(interfaceName, MaxPacketSize, true, pcap.BlockForever)
		if err != nil {
			logger.Fatal().Err(err).Msg("fatal: opening interface")
		}
		defer handle.Close()

		// create outbound thread
		packetQueue = make(chan []byte, channelSize)
		go sendthread(interfaceName, packetQueue)

		logger.Info().Str("filter", filter).Msg("set bpf filter")
		if err := handle.SetBPFFilter(filter); err != nil {
			logger.Fatal().Err(err).Msg("fatal: setting bpf filter")
		}

		logger.Info().Str("interface", interfaceName).Msg("Listening on interface")

		reflectPayloads := c.Bool("udp-reflect")
		if reflectPayloads {
			logger.Info().Msg("reflecting udp scanners payloads")
		}

		udpCfg := udprl.ConfigFromEnv()

		// Make the thread loop infinitely in case it ever fails
		for {
			var udpLimiter *udprl.Limiter
			// Init rate limiter
			if udpspoofing {
				udpLimiter = udprl.New(udpCfg, logger)
			}

			// Packet capture loop
			packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
			for packet := range packetSource.Packets() {
				// Only process IPv4
				ipLayer := packet.Layer(layers.LayerTypeIPv4)
				if ipLayer != nil {
					if tcpLayer := packet.Layer(layers.LayerTypeTCP); tcpLayer != nil {
						logger.Trace().Msg("new TCP/IPv4 packet read")
						if synspoofing {
							SendSYNACK(packet, packetQueue)
						}
					} else if udpLayer := packet.Layer(layers.LayerTypeUDP); udpLayer != nil {
						logger.Trace().Msg("new UDP/IPv4 packet read")
						if udpspoofing {
							SendUDPReply(packet, packetQueue, udpLimiter, reflectPayloads)
						}
					} else {
						// Not saving anything else for now
						logger.Trace().Msg("new OtherProto/IPv4 packet read")
						continue
					}

					savePackets(packet, tcpQueue, udpQueue)
				}
			}
			logger.Warn().Msg("out of packetSource loop, starting again")
		}
	}

	if err := app.Run(os.Args); err != nil {
		logger.Fatal().Err(err).Msg("fatal: running app")
	}
}

// Save to DB - This code you probably do not really need to touch, it is specific to our DB.
func savePackets(packet gopacket.Packet, tcpQueue chan (TcpPacket), udpQueue chan (UdpPacket)) {
	timestamp := packet.Metadata().Timestamp.Unix() * 1000
	// Get IP layer
	ipLayer := packet.Layer(layers.LayerTypeIPv4)

	staticDropLog := struct {
		last  time.Time
		count int
	}{}

	if ipLayer != nil {
		ip, _ := ipLayer.(*layers.IPv4)

		var ippacket IpPacket
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

			var tcppacket TcpPacket
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
			tcppacket.Options = SerializeTCPOptions(tcp.Options)
			tcppacket.Payload = b64.StdEncoding.EncodeToString(tcp.Payload)

			select {
			case tcpQueue <- tcppacket:
			default:
				staticDropLog.count++
				now := time.Now()
				if now.Sub(staticDropLog.last) > time.Second {
					logger.Warn().Int("dropped", staticDropLog.count).Msg("tcp queue full, dropping packets to avoid capture stall")
					staticDropLog.count = 0
					staticDropLog.last = now
				}
			}

		} else if udpLayer := packet.Layer(layers.LayerTypeUDP); udpLayer != nil {
			udp, _ := udpLayer.(*layers.UDP)

			var udppacket UdpPacket
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
				if now.Sub(staticDropLog.last) > time.Second {
					logger.Warn().Int("dropped", staticDropLog.count).Msg("udp queue full, dropping packets to avoid capture stall")
					staticDropLog.count = 0
					staticDropLog.last = now
				}
			}
		}
	}
}

// Yeah this is janky, but it works. Not very efficient though
func SerializeTCPOptions(options []layers.TCPOption) string {
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
	// Open the network interface for packet capture
	handle, err := pcap.OpenLive(interfaceName, MaxPacketSize, true, pcap.BlockForever)
	if err != nil {
		logger.Fatal().Err(err).Msg("sendthread: error opening interface")
	}
	defer handle.Close()

	logger.Info().Str("iface", interfaceName).Msg("sending replies on interface")

	for {
		packet := <-packetQueue

		// Send the packet
		err = handle.WritePacketData(packet)
		if err != nil {
			logger.Error().Err(err).
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
				logger.Error().Err(err).Msg("serialize tcp packet error")
				return
			}

			packetQueue <- buffer.Bytes()

			logger.Debug().
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
				logger.Error().Err(err).Msg("serialize tcp packet error")
				return
			}

			packetQueue <- buffer.Bytes()

			logger.Debug().
				Str("src_ip", ipLayer.SrcIP.String()).Str("dst_ip", ipLayer.DstIP.String()).
				Uint16("src_port", uint16(tcpLayer.SrcPort)).Uint16("dst_port", uint16(tcpLayer.DstPort)).
				Msg("ACK sent")
		}
	}
}

// Take the incoming UDP packet, and reply with the values from the packet.
// Assumes packet is IPv4
func SendUDPReply(packet gopacket.Packet, packetQueue chan []byte, rl *udprl.Limiter, reflect bool) {
	udpLay := packet.Layer(layers.LayerTypeUDP)
	ipLay := packet.Layer(layers.LayerTypeIPv4)
	if udpLay == nil || ipLay == nil {
		return
	}

	ip, _ := ipLay.(*layers.IPv4)
	udp, _ := udpLay.(*layers.UDP)

	// AmpPot-style rate limit
	if !rl.Allow(ip.SrcIP, ip.DstIP, uint16(udp.DstPort)) {
		logger.Debug().
			Str("src_ip", ip.SrcIP.String()).Str("dst_ip", ip.DstIP.String()).
			Uint16("src_port", uint16(udp.SrcPort)).Uint16("dst_port", uint16(udp.DstPort)).
			Msg("PACKET BLOCKED")
		return
	}

	ethernetLayer := packet.Layer(layers.LayerTypeEthernet)
	if ethernetLayer == nil {
		return
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

	if reflect {
		if err := gopacket.SerializeLayers(
			buffer,
			gopacket.SerializeOptions{
				FixLengths:       true,
				ComputeChecksums: true,
			},
			ethLayer,
			ipLayer,
			udpLayer,
			gopacket.Payload(udp.Payload),
		); err != nil {
			logger.Error().Err(err).Msg("serialize udp packet error")
			return
		}
	} else {
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
			logger.Error().Err(err).Msg("serialize udp packet error")
			return
		}
	}

	packetQueue <- buffer.Bytes()

	logger.Debug().
		Str("src_ip", ipLayer.SrcIP.String()).
		Str("dst_ip", ipLayer.DstIP.String()).
		Uint16("src_port", uint16(udpLayer.SrcPort)).
		Uint16("dst_port", uint16(udpLayer.DstPort)).
		Msg("UDP sent")
}

// Function to connect to a Clickhouse database. NOTE: TLS is disabled at this moment. To allow for TLS, we should include this here.
// It is running internally, so for now w/e
func Connect() (driver.Conn, error) {
	var (
		ctx       = context.Background()
		conn, err = clickhouse.Open(&clickhouse.Options{
			Addr: []string{config.GetString("DATABASE_HOST", "") + ":" + config.GetString("DATABASE_PORT", "")},
			Auth: clickhouse.Auth{
				Database: config.GetString("DATABASE", ""),
				Username: config.GetString("DATABASE_USER", ""),
				Password: config.GetString("DATABASE_PASSWORD", ""),
			},
			ClientInfo: clickhouse.ClientInfo{
				Products: []struct {
					Name    string
					Version string
				}{
					{Name: config.GetString("DATABASE_CLIENT_NAME", ""), Version: config.GetString("VERSION", "")},
				},
			},

			Debugf: func(format string, v ...interface{}) {
				fmt.Printf(format, v)
			},
		})
	)

	if err != nil {
		return nil, err
	}

	if err := conn.Ping(ctx); err != nil {
		if exception, ok := err.(*clickhouse.Exception); ok {
			fmt.Printf("Exception [%d] %s \n%s\n", exception.Code, exception.Message, exception.StackTrace)
		}
		return nil, err
	}

	return conn, nil
}

func Query(conn driver.Conn, query string) (driver.Rows, error) {
	ctx := context.Background()
	rows, err := conn.Query(ctx, query)
	if err != nil {
		return nil, err
	}
	return rows, nil
}

//////// SOME HELPER STUFF /////////

type Packet struct {
	Timestamp int64
	Flush     bool `default:"false"`
}

type IpPacket struct {
	Packet
	SrcIP, DstIP uint32
	IHL          uint8
	TOS          uint8
	Length       uint16
	IpId         uint16
	Flags        uint8
	FragOffset   uint16
	TTL          uint8
	Protocol     uint8
	Checksum     uint16
}

type TcpPacket struct {
	IpPacket
	SrcPort, DstPort                           uint16
	Seq                                        uint32
	Ack                                        uint32
	DataOffset                                 uint8
	FIN, SYN, RST, PSH, ACK, URG, ECE, CWR, NS bool
	Window                                     uint16
	TCPChecksum                                uint16
	Urgent                                     uint16
	Options                                    string
	Payload                                    string
}

type UdpPacket struct {
	IpPacket
	SrcPort, DstPort uint16
	UDPLength        uint16
	UDPChecksum      uint16
	Payload          string
}

func prepareBatch(conn driver.Conn, table string) (driver.Batch, error) {
	ctx := context.Background()
	header := fmt.Sprintf("INSERT INTO %s ", table)
	return conn.PrepareBatch(ctx, header, driver.WithReleaseConnection())
}

// Single-writer UDP batcher: no concurrent Send/PrepareBatch to avoid ClickHouse pool starvation.
func SaveUDPPackets(conn driver.Conn, udpQueue chan (UdpPacket), batchSize int) {
	current, err := prepareBatch(conn, "udppackets")
	if err != nil {
		logger.Fatal().Err(err).Msg("Error preparing UDP batch")
	}
	logger.Info().Msg("UDP batch created...")

	inBatch := 0

	flush := func() {
		if inBatch == 0 {
			return
		}
		logger.Info().Str("proto", "udp").Int("batch_size", inBatch).Msg("saving batch to clickhouse")
		if err := current.Send(); err != nil {
			logger.Error().Err(err).Msg("udp batch send error")
			// Drop the batch and try to recreate on next packet.
		}

		current, err = prepareBatch(conn, "udppackets")
		if err != nil {
			logger.Error().Err(err).Msg("udp prepare new batch error")
			current = nil
		} else {
			logger.Debug().Msg("prepare new UDP batch after send")
		}
		inBatch = 0
	}

	for {
		pkt := <-udpQueue
		if pkt.Flush || inBatch >= batchSize {
			flush()
			if pkt.Flush {
				continue
			}
		}

		if current == nil {
			current, err = prepareBatch(conn, "udppackets")
			if err != nil {
				logger.Error().Err(err).Msg("udp re-prepare batch error; will retry on next packet")
				continue
			}
			logger.Debug().Msg("prepared new UDP batch after previous error")
		}

		err = current.Append(
			pkt.Timestamp,
			pkt.SrcIP,
			pkt.DstIP,
			pkt.IHL,
			pkt.TOS,
			pkt.Length,
			pkt.IpId,
			pkt.Flags,
			pkt.FragOffset,
			pkt.TTL,
			pkt.Protocol,
			pkt.SrcPort,
			pkt.DstPort,
			pkt.UDPLength,
			pkt.Payload,
		)
		if err != nil {
			logger.Error().Err(err).Msg("ERROR in batching UDPPacket")
			continue
		}
		inBatch++
	}
}

// Single-writer TCP batcher: no concurrent Send/PrepareBatch to avoid ClickHouse pool starvation.
func SaveTCPPackets(conn driver.Conn, tcpQueue chan (TcpPacket), batchSize int) {
	current, err := prepareBatch(conn, "tcppackets")
	if err != nil {
		logger.Fatal().Err(err).Msg("Error preparing TCP batch")
	}
	logger.Info().Msg("TCP batch created...")

	inBatch := 0

	flush := func() {
		if inBatch == 0 {
			return
		}
		logger.Info().Str("proto", "tcp").Int("batch_size", inBatch).Msg("saving batch to clickhouse")
		if err := current.Send(); err != nil {
			logger.Error().Err(err).Msg("tcp batch send error")
		}

		current, err = prepareBatch(conn, "tcppackets")
		if err != nil {
			logger.Error().Err(err).Msg("tcp prepare new batch error")
			current = nil
		} else {
			logger.Debug().Msg("prepare new TCP batch after send")
		}
		inBatch = 0
	}

	for {
		pkt := <-tcpQueue
		if pkt.Flush || inBatch >= batchSize {
			flush()
			if pkt.Flush {
				continue
			}
		}

		if current == nil {
			current, err = prepareBatch(conn, "tcppackets")
			if err != nil {
				logger.Error().Err(err).Msg("tcp re-prepare batch error; will retry on next packet")
				continue
			}
			logger.Debug().Msg("prepared new TCP batch after previous error")
		}

		err = current.Append(
			pkt.Timestamp,
			pkt.SrcIP,
			pkt.DstIP,
			pkt.IHL,
			pkt.TOS,
			pkt.Length,
			pkt.IpId,
			pkt.Flags,
			pkt.FragOffset,
			pkt.TTL,
			pkt.Protocol,
			pkt.SrcPort,
			pkt.DstPort,
			pkt.Seq,
			pkt.Ack,
			pkt.DataOffset,
			pkt.FIN,
			pkt.SYN,
			pkt.RST,
			pkt.PSH,
			pkt.ACK,
			pkt.URG,
			pkt.ECE,
			pkt.CWR,
			pkt.NS,
			pkt.Window,
			pkt.Urgent,
			pkt.Options,
			pkt.Payload,
		)
		if err != nil {
			logger.Error().Err(err).Msg("ERROR in batching TCPPacket")
			continue
		}
		inBatch++
	}
}

// NOTE: this file still imports encoding/binary for other code paths, but Ip2int is now unused.
// If you want, we can remove encoding/binary import and any remaining uses in a follow-up cleanup.
var _ = binary.BigEndian
