package main

import (
	"context"
	"fmt"
	"log"
	"math/rand"
	"net"
	"os"
	"strings"

	b64 "encoding/base64"
	"encoding/binary"
	"encoding/json"

	"github.com/ClickHouse/clickhouse-go/v2"
	"github.com/ClickHouse/clickhouse-go/v2/lib/driver"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/joho/godotenv"
	"github.com/urfave/cli"
)

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
	}

	app.Action = func(c *cli.Context) error {
		interfaceName := c.String("interface")
		serverAddrStr := c.String("subnet")
		synspoofing := false
		udpspoofing := false

		if serverAddrStr == "" {
			log.Panic("Please provide a subnet to spoof...")
		}

		protoStr := c.String("protocols")
		protocols := strings.Split(protoStr, ",")

		connection, err := Connect()
		if err != nil {
			log.Fatalf("Couldnt establish connection to database: %v", err)
		}
		fmt.Println("Database connection set up!")

		// Init protocol channels and update packet filter

		var tcpQueue chan TcpPacket
		var udpQueue chan UdpPacket
		var filter string = "inbound and net " + serverAddrStr

		for _, proto := range protocols {
			switch proto {
			case "tcp":
				synspoofing = true
				tcpQueue = make(chan TcpPacket, 10000)
				filter += " and (tcp[tcpflags] & tcp-fin) == 0 and (tcp[tcpflags] & tcp-rst) == 0"
				go SaveTCPPackets(connection, tcpQueue)
			case "udp":
				// filter should already work
				udpspoofing = true
				udpQueue = make(chan UdpPacket, 10000)
				go SaveUDPPackets(connection, udpQueue)
			default:
				log.Println(c.App.Usage)
				log.Fatalf("protocol not supported: %s", proto)
			}
		}

		// Open the network interface for packet capture
		handle, err := pcap.OpenLive(interfaceName, MaxPacketSize, true, pcap.BlockForever)
		if err != nil {
			log.Fatalf("Error opening interface: %v", err)
		}
		defer handle.Close()

		// create outbound thread
		packetQueue = make(chan []byte)
		go sendthread(interfaceName, packetQueue)

		fmt.Printf("BPF filter: %s\n", filter)
		err = handle.SetBPFFilter(filter)
		if err != nil {
			log.Fatalf("Error setting BPF filter: %v", err)
		}

		fmt.Printf("Listening on interface: %s\n", interfaceName)

		// Make the thread loop infinitely in case it ever fails
		for {
			// Packet capture loop
			packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
			for packet := range packetSource.Packets() {

				// Only process IPv4
				ipLayer := packet.Layer(layers.LayerTypeIPv4)
				if ipLayer != nil {

					transport := packet.TransportLayer()
					switch transport.LayerType() {
					case layers.LayerTypeTCP:
						if synspoofing {
							SendSYNACK(packet, packetQueue)
						}
					case layers.LayerTypeUDP:
						if udpspoofing {
							SendUDPReply(packet, packetQueue)
						}
					default:
						// TODO: save them?
						continue
					}
					savePackets(packet, tcpQueue, udpQueue)
				}
			}
		}
	}

	err := app.Run(os.Args)
	if err != nil {
		log.Fatal(err)
	}
}

// Save to DB - This code you probably do not really need to touch, it is specific to our DB.
func savePackets(packet gopacket.Packet, tcpQueue chan (TcpPacket), udpQueue chan (UdpPacket)) {
	timestamp := packet.Metadata().Timestamp.Unix() * 1000
	// Get IP layer
	ipLayer := packet.Layer(layers.LayerTypeIPv4)

	if ipLayer != nil {
		ip, _ := ipLayer.(*layers.IPv4)

		var ippacket IpPacket
		ippacket.Timestamp = timestamp
		ippacket.SrcIP = Ip2int(ip.SrcIP)
		ippacket.DstIP = Ip2int(ip.DstIP)
		ippacket.IHL = ip.IHL
		ippacket.TOS = ip.TOS
		ippacket.Length = ip.Length
		ippacket.IpId = ip.Id
		ippacket.Flags = uint8(ip.Flags)
		ippacket.FragOffset = ip.FragOffset
		ippacket.TTL = ip.TTL
		ippacket.Protocol = uint8(ip.Protocol)
		ippacket.Checksum = ip.Checksum

		// Let's see the type of the packet
		tcpLayer := packet.Layer(layers.LayerTypeTCP)
		udpLayer := packet.Layer(layers.LayerTypeUDP)

		if tcpLayer != nil {
			tcp, _ := tcpLayer.(*layers.TCP)

			var tcppacket TcpPacket

			// Save IP header to packet
			tcppacket.IpPacket = ippacket

			// Save TCP header to Packet
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

			tcpQueue <- tcppacket

		} else if udpLayer != nil {
			udp, _ := udpLayer.(*layers.UDP)

			var udppacket UdpPacket

			// Save IP header to packet
			udppacket.IpPacket = ippacket

			// Save TCP header to Packet
			udppacket.SrcPort = uint16(udp.SrcPort)
			udppacket.DstPort = uint16(udp.DstPort)
			udppacket.Checksum = udp.Checksum

			udppacket.Payload = b64.StdEncoding.EncodeToString(udp.Payload)

			udpQueue <- udppacket
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

func Ip2int(ip net.IP) uint32 {
	if len(ip) == 16 {
		panic("no sane way to convert ipv6 into uint32")
	}
	return binary.BigEndian.Uint32(ip)
}

func sendthread(interfaceName string, packetQueue chan []byte) {
	// Open the network interface for packet capture
	handle, err := pcap.OpenLive(interfaceName, MaxPacketSize, true, pcap.BlockForever)
	if err != nil {
		log.Fatalf("Error opening interface: %v", err)
	}
	defer handle.Close()

	for {
		packet := <-packetQueue

		// Send the packet
		err = handle.WritePacketData(packet)
		if err != nil {
			log.Printf("Error sending packet: %v\n", err)
			log.Printf("Packet: %x\n", packet)
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
				log.Printf("Error serializing packet: %c\n", err)
				return
			}

			packetQueue <- buffer.Bytes()
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
				log.Printf("Error serializing packet: %c", err)
				return
			}

			packetQueue <- buffer.Bytes()
		}
	}
}

// Take the incoming UDP packet, and reply with the values from the packet.
// Assumes packet is IPv4
func SendUDPReply(packet gopacket.Packet, packetQueue chan []byte) {
	udpLay := packet.Layer(layers.LayerTypeUDP)
	if udpLay != nil {
		udp, _ := udpLay.(*layers.UDP)

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
			log.Printf("Error serializing packet: %c\n", err)
			return
		}

		packetQueue <- buffer.Bytes()
	}

}

// use godot package to load/read the .env file and
// return the value of the key
func GoDotEnvVariable(key string) string {

	// load .env file
	err := godotenv.Load(".env")

	if err != nil {
		log.Fatalf("Error loading .env file")
	}

	return os.Getenv(key)
}

// Function to connect to a Clickhouse database. NOTE: TLS is disabled at this moment. To allow for TLS, we should include this here.
// It is running internally, so for now w/e
func Connect() (driver.Conn, error) {
	var (
		ctx       = context.Background()
		conn, err = clickhouse.Open(&clickhouse.Options{
			Addr: []string{GoDotEnvVariable("DATABASE_HOST") + ":" + GoDotEnvVariable("DATABASE_PORT")},
			Auth: clickhouse.Auth{
				Database: GoDotEnvVariable("DATABASE"),
				Username: GoDotEnvVariable("DATABASE_USER"),
				Password: GoDotEnvVariable("DATABASE_PASSWORD"),
			},
			ClientInfo: clickhouse.ClientInfo{
				Products: []struct {
					Name    string
					Version string
				}{
					{Name: GoDotEnvVariable("DATABASE_CLIENT_NAME"), Version: GoDotEnvVariable("VERSION")},
				},
			},

			Debugf: func(format string, v ...interface{}) {
				fmt.Printf(format, v)
			},
			// TLS: &tls.Config{
			// 	InsecureSkipVerify: true,
			// },
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

func SaveUDPPackets(conn driver.Conn, udpQueue chan (UdpPacket)) {
	udpbatch, err := prepareBatch(conn, "udppackets")
	if err != nil {
		log.Panic(err)
	}

	fmt.Println("UDP batch created...")

	udppackets := 0
	save := false
	for {
		if udppackets >= 50000 || save {
			fmt.Println("Saving packets to database...")
			err = udpbatch.Send()
			if err != nil {
				fmt.Println(err)
			}
			udpbatch, err = prepareBatch(conn, "udppackets")
			if err != nil {
				fmt.Println(err)
			}
			udppackets = 0
			save = false
		}

		// Blocking call to recieve from the queue
		packet := <-udpQueue
		if packet.Flush {
			save = true
			continue
		}
		err = udpbatch.Append(
			packet.Timestamp,
			// IP Header
			packet.SrcIP,
			packet.DstIP,
			packet.IHL,
			packet.TOS,
			packet.Length,
			packet.IpId,
			packet.Flags,
			packet.FragOffset,
			packet.TTL,
			packet.Protocol,
			// REMOVED Checksum due to compression
			// packet.Checksum,

			//Start of the UDP header
			packet.SrcPort,
			packet.DstPort,
			packet.UDPLength,
			// packet.UDPChecksum,

			packet.Payload,
		)
		if err != nil {
			fmt.Println("ERROR in batching UDPPacket: " + err.Error())
		}
		udppackets++
	}
}

func SaveTCPPackets(conn driver.Conn, tcpQueue chan (TcpPacket)) {
	tcpbatch, err := prepareBatch(conn, "tcppackets")
	if err != nil {
		log.Panic(err)
	}

	fmt.Println("TCP batch created...")

	tcppackets := 0
	save := false
	for {
		if tcppackets >= 50000 || save {
			fmt.Println("Saving packets to database...")
			err = tcpbatch.Send()
			if err != nil {
				fmt.Println(err)
			}
			tcpbatch, err = prepareBatch(conn, "tcppackets")
			if err != nil {
				fmt.Println(err)
			}
			tcppackets = 0
			save = false
		}

		// Blocking call to recieve from the queue
		packet := <-tcpQueue
		if packet.Flush {
			save = true
			continue
		}
		err = tcpbatch.Append(
			packet.Timestamp,
			// IP Header
			packet.SrcIP,
			packet.DstIP,
			packet.IHL,
			packet.TOS,
			packet.Length,
			packet.IpId,
			packet.Flags,
			packet.FragOffset,
			packet.TTL,
			packet.Protocol,
			// REMOVED Checksum due to compression
			// packet.Checksum,

			//Start of the TCP header
			packet.SrcPort,
			packet.DstPort,
			packet.Seq,
			packet.Ack,
			packet.DataOffset,
			packet.FIN,
			packet.SYN,
			packet.RST,
			packet.PSH,
			packet.ACK,
			packet.URG,
			packet.ECE,
			packet.CWR,
			packet.NS,
			packet.Window,
			// packet.TCPChecksum,
			packet.Urgent,
			packet.Options,
			packet.Payload,
		)
		if err != nil {
			fmt.Println("ERROR in batching TCPPacket: " + err.Error())
		}
		tcppackets++
	}
}
