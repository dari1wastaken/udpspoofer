package db

import (
	"context"
	"fmt"
	"udpspoofer/internal/config"
	"udpspoofer/internal/log"
	"udpspoofer/internal/netutil"

	"github.com/ClickHouse/clickhouse-go/v2"
	"github.com/ClickHouse/clickhouse-go/v2/lib/driver"
)

// Connect to a Clickhouse database
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

func prepareBatch(conn driver.Conn, table string) (driver.Batch, error) {
	ctx := context.Background()
	header := fmt.Sprintf("INSERT INTO %s ", table)
	return conn.PrepareBatch(ctx, header, driver.WithReleaseConnection())
}

// Single-writer UDP batcher: no concurrent Send/PrepareBatch to avoid ClickHouse pool starvation.
func SaveUDPPackets(conn driver.Conn, udpQueue chan (netutil.UdpPacket), batchSize int) {

	l := log.Logger()

	current, err := prepareBatch(conn, "udppackets")
	if err != nil {
		l.Fatal().Err(err).Msg("Error preparing UDP batch")
	}
	l.Info().Msg("UDP batch created...")

	inBatch := 0

	flush := func() {
		if inBatch == 0 {
			return
		}
		l.Info().Str("proto", "udp").Int("batch_size", inBatch).Msg("saving batch to clickhouse")
		if err := current.Send(); err != nil {
			l.Error().Err(err).Msg("udp batch send error")
			// Drop the batch and try to recreate on next packet.
		}

		current, err = prepareBatch(conn, "udppackets")
		if err != nil {
			l.Error().Err(err).Msg("udp prepare new batch error")
			current = nil
		} else {
			l.Debug().Msg("prepare new UDP batch after send")
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
				l.Error().Err(err).Msg("udp re-prepare batch error; will retry on next packet")
				continue
			}
			l.Debug().Msg("prepared new UDP batch after previous error")
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
			pkt.Blocked,
			pkt.Replied,
		)
		if err != nil {
			l.Error().Err(err).Msg("ERROR in batching UDPPacket")
			continue
		}
		inBatch++
	}
}

// Single-writer TCP batcher: no concurrent Send/PrepareBatch to avoid ClickHouse pool starvation.
func SaveTCPPackets(conn driver.Conn, tcpQueue chan (netutil.TcpPacket), batchSize int) {

	l := log.Logger()

	current, err := prepareBatch(conn, "tcppackets")
	if err != nil {
		l.Fatal().Err(err).Msg("Error preparing TCP batch")
	}
	l.Info().Msg("TCP batch created...")

	inBatch := 0

	flush := func() {
		if inBatch == 0 {
			return
		}
		l.Info().Str("proto", "tcp").Int("batch_size", inBatch).Msg("saving batch to clickhouse")
		if err := current.Send(); err != nil {
			l.Error().Err(err).Msg("tcp batch send error")
		}

		current, err = prepareBatch(conn, "tcppackets")
		if err != nil {
			l.Error().Err(err).Msg("tcp prepare new batch error")
			current = nil
		} else {
			l.Debug().Msg("prepare new TCP batch after send")
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
				l.Error().Err(err).Msg("tcp re-prepare batch error; will retry on next packet")
				continue
			}
			l.Debug().Msg("prepared new TCP batch after previous error")
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
			l.Error().Err(err).Msg("ERROR in batching TCPPacket")
			continue
		}
		inBatch++
	}
}
