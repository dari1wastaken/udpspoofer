-- Initialize test database and tables for udpspoofer

CREATE DATABASE IF NOT EXISTS test;

-- UDP packets table
CREATE TABLE test.udppackets
(
    Timestamp DateTime64(0, 'Europe/Amsterdam') CODEC(Delta(8), ZSTD(1)),
    SrcIP UInt32 CODEC(Delta(4), ZSTD(1)),
    DstIP UInt32 CODEC(Delta(4), ZSTD(1)),
    IHL UInt8 CODEC(Delta(1), ZSTD(1)),
    TOS UInt8 CODEC(Delta(1), ZSTD(1)),
    Length UInt16 CODEC(Delta(2), ZSTD(1)),
    IPId UInt16 CODEC(Delta(2), ZSTD(1)),
    Flags UInt8 CODEC(Delta(1), ZSTD(1)),
    FragOffset UInt16 CODEC(Delta(2), ZSTD(1)),
    TTL UInt8 CODEC(Delta(1), ZSTD(1)),
    Protocol UInt8 CODEC(Delta(1), ZSTD(1)),
    SrcPort UInt16 CODEC(Delta(2), ZSTD(1)),
    DstPort UInt16 CODEC(Delta(2), ZSTD(1)),
    UDPLength UInt16 CODEC(Delta(2), ZSTD(1)),
    Payload String CODEC(ZSTD(1))
)
ENGINE = MergeTree
PARTITION BY toYYYYMM(Timestamp)
PRIMARY KEY (DstPort, toStartOfDay(Timestamp), SrcIP)
ORDER BY (DstPort, toStartOfDay(Timestamp), SrcIP, DstIP)
SETTINGS index_granularity = 8192
COMMENT 'Main Packet table containing UDP packet fields'


CREATE TABLE test.tcppackets
   (
       Timestamp DateTime64(0, 'Europe/Amsterdam') CODEC(Delta(8), ZSTD(1)),
       SrcIP UInt32 CODEC(Delta(4), ZSTD(1)),
       DstIP UInt32 CODEC(Delta(4), ZSTD(1)),
       IHL UInt8 CODEC(Delta(1), ZSTD(1)),
       TOS UInt8 CODEC(Delta(1), ZSTD(1)),
       Length UInt16 CODEC(Delta(2), ZSTD(1)),
       IPId UInt16 CODEC(Delta(2), ZSTD(1)),
       Flags UInt8 CODEC(Delta(1), ZSTD(1)),
       FragOffset UInt16 CODEC(Delta(2), ZSTD(1)),
       TTL UInt8 CODEC(Delta(1), ZSTD(1)),
       Protocol UInt8 CODEC(Delta(1), ZSTD(1)),
       SrcPort UInt16 CODEC(Delta(2), ZSTD(1)),
       DstPort UInt16 CODEC(Delta(2), ZSTD(1)),
       Seq UInt32 CODEC(LZ4),
       Ack UInt32 CODEC(Delta(4), ZSTD(1)),
       DataOffset UInt8 CODEC(Delta(1), ZSTD(1)),
       FIN Bool CODEC(Delta(1), ZSTD(1)),
       SYN Bool CODEC(Delta(1), ZSTD(1)),
       RST Bool CODEC(Delta(1), ZSTD(1)),
       PSH Bool CODEC(Delta(1), ZSTD(1)),
       ACK Bool CODEC(Delta(1), ZSTD(1)),
       URG Bool CODEC(Delta(1), ZSTD(1)),
       ECE Bool CODEC(Delta(1), ZSTD(1)),
       CWR Bool CODEC(Delta(1), ZSTD(1)),
       NS Bool CODEC(Delta(1), ZSTD(1)),
       Window UInt16 CODEC(Delta(2), ZSTD(1)),
       Urgent UInt16 CODEC(Delta(2), ZSTD(1)),
       Options String CODEC(ZSTD(1)),
       Payload String CODEC(ZSTD(1))
   )
   ENGINE = MergeTree
   PARTITION BY toYYYYMM(Timestamp)
   PRIMARY KEY (DstPort, toStartOfDay(Timestamp), SrcIP)
   ORDER BY (DstPort, toStartOfDay(Timestamp), SrcIP, DstIP)
   SETTINGS index_granularity = 8192
   COMMENT 'Main Packet table containing TCP packet fields'