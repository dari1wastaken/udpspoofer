package main

import (
	"net"
	"sync"
	"time"
)

var (
	udpWindow        = time.Duration(GetEnvInt("UDP_RL_WINDOW_MINUTES", 1)) * time.Minute
	udpBlockTTL      = time.Duration(GetEnvInt("UDP_RL_BLOCK_TTL_MINUTES", 60)) * time.Minute
	udpIPLimit       = GetEnvInt("UDP_IP_LIMIT", 3)
	udpSubnetLimit   = GetEnvInt("UDP_SUBNET_LIMIT", 30)
	udpEndpointLimit = GetEnvInt("UDP_ENDPOINT_LIMIT", 100)

	// Prune expired rate-entry maps only every N cleanup ticks, to reduce CPU overhead.
	// (blocked maps are still cleaned every tick)
	udpEntryCleanupIntervals = GetEnvInt("UDP_ENTRY_CLEANUP_INTERVALS", 10)
)

type rateEntry struct {
	count     int
	windowEnd time.Time
}

type blockEntry struct {
	until time.Time
}

type UdpRateLimiter struct {
	mu               sync.Mutex
	ipRates          map[uint32]*rateEntry
	subRates         map[uint32]*rateEntry
	epRates          map[uint32]*rateEntry
	blockedIP        map[uint32]*blockEntry
	blocked24        map[uint32]*blockEntry
	blockedEndpoints map[uint32]*blockEntry
}

func NewUdpRateLimiter() *UdpRateLimiter {
	rl := &UdpRateLimiter{
		ipRates:   make(map[uint32]*rateEntry),
		subRates:  make(map[uint32]*rateEntry),
		epRates:   make(map[uint32]*rateEntry),
		blockedIP: make(map[uint32]*blockEntry),
		blocked24: make(map[uint32]*blockEntry),
		// Key: (DstIP_last2bytes << 16) | DstPort
		// We won't monitor more than one IPv4 /16 anyway.
		blockedEndpoints: make(map[uint32]*blockEntry),
	}
	go rl.cleanupLoop()
	return rl
}

func (r *UdpRateLimiter) Allow(srcIP, dstIP net.IP, dstPort uint16) bool {
	// Defensive normalization: even if the caller filters for IPv4 earlier,
	// Go can still hand around IPv4 as a 16-byte slice (e.g. ::ffff:a.b.c.d).
	src4 := srcIP.To4()
	dst4 := dstIP.To4()
	if src4 == nil || dst4 == nil {
		// Not IPv4 (or malformed). Refuse to reply (safe default).
		return false
	}

	r.mu.Lock()
	defer r.mu.Unlock()

	now := time.Now()

	// Block check
	src := Ip2int(src4)
	if b, ok := r.blockedIP[src]; ok && now.Before(b.until) {
		logger.Debug().Str("src_ip", src4.String()).Msg("REASON srcIP blocked")
		return false
	}

	subnet := src & 0xFFFFFF00
	if b, ok := r.blocked24[subnet]; ok && now.Before(b.until) {
		logger.Debug().Str("subnet", src4.String()).Msg("REASON subnet blocked")
		return false
	}

	// Endpoint key: last two bytes of dst IPv4 + dst port.
	// (dst4[2], dst4[3]) are safe now because dst4 is exactly 4 bytes.
	dst := (uint32(dst4[2]) << 24) | (uint32(dst4[3]) << 16) | uint32(dstPort)
	if b, ok := r.blockedEndpoints[dst]; ok && now.Before(b.until) {
		logger.Debug().Str("dst_ip", dst4.String()).Uint16("dst_port", dstPort).Msg("REASON endpoint blocked")
		return false
	}

	// IP rate
	if !r.bump(r.ipRates, src, udpIPLimit, now) {
		r.blockedIP[src] = &blockEntry{until: now.Add(udpBlockTTL)}
		logger.Info().Str("src_ip", src4.String()).Msg("BLOCKING Source IP")
		return false
	}

	// /24 rate
	if !r.bump(r.subRates, subnet, udpSubnetLimit, now) {
		r.blocked24[subnet] = &blockEntry{until: now.Add(udpBlockTTL)}
		logger.Info().Str("src_net", src4.String()).Msg("BLOCKING Source /24")
		return false
	}

	// Endpoint rate
	if !r.bump(r.epRates, dst, udpEndpointLimit, now) {
		r.blockedEndpoints[dst] = &blockEntry{until: now.Add(udpBlockTTL)}
		logger.Info().Str("dst_ip", dst4.String()).Uint16("dst_port", dstPort).Msg("BLOCKING Endpoint")
		return false
	}

	return true
}

func (r *UdpRateLimiter) bump(m map[uint32]*rateEntry, key uint32, limit int, now time.Time) bool {
	e, ok := m[key]

	if !ok || now.After(e.windowEnd) {
		m[key] = &rateEntry{
			count:     1,
			windowEnd: now.Add(udpWindow),
		}
		return true
	}

	e.count++
	return e.count <= limit
}

func (r *UdpRateLimiter) cleanupLoop() {
	intervalMinutes := GetEnvInt("UDP_RL_CLEANUP_INTERVAL_MINUTES", 3)
	ticker := time.NewTicker(time.Duration(intervalMinutes) * time.Minute)
	logger.Info().
		Int("minutes", intervalMinutes).
		Int("udp_entry_cleanup_intervals", udpEntryCleanupIntervals).
		Msg("cleanup loop interval")

	if udpEntryCleanupIntervals <= 0 {
		udpEntryCleanupIntervals = 10
	}

	var (
		cleanedBlockedIPs  int64
		cleanedBlockedNets int64
		cleanedBlockedEPs  int64

		cleanedRateIPs  int64
		cleanedRateNets int64
		cleanedRateEPs  int64

		ticks int
	)

	for range ticker.C {
		now := time.Now()

		cleanedBlockedIPs = 0
		cleanedBlockedNets = 0
		cleanedBlockedEPs = 0
		cleanedRateIPs = 0
		cleanedRateNets = 0
		cleanedRateEPs = 0

		ticks++

		r.mu.Lock()

		logger.Info().
			Time("time", now).
			Int("src_ips", len(r.ipRates)).
			Int("src_24s", len(r.subRates)).
			Int("endpoints", len(r.epRates)).
			Msg("current tracked entries")

		logger.Info().
			Time("time", now).
			Int("src_ips", len(r.blockedIP)).
			Int("src_24s", len(r.blocked24)).
			Int("endpoints", len(r.blockedEndpoints)).
			Msg("current blocked entries")

		// Always clean blocked entries
		for k, v := range r.blockedIP {
			if now.After(v.until) {
				delete(r.blockedIP, k)
				logger.Debug().Time("time", now).Uint32("key", k).Msg("CLEAN blocked IP")
				cleanedBlockedIPs++
			}
		}
		for k, v := range r.blocked24 {
			if now.After(v.until) {
				delete(r.blocked24, k)
				logger.Debug().Time("time", now).Uint32("key", k).Msg("CLEAN blocked Net")
				cleanedBlockedNets++
			}
		}
		for k, v := range r.blockedEndpoints {
			if now.After(v.until) {
				delete(r.blockedEndpoints, k)
				logger.Debug().Time("time", now).Uint32("key", k).Msg("CLEAN blocked EP")
				cleanedBlockedEPs++
			}
		}

		// Clean expired rate entries only every N ticks
		if ticks%udpEntryCleanupIntervals == 0 {
			for k, v := range r.ipRates {
				if now.After(v.windowEnd) {
					delete(r.ipRates, k)
					cleanedRateIPs++
				}
			}
			for k, v := range r.subRates {
				if now.After(v.windowEnd) {
					delete(r.subRates, k)
					cleanedRateNets++
				}
			}
			for k, v := range r.epRates {
				if now.After(v.windowEnd) {
					delete(r.epRates, k)
					cleanedRateEPs++
				}
			}
		}

		logger.Info().
			Time("time", now).
			Int64("blocked_src_ips", cleanedBlockedIPs).
			Int64("blocked_src_24s", cleanedBlockedNets).
			Int64("blocked_endpoints", cleanedBlockedEPs).
			Int64("rate_src_ips", cleanedRateIPs).
			Int64("rate_src_24s", cleanedRateNets).
			Int64("rate_endpoints", cleanedRateEPs).
			Msg("cleaned entries")

		r.mu.Unlock()
	}
}
