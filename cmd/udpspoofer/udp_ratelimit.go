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
		// Key: (DstIP << 16) | DstPort
		// We won't track more than one /16 anyway
		blockedEndpoints: make(map[uint32]*blockEntry),
	}
	go rl.cleanupLoop()
	return rl
}

func (r *UdpRateLimiter) Allow(srcIP, dstIP net.IP, dstPort uint16) bool {

	r.mu.Lock()
	defer r.mu.Unlock()

	now := time.Now()

	// Block check
	src := Ip2int(srcIP)
	if b, ok := r.blockedIP[src]; ok && now.Before(b.until) {
		logger.Debug().
			Str("src_ip", srcIP.String()).
			Msg("REASON srcIP blocked")
		return false
	}

	subnet := src & 0xFFFFFF00
	if b, ok := r.blocked24[subnet]; ok && now.Before(b.until) {
		logger.Debug().
			Str("subnet", srcIP.String()).
			Msg("REASON subnet blocked")
		return false
	}

	dst := uint32(dstIP[2])<<24 | uint32(dstIP[3])<<16 | uint32(dstPort)
	if b, ok := r.blockedEndpoints[dst]; ok && now.Before(b.until) {
		logger.Debug().
			Str("dst_ip", dstIP.String()).
			Uint16("dst_port", dstPort).
			Msg("REASON endpoint blocked")
		return false
	}

	// IP rate
	if !r.bump(r.ipRates, src, udpIPLimit, now) {
		r.blockedIP[src] = &blockEntry{until: now.Add(udpBlockTTL)}
		logger.Info().Str("src_ip", srcIP.String()).Msg("BLOCKING Source IP")
		return false
	}

	// /24 rate
	if !r.bump(r.subRates, subnet, udpSubnetLimit, now) {
		r.blocked24[subnet] = &blockEntry{until: now.Add(udpBlockTTL)}
		logger.Info().Str("src_net", srcIP.String()).Msg("BLOCKING Source /24")
		return false
	}

	// Endpoint Rate
	if !r.bump(r.epRates, dst, udpEndpointLimit, now) {
		r.blockedEndpoints[dst] = &blockEntry{until: now.Add(udpBlockTTL)}
		logger.Info().Str("dst_ip", dstIP.String()).Int16("dst_port", int16(dstPort)).Msg("BLOCKING Endpoint")
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
	logger.Info().Int("minutes", intervalMinutes).Msg("cleanup loop interval")
	var ips, nets, eps int64

	for range ticker.C {
		now := time.Now()
		ips = 0
		nets = 0
		eps = 0
		r.mu.Lock()
		for k, v := range r.blockedIP {
			if now.After(v.until) {
				delete(r.blockedIP, k)
				logger.Debug().Time("time", now).Uint32("key", k).Msg("CLEAN blocked IP")
				ips += 1
			}
		}
		for k, v := range r.blocked24 {
			if now.After(v.until) {
				delete(r.blocked24, k)
				logger.Debug().Time("time", now).Uint32("key", k).Msg("CLEAN blocked Net")
				nets += 1
			}
		}
		for k, v := range r.blockedEndpoints {
			if now.After(v.until) {
				delete(r.blockedEndpoints, k)
				logger.Debug().Time("time", now).Uint32("key", k).Msg("CLEAN blocked EP")
				eps += 1
			}
		}
		logger.Info().Time("time", now).Int64("src_ips", ips).Int64("src_24s", nets).Int64("endpoints", eps).Msg("cleanup blocked entries")
		r.mu.Unlock()
	}
}
