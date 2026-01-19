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
	src := Ip2int(srcIP)
	subnet := src & 0xFFFFFF00
	dst := uint32(dstIP[2])<<24 | uint32(dstIP[3])<<16 | uint32(dstPort)
	now := time.Now()

	r.mu.Lock()
	defer r.mu.Unlock()

	// Block check
	if b, ok := r.blockedIP[src]; ok && now.Before(b.until) {
		return false
	}
	if b, ok := r.blocked24[subnet]; ok && now.Before(b.until) {
		return false
	}
	if b, ok := r.blockedEndpoints[dst]; ok && now.Before(b.until) {
		return false
	}

	// IP rate
	if !r.bump(r.ipRates, src, udpIPLimit, now) {
		r.blockedIP[src] = &blockEntry{until: now.Add(udpBlockTTL)}
		return false
	}

	// /24 rate
	if !r.bump(r.subRates, subnet, udpSubnetLimit, now) {
		r.blocked24[subnet] = &blockEntry{until: now.Add(udpBlockTTL)}
		return false
	}

	// Endpoint Rate
	if !r.bump(r.epRates, dst, udpEndpointLimit, now) {
		r.blockedEndpoints[dst] = &blockEntry{until: now.Add(udpBlockTTL)}
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
	ticker := time.NewTicker(5 * time.Minute)
	for range ticker.C {
		now := time.Now()
		r.mu.Lock()
		for k, v := range r.blockedIP {
			if now.After(v.until) {
				delete(r.blockedIP, k)
			}
		}
		for k, v := range r.blocked24 {
			if now.After(v.until) {
				delete(r.blocked24, k)
			}
		}
		for k, v := range r.blockedEndpoints {
			if now.After(v.until) {
				delete(r.blockedEndpoints, k)
			}
		}
		r.mu.Unlock()
	}
}
