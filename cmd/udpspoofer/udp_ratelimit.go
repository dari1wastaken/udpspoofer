package main

import (
	"net"
	"sync"
	"time"
)

const (
	udpIPLimit     = 3
	udpSubnetLimit = 30
	udpWindow      = time.Minute
	udpBlockTTL    = time.Hour
)

type rateEntry struct {
	count     int
	windowEnd time.Time
}

type blockEntry struct {
	until time.Time
}

type UdpRateLimiter struct {
	mu        sync.Mutex
	ipRates   map[uint32]*rateEntry
	subRates  map[uint32]*rateEntry
	blockedIP map[uint32]*blockEntry
	blocked24 map[uint32]*blockEntry
}

func NewUdpRateLimiter() *UdpRateLimiter {
	rl := &UdpRateLimiter{
		ipRates:   make(map[uint32]*rateEntry),
		subRates:  make(map[uint32]*rateEntry),
		blockedIP: make(map[uint32]*blockEntry),
		blocked24: make(map[uint32]*blockEntry),
	}
	go rl.cleanupLoop()
	return rl
}

func (r *UdpRateLimiter) Allow(src net.IP) bool {
	ip := Ip2int(src)
	subnet := ip & 0xFFFFFF00
	now := time.Now()

	r.mu.Lock()
	defer r.mu.Unlock()

	// Block check
	if b, ok := r.blockedIP[ip]; ok && now.Before(b.until) {
		return false
	}
	if b, ok := r.blocked24[subnet]; ok && now.Before(b.until) {
		return false
	}

	// IP rate
	if !r.bump(r.ipRates, ip, udpIPLimit, now) {
		r.blockedIP[ip] = &blockEntry{until: now.Add(udpBlockTTL)}
		return false
	}

	// /24 rate
	if !r.bump(r.subRates, subnet, udpSubnetLimit, now) {
		r.blocked24[subnet] = &blockEntry{until: now.Add(udpBlockTTL)}
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
		r.mu.Unlock()
	}
}
