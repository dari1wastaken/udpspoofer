package udp

import (
	"time"
	"udpspoofer/internal/config"
)

type Config struct {
	Window                time.Duration
	BlockTTL              time.Duration
	IPLimit               int
	SubnetLimit           int
	EndpointLimit         int
	CleanupInterval       time.Duration
	EntryCleanupIntervals int
}

func ConfigFromEnv() Config {
	windowMins := config.GetInt("UDP_RL_WINDOW_MINUTES", 1)
	blockTTLMins := config.GetInt("UDP_RL_BLOCK_TTL_MINUTES", 60)

	cleanupIntervalMins := config.GetInt("UDP_RL_CLEANUP_INTERVAL_MINUTES", 3)

	entryCleanupIntervals := config.GetInt("UDP_ENTRY_CLEANUP_INTERVALS", 10)
	if entryCleanupIntervals <= 0 {
		entryCleanupIntervals = 10
	}

	return Config{
		Window:                time.Duration(windowMins) * time.Minute,
		BlockTTL:              time.Duration(blockTTLMins) * time.Minute,
		IPLimit:               config.GetInt("UDP_IP_LIMIT", 3),
		SubnetLimit:           config.GetInt("UDP_SUBNET_LIMIT", 30),
		EndpointLimit:         config.GetInt("UDP_ENDPOINT_LIMIT", 100),
		CleanupInterval:       time.Duration(cleanupIntervalMins) * time.Minute,
		EntryCleanupIntervals: entryCleanupIntervals,
	}
}
