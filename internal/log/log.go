package log

import (
	"os"
	"strings"
	"time"

	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
)

var logger zerolog.Logger

func Setup(cfgLevel string) {
	zerolog.TimeFieldFormat = time.RFC3339Nano
	var level zerolog.Level
	switch strings.ToLower(cfgLevel) {
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
}

func Logger() zerolog.Logger {
	return logger
}
