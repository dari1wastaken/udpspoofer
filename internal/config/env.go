package config

import (
	"os"
	"strconv"
	"sync"

	"github.com/joho/godotenv"
)

var loadOnce sync.Once
var loadErr error

func LoadDotEnvOnce(path string) error {
	loadOnce.Do(func() {
		loadErr = godotenv.Load(path)
	})
	return loadErr
}

func GetString(key, def string) string {
	v := os.Getenv(key)
	if v == "" {
		return def
	}
	return v
}

func GetInt(key string, def int) int {
	v := os.Getenv(key)
	if v == "" {
		return def
	}
	i, err := strconv.Atoi(v)
	if err != nil {
		return def
	}
	return i
}
