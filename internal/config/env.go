package config

import (
	"os"
	"strconv"
	"sync"

	"github.com/joho/godotenv"
)

var loadOnce sync.Once
var loadErr error

// LoadDotEnvOnce loads variables from a dotenv file exactly once.
// Subsequent calls are no-ops and return the original error (if any).
//
// Per your requirement, we only load from ".env" (callers choose the path).
func LoadDotEnvOnce(path string) error {
	loadOnce.Do(func() {
		// Using Load() preserves existing environment variables and only fills in missing ones.
		// (If you want ".env" to override existing env, switch to godotenv.Overload)
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
