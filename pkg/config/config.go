package config

import (
	"fmt"
	"os"
)

type Config struct {
	NatsHost string
	NatsPort string
}

func fetchEnv(varString string, fallbackString string) string {
	env, found := os.LookupEnv(varString)
	if !found {
		return fallbackString
	}
	return env
}

func LoadConfig() *Config {
	return &Config{
		NatsHost: fetchEnv("NATS_HOST", "localhost"),
		NatsPort: fetchEnv("NATS_PORT", "4222"),
	}
}

func (c *Config) GetNatsConnStr() string {
	return fmt.Sprintf("http://%s:%s", c.NatsHost, c.NatsPort)
}
