package config

import (
	"io"
	"os"
	"strings"

	"gopkg.in/yaml.v3"
)

type NameServerConfig struct {
	Name        string `yaml:"name"`
	Type        string `yaml:"type"`   // ip | doh
	Server      string `yaml:"server"` // IP:port or DoH URL
	ECSOverride bool   `yaml:"ecs-override"`
	ECS         string `yaml:"ecs"`
}

type NameServerGroup struct {
	Name        string   `yaml:"name"`
	Nameservers []string `yaml:"nameservers"`
	ECSOverride bool     `yaml:"ecs-override"`
	ECS         string   `yaml:"ecs"`
}

type CacheSection struct {
	Enable bool `yaml:"enable"`
}

type LogSection struct {
	Level string `yaml:"level"` // debug | info
}

type Config struct {
	Listen               string             `yaml:"listen"`
	BootstrapNameservers []string           `yaml:"bootstrap-nameservers"`
	Nameservers          []NameServerConfig `yaml:"nameservers"`
	NameserverGroup      []NameServerGroup  `yaml:"nameserver-group"`
	NameserverPolicy     []string           `yaml:"nameserver-policy"`
	GeoxURL              string             `yaml:"geox-url"`
	Cache                *CacheSection      `yaml:"cache"`
	Log                  *LogSection        `yaml:"log"`
	IPv6                 *bool              `yaml:"ipv6"` // enable returning AAAA records
}

func Load(path string) (*Config, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return LoadFromReader(f)
}

func LoadFromReader(r io.Reader) (*Config, error) {
	var c Config
	dec := yaml.NewDecoder(r)
	dec.KnownFields(true)
	if err := dec.Decode(&c); err != nil {
		return nil, err
	}
	// Normalize
	for i := range c.Nameservers {
		c.Nameservers[i].Type = strings.ToLower(strings.TrimSpace(c.Nameservers[i].Type))
	}
	// Default: enable cache if not specified
	if c.Cache == nil {
		c.Cache = &CacheSection{Enable: true}
	}
	if c.Log == nil {
		c.Log = &LogSection{Level: "info"}
	} else {
		c.Log.Level = strings.ToLower(strings.TrimSpace(c.Log.Level))
		if c.Log.Level == "" {
			c.Log.Level = "info"
		}
	}
	// Default IPv6 behavior: enabled if not set (backward compatible)
	if c.IPv6 == nil {
		val := true
		c.IPv6 = &val
	}
	return &c, nil
}
