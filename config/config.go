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

type Config struct {
	Listen               string             `yaml:"listen"`
	BootstrapNameservers []string           `yaml:"bootstrap-nameservers"`
	Nameservers          []NameServerConfig `yaml:"nameservers"`
	NameserverGroup      []NameServerGroup  `yaml:"nameserver-group"`
	NameserverPolicy     []string           `yaml:"nameserver-policy"`
	GeoxURL              string             `yaml:"geox-url"`
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
	return &c, nil
}
