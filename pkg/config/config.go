package config

import "gopkg.in/yaml.v2"

type Config struct {
	Static Static `yaml:"static"`
}

type Static struct {
	Targets []string `yaml:"targets"`
}

func Parse(buf []byte) (*Config, error) {
	var c Config
	if err := yaml.Unmarshal(buf, &c); err != nil {
		return nil, err
	}
	return &c, nil
}
