package main

import (
	"errors"
	"os"

	"github.com/BurntSushi/toml"
)

type crlConfig struct {
	URL          string   `toml:"url"`
	Name         string   `toml:"name"`
	ProfileName  string   `toml:"profile_name"`
	RefreshDelay duration `toml:"refresh_delay"`
	Validate     bool     `toml:"validate"`
}

type f5Config struct {
	AuthMethod        string `toml:"auth_method"`
	URL               string `toml:"url"`
	User              string `toml:"user"`
	Password          string `toml:"password"`
	SSLCheck          bool   `toml:"ssl_check"`
	LoginProviderName string `toml:"login_provided_name"`
}

type config struct {
	F5  f5Config    `toml:"f5"`
	CRL []crlConfig `toml:"crl"`
}

func readConfig(path string) (*config, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, errors.New("cannot open configuration file: " + err.Error())
	}
	defer file.Close()

	var cfg config
	if _, err := toml.DecodeReader(file, &cfg); err != nil {
		return nil, errors.New("cannot read configuration file: " + err.Error())
	}

	return &cfg, nil
}

// hasCRLDistributionPoint reports whether the config defines at least one CRL
// distribution point.
func (c config) hasCRLDistributionPoint() bool {
	return c.CRL != nil && len(c.CRL) > 0
}
