package config

import (
	"os"
	"log"
	"path/filepath"
	"encoding/json/v2"
)

type FixedConfigSettings struct {
	Enabled bool `json:"enabled"`
	Port int `json:"port"`
	Policy string `json:"policy"`
	IPSetV4 []string `json:"ipset_v4"`
	IPSetV6 []string `json:"ipset_v6"`
}

type ExtraConfigIPSet struct {
	Name string `json:"name"`
	List []string `json:"list"`
}

type ExtraConfigSettings struct {
	Enabled bool `json:"enabled"`
	Protocol string `json:"protocol"`
	Port int `json:"port"`
	Policy string `json:"policy"`
	IPSetV4 ExtraConfigIPSet `json:"ipset_v4"`
	IPSetV6 ExtraConfigIPSet `json:"ipset_v6"`
}

type Config struct {
	DefaultPolicy string `json:"default_policy"`
	SSH FixedConfigSettings `json:"ssh"`
	HTTP FixedConfigSettings `json:"http"`
	HTTPS FixedConfigSettings `json:"https"`
	Extras []any `json:"extras"` // string | ExtraConfigSettings
}

func LoadConfig(path string) (Config, error) {
	var config Config

	file, err := os.ReadFile(path)

	if err != nil {
		return config, err
	}

	err = json.Unmarshal(file, &config, json.MatchCaseInsensitiveNames(true))
	if err != nil {
		return config, err
	}

	return config, nil
}

var configCache *Config = nil

func GetConfig() (*Config, error) {
	if configCache != nil {
		return configCache, nil
	}

	currentDir, err := os.Getwd()

	if err != nil {
		log.Println(err)
		return nil, err
	}

	configPath := filepath.Join(currentDir, "config.json")

	config, err := LoadConfig(configPath)

	if err != nil {
		log.Println(err)
		return nil, err
	}

	configCache = &config

	return &config, err
}
