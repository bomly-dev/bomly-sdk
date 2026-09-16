package plugin

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func TestDecodePluginConfigFromEnv(t *testing.T) {
	type pluginConfig struct {
		APIBase string `json:"api_base"`
		Enabled bool   `json:"enabled"`
	}
	path := filepath.Join(t.TempDir(), "config.json")
	data, err := json.Marshal(map[string]any{"api_base": "https://api.example.com", "enabled": true})
	if err != nil {
		t.Fatalf("marshal config: %v", err)
	}
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}
	t.Setenv(EnvPluginConfigFile, path)

	var cfg pluginConfig
	if err := DecodePluginConfigFromEnv(&cfg); err != nil {
		t.Fatalf("DecodePluginConfigFromEnv() error = %v", err)
	}
	if cfg.APIBase != "https://api.example.com" || !cfg.Enabled {
		t.Fatalf("decoded config = %#v", cfg)
	}
}
