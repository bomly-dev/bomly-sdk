package sdk

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
)

const (
	// EnvPluginConfigFile points external plugins at their per-plugin JSON config.
	EnvPluginConfigFile = "BOMLY_PLUGIN_CONFIG_FILE"
	// EnvPluginID identifies the managed plugin currently being executed.
	EnvPluginID = "BOMLY_PLUGIN_ID"
)

// RawPluginConfigFromEnv reads the per-plugin JSON config file named by
// BOMLY_PLUGIN_CONFIG_FILE. It returns nil when no plugin config file is set.
func RawPluginConfigFromEnv() ([]byte, error) {
	path := strings.TrimSpace(os.Getenv(EnvPluginConfigFile))
	if path == "" {
		return nil, nil
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read plugin config: %w", err)
	}
	return data, nil
}

// DecodePluginConfigFromEnv decodes the current plugin's JSON config file into
// target. Bomly writes this file from the enabled plugin's own
// plugins.<plugin-id> config block and exposes its path through the plugin
// environment.
func DecodePluginConfigFromEnv(target any) error {
	data, err := RawPluginConfigFromEnv()
	if err != nil {
		return err
	}
	if len(data) == 0 {
		return nil
	}
	if target == nil {
		return fmt.Errorf("plugin config target is nil")
	}
	if err := json.Unmarshal(data, target); err != nil {
		return fmt.Errorf("decode plugin config: %w", err)
	}
	return nil
}
