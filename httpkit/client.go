// Package httpkit builds Bomly's proxy- and CA-aware outbound HTTP clients
// from explicit configuration or the BOMLY_HTTP_* environment, so hosts,
// embedded components, and managed plugins share one transport policy.
//
// A ClientProvider owns one reusable transport; Client hands out per-timeout
// http.Clients over it. Standard HTTP_PROXY, HTTPS_PROXY, and NO_PROXY remain
// honored when the Bomly-specific settings are absent.
package httpkit

import (
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"
)

const (
	// EnvHTTPProxy is Bomly's explicit outbound HTTP proxy environment variable.
	EnvHTTPProxy = "BOMLY_HTTP_PROXY"
	// EnvHTTPNoProxy is Bomly's explicit proxy bypass list environment variable.
	EnvHTTPNoProxy = "BOMLY_HTTP_NO_PROXY"
	// EnvHTTPProxyType is Bomly's explicit outbound proxy type.
	EnvHTTPProxyType = "BOMLY_HTTP_PROXY_TYPE"
	// EnvHTTPProxyHost is Bomly's explicit outbound proxy host.
	EnvHTTPProxyHost = "BOMLY_HTTP_PROXY_HOST"
	// EnvHTTPProxyPort is Bomly's explicit outbound proxy port.
	EnvHTTPProxyPort = "BOMLY_HTTP_PROXY_PORT"
	// EnvHTTPProxyUsername is Bomly's explicit outbound proxy username.
	EnvHTTPProxyUsername = "BOMLY_HTTP_PROXY_USERNAME"
	// EnvHTTPProxyPassword is Bomly's explicit outbound proxy password.
	EnvHTTPProxyPassword = "BOMLY_HTTP_PROXY_PASSWORD"
	// EnvHTTPCACertFile points to an additional PEM certificate chain for outbound HTTPS.
	EnvHTTPCACertFile = "BOMLY_HTTP_CA_CERT_FILE"
)

// ClientConfig configures Bomly's shared outbound HTTP client. External
// plugins normally obtain this from ClientConfigFromEnv instead of building
// it by hand, so Bomly-managed proxy and CA settings are honored.
type ClientConfig struct {
	ProxyURL      string
	NoProxy       string
	ProxyType     string
	ProxyHost     string
	ProxyPort     int
	ProxyUsername string
	ProxyPassword string
	CACertFile    string
	Timeout       time.Duration
}

// ClientProvider owns reusable HTTP transport state for one Bomly execution
// or plugin process. Reuse one provider for repeated outbound calls so
// connection pools, proxy settings, and TLS configuration stay consistent.
type ClientProvider struct {
	transport      *http.Transport
	defaultTimeout time.Duration
}

// ClientConfigFromEnv returns Bomly-specific HTTP client settings from
// environment variables. Standard HTTP_PROXY, HTTPS_PROXY, and NO_PROXY are
// still honored by NewClient when Bomly-specific values are absent.
func ClientConfigFromEnv() ClientConfig {
	port, _ := strconv.Atoi(strings.TrimSpace(os.Getenv(EnvHTTPProxyPort)))
	return ClientConfig{
		ProxyURL:      strings.TrimSpace(os.Getenv(EnvHTTPProxy)),
		NoProxy:       strings.TrimSpace(os.Getenv(EnvHTTPNoProxy)),
		ProxyType:     strings.TrimSpace(os.Getenv(EnvHTTPProxyType)),
		ProxyHost:     strings.TrimSpace(os.Getenv(EnvHTTPProxyHost)),
		ProxyPort:     port,
		ProxyUsername: strings.TrimSpace(os.Getenv(EnvHTTPProxyUsername)),
		ProxyPassword: os.Getenv(EnvHTTPProxyPassword),
		CACertFile:    strings.TrimSpace(os.Getenv(EnvHTTPCACertFile)),
	}
}

// NewClientProvider creates an HTTP client provider with a reusable
// transport. Call Client to create timeout-specific clients that share
// connection pools and TLS/proxy settings.
func NewClientProvider(config ClientConfig) (*ClientProvider, error) {
	transport := http.DefaultTransport.(*http.Transport).Clone()
	proxy, err := proxyFunc(config)
	if err != nil {
		return nil, err
	}
	transport.Proxy = proxy
	if strings.TrimSpace(config.CACertFile) != "" {
		tlsConfig, err := tlsConfigWithCACert(config.CACertFile)
		if err != nil {
			return nil, err
		}
		transport.TLSClientConfig = tlsConfig
	}
	return &ClientProvider{
		transport:      transport,
		defaultTimeout: config.Timeout,
	}, nil
}

// NewClientProviderFromEnv creates a provider from Bomly HTTP environment
// variables, with standard proxy environment variables honored as fallback. Use
// this in external plugins that make outbound HTTP calls.
func NewClientProviderFromEnv() (*ClientProvider, error) {
	return NewClientProvider(ClientConfigFromEnv())
}

// Client returns an HTTP client with the requested timeout. A zero timeout uses
// the provider's configured default timeout.
func (p *ClientProvider) Client(timeout time.Duration) *http.Client {
	if p == nil {
		client, _ := NewClient(ClientConfig{Timeout: timeout})
		return client
	}
	if timeout == 0 {
		timeout = p.defaultTimeout
	}
	return &http.Client{
		Transport: p.transport,
		Timeout:   timeout,
	}
}

// CloseIdleConnections closes idle connections held by the provider transport.
func (p *ClientProvider) CloseIdleConnections() {
	if p == nil || p.transport == nil {
		return
	}
	p.transport.CloseIdleConnections()
}

// NewClient creates an outbound HTTP client using Go's default transport
// behavior plus Bomly's proxy configuration.
func NewClient(config ClientConfig) (*http.Client, error) {
	provider, err := NewClientProvider(config)
	if err != nil {
		return nil, err
	}
	return provider.Client(config.Timeout), nil
}

// EffectiveProxyURL returns the effective proxy URL after applying Bomly's URL or
// decomposed proxy settings. It does not inspect standard proxy environment
// variables.
func (config ClientConfig) EffectiveProxyURL() (string, error) {
	return resolvedProxyURL(config)
}
