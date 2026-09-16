package httpkit

import (
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestNewHTTPClientExplicitProxy(t *testing.T) {
	client, err := NewClient(ClientConfig{
		ProxyURL: "http://proxy.example:8080",
		Timeout:  3 * time.Second,
	})
	if err != nil {
		t.Fatalf("NewClient() error = %v", err)
	}
	if client.Timeout != 3*time.Second {
		t.Fatalf("Timeout = %v, want 3s", client.Timeout)
	}
	proxyURL := proxyForRequest(t, client, "http://service.example/v1")
	if proxyURL == nil || proxyURL.String() != "http://proxy.example:8080" {
		t.Fatalf("proxy = %v, want http://proxy.example:8080", proxyURL)
	}
}

func TestNewHTTPClientNoProxyBypass(t *testing.T) {
	client, err := NewClient(ClientConfig{
		ProxyURL: "http://proxy.example:8080",
		NoProxy:  ".corp.example",
	})
	if err != nil {
		t.Fatalf("NewClient() error = %v", err)
	}
	if proxyURL := proxyForRequest(t, client, "http://service.corp.example/v1"); proxyURL != nil {
		t.Fatalf("proxy = %v, want bypass", proxyURL)
	}
}

func TestNewHTTPClientMergesNoProxyWithStandardProxyFallback(t *testing.T) {
	t.Setenv("HTTP_PROXY", "http://standard-proxy.example:8080")
	t.Setenv("HTTPS_PROXY", "http://standard-proxy.example:8080")
	t.Setenv("ALL_PROXY", "")
	t.Setenv("NO_PROXY", ".standard.example,.shared.example")
	t.Setenv("no_proxy", "")

	client, err := NewClient(ClientConfig{NoProxy: ".bomly.example,.shared.example"})
	if err != nil {
		t.Fatalf("NewClient() error = %v", err)
	}
	for _, endpoint := range []string{
		"http://service.standard.example/v1",
		"http://service.bomly.example/v1",
		"http://service.shared.example/v1",
	} {
		if proxyURL := proxyForRequest(t, client, endpoint); proxyURL != nil {
			t.Fatalf("proxy for %s = %v, want merged no-proxy bypass", endpoint, proxyURL)
		}
	}
	proxyURL := proxyForRequest(t, client, "http://service.example/v1")
	if proxyURL == nil || proxyURL.String() != "http://standard-proxy.example:8080" {
		t.Fatalf("proxy = %v, want standard environment proxy", proxyURL)
	}
}

func TestNewHTTPClientMergesNoProxyWithExplicitProxy(t *testing.T) {
	t.Setenv("NO_PROXY", ".standard.example")
	t.Setenv("no_proxy", "")

	client, err := NewClient(ClientConfig{
		ProxyURL: "http://bomly-proxy.example:8080",
		NoProxy:  ".bomly.example",
	})
	if err != nil {
		t.Fatalf("NewClient() error = %v", err)
	}
	for _, endpoint := range []string{
		"http://service.standard.example/v1",
		"http://service.bomly.example/v1",
	} {
		if proxyURL := proxyForRequest(t, client, endpoint); proxyURL != nil {
			t.Fatalf("proxy for %s = %v, want merged no-proxy bypass", endpoint, proxyURL)
		}
	}
	proxyURL := proxyForRequest(t, client, "http://service.example/v1")
	if proxyURL == nil || proxyURL.String() != "http://bomly-proxy.example:8080" {
		t.Fatalf("proxy = %v, want explicit Bomly proxy", proxyURL)
	}
}

func TestMergeNoProxyPreservesOrderAndRemovesDuplicates(t *testing.T) {
	got := mergeNoProxy(".standard.example, localhost", "LOCALHOST,.bomly.example")
	if got != ".standard.example,localhost,.bomly.example" {
		t.Fatalf("mergeNoProxy() = %q", got)
	}
}

func TestNewHTTPClientBuildsProxyFromHostPort(t *testing.T) {
	client, err := NewClient(ClientConfig{
		ProxyType:     "socks5",
		ProxyHost:     "proxy.example",
		ProxyPort:     1080,
		ProxyUsername: "user@example.com",
		ProxyPassword: "p@ss word",
	})
	if err != nil {
		t.Fatalf("NewClient() error = %v", err)
	}
	proxyURL := proxyForRequest(t, client, "http://service.example/v1")
	if proxyURL == nil {
		t.Fatal("proxy = nil, want socks5 proxy")
	}
	if proxyURL.Scheme != "socks5" || proxyURL.Host != "proxy.example:1080" {
		t.Fatalf("proxy = %v, want socks5://proxy.example:1080", proxyURL)
	}
	username := proxyURL.User.Username()
	password, _ := proxyURL.User.Password()
	if username != "user@example.com" || password != "p@ss word" {
		t.Fatalf("proxy credentials = %q/%q", username, password)
	}
}

func TestHTTPClientProviderReusesTransportWithPerClientTimeouts(t *testing.T) {
	provider, err := NewClientProvider(ClientConfig{
		ProxyURL: "http://proxy.example:8080",
		Timeout:  7 * time.Second,
	})
	if err != nil {
		t.Fatalf("NewClientProvider() error = %v", err)
	}
	first := provider.Client(3 * time.Second)
	second := provider.Client(5 * time.Second)
	defaultTimeout := provider.Client(0)
	if first.Transport != second.Transport || first.Transport != defaultTimeout.Transport {
		t.Fatalf("provider clients do not share transport")
	}
	if first.Timeout != 3*time.Second || second.Timeout != 5*time.Second || defaultTimeout.Timeout != 7*time.Second {
		t.Fatalf("timeouts = %v/%v/%v, want 3s/5s/7s", first.Timeout, second.Timeout, defaultTimeout.Timeout)
	}
	proxyURL := proxyForRequest(t, second, "http://service.example/v1")
	if proxyURL == nil || proxyURL.String() != "http://proxy.example:8080" {
		t.Fatalf("proxy = %v, want http://proxy.example:8080", proxyURL)
	}
}

func TestNewHTTPClientRejectsHostWithoutPort(t *testing.T) {
	if _, err := NewClient(ClientConfig{ProxyHost: "proxy.example"}); err == nil {
		t.Fatal("NewClient() error = nil, want missing port error")
	}
}

func TestNewHTTPClientRejectsInvalidProxy(t *testing.T) {
	if _, err := NewClient(ClientConfig{ProxyURL: "proxy.example:8080"}); err == nil {
		t.Fatal("NewClient() error = nil, want invalid proxy error")
	}
}

func TestNewHTTPClientRedactsCredentialsInInvalidProxy(t *testing.T) {
	_, err := NewClient(ClientConfig{ProxyURL: "http://agent:super-secret%zz@proxy.example:8080"})
	if err == nil {
		t.Fatal("NewClient() error = nil, want invalid proxy error")
	}
	if strings.Contains(err.Error(), "super-secret") {
		t.Fatalf("error leaked proxy password: %q", err.Error())
	}
	if strings.Contains(err.Error(), "agent:") {
		t.Fatalf("error leaked proxy userinfo: %q", err.Error())
	}
}

func TestNewHTTPClientRejectsInvalidCACertFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "ca.pem")
	if err := os.WriteFile(path, []byte("not a cert"), 0o600); err != nil {
		t.Fatalf("write cert: %v", err)
	}
	if _, err := NewClient(ClientConfig{CACertFile: path}); err == nil {
		t.Fatal("NewClient() error = nil, want invalid CA cert error")
	}
}

func TestHTTPClientConfigFromEnvAndStandardFallback(t *testing.T) {
	t.Setenv(EnvHTTPProxy, "http://bomly-proxy.example:8080")
	t.Setenv(EnvHTTPNoProxy, "internal.example")
	t.Setenv(EnvHTTPProxyType, "socks5")
	t.Setenv(EnvHTTPProxyHost, "host.example")
	t.Setenv(EnvHTTPProxyPort, "1080")
	t.Setenv(EnvHTTPProxyUsername, "agent")
	t.Setenv(EnvHTTPProxyPassword, "secret")
	t.Setenv(EnvHTTPCACertFile, "/tmp/ca.pem")
	cfg := ClientConfigFromEnv()
	if cfg.ProxyURL != "http://bomly-proxy.example:8080" {
		t.Fatalf("ProxyURL = %q", cfg.ProxyURL)
	}
	if cfg.NoProxy != "internal.example" {
		t.Fatalf("NoProxy = %q", cfg.NoProxy)
	}
	if cfg.ProxyType != "socks5" || cfg.ProxyHost != "host.example" || cfg.ProxyPort != 1080 {
		t.Fatalf("decomposed proxy config = %#v", cfg)
	}
	if cfg.ProxyUsername != "agent" || cfg.ProxyPassword != "secret" || cfg.CACertFile != "/tmp/ca.pem" {
		t.Fatalf("proxy auth/cert config = %#v", cfg)
	}

	t.Setenv(EnvHTTPProxy, "")
	t.Setenv(EnvHTTPNoProxy, "")
	t.Setenv(EnvHTTPProxyType, "")
	t.Setenv(EnvHTTPProxyHost, "")
	t.Setenv(EnvHTTPProxyPort, "")
	t.Setenv(EnvHTTPProxyUsername, "")
	t.Setenv(EnvHTTPProxyPassword, "")
	t.Setenv(EnvHTTPCACertFile, "")
	t.Setenv("HTTP_PROXY", "http://standard-proxy.example:8080")
	client, err := NewClient(ClientConfigFromEnv())
	if err != nil {
		t.Fatalf("NewClient() error = %v", err)
	}
	proxyURL := proxyForRequest(t, client, "http://service.example/v1")
	if proxyURL == nil || proxyURL.String() != "http://standard-proxy.example:8080" {
		t.Fatalf("proxy = %v, want standard env proxy", proxyURL)
	}
}

func proxyForRequest(t *testing.T, client *http.Client, rawURL string) *url.URL {
	t.Helper()
	transport, ok := client.Transport.(*http.Transport)
	if !ok || transport.Proxy == nil {
		t.Fatalf("client transport proxy unavailable")
	}
	req, err := http.NewRequest(http.MethodGet, rawURL, nil)
	if err != nil {
		t.Fatalf("build request: %v", err)
	}
	proxyURL, err := transport.Proxy(req)
	if err != nil {
		t.Fatalf("proxy func error = %v", err)
	}
	return proxyURL
}
