package httpkit

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"

	"golang.org/x/net/http/httpproxy"
)

func proxyFunc(config ClientConfig) (func(*http.Request) (*url.URL, error), error) {
	proxyURL, err := resolvedProxyURL(config)
	if err != nil {
		return nil, err
	}
	envProxy := httpproxy.FromEnvironment()
	noProxy := mergeNoProxy(envProxy.NoProxy, config.NoProxy)
	if proxyURL == "" {
		if strings.TrimSpace(config.NoProxy) == "" {
			return http.ProxyFromEnvironment, nil
		}
		envProxy.NoProxy = noProxy
		urlProxy := envProxy.ProxyFunc()
		return func(req *http.Request) (*url.URL, error) {
			return urlProxy(req.URL)
		}, nil
	}
	parsed, err := parseProxyURL(proxyURL)
	if err != nil {
		return nil, err
	}
	if parsed.Scheme == "" || parsed.Host == "" {
		return nil, fmt.Errorf("proxy URL must be absolute")
	}
	urlProxy := (&httpproxy.Config{
		HTTPProxy:  proxyURL,
		HTTPSProxy: proxyURL,
		NoProxy:    noProxy,
	}).ProxyFunc()
	return func(req *http.Request) (*url.URL, error) {
		return urlProxy(req.URL)
	}, nil
}

func mergeNoProxy(standard, bomly string) string {
	entries := make([]string, 0)
	seen := make(map[string]struct{})
	for _, list := range []string{standard, bomly} {
		for entry := range strings.SplitSeq(list, ",") {
			entry = strings.TrimSpace(entry)
			if entry == "" {
				continue
			}
			key := strings.ToLower(entry)
			if _, ok := seen[key]; ok {
				continue
			}
			seen[key] = struct{}{}
			entries = append(entries, entry)
		}
	}
	return strings.Join(entries, ",")
}

func resolvedProxyURL(config ClientConfig) (string, error) {
	if proxyURL := strings.TrimSpace(config.ProxyURL); proxyURL != "" {
		if err := validateProxyURL(proxyURL); err != nil {
			return "", err
		}
		return proxyURL, nil
	}
	if strings.TrimSpace(config.ProxyHost) == "" {
		return "", nil
	}
	if config.ProxyPort <= 0 || config.ProxyPort > 65535 {
		return "", fmt.Errorf("proxy port must be between 1 and 65535")
	}
	scheme, err := proxyScheme(config.ProxyType)
	if err != nil {
		return "", err
	}
	parsed := &url.URL{
		Scheme: scheme,
		Host:   net.JoinHostPort(strings.TrimSpace(config.ProxyHost), strconv.Itoa(config.ProxyPort)),
	}
	username := strings.TrimSpace(config.ProxyUsername)
	if username != "" {
		if config.ProxyPassword != "" {
			parsed.User = url.UserPassword(username, config.ProxyPassword)
		} else {
			parsed.User = url.User(username)
		}
	}
	return parsed.String(), nil
}

func proxyScheme(value string) (string, error) {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "", "http":
		return "http", nil
	case "https":
		return "https", nil
	case "socks", "socks5":
		return "socks5", nil
	default:
		return "", fmt.Errorf("proxy type %q is unsupported (accepted: http, https, socks5)", value)
	}
}

func validateProxyURL(value string) error {
	parsed, err := parseProxyURL(value)
	if err != nil {
		return err
	}
	if parsed.Scheme == "" || parsed.Host == "" {
		return fmt.Errorf("proxy URL must be absolute")
	}
	if _, err := proxyScheme(parsed.Scheme); err != nil {
		return err
	}
	return nil
}

func parseProxyURL(value string) (*url.URL, error) {
	parsed, err := url.Parse(value)
	if err != nil {
		return nil, fmt.Errorf("parse proxy URL: %w", redactURLParseError(err))
	}
	return parsed, nil
}

func redactURLParseError(err error) error {
	if urlErr, ok := errors.AsType[*url.Error](err); ok && urlErr.Err != nil {
		return urlErr.Err
	}
	return err
}

func tlsConfigWithCACert(path string) (*tls.Config, error) {
	data, err := os.ReadFile(strings.TrimSpace(path))
	if err != nil {
		return nil, fmt.Errorf("read HTTP CA certificate file: %w", err)
	}
	pool, err := x509.SystemCertPool()
	if err != nil {
		pool = x509.NewCertPool()
	}
	if pool == nil {
		pool = x509.NewCertPool()
	}
	if ok := pool.AppendCertsFromPEM(data); !ok {
		return nil, fmt.Errorf("HTTP CA certificate file does not contain any PEM certificates")
	}
	return &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12}, nil
}
