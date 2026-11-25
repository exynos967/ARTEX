package httpx

import (
	"container/list"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

const (
	defaultMaxCachedTransports   = 64
	defaultDialTimeout           = 10 * time.Second
	defaultDialKeepAlive         = 30 * time.Second
	defaultTLSHandshakeTimeout   = 10 * time.Second
	defaultResponseHeaderTimeout = 30 * time.Second
	defaultIdleConnTimeout       = 60 * time.Second
	defaultMaxIdleConns          = 128
	defaultMaxIdleConnsPerHost   = 32
	maxDrainBytes                = 4096
	// caStatSettleWindow avoids the classic "racy stat" window where a file is
	// overwritten with identical length within the same coarse OS mtime tick
	// (~15.6ms on Windows NTFS, ~4ms on Linux jiffy timers).
	caStatSettleWindow = 50 * time.Millisecond
)

// TransportOpts configures a shared pooled *http.Transport.
type TransportOpts struct {
	// ProxyURL routes requests through this proxy (http/https/socks5) when set
	// and DisableProxy is false. Empty falls back to http.ProxyFromEnvironment.
	ProxyURL string
	// CACertPath adds a PEM CA certificate bundle on top of the system trust pool.
	// Ignored when InsecureTLS is true.
	CACertPath string
	// InsecureTLS disables TLS certificate verification.
	InsecureTLS bool
	// DisableProxy forces direct dialing (Transport.Proxy = nil), ignoring both
	// ProxyURL and environment HTTP(S)_PROXY variables.
	DisableProxy bool
	// ResponseHeaderTimeout optionally overrides the default 30s response header
	// timeout (for example, long-running synchronous RPC endpoints). Zero or
	// negative uses the 30s default.
	ResponseHeaderTimeout time.Duration
}

type transportKey struct {
	proxyURL              string
	caCertPath            string
	caCertHash            [sha256.Size]byte
	insecureTLS           bool
	disableProxy          bool
	responseHeaderTimeout time.Duration
}

type cachedTransport struct {
	key transportKey
	tr  *http.Transport
}

type cachedCAPEM struct {
	modTime time.Time
	size    int64
	hash    [sha256.Size]byte
	pem     []byte
}

type transportPool struct {
	mu      sync.Mutex
	maxSize int
	order   *list.List // front = most recently used
	entries map[transportKey]*list.Element

	caMu    sync.Mutex
	caCache map[string]cachedCAPEM
	caReads atomic.Int64 // disk read count for tests/diagnostics
}

func newTransportPool(maxSize int) *transportPool {
	if maxSize <= 0 {
		maxSize = defaultMaxCachedTransports
	}
	return &transportPool{
		maxSize: maxSize,
		order:   list.New(),
		entries: make(map[transportKey]*list.Element, maxSize),
		caCache: make(map[string]cachedCAPEM),
	}
}

var defaultPool = newTransportPool(defaultMaxCachedTransports)

// SharedTransport returns a process-wide cached *http.Transport for opts,
// cloned from http.DefaultTransport with bounded timeouts and connection pool
// limits. Distinct option tuples (including changes to CACertPath PEM content)
// map to distinct cached transports; least-recently-used entries beyond the
// pool cap are evicted with CloseIdleConnections.
func SharedTransport(opts TransportOpts) (*http.Transport, error) {
	return defaultPool.get(opts)
}

func (p *transportPool) get(opts TransportOpts) (*http.Transport, error) {
	key, proxyU, pemData, err := p.prepareTransportKey(opts)
	if err != nil {
		return nil, err
	}

	p.mu.Lock()
	if elem, ok := p.entries[key]; ok {
		p.order.MoveToFront(elem)
		tr := elem.Value.(*cachedTransport).tr
		p.mu.Unlock()
		return tr, nil
	}
	p.mu.Unlock()

	tr, err := buildTransport(key, proxyU, pemData)
	if err != nil {
		return nil, err
	}

	var evicted *http.Transport
	p.mu.Lock()
	if elem, ok := p.entries[key]; ok {
		p.order.MoveToFront(elem)
		existing := elem.Value.(*cachedTransport).tr
		p.mu.Unlock()
		tr.CloseIdleConnections()
		return existing, nil
	}
	elem := p.order.PushFront(&cachedTransport{key: key, tr: tr})
	p.entries[key] = elem
	if p.order.Len() > p.maxSize {
		if oldest := p.order.Back(); oldest != nil {
			p.order.Remove(oldest)
			ct := oldest.Value.(*cachedTransport)
			delete(p.entries, ct.key)
			evicted = ct.tr
		}
	}
	p.mu.Unlock()

	if evicted != nil {
		evicted.CloseIdleConnections()
	}
	return tr, nil
}

func (p *transportPool) loadCACert(caPath string) ([sha256.Size]byte, []byte, error) {
	st, err := os.Stat(caPath)
	if err != nil {
		return [sha256.Size]byte{}, nil, fmt.Errorf("httpx: read CA cert %q: %w", caPath, err)
	}
	modTime := st.ModTime()
	size := st.Size()
	now := time.Now()

	p.caMu.Lock()
	if cached, ok := p.caCache[caPath]; ok && cached.size == size && cached.modTime.Equal(modTime) && now.Sub(modTime) >= caStatSettleWindow {
		p.caMu.Unlock()
		return cached.hash, cached.pem, nil
	}
	p.caMu.Unlock()

	data, err := os.ReadFile(caPath)
	if err != nil {
		return [sha256.Size]byte{}, nil, fmt.Errorf("httpx: read CA cert %q: %w", caPath, err)
	}
	p.caReads.Add(1)
	hash := sha256.Sum256(data)

	p.caMu.Lock()
	if p.caCache == nil {
		p.caCache = make(map[string]cachedCAPEM)
	}
	maxCA := p.maxSize * 2
	if maxCA < 16 {
		maxCA = 16
	}
	if _, exists := p.caCache[caPath]; !exists && len(p.caCache) >= maxCA {
		clear(p.caCache)
	}
	p.caCache[caPath] = cachedCAPEM{
		modTime: modTime,
		size:    size,
		hash:    hash,
		pem:     data,
	}
	p.caMu.Unlock()
	return hash, data, nil
}

func (p *transportPool) prepareTransportKey(opts TransportOpts) (transportKey, *url.URL, []byte, error) {
	hdrTimeout := opts.ResponseHeaderTimeout
	if hdrTimeout <= 0 {
		hdrTimeout = defaultResponseHeaderTimeout
	}
	key := transportKey{
		insecureTLS:           opts.InsecureTLS,
		disableProxy:          opts.DisableProxy,
		responseHeaderTimeout: hdrTimeout,
	}

	var proxyU *url.URL
	if !opts.DisableProxy {
		if raw := strings.TrimSpace(opts.ProxyURL); raw != "" {
			u, err := url.Parse(raw)
			if err != nil || u.Scheme == "" || u.Host == "" {
				return transportKey{}, nil, nil, fmt.Errorf("httpx: invalid proxy URL %q", redactProxyURL(raw))
			}
			key.proxyURL = raw
			proxyU = u
		}
	}

	var pemData []byte
	if !opts.InsecureTLS {
		if caPath := strings.TrimSpace(opts.CACertPath); caPath != "" {
			hash, data, err := p.loadCACert(caPath)
			if err != nil {
				return transportKey{}, nil, nil, err
			}
			key.caCertPath = caPath
			key.caCertHash = hash
			pemData = data
		}
	}
	return key, proxyU, pemData, nil
}

// redactProxyURL masks credentials (user:pass@) in proxy URLs before formatting
// error messages, including malformed URLs that url.Parse rejects.
func redactProxyURL(raw string) string {
	s := strings.TrimSpace(raw)
	if u, err := url.Parse(s); err == nil && u.Scheme != "" && u.Host != "" {
		return u.Redacted()
	}
	prefix := ""
	rest := s
	if idx := strings.Index(s, "://"); idx >= 0 {
		prefix = s[:idx+3]
		rest = s[idx+3:]
	}
	auth := rest
	suffix := ""
	if end := strings.IndexAny(rest, "/?#"); end >= 0 {
		auth = rest[:end]
		suffix = rest[end:]
	}
	if at := strings.LastIndex(auth, "@"); at >= 0 {
		return prefix + "***@" + auth[at+1:] + suffix
	}
	return s
}

func buildTransport(key transportKey, proxyU *url.URL, pemData []byte) (*http.Transport, error) {
	var tr *http.Transport
	if base, ok := http.DefaultTransport.(*http.Transport); ok && base != nil {
		tr = base.Clone()
	} else {
		tr = &http.Transport{}
	}

	tr.DialContext = (&net.Dialer{
		Timeout:   defaultDialTimeout,
		KeepAlive: defaultDialKeepAlive,
	}).DialContext
	tr.TLSHandshakeTimeout = defaultTLSHandshakeTimeout
	tr.ResponseHeaderTimeout = key.responseHeaderTimeout
	tr.IdleConnTimeout = defaultIdleConnTimeout
	tr.MaxIdleConns = defaultMaxIdleConns
	tr.MaxIdleConnsPerHost = defaultMaxIdleConnsPerHost
	tr.ForceAttemptHTTP2 = true

	switch {
	case key.disableProxy:
		tr.Proxy = nil
	case proxyU != nil:
		tr.Proxy = http.ProxyURL(proxyU)
	default:
		tr.Proxy = http.ProxyFromEnvironment
	}

	switch {
	case key.insecureTLS:
		cfg := cloneTLSConfig(tr.TLSClientConfig)
		cfg.InsecureSkipVerify = true
		tr.TLSClientConfig = cfg
	case len(pemData) > 0:
		pool, _ := x509.SystemCertPool()
		if pool == nil {
			pool = x509.NewCertPool()
		}
		if !pool.AppendCertsFromPEM(pemData) {
			return nil, fmt.Errorf("httpx: no valid PEM certificates in %q", key.caCertPath)
		}
		cfg := cloneTLSConfig(tr.TLSClientConfig)
		cfg.RootCAs = pool
		tr.TLSClientConfig = cfg
	}

	return tr, nil
}

func cloneTLSConfig(cfg *tls.Config) *tls.Config {
	if cfg == nil {
		return &tls.Config{}
	}
	return cfg.Clone()
}

// DrainAndClose discards up to 4 KiB of unread response body so the underlying
// HTTP/1.1 connection can return to the keep-alive pool, then closes body.
func DrainAndClose(body io.ReadCloser) {
	if body == nil {
		return
	}
	_, _ = io.Copy(io.Discard, io.LimitReader(body, maxDrainBytes))
	_ = body.Close()
}
