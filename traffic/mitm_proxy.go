package traffic

import (
	"bufio"
	"bytes"
	"container/list"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"log"
	"math/big"
	"net"
	"net/http"
	"net/http/httptrace"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	xproxy "golang.org/x/net/proxy"
)

const (
	// maxConcurrentProxyConns bounds simultaneous proxy client connections so
	// scanner floods cannot exhaust goroutines or file descriptors.
	maxConcurrentProxyConns = 512
	// maxCapturedBody caps request/response bytes buffered in RAM for recording.
	// Larger responses stream directly to the client with zero full-body buffering.
	maxCapturedBody = 1 << 20 // 1 MiB
	// leafCertCacheSize bounds the in-memory MITM leaf certificate LRU cache.
	leafCertCacheSize = 4096
	// passthroughHostCacheSize bounds the fail-open passthrough host LRU cache.
	passthroughHostCacheSize = 4096

	proxyReadHeaderTimeout   = 10 * time.Second
	proxyIdleTimeout         = 60 * time.Second
	proxyTLSHandshakeTimeout = 10 * time.Second
	proxyDialTimeout         = 10 * time.Second
	proxyDialKeepAlive       = 30 * time.Second
	proxyRespHeaderTimeout   = 30 * time.Second
)

// capturedFlow holds one intercepted HTTP exchange ready for async recording.
type capturedFlow struct {
	Request  *capturedRequest
	Response *capturedResponse
}

// capturedRequest stores the request metadata and bounded body snapshot.
type capturedRequest struct {
	Method string
	URL    *url.URL
	Proto  string
	Host   string
	Header http.Header
	Body   []byte
}

// capturedResponse stores the response metadata and bounded body snapshot.
type capturedResponse struct {
	StatusCode int
	Header     http.Header
	Body       []byte
}

// hostLRU is a mutex-protected bounded LRU set of hostnames. Its zero value is
// usable with capacity passthroughHostCacheSize.
type hostLRU struct {
	mu    sync.Mutex
	max   int
	order *list.List
	items map[string]*list.Element
}

func (l *hostLRU) initLocked() {
	if l.max <= 0 {
		l.max = passthroughHostCacheSize
	}
	if l.order == nil {
		l.order = list.New()
		l.items = make(map[string]*list.Element)
	}
}

func (l *hostLRU) Has(host string) bool {
	key := strings.ToLower(strings.TrimSpace(hostOnly(host)))
	if key == "" {
		return false
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.items == nil {
		return false
	}
	elem, ok := l.items[key]
	if !ok {
		return false
	}
	l.order.MoveToFront(elem)
	return true
}

// Add inserts host and returns true if it was newly added (false if already present).
func (l *hostLRU) Add(host string) bool {
	key := strings.ToLower(strings.TrimSpace(hostOnly(host)))
	if key == "" {
		return false
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	l.initLocked()
	if elem, ok := l.items[key]; ok {
		l.order.MoveToFront(elem)
		return false
	}
	elem := l.order.PushFront(key)
	l.items[key] = elem
	for l.order.Len() > l.max {
		oldest := l.order.Back()
		if oldest == nil {
			break
		}
		l.order.Remove(oldest)
		delete(l.items, oldest.Value.(string))
	}
	return true
}

func (l *hostLRU) Len() int {
	l.mu.Lock()
	defer l.mu.Unlock()
	return len(l.items)
}

// singleflightCall deduplicates concurrent leaf certificate generation per host.
type singleflightCall struct {
	wg   sync.WaitGroup
	cert *tls.Certificate
	err  error
}

type certSingleflight struct {
	mu    sync.Mutex
	calls map[string]*singleflightCall
}

func (g *certSingleflight) Do(key string, fn func() (*tls.Certificate, error)) (*tls.Certificate, error) {
	g.mu.Lock()
	if g.calls == nil {
		g.calls = make(map[string]*singleflightCall)
	}
	if c, ok := g.calls[key]; ok {
		g.mu.Unlock()
		c.wg.Wait()
		return c.cert, c.err
	}
	c := &singleflightCall{}
	c.wg.Add(1)
	g.calls[key] = c
	g.mu.Unlock()

	defer func() {
		g.mu.Lock()
		delete(g.calls, key)
		g.mu.Unlock()
		c.wg.Done()
	}()

	c.cert, c.err = fn()
	return c.cert, c.err
}

type certLRUEntry struct {
	host string
	cert *tls.Certificate
}

// mitmCA manages the local MITM root CA on disk and a bounded 4096-entry LRU
// cache of dynamically signed leaf certificates with singleflight deduplication.
type mitmCA struct {
	dir      string
	rootCert *x509.Certificate
	signer   crypto.Signer

	mu      sync.Mutex
	maxSize int
	order   *list.List
	items   map[string]*list.Element
	sf      certSingleflight

	signCount atomic.Int64 // number of leaf certs actually signed (for diagnostics/tests)
}

func loadOrCreateCA(caDir string) (*mitmCA, error) {
	if err := os.MkdirAll(caDir, 0o755); err != nil {
		return nil, fmt.Errorf("create CA dir %s: %w", caDir, err)
	}
	ca := &mitmCA{
		dir:     caDir,
		maxSize: leafCertCacheSize,
		order:   list.New(),
		items:   make(map[string]*list.Element),
	}

	// 1. Existing combined PEM (mitmproxy-ca.pem, preserved for existing installs).
	combinedPath := filepath.Join(caDir, "mitmproxy-ca.pem")
	if cert, signer, err := loadCombinedCA(combinedPath); err == nil {
		ca.rootCert = cert
		ca.signer = signer
		if err := ensureCACertFiles(caDir, cert); err != nil {
			return nil, err
		}
		return ca, nil
	} else if !os.IsNotExist(err) {
		return nil, fmt.Errorf("load %s: %w", combinedPath, err)
	}

	// 2. Separate ca.crt + ca.key format.
	crtPath := filepath.Join(caDir, "ca.crt")
	keyPath := filepath.Join(caDir, "ca.key")
	if cert, signer, err := loadSplitCA(crtPath, keyPath); err == nil {
		ca.rootCert = cert
		ca.signer = signer
		if err := ensureCACertFiles(caDir, cert); err != nil {
			return nil, err
		}
		return ca, nil
	} else if !os.IsNotExist(err) {
		return nil, fmt.Errorf("load ca.crt/ca.key: %w", err)
	}

	// 3. Generate a fresh ECDSA P-256 root CA and persist in compatible formats.
	cert, signer, err := generateRootCA()
	if err != nil {
		return nil, fmt.Errorf("generate root CA: %w", err)
	}
	ca.rootCert = cert
	ca.signer = signer
	if err := saveCAFiles(caDir, cert, signer); err != nil {
		return nil, fmt.Errorf("save root CA: %w", err)
	}
	return ca, nil
}

func loadCombinedCA(path string) (*x509.Certificate, crypto.Signer, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, nil, err
	}
	var cert *x509.Certificate
	var signer crypto.Signer
	for len(raw) > 0 {
		var blk *pem.Block
		blk, raw = pem.Decode(raw)
		if blk == nil {
			break
		}
		switch {
		case blk.Type == "CERTIFICATE" && cert == nil:
			c, err := x509.ParseCertificate(blk.Bytes)
			if err != nil {
				return nil, nil, err
			}
			cert = c
		case strings.Contains(blk.Type, "PRIVATE KEY") && signer == nil:
			s, err := parsePrivateKey(blk.Bytes)
			if err != nil {
				return nil, nil, err
			}
			signer = s
		}
	}
	if cert == nil || signer == nil {
		return nil, nil, fmt.Errorf("incomplete CA bundle in %s", path)
	}
	return cert, signer, nil
}

func loadSplitCA(crtPath, keyPath string) (*x509.Certificate, crypto.Signer, error) {
	certRaw, err := os.ReadFile(crtPath)
	if err != nil {
		return nil, nil, err
	}
	keyRaw, err := os.ReadFile(keyPath)
	if err != nil {
		return nil, nil, err
	}
	certBlk, _ := pem.Decode(certRaw)
	if certBlk == nil {
		return nil, nil, fmt.Errorf("no PEM certificate in %s", crtPath)
	}
	cert, err := x509.ParseCertificate(certBlk.Bytes)
	if err != nil {
		return nil, nil, err
	}
	keyBlk, _ := pem.Decode(keyRaw)
	if keyBlk == nil {
		return nil, nil, fmt.Errorf("no PEM private key in %s", keyPath)
	}
	signer, err := parsePrivateKey(keyBlk.Bytes)
	if err != nil {
		return nil, nil, err
	}
	return cert, signer, nil
}

func parsePrivateKey(der []byte) (crypto.Signer, error) {
	if k, err := x509.ParsePKCS8PrivateKey(der); err == nil {
		if s, ok := k.(crypto.Signer); ok {
			return s, nil
		}
		return nil, errors.New("unsupported PKCS#8 private key type")
	}
	if k, err := x509.ParsePKCS1PrivateKey(der); err == nil {
		return k, nil
	}
	if k, err := x509.ParseECPrivateKey(der); err == nil {
		return k, nil
	}
	return nil, errors.New("unrecognized private key format")
}

func randomSerial() (*big.Int, error) {
	limit := new(big.Int).Lsh(big.NewInt(1), 128)
	n, err := rand.Int(rand.Reader, limit)
	if err != nil {
		return nil, err
	}
	if n.Sign() <= 0 {
		n = big.NewInt(1)
	}
	return n, nil
}

func subjectKeyID(pub crypto.PublicKey) []byte {
	spki, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return nil
	}
	sum := sha1.Sum(spki)
	return sum[:]
}

func generateRootCA() (*x509.Certificate, crypto.Signer, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	serial, err := randomSerial()
	if err != nil {
		return nil, nil, err
	}
	now := time.Now()
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject: pkix.Name{
			CommonName:   "ARTEX MITM CA",
			Organization: []string{"ARTEX"},
		},
		NotBefore:             now.Add(-48 * time.Hour),
		NotAfter:              now.Add(10 * 365 * 24 * time.Hour),
		BasicConstraintsValid: true,
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign | x509.KeyUsageDigitalSignature,
		SubjectKeyId:          subjectKeyID(key.Public()),
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, key.Public(), key)
	if err != nil {
		return nil, nil, err
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, nil, err
	}
	return cert, key, nil
}

func saveCAFiles(caDir string, cert *x509.Certificate, signer crypto.Signer) error {
	keyDER, err := x509.MarshalPKCS8PrivateKey(signer)
	if err != nil {
		return err
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw})

	// Combined PEM (go-mitmproxy compatible) + split ca.key/ca.crt + public cert files.
	combined := append(append([]byte(nil), keyPEM...), certPEM...)
	if err := os.WriteFile(filepath.Join(caDir, "mitmproxy-ca.pem"), combined, 0o600); err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(caDir, "ca.key"), keyPEM, 0o600); err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(caDir, "ca.crt"), certPEM, 0o644); err != nil {
		return err
	}
	return ensureCACertFiles(caDir, cert)
}

func ensureCACertFiles(caDir string, cert *x509.Certificate) error {
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw})
	for _, name := range []string{"mitmproxy-ca-cert.pem", "mitmproxy-ca-cert.cer", "ca.crt"} {
		p := filepath.Join(caDir, name)
		if _, err := os.Stat(p); os.IsNotExist(err) {
			if err := os.WriteFile(p, certPEM, 0o644); err != nil {
				return err
			}
		}
	}
	return nil
}

// GetCert returns a cached or freshly signed leaf certificate for host.
// Concurrent requests for the same host are deduplicated via singleflight.
func (ca *mitmCA) GetCert(host string) (*tls.Certificate, error) {
	key := normalizeCertHost(host)
	if key == "" {
		return nil, errors.New("empty certificate host")
	}

	if cert := ca.getCached(key); cert != nil {
		return cert, nil
	}

	return ca.sf.Do(key, func() (*tls.Certificate, error) {
		if cert := ca.getCached(key); cert != nil {
			return cert, nil
		}
		cert, err := ca.signLeaf(key)
		if err != nil {
			return nil, err
		}
		ca.putCached(key, cert)
		return cert, nil
	})
}

func normalizeCertHost(host string) string {
	h := strings.TrimSpace(hostOnly(host))
	h = strings.Trim(h, "[]")
	h = strings.TrimSuffix(h, ".")
	return strings.ToLower(h)
}

func (ca *mitmCA) getCached(key string) *tls.Certificate {
	ca.mu.Lock()
	defer ca.mu.Unlock()
	elem, ok := ca.items[key]
	if !ok {
		return nil
	}
	entry := elem.Value.(*certLRUEntry)
	if entry.cert.Leaf != nil && time.Now().Add(time.Hour).After(entry.cert.Leaf.NotAfter) {
		ca.order.Remove(elem)
		delete(ca.items, key)
		return nil
	}
	ca.order.MoveToFront(elem)
	return entry.cert
}

func (ca *mitmCA) putCached(key string, cert *tls.Certificate) {
	ca.mu.Lock()
	defer ca.mu.Unlock()
	if elem, ok := ca.items[key]; ok {
		elem.Value.(*certLRUEntry).cert = cert
		ca.order.MoveToFront(elem)
		return
	}
	elem := ca.order.PushFront(&certLRUEntry{host: key, cert: cert})
	ca.items[key] = elem
	for ca.order.Len() > ca.maxSize {
		oldest := ca.order.Back()
		if oldest == nil {
			break
		}
		ca.order.Remove(oldest)
		delete(ca.items, oldest.Value.(*certLRUEntry).host)
	}
}

func (ca *mitmCA) CacheLen() int {
	ca.mu.Lock()
	defer ca.mu.Unlock()
	return len(ca.items)
}

func (ca *mitmCA) signLeaf(host string) (*tls.Certificate, error) {
	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	serial, err := randomSerial()
	if err != nil {
		return nil, err
	}
	now := time.Now()
	cn := host
	if len(cn) > 64 {
		// RFC 5280 caps CommonName at 64 octets; TLS verification uses SANs below.
		cn = ""
	}
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject: pkix.Name{
			CommonName:   cn,
			Organization: []string{"ARTEX"},
		},
		NotBefore:             now.Add(-24 * time.Hour),
		NotAfter:              now.Add(365 * 24 * time.Hour),
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		AuthorityKeyId:        ca.rootCert.SubjectKeyId,
		SubjectKeyId:          subjectKeyID(leafKey.Public()),
	}
	if _, isRSA := ca.signer.(*rsa.PrivateKey); isRSA {
		// Leaf key is ECDSA P-256; SignatureAlgorithm=0 lets x509 pick SHA256WithRSA for the RSA CA.
		tmpl.KeyUsage = x509.KeyUsageDigitalSignature
	}
	if ip := net.ParseIP(host); ip != nil {
		tmpl.IPAddresses = []net.IP{ip}
	} else {
		tmpl.DNSNames = []string{host}
	}

	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca.rootCert, leafKey.Public(), ca.signer)
	if err != nil {
		return nil, err
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, err
	}
	ca.signCount.Add(1)
	return &tls.Certificate{
		Certificate: [][]byte{der},
		PrivateKey:  leafKey,
		Leaf:        leaf,
	}, nil
}

// limitListener caps concurrent accepted TCP connections without leaking slots
// or deadlocking when Close() is called while all slots are in use.
type limitListener struct {
	net.Listener
	sem       chan struct{}
	done      chan struct{}
	closeOnce sync.Once
}

func newLimitListener(ln net.Listener, limit int) *limitListener {
	return &limitListener{
		Listener: ln,
		sem:      make(chan struct{}, limit),
		done:     make(chan struct{}),
	}
}

func (l *limitListener) Accept() (net.Conn, error) {
	select {
	case l.sem <- struct{}{}:
	case <-l.done:
		return nil, net.ErrClosed
	}
	c, err := l.Listener.Accept()
	if err != nil {
		<-l.sem
		return nil, err
	}
	return &limitListenerConn{Conn: c, sem: l.sem}, nil
}

func (l *limitListener) Close() error {
	var err error
	l.closeOnce.Do(func() {
		close(l.done)
		err = l.Listener.Close()
	})
	return err
}

type limitListenerConn struct {
	net.Conn
	sem       chan struct{}
	closeOnce sync.Once
}

func (c *limitListenerConn) Close() error {
	err := c.Conn.Close()
	c.closeOnce.Do(func() {
		<-c.sem
	})
	return err
}

type trackedConn struct {
	conn   net.Conn
	active bool // false when idle waiting for the next keep-alive request in serveMITMTLS
}

// mitmProxy is a pooled stdlib net/http + crypto/tls MITM proxy replacing go-mitmproxy.
type mitmProxy struct {
	addr      string
	ca        *mitmCA
	dialer    *net.Dialer
	transport *http.Transport
	server    *http.Server

	baseCtx    context.Context
	baseCancel context.CancelFunc

	upstreamFn      func() *url.URL
	isPassthroughFn func(host string) bool
	onRecordFn      func(*capturedFlow)
	onErrorFn       func(host string, err error)

	mu        sync.Mutex
	closed    bool
	ln        net.Listener
	boundAddr string

	connMu      sync.Mutex
	activeConns map[net.Conn]*trackedConn
	wg          sync.WaitGroup
}

type mitmProxyConfig struct {
	Addr            string
	CADir           string
	UpstreamFn      func() *url.URL
	IsPassthroughFn func(host string) bool
	OnRecordFn      func(*capturedFlow)
	OnErrorFn       func(host string, err error)
}

func newMITMProxy(cfg mitmProxyConfig) (*mitmProxy, error) {
	ca, err := loadOrCreateCA(cfg.CADir)
	if err != nil {
		return nil, err
	}
	dialer := &net.Dialer{
		Timeout:   proxyDialTimeout,
		KeepAlive: proxyDialKeepAlive,
	}
	baseTr, ok := http.DefaultTransport.(*http.Transport)
	var tr *http.Transport
	if ok {
		tr = baseTr.Clone()
	} else {
		tr = &http.Transport{}
	}
	tr.DialContext = dialer.DialContext
	tr.TLSHandshakeTimeout = proxyTLSHandshakeTimeout
	tr.ResponseHeaderTimeout = proxyRespHeaderTimeout
	tr.IdleConnTimeout = proxyIdleTimeout
	tr.MaxIdleConns = 256
	tr.MaxIdleConnsPerHost = 32
	tr.MaxConnsPerHost = 64
	tr.DisableCompression = true
	tr.TLSClientConfig = &tls.Config{
		InsecureSkipVerify: true, // MITM proxies inspect targets with self-signed/expired certs; session tickets stay enabled.
	}
	upstreamFn := cfg.UpstreamFn
	if upstreamFn == nil {
		upstreamFn = func() *url.URL { return nil }
	}
	tr.Proxy = func(*http.Request) (*url.URL, error) {
		return upstreamFn(), nil
	}

	baseCtx, baseCancel := context.WithCancel(context.Background())
	p := &mitmProxy{
		addr:            cfg.Addr,
		ca:              ca,
		dialer:          dialer,
		transport:       tr,
		baseCtx:         baseCtx,
		baseCancel:      baseCancel,
		upstreamFn:      upstreamFn,
		isPassthroughFn: cfg.IsPassthroughFn,
		onRecordFn:      cfg.OnRecordFn,
		onErrorFn:       cfg.OnErrorFn,
		activeConns:     make(map[net.Conn]*trackedConn),
	}
	p.server = &http.Server{
		Addr:              cfg.Addr,
		Handler:           p,
		ReadHeaderTimeout: proxyReadHeaderTimeout,
		IdleTimeout:       proxyIdleTimeout,
		BaseContext:       func(net.Listener) context.Context { return baseCtx },
		ErrorLog:          log.New(io.Discard, "", 0),
	}
	return p, nil
}

// ListenAddr returns the actual bound TCP address once listening, else the configured addr.
func (p *mitmProxy) ListenAddr() string {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.boundAddr != "" {
		return p.boundAddr
	}
	return p.addr
}

func (p *mitmProxy) CloseIdleConnections() {
	if p != nil && p.transport != nil {
		p.transport.CloseIdleConnections()
	}
}

func (p *mitmProxy) Start() error {
	p.mu.Lock()
	if p.closed {
		p.mu.Unlock()
		return http.ErrServerClosed
	}
	ln, err := net.Listen("tcp", p.addr)
	if err != nil {
		p.mu.Unlock()
		return err
	}
	ll := newLimitListener(ln, maxConcurrentProxyConns)
	p.ln = ll
	p.boundAddr = ln.Addr().String()
	p.mu.Unlock()
	return p.server.Serve(ll)
}

func (p *mitmProxy) Shutdown(ctx context.Context) error {
	p.mu.Lock()
	p.closed = true
	ll := p.ln
	p.mu.Unlock()

	// Interrupt hijacked HTTPS connections currently idle between keep-alive
	// requests immediately, while letting in-flight requests finish gracefully.
	p.closeIdleHijackedConns()

	err := p.server.Shutdown(ctx)
	if ll != nil {
		_ = ll.Close()
	}
	if err == nil {
		done := make(chan struct{})
		go func() {
			p.wg.Wait()
			close(done)
		}()
		select {
		case <-done:
		case <-ctx.Done():
			err = ctx.Err()
		}
	}
	p.baseCancel()
	p.transport.CloseIdleConnections()
	return err
}

func (p *mitmProxy) Close() error {
	p.mu.Lock()
	p.closed = true
	ll := p.ln
	p.mu.Unlock()

	p.baseCancel()
	if ll != nil {
		_ = ll.Close()
	}
	err := p.server.Close()
	p.closeActiveConns()
	p.transport.CloseIdleConnections()
	p.wg.Wait()
	return err
}

func (p *mitmProxy) isClosed() bool {
	p.mu.Lock()
	closed := p.closed
	p.mu.Unlock()
	return closed
}

func (p *mitmProxy) trackConn(c net.Conn) bool {
	p.connMu.Lock()
	defer p.connMu.Unlock()
	p.mu.Lock()
	closed := p.closed
	p.mu.Unlock()
	if closed {
		return false
	}
	p.activeConns[c] = &trackedConn{conn: c, active: true}
	return true
}

func (p *mitmProxy) untrackConn(c net.Conn) {
	p.connMu.Lock()
	delete(p.activeConns, c)
	p.connMu.Unlock()
}

// setConnIdle transitions a tracked hijacked connection between idle (waiting
// for the next keep-alive request) and active (serving a request). When marking
// idle after Shutdown/Close has started, returns false so the loop exits cleanly.
func (p *mitmProxy) setConnIdle(c net.Conn, idle bool) bool {
	p.connMu.Lock()
	defer p.connMu.Unlock()
	if tc, ok := p.activeConns[c]; ok {
		tc.active = !idle
	}
	if idle {
		p.mu.Lock()
		closed := p.closed
		p.mu.Unlock()
		if closed {
			return false
		}
	}
	return true
}

func (p *mitmProxy) closeIdleHijackedConns() {
	p.connMu.Lock()
	var idle []net.Conn
	for _, tc := range p.activeConns {
		if !tc.active {
			idle = append(idle, tc.conn)
		}
	}
	p.connMu.Unlock()
	now := time.Now()
	for _, c := range idle {
		_ = c.SetReadDeadline(now)
		_ = c.Close()
	}
}

func (p *mitmProxy) closeActiveConns() {
	p.connMu.Lock()
	conns := make([]net.Conn, 0, len(p.activeConns))
	for c := range p.activeConns {
		conns = append(conns, c)
	}
	p.connMu.Unlock()
	now := time.Now()
	for _, c := range conns {
		_ = c.SetDeadline(now)
		_ = c.Close()
	}
}

func (p *mitmProxy) isPassthrough(host string) bool {
	if p.isPassthroughFn == nil {
		return false
	}
	return p.isPassthroughFn(host)
}

func (p *mitmProxy) recordFlowAsync(f *capturedFlow) {
	if p.onRecordFn != nil && f != nil {
		p.onRecordFn(f)
	}
}

func (p *mitmProxy) reportError(host string, err error) {
	if p.onErrorFn != nil && err != nil {
		p.onErrorFn(host, err)
	}
}

// ServeHTTP dispatches plain HTTP proxy requests and HTTPS CONNECT tunnels.
func (p *mitmProxy) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodConnect {
		p.handleConnect(w, r)
		return
	}
	p.handleHTTP(w, r)
}

func (p *mitmProxy) handleHTTP(w http.ResponseWriter, r *http.Request) {
	targetURL := cloneURL(r.URL)
	if targetURL.Scheme == "" {
		targetURL.Scheme = "http"
	}
	if targetURL.Host == "" {
		targetURL.Host = r.Host
	}
	if strings.TrimSpace(targetURL.Host) == "" {
		http.Error(w, "bad proxy request: missing host", http.StatusBadRequest)
		return
	}

	if isUpgradeRequest(r) {
		p.handleHTTPUpgrade(w, r, targetURL)
		return
	}

	origHost := strings.TrimSpace(r.Host)
	if origHost == "" {
		origHost = targetURL.Host
	}
	origProto := r.Proto
	if origProto == "" {
		origProto = "HTTP/1.1"
	}
	origReqHeader := r.Header.Clone()

	outReq := r.Clone(r.Context())
	outReq.RequestURI = ""
	outReq.URL = targetURL
	outReq.Host = origHost
	stripHopByHopHeaders(outReq.Header)

	var reqCap boundedBuffer
	reqCap.max = maxCapturedBody
	if r.Body != nil && r.Body != http.NoBody {
		outReq.Body = &teeReadCloser{r: r.Body, dst: &reqCap}
	}

	resp, err := p.transport.RoundTrip(outReq)
	if err != nil {
		p.reportError(targetURL.Hostname(), err)
		http.Error(w, "bad gateway: "+err.Error(), http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()

	origRespHeader := resp.Header.Clone()

	dstHeader := w.Header()
	copyCleanHeaders(dstHeader, resp.Header)
	w.WriteHeader(resp.StatusCode)

	var respCap boundedBuffer
	respCap.max = maxCapturedBody
	flushStream := strings.Contains(strings.ToLower(resp.Header.Get("Content-Type")), "text/event-stream")
	copyErr := streamResponseBody(w, resp.Body, &respCap, flushStream)
	if copyErr != nil {
		return
	}

	p.recordFlowAsync(&capturedFlow{
		Request: &capturedRequest{
			Method: r.Method,
			URL:    targetURL,
			Proto:  origProto,
			Host:   origHost,
			Header: origReqHeader,
			Body:   reqCap.Bytes(),
		},
		Response: &capturedResponse{
			StatusCode: resp.StatusCode,
			Header:     origRespHeader,
			Body:       respCap.Bytes(),
		},
	})
}

func (p *mitmProxy) handleHTTPUpgrade(w http.ResponseWriter, r *http.Request, targetURL *url.URL) {
	hj, ok := w.(http.Hijacker)
	if !ok {
		http.Error(w, "upgrade unsupported", http.StatusInternalServerError)
		return
	}
	targetAddr := ensureHostPort(targetURL.Host, "80")
	dialCtx, cancel := context.WithTimeout(r.Context(), proxyDialTimeout)
	upConn, err := p.dialUpstream(dialCtx, targetAddr)
	cancel()
	if err != nil {
		http.Error(w, "bad gateway: "+err.Error(), http.StatusBadGateway)
		return
	}

	clientConn, bufRW, err := hj.Hijack()
	if err != nil {
		_ = upConn.Close()
		return
	}
	p.wg.Add(1)
	defer p.wg.Done()
	if !p.trackConn(clientConn) {
		_ = clientConn.Close()
		_ = upConn.Close()
		return
	}
	if !p.trackConn(upConn) {
		p.untrackConn(clientConn)
		_ = clientConn.Close()
		_ = upConn.Close()
		return
	}
	defer func() {
		p.untrackConn(upConn)
		p.untrackConn(clientConn)
		_ = upConn.Close()
		_ = clientConn.Close()
	}()

	reqCopy := r.Clone(r.Context())
	reqCopy.RequestURI = ""
	reqCopy.URL = &url.URL{
		Path:     targetURL.Path,
		RawPath:  targetURL.RawPath,
		RawQuery: targetURL.RawQuery,
	}
	if reqCopy.URL.Path == "" {
		reqCopy.URL.Path = "/"
	}
	if reqCopy.Host == "" {
		reqCopy.Host = targetURL.Host
	}
	reqCopy.Header.Del("Proxy-Connection")
	reqCopy.Header.Del("Proxy-Authorization")
	if err := reqCopy.Write(upConn); err != nil {
		return
	}
	var src net.Conn = clientConn
	if bufRW != nil && bufRW.Reader.Buffered() > 0 {
		src = &bufferedConn{Conn: clientConn, r: bufRW.Reader}
	}
	tunnelCopy(p.baseCtx, src, upConn)
}

func (p *mitmProxy) handleConnect(w http.ResponseWriter, r *http.Request) {
	targetAddr := ensureHostPort(r.Host, "443")
	host := hostOnly(targetAddr)
	if host == "" {
		http.Error(w, "bad CONNECT host", http.StatusBadRequest)
		return
	}
	hj, ok := w.(http.Hijacker)
	if !ok {
		http.Error(w, "hijacking not supported", http.StatusInternalServerError)
		return
	}
	clientConn, bufRW, err := hj.Hijack()
	if err != nil {
		return
	}
	p.wg.Add(1)
	defer p.wg.Done()
	if !p.trackConn(clientConn) {
		_ = clientConn.Close()
		return
	}
	defer func() {
		p.untrackConn(clientConn)
		_ = clientConn.Close()
	}()

	if _, err := io.WriteString(clientConn, "HTTP/1.1 200 Connection Established\r\n\r\n"); err != nil {
		return
	}

	var reader *bufio.Reader
	if bufRW != nil && bufRW.Reader != nil {
		reader = bufRW.Reader
	} else {
		reader = bufio.NewReader(clientConn)
	}

	if p.isPassthrough(host) {
		p.servePassthrough(clientConn, reader, targetAddr)
		return
	}

	// Peek first byte to detect TLS ClientHello (0x16); non-TLS traffic falls back
	// transparently to a raw tunnel so non-HTTP protocols over CONNECT still work.
	_ = clientConn.SetReadDeadline(time.Now().Add(proxyTLSHandshakeTimeout))
	firstByte, err := reader.Peek(1)
	_ = clientConn.SetReadDeadline(time.Time{})
	if err != nil {
		return
	}
	if firstByte[0] != 0x16 {
		p.servePassthrough(clientConn, reader, targetAddr)
		return
	}

	wrappedClient := &bufferedConn{Conn: clientConn, r: reader}
	var sniHost string
	tlsCfg := &tls.Config{
		GetCertificate: func(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
			certHost := host
			if s := strings.TrimSpace(hello.ServerName); s != "" {
				certHost = s
				sniHost = s
			}
			return p.ca.GetCert(certHost)
		},
		NextProtos: []string{"http/1.1"},
	}

	tlsConn := tls.Server(wrappedClient, tlsCfg)
	hsCtx, hsCancel := context.WithTimeout(p.baseCtx, proxyTLSHandshakeTimeout)
	hsErr := tlsConn.HandshakeContext(hsCtx)
	hsCancel()
	if hsErr != nil {
		if proxyCausedErr(hsErr) {
			p.reportError(host, hsErr)
		}
		return
	}
	defer tlsConn.Close()

	if sniHost == "" {
		sniHost = host
	}
	p.serveMITMTLS(clientConn, tlsConn, targetAddr, sniHost)
}

func (p *mitmProxy) servePassthrough(clientConn net.Conn, reader *bufio.Reader, targetAddr string) {
	dialCtx, cancel := context.WithTimeout(p.baseCtx, proxyDialTimeout)
	upConn, err := p.dialUpstream(dialCtx, targetAddr)
	cancel()
	if err != nil {
		return
	}
	defer upConn.Close()
	if !p.trackConn(upConn) {
		return
	}
	defer p.untrackConn(upConn)

	var src net.Conn = clientConn
	if reader != nil && reader.Buffered() > 0 {
		src = &bufferedConn{Conn: clientConn, r: reader}
	}
	tunnelCopy(p.baseCtx, src, upConn)
}

func (p *mitmProxy) serveMITMTLS(rawConn net.Conn, tlsConn *tls.Conn, targetAddr, sniHost string) {
	br := bufio.NewReader(tlsConn)
	connCtx, connCancel := context.WithCancel(p.baseCtx)
	defer connCancel()

	for i := 0; ; i++ {
		if connCtx.Err() != nil {
			return
		}
		timeout := proxyIdleTimeout
		if i == 0 {
			timeout = proxyReadHeaderTimeout
		} else {
			// Mark connection idle while waiting for the next keep-alive request so
			// Shutdown(ctx) interrupts idle connections immediately without waiting 5s.
			if !p.setConnIdle(rawConn, true) {
				return
			}
		}
		_ = tlsConn.SetReadDeadline(time.Now().Add(timeout))
		req, err := http.ReadRequest(br)
		_ = tlsConn.SetReadDeadline(time.Time{})
		if err != nil {
			return
		}
		if i > 0 {
			p.setConnIdle(rawConn, false)
		}

		req = req.WithContext(connCtx)
		origHost := strings.TrimSpace(req.Host)
		if origHost == "" {
			origHost = targetAddr
		}
		// Keep targetURL.Host = targetAddr so Transport dials the exact CONNECT
		// destination IP/host & non-default port, while outReq.Host preserves the
		// client's virtual-host Host header (e.g. curl -H "Host: admin.internal" https://10.0.0.5:8443/).
		targetURL := cloneURL(req.URL)
		targetURL.Scheme = "https"
		targetURL.Host = targetAddr

		if isUpgradeRequest(req) {
			p.serveMITMUpgrade(connCtx, tlsConn, br, req, targetAddr, sniHost)
			return
		}

		shouldClose := p.roundTripMITM(tlsConn, req, targetURL, origHost)
		if shouldClose {
			return
		}
	}
}

func (p *mitmProxy) roundTripMITM(tlsConn *tls.Conn, req *http.Request, targetURL *url.URL, origHost string) (shouldClose bool) {
	origProto := req.Proto
	if origProto == "" {
		origProto = "HTTP/1.1"
	}
	origReqHeader := req.Header.Clone()

	outReq := req.Clone(req.Context())
	outReq.RequestURI = ""
	outReq.URL = targetURL
	outReq.Host = origHost
	stripHopByHopHeaders(outReq.Header)

	var reqCap boundedBuffer
	reqCap.max = maxCapturedBody
	var reqBodyTee *teeReadCloser
	hasReqBody := req.Body != nil && req.Body != http.NoBody && (req.ContentLength != 0 || len(req.TransferEncoding) > 0)
	if req.Body != nil && req.Body != http.NoBody {
		reqBodyTee = &teeReadCloser{r: req.Body, dst: &reqCap}
		outReq.Body = reqBodyTee
	}

	var cw *continue100Writer
	if hasExpect100Continue(req.Header) {
		cw = &continue100Writer{w: tlsConn}
		if outReq.Body != nil && outReq.Body != http.NoBody {
			outReq.Body = &continue100ReadCloser{ReadCloser: outReq.Body, cw: cw}
		}
		trace := &httptrace.ClientTrace{
			Got100Continue: cw.send,
		}
		outReq = outReq.WithContext(httptrace.WithClientTrace(outReq.Context(), trace))
	}

	resp, err := p.transport.RoundTrip(outReq)
	if cw != nil {
		cw.finish()
	}
	if err != nil {
		p.reportError(targetURL.Hostname(), err)
		writeRawHTTPError(tlsConn, http.StatusBadGateway, "bad gateway: "+err.Error())
		return true
	}
	defer resp.Body.Close()

	origRespHeader := resp.Header.Clone()
	closeConn := req.Close || resp.Close || !req.ProtoAtLeast(1, 1) || p.isClosed()

	// Guard against HTTP/1.1 keep-alive desync: if the request carried a body
	// that was not fully consumed (e.g. upstream replied 413/401 early without
	// reading req.Body), residual body bytes remain on tlsConn/br so we must
	// close the connection rather than parsing leftover bytes as the next request.
	if hasReqBody && reqBodyTee != nil {
		bodyConsumed := reqBodyTee.eofReached.Load()
		if !bodyConsumed && req.ContentLength > 0 && reqBodyTee.bytesRead.Load() >= req.ContentLength {
			bodyConsumed = true
		}
		if !bodyConsumed {
			closeConn = true
		}
	}

	cleanHdr := make(http.Header, len(resp.Header))
	copyCleanHeaders(cleanHdr, resp.Header)

	var respCap boundedBuffer
	respCap.max = maxCapturedBody

	bodyAllowed := responseBodyAllowed(req.Method, resp.StatusCode)
	isEventStream := strings.Contains(strings.ToLower(resp.Header.Get("Content-Type")), "text/event-stream")
	isChunked := bodyAllowed && resp.ContentLength < 0

	if isEventStream || isChunked {
		if err := writeMITMStreamingResponse(tlsConn, resp, cleanHdr, closeConn, isChunked, bodyAllowed, &respCap); err != nil {
			return true
		}
	} else {
		outResp := *resp
		outResp.Proto = "HTTP/1.1"
		outResp.ProtoMajor = 1
		outResp.ProtoMinor = 1
		outResp.Header = cleanHdr
		outResp.Close = closeConn
		outResp.Request = outReq
		if resp.Body != nil {
			outResp.Body = &teeReadCloser{r: resp.Body, dst: &respCap}
		}
		if err := outResp.Write(tlsConn); err != nil {
			return true
		}
	}

	recordURL := cloneURL(targetURL)
	if strings.HasSuffix(targetURL.Host, ":443") && strings.EqualFold(origHost, hostOnly(targetURL.Host)) {
		recordURL.Host = origHost
	}
	p.recordFlowAsync(&capturedFlow{
		Request: &capturedRequest{
			Method: req.Method,
			URL:    recordURL,
			Proto:  origProto,
			Host:   origHost,
			Header: origReqHeader,
			Body:   reqCap.Bytes(),
		},
		Response: &capturedResponse{
			StatusCode: resp.StatusCode,
			Header:     origRespHeader,
			Body:       respCap.Bytes(),
		},
	})
	return closeConn
}

func (p *mitmProxy) serveMITMUpgrade(ctx context.Context, clientTLS *tls.Conn, br *bufio.Reader, req *http.Request, targetAddr, sniHost string) {
	dialCtx, cancel := context.WithTimeout(ctx, proxyDialTimeout)
	rawUp, err := p.dialUpstream(dialCtx, targetAddr)
	cancel()
	if err != nil {
		writeRawHTTPError(clientTLS, http.StatusBadGateway, "bad gateway: "+err.Error())
		return
	}
	upTLS := tls.Client(rawUp, &tls.Config{
		ServerName:         sniHost,
		InsecureSkipVerify: true,
	})
	hsCtx, hsCancel := context.WithTimeout(ctx, proxyTLSHandshakeTimeout)
	err = upTLS.HandshakeContext(hsCtx)
	hsCancel()
	if err != nil {
		_ = rawUp.Close()
		writeRawHTTPError(clientTLS, http.StatusBadGateway, "upstream tls failed: "+err.Error())
		return
	}
	defer upTLS.Close()
	if !p.trackConn(upTLS) {
		return
	}
	defer p.untrackConn(upTLS)

	if err := req.Write(upTLS); err != nil {
		return
	}
	var src net.Conn = clientTLS
	if br != nil && br.Buffered() > 0 {
		src = &bufferedConn{Conn: clientTLS, r: br}
	}
	tunnelCopy(ctx, src, upTLS)
}

func (p *mitmProxy) dialUpstream(ctx context.Context, targetAddr string) (net.Conn, error) {
	u := p.upstreamFn()
	if u == nil {
		return p.dialer.DialContext(ctx, "tcp", targetAddr)
	}
	switch u.Scheme {
	case "socks5", "socks5h":
		var auth *xproxy.Auth
		if u.User != nil {
			pw, _ := u.User.Password()
			auth = &xproxy.Auth{User: u.User.Username(), Password: pw}
		}
		d, err := xproxy.SOCKS5("tcp", u.Host, auth, p.dialer)
		if err != nil {
			return nil, err
		}
		if cd, ok := d.(xproxy.ContextDialer); ok {
			return cd.DialContext(ctx, "tcp", targetAddr)
		}
		return d.Dial("tcp", targetAddr)

	case "http", "https":
		defaultPort := "80"
		if u.Scheme == "https" {
			defaultPort = "443"
		}
		proxyAddr := ensureHostPort(u.Host, defaultPort)
		conn, err := p.dialer.DialContext(ctx, "tcp", proxyAddr)
		if err != nil {
			return nil, err
		}
		if u.Scheme == "https" {
			tlsConn := tls.Client(conn, &tls.Config{
				ServerName:         hostOnly(u.Host),
				InsecureSkipVerify: true,
			})
			if err := tlsConn.HandshakeContext(ctx); err != nil {
				_ = conn.Close()
				return nil, err
			}
			conn = tlsConn
		}
		if deadline, ok := ctx.Deadline(); ok {
			_ = conn.SetDeadline(deadline)
		}
		var reqBuf strings.Builder
		reqBuf.WriteString("CONNECT ")
		reqBuf.WriteString(targetAddr)
		reqBuf.WriteString(" HTTP/1.1\r\nHost: ")
		reqBuf.WriteString(targetAddr)
		reqBuf.WriteString("\r\n")
		if u.User != nil {
			pw, _ := u.User.Password()
			cred := base64.StdEncoding.EncodeToString([]byte(u.User.Username() + ":" + pw))
			reqBuf.WriteString("Proxy-Authorization: Basic ")
			reqBuf.WriteString(cred)
			reqBuf.WriteString("\r\n")
		}
		reqBuf.WriteString("\r\n")
		if _, err := io.WriteString(conn, reqBuf.String()); err != nil {
			_ = conn.Close()
			return nil, err
		}
		br := bufio.NewReader(conn)
		resp, err := http.ReadResponse(br, &http.Request{Method: http.MethodConnect})
		if err != nil {
			_ = conn.Close()
			return nil, err
		}
		_ = resp.Body.Close()
		_ = conn.SetDeadline(time.Time{})
		if resp.StatusCode != http.StatusOK {
			_ = conn.Close()
			return nil, fmt.Errorf("upstream proxy CONNECT %s: %s", targetAddr, resp.Status)
		}
		if br.Buffered() > 0 {
			return &bufferedConn{Conn: conn, r: br}, nil
		}
		return conn, nil

	default:
		return nil, fmt.Errorf("unsupported upstream proxy scheme %q", u.Scheme)
	}
}

// --- Streaming, header, and socket helpers ---

var copyBufPool = sync.Pool{
	New: func() any {
		b := make([]byte, 32*1024)
		return &b
	},
}

// boundedBuffer records up to max bytes in RAM and silently discards the rest.
type boundedBuffer struct {
	buf bytes.Buffer
	max int
}

func (b *boundedBuffer) Write(p []byte) (int, error) {
	if b.max <= 0 {
		return len(p), nil
	}
	rem := b.max - b.buf.Len()
	if rem > 0 {
		if len(p) <= rem {
			_, _ = b.buf.Write(p)
		} else {
			_, _ = b.buf.Write(p[:rem])
		}
	}
	return len(p), nil
}

func (b *boundedBuffer) Bytes() []byte {
	if b.buf.Len() == 0 {
		return nil
	}
	return b.buf.Bytes()
}

type teeReadCloser struct {
	r          io.ReadCloser
	dst        io.Writer
	eofReached atomic.Bool
	bytesRead  atomic.Int64
}

func (t *teeReadCloser) Read(p []byte) (int, error) {
	n, err := t.r.Read(p)
	if n > 0 {
		t.bytesRead.Add(int64(n))
		if t.dst != nil {
			_, _ = t.dst.Write(p[:n])
		}
	}
	if errors.Is(err, io.EOF) {
		t.eofReached.Store(true)
	}
	return n, err
}

func (t *teeReadCloser) Close() error {
	return t.r.Close()
}

// continue100Writer serializes writing at most one "HTTP/1.1 100 Continue"
// interim response to the client TLS connection before the final response begins.
type continue100Writer struct {
	w    io.Writer
	mu   sync.Mutex
	sent bool
	done bool
}

func (c *continue100Writer) send() {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.done || c.sent {
		return
	}
	c.sent = true
	_, _ = io.WriteString(c.w, "HTTP/1.1 100 Continue\r\n\r\n")
}

func (c *continue100Writer) finish() {
	c.mu.Lock()
	c.done = true
	c.mu.Unlock()
}

type continue100ReadCloser struct {
	io.ReadCloser
	cw *continue100Writer
}

func (r *continue100ReadCloser) Read(p []byte) (int, error) {
	r.cw.send()
	return r.ReadCloser.Read(p)
}

func hasExpect100Continue(h http.Header) bool {
	for _, v := range h.Values("Expect") {
		for _, tok := range strings.Split(v, ",") {
			if strings.EqualFold(strings.TrimSpace(tok), "100-continue") {
				return true
			}
		}
	}
	return false
}

func responseBodyAllowed(method string, status int) bool {
	if method == http.MethodHead {
		return false
	}
	if status >= 100 && status <= 199 {
		return false
	}
	return status != http.StatusNoContent && status != http.StatusNotModified
}

// writeMITMStreamingResponse writes response headers and streams each body read
// directly to w without buffering inside net/http.Response.Write's 4 KiB
// bufio.Writer, so SSE (text/event-stream) and chunked responses flush immediately.
func writeMITMStreamingResponse(w io.Writer, resp *http.Response, cleanHdr http.Header, closeConn, chunked, bodyAllowed bool, capDst io.Writer) error {
	hdr := cleanHdr.Clone()
	if chunked {
		hdr.Del("Content-Length")
	} else if bodyAllowed && resp.ContentLength >= 0 && hdr.Get("Content-Length") == "" {
		hdr.Set("Content-Length", fmt.Sprintf("%d", resp.ContentLength))
	}

	var headBuf bytes.Buffer
	statusText := strings.TrimSpace(resp.Status)
	if statusText == "" {
		statusText = fmt.Sprintf("%d %s", resp.StatusCode, http.StatusText(resp.StatusCode))
	} else if _, rest, ok := strings.Cut(statusText, " "); ok {
		statusText = fmt.Sprintf("%d %s", resp.StatusCode, rest)
	}
	fmt.Fprintf(&headBuf, "HTTP/1.1 %s\r\n", statusText)
	if chunked {
		headBuf.WriteString("Transfer-Encoding: chunked\r\n")
	}
	if closeConn {
		headBuf.WriteString("Connection: close\r\n")
	}
	_ = hdr.Write(&headBuf)
	headBuf.WriteString("\r\n")
	if _, err := w.Write(headBuf.Bytes()); err != nil {
		return err
	}

	if !bodyAllowed {
		return nil
	}
	if resp.Body == nil {
		if chunked {
			_, err := io.WriteString(w, "0\r\n\r\n")
			return err
		}
		return nil
	}

	bp := copyBufPool.Get().(*[]byte)
	buf := *bp
	defer copyBufPool.Put(bp)

	var frameBuf bytes.Buffer
	for {
		n, readErr := resp.Body.Read(buf)
		if n > 0 {
			if capDst != nil {
				_, _ = capDst.Write(buf[:n])
			}
			if chunked {
				frameBuf.Reset()
				fmt.Fprintf(&frameBuf, "%x\r\n", n)
				frameBuf.Write(buf[:n])
				frameBuf.WriteString("\r\n")
				if _, err := w.Write(frameBuf.Bytes()); err != nil {
					return err
				}
			} else {
				if _, err := w.Write(buf[:n]); err != nil {
					return err
				}
			}
		}
		if readErr != nil {
			if errors.Is(readErr, io.EOF) {
				if chunked {
					if len(resp.Trailer) > 0 {
						frameBuf.Reset()
						frameBuf.WriteString("0\r\n")
						_ = resp.Trailer.Write(&frameBuf)
						frameBuf.WriteString("\r\n")
						_, err := w.Write(frameBuf.Bytes())
						return err
					}
					_, err := io.WriteString(w, "0\r\n\r\n")
					return err
				}
				return nil
			}
			return readErr
		}
	}
}

func streamResponseBody(w http.ResponseWriter, src io.Reader, capDst io.Writer, flushEach bool) error {
	bp := copyBufPool.Get().(*[]byte)
	buf := *bp
	defer copyBufPool.Put(bp)
	flusher, _ := w.(http.Flusher)
	for {
		n, readErr := src.Read(buf)
		if n > 0 {
			if capDst != nil {
				_, _ = capDst.Write(buf[:n])
			}
			if _, writeErr := w.Write(buf[:n]); writeErr != nil {
				return writeErr
			}
			if flushEach && flusher != nil {
				flusher.Flush()
			}
		}
		if readErr != nil {
			if errors.Is(readErr, io.EOF) {
				return nil
			}
			return readErr
		}
	}
}

func writeRawHTTPError(w io.Writer, status int, msg string) {
	body := msg + "\n"
	_, _ = fmt.Fprintf(w, "HTTP/1.1 %d %s\r\nContent-Type: text/plain; charset=utf-8\r\nContent-Length: %d\r\nConnection: close\r\n\r\n%s",
		status, http.StatusText(status), len(body), body)
}

var hopByHopHeaders = map[string]struct{}{
	"Connection":          {},
	"Keep-Alive":          {},
	"Proxy-Authenticate":  {},
	"Proxy-Authorization": {},
	"Proxy-Connection":    {},
	"Te":                  {},
	"Trailers":            {},
	"Transfer-Encoding":   {},
	"Upgrade":             {},
}

func stripHopByHopHeaders(h http.Header) {
	for _, connVal := range h.Values("Connection") {
		for _, tok := range strings.Split(connVal, ",") {
			if name := strings.TrimSpace(tok); name != "" {
				h.Del(name)
			}
		}
	}
	for k := range hopByHopHeaders {
		h.Del(k)
	}
}

func copyCleanHeaders(dst, src http.Header) {
	// Collect dynamic Connection-nominated hop-by-hop headers.
	var drop map[string]struct{}
	for _, connVal := range src.Values("Connection") {
		for _, tok := range strings.Split(connVal, ",") {
			if name := http.CanonicalHeaderKey(strings.TrimSpace(tok)); name != "" {
				if drop == nil {
					drop = make(map[string]struct{})
				}
				drop[name] = struct{}{}
			}
		}
	}
	for k, vs := range src {
		ck := http.CanonicalHeaderKey(k)
		if _, isHop := hopByHopHeaders[ck]; isHop {
			continue
		}
		if _, isDyn := drop[ck]; isDyn {
			continue
		}
		dst[k] = append([]string(nil), vs...)
	}
}

func isUpgradeRequest(r *http.Request) bool {
	if strings.TrimSpace(r.Header.Get("Upgrade")) == "" {
		return false
	}
	for _, v := range r.Header.Values("Connection") {
		for _, tok := range strings.Split(v, ",") {
			if strings.EqualFold(strings.TrimSpace(tok), "upgrade") {
				return true
			}
		}
	}
	return false
}

func ensureHostPort(host, defaultPort string) string {
	host = strings.TrimSpace(host)
	if host == "" {
		return ""
	}
	if _, _, err := net.SplitHostPort(host); err == nil {
		return host
	}
	return net.JoinHostPort(strings.Trim(host, "[]"), defaultPort)
}

func cloneURL(u *url.URL) *url.URL {
	if u == nil {
		return &url.URL{}
	}
	cp := *u
	return &cp
}

type bufferedConn struct {
	net.Conn
	r *bufio.Reader
}

func (c *bufferedConn) Read(p []byte) (int, error) {
	return c.r.Read(p)
}

func tunnelCopy(ctx context.Context, a, b net.Conn) {
	if ctx != nil {
		stop := context.AfterFunc(ctx, func() {
			now := time.Now()
			_ = a.SetDeadline(now)
			_ = b.SetDeadline(now)
			_ = a.Close()
			_ = b.Close()
		})
		defer stop()
	}
	var wg sync.WaitGroup
	wg.Add(2)
	pipe := func(dst, src net.Conn) {
		defer wg.Done()
		bp := copyBufPool.Get().(*[]byte)
		_, _ = io.CopyBuffer(dst, src, *bp)
		copyBufPool.Put(bp)
		if cw, ok := dst.(interface{ CloseWrite() error }); ok {
			_ = cw.CloseWrite()
		} else {
			_ = dst.Close()
		}
		if ctx != nil && ctx.Err() != nil {
			now := time.Now()
			_ = dst.SetDeadline(now)
			_ = src.SetDeadline(now)
		}
	}
	go pipe(a, b)
	go pipe(b, a)
	wg.Wait()
}
