package httpx

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func writeTestCACert(t *testing.T, path, commonName string) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: commonName},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create cert: %v", err)
	}
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	if err := os.WriteFile(path, pemBytes, 0o600); err != nil {
		t.Fatalf("write ca cert: %v", err)
	}
}

func TestSharedTransportCacheHitAndDistinctKeys(t *testing.T) {
	pool := newTransportPool(8)

	tr1, err := pool.get(TransportOpts{})
	if err != nil {
		t.Fatalf("default transport: %v", err)
	}
	tr2, err := pool.get(TransportOpts{})
	if err != nil {
		t.Fatalf("cached default transport: %v", err)
	}
	if tr1 != tr2 {
		t.Fatal("expected identical *http.Transport instance on cache hit")
	}

	trProxy, err := pool.get(TransportOpts{ProxyURL: "http://127.0.0.1:8788"})
	if err != nil {
		t.Fatalf("proxy transport: %v", err)
	}
	if trProxy == tr1 {
		t.Fatal("proxy transport must not alias direct/default transport")
	}

	trInsecure, err := pool.get(TransportOpts{InsecureTLS: true})
	if err != nil {
		t.Fatalf("insecure transport: %v", err)
	}
	if trInsecure == tr1 || trInsecure == trProxy {
		t.Fatal("insecure transport must have its own cache entry")
	}
	if trInsecure.TLSClientConfig == nil || !trInsecure.TLSClientConfig.InsecureSkipVerify {
		t.Fatal("expected InsecureSkipVerify=true on insecure transport")
	}
	if tr1.TLSClientConfig != nil && tr1.TLSClientConfig.InsecureSkipVerify {
		t.Fatal("default transport must not have InsecureSkipVerify mutated")
	}

	caPath := filepath.Join(t.TempDir(), "ca.pem")
	writeTestCACert(t, caPath, "ca-v1")
	trCA1, err := pool.get(TransportOpts{CACertPath: caPath})
	if err != nil {
		t.Fatalf("ca transport v1: %v", err)
	}
	trCA1Again, err := pool.get(TransportOpts{CACertPath: caPath})
	if err != nil {
		t.Fatalf("ca transport v1 cached: %v", err)
	}
	if trCA1 != trCA1Again {
		t.Fatal("expected cache hit for unchanged CA file")
	}

	// Rewriting the CA file with new PEM content must produce a fresh transport.
	writeTestCACert(t, caPath, "ca-v2")
	trCA2, err := pool.get(TransportOpts{CACertPath: caPath})
	if err != nil {
		t.Fatalf("ca transport v2: %v", err)
	}
	if trCA2 == trCA1 {
		t.Fatal("expected cache miss after CA PEM content changed")
	}
}

func TestSharedTransportTimeoutsAndPoolConfig(t *testing.T) {
	tr, err := SharedTransport(TransportOpts{})
	if err != nil {
		t.Fatalf("SharedTransport: %v", err)
	}
	if tr.TLSHandshakeTimeout != 10*time.Second {
		t.Errorf("TLSHandshakeTimeout = %v, want 10s", tr.TLSHandshakeTimeout)
	}
	if tr.ResponseHeaderTimeout != 30*time.Second {
		t.Errorf("ResponseHeaderTimeout = %v, want 30s", tr.ResponseHeaderTimeout)
	}
	if tr.IdleConnTimeout != 60*time.Second {
		t.Errorf("IdleConnTimeout = %v, want 60s", tr.IdleConnTimeout)
	}
	if tr.MaxIdleConns != 128 {
		t.Errorf("MaxIdleConns = %d, want 128", tr.MaxIdleConns)
	}
	if tr.MaxIdleConnsPerHost != 32 {
		t.Errorf("MaxIdleConnsPerHost = %d, want 32", tr.MaxIdleConnsPerHost)
	}
	if !tr.ForceAttemptHTTP2 {
		t.Error("ForceAttemptHTTP2 = false, want true")
	}
	if tr.DialContext == nil {
		t.Error("DialContext must be configured")
	}
}

func TestSharedTransportDisableProxyIgnoresEnvAndProxyURL(t *testing.T) {
	t.Setenv("HTTP_PROXY", "http://127.0.0.1:9999")
	t.Setenv("HTTPS_PROXY", "http://127.0.0.1:9999")

	pool := newTransportPool(8)
	trDirect, err := pool.get(TransportOpts{
		ProxyURL:     "http://127.0.0.1:8788",
		DisableProxy: true,
	})
	if err != nil {
		t.Fatalf("DisableProxy transport: %v", err)
	}
	if trDirect.Proxy != nil {
		t.Fatal("DisableProxy must set Transport.Proxy = nil so env HTTP_PROXY is bypassed")
	}

	// Default (DisableProxy=false, ProxyURL="") should still honor env HTTP_PROXY.
	trEnv, err := pool.get(TransportOpts{})
	if err != nil {
		t.Fatalf("env proxy transport: %v", err)
	}
	if trEnv.Proxy == nil {
		t.Fatal("expected ProxyFromEnvironment on default transport")
	}
	req, _ := http.NewRequest(http.MethodGet, "http://example.com", nil)
	gotProxy, err := trEnv.Proxy(req)
	if err != nil || gotProxy == nil || gotProxy.String() != "http://127.0.0.1:9999" {
		t.Fatalf("default transport proxy = (%v, %v), want http://127.0.0.1:9999", gotProxy, err)
	}

	// Explicit ProxyURL should route through the configured proxy.
	trExplicit, err := pool.get(TransportOpts{ProxyURL: "http://127.0.0.1:8788"})
	if err != nil {
		t.Fatalf("explicit proxy transport: %v", err)
	}
	u, err := trExplicit.Proxy(req)
	if err != nil || u == nil || u.String() != "http://127.0.0.1:8788" {
		t.Fatalf("explicit proxy = (%v, %v), want http://127.0.0.1:8788", u, err)
	}
}

func TestSharedTransportInvalidInputs(t *testing.T) {
	pool := newTransportPool(4)
	if _, err := pool.get(TransportOpts{ProxyURL: "127.0.0.1:8788"}); err == nil {
		t.Error("expected error for schemeless proxy URL")
	}
	if _, err := pool.get(TransportOpts{CACertPath: filepath.Join(t.TempDir(), "missing.pem")}); err == nil {
		t.Error("expected error for missing CA cert file")
	}
	badPEM := filepath.Join(t.TempDir(), "bad.pem")
	if err := os.WriteFile(badPEM, []byte("not-a-cert"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.get(TransportOpts{CACertPath: badPEM}); err == nil {
		t.Error("expected error for invalid PEM content")
	}

	// Invalid proxy URLs containing credentials must never leak them in errors.
	for _, raw := range []string{
		"http://alice:TOPSECRET123@",
		"http://alice:TOPSECRET123@bad host:8080",
		"alice:TOPSECRET123@127.0.0.1:8080",
	} {
		_, err := pool.get(TransportOpts{ProxyURL: raw})
		if err == nil {
			t.Errorf("expected error for invalid proxy URL %q", raw)
			continue
		}
		if strings.Contains(err.Error(), "TOPSECRET123") {
			t.Errorf("invalid proxy URL error leaked credentials: %v", err)
		}
	}
}

func TestSharedTransportCachesCAPEMByStat(t *testing.T) {
	pool := newTransportPool(8)
	caPath := filepath.Join(t.TempDir(), "ca.pem")
	writeTestCACert(t, caPath, "ca-cached-v1")
	// Set mtime beyond the racy-stat settle window (simulating an existing CA on disk).
	past := time.Now().Add(-2 * time.Second)
	if err := os.Chtimes(caPath, past, past); err != nil {
		t.Fatal(err)
	}

	tr1, err := pool.get(TransportOpts{CACertPath: caPath})
	if err != nil {
		t.Fatalf("first get: %v", err)
	}
	for i := 0; i < 10; i++ {
		trNext, err := pool.get(TransportOpts{CACertPath: caPath})
		if err != nil {
			t.Fatalf("cached get #%d: %v", i, err)
		}
		if trNext != tr1 {
			t.Fatalf("cached get #%d returned different transport", i)
		}
	}
	if reads := pool.caReads.Load(); reads != 1 {
		t.Fatalf("CA PEM read from disk %d times across 11 hits, want 1", reads)
	}

	// Updating the CA file (new content + newer mtime) must miss cache and re-read.
	writeTestCACert(t, caPath, "ca-cached-v2-updated")
	tr2, err := pool.get(TransportOpts{CACertPath: caPath})
	if err != nil {
		t.Fatalf("updated get: %v", err)
	}
	if tr2 == tr1 {
		t.Fatal("expected fresh transport after CA cert update")
	}
	if reads := pool.caReads.Load(); reads != 2 {
		t.Fatalf("CA PEM read count = %d after update, want 2", reads)
	}
}

func TestTransportPoolEvictsLRU(t *testing.T) {
	pool := newTransportPool(2)
	trA, err := pool.get(TransportOpts{ProxyURL: "http://127.0.0.1:8001"})
	if err != nil {
		t.Fatal(err)
	}
	trB, err := pool.get(TransportOpts{ProxyURL: "http://127.0.0.1:8002"})
	if err != nil {
		t.Fatal(err)
	}
	// Touch A so B becomes least recently used.
	trAAgain, err := pool.get(TransportOpts{ProxyURL: "http://127.0.0.1:8001"})
	if err != nil || trAAgain != trA {
		t.Fatal("expected A to be cached")
	}
	// Inserting C should evict B, keeping A.
	if _, err := pool.get(TransportOpts{ProxyURL: "http://127.0.0.1:8003"}); err != nil {
		t.Fatal(err)
	}
	if len(pool.entries) != 2 {
		t.Fatalf("pool size = %d, want 2", len(pool.entries))
	}
	trACheck, err := pool.get(TransportOpts{ProxyURL: "http://127.0.0.1:8001"})
	if err != nil || trACheck != trA {
		t.Fatal("expected A to survive LRU eviction")
	}
	trBNew, err := pool.get(TransportOpts{ProxyURL: "http://127.0.0.1:8002"})
	if err != nil {
		t.Fatal(err)
	}
	if trBNew == trB {
		t.Fatal("expected evicted B to be rebuilt as a new transport")
	}
}

type trackingReadCloser struct {
	r      io.Reader
	readN  int
	closed bool
}

func (trc *trackingReadCloser) Read(p []byte) (int, error) {
	n, err := trc.r.Read(p)
	trc.readN += n
	return n, err
}

func (trc *trackingReadCloser) Close() error {
	trc.closed = true
	return nil
}

func TestDrainAndClose(t *testing.T) {
	// Nil safety.
	DrainAndClose(nil)

	// Small body is completely drained and closed.
	small := &trackingReadCloser{r: strings.NewReader("hello")}
	DrainAndClose(small)
	if !small.closed || small.readN != 5 {
		t.Fatalf("small body: closed=%v readN=%d, want true, 5", small.closed, small.readN)
	}

	// Large body is capped at 4 KiB and still closed.
	large := &trackingReadCloser{r: strings.NewReader(strings.Repeat("x", 16*1024))}
	DrainAndClose(large)
	if !large.closed {
		t.Fatal("large body was not closed")
	}
	if large.readN != maxDrainBytes {
		t.Fatalf("large body drained %d bytes, want %d", large.readN, maxDrainBytes)
	}

	// Verify URL helper didn't break with custom proxy schemes.
	if _, err := url.Parse("socks5://127.0.0.1:1080"); err != nil {
		t.Fatal(err)
	}
	if tr, err := SharedTransport(TransportOpts{ProxyURL: fmt.Sprintf("socks5://127.0.0.1:%d", 1080)}); err != nil || tr.Proxy == nil {
		t.Fatalf("socks5 proxy transport failed: tr=%v err=%v", tr, err)
	}
}
