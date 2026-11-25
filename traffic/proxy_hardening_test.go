package traffic

import (
	"bufio"
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// startHardeningProxy starts a live MITM proxy on a free loopback port and
// returns both the Traffic instance and an *http.Client that strictly verifies
// HTTPS leaf certificates against the proxy's on-disk CA (no InsecureSkipVerify).
func startHardeningProxy(t *testing.T) (*Traffic, *http.Client) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := ln.Addr().String()
	_ = ln.Close()

	tr, err := Open(t.TempDir(), addr)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = tr.Close() })

	startErr := make(chan error, 1)
	go func() { startErr <- tr.Start() }()

	deadline := time.Now().Add(3 * time.Second)
	for {
		c, dialErr := net.DialTimeout("tcp", addr, 50*time.Millisecond)
		if dialErr == nil {
			_ = c.Close()
			break
		}
		select {
		case err := <-startErr:
			t.Fatalf("proxy Start failed: %v", err)
		default:
		}
		if time.Now().After(deadline) {
			t.Fatal("proxy did not start listening")
		}
		time.Sleep(time.Millisecond)
	}

	caPEM, err := os.ReadFile(tr.CACertPath())
	if err != nil {
		t.Fatalf("read proxy CA %s: %v", tr.CACertPath(), err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(caPEM) {
		t.Fatal("failed to parse proxy CA PEM")
	}

	proxyURL, err := url.Parse(tr.ProxyAddr())
	if err != nil {
		t.Fatal(err)
	}
	transport := &http.Transport{
		Proxy:           http.ProxyURL(proxyURL),
		TLSClientConfig: &tls.Config{RootCAs: pool},
	}
	t.Cleanup(transport.CloseIdleConnections)
	return tr, &http.Client{Transport: transport, Timeout: 10 * time.Second}
}

// TestProxyConcurrentHTTPAndHTTPSWhileDeletingHost verifies that 50 concurrent
// HTTP + HTTPS MITM requests complete cleanly without blocking or deadlocking
// while DeleteHost runs concurrently.
func TestProxyConcurrentHTTPAndHTTPSWhileDeletingHost(t *testing.T) {
	httpTarget := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = fmt.Fprintf(w, `{"scheme":"http","path":%q}`, r.URL.Path)
	}))
	defer httpTarget.Close()

	httpsTarget := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = fmt.Fprintf(w, `{"scheme":"https","path":%q}`, r.URL.Path)
	}))
	defer httpsTarget.Close()

	tr, client := startHardeningProxy(t)

	// Seed another host so DeleteHost performs real index + FTS + GC work.
	for i := 0; i < 20; i++ {
		tr.record(newFlow("delete-me.example", "GET", fmt.Sprintf("/old/%d", i), nil,
			[]byte(strings.Repeat("delete-payload-", 200))))
	}

	const perScheme = 25 // 50 concurrent requests total
	var wg sync.WaitGroup
	var errCount atomic.Int64

	stopDel := make(chan struct{})
	delDone := make(chan struct{})
	go func() {
		defer close(delDone)
		for {
			select {
			case <-stopDel:
				return
			default:
				_, _ = tr.DeleteHost("delete-me.example")
				time.Sleep(2 * time.Millisecond)
			}
		}
	}()

	for i := 0; i < perScheme; i++ {
		idx := i
		wg.Add(2)
		go func() {
			defer wg.Done()
			resp, err := client.Get(fmt.Sprintf("%s/http/%d", httpTarget.URL, idx))
			if err != nil {
				errCount.Add(1)
				t.Errorf("HTTP #%d failed: %v", idx, err)
				return
			}
			body, _ := io.ReadAll(resp.Body)
			resp.Body.Close()
			if resp.StatusCode != 200 || !strings.Contains(string(body), fmt.Sprintf("/http/%d", idx)) {
				errCount.Add(1)
				t.Errorf("HTTP #%d unexpected: status=%d body=%q", idx, resp.StatusCode, body)
			}
		}()
		go func() {
			defer wg.Done()
			resp, err := client.Get(fmt.Sprintf("%s/https/%d", httpsTarget.URL, idx))
			if err != nil {
				errCount.Add(1)
				t.Errorf("HTTPS #%d failed: %v", idx, err)
				return
			}
			body, _ := io.ReadAll(resp.Body)
			resp.Body.Close()
			if resp.StatusCode != 200 || !strings.Contains(string(body), fmt.Sprintf("/https/%d", idx)) {
				errCount.Add(1)
				t.Errorf("HTTPS #%d unexpected: status=%d body=%q", idx, resp.StatusCode, body)
			}
		}()
	}

	wg.Wait()
	close(stopDel)
	<-delDone

	if errCount.Load() != 0 {
		t.Fatalf("concurrent proxy requests had %d errors", errCount.Load())
	}

	waitFlushedCount(t, tr, perScheme*2)
	if tr.DroppedFlows() != 0 {
		t.Fatalf("unexpected dropped flows: %d", tr.DroppedFlows())
	}

	rows, err := tr.Search("127.0.0.1", 0, 100)
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != perScheme*2 {
		t.Fatalf("recorded %d exchanges, want %d", len(rows), perScheme*2)
	}
}

// waitFlushedCount waits for the proxy handler goroutines to finish enqueueing
// their exchanges after the client reads response EOF, then flushes the async
// writer until at least want exchanges are persisted.
func waitFlushedCount(t *testing.T, tr *Traffic, want int) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		err := tr.Flush(ctx)
		cancel()
		if err != nil {
			t.Fatalf("Flush: %v", err)
		}
		n, err := tr.Count()
		if err != nil {
			t.Fatalf("Count: %v", err)
		}
		if n >= want {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("after flush Count=%d, want >= %d", n, want)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// TestProxyResponseNeverBlocksOnWriteLock proves that holding t.wmu (e.g.,
// during a slow DeleteAll/VACUUM) does not stall HTTP or HTTPS proxy responses.
func TestProxyResponseNeverBlocksOnWriteLock(t *testing.T) {
	httpTarget := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, "fast-http-ok")
	}))
	defer httpTarget.Close()

	httpsTarget := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, "fast-https-ok")
	}))
	defer httpsTarget.Close()

	tr, client := startHardeningProxy(t)

	// Hold wmu exclusively to simulate DeleteAll / VACUUM / heavy DB lock.
	tr.wmu.Lock()
	unlocked := false
	defer func() {
		if !unlocked {
			tr.wmu.Unlock()
		}
	}()

	start := time.Now()
	for _, u := range []string{httpTarget.URL + "/unlocked-path", httpsTarget.URL + "/unlocked-tls"} {
		resp, err := client.Get(u)
		if err != nil {
			t.Fatalf("request %s blocked or failed while wmu held: %v", u, err)
		}
		_, _ = io.ReadAll(resp.Body)
		resp.Body.Close()
		if resp.StatusCode != 200 {
			t.Fatalf("unexpected status %d for %s", resp.StatusCode, u)
		}
	}
	if elapsed := time.Since(start); elapsed > 2*time.Second {
		t.Fatalf("proxy responses took %v while wmu was held (head-of-line blocking)", elapsed)
	}

	tr.wmu.Unlock()
	unlocked = true

	waitFlushedCount(t, tr, 2)
	if n, err := tr.Count(); err != nil || n != 2 {
		t.Fatalf("after flush Count=(%d,%v), want (2,nil)", n, err)
	}
}

// TestSelfLoopProxyURLRejection verifies ValidateProxyURLForSelf and
// SetUpstreamProxy reject self-targeting URLs across loopback/wildcard forms.
func TestSelfLoopProxyURLRejection(t *testing.T) {
	rejectCases := []struct {
		self string
		raw  string
	}{
		{"127.0.0.1:8788", "http://127.0.0.1:8788"},
		{"127.0.0.1:8788", "http://localhost:8788"},
		{"127.0.0.1:8788", "http://LOCALHOST.:8788"},
		{"127.0.0.1:8788", "http://[::1]:8788"},
		{"127.0.0.1:8788", "http://[::ffff:127.0.0.1]:8788"},
		{"127.0.0.1:8788", "http://0.0.0.0:8788"},
		{"127.0.0.1:8788", "socks5://127.0.0.1:8788"},
		{"127.0.0.1:8788", "https://localhost:8788"},
		{"127.0.0.1:8788", "http://user:topsecret@localhost:8788"},
		{":8788", "http://127.0.0.1:8788"},
		{":8788", "http://localhost:8788"},
		{":8788", "http://[::1]:8788"},
		{"0.0.0.0:8788", "http://127.0.0.1:8788"},
		{"[::]:8788", "http://localhost:8788"},
		{"http://127.0.0.1:8788", "http://localhost:8788"},
	}
	for _, tc := range rejectCases {
		_, err := ValidateProxyURLForSelf(tc.raw, tc.self)
		if err == nil {
			t.Errorf("ValidateProxyURLForSelf(%q, %q) = nil, want self-loop error", tc.raw, tc.self)
			continue
		}
		if strings.Contains(err.Error(), "topsecret") {
			t.Errorf("ValidateProxyURLForSelf(%q, %q) leaked credential in error: %v", tc.raw, tc.self, err)
		}
	}

	allowCases := []struct {
		self string
		raw  string
	}{
		{"127.0.0.1:8788", "http://127.0.0.1:8080"},
		{"127.0.0.1:8788", "http://localhost:9000"},
		{"127.0.0.1:8788", "http://10.0.0.5:8788"},
		{"127.0.0.1:8788", "socks5://10.0.0.5:1080"},
		{"", "http://127.0.0.1:8788"},
		{"127.0.0.1:0", "http://127.0.0.1:8788"},
	}
	for _, tc := range allowCases {
		if _, err := ValidateProxyURLForSelf(tc.raw, tc.self); err != nil {
			t.Errorf("ValidateProxyURLForSelf(%q, %q) unexpected error: %v", tc.raw, tc.self, err)
		}
	}

	// Live proxy SetUpstreamProxy must reject its own listening port and keep upstream untouched.
	tr, _ := startHardeningProxy(t)
	_, port, err := net.SplitHostPort(tr.effectiveListenAddr())
	if err != nil {
		t.Fatal(err)
	}
	for _, selfURL := range []string{
		"http://127.0.0.1:" + port,
		"http://localhost:" + port,
		"http://[::1]:" + port,
		"http://0.0.0.0:" + port,
	} {
		if err := tr.SetUpstreamProxy(selfURL); err == nil {
			t.Fatalf("SetUpstreamProxy(%q) succeeded, expected self-loop rejection", selfURL)
		}
		if tr.upstream.Load() != nil {
			t.Fatalf("rejected self-loop mutated upstream to %v", tr.upstream.Load())
		}
	}
}

// TestLargeResponseBodyStreamsCleanlyWithBoundedCapture verifies responses > 1 MiB
// arrive completely intact at the client over both HTTP and HTTPS while recorded
// memory/storage is capped at maxCapturedBody (1 MiB).
func TestLargeResponseBodyStreamsCleanlyWithBoundedCapture(t *testing.T) {
	const totalSize = 2*1024*1024 + 512*1024 // 2.5 MiB
	payload := make([]byte, totalSize)
	for i := range payload {
		payload[i] = byte('A' + (i % 26))
	}
	wantSum := sha256.Sum256(payload)

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		// Stream in chunks to also exercise chunked / streaming paths.
		for off := 0; off < len(payload); off += 64 * 1024 {
			end := off + 64*1024
			if end > len(payload) {
				end = len(payload)
			}
			_, _ = w.Write(payload[off:end])
		}
	})
	httpTarget := httptest.NewServer(handler)
	defer httpTarget.Close()
	httpsTarget := httptest.NewTLSServer(handler)
	defer httpsTarget.Close()

	tr, client := startHardeningProxy(t)

	for _, tc := range []struct {
		name string
		url  string
	}{
		{"HTTP", httpTarget.URL + "/large.txt"},
		{"HTTPS", httpsTarget.URL + "/large.txt"},
	} {
		resp, err := client.Get(tc.url)
		if err != nil {
			t.Fatalf("%s GET failed: %v", tc.name, err)
		}
		got, err := io.ReadAll(resp.Body)
		resp.Body.Close()
		if err != nil {
			t.Fatalf("%s read body: %v", tc.name, err)
		}
		if len(got) != totalSize {
			t.Fatalf("%s client got %d bytes, want %d (response truncated!)", tc.name, len(got), totalSize)
		}
		if sha256.Sum256(got) != wantSum {
			t.Fatalf("%s client body checksum mismatch", tc.name)
		}
	}

	waitFlushedCount(t, tr, 2)

	rows, err := tr.Search("127.0.0.1", 0, 10)
	if err != nil || len(rows) != 2 {
		t.Fatalf("recorded rows=%d err=%v, want 2", len(rows), err)
	}
	for _, r := range rows {
		if r.RespLen != maxCapturedBody {
			t.Fatalf("exchange %s (%s) resp_len=%d, want capped %d", r.ID, r.URL, r.RespLen, maxCapturedBody)
		}
		var hash string
		if err := tr.DB().QueryRow(`SELECT resp_blob FROM exchange_bodies WHERE id=?`, r.ID).Scan(&hash); err != nil {
			t.Fatalf("read resp_blob for %s: %v", r.ID, err)
		}
		f, size, err := tr.Blob(hash)
		if err != nil {
			t.Fatalf("open blob %s: %v", hash, err)
		}
		_ = f.Close()
		if size != maxCapturedBody {
			t.Fatalf("spilled blob size=%d, want %d", size, maxCapturedBody)
		}
	}
}

// TestStaticAssetsSkipBodyIndexingKeepURLAndHeadersSearchable verifies that
// static asset extensions (.js/.css/.png/...) and binary content-types omit
// response bodies from ex_fts while keeping URLs and headers searchable.
func TestStaticAssetsSkipBodyIndexingKeepURLAndHeadersSearchable(t *testing.T) {
	tr, _ := openTraffic(t)
	if !tr.fts {
		t.Skip("FTS5 unavailable")
	}
	const host = "assets.example.com"

	jsFlow := newFlow(host, "GET", "/static/bundle-alpha-99.js?v=123", nil,
		[]byte(`console.log("UNIQUE_JS_SECRET_TOKEN_12345");`),
		withRespType("application/javascript; charset=utf-8"))
	jsFlow.Response.Header.Set("X-Asset-Tag", "asset-header-marker")
	tr.record(jsFlow)

	cssFlow := newFlow(host, "GET", "/static/theme-main.css", nil,
		[]byte(`body { content: "UNIQUE_CSS_SECRET_TOKEN"; }`),
		withRespType("text/css"))
	tr.record(cssFlow)

	imgFlow := newFlow(host, "GET", "/media/avatar.webp", nil,
		[]byte("UNIQUE_WEBP_SECRET_TOKEN"),
		withRespType("image/webp"))
	tr.record(imgFlow)

	apiFlow := newFlow(host, "GET", "/api/v1/profile", nil,
		[]byte(`{"secret":"UNIQUE_API_SECRET_TOKEN"}`),
		withRespType("application/json"))
	tr.record(apiFlow)

	// Static/binary response bodies must NOT appear in ex_fts.
	for _, secret := range []string{"UNIQUE_JS_SECRET_TOKEN_12345", "UNIQUE_CSS_SECRET_TOKEN", "UNIQUE_WEBP_SECRET_TOKEN"} {
		hits, err := tr.query(host, "", secret, 0, 10)
		if err != nil {
			t.Fatal(err)
		}
		if len(hits) != 0 {
			t.Fatalf("static asset body term %q matched %d rows in ex_fts, want 0", secret, len(hits))
		}
	}

	// URL and response headers of static assets MUST remain searchable in ex_fts!
	for _, metaTerm := range []string{"bundle-alpha-99.js", "asset-header-marker", "theme-main.css", "avatar.webp"} {
		hits, err := tr.query(host, "", metaTerm, 0, 10)
		if err != nil {
			t.Fatal(err)
		}
		if len(hits) != 1 {
			t.Fatalf("static asset URL/header term %q matched %d rows, want 1", metaTerm, len(hits))
		}
	}

	// Normal API JSON response body IS indexed as usual.
	hits, err := tr.query(host, "", "UNIQUE_API_SECRET_TOKEN", 0, 10)
	if err != nil || len(hits) != 1 {
		t.Fatalf("API body search hits=%d err=%v, want 1", len(hits), err)
	}

	// Raw capture of the .js file is still intact via Get().
	jsHits, err := tr.query(host, "bundle-alpha-99.js", "", 0, 10)
	if err != nil || len(jsHits) != 1 {
		t.Fatalf("lookup js exchange: %d %v", len(jsHits), err)
	}
	_, resp, err := tr.Get(jsHits[0].ID)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(resp, "UNIQUE_JS_SECRET_TOKEN_12345") {
		t.Fatalf("raw .js body missing from Get(): %q", resp)
	}
}

// TestCleanIndexTextSinglePass checks cleanIndexText handles clean UTF-8,
// NUL bytes, and invalid UTF-8 sequences identically to ToValidUTF8 + ReplaceAll.
func TestCleanIndexTextSinglePass(t *testing.T) {
	clean := "GET /api/测试 HTTP/1.1\n{\"ok\":true}"
	if got := cleanIndexText(clean); got != clean {
		t.Fatalf("clean string modified: %q", got)
	}
	dirty := "abc\x00def" + string([]byte{0xff, 0xfe}) + "中文\x00\x80end"
	want := strings.ReplaceAll(strings.ToValidUTF8(dirty, "\uFFFD"), "\x00", "\uFFFD")
	if got := cleanIndexText(dirty); got != want {
		t.Fatalf("cleanIndexText mismatch:\n got=%q\nwant=%q", got, want)
	}
}

// TestAsyncQueueDropOnFullDoesNotStallProxy verifies that when the bounded
// async queue (1024) fills up while persistence is paused, proxy responses
// still complete immediately and droppedFlows increments.
func TestAsyncQueueDropOnFullDoesNotStallProxy(t *testing.T) {
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, "ok")
	}))
	defer target.Close()

	tr, client := startHardeningProxy(t)

	// Block ingestLoop's DB commit by holding wmu.
	tr.wmu.Lock()
	unlocked := false
	defer func() {
		if !unlocked {
			tr.wmu.Unlock()
		}
	}()

	// Enqueue one flow so ingestLoop pulls it and blocks on wmu.
	tr.enqueueFlow(newFlow("fill.example", "GET", "/seed", nil, []byte("seed")))
	// Wait briefly until ingestLoop has picked up the seed item and paused on wmu.
	time.Sleep(20 * time.Millisecond)

	// Flood past ingestQueueCap (1024).
	for i := 0; i < ingestQueueCap+200; i++ {
		tr.enqueueFlow(newFlow("fill.example", "GET", fmt.Sprintf("/flood/%d", i), nil, []byte("x")))
	}
	if tr.DroppedFlows() == 0 {
		t.Fatal("expected droppedFlows > 0 when ingest queue is saturated")
	}

	// Live HTTP request through the proxy MUST NOT stall even though queue is 100% full.
	droppedBefore := tr.DroppedFlows()
	start := time.Now()
	resp, err := client.Get(target.URL + "/must-not-stall")
	if err != nil {
		t.Fatalf("live proxy request failed when ingestCh full: %v", err)
	}
	_, _ = io.ReadAll(resp.Body)
	resp.Body.Close()
	if time.Since(start) > 2*time.Second {
		t.Fatalf("live proxy request stalled for %v on full queue", time.Since(start))
	}
	if tr.DroppedFlows() <= droppedBefore {
		t.Fatalf("expected live request to drop cleanly on full queue: before=%d after=%d", droppedBefore, tr.DroppedFlows())
	}

	// Release lock and confirm remaining buffered items flush cleanly.
	tr.wmu.Unlock()
	unlocked = true

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := tr.Flush(ctx); err != nil {
		t.Fatalf("Flush after full queue: %v", err)
	}
}

// TestLeafCertCacheSingleflightAndLRU verifies concurrent GetCert calls for the
// same host sign only once, SAN DNS/IP verification works, LRU eviction bounds
// memory, and both RSA mitmproxy-ca.pem and split ca.crt/ca.key CAs load cleanly.
func TestLeafCertCacheSingleflightAndLRU(t *testing.T) {
	caDir := filepath.Join(t.TempDir(), "_ca")
	ca, err := loadOrCreateCA(caDir)
	if err != nil {
		t.Fatal(err)
	}

	// Verify CA cert files written on disk.
	for _, f := range []string{"mitmproxy-ca.pem", "mitmproxy-ca-cert.pem", "ca.crt", "ca.key"} {
		if _, err := os.Stat(filepath.Join(caDir, f)); err != nil {
			t.Fatalf("expected CA file %s: %v", f, err)
		}
	}

	// 32 concurrent GetCert calls for the same host -> singleflight signs only once!
	const workers = 32
	certs := make([]*tls.Certificate, workers)
	var wg sync.WaitGroup
	for i := 0; i < workers; i++ {
		idx := i
		wg.Add(1)
		go func() {
			defer wg.Done()
			c, err := ca.GetCert("SingleFlight.Example.COM:443")
			if err != nil {
				t.Errorf("GetCert #%d: %v", idx, err)
				return
			}
			certs[idx] = c
		}()
	}
	wg.Wait()

	if got := ca.signCount.Load(); got != 1 {
		t.Fatalf("signCount=%d after %d concurrent calls for same host, want 1", got, workers)
	}
	for i := 1; i < workers; i++ {
		if certs[i] != certs[0] {
			t.Fatalf("worker %d received distinct cert pointer instead of cached/deduplicated cert", i)
		}
	}

	// Verify DNS SAN and IP SAN against root CA.
	pool := x509.NewCertPool()
	pool.AddCert(ca.rootCert)
	if _, err := certs[0].Leaf.Verify(x509.VerifyOptions{DNSName: "singleflight.example.com", Roots: pool}); err != nil {
		t.Fatalf("DNS leaf cert failed verification: %v", err)
	}
	ipCert, err := ca.GetCert("127.0.0.1")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ipCert.Leaf.Verify(x509.VerifyOptions{DNSName: "127.0.0.1", Roots: pool}); err != nil {
		t.Fatalf("IP leaf cert failed verification: %v", err)
	}

	// Test LRU eviction with small cap.
	ca.maxSize = 4
	for i := 0; i < 8; i++ {
		if _, err := ca.GetCert(fmt.Sprintf("host-%d.example.com", i)); err != nil {
			t.Fatal(err)
		}
	}
	if ca.CacheLen() != 4 {
		t.Fatalf("CacheLen=%d, want 4", ca.CacheLen())
	}

	// Test loading a legacy RSA mitmproxy-ca.pem (go-mitmproxy compatibility).
	legacyDir := filepath.Join(t.TempDir(), "_ca")
	if err := os.MkdirAll(legacyDir, 0o755); err != nil {
		t.Fatal(err)
	}
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(42),
		Subject:               pkix.Name{CommonName: "mitmproxy"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		BasicConstraintsValid: true,
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &rsaKey.PublicKey, rsaKey)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, _ := x509.MarshalPKCS8PrivateKey(rsaKey)
	combined := append(
		pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}),
		pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})...,
	)
	if err := os.WriteFile(filepath.Join(legacyDir, "mitmproxy-ca.pem"), combined, 0o600); err != nil {
		t.Fatal(err)
	}
	loadedRSA, err := loadOrCreateCA(legacyDir)
	if err != nil {
		t.Fatalf("load legacy RSA mitmproxy-ca.pem: %v", err)
	}
	leafFromRSA, err := loadedRSA.GetCert("legacy-rsa.example.com")
	if err != nil {
		t.Fatalf("sign leaf with legacy RSA CA: %v", err)
	}
	rsaPool := x509.NewCertPool()
	rsaPool.AddCert(loadedRSA.rootCert)
	if _, err := leafFromRSA.Leaf.Verify(x509.VerifyOptions{DNSName: "legacy-rsa.example.com", Roots: rsaPool}); err != nil {
		t.Fatalf("leaf signed by legacy RSA CA failed verification: %v", err)
	}
}

// TestPassthroughHostLRUBoundedAndLiveTunnel checks that t.pass is bounded to
// 4096 hosts and that flagged hosts are transparently tunneled without MITM.
func TestPassthroughHostLRUBoundedAndLiveTunnel(t *testing.T) {
	tr := &Traffic{}
	for i := 0; i < passthroughHostCacheSize+200; i++ {
		tr.pass.Add(fmt.Sprintf("host-%d.example.com", i))
	}
	if got := tr.pass.Len(); got != passthroughHostCacheSize {
		t.Fatalf("pass LRU len=%d, want %d", got, passthroughHostCacheSize)
	}
	if tr.isPassthrough("host-0.example.com") {
		t.Fatal("oldest host should have been evicted from passthrough LRU")
	}
	if !tr.isPassthrough(fmt.Sprintf("host-%d.example.com", passthroughHostCacheSize+199)) {
		t.Fatal("newest host should remain in passthrough LRU")
	}

	// Live transparent HTTPS passthrough: client trusts ONLY target's real cert
	// (NOT MITM CA), so the request can only succeed if the proxy truly tunnels.
	target := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, "direct-tls-ok")
	}))
	defer target.Close()

	liveTr, _ := startHardeningProxy(t)
	liveTr.pass.Add("127.0.0.1")

	proxyURL, _ := url.Parse(liveTr.ProxyAddr())
	targetPool := x509.NewCertPool()
	targetPool.AddCert(target.Certificate())
	client := &http.Client{
		Transport: &http.Transport{
			Proxy:           http.ProxyURL(proxyURL),
			TLSClientConfig: &tls.Config{RootCAs: targetPool},
		},
		Timeout: 5 * time.Second,
	}
	resp, err := client.Get(target.URL + "/tunnel")
	if err != nil {
		t.Fatalf("passthrough HTTPS request failed: %v", err)
	}
	got, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if string(got) != "direct-tls-ok" {
		t.Fatalf("passthrough body=%q, want direct-tls-ok", got)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	_ = liveTr.Flush(ctx)
	if n, err := liveTr.Count(); err != nil || n != 0 {
		t.Fatalf("passthrough tunnel must not be recorded: count=%d err=%v", n, err)
	}
}

// TestProxyUpgradeTunnelAndUpstreamProxy verifies raw Upgrade tunneling and
// dynamic SetUpstreamProxy forwarding + clearing.
func TestProxyUpgradeTunnelAndUpstreamProxy(t *testing.T) {
	// 1. Plain HTTP Upgrade echo server.
	upgradeSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.EqualFold(r.Header.Get("Upgrade"), "echo") {
			http.Error(w, "no upgrade", http.StatusBadRequest)
			return
		}
		hj, ok := w.(http.Hijacker)
		if !ok {
			http.Error(w, "no hijack", http.StatusInternalServerError)
			return
		}
		c, rw, err := hj.Hijack()
		if err != nil {
			return
		}
		defer c.Close()
		_, _ = rw.WriteString("HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: echo\r\n\r\n")
		_ = rw.Flush()
		line, err := rw.ReadString('\n')
		if err == nil {
			_, _ = rw.WriteString("ECHO:" + line)
			_ = rw.Flush()
		}
	}))
	defer upgradeSrv.Close()

	tr, client := startHardeningProxy(t)

	// Dial proxy directly to send an HTTP Upgrade request.
	conn, err := net.DialTimeout("tcp", tr.effectiveListenAddr(), 3*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
	u, _ := url.Parse(upgradeSrv.URL)
	_, err = fmt.Fprintf(conn, "GET %s/ws HTTP/1.1\r\nHost: %s\r\nConnection: Upgrade\r\nUpgrade: echo\r\n\r\n", upgradeSrv.URL, u.Host)
	if err != nil {
		t.Fatal(err)
	}
	br := bufio.NewReader(conn)
	resp, err := http.ReadResponse(br, &http.Request{Method: http.MethodGet})
	if err != nil {
		t.Fatalf("read upgrade response: %v", err)
	}
	if resp.StatusCode != http.StatusSwitchingProtocols {
		t.Fatalf("upgrade status=%d, want 101", resp.StatusCode)
	}
	_, _ = io.WriteString(conn, "hello-upgrade\n")
	echoLine, err := br.ReadString('\n')
	if err != nil || echoLine != "ECHO:hello-upgrade\n" {
		t.Fatalf("upgrade echo=%q err=%v, want ECHO:hello-upgrade\\n", echoLine, err)
	}

	// 2. Dynamic upstream proxy switching.
	var upstreamHits atomic.Int64
	upstreamProxy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		upstreamHits.Add(1)
		w.Header().Set("X-Via-Upstream", "yes")
		_, _ = io.WriteString(w, "from-upstream-proxy")
	}))
	defer upstreamProxy.Close()

	if err := tr.SetUpstreamProxy(upstreamProxy.URL); err != nil {
		t.Fatalf("SetUpstreamProxy: %v", err)
	}
	r1, err := client.Get("http://upstream-check.example/test")
	if err != nil {
		t.Fatalf("GET via upstream proxy: %v", err)
	}
	b1, _ := io.ReadAll(r1.Body)
	r1.Body.Close()
	if string(b1) != "from-upstream-proxy" || upstreamHits.Load() != 1 {
		t.Fatalf("upstream proxy not used: body=%q hits=%d", b1, upstreamHits.Load())
	}

	// Clear upstream proxy back to direct.
	if err := tr.SetUpstreamProxy(""); err != nil {
		t.Fatalf("clear upstream proxy: %v", err)
	}
	directTarget := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, "direct-now")
	}))
	defer directTarget.Close()
	r2, err := client.Get(directTarget.URL + "/direct")
	if err != nil {
		t.Fatalf("GET after clearing upstream: %v", err)
	}
	b2, _ := io.ReadAll(r2.Body)
	r2.Body.Close()
	if string(b2) != "direct-now" || upstreamHits.Load() != 1 {
		t.Fatalf("expected direct dial after clear: body=%q upstreamHits=%d", b2, upstreamHits.Load())
	}
}

// TestPruneExchangesEnforcesMaxAgeAndMaxRowsPreservingEvidence verifies both
// age-based and row-count retention pruning, blob GC, and preservation of
// exchanges referenced by evidence bindings.
func TestPruneExchangesEnforcesMaxAgeAndMaxRowsPreservingEvidence(t *testing.T) {
	tr, _ := openTraffic(t)

	// Create evidence binding tables (matching db/schema.sql) in the test DB.
	for _, ddl := range []string{
		`CREATE TABLE traffic_evidence_snapshots (id TEXT PRIMARY KEY, source_traffic_id TEXT NOT NULL)`,
		`CREATE TABLE finding_traffic_bindings (id INTEGER PRIMARY KEY, finding_id INTEGER NOT NULL, snapshot_id TEXT NOT NULL)`,
	} {
		if _, err := tr.DB().Exec(ddl); err != nil {
			t.Fatal(err)
		}
	}

	seedWithAge := func(host, path string, age time.Duration, body []byte) (id, blobHash string) {
		t.Helper()
		tr.record(newFlow(host, "GET", path, nil, body, withRespType("application/sql")))
		if err := tr.DB().QueryRow(`SELECT id FROM exchanges WHERE url LIKE ? ORDER BY rowid DESC LIMIT 1`, "%"+path).Scan(&id); err != nil {
			t.Fatal(err)
		}
		ts := time.Now().Add(-age).Unix()
		if _, err := tr.DB().Exec(`UPDATE exchanges SET ts=? WHERE id=?`, ts, id); err != nil {
			t.Fatal(err)
		}
		var h *string
		_ = tr.DB().QueryRow(`SELECT resp_blob FROM exchange_bodies WHERE id=?`, id).Scan(&h)
		if h != nil {
			blobHash = *h
		}
		return id, blobHash
	}

	bigOld := bytes.Repeat([]byte("O"), maxInlineBody+1024)
	bigBound := bytes.Repeat([]byte("E"), maxInlineBody+1024)

	// Two old rows (10 days old): one unbound (must be pruned + blob GC'd), one bound (must survive!).
	oldUnboundID, oldUnboundBlob := seedWithAge("prune.example", "/old-unbound", 10*24*time.Hour, bigOld)
	oldBoundID, oldBoundBlob := seedWithAge("prune.example", "/old-bound", 10*24*time.Hour, bigBound)

	if _, err := tr.DB().Exec(`INSERT INTO traffic_evidence_snapshots(id, source_traffic_id) VALUES('snap-1', ?)`, oldBoundID); err != nil {
		t.Fatal(err)
	}
	if _, err := tr.DB().Exec(`INSERT INTO finding_traffic_bindings(id, finding_id, snapshot_id) VALUES(1, 100, 'snap-1')`); err != nil {
		t.Fatal(err)
	}

	// Five fresh rows (1h..5h old).
	var freshIDs []string
	for i := 5; i >= 1; i-- {
		id, _ := seedWithAge("prune.example", fmt.Sprintf("/fresh-%d", i), time.Duration(i)*time.Hour, []byte("fresh"))
		freshIDs = append(freshIDs, id)
	}

	// 1. maxAge = 7 days: prunes only oldUnboundID; keeps oldBoundID + 5 fresh rows.
	deleted, err := tr.PruneExchanges(context.Background(), 7*24*time.Hour, 0)
	if err != nil {
		t.Fatalf("PruneExchanges(maxAge): %v", err)
	}
	if deleted != 1 {
		t.Fatalf("PruneExchanges(maxAge) deleted=%d, want 1", deleted)
	}
	if _, _, err := tr.Get(oldUnboundID); err == nil {
		t.Fatal("oldUnboundID should have been pruned")
	}
	if _, err := tr.blobPath(oldUnboundBlob); err == nil {
		t.Fatal("oldUnboundBlob should have been GC'd")
	}
	if _, _, err := tr.Get(oldBoundID); err != nil {
		t.Fatalf("evidence-bound oldBoundID was pruned: %v", err)
	}
	if _, err := tr.blobPath(oldBoundBlob); err != nil {
		t.Fatalf("evidence-bound blob was GC'd: %v", err)
	}

	// 2. maxRows = 3: currently 6 rows (1 bound + 5 fresh). Trims 3 oldest UNPROTECTED
	// fresh rows, leaving 3 rows total: oldBoundID + 2 newest fresh rows!
	deleted, err = tr.PruneExchanges(context.Background(), 0, 3)
	if err != nil {
		t.Fatalf("PruneExchanges(maxRows): %v", err)
	}
	if deleted != 3 {
		t.Fatalf("PruneExchanges(maxRows) deleted=%d, want 3", deleted)
	}
	if n, err := tr.Count(); err != nil || n != 3 {
		t.Fatalf("Count after maxRows prune=(%d,%v), want (3,nil)", n, err)
	}
	if _, _, err := tr.Get(oldBoundID); err != nil {
		t.Fatalf("evidence-bound exchange lost during maxRows prune: %v", err)
	}
	// Newest 2 fresh rows (freshIDs[3], freshIDs[4]) must remain; oldest 3 pruned.
	for _, prunedID := range freshIDs[:3] {
		if _, _, err := tr.Get(prunedID); err == nil {
			t.Fatalf("older fresh row %s should have been trimmed", prunedID)
		}
	}
	for _, keptID := range freshIDs[3:] {
		if _, _, err := tr.Get(keptID); err != nil {
			t.Fatalf("newest fresh row %s should have been kept: %v", keptID, err)
		}
	}

	// 3. Also verify finding_traffic(exchange_id) protection table is honored.
	if _, err := tr.DB().Exec(`CREATE TABLE finding_traffic (exchange_id TEXT PRIMARY KEY)`); err != nil {
		t.Fatal(err)
	}
	if _, err := tr.DB().Exec(`INSERT INTO finding_traffic(exchange_id) VALUES(?)`, freshIDs[3]); err != nil {
		t.Fatal(err)
	}
	if deleted, err := tr.PruneExchanges(context.Background(), 0, 2); err != nil || deleted != 1 {
		t.Fatalf("PruneExchanges with finding_traffic deleted=(%d,%v), want (1,nil)", deleted, err)
	}
	if _, _, err := tr.Get(freshIDs[3]); err != nil {
		t.Fatalf("finding_traffic protected row was deleted: %v", err)
	}
}
