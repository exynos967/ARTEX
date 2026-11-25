package enrich

import (
	"bytes"
	"context"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/miekg/dns"
)

// countEnrichWorkerGoroutines inspects all live goroutine stacks and counts
// active (*Engine).worker frames. Unlike raw runtime.NumGoroutine deltas, this
// is immune to unrelated Go runtime/GC/netpoll background goroutines.
func countEnrichWorkerGoroutines() int {
	buf := make([]byte, 64<<10)
	for {
		n := runtime.Stack(buf, true)
		if n < len(buf) {
			return strings.Count(string(buf[:n]), "(*Engine).worker(")
		}
		buf = make([]byte, len(buf)*2)
	}
}

func TestLazyDormancySpawnsZeroWorkers(t *testing.T) {
	if n := countEnrichWorkerGoroutines(); n != 0 {
		t.Fatalf("unexpected pre-existing enrich worker goroutines: %d", n)
	}

	before := runtime.NumGoroutine()
	engines := make([]*Engine, 4)
	for i := range engines {
		engines[i] = New(nil, nil, 8)
	}
	// Invalid/empty inputs must remain no-ops and must not wake worker pools.
	engines[0].ResolveDomain(0, "example.com")
	engines[0].ResolveDomain(1, "")
	engines[0].ProbeSite(-1, "http://example.com")
	engines[0].ProbeSite(1, "")

	runtime.Gosched()
	if workers := countEnrichWorkerGoroutines(); workers != 0 {
		t.Fatalf("dormant engines spawned %d worker goroutines, want 0", workers)
	}
	// 4 engines * 8 workers = 32 workers would have been spawned eagerly.
	if delta := runtime.NumGoroutine() - before; delta >= 8 {
		t.Fatalf("dormant engines increased goroutine count by %d (before=%d), want 0 worker goroutines", delta, before)
	}

	for _, e := range engines {
		e.Close()
		e.Close() // idempotent close on dormant engine
	}
	if workers := countEnrichWorkerGoroutines(); workers != 0 {
		t.Fatalf("worker goroutines leaked after Close on dormant engines: %d", workers)
	}
}

func TestLazyStartOnFirstJobAndConcurrentClose(t *testing.T) {
	e := New(nil, nil, 4)
	if workers := countEnrichWorkerGoroutines(); workers != 0 {
		t.Fatalf("workers started before first job: %d", workers)
	}

	done := make(chan struct{}, 1)
	e.dnsQuery = func(ctx context.Context, host string) (dnsRecords, error) {
		select {
		case done <- struct{}{}:
		default:
		}
		return dnsRecords{}, nil
	}

	e.ResolveDomain(1, "lazy.example.com")
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("lazy worker did not execute first ResolveDomain job")
	}

	e.Close()
	if workers := countEnrichWorkerGoroutines(); workers != 0 {
		t.Fatalf("worker goroutines remained after Close: %d", workers)
	}

	// Stress concurrent ResolveDomain/ProbeSite racing against Close().
	for round := 0; round < 20; round++ {
		eng := New(nil, nil, 2)
		eng.dnsQuery = func(ctx context.Context, host string) (dnsRecords, error) { return dnsRecords{}, nil }
		var wg sync.WaitGroup
		start := make(chan struct{})
		for g := 0; g < 8; g++ {
			id := int64(g + 1)
			wg.Add(1)
			go func() {
				defer wg.Done()
				<-start
				eng.ResolveDomain(id, "race.example.com")
			}()
		}
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			eng.Close()
		}()
		close(start)
		wg.Wait()
		eng.Close()
	}
	if workers := countEnrichWorkerGoroutines(); workers != 0 {
		t.Fatalf("worker goroutines leaked after concurrent start/close stress: %d", workers)
	}
}

func TestClaimCooldownAtomicSingleWinner(t *testing.T) {
	e := New(nil, nil, 1)
	defer e.Close()

	const goroutines = 32
	for round := 0; round < 5; round++ {
		key := fmt.Sprintf("http:race-%d", round)
		start := make(chan struct{})
		var winners atomic.Int32
		var wg sync.WaitGroup
		wg.Add(goroutines)
		for i := 0; i < goroutines; i++ {
			go func() {
				defer wg.Done()
				<-start
				if e.claimCooldown(key, 5*time.Minute) {
					winners.Add(1)
				}
			}()
		}
		close(start)
		wg.Wait()

		if got := winners.Load(); got != 1 {
			t.Fatalf("round %d: claimCooldown allowed %d winners out of %d goroutines, want exactly 1", round, got, goroutines)
		}
	}

	// Verify TTL expiration allows re-claiming once expired.
	if !e.claimCooldown("expiring", 25*time.Millisecond) {
		t.Fatal("initial claim should succeed")
	}
	if e.claimCooldown("expiring", 25*time.Millisecond) {
		t.Fatal("immediate duplicate claim should be blocked")
	}
	time.Sleep(40 * time.Millisecond)
	if !e.claimCooldown("expiring", 25*time.Millisecond) {
		t.Fatal("claim after TTL expiry should succeed")
	}
	if e.claimCooldown("expiring", 25*time.Millisecond) {
		t.Fatal("claim immediately after re-claim should be blocked")
	}
}

func TestClaimCooldownBoundedCap(t *testing.T) {
	e := New(nil, nil, 1)
	defer e.Close()

	const totalKeys = 6000
	for i := 0; i < totalKeys; i++ {
		key := fmt.Sprintf("k-%d", i)
		if !e.claimCooldown(key, 5*time.Minute) {
			t.Fatalf("fresh key %q unexpectedly rejected", key)
		}
		if n := e.cooldownLen(); n > maxCooldownEntries {
			t.Fatalf("cooldown cache exceeded cap at insert %d: len=%d > max=%d", i, n, maxCooldownEntries)
		}
	}

	if n := e.cooldownLen(); n != maxCooldownEntries {
		t.Fatalf("cooldown cache len=%d after %d distinct inserts, want %d", n, totalKeys, maxCooldownEntries)
	}
	// Newest key must still be cached and rejected on duplicate claim.
	if e.claimCooldown(fmt.Sprintf("k-%d", totalKeys-1), 5*time.Minute) {
		t.Fatal("newest key should still be on cooldown")
	}
	// Oldest key should have been evicted and thus claimable again.
	if !e.claimCooldown("k-0", 5*time.Minute) {
		t.Fatal("oldest evicted key should be claimable again")
	}
	if n := e.cooldownLen(); n > maxCooldownEntries {
		t.Fatalf("cooldown cache exceeded cap after re-insert: len=%d", n)
	}
}

func TestBuildClientKeepAliveAndTimeouts(t *testing.T) {
	var proxyAddr atomic.Value
	proxyAddr.Store("")

	c := buildClient(func() string { return proxyAddr.Load().(string) })
	if c == nil {
		t.Fatal("buildClient returned nil")
	}
	if c.Timeout <= 0 {
		t.Fatalf("client.Timeout=%v, want > 0", c.Timeout)
	}
	tr, ok := c.Transport.(*http.Transport)
	if !ok || tr == nil {
		t.Fatalf("client.Transport = %T, want non-nil *http.Transport", c.Transport)
	}
	if tr.DisableKeepAlives {
		t.Fatal("DisableKeepAlives is true, want false (keep-alives enabled)")
	}
	if tr.DialContext == nil {
		t.Fatal("DialContext is nil, want bounded net.Dialer.DialContext")
	}
	if tr.TLSHandshakeTimeout != tlsHandshakeTimeout {
		t.Fatalf("TLSHandshakeTimeout=%v, want %v", tr.TLSHandshakeTimeout, tlsHandshakeTimeout)
	}
	if tr.ResponseHeaderTimeout != responseHeaderTimeout {
		t.Fatalf("ResponseHeaderTimeout=%v, want %v", tr.ResponseHeaderTimeout, responseHeaderTimeout)
	}
	if tr.ResponseHeaderTimeout >= c.Timeout {
		t.Fatalf("ResponseHeaderTimeout=%v must be strictly less than client Timeout=%v", tr.ResponseHeaderTimeout, c.Timeout)
	}
	if tr.IdleConnTimeout != idleConnTimeout {
		t.Fatalf("IdleConnTimeout=%v, want %v", tr.IdleConnTimeout, idleConnTimeout)
	}
	if tr.MaxIdleConnsPerHost != maxIdleConnsPerHost {
		t.Fatalf("MaxIdleConnsPerHost=%d, want %d", tr.MaxIdleConnsPerHost, maxIdleConnsPerHost)
	}
	if tr.TLSClientConfig == nil || !tr.TLSClientConfig.InsecureSkipVerify {
		t.Fatal("TLSClientConfig.InsecureSkipVerify must be true for MITM/self-signed targets")
	}

	// Dynamic proxy toggle: empty -> direct (nil URL), non-empty -> parsed proxy URL.
	req, _ := http.NewRequest(http.MethodGet, "http://example.com", nil)
	if u, err := tr.Proxy(req); err != nil || u != nil {
		t.Fatalf("empty proxy callback returned (%v, %v), want (nil, nil)", u, err)
	}
	proxyAddr.Store("http://127.0.0.1:8080")
	if u, err := tr.Proxy(req); err != nil || u == nil || u.String() != "http://127.0.0.1:8080" {
		t.Fatalf("active proxy callback returned (%v, %v), want http://127.0.0.1:8080", u, err)
	}

	// Nil proxy callback must disable proxy lookup (direct dial, ignores env proxy).
	direct := buildClient(nil)
	directTr := direct.Transport.(*http.Transport)
	if directTr.Proxy != nil {
		t.Fatal("buildClient(nil) should have nil Transport.Proxy")
	}

	// End-to-end keep-alive connection reuse with body > 1 MiB (exercises httpx.DrainAndClose).
	oversized := bytes.Repeat([]byte("a"), (1<<20)+512)
	var mu sync.Mutex
	var remoteAddrs []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		remoteAddrs = append(remoteAddrs, r.RemoteAddr)
		mu.Unlock()
		w.Header().Set("Content-Type", "text/html")
		_, _ = w.Write(oversized)
	}))
	defer srv.Close()

	e := New(nil, nil, 1)
	defer e.Close()
	e.doHTTP(1, srv.URL+"/first")
	e.doHTTP(2, srv.URL+"/second")

	mu.Lock()
	defer mu.Unlock()
	if len(remoteAddrs) != 2 {
		t.Fatalf("expected 2 requests, got %d", len(remoteAddrs))
	}
	if remoteAddrs[0] != remoteAddrs[1] {
		t.Fatalf("expected HTTP/1.1 keep-alive connection reuse, got distinct client addrs %q vs %q", remoteAddrs[0], remoteAddrs[1])
	}
}

func TestDNSRateLimiterPacingAndCancellation(t *testing.T) {
	// 20 QPS with burst 2: 2 calls immediate, 3 more calls require ~150ms.
	lim := newRateLimiter(20, 2)
	start := time.Now()
	for i := 0; i < 5; i++ {
		if err := lim.wait(context.Background()); err != nil {
			t.Fatalf("call %d unexpected error: %v", i, err)
		}
	}
	if elapsed := time.Since(start); elapsed < 110*time.Millisecond {
		t.Fatalf("5 calls at 20 QPS (burst 2) finished too quickly in %v", elapsed)
	}

	// Slow limiter: cancellation must abort wait immediately without blocking.
	slow := newRateLimiter(0.5, 1) // 1 token every 2s
	if err := slow.wait(context.Background()); err != nil {
		t.Fatalf("burst token failed: %v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Millisecond)
	defer cancel()
	cancelStart := time.Now()
	err := slow.wait(ctx)
	if err == nil {
		t.Fatal("expected context error while waiting on rate limiter")
	}
	if elapsed := time.Since(cancelStart); elapsed > 300*time.Millisecond {
		t.Fatalf("rateLimiter.wait did not honor context cancellation promptly: %v", elapsed)
	}
}

func TestCloseCancelsActiveDNSQuery(t *testing.T) {
	// 1. Custom dnsQuery honoring ctx cancels synchronously with zero leaked goroutines.
	e := New(nil, nil, 1)
	started := make(chan struct{})
	exited := make(chan struct{})

	e.dnsQuery = func(ctx context.Context, host string) (dnsRecords, error) {
		close(started)
		<-ctx.Done()
		close(exited)
		return dnsRecords{}, ctx.Err()
	}

	e.ResolveDomain(1, "slow.example.com")
	select {
	case <-started:
	case <-time.After(2 * time.Second):
		t.Fatal("DNS query did not start")
	}

	closed := make(chan struct{})
	go func() {
		e.Close()
		close(closed)
	}()
	select {
	case <-closed:
	case <-time.After(500 * time.Millisecond):
		t.Fatal("Close blocked on slow in-flight DNS query instead of canceling promptly")
	}
	select {
	case <-exited:
	default:
		t.Fatal("Close returned while DNS query goroutine was still running (orphaned goroutine)")
	}

	// After Close, doDNS must not invoke dnsQuery at all.
	var calledAfterClose atomic.Bool
	e.dnsQuery = func(ctx context.Context, host string) (dnsRecords, error) {
		calledAfterClose.Store(true)
		return dnsRecords{}, nil
	}
	e.doDNS(2, "after-close.example.com")
	if calledAfterClose.Load() {
		t.Fatal("doDNS executed query after context was cancelled")
	}
}

func TestRealDNSExchangeContextCancelsWithoutOrphanGoroutines(t *testing.T) {
	// Start a local UDP socket that receives DNS queries and intentionally never replies.
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer pc.Close()

	received := make(chan struct{}, 1)
	go func() {
		buf := make([]byte, 512)
		for {
			_, _, err := pc.ReadFrom(buf)
			if err != nil {
				return
			}
			select {
			case received <- struct{}{}:
			default:
			}
		}
	}()

	e := New(nil, nil, 1)
	e.dnsResolvers = []string{pc.LocalAddr().String()}

	e.ResolveDomain(1, "hang.example.test")
	select {
	case <-received:
	case <-time.After(2 * time.Second):
		t.Fatal("DNS ExchangeContext query never arrived at local UDP server")
	}

	start := time.Now()
	e.Close()
	if elapsed := time.Since(start); elapsed > 500*time.Millisecond {
		t.Fatalf("Close took %v to cancel hanging ExchangeContext, want < 500ms", elapsed)
	}
	if workers := countEnrichWorkerGoroutines(); workers != 0 {
		t.Fatalf("orphaned worker goroutines after Close: %d", workers)
	}
}

func TestQueryDNSContextExtractsRecords(t *testing.T) {
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer pc.Close()

	go func() {
		buf := make([]byte, 1500)
		for {
			n, addr, err := pc.ReadFrom(buf)
			if err != nil {
				return
			}
			req := new(dns.Msg)
			if err := req.Unpack(buf[:n]); err != nil || len(req.Question) == 0 {
				continue
			}
			resp := new(dns.Msg)
			resp.SetReply(req)
			q := req.Question[0]
			switch q.Qtype {
			case dns.TypeA:
				resp.Answer = append(resp.Answer, &dns.A{
					Hdr: dns.RR_Header{Name: q.Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 60},
					A:   net.ParseIP("93.184.216.34"),
				})
			case dns.TypeAAAA:
				resp.Answer = append(resp.Answer, &dns.AAAA{
					Hdr:  dns.RR_Header{Name: q.Name, Rrtype: dns.TypeAAAA, Class: dns.ClassINET, Ttl: 60},
					AAAA: net.ParseIP("2606:2800:220:1:248:1893:25c8:1946"),
				})
			case dns.TypeCNAME:
				resp.Answer = append(resp.Answer, &dns.CNAME{
					Hdr:    dns.RR_Header{Name: q.Name, Rrtype: dns.TypeCNAME, Class: dns.ClassINET, Ttl: 60},
					Target: "alias.example.net.",
				})
			}
			if raw, err := resp.Pack(); err == nil {
				_, _ = pc.WriteTo(raw, addr)
			}
		}
	}()

	e := New(nil, nil, 1)
	defer e.Close()
	e.dnsResolvers = []string{pc.LocalAddr().String()}

	rec, err := e.queryDNSContext(context.Background(), "www.example.com")
	if err != nil {
		t.Fatalf("queryDNSContext: %v", err)
	}
	if len(rec.A) != 1 || rec.A[0] != "93.184.216.34" {
		t.Errorf("A = %v, want [93.184.216.34]", rec.A)
	}
	if len(rec.AAAA) != 1 || rec.AAAA[0] != "2606:2800:220:1:248:1893:25c8:1946" {
		t.Errorf("AAAA = %v, want [2606:2800:220:1:248:1893:25c8:1946]", rec.AAAA)
	}
	if len(rec.CNAME) != 1 || rec.CNAME[0] != "alias.example.net" {
		t.Errorf("CNAME = %v, want [alias.example.net]", rec.CNAME)
	}
}
