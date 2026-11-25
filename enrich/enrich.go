// Package enrich is the engine-side (non-AI) asset auto-completion layer described
// in docs/资产模型与自动关联设计.md §5: an async worker pool that resolves domains
// (dnsx) and probes web assets (HTTP, through the recording proxy) and writes the
// results back into the asset graph — creating IP/port nodes, resolves/exposes
// edges, and filling attrs.dns / attrs.http. DNS is ungated; HTTP probing is gated
// by RoE (§5.2).
package enrich

import (
	"container/list"
	"context"
	"crypto/tls"
	"html"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/RC-CHN/ARTEX/db"
	"github.com/RC-CHN/ARTEX/internal/httpx"

	"github.com/miekg/dns"
)

type jobKind int

const (
	jobDNS  jobKind = iota // resolve a domain
	jobHTTP                // probe a web asset (site)
)

type job struct {
	kind jobKind
	id   int64  // asset id (domain for DNS, site for HTTP)
	arg  string // host (DNS) or url (HTTP)
}

// Engine owns the resolver, the proxy-routed HTTP client, and the lazy worker pool.
type Engine struct {
	as           *db.AssetStore
	dnsClient    *dns.Client
	dnsResolvers []string
	dnsRR        atomic.Uint64
	client       *http.Client
	workers      int

	// dnsQuery overrides queryDNSContext in tests; nil uses miekg/dns ExchangeContext.
	dnsQuery   func(ctx context.Context, host string) (dnsRecords, error)
	dnsLimiter *rateLimiter

	jobs chan job
	cool cooldownCache

	mu        sync.Mutex
	closed    bool
	startOnce sync.Once
	closeOnce sync.Once
	closeCh   chan struct{}
	ctx       context.Context
	cancel    context.CancelFunc
	wg        sync.WaitGroup
}

const (
	cooldown              = 5 * time.Minute
	maxCooldownEntries    = 4096
	httpTimeout           = 12 * time.Second
	dialTimeout           = 10 * time.Second
	dialKeepAlive         = 30 * time.Second
	tlsHandshakeTimeout   = 10 * time.Second
	responseHeaderTimeout = 8 * time.Second
	idleConnTimeout       = 30 * time.Second
	maxIdleConns          = 64
	maxIdleConnsPerHost   = 16
	queueSize             = 1024
	dnsRateLimitQPS       = 20
	dnsRateLimitBurst     = 4
	dnsTimeout            = 4 * time.Second
	dnsMaxRetries         = 3
)

var defaultDNSResolvers = []string{
	"1.1.1.1:53",
	"8.8.8.8:53",
	"9.9.9.9:53",
	"1.0.0.1:53",
	"8.8.4.4:53",
}

// New builds the engine without spawning worker goroutines until first use.
// proxy() returns the recording-proxy address to route HTTP probes through (so
// they land in the traffic store), evaluated per request so the runtime
// traffic-capture toggle takes effect live; "" = direct.
func New(as *db.AssetStore, proxy func() string, workers int) *Engine {
	if workers <= 0 {
		workers = 4
	}
	ctx, cancel := context.WithCancel(context.Background())
	return &Engine{
		ctx:          ctx,
		cancel:       cancel,
		as:           as,
		dnsClient:    &dns.Client{Net: "udp", Timeout: dnsTimeout},
		dnsResolvers: append([]string(nil), defaultDNSResolvers...),
		client:       buildClient(proxy),
		workers:      workers,
		jobs:         make(chan job, queueSize),
		cool:         newCooldownCache(maxCooldownEntries),
		dnsLimiter:   newRateLimiter(dnsRateLimitQPS, dnsRateLimitBurst),
		closeCh:      make(chan struct{}),
	}
}

// buildClient returns a keep-alive-enabled HTTP client cloned from
// http.DefaultTransport with bounded timeouts. It dials via the recording proxy
// (resolved per-request via proxy(), so the traffic-capture toggle applies live)
// and skips TLS verification (the proxy re-signs with its MITM CA; targets are
// often self-signed — this is a pentest probe).
func buildClient(proxy func() string) *http.Client {
	var tr *http.Transport
	if base, ok := http.DefaultTransport.(*http.Transport); ok && base != nil {
		tr = base.Clone()
	} else {
		tr = &http.Transport{}
	}
	tr.DialContext = (&net.Dialer{
		Timeout:   dialTimeout,
		KeepAlive: dialKeepAlive,
	}).DialContext
	tr.TLSClientConfig = &tls.Config{InsecureSkipVerify: true}
	tr.DisableKeepAlives = false
	tr.TLSHandshakeTimeout = tlsHandshakeTimeout
	tr.ResponseHeaderTimeout = responseHeaderTimeout
	tr.IdleConnTimeout = idleConnTimeout
	tr.MaxIdleConns = maxIdleConns
	tr.MaxIdleConnsPerHost = maxIdleConnsPerHost
	tr.Proxy = nil
	if proxy != nil {
		tr.Proxy = func(*http.Request) (*url.URL, error) {
			p := strings.TrimSpace(proxy())
			if p == "" {
				return nil, nil // direct
			}
			return url.Parse(p)
		}
	}
	return &http.Client{
		Transport: tr,
		Timeout:   httpTimeout,
		// cap redirects; keep them within scope by re-checking at probe time
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
}

// ensureStarted lazily spawns worker goroutines on first work submission.
// Serialized with Close via e.mu so no worker can ever start after Close.
func (e *Engine) ensureStarted() bool {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.closed || e.jobs == nil || e.closeCh == nil {
		return false
	}
	e.startOnce.Do(func() {
		n := e.workers
		if n <= 0 {
			n = 4
		}
		e.wg.Add(n)
		for i := 0; i < n; i++ {
			go func() {
				defer e.wg.Done()
				e.worker()
			}()
		}
	})
	return true
}

// ResolveDomain enqueues a DNS resolution for a domain asset (ungated). host is the
// FQDN. No-op for an empty engine.
func (e *Engine) ResolveDomain(id int64, host string) { e.enqueue(job{jobDNS, id, host}) }

// ProbeSite enqueues an HTTP probe for a web-asset (site). rawURL is the site URL.
func (e *Engine) ProbeSite(id int64, rawURL string) { e.enqueue(job{jobHTTP, id, rawURL}) }

func (e *Engine) enqueue(j job) {
	if e == nil || id0(j.id) || j.arg == "" {
		return
	}
	if !e.ensureStarted() {
		return
	}
	select {
	case <-e.closeCh:
		return
	default:
	}
	select {
	case <-e.closeCh:
		return
	case e.jobs <- j:
	default: // queue full → drop (best-effort enrichment)
		log.Printf("[enrich] 队列已满，丢弃任务 kind=%d id=%d", j.kind, j.id)
	}
}

func id0(id int64) bool { return id <= 0 }

// Close cancels active probes and joins any started workers before their database
// is closed. Safe to call on a dormant engine or multiple times.
func (e *Engine) Close() {
	if e == nil {
		return
	}
	e.mu.Lock()
	e.closeOnce.Do(func() {
		e.closed = true
		if e.closeCh != nil {
			close(e.closeCh)
		}
		if e.cancel != nil {
			e.cancel()
		}
	})
	e.mu.Unlock()
	e.wg.Wait()
	if e.client != nil {
		if tr, ok := e.client.Transport.(*http.Transport); ok && tr != nil {
			tr.CloseIdleConnections()
		}
	}
}

func (e *Engine) worker() {
	for {
		select {
		case <-e.closeCh:
			return
		default:
		}
		select {
		case <-e.closeCh:
			return
		case j := <-e.jobs:
			if !e.claimCooldown(cooldownKey(j), cooldown) {
				continue
			}
			switch j.kind {
			case jobDNS:
				e.doDNS(j.id, j.arg)
			case jobHTTP:
				e.doHTTP(j.id, j.arg)
			}
		}
	}
}

func cooldownKey(j job) string {
	return strconv.Itoa(int(j.kind)) + ":" + itoa(j.id)
}

type cooldownEntry struct {
	key       string
	expiresAt time.Time
}

// cooldownCache is an atomic, mutex-protected, bounded TTL cache that prevents
// duplicate concurrent probes (no TOCTOU race) and unbounded memory growth.
type cooldownCache struct {
	mu      sync.Mutex
	maxSize int
	order   *list.List // front = newest, back = oldest
	entries map[string]*list.Element
}

func newCooldownCache(maxSize int) cooldownCache {
	if maxSize <= 0 {
		maxSize = maxCooldownEntries
	}
	return cooldownCache{
		maxSize: maxSize,
		order:   list.New(),
		entries: make(map[string]*list.Element),
	}
}

// claimCooldown atomically checks whether key is currently on cooldown; if not,
// it evicts expired/oldest entries as needed to stay within maxCooldownEntries,
// marks key with ttl, and returns true (caller won the right to execute).
func (e *Engine) claimCooldown(key string, ttl time.Duration) bool {
	return e.cool.claim(key, ttl)
}

func (e *Engine) cooldownLen() int {
	e.cool.mu.Lock()
	defer e.cool.mu.Unlock()
	return len(e.cool.entries)
}

func (c *cooldownCache) claim(key string, ttl time.Duration) bool {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.entries == nil {
		c.order = list.New()
		c.entries = make(map[string]*list.Element)
	}
	maxSize := c.maxSize
	if maxSize <= 0 {
		maxSize = maxCooldownEntries
	}

	now := time.Now()
	if ttl <= 0 {
		if elem, ok := c.entries[key]; ok {
			c.order.Remove(elem)
			delete(c.entries, key)
		}
		return true
	}

	if elem, ok := c.entries[key]; ok {
		ent := elem.Value.(*cooldownEntry)
		if now.Before(ent.expiresAt) {
			return false
		}
		ent.expiresAt = now.Add(ttl)
		c.order.MoveToFront(elem)
		return true
	}

	// When at capacity, prune expired tail entries first, then evict oldest entries.
	if len(c.entries) >= maxSize {
		for back := c.order.Back(); back != nil && !now.Before(back.Value.(*cooldownEntry).expiresAt); back = c.order.Back() {
			be := back.Value.(*cooldownEntry)
			c.order.Remove(back)
			delete(c.entries, be.key)
		}
		for len(c.entries) >= maxSize {
			oldest := c.order.Back()
			if oldest == nil {
				break
			}
			oe := oldest.Value.(*cooldownEntry)
			c.order.Remove(oldest)
			delete(c.entries, oe.key)
		}
	}

	elem := c.order.PushFront(&cooldownEntry{
		key:       key,
		expiresAt: now.Add(ttl),
	})
	c.entries[key] = elem
	return true
}

func itoa(n int64) string { return strconv.FormatInt(n, 10) }

// rateLimiter is a lightweight, zero-goroutine token-bucket QPS limiter.
type rateLimiter struct {
	mu     sync.Mutex
	rate   float64 // tokens per second
	burst  float64 // max burst tokens
	tokens float64
	last   time.Time
}

func newRateLimiter(qps float64, burst int) *rateLimiter {
	if qps <= 0 {
		return nil
	}
	if burst < 1 {
		burst = 1
	}
	return &rateLimiter{
		rate:   qps,
		burst:  float64(burst),
		tokens: float64(burst),
		last:   time.Now(),
	}
}

func (l *rateLimiter) refillLocked(now time.Time) {
	if elapsed := now.Sub(l.last).Seconds(); elapsed > 0 {
		l.tokens += elapsed * l.rate
		if l.tokens > l.burst {
			l.tokens = l.burst
		}
		l.last = now
	}
}

// wait blocks until a token is available or ctx is cancelled.
func (l *rateLimiter) wait(ctx context.Context) error {
	if ctx == nil {
		ctx = context.Background()
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if l == nil {
		return nil
	}

	l.mu.Lock()
	l.refillLocked(time.Now())
	l.tokens -= 1
	var waitDur time.Duration
	if l.tokens < 0 {
		waitDur = time.Duration((-l.tokens / l.rate) * float64(time.Second))
	}
	l.mu.Unlock()

	if waitDur <= 0 {
		return ctx.Err()
	}

	timer := time.NewTimer(waitDur)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		// Refund the reserved token when cancelled before dispatch.
		l.mu.Lock()
		l.refillLocked(time.Now())
		l.tokens += 1
		if l.tokens > l.burst {
			l.tokens = l.burst
		}
		l.mu.Unlock()
		return ctx.Err()
	case <-timer.C:
		return ctx.Err()
	}
}

// ---- DNS ----

type dnsRecords struct {
	A     []string
	AAAA  []string
	CNAME []string
}

// queryDNSContext resolves A, AAAA, and CNAME records directly via miekg/dns
// ExchangeContext so Close() cancels active socket reads synchronously with
// zero orphaned goroutines.
func (e *Engine) queryDNSContext(ctx context.Context, host string) (dnsRecords, error) {
	if e.dnsClient == nil || len(e.dnsResolvers) == 0 {
		return dnsRecords{}, nil
	}
	fqdn := dns.Fqdn(strings.TrimSpace(host))
	if fqdn == "." {
		return dnsRecords{}, nil
	}
	var out dnsRecords
	var lastErr error
	var succeeded bool

	qtypes := []uint16{dns.TypeA, dns.TypeAAAA, dns.TypeCNAME}
	for _, qt := range qtypes {
		if err := ctx.Err(); err != nil {
			return dnsRecords{}, err
		}
		resp, err := e.exchangeWithRetry(ctx, fqdn, qt)
		if err != nil {
			if ctx.Err() != nil {
				return dnsRecords{}, ctx.Err()
			}
			lastErr = err
			continue
		}
		succeeded = true
		if resp == nil {
			continue
		}
		for _, ans := range resp.Answer {
			switch rr := ans.(type) {
			case *dns.A:
				if rr.A != nil {
					out.A = append(out.A, rr.A.String())
				}
			case *dns.AAAA:
				if rr.AAAA != nil {
					out.AAAA = append(out.AAAA, rr.AAAA.String())
				}
			case *dns.CNAME:
				if target := strings.TrimSuffix(rr.Target, "."); target != "" {
					out.CNAME = append(out.CNAME, target)
				}
			}
		}
	}
	out.A = uniq(out.A)
	out.AAAA = uniq(out.AAAA)
	out.CNAME = uniq(out.CNAME)
	if !succeeded && lastErr != nil {
		return dnsRecords{}, lastErr
	}
	return out, nil
}

func (e *Engine) exchangeWithRetry(ctx context.Context, fqdn string, qtype uint16) (*dns.Msg, error) {
	resolvers := e.dnsResolvers
	if len(resolvers) == 0 {
		return nil, nil
	}
	attempts := dnsMaxRetries
	if attempts < 1 {
		attempts = 1
	}
	start := e.dnsRR.Add(1) - 1
	var lastErr error
	for attempt := 0; attempt < attempts; attempt++ {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		server := resolvers[(int(start)+attempt)%len(resolvers)]
		m := new(dns.Msg)
		m.SetQuestion(fqdn, qtype)
		m.RecursionDesired = true

		qctx, cancel := context.WithTimeout(ctx, dnsTimeout)
		rawConn, dialErr := (&net.Dialer{Timeout: dnsTimeout}).DialContext(qctx, "udp", server)
		if dialErr != nil {
			cancel()
			lastErr = dialErr
			if ctx.Err() != nil {
				return nil, ctx.Err()
			}
			continue
		}
		// miekg/dns ExchangeContext only applies ctx.Deadline(), not ctx cancellation
		// mid-read; interrupt the socket deadline directly via context.AfterFunc so
		// Close() unblocks immediately with zero wrapper goroutines.
		stopCancel := context.AfterFunc(qctx, func() {
			_ = rawConn.SetDeadline(time.Now())
		})
		resp, _, err := e.dnsClient.ExchangeWithConnContext(qctx, m, &dns.Conn{Conn: rawConn})
		stopCancel()
		_ = rawConn.Close()
		cancel()
		if err == nil {
			return resp, nil
		}
		lastErr = err
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
	}
	return nil, lastErr
}

func (e *Engine) doDNS(id int64, host string) {
	queryFn := e.dnsQuery
	if queryFn == nil {
		queryFn = e.queryDNSContext
	}

	ctx := e.ctx
	if ctx == nil {
		ctx = context.Background()
	}
	if ctx.Err() != nil {
		return
	}
	if err := e.dnsLimiter.wait(ctx); err != nil {
		return
	}
	if ctx.Err() != nil {
		return
	}

	rec, err := queryFn(ctx, host)
	if err != nil || ctx.Err() != nil || e.as == nil {
		return
	}

	ips := uniq(append(append([]string{}, rec.A...), rec.AAAA...))
	// Upsert resolved IPs into the asset store.
	for _, ip := range ips {
		if ctx.Err() != nil {
			return
		}
		_, _ = e.as.UpsertIP(db.UpsertIPReq{
			IP:           ip,
			BoundDomains: []string{host},
		})
	}
	// Record A records as subdomains if host looks like a subdomain.
	for _, a := range rec.A {
		if ctx.Err() != nil {
			return
		}
		_, _ = e.as.UpsertSubdomain(db.UpsertSubdomainReq{
			Domain:      host,
			RecordType:  "A",
			RecordValue: []string{a},
		})
	}
	for _, aaaa := range rec.AAAA {
		if ctx.Err() != nil {
			return
		}
		_, _ = e.as.UpsertSubdomain(db.UpsertSubdomainReq{
			Domain:      host,
			RecordType:  "AAAA",
			RecordValue: []string{aaaa},
		})
	}
	for _, cname := range rec.CNAME {
		if ctx.Err() != nil {
			return
		}
		_, _ = e.as.UpsertSubdomain(db.UpsertSubdomainReq{
			Domain:      host,
			RecordType:  "CNAME",
			RecordValue: []string{cname},
		})
	}
}

// ---- HTTP probe ----

var reTitle = regexp.MustCompile(`(?is)<title[^>]*>(.*?)</title>`)

func (e *Engine) doHTTP(id int64, rawURL string) {
	host := hostOf(rawURL)
	if host == "" {
		return
	}
	ctx := e.ctx
	if ctx == nil {
		ctx = context.Background()
	}
	if ctx.Err() != nil {
		return
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return
	}
	req.Header.Set("User-Agent", "artex-enrich/1.0")
	resp, err := e.client.Do(req)
	if err != nil {
		return
	}
	defer httpx.DrainAndClose(resp.Body)
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20)) // cap 1 MiB
	if err != nil {
		return
	}
	if ctx.Err() != nil || e.as == nil {
		return
	}
	statusCode := resp.StatusCode
	bodyLen := int64(len(body))
	title := extractTitle(body)
	_, _ = e.as.UpsertHTTPService(db.UpsertHTTPServiceReq{
		URL:           rawURL,
		StatusCode:    &statusCode,
		ContentLength: &bodyLen,
		PageTitle:     title,
	})
}

func extractTitle(body []byte) string {
	m := reTitle.FindSubmatch(body)
	if m == nil {
		return ""
	}
	return strings.TrimSpace(html.UnescapeString(string(m[1])))
}

func hostOf(rawURL string) string {
	u, err := url.Parse(rawURL)
	if err != nil {
		return ""
	}
	return u.Hostname()
}

func uniq(in []string) []string {
	seen := map[string]struct{}{}
	out := in[:0]
	for _, s := range in {
		if _, ok := seen[s]; ok {
			continue
		}
		seen[s] = struct{}{}
		out = append(out, s)
	}
	return out
}
