// Package traffic implements the request-recording subsystem (docs §10): an
// embedded pooled HTTP/HTTPS MITM proxy that asynchronously records target HTTP
// exchanges into PostgreSQL (or legacy SQLite) with content-addressed files for
// large bodies. Full capture, plaintext (no redaction), target HTTP only.
package traffic

import (
	"bytes"
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"log"
	"net"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
	"unicode/utf8"

	"github.com/RC-CHN/ARTEX/db"
	"github.com/RC-CHN/ARTEX/norma/permission"
	actool "github.com/RC-CHN/ARTEX/norma/tool"
	"github.com/google/uuid"
	_ "modernc.org/sqlite"
)

const indexSchema = `
CREATE TABLE IF NOT EXISTS exchanges (
  id           TEXT PRIMARY KEY,
  ts           INTEGER,
  host         TEXT,
  method       TEXT,
  url_template TEXT,
  url          TEXT,
  status       INTEGER,
  content_type TEXT,
  req_len      INTEGER,
  resp_len     INTEGER,
  path         TEXT
);
CREATE INDEX IF NOT EXISTS idx_ex_host ON exchanges(host);
CREATE INDEX IF NOT EXISTS idx_ex_tmpl ON exchanges(host, url_template);
CREATE INDEX IF NOT EXISTS idx_ex_ts   ON exchanges(ts);
CREATE INDEX IF NOT EXISTS idx_ex_status ON exchanges(status);
CREATE INDEX IF NOT EXISTS idx_ex_resp   ON exchanges(resp_len);

CREATE TABLE IF NOT EXISTS exchange_bodies (
  id        TEXT PRIMARY KEY,
  req_head  TEXT NOT NULL DEFAULT '',
  req_body  BLOB,
  req_blob  TEXT,
  resp_head TEXT NOT NULL DEFAULT '',
  resp_body BLOB,
  resp_blob TEXT
);

CREATE TABLE IF NOT EXISTS blob_refs (
  hash        TEXT NOT NULL,
  exchange_id TEXT NOT NULL,
  PRIMARY KEY (hash, exchange_id)
);
CREATE INDEX IF NOT EXISTS idx_blob_refs_ex ON blob_refs(exchange_id);
`

// ftsSchema is applied separately from indexSchema: a driver build without FTS5
// must degrade to "no full-text search" rather than take the whole recorder down.
// trigram (not the default unicode61) is required for two reasons this subsystem
// depends on: it matches arbitrary substrings — "ssw0r" finds "P@ssw0rd" — and it
// handles CJK, which unicode61 does not tokenize. Contentless (content=”) keeps
// only the index, since the text itself lives in exchange_bodies; contentless_delete
// lets rows be deleted without replaying the original text back in.
const ftsSchema = `CREATE VIRTUAL TABLE IF NOT EXISTS ex_fts USING fts5(
  content, tokenize='trigram', content='', contentless_delete=1
);`

const (
	// maxInlineBody is the cutoff between a body stored inline (database column) and
	// one spilled to the content-addressed blob store (16 KiB).
	maxInlineBody = 16 * 1024
	// blobPreview is how much of a spilled body stays inline so readers can tell
	// what it is (JSON shape, SQL dump header, ZIP magic) without fetching it.
	blobPreview = 8 * 1024
	// maxIndexBody caps a single body's contribution to the full-text index (64 KiB).
	// Text is indexed up to this cap; static assets and binary bodies are skipped.
	maxIndexBody = 64 * 1024
	// ingestQueueCap bounds the async recording queue between the proxy response
	// path and the background persistence worker so slow DB/GC ops never stall HTTP.
	ingestQueueCap = 1024
	// ingestBatchSize bounds how many queued exchanges are persisted per DB transaction.
	ingestBatchSize = 32
	// defaultRetentionInterval, defaultRetentionMaxAge, and defaultRetentionMaxRows
	// configure the background retention pruner.
	defaultRetentionInterval = time.Hour
	defaultRetentionMaxAge   = 7 * 24 * time.Hour
	defaultRetentionMaxRows  = 100000
	// minTrigram is the shortest term the trigram tokenizer can match; shorter
	// queries fall back to metadata LIKE.
	minTrigram = 3
	// maxBlobRead caps one traffic_blob read so paging through a large body never
	// floods the agent's context.
	maxBlobRead = 8 * 1024
	// autoVacuumIncremental is SQLite's numeric value for auto_vacuum=incremental.
	autoVacuumIncremental = 2
	// reclaimChunkPages bounds how much index space one locked step returns to the
	// filesystem (pages are 4KiB, so ~32MB). Reclamation holds the write lock, so
	// bounded chunks keep background persistence responsive.
	reclaimChunkPages = 8192
	// reclaimMergePages bounds the full-text merge done alongside each chunk.
	// Deleting from a contentless_delete index only writes tombstones; merging is
	// what discards them, and left undone the index grows on every deletion.
	reclaimMergePages = 256
	// reclaimMergeSteps bounds how many merges one reclamation performs. fts5
	// offers no way to ask whether an index has settled — its special INSERT
	// registers a row change of its own, so change counting cannot tell a real
	// merge from a no-op — so the budget is simply spent down, and whatever is
	// left over falls to the next deletion.
	reclaimMergeSteps = 16
	// reclaimMaxSteps backstops the loop. Both merging and incremental_vacuum are
	// documented to stop making progress eventually, but a reclamation that cannot
	// converge must give up rather than spin holding the write lock.
	reclaimMaxSteps = 512
	// reclaimBudget caps one background reclamation. Deleting a busy host can free
	// gigabytes, and the next deletion resumes wherever this one stopped.
	reclaimBudget = 5 * time.Minute
)

// TrafficSearchDescription is persisted into the tool catalog for new and
// upgraded installations. Keep it in the traffic package so the runtime tool
// and the catalog migration cannot drift apart.
const TrafficSearchDescription = "查询记录代理已抓取的目标流量（必须指定 host；支持裸主机、主机:端口或完整 URL，可再按 URL 子串或正文关键词过滤）。指定端口时只返回该服务的流量，避免同一 IP 的不同端口串包。body_contains 会在已抓取的请求/响应头与正文中做全文搜索，支持任意子串和中文（至少 3 个字符）。仅返回极轻量索引(id/method/url/status/resp_len)，不含响应内容；结果非空后必须用 traffic_get 逐条核实请求/响应，再把确实支持当前漏洞的 ID 交给 bind_finding_traffic。默认只返回 3 条、每页最多 10 条；结果多时用 page 翻页。"

// Traffic runs the recording proxy and owns the file tree + index.
type Traffic struct {
	dir   string
	addr  string
	db    *indexDB
	wmu   sync.Mutex // serializes DB/GC mutations (recordBatch DB commit, DeleteHost, DeleteAll, PruneExchanges)
	proxy *mitmProxy
	// fts reports whether the full-text index is available. False on a driver
	// build without FTS5: recording and metadata search still work, body search
	// degrades to unsupported rather than erroring.
	fts bool
	// reaping tracks finite background reclamation of legacy trees and index space,
	// so shutdown and tests can wait for it via reaping.Wait() before Close.
	reaping sync.WaitGroup
	// retentionWG tracks the long-lived periodic retention pruner goroutine,
	// stopped cleanly by Close() closing t.closed.
	retentionWG sync.WaitGroup
	// incrementalVacuum reports whether the index can return freed pages to the
	// filesystem on its own. False on a database created before this was the
	// default: PRAGMA incremental_vacuum is a silent no-op there, so deletions
	// reclaim nothing until an explicit full compaction converts the file.
	incrementalVacuum bool
	// reclaiming keeps a single background reclamation in flight. Concurrent ones
	// would only contend for wmu, never finish sooner.
	reclaiming atomic.Bool
	// closed is shut by Close so background workers abandon remaining budgets
	// instead of holding shutdown open. Nil on the zero value, which stopping()
	// treats as "not closing".
	closed    chan struct{}
	closeOnce sync.Once
	closeErr  error
	// lifecycleMu serializes proxy start, recorder/reaper admission, and close.
	lifecycleMu   sync.Mutex
	closing       bool
	recordsClosed bool
	started       bool
	startDone     chan struct{}
	recording     sync.WaitGroup
	// Async bounded ingestion queue decoupling HTTP proxy responses from wmu/DB/GC.
	ingestMu     sync.Mutex
	ingestCh     chan *capturedFlow
	ingestDone   chan struct{}
	ingestClosed bool
	ingestSeq    atomic.Int64
	droppedFlows atomic.Int64
	flushMu      sync.Mutex
	flushedSeq   int64
	flushNotify  chan struct{}
	// inflightBlobs pins hashes currently being spilled outside wmu so concurrent
	// gcBlobs cannot remove a freshly written blob before its blob_refs row lands.
	inflightMu    sync.Mutex
	inflightBlobs map[string]int
	gcGen         atomic.Uint64
	// exportMu coordinates active streaming ExportHosts readers with gcBlobs so
	// blobs queried on a page can never be unlinked before exportBlobFile opens them.
	exportMu        sync.Mutex
	exportsInFlight int
	gcDeferred      bool
	// pass is the bounded LRU set of hosts whose MITM interception failed for a
	// proxy/protocol reason; connections to them are tunneled transparently.
	pass hostLRU
	// upstream is the global egress proxy every captured request is forwarded
	// through (nil = dial targets directly). Both the intercepted and the
	// transparent-passthrough paths honor it, so no host escapes it.
	// Hot-swappable at runtime via SetUpstreamProxy.
	upstream atomic.Pointer[url.URL]
}

// Open opens the legacy SQLite backend for migration tooling and benchmarks.
// The application uses OpenPostgres; new production captures never use SQLite.
func Open(dir, addr string) (*Traffic, error) {
	for _, d := range []string{dir, filepath.Join(dir, "_index"), filepath.Join(dir, "_blobs"), filepath.Join(dir, "_ca")} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			return nil, err
		}
	}
	// busy_timeout is a per-connection setting, so it belongs in the DSN rather
	// than in a one-off Exec: the pool opens connections on demand, and an Exec
	// only configures whichever one happened to serve it — leaving every other
	// connection to fail instantly the moment a writer holds the database.
	// The driver splits the DSN at the first '?', so a data directory containing
	// one would silently name a different file; that path falls back to a bare
	// DSN, where initIndex still applies the pragmas to its own connection.
	index := filepath.Join(dir, "_index", "index.sqlite")
	dsn := index
	if !strings.ContainsRune(index, '?') {
		dsn = "file:" + index + "?_pragma=busy_timeout(5000)&_pragma=journal_mode(WAL)"
	}
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, err
	}
	t := &Traffic{dir: dir, addr: addr, db: &indexDB{DB: db}, closed: make(chan struct{})}
	if err := t.initIndex(); err != nil {
		db.Close()
		return nil, err
	}

	return t.startProxy()
}

func (t *Traffic) startProxy() (*Traffic, error) {
	p, err := newMITMProxy(mitmProxyConfig{
		Addr:            t.addr,
		CADir:           filepath.Join(t.dir, "_ca"),
		UpstreamFn:      func() *url.URL { return t.upstream.Load() },
		IsPassthroughFn: t.isPassthrough,
		OnRecordFn:      func(f *capturedFlow) { t.enqueueFlow(f) },
		OnErrorFn:       t.maybePassthroughHost,
	})
	if err != nil {
		t.db.Close()
		return nil, err
	}
	t.proxy = p
	t.startIngest()
	t.startRetention(defaultRetentionInterval, defaultRetentionMaxAge, defaultRetentionMaxRows)
	return t, nil
}

// initIndex applies the schema on a single pinned connection. Pinning is what
// makes auto_vacuum reliable: it can only be set while the database still holds
// no tables, and only the VACUUM that follows writes it into the file header —
// two steps a pooled *sql.DB is free to route to different connections, which
// would silently drop the setting.
//
// auto_vacuum=incremental is what lets a deletion hand freed pages back to the
// filesystem. Without it SQLite merely chains them onto its freelist, so the
// index file never shrinks no matter how much traffic is deleted — and since
// every body below maxInlineBody lives in that file, plus a trigram index
// roughly twice the size of the text it covers, a capture-heavy install ends up
// holding gigabytes for traffic it no longer has. On a database that already has
// tables the pragma is a documented no-op, so installs created before this keep
// auto_vacuum=0 until a full compaction converts the file; incrementalVacuum
// records that so reclaim can say so instead of pretending to reclaim.
func (t *Traffic) initIndex() error {
	ctx := context.Background()
	conn, err := t.db.Conn(ctx)
	if err != nil {
		return err
	}
	defer conn.Close()
	// Re-applied rather than left to the DSN so the bare-DSN fallback in Open is
	// still correct: journal_mode persists in the file header, which is what every
	// later connection reads.
	for _, p := range []string{`PRAGMA journal_mode=WAL`, `PRAGMA busy_timeout=5000`} {
		if _, err := conn.ExecContext(ctx, p); err != nil {
			return err
		}
	}
	var tables int
	if err := conn.QueryRowContext(ctx, `SELECT count(*) FROM sqlite_master WHERE type='table'`).Scan(&tables); err != nil {
		return err
	}
	if tables == 0 {
		for _, p := range []string{`PRAGMA auto_vacuum=incremental`, `VACUUM`} {
			if _, err := conn.ExecContext(ctx, p); err != nil {
				return err
			}
		}
	}
	var mode int
	if err := conn.QueryRowContext(ctx, `PRAGMA auto_vacuum`).Scan(&mode); err != nil {
		return err
	}
	t.incrementalVacuum = mode == autoVacuumIncremental
	if !t.incrementalVacuum {
		log.Printf("[traffic] 索引库未启用增量回收（auto_vacuum=%d）：删除流量不会缩小 index.sqlite，需要执行一次存储压缩来转换", mode)
	}
	if _, err := conn.ExecContext(ctx, indexSchema); err != nil {
		return err
	}
	if _, err := conn.ExecContext(ctx, ftsSchema); err != nil {
		log.Printf("[traffic] 全文索引不可用，正文搜索将被禁用（元数据搜索不受影响）：%v", err)
		return nil
	}
	t.fts = true
	return nil
}

// hostOnly strips an optional :port, so passthrough keys match whether the host
// arrives as "example.com:443" (CONNECT) or "example.com" (request URL).
func hostOnly(hostport string) string {
	if h, _, err := net.SplitHostPort(hostport); err == nil {
		return h
	}
	return hostport
}

// effectiveListenAddr returns the actual bound TCP address once the proxy has
// started listening, falling back to the configured t.addr.
func (t *Traffic) effectiveListenAddr() string {
	if t == nil {
		return ""
	}
	if t.proxy != nil {
		if a := strings.TrimSpace(t.proxy.ListenAddr()); a != "" {
			return a
		}
	}
	return strings.TrimSpace(t.addr)
}

// ProxyAddr returns the address workers should set as HTTP(S)_PROXY. A bare
// ":port" means "bind all interfaces" (legacy default), so map it to loopback.
func (t *Traffic) ProxyAddr() string {
	addr := t.effectiveListenAddr()
	if strings.HasPrefix(addr, ":") {
		return "http://127.0.0.1" + addr
	}
	return "http://" + addr
}

// SetUpstreamProxy points every captured request at a global egress proxy
// (http/https/socks5, optional user:pass in the URL). An empty raw string clears
// it, restoring direct dialing. The change is atomic and takes effect on the next
// connection — no restart, no proxy rebuild. Self-looping URLs targeting this
// proxy's own listening address are rejected.
func (t *Traffic) SetUpstreamProxy(raw string) error {
	if strings.TrimSpace(raw) == "" {
		t.upstream.Store(nil)
		if t.proxy != nil {
			t.proxy.CloseIdleConnections()
		}
		return nil
	}
	u, err := ValidateProxyURLForSelf(raw, t.effectiveListenAddr())
	if err != nil {
		return err
	}
	t.upstream.Store(u)
	if t.proxy != nil {
		t.proxy.CloseIdleConnections()
	}
	return nil
}

// ValidateProxyURL parses and checks a proxy URL (http/https/socks5/socks5h,
// optional user:pass), returning the parsed URL. Exposed so callers can validate
// a global proxy before persisting it even when the traffic proxy itself is disabled.
func ValidateProxyURL(raw string) (*url.URL, error) {
	raw = strings.TrimSpace(raw)
	safe := redactRawProxyURL(raw)
	u, err := url.Parse(raw)
	if err != nil {
		var uerr *url.Error
		if errors.As(err, &uerr) && uerr.Err != nil {
			return nil, fmt.Errorf("解析代理地址 %q: %w", safe, uerr.Err)
		}
		return nil, fmt.Errorf("解析代理地址 %q: 格式无效", safe)
	}
	switch u.Scheme {
	case "http", "https", "socks5", "socks5h":
	case "":
		return nil, fmt.Errorf("代理 %q 缺少协议(用 http://、https://、socks5:// 或 socks5h://)", safe)
	default:
		return nil, fmt.Errorf("不支持的代理协议 %q(用 http、https、socks5 或 socks5h)", u.Scheme)
	}
	if u.Host == "" {
		return nil, fmt.Errorf("代理 %q 缺少主机地址", safe)
	}
	return u, nil
}

// redactRawProxyURL strips userinfo credentials from a raw proxy string before
// it is interpolated into error messages (even when url.Parse rejects the input).
func redactRawProxyURL(raw string) string {
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

// ValidateProxyURLForSelf validates raw as a proxy URL and additionally rejects
// addresses that point back at selfAddr (the recording proxy's own listen
// address), preventing infinite self-loop forwarding.
func ValidateProxyURLForSelf(raw, selfAddr string) (*url.URL, error) {
	u, err := ValidateProxyURL(raw)
	if err != nil {
		return nil, err
	}
	if isSelfProxyLoop(u, selfAddr) {
		return nil, fmt.Errorf("上游代理地址 %q 指向录制代理自身监听地址 %s，会造成代理自环", u.Redacted(), selfAddr)
	}
	return u, nil
}

func isSelfProxyLoop(u *url.URL, selfAddr string) bool {
	selfHost, selfPort, ok := splitListenHostPort(selfAddr)
	if !ok || selfPort == "" || selfPort == "0" {
		return false
	}
	targetPort := u.Port()
	if targetPort == "" {
		switch u.Scheme {
		case "http":
			targetPort = "80"
		case "https":
			targetPort = "443"
		case "socks5", "socks5h":
			targetPort = "1080"
		}
	}
	if targetPort != selfPort {
		return false
	}
	targetHost := normalizeAddrHost(u.Hostname())
	selfHost = normalizeAddrHost(selfHost)
	if targetHost == "" {
		return false
	}
	if targetHost == selfHost {
		return true
	}
	if tip, sip := net.ParseIP(targetHost), net.ParseIP(selfHost); tip != nil && sip != nil && tip.Equal(sip) {
		return true
	}
	targetLoopOrAny := isLoopbackOrWildcardHost(targetHost)
	selfWildcard := isWildcardHost(selfHost)
	if selfWildcard && (targetLoopOrAny || isLocalInterfaceHost(targetHost)) {
		return true
	}
	if isLoopbackOrWildcardHost(selfHost) && targetLoopOrAny {
		return true
	}
	return false
}

func splitListenHostPort(addr string) (host, port string, ok bool) {
	addr = strings.TrimSpace(addr)
	if addr == "" {
		return "", "", false
	}
	if strings.Contains(addr, "://") {
		if u, err := url.Parse(addr); err == nil && u.Host != "" {
			return u.Hostname(), u.Port(), true
		}
		return "", "", false
	}
	h, p, err := net.SplitHostPort(addr)
	if err != nil {
		return "", "", false
	}
	return h, p, true
}

func normalizeAddrHost(h string) string {
	h = strings.ToLower(strings.TrimSpace(h))
	h = strings.Trim(h, "[]")
	return strings.TrimSuffix(h, ".")
}

func isWildcardHost(h string) bool {
	if h == "" || h == "0.0.0.0" || h == "::" {
		return true
	}
	if ip := net.ParseIP(h); ip != nil && ip.IsUnspecified() {
		return true
	}
	return false
}

func isLoopbackOrWildcardHost(h string) bool {
	if isWildcardHost(h) || h == "localhost" || strings.HasSuffix(h, ".localhost") {
		return true
	}
	if ip := net.ParseIP(h); ip != nil && ip.IsLoopback() {
		return true
	}
	return false
}

func isLocalInterfaceHost(h string) bool {
	ip := net.ParseIP(h)
	if ip == nil {
		return false
	}
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		return false
	}
	for _, a := range addrs {
		var ifaceIP net.IP
		switch v := a.(type) {
		case *net.IPNet:
			ifaceIP = v.IP
		case *net.IPAddr:
			ifaceIP = v.IP
		}
		if ifaceIP != nil && ifaceIP.Equal(ip) {
			return true
		}
	}
	return false
}

// CACertPath returns the PEM CA cert clients must trust to verify HTTPS through
// the MITM proxy.
func (t *Traffic) CACertPath() string {
	return filepath.Join(t.dir, "_ca", "mitmproxy-ca-cert.pem")
}

// stopping reports whether Close has been called. A nil channel (the zero value)
// is never ready, so this reads as "not closing" without a separate guard.
func (t *Traffic) stopping() bool {
	select {
	case <-t.closed:
		return true
	default:
		return false
	}
}
func (t *Traffic) DB() *sql.DB { return t.db.DB }

// Backend reports the active index engine, independently of file/blob storage.
func (t *Traffic) Backend() string {
	if t.db.postgres {
		return "postgres"
	}
	return "sqlite"
}

// isPassthrough reports whether host has been flagged for transparent tunneling.
func (t *Traffic) isPassthrough(host string) bool {
	return t.pass.Has(host)
}

// maybePassthroughHost marks a host to be tunneled transparently on the next
// connection, but only for errors the proxy itself caused — a target that is
// simply down/filtered would fail without us too, and must stay MITM'd+recorded.
func (t *Traffic) maybePassthroughHost(host string, err error) {
	if err == nil || !proxyCausedErr(err) {
		return
	}
	host = hostOnly(strings.TrimSpace(host))
	if host == "" {
		return
	}
	if t.pass.Add(host) {
		log.Printf("[traffic] 与 %s 的 MITM 出错，改为透传（该 host 后续直连目标、不再记录，但请求照常）：%v", host, err)
	}
}

func (t *Traffic) maybePassthrough(f *capturedFlow, err error) {
	if err == nil || f == nil || f.Request == nil || f.Request.URL == nil {
		return
	}
	t.maybePassthroughHost(f.Request.URL.Hostname(), err)
}

// proxyCausedErr reports whether err indicates the interception layer (not the
// target) is at fault — HTTP/2 handling, HEAD-with-body, or a protocol violation.
func proxyCausedErr(err error) bool {
	s := strings.ToLower(err.Error())
	for _, p := range []string{"head request", "http2", "http/2", "protocol error", "protocol_error", "malformed"} {
		if strings.Contains(s, p) {
			return true
		}
	}
	return false
}

// startIngest launches the background ingestion goroutine that drains batches
// from ingestCh and persists them without blocking proxy response delivery.
func (t *Traffic) startIngest() {
	t.ingestMu.Lock()
	if t.ingestCh != nil {
		t.ingestMu.Unlock()
		return
	}
	ch := make(chan *capturedFlow, ingestQueueCap)
	done := make(chan struct{})
	t.ingestCh = ch
	t.ingestDone = done
	t.flushMu.Lock()
	t.flushNotify = make(chan struct{})
	t.flushMu.Unlock()
	t.ingestMu.Unlock()

	go t.ingestLoop(ch, done)
}

// enqueueFlow pushes f into the bounded async ingestion queue without blocking.
// If the queue is full or traffic is closing, droppedFlows is incremented and
// false is returned immediately so HTTP responses never stall on DB/GC/wmu.
func (t *Traffic) enqueueFlow(f *capturedFlow) bool {
	if f == nil || f.Request == nil || f.Response == nil || f.Request.URL == nil {
		return false
	}
	t.ingestMu.Lock()
	if t.ingestClosed || t.ingestCh == nil {
		t.ingestMu.Unlock()
		t.droppedFlows.Add(1)
		return false
	}
	select {
	case t.ingestCh <- f:
		t.ingestSeq.Add(1)
		t.ingestMu.Unlock()
		return true
	default:
		t.ingestMu.Unlock()
		t.droppedFlows.Add(1)
		return false
	}
}

// DroppedFlows returns the count of captured exchanges dropped because the
// async ingestion queue was full or shutting down.
func (t *Traffic) DroppedFlows() int64 {
	if t == nil {
		return 0
	}
	return t.droppedFlows.Load()
}

// Flush blocks until all flows enqueued prior to this call have been persisted
// (or ctx is canceled / ingestLoop exits).
func (t *Traffic) Flush(ctx context.Context) error {
	if t == nil {
		return nil
	}
	if ctx == nil {
		ctx = context.Background()
	}
	target := t.ingestSeq.Load()
	for {
		t.flushMu.Lock()
		if t.flushedSeq >= target {
			t.flushMu.Unlock()
			return nil
		}
		notify := t.flushNotify
		t.flushMu.Unlock()

		t.ingestMu.Lock()
		done := t.ingestDone
		t.ingestMu.Unlock()
		if done == nil {
			return nil
		}
		select {
		case <-notify:
		case <-done:
			return nil
		case <-ctx.Done():
			return ctx.Err()
		}
	}
}

func (t *Traffic) stopIngest() {
	t.ingestMu.Lock()
	if !t.ingestClosed {
		t.ingestClosed = true
		if t.ingestCh != nil {
			close(t.ingestCh)
		}
	}
	done := t.ingestDone
	t.ingestMu.Unlock()
	if done != nil {
		<-done
	}
}

func (t *Traffic) ingestLoop(ch <-chan *capturedFlow, done chan struct{}) {
	defer close(done)
	batch := make([]*capturedFlow, 0, ingestBatchSize)
	for first := range ch {
		batch = append(batch[:0], first)
	drain:
		for len(batch) < ingestBatchSize {
			select {
			case next, ok := <-ch:
				if !ok {
					break drain
				}
				batch = append(batch, next)
			default:
				break drain
			}
		}
		if err := t.recordBatch(batch); err != nil && !errors.Is(err, ErrClosed) {
			log.Printf("[traffic] 批量记录流量(%d条)失败: %v", len(batch), err)
		}
		t.flushMu.Lock()
		t.flushedSeq += int64(len(batch))
		close(t.flushNotify)
		t.flushNotify = make(chan struct{})
		t.flushMu.Unlock()
	}
}

// record is a synchronous test/internal helper that logs errors from recordFlow.
func (t *Traffic) record(f *capturedFlow) {
	if err := t.recordFlow(f); err != nil {
		log.Printf("[traffic] 记录流量失败: %v", err)
	}
}

// recordFlow persists a single exchange synchronously, exposing errors to tests,
// migration, and benchmarks.
func (t *Traffic) recordFlow(f *capturedFlow) error {
	if f == nil || f.Request == nil || f.Response == nil || f.Request.URL == nil {
		return nil
	}
	return t.recordBatch([]*capturedFlow{f})
}

type preparedExchange struct {
	item     ArchiveExchange
	content  string
	reqRaw   []byte
	respRaw  []byte
	reqHash  string
	respHash string
}

// recordBatch spills large content-addressed blobs outside t.wmu (pinned against
// concurrent blob GC) and commits all metadata, inline bodies, blob_refs, and
// search documents in one short database transaction under t.wmu.
func (t *Traffic) recordBatch(flows []*capturedFlow) error {
	if len(flows) == 0 {
		return nil
	}
	if !t.beginRecording() {
		return ErrClosed
	}
	defer t.recording.Done()

	gcGenBefore := t.gcGen.Load()
	prepared := make([]preparedExchange, 0, len(flows))
	pinned := make([]string, 0, len(flows))
	defer func() {
		if len(pinned) > 0 {
			t.unpinBlobs(pinned)
		}
	}()

	now := time.Now().Unix()
	for _, f := range flows {
		if f == nil || f.Request == nil || f.Response == nil || f.Request.URL == nil {
			continue
		}
		reqCT := f.Request.Header.Get("Content-Type")
		respCT := f.Response.Header.Get("Content-Type")
		reqB := t.spillOutsideLock(f.Request.Body, reqCT, false, &pinned)
		skipRespIdx := shouldSkipRespBodyIndex(f.Request.URL.Path, respCT)
		respB := t.spillOutsideLock(f.Response.Body, respCT, skipRespIdx, &pinned)

		proto := f.Request.Proto
		if proto == "" {
			proto = "HTTP/1.1"
		}
		item := ArchiveExchange{
			ID: uuid.NewString(), TS: now, Host: strings.ToLower(f.Request.URL.Hostname()),
			Method: f.Request.Method, URLTemplate: db.TemplatePath(f.Request.URL.EscapedPath()),
			URL: f.Request.URL.String(), Status: f.Response.StatusCode, ContentType: respCT,
			ReqLen: len(f.Request.Body), RespLen: len(f.Response.Body),
			ReqHead:  fmt.Sprintf("%s %s %s\n%s", f.Request.Method, f.Request.URL.RequestURI(), proto, requestHeaderLines(f.Request)),
			RespHead: fmt.Sprintf("HTTP %d\n%s", f.Response.StatusCode, headerLines(f.Response.Header)),
			ReqBody:  reqB.inline, RespBody: respB.inline, ReqBlob: reqB.hash, RespBlob: respB.hash,
		}
		content := buildSearchDocument(item.URL, item.ReqHead, reqB.index, item.RespHead, respB.index)
		prepared = append(prepared, preparedExchange{
			item:     item,
			content:  content,
			reqRaw:   f.Request.Body,
			respRaw:  f.Response.Body,
			reqHash:  reqB.hash,
			respHash: respB.hash,
		})
	}
	if len(prepared) == 0 {
		return nil
	}

	t.wmu.Lock()
	defer t.wmu.Unlock()

	// If gcBlobs ran concurrently while we were spilling outside wmu, verify that
	// every referenced blob file still exists on disk before inserting blob_refs.
	if t.gcGen.Load() != gcGenBefore {
		for _, p := range prepared {
			if p.reqHash != "" {
				_ = t.ensureBlobFile(p.reqHash, p.reqRaw)
			}
			if p.respHash != "" {
				_ = t.ensureBlobFile(p.respHash, p.respRaw)
			}
		}
	}

	if t.db.postgres && len(prepared) == 1 {
		_, err := t.db.Exec(postgresInsertExchange, exchangeArgs(prepared[0].item, "", prepared[0].content)...)
		return err
	}
	tx, err := t.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	for _, p := range prepared {
		if t.db.postgres {
			if _, err := tx.Exec(postgresInsertExchange, exchangeArgs(p.item, "", p.content)...); err != nil {
				return err
			}
		} else {
			if err := t.insertExchange(tx, p.item, "", p.content); err != nil {
				return err
			}
		}
	}
	return tx.Commit()
}

// buildSearchDocument joins URL, headers, and indexable body slices in a single
// builder allocation and normalizes NUL / invalid UTF-8 in one pass.
func buildSearchDocument(rawURL, reqHead, reqBodyIdx, respHead, respBodyIdx string) string {
	total := len(rawURL) + len(reqHead) + len(reqBodyIdx) + len(respHead) + len(respBodyIdx) + 4
	var b strings.Builder
	b.Grow(total)
	b.WriteString(rawURL)
	b.WriteByte('\n')
	b.WriteString(reqHead)
	b.WriteByte('\n')
	b.WriteString(reqBodyIdx)
	b.WriteByte('\n')
	b.WriteString(respHead)
	b.WriteByte('\n')
	b.WriteString(respBodyIdx)
	return cleanIndexText(b.String())
}

// insertExchange writes the SQLite reference backend used by tests and benchmarks.
func (t *Traffic) insertExchange(tx *indexTx, item ArchiveExchange, path, content string) error {
	var rowid int64
	err := tx.QueryRow(`INSERT INTO exchanges(id,ts,host,method,url_template,url,status,content_type,req_len,resp_len,path)
VALUES(?,?,?,?,?,?,?,?,?,?,?) RETURNING rowid`, item.ID, item.TS, item.Host, item.Method, item.URLTemplate,
		item.URL, item.Status, item.ContentType, item.ReqLen, item.RespLen, path).Scan(&rowid)
	if err != nil {
		return err
	}
	if _, err := tx.Exec(`INSERT INTO exchange_bodies(id,req_head,req_body,req_blob,resp_head,resp_body,resp_blob)
VALUES(?,?,?,?,?,?,?)`, item.ID, t.headerValue(item.ReqHead), item.ReqBody, nullIfEmpty(item.ReqBlob), t.headerValue(item.RespHead), item.RespBody, nullIfEmpty(item.RespBlob)); err != nil {
		return err
	}
	for _, hash := range []string{item.ReqBlob, item.RespBlob} {
		if hash != "" {
			if _, err := tx.Exec(`INSERT INTO blob_refs(hash,exchange_id) VALUES(?,?) ON CONFLICT DO NOTHING`, hash, item.ID); err != nil {
				return err
			}
		}
	}
	if t.fts {
		_, err = tx.Exec(`INSERT INTO ex_fts(rowid,content) VALUES(?,?)`, rowid, cleanIndexText(content))
	}
	return err
}

func (t *Traffic) pinBlob(hash string) {
	t.inflightMu.Lock()
	if t.inflightBlobs == nil {
		t.inflightBlobs = make(map[string]int)
	}
	t.inflightBlobs[hash]++
	t.inflightMu.Unlock()
}

func (t *Traffic) unpinBlobs(hashes []string) {
	t.inflightMu.Lock()
	for _, h := range hashes {
		if n := t.inflightBlobs[h]; n <= 1 {
			delete(t.inflightBlobs, h)
		} else {
			t.inflightBlobs[h] = n - 1
		}
	}
	t.inflightMu.Unlock()
}

func (t *Traffic) isBlobPinned(hash string) bool {
	t.inflightMu.Lock()
	n := t.inflightBlobs[hash]
	t.inflightMu.Unlock()
	return n > 0
}

func (t *Traffic) snapshotPinnedBlobs(dst map[string]struct{}) {
	t.inflightMu.Lock()
	for h := range t.inflightBlobs {
		dst[h] = struct{}{}
	}
	t.inflightMu.Unlock()
}

// storedBody is one body after the inline/spill decision: inline is what goes in
// the database column (the whole body, or a preview when spilled), hash names the
// blob when it spilled, and index is the text handed to FTS (empty for binary or
// skipped static assets).
type storedBody struct {
	inline []byte
	hash   string
	index  string
}

func (t *Traffic) ensureBlobFile(h string, body []byte) error {
	blobDir := filepath.Join(t.dir, "_blobs", "sha256", h[:2])
	if err := os.MkdirAll(blobDir, 0o755); err != nil {
		return err
	}
	blobPath := filepath.Join(blobDir, h+".bin")
	if _, err := os.Stat(blobPath); err == nil {
		return nil
	} else if !os.IsNotExist(err) {
		return err
	}
	tmp, err := os.CreateTemp(blobDir, ".blob-*")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	if _, err := tmp.Write(body); err != nil {
		_ = tmp.Close()
		_ = os.Remove(tmpName)
		return err
	}
	if err := tmp.Close(); err != nil {
		_ = os.Remove(tmpName)
		return err
	}
	_ = os.Chmod(tmpName, 0o644)
	if err := os.Rename(tmpName, blobPath); err != nil {
		_ = os.Remove(tmpName)
		if _, statErr := os.Stat(blobPath); statErr == nil {
			return nil
		}
		return err
	}
	return nil
}

// spillOutsideLock decides whether body stays inline or spills to the
// content-addressed blob store. Blobs are pinned before writing so concurrent
// blob GC cannot reap them before the DB transaction inserts blob_refs.
func (t *Traffic) spillOutsideLock(body []byte, contentType string, skipIndex bool, pinned *[]string) storedBody {
	if len(body) == 0 {
		return storedBody{}
	}
	text := !isBinaryBody(contentType, body)
	indexText := func() string {
		if !text || skipIndex {
			return ""
		}
		return truncateUTF8(body, maxIndexBody)
	}
	if len(body) <= maxInlineBody {
		return storedBody{inline: body, index: indexText()}
	}

	sum := sha256.Sum256(body)
	h := hex.EncodeToString(sum[:])
	t.pinBlob(h)
	*pinned = append(*pinned, h)
	if err := t.ensureBlobFile(h, body); err != nil {
		log.Printf("[traffic] 写 blob %s 失败：%v", h, err)
		return storedBody{inline: clipBytes(body, blobPreview), index: indexText()}
	}
	sb := storedBody{hash: h, index: indexText()}
	if text {
		sb.inline = []byte(truncateUTF8(body, blobPreview))
	} else {
		sb.inline = []byte(binaryTag(contentType, body))
	}
	return sb
}

// staticAssetExts lists static asset extensions whose response bodies bloat
// trigram full-text indexes without adding search value (URL + headers remain indexed).
var staticAssetExts = map[string]struct{}{
	".js":    {},
	".css":   {},
	".png":   {},
	".jpg":   {},
	".jpeg":  {},
	".gif":   {},
	".webp":  {},
	".svg":   {},
	".woff":  {},
	".woff2": {},
	".ttf":   {},
	".ico":   {},
	".map":   {},
}

// skipIndexContentTypes lists binary content-type prefixes skipped from ex_fts body indexing.
var skipIndexContentTypes = []string{
	"image/", "font/", "audio/", "video/",
	"application/octet-stream", "application/wasm",
}

// shouldSkipRespBodyIndex reports whether a response body should be omitted from
// ex_fts full-text indexing (URL and HTTP headers are still indexed).
func shouldSkipRespBodyIndex(urlOrPath, contentType string) bool {
	p := urlOrPath
	if idx := strings.IndexAny(p, "?#"); idx >= 0 {
		p = p[:idx]
	}
	if ext := strings.ToLower(path.Ext(p)); ext != "" {
		if _, ok := staticAssetExts[ext]; ok {
			return true
		}
	}
	ct := strings.ToLower(strings.TrimSpace(contentType))
	if i := strings.IndexByte(ct, ';'); i >= 0 {
		ct = strings.TrimSpace(ct[:i])
	}
	for _, prefix := range skipIndexContentTypes {
		if strings.HasPrefix(ct, prefix) {
			return true
		}
	}
	return false
}

// binaryTypes are content-type prefixes whose bodies are never worth indexing or
// previewing as text. Anything not listed is treated as text (with a NUL-byte
// check as backstop), so unusual-but-searchable types like application/sql or a
// bare text/* are not silently dropped from the index.
var binaryTypes = []string{
	"image/", "audio/", "video/", "font/",
	"application/octet-stream", "application/zip", "application/gzip",
	"application/x-gzip", "application/x-tar", "application/x-7z-compressed",
	"application/x-rar", "application/pdf", "application/x-msdownload",
	"application/vnd.android.package-archive", "application/java-archive",
	"application/wasm", "application/x-shockwave-flash",
}

func isBinaryBody(contentType string, body []byte) bool {
	ct := strings.ToLower(strings.TrimSpace(contentType))
	if i := strings.IndexByte(ct, ';'); i >= 0 {
		ct = strings.TrimSpace(ct[:i])
	}
	for _, p := range binaryTypes {
		if strings.HasPrefix(ct, p) {
			return true
		}
	}
	// Backstop for mislabeled or absent content types: real text does not carry
	// NUL bytes, so a NUL in the head of the body means binary regardless.
	return bytes.IndexByte(clipBytes(body, 512), 0) >= 0
}

// binaryTag describes a spilled binary body in one line, including the leading
// magic bytes so a reader can recognize the format without downloading it.
func binaryTag(contentType string, body []byte) string {
	ct := strings.TrimSpace(contentType)
	if ct == "" {
		ct = "application/octet-stream"
	}
	magic := hex.EncodeToString(clipBytes(body, 4))
	return fmt.Sprintf("[binary %s, %d bytes, magic=%s]", ct, len(body), magic)
}

func clipBytes(b []byte, n int) []byte {
	if len(b) <= n {
		return b
	}
	return b[:n]
}

// truncateUTF8 cuts b to at most n bytes without splitting a multi-byte rune,
// so a preview never ends in half a CJK character.
func truncateUTF8(b []byte, n int) string {
	if len(b) <= n {
		return string(b)
	}
	b = b[:n]
	// A rune is at most 4 bytes, so backing off 3 bytes always finds the boundary
	// (unless the input was already invalid UTF-8, in which case we keep the cut).
	for i := 0; i < utf8.UTFMax-1 && len(b) > 0; i++ {
		if r, size := utf8.DecodeLastRune(b); r != utf8.RuneError || size != 1 {
			break
		}
		b = b[:len(b)-1]
	}
	return string(b)
}

func nullIfEmpty(s string) any {
	if s == "" {
		return nil
	}
	return s
}

func headerLines(h map[string][]string) string {
	var b strings.Builder
	for k, vs := range h {
		for _, v := range vs {
			b.WriteString(k)
			b.WriteString(": ")
			b.WriteString(v)
			b.WriteByte('\n')
		}
	}
	return b.String()
}

// requestHeaderLines restores the HTTP Host header, which net/http stores on
// Request.Host rather than in Header. Keeping it in request.http makes the raw
// capture complete and directly replayable.
func requestHeaderLines(req *capturedRequest) string {
	headers := req.Header.Clone()
	headers.Del("Host")
	host := ""
	if req.URL != nil {
		host = req.URL.Host
	}
	if strings.TrimSpace(req.Host) != "" {
		host = req.Host
	}
	var b strings.Builder
	if host = strings.TrimSpace(host); host != "" {
		b.WriteString("Host: ")
		b.WriteString(host)
		b.WriteByte('\n')
	}
	b.WriteString(headerLines(headers))
	return b.String()
}

func sanitize(s string) string {
	r := strings.NewReplacer("/", "_", "\\", "_", ":", "_", "?", "_", "*", "_", "\"", "_", "<", "_", ">", "_", "|", "_")
	out := r.Replace(s)
	if out == "" || out == "_" {
		return "root"
	}
	if len(out) > 120 {
		out = out[:120]
	}
	return out
}

var blobHashRe = regexp.MustCompile(`^[0-9a-f]{64}$`)

// blobPath locates a stored blob. Current writes use one bucket level; blobs
// written before that change used two, so both layouts are probed rather than
// migrated.
func (t *Traffic) blobPath(hash string) (string, error) {
	hash = strings.ToLower(strings.TrimSpace(hash))
	// Validated as pure hex before touching the filesystem, so a crafted hash can
	// never traverse out of the blob directory.
	if !blobHashRe.MatchString(hash) {
		return "", fmt.Errorf("非法的 blob hash")
	}
	for _, p := range []string{
		filepath.Join(t.dir, "_blobs", "sha256", hash[:2], hash+".bin"),
		filepath.Join(t.dir, "_blobs", "sha256", hash[:2], hash[2:4], hash+".bin"),
	} {
		if st, err := os.Stat(p); err == nil && !st.IsDir() {
			return p, nil
		}
	}
	return "", fmt.Errorf("blob %s 不存在", hash)
}

// Blob opens a spilled body for streaming; the caller must close the file.
// Streaming matters here: the driver exposes no incremental BLOB API, so keeping
// large bodies on disk is what lets them be served without loading them whole.
func (t *Traffic) Blob(hash string) (*os.File, int64, error) {
	p, err := t.blobPath(hash)
	if err != nil {
		return nil, 0, err
	}
	f, err := os.Open(p)
	if err != nil {
		return nil, 0, err
	}
	st, err := f.Stat()
	if err != nil {
		f.Close()
		return nil, 0, err
	}
	return f, st.Size(), nil
}

// BlobRange reads at most length bytes of a blob from offset, and reports the
// blob's total size. Used by the agent tool to page through a large body without
// pulling all of it into the model's context.
func (t *Traffic) BlobRange(hash string, offset, length int64) (data []byte, total int64, err error) {
	f, size, err := t.Blob(hash)
	if err != nil {
		return nil, 0, err
	}
	defer f.Close()
	if offset < 0 {
		offset = 0
	}
	if offset >= size {
		return nil, size, nil
	}
	if length <= 0 || offset+length > size {
		length = size - offset
	}
	buf := make([]byte, length)
	n, err := f.ReadAt(buf, offset)
	if err != nil && !errors.Is(err, io.EOF) {
		return nil, size, err
	}
	return buf[:n], size, nil
}

// ExchangeMeta is one row of the index (returned by Search).
type ExchangeMeta struct {
	ID          string `json:"id"`
	TS          int64  `json:"ts"`
	Host        string `json:"host"`
	Method      string `json:"method"`
	URLTemplate string `json:"url_template"`
	URL         string `json:"url"`
	Status      int    `json:"status"`
	ContentType string `json:"content_type"`
	RespLen     int    `json:"resp_len"`
	Path        string `json:"path"`
}

// Search returns paged exchange metadata (never bodies).
func (t *Traffic) Search(host string, page, size int) ([]ExchangeMeta, error) {
	if size <= 0 || size > 500 {
		size = 100
	}
	q := `SELECT id,ts,host,method,url_template,url,status,content_type,resp_len,path FROM exchanges`
	args := []any{}
	if host != "" {
		q += ` WHERE host=?`
		args = append(args, strings.ToLower(strings.TrimSpace(host)))
	}
	q += ` ORDER BY ts DESC LIMIT ? OFFSET ?`
	args = append(args, size, page*size)
	rows, err := t.db.Query(q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []ExchangeMeta
	for rows.Next() {
		var m ExchangeMeta
		if err := rows.Scan(&m.ID, &m.TS, &m.Host, &m.Method, &m.URLTemplate, &m.URL, &m.Status, &m.ContentType, &m.RespLen, &m.Path); err != nil {
			return nil, err
		}
		out = append(out, m)
	}
	return out, rows.Err()
}

// ftsFilter builds the SQL condition restricting rows to those whose indexed
// text matches term. ok is false when full-text search cannot serve the term —
// no FTS index on this build, or fewer than three characters, which the trigram
// tokenizer cannot match — leaving callers to fall back to metadata matching.
func (t *Traffic) ftsFilter(term string) (cond string, arg any, ok bool) {
	term = strings.TrimSpace(term)
	if !t.fts || utf8.RuneCountInString(term) < minTrigram {
		return "", nil, false
	}
	if t.db.postgres {
		return `rowid IN (SELECT rowid FROM ex_fts WHERE content LIKE lower(?) ESCAPE '\')`, literalLike(term), true
	}
	return `rowid IN (SELECT rowid FROM ex_fts WHERE ex_fts MATCH ?)`, ftsQuote(term), true
}

// ftsQuote wraps a term as an FTS5 string literal so that punctuation and query
// operators inside it (quotes, AND/OR/NEAR, *, ^) are matched literally instead
// of being parsed as query syntax.
func ftsQuote(s string) string {
	return `"` + strings.ReplaceAll(s, `"`, `""`) + `"`
}

// PageQuery bundles the optional filters and sort order for Page. Every filter
// is combined with AND; an empty string skips that filter, and RespMin/RespMax
// of -1 skip the response-size bounds. An empty Sort/Order defaults to
// newest-first by timestamp.
type PageQuery struct {
	Host    string // host substring
	Method  string // exact method (case-insensitive)
	Query   string // broad search box: metadata columns OR captured text
	Body    string // content box: captured request/response text only (full-text)
	Path    string // url_template substring — the vulnerability's path
	Status  string // exact code ("404") or class bucket ("4xx")
	RespMin int64  // minimum resp_len, or -1 when unset
	RespMax int64  // maximum resp_len, or -1 when unset
	Sort    string // ts | status | resp_len (default ts)
	Order   string // asc | desc (default desc)
}

// sortColumns whitelists the columns Page may order by, so the caller-supplied
// Sort can never reach the SQL as anything but one of these fixed names.
var sortColumns = map[string]string{"ts": "ts", "status": "status", "resp_len": "resp_len"}

// statusFilter turns a status token into a SQL condition: an exact code ("404")
// matches that status, an "Nxx" class ("4xx") matches the whole hundreds band.
// ok is false for an empty or unrecognized token.
func statusFilter(s string) (cond string, args []any, ok bool) {
	s = strings.ToLower(strings.TrimSpace(s))
	if s == "" {
		return "", nil, false
	}
	if len(s) == 3 && s[0] >= '1' && s[0] <= '5' && s[1] == 'x' && s[2] == 'x' {
		base := int(s[0]-'0') * 100
		return "status>=? AND status<?", []any{base, base + 100}, true
	}
	if n, err := strconv.Atoi(s); err == nil {
		return "status=?", []any{n}, true
	}
	return "", nil, false
}

// Page returns one page of exchange metadata for the traffic list, filtered by
// the criteria in f (all optional, combined with AND) and ordered by the
// requested column. Query is the broad search box (metadata columns OR, when the
// term is long enough for the trigram index, captured request/response text);
// Body narrows to exchanges whose captured text matches, via that same index.
// Also returns the total number of rows matching the filter (for the UI's
// pagination). Bodies are never included in the rows.
func (t *Traffic) Page(f PageQuery, page, size int) (rows []ExchangeMeta, total int, err error) {
	if size <= 0 || size > 500 {
		size = 100
	}
	if page < 0 {
		page = 0
	}
	where := ""
	var args []any
	add := func(cond string, vs ...any) {
		if where == "" {
			where = " WHERE "
		} else {
			where += " AND "
		}
		where += cond
		args = append(args, vs...)
	}
	if h := strings.TrimSpace(f.Host); h != "" {
		add(t.metadataLike("host LIKE ?"), "%"+h+"%")
	}
	if m := strings.TrimSpace(f.Method); m != "" {
		add("method=?", strings.ToUpper(m))
	}
	if p := strings.TrimSpace(f.Path); p != "" {
		add(t.metadataLike("url_template LIKE ?"), "%"+p+"%")
	}
	if cond, sargs, ok := statusFilter(f.Status); ok {
		add(cond, sargs...)
	}
	if f.RespMin >= 0 {
		add("resp_len>=?", f.RespMin)
	}
	if f.RespMax >= 0 {
		add("resp_len<=?", f.RespMax)
	}
	if s := strings.TrimSpace(f.Query); s != "" {
		like := "%" + s + "%"
		meta := t.metadataLike("host LIKE ? OR url LIKE ? OR url_template LIKE ? OR method LIKE ? OR content_type LIKE ? OR CAST(status AS TEXT) LIKE ?")
		// Metadata match OR full-text match: one search box, widest recall. Terms
		// too short for trigram silently fall back to metadata only.
		if cond, arg, ok := t.ftsFilter(s); ok {
			add("(("+meta+") OR "+cond+")", like, like, like, like, like, like, arg)
		} else {
			add("("+meta+")", like, like, like, like, like, like)
		}
	}
	// Body is the dedicated content box: it only searches captured request/response
	// text, so it goes straight to the full-text index with no metadata fallback. A
	// term too short for the trigram tokenizer cannot be served and is skipped
	// rather than guessed at — the UI hints at the three-character minimum.
	if b := strings.TrimSpace(f.Body); b != "" {
		if cond, arg, ok := t.ftsFilter(b); ok {
			add(cond, arg)
		}
	}
	if err = t.db.QueryRow(`SELECT COUNT(*) FROM exchanges`+where, args...).Scan(&total); err != nil {
		return nil, 0, err
	}
	col := sortColumns[strings.ToLower(strings.TrimSpace(f.Sort))]
	if col == "" {
		col = "ts"
	}
	dir := "DESC"
	if strings.EqualFold(strings.TrimSpace(f.Order), "asc") {
		dir = "ASC"
	}
	// A unique id tie-breaker makes the order
	// total and pagination stable even when the sort column has many ties.
	sel := `SELECT id,ts,host,method,url_template,url,status,content_type,resp_len,path FROM exchanges` +
		where + ` ORDER BY ` + col + ` ` + dir + `, id DESC LIMIT ? OFFSET ?`
	qargs := append(append([]any{}, args...), size, page*size)
	rs, err := t.db.Query(sel, qargs...)
	if err != nil {
		return nil, 0, err
	}
	defer rs.Close()
	for rs.Next() {
		var m ExchangeMeta
		if err := rs.Scan(&m.ID, &m.TS, &m.Host, &m.Method, &m.URLTemplate, &m.URL, &m.Status, &m.ContentType, &m.RespLen, &m.Path); err != nil {
			return nil, 0, err
		}
		rows = append(rows, m)
	}
	return rows, total, rs.Err()
}

// Get returns the full request/response text of one exchange. Bodies come from
// the database; rows recorded before bodies moved into SQLite carry a non-empty
// path and are read from the legacy on-disk tree instead, so history stays
// readable without being migrated.
func (t *Traffic) Get(id string) (req, resp string, err error) {
	var reqHead, respHead string
	var reqBody, respBody []byte
	var reqBlob, respBlob sql.NullString
	var reqLen, respLen int
	err = t.db.QueryRow(`SELECT b.req_head,b.req_body,b.req_blob,b.resp_head,b.resp_body,b.resp_blob,e.req_len,e.resp_len
FROM exchange_bodies b JOIN exchanges e ON e.id=b.id WHERE b.id=?`, id).
		Scan(&reqHead, &reqBody, &reqBlob, &respHead, &respBody, &respBlob, &reqLen, &respLen)
	if err == nil {
		return assembleRaw(reqHead, reqBody, reqBlob, reqLen), assembleRaw(respHead, respBody, respBlob, respLen), nil
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return "", "", err
	}

	var rel string
	if err = t.db.QueryRow(`SELECT path FROM exchanges WHERE id=?`, id).Scan(&rel); err != nil {
		return "", "", err
	}
	if strings.TrimSpace(rel) == "" {
		return "", "", fmt.Errorf("exchange %s 无正文记录", id)
	}
	rb, _ := os.ReadFile(filepath.Join(t.dir, rel, "request.http"))
	pb, _ := os.ReadFile(filepath.Join(t.dir, rel, "response.http"))
	return string(rb), string(pb), nil
}

// assembleRaw rebuilds one side's raw HTTP text: head, blank line, body. A body
// that spilled to the blob store shows its inline preview followed by the blob
// pointer, so the reader can see what it is and fetch the rest by hash.
func assembleRaw(head string, body []byte, blob sql.NullString, total int) string {
	var b strings.Builder
	b.WriteString(head)
	b.WriteByte('\n')
	b.Write(body)
	if blob.Valid && blob.String != "" {
		fmt.Fprintf(&b, "\n…[truncated] @blob sha256:%s (len=%d)", blob.String, total)
	}
	return b.String()
}

// HostCount is one distinct recorded host plus its exchange count.
type HostCount struct {
	Host  string `json:"host"`
	Count int    `json:"count"`
}

// Hosts returns distinct recorded hosts with exchange counts, most recent
// activity first — powers the page's target picker.
func (t *Traffic) Hosts() ([]HostCount, error) {
	rows, err := t.db.Query(`SELECT host, COUNT(*) AS n, MAX(ts) AS last FROM exchanges GROUP BY host ORDER BY last DESC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []HostCount
	for rows.Next() {
		var h HostCount
		var last int64
		if err := rows.Scan(&h.Host, &h.Count, &last); err != nil {
			return nil, err
		}
		out = append(out, h)
	}
	return out, rows.Err()
}

// Count returns total recorded exchanges.
func (t *Traffic) Count() (int, error) {
	var n int
	err := t.db.QueryRow(`SELECT COUNT(*) FROM exchanges`).Scan(&n)
	return n, err
}

// DeleteHost removes every recorded exchange whose host contains the given
// substring — mirroring the UI's host filter, so what you filtered is what gets
// deleted. All index rows share one database, so deletion is one transaction across
// the index, bodies, full-text index and blob references. Content-addressed
// blobs are shared across hosts and so are garbage-collected afterwards rather
// than deleted by host. Returns rows deleted.
func (t *Traffic) DeleteHost(host string) (int64, error) {
	like := "%" + host + "%"
	t.wmu.Lock()
	defer t.wmu.Unlock()
	// Resolved before the rows go away: with a substring match, the index is the
	// only record of which host directories the filter actually hit.
	legacy, err := t.hostTrees(t.metadataLike(`host LIKE ?`), like)
	if err != nil {
		return 0, err
	}
	tx, err := t.db.Begin()
	if err != nil {
		return 0, err
	}
	defer tx.Rollback() //nolint:errcheck // no-op once committed
	n, err := t.deleteWhere(tx, t.metadataLike(`host LIKE ?`), like)
	if err != nil {
		return 0, err
	}
	// Staged before the commit so a filesystem failure can still abort the whole
	// deletion, and before gcBlobs so reference collection sees the correct live
	// set — a staged tree is invisible to it.
	stageDir, moves, err := t.stageTrees(legacy)
	if err != nil {
		return 0, errors.Join(err, restoreTrees(stageDir, moves))
	}
	if err := tx.Commit(); err != nil {
		return 0, errors.Join(fmt.Errorf("提交流量索引删除: %w", err), restoreTrees(stageDir, moves))
	}
	t.reapStage(stageDir)
	if n > 0 {
		t.reclaim()
		if err := t.gcBlobs(); err != nil {
			return n, err
		}
	}
	return n, nil
}

// DeleteAll removes every recorded exchange — the page's clear-everything
// action. It differs from the host-scoped deletions in two ways. It sweeps host
// directories without consulting the index, because "clear everything" should
// leave nothing behind and a directory whose rows are already gone would
// otherwise survive. And it ends with a full compaction: VACUUM costs what it
// keeps, so an emptied index is the one moment it is free, and it is also the
// only way to switch on auto_vacuum for a database created without it.
//
// Evidence already bound to a finding is untouched. Those bodies were copied
// into the evidence store when they were bound, precisely so that disposable
// traffic could be cleared without taking proof with it.
//
// Returns the number of exchanges deleted and how many bytes of index the
// compaction handed back.
func (t *Traffic) DeleteAll() (deleted int64, reclaimed int64, err error) {
	t.wmu.Lock()
	defer t.wmu.Unlock()
	before := t.indexBytes()
	trees, err := t.allHostTrees()
	if err != nil {
		return 0, 0, err
	}
	tx, err := t.db.Begin()
	if err != nil {
		return 0, 0, err
	}
	defer tx.Rollback() //nolint:errcheck // no-op once committed
	if deleted, err = t.deleteWhere(tx, `1=1`); err != nil {
		return 0, 0, err
	}
	// Staged before the commit so a filesystem failure can still abort the whole
	// deletion, exactly as in DeleteHost.
	stageDir, moves, err := t.stageTrees(trees)
	if err != nil {
		return 0, 0, errors.Join(err, restoreTrees(stageDir, moves))
	}
	if err := tx.Commit(); err != nil {
		return 0, 0, errors.Join(fmt.Errorf("提交流量索引删除: %w", err), restoreTrees(stageDir, moves))
	}
	t.reapStage(stageDir)
	if err := t.gcBlobs(); err != nil {
		return deleted, 0, err
	}
	if err := t.compactIndex(); err != nil {
		// The deletion is already durable; compaction is disk space, not
		// correctness, so it must not turn a completed purge into a failed one.
		log.Printf("[traffic] 压实索引失败：%v", err)
		return deleted, 0, nil
	}
	return deleted, before - t.indexBytes(), nil
}

// allHostTrees lists every host directory left by the pre-SQLite layout. Unlike
// hostTrees it does not go through the index, so it also finds directories whose
// rows are already gone. Underscore-prefixed entries are the store's own
// (_index, _blobs, _ca, _delete_staging) and are never hosts.
func (t *Traffic) allHostTrees() ([]string, error) {
	entries, err := os.ReadDir(t.dir)
	if err != nil {
		return nil, err
	}
	var dirs []string
	for _, e := range entries {
		if e.IsDir() && !strings.HasPrefix(e.Name(), "_") {
			dirs = append(dirs, filepath.Join(t.dir, e.Name()))
		}
	}
	return dirs, nil
}

// compactIndex rewrites the index into a fresh file, which is what actually
// returns its pages to the filesystem. VACUUM's runtime and temporary space
// scale with the content it keeps, so this is only reached right after DeleteAll
// has emptied the index — never as a routine step. It doubles as the conversion
// path for a database created before auto_vacuum=incremental: that pragma only
// takes effect through the VACUUM that follows it, and both must run on the same
// connection. Callers must hold wmu.
func (t *Traffic) compactIndex() error {
	if t.db.postgres {
		return t.vacuumPostgres()
	}
	ctx := context.Background()
	conn, err := t.db.Conn(ctx)
	if err != nil {
		return err
	}
	defer conn.Close()
	if t.fts {
		// A full merge, not the bounded one reclaim uses: with the index emptied
		// there is nothing left to merge, so this only discards the tombstones.
		if _, err := conn.ExecContext(ctx, `INSERT INTO ex_fts(ex_fts) VALUES('optimize')`); err != nil {
			return fmt.Errorf("合并全文索引: %w", err)
		}
	}
	if _, err := conn.ExecContext(ctx, `PRAGMA auto_vacuum=incremental`); err != nil {
		return err
	}
	if _, err := conn.ExecContext(ctx, `VACUUM`); err != nil {
		return fmt.Errorf("压实索引: %w", err)
	}
	var mode int
	if err := conn.QueryRowContext(ctx, `PRAGMA auto_vacuum`).Scan(&mode); err != nil {
		return err
	}
	// A legacy database has just been converted, so later deletions can reclaim
	// space on their own instead of waiting for another purge.
	t.incrementalVacuum = mode == autoVacuumIncremental
	if _, err := conn.ExecContext(ctx, `PRAGMA wal_checkpoint(TRUNCATE)`); err != nil {
		return fmt.Errorf("截断 WAL: %w", err)
	}
	return nil
}

// deleteWhere removes every trace of the exchanges matching the condition:
// full-text index rows, bodies, blob references, and finally the index rows.
// Order matters — each sub-select reads exchanges, so that table is emptied last.
func (t *Traffic) deleteWhere(tx *indexTx, where string, args ...any) (int64, error) {
	if t.fts {
		// ex_fts is contentless and addressed by rowid, hence the rowid sub-select.
		if _, err := tx.Exec(`DELETE FROM ex_fts WHERE rowid IN (SELECT rowid FROM exchanges WHERE `+where+`)`, args...); err != nil {
			return 0, fmt.Errorf("删除全文索引: %w", err)
		}
	}
	if _, err := tx.Exec(`DELETE FROM exchange_bodies WHERE id IN (SELECT id FROM exchanges WHERE `+where+`)`, args...); err != nil {
		return 0, fmt.Errorf("删除正文: %w", err)
	}
	if _, err := tx.Exec(`DELETE FROM blob_refs WHERE exchange_id IN (SELECT id FROM exchanges WHERE `+where+`)`, args...); err != nil {
		return 0, fmt.Errorf("删除 blob 引用: %w", err)
	}
	res, err := tx.Exec(`DELETE FROM exchanges WHERE `+where, args...)
	if err != nil {
		return 0, fmt.Errorf("删除索引行: %w", err)
	}
	n, _ := res.RowsAffected()
	return n, nil
}

// hostTrees returns the on-disk directory of every host matching the condition.
// Exchanges recorded since bodies moved into SQLite have no directory at all, so
// most of these paths simply will not exist — staging skips those. The lookup is
// deliberately not restricted to rows with a path: a host whose index rows are
// already gone can still have an orphaned directory, and deleting the host should
// take that with it.
func (t *Traffic) hostTrees(where string, args ...any) ([]string, error) {
	rows, err := t.db.Query(`SELECT DISTINCT host FROM exchanges WHERE `+where, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var dirs []string
	for rows.Next() {
		var h string
		if err := rows.Scan(&h); err != nil {
			return nil, err
		}
		dirs = append(dirs, filepath.Join(t.dir, sanitize(h)))
	}
	return dirs, rows.Err()
}

type stagedTrafficPath struct {
	source string
	staged string
}

type hostDeleteStageJournal struct {
	Version   int                   `json:"version"`
	ArchiveID int64                 `json:"archive_id,omitempty"`
	TaskID    int64                 `json:"task_id,omitempty"`
	Hosts     []string              `json:"hosts,omitempty"`
	Moves     []hostDeleteStageMove `json:"moves"`
}

type hostDeleteStageMove struct {
	Source string `json:"source"`
	Staged string `json:"staged"`
}

const hostDeleteStageJournalName = "journal.json"

// stageTrees moves host directories aside onto the same filesystem. The rename is
// atomic and instant, which buys two things the unlink cannot: the deletion stays
// reversible until the transaction commits, and the tree stops being visible to
// blob reference collection right away (legacyBlobRefs skips underscore-prefixed
// directories, so anything under _delete_staging is already out of the live set).
// An empty stageDir is returned when there was nothing to stage.
func (t *Traffic) stageTrees(dirs []string) (stageDir string, moves []stagedTrafficPath, err error) {
	return t.stageTreesForArchive(dirs, nil, 0, 0)
}

func (t *Traffic) stageTreesForArchive(dirs, hosts []string, archiveID, taskID int64) (stageDir string, moves []stagedTrafficPath, err error) {
	seen := make(map[string]struct{}, len(dirs))
	planned := make([]stagedTrafficPath, 0, len(dirs))
	for _, source := range dirs {
		if _, dup := seen[source]; dup {
			continue
		}
		seen[source] = struct{}{}
		if _, err := os.Lstat(source); err != nil {
			if os.IsNotExist(err) {
				continue
			}
			return stageDir, moves, fmt.Errorf("检查历史流量目录 %s: %w", source, err)
		}
		planned = append(planned, stagedTrafficPath{source: source})
	}
	// 归档路径即使一个历史 host 目录都没有(新装机的流量落在 PostgreSQL + _blobs)
	// 也必须留下 journal：崩溃点若落在 业务库提交与流量事务提交之间，重启后
	// 流量事务被回滚，只有这份 journal 能让恢复流程补做 host 行的删除。少了它，
	// 已转冷任务的独占流量会永久留在热库里。
	uniqueHosts := uniqueArchiveHosts(hosts)
	if len(planned) == 0 && len(uniqueHosts) == 0 {
		return "", nil, nil
	}
	parent := filepath.Join(t.dir, "_delete_staging")
	if err := os.MkdirAll(parent, 0o700); err != nil {
		return "", nil, fmt.Errorf("创建流量暂存目录: %w", err)
	}
	if stageDir, err = os.MkdirTemp(parent, "hosts-"); err != nil {
		return "", nil, fmt.Errorf("创建流量暂存目录: %w", err)
	}
	journal := hostDeleteStageJournal{Version: 1, ArchiveID: archiveID, TaskID: taskID, Hosts: uniqueHosts}
	for i := range planned {
		planned[i].staged = filepath.Join(stageDir, fmt.Sprintf("%d-%s", i, filepath.Base(planned[i].source)))
		journal.Moves = append(journal.Moves, hostDeleteStageMove{Source: planned[i].source, Staged: planned[i].staged})
	}
	if err := writeHostDeleteStageJournal(filepath.Join(stageDir, hostDeleteStageJournalName), journal); err != nil {
		_ = os.RemoveAll(stageDir)
		return "", nil, err
	}
	for _, move := range planned {
		source, staged := move.source, move.staged
		if err := os.Rename(source, staged); err != nil {
			return stageDir, moves, fmt.Errorf("移出历史流量目录 %s: %w", source, err)
		}
		moves = append(moves, stagedTrafficPath{source: source, staged: staged})
	}
	return stageDir, moves, nil
}

func writeHostDeleteStageJournal(path string, journal hostDeleteStageJournal) error {
	raw, err := json.Marshal(journal)
	if err != nil {
		return err
	}
	file, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	if _, err := file.Write(raw); err != nil {
		_ = file.Close()
		return err
	}
	if err := file.Sync(); err != nil {
		_ = file.Close()
		return err
	}
	return file.Close()
}

// restoreTrees puts staged directories back where they came from, newest move
// first, and drops the staging directory once everything is home.
func restoreTrees(stageDir string, moves []stagedTrafficPath) error {
	var errs []error
	for i := len(moves) - 1; i >= 0; i-- {
		move := moves[i]
		if _, err := os.Lstat(move.source); err == nil {
			errs = append(errs, fmt.Errorf("restore destination already exists: %s", move.source))
			continue
		} else if !os.IsNotExist(err) {
			errs = append(errs, fmt.Errorf("inspect restore destination %s: %w", move.source, err))
			continue
		}
		if err := os.Rename(move.staged, move.source); err != nil {
			errs = append(errs, fmt.Errorf("restore %s: %w", move.source, err))
		}
	}
	if len(errs) == 0 && stageDir != "" {
		if err := os.RemoveAll(stageDir); err != nil {
			errs = append(errs, fmt.Errorf("remove traffic stage: %w", err))
		}
	}
	return errors.Join(errs...)
}

// reapStage unlinks a committed staging directory in the background. This is the
// step that used to stall the recorder: a legacy tree mirrors the URL path per
// request and can hold hundreds of thousands of small files, and the whole unlink
// ran while the write lock was held. The rows are already gone by now, so losing
// this to a shutdown leaves garbage under _delete_staging, never inconsistent
// state.
func (t *Traffic) reapStage(stageDir string) {
	if stageDir == "" {
		return
	}
	t.startReaper(func() {
		if err := os.RemoveAll(stageDir); err != nil {
			log.Printf("[traffic] 清理历史流量目录 %s 失败：%v", stageDir, err)
		}
	})
}

// DeleteHostsExact removes recorded exchanges for a set of EXACT hosts (the
// batch path for the page's multi-select delete): index rows + each host's file
// tree, then one blob-GC pass. Exact match — unlike DeleteHost's substring —
// so picking "api.example.com" never sweeps "api.example.com.cn". Returns rows
// deleted. Duplicate hosts are harmless (idempotent deletes, single tree pass).
func (t *Traffic) DeleteHostsExact(hosts []string) (int64, error) {
	stage, err := t.StageDeleteHostsExact(hosts)
	if err != nil {
		return 0, err
	}
	deleted := stage.Deleted()
	if err := stage.Commit(); err != nil {
		return deleted, err
	}
	return deleted, nil
}

// HostDeleteStage keeps the traffic delete transaction open so a task deletion
// can be coordinated with the business transaction: traffic is staged here and only
// committed once the caller's own transaction has succeeded. The Traffic write
// lock is held until Commit or Rollback, so no recorder can add rows or a blob
// reference for a host that is mid-deletion. Rolling back is just a transaction
// rollback now that nothing is moved on disk.
type HostDeleteStage struct {
	traffic  *Traffic
	tx       *indexTx
	stageDir string
	moves    []stagedTrafficPath
	deleted  int64
	done     bool
}

// Deleted reports the number of exchange rows selected by this stage.
func (s *HostDeleteStage) Deleted() int64 {
	if s == nil {
		return 0
	}
	return s.deleted
}

// StageDeleteHostsExact prepares a reversible exact-host deletion. Callers must
// finish every successful stage with Commit or Rollback.
func (t *Traffic) StageDeleteHostsExact(hosts []string) (*HostDeleteStage, error) {
	return t.stageDeleteHostsExact(hosts, 0, 0)
}

// StageDeleteHostsExactForArchive ties the reversible traffic deletion to a
// persistent task archive. Startup recovery uses archiveCommitted to decide
// whether an interrupted stage must be completed or rolled back.
func (t *Traffic) StageDeleteHostsExactForArchive(hosts []string, archiveID, taskID int64) (*HostDeleteStage, error) {
	if archiveID <= 0 || taskID <= 0 {
		return nil, errors.New("archive and task ids must be positive")
	}
	return t.stageDeleteHostsExact(hosts, archiveID, taskID)
}

func (t *Traffic) stageDeleteHostsExact(hosts []string, archiveID, taskID int64) (*HostDeleteStage, error) {
	t.wmu.Lock()
	stage := &HostDeleteStage{traffic: t}
	fail := func(cause error) (*HostDeleteStage, error) {
		if rollbackErr := stage.rollbackLocked(); rollbackErr != nil {
			return nil, errors.Join(cause, fmt.Errorf("回滚流量删除: %w", rollbackErr))
		}
		return nil, cause
	}
	abort := func(cause error) (*HostDeleteStage, error) {
		t.wmu.Unlock()
		stage.done = true
		return nil, cause
	}

	unique := make([]string, 0, len(hosts))
	seen := make(map[string]struct{}, len(hosts))
	for _, host := range hosts {
		host = strings.ToLower(strings.TrimSpace(host))
		if host == "" {
			continue
		}
		if _, ok := seen[host]; ok {
			continue
		}
		seen[host] = struct{}{}
		unique = append(unique, host)
	}

	// Exact hosts are known up front, so their directories are derived directly
	// rather than looked up: a host whose index rows are already gone can still
	// own an orphaned directory that this deletion should take with it.
	legacy := make([]string, 0, len(unique))
	for _, h := range unique {
		legacy = append(legacy, filepath.Join(t.dir, sanitize(h)))
	}

	tx, err := t.db.Begin()
	if err != nil {
		return abort(err)
	}
	stage.tx = tx
	for _, h := range unique {
		n, err := t.deleteWhere(tx, `host=?`, h)
		if err != nil {
			return fail(err)
		}
		stage.deleted += n
	}

	stage.stageDir, stage.moves, err = t.stageTreesForArchive(legacy, unique, archiveID, taskID)
	if err != nil {
		return fail(err)
	}
	return stage, nil
}

// RecoverHostDeleteStages resolves filesystem moves left by a process exit.
// The database rolls open transactions back on restart, while the supplied callback
// identifies task archives whose PostgreSQL compaction already committed.
func (t *Traffic) RecoverHostDeleteStages(archiveCommitted func(int64, int64) (bool, error)) error {
	if t == nil {
		return nil
	}
	t.wmu.Lock()
	defer t.wmu.Unlock()
	parent := filepath.Join(t.dir, "_delete_staging")
	entries, err := os.ReadDir(parent)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return err
	}
	var errs []error
	needsGC := false
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		stageDir := filepath.Join(parent, entry.Name())
		raw, err := os.ReadFile(filepath.Join(stageDir, hostDeleteStageJournalName))
		if os.IsNotExist(err) {
			// Older versions did not persist enough information for lossless
			// recovery. Keep the directory for manual inspection.
			continue
		}
		if err != nil {
			errs = append(errs, err)
			continue
		}
		var journal hostDeleteStageJournal
		if err := json.Unmarshal(raw, &journal); err != nil {
			errs = append(errs, fmt.Errorf("读取流量暂存日志 %s: %w", stageDir, err))
			continue
		}
		if journal.Version != 1 {
			errs = append(errs, fmt.Errorf("流量暂存日志 %s 的版本 %d 不受支持", stageDir, journal.Version))
			continue
		}
		moves := make([]stagedTrafficPath, 0, len(journal.Moves))
		for _, move := range journal.Moves {
			if !pathWithin(t.dir, move.Source) || !pathWithin(stageDir, move.Staged) {
				errs = append(errs, fmt.Errorf("流量暂存日志包含越界路径: %s", stageDir))
				moves = nil
				break
			}
			if _, err := os.Lstat(move.Staged); err == nil {
				moves = append(moves, stagedTrafficPath{source: move.Source, staged: move.Staged})
			} else if !os.IsNotExist(err) {
				errs = append(errs, err)
				moves = nil
				break
			}
		}
		if moves == nil {
			continue
		}
		committed := false
		if journal.ArchiveID > 0 {
			if archiveCommitted == nil {
				errs = append(errs, fmt.Errorf("流量归档 %d 无状态解析器", journal.ArchiveID))
				continue
			}
			committed, err = archiveCommitted(journal.ArchiveID, journal.TaskID)
			if err != nil {
				errs = append(errs, err)
				continue
			}
		} else if len(journal.Hosts) > 0 {
			committed, err = t.hostsHaveNoExchanges(journal.Hosts)
			if err != nil {
				errs = append(errs, err)
				continue
			}
		}
		if !committed {
			if err := restoreTrees(stageDir, moves); err != nil {
				errs = append(errs, err)
			}
			continue
		}
		if err := t.deleteArchivedHosts(journal.Hosts); err != nil {
			errs = append(errs, err)
			continue
		}
		if err := os.RemoveAll(stageDir); err != nil {
			errs = append(errs, err)
			continue
		}
		needsGC = true
	}
	if needsGC {
		t.reclaim()
		if err := t.gcBlobs(); err != nil {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}

func (t *Traffic) hostsHaveNoExchanges(hosts []string) (bool, error) {
	for _, host := range hosts {
		var count int
		if err := t.db.QueryRow(`SELECT count(*) FROM exchanges WHERE host=?`, host).Scan(&count); err != nil {
			return false, err
		}
		if count > 0 {
			return false, nil
		}
	}
	return true, nil
}

func (t *Traffic) deleteArchivedHosts(hosts []string) error {
	tx, err := t.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback() //nolint:errcheck
	for _, host := range hosts {
		if _, err := t.deleteWhere(tx, `host=?`, host); err != nil {
			return err
		}
	}
	return tx.Commit()
}

func pathWithin(root, candidate string) bool {
	rootAbs, err := filepath.Abs(root)
	if err != nil {
		return false
	}
	candidateAbs, err := filepath.Abs(candidate)
	if err != nil {
		return false
	}
	relative, err := filepath.Rel(rootAbs, candidateAbs)
	return err == nil && relative != ".." && !strings.HasPrefix(relative, ".."+string(filepath.Separator))
}

// Rollback discards the staged deletion, leaving the traffic store untouched.
func (s *HostDeleteStage) Rollback() error {
	if s == nil || s.done {
		return nil
	}
	return s.rollbackLocked()
}

func (s *HostDeleteStage) rollbackLocked() error {
	if s == nil || s.done {
		return nil
	}
	var errs []error
	if s.tx != nil {
		if err := s.tx.Rollback(); err != nil && !errors.Is(err, sql.ErrTxDone) {
			errs = append(errs, fmt.Errorf("回滚流量索引: %w", err))
		}
	}
	if err := restoreTrees(s.stageDir, s.moves); err != nil {
		errs = append(errs, err)
	}
	s.done = true
	s.traffic.wmu.Unlock()
	return errors.Join(errs...)
}

// Commit makes the staged deletion permanent. The traffic transaction is committed only after
// the caller has committed its PostgreSQL task deletion.
func (s *HostDeleteStage) Commit() error {
	if s == nil || s.done {
		return nil
	}
	if err := s.tx.Commit(); err != nil {
		// A failed traffic commit normally rolls the transaction back. Restore the
		// trees so the traffic store remains internally consistent and recoverable.
		restoreErr := restoreTrees(s.stageDir, s.moves)
		s.done = true
		s.traffic.wmu.Unlock()
		return errors.Join(fmt.Errorf("提交流量索引删除: %w", err), restoreErr)
	}
	// Unlinking the staged trees is what used to hold the write lock for hours;
	// it now runs in the background, while collection below only needs them to be
	// out of the live tree — which the staging rename already guaranteed.
	s.traffic.reapStage(s.stageDir)
	s.traffic.reclaim()
	var errs []error
	if err := s.traffic.gcBlobs(); err != nil {
		errs = append(errs, fmt.Errorf("回收流量 blob: %w", err))
	}
	s.done = true
	s.traffic.wmu.Unlock()
	return errors.Join(errs...)
}

// indexBytes is the index's real footprint on disk: the database plus its
// write-ahead log and shared-memory file, since those are what an operator sees
// the data directory holding.
func (t *Traffic) indexBytes() int64 {
	if t.db.postgres {
		var size int64
		_ = t.db.QueryRow(`SELECT COALESCE(sum(pg_total_relation_size(c.oid)),0)::bigint FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname=current_schema() AND c.relkind='r'`).Scan(&size)
		return size
	}
	base := filepath.Join(t.dir, "_index", "index.sqlite")
	var total int64
	for _, p := range []string{base, base + "-wal", base + "-shm"} {
		if st, err := os.Stat(p); err == nil {
			total += st.Size()
		}
	}
	return total
}

// reclaim hands space freed by a deletion back to the filesystem. Deleting rows
// only makes them invisible: SQLite chains their pages onto a freelist, and
// deleting from the contentless_delete full-text index writes tombstones rather
// than removing the postings they hide. Neither shrinks a single byte on disk,
// and since bodies below maxInlineBody live in that same file, an install that
// captures heavily ends up holding far more than the traffic it still has.
//
// The work is done in the background, in bounded steps that drop the write lock
// between them, because it is proportional to what was deleted — freeing several
// gigabytes under one lock would stall background persistence batches.
// Safe to call with wmu held: the background pass simply waits for it.
//
// Best-effort throughout. Failing to reclaim costs disk space, never
// correctness, so errors are logged and the next deletion resumes the work.
func (t *Traffic) reclaim() {
	if t.db.postgres {
		return
	} // PostgreSQL autovacuum reuses dead tuples and maintains GIN.
	if !t.reclaiming.CompareAndSwap(false, true) {
		return // one pass at a time; a second would only contend for the lock
	}
	if !t.startReaper(func() {
		defer t.reclaiming.Store(false)
		// One pinned connection for the whole pass: a long reclamation issues
		// hundreds of statements, and letting the pool hand each one a different
		// connection would both churn connections and split the freelist readings
		// that decide when to stop away from the vacuum they measure.
		ctx := context.Background()
		conn, err := t.db.Conn(ctx)
		if err != nil {
			log.Printf("[traffic] 回收索引空间失败（获取连接）：%v", err)
			return
		}
		defer conn.Close()
		deadline := time.Now().Add(reclaimBudget)
		merges := reclaimMergeSteps
		for step := 0; ; step++ {
			t.wmu.Lock()
			progressed, err := t.reclaimChunk(ctx, conn, &merges)
			t.wmu.Unlock()
			if err != nil {
				log.Printf("[traffic] 回收索引空间失败：%v", err)
				return
			}
			if !progressed {
				break
			}
			if t.stopping() {
				return // shutdown must not wait out the remaining budget
			}
			if step+1 >= reclaimMaxSteps {
				log.Printf("[traffic] 索引空间回收未做完（已用满 %d 步上限），下次删除时继续", reclaimMaxSteps)
				return
			}
			if time.Now().After(deadline) {
				log.Printf("[traffic] 索引空间回收未做完（已用满 %s 预算），下次删除时继续", reclaimBudget)
				return
			}
		}
		// Truncating the log is what makes the reclamation visible on disk: in WAL
		// mode the freed pages are recorded there first, and a PASSIVE checkpoint
		// would leave the log itself sitting at its high-water mark.
		t.wmu.Lock()
		defer t.wmu.Unlock()
		if _, err := conn.ExecContext(ctx, `PRAGMA wal_checkpoint(TRUNCATE)`); err != nil {
			log.Printf("[traffic] 截断 WAL 失败：%v", err)
		}
	}) {
		t.reclaiming.Store(false)
	}
}

// reclaimChunk does one bounded step and reports whether it made progress, which
// is what the caller loops on. merges carries the remaining full-text merge
// budget and is spent down here. Callers must hold wmu.
func (t *Traffic) reclaimChunk(ctx context.Context, conn *sql.Conn, merges *int) (bool, error) {
	progressed := false
	if t.fts && *merges > 0 {
		// A negative rank is fts5's page budget for one incremental merge.
		if _, err := conn.ExecContext(ctx, `INSERT INTO ex_fts(ex_fts, rank) VALUES('merge', ?)`, -reclaimMergePages); err != nil {
			return false, fmt.Errorf("合并全文索引: %w", err)
		}
		*merges--
		progressed = true
	}
	if !t.incrementalVacuum {
		// incremental_vacuum is a silent no-op on a database created with
		// auto_vacuum=0; only a full compaction can convert one. Merging the
		// full-text index above still pays off, so stop here rather than earlier.
		return progressed, nil
	}
	var before, after int
	if err := conn.QueryRowContext(ctx, `PRAGMA freelist_count`).Scan(&before); err != nil {
		return false, err
	}
	if before == 0 {
		return progressed, nil
	}
	// The budget is a constant and PRAGMA arguments cannot be bound as parameters.
	if _, err := conn.ExecContext(ctx, fmt.Sprintf(`PRAGMA incremental_vacuum(%d)`, reclaimChunkPages)); err != nil {
		return false, fmt.Errorf("回收索引空闲页: %w", err)
	}
	if err := conn.QueryRowContext(ctx, `PRAGMA freelist_count`).Scan(&after); err != nil {
		return false, err
	}
	// Progress, not an empty freelist, is the right stopping condition:
	// incremental_vacuum can only release pages it manages to move to the end of
	// the file, so a residual freelist it cannot shrink is a normal outcome.
	return progressed || after < before, nil
}

func (t *Traffic) beginExport() {
	t.exportMu.Lock()
	t.exportsInFlight++
	t.exportMu.Unlock()
}

func (t *Traffic) endExport() {
	t.exportMu.Lock()
	t.exportsInFlight--
	runGC := t.exportsInFlight == 0 && t.gcDeferred
	if runGC {
		t.gcDeferred = false
	}
	t.exportMu.Unlock()
	if runGC {
		t.startReaper(func() {
			t.wmu.Lock()
			defer t.wmu.Unlock()
			_ = t.gcBlobs()
		})
	}
}

func (t *Traffic) deferGCIfExporting() bool {
	t.exportMu.Lock()
	defer t.exportMu.Unlock()
	if t.exportsInFlight > 0 {
		t.gcDeferred = true
		return true
	}
	return false
}

// gcBlobs removes blobs that no remaining exchange references. Live references
// come from blob_refs plus any blobs currently pinned by an in-flight batch
// spilling outside wmu. Emptied bucket directories are removed as well.
// Best-effort: walk errors only skip the affected entries. Callers must hold wmu.
func (t *Traffic) gcBlobs() error {
	if t.deferGCIfExporting() {
		return nil
	}
	t.gcGen.Add(1)
	refs := make(map[string]struct{})
	rows, err := t.db.Query(`SELECT DISTINCT hash FROM blob_refs`)
	if err != nil {
		return err
	}
	for rows.Next() {
		var h string
		if err := rows.Scan(&h); err != nil {
			rows.Close()
			return err
		}
		refs[h] = struct{}{}
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return err
	}
	if err := t.legacyBlobRefs(refs); err != nil {
		return err
	}
	t.snapshotPinnedBlobs(refs)

	root := filepath.Join(t.dir, "_blobs", "sha256")
	var buckets []string
	if err := filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if err != nil || d == nil {
			return nil
		}
		if d.IsDir() {
			if p != root {
				buckets = append(buckets, p)
			}
			return nil
		}
		name := d.Name()
		if strings.HasPrefix(name, ".blob-") || !strings.HasSuffix(name, ".bin") {
			return nil
		}
		h := strings.TrimSuffix(name, ".bin")
		if _, ok := refs[h]; !ok && !t.isBlobPinned(h) {
			if t.deferGCIfExporting() {
				return filepath.SkipAll
			}
			os.Remove(p)
		}
		return nil
	}); err != nil {
		return err
	}
	// Deepest first, so a two-level bucket left by the old layout collapses fully.
	// Remove fails harmlessly on a non-empty directory — exactly the guard needed
	// to avoid deleting a bucket that still holds live blobs.
	sort.Slice(buckets, func(i, j int) bool { return len(buckets[i]) > len(buckets[j]) })
	for _, b := range buckets {
		os.Remove(b)
	}
	return nil
}

// deleteWhereContext mirrors deleteWhere while honoring ctx cancellation.
func (t *Traffic) deleteWhereContext(ctx context.Context, tx *indexTx, where string, args ...any) (int64, error) {
	if t.fts {
		if _, err := tx.ExecContext(ctx, `DELETE FROM ex_fts WHERE rowid IN (SELECT rowid FROM exchanges WHERE `+where+`)`, args...); err != nil {
			return 0, fmt.Errorf("删除全文索引: %w", err)
		}
	}
	if _, err := tx.ExecContext(ctx, `DELETE FROM exchange_bodies WHERE id IN (SELECT id FROM exchanges WHERE `+where+`)`, args...); err != nil {
		return 0, fmt.Errorf("删除正文: %w", err)
	}
	if _, err := tx.ExecContext(ctx, `DELETE FROM blob_refs WHERE exchange_id IN (SELECT id FROM exchanges WHERE `+where+`)`, args...); err != nil {
		return 0, fmt.Errorf("删除 blob 引用: %w", err)
	}
	res, err := tx.ExecContext(ctx, `DELETE FROM exchanges WHERE `+where, args...)
	if err != nil {
		return 0, fmt.Errorf("删除索引行: %w", err)
	}
	n, _ := res.RowsAffected()
	return n, nil
}

// protectedExchangeNotInClause returns a SQL predicate that evaluates true only
// for exchanges NOT referenced by finding evidence bindings.
func (t *Traffic) protectedExchangeNotInClause(ctx context.Context, tx *indexTx) (string, error) {
	var clauses []string
	if t.db.postgres {
		var hasEvidence bool
		if err := tx.QueryRowContext(ctx,
			`SELECT to_regclass('public.finding_traffic_bindings') IS NOT NULL AND to_regclass('public.traffic_evidence_snapshots') IS NOT NULL`,
		).Scan(&hasEvidence); err != nil {
			return "", err
		}
		if hasEvidence {
			clauses = append(clauses, `id NOT IN (SELECT s.source_traffic_id FROM public.traffic_evidence_snapshots s JOIN public.finding_traffic_bindings b ON b.snapshot_id = s.id WHERE s.source_traffic_id IS NOT NULL)`)
		}
		var ftCol string
		err := tx.QueryRowContext(ctx,
			`SELECT column_name FROM information_schema.columns WHERE table_schema='public' AND table_name='finding_traffic' AND column_name IN ('exchange_id','traffic_id') ORDER BY column_name LIMIT 1`,
		).Scan(&ftCol)
		if err == nil && (ftCol == "exchange_id" || ftCol == "traffic_id") {
			clauses = append(clauses, `id NOT IN (SELECT `+ftCol+` FROM public.finding_traffic WHERE `+ftCol+` IS NOT NULL)`)
		} else if err != nil && !errors.Is(err, sql.ErrNoRows) {
			return "", err
		}
	} else {
		var count int
		if err := tx.QueryRowContext(ctx,
			`SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name IN ('finding_traffic_bindings','traffic_evidence_snapshots')`,
		).Scan(&count); err != nil {
			return "", err
		}
		if count == 2 {
			clauses = append(clauses, `id NOT IN (SELECT s.source_traffic_id FROM traffic_evidence_snapshots s JOIN finding_traffic_bindings b ON b.snapshot_id = s.id WHERE s.source_traffic_id IS NOT NULL)`)
		}
		var hasFT int
		if err := tx.QueryRowContext(ctx,
			`SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name='finding_traffic'`,
		).Scan(&hasFT); err != nil {
			return "", err
		}
		if hasFT == 1 {
			rows, err := tx.Tx.QueryContext(ctx, `PRAGMA table_info(finding_traffic)`)
			if err != nil {
				return "", err
			}
			var ftCol string
			for rows.Next() {
				var cid int
				var name, ctype string
				var notnull, pk int
				var dflt any
				if scanErr := rows.Scan(&cid, &name, &ctype, &notnull, &dflt, &pk); scanErr == nil {
					if name == "exchange_id" || name == "traffic_id" {
						ftCol = name
						break
					}
				}
			}
			_ = rows.Close()
			if ftCol != "" {
				clauses = append(clauses, `id NOT IN (SELECT `+ftCol+` FROM finding_traffic WHERE `+ftCol+` IS NOT NULL)`)
			}
		}
	}
	if len(clauses) == 0 {
		return "1=1", nil
	}
	return strings.Join(clauses, " AND "), nil
}

// PruneExchanges enforces retention bounds by deleting exchanges older than
// maxAge (if > 0) and then trimming the oldest rows exceeding maxRows (if > 0),
// while preserving any exchange referenced by finding evidence bindings.
// Orphaned content-addressed blobs are garbage-collected afterwards.
func (t *Traffic) PruneExchanges(ctx context.Context, maxAge time.Duration, maxRows int) (int64, error) {
	if t == nil || t.db == nil || (maxAge <= 0 && maxRows <= 0) {
		return 0, nil
	}
	if ctx == nil {
		ctx = context.Background()
	}
	if err := ctx.Err(); err != nil {
		return 0, err
	}
	t.wmu.Lock()
	defer t.wmu.Unlock()
	if err := ctx.Err(); err != nil {
		return 0, err
	}

	tx, err := t.db.BeginTx(ctx, nil)
	if err != nil {
		return 0, err
	}
	defer tx.Rollback() //nolint:errcheck

	notProtected, err := t.protectedExchangeNotInClause(ctx, tx)
	if err != nil {
		return 0, err
	}

	var totalDeleted int64
	if maxAge > 0 {
		cutoff := time.Now().Add(-maxAge).Unix()
		n, err := t.deleteWhereContext(ctx, tx, `ts < ? AND `+notProtected, cutoff)
		if err != nil {
			return 0, err
		}
		totalDeleted += n
	}

	if maxRows > 0 {
		var count int
		if err := tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM exchanges`).Scan(&count); err != nil {
			return 0, err
		}
		if count > maxRows {
			excess := count - maxRows
			n, err := t.deleteWhereContext(ctx, tx,
				`id IN (SELECT id FROM exchanges WHERE `+notProtected+` ORDER BY ts ASC, id ASC LIMIT ?)`,
				excess)
			if err != nil {
				return 0, err
			}
			totalDeleted += n
		}
	}

	if err := tx.Commit(); err != nil {
		return 0, err
	}
	if totalDeleted > 0 {
		t.reclaim()
		if err := t.gcBlobs(); err != nil {
			return totalDeleted, err
		}
	}
	return totalDeleted, nil
}

// startRetention runs periodic retention pruning until Close cancels t.closed.
func (t *Traffic) startRetention(interval, maxAge time.Duration, maxRows int) {
	if interval <= 0 || (maxAge <= 0 && maxRows <= 0) {
		return
	}
	t.lifecycleMu.Lock()
	if t.closing {
		t.lifecycleMu.Unlock()
		return
	}
	t.retentionWG.Add(1)
	t.lifecycleMu.Unlock()

	go func() {
		defer t.retentionWG.Done()
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		for {
			select {
			case <-t.closed:
				return
			case <-ticker.C:
				ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
				stopWatch := make(chan struct{})
				go func() {
					select {
					case <-t.closed:
						cancel()
					case <-stopWatch:
					}
				}()
				n, err := t.PruneExchanges(ctx, maxAge, maxRows)
				close(stopWatch)
				cancel()
				if err != nil && !errors.Is(err, context.Canceled) {
					log.Printf("[traffic] 定时清理历史流量失败：%v", err)
				} else if n > 0 {
					log.Printf("[traffic] 定时清理过期/超限流量 %d 条", n)
				}
			}
		}
	}()
}

// legacyBlobRefs adds hashes referenced by pre-SQLite exchanges, whose bodies are
// still .http files on disk holding "@blob sha256:<hex>" pointers. Without this
// the first collection after the upgrade would delete blobs that history still
// points at. Skipped entirely once no legacy rows remain — the steady state — so
// the tree walk is transitional rather than a permanent cost.
func (t *Traffic) legacyBlobRefs(refs map[string]struct{}) error {
	var n int
	if err := t.db.QueryRow(`SELECT COUNT(*) FROM exchanges WHERE path<>''`).Scan(&n); err != nil {
		return err
	}
	if n == 0 {
		return nil
	}
	blobRe := regexp.MustCompile(`@blob sha256:([0-9a-f]{64})`)
	return filepath.WalkDir(t.dir, func(p string, d fs.DirEntry, err error) error {
		if err != nil || d == nil {
			return nil // skip unreadable entries
		}
		if d.IsDir() {
			// _blobs/_index/_ca never contain references; skip their subtrees.
			if p != t.dir && strings.HasPrefix(d.Name(), "_") {
				return filepath.SkipDir
			}
			return nil
		}
		if nm := d.Name(); nm != "request.http" && nm != "response.http" {
			return nil
		}
		b, err := os.ReadFile(p)
		if err != nil {
			return nil
		}
		for _, m := range blobRe.FindAllSubmatch(b, -1) {
			refs[string(m[1])] = struct{}{}
		}
		return nil
	})
}

// query returns one page of exchange metadata filtered by host and/or a url
// substring. Default page size is intentionally small (3) to keep tool results
// lightweight and capped at 10; page is 0-based (page*limit offset).
func (t *Traffic) query(host, contains, bodyContains string, page, limit int) ([]ExchangeMeta, error) {
	if limit <= 0 {
		limit = 3
	}
	if limit > 10 {
		limit = 10
	}
	if page < 0 {
		page = 0
	}
	q := `SELECT id,ts,host,method,url_template,url,status,content_type,resp_len,path FROM exchanges WHERE 1=1`
	args := []any{}
	if host != "" {
		hostName, port, err := normalizeSearchHost(host)
		if err != nil {
			return nil, err
		}
		q += ` AND host=?`
		args = append(args, hostName)
		if port != "" {
			// Recorded rows historically store URL.Hostname() (without the port),
			// so constrain the original URL authority as a compatibility fallback.
			// New and old captures therefore share the same search contract.
			authority := net.JoinHostPort(hostName, port)
			q += t.metadataLike(` AND (url LIKE ? OR url LIKE ? OR url LIKE ?)`)
			args = append(args,
				"%://"+authority+"/%",
				"%://"+authority+"?%",
				"%://"+authority,
			)
		}
	}
	if contains != "" {
		q += t.metadataLike(` AND (url LIKE ? OR url_template LIKE ?)`)
		args = append(args, "%"+contains+"%", "%"+contains+"%")
	}
	if b := strings.TrimSpace(bodyContains); b != "" {
		cond, arg, ok := t.ftsFilter(b)
		if !ok {
			if !t.fts {
				return nil, fmt.Errorf("当前实例未启用全文索引，无法按正文搜索")
			}
			return nil, fmt.Errorf("正文搜索关键词至少需要 %d 个字符（当前 %d 个）", minTrigram, utf8.RuneCountInString(b))
		}
		q += ` AND ` + cond
		args = append(args, arg)
	}
	q += ` ORDER BY ts DESC LIMIT ? OFFSET ?`
	args = append(args, limit, page*limit)
	rows, err := t.db.Query(q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []ExchangeMeta
	for rows.Next() {
		var m ExchangeMeta
		if err := rows.Scan(&m.ID, &m.TS, &m.Host, &m.Method, &m.URLTemplate, &m.URL, &m.Status, &m.ContentType, &m.RespLen, &m.Path); err != nil {
			return nil, err
		}
		out = append(out, m)
	}
	return out, rows.Err()
}

// normalizeSearchHost accepts the forms agents commonly have at hand while
// keeping the stored host (URL.Hostname()) as the canonical host key. A port,
// when supplied, is applied to the URL authority so captures from different
// services on the same IP cannot be mixed.
func normalizeSearchHost(raw string) (host, port string, err error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return "", "", errors.New("host 为必填参数")
	}
	if strings.Contains(raw, "://") {
		u, parseErr := url.Parse(raw)
		if parseErr != nil || u.Host == "" {
			return "", "", fmt.Errorf("无法解析 host：%q", raw)
		}
		host, port = u.Hostname(), u.Port()
	} else if h, p, splitErr := net.SplitHostPort(raw); splitErr == nil {
		host, port = h, p
	} else if strings.HasPrefix(raw, "[") && strings.HasSuffix(raw, "]") {
		host = strings.TrimSuffix(strings.TrimPrefix(raw, "["), "]")
	} else {
		host = raw
	}
	host = strings.Trim(strings.TrimSpace(host), "[]")
	if host == "" {
		return "", "", fmt.Errorf("无法解析 host：%q", raw)
	}
	if port != "" {
		p, parseErr := strconv.Atoi(port)
		if parseErr != nil || p < 1 || p > 65535 {
			return "", "", fmt.Errorf("端口无效：%q", port)
		}
		port = strconv.Itoa(p)
	}
	return strings.ToLower(host), port, nil
}

// Tools exposes traffic lookup to work agents so they query already-captured
// traffic instead of re-curling the same resource (token + dedup win).
func (t *Traffic) Tools() []actool.CoreTool {
	allow := func(context.Context, json.RawMessage, permission.Context) permission.Decision {
		return permission.Allowed()
	}
	ro := func(json.RawMessage) bool { return true }

	search := actool.Build(actool.Spec{
		Name:        "traffic_search",
		Description: TrafficSearchDescription,
		Schema: map[string]any{
			"type": "object",
			"properties": map[string]any{
				"host":          map[string]any{"type": "string", "description": "按主机过滤（必填；如 '107.172.96.177'、'107.172.96.177:8082' 或 'http://107.172.96.177:8082/path'）"},
				"contains":      map[string]any{"type": "string", "description": "URL 子串过滤（可选，如 'api' / 'login'）"},
				"body_contains": map[string]any{"type": "string", "description": "正文全文搜索（可选，至少 3 个字符），匹配请求/响应的头与正文，如 'password' / 'root:x:0' / '内网测试'"},
				"limit":         map[string]any{"type": "integer", "description": "每页条数，默认 3，最大 10"},
				"page":          map[string]any{"type": "integer", "description": "页码，从 0 开始，默认 0（按 ts 倒序分页）"},
			},
			"required": []any{"host"},
		},
		ReadOnly:    ro,
		Permissions: allow,
		Run: func(_ context.Context, in json.RawMessage, _ *actool.ToolContext) (actool.Result, error) {
			var a struct {
				Host, Contains string
				BodyContains   string `json:"body_contains"`
				Limit          int
				Page           int
			}
			_ = json.Unmarshal(in, &a)
			if strings.TrimSpace(a.Host) == "" {
				return actool.Errorf("host 为必填参数：请指定裸主机、主机:端口或完整 URL，避免全库扫描。"), nil
			}
			rows, err := t.query(a.Host, a.Contains, a.BodyContains, a.Page, a.Limit)
			if err != nil {
				return actool.Errorf(err.Error()), nil
			}
			if len(rows) == 0 {
				return actool.Text("无匹配流量。"), nil
			}
			// 精简为最小索引：仅保留定位所需字段 + 响应码/长度，不带任何响应内容。
			type liteRow struct {
				ID      string `json:"id"`
				Method  string `json:"method"`
				URL     string `json:"url"`
				Status  int    `json:"status"`
				RespLen int    `json:"resp_len"`
			}
			lite := make([]liteRow, 0, len(rows))
			for _, r := range rows {
				lite = append(lite, liteRow{ID: r.ID, Method: r.Method, URL: r.URL, Status: r.Status, RespLen: r.RespLen})
			}
			b, _ := json.Marshal(lite)
			return actool.Text(string(b)), nil
		},
	})

	get := actool.Build(actool.Spec{
		Name:        "traffic_get",
		Description: "按 id 取一条已抓流量的请求/响应原文（过大会截断）。配合 traffic_search 用，避免重复 curl。",
		Schema: map[string]any{
			"type":       "object",
			"properties": map[string]any{"id": map[string]any{"type": "string", "description": "traffic_search 返回的 id"}},
			"required":   []any{"id"},
		},
		ReadOnly:    ro,
		Permissions: allow,
		Run: func(_ context.Context, in json.RawMessage, _ *actool.ToolContext) (actool.Result, error) {
			var a struct{ ID string }
			_ = json.Unmarshal(in, &a)
			req, resp, err := t.Get(a.ID)
			if err != nil {
				return actool.Errorf(err.Error()), nil
			}
			return actool.Text("=== REQUEST ===\n" + clip(req, 2500) + "\n\n=== RESPONSE ===\n" + clip(resp, 4000)), nil
		},
	})

	blob := actool.Build(actool.Spec{
		Name:        "traffic_blob",
		Description: "分段读取超大请求/响应体的原文。traffic_get 里显示为 '…[truncated] @blob sha256:<hash>' 的部分即存放于此，把该 hash 传进来即可取完整内容。单次最多返回 8KB，用 offset 继续往后读（返回结果会给出总长度）。适合翻阅备份文件、源码泄露、大 JSON 导出等超过内联阈值的响应。",
		Schema: map[string]any{
			"type": "object",
			"properties": map[string]any{
				"hash":   map[string]any{"type": "string", "description": "traffic_get 中 @blob sha256: 后面的 64 位十六进制值"},
				"offset": map[string]any{"type": "integer", "description": "起始字节偏移，默认 0"},
				"length": map[string]any{"type": "integer", "description": "本次读取字节数，默认且最大 8192"},
			},
			"required": []any{"hash"},
		},
		ReadOnly:    ro,
		Permissions: allow,
		Run: func(_ context.Context, in json.RawMessage, _ *actool.ToolContext) (actool.Result, error) {
			var a struct {
				Hash   string
				Offset int64
				Length int64
			}
			_ = json.Unmarshal(in, &a)
			if a.Length <= 0 || a.Length > maxBlobRead {
				a.Length = maxBlobRead
			}
			data, total, err := t.BlobRange(a.Hash, a.Offset, a.Length)
			if err != nil {
				return actool.Errorf(err.Error()), nil
			}
			if len(data) == 0 {
				return actool.Text(fmt.Sprintf("偏移 %d 已超出内容长度（总长 %d 字节）。", a.Offset, total)), nil
			}
			head := fmt.Sprintf("[offset=%d 本次=%d 总长=%d]\n", a.Offset, len(data), total)
			if isBinaryBody("", data) {
				return actool.Text(head + "二进制内容，以十六进制展示前 512 字节：\n" + hex.EncodeToString(clipBytes(data, 512))), nil
			}
			return actool.Text(head + truncateUTF8(data, len(data))), nil
		},
	})

	return []actool.CoreTool{search, get, blob}
}

// SeedToolMetas returns the traffic tools built on a ZERO receiver, for seeding the
// tools catalog (metadata only — Name/Description/InputSchema). The handlers close
// over the nil receiver but are never invoked on this instance, so it is safe.
func SeedToolMetas() []actool.CoreTool { return (&Traffic{}).Tools() }

func clip(s string, max int) string {
	if len(s) <= max {
		return s
	}
	return s[:max] + fmt.Sprintf("\n... [截断，共 %d 字节；完整在流量文件树] ...", len(s))
}
