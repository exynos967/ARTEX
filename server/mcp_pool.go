package server

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/RC-CHN/ARTEX/db"
	"github.com/RC-CHN/ARTEX/norma/permission"
	actool "github.com/RC-CHN/ARTEX/norma/tool"
)

const (
	defaultMCPIdleTTL        = 5 * time.Minute
	defaultMCPMetaTTL        = 10 * time.Minute
	defaultMCPConnectTimeout = 45 * time.Second
)

// mcpConnector dials a live MCP client for the given server configuration.
type mcpConnector func(ctx context.Context, m *db.MCPServer) (mcpClient, error)

// mcpToolMeta caches the schema-discovery surface of one MCP tool so subsequent
// agent runs can build lazy CoreTool proxies without re-spawning the MCP server.
type mcpToolMeta struct {
	Name        string
	Description string
	InputSchema map[string]any
	ReadOnly    bool
	Concurrent  bool
}

type mcpMetaEntry struct {
	fingerprint string
	metas       []mcpToolMeta
	fetchedAt   time.Time
}

type pooledMCP struct {
	fingerprint string
	client      mcpClient
	cancel      context.CancelFunc
	tools       map[string]actool.CoreTool
	lastUsed    time.Time
	inFlight    int
}

type connectKey struct {
	name        string
	fingerprint string
}

type inflightConnect struct {
	done  chan struct{}
	entry *pooledMCP
	metas []mcpToolMeta
	err   error
}

// mcpPool manages process-wide pooled MCP connections and schema metadata cache.
//
// Design invariants:
//   - Self-invalidating fingerprint: any edit/disable of a db.MCPServer changes its
//     SHA-256 fingerprint, evicting & closing the old live client and discarding
//     old cached metadata automatically.
//   - Metadata cache with stale fallback: fresh metadata is returned without
//     spawning a process; if a TTL refresh transiently fails while cached metadata
//     for the SAME fingerprint exists, the stale metadata is returned so
//     <available-deferred-tools> never drops tools and busts LLM prompt caches.
//   - Lazy pooled execution: LazyToolsFor returns lightweight proxies that connect
//     on demand (singleflight per (name, fingerprint)), automatically reconnect
//     once if an idle connection died, and reap idle clients after idleTTL.
type mcpPool struct {
	connector      mcpConnector
	idleTTL        time.Duration
	metaTTL        time.Duration
	connectTimeout time.Duration
	reapInterval   time.Duration
	now            func() time.Time

	ctx    context.Context
	cancel context.CancelFunc

	mu            sync.Mutex
	closed        bool
	stopCh        chan struct{}
	reaperRunning bool
	live          map[string]*pooledMCP
	meta          map[string]mcpMetaEntry
	connecting    map[connectKey]*inflightConnect
}

var (
	globalMCPPoolMu sync.Mutex
	globalMCPPool   *mcpPool
)

func defaultMCPPool() *mcpPool {
	globalMCPPoolMu.Lock()
	defer globalMCPPoolMu.Unlock()
	if globalMCPPool == nil {
		globalMCPPool = newMCPPool(connectMCP, defaultMCPIdleTTL)
	}
	return globalMCPPool
}

// CloseGlobalMCPPool closes all live pooled MCP clients and stops the idle reaper
// (intended for graceful server shutdown).
func CloseGlobalMCPPool() {
	globalMCPPoolMu.Lock()
	p := globalMCPPool
	globalMCPPool = nil
	globalMCPPoolMu.Unlock()
	if p != nil {
		_ = p.Close()
	}
}

func newMCPPool(connector mcpConnector, idleTTL time.Duration) *mcpPool {
	if connector == nil {
		connector = connectMCP
	}
	ctx, cancel := context.WithCancel(context.Background())
	return &mcpPool{
		connector:  connector,
		idleTTL:    idleTTL,
		metaTTL:    defaultMCPMetaTTL,
		now:        time.Now,
		ctx:        ctx,
		cancel:     cancel,
		stopCh:     make(chan struct{}),
		live:       make(map[string]*pooledMCP),
		meta:       make(map[string]mcpMetaEntry),
		connecting: make(map[connectKey]*inflightConnect),
	}
}

// Close evicts and closes all live pooled clients and stops the idle reaper.
func (p *mcpPool) Close() error {
	p.mu.Lock()
	if p.closed {
		p.mu.Unlock()
		return nil
	}
	p.closed = true
	close(p.stopCh)
	toClose := make([]*pooledMCP, 0, len(p.live))
	for name, e := range p.live {
		delete(p.live, name)
		toClose = append(toClose, e)
	}
	clear(p.meta)
	cancelBase := p.cancel
	p.mu.Unlock()

	for _, e := range toClose {
		closePooledMCP(e)
	}
	if cancelBase != nil {
		cancelBase()
	}
	return nil
}

// DiscoverTools returns lazy proxy CoreTools for m. If cached metadata for m's
// current config fingerprint is still fresh, it returns immediately without
// spawning or connecting to the server. Otherwise it connects/reuses via the
// pool, refreshes metadata, and falls back to same-fingerprint stale metadata on
// transient refresh failure so prompt caches stay stable.
func (p *mcpPool) DiscoverTools(ctx context.Context, m *db.MCPServer) ([]actool.CoreTool, error) {
	if m == nil {
		return nil, fmt.Errorf("nil MCP server")
	}
	if !m.Enabled {
		p.evictServer(m.Name)
		return nil, fmt.Errorf("MCP server %q is disabled", m.Name)
	}
	fp := mcpServerFingerprint(m)

	var (
		evicted *pooledMCP
		stale   []mcpToolMeta
	)
	p.mu.Lock()
	if p.closed {
		p.mu.Unlock()
		return nil, fmt.Errorf("mcp pool closed")
	}
	if cur := p.live[m.Name]; cur != nil && cur.fingerprint != fp {
		delete(p.live, m.Name)
		evicted = cur
	}
	if cached, ok := p.meta[m.Name]; ok {
		if cached.fingerprint == fp {
			if p.now().Sub(cached.fetchedAt) < p.metaTTL {
				metas := cached.metas
				p.mu.Unlock()
				closePooledMCP(evicted)
				return p.LazyToolsFor(m, metas), nil
			}
			stale = cached.metas
		} else {
			delete(p.meta, m.Name)
		}
	}
	p.mu.Unlock()
	closePooledMCP(evicted)

	// Cache miss or TTL expired: acquire or dial a pooled client and refresh metadata.
	entry, reused, metas, err := p.acquireLive(ctx, m, fp)
	if err != nil {
		if len(stale) > 0 {
			log.Printf("[mcp-pool] %s 刷新工具列表失败，降级使用缓存元数据 (%d 个工具): %v", m.Name, len(stale), err)
			return p.LazyToolsFor(m, stale), nil
		}
		return nil, err
	}

	if !reused {
		// Fresh dial already called Tools() and updated p.meta[m.Name].
		p.releaseLive(entry)
		return p.LazyToolsFor(m, metas), nil
	}

	// Reused an existing live client: check if another goroutine just refreshed metadata.
	p.mu.Lock()
	if cached, ok := p.meta[m.Name]; ok && cached.fingerprint == fp && p.now().Sub(cached.fetchedAt) < p.metaTTL {
		fresh := cached.metas
		p.mu.Unlock()
		p.releaseLive(entry)
		return p.LazyToolsFor(m, fresh), nil
	}
	p.mu.Unlock()

	// Refresh metadata from the live client; if the idle client died, reconnect once.
	tools, listErr := entry.client.Tools(ctx)
	if listErr == nil {
		toolMap, refreshed := extractToolMetas(tools)
		p.mu.Lock()
		entry.tools = toolMap
		p.meta[m.Name] = mcpMetaEntry{
			fingerprint: fp,
			metas:       refreshed,
			fetchedAt:   p.now(),
		}
		p.mu.Unlock()
		p.releaseLive(entry)
		return p.LazyToolsFor(m, refreshed), nil
	}

	p.releaseLive(entry)
	p.evictIfMatch(m.Name, entry)

	// Reconnect once on stale client failure (unless caller ctx is already done).
	if ctx.Err() == nil {
		retryEntry, retryReused, retryMetas, retryErr := p.acquireLive(ctx, m, fp)
		if retryErr == nil {
			if retryReused && len(retryMetas) == 0 {
				p.mu.Lock()
				if cached, ok := p.meta[m.Name]; ok && cached.fingerprint == fp && p.now().Sub(cached.fetchedAt) < p.metaTTL {
					retryMetas = cached.metas
				}
				p.mu.Unlock()
			}
			if retryReused && len(retryMetas) == 0 {
				if retryTools, err := retryEntry.client.Tools(ctx); err == nil {
					toolMap, refreshed := extractToolMetas(retryTools)
					p.mu.Lock()
					retryEntry.tools = toolMap
					p.meta[m.Name] = mcpMetaEntry{
						fingerprint: fp,
						metas:       refreshed,
						fetchedAt:   p.now(),
					}
					p.mu.Unlock()
					retryMetas = refreshed
				} else {
					retryErr = err
				}
			}
			p.releaseLive(retryEntry)
			if retryErr == nil {
				return p.LazyToolsFor(m, retryMetas), nil
			}
			p.evictIfMatch(m.Name, retryEntry)
		}
		listErr = retryErr
	}

	if len(stale) > 0 {
		log.Printf("[mcp-pool] %s 刷新工具列表失败，降级使用缓存元数据 (%d 个工具): %v", m.Name, len(stale), listErr)
		return p.LazyToolsFor(m, stale), nil
	}
	return nil, listErr
}

// LazyToolsFor builds lightweight CoreTool proxies from cached metadata. No live
// MCP connection is opened until a returned tool's Call/Run is actually invoked.
func (p *mcpPool) LazyToolsFor(m *db.MCPServer, metas []mcpToolMeta) []actool.CoreTool {
	srv := cloneMCPServer(m)
	out := make([]actool.CoreTool, 0, len(metas))
	for _, meta := range metas {
		meta := meta
		schema := cloneSchemaMap(meta.InputSchema)
		if schema == nil {
			schema = map[string]any{"type": "object"}
		}
		toolName := meta.Name
		readOnly := meta.ReadOnly
		concurrent := meta.Concurrent
		out = append(out, actool.Build(actool.Spec{
			Name:        toolName,
			Description: meta.Description,
			Schema:      schema,
			ReadOnly:    func(json.RawMessage) bool { return readOnly },
			Concurrent:  func(json.RawMessage) bool { return concurrent },
			Permissions: func(context.Context, json.RawMessage, permission.Context) permission.Decision {
				return permission.AskUser("call MCP tool " + toolName + "?")
			},
			Run: func(ctx context.Context, in json.RawMessage, tc *actool.ToolContext) (actool.Result, error) {
				return p.invoke(ctx, srv, toolName, in, tc)
			},
		}))
	}
	return out
}

// invoke acquires a live pooled client on demand, runs toolName, updates lastUsed,
// and reconnects once automatically if a reused idle connection died.
func (p *mcpPool) invoke(ctx context.Context, m *db.MCPServer, toolName string, input json.RawMessage, tc *actool.ToolContext) (actool.Result, error) {
	if m == nil || !m.Enabled {
		return actool.Errorf("Error: MCP server is disabled"), nil
	}
	fp := mcpServerFingerprint(m)

	for attempt := 0; attempt < 2; attempt++ {
		entry, reused, _, err := p.acquireLive(ctx, m, fp)
		if err != nil {
			return actool.Errorf("Error: MCP server " + m.Name + " unavailable: " + err.Error()), nil
		}
		p.mu.Lock()
		t := entry.tools[toolName]
		p.mu.Unlock()
		if t == nil {
			p.releaseLive(entry)
			return actool.Errorf("Error: MCP tool " + toolName + " not found on server " + m.Name), nil
		}

		res, callErr := t.Call(ctx, input, tc)
		p.releaseLive(entry)

		if attempt == 0 && reused && ctx.Err() == nil && isBrokenMCPCall(res, callErr) {
			p.evictIfMatch(m.Name, entry)
			continue
		}
		if callErr != nil {
			return actool.Errorf("Error: " + callErr.Error()), nil
		}
		return res, nil
	}
	return actool.Errorf("Error: MCP tool " + toolName + " failed after reconnect"), nil
}

func (p *mcpPool) connectTimeoutOrDefault() time.Duration {
	if p.connectTimeout > 0 {
		return p.connectTimeout
	}
	return defaultMCPConnectTimeout
}

// acquireLive returns a live pooled client matching (m.Name, fp) with inFlight
// already incremented by 1. Callers MUST pair every nil-error return with releaseLive.
// Singleflight dials run on the pool-owned context so cancelling caller A never
// poisons concurrent caller B waiting on the same MCP server.
func (p *mcpPool) acquireLive(ctx context.Context, m *db.MCPServer, fp string) (entry *pooledMCP, reused bool, metas []mcpToolMeta, err error) {
	if ctx == nil {
		ctx = context.Background()
	}
	for {
		if err := ctx.Err(); err != nil {
			return nil, false, nil, err
		}
		p.mu.Lock()
		if p.closed {
			p.mu.Unlock()
			return nil, false, nil, fmt.Errorf("mcp pool closed")
		}
		if cur := p.live[m.Name]; cur != nil {
			if cur.fingerprint == fp {
				cur.inFlight++
				cur.lastUsed = p.now()
				p.mu.Unlock()
				return cur, true, nil, nil
			}
			delete(p.live, m.Name)
			p.mu.Unlock()
			closePooledMCP(cur)
			continue
		}
		key := connectKey{name: m.Name, fingerprint: fp}
		call := p.connecting[key]
		if call == nil {
			call = &inflightConnect{done: make(chan struct{})}
			p.connecting[key] = call
			srv := cloneMCPServer(m)
			go p.runConnect(key, srv, fp, call)
		}
		p.mu.Unlock()

		select {
		case <-call.done:
			if call.err != nil {
				return nil, false, nil, call.err
			}
			// Take an inFlight reference if the freshly connected entry is still
			// active in p.live; otherwise loop to re-check/reconnect cleanly.
			p.mu.Lock()
			if !p.closed && call.entry != nil && p.live[m.Name] == call.entry && call.entry.fingerprint == fp {
				call.entry.inFlight++
				call.entry.lastUsed = p.now()
				freshMetas := call.metas
				p.mu.Unlock()
				return call.entry, false, freshMetas, nil
			}
			p.mu.Unlock()
			continue
		case <-ctx.Done():
			return nil, false, nil, ctx.Err()
		}
	}
}

func (p *mcpPool) runConnect(key connectKey, m *db.MCPServer, fp string, call *inflightConnect) {
	newEntry, newMetas, dialErr := p.dialAndList(m, fp)

	var replaced *pooledMCP
	p.mu.Lock()
	delete(p.connecting, key)
	if dialErr != nil || p.closed {
		if dialErr == nil {
			dialErr = fmt.Errorf("mcp pool closed")
		}
		call.err = dialErr
		close(call.done)
		p.mu.Unlock()
		closePooledMCP(newEntry)
		return
	}
	if prev := p.live[m.Name]; prev != nil {
		delete(p.live, m.Name)
		replaced = prev
	}
	now := p.now()
	newEntry.inFlight = 0
	newEntry.lastUsed = now
	p.live[m.Name] = newEntry
	p.meta[m.Name] = mcpMetaEntry{
		fingerprint: fp,
		metas:       newMetas,
		fetchedAt:   now,
	}
	p.ensureReaperLocked()
	call.entry = newEntry
	call.metas = newMetas
	close(call.done)
	p.mu.Unlock()

	closePooledMCP(replaced)
}

func (p *mcpPool) dialAndList(m *db.MCPServer, fp string) (*pooledMCP, []mcpToolMeta, error) {
	if err := p.ctx.Err(); err != nil {
		return nil, nil, err
	}
	dialCtx, cancelDial := context.WithCancel(p.ctx)

	// Bound the initial connect + tools/list by the pool-owned handshake timeout
	// (decoupled from any individual caller's ctx), then detach via stopWatch()
	// so the pooled subprocess outlives the handshake.
	handshakeCtx, cancelCap := context.WithTimeout(p.ctx, p.connectTimeoutOrDefault())
	stopWatch := context.AfterFunc(handshakeCtx, cancelDial)

	cl, err := p.connector(dialCtx, m)
	if err != nil {
		stopWatch()
		cancelCap()
		cancelDial()
		return nil, nil, err
	}
	tools, err := cl.Tools(handshakeCtx)
	stopped := stopWatch()
	cancelCap()
	if !stopped {
		_ = cl.Close()
		cancelDial()
		if err != nil {
			return nil, nil, err
		}
		return nil, nil, handshakeCtx.Err()
	}
	if err != nil {
		_ = cl.Close()
		cancelDial()
		return nil, nil, err
	}

	toolMap, metas := extractToolMetas(tools)
	return &pooledMCP{
		fingerprint: fp,
		client:      cl,
		cancel:      cancelDial,
		tools:       toolMap,
	}, metas, nil
}

func (p *mcpPool) releaseLive(e *pooledMCP) {
	if e == nil {
		return
	}
	p.mu.Lock()
	if e.inFlight > 0 {
		e.inFlight--
	}
	e.lastUsed = p.now()
	p.mu.Unlock()
}

func (p *mcpPool) evictIfMatch(name string, target *pooledMCP) {
	p.mu.Lock()
	var evicted *pooledMCP
	if cur := p.live[name]; cur == target {
		delete(p.live, name)
		evicted = cur
	}
	p.mu.Unlock()
	closePooledMCP(evicted)
}

func (p *mcpPool) evictServer(name string) {
	p.mu.Lock()
	evicted := p.live[name]
	delete(p.live, name)
	delete(p.meta, name)
	p.mu.Unlock()
	closePooledMCP(evicted)
}

func (p *mcpPool) ensureReaperLocked() {
	if p.reaperRunning || p.idleTTL <= 0 || p.closed {
		return
	}
	p.reaperRunning = true
	interval := p.reapInterval
	if interval <= 0 {
		interval = p.idleTTL / 2
		if interval < 10*time.Millisecond {
			interval = 10 * time.Millisecond
		}
		if interval > 30*time.Second {
			interval = 30 * time.Second
		}
	}
	stopCh := p.stopCh
	go p.reapLoop(interval, stopCh)
}

func (p *mcpPool) reapLoop(interval time.Duration, stopCh <-chan struct{}) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-stopCh:
			p.mu.Lock()
			p.reaperRunning = false
			p.mu.Unlock()
			return
		case <-ticker.C:
			var toClose []*pooledMCP
			now := p.now()
			p.mu.Lock()
			for name, e := range p.live {
				if e.inFlight == 0 && now.Sub(e.lastUsed) >= p.idleTTL {
					delete(p.live, name)
					toClose = append(toClose, e)
				}
			}
			shouldStop := len(p.live) == 0 || p.closed
			if shouldStop {
				p.reaperRunning = false
			}
			p.mu.Unlock()
			for _, e := range toClose {
				closePooledMCP(e)
			}
			if shouldStop {
				return
			}
		}
	}
}

func closePooledMCP(e *pooledMCP) {
	if e == nil {
		return
	}
	// Close the client BEFORE cancelling dialCtx so stdioCloser can perform
	// graceful stdin EOF + SIGTERM -> SIGKILL before exec.CommandContext cancels.
	if e.client != nil {
		_ = e.client.Close()
	}
	if e.cancel != nil {
		e.cancel()
	}
}

func extractToolMetas(tools []actool.CoreTool) (map[string]actool.CoreTool, []mcpToolMeta) {
	toolMap := make(map[string]actool.CoreTool, len(tools))
	metas := make([]mcpToolMeta, 0, len(tools))
	for _, t := range tools {
		toolMap[t.Name()] = t
		metas = append(metas, mcpToolMeta{
			Name:        t.Name(),
			Description: t.Description(),
			InputSchema: cloneSchemaMap(t.InputSchema()),
			ReadOnly:    t.IsReadOnly(nil),
			Concurrent:  t.IsConcurrencySafe(nil),
		})
	}
	return toolMap, metas
}

// isBrokenMCPCall reports whether a failed tool call indicates a dead underlying
// transport connection (rather than a normal tool/application error) that merits
// one transparent reconnect.
func isBrokenMCPCall(res actool.Result, callErr error) bool {
	if callErr != nil {
		return true
	}
	if !res.IsError {
		return false
	}
	txt := strings.ToLower(res.Flatten())
	for _, sig := range []string{
		"mcp: connection closed",
		"broken pipe",
		"file already closed",
		"pipe is being closed",
		"pipe has been ended",
		"mcp sse stream:",
		"connection reset",
		"unexpected eof",
	} {
		if strings.Contains(txt, sig) {
			return true
		}
	}
	return strings.HasSuffix(strings.TrimSpace(txt), ": eof")
}

// mcpServerFingerprint hashes every operational field of an MCPServer so any DB
// edit (command, args, env/headers, URL, TLS mode, enabled flag) deterministically
// invalidates cached metadata and evicts stale pooled clients.
func mcpServerFingerprint(m *db.MCPServer) string {
	if m == nil {
		return ""
	}
	type kv struct {
		K string `json:"k"`
		V string `json:"v"`
	}
	var envPairs []kv
	var rawEnv string
	if len(m.Env) > 0 {
		var envMap map[string]string
		if err := json.Unmarshal(m.Env, &envMap); err == nil {
			keys := make([]string, 0, len(envMap))
			for k := range envMap {
				keys = append(keys, k)
			}
			sort.Strings(keys)
			envPairs = make([]kv, 0, len(keys))
			for _, k := range keys {
				envPairs = append(envPairs, kv{K: k, V: envMap[k]})
			}
		} else {
			rawEnv = string(m.Env)
		}
	}
	var args []string
	var rawArgs string
	if len(m.Args) > 0 {
		if err := json.Unmarshal(m.Args, &args); err != nil {
			rawArgs = string(m.Args)
		}
	}
	payload := struct {
		ID        int64    `json:"id"`
		Name      string   `json:"name"`
		Transport string   `json:"transport"`
		Command   string   `json:"command"`
		Args      []string `json:"args,omitempty"`
		RawArgs   string   `json:"raw_args,omitempty"`
		Env       []kv     `json:"env,omitempty"`
		RawEnv    string   `json:"raw_env,omitempty"`
		URL       string   `json:"url"`
		Insecure  bool     `json:"insecure"`
		Enabled   bool     `json:"enabled"`
	}{
		ID:        m.ID,
		Name:      m.Name,
		Transport: m.Transport,
		Command:   m.Command,
		Args:      args,
		RawArgs:   rawArgs,
		Env:       envPairs,
		RawEnv:    rawEnv,
		URL:       m.URL,
		Insecure:  m.Insecure,
		Enabled:   m.Enabled,
	}
	b, _ := json.Marshal(payload)
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

func cloneMCPServer(m *db.MCPServer) *db.MCPServer {
	if m == nil {
		return nil
	}
	cp := *m
	cp.Args = append(json.RawMessage(nil), m.Args...)
	cp.Env = append(json.RawMessage(nil), m.Env...)
	cp.Tools = append([]string(nil), m.Tools...)
	return &cp
}

func cloneSchemaMap(src map[string]any) map[string]any {
	if src == nil {
		return nil
	}
	dst := make(map[string]any, len(src))
	for k, v := range src {
		dst[k] = cloneSchemaValue(v)
	}
	return dst
}

func cloneSchemaValue(v any) any {
	switch x := v.(type) {
	case map[string]any:
		return cloneSchemaMap(x)
	case []any:
		out := make([]any, len(x))
		for i, elem := range x {
			out[i] = cloneSchemaValue(elem)
		}
		return out
	default:
		return v
	}
}
