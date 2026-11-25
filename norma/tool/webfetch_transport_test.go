package tool

import (
	"net/http"
	"testing"
	"time"
)

func TestSharedFetchTransportReuseTimeoutsAndDisableProxy(t *testing.T) {
	t.Setenv("HTTP_PROXY", "http://127.0.0.1:9999")
	t.Setenv("HTTPS_PROXY", "http://127.0.0.1:9999")

	tr1 := sharedFetchTransport(fetchClientOpts{Proxy: "http://127.0.0.1:8788"})
	tr2 := sharedFetchTransport(fetchClientOpts{Proxy: "http://127.0.0.1:8788"})
	if tr1 != tr2 {
		t.Fatal("expected cached *http.Transport reuse for identical proxy options")
	}
	if tr1.TLSHandshakeTimeout != 10*time.Second || tr1.ResponseHeaderTimeout != 30*time.Second || tr1.IdleConnTimeout != 60*time.Second {
		t.Fatalf("unexpected timeouts: tls=%v hdr=%v idle=%v", tr1.TLSHandshakeTimeout, tr1.ResponseHeaderTimeout, tr1.IdleConnTimeout)
	}
	if tr1.MaxIdleConns != 128 || tr1.MaxIdleConnsPerHost != 32 {
		t.Fatalf("unexpected pool sizes: maxIdle=%d perHost=%d", tr1.MaxIdleConns, tr1.MaxIdleConnsPerHost)
	}

	// Direct fallback must explicitly set Proxy = nil so env HTTP_PROXY is bypassed.
	direct := newFetchClientOpts(fetchClientOpts{DisableProxy: true})
	trDirect, ok := direct.Transport.(*http.Transport)
	if !ok || trDirect == nil {
		t.Fatalf("expected *http.Transport on direct client, got %T", direct.Transport)
	}
	if trDirect.Proxy != nil {
		t.Fatal("direct fallback transport must set Proxy = nil to bypass env HTTP_PROXY")
	}

	// DeepSeek search client uses a 120s response header timeout.
	trDS := sharedFetchTransport(fetchClientOpts{ResponseHeaderTimeout: 120 * time.Second})
	if trDS.ResponseHeaderTimeout != 120*time.Second {
		t.Fatalf("deepseek ResponseHeaderTimeout = %v, want 120s", trDS.ResponseHeaderTimeout)
	}
	if trDS == tr1 {
		t.Fatal("distinct response header timeout must not alias default transport")
	}
}
