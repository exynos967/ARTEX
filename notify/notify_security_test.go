package notify

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
	"time"
	"unicode/utf8"
)

func TestNotifyTransportIgnoresHTTPProxyEnv(t *testing.T) {
	if notifyTransport.Proxy != nil {
		t.Fatal("notifyTransport.Proxy must be nil so HTTP_PROXY cannot bypass blockInternalDial")
	}

	var proxyHit atomic.Bool
	fakeProxy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		proxyHit.Store(true)
		_, _ = io.WriteString(w, `{"errcode":0,"errmsg":"via-proxy"}`)
	}))
	defer fakeProxy.Close()

	var targetHit atomic.Bool
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		targetHit.Store(true)
		_, _ = io.WriteString(w, `{"errcode":0,"errmsg":"direct"}`)
	}))
	defer target.Close()

	t.Setenv("HTTP_PROXY", fakeProxy.URL)
	t.Setenv("HTTPS_PROXY", fakeProxy.URL)
	t.Setenv("NO_PROXY", "")

	// With local targets allowed, request must hit target directly, NOT fakeProxy.
	t.Setenv(AllowLocalTargetsEnv, "1")
	if _, err := doJSON(context.Background(), http.MethodPost, target.URL+"/hook", nil, map[string]string{"k": "v"}); err != nil {
		t.Fatalf("direct local request failed: %v", err)
	}
	if proxyHit.Load() {
		t.Fatal("notifyTransport routed through HTTP_PROXY instead of direct dial")
	}
	if !targetHit.Load() {
		t.Fatal("direct target was not reached")
	}

	// With local targets disallowed (default), HTTP_PROXY must NOT bypass blockInternalDial.
	notifyTransport.CloseIdleConnections()
	t.Setenv(AllowLocalTargetsEnv, "")
	_, err := doJSON(context.Background(), http.MethodPost, target.URL+"/hook", nil, map[string]string{"k": "v"})
	if err == nil {
		t.Fatal("loopback target must still be rejected even when HTTP_PROXY is set")
	}
	if proxyHit.Load() {
		t.Fatal("HTTP_PROXY was contacted to bypass SSRF dial guard")
	}
}

func TestCheckRedirectRejectsHTTPSDowngradeAndMatchesHostCaseInsensitively(t *testing.T) {
	initial, _ := http.NewRequest(http.MethodPost, "https://Hook.Example.COM/bot/send?token=s3cret", nil)

	// 1. HTTPS -> HTTP downgrade on same host MUST be rejected.
	downgrade, _ := http.NewRequest(http.MethodPost, "http://Hook.Example.COM/bot/send?token=s3cret", nil)
	if err := httpClient.CheckRedirect(downgrade, []*http.Request{initial}); err == nil {
		t.Fatal("expected HTTPS -> HTTP downgrade redirect to be rejected")
	}

	// 2. HTTPS -> HTTPS same host differing only in letter case MUST be allowed.
	sameHostDiffCase, _ := http.NewRequest(http.MethodPost, "https://hook.example.com/bot/send/", nil)
	if err := httpClient.CheckRedirect(sameHostDiffCase, []*http.Request{initial}); err != nil {
		t.Fatalf("case-insensitive same-host HTTPS redirect should be allowed, got: %v", err)
	}

	// 3. Cross-host redirect MUST still be rejected.
	crossHost, _ := http.NewRequest(http.MethodPost, "https://evil.example.com/bot/send", nil)
	if err := httpClient.CheckRedirect(crossHost, []*http.Request{initial}); err == nil {
		t.Fatal("cross-host HTTPS redirect should be rejected")
	}
}

func TestRedactTransportErrorRedactsNestedURLErr(t *testing.T) {
	inner := fmt.Errorf("upstream redirect to https://api.telegram.org/bot%s/sendMessage refused", leakProbeToken)
	uerr := &url.Error{
		Op:  "Post",
		URL: "https://api.telegram.org/bot" + leakProbeToken + "/sendMessage",
		Err: inner,
	}
	got := redactTransportError(uerr)
	assertNoSecret(t, got, leakProbeToken)
	if !strings.Contains(got, "https://api.telegram.org/…") {
		t.Fatalf("expected embedded URL in uerr.Err to be redacted, got %q", got)
	}
}

func TestEmailDialHonorsContextCancellation(t *testing.T) {
	t.Setenv(AllowLocalTargetsEnv, "1")

	for _, tc := range []struct {
		name        string
		implicitTLS bool
		sendBanner  bool
	}{
		{"plain TCP banner hang", false, false},
		{"implicit TLS handshake hang", true, false},
		{"plain TCP mid-session hang after banner", false, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ln, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			defer ln.Close()

			accepted := make(chan struct{}, 1)
			doneSrv := make(chan struct{})
			defer close(doneSrv)
			go func() {
				conn, err := ln.Accept()
				if err != nil {
					return
				}
				defer conn.Close()
				select {
				case accepted <- struct{}{}:
				default:
				}
				if tc.sendBanner {
					// Send SMTP greeting then stall on EHLO so smtp.NewClient succeeds
					// and subsequent Send() operations block until ctx cancels.
					_, _ = conn.Write([]byte("220 slow.local ESMTP\r\n"))
				}
				<-doneSrv
			}()

			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()

			errCh := make(chan error, 1)
			go func() {
				if tc.sendBanner {
					addr := ln.Addr().(*net.TCPAddr)
					cfg := map[string]any{
						"host": "127.0.0.1",
						"port": float64(addr.Port),
						"from": "a@example.com",
						"to":   []any{"b@example.com"},
					}
					_, sendErr := (emailChannel{}).Send(ctx, cfg, singleMsg())
					errCh <- sendErr
					return
				}
				client, dialErr := emailDial(ctx, ln.Addr().String(), "127.0.0.1", tc.implicitTLS)
				if client != nil {
					_ = client.Close()
				}
				errCh <- dialErr
			}()

			select {
			case <-accepted:
			case <-time.After(2 * time.Second):
				t.Fatal("server never accepted SMTP connection")
			}

			// Allow brief time for handshake/greeting read to enter blocking state, then cancel.
			time.Sleep(25 * time.Millisecond)
			cancelStart := time.Now()
			cancel()

			select {
			case err := <-errCh:
				if err == nil {
					t.Fatal("expected error after context cancellation")
				}
				if elapsed := time.Since(cancelStart); elapsed > time.Second {
					t.Fatalf("SMTP operation took %v after cancel, want < 1s", elapsed)
				}
			case <-time.After(2 * time.Second):
				t.Fatal("SMTP operation hung after context cancellation")
			}
		})
	}
}

func TestDingTalkAndFeishuRateLimitsAreRetryable(t *testing.T) {
	// DingTalk 130101 is rate-limited (retryable).
	dtLimited := capturePost(t, `{"errcode":130101,"errmsg":"send too fast"}`, nil)
	_, err := (dingTalkChannel{}).Send(context.Background(), map[string]any{"webhook": dtLimited.URL}, singleMsg())
	if err == nil {
		t.Fatal("DingTalk 130101 should return error")
	}
	if IsPermanent(err) {
		t.Fatalf("DingTalk 130101 rate limit must be retryable (non-Permanent), got: %v", err)
	}

	// Feishu rate-limit codes across both `code` and `StatusCode` fields.
	for _, code := range []int{11232, 9499, 99991400} {
		srvCode := capturePost(t, fmt.Sprintf(`{"code":%d,"msg":"too many requests"}`, code), nil)
		_, err := (feishuChannel{}).Send(context.Background(), map[string]any{"webhook": srvCode.URL}, singleMsg())
		if err == nil || IsPermanent(err) {
			t.Fatalf("Feishu code=%d must be retryable, got err=%v permanent=%v", code, err, IsPermanent(err))
		}

		srvStatus := capturePost(t, fmt.Sprintf(`{"StatusCode":%d,"StatusMessage":"rate limit"}`, code), nil)
		_, err = (feishuChannel{}).Send(context.Background(), map[string]any{"webhook": srvStatus.URL}, singleMsg())
		if err == nil || IsPermanent(err) {
			t.Fatalf("Feishu StatusCode=%d must be retryable, got err=%v permanent=%v", code, err, IsPermanent(err))
		}
	}

	// Non-rate-limit Feishu config error (19021 invalid sign) stays Permanent.
	fsBadSign := capturePost(t, `{"code":19021,"msg":"sign match fail"}`, nil)
	_, err = (feishuChannel{}).Send(context.Background(), map[string]any{"webhook": fsBadSign.URL}, singleMsg())
	if err == nil || !IsPermanent(err) {
		t.Fatalf("Feishu 19021 should be Permanent, got err=%v", err)
	}
}

func TestMaskedValueHandlesUTF8Runes(t *testing.T) {
	// 4 CJK runes = 12 bytes (> 6 bytes, but <= 6 runes) must NOT leak tail hint.
	shortCJK := "机密密码"
	if got := MaskedValue(shortCJK); got != MaskedPrefix {
		t.Fatalf("short 4-rune CJK secret leaked hint: %q", got)
	}
	sixCJK := "一二三四五六"
	if got := MaskedValue(sixCJK); got != MaskedPrefix {
		t.Fatalf("6-rune CJK secret leaked hint: %q", got)
	}

	// Longer multi-byte UTF-8 secret (CJK + emoji) must slice on rune boundary and stay valid UTF-8.
	longUTF8 := "prefix-🔑密码测试一二三四五六"
	got := MaskedValue(longUTF8)
	if !utf8.ValidString(got) {
		t.Fatalf("MaskedValue produced invalid UTF-8: %q", got)
	}
	want := MaskedPrefix + ":…一二三四五六"
	if got != want {
		t.Fatalf("MaskedValue(%q) = %q, want %q", longUTF8, got, want)
	}
	if errors.Is(nil, nil) && !IsMasked(got) {
		t.Fatalf("MaskedValue result not recognized by IsMasked: %q", got)
	}
}
