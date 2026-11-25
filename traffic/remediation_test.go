package traffic

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"database/sql"
	"database/sql/driver"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
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

// dialProxyTLS opens a CONNECT tunnel through tr's MITM proxy and completes a
// TLS handshake verifying against tr's MITM CA.
func dialProxyTLS(t *testing.T, tr *Traffic, targetAddr, serverName string) (*tls.Conn, *bufio.Reader) {
	t.Helper()
	caPEM, err := os.ReadFile(tr.CACertPath())
	if err != nil {
		t.Fatalf("read CA: %v", err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(caPEM) {
		t.Fatal("parse CA PEM failed")
	}

	raw, err := net.DialTimeout("tcp", tr.effectiveListenAddr(), 3*time.Second)
	if err != nil {
		t.Fatalf("dial proxy: %v", err)
	}
	_ = raw.SetDeadline(time.Now().Add(5 * time.Second))
	if _, err := fmt.Fprintf(raw, "CONNECT %s HTTP/1.1\r\nHost: %s\r\n\r\n", targetAddr, targetAddr); err != nil {
		_ = raw.Close()
		t.Fatalf("write CONNECT: %v", err)
	}
	br := bufio.NewReader(raw)
	resp, err := http.ReadResponse(br, &http.Request{Method: http.MethodConnect})
	if err != nil || resp.StatusCode != http.StatusOK {
		_ = raw.Close()
		t.Fatalf("CONNECT failed: resp=%v err=%v", resp, err)
	}
	_ = raw.SetDeadline(time.Time{})

	var baseConn net.Conn = raw
	if br.Buffered() > 0 {
		baseConn = &bufferedConn{Conn: raw, r: br}
	}
	tlsConn := tls.Client(baseConn, &tls.Config{
		RootCAs:    pool,
		ServerName: serverName,
	})
	if err := tlsConn.Handshake(); err != nil {
		_ = raw.Close()
		t.Fatalf("MITM TLS handshake: %v", err)
	}
	return tlsConn, bufio.NewReader(tlsConn)
}

// [P1-14] Verify mitmProxy.Close() never deadlocks when an HTTP Upgrade tunnel is active.
func TestMITMProxyCloseDoesNotDeadlockOnActiveUpgradeTunnel(t *testing.T) {
	tunnelEstablished := make(chan struct{}, 1)
	upstreamClosed := make(chan struct{}, 1)
	upgradeSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hj, ok := w.(http.Hijacker)
		if !ok {
			http.Error(w, "no hijack", http.StatusInternalServerError)
			return
		}
		c, rw, err := hj.Hijack()
		if err != nil {
			return
		}
		defer func() {
			_ = c.Close()
			select {
			case upstreamClosed <- struct{}{}:
			default:
			}
		}()
		_, _ = rw.WriteString("HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: ws\r\n\r\n")
		_ = rw.Flush()
		select {
		case tunnelEstablished <- struct{}{}:
		default:
		}
		// Block indefinitely waiting for client data until proxy closes the tunnel.
		buf := make([]byte, 64)
		for {
			if _, err := rw.Read(buf); err != nil {
				return
			}
		}
	}))
	defer upgradeSrv.Close()

	tr, _ := startHardeningProxy(t)
	conn, err := net.DialTimeout("tcp", tr.effectiveListenAddr(), 3*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	u, _ := url.Parse(upgradeSrv.URL)
	_, err = fmt.Fprintf(conn, "GET %s/ws HTTP/1.1\r\nHost: %s\r\nConnection: Upgrade\r\nUpgrade: ws\r\n\r\n", upgradeSrv.URL, u.Host)
	if err != nil {
		t.Fatal(err)
	}
	br := bufio.NewReader(conn)
	resp, err := http.ReadResponse(br, &http.Request{Method: http.MethodGet})
	if err != nil || resp.StatusCode != http.StatusSwitchingProtocols {
		t.Fatalf("upgrade handshake failed: resp=%v err=%v", resp, err)
	}
	<-tunnelEstablished

	// Close() must forcefully tear down the active upgrade tunnel promptly without deadlocking.
	closed := make(chan error, 1)
	go func() {
		closed <- tr.proxy.Close()
	}()
	select {
	case err := <-closed:
		if err != nil {
			t.Fatalf("proxy.Close: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("mitmProxy.Close deadlocked on active HTTP Upgrade tunnel")
	}
	select {
	case <-upstreamClosed:
	case <-time.After(2 * time.Second):
		t.Fatal("upstream upgrade connection was not closed when proxy closed")
	}
}

// [P1-15] Verify HTTPS keep-alive closes connection when upstream replies early
// without consuming req.Body (preventing HTTP/1.1 framing desync), while still
// keeping connections alive when req.Body IS fully consumed.
func TestMITMHTTPSUnreadReqBodyForcesConnectionClose(t *testing.T) {
	var hits atomic.Int32
	target := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		switch r.URL.Path {
		case "/reject-early":
			// Intentionally reply 413 WITHOUT reading r.Body and close upstream side.
			w.Header().Set("Connection", "close")
			w.WriteHeader(http.StatusRequestEntityTooLarge)
			_, _ = io.WriteString(w, "too large")
		case "/echo":
			b, _ := io.ReadAll(r.Body)
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write(b)
		}
	}))
	defer target.Close()

	tr, _ := startHardeningProxy(t)
	u, _ := url.Parse(target.URL)

	// 1. Early 413 response with unread large request body must send Connection: close
	// and close the TLS connection cleanly (never desync).
	tlsConn, br := dialProxyTLS(t, tr, u.Host, "127.0.0.1")
	defer tlsConn.Close()
	_ = tlsConn.SetDeadline(time.Now().Add(5 * time.Second))

	// Declare 1 MiB body, send only headers + 16 bytes so upstream rejects before EOF.
	reqHdr := fmt.Sprintf("POST /reject-early HTTP/1.1\r\nHost: %s\r\nContent-Length: %d\r\n\r\n", u.Host, 1<<20)
	if _, err := io.WriteString(tlsConn, reqHdr+"partial-body-123"); err != nil {
		t.Fatal(err)
	}
	resp, err := http.ReadResponse(br, &http.Request{Method: http.MethodPost})
	if err != nil {
		t.Fatalf("read 413 response: %v", err)
	}
	_, _ = io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusRequestEntityTooLarge {
		t.Fatalf("status=%d, want 413", resp.StatusCode)
	}
	if !resp.Close {
		t.Fatalf("expected Connection: close on early unread-body response, headers=%v", resp.Header)
	}

	// 2. Normal keep-alive POST (full Content-Length body + chunked body) must reuse the SAME TLS conn.
	tlsConn2, br2 := dialProxyTLS(t, tr, u.Host, "127.0.0.1")
	defer tlsConn2.Close()
	_ = tlsConn2.SetDeadline(time.Now().Add(5 * time.Second))

	for i, rawReq := range []string{
		fmt.Sprintf("POST /echo HTTP/1.1\r\nHost: %s\r\nContent-Length: 5\r\n\r\nhello", u.Host),
		fmt.Sprintf("POST /echo HTTP/1.1\r\nHost: %s\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nworld\r\n0\r\n\r\n", u.Host),
	} {
		if _, err := io.WriteString(tlsConn2, rawReq); err != nil {
			t.Fatalf("keep-alive req #%d write: %v", i, err)
		}
		r, err := http.ReadResponse(br2, &http.Request{Method: http.MethodPost})
		if err != nil {
			t.Fatalf("keep-alive req #%d read: %v", i, err)
		}
		body, _ := io.ReadAll(r.Body)
		r.Body.Close()
		if r.StatusCode != 200 || r.Close {
			t.Fatalf("keep-alive req #%d status=%d close=%v", i, r.StatusCode, r.Close)
		}
		want := []string{"hello", "world"}[i]
		if string(body) != want {
			t.Fatalf("keep-alive req #%d body=%q, want %q", i, body, want)
		}
	}
}

// [P1-16] Verify HTTPS Expect: 100-continue sends 100 Continue before reading body
// (so curl -X POST never stalls) and cleanly rejects without 100 Continue when upstream refuses.
func TestMITMHTTPSExpect100Continue(t *testing.T) {
	target := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/deny" {
			w.WriteHeader(http.StatusUnauthorized)
			_, _ = io.WriteString(w, "denied")
			return
		}
		b, _ := io.ReadAll(r.Body)
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(b)
	}))
	defer target.Close()

	tr, _ := startHardeningProxy(t)
	u, _ := url.Parse(target.URL)

	// 1. Happy path: client waits for 100 Continue before sending body.
	tlsConn, br := dialProxyTLS(t, tr, u.Host, "127.0.0.1")
	defer tlsConn.Close()
	_ = tlsConn.SetDeadline(time.Now().Add(5 * time.Second))

	payload := "expect-100-body-ok"
	if _, err := fmt.Fprintf(tlsConn, "POST /upload HTTP/1.1\r\nHost: %s\r\nExpect: 100-continue\r\nContent-Length: %d\r\n\r\n", u.Host, len(payload)); err != nil {
		t.Fatal(err)
	}
	statusLine, err := br.ReadString('\n')
	if err != nil {
		t.Fatalf("waiting for 100 Continue failed: %v", err)
	}
	if !strings.HasPrefix(statusLine, "HTTP/1.1 100 ") {
		t.Fatalf("expected HTTP/1.1 100 Continue, got %q", statusLine)
	}
	blank, err := br.ReadString('\n')
	if err != nil || blank != "\r\n" {
		t.Fatalf("expected blank line after 100 Continue, got %q err=%v", blank, err)
	}
	if _, err := io.WriteString(tlsConn, payload); err != nil {
		t.Fatal(err)
	}
	resp, err := http.ReadResponse(br, &http.Request{Method: http.MethodPost})
	if err != nil {
		t.Fatalf("read final 200 response: %v", err)
	}
	gotBody, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != 200 || string(gotBody) != payload {
		t.Fatalf("final response status=%d body=%q, want 200 %q", resp.StatusCode, gotBody, payload)
	}

	// 2. Early rejection path: upstream returns 401 without 100 Continue.
	tlsConn2, br2 := dialProxyTLS(t, tr, u.Host, "127.0.0.1")
	defer tlsConn2.Close()
	_ = tlsConn2.SetDeadline(time.Now().Add(5 * time.Second))
	if _, err := fmt.Fprintf(tlsConn2, "POST /deny HTTP/1.1\r\nHost: %s\r\nExpect: 100-continue\r\nContent-Length: 100\r\n\r\n", u.Host); err != nil {
		t.Fatal(err)
	}
	resp2, err := http.ReadResponse(br2, &http.Request{Method: http.MethodPost})
	if err != nil {
		t.Fatalf("read early 401 response: %v", err)
	}
	b2, _ := io.ReadAll(resp2.Body)
	resp2.Body.Close()
	if resp2.StatusCode != http.StatusUnauthorized || string(b2) != "denied" {
		t.Fatalf("early rejection status=%d body=%q, want 401 denied", resp2.StatusCode, b2)
	}
}

// [P1-17] Verify HTTPS CONNECT dials targetAddr (exact IP/port) while forwarding
// virtual-host Host header intact on the wire and in recorded ReqHead.
func TestMITMHTTPSConnectTargetAddrVsVirtualHostHeader(t *testing.T) {
	var seenHost atomic.Value
	target := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seenHost.Store(r.Host)
		_, _ = fmt.Fprintf(w, "vhost=%s", r.Host)
	}))
	defer target.Close()

	tr, client := startHardeningProxy(t)
	req, err := http.NewRequest(http.MethodGet, target.URL+"/secret", nil)
	if err != nil {
		t.Fatal(err)
	}
	// Non-existent virtual host: dialing admin.internal would fail DNS; only
	// dialing CONNECT targetAddr while preserving Host: admin.internal succeeds!
	req.Host = "Admin.Internal"
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("HTTPS virtual-host request failed: %v", err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != 200 || string(body) != "vhost=Admin.Internal" {
		t.Fatalf("unexpected response status=%d body=%q", resp.StatusCode, body)
	}
	if got, _ := seenHost.Load().(string); got != "Admin.Internal" {
		t.Fatalf("upstream saw Host=%q, want Admin.Internal", got)
	}

	waitFlushedCount(t, tr, 1)
	rows, err := tr.Search("127.0.0.1", 0, 10)
	if err != nil || len(rows) != 1 {
		t.Fatalf("recorded rows=%d err=%v, want 1", len(rows), err)
	}
	reqText, _, err := tr.Get(rows[0].ID)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(reqText, "Host: Admin.Internal") {
		t.Fatalf("recorded ReqHead lost virtual Host header:\n%s", reqText)
	}
}

// [P2-15] Verify HTTPS MITM SSE responses flush immediately without buffering in 4 KiB chunks.
func TestMITMHTTPSSSEFlushesImmediately(t *testing.T) {
	gotFirst := make(chan struct{})
	target := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fl := w.(http.Flusher)
		w.Header().Set("Content-Type", "text/event-stream")
		w.Header().Set("Cache-Control", "no-cache")
		_, _ = io.WriteString(w, "data: ping-1\n\n")
		fl.Flush()
		// Block until client actually receives the tiny 14-byte first event!
		select {
		case <-gotFirst:
		case <-r.Context().Done():
			return
		}
		_, _ = io.WriteString(w, "data: ping-2\n\n")
		fl.Flush()
	}))
	defer target.Close()

	tr, client := startHardeningProxy(t)
	_ = tr
	resp, err := client.Get(target.URL + "/events")
	if err != nil {
		t.Fatalf("HTTPS SSE GET failed: %v", err)
	}
	defer resp.Body.Close()

	br := bufio.NewReader(resp.Body)
	firstLineCh := make(chan string, 1)
	go func() {
		line, _ := br.ReadString('\n')
		firstLineCh <- line
	}()

	select {
	case line := <-firstLineCh:
		if line != "data: ping-1\n" {
			t.Fatalf("first SSE line = %q, want %q", line, "data: ping-1\n")
		}
	case <-time.After(1 * time.Second):
		t.Fatal("HTTPS SSE first event did not flush promptly (buffered inside Response.Write?)")
	}

	close(gotFirst)
	rest, err := io.ReadAll(br)
	if err != nil {
		t.Fatalf("read remaining SSE: %v", err)
	}
	if !strings.Contains(string(rest), "data: ping-2") {
		t.Fatalf("missing second SSE event: %q", rest)
	}
}

// [P2-16] Verify mitmProxy.Shutdown(ctx) immediately interrupts idle HTTPS keep-alive
// connections (no 5s hang/DeadlineExceeded) while allowing active in-flight HTTPS requests to finish.
func TestMITMProxyShutdownIdleKeepAliveFastAndDrainsActiveHTTPS(t *testing.T) {
	// Subtest 1: Idle HTTPS keep-alive connection must NOT stall Shutdown().
	t.Run("idle keep-alive closes immediately", func(t *testing.T) {
		target := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			_, _ = io.WriteString(w, "ok")
		}))
		defer target.Close()

		tr, client := startHardeningProxy(t)
		resp, err := client.Get(target.URL + "/keepalive")
		if err != nil {
			t.Fatal(err)
		}
		_, _ = io.ReadAll(resp.Body)
		resp.Body.Close()
		// Deliberately keep client's idle TLS connection open in the keep-alive pool.

		// Give serveMITMTLS a brief moment to loop back to idle ReadRequest.
		time.Sleep(25 * time.Millisecond)

		start := time.Now()
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := tr.Shutdown(ctx); err != nil {
			t.Fatalf("Shutdown returned error with idle HTTPS keep-alive: %v", err)
		}
		if elapsed := time.Since(start); elapsed > time.Second {
			t.Fatalf("Shutdown took %v with idle HTTPS keep-alive (expected fast return)", elapsed)
		}
	})

	// Subtest 2: Active in-flight HTTPS request finishes cleanly during Shutdown().
	t.Run("active in-flight HTTPS drains gracefully", func(t *testing.T) {
		started := make(chan struct{})
		release := make(chan struct{})
		target := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			close(started)
			<-release
			_, _ = io.WriteString(w, "in-flight-https-ok")
		}))
		defer target.Close()

		tr, client := startHardeningProxy(t)
		reqErr := make(chan error, 1)
		go func() {
			resp, err := client.Get(target.URL + "/slow")
			if err != nil {
				reqErr <- err
				return
			}
			b, rerr := io.ReadAll(resp.Body)
			resp.Body.Close()
			if rerr != nil {
				reqErr <- rerr
				return
			}
			if string(b) != "in-flight-https-ok" {
				reqErr <- fmt.Errorf("body=%q", b)
				return
			}
			reqErr <- nil
		}()
		<-started

		shutDone := make(chan error, 1)
		go func() {
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			shutDone <- tr.Shutdown(ctx)
		}()

		// Confirm Shutdown waits while the active HTTPS request is still running.
		select {
		case err := <-shutDone:
			t.Fatalf("Shutdown returned before active HTTPS request finished: %v", err)
		case <-time.After(50 * time.Millisecond):
		}

		close(release)
		if err := <-reqErr; err != nil {
			t.Fatalf("active HTTPS request failed during Shutdown: %v", err)
		}
		if err := <-shutDone; err != nil {
			t.Fatalf("Shutdown error after active HTTPS drained: %v", err)
		}
	})
}

// [P3-2] Verify leaf cert CommonName is omitted when host > 64 chars while SAN validates cleanly.
func TestSignLeafLongHostnameOmitsCNAndVerifiesSAN(t *testing.T) {
	ca, err := loadOrCreateCA(filepath.Join(t.TempDir(), "_ca"))
	if err != nil {
		t.Fatal(err)
	}
	longHost := strings.Repeat("a", 35) + "." + strings.Repeat("b", 35) + ".example.com"
	if len(longHost) <= 64 {
		t.Fatalf("test hostname too short: %d", len(longHost))
	}
	cert, err := ca.GetCert(longHost)
	if err != nil {
		t.Fatalf("GetCert(%q): %v", longHost, err)
	}
	if len(cert.Leaf.Subject.CommonName) > 64 {
		t.Fatalf("CommonName exceeded 64 octets: %d", len(cert.Leaf.Subject.CommonName))
	}
	pool := x509.NewCertPool()
	pool.AddCert(ca.rootCert)
	if _, err := cert.Leaf.Verify(x509.VerifyOptions{DNSName: longHost, Roots: pool}); err != nil {
		t.Fatalf("long hostname SAN verification failed: %v", err)
	}
}

// [P1-18] Verify host case normalization across recordBatch, ExportHosts, StageDeleteHostsExact, and ImportArchive.
func TestHostCaseNormalizationAcrossRecordExportDeleteImport(t *testing.T) {
	tr, _ := openTraffic(t)

	flow := newFlow("MiXeD.ExAmPlE.CoM", "GET", "/case-test", nil, []byte("body-ok"))
	flow.Request.Host = "MiXeD.ExAmPlE.CoM"
	if err := tr.recordFlow(flow); err != nil {
		t.Fatal(err)
	}

	var storedHost string
	var id string
	if err := tr.DB().QueryRow(`SELECT id, host FROM exchanges LIMIT 1`).Scan(&id, &storedHost); err != nil {
		t.Fatal(err)
	}
	if storedHost != "mixed.example.com" {
		t.Fatalf("stored host = %q, want lowercase mixed.example.com", storedHost)
	}
	reqRaw, _, err := tr.Get(id)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(reqRaw, "Host: MiXeD.ExAmPlE.CoM") {
		t.Fatalf("ReqHead must preserve raw Host header casing:\n%s", reqRaw)
	}

	// Export with uppercase host matches normalized DB row.
	archiveDir := filepath.Join(t.TempDir(), "case-archive")
	n, err := tr.ExportHosts([]string{"MIXED.EXAMPLE.COM"}, archiveDir)
	if err != nil || n != 1 {
		t.Fatalf("ExportHosts uppercase count=%d err=%v, want 1", n, err)
	}

	// StageDeleteHostsExact with mixed-case host deletes normalized DB row.
	deleted, err := tr.DeleteHostsExact([]string{"Mixed.Example.COM"})
	if err != nil || deleted != 1 {
		t.Fatalf("DeleteHostsExact mixed-case deleted=%d err=%v, want 1", deleted, err)
	}

	// ImportArchive with an uppercase host in the archive normalizes on insert.
	upperArchive := filepath.Join(t.TempDir(), "upper-import")
	if err := os.MkdirAll(upperArchive, 0o700); err != nil {
		t.Fatal(err)
	}
	manifest, _ := json.Marshal(ArchiveSnapshot{Version: 2, Format: "ndjson", Count: 1, Blobs: []string{}})
	if err := os.WriteFile(filepath.Join(upperArchive, "traffic.json"), manifest, 0o600); err != nil {
		t.Fatal(err)
	}
	rowJSON, _ := json.Marshal(ArchiveExchange{
		ID: "upper-id-1", TS: 100, Host: "UPPER.IMPORT.EXAMPLE", Method: "GET",
		URLTemplate: "/", URL: "https://UPPER.IMPORT.EXAMPLE/", Status: 200,
		ReqHead: "GET / HTTP/1.1\nHost: UPPER.IMPORT.EXAMPLE\n", RespHead: "HTTP 200\n",
	})
	if err := os.WriteFile(filepath.Join(upperArchive, "traffic.ndjson"), append(rowJSON, '\n'), 0o600); err != nil {
		t.Fatal(err)
	}
	if imported, err := tr.ImportArchive(upperArchive); err != nil || imported != 1 {
		t.Fatalf("ImportArchive uppercase imported=%d err=%v, want 1", imported, err)
	}
	if err := tr.DB().QueryRow(`SELECT host FROM exchanges WHERE id='upper-id-1'`).Scan(&storedHost); err != nil {
		t.Fatal(err)
	}
	if storedHost != "upper.import.example" {
		t.Fatalf("imported host = %q, want lowercase upper.import.example", storedHost)
	}
}

// [P2-17] Verify archive hardening: gcBlobs defers during active ExportHosts,
// legacy path traversal is rejected, truncated NDJSON / oversized NDJSON line /
// undeclared or invalid blob hashes are rejected.
func TestArchiveHardeningExportGCRaceAndImportValidation(t *testing.T) {
	tr, _ := openTraffic(t)

	// 1. Export vs gcBlobs race protection.
	bigBody := bytes.Repeat([]byte("Z"), maxInlineBody+4096)
	if err := tr.recordFlow(newFlow("gc-race.example", "GET", "/big", nil, bigBody)); err != nil {
		t.Fatal(err)
	}
	var blobHash string
	if err := tr.DB().QueryRow(`SELECT resp_blob FROM exchange_bodies LIMIT 1`).Scan(&blobHash); err != nil {
		t.Fatal(err)
	}

	tr.beginExport()
	if _, err := tr.DeleteHostsExact([]string{"gc-race.example"}); err != nil {
		tr.endExport()
		t.Fatal(err)
	}
	// While export is in flight, gcBlobs must NOT delete the blob file!
	if _, err := tr.blobPath(blobHash); err != nil {
		tr.endExport()
		t.Fatalf("gcBlobs deleted blob while export was in flight: %v", err)
	}
	tr.endExport()
	tr.reaping.Wait()
	// After export finishes, deferred GC reclaims the orphaned blob.
	if _, err := tr.blobPath(blobHash); err == nil {
		t.Fatal("deferred gcBlobs did not reclaim orphaned blob after export ended")
	}

	// 2. Non-local legacy path must be rejected during ExportHosts.
	if _, err := tr.DB().Exec(`INSERT INTO exchanges(id,ts,host,method,url_template,url,status,content_type,req_len,resp_len,path)
VALUES('evil-legacy',1,'evil.example','GET','/','http://evil.example/',200,'text/plain',0,0,'../escape')`); err != nil {
		t.Fatal(err)
	}
	if _, err := tr.ExportHosts([]string{"evil.example"}, filepath.Join(t.TempDir(), "out")); err == nil || !strings.Contains(err.Error(), "invalid legacy path") {
		t.Fatalf("ExportHosts allowed non-local legacyPath, got err=%v", err)
	}

	// 3. Truncated traffic.ndjson (manifest count=3, file has 1 row) must fail.
	truncDir := filepath.Join(t.TempDir(), "trunc")
	if err := os.MkdirAll(truncDir, 0o700); err != nil {
		t.Fatal(err)
	}
	mRaw, _ := json.Marshal(ArchiveSnapshot{Version: 2, Format: "ndjson", Count: 3, Blobs: []string{}})
	_ = os.WriteFile(filepath.Join(truncDir, "traffic.json"), mRaw, 0o600)
	rRaw, _ := json.Marshal(ArchiveExchange{ID: "t1", TS: 1, Host: "t.example", Method: "GET", URL: "http://t.example/"})
	_ = os.WriteFile(filepath.Join(truncDir, "traffic.ndjson"), append(rRaw, '\n'), 0o600)
	if _, err := tr.ImportArchive(truncDir); err == nil || !strings.Contains(err.Error(), "count mismatch") {
		t.Fatalf("expected truncated NDJSON count mismatch error, got %v", err)
	}

	// 4. Oversized NDJSON line (> maxBytes) must be rejected by readBoundedNDJSONLine.
	oversize := strings.NewReader(strings.Repeat("x", 1024) + "\n")
	if _, _, err := readBoundedNDJSONLine(bufio.NewReaderSize(oversize, 128), 256); err == nil || !strings.Contains(err.Error(), "exceeds maximum size") {
		t.Fatalf("expected oversized NDJSON line error, got %v", err)
	}

	// 5. Invalid or undeclared blob hash referenced by an exchange must be rejected.
	sum := sha256.Sum256([]byte("undeclared"))
	undeclaredHash := hex.EncodeToString(sum[:])
	for _, badBlob := range []string{"../traversal", undeclaredHash} {
		badDir := filepath.Join(t.TempDir(), "bad-blob")
		_ = os.MkdirAll(badDir, 0o700)
		m, _ := json.Marshal(ArchiveSnapshot{Version: 2, Format: "ndjson", Count: 1, Blobs: []string{}})
		_ = os.WriteFile(filepath.Join(badDir, "traffic.json"), m, 0o600)
		ex, _ := json.Marshal(ArchiveExchange{ID: "b1", TS: 1, Host: "b.example", Method: "GET", URL: "http://b.example/", RespBlob: badBlob})
		_ = os.WriteFile(filepath.Join(badDir, "traffic.ndjson"), append(ex, '\n'), 0o600)
		if _, err := tr.ImportArchive(badDir); err == nil {
			t.Fatalf("ImportArchive accepted bad/undeclared blob hash %q", badBlob)
		}
	}
}

// [P2-18] Verify vacuumPostgres discards the connection via driver.ErrBadConn when RESET fails.
type vacuumStubState struct {
	mu       sync.Mutex
	closed   int
	resetErr error
}

type vacuumStubConnector struct{ st *vacuumStubState }

func (c *vacuumStubConnector) Connect(context.Context) (driver.Conn, error) {
	return &vacuumStubConn{st: c.st}, nil
}
func (c *vacuumStubConnector) Driver() driver.Driver { return vacuumStubDriver{} }

type vacuumStubDriver struct{}

func (vacuumStubDriver) Open(string) (driver.Conn, error) { return nil, errors.New("unused") }

type vacuumStubConn struct{ st *vacuumStubState }

func (c *vacuumStubConn) Prepare(string) (driver.Stmt, error) { return nil, errors.New("unused") }
func (c *vacuumStubConn) Begin() (driver.Tx, error)           { return nil, errors.New("unused") }
func (c *vacuumStubConn) Close() error {
	c.st.mu.Lock()
	c.st.closed++
	c.st.mu.Unlock()
	return nil
}

func (c *vacuumStubConn) ExecContext(_ context.Context, query string, _ []driver.NamedValue) (driver.Result, error) {
	if strings.Contains(query, "RESET statement_timeout") {
		return nil, c.st.resetErr
	}
	return driver.RowsAffected(0), nil
}

func TestVacuumPostgresDiscardsTaintedConnWhenResetFails(t *testing.T) {
	st := &vacuumStubState{resetErr: errors.New("simulated RESET failure")}
	sqlDB := sql.OpenDB(&vacuumStubConnector{st: st})
	defer sqlDB.Close()

	tr := &Traffic{db: &indexDB{DB: sqlDB, postgres: true}}
	if err := tr.vacuumPostgres(); err != nil {
		t.Fatalf("vacuumPostgres: %v", err)
	}
	st.mu.Lock()
	closedCount := st.closed
	st.mu.Unlock()
	if closedCount != 1 {
		t.Fatalf("expected tainted connection to be discarded (closed=1), got closed=%d", closedCount)
	}
}

// [P2-19] Verify ValidateProxyURL redacts credentials across all error branches and supports socks5h.
func TestValidateProxyURLRedactsCredentialsAndSupportsSocks5h(t *testing.T) {
	u, err := ValidateProxyURL("socks5h://alice:pass@10.0.0.2:1080")
	if err != nil || u.Scheme != "socks5h" || u.Host != "10.0.0.2:1080" {
		t.Fatalf("socks5h should be accepted, got u=%v err=%v", u, err)
	}
	if _, err := ValidateProxyURLForSelf("socks5h://127.0.0.1:8788", "127.0.0.1:8788"); err == nil {
		t.Fatal("socks5h self-loop should be rejected")
	}

	const secret = "TOPSECRET_PROXY_PASS_999"
	for _, bad := range []string{
		"http://user:" + secret + "@bad host:8080",
		"user:" + secret + "@127.0.0.1:8080",
		"http://user:" + secret + "@",
		"ftp://user:" + secret + "@10.0.0.1:21",
	} {
		_, err := ValidateProxyURL(bad)
		if err == nil {
			t.Errorf("ValidateProxyURL(%q) expected error", bad)
			continue
		}
		if strings.Contains(err.Error(), secret) {
			t.Errorf("ValidateProxyURL(%q) leaked credential in error: %v", bad, err)
		}
	}
}

// [P3-1] Verify sqliteReadOnlyURI produces a valid read-only SQLite URI across Windows/Unix paths.
func TestSQLiteReadOnlyURIOpensLegacyDB(t *testing.T) {
	winPath := filepath.FromSlash("C:/tmp/sub dir/index.sqlite")
	if got := sqliteReadOnlyURI(winPath); got != "file:///C:/tmp/sub%20dir/index.sqlite?mode=ro" {
		t.Fatalf("unexpected Windows drive URI: %q", got)
	}
	if got := sqliteReadOnlyURI("/var/lib/artex/index.sqlite"); got != "file:///var/lib/artex/index.sqlite?mode=ro" {
		t.Fatalf("unexpected Unix URI: %q", got)
	}

	// Open a real SQLite file on the current OS using sqliteReadOnlyURI.
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "index.sqlite")
	wdb, err := sql.Open("sqlite", dbPath)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := wdb.Exec(`CREATE TABLE t(id INTEGER PRIMARY KEY)`); err != nil {
		wdb.Close()
		t.Fatal(err)
	}
	_ = wdb.Close()

	rdb, err := sql.Open("sqlite", sqliteReadOnlyURI(dbPath))
	if err != nil {
		t.Fatalf("open sqliteReadOnlyURI: %v", err)
	}
	defer rdb.Close()
	var integrity string
	if err := rdb.QueryRow(`PRAGMA quick_check`).Scan(&integrity); err != nil || integrity != "ok" {
		t.Fatalf("PRAGMA quick_check via sqliteReadOnlyURI = (%q, %v), want (\"ok\", nil)", integrity, err)
	}
}
