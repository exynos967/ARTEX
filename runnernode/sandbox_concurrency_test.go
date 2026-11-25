package runnernode

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/RC-CHN/ARTEX/runner"
)

func TestSandboxConcurrencyCapsCallsWithoutBlockingCancelOrHeartbeat(t *testing.T) {
	prevLimit := maxConcurrentSandboxCalls
	maxConcurrentSandboxCalls = 2
	t.Cleanup(func() { maxConcurrentSandboxCalls = prevLimit })

	var inFlight, maxObserved atomic.Int32
	started := make(chan struct{}, 8)
	exited := make(chan struct{}, 8)
	release := make(chan struct{})

	mcpServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodDelete {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		var req map[string]any
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		if req["method"] == "initialize" {
			w.Header().Set("Mcp-Session-Id", "concurrency-session")
		}
		if _, hasID := req["id"]; !hasID {
			w.WriteHeader(http.StatusAccepted)
			return
		}
		if req["method"] == "tools/call" {
			cur := inFlight.Add(1)
			for {
				prev := maxObserved.Load()
				if cur <= prev || maxObserved.CompareAndSwap(prev, cur) {
					break
				}
			}
			defer func() {
				inFlight.Add(-1)
				exited <- struct{}{}
			}()
			started <- struct{}{}
			select {
			case <-r.Context().Done():
				return
			case <-release:
			}
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(mcpReply(req))
	}))
	defer mcpServer.Close()
	defer mcpServer.CloseClientConnections()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	in, input := io.Pipe()
	output, out := io.Pipe()
	defer input.Close()
	defer output.Close()

	serveDone := make(chan error, 1)
	go func() {
		serveDone <- ServeSandboxWithHeartbeat(ctx, in, out, 5*time.Second)
		_ = out.Close()
	}()

	replies := make(chan SandboxReply, 32)
	go func() {
		defer close(replies)
		dec := json.NewDecoder(output)
		for {
			var r SandboxReply
			if err := dec.Decode(&r); err != nil {
				return
			}
			replies <- r
		}
	}()

	enc := json.NewEncoder(input)
	sendReq := func(req SandboxRequest) {
		t.Helper()
		if err := enc.Encode(req); err != nil {
			t.Fatalf("encode %s: %v", req.Method, err)
		}
	}
	nextReply := func() SandboxReply {
		t.Helper()
		select {
		case r, ok := <-replies:
			if !ok {
				t.Fatal("sandbox reply stream closed unexpectedly")
			}
			return r
		case <-time.After(3 * time.Second):
			t.Fatal("timed out waiting for sandbox reply")
			return SandboxReply{}
		}
	}

	spec := baseSpec(t.TempDir())
	spec.MCPs = []runner.MCPConfig{{Name: "fixture", Transport: "http", URL: mcpServer.URL}}
	sendReq(SandboxRequest{ID: "open", Method: "open", SessionID: "conc-sess", Spec: &spec})
	if r := nextReply(); r.ID != "open" || r.Error != "" {
		t.Fatalf("open failed: %+v", r)
	}

	callReq := func(id string) SandboxRequest {
		return SandboxRequest{
			ID:     id,
			Method: "call",
			Call:   &runner.ToolCall{ID: id, Name: "mcp__fixture__echo", Input: json.RawMessage(`{}`)},
		}
	}

	// Fill both concurrency slots.
	sendReq(callReq("c1"))
	sendReq(callReq("c2"))
	for range 2 {
		select {
		case <-started:
		case <-time.After(3 * time.Second):
			t.Fatal("initial calls did not reach MCP tool")
		}
	}

	// Third concurrent call must be rejected immediately with a clear error.
	sendReq(callReq("c3"))
	if r := nextReply(); r.ID != "c3" || !strings.Contains(r.Error, "sandbox concurrent tool-call limit reached") {
		t.Fatalf("overflow reply = %+v, want concurrent limit error", r)
	}

	// Heartbeat must remain unblocked while all call slots are occupied.
	sendReq(SandboxRequest{ID: "hb", Method: "heartbeat"})
	if r := nextReply(); r.ID != "hb" || r.Error != "" {
		t.Fatalf("heartbeat reply = %+v, want clean reply", r)
	}

	// Cancel c1 must NOT deadlock while callSem is full, and must free its slot.
	sendReq(SandboxRequest{ID: "cancel-c1", Method: "cancel", CancelID: "c1"})
	if r := nextReply(); r.ID != "c1" || (r.Error == "" && !r.Result.IsError) {
		t.Fatalf("cancelled c1 reply = %+v, want cancellation error", r)
	}
	// Wait for the HTTP server handler to observe TCP disconnect and decrement
	// inFlight before starting c4, avoiding a transient server-side count of 3.
	select {
	case <-exited:
	case <-time.After(3 * time.Second):
		t.Fatal("cancelled c1 handler did not exit on MCP server")
	}

	// Freed slot must immediately admit c4.
	sendReq(callReq("c4"))
	select {
	case <-started:
	case <-time.After(3 * time.Second):
		t.Fatal("c4 was not admitted after c1 cancellation freed a slot")
	}

	// Release c2 and c4 to finish normally.
	close(release)
	finished := map[string]SandboxReply{}
	for range 2 {
		r := nextReply()
		finished[r.ID] = r
	}
	for _, id := range []string{"c2", "c4"} {
		r, ok := finished[id]
		if !ok || r.Error != "" || r.Result.Flatten() != "remote fixture" {
			t.Fatalf("call %s reply = %+v, want success", id, r)
		}
	}

	if got := maxObserved.Load(); got > 2 {
		t.Fatalf("max concurrent calls observed = %d, want <= 2", got)
	}

	sendReq(SandboxRequest{ID: "close", Method: "close"})
	if r := nextReply(); r.ID != "close" || r.Error != "" {
		t.Fatalf("close reply = %+v", r)
	}
	select {
	case err := <-serveDone:
		if err != nil {
			t.Fatalf("ServeSandboxWithHeartbeat returned err: %v", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("ServeSandboxWithHeartbeat did not exit after close")
	}
}
