package mcphttp

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestLegacySSEClientDiscoverAndCall(t *testing.T) {
	var mu sync.Mutex
	var stream http.ResponseWriter
	var flusher http.Flusher
	sessions := make(map[string]bool)
	messages := make(chan []byte, 8)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/sse":
			id := "test-session"
			mu.Lock()
			sessions[id] = true
			stream, flusher = w, w.(http.Flusher)
			mu.Unlock()
			w.Header().Set("Content-Type", "text/event-stream")
			w.Header().Set("Cache-Control", "no-cache")
			fmt.Fprintf(w, "event: endpoint\ndata: %s/message?sessionId=%s\n\n", "http://"+r.Host, id)
			flusher.Flush()
			for {
				select {
				case payload := <-messages:
					fmt.Fprintf(w, "event: message\ndata: %s\n\n", payload)
					flusher.Flush()
				case <-r.Context().Done():
					return
				}
			}
		case "/message":
			mu.Lock()
			knownSession := sessions["test-session"]
			mu.Unlock()
			if r.URL.Query().Get("sessionId") != "test-session" || !knownSession {
				http.Error(w, "unknown session", http.StatusBadRequest)
				return
			}
			var req rpcRequest
			if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
				http.Error(w, err.Error(), http.StatusBadRequest)
				return
			}
			w.WriteHeader(http.StatusAccepted)
			if req.ID == 0 {
				return
			}
			var result any
			switch req.Method {
			case "initialize":
				result = map[string]any{"protocolVersion": "2024-11-05", "capabilities": map[string]any{"tools": map[string]any{}}, "serverInfo": map[string]any{"name": "test", "version": "1"}}
			case "tools/list":
				result = map[string]any{"tools": []any{map[string]any{"name": "echo", "description": "echo input", "inputSchema": map[string]any{"type": "object"}}}}
			case "tools/call":
				result = map[string]any{"content": []any{map[string]any{"type": "text", "text": "ok"}}}
			default:
				result = map[string]any{}
			}
			resultJSON, err := json.Marshal(result)
			if err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
			payload, _ := json.Marshal(rpcResponse{JSONRPC: "2.0", ID: req.ID, Result: json.RawMessage(resultJSON)})
			mu.Lock()
			streamReady := stream != nil
			mu.Unlock()
			if streamReady {
				messages <- payload
			}
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	c, err := NewSSE(ctx, "test", srv.URL+"/sse", map[string]string{"Authorization ": "Bearer test"}, false)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	tools, err := c.Tools(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(tools) != 1 || !strings.Contains(tools[0].Name(), "echo") {
		t.Fatalf("unexpected tools: %#v", tools)
	}
	got, err := c.Call(ctx, "echo", map[string]any{"value": "x"})
	if err != nil || got != "ok" {
		t.Fatalf("Call() = %q, %v", got, err)
	}
}

func TestLegacySSECloseDuringInFlightCallDoesNotHang(t *testing.T) {
	inFlightPosted := make(chan struct{}, 1)
	releaseSSE := make(chan struct{})
	defer close(releaseSSE)

	messages := make(chan []byte, 4)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/sse":
			fl := w.(http.Flusher)
			w.Header().Set("Content-Type", "text/event-stream")
			fmt.Fprintf(w, "event: endpoint\ndata: /message\n\n")
			fl.Flush()
			for {
				select {
				case payload := <-messages:
					fmt.Fprintf(w, "event: message\ndata: %s\n\n", payload)
					fl.Flush()
				case <-r.Context().Done():
					return
				case <-releaseSSE:
					return
				}
			}
		case "/message":
			var req rpcRequest
			_ = json.NewDecoder(r.Body).Decode(&req)
			w.WriteHeader(http.StatusAccepted)
			if req.Method == "initialize" {
				payload, _ := json.Marshal(rpcResponse{
					JSONRPC: "2.0",
					ID:      req.ID,
					Result:  json.RawMessage(`{"protocolVersion":"2024-11-05","capabilities":{},"serverInfo":{"name":"t","version":"1"}}`),
				})
				messages <- payload
				return
			}
			if req.Method == "tools/call" {
				// Acknowledge POST but never reply on SSE so Call waits in-flight.
				select {
				case inFlightPosted <- struct{}{}:
				default:
				}
			}
		}
	}))
	defer srv.Close()

	c, err := NewSSE(context.Background(), "test", srv.URL+"/sse", nil, false)
	if err != nil {
		t.Fatalf("NewSSE: %v", err)
	}

	callErr := make(chan error, 1)
	go func() {
		_, err := c.Call(context.Background(), "hang_tool", map[string]any{})
		callErr <- err
	}()

	select {
	case <-inFlightPosted:
	case <-time.After(2 * time.Second):
		t.Fatal("in-flight tools/call POST did not arrive")
	}

	// Give legacyRoundTrip a moment to enter select, then Close().
	time.Sleep(20 * time.Millisecond)
	if err := c.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	select {
	case err := <-callErr:
		if err == nil {
			t.Fatal("in-flight Call should return error after Close")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("in-flight Call hung after Close()")
	}
}

func TestLegacySSERepeatedCallsAfterEOFFailImmediately(t *testing.T) {
	dropStream := make(chan struct{})
	messages := make(chan []byte, 4)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/sse":
			fl := w.(http.Flusher)
			w.Header().Set("Content-Type", "text/event-stream")
			fmt.Fprintf(w, "event: endpoint\ndata: /message\n\n")
			fl.Flush()
			for {
				select {
				case payload := <-messages:
					fmt.Fprintf(w, "event: message\ndata: %s\n\n", payload)
					fl.Flush()
				case <-dropStream:
					return // cleanly close SSE stream (EOF)
				case <-r.Context().Done():
					return
				}
			}
		case "/message":
			var req rpcRequest
			_ = json.NewDecoder(r.Body).Decode(&req)
			w.WriteHeader(http.StatusAccepted)
			if req.Method == "initialize" {
				payload, _ := json.Marshal(rpcResponse{
					JSONRPC: "2.0",
					ID:      req.ID,
					Result:  json.RawMessage(`{"protocolVersion":"2024-11-05","capabilities":{},"serverInfo":{"name":"t","version":"1"}}`),
				})
				messages <- payload
			}
		}
	}))
	defer srv.Close()

	c, err := NewSSE(context.Background(), "test", srv.URL+"/sse", nil, false)
	if err != nil {
		t.Fatalf("NewSSE: %v", err)
	}
	defer c.Close()

	// Terminate the SSE stream from the server side.
	close(dropStream)
	select {
	case <-c.streamDone:
	case <-time.After(2 * time.Second):
		t.Fatal("streamDone did not close after server EOF")
	}

	// Multiple subsequent calls must ALL return promptly with an error (never block on drained channel).
	for i := 0; i < 3; i++ {
		done := make(chan error, 1)
		go func() {
			_, err := c.Call(context.Background(), "echo", map[string]any{"n": i})
			done <- err
		}()
		select {
		case err := <-done:
			if err == nil {
				t.Fatalf("call #%d after EOF returned nil error", i)
			}
		case <-time.After(time.Second):
			t.Fatalf("call #%d after EOF hung", i)
		}
	}
}

func TestLegacySSESkipsNonEndpointPreEventsAndHandlesMultilineData(t *testing.T) {
	messages := make(chan string, 4)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/sse":
			fl := w.(http.Flusher)
			w.Header().Set("Content-Type", "text/event-stream")
			// Send comment + non-endpoint pre-events before actual endpoint event.
			fmt.Fprint(w, ": keepalive comment\n\n")
			fmt.Fprint(w, "event: ping\ndata: heartbeat\n\n")
			fmt.Fprint(w, "event: message\ndata: {\"ignored\":true}\n\n")
			fmt.Fprint(w, "event: endpoint\ndata: /message?sessionId=s42\n\n")
			fl.Flush()
			for {
				select {
				case frame := <-messages:
					fmt.Fprint(w, frame)
					fl.Flush()
				case <-r.Context().Done():
					return
				}
			}
		case "/message":
			if r.URL.Query().Get("sessionId") != "s42" {
				http.Error(w, "wrong session", http.StatusBadRequest)
				return
			}
			var req rpcRequest
			_ = json.NewDecoder(r.Body).Decode(&req)
			w.WriteHeader(http.StatusAccepted)
			if req.ID == 0 {
				return
			}
			switch req.Method {
			case "initialize":
				// Multi-line SSE data: lines representing pretty-printed JSON.
				messages <- fmt.Sprintf("event: message\ndata: {\"jsonrpc\":\"2.0\",\ndata: \"id\":%d,\ndata: \"result\":{\"protocolVersion\":\"2024-11-05\"}}\n\n", req.ID)
			case "tools/call":
				messages <- fmt.Sprintf("event: message\ndata: {\"jsonrpc\":\"2.0\",\ndata: \"id\":%d,\ndata: \"result\":{\"content\":[{\"type\":\"text\",\"text\":\"multiline-ok\"}]}}\n\n", req.ID)
			}
		}
	}))
	defer srv.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	c, err := NewSSE(ctx, "test", srv.URL+"/sse", nil, false)
	if err != nil {
		t.Fatalf("NewSSE failed with non-endpoint pre-events: %v", err)
	}
	defer c.Close()

	got, err := c.Call(ctx, "demo", map[string]any{})
	if err != nil || got != "multiline-ok" {
		t.Fatalf("Call with multiline SSE data = (%q, %v), want (\"multiline-ok\", nil)", got, err)
	}
}

func TestSSEReaderMultilineJoinAndBounds(t *testing.T) {
	// 1. Multi-line data: lines must be joined with "\n", and default event type is "message".
	raw := "data: line1\ndata: line2\n\nevent: custom\ndata: a\ndata: b\n\n"
	sr := newSSEReader(strings.NewReader(raw))
	ev1, err := sr.Next()
	if err != nil || ev1.Event != "message" || ev1.Data != "line1\nline2" {
		t.Fatalf("ev1 = (%+v, %v), want Event=message Data=\"line1\\nline2\"", ev1, err)
	}
	ev2, err := sr.Next()
	if err != nil || ev2.Event != "custom" || ev2.Data != "a\nb" {
		t.Fatalf("ev2 = (%+v, %v), want Event=custom Data=\"a\\nb\"", ev2, err)
	}
	if _, err := sr.Next(); !errors.Is(err, io.EOF) {
		t.Fatalf("expected EOF, got %v", err)
	}

	// 2. Oversized single line (> maxSSELineBytes) must be rejected without unbounded allocation.
	oversizedLine := "data: " + strings.Repeat("x", maxSSELineBytes+128) + "\n\n"
	if _, err := parseSSE(strings.NewReader(oversizedLine), 1); !errors.Is(err, errSSELineTooLong) {
		t.Fatalf("parseSSE oversized line err = %v, want errSSELineTooLong", err)
	}

	// 3. Multi-line event exceeding maxEventBytes cap must be rejected.
	bounded := newSSEReaderWithLimits(strings.NewReader("data: 123456\ndata: 123456\n\n"), 64, 10)
	if _, err := bounded.Next(); !errors.Is(err, errSSEEventTooLong) {
		t.Fatalf("oversized event err = %v, want errSSEEventTooLong", err)
	}
}
