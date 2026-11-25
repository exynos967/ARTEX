package intercept

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"errors"
	"io"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/RC-CHN/ARTEX/db"
)

type stubInterceptDB struct {
	mu           sync.Mutex
	rules        []db.InterceptRule
	rulesErr     error
	settings     map[string]string
	settingErr   error
	ruleQueries  int
	settingCalls int
}

func (s *stubInterceptDB) openDB() *db.DB {
	return &db.DB{DB: sql.OpenDB(&stubConnector{st: s})}
}

type stubConnector struct{ st *stubInterceptDB }

func (c *stubConnector) Connect(context.Context) (driver.Conn, error) {
	return &stubConn{st: c.st}, nil
}
func (c *stubConnector) Driver() driver.Driver { return stubDriver{} }

type stubDriver struct{}

func (stubDriver) Open(string) (driver.Conn, error) { return nil, errors.New("unused") }

type stubConn struct{ st *stubInterceptDB }

func (c *stubConn) Prepare(string) (driver.Stmt, error) { return nil, errors.New("unused") }
func (c *stubConn) Close() error                        { return nil }
func (c *stubConn) Begin() (driver.Tx, error)           { return nil, errors.New("unused") }

func (c *stubConn) QueryContext(_ context.Context, query string, args []driver.NamedValue) (driver.Rows, error) {
	c.st.mu.Lock()
	defer c.st.mu.Unlock()

	switch {
	case strings.Contains(query, "FROM intercept_rules"):
		c.st.ruleQueries++
		if c.st.rulesErr != nil {
			return nil, c.st.rulesErr
		}
		rows := make([][]driver.Value, 0, len(c.st.rules))
		for _, r := range c.st.rules {
			rows = append(rows, []driver.Value{
				r.ID, r.Name, r.Enabled, int64(r.Priority),
				r.MatchTarget, r.MatchType, r.Pattern, r.Action, r.Message,
				r.TimeoutEnabled, int64(r.TimeoutSeconds), r.TimeoutAction,
				r.CreatedAt, r.UpdatedAt,
			})
		}
		return &stubRows{
			cols: []string{"id", "name", "enabled", "priority", "match_target", "match_type", "pattern", "action", "message", "timeout_enabled", "timeout_seconds", "timeout_action", "created_at", "updated_at"},
			data: rows,
		}, nil

	case strings.Contains(query, "FROM settings"):
		c.st.settingCalls++
		if c.st.settingErr != nil {
			return nil, c.st.settingErr
		}
		var key string
		if len(args) > 0 {
			key, _ = args[0].Value.(string)
		}
		if v, ok := c.st.settings[key]; ok {
			return &stubRows{cols: []string{"value"}, data: [][]driver.Value{{v}}}, nil
		}
		return &stubRows{cols: []string{"value"}}, nil
	}
	return nil, errors.New("unexpected query: " + query)
}

type stubRows struct {
	cols []string
	data [][]driver.Value
	idx  int
}

func (r *stubRows) Columns() []string { return r.cols }
func (r *stubRows) Close() error      { return nil }
func (r *stubRows) Next(dest []driver.Value) error {
	if r.idx >= len(r.data) {
		return io.EOF
	}
	copy(dest, r.data[r.idx])
	r.idx++
	return nil
}

func TestEmptyEnabledRulesAreCached(t *testing.T) {
	now := time.Now()
	st := &stubInterceptDB{
		// Only disabled rules -> 0 enabled rules.
		rules: []db.InterceptRule{
			{ID: 1, Name: "disabled-rule", Enabled: false, Priority: 10, MatchTarget: "tool_input", MatchType: "contains", Pattern: "rm", Action: "deny", CreatedAt: now, UpdatedAt: now},
		},
		settings: map[string]string{},
	}
	d := st.openDB()
	defer d.Close()

	ic := New(d)
	for i := 0; i < 10; i++ {
		if _, matched := ic.Match("Bash", []byte(`{"command":"rm -rf /"}`)); matched {
			t.Fatalf("call %d unexpectedly matched disabled rule", i)
		}
	}

	st.mu.Lock()
	gotQueries := st.ruleQueries
	st.mu.Unlock()
	if gotQueries != 1 {
		t.Fatalf("ListInterceptRules queried %d times for 0 enabled rules, want 1 (empty slice must be cached non-nil)", gotQueries)
	}
	ic.mu.RLock()
	cachedIsNil := ic.cached == nil
	ic.mu.RUnlock()
	if cachedIsNil {
		t.Fatal("ic.cached is nil after loading 0 enabled rules, expected non-nil empty slice")
	}
}

func TestLoadLockedPropagatesSettingDBError(t *testing.T) {
	st := &stubInterceptDB{
		settings:   map[string]string{"intercept_enabled_tools": `["Write"]`},
		settingErr: errors.New("postgres temporarily unavailable"),
	}
	d := st.openDB()
	defer d.Close()

	ic := New(d)

	// First attempt must surface the DB error and NOT poison cached/enabledTools with defaults.
	if _, err := ic.rules(); err == nil {
		t.Fatal("rules() returned nil error when GetSetting failed, want error")
	}
	ic.mu.RLock()
	cachedNil := ic.cached == nil
	enabledNil := ic.enabledTools == nil
	ic.mu.RUnlock()
	if !cachedNil || !enabledNil {
		t.Fatalf("failed loadLocked mutated cache state: cachedNil=%v enabledNil=%v", cachedNil, enabledNil)
	}

	// IsToolEnabled must also not cache defaultEnabledTools on transient DB failure.
	if ic.IsToolEnabled("Bash") {
		t.Fatal("IsToolEnabled returned true during DB error (should not fall back to defaultEnabledTools on error)")
	}
	ic.mu.RLock()
	stillNil := ic.enabledTools == nil
	ic.mu.RUnlock()
	if !stillNil {
		t.Fatal("IsToolEnabled cached enabledTools despite DB error")
	}

	// Once DB recovers, the saved setting (only "Write") loads and caches properly.
	st.mu.Lock()
	st.settingErr = nil
	st.mu.Unlock()

	if ic.IsToolEnabled("Bash") {
		t.Fatal("Bash should be disabled per saved setting [\"Write\"]")
	}
	if !ic.IsToolEnabled("Write") {
		t.Fatal("Write should be enabled per saved setting [\"Write\"]")
	}
}
