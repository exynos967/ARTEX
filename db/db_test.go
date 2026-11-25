package db

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

	"github.com/jackc/pgx/v5/pgconn"
)

type schemaExecFunc func(context.Context, string, ...any) (sql.Result, error)

func (f schemaExecFunc) ExecContext(ctx context.Context, query string, args ...any) (sql.Result, error) {
	return f(ctx, query, args...)
}

func TestApplySchemaRetriesOnlyDeadlocks(t *testing.T) {
	deadlockAttempts := 0
	delays := []time.Duration{}
	err := applySchemaWithRetry(t.Context(), schemaExecFunc(func(context.Context, string, ...any) (sql.Result, error) {
		deadlockAttempts++
		if deadlockAttempts < 3 {
			return nil, &pgconn.PgError{Code: "40P01", Message: "deadlock detected"}
		}
		return nil, nil
	}), func(delay time.Duration) {
		delays = append(delays, delay)
	})
	if err != nil {
		t.Fatal(err)
	}
	if deadlockAttempts != 3 {
		t.Fatalf("schema attempts=%d, want 3", deadlockAttempts)
	}
	if len(delays) != 2 || delays[0] != schemaDeadlockRetryDelays[0] || delays[1] != schemaDeadlockRetryDelays[1] {
		t.Fatalf("schema retry delays=%v", delays)
	}

	nonRetryable := errors.New("permission denied")
	nonRetryableAttempts := 0
	err = applySchemaWithRetry(t.Context(), schemaExecFunc(func(context.Context, string, ...any) (sql.Result, error) {
		nonRetryableAttempts++
		return nil, nonRetryable
	}), func(time.Duration) {
		t.Fatal("non-deadlock error must not be retried")
	})
	if !errors.Is(err, nonRetryable) || nonRetryableAttempts != 1 {
		t.Fatalf("non-retryable result: attempts=%d err=%v", nonRetryableAttempts, err)
	}
}

// testDSN returns the configured DSN, skipping the test when neither the env var
// nor a config file supplies one (DSN no longer has a built-in default).
func testDSN(t *testing.T) string {
	t.Helper()
	dsn, _, err := DSN()
	if err != nil {
		t.Skipf("no database config (%v) — skipping", err)
	}
	return dsn
}

// TestOpenSeed opens the live dev PG, applies schema, seeds, and verifies the
// builtin agents + their variable catalog exist. Skips if PG is unreachable.
func TestOpenSeed(t *testing.T) {
	d, err := Open(testDSN(t))
	if err != nil {
		t.Skipf("postgres unavailable (%v) — skipping", err)
	}
	defer d.Close()

	wantAgents := len(builtinAgents)
	var agents int
	if err := d.QueryRow(`SELECT count(*) FROM agents WHERE builtin`).Scan(&agents); err != nil {
		t.Fatal(err)
	}
	if agents != wantAgents {
		t.Fatalf("want %d builtin agents, got %d", wantAgents, agents)
	}

	// planner should have at least its seeded catalog vars
	wantPlannerVars := 0
	for _, a := range builtinAgents {
		if a.key == "planner" {
			wantPlannerVars = len(a.vars)
			break
		}
	}
	var plannerVars int
	if err := d.QueryRow(`
SELECT count(*) FROM agent_prompt_vars v
JOIN agents a ON a.id = v.agent_id
WHERE a.key = 'planner'`).Scan(&plannerVars); err != nil {
		t.Fatal(err)
	}
	if plannerVars < wantPlannerVars {
		t.Fatalf("want at least %d planner vars, got %d", wantPlannerVars, plannerVars)
	}

	// re-open must be idempotent (no duplicate agents)
	d2, err := Open(testDSN(t))
	if err != nil {
		t.Fatal(err)
	}
	defer d2.Close()
	if err := d2.QueryRow(`SELECT count(*) FROM agents WHERE builtin`).Scan(&agents); err != nil {
		t.Fatal(err)
	}
	if agents != wantAgents {
		t.Fatalf("after re-open want %d agents, got %d", wantAgents, agents)
	}
}

type stubExecEvent struct {
	connID int
	inTx   bool
	query  string
	args   []any
}

type stubSQLState struct {
	mu           sync.Mutex
	nextConnID   int
	closedConns  int
	begins       int
	commits      int
	rollbacks    int
	events       []stubExecEvent
	execHandler  func(connID int, inTx bool, query string, args []any) (driver.Result, error)
	queryHandler func(connID int, inTx bool, query string, args []any) ([]string, [][]driver.Value, error)
}

func (s *stubSQLState) openDB() *DB {
	sqlDB := sql.OpenDB(&stubConnector{state: s})
	sqlDB.SetMaxOpenConns(4)
	sqlDB.SetMaxIdleConns(4)
	return &DB{sqlDB}
}

func (s *stubSQLState) snapshotEvents() []stubExecEvent {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]stubExecEvent, len(s.events))
	copy(out, s.events)
	return out
}

type stubConnector struct{ state *stubSQLState }

func (c *stubConnector) Connect(context.Context) (driver.Conn, error) {
	c.state.mu.Lock()
	c.state.nextConnID++
	id := c.state.nextConnID
	c.state.mu.Unlock()
	return &stubConn{state: c.state, id: id}, nil
}

func (c *stubConnector) Driver() driver.Driver { return stubDriver{} }

type stubDriver struct{}

func (stubDriver) Open(string) (driver.Conn, error) { return nil, errors.New("use OpenDB") }

type stubConn struct {
	state *stubSQLState
	id    int
	inTx  bool
}

func (c *stubConn) Prepare(string) (driver.Stmt, error)     { return nil, errors.New("unused") }
func (c *stubConn) CheckNamedValue(*driver.NamedValue) error { return nil }
func (c *stubConn) Close() error {
	c.state.mu.Lock()
	c.state.closedConns++
	c.state.mu.Unlock()
	return nil
}

func (c *stubConn) Begin() (driver.Tx, error) { return c.BeginTx(context.Background(), driver.TxOptions{}) }

func (c *stubConn) BeginTx(context.Context, driver.TxOptions) (driver.Tx, error) {
	c.inTx = true
	c.state.mu.Lock()
	c.state.begins++
	c.state.mu.Unlock()
	return &stubTx{conn: c}, nil
}

func (c *stubConn) ExecContext(_ context.Context, query string, args []driver.NamedValue) (driver.Result, error) {
	vals := make([]any, len(args))
	for i, a := range args {
		vals[i] = a.Value
	}
	c.state.mu.Lock()
	c.state.events = append(c.state.events, stubExecEvent{connID: c.id, inTx: c.inTx, query: query, args: vals})
	handler := c.state.execHandler
	c.state.mu.Unlock()
	if handler != nil {
		return handler(c.id, c.inTx, query, vals)
	}
	return driver.RowsAffected(1), nil
}

func (c *stubConn) QueryContext(_ context.Context, query string, args []driver.NamedValue) (driver.Rows, error) {
	vals := make([]any, len(args))
	for i, a := range args {
		vals[i] = a.Value
	}
	c.state.mu.Lock()
	c.state.events = append(c.state.events, stubExecEvent{connID: c.id, inTx: c.inTx, query: query, args: vals})
	handler := c.state.queryHandler
	c.state.mu.Unlock()
	if handler != nil {
		cols, rows, err := handler(c.id, c.inTx, query, vals)
		if err != nil {
			return nil, err
		}
		return &stubRows{cols: cols, rows: rows}, nil
	}
	return &stubRows{cols: []string{"col"}}, nil
}

type stubTx struct{ conn *stubConn }

func (t *stubTx) Commit() error {
	t.conn.inTx = false
	t.conn.state.mu.Lock()
	t.conn.state.commits++
	t.conn.state.mu.Unlock()
	return nil
}

func (t *stubTx) Rollback() error {
	t.conn.inTx = false
	t.conn.state.mu.Lock()
	t.conn.state.rollbacks++
	t.conn.state.mu.Unlock()
	return nil
}

type stubRows struct {
	cols []string
	rows [][]driver.Value
	idx  int
}

func (r *stubRows) Columns() []string { return r.cols }
func (r *stubRows) Close() error      { return nil }
func (r *stubRows) Next(dest []driver.Value) error {
	if r.idx >= len(r.rows) {
		return io.EOF
	}
	copy(dest, r.rows[r.idx])
	r.idx++
	return nil
}

func TestSetMaintenanceTimeouts(t *testing.T) {
	var gotQuery string
	err := SetMaintenanceTimeouts(nil, schemaExecFunc(func(ctx context.Context, query string, _ ...any) (sql.Result, error) {
		if ctx == nil {
			t.Fatal("nil context passed to exec")
		}
		gotQuery = query
		return fakeResult(0), nil
	}))
	if err != nil {
		t.Fatalf("SetMaintenanceTimeouts: %v", err)
	}
	for _, want := range []string{
		"SET LOCAL statement_timeout = '0'",
		"SET LOCAL lock_timeout = '30s'",
		"SET LOCAL idle_in_transaction_session_timeout = '0'",
	} {
		if !strings.Contains(gotQuery, want) {
			t.Fatalf("query %q missing %q", gotQuery, want)
		}
	}
	if err := SetMaintenanceTimeouts(t.Context(), nil); err == nil {
		t.Fatal("expected error for nil execer")
	}
	sentinel := errors.New("boom")
	if err := SetMaintenanceTimeouts(t.Context(), schemaExecFunc(func(context.Context, string, ...any) (sql.Result, error) {
		return nil, sentinel
	})); !errors.Is(err, sentinel) {
		t.Fatalf("expected wrapped sentinel error, got %v", err)
	}
}

func TestQuotePGIdent(t *testing.T) {
	cases := []struct {
		in, want string
	}{
		{"artex", `"artex"`},
		{`artex"prod`, `"artex""prod"`},
		{`x"; DROP DATABASE postgres; --`, `"x""; DROP DATABASE postgres; --"`},
		{`""`, `""""""`},
	}
	for _, tc := range cases {
		if got := quotePGIdent(tc.in); got != tc.want {
			t.Fatalf("quotePGIdent(%q)=%q want %q", tc.in, got, tc.want)
		}
	}
}

func TestWithSchemaMigrationLockAndEvidenceSessionLock(t *testing.T) {
	t.Run("schema_migration_lock_sets_and_resets_session_timeouts_on_single_conn", func(t *testing.T) {
		st := &stubSQLState{}
		d := st.openDB()
		defer d.Close()

		called := false
		err := withSchemaMigrationLock(t.Context(), d.DB, func(conn *sql.Conn) error {
			called = true
			_, err := conn.ExecContext(t.Context(), `SELECT 1`)
			return err
		})
		if err != nil || !called {
			t.Fatalf("withSchemaMigrationLock err=%v called=%v", err, called)
		}
		if st.begins != 0 {
			t.Fatalf("expected 0 open transactions, got %d", st.begins)
		}
		events := st.snapshotEvents()
		if len(events) != 5 {
			t.Fatalf("expected 5 session statements, got %d: %+v", len(events), events)
		}
		connID := events[0].connID
		for i, ev := range events {
			if ev.connID != connID || ev.inTx {
				t.Fatalf("event %d used wrong conn/tx: %+v (want conn %d, inTx=false)", i, ev, connID)
			}
		}
		if events[0].query != maintenanceSessionTimeoutsSQL ||
			events[1].query != `SELECT pg_advisory_lock($1)` || events[1].args[0] != LockSchemaMigration ||
			events[2].query != `SELECT 1` ||
			events[3].query != `SELECT pg_advisory_unlock($1)` || events[3].args[0] != LockSchemaMigration ||
			events[4].query != resetMaintenanceSessionTimeoutsSQL {
			t.Fatalf("unexpected statement sequence: %+v", events)
		}
		if st.closedConns != 0 {
			t.Fatalf("clean conn should return to pool, closedConns=%d", st.closedConns)
		}
	})

	t.Run("evidence_session_lock_holds_no_tx_and_discards_dirty_conn_on_reset_failure", func(t *testing.T) {
		st := &stubSQLState{
			execHandler: func(_ int, _ bool, query string, _ []any) (driver.Result, error) {
				if query == `RESET lock_timeout` {
					return nil, errors.New("reset failed")
				}
				return driver.RowsAffected(1), nil
			},
		}
		d := st.openDB()
		defer d.Close()

		err := d.WithEvidenceSessionLock(t.Context(), func() error {
			return nil
		})
		if err != nil {
			t.Fatalf("WithEvidenceSessionLock: %v", err)
		}
		if st.begins != 0 {
			t.Fatalf("WithEvidenceSessionLock must not open a tx, got begins=%d", st.begins)
		}
		events := st.snapshotEvents()
		if len(events) != 4 ||
			events[0].query != `SET lock_timeout = '30s'` ||
			events[1].query != `SELECT pg_advisory_lock($1)` || events[1].args[0] != LockFindingEvidence ||
			events[2].query != `SELECT pg_advisory_unlock($1)` || events[2].args[0] != LockFindingEvidence ||
			events[3].query != `RESET lock_timeout` {
			t.Fatalf("unexpected evidence session lock events: %+v", events)
		}
		// Because RESET failed, discardConn must close the underlying driver conn
		// instead of returning a dirty session to the pool.
		if st.closedConns != 1 {
			t.Fatalf("expected dirty conn to be discarded (closedConns=1), got %d", st.closedConns)
		}
	})
}
