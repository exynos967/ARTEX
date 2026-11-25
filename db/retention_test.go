package db

import (
	"context"
	"database/sql"
	"errors"
	"regexp"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/RC-CHN/ARTEX/internal/operation"
	"github.com/jackc/pgx/v5/pgconn"
)

type fakeResult int64

func (r fakeResult) LastInsertId() (int64, error) { return 0, nil }
func (r fakeResult) RowsAffected() (int64, error) { return int64(r), nil }

type mockSchemaMigrator struct {
	currentHash string
	hasRow      bool
	readErr     error
	schemaErrs  []error
	execs       []string
	upsertHash  string
}

func (m *mockSchemaMigrator) ExecContext(_ context.Context, query string, args ...any) (sql.Result, error) {
	m.execs = append(m.execs, query)
	if query == schemaSQL && len(m.schemaErrs) > 0 {
		err := m.schemaErrs[0]
		m.schemaErrs = m.schemaErrs[1:]
		if err != nil {
			return nil, err
		}
	}
	if strings.Contains(query, "INSERT INTO schema_migrations") && len(args) >= 2 {
		if h, ok := args[1].(string); ok {
			m.upsertHash = h
		}
	}
	return fakeResult(1), nil
}

func (m *mockSchemaMigrator) CurrentSchemaDigest(_ context.Context, key string) (string, bool, error) {
	if key != schemaMigrationKey {
		return "", false, errors.New("unexpected key: " + key)
	}
	return m.currentHash, m.hasRow, m.readErr
}

func TestSchemaDigestDeterministicAndNonEmpty(t *testing.T) {
	h1 := schemaDigest(schemaSQL)
	h2 := schemaDigest(schemaSQL)
	if len(h1) != 64 {
		t.Fatalf("schemaDigest len=%d want 64 hex chars (%q)", len(h1), h1)
	}
	if h1 != h2 {
		t.Fatalf("schemaDigest not deterministic: %q != %q", h1, h2)
	}
	if schemaDigest(schemaSQL+"\n-- change") == h1 {
		t.Fatal("schemaDigest did not change on content modification")
	}
}

func TestSchemaMigrationGateSkipsOrApplies(t *testing.T) {
	wantHash := schemaDigest(schemaSQL)

	t.Run("up_to_date_skips_schema_sql", func(t *testing.T) {
		m := &mockSchemaMigrator{currentHash: wantHash, hasRow: true}
		applied, err := applySchemaIfChanged(t.Context(), m, func(time.Duration) {
			t.Fatal("unexpected retry sleep")
		})
		if err != nil || applied {
			t.Fatalf("applied=%v err=%v want (false, nil)", applied, err)
		}
		if len(m.execs) != 1 || !strings.Contains(m.execs[0], "CREATE TABLE IF NOT EXISTS schema_migrations") {
			t.Fatalf("expected only schema_migrations table check, got %d execs", len(m.execs))
		}
		if m.upsertHash != "" {
			t.Fatalf("unexpected schema_migrations upsert: %q", m.upsertHash)
		}
	})

	t.Run("missing_row_applies_and_records_digest", func(t *testing.T) {
		m := &mockSchemaMigrator{hasRow: false}
		applied, err := applySchemaIfChanged(t.Context(), m, func(time.Duration) {})
		if err != nil || !applied {
			t.Fatalf("applied=%v err=%v want (true, nil)", applied, err)
		}
		if len(m.execs) != 3 || m.execs[1] != schemaSQL {
			t.Fatalf("expected [ensure table, schemaSQL, upsert], got %d execs", len(m.execs))
		}
		if m.upsertHash != wantHash {
			t.Fatalf("recorded hash=%q want %q", m.upsertHash, wantHash)
		}
	})

	t.Run("stale_hash_retries_deadlock_and_updates_digest", func(t *testing.T) {
		m := &mockSchemaMigrator{
			currentHash: "0000000000000000000000000000000000000000000000000000000000000000",
			hasRow:      true,
			schemaErrs:  []error{&pgconn.PgError{Code: "40P01", Message: "deadlock detected"}, nil},
		}
		var sleeps []time.Duration
		applied, err := applySchemaIfChanged(t.Context(), m, func(d time.Duration) {
			sleeps = append(sleeps, d)
		})
		if err != nil || !applied {
			t.Fatalf("applied=%v err=%v want (true, nil)", applied, err)
		}
		if len(sleeps) != 1 || sleeps[0] != schemaDeadlockRetryDelays[0] {
			t.Fatalf("unexpected retry sleeps: %v", sleeps)
		}
		if m.upsertHash != wantHash {
			t.Fatalf("recorded hash=%q want %q", m.upsertHash, wantHash)
		}
	})
}

func TestSchemaPhase4HardeningClauses(t *testing.T) {
	requiredInSchema := []string{
		"DROP TRIGGER IF EXISTS trg_assets_task_links ON assets;",
		"CREATE TRIGGER trg_assets_task_links_ins AFTER INSERT ON assets",
		"CREATE TRIGGER trg_assets_task_links_upd AFTER UPDATE OF task_ids ON assets",
		"WHEN (NEW.task_ids IS DISTINCT FROM OLD.task_ids)",
		"ALTER TABLE tasks ADD COLUMN IF NOT EXISTS tokens_used BIGINT NOT NULL DEFAULT 0;",
		"CREATE TABLE IF NOT EXISTS task_token_counters",
		"ALTER TABLE task_token_counters SET (fillfactor = 85, autovacuum_vacuum_scale_factor = 0.05, autovacuum_analyze_scale_factor = 0.02);",
		"CREATE OR REPLACE FUNCTION sync_task_tokens_used() RETURNS trigger",
		"INSERT INTO task_token_counters(task_id, tokens_used)",
		"UPDATE task_token_counters",
		"CREATE TRIGGER trg_llm_usage_task_tokens AFTER INSERT OR DELETE ON llm_usage",
		"CREATE INDEX IF NOT EXISTS idx_notification_deliveries_event",
		"CREATE INDEX IF NOT EXISTS idx_server_logs_created ON server_logs(created_at);",
		"CREATE INDEX IF NOT EXISTS idx_notification_events_fanned_created",
		"CREATE INDEX IF NOT EXISTS idx_notification_deliveries_terminal_created",
		"CREATE INDEX IF NOT EXISTS idx_intercept_pending_decided_at",
		"DROP INDEX IF EXISTS idx_notification_deliveries_history;",
		"ALTER TABLE activity SET (autovacuum_vacuum_scale_factor = 0.05, autovacuum_analyze_scale_factor = 0.02);",
		"ALTER TABLE server_logs SET (autovacuum_vacuum_scale_factor = 0.05, autovacuum_analyze_scale_factor = 0.02);",
		"ALTER TABLE llm_records SET (autovacuum_vacuum_scale_factor = 0.05, autovacuum_analyze_scale_factor = 0.02);",
		"ALTER TABLE llm_usage SET (autovacuum_vacuum_scale_factor = 0.05, autovacuum_analyze_scale_factor = 0.02);",
		"ALTER TABLE intercept_pending SET (autovacuum_vacuum_scale_factor = 0.05, autovacuum_analyze_scale_factor = 0.02);",
		"ALTER TABLE tasks SET (fillfactor = 85, autovacuum_vacuum_scale_factor = 0.05, autovacuum_analyze_scale_factor = 0.02);",
		"ALTER TABLE exploration_nodes SET (fillfactor = 85, autovacuum_vacuum_scale_factor = 0.05, autovacuum_analyze_scale_factor = 0.02);",
		"ALTER TABLE side_question_sessions SET (fillfactor = 85, autovacuum_vacuum_scale_factor = 0.05, autovacuum_analyze_scale_factor = 0.02);",
	}
	for _, needle := range requiredInSchema {
		if !strings.Contains(schemaSQL, needle) {
			t.Errorf("schema.sql missing expected clause: %s", needle)
		}
	}
	if strings.Contains(schemaSQL, "AFTER INSERT OR UPDATE OF task_ids ON assets") {
		t.Fatal("schema.sql still uses combined INSERT OR UPDATE trigger for assets.task_ids")
	}
	if strings.Contains(schemaSQL, "UPDATE tasks SET tokens_used") {
		t.Fatal("schema.sql sync_task_tokens_used must update task_token_counters, not tasks")
	}
	if strings.Contains(schemaSQL, "CREATE INDEX IF NOT EXISTS idx_notification_deliveries_history") {
		t.Fatal("schema.sql must not create redundant idx_notification_deliveries_history")
	}

	for _, needle := range []string{
		"CREATE OR REPLACE FUNCTION sync_task_tokens_used() RETURNS trigger",
		"INSERT INTO task_token_counters(task_id, tokens_used)",
		"UPDATE task_token_counters",
		"CREATE TRIGGER trg_llm_usage_task_tokens AFTER INSERT OR DELETE ON llm_usage",
		"ALTER TABLE llm_usage SET (autovacuum_vacuum_scale_factor = 0.05, autovacuum_analyze_scale_factor = 0.02);",
	} {
		if !strings.Contains(llmUsageSchema, needle) {
			t.Errorf("llmUsageSchema missing expected clause: %s", needle)
		}
	}
	if strings.Contains(llmUsageSchema, "UPDATE tasks t") {
		t.Fatal("llmUsageSchema must backfill task_token_counters, not tasks")
	}
}

func TestRetentionConfigFromEnv(t *testing.T) {
	for _, k := range []string{
		"ARTEX_RETENTION_LOGS_DAYS",
		"ARTEX_RETENTION_RECEIPTS_DAYS",
		"ARTEX_RETENTION_NOTIFICATIONS_DAYS",
		"ARTEX_RETENTION_LLM_RECORDS_DAYS",
		"ARTEX_RETENTION_INTERCEPT_DAYS",
	} {
		t.Setenv(k, "")
	}

	def := RetentionConfigFromEnv()
	if def.ServerLogsDays != 14 || def.OperationReceiptsDays != 7 ||
		def.NotificationDays != 30 || def.LLMRecordsDays != 7 ||
		def.InterceptDecidedDays != 30 {
		t.Fatalf("unexpected default retention days: %+v", def)
	}
	if def.BatchSize != 2000 || def.MaxBatchesPerTable != 25 ||
		def.BatchPause != 50*time.Millisecond || def.Interval != time.Hour ||
		def.InitialDelay != 2*time.Minute {
		t.Fatalf("unexpected default retention runtime params: %+v", def)
	}

	t.Setenv("ARTEX_RETENTION_LOGS_DAYS", "21")
	t.Setenv("ARTEX_RETENTION_RECEIPTS_DAYS", "0")
	t.Setenv("ARTEX_RETENTION_NOTIFICATIONS_DAYS", "45")
	t.Setenv("ARTEX_RETENTION_LLM_RECORDS_DAYS", "-3")
	t.Setenv("ARTEX_RETENTION_INTERCEPT_DAYS", "not-a-number")

	cfg := RetentionConfigFromEnv()
	if cfg.ServerLogsDays != 21 {
		t.Fatalf("ServerLogsDays=%d want 21", cfg.ServerLogsDays)
	}
	if cfg.OperationReceiptsDays != 0 {
		t.Fatalf("OperationReceiptsDays=%d want 0 (disabled)", cfg.OperationReceiptsDays)
	}
	if cfg.NotificationDays != 45 {
		t.Fatalf("NotificationDays=%d want 45", cfg.NotificationDays)
	}
	if cfg.LLMRecordsDays != 7 {
		t.Fatalf("negative env should keep default 7, got %d", cfg.LLMRecordsDays)
	}
	if cfg.InterceptDecidedDays != 30 {
		t.Fatalf("invalid env should keep default 30, got %d", cfg.InterceptDecidedDays)
	}
}

// parseDDLTableColumns extracts declared column names for every CREATE TABLE and
// ALTER TABLE ... ADD COLUMN statement in the provided SQL text.
func parseDDLTableColumns(sqlText string) map[string]map[string]bool {
	tables := map[string]map[string]bool{}
	createRe := regexp.MustCompile(`(?is)CREATE\s+TABLE\s+IF\s+NOT\s+EXISTS\s+([a-z_][a-z0-9_]*)\s*\((.*?)\)\s*;`)
	for _, m := range createRe.FindAllStringSubmatch(sqlText, -1) {
		tbl := strings.ToLower(m[1])
		cols := tables[tbl]
		if cols == nil {
			cols = map[string]bool{}
			tables[tbl] = cols
		}
		// Extract column definitions (skip comments and table-level constraints).
		for _, line := range strings.Split(m[2], "\n") {
			if idx := strings.Index(line, "--"); idx >= 0 {
				line = line[:idx]
			}
			line = strings.TrimSpace(line)
			if line == "" {
				continue
			}
			// Handle multiple columns on a single compact line (e.g., operation_receipts).
			depth := 0
			start := 0
			splitTopComma := func(s string) []string {
				var parts []string
				for i := 0; i < len(s); i++ {
					switch s[i] {
					case '(':
						depth++
					case ')':
						if depth > 0 {
							depth--
						}
					case ',':
						if depth == 0 {
							parts = append(parts, s[start:i])
							start = i + 1
						}
					}
				}
				parts = append(parts, s[start:])
				return parts
			}
			for _, part := range splitTopComma(line) {
				fields := strings.Fields(strings.TrimSpace(part))
				if len(fields) < 2 {
					continue
				}
				first := strings.ToUpper(fields[0])
				if first == "PRIMARY" || first == "FOREIGN" || first == "UNIQUE" || first == "CHECK" || first == "CONSTRAINT" {
					continue
				}
				col := strings.ToLower(strings.Trim(fields[0], `",`))
				if col != "" {
					cols[col] = true
				}
			}
		}
	}
	alterRe := regexp.MustCompile(`(?i)ALTER\s+TABLE\s+([a-z_][a-z0-9_]*)\s+ADD\s+COLUMN\s+IF\s+NOT\s+EXISTS\s+([a-z_][a-z0-9_]*)`)
	for _, m := range alterRe.FindAllStringSubmatch(sqlText, -1) {
		tbl := strings.ToLower(m[1])
		col := strings.ToLower(m[2])
		if tables[tbl] == nil {
			tables[tbl] = map[string]bool{}
		}
		tables[tbl][col] = true
	}
	return tables
}

func TestRetentionSchemaReferencesExist(t *testing.T) {
	allDDL := schemaSQL + "\n" + llmRecordsSchema + "\n" + llmRecordsMigrate
	tables := parseDDLTableColumns(allDDL)

	for _, spec := range retentionSpecs {
		cols, ok := tables[spec.table]
		if !ok {
			t.Fatalf("retention table %q not found in DDL", spec.table)
		}
		for _, col := range spec.columns {
			if !cols[col] {
				t.Errorf("retention table %q references column %q which does not exist in DDL (known: %v)", spec.table, col, cols)
			}
			if !strings.Contains(spec.query, col) {
				t.Errorf("retention query for %q does not reference declared column %q", spec.table, col)
			}
		}
		if !strings.Contains(spec.query, "DELETE FROM "+spec.table) {
			t.Errorf("retention query for %q missing DELETE FROM %s", spec.table, spec.table)
		}
		if !strings.Contains(spec.query, "LIMIT $2") {
			t.Errorf("retention query for %q must be bounded with LIMIT $2", spec.table)
		}
	}
	// Cross-table FK guard in notification_events retention query.
	if !tables["notification_deliveries"]["event_id"] {
		t.Fatal("notification_deliveries.event_id missing from schema.sql")
	}
}

type mockRetentionExecer struct {
	handler func(ctx context.Context, query string, args ...any) (sql.Result, error)
}

func (m mockRetentionExecer) ExecContext(ctx context.Context, query string, args ...any) (sql.Result, error) {
	return m.handler(ctx, query, args...)
}

func TestRetentionPassBatchingAndCancellation(t *testing.T) {
	t.Run("batched_pruning_caps_and_optional_42P01", func(t *testing.T) {
		callsByTable := map[string]int{}
		pauses := 0
		cfg := RetentionConfig{
			ServerLogsDays:        14,
			OperationReceiptsDays: 7,
			NotificationDays:      0, // disabled -> must skip both notification tables
			LLMRecordsDays:        7,
			InterceptDecidedDays:  30,
			BatchSize:             100,
			MaxBatchesPerTable:    3,
			BatchPause:            time.Millisecond,
		}
		now := time.Date(2026, 11, 24, 12, 0, 0, 0, time.UTC)

		execer := mockRetentionExecer{handler: func(_ context.Context, query string, args ...any) (sql.Result, error) {
			if len(args) != 2 || args[1] != 100 {
				t.Fatalf("unexpected retention args: %v", args)
			}
			switch {
			case strings.Contains(query, "DELETE FROM server_logs"):
				callsByTable["server_logs"]++
				if callsByTable["server_logs"] <= 2 {
					return fakeResult(100), nil
				}
				return fakeResult(23), nil // partial batch ends loop
			case strings.Contains(query, "DELETE FROM operation_receipts"):
				callsByTable["operation_receipts"]++
				return fakeResult(100), nil // full batches -> capped at MaxBatchesPerTable=3
			case strings.Contains(query, "DELETE FROM llm_records"):
				callsByTable["llm_records"]++
				return nil, &pgconn.PgError{Code: "42P01", Message: `relation "llm_records" does not exist`}
			case strings.Contains(query, "DELETE FROM intercept_pending"):
				callsByTable["intercept_pending"]++
				return fakeResult(12), nil
			default:
				t.Fatalf("unexpected query executed: %s", query)
				return nil, nil
			}
		}}

		stats, err := runRetentionPass(t.Context(), execer, cfg, now, func(context.Context, time.Duration) bool {
			pauses++
			return true
		})
		if err != nil {
			t.Fatalf("runRetentionPass err=%v want nil", err)
		}
		if stats.ServerLogs != 223 || stats.OperationReceipts != 300 ||
			stats.NotificationDeliveries != 0 || stats.NotificationEvents != 0 ||
			stats.LLMRecords != 0 || stats.InterceptPending != 12 || stats.Total() != 535 {
			t.Fatalf("unexpected stats: %+v", stats)
		}
		if callsByTable["server_logs"] != 3 || callsByTable["operation_receipts"] != 3 ||
			callsByTable["llm_records"] != 1 || callsByTable["intercept_pending"] != 1 {
			t.Fatalf("unexpected batch call counts: %v", callsByTable)
		}
		// 2 pauses between 3 server_logs batches + 2 pauses between 3 operation_receipts batches = 4.
		if pauses != 4 {
			t.Fatalf("pauses=%d want 4", pauses)
		}
	})

	t.Run("stops_immediately_on_context_cancel", func(t *testing.T) {
		ctx, cancel := context.WithCancel(t.Context())
		calls := 0
		cfg := RetentionConfig{
			ServerLogsDays:     14,
			BatchSize:          10,
			MaxBatchesPerTable: 5,
			BatchPause:         time.Hour,
		}
		execer := mockRetentionExecer{handler: func(context.Context, string, ...any) (sql.Result, error) {
			calls++
			cancel()
			return fakeResult(10), nil
		}}
		stats, err := runRetentionPass(ctx, execer, cfg, time.Now().UTC(), waitRetentionTimer)
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("err=%v want context.Canceled", err)
		}
		if calls != 1 || stats.ServerLogs != 10 {
			t.Fatalf("calls=%d stats=%+v want 1/10", calls, stats)
		}
	})
}

func TestRetentionWorkerExitsOnCancel(t *testing.T) {
	t.Run("cancel_during_initial_delay", func(t *testing.T) {
		ctx, cancel := context.WithCancel(t.Context())
		var runs atomic.Int32
		done := make(chan struct{})
		cfg := DefaultRetentionConfig()
		cfg.InitialDelay = time.Hour

		go func() {
			defer close(done)
			runRetentionWorker(ctx, cfg, func(context.Context, RetentionConfig) (RetentionStats, error) {
				runs.Add(1)
				return RetentionStats{}, nil
			})
		}()
		cancel()
		select {
		case <-done:
		case <-time.After(time.Second):
			t.Fatal("retention worker did not exit promptly on cancel during initial delay")
		}
		if runs.Load() != 0 {
			t.Fatalf("runs=%d want 0 when cancelled before initial delay", runs.Load())
		}
	})

	t.Run("runs_periodic_pass_then_exits_on_cancel", func(t *testing.T) {
		ctx, cancel := context.WithCancel(t.Context())
		ran := make(chan struct{}, 4)
		done := make(chan struct{})
		cfg := DefaultRetentionConfig()
		cfg.InitialDelay = -1 // skip initial wait in test
		cfg.Interval = 20 * time.Millisecond

		go func() {
			defer close(done)
			runRetentionWorker(ctx, cfg, func(context.Context, RetentionConfig) (RetentionStats, error) {
				select {
				case ran <- struct{}{}:
				default:
				}
				return RetentionStats{ServerLogs: 1}, nil
			})
		}()
		select {
		case <-ran:
		case <-time.After(time.Second):
			t.Fatal("worker did not execute initial pass")
		}
		cancel()
		select {
		case <-done:
		case <-time.After(time.Second):
			t.Fatal("retention worker did not exit promptly on cancel")
		}
	})
}

func TestSchemaTaskTokenBudgetEvaluation(t *testing.T) {
	if !strings.Contains(taskTokenBudgetQuery, "LEFT JOIN task_token_counters c ON c.task_id = t.id") ||
		!strings.Contains(taskTokenBudgetQuery, "COALESCE(c.tokens_used, 0)") {
		t.Fatalf("taskTokenBudgetQuery must join task_token_counters: %s", taskTokenBudgetQuery)
	}
	if strings.Contains(strings.ToLower(taskTokenBudgetQuery), "from llm_usage") {
		t.Fatalf("taskTokenBudgetQuery must not scan llm_usage: %s", taskTokenBudgetQuery)
	}

	// Unlimited, usage not requested: returns zeroed usage without error even if unavailable.
	b, err := evaluateTaskTokenBudget(0, 1, 500, false, false)
	if err != nil || b.Limit != 0 || b.Revision != 1 || b.Used != 0 || b.Reached || b.UsageAvailable {
		t.Fatalf("unlimited !includeUsage = (%+v, %v)", b, err)
	}

	// Unlimited, usage requested, table unavailable: returns UsageAvailable=false without error.
	b, err = evaluateTaskTokenBudget(0, 2, 500, false, true)
	if err != nil || b.UsageAvailable || b.Used != 0 || b.Reached {
		t.Fatalf("unlimited unavailable = (%+v, %v)", b, err)
	}

	// Unlimited, usage requested, table available: reports Used without Reached.
	b, err = evaluateTaskTokenBudget(0, 2, 1000, true, true)
	if err != nil || !b.UsageAvailable || b.Used != 1000 || b.Reached {
		t.Fatalf("unlimited available = (%+v, %v)", b, err)
	}

	// Limited, table unavailable: fails closed with budget_usage_unavailable.
	_, err = evaluateTaskTokenBudget(1000, 3, 0, false, false)
	var opErr *operation.Error
	if !errors.As(err, &opErr) || opErr.Code != "budget_usage_unavailable" {
		t.Fatalf("expected budget_usage_unavailable, got %v", err)
	}

	// Limited, below threshold.
	b, err = evaluateTaskTokenBudget(1000, 3, 999, true, false)
	if err != nil || !b.UsageAvailable || b.Used != 999 || b.Reached {
		t.Fatalf("below limit = (%+v, %v)", b, err)
	}

	// Limited, at threshold.
	b, err = evaluateTaskTokenBudget(1000, 3, 1000, true, false)
	if err != nil || !b.UsageAvailable || b.Used != 1000 || !b.Reached {
		t.Fatalf("at limit = (%+v, %v)", b, err)
	}
}

func TestSchemaNotificationAssetNamesOrderAndDedup(t *testing.T) {
	labels := map[int64]string{
		10: "https://a.example.com/admin",
		20: "a.example.com",
		30: "10.1.2.3",
		40: "",
	}
	got := resolveNotificationAssetNames([]int64{10, 999, 20, 40, 30, 10}, labels)
	want := []string{"https://a.example.com/admin", "a.example.com", "10.1.2.3"}
	if len(got) != len(want) {
		t.Fatalf("got=%v want=%v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("index %d: got=%q want=%q", i, got[i], want[i])
		}
	}
}
