package db

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"log"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/jackc/pgx/v5/pgconn"
)

const (
	defaultRetentionServerLogsDays        = 14
	defaultRetentionOperationReceiptsDays = 7
	defaultRetentionNotificationDays      = 30
	defaultRetentionLLMRecordsDays        = 7
	defaultRetentionInterceptDecidedDays  = 30

	defaultRetentionBatchSize          = 2000
	defaultRetentionMaxBatchesPerTable = 25
	defaultRetentionBatchPause         = 50 * time.Millisecond
	defaultRetentionInterval           = time.Hour
	defaultRetentionInitialDelay       = 2 * time.Minute
)

// RetentionConfig controls bounded background pruning of append-heavy operational
// tables. Setting any *Days field to 0 disables pruning for that table.
type RetentionConfig struct {
	ServerLogsDays        int
	OperationReceiptsDays int
	NotificationDays      int
	LLMRecordsDays        int
	InterceptDecidedDays  int

	BatchSize          int
	MaxBatchesPerTable int
	BatchPause         time.Duration
	Interval           time.Duration
	InitialDelay       time.Duration
}

// DefaultRetentionConfig returns conservative production defaults for retention pruning.
func DefaultRetentionConfig() RetentionConfig {
	return RetentionConfig{
		ServerLogsDays:        defaultRetentionServerLogsDays,
		OperationReceiptsDays: defaultRetentionOperationReceiptsDays,
		NotificationDays:      defaultRetentionNotificationDays,
		LLMRecordsDays:        defaultRetentionLLMRecordsDays,
		InterceptDecidedDays:  defaultRetentionInterceptDecidedDays,
		BatchSize:             defaultRetentionBatchSize,
		MaxBatchesPerTable:    defaultRetentionMaxBatchesPerTable,
		BatchPause:            defaultRetentionBatchPause,
		Interval:              defaultRetentionInterval,
		InitialDelay:          defaultRetentionInitialDelay,
	}
}

// RetentionConfigFromEnv builds a RetentionConfig from defaults overlaid with
// ARTEX_RETENTION_*_DAYS environment overrides. An explicit "0" disables pruning
// for that table; empty, negative, or non-integer values keep the safe default.
func RetentionConfigFromEnv() RetentionConfig {
	cfg := DefaultRetentionConfig()
	cfg.ServerLogsDays = parseRetentionDaysEnv("ARTEX_RETENTION_LOGS_DAYS", cfg.ServerLogsDays)
	cfg.OperationReceiptsDays = parseRetentionDaysEnv("ARTEX_RETENTION_RECEIPTS_DAYS", cfg.OperationReceiptsDays)
	cfg.NotificationDays = parseRetentionDaysEnv("ARTEX_RETENTION_NOTIFICATIONS_DAYS", cfg.NotificationDays)
	cfg.LLMRecordsDays = parseRetentionDaysEnv("ARTEX_RETENTION_LLM_RECORDS_DAYS", cfg.LLMRecordsDays)
	cfg.InterceptDecidedDays = parseRetentionDaysEnv("ARTEX_RETENTION_INTERCEPT_DAYS", cfg.InterceptDecidedDays)
	return cfg
}

func parseRetentionDaysEnv(name string, def int) int {
	raw, ok := os.LookupEnv(name)
	if !ok {
		return def
	}
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return def
	}
	n, err := strconv.Atoi(raw)
	if err != nil || n < 0 {
		return def
	}
	return n
}

func (c RetentionConfig) normalized() RetentionConfig {
	if c.BatchSize <= 0 {
		c.BatchSize = defaultRetentionBatchSize
	}
	if c.MaxBatchesPerTable <= 0 {
		c.MaxBatchesPerTable = defaultRetentionMaxBatchesPerTable
	}
	if c.BatchPause <= 0 {
		c.BatchPause = defaultRetentionBatchPause
	}
	if c.Interval <= 0 {
		c.Interval = defaultRetentionInterval
	}
	if c.InitialDelay == 0 {
		c.InitialDelay = defaultRetentionInitialDelay
	}
	return c
}

// RetentionStats summarizes rows deleted across tables during one retention pass.
type RetentionStats struct {
	ServerLogs             int64
	OperationReceipts      int64
	NotificationDeliveries int64
	NotificationEvents     int64
	LLMRecords             int64
	InterceptPending       int64
}

// Total returns the total number of rows removed in this pass.
func (s RetentionStats) Total() int64 {
	return s.ServerLogs + s.OperationReceipts + s.NotificationDeliveries +
		s.NotificationEvents + s.LLMRecords + s.InterceptPending
}

type retentionTableSpec struct {
	table    string
	columns  []string // referenced columns validated by schema unit tests
	optional bool     // table may not exist yet (e.g. llm_records before EnsureLLMRecordsTable)
	days     func(RetentionConfig) int
	addStat  func(*RetentionStats, int64)
	query    string
}

var retentionSpecs = []retentionTableSpec{
	{
		table:   "server_logs",
		columns: []string{"id", "created_at"},
		days:    func(c RetentionConfig) int { return c.ServerLogsDays },
		addStat: func(s *RetentionStats, n int64) { s.ServerLogs += n },
		query: `
DELETE FROM server_logs
WHERE id IN (
    SELECT id FROM server_logs
    WHERE created_at < $1
    ORDER BY created_at, id
    LIMIT $2
)`,
	},
	{
		table:   "operation_receipts",
		columns: []string{"scope", "request_id", "created_at"},
		days:    func(c RetentionConfig) int { return c.OperationReceiptsDays },
		addStat: func(s *RetentionStats, n int64) { s.OperationReceipts += n },
		query: `
DELETE FROM operation_receipts
WHERE (scope, request_id) IN (
    SELECT scope, request_id FROM operation_receipts
    WHERE created_at < $1
    ORDER BY created_at, scope, request_id
    LIMIT $2
)`,
	},
	{
		table:   "notification_deliveries",
		columns: []string{"id", "state", "created_at"},
		days:    func(c RetentionConfig) int { return c.NotificationDays },
		addStat: func(s *RetentionStats, n int64) { s.NotificationDeliveries += n },
		query: `
DELETE FROM notification_deliveries
WHERE id IN (
    SELECT id FROM notification_deliveries
    WHERE state IN ('sent', 'failed', 'skipped')
      AND created_at < $1
    ORDER BY created_at, id
    LIMIT $2
)`,
	},
	{
		table:   "notification_events",
		columns: []string{"id", "fanned_out", "created_at"},
		days:    func(c RetentionConfig) int { return c.NotificationDays },
		addStat: func(s *RetentionStats, n int64) { s.NotificationEvents += n },
		query: `
DELETE FROM notification_events
WHERE id IN (
    SELECT e.id FROM notification_events e
    WHERE e.fanned_out
      AND e.created_at < $1
      AND NOT EXISTS (
          SELECT 1 FROM notification_deliveries d WHERE d.event_id = e.id
      )
    ORDER BY e.created_at, e.id
    LIMIT $2
)`,
	},
	{
		table:    "llm_records",
		columns:  []string{"id", "ts"},
		optional: true,
		days:     func(c RetentionConfig) int { return c.LLMRecordsDays },
		addStat:  func(s *RetentionStats, n int64) { s.LLMRecords += n },
		query: `
DELETE FROM llm_records
WHERE id IN (
    SELECT id FROM llm_records
    WHERE ts < $1
    ORDER BY ts, id
    LIMIT $2
)`,
	},
	{
		table:   "intercept_pending",
		columns: []string{"id", "status", "decided_at", "created_at"},
		days:    func(c RetentionConfig) int { return c.InterceptDecidedDays },
		addStat: func(s *RetentionStats, n int64) { s.InterceptPending += n },
		query: `
DELETE FROM intercept_pending
WHERE id IN (
    SELECT id FROM intercept_pending
    WHERE status <> 'pending'
      AND COALESCE(decided_at, created_at) < $1
    ORDER BY COALESCE(decided_at, created_at), id
    LIMIT $2
)`,
	},
}

type retentionExecer interface {
	ExecContext(ctx context.Context, query string, args ...any) (sql.Result, error)
}

func isUndefinedTable(err error) bool {
	var pgErr *pgconn.PgError
	return errors.As(err, &pgErr) && pgErr.Code == "42P01"
}

func waitRetentionTimer(ctx context.Context, d time.Duration) bool {
	if d <= 0 {
		return ctx.Err() == nil
	}
	timer := time.NewTimer(d)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-timer.C:
		return true
	}
}

// RunRetentionPass prunes expired rows from operational tables using bounded,
// short-lived batched deletes so locks and WAL spikes stay small.
func (d *DB) RunRetentionPass(ctx context.Context, cfg RetentionConfig) (RetentionStats, error) {
	if d == nil || d.DB == nil {
		return RetentionStats{}, ctx.Err()
	}
	return runRetentionPass(ctx, d.DB, cfg, time.Now().UTC(), waitRetentionTimer)
}

func runRetentionPass(
	ctx context.Context,
	execer retentionExecer,
	cfg RetentionConfig,
	now time.Time,
	pause func(context.Context, time.Duration) bool,
) (RetentionStats, error) {
	cfg = cfg.normalized()
	var stats RetentionStats
	var errs []error

	for _, spec := range retentionSpecs {
		if err := ctx.Err(); err != nil {
			return stats, err
		}
		days := spec.days(cfg)
		if days <= 0 {
			continue
		}
		cutoff := now.AddDate(0, 0, -days)
		for batch := 0; batch < cfg.MaxBatchesPerTable; batch++ {
			if err := ctx.Err(); err != nil {
				return stats, err
			}
			res, err := execer.ExecContext(ctx, spec.query, cutoff, cfg.BatchSize)
			if err != nil {
				if ctx.Err() != nil {
					return stats, ctx.Err()
				}
				if spec.optional && isUndefinedTable(err) {
					break
				}
				errs = append(errs, fmt.Errorf("retention %s: %w", spec.table, err))
				break
			}
			n, _ := res.RowsAffected()
			spec.addStat(&stats, n)
			if n < int64(cfg.BatchSize) {
				break
			}
			if batch+1 < cfg.MaxBatchesPerTable && !pause(ctx, cfg.BatchPause) {
				return stats, ctx.Err()
			}
		}
	}
	return stats, errors.Join(errs...)
}

// RunRetentionWorker runs periodic retention passes in the background after an
// initial startup grace period (default 2 minutes), exiting promptly when ctx
// is cancelled.
func (d *DB) RunRetentionWorker(ctx context.Context, cfg RetentionConfig) {
	if d == nil || d.DB == nil {
		return
	}
	runRetentionWorker(ctx, cfg, d.RunRetentionPass)
}

func runRetentionWorker(
	ctx context.Context,
	cfg RetentionConfig,
	pass func(context.Context, RetentionConfig) (RetentionStats, error),
) {
	cfg = cfg.normalized()
	if cfg.InitialDelay > 0 && !waitRetentionTimer(ctx, cfg.InitialDelay) {
		return
	}
	runOnce := func() {
		stats, err := pass(ctx, cfg)
		if ctx.Err() != nil {
			return
		}
		if err != nil {
			log.Printf("[retention] pass finished with errors (deleted=%d): %v", stats.Total(), err)
			return
		}
		if stats.Total() > 0 {
			log.Printf("[retention] pruned %d rows (logs=%d receipts=%d notify_deliveries=%d notify_events=%d llm_records=%d intercept=%d)",
				stats.Total(), stats.ServerLogs, stats.OperationReceipts,
				stats.NotificationDeliveries, stats.NotificationEvents,
				stats.LLMRecords, stats.InterceptPending)
		}
	}
	runOnce()
	ticker := time.NewTicker(cfg.Interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			runOnce()
		}
	}
}
