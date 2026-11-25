// Package db is the PostgreSQL data source for ARTEX (取代旧 graph 单文件 SQLite)。
// 它打开连接、应用 schema、并 seed 内置 agent 与变量目录。
package db

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"database/sql/driver"
	_ "embed"
	"encoding/hex"
	"errors"
	"fmt"
	"log"
	"net/url"
	"strings"
	"time"

	"github.com/RC-CHN/ARTEX/config"
	"github.com/jackc/pgx/v5/pgconn"
	_ "github.com/jackc/pgx/v5/stdlib" // pgx database/sql driver ("pgx")
)

//go:embed schema.sql
var schemaSQL string

const schemaMigrationLockKey int64 = LockSchemaMigration

// maxOpenConns / maxIdleConns 是主库连接池上限，见 Open 里的说明。留足余量给
// traffic 连接池、psql / reset-password.sh 以及可能并存的其他实例，同时远高于
// 启动期 schema advisory lock 的嵌套取连接深度，不会自锁。
const (
	maxOpenConns = 18
	maxIdleConns = 8
)

var defaultDSNTimeouts = []struct {
	key string
	val string
}{
	{"connect_timeout", "5"},
	{"statement_timeout", "30000"},
	{"lock_timeout", "5000"},
	{"idle_in_transaction_session_timeout", "30000"},
}

// applyDefaultTimeouts injects conservative connection/session timeouts into a
// PostgreSQL DSN (URL or keyword-value format) only when the caller has not
// already specified them explicitly (either as top-level parameters or via
// PostgreSQL `options`).
func applyDefaultTimeouts(dsn string) string {
	trimmed := strings.TrimSpace(dsn)
	if trimmed == "" {
		return dsn
	}
	lower := strings.ToLower(trimmed)
	if strings.HasPrefix(lower, "postgres://") || strings.HasPrefix(lower, "postgresql://") {
		u, err := url.Parse(trimmed)
		if err != nil {
			return dsn
		}
		q := u.Query()
		optionsVal := queryValueFold(q, "options")
		changed := false
		for _, def := range defaultDSNTimeouts {
			if hasQueryKeyFold(q, def.key) || hasPGOption(optionsVal, def.key) {
				continue
			}
			q.Set(def.key, def.val)
			changed = true
		}
		if !changed {
			return dsn
		}
		u.RawQuery = q.Encode()
		return u.String()
	}

	keys, optionsVal := parseKeywordDSNKeys(trimmed)
	var extra []string
	for _, def := range defaultDSNTimeouts {
		if keys[def.key] || hasPGOption(optionsVal, def.key) {
			continue
		}
		extra = append(extra, def.key+"="+def.val)
	}
	if len(extra) == 0 {
		return dsn
	}
	return trimmed + " " + strings.Join(extra, " ")
}

func hasQueryKeyFold(q url.Values, target string) bool {
	for k := range q {
		if strings.EqualFold(k, target) {
			return true
		}
	}
	return false
}

func queryValueFold(q url.Values, target string) string {
	for k, vals := range q {
		if strings.EqualFold(k, target) && len(vals) > 0 {
			return vals[len(vals)-1]
		}
	}
	return ""
}

// hasPGOption reports whether a libpq `options` string configures the given GUC
// parameter via `-c key=val`, `-c key = val`, or `--key=val`.
func hasPGOption(options, key string) bool {
	if strings.TrimSpace(options) == "" {
		return false
	}
	fields := strings.Fields(options)
	for i := 0; i < len(fields); i++ {
		tok := fields[i]
		var assign string
		switch {
		case tok == "-c" && i+1 < len(fields):
			i++
			assign = fields[i]
		case strings.HasPrefix(tok, "-c") && len(tok) > 2:
			assign = tok[2:]
		case strings.HasPrefix(tok, "--") && len(tok) > 2:
			assign = tok[2:]
		default:
			continue
		}
		name, _, hasEq := strings.Cut(assign, "=")
		if !hasEq && i+1 < len(fields) && strings.HasPrefix(fields[i+1], "=") {
			hasEq = true
		}
		if hasEq && strings.EqualFold(strings.ReplaceAll(strings.TrimSpace(name), "-", "_"), key) {
			return true
		}
	}
	return false
}

// parseKeywordDSNKeys extracts lowercased parameter names (and the `options`
// value if present) from a libpq keyword=value connection string, honoring
// single-quoted values and backslash escapes.
func parseKeywordDSNKeys(dsn string) (map[string]bool, string) {
	keys := map[string]bool{}
	var optionsVal string
	i, n := 0, len(dsn)
	skipSpace := func() {
		for i < n && (dsn[i] == ' ' || dsn[i] == '\t' || dsn[i] == '\n' || dsn[i] == '\r') {
			i++
		}
	}
	for i < n {
		skipSpace()
		if i >= n {
			break
		}
		start := i
		for i < n && dsn[i] != '=' && dsn[i] != ' ' && dsn[i] != '\t' && dsn[i] != '\n' && dsn[i] != '\r' {
			i++
		}
		key := strings.ToLower(dsn[start:i])
		skipSpace()
		if i >= n || dsn[i] != '=' {
			// Skip malformed token to avoid infinite loop.
			for i < n && dsn[i] != ' ' && dsn[i] != '\t' && dsn[i] != '\n' && dsn[i] != '\r' {
				i++
			}
			continue
		}
		i++ // consume '='
		skipSpace()
		var val strings.Builder
		if i < n && dsn[i] == '\'' {
			i++ // opening quote
			for i < n {
				if dsn[i] == '\\' && i+1 < n {
					val.WriteByte(dsn[i+1])
					i += 2
					continue
				}
				if dsn[i] == '\'' {
					i++
					break
				}
				val.WriteByte(dsn[i])
				i++
			}
		} else {
			for i < n && dsn[i] != ' ' && dsn[i] != '\t' && dsn[i] != '\n' && dsn[i] != '\r' {
				if dsn[i] == '\\' && i+1 < n {
					val.WriteByte(dsn[i+1])
					i += 2
					continue
				}
				val.WriteByte(dsn[i])
				i++
			}
		}
		if key != "" {
			keys[key] = true
			if key == "options" {
				optionsVal = val.String()
			}
		}
	}
	return keys, optionsVal
}

var schemaDeadlockRetryDelays = [...]time.Duration{
	100 * time.Millisecond,
	250 * time.Millisecond,
	500 * time.Millisecond,
	time.Second,
}

type schemaExecer interface {
	ExecContext(context.Context, string, ...any) (sql.Result, error)
}

type schemaMigrationRunner interface {
	schemaExecer
	CurrentSchemaDigest(ctx context.Context, key string) (string, bool, error)
}

type sqlSchemaMigrator struct {
	conn *sql.Conn
}

func (m sqlSchemaMigrator) ExecContext(ctx context.Context, query string, args ...any) (sql.Result, error) {
	return m.conn.ExecContext(ctx, query, args...)
}

func (m sqlSchemaMigrator) CurrentSchemaDigest(ctx context.Context, key string) (string, bool, error) {
	var hash string
	err := m.conn.QueryRowContext(ctx, `SELECT sha256 FROM schema_migrations WHERE key = $1`, key).Scan(&hash)
	if errors.Is(err, sql.ErrNoRows) {
		return "", false, nil
	}
	if err != nil {
		return "", false, err
	}
	return hash, true, nil
}

const schemaMigrationKey = "schema.sql"

const schemaMigrationsTableDDL = `
CREATE TABLE IF NOT EXISTS schema_migrations (
    key TEXT PRIMARY KEY,
    sha256 TEXT NOT NULL,
    applied_at TIMESTAMPTZ NOT NULL DEFAULT now()
)`

// schemaDigest computes the deterministic SHA-256 hex digest used to gate
// startup DDL re-execution via schema_migrations.
func schemaDigest(sqlText string) string {
	sum := sha256.Sum256([]byte(sqlText))
	return hex.EncodeToString(sum[:])
}

func isPostgresDeadlock(err error) bool {
	var pgErr *pgconn.PgError
	return errors.As(err, &pgErr) && pgErr.Code == "40P01"
}

func applySchemaWithRetry(ctx context.Context, execer schemaExecer, sleep func(time.Duration)) error {
	for attempt := 0; ; attempt++ {
		if _, err := execer.ExecContext(ctx, schemaSQL); err != nil {
			if !isPostgresDeadlock(err) || attempt >= len(schemaDeadlockRetryDelays) {
				return err
			}
			sleep(schemaDeadlockRetryDelays[attempt])
			continue
		}
		return nil
	}
}

// applySchemaIfChanged ensures schema_migrations exists and skips re-running
// schema.sql when its SHA-256 digest matches the last applied version.
func applySchemaIfChanged(ctx context.Context, m schemaMigrationRunner, sleep func(time.Duration)) (bool, error) {
	if _, err := m.ExecContext(ctx, schemaMigrationsTableDDL); err != nil {
		return false, fmt.Errorf("ensure schema_migrations: %w", err)
	}
	wantHash := schemaDigest(schemaSQL)
	gotHash, ok, err := m.CurrentSchemaDigest(ctx, schemaMigrationKey)
	if err != nil {
		return false, fmt.Errorf("read schema_migrations: %w", err)
	}
	if ok && gotHash == wantHash {
		log.Printf("[pg] schema up-to-date, skipped DDL")
		return false, nil
	}
	if err := applySchemaWithRetry(ctx, m, sleep); err != nil {
		return false, err
	}
	if _, err := m.ExecContext(ctx, `
INSERT INTO schema_migrations(key, sha256, applied_at)
VALUES ($1, $2, now())
ON CONFLICT (key) DO UPDATE
    SET sha256 = EXCLUDED.sha256,
        applied_at = EXCLUDED.applied_at`, schemaMigrationKey, wantHash); err != nil {
		return false, fmt.Errorf("record schema_migrations: %w", err)
	}
	return true, nil
}

const (
	maintenanceLocalTimeoutsSQL        = `SET LOCAL statement_timeout = '0'; SET LOCAL lock_timeout = '30s'; SET LOCAL idle_in_transaction_session_timeout = '0'`
	maintenanceSessionTimeoutsSQL      = `SET statement_timeout = '0'; SET lock_timeout = '30s'; SET idle_in_transaction_session_timeout = '0'`
	resetMaintenanceSessionTimeoutsSQL = `RESET statement_timeout; RESET lock_timeout; RESET idle_in_transaction_session_timeout`
	sessionCleanupTimeout              = 5 * time.Second
)

// SetMaintenanceTimeouts overrides conservative default DSN timeouts for the
// current transaction so legitimate long-running maintenance operations (DDL,
// backfills, archive snapshot/restore/compaction, evidence/resource sweeps) do
// not get aborted prematurely by the 5s lock / 30s statement / 30s idle-in-tx
// runtime limits. SET LOCAL automatically reverts at transaction end.
func SetMaintenanceTimeouts(ctx context.Context, exec interface {
	ExecContext(context.Context, string, ...any) (sql.Result, error)
}) error {
	if exec == nil {
		return errors.New("nil maintenance timeout execer")
	}
	if ctx == nil {
		ctx = context.Background()
	}
	if _, err := exec.ExecContext(ctx, maintenanceLocalTimeoutsSQL); err != nil {
		return fmt.Errorf("set maintenance timeouts: %w", err)
	}
	return nil
}

// discardConn marks a pinned *sql.Conn as bad so database/sql closes and drops
// the underlying PostgreSQL session instead of returning a dirty session (with
// an unreleased advisory lock or non-default session timeouts) to the pool.
func discardConn(conn *sql.Conn) {
	if conn == nil {
		return
	}
	_ = conn.Raw(func(any) error { return driver.ErrBadConn })
}

// withPinnedSessionLock checks out a dedicated *sql.Conn, applies optional
// session-level timeout overrides, acquires a session-level PostgreSQL advisory
// lock (no open transaction, no idle_in_transaction_session_timeout, no MVCC
// xmin pinning), runs action, and cleanly unlocks + resets timeouts before
// returning the connection to the pool (discarding the connection if cleanup
// fails so pool callers never inherit leaked locks or altered GUCs).
func withPinnedSessionLock(
	ctx context.Context,
	sqlDB *sql.DB,
	lockKey int64,
	setTimeoutsSQL string,
	resetTimeoutsSQL string,
	action func(*sql.Conn) error,
) (err error) {
	if ctx == nil {
		ctx = context.Background()
	}
	conn, err := sqlDB.Conn(ctx)
	if err != nil {
		return err
	}
	timeoutsSet := false
	locked := false
	defer func() {
		dirty := false
		if locked {
			cleanCtx, cancel := context.WithTimeout(context.Background(), sessionCleanupTimeout)
			if _, unlockErr := conn.ExecContext(cleanCtx, `SELECT pg_advisory_unlock($1)`, lockKey); unlockErr != nil {
				dirty = true
				if err == nil {
					err = fmt.Errorf("advisory unlock: %w", unlockErr)
				}
			}
			cancel()
		}
		if timeoutsSet && !dirty {
			cleanCtx, cancel := context.WithTimeout(context.Background(), sessionCleanupTimeout)
			if _, resetErr := conn.ExecContext(cleanCtx, resetTimeoutsSQL); resetErr != nil {
				dirty = true
			}
			cancel()
		}
		if dirty {
			discardConn(conn)
		}
		_ = conn.Close()
	}()

	if setTimeoutsSQL != "" {
		if _, err := conn.ExecContext(ctx, setTimeoutsSQL); err != nil {
			discardConn(conn)
			return fmt.Errorf("set session timeouts: %w", err)
		}
		timeoutsSet = true
	}
	if _, err := conn.ExecContext(ctx, `SELECT pg_advisory_lock($1)`, lockKey); err != nil {
		return fmt.Errorf("advisory lock: %w", err)
	}
	locked = true
	return action(conn)
}

// withSchemaMigrationLock pins the session-level lock to one checked-out
// connection with maintenance session timeouts so startup DDL and backfills
// never trip the short runtime lock/statement defaults.
func withSchemaMigrationLock(ctx context.Context, sqlDB *sql.DB, action func(*sql.Conn) error) error {
	return withPinnedSessionLock(
		ctx,
		sqlDB,
		schemaMigrationLockKey,
		maintenanceSessionTimeoutsSQL,
		resetMaintenanceSessionTimeoutsSQL,
		action,
	)
}

// coordinateWithSchemaMigration makes long, multi-table archive transactions
// mutually exclusive with startup DDL while allowing ordinary runtime queries
// to continue normally.
func coordinateWithSchemaMigration(tx *sql.Tx) error {
	if _, err := tx.Exec(`SELECT pg_advisory_xact_lock($1)`, schemaMigrationLockKey); err != nil {
		return fmt.Errorf("coordinate with schema migration: %w", err)
	}
	return nil
}

// DSN resolves the PostgreSQL connection string and reports where it came from.
// Precedence: env ARTEX_PG_DSN > config file (config.json). There is no
// built-in default — it errors if neither source is configured.
func DSN() (dsn, source string, err error) {
	return config.PostgresDSN()
}

// DB wraps the shared *sql.DB. PG handles its own connection pool + concurrency
// (MVCC), so unlike the old SQLite store there is no process-wide write mutex.
type DB struct{ *sql.DB }

// quotePGIdent safely quotes a PostgreSQL identifier by doubling embedded double quotes.
func quotePGIdent(ident string) string {
	return `"` + strings.ReplaceAll(ident, `"`, `""`) + `"`
}

// ensureDatabase connects to the postgres system database and creates the target
// database if it does not exist. dsn must be a postgres:// URL.
func ensureDatabase(dsn string) error {
	u, err := url.Parse(dsn)
	if err != nil {
		return nil // unparseable DSN — let the normal Open fail with a clear error
	}
	dbName := strings.TrimPrefix(u.Path, "/")
	if dbName == "" || dbName == "postgres" {
		return nil
	}
	// connect to the postgres maintenance database instead
	adminDSN := *u
	adminDSN.Path = "/postgres"
	admin, err := sql.Open("pgx", adminDSN.String())
	if err != nil {
		return nil // best-effort; let Open surface the real error
	}
	defer admin.Close()
	if err := admin.Ping(); err != nil {
		return nil
	}
	var exists bool
	_ = admin.QueryRow(`SELECT true FROM pg_database WHERE datname=$1`, dbName).Scan(&exists)
	if !exists {
		if _, err := admin.Exec(`CREATE DATABASE ` + quotePGIdent(dbName)); err != nil {
			return fmt.Errorf("create database %q: %w", dbName, err)
		}
	}
	return nil
}

// Open connects, applies the schema (idempotent), and seeds builtin rows.
func Open(dsn string) (*DB, error) {
	effectiveDSN := applyDefaultTimeouts(dsn)
	if err := ensureDatabase(effectiveDSN); err != nil {
		return nil, err
	}
	sqlDB, err := sql.Open("pgx", effectiveDSN)
	if err != nil {
		return nil, err
	}
	// database/sql 默认不限制连接数：池里没有空闲连接时会无条件新建，一路顶到
	// PostgreSQL 的 max_connections（默认 100）才被拒，于是高峰期的查询拿到的是
	// `FATAL: sorry, too many clients already` 这种**错误**。封顶之后超额查询改为
	// 排队等待空闲连接——同样的负载下变成变慢而不是报错，调用方不必再去区分
	// "读不到"和"没有"。maxOpenConns 要留出余量给 psql / reset-password.sh 以及
	// 可能并存的其他实例；若 max_connections 调低过，这里也要跟着往下调。
	sqlDB.SetMaxOpenConns(maxOpenConns)
	sqlDB.SetMaxIdleConns(maxIdleConns)
	sqlDB.SetConnMaxLifetime(30 * time.Minute)
	sqlDB.SetConnMaxIdleTime(5 * time.Minute)
	if err := sqlDB.Ping(); err != nil {
		sqlDB.Close()
		return nil, fmt.Errorf("ping postgres (%s): %w", config.Redact(dsn), err)
	}
	d := &DB{sqlDB}
	// pgx runs multi-statement Exec via the simple protocol when there are no args.
	// Keep the dedicated lock connection checked out until both DDL and seeding
	// finish so concurrent application instances cannot initialize out of order.
	err = withSchemaMigrationLock(context.Background(), sqlDB, func(conn *sql.Conn) error {
		if _, err := applySchemaIfChanged(context.Background(), sqlSchemaMigrator{conn: conn}, time.Sleep); err != nil {
			return fmt.Errorf("apply schema: %w", err)
		}
		if err := d.seedBuiltins(); err != nil {
			return fmt.Errorf("seed builtins: %w", err)
		}
		return nil
	})
	if err != nil {
		sqlDB.Close()
		return nil, err
	}
	return d, nil
}

// builtinAgent describes one of the fixed agents and its prompt-variable catalog.
type builtinAgent struct {
	key, name, role, desc string
	vars                  []promptVar
	interactiveShell      bool // 建行时的默认交互式 shell 开关；ON CONFLICT 不覆盖用户后续手动开关
	runSeconds            *int // 建行时的单次 run 墙钟上限(秒)；nil=用种子默认(1200)，0=不限时
}

type promptVar struct{ name, desc, example, source string }

// intp 返回 v 的指针，用于给 builtinAgent 可选字段(如 runSeconds)显式取值。
func intp(v int) *int { return &v }

// builtinAgents mirrors docs §5(a). 内置工具不入库；这里只 seed agent + 变量目录。
// 注：planner/worker/mainagent/auto 的交互式 shell 默认由下方 interactive_shell_default_v1
// 块统一置 true（尊重后续 toggle）；这里的 interactiveShell 只给需要「建行即默认开」的新 agent。
var builtinAgents = []builtinAgent{
	{"goals", "目标拆解", "goals", "把渗透任务目标拆解成若干独立、可验证的子目标。", []promptVar{
		{"EngagementDescription", "任务描述（测试对象/背景）", "测试 example.com 站点", "exploration"},
		// Now 是全局 runtime 变量(见 server.globalPromptVars),不再在各 agent 目录里
		// 重复定义,否则 withGlobalVars 追加时会与全局项撞名。
	}, false, nil},
	{"planner", "规划", "planner", "读取态势、判定目标，只在确有未覆盖的新方向时补充探索意图（每任务一个规划循环）。", []promptVar{
		{"Goal", "任务总目标", "拿下 example.com 的管理员权限", "exploration"},
		{"AssetSummary", "资产计数/类型分布摘要(可选)", "domain:3 ip:5 site:2", "distilled"},
	}, false, nil},
	{"mainagent", "主", "main", "人机接口：观察进展，把人的意图落成 hint 或高优先级意图。", []promptVar{
		{"Goal", "当前任务目标", "拿下 example.com 的管理员权限", "exploration"},
		{"AssetSummary", "开局态势摘要(可选)", "domain:3 ip:5", "distilled"},
		{"FindingsSummary", "已确认漏洞摘要(可选)", "high:1 medium:2", "distilled"},
	}, false, nil},
	{"worker", "执行", "worker", "领取一条意图执行，把发现的事实/漏洞写回知识图谱后停止。", []promptVar{
		{"ProxyAddr", "记录代理地址(驱动 if 双文案)", "127.0.0.1:8080", "runtime"},
		{"WorkerName", "worker 自我标识(可选)", "worker-1", "runtime"},
	}, false, nil},
	// Auto:内置「平台操作」agent。不参与渗透编排循环,经对话页驱动,用工具操作平台。
	{"auto", "Auto", "assistant", "平台操作助手：用工具管理任务(建/看/暂停/给提示)与资产，并可创建/修改 skill、自定义工具、MCP。", nil, false, nil},
	// 渗透测试:内置「独立渗透」agent。经对话页驱动,一人从侦察到收尾走完整条渗透链,自己规划自己执行自己验证。默认开启交互式 shell。
	{"pentest", "渗透测试", "assistant", "独立渗透 agent：一人从侦察→找攻击面→深入利用→验证→收尾走完整条链，自己规划、自己执行、自己对抗式验证。", nil, true, intp(0)},
}

// seedBuiltins inserts the fixed built-in agents and their variable catalog (idempotent).
func (d *DB) seedBuiltins() error {
	for _, a := range builtinAgents {
		var agentID int64
		err := d.QueryRow(`
INSERT INTO agents(key, name, description, role, builtin, enabled, interactive_shell, run_seconds)
VALUES ($1, $2, NULLIF($3,''), $4, true, true, $5, CASE WHEN $1='worker' THEN 0 ELSE COALESCE($6, 1200) END)
ON CONFLICT (key) DO UPDATE SET name = EXCLUDED.name, description = EXCLUDED.description
RETURNING id`, a.key, a.name, a.desc, a.role, a.interactiveShell, a.runSeconds).Scan(&agentID)
		if err != nil {
			return fmt.Errorf("agent %s: %w", a.key, err)
		}
		for _, v := range a.vars {
			if _, err := d.Exec(`
INSERT INTO agent_prompt_vars(agent_id, var_name, description, example, source)
VALUES ($1, $2, $3, $4, $5)
ON CONFLICT (agent_id, var_name) DO UPDATE
  SET description = EXCLUDED.description, example = EXCLUDED.example, source = EXCLUDED.source`,
				agentID, v.name, v.desc, v.example, v.source); err != nil {
				return fmt.Errorf("agent %s var %s: %w", a.key, v.name, err)
			}
		}
	}
	if err := d.seedWorkerBudgetDefaults(); err != nil {
		return fmt.Errorf("seed worker budget: %w", err)
	}
	// Drop catalog entries for variables that were renamed, so the white-list no
	// longer advertises a name templates can't resolve (EngagementTitle→Description).
	// 'Now' 从各 agent 目录提升为全局 runtime 变量后,旧库里 goals 仍残留一条 'Now'
	// 会与全局项撞名(前端变量列表 key 重复);一并清掉。
	if _, err := d.Exec(`DELETE FROM agent_prompt_vars WHERE var_name IN ('EngagementTitle', 'CoverageGaps', 'Now')`); err != nil {
		return fmt.Errorf("cleanup renamed vars: %w", err)
	}
	// Default-on interactive_shell for the runtime agents (planner/worker/mainagent/auto)
	// ONCE — respects a later user toggle-off (guarded by a settings flag). goals(one-shot
	// decomposer) stays off. Runs after the column exists (schema applied before seed).
	if v, _, _ := d.GetSetting("interactive_shell_default_v1"); v != "true" {
		if _, err := d.Exec(`UPDATE agents SET interactive_shell=true WHERE key IN ('planner','worker','mainagent','auto')`); err != nil {
			return fmt.Errorf("seed interactive_shell defaults: %w", err)
		}
		_ = d.SetSetting("interactive_shell_default_v1", "true")
	}
	// Seed the built-in browser (Playwright) MCP once — DISABLED by default (用户
	// 需要时自行启用), no proxy by default. The traffic-capture toggle injects/strips
	// the recording proxy + CA at runtime (server.Manager.syncBrowserMCPProxy).
	// Insert only if absent so we never clobber user edits (args/env/enabled/
	// visibility) on restart.
	if _, err := d.Exec(`
INSERT INTO mcp_servers(name, transport, command, args, env, enabled)
VALUES ('browser', 'stdio', 'npx', $1, '{}', false)
ON CONFLICT (name) DO NOTHING`,
		`["@playwright/mcp","--headless"]`); err != nil {
		return fmt.Errorf("seed browser mcp: %w", err)
	}
	// NOTE: the placeholder ScopeSentry data-source MCP (empty URL + empty X-API-Key,
	// disabled) is seeded directly in schema.sql §F so a raw `psql < schema.sql` init
	// also gets it. schema.sql is Exec'd on every startup, so it stays idempotent.
	if err := d.seedBuiltinSkillVisibility(); err != nil {
		return fmt.Errorf("seed skill visibility: %w", err)
	}
	if err := d.seedDefaultInterceptRules(); err != nil {
		return fmt.Errorf("seed intercept rules: %w", err)
	}
	if err := d.seedDefaultInterceptRulesV2(); err != nil {
		return fmt.Errorf("seed intercept rules v2: %w", err)
	}
	if err := d.seedDefaultInterceptRulesV3(); err != nil {
		return fmt.Errorf("seed intercept rules v3: %w", err)
	}
	if err := d.seedDefaultAssetInterceptRules(); err != nil {
		return fmt.Errorf("seed asset intercept rules: %w", err)
	}
	return nil
}

// seedDefaultAssetInterceptRules inserts the built-in asset blocklist (fuzzy
// domain matches for government / education sites) once on first startup. Gated
// by a settings flag so a user's later disable/delete is never resurrected on
// restart — same policy as the intercept-rule seed.
func (d *DB) seedDefaultAssetInterceptRules() error {
	if v, _, _ := d.GetSetting("asset_intercept_default_rules_v1"); v == "done" {
		return nil
	}
	rules := []struct {
		kind    string
		pattern string
		note    string
	}{
		{"fuzzy_domain", ".gov", "[内置] 政府网站 (.gov)"},
		{"fuzzy_domain", ".gov.cn", "[内置] 政府网站 (.gov.cn)"},
		{"fuzzy_domain", ".edu", "[内置] 教育网站 (.edu)"},
		{"fuzzy_domain", ".edu.cn", "[内置] 教育网站 (.edu.cn)"},
	}
	for _, r := range rules {
		if _, err := d.Exec(`
INSERT INTO asset_intercept_rules(enabled, kind, pattern, note, builtin)
VALUES (true, $1, $2, $3, true)
ON CONFLICT DO NOTHING`, r.kind, r.pattern, r.note); err != nil {
			return fmt.Errorf("asset rule %q: %w", r.pattern, err)
		}
	}
	return d.SetSetting("asset_intercept_default_rules_v1", "done")
}

// builtinSkillVisibility maps a shipped skill's directory name → the built-in
// agent keys that should see it by default. The skill FILES themselves live on the
// filesystem (SkillDir, loaded by norma at runtime); DB only carries this visibility
// binding. Skills omitted here (e.g. playwright-cli, scopesentry) ship invisible by
// default — the user turns them on per-agent when needed. scopesentry additionally
// declares `mcps: ScopeSentry`, which only takes effect once it's made visible and
// that MCP is enabled/configured.
var builtinSkillVisibility = map[string][]string{
	"api-recon":            {"auto", "pentest", "worker"},
	"nuclei":               {"mainagent", "planner", "worker", "auto", "pentest"},
	"vulnx":                {"mainagent", "planner", "worker", "auto", "pentest"},
	"web-discovery":        {"mainagent", "planner", "worker", "auto", "pentest"},
	"authenticated-verify": {"mainagent", "planner", "worker", "auto", "pentest"},
	"portable-tools":       {"mainagent", "planner", "worker", "auto", "pentest"},
	"targeted-verify":      {"mainagent", "planner", "worker", "auto", "pentest"},
	"protocol-check":       {"mainagent", "planner", "worker", "auto", "pentest"},
	"ip-lookup":            {"mainagent", "planner", "worker", "auto", "pentest"},
	"python-environment":   {"mainagent", "planner", "worker", "auto", "pentest"},
	"tack":                 {"mainagent", "planner", "worker", "auto", "pentest"},
	"resource-creator":     {"mainagent", "planner", "worker", "auto", "pentest"},
}

// seedBuiltinSkillVisibility binds the shipped built-in skills to their default
// agents. Insert-if-absent (ON CONFLICT DO NOTHING) so a user's later toggle-off is
// never resurrected on restart — matches the browser-MCP / intercept-rule seed policy.
func (d *DB) seedBuiltinSkillVisibility() error {
	for skillName, agentKeys := range builtinSkillVisibility {
		for _, key := range agentKeys {
			if _, err := d.Exec(`
WITH agent AS MATERIALIZED (SELECT id FROM agents WHERE key=$1 FOR UPDATE)
INSERT INTO agent_skill_visibility(agent_id, skill_name, enabled)
SELECT id, $2, true FROM agent
ON CONFLICT (agent_id, skill_name) DO NOTHING`, key, skillName); err != nil {
				return fmt.Errorf("skill %s → agent %s: %w", skillName, key, err)
			}
		}
	}
	return nil
}

// seedDefaultInterceptRules inserts built-in safety intercept rules once on
// first startup. The seed is gated by a settings flag so user edits (disable,
// delete, re-order) are never overwritten on subsequent restarts.
func (d *DB) seedDefaultInterceptRules() error {
	if v, _, _ := d.GetSetting("intercept_default_rules_v1"); v == "done" {
		return nil
	}
	type rule struct {
		name     string
		target   string // tool_name | tool_input
		typ      string // string | regex
		pattern  string
		action   string
		message  string
		priority int
	}
	rules := []rule{
		// ── 系统破坏性命令 (priority 100) ──────────────────────────────────
		{
			name:     "[内置] 递归强制删除 rm -rf",
			target:   "tool_input",
			typ:      "regex",
			pattern:  `(?i)\brm\b.{0,80}(?:-[a-z]*r[a-z]*f[a-z]*|-[a-z]*f[a-z]*r[a-z]*|--recursive|--no-preserve-root)`,
			action:   "deny",
			message:  "禁止执行递归强制删除（rm -rf / rm --recursive），可能永久损坏系统或靶机环境",
			priority: 100,
		},
		{
			name:     "[内置] 删除系统关键目录",
			target:   "tool_input",
			typ:      "regex",
			pattern:  `\brm\b[^"'\n]{0,60}["'\s](/|/etc|/bin|/usr|/boot|/var|/lib|/sys|/proc|/dev|/sbin|/root)`,
			action:   "deny",
			message:  "禁止删除系统关键路径",
			priority: 100,
		},
		{
			name:     "[内置] 磁盘格式化 mkfs",
			target:   "tool_input",
			typ:      "regex",
			pattern:  `\bmkfs\b`,
			action:   "deny",
			message:  "禁止格式化磁盘（mkfs）",
			priority: 100,
		},
		{
			name:     "[内置] 覆写磁盘设备 dd",
			target:   "tool_input",
			typ:      "regex",
			pattern:  `\bdd\b[^|\n]{0,100}\bof=\s*/dev/[a-zA-Z]`,
			action:   "deny",
			message:  "禁止使用 dd 覆写磁盘设备",
			priority: 100,
		},
		{
			name:     "[内置] Fork 炸弹",
			target:   "tool_input",
			typ:      "regex",
			pattern:  `:\(\)\s*\{[^}]*:\|:`,
			action:   "deny",
			message:  "禁止执行 Fork 炸弹",
			priority: 100,
		},
		{
			name:     "[内置] 关机 / 重启",
			target:   "tool_input",
			typ:      "regex",
			pattern:  `\b(?:shutdown|reboot|halt|poweroff|init\s+[06])\b`,
			action:   "deny",
			message:  "禁止执行关机或重启命令",
			priority: 100,
		},
		{
			name:     "[内置] 杀死全部进程",
			target:   "tool_input",
			typ:      "regex",
			pattern:  `\bkill\s+-9\s+-1\b|\bkillall\s+-9\b`,
			action:   "deny",
			message:  "禁止 kill -9 -1 或 killall -9（杀死所有进程）",
			priority: 100,
		},
		{
			name:     "[内置] 磁盘擦除 shred / wipe",
			target:   "tool_input",
			typ:      "regex",
			pattern:  `\b(?:shred|wipe)\b[^|\n]{0,80}/dev/[a-zA-Z]`,
			action:   "deny",
			message:  "禁止对磁盘设备执行 shred/wipe 擦除",
			priority: 100,
		},
		{
			name:     "[内置] 清空防火墙规则",
			target:   "tool_input",
			typ:      "regex",
			pattern:  `\biptables\s+(?:-F|--flush)\b|\bnft\s+flush\s+ruleset\b`,
			action:   "deny",
			message:  "禁止清空防火墙规则（iptables -F / nft flush）",
			priority: 100,
		},
		// ── 数据库破坏性操作 (priority 90) ─────────────────────────────────
		{
			name:     "[内置] SQL DROP DATABASE / TABLE / SCHEMA",
			target:   "tool_input",
			typ:      "regex",
			pattern:  `(?i)\bDROP\s+(?:DATABASE|TABLE|SCHEMA|INDEX|VIEW|TABLESPACE|USER|ROLE)\b`,
			action:   "deny",
			message:  "禁止执行 DROP 操作，可能不可逆地销毁数据库对象",
			priority: 90,
		},
		{
			name:     "[内置] SQL TRUNCATE",
			target:   "tool_input",
			typ:      "regex",
			pattern:  `(?i)\bTRUNCATE\s+(?:TABLE\s+)?\w`,
			action:   "deny",
			message:  "禁止执行 TRUNCATE，可能清空数据表所有数据",
			priority: 90,
		},
		{
			name:     "[内置] MongoDB drop / dropDatabase",
			target:   "tool_input",
			typ:      "regex",
			pattern:  `(?i)\.(?:dropDatabase|dropCollection|drop)\s*\(`,
			action:   "deny",
			message:  "禁止执行 MongoDB drop 操作",
			priority: 90,
		},
		{
			name:     "[内置] Redis FLUSHALL / FLUSHDB",
			target:   "tool_input",
			typ:      "regex",
			pattern:  `(?i)\b(?:FLUSHALL|FLUSHDB)\b`,
			action:   "deny",
			message:  "禁止执行 Redis FLUSHALL / FLUSHDB，可能清空全部缓存数据",
			priority: 90,
		},
		// ── HTTP 破坏性请求 (priority 80) ──────────────────────────────────
		// Agent 发送 DELETE 请求的三种常见方式：
		//   1. curl -X DELETE / --request DELETE（Bash 工具直接执行或写入脚本）
		//   2. Python HTTP 客户端 .delete() 方法
		//   3. JS/通用脚本里的 method: 'DELETE' / method="DELETE"
		{
			name:     "[内置] curl / wget 发送 DELETE 请求",
			target:   "tool_input",
			typ:      "regex",
			pattern:  `(?i)\bcurl\b[^|\n&;"]{0,300}(?:-X\s*DELETE|--request\s+DELETE|-XDELETE)|\bwget\b[^|\n&;"]{0,300}--method[=\s]+DELETE`,
			action:   "deny",
			message:  "禁止通过 curl/wget 发送 HTTP DELETE 请求，可能删除目标系统数据",
			priority: 80,
		},
		{
			name:     "[内置] Python HTTP 客户端 DELETE（requests/httpx/aiohttp）",
			target:   "tool_input",
			typ:      "regex",
			pattern:  `(?i)\b(?:requests|httpx|aiohttp|urllib\.request)\.delete\s*\(|session\.delete\s*\(|client\.delete\s*\(`,
			action:   "deny",
			message:  "禁止使用 Python HTTP 客户端发送 DELETE 请求",
			priority: 80,
		},
		{
			name:     "[内置] 脚本中声明 HTTP DELETE 方法（JS/通用）",
			target:   "tool_input",
			typ:      "regex",
			pattern:  `(?i)axios\.delete\s*\(|method\s*[:=]\s*['"]DELETE['"]`,
			action:   "deny",
			message:  "禁止在脚本中声明并发送 HTTP DELETE 请求",
			priority: 80,
		},
		{
			name:     "[内置] 批量清空 / 清除接口路径",
			target:   "tool_input",
			typ:      "regex",
			pattern:  `(?i)/(?:clear|wipe|flush|purge|truncate|drop|destroy|factory[-_]reset|reset[-_]all)(?:[/?#"'\s]|$)`,
			action:   "deny",
			message:  "禁止调用批量清空或销毁类接口（/clear /wipe /flush /purge 等）",
			priority: 80,
		},
	}
	for _, r := range rules {
		if _, err := d.Exec(`
INSERT INTO intercept_rules(name, enabled, priority, match_target, match_type, pattern, action, message, timeout_enabled, timeout_seconds, timeout_action)
VALUES ($1, true, $2, $3, $4, $5, $6, $7, false, 60, 'deny')
ON CONFLICT DO NOTHING`,
			r.name, r.priority, r.target, r.typ, r.pattern, r.action, r.message,
		); err != nil {
			return fmt.Errorf("rule %q: %w", r.name, err)
		}
	}
	return d.SetSetting("intercept_default_rules_v1", "done")
}

// seedDefaultInterceptRulesV2 migrates the two safety patterns that used to be
// hard-coded in guard.go (destructive shell + data-exfil pipe) into ordinary
// intercept rules. Gated by its own flag so it also lands on DBs that already ran
// v1. Unlike the old guard.go floor, these are plain [内置] rules — the user can
// disable or delete them. The exfil rule ships DISABLED by default (its
// curl/wget/nc pipe pattern mis-fires on legitimate CTF/pentest reverse-shell and
// data-transfer pipes); enable it manually when exfil gating is actually wanted.
func (d *DB) seedDefaultInterceptRulesV2() error {
	if v, _, _ := d.GetSetting("intercept_default_rules_v2"); v == "done" {
		return nil
	}
	rules := []struct {
		name     string
		pattern  string
		action   string
		message  string
		enabled  bool
		priority int
	}{
		{
			name:     "[内置] 破坏性系统命令",
			pattern:  `(?i)\b(rm\s+-rf\s+/|mkfs|dd\s+if=|:\(\)\s*\{|shutdown|reboot|>\s*/dev/sd)`,
			action:   "deny",
			message:  "破坏性命令被拒绝（rm -rf / / mkfs / dd / fork bomb / 关机重启 / 覆写磁盘设备）",
			enabled:  true,
			priority: 100,
		},
		{
			name:     "[内置] 数据外泄管道",
			pattern:  `(?i)(curl|wget|nc|ncat)\b[^|]*\b(\|\s*(curl|wget|nc))`,
			action:   "deny",
			message:  "疑似数据外泄管道被拒绝（命令输出经 curl/wget/nc 外传）",
			enabled:  false,
			priority: 80,
		},
	}
	for _, r := range rules {
		if _, err := d.Exec(`
INSERT INTO intercept_rules(name, enabled, priority, match_target, match_type, pattern, action, message, timeout_enabled, timeout_seconds, timeout_action)
VALUES ($1, $2, $3, 'tool_input', 'regex', $4, $5, $6, false, 60, 'deny')
ON CONFLICT DO NOTHING`,
			r.name, r.enabled, r.priority, r.pattern, r.action, r.message,
		); err != nil {
			return fmt.Errorf("rule %q: %w", r.name, err)
		}
	}
	return d.SetSetting("intercept_default_rules_v2", "done")
}

// seedDefaultInterceptRulesV3 adds the delete-endpoint path rule. The v1 HTTP rules
// only catch the DELETE *method* (curl -X DELETE, requests.delete(, method:'DELETE'),
// and v1's path rule covers only /clear /wipe /flush /purge /truncate /drop /destroy
// /factory-reset /reset-all — so a plain `curl 'http://t/api/user/delete?id=1'` (a
// delete endpoint reached with GET/POST, which is how most web apps expose deletion)
// slipped through every built-in rule. Own flag so it also lands on DBs that already
// ran v1/v2, where editing the v1 seed would have no effect.
//
// The pattern deliberately requires a separator after the verb so /delivery,
// /details, /delta and /delegate do not match, while /deleteAll, /delete_user and
// /delete-user do. destroy is re-covered here because v1's rule does not allow a
// suffix (/destroyAll was missed).
//
// Exported as a package const only so the seeded regex is unit-testable without a DB.
const deleteEndpointPathPattern = `(?i)/(?:(?:delete|remove|unlink|erase|destroy)[-\w]*|del)(?:[/?#"'\s]|$)`

func (d *DB) seedDefaultInterceptRulesV3() error {
	if v, _, _ := d.GetSetting("intercept_default_rules_v3"); v == "done" {
		return nil
	}
	const name = "[内置] 删除类接口路径"
	if _, err := d.Exec(`
INSERT INTO intercept_rules(name, enabled, priority, match_target, match_type, pattern, action, message, timeout_enabled, timeout_seconds, timeout_action)
SELECT $1, true, 80, 'tool_input', 'regex', $2, 'deny', $3, false, 60, 'deny'
WHERE NOT EXISTS (SELECT 1 FROM intercept_rules WHERE name = $1)`,
		name,
		deleteEndpointPathPattern,
		"禁止调用删除类接口（/delete /remove /unlink /erase 等），不论使用哪种 HTTP 方法——多数应用的删除接口用 GET/POST 就能触发，同样会真实删除目标数据",
	); err != nil {
		return fmt.Errorf("rule %q: %w", name, err)
	}
	return d.SetSetting("intercept_default_rules_v3", "done")
}
