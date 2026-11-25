package db

import (
	"bufio"
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"
)

const (
	TaskArchiveFormatVersion       = 3
	TaskArchiveLegacyFormatVersion = 1
	TaskArchiveLLMRecordsPath      = "database/llm_records.ndjson"
	TaskArchiveTablesDir           = "tables"
	recordExportPageSize           = 500
	archiveStreamBufSize           = 64 * 1024
)

// streamableArchiveTables lists task archive tables that may be stored as
// per-table NDJSON files under tables/<table>.ndjson (plus the legacy
// database/llm_records.ndjson path for llm_records). Small structural tables
// (tasks, explorations, finding traffic bindings/snapshots, relations, scopes,
// profiles, owned resources) remain inline in manifest.json.
var streamableArchiveTables = map[string]bool{
	"exploration_nodes":      true,
	"exploration_edges":      true,
	"exploration_anchors":    true,
	"task_constraints":       true,
	"activity":               true,
	"main_requests":          true,
	"task_asset_links":       true,
	"task_deployments":       true,
	"task_deployment_events": true,
	"worker_budgets":         true,
	"worker_budget_events":   true,
	"findings":               true,
	"finding_retests":        true,
	"llm_records":            true,
	"llm_usage":              true,
	"skill_usage":            true,
	"tool_usage":             true,
	"intercept_pending":      true,
	"side_question_sessions": true,
	"side_question_requests": true,
	"assets":                 true,
}

// TaskArchiveTablePath returns the canonical relative package path for a
// streamed NDJSON table file inside a cold task archive.
func TaskArchiveTablePath(table string) string {
	return TaskArchiveTablesDir + "/" + table + ".ndjson"
}

// ValidateTaskArchiveStreamedTables verifies that snapshot's format version and
// StreamedTables/NDJSONTables metadata only reference allowed tables and paths.
func ValidateTaskArchiveStreamedTables(snapshot *TaskArchiveSnapshot) error {
	if snapshot == nil || !IsTaskArchiveFormatSupported(snapshot.FormatVersion) {
		return ErrTaskArchiveFormatMismatch
	}
	if (len(snapshot.StreamedTables) > 0 || len(snapshot.NDJSONTables) > 0) && snapshot.FormatVersion < 2 {
		return fmt.Errorf("%w: unsupported streamed table metadata", ErrTaskArchiveFormatMismatch)
	}
	for table, relPath := range snapshot.StreamedTables {
		if !streamableArchiveTables[table] {
			return fmt.Errorf("%w: unsupported streamed table %q", ErrTaskArchiveFormatMismatch, table)
		}
		validPath := relPath == TaskArchiveTablePath(table) ||
			(table == "llm_records" && relPath == TaskArchiveLLMRecordsPath)
		if !validPath {
			return fmt.Errorf("%w: unsupported streamed table path %q", ErrTaskArchiveFormatMismatch, relPath)
		}
	}
	for table, count := range snapshot.NDJSONTables {
		if !streamableArchiveTables[table] || count < 0 {
			return fmt.Errorf("%w: unsupported ndjson table count %q", ErrTaskArchiveFormatMismatch, table)
		}
		if _, ok := snapshot.StreamedTables[table]; !ok {
			return fmt.Errorf("%w: ndjson table %q missing from streamed_tables", ErrTaskArchiveFormatMismatch, table)
		}
	}
	return nil
}

func IsTaskArchiveFormatSupported(version int) bool {
	return version >= TaskArchiveLegacyFormatVersion && version <= TaskArchiveFormatVersion
}

const (
	ArchiveQueued     = "archive_queued"
	Archiving         = "archiving"
	ArchiveCompacting = "compacting"
	ArchiveFailed     = "archive_failed"
	ArchiveReady      = "ready"
	RestoreQueued     = "restore_queued"
	Restoring         = "restoring"
	RestoreFailed     = "restore_failed"
	DeleteQueued      = "delete_queued"
	Deleting          = "deleting"
	DeleteFailed      = "delete_failed"
)

var (
	ErrTaskArchiveNotFound       = errors.New("task archive not found")
	ErrTaskArchiveIneligible     = errors.New("task must be paused or terminal before archiving")
	ErrTaskArchiveQueued         = errors.New("queued task must be paused before archiving")
	ErrTaskArchiveDependent      = errors.New("task is inherited by a live task")
	ErrTaskArchiveState          = errors.New("task archive state does not allow this operation")
	ErrTaskArchiveDeleteBlocked  = errors.New("task archive is required by another archive")
	ErrTaskArchiveFormatMismatch = errors.New("task archive format is not supported")
)

// TaskArchive is the compact PostgreSQL record retained while a task is cold.
// Sensitive profile configuration and API keys are intentionally absent.
type TaskArchive struct {
	ID                      int64           `json:"id"`
	TaskID                  int64           `json:"task_id"`
	State                   string          `json:"state"`
	Phase                   string          `json:"phase"`
	Progress                int             `json:"progress"`
	Error                   string          `json:"error,omitempty"`
	Warnings                json.RawMessage `json:"warnings"`
	FormatVersion           int             `json:"format_version"`
	ArchivePath             string          `json:"-"`
	SHA256                  string          `json:"sha256,omitempty"`
	OriginalSize            int64           `json:"original_size"`
	CompressedSize          int64           `json:"compressed_size"`
	TaskName                string          `json:"task_name"`
	TaskDescription         string          `json:"task_description"`
	TaskGoal                string          `json:"task_goal"`
	OriginalStatus          string          `json:"original_status"`
	CategoryIDSnapshot      *int64          `json:"category_id,omitempty"`
	CategoryNameSnapshot    string          `json:"category_name,omitempty"`
	SourceTaskIDs           []int64         `json:"source_task_ids"`
	RemainingTimeoutSeconds int64           `json:"remaining_timeout_seconds"`
	DataCounts              json.RawMessage `json:"data_counts"`
	AggregateStats          json.RawMessage `json:"aggregate_stats"`
	ArchivedAt              *time.Time      `json:"archived_at,omitempty"`
	RequestedAt             time.Time       `json:"requested_at"`
	CreatedAt               time.Time       `json:"created_at"`
	UpdatedAt               time.Time       `json:"updated_at"`
}

// TaskArchiveBlockers returns one live direct dependent for every source task
// that cannot currently be archived. Dependents already queued for archiving do
// not block their source because the FIFO worker will compact them first.
func (d *DB) TaskArchiveBlockers() (map[int64]int64, error) {
	rows, err := d.Query(`SELECT relation.source_task_id, MIN(child.id)
FROM task_relations relation
JOIN tasks child ON child.id=relation.task_id AND child.deleted_at IS NULL
LEFT JOIN task_archives pending ON pending.task_id=child.id
WHERE pending.id IS NULL OR pending.state NOT IN ('archive_queued','archiving','compacting')
GROUP BY relation.source_task_id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	blockers := map[int64]int64{}
	for rows.Next() {
		var sourceID, dependentID int64
		if err := rows.Scan(&sourceID, &dependentID); err != nil {
			return nil, err
		}
		blockers[sourceID] = dependentID
	}
	return blockers, rows.Err()
}

type TaskArchivePage struct {
	Items []TaskArchive `json:"items"`
	Total int           `json:"total"`
	Page  int           `json:"page"`
	Size  int           `json:"size"`
}

// TaskArchiveSnapshot is serialized into manifest.json inside the cold package.
// Small tables remain JSON arrays in Tables. Large tables are streamed to
// per-table NDJSON files listed in StreamedTables (with row counts in
// NDJSONTables) so their size is not bounded by memory.
type TaskArchiveSnapshot struct {
	FormatVersion     int                        `json:"format_version"`
	CreatedAt         time.Time                  `json:"created_at"`
	TaskID            int64                      `json:"task_id"`
	ExplorationID     int64                      `json:"exploration_id"`
	SourceTaskIDs     []int64                    `json:"source_task_ids"`
	Hosts             []string                   `json:"hosts"`
	ExclusiveHosts    []string                   `json:"exclusive_hosts"`
	ExclusiveAssetIDs []int64                    `json:"exclusive_asset_ids"`
	Tables            map[string]json.RawMessage `json:"tables"`
	StreamedTables    map[string]string          `json:"streamed_tables,omitempty"`
	NDJSONTables      map[string]int64           `json:"ndjson_tables,omitempty"`
	DataCounts        map[string]int64           `json:"data_counts"`
	AggregateStats    map[string]any             `json:"aggregate_stats"`
}

func scanTaskArchive(sc interface{ Scan(...any) error }) (*TaskArchive, error) {
	var item TaskArchive
	var sources string
	err := sc.Scan(
		&item.ID, &item.TaskID, &item.State, &item.Phase, &item.Progress, &item.Error,
		&item.Warnings, &item.FormatVersion, &item.ArchivePath, &item.SHA256,
		&item.OriginalSize, &item.CompressedSize, &item.TaskName, &item.TaskDescription,
		&item.TaskGoal, &item.OriginalStatus, &item.CategoryIDSnapshot,
		&item.CategoryNameSnapshot, &sources, &item.RemainingTimeoutSeconds,
		&item.DataCounts, &item.AggregateStats, &item.ArchivedAt, &item.RequestedAt,
		&item.CreatedAt, &item.UpdatedAt,
	)
	if err != nil {
		return nil, err
	}
	if err := json.Unmarshal([]byte(sources), &item.SourceTaskIDs); err != nil {
		return nil, err
	}
	if len(item.Warnings) == 0 {
		item.Warnings = json.RawMessage("[]")
	}
	if len(item.DataCounts) == 0 {
		item.DataCounts = json.RawMessage("{}")
	}
	if len(item.AggregateStats) == 0 {
		item.AggregateStats = json.RawMessage("{}")
	}
	return &item, nil
}

const taskArchiveCols = `id, task_id, state, phase, progress, COALESCE(error,''), warnings,
format_version, COALESCE(archive_path,''), COALESCE(sha256,''), original_size,
compressed_size, COALESCE(task_name,''), COALESCE(task_description,''),
COALESCE(task_goal,''), COALESCE(original_status,''), category_id_snapshot,
COALESCE(category_name_snapshot,''), array_to_json(source_task_ids)::text,
remaining_timeout_seconds, data_counts, aggregate_stats, archived_at,
requested_at, created_at, updated_at`

func (d *DB) GetTaskArchive(id int64) (*TaskArchive, error) {
	item, err := scanTaskArchive(d.QueryRow(`SELECT `+taskArchiveCols+` FROM task_archives WHERE id=$1`, id))
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	return item, err
}

func (d *DB) GetTaskArchiveByTask(taskID int64) (*TaskArchive, error) {
	item, err := scanTaskArchive(d.QueryRow(`SELECT `+taskArchiveCols+` FROM task_archives WHERE task_id=$1`, taskID))
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	return item, err
}

func (d *DB) ListTaskArchives(search, state string, page, size int) (TaskArchivePage, error) {
	if page < 1 {
		page = 1
	}
	if size <= 0 || size > 100 {
		size = 20
	}
	search = strings.TrimSpace(search)
	state = strings.TrimSpace(state)
	where := `WHERE ($1='' OR task_id::text ILIKE '%'||$1||'%' OR task_name ILIKE '%'||$1||'%' OR task_description ILIKE '%'||$1||'%')
AND ($2='' OR state=$2)`
	var out TaskArchivePage
	out.Page, out.Size = page, size
	if err := d.QueryRow(`SELECT count(*) FROM task_archives `+where, search, state).Scan(&out.Total); err != nil {
		return out, err
	}
	rows, err := d.Query(`SELECT `+taskArchiveCols+` FROM task_archives `+where+`
ORDER BY COALESCE(archived_at, requested_at) DESC, id DESC LIMIT $3 OFFSET $4`, search, state, size, (page-1)*size)
	if err != nil {
		return out, err
	}
	defer rows.Close()
	for rows.Next() {
		item, err := scanTaskArchive(rows)
		if err != nil {
			return out, err
		}
		out.Items = append(out.Items, *item)
	}
	return out, rows.Err()
}

// QueueTaskArchive validates lifecycle and direct inheritance while holding the
// task row. A failed archive can be explicitly retried through the same API.
func (d *DB) QueueTaskArchive(taskID int64) (*TaskArchive, error) {
	tx, err := d.Begin()
	if err != nil {
		return nil, err
	}
	defer tx.Rollback() //nolint:errcheck
	var name, description, goal, status, categoryName string
	var categoryID *int64
	var paused, queued bool
	var deadline *time.Time
	err = tx.QueryRow(`SELECT COALESCE(t.name,''), t.description, t.goal, t.status,
 t.category_id, COALESCE(c.name,''), t.paused, t.queued, t.deadline_at
FROM tasks t LEFT JOIN task_categories c ON c.id=t.category_id
WHERE t.id=$1 AND t.deleted_at IS NULL FOR UPDATE OF t`, taskID).Scan(
		&name, &description, &goal, &status, &categoryID, &categoryName, &paused, &queued, &deadline,
	)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrTaskArchiveNotFound
	}
	if err != nil {
		return nil, err
	}
	if queued {
		return nil, ErrTaskArchiveQueued
	}
	if !paused && !IsTerminal(status) {
		return nil, ErrTaskArchiveIneligible
	}
	var dependent int64
	err = tx.QueryRow(`SELECT child.id FROM task_relations relation
JOIN tasks child ON child.id=relation.task_id AND child.deleted_at IS NULL
LEFT JOIN task_archives pending ON pending.task_id=child.id
WHERE relation.source_task_id=$1
  AND (pending.id IS NULL OR pending.state NOT IN ('archive_queued','archiving','compacting'))
LIMIT 1`, taskID).Scan(&dependent)
	if err == nil {
		return nil, fmt.Errorf("%w: task %d", ErrTaskArchiveDependent, dependent)
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return nil, err
	}
	var sources []int64
	rows, err := tx.Query(`SELECT source_task_id FROM task_relations WHERE task_id=$1 ORDER BY created_at, source_task_id`, taskID)
	if err != nil {
		return nil, err
	}
	for rows.Next() {
		var id int64
		if err := rows.Scan(&id); err != nil {
			rows.Close()
			return nil, err
		}
		sources = append(sources, id)
	}
	if err := rows.Close(); err != nil {
		return nil, err
	}
	if sources == nil {
		sources = []int64{}
	}
	remaining := int64(0)
	if paused && deadline != nil {
		remaining = int64(time.Until(*deadline).Seconds())
		if remaining < 0 {
			remaining = 0
		}
	}
	_, err = tx.Exec(`INSERT INTO task_archives(
 task_id,state,phase,progress,error,warnings,format_version,task_name,
 task_description,task_goal,original_status,category_id_snapshot,
 category_name_snapshot,source_task_ids,remaining_timeout_seconds,requested_at)
VALUES ($1,$2,'queued',0,'','[]',$3,$4,$5,$6,$7,$8,$9,$10,$11,now())
	ON CONFLICT (task_id) DO UPDATE SET
	 state=CASE WHEN task_archives.state IN ('archive_failed') THEN EXCLUDED.state ELSE task_archives.state END,
	 phase=CASE WHEN task_archives.state IN ('archive_failed') THEN 'queued' ELSE task_archives.phase END,
	 progress=CASE WHEN task_archives.state IN ('archive_failed') THEN 0 ELSE task_archives.progress END,
	 error=CASE WHEN task_archives.state IN ('archive_failed') THEN '' ELSE task_archives.error END,
	 format_version=CASE WHEN task_archives.state IN ('archive_failed') THEN EXCLUDED.format_version ELSE task_archives.format_version END,
	 requested_at=CASE WHEN task_archives.state IN ('archive_failed') THEN now() ELSE task_archives.requested_at END`,
		taskID, ArchiveQueued, TaskArchiveFormatVersion, name, description, goal, status,
		categoryID, categoryName, sources, remaining)
	if err != nil {
		return nil, err
	}
	item, err := scanTaskArchive(tx.QueryRow(`SELECT `+taskArchiveCols+` FROM task_archives WHERE task_id=$1`, taskID))
	if err != nil {
		return nil, err
	}
	if item.State != ArchiveQueued && item.State != ArchiveFailed {
		return nil, fmt.Errorf("%w: current state %s", ErrTaskArchiveState, item.State)
	}
	return item, tx.Commit()
}

func (d *DB) QueueTaskArchiveRestore(id int64) (*TaskArchive, error) {
	item, err := scanTaskArchive(d.QueryRow(`UPDATE task_archives
SET state=$2, phase='queued', progress=0, error='', requested_at=now()
WHERE id=$1 AND state IN ('ready','restore_failed') RETURNING `+taskArchiveCols, id, RestoreQueued))
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrTaskArchiveState
	}
	return item, err
}

func (d *DB) QueueTaskArchiveDelete(id int64) (*TaskArchive, error) {
	tx, err := d.Begin()
	if err != nil {
		return nil, err
	}
	defer tx.Rollback() //nolint:errcheck
	var taskID int64
	if err := tx.QueryRow(`SELECT task_id FROM task_archives WHERE id=$1 AND state IN ('ready','delete_failed') FOR UPDATE`, id).Scan(&taskID); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrTaskArchiveState
		}
		return nil, err
	}
	var dependent int64
	err = tx.QueryRow(`SELECT task_id FROM task_archives
WHERE id<>$1 AND source_task_ids @> ARRAY[$2]::bigint[] AND state NOT IN ('delete_queued','deleting') LIMIT 1`, id, taskID).Scan(&dependent)
	if err == nil {
		return nil, fmt.Errorf("%w: task %d", ErrTaskArchiveDeleteBlocked, dependent)
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return nil, err
	}
	item, err := scanTaskArchive(tx.QueryRow(`UPDATE task_archives
SET state=$2, phase='queued', progress=0, error='', requested_at=now()
WHERE id=$1 RETURNING `+taskArchiveCols, id, DeleteQueued))
	if err != nil {
		return nil, err
	}
	return item, tx.Commit()
}

// recoverTaskArchiveJobsSQL resets interrupted jobs after an unclean shutdown.
// Rows already past Phase 1 compaction (state='compacting', or legacy
// state='archiving' with phase='compact_rows' and a tombstoned unarchived task)
// are never downgraded to archive_failed — they stay/become 'compacting' so
// ResumeCompactingTaskArchives can finish Phase 2->3 cleanly.
const recoverTaskArchiveJobsSQL = `UPDATE task_archives a SET
	 state = CASE
	     WHEN a.state = 'archiving' AND a.phase = 'compact_rows'
	          AND EXISTS (
	              SELECT 1 FROM tasks t
	              WHERE t.id = a.task_id AND t.deleted_at IS NOT NULL AND t.archived_at IS NULL
	          ) THEN 'compacting'
	     WHEN a.state = 'archiving' THEN 'archive_failed'
	     WHEN a.state = 'restoring' THEN 'restore_queued'
	     WHEN a.state = 'deleting' THEN 'delete_queued'
	     ELSE a.state
	 END,
	 phase = CASE
	     WHEN a.state = 'archiving' AND a.phase = 'compact_rows'
	          AND EXISTS (
	              SELECT 1 FROM tasks t
	              WHERE t.id = a.task_id AND t.deleted_at IS NOT NULL AND t.archived_at IS NULL
	          ) THEN a.phase
	     ELSE 'interrupted'
	 END,
	 error = CASE
	     WHEN a.state = 'archiving' AND NOT (
	          a.phase = 'compact_rows'
	          AND EXISTS (
	              SELECT 1 FROM tasks t
	              WHERE t.id = a.task_id AND t.deleted_at IS NOT NULL AND t.archived_at IS NULL
	          )
	     ) THEN '上次归档进程异常退出，请手动重试'
	     ELSE ''
	 END
	WHERE a.state IN ('archiving','restoring','deleting')`

// RecoverTaskArchiveJobs keeps restore/delete/compacting jobs resumable after
// an unclean shutdown. An interrupted pre-Phase-1 archive requires an explicit
// retry: automatic startup retries can otherwise form a crash loop when the
// prior process was killed by resource limits.
func (d *DB) RecoverTaskArchiveJobs() error {
	_, err := d.Exec(recoverTaskArchiveJobsSQL)
	return err
}

// ClaimTaskArchiveJob claims one persistent FIFO item for the single archive
// worker. It returns nil when the queue is empty.
func (d *DB) ClaimTaskArchiveJob(ctx context.Context) (*TaskArchive, error) {
	tx, err := d.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback() //nolint:errcheck
	var id int64
	var queuedState string
	err = tx.QueryRowContext(ctx, `SELECT id,state FROM task_archives
WHERE state IN ('archive_queued','restore_queued','delete_queued')
ORDER BY requested_at,id FOR UPDATE SKIP LOCKED LIMIT 1`).Scan(&id, &queuedState)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	active := map[string]string{ArchiveQueued: Archiving, RestoreQueued: Restoring, DeleteQueued: Deleting}[queuedState]
	item, err := scanTaskArchive(tx.QueryRowContext(ctx, `UPDATE task_archives
SET state=$2,phase='starting',progress=1,error='' WHERE id=$1 RETURNING `+taskArchiveCols, id, active))
	if err != nil {
		return nil, err
	}
	return item, tx.Commit()
}

func (d *DB) UpdateTaskArchiveProgress(id int64, phase string, progress int) error {
	if progress < 0 {
		progress = 0
	}
	if progress > 100 {
		progress = 100
	}
	_, err := d.Exec(`UPDATE task_archives SET phase=$2,progress=$3 WHERE id=$1`, id, phase, progress)
	return err
}

func (d *DB) AppendTaskArchiveWarning(id int64, warning string) error {
	if strings.TrimSpace(warning) == "" {
		return nil
	}
	_, err := d.Exec(`UPDATE task_archives SET warnings=warnings || jsonb_build_array($2::text) WHERE id=$1`, id, warning)
	return err
}

func (d *DB) IsTaskArchiveRestored(id int64) (bool, error) {
	var restored bool
	err := d.QueryRow(`SELECT task.deleted_at IS NULL AND task.archived_at IS NULL
FROM task_archives archive JOIN tasks task ON task.id=archive.task_id WHERE archive.id=$1`, id).Scan(&restored)
	if errors.Is(err, sql.ErrNoRows) {
		return false, ErrTaskArchiveNotFound
	}
	return restored, err
}

const failTaskArchiveJobSQL = `UPDATE task_archives SET
 state = CASE WHEN state = $4 THEN state ELSE $2 END,
 phase = CASE WHEN state = $4 THEN phase ELSE 'failed' END,
 error = $3
WHERE id = $1`

func (d *DB) FailTaskArchiveJob(id int64, activeState string, cause error) error {
	failed := map[string]string{
		Archiving:         ArchiveFailed,
		ArchiveCompacting: ArchiveCompacting,
		Restoring:         RestoreFailed,
		Deleting:          DeleteFailed,
	}[activeState]
	if failed == "" {
		return fmt.Errorf("unknown active archive state %q", activeState)
	}
	message := "unknown archive failure"
	if cause != nil {
		message = cause.Error()
	}
	_, err := d.Exec(failTaskArchiveJobSQL, id, failed, message, ArchiveCompacting)
	return err
}

func queryArchiveRows(q interface {
	Query(query string, args ...any) (*sql.Rows, error)
}, inner string, args ...any) (json.RawMessage, int64, error) {
	// Do not aggregate the result in PostgreSQL. A jsonb array has a hard limit
	// of 256 MiB for its elements, which large LLM request/response histories can
	// exceed even though every individual record is valid. Reading row JSON in
	// order also avoids building a second copy of the full table in PostgreSQL.
	rows, err := q.Query(`SELECT row_to_json(row_data)::text FROM (`+inner+`) row_data`, args...)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()
	return encodeArchiveRows(rows)
}

func encodeArchiveRows(rows interface {
	Next() bool
	Scan(dest ...any) error
	Err() error
}) (json.RawMessage, int64, error) {
	var output bytes.Buffer
	output.WriteByte('[')
	var count int64
	for rows.Next() {
		var raw []byte
		if err := rows.Scan(&raw); err != nil {
			return nil, 0, err
		}
		if count > 0 {
			output.WriteByte(',')
		}
		output.Write(raw)
		count++
	}
	if err := rows.Err(); err != nil {
		return nil, 0, err
	}
	output.WriteByte(']')
	return json.RawMessage(output.Bytes()), count, nil
}

func writeArchiveRows(rows interface {
	Next() bool
	Scan(dest ...any) error
	Err() error
}, writer io.Writer) (int64, error) {
	var count int64
	for rows.Next() {
		var raw []byte
		if err := rows.Scan(&raw); err != nil {
			return 0, err
		}
		if written, err := writer.Write(raw); err != nil {
			return 0, err
		} else if written != len(raw) {
			return 0, io.ErrShortWrite
		}
		if written, err := io.WriteString(writer, "\n"); err != nil {
			return 0, err
		} else if written != 1 {
			return 0, io.ErrShortWrite
		}
		count++
	}
	if err := rows.Err(); err != nil {
		return 0, err
	}
	return count, nil
}

func streamArchiveRows(q interface {
	Query(query string, args ...any) (*sql.Rows, error)
}, writer io.Writer, inner string, args ...any) (int64, error) {
	rows, err := q.Query(`SELECT row_to_json(row_data)::text FROM (`+inner+`) row_data`, args...)
	if err != nil {
		return 0, err
	}
	defer rows.Close()
	return writeArchiveRows(rows, writer)
}

func rawRowCount(raw json.RawMessage) int64 {
	trimmed := bytes.TrimSpace(raw)
	if len(trimmed) == 0 || bytes.Equal(trimmed, []byte("[]")) || bytes.Equal(trimmed, []byte("null")) {
		return 0
	}
	dec := json.NewDecoder(bytes.NewReader(trimmed))
	tok, err := dec.Token()
	if err != nil {
		return 0
	}
	if delim, ok := tok.(json.Delim); !ok || delim != '[' {
		return 0
	}
	var count int64
	for dec.More() {
		if err := skipArchiveJSONValue(dec); err != nil {
			return 0
		}
		count++
	}
	tok, err = dec.Token()
	if err != nil {
		return 0
	}
	if delim, ok := tok.(json.Delim); !ok || delim != ']' {
		return 0
	}
	return count
}

func skipArchiveJSONValue(dec *json.Decoder) error {
	tok, err := dec.Token()
	if err != nil {
		return err
	}
	delim, ok := tok.(json.Delim)
	if !ok || (delim != '{' && delim != '[') {
		return nil
	}
	depth := 1
	for depth > 0 {
		t, err := dec.Token()
		if err != nil {
			return err
		}
		if d, ok := t.(json.Delim); ok {
			switch d {
			case '{', '[':
				depth++
			case '}', ']':
				depth--
			}
		}
	}
	return nil
}

func archiveAssetIDsQuery() string {
	return `SELECT id FROM assets WHERE task_ids @> ARRAY[$1]::bigint[]
UNION SELECT link.asset_id FROM task_asset_links link WHERE link.task_id=$1
UNION SELECT anchor.asset_id FROM exploration_anchors anchor
      JOIN exploration_nodes node ON node.id=anchor.node_id WHERE node.exploration_id=$2
UNION SELECT value::bigint FROM findings finding
      CROSS JOIN LATERAL jsonb_array_elements_text(
        CASE WHEN jsonb_typeof(finding.asset_ids)='array' THEN finding.asset_ids ELSE '[]'::jsonb END
      ) value WHERE finding.task_id=$1 AND value ~ '^[0-9]+$'`
}

// SnapshotTaskArchive reads one repeatable PostgreSQL snapshot. Task-owned Agent
// writes are already quiescent at the server barrier; repeatable-read also keeps
// the asset and accounting views mutually consistent during serialization.
func (d *DB) SnapshotTaskArchive(taskID int64) (*TaskArchiveSnapshot, error) {
	return d.snapshotTaskArchive(taskID, nil, nil)
}

// SnapshotTaskArchiveWithLLMRecords streams the heavyweight record history to
// llmRecords while all other task-owned data is read from the same repeatable
// PostgreSQL snapshot.
func (d *DB) SnapshotTaskArchiveWithLLMRecords(taskID int64, llmRecords io.Writer) (*TaskArchiveSnapshot, error) {
	if llmRecords == nil {
		return nil, errors.New("nil LLM record archive writer")
	}
	return d.snapshotTaskArchive(taskID, llmRecords, nil)
}

// SnapshotTaskArchiveStreamed streams every large task-owned table to per-table
// NDJSON files via tableSink (receiving table name and canonical relative path
// "tables/<table>.ndjson") while keeping compact structural tables and counts in
// the returned snapshot.
func (d *DB) SnapshotTaskArchiveStreamed(
	taskID int64,
	tableSink func(table, relPath string) (io.WriteCloser, error),
) (*TaskArchiveSnapshot, error) {
	if tableSink == nil {
		return nil, errors.New("nil task archive table sink")
	}
	return d.snapshotTaskArchive(taskID, nil, tableSink)
}

func (d *DB) snapshotTaskArchive(
	taskID int64,
	llmRecords io.Writer,
	tableSink func(table, relPath string) (io.WriteCloser, error),
) (*TaskArchiveSnapshot, error) {
	tx, err := d.BeginTx(context.Background(), &sql.TxOptions{Isolation: sql.LevelRepeatableRead, ReadOnly: true})
	if err != nil {
		return nil, err
	}
	defer tx.Rollback() //nolint:errcheck
	if err := SetMaintenanceTimeouts(context.Background(), tx); err != nil {
		return nil, err
	}
	if err := coordinateWithSchemaMigration(tx); err != nil {
		return nil, err
	}
	snapshot, err := d.snapshotTaskRows(tx, taskID, llmRecords, tableSink)
	if err != nil {
		return nil, err
	}
	return snapshot, tx.Commit()
}

// snapshotTaskRows snapshots a quiescent task for cold archiving. When
// tableSink is provided, every streamableArchiveTables entry is streamed to its
// NDJSON sink instead of being buffered into manifest.json.
func (d *DB) snapshotTaskRows(
	tx *sql.Tx,
	taskID int64,
	llmRecords io.Writer,
	tableSink func(table, relPath string) (io.WriteCloser, error),
) (*TaskArchiveSnapshot, error) {
	var expID int64
	if err := tx.QueryRow(`SELECT exploration_id FROM tasks WHERE id=$1 AND deleted_at IS NULL`, taskID).Scan(&expID); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrTaskArchiveNotFound
		}
		return nil, err
	}
	tables := make(map[string]json.RawMessage)
	queries := []struct {
		name  string
		query string
		args  []any
	}{
		{"tasks", `SELECT * FROM tasks WHERE id=$1`, []any{taskID}},
		{"explorations", `SELECT * FROM explorations WHERE id=$1`, []any{expID}},
		{"exploration_nodes", `SELECT * FROM exploration_nodes WHERE exploration_id=$1 ORDER BY id`, []any{expID}},
		{"exploration_edges", `SELECT * FROM exploration_edges WHERE exploration_id=$1 ORDER BY src_id,rel,dst_id`, []any{expID}},
		{"exploration_anchors", `SELECT anchor.* FROM exploration_anchors anchor JOIN exploration_nodes node ON node.id=anchor.node_id WHERE node.exploration_id=$1 ORDER BY node_id,asset_id`, []any{expID}},
		{"task_constraints", `SELECT * FROM task_constraints WHERE exploration_id=$1 ORDER BY id`, []any{expID}},
		{"activity", `SELECT * FROM activity WHERE exploration_id=$1 ORDER BY id`, []any{expID}},
		{"main_requests", `SELECT * FROM main_requests WHERE exploration_id=$1 ORDER BY id`, []any{expID}},
		{"task_relations", `SELECT * FROM task_relations WHERE task_id=$1 ORDER BY created_at,source_task_id`, []any{taskID}},
		{"task_asset_links", `SELECT * FROM task_asset_links WHERE task_id=$1 ORDER BY asset_id`, []any{taskID}},
		{"task_llm_profiles", `SELECT * FROM task_llm_profiles WHERE task_id=$1 ORDER BY position`, []any{taskID}},
		{"task_scope", `SELECT * FROM task_scope WHERE task_id=$1 ORDER BY id`, []any{taskID}},
		{"task_owned_resources", `SELECT * FROM task_owned_resources WHERE task_id=$1 ORDER BY resource_id`, []any{taskID}},
		// Keep the live ledger during archive compaction: pending cleanup must
		// still block resource deletion. Include its history in the package too.
		{"task_deployments", `SELECT * FROM task_deployments WHERE task_id=$1 ORDER BY id`, []any{taskID}},
		{"task_deployment_events", `SELECT * FROM task_deployment_events WHERE task_id=$1 ORDER BY id`, []any{taskID}},
		{"worker_budgets", `SELECT * FROM worker_budgets WHERE task_id=$1 ORDER BY intent_id`, []any{taskID}},
		{"worker_budget_events", `SELECT * FROM worker_budget_events WHERE task_id=$1 ORDER BY id`, []any{taskID}},
		{"findings", `SELECT * FROM findings WHERE task_id=$1 ORDER BY id`, []any{taskID}},
		{"finding_retests", `SELECT r.* FROM finding_retests r JOIN findings f ON f.id=r.finding_id WHERE f.task_id=$1 ORDER BY r.id`, []any{taskID}},
		{"finding_traffic_bindings", `SELECT b.* FROM finding_traffic_bindings b JOIN findings f ON f.id=b.finding_id WHERE f.task_id=$1 ORDER BY b.finding_id,b.position,b.id`, []any{taskID}},
		{"traffic_evidence_snapshots", `SELECT s.* FROM traffic_evidence_snapshots s WHERE EXISTS(SELECT 1 FROM finding_traffic_bindings b JOIN findings f ON f.id=b.finding_id WHERE b.snapshot_id=s.id AND f.task_id=$1) ORDER BY s.id`, []any{taskID}},
		{"llm_records", `SELECT * FROM llm_records WHERE task_id=$1 ORDER BY id`, []any{strconv.FormatInt(taskID, 10)}},
		{"llm_usage", `SELECT * FROM llm_usage WHERE task_id=$1 OR exploration_id=$2 ORDER BY id`, []any{strconv.FormatInt(taskID, 10), expID}},
		{"skill_usage", `SELECT * FROM skill_usage WHERE task_id=$1 OR exploration_id=$2 ORDER BY id`, []any{taskID, expID}},
		{"tool_usage", `SELECT * FROM tool_usage WHERE task_id=$1 OR exploration_id=$2 ORDER BY id`, []any{taskID, expID}},
		{"intercept_pending", `SELECT * FROM intercept_pending WHERE task_id=$1 ORDER BY id`, []any{strconv.FormatInt(taskID, 10)}},
		{"side_question_sessions", `SELECT * FROM side_question_sessions WHERE task_id=$1 ORDER BY session_key`, []any{taskID}},
		{"side_question_requests", `SELECT r.* FROM side_question_requests r JOIN side_question_sessions s ON s.session_key=r.session_key WHERE s.task_id=$1 ORDER BY r.ordinal`, []any{taskID}},
		{"assets", `SELECT asset.* FROM assets asset WHERE asset.id IN (` + archiveAssetIDsQuery() + `) ORDER BY asset.id`, []any{taskID, expID}},
	}
	counts := make(map[string]int64, len(queries))
	streamedTables := map[string]string{}
	ndjsonTables := map[string]int64{}

	for _, query := range queries {
		if tableSink != nil && streamableArchiveTables[query.name] {
			relPath := TaskArchiveTablePath(query.name)
			writer, err := tableSink(query.name, relPath)
			if err != nil {
				return nil, fmt.Errorf("snapshot %s: %w", query.name, err)
			}
			bw := bufio.NewWriterSize(writer, archiveStreamBufSize)
			count, streamErr := streamArchiveRows(tx, bw, query.query, query.args...)
			var flushErr error
			if streamErr == nil {
				flushErr = bw.Flush()
			}
			closeErr := writer.Close()
			if err := errors.Join(streamErr, flushErr, closeErr); err != nil {
				return nil, fmt.Errorf("snapshot %s: %w", query.name, err)
			}
			tables[query.name] = json.RawMessage("[]")
			counts[query.name] = count
			streamedTables[query.name] = relPath
			ndjsonTables[query.name] = count
			continue
		}
		if query.name == "llm_records" && llmRecords != nil {
			count, err := streamArchiveRows(tx, llmRecords, query.query, query.args...)
			if err != nil {
				return nil, fmt.Errorf("snapshot %s: %w", query.name, err)
			}
			tables[query.name] = json.RawMessage("[]")
			counts[query.name] = count
			streamedTables[query.name] = TaskArchiveLLMRecordsPath
			continue
		}
		raw, count, err := queryArchiveRows(tx, query.query, query.args...)
		if err != nil {
			return nil, fmt.Errorf("snapshot %s: %w", query.name, err)
		}
		tables[query.name] = raw
		counts[query.name] = count
	}

	exclusiveAssetIDs, hosts, exclusiveHosts, err := archiveAssetMetadata(tx, taskID, expID)
	if err != nil {
		return nil, err
	}
	var sources []int64
	rows, err := tx.Query(`SELECT source_task_id FROM task_relations WHERE task_id=$1 ORDER BY created_at,source_task_id`, taskID)
	if err != nil {
		return nil, err
	}
	for rows.Next() {
		var id int64
		if err := rows.Scan(&id); err != nil {
			rows.Close()
			return nil, err
		}
		sources = append(sources, id)
	}
	if err := rows.Close(); err != nil {
		return nil, err
	}
	stats, err := taskArchiveAggregates(tx, taskID, expID)
	if err != nil {
		return nil, err
	}
	snapshot := &TaskArchiveSnapshot{
		FormatVersion: TaskArchiveFormatVersion, CreatedAt: time.Now().UTC(), TaskID: taskID,
		ExplorationID: expID, SourceTaskIDs: sources, Hosts: hosts, ExclusiveHosts: exclusiveHosts,
		ExclusiveAssetIDs: exclusiveAssetIDs, Tables: tables, StreamedTables: streamedTables,
		NDJSONTables: ndjsonTables, DataCounts: counts, AggregateStats: stats,
	}
	return snapshot, nil
}

type recordExportTableSnapshot struct {
	name  string
	data  []byte
	count int64
}

type recordExportCutoffs struct {
	taskID              int64
	expID               int64
	smallTables         []recordExportTableSnapshot
	maxNodeID           int64
	maxConstraintID     int64
	maxActivityID       int64
	maxMainRequestID    int64
	maxTaskAssetID      int64
	maxDeployEventID    int64
	maxBudgetEventID   int64
	maxFindingID       int64
	maxFindingRetestID int64
	maxLLMRecordID     int64
	maxLLMUsageID       int64
	maxSkillUsageID     int64
	maxToolUsageID      int64
	maxInterceptID      int64
	maxSideRequestOrd   int64
	maxAssetID          int64
	maxResourceEventID  int64
}

// SnapshotTaskRecords exports multiple tasks including raw LLM records and
// lifecycle history without pinning PostgreSQL MVCC xmin for the export's
// duration. A brief read-only repeatable-read transaction captures small
// metadata tables plus integer MAX(id) cutoffs across all requested tasks and
// commits immediately; large tables are then streamed outside any transaction
// in 500-row keyset-paginated queries directly to sink.
func (d *DB) SnapshotTaskRecords(ctx context.Context, ids []int64, sink func(int64, string) (io.WriteCloser, error)) ([]*TaskArchiveSnapshot, error) {
	if len(ids) == 0 {
		return []*TaskArchiveSnapshot{}, nil
	}
	cutoff, plans, err := d.prepareRecordExportCutoffs(ctx, ids)
	if err != nil {
		return nil, err
	}

	out := make([]*TaskArchiveSnapshot, 0, len(plans))
	for _, plan := range plans {
		snapshot, err := d.streamRecordExportPlan(ctx, plan, cutoff, sink)
		if err != nil {
			return nil, err
		}
		out = append(out, snapshot)
	}
	return out, nil
}

func (d *DB) prepareRecordExportCutoffs(ctx context.Context, ids []int64) (time.Time, []recordExportCutoffs, error) {
	tx, err := d.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelRepeatableRead, ReadOnly: true})
	if err != nil {
		return time.Time{}, nil, err
	}
	defer tx.Rollback() //nolint:errcheck
	if err = SetMaintenanceTimeouts(ctx, tx); err != nil {
		return time.Time{}, nil, err
	}
	if err = coordinateWithSchemaMigration(tx); err != nil {
		return time.Time{}, nil, err
	}
	var cutoff time.Time
	if err = tx.QueryRowContext(ctx, `SELECT transaction_timestamp()`).Scan(&cutoff); err != nil {
		return time.Time{}, nil, err
	}

	plans := make([]recordExportCutoffs, 0, len(ids))
	for _, taskID := range ids {
		var expID int64
		if err := tx.QueryRowContext(ctx, `SELECT exploration_id FROM tasks WHERE id=$1 AND deleted_at IS NULL`, taskID).Scan(&expID); err != nil {
			if errors.Is(err, sql.ErrNoRows) {
				return time.Time{}, nil, ErrTaskArchiveNotFound
			}
			return time.Time{}, nil, err
		}
		taskIDStr := strconv.FormatInt(taskID, 10)
		plan := recordExportCutoffs{taskID: taskID, expID: expID}

		// Snapshot small, potentially mutable metadata tables inside the brief
		// repeatable-read view so cross-task metadata remains mutually consistent.
		resourceIDs := `SELECT resource_id FROM task_owned_resources WHERE task_id=$1 UNION SELECT resource_id FROM task_deployments WHERE task_id=$1 AND resource_id IS NOT NULL UNION SELECT id FROM owned_resources WHERE creator_task_id=$1`
		smallQueries := []struct {
			name  string
			query string
			args  []any
		}{
			{"tasks", `SELECT * FROM tasks WHERE id=$1`, []any{taskID}},
			{"explorations", `SELECT * FROM explorations WHERE id=$1`, []any{expID}},
			{"task_relations", `SELECT * FROM task_relations WHERE task_id=$1 ORDER BY created_at,source_task_id`, []any{taskID}},
			{"task_llm_profiles", `SELECT * FROM task_llm_profiles WHERE task_id=$1 ORDER BY position`, []any{taskID}},
			{"task_scope", `SELECT * FROM task_scope WHERE task_id=$1 ORDER BY id`, []any{taskID}},
			{"task_owned_resources", `SELECT * FROM task_owned_resources WHERE task_id=$1 ORDER BY resource_id`, []any{taskID}},
			{"task_deployments", `SELECT * FROM task_deployments WHERE task_id=$1 ORDER BY id`, []any{taskID}},
			{"worker_budgets", `SELECT * FROM worker_budgets WHERE task_id=$1 ORDER BY intent_id`, []any{taskID}},
			{"finding_traffic_bindings", `SELECT b.* FROM finding_traffic_bindings b JOIN findings f ON f.id=b.finding_id WHERE f.task_id=$1 ORDER BY b.finding_id,b.position,b.id`, []any{taskID}},
			{"traffic_evidence_snapshots", `SELECT s.* FROM traffic_evidence_snapshots s WHERE EXISTS(SELECT 1 FROM finding_traffic_bindings b JOIN findings f ON f.id=b.finding_id WHERE b.snapshot_id=s.id AND f.task_id=$1) ORDER BY s.id`, []any{taskID}},
			{"side_question_sessions", `SELECT * FROM side_question_sessions WHERE task_id=$1 ORDER BY session_key`, []any{taskID}},
			{"owned_resources", `SELECT id,name,kind,description,tags,access_mode,enabled,revision,creator_task_id,updated_at,deleted_at FROM owned_resources WHERE id IN (` + resourceIDs + `) ORDER BY id`, []any{taskID}},
			{"owned_resource_versions", `SELECT id,resource_id,version,size,manifest,note,validation,actor,created_at FROM owned_resource_versions WHERE id IN(SELECT version_id FROM task_owned_resources WHERE task_id=$1) OR resource_id IN(SELECT id FROM owned_resources WHERE creator_task_id=$1) ORDER BY id`, []any{taskID}},
		}
		plan.smallTables = make([]recordExportTableSnapshot, 0, len(smallQueries))
		for _, q := range smallQueries {
			var buf bytes.Buffer
			count, err := streamArchiveRowsContext(ctx, tx, &buf, q.query, q.args...)
			if err != nil {
				return time.Time{}, nil, fmt.Errorf("snapshot %s: %w", q.name, err)
			}
			plan.smallTables = append(plan.smallTables, recordExportTableSnapshot{
				name:  q.name,
				data:  buf.Bytes(),
				count: count,
			})
		}

		// Record integer MAX cutoffs for all large tables in one fast query so
		// keyset streaming can proceed outside the transaction.
		if err := tx.QueryRowContext(ctx, `SELECT
 COALESCE((SELECT MAX(id) FROM exploration_nodes WHERE exploration_id=$2), 0),
 COALESCE((SELECT MAX(id) FROM task_constraints WHERE exploration_id=$2), 0),
 COALESCE((SELECT MAX(id) FROM activity WHERE exploration_id=$2), 0),
 COALESCE((SELECT MAX(id) FROM main_requests WHERE exploration_id=$2), 0),
 COALESCE((SELECT MAX(asset_id) FROM task_asset_links WHERE task_id=$1), 0),
 COALESCE((SELECT MAX(id) FROM task_deployment_events WHERE task_id=$1), 0),
 COALESCE((SELECT MAX(id) FROM worker_budget_events WHERE task_id=$1), 0),
 COALESCE((SELECT MAX(id) FROM findings WHERE task_id=$1), 0),
 COALESCE((SELECT MAX(r.id) FROM finding_retests r JOIN findings f ON f.id=r.finding_id WHERE f.task_id=$1), 0),
 COALESCE((SELECT MAX(id) FROM llm_records WHERE task_id=$3), 0),
 COALESCE((SELECT MAX(id) FROM llm_usage WHERE task_id=$3 OR exploration_id=$2), 0),
 COALESCE((SELECT MAX(id) FROM skill_usage WHERE task_id=$1 OR exploration_id=$2), 0),
 COALESCE((SELECT MAX(id) FROM tool_usage WHERE task_id=$1 OR exploration_id=$2), 0),
 COALESCE((SELECT MAX(id) FROM intercept_pending WHERE task_id=$3), 0),
 COALESCE((SELECT MAX(r.ordinal) FROM side_question_requests r JOIN side_question_sessions s ON s.session_key=r.session_key WHERE s.task_id=$1), 0),
 COALESCE((SELECT MAX(asset.id) FROM assets asset WHERE asset.id IN (`+archiveAssetIDsQuery()+`)), 0),
 COALESCE((SELECT MAX(id) FROM owned_resource_events WHERE actor->>'task_id'=$3), 0)`,
			taskID, expID, taskIDStr).Scan(
			&plan.maxNodeID, &plan.maxConstraintID, &plan.maxActivityID, &plan.maxMainRequestID,
			&plan.maxTaskAssetID, &plan.maxDeployEventID, &plan.maxBudgetEventID, &plan.maxFindingID, &plan.maxFindingRetestID,
			&plan.maxLLMRecordID, &plan.maxLLMUsageID, &plan.maxSkillUsageID, &plan.maxToolUsageID,
			&plan.maxInterceptID, &plan.maxSideRequestOrd, &plan.maxAssetID, &plan.maxResourceEventID,
		); err != nil {
			return time.Time{}, nil, fmt.Errorf("snapshot cutoffs for task %d: %w", taskID, err)
		}
		plans = append(plans, plan)
	}

	if err := tx.Commit(); err != nil {
		return time.Time{}, nil, err
	}
	return cutoff, plans, nil
}

func (d *DB) streamRecordExportPlan(
	ctx context.Context,
	plan recordExportCutoffs,
	cutoff time.Time,
	sink func(int64, string) (io.WriteCloser, error),
) (*TaskArchiveSnapshot, error) {
	counts := make(map[string]int64, 32)
	streamedTables := make(map[string]string, 32)
	taskID := plan.taskID
	expID := plan.expID
	taskIDStr := strconv.FormatInt(taskID, 10)

	writeTable := func(name string, writeFn func(w io.Writer) (int64, error)) error {
		w, err := sink(taskID, name)
		if err != nil {
			return err
		}
		bw := bufio.NewWriterSize(w, archiveStreamBufSize)
		count, writeErr := writeFn(bw)
		var flushErr error
		if writeErr == nil {
			flushErr = bw.Flush()
		}
		closeErr := w.Close()
		if err := errors.Join(writeErr, flushErr, closeErr); err != nil {
			return fmt.Errorf("snapshot %s: %w", name, err)
		}
		counts[name] = count
		streamedTables[name] = "database/" + name + ".jsonl"
		return nil
	}

	for _, tbl := range plan.smallTables {
		tbl := tbl
		if err := writeTable(tbl.name, func(w io.Writer) (int64, error) {
			if len(tbl.data) > 0 {
				if _, err := w.Write(tbl.data); err != nil {
					return 0, err
				}
			}
			return tbl.count, nil
		}); err != nil {
			return nil, err
		}
	}

	type singleKeySpec struct {
		name      string
		cutoffID  int64
		keyCol    string
		pageQuery string // expects trailing ($last, $cutoff, $limit) args
		baseArgs  []any
	}
	singleKeyTables := []singleKeySpec{
		{
			name:      "exploration_nodes",
			cutoffID:  plan.maxNodeID,
			keyCol:    "id",
			pageQuery: `SELECT * FROM exploration_nodes WHERE exploration_id=$1 AND id>$2 AND id<=$3 ORDER BY id ASC LIMIT $4`,
			baseArgs:  []any{expID},
		},
		{
			name:      "task_constraints",
			cutoffID:  plan.maxConstraintID,
			keyCol:    "id",
			pageQuery: `SELECT * FROM task_constraints WHERE exploration_id=$1 AND id>$2 AND id<=$3 ORDER BY id ASC LIMIT $4`,
			baseArgs:  []any{expID},
		},
		{
			name:      "activity",
			cutoffID:  plan.maxActivityID,
			keyCol:    "id",
			pageQuery: `SELECT * FROM activity WHERE exploration_id=$1 AND id>$2 AND id<=$3 ORDER BY id ASC LIMIT $4`,
			baseArgs:  []any{expID},
		},
		{
			name:      "main_requests",
			cutoffID:  plan.maxMainRequestID,
			keyCol:    "id",
			pageQuery: `SELECT * FROM main_requests WHERE exploration_id=$1 AND id>$2 AND id<=$3 ORDER BY id ASC LIMIT $4`,
			baseArgs:  []any{expID},
		},
		{
			name:      "task_asset_links",
			cutoffID:  plan.maxTaskAssetID,
			keyCol:    "asset_id",
			pageQuery: `SELECT * FROM task_asset_links WHERE task_id=$1 AND asset_id>$2 AND asset_id<=$3 ORDER BY asset_id ASC LIMIT $4`,
			baseArgs:  []any{taskID},
		},
		{
			name:      "task_deployment_events",
			cutoffID:  plan.maxDeployEventID,
			keyCol:    "id",
			pageQuery: `SELECT * FROM task_deployment_events WHERE task_id=$1 AND id>$2 AND id<=$3 ORDER BY id ASC LIMIT $4`,
			baseArgs:  []any{taskID},
		},
		{
			name:      "worker_budget_events",
			cutoffID:  plan.maxBudgetEventID,
			keyCol:    "id",
			pageQuery: `SELECT * FROM worker_budget_events WHERE task_id=$1 AND id>$2 AND id<=$3 ORDER BY id ASC LIMIT $4`,
			baseArgs:  []any{taskID},
		},
		{
			name:      "findings",
			cutoffID:  plan.maxFindingID,
			keyCol:    "id",
			pageQuery: `SELECT * FROM findings WHERE task_id=$1 AND id>$2 AND id<=$3 ORDER BY id ASC LIMIT $4`,
			baseArgs:  []any{taskID},
		},
		{
			name:      "finding_retests",
			cutoffID:  plan.maxFindingRetestID,
			keyCol:    "id",
			pageQuery: `SELECT r.* FROM finding_retests r JOIN findings f ON f.id=r.finding_id WHERE f.task_id=$1 AND r.id>$2 AND r.id<=$3 ORDER BY r.id ASC LIMIT $4`,
			baseArgs:  []any{taskID},
		},
		{
			name:      "llm_records",
			cutoffID:  plan.maxLLMRecordID,
			keyCol:    "id",
			pageQuery: `SELECT * FROM llm_records WHERE task_id=$1 AND id>$2 AND id<=$3 ORDER BY id ASC LIMIT $4`,
			baseArgs:  []any{taskIDStr},
		},
		{
			name:      "llm_usage",
			cutoffID:  plan.maxLLMUsageID,
			keyCol:    "id",
			pageQuery: `SELECT * FROM llm_usage WHERE (task_id=$1 OR exploration_id=$2) AND id>$3 AND id<=$4 ORDER BY id ASC LIMIT $5`,
			baseArgs:  []any{taskIDStr, expID},
		},
		{
			name:      "skill_usage",
			cutoffID:  plan.maxSkillUsageID,
			keyCol:    "id",
			pageQuery: `SELECT * FROM skill_usage WHERE (task_id=$1 OR exploration_id=$2) AND id>$3 AND id<=$4 ORDER BY id ASC LIMIT $5`,
			baseArgs:  []any{taskID, expID},
		},
		{
			name:      "tool_usage",
			cutoffID:  plan.maxToolUsageID,
			keyCol:    "id",
			pageQuery: `SELECT * FROM tool_usage WHERE (task_id=$1 OR exploration_id=$2) AND id>$3 AND id<=$4 ORDER BY id ASC LIMIT $5`,
			baseArgs:  []any{taskID, expID},
		},
		{
			name:      "intercept_pending",
			cutoffID:  plan.maxInterceptID,
			keyCol:    "id",
			pageQuery: `SELECT * FROM intercept_pending WHERE task_id=$1 AND id>$2 AND id<=$3 ORDER BY id ASC LIMIT $4`,
			baseArgs:  []any{taskIDStr},
		},
		{
			name:      "side_question_requests",
			cutoffID:  plan.maxSideRequestOrd,
			keyCol:    "ordinal",
			pageQuery: `SELECT r.* FROM side_question_requests r JOIN side_question_sessions s ON s.session_key=r.session_key WHERE s.task_id=$1 AND r.ordinal>$2 AND r.ordinal<=$3 ORDER BY r.ordinal ASC LIMIT $4`,
			baseArgs:  []any{taskID},
		},
		{
			name:      "assets",
			cutoffID:  plan.maxAssetID,
			keyCol:    "id",
			pageQuery: `SELECT asset.* FROM assets asset WHERE asset.id IN (` + archiveAssetIDsQuery() + `) AND asset.id>$3 AND asset.id<=$4 ORDER BY asset.id ASC LIMIT $5`,
			baseArgs:  []any{taskID, expID},
		},
		{
			name:      "owned_resource_events",
			cutoffID:  plan.maxResourceEventID,
			keyCol:    "id",
			pageQuery: `SELECT * FROM owned_resource_events WHERE actor->>'task_id'=$1 AND id>$2 AND id<=$3 ORDER BY id ASC LIMIT $4`,
			baseArgs:  []any{taskIDStr},
		},
	}

	for _, spec := range singleKeyTables {
		spec := spec
		if err := writeTable(spec.name, func(w io.Writer) (int64, error) {
			return streamKeysetPages(ctx, spec.cutoffID, recordExportPageSize, func(ctx context.Context, lastID, cutoffID int64, limit int) (int64, int64, error) {
				args := make([]any, 0, len(spec.baseArgs)+3)
				args = append(args, spec.baseArgs...)
				args = append(args, lastID, cutoffID, limit)
				rows, err := d.QueryContext(ctx, `SELECT row_data.`+spec.keyCol+`, row_to_json(row_data)::text FROM (`+spec.pageQuery+`) row_data`, args...)
				if err != nil {
					return lastID, 0, err
				}
				defer rows.Close()
				return writeKeysetRows(rows, w)
			})
		}); err != nil {
			return nil, err
		}
	}

	// Composite-key tables bounded by maxNodeID.
	if err := writeTable("exploration_edges", func(w io.Writer) (int64, error) {
		return d.streamExplorationEdgesKeyset(ctx, expID, plan.maxNodeID, w)
	}); err != nil {
		return nil, err
	}
	if err := writeTable("exploration_anchors", func(w io.Writer) (int64, error) {
		return d.streamExplorationAnchorsKeyset(ctx, expID, plan.maxNodeID, w)
	}); err != nil {
		return nil, err
	}

	return &TaskArchiveSnapshot{
		FormatVersion:  TaskArchiveFormatVersion,
		CreatedAt:      cutoff,
		TaskID:         taskID,
		ExplorationID:  expID,
		StreamedTables: streamedTables,
		DataCounts:     counts,
	}, nil
}

func streamArchiveRowsContext(ctx context.Context, q interface {
	QueryContext(ctx context.Context, query string, args ...any) (*sql.Rows, error)
}, writer io.Writer, inner string, args ...any) (int64, error) {
	rows, err := q.QueryContext(ctx, `SELECT row_to_json(row_data)::text FROM (`+inner+`) row_data`, args...)
	if err != nil {
		return 0, err
	}
	defer rows.Close()
	return writeArchiveRows(rows, writer)
}

func writeKeysetRows(rows *sql.Rows, w io.Writer) (lastID int64, count int64, err error) {
	for rows.Next() {
		var id int64
		var raw []byte
		if err := rows.Scan(&id, &raw); err != nil {
			return lastID, count, err
		}
		if err := writeNDJSONLine(w, raw); err != nil {
			return lastID, count, err
		}
		lastID = id
		count++
	}
	return lastID, count, rows.Err()
}

func writeNDJSONLine(w io.Writer, raw []byte) error {
	if written, err := w.Write(raw); err != nil {
		return err
	} else if written != len(raw) {
		return io.ErrShortWrite
	}
	if written, err := io.WriteString(w, "\n"); err != nil {
		return err
	} else if written != 1 {
		return io.ErrShortWrite
	}
	return nil
}

// streamKeysetPages advances a single-integer-key cursor in bounded short
// queries up to cutoffID, avoiding long-lived transactions.
func streamKeysetPages(
	ctx context.Context,
	cutoffID int64,
	pageSize int,
	fetch func(ctx context.Context, lastID, cutoffID int64, limit int) (nextLastID int64, count int64, err error),
) (int64, error) {
	if cutoffID <= 0 {
		return 0, nil
	}
	if pageSize <= 0 {
		pageSize = recordExportPageSize
	}
	var total int64
	var lastID int64
	for {
		if err := ctx.Err(); err != nil {
			return total, err
		}
		nextLastID, n, err := fetch(ctx, lastID, cutoffID, pageSize)
		if err != nil {
			return total, err
		}
		total += n
		if n < int64(pageSize) || nextLastID <= lastID || nextLastID >= cutoffID {
			return total, nil
		}
		lastID = nextLastID
	}
}

const (
	explorationEdgesKeysetFirstSQL = `SELECT row_data.src_id, row_data.rel, row_data.dst_id, row_to_json(row_data)::text FROM (
SELECT * FROM exploration_edges WHERE exploration_id=$1 AND src_id<=$2 AND dst_id<=$2 ORDER BY src_id ASC, rel ASC, dst_id ASC LIMIT $3
) row_data`
	explorationEdgesKeysetNextSQL = `SELECT row_data.src_id, row_data.rel, row_data.dst_id, row_to_json(row_data)::text FROM (
SELECT * FROM exploration_edges WHERE exploration_id=$1 AND src_id<=$2 AND dst_id<=$2 AND (src_id, rel, dst_id) > ($3, $4, $5) ORDER BY src_id ASC, rel ASC, dst_id ASC LIMIT $6
) row_data`
)

func (d *DB) streamExplorationEdgesKeyset(ctx context.Context, expID, maxNodeID int64, w io.Writer) (int64, error) {
	if maxNodeID <= 0 {
		return 0, nil
	}
	var total int64
	var hasCursor bool
	var lastSrc, lastDst int64
	var lastRel string
	for {
		if err := ctx.Err(); err != nil {
			return total, err
		}
		var rows *sql.Rows
		var err error
		if !hasCursor {
			rows, err = d.QueryContext(ctx, explorationEdgesKeysetFirstSQL, expID, maxNodeID, recordExportPageSize)
		} else {
			rows, err = d.QueryContext(ctx, explorationEdgesKeysetNextSQL, expID, maxNodeID, lastSrc, lastRel, lastDst, recordExportPageSize)
		}
		if err != nil {
			return total, err
		}
		var pageCount int64
		for rows.Next() {
			var srcID, dstID int64
			var rel string
			var raw []byte
			if err := rows.Scan(&srcID, &rel, &dstID, &raw); err != nil {
				rows.Close()
				return total, err
			}
			if err := writeNDJSONLine(w, raw); err != nil {
				rows.Close()
				return total, err
			}
			lastSrc, lastRel, lastDst = srcID, rel, dstID
			hasCursor = true
			pageCount++
		}
		rowErr := rows.Err()
		rows.Close()
		if rowErr != nil {
			return total, rowErr
		}
		total += pageCount
		if pageCount < recordExportPageSize {
			return total, nil
		}
	}
}

func (d *DB) streamExplorationAnchorsKeyset(ctx context.Context, expID, maxNodeID int64, w io.Writer) (int64, error) {
	if maxNodeID <= 0 {
		return 0, nil
	}
	var total int64
	var hasCursor bool
	var lastNode, lastAsset int64
	for {
		if err := ctx.Err(); err != nil {
			return total, err
		}
		var rows *sql.Rows
		var err error
		if !hasCursor {
			rows, err = d.QueryContext(ctx, `SELECT row_data.node_id, row_data.asset_id, row_to_json(row_data)::text FROM (
SELECT anchor.* FROM exploration_anchors anchor JOIN exploration_nodes node ON node.id=anchor.node_id
WHERE node.exploration_id=$1 AND anchor.node_id<=$2 ORDER BY anchor.node_id ASC, anchor.asset_id ASC LIMIT $3
) row_data`, expID, maxNodeID, recordExportPageSize)
		} else {
			rows, err = d.QueryContext(ctx, `SELECT row_data.node_id, row_data.asset_id, row_to_json(row_data)::text FROM (
SELECT anchor.* FROM exploration_anchors anchor JOIN exploration_nodes node ON node.id=anchor.node_id
WHERE node.exploration_id=$1 AND anchor.node_id<=$2 AND (anchor.node_id, anchor.asset_id) > ($3, $4) ORDER BY anchor.node_id ASC, anchor.asset_id ASC LIMIT $5
) row_data`, expID, maxNodeID, lastNode, lastAsset, recordExportPageSize)
		}
		if err != nil {
			return total, err
		}
		var pageCount int64
		for rows.Next() {
			var nodeID, assetID int64
			var raw []byte
			if err := rows.Scan(&nodeID, &assetID, &raw); err != nil {
				rows.Close()
				return total, err
			}
			if err := writeNDJSONLine(w, raw); err != nil {
				rows.Close()
				return total, err
			}
			lastNode, lastAsset = nodeID, assetID
			hasCursor = true
			pageCount++
		}
		rowErr := rows.Err()
		rows.Close()
		if rowErr != nil {
			return total, rowErr
		}
		total += pageCount
		if pageCount < recordExportPageSize {
			return total, nil
		}
	}
}

func archiveAssetMetadata(tx *sql.Tx, taskID, expID int64) ([]int64, []string, []string, error) {
	allHosts := map[string]struct{}{}
	hostRows, err := tx.Query(`SELECT COALESCE(domain,''), COALESCE(ip,''), COALESCE(url,'')
FROM assets WHERE id IN (`+archiveAssetIDsQuery()+`)`, taskID, expID)
	if err != nil {
		return nil, nil, nil, err
	}
	for hostRows.Next() {
		var domain, ip, rawURL string
		if err := hostRows.Scan(&domain, &ip, &rawURL); err != nil {
			hostRows.Close()
			return nil, nil, nil, err
		}
		for _, value := range []string{domain, ip} {
			if trimmed := strings.TrimSpace(value); trimmed != "" {
				allHosts[strings.ToLower(trimmed)] = struct{}{}
			}
		}
		if rawURL != "" {
			if parsed, err := url.Parse(rawURL); err == nil && parsed.Hostname() != "" {
				allHosts[strings.ToLower(parsed.Hostname())] = struct{}{}
			}
		}
	}
	if err := hostRows.Close(); err != nil {
		return nil, nil, nil, err
	}
	if err := hostRows.Err(); err != nil {
		return nil, nil, nil, err
	}

	exclusiveHosts, err := hostsForTaskDeletion(tx, taskID, expID)
	if err != nil {
		return nil, nil, nil, err
	}
	rowsID, err := tx.Query(`WITH candidate AS (`+archiveAssetIDsQuery()+`)
SELECT asset.id FROM assets asset JOIN candidate ON candidate.id=asset.id
WHERE asset.company_id IS NULL
AND NOT EXISTS (SELECT 1 FROM tasks task WHERE task.id<>$1 AND task.deleted_at IS NULL AND task.id=ANY(asset.task_ids))
AND NOT EXISTS (
 SELECT 1 FROM exploration_anchors anchor JOIN exploration_nodes node ON node.id=anchor.node_id
 JOIN tasks task ON task.exploration_id=node.exploration_id
 WHERE anchor.asset_id=asset.id AND task.id<>$1 AND task.deleted_at IS NULL
) ORDER BY asset.id`, taskID, expID)
	if err != nil {
		return nil, nil, nil, err
	}
	var exclusiveIDs []int64
	for rowsID.Next() {
		var id int64
		if err := rowsID.Scan(&id); err != nil {
			rowsID.Close()
			return nil, nil, nil, err
		}
		exclusiveIDs = append(exclusiveIDs, id)
	}
	if err := rowsID.Close(); err != nil {
		return nil, nil, nil, err
	}
	hosts := make([]string, 0, len(allHosts))
	for host := range allHosts {
		hosts = append(hosts, host)
	}
	sort.Strings(hosts)
	return exclusiveIDs, hosts, exclusiveHosts, nil
}

func taskArchiveAggregates(tx *sql.Tx, taskID, expID int64) (map[string]any, error) {
	stats := map[string]any{}
	var calls, input, output, cacheRead, cacheWrite int64
	if err := tx.QueryRow(`SELECT count(*),COALESCE(sum(input_tokens),0),COALESCE(sum(output_tokens),0),
COALESCE(sum(cache_read),0),COALESCE(sum(cache_write),0)
FROM llm_usage WHERE task_id=$1 OR exploration_id=$2`, strconv.FormatInt(taskID, 10), expID).
		Scan(&calls, &input, &output, &cacheRead, &cacheWrite); err != nil {
		return nil, err
	}
	stats["tokens"] = map[string]int64{"calls": calls, "input_tokens": input, "output_tokens": output, "cache_read_tokens": cacheRead, "cache_write_tokens": cacheWrite}
	for _, item := range []struct {
		name  string
		query string
		args  []any
	}{
		{"token_profiles", `SELECT COALESCE(jsonb_agg(to_jsonb(x)),'[]'::jsonb) FROM (
SELECT COALESCE(profile_name,'') profile_name,count(*) calls,1 tasks,
       COALESCE(sum(input_tokens),0) input_tokens,COALESCE(sum(output_tokens),0) output_tokens,
       COALESCE(sum(cache_read),0) cache_read_tokens,COALESCE(sum(cache_write),0) cache_write_tokens
FROM llm_usage WHERE task_id=$1 OR exploration_id=$2
GROUP BY profile_name ORDER BY sum(input_tokens)+sum(output_tokens) DESC) x`, []any{strconv.FormatInt(taskID, 10), expID}},
		{"token_daily", `SELECT COALESCE(jsonb_agg(to_jsonb(x)),'[]'::jsonb) FROM (
SELECT COALESCE(profile_name,'') profile_name,to_char(ts AT TIME ZONE 'UTC','YYYY-MM-DD') date,
       COALESCE(sum(input_tokens),0) input_tokens,COALESCE(sum(output_tokens),0) output_tokens,
       COALESCE(sum(cache_read),0) cache_read_tokens
FROM llm_usage WHERE task_id=$1 OR exploration_id=$2
GROUP BY profile_name,date ORDER BY date) x`, []any{strconv.FormatInt(taskID, 10), expID}},
		{"skills", `SELECT COALESCE(jsonb_object_agg(name,n),'{}'::jsonb) FROM (SELECT skill name,count(*) n FROM skill_usage WHERE (task_id=$1 OR exploration_id=$2) AND found GROUP BY skill) x`, []any{taskID, expID}},
		{"skill_stats", `SELECT COALESCE(jsonb_agg(to_jsonb(x)),'[]'::jsonb) FROM (
SELECT skill,count(*) calls,1 tasks,
       COALESCE(array_agg(DISTINCT agent_key) FILTER (WHERE agent_key IS NOT NULL),ARRAY[]::text[]) agents,
       max(ts) last_used
FROM skill_usage WHERE (task_id=$1 OR exploration_id=$2) AND found GROUP BY skill) x`, []any{taskID, expID}},
		{"missing_skill_stats", `SELECT COALESCE(jsonb_agg(to_jsonb(x)),'[]'::jsonb) FROM (
SELECT skill,count(*) calls,0 tasks,
       COALESCE(array_agg(DISTINCT agent_key) FILTER (WHERE agent_key IS NOT NULL),ARRAY[]::text[]) agents,
       max(ts) last_used
FROM skill_usage WHERE (task_id=$1 OR exploration_id=$2) AND NOT found GROUP BY skill) x`, []any{taskID, expID}},
		{"tools", `SELECT COALESCE(jsonb_object_agg(name,n),'{}'::jsonb) FROM (SELECT tool_key name,count(*) n FROM tool_usage WHERE task_id=$1 OR exploration_id=$2 GROUP BY tool_key) x`, []any{taskID, expID}},
		{"findings", `SELECT COALESCE(jsonb_object_agg(name,n),'{}'::jsonb) FROM (SELECT COALESCE(NULLIF(severity,''),'unknown') name,count(*) n FROM findings WHERE task_id=$1 GROUP BY severity) x`, []any{taskID}},
		{"finding_stats", `SELECT jsonb_build_object(
 'total',count(*),'pending',count(*) FILTER (WHERE status='pending'),
 'critical',count(*) FILTER (WHERE severity='critical'),'high',count(*) FILTER (WHERE severity='high'),
 'medium',count(*) FILTER (WHERE severity='medium'),'low',count(*) FILTER (WHERE severity='low'),
 'vulnclasses',COALESCE(jsonb_agg(DISTINCT vulnclass) FILTER (WHERE vulnclass<>''),'[]'::jsonb))
FROM findings WHERE task_id=$1`, []any{taskID}},
	} {
		var raw []byte
		if err := tx.QueryRow(item.query, item.args...).Scan(&raw); err != nil {
			return nil, err
		}
		var value any
		if err := json.Unmarshal(raw, &value); err != nil {
			return nil, err
		}
		stats[item.name] = value
	}
	return stats, nil
}

func jsonInt64(value any) (int64, bool) {
	switch value := value.(type) {
	case float64:
		return int64(value), value == float64(int64(value))
	case json.Number:
		id, err := value.Int64()
		return id, err == nil
	case string:
		id, err := strconv.ParseInt(value, 10, 64)
		return id, err == nil
	default:
		return 0, false
	}
}
