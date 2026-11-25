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
	"strconv"
	"strings"
	"time"
)

const (
	archiveRestoreBatchSize     = 500
	archiveRestoreBatchMaxBytes = 16 << 20
)

var allowedArchiveRestoreTables = map[string]bool{
	"exploration_nodes":      true,
	"exploration_edges":      true,
	"exploration_anchors":    true,
	"task_constraints":       true,
	"activity":               true,
	"main_requests":          true,
	"task_asset_links":       true,
	"findings":               true,
	"finding_retests":        true,
	"llm_records":            true,
	"llm_usage":              true,
	"skill_usage":            true,
	"tool_usage":             true,
	"intercept_pending":      true,
	"side_question_sessions": true,
	"side_question_requests": true,
}

// CompleteTaskArchive performs hot-store compaction only after the external
// package has been fully written and checksummed. LOCK TABLE assets,
// exploration_anchors is held strictly for the short millisecond asset/anchor
// detach/delete and task-stub step; heavyweight child-table deletes execute
// afterwards outside LOCK TABLE in bounded 2000-row batches.
func (d *DB) CompleteTaskArchive(
	archiveID int64,
	snapshot *TaskArchiveSnapshot,
	archivePath, sha256 string,
	originalSize, compressedSize int64,
) error {
	if snapshot == nil || snapshot.FormatVersion != TaskArchiveFormatVersion {
		return ErrTaskArchiveFormatMismatch
	}
	countsRaw, err := json.Marshal(snapshot.DataCounts)
	if err != nil {
		return err
	}
	statsRaw, err := json.Marshal(snapshot.AggregateStats)
	if err != nil {
		return err
	}

	// Phase 1: short locked transaction for exclusivity validation, asset/anchor
	// detach/delete, small metadata cleanup, and hiding the live task stub.
	tx, err := d.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback() //nolint:errcheck
	if err := SetMaintenanceTimeouts(context.Background(), tx); err != nil {
		return err
	}
	if err := coordinateWithSchemaMigration(tx); err != nil {
		return err
	}
	var taskID, expID int64
	var state string
	if err := tx.QueryRow(`SELECT archive.task_id,task.exploration_id,archive.state
FROM task_archives archive JOIN tasks task ON task.id=archive.task_id
WHERE archive.id=$1 FOR UPDATE OF archive,task`, archiveID).Scan(&taskID, &expID, &state); err != nil {
		return err
	}
	if state != Archiving || taskID != snapshot.TaskID || expID != snapshot.ExplorationID {
		return fmt.Errorf("%w: archive snapshot identity/state mismatch", ErrTaskArchiveState)
	}
	var dependent int64
	err = tx.QueryRow(`SELECT child.id FROM task_relations relation
JOIN tasks child ON child.id=relation.task_id AND child.deleted_at IS NULL
WHERE relation.source_task_id=$1 LIMIT 1`, taskID).Scan(&dependent)
	if err == nil {
		return fmt.Errorf("%w: task %d", ErrTaskArchiveDependent, dependent)
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return err
	}
	// Prevent task/asset ownership from changing while exclusivity is rechecked.
	// Scoped strictly to asset/anchor mutation and task tombstone, never big-table deletes.
	if _, err := tx.Exec(`SET LOCAL lock_timeout = '` + taskDeleteLockTimeout + `'`); err != nil {
		return err
	}
	if _, err := tx.Exec(`LOCK TABLE assets, exploration_anchors IN SHARE ROW EXCLUSIVE MODE`); err != nil {
		return err
	}
	if _, err := tx.Exec(`UPDATE assets SET task_ids=array_remove(task_ids,$1) WHERE task_ids @> ARRAY[$1]::bigint[]`, taskID); err != nil {
		return err
	}
	if len(snapshot.ExclusiveAssetIDs) > 0 {
		if _, err := tx.Exec(`DELETE FROM assets asset
WHERE asset.id=ANY($2::bigint[]) AND asset.company_id IS NULL
AND NOT EXISTS (SELECT 1 FROM tasks task WHERE task.id<>$1 AND task.deleted_at IS NULL AND task.id=ANY(asset.task_ids))
AND NOT EXISTS (
 SELECT 1 FROM exploration_anchors anchor JOIN exploration_nodes node ON node.id=anchor.node_id
 JOIN tasks task ON task.exploration_id=node.exploration_id
 WHERE anchor.asset_id=asset.id AND task.id<>$1 AND task.deleted_at IS NULL
)`, taskID, snapshot.ExclusiveAssetIDs); err != nil {
			return err
		}
	}
	if _, err := tx.Exec(`DELETE FROM exploration_anchors WHERE node_id IN (SELECT id FROM exploration_nodes WHERE exploration_id=$1)`, expID); err != nil {
		return err
	}
	for _, statement := range []struct {
		query string
		args  []any
	}{
		{`DELETE FROM task_relations WHERE task_id=$1 OR source_task_id=$1`, []any{taskID}},
		{`DELETE FROM task_asset_links WHERE task_id=$1`, []any{taskID}},
		{`DELETE FROM task_llm_profiles WHERE task_id=$1`, []any{taskID}},
		{`DELETE FROM task_scope WHERE task_id=$1`, []any{taskID}},
		{`DELETE FROM task_owned_resources WHERE task_id=$1`, []any{taskID}},
	} {
		if _, err := tx.Exec(statement.query, statement.args...); err != nil {
			return err
		}
	}
	if _, err := tx.Exec(`UPDATE explorations SET description='',goal='',status='open' WHERE id=$1`, expID); err != nil {
		return err
	}
	// Hide the task immediately (deleted_at=now()) while keeping archived_at NULL
	// until Phase 3 so ArchivedAggregateStats does not double-count rows before
	// batched deletes finish.
	if _, err := tx.Exec(`UPDATE tasks SET
 name='',category_id=NULL,description='',goal='',paused=true,queued=false,queued_at=NULL,queue_mode='',
 llm_profile_id=NULL,active_llm_profile_id=NULL,llm_chain_revision=llm_chain_revision+1,
 company_id=NULL,parent_ref=NULL,timeout_seconds=0,coverage_enabled=true,pinned_at=NULL,
 first_run_at=NULL,deadline_at=NULL,deleted_at=now()
WHERE id=$1`, taskID); err != nil {
		return err
	}
	if _, err := tx.Exec(`UPDATE task_archives SET
 state=$2,phase='compact_rows',error='',archive_path=$3,sha256=$4,
 original_size=$5,compressed_size=$6,data_counts=$7,aggregate_stats=$8,format_version=$9
WHERE id=$1`, archiveID, ArchiveCompacting, archivePath, sha256, originalSize, compressedSize,
		string(countsRaw), string(statsRaw), snapshot.FormatVersion); err != nil {
		return err
	}
	if err := tx.Commit(); err != nil {
		return err
	}

	return d.completeArchiveCompaction(archiveID, taskID, expID)
}

// completeArchiveCompaction executes Phase 2 (batched child-table deletes
// outside LOCK TABLE) and Phase 3 (marking tasks.archived_at and transitioning
// task_archives to ready). It is idempotent so an interrupted compaction can
// always be resumed after a crash or transient database error.
func (d *DB) completeArchiveCompaction(archiveID, taskID, expID int64) error {
	return d.completeArchiveCompactionContext(context.Background(), archiveID, taskID, expID)
}

func (d *DB) completeArchiveCompactionContext(ctx context.Context, archiveID, taskID, expID int64) error {
	if ctx == nil {
		ctx = context.Background()
	}
	// Phase 2: batched deletes of heavyweight tables outside LOCK TABLE.
	taskIDStr := strconv.FormatInt(taskID, 10)
	for _, step := range []struct {
		query    string
		args     []any
		optional bool
	}{
		{`DELETE FROM intercept_pending WHERE id IN (SELECT id FROM intercept_pending WHERE task_id=$1 LIMIT $2)`, []any{taskIDStr, taskDeleteBatchSize}, false},
		{`DELETE FROM llm_records WHERE id IN (SELECT id FROM llm_records WHERE task_id=$1 LIMIT $2)`, []any{taskIDStr, taskDeleteBatchSize}, true},
		{`DELETE FROM llm_usage WHERE id IN (SELECT id FROM llm_usage WHERE task_id=$1 OR exploration_id=$2 LIMIT $3)`, []any{taskIDStr, expID, taskDeleteBatchSize}, true},
		{`DELETE FROM skill_usage WHERE id IN (SELECT id FROM skill_usage WHERE task_id=$1 OR exploration_id=$2 LIMIT $3)`, []any{taskID, expID, taskDeleteBatchSize}, false},
		{`DELETE FROM tool_usage WHERE id IN (SELECT id FROM tool_usage WHERE task_id=$1 OR exploration_id=$2 LIMIT $3)`, []any{taskID, expID, taskDeleteBatchSize}, false},
		{`DELETE FROM side_question_requests WHERE id IN (SELECT r.id FROM side_question_requests r JOIN side_question_sessions s ON s.session_key=r.session_key WHERE s.task_id=$1 LIMIT $2)`, []any{taskID, taskDeleteBatchSize}, false},
		{`DELETE FROM side_question_sessions WHERE session_key IN (SELECT session_key FROM side_question_sessions WHERE task_id=$1 LIMIT $2)`, []any{taskID, taskDeleteBatchSize}, false},
		{`DELETE FROM finding_traffic_bindings WHERE id IN (SELECT b.id FROM finding_traffic_bindings b JOIN findings f ON f.id=b.finding_id WHERE f.task_id=$1 LIMIT $2)`, []any{taskID, taskDeleteBatchSize}, false},
		{`DELETE FROM finding_retests WHERE id IN (SELECT r.id FROM finding_retests r JOIN findings f ON f.id=r.finding_id WHERE f.task_id=$1 LIMIT $2)`, []any{taskID, taskDeleteBatchSize}, false},
		{`DELETE FROM findings WHERE id IN (SELECT id FROM findings WHERE task_id=$1 LIMIT $2)`, []any{taskID, taskDeleteBatchSize}, false},
		{`DELETE FROM task_constraints WHERE id IN (SELECT id FROM task_constraints WHERE exploration_id=$1 LIMIT $2)`, []any{expID, taskDeleteBatchSize}, false},
		{`DELETE FROM activity WHERE id IN (SELECT id FROM activity WHERE exploration_id=$1 LIMIT $2)`, []any{expID, taskDeleteBatchSize}, false},
		{`DELETE FROM main_requests WHERE id IN (SELECT id FROM main_requests WHERE exploration_id=$1 LIMIT $2)`, []any{expID, taskDeleteBatchSize}, false},
		{`DELETE FROM exploration_edges WHERE ctid IN (SELECT ctid FROM exploration_edges WHERE exploration_id=$1 LIMIT $2)`, []any{expID, taskDeleteBatchSize}, false},
		{`DELETE FROM exploration_nodes WHERE id IN (SELECT id FROM exploration_nodes WHERE exploration_id=$1 LIMIT $2)`, []any{expID, taskDeleteBatchSize}, false},
	} {
		if _, err := d.execMaintenanceDeleteBatches(ctx, step.optional, step.query, step.args...); err != nil {
			return err
		}
	}

	// Phase 3: finalize cold archive state in a tiny unlocked transaction.
	finalTx, err := d.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer finalTx.Rollback() //nolint:errcheck
	if err := SetMaintenanceTimeouts(ctx, finalTx); err != nil {
		return err
	}
	if _, err := finalTx.ExecContext(ctx, `UPDATE tasks SET archived_at=now() WHERE id=$1`, taskID); err != nil {
		return err
	}
	if _, err := finalTx.ExecContext(ctx, `UPDATE task_archives SET
 state=$2,phase='ready',progress=100,error='',archived_at=now(),warnings='[]'
WHERE id=$1`, archiveID, ArchiveReady); err != nil {
		return err
	}
	return finalTx.Commit()
}

// ResumeCompactingTaskArchives finds all archives whose Phase 1 commit already
// wrote the verified archive package and tombstoned the task (state='compacting'
// or legacy phase='compact_rows' with state<>'ready' and non-empty archive_path)
// and completes Phase 2+3 compaction to drive them cleanly to state='ready'.
func (d *DB) ResumeCompactingTaskArchives(ctx context.Context) (int, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if d == nil || d.DB == nil {
		return 0, ctx.Err()
	}
	rows, err := d.QueryContext(ctx, `SELECT a.id, a.task_id, t.exploration_id
FROM task_archives a
JOIN tasks t ON t.id = a.task_id
WHERE (a.state = $1 OR (a.phase = 'compact_rows' AND a.state <> $2))
  AND a.archive_path <> ''
  AND t.deleted_at IS NOT NULL
ORDER BY a.id`, ArchiveCompacting, ArchiveReady)
	if err != nil {
		return 0, err
	}
	type candidate struct {
		archiveID int64
		taskID    int64
		expID     int64
	}
	var items []candidate
	for rows.Next() {
		var c candidate
		if err := rows.Scan(&c.archiveID, &c.taskID, &c.expID); err != nil {
			rows.Close()
			return 0, err
		}
		items = append(items, c)
	}
	rowErr := rows.Err()
	rows.Close()
	if rowErr != nil {
		return 0, rowErr
	}

	resumed := 0
	var errs []error
	for _, c := range items {
		if err := ctx.Err(); err != nil {
			return resumed, err
		}
		if err := d.completeArchiveCompactionContext(ctx, c.archiveID, c.taskID, c.expID); err != nil {
			if ctx.Err() != nil {
				return resumed, ctx.Err()
			}
			_ = d.FailTaskArchiveJob(c.archiveID, ArchiveCompacting, err)
			errs = append(errs, fmt.Errorf("resume archive compaction %d (task %d): %w", c.archiveID, c.taskID, err))
			continue
		}
		resumed++
	}
	return resumed, errors.Join(errs...)
}

// RestoreTaskArchive restores PostgreSQL rows from a verified manifest. It is
// idempotent for accounting/traffic retry scenarios and returns non-fatal
// warnings for global objects that intentionally are not recreated.
func (d *DB) RestoreTaskArchive(archiveID int64, snapshot *TaskArchiveSnapshot, remainingTimeoutSeconds int64) ([]string, error) {
	return d.restoreTaskArchive(archiveID, snapshot, remainingTimeoutSeconds, nil)
}

// RestoreTaskArchiveWithLLMRecords restores a package whose heavyweight LLM
// record history is stored as a sequence of JSON objects outside manifest.json.
func (d *DB) RestoreTaskArchiveWithLLMRecords(
	archiveID int64,
	snapshot *TaskArchiveSnapshot,
	remainingTimeoutSeconds int64,
	llmRecords io.Reader,
) ([]string, error) {
	if llmRecords == nil {
		return nil, errors.New("nil streamed LLM record reader")
	}
	return d.restoreTaskArchive(archiveID, snapshot, remainingTimeoutSeconds, func(table, _ string) (io.ReadCloser, error) {
		if table != "llm_records" {
			return nil, fmt.Errorf("%w: missing stream for table %q", ErrTaskArchiveFormatMismatch, table)
		}
		return io.NopCloser(llmRecords), nil
	})
}

// RestoreTaskArchiveWithStreams restores a task archive whose large tables may
// be stored as per-table NDJSON files referenced by StreamedTables (or inline
// JSON arrays for legacy archives). Every table is restored in bounded batches.
func (d *DB) RestoreTaskArchiveWithStreams(
	archiveID int64,
	snapshot *TaskArchiveSnapshot,
	remainingTimeoutSeconds int64,
	openStream func(table, relPath string) (io.ReadCloser, error),
) ([]string, error) {
	return d.restoreTaskArchive(archiveID, snapshot, remainingTimeoutSeconds, openStream)
}

type archiveBatchStreamer func(table string, fn func(batch []json.RawMessage) error) (int64, error)

func (d *DB) restoreTaskArchive(
	archiveID int64,
	snapshot *TaskArchiveSnapshot,
	remainingTimeoutSeconds int64,
	openStream func(table, relPath string) (io.ReadCloser, error),
) ([]string, error) {
	if err := ValidateTaskArchiveStreamedTables(snapshot); err != nil {
		return nil, err
	}
	if len(snapshot.StreamedTables) > 0 && openStream == nil {
		return nil, fmt.Errorf("%w: streamed archive tables are missing", ErrTaskArchiveFormatMismatch)
	}

	tx, err := d.Begin()
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
	var taskID, expID int64
	var state string
	if err := tx.QueryRow(`SELECT archive.task_id,task.exploration_id,archive.state
FROM task_archives archive JOIN tasks task ON task.id=archive.task_id
WHERE archive.id=$1 FOR UPDATE OF archive,task`, archiveID).Scan(&taskID, &expID, &state); err != nil {
		return nil, err
	}
	if state != Restoring || taskID != snapshot.TaskID || expID != snapshot.ExplorationID {
		return nil, fmt.Errorf("%w: restore snapshot identity/state mismatch", ErrTaskArchiveState)
	}

	streamTable := func(table string, fn func(batch []json.RawMessage) error) (int64, error) {
		if relPath, streamed := snapshot.StreamedTables[table]; streamed {
			rc, err := openStream(table, relPath)
			if err != nil {
				return 0, err
			}
			count, readErr := streamNDJSONBatches(rc, archiveRestoreBatchSize, archiveRestoreBatchMaxBytes, fn)
			closeErr := rc.Close()
			if err := errors.Join(readErr, closeErr); err != nil {
				return count, err
			}
			if expected, hasNDJSON := snapshot.NDJSONTables[table]; hasNDJSON {
				if count != expected {
					return count, fmt.Errorf("row count %d does not match manifest %d", count, expected)
				}
			} else if table == "llm_records" {
				if expected := snapshot.DataCounts["llm_records"]; count != expected {
					return count, fmt.Errorf("row count %d does not match manifest %d", count, expected)
				}
			}
			return count, nil
		}
		raw := snapshot.Tables[table]
		if len(bytes.TrimSpace(raw)) == 0 {
			return 0, nil
		}
		return streamJSONArrayBatches(bytes.NewReader(raw), archiveRestoreBatchSize, archiveRestoreBatchMaxBytes, fn)
	}

	warnings := []string{}
	assetMap, assetWarnings, err := restoreArchiveAssetsStreamed(tx, taskID, streamTable)
	if err != nil {
		return nil, err
	}
	warnings = append(warnings, assetWarnings...)
	hasAssetRemap := hasAssetIDRemapping(assetMap)

	// The task row exists as an archived stub. Restore its global references only
	// when the current instance still owns them; never recreate categories/profiles.
	taskRows, err := decodeArchiveRows(snapshot.Tables["tasks"])
	if err != nil || len(taskRows) != 1 {
		return nil, fmt.Errorf("restore task row: expected one row: %w", err)
	}
	taskRow := taskRows[0]
	categoryID, _ := jsonInt64(taskRow["category_id"])
	if categoryID > 0 && !rowExists(tx, "task_categories", categoryID) {
		taskRow["category_id"] = nil
		warnings = append(warnings, fmt.Sprintf("任务分类 %d 已删除，已恢复为未分类", categoryID))
	}
	companyID, _ := jsonInt64(taskRow["company_id"])
	if companyID > 0 && !rowExists(tx, "companies", companyID) {
		taskRow["company_id"] = nil
		warnings = append(warnings, fmt.Sprintf("任务企业 %d 已删除，企业关联已跳过", companyID))
	}
	for _, key := range []string{"llm_profile_id", "active_llm_profile_id"} {
		profileID, _ := jsonInt64(taskRow[key])
		if profileID > 0 && !rowExists(tx, "llm_profiles", profileID) {
			taskRow[key] = nil
			warnings = append(warnings, fmt.Sprintf("LLM 配置 %d 已删除，已从任务配置中移除", profileID))
		}
	}
	if err := restoreExplorationStub(tx, snapshot.Tables["explorations"], expID); err != nil {
		return nil, err
	}
	if err := restoreTaskStub(tx, taskRow, taskID, remainingTimeoutSeconds); err != nil {
		return nil, err
	}

	var nodeTransform, anchorTransform archiveRowTransform
	if hasAssetRemap {
		nodeTransform = func(raw json.RawMessage) (json.RawMessage, error) {
			return remapExplorationNodeAssetIDs(raw, assetMap)
		}
		anchorTransform = func(raw json.RawMessage) (json.RawMessage, error) {
			return remapAssetIDField(raw, assetMap)
		}
	}

	// Insert graph rows in foreign-key order in bounded batches.
	for _, item := range []struct {
		table     string
		transform archiveRowTransform
	}{
		{"exploration_nodes", nodeTransform},
		{"exploration_edges", nil},
		{"exploration_anchors", anchorTransform},
		{"task_constraints", nil},
		{"activity", nil},
		{"main_requests", nil},
	} {
		if err := insertStreamedArchiveTable(tx, item.table, streamTable, item.transform); err != nil {
			return nil, fmt.Errorf("restore %s: %w", item.table, err)
		}
	}
	// An archived process no longer owns an in-flight main turn.
	if _, err := tx.Exec(`UPDATE main_requests SET state='pending',updated_at=now() WHERE exploration_id=$1 AND state='processing'`, expID); err != nil {
		return nil, err
	}
	if warning, err := restoreTaskRelations(tx, taskID, snapshot.Tables["task_relations"]); err != nil {
		return nil, err
	} else {
		warnings = append(warnings, warning...)
	}
	for _, item := range []struct {
		table string
		field string
	}{
		{"side_question_sessions", "memory"},
		{"side_question_requests", "context_info"},
	} {
		field := item.field
		if err := insertStreamedArchiveTable(tx, item.table, streamTable, func(raw json.RawMessage) (json.RawMessage, error) {
			return ensureArchiveJSONObjectField(raw, field)
		}); err != nil {
			return nil, fmt.Errorf("restore %s: %w", item.table, err)
		}
	}
	if warning, err := restoreTaskScopes(tx, snapshot.Tables["task_scope"]); err != nil {
		return nil, err
	} else {
		warnings = append(warnings, warning...)
	}
	if warning, err := restoreTaskLLMProfiles(tx, snapshot.Tables["task_llm_profiles"]); err != nil {
		return nil, err
	} else {
		warnings = append(warnings, warning...)
	}
	if warning, err := restoreTaskResources(tx, taskID, snapshot.Tables["task_owned_resources"]); err != nil {
		return nil, err
	} else {
		warnings = append(warnings, warning...)
	}
	if err := insertStreamedArchiveTable(tx, "task_asset_links", streamTable, anchorTransform); err != nil {
		return nil, fmt.Errorf("restore task_asset_links: %w", err)
	}
	now := time.Now().UTC()
	fkResolver := newTxArchiveFKResolver(tx, &warnings)

	if err := insertStreamedArchiveTable(tx, "findings", streamTable, func(raw json.RawMessage) (json.RawMessage, error) {
		return normalizeAndRemapFindingRow(raw, assetMap, hasAssetRemap)
	}); err != nil {
		return nil, fmt.Errorf("restore findings: %w", err)
	}
	if err := insertStreamedArchiveTable(tx, "finding_retests", streamTable, func(raw json.RawMessage) (json.RawMessage, error) {
		return normalizeFindingRetestRow(raw, now, fkResolver)
	}); err != nil {
		return nil, fmt.Errorf("restore finding_retests: %w", err)
	}
	if err := restoreFindingTrafficTx(tx, snapshot); err != nil {
		return nil, fmt.Errorf("restore finding traffic: %w", err)
	}
	for _, table := range []string{"llm_records", "llm_usage", "skill_usage", "tool_usage"} {
		if err := insertStreamedArchiveTable(tx, table, streamTable, nil); err != nil {
			return nil, fmt.Errorf("restore %s: %w", table, err)
		}
		if table == "llm_usage" {
			if err := reconcileTaskTokenCounterTx(tx, taskID); err != nil {
				return nil, fmt.Errorf("reconcile task token counter: %w", err)
			}
		}
	}
	if err := insertStreamedArchiveTable(tx, "intercept_pending", streamTable, func(raw json.RawMessage) (json.RawMessage, error) {
		return normalizeInterceptRowWithFKs(raw, now, fkResolver)
	}); err != nil {
		return nil, fmt.Errorf("restore intercept_pending: %w", err)
	}

	warningsRaw, _ := json.Marshal(warnings)
	if _, err := tx.Exec(`UPDATE task_archives SET warnings=$2,phase='database_restored',progress=85,error='' WHERE id=$1`, archiveID, string(warningsRaw)); err != nil {
		return nil, err
	}
	return warnings, tx.Commit()
}

type archiveRowTransform func(raw json.RawMessage) (json.RawMessage, error)

func insertStreamedArchiveTable(
	tx *sql.Tx,
	table string,
	streamTable archiveBatchStreamer,
	transform archiveRowTransform,
) error {
	if !allowedArchiveRestoreTables[table] {
		return fmt.Errorf("archive restore table %q is not allowed", table)
	}
	query := `INSERT INTO ` + table + ` SELECT * FROM json_populate_recordset(NULL::` + table + `,$1::json)`
	_, err := streamTable(table, func(batch []json.RawMessage) error {
		if len(batch) == 0 {
			return nil
		}
		if transform != nil {
			for i, row := range batch {
				updated, err := transform(row)
				if err != nil {
					return err
				}
				batch[i] = updated
			}
		}
		payload := marshalJSONBatch(batch)
		_, err := tx.Exec(query, string(payload))
		return err
	})
	return err
}

// insertArchiveRows restores one inline JSON array table in bounded 500-row
// batches, preserving compatibility with legacy tests and callers.
func insertArchiveRows(tx *sql.Tx, table string, raw json.RawMessage) error {
	var transform archiveRowTransform
	switch table {
	case "side_question_sessions":
		transform = func(row json.RawMessage) (json.RawMessage, error) {
			return ensureArchiveJSONObjectField(row, "memory")
		}
	case "side_question_requests":
		transform = func(row json.RawMessage) (json.RawMessage, error) {
			return ensureArchiveJSONObjectField(row, "context_info")
		}
	}
	return insertStreamedArchiveTable(tx, table, func(_ string, fn func(batch []json.RawMessage) error) (int64, error) {
		if len(bytes.TrimSpace(raw)) == 0 {
			return 0, nil
		}
		return streamJSONArrayBatches(bytes.NewReader(raw), archiveRestoreBatchSize, archiveRestoreBatchMaxBytes, fn)
	}, transform)
}

// restoreInterceptRows normalizes and restores inline intercept_pending rows in
// bounded 500-row batches.
func restoreInterceptRows(tx *sql.Tx, raw json.RawMessage) error {
	now := time.Now().UTC()
	var warnings []string
	fkResolver := newTxArchiveFKResolver(tx, &warnings)
	return insertStreamedArchiveTable(tx, "intercept_pending", func(_ string, fn func(batch []json.RawMessage) error) (int64, error) {
		if len(bytes.TrimSpace(raw)) == 0 {
			return 0, nil
		}
		return streamJSONArrayBatches(bytes.NewReader(raw), archiveRestoreBatchSize, archiveRestoreBatchMaxBytes, fn)
	}, func(row json.RawMessage) (json.RawMessage, error) {
		return normalizeInterceptRowWithFKs(row, now, fkResolver)
	})
}

// streamNDJSONBatches reads one JSON object per line from r and emits batches
// bounded by both row count (batchSize) and aggregate byte size (maxBatchBytes).
func streamNDJSONBatches(
	r io.Reader,
	batchSize int,
	maxBatchBytes int,
	fn func(batch []json.RawMessage) error,
) (int64, error) {
	if batchSize <= 0 {
		batchSize = archiveRestoreBatchSize
	}
	if maxBatchBytes <= 0 {
		maxBatchBytes = archiveRestoreBatchMaxBytes
	}
	br := bufio.NewReaderSize(r, archiveStreamBufSize)
	batch := make([]json.RawMessage, 0, min(batchSize, 64))
	var batchBytes int
	var count int64

	flush := func() error {
		if len(batch) == 0 {
			return nil
		}
		if err := fn(batch); err != nil {
			return err
		}
		batch = batch[:0]
		batchBytes = 0
		return nil
	}

	for {
		line, readErr := br.ReadBytes('\n')
		if readErr != nil && !errors.Is(readErr, io.EOF) {
			return count, readErr
		}
		trimmed := bytes.TrimSpace(line)
		if len(trimmed) > 0 {
			if trimmed[0] != '{' || !json.Valid(trimmed) {
				return count, errors.New("streamed archive row must be a valid JSON object")
			}
			if len(batch) > 0 && (len(batch) >= batchSize || batchBytes+len(trimmed) > maxBatchBytes) {
				if err := flush(); err != nil {
					return count, err
				}
			}
			batch = append(batch, json.RawMessage(trimmed))
			batchBytes += len(trimmed)
			count++
		}
		if errors.Is(readErr, io.EOF) {
			break
		}
	}
	if err := flush(); err != nil {
		return count, err
	}
	return count, nil
}

// streamJSONArrayBatches streams a JSON array of objects (legacy v1/inline
// archive table format) in bounded batches without buffering the full array.
func streamJSONArrayBatches(
	r io.Reader,
	batchSize int,
	maxBatchBytes int,
	fn func(batch []json.RawMessage) error,
) (int64, error) {
	if batchSize <= 0 {
		batchSize = archiveRestoreBatchSize
	}
	if maxBatchBytes <= 0 {
		maxBatchBytes = archiveRestoreBatchMaxBytes
	}
	dec := json.NewDecoder(bufio.NewReaderSize(r, archiveStreamBufSize))
	tok, err := dec.Token()
	if errors.Is(err, io.EOF) || tok == nil {
		return 0, nil
	}
	if err != nil {
		return 0, err
	}
	if delim, ok := tok.(json.Delim); !ok || delim != '[' {
		return 0, errors.New("archive table payload must be a JSON array")
	}

	batch := make([]json.RawMessage, 0, min(batchSize, 64))
	var batchBytes int
	var count int64
	flush := func() error {
		if len(batch) == 0 {
			return nil
		}
		if err := fn(batch); err != nil {
			return err
		}
		batch = batch[:0]
		batchBytes = 0
		return nil
	}

	for dec.More() {
		var raw json.RawMessage
		if err := dec.Decode(&raw); err != nil {
			return count, err
		}
		trimmed := bytes.TrimSpace(raw)
		if len(trimmed) == 0 || trimmed[0] != '{' {
			return count, errors.New("archive table row must be a JSON object")
		}
		if len(batch) > 0 && (len(batch) >= batchSize || batchBytes+len(trimmed) > maxBatchBytes) {
			if err := flush(); err != nil {
				return count, err
			}
		}
		batch = append(batch, trimmed)
		batchBytes += len(trimmed)
		count++
	}
	endTok, err := dec.Token()
	if err != nil {
		return count, err
	}
	if delim, ok := endTok.(json.Delim); !ok || delim != ']' {
		return count, errors.New("archive table array missing closing bracket")
	}
	if err := flush(); err != nil {
		return count, err
	}
	return count, nil
}

func marshalJSONBatch(rows []json.RawMessage) []byte {
	if len(rows) == 0 {
		return []byte("[]")
	}
	totalLen := 2 + len(rows) - 1
	for _, r := range rows {
		totalLen += len(r)
	}
	buf := bytes.NewBuffer(make([]byte, 0, totalLen))
	buf.WriteByte('[')
	for i, r := range rows {
		if i > 0 {
			buf.WriteByte(',')
		}
		buf.Write(r)
	}
	buf.WriteByte(']')
	return buf.Bytes()
}

func decodeArchiveObject(raw json.RawMessage) (map[string]any, error) {
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	var row map[string]any
	if err := dec.Decode(&row); err != nil {
		return nil, err
	}
	return row, nil
}

func hasAssetIDRemapping(mapping map[int64]int64) bool {
	for oldID, newID := range mapping {
		if oldID != newID {
			return true
		}
	}
	return false
}

// json_populate_recordset inserts NULL for absent columns, bypassing SQL
// defaults. Preserve compatibility with archives predating side memory fields.
func ensureArchiveJSONObjectField(raw json.RawMessage, field string) (json.RawMessage, error) {
	var row map[string]json.RawMessage
	if err := json.Unmarshal(raw, &row); err != nil {
		return nil, err
	}
	v := bytes.TrimSpace(row[field])
	if len(v) > 0 && !bytes.Equal(v, []byte("null")) {
		return raw, nil
	}
	row[field] = json.RawMessage(`{}`)
	encoded, err := json.Marshal(row)
	if err != nil {
		return nil, err
	}
	return json.RawMessage(encoded), nil
}

func remapAssetIDField(raw json.RawMessage, mapping map[int64]int64) (json.RawMessage, error) {
	row, err := decodeArchiveObject(raw)
	if err != nil {
		return nil, err
	}
	oldID, ok := jsonInt64(row["asset_id"])
	if !ok {
		return raw, nil
	}
	replacement, exists := mapping[oldID]
	if !exists || replacement == oldID {
		return raw, nil
	}
	row["asset_id"] = replacement
	encoded, err := json.Marshal(row)
	if err != nil {
		return nil, err
	}
	return json.RawMessage(encoded), nil
}

func remapExplorationNodeAssetIDs(raw json.RawMessage, mapping map[int64]int64) (json.RawMessage, error) {
	row, err := decodeArchiveObject(raw)
	if err != nil {
		return nil, err
	}
	payload, ok := row["payload"].(map[string]any)
	if !ok {
		return raw, nil
	}
	values, ok := payload["asset_ids"].([]any)
	if !ok || len(values) == 0 {
		return raw, nil
	}
	changed := false
	for i, value := range values {
		if oldID, ok := jsonInt64(value); ok {
			if replacement, exists := mapping[oldID]; exists && replacement != oldID {
				values[i] = replacement
				changed = true
			}
		}
	}
	if !changed {
		return raw, nil
	}
	payload["asset_ids"] = values
	encoded, err := json.Marshal(row)
	if err != nil {
		return nil, err
	}
	return json.RawMessage(encoded), nil
}

func normalizeAndRemapFindingRow(raw json.RawMessage, mapping map[int64]int64, remap bool) (json.RawMessage, error) {
	row, err := decodeArchiveObject(raw)
	if err != nil {
		return nil, err
	}
	changed := false
	for _, key := range []string{"evidence_version", "report_evidence_version"} {
		if row[key] == nil {
			row[key] = 0
			changed = true
		}
	}
	if remap {
		if values, ok := row["asset_ids"].([]any); ok {
			for i, value := range values {
				if oldID, ok := jsonInt64(value); ok {
					if replacement, exists := mapping[oldID]; exists && replacement != oldID {
						values[i] = replacement
						changed = true
					}
				}
			}
			row["asset_ids"] = values
		}
	}
	if !changed {
		return raw, nil
	}
	encoded, err := json.Marshal(row)
	if err != nil {
		return nil, err
	}
	return json.RawMessage(encoded), nil
}

// archiveFKResolver memoizes global FK existence checks during archive restore
// and deduplicates non-fatal warnings when global rows (intercept rules or
// conversations) were deleted while the task was archived.
type archiveFKResolver struct {
	checkRule func(int64) bool
	checkConv func(int64) bool
	ruleCache map[int64]bool
	convCache map[int64]bool
	warnRule  map[int64]bool
	warnConv  map[int64]bool
	warnings  *[]string
}

func newArchiveFKResolver(checkRule, checkConv func(int64) bool, warnings *[]string) *archiveFKResolver {
	return &archiveFKResolver{
		checkRule: checkRule,
		checkConv: checkConv,
		ruleCache: map[int64]bool{},
		convCache: map[int64]bool{},
		warnRule:  map[int64]bool{},
		warnConv:  map[int64]bool{},
		warnings:  warnings,
	}
}

func newTxArchiveFKResolver(tx *sql.Tx, warnings *[]string) *archiveFKResolver {
	return newArchiveFKResolver(
		func(id int64) bool { return rowExists(tx, "intercept_rules", id) },
		func(id int64) bool { return rowExists(tx, "conversations", id) },
		warnings,
	)
}

func (r *archiveFKResolver) ruleExists(id int64) bool {
	if r == nil || r.checkRule == nil {
		return true
	}
	if ok, cached := r.ruleCache[id]; cached {
		return ok
	}
	ok := r.checkRule(id)
	r.ruleCache[id] = ok
	return ok
}

func (r *archiveFKResolver) conversationExists(id int64) bool {
	if r == nil || r.checkConv == nil {
		return true
	}
	if ok, cached := r.convCache[id]; cached {
		return ok
	}
	ok := r.checkConv(id)
	r.convCache[id] = ok
	return ok
}

func (r *archiveFKResolver) warnMissingRule(id int64) {
	if r == nil || r.warnings == nil || r.warnRule[id] {
		return
	}
	r.warnRule[id] = true
	*r.warnings = append(*r.warnings, fmt.Sprintf("拦截规则 %d 已删除，审批记录中的规则关联已清空", id))
}

func (r *archiveFKResolver) warnMissingConversation(id int64, contextLabel string) {
	if r == nil || r.warnings == nil || r.warnConv[id] {
		return
	}
	r.warnConv[id] = true
	*r.warnings = append(*r.warnings, fmt.Sprintf("对话 %d 已删除，%s中的对话关联已清空", id, contextLabel))
}

func normalizeInterceptRow(raw json.RawMessage, now time.Time) (json.RawMessage, error) {
	return normalizeInterceptRowWithFKs(raw, now, nil)
}

func normalizeInterceptRowWithFKs(raw json.RawMessage, now time.Time, fk *archiveFKResolver) (json.RawMessage, error) {
	row, err := decodeArchiveObject(raw)
	if err != nil {
		return nil, err
	}
	changed := false
	// Archives predating approval snapshots lack this NOT NULL column.
	// Infer decision_source BEFORE clearing a deleted rule_id so historical
	// attribution stays accurate.
	if source, _ := row["decision_source"].(string); source == "" {
		source = "unknown"
		if row["rule_id"] != nil {
			source = "rule"
		} else if reason, _ := row["reason"].(string); strings.HasPrefix(reason, "[模型]") {
			source = "model"
		}
		row["decision_source"] = source
		changed = true
	}
	if fk != nil {
		if ruleID, ok := jsonInt64(row["rule_id"]); ok && ruleID > 0 && !fk.ruleExists(ruleID) {
			row["rule_id"] = nil
			changed = true
			fk.warnMissingRule(ruleID)
		}
		if convID, ok := jsonInt64(row["conversation_id"]); ok && convID > 0 && !fk.conversationExists(convID) {
			row["conversation_id"] = nil
			changed = true
			fk.warnMissingConversation(convID, "审批记录")
		}
	}
	if status, _ := row["status"].(string); status == "pending" {
		row["status"] = "timeout"
		row["reason"] = "任务归档期间审批已超时"
		row["decided_at"] = now
		if audit, ok := row["audit"].(map[string]any); ok {
			audit["effective_action"] = "deny"
			audit["decision_reason"] = "任务归档期间审批已超时"
			audit["execution_status"] = "not_executed"
		}
		changed = true
	} else if audit, ok := row["audit"].(map[string]any); ok && audit["execution_status"] == "awaiting_result" {
		// An archived run cannot resume its former result callback.
		audit["execution_status"] = "unknown"
		changed = true
	}
	if !changed {
		return raw, nil
	}
	encoded, err := json.Marshal(row)
	if err != nil {
		return nil, err
	}
	return json.RawMessage(encoded), nil
}

func normalizeFindingRetestRow(raw json.RawMessage, now time.Time, fk *archiveFKResolver) (json.RawMessage, error) {
	row, err := decodeArchiveObject(raw)
	if err != nil {
		return nil, err
	}
	changed := false
	if fk != nil {
		if convID, ok := jsonInt64(row["conversation_id"]); ok && convID > 0 && !fk.conversationExists(convID) {
			row["conversation_id"] = nil
			changed = true
			fk.warnMissingConversation(convID, "漏洞复测记录")
		}
	}
	if status, _ := row["status"].(string); status == "pending" || status == "running" {
		row["status"] = "stopped"
		if errMsg, _ := row["error"].(string); errMsg == "" {
			row["error"] = "任务归档期间复测已中断"
		}
		if row["finished_at"] == nil {
			row["finished_at"] = now
		}
		changed = true
	}
	if row["snapshot"] == nil {
		row["snapshot"] = map[string]any{}
		changed = true
	}
	if !changed {
		return raw, nil
	}
	encoded, err := json.Marshal(row)
	if err != nil {
		return nil, err
	}
	return json.RawMessage(encoded), nil
}

// reconcileTaskTokenCounterTx sets task_token_counters.tokens_used for taskID
// directly from the restored llm_usage rows so restored tasks always have exact
// token totals with zero double-counting regardless of prior counter state.
func reconcileTaskTokenCounterTx(tx *sql.Tx, taskID int64) error {
	var hasUsage bool
	if err := tx.QueryRow(`SELECT to_regclass('llm_usage') IS NOT NULL`).Scan(&hasUsage); err != nil {
		return err
	}
	if !hasUsage {
		return nil
	}
	_, err := tx.Exec(`
INSERT INTO task_token_counters(task_id, tokens_used)
SELECT $1, COALESCE(SUM(input_tokens::bigint + output_tokens::bigint), 0)
FROM llm_usage
WHERE task_id = $2
ON CONFLICT (task_id) DO UPDATE
    SET tokens_used = EXCLUDED.tokens_used`, taskID, strconv.FormatInt(taskID, 10))
	return err
}

func restoreExplorationStub(tx *sql.Tx, raw json.RawMessage, expID int64) error {
	_, err := tx.Exec(`UPDATE explorations current SET
 description=archived.description,goal=archived.goal,status=archived.status,
 created_at=archived.created_at,updated_at=archived.updated_at
FROM json_populate_record(NULL::explorations,$2::json) archived
WHERE current.id=$1 AND archived.id=$1`, expID, string(firstArchiveRow(raw)))
	return err
}

func restoreTaskStub(tx *sql.Tx, row map[string]any, taskID, remaining int64) error {
	raw, err := json.Marshal(row)
	if err != nil {
		return err
	}
	_, err = tx.Exec(`UPDATE tasks current SET
 name=archived.name,category_id=archived.category_id,description=archived.description,goal=archived.goal,
 status=archived.status,paused=archived.paused,queued=false,queued_at=NULL,queue_mode='',
 llm_profile_id=archived.llm_profile_id,active_llm_profile_id=archived.active_llm_profile_id,
 llm_chain_revision=archived.llm_chain_revision,company_id=archived.company_id,parent_ref=archived.parent_ref,
 timeout_seconds=archived.timeout_seconds,plan_heartbeat_seconds=archived.plan_heartbeat_seconds,
 token_budget_limit=COALESCE(archived.token_budget_limit,0),token_budget_revision=COALESCE(archived.token_budget_revision,1),
 coverage_enabled=archived.coverage_enabled,pinned_at=archived.pinned_at,first_run_at=archived.first_run_at,
 deadline_at=CASE WHEN archived.paused AND $3>0 THEN now()+make_interval(secs=>$3::double precision)
                  ELSE archived.deadline_at END,
 deleted_at=NULL,archived_at=NULL,completed_at=archived.completed_at,
 created_at=archived.created_at,updated_at=archived.updated_at
FROM json_populate_record(NULL::tasks,$2::json) archived
WHERE current.id=$1 AND archived.id=$1`, taskID, string(raw), remaining)
	return err
}

func firstArchiveRow(raw json.RawMessage) json.RawMessage {
	var rows []json.RawMessage
	if json.Unmarshal(raw, &rows) != nil || len(rows) == 0 {
		return json.RawMessage("{}")
	}
	return rows[0]
}

func decodeArchiveRows(raw json.RawMessage) ([]map[string]any, error) {
	if len(raw) == 0 {
		return nil, nil
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	var rows []map[string]any
	if err := decoder.Decode(&rows); err != nil {
		return nil, err
	}
	return rows, nil
}

func rowExists(tx *sql.Tx, table string, id int64) bool {
	switch table {
	case "task_categories", "llm_profiles", "companies", "tasks", "assets", "intercept_rules", "conversations":
	default:
		return false
	}
	var exists bool
	_ = tx.QueryRow(`SELECT EXISTS(SELECT 1 FROM `+table+` WHERE id=$1)`, id).Scan(&exists)
	return exists
}

func restoreArchiveAssetsStreamed(tx *sql.Tx, taskID int64, streamTable archiveBatchStreamer) (map[int64]int64, []string, error) {
	mapping := make(map[int64]int64)
	warnings := []string{}
	_, err := streamTable("assets", func(batch []json.RawMessage) error {
		for _, rawRow := range batch {
			row, err := decodeArchiveObject(rawRow)
			if err != nil {
				return err
			}
			oldID, ok := jsonInt64(row["id"])
			if !ok || oldID <= 0 {
				return errors.New("archived asset has invalid id")
			}
			if companyID, ok := jsonInt64(row["company_id"]); ok && companyID > 0 && !rowExists(tx, "companies", companyID) {
				row["company_id"] = nil
				row["company_source"] = "explicit"
				warnings = append(warnings, fmt.Sprintf("资产 %d 的企业 %d 已删除，已恢复为未归属", oldID, companyID))
			}
			if existing, found, err := findArchiveAssetNaturalID(tx, row); err != nil {
				return err
			} else if found {
				mapping[oldID] = existing
				if _, err := tx.Exec(`UPDATE assets SET task_ids=CASE WHEN $1=ANY(task_ids) THEN task_ids ELSE array_append(task_ids,$1) END WHERE id=$2`, taskID, existing); err != nil {
					return err
				}
				continue
			}
			candidate := oldID
			if rowExists(tx, "assets", oldID) {
				if err := tx.QueryRow(`SELECT nextval(pg_get_serial_sequence('assets','id'))`).Scan(&candidate); err != nil {
					return err
				}
				row["id"] = candidate
				warnings = append(warnings, fmt.Sprintf("资产 ID %d 已被占用，恢复为 %d", oldID, candidate))
			}
			row["task_ids"] = mergeJSONTaskID(row["task_ids"], taskID)
			assetRaw, err := json.Marshal(row)
			if err != nil {
				return err
			}
			res, err := tx.Exec(`INSERT INTO assets SELECT * FROM json_populate_record(NULL::assets,$1::json) ON CONFLICT DO NOTHING`, string(assetRaw))
			if err != nil {
				return err
			}
			inserted, _ := res.RowsAffected()
			if inserted == 0 {
				existing, found, findErr := findArchiveAssetNaturalID(tx, row)
				if findErr != nil || !found {
					return errors.Join(findErr, fmt.Errorf("could not restore asset %d", oldID))
				}
				candidate = existing
				if _, err := tx.Exec(`UPDATE assets SET task_ids=CASE WHEN $1=ANY(task_ids) THEN task_ids ELSE array_append(task_ids,$1) END WHERE id=$2`, taskID, existing); err != nil {
					return err
				}
			}
			mapping[oldID] = candidate
		}
		return nil
	})
	if err != nil {
		return nil, nil, err
	}
	return mapping, warnings, nil
}

func mergeJSONTaskID(value any, taskID int64) []int64 {
	out := []int64{}
	seen := map[int64]bool{}
	if values, ok := value.([]any); ok {
		for _, item := range values {
			if id, ok := jsonInt64(item); ok && id > 0 && !seen[id] {
				seen[id] = true
				out = append(out, id)
			}
		}
	}
	if !seen[taskID] {
		out = append(out, taskID)
	}
	return out
}

func findArchiveAssetNaturalID(tx *sql.Tx, row map[string]any) (int64, bool, error) {
	typeName, _ := row["type"].(string)
	stringValue := func(key string) string {
		value, _ := row[key].(string)
		return value
	}
	var query string
	var args []any
	switch typeName {
	case "root_domain":
		query, args = `SELECT id FROM assets WHERE type='root_domain' AND domain=$1`, []any{stringValue("domain")}
	case "ip":
		query, args = `SELECT id FROM assets WHERE type='ip' AND ip=$1`, []any{stringValue("ip")}
	case "subdomain":
		query, args = `SELECT id FROM assets WHERE type='subdomain' AND domain=$1 AND COALESCE(record_type,'')=$2`, []any{stringValue("domain"), stringValue("record_type")}
	case "app":
		if bundle := stringValue("bundle_id"); bundle != "" {
			query, args = `SELECT id FROM assets WHERE type='app' AND bundle_id=$1`, []any{bundle}
		} else {
			query, args = `SELECT id FROM assets WHERE type='app' AND bundle_id IS NULL AND app_name=$1`, []any{stringValue("app_name")}
		}
	case "service":
		if stringValue("service_type") == "http" {
			query, args = `SELECT id FROM assets WHERE type='service' AND service_type='http' AND url=$1`, []any{stringValue("url")}
		} else {
			port, _ := jsonInt64(row["port"])
			query, args = `SELECT id FROM assets WHERE type='service' AND service_type='other' AND COALESCE(domain,'')=$1 AND COALESCE(ip,'')=$2 AND port=$3 AND service_name=$4`, []any{stringValue("domain"), stringValue("ip"), port, stringValue("service_name")}
		}
	case "endpoint":
		query, args = `SELECT id FROM assets WHERE type='endpoint' AND url=$1 AND method=$2`, []any{stringValue("url"), stringValue("method")}
	default:
		return 0, false, fmt.Errorf("unsupported archived asset type %q", typeName)
	}
	var id int64
	err := tx.QueryRow(query, args...).Scan(&id)
	if errors.Is(err, sql.ErrNoRows) {
		return 0, false, nil
	}
	return id, err == nil, err
}

func restoreTaskRelations(tx *sql.Tx, taskID int64, raw json.RawMessage) ([]string, error) {
	rows, err := decodeArchiveRows(raw)
	if err != nil {
		return nil, err
	}
	warnings := []string{}
	for _, row := range rows {
		sourceID, ok := jsonInt64(row["source_task_id"])
		if !ok || !liveTaskExists(tx, sourceID) {
			warnings = append(warnings, fmt.Sprintf("来源任务 %d 不可用，继承关系已跳过", sourceID))
			continue
		}
		created, _ := row["created_at"].(string)
		if _, err := tx.Exec(`INSERT INTO task_relations(task_id,source_task_id,created_at) VALUES($1,$2,COALESCE($3::timestamptz,now())) ON CONFLICT DO NOTHING`, taskID, sourceID, nilIfEmptyString(created)); err != nil {
			return nil, err
		}
	}
	return warnings, nil
}

func restoreTaskScopes(tx *sql.Tx, raw json.RawMessage) ([]string, error) {
	if len(bytes.TrimSpace(raw)) == 0 {
		return []string{}, nil
	}
	warnings := []string{}
	_, err := streamJSONArrayBatches(bytes.NewReader(raw), archiveRestoreBatchSize, archiveRestoreBatchMaxBytes, func(batch []json.RawMessage) error {
		kept := make([]json.RawMessage, 0, len(batch))
		for _, rawRow := range batch {
			row, err := decodeArchiveObject(rawRow)
			if err != nil {
				return err
			}
			if companyID, ok := jsonInt64(row["company_id"]); ok && companyID > 0 && !rowExists(tx, "companies", companyID) {
				warnings = append(warnings, fmt.Sprintf("企业 %d 已删除，关联范围已跳过", companyID))
				continue
			}
			kept = append(kept, rawRow)
		}
		if len(kept) == 0 {
			return nil
		}
		payload := marshalJSONBatch(kept)
		_, err := tx.Exec(`INSERT INTO task_scope SELECT * FROM json_populate_recordset(NULL::task_scope,$1::json) ON CONFLICT DO NOTHING`, string(payload))
		return err
	})
	return warnings, err
}

func restoreTaskLLMProfiles(tx *sql.Tx, raw json.RawMessage) ([]string, error) {
	rows, err := decodeArchiveRows(raw)
	if err != nil {
		return nil, err
	}
	warnings := []string{}
	position := 0
	for _, row := range rows {
		profileID, ok := jsonInt64(row["profile_id"])
		if !ok || !rowExists(tx, "llm_profiles", profileID) {
			warnings = append(warnings, fmt.Sprintf("LLM 配置 %d 已删除，配置链项已跳过", profileID))
			continue
		}
		taskID, _ := jsonInt64(row["task_id"])
		status, _ := row["status"].(string)
		lastError, _ := row["last_error"].(string)
		exhaustedAt, _ := row["exhausted_at"].(string)
		createdAt, _ := row["created_at"].(string)
		updatedAt, _ := row["updated_at"].(string)
		if _, err := tx.Exec(`INSERT INTO task_llm_profiles(task_id,profile_id,position,status,last_error,exhausted_at,created_at,updated_at)
	VALUES($1,$2,$3,$4,NULLIF($5,''),$6::timestamptz,COALESCE($7::timestamptz,now()),COALESCE($8::timestamptz,now()))
	ON CONFLICT DO NOTHING`, taskID, profileID, position, status, lastError,
			nilIfEmptyString(exhaustedAt), nilIfEmptyString(createdAt), nilIfEmptyString(updatedAt)); err != nil {
			return nil, err
		}
		position++
	}
	return warnings, nil
}

func liveTaskExists(tx *sql.Tx, id int64) bool {
	var exists bool
	_ = tx.QueryRow(`SELECT EXISTS(SELECT 1 FROM tasks WHERE id=$1 AND deleted_at IS NULL)`, id).Scan(&exists)
	return exists
}

func nilIfEmptyString(value string) any {
	if strings.TrimSpace(value) == "" {
		return nil
	}
	return value
}

// CompleteTaskArchiveRestore removes compact metadata after every external
// component has been verified and the package has been consumed.
func (d *DB) CompleteTaskArchiveRestore(archiveID int64) error {
	res, err := d.Exec(`DELETE FROM task_archives archive USING tasks task
WHERE archive.id=$1 AND archive.task_id=task.id AND task.deleted_at IS NULL AND task.archived_at IS NULL`, archiveID)
	if err != nil {
		return err
	}
	n, _ := res.RowsAffected()
	if n != 1 {
		return ErrTaskArchiveState
	}
	return nil
}

// DeleteTaskArchiveStub permanently removes the cold task after its package has
// been staged for deletion. Dependency protection is rechecked transactionally.
func (d *DB) DeleteTaskArchiveStub(archiveID int64) error {
	tx, err := d.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback() //nolint:errcheck
	if err := SetMaintenanceTimeouts(context.Background(), tx); err != nil {
		return err
	}
	if err := coordinateWithSchemaMigration(tx); err != nil {
		return err
	}
	var taskID, expID int64
	var state string
	if err := tx.QueryRow(`SELECT archive.task_id,task.exploration_id,archive.state
FROM task_archives archive JOIN tasks task ON task.id=archive.task_id
WHERE archive.id=$1 FOR UPDATE OF archive,task`, archiveID).Scan(&taskID, &expID, &state); err != nil {
		return err
	}
	if state != Deleting {
		return ErrTaskArchiveState
	}
	var dependent int64
	err = tx.QueryRow(`SELECT task_id FROM task_archives WHERE id<>$1 AND source_task_ids @> ARRAY[$2]::bigint[] LIMIT 1`, archiveID, taskID).Scan(&dependent)
	if err == nil {
		return fmt.Errorf("%w: task %d", ErrTaskArchiveDeleteBlocked, dependent)
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return err
	}
	if _, err := tx.Exec(`DELETE FROM tasks WHERE id=$1 AND archived_at IS NOT NULL`, taskID); err != nil {
		return err
	}
	if _, err := tx.Exec(`DELETE FROM explorations WHERE id=$1`, expID); err != nil {
		return err
	}
	return tx.Commit()
}

// ArchivedAggregateStats returns compact summaries used by global dashboards so
// cold data does not disappear from historical totals.
func (d *DB) ArchivedAggregateStats() ([]json.RawMessage, error) {
	rows, err := d.Query(`SELECT archive.aggregate_stats
FROM task_archives archive
JOIN tasks task ON task.id=archive.task_id
WHERE task.archived_at IS NOT NULL`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []json.RawMessage
	for rows.Next() {
		var raw json.RawMessage
		if err := rows.Scan(&raw); err != nil {
			return nil, err
		}
		out = append(out, raw)
	}
	return out, rows.Err()
}
