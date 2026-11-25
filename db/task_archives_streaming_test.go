package db

import (
	"bytes"
	"context"
	"database/sql/driver"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgconn"
)

func TestTaskArchiveStreamingNDJSONBatches(t *testing.T) {
	t.Run("chunks 1250 rows into 500-500-250 batches", func(t *testing.T) {
		var buf bytes.Buffer
		for i := 1; i <= 1250; i++ {
			if i == 100 {
				buf.WriteString("\n   \n") // blank lines must be skipped cleanly
			}
			fmt.Fprintf(&buf, `{"id":%d,"msg":"row-%d"}`+"\n", i, i)
		}

		var batchSizes []int
		var seenIDs []int64
		count, err := streamNDJSONBatches(&buf, archiveRestoreBatchSize, archiveRestoreBatchMaxBytes, func(batch []json.RawMessage) error {
			batchSizes = append(batchSizes, len(batch))
			payload := marshalJSONBatch(batch)
			var decoded []struct {
				ID  int64  `json:"id"`
				Msg string `json:"msg"`
			}
			if err := json.Unmarshal(payload, &decoded); err != nil {
				return err
			}
			for _, row := range decoded {
				seenIDs = append(seenIDs, row.ID)
			}
			return nil
		})
		if err != nil {
			t.Fatalf("streamNDJSONBatches: %v", err)
		}
		if count != 1250 || len(seenIDs) != 1250 {
			t.Fatalf("count=%d seen=%d, want 1250", count, len(seenIDs))
		}
		if fmt.Sprint(batchSizes) != "[500 500 250]" {
			t.Fatalf("batchSizes=%v, want [500 500 250]", batchSizes)
		}
		if seenIDs[0] != 1 || seenIDs[len(seenIDs)-1] != 1250 {
			t.Fatalf("order mismatch: first=%d last=%d", seenIDs[0], seenIDs[len(seenIDs)-1])
		}
	})

	t.Run("byte cap splits oversized rows safely", func(t *testing.T) {
		var buf bytes.Buffer
		big := strings.Repeat("x", 1024)
		for i := 0; i < 5; i++ {
			fmt.Fprintf(&buf, `{"id":%d,"body":"%s"}`+"\n", i, big)
		}
		var batchSizes []int
		count, err := streamNDJSONBatches(&buf, 500, 2200, func(batch []json.RawMessage) error {
			batchSizes = append(batchSizes, len(batch))
			return nil
		})
		if err != nil {
			t.Fatalf("byte-capped streamNDJSONBatches: %v", err)
		}
		if count != 5 || fmt.Sprint(batchSizes) != "[2 2 1]" {
			t.Fatalf("count=%d batchSizes=%v, want 5 / [2 2 1]", count, batchSizes)
		}
	})

	t.Run("empty input produces zero batches", func(t *testing.T) {
		called := false
		count, err := streamNDJSONBatches(strings.NewReader(" \n\t\n "), 500, 1<<20, func(batch []json.RawMessage) error {
			called = true
			return nil
		})
		if err != nil || count != 0 || called {
			t.Fatalf("empty input count=%d called=%v err=%v", count, called, err)
		}
	})

	t.Run("corrupt or non-object lines fail", func(t *testing.T) {
		for _, bad := range []string{
			"[1,2,3]\n",
			"{\"id\":1}\n{not valid json\n",
			"\"bare string\"\n",
		} {
			if _, err := streamNDJSONBatches(strings.NewReader(bad), 500, 1<<20, func(batch []json.RawMessage) error { return nil }); err == nil {
				t.Fatalf("expected error for corrupt NDJSON %q", bad)
			}
		}
	})
}

func TestChunkJSONArrayBatchesLegacyV1(t *testing.T) {
	t.Run("chunks 1250 inline JSON rows into 500-500-250 batches", func(t *testing.T) {
		rows := make([]json.RawMessage, 1250)
		for i := range rows {
			rows[i] = json.RawMessage(fmt.Sprintf(`{"id":%d,"label":"v1-%d"}`, i+1, i+1))
		}
		raw := marshalJSONBatch(rows)

		var batchSizes []int
		var lastID int64
		count, err := streamJSONArrayBatches(bytes.NewReader(raw), archiveRestoreBatchSize, archiveRestoreBatchMaxBytes, func(batch []json.RawMessage) error {
			batchSizes = append(batchSizes, len(batch))
			var decoded []struct {
				ID int64 `json:"id"`
			}
			if err := json.Unmarshal(marshalJSONBatch(batch), &decoded); err != nil {
				return err
			}
			lastID = decoded[len(decoded)-1].ID
			return nil
		})
		if err != nil {
			t.Fatalf("streamJSONArrayBatches: %v", err)
		}
		if count != 1250 || lastID != 1250 || fmt.Sprint(batchSizes) != "[500 500 250]" {
			t.Fatalf("count=%d lastID=%d batchSizes=%v", count, lastID, batchSizes)
		}
	})

	t.Run("empty, null, and [] inputs return zero", func(t *testing.T) {
		for _, raw := range []string{"", "   ", "null", "[]"} {
			count, err := streamJSONArrayBatches(strings.NewReader(raw), 500, 1<<20, func(batch []json.RawMessage) error {
				t.Fatalf("unexpected batch for %q", raw)
				return nil
			})
			if err != nil || count != 0 {
				t.Fatalf("input %q: count=%d err=%v", raw, count, err)
			}
		}
	})

	t.Run("rejects non-array and non-object elements", func(t *testing.T) {
		for _, bad := range []string{`{"id":1}`, `[1,2,3]`, `[{"id":1},`} {
			if _, err := streamJSONArrayBatches(strings.NewReader(bad), 500, 1<<20, func(batch []json.RawMessage) error { return nil }); err == nil {
				t.Fatalf("expected error for malformed JSON array %q", bad)
			}
		}
	})
}

func TestTaskArchiveStreamingValidationAndRawRowCount(t *testing.T) {
	if got := rawRowCount(nil); got != 0 {
		t.Fatalf("rawRowCount(nil)=%d, want 0", got)
	}
	if got := rawRowCount(json.RawMessage("[]")); got != 0 {
		t.Fatalf("rawRowCount([])=%d, want 0", got)
	}
	if got := rawRowCount(json.RawMessage(`[{"a":[1,2,{"b":"c"}]},{"d":4},{"e":null}]`)); got != 3 {
		t.Fatalf("rawRowCount nested=%d, want 3", got)
	}
	if got := rawRowCount(json.RawMessage(`{"not":"array"}`)); got != 0 {
		t.Fatalf("rawRowCount object=%d, want 0", got)
	}
	if got := rawRowCount(json.RawMessage(`[{"broken"`)); got != 0 {
		t.Fatalf("rawRowCount corrupt=%d, want 0", got)
	}

	validMultiTable := &TaskArchiveSnapshot{
		FormatVersion: TaskArchiveFormatVersion,
		StreamedTables: map[string]string{
			"activity":          TaskArchiveTablePath("activity"),
			"exploration_nodes": TaskArchiveTablePath("exploration_nodes"),
			"llm_records":       TaskArchiveTablePath("llm_records"),
		},
		NDJSONTables: map[string]int64{
			"activity":          10,
			"exploration_nodes": 5,
			"llm_records":       2,
		},
	}
	if err := ValidateTaskArchiveStreamedTables(validMultiTable); err != nil {
		t.Fatalf("valid multi-table snapshot rejected: %v", err)
	}

	validLegacyV2 := &TaskArchiveSnapshot{
		FormatVersion:  2,
		StreamedTables: map[string]string{"llm_records": TaskArchiveLLMRecordsPath},
	}
	if err := ValidateTaskArchiveStreamedTables(validLegacyV2); err != nil {
		t.Fatalf("valid legacy v2 snapshot rejected: %v", err)
	}

	invalidCases := []*TaskArchiveSnapshot{
		nil,
		{FormatVersion: 1, StreamedTables: map[string]string{"activity": TaskArchiveTablePath("activity")}},
		{FormatVersion: TaskArchiveFormatVersion, StreamedTables: map[string]string{"unknown_table": "tables/unknown_table.ndjson"}},
		{FormatVersion: TaskArchiveFormatVersion, StreamedTables: map[string]string{"activity": "../escape.ndjson"}},
		{FormatVersion: TaskArchiveFormatVersion, StreamedTables: map[string]string{"activity": TaskArchiveTablePath("findings")}},
		{FormatVersion: TaskArchiveFormatVersion, NDJSONTables: map[string]int64{"activity": 1}},
		{FormatVersion: TaskArchiveFormatVersion, StreamedTables: map[string]string{"activity": TaskArchiveTablePath("activity")}, NDJSONTables: map[string]int64{"activity": -1}},
	}
	for i, snap := range invalidCases {
		if err := ValidateTaskArchiveStreamedTables(snap); !errors.Is(err, ErrTaskArchiveFormatMismatch) {
			t.Fatalf("case %d: got %v, want ErrTaskArchiveFormatMismatch", i, err)
		}
	}
}

func TestTaskArchiveStreamingRowTransforms(t *testing.T) {
	mapping := map[int64]int64{10: 100, 20: 20}

	// Remap asset_id on exploration_anchors / task_asset_links.
	remappedAnchor, err := remapAssetIDField(json.RawMessage(`{"node_id":1,"asset_id":10}`), mapping)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(remappedAnchor), `"asset_id":100`) {
		t.Fatalf("anchor asset_id not remapped: %s", remappedAnchor)
	}

	// Remap payload.asset_ids on exploration_nodes.
	remappedNode, err := remapExplorationNodeAssetIDs(json.RawMessage(`{"id":5,"payload":{"asset_ids":[10,20]}}`), mapping)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(remappedNode), `[100,20]`) {
		t.Fatalf("node asset_ids not remapped: %s", remappedNode)
	}

	// Normalize finding versions + remap asset_ids.
	remappedFinding, err := normalizeAndRemapFindingRow(json.RawMessage(`{"id":7,"asset_ids":[10]}`), mapping, true)
	if err != nil {
		t.Fatal(err)
	}
	var findingObj map[string]any
	if err := json.Unmarshal(remappedFinding, &findingObj); err != nil {
		t.Fatal(err)
	}
	if findingObj["evidence_version"] != float64(0) || findingObj["report_evidence_version"] != float64(0) {
		t.Fatalf("finding versions not defaulted: %v", findingObj)
	}

	// Ensure side_question JSON fields default to {}.
	fixedSession, err := ensureArchiveJSONObjectField(json.RawMessage(`{"session_key":"k1"}`), "memory")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(fixedSession), `"memory":{}`) {
		t.Fatalf("side_question memory not defaulted: %s", fixedSession)
	}

	// Normalize pending intercept row to timeout.
	now := time.Date(2026, 5, 10, 12, 0, 0, 0, time.UTC)
	fixedIntercept, err := normalizeInterceptRow(json.RawMessage(`{"id":1,"status":"pending","reason":"[模型] check","audit":{"execution_status":"awaiting_result"}}`), now)
	if err != nil {
		t.Fatal(err)
	}
	var interceptObj map[string]any
	if err := json.Unmarshal(fixedIntercept, &interceptObj); err != nil {
		t.Fatal(err)
	}
	if interceptObj["status"] != "timeout" || interceptObj["decision_source"] != "model" {
		t.Fatalf("intercept row not normalized: %v", interceptObj)
	}
}

func TestBatchKeysetPagesAndDeleteInBatches(t *testing.T) {
	t.Run("keyset pagination stops at cutoff and handles gaps", func(t *testing.T) {
		// Simulate sparse IDs up to 1205.
		ids := make([]int64, 0, 1100)
		for i := int64(1); i <= 1100; i++ {
			ids = append(ids, i*2) // 2, 4, ..., 2200
		}
		cutoff := int64(1205)
		var pages int
		var visited []int64
		total, err := streamKeysetPages(context.Background(), cutoff, 500, func(_ context.Context, lastID, maxID int64, limit int) (int64, int64, error) {
			pages++
			var n int64
			cur := lastID
			for _, id := range ids {
				if id > lastID && id <= maxID {
					visited = append(visited, id)
					cur = id
					n++
					if int(n) == limit {
						break
					}
				}
			}
			return cur, n, nil
		})
		if err != nil {
			t.Fatalf("streamKeysetPages: %v", err)
		}
		if total != 602 || len(visited) != 602 || pages != 2 {
			t.Fatalf("total=%d visited=%d pages=%d, want 602/602/2", total, len(visited), pages)
		}
		if visited[len(visited)-1] != 1204 {
			t.Fatalf("last id=%d, want 1204", visited[len(visited)-1])
		}
	})

	t.Run("keyset pagination honors zero cutoff and context cancel", func(t *testing.T) {
		total, err := streamKeysetPages(context.Background(), 0, 500, func(context.Context, int64, int64, int) (int64, int64, error) {
			t.Fatal("fetch must not be called when cutoff is 0")
			return 0, 0, nil
		})
		if err != nil || total != 0 {
			t.Fatalf("zero cutoff total=%d err=%v", total, err)
		}

		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		if _, err := streamKeysetPages(ctx, 100, 500, func(context.Context, int64, int64, int) (int64, int64, error) {
			return 100, 1, nil
		}); !errors.Is(err, context.Canceled) {
			t.Fatalf("canceled ctx returned %v, want context.Canceled", err)
		}
	})

	t.Run("deleteInBatches loops until partial batch", func(t *testing.T) {
		remaining := int64(4500)
		var calls int
		deleted, err := deleteInBatches(func() (int64, error) {
			calls++
			if remaining >= 2000 {
				remaining -= 2000
				return 2000, nil
			}
			n := remaining
			remaining = 0
			return n, nil
		}, 2000)
		if err != nil || deleted != 4500 || calls != 3 {
			t.Fatalf("deleted=%d calls=%d err=%v, want 4500/3/nil", deleted, calls, err)
		}

		sentinel := errors.New("lock timeout")
		deleted, err = deleteInBatches(func() (int64, error) {
			return 0, sentinel
		}, 2000)
		if !errors.Is(err, sentinel) || deleted != 0 {
			t.Fatalf("error propagation deleted=%d err=%v", deleted, err)
		}
	})
}

func TestArchiveCompactingStateRecoveryAndResume(t *testing.T) {
	if ArchiveCompacting != "compacting" {
		t.Fatalf("ArchiveCompacting=%q want compacting", ArchiveCompacting)
	}
	if strings.Contains(recoverTaskArchiveJobsSQL, "'compacting'") &&
		!strings.Contains(recoverTaskArchiveJobsSQL, "THEN 'compacting'") {
		t.Fatalf("recoverTaskArchiveJobsSQL unexpectedly handles compacting: %s", recoverTaskArchiveJobsSQL)
	}
	if strings.Contains(recoverTaskArchiveJobsSQL, "WHERE a.state IN ('archiving','compacting'") {
		t.Fatalf("recoverTaskArchiveJobsSQL must never downgrade compacting rows: %s", recoverTaskArchiveJobsSQL)
	}
	if !strings.Contains(failTaskArchiveJobSQL, "CASE WHEN state = $4 THEN state ELSE $2 END") ||
		!strings.Contains(failTaskArchiveJobSQL, "CASE WHEN state = $4 THEN phase ELSE 'failed' END") {
		t.Fatalf("failTaskArchiveJobSQL must preserve compacting state/phase: %s", failTaskArchiveJobSQL)
	}

	t.Run("FailTaskArchiveJob_accepts_compacting_and_guards_sql", func(t *testing.T) {
		st := &stubSQLState{}
		d := st.openDB()
		defer d.Close()

		if err := d.FailTaskArchiveJob(7, ArchiveCompacting, errors.New("transient io")); err != nil {
			t.Fatalf("FailTaskArchiveJob(compacting): %v", err)
		}
		events := st.snapshotEvents()
		if len(events) != 1 || events[0].args[1] != ArchiveCompacting || events[0].args[3] != ArchiveCompacting {
			t.Fatalf("unexpected FailTaskArchiveJob args: %+v", events)
		}
		if err := d.FailTaskArchiveJob(7, "bogus", errors.New("x")); err == nil {
			t.Fatal("expected error for unknown active state")
		}
	})

	t.Run("ResumeCompactingTaskArchives_drives_compacting_to_ready_and_ignores_42P01", func(t *testing.T) {
		var sawMaintenance, sawReady, sawArchivedAt bool
		st := &stubSQLState{
			queryHandler: func(_ int, _ bool, query string, _ []any) ([]string, [][]driver.Value, error) {
				if strings.Contains(query, "FROM task_archives a") {
					return []string{"id", "task_id", "exploration_id"}, [][]driver.Value{{int64(99), int64(42), int64(100)}}, nil
				}
				return []string{"col"}, nil, nil
			},
			execHandler: func(_ int, _ bool, query string, args []any) (driver.Result, error) {
				if query == maintenanceLocalTimeoutsSQL {
					sawMaintenance = true
				}
				if strings.Contains(query, "DELETE FROM llm_records") || strings.Contains(query, "DELETE FROM llm_usage") {
					return nil, &pgconn.PgError{Code: "42P01", Message: "undefined_table"}
				}
				if strings.Contains(query, "UPDATE tasks SET archived_at=now()") {
					sawArchivedAt = true
				}
				if strings.Contains(query, "UPDATE task_archives SET") && len(args) >= 2 && args[1] == ArchiveReady {
					sawReady = true
				}
				return driver.RowsAffected(0), nil
			},
		}
		d := st.openDB()
		defer d.Close()

		resumed, err := d.ResumeCompactingTaskArchives(t.Context())
		if err != nil || resumed != 1 {
			t.Fatalf("ResumeCompactingTaskArchives resumed=%d err=%v, want 1/nil", resumed, err)
		}
		if !sawMaintenance || !sawArchivedAt || !sawReady {
			t.Fatalf("missing compaction steps: maintenance=%v archivedAt=%v ready=%v", sawMaintenance, sawArchivedAt, sawReady)
		}
	})
}

func TestNormalizeInterceptRowFKResilience(t *testing.T) {
	now := time.Date(2026, 6, 1, 12, 0, 0, 0, time.UTC)
	var warnings []string
	ruleChecks := 0
	convChecks := 0
	fk := newArchiveFKResolver(
		func(id int64) bool {
			ruleChecks++
			return id == 10
		},
		func(id int64) bool {
			convChecks++
			return id == 20
		},
		&warnings,
	)

	// Row 1: missing rule_id=99 and missing conversation_id=88; decision_source
	// omitted so it must STILL infer "rule" before clearing rule_id!
	out1, err := normalizeInterceptRowWithFKs(
		json.RawMessage(`{"id":1,"rule_id":99,"conversation_id":88,"status":"allowed","reason":"matched"}`),
		now, fk,
	)
	if err != nil {
		t.Fatal(err)
	}
	var obj1 map[string]any
	if err := json.Unmarshal(out1, &obj1); err != nil {
		t.Fatal(err)
	}
	if obj1["rule_id"] != nil || obj1["conversation_id"] != nil {
		t.Fatalf("missing FKs were not cleared: %v", obj1)
	}
	if obj1["decision_source"] != "rule" {
		t.Fatalf("decision_source=%v want rule (inferred before clearing deleted rule_id)", obj1["decision_source"])
	}

	// Row 2: same missing rule_id=99 & conv=88 -> cached checks and deduplicated warnings.
	if _, err := normalizeInterceptRowWithFKs(
		json.RawMessage(`{"id":2,"rule_id":99,"conversation_id":88,"status":"denied","decision_source":"rule"}`),
		now, fk,
	); err != nil {
		t.Fatal(err)
	}
	if ruleChecks != 1 || convChecks != 1 {
		t.Fatalf("FK checks not memoized: ruleChecks=%d convChecks=%d", ruleChecks, convChecks)
	}
	if len(warnings) != 2 {
		t.Fatalf("expected 2 deduplicated warnings, got %d: %v", len(warnings), warnings)
	}

	// Row 3: existing rule_id=10 and conversation_id=20 -> preserved untouched.
	out3, err := normalizeInterceptRowWithFKs(
		json.RawMessage(`{"id":3,"rule_id":10,"conversation_id":20,"status":"allowed","decision_source":"rule"}`),
		now, fk,
	)
	if err != nil {
		t.Fatal(err)
	}
	var obj3 map[string]any
	if err := json.Unmarshal(out3, &obj3); err != nil {
		t.Fatal(err)
	}
	if obj3["rule_id"] != float64(10) || obj3["conversation_id"] != float64(20) {
		t.Fatalf("existing FKs should be preserved: %v", obj3)
	}
	if len(warnings) != 2 {
		t.Fatalf("unexpected warnings for existing FKs: %v", warnings)
	}
}

func TestFindingRetestsArchiveSupportAndNormalization(t *testing.T) {
	if !streamableArchiveTables["finding_retests"] || !allowedArchiveRestoreTables["finding_retests"] {
		t.Fatal("finding_retests must be registered in streamableArchiveTables and allowedArchiveRestoreTables")
	}
	snap := &TaskArchiveSnapshot{
		FormatVersion:  TaskArchiveFormatVersion,
		StreamedTables: map[string]string{"finding_retests": TaskArchiveTablePath("finding_retests")},
		NDJSONTables:   map[string]int64{"finding_retests": 3},
	}
	if err := ValidateTaskArchiveStreamedTables(snap); err != nil {
		t.Fatalf("finding_retests streamed table rejected: %v", err)
	}

	now := time.Date(2026, 6, 1, 12, 0, 0, 0, time.UTC)
	var warnings []string
	fk := newArchiveFKResolver(nil, func(id int64) bool { return id == 5 }, &warnings)

	// Missing conversation + running status -> conv nulled with warning, status stopped.
	out, err := normalizeFindingRetestRow(
		json.RawMessage(`{"id":1,"finding_id":10,"conversation_id":404,"status":"running","verdict":"","error":""}`),
		now, fk,
	)
	if err != nil {
		t.Fatal(err)
	}
	var obj map[string]any
	if err := json.Unmarshal(out, &obj); err != nil {
		t.Fatal(err)
	}
	if obj["conversation_id"] != nil || obj["status"] != "stopped" || obj["finished_at"] == nil || obj["snapshot"] == nil {
		t.Fatalf("finding_retests row not normalized: %v", obj)
	}
	if len(warnings) != 1 {
		t.Fatalf("expected 1 missing conversation warning, got %v", warnings)
	}

	// Completed row with valid conversation -> preserved verbatim.
	rawCompleted := json.RawMessage(`{"id":2,"finding_id":10,"conversation_id":5,"status":"completed","verdict":"fixed","snapshot":{"finding":{"id":10}}}`)
	outCompleted, err := normalizeFindingRetestRow(rawCompleted, now, fk)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(outCompleted, rawCompleted) {
		t.Fatalf("completed retest row unexpectedly mutated: %s", outCompleted)
	}
}

func TestDeleteTaskTombstonedAndSweepOrphans(t *testing.T) {
	t.Run("DeleteTaskCascadePrepared_marks_Tombstoned_before_phase2_failure", func(t *testing.T) {
		st := &stubSQLState{
			queryHandler: func(_ int, _ bool, query string, _ []any) ([]string, [][]driver.Value, error) {
				if strings.Contains(query, "SELECT exploration_id FROM tasks WHERE id=$1") {
					return []string{"exploration_id"}, [][]driver.Value{{int64(77)}}, nil
				}
				return []string{"col"}, nil, nil
			},
			execHandler: func(_ int, _ bool, query string, _ []any) (driver.Result, error) {
				if strings.Contains(query, "DELETE FROM llm_records") {
					return nil, &pgconn.PgError{Code: "42P01", Message: "undefined_table"}
				}
				if strings.Contains(query, "DELETE FROM activity") {
					return nil, errors.New("simulated phase 2 error")
				}
				return driver.RowsAffected(0), nil
			},
		}
		d := st.openDB()
		defer d.Close()

		res, err := d.DeleteTaskCascadePrepared(55, false, false, true, nil)
		if err == nil || !strings.Contains(err.Error(), "simulated phase 2 error") {
			t.Fatalf("expected phase 2 error, got %v", err)
		}
		if !res.Tombstoned {
			t.Fatal("expected res.Tombstoned=true after Phase 1 committed")
		}
	})

	t.Run("SweepOrphanedDeletedTasks_cleans_tombstoned_tasks", func(t *testing.T) {
		var deletedTaskID, deletedExpID int64
		st := &stubSQLState{
			queryHandler: func(_ int, _ bool, query string, _ []any) ([]string, [][]driver.Value, error) {
				if strings.Contains(query, "FROM tasks t") && strings.Contains(query, "NOT EXISTS (SELECT 1 FROM task_archives") {
					return []string{"id", "exploration_id"}, [][]driver.Value{{int64(88), int64(188)}}, nil
				}
				return []string{"col"}, nil, nil
			},
			execHandler: func(_ int, _ bool, query string, args []any) (driver.Result, error) {
				if query == `DELETE FROM tasks WHERE id=$1` && len(args) == 1 {
					deletedTaskID, _ = args[0].(int64)
				}
				if query == `DELETE FROM explorations WHERE id=$1` && len(args) == 1 {
					deletedExpID, _ = args[0].(int64)
				}
				return driver.RowsAffected(0), nil
			},
		}
		d := st.openDB()
		defer d.Close()

		swept, err := d.SweepOrphanedDeletedTasks(t.Context())
		if err != nil || swept != 1 {
			t.Fatalf("SweepOrphanedDeletedTasks swept=%d err=%v, want 1/nil", swept, err)
		}
		if deletedTaskID != 88 || deletedExpID != 188 {
			t.Fatalf("deletedTaskID=%d deletedExpID=%d want 88/188", deletedTaskID, deletedExpID)
		}
	})
}
