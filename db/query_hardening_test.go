package db

import (
	"strings"
	"testing"
)

func TestActivitySessionFilterMainSegIndexFriendly(t *testing.T) {
	cond, args := (ActivitySessionFilter{Main: true}).cond(2)
	if strings.Contains(cond, "COALESCE") {
		t.Fatalf("seg 0 filter wraps main_seg in COALESCE: %q", cond)
	}
	if cond != " AND worker='mainagent' AND (main_seg = 0 OR main_seg IS NULL)" {
		t.Fatalf("unexpected seg 0 filter: %q", cond)
	}
	if len(args) != 0 {
		t.Fatalf("unexpected args for seg 0: %v", args)
	}

	seg := 3
	cond, args = (ActivitySessionFilter{Main: true, MainSeg: &seg}).cond(2)
	if cond != " AND worker='mainagent' AND main_seg=$2" || len(args) != 1 || args[0] != 3 {
		t.Fatalf("unexpected non-zero seg filter: cond=%q args=%v", cond, args)
	}
}

func TestDSLTaskIDUsesGINContainment(t *testing.T) {
	node, err := ParseDSL("task_id=42")
	if err != nil {
		t.Fatal(err)
	}
	where, args, err := buildDSLWhere(node)
	if err != nil {
		t.Fatal(err)
	}
	if where != "task_ids @> ARRAY[$1]::bigint[]" {
		t.Fatalf("task_id DSL clause=%q want GIN containment", where)
	}
	if len(args) != 1 || args[0] != int64(42) {
		t.Fatalf("task_id DSL args=%v want [42]", args)
	}
}

func TestArchiveAssetIDsQueryUsesGINContainment(t *testing.T) {
	q := archiveAssetIDsQuery()
	if !strings.Contains(q, "task_ids @> ARRAY[$1]::bigint[]") {
		t.Fatalf("archiveAssetIDsQuery must use GIN containment: %s", q)
	}
	if strings.Contains(q, "ANY(task_ids)") {
		t.Fatalf("archiveAssetIDsQuery still uses ANY(task_ids): %s", q)
	}
}

func TestClampRecordPageSize(t *testing.T) {
	cases := map[int]int{
		-10: 50,
		0:   50,
		1:   1,
		50:  50,
		200: 200,
		201: 200,
		999: 200,
	}
	for in, want := range cases {
		if got := clampRecordPageSize(in); got != want {
			t.Fatalf("clampRecordPageSize(%d)=%d want %d", in, got, want)
		}
	}
}

func TestSchemaHardeningDefinitions(t *testing.T) {
	if !strings.Contains(schemaSQL, "LANGUAGE sql STABLE") {
		t.Fatal("schema.sql try_inet must be declared LANGUAGE sql STABLE")
	}
	if strings.Contains(schemaSQL, "IMMUTABLE STRICT") {
		t.Fatal("schema.sql try_inet must not use IMMUTABLE STRICT over STABLE pg_input_is_valid")
	}
	if !strings.Contains(schemaSQL, "pg_input_is_valid(value, 'pg_catalog.inet')") {
		t.Fatal("schema.sql try_inet must qualify pg_catalog.inet")
	}
	if strings.Contains(schemaSQL, "EXCEPTION WHEN others") {
		t.Fatal("schema.sql still contains subtransaction-heavy EXCEPTION WHEN others")
	}

	requiredIndexes := []string{
		"idx_findings_node_id",
		"idx_notification_deliveries_due_v2",
		"idx_notification_deliveries_state_sent",
		"idx_notification_deliveries_event",
		"idx_notification_deliveries_terminal_created",
		"DROP INDEX IF EXISTS idx_notification_deliveries_history",
		"idx_notification_events_fanned_created",
		"idx_server_logs_created",
		"idx_intercept_pending_decided_at",
		"idx_expnodes_running_intent",
		"idx_expnodes_kind_state_id",
		"idx_act_tool_result_id",
		"idx_skill_usage_exp",
		"idx_tool_usage_exp",
		"idx_intercept_pending_created",
		"DROP INDEX IF EXISTS idx_server_logs_id",
		"ALTER TABLE task_archives ALTER COLUMN format_version SET DEFAULT 3;",
		"'compacting'",
	}
	for _, needle := range requiredIndexes {
		if !strings.Contains(schemaSQL, needle) {
			t.Fatalf("schema.sql missing %q", needle)
		}
	}
	if strings.Contains(schemaSQL, "CREATE INDEX IF NOT EXISTS idx_server_logs_id") {
		t.Fatal("schema.sql still creates redundant idx_server_logs_id")
	}
	if strings.Contains(schemaSQL, "CREATE INDEX IF NOT EXISTS idx_notification_deliveries_history") {
		t.Fatal("schema.sql still creates redundant idx_notification_deliveries_history")
	}

	taskColIdx := strings.Index(llmRecordsMigrate, "ADD COLUMN IF NOT EXISTS task_id")
	taskIdxPos := strings.Index(llmRecordsMigrate, "idx_llm_records_task_id")
	modelIdxPos := strings.Index(llmRecordsMigrate, "idx_llm_records_model_id")
	autovacIdxPos := strings.Index(llmRecordsMigrate, "ALTER TABLE llm_records SET (autovacuum_vacuum_scale_factor = 0.05, autovacuum_analyze_scale_factor = 0.02);")
	if taskColIdx < 0 || taskIdxPos < taskColIdx || modelIdxPos < 0 || autovacIdxPos < 0 {
		t.Fatalf("llmRecordsMigrate missing indexes/autovacuum or wrong order: %s", llmRecordsMigrate)
	}

	for _, needle := range []string{"idx_llm_usage_ts", "idx_llm_usage_worker_ts"} {
		if !strings.Contains(llmUsageSchema, needle) {
			t.Fatalf("llmUsageSchema missing %q", needle)
		}
	}

	if !strings.Contains(explorationEdgesKeysetFirstSQL, "ORDER BY src_id ASC, rel ASC, dst_id ASC") ||
		!strings.Contains(explorationEdgesKeysetNextSQL, "(src_id, rel, dst_id) > ($3, $4, $5) ORDER BY src_id ASC, rel ASC, dst_id ASC") {
		t.Fatalf("explorationEdgesKeyset SQL must match PK (src_id, rel, dst_id)")
	}
}
