package db

import (
	"context"
	"database/sql"
	"errors"
	"strings"
	"testing"
	"unicode/utf8"
)

func TestLogQueriesRespectCancellation(t *testing.T) {
	// An already cancelled request must return without opening a connection.
	pool, err := sql.Open("pgx", "postgres://unused.invalid/test")
	if err != nil {
		t.Fatal(err)
	}
	defer pool.Close()
	d := &DB{pool}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	_, readErr := d.RecentLogsContext(ctx, 1)
	_, pageErr := d.ListLogsBeforeContext(ctx, 2, 1)
	_, writeErr := d.InsertLogContext(ctx, "info", "", "test")
	_, batchErr := d.InsertLogsBatchContext(ctx, []LogBatchEntry{{Level: "info", Tag: "pg", Text: "batch"}})
	_, emptyBatchErr := d.InsertLogsBatchContext(ctx, nil)
	for _, err := range []error{readErr, pageErr, writeErr, batchErr, emptyBatchErr} {
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("expected cancellation, got %v", err)
		}
	}
	if ids, err := d.InsertLogsBatchContext(t.Context(), nil); err != nil || len(ids) != 0 {
		t.Fatalf("empty batch = (%v, %v), want (nil, nil)", ids, err)
	}
	if pool.Stats().OpenConnections != 0 {
		t.Fatal("cancelled queries opened a connection")
	}
}

func TestLogHistoryBoundsLegacyRows(t *testing.T) {
	d, err := Open(testDSN(t))
	if err != nil {
		t.Fatal(err)
	}
	defer d.Close()
	tag := strings.Repeat("x", 9000)
	text := strings.Repeat("界", 9000)
	var older int64
	err = d.QueryRow("INSERT INTO server_logs(level,tag,text) VALUES('info',$1,$2) RETURNING id", tag, text).Scan(&older)
	if err != nil {
		t.Fatal(err)
	}
	newer, err := d.InsertLogContext(t.Context(), "info", tag, text)
	if err != nil {
		t.Fatal(err)
	}
	rows, err := d.ListLogsBeforeContext(t.Context(), newer+1, 2)
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 2 || rows[0].ID != older || rows[1].ID != newer {
		t.Fatalf("wrong log page: %v", rows)
	}
	for _, row := range rows {
		if row.Tag != LogPreview(tag) || row.Text != LogPreview(text) || !utf8.ValidString(row.Text) {
			t.Fatalf("unexpected log preview for id %d", row.ID)
		}
	}
	var legacyBytes, newBytes int
	err = d.QueryRow("SELECT (SELECT octet_length(text) FROM server_logs WHERE id=$1), (SELECT octet_length(text) FROM server_logs WHERE id=$2)", older, newer).Scan(&legacyBytes, &newBytes)
	if err != nil || legacyBytes != len(text) || newBytes != len(LogPreview(text)) {
		t.Fatalf("stored sizes = %d, %d, err = %v", legacyBytes, newBytes, err)
	}
}

func TestLogBatchInsertPreservesOrderAndSanitizes(t *testing.T) {
	d, err := Open(testDSN(t))
	if err != nil {
		t.Fatal(err)
	}
	defer d.Close()

	longText := strings.Repeat("界", 9000)
	entries := []LogBatchEntry{
		{Level: "info", Tag: "pg", Text: "batch-one"},
		{Level: "warn", Tag: strings.Repeat("t", 9000), Text: longText},
		{Level: "error", Tag: "engine", Text: "batch-three"},
	}
	ids, err := d.InsertLogsBatchContext(t.Context(), entries)
	if err != nil {
		t.Fatal(err)
	}
	if len(ids) != len(entries) || !(ids[0] < ids[1] && ids[1] < ids[2]) {
		t.Fatalf("unexpected batch ids: %v", ids)
	}
	rows, err := d.ListLogsBeforeContext(t.Context(), ids[2]+1, 3)
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 3 || rows[0].ID != ids[0] || rows[1].ID != ids[1] || rows[2].ID != ids[2] {
		t.Fatalf("unexpected rows: %v", rows)
	}
	if rows[0].Text != "batch-one" || rows[1].Text != LogPreview(longText) || rows[2].Text != "batch-three" {
		t.Fatalf("unexpected texts: %+v", rows)
	}
}
