package db

import (
	"context"
	"slices"
	"strings"
	"time"
	"unicode/utf8"
)

// LogPreviewBytes caps management log messages and tags before storage or display.
const LogPreviewBytes = 8 << 10

func LogPreview(text string) string {
	const marker = " [truncated]"
	if len(text) <= LogPreviewBytes {
		return strings.ToValidUTF8(text, "?")
	}
	end := LogPreviewBytes - len(marker)
	for end > 0 && !utf8.RuneStart(text[end]) {
		end--
	}
	return strings.ToValidUTF8(text[:end], "?") + marker
}

// DBLog is one persisted backend log row from the server_logs table.
type DBLog struct {
	ID        int64
	CreatedAt time.Time
	Level     string
	Tag       string
	Text      string
}

// LogBatchEntry is one log row queued for batched persistence into server_logs.
type LogBatchEntry struct {
	Level string
	Tag   string
	Text  string
}

// InsertLog appends one log preview and returns its auto-assigned id.
func (d *DB) InsertLog(level, tag, text string) (int64, error) {
	return d.InsertLogContext(context.Background(), level, tag, text)
}

func (d *DB) InsertLogContext(ctx context.Context, level, tag, text string) (int64, error) {
	var id int64
	err := d.QueryRowContext(ctx,
		"INSERT INTO server_logs(level,tag,text) VALUES($1,$2,$3) RETURNING id",
		level, LogPreview(tag), LogPreview(text),
	).Scan(&id)
	return id, err
}

// InsertLogsBatchContext inserts multiple sanitized log previews in a single
// round-trip and returns their assigned server_logs ids in input order.
func (d *DB) InsertLogsBatchContext(ctx context.Context, entries []LogBatchEntry) ([]int64, error) {
	if len(entries) == 0 {
		return nil, ctx.Err()
	}
	levels := make([]string, len(entries))
	tags := make([]string, len(entries))
	texts := make([]string, len(entries))
	for i, e := range entries {
		levels[i] = e.Level
		tags[i] = LogPreview(e.Tag)
		texts[i] = LogPreview(e.Text)
	}
	rows, err := d.QueryContext(ctx, `
INSERT INTO server_logs(level, tag, text)
SELECT level, tag, text
FROM UNNEST($1::text[], $2::text[], $3::text[]) WITH ORDINALITY AS t(level, tag, text, ord)
ORDER BY ord
RETURNING id`, levels, tags, texts)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	ids := make([]int64, 0, len(entries))
	for rows.Next() {
		var id int64
		if err := rows.Scan(&id); err != nil {
			return nil, err
		}
		ids = append(ids, id)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return ids, nil
}

// RecentLogs returns the most recent limit rows, oldest-first.
func (d *DB) RecentLogs(limit int) ([]*DBLog, error) {
	return d.RecentLogsContext(context.Background(), limit)
}

// PostgreSQL's left counts characters. One extra character lets LogPreview mark
// truncation, even for legacy rows made entirely of single-byte characters.
const logColumns = "SELECT id, created_at, level, left(tag, $1), left(text, $1) FROM server_logs "

func (d *DB) RecentLogsContext(ctx context.Context, limit int) ([]*DBLog, error) {
	return d.readLogs(ctx, logColumns+"ORDER BY id DESC LIMIT $2", LogPreviewBytes+1, limit)
}

// ListLogsBefore returns up to limit rows with id < beforeID, oldest-first.
func (d *DB) ListLogsBefore(beforeID int64, limit int) ([]*DBLog, error) {
	return d.ListLogsBeforeContext(context.Background(), beforeID, limit)
}

func (d *DB) ListLogsBeforeContext(ctx context.Context, beforeID int64, limit int) ([]*DBLog, error) {
	return d.readLogs(ctx, logColumns+"WHERE id < $3 ORDER BY id DESC LIMIT $2", LogPreviewBytes+1, limit, beforeID)
}

func (d *DB) readLogs(ctx context.Context, query string, args ...any) ([]*DBLog, error) {
	rows, err := d.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*DBLog
	for rows.Next() {
		l := &DBLog{}
		if err := rows.Scan(&l.ID, &l.CreatedAt, &l.Level, &l.Tag, &l.Text); err != nil {
			return nil, err
		}
		l.Tag, l.Text = LogPreview(l.Tag), LogPreview(l.Text)
		out = append(out, l)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	slices.Reverse(out)
	return out, nil
}
