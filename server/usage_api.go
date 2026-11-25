package server

import (
	"context"
	"net/http"
	"sort"

	"github.com/RC-CHN/ARTEX/db"
)

// taskTokenStatsQuery aggregates per-worker, per-session, and whole-task token
// totals from activity(kind='result') in a single pass instead of three separate
// queries over the same exploration slice.
const taskTokenStatsQuery = `
SELECT
	COALESCE(a.worker, '') AS worker,
	CASE
		WHEN COALESCE(a.worker, '') = 'mainagent' THEN 'main:' || COALESCE(a.main_seg, 0)::text
		WHEN COALESCE(a.worker, '') = 'planner' THEN 'plan'
		WHEN n.id IS NOT NULL THEN 'intent:' || n.id::text
		ELSE ''
	END AS session_key,
	COALESCE(SUM(a.input_tokens), 0),
	COALESCE(SUM(a.output_tokens), 0),
	COALESCE(SUM(a.cache_read_tokens), 0),
	COALESCE(SUM(a.cache_write_tokens), 0)
FROM activity a
LEFT JOIN exploration_nodes n
  ON n.id = a.node_id AND n.exploration_id = a.exploration_id AND n.kind = 'intent'
WHERE a.exploration_id = $1 AND a.kind = 'result'
GROUP BY 1, 2`

type taskTokenBucket struct {
	Worker           string
	Session          string
	InputTokens      int
	OutputTokens     int
	CacheReadTokens  int
	CacheWriteTokens int
}

func queryTaskTokenStats(ctx context.Context, pg *db.DB, expID int64) ([]db.TokenUsage, []db.SessionTokenUsage, db.TokenUsage, error) {
	rows, err := pg.QueryContext(ctx, taskTokenStatsQuery, expID)
	if err != nil {
		return nil, nil, db.TokenUsage{}, err
	}
	defer rows.Close()
	var buckets []taskTokenBucket
	for rows.Next() {
		var b taskTokenBucket
		if err := rows.Scan(&b.Worker, &b.Session, &b.InputTokens, &b.OutputTokens, &b.CacheReadTokens, &b.CacheWriteTokens); err != nil {
			return nil, nil, db.TokenUsage{}, err
		}
		buckets = append(buckets, b)
	}
	if err := rows.Err(); err != nil {
		return nil, nil, db.TokenUsage{}, err
	}
	workers, sessions, total := aggregateTaskTokenRows(buckets)
	return workers, sessions, total, nil
}

func aggregateTaskTokenRows(buckets []taskTokenBucket) ([]db.TokenUsage, []db.SessionTokenUsage, db.TokenUsage) {
	byWorker := make(map[string]db.TokenUsage, len(buckets))
	bySession := make(map[string]db.SessionTokenUsage, len(buckets))
	var total db.TokenUsage

	for _, b := range buckets {
		total.InputTokens += b.InputTokens
		total.OutputTokens += b.OutputTokens
		total.CacheReadTokens += b.CacheReadTokens
		total.CacheWriteTokens += b.CacheWriteTokens

		w := byWorker[b.Worker]
		w.Worker = b.Worker
		w.InputTokens += b.InputTokens
		w.OutputTokens += b.OutputTokens
		w.CacheReadTokens += b.CacheReadTokens
		w.CacheWriteTokens += b.CacheWriteTokens
		byWorker[b.Worker] = w

		if b.Session != "" {
			sess := bySession[b.Session]
			sess.Session = b.Session
			sess.InputTokens += b.InputTokens
			sess.OutputTokens += b.OutputTokens
			sess.CacheReadTokens += b.CacheReadTokens
			sess.CacheWriteTokens += b.CacheWriteTokens
			bySession[b.Session] = sess
		}
	}

	workers := make([]db.TokenUsage, 0, len(byWorker))
	for _, w := range byWorker {
		workers = append(workers, w)
	}
	sort.Slice(workers, func(i, j int) bool { return workers[i].Worker < workers[j].Worker })

	sessions := make([]db.SessionTokenUsage, 0, len(bySession))
	for _, sess := range bySession {
		sessions = append(sessions, sess)
	}
	sort.Slice(sessions, func(i, j int) bool { return sessions[i].Session < sessions[j].Session })

	return workers, sessions, total
}

// tokenStats returns per-worker token usage (input/output/cache read/write) for a
// task — main agent, planner, and each work#N.
func (s *Server) tokenStats(w http.ResponseWriter, r *http.Request) {
	t := s.m.ResolveTask(r.URL.Query().Get("task"))
	if t == nil {
		writeJSON(w, 200, map[string]any{
			"workers":  []db.TokenUsage{},
			"sessions": []db.SessionTokenUsage{},
			"total":    tokenTotalDTO(db.TokenUsage{}),
		})
		return
	}
	expID := t.ExpID
	if expID == 0 && t.Store != nil {
		expID = t.Store.ID()
	}
	if s.m.pg == nil {
		writeJSON(w, 200, map[string]any{
			"workers":  []db.TokenUsage{},
			"sessions": []db.SessionTokenUsage{},
			"total":    tokenTotalDTO(db.TokenUsage{}),
		})
		return
	}
	stats, sessions, total, err := queryTaskTokenStats(r.Context(), s.m.pg, expID)
	if err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	writeJSON(w, 200, map[string]any{"workers": stats, "sessions": sessions, "total": tokenTotalDTO(total)})
}

// tokenDailyStats returns global token consumption aggregated by calendar day
// (UTC) across all tasks for the past ?days=N days (default 30).
func (s *Server) tokenDailyStats(w http.ResponseWriter, r *http.Request) {
	days := atoiDefault(r.URL.Query().Get("days"), 30)
	if s.m.pg == nil {
		writeJSON(w, 200, []any{})
		return
	}
	buckets, err := s.m.pg.TokenDailyAll(days)
	if err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	if buckets == nil {
		buckets = []db.DailyTokenBucket{}
	}
	writeJSON(w, 200, buckets)
}

// conversationTokens returns per-conversation token summaries so the dashboard can
// merge chat (conversation) usage into its per-profile / daily token stats — which
// otherwise count only task (exploration) usage.
func (s *Server) conversationTokens(w http.ResponseWriter, r *http.Request) {
	if s.m.pg == nil {
		writeJSON(w, 200, []any{})
		return
	}
	rows, err := s.m.pg.ConversationTokenSummaries()
	if err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	writeJSON(w, 200, rows)
}
