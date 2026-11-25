package db

import (
	"context"
	"database/sql"

	"github.com/RC-CHN/ARTEX/internal/operation"
)

// Soft admission threshold over existing metering, not a billing guarantee.
// In-flight requests and wrap-up may exceed it; zero preserves unlimited work.
type TaskTokenBudget struct {
	Limit          int64 `json:"limit"`
	Used           int64 `json:"used"`
	Revision       int64 `json:"revision"`
	Reached        bool  `json:"reached"`
	UsageAvailable bool  `json:"usage_available"`
}

type tokenBudgetReader interface {
	QueryRowContext(context.Context, string, ...any) *sql.Row
}

// taskTokenBudgetQuery reads the task's budget threshold, revision, and
// trigger-maintained cumulative tokens_used from task_token_counters in one PK
// lookup. When usage is not required (limit=0 and !includeUsage), PostgreSQL
// short-circuits the CASE and avoids even the catalog lookup for llm_usage.
const taskTokenBudgetQuery = `
SELECT t.token_budget_limit, t.token_budget_revision, COALESCE(c.tokens_used, 0),
       CASE WHEN t.token_budget_limit > 0 OR $2 THEN to_regclass('llm_usage') IS NOT NULL ELSE false END
FROM tasks t
LEFT JOIN task_token_counters c ON c.task_id = t.id
WHERE t.id=$1 AND t.deleted_at IS NULL AND t.archived_at IS NULL`

func (d *DB) TaskTokenBudget(ctx context.Context, taskID int64, includeUsage bool) (TaskTokenBudget, error) {
	return taskTokenBudget(ctx, d.DB, taskID, includeUsage)
}

func taskTokenBudget(ctx context.Context, q tokenBudgetReader, taskID int64, includeUsage bool) (TaskTokenBudget, error) {
	var limit, revision, used int64
	var available bool
	if err := q.QueryRowContext(ctx, taskTokenBudgetQuery, taskID, includeUsage).Scan(&limit, &revision, &used, &available); err != nil {
		return TaskTokenBudget{}, err
	}
	return evaluateTaskTokenBudget(limit, revision, used, available, includeUsage)
}

func evaluateTaskTokenBudget(limit, revision, used int64, available, includeUsage bool) (TaskTokenBudget, error) {
	b := TaskTokenBudget{Limit: limit, Revision: revision}
	if b.Limit == 0 && !includeUsage {
		return b, nil
	}
	if !available {
		if b.Limit > 0 {
			return b, &operation.Error{Code: "budget_usage_unavailable", Message: "累计用量暂不可查询。", NextAction: "恢复用量数据库后再开始自动工作；不要推断预算尚未使用。"}
		}
		return b, nil
	}
	b.Used = used
	b.UsageAvailable = true
	b.Reached = b.Limit > 0 && b.Used >= b.Limit
	return b, nil
}

func (s *ExplorationStore) TaskTokenBudget(ctx context.Context, taskID int64, includeUsage bool) (TaskTokenBudget, error) {
	return s.db.TaskTokenBudget(ctx, taskID, includeUsage)
}

func (d *DB) SetTaskTokenBudget(ctx context.Context, taskID, limit, revision int64) (TaskTokenBudget, error) {
	if limit < 0 || limit > 1_000_000_000_000 || revision <= 0 {
		return TaskTokenBudget{}, &operation.Error{Code: "invalid_budget", Message: "预算必须为0至1万亿的整数，并提供当前revision。", NextAction: "0表示不限额；重新读取预算后提交。"}
	}
	tx, err := d.BeginTx(ctx, nil)
	if err != nil {
		return TaskTokenBudget{}, err
	}
	defer tx.Rollback()
	var next int64
	err = tx.QueryRowContext(ctx, `UPDATE tasks SET token_budget_limit=$2,token_budget_revision=token_budget_revision+1 WHERE id=$1 AND token_budget_revision=$3 AND deleted_at IS NULL AND archived_at IS NULL RETURNING token_budget_revision`, taskID, limit, revision).Scan(&next)
	if err == sql.ErrNoRows {
		return TaskTokenBudget{}, &operation.Error{Code: "budget_conflict", Message: "任务预算已变更或任务不可用。", NextAction: "重新读取预算，核对后再设置；不自动恢复已停止的Worker。"}
	}
	if err != nil {
		return TaskTokenBudget{}, err
	}
	b, err := taskTokenBudget(ctx, tx, taskID, true)
	if err != nil {
		return b, err
	}
	err = tx.Commit()
	return b, err
}
