package agent

import (
	"context"
	"strconv"
	"strings"

	"github.com/RC-CHN/ARTEX/norma/agentcore"
	"github.com/RC-CHN/ARTEX/norma/transcript"
	"github.com/RC-CHN/ARTEX/sidequestion"
)

func attachSideCapture(ctx context.Context, opts *agentcore.Options) context.Context {
	ri := RunInfoFrom(ctx)
	p := sidequestion.Parent{TaskID: ri.TaskID, ExplorationID: ri.ExplorationID, IntentID: ri.IntentID}
	if strings.HasPrefix(ri.SessionID, "conv-") {
		p.ConversationID, _ = strconv.ParseInt(strings.TrimPrefix(ri.SessionID, "conv-"), 10, 64)
	}
	if p.ConversationID == 0 && (p.TaskID == 0 || p.ExplorationID == 0) {
		return ctx
	}
	sessionID := strings.TrimSpace(opts.SessionID)
	if sessionID == "" {
		sessionID = strings.TrimSpace(transcript.SessionIDFrom(ctx))
	}
	if sessionID == "" {
		sessionID = strings.TrimSpace(ri.SessionID)
	}
	if sessionID != "" {
		ctx = sidequestion.WithSessionID(ctx, sessionID)
	}
	ctx, opts.Deps = sidequestion.Attach(ctx, p, opts.Deps, opts.Provider)
	return ctx
}
