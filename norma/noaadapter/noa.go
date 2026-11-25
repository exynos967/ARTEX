package noaadapter

import (
	"github.com/RC-CHN/ARTEX/norma/agentcore"
	"github.com/RC-CHN/ARTEX/norma/noa"
	"github.com/RC-CHN/ARTEX/norma/tool"
)

// Enable wires noa into a set of agentcore Options.
//
// This is the ONLY entry point, and it is all-or-nothing by design. It attaches
// three things at once:
//
//  1. opts.Compactor          — takes over the view (and disables the built-in
//     Compaction, which a session cannot run alongside it)
//  2. opts.Tools += Compress  — the compression tool
//  3. opts.AppendSystemPrompt — the three resident prompt sections
//
// They must live or die together. Wiring them separately makes three ways to
// get it half-right, and each failure is quiet:
//
//   - no Compactor: the model compresses, the panel says it worked, and the
//     view never changes — the compression went nowhere.
//   - no tool: the prompt teaches a tool that does not exist.
//   - no prompt: the model has the tool but not the rules, and writes summaries
//     that drop paths, decisions and error strings. Nothing reports an error;
//     it surfaces hours later as a model that has forgotten what it did.
//
// Not calling Enable is the off switch: nothing is attached, and the built-in
// compaction keeps working exactly as before.
func Enable(opts *agentcore.Options, o Options) error {
	if o.ModelContextLimit == 0 && o.Config == nil {
		o.ModelContextLimit = defaultContextLimit
	}
	if o.OnWarn == nil {
		o.OnWarn = opts.OnWarn
	}
	sess, err := newSession(o)
	if err != nil {
		return err
	}

	opts.Compactor = &Compactor{sess: sess}
	opts.Tools = append(opts.Tools, newCompressTool(sess))
	noaPrompt := noa.BuildSystemPrompt(noa.Sections{})
	// The noa prompt section is fully static, so it belongs inside the cacheable
	// prefix — WITHOUT pulling any post-boundary dynamic segments (such as
	// <artex-dynamic-time>) across DynamicBoundary, and WITHOUT pushing
	// pre-existing static AppendSystemPrompt segments past a newly invented
	// boundary when opts.DynamicBoundary <= 0.
	switch {
	case opts.DynamicBoundary > 0 && opts.DynamicBoundary < len(opts.SystemPrompt):
		b := opts.DynamicBoundary
		sys := make([]string, 0, len(opts.SystemPrompt)+1)
		sys = append(sys, opts.SystemPrompt[:b]...)
		sys = append(sys, noaPrompt)
		sys = append(sys, opts.SystemPrompt[b:]...)
		opts.SystemPrompt = sys
		opts.DynamicBoundary = b + 1
	case opts.DynamicBoundary > len(opts.SystemPrompt) && opts.DynamicBoundary < len(opts.SystemPrompt)+len(opts.AppendSystemPrompt):
		idx := opts.DynamicBoundary - len(opts.SystemPrompt)
		app := make([]string, 0, len(opts.AppendSystemPrompt)+1)
		app = append(app, opts.AppendSystemPrompt[:idx]...)
		app = append(app, noaPrompt)
		app = append(app, opts.AppendSystemPrompt[idx:]...)
		opts.AppendSystemPrompt = app
		opts.DynamicBoundary++
	case opts.DynamicBoundary > 0 && opts.DynamicBoundary == len(opts.SystemPrompt) && len(opts.AppendSystemPrompt) > 0:
		// Callers explicitly placed DynamicBoundary at the end of SystemPrompt
		// so AppendSystemPrompt stays post-boundary; insert noaPrompt at the end
		// of SystemPrompt so those dynamic segments stay post-boundary.
		opts.SystemPrompt = append(append([]string(nil), opts.SystemPrompt...), noaPrompt)
		opts.DynamicBoundary = len(opts.SystemPrompt)
	default:
		// Either DynamicBoundary <= 0 (all pre-existing SystemPrompt and
		// AppendSystemPrompt segments are static) or DynamicBoundary already
		// covers everything: append noaPrompt and cover the full static prefix.
		opts.AppendSystemPrompt = append(opts.AppendSystemPrompt, noaPrompt)
		opts.DynamicBoundary = len(opts.SystemPrompt) + len(opts.AppendSystemPrompt)
	}
	return nil
}

// defaultContextLimit is used when the host names no window. It is deliberately
// conservative: guessing high would delay every pressure threshold past the
// point where they could still help.
const defaultContextLimit = 200000

// EnableWithSession is Enable, also returning the session so a host can inspect
// state or archives. The session is owned by the returned wiring; callers must
// not construct a second one over the same directory.
func EnableWithSession(opts *agentcore.Options, o Options) (*Session, error) {
	if err := Enable(opts, o); err != nil {
		return nil, err
	}
	c, ok := opts.Compactor.(*Compactor)
	if !ok {
		return nil, ErrNoArchiveDir
	}
	return c.sess, nil
}

var _ tool.CoreTool = newCompressTool(&Session{cfg: noa.DefaultConfig(1)})
