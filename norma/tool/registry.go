package tool

import (
	"sort"
	"sync"

	"github.com/RC-CHN/ARTEX/norma/llm"
)

// Registry is a concurrency-safe, ordered, name-indexed collection of tools (FR-04.3).
// Tools added via AddDeferred live in deferredByName only: they remain lookupable
// via Get and discoverable via DeferredNames, while Schemas() stays strictly
// immutable (preventing mid-session LLM prompt-cache invalidation).
type Registry struct {
	mu             sync.RWMutex
	order          []string
	byName         map[string]CoreTool
	deferredOrder  []string
	deferredByName map[string]CoreTool
}

// NewRegistry builds a registry from tools, preserving order.
func NewRegistry(tools ...CoreTool) *Registry {
	r := &Registry{
		byName:         map[string]CoreTool{},
		deferredByName: map[string]CoreTool{},
	}
	for _, t := range tools {
		r.Add(t)
	}
	return r
}

// Add registers a tool, replacing any existing one with the same name.
func (r *Registry) Add(t CoreTool) {
	if t == nil {
		return
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.byName == nil {
		r.byName = map[string]CoreTool{}
	}
	if _, ok := r.byName[t.Name()]; !ok {
		r.order = append(r.order, t.Name())
	}
	r.byName[t.Name()] = t
}

// AddDeferred registers a deferred-only tool without adding it to the primary
// Schemas() list. It can be discovered via DeferredNames/SearchExtraTools and
// retrieved via Get/ExecuteExtraTool without mutating req.Tools mid-session.
func (r *Registry) AddDeferred(t CoreTool) {
	if t == nil {
		return
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.deferredByName == nil {
		r.deferredByName = map[string]CoreTool{}
	}
	name := t.Name()
	if _, ok := r.deferredByName[name]; !ok {
		r.deferredOrder = append(r.deferredOrder, name)
	}
	r.deferredByName[name] = t
}

// DeferredNames returns a sorted copy of tool names registered via AddDeferred.
func (r *Registry) DeferredNames() []string {
	r.mu.RLock()
	out := append([]string(nil), r.deferredOrder...)
	r.mu.RUnlock()
	sort.Strings(out)
	return out
}

// Get returns the named tool, checking primary tools first and then deferred-only tools.
func (r *Registry) Get(name string) (CoreTool, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	if t, ok := r.byName[name]; ok {
		return t, true
	}
	t, ok := r.deferredByName[name]
	return t, ok
}

// List returns all primary tools in registration order.
func (r *Registry) List() []CoreTool {
	r.mu.RLock()
	defer r.mu.RUnlock()
	out := make([]CoreTool, 0, len(r.order))
	for _, n := range r.order {
		out = append(out, r.byName[n])
	}
	return out
}

// Schemas renders the primary registry into provider-facing tool definitions,
// merging each tool's extended Prompt into its description. Deferred-only tools
// registered via AddDeferred are intentionally excluded to preserve prompt cache.
func (r *Registry) Schemas() []llm.ToolSchema {
	tools := r.List()
	out := make([]llm.ToolSchema, 0, len(tools))
	for _, t := range tools {
		desc := t.Description()
		if p := t.Prompt(); p != "" {
			desc += "\n\n" + p
		}
		out = append(out, llm.ToolSchema{
			Name:        t.Name(),
			Description: desc,
			InputSchema: t.InputSchema(),
			// Advertised so the transport can hand a partial call to the tool that
			// repairs it instead of ending the turn (see llm.ToolSchema.RawInput).
			RawInput: AcceptsRawInput(t),
		})
	}
	return out
}

// DefaultTools returns the core toolset every agent gets: the file/shell tools
// (Read, Write, Edit, MultiEdit, LS, Glob, Grep, Bash) plus Sleep — a small
// context-cancellable wait that pairs with background execution. Network and
// stateful tools (WebFetch, TodoWrite) remain opt-in via their own constructors.
func DefaultTools() []CoreTool {
	return []CoreTool{
		NewRead(), NewWrite(), NewEdit(), NewMultiEdit(), NewLS(), NewGlob(), NewGrep(), NewBash(),
		NewSleep(),
	}
}
