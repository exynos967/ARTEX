package llm

// rawInputToolSet indexes the tools that parse their own arguments.
//
// A call to one of them is delivered even when its arguments are malformed: the
// tool repairs what it can and answers the rest with a Result, so ending the
// whole turn at the transport would destroy the only chance it gets. The set is
// built per request because the tool list is the only place the adapters learn
// which calls are safe to hand over untouched.
func rawInputToolSet(tools []ToolSchema) map[string]bool {
	var set map[string]bool
	for _, t := range tools {
		if !t.RawInput || t.Name == "" {
			continue
		}
		if set == nil {
			set = make(map[string]bool, len(tools))
		}
		set[t.Name] = true
	}
	return set
}
