package server

import (
	"reflect"
	"testing"

	"github.com/RC-CHN/ARTEX/db"
)

func TestActivitySystemFilterParseAndSQL(t *testing.T) {
	f, ok := parseActivitySession("system")
	if !ok {
		t.Fatal("parseActivitySession(\"system\") = false, want true")
	}
	if !f.System || f.Main || f.Worker != "" || f.NodeID != nil || f.MainSeg != nil {
		t.Fatalf("unexpected filter for system: %+v", f)
	}
	cond, args := f.SQLCondition(2)
	wantCond := " AND (worker='system' OR kind IN ('llm_switch','llm_failover'))"
	if cond != wantCond {
		t.Fatalf("SQLCondition(2) = %q, want %q", cond, wantCond)
	}
	if len(args) != 0 {
		t.Fatalf("SQLCondition(2) args = %v, want empty", args)
	}
}

func TestActivitySessionFilterAllKinds(t *testing.T) {
	tests := []struct {
		name     string
		session  string
		wantOK   bool
		wantCond string
		wantArgs []any
	}{
		{
			name:     "empty defaults to main segment 0",
			session:  "",
			wantOK:   true,
			wantCond: " AND worker='mainagent' AND (main_seg = 0 OR main_seg IS NULL)",
		},
		{
			name:     "main explicit segment",
			session:  "main:3",
			wantOK:   true,
			wantCond: " AND worker='mainagent' AND main_seg=$2",
			wantArgs: []any{3},
		},
		{
			name:     "main consultation lane",
			session:  "main:-1",
			wantOK:   true,
			wantCond: " AND worker='mainagent' AND main_seg=$2",
			wantArgs: []any{db.MainSegConsultation},
		},
		{
			name:     "planner session",
			session:  "plan",
			wantOK:   true,
			wantCond: " AND worker=$2",
			wantArgs: []any{"planner"},
		},
		{
			name:     "system audit session",
			session:  "system",
			wantOK:   true,
			wantCond: " AND (worker='system' OR kind IN ('llm_switch','llm_failover'))",
		},
		{
			name:     "worker intent session",
			session:  "intent:42",
			wantOK:   true,
			wantCond: " AND node_id=$2",
			wantArgs: []any{int64(42)},
		},
		{
			name:    "invalid main segment",
			session: "main:-2",
			wantOK:  false,
		},
		{
			name:    "invalid intent id",
			session: "intent:abc",
			wantOK:  false,
		},
		{
			name:    "unknown session",
			session: "unknown",
			wantOK:  false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			filter, ok := parseActivitySession(tc.session)
			if ok != tc.wantOK {
				t.Fatalf("parseActivitySession(%q) ok = %v, want %v", tc.session, ok, tc.wantOK)
			}
			if !ok {
				return
			}
			cond, args := filter.SQLCondition(2)
			if cond != tc.wantCond {
				t.Fatalf("SQLCondition(2) = %q, want %q", cond, tc.wantCond)
			}
			if !reflect.DeepEqual(args, tc.wantArgs) {
				t.Fatalf("SQLCondition(2) args = %#v, want %#v", args, tc.wantArgs)
			}
		})
	}
}
