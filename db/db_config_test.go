package db

import (
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
)

func TestPoolBounds(t *testing.T) {
	if maxOpenConns != 18 {
		t.Fatalf("maxOpenConns=%d want 18", maxOpenConns)
	}
	if maxIdleConns != 8 {
		t.Fatalf("maxIdleConns=%d want 8", maxIdleConns)
	}
}

func TestApplyDefaultTimeoutsURL(t *testing.T) {
	cases := []struct {
		name           string
		dsn            string
		wantConnect    time.Duration
		wantStatement  string
		wantLock       string
		wantIdleInTx   string
		wantExtraParam map[string]string
	}{
		{
			name:          "bare postgres url",
			dsn:           "postgres://artex:secret@127.0.0.1:5432/artex",
			wantConnect:   5 * time.Second,
			wantStatement: "30000",
			wantLock:      "5000",
			wantIdleInTx:  "30000",
		},
		{
			name:          "postgresql scheme with existing query params",
			dsn:           "postgresql://artex:secret@localhost:5432/artex?sslmode=disable&application_name=test",
			wantConnect:   5 * time.Second,
			wantStatement: "30000",
			wantLock:      "5000",
			wantIdleInTx:  "30000",
			wantExtraParam: map[string]string{
				"application_name": "test",
			},
		},
		{
			name:          "explicit overrides including zero preserved",
			dsn:           "postgres://artex:secret@localhost:5432/artex?connect_timeout=12&statement_timeout=60000&lock_timeout=0",
			wantConnect:   12 * time.Second,
			wantStatement: "60000",
			wantLock:      "0",
			wantIdleInTx:  "30000",
		},
		{
			name:          "all defaults already specified keeps original",
			dsn:           "postgres://artex:secret@localhost:5432/artex?connect_timeout=9&statement_timeout=9000&lock_timeout=1500&idle_in_transaction_session_timeout=45000",
			wantConnect:   9 * time.Second,
			wantStatement: "9000",
			wantLock:      "1500",
			wantIdleInTx:  "45000",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := applyDefaultTimeouts(tc.dsn)
			cfg, err := pgx.ParseConfig(got)
			if err != nil {
				t.Fatalf("pgx.ParseConfig(%q): %v", got, err)
			}
			if cfg.ConnectTimeout != tc.wantConnect {
				t.Fatalf("ConnectTimeout=%v want %v (dsn=%q)", cfg.ConnectTimeout, tc.wantConnect, got)
			}
			if cfg.RuntimeParams["statement_timeout"] != tc.wantStatement {
				t.Fatalf("statement_timeout=%q want %q", cfg.RuntimeParams["statement_timeout"], tc.wantStatement)
			}
			if cfg.RuntimeParams["lock_timeout"] != tc.wantLock {
				t.Fatalf("lock_timeout=%q want %q", cfg.RuntimeParams["lock_timeout"], tc.wantLock)
			}
			if cfg.RuntimeParams["idle_in_transaction_session_timeout"] != tc.wantIdleInTx {
				t.Fatalf("idle_in_transaction_session_timeout=%q want %q", cfg.RuntimeParams["idle_in_transaction_session_timeout"], tc.wantIdleInTx)
			}
			for k, want := range tc.wantExtraParam {
				if cfg.RuntimeParams[k] != want {
					t.Fatalf("RuntimeParams[%q]=%q want %q", k, cfg.RuntimeParams[k], want)
				}
			}
		})
	}
}

func TestApplyDefaultTimeoutsKeywordValue(t *testing.T) {
	cases := []struct {
		name          string
		dsn           string
		wantConnect   time.Duration
		wantStatement string
		wantLock      string
		wantIdleInTx  string
	}{
		{
			name:          "plain keyword-value dsn",
			dsn:           "host=127.0.0.1 port=5432 user=artex password=secret dbname=artex sslmode=disable",
			wantConnect:   5 * time.Second,
			wantStatement: "30000",
			wantLock:      "5000",
			wantIdleInTx:  "30000",
		},
		{
			name:          "partial overrides preserved",
			dsn:           "host=127.0.0.1 dbname=artex statement_timeout=45000 lock_timeout = 2000",
			wantConnect:   5 * time.Second,
			wantStatement: "45000",
			wantLock:      "2000",
			wantIdleInTx:  "30000",
		},
		{
			name:          "quoted password containing param name does not suppress injection",
			dsn:           "host=127.0.0.1 user=artex password='statement_timeout=1 lock_timeout=2' dbname=artex",
			wantConnect:   5 * time.Second,
			wantStatement: "30000",
			wantLock:      "5000",
			wantIdleInTx:  "30000",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := applyDefaultTimeouts(tc.dsn)
			cfg, err := pgx.ParseConfig(got)
			if err != nil {
				t.Fatalf("pgx.ParseConfig(%q): %v", got, err)
			}
			if cfg.ConnectTimeout != tc.wantConnect {
				t.Fatalf("ConnectTimeout=%v want %v", cfg.ConnectTimeout, tc.wantConnect)
			}
			if cfg.RuntimeParams["statement_timeout"] != tc.wantStatement {
				t.Fatalf("statement_timeout=%q want %q", cfg.RuntimeParams["statement_timeout"], tc.wantStatement)
			}
			if cfg.RuntimeParams["lock_timeout"] != tc.wantLock {
				t.Fatalf("lock_timeout=%q want %q", cfg.RuntimeParams["lock_timeout"], tc.wantLock)
			}
			if cfg.RuntimeParams["idle_in_transaction_session_timeout"] != tc.wantIdleInTx {
				t.Fatalf("idle_in_transaction_session_timeout=%q want %q", cfg.RuntimeParams["idle_in_transaction_session_timeout"], tc.wantIdleInTx)
			}
		})
	}
}

func TestApplyDefaultTimeoutsRespectsPGOptionsAndEdgeCases(t *testing.T) {
	urlWithOptions := "postgres://artex:secret@localhost:5432/artex?options=-c%20statement_timeout%3D90000"
	got := applyDefaultTimeouts(urlWithOptions)
	cfg, err := pgx.ParseConfig(got)
	if err != nil {
		t.Fatalf("pgx.ParseConfig(%q): %v", got, err)
	}
	if _, injected := cfg.RuntimeParams["statement_timeout"]; injected {
		t.Fatalf("statement_timeout should not be injected when set via options: %q", got)
	}
	if cfg.RuntimeParams["lock_timeout"] != "5000" || cfg.RuntimeParams["idle_in_transaction_session_timeout"] != "30000" {
		t.Fatalf("missing sibling timeouts: %+v", cfg.RuntimeParams)
	}

	kvWithOptions := "host=127.0.0.1 dbname=artex options='-c lock_timeout=1234 --idle-in-transaction-session-timeout=5678'"
	gotKV := applyDefaultTimeouts(kvWithOptions)
	cfgKV, err := pgx.ParseConfig(gotKV)
	if err != nil {
		t.Fatalf("pgx.ParseConfig(%q): %v", gotKV, err)
	}
	if _, injected := cfgKV.RuntimeParams["lock_timeout"]; injected {
		t.Fatalf("lock_timeout should not be injected when set via options: %q", gotKV)
	}
	if _, injected := cfgKV.RuntimeParams["idle_in_transaction_session_timeout"]; injected {
		t.Fatalf("idle_in_transaction_session_timeout should not be injected when set via options: %q", gotKV)
	}
	if cfgKV.RuntimeParams["statement_timeout"] != "30000" {
		t.Fatalf("statement_timeout=%q want 30000", cfgKV.RuntimeParams["statement_timeout"])
	}

	if got := applyDefaultTimeouts(""); got != "" {
		t.Fatalf("empty dsn modified: %q", got)
	}
	if got := applyDefaultTimeouts("   "); got != "   " {
		t.Fatalf("blank dsn modified: %q", got)
	}
	badURL := "postgres://[::1"
	if got := applyDefaultTimeouts(badURL); got != badURL {
		t.Fatalf("unparseable url modified: %q", got)
	}
}
