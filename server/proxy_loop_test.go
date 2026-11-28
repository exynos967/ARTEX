package server

import (
	"encoding/json"
	"strings"
	"testing"

	actool "github.com/RC-CHN/ARTEX/norma/tool"
	"github.com/RC-CHN/ARTEX/runner"
	"github.com/RC-CHN/ARTEX/runnerfiles"
	"github.com/RC-CHN/ARTEX/traffic"
)

func openTestTrafficProxy(t *testing.T, addr string) *traffic.Traffic {
	t.Helper()
	tr, err := traffic.Open(t.TempDir(), addr)
	if err != nil {
		t.Fatalf("open test traffic proxy %s: %v", addr, err)
	}
	t.Cleanup(func() { _ = tr.Close() })
	return tr
}

func TestProxyLoopRejectsSelfRecordingProxy(t *testing.T) {
	tr := openTestTrafficProxy(t, ":8788")

	loopURLs := []string{
		"http://127.0.0.1:8788",
		"http://localhost:8788",
		"http://LOCALHOST.:8788",
		"http://[::1]:8788",
		"http://[0:0:0:0:0:0:0:1]:8788",
		"http://0.0.0.0:8788",
		"http://[::]:8788",
		"https://localhost:8788",
		"socks5://127.0.0.1:8788",
		"http://user:topsecret@localhost:8788",
	}

	for _, trafficOn := range []bool{true, false} {
		m := &Manager{traffic: tr, trafficOn: trafficOn}
		for _, raw := range loopURLs {
			err := m.SetGlobalProxy(raw)
			if err == nil {
				t.Fatalf("trafficOn=%v: SetGlobalProxy(%q) succeeded, expected self-loop rejection", trafficOn, raw)
			}
			if !strings.Contains(err.Error(), "代理自环") {
				t.Fatalf("trafficOn=%v: SetGlobalProxy(%q) error = %q, want Chinese self-loop message", trafficOn, raw, err.Error())
			}
			if strings.Contains(err.Error(), "topsecret") {
				t.Fatalf("SetGlobalProxy(%q) leaked proxy password in error: %q", raw, err.Error())
			}
		}
	}
}

func TestGlobalProxySelfLoopHelperAllowsExternalAndOtherPorts(t *testing.T) {
	cases := []struct {
		name      string
		selfAddr  string
		candidate string
		wantLoop  bool
	}{
		{
			name:      "different port on loopback allowed",
			selfAddr:  "http://127.0.0.1:8788",
			candidate: "http://127.0.0.1:7890",
			wantLoop:  false,
		},
		{
			name:      "different port on localhost socks5 allowed",
			selfAddr:  "http://127.0.0.1:8788",
			candidate: "socks5://localhost:1080",
			wantLoop:  false,
		},
		{
			name:      "external host same port allowed",
			selfAddr:  "http://127.0.0.1:8788",
			candidate: "http://proxy.corp.internal:8788",
			wantLoop:  false,
		},
		{
			name:      "external ip same port allowed",
			selfAddr:  "http://127.0.0.1:8788",
			candidate: "socks5://10.0.0.2:8788",
			wantLoop:  false,
		},
		{
			name:      "same explicit non-loopback ip and port rejected",
			selfAddr:  "http://192.168.1.50:8788",
			candidate: "http://192.168.1.50:8788",
			wantLoop:  true,
		},
		{
			name:      "different explicit non-loopback ip allowed",
			selfAddr:  "http://192.168.1.50:8788",
			candidate: "http://192.168.1.51:8788",
			wantLoop:  false,
		},
		{
			name:      "implicit http port 80 loop rejected",
			selfAddr:  "http://127.0.0.1:80",
			candidate: "http://localhost",
			wantLoop:  true,
		},
		{
			name:      "ipv4-mapped ipv6 loopback rejected",
			selfAddr:  "http://127.0.0.1:8788",
			candidate: "http://[::ffff:127.0.0.1]:8788",
			wantLoop:  true,
		},
		{
			name:      "empty recording proxy allows any valid proxy",
			selfAddr:  "",
			candidate: "http://127.0.0.1:8788",
			wantLoop:  false,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			u, err := traffic.ValidateProxyURL(tc.candidate)
			if err != nil {
				t.Fatalf("ValidateProxyURL(%q): %v", tc.candidate, err)
			}
			gotErr := checkGlobalProxySelfLoop(u, tc.selfAddr)
			if tc.wantLoop && gotErr == nil {
				t.Fatalf("checkGlobalProxySelfLoop(%q, %q) = nil, want error", tc.candidate, tc.selfAddr)
			}
			if !tc.wantLoop && gotErr != nil {
				t.Fatalf("checkGlobalProxySelfLoop(%q, %q) = %v, want nil", tc.candidate, tc.selfAddr, gotErr)
			}
		})
	}
}

func TestRunnerNetworkWebSearchProxyIsolation(t *testing.T) {
	tr := openTestTrafficProxy(t, ":8788")
	s := &Server{
		m: &Manager{
			dir:       t.TempDir(),
			traffic:   tr,
			trafficOn: true,
		},
	}

	recordingProxy := "http://recording.runner.local:8788"

	t.Run("preserves dedicated web_search proxy without recording proxy overwrite", func(t *testing.T) {
		origSearch := actool.WebSearchConfig{
			Backend:     "brave-free",
			BraveAPIKey: "brave-test-key",
			Proxy:       "http://search-egress.internal:7890",
		}
		searchRaw, _ := json.Marshal(origSearch)
		customRaw, _ := json.Marshal(httpExec{URL: "https://target.example.invalid", UseRecordingProxy: true})

		spec := runner.RunSpec{
			Env: map[string]string{},
			Tools: []runner.ToolDefinition{
				{Name: "WebFetch", Kind: "builtin"},
				{Name: "web_search", Kind: "builtin", Exec: searchRaw},
				{Name: "custom_http", Kind: "http", Exec: customRaw},
			},
		}
		var plan runnerfiles.Plan
		if err := s.runnerNetwork(&spec, &plan, runnerEnvironment{ProxyURL: recordingProxy}, defaultRunnerConfig()); err != nil {
			t.Fatalf("runnerNetwork: %v", err)
		}

		// WebFetch must receive the runner-reachable recording proxy + CA cert.
		var wf actool.WebFetchConfig
		if err := json.Unmarshal(spec.Tools[0].Exec, &wf); err != nil {
			t.Fatalf("unmarshal WebFetch: %v", err)
		}
		if wf.Proxy != recordingProxy || wf.CACert == "" {
			t.Fatalf("WebFetch = %+v, want proxy %q and non-empty CACert", wf, recordingProxy)
		}

		// web_search must retain its independent proxy and must NOT inherit recording proxy/CA.
		var ws actool.WebSearchConfig
		if err := json.Unmarshal(spec.Tools[1].Exec, &ws); err != nil {
			t.Fatalf("unmarshal web_search: %v", err)
		}
		if ws != origSearch {
			t.Fatalf("web_search config mutated:\n got: %+v\nwant: %+v", ws, origSearch)
		}

		// Custom HTTP tool with UseRecordingProxy must still receive recording proxy + CA.
		var custom struct {
			httpExec
			CACert string `json:"ca_cert"`
		}
		if err := json.Unmarshal(spec.Tools[2].Exec, &custom); err != nil {
			t.Fatalf("unmarshal custom_http: %v", err)
		}
		if custom.Proxy != recordingProxy || custom.CACert == "" || custom.UseRecordingProxy {
			t.Fatalf("custom_http = %+v, want proxy %q, non-empty CACert, UseRecordingProxy=false", custom, recordingProxy)
		}
	})

	t.Run("preserves direct web_search when web_search_proxy is empty", func(t *testing.T) {
		origSearch := actool.WebSearchConfig{
			Backend: "ddgs",
			Proxy:   "",
		}
		searchRaw, _ := json.Marshal(origSearch)
		spec := runner.RunSpec{
			Env: map[string]string{},
			Tools: []runner.ToolDefinition{
				{Name: "web_search", Kind: "builtin", Exec: searchRaw},
			},
		}
		if err := s.runnerNetwork(&spec, &runnerfiles.Plan{}, runnerEnvironment{ProxyURL: recordingProxy}, defaultRunnerConfig()); err != nil {
			t.Fatalf("runnerNetwork: %v", err)
		}
		var ws actool.WebSearchConfig
		if err := json.Unmarshal(spec.Tools[0].Exec, &ws); err != nil {
			t.Fatalf("unmarshal web_search: %v", err)
		}
		if ws.Proxy != "" || ws.CACert != "" {
			t.Fatalf("direct web_search was overwritten with recording proxy: %+v", ws)
		}
	})
}

func TestBrowserProxyArgNormalization(t *testing.T) {
	if got, warn := browserProxyArg("socks5h://10.0.0.2:1080"); got != "socks5://10.0.0.2:1080" || warn != "" {
		t.Fatalf("socks5h without auth = (%q, %q), want (socks5://10.0.0.2:1080, \"\")", got, warn)
	}
	got, warn := browserProxyArg("socks5h://alice:topsecret@10.0.0.2:1080")
	if got != "socks5://alice:topsecret@10.0.0.2:1080" {
		t.Fatalf("socks5h with auth arg = %q, want socks5://alice:topsecret@10.0.0.2:1080", got)
	}
	if warn == "" || strings.Contains(warn, "topsecret") {
		t.Fatalf("socks5h with auth warn = %q, want non-empty redacted warning", warn)
	}
	if got, warn := browserProxyArg("http://user:pass@10.0.0.2:8080"); got != "http://user:pass@10.0.0.2:8080" || warn != "" {
		t.Fatalf("http with auth = (%q, %q), want unchanged with empty warn", got, warn)
	}
}

func TestRunnerNetworkStrictGlobalProxy(t *testing.T) {
	s := &Server{
		m: &Manager{
			dir:         t.TempDir(),
			globalProxy: "http://10.0.0.5:8080",
		},
	}
	customRaw, _ := json.Marshal(httpExec{URL: "https://target.example.invalid"})
	spec := runner.RunSpec{
		Env: map[string]string{},
		MCPs: []runner.MCPConfig{
			{Name: browserMCPName, Args: []string{"@playwright/mcp", "--headless"}, Env: map[string]string{}},
		},
		Tools: []runner.ToolDefinition{
			{Name: "WebFetch", Kind: "builtin"},
			{Name: "custom_http", Kind: "http", Exec: customRaw},
		},
	}
	if err := s.runnerNetwork(&spec, &runnerfiles.Plan{}, runnerEnvironment{ProxyURL: "socks5h://10.0.0.5:1080"}, defaultRunnerConfig()); err != nil {
		t.Fatalf("runnerNetwork: %v", err)
	}

	var wf actool.WebFetchConfig
	if err := json.Unmarshal(spec.Tools[0].Exec, &wf); err != nil {
		t.Fatalf("unmarshal WebFetch: %v", err)
	}
	if !wf.DisableDirectFallback || wf.Proxy != "socks5h://10.0.0.5:1080" {
		t.Fatalf("WebFetch = %+v, want DisableDirectFallback=true and Proxy set", wf)
	}

	var custom httpExec
	if err := json.Unmarshal(spec.Tools[1].Exec, &custom); err != nil {
		t.Fatalf("unmarshal custom_http: %v", err)
	}
	if custom.Proxy != "socks5h://10.0.0.5:1080" {
		t.Fatalf("custom_http.Proxy = %q, want socks5h://10.0.0.5:1080", custom.Proxy)
	}

	joined := strings.Join(spec.MCPs[0].Args, " ")
	if !strings.Contains(joined, "--proxy-server socks5://10.0.0.5:1080") {
		t.Fatalf("browser MCP args = %v, want normalized socks5:// proxy", spec.MCPs[0].Args)
	}
}

func TestRunnerNetworkOOBAndCallbackEnv(t *testing.T) {
	t.Setenv("ARTEX_OOB_SERVER", "https://oob.example.com")
	t.Setenv("ARTEX_OOB_TOKEN", "oob-secret")
	t.Setenv("ARTEX_OOB_DISABLE_PUBLIC", "1")
	t.Setenv("ARTEX_CALLBACK_PUBLIC_HOST", "203.0.113.20")
	t.Setenv("ARTEX_CALLBACK_PORTS", "20001-20005")
	t.Setenv("ARTEX_RUNNER_CALLBACK_PORTS", "")

	s := &Server{m: &Manager{dir: t.TempDir()}}

	// Without ARTEX_RUNNER_CALLBACK_PORTS, OOB vars propagate, but controller's callback ports do NOT.
	spec := runner.RunSpec{Env: map[string]string{"ARTEX_OOB_SERVER": "https://env-override.example"}}
	if err := s.runnerNetwork(&spec, &runnerfiles.Plan{}, runnerEnvironment{DirectNetwork: true}, defaultRunnerConfig()); err != nil {
		t.Fatalf("runnerNetwork: %v", err)
	}
	if spec.Env["ARTEX_OOB_SERVER"] != "https://env-override.example" {
		t.Fatalf("per-env ARTEX_OOB_SERVER override lost: %q", spec.Env["ARTEX_OOB_SERVER"])
	}
	if spec.Env["ARTEX_OOB_TOKEN"] != "oob-secret" || spec.Env["ARTEX_OOB_DISABLE_PUBLIC"] != "1" {
		t.Fatalf("OOB env not forwarded: %+v", spec.Env)
	}
	if spec.Env["ARTEX_CALLBACK_PORTS"] != "" || spec.Env["ARTEX_CALLBACK_PUBLIC_HOST"] != "" {
		t.Fatalf("controller callback ports should not leak to runner without ARTEX_RUNNER_CALLBACK_PORTS: %+v", spec.Env)
	}

	// With ARTEX_RUNNER_CALLBACK_PORTS configured, runner receives its dedicated ports + public host.
	t.Setenv("ARTEX_RUNNER_CALLBACK_PORTS", "20011-20015")
	t.Setenv("NORMA_GREP_TIMEOUT_MS", "45000")
	t.Setenv("NORMA_BASH_MAX_FILE_MB", "1024")
	spec2 := runner.RunSpec{Env: map[string]string{}}
	if err := s.runnerNetwork(&spec2, &runnerfiles.Plan{}, runnerEnvironment{DirectNetwork: true}, defaultRunnerConfig()); err != nil {
		t.Fatalf("runnerNetwork with runner callback: %v", err)
	}
	if spec2.Env["ARTEX_OOB_SERVER"] != "https://oob.example.com" {
		t.Fatalf("ARTEX_OOB_SERVER = %q, want https://oob.example.com", spec2.Env["ARTEX_OOB_SERVER"])
	}
	if spec2.Env["ARTEX_CALLBACK_PORTS"] != "20011-20015" || spec2.Env["ARTEX_CALLBACK_PUBLIC_HOST"] != "203.0.113.20" {
		t.Fatalf("runner callback env = %+v, want 20011-20015 / 203.0.113.20", spec2.Env)
	}
	if spec2.Env["NORMA_GREP_TIMEOUT_MS"] != "45000" || spec2.Env["NORMA_BASH_MAX_FILE_MB"] != "1024" {
		t.Fatalf("runner tool env = %+v, want NORMA_GREP_TIMEOUT_MS=45000 NORMA_BASH_MAX_FILE_MB=1024", spec2.Env)
	}
}

func TestOOBCallbackGuidance(t *testing.T) {
	mapLookup := func(m map[string]string) func(string) string {
		return func(k string) string { return m[k] }
	}

	// Empty or ports-without-host must emit nothing (preserve static prompt cache).
	if got := oobCallbackGuidance(mapLookup(map[string]string{"ARTEX_CALLBACK_PORTS": "20001-20005"})); got != "" {
		t.Fatalf("expected empty guidance when host unset, got %q", got)
	}

	// Private OOB + SSH callback emits sanitized host/ports and NEVER leaks tokens or URL credentials.
	got := oobCallbackGuidance(mapLookup(map[string]string{
		"ARTEX_OOB_SERVER":           "https://user:urlsecret@oob.example.com",
		"ARTEX_OOB_TOKEN":            "super-secret-oob-token",
		"ARTEX_CALLBACK_PUBLIC_HOST": "203.0.113.20",
		"ARTEX_CALLBACK_PORTS":       "20001-20005,8080:18080",
	}))
	for _, want := range []string{"https://oob.example.com", "203.0.113.20", "20001-20005,8080:18080", "0.0.0.0:<本地端口>"} {
		if !strings.Contains(got, want) {
			t.Fatalf("guidance missing %q:\n%s", want, got)
		}
	}
	for _, forbidden := range []string{"urlsecret", "super-secret-oob-token"} {
		if strings.Contains(got, forbidden) {
			t.Fatalf("guidance leaked secret %q:\n%s", forbidden, got)
		}
	}

	// Disable-public OOB without private server notifies worker.
	gotDisable := oobCallbackGuidance(mapLookup(map[string]string{"ARTEX_OOB_DISABLE_PUBLIC": "1"}))
	if !strings.Contains(gotDisable, "-ni") {
		t.Fatalf("expected disable-public notice, got %q", gotDisable)
	}
}
