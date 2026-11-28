package tool

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os/exec"
	"regexp"
	"strings"
	"time"

	"github.com/RC-CHN/ARTEX/norma/permission"
)

// catastrophicBash matches a small set of irreversibly destructive commands
// that are hard-denied regardless of mode (NFR-10). This is a safety floor, not
// a full sandbox — hosts should still gate Bash via CanUseTool.
var catastrophicBash = []*regexp.Regexp{
	regexp.MustCompile(`\brm\s+(-[a-zA-Z]*\s+)*-[a-zA-Z]*[rf][a-zA-Z]*\s+(-[a-zA-Z]+\s+)*/(\s|$)`), // rm -rf /
	regexp.MustCompile(`:\s*\(\s*\)\s*\{\s*:\s*\|\s*:\s*&\s*\}\s*;`),                               // fork bomb
	regexp.MustCompile(`\bmkfs\.\w+\s+/dev/`),                                                      // format a device
	regexp.MustCompile(`\bdd\b[^\n]*\bof=/dev/(sd|nvme|hd)`),                                       // overwrite a disk
}

// disallowedAutoBackground lists commands that must never be silently moved to
// the background on timeout (wait primitives, heavy scanners, browsers, network
// clients, and long-running script runtimes).
var disallowedAutoBackground = []string{
	"sleep",
	"katana", "nuclei", "httpx", "ffuf", "naabu", "sqlmap", "nmap", "masscan",
	"gobuster", "feroxbuster", "dirsearch", "subfinder", "amass",
	"chromium", "google-chrome", "playwright",
	"curl", "wget",
	"python", "python3", "node",
}

// NewBash builds the Bash tool: run a shell command with a timeout, optionally in
// the background.
func NewBash() CoreTool {
	props := map[string]any{
		"command":    map[string]any{"type": "string", "description": "The shell command to execute."},
		"timeout_ms": map[string]any{"type": "integer", "description": "Timeout in ms (default 120000, max 600000)."},
	}
	desc := "Executes a shell command in the working directory and returns combined stdout and stderr. Use for running tests, builds, package managers, and git. Prefer the dedicated file tools for file work."
	prompt := "The command runs through the shell, so you are not limited to one command: chain steps with && or ;, use pipes, and pass multi-line scripts or heredocs. For anything beyond a simple one-liner — loops, parsing, string/JSON handling, HTTP logic, computation — prefer writing a short script (Python, Node, shell, etc.) and executing it (e.g. via a heredoc or by writing a file then running it) rather than forcing everything into a single command. A timeout (default 120s, max 600s) applies. Avoid commands needing interactive input."
	if !BackgroundTasksDisabled() {
		props["run_in_background"] = map[string]any{
			"type":        "boolean",
			"description": "Run in the background and return immediately; read its output later with TaskOutput or Read, and you are notified when it completes. A foreground command that exceeds its timeout is also moved to the background automatically.",
		}
		desc += " Set run_in_background to return immediately and read the output later."
	}
	return Build(Spec{
		Name:        "Bash",
		Description: desc,
		Prompt:      prompt,
		Schema: map[string]any{
			"type":       "object",
			"properties": props,
			"required":   []any{"command"},
		},
		Permissions: bashPermissions,
		Run:         runBash,
	})
}

func bashPermissions(_ context.Context, input json.RawMessage, _ permission.Context) permission.Decision {
	var in struct {
		Command string `json:"command"`
	}
	_ = json.Unmarshal(input, &in)
	for _, re := range catastrophicBash {
		if re.MatchString(in.Command) {
			return permission.Denied("denied: command appears irreversibly destructive and is blocked by the safety floor")
		}
	}
	return permission.AskUser("run shell command: " + in.Command)
}

func runBash(ctx context.Context, input json.RawMessage, tc *ToolContext) (Result, error) {
	var in struct {
		Command         string `json:"command"`
		TimeoutMS       int    `json:"timeout_ms"`
		RunInBackground bool   `json:"run_in_background"`
	}
	if err := json.Unmarshal(input, &in); err != nil {
		return Result{}, err
	}
	if strings.TrimSpace(in.Command) == "" {
		return Errorf("Error: command is required"), nil
	}
	timeout := 120 * time.Second
	if in.TimeoutMS > 0 {
		timeout = time.Duration(in.TimeoutMS) * time.Millisecond
		if timeout > 600*time.Second {
			timeout = 600 * time.Second
		}
	}

	// Background-capable path: requires a task manager on the context.
	if tc != nil && tc.Tasks != nil && !BackgroundTasksDisabled() {
		return runBashManaged(ctx, tc, in.Command, timeout, in.RunInBackground)
	}
	// Fallback: synchronous execution (unchanged legacy behavior).
	return runBashSync(ctx, tc, in.Command, timeout)
}

// runBashManaged runs the command through the task manager, supporting explicit
// background launch and timeout auto-backgrounding.
func runBashManaged(ctx context.Context, tc *ToolContext, command string, timeout time.Duration, explicitBG bool) (Result, error) {
	spec := SpawnSpec{Command: command, Kind: KindBash, WorkingDir: tc.WorkingDir, Description: short(command), Env: tc.Env}

	if explicitBG {
		if running, maxBG := tc.Tasks.RunningBackgroundCount(), tc.Tasks.MaxBackgroundTasks(); running >= maxBG {
			return Errorf(fmt.Sprintf(
				"Error: background task limit reached (%d/%d running). Wait for an existing task to finish or stop one with TaskList/TaskStop before launching another.",
				running, maxBG)), nil
		}
		t, err := tc.Tasks.Spawn(spec)
		if err != nil {
			return Errorf("Error: failed to start background command: " + err.Error()), nil
		}
		tc.Tasks.Background(t.ID)
		return Text(fmt.Sprintf(
			"Running in background as %s. Output file: %s\nUse TaskOutput{task_id:%q} or Read to read its output; you are notified when it completes.",
			t.ID, t.OutputPath, t.ID)), nil
	}

	t, finished, output, err := tc.Tasks.RunForeground(ctx, spec, timeout)
	if err != nil {
		if t != nil {
			tc.Tasks.Forget(t.ID)
		}
		return Errorf("Error: " + err.Error()), nil
	}
	if finished {
		info, _ := tc.Tasks.Get(t.ID)
		tc.Tasks.Forget(t.ID)
		if info.Status == TaskFailed {
			if strings.TrimSpace(output) == "" {
				output = "(no output)"
			}
			return Errorf(fmt.Sprintf("%s\n\n[exit code %d]", Capture(tc, output), info.ExitCode)), nil
		}
		if strings.TrimSpace(output) == "" {
			output = "(command produced no output)"
		}
		return Text(Capture(tc, output)), nil
	}

	// Timed out while still running.
	if autoBackgroundAllowed(command) && tc.Tasks.RunningBackgroundCount() < tc.Tasks.MaxBackgroundTasks() {
		tc.Tasks.Background(t.ID)
		return Text(fmt.Sprintf(
			"Command still running after %s; moved to background as %s. Output file: %s\nUse TaskOutput{task_id:%q} to read its output; you are notified when it completes.",
			timeout, t.ID, t.OutputPath, t.ID)), nil
	}
	out, _ := tc.Tasks.Output(t.ID, 0)
	tc.Tasks.Kill(t.ID)
	select {
	case <-t.done:
	case <-time.After(3 * time.Second):
	}
	tc.Tasks.Forget(t.ID)
	return Errorf(Capture(tc, out) + fmt.Sprintf("\n\n[command timed out after %s]", timeout)), nil
}

// runBashSync is the original blocking implementation, used when no task manager
// is available (background execution disabled).
func runBashSync(ctx context.Context, tc *ToolContext, command string, timeout time.Duration) (Result, error) {
	cctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	shell, flags := shellCmd()
	var extraEnv []string
	if tc != nil {
		extraEnv = tc.Env
	}
	execCommand := wrapCommandWithFsize(command, extraEnv)
	cmd := exec.CommandContext(cctx, shell, append(flags, execCommand)...)
	if tc != nil {
		cmd.Dir = tc.WorkingDir
		if env := withEnv(tc.Env); env != nil {
			cmd.Env = env
		}
	}
	buf := newCaptureWriter(tc)
	cmd.Stdout = buf
	cmd.Stderr = buf
	cg := newCmdCgroup()
	setDetachedWithCgroup(cmd, cg)

	var err error
	if startErr := cmd.Start(); startErr != nil {
		cg.cleanup()
		err = startErr
	} else {
		if cg != nil && !cg.attach(cmd.Process.Pid) {
			cg = nil
		}
		err = cmd.Wait()
		cg.cleanup()
	}

	out := buf.finish()
	if cctx.Err() == context.DeadlineExceeded {
		return Errorf(out + fmt.Sprintf("\n\n[command timed out after %s]", timeout)), nil
	}
	if err != nil {
		var ee *exec.ExitError
		if errors.As(err, &ee) {
			if out == "" {
				out = "(no output)"
			}
			return Errorf(fmt.Sprintf("%s\n\n[exit code %d]", out, ee.ExitCode())), nil
		}
		return Errorf(fmt.Sprintf("%s\n\n[failed to run: %v]", out, err)), nil
	}
	if strings.TrimSpace(out) == "" {
		out = "(command produced no output)"
	}
	return Text(out), nil
}

// autoBackgroundAllowed reports whether a timed-out command may be moved to the
// background instead of being killed. It inspects every shell segment separated
// by &&, ||, ;, |, or newline and strips common wrapper prefixes (env, timeout,
// nohup, nice, sudo, subshell parens, and env assignments) so chained or
// wrapped scanners cannot bypass the denylist.
func autoBackgroundAllowed(command string) bool {
	segs := splitShellSegments(command)
	if len(segs) == 0 {
		return false
	}
	foundAny := false
	for _, seg := range segs {
		cmdName, ok := extractSegmentCommand(seg)
		if !ok {
			continue
		}
		foundAny = true
		for _, d := range disallowedAutoBackground {
			if cmdName == d {
				return false
			}
		}
	}
	return foundAny
}

// splitShellSegments splits command on unquoted shell operators (&&, ||, |&, ;,
// |, \n) while preserving quotes and avoiding splits inside redirections such
// as 2>&1.
func splitShellSegments(command string) []string {
	var segs []string
	var cur strings.Builder
	inSingle, inDouble := false, false
	flush := func() {
		if s := strings.TrimSpace(cur.String()); s != "" {
			segs = append(segs, s)
		}
		cur.Reset()
	}
	for i := 0; i < len(command); i++ {
		ch := command[i]
		if ch == '\\' && !inSingle && i+1 < len(command) {
			next := command[i+1]
			if next == '"' || next == '\'' || next == ';' || next == '|' || next == '&' || next == '\n' {
				cur.WriteByte(ch)
				cur.WriteByte(next)
				i++
				continue
			}
		}
		if ch == '\'' && !inDouble {
			inSingle = !inSingle
			cur.WriteByte(ch)
			continue
		}
		if ch == '"' && !inSingle {
			inDouble = !inDouble
			cur.WriteByte(ch)
			continue
		}
		if inSingle || inDouble {
			cur.WriteByte(ch)
			continue
		}
		switch ch {
		case ';', '\n':
			flush()
		case '|':
			if i+1 < len(command) && (command[i+1] == '|' || command[i+1] == '&') {
				i++
			}
			flush()
		case '&':
			if i+1 < len(command) && command[i+1] == '&' {
				i++
				flush()
				continue
			}
			// Keep redirections like 2>&1 or &>file intact.
			if (i > 0 && command[i-1] == '>') || (i+1 < len(command) && command[i+1] == '>') {
				cur.WriteByte(ch)
				continue
			}
			flush()
		default:
			cur.WriteByte(ch)
		}
	}
	flush()
	return segs
}

// extractSegmentCommand peels subshell grouping, env assignments, shell control
// keywords, and wrapper commands (env, timeout, nohup, nice, sudo) from one
// shell segment and returns the normalized lowercase executable basename.
func extractSegmentCommand(seg string) (string, bool) {
	fields := strings.Fields(seg)
	i := 0
	for i < len(fields) {
		tok := strings.TrimLeft(fields[i], "({!")
		if tok == "" {
			i++
			continue
		}
		fields[i] = tok

		// Skip leading VAR=val environment variable assignments.
		if isEnvAssign(tok) {
			i++
			continue
		}

		base := normalizeCmdBase(tok)
		switch base {
		case "do", "then", "else", "elif", "if", "while", "until", "command", "exec":
			i++
			continue
		case "time":
			i++
			if i < len(fields) && fields[i] == "-p" {
				i++
			}
			continue
		case "nohup":
			i++
			if i < len(fields) && fields[i] == "--" {
				i++
			}
			continue
		case "env":
			i++
			for i < len(fields) {
				f := fields[i]
				if f == "--" {
					i++
					break
				}
				if isEnvAssign(f) {
					i++
					continue
				}
				if strings.HasPrefix(f, "-") && f != "-" {
					if envFlagTakesArg(f) && !strings.Contains(f, "=") {
						i += 2
					} else {
						i++
					}
					continue
				}
				if f == "-" {
					i++
					continue
				}
				break
			}
			continue
		case "timeout":
			i++
			for i < len(fields) {
				f := fields[i]
				if f == "--" {
					i++
					break
				}
				if strings.HasPrefix(f, "-") {
					if timeoutFlagTakesArg(f) && !strings.Contains(f, "=") {
						i += 2
					} else {
						i++
					}
					continue
				}
				break
			}
			// Skip the required DURATION positional argument.
			if i < len(fields) {
				i++
			}
			continue
		case "nice":
			i++
			for i < len(fields) {
				f := fields[i]
				if f == "--" {
					i++
					break
				}
				if f == "-n" || f == "--adjustment" {
					i += 2
					continue
				}
				if strings.HasPrefix(f, "-") {
					i++
					continue
				}
				break
			}
			continue
		case "sudo":
			i++
			for i < len(fields) {
				f := fields[i]
				if f == "--" {
					i++
					break
				}
				if isEnvAssign(f) {
					i++
					continue
				}
				if strings.HasPrefix(f, "-") {
					if sudoFlagTakesArg(f) && !strings.Contains(f, "=") {
						i += 2
					} else {
						i++
					}
					continue
				}
				break
			}
			continue
		}
		if base == "" {
			return "", false
		}
		return base, true
	}
	return "", false
}

func isEnvAssign(tok string) bool {
	eq := strings.IndexByte(tok, '=')
	return eq > 0 && !strings.ContainsAny(tok[:eq], "/\\\"'-")
}

func normalizeCmdBase(tok string) string {
	base := strings.TrimRight(tok, ")}")
	base = strings.Trim(base, "\"'")
	if idx := strings.LastIndexAny(base, "/\\"); idx >= 0 {
		base = base[idx+1:]
	}
	base = strings.TrimSuffix(strings.ToLower(base), ".exe")
	return base
}

func envFlagTakesArg(f string) bool {
	switch f {
	case "-u", "--unset", "-C", "--chdir", "-S", "--split-string",
		"--block-signal", "--default-signal", "--ignore-signal":
		return true
	}
	return false
}

func timeoutFlagTakesArg(f string) bool {
	switch f {
	case "-k", "--kill-after", "-s", "--signal":
		return true
	}
	return false
}

func sudoFlagTakesArg(f string) bool {
	switch f {
	case "-u", "--user", "-g", "--group", "-h", "--host", "-p", "--prompt",
		"-r", "--role", "-t", "--type", "-C", "--close-from", "-T", "--command-timeout",
		"-D", "--chdir":
		return true
	}
	return false
}
