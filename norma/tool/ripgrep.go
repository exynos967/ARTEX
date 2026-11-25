package tool

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	// Safety ceilings for ripgrep output buffering.
	maxRipgrepLines     = 5000    // hard line ceiling when head_limit <= 0
	maxRipgrepBytes     = 8 << 20 // 8 MiB total buffered output ceiling
	maxRipgrepLineBytes = 64 << 10 // 64 KiB per buffered line
)

// Ripgrep integration: the Grep tool prefers the ripgrep binary when available
// (faster, .gitignore-aware, full ripgrep syntax) and falls back to the pure-Go
// implementation otherwise. Resolution runs once:
//
//  1. an `rg` already on PATH is used as-is;
//  2. otherwise a best-effort `npm install -g @vscode/ripgrep` runs (npm is
//     assumed present) and the installed binary is located;
//  3. on any failure — no npm, install error, binary not found — the pure-Go
//     grep is used, so search always works.
//
// Env controls:
//   - NORMA_DISABLE_RIPGREP=1     force the pure-Go implementation (also used by tests)
//   - NORMA_RIPGREP_NO_INSTALL=1  use an existing rg but never auto-install

var (
	rgOnce     sync.Once
	rgResolved string
)

// RipgrepPath returns the resolved ripgrep binary path, or "" when the pure-Go
// grep should be used. The heavy resolution (detect + optional npm install) runs
// at most once per process.
func RipgrepPath() string {
	if os.Getenv("NORMA_DISABLE_RIPGREP") != "" {
		return ""
	}
	rgOnce.Do(func() { rgResolved = resolveRipgrep() })
	return rgResolved
}

// EnsureRipgrep warms ripgrep resolution so the cost (including a possible npm
// install) is paid at startup rather than on the first Grep call. Hosts may call
// it once at boot. Returns the resolved path ("" = Go fallback).
func EnsureRipgrep() string { return RipgrepPath() }

func resolveRipgrep() string {
	if p, err := exec.LookPath("rg"); err == nil {
		return p
	}
	if os.Getenv("NORMA_RIPGREP_NO_INSTALL") != "" {
		return ""
	}
	return installRipgrepViaNpm()
}

func installRipgrepViaNpm() string {
	if _, err := exec.LookPath("npm"); err != nil {
		return "" // no npm → Go fallback
	}
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, "npm", "install", "-g", "@vscode/ripgrep")
	setDetached(cmd)
	if err := cmd.Run(); err != nil {
		return ""
	}
	if p, err := exec.LookPath("rg"); err == nil {
		return p
	}
	return npmGlobalRipgrep()
}

// npmGlobalRipgrep locates the rg binary vendored by @vscode/ripgrep in the npm
// global root (it exposes no `rg` command, so we resolve the path directly).
func npmGlobalRipgrep() string {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, "npm", "root", "-g")
	setDetached(cmd)
	out, err := cmd.Output()
	if err != nil {
		return ""
	}
	name := "rg"
	if runtime.GOOS == "windows" {
		name = "rg.exe"
	}
	p := filepath.Join(strings.TrimSpace(string(out)), "@vscode", "ripgrep", "bin", name)
	if st, err := os.Stat(p); err == nil && !st.IsDir() {
		return p
	}
	return ""
}

// ripgrepReq carries the parsed Grep parameters for the ripgrep backend.
type ripgrepReq struct {
	pattern, glob, typ, mode         string
	ignoreCase, multiline, showLines bool
	before, after                    int
	root                             string
	headLimit                        *int
	offset                           int
}

// runWithRipgrep runs the query through the rg binary and formats the result.
// Returns ok=false when rg failed for a real reason (not "no matches"), so the
// caller falls back to the Go implementation.
func runWithRipgrep(ctx context.Context, rg string, r ripgrepReq, tc *ToolContext) (Result, bool) {
	args := []string{"--color", "never"}
	if r.ignoreCase {
		args = append(args, "-i")
	}
	if r.multiline {
		args = append(args, "-U", "--multiline-dotall")
	}
	switch r.mode {
	case "files_with_matches":
		args = append(args, "-l")
	case "count":
		args = append(args, "-c")
	default: // content
		args = append(args, "--no-heading")
		if r.showLines {
			args = append(args, "-n")
		}
		if r.before > 0 {
			args = append(args, "-B", strconv.Itoa(r.before))
		}
		if r.after > 0 {
			args = append(args, "-A", strconv.Itoa(r.after))
		}
	}
	if r.glob != "" {
		args = append(args, "--glob", r.glob)
	}
	if r.typ != "" {
		if _, known := rgFileTypes[strings.ToLower(r.typ)]; known {
			args = append(args, "--type", r.typ)
		} else {
			args = append(args, "--glob", "*."+r.typ) // unknown type → extension glob
		}
	}
	// Run inside root so printed paths are root-relative (matching the Go impl).
	dir, target := r.root, "."
	if st, err := os.Stat(r.root); err == nil && !st.IsDir() {
		dir, target = filepath.Dir(r.root), filepath.Base(r.root)
	}
	// `-e pattern --` keeps a pattern/path starting with '-' from being read as a flag.
	args = append(args, "-e", r.pattern, "--", target)

	cmd := exec.CommandContext(ctx, rg, args...)
	cmd.Dir = dir
	headLimit := 250
	if r.headLimit != nil {
		headLimit = *r.headLimit
	}
	page := newLinePager(headLimit, r.offset)
	cmd.Stdout = page
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
	if err != nil {
		var ee *exec.ExitError
		if errors.As(err, &ee) && ee.ExitCode() == 1 {
			return Text("No matches found"), true // rg exit 1 = no matches
		}
		return Result{}, false // real failure → Go fallback
	}
	kept, more := page.finish()
	if page.total == 0 {
		return Text("No matches found"), true
	}
	res := strings.Join(kept, "\n")
	if len(kept) > 0 {
		res += "\n"
	}
	if more > 0 {
		if page.hitSafetyCap(more) {
			res += fmt.Sprintf("... [%d more result(s) truncated by safety ceiling — page with offset=%d or narrow pattern/path] ...\n", more, max(r.offset, 0)+len(kept))
		} else {
			res += fmt.Sprintf("... [%d more result(s) — page with offset=%d, or head_limit=0 for all] ...\n", more, max(r.offset, 0)+len(kept))
		}
	}
	return Text(Capture(tc, res)), true
}

// Retain only the requested page while counting every result for the existing
// exact "more results" notice. Large skipped lines never need to be buffered.
// Trailing blank lines are dropped just like TrimRight(output, "\n").
type linePager struct {
	limit, offset   int
	maxLines        int // safety ceiling when limit <= 0 (0 = uncapped)
	maxBytes        int // safety ceiling on total buffered bytes (0 = uncapped)
	maxLineBytes    int // safety ceiling on a single buffered line (0 = uncapped)
	position, total int
	lineBytes       int
	bufferedBytes   int
	lineTruncated   bool
	byteCapped      bool
	pending         strings.Builder
	lines           []string
}

func newLinePager(limit, offset int) *linePager {
	return &linePager{
		limit:        limit,
		offset:       max(offset, 0),
		maxLines:     maxRipgrepLines,
		maxBytes:     maxRipgrepBytes,
		maxLineBytes: maxRipgrepLineBytes,
	}
}

func (p *linePager) keeping() bool {
	if p.byteCapped || p.position < p.offset {
		return false
	}
	if p.limit > 0 && p.position-p.offset >= p.limit {
		return false
	}
	if p.limit <= 0 && p.maxLines > 0 && p.position-p.offset >= p.maxLines {
		return false
	}
	if p.maxBytes > 0 && p.bufferedBytes >= p.maxBytes {
		return false
	}
	return true
}

func (p *linePager) endLine() {
	if p.keeping() {
		line := p.pending.String()
		if p.maxBytes > 0 && len(p.lines) > 0 && p.bufferedBytes+len(line)+1 > p.maxBytes {
			p.byteCapped = true
		} else {
			p.lines = append(p.lines, line)
			p.bufferedBytes += len(line) + 1
		}
	}
	p.pending.Reset()
	p.lineTruncated = false
	p.position++
	if p.lineBytes > 0 {
		p.total = p.position
	}
	p.lineBytes = 0
}

func (p *linePager) Write(data []byte) (int, error) {
	n := len(data)
	for len(data) > 0 {
		i := bytes.IndexByte(data, '\n')
		end := len(data)
		if i >= 0 {
			end = i
		}
		p.lineBytes += end
		if p.keeping() {
			if p.maxLineBytes <= 0 {
				p.pending.Write(data[:end])
			} else {
				rem := p.maxLineBytes - p.pending.Len()
				if rem > 0 {
					p.pending.Write(data[:min(end, rem)])
					if end > rem && !p.lineTruncated {
						p.pending.WriteString("...[truncated]")
						p.lineTruncated = true
					}
				} else if end > 0 && !p.lineTruncated {
					p.pending.WriteString("...[truncated]")
					p.lineTruncated = true
				}
			}
		}
		if i < 0 {
			break
		}
		p.endLine()
		data = data[i+1:]
	}
	return n, nil
}

func (p *linePager) finish() ([]string, int) {
	if p.lineBytes > 0 {
		p.endLine()
	}
	available := max(0, p.total-p.offset)
	if len(p.lines) > available {
		p.lines = p.lines[:available]
	}
	return p.lines, available - len(p.lines)
}

func (p *linePager) hitSafetyCap(more int) bool {
	if more <= 0 {
		return false
	}
	if p.byteCapped || (p.maxBytes > 0 && p.bufferedBytes >= p.maxBytes) {
		return true
	}
	return p.limit <= 0 && p.maxLines > 0
}
