package tool

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
)

var skipDirs = map[string]bool{".git": true, "node_modules": true, "vendor": true}

const (
	// maxGrepFileBytes skips giant files/dumps in the Go grep fallback so
	// os.ReadFile cannot cause OOM.
	maxGrepFileBytes = 8 << 20 // 8 MiB
	// maxGrepLineBytes caps single-line buffering in scanLineCount.
	maxGrepLineBytes = 256 << 10 // 256 KiB
	// maxGlobMatches caps collected files in Glob before returning a truncation notice.
	maxGlobMatches = 10000
	// defaultSearchTimeout bounds a single Grep or Glob call so searching a
	// huge directory tree never hangs indefinitely.
	defaultSearchTimeout = 30 * time.Second
	// maxGrepScannedFiles caps regular files inspected by the pure-Go fallback.
	maxGrepScannedFiles = 50000
	// maxGrepEarlyStopExtra is how many extra matching entries the pure-Go walk
	// collects past offset+head_limit before stopping early.
	maxGrepEarlyStopExtra = 1000
)

func searchTimeout() time.Duration {
	if raw := strings.TrimSpace(os.Getenv("NORMA_GREP_TIMEOUT_MS")); raw != "" {
		if ms, err := strconv.Atoi(raw); err == nil && ms > 0 {
			return time.Duration(ms) * time.Millisecond
		}
	}
	return defaultSearchTimeout
}

func withSearchTimeout(ctx context.Context) (context.Context, context.CancelFunc, time.Duration) {
	d := searchTimeout()
	if dl, ok := ctx.Deadline(); ok {
		if rem := time.Until(dl); rem > 0 && rem < d {
			d = rem
		}
	}
	sctx, cancel := context.WithTimeout(ctx, d)
	return sctx, cancel, d
}

// isVirtualSystemDir reports Linux/Unix pseudo-filesystems that must never be
// recursively walked when searching a broad parent such as "/".
func isVirtualSystemDir(path string) bool {
	switch filepath.Clean(path) {
	case "/proc", "/sys", "/dev":
		return true
	default:
		return false
	}
}

// NewGlob builds the Glob tool: find files by pattern, newest first.
func NewGlob() CoreTool {
	return Build(Spec{
		Name:        "Glob",
		Description: "Finds files whose path matches a glob pattern (supports ** for any depth, e.g. \"**/*.go\"). Returns paths sorted by modification time, newest first.",
		Prompt:      "Use this instead of `find`. The pattern matches paths relative to the search directory.",
		Schema: map[string]any{
			"type": "object",
			"properties": map[string]any{
				"pattern": map[string]any{"type": "string", "description": "Glob pattern, e.g. src/**/*.go"},
				"path":    map[string]any{"type": "string", "description": "Directory to search (default working dir)."},
			},
			"required": []any{"pattern"},
		},
		ReadOnly:    always,
		Concurrent:  always,
		Permissions: allowReadOnly,
		Run:         runGlob,
	})
}

func runGlob(ctx context.Context, input json.RawMessage, tc *ToolContext) (Result, error) {
	return runGlobWithCap(ctx, input, tc, maxGlobMatches)
}

func runGlobWithCap(ctx context.Context, input json.RawMessage, tc *ToolContext, capMatches int) (Result, error) {
	if capMatches <= 0 {
		capMatches = maxGlobMatches
	}
	var in struct {
		Pattern string `json:"pattern"`
		Path    string `json:"path"`
	}
	if err := json.Unmarshal(input, &in); err != nil {
		return Result{}, err
	}
	root := tc.WorkingDir
	if in.Path != "" {
		root = resolvePath(tc, in.Path)
	}
	if root == "" {
		root = "."
	}
	searchCtx, cancelSearch, timeout := withSearchTimeout(ctx)
	defer cancelSearch()

	type match struct {
		path string
		mod  int64
	}
	var matches []match
	truncated := false
	timedOut := false
	matchPath := compileGlob(in.Pattern)
	walkErr := filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if searchCtx.Err() != nil {
			if ctx.Err() == nil {
				timedOut = true
			}
			return searchCtx.Err()
		}
		if err != nil {
			return nil
		}
		if d.IsDir() {
			if skipDirs[d.Name()] || (p != root && isVirtualSystemDir(p)) {
				return filepath.SkipDir
			}
			return nil
		}
		rel, rerr := filepath.Rel(root, p)
		if rerr != nil {
			rel = p
		}
		if matchPath(rel) {
			if len(matches) >= capMatches {
				truncated = true
				return fs.SkipAll
			}
			var mod int64
			if info, e := d.Info(); e == nil {
				mod = info.ModTime().UnixNano()
			}
			matches = append(matches, match{p, mod})
		}
		return nil
	})
	if walkErr != nil && ctx.Err() != nil {
		return Result{}, ctx.Err()
	}
	if searchCtx.Err() != nil && ctx.Err() == nil {
		timedOut = true
	}
	sort.Slice(matches, func(i, j int) bool { return matches[i].mod > matches[j].mod })
	if len(matches) == 0 {
		if timedOut {
			return Errorf(fmt.Sprintf("Error: glob timed out after %s while scanning %s — narrow pattern or path", timeout, root)), nil
		}
		return Text("No files found"), nil
	}
	var b strings.Builder
	for _, m := range matches {
		b.WriteString(m.path)
		b.WriteByte('\n')
	}
	if truncated {
		fmt.Fprintf(&b, "... [results truncated at %d matches — narrow pattern or path] ...\n", capMatches)
	}
	if timedOut {
		fmt.Fprintf(&b, "... [search timed out after %s — partial results shown; narrow pattern or path] ...\n", timeout)
	}
	return Text(Capture(tc, b.String())), nil
}

func matchGlob(pattern, path string) bool {
	return compileGlob(pattern)(path)
}

// Parse the pattern once per directory walk; retain filepath.Match's exact
// escaping, malformed-pattern and platform semantics for each segment.
func compileGlob(pattern string) func(string) bool {
	pattern = filepath.ToSlash(pattern)
	segments := strings.Split(pattern, "/")
	baseOnly := !strings.Contains(pattern, "/")
	return func(path string) bool {
		path = filepath.ToSlash(path)
		if baseOnly {
			if ok, _ := filepath.Match(pattern, filepath.Base(path)); ok {
				return true
			}
		}
		return globSegments(segments, strings.Split(path, "/"))
	}
}

func globSegments(pat, name []string) bool {
	if len(pat) == 0 {
		return len(name) == 0
	}
	if pat[0] == "**" {
		for i := 0; i <= len(name); i++ {
			if globSegments(pat[1:], name[i:]) {
				return true
			}
		}
		return false
	}
	if len(name) == 0 {
		return false
	}
	if ok, _ := filepath.Match(pat[0], name[0]); !ok {
		return false
	}
	return globSegments(pat[1:], name[1:])
}

// NewGrep builds the Grep tool: regex content search (RE2).
const grepDescription = "A powerful search tool built on ripgrep\n" +
	"\n" +
	"Usage:\n" +
	"- ALWAYS use Grep for search tasks. NEVER invoke `grep` or `rg` as a Bash command. The Grep tool has been optimized for correct permissions and access.\n" +
	"- Supports full regex syntax (e.g., \"log.*Error\", \"function\\s+\\w+\")\n" +
	"- Filter files with glob parameter (e.g., \"*.js\", \"**/*.tsx\") or type parameter (e.g., \"js\", \"py\", \"rust\")\n" +
	"- Output modes: \"content\" shows matching lines, \"files_with_matches\" shows only file paths (default), \"count\" shows match counts\n" +
	"- Use Agent tool for open-ended searches requiring multiple rounds\n" +
	"- Pattern syntax: Uses ripgrep (not grep) - literal braces need escaping (use `interface\\{\\}` to find `interface{}` in Go code)\n" +
	"- Prefer `head_limit` to avoid large result sets.\n" +
	"- Multiline matching: By default patterns match within single lines only. For cross-line patterns like `struct \\{[\\s\\S]*?field`, use `multiline: true`\n" +
	"- Prefer Grep over terminal rg/grep for codebase search unless you specifically need shell features."

func NewGrep() CoreTool {
	return Build(Spec{
		Name:        "Grep",
		Description: grepDescription,
		Schema: map[string]any{
			"type": "object",
			"properties": map[string]any{
				"pattern":     map[string]any{"type": "string", "description": "RE2 regular expression to search for."},
				"path":        map[string]any{"type": "string", "description": "File or directory to search. Defaults to the working directory."},
				"glob":        map[string]any{"type": "string", "description": "Only search files matching this glob, e.g. *.go or *.{ts,tsx}"},
				"type":        map[string]any{"type": "string", "description": "Only search a file type, e.g. go, py, js, ts, rust, java. Unknown types are treated as an extension (type:foo → *.foo)."},
				"output_mode": map[string]any{"type": "string", "description": "files_with_matches (default) | content | count"},
				"-i":          map[string]any{"type": "boolean", "description": "Case-insensitive."},
				"-n":          map[string]any{"type": "boolean", "description": "Show line numbers (content mode). Default true."},
				"-A":          map[string]any{"type": "integer", "description": "Lines of context to show after each match (content mode)."},
				"-B":          map[string]any{"type": "integer", "description": "Lines of context to show before each match (content mode)."},
				"-C":          map[string]any{"type": "integer", "description": "Lines of context before and after each match (content mode)."},
				"multiline":   map[string]any{"type": "boolean", "description": "Multiline mode: . matches newlines and patterns may span lines. Default false."},
				"head_limit":  map[string]any{"type": "integer", "description": "Limit output to the first N results (lines/files/counts). Default 250; pass 0 for unlimited."},
				"offset":      map[string]any{"type": "integer", "description": "Skip the first N results before applying head_limit (paging). Default 0."},
			},
			"required": []any{"pattern"},
		},
		ReadOnly:    always,
		Concurrent:  always,
		Permissions: allowReadOnly,
		Run:         runGrep,
	})
}

func runGrep(ctx context.Context, input json.RawMessage, tc *ToolContext) (Result, error) {
	var in struct {
		Pattern    string `json:"pattern"`
		Path       string `json:"path"`
		Glob       string `json:"glob"`
		Type       string `json:"type"`
		OutputMode string `json:"output_mode"`
		IgnoreCase bool   `json:"-i"`
		LineNums   *bool  `json:"-n"`
		After      int    `json:"-A"`
		Before     int    `json:"-B"`
		Context    int    `json:"-C"`
		Multiline  bool   `json:"multiline"`
		HeadLimit  *int   `json:"head_limit"`
		Offset     int    `json:"offset"`
	}
	if err := json.Unmarshal(input, &in); err != nil {
		return Result{}, err
	}
	before, after := in.Before, in.After
	if in.Context > 0 {
		before, after = in.Context, in.Context
	}
	// RE2 inline flags: (?i) case-insensitive, (?s) dotall for multiline.
	flags := ""
	if in.IgnoreCase {
		flags += "i"
	}
	if in.Multiline {
		flags += "s"
	}
	pat := in.Pattern
	if flags != "" {
		pat = "(?" + flags + ")" + pat
	}
	re, err := regexp.Compile(pat)
	if err != nil {
		return Errorf(fmt.Sprintf("Error: invalid regex: %v", err)), nil
	}
	root := tc.WorkingDir
	if in.Path != "" {
		root = resolvePath(tc, in.Path)
	}
	if root == "" {
		root = "."
	}
	mode := in.OutputMode
	if mode == "" {
		mode = "files_with_matches"
	}
	showLines := true
	if in.LineNums != nil {
		showLines = *in.LineNums
	}

	searchCtx, cancelSearch, timeout := withSearchTimeout(ctx)
	defer cancelSearch()

	// Prefer the ripgrep binary when available; fall back to the Go walk below.
	if rg := RipgrepPath(); rg != "" {
		if res, ok := runWithRipgrep(ctx, searchCtx, timeout, rg, ripgrepReq{
			pattern: in.Pattern, glob: in.Glob, typ: in.Type, mode: mode,
			ignoreCase: in.IgnoreCase, multiline: in.Multiline, showLines: showLines,
			before: before, after: after, root: root, headLimit: in.HeadLimit, offset: in.Offset,
		}, tc); ok {
			return res, nil
		}
		if ctx.Err() != nil {
			return Result{}, ctx.Err()
		}
	}

	headLimit := 250
	if in.HeadLimit != nil {
		headLimit = *in.HeadLimit
	}
	earlyStopTarget := 0
	if headLimit > 0 {
		earlyStopTarget = max(in.Offset, 0) + headLimit + maxGrepEarlyStopExtra
	}

	typeGlobs := rgTypeGlobs(in.Type)
	var results []grepHit
	collectedEntries := 0
	scannedFiles := 0
	stoppedEarly := false
	cappedFiles := false
	timedOut := false

	scan := func(p, base string) {
		fh := scanFileContext(searchCtx, p, base, re, mode, showLines, in.Multiline, before, after)
		if fh != nil {
			results = append(results, *fh)
			if mode == "content" {
				collectedEntries += len(fh.lines)
			} else {
				collectedEntries++
			}
		}
	}
	info, statErr := os.Stat(root)
	if statErr != nil {
		return Errorf(fmt.Sprintf("Error: %v", statErr)), nil
	}
	if info.IsDir() {
		walkErr := filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
			if searchCtx.Err() != nil {
				if ctx.Err() == nil {
					timedOut = true
				}
				return searchCtx.Err()
			}
			if err != nil {
				return nil
			}
			if d.IsDir() {
				if skipDirs[d.Name()] || (p != root && isVirtualSystemDir(p)) {
					return filepath.SkipDir
				}
				return nil
			}
			// Skip FIFOs, sockets, device nodes, and symlinks so os.Open/ReadFile
			// can never block indefinitely on special files.
			if !d.Type().IsRegular() {
				return nil
			}
			base := filepath.Base(p)
			if in.Glob != "" {
				if ok, _ := filepath.Match(in.Glob, base); !ok {
					return nil
				}
			}
			if len(typeGlobs) > 0 && !matchAnyGlob(typeGlobs, base) {
				return nil
			}
			if scannedFiles >= maxGrepScannedFiles {
				cappedFiles = true
				return fs.SkipAll
			}
			scannedFiles++
			scan(p, root)
			if earlyStopTarget > 0 && collectedEntries >= earlyStopTarget {
				stoppedEarly = true
				return fs.SkipAll
			}
			return nil
		})
		if walkErr != nil && ctx.Err() != nil {
			return Result{}, ctx.Err()
		}
		if searchCtx.Err() != nil && ctx.Err() == nil {
			timedOut = true
		}
	} else {
		if ctx.Err() != nil {
			return Result{}, ctx.Err()
		}
		scan(root, filepath.Dir(root))
		if searchCtx.Err() != nil && ctx.Err() == nil {
			timedOut = true
		}
	}
	if len(results) == 0 {
		if timedOut {
			return Errorf(fmt.Sprintf("Error: grep timed out after %s while searching %s — narrow path, glob, or type", timeout, root)), nil
		}
		if cappedFiles {
			return Text(fmt.Sprintf("No matches found (stopped after scanning %d files — narrow path, glob, or type)", maxGrepScannedFiles)), nil
		}
		return Text("No matches found"), nil
	}
	sort.Slice(results, func(i, j int) bool { return results[i].path < results[j].path })

	// Flatten to output entries per mode, then page with offset + head_limit.
	var lines []string
	switch mode {
	case "content":
		for _, r := range results {
			lines = append(lines, r.lines...)
		}
	case "count":
		for _, r := range results {
			lines = append(lines, fmt.Sprintf("%s: %d", r.path, r.count))
		}
	default: // files_with_matches
		for _, r := range results {
			lines = append(lines, r.path)
		}
	}
	kept, more := applyHeadOffset(lines, headLimit, in.Offset)
	out := strings.Join(kept, "\n")
	if len(kept) > 0 {
		out += "\n"
	}
	if more > 0 {
		if stoppedEarly {
			out += fmt.Sprintf("... [at least %d more result(s), search stopped early — page with offset=%d or narrow pattern/path] ...\n", more, max(in.Offset, 0)+len(kept))
		} else {
			out += fmt.Sprintf("... [%d more result(s) — page with offset=%d, or head_limit=0 for all] ...\n", more, max(in.Offset, 0)+len(kept))
		}
	}
	if timedOut {
		out += fmt.Sprintf("... [search timed out after %s — partial results shown; narrow path, glob, or type] ...\n", timeout)
	} else if cappedFiles {
		out += fmt.Sprintf("... [stopped after scanning %d files — partial results shown; narrow path, glob, or type] ...\n", maxGrepScannedFiles)
	}
	return Text(Capture(tc, out)), nil
}

// rgFileTypes maps a ripgrep-style file type to its globs (common subset).
var rgFileTypes = map[string][]string{
	"go":       {"*.go"},
	"py":       {"*.py", "*.pyi"},
	"python":   {"*.py", "*.pyi"},
	"js":       {"*.js", "*.jsx", "*.mjs", "*.cjs", "*.vue"},
	"ts":       {"*.ts", "*.tsx", "*.mts", "*.cts"},
	"rust":     {"*.rs"},
	"java":     {"*.java"},
	"kotlin":   {"*.kt", "*.kts"},
	"c":        {"*.c", "*.h"},
	"cpp":      {"*.cpp", "*.cc", "*.cxx", "*.hpp", "*.hh", "*.hxx", "*.h"},
	"cs":       {"*.cs"},
	"rb":       {"*.rb"},
	"ruby":     {"*.rb"},
	"php":      {"*.php"},
	"swift":    {"*.swift"},
	"sh":       {"*.sh", "*.bash", "*.zsh"},
	"html":     {"*.html", "*.htm"},
	"css":      {"*.css", "*.scss", "*.sass", "*.less"},
	"json":     {"*.json"},
	"yaml":     {"*.yaml", "*.yml"},
	"toml":     {"*.toml"},
	"xml":      {"*.xml"},
	"md":       {"*.md", "*.markdown"},
	"markdown": {"*.md", "*.markdown"},
	"sql":      {"*.sql"},
	"proto":    {"*.proto"},
}

// rgTypeGlobs resolves a type name to its globs; an unknown type falls back to
// treating it as a bare extension (type:foo → *.foo). Empty type → nil.
func rgTypeGlobs(t string) []string {
	if t == "" {
		return nil
	}
	if g, ok := rgFileTypes[strings.ToLower(t)]; ok {
		return g
	}
	return []string{"*." + t}
}

func matchAnyGlob(globs []string, name string) bool {
	for _, g := range globs {
		if ok, _ := filepath.Match(g, name); ok {
			return true
		}
	}
	return false
}

// applyHeadOffset skips the first offset entries then keeps at most limit (0 =
// unlimited). more is the number of entries beyond the kept window.
func applyHeadOffset(lines []string, limit, offset int) (kept []string, more int) {
	if offset > 0 {
		if offset >= len(lines) {
			return nil, 0
		}
		lines = lines[offset:]
	}
	if limit > 0 && len(lines) > limit {
		return lines[:limit], len(lines) - limit
	}
	return lines, 0
}

// grepHit holds one file's grep results.
type grepHit struct {
	path  string
	lines []string
	count int
}

func scanFile(path, base string, re *regexp.Regexp, mode string, showLines, multiline bool, before, after int) *grepHit {
	return scanFileContext(context.Background(), path, base, re, mode, showLines, multiline, before, after)
}

func scanFileContext(ctx context.Context, path, base string, re *regexp.Regexp, mode string, showLines, multiline bool, before, after int) *grepHit {
	if ctx.Err() != nil {
		return nil
	}
	fi, err := os.Stat(path)
	if err != nil || !fi.Mode().IsRegular() || fi.Size() > maxGrepFileBytes {
		return nil
	}
	rel := path
	if r, e := filepath.Rel(base, path); e == nil {
		rel = r
	}
	if !multiline && mode != "content" {
		count := scanLineCountCtx(ctx, path, re)
		if count == 0 {
			return nil
		}
		return &grepHit{path: rel, count: count}
	}
	data, err := os.ReadFile(path)
	if err != nil || isBinary(data) {
		return nil
	}
	lines := strings.Split(string(data), "\n")
	if n := len(lines); n > 0 && lines[n-1] == "" {
		lines = lines[:n-1] // drop the empty element from a trailing newline
	}

	var matches []int
	if multiline {
		// Match against the whole file; a line "matches" if it overlaps any match span.
		lineStart := make([]int, len(lines))
		off := 0
		for i, ln := range lines {
			lineStart[i] = off
			off += len(ln) + 1 // + newline
		}
		hit := make([]bool, len(lines))
		first := 0
		for _, loc := range re.FindAllIndex(data, -1) {
			s, e := loc[0], loc[1]
			// RE2 spans are ordered. Advance across each line once rather than
			// walking the entire file again for every match (including empty spans).
			for first < len(lines) && lineStart[first]+len(lines[first]) < s {
				first++
			}
			for i := first; i < len(lines) && lineStart[i] < e; i++ {
				hit[i] = true
			}
		}
		for i, h := range hit {
			if h {
				matches = append(matches, i)
			}
		}
	} else {
		for i, ln := range lines {
			if re.MatchString(ln) {
				matches = append(matches, i)
			}
		}
	}
	if len(matches) == 0 {
		return nil
	}
	res := &grepHit{path: rel, count: len(matches)}
	if mode != "content" {
		return res
	}

	isMatch := make([]bool, len(lines))
	for _, m := range matches {
		isMatch[m] = true
	}
	// Collect the set of line indices to print (matches plus context), in order.
	var order []int
	last := -1
	for _, m := range matches {
		lo, hi := m-before, m+after
		if lo < 0 {
			lo = 0
		}
		if hi >= len(lines) {
			hi = len(lines) - 1
		}
		// Sorted match positions produce sorted windows, so merge overlaps
		// directly. This also preserves negative context arguments.
		for j := max(lo, last+1); j <= hi; j++ {
			order = append(order, j)
			last = j
		}
	}

	hasContext := before > 0 || after > 0
	prev := -2
	for _, j := range order {
		if hasContext && prev >= 0 && j != prev+1 {
			res.lines = append(res.lines, "--") // separate non-contiguous groups
		}
		sep := "-" // context line
		if isMatch[j] {
			sep = ":" // matching line
		}
		if showLines {
			res.lines = append(res.lines, fmt.Sprintf("%s%s%d%s%s", rel, sep, j+1, sep, lines[j]))
		} else {
			res.lines = append(res.lines, fmt.Sprintf("%s%s%s", rel, sep, lines[j]))
		}
		prev = j
	}
	return res
}

// Count line matches without retaining the whole file or all match indices.
// ReadSlice handles ordinary lines without allocating; unusually long lines are
// buffered up to maxGrepLineBytes (256 KiB) and absurdly long lines are skipped.
func scanLineCount(path string, re *regexp.Regexp) int {
	return scanLineCountCtx(context.Background(), path, re)
}

func scanLineCountCtx(ctx context.Context, path string, re *regexp.Regexp) int {
	f, err := os.Open(path)
	if err != nil {
		return 0
	}
	defer f.Close()
	r := bufio.NewReaderSize(f, 32<<10)
	sample, err := r.Peek(8000)
	if (err != nil && err != io.EOF) || isBinary(sample) {
		return 0
	}
	count := 0
	var long []byte
	oversized := false
	for {
		if ctx.Err() != nil {
			return count
		}
		line, err := r.ReadSlice('\n')
		if err == bufio.ErrBufferFull {
			if !oversized {
				if len(long)+len(line) > maxGrepLineBytes {
					oversized = true
					long = long[:0]
				} else {
					long = append(long, line...)
				}
			}
			continue
		}
		if err != nil && err != io.EOF {
			return 0
		}
		if oversized {
			oversized = false
			long = long[:0]
			if err == io.EOF {
				return count
			}
			continue
		}
		if len(long) > 0 {
			if len(long)+len(line) > maxGrepLineBytes {
				long = long[:0]
				if err == io.EOF {
					return count
				}
				continue
			}
			long = append(long, line...)
			line = long
		}
		if len(line) > 0 && re.Match(bytes.TrimSuffix(line, []byte{'\n'})) {
			count++
		}
		long = long[:0]
		if err == io.EOF {
			return count
		}
	}
}
