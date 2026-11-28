package tool

import (
	"fmt"
	"os"
	"runtime"
	"strconv"
	"strings"
)

const (
	// BashMaxFileEnv overrides the per-file size ceiling (in MiB) applied to
	// child shells launched by Bash / Monitor tasks. Set to 0 to disable.
	BashMaxFileEnv = "NORMA_BASH_MAX_FILE_MB"
	// DefaultBashMaxFileMiB is the default per-file ceiling (2048 MiB = 2 GiB),
	// preventing runaway log redirects (e.g. 9 GB error.log) from filling disk
	// without restricting normal pentest artifacts or payloads.
	DefaultBashMaxFileMiB int64 = 2048
	maxBashMaxFileMiB     int64 = 1 << 20 // 1 TiB sanity ceiling
)

func lookupEnvValue(extraEnv []string, key string) (string, bool) {
	prefix := key + "="
	found := false
	val := ""
	for _, entry := range extraEnv {
		if strings.HasPrefix(entry, prefix) {
			val = entry[len(prefix):]
			found = true
		}
	}
	if found {
		return val, true
	}
	return os.LookupEnv(key)
}

// bashMaxFileBytes resolves NORMA_BASH_MAX_FILE_MB from extraEnv or process env.
// Returns 0 when explicitly disabled ("0"); invalid or negative values fall
// back to DefaultBashMaxFileMiB.
func bashMaxFileBytes(extraEnv []string) int64 {
	raw, ok := lookupEnvValue(extraEnv, BashMaxFileEnv)
	if !ok {
		return DefaultBashMaxFileMiB << 20
	}
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		return DefaultBashMaxFileMiB << 20
	}
	mb, err := strconv.ParseInt(trimmed, 10, 64)
	if err != nil || mb < 0 {
		return DefaultBashMaxFileMiB << 20
	}
	if mb == 0 {
		return 0
	}
	if mb > maxBashMaxFileMiB {
		mb = maxBashMaxFileMiB
	}
	return mb << 20
}

// bashUlimitFsizeBlockBytes returns the block size used by GNU bash's `ulimit -f`
// in default (non-POSIX) mode: 1024 bytes on both Linux (bash 5.x) and macOS
// (bash 3.2.57).
const bashUlimitFsizeBlockBytes int64 = 1024

// wrapCommandWithFsize prepends a child-shell `ulimit -f` directive on Unix so
// runaway file redirects hit SIGXFSZ/EFBIG at the kernel layer without affecting
// the host Go server process. Uses a newline separator and `2>/dev/null || true`
// so multi-line scripts, leading comments, `set -e`, and restricted hard limits
// all keep working cleanly.
func wrapCommandWithFsize(command string, extraEnv []string) string {
	if runtime.GOOS == "windows" {
		return command
	}
	limitBytes := bashMaxFileBytes(extraEnv)
	if limitBytes <= 0 {
		return command
	}
	blocks := (limitBytes + bashUlimitFsizeBlockBytes - 1) / bashUlimitFsizeBlockBytes
	if blocks < 1 {
		blocks = 1
	}
	return fmt.Sprintf("ulimit -f %d 2>/dev/null || true\n%s", blocks, command)
}
