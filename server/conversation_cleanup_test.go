package server

import (
	"bytes"
	"io"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func createConversationArtifacts(t *testing.T, workDir, key string) []string {
	t.Helper()
	files := []string{
		filepath.Join(workDir, "sessions", key, "uploads", "report.txt"),
		filepath.Join(workDir, "sessions", key, "cmd-output", "1.log"),
		filepath.Join(workDir, "transcripts", key+".jsonl"),
		filepath.Join(workDir, "transcripts", key, "subagents", "agent-1.jsonl"),
		filepath.Join(workDir, "noa", key, "state.json"),
		filepath.Join(workDir, "noa", "chat-"+key, "state.json"),
	}
	for _, f := range files {
		if err := os.MkdirAll(filepath.Dir(f), 0o755); err != nil {
			t.Fatalf("mkdir %s: %v", f, err)
		}
		if err := os.WriteFile(f, []byte("artifact-"+key), 0o644); err != nil {
			t.Fatalf("write %s: %v", f, err)
		}
	}
	return files
}

func TestCleanupConversationFilesRemovesOnlyTarget(t *testing.T) {
	workDir := t.TempDir()
	conv1Files := createConversationArtifacts(t, workDir, "conv-1")
	conv10Files := createConversationArtifacts(t, workDir, "conv-10")
	conv2Files := createConversationArtifacts(t, workDir, "conv-2")

	s := &Server{m: &Manager{dir: workDir}}
	s.cleanupConversationFiles(1)

	for _, f := range conv1Files {
		if _, err := os.Stat(f); !os.IsNotExist(err) {
			t.Fatalf("expected conv-1 artifact %s to be deleted, stat err=%v", f, err)
		}
	}
	for _, dir := range []string{
		filepath.Join(workDir, "sessions", "conv-1"),
		filepath.Join(workDir, "transcripts", "conv-1"),
		filepath.Join(workDir, "noa", "conv-1"),
		filepath.Join(workDir, "noa", "chat-conv-1"),
	} {
		if _, err := os.Stat(dir); !os.IsNotExist(err) {
			t.Fatalf("expected conv-1 directory %s to be deleted, stat err=%v", dir, err)
		}
	}

	// Sibling conversations (including prefix-overlapping conv-10) must stay intact.
	for _, f := range append(conv10Files, conv2Files...) {
		data, err := os.ReadFile(f)
		if err != nil {
			t.Fatalf("expected sibling artifact %s to remain: %v", f, err)
		}
		if len(data) == 0 {
			t.Fatalf("expected sibling artifact %s to stay non-empty", f)
		}
	}
}

func TestCleanupConversationFilesHandlesInvalidAndMissing(t *testing.T) {
	workDir := t.TempDir()
	sibling := createConversationArtifacts(t, workDir, "conv-10")

	var nilServer *Server
	nilServer.cleanupConversationFiles(1)

	(&Server{}).cleanupConversationFiles(1)
	(&Server{m: &Manager{}}).cleanupConversationFiles(1)

	s := &Server{m: &Manager{dir: workDir}}
	s.cleanupConversationFiles(0)
	s.cleanupConversationFiles(-5)
	s.cleanupConversationFiles(999) // non-existent artifacts

	for _, f := range sibling {
		if _, err := os.Stat(f); err != nil {
			t.Fatalf("sibling artifact %s should not be affected: %v", f, err)
		}
	}
}

func buildLargeMultipartBody(t *testing.T, filename string, size int) (*bytes.Buffer, string) {
	t.Helper()
	var buf bytes.Buffer
	mw := multipart.NewWriter(&buf)
	part, err := mw.CreateFormFile("file", filename)
	if err != nil {
		t.Fatalf("CreateFormFile: %v", err)
	}
	chunk := bytes.Repeat([]byte("A"), 1<<20)
	for remaining := size; remaining > 0; {
		n := min(remaining, len(chunk))
		if _, err := part.Write(chunk[:n]); err != nil {
			t.Fatalf("write multipart chunk: %v", err)
		}
		remaining -= n
	}
	if err := mw.Close(); err != nil {
		t.Fatalf("close multipart writer: %v", err)
	}
	return &buf, mw.FormDataContentType()
}

func TestMultipartUploadCleansTempSpillFiles(t *testing.T) {
	// Go's ParseMultipartForm(32<<20) spills to os.TempDir() once total bytes
	// exceed 32 MiB + 10 MiB buffer. Use 44 MiB to force a real temp spill.
	const spillPayloadSize = 44 << 20

	cases := []struct {
		name      string
		target    string
		call      func(s *Server, w http.ResponseWriter, r *http.Request)
		checkPath func(workDir string) string
	}{
		{
			name:   "wsUpload",
			target: "/api/workspace/upload?path=",
			call:   func(s *Server, w http.ResponseWriter, r *http.Request) { s.wsUpload(w, r) },
			checkPath: func(workDir string) string {
				return filepath.Join(workDir, "big.bin")
			},
		},
		{
			name:   "chatUpload",
			target: "/api/chat/upload?scope=session&id=conv-7",
			call:   func(s *Server, w http.ResponseWriter, r *http.Request) { s.chatUpload(w, r) },
			checkPath: func(workDir string) string {
				return filepath.Join(workDir, "sessions", "conv-7", "uploads", "big.bin")
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			isolatedTmp := t.TempDir()
			t.Setenv("TMPDIR", isolatedTmp)
			t.Setenv("TMP", isolatedTmp)
			t.Setenv("TEMP", isolatedTmp)

			workDir := t.TempDir()
			s := &Server{m: &Manager{dir: workDir}}

			body, contentType := buildLargeMultipartBody(t, "big.bin", spillPayloadSize)
			req := httptest.NewRequest(http.MethodPost, tc.target, io.NopCloser(body))
			req.Header.Set("Content-Type", contentType)
			rec := httptest.NewRecorder()

			tc.call(s, rec, req)
			if rec.Code != http.StatusOK {
				t.Fatalf("%s returned status %d: %s", tc.name, rec.Code, rec.Body.String())
			}

			dest := tc.checkPath(workDir)
			st, err := os.Stat(dest)
			if err != nil {
				t.Fatalf("expected uploaded file at %s: %v", dest, err)
			}
			if st.Size() != spillPayloadSize {
				t.Fatalf("uploaded size = %d, want %d", st.Size(), spillPayloadSize)
			}

			leftover, err := os.ReadDir(isolatedTmp)
			if err != nil {
				t.Fatalf("read isolated temp dir: %v", err)
			}
			for _, ent := range leftover {
				if strings.HasPrefix(ent.Name(), "multipart-") {
					t.Fatalf("leaked multipart temp file in %s: %s", isolatedTmp, ent.Name())
				}
			}
			if len(leftover) != 0 {
				t.Fatalf("unexpected temp files left in %s: %d", isolatedTmp, len(leftover))
			}
		})
	}
}
