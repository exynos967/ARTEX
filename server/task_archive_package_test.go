package server

import (
	"archive/tar"
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strconv"
	"testing"

	pgdb "github.com/RC-CHN/ARTEX/db"
	"github.com/klauspost/compress/zstd"
)

func TestTaskArchivePackageFilesRoundTrip(t *testing.T) {
	dataDir := t.TempDir()
	taskID := "42"
	explorationID := int64(73)
	taskFile := filepath.Join(dataDir, "tasks", taskID, "uploads", "evidence.txt")
	transcriptFile := filepath.Join(dataDir, "transcripts", "exp73-worker-1.jsonl")
	unrelatedTranscript := filepath.Join(dataDir, "transcripts", "exp74-worker-1.jsonl")
	for path, body := range map[string]string{
		taskFile:            "task evidence",
		transcriptFile:      "transcript",
		unrelatedTranscript: "leave me hot",
	} {
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}

	stage, err := stageTaskArchiveFiles(dataDir, 1, taskID, explorationID)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(taskFile); !os.IsNotExist(err) {
		t.Fatalf("task file still hot after staging: %v", err)
	}
	if _, err := os.Stat(transcriptFile); !os.IsNotExist(err) {
		t.Fatalf("task transcript still hot after staging: %v", err)
	}
	if _, err := os.Stat(unrelatedTranscript); err != nil {
		t.Fatalf("unrelated transcript was staged: %v", err)
	}

	archivePath := taskArchivePath(dataDir, 1, taskID)
	streamPath := filepath.Join(stage.payload, filepath.FromSlash(pgdb.TaskArchiveLLMRecordsPath))
	if err := os.MkdirAll(filepath.Dir(streamPath), archiveDirMode); err != nil {
		t.Fatal(err)
	}
	streamBody := []byte("{\"id\":1,\"raw_request\":\"large\"}\n")
	if err := os.WriteFile(streamPath, streamBody, archiveFileMode); err != nil {
		t.Fatal(err)
	}
	snapshot := &pgdb.TaskArchiveSnapshot{
		FormatVersion: pgdb.TaskArchiveFormatVersion, TaskID: 42, ExplorationID: explorationID,
		StreamedTables: map[string]string{"llm_records": pgdb.TaskArchiveLLMRecordsPath},
	}
	original, compressed, checksum, err := writeTaskArchivePackage(archivePath, stage.payload, snapshot)
	if err != nil {
		t.Fatal(err)
	}
	if original == 0 || compressed == 0 || checksum == "" {
		t.Fatalf("invalid package metrics original=%d compressed=%d checksum=%q", original, compressed, checksum)
	}
	if err := stage.commit(); err != nil {
		t.Fatal(err)
	}
	extracted := filepath.Join(dataDir, "restore")
	if err := extractTaskArchivePackage(archivePath, checksum, extracted); err != nil {
		t.Fatal(err)
	}
	if got, err := os.ReadFile(filepath.Join(extracted, filepath.FromSlash(pgdb.TaskArchiveLLMRecordsPath))); err != nil || !bytes.Equal(got, streamBody) {
		t.Fatalf("streamed LLM archive payload=%q err=%v", got, err)
	}
	installed, err := installTaskArchiveFiles(dataDir, extracted, taskID, 1)
	if err != nil {
		t.Fatal(err)
	}
	if err := installed.commit(); err != nil {
		t.Fatal(err)
	}
	for path, want := range map[string]string{taskFile: "task evidence", transcriptFile: "transcript"} {
		got, err := os.ReadFile(path)
		if err != nil || string(got) != want {
			t.Fatalf("restored %s = %q, %v; want %q", path, got, err, want)
		}
	}
	if err := extractTaskArchivePackage(archivePath, "deadbeef", filepath.Join(dataDir, "bad-checksum")); err == nil {
		t.Fatal("checksum mismatch was accepted")
	}
}

func TestTaskArchivePackageSkipsSymlink(t *testing.T) {
	dataDir := t.TempDir()
	payload := filepath.Join(dataDir, "payload")
	if err := os.MkdirAll(payload, archiveDirMode); err != nil {
		t.Fatal(err)
	}
	regular := filepath.Join(payload, "keep.txt")
	if err := os.WriteFile(regular, []byte("keep me"), archiveFileMode); err != nil {
		t.Fatal(err)
	}
	// 工作目录里出现的符号链接应被跳过，而不是让整个归档失败。
	if err := os.Symlink(regular, filepath.Join(payload, "link.txt")); err != nil {
		t.Skipf("symlink unsupported on this platform: %v", err)
	}

	archivePath := filepath.Join(dataDir, "archive.tar.zst")
	snapshot := &pgdb.TaskArchiveSnapshot{FormatVersion: pgdb.TaskArchiveFormatVersion, TaskID: 42}
	_, _, checksum, err := writeTaskArchivePackage(archivePath, payload, snapshot)
	if err != nil {
		t.Fatalf("archive should skip symlink, not fail: %v", err)
	}
	extracted := filepath.Join(dataDir, "restore")
	if err := extractTaskArchivePackage(archivePath, checksum, extracted); err != nil {
		t.Fatal(err)
	}
	if got, err := os.ReadFile(filepath.Join(extracted, "keep.txt")); err != nil || string(got) != "keep me" {
		t.Fatalf("regular file not archived: got=%q err=%v", got, err)
	}
	if _, err := os.Lstat(filepath.Join(extracted, "link.txt")); !os.IsNotExist(err) {
		t.Fatalf("symlink should have been skipped, but link.txt exists: %v", err)
	}
}

func TestTaskArchiveStageJournalRollsBackInterruptedMoves(t *testing.T) {
	dataDir := t.TempDir()
	taskFile := filepath.Join(dataDir, "tasks", "42", "evidence.txt")
	transcriptFile := filepath.Join(dataDir, "transcripts", "exp73-worker.jsonl")
	for _, path := range []string{taskFile, transcriptFile} {
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(path), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	stage, err := stageTaskArchiveFiles(dataDir, 9, "42", 73)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(filepath.Join(stage.root, "journal.json"))
	if err != nil {
		t.Fatal(err)
	}
	var journal archiveStageJournal
	if err := json.Unmarshal(raw, &journal); err != nil {
		t.Fatal(err)
	}
	if len(journal.Moves) != 2 {
		t.Fatalf("journal moves=%d, want 2", len(journal.Moves))
	}
	recovered := &taskArchiveFileStage{root: stage.root, payload: stage.payload, journal: journal}
	if err := recovered.rollback(); err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{taskFile, transcriptFile} {
		if _, err := os.Stat(path); err != nil {
			t.Fatalf("interrupted archive did not restore %s: %v", path, err)
		}
	}
}

func TestTaskArchiveRestoreJournalRollsBackInterruptedInstall(t *testing.T) {
	dataDir := t.TempDir()
	extracted := filepath.Join(dataDir, "archives", "tasks", ".restore", "11-test")
	source := filepath.Join(extracted, "files", "tasks", "42", "evidence.txt")
	if err := os.MkdirAll(filepath.Dir(source), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(source, []byte("evidence"), 0o600); err != nil {
		t.Fatal(err)
	}
	_, err := installTaskArchiveFiles(dataDir, extracted, "42", 11)
	if err != nil {
		t.Fatal(err)
	}
	destination := filepath.Join(dataDir, "tasks", "42", "evidence.txt")
	if _, err := os.Stat(destination); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(filepath.Join(extracted, "restore-journal.json"))
	if err != nil {
		t.Fatal(err)
	}
	var journal archiveRestoreJournal
	if err := json.Unmarshal(raw, &journal); err != nil {
		t.Fatal(err)
	}
	if journal.ArchiveID != 11 || len(journal.Moves) != 1 {
		t.Fatalf("unexpected restore journal: %+v", journal)
	}
	recovered := &taskArchiveRestoreFiles{extracted: extracted, moves: journal.Moves}
	if err := recovered.rollback(); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(destination); !os.IsNotExist(err) {
		t.Fatalf("hot destination remains after restore rollback: %v", err)
	}
	if got, err := os.ReadFile(source); err != nil || string(got) != "evidence" {
		t.Fatalf("restore source=%q err=%v", got, err)
	}
}

func TestTaskArchiveDeletePackageCanResumeFromStagedPath(t *testing.T) {
	dataDir := t.TempDir()
	archivePath := taskArchivePath(dataDir, 21, "42")
	if err := os.MkdirAll(filepath.Dir(archivePath), archiveDirMode); err != nil {
		t.Fatal(err)
	}
	staged := archivePath + ".deleting-21"
	if err := os.WriteFile(staged, []byte("archive"), archiveFileMode); err != nil {
		t.Fatal(err)
	}
	got, moved, err := stageTaskArchivePackageDelete(archivePath, 21)
	if err != nil || !moved || got != staged {
		t.Fatalf("resume staged package path=%q moved=%v err=%v", got, moved, err)
	}
}

func TestTaskArchivePackageRejectsTraversal(t *testing.T) {
	var compressed bytes.Buffer
	encoder, err := zstd.NewWriter(&compressed)
	if err != nil {
		t.Fatal(err)
	}
	tw := tar.NewWriter(encoder)
	content := []byte("escape")
	if err := tw.WriteHeader(&tar.Header{Name: "../escape.txt", Mode: 0o600, Size: int64(len(content))}); err != nil {
		t.Fatal(err)
	}
	if _, err := tw.Write(content); err != nil {
		t.Fatal(err)
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := encoder.Close(); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "malicious.tar.zst")
	if err := os.WriteFile(path, compressed.Bytes(), 0o600); err != nil {
		t.Fatal(err)
	}
	root := t.TempDir()
	if err := extractTaskArchivePackage(path, "", root); err == nil {
		t.Fatal("path traversal archive was accepted")
	}
	if _, err := os.Stat(filepath.Join(filepath.Dir(root), "escape.txt")); !os.IsNotExist(err) {
		t.Fatalf("traversal wrote outside destination: %v", err)
	}
}

func TestTaskArchivePackageNDJSONTablesAndLowMemZstdRoundTrip(t *testing.T) {
	dataDir := t.TempDir()
	payload := filepath.Join(dataDir, "payload")
	tablesDir := filepath.Join(payload, pgdb.TaskArchiveTablesDir)
	if err := os.MkdirAll(tablesDir, archiveDirMode); err != nil {
		t.Fatal(err)
	}

	var activityBuf bytes.Buffer
	for i := 1; i <= 1200; i++ {
		activityBuf.WriteString(`{"id":` + strconv.Itoa(i) + `,"summary":"streamed activity row with compressible text payload"}` + "\n")
	}
	llmBody := []byte(`{"id":1,"raw_request":"` + string(bytes.Repeat([]byte("A"), 64*1024)) + `"}` + "\n")
	if err := os.WriteFile(filepath.Join(tablesDir, "activity.ndjson"), activityBuf.Bytes(), archiveFileMode); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(tablesDir, "llm_records.ndjson"), llmBody, archiveFileMode); err != nil {
		t.Fatal(err)
	}

	snapshot := &pgdb.TaskArchiveSnapshot{
		FormatVersion: pgdb.TaskArchiveFormatVersion,
		TaskID:        99,
		ExplorationID: 199,
		Tables: map[string]json.RawMessage{
			"tasks":        json.RawMessage(`[{"id":99}]`),
			"explorations": json.RawMessage(`[{"id":199}]`),
			"activity":     json.RawMessage(`[]`),
			"llm_records":  json.RawMessage(`[]`),
		},
		StreamedTables: map[string]string{
			"activity":    pgdb.TaskArchiveTablePath("activity"),
			"llm_records": pgdb.TaskArchiveTablePath("llm_records"),
		},
		NDJSONTables: map[string]int64{
			"activity":    1200,
			"llm_records": 1,
		},
		DataCounts: map[string]int64{
			"activity":    1200,
			"llm_records": 1,
		},
	}

	archivePath := taskArchivePath(dataDir, 7, "99")
	origSize, compSize, checksum, err := writeTaskArchivePackage(archivePath, payload, snapshot)
	if err != nil {
		t.Fatalf("writeTaskArchivePackage: %v", err)
	}
	if origSize == 0 || compSize == 0 || compSize >= origSize || checksum == "" {
		t.Fatalf("unexpected compression metrics orig=%d comp=%d sha=%q", origSize, compSize, checksum)
	}

	extracted := filepath.Join(dataDir, "extracted")
	if err := extractTaskArchivePackage(archivePath, checksum, extracted); err != nil {
		t.Fatalf("extractTaskArchivePackage: %v", err)
	}

	manifestRaw, err := os.ReadFile(filepath.Join(extracted, "manifest.json"))
	if err != nil {
		t.Fatal(err)
	}
	var gotSnap pgdb.TaskArchiveSnapshot
	if err := json.Unmarshal(manifestRaw, &gotSnap); err != nil {
		t.Fatal(err)
	}
	if err := pgdb.ValidateTaskArchiveStreamedTables(&gotSnap); err != nil {
		t.Fatalf("extracted manifest failed validation: %v", err)
	}
	if gotSnap.NDJSONTables["activity"] != 1200 || gotSnap.NDJSONTables["llm_records"] != 1 {
		t.Fatalf("unexpected ndjson_tables: %#v", gotSnap.NDJSONTables)
	}

	gotActivity, err := os.ReadFile(filepath.Join(extracted, filepath.FromSlash(pgdb.TaskArchiveTablePath("activity"))))
	if err != nil || !bytes.Equal(gotActivity, activityBuf.Bytes()) {
		t.Fatalf("extracted activity.ndjson mismatch err=%v len=%d", err, len(gotActivity))
	}
	gotLLM, err := os.ReadFile(filepath.Join(extracted, filepath.FromSlash(pgdb.TaskArchiveTablePath("llm_records"))))
	if err != nil || !bytes.Equal(gotLLM, llmBody) {
		t.Fatalf("extracted llm_records.ndjson mismatch err=%v len=%d", err, len(gotLLM))
	}

	// Verify path safety helper rejects escaping paths.
	if _, err := resolveArchivePayloadPath(extracted, "../escape.ndjson"); err == nil {
		t.Fatal("resolveArchivePayloadPath accepted traversal")
	}
	if _, err := resolveArchivePayloadPath(extracted, pgdb.TaskArchiveTablePath("activity")); err != nil {
		t.Fatalf("resolveArchivePayloadPath rejected valid table path: %v", err)
	}
}

func TestTaskArchivePackageSlimsOversizedLogsAndSkipsCmdOutput(t *testing.T) {
	dataDir := t.TempDir()
	taskID := "55"
	explorationID := int64(88)

	// Build a realistic task directory with:
	// - cmd-output/ spill caches (both task root and worker subdir) -> skipped
	// - >10 MiB error.log and scan.err -> slimmed to head+tail in archive, source untouched
	// - small <=10 MiB small.log, PoC evidence.py, and transcript .jsonl -> preserved verbatim
	taskRoot := filepath.Join(dataDir, "tasks", taskID)
	bigPayload := make([]byte, maxArchiveLogFileBytes+512*1024)
	copy(bigPayload, "LOG_HEAD_START\n")
	for i := len("LOG_HEAD_START\n"); i < len(bigPayload)-len("LOG_TAIL_END\n"); i++ {
		bigPayload[i] = 'X'
	}
	copy(bigPayload[len(bigPayload)-len("LOG_TAIL_END\n"):], "LOG_TAIL_END\n")

	files := map[string][]byte{
		filepath.Join(taskRoot, "cmd-output", "output-1.txt"):       []byte("transient spill"),
		filepath.Join(taskRoot, "i7", "cmd-output", "output-2.txt"): []byte("worker spill"),
		filepath.Join(taskRoot, "i7", "error.log"):                  bigPayload,
		filepath.Join(taskRoot, "scan.err"):                         bigPayload,
		filepath.Join(taskRoot, "i7", "small.log"):                  []byte("keep small log verbatim"),
		filepath.Join(taskRoot, "i7", "poc.py"):                     []byte("print('poc-ok')"),
		filepath.Join(dataDir, "transcripts", "exp88-main.jsonl"):   []byte(`{"type":"message"}` + "\n"),
	}
	for p, body := range files {
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, body, 0o600); err != nil {
			t.Fatal(err)
		}
	}

	stage, err := stageTaskArchiveFiles(dataDir, 12, taskID, explorationID)
	if err != nil {
		t.Fatal(err)
	}
	archivePath := taskArchivePath(dataDir, 12, taskID)
	snapshot := &pgdb.TaskArchiveSnapshot{FormatVersion: pgdb.TaskArchiveFormatVersion, TaskID: 55, ExplorationID: explorationID}
	_, _, checksum, err := writeTaskArchivePackage(archivePath, stage.payload, snapshot)
	if err != nil {
		t.Fatalf("writeTaskArchivePackage: %v", err)
	}

	// Rollback safety: staged source error.log must NOT be mutated on disk.
	stagedLogInfo, err := os.Stat(filepath.Join(stage.payload, "files", "tasks", taskID, "i7", "error.log"))
	if err != nil || stagedLogInfo.Size() != int64(len(bigPayload)) {
		t.Fatalf("staged source log mutated: size=%v err=%v", stagedLogInfo, err)
	}

	extracted := filepath.Join(dataDir, "extracted")
	if err := extractTaskArchivePackage(archivePath, checksum, extracted); err != nil {
		t.Fatalf("extractTaskArchivePackage: %v", err)
	}

	// cmd-output directories must be absent from the archive.
	for _, omitted := range []string{
		filepath.Join(extracted, "files", "tasks", taskID, "cmd-output"),
		filepath.Join(extracted, "files", "tasks", taskID, "i7", "cmd-output"),
	} {
		if _, err := os.Stat(omitted); !os.IsNotExist(err) {
			t.Fatalf("expected %s to be omitted from archive, err=%v", omitted, err)
		}
	}

	// Oversized *.log and *.err must be slimmed while preserving head + notice + tail.
	for _, rel := range []string{
		filepath.Join("files", "tasks", taskID, "i7", "error.log"),
		filepath.Join("files", "tasks", taskID, "scan.err"),
	} {
		got, err := os.ReadFile(filepath.Join(extracted, rel))
		if err != nil {
			t.Fatalf("read slimmed %s: %v", rel, err)
		}
		if len(got) > archiveLogHeadBytes+archiveLogTailBytes+512 {
			t.Fatalf("%s was not slimmed: len=%d", rel, len(got))
		}
		if !bytes.Contains(got, []byte("LOG_HEAD_START")) ||
			!bytes.Contains(got, []byte("ARTEX archive: oversized log truncated")) ||
			!bytes.Contains(got, []byte("LOG_TAIL_END")) {
			t.Fatalf("%s missing head/notice/tail markers", rel)
		}
	}

	// Small logs, PoCs, and transcripts must stay byte-identical.
	for rel, want := range map[string]string{
		filepath.Join("files", "tasks", taskID, "i7", "small.log"): "keep small log verbatim",
		filepath.Join("files", "tasks", taskID, "i7", "poc.py"):    "print('poc-ok')",
		filepath.Join("files", "transcripts", "exp88-main.jsonl"):  `{"type":"message"}` + "\n",
	} {
		got, err := os.ReadFile(filepath.Join(extracted, rel))
		if err != nil || string(got) != want {
			t.Fatalf("preserved %s mismatch: got=%q err=%v", rel, got, err)
		}
	}
}
