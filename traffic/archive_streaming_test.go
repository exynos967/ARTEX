package traffic

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestArchiveStreamingV2RoundTripLargeExchangesAndBlobs(t *testing.T) {
	srcDir := t.TempDir()
	src, err := Open(srcDir, "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer src.Close()

	const (
		host          = "stream-v2.example"
		totalCount    = 1150
		largeBlobSize = 2 * 1024 * 1024 // 2 MiB
	)

	// Prepare two distinct multi-MiB blobs so deduplication and streaming copy are both exercised.
	blobA := bytes.Repeat([]byte("ALPHA-PAYLOAD-BLOCK-0123456789\n"), largeBlobSize/31+1)[:largeBlobSize]
	blobB := bytes.Repeat([]byte("BETA-PAYLOAD-BLOCK-ABCDEFGHIJK\n"), largeBlobSize/31+1)[:largeBlobSize]
	sumA := sha256.Sum256(blobA)
	sumB := sha256.Sum256(blobB)
	hashA := hex.EncodeToString(sumA[:])
	hashB := hex.EncodeToString(sumB[:])
	if err := src.ensureBlobFile(hashA, blobA); err != nil {
		t.Fatal(err)
	}
	if err := src.ensureBlobFile(hashB, blobB); err != nil {
		t.Fatal(err)
	}

	tx, err := src.DB().Begin()
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < totalCount; i++ {
		id := fmt.Sprintf("stream-ex-%04d", i)
		reqBody := []byte(fmt.Sprintf(`{"index":%d}`, i))
		respBody := []byte(fmt.Sprintf(`{"ok":true,"index":%d}`, i))
		respLen := len(respBody)
		var respBlob any
		switch i {
		case 0, 500:
			respBody = blobA[:blobPreview]
			respBlob = hashA
			respLen = len(blobA)
		case 1001:
			respBody = blobB[:blobPreview]
			respBlob = hashB
			respLen = len(blobB)
		}
		if _, err := tx.Exec(`INSERT INTO exchanges(id,ts,host,method,url_template,url,status,content_type,req_len,resp_len,path)
VALUES(?,?,?,?,?,?,?,?,?,?,?)`, id, int64(1700000000+i), host, "POST", "/api/item/{n}",
			fmt.Sprintf("https://%s/api/item/%d", host, i), 200, "application/json", len(reqBody), respLen, ""); err != nil {
			tx.Rollback()
			t.Fatal(err)
		}
		if _, err := tx.Exec(`INSERT INTO exchange_bodies(id,req_head,req_body,req_blob,resp_head,resp_body,resp_blob)
VALUES(?,?,?,?,?,?,?)`, id, "POST /api HTTP/1.1\nHost: "+host, reqBody, nil,
			"HTTP/1.1 200 OK\nContent-Type: application/json", respBody, respBlob); err != nil {
			tx.Rollback()
			t.Fatal(err)
		}
		if h, ok := respBlob.(string); ok {
			if _, err := tx.Exec(`INSERT INTO blob_refs(hash,exchange_id) VALUES(?,?)`, h, id); err != nil {
				tx.Rollback()
				t.Fatal(err)
			}
		}
	}
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}

	archiveDir := filepath.Join(t.TempDir(), "traffic-export")
	exported, err := src.ExportHosts([]string{host}, archiveDir)
	if err != nil {
		t.Fatalf("ExportHosts failed: %v", err)
	}
	if exported != totalCount {
		t.Fatalf("ExportHosts count=%d, want %d", exported, totalCount)
	}

	// Verify v2 compact traffic.json manifest + traffic.ndjson exist.
	manifestRaw, err := os.ReadFile(filepath.Join(archiveDir, "traffic.json"))
	if err != nil {
		t.Fatal(err)
	}
	var manifest ArchiveSnapshot
	if err := json.Unmarshal(manifestRaw, &manifest); err != nil {
		t.Fatal(err)
	}
	if manifest.Version != 2 || manifest.Format != "ndjson" || manifest.Count != totalCount {
		t.Fatalf("unexpected v2 manifest: %+v", manifest)
	}
	if len(manifest.Exchanges) != 0 {
		t.Fatalf("v2 manifest should not embed exchanges inline, got %d", len(manifest.Exchanges))
	}
	if len(manifest.Blobs) != 2 {
		t.Fatalf("expected 2 deduplicated blobs in manifest, got %v", manifest.Blobs)
	}
	if _, err := os.Stat(filepath.Join(archiveDir, "traffic.ndjson")); err != nil {
		t.Fatalf("traffic.ndjson missing: %v", err)
	}

	// Import into a brand-new traffic instance.
	dstDir := t.TempDir()
	dst, err := Open(dstDir, "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer dst.Close()

	imported, err := dst.ImportArchive(archiveDir)
	if err != nil {
		t.Fatalf("ImportArchive v2 failed: %v", err)
	}
	if imported != totalCount {
		t.Fatalf("ImportArchive imported=%d, want %d", imported, totalCount)
	}

	// Verify idempotency: second import imports 0 rows.
	importedAgain, err := dst.ImportArchive(archiveDir)
	if err != nil || importedAgain != 0 {
		t.Fatalf("second ImportArchive imported=%d err=%v, want 0", importedAgain, err)
	}

	// Verify both multi-MiB blobs restored with exact byte contents.
	for hash, want := range map[string][]byte{hashA: blobA, hashB: blobB} {
		f, size, err := dst.Blob(hash)
		if err != nil {
			t.Fatalf("dst.Blob(%s): %v", hash, err)
		}
		got, readErr := io.ReadAll(f)
		_ = f.Close()
		if readErr != nil || size != int64(len(want)) || !bytes.Equal(got, want) {
			t.Fatalf("restored blob %s mismatch: size=%d err=%v", hash, size, readErr)
		}
	}

	// Verify an inline exchange near the tail (past multiple 500-row batches).
	req, resp, err := dst.Get("stream-ex-1149")
	if err != nil || !strings.Contains(req, `"index":1149`) || !strings.Contains(resp, `"index":1149`) {
		t.Fatalf("restored tail exchange mismatch: req=%q resp=%q err=%v", req, resp, err)
	}

	// Corrupt a blob in the archive and verify streaming SHA-256 verification rejects it.
	corruptDir := filepath.Join(t.TempDir(), "corrupt-traffic")
	if err := os.MkdirAll(filepath.Join(corruptDir, "blobs"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(corruptDir, "traffic.json"), manifestRaw, 0o600); err != nil {
		t.Fatal(err)
	}
	ndjsonBytes, err := os.ReadFile(filepath.Join(archiveDir, "traffic.ndjson"))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(corruptDir, "traffic.ndjson"), ndjsonBytes, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(corruptDir, "blobs", hashA+".bin"), []byte("corrupted"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(corruptDir, "blobs", hashB+".bin"), blobB, 0o600); err != nil {
		t.Fatal(err)
	}
	verifyTarget, err := Open(t.TempDir(), "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer verifyTarget.Close()
	if _, err := verifyTarget.ImportArchive(corruptDir); err == nil || !strings.Contains(err.Error(), "checksum mismatch") {
		t.Fatalf("corrupt blob should fail checksum verification, got %v", err)
	}
}

func TestArchiveImportLegacyV1Compatibility(t *testing.T) {
	tr, err := Open(t.TempDir(), "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer tr.Close()

	blobData := bytes.Repeat([]byte("legacy-v1-blob-content-"), 2000)
	sum := sha256.Sum256(blobData)
	blobHash := hex.EncodeToString(sum[:])

	const count = 620 // > 500 to verify v1 batch chunking too
	exchanges := make([]ArchiveExchange, 0, count)
	for i := 0; i < count; i++ {
		item := ArchiveExchange{
			ID:          fmt.Sprintf("v1-ex-%04d", i),
			TS:          int64(1600000000 + i),
			Host:        "legacy-v1.example",
			Method:      "GET",
			URLTemplate: "/v1/item/{n}",
			URL:         fmt.Sprintf("https://legacy-v1.example/v1/item/%d", i),
			Status:      200,
			ContentType: "text/plain",
			ReqHead:     "GET /v1 HTTP/1.1\nHost: legacy-v1.example",
			RespHead:    "HTTP/1.1 200 OK\nContent-Type: text/plain",
			RespBody:    []byte(fmt.Sprintf("v1-body-%d", i)),
			RespLen:     len(fmt.Sprintf("v1-body-%d", i)),
		}
		if i == 10 {
			item.RespBody = blobData[:blobPreview]
			item.RespBlob = blobHash
			item.RespLen = len(blobData)
		}
		exchanges = append(exchanges, item)
	}

	archiveDir := filepath.Join(t.TempDir(), "legacy-v1")
	if err := os.MkdirAll(filepath.Join(archiveDir, "blobs"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(archiveDir, "blobs", blobHash+".bin"), blobData, 0o600); err != nil {
		t.Fatal(err)
	}
	legacyRaw, err := json.Marshal(ArchiveSnapshot{
		Version:   1,
		Exchanges: exchanges,
		Blobs:     []string{blobHash},
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(archiveDir, "traffic.json"), legacyRaw, 0o600); err != nil {
		t.Fatal(err)
	}

	imported, err := tr.ImportArchive(archiveDir)
	if err != nil {
		t.Fatalf("ImportArchive legacy v1 failed: %v", err)
	}
	if imported != count {
		t.Fatalf("imported=%d, want %d", imported, count)
	}
	_, resp, err := tr.Get("v1-ex-0619")
	if err != nil || !strings.Contains(resp, "v1-body-619") {
		t.Fatalf("legacy v1 tail row mismatch: resp=%q err=%v", resp, err)
	}
	f, _, err := tr.Blob(blobHash)
	if err != nil {
		t.Fatalf("legacy v1 blob missing: %v", err)
	}
	gotBlob, readErr := io.ReadAll(f)
	_ = f.Close()
	if readErr != nil || !bytes.Equal(gotBlob, blobData) {
		t.Fatalf("legacy v1 blob content mismatch: err=%v", readErr)
	}
}

func TestExportHostsDoesNotBlockProxyWrites(t *testing.T) {
	tr, err := Open(t.TempDir(), "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer tr.Close()

	const exportHost = "export-concurrent.example"
	for i := 0; i < 60; i++ {
		if err := tr.recordFlow(newFlow(exportHost, "GET", fmt.Sprintf("/seed/%d", i), nil, []byte("seed"))); err != nil {
			t.Fatal(err)
		}
	}

	// Hold t.wmu from a concurrent writer simulation to prove ExportHosts does not
	// block waiting on t.wmu (and vice versa).
	tr.wmu.Lock()
	exportDone := make(chan error, 1)
	go func() {
		_, err := tr.ExportHosts([]string{exportHost}, filepath.Join(t.TempDir(), "out"))
		exportDone <- err
	}()
	select {
	case err := <-exportDone:
		tr.wmu.Unlock()
		if err != nil {
			t.Fatalf("ExportHosts failed while wmu was held: %v", err)
		}
	case <-time.After(5 * time.Second):
		tr.wmu.Unlock()
		t.Fatal("ExportHosts deadlocked waiting on t.wmu")
	}

	// Also verify concurrent proxy recording + ExportHosts run cleanly together.
	var wg sync.WaitGroup
	wg.Add(2)
	var exportErr, writeErr error
	go func() {
		defer wg.Done()
		_, exportErr = tr.ExportHosts([]string{exportHost}, filepath.Join(t.TempDir(), "out2"))
	}()
	go func() {
		defer wg.Done()
		for i := 0; i < 40; i++ {
			tr.enqueueFlow(newFlow("live-proxy.example", "POST", fmt.Sprintf("/live/%d", i), []byte("req"), []byte("resp")))
		}
		writeErr = tr.Flush(context.Background())
	}()
	wg.Wait()
	if exportErr != nil {
		t.Fatalf("concurrent ExportHosts failed: %v", exportErr)
	}
	if writeErr != nil {
		t.Fatalf("concurrent Flush failed: %v", writeErr)
	}
}
