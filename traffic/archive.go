package traffic

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

const (
	trafficArchiveVersionV1   = 1
	trafficArchiveVersionV2   = 2
	trafficExportPageSize     = 500
	trafficImportBatchSize    = 500
	trafficStreamBufSize      = 64 * 1024
	maxTrafficNDJSONLineBytes = 16 << 20 // 16 MiB cap per NDJSON exchange record
)

// ArchiveSnapshot is the portable traffic subset embedded in one task archive.
// Version 2 streams exchanges into traffic.ndjson and keeps only compact
// metadata in traffic.json. Version 1 archives retain inline Exchanges.
// Large content-addressed bodies are copied alongside the manifest rather than
// base64-encoded, preserving deduplication and allowing the tar writer to stream.
type ArchiveSnapshot struct {
	Version   int               `json:"version"`
	Format    string            `json:"format,omitempty"`
	Count     int64             `json:"count,omitempty"`
	Exchanges []ArchiveExchange `json:"exchanges,omitempty"`
	Blobs     []string          `json:"blobs"`
}

type ArchiveExchange struct {
	ID          string `json:"id"`
	TS          int64  `json:"ts"`
	Host        string `json:"host"`
	Method      string `json:"method"`
	URLTemplate string `json:"url_template"`
	URL         string `json:"url"`
	Status      int    `json:"status"`
	ContentType string `json:"content_type"`
	ReqLen      int    `json:"req_len"`
	RespLen     int    `json:"resp_len"`
	ReqHead     string `json:"req_head"`
	ReqBody     []byte `json:"req_body,omitempty"`
	ReqBlob     string `json:"req_blob,omitempty"`
	RespHead    string `json:"resp_head"`
	RespBody    []byte `json:"resp_body,omitempty"`
	RespBlob    string `json:"resp_blob,omitempty"`
}

type exportedExchangeRow struct {
	item       ArchiveExchange
	hasBody    bool
	legacyPath string
}

// ExportHosts writes an exact-host v2 streaming snapshot to dir without holding
// t.wmu or buffering the full exchange slice or blob bodies in memory.
func (t *Traffic) ExportHosts(hosts []string, dir string) (int64, error) {
	if t == nil || len(hosts) == 0 {
		return 0, nil
	}
	unique := uniqueArchiveHosts(hosts)
	if len(unique) == 0 {
		return 0, nil
	}
	_ = t.Flush(context.Background())

	t.beginExport()
	defer t.endExport()

	if err := os.MkdirAll(filepath.Join(dir, "blobs"), 0o700); err != nil {
		return 0, err
	}
	ndjsonPath := filepath.Join(dir, "traffic.ndjson")
	ndjsonFile, err := os.OpenFile(ndjsonPath, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o600)
	if err != nil {
		return 0, err
	}
	ndjsonClosed := false
	defer func() {
		if !ndjsonClosed {
			_ = ndjsonFile.Close()
		}
	}()
	bw := bufio.NewWriterSize(ndjsonFile, trafficStreamBufSize)
	enc := json.NewEncoder(bw)

	placeholders := make([]string, len(unique))
	baseArgs := make([]any, len(unique))
	for i, host := range unique {
		placeholders[i] = "?"
		baseArgs[i] = host
	}
	hostIn := strings.Join(placeholders, ",")

	blobsSeen := map[string]struct{}{}
	blobList := []string{}
	var count int64
	var hasCursor bool
	var lastTS int64
	var lastID string

	for {
		page, err := t.queryExportPage(hostIn, baseArgs, hasCursor, lastTS, lastID, trafficExportPageSize)
		if err != nil {
			return 0, err
		}
		if len(page) == 0 {
			break
		}
		for _, row := range page {
			item := row.item
			if !row.hasBody && strings.TrimSpace(row.legacyPath) != "" {
				if !filepath.IsLocal(row.legacyPath) {
					return 0, fmt.Errorf("invalid legacy path for exchange %s", item.ID)
				}
				req, readErr := os.ReadFile(filepath.Join(t.dir, row.legacyPath, "request.http"))
				if readErr != nil && !os.IsNotExist(readErr) {
					return 0, readErr
				}
				resp, readErr := os.ReadFile(filepath.Join(t.dir, row.legacyPath, "response.http"))
				if readErr != nil && !os.IsNotExist(readErr) {
					return 0, readErr
				}
				item.ReqHead, item.RespHead = string(req), string(resp)
			}
			for _, hash := range []string{item.ReqBlob, item.RespBlob} {
				if hash == "" {
					continue
				}
				if _, exists := blobsSeen[hash]; exists {
					continue
				}
				if err := t.exportBlobFile(hash, filepath.Join(dir, "blobs", hash+".bin")); err != nil {
					return 0, err
				}
				blobsSeen[hash] = struct{}{}
				blobList = append(blobList, hash)
			}
			if err := enc.Encode(item); err != nil {
				return 0, err
			}
			count++
			lastTS, lastID = item.TS, item.ID
			hasCursor = true
		}
		if len(page) < trafficExportPageSize {
			break
		}
	}

	if err := bw.Flush(); err != nil {
		return 0, err
	}
	if err := ndjsonFile.Sync(); err != nil {
		return 0, err
	}
	ndjsonClosed = true
	if err := ndjsonFile.Close(); err != nil {
		return 0, err
	}

	sort.Strings(blobList)
	manifest := ArchiveSnapshot{
		Version: trafficArchiveVersionV2,
		Format:  "ndjson",
		Count:   count,
		Blobs:   blobList,
	}
	raw, err := json.Marshal(manifest)
	if err != nil {
		return 0, err
	}
	if err := os.WriteFile(filepath.Join(dir, "traffic.json"), raw, 0o600); err != nil {
		return 0, err
	}
	return count, nil
}

func (t *Traffic) queryExportPage(hostIn string, baseArgs []any, hasCursor bool, lastTS int64, lastID string, limit int) ([]exportedExchangeRow, error) {
	var q strings.Builder
	q.WriteString(`SELECT e.id,e.ts,e.host,e.method,e.url_template,e.url,e.status,e.content_type,e.req_len,e.resp_len,e.path,
b.id,b.req_head,b.req_body,b.req_blob,b.resp_head,b.resp_body,b.resp_blob
FROM exchanges e LEFT JOIN exchange_bodies b ON b.id=e.id
WHERE e.host IN (`)
	q.WriteString(hostIn)
	q.WriteByte(')')
	args := make([]any, 0, len(baseArgs)+4)
	args = append(args, baseArgs...)
	if hasCursor {
		q.WriteString(` AND (e.ts > ? OR (e.ts = ? AND e.id > ?))`)
		args = append(args, lastTS, lastTS, lastID)
	}
	q.WriteString(` ORDER BY e.ts,e.id LIMIT ?`)
	args = append(args, limit)

	rows, err := t.db.Query(q.String(), args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	page := make([]exportedExchangeRow, 0, min(limit, 64))
	for rows.Next() {
		var row exportedExchangeRow
		var bodyID, reqBlob, respBlob sql.NullString
		var reqHead, respHead []byte
		if err := rows.Scan(
			&row.item.ID, &row.item.TS, &row.item.Host, &row.item.Method, &row.item.URLTemplate,
			&row.item.URL, &row.item.Status, &row.item.ContentType, &row.item.ReqLen, &row.item.RespLen,
			&row.legacyPath, &bodyID, &reqHead, &row.item.ReqBody, &reqBlob,
			&respHead, &row.item.RespBody, &respBlob,
		); err != nil {
			return nil, err
		}
		row.hasBody = bodyID.Valid
		row.item.ReqHead = string(reqHead)
		row.item.RespHead = string(respHead)
		row.item.ReqBlob = reqBlob.String
		row.item.RespBlob = respBlob.String
		page = append(page, row)
	}
	return page, rows.Err()
}

// exportBlobFile streams a content-addressed blob from the store to dest while
// pinning its hash against concurrent gcBlobs.
func (t *Traffic) exportBlobFile(hash, dest string) error {
	t.pinBlob(hash)
	defer t.unpinBlobs([]string{hash})

	source, err := t.blobPath(hash)
	if err != nil {
		return err
	}
	in, err := os.Open(source)
	if err != nil {
		return err
	}
	defer in.Close()

	out, err := os.OpenFile(dest, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	_, copyErr := io.Copy(out, in)
	closeErr := out.Close()
	if copyErr != nil || closeErr != nil {
		_ = os.Remove(dest)
		return errors.Join(copyErr, closeErr)
	}
	return nil
}

// ImportArchive imports only missing exchange IDs from either a v2 streaming
// archive (traffic.json + traffic.ndjson) or a legacy v1 inline archive.
// Current hot rows always win, and repeated restore attempts are safe after a
// partial external failure.
func (t *Traffic) ImportArchive(dir string) (int64, error) {
	if t == nil {
		return 0, nil
	}
	manifestPath := filepath.Join(dir, "traffic.json")
	meta, err := readTrafficArchiveManifest(manifestPath)
	if os.IsNotExist(err) {
		return 0, nil
	}
	if err != nil {
		return 0, err
	}
	switch meta.Version {
	case trafficArchiveVersionV1:
	case trafficArchiveVersionV2:
		if meta.Format != "" && meta.Format != "ndjson" {
			return 0, fmt.Errorf("unsupported traffic archive format %q", meta.Format)
		}
	default:
		return 0, fmt.Errorf("unsupported traffic archive version %d", meta.Version)
	}

	pinned := make([]string, 0, len(meta.Blobs))
	allowedBlobs := make(map[string]struct{}, len(meta.Blobs))
	defer func() {
		if len(pinned) > 0 {
			t.unpinBlobs(pinned)
		}
	}()
	for _, hash := range meta.Blobs {
		if !blobHashRe.MatchString(hash) {
			return 0, fmt.Errorf("invalid archived traffic blob %q", hash)
		}
		t.pinBlob(hash)
		pinned = append(pinned, hash)
		if err := t.importBlobFile(filepath.Join(dir, "blobs", hash+".bin"), hash); err != nil {
			return 0, err
		}
		allowedBlobs[hash] = struct{}{}
	}

	var totalImported int64
	batch := make([]ArchiveExchange, 0, trafficImportBatchSize)
	flush := func() error {
		if len(batch) == 0 {
			return nil
		}
		n, err := t.importExchangeBatch(batch)
		totalImported += n
		batch = batch[:0]
		return err
	}
	push := func(item ArchiveExchange) error {
		for _, hash := range []string{item.ReqBlob, item.RespBlob} {
			if hash == "" {
				continue
			}
			if !blobHashRe.MatchString(hash) {
				return fmt.Errorf("exchange %s references invalid blob hash %q", item.ID, hash)
			}
			if _, ok := allowedBlobs[hash]; !ok {
				return fmt.Errorf("exchange %s references undeclared blob %s", item.ID, hash)
			}
		}
		batch = append(batch, item)
		if len(batch) >= trafficImportBatchSize {
			return flush()
		}
		return nil
	}

	if meta.Version == trafficArchiveVersionV2 {
		if err := streamTrafficNDJSON(filepath.Join(dir, "traffic.ndjson"), meta.Count, push); err != nil {
			return totalImported, err
		}
	} else {
		if err := streamLegacyV1Exchanges(manifestPath, push); err != nil {
			return totalImported, err
		}
	}
	if err := flush(); err != nil {
		return totalImported, err
	}
	return totalImported, nil
}

// importBlobFile verifies the archived blob's SHA-256 via streaming io.Copy and
// atomically installs it into the content-addressed blob directory when absent.
func (t *Traffic) importBlobFile(source, hash string) error {
	in, err := os.Open(source)
	if err != nil {
		return err
	}
	defer in.Close()

	destination := filepath.Join(t.dir, "_blobs", "sha256", hash[:2], hash+".bin")
	hasher := sha256.New()

	if _, statErr := os.Stat(destination); statErr == nil {
		if _, err := io.Copy(hasher, in); err != nil {
			return err
		}
		if hex.EncodeToString(hasher.Sum(nil)) != hash {
			return fmt.Errorf("traffic blob checksum mismatch: %s", hash)
		}
		return nil
	} else if !os.IsNotExist(statErr) {
		return statErr
	}

	destDir := filepath.Dir(destination)
	if err := os.MkdirAll(destDir, 0o755); err != nil {
		return err
	}
	// Prefix ".blob-" ensures concurrent gcBlobs ignores in-progress temp files.
	tmp, err := os.CreateTemp(destDir, ".blob-import-*")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	cleanupTmp := true
	defer func() {
		if cleanupTmp {
			_ = os.Remove(tmpName)
		}
	}()

	_, copyErr := io.Copy(io.MultiWriter(tmp, hasher), in)
	closeErr := tmp.Close()
	if err := errors.Join(copyErr, closeErr); err != nil {
		return err
	}
	if hex.EncodeToString(hasher.Sum(nil)) != hash {
		return fmt.Errorf("traffic blob checksum mismatch: %s", hash)
	}
	if err := os.Chmod(tmpName, 0o644); err != nil {
		return err
	}
	if err := os.Rename(tmpName, destination); err != nil {
		if _, statErr := os.Stat(destination); statErr == nil {
			return nil
		}
		return err
	}
	cleanupTmp = false
	return nil
}

func (t *Traffic) importExchangeBatch(batch []ArchiveExchange) (int64, error) {
	if len(batch) == 0 {
		return 0, nil
	}
	var searchTexts []string
	var precomputed []bool
	if t.fts {
		existing, err := t.existingExchangeIDs(batch)
		if err != nil {
			return 0, err
		}
		searchTexts = make([]string, len(batch))
		precomputed = make([]bool, len(batch))
		for i, item := range batch {
			if existing[item.ID] {
				continue
			}
			content, err := t.exchangeSearchText(item)
			if err != nil {
				return 0, err
			}
			searchTexts[i] = searchText(content)
			precomputed[i] = true
		}
	}

	t.wmu.Lock()
	defer t.wmu.Unlock()

	tx, err := t.db.Begin()
	if err != nil {
		return 0, err
	}
	defer tx.Rollback() //nolint:errcheck

	var imported int64
	for i, item := range batch {
		host := strings.ToLower(strings.TrimSpace(item.Host))
		res, err := tx.Exec(`INSERT INTO exchanges(id,ts,host,method,url_template,url,status,content_type,req_len,resp_len,path)
VALUES(?,?,?,?,?,?,?,?,?,?,'') ON CONFLICT DO NOTHING`, item.ID, item.TS, host, item.Method, item.URLTemplate,
			item.URL, item.Status, item.ContentType, item.ReqLen, item.RespLen)
		if err != nil {
			return imported, err
		}
		n, _ := res.RowsAffected()
		if n == 0 {
			continue
		}
		if _, err := tx.Exec(`INSERT INTO exchange_bodies(id,req_head,req_body,req_blob,resp_head,resp_body,resp_blob)
VALUES(?,?,?,?,?,?,?)`, item.ID, t.headerValue(item.ReqHead), item.ReqBody, nullIfEmpty(item.ReqBlob),
			t.headerValue(item.RespHead), item.RespBody, nullIfEmpty(item.RespBlob)); err != nil {
			return imported, err
		}
		for _, hash := range []string{item.ReqBlob, item.RespBlob} {
			if hash != "" {
				if _, err := tx.Exec(`INSERT INTO blob_refs(hash,exchange_id) VALUES(?,?) ON CONFLICT DO NOTHING`, hash, item.ID); err != nil {
					return imported, err
				}
			}
		}
		if t.fts {
			var rowID int64
			if err := tx.QueryRow(`SELECT rowid FROM exchanges WHERE id=?`, item.ID).Scan(&rowID); err != nil {
				return imported, err
			}
			doc := searchTexts[i]
			if !precomputed[i] {
				content, err := t.exchangeSearchText(item)
				if err != nil {
					return imported, err
				}
				doc = searchText(content)
			}
			if _, err := tx.Exec(`INSERT INTO ex_fts(rowid,content) VALUES(?,?)`, rowID, doc); err != nil {
				return imported, err
			}
		}
		imported++
	}
	if err := tx.Commit(); err != nil {
		return imported, err
	}
	return imported, nil
}

func (t *Traffic) existingExchangeIDs(batch []ArchiveExchange) (map[string]bool, error) {
	placeholders := make([]string, len(batch))
	args := make([]any, len(batch))
	for i, item := range batch {
		placeholders[i] = "?"
		args[i] = item.ID
	}
	rows, err := t.db.Query(`SELECT id FROM exchanges WHERE id IN (`+strings.Join(placeholders, ",")+`)`, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	existing := make(map[string]bool)
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return nil, err
		}
		existing[id] = true
	}
	return existing, rows.Err()
}

// readTrafficArchiveManifest extracts top-level metadata without materializing
// a legacy v1 "exchanges" array in RAM.
func readTrafficArchiveManifest(path string) (ArchiveSnapshot, error) {
	var meta ArchiveSnapshot
	f, err := os.Open(path)
	if err != nil {
		return meta, err
	}
	defer f.Close()

	dec := json.NewDecoder(bufio.NewReaderSize(f, trafficStreamBufSize))
	tok, err := dec.Token()
	if err != nil {
		return meta, err
	}
	if delim, ok := tok.(json.Delim); !ok || delim != '{' {
		return meta, errors.New("traffic manifest must be a JSON object")
	}
	for dec.More() {
		keyTok, err := dec.Token()
		if err != nil {
			return meta, err
		}
		key, ok := keyTok.(string)
		if !ok {
			return meta, errors.New("traffic manifest key must be a string")
		}
		switch key {
		case "version":
			if err := dec.Decode(&meta.Version); err != nil {
				return meta, err
			}
		case "format":
			if err := dec.Decode(&meta.Format); err != nil {
				return meta, err
			}
		case "count":
			if err := dec.Decode(&meta.Count); err != nil {
				return meta, err
			}
		case "blobs":
			if err := dec.Decode(&meta.Blobs); err != nil {
				return meta, err
			}
		default:
			if err := skipTrafficJSONValue(dec); err != nil {
				return meta, err
			}
		}
	}
	if _, err := dec.Token(); err != nil {
		return meta, err
	}
	return meta, nil
}

func skipTrafficJSONValue(dec *json.Decoder) error {
	tok, err := dec.Token()
	if err != nil {
		return err
	}
	delim, ok := tok.(json.Delim)
	if !ok || (delim != '{' && delim != '[') {
		return nil
	}
	depth := 1
	for depth > 0 {
		t, err := dec.Token()
		if err != nil {
			return err
		}
		if d, ok := t.(json.Delim); ok {
			switch d {
			case '{', '[':
				depth++
			case '}', ']':
				depth--
			}
		}
	}
	return nil
}

func streamTrafficNDJSON(path string, expectedCount int64, consume func(ArchiveExchange) error) error {
	f, err := os.Open(path)
	if os.IsNotExist(err) && expectedCount == 0 {
		return nil
	}
	if err != nil {
		return err
	}
	defer f.Close()

	br := bufio.NewReaderSize(f, trafficStreamBufSize)
	var readCount int64
	for {
		line, eof, readErr := readBoundedNDJSONLine(br, maxTrafficNDJSONLineBytes)
		if readErr != nil {
			return readErr
		}
		trimmed := bytes.TrimSpace(line)
		if len(trimmed) > 0 {
			var item ArchiveExchange
			if err := json.Unmarshal(trimmed, &item); err != nil {
				return fmt.Errorf("decode traffic.ndjson row: %w", err)
			}
			if err := consume(item); err != nil {
				return err
			}
			readCount++
		}
		if eof {
			if expectedCount > 0 && readCount != expectedCount {
				return fmt.Errorf("traffic.ndjson count mismatch: read %d rows, manifest expected %d", readCount, expectedCount)
			}
			return nil
		}
	}
}

func readBoundedNDJSONLine(br *bufio.Reader, maxBytes int) ([]byte, bool, error) {
	var buf []byte
	for {
		frag, err := br.ReadSlice('\n')
		if err == nil {
			if len(buf)+len(frag) > maxBytes {
				return nil, false, fmt.Errorf("traffic.ndjson row exceeds maximum size (%d bytes)", maxBytes)
			}
			if len(buf) == 0 {
				return frag, false, nil
			}
			buf = append(buf, frag...)
			return buf, false, nil
		}
		if errors.Is(err, bufio.ErrBufferFull) {
			if len(buf)+len(frag) > maxBytes {
				return nil, false, fmt.Errorf("traffic.ndjson row exceeds maximum size (%d bytes)", maxBytes)
			}
			buf = append(buf, frag...)
			continue
		}
		if errors.Is(err, io.EOF) {
			if len(buf)+len(frag) > maxBytes {
				return nil, false, fmt.Errorf("traffic.ndjson row exceeds maximum size (%d bytes)", maxBytes)
			}
			if len(buf) == 0 {
				return frag, true, nil
			}
			buf = append(buf, frag...)
			return buf, true, nil
		}
		return nil, false, err
	}
}

func streamLegacyV1Exchanges(path string, consume func(ArchiveExchange) error) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()

	dec := json.NewDecoder(bufio.NewReaderSize(f, trafficStreamBufSize))
	tok, err := dec.Token()
	if err != nil {
		return err
	}
	if delim, ok := tok.(json.Delim); !ok || delim != '{' {
		return errors.New("traffic manifest must be a JSON object")
	}
	for dec.More() {
		keyTok, err := dec.Token()
		if err != nil {
			return err
		}
		key, ok := keyTok.(string)
		if !ok {
			return errors.New("traffic manifest key must be a string")
		}
		if key != "exchanges" {
			if err := skipTrafficJSONValue(dec); err != nil {
				return err
			}
			continue
		}
		arrTok, err := dec.Token()
		if err != nil {
			return err
		}
		if arrTok == nil {
			continue // null exchanges array
		}
		if delim, ok := arrTok.(json.Delim); !ok || delim != '[' {
			return errors.New("traffic v1 exchanges must be a JSON array")
		}
		for dec.More() {
			var item ArchiveExchange
			if err := dec.Decode(&item); err != nil {
				return err
			}
			if err := consume(item); err != nil {
				return err
			}
		}
		if _, err := dec.Token(); err != nil {
			return err
		}
	}
	return nil
}

func uniqueArchiveHosts(hosts []string) []string {
	seen := make(map[string]struct{}, len(hosts))
	out := make([]string, 0, len(hosts))
	for _, host := range hosts {
		host = strings.ToLower(strings.TrimSpace(host))
		if host == "" {
			continue
		}
		if _, exists := seen[host]; exists {
			continue
		}
		seen[host] = struct{}{}
		out = append(out, host)
	}
	sort.Strings(out)
	return out
}
