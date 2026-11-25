// Package transcript persists a conversation to an append-only JSONL log on
// disk and reconstructs it for resume. The main session is written to
// <dir>/<sessionID>.jsonl; each
// subagent is written to its own sidechain file under
// <dir>/<sessionID>/subagents/agent-<agentID>.jsonl, so subagent tokens are
// counted and stored separately (aggregate them offline if needed).
//
// The log is the full-fidelity history: every user/assistant/tool message is
// recorded as it is born. When compaction inserts a boundary, the post-boundary
// working set — the boundary marker, the summary, and the kept recent tail — is
// ALSO persisted (kept-tail messages already on disk are recorded as compact
// Type=="ref" pointers instead of duplicating payloads), so a cold-start resume
// restores the COMPACTED view (via llm.MessagesForAPI, which slices from the
// last boundary) instead of replaying raw history and re-summarizing. A tiny
// sidecar index (<path>.idx) tracks the last boundary offset and cumulative
// usage so LoadActive can seek straight to the working set in O(working set)
// I/O, falling back to reverse chunk scanning if the sidecar is missing or
// stale. Lightweight working-set edits that do not add a boundary (MicroCompact
// tool-result clearing) stay ephemeral and are not persisted. A separate
// Type=="boundary" record is written for observability and cumulative-usage
// checkpointing, and is skipped during message reconstruction.
package transcript

import (
	"bufio"
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/RC-CHN/ARTEX/norma/llm"
)

const (
	sidecarVersion         = 1
	maxTranscriptLineBytes = 64 * 1024 * 1024
	reverseChunkSize       = 64 * 1024
	reverseNeedleOverlap   = 32
	maxWriterRefs          = 128
)

var (
	boundaryNeedleCompact = []byte(`"type":"boundary"`)
	boundaryNeedleSpaced  = []byte(`"type": "boundary"`)
)

// Record is one line of a JSONL transcript.
type Record struct {
	UUID        string            `json:"uuid"`
	ParentUUID  string            `json:"parent_uuid,omitempty"`
	SessionID   string            `json:"session_id"`
	AgentID     string            `json:"agent_id,omitempty"`
	IsSidechain bool              `json:"is_sidechain,omitempty"`
	Timestamp   string            `json:"timestamp"`
	Type        string            `json:"type"` // "message" | "boundary" | "ref"
	Message     *llm.Message      `json:"message,omitempty"`
	Usage       *llm.Usage        `json:"usage,omitempty"`       // assistant turns only
	Boundary    *llm.BoundaryMeta `json:"boundary,omitempty"`    // Type=="boundary"
	TotalUsage  *llm.Usage        `json:"total_usage,omitempty"` // Type=="boundary": cumulative usage up to boundary
	RefUUID     string            `json:"ref_uuid,omitempty"`    // Type=="ref": original message UUID
	RefOffset   int64             `json:"ref_offset,omitempty"`  // Type=="ref": byte offset of original record line
	RefLength   int               `json:"ref_length,omitempty"`  // Type=="ref": byte length of original JSON line
}

// ActiveTranscript holds the active working-set records starting from the last
// compaction boundary (or the full transcript if no boundary exists), together
// with session metadata recovered without scanning pre-boundary history.
type ActiveTranscript struct {
	Records        []Record
	FirstTimestamp string
	LastUUID       string
	TotalUsage     llm.Usage
	BytesRead      int64

	hasBoundary        bool
	lastBoundaryOffset int64
	refs               []refEntry
}

type sidecarIndex struct {
	Version            int       `json:"version"`
	FileSize           int64     `json:"file_size"`
	HasBoundary        bool      `json:"has_boundary,omitempty"`
	LastBoundaryOffset int64     `json:"last_boundary_offset"`
	FirstTimestamp     string    `json:"first_timestamp,omitempty"`
	LastUUID           string    `json:"last_uuid,omitempty"`
	TotalUsage         llm.Usage `json:"total_usage"`
}

type recordSpan struct {
	uuid   string
	offset int64
	length int
}

type refEntry struct {
	hash [sha256.Size]byte
	span recordSpan
}

type positionedRecord struct {
	rec    Record
	offset int64
	length int
}

type countingReader struct {
	r io.Reader
	n int64
}

func (c *countingReader) Read(p []byte) (int, error) {
	n, err := c.r.Read(p)
	c.n += int64(n)
	return n, err
}

// Store is a directory of session transcripts.
type Store struct {
	dir string
	mu  sync.RWMutex // serializes appends/sidecar updates against concurrent reads in this process
}

// NewStore returns a Store rooted at dir (created lazily on first write).
func NewStore(dir string) *Store { return &Store{dir: dir} }

// MainPath is the JSONL file for a top-level session.
func (s *Store) MainPath(sessionID string) string {
	return filepath.Join(s.dir, sessionID+".jsonl")
}

// AgentPath is the sidechain JSONL file for a subagent of a session.
func (s *Store) AgentPath(sessionID, agentID string) string {
	return filepath.Join(s.dir, sessionID, "subagents", "agent-"+agentID+".jsonl")
}

// IndexPath returns the sidecar index path for a transcript JSONL file.
func IndexPath(path string) string { return path + ".idx" }

// Append writes records to path as JSONL, creating parent directories and
// updating the lightweight sidecar index. It is safe for concurrent use within
// the process.
func (s *Store) Append(path string, recs ...Record) error {
	_, err := s.appendWithSpans(path, recs...)
	return err
}

func (s *Store) appendWithSpans(path string, recs ...Record) ([]recordSpan, error) {
	if len(recs) == 0 {
		return nil, nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return nil, err
	}
	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644)
	if err != nil {
		return nil, err
	}
	st, err := f.Stat()
	if err != nil {
		_ = f.Close()
		return nil, err
	}
	startOffset := st.Size()
	idx, idxValid := loadOrRebuildIndexUnlocked(path, startOffset)

	w := bufio.NewWriter(f)
	curOffset := startOffset
	spans := make([]recordSpan, 0, len(recs))
	for _, r := range recs {
		if r.Type == "boundary" && r.TotalUsage == nil && idxValid {
			u := idx.TotalUsage
			r.TotalUsage = &u
		}
		b, err := json.Marshal(r)
		if err != nil {
			_ = f.Close()
			return nil, err
		}
		if _, err := w.Write(b); err != nil {
			_ = f.Close()
			return nil, err
		}
		if err := w.WriteByte('\n'); err != nil {
			_ = f.Close()
			return nil, err
		}
		spans = append(spans, recordSpan{uuid: r.UUID, offset: curOffset, length: len(b)})
		if idxValid {
			if idx.FirstTimestamp == "" && r.Timestamp != "" {
				idx.FirstTimestamp = r.Timestamp
			}
			if r.Type == "boundary" {
				idx.HasBoundary = true
				idx.LastBoundaryOffset = curOffset
			}
			if r.Type != "boundary" && r.Type != "ref" && r.Usage != nil {
				idx.TotalUsage.Add(*r.Usage)
			}
			if r.UUID != "" {
				idx.LastUUID = r.UUID
			}
		}
		curOffset += int64(len(b)) + 1
	}
	if err := w.Flush(); err != nil {
		_ = f.Close()
		return nil, err
	}
	if err := f.Close(); err != nil {
		return nil, err
	}
	if idxValid {
		idx.FileSize = curOffset
		_ = writeIndexAtomic(IndexPath(path), idx)
	}
	return spans, nil
}

func loadOrRebuildIndexUnlocked(path string, startOffset int64) (sidecarIndex, bool) {
	if startOffset == 0 {
		return sidecarIndex{Version: sidecarVersion}, true
	}
	if idx, ok := readIndexFile(IndexPath(path)); ok && idx.FileSize == startOffset {
		return idx, true
	}
	active, err := loadActiveFile(path, nil)
	if err != nil {
		return sidecarIndex{}, false
	}
	return sidecarIndex{
		Version:            sidecarVersion,
		FileSize:           startOffset,
		HasBoundary:        active.hasBoundary,
		LastBoundaryOffset: active.lastBoundaryOffset,
		FirstTimestamp:     active.FirstTimestamp,
		LastUUID:           active.LastUUID,
		TotalUsage:         active.TotalUsage,
	}, true
}

func readIndexFile(idxPath string) (sidecarIndex, bool) {
	b, err := os.ReadFile(idxPath)
	if err != nil {
		return sidecarIndex{}, false
	}
	var idx sidecarIndex
	if err := json.Unmarshal(b, &idx); err != nil {
		return sidecarIndex{}, false
	}
	if idx.Version != sidecarVersion || idx.FileSize < 0 {
		return sidecarIndex{}, false
	}
	if idx.HasBoundary && (idx.LastBoundaryOffset < 0 || idx.LastBoundaryOffset >= idx.FileSize) {
		return sidecarIndex{}, false
	}
	return idx, true
}

func writeIndexAtomic(idxPath string, idx sidecarIndex) error {
	b, err := json.Marshal(idx)
	if err != nil {
		return err
	}
	dir := filepath.Dir(idxPath)
	tmp, err := os.CreateTemp(dir, ".idx-*")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	if _, err := tmp.Write(b); err != nil {
		_ = tmp.Close()
		_ = os.Remove(tmpName)
		return err
	}
	if err := tmp.Close(); err != nil {
		_ = os.Remove(tmpName)
		return err
	}
	if err := os.Rename(tmpName, idxPath); err != nil {
		_ = os.Remove(tmpName)
		return err
	}
	return nil
}

// Load reads all records from a transcript file, materializing any Type=="ref"
// records from earlier in the same log. A missing file yields no records and no
// error (a fresh session).
func (s *Store) Load(path string) ([]Record, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	f, err := os.Open(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, nil
		}
		return nil, err
	}
	defer f.Close()
	posRecs, _, err := readRecordsFrom(f, 0)
	if err != nil {
		return nil, err
	}
	if len(posRecs) == 0 {
		return nil, nil
	}
	byUUID := make(map[string]*llm.Message, len(posRecs))
	recs := make([]Record, len(posRecs))
	for i, pr := range posRecs {
		r := pr.rec
		if r.Type == "message" && r.Message != nil && r.UUID != "" {
			byUUID[r.UUID] = r.Message
		} else if r.Type == "ref" && r.Message == nil && r.RefUUID != "" {
			if orig, ok := byUUID[r.RefUUID]; ok {
				r.Message = orig
			}
		}
		recs[i] = r
	}
	return recs, nil
}

// LoadActive loads only the active post-boundary working set (starting from the
// last compaction boundary record) along with the session's FirstTimestamp,
// LastUUID, and cumulative TotalUsage. When a valid sidecar index (<path>.idx)
// is present it seeks straight to the last boundary; otherwise it falls back to
// reading line 0 and reverse-scanning from EOF in 64 KiB chunks. If no boundary
// exists, it returns the full transcript. A missing file yields an empty
// ActiveTranscript and nil error.
func (s *Store) LoadActive(path string) (ActiveTranscript, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	var idxPtr *sidecarIndex
	if idx, ok := readIndexFile(IndexPath(path)); ok {
		idxCopy := idx
		idxPtr = &idxCopy
	}
	return loadActiveFile(path, idxPtr)
}

func loadActiveFile(path string, idx *sidecarIndex) (ActiveTranscript, error) {
	f, err := os.Open(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return ActiveTranscript{}, nil
		}
		return ActiveTranscript{}, err
	}
	defer f.Close()

	st, err := f.Stat()
	if err != nil {
		return ActiveTranscript{}, err
	}
	fileSize := st.Size()
	if fileSize == 0 {
		return ActiveTranscript{}, nil
	}

	// Fast path: sidecar index is present and covers a prefix (usually all) of the file.
	if idx != nil && idx.FileSize <= fileSize {
		if idx.HasBoundary && idx.LastBoundaryOffset < fileSize {
			if active, ok, err := loadActiveFromIndex(f, fileSize, *idx); err != nil {
				return ActiveTranscript{}, err
			} else if ok {
				return active, nil
			}
		} else if !idx.HasBoundary && idx.FileSize == fileSize {
			return loadFullActive(f, fileSize, 0)
		}
	}

	// Fallback path: sidecar missing, corrupt, stale, or file grew without boundary index.
	var totalBytesRead int64
	boundaryOff, foundBoundary, scanRead, err := reverseFindLastBoundary(f, fileSize)
	totalBytesRead += scanRead
	if err != nil {
		return ActiveTranscript{}, err
	}
	if !foundBoundary {
		return loadFullActive(f, fileSize, totalBytesRead)
	}

	firstTS, tsRead, err := readFirstTimestamp(f, fileSize)
	totalBytesRead += tsRead
	if err != nil {
		return ActiveTranscript{}, err
	}

	posRecs, tailRead, err := readRecordsFrom(f, boundaryOff)
	totalBytesRead += tailRead
	if err != nil {
		return ActiveTranscript{}, err
	}
	if len(posRecs) == 0 {
		return ActiveTranscript{FirstTimestamp: firstTS, BytesRead: totalBytesRead}, nil
	}

	var totalUsage llm.Usage
	if posRecs[0].rec.Type == "boundary" && posRecs[0].rec.TotalUsage != nil {
		totalUsage = *posRecs[0].rec.TotalUsage
	} else if posRecs[0].rec.Type == "boundary" && boundaryOff > 0 {
		// Legacy pre-Phase-4 transcript with no total_usage checkpoint and no
		// sidecar index: stream-scan [0, boundaryOff) once so pre-boundary usage is
		// recovered accurately instead of zeroed and persisted into .idx.
		preUsage, preRead, uerr := sumUsageBefore(f, boundaryOff)
		totalBytesRead += preRead
		if uerr != nil {
			return ActiveTranscript{}, uerr
		}
		totalUsage = preUsage
	}
	for _, pr := range posRecs[1:] {
		if pr.rec.Type != "boundary" && pr.rec.Type != "ref" && pr.rec.Usage != nil {
			totalUsage.Add(*pr.rec.Usage)
		}
	}

	recs, refs, refRead, err := resolveActiveRefs(f, fileSize, posRecs, nil)
	totalBytesRead += refRead
	if err != nil {
		return ActiveTranscript{}, err
	}
	return ActiveTranscript{
		Records:            recs,
		FirstTimestamp:     firstTS,
		LastUUID:           LastUUID(recs),
		TotalUsage:         totalUsage,
		BytesRead:          totalBytesRead,
		hasBoundary:        true,
		lastBoundaryOffset: boundaryOff,
		refs:               refs,
	}, nil
}

func loadActiveFromIndex(f *os.File, fileSize int64, idx sidecarIndex) (ActiveTranscript, bool, error) {
	// Verify that LastBoundaryOffset starts on a line boundary and actually holds
	// a Type=="boundary" record; if not (e.g. file replaced while leaving a stale
	// .idx), return ok=false so LoadActive falls back cleanly to reverse-scan.
	if idx.LastBoundaryOffset > 0 {
		var prev [1]byte
		if n, err := f.ReadAt(prev[:], idx.LastBoundaryOffset-1); err != nil || n != 1 || prev[0] != '\n' {
			return ActiveTranscript{}, false, nil
		}
	}
	firstLine, _, err := readLineAt(f, idx.LastBoundaryOffset, fileSize, nil, 0)
	if err != nil || !isBoundaryLine(firstLine) {
		return ActiveTranscript{}, false, nil
	}

	posRecs, bytesRead, err := readRecordsFrom(f, idx.LastBoundaryOffset)
	if err != nil {
		return ActiveTranscript{}, false, err
	}
	if len(posRecs) == 0 || posRecs[0].rec.Type != "boundary" {
		return ActiveTranscript{}, false, nil
	}

	totalUsage := idx.TotalUsage
	lastBoundaryIdx := 0
	for i, pr := range posRecs {
		if pr.rec.Type == "boundary" {
			lastBoundaryIdx = i
		}
		// Accumulate delta usage for any records appended after the index snapshot.
		if pr.offset >= idx.FileSize && pr.rec.Type != "boundary" && pr.rec.Type != "ref" && pr.rec.Usage != nil {
			totalUsage.Add(*pr.rec.Usage)
		}
	}

	activePos := posRecs[lastBoundaryIdx:]
	priorPos := posRecs[:lastBoundaryIdx]
	boundaryOff := activePos[0].offset

	firstTS := idx.FirstTimestamp
	if firstTS == "" {
		ts, tsRead, tsErr := readFirstTimestamp(f, fileSize)
		bytesRead += tsRead
		if tsErr != nil {
			return ActiveTranscript{}, false, tsErr
		}
		firstTS = ts
	}

	recs, refs, refRead, err := resolveActiveRefs(f, fileSize, activePos, priorPos)
	bytesRead += refRead
	if err != nil {
		return ActiveTranscript{}, false, err
	}

	lastUUID := LastUUID(recs)
	if lastUUID == "" {
		lastUUID = idx.LastUUID
	}
	return ActiveTranscript{
		Records:            recs,
		FirstTimestamp:     firstTS,
		LastUUID:           lastUUID,
		TotalUsage:         totalUsage,
		BytesRead:          bytesRead,
		hasBoundary:        true,
		lastBoundaryOffset: boundaryOff,
		refs:               refs,
	}, true, nil
}

func loadFullActive(f *os.File, fileSize int64, priorBytesRead int64) (ActiveTranscript, error) {
	posRecs, readBytes, err := readRecordsFrom(f, 0)
	totalBytesRead := priorBytesRead + readBytes
	if err != nil {
		return ActiveTranscript{}, err
	}
	if len(posRecs) == 0 {
		return ActiveTranscript{BytesRead: totalBytesRead}, nil
	}

	byUUID := make(map[string]*llm.Message, len(posRecs))
	spanByUUID := make(map[string]recordSpan, len(posRecs))
	recs := make([]Record, len(posRecs))
	var (
		totalUsage         llm.Usage
		firstTS            string
		hasBoundary        bool
		lastBoundaryOffset int64
		lastBoundaryIdx    int
		refs               []refEntry
	)
	for i, pr := range posRecs {
		r := pr.rec
		if firstTS == "" && r.Timestamp != "" {
			firstTS = r.Timestamp
		}
		if r.Type == "boundary" {
			hasBoundary = true
			lastBoundaryOffset = pr.offset
			lastBoundaryIdx = i
		}
		if r.Type == "message" && r.Message != nil {
			if r.UUID != "" {
				byUUID[r.UUID] = r.Message
				spanByUUID[r.UUID] = recordSpan{uuid: r.UUID, offset: pr.offset, length: pr.length}
			}
			if r.Usage != nil {
				totalUsage.Add(*r.Usage)
			}
			if hash, herr := messageHash(*r.Message); herr == nil {
				refs = append(refs, refEntry{hash: hash, span: recordSpan{uuid: r.UUID, offset: pr.offset, length: pr.length}})
			}
		} else if r.Type == "ref" && r.Message == nil && r.RefUUID != "" {
			if orig, ok := byUUID[r.RefUUID]; ok {
				r.Message = orig
				if sp, ok := spanByUUID[r.RefUUID]; ok {
					if hash, herr := messageHash(*orig); herr == nil {
						refs = append(refs, refEntry{hash: hash, span: sp})
					}
				}
			}
		}
		recs[i] = r
	}
	if hasBoundary && lastBoundaryIdx > 0 {
		recs = recs[lastBoundaryIdx:]
	}
	if len(refs) > maxWriterRefs {
		refs = refs[len(refs)-maxWriterRefs:]
	}
	return ActiveTranscript{
		Records:            recs,
		FirstTimestamp:     firstTS,
		LastUUID:           LastUUID(recs),
		TotalUsage:         totalUsage,
		BytesRead:          totalBytesRead,
		hasBoundary:        hasBoundary,
		lastBoundaryOffset: lastBoundaryOffset,
		refs:               refs,
	}, nil
}

func resolveActiveRefs(f *os.File, fileSize int64, posRecs []positionedRecord, priorPos []positionedRecord) ([]Record, []refEntry, int64, error) {
	byUUID := make(map[string]*llm.Message, len(posRecs)+len(priorPos))
	spanByUUID := make(map[string]recordSpan, len(posRecs)+len(priorPos))
	for _, pr := range priorPos {
		if pr.rec.Type == "message" && pr.rec.Message != nil && pr.rec.UUID != "" {
			byUUID[pr.rec.UUID] = pr.rec.Message
			spanByUUID[pr.rec.UUID] = recordSpan{uuid: pr.rec.UUID, offset: pr.offset, length: pr.length}
		}
	}
	recs := make([]Record, len(posRecs))
	var (
		refs          []refEntry
		unresolvedIdx []int
		bytesRead     int64
	)

	for i, pr := range posRecs {
		r := pr.rec
		if r.Type == "message" && r.Message != nil {
			sp := recordSpan{uuid: r.UUID, offset: pr.offset, length: pr.length}
			if r.UUID != "" {
				byUUID[r.UUID] = r.Message
				spanByUUID[r.UUID] = sp
			}
			if hash, err := messageHash(*r.Message); err == nil {
				refs = append(refs, refEntry{hash: hash, span: sp})
			}
		}
		recs[i] = r
	}

	for i := range recs {
		r := &recs[i]
		if r.Type != "ref" || r.Message != nil || r.RefUUID == "" {
			continue
		}
		if orig, ok := byUUID[r.RefUUID]; ok {
			r.Message = orig
			if sp, ok := spanByUUID[r.RefUUID]; ok {
				if hash, err := messageHash(*orig); err == nil {
					refs = append(refs, refEntry{hash: hash, span: sp})
				}
			}
			continue
		}
		// Direct O(1) ReadAt using stored byte offset + length.
		if r.RefOffset >= 0 && r.RefLength > 0 && r.RefLength <= maxTranscriptLineBytes && r.RefOffset+int64(r.RefLength) <= fileSize {
			buf := make([]byte, r.RefLength)
			n, rerr := f.ReadAt(buf, r.RefOffset)
			bytesRead += int64(n)
			if rerr == nil || (errors.Is(rerr, io.EOF) && n == r.RefLength) {
				var orig Record
				if json.Unmarshal(buf[:n], &orig) == nil && orig.UUID == r.RefUUID && orig.Type == "message" && orig.Message != nil {
					r.Message = orig.Message
					sp := recordSpan{uuid: orig.UUID, offset: r.RefOffset, length: r.RefLength}
					byUUID[orig.UUID] = orig.Message
					spanByUUID[orig.UUID] = sp
					if hash, err := messageHash(*orig.Message); err == nil {
						refs = append(refs, refEntry{hash: hash, span: sp})
					}
					continue
				}
			}
		}
		unresolvedIdx = append(unresolvedIdx, i)
	}

	// Fallback if any ref offset failed validation (e.g. file manually edited):
	// perform a single scan by UUID so resolution still succeeds cleanly.
	if len(unresolvedIdx) > 0 {
		need := make(map[string]bool, len(unresolvedIdx))
		for _, idx := range unresolvedIdx {
			need[recs[idx].RefUUID] = true
		}
		allRecs, scanBytes, err := readRecordsFrom(f, 0)
		bytesRead += scanBytes
		if err != nil {
			return nil, nil, bytesRead, err
		}
		for _, pr := range allRecs {
			if pr.rec.Type == "message" && pr.rec.Message != nil && need[pr.rec.UUID] {
				byUUID[pr.rec.UUID] = pr.rec.Message
				spanByUUID[pr.rec.UUID] = recordSpan{uuid: pr.rec.UUID, offset: pr.offset, length: pr.length}
			}
		}
		for _, idx := range unresolvedIdx {
			r := &recs[idx]
			if orig, ok := byUUID[r.RefUUID]; ok {
				r.Message = orig
				if sp, ok := spanByUUID[r.RefUUID]; ok {
					if hash, err := messageHash(*orig); err == nil {
						refs = append(refs, refEntry{hash: hash, span: sp})
					}
				}
			}
		}
	}

	if len(refs) > maxWriterRefs {
		refs = refs[len(refs)-maxWriterRefs:]
	}
	return recs, refs, bytesRead, nil
}

func sumUsageBefore(f *os.File, endOffset int64) (llm.Usage, int64, error) {
	if endOffset <= 0 {
		return llm.Usage{}, 0, nil
	}
	sr := io.NewSectionReader(f, 0, endOffset)
	cr := &countingReader{r: sr}
	br := bufio.NewReaderSize(cr, 16*1024)
	var total llm.Usage
	for {
		raw, err := br.ReadBytes('\n')
		if err != nil && !errors.Is(err, io.EOF) {
			return llm.Usage{}, cr.n, err
		}
		trimmed := bytes.TrimRight(raw, "\r\n")
		if len(trimmed) > maxTranscriptLineBytes {
			return llm.Usage{}, cr.n, fmt.Errorf("transcript: line exceeds %d bytes", maxTranscriptLineBytes)
		}
		if len(trimmed) > 0 {
			var r struct {
				Type  string     `json:"type"`
				Usage *llm.Usage `json:"usage,omitempty"`
			}
			if uerr := json.Unmarshal(trimmed, &r); uerr != nil {
				return llm.Usage{}, cr.n, fmt.Errorf("transcript: corrupt line: %w", uerr)
			}
			if r.Type != "boundary" && r.Type != "ref" && r.Usage != nil {
				total.Add(*r.Usage)
			}
		}
		if errors.Is(err, io.EOF) {
			break
		}
	}
	return total, cr.n, nil
}

func readRecordsFrom(f *os.File, startOffset int64) ([]positionedRecord, int64, error) {
	if _, err := f.Seek(startOffset, io.SeekStart); err != nil {
		return nil, 0, err
	}
	cr := &countingReader{r: f}
	br := bufio.NewReaderSize(cr, 16*1024)
	curOffset := startOffset
	var out []positionedRecord
	for {
		lineOffset := curOffset
		raw, err := br.ReadBytes('\n')
		curOffset += int64(len(raw))
		if err != nil && !errors.Is(err, io.EOF) {
			return nil, cr.n, err
		}
		trimmed := bytes.TrimRight(raw, "\r\n")
		if len(trimmed) > maxTranscriptLineBytes {
			return nil, cr.n, fmt.Errorf("transcript: line exceeds %d bytes", maxTranscriptLineBytes)
		}
		if len(trimmed) > 0 {
			var r Record
			if uerr := json.Unmarshal(trimmed, &r); uerr != nil {
				return nil, cr.n, fmt.Errorf("transcript: corrupt line: %w", uerr)
			}
			out = append(out, positionedRecord{rec: r, offset: lineOffset, length: len(trimmed)})
		}
		if errors.Is(err, io.EOF) {
			break
		}
	}
	return out, cr.n, nil
}

func reverseFindLastBoundary(f *os.File, fileSize int64) (int64, bool, int64, error) {
	var bytesRead int64
	buf := make([]byte, reverseChunkSize+reverseNeedleOverlap)
	pos := fileSize

	for pos > 0 {
		chunkStart := pos - reverseChunkSize
		if chunkStart < 0 {
			chunkStart = 0
		}
		readEnd := pos + reverseNeedleOverlap
		if readEnd > fileSize {
			readEnd = fileSize
		}
		want := int(readEnd - chunkStart)
		n, err := f.ReadAt(buf[:want], chunkStart)
		bytesRead += int64(n)
		if err != nil && !errors.Is(err, io.EOF) {
			return 0, false, bytesRead, err
		}
		chunk := buf[:n]

		searchEnd := len(chunk)
		nextPos := chunkStart
		for searchEnd > 0 {
			idx := lastBoundaryNeedle(chunk[:searchEnd])
			if idx < 0 {
				break
			}
			var lineStart int64
			if nl := bytes.LastIndexByte(chunk[:idx], '\n'); nl >= 0 {
				lineStart = chunkStart + int64(nl) + 1
			} else if chunkStart == 0 {
				lineStart = 0
			} else {
				ls, readN, lerr := findLineStartBackwards(f, chunkStart)
				bytesRead += readN
				if lerr != nil {
					return 0, false, bytesRead, lerr
				}
				lineStart = ls
			}

			line, readN, lerr := readLineAt(f, lineStart, fileSize, chunk, chunkStart)
			bytesRead += readN
			if lerr == nil && isBoundaryLine(line) {
				return lineStart, true, bytesRead, nil
			}
			// False positive (e.g. nested inside tool_use input JSON). Continue
			// searching strictly before this line.
			if lineStart <= chunkStart {
				nextPos = lineStart
				break
			}
			searchEnd = int(lineStart - chunkStart)
		}
		pos = nextPos
	}
	return 0, false, bytesRead, nil
}

func lastBoundaryNeedle(b []byte) int {
	a := bytes.LastIndex(b, boundaryNeedleCompact)
	c := bytes.LastIndex(b, boundaryNeedleSpaced)
	if c > a {
		return c
	}
	return a
}

func findLineStartBackwards(f *os.File, beforeOffset int64) (int64, int64, error) {
	const step = 4096
	buf := make([]byte, step)
	var bytesRead int64
	pos := beforeOffset
	for pos > 0 {
		start := pos - step
		if start < 0 {
			start = 0
		}
		n, err := f.ReadAt(buf[:pos-start], start)
		bytesRead += int64(n)
		if err != nil && !errors.Is(err, io.EOF) {
			return 0, bytesRead, err
		}
		if nl := bytes.LastIndexByte(buf[:n], '\n'); nl >= 0 {
			return start + int64(nl) + 1, bytesRead, nil
		}
		pos = start
	}
	return 0, bytesRead, nil
}

func readLineAt(f *os.File, lineStart, fileSize int64, cachedChunk []byte, cachedStart int64) ([]byte, int64, error) {
	// Zero-I/O fast path when the complete line already sits inside cachedChunk.
	if cachedChunk != nil && lineStart >= cachedStart && lineStart < cachedStart+int64(len(cachedChunk)) {
		rel := int(lineStart - cachedStart)
		rest := cachedChunk[rel:]
		if nl := bytes.IndexByte(rest, '\n'); nl >= 0 {
			return bytes.TrimRight(rest[:nl], "\r"), 0, nil
		}
		if cachedStart+int64(len(cachedChunk)) == fileSize {
			return bytes.TrimRight(rest, "\r"), 0, nil
		}
	}
	// Read line starting at lineStart using a bounded ReadAt loop so caller's
	// file offset is never disturbed.
	const step = 4096
	var out []byte
	var bytesRead int64
	off := lineStart
	buf := make([]byte, step)
	for off < fileSize {
		want := step
		if rem := fileSize - off; rem < int64(want) {
			want = int(rem)
		}
		n, err := f.ReadAt(buf[:want], off)
		bytesRead += int64(n)
		if err != nil && !errors.Is(err, io.EOF) {
			return nil, bytesRead, err
		}
		if n == 0 {
			break
		}
		if nl := bytes.IndexByte(buf[:n], '\n'); nl >= 0 {
			out = append(out, buf[:nl]...)
			return bytes.TrimRight(out, "\r"), bytesRead, nil
		}
		out = append(out, buf[:n]...)
		if len(out) > maxTranscriptLineBytes {
			return nil, bytesRead, fmt.Errorf("transcript: line exceeds %d bytes", maxTranscriptLineBytes)
		}
		off += int64(n)
	}
	return bytes.TrimRight(out, "\r"), bytesRead, nil
}

func isBoundaryLine(line []byte) bool {
	line = bytes.TrimSpace(line)
	if len(line) == 0 || line[0] != '{' {
		return false
	}
	var hdr struct {
		Type string `json:"type"`
	}
	if err := json.Unmarshal(line, &hdr); err != nil {
		return false
	}
	return hdr.Type == "boundary"
}

func readFirstTimestamp(f *os.File, fileSize int64) (string, int64, error) {
	if fileSize <= 0 {
		return "", 0, nil
	}
	const peekSize = 4096
	peekLen := int64(peekSize)
	if fileSize < peekLen {
		peekLen = fileSize
	}
	buf := make([]byte, peekLen)
	n, err := f.ReadAt(buf, 0)
	bytesRead := int64(n)
	if err != nil && !errors.Is(err, io.EOF) {
		return "", bytesRead, err
	}
	head := buf[:n]
	if nl := bytes.IndexByte(head, '\n'); nl >= 0 || int64(n) == fileSize {
		line := head
		if nl >= 0 {
			line = head[:nl]
		}
		var hdr struct {
			Timestamp string `json:"timestamp"`
		}
		if err := json.Unmarshal(bytes.TrimSpace(line), &hdr); err == nil {
			return hdr.Timestamp, bytesRead, nil
		}
		return "", bytesRead, nil
	}
	if ts, ok := extractTimestampFromPrefix(head); ok {
		return ts, bytesRead, nil
	}
	line, moreRead, err := readLineAt(f, 0, fileSize, nil, 0)
	bytesRead += moreRead
	if err != nil {
		return "", bytesRead, err
	}
	var hdr struct {
		Timestamp string `json:"timestamp"`
	}
	if err := json.Unmarshal(bytes.TrimSpace(line), &hdr); err == nil {
		return hdr.Timestamp, bytesRead, nil
	}
	return "", bytesRead, nil
}

func extractTimestampFromPrefix(head []byte) (string, bool) {
	prefix := head
	if mi := bytes.Index(prefix, []byte(`"message"`)); mi >= 0 {
		prefix = prefix[:mi]
	}
	key := []byte(`"timestamp"`)
	ki := bytes.Index(prefix, key)
	if ki < 0 {
		return "", false
	}
	rest := bytes.TrimLeft(prefix[ki+len(key):], " \t")
	if len(rest) == 0 || rest[0] != ':' {
		return "", false
	}
	rest = bytes.TrimLeft(rest[1:], " \t")
	var ts string
	if err := json.NewDecoder(bytes.NewReader(rest)).Decode(&ts); err != nil || ts == "" {
		return "", false
	}
	return ts, true
}

func messageHash(m llm.Message) ([sha256.Size]byte, error) {
	b, err := json.Marshal(m)
	if err != nil {
		return [sha256.Size]byte{}, err
	}
	return sha256.Sum256(b), nil
}

// Messages reconstructs the raw conversation and cumulative usage from records.
// Boundary records are skipped — the working set is rebuilt by compaction on the
// next turn, not replayed from disk. Type=="ref" records resolve from earlier
// records when not already materialized by Load/LoadActive, and never double-count
// usage.
func Messages(recs []Record) ([]llm.Message, llm.Usage) {
	var msgs []llm.Message
	var total llm.Usage
	var byUUID map[string]*llm.Message
	for _, r := range recs {
		if r.Type == "boundary" {
			continue
		}
		msg := r.Message
		if r.Type == "ref" {
			if msg == nil && r.RefUUID != "" && byUUID != nil {
				msg = byUUID[r.RefUUID]
			}
			if msg == nil {
				continue
			}
			msgs = append(msgs, *msg)
			continue
		}
		if msg == nil {
			continue
		}
		if r.UUID != "" {
			if byUUID == nil {
				byUUID = make(map[string]*llm.Message)
			}
			byUUID[r.UUID] = msg
		}
		msgs = append(msgs, *msg)
		if r.Usage != nil {
			total.Add(*r.Usage)
		}
	}
	return msgs, total
}

// LastUUID returns the UUID of the last record, for continuing the parent chain.
func LastUUID(recs []Record) string {
	if len(recs) == 0 {
		return ""
	}
	return recs[len(recs)-1].UUID
}

// Writer binds a Store, a file path, and a session/agent identity, assigning a
// UUID and parent link to each record. It satisfies harness.Recorder. Append
// errors are retained (see Err) rather than panicking, so a failing disk
// degrades to in-memory operation instead of crashing the agent loop.
type Writer struct {
	store       *Store
	path        string
	sessionID   string
	agentID     string
	isSidechain bool

	mu   sync.Mutex
	last string
	now  func() time.Time
	err  error
	refs []refEntry // bounded LRU of original Type=="message" spans (never ref->ref)
}

// NewWriter returns a Writer for a fresh transcript file. agentID == "" writes
// the main session file; a non-empty agentID writes a subagent sidechain.
func (s *Store) NewWriter(sessionID, agentID string) *Writer {
	w := &Writer{store: s, sessionID: sessionID, agentID: agentID, now: time.Now}
	if agentID == "" {
		w.path = s.MainPath(sessionID)
	} else {
		w.path = s.AgentPath(sessionID, agentID)
		w.isSidechain = true
	}
	return w
}

// ResumeWriter returns a Writer that continues an existing main-session file,
// chaining new records after lastUUID.
func (s *Store) ResumeWriter(sessionID, lastUUID string) *Writer {
	w := s.NewWriter(sessionID, "")
	w.last = lastUUID
	return w
}

// SeedRefs primes the writer's deduplication table with the original message
// locations recovered by LoadActive, so a compaction right after Resume can
// emit compact Type=="ref" records instead of re-writing kept tail payloads.
func (w *Writer) SeedRefs(active ActiveTranscript) {
	if w == nil || len(active.refs) == 0 {
		return
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	for _, e := range active.refs {
		w.putRefLocked(e.hash, e.span)
	}
}

// Err returns the first append error encountered, if any.
func (w *Writer) Err() error {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.err
}

func (w *Writer) writeLocked(r Record) (recordSpan, bool) {
	r.SessionID = w.sessionID
	r.AgentID = w.agentID
	r.IsSidechain = w.isSidechain
	r.UUID = newID()
	r.ParentUUID = w.last
	r.Timestamp = w.now().UTC().Format(time.RFC3339Nano)
	spans, err := w.store.appendWithSpans(w.path, r)
	if err != nil {
		if w.err == nil {
			w.err = err
		}
		return recordSpan{}, false
	}
	w.last = r.UUID
	if len(spans) > 0 {
		return spans[0], true
	}
	return recordSpan{}, true
}

func (w *Writer) putRefLocked(hash [sha256.Size]byte, span recordSpan) {
	if span.uuid == "" || span.length <= 0 {
		return
	}
	for i := range w.refs {
		if w.refs[i].hash == hash {
			w.refs[i].span = span
			// Move to end (MRU).
			e := w.refs[i]
			copy(w.refs[i:], w.refs[i+1:])
			w.refs[len(w.refs)-1] = e
			return
		}
	}
	if len(w.refs) >= maxWriterRefs {
		copy(w.refs, w.refs[1:])
		w.refs[len(w.refs)-1] = refEntry{hash: hash, span: span}
		return
	}
	w.refs = append(w.refs, refEntry{hash: hash, span: span})
}

func (w *Writer) getRefLocked(hash [sha256.Size]byte) (recordSpan, bool) {
	for i := len(w.refs) - 1; i >= 0; i-- {
		if w.refs[i].hash == hash {
			e := w.refs[i]
			copy(w.refs[i:], w.refs[i+1:])
			w.refs[len(w.refs)-1] = e
			return e.span, true
		}
	}
	return recordSpan{}, false
}

// RecordMessage persists a conversation message. usage is attributed to this
// turn (zero for non-assistant messages).
func (w *Writer) RecordMessage(m llm.Message, usage llm.Usage) {
	rec := Record{Type: "message", Message: &m}
	if usage != (llm.Usage{}) {
		u := usage
		rec.Usage = &u
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	span, ok := w.writeLocked(rec)
	if ok && span.length > 0 {
		if hash, err := messageHash(m); err == nil {
			w.putRefLocked(hash, span)
		}
	}
}

// RecordMessageRef persists a post-boundary kept-tail message as a compact
// Type=="ref" pointer to its original on-disk record when an identical message
// was already persisted, avoiding repeated duplication across compactions. If
// the message is new or modified (e.g. MicroCompacted), it falls back to
// writing a full Type=="message" record.
func (w *Writer) RecordMessageRef(m llm.Message) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if hash, err := messageHash(m); err == nil {
		if target, ok := w.getRefLocked(hash); ok {
			// Keep pointing to the original record (never chain ref->ref).
			w.writeLocked(Record{
				Type:      "ref",
				RefUUID:   target.uuid,
				RefOffset: target.offset,
				RefLength: target.length,
			})
			return
		}
	}
	span, ok := w.writeLocked(Record{Type: "message", Message: &m})
	if ok && span.length > 0 {
		if hash, err := messageHash(m); err == nil {
			w.putRefLocked(hash, span)
		}
	}
}

// RecordBoundary persists a compaction boundary for observability and records
// cumulative session usage at the boundary so resume can recover exact totals
// without scanning pre-boundary history.
func (w *Writer) RecordBoundary(meta llm.BoundaryMeta) {
	m := meta
	w.mu.Lock()
	defer w.mu.Unlock()
	w.writeLocked(Record{Type: "boundary", Boundary: &m})
}

// newID returns a random 128-bit hex identifier.
func newID() string {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		// rand should never fail; fall back to a time-based id to stay unique-ish.
		return hex.EncodeToString([]byte(time.Now().UTC().Format(time.RFC3339Nano)))
	}
	return hex.EncodeToString(b[:])
}

// NewSessionID returns a fresh session identifier.
func NewSessionID() string { return newID() }

// NewAgentID returns a fresh subagent identifier.
func NewAgentID() string { return newID() }
