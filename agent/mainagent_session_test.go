package agent

import (
	"testing"

	"github.com/RC-CHN/ARTEX/db"
)

func TestMainSessionTranscriptIDIsolation(t *testing.T) {
	if got := mainSessionTranscriptID(42, 0, nil); got != "exp42-main" {
		t.Fatalf("human seg 0 = %q, want exp42-main", got)
	}
	if got := mainSessionTranscriptID(42, 2, nil); got != "exp42-main-s2" {
		t.Fatalf("human seg 2 = %q, want exp42-main-s2", got)
	}
	// Consultation must ALWAYS be isolated from human transcripts, even for a
	// legacy request whose MainSeg is 0.
	if got := mainSessionTranscriptID(42, 0, &db.MainRequest{ID: 9, MainSeg: 0}); got != "exp42-main-consult-9" {
		t.Fatalf("legacy consultation = %q, want exp42-main-consult-9", got)
	}
	if got := mainSessionTranscriptID(42, db.MainSegConsultation, &db.MainRequest{ID: 10, MainSeg: db.MainSegConsultation}); got != "exp42-main-consult-10" {
		t.Fatalf("consultation = %q, want exp42-main-consult-10", got)
	}
}
