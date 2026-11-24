package server

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"reflect"
	"testing"
	"time"

	"github.com/RC-CHN/ARTEX/agent"
	"github.com/RC-CHN/ARTEX/db"
)

func TestTaskChatStatusReportsRunningSegmentsAndConsultation(t *testing.T) {
	m := &Manager{tasks: map[string]*Task{"7": {ID: "7"}, "71": {ID: "71"}}}
	s := &Server{
		m:      m,
		engine: NewEngine(m),
		chatBusy: map[string]bool{
			taskChatKey("7", 0):        true,
			taskChatKey("7", 2):        true,
			taskConsultKey("7"):        true,
			taskChatKey("71", 1):       true,
			taskConsultKey("71"):       true,
			"conv-7":                   true,
		},
		chatCancel: map[string]context.CancelCauseFunc{},
	}

	req := httptest.NewRequest(http.MethodGet, "/api/tasks/7/chat/status", nil)
	req.SetPathValue("id", "7")
	rec := httptest.NewRecorder()
	s.taskChatStatus(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s, want 200", rec.Code, rec.Body.String())
	}

	var got struct {
		Running             bool  `json:"running"`
		RunningSegs         []int `json:"running_segs"`
		ConsultationRunning bool  `json:"consultation_running"`
	}
	if err := json.NewDecoder(rec.Body).Decode(&got); err != nil {
		t.Fatal(err)
	}
	if !got.Running {
		t.Fatal("expected running=true")
	}
	if !got.ConsultationRunning {
		t.Fatal("expected consultation_running=true")
	}
	wantSegs := []int{0, 2}
	if !reflect.DeepEqual(got.RunningSegs, wantSegs) {
		t.Fatalf("running_segs=%v, want %v", got.RunningSegs, wantSegs)
	}
}

func TestTaskChatStatusOnlyConsultationDoesNotMarkHumanSegsRunning(t *testing.T) {
	m := &Manager{tasks: map[string]*Task{"7": {ID: "7"}}}
	s := &Server{
		m:      m,
		engine: NewEngine(m),
		chatBusy: map[string]bool{
			taskConsultKey("7"): true,
		},
		chatCancel: map[string]context.CancelCauseFunc{},
	}

	req := httptest.NewRequest(http.MethodGet, "/api/tasks/7/chat/status", nil)
	req.SetPathValue("id", "7")
	rec := httptest.NewRecorder()
	s.taskChatStatus(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s, want 200", rec.Code, rec.Body.String())
	}

	var got struct {
		Running             bool  `json:"running"`
		RunningSegs         []int `json:"running_segs"`
		ConsultationRunning bool  `json:"consultation_running"`
	}
	if err := json.NewDecoder(rec.Body).Decode(&got); err != nil {
		t.Fatal(err)
	}
	if !got.Running || !got.ConsultationRunning {
		t.Fatalf("expected consultation running: %+v", got)
	}
	if len(got.RunningSegs) != 0 {
		t.Fatalf("human running_segs=%v, want empty when only consultation is running", got.RunningSegs)
	}
}

func TestTaskChatLaneAdmissionIsolatesHumanSegmentsAndConsultation(t *testing.T) {
	s := &Server{
		ctx:        context.Background(),
		engine:     NewEngine(nil),
		chatBusy:   map[string]bool{},
		chatCancel: map[string]context.CancelCauseFunc{},
	}

	// Start consultation lane first — must NOT block human seg 0 or newly created seg 1.
	consultKey, _, consultCancel, status, msg := s.admitTaskChatLane("7", db.MainSegConsultation, "")
	if status != 0 {
		t.Fatalf("admit consultation failed: %d %s", status, msg)
	}
	defer s.finishTaskChatLane(consultKey, consultCancel)

	// Second concurrent consultation on same task must still serialize.
	if _, _, _, dupStatus, _ := s.admitTaskChatLane("7", db.MainSegConsultation, ""); dupStatus != http.StatusConflict {
		t.Fatalf("expected 409 for duplicate consultation lane, got %d", dupStatus)
	}

	// Human seg 0 must be admitted while consultation is running.
	seg0Key, _, seg0Cancel, status, msg := s.admitTaskChatLane("7", 0, "hello seg 0")
	if status != 0 {
		t.Fatalf("admit human seg 0 blocked by consultation: %d %s", status, msg)
	}
	defer s.finishTaskChatLane(seg0Key, seg0Cancel)

	// Same human seg 0 must reject concurrent overlapping message.
	if _, _, _, dupStatus, _ := s.admitTaskChatLane("7", 0, "overlap"); dupStatus != http.StatusConflict {
		t.Fatalf("expected 409 for overlapping seg 0, got %d", dupStatus)
	}

	// Brand-new human seg 1 must NOT be blocked by running seg 0 OR running consultation.
	seg1Key, _, seg1Cancel, status, msg := s.admitTaskChatLane("7", 1, "hello seg 1")
	if status != 0 {
		t.Fatalf("admit new human seg 1 blocked by seg 0 / consultation: %d %s", status, msg)
	}
	defer s.finishTaskChatLane(seg1Key, seg1Cancel)
}

func TestStopChatTargetsRequestedSegmentAndPreservesOthers(t *testing.T) {
	m := &Manager{tasks: map[string]*Task{"7": {ID: "7"}, "71": {ID: "71"}}}
	ctx0, cancel0 := context.WithCancelCause(context.Background())
	ctx1, cancel1 := context.WithCancelCause(context.Background())
	ctxC, cancelC := context.WithCancelCause(context.Background())
	ctxOther, cancelOther := context.WithCancelCause(context.Background())
	defer cancel0(nil)
	defer cancel1(nil)
	defer cancelC(nil)
	defer cancelOther(nil)

	s := &Server{
		m:      m,
		engine: NewEngine(m),
		chatBusy: map[string]bool{
			taskChatKey("7", 0):  true,
			taskChatKey("7", 1):  true,
			taskConsultKey("7"):  true,
			taskChatKey("71", 0): true,
		},
		chatCancel: map[string]context.CancelCauseFunc{
			taskChatKey("7", 0):  cancel0,
			taskChatKey("7", 1):  cancel1,
			taskConsultKey("7"):  cancelC,
			taskChatKey("71", 0): cancelOther,
		},
	}

	// Stop only seg 1.
	req := httptest.NewRequest(http.MethodPost, "/api/tasks/7/chat/stop", bytes.NewBufferString(`{"seg":1}`))
	req.SetPathValue("id", "7")
	rec := httptest.NewRecorder()
	s.stopChat(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("stop seg 1: status=%d body=%s", rec.Code, rec.Body.String())
	}
	if !errors.Is(context.Cause(ctx1), agent.AbortChatStoppedByUser) {
		t.Fatalf("seg 1 not cancelled with user stop: %v", context.Cause(ctx1))
	}
	if ctx0.Err() != nil || ctxC.Err() != nil || ctxOther.Err() != nil {
		t.Fatal("stopping seg 1 cancelled unrelated lanes")
	}

	// Stop only consultation lane (-1).
	req = httptest.NewRequest(http.MethodPost, "/api/tasks/7/chat/stop", bytes.NewBufferString(`{"seg":-1}`))
	req.SetPathValue("id", "7")
	rec = httptest.NewRecorder()
	s.stopChat(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("stop consultation: status=%d body=%s", rec.Code, rec.Body.String())
	}
	if !errors.Is(context.Cause(ctxC), agent.AbortChatStoppedByUser) {
		t.Fatalf("consultation not cancelled: %v", context.Cause(ctxC))
	}
	if ctx0.Err() != nil || ctxOther.Err() != nil {
		t.Fatal("stopping consultation cancelled human seg 0 or task 71")
	}

	// Legacy stop without seg cancels remaining active lanes of task 7 only.
	req = httptest.NewRequest(http.MethodPost, "/api/tasks/7/chat/stop", bytes.NewBufferString(`{}`))
	req.SetPathValue("id", "7")
	rec = httptest.NewRecorder()
	s.stopChat(rec, req)
	if !errors.Is(context.Cause(ctx0), agent.AbortChatStoppedByUser) {
		t.Fatalf("legacy stop did not cancel seg 0: %v", context.Cause(ctx0))
	}
	if ctxOther.Err() != nil {
		t.Fatal("stopping task 7 cancelled task 71")
	}
}

func TestWaitTaskQuiescentWaitsForAllMainLanes(t *testing.T) {
	e := NewEngine(nil)
	seg1Ctx, seg1Cancel := context.WithCancelCause(context.Background())
	consultCtx, consultCancel := context.WithCancelCause(context.Background())
	otherKey := taskChatKey("71", 1)
	s := &Server{
		engine: e,
		chatBusy: map[string]bool{
			taskChatKey("7", 1): true,
			taskConsultKey("7"): true,
			otherKey:            true,
		},
		chatCancel: map[string]context.CancelCauseFunc{
			taskChatKey("7", 1): seg1Cancel,
			taskConsultKey("7"): consultCancel,
		},
	}

	if !s.cancelTaskChat("7", agent.AbortTaskDeleted) {
		t.Fatal("expected cancelTaskChat to cancel active seg 1 and consultation")
	}
	if seg1Ctx.Err() == nil || consultCtx.Err() == nil {
		t.Fatal("cancelTaskChat missed non-zero seg or consultation lane")
	}

	waitDone := make(chan error, 1)
	waitCtx, waitCancel := context.WithTimeout(context.Background(), time.Second)
	defer waitCancel()
	go func() { waitDone <- s.waitTaskQuiescent(waitCtx, "7") }()

	select {
	case err := <-waitDone:
		t.Fatalf("quiescent returned while seg 1 and consultation were busy: %v", err)
	case <-time.After(25 * time.Millisecond):
	}

	s.finishTaskChatLane(taskChatKey("7", 1), seg1Cancel)
	select {
	case err := <-waitDone:
		t.Fatalf("quiescent returned while consultation was still busy: %v", err)
	case <-time.After(25 * time.Millisecond):
	}

	s.finishTaskChatLane(taskConsultKey("7"), consultCancel)
	if err := <-waitDone; err != nil {
		t.Fatalf("waitTaskQuiescent failed after all lanes finished: %v", err)
	}
}

func TestParseActivitySessionSupportsConsultationLane(t *testing.T) {
	f, ok := parseActivitySession("main:-1")
	if !ok || !f.Main || f.MainSeg == nil || *f.MainSeg != db.MainSegConsultation {
		t.Fatalf("parseActivitySession(main:-1) = (%+v, %v), want consultation lane", f, ok)
	}
	if _, ok := parseActivitySession("main:-2"); ok {
		t.Fatal("parseActivitySession(main:-2) should fail")
	}
}
