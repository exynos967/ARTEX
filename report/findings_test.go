package report

import (
	"bytes"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/RC-CHN/ARTEX/db"
)

type errWriter struct {
	failAfter int
	written   int
	err       error
}

func (w *errWriter) Write(p []byte) (int, error) {
	if w.written >= w.failAfter {
		return 0, w.err
	}
	w.written += len(p)
	return len(p), nil
}

func sampleReportFindings() []*db.DBFinding {
	base := time.Date(2026, 5, 10, 14, 30, 0, 0, time.UTC)
	return []*db.DBFinding{
		{
			ID:                    10,
			Name:                  "反射型 XSS",
			VulnClass:             "XSS",
			Severity:              "medium",
			Status:                "confirmed",
			TaskDescription:       "目标站点常规扫描",
			Summary:               "搜索框存在未转义输出,含逗号,与\"引号\"",
			Evidence:              "<script>alert(1)</script>",
			Report:                "详细复现步骤与修复建议。",
			EvidenceVersion:       2,
			ReportEvidenceVersion: 1,
			CreatedAt:             base.Add(time.Minute),
			TrafficBindings: []db.FindingTrafficBinding{
				{
					ID:   101,
					Role: "poc",
					Note: "触发点\n第二行备注",
					Snapshot: db.TrafficEvidenceSnapshot{
						Method: "GET",
						URL:    "https://example.test/search?q=`test`",
						Status: 200,
					},
				},
			},
		},
		{
			ID:              20,
			Name:            "",
			VulnClass:       "SQLi",
			Severity:        "critical",
			Status:          "",
			TaskDescription: "核心接口专项测试",
			Summary:         "  登录接口存在布尔盲注  ",
			Evidence:        "' OR 1=1--",
			CreatedAt:       base,
		},
		{
			ID:        30,
			Severity:  "high",
			Status:    "pending",
			Summary:   "越权读取",
			CreatedAt: base.Add(2 * time.Minute),
		},
	}
}

func TestWriteFindingsMarkdownMatchesFindingsMarkdown(t *testing.T) {
	now := time.Date(2026, 5, 10, 15, 0, 0, 0, time.UTC)

	t.Run("empty", func(t *testing.T) {
		var buf bytes.Buffer
		if err := WriteFindingsMarkdown(&buf, nil, now); err != nil {
			t.Fatalf("WriteFindingsMarkdown empty: %v", err)
		}
		want := FindingsMarkdown(nil, now)
		if buf.String() != want {
			t.Fatalf("markdown mismatch for empty input:\ngot:\n%s\nwant:\n%s", buf.String(), want)
		}
		if !strings.Contains(want, "_无匹配的漏洞。_") {
			t.Fatalf("expected empty marker in %q", want)
		}
	})

	t.Run("populated", func(t *testing.T) {
		fs := sampleReportFindings()
		var buf bytes.Buffer
		if err := WriteFindingsMarkdown(&buf, fs, now); err != nil {
			t.Fatalf("WriteFindingsMarkdown populated: %v", err)
		}
		want := FindingsMarkdown(fs, now)
		if buf.String() != want {
			t.Fatalf("markdown mismatch:\ngot:\n%s\nwant:\n%s", buf.String(), want)
		}
		// Ensure input slice was not mutated by sorting.
		if fs[0].ID != 10 || fs[1].ID != 20 || fs[2].ID != 30 {
			t.Fatalf("input slice was mutated: ids=%d,%d,%d", fs[0].ID, fs[1].ID, fs[2].ID)
		}
	})

	t.Run("write error propagation", func(t *testing.T) {
		sentinel := errors.New("broken pipe")
		err := WriteFindingsMarkdown(&errWriter{failAfter: 16, err: sentinel}, sampleReportFindings(), now)
		if !errors.Is(err, sentinel) {
			t.Fatalf("err=%v, want %v", err, sentinel)
		}
	})
}

func TestWriteFindingsCSVMatchesFindingsCSV(t *testing.T) {
	t.Run("empty", func(t *testing.T) {
		var buf bytes.Buffer
		if err := WriteFindingsCSV(&buf, nil); err != nil {
			t.Fatalf("WriteFindingsCSV empty: %v", err)
		}
		want := FindingsCSV(nil)
		if !bytes.Equal(buf.Bytes(), want) {
			t.Fatalf("csv mismatch for empty input:\ngot:  %q\nwant: %q", buf.Bytes(), want)
		}
		if !bytes.HasPrefix(want, []byte("\xEF\xBB\xBF")) {
			t.Fatal("missing UTF-8 BOM")
		}
	})

	t.Run("populated", func(t *testing.T) {
		fs := sampleReportFindings()
		var buf bytes.Buffer
		if err := WriteFindingsCSV(&buf, fs); err != nil {
			t.Fatalf("WriteFindingsCSV populated: %v", err)
		}
		want := FindingsCSV(fs)
		if !bytes.Equal(buf.Bytes(), want) {
			t.Fatalf("csv mismatch:\ngot:\n%s\nwant:\n%s", buf.Bytes(), want)
		}
	})

	t.Run("write error propagation", func(t *testing.T) {
		sentinel := errors.New("disk full")
		err := WriteFindingsCSV(&errWriter{failAfter: 0, err: sentinel}, sampleReportFindings())
		if !errors.Is(err, sentinel) {
			t.Fatalf("err=%v, want %v", err, sentinel)
		}
	})
}
