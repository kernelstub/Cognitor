package cli

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/kernelstub/cognitor/pkg/model"
)

func TestEnrichIOCTLDecodesCTLCode(t *testing.T) {
	ioctl := enrichIOCTL(model.IOCTL{Code: "0x222003", Reachability: "noob"})
	if ioctl.Code != "0x222003" {
		t.Fatalf("enrich should not normalize code, got %q", ioctl.Code)
	}
	if ioctl.DeviceType != "0x0022" {
		t.Fatalf("expected device type 0x0022, got %q", ioctl.DeviceType)
	}
	if ioctl.Function != "0x800" {
		t.Fatalf("expected function 0x800, got %q", ioctl.Function)
	}
	if ioctl.Method != "METHOD_NEITHER" {
		t.Fatalf("expected METHOD_NEITHER, got %q", ioctl.Method)
	}
	if ioctl.Access != "FILE_ANY_ACCESS" {
		t.Fatalf("expected FILE_ANY_ACCESS, got %q", ioctl.Access)
	}
	for _, signal := range []string{"method-neither", "any-access", "low-privilege-reachable"} {
		if !contains(ioctl.RiskSignals, signal) {
			t.Fatalf("expected risk signal %q in %#v", signal, ioctl.RiskSignals)
		}
	}
}

func TestNormalizeLabIOCTLsMergesAndPadsCodes(t *testing.T) {
	values := normalizeLabIOCTLs([]model.IOCTL{
		{Code: "50", Handlers: []string{"A"}},
		{Code: "0x00000050", Device: "\\\\.\\X", Handlers: []string{"B"}},
	})
	if len(values) != 1 {
		t.Fatalf("expected one merged ioctl, got %#v", values)
	}
	if values[0].Code != "0x00000050" {
		t.Fatalf("expected padded code, got %q", values[0].Code)
	}
	if len(values[0].Handlers) != 2 {
		t.Fatalf("expected merged handlers, got %#v", values[0].Handlers)
	}
}

func TestDiffIOCTLInventoriesSignalsReachabilityAndAccessChanges(t *testing.T) {
	oldInv := map[string][]model.IOCTL{
		"driver.sys": {{Code: "0x222003", Reachability: "noob"}},
	}
	newInv := map[string][]model.IOCTL{
		"driver.sys": {{Code: "0x222003", Access: "FILE_READ_DATA", Reachability: "exp"}},
	}
	report := diffIOCTLInventories("old", "new", oldInv, newInv)
	if len(report.Changed) != 1 {
		t.Fatalf("expected one changed ioctl, got %#v", report)
	}
	if !contains(report.RiskSignals, "access-change:driver.sys:0x00222003") {
		t.Fatalf("expected access-change signal, got %#v", report.RiskSignals)
	}
	if !contains(report.RiskSignals, "reachability-change:driver.sys:0x00222003") {
		t.Fatalf("expected reachability-change signal, got %#v", report.RiskSignals)
	}
}

func TestParseReachabilityLog(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "zap.log")
	log := "persona=noob device=\\\\.\\X ioctl=0x00222003 ok=0 gle=5 returned=0\n" +
		"persona=exp device=\\\\.\\X ioctl=0x00222003 ok=1 gle=0 returned=8\n"
	if err := os.WriteFile(path, []byte(log), 0o644); err != nil {
		t.Fatal(err)
	}
	report, err := parseReachabilityLog(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(report.Records) != 2 {
		t.Fatalf("expected two records, got %#v", report)
	}
	if !contains(report.Reachable, "exp:0x00222003") {
		t.Fatalf("expected elevated reachability, got %#v", report.Reachable)
	}
	if !contains(report.Denied, "noob:0x00222003") {
		t.Fatalf("expected noob denial, got %#v", report.Denied)
	}
}

func TestBuildDossierReviewQueue(t *testing.T) {
	dossier := labDossier{
		PairAudit: pairAudit{Missing: []string{"missing.sys"}},
		SidecarAudit: sidecarAudit{
			ThinSidecars: []string{"thin.sys"},
		},
		IOCTLDiff: ioctlDiffReport{RiskSignals: []string{"access-change:driver.sys:0x00222003"}},
		Surface: surfaceReport{Targets: []surfaceEntry{{
			Binary:      "driver.sys",
			Score:       31,
			IOCTLCount:  1,
			RiskSignals: []string{"ioctl-method-neither"},
		}}},
	}
	queue := buildDossierReviewQueue(dossier)
	if len(queue) < 4 {
		t.Fatalf("expected combined queue entries, got %#v", queue)
	}
	if queue[0].Priority != "high" {
		t.Fatalf("expected high priority first, got %#v", queue)
	}
	if !contains(queue[0].Signals, "missing-prepatch-pair") && queue[0].Target != "access-change:driver.sys:0x00222003" && queue[0].Target != "driver.sys" {
		t.Fatalf("unexpected first queue item: %#v", queue[0])
	}
}

func TestLabDossierMarkdownIncludesSummary(t *testing.T) {
	dossier := labDossier{
		GeneratedAt:     "2026-06-17T00:00:00Z",
		OldSnapshot:     "old",
		NewSnapshot:     "new",
		PairAudit:       pairAudit{Matched: []string{"driver.sys"}},
		SidecarAudit:    sidecarAudit{BinaryCount: 1, SidecarCount: 1},
		Surface:         surfaceReport{Targets: []surfaceEntry{{Rank: 1, Binary: "driver.sys", Score: 31, RiskSignals: []string{"kernel-driver"}}}},
		RecommendedNext: []string{"Review the high-priority queue."},
	}
	md := labDossierMarkdown(dossier)
	for _, needle := range []string{"# Cognitor Lab Dossier", "## Summary", "driver.sys", "Review the high-priority queue."} {
		if !containsFold(md, needle) {
			t.Fatalf("expected markdown to contain %q:\n%s", needle, md)
		}
	}
}
