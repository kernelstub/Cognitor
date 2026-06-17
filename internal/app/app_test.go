package app

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestCLIEndToEndFixture(t *testing.T) {
	dir := t.TempDir()
	oldDB := filepath.Join(dir, "old.db")
	newDB := filepath.Join(dir, "new.db")
	findingsDB := filepath.Join(dir, "findings.db")
	reportPath := filepath.Join(dir, "report.md")
	var out bytes.Buffer
	var errOut bytes.Buffer
	commands := [][]string{
		{"scan", "--snapshot", "old", "--path", "../../testdata/snapshots/old", "--out", oldDB},
		{"scan", "--snapshot", "new", "--path", "../../testdata/snapshots/new", "--out", newDB},
		{"diff", "--old", oldDB, "--new", newDB, "--out", findingsDB},
		{"report", "--db", findingsDB, "--format", "markdown", "--out", reportPath},
	}
	for _, args := range commands {
		if err := RunWithIO(context.Background(), args, &out, &errOut); err != nil {
			t.Fatalf("%v failed: %v stderr=%s", args, err, errOut.String())
		}
	}
	if !strings.Contains(out.String(), "diffed") {
		t.Fatalf("expected diff output, got %s", out.String())
	}
}

func TestCLIAnalyzeConvenienceFixture(t *testing.T) {
	dir := t.TempDir()
	reportPath := filepath.Join(dir, "report.md")
	var out bytes.Buffer
	var errOut bytes.Buffer
	args := []string{"analyze", "../../testdata/snapshots/old", "../../testdata/snapshots/new", "--workdir", dir, "--out", reportPath}
	if err := RunWithIO(context.Background(), args, &out, &errOut); err != nil {
		t.Fatalf("%v failed: %v stderr=%s", args, err, errOut.String())
	}
	if !strings.Contains(out.String(), "✓ done") {
		t.Fatalf("expected completion output, got %s", out.String())
	}
}

func TestCLICompareAliasFixture(t *testing.T) {
	dir := t.TempDir()
	var out bytes.Buffer
	var errOut bytes.Buffer
	args := []string{"compare", "../../testdata/snapshots/old", "../../testdata/snapshots/new", "--workdir", dir, "--all-formats"}
	if err := RunWithIO(context.Background(), args, &out, &errOut); err != nil {
		t.Fatalf("%v failed: %v stderr=%s", args, err, errOut.String())
	}
	if !strings.Contains(out.String(), "report    markdown · json · sarif · csv") {
		t.Fatalf("expected report output, got %s", out.String())
	}
	for _, name := range []string{"report.md", "report.json", "report.sarif", "report.csv", "findings.db", "cognitor-bundle.json"} {
		if _, err := os.Stat(filepath.Join(dir, name)); err != nil {
			t.Fatalf("missing %s: %v", name, err)
		}
	}
}

func TestCLICompareFocusDLLFixture(t *testing.T) {
	dir := t.TempDir()
	var out bytes.Buffer
	var errOut bytes.Buffer
	args := []string{"compare", "../../testdata/snapshots/old", "../../testdata/snapshots/new", "--workdir", dir, "--focus", "ntdll.dll"}
	if err := RunWithIO(context.Background(), args, &out, &errOut); err != nil {
		t.Fatalf("%v failed: %v stderr=%s", args, err, errOut.String())
	}
	report, err := os.ReadFile(filepath.Join(dir, "report.md"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(report), "ntdll.dll") {
		t.Fatalf("expected focused DLL report, got %s", string(report))
	}
	if strings.Contains(string(report), "driver.sys") {
		t.Fatalf("focused DLL report should not include driver.sys: %s", string(report))
	}
}
