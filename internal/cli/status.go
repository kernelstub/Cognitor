package cli

import (
	"fmt"
	"io"
	"path/filepath"
	"strings"

	"github.com/kernelstub/cognitor/pkg/model"
)

const banner = ` _____ _____ _____ _____ _____ _____ _____ _____ 
|     |     |   __|   | |     |_   _|     | __  |
|   --|  |  |  |  | | | |-   -| | | |  |  |    -|
|_____|_____|_____|_|___|_____| |_| |_____|__|__|
`

type statusKind string

const (
	statusInfo     statusKind = "*"
	statusStep     statusKind = "-"
	statusSuccess  statusKind = "+"
	statusWarning  statusKind = "!"
	statusQuestion statusKind = "?"
)

func statusf(w io.Writer, kind statusKind, format string, args ...any) {
	_, _ = fmt.Fprintf(w, "[%s] %s\n", kind, fmt.Sprintf(format, args...))
}

func bannerf(w io.Writer) {
	_, _ = fmt.Fprint(w, banner)
	_, _ = fmt.Fprintf(w, "\ncognitor v%s\n", Version)
	_, _ = fmt.Fprintln(w, "kernelstub · github.com/kernelstub/cognitor")
	_, _ = fmt.Fprintln(w)
}

func dividerf(w io.Writer) {
	_, _ = fmt.Fprintln(w, "────────────────────────────────────────────────────")
}

func analyzeStartf(w io.Writer, oldPath string, newPath string, noBanner bool) {
	if !noBanner {
		bannerf(w)
	}
	dividerf(w)
	_, _ = fmt.Fprintf(w, "\n● scanning snapshots\n")
	_, _ = fmt.Fprintf(w, "  old  %s\n", oldPath)
	_, _ = fmt.Fprintf(w, "  new  %s\n", newPath)
}

func analyzeFocusf(w io.Writer, focus []string) {
	if len(focus) == 0 {
		return
	}
	_, _ = fmt.Fprintf(w, "\n? focus applied\n")
	_, _ = fmt.Fprintf(w, "  %s\n", strings.Join(focus, " · "))
}

func analyzeDonef(w io.Writer, findings int, changes model.ChangeSummary, report model.Report, dbPath string, outputs []string, manifestPath string) {
	_, _ = fmt.Fprintf(w, "\n● comparison complete\n")
	_, _ = fmt.Fprintf(w, "  %d %s · %d modified %s · %d changed %s\n",
		findings,
		plural(findings, "finding", "findings"),
		len(changes.ModifiedBinaries),
		plural(len(changes.ModifiedBinaries), "binary", "binaries"),
		len(changes.ChangedArtifacts),
		plural(len(changes.ChangedArtifacts), "artifact", "artifacts"),
	)
	_, _ = fmt.Fprintf(w, "\n▲ risk %s\n", report.Executive.RiskLevel)
	if report.Executive.Priority != "" {
		_, _ = fmt.Fprintf(w, "  %s recommended\n", report.Executive.Priority)
	}
	_, _ = fmt.Fprintf(w, "\n● outputs written\n")
	_, _ = fmt.Fprintf(w, "  db        %s\n", dbPath)
	_, _ = fmt.Fprintf(w, "  report    %s\n", reportSummary(outputs))
	_, _ = fmt.Fprintf(w, "  manifest  %s\n", manifestPath)
	_, _ = fmt.Fprintf(w, "\n✓ done\n")
}

func reportSummary(outputs []string) string {
	if len(outputs) == 0 {
		return "none"
	}
	formats := make([]string, 0, len(outputs))
	for _, output := range outputs {
		switch strings.ToLower(filepath.Ext(output)) {
		case ".md":
			formats = append(formats, "markdown")
		case ".json":
			formats = append(formats, "json")
		case ".sarif":
			formats = append(formats, "sarif")
		case ".csv":
			formats = append(formats, "csv")
		default:
			formats = append(formats, strings.TrimPrefix(strings.ToLower(filepath.Ext(output)), "."))
		}
	}
	return strings.Join(uniqueStrings(formats), " · ")
}

func uniqueStrings(values []string) []string {
	seen := map[string]struct{}{}
	out := make([]string, 0, len(values))
	for _, value := range values {
		if value == "" {
			continue
		}
		if _, ok := seen[value]; ok {
			continue
		}
		seen[value] = struct{}{}
		out = append(out, value)
	}
	return out
}

func plural(count int, singular string, pluralValue string) string {
	if count == 1 {
		return singular
	}
	return pluralValue
}
