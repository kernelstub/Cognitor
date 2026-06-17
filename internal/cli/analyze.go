package cli

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	sem "github.com/kernelstub/cognitor/internal/diff"
	"github.com/kernelstub/cognitor/internal/graph"
	"github.com/kernelstub/cognitor/internal/ingest"
	rep "github.com/kernelstub/cognitor/internal/report"
	"github.com/kernelstub/cognitor/internal/store"
	"github.com/kernelstub/cognitor/internal/util"
	"github.com/kernelstub/cognitor/pkg/model"
	"github.com/spf13/cobra"
)

func newAnalyzeCommand(streams ioStreams, configPath *string) *cobra.Command {
	var oldPath, newPath, workDir, format, reportOut, failOn string
	var focus []string
	var allFormats, noBanner bool
	cmd := &cobra.Command{
		Use:     "analyze [old snapshot directory] [new snapshot directory]",
		Aliases: []string{"compare", "patch-diff", "pdiff"},
		Short:   "Scan, diff, and report on old/new Windows snapshots in one step",
		Example: strings.Join([]string{
			"  cognitor analyze old new",
			"  cognitor compare C:\\cognitor-data\\old C:\\cognitor-data\\new --workdir C:\\cognitor-data\\out --all-formats",
			"  cognitor patch-diff --old ./old --new ./new --out report.md --fail-on high",
			"  cognitor compare ./old ./new --focus ntdll.dll",
			"  cognitor compare ./old ./new --focus \"*.dll\"",
		}, "\n"),
		RunE: func(cmd *cobra.Command, args []string) error {
			if len(args) == 2 {
				oldPath = args[0]
				newPath = args[1]
			}
			if oldPath == "" || newPath == "" {
				return fmt.Errorf("old and new snapshot directories are required; use `cognitor analyze OLD NEW`")
			}
			cfg, err := loadConfig(*configPath)
			if err != nil {
				return err
			}
			if format == "" {
				format = cfg.OutputFormat
			}
			if workDir == "" {
				workDir = "."
			}
			if err := os.MkdirAll(workDir, 0o755); err != nil {
				return err
			}
			if allFormats && reportOut != "" {
				info, err := os.Stat(reportOut)
				if err == nil && !info.IsDir() {
					return fmt.Errorf("--out must be a directory when --all-formats is used")
				}
				if err != nil && !os.IsNotExist(err) {
					return err
				}
			}

			analyzeStartf(streams.stdout, oldPath, newPath, noBanner)
			oldSnapshot, err := ingest.Scan(cmd.Context(), ingest.Options{Name: "old", Path: oldPath, Workers: cfg.Workers, StringMinLength: cfg.StringMinLength})
			if err != nil {
				return err
			}
			newSnapshot, err := ingest.Scan(cmd.Context(), ingest.Options{Name: "new", Path: newPath, Workers: cfg.Workers, StringMinLength: cfg.StringMinLength})
			if err != nil {
				return err
			}
			if len(focus) > 0 {
				oldSnapshot, newSnapshot, err = applyFocus(oldSnapshot, newSnapshot, focus)
				if err != nil {
					return err
				}
				analyzeFocusf(streams.stdout, focus)
			}
			findings := sem.Analyze(cmd.Context(), oldSnapshot, newSnapshot)
			changes := sem.SummarizeChanges(oldSnapshot, newSnapshot)
			graphModel := graph.Build(newSnapshot, findings)

			dbPath := filepath.Join(workDir, "findings.db")
			db, err := store.Open(dbPath)
			if err != nil {
				return err
			}
			defer db.Close()
			if err := db.SaveFindings(cmd.Context(), findings); err != nil {
				return err
			}
			if err := db.SaveChangeSummary(cmd.Context(), changes); err != nil {
				return err
			}
			if err := db.SaveGraph(cmd.Context(), graphModel); err != nil {
				return err
			}

			report := rep.BuildWithMetadata(findings, graphModel, model.ReportMetadata{
				GeneratedAt: util.NowUTC().Format("2006-01-02T15:04:05Z07:00"),
				ToolVersion: Version,
				OldSnapshot: snapshotBrief(oldSnapshot),
				NewSnapshot: snapshotBrief(newSnapshot),
			}, changes)
			outputs, err := writeAnalyzeReports(report, format, workDir, reportOut, allFormats)
			if err != nil {
				return err
			}
			manifestPath, err := writeBundleManifest(workDir, oldPath, newPath, dbPath, outputs, report)
			if err != nil {
				return err
			}
			analyzeDonef(streams.stdout, len(findings), changes, report, dbPath, outputs, manifestPath)
			if thresholdExceeded(findings, failOn) {
				return fmt.Errorf("policy gate failed: finding severity met or exceeded %q", failOn)
			}
			return nil
		},
	}
	cmd.Flags().StringVar(&oldPath, "old", "", "old snapshot directory")
	cmd.Flags().StringVar(&newPath, "new", "", "new snapshot directory")
	cmd.Flags().StringVar(&workDir, "workdir", ".", "directory for generated databases and default report output")
	cmd.Flags().StringVar(&format, "format", "", "report format: markdown, json, sarif, csv")
	cmd.Flags().StringVar(&reportOut, "out", "", "output report path, or output directory with --all-formats")
	cmd.Flags().BoolVar(&allFormats, "all-formats", false, "write markdown, JSON, SARIF, and CSV reports")
	cmd.Flags().BoolVar(&noBanner, "no-banner", false, "suppress the Cognitor ASCII banner")
	cmd.Flags().StringVar(&failOn, "fail-on", "", "exit non-zero when a finding reaches severity: low, medium, high")
	cmd.Flags().StringSliceVar(&focus, "focus", nil, "limit analysis to matching binary/artifact names or glob paths, for example ntdll.dll or *.dll")
	return cmd
}

func riskStatusKind(risk string) statusKind {
	switch strings.ToLower(risk) {
	case "critical", "high", "elevated":
		return statusWarning
	case "unknown":
		return statusQuestion
	default:
		return statusInfo
	}
}

func writeAnalyzeReports(report model.Report, format string, workDir string, out string, allFormats bool) ([]string, error) {
	if allFormats {
		outDir := out
		if outDir == "" {
			outDir = workDir
		}
		if err := os.MkdirAll(outDir, 0o755); err != nil {
			return nil, err
		}
		var outputs []string
		for _, f := range []string{"markdown", "json", "sarif", "csv"} {
			path := filepath.Join(outDir, defaultReportName(f))
			if err := writeAnalyzeReport(report, f, path); err != nil {
				return nil, err
			}
			outputs = append(outputs, path)
		}
		return outputs, nil
	}
	if out == "" {
		out = filepath.Join(workDir, defaultReportName(format))
	}
	return []string{out}, writeAnalyzeReport(report, format, out)
}

func writeAnalyzeReport(report model.Report, format string, path string) error {
	var (
		data []byte
		err  error
	)
	switch format {
	case "json":
		data, err = rep.JSON(report)
	case "sarif":
		data, err = rep.SARIF(report)
	case "markdown":
		data, err = rep.Markdown(report)
	case "csv":
		data, err = rep.CSV(report)
	default:
		return fmt.Errorf("unsupported report format %q", format)
	}
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	return os.WriteFile(path, data, 0o644)
}

func snapshotBrief(snapshot model.Snapshot) model.SnapshotBrief {
	return model.SnapshotBrief{
		Name:          snapshot.Name,
		Path:          snapshot.Path,
		BinaryCount:   len(snapshot.Binaries),
		ArtifactCount: len(snapshot.Artifacts),
		ServiceCount:  len(snapshot.Services),
		RegistryCount: len(snapshot.Registry),
	}
}

func applyFocus(oldSnapshot model.Snapshot, newSnapshot model.Snapshot, patterns []string) (model.Snapshot, model.Snapshot, error) {
	oldSnapshot.Binaries = filterBinaries(oldSnapshot.Binaries, patterns)
	newSnapshot.Binaries = filterBinaries(newSnapshot.Binaries, patterns)
	oldSnapshot.Artifacts = filterArtifacts(oldSnapshot.Artifacts, patterns)
	newSnapshot.Artifacts = filterArtifacts(newSnapshot.Artifacts, patterns)
	oldSnapshot.Services = filterServices(oldSnapshot.Services, patterns)
	newSnapshot.Services = filterServices(newSnapshot.Services, patterns)
	oldSnapshot.Registry = filterRegistry(oldSnapshot.Registry, patterns)
	newSnapshot.Registry = filterRegistry(newSnapshot.Registry, patterns)
	if len(oldSnapshot.Binaries)+len(newSnapshot.Binaries)+len(oldSnapshot.Artifacts)+len(newSnapshot.Artifacts) == 0 {
		return oldSnapshot, newSnapshot, fmt.Errorf("focus patterns matched no binaries or artifacts: %s", strings.Join(patterns, ", "))
	}
	return oldSnapshot, newSnapshot, nil
}

func filterBinaries(values []model.Binary, patterns []string) []model.Binary {
	var out []model.Binary
	for _, value := range values {
		if focusMatch(value.Path, value.Name, patterns) {
			out = append(out, value)
		}
	}
	return out
}

func filterArtifacts(values []model.Artifact, patterns []string) []model.Artifact {
	var out []model.Artifact
	for _, value := range values {
		if focusMatch(value.Path, value.Name, patterns) {
			out = append(out, value)
		}
	}
	return out
}

func filterServices(values []model.Service, patterns []string) []model.Service {
	var out []model.Service
	for _, value := range values {
		if focusMatch(value.Name, value.BinaryPath, patterns) {
			out = append(out, value)
		}
	}
	return out
}

func filterRegistry(values []model.RegistryKey, patterns []string) []model.RegistryKey {
	var out []model.RegistryKey
	for _, value := range values {
		if focusMatch(value.Path, value.Description, patterns) {
			out = append(out, value)
		}
	}
	return out
}

func focusMatch(path string, name string, patterns []string) bool {
	candidates := []string{strings.ToLower(filepath.ToSlash(path)), strings.ToLower(name)}
	for _, pattern := range patterns {
		pattern = strings.ToLower(filepath.ToSlash(strings.TrimSpace(pattern)))
		if pattern == "" {
			continue
		}
		for _, candidate := range candidates {
			if candidate == pattern || strings.Contains(candidate, pattern) {
				return true
			}
			if ok, _ := filepath.Match(pattern, candidate); ok {
				return true
			}
			if ok, _ := filepath.Match(pattern, filepath.Base(candidate)); ok {
				return true
			}
		}
	}
	return false
}

type bundleManifest struct {
	GeneratedAt string              `json:"generated_at"`
	ToolVersion string              `json:"tool_version"`
	OldPath     string              `json:"old_path"`
	NewPath     string              `json:"new_path"`
	RiskLevel   string              `json:"risk_level"`
	Priority    string              `json:"priority"`
	Outputs     []bundleManifestRef `json:"outputs"`
}

type bundleManifestRef struct {
	Kind   string `json:"kind"`
	Path   string `json:"path"`
	SHA256 string `json:"sha256"`
}

func writeBundleManifest(workDir string, oldPath string, newPath string, dbPath string, outputs []string, report model.Report) (string, error) {
	manifest := bundleManifest{
		GeneratedAt: report.Metadata.GeneratedAt,
		ToolVersion: report.Metadata.ToolVersion,
		OldPath:     oldPath,
		NewPath:     newPath,
		RiskLevel:   report.Executive.RiskLevel,
		Priority:    report.Executive.Priority,
	}
	for _, output := range append([]string{dbPath}, outputs...) {
		sha, err := util.FileSHA256(output)
		if err != nil {
			return "", err
		}
		manifest.Outputs = append(manifest.Outputs, bundleManifestRef{
			Kind:   outputKind(output),
			Path:   output,
			SHA256: sha,
		})
	}
	data, err := json.MarshalIndent(manifest, "", "  ")
	if err != nil {
		return "", err
	}
	path := filepath.Join(workDir, "cognitor-bundle.json")
	if err := os.WriteFile(path, append(data, '\n'), 0o644); err != nil {
		return "", err
	}
	return path, nil
}

func outputKind(path string) string {
	switch strings.ToLower(filepath.Ext(path)) {
	case ".db":
		return "sqlite"
	case ".md":
		return "markdown"
	case ".json":
		return "json"
	case ".sarif":
		return "sarif"
	case ".csv":
		return "csv"
	default:
		return "artifact"
	}
}

func thresholdExceeded(findings []model.Finding, threshold string) bool {
	if threshold == "" {
		return false
	}
	minRank := severityRank(threshold)
	if minRank == 0 {
		return false
	}
	for _, finding := range findings {
		if severityRank(finding.Severity) >= minRank {
			return true
		}
	}
	return false
}

func severityRank(severity string) int {
	switch strings.ToLower(severity) {
	case "low":
		return 1
	case "medium":
		return 2
	case "high":
		return 3
	default:
		return 0
	}
}

func defaultReportName(format string) string {
	switch format {
	case "json":
		return "report.json"
	case "sarif":
		return "report.sarif"
	case "csv":
		return "report.csv"
	default:
		return "report.md"
	}
}
