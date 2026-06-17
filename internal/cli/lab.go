package cli

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"github.com/kernelstub/cognitor/internal/ingest"
	"github.com/kernelstub/cognitor/internal/util"
	"github.com/kernelstub/cognitor/pkg/model"
	"github.com/spf13/cobra"
)

type pairAudit struct {
	PrepatchDir string   `json:"prepatch_dir"`
	PatchedDir  string   `json:"patched_dir"`
	Extension   string   `json:"extension"`
	Matched     []string `json:"matched"`
	Missing     []string `json:"missing"`
	Extra       []string `json:"extra"`
}

type sidecarAudit struct {
	SnapshotDir      string         `json:"snapshot_dir"`
	BinaryCount      int            `json:"binary_count"`
	SidecarCount     int            `json:"sidecar_count"`
	IOCTLBinaryCount int            `json:"ioctl_binary_count"`
	MissingSidecars  []string       `json:"missing_sidecars"`
	ThinSidecars     []string       `json:"thin_sidecars"`
	IOCTLsByBinary   map[string]int `json:"ioctls_by_binary"`
}

type crashRecord struct {
	Driver   string   `json:"driver"`
	Bugcheck string   `json:"bugcheck"`
	Dump     string   `json:"dump"`
	IOCTL    string   `json:"ioctl,omitempty"`
	Persona  string   `json:"persona,omitempty"`
	Inputs   []string `json:"inputs,omitempty"`
	Notes    string   `json:"notes,omitempty"`
}

type ioctlDiffReport struct {
	OldSnapshot string              `json:"old_snapshot"`
	NewSnapshot string              `json:"new_snapshot"`
	Added       []ioctlDiffEntry    `json:"added"`
	Removed     []ioctlDiffEntry    `json:"removed"`
	Changed     []ioctlChangeRecord `json:"changed"`
	RiskSignals []string            `json:"risk_signals"`
}

type ioctlDiffEntry struct {
	Binary string      `json:"binary"`
	IOCTL  model.IOCTL `json:"ioctl"`
}

type ioctlChangeRecord struct {
	Binary string      `json:"binary"`
	Code   string      `json:"code"`
	Old    model.IOCTL `json:"old"`
	New    model.IOCTL `json:"new"`
}

type reachabilityRecord struct {
	Persona   string `json:"persona"`
	Device    string `json:"device"`
	IOCTL     string `json:"ioctl"`
	OK        bool   `json:"ok"`
	LastError string `json:"last_error"`
	Returned  string `json:"returned"`
}

type reachabilityReport struct {
	LogPath   string               `json:"log_path"`
	Records   []reachabilityRecord `json:"records"`
	ByPersona map[string]int       `json:"by_persona"`
	Reachable []string             `json:"reachable"`
	Denied    []string             `json:"denied"`
}

type surfaceReport struct {
	SnapshotDir string         `json:"snapshot_dir"`
	Targets     []surfaceEntry `json:"targets"`
	Summary     surfaceSummary `json:"summary"`
}

type surfaceSummary struct {
	BinaryCount     int `json:"binary_count"`
	DriverCount     int `json:"driver_count"`
	IOCTLCount      int `json:"ioctl_count"`
	HighRiskTargets int `json:"high_risk_targets"`
}

type surfaceEntry struct {
	Rank             int           `json:"rank"`
	Binary           string        `json:"binary"`
	Kind             string        `json:"kind"`
	Score            int           `json:"score"`
	IOCTLCount       int           `json:"ioctl_count"`
	RiskSignals      []string      `json:"risk_signals"`
	ReviewFocus      []string      `json:"review_focus"`
	InterestingAPIs  []string      `json:"interesting_apis"`
	InterestingText  []string      `json:"interesting_text"`
	RiskyIOCTLs      []model.IOCTL `json:"risky_ioctls"`
	SidecarFunctions int           `json:"sidecar_functions"`
}

type labDossier struct {
	GeneratedAt     string              `json:"generated_at"`
	OldSnapshot     string              `json:"old_snapshot"`
	NewSnapshot     string              `json:"new_snapshot"`
	PairAudit       pairAudit           `json:"pair_audit"`
	SidecarAudit    sidecarAudit        `json:"sidecar_audit"`
	IOCTLDiff       ioctlDiffReport     `json:"ioctl_diff"`
	Surface         surfaceReport       `json:"surface"`
	Reachability    *reachabilityReport `json:"reachability,omitempty"`
	CrashFindings   []model.Finding     `json:"crash_findings,omitempty"`
	ReviewQueue     []dossierReview     `json:"review_queue"`
	RecommendedNext []string            `json:"recommended_next"`
}

type dossierReview struct {
	Priority string   `json:"priority"`
	Target   string   `json:"target"`
	Reason   string   `json:"reason"`
	Signals  []string `json:"signals,omitempty"`
}

func newLabCommand(streams ioStreams, configPath *string) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "lab",
		Short: "Lab automation for driver sidecars, IOCTL inventories, A/B checks, and crash intake",
	}
	cmd.AddCommand(newLabPairsCommand(streams))
	cmd.AddCommand(newLabSidecarsCommand(streams, configPath))
	cmd.AddCommand(newLabIOCTLsCommand(streams, configPath))
	cmd.AddCommand(newLabDiffIOCTLsCommand(streams, configPath))
	cmd.AddCommand(newLabReachabilityCommand(streams))
	cmd.AddCommand(newLabSurfaceCommand(streams, configPath))
	cmd.AddCommand(newLabCrashesCommand(streams))
	cmd.AddCommand(newLabDossierCommand(streams, configPath))
	return cmd
}

func newLabPairsCommand(streams ioStreams) *cobra.Command {
	var prepatchDir, patchedDir, ext, out string
	cmd := &cobra.Command{
		Use:   "pairs --prepatch DIR --patched DIR",
		Short: "Audit patched drivers that do not have a prepatch pair",
		RunE: func(cmd *cobra.Command, args []string) error {
			if prepatchDir == "" || patchedDir == "" {
				return fmt.Errorf("--prepatch and --patched are required")
			}
			audit, err := auditPairs(prepatchDir, patchedDir, ext)
			if err != nil {
				return err
			}
			data, err := json.MarshalIndent(audit, "", "  ")
			if err != nil {
				return err
			}
			if out != "" {
				if err := writeJSON(out, data); err != nil {
					return err
				}
			}
			_, _ = fmt.Fprintf(streams.stdout, "%s\n", data)
			if len(audit.Missing) > 0 {
				return fmt.Errorf("%d patched files have no prepatch pair", len(audit.Missing))
			}
			return nil
		},
	}
	cmd.Flags().StringVar(&prepatchDir, "prepatch", "", "directory containing prepatch drivers")
	cmd.Flags().StringVar(&patchedDir, "patched", "", "directory containing patched drivers")
	cmd.Flags().StringVar(&ext, "ext", ".sys", "file extension to pair")
	cmd.Flags().StringVar(&out, "out", "", "optional JSON output path")
	return cmd
}

func newLabSidecarsCommand(streams ioStreams, configPath *string) *cobra.Command {
	var snapshotDir, out string
	cmd := &cobra.Command{
		Use:   "sidecars --snapshot DIR",
		Short: "Audit Cognitor analysis sidecar coverage and thin sidecars",
		RunE: func(cmd *cobra.Command, args []string) error {
			if snapshotDir == "" && len(args) == 1 {
				snapshotDir = args[0]
			}
			if snapshotDir == "" {
				return fmt.Errorf("--snapshot is required")
			}
			cfg, err := loadConfig(*configPath)
			if err != nil {
				return err
			}
			snapshot, err := ingest.Scan(cmd.Context(), ingest.Options{Name: "lab", Path: snapshotDir, Workers: cfg.Workers, StringMinLength: cfg.StringMinLength})
			if err != nil {
				return err
			}
			audit := auditSidecars(snapshot, snapshotDir)
			data, err := json.MarshalIndent(audit, "", "  ")
			if err != nil {
				return err
			}
			if out != "" {
				if err := writeJSON(out, data); err != nil {
					return err
				}
			}
			_, _ = fmt.Fprintf(streams.stdout, "%s\n", data)
			return nil
		},
	}
	cmd.Flags().StringVar(&snapshotDir, "snapshot", "", "snapshot directory containing drivers and .analysis.json sidecars")
	cmd.Flags().StringVar(&out, "out", "", "optional JSON output path")
	return cmd
}

func newLabIOCTLsCommand(streams ioStreams, configPath *string) *cobra.Command {
	var snapshotDir, out string
	cmd := &cobra.Command{
		Use:   "ioctls --snapshot DIR --out ioctl.json",
		Short: "Build a normalized IOCTL inventory from sidecars and driver strings",
		RunE: func(cmd *cobra.Command, args []string) error {
			if snapshotDir == "" && len(args) == 1 {
				snapshotDir = args[0]
			}
			if snapshotDir == "" {
				return fmt.Errorf("--snapshot is required")
			}
			cfg, err := loadConfig(*configPath)
			if err != nil {
				return err
			}
			snapshot, err := ingest.Scan(cmd.Context(), ingest.Options{Name: "lab", Path: snapshotDir, Workers: cfg.Workers, StringMinLength: cfg.StringMinLength})
			if err != nil {
				return err
			}
			inventory := buildIOCTLInventory(snapshot)
			data, err := json.MarshalIndent(inventory, "", "  ")
			if err != nil {
				return err
			}
			if out != "" {
				if err := writeJSON(out, data); err != nil {
					return err
				}
			}
			_, _ = fmt.Fprintf(streams.stdout, "%s\n", data)
			return nil
		},
	}
	cmd.Flags().StringVar(&snapshotDir, "snapshot", "", "snapshot directory containing drivers and .analysis.json sidecars")
	cmd.Flags().StringVar(&out, "out", "ioctl.json", "JSON output path")
	return cmd
}

func newLabDiffIOCTLsCommand(streams ioStreams, configPath *string) *cobra.Command {
	var oldDir, newDir, out string
	cmd := &cobra.Command{
		Use:   "diff-ioctls --old DIR --new DIR",
		Short: "Compare old/new IOCTL inventories and surface changed reachability or validation metadata",
		RunE: func(cmd *cobra.Command, args []string) error {
			if oldDir == "" || newDir == "" {
				return fmt.Errorf("--old and --new are required")
			}
			cfg, err := loadConfig(*configPath)
			if err != nil {
				return err
			}
			oldSnapshot, err := ingest.Scan(cmd.Context(), ingest.Options{Name: "old", Path: oldDir, Workers: cfg.Workers, StringMinLength: cfg.StringMinLength})
			if err != nil {
				return err
			}
			newSnapshot, err := ingest.Scan(cmd.Context(), ingest.Options{Name: "new", Path: newDir, Workers: cfg.Workers, StringMinLength: cfg.StringMinLength})
			if err != nil {
				return err
			}
			report := diffIOCTLInventories(oldDir, newDir, buildIOCTLInventory(oldSnapshot), buildIOCTLInventory(newSnapshot))
			data, err := json.MarshalIndent(report, "", "  ")
			if err != nil {
				return err
			}
			if out != "" {
				if err := writeJSON(out, data); err != nil {
					return err
				}
			}
			_, _ = fmt.Fprintf(streams.stdout, "%s\n", data)
			return nil
		},
	}
	cmd.Flags().StringVar(&oldDir, "old", "", "old snapshot directory")
	cmd.Flags().StringVar(&newDir, "new", "", "new snapshot directory")
	cmd.Flags().StringVar(&out, "out", "ioctl-diff.json", "JSON output path")
	return cmd
}

func newLabReachabilityCommand(streams ioStreams) *cobra.Command {
	var logPath, out string
	cmd := &cobra.Command{
		Use:   "reachability --log ioctl_zap.log",
		Short: "Parse ioctl_zap output into structured noob/elevated reachability evidence",
		RunE: func(cmd *cobra.Command, args []string) error {
			if logPath == "" && len(args) == 1 {
				logPath = args[0]
			}
			if logPath == "" {
				return fmt.Errorf("--log is required")
			}
			report, err := parseReachabilityLog(logPath)
			if err != nil {
				return err
			}
			data, err := json.MarshalIndent(report, "", "  ")
			if err != nil {
				return err
			}
			if out != "" {
				if err := writeJSON(out, data); err != nil {
					return err
				}
			}
			_, _ = fmt.Fprintf(streams.stdout, "%s\n", data)
			return nil
		},
	}
	cmd.Flags().StringVar(&logPath, "log", "", "ioctl_zap output log")
	cmd.Flags().StringVar(&out, "out", "reachability.json", "JSON output path")
	return cmd
}

func newLabSurfaceCommand(streams ioStreams, configPath *string) *cobra.Command {
	var snapshotDir, out string
	var limit int
	cmd := &cobra.Command{
		Use:   "surface --snapshot DIR",
		Short: "Rank driver attack surface for defensive research triage",
		RunE: func(cmd *cobra.Command, args []string) error {
			if snapshotDir == "" && len(args) == 1 {
				snapshotDir = args[0]
			}
			if snapshotDir == "" {
				return fmt.Errorf("--snapshot is required")
			}
			cfg, err := loadConfig(*configPath)
			if err != nil {
				return err
			}
			snapshot, err := ingest.Scan(cmd.Context(), ingest.Options{Name: "lab", Path: snapshotDir, Workers: cfg.Workers, StringMinLength: cfg.StringMinLength})
			if err != nil {
				return err
			}
			report := buildSurfaceReport(snapshotDir, snapshot, limit)
			data, err := json.MarshalIndent(report, "", "  ")
			if err != nil {
				return err
			}
			if out != "" {
				if err := writeJSON(out, data); err != nil {
					return err
				}
			}
			_, _ = fmt.Fprintf(streams.stdout, "%s\n", data)
			return nil
		},
	}
	cmd.Flags().StringVar(&snapshotDir, "snapshot", "", "snapshot directory to rank")
	cmd.Flags().StringVar(&out, "out", "surface.json", "JSON output path")
	cmd.Flags().IntVar(&limit, "limit", 25, "maximum targets to include")
	return cmd
}

func newLabCrashesCommand(streams ioStreams) *cobra.Command {
	var crashesPath, out string
	cmd := &cobra.Command{
		Use:   "crashes --manifest crashes.json --out crash-findings.json",
		Short: "Convert pulled crash/bugcheck manifests into Cognitor finding seeds",
		RunE: func(cmd *cobra.Command, args []string) error {
			if crashesPath == "" {
				return fmt.Errorf("--manifest is required")
			}
			data, err := os.ReadFile(crashesPath)
			if err != nil {
				return err
			}
			var crashes []crashRecord
			if err := json.Unmarshal(data, &crashes); err != nil {
				return err
			}
			findings := crashFindings(crashes)
			result, err := json.MarshalIndent(findings, "", "  ")
			if err != nil {
				return err
			}
			if out != "" {
				if err := writeJSON(out, result); err != nil {
					return err
				}
			}
			_, _ = fmt.Fprintf(streams.stdout, "%s\n", result)
			return nil
		},
	}
	cmd.Flags().StringVar(&crashesPath, "manifest", "", "JSON manifest produced by scripts/lab/crash_pull.ps1")
	cmd.Flags().StringVar(&out, "out", "crash-findings.json", "JSON output path")
	return cmd
}

func newLabDossierCommand(streams ioStreams, configPath *string) *cobra.Command {
	var oldDir, newDir, out, markdownOut, reachabilityLog, crashesPath string
	var limit int
	cmd := &cobra.Command{
		Use:   "dossier --old DIR --new DIR",
		Short: "Build a combined driver research dossier from lab artifacts",
		RunE: func(cmd *cobra.Command, args []string) error {
			if oldDir == "" || newDir == "" {
				return fmt.Errorf("--old and --new are required")
			}
			cfg, err := loadConfig(*configPath)
			if err != nil {
				return err
			}
			oldSnapshot, err := ingest.Scan(cmd.Context(), ingest.Options{Name: "old", Path: oldDir, Workers: cfg.Workers, StringMinLength: cfg.StringMinLength})
			if err != nil {
				return err
			}
			newSnapshot, err := ingest.Scan(cmd.Context(), ingest.Options{Name: "new", Path: newDir, Workers: cfg.Workers, StringMinLength: cfg.StringMinLength})
			if err != nil {
				return err
			}
			dossier, err := buildLabDossier(oldDir, newDir, oldSnapshot, newSnapshot, reachabilityLog, crashesPath, limit)
			if err != nil {
				return err
			}
			data, err := json.MarshalIndent(dossier, "", "  ")
			if err != nil {
				return err
			}
			if out != "" {
				if err := writeJSON(out, data); err != nil {
					return err
				}
			}
			if markdownOut != "" {
				if err := writeText(markdownOut, labDossierMarkdown(dossier)); err != nil {
					return err
				}
			}
			_, _ = fmt.Fprintf(streams.stdout, "%s\n", data)
			return nil
		},
	}
	cmd.Flags().StringVar(&oldDir, "old", "", "old/prepatch snapshot directory")
	cmd.Flags().StringVar(&newDir, "new", "", "new/patched snapshot directory")
	cmd.Flags().StringVar(&out, "out", "lab-dossier.json", "JSON output path")
	cmd.Flags().StringVar(&markdownOut, "markdown", "lab-dossier.md", "Markdown output path")
	cmd.Flags().StringVar(&reachabilityLog, "reachability-log", "", "optional ioctl_zap log to include")
	cmd.Flags().StringVar(&crashesPath, "crashes", "", "optional crashes.json manifest to include")
	cmd.Flags().IntVar(&limit, "limit", 10, "maximum surface targets in the review queue")
	return cmd
}

func auditPairs(prepatchDir, patchedDir, ext string) (pairAudit, error) {
	oldFiles, err := namedFiles(prepatchDir, ext)
	if err != nil {
		return pairAudit{}, err
	}
	newFiles, err := namedFiles(patchedDir, ext)
	if err != nil {
		return pairAudit{}, err
	}
	audit := pairAudit{PrepatchDir: prepatchDir, PatchedDir: patchedDir, Extension: ext}
	for name := range newFiles {
		if _, ok := oldFiles[name]; ok {
			audit.Matched = append(audit.Matched, name)
		} else {
			audit.Missing = append(audit.Missing, name)
		}
	}
	for name := range oldFiles {
		if _, ok := newFiles[name]; !ok {
			audit.Extra = append(audit.Extra, name)
		}
	}
	sort.Strings(audit.Matched)
	sort.Strings(audit.Missing)
	sort.Strings(audit.Extra)
	return audit, nil
}

func namedFiles(root, ext string) (map[string]string, error) {
	out := map[string]string{}
	err := filepath.WalkDir(root, func(path string, entry os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if entry.IsDir() {
			return nil
		}
		if ext == "" || strings.EqualFold(filepath.Ext(path), ext) {
			out[strings.ToLower(entry.Name())] = path
		}
		return nil
	})
	return out, err
}

func auditSidecars(snapshot model.Snapshot, root string) sidecarAudit {
	audit := sidecarAudit{SnapshotDir: root, BinaryCount: len(snapshot.Binaries), IOCTLsByBinary: map[string]int{}}
	for _, binary := range snapshot.Binaries {
		sidecar := filepath.Join(root, filepath.FromSlash(binary.Path)) + ".analysis.json"
		if _, err := os.Stat(sidecar); err != nil {
			audit.MissingSidecars = append(audit.MissingSidecars, binary.Path)
			continue
		}
		audit.SidecarCount++
		if len(binary.Functions) < 2 && len(binary.IOCTLs) == 0 {
			audit.ThinSidecars = append(audit.ThinSidecars, binary.Path)
		}
		if len(binary.IOCTLs) > 0 {
			audit.IOCTLBinaryCount++
			audit.IOCTLsByBinary[binary.Path] = len(binary.IOCTLs)
		}
	}
	sort.Strings(audit.MissingSidecars)
	sort.Strings(audit.ThinSidecars)
	return audit
}

func buildIOCTLInventory(snapshot model.Snapshot) map[string][]model.IOCTL {
	out := map[string][]model.IOCTL{}
	for _, binary := range snapshot.Binaries {
		ioctls := append([]model.IOCTL{}, binary.IOCTLs...)
		ioctls = append(ioctls, inferIOCTLs(binary)...)
		ioctls = normalizeLabIOCTLs(ioctls)
		sort.Slice(ioctls, func(i, j int) bool { return ioctls[i].Code < ioctls[j].Code })
		out[binary.Path] = ioctls
	}
	return out
}

var ioctlPattern = regexp.MustCompile(`(?i)\b(?:0x)?[0-9a-f]{4,8}\b`)

func inferIOCTLs(binary model.Binary) []model.IOCTL {
	seen := map[string]model.IOCTL{}
	for _, fn := range binary.Functions {
		values := append([]string{}, fn.Strings...)
		values = append(values, fn.Operations...)
		for _, value := range values {
			lower := strings.ToLower(value)
			if !strings.Contains(lower, "ioctl") && !strings.Contains(lower, "ctl_code") && !strings.Contains(lower, "device_control") {
				continue
			}
			for _, raw := range ioctlPattern.FindAllString(value, -1) {
				code := strings.ToLower(raw)
				if !strings.HasPrefix(code, "0x") {
					code = "0x" + code
				}
				entry := seen[code]
				entry.Code = code
				entry.Source = "inferred"
				entry.Handlers = append(entry.Handlers, fn.Name)
				seen[code] = entry
			}
		}
	}
	out := make([]model.IOCTL, 0, len(seen))
	for _, value := range seen {
		value.Handlers = unique(value.Handlers)
		out = append(out, value)
	}
	return out
}

func normalizeLabIOCTLs(values []model.IOCTL) []model.IOCTL {
	seen := map[string]model.IOCTL{}
	for _, value := range values {
		value.Code = normalizeIOCTLCode(value.Code)
		if value.Code == "" {
			continue
		}
		value = enrichIOCTL(value)
		existing, ok := seen[value.Code]
		if !ok {
			value.Handlers = unique(value.Handlers)
			value.RiskSignals = unique(value.RiskSignals)
			seen[value.Code] = value
			continue
		}
		existing.Handlers = unique(append(existing.Handlers, value.Handlers...))
		existing.RiskSignals = unique(append(existing.RiskSignals, value.RiskSignals...))
		if existing.Name == "" {
			existing.Name = value.Name
		}
		if existing.Device == "" {
			existing.Device = value.Device
		}
		if existing.DeviceType == "" {
			existing.DeviceType = value.DeviceType
		}
		if existing.Method == "" {
			existing.Method = value.Method
		}
		if existing.Access == "" {
			existing.Access = value.Access
		}
		if existing.Function == "" {
			existing.Function = value.Function
		}
		if existing.Reachability == "" {
			existing.Reachability = value.Reachability
		}
		if existing.Source == "" {
			existing.Source = value.Source
		}
		seen[value.Code] = existing
	}
	out := make([]model.IOCTL, 0, len(seen))
	for _, value := range seen {
		out = append(out, value)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Code < out[j].Code })
	return out
}

func enrichIOCTL(value model.IOCTL) model.IOCTL {
	code, ok := parseIOCTLCode(value.Code)
	if !ok {
		return value
	}
	if value.DeviceType == "" {
		value.DeviceType = fmt.Sprintf("0x%04x", (code>>16)&0xffff)
	}
	if value.Function == "" {
		value.Function = fmt.Sprintf("0x%03x", (code>>2)&0x0fff)
	}
	if value.Method == "" {
		value.Method = methodName(code & 0x3)
	}
	if value.Access == "" {
		value.Access = accessName((code >> 14) & 0x3)
	}
	if value.Method == "METHOD_NEITHER" {
		value.RiskSignals = append(value.RiskSignals, "method-neither")
	}
	if value.Access == "FILE_ANY_ACCESS" {
		value.RiskSignals = append(value.RiskSignals, "any-access")
	}
	if strings.EqualFold(value.Reachability, "noob") {
		value.RiskSignals = append(value.RiskSignals, "low-privilege-reachable")
	}
	value.RiskSignals = unique(value.RiskSignals)
	return value
}

func normalizeIOCTLCode(raw string) string {
	raw = strings.TrimSpace(strings.ToLower(raw))
	raw = strings.Trim(raw, "\"'")
	if raw == "" {
		return ""
	}
	if !strings.HasPrefix(raw, "0x") {
		raw = "0x" + raw
	}
	code, ok := parseIOCTLCode(raw)
	if !ok {
		return ""
	}
	return fmt.Sprintf("0x%08x", code)
}

func parseIOCTLCode(raw string) (uint32, bool) {
	raw = strings.TrimSpace(strings.ToLower(raw))
	raw = strings.TrimPrefix(raw, "0x")
	if raw == "" {
		return 0, false
	}
	var value uint32
	if _, err := fmt.Sscanf(raw, "%x", &value); err != nil {
		return 0, false
	}
	return value, true
}

func methodName(value uint32) string {
	switch value {
	case 0:
		return "METHOD_BUFFERED"
	case 1:
		return "METHOD_IN_DIRECT"
	case 2:
		return "METHOD_OUT_DIRECT"
	case 3:
		return "METHOD_NEITHER"
	default:
		return ""
	}
}

func accessName(value uint32) string {
	switch value {
	case 0:
		return "FILE_ANY_ACCESS"
	case 1:
		return "FILE_READ_DATA"
	case 2:
		return "FILE_WRITE_DATA"
	case 3:
		return "FILE_READ_DATA|FILE_WRITE_DATA"
	default:
		return ""
	}
}

func diffIOCTLInventories(oldDir, newDir string, oldInv, newInv map[string][]model.IOCTL) ioctlDiffReport {
	report := ioctlDiffReport{OldSnapshot: oldDir, NewSnapshot: newDir}
	allBinaries := map[string]struct{}{}
	for binary := range oldInv {
		allBinaries[binary] = struct{}{}
	}
	for binary := range newInv {
		allBinaries[binary] = struct{}{}
	}
	for binary := range allBinaries {
		oldByCode := ioctlsByCode(oldInv[binary])
		newByCode := ioctlsByCode(newInv[binary])
		for code, oldValue := range oldByCode {
			newValue, ok := newByCode[code]
			if !ok {
				report.Removed = append(report.Removed, ioctlDiffEntry{Binary: binary, IOCTL: oldValue})
				continue
			}
			if ioctlChanged(oldValue, newValue) {
				report.Changed = append(report.Changed, ioctlChangeRecord{Binary: binary, Code: code, Old: oldValue, New: newValue})
			}
		}
		for code, newValue := range newByCode {
			if _, ok := oldByCode[code]; !ok {
				report.Added = append(report.Added, ioctlDiffEntry{Binary: binary, IOCTL: newValue})
			}
		}
	}
	sort.Slice(report.Added, func(i, j int) bool {
		return report.Added[i].Binary+report.Added[i].IOCTL.Code < report.Added[j].Binary+report.Added[j].IOCTL.Code
	})
	sort.Slice(report.Removed, func(i, j int) bool {
		return report.Removed[i].Binary+report.Removed[i].IOCTL.Code < report.Removed[j].Binary+report.Removed[j].IOCTL.Code
	})
	sort.Slice(report.Changed, func(i, j int) bool {
		return report.Changed[i].Binary+report.Changed[i].Code < report.Changed[j].Binary+report.Changed[j].Code
	})
	report.RiskSignals = ioctlDiffSignals(report)
	return report
}

func ioctlsByCode(values []model.IOCTL) map[string]model.IOCTL {
	out := map[string]model.IOCTL{}
	for _, value := range normalizeLabIOCTLs(values) {
		out[value.Code] = value
	}
	return out
}

func ioctlChanged(oldValue, newValue model.IOCTL) bool {
	return oldValue.Method != newValue.Method ||
		oldValue.Access != newValue.Access ||
		oldValue.Reachability != newValue.Reachability ||
		strings.Join(oldValue.Handlers, "\x00") != strings.Join(newValue.Handlers, "\x00") ||
		strings.Join(oldValue.RiskSignals, "\x00") != strings.Join(newValue.RiskSignals, "\x00")
}

func ioctlDiffSignals(report ioctlDiffReport) []string {
	var signals []string
	for _, entry := range report.Added {
		if contains(entry.IOCTL.RiskSignals, "low-privilege-reachable") || contains(entry.IOCTL.RiskSignals, "method-neither") {
			signals = append(signals, "new-risky-ioctl:"+entry.Binary+":"+entry.IOCTL.Code)
		}
	}
	for _, entry := range report.Changed {
		if entry.Old.Access != entry.New.Access {
			signals = append(signals, "access-change:"+entry.Binary+":"+entry.Code)
		}
		if entry.Old.Reachability != entry.New.Reachability {
			signals = append(signals, "reachability-change:"+entry.Binary+":"+entry.Code)
		}
		if !contains(entry.Old.RiskSignals, "method-neither") && contains(entry.New.RiskSignals, "method-neither") {
			signals = append(signals, "became-method-neither:"+entry.Binary+":"+entry.Code)
		}
	}
	return unique(signals)
}

var reachabilityLine = regexp.MustCompile(`persona=([^ ]+)\s+device=([^ ]+)\s+ioctl=(0x[0-9a-fA-F]+)\s+ok=([01])\s+gle=([0-9]+)\s+returned=([0-9]+)`)

func parseReachabilityLog(path string) (reachabilityReport, error) {
	file, err := os.Open(path)
	if err != nil {
		return reachabilityReport{}, err
	}
	defer file.Close()
	report := reachabilityReport{LogPath: path, ByPersona: map[string]int{}}
	reachable := map[string]struct{}{}
	denied := map[string]struct{}{}
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		match := reachabilityLine.FindStringSubmatch(scanner.Text())
		if match == nil {
			continue
		}
		record := reachabilityRecord{
			Persona:   match[1],
			Device:    match[2],
			IOCTL:     normalizeIOCTLCode(match[3]),
			OK:        match[4] == "1",
			LastError: match[5],
			Returned:  match[6],
		}
		report.Records = append(report.Records, record)
		report.ByPersona[record.Persona]++
		key := record.Persona + ":" + record.IOCTL
		if record.OK || record.LastError != "5" {
			reachable[key] = struct{}{}
		} else {
			denied[key] = struct{}{}
		}
	}
	if err := scanner.Err(); err != nil {
		return report, err
	}
	for key := range reachable {
		report.Reachable = append(report.Reachable, key)
	}
	for key := range denied {
		if _, ok := reachable[key]; !ok {
			report.Denied = append(report.Denied, key)
		}
	}
	sort.Strings(report.Reachable)
	sort.Strings(report.Denied)
	return report, nil
}

func buildSurfaceReport(root string, snapshot model.Snapshot, limit int) surfaceReport {
	inventory := buildIOCTLInventory(snapshot)
	report := surfaceReport{SnapshotDir: root}
	for _, binary := range snapshot.Binaries {
		entry := scoreSurface(binary, inventory[binary.Path])
		report.Summary.BinaryCount++
		report.Summary.IOCTLCount += entry.IOCTLCount
		if strings.EqualFold(binary.Kind, "driver") || strings.HasSuffix(strings.ToLower(binary.Name), ".sys") {
			report.Summary.DriverCount++
		}
		if entry.Score >= 20 {
			report.Summary.HighRiskTargets++
		}
		if entry.Score > 0 {
			report.Targets = append(report.Targets, entry)
		}
	}
	sort.Slice(report.Targets, func(i, j int) bool {
		if report.Targets[i].Score == report.Targets[j].Score {
			return report.Targets[i].Binary < report.Targets[j].Binary
		}
		return report.Targets[i].Score > report.Targets[j].Score
	})
	if limit > 0 && len(report.Targets) > limit {
		report.Targets = report.Targets[:limit]
	}
	for i := range report.Targets {
		report.Targets[i].Rank = i + 1
	}
	return report
}

func buildLabDossier(oldDir, newDir string, oldSnapshot model.Snapshot, newSnapshot model.Snapshot, reachabilityLog string, crashesPath string, limit int) (labDossier, error) {
	pairs, err := auditPairs(oldDir, newDir, ".sys")
	if err != nil {
		return labDossier{}, err
	}
	ioctlDiff := diffIOCTLInventories(oldDir, newDir, buildIOCTLInventory(oldSnapshot), buildIOCTLInventory(newSnapshot))
	surface := buildSurfaceReport(newDir, newSnapshot, limit)
	dossier := labDossier{
		GeneratedAt:  util.NowUTC().Format("2006-01-02T15:04:05Z07:00"),
		OldSnapshot:  oldDir,
		NewSnapshot:  newDir,
		PairAudit:    pairs,
		SidecarAudit: auditSidecars(newSnapshot, newDir),
		IOCTLDiff:    ioctlDiff,
		Surface:      surface,
	}
	if reachabilityLog != "" {
		reachability, err := parseReachabilityLog(reachabilityLog)
		if err != nil {
			return labDossier{}, err
		}
		dossier.Reachability = &reachability
	}
	if crashesPath != "" {
		crashData, err := os.ReadFile(crashesPath)
		if err != nil {
			return labDossier{}, err
		}
		var crashes []crashRecord
		if err := json.Unmarshal(crashData, &crashes); err != nil {
			return labDossier{}, err
		}
		dossier.CrashFindings = crashFindings(crashes)
	}
	dossier.ReviewQueue = buildDossierReviewQueue(dossier)
	dossier.RecommendedNext = dossierNextActions(dossier)
	return dossier, nil
}

func buildDossierReviewQueue(dossier labDossier) []dossierReview {
	var queue []dossierReview
	for _, missing := range dossier.PairAudit.Missing {
		queue = append(queue, dossierReview{
			Priority: "high",
			Target:   missing,
			Reason:   "patched driver has no prepatch pair",
			Signals:  []string{"missing-prepatch-pair"},
		})
	}
	for _, thin := range dossier.SidecarAudit.ThinSidecars {
		queue = append(queue, dossierReview{
			Priority: "medium",
			Target:   thin,
			Reason:   "analysis sidecar is thin or lacks IOCTL metadata",
			Signals:  []string{"thin-sidecar"},
		})
	}
	for _, signal := range dossier.IOCTLDiff.RiskSignals {
		queue = append(queue, dossierReview{
			Priority: "high",
			Target:   signal,
			Reason:   "IOCTL diff produced a risk signal",
			Signals:  []string{signal},
		})
	}
	for _, target := range dossier.Surface.Targets {
		priority := "medium"
		if target.Score >= 30 {
			priority = "high"
		}
		queue = append(queue, dossierReview{
			Priority: priority,
			Target:   target.Binary,
			Reason:   fmt.Sprintf("surface score %d with %d IOCTLs", target.Score, target.IOCTLCount),
			Signals:  target.RiskSignals,
		})
	}
	if dossier.Reachability != nil {
		for _, reachable := range dossier.Reachability.Reachable {
			priority := "medium"
			if strings.HasPrefix(reachable, "noob:") {
				priority = "high"
			}
			queue = append(queue, dossierReview{
				Priority: priority,
				Target:   reachable,
				Reason:   "IOCTL was reachable during harness run",
				Signals:  []string{"reachable-ioctl"},
			})
		}
	}
	for _, finding := range dossier.CrashFindings {
		queue = append(queue, dossierReview{
			Priority: "high",
			Target:   finding.AffectedBinary,
			Reason:   finding.Title,
			Signals:  finding.Evidence,
		})
	}
	sort.SliceStable(queue, func(i, j int) bool {
		return dossierPriority(queue[i].Priority) > dossierPriority(queue[j].Priority)
	})
	if len(queue) > 25 {
		queue = queue[:25]
	}
	return queue
}

func dossierPriority(priority string) int {
	switch priority {
	case "high":
		return 3
	case "medium":
		return 2
	case "low":
		return 1
	default:
		return 0
	}
}

func dossierNextActions(dossier labDossier) []string {
	var actions []string
	if len(dossier.PairAudit.Missing) > 0 {
		actions = append(actions, "Recover missing prepatch driver pairs before claiming patch-specific behavior.")
	}
	if len(dossier.SidecarAudit.ThinSidecars) > 0 || len(dossier.SidecarAudit.MissingSidecars) > 0 {
		actions = append(actions, "Regenerate sidecars for missing or thin targets, prioritizing dispatch and validation functions.")
	}
	if len(dossier.IOCTLDiff.RiskSignals) > 0 {
		actions = append(actions, "Manually review IOCTL diff risk signals and confirm access-mask or reachability changes.")
	}
	if dossier.Reachability == nil {
		actions = append(actions, "Run ioctl_zap as noob and exp, then include the log with --reachability-log.")
	}
	if len(dossier.CrashFindings) == 0 {
		actions = append(actions, "Pull crash manifests after A/B testing and include them with --crashes when available.")
	}
	if len(actions) == 0 {
		actions = append(actions, "Review the high-priority queue and preserve generated artifacts for handoff.")
	}
	return actions
}

func labDossierMarkdown(dossier labDossier) string {
	var b strings.Builder
	fmt.Fprintf(&b, "# Cognitor Lab Dossier\n\n")
	fmt.Fprintf(&b, "- Generated: `%s`\n", dossier.GeneratedAt)
	fmt.Fprintf(&b, "- Old snapshot: `%s`\n", dossier.OldSnapshot)
	fmt.Fprintf(&b, "- New snapshot: `%s`\n\n", dossier.NewSnapshot)
	fmt.Fprintf(&b, "## Summary\n\n")
	fmt.Fprintf(&b, "- Pairs: `%d` matched, `%d` missing, `%d` extra\n", len(dossier.PairAudit.Matched), len(dossier.PairAudit.Missing), len(dossier.PairAudit.Extra))
	fmt.Fprintf(&b, "- Sidecars: `%d/%d` present, `%d` thin, `%d` with IOCTL metadata\n", dossier.SidecarAudit.SidecarCount, dossier.SidecarAudit.BinaryCount, len(dossier.SidecarAudit.ThinSidecars), dossier.SidecarAudit.IOCTLBinaryCount)
	fmt.Fprintf(&b, "- IOCTL diff: `%d` added, `%d` removed, `%d` changed, `%d` risk signals\n", len(dossier.IOCTLDiff.Added), len(dossier.IOCTLDiff.Removed), len(dossier.IOCTLDiff.Changed), len(dossier.IOCTLDiff.RiskSignals))
	fmt.Fprintf(&b, "- Surface: `%d` binaries, `%d` drivers, `%d` IOCTLs, `%d` high-risk targets\n", dossier.Surface.Summary.BinaryCount, dossier.Surface.Summary.DriverCount, dossier.Surface.Summary.IOCTLCount, dossier.Surface.Summary.HighRiskTargets)
	if dossier.Reachability != nil {
		fmt.Fprintf(&b, "- Reachability: `%d` records, `%d` reachable, `%d` denied\n", len(dossier.Reachability.Records), len(dossier.Reachability.Reachable), len(dossier.Reachability.Denied))
	}
	if len(dossier.CrashFindings) > 0 {
		fmt.Fprintf(&b, "- Crash finding seeds: `%d`\n", len(dossier.CrashFindings))
	}
	fmt.Fprintf(&b, "\n## Priority Review Queue\n\n")
	if len(dossier.ReviewQueue) == 0 {
		fmt.Fprintf(&b, "No priority review items were generated.\n\n")
	} else {
		for _, item := range dossier.ReviewQueue {
			fmt.Fprintf(&b, "- `%s` `%s`: %s", item.Priority, item.Target, item.Reason)
			if len(item.Signals) > 0 {
				fmt.Fprintf(&b, " Signals: %s", strings.Join(item.Signals, ", "))
			}
			fmt.Fprintf(&b, "\n")
		}
		fmt.Fprintf(&b, "\n")
	}
	fmt.Fprintf(&b, "## Recommended Next Actions\n\n")
	for _, action := range dossier.RecommendedNext {
		fmt.Fprintf(&b, "- %s\n", action)
	}
	fmt.Fprintf(&b, "\n## Top Surface Targets\n\n")
	if len(dossier.Surface.Targets) == 0 {
		fmt.Fprintf(&b, "No surface targets were ranked.\n")
		return b.String()
	}
	for _, target := range dossier.Surface.Targets {
		fmt.Fprintf(&b, "- `#%d` `%s` score `%d`: %s\n", target.Rank, target.Binary, target.Score, strings.Join(target.RiskSignals, ", "))
	}
	return b.String()
}

func scoreSurface(binary model.Binary, ioctls []model.IOCTL) surfaceEntry {
	entry := surfaceEntry{
		Binary:           binary.Path,
		Kind:             binary.Kind,
		IOCTLCount:       len(ioctls),
		SidecarFunctions: len(binary.Functions),
	}
	text := strings.ToLower(strings.Join(append(append([]string{}, binary.Strings...), binary.Imports...), " "))
	for _, fn := range binary.Functions {
		text += " " + strings.ToLower(fn.Name+" "+strings.Join(fn.Calls, " ")+" "+strings.Join(fn.Imports, " ")+" "+strings.Join(fn.Strings, " ")+" "+strings.Join(fn.Operations, " "))
	}
	addSignal := func(score int, signal string, focus string) {
		entry.Score += score
		entry.RiskSignals = append(entry.RiskSignals, signal)
		if focus != "" {
			entry.ReviewFocus = append(entry.ReviewFocus, focus)
		}
	}
	if strings.EqualFold(binary.Kind, "driver") || strings.HasSuffix(strings.ToLower(binary.Name), ".sys") {
		addSignal(3, "kernel-driver", "Confirm exposed device objects and dispatch routines.")
	}
	if len(binary.Functions) == 0 {
		addSignal(4, "missing-sidecar-functions", "Generate a richer sidecar before trusting negative results.")
	} else if len(binary.Functions) < 3 {
		addSignal(2, "thin-sidecar", "Expand sidecar coverage around dispatch and validation paths.")
	}
	if len(ioctls) > 0 {
		addSignal(len(ioctls)*2, "ioctl-surface", "Review IOCTL dispatch table, access masks, and user buffer handling.")
	}
	for _, ioctl := range ioctls {
		if len(ioctl.RiskSignals) > 0 {
			entry.RiskyIOCTLs = append(entry.RiskyIOCTLs, ioctl)
		}
		for _, signal := range ioctl.RiskSignals {
			switch signal {
			case "method-neither":
				addSignal(8, "ioctl-method-neither", "Audit user pointer probing, exception handling, and buffer lifetime.")
			case "any-access":
				addSignal(5, "ioctl-any-access", "Check whether FILE_ANY_ACCESS should be narrowed.")
			case "low-privilege-reachable":
				addSignal(10, "low-privilege-ioctl", "Re-test reachability from standard-user context.")
			}
		}
	}
	interestingAPIs := []string{
		"ProbeForRead", "ProbeForWrite", "SeAccessCheck", "IoCreateDevice", "IoCreateSymbolicLink",
		"IoCompleteRequest", "MmMapLockedPagesSpecifyCache", "MmCopyVirtualMemory", "ZwOpenProcess",
		"ZwSetValueKey", "RtlCopyMemory", "memcpy", "memmove",
	}
	for _, api := range interestingAPIs {
		if containsFold(text, api) {
			entry.InterestingAPIs = append(entry.InterestingAPIs, api)
		}
	}
	if containsFold(text, "memcpy") || containsFold(text, "RtlCopyMemory") || containsFold(text, "memmove") {
		addSignal(4, "copy-primitive", "Pair copy sites with length checks and trust-boundary checks.")
	}
	if containsFold(text, "privileged operation") || containsFold(text, "SeAccessCheck") {
		addSignal(4, "privileged-operation", "Confirm the authorization check dominates the sensitive operation.")
	}
	if containsFold(text, "DeviceControl") || containsFold(text, "IRP_MJ_DEVICE_CONTROL") || containsFold(text, "ioctl") {
		addSignal(4, "device-control-path", "Map all DeviceControl handlers and fallthrough cases.")
	}
	if containsFold(text, "METHOD_NEITHER") || containsFold(text, "user buffer") {
		addSignal(4, "user-buffer-boundary", "Inspect user buffer validation and exception boundaries.")
	}
	if containsFold(text, "registry") || containsFold(text, "ZwSetValueKey") {
		addSignal(2, "registry-touchpoint", "Review registry ACL and policy assumptions.")
	}
	if containsFold(text, "alpc") || containsFold(text, "rpc") || containsFold(text, "named pipe") {
		addSignal(3, "ipc-surface", "Check caller identity and message marshalling.")
	}
	entry.InterestingText = interestingText(binary)
	entry.RiskSignals = unique(entry.RiskSignals)
	entry.ReviewFocus = unique(entry.ReviewFocus)
	entry.InterestingAPIs = unique(entry.InterestingAPIs)
	if len(entry.RiskyIOCTLs) > 5 {
		entry.RiskyIOCTLs = entry.RiskyIOCTLs[:5]
	}
	if len(entry.InterestingText) > 8 {
		entry.InterestingText = entry.InterestingText[:8]
	}
	return entry
}

func interestingText(binary model.Binary) []string {
	var out []string
	needles := []string{"ioctl", "device", "access", "privilege", "admin", "token", "sid", "registry", "alpc", "rpc", "user buffer", "probe", "copy"}
	for _, value := range binary.Strings {
		for _, needle := range needles {
			if strings.Contains(strings.ToLower(value), needle) {
				out = append(out, value)
				break
			}
		}
	}
	for _, fn := range binary.Functions {
		for _, value := range append(append([]string{}, fn.Strings...), fn.Operations...) {
			for _, needle := range needles {
				if strings.Contains(strings.ToLower(value), needle) {
					out = append(out, value)
					break
				}
			}
		}
	}
	return unique(out)
}

func crashFindings(crashes []crashRecord) []model.Finding {
	var out []model.Finding
	for i, crash := range crashes {
		title := "Lab bugcheck requires triage"
		if crash.Bugcheck != "" {
			title = "Lab bugcheck " + crash.Bugcheck + " requires triage"
		}
		evidence := []string{crash.Dump, crash.IOCTL, crash.Persona, crash.Notes}
		out = append(out, model.Finding{
			ID:                      fmt.Sprintf("crash-%03d", i+1),
			Title:                   title,
			AffectedBinary:          crash.Driver,
			Category:                "lab-crash",
			Confidence:              0.85,
			Severity:                "high",
			RiskScore:               8.0,
			Evidence:                compact(evidence),
			Reasoning:               "Crash was observed in the lab and should be correlated with the patched/prepatch A/B run before any vulnerability claim.",
			RecommendedAuditTargets: compact([]string{crash.Driver, crash.IOCTL}),
		})
	}
	return out
}

func contains(values []string, needle string) bool {
	for _, value := range values {
		if value == needle {
			return true
		}
	}
	return false
}

func containsFold(haystack string, needle string) bool {
	return strings.Contains(strings.ToLower(haystack), strings.ToLower(needle))
}

func unique(values []string) []string {
	seen := map[string]struct{}{}
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value != "" {
			seen[value] = struct{}{}
		}
	}
	out := make([]string, 0, len(seen))
	for value := range seen {
		out = append(out, value)
	}
	sort.Strings(out)
	return out
}

func compact(values []string) []string {
	var out []string
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value != "" {
			out = append(out, value)
		}
	}
	return out
}

func writeJSON(path string, data []byte) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	return os.WriteFile(path, data, 0o644)
}

func writeText(path string, text string) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	return os.WriteFile(path, []byte(text), 0o644)
}
