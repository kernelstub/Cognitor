package ingest

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/kernelstub/cognitor/internal/util"
	"github.com/kernelstub/cognitor/internal/workers"
	"github.com/kernelstub/cognitor/pkg/model"
)

type Options struct {
	Name            string
	Path            string
	Workers         int
	StringMinLength int
}

type AnalysisExport struct {
	Functions []model.Function `json:"functions"`
	IOCTLs    []model.IOCTL    `json:"ioctls"`
}

func Scan(ctx context.Context, opts Options) (model.Snapshot, error) {
	snapshot := model.Snapshot{
		ID:        util.StableID(opts.Name, opts.Path),
		Name:      opts.Name,
		Path:      opts.Path,
		CreatedAt: util.NowUTC(),
	}
	var paths []string
	var artifactPaths []string
	err := filepath.WalkDir(opts.Path, func(path string, entry os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if entry.IsDir() {
			return nil
		}
		switch {
		case util.IsBinaryLike(path):
			paths = append(paths, path)
		case util.IsArtifactLike(path) && !isGeneratedSnapshotFile(opts.Path, path) && !isBinarySidecar(path):
			artifactPaths = append(artifactPaths, path)
		}
		return nil
	})
	if err != nil {
		return snapshot, err
	}
	sort.Strings(paths)
	results := workers.Map(ctx, opts.Workers, paths, func(ctx context.Context, path string) (model.Binary, error) {
		return scanBinary(ctx, snapshot.ID, opts.Path, path, opts.StringMinLength)
	})
	var errs []error
	for _, result := range results {
		if result.Err != nil {
			errs = append(errs, result.Err)
			continue
		}
		snapshot.Binaries = append(snapshot.Binaries, result.Value)
	}
	sort.Slice(snapshot.Binaries, func(i, j int) bool {
		return snapshot.Binaries[i].Path < snapshot.Binaries[j].Path
	})
	sort.Strings(artifactPaths)
	artifactResults := workers.Map(ctx, opts.Workers, artifactPaths, func(ctx context.Context, path string) (model.Artifact, error) {
		return scanArtifact(ctx, snapshot.ID, opts.Path, path, opts.StringMinLength)
	})
	for _, result := range artifactResults {
		if result.Err != nil {
			errs = append(errs, result.Err)
			continue
		}
		snapshot.Artifacts = append(snapshot.Artifacts, result.Value)
	}
	sort.Slice(snapshot.Artifacts, func(i, j int) bool {
		return snapshot.Artifacts[i].Path < snapshot.Artifacts[j].Path
	})
	snapshot.Services = readServices(opts.Path)
	snapshot.Registry = readRegistry(opts.Path)
	return snapshot, errors.Join(errs...)
}

func scanBinary(ctx context.Context, snapshotID string, root string, path string, minLen int) (model.Binary, error) {
	if err := ctx.Err(); err != nil {
		return model.Binary{}, err
	}
	rel, err := filepath.Rel(root, path)
	if err != nil {
		return model.Binary{}, err
	}
	info, err := os.Stat(path)
	if err != nil {
		return model.Binary{}, err
	}
	sha, err := util.FileSHA256(path)
	if err != nil {
		return model.Binary{}, err
	}
	kind, imports, exports, sections := ReadPEMetadata(path)
	stringsFound, err := ExtractStrings(path, minLen)
	if err != nil {
		return model.Binary{}, err
	}
	functions, ioctls, err := readAnalysis(path)
	if err != nil {
		return model.Binary{}, err
	}
	id := util.StableID(snapshotID, util.NormalizeSlash(rel))
	for i := range functions {
		functions[i].BinaryID = id
		if functions[i].ID == "" {
			functions[i].ID = util.StableID(id, functions[i].Name)
		}
		if functions[i].NormalizedName == "" {
			functions[i].NormalizedName = NormalizeSymbol(functions[i].Name)
		}
	}
	return model.Binary{
		ID:         id,
		SnapshotID: snapshotID,
		Path:       util.NormalizeSlash(rel),
		Name:       filepath.Base(path),
		Kind:       kind,
		SHA256:     sha,
		Size:       info.Size(),
		Version:    readTextSidecar(path + ".version"),
		Signer:     "unverified-placeholder",
		Imports:    cleanSymbols(imports),
		Exports:    cleanSymbols(exports),
		Sections:   sections,
		Strings:    stringsFound,
		Functions:  functions,
		IOCTLs:     ioctls,
		Manifest:   ReadManifest(path),
	}, nil
}

func scanArtifact(ctx context.Context, snapshotID string, root string, path string, minLen int) (model.Artifact, error) {
	if err := ctx.Err(); err != nil {
		return model.Artifact{}, err
	}
	rel, err := filepath.Rel(root, path)
	if err != nil {
		return model.Artifact{}, err
	}
	info, err := os.Stat(path)
	if err != nil {
		return model.Artifact{}, err
	}
	sha, err := util.FileSHA256(path)
	if err != nil {
		return model.Artifact{}, err
	}
	stringsFound, err := ExtractStrings(path, minLen)
	if err != nil {
		return model.Artifact{}, err
	}
	rel = util.NormalizeSlash(rel)
	return model.Artifact{
		ID:         util.StableID(snapshotID, "artifact", rel),
		SnapshotID: snapshotID,
		Path:       rel,
		Name:       filepath.Base(path),
		Kind:       strings.TrimPrefix(strings.ToLower(filepath.Ext(path)), "."),
		SHA256:     sha,
		Size:       info.Size(),
		Strings:    stringsFound,
	}, nil
}

func isGeneratedSnapshotFile(root string, path string) bool {
	rel, err := filepath.Rel(root, path)
	if err != nil {
		return false
	}
	switch util.NormalizeSlash(rel) {
	case "services.json", "registry.json":
		return true
	default:
		return false
	}
}

func isBinarySidecar(path string) bool {
	for _, suffix := range []string{".analysis.json", ".symbols.json", ".version", ".manifest", ".manifest.json"} {
		if strings.HasSuffix(path, suffix) {
			return true
		}
	}
	return false
}

func readAnalysis(path string) ([]model.Function, []model.IOCTL, error) {
	data, err := os.ReadFile(path + ".analysis.json")
	if err != nil {
		symbols, symErr := ReadSymbols(path)
		if symErr != nil {
			return nil, nil, symErr
		}
		var functions []model.Function
		for _, symbol := range symbols {
			functions = append(functions, model.Function{Name: symbol, NormalizedName: NormalizeSymbol(symbol)})
		}
		return functions, nil, nil
	}
	var export AnalysisExport
	if err := json.Unmarshal(data, &export); err != nil {
		return nil, nil, err
	}
	ioctls := append([]model.IOCTL{}, export.IOCTLs...)
	for _, fn := range export.Functions {
		for _, ioctl := range fn.IOCTLs {
			if ioctl.Source == "" {
				ioctl.Source = fn.Name
			}
			if len(ioctl.Handlers) == 0 && fn.Name != "" {
				ioctl.Handlers = []string{fn.Name}
			}
			ioctls = append(ioctls, ioctl)
		}
	}
	return export.Functions, normalizeIOCTLs(ioctls), nil
}

func normalizeIOCTLs(values []model.IOCTL) []model.IOCTL {
	seen := map[string]model.IOCTL{}
	for _, value := range values {
		value.Code = strings.ToLower(strings.TrimSpace(value.Code))
		if value.Code == "" {
			continue
		}
		if !strings.HasPrefix(value.Code, "0x") {
			value.Code = "0x" + value.Code
		}
		key := value.Code
		existing, ok := seen[key]
		if !ok {
			seen[key] = value
			continue
		}
		existing.Handlers = cleanSymbols(append(existing.Handlers, value.Handlers...))
		if existing.Name == "" {
			existing.Name = value.Name
		}
		if existing.Device == "" {
			existing.Device = value.Device
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
		seen[key] = existing
	}
	out := make([]model.IOCTL, 0, len(seen))
	for _, value := range seen {
		out = append(out, value)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Device == out[j].Device {
			return out[i].Code < out[j].Code
		}
		return out[i].Device < out[j].Device
	})
	return out
}

func readTextSidecar(path string) string {
	data, err := os.ReadFile(path)
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(data))
}

func cleanSymbols(values []string) []string {
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

func readServices(root string) []model.Service {
	data, err := os.ReadFile(filepath.Join(root, "services.json"))
	if err != nil {
		return nil
	}
	var services []model.Service
	_ = json.Unmarshal(data, &services)
	sort.Slice(services, func(i, j int) bool { return services[i].Name < services[j].Name })
	return services
}

func readRegistry(root string) []model.RegistryKey {
	data, err := os.ReadFile(filepath.Join(root, "registry.json"))
	if err != nil {
		return nil
	}
	var keys []model.RegistryKey
	_ = json.Unmarshal(data, &keys)
	sort.Slice(keys, func(i, j int) bool { return keys[i].Path < keys[j].Path })
	return keys
}
