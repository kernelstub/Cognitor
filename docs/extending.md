# Extending Cognitor

This guide covers common extension points.

## Add A Rule

Rules live in `internal/analysis`.

Minimal shape:

```go
package analysis

import (
    "context"

    "github.com/kernelstub/cognitor/pkg/model"
)

type ExampleRule struct{}

func (ExampleRule) ID() string { return "example-rule" }

func (ExampleRule) Evaluate(ctx context.Context, change model.SemanticChange) []model.Finding {
    hits := hasAny(append(change.AddedCalls, change.AddedOps...), "ExampleSignal")
    if len(hits) == 0 {
        return nil
    }
    return []model.Finding{
        finding(change, "example-category", "Example defensive change", hits, 0.8*change.Similarity),
    }
}
```

Wire it into `DefaultEngine()`:

```go
func DefaultEngine() Engine {
    return NewEngine(
        AccessCheckRule{},
        ExampleRule{},
    )
}
```

Add tests in `internal/analysis/rules_test.go`.

## Rule Guidelines

Good rules:

- detect newly added defensive behavior,
- use clear evidence strings or calls,
- avoid broad keywords that create noisy results,
- include a category that explains the vulnerability class or boundary,
- stay defensive and review-oriented.

Avoid:

- exploit payload hints,
- bypass instructions,
- overfitting to one sample string,
- vague categories such as `misc`.

## Add A Sidecar Exporter

Cognitor intentionally uses file-based sidecars so exporters can be written for IDA, Ghidra, Binary Ninja, radare2, custom scripts, or internal pipelines.

Emit:

```text
binary.dll.analysis.json
```

With:

```json
{
  "ioctls": [
    {
      "code": "0x00222003",
      "device": "\\\\.\\Example",
      "handlers": ["DispatchDeviceControl"],
      "reachability": "noob",
      "source": "custom-exporter"
    }
  ],
  "functions": [
    {
      "name": "FunctionName",
      "basic_block_count": 8,
      "calls": ["ApiCall"],
      "strings": ["string evidence"],
      "imports": ["module!import"],
      "operations": ["normalized semantic operation"],
      "ioctls": [
        {
          "code": "0x00222003",
          "handlers": ["FunctionName"]
        }
      ]
    }
  ]
}
```

Exporter quality tips:

- Normalize API names consistently.
- Include security-relevant operations such as `access mask validation`, `length check`, `handle type validation`, or `rpc auth level check`.
- Include strings even if symbols are stripped.
- For drivers, emit IOCTL records from dispatch switch cases, comparison immediates, symbolic constants, or recovered CTL_CODE macros.
- Include `reachability` when lab evidence shows whether a standard user (`noob`) or elevated caller (`exp`) can open the device and issue the code.
- Prefer stable function names when available; synthetic names are acceptable.

IOCTL exporter quality tips:

- Preserve exact hexadecimal codes; Cognitor normalizes padding and case.
- Fill `method` and `access` if your tool has symbolic CTL_CODE data; otherwise Cognitor decodes them from the code.
- Set `handlers` to dispatch or helper functions that enforce access, probe buffers, or perform sensitive work.
- Keep notes defensive and review-oriented. Do not emit exploit payloads or bypass steps.

## Add A Report Format

Report generators live in `internal/report`.

1. Add `format.go`.
2. Implement:

```go
func FormatName(report model.Report) ([]byte, error) {
    // serialize report
}
```

3. Wire the format into:

- `internal/cli/report.go`,
- `internal/cli/analyze.go`,
- `defaultReportName()` if the one-command workflow should produce it.

4. Add tests in `internal/report`.

## Add A Snapshot Input Type

Binary-like extensions are handled in `internal/util/paths.go`.

Evidence artifact extensions are also handled in `internal/util/paths.go`.

If the new input needs special parsing:

1. Add parser code in `internal/ingest`.
2. Extend `pkg/model`.
3. Persist it in `internal/store`.
4. Compare it in `internal/diff`.
5. Render it in `internal/report`.

## Test Strategy

Use focused tests:

- `internal/analysis`: rule behavior and categories.
- `internal/diff`: matching, case-insensitive Windows paths, change summaries.
- `internal/ingest`: file type scanning and sidecars.
- `internal/store`: persistence round trips.
- `internal/app`: end-to-end CLI workflows.

Run:

```sh
go test ./...
```

## Safety Expectations

Cognitor is for defensive review, patch comprehension, validation, and responsible disclosure workflows. Keep extensions aligned with those goals.
