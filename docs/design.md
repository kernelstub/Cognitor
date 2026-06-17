# Architecture

Cognitor is a defensive Windows patch-diff pipeline. It compares two snapshots, extracts evidence, identifies security-relevant semantic changes, scores findings, and emits reports for review or automation.

## Data Flow

```text
old snapshot dir      new snapshot dir
      |                    |
      v                    v
  ingest.Scan()        ingest.Scan()
      |                    |
      +------ model.Snapshot
               |
               v
        diff.SummarizeChanges()
        diff.Analyze()
               |
               v
        analysis.DefaultEngine()
               |
               v
        score.DefaultScorer()
               |
               v
        graph.Build()
        report.BuildWithMetadata()
               |
               v
        Markdown / JSON / SARIF / CSV / SQLite / bundle manifest
```

Driver lab workflows reuse `ingest.Scan()` and sidecar metadata, then emit focused JSON artifacts:

```text
snapshot dirs + sidecars
      |
      v
lab pairs / sidecars / ioctls / diff-ioctls / reachability / surface / crashes / dossier
      |
      v
prepatch-pairs.json / ioctl.json / ioctl-diff.json / reachability.json / surface.json / crash-findings.json / lab-dossier.json
```

## Packages

- `cmd/cognitor`: executable entry point.
- `internal/cli`: Cobra commands and user-facing workflow orchestration.
- `internal/ingest`: snapshot scanning, PE metadata, strings, manifests, symbols, and analysis sidecars.
- `internal/diff`: binary/function matching, semantic additions, inventory change summaries, and focus filtering support.
- `internal/analysis`: composable defensive hardening rules.
- `internal/score`: severity and risk scoring.
- `internal/graph`: graph model used for triage queries.
- `internal/report`: Markdown, JSON, SARIF, CSV, executive summaries, and review queues.
- `internal/store`: SQLite persistence for snapshots, findings, graph data, and change summaries.
- `pkg/model`: stable data contracts shared across internal packages.
- `tools/ida` and `scripts/lab`: optional lab helpers for sidecar extraction, generic reachability checks, driver swapping, and crash collection.

## Normal Workflow

Most users should run:

```sh
cognitor compare old new --workdir out --all-formats
```

This performs scanning, diffing, scoring, graph building, report generation, and bundle manifest generation in one pass.

## Advanced Workflow

The staged workflow is still available when you want to inspect intermediate databases:

```sh
cognitor scan --snapshot old --path old --out old.db
cognitor scan --snapshot new --path new --out new.db
cognitor diff --old old.db --new new.db --out findings.db
cognitor report --db findings.db --format markdown --out report.md
```

## Matching Model

Cognitor matches binaries by normalized Windows-style relative path. Matching is case-insensitive, so `System32/NTDLL.DLL` and `system32/ntdll.dll` are treated as the same target.

Functions are matched by:

- exact symbol name,
- normalized symbol name,
- semantic neighborhood similarity from strings, calls, imports, and basic block count.

Sidecar analysis files improve matching quality and finding precision.

IOCTL metadata can appear at the top level of an analysis sidecar or under `functions[].ioctls`. Cognitor normalizes codes, decodes CTL_CODE fields, merges handlers, and adds lab risk signals for driver triage.

## Snapshot Model

A snapshot contains:

- binaries such as `.exe`, `.dll`, `.sys`, `.drv`, `.ocx`, and `.cpl`,
- evidence artifacts such as `.edb`, `.dat`, `.log`, `.evtx`, `.etl`, `.reg`, `.json`, `.xml`, `.ini`, `.inf`, `.cfg`, and `.conf`,
- optional `services.json`,
- optional `registry.json`.

## Report Model

Reports include:

- run metadata,
- executive risk posture,
- beginner guidance,
- researcher checklist,
- priority review queue,
- automatic change inventory,
- scored findings,
- graph data,
- responsible-disclosure-oriented manual review plan.

## Design Principles

- Defensive only: Cognitor identifies likely hardening changes and review targets, not exploit steps.
- Evidence oriented: every finding should have supporting strings, calls, operations, imports, or artifact evidence.
- Automation friendly: JSON, SARIF, CSV, SQLite, and bundle hashes are deterministic enough for CI retention and regression review.
- Tool agnostic: disassembler integration is file based through `*.analysis.json`.
- Lab friendly: target hosts, device names, credentials, and driver paths stay in local environment variables instead of repository files.
