# Cognitor Documentation

Start here when working with Cognitor.

## User Docs

- [Examples](examples.md): copy-paste workflows for demos, real snapshots, DLL focus, CI, and staged analysis.
- [Snapshot Inputs](inputs.md): supported files, sidecars, service context, registry context, and layout tips.
- [Reports And Output Bundle](reports.md): Markdown, JSON, SARIF, CSV, SQLite, bundle manifests, and CI gates.
- [Lab Workflow](lab.md): driver-focused pair audits, IOCTL extraction/diffing, reachability parsing, crash intake, and attack-surface ranking.

## Technical Docs

- [Architecture](design.md): package map, data flow, matching model, and design principles.
- [Rule Guide](rules.md): rule families, evidence signals, researcher checks, scoring, and adding rules.
- [Extending Cognitor](extending.md): rule development, sidecar exporters, report formats, and test strategy.

## Fast Path

```sh
cognitor compare old new --workdir out --all-formats
```

Use `--no-banner` if the banner is noisy in CI.

## Focused DLL Review

```sh
cognitor compare old new --focus ntdll.dll --workdir out-ntdll --all-formats
```

## Driver Lab Triage

```sh
cognitor lab sidecars --snapshot patched --out out/sidecars.json
cognitor lab ioctls --snapshot patched --out out/ioctl.json
cognitor lab surface --snapshot patched --out out/surface.json
cognitor lab dossier --old prepatch --new patched --out out/lab-dossier.json --markdown out/lab-dossier.md
```
