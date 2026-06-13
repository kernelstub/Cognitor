# Cognitor

<img width="1672" height="941" alt="image" src="https://github.com/user-attachments/assets/77e68a58-6ee2-4030-85d7-eb6db80d8a4e" />


Defensive patch Tuesday semantic diff cli for Windows build snapshots

It is designed for patch comprehension, validation review, sibling-bug hypothesis generation, and responsible disclosure workflows. It does not generate exploits, weaponized proof of concept material, shellcode, bypass steps, or offensive payloads.

## Install

```sh
go build ./cmd/cognitor
```

## Usage

Most users only need one command:

```sh
./cognitor compare ./testdata/snapshots/old ./testdata/snapshots/new
```

That scans both folders, compares binaries and evidence artifacts, writes `findings.db`, creates `report.md`, and prints the overall risk posture.

Equivalent explicit forms:

```sh
./cognitor analyze ./testdata/snapshots/old ./testdata/snapshots/new
./cognitor patch-diff ./testdata/snapshots/old ./testdata/snapshots/new --all-formats
./cognitor patch-diff --old ./testdata/snapshots/old --new ./testdata/snapshots/new --out report.md
```

Focus on a specific Windows DLL, such as `ntdll.dll`:

```sh
./cognitor compare ./old ./new --focus ntdll.dll --workdir ./out
```

Diff every DLL in the snapshots:

```sh
./cognitor compare ./old ./new --focus "*.dll" --workdir ./out --all-formats
```

For the full analyst bundle:

```sh
./cognitor compare ./testdata/snapshots/old ./testdata/snapshots/new --workdir ./out --all-formats
```

This writes:

```text
out/findings.db
out/report.md
out/report.json
out/report.sarif
out/report.csv
out/cognitor-bundle.json
```

`cognitor-bundle.json` records the input paths, risk posture, generated artifacts, and SHA-256 hashes for handoff or CI retention.

CI/pipeline gate example:

```sh
./cognitor compare ./testdata/snapshots/old ./testdata/snapshots/new --workdir /tmp/cognitor-convenience --all-formats --fail-on high
```

Advanced/manual pipeline:

```sh
./cognitor snapshot create --name old --path ./snapshots/old
./cognitor snapshot create --name new --path ./snapshots/new --source /path/to/windows/build
./cognitor scan --snapshot old --path ./testdata/snapshots/old --out old.db
./cognitor scan --snapshot new --path ./testdata/snapshots/new --out new.db
./cognitor diff --old old.db --new new.db --out findings.db
./cognitor report --db findings.db --format markdown --out report.md
./cognitor report --db findings.db --format json --out report.json
./cognitor report --db findings.db --format sarif --out report.sarif
./cognitor graph --db findings.db --query newly-protected
./cognitor rules
```

## Try It On Windows

Build the CLI from the project root in PowerShell:

```powershell
.\scripts\build.ps1
```

This creates:

```text
bin\cognitor.exe
```

The default build targets Windows 11 on typical Intel or AMD 64-bit machines, also known as `windows/amd64`. If you are on Windows on ARM, build with:

```powershell
.\scripts\build.ps1 -Arch arm64
```

If you build from Linux, WSL, Git Bash, or macOS, use:

```sh
./scripts/build.sh
```

That script cross-compiles a real Windows `.exe` by default. If Windows says the executable is not compatible, delete `bin\cognitor.exe` and rebuild with the command that matches your CPU architecture.

Run the included fake fixture first:

```powershell
.\bin\cognitor.exe compare .\testdata\snapshots\old .\testdata\snapshots\new
notepad .\report.md
```

To write every report format in one run:

```powershell
.\bin\cognitor.exe compare .\testdata\snapshots\old .\testdata\snapshots\new --workdir .\out --all-formats
notepad .\out\report.md
```

Or run each stage manually:

```powershell
.\bin\cognitor.exe scan --snapshot old --path .\testdata\snapshots\old --out old.db
.\bin\cognitor.exe scan --snapshot new --path .\testdata\snapshots\new --out new.db
.\bin\cognitor.exe diff --old old.db --new new.db --out findings.db
.\bin\cognitor.exe report --db findings.db --format markdown --out report.md
notepad .\report.md
```

To use your own old and new folders, create or choose two directories:

```text
C:\cognitor-data\old
C:\cognitor-data\new
```

Put older Windows binaries in `old` and newer patched binaries in `new`, then run:

```powershell
.\bin\cognitor.exe compare C:\cognitor-data\old C:\cognitor-data\new --workdir C:\cognitor-data\out --all-formats
```

For separate scan, diff, and report stages:

```powershell
.\bin\cognitor.exe scan --snapshot old --path C:\cognitor-data\old --out old.db
.\bin\cognitor.exe scan --snapshot new --path C:\cognitor-data\new --out new.db
.\bin\cognitor.exe diff --old old.db --new new.db --out findings.db
.\bin\cognitor.exe report --db findings.db --format markdown --out report.md
notepad .\report.md
```

You can also have Cognitor initialize scan-ready folders:

```powershell
.\bin\cognitor.exe snapshot create --name old --path C:\cognitor-data\old
.\bin\cognitor.exe snapshot create --name new --path C:\cognitor-data\new
```

Use binaries you are authorized to analyze, such as files from your own lab VM, mounted Windows image, or internal update extraction workflow. Cognitor prepares and scans folders, but it does not download Windows builds.

## Snapshot Inputs

Cognitor scans PE-like files with extensions such as `.exe`, `.dll`, and `.sys`. DLLs are first-class inputs, so Windows libraries such as `ntdll.dll`, `kernel32.dll`, `win32u.dll`, browser DLLs, service DLLs, and application DLLs can be compared directly. Cognitor collects hashes, file metadata, printable strings, best-effort PE imports and sections, sidecar manifests, and optional analysis exports.

It also tracks evidence artifacts such as `.edb`, `.dat`, `.log`, `.evtx`, `.etl`, `.reg`, `.json`, `.xml`, `.ini`, `.inf`, `.cfg`, and `.conf`. These are hashed, string-scanned, stored in the snapshot database, and compared automatically so reports can call out changed policy databases, service/registry exports, event traces, manifests, and configuration evidence.

You can create scan-ready directories with `snapshot create`. Without `--source`, it initializes `services.json`, `registry.json`, and `SNAPSHOT.md`. With `--source`, it copies binary-like files and supported sidecars while preserving relative paths.

Disassembler exporters can provide a sidecar named:

```text
binary.sys.analysis.json
```

with this shape:

```json
{
  "functions": [
    {
      "name": "DispatchCreate",
      "basic_block_count": 8,
      "calls": ["memcpy"],
      "strings": ["IOCTL_FOO"],
      "operations": ["copy user buffer"]
    }
  ]
}
```

## Reports

Markdown reports include run metadata, executive risk posture, priority review queue, automatic change inventory, top changed components, top findings, semantic clusters, likely vulnerability classes, sibling-bug hypotheses, and a manual review plan. JSON and SARIF are deterministic for automation. CSV provides a compact triage export for spreadsheets and CI dashboards.

Reports also include beginner guidance and a researcher checklist. The rule engine looks for defensive patch signals across access checks, memory/bounds checks, native API/syscall boundary validation, handle/object validation, token and impersonation flow, RPC auth and marshalling validation, COM launch/security permission changes, ALPC, registry, services, and object lifetime/rundown protection.

## Development

```sh
make test
make build
```
