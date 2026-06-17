# Cognitor Lab Workflow

This workflow turns the old hand-run scripts into one repeatable path. It keeps credentials, VM names, device names, and driver paths in environment variables.

## 1. Audit Inputs

Check patched drivers that do not have a prepatch pair:

```sh
cognitor lab pairs --prepatch ./prepatch --patched ./patched --out out/prepatch-pairs.json
```

Audit sidecar coverage:

```sh
cognitor lab sidecars --snapshot ./patched --out out/sidecars.json
```

Thin sidecars are drivers with a sidecar but fewer than two functions and no IOCTL metadata.

Command map:

```text
lab pairs         prepatch/patched file coverage
lab sidecars      analysis sidecar coverage and thin exports
lab ioctls        normalized IOCTL inventory with decoded CTL_CODE fields
lab diff-ioctls   old/new IOCTL additions, removals, and metadata changes
lab surface       ranked attack-surface triage targets
lab reachability  parsed ioctl_zap noob/elevated logs
lab crashes       crash manifest to finding seeds
lab dossier       combined JSON and Markdown research handoff
```

## 2. Extract IOCTLs Without BinExport

The IDA exporter does not use BinExport, so it avoids the IDA 9.1 plugin compatibility issue:

```powershell
ida64.exe -A -S"tools\ida\ioctl_export.py --out C:\cognitor\sidecars --device \\.\MyDevice" C:\drivers\driver.sys
```

Copy the generated `driver.sys.analysis.json` next to the driver in the snapshot directory, then normalize:

```sh
cognitor lab ioctls --snapshot ./patched --out out/ioctl.json
```

The normalized inventory decodes CTL_CODE values into `device_type`, `function`, `method`, and `access`, then adds conservative risk signals such as `method-neither`, `any-access`, and `low-privilege-reachable`.

Sidecars can declare IOCTLs either at the top level:

```json
{
  "ioctls": [
    {
      "code": "0x222000",
      "device": "\\\\.\\MyDevice",
      "method": "METHOD_BUFFERED",
      "access": "FILE_ANY_ACCESS",
      "handlers": ["DispatchDeviceControl"],
      "reachability": "noob"
    }
  ],
  "functions": []
}
```

or inside a function record under `functions[].ioctls`.

Compare old and new inventories:

```sh
cognitor lab diff-ioctls --old ./prepatch --new ./patched --out out/ioctl-diff.json
```

The diff calls out added, removed, and changed IOCTLs, including access-mask and reachability changes.

Rank the driver attack surface for defensive triage:

```sh
cognitor lab surface --snapshot ./patched --out out/surface.json
```

The surface report scores targets using IOCTL metadata, CTL_CODE risk, low-privilege reachability, copy primitives, access-check APIs, IPC indicators, registry touchpoints, and sidecar depth. Use it to decide which drivers and dispatch paths deserve manual review first.

Important `surface.json` fields:

- `score`: relative triage priority, not a vulnerability claim.
- `risk_signals`: why the target was ranked.
- `review_focus`: concrete manual review prompts.
- `interesting_apis`: APIs worth inspecting in context.
- `risky_ioctls`: IOCTLs with risk signals after CTL_CODE decoding.

Build a combined research dossier:

```sh
cognitor lab dossier --old ./prepatch --new ./patched --out out/lab-dossier.json --markdown out/lab-dossier.md
```

With optional lab evidence:

```sh
cognitor lab dossier \
  --old ./prepatch \
  --new ./patched \
  --reachability-log ./patched-zap.log \
  --crashes ./crashes/crashes.json \
  --out out/lab-dossier.json \
  --markdown out/lab-dossier.md
```

The dossier combines pair audit, sidecar coverage, IOCTL diff, surface ranking, optional reachability logs, optional crash seeds, a priority review queue, and recommended next actions. Use the Markdown file for human handoff and the JSON file for automation.

## 3. Build And Deploy The Generic Harness

On the Windows build host:

```powershell
. .\scripts\lab\env.example.ps1
# edit the environment values in your shell profile or a private .ps1 file
.\scripts\lab\build_deploy.ps1 -IoctlJson out\ioctl.json
```

The harness performs defensive reachability checks with zero-filled buffers. It logs return codes and does not include exploit payloads.

## 4. A/B Confirm A Patch Signal

On the lab VM, use an elevated PowerShell:

```powershell
.\scripts\lab\swap_driver.ps1 -Slot prepatch -RestartService
.\scripts\lab\reachability_test.ps1 -Persona both -IoctlJson .\ioctl.json -Log .\prepatch-zap.log
.\scripts\lab\swap_driver.ps1 -Slot patched -RestartService
.\scripts\lab\reachability_test.ps1 -Persona both -IoctlJson .\ioctl.json -Log .\patched-zap.log
```

Use `noob` for standard-user reachability and `exp` for elevated reachability. Run `exp` from an elevated PowerShell so the log can be captured.

Parse the harness output into evidence:

```sh
cognitor lab reachability --log ./patched-zap.log --out out/reachability.json
```

## 5. Pull Crashes And Seed Findings

On the lab VM:

```powershell
.\scripts\lab\crash_pull.ps1 -OutDir C:\cognitor-lab\crashes -Driver driver.sys
```

Back on the analysis host:

```sh
cognitor lab crashes --manifest ./crashes/crashes.json --out out/crash-findings.json
```

The generated findings are triage seeds. Correlate them with the prepatch/patched A/B run before making vulnerability claims.

## 6. Safety And Scope

The lab harness and commands are intended for authorized defensive validation. `ioctl_zap` sends zero-filled buffers and records reachability/error behavior; it does not generate exploit payloads. Keep real hostnames, credentials, device paths, and driver paths in private environment files, not in Git.
