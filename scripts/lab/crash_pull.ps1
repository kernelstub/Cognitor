param(
    [string]$OutDir = "out\crashes",
    [string]$Since = "",
    [string]$Driver = ""
)

$ErrorActionPreference = "Stop"
New-Item -ItemType Directory -Force -Path $OutDir | Out-Null

$DumpSources = @("$env:SystemRoot\Minidump", "$env:SystemRoot\MEMORY.DMP")
$Dumps = @()
foreach ($Source in $DumpSources) {
    if (Test-Path $Source -PathType Container) {
        $Dumps += Get-ChildItem $Source -Filter "*.dmp" -ErrorAction SilentlyContinue
    } elseif (Test-Path $Source -PathType Leaf) {
        $Dumps += Get-Item $Source
    }
}

$Cutoff = $null
if (![string]::IsNullOrWhiteSpace($Since)) {
    $Cutoff = [DateTime]::Parse($Since)
}

$Records = @()
foreach ($Dump in $Dumps) {
    if ($Cutoff -and $Dump.LastWriteTime -lt $Cutoff) {
        continue
    }
    $Dest = Join-Path $OutDir $Dump.Name
    Copy-Item -Force $Dump.FullName $Dest
    $Records += [PSCustomObject]@{
        driver = $Driver
        bugcheck = ""
        dump = $Dest
        ioctl = ""
        persona = ""
        inputs = @()
        notes = "Pulled from $($Dump.FullName)"
    }
}

$Events = Get-WinEvent -FilterHashtable @{LogName="System"; Id=1001} -MaxEvents 20 -ErrorAction SilentlyContinue
foreach ($Event in $Events) {
    if ($Cutoff -and $Event.TimeCreated -lt $Cutoff) {
        continue
    }
    $Records += [PSCustomObject]@{
        driver = $Driver
        bugcheck = ""
        dump = ""
        ioctl = ""
        persona = ""
        inputs = @()
        notes = $Event.Message
    }
}

$Manifest = Join-Path $OutDir "crashes.json"
$Records | ConvertTo-Json -Depth 5 | Set-Content -Encoding UTF8 $Manifest
Write-Host $Manifest
