param(
    [ValidateSet("prepatch", "patched")]
    [string]$Slot,
    [switch]$RestartService
)

$ErrorActionPreference = "Stop"

function Require-Env($Name) {
    $Value = [Environment]::GetEnvironmentVariable($Name)
    if ([string]::IsNullOrWhiteSpace($Value)) {
        throw "Missing environment variable $Name. See scripts\lab\env.example.ps1."
    }
    return $Value
}

$Service = Require-Env "COGNITOR_LAB_SERVICE"
$Target = Require-Env "COGNITOR_LAB_DRIVER"
$SourceName = if ($Slot -eq "prepatch") { "COGNITOR_LAB_PREPATCH" } else { "COGNITOR_LAB_PATCHED" }
$Source = Require-Env $SourceName

if ($RestartService) {
    sc.exe stop $Service | Out-Null
    Start-Sleep -Seconds 2
}

Copy-Item -Force $Source $Target

if ($RestartService) {
    sc.exe start $Service | Out-Null
}

Write-Host "active driver is now $Slot ($Source -> $Target)"
