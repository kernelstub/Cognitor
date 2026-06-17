param(
    [string]$Configuration = "Release",
    [string]$Arch = "x64",
    [string]$OutDir = "bin\lab",
    [string]$IoctlJson = "ioctl.json"
)

$ErrorActionPreference = "Stop"

function Require-Env($Name) {
    $Value = [Environment]::GetEnvironmentVariable($Name)
    if ([string]::IsNullOrWhiteSpace($Value)) {
        throw "Missing environment variable $Name. See scripts\lab\env.example.ps1."
    }
    return $Value
}

$HostName = Require-Env "COGNITOR_LAB_HOST"
$User = Require-Env "COGNITOR_LAB_USER"
$Key = Require-Env "COGNITOR_LAB_SSH_KEY"
$Remote = Require-Env "COGNITOR_LAB_REMOTE"

New-Item -ItemType Directory -Force -Path $OutDir | Out-Null
$Zap = Join-Path $OutDir "ioctl_zap.exe"

$Cl = Get-Command cl.exe -ErrorAction SilentlyContinue
if ($null -eq $Cl) {
    throw "cl.exe not found. Run from a Visual Studio Developer PowerShell."
}

cl.exe /nologo /W4 /O2 /Fe:$Zap scripts\lab\ioctl_zap.c

ssh -i $Key "$User@$HostName" "powershell -NoProfile -Command New-Item -ItemType Directory -Force -Path '$Remote' | Out-Null"
scp -i $Key $Zap "${User}@${HostName}:$Remote\ioctl_zap.exe"
scp -i $Key $IoctlJson "${User}@${HostName}:$Remote\ioctl.json"

Write-Host "deployed $Zap and $IoctlJson to ${HostName}:$Remote"
