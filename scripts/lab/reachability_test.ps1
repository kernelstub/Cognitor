param(
    [ValidateSet("noob", "exp", "both")]
    [string]$Persona = "both",
    [string]$IoctlJson = "ioctl.json",
    [string]$Log = "ioctl_zap.log",
    [switch]$DryRun
)

$ErrorActionPreference = "Stop"

function Require-Env($Name) {
    $Value = [Environment]::GetEnvironmentVariable($Name)
    if ([string]::IsNullOrWhiteSpace($Value)) {
        throw "Missing environment variable $Name. See scripts\lab\env.example.ps1."
    }
    return $Value
}

$Device = Require-Env "COGNITOR_LAB_DEVICE"
$Exe = ".\ioctl_zap.exe"
if (!(Test-Path $Exe)) {
    throw "$Exe not found. Run scripts\lab\build_deploy.ps1 first or copy ioctl_zap.exe here."
}

$Personas = @($Persona)
if ($Persona -eq "both") {
    $Personas = @("noob", "exp")
}

$Identity = [Security.Principal.WindowsIdentity]::GetCurrent()
$Principal = [Security.Principal.WindowsPrincipal]::new($Identity)
$IsAdmin = $Principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

foreach ($Current in $Personas) {
    if ($Current -eq "exp" -and !$IsAdmin) {
        throw "exp reachability requires an elevated PowerShell so output can be captured in $Log."
    }
    $Args = @("--device", $Device, "--ioctls", $IoctlJson, "--persona", $Current)
    if ($DryRun) {
        $Args += "--dry-run"
    }
    & $Exe @Args 2>&1 | Tee-Object -FilePath $Log -Append
}
