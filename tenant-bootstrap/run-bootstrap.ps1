param(
  [Parameter(Mandatory)][string]$ConfigPath,
  [string]$TenantName,
  [switch]$RunApps = $true,
  [switch]$RunIdentity = $true,
  [switch]$RunLicensing = $true,
  [switch]$RunExchange = $true,
  [switch]$RunTeams = $true,
  [switch]$RunSharepoint = $true,
  [switch]$RunSampleData = $true,
  [switch]$RunSecurity = $true,
  [switch]$RunEvidence = $false,
  [switch]$DryRun,
  [string]$RunName = ""
)

$scripts = @()

if ($RunApps) { $scripts += "01-create-workload-apps.ps1" }
if ($RunIdentity) { $scripts += "02-seed-identities-groups.ps1" }
if ($RunLicensing) { $scripts += "03-seed-licenses.ps1" }
if ($RunExchange) { $scripts += "04-seed-exchange.ps1" }
if ($RunTeams) { $scripts += "05-seed-teams.ps1" }
if ($RunSharepoint) { $scripts += "06-seed-sharepoint-intune.ps1" }
if ($RunSampleData) { $scripts += "07-seed-sample-data.ps1" }
if ($RunSecurity) { $scripts += "08-secure-baseline.ps1" }
if ($RunEvidence) { $scripts += "09-collect-evidence.ps1" }

$sharedConfig = Get-Content -Path $ConfigPath -Raw | ConvertFrom-Json
if (-not $sharedConfig.tenant.tenantName) {
  throw "tenant.tenantName is required in config."
}

$runName = if ($RunName) { $RunName } else { "bootstrap-{0}" -f (Get-Date -Format "yyyyMMdd_HHmmss") }
$runDirectory = Join-Path $PSScriptRoot "runs/$runName"
if (-not (Test-Path $runDirectory)) { New-Item -Path $runDirectory -ItemType Directory -Force | Out-Null }

$runtimeConfigPath = $ConfigPath
if ($TenantName) {
  $sharedConfig.tenant.tenantName = $TenantName
  $runtimeConfigPath = Join-Path $runDirectory "config.runtime.json"
  $sharedConfig | ConvertTo-Json -Depth 20 | Set-Content -Path $runtimeConfigPath -NoNewline
}


foreach ($script in $scripts) {
  $path = Join-Path $PSScriptRoot "scripts/$script"
  if (Test-Path $path) {
    & $path -ConfigPath $runtimeConfigPath -RunName $runName -RunDirectory $runDirectory -DryRun:$DryRun
  }
}
