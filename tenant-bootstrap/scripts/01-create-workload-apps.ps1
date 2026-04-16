param(
  [Parameter(Mandatory)][string]$ConfigPath,
  [string]$RunName,
  [string]$RunDirectory,
  [switch]$DryRun
)

. "$PSScriptRoot/00-shared.ps1" -ConfigPath $ConfigPath -RunName $RunName -RunDirectory $RunDirectory

Initialize-BootstrapSession -ConfigPath $ConfigPath -RunName $RunName -RunDirectory $RunDirectory | Out-Null

function Ensure-AppRegistration {
  param(
    [string]$DisplayName,
    [string]$Description
  )

  $existing = Get-MgApplication -Filter "displayName eq '$($DisplayName.Replace("'", "''"))'" -ErrorAction SilentlyContinue
  if ($existing) {
    Write-BootstrapEvent -Message "app.alreadyExists" -Status "success" -Step "apps" -Details @{name=$DisplayName; appId=$existing.AppId}
    return $existing
  }

  if ($DryRun) {
    Write-BootstrapEvent -Message "app.wouldCreate" -Status "success" -Step "apps" -Details @{name=$DisplayName; description=$Description}
    return $null
  }

  Invoke-BootstrapCommand -Name "create-application" -Module "graph" -Step "apps" -Action {
    New-MgApplication -DisplayName $DisplayName -Description $Description -SignInAudience AzureADMyOrg
  } | ForEach-Object {
    Write-BootstrapEvent -Message "app.created" -Status "success" -Step "apps" -Details @{name=$DisplayName; appId=$_.AppId}

    New-MgServicePrincipal -AppId $_.AppId | Out-Null
    Write-BootstrapEvent -Message "servicePrincipal.created" -Status "success" -Step "apps" -Details @{name=$DisplayName; appId=$_.AppId}
    return $_
  }
}

$cfg = $global:BootstrapSession.Config
if ($DryRun) {
  Write-BootstrapEvent -Message "auth.skipped" -Status "success" -Step "apps" -Details @{reason = "dry-run"}
} else {
  Connect-BootstrapGraph
}

$apps = @(
  @{name="audit-bootstrap"; desc="Tenant bootstrap orchestrator"},
  @{name="audit-seed-data"; desc="Data seeding workload"},
  @{name="audit-reporting"; desc="Read-only reporting workload"}
)

foreach ($app in $apps) {
  Ensure-AppRegistration -DisplayName $app.name -Description $app.desc
}

Write-BootstrapEvent -Message "apps.instructions" -Status "warn" -Step "apps" -Details @{
  message = "Admin consent and cert credential wiring must be completed in Entra Admin Center for least-privilege operation."
}

End-BootstrapSession
