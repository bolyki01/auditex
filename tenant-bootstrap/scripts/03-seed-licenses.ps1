param(
  [Parameter(Mandatory)][string]$ConfigPath,
  [string]$RunName,
  [string]$RunDirectory,
  [switch]$DryRun
)

. "$PSScriptRoot/00-shared.ps1" -ConfigPath $ConfigPath -RunName $RunName -RunDirectory $RunDirectory
Initialize-BootstrapSession -ConfigPath $ConfigPath -RunName $RunName -RunDirectory $RunDirectory | Out-Null

$cfg = $global:BootstrapSession.Config
if ($DryRun) {
  Write-BootstrapEvent -Message "auth.skipped" -Status "success" -Step "licensing" -Details @{reason = "dry-run"}
} else {
  Connect-BootstrapGraph
}

function Resolve-SkuByPattern {
  param([string]$Pattern)
  $subscribedSkus = Invoke-MgGraphRequest -Method GET -Uri "https://graph.microsoft.com/v1.0/subscribedSkus"
  $match = $subscribedSkus.value | Where-Object {
    $_.skuPartNumber -like "*$Pattern*" -or $_.skuId -like "*$Pattern*"
  } | Select-Object -First 1
  if (-not $match) {
    throw "No matching SKU found for pattern '$Pattern'."
  }
  return $match
}

function Assign-LicenseToGroup {
  param(
    [string]$GroupDisplay,
    [string]$SkuPattern,
    [string[]]$DisabledPlans = @()
  )
  $group = Get-MgGroup -Filter "displayName eq '$($GroupDisplay.Replace("'", "''"))'" -ErrorAction SilentlyContinue
  if (-not $group) {
    throw "Missing target group '$GroupDisplay'."
  }
  $sku = Resolve-SkuByPattern -Pattern $SkuPattern
  $payload = @{
    addLicenses = @(@{
      disabledPlans = $DisabledPlans
      skuId = $sku.skuId
    })
    removeLicenses = @()
  } | ConvertTo-Json -Depth 10

  if ($DryRun) {
    Write-BootstrapEvent -Message "license.wouldAssign" -Status "success" -Step "licensing" -Details @{group=$GroupDisplay; sku=$SkuPattern}
    return
  }

  Invoke-BootstrapCommand -Name "assign-license-$GroupDisplay" -Module "graph" -Step "licensing" -Action {
    Invoke-MgGraphRequest -Method POST -Uri "https://graph.microsoft.com/v1.0/groups/$($group.Id)/assignLicense" -Body $payload
  } | Out-Null
}

function Assign-LicenseToUser {
  param(
    [string]$UserAliasOrUpn,
    [string]$SkuPattern,
    [string[]]$DisabledPlans = @()
  )
  if ([string]::IsNullOrWhiteSpace($UserAliasOrUpn) -or [string]::IsNullOrWhiteSpace($SkuPattern)) {
    Write-BootstrapEvent -Message "license.user.skip" -Status "success" -Step "licensing" -Details @{reason="not-configured"}
    return
  }

  $upn = if ($UserAliasOrUpn -like "*@*") { $UserAliasOrUpn } else { "$UserAliasOrUpn@$($cfg.tenant.tenantDomain)" }
  $user = Get-MgUser -Filter "userPrincipalName eq '$($upn.Replace("'", "''"))'" -Property "id,userPrincipalName,assignedLicenses" -ErrorAction SilentlyContinue
  if (-not $user) {
    Write-BootstrapEvent -Message "license.user.skip" -Status "warn" -Step "licensing" -Details @{reason="target-user-missing"; userPrincipalName=$upn}
    return
  }

  $sku = Resolve-SkuByPattern -Pattern $SkuPattern
  if ($user.AssignedLicenses | Where-Object { $_.SkuId -eq $sku.skuId }) {
    Write-BootstrapEvent -Message "license.user.alreadyAssigned" -Status "success" -Step "licensing" -Details @{userPrincipalName=$upn; sku=$SkuPattern}
    return
  }

  $available = [int]$sku.prepaidUnits.enabled - [int]$sku.consumedUnits
  if ($available -lt 1) {
    Write-BootstrapEvent -Message "license.user.skip" -Status "warn" -Step "licensing" -Details @{reason="no-available-seats"; userPrincipalName=$upn; sku=$SkuPattern}
    return
  }

  $payload = @{
    addLicenses = @(@{
      disabledPlans = $DisabledPlans
      skuId = $sku.skuId
    })
    removeLicenses = @()
  } | ConvertTo-Json -Depth 10

  if ($DryRun) {
    Write-BootstrapEvent -Message "license.user.wouldAssign" -Status "success" -Step "licensing" -Details @{userPrincipalName=$upn; sku=$SkuPattern}
    return
  }

  Invoke-BootstrapCommand -Name "assign-license-user-$upn" -Module "graph" -Step "licensing" -Action {
    Invoke-MgGraphRequest -Method POST -Uri "https://graph.microsoft.com/v1.0/users/$($user.Id)/assignLicense" -Body $payload
  } | Out-Null
}

function Get-MailboxSeedAliases {
  $aliases = New-Object System.Collections.Generic.List[string]
  if ($cfg.actors.dailyUser) { $aliases.Add([string]$cfg.actors.dailyUser) }
  if ($cfg.actors.namedAdmin) { $aliases.Add([string]$cfg.actors.namedAdmin) }
  foreach ($department in $cfg.departments) {
    $count = [int]$cfg.departmentDistribution.$department
    for ($index = 1; $index -le $count; $index++) {
      $aliases.Add(("{0}.{1:D2}.staff" -f ([string]$department).ToLowerInvariant(), $index))
    }
  }

  $excluded = @{}
  foreach ($alias in @($cfg.licenses.mailboxSeedExcludeAliases) + @($cfg.actors.breakGlassUsers)) {
    if ($alias) { $excluded[[string]$alias.ToLowerInvariant()] = $true }
  }

  $seen = @{}
  $result = New-Object System.Collections.Generic.List[string]
  foreach ($alias in $aliases) {
    if (-not $alias) { continue }
    $key = [string]$alias.ToLowerInvariant()
    if ($excluded.ContainsKey($key) -or $seen.ContainsKey($key)) { continue }
    $seen[$key] = $true
    $result.Add($alias)
  }
  return $result
}

function Assign-MailboxSeedLicenses {
  if ([string]::IsNullOrWhiteSpace($cfg.licenses.mailboxSeed)) {
    Write-BootstrapEvent -Message "license.mailboxSeed.skip" -Status "success" -Step "licensing" -Details @{reason="not-configured"}
    return
  }

  $sku = Resolve-SkuByPattern -Pattern $cfg.licenses.mailboxSeed
  $available = [int]$sku.prepaidUnits.enabled - [int]$sku.consumedUnits
  if ($available -lt 1) {
    Write-BootstrapEvent -Message "license.mailboxSeed.skip" -Status "warn" -Step "licensing" -Details @{reason="no-available-seats"; sku=$cfg.licenses.mailboxSeed}
    return
  }

  $maxUsers = if ($cfg.licenses.mailboxSeedMaxUsers) { [int]$cfg.licenses.mailboxSeedMaxUsers } else { $available }
  $targetAliases = @(Get-MailboxSeedAliases | Select-Object -First $maxUsers)
  $assigned = 0
  $alreadyAssigned = 0
  $skipped = 0
  foreach ($alias in $targetAliases) {
    if ($assigned -ge $available) {
      $skipped += 1
      Write-BootstrapEvent -Message "license.mailboxSeed.skipUser" -Status "warn" -Step "licensing" -Details @{reason="seat-limit-reached"; alias=$alias; sku=$cfg.licenses.mailboxSeed}
      continue
    }
    $upn = if ($alias -like "*@*") { $alias } else { "$alias@$($cfg.tenant.tenantDomain)" }
    $user = Get-MgUser -Filter "userPrincipalName eq '$($upn.Replace("'", "''"))'" -Property "id,userPrincipalName,assignedLicenses" -ErrorAction SilentlyContinue
    if (-not $user) {
      $skipped += 1
      Write-BootstrapEvent -Message "license.mailboxSeed.skipUser" -Status "warn" -Step "licensing" -Details @{reason="target-user-missing"; userPrincipalName=$upn}
      continue
    }
    if ($user.AssignedLicenses | Where-Object { $_.SkuId -eq $sku.skuId }) {
      $alreadyAssigned += 1
      Write-BootstrapEvent -Message "license.mailboxSeed.alreadyAssigned" -Status "success" -Step "licensing" -Details @{userPrincipalName=$upn; sku=$cfg.licenses.mailboxSeed}
      continue
    }

    Assign-LicenseToUser -UserAliasOrUpn $upn -SkuPattern $cfg.licenses.mailboxSeed
    $assigned += 1
  }

  Write-BootstrapEvent -Message "license.mailboxSeed.summary" -Status "success" -Step "licensing" -Details @{sku=$cfg.licenses.mailboxSeed; targeted=$targetAliases.Count; assigned=$assigned; alreadyAssigned=$alreadyAssigned; skipped=$skipped; availableAtStart=$available}
}

Invoke-BootstrapCommand -Name "assign-base-license" -Module "graph" -Step "licensing" -Action {
  Assign-LicenseToGroup -GroupDisplay $cfg.groupNames.allUsers -SkuPattern $cfg.licenses.base
}

Invoke-BootstrapCommand -Name "assign-copilot-license" -Module "graph" -Step "licensing" -Action {
  Assign-LicenseToGroup -GroupDisplay $cfg.groupNames.copilotPilot -SkuPattern $cfg.licenses.copilotPilot
}

Invoke-BootstrapCommand -Name "assign-bi-license" -Module "graph" -Step "licensing" -Action {
  Assign-LicenseToGroup -GroupDisplay $cfg.groupNames.reporting -SkuPattern $cfg.licenses.powerBi
}

Invoke-BootstrapCommand -Name "assign-entraP2-license" -Module "graph" -Step "licensing" -Action {
  Assign-LicenseToGroup -GroupDisplay $cfg.groupNames.entraP2 -SkuPattern $cfg.licenses.entraP2
}

Invoke-BootstrapCommand -Name "assign-cloudpc-business-license" -Module "graph" -Step "licensing" -Action {
  Assign-LicenseToUser -UserAliasOrUpn $cfg.licenses.cloudPcBusinessUser -SkuPattern $cfg.licenses.cloudPcBusiness
}

Invoke-BootstrapCommand -Name "assign-mailbox-seed-licenses" -Module "graph" -Step "licensing" -Action {
  Assign-MailboxSeedLicenses
}

Write-BootstrapEvent -Message "licenses.done" -Status "success" -Step "licensing" -Details @{base=$cfg.groupNames.allUsers; copilot=$cfg.groupNames.copilotPilot; reporting=$cfg.groupNames.reporting}

End-BootstrapSession
