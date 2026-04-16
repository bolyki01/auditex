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
  Write-BootstrapEvent -Message "graph.connect.skipped-dryrun" -Status "success" -Step "auth" -Details @{reason = "identity dry-run does not query tenant"}
} else {
  Connect-BootstrapGraph
}

$defaultEnterpriseScale = @{
  enabled = $true
  departmentSecurityGroupsPerDepartment = 14
  departmentM365GroupsPerDepartment = 1
  departmentServiceGroupsPerDepartment = 2
  functionGroupsPerFunction = 2
  resourceOwnerGroups = 20
  policyAndProgramGroups = 30
  overshareSignalGroups = 10
  geoRegionGroups = 8
  functionFamilies = @(
    "CloudOps",
    "DataOps",
    "Compliance",
    "Identity",
    "Finance",
    "HR",
    "Support",
    "Legal",
    "Procurement",
    "Risk",
    "Security",
    "Dev",
    "Engineering",
    "Workforce",
    "SalesEnablement",
    "Incident",
    "Operations",
    "Governance"
  )
  geoCodes = @("NA", "EMEA", "APAC", "LATAM", "USC", "USE", "CAN", "IN", "AUS", "UK", "BR", "MEA")
}

function Get-EnterpriseScaleConfig {
  param([psobject]$Config, [hashtable]$Default)
  $scale = $Default.Clone()

  if (-not $Config.enterpriseScale) {
    return $scale
  }

  if ($Config.enterpriseScale.PSObject.Properties["enabled"]) {
    $scale["enabled"] = [bool]$Config.enterpriseScale.enabled
  }
  if ($Config.enterpriseScale.PSObject.Properties["profile"]) {
    $profile = $Config.enterpriseScale.profile
    if ($profile) {
      foreach ($key in "departmentSecurityGroupsPerDepartment","departmentM365GroupsPerDepartment","departmentServiceGroupsPerDepartment","functionGroupsPerFunction","resourceOwnerGroups","policyAndProgramGroups","overshareSignalGroups","geoRegionGroups") {
        if ($profile.PSObject.Properties[$key] -and ($null -ne $profile.$key)) {
          $value = [int]$profile.$key
          if ($value -gt 0) {
            $scale[$key] = $value
          }
        }
      }
    }
  }

  if ($Config.enterpriseScale.PSObject.Properties["functionFamilies"] -and $Config.enterpriseScale.functionFamilies) {
    $scale["functionFamilies"] = @($Config.enterpriseScale.functionFamilies)
  }
  if ($Config.enterpriseScale.PSObject.Properties["geoCodes"] -and $Config.enterpriseScale.geoCodes) {
    $scale["geoCodes"] = @($Config.enterpriseScale.geoCodes)
  }

  return $scale
}

function To-GroupToken {
  param([string]$Value)
  if ([string]::IsNullOrWhiteSpace($Value)) { return "GEN" }
  $token = [regex]::Replace($Value.ToUpper(), "[^A-Z0-9]", "")
  if ([string]::IsNullOrWhiteSpace($token)) { return "GEN" }
  return $token
}

function New-MailNickNameSafe {
  param([string]$DisplayName)
  $mailNick = [regex]::Replace($DisplayName.ToLower(), "[^a-z0-9]", "")
  if ([string]::IsNullOrWhiteSpace($mailNick)) {
    $mailNick = "group-" + [guid]::NewGuid().ToString("N").Substring(0, 8)
  }
  if ($mailNick.Length -gt 56) {
    $mailNick = $mailNick.Substring(0, 56)
  }
  return $mailNick
}

function Ensure-Group {
  param([string]$DisplayName, [string]$Type)
  if ($DryRun) {
    Write-BootstrapEvent -Message "group.wouldCreate" -Status "success" -Step "identity" -Details @{group = $DisplayName; type = $Type}
    return $null
  }
  $existing = Get-MgGroup -Filter "displayName eq '$($DisplayName.Replace("'", "''"))'" -ErrorAction SilentlyContinue
  if ($existing) {
    Write-BootstrapEvent -Message "group.exists" -Status "success" -Step "identity" -Details @{group = $DisplayName; type = $Type}
    return $existing
  }

  Invoke-BootstrapCommand -Name "create-group-$DisplayName" -Module "graph" -Step "identity" -Action {
    if ($Type -eq "m365") {
      New-MgGroup -DisplayName $DisplayName -MailEnabled $true -MailNickName (New-MailNickNameSafe -DisplayName $DisplayName) -SecurityEnabled $false -GroupTypes @("Unified")
    } else {
      New-MgGroup -DisplayName $DisplayName -MailEnabled $false -SecurityEnabled $true
    }
  }
}

function Ensure-DynamicGroup {
  param([string]$DisplayName, [string]$Rule)
  if ($DryRun) {
    Write-BootstrapEvent -Message "group.wouldCreate" -Status "success" -Step "identity" -Details @{group = $DisplayName; type = "dynamic"}
    return $null
  }
  $existing = Get-MgGroup -Filter "displayName eq '$($DisplayName.Replace("'", "''"))'" -ErrorAction SilentlyContinue
  if ($existing) {
    Write-BootstrapEvent -Message "group.exists" -Status "success" -Step "identity" -Details @{group = $DisplayName; type = "dynamic"}
    return $existing
  }

  Invoke-BootstrapCommand -Name "create-dynamic-group-$DisplayName" -Module "graph" -Step "identity" -Action {
    New-MgGroup -DisplayName $DisplayName -MailEnabled $false -SecurityEnabled $true -GroupTypes @("DynamicMembership") -MembershipRule $Rule -MembershipRuleProcessingState "On"
  }
}

function Ensure-User {
  param([string]$Alias, [string]$DisplayName, [string]$Department, [string]$JobTitle, [bool]$IsGuest = $false)
  $upn = Get-Upn -Alias $Alias
  if ($DryRun) {
    Write-BootstrapEvent -Message "user.wouldCreate" -Status "success" -Step "identity" -Details @{upn = $upn}
    return $null
  }
  $existing = Get-MgUser -Filter "userPrincipalName eq '$upn'" -ErrorAction SilentlyContinue
  if ($existing) {
    Write-BootstrapEvent -Message "user.exists" -Status "success" -Step "identity" -Details @{upn = $upn}
    return $existing
  }

  if ($IsGuest) {
    Invoke-BootstrapCommand -Name "create-guest-$Alias" -Module "graph" -Step "identity" -Action {
      New-MgInvitation -InvitedUserEmailAddress "$Alias@$($cfg.tenant.tenantDomain)" -InviteRedirectUrl "https://myapplications.microsoft.com" -SendInvitationMessage $true -InvitedUserDisplayName $DisplayName
    } | Out-Null
    return Get-MgUser -Filter "mail eq '$Alias@$($cfg.tenant.tenantDomain)'" -ErrorAction SilentlyContinue
  }

  $passwordProfile = @{
    Password = New-SamplePassword
    ForceChangePasswordNextSignIn = $true
  }

  Invoke-BootstrapCommand -Name "create-user-$Alias" -Module "graph" -Step "identity" -Action {
    New-MgUser -DisplayName $DisplayName -GivenName $DisplayName.Split(" ")[0] -Surname $DisplayName.Split(" ")[-1] -UserPrincipalName $upn -MailNickName ($Alias.Replace(".", "")) -UsageLocation $cfg.tenant.usageLocation -Department $Department -JobTitle $JobTitle -AccountEnabled $true -PasswordProfile $passwordProfile -PasswordPolicies "DisableStrongPassword"
  }
}

function Build-UserRecord {
  param([string]$Alias, [string]$DisplayName, [string]$Department, [string]$JobTitle, [bool]$IsGuest = $false)
  $user = Ensure-User -Alias $Alias -DisplayName $DisplayName -Department $Department -JobTitle $JobTitle -IsGuest $IsGuest
  if (-not $user) {
    return $null
  }

  $upn = if ($user.UserPrincipalName) { $user.UserPrincipalName } else { Get-Upn -Alias $Alias }
  return [PSCustomObject]@{
    Alias = $Alias
    Upn = $upn
    UserId = $user.Id
    Department = $Department
    JobTitle = $JobTitle
    IsGuest = $IsGuest
  }
}

function Add-GroupDef {
  param([object]$List, [hashtable]$Seen, [string]$DisplayName, [string]$Type, [string]$Category)
  if (-not $Seen.ContainsKey($DisplayName)) {
    $List.Add([PSCustomObject]@{
      DisplayName = $DisplayName
      Type = $Type
      Category = $Category
    })
    $Seen[$DisplayName] = $true
  }
}

function Build-EnterpriseGroupDefs {
  param([hashtable]$Scale)
  $defs = [System.Collections.Generic.List[object]]::new()
  $seen = @{}

  foreach ($dept in $cfg.departments) {
    $deptToken = To-GroupToken $dept
    for ($i = 1; $i -le $Scale["departmentSecurityGroupsPerDepartment"]; $i++) {
      $suffix = "{0:D2}" -f $i
      Add-GroupDef -List $defs -Seen $seen -DisplayName "SG-$deptToken-APP-$suffix" -Type "security" -Category "department-security"
    }
    for ($i = 1; $i -le $Scale["departmentM365GroupsPerDepartment"]; $i++) {
      $suffix = "{0:D2}" -f $i
      Add-GroupDef -List $defs -Seen $seen -DisplayName "MG-$deptToken-COLLAB-$suffix" -Type "m365" -Category "department-collab"
    }
    for ($i = 1; $i -le $Scale["departmentServiceGroupsPerDepartment"]; $i++) {
      $suffix = "{0:D2}" -f $i
      Add-GroupDef -List $defs -Seen $seen -DisplayName "SG-$deptToken-SVC-$suffix" -Type "security" -Category "department-service"
    }
  }

  for ($iFamily = 0; $iFamily -lt $Scale["functionFamilies"].Count; $iFamily++) {
    $family = $Scale["functionFamilies"][$iFamily]
    $familyToken = To-GroupToken $family
    for ($i = 1; $i -le $Scale["functionGroupsPerFunction"]; $i++) {
      $suffix = "{0:D2}" -f $i
      if ($i % 2 -eq 0) {
        Add-GroupDef -List $defs -Seen $seen -DisplayName "SG-FUNC-$familyToken-WORK-$suffix" -Type "security" -Category "function-security"
      } else {
        Add-GroupDef -List $defs -Seen $seen -DisplayName "MG-FUNC-$familyToken-WORK-$suffix" -Type "m365" -Category "function-collab"
      }
    }
  }

  for ($i = 1; $i -le $Scale["resourceOwnerGroups"]; $i++) {
    $suffix = "{0:D2}" -f $i
    if ($i % 2 -eq 0) {
      Add-GroupDef -List $defs -Seen $seen -DisplayName "SG-OWNER-RSRC-$suffix" -Type "security" -Category "resource-owner"
    } else {
      Add-GroupDef -List $defs -Seen $seen -DisplayName "MG-OWNER-RSRC-$suffix" -Type "m365" -Category "resource-owner"
    }
  }

  for ($i = 1; $i -le $Scale["policyAndProgramGroups"]; $i++) {
    $suffix = "{0:D2}" -f $i
    if ($i % 2 -eq 0) {
      Add-GroupDef -List $defs -Seen $seen -DisplayName "SG-PROG-POLICY-$suffix" -Type "security" -Category "policy-program"
    } else {
      Add-GroupDef -List $defs -Seen $seen -DisplayName "MG-PROG-GOV-$suffix" -Type "m365" -Category "policy-program"
    }
  }

  for ($i = 1; $i -le $Scale["overshareSignalGroups"]; $i++) {
    $suffix = "{0:D2}" -f $i
    if ($i % 2 -eq 0) {
      Add-GroupDef -List $defs -Seen $seen -DisplayName "MG-RISK-MISSHARE-$suffix" -Type "m365" -Category "overshare"
    } else {
      Add-GroupDef -List $defs -Seen $seen -DisplayName "SG-RISK-OVERSHARE-$suffix" -Type "security" -Category "overshare"
    }
  }

  for ($i = 0; $i -lt $Scale["geoRegionGroups"]; $i++) {
    $region = $Scale["geoCodes"][$i % $Scale["geoCodes"].Count]
    $suffix = "{0:D2}" -f ($i + 1)
    if ($i % 3 -eq 0) {
      Add-GroupDef -List $defs -Seen $seen -DisplayName "SG-GEO-$region-OPS-$suffix" -Type "security" -Category "geo-region"
    } elseif ($i % 3 -eq 1) {
      Add-GroupDef -List $defs -Seen $seen -DisplayName "MG-GEO-$region-INT-$suffix" -Type "m365" -Category "geo-region"
    } else {
      Add-GroupDef -List $defs -Seen $seen -DisplayName "SG-GEO-$region-POLICY-$suffix" -Type "security" -Category "geo-region"
    }
  }

  return $defs
}

function Escape-RuleValue {
  param([string]$Value)
  return $Value.Replace("'", "''")
}

function Get-DepartmentSeedCount {
  param([string]$Department)
  if ($cfg.departmentDistribution -and $cfg.departmentDistribution.PSObject.Properties[$Department]) {
    return [int]$cfg.departmentDistribution.PSObject.Properties[$Department].Value
  }
  return 0
}

function Add-SafeGroupMember {
  param([string]$GroupDisplay, [string]$GroupId, [string]$UserId, [string]$UserUpn)
  if (-not $GroupId -or -not $UserId) {
    return
  }
  if ($DryRun) {
    Write-BootstrapEvent -Message "group.member.wouldAdd" -Status "success" -Step "identity" -Details @{group=$GroupDisplay; upn=$UserUpn}
    return
  }

  Invoke-BootstrapCommand -Name "group-member-$GroupDisplay-$UserId" -Module "graph" -Step "identity" -Action {
    try {
      New-MgGroupMember -GroupId $GroupId -DirectoryObjectId $UserId -ErrorAction Stop
    } catch {
      if ($_.Exception.Message -and $_.Exception.Message -match "already exist|already a member|already exists|Conflict") {
        Write-BootstrapEvent -Message "group.member.exists" -Status "success" -Step "identity" -Details @{group=$GroupDisplay; upn=$UserUpn}
      } else {
        throw
      }
    }
  } | Out-Null
}

$enterpriseScale = Get-EnterpriseScaleConfig -Config $cfg -Default $defaultEnterpriseScale

$userRecords = Invoke-BootstrapCommand -Name "ensure-core-users" -Module "graph" -Step "identity" -Action {
  $records = @()
  $roleRotation = @(
    "Director",
    "Manager",
    "Senior Analyst",
    "Specialist",
    "Security Lead",
    "Cloud Operator",
    "Engineer",
    "Compliance Analyst",
    "Support Specialist",
    "Account Executive",
    "Data Analyst",
    "SRE"
  )

  $records += Build-UserRecord -Alias $cfg.actors.dailyUser -DisplayName "Daily Operations" -Department "IT" -JobTitle "Cloud Operator"
  $records += Build-UserRecord -Alias $cfg.actors.namedAdmin -DisplayName "Named Admin" -Department "IT" -JobTitle "Security Lead"

  foreach ($alias in $cfg.actors.breakGlassUsers) {
    $records += Build-UserRecord -Alias $alias -DisplayName "Break Glass $alias" -Department "Exec" -JobTitle "Emergency Account"
  }

  $staffIndex = 0
  foreach ($dept in $cfg.departments) {
    $count = Get-DepartmentSeedCount -Department $dept
    for ($i = 1; $i -le $count; $i++) {
      $alias = "{0}.{1:00}.staff" -f $dept.ToLower(), $i
      $job = $roleRotation[$staffIndex % $roleRotation.Count]
      $records += Build-UserRecord -Alias $alias -DisplayName "$dept $job $i" -Department $dept -JobTitle $job
      $staffIndex++
    }
  }

  for ($i = 1; $i -le $cfg.counts.targetGuests; $i++) {
    $records += Build-UserRecord -Alias "guest.$i.partner" -DisplayName "Partner Guest $i" -Department "External" -JobTitle "Contractor" -IsGuest $true
  }

  return $records
}

$internalUserRecords = @($userRecords | Where-Object { $_ -and -not $_.IsGuest })
$guestUserRecords = @($userRecords | Where-Object { $_ -and $_.IsGuest })
$expectedInternalUsers = 2 + $cfg.actors.breakGlassUsers.Count
foreach ($dept in $cfg.departments) {
  $expectedInternalUsers += Get-DepartmentSeedCount -Department $dept
}
$expectedGuestUsers = [int]$cfg.counts.targetGuests
$effectiveInternalUsers = if ($internalUserRecords.Count -gt 0) { $internalUserRecords.Count } else { $expectedInternalUsers }
$effectiveGuestUsers = if ($guestUserRecords.Count -gt 0) { $guestUserRecords.Count } else { $expectedGuestUsers }

$groupDefs = [System.Collections.Generic.List[object]]::new()
$seenGroupNames = @{}

Add-GroupDef -List $groupDefs -Seen $seenGroupNames -DisplayName $cfg.groupNames.allUsers -Type "security" -Category "core"
Add-GroupDef -List $groupDefs -Seen $seenGroupNames -DisplayName $cfg.groupNames.admins -Type "security" -Category "core"
Add-GroupDef -List $groupDefs -Seen $seenGroupNames -DisplayName $cfg.groupNames.breakGlass -Type "security" -Category "core"
Add-GroupDef -List $groupDefs -Seen $seenGroupNames -DisplayName $cfg.groupNames.copilotPilot -Type "security" -Category "core"
Add-GroupDef -List $groupDefs -Seen $seenGroupNames -DisplayName $cfg.groupNames.reporting -Type "security" -Category "core"
Add-GroupDef -List $groupDefs -Seen $seenGroupNames -DisplayName $cfg.groupNames.entraP2 -Type "security" -Category "core"
Add-GroupDef -List $groupDefs -Seen $seenGroupNames -DisplayName $cfg.groupNames.itM365 -Type "m365" -Category "core"
Add-GroupDef -List $groupDefs -Seen $seenGroupNames -DisplayName $cfg.groupNames.salesM365 -Type "m365" -Category "core"
Add-GroupDef -List $groupDefs -Seen $seenGroupNames -DisplayName $cfg.groupNames.financeM365 -Type "m365" -Category "core"

if ($enterpriseScale["enabled"]) {
  foreach ($def in Build-EnterpriseGroupDefs -Scale $enterpriseScale) {
    Add-GroupDef -List $groupDefs -Seen $seenGroupNames -DisplayName $def.DisplayName -Type $def.Type -Category $def.Category
  }
}

$dynamicGroupDefs = @()
if ($enterpriseScale["enabled"]) {
  $dynamicGroupDefs += @{DisplayName = "DG-GUEST-ACCOUNTS"; Rule = 'user.userType -eq "Guest"'}
  $dynamicGroupDefs += @{DisplayName = "DG-HIGH-RISK-IT-ADMIN"; Rule = '(user.department -eq "IT") -or (user.jobTitle -eq "Security Lead")'}
  $dynamicGroupDefs += @{DisplayName = "DG-PERMIT-ALL-DEVICES"; Rule = 'user.jobTitle -eq "Cloud Operator"'}
  $dynamicGroupDefs += @{DisplayName = "DG-EXTERNAL-PARTNER-OVERPRIV"; Rule = '(user.userType -eq "Guest") -and (user.jobTitle -eq "Contractor")'}

  foreach ($dept in $cfg.departments) {
    $safeDept = Escape-RuleValue -Value $dept
    $dynamicGroupDefs += @{DisplayName = "DG-DEPT-$([regex]::Replace($dept.ToUpper(), '[^A-Z0-9]', ''))-USERS"; Rule = "user.department -eq `"$safeDept`""}
  }

  $titlePatterns = @("Manager", "Director", "Lead", "Analyst", "Specialist", "Architect", "Engineer", "Coordinator", "Advisor")
  foreach ($title in $titlePatterns) {
    $safeTitle = Escape-RuleValue -Value $title
    $dynamicGroupDefs += @{DisplayName = "DG-TITLE-$([regex]::Replace($title.ToUpper(), '[^A-Z0-9]', ''))"; Rule = "user.jobTitle -eq `"$safeTitle`""}
  }
}

Invoke-BootstrapCommand -Name "ensure-groups" -Module "graph" -Step "identity" -Action {
  foreach ($def in $groupDefs) {
    Ensure-Group -DisplayName $def.DisplayName -Type $def.Type | Out-Null
  }
  foreach ($entry in $dynamicGroupDefs) {
    Ensure-DynamicGroup -DisplayName $entry.DisplayName -Rule $entry.Rule
  }
}

if ($DryRun) {
  Write-BootstrapEvent -Message "identity.seed.summary" -Status "success" -Step "identity" -Details @{
    users = $effectiveInternalUsers
    guests = $effectiveGuestUsers
    staticGroups = $groupDefs.Count
    dynamicGroups = $dynamicGroupDefs.Count
    enterpriseScale = $enterpriseScale["enabled"]
  }
  End-BootstrapSession
  return
}

$allUsersGroupId = Get-GroupId -DisplayName $cfg.groupNames.allUsers
$adminGroupId = Get-GroupId -DisplayName $cfg.groupNames.admins
$breakGlassGroupId = Get-GroupId -DisplayName $cfg.groupNames.breakGlass
$copilotGroupId = Get-GroupId -DisplayName $cfg.groupNames.copilotPilot
$p2GroupId = Get-GroupId -DisplayName $cfg.groupNames.entraP2
$reportGroupId = Get-GroupId -DisplayName $cfg.groupNames.reporting

Invoke-BootstrapCommand -Name "seed-group-membership" -Module "graph" -Step "identity" -Action {
  if ($userRecords.Count -eq 0) {
    throw "No user identities were created or found."
  }

  $departmentUsers = @{}
  foreach ($dept in $cfg.departments) {
    $departmentUsers[$dept] = @()
  }
  foreach ($rec in $internalUserRecords) {
    if ($departmentUsers.ContainsKey($rec.Department)) {
      $departmentUsers[$rec.Department] += $rec
    }
    Add-SafeGroupMember -GroupDisplay $cfg.groupNames.allUsers -GroupId $allUsersGroupId -UserId $rec.UserId -UserUpn $rec.Upn
  }

  foreach ($alias in @($cfg.actors.breakGlassUsers)) {
    $upn = Get-Upn -Alias $alias
    $user = $internalUserRecords | Where-Object { $_.Upn -eq $upn } | Select-Object -First 1
    if ($user -and $breakGlassGroupId) {
      Add-SafeGroupMember -GroupDisplay $cfg.groupNames.breakGlass -GroupId $breakGlassGroupId -UserId $user.UserId -UserUpn $user.Upn
    }
  }

  $adminUpn = Get-Upn -Alias $cfg.actors.namedAdmin
  $adminRecord = $internalUserRecords | Where-Object { $_.Upn -eq $adminUpn } | Select-Object -First 1
  if ($adminRecord) {
    if ($adminGroupId) {
      Add-SafeGroupMember -GroupDisplay $cfg.groupNames.admins -GroupId $adminGroupId -UserId $adminRecord.UserId -UserUpn $adminRecord.Upn
    }
    if ($p2GroupId) {
      Add-SafeGroupMember -GroupDisplay $cfg.groupNames.entraP2 -GroupId $p2GroupId -UserId $adminRecord.UserId -UserUpn $adminRecord.Upn
    } else {
      Write-BootstrapEvent -Message "group.missingReference" -Status "warn" -Step "identity" -Details @{group = $cfg.groupNames.entraP2}
    }
  }

  if ($reportGroupId) {
    foreach ($alias in $cfg.actors.reportingUsers) {
      $upn = Get-Upn -Alias $alias
      $record = $internalUserRecords | Where-Object { $_.Upn -eq $upn } | Select-Object -First 1
      if ($record) {
        Add-SafeGroupMember -GroupDisplay $cfg.groupNames.reporting -GroupId $reportGroupId -UserId $record.UserId -UserUpn $record.Upn
      }
    }
  }

  if ($copilotGroupId) {
    foreach ($alias in $cfg.actors.copilotPilotUsers) {
      $upn = Get-Upn -Alias $alias
      $record = $internalUserRecords | Where-Object { $_.Upn -eq $upn } | Select-Object -First 1
      if ($record) {
        Add-SafeGroupMember -GroupDisplay $cfg.groupNames.copilotPilot -GroupId $copilotGroupId -UserId $record.UserId -UserUpn $record.Upn
      }
    }
  }

  # Department-local membership to create realistic access patterns
  foreach ($dept in $cfg.departments) {
    $deptToken = To-GroupToken $dept
    $members = $departmentUsers[$dept]
    if (-not $members -or $members.Count -eq 0) { continue }

    $deptSecurityGroup = Get-GroupId -DisplayName "SG-$deptToken-APP-01"
    $deptServiceGroup = Get-GroupId -DisplayName "SG-$deptToken-SVC-01"
    $deptCollabGroup = Get-GroupId -DisplayName "MG-$deptToken-COLLAB-01"

    for ($i = 0; $i -lt $members.Count; $i++) {
      $member = $members[$i]
      if ($deptSecurityGroup) {
        Add-SafeGroupMember -GroupDisplay "SG-$deptToken-APP-01" -GroupId $deptSecurityGroup -UserId $member.UserId -UserUpn $member.Upn
      }
      if ($deptServiceGroup -and ($i % 2 -eq 0)) {
        Add-SafeGroupMember -GroupDisplay "SG-$deptToken-SVC-01" -GroupId $deptServiceGroup -UserId $member.UserId -UserUpn $member.Upn
      }
      if ($deptCollabGroup -and ($i -lt 2)) {
        Add-SafeGroupMember -GroupDisplay "MG-$deptToken-COLLAB-01" -GroupId $deptCollabGroup -UserId $member.UserId -UserUpn $member.Upn
      }
    }
  }

  # Functional cross-pollination across workstreams
  for ($i = 0; $i -lt $internalUserRecords.Count; $i++) {
    $record = $internalUserRecords[$i]
    $functionToken = To-GroupToken $enterpriseScale["functionFamilies"][$i % $enterpriseScale["functionFamilies"].Count]
    $groupOne = Get-GroupId -DisplayName "MG-FUNC-$functionToken-WORK-01"
    $groupTwo = Get-GroupId -DisplayName "SG-FUNC-$functionToken-WORK-02"

    if ($groupOne) {
      Add-SafeGroupMember -GroupDisplay "MG-FUNC-$functionToken-WORK-01" -GroupId $groupOne -UserId $record.UserId -UserUpn $record.Upn
    }
    if ($groupTwo -and ($i % 2 -eq 0)) {
      Add-SafeGroupMember -GroupDisplay "SG-FUNC-$functionToken-WORK-02" -GroupId $groupTwo -UserId $record.UserId -UserUpn $record.Upn
    }
  }

  # Intentional overshare/risk-seed groups
  $overshareTargets = @("SG-RISK-OVERSHARE-01", "MG-RISK-MISSHARE-02", "SG-OWNER-RSRC-02", "MG-PROG-GOV-01", "SG-GEO-NA-OPS-01")
  if ($internalUserRecords.Count -gt 0) {
    $seed = $internalUserRecords[0]
    foreach ($target in $overshareTargets) {
      $targetId = Get-GroupId -DisplayName $target
      if ($targetId) {
        Add-SafeGroupMember -GroupDisplay $target -GroupId $targetId -UserId $seed.UserId -UserUpn $seed.Upn
      }
    }
  }
}

Write-BootstrapEvent -Message "identity.seed.summary" -Status "success" -Step "identity" -Details @{
  users = $effectiveInternalUsers
  guests = $effectiveGuestUsers
  staticGroups = $groupDefs.Count
  dynamicGroups = $dynamicGroupDefs.Count
  enterpriseScale = $enterpriseScale["enabled"]
}

End-BootstrapSession
