# Quick Graph/CLI Query Catalog

Use this as a lookup when extending collectors.

## Identity / Tenant

- `GET /organization`
- `GET /domains`
- `GET /users?$top=...`
- `GET /groups?$filter=securityEnabled eq true`
- `GET /applications`
- `GET /servicePrincipals`
- `GET /roleManagement/directory/roleDefinitions`
- `GET /roleManagement/directory/roleAssignments`

## Security

- `GET /identity/conditionalAccess/policies`
- `GET /identity/conditionalAccess/namedLocations`
- `GET /auditLogs/signIns`
- `GET /auditLogs/directoryAudits`
- `GET /security/alerts`

## Authentication Methods

- `GET /policies/authenticationMethodsPolicy`
- `GET /reports/authenticationMethods/userRegistrationDetails`

## Intune

- `GET /deviceManagement/managedDevices`
- `GET /deviceManagement/deviceCompliancePolicies`
- `GET /deviceManagement/deviceConfigurations`

## SharePoint / OneDrive

- `GET /admin/sharepoint/settings`
- `GET /sites`

## Teams

- `GET /groups?$filter=resourceProvisioningOptions/Any(x:x eq 'Team')`
- `GET /teams/{id}/channels`

## Exchange (optional via command tooling)

- `m365 tenant info get --output json`
- `m365 status --output json`
- `m365 outlook report mailboxusagemailboxcount --period D30 --output json`
- `m365 outlook report mailboxusagedetail --period D30 --output json`
- `m365 outlook roomlist list --output json`
- `Get-MessageTrace ...` via PowerShell / ExchangeOnlineManagement for response flows

## Offline extension

Add new queries by duplicating existing collector functions and following `collectors/<name>.py`.

## Azure CLI token helper (no app registration)

- `az login --tenant <tenant-id-or-domain>`
- `az account get-access-token --resource https://graph.microsoft.com --output json`
