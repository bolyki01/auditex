# Permission and Role Notes

The toolkit aims for read-only collection. Recommended minimum scopes for broad coverage:

- `Directory.Read.All`
- `User.Read.All`
- `Group.Read.All`
- `Application.Read.All`
- `AuditLog.Read.All`
- `SecurityEvents.Read.All`
- `SecurityActions.Read.All`
- `DeviceManagementManagedDevices.Read.All`
- `DeviceManagementConfiguration.Read.All`
- `DeviceManagementApps.Read.All`
- `Team.ReadBasic.All`
- `Channel.ReadBasic.All`

Role mapping hints are in `configs/collector-permissions.json`.

## App-less Azure CLI execution path

- Use a Global Reader or Security Reader account first.
- Run `az login --allow-no-subscriptions` in browser first.
- Ensure the account has at least read permissions used by the selected collectors.
- Start audit with:

```bash
python3 -m azure_tenant_audit --tenant-name ACME --use-azure-cli-token --tenant-id <tenant-id>
```

This path does not require `AZURE_CLIENT_ID` / `AZURE_CLIENT_SECRET`.
It is the default first-run path for this repo.

## Auth and profile matrix

| Path | CLI profile | Sign-in | Exchange-assisted | Response |
| --- | --- | --- | --- | --- |
| Global Reader | `global-reader` | Delegated | Optional with `--include-exchange` | No |
| Security Reader | `security-reader` | Delegated | No | No |
| App read-only full | `app-readonly-full` | App-only or delegated token | Yes, with `m365` and `powershell_graph` adapters | No |
| Exchange-assisted | `exchange-reader` | Delegated | Yes, built in | Yes |

`global-reader` is the default live audit profile. `security-reader` is the narrower delegated security path. `app-readonly-full` is the customer-local app-only read path. `exchange-reader` is the only built-in response-capable profile.

### Practical setup advice

- For interactive mode, use delegated permissions on the same scope set and sign in with a Global Reader account first.
- Start with the minimum set of scopes and add missing permissions as failures indicate.
- Test with `--collectors identity` first.
- If Intune returns no data, check tenant license and endpoint access.
- If Teams/Exchange has large tenant volume, tune `--top` and use collector filters before full run.
- Use `m365` only for Exchange-backed collectors.
