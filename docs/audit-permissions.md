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

- Run `az login` in browser first.
- Ensure the account has at least read permissions used by the selected collectors.
- Start audit with:

```bash
python3 -m azure_tenant_audit --tenant-name ACME --use-azure-cli-token --tenant-id <tenant-id>
```

This path does not require `AZURE_CLIENT_ID` / `AZURE_CLIENT_SECRET`.

### Practical setup advice

- For interactive mode, use delegated permissions on the same scope set and sign in with a Global Reader or Global Admin account.
- Start with the minimum set of scopes and add missing permissions as failures indicate.
- Test with `--collectors identity` first.
- If Intune returns no data, check tenant license and endpoint access.
- If Teams/Exchange has large tenant volume, tune `--top` and use collector filters before full run.
