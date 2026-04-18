# Exchange App Request

Use this when Auditex operator does not have Global Administrator.

## What customer admin must do

1. Create a single-tenant Entra app registration.
2. Name can be `CLI for M365` or company standard.
3. Add mobile/desktop redirect URI:
   `https://login.microsoftonline.com/common/oauth2/nativeclient`
4. Enable public client flows.
5. Add delegated permissions needed for planned `m365` commands.
6. Grant admin consent for those delegated permissions.
7. Send operator:
   - tenant id
   - app/client id
   - permission list
   - who granted consent

## What operator does

1. Put app id in `.secrets/m365-auth.env`
2. Keep tenant id in same file
3. Run:
   `./scripts/tenant-audit-login <tenant> --browser safari --m365 --m365-app-id <app-id>`

## Local file shape

```env
M365_CLI_APP_ID=<app-id>
M365_CLI_CLIENT_ID=<app-id>
AUDITEX_TENANT_ID=<tenant-id>
```

## Important

- Customer admin does the one-time app creation and consent.
- Operator does not need GA after that.
- Global Reader can use the app later, but only for commands allowed by:
  - granted delegated permissions
  - the signed-in GR account
