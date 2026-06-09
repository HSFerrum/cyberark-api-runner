# CyberArk API Runner

PowerShell CLI for CyberArk reporting and safe management.

The app authenticates once, then lets you run CyberArk tasks from a menu. Privilege Cloud mode supports safe member reporting/imports. On-prem mode supports PVWA authentication and PSM usage reporting from recorded sessions.

## Requirements

- PowerShell 7 or newer
- For Privilege Cloud: a CyberArk Identity OAuth user or interactive user that can get a Privilege Cloud platform token
- For on-prem PAM: a PVWA URL and CyberArk, LDAP, or RADIUS user that can view PSM recordings

On this Linux machine, PowerShell is available as `pwsh`.

## Safety Notes

- Generated CSV files are ignored by Git because they can contain real tenant, safe, user, group, or permission data.
- The import workflow skips existing safe members by default. It does not overwrite permissions for members that are already on a safe.
- The authenticated account must have enough CyberArk permissions to list safes, read safe members, and manage safe members.

## Run

```bash
pwsh ./CyberArkApiRunner.ps1
```

To launch directly into on-prem mode:

```bash
pwsh ./CyberArkApiRunner.ps1 -EnvironmentType onprem -PVWAUrl https://pvwa.company.com/PasswordVault -OnPremAuthType cyberark -Username apiuser
```

You can also pass values directly:

```bash
pwsh ./CyberArkApiRunner.ps1 -Subdomain serviceslab -AuthType oauth -ApplicationId HaydenOAUTHAPI -ClientId "user@tenant"
```

To declare the import CSV on launch:

```bash
pwsh ./CyberArkApiRunner.ps1 -Subdomain serviceslab -CsvPath ./safe_members_and_groups.csv
```

The script follows the same authentication pattern used by FastPAS:

- OAuth calls `https://<identity-host>/oauth2/token/<application-id>` and then `https://<identity-host>/oauth2/platformtoken`.
- Interactive login calls `Security/StartAuthentication` and `Security/AdvanceAuthentication`, including MFA follow-up actions.

The app asks for the password or OAuth secret at runtime and does not save it.
If you pass `-Token`, the script will still use that token directly as an
override. Privilege Cloud tokens are sent as bearer tokens; on-prem PVWA session
tokens are sent as the raw `Authorization` header value returned by PVWA.

## Menu Options

### Fetch Safe Members And Groups

Calls:

```text
GET https://<subdomain>.privilegecloud.cyberark.cloud/PasswordVault/API/Safes
GET https://<subdomain>.privilegecloud.cyberark.cloud/PasswordVault/API/Safes/<safeUrlId>/Members
```

The CSV is written to the directory where the script is run. The default file
name includes a timestamp:

```text
safe_members_and_groups_20260520_121500.csv
```

The export includes:

- `SafeName`
- `UserName`
- `MemberType`
- `IdentityType`, with `GROUP` or `USER`
- `IsGroup`, with `True` or `False`
- `UserLocation`
- flattened safe permission columns from CyberArk

Groups are sorted before users within each safe.

### Export PSM Users From Recordings CSV

On-prem mode calls:

```text
POST https://<pvwa>/PasswordVault/API/Auth/<CyberArk|LDAP|RADIUS>/Logon
GET  https://<pvwa>/PasswordVault/API/Recordings?FromTime=<epoch>&ToTime=<epoch>&Limit=100&OffSet=<offset>
```

By default, the report looks back 90 days, which is roughly the past three months.
You can change this when launching the script with `-PsmLookbackDays <days>`.

The CSV is written to the directory where the script is run. The default file
name includes a timestamp:

```text
psm_users_past_90_days_20260603_121500.csv
```

The export includes one row per PSM vault user:

- `UserName`
- `SessionCount`
- `FirstSession`
- `LastSession`
- `Protocols`
- `Clients`
- `Safes`
- `RemoteMachines`

### Add Safe Members And Groups From CSV

Reads a CSV and adds missing safe members to existing safes. Existing members
are skipped by default; their permissions are not overwritten.

The importer supports this app's export format:

```text
SafeName,UserName,MemberType,IdentityType,IsGroup,UserLocation,UseAccounts,...
```

It also supports the CyberArk epv-api-scripts safe member format:

```text
Safename,Member,MemberLocation,MemberType,UseAccounts,...
```

For each row, the script:

- maps `SafeName` or `Safename` to the safe
- maps `UserName` or `Member` to the safe member name
- maps `UserLocation` or `MemberLocation` to the member search location
- rebuilds the permissions object from the permission columns
- calls the Privilege Cloud Safe Members API

Calls:

```text
GET  https://<subdomain>.privilegecloud.cyberark.cloud/PasswordVault/API/Safes
GET  https://<subdomain>.privilegecloud.cyberark.cloud/PasswordVault/API/Safes/<safeUrlId>/Members/<memberName>
POST https://<subdomain>.privilegecloud.cyberark.cloud/PasswordVault/API/Safes/<safeUrlId>/Members
```

## Documentation

- [CSV formats](docs/CSV_FORMATS.md)
- [GitHub upload notes](docs/GITHUB_UPLOAD.md)
