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
- The PMTerminal platform audit is read-only. CyberArk does not document an in-place REST update for the CPM plug-in setting, so the runner does not attempt an unsupported tenant-wide change.
- Safe CPM imports show a preview and require typing `APPLY` before changing any safe.
- The authenticated account must have enough CyberArk permissions to list safes, read safe details, manage safes, and manage safe members.

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

To declare a safe CPM assignment CSV on launch:

```bash
pwsh ./CyberArkApiRunner.ps1 -Subdomain serviceslab -SafeCpmCsvPath ./safe_cpm_assignments.csv
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

### Audit Platforms Using The PMTerminal CPM Plug-in

Privilege Cloud mode calls:

```text
GET https://<subdomain>.privilegecloud.cyberark.cloud/PasswordVault/API/Platforms
GET https://<subdomain>.privilegecloud.cyberark.cloud/PasswordVault/API/Platforms/<platformId>
```

The audit recursively checks each visible platform detail for values containing
`PMTerminal` or `PMTerminal.exe`. Matches are displayed and written to a
timestamped CSV with the platform ID, platform name, property path, current
value, and proposed `CyberArk.TPC.exe` value.

The operation is read-only because the documented platform REST API does not
provide an in-place update for this CPM plug-in setting.

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

### Export And Update Safe CPM Assignments

The export option writes a timestamped CSV:

```text
safe_cpm_assignments_20260610_121500.csv
```

The file contains:

```text
SafeName,CurrentManagingCPM,ManagingCPM
```

Edit `ManagingCPM` to the new CPM name. Leave it blank to skip the safe, or use
`NULL` or `<NONE>` to clear the safe's CPM assignment. The importer reads each
safe's current settings, previews only actual changes, and requires typing
`APPLY` before updating anything. It preserves the safe's description, OLAC
setting, and retention setting. During import, only safes listed in the CSV are
requested through CyberArk's filtered safe search; the runner does not enumerate
every safe in the tenant.

Calls:

```text
GET https://<subdomain>.privilegecloud.cyberark.cloud/PasswordVault/API/Safes
GET https://<subdomain>.privilegecloud.cyberark.cloud/PasswordVault/API/Safes?search=<safeName>
PUT https://<subdomain>.privilegecloud.cyberark.cloud/PasswordVault/API/Safes/<safeUrlId>
```

## Documentation

- [CSV formats](docs/CSV_FORMATS.md)
- [GitHub upload notes](docs/GITHUB_UPLOAD.md)
