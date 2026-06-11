# CSV Formats

## Export Format

The `Fetch safe members and groups CSV` option writes CSV files with columns like:

```text
SafeName,UserName,MemberType,IdentityType,IsGroup,UserLocation,UseAccounts,RetrieveAccounts,...
```

`IdentityType` and `IsGroup` are helper columns that make group rows easier to identify.

## Import Format

The `Add safe members and groups from CSV` option accepts this app's export format and the CyberArk epv-api-scripts safe member format.

This app's format:

```text
SafeName,UserName,MemberType,IdentityType,IsGroup,UserLocation,UseAccounts,RetrieveAccounts,...
```

CyberArk epv-api-scripts format:

```text
Safename,Member,MemberLocation,MemberType,UseAccounts,RetrieveAccounts,...
```

## Permission Columns

Supported permission columns include:

```text
UseAccounts
RetrieveAccounts
ListAccounts
AddAccounts
UpdateAccountContent
UpdateAccountProperties
InitiateCPMAccountManagementOperations
SpecifyNextAccountContent
RenameAccounts
DeleteAccounts
UnlockAccounts
ManageSafe
ManageSafeMembers
BackupSafe
ViewAuditLog
ViewSafeMembers
RequestsAuthorizationLevel
AccessWithoutConfirmation
CreateFolders
DeleteFolders
MoveAccountsAndFolders
```

Boolean values can be `TRUE` or `FALSE`. `RequestsAuthorizationLevel` should be numeric.

## Safe CPM Assignment Export And Import

The `Export safe CPM assignments CSV` option writes:

```text
CpmUpdateMode,SafeName,SafeUrlId,CurrentManagingCPM,ManagingCPM,Description,OLACEnabled,NumberOfVersionsRetention,NumberOfDaysRetention
DirectWrite,Windows-Safe,42,PasswordManager,PasswordManager,Windows accounts,FALSE,5,
DirectWrite,Linux-Safe,43,PasswordManager,PasswordManager,Linux accounts,FALSE,,30
```

Only edit `ManagingCPM`:

- Set it to a CPM name to assign that CPM.
- Leave it blank to make no change.
- Set it to `NULL` or `<NONE>` to clear the CPM assignment.

Do not edit `CpmUpdateMode`, `SafeUrlId`, `CurrentManagingCPM`, `Description`,
`OLACEnabled`, or the retention columns. They are the exported snapshot metadata
used to build CyberArk's full safe update body.

With all snapshot columns present, the importer uses direct-write mode: it
compares CPM values locally and sends one `PUT` per changed row without safe
lookup or verification requests. Use a recent export because newer description,
OLAC, or retention changes made after export could be overwritten by the CSV
snapshot. Legacy three-column files are supported with the slower queried mode.

Before applying changes, the importer creates a
`safe_cpm_remaining_<timestamp>.csv` checkpoint in the source CSV directory.
It periodically removes completed rows. Re-import this checkpoint after an
interruption to resume unfinished work. The checkpoint contains no token,
password, or OAuth secret.

During the batch, an HTTP 401 or 403 triggers token renewal and one retry of the
current request. OAuth credentials are retained only in process memory;
interactive authentication can require another MFA approval.

## PSM Users From Recordings Export

The on-prem `Export PSM users from recordings CSV` option writes one row per
unique vault user found in PSM recording metadata for the selected lookback
window. The default lookback window is 90 days.

```text
UserName,SessionCount,FirstSession,LastSession,Protocols,Clients,Safes,RemoteMachines
```

`SessionCount` is the number of returned recordings for that user. The remaining
fields are distinct values observed across that user's sessions, joined with
semicolons where more than one value exists.
