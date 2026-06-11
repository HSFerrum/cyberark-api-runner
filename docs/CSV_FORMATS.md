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
SafeName,CurrentManagingCPM,ManagingCPM
Windows-Safe,PasswordManager,PasswordManager
Linux-Safe,PasswordManager,PasswordManager
```

Only edit `ManagingCPM`:

- Set it to a CPM name to assign that CPM.
- Leave it blank to make no change.
- Set it to `NULL` or `<NONE>` to clear the CPM assignment.

`CurrentManagingCPM` is the exported baseline and should not be edited. The
importer compares it locally with `ManagingCPM`, then contacts CyberArk only for
rows whose values differ. It re-reads those edited safes before creating update
requests. The CSV preview and `APPLY` confirmation happen before API calls, then
each edited safe is read, updated, and verified immediately. The exact safe and
its `safeUrlId` are resolved with CyberArk's filtered safe search.

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
