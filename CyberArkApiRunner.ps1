#!/usr/bin/env pwsh
<#
.SYNOPSIS
    CyberArk Privilege Cloud PowerShell API runner.

.DESCRIPTION
    Exports all safes and safe members from CyberArk Privilege Cloud to CSV.
    The export flattens each member's permissions object into CSV columns and
    includes columns that make group members easy to identify.
#>

[CmdletBinding()]
param (
    [Parameter(Mandatory = $false)]
    [string]$Subdomain,

    [Parameter(Mandatory = $false)]
    [string]$Token,

    [Parameter(Mandatory = $false)]
    [ValidateSet("oauth", "interactive")]
    [string]$AuthType,

    [Parameter(Mandatory = $false)]
    [string]$IdentityHost,

    [Parameter(Mandatory = $false)]
    [string]$ApplicationId,

    [Parameter(Mandatory = $false)]
    [string]$ClientId,

    [Parameter(Mandatory = $false)]
    [string]$Username,

    [Parameter(Mandatory = $false)]
    [string]$CsvPath,

    [Parameter(Mandatory = $false)]
    [string]$SafeCpmCsvPath,

    [Parameter(Mandatory = $false)]
    [string]$OutputFile,

    [Parameter(Mandatory = $false)]
    [ValidateSet("privilegecloud", "onprem")]
    [string]$EnvironmentType,

    [Parameter(Mandatory = $false)]
    [string]$PVWAUrl,

    [Parameter(Mandatory = $false)]
    [ValidateSet("cyberark", "ldap", "radius")]
    [string]$OnPremAuthType,

    [Parameter(Mandatory = $false)]
    [int]$PsmLookbackDays = 90
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

function Read-RequiredValue {
    param (
        [Parameter(Mandatory = $true)]
        [string]$Prompt
    )

    while ($true) {
        $Value = Read-Host $Prompt
        if (-not [string]::IsNullOrWhiteSpace($Value)) {
            return $Value.Trim()
        }
        Write-Host "This value is required." -ForegroundColor Yellow
    }
}

function Read-Token {
    param (
        [Parameter(Mandatory = $false)]
        [string]$ExistingToken
    )

    if (-not [string]::IsNullOrWhiteSpace($ExistingToken)) {
        return Format-AuthorizationToken -Token $ExistingToken
    }

    $SecureToken = Read-Host "Platform token" -AsSecureString
    $PlainToken = ConvertFrom-SecureStringToPlainText -SecureString $SecureToken
    return Format-AuthorizationToken -Token $PlainToken
}

function Read-Choice {
    param (
        [Parameter(Mandatory = $true)]
        [string]$Prompt,

        [Parameter(Mandatory = $true)]
        [string[]]$Choices
    )

    $ChoiceText = $Choices -join "/"
    while ($true) {
        $Value = (Read-Host "$Prompt ($ChoiceText)").Trim().ToLowerInvariant()
        if ($Choices -contains $Value) {
            return $Value
        }
        Write-Host "Choose one of: $ChoiceText" -ForegroundColor Yellow
    }
}

function ConvertFrom-SecureStringToPlainText {
    param (
        [Parameter(Mandatory = $true)]
        [securestring]$SecureString
    )

    $Bstr = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($SecureString)
    try {
        return [Runtime.InteropServices.Marshal]::PtrToStringBSTR($Bstr)
    }
    finally {
        [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($Bstr)
    }
}

function Format-AuthorizationToken {
    param (
        [Parameter(Mandatory = $true)]
        [string]$Token
    )

    $TrimmedToken = $Token.Trim()
    if ($TrimmedToken -match "^(?i)Bearer\s+") {
        return $TrimmedToken
    }
    return "Bearer $TrimmedToken"
}

function Format-OnPremAuthorizationToken {
    param (
        [Parameter(Mandatory = $true)]
        [string]$Token
    )

    $TrimmedToken = $Token.Trim()
    if ($TrimmedToken -match "^(?i)Bearer\s+") {
        return $TrimmedToken
    }
    return $TrimmedToken
}

function Resolve-PVWAUrl {
    param (
        [Parameter(Mandatory = $true)]
        [string]$Url
    )

    $Resolved = $Url.Trim().TrimEnd("/")
    if ([string]::IsNullOrWhiteSpace($Resolved)) {
        throw "PVWA URL is required."
    }
    if ($Resolved -notmatch "^(?i)https?://") {
        $Resolved = "https://$Resolved"
    }
    if ($Resolved -notmatch "(?i)/PasswordVault$") {
        $Resolved = "$Resolved/PasswordVault"
    }
    return $Resolved
}

function Resolve-IdentityHost {
    param (
        [Parameter(Mandatory = $true)]
        [string]$Subdomain,

        [Parameter(Mandatory = $false)]
        [string]$ExistingIdentityHost
    )

    if (-not [string]::IsNullOrWhiteSpace($ExistingIdentityHost)) {
        return $ExistingIdentityHost.Trim().Replace("https://", "").TrimEnd("/")
    }

    $Candidates = @(
        "https://$Subdomain.cyberark.cloud",
        "https://$Subdomain-userportal.cyberark.cloud",
        "https://$Subdomain.privilegecloud.cyberark.cloud"
    )

    foreach ($Candidate in $Candidates) {
        try {
            $Response = Invoke-WebRequest -Uri $Candidate -Method Get -MaximumRedirection 8 -TimeoutSec 20 -ErrorAction Stop
            $ResponseHost = Get-WebResponseHost -Response $Response
            if ($ResponseHost -match "\.id\.cyberark\.cloud$") {
                return $ResponseHost
            }
        }
        catch {
            $RedirectHost = Get-ExceptionRedirectHost -ErrorRecord $_
            if ($RedirectHost -match "\.id\.cyberark\.cloud$") {
                return $RedirectHost
            }
        }
    }

    return "$Subdomain.id.cyberark.cloud"
}

function Get-WebResponseHost {
    param (
        [Parameter(Mandatory = $true)]
        [object]$Response
    )

    if ($Response.PSObject.Properties.Name -contains "BaseResponse" -and $null -ne $Response.BaseResponse) {
        $BaseResponse = $Response.BaseResponse
        if ($BaseResponse.PSObject.Properties.Name -contains "ResponseUri" -and $null -ne $BaseResponse.ResponseUri) {
            return $BaseResponse.ResponseUri.Host
        }
        if ($BaseResponse.PSObject.Properties.Name -contains "RequestMessage" -and $null -ne $BaseResponse.RequestMessage) {
            if ($BaseResponse.RequestMessage.PSObject.Properties.Name -contains "RequestUri" -and $null -ne $BaseResponse.RequestMessage.RequestUri) {
                return $BaseResponse.RequestMessage.RequestUri.Host
            }
        }
    }

    return ""
}

function Get-ExceptionRedirectHost {
    param (
        [Parameter(Mandatory = $true)]
        [object]$ErrorRecord
    )

    if ($ErrorRecord.Exception -and $ErrorRecord.Exception.Response -and $ErrorRecord.Exception.Response.Headers) {
        $Headers = $ErrorRecord.Exception.Response.Headers
        if ($Headers.PSObject.Properties.Name -contains "Location" -and $null -ne $Headers.Location) {
            try {
                $Location = [uri]$Headers.Location
                if ($Location.Host -match "\.id\.cyberark\.cloud$") {
                    return $Location.Host
                }
            }
            catch {
                return ""
            }
        }
    }

    return ""
}

function Invoke-JsonPost {
    param (
        [Parameter(Mandatory = $true)]
        [string]$Uri,

        [Parameter(Mandatory = $true)]
        [object]$Body,

        [Parameter(Mandatory = $false)]
        [hashtable]$Headers = @{}
    )

    try {
        return Invoke-RestMethod -Uri $Uri -Method Post -Body ($Body | ConvertTo-Json -Depth 20) -ContentType "application/json" -Headers $Headers -TimeoutSec 120
    }
    catch {
        $StatusCode = $null
        if ($_.Exception.Response -and $_.Exception.Response.StatusCode) {
            $StatusCode = [int]$_.Exception.Response.StatusCode
        }
        if ($StatusCode) {
            throw "POST failed with HTTP $StatusCode from $Uri. $($_.Exception.Message)"
        }
        throw "POST failed from $Uri. $($_.Exception.Message)"
    }
}

function Invoke-FormPost {
    param (
        [Parameter(Mandatory = $true)]
        [string]$Uri,

        [Parameter(Mandatory = $true)]
        [hashtable]$Body
    )

    try {
        return Invoke-RestMethod -Uri $Uri -Method Post -Body $Body -ContentType "application/x-www-form-urlencoded" -TimeoutSec 120
    }
    catch {
        $StatusCode = $null
        if ($_.Exception.Response -and $_.Exception.Response.StatusCode) {
            $StatusCode = [int]$_.Exception.Response.StatusCode
        }
        if ($StatusCode) {
            throw "POST failed with HTTP $StatusCode from $Uri. $($_.Exception.Message)"
        }
        throw "POST failed from $Uri. $($_.Exception.Message)"
    }
}

function Get-ResponseToken {
    param (
        [Parameter(Mandatory = $true)]
        [object]$Response
    )

    if ($Response.PSObject.Properties.Name -contains "access_token" -and -not [string]::IsNullOrWhiteSpace($Response.access_token)) {
        return [string]$Response.access_token
    }
    if ($Response.PSObject.Properties.Name -contains "token" -and -not [string]::IsNullOrWhiteSpace($Response.token)) {
        return [string]$Response.token
    }
    if ($Response.PSObject.Properties.Name -contains "Result" -and $null -ne $Response.Result) {
        if ($Response.Result.PSObject.Properties.Name -contains "Token" -and -not [string]::IsNullOrWhiteSpace($Response.Result.Token)) {
            return [string]$Response.Result.Token
        }
        if ($Response.Result.PSObject.Properties.Name -contains "Auth" -and -not [string]::IsNullOrWhiteSpace($Response.Result.Auth)) {
            return [string]$Response.Result.Auth
        }
    }
    return ""
}

function Get-ResponseSummary {
    param (
        [Parameter(Mandatory = $true)]
        [object]$Response
    )

    if ($Response.PSObject.Properties.Name -contains "Result" -and $null -ne $Response.Result) {
        if ($Response.Result.PSObject.Properties.Name -contains "Summary" -and $null -ne $Response.Result.Summary) {
            return [string]$Response.Result.Summary
        }
    }
    return ""
}

function Assert-InteractiveResponseSuccess {
    param (
        [Parameter(Mandatory = $true)]
        [object]$Response
    )

    if ($Response.PSObject.Properties.Name -contains "success" -and $Response.success -eq $false) {
        $Message = "Interactive authentication challenge was rejected by CyberArk."
        if ($Response.PSObject.Properties.Name -contains "Message" -and -not [string]::IsNullOrWhiteSpace([string]$Response.Message)) {
            $Message = "Interactive authentication failed: $($Response.Message)"
        }
        $Summary = Get-ResponseSummary -Response $Response
        if (-not [string]::IsNullOrWhiteSpace($Summary)) {
            $Message = "$Message (Summary: $Summary)"
        }
        if ($Response.PSObject.Properties.Name -contains "ErrorID" -and -not [string]::IsNullOrWhiteSpace([string]$Response.ErrorID)) {
            $Message = "$Message [ErrorID: $($Response.ErrorID)]"
        }
        throw $Message
    }
}

function Get-OAuthPlatformToken {
    param (
        [Parameter(Mandatory = $true)]
        [string]$IdentityHost,

        [Parameter(Mandatory = $true)]
        [string]$ApplicationId,

        [Parameter(Mandatory = $true)]
        [string]$ClientId
    )

    $ClientSecret = ConvertFrom-SecureStringToPlainText -SecureString (Read-Host "OAuth client secret / password" -AsSecureString)
    $TokenFields = @{
        grant_type    = "client_credentials"
        client_id     = $ClientId
        client_secret = $ClientSecret
    }

    Write-Host "Requesting Identity OAuth token..." -ForegroundColor Cyan
    $null = Invoke-FormPost -Uri "https://$IdentityHost/oauth2/token/$ApplicationId" -Body $TokenFields

    Write-Host "Requesting Privilege Cloud platform token..." -ForegroundColor Cyan
    $PlatformResponse = Invoke-FormPost -Uri "https://$IdentityHost/oauth2/platformtoken" -Body $TokenFields
    $PlatformToken = Get-ResponseToken -Response $PlatformResponse

    if ([string]::IsNullOrWhiteSpace($PlatformToken)) {
        throw "Platform token response did not contain a token."
    }

    return Format-AuthorizationToken -Token $PlatformToken
}

function Get-Mechanisms {
    param (
        [Parameter(Mandatory = $true)]
        [object]$Response
    )

    $Mechanisms = @()
    if ($Response.PSObject.Properties.Name -notcontains "Result" -or $null -eq $Response.Result) {
        return $Mechanisms
    }
    if ($Response.Result.PSObject.Properties.Name -notcontains "Challenges" -or $null -eq $Response.Result.Challenges) {
        return $Mechanisms
    }

    foreach ($Challenge in @($Response.Result.Challenges)) {
        if ($Challenge.PSObject.Properties.Name -contains "Mechanisms" -and $null -ne $Challenge.Mechanisms) {
            foreach ($Mechanism in @($Challenge.Mechanisms)) {
                if ($Mechanism.PSObject.Properties.Name -contains "MechanismId" -and -not [string]::IsNullOrWhiteSpace($Mechanism.MechanismId)) {
                    $Mechanisms += $Mechanism
                }
            }
        }
    }
    return $Mechanisms
}

function Get-ChallengeSets {
    param (
        [Parameter(Mandatory = $true)]
        [object]$Response
    )

    $ChallengeSets = @()
    if ($Response.PSObject.Properties.Name -notcontains "Result" -or $null -eq $Response.Result) {
        return $ChallengeSets
    }
    if ($Response.Result.PSObject.Properties.Name -notcontains "Challenges" -or $null -eq $Response.Result.Challenges) {
        return $ChallengeSets
    }

    foreach ($Challenge in @($Response.Result.Challenges)) {
        $Set = @()
        if ($Challenge.PSObject.Properties.Name -contains "Mechanisms" -and $null -ne $Challenge.Mechanisms) {
            foreach ($Mechanism in @($Challenge.Mechanisms)) {
                if ($Mechanism.PSObject.Properties.Name -contains "MechanismId" -and -not [string]::IsNullOrWhiteSpace($Mechanism.MechanismId)) {
                    $Set += $Mechanism
                }
            }
        }
        if ($Set.Count -gt 0) {
            $ChallengeSets += ,$Set
        }
    }

    return $ChallengeSets
}

function Get-MechanismText {
    param (
        [Parameter(Mandatory = $true)]
        [object]$Mechanism
    )

    $Parts = @()
    foreach ($Name in @("Name", "PromptSelectMech", "AnswerType")) {
        if ($Mechanism.PSObject.Properties.Name -contains $Name -and $null -ne $Mechanism.$Name) {
            $Parts += [string]$Mechanism.$Name
        }
    }
    return ($Parts -join " ")
}

function Get-MechanismActions {
    param (
        [Parameter(Mandatory = $true)]
        [object]$Mechanism
    )

    $Actions = @()
    if ($Mechanism.PSObject.Properties.Name -contains "Actions" -and $null -ne $Mechanism.Actions) {
        foreach ($Action in @($Mechanism.Actions)) {
            if ($Action -is [string]) {
                $Actions += $Action
            }
            elseif ($Action.PSObject.Properties.Name -contains "Name") {
                $Actions += [string]$Action.Name
            }
        }
    }

    $Hint = (Get-MechanismText -Mechanism $Mechanism).ToLowerInvariant()
    if ($Hint -match "sms|email|text|phone|cell|message") {
        $Actions += "StartTextOob"
    }
    if ($Hint -match "mobile|push|oob|app") {
        $Actions += "StartOOB"
        $Actions += "Poll"
    }
    if ($Hint -match "otp|code|answer|password") {
        $Actions += "Answer"
    }
    if ($Actions.Count -eq 0) {
        $Actions = @("Answer", "Poll")
    }

    return @($Actions | Sort-Object -Unique)
}

function Format-MechanismAction {
    param (
        [Parameter(Mandatory = $true)]
        [string]$Action
    )

    switch ($Action) {
        "StartTextOob" { return "Send SMS/Email Code" }
        "StartOOB" { return "Send Push" }
        "Poll" { return "Check Push Approval" }
        "Answer" { return "Submit Code / Answer" }
        "StartNextChallenge" { return "Fetch Next Challenge" }
        default { return $Action }
    }
}

function Select-IndexedItem {
    param (
        [Parameter(Mandatory = $true)]
        [string]$Prompt,

        [Parameter(Mandatory = $true)]
        [object[]]$Items
    )

    while ($true) {
        $Raw = Read-Host "$Prompt [1-$($Items.Count)]"
        $Index = 0
        if ([int]::TryParse($Raw, [ref]$Index) -and $Index -ge 1 -and $Index -le $Items.Count) {
            return $Items[$Index - 1]
        }
        Write-Host "Enter a number from 1 to $($Items.Count)." -ForegroundColor Yellow
    }
}

function Find-PasswordMechanism {
    param (
        [Parameter(Mandatory = $true)]
        [object]$Response
    )

    foreach ($Mechanism in Get-Mechanisms -Response $Response) {
        $Text = (Get-MechanismText -Mechanism $Mechanism).ToLowerInvariant()
        if (($Mechanism.PSObject.Properties.Name -contains "Name" -and $Mechanism.Name -eq "UP") -or $Text.Contains("password")) {
            return $Mechanism
        }
    }
    return $null
}

function Wait-ForInteractiveApproval {
    param (
        [Parameter(Mandatory = $true)]
        [string]$AdvanceUrl,

        [Parameter(Mandatory = $true)]
        [string]$SessionId,

        [Parameter(Mandatory = $true)]
        [string]$MechanismId,

        [Parameter(Mandatory = $true)]
        [hashtable]$Headers
    )

    for ($Attempt = 0; $Attempt -lt 120; $Attempt++) {
        Start-Sleep -Seconds 2
        $Response = Invoke-JsonPost -Uri $AdvanceUrl -Headers $Headers -Body @{
            SessionId   = $SessionId
            MechanismId = $MechanismId
            Action      = "Poll"
        }

        if (-not [string]::IsNullOrWhiteSpace((Get-ResponseToken -Response $Response))) {
            return $Response
        }

        Assert-InteractiveResponseSuccess -Response $Response
        $Summary = Get-ResponseSummary -Response $Response
        if ($Summary.ToLowerInvariant() -ne "oobpending") {
            return $Response
        }
    }

    throw "Timed out waiting for interactive approval."
}

function Complete-InteractiveChallenge {
    param (
        [Parameter(Mandatory = $true)]
        [string]$AdvanceUrl,

        [Parameter(Mandatory = $true)]
        [string]$SessionId,

        [Parameter(Mandatory = $true)]
        [object[]]$Mechanisms,

        [Parameter(Mandatory = $true)]
        [hashtable]$Headers
    )

    Write-Host ""
    Write-Host "Additional authentication is required." -ForegroundColor Cyan

    for ($Index = 0; $Index -lt $Mechanisms.Count; $Index++) {
        $Label = Get-MechanismText -Mechanism $Mechanisms[$Index]
        Write-Host "$($Index + 1). $Label"
    }

    $Mechanism = Select-IndexedItem -Prompt "Select mechanism" -Items $Mechanisms
    $Actions = @(Get-MechanismActions -Mechanism $Mechanism)

    while ($true) {
        Write-Host ""
        for ($Index = 0; $Index -lt $Actions.Count; $Index++) {
            Write-Host "$($Index + 1). $(Format-MechanismAction -Action $Actions[$Index])"
        }

        $Action = Select-IndexedItem -Prompt "Action" -Items $Actions
        $Body = @{
            SessionId   = $SessionId
            MechanismId = $Mechanism.MechanismId
            Action      = $Action
        }

        if ($Action.ToLowerInvariant() -eq "answer") {
            $Body["Answer"] = ConvertFrom-SecureStringToPlainText -SecureString (Read-Host "Challenge answer / OTP" -AsSecureString)
        }

        $Response = Invoke-JsonPost -Uri $AdvanceUrl -Headers $Headers -Body $Body
        if (-not [string]::IsNullOrWhiteSpace((Get-ResponseToken -Response $Response))) {
            return $Response
        }

        Assert-InteractiveResponseSuccess -Response $Response
        $Summary = Get-ResponseSummary -Response $Response
        if ($Summary.ToLowerInvariant() -eq "oobpending" -or $Action.ToLowerInvariant() -eq "poll") {
            Write-Host "Waiting for approval..." -ForegroundColor Cyan
            return Wait-ForInteractiveApproval -AdvanceUrl $AdvanceUrl -SessionId $SessionId -MechanismId $Mechanism.MechanismId -Headers $Headers
        }

        $NextMechanisms = @(Get-Mechanisms -Response $Response)
        if ($NextMechanisms.Count -gt 0) {
            return $Response
        }

        Write-Host "Challenge did not return a token yet." -ForegroundColor Yellow
    }
}

function Get-InteractivePlatformToken {
    param (
        [Parameter(Mandatory = $true)]
        [string]$Subdomain,

        [Parameter(Mandatory = $true)]
        [string]$IdentityHost,

        [Parameter(Mandatory = $true)]
        [string]$Username
    )

    $Password = ConvertFrom-SecureStringToPlainText -SecureString (Read-Host "Interactive password" -AsSecureString)
    $StartUrl = "https://$IdentityHost/Security/StartAuthentication"
    $AdvanceUrl = "https://$IdentityHost/Security/AdvanceAuthentication"
    $Headers = @{ "X-IDAP-NATIVE-CLIENT" = "true" }

    Write-Host "Starting interactive authentication..." -ForegroundColor Cyan
    $StartResponse = Invoke-JsonPost -Uri $StartUrl -Headers $Headers -Body @{
        User     = $Username
        Version  = "1.0"
        TenantId = $Subdomain
    }

    if ($StartResponse.PSObject.Properties.Name -notcontains "Result" -or $StartResponse.Result.PSObject.Properties.Name -notcontains "SessionId") {
        throw "StartAuthentication did not return SessionId."
    }

    $SessionId = [string]$StartResponse.Result.SessionId
    $PasswordMechanism = Find-PasswordMechanism -Response $StartResponse
    if ($null -eq $PasswordMechanism) {
        throw "Could not find username/password mechanism."
    }
    $ChallengeSets = @(Get-ChallengeSets -Response $StartResponse)
    $NextChallengeIndex = 1

    $Current = Invoke-JsonPost -Uri $AdvanceUrl -Headers $Headers -Body @{
        SessionId   = $SessionId
        MechanismId = $PasswordMechanism.MechanismId
        Action      = "Answer"
        Answer      = $Password
    }

    $Token = Get-ResponseToken -Response $Current
    while ([string]::IsNullOrWhiteSpace($Token)) {
        Assert-InteractiveResponseSuccess -Response $Current
        $Mechanisms = @(Get-Mechanisms -Response $Current)
        $Summary = Get-ResponseSummary -Response $Current
        if ($Mechanisms.Count -eq 0 -and $Summary.ToLowerInvariant() -eq "startnextchallenge" -and $NextChallengeIndex -lt $ChallengeSets.Count) {
            $Mechanisms = @($ChallengeSets[$NextChallengeIndex])
            $NextChallengeIndex++
        }
        if ($Mechanisms.Count -eq 0) {
            throw "Interactive authentication did not return a token or challenge. Summary: $Summary"
        }
        $Current = Complete-InteractiveChallenge -AdvanceUrl $AdvanceUrl -SessionId $SessionId -Mechanisms $Mechanisms -Headers $Headers
        $Token = Get-ResponseToken -Response $Current
    }

    return Format-AuthorizationToken -Token $Token
}

function Get-OnPremSessionToken {
    param (
        [Parameter(Mandatory = $true)]
        [string]$PVWAUrl,

        [Parameter(Mandatory = $false)]
        [string]$ExistingToken
    )

    if (-not [string]::IsNullOrWhiteSpace($ExistingToken)) {
        return Format-OnPremAuthorizationToken -Token $ExistingToken
    }

    if ([string]::IsNullOrWhiteSpace($script:OnPremAuthType)) {
        $script:OnPremAuthType = Read-Choice -Prompt "On-prem authentication type" -Choices @("cyberark", "ldap", "radius")
    }
    if ([string]::IsNullOrWhiteSpace($script:Username)) {
        $script:Username = Read-RequiredValue -Prompt "Vault username"
    }

    $Password = ConvertFrom-SecureStringToPlainText -SecureString (Read-Host "Vault password" -AsSecureString)
    if ($script:OnPremAuthType -eq "radius") {
        $Otp = Read-Host "RADIUS OTP (leave blank if appended by your password workflow)"
        if (-not [string]::IsNullOrWhiteSpace($Otp)) {
            $Password = "$Password,$($Otp.Trim())"
        }
    }

    $AuthProvider = switch ($script:OnPremAuthType) {
        "cyberark" { "CyberArk" }
        "ldap" { "LDAP" }
        "radius" { "RADIUS" }
    }

    $LogonUrl = "$PVWAUrl/API/Auth/$AuthProvider/Logon"
    $Body = @{
        username          = $script:Username
        password          = $Password
        concurrentSession = $true
    }

    Write-Host "Authenticating to on-prem PVWA..." -ForegroundColor Cyan
    $Response = Invoke-JsonPost -Uri $LogonUrl -Body $Body
    if ($Response -is [string] -and -not [string]::IsNullOrWhiteSpace($Response)) {
        return Format-OnPremAuthorizationToken -Token $Response
    }

    $Token = Get-ResponseToken -Response $Response
    if ([string]::IsNullOrWhiteSpace($Token) -and $Response.PSObject.Properties.Name -contains "CyberArkLogonResult") {
        $Token = [string]$Response.CyberArkLogonResult
    }
    if ([string]::IsNullOrWhiteSpace($Token)) {
        throw "On-prem logon response did not contain a session token."
    }

    return Format-OnPremAuthorizationToken -Token $Token
}

function Get-PlatformToken {
    param (
        [Parameter(Mandatory = $true)]
        [string]$Subdomain,

        [Parameter(Mandatory = $false)]
        [string]$ExistingToken
    )

    if (-not [string]::IsNullOrWhiteSpace($ExistingToken)) {
        return Read-Token -ExistingToken $ExistingToken
    }

    if ([string]::IsNullOrWhiteSpace($script:AuthType)) {
        $script:AuthType = Read-Choice -Prompt "Authentication type" -Choices @("oauth", "interactive")
    }

    $script:IdentityHost = Resolve-IdentityHost -Subdomain $Subdomain -ExistingIdentityHost $script:IdentityHost
    Write-Host "Identity host: $script:IdentityHost" -ForegroundColor Cyan

    if ($script:AuthType -eq "oauth") {
        if ([string]::IsNullOrWhiteSpace($script:ApplicationId)) {
            $script:ApplicationId = Read-RequiredValue -Prompt "OAuth application ID"
        }
        if ([string]::IsNullOrWhiteSpace($script:ClientId)) {
            $script:ClientId = Read-RequiredValue -Prompt "OAuth client ID / login name"
        }
        return Get-OAuthPlatformToken -IdentityHost $script:IdentityHost -ApplicationId $script:ApplicationId -ClientId $script:ClientId
    }

    if ([string]::IsNullOrWhiteSpace($script:Username)) {
        $script:Username = Read-RequiredValue -Prompt "Interactive username"
    }
    return Get-InteractivePlatformToken -Subdomain $Subdomain -IdentityHost $script:IdentityHost -Username $script:Username
}

function New-TimestampedOutputPath {
    param (
        [Parameter(Mandatory = $true)]
        [string]$Prefix
    )

    $Timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
    return Join-Path -Path (Get-Location) -ChildPath "$Prefix`_$Timestamp.csv"
}

function Invoke-CyberArkGet {
    param (
        [Parameter(Mandatory = $true)]
        [string]$Uri,

        [Parameter(Mandatory = $true)]
        [hashtable]$Headers,

        [Parameter(Mandatory = $false)]
        [int]$MaxAttempts = 4
    )

    for ($Attempt = 1; $Attempt -le $MaxAttempts; $Attempt++) {
        try {
            return Invoke-RestMethod -Uri $Uri -Method Get -Headers $Headers -TimeoutSec 120
        }
        catch {
            $StatusCode = $null
            if ($_.Exception.Response -and $_.Exception.Response.StatusCode) {
                $StatusCode = [int]$_.Exception.Response.StatusCode
            }

            $IsTransient = $StatusCode -in @(408, 429, 500, 502, 503, 504)
            if ($IsTransient -and $Attempt -lt $MaxAttempts) {
                $DelaySeconds = [int][math]::Pow(2, $Attempt)
                Write-Warning "GET returned HTTP $StatusCode. Retrying in $DelaySeconds seconds (attempt $($Attempt + 1) of $MaxAttempts)..."
                Start-Sleep -Seconds $DelaySeconds
                continue
            }

            if ($StatusCode) {
                throw "GET failed with HTTP $StatusCode from $Uri after $Attempt attempt(s). $($_.Exception.Message)"
            }
            throw "GET failed from $Uri after $Attempt attempt(s). $($_.Exception.Message)"
        }
    }
}

function Invoke-CyberArkJsonRequest {
    param (
        [Parameter(Mandatory = $true)]
        [ValidateSet("POST", "PATCH", "PUT", "DELETE")]
        [string]$Method,

        [Parameter(Mandatory = $true)]
        [string]$Uri,

        [Parameter(Mandatory = $true)]
        [hashtable]$Headers,

        [Parameter(Mandatory = $false)]
        [object]$Body
    )

    try {
        if ($null -eq $Body) {
            return Invoke-RestMethod -Uri $Uri -Method $Method -Headers $Headers -TimeoutSec 120
        }
        return Invoke-RestMethod -Uri $Uri -Method $Method -Headers $Headers -Body ($Body | ConvertTo-Json -Depth 20) -ContentType "application/json" -TimeoutSec 120
    }
    catch {
        $StatusCode = $null
        $ErrorBody = ""
        if ($_.Exception.Response -and $_.Exception.Response.StatusCode) {
            $StatusCode = [int]$_.Exception.Response.StatusCode
        }
        if ($_.ErrorDetails -and $_.ErrorDetails.Message) {
            $ErrorBody = $_.ErrorDetails.Message
        }

        $Message = "$Method failed"
        if ($StatusCode) {
            $Message = "$Message with HTTP $StatusCode"
        }
        $Message = "$Message from $Uri. $($_.Exception.Message)"
        if (-not [string]::IsNullOrWhiteSpace($ErrorBody)) {
            $Message = "$Message $ErrorBody"
        }
        throw $Message
    }
}

function Get-PagedVaultItems {
    param (
        [Parameter(Mandatory = $true)]
        [string]$BaseUrl,

        [Parameter(Mandatory = $true)]
        [string]$Path,

        [Parameter(Mandatory = $true)]
        [hashtable]$Headers,

        [Parameter(Mandatory = $false)]
        [int]$Limit = 100
    )

    $Items = @()
    $Offset = 0

    while ($true) {
        $Separator = "?"
        if ($Path.Contains("?")) {
            $Separator = "&"
        }

        $Uri = "$BaseUrl/API/$Path$Separator`limit=$Limit&offset=$Offset"
        $Response = Invoke-CyberArkGet -Uri $Uri -Headers $Headers
        $Page = @()

        if ($null -ne $Response.value) {
            $Page = @($Response.value)
        }
        elseif ($Response -is [array]) {
            $Page = @($Response)
        }

        if ($Page.Count -eq 0) {
            break
        }

        $Items += $Page

        if ($Page.Count -lt $Limit) {
            break
        }

        $Offset += $Limit
    }

    return $Items
}

function Get-MemberIdentityType {
    param (
        [Parameter(Mandatory = $true)]
        [object]$Member
    )

    $MemberType = [string]$Member.memberType
    if ($MemberType -match "(?i)group") {
        return "GROUP"
    }
    return "USER"
}

function ConvertTo-CyberArkBoolean {
    param (
        [Parameter(Mandatory = $false)]
        [object]$Value
    )

    if ($null -eq $Value) {
        return $null
    }
    if ($Value -is [bool]) {
        return $Value
    }

    $Text = ([string]$Value).Trim()
    if ([string]::IsNullOrWhiteSpace($Text)) {
        return $null
    }

    if ($Text -match "^(?i:true|yes|y|1)$") {
        return $true
    }
    if ($Text -match "^(?i:false|no|n|0)$") {
        return $false
    }

    return $Value
}

function Get-RowValue {
    param (
        [Parameter(Mandatory = $true)]
        [object]$Row,

        [Parameter(Mandatory = $true)]
        [string[]]$Names
    )

    foreach ($Name in $Names) {
        if ($Row.PSObject.Properties.Name -contains $Name) {
            $Value = $Row.$Name
            if ($null -ne $Value -and -not [string]::IsNullOrWhiteSpace([string]$Value)) {
                return ([string]$Value).Trim()
            }
        }
    }

    return ""
}

function Get-PermissionColumnMap {
    return [ordered]@{
        UseAccounts                            = "useAccounts"
        RetrieveAccounts                       = "retrieveAccounts"
        ListAccounts                           = "listAccounts"
        AddAccounts                            = "addAccounts"
        UpdateAccountContent                   = "updateAccountContent"
        UpdateAccountProperties                = "updateAccountProperties"
        InitiateCPMAccountManagementOperations = "initiateCPMAccountManagementOperations"
        SpecifyNextAccountContent              = "specifyNextAccountContent"
        RenameAccounts                         = "renameAccounts"
        DeleteAccounts                         = "deleteAccounts"
        UnlockAccounts                         = "unlockAccounts"
        ManageSafe                             = "manageSafe"
        ManageSafeMembers                      = "manageSafeMembers"
        BackupSafe                             = "backupSafe"
        ViewAuditLog                           = "viewAuditLog"
        ViewSafeMembers                        = "viewSafeMembers"
        RequestsAuthorizationLevel             = "requestsAuthorizationLevel"
        AccessWithoutConfirmation              = "accessWithoutConfirmation"
        CreateFolders                          = "createFolders"
        DeleteFolders                          = "deleteFolders"
        MoveAccountsAndFolders                 = "moveAccountsAndFolders"
    }
}

function New-PermissionsFromCsvRow {
    param (
        [Parameter(Mandatory = $true)]
        [object]$Row
    )

    $Permissions = [ordered]@{}
    $PermissionMap = Get-PermissionColumnMap

    foreach ($CsvColumn in $PermissionMap.Keys) {
        if ($Row.PSObject.Properties.Name -notcontains $CsvColumn) {
            continue
        }

        $RawValue = $Row.$CsvColumn
        if ($null -eq $RawValue -or [string]::IsNullOrWhiteSpace([string]$RawValue)) {
            continue
        }

        if ($CsvColumn -eq "RequestsAuthorizationLevel") {
            $IntValue = 0
            if ([int]::TryParse(([string]$RawValue).Trim(), [ref]$IntValue)) {
                $Permissions[$PermissionMap[$CsvColumn]] = $IntValue
            }
            continue
        }

        $Permissions[$PermissionMap[$CsvColumn]] = ConvertTo-CyberArkBoolean -Value $RawValue
    }

    return $Permissions
}

function New-SafeLookup {
    param (
        [Parameter(Mandatory = $true)]
        [object[]]$Safes
    )

    $Lookup = @{}
    foreach ($Safe in $Safes) {
        if ($Safe.PSObject.Properties.Name -notcontains "safeName" -or [string]::IsNullOrWhiteSpace([string]$Safe.safeName)) {
            continue
        }
        $Lookup[[string]$Safe.safeName] = $Safe
    }
    return $Lookup
}

function Get-SafePropertyValue {
    param (
        [Parameter(Mandatory = $true)]
        [object]$Safe,

        [Parameter(Mandatory = $true)]
        [string[]]$Names
    )

    foreach ($Name in $Names) {
        if ($Safe.PSObject.Properties.Name -contains $Name) {
            return $Safe.$Name
        }
    }

    return $null
}

function ConvertTo-DesiredManagingCpm {
    param (
        [Parameter(Mandatory = $false)]
        [AllowNull()]
        [object]$Value
    )

    if ($null -eq $Value) {
        return $null
    }

    $Text = ([string]$Value).Trim()
    if ([string]::IsNullOrWhiteSpace($Text)) {
        return $null
    }
    if ($Text -match "^(?i:NULL|<NONE>)$") {
        return ""
    }

    return $Text
}

function New-SafeCpmUpdateBody {
    param (
        [Parameter(Mandatory = $true)]
        [object]$Safe,

        [Parameter(Mandatory = $true)]
        [AllowEmptyString()]
        [string]$ManagingCPM
    )

    $SafeName = [string](Get-SafePropertyValue -Safe $Safe -Names @("safeName", "SafeName"))
    if ([string]::IsNullOrWhiteSpace($SafeName)) {
        throw "Safe details did not contain a safe name."
    }

    $Body = [ordered]@{
        SafeName    = $SafeName
        Description = [string](Get-SafePropertyValue -Safe $Safe -Names @("description", "Description"))
        OLACEnabled = [bool](Get-SafePropertyValue -Safe $Safe -Names @("olacEnabled", "OLACEnabled"))
        ManagingCPM = $ManagingCPM
    }

    $Versions = Get-SafePropertyValue -Safe $Safe -Names @("numberOfVersionsRetention", "NumberOfVersionsRetention")
    $Days = Get-SafePropertyValue -Safe $Safe -Names @("numberOfDaysRetention", "NumberOfDaysRetention")
    if ($null -ne $Versions -and -not [string]::IsNullOrWhiteSpace([string]$Versions)) {
        $Body["NumberOfVersionsRetention"] = [int]$Versions
    }
    elseif ($null -ne $Days -and -not [string]::IsNullOrWhiteSpace([string]$Days)) {
        $Body["NumberOfDaysRetention"] = [int]$Days
    }
    else {
        throw "Safe $SafeName did not contain a retention setting."
    }

    return $Body
}

function Find-SafeByName {
    param (
        [Parameter(Mandatory = $true)]
        [string]$TenantUrl,

        [Parameter(Mandatory = $true)]
        [string]$SafeName,

        [Parameter(Mandatory = $true)]
        [hashtable]$Headers
    )

    $EncodedName = [uri]::EscapeDataString($SafeName)
    $Response = Invoke-CyberArkGet -Uri "$TenantUrl/API/Safes?search=$EncodedName&limit=100&offset=0" -Headers $Headers
    $Candidates = @()
    if ($Response.PSObject.Properties.Name -contains "value" -and $null -ne $Response.value) {
        $Candidates = @($Response.value)
    }
    elseif ($Response -is [array]) {
        $Candidates = @($Response)
    }

    $Matches = @($Candidates | Where-Object {
        $CandidateName = [string](Get-SafePropertyValue -Safe $_ -Names @("safeName", "SafeName"))
        [string]::Equals($CandidateName, $SafeName, [StringComparison]::OrdinalIgnoreCase)
    })

    if ($Matches.Count -eq 0) {
        throw "Safe '$SafeName' was not found."
    }
    if ($Matches.Count -gt 1) {
        throw "More than one exact match was returned for safe '$SafeName'."
    }

    return $Matches[0]
}

function Test-SafeMemberExists {
    param (
        [Parameter(Mandatory = $true)]
        [string]$TenantUrl,

        [Parameter(Mandatory = $true)]
        [string]$SafeUrlId,

        [Parameter(Mandatory = $true)]
        [string]$MemberName,

        [Parameter(Mandatory = $true)]
        [hashtable]$Headers
    )

    $EncodedMember = [uri]::EscapeDataString($MemberName)
    $Uri = "$TenantUrl/API/Safes/$SafeUrlId/Members/$EncodedMember"

    try {
        $null = Invoke-CyberArkGet -Uri $Uri -Headers $Headers
        return $true
    }
    catch {
        $Message = [string]$_.Exception.Message
        if ($Message -match "HTTP 404|PASWS|not found|does not exist") {
            return $false
        }
        throw
    }
}

function Add-SafeMemberFromCsvRow {
    param (
        [Parameter(Mandatory = $true)]
        [string]$TenantUrl,

        [Parameter(Mandatory = $true)]
        [string]$SafeUrlId,

        [Parameter(Mandatory = $true)]
        [object]$Row,

        [Parameter(Mandatory = $true)]
        [hashtable]$Headers
    )

    $MemberName = Get-RowValue -Row $Row -Names @("UserName", "Member", "memberName")
    $MemberType = Get-RowValue -Row $Row -Names @("MemberType", "memberType")
    $MemberLocation = Get-RowValue -Row $Row -Names @("MemberLocation", "UserLocation", "memberLocation")
    $Permissions = New-PermissionsFromCsvRow -Row $Row

    if ([string]::IsNullOrWhiteSpace($MemberName)) {
        throw "CSV row is missing UserName or Member."
    }
    if ([string]::IsNullOrWhiteSpace($MemberType)) {
        $IsGroup = Get-RowValue -Row $Row -Names @("IsGroup")
        $IdentityType = Get-RowValue -Row $Row -Names @("IdentityType")
        if ($IsGroup -match "^(?i:true|yes|1)$" -or $IdentityType -match "^(?i:group)$") {
            $MemberType = "Group"
        }
        else {
            $MemberType = "User"
        }
    }

    $Body = [ordered]@{
        memberName  = $MemberName
        memberType  = $MemberType
        permissions = $Permissions
    }

    if (-not [string]::IsNullOrWhiteSpace($MemberLocation) -and $MemberLocation.ToLowerInvariant() -ne "vault") {
        $Body["searchIn"] = $MemberLocation
    }

    $Uri = "$TenantUrl/API/Safes/$SafeUrlId/Members"
    $null = Invoke-CyberArkJsonRequest -Method "POST" -Uri $Uri -Headers $Headers -Body $Body
}

function ConvertTo-UnixSeconds {
    param (
        [Parameter(Mandatory = $true)]
        [datetime]$DateTime
    )

    return [int64]([datetimeoffset]$DateTime.ToUniversalTime()).ToUnixTimeSeconds()
}

function ConvertFrom-CyberArkEpoch {
    param (
        [Parameter(Mandatory = $false)]
        [object]$Value
    )

    if ($null -eq $Value -or [string]::IsNullOrWhiteSpace([string]$Value)) {
        return $null
    }

    $Epoch = [int64]0
    if (-not [int64]::TryParse(([string]$Value).Trim(), [ref]$Epoch)) {
        $Parsed = [datetime]::MinValue
        if ([datetime]::TryParse(([string]$Value).Trim(), [ref]$Parsed)) {
            return $Parsed
        }
        return $null
    }

    if (([string][math]::Abs($Epoch)).Length -gt 10) {
        return [datetimeoffset]::FromUnixTimeMilliseconds($Epoch).LocalDateTime
    }
    return [datetimeoffset]::FromUnixTimeSeconds($Epoch).LocalDateTime
}

function Get-ObjectStringValue {
    param (
        [Parameter(Mandatory = $true)]
        [object]$Item,

        [Parameter(Mandatory = $true)]
        [string[]]$Names
    )

    foreach ($Name in $Names) {
        if ($Item.PSObject.Properties.Name -contains $Name -and $null -ne $Item.$Name) {
            $Value = [string]$Item.$Name
            if (-not [string]::IsNullOrWhiteSpace($Value)) {
                return $Value.Trim()
            }
        }
    }
    return ""
}

function New-QueryString {
    param (
        [Parameter(Mandatory = $true)]
        [hashtable]$Parameters
    )

    $Parts = @()
    foreach ($Key in $Parameters.Keys) {
        if ($null -eq $Parameters[$Key] -or [string]::IsNullOrWhiteSpace([string]$Parameters[$Key])) {
            continue
        }
        $Parts += "$([uri]::EscapeDataString($Key))=$([uri]::EscapeDataString([string]$Parameters[$Key]))"
    }
    return ($Parts -join "&")
}

function Get-PagedPsmRecordings {
    param (
        [Parameter(Mandatory = $true)]
        [string]$PVWAUrl,

        [Parameter(Mandatory = $true)]
        [hashtable]$Headers,

        [Parameter(Mandatory = $true)]
        [datetime]$FromTime,

        [Parameter(Mandatory = $true)]
        [datetime]$ToTime,

        [Parameter(Mandatory = $false)]
        [int]$Limit = 100
    )

    $Recordings = @()
    $Offset = 0
    $Total = $null
    $FromEpoch = ConvertTo-UnixSeconds -DateTime $FromTime
    $ToEpoch = ConvertTo-UnixSeconds -DateTime $ToTime

    while ($true) {
        $Query = New-QueryString -Parameters @{
            FromTime = $FromEpoch
            ToTime   = $ToEpoch
            Limit    = $Limit
            OffSet   = $Offset
        }
        $Uri = "$PVWAUrl/API/Recordings?$Query"
        $Response = Invoke-CyberArkGet -Uri $Uri -Headers $Headers

        $Page = @()
        if ($Response.PSObject.Properties.Name -contains "Recordings" -and $null -ne $Response.Recordings) {
            $Page = @($Response.Recordings)
        }
        elseif ($Response.PSObject.Properties.Name -contains "value" -and $null -ne $Response.value) {
            $Page = @($Response.value)
        }
        elseif ($Response -is [array]) {
            $Page = @($Response)
        }

        if ($null -eq $Total -and $Response.PSObject.Properties.Name -contains "Total" -and $null -ne $Response.Total) {
            $Total = [int]$Response.Total
        }

        if ($Page.Count -eq 0) {
            break
        }

        $Recordings += $Page
        $Offset += $Limit

        if ($null -ne $Total) {
            if ($Offset -ge $Total) {
                break
            }
        }
        elseif ($Page.Count -lt $Limit) {
            break
        }
    }

    return $Recordings
}

function Export-PsmUsersFromRecordings {
    param (
        [Parameter(Mandatory = $true)]
        [string]$PVWAUrl,

        [Parameter(Mandatory = $true)]
        [string]$Token,

        [Parameter(Mandatory = $true)]
        [string]$OutputFile,

        [Parameter(Mandatory = $false)]
        [int]$LookbackDays = 90
    )

    if ($LookbackDays -le 0) {
        throw "Lookback days must be greater than zero."
    }

    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
    $Headers = @{
        "Authorization" = $Token
        "Content-Type"  = "application/json"
    }

    $ToTime = Get-Date
    $FromTime = $ToTime.AddDays(-1 * $LookbackDays)

    Write-Host "Fetching PSM recordings from $($FromTime.ToString('s')) through $($ToTime.ToString('s'))..." -ForegroundColor Cyan
    $Recordings = @(Get-PagedPsmRecordings -PVWAUrl $PVWAUrl -Headers $Headers -FromTime $FromTime -ToTime $ToTime)

    if ($Recordings.Count -eq 0) {
        Write-Warning "No PSM recordings were found for the selected time window, or the account does not have permission to view recordings."
        return
    }

    Write-Host "Found $($Recordings.Count) recordings. Summarizing unique PSM users..." -ForegroundColor Green

    $Grouped = $Recordings | Group-Object -Property {
        $User = Get-ObjectStringValue -Item $_ -Names @("PSMVaultUserName", "UserName", "VaultUserName", "Username")
        if ([string]::IsNullOrWhiteSpace($User)) {
            return "<unknown>"
        }
        return $User
    }

    $ExportData = @()
    foreach ($Group in $Grouped) {
        if ($Group.Name -eq "<unknown>") {
            continue
        }

        $StartTimes = @()
        foreach ($Recording in $Group.Group) {
            $StartValue = Get-ObjectStringValue -Item $Recording -Names @("PSMStartTime", "StartTime", "Start", "CreationDate")
            $StartTime = ConvertFrom-CyberArkEpoch -Value $StartValue
            if ($null -ne $StartTime) {
                $StartTimes += $StartTime
            }
        }

        $FirstSession = ""
        $LastSession = ""
        if ($StartTimes.Count -gt 0) {
            $FirstSession = ($StartTimes | Sort-Object | Select-Object -First 1).ToString("s")
            $LastSession = ($StartTimes | Sort-Object | Select-Object -Last 1).ToString("s")
        }

        $Safes = @($Group.Group | ForEach-Object { Get-ObjectStringValue -Item $_ -Names @("SafeName") } | Where-Object { -not [string]::IsNullOrWhiteSpace($_) } | Sort-Object -Unique)
        $Targets = @($Group.Group | ForEach-Object { Get-ObjectStringValue -Item $_ -Names @("RemoteMachine", "AccountAddress") } | Where-Object { -not [string]::IsNullOrWhiteSpace($_) } | Sort-Object -Unique)
        $Protocols = @($Group.Group | ForEach-Object { Get-ObjectStringValue -Item $_ -Names @("Protocol", "PSMProtocol") } | Where-Object { -not [string]::IsNullOrWhiteSpace($_) } | Sort-Object -Unique)
        $Clients = @($Group.Group | ForEach-Object { Get-ObjectStringValue -Item $_ -Names @("Client", "PSMClientApp") } | Where-Object { -not [string]::IsNullOrWhiteSpace($_) } | Sort-Object -Unique)

        $ExportData += [PSCustomObject][ordered]@{
            UserName       = $Group.Name
            SessionCount   = $Group.Count
            FirstSession   = $FirstSession
            LastSession    = $LastSession
            Protocols      = ($Protocols -join "; ")
            Clients        = ($Clients -join "; ")
            Safes          = ($Safes -join "; ")
            RemoteMachines = ($Targets -join "; ")
        }
    }

    if ($ExportData.Count -eq 0) {
        Write-Warning "Recordings were returned, but no PSM vault user names were found in them."
        return
    }

    $ExportData |
        Sort-Object @{ Expression = "SessionCount"; Descending = $true }, UserName |
        Export-Csv -Path $OutputFile -NoTypeInformation -Encoding UTF8

    Write-Host "Export complete. Data saved to $OutputFile" -ForegroundColor Green
}

function Import-SafeMembersAndGroups {
    param (
        [Parameter(Mandatory = $true)]
        [string]$Subdomain,

        [Parameter(Mandatory = $true)]
        [string]$Token,

        [Parameter(Mandatory = $true)]
        [string]$CsvPath
    )

    if (-not (Test-Path -Path $CsvPath -PathType Leaf)) {
        throw "CSV file not found: $CsvPath"
    }

    $TenantUrl = "https://$Subdomain.privilegecloud.cyberark.cloud/PasswordVault"
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

    $Headers = @{
        "Authorization" = $Token
        "Content-Type"  = "application/json"
    }

    Write-Host "Reading CSV: $CsvPath" -ForegroundColor Cyan
    $Rows = @(Import-Csv -Path $CsvPath)
    if ($Rows.Count -eq 0) {
        Write-Warning "CSV contained no rows."
        return
    }

    Write-Host "Fetching safes for lookup..." -ForegroundColor Cyan
    $Safes = @(Get-PagedVaultItems -BaseUrl $TenantUrl -Path "Safes" -Headers $Headers)
    $SafeLookup = New-SafeLookup -Safes $Safes

    $Added = 0
    $Skipped = 0
    $Failed = 0

    foreach ($Row in $Rows) {
        $SafeName = Get-RowValue -Row $Row -Names @("SafeName", "Safename", "safeName")
        $MemberName = Get-RowValue -Row $Row -Names @("UserName", "Member", "memberName")

        if ([string]::IsNullOrWhiteSpace($SafeName) -or [string]::IsNullOrWhiteSpace($MemberName)) {
            Write-Warning "Skipping row missing SafeName/Safename or UserName/Member."
            $Skipped++
            continue
        }

        if (-not $SafeLookup.ContainsKey($SafeName)) {
            Write-Warning "Skipping $MemberName on $SafeName because the safe was not found."
            $Skipped++
            continue
        }

        $Safe = $SafeLookup[$SafeName]
        $SafeUrlId = $Safe.safeUrlId
        if ([string]::IsNullOrWhiteSpace($SafeUrlId)) {
            $SafeUrlId = [uri]::EscapeDataString($SafeName)
        }

        try {
            if (Test-SafeMemberExists -TenantUrl $TenantUrl -SafeUrlId $SafeUrlId -MemberName $MemberName -Headers $Headers) {
                Write-Host "Skipping existing member: $MemberName on $SafeName" -ForegroundColor Yellow
                $Skipped++
                continue
            }

            Add-SafeMemberFromCsvRow -TenantUrl $TenantUrl -SafeUrlId $SafeUrlId -Row $Row -Headers $Headers
            Write-Host "Added member: $MemberName on $SafeName" -ForegroundColor Green
            $Added++
        }
        catch {
            Write-Warning "Failed to add $MemberName on $SafeName. $($_.Exception.Message)"
            $Failed++
        }
    }

    Write-Host ""
    Write-Host "Import complete." -ForegroundColor Cyan
    Write-Host "Added:   $Added"
    Write-Host "Skipped: $Skipped"
    Write-Host "Failed:  $Failed"
}

function Export-SafeMembersAndGroups {
    param (
        [Parameter(Mandatory = $true)]
        [string]$Subdomain,

        [Parameter(Mandatory = $true)]
        [string]$Token,

        [Parameter(Mandatory = $true)]
        [string]$OutputFile
    )

    $TenantUrl = "https://$Subdomain.privilegecloud.cyberark.cloud/PasswordVault"
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

    $Headers = @{
        "Authorization" = $Token
        "Content-Type"  = "application/json"
    }

    Write-Host "Starting Safe member and group export for $Subdomain..." -ForegroundColor Cyan
    Write-Host "Fetching Safes from $TenantUrl..." -ForegroundColor Cyan

    $AllSafes = Get-PagedVaultItems -BaseUrl $TenantUrl -Path "Safes" -Headers $Headers

    if ($AllSafes.Count -eq 0) {
        Write-Warning "No safes found, or the token does not have permission to list safes."
        return
    }

    Write-Host "Found $($AllSafes.Count) safes." -ForegroundColor Green
    Write-Host "Fetching Safe Members..." -ForegroundColor Cyan

    $ExportData = @()

    foreach ($Safe in $AllSafes) {
        $SafeName = $Safe.safeName
        $SafeUrlId = $Safe.safeUrlId

        if ([string]::IsNullOrWhiteSpace($SafeUrlId)) {
            $SafeUrlId = [uri]::EscapeDataString($SafeName)
        }

        Write-Host " -> Processing Safe: $SafeName"

        try {
            $Members = Get-PagedVaultItems -BaseUrl $TenantUrl -Path "Safes/$SafeUrlId/Members" -Headers $Headers

            foreach ($Member in $Members) {
                $IdentityType = Get-MemberIdentityType -Member $Member
                $Record = [ordered]@{
                    SafeName       = $SafeName
                    UserName       = $Member.memberName
                    MemberType     = $Member.memberType
                    IdentityType   = $IdentityType
                    IsGroup        = ($IdentityType -eq "GROUP")
                    UserLocation   = "Vault"
                }

                if ($null -ne $Member.permissions) {
                    foreach ($Perm in $Member.permissions.psobject.properties) {
                        $Record[$Perm.Name] = $Perm.Value
                    }
                }

                $ExportData += [PSCustomObject]$Record
            }
        }
        catch {
            Write-Warning "Failed to fetch members for safe $SafeName. $($_.Exception.Message)"
        }
    }

    if ($ExportData.Count -eq 0) {
        Write-Warning "No safe members were exported."
        return
    }

    $ExportData |
        Sort-Object SafeName, @{ Expression = { if ($_.IsGroup) { 0 } else { 1 } } }, UserName |
        Export-Csv -Path $OutputFile -NoTypeInformation -Encoding UTF8

    Write-Host ""
    Write-Host "Export complete. Data saved to $OutputFile" -ForegroundColor Green
}

function Export-SafeCpmAssignments {
    param (
        [Parameter(Mandatory = $true)]
        [string]$Subdomain,

        [Parameter(Mandatory = $true)]
        [string]$Token,

        [Parameter(Mandatory = $true)]
        [string]$OutputFile
    )

    $TenantUrl = "https://$Subdomain.privilegecloud.cyberark.cloud/PasswordVault"
    $Headers = @{
        "Authorization" = $Token
        "Content-Type"  = "application/json"
    }

    Write-Host "Fetching safes and their assigned CPMs..." -ForegroundColor Cyan
    $Safes = @(Get-PagedVaultItems -BaseUrl $TenantUrl -Path "Safes" -Headers $Headers)
    if ($Safes.Count -eq 0) {
        Write-Warning "No safes found, or the token does not have permission to list safes."
        return
    }

    $Rows = @()
    foreach ($Safe in $Safes) {
        $SafeName = [string](Get-SafePropertyValue -Safe $Safe -Names @("safeName", "SafeName"))
        if ([string]::IsNullOrWhiteSpace($SafeName)) {
            Write-Warning "Skipping a safe whose name could not be determined."
            continue
        }

        $CurrentManagingCPM = [string](Get-SafePropertyValue -Safe $Safe -Names @("managingCPM", "ManagingCPM"))
        $Rows += [PSCustomObject][ordered]@{
            SafeName           = $SafeName
            CurrentManagingCPM = $CurrentManagingCPM
            ManagingCPM        = $CurrentManagingCPM
        }
    }

    $Rows |
        Sort-Object SafeName |
        Export-Csv -Path $OutputFile -NoTypeInformation -Encoding UTF8

    Write-Host "Export complete. Data saved to $OutputFile" -ForegroundColor Green
    Write-Host "Edit ManagingCPM, leave it blank to skip a safe, or use NULL to clear the assignment." -ForegroundColor Yellow
}

function Import-SafeCpmAssignments {
    param (
        [Parameter(Mandatory = $true)]
        [string]$Subdomain,

        [Parameter(Mandatory = $true)]
        [string]$Token,

        [Parameter(Mandatory = $true)]
        [string]$CsvPath
    )

    if (-not (Test-Path -Path $CsvPath -PathType Leaf)) {
        throw "CSV file not found: $CsvPath"
    }

    $Rows = @(Import-Csv -Path $CsvPath)
    if ($Rows.Count -eq 0) {
        Write-Warning "CSV contained no rows."
        return
    }
    if ($Rows[0].PSObject.Properties.Name -notcontains "SafeName" -or
        $Rows[0].PSObject.Properties.Name -notcontains "ManagingCPM") {
        throw "CSV must contain SafeName and ManagingCPM columns."
    }

    $TenantUrl = "https://$Subdomain.privilegecloud.cyberark.cloud/PasswordVault"
    $Headers = @{
        "Authorization" = $Token
        "Content-Type"  = "application/json"
    }

    $HasCurrentManagingCpmColumn = $Rows[0].PSObject.Properties.Name -contains "CurrentManagingCPM"
    if (-not $HasCurrentManagingCpmColumn) {
        Write-Warning "CSV has no CurrentManagingCPM column. Every nonblank row must be checked against CyberArk."
    }

    $Skipped = 0
    $Failed = 0
    $SeenSafes = @{}
    $EditedRows = @()

    foreach ($Row in $Rows) {
        $SafeName = Get-RowValue -Row $Row -Names @("SafeName")
        $DesiredManagingCPM = ConvertTo-DesiredManagingCpm -Value $Row.ManagingCPM

        if ([string]::IsNullOrWhiteSpace($SafeName)) {
            Write-Warning "Skipping a row with no SafeName."
            $Skipped++
            continue
        }
        if ($null -eq $DesiredManagingCPM) {
            $Skipped++
            continue
        }
        if ($SeenSafes.ContainsKey($SafeName)) {
            Write-Warning "Skipping duplicate CSV row for safe $SafeName."
            $Skipped++
            continue
        }
        $SeenSafes[$SafeName] = $true

        if ($HasCurrentManagingCpmColumn) {
            $CsvCurrentManagingCPM = ([string]$Row.CurrentManagingCPM).Trim()
            if ([string]::Equals($CsvCurrentManagingCPM, $DesiredManagingCPM, [StringComparison]::OrdinalIgnoreCase)) {
                $Skipped++
                continue
            }
        }

        $EditedRows += [PSCustomObject]@{
            SafeName           = $SafeName
            CurrentManagingCPM = if ($HasCurrentManagingCpmColumn) { ([string]$Row.CurrentManagingCPM).Trim() } else { "<not provided>" }
            ManagingCPM        = $DesiredManagingCPM
        }
    }

    if ($EditedRows.Count -eq 0) {
        Write-Host "No edited CPM assignments were found in the CSV. Skipped: $Skipped" -ForegroundColor Yellow
        return
    }

    Write-Host ""
    Write-Host "Proposed safe CPM changes from the CSV:" -ForegroundColor Yellow
    $EditedRows |
        Select-Object SafeName, CurrentManagingCPM, @{ Name = "NewManagingCPM"; Expression = { $_.ManagingCPM } } |
        Format-Table -AutoSize
    Write-Warning "This will check and potentially update $($EditedRows.Count) safe(s)."
    $Confirmation = Read-Host "Type APPLY to continue"
    if ($Confirmation -cne "APPLY") {
        Write-Host "No changes were made." -ForegroundColor Yellow
        return
    }

    $Updated = 0
    Write-Host "Applying edited rows without fetching unchanged safes..." -ForegroundColor Cyan
    foreach ($EditedRow in $EditedRows) {
        $SafeName = $EditedRow.SafeName
        $DesiredManagingCPM = $EditedRow.ManagingCPM

        try {
            $SafeDetails = Find-SafeByName -TenantUrl $TenantUrl -SafeName $SafeName -Headers $Headers
            $SafeUrlId = [string](Get-SafePropertyValue -Safe $SafeDetails -Names @("safeUrlId", "SafeUrlId"))
            if ([string]::IsNullOrWhiteSpace($SafeUrlId)) {
                throw "Safe '$SafeName' did not contain a safeUrlId."
            }

            $CurrentManagingCPM = [string](Get-SafePropertyValue -Safe $SafeDetails -Names @("managingCPM", "ManagingCPM"))
            if ([string]::Equals($CurrentManagingCPM, $DesiredManagingCPM, [StringComparison]::OrdinalIgnoreCase)) {
                Write-Host "Skipping $SafeName because it already uses '$DesiredManagingCPM'." -ForegroundColor Yellow
                $Skipped++
                continue
            }

            $Body = New-SafeCpmUpdateBody -Safe $SafeDetails -ManagingCPM $DesiredManagingCPM
            $Uri = "$TenantUrl/API/Safes/$SafeUrlId"
            $null = Invoke-CyberArkJsonRequest -Method "PUT" -Uri $Uri -Headers $Headers -Body $Body

            $VerifiedSafe = Find-SafeByName -TenantUrl $TenantUrl -SafeName $SafeName -Headers $Headers
            $VerifiedManagingCPM = [string](Get-SafePropertyValue -Safe $VerifiedSafe -Names @("managingCPM", "ManagingCPM"))
            if (-not [string]::Equals($VerifiedManagingCPM, $DesiredManagingCPM, [StringComparison]::OrdinalIgnoreCase)) {
                throw "Verification returned ManagingCPM '$VerifiedManagingCPM'."
            }

            Write-Host "Updated $SafeName`: '$CurrentManagingCPM' -> '$DesiredManagingCPM'" -ForegroundColor Green
            $Updated++
        }
        catch {
            Write-Warning "Failed to update $SafeName. $($_.Exception.Message)"
            $Failed++
        }
    }

    Write-Host ""
    Write-Host "Safe CPM import complete." -ForegroundColor Cyan
    Write-Host "Updated: $Updated"
    Write-Host "Skipped: $Skipped"
    Write-Host "Failed:  $Failed"
}

function Get-PlatformIdentifier {
    param (
        [Parameter(Mandatory = $true)]
        [object]$Platform
    )

    foreach ($PropertyName in @("PlatformID", "platformID", "id")) {
        if ($Platform.PSObject.Properties.Name -contains $PropertyName) {
            $Value = [string]$Platform.$PropertyName
            if (-not [string]::IsNullOrWhiteSpace($Value)) {
                return $Value
            }
        }
    }

    if ($Platform.PSObject.Properties.Name -contains "general" -and $null -ne $Platform.general) {
        if ($Platform.general.PSObject.Properties.Name -contains "id") {
            return [string]$Platform.general.id
        }
    }

    return ""
}

function Get-PlatformDisplayName {
    param (
        [Parameter(Mandatory = $true)]
        [object]$Platform
    )

    if ($Platform.PSObject.Properties.Name -contains "Details" -and $null -ne $Platform.Details) {
        if ($Platform.Details.PSObject.Properties.Name -contains "PolicyName") {
            return [string]$Platform.Details.PolicyName
        }
    }
    if ($Platform.PSObject.Properties.Name -contains "general" -and $null -ne $Platform.general) {
        if ($Platform.general.PSObject.Properties.Name -contains "name") {
            return [string]$Platform.general.name
        }
    }
    if ($Platform.PSObject.Properties.Name -contains "Name") {
        return [string]$Platform.Name
    }

    return ""
}

function Find-PlatformStringMatches {
    param (
        [Parameter(Mandatory = $true)]
        [AllowNull()]
        [object]$Value,

        [Parameter(Mandatory = $false)]
        [string]$Path = ""
    )

    $Results = @()
    if ($Value -is [string]) {
        if ($Value -match "(?i)pmterminal(?:\.exe)?") {
            $Results += [PSCustomObject]@{
                PropertyPath = $Path
                CurrentValue = $Value
            }
        }
        return $Results
    }

    if ($Value -is [System.Collections.IDictionary]) {
        foreach ($Key in $Value.Keys) {
            $ChildPath = if ([string]::IsNullOrWhiteSpace($Path)) { [string]$Key } else { "$Path.$Key" }
            $Results += @(Find-PlatformStringMatches -Value $Value[$Key] -Path $ChildPath)
        }
        return $Results
    }

    if ($Value -is [System.Collections.IEnumerable]) {
        $Index = 0
        foreach ($Item in $Value) {
            $Results += @(Find-PlatformStringMatches -Value $Item -Path "$($Path)[$Index]")
            $Index++
        }
        return $Results
    }

    if ($null -ne $Value -and $null -ne $Value.PSObject) {
        foreach ($Property in $Value.PSObject.Properties) {
            $ChildPath = if ([string]::IsNullOrWhiteSpace($Path)) { $Property.Name } else { "$Path.$($Property.Name)" }
            $Results += @(Find-PlatformStringMatches -Value $Property.Value -Path $ChildPath)
        }
    }

    return $Results
}

function Export-PMTerminalPlatformAudit {
    param (
        [Parameter(Mandatory = $true)]
        [string]$Subdomain,

        [Parameter(Mandatory = $true)]
        [string]$Token,

        [Parameter(Mandatory = $true)]
        [string]$OutputFile
    )

    $TenantUrl = "https://$Subdomain.privilegecloud.cyberark.cloud/PasswordVault"
    $Headers = @{
        "Authorization" = $Token
        "Content-Type"  = "application/json"
    }

    Write-Host "Fetching target platforms..." -ForegroundColor Cyan
    $Response = Invoke-CyberArkGet -Uri "$TenantUrl/API/Platforms" -Headers $Headers
    $Platforms = @()
    if ($Response.PSObject.Properties.Name -contains "Platforms" -and $null -ne $Response.Platforms) {
        $Platforms = @($Response.Platforms)
    }
    elseif ($Response.PSObject.Properties.Name -contains "value" -and $null -ne $Response.value) {
        $Platforms = @($Response.value)
    }
    elseif ($Response -is [array]) {
        $Platforms = @($Response)
    }

    if ($Platforms.Count -eq 0) {
        Write-Warning "No visible platforms were returned."
        return
    }

    Write-Host "Inspecting $($Platforms.Count) platform(s) for PMTerminal CPM plug-in values..." -ForegroundColor Cyan
    $AuditRows = @()
    foreach ($Platform in $Platforms) {
        $PlatformId = Get-PlatformIdentifier -Platform $Platform
        if ([string]::IsNullOrWhiteSpace($PlatformId)) {
            Write-Warning "Skipping a platform whose ID could not be determined."
            continue
        }

        try {
            $EncodedPlatformId = [uri]::EscapeDataString($PlatformId)
            $Details = Invoke-CyberArkGet -Uri "$TenantUrl/API/Platforms/$EncodedPlatformId" -Headers $Headers
            $PlatformName = Get-PlatformDisplayName -Platform $Details
            if ([string]::IsNullOrWhiteSpace($PlatformName)) {
                $PlatformName = Get-PlatformDisplayName -Platform $Platform
            }

            foreach ($Match in @(Find-PlatformStringMatches -Value $Details)) {
                $AuditRows += [PSCustomObject]@{
                    PlatformID   = $PlatformId
                    PlatformName = $PlatformName
                    PropertyPath = $Match.PropertyPath
                    CurrentValue = $Match.CurrentValue
                    TargetValue  = "CyberArk.TPC.exe"
                }
            }
        }
        catch {
            Write-Warning "Failed to inspect platform $PlatformId. $($_.Exception.Message)"
        }
    }

    if ($AuditRows.Count -eq 0) {
        Write-Host "No PMTerminal CPM plug-in values were found." -ForegroundColor Green
        return
    }

    $AuditRows |
        Sort-Object PlatformID, PropertyPath |
        Export-Csv -Path $OutputFile -NoTypeInformation -Encoding UTF8

    Write-Host ""
    Write-Host "Found $($AuditRows.Count) matching setting(s):" -ForegroundColor Yellow
    $AuditRows | Format-Table PlatformID, PlatformName, PropertyPath, CurrentValue -AutoSize
    Write-Host "Audit saved to $OutputFile" -ForegroundColor Green
    Write-Warning "No changes were made. CyberArk does not document an in-place REST update for this platform setting."
}

function Start-CyberArkApiRunner {
    if ([string]::IsNullOrWhiteSpace($script:EnvironmentType)) {
        $script:EnvironmentType = Read-Choice -Prompt "CyberArk environment" -Choices @("privilegecloud", "onprem")
    }

    if ($script:EnvironmentType -eq "onprem") {
        if ([string]::IsNullOrWhiteSpace($script:PVWAUrl)) {
            $script:PVWAUrl = Read-RequiredValue -Prompt "PVWA URL, e.g. https://pvwa.company.com/PasswordVault"
        }
        $script:PVWAUrl = Resolve-PVWAUrl -Url $script:PVWAUrl
        $script:Token = Get-OnPremSessionToken -PVWAUrl $script:PVWAUrl -ExistingToken $script:Token

        while ($true) {
            Write-Host ""
            Write-Host "CyberArk PowerShell API Runner - On-Prem" -ForegroundColor Cyan
            Write-Host "PVWA: $script:PVWAUrl"
            Write-Host "1. Export PSM users from recordings CSV (last $script:PsmLookbackDays days)"
            Write-Host "2. Quit"
            $Choice = Read-Host "Choose an option"

            switch ($Choice) {
                "1" {
                    $PsmOutputFile = New-TimestampedOutputPath -Prefix "psm_users_past_$($script:PsmLookbackDays)_days"
                    Export-PsmUsersFromRecordings -PVWAUrl $script:PVWAUrl -Token $script:Token -OutputFile $PsmOutputFile -LookbackDays $script:PsmLookbackDays
                }
                "2" {
                    return
                }
                default {
                    Write-Host "Choose 1 or 2." -ForegroundColor Yellow
                }
            }
        }
    }

    if ([string]::IsNullOrWhiteSpace($script:Subdomain)) {
        $script:Subdomain = Read-RequiredValue -Prompt "Privilege Cloud tenant subdomain, e.g. serviceslab"
    }
    else {
        $script:Subdomain = $script:Subdomain.Trim()
    }

    $script:Token = Get-PlatformToken -Subdomain $script:Subdomain -ExistingToken $script:Token

    while ($true) {
        Write-Host ""
        Write-Host "CyberArk PowerShell API Runner - Privilege Cloud" -ForegroundColor Cyan
        Write-Host "1. Fetch safe members and groups CSV"
        Write-Host "2. Add safe members and groups from CSV"
        Write-Host "3. Audit platforms using the PMTerminal CPM plug-in"
        Write-Host "4. Export safe CPM assignments CSV"
        Write-Host "5. Update safe CPM assignments from CSV"
        Write-Host "6. Quit"
        $Choice = Read-Host "Choose an option"

        switch ($Choice) {
            "1" {
                $SafeOutputFile = $script:OutputFile
                if ([string]::IsNullOrWhiteSpace($SafeOutputFile)) {
                    $SafeOutputFile = New-TimestampedOutputPath -Prefix "safe_members_and_groups"
                }
                Export-SafeMembersAndGroups -Subdomain $script:Subdomain -Token $script:Token -OutputFile $SafeOutputFile
            }
            "2" {
                if ([string]::IsNullOrWhiteSpace($script:CsvPath)) {
                    $script:CsvPath = Read-RequiredValue -Prompt "CSV file path"
                }
                Import-SafeMembersAndGroups -Subdomain $script:Subdomain -Token $script:Token -CsvPath $script:CsvPath
            }
            "3" {
                $PlatformAuditFile = New-TimestampedOutputPath -Prefix "pmterminal_platform_audit"
                Export-PMTerminalPlatformAudit -Subdomain $script:Subdomain -Token $script:Token -OutputFile $PlatformAuditFile
            }
            "4" {
                $SafeCpmOutputFile = New-TimestampedOutputPath -Prefix "safe_cpm_assignments"
                Export-SafeCpmAssignments -Subdomain $script:Subdomain -Token $script:Token -OutputFile $SafeCpmOutputFile
            }
            "5" {
                if ([string]::IsNullOrWhiteSpace($script:SafeCpmCsvPath)) {
                    $script:SafeCpmCsvPath = Read-RequiredValue -Prompt "Safe CPM CSV file path"
                }
                Import-SafeCpmAssignments -Subdomain $script:Subdomain -Token $script:Token -CsvPath $script:SafeCpmCsvPath
            }
            "6" {
                return
            }
            default {
                Write-Host "Choose 1, 2, 3, 4, 5, or 6." -ForegroundColor Yellow
            }
        }
    }
}

try {
    Start-CyberArkApiRunner
}
catch {
    Write-Host ""
    Write-Host "Application error:" -ForegroundColor Red
    Write-Host $_.Exception.Message -ForegroundColor Red
    Write-Host ""
    $null = Read-Host "Press Enter to close"
    exit 1
}
