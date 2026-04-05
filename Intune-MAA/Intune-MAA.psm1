#region Module State

$script:DebugMode = $false
$script:CustomClientId = $null
$script:CustomTenantId = $null

$script:ResourceTypeMap = @{
    "MobileApp"                            = "App"
    "DeviceHealthScript"                   = "Remediation script"
    "DeviceConfiguration"                  = "Configuration profile"
    "DeviceCompliancePolicy"               = "Compliance policy"
    "WindowsAutopilotDeploymentProfile"    = "Autopilot profile"
    "DeviceManagementScript"               = "Platform script"
    "GroupPolicyConfiguration"             = "Group policy"
    "DeviceEnrollmentConfiguration"        = "Enrollment config"
    "WindowsFeatureUpdateProfile"          = "Feature update"
    "WindowsQualityUpdateProfile"          = "Quality update"
    "WindowsDriverUpdateProfile"           = "Driver update"
    "ConfigurationPolicy"                  = "Settings catalog"
    "IDeviceManagementPolicy"              = "Settings catalog"
    "OperationApprovalPolicy"              = "Approval policy"
    "DeviceCategory"                       = "Device category"
    "RoleDefinition"                       = "Role definition"
    "DeviceAndAppManagementRoleDefinition" = "Role definition"
}

$script:GroupNameCache = @{}
$script:MSALAssemblyPaths = @{}
$script:MSALHelperCompiled = $false

#endregion Module State

#region MSAL Browser Authentication

function Initialize-MSALAssemblies {
    $userHome = if ($env:USERPROFILE) { $env:USERPROFILE } else { $HOME }

    $nugetPath = Join-Path $userHome ".nuget/packages/microsoft.identity.client"
    $msalDll = $null
    $abstractionsDll = $null

    if (Test-Path $nugetPath) {
        $latestVersion = Get-ChildItem $nugetPath -Directory | Sort-Object Name -Descending | Select-Object -First 1
        if ($latestVersion) {
            $msalDll = Join-Path $latestVersion.FullName "lib/net6.0/Microsoft.Identity.Client.dll"
            if (-not (Test-Path $msalDll)) {
                $msalDll = Join-Path $latestVersion.FullName "lib/netstandard2.0/Microsoft.Identity.Client.dll"
            }
        }

        $abstractionsPath = Join-Path $userHome ".nuget/packages/microsoft.identitymodel.abstractions"
        if (Test-Path $abstractionsPath) {
            $latestAbstractions = Get-ChildItem $abstractionsPath -Directory | Sort-Object Name -Descending | Select-Object -First 1
            if ($latestAbstractions) {
                $abstractionsDll = Join-Path $latestAbstractions.FullName "lib/net6.0/Microsoft.IdentityModel.Abstractions.dll"
                if (-not (Test-Path $abstractionsDll)) {
                    $abstractionsDll = Join-Path $latestAbstractions.FullName "lib/netstandard2.0/Microsoft.IdentityModel.Abstractions.dll"
                }
            }
        }
    }

    # Fallback to Az.Accounts module
    if (-not $msalDll -or -not (Test-Path $msalDll)) {
        $LoadedAzAccountsModule = Get-Module -Name Az.Accounts
        if ($null -eq $LoadedAzAccountsModule) {
            $AzAccountsModule = Get-Module -Name Az.Accounts -ListAvailable | Select-Object -First 1
            if ($null -eq $AzAccountsModule) {
                return $false
            }
            Import-Module Az.Accounts -ErrorAction SilentlyContinue -Verbose:$false
        }

        $LoadedAssemblies = [System.AppDomain]::CurrentDomain.GetAssemblies() | Select-Object -ExpandProperty Location -ErrorAction SilentlyContinue
        $AzureCommon = $LoadedAssemblies | Where-Object { $_ -match "[/\\]Modules[/\\]Az.Accounts[/\\]" -and $_ -match "Microsoft.Azure.Common" }

        if ($AzureCommon) {
            $AzureCommonLocation = Split-Path -Parent $AzureCommon
            $foundMsal = Get-ChildItem -Path $AzureCommonLocation -Filter "Microsoft.Identity.Client.dll" -Recurse -File -ErrorAction SilentlyContinue | Select-Object -First 1
            $foundAbstractions = Get-ChildItem -Path $AzureCommonLocation -Filter "Microsoft.IdentityModel.Abstractions.dll" -Recurse -File -ErrorAction SilentlyContinue | Select-Object -First 1
            if ($foundMsal) { $msalDll = $foundMsal.FullName }
            if ($foundAbstractions) { $abstractionsDll = $foundAbstractions.FullName }
        }
    }

    if (-not $msalDll -or -not (Test-Path $msalDll)) {
        return $false
    }

    $loadedAssembliesCheck = [System.AppDomain]::CurrentDomain.GetAssemblies()

    if ($abstractionsDll -and (Test-Path $abstractionsDll)) {
        $alreadyLoaded = $loadedAssembliesCheck | Where-Object { $_.GetName().Name -eq 'Microsoft.IdentityModel.Abstractions' } | Select-Object -First 1
        if (-not $alreadyLoaded) {
            try { [void][System.Reflection.Assembly]::LoadFrom($abstractionsDll); $script:MSALAssemblyPaths['Microsoft.IdentityModel.Abstractions'] = $abstractionsDll } catch { }
        }
        else {
            $script:MSALAssemblyPaths['Microsoft.IdentityModel.Abstractions'] = $alreadyLoaded.Location
        }
    }

    $alreadyLoaded = $loadedAssembliesCheck | Where-Object { $_.GetName().Name -eq 'Microsoft.Identity.Client' } | Select-Object -First 1
    if (-not $alreadyLoaded) {
        try {
            [void][System.Reflection.Assembly]::LoadFrom($msalDll)
            $script:MSALAssemblyPaths['Microsoft.Identity.Client'] = $msalDll
        }
        catch {
            return $false
        }
    }
    else {
        $script:MSALAssemblyPaths['Microsoft.Identity.Client'] = $alreadyLoaded.Location
    }

    return $true
}

function Initialize-MSALHelper {
    if ($script:MSALHelperCompiled) { return $true }

    $referencedAssemblies = @(
        $script:MSALAssemblyPaths['Microsoft.IdentityModel.Abstractions'],
        $script:MSALAssemblyPaths['Microsoft.Identity.Client']
    ) | Where-Object { $_ }

    if ($referencedAssemblies.Count -lt 1) {
        throw "Missing required MSAL assemblies"
    }

    $referencedAssemblies += @("netstandard", "System.Linq", "System.Threading.Tasks", "System.Collections")

    $code = @"
using System;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Identity.Client;

public class MAABrowserAuth
{
    public static string GetAccessToken(string clientId, string[] scopes, string tenantId = null, string loginHint = null)
    {
        try
        {
            var task = Task.Run(async () => await GetAccessTokenAsync(clientId, scopes, tenantId, loginHint));
            if (task.Wait(TimeSpan.FromSeconds(180)))
            {
                return task.Result;
            }
            throw new TimeoutException("Authentication timed out");
        }
        catch (AggregateException ae)
        {
            if (ae.InnerException != null) throw ae.InnerException;
            throw;
        }
    }

    private static async Task<string> GetAccessTokenAsync(string clientId, string[] scopes, string tenantId, string loginHint)
    {
        var builder = PublicClientApplicationBuilder.Create(clientId)
            .WithRedirectUri("http://localhost");

        if (!string.IsNullOrEmpty(tenantId))
        {
            builder = builder.WithAuthority(string.Format("https://login.microsoftonline.com/{0}", tenantId));
        }

        IPublicClientApplication publicClientApp = builder.Build();

        using (var cts = new CancellationTokenSource(TimeSpan.FromSeconds(180)))
        {
            var webViewOptions = new SystemWebViewOptions
            {
                HtmlMessageSuccess = @"
<html>
<head>
    <meta charset='UTF-8'>
    <title>Authentication Successful - MAA Manager</title>
    <style>
        body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; display: flex; justify-content: center; align-items: center; height: 100vh; margin: 0; background: linear-gradient(135deg, #0e7490 0%, #155e75 100%); }
        .container { text-align: center; color: white; }
        .brand { font-size: 14px; letter-spacing: 4px; margin-bottom: 30px; opacity: 0.9; }
        .checkmark { font-size: 64px; margin-bottom: 20px; }
        h1 { margin: 0 0 10px 0; font-weight: 300; font-size: 28px; }
        p { margin: 0; opacity: 0.9; font-size: 16px; }
    </style>
</head>
<body>
    <div class='container'>
        <div class='brand'>[ M A A &nbsp; M A N A G E R ]</div>
        <div class='checkmark'>&#10003;</div>
        <h1>Authentication Successful</h1>
        <p>You can close this window and return to PowerShell.</p>
    </div>
</body>
</html>",
                HtmlMessageError = @"
<html>
<head>
    <meta charset='UTF-8'>
    <title>Authentication Failed - MAA Manager</title>
    <style>
        body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; display: flex; justify-content: center; align-items: center; height: 100vh; margin: 0; background: linear-gradient(135deg, #e74c3c 0%, #c0392b 100%); }
        .container { text-align: center; color: white; }
        .brand { font-size: 14px; letter-spacing: 4px; margin-bottom: 30px; opacity: 0.9; }
        .icon { font-size: 64px; margin-bottom: 20px; }
        h1 { margin: 0 0 10px 0; font-weight: 300; font-size: 28px; }
        p { margin: 0; opacity: 0.9; font-size: 16px; }
    </style>
</head>
<body>
    <div class='container'>
        <div class='brand'>[ M A A &nbsp; M A N A G E R ]</div>
        <div class='icon'>&#10005;</div>
        <h1>Authentication Failed</h1>
        <p>Please close this window and try again.</p>
    </div>
</body>
</html>"
            };

            var tokenBuilder = publicClientApp.AcquireTokenInteractive(scopes)
                .WithPrompt(Prompt.SelectAccount)
                .WithUseEmbeddedWebView(false)
                .WithSystemWebViewOptions(webViewOptions)
;

            var result = await tokenBuilder
                .ExecuteAsync(cts.Token)
                .ConfigureAwait(false);

            return result.AccessToken;
        }
    }
}
"@

    try {
        $null = [MAABrowserAuth]
        $script:MSALHelperCompiled = $true
        return $true
    }
    catch { }

    Add-Type -ReferencedAssemblies $referencedAssemblies -TypeDefinition $code -Language CSharp -ErrorAction Stop -IgnoreWarnings 3>$null

    $script:MSALHelperCompiled = $true
    return $true
}

function Get-BrowserAccessToken {
    param(
        [string[]]$Scopes,
        [string]$LoginHint
    )

    if (-not $script:MSALHelperCompiled) {
        $null = Initialize-MSALHelper
    }

    $clientId = if ($script:CustomClientId) { $script:CustomClientId } else { "14d82eec-204b-4c2f-b7e8-296a70dab67e" }
    $tenantId = $script:CustomTenantId

    $scopeArray = $Scopes | ForEach-Object {
        if ($_ -notlike "https://*") { "https://graph.microsoft.com/$_" } else { $_ }
    }

    $accessToken = [MAABrowserAuth]::GetAccessToken($clientId, $scopeArray, $tenantId, $LoginHint)
    return $accessToken
}

#endregion MSAL Browser Authentication

#region UI Functions

function Show-Header {
    param([string]$UserEmail = "")

    Clear-Host
    Write-Host ""
    Write-Host "[ M A A   M A N A G E R ]  " -ForegroundColor DarkCyan -NoNewline
    Write-Host "v1.0" -ForegroundColor White
    Write-Host "      Multi Admin Approval Tool" -ForegroundColor DarkGray
    Write-Host ""
    if ($UserEmail) {
        Write-Host "  Logged in as: " -ForegroundColor DarkGray -NoNewline
        Write-Host "$UserEmail" -ForegroundColor Cyan
        Write-Host ""
    }
}

function Wait-ForKeyPress {
    Write-Host ""
    Write-Host ""
    $null = Read-Host "  Press Enter to continue"
}

function Show-InlineActions {
    param([array]$Actions)

    Write-Host ""
    Write-Host "  " -NoNewline
    for ($i = 0; $i -lt $Actions.Count; $i++) {
        $a = $Actions[$i]
        Write-Host "[$($a.Key)]" -ForegroundColor DarkCyan -NoNewline
        Write-Host " $($a.Text)" -ForegroundColor Gray -NoNewline
        if ($i -lt $Actions.Count - 1) {
            Write-Host "  " -NoNewline
        }
    }
    Write-Host ""
}

function Show-ControlBar {
    param(
        [switch]$NoBack,
        [int]$ReserveLines = 2
    )

    $currentLine = [Console]::CursorTop
    $windowBottom = $Host.UI.RawUI.WindowPosition.Y + $Host.UI.RawUI.WindowSize.Height
    $padding = $windowBottom - $currentLine - $ReserveLines - 2
    if ($padding -lt 0) { $padding = 0 }

    for ($i = 0; $i -lt $ReserveLines; $i++) {
        Write-Host ""
    }
    for ($i = 0; $i -lt $padding; $i++) {
        Write-Host ""
    }

    $divider = [string]::new([char]0x2500, [Math]::Min(60, [Console]::WindowWidth - 4))
    Write-Host "  $divider" -ForegroundColor DarkGray
    Write-Host "  " -NoNewline
    if (-not $NoBack) {
        Write-Host "[B]" -ForegroundColor DarkCyan -NoNewline
        Write-Host " Back" -ForegroundColor Gray -NoNewline
        Write-Host "  " -NoNewline
    }
    Write-Host "[E]" -ForegroundColor DarkCyan -NoNewline
    Write-Host " Exit" -ForegroundColor Gray -NoNewline

    $linesUp = $padding + $ReserveLines + 1
    [Console]::Write("$([char]27)[${linesUp}A$([char]27)[1G")
}

function Read-MenuKey {
    Write-Host ""
    Write-Host "  > " -ForegroundColor DarkCyan -NoNewline
    $key = [Console]::ReadKey($true)

    [Console]::Write("$([char]27)[J")

    if ($key.Modifiers -band [ConsoleModifiers]::Control -and ($key.Key -eq 'Q' -or $key.Key -eq 'E')) {
        Write-Host "E"
        return "E"
    }

    $char = $key.KeyChar
    if ($char -match '[a-zA-Z0-9]') {
        Write-Host "$char"
        return "$char".ToUpper()
    }

    if ($key.Key -eq 'Enter') {
        Write-Host ""
        return "ENTER"
    }

    Write-Host ""
    return ""
}

#endregion UI Functions

#region Payload Summary Functions

function ConvertTo-ReadableSettingId {
    param([string]$SettingId)

    $readable = $SettingId -replace '^(device|user)_vendor_msft_policy_config_', '' `
        -replace '^(device|user)_vendor_msft_', '' `
        -replace '^admx_', ''

    $parts = $readable -split '_' | Where-Object { $_ -ne '' } | ForEach-Object {
        $split = $_ -creplace '([a-z])([A-Z])', '$1 $2'
        (Get-Culture).TextInfo.ToTitleCase($split.ToLower())
    }

    if ($parts.Count -gt 1) {
        return "$($parts[0]) > $($parts[1..($parts.Count-1)] -join ' ')"
    }
    return ($parts -join ' ')
}

function ConvertTo-ReadableSettingValue {
    param(
        [string]$Value,
        [string]$SettingId
    )

    $suffix = $Value
    if ($Value -like "${SettingId}_*") {
        $suffix = $Value.Substring($SettingId.Length + 1)
    }

    switch ($suffix) {
        "0" { return "Disabled" }
        "1" { return "Enabled" }
        "block" { return "Block" }
        "allow" { return "Allow" }
        "notconfigured" { return "Not Configured" }
        default {
            $parts = $suffix -split '_' | Where-Object { $_ -ne '' } | ForEach-Object {
                (Get-Culture).TextInfo.ToTitleCase($_.ToLower())
            }
            return ($parts -join ' ')
        }
    }
}

function Get-ConfigurationPolicySummary {
    param(
        [object]$Payload,
        [int]$MaxSettings = 5
    )

    $summary = @()

    if ($Payload.name) {
        $summary += [PSCustomObject]@{ Label = "Name"; Value = $Payload.name }
    }
    if ($Payload.description) {
        $summary += [PSCustomObject]@{ Label = "Description"; Value = $Payload.description }
    }
    if ($Payload.platforms) {
        $platMap = @{ "windows10" = "Windows 10/11"; "macOS" = "macOS"; "iOS" = "iOS/iPadOS"; "android" = "Android" }
        $platDisplay = if ($platMap.ContainsKey($Payload.platforms)) { $platMap[$Payload.platforms] } else { $Payload.platforms }
        $summary += [PSCustomObject]@{ Label = "Platform"; Value = $platDisplay }
    }
    if ($Payload.technologies) {
        $summary += [PSCustomObject]@{ Label = "Technologies"; Value = $Payload.technologies.ToUpper() }
    }

    $settings = $Payload.settings
    if ($settings -and $settings.Count -gt 0) {
        $maxShow = $MaxSettings
        $settingLines = @()
        $count = 0
        foreach ($setting in $settings) {
            if ($count -ge $maxShow) { break }
            $instance = $setting.settingInstance
            if (-not $instance) { continue }

            $defId = $instance.settingDefinitionId
            $readableName = ConvertTo-ReadableSettingId -SettingId $defId

            $displayValue = ""
            if ($instance.choiceSettingValue) {
                $displayValue = ConvertTo-ReadableSettingValue -Value $instance.choiceSettingValue.value -SettingId $defId
            }
            elseif ($instance.simpleSettingValue) {
                $displayValue = "$($instance.simpleSettingValue.value)"
            }
            elseif ($instance.groupSettingCollectionValue) {
                $displayValue = "($($instance.groupSettingCollectionValue.Count) items)"
            }
            else {
                $displayValue = "(configured)"
            }

            $settingLines += "    $readableName = $displayValue"
            $count++
        }

        $settingsLabel = "Settings ($($settings.Count))"
        if ($settings.Count -gt $maxShow) {
            $settingsLabel = "Settings ($maxShow of $($settings.Count))"
        }
        $summary += [PSCustomObject]@{ Label = $settingsLabel; Value = "" }
        foreach ($line in $settingLines) {
            $summary += [PSCustomObject]@{ Label = ""; Value = $line }
        }
        if ($settings.Count -gt $maxShow) {
            $summary += [PSCustomObject]@{ Label = ""; Value = "    ...and $($settings.Count - $maxShow) more (use [S] or [N] to review all)" }
        }
    }

    return $summary
}

function Get-MobileAppSummary {
    param([object]$Payload)

    $summary = @()

    if ($Payload.displayName) {
        $summary += [PSCustomObject]@{ Label = "Name"; Value = $Payload.displayName }
    }
    if ($Payload.description) {
        $desc = $Payload.description
        if ($desc.Length -gt 100) { $desc = $desc.Substring(0, 97) + "..." }
        $summary += [PSCustomObject]@{ Label = "Description"; Value = $desc }
    }
    if ($Payload.publisher) {
        $summary += [PSCustomObject]@{ Label = "Publisher"; Value = $Payload.publisher }
    }

    $odataType = $Payload.'@odata.type'
    if ($odataType) {
        $appType = switch -Wildcard ($odataType) {
            "*win32LobApp*" { "Win32 App" }
            "*windowsMobileMSI*" { "MSI App" }
            "*microsoftStoreForBusinessApp*" { "Store App" }
            "*managedIOSLobApp*" { "iOS LOB App" }
            "*managedAndroidLobApp*" { "Android LOB App" }
            "*webApp*" { "Web Link" }
            default { $odataType.Split('.')[-1] }
        }
        $summary += [PSCustomObject]@{ Label = "App Type"; Value = $appType }
    }

    if ($Payload.fileName) {
        $summary += [PSCustomObject]@{ Label = "File"; Value = $Payload.fileName }
    }
    if ($Payload.installCommandLine) {
        $summary += [PSCustomObject]@{ Label = "Install Cmd"; Value = $Payload.installCommandLine }
    }
    if ($Payload.uninstallCommandLine) {
        $summary += [PSCustomObject]@{ Label = "Uninstall Cmd"; Value = $Payload.uninstallCommandLine }
    }

    $hasDetectionScript = $false
    if ($Payload.detectionRules) {
        foreach ($rule in $Payload.detectionRules) {
            if ($rule.'@odata.type' -like '*PowerShellScriptDetection*' -and $rule.scriptContent) {
                $hasDetectionScript = $true
                break
            }
        }
    }
    if ($hasDetectionScript) {
        $summary += [PSCustomObject]@{ Label = "Detection Script"; Value = "Present (use [S] to view)" }
    }

    return $summary
}

function Get-DeviceHealthScriptSummary {
    param([object]$Payload)

    $summary = @()

    if ($Payload.displayName) {
        $summary += [PSCustomObject]@{ Label = "Name"; Value = $Payload.displayName }
    }
    if ($Payload.description) {
        $desc = $Payload.description
        if ($desc.Length -gt 100) { $desc = $desc.Substring(0, 97) + "..." }
        $summary += [PSCustomObject]@{ Label = "Description"; Value = $desc }
    }
    if ($Payload.publisher) {
        $summary += [PSCustomObject]@{ Label = "Publisher"; Value = $Payload.publisher }
    }
    $summary += [PSCustomObject]@{ Label = "Run As"; Value = $(if ($Payload.runAsAccount) { $Payload.runAsAccount } else { "System" }) }
    $summary += [PSCustomObject]@{ Label = "Run As 32-bit"; Value = $(if ($Payload.runAs32Bit) { "Yes" } else { "No" }) }
    $summary += [PSCustomObject]@{ Label = "Signature Check"; Value = $(if ($Payload.enforceSignatureCheck) { "Yes" } else { "No" }) }

    $hasDetection = $Payload.detectionScriptContent
    $hasRemediation = $Payload.remediationScriptContent
    $hasScript = $Payload.scriptContent

    if ($hasScript) {
        $summary += [PSCustomObject]@{ Label = "Script"; Value = "Present (use [S] to view)" }
    }
    if ($hasDetection) {
        $summary += [PSCustomObject]@{ Label = "Detection Script"; Value = "Present (use [S] to view)" }
    }
    elseif (-not $hasScript) {
        $summary += [PSCustomObject]@{ Label = "Detection Script"; Value = "None" }
    }
    if ($hasRemediation) {
        $summary += [PSCustomObject]@{ Label = "Remediation Script"; Value = "Present (use [S] to view)" }
    }
    elseif (-not $hasScript) {
        $summary += [PSCustomObject]@{ Label = "Remediation Script"; Value = "None" }
    }

    return $summary
}

function Get-ScriptContentFromPayload {
    param([object]$Request)

    $payload = $Request.payload
    if ([string]::IsNullOrWhiteSpace($payload)) { return @() }

    try {
        $parsed = $payload | ConvertFrom-Json
    }
    catch {
        return @()
    }

    $scripts = @()

    if ($parsed.scriptContent) {
        $name = if ($parsed.displayName) { $parsed.displayName } elseif ($parsed.fileName) { $parsed.fileName } else { "Script" }
        $scripts += [PSCustomObject]@{ Name = $name; Content = $parsed.scriptContent }
    }

    if ($parsed.detectionScriptContent) {
        $scripts += [PSCustomObject]@{ Name = "Detection Script"; Content = $parsed.detectionScriptContent }
    }
    if ($parsed.remediationScriptContent) {
        $scripts += [PSCustomObject]@{ Name = "Remediation Script"; Content = $parsed.remediationScriptContent }
    }

    if ($parsed.detectionRules) {
        $scriptIndex = 1
        foreach ($rule in $parsed.detectionRules) {
            if ($rule.'@odata.type' -like '*PowerShellScriptDetection*' -and $rule.scriptContent) {
                $scriptName = if ($parsed.detectionRules.Count -gt 1) { "Detection Script $scriptIndex" } else { "Detection Script" }
                $scripts += [PSCustomObject]@{ Name = $scriptName; Content = $rule.scriptContent }
                $scriptIndex++
            }
        }
    }

    return $scripts
}

function Open-ScriptForReview {
    param(
        [object]$Request,
        [ValidateSet("code", "notepad")]
        [string]$Editor = "code"
    )

    $scripts = Get-ScriptContentFromPayload -Request $Request

    if ($scripts.Count -eq 0) {
        Write-Host "  No script content found in this request." -ForegroundColor Yellow
        return
    }

    foreach ($scriptItem in $scripts) {
        try {
            $decoded = [System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String($scriptItem.Content))

            $safeName = $scriptItem.Name -replace '[^\w\-\.]', '_'
            $tempFile = Join-Path $env:TEMP "MAA_Review_$safeName.ps1"
            $decoded | Out-File -FilePath $tempFile -Encoding UTF8 -Force

            Write-Host "  Opening in $($Editor): " -ForegroundColor Cyan -NoNewline
            Write-Host "$($scriptItem.Name)" -ForegroundColor White
            if ($Editor -eq "code") {
                Start-Process cmd -ArgumentList "/c `"code `"$tempFile`"`"" -WindowStyle Hidden
            }
            else {
                Start-Process $Editor -ArgumentList $tempFile
            }
        }
        catch {
            Write-Host "  Failed to open $($scriptItem.Name): $($_.Exception.Message)" -ForegroundColor Red
        }
    }
}

function Open-PayloadForReview {
    param(
        [object]$Request,
        [ValidateSet("code", "notepad")]
        [string]$Editor = "code"
    )

    $scripts = Get-ScriptContentFromPayload -Request $Request
    if ($scripts.Count -gt 0) {
        Open-ScriptForReview -Request $Request -Editor $Editor
        return
    }

    if (-not $Request.payload) {
        Write-Host "  No payload data to display." -ForegroundColor Yellow
        return
    }

    try {
        $safeName = $Request.payloadName
        if ([string]::IsNullOrWhiteSpace($safeName)) { $safeName = "Payload" }
        $safeName = $safeName -replace '[^\w\-\.]', '_'

        $payloadSummary = Get-PayloadSummary -Request $Request -MaxSettings 999
        $assignments = $Request.addedAssignments
        if (-not $assignments) { $assignments = Get-RelatedAssignments -Request $Request }
        $assignmentsSummary = Get-AssignmentsSummary -Assignments $assignments

        $lines = @()
        $divider = [string]::new([char]0x2500, 50)
        $lines += "$([char]0x2500)$([char]0x2500) DETAILS $divider"
        $lines += ""

        if ($payloadSummary) {
            foreach ($item in $payloadSummary) {
                if ($item.Label -and $item.Value) {
                    $padding = ' ' * [Math]::Max(1, 18 - $item.Label.Length)
                    $lines += "$($item.Label):$padding$($item.Value)"
                }
                elseif ($item.Label -and -not $item.Value) {
                    $lines += "$($item.Label):"
                }
                else {
                    $lines += "$($item.Value)"
                }
            }
        }

        if ($assignmentsSummary -and $assignmentsSummary.Count -gt 0) {
            $lines += ""
            foreach ($item in $assignmentsSummary) {
                if ($item.Label -and -not $item.Value) {
                    $lines += "$($item.Label):"
                }
                else {
                    $lines += "$($item.Value)"
                }
            }
        }

        $lines += ""
        $lines += "$divider$([char]0x2500)$([char]0x2500)$([char]0x2500)$([char]0x2500)$([char]0x2500)$([char]0x2500)$([char]0x2500)$([char]0x2500)$([char]0x2500)$([char]0x2500)$([char]0x2500)"

        $tempFile = Join-Path $env:TEMP "MAA_Review_$safeName.txt"
        $lines | Out-File -FilePath $tempFile -Encoding UTF8 -Force

        Write-Host "  Opening in $($Editor): " -ForegroundColor Cyan -NoNewline
        Write-Host "$($Request.payloadName)" -ForegroundColor White

        if ($Editor -eq "code") {
            Start-Process cmd -ArgumentList "/c `"code `"$tempFile`"`"" -WindowStyle Hidden
        }
        else {
            Start-Process $Editor -ArgumentList $tempFile
        }
    }
    catch {
        Write-Host "  Failed to open payload: $($_.Exception.Message)" -ForegroundColor Red
    }
}

function Resolve-GroupName {
    param([string]$GroupId)

    if ([string]::IsNullOrWhiteSpace($GroupId)) { return $GroupId }

    if ($script:GroupNameCache.ContainsKey($GroupId)) {
        $cached = $script:GroupNameCache[$GroupId]
        if ($cached) { return $cached }
        return $GroupId
    }

    try {
        $grp = Invoke-MgGraphRequest -Uri "https://graph.microsoft.com/v1.0/groups/$GroupId`?`$select=displayName" -Method GET -ErrorAction SilentlyContinue
        if ($grp.displayName) {
            $script:GroupNameCache[$GroupId] = $grp.displayName
            return $grp.displayName
        }
    }
    catch {
        $script:GroupNameCache[$GroupId] = $null
    }

    return $GroupId
}

function Get-ApprovalPolicySummary {
    param([object]$Payload)

    $summary = @()

    if ($Payload.displayName) {
        $summary += [PSCustomObject]@{ Label = "Name"; Value = $Payload.displayName }
    }
    if ($Payload.description) {
        $summary += [PSCustomObject]@{ Label = "Description"; Value = $Payload.description }
    }

    if ($Payload.policySet) {
        $policyType = $Payload.policySet.policyType
        if ($policyType) {
            $friendlyType = switch ($policyType) {
                "role" { "Role-based" }
                "app" { "Application" }
                "script" { "Script" }
                "configuration" { "Configuration" }
                default { $policyType }
            }
            $summary += [PSCustomObject]@{ Label = "Policy Type"; Value = $friendlyType }
        }
        if ($Payload.policySet.policyPlatform -and $Payload.policySet.policyPlatform -ne "notApplicable") {
            $summary += [PSCustomObject]@{ Label = "Platform"; Value = $Payload.policySet.policyPlatform }
        }
    }

    if ($Payload.approverGroupIds -and $Payload.approverGroupIds.Count -gt 0) {
        $summary += [PSCustomObject]@{ Label = "Approver Groups ($($Payload.approverGroupIds.Count))"; Value = "" }
        foreach ($groupId in $Payload.approverGroupIds) {
            $groupName = Resolve-GroupName -GroupId $groupId
            $summary += [PSCustomObject]@{ Label = ""; Value = "    $groupName" }
        }
    }

    return $summary
}

function Get-CompliancePolicySummary {
    param(
        [object]$Payload,
        [int]$MaxSettings = 5
    )

    $summary = @()

    $name = $Payload.displayName
    if ([string]::IsNullOrWhiteSpace($name)) { $name = $Payload.name }
    if ($name) {
        $summary += [PSCustomObject]@{ Label = "Name"; Value = $name }
    }
    if ($Payload.description) {
        $summary += [PSCustomObject]@{ Label = "Description"; Value = $Payload.description }
    }

    $odataType = $Payload.'@odata.type'
    if ($odataType) {
        $platformMap = @{
            "windows10CompliancePolicy"          = "Windows 10/11"
            "iosCompliancePolicy"                = "iOS/iPadOS"
            "macOSCompliancePolicy"              = "macOS"
            "androidCompliancePolicy"            = "Android"
            "androidDeviceOwnerCompliancePolicy" = "Android Enterprise"
            "androidWorkProfileCompliancePolicy" = "Android Work Profile"
        }
        $shortOdata = $odataType.Split('.')[-1]
        $platform = if ($platformMap.ContainsKey($shortOdata)) { $platformMap[$shortOdata] } else { $shortOdata }
        $summary += [PSCustomObject]@{ Label = "Platform"; Value = $platform }
    }

    $settingsList = @()

    if ($Payload.passwordRequired) { $settingsList += "Password Required = Yes" }
    if ($Payload.passwordRequiredType -and $Payload.passwordRequiredType -ne "deviceDefault") {
        $settingsList += "Password Type = $($Payload.passwordRequiredType)"
    }
    if ($Payload.passwordMinimumLength) { $settingsList += "Min Password Length = $($Payload.passwordMinimumLength)" }
    if ($Payload.passwordExpirationDays) { $settingsList += "Password Expiry = $($Payload.passwordExpirationDays) days" }
    if ($Payload.passwordMinutesOfInactivityBeforeLock) { $settingsList += "Lock After Inactivity = $($Payload.passwordMinutesOfInactivityBeforeLock) min" }

    if ($Payload.secureBootEnabled) { $settingsList += "Secure Boot = Required" }
    if ($Payload.bitLockerEnabled) { $settingsList += "BitLocker = Required" }
    if ($Payload.codeIntegrityEnabled) { $settingsList += "Code Integrity = Required" }
    if ($Payload.storageRequireEncryption) { $settingsList += "Encryption = Required" }
    if ($Payload.tpmRequired) { $settingsList += "TPM = Required" }

    if ($Payload.defenderEnabled) { $settingsList += "Defender = Required" }
    if ($Payload.antivirusRequired) { $settingsList += "Antivirus = Required" }
    if ($Payload.antiSpywareRequired) { $settingsList += "Anti-Spyware = Required" }
    if ($Payload.rtpEnabled) { $settingsList += "Real-Time Protection = Required" }

    if ($Payload.deviceThreatProtectionEnabled) { $settingsList += "Threat Protection = Enabled" }
    if ($Payload.deviceThreatProtectionRequiredSecurityLevel -and $Payload.deviceThreatProtectionRequiredSecurityLevel -ne "unavailable") {
        $settingsList += "Threat Level = $($Payload.deviceThreatProtectionRequiredSecurityLevel)"
    }

    if ($Payload.osMinimumVersion) { $settingsList += "Min OS Version = $($Payload.osMinimumVersion)" }
    if ($Payload.osMaximumVersion) { $settingsList += "Max OS Version = $($Payload.osMaximumVersion)" }

    if ($Payload.firewallEnabled) { $settingsList += "Firewall = Required" }
    if ($Payload.configurationManagerComplianceRequired) { $settingsList += "ConfigMgr Compliance = Required" }
    if ($Payload.securityBlockJailbrokenDevices) { $settingsList += "Block Jailbroken = Yes" }

    if ($Payload.scheduledActionsForRule) {
        $actions = @($Payload.scheduledActionsForRule)
        foreach ($rule in $actions) {
            $schedActions = $rule.scheduledActionConfigurations
            if ($schedActions) {
                foreach ($sa in @($schedActions)) {
                    $actionType = $sa.actionType
                    $grace = $sa.gracePeriodHours
                    if ($actionType) {
                        $friendlyAction = switch ($actionType) {
                            "block" { "Block access" }
                            "retire" { "Retire device" }
                            "wipe" { "Wipe device" }
                            "remoteLock" { "Remote lock" }
                            "pushNotification" { "Send notification" }
                            "notification" { "Send notification" }
                            default { $actionType }
                        }
                        if ($grace -and $grace -gt 0) {
                            $settingsList += "Non-compliance: $friendlyAction (after $grace hrs)"
                        }
                        else {
                            $settingsList += "Non-compliance: $friendlyAction (immediately)"
                        }
                    }
                }
            }
        }
    }

    if ($settingsList.Count -gt 0) {
        $showCount = [Math]::Min($settingsList.Count, $MaxSettings)
        $settingsLabel = if ($settingsList.Count -gt $MaxSettings) {
            "Settings ($showCount of $($settingsList.Count))"
        }
        else {
            "Settings ($($settingsList.Count))"
        }
        $summary += [PSCustomObject]@{ Label = $settingsLabel; Value = "" }
        for ($i = 0; $i -lt $showCount; $i++) {
            $summary += [PSCustomObject]@{ Label = ""; Value = "    $($settingsList[$i])" }
        }
        if ($settingsList.Count -gt $MaxSettings) {
            $summary += [PSCustomObject]@{ Label = ""; Value = "    ...and $($settingsList.Count - $MaxSettings) more (use [S] or [N] to review all)" }
        }
    }

    return $summary
}

function Get-ManagedDeviceSummary {
    param([object]$Payload)

    $summary = @()

    if ($script:DebugMode) {
        Write-Host "  [DEBUG] ManagedDevice payload type: $($Payload.GetType().FullName)" -ForegroundColor Magenta
        Write-Host "  [DEBUG] Payload: $(ConvertTo-Json $Payload -Depth 4 -Compress)" -ForegroundColor DarkMagenta
        Wait-ForKeyPress
    }

    $devices = @($Payload)

    foreach ($device in $devices) {
        $devName = if ($device -is [hashtable]) { $device["deviceName"] } else { $device.deviceName }
        $serial = if ($device -is [hashtable]) { $device["serialNumber"] } else { $device.serialNumber }
        $userEmail = if ($device -is [hashtable]) { $device["primaryUserEmail"] } else { $device.primaryUserEmail }
        $userId = if ($device -is [hashtable]) { $device["primaryUser"] } else { $device.primaryUser }
        $action = if ($device -is [hashtable]) { $device["actionName"] } else { $device.actionName }
        $devId = if ($device -is [hashtable]) { $device["deviceId"] } else { $device.deviceId }

        if ($devName) {
            $summary += [PSCustomObject]@{ Label = "Device"; Value = $devName }
        }
        if ($serial) {
            $summary += [PSCustomObject]@{ Label = "Serial Number"; Value = $serial }
        }

        $primaryUserDisplay = $userEmail
        if ([string]::IsNullOrWhiteSpace($primaryUserDisplay) -and $userId) {
            try {
                $user = Invoke-MgGraphRequest -Uri "https://graph.microsoft.com/v1.0/users/$userId`?`$select=userPrincipalName,displayName" -Method GET -ErrorAction SilentlyContinue
                if ($user.userPrincipalName) {
                    $primaryUserDisplay = $user.userPrincipalName
                }
                elseif ($user.displayName) {
                    $primaryUserDisplay = $user.displayName
                }
            }
            catch {
                $primaryUserDisplay = $userId
            }
        }
        if (-not [string]::IsNullOrWhiteSpace($primaryUserDisplay)) {
            $summary += [PSCustomObject]@{ Label = "Primary User"; Value = $primaryUserDisplay }
        }

        if ($action) {
            $summary += [PSCustomObject]@{ Label = "Action"; Value = $action }
        }
    }

    return $summary
}

function Get-RoleDefinitionSummary {
    param(
        [object]$Payload,
        [int]$MaxSettings = 5
    )

    $summary = @()

    $name = $Payload.displayName
    if ([string]::IsNullOrWhiteSpace($name)) { $name = $Payload.name }
    if ($name) {
        $summary += [PSCustomObject]@{ Label = "Name"; Value = $name }
    }
    if ($Payload.description) {
        $summary += [PSCustomObject]@{ Label = "Description"; Value = $Payload.description }
    }
    if ($Payload.isBuiltIn -ne $null) {
        $summary += [PSCustomObject]@{ Label = "Built-in"; Value = $(if ($Payload.isBuiltIn) { "Yes" } else { "No" }) }
    }

    $rawPerms = @()
    $rolePerms = if ($Payload -is [hashtable]) { $Payload["rolePermissions"] } else { $Payload.rolePermissions }
    if (-not $rolePerms) {
        $rolePerms = if ($Payload -is [hashtable]) { $Payload["permissions"] } else { $Payload.permissions }
    }
    if ($rolePerms) {
        foreach ($rp in @($rolePerms)) {
            $resActions = if ($rp -is [hashtable]) { $rp["resourceActions"] } else { $rp.resourceActions }
            if (-not $resActions) {
                $resActions = if ($rp -is [hashtable]) { $rp["actions"] } else { $rp.actions }
            }
            if ($resActions) {
                foreach ($ra in @($resActions)) {
                    $allowed = if ($ra -is [hashtable]) { $ra["allowedResourceActions"] } else { $ra.allowedResourceActions }
                    if (-not $allowed) {
                        $allowed = if ($ra -is [hashtable]) { $ra["allowed"] } else { $ra.allowed }
                    }
                    if ($allowed) {
                        if ($allowed -is [string]) {
                            $rawPerms += ($allowed -split ',\s*')
                        }
                        else {
                            $rawPerms += $allowed
                        }
                    }
                }
            }
        }
    }

    $allPermissions = @()
    foreach ($perm in $rawPerms) {
        $rawPerm = "$perm"
        $normalized = $perm -replace '_', '/'
        $parts = $normalized -split '/'

        if ($parts.Count -ge 3) {
            $category = $parts[1] -creplace '([a-z])([A-Z])', '$1 $2'
            $action = $parts[2] -creplace '([a-z])([A-Z])', '$1 $2'
            $allPermissions += "$category > $action  ($rawPerm)"
        }
        elseif ($parts.Count -eq 2) {
            $category = $parts[0] -creplace '([a-z])([A-Z])', '$1 $2'
            $action = $parts[1] -creplace '([a-z])([A-Z])', '$1 $2'
            $allPermissions += "$category > $action  ($rawPerm)"
        }
        else {
            $allPermissions += $rawPerm
        }
    }

    if ($allPermissions.Count -gt 0) {
        $showCount = [Math]::Min($allPermissions.Count, $MaxSettings)
        $permLabel = if ($allPermissions.Count -gt $MaxSettings) {
            "Permissions ($showCount of $($allPermissions.Count))"
        }
        else {
            "Permissions ($($allPermissions.Count))"
        }
        $summary += [PSCustomObject]@{ Label = $permLabel; Value = "" }
        for ($i = 0; $i -lt $showCount; $i++) {
            $summary += [PSCustomObject]@{ Label = ""; Value = "    $($allPermissions[$i])" }
        }
        if ($allPermissions.Count -gt $MaxSettings) {
            $summary += [PSCustomObject]@{ Label = ""; Value = "    ...and $($allPermissions.Count - $MaxSettings) more (use [S] or [N] to review all)" }
        }
        $summary += [PSCustomObject]@{ Label = ""; Value = "" }
        $summary += [PSCustomObject]@{ Label = "Reference"; Value = "https://learn.microsoft.com/en-us/intune/intune-service/fundamentals/create-custom-role" }
    }

    return $summary
}

function Get-GenericPayloadSummary {
    param([object]$Payload)

    $summary = @()

    $name = $Payload.displayName
    if ([string]::IsNullOrWhiteSpace($name)) { $name = $Payload.name }
    if ($name) {
        $summary += [PSCustomObject]@{ Label = "Name"; Value = $name }
    }

    if ($Payload.description) {
        $desc = $Payload.description
        if ($desc.Length -gt 100) { $desc = $desc.Substring(0, 97) + "..." }
        $summary += [PSCustomObject]@{ Label = "Description"; Value = $desc }
    }

    if ($Payload.'@odata.type') {
        $summary += [PSCustomObject]@{ Label = "Type"; Value = $Payload.'@odata.type'.Split('.')[-1] }
    }

    $props = $Payload.PSObject.Properties | Where-Object { $_.Name -notlike '@*' -and $_.Name -ne 'name' -and $_.Name -ne 'displayName' -and $_.Name -ne 'description' } | Select-Object -First 10 -ExpandProperty Name
    if ($props) {
        $summary += [PSCustomObject]@{ Label = "Properties"; Value = ($props -join ', ') }
    }

    return $summary
}

function Get-PayloadSummary {
    param(
        [object]$Request,
        [int]$MaxSettings = 5
    )

    $shortType = $Request.payloadType
    if ($shortType -like "*.*") {
        $shortType = $shortType.Split('.')[-1]
    }

    $payloadRaw = if ($shortType -eq "ManagedDevice" -and $Request.displayPayload) {
        $Request.displayPayload
    }
    else {
        $Request.payload
    }

    if (-not $payloadRaw) {
        return @([PSCustomObject]@{ Label = "Details"; Value = "No payload data available" })
    }

    try {
        if ($payloadRaw -is [string]) {
            $parsed = $payloadRaw | ConvertFrom-Json
            if ($payloadRaw.TrimStart() -match '^\[') {
                $parsed = @($parsed)
            }
        }
        else {
            $parsed = $payloadRaw
        }
    }
    catch {
        return @([PSCustomObject]@{ Label = "Details"; Value = "Unable to parse payload" })
    }

    switch -Wildcard ($shortType) {
        { $_ -in "ConfigurationPolicy", "IDeviceManagementPolicy" } {
            return (Get-ConfigurationPolicySummary -Payload $parsed -MaxSettings $MaxSettings)
        }
        "MobileApp" {
            return (Get-MobileAppSummary -Payload $parsed)
        }
        { $_ -in "DeviceHealthScript", "DeviceManagementScript" } {
            return (Get-DeviceHealthScriptSummary -Payload $parsed)
        }
        { $_ -in "DeviceCompliancePolicy" } {
            return (Get-CompliancePolicySummary -Payload $parsed -MaxSettings $MaxSettings)
        }
        "OperationApprovalPolicy" {
            return (Get-ApprovalPolicySummary -Payload $parsed)
        }
        { $_ -in "RoleDefinition", "DeviceAndAppManagementRoleDefinition" } {
            return (Get-RoleDefinitionSummary -Payload $parsed -MaxSettings $MaxSettings)
        }
        "ManagedDevice" {
            return (Get-ManagedDeviceSummary -Payload $parsed)
        }
        default {
            return (Get-GenericPayloadSummary -Payload $parsed)
        }
    }
}

function Get-RelatedAssignments {
    param([object]$Request)

    $payloadName = $Request.payloadName
    if ([string]::IsNullOrWhiteSpace($payloadName)) { return $null }

    try {
        $uri = "https://graph.microsoft.com/beta/deviceManagement/operationApprovalRequests"
        $allRequests = @()
        $response = Invoke-MgGraphRequest -Uri $uri -Method GET
        if ($response.value) { $allRequests += $response.value }

        while ($response.'@odata.nextLink') {
            $response = Invoke-MgGraphRequest -Uri $response.'@odata.nextLink' -Method GET
            if ($response.value) { $allRequests += $response.value }
        }

        $related = $allRequests | Where-Object {
            $_.payloadName -ieq $payloadName -and
            $_.id -ne $Request.id -and
            $_.addedAssignments
        }

        if ($related) {
            $allAssignments = @()
            foreach ($rel in $related) {
                $parsed = if ($rel.addedAssignments -is [string]) {
                    $rel.addedAssignments | ConvertFrom-Json
                }
                else {
                    $rel.addedAssignments
                }
                if ($parsed) { $allAssignments += $parsed }
            }
            if ($allAssignments.Count -gt 0) {
                return $allAssignments
            }
        }
    }
    catch { }

    return $null
}

function Get-AssignmentsSummary {
    param([object]$Assignments)

    if (-not $Assignments) { return @() }

    try {
        $parsed = if ($Assignments -is [string]) { $Assignments | ConvertFrom-Json } else { $Assignments }
    }
    catch {
        return @([PSCustomObject]@{ Label = "Assignments"; Value = "Unable to parse" })
    }

    if (-not $parsed -or $parsed.Count -eq 0) { return @() }

    $summary = @()
    $summary += [PSCustomObject]@{ Label = "Assignments ($($parsed.Count))"; Value = "" }

    foreach ($assignment in $parsed) {
        $target = $assignment.target
        if (-not $target) { continue }

        $targetType = $target.'@odata.type'
        $targetDisplay = switch -Wildcard ($targetType) {
            "*allLicensedUsersAssignmentTarget" { "All Users" }
            "*allDevicesAssignmentTarget" { "All Devices" }
            "*exclusionGroupAssignmentTarget" { "Exclude Group" }
            "*groupAssignmentTarget" { "Group" }
            default { "Target" }
        }

        $groupId = $target.groupId
        if ($groupId) {
            $groupName = Resolve-GroupName -GroupId $groupId
            $targetDisplay = "$targetDisplay`: $groupName"
        }

        $intent = $assignment.intent
        if ($intent) {
            $targetDisplay = "$targetDisplay ($intent)"
        }

        $summary += [PSCustomObject]@{ Label = ""; Value = "    $targetDisplay" }
    }

    return $summary
}

function Show-PayloadDetails {
    param(
        [array]$Summary,
        [array]$AssignmentsSummary
    )

    if ((-not $Summary -or $Summary.Count -eq 0) -and (-not $AssignmentsSummary -or $AssignmentsSummary.Count -eq 0)) {
        return
    }

    $divider = [string]::new([char]0x2500, 44)

    if ($Summary -and $Summary.Count -gt 0) {
        Write-Host "  $([char]0x2500)$([char]0x2500) DETAILS $divider" -ForegroundColor DarkCyan
        foreach ($item in $Summary) {
            if ($item.Label -and $item.Value) {
                $padding = ' ' * [Math]::Max(1, 18 - $item.Label.Length)
                Write-Host "  $($item.Label):$padding" -ForegroundColor DarkGray -NoNewline
                Write-Host "$($item.Value)" -ForegroundColor White
            }
            elseif ($item.Label -and -not $item.Value) {
                Write-Host "  $($item.Label):" -ForegroundColor DarkGray
            }
            else {
                Write-Host "  $($item.Value)" -ForegroundColor Gray
            }
        }
    }

    if ($AssignmentsSummary -and $AssignmentsSummary.Count -gt 0) {
        Write-Host ""
        foreach ($item in $AssignmentsSummary) {
            if ($item.Label -and -not $item.Value) {
                Write-Host "  $($item.Label):" -ForegroundColor DarkGray
            }
            else {
                Write-Host "  $($item.Value)" -ForegroundColor Gray
            }
        }
    }

    Write-Host "  $divider$([char]0x2500)$([char]0x2500)$([char]0x2500)$([char]0x2500)$([char]0x2500)$([char]0x2500)$([char]0x2500)$([char]0x2500)$([char]0x2500)$([char]0x2500)$([char]0x2500)" -ForegroundColor DarkCyan
    Write-Host ""
}

#endregion Payload Summary Functions

#region Graph API Functions

function Connect-ToGraph {
    param([string]$TenantId)

    $graphModule = Get-Module -Name Microsoft.Graph.Authentication -ListAvailable

    if (-not $graphModule) {
        Write-Host "  Installing Microsoft.Graph.Authentication module..." -ForegroundColor Yellow
        Install-Module Microsoft.Graph.Authentication -Scope CurrentUser -Force -AllowClobber
    }

    Import-Module Microsoft.Graph.Authentication -ErrorAction Stop

    try { Disconnect-MgGraph -ErrorAction SilentlyContinue | Out-Null } catch {}

    Write-Host "  Loading authentication libraries..." -ForegroundColor DarkGray
    $msalLoaded = Initialize-MSALAssemblies
    if (-not $msalLoaded) {
        Write-Host "  ERROR: " -ForegroundColor Red -NoNewline
        Write-Host "Could not load MSAL assemblies. Install the Az.Accounts module or NuGet Microsoft.Identity.Client." -ForegroundColor White
        return $null
    }
    $null = Initialize-MSALHelper

    $scopes = @(
        "DeviceManagementConfiguration.ReadWrite.All",
        "DeviceManagementRBAC.ReadWrite.All",
        "DeviceManagementManagedDevices.ReadWrite.All",
        "DeviceManagementApps.ReadWrite.All",
        "DeviceManagementScripts.ReadWrite.All"
    )

    if ($script:CustomClientId) {
        Write-Host "  Using app registration: " -ForegroundColor DarkGray -NoNewline
        Write-Host $script:CustomClientId -ForegroundColor Gray
    }

    $maxAttempts = 3
    for ($attempt = 1; $attempt -le $maxAttempts; $attempt++) {
        Write-Host "  Opening browser for authentication..." -ForegroundColor Cyan
        try {
            $accessToken = Get-BrowserAccessToken -Scopes $scopes
            $secureToken = ConvertTo-SecureString $accessToken -AsPlainText -Force
            Connect-MgGraph -AccessToken $secureToken -NoWelcome -ErrorAction Stop

            $context = Get-MgContext
            if ($context) {
                Write-Host "  Connected as: " -ForegroundColor Green -NoNewline
                Write-Host $context.Account -ForegroundColor White
                return $context
            }
        }
        catch {
            if ($attempt -lt $maxAttempts) {
                Write-Host "  Authentication failed or timed out. Retrying ($attempt/$maxAttempts)..." -ForegroundColor Yellow
            }
            else {
                Write-Host "  Authentication failed after $maxAttempts attempts." -ForegroundColor Red
                Write-Host "  $($_.Exception.Message)" -ForegroundColor DarkRed
            }
        }
    }

    return $null
}

function Get-PendingMAARequests {
    param([string]$UserEmail)

    $uri = "https://graph.microsoft.com/beta/deviceManagement/operationApprovalRequests?`$filter=status eq 'needsApproval'"

    try {
        $allRequests = @()

        try {
            $response = Invoke-MgGraphRequest -Uri $uri -Method GET
            if ($response.value) { $allRequests += $response.value }

            while ($response.'@odata.nextLink') {
                $response = Invoke-MgGraphRequest -Uri $response.'@odata.nextLink' -Method GET
                if ($response.value) { $allRequests += $response.value }
            }
        }
        catch {
            $uri = "https://graph.microsoft.com/beta/deviceManagement/operationApprovalRequests"
            $response = Invoke-MgGraphRequest -Uri $uri -Method GET

            if ($response.value) { $allRequests += $response.value }

            while ($response.'@odata.nextLink') {
                $response = Invoke-MgGraphRequest -Uri $response.'@odata.nextLink' -Method GET
                if ($response.value) { $allRequests += $response.value }
            }

            $allRequests = $allRequests | Where-Object { $_.status -ieq "needsApproval" }
        }

        if ($script:DebugMode -and $allRequests.Count -gt 0) {
            Write-Host ""
            Write-Host "  [DEBUG] Raw API fields for first pending request:" -ForegroundColor Magenta
            $allRequests[0].PSObject.Properties | ForEach-Object {
                Write-Host "    $($_.Name): $($_.Value)" -ForegroundColor DarkMagenta
            }
            Write-Host ""
            Wait-ForKeyPress
        }

        $pendingRequests = $allRequests | Where-Object {
            $requestorObj = $_.requestor
            if ($requestorObj -is [hashtable] -and $requestorObj.user) {
                $upn = $requestorObj.user.Upn
                return ($upn -ine $UserEmail)
            }
            return $true
        }

        return $pendingRequests

    }
    catch {
        Write-Host "  ERROR: " -ForegroundColor Red -NoNewline
        Write-Host $_.Exception.Message -ForegroundColor White
        return @()
    }
}

function Approve-MAARequest {
    param(
        [string]$RequestId,
        [string]$Justification = "Approved via MAA Manager"
    )

    $endpoint = "https://graph.microsoft.com/beta/deviceManagement/operationApprovalRequests/$RequestId/approve"
    $body = @{
        approvalSource = "AdminConsole"
        justification  = $Justification
    } | ConvertTo-Json

    try {
        Invoke-MgGraphRequest -Uri $endpoint -Method POST -Body $body -ContentType "application/json" | Out-Null
        return @{ Success = $true; Error = $null }
    }
    catch {
        $errMsg = $_.Exception.Message
        $errDetails = $null
        try { $errDetails = $_.ErrorDetails.Message } catch {}
        $fullErr = "Exception: $errMsg"
        if ($errDetails) { $fullErr = "$fullErr ; Details: $errDetails" }
        return @{ Success = $false; Error = $fullErr }
    }
}

function Cancel-MAARequest {
    param([string]$RequestId)

    $endpoint = "https://graph.microsoft.com/beta/deviceManagement/operationApprovalRequests/$RequestId/reject"
    $body = @{
        approvalSource = "AdminConsole"
        justification  = "Cancelled via MAA Manager"
    } | ConvertTo-Json

    try {
        Invoke-MgGraphRequest -Uri $endpoint -Method POST -Body $body -ContentType "application/json" | Out-Null
        return @{ Success = $true; Error = $null }
    }
    catch {
        return @{ Success = $false; Error = $_.ErrorDetails.Message }
    }
}

#endregion Graph API Functions

#region View Functions

function Show-RequestsList {
    param(
        [array]$Requests,
        [string]$UserEmail
    )

    Show-Header -UserEmail $UserEmail
    Write-Host "  APPROVED REQUESTS" -ForegroundColor DarkCyan
    Write-Host ""

    if ($Requests.Count -eq 0) {
        Write-Host "  No approved MAA requests found." -ForegroundColor Yellow
        Write-Host ""
        return
    }

    Write-Host "  Total: " -ForegroundColor DarkGray -NoNewline
    Write-Host "$($Requests.Count)" -ForegroundColor White
    Write-Host ""

    for ($i = 0; $i -lt $Requests.Count; $i++) {
        $request = $Requests[$i]

        $displayName = $request.payloadName
        if ([string]::IsNullOrWhiteSpace($displayName)) { $displayName = $request.displayName }
        if ([string]::IsNullOrWhiteSpace($displayName)) { $displayName = "Unnamed Request" }

        $resourceType = $request.payloadType
        if ([string]::IsNullOrWhiteSpace($resourceType)) { $resourceType = "-" }
        if ($resourceType -like "*.*") {
            $resourceType = $resourceType.Split('.')[-1]
        }
        if ($script:ResourceTypeMap.ContainsKey($resourceType)) {
            $resourceType = $script:ResourceTypeMap[$resourceType]
        }

        $requestDate = if ($request.requestDateTime) {
            ([DateTime]$request.requestDateTime).ToString("yyyy-MM-dd h:mm tt")
        }
        else { "N/A" }

        $requestedBy = "-"
        if ($request.requestor -and $request.requestor.user) {
            $requestedBy = $request.requestor.user.Upn
            if ([string]::IsNullOrWhiteSpace($requestedBy)) {
                $requestedBy = $request.requestor.user.displayName
            }
        }
        if ([string]::IsNullOrWhiteSpace($requestedBy)) { $requestedBy = "-" }

        if ($displayName.Length -gt 50) {
            $displayName = $displayName.Substring(0, 47) + "..."
        }

        Write-Host "    [$($i + 1)] " -ForegroundColor DarkGray -NoNewline
        $operation = $request.payloadOperation
        if ([string]::IsNullOrWhiteSpace($operation)) { $operation = "-" }
        if ($operation -ieq "Action") {
            $policyTypes = $request.requiredOperationApprovalPolicyTypes
            if ($policyTypes -and $policyTypes.Count -gt 0) {
                $actionMap = @{
                    "deviceWipe"   = "Wipe"
                    "deviceRetire" = "Retire"
                    "deviceDelete" = "Delete"
                }
                $mapped = $policyTypes | ForEach-Object {
                    if ($actionMap.ContainsKey($_)) { $actionMap[$_] } else { $_ }
                }
                $operation = ($mapped -join ', ')
            }
        }

        Write-Host "$displayName" -ForegroundColor White
        Write-Host "        " -NoNewline
        Write-Host "APPROVED" -ForegroundColor Green -NoNewline
        Write-Host " | " -ForegroundColor DarkGray -NoNewline
        Write-Host "$operation" -ForegroundColor Magenta -NoNewline
        Write-Host " | " -ForegroundColor DarkGray -NoNewline
        Write-Host "$resourceType" -ForegroundColor Cyan -NoNewline
        Write-Host " | $requestDate" -ForegroundColor DarkGray
        Write-Host "        Requested by: " -ForegroundColor DarkGray -NoNewline
        Write-Host "$requestedBy" -ForegroundColor Gray

        if ($resourceType -eq "ManagedDevice") {
            $devPayload = if ($request.displayPayload) { $request.displayPayload } else { $request.payload }
            if ($devPayload) {
                try {
                    $parsedPayload = if ($devPayload -is [string]) { $devPayload | ConvertFrom-Json } else { $devPayload }
                    $devItems = @($parsedPayload)
                    foreach ($dev in $devItems) {
                        $userDisplay = if ($dev -is [hashtable]) { $dev["primaryUserEmail"] } else { $dev.primaryUserEmail }
                        if (-not [string]::IsNullOrWhiteSpace($userDisplay)) {
                            Write-Host "        Primary User: " -ForegroundColor DarkGray -NoNewline
                            Write-Host "$userDisplay" -ForegroundColor Yellow
                        }
                    }
                }
                catch {}
            }
        }

        Write-Host ""
    }
}

function Show-PendingRequestsList {
    param(
        [array]$Requests,
        [string]$UserEmail
    )

    Show-Header -UserEmail $UserEmail
    Write-Host "  PENDING APPROVAL" -ForegroundColor Yellow
    Write-Host ""

    if ($Requests.Count -eq 0) {
        Write-Host "  No requests pending your approval." -ForegroundColor Yellow
        Write-Host ""
        return
    }

    Write-Host "  Total: " -ForegroundColor DarkGray -NoNewline
    Write-Host "$($Requests.Count)" -ForegroundColor White
    Write-Host ""

    for ($i = 0; $i -lt $Requests.Count; $i++) {
        $request = $Requests[$i]

        $displayName = $request.payloadName
        if ([string]::IsNullOrWhiteSpace($displayName)) { $displayName = $request.displayName }
        if ([string]::IsNullOrWhiteSpace($displayName)) { $displayName = "Unnamed Request" }

        $resourceType = $request.payloadType
        if ([string]::IsNullOrWhiteSpace($resourceType)) { $resourceType = "-" }
        if ($resourceType -like "*.*") {
            $resourceType = $resourceType.Split('.')[-1]
        }
        if ($script:ResourceTypeMap.ContainsKey($resourceType)) {
            $resourceType = $script:ResourceTypeMap[$resourceType]
        }

        $requestDate = if ($request.requestDateTime) {
            ([DateTime]$request.requestDateTime).ToString("yyyy-MM-dd h:mm tt")
        }
        else { "N/A" }

        $requestedBy = "-"
        if ($request.requestor -and $request.requestor.user) {
            $requestedBy = $request.requestor.user.Upn
            if ([string]::IsNullOrWhiteSpace($requestedBy)) {
                $requestedBy = $request.requestor.user.displayName
            }
        }
        if ([string]::IsNullOrWhiteSpace($requestedBy)) { $requestedBy = "-" }

        $operation = $request.payloadOperation
        if ([string]::IsNullOrWhiteSpace($operation)) { $operation = "-" }
        if ($operation -ieq "Action") {
            $policyTypes = $request.requiredOperationApprovalPolicyTypes
            if ($policyTypes -and $policyTypes.Count -gt 0) {
                $actionMap = @{
                    "deviceWipe"   = "Wipe"
                    "deviceRetire" = "Retire"
                    "deviceDelete" = "Delete"
                }
                $mapped = $policyTypes | ForEach-Object {
                    if ($actionMap.ContainsKey($_)) { $actionMap[$_] } else { $_ }
                }
                $operation = ($mapped -join ', ')
            }
            elseif ($request.payloadSubtype) {
                $subtype = $request.payloadSubtype
                if ($subtype -like "*.*") { $subtype = $subtype.Split('.')[-1] }
                $operation = $subtype
            }
        }

        $justification = $request.requestJustification
        if ([string]::IsNullOrWhiteSpace($justification)) { $justification = "" }

        if ($displayName.Length -gt 50) {
            $displayName = $displayName.Substring(0, 47) + "..."
        }

        Write-Host "    [$($i + 1)] " -ForegroundColor DarkGray -NoNewline
        Write-Host "$displayName" -ForegroundColor White
        Write-Host "        " -NoNewline
        Write-Host "PENDING" -ForegroundColor Yellow -NoNewline
        Write-Host " | " -ForegroundColor DarkGray -NoNewline
        Write-Host "$operation" -ForegroundColor Magenta -NoNewline
        Write-Host " | " -ForegroundColor DarkGray -NoNewline
        Write-Host "$resourceType" -ForegroundColor Cyan -NoNewline
        Write-Host " | $requestDate" -ForegroundColor DarkGray
        Write-Host "        Requested by: " -ForegroundColor DarkGray -NoNewline
        Write-Host "$requestedBy" -ForegroundColor Gray
        if ($justification) {
            Write-Host "        Reason: " -ForegroundColor DarkGray -NoNewline
            Write-Host "$justification" -ForegroundColor Gray
        }

        if ($resourceType -eq "ManagedDevice") {
            $devPayload = if ($request.displayPayload) { $request.displayPayload } else { $request.payload }
            if ($devPayload) {
                try {
                    $parsedPayload = if ($devPayload -is [string]) { $devPayload | ConvertFrom-Json } else { $devPayload }
                    $devItems = @($parsedPayload)
                    foreach ($dev in $devItems) {
                        $userDisplay = if ($dev -is [hashtable]) { $dev["primaryUserEmail"] } else { $dev.primaryUserEmail }
                        if (-not [string]::IsNullOrWhiteSpace($userDisplay)) {
                            Write-Host "        Primary User: " -ForegroundColor DarkGray -NoNewline
                            Write-Host "$userDisplay" -ForegroundColor Yellow
                        }
                    }
                }
                catch {}
            }
        }

        Write-Host ""
    }
}

function Show-PendingActions {
    param([object]$Request)

    $displayName = $Request.payloadName
    if ([string]::IsNullOrWhiteSpace($displayName)) { $displayName = $Request.displayName }
    if ([string]::IsNullOrWhiteSpace($displayName)) { $displayName = "Unnamed Request" }

    $resourceType = $Request.payloadType
    if ([string]::IsNullOrWhiteSpace($resourceType)) { $resourceType = "-" }
    if ($resourceType -like "*.*") {
        $resourceType = $resourceType.Split('.')[-1]
    }
    if ($script:ResourceTypeMap.ContainsKey($resourceType)) {
        $resourceType = $script:ResourceTypeMap[$resourceType]
    }

    $operation = $Request.payloadOperation
    if ([string]::IsNullOrWhiteSpace($operation)) { $operation = "-" }
    if ($operation -ieq "Action") {
        $policyTypes = $Request.requiredOperationApprovalPolicyTypes
        if ($policyTypes -and $policyTypes.Count -gt 0) {
            $actionMap = @{
                "deviceWipe"   = "Wipe"
                "deviceRetire" = "Retire"
                "deviceDelete" = "Delete"
            }
            $mapped = $policyTypes | ForEach-Object {
                if ($actionMap.ContainsKey($_)) { $actionMap[$_] } else { $_ }
            }
            $operation = ($mapped -join ', ')
        }
        elseif ($Request.payloadSubtype) {
            $subtype = $Request.payloadSubtype
            if ($subtype -like "*.*") { $subtype = $subtype.Split('.')[-1] }
            $operation = $subtype
        }
    }

    $justification = $Request.requestJustification
    if ([string]::IsNullOrWhiteSpace($justification)) { $justification = "None provided" }

    $requestedBy = "-"
    if ($Request.requestor -and $Request.requestor.user) {
        $requestedBy = $Request.requestor.user.Upn
        if ([string]::IsNullOrWhiteSpace($requestedBy)) {
            $requestedBy = $Request.requestor.user.displayName
        }
    }

    Write-Host ""
    Write-Host "  REVIEW REQUEST" -ForegroundColor Yellow
    Write-Host ""
    Write-Host "  $displayName" -ForegroundColor Cyan
    Write-Host "  Operation: $operation" -ForegroundColor DarkGray
    Write-Host "  Type: $resourceType" -ForegroundColor DarkGray
    Write-Host "  Requested by: $requestedBy" -ForegroundColor DarkGray
    Write-Host "  Reason: $justification" -ForegroundColor DarkGray
    Write-Host "  ID: $($Request.id)" -ForegroundColor DarkGray
    Write-Host ""

    $payloadSummary = Get-PayloadSummary -Request $Request

    $assignments = $Request.addedAssignments
    if (-not $assignments) {
        $assignments = Get-RelatedAssignments -Request $Request
    }
    $assignmentsSummary = Get-AssignmentsSummary -Assignments $assignments
    Show-PayloadDetails -Summary $payloadSummary -AssignmentsSummary $assignmentsSummary

    $actions = @()
    if ($Request.payload) {
        $actions += @{ Key = "S"; Text = "VS Code" }
        $actions += @{ Key = "N"; Text = "Notepad" }
    }
    $actions += @{ Key = "A"; Text = "Approve" }
    $actions += @{ Key = "D"; Text = "Deny" }
    Show-InlineActions -Actions $actions
    Show-ControlBar
}

#endregion View Functions

#region Configuration

function Configure-IntuneMAA {
    <#
    .SYNOPSIS
        Configure Intune-MAA with custom app registration credentials.

    .DESCRIPTION
        Interactively prompts for ClientId and TenantId and saves them as user-level
        environment variables. Once configured, Start-MAAApproval will automatically
        use these credentials without requiring parameters.

    .EXAMPLE
        Configure-IntuneMAA
    #>
    [CmdletBinding()]
    param()

    Write-Host "`nIntune-MAA Configuration" -ForegroundColor Cyan
    Write-Host "========================" -ForegroundColor Cyan
    Write-Host "`nThis will configure your custom app registration for Intune-MAA."
    Write-Host "These settings will be saved as user-level environment variables.`n"

    # Show current config if any
    $currentClient = $env:MAA_CLIENT_ID
    $currentTenant = $env:MAA_TENANT_ID
    if ($currentClient) {
        Write-Host "Current Config:" -ForegroundColor Yellow
        Write-Host "  Client ID: $currentClient" -ForegroundColor Gray
        Write-Host "  Tenant ID: $(if ($currentTenant) { $currentTenant } else { '(not set)' })" -ForegroundColor Gray
        Write-Host ""
    }

    # Prompt for ClientId
    $clientId = Read-Host "Enter your App Registration Client ID"
    if ([string]::IsNullOrWhiteSpace($clientId)) {
        Write-Host "ClientId cannot be empty. Configuration cancelled." -ForegroundColor Yellow
        return
    }

    # Prompt for TenantId
    $tenantId = Read-Host "Enter your Tenant ID"
    if ([string]::IsNullOrWhiteSpace($tenantId)) {
        Write-Host "TenantId cannot be empty. Configuration cancelled." -ForegroundColor Yellow
        return
    }

    # Set user-level environment variables
    try {
        [System.Environment]::SetEnvironmentVariable('MAA_CLIENT_ID', $clientId, 'User')
        [System.Environment]::SetEnvironmentVariable('MAA_TENANT_ID', $tenantId, 'User')

        # Also set for current session
        $env:MAA_CLIENT_ID = $clientId
        $env:MAA_TENANT_ID = $tenantId

        Write-Host "`nConfiguration saved successfully!" -ForegroundColor Green
        Write-Host "You can now run Start-MAAApproval without parameters.`n" -ForegroundColor Green

        Write-Host "App Registration Requirements:" -ForegroundColor Yellow
        Write-Host "  Platform: Mobile and desktop applications" -ForegroundColor DarkGray
        Write-Host "  Redirect URI: http://localhost" -ForegroundColor DarkGray
        Write-Host "  Allow public client flows: Yes" -ForegroundColor DarkGray
        Write-Host "  Delegated permissions:" -ForegroundColor DarkGray
        Write-Host "    - DeviceManagementConfiguration.ReadWrite.All" -ForegroundColor DarkGray
        Write-Host "    - DeviceManagementRBAC.ReadWrite.All" -ForegroundColor DarkGray
        Write-Host "    - DeviceManagementManagedDevices.ReadWrite.All" -ForegroundColor DarkGray
        Write-Host "    - DeviceManagementApps.ReadWrite.All" -ForegroundColor DarkGray
        Write-Host "    - DeviceManagementScripts.ReadWrite.All" -ForegroundColor DarkGray
        Write-Host ""

        # macOS-specific handling
        $isRunningOnMac = if ($null -ne $IsMacOS) { $IsMacOS } else { $PSVersionTable.OS -match 'Darwin' }
        if ($isRunningOnMac) {
            Write-Host "macOS Note:" -ForegroundColor Yellow
            Write-Host "Environment variables may not persist across terminal sessions on macOS." -ForegroundColor Gray
            Write-Host "To ensure persistence, add the following to your PowerShell profile:`n" -ForegroundColor Gray
            Write-Host "`$env:MAA_CLIENT_ID = `"$clientId`"" -ForegroundColor Cyan
            Write-Host "`$env:MAA_TENANT_ID = `"$tenantId`"`n" -ForegroundColor Cyan

            Write-Host "Would you like to:" -ForegroundColor Yellow
            Write-Host "  1) Add automatically to PowerShell profile" -ForegroundColor White
            Write-Host "  2) Do it manually later" -ForegroundColor White
            Write-Host ""
            $choice = Read-Host "Enter choice (1 or 2)"

            if ($choice -eq "1") {
                $profilePath = $PROFILE.CurrentUserAllHosts
                if (-not (Test-Path $profilePath)) {
                    New-Item -Path $profilePath -ItemType File -Force | Out-Null
                }

                $profileContent = @"

# Intune-MAA Configuration
`$env:MAA_CLIENT_ID = "$clientId"
`$env:MAA_TENANT_ID = "$tenantId"
"@
                Add-Content -Path $profilePath -Value $profileContent
                Write-Host "`nAdded to PowerShell profile: $profilePath" -ForegroundColor Green
                Write-Host "Configuration will persist across sessions.`n" -ForegroundColor Green
            }
            else {
                Write-Host "`nYou can add it manually later to: $($PROFILE.CurrentUserAllHosts)`n" -ForegroundColor Gray
            }
        }
    }
    catch {
        Write-Host "`nFailed to save configuration: $_" -ForegroundColor Red
    }
}

function Clear-IntuneMAA {
    <#
    .SYNOPSIS
        Clears the saved Intune-MAA configuration.

    .DESCRIPTION
        Removes the user-level environment variables for ClientId and TenantId.
        On macOS, also offers to remove the configuration from PowerShell profile.
        After clearing, Start-MAAApproval will use the default authentication flow.

    .EXAMPLE
        Clear-IntuneMAA
    #>
    [CmdletBinding()]
    param()

    try {
        [System.Environment]::SetEnvironmentVariable('MAA_CLIENT_ID', $null, 'User')
        [System.Environment]::SetEnvironmentVariable('MAA_TENANT_ID', $null, 'User')

        # Also clear from current session
        $env:MAA_CLIENT_ID = $null
        $env:MAA_TENANT_ID = $null

        Write-Host "Intune-MAA configuration cleared successfully." -ForegroundColor Green
        Write-Host "Start-MAAApproval will now use the default authentication flow.`n" -ForegroundColor Green

        # macOS-specific handling
        $isRunningOnMac = if ($null -ne $IsMacOS) { $IsMacOS } else { $PSVersionTable.OS -match 'Darwin' }
        if ($isRunningOnMac) {
            $profilePath = $PROFILE.CurrentUserAllHosts
            if (Test-Path $profilePath) {
                $profileContent = Get-Content -Path $profilePath -Raw
                if ($profileContent -match 'MAA_CLIENT_ID' -or $profileContent -match 'MAA_TENANT_ID') {
                    Write-Host "macOS Note:" -ForegroundColor Yellow
                    Write-Host "Configuration found in PowerShell profile." -ForegroundColor Gray
                    Write-Host "Would you like to remove it from your profile? (y/n)" -ForegroundColor Yellow
                    $choice = Read-Host

                    if ($choice -eq 'y' -or $choice -eq 'Y') {
                        $newContent = $profileContent -replace '(?ms)# Intune-MAA Configuration.*?\$env:MAA_TENANT_ID = ".*?"', ''
                        Set-Content -Path $profilePath -Value $newContent.Trim()
                        Write-Host "Removed from PowerShell profile: $profilePath`n" -ForegroundColor Green
                    }
                    else {
                        Write-Host "Profile not modified. You can manually edit: $profilePath`n" -ForegroundColor Gray
                    }
                }
            }
        }
    }
    catch {
        Write-Host "Failed to clear configuration: $_" -ForegroundColor Red
    }
}

#endregion Configuration

#region Main Entry Point

function Start-MAAApproval {
    <#
    .SYNOPSIS
        Launch the MAA Approval Manager TUI for reviewing and approving Intune MAA requests.

    .PARAMETER ClientId
        Client ID of a custom app registration for delegated auth.

    .PARAMETER TenantId
        Your Azure AD tenant ID.

    .PARAMETER ShowRaw
        Enable debug mode to show raw API responses.

    .EXAMPLE
        Start-MAAApproval

    .EXAMPLE
        Start-MAAApproval -ClientId "your-app-id" -TenantId "your-tenant-id"
    #>
    [CmdletBinding()]
    param(
        [Parameter()]
        [string]$ClientId,

        [Parameter()]
        [string]$TenantId,

        [switch]$ShowRaw
    )

    $script:DebugMode = $ShowRaw

    # Load saved config from environment variables (parameters take priority)
    if (-not $ClientId -and $env:MAA_CLIENT_ID) { $ClientId = $env:MAA_CLIENT_ID }
    if (-not $TenantId -and $env:MAA_TENANT_ID) { $TenantId = $env:MAA_TENANT_ID }

    $script:CustomClientId = $ClientId
    $script:CustomTenantId = $TenantId

    try {
        Show-Header
        Write-Host "  Initializing..." -ForegroundColor DarkGray
        Write-Host ""

        $context = Connect-ToGraph -TenantId $TenantId

        if (-not $context) {
            Write-Host ""
            Write-Host "  ERROR: " -ForegroundColor Red -NoNewline
            Write-Host "Failed to connect to Microsoft Graph." -ForegroundColor White
            Write-Host ""
            Read-Host "  Press Enter to exit"
            return
        }

        $loggedInUser = $context.Account

        if (-not $loggedInUser) {
            Write-Host "  ERROR: " -ForegroundColor Red -NoNewline
            Write-Host "Could not determine logged-in user." -ForegroundColor White
            Write-Host ""
            Read-Host "  Press Enter to exit"
            return
        }

        Start-Sleep -Milliseconds 500

        Start-ApprovalManager -UserEmail $loggedInUser

        Write-Host ""
        Write-Host "  Disconnecting from Microsoft Graph..." -ForegroundColor DarkGray
        Disconnect-MgGraph -ErrorAction SilentlyContinue | Out-Null
        Write-Host "  Disconnected." -ForegroundColor Green
        Write-Host ""

    }
    catch {
        Write-Host ""
        Write-Host "  UNEXPECTED ERROR: " -ForegroundColor Red -NoNewline
        Write-Host $_.Exception.Message -ForegroundColor White
        Write-Host ""
        Write-Host "  Stack trace:" -ForegroundColor DarkGray
        Write-Host $_.ScriptStackTrace -ForegroundColor DarkGray
        Write-Host ""
        Read-Host "  Press Enter to exit"
    }
}

function Start-ApprovalManager {
    param([string]$UserEmail)

    while ($true) {
        Show-Header -UserEmail $UserEmail
        Write-Host "  Fetching pending requests..." -ForegroundColor Cyan
        $pendingRequests = @(Get-PendingMAARequests -UserEmail $UserEmail)

        Show-PendingRequestsList -Requests $pendingRequests -UserEmail $UserEmail

        $actions = @()
        if ($pendingRequests.Count -gt 0) {
            $actions += @{ Key = "1-$($pendingRequests.Count)"; Text = "Select" }
            $actions += @{ Key = "A"; Text = "Approve All" }
        }
        $actions += @{ Key = "R"; Text = "Refresh" }
        Show-InlineActions -Actions $actions
        Show-ControlBar

        $pSelection = Read-MenuKey

        switch ($pSelection) {
            "B" { return }
            "E" {
                Write-Host ""
                Write-Host "  Disconnecting from Microsoft Graph..." -ForegroundColor DarkGray
                Disconnect-MgGraph -ErrorAction SilentlyContinue | Out-Null
                Write-Host "  Disconnected." -ForegroundColor Green
                Write-Host ""
                exit 0
            }
            "R" { continue }
            "A" {
                if ($pendingRequests.Count -eq 0) {
                    Write-Host ""
                    Write-Host "  No requests to approve." -ForegroundColor Yellow
                    Start-Sleep -Milliseconds 800
                    continue
                }

                Show-Header -UserEmail $UserEmail
                Write-Host "  APPROVE ALL PENDING REQUESTS" -ForegroundColor Green
                Write-Host ""
                Write-Host "  About to approve $($pendingRequests.Count) request(s)." -ForegroundColor Yellow
                Write-Host ""
                Show-ControlBar -NoBack -ReserveLines 1
                $justInput = Read-Host "  Justification (or press Enter for default)"
                if ([string]::IsNullOrWhiteSpace($justInput)) { $justInput = "Approved via MAA Manager" }
                Write-Host ""
                Show-ControlBar -NoBack -ReserveLines 1
                $confirm = Read-Host "  Confirm? (Y/N)"
                [Console]::Write("$([char]27)[J")

                if ($confirm.ToUpper() -eq "Y") {
                    Write-Host ""
                    $approved = 0
                    foreach ($req in $pendingRequests) {
                        $name = $req.payloadName
                        if ([string]::IsNullOrWhiteSpace($name)) { $name = $req.displayName }
                        if ([string]::IsNullOrWhiteSpace($name)) { $name = "Request" }
                        Write-Host "  Approving: $name... " -ForegroundColor Cyan -NoNewline
                        $result = Approve-MAARequest -RequestId $req.id -Justification $justInput
                        if ($result.Success) {
                            Write-Host "Done" -ForegroundColor Green
                            $approved++
                        }
                        else {
                            Write-Host "Failed" -ForegroundColor Red
                            if ($result.Error) {
                                Write-Host "        Error: $($result.Error)" -ForegroundColor DarkRed
                            }
                        }
                        Start-Sleep -Milliseconds 300
                    }
                    Write-Host ""
                    Write-Host "  SUCCESS: " -ForegroundColor Green -NoNewline
                    Write-Host "Approved $approved of $($pendingRequests.Count) requests" -ForegroundColor White
                    Wait-ForKeyPress
                }
            }
            { $_ -match '^[0-9]$' } {
                $pIdx = [int]$pSelection - 1
                if ($pIdx -ge 0 -and $pIdx -lt $pendingRequests.Count) {
                    $selectedPending = $pendingRequests[$pIdx]

                    $inReview = $true
                    while ($inReview) {
                        Show-Header -UserEmail $UserEmail
                        Show-PendingActions -Request $selectedPending

                        $pAction = Read-MenuKey

                        switch ($pAction) {
                            "A" {
                                Write-Host ""
                                Show-ControlBar -ReserveLines 1
                                $justInput = Read-Host "  Justification (or press Enter for default)"
                                if ([string]::IsNullOrWhiteSpace($justInput)) { $justInput = "Approved via MAA Manager" }
                                [Console]::Write("$([char]27)[J")
                                Write-Host "  Approving request... " -ForegroundColor Cyan -NoNewline
                                $result = Approve-MAARequest -RequestId $selectedPending.id -Justification $justInput
                                if ($result.Success) {
                                    Write-Host "SUCCESS" -ForegroundColor Green
                                }
                                else {
                                    Write-Host "FAILED" -ForegroundColor Red
                                    if ($result.Error) {
                                        Write-Host ""
                                        Write-Host "  Error: $($result.Error)" -ForegroundColor DarkRed
                                    }
                                }
                                Wait-ForKeyPress
                                $inReview = $false
                            }
                            "D" {
                                Write-Host ""
                                Show-ControlBar -ReserveLines 1
                                $confirm = Read-Host "  Deny this request? (Y/N)"
                                [Console]::Write("$([char]27)[J")
                                if ($confirm.ToUpper() -eq "Y") {
                                    Write-Host "  Denying request... " -ForegroundColor Cyan -NoNewline
                                    $result = Cancel-MAARequest -RequestId $selectedPending.id
                                    if ($result.Success) {
                                        Write-Host "SUCCESS" -ForegroundColor Green
                                    }
                                    else {
                                        Write-Host "FAILED" -ForegroundColor Red
                                        if ($result.Error) {
                                            Write-Host ""
                                            Write-Host "  Error: $($result.Error)" -ForegroundColor DarkRed
                                        }
                                    }
                                    Start-Sleep -Milliseconds 800
                                }
                                $inReview = $false
                            }
                            "S" {
                                Write-Host ""
                                Open-PayloadForReview -Request $selectedPending -Editor "code"
                                Write-Host ""
                                Show-ControlBar -ReserveLines 1
                                $null = Read-Host "  Review completed? (Y to continue)"
                            }
                            "N" {
                                Write-Host ""
                                Open-PayloadForReview -Request $selectedPending -Editor "notepad"
                                Write-Host ""
                                Show-ControlBar -ReserveLines 1
                                $null = Read-Host "  Review completed? (Y to continue)"
                            }
                            "B" { $inReview = $false }
                            "E" {
                                Write-Host ""
                                Write-Host "  Disconnecting from Microsoft Graph..." -ForegroundColor DarkGray
                                Disconnect-MgGraph -ErrorAction SilentlyContinue | Out-Null
                                Write-Host "  Disconnected." -ForegroundColor Green
                                Write-Host ""
                                exit 0
                            }
                            default {
                                Write-Host "  Invalid option." -ForegroundColor Yellow
                                Start-Sleep -Milliseconds 500
                            }
                        }
                    }
                }
                else {
                    Write-Host "  Invalid selection." -ForegroundColor Yellow
                    Start-Sleep -Seconds 1
                }
            }
            default {
                if (-not [string]::IsNullOrWhiteSpace($pSelection)) {
                    Write-Host "  Invalid option." -ForegroundColor Yellow
                    Start-Sleep -Seconds 1
                }
            }
        }
    }
}

#endregion Main Entry Point
