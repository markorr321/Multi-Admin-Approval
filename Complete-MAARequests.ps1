<#
.SYNOPSIS
    MAA Manager - Manage approved Multi Admin Approval requests in Microsoft Intune.

.DESCRIPTION
    This script provides a terminal user interface for managing approved MAA requests.
    It automatically detects the logged-in user and allows completing or cancelling
    approved requests interactively.

.PARAMETER TenantId
    Your Azure AD tenant ID. Optional - will use common endpoint if not specified.

.PARAMETER Install
    Adds a 'MAAManager' function to your PowerShell profile for easy access.

.EXAMPLE
    .\Complete-MAARequests.ps1

.EXAMPLE
    .\Complete-MAARequests.ps1 -TenantId "your-tenant-id"

.EXAMPLE
    .\Complete-MAARequests.ps1 -Install

.NOTES
    Required Permissions:
    - DeviceManagementConfiguration.ReadWrite.All
    - DeviceManagementRBAC.ReadWrite.All
#>

[CmdletBinding()]
param(
    [Parameter()]
    [string]$TenantId,
    
    [switch]$Install,
    
    [switch]$ShowRaw
)

$script:DebugMode = $ShowRaw

#region Self-Install

if ($Install) {
    $ScriptPath = $MyInvocation.MyCommand.Path
    $FunctionDefinition = "`nfunction MAAManager { & '$ScriptPath' }"
    
    if (!(Test-Path $PROFILE)) {
        New-Item -Path $PROFILE -ItemType File -Force | Out-Null
        Write-Host "Created PowerShell profile at: $PROFILE" -ForegroundColor Green
    }
    
    $ProfileContent = Get-Content $PROFILE -Raw -ErrorAction SilentlyContinue
    if ($ProfileContent -match 'function MAAManager') {
        Write-Host "MAAManager is already installed in your profile." -ForegroundColor Yellow
    }
    else {
        Add-Content $PROFILE $FunctionDefinition
        Write-Host "MAAManager has been added to your PowerShell profile." -ForegroundColor Green
        Write-Host "Restart PowerShell or run: . `$PROFILE" -ForegroundColor Cyan
    }
    return
}

#endregion

#region Functions

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
    Write-Host "  Press any key to continue..." -ForegroundColor DarkGray
    $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
}

function Connect-ToGraph {
    param([string]$TenantId)
    
    # Suppress WAM warning
    $env:AZURE_CLIENT_DISABLE_WAM = "true"
    
    $graphModule = Get-Module -Name Microsoft.Graph.Authentication -ListAvailable
    
    if (-not $graphModule) {
        Write-Host "  Installing Microsoft.Graph.Authentication module..." -ForegroundColor Yellow
        Install-Module Microsoft.Graph.Authentication -Scope CurrentUser -Force -AllowClobber
    }
    
    Import-Module Microsoft.Graph.Authentication -ErrorAction Stop
    
    $scopes = @(
        "DeviceManagementConfiguration.ReadWrite.All",
        "DeviceManagementRBAC.ReadWrite.All"
    )
    
    $connectParams = @{ Scopes = $scopes; NoWelcome = $true }
    if ($TenantId) { $connectParams.TenantId = $TenantId }
    
    Write-Host "  Connecting to Microsoft Graph..." -ForegroundColor Cyan
    Connect-MgGraph @connectParams -WarningAction SilentlyContinue
    
    $context = Get-MgContext
    if ($context) {
        Write-Host "  Connected as: " -ForegroundColor Green -NoNewline
        Write-Host $context.Account -ForegroundColor White
        return $context
    }
    
    return $null
}

function Get-ApprovedMAARequests {
    param([string]$UserEmail)
    
    # Use server-side filtering for approved status - much faster than client-side filtering
    $uri = "https://graph.microsoft.com/beta/deviceManagement/operationApprovalRequests?`$filter=status eq 'approved'"
    
    try {
        $allRequests = @()
        
        try {
            $response = Invoke-MgGraphRequest -Uri $uri -Method GET
            if ($response.value) { $allRequests += $response.value }
            
            while ($response.'@odata.nextLink') {
                $response = Invoke-MgGraphRequest -Uri $response.'@odata.nextLink' -Method GET
                if ($response.value) { $allRequests += $response.value }
            }
        } catch {
            # Fallback if filter not supported - fetch all and filter client-side
            $uri = "https://graph.microsoft.com/beta/deviceManagement/operationApprovalRequests"
            $response = Invoke-MgGraphRequest -Uri $uri -Method GET
            
            if ($response.value) { $allRequests += $response.value }
            
            while ($response.'@odata.nextLink') {
                $response = Invoke-MgGraphRequest -Uri $response.'@odata.nextLink' -Method GET
                if ($response.value) { $allRequests += $response.value }
            }
            
            $allRequests = $allRequests | Where-Object { $_.status -ieq "approved" }
        }
        
        # Debug: Show raw API response fields
        if ($script:DebugMode -and $allRequests.Count -gt 0) {
            Write-Host ""
            Write-Host "  [DEBUG] Raw API fields for first request:" -ForegroundColor Magenta
            $allRequests[0].PSObject.Properties | ForEach-Object {
                Write-Host "    $($_.Name): $($_.Value)" -ForegroundColor DarkMagenta
            }
            Write-Host ""
            Write-Host "  Press any key to continue..." -ForegroundColor DarkGray
            $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
        }
        
        # Filter by the logged-in user - requestor.user.Upn contains the UPN
        $approvedRequests = $allRequests | Where-Object {
            $requestorObj = $_.requestor
            if ($requestorObj -is [hashtable] -and $requestorObj.user) {
                $upn = $requestorObj.user.Upn
                return ($upn -ieq $UserEmail)
            }
            return $false
        }
        
        # If still no matches, return all approved (user can see all they have access to)
        if ($approvedRequests.Count -eq 0 -and $allRequests.Count -gt 0) {
            if ($script:DebugMode) {
                Write-Host "  [DEBUG] No user match found, showing all $($allRequests.Count) approved requests" -ForegroundColor Magenta
            }
            $approvedRequests = $allRequests
        }
        
        return $approvedRequests
        
    } catch {
        Write-Host "  ERROR: " -ForegroundColor Red -NoNewline
        Write-Host $_.Exception.Message -ForegroundColor White
        return @()
    }
}

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
        
        # Use correct API field names
        $displayName = $request.payloadName
        if ([string]::IsNullOrWhiteSpace($displayName)) { $displayName = $request.displayName }
        if ([string]::IsNullOrWhiteSpace($displayName)) { $displayName = "Unnamed Request" }
        
        # Resource type from payloadType - translate to friendly names
        $resourceTypeMap = @{
            "MobileApp"                    = "App"
            "DeviceHealthScript"           = "Remediation script"
            "DeviceConfiguration"          = "Configuration profile"
            "DeviceCompliancePolicy"       = "Compliance policy"
            "WindowsAutopilotDeploymentProfile" = "Autopilot profile"
            "DeviceManagementScript"       = "Platform script"
            "GroupPolicyConfiguration"     = "Group policy"
            "DeviceEnrollmentConfiguration" = "Enrollment config"
            "WindowsFeatureUpdateProfile"  = "Feature update"
            "WindowsQualityUpdateProfile"  = "Quality update"
            "WindowsDriverUpdateProfile"   = "Driver update"
        }
        
        $resourceType = $request.payloadType
        if ([string]::IsNullOrWhiteSpace($resourceType)) { $resourceType = "-" }
        if ($resourceType -like "*.*") {
            $resourceType = $resourceType.Split('.')[-1]
        }
        # Apply friendly name translation
        if ($resourceTypeMap.ContainsKey($resourceType)) {
            $resourceType = $resourceTypeMap[$resourceType]
        }
        
        # Get request date - use 12-hour format with AM/PM
        $requestDate = if ($request.requestDateTime) { 
            ([DateTime]$request.requestDateTime).ToString("yyyy-MM-dd h:mm tt") 
        } else { "N/A" }
        
        # Get requestor info - nested in requestor.user.Upn
        $requestedBy = "-"
        if ($request.requestor -and $request.requestor.user) {
            $requestedBy = $request.requestor.user.Upn
            if ([string]::IsNullOrWhiteSpace($requestedBy)) {
                $requestedBy = $request.requestor.user.displayName
            }
        }
        if ([string]::IsNullOrWhiteSpace($requestedBy)) { $requestedBy = "-" }
        
        # Truncate if too long
        if ($displayName.Length -gt 50) {
            $displayName = $displayName.Substring(0, 47) + "..."
        }
        
        Write-Host "    [$($i + 1)] " -ForegroundColor DarkGray -NoNewline
        Write-Host "$displayName" -ForegroundColor White
        Write-Host "        " -NoNewline
        Write-Host "APPROVED" -ForegroundColor Green -NoNewline
        Write-Host " | " -ForegroundColor DarkGray -NoNewline
        Write-Host "$resourceType" -ForegroundColor Cyan -NoNewline
        Write-Host " | $requestDate" -ForegroundColor DarkGray
        Write-Host "        Requested by: " -ForegroundColor DarkGray -NoNewline
        Write-Host "$requestedBy" -ForegroundColor Gray
        Write-Host ""
    }
}

function Complete-MAARequest {
    param(
        [string]$RequestId,
        [hashtable]$RequestData
    )
    
    try {
        # Get full request details if not provided
        if (-not $RequestData) {
            $RequestData = Invoke-MgGraphRequest -Uri "https://graph.microsoft.com/beta/deviceManagement/operationApprovalRequests/$RequestId" -Method GET
        }
        
        $payloadId = $RequestData.payloadId
        $payloadType = $RequestData.payloadType
        $addedAssignments = $RequestData.addedAssignments
        
        # addedAssignments is already a JSON array string - use it directly
        $assignmentsJson = if ($addedAssignments -is [string]) { 
            $addedAssignments 
        } else { 
            $addedAssignments | ConvertTo-Json -Depth 10 -Compress
        }
        
        # Determine endpoint and body key based on payload type
        $endpoint = $null
        $bodyKey = $null
        
        if ($payloadType -like "*MobileApp*") {
            # Check if the app is published before attempting to assign
            $appDetails = Invoke-MgGraphRequest -Uri "https://graph.microsoft.com/beta/deviceAppManagement/mobileApps/$payloadId" -Method GET
            if ($appDetails.publishingState -ne "published") {
                $appName = $appDetails.displayName
                if ([string]::IsNullOrWhiteSpace($appName)) { $appName = $payloadId }
                return @{ Success = $false; Error = "App '$appName' is not published (state: $($appDetails.publishingState)). Please wait for the app to finish processing in Intune before completing this request." }
            }
            $endpoint = "https://graph.microsoft.com/beta/deviceAppManagement/mobileApps/$payloadId/assign"
            $bodyKey = "mobileAppAssignments"
        }
        elseif ($payloadType -like "*DeviceHealthScript*" -or $payloadType -like "*Script*") {
            $endpoint = "https://graph.microsoft.com/beta/deviceManagement/deviceHealthScripts/$payloadId/assign"
            $bodyKey = "deviceHealthScriptAssignments"
        }
        elseif ($payloadType -like "*DeviceConfiguration*") {
            $endpoint = "https://graph.microsoft.com/beta/deviceManagement/deviceConfigurations/$payloadId/assign"
            $bodyKey = "assignments"
        }
        else {
            return @{ Success = $false; Error = "Unsupported payload type: $payloadType" }
        }
        
        # Build body with raw JSON to avoid serialization issues
        $body = "{`"$bodyKey`":$assignmentsJson}"
        
        # Execute with approval code header
        $headers = @{ "x-msft-approval-code" = $RequestId }
        
        Invoke-MgGraphRequest -Uri $endpoint -Method POST -Body $body -ContentType "application/json" -Headers $headers | Out-Null
        return @{ Success = $true; Error = $null }
        
    } catch {
        return @{ Success = $false; Error = $_.ErrorDetails.Message }
    }
}

function Cancel-MAARequest {
    param([string]$RequestId)
    
    $endpoint = "https://graph.microsoft.com/beta/deviceManagement/operationApprovalRequests/$RequestId/reject"
    $body = @{ 
        approvalSource = "AdminConsole"
        justification = "Cancelled via MAA Manager" 
    } | ConvertTo-Json
    
    try {
        Invoke-MgGraphRequest -Uri $endpoint -Method POST -Body $body -ContentType "application/json" | Out-Null
        return @{ Success = $true; Error = $null }
    } catch {
        return @{ Success = $false; Error = $_.ErrorDetails.Message }
    }
}

function Show-MainMenu {
    param([int]$RequestCount)
    
    Write-Host "  ACTIONS" -ForegroundColor DarkCyan
    Write-Host ""
    
    if ($RequestCount -gt 0) {
        Write-Host "    [1-$RequestCount] " -ForegroundColor DarkGray -NoNewline
        Write-Host "Select request to manage" -ForegroundColor White
        Write-Host "    [A] " -ForegroundColor DarkGray -NoNewline
        Write-Host "Complete ALL requests" -ForegroundColor White
    }
    Write-Host "    [R] " -ForegroundColor DarkGray -NoNewline
    Write-Host "Refresh list" -ForegroundColor White
    Write-Host "    [Q] " -ForegroundColor DarkGray -NoNewline
    Write-Host "Quit" -ForegroundColor White
    Write-Host ""
}

function Show-RequestActions {
    param([object]$Request)
    
    $displayName = $Request.payloadName
    if ([string]::IsNullOrWhiteSpace($displayName)) { $displayName = $Request.displayName }
    if ([string]::IsNullOrWhiteSpace($displayName)) { $displayName = "Unnamed Request" }
    
    $resourceType = $Request.payloadType
    if ([string]::IsNullOrWhiteSpace($resourceType)) { $resourceType = "-" }
    
    Write-Host ""
    Write-Host "  SELECTED REQUEST" -ForegroundColor DarkCyan
    Write-Host ""
    Write-Host "  $displayName" -ForegroundColor Cyan
    Write-Host "  Type: $resourceType" -ForegroundColor DarkGray
    Write-Host "  ID: $($Request.id)" -ForegroundColor DarkGray
    Write-Host ""
    Write-Host "    [C] " -ForegroundColor DarkGray -NoNewline
    Write-Host "Complete this request" -ForegroundColor Green
    Write-Host "    [X] " -ForegroundColor DarkGray -NoNewline
    Write-Host "Cancel this request" -ForegroundColor Red
    Write-Host "    [B] " -ForegroundColor DarkGray -NoNewline
    Write-Host "Back to list" -ForegroundColor White
    Write-Host ""
}

function Start-MAAManager {
    param([string]$UserEmail)
    
    while ($true) {
        Show-Header -UserEmail $UserEmail
        Write-Host "  Fetching requests..." -ForegroundColor Cyan
        $requests = @(Get-ApprovedMAARequests -UserEmail $UserEmail)
        
        Show-RequestsList -Requests $requests -UserEmail $UserEmail
        Show-MainMenu -RequestCount $requests.Count
        
        $selection = Read-Host "  Select option"
        
        switch -Regex ($selection.ToUpper()) {
            "^Q$" { return }
            "^R$" { continue }
            "^A$" {
                if ($requests.Count -eq 0) {
                    Write-Host ""
                    Write-Host "  No requests to complete." -ForegroundColor Yellow
                    Wait-ForKeyPress
                    continue
                }
                
                Show-Header -UserEmail $UserEmail
                Write-Host "  COMPLETE ALL REQUESTS" -ForegroundColor Green
                Write-Host ""
                Write-Host "  About to complete $($requests.Count) request(s)." -ForegroundColor Yellow
                Write-Host ""
                $confirm = Read-Host "  Confirm? (Y/N)"
                
                if ($confirm.ToUpper() -eq "Y") {
                    Write-Host ""
                    $completed = 0
                    foreach ($req in $requests) {
                        $name = $req.payloadName
                        if ([string]::IsNullOrWhiteSpace($name)) { $name = $req.displayName }
                        if ([string]::IsNullOrWhiteSpace($name)) { $name = "Request" }
                        Write-Host "  Completing: $name... " -ForegroundColor Cyan -NoNewline
                        $result = Complete-MAARequest -RequestId $req.id -RequestData $req
                        if ($result.Success) {
                            Write-Host "Done" -ForegroundColor Green
                            $completed++
                        } else {
                            Write-Host "Failed" -ForegroundColor Red
                            if ($result.Error) {
                                Write-Host "        Error: $($result.Error)" -ForegroundColor DarkRed
                            }
                        }
                        Start-Sleep -Milliseconds 300
                    }
                    Write-Host ""
                    Write-Host "  SUCCESS: " -ForegroundColor Green -NoNewline
                    Write-Host "Completed $completed of $($requests.Count) requests" -ForegroundColor White
                    Wait-ForKeyPress
                }
            }
            "^[0-9]+$" {
                $idx = [int]$selection - 1
                if ($idx -ge 0 -and $idx -lt $requests.Count) {
                    $selectedRequest = $requests[$idx]
                    
                    $inSubmenu = $true
                    while ($inSubmenu) {
                        Show-Header -UserEmail $UserEmail
                        Show-RequestActions -Request $selectedRequest
                        
                        $action = Read-Host "  Select action"
                        
                        switch ($action.ToUpper()) {
                            "C" {
                                Write-Host ""
                                Write-Host "  Completing request... " -ForegroundColor Cyan -NoNewline
                                $result = Complete-MAARequest -RequestId $selectedRequest.id -RequestData $selectedRequest
                                if ($result.Success) {
                                    Write-Host "SUCCESS" -ForegroundColor Green
                                } else {
                                    Write-Host "FAILED" -ForegroundColor Red
                                    if ($result.Error) {
                                        Write-Host ""
                                        Write-Host "  Error: $($result.Error)" -ForegroundColor DarkRed
                                    }
                                }
                                Wait-ForKeyPress
                                $inSubmenu = $false
                            }
                            "X" {
                                Write-Host ""
                                $confirm = Read-Host "  Cancel this request? (Y/N)"
                                if ($confirm.ToUpper() -eq "Y") {
                                    Write-Host "  Cancelling request... " -ForegroundColor Cyan -NoNewline
                                    $result = Cancel-MAARequest -RequestId $selectedRequest.id
                                    if ($result.Success) {
                                        Write-Host "SUCCESS" -ForegroundColor Green
                                    } else {
                                        Write-Host "FAILED" -ForegroundColor Red
                                        if ($result.Error) {
                                            Write-Host ""
                                            Write-Host "  Error: $($result.Error)" -ForegroundColor DarkRed
                                        }
                                    }
                                    Wait-ForKeyPress
                                }
                                $inSubmenu = $false
                            }
                            "B" { $inSubmenu = $false }
                            default {
                                Write-Host "  Invalid option." -ForegroundColor Yellow
                                Start-Sleep -Milliseconds 500
                            }
                        }
                    }
                } else {
                    Write-Host "  Invalid selection." -ForegroundColor Yellow
                    Start-Sleep -Seconds 1
                }
            }
            default {
                if (-not [string]::IsNullOrWhiteSpace($selection)) {
                    Write-Host "  Invalid option." -ForegroundColor Yellow
                    Start-Sleep -Seconds 1
                }
            }
        }
    }
}

#endregion Functions

#region Main Script

Show-Header
Write-Host "  Initializing..." -ForegroundColor DarkGray
Write-Host ""

$context = Connect-ToGraph -TenantId $TenantId

if (-not $context) {
    Write-Host ""
    Write-Host "  ERROR: " -ForegroundColor Red -NoNewline
    Write-Host "Failed to connect to Microsoft Graph." -ForegroundColor White
    exit 1
}

$loggedInUser = $context.Account

if (-not $loggedInUser) {
    Write-Host "  ERROR: " -ForegroundColor Red -NoNewline
    Write-Host "Could not determine logged-in user." -ForegroundColor White
    exit 1
}

Start-Sleep -Milliseconds 500

Start-MAAManager -UserEmail $loggedInUser

Write-Host ""
Write-Host "  Disconnecting..." -ForegroundColor DarkGray
Disconnect-MgGraph -ErrorAction SilentlyContinue | Out-Null
Write-Host "  Goodbye!" -ForegroundColor Green
Write-Host ""

#endregion Main Script
