# Intune Multi Admin Approval (MAA) Manager

> **Note:** This project is a work in progress. Features and documentation may change.

A modern PowerShell TUI tool to manage Multi Admin Approval requests in Microsoft Intune.

## Why Two Scripts?

The solution is split into two scripts because approving and completing MAA requests are fundamentally different operations with different permission requirements and risk profiles.

**Approving** a request is straightforward — you review what someone wants to do and say yes or no. It's a safe, read-and-respond workflow that most admins need day to day.

**Completing** a request means actually executing the approved change against the Intune backend (creating an app, deleting a policy, reassigning a profile). This requires broader API permissions, involves direct writes to your tenant, and has limitations — notably, the Intune backend restricts Update completions to the portal's own extension app, so only Create, Delete, and Assign completions can be done via the Graph API.

Separating these concerns keeps the common workflow simple and self-contained, while the full version remains available when you need it.

| Script | Purpose | Use When |
|--------|---------|----------|
| **`MAA-Approvals.ps1`** | Review, approve, and deny pending requests | Day-to-day approval workflow (recommended) |
| **`MAA-Manager.ps1`** | Everything above, plus completing approved requests | You need to complete Create, Delete, or Assign operations outside the admin center |

## Features

- **Modern TUI** — Clean terminal interface with pinned control bar and inline actions
- **Browser authentication** — Interactive browser login on every run (no cached tokens)
- **Custom app registration** — Configure and persist your own app registration, or use the default Microsoft Graph client
- **Approve or deny pending requests** — Review and approve/deny requests awaiting your approval
- **Complete approved requests** — (MAA-Manager.ps1 only) Complete Create, Delete, and Assign operations
- **Payload review** — Open request payloads in VS Code or Notepad for detailed inspection
- **Detailed summaries** — View app info, compliance policies, configuration profiles, device actions, scripts, and more
- **Assignment visibility** — See target groups, assignment intent (Required/Available/Uninstall), and filters
- **Bulk operations** — Approve all pending requests at once
- **Auto-detect logged-in user** — No need to specify email manually
- **Self-install** — Add to PowerShell profile for easy access
- **Real-time refresh** — Update request lists without restarting

## Prerequisites

1. **PowerShell 5.1+** or **PowerShell 7+**
2. **Microsoft.Graph.Authentication module** (auto-installs if missing)
3. **Delegated API permissions:**

   Both scripts require:
   - `DeviceManagementConfiguration.ReadWrite.All`
   - `DeviceManagementRBAC.ReadWrite.All`
   - `DeviceManagementManagedDevices.ReadWrite.All`
   - `DeviceManagementApps.ReadWrite.All`
   - `DeviceManagementScripts.ReadWrite.All`

   MAA-Manager.ps1 additionally requires:
   - `DeviceManagementServiceConfig.ReadWrite.All`

## Quick Start

```powershell
# Approval-only (recommended)
.\MAA-Approvals.ps1

# Full version (includes completion workflow)
.\MAA-Manager.ps1
```

This opens a browser for authentication on every run. No tokens are cached between sessions.

## Installation (Optional)

Add to your PowerShell profile for easy access:

```powershell
.\MAA-Manager.ps1 -Install
```

Then run from anywhere with:
```powershell
MAAManager
```

## Custom App Registration

By default, MAA Manager uses the Microsoft Graph PowerShell public client. You can configure a custom app registration instead.

### Persistent Configuration (Recommended)

Save your app registration so it's used automatically on every run:

```powershell
.\MAA-Manager.ps1 -Configure
```

This prompts for your Client ID and Tenant ID, then saves them as user-level environment variables (`MAA_CLIENT_ID`, `MAA_TENANT_ID`).

To remove saved configuration:

```powershell
.\MAA-Manager.ps1 -ClearConfig
```

### One-Time Override

Use a custom app registration for a single session:

```powershell
.\MAA-Manager.ps1 -ClientId "your-app-id" -TenantId "your-tenant-id"
```

### App Registration Requirements

When creating a custom app registration in Entra ID:

| Setting | Value |
|---------|-------|
| Platform | Mobile and desktop applications |
| Redirect URI | `https://login.microsoftonline.com/common/oauth2/nativeclient` |
| Allow public client flows | Yes |
| API permissions (Delegated) | See permissions listed in Prerequisites |

## TUI Controls

### Request List
| Key | Action |
|-----|--------|
| `1-9` | Select request by number |
| `A` | Approve all pending requests |
| `R` | Refresh list |
| `B` | Back |
| `E` | Exit |

### Request Detail
| Key | Action |
|-----|--------|
| `S` | Open payload in VS Code |
| `N` | Open payload in Notepad |
| `A` | Approve the request |
| `D` | Deny the request |
| `B` | Back to list |
| `E` | Exit |

### Global Shortcuts
| Key | Action |
|-----|--------|
| `Ctrl+Q` | Exit from anywhere |
| `Ctrl+E` | Exit from anywhere |

## Usage Examples

### Basic (auto-detects user, browser login)
```powershell
.\MAA-Manager.ps1
```

### With custom app registration (one-time)
```powershell
.\MAA-Manager.ps1 -ClientId "your-app-id" -TenantId "your-tenant-id"
```

### Configure persistent app registration
```powershell
.\MAA-Manager.ps1 -Configure
```

### Debug mode (show raw API responses)
```powershell
.\MAA-Manager.ps1 -ShowRaw
```

## Supported Resource Types

| Intune Resource | Display Name |
|----------------|--------------|
| MobileApp | App |
| ConfigurationPolicy | Settings catalog |
| DeviceConfiguration | Configuration profile |
| DeviceCompliancePolicy | Compliance policy |
| DeviceHealthScript | Remediation script |
| DeviceManagementScript | Platform script |
| GroupPolicyConfiguration | Group policy |
| WindowsAutopilotDeploymentProfile | Autopilot profile |
| DeviceEnrollmentConfiguration | Enrollment config |
| WindowsFeatureUpdateProfile | Feature update |
| WindowsQualityUpdateProfile | Quality update |
| WindowsDriverUpdateProfile | Driver update |
| OperationApprovalPolicy | Approval policy |
| RoleDefinition | Role definition |
| DeviceCategory | Device category |

## Troubleshooting

### "Access Denied" or "Insufficient Privileges"
- Ensure you have the required Azure AD permissions listed above
- Ask your Global Admin to grant consent for Microsoft Graph PowerShell

### "No approved MAA requests found"
- Verify requests exist in Intune admin center with "Approved" status
- Confirm requests are associated with your account

### "Forbidden" when completing a request
- The logged-in account may not have the required Intune role to perform the underlying operation (e.g., assigning apps requires App Manager or Intune Administrator)

### Module Installation Issues
```powershell
Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser
Install-Module Microsoft.Graph.Authentication -Force -AllowClobber
```

## Known Limitations

- **Update completions** — The Intune backend restricts Update completion operations (PUT/PATCH with approval codes) to the Intune portal extension app. Update completions must be done through the Intune admin center. Create, Delete, and Assign completions work from `MAA-Manager.ps1`.

## Files

| File | Description |
|------|-------------|
| `MAA-Approvals.ps1` | Approval-only tool (review, approve, deny) |
| `MAA-Manager.ps1` | Full version with completion workflow |
| `README.md` | This documentation |
