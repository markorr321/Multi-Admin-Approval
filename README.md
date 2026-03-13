# Intune Multi Admin Approval (MAA) Manager

A modern PowerShell TUI tool to manage approved MAA requests in Microsoft Intune. Automatically detects the logged-in user and allows completing or cancelling requests interactively.

## Features

- **Modern TUI** - Clean interface matching GroupManager style
- **Auto-detect logged-in user** - No need to specify email manually
- **Complete or Cancel** - Choose action per request
- **Bulk operations** - Complete all approved requests at once
- **Self-install** - Add to PowerShell profile for easy access
- **Real-time refresh** - Update the list without restarting

## Prerequisites

1. **PowerShell 5.1+** or **PowerShell 7+**
2. **Microsoft.Graph.Authentication module** (auto-installs if missing)
3. **Azure AD permissions:**
   - `DeviceManagementConfiguration.ReadWrite.All`
   - `DeviceManagementRBAC.ReadWrite.All`

## Quick Start

```powershell
cd C:\MAA
.\Complete-MAARequests.ps1
```

## Installation (Optional)

Add to your PowerShell profile for easy access:

```powershell
.\Complete-MAARequests.ps1 -Install
```

Then run from anywhere with:
```powershell
MAAManager
```

## TUI Controls

### Main List View
| Key | Action |
|-----|--------|
| `1-9` | Select request by number |
| `A` | Complete ALL requests |
| `R` | Refresh list |
| `Q` | Quit |

### Action Menu (after selecting a request)
| Key | Action |
|-----|--------|
| `C` | Complete the selected request |
| `X` | Cancel the selected request |
| `B` | Back to list |

## Usage Examples

### Basic (auto-detects user)
```powershell
.\Complete-MAARequests.ps1
```

### With specific tenant
```powershell
.\Complete-MAARequests.ps1 -TenantId "your-tenant-id-here"
```

## Troubleshooting

### "Access Denied" or "Insufficient Privileges"
- Ensure you have the required AAD permissions
- Ask your Global Admin to grant consent for Microsoft Graph PowerShell

### "No approved MAA requests found"
- Verify requests exist in Intune admin center with "Approved" status
- Confirm requests are associated with your account

### Module Installation Issues
```powershell
Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser
Install-Module Microsoft.Graph.Authentication -Force -AllowClobber
```

## Files

| File | Description |
|------|-------------|
| `Complete-MAARequests.ps1` | Main TUI script (recommended) |
| `Complete-MAARequests-REST.ps1` | Alternative using direct REST API |
| `README.md` | This documentation |
