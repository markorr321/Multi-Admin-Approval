# Changelog

## 1.0.0 - 2026-04-05

### Added
- Initial release of Intune-MAA module
- `Start-MAAApproval` - Full-screen terminal UI for reviewing and approving MAA requests
- `Approve-MAARequest` - Approve a single request by ID with justification
- `Cancel-MAARequest` - Deny/reject a request by ID
- `Get-PendingMAARequests` - Retrieve all pending MAA requests
- Payload detail view for all Intune resource types (apps, policies, scripts, devices, roles, etc.)
- Script content viewer with VS Code and Notepad support
- Bulk approve all pending requests
- MSAL browser-based authentication (no WAM dependency)
- Custom app registration support via ClientId/TenantId parameters
- Environment variable config persistence (MAA_CLIENT_ID, MAA_TENANT_ID)
