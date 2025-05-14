
<#
.SYNOPSIS
    Deploys full baseline Conditional Access policies for Zero Trust using Microsoft Graph API via PowerShell.
.DESCRIPTION
    Designed to be cloned and run directly from GitHub using Azure PowerShell.
    Includes CA000 to CA600 series policies for Identity and Endpoint Zero Trust pillars.
.NOTES
    Requires Microsoft.Graph PowerShell SDK
    Execute in Azure Cloud Shell or local PowerShell (7+) with appropriate permissions
#>

# Import required modules
Import-Module Microsoft.Graph.Identity.SignIns -ErrorAction Stop
Import-Module Microsoft.Graph.Authentication -ErrorAction Stop

# Connect to Microsoft Graph
Write-Host "🔐 Connecting to Microsoft Graph..." -ForegroundColor Cyan
Connect-MgGraph -Scopes "Policy.ReadWrite.ConditionalAccess"

function Create-Policy {
    param (
        [string]$Name,
        [string]$State,
        [hashtable]$Conditions,
        [hashtable]$Grants,
        [hashtable]$Users
    )

    $body = @{
        displayName = $Name
        state = $State
        conditions = $Conditions
        grantControls = $Grants
        assignments = @{
            users = $Users
        }
    }

    try {
        $null = New-MgConditionalAccessPolicy -BodyParameter $body
        Write-Host "[+] Created policy: $Name" -ForegroundColor Green
    } catch {
        Write-Host "[!] Failed to create policy: $Name" -ForegroundColor Red
        Write-Host $_.Exception.Message -ForegroundColor DarkRed
    }
}

# Baseline Conditional Access Policies
$Policies = @(
    # CA000 - Block Legacy Auth
    @{
        Name = "CA000-Block-AttackSurfaceReduction-Global-AllApps-LegacyAuth"
        State = "enabled"
        Users = @{ includeUsers = @("All"); excludeUsers = @("admin@M365x20552510.onmicrosoft.com", "Blackhole_3000@M365x20552510.onmicrosoft.com", "Venusknows33#@M365x20552510.onmicrosoft.com") }
        Conditions = @{
            clientAppTypes = @("legacyAuthenticationClient")
            applications = @{ includeApplications = @("All") }
        }
        Grants = @{ operator = "OR"; builtInControls = @("block") }
    },

    # CA100 - MFA for Admins
    @{
        Name = "CA100-MFA-IdentityProtection-Admin-AllApps-AnyPlatform"
        State = "enabled"
        Users = @{
            includeRoles = @("62e90394-69f5-4237-9190-012177145e10", "194ae4cb-b126-40b2-bd5b-6091b380977d")  # Global & Security Admin
            excludeUsers = @("admin@M365x20552510.onmicrosoft.com", "Blackhole_3000@M365x20552510.onmicrosoft.com", "Venusknows33#@M365x20552510.onmicrosoft.com")
        }
        Conditions = @{
            applications = @{ includeApplications = @("All") }
            clientAppTypes = @("all")
            locations = @{ includeLocations = @("All") }
            platforms = @{ includePlatforms = @("all") }
        }
        Grants = @{ operator = "OR"; builtInControls = @("mfa") }
    },

    # CA101 - Block risky sign-in for admins
    @{
        Name = "CA101-MFA-IdentityProtection-Admin-AllApps-RiskySignIn"
        State = "enabled"
        Users = @{ includeRoles = @("62e90394-69f5-4237-9190-012177145e10") }
        Conditions = @{
            signInRiskLevels = @("high")
            applications = @{ includeApplications = @("All") }
        }
        Grants = @{ operator = "OR"; builtInControls = @("block") }
    },

    # CA001 - Block high risk users
    @{
        Name = "CA001-MFA-IdentityProtection-Global-AllApps-HighRiskUsers"
        State = "enabled"
        Users = @{ includeUsers = @("All"); excludeUsers = @("admin@M365x20552510.onmicrosoft.com", "Blackhole_3000@M365x20552510.onmicrosoft.com", "Venusknows33#@M365x20552510.onmicrosoft.com") }
        Conditions = @{
            userRiskLevels = @("high")
            applications = @{ includeApplications = @("All") }
        }
        Grants = @{ operator = "OR"; builtInControls = @("block") }
    },

    # CA500 - MFA Global
    @{
        Name = "CA500-MFA-IdentityProtection-Global-AllApps-AnyPlatform"
        State = "enabled"
        Users = @{ includeUsers = @("All"); excludeUsers = @("admin@M365x20552510.onmicrosoft.com", "Blackhole_3000@M365x20552510.onmicrosoft.com", "Venusknows33#@M365x20552510.onmicrosoft.com") }
        Conditions = @{
            applications = @{ includeApplications = @("All") }
            clientAppTypes = @("all")
            platforms = @{ includePlatforms = @("all") }
            locations = @{ includeLocations = @("All") }
        }
        Grants = @{ operator = "OR"; builtInControls = @("mfa") }
    },

    # CA501 - MFA for O365
    @{
        Name = "CA501-MFA-AppProtection-Global-O365-AnyPlatform"
        State = "enabled"
        Users = @{ includeUsers = @("All"); excludeUsers = @("admin@M365x20552510.onmicrosoft.com", "Blackhole_3000@M365x20552510.onmicrosoft.com", "Venusknows33#@M365x20552510.onmicrosoft.com") }
        Conditions = @{
            applications = @{ includeApplications = @("Office365") }
            platforms = @{ includePlatforms = @("all") }
        }
        Grants = @{ operator = "OR"; builtInControls = @("mfa") }
    },

    # CA502 - Trusted Location MFA bypass
    @{
        Name = "CA502-MFA-IdentityProtection-Global-AllApps-TrustedLocation"
        State = "enabled"
        Users = @{ includeUsers = @("All"); excludeUsers = @("admin@yourorg.com") }
        Conditions = @{
            applications = @{ includeApplications = @("All") }
            locations = @{ includeLocations = @("trustedLocationId") }
        }
        Grants = @{ operator = "OR"; builtInControls = @("mfa") }
    },

    # CA503 - Require compliant devices
    @{
        Name = "CA503-Require-DeviceCompliance-Global-AllApps-AnyPlatform"
        State = "enabled"
        Users = @{ includeUsers = @("All"); excludeUsers = @("admin@M365x20552510.onmicrosoft.com", "Blackhole_3000@M365x20552510.onmicrosoft.com", "Venusknows33#@M365x20552510.onmicrosoft.com") }
        Conditions = @{
            applications = @{ includeApplications = @("All") }
            platforms = @{ includePlatforms = @("all") }
        }
        Grants = @{ operator = "OR"; builtInControls = @("compliantDevice") }
    },

    # CA504 - Require device enrollment
    @{
        Name = "CA504-Require-DeviceEnrollment-Global-AllApps-AnyPlatform"
        State = "enabled"
        Users = @{ includeUsers = @("All"); excludeUsers = @("admin@M365x20552510.onmicrosoft.com", "Blackhole_3000@M365x20552510.onmicrosoft.com", "Venusknows33#@M365x20552510.onmicrosoft.com") }
        Conditions = @{
            applications = @{ includeApplications = @("All") }
            platforms = @{ includePlatforms = @("all") }
        }
        Grants = @{ operator = "OR"; builtInControls = @("compliantDevice") }
    },

    # CA505 - App protection on managed devices (O365)
    @{
        Name = "CA505-Allow-AppProtection-Global-O365-ManagedDevices"
        State = "enabled"
        Users = @{ includeUsers = @("All"); excludeUsers = @("admin@M365x20552510.onmicrosoft.com", "Blackhole_3000@M365x20552510.onmicrosoft.com", "Venusknows33#@M365x20552510.onmicrosoft.com") }
        Conditions = @{
            applications = @{ includeApplications = @("Office365") }
            platforms = @{ includePlatforms = @("iOS", "android") }
        }
        Grants = @{ operator = "OR"; builtInControls = @("approvedApplication") }
    },

    # CA002 - Block unmanaged devices
    @{
        Name = "CA002-Block-AttackSurfaceReduction-Global-AllApps-UnmanagedDevices"
        State = "enabled"
        Users = @{ includeUsers = @("All"); excludeUsers = @("admin@M365x20552510.onmicrosoft.com", "Blackhole_3000@M365x20552510.onmicrosoft.com", "Venusknows33#@M365x20552510.onmicrosoft.com") }
        Conditions = @{
            applications = @{ includeApplications = @("All") }
            deviceStates = @{ includeDeviceStates = @("unknown") }
        }
        Grants = @{ operator = "OR"; builtInControls = @("block") }
    }
)

# Execute deployment
foreach ($policy in $Policies) {
    Create-Policy -Name $policy.Name -State $policy.State `
        -Conditions $policy.Conditions -Grants $policy.Grants -Users $policy.Users
}

Write-Host "`n✅ All policies processed." -ForegroundColor Cyan

