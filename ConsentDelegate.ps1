<#
.SYNOPSIS

.DESCRIPTION

.PARAMETER customerTenantId
GUID property

.NOTES
Created by   : Roel van der Wegen
Date Coded   : August 20223
More info    : https://github.com/OfficeGrip/to-do
#>

Param(
    # TenantId of specific customer
    [Parameter(Mandatory=$false)]
    [GUID]$customerTenantId
)

$CSPtenant = "CSP Tenant ID Goes here"
$applicationID = "SAM APP ID Goes here"
$ApplicationSecret = "SAM APP Secret Goes here"
$RefreshToken = "Refresh Token Goes here"
$AppId = 'Single Sign On App ID goes here' # This is the app you want to consent in your customer tenants


# in 7.2 the progress on Invoke-WebRequest is returned to the runbook log output
$ProgressPreference = 'SilentlyContinue'

#region ############################## Functions ####################################

function Get-MicrosoftToken {
    Param(
        # Tenant Id
        [Parameter(Mandatory=$false)]
        [guid]$TenantId,

        # Scope
        [Parameter(Mandatory=$false)]
        [string]$Scope = 'https://graph.microsoft.com/.default',

        # ApplicationID
        [Parameter(Mandatory=$true)]
        [guid]$ApplicationID,

        # ApplicationSecret
        [Parameter(Mandatory=$true)]
        [string]$ApplicationSecret,

        # RefreshToken
        [Parameter(Mandatory=$true)]
        [string]$RefreshToken
    )

    if ($TenantId) {
        $Uri = "https://login.microsoftonline.com/$TenantId/oauth2/v2.0/token"
    }
    else {
        $Uri = "https://login.microsoftonline.com/common/oauth2/v2.0/token"
    }

    # Define the parameters for the token request
    $Body = @{
        client_id       = $ApplicationID
        client_secret   = $ApplicationSecret
        scope           = $Scope
        refresh_token   = $RefreshToken
        grant_type      = 'refresh_token'
    }

    $Params = @{
        Uri = $Uri
        Method = 'POST'
        Body = $Body
        ContentType = 'application/x-www-form-urlencoded'
        UseBasicParsing = $true
    }

    try {
        $AuthResponse = (Invoke-WebRequest @Params).Content | ConvertFrom-Json
    } catch {
        throw "Authentication Error Occured $_"
    }

    return $AuthResponse
}

#endregion

$commonTokenSplat = @{
    ApplicationID = $ApplicationID
    ApplicationSecret = $ApplicationSecret
    RefreshToken = $RefreshToken
}



try {
    if ($ogtoken = (Get-MicrosoftToken @commonTokenSplat -TenantID $CSPtenant -Scope "https://graph.microsoft.com/.default").Access_Token) {
        $ogheader = @{
            Authorization = 'bearer {0}' -f $ogtoken
            Accept        = "application/json"
        }
    }

    if ($customertenantid) {
        $uri = 'https://graph.microsoft.com/v1.0/contracts?$filter=customerId eq ' + $customertenantid
        $tenants = (Invoke-RestMethod -Method GET -headers $ogheader -Uri $uri).value
    } else {
        $tenants = (Invoke-RestMethod -Method GET -headers $ogheader -Uri 'https://graph.microsoft.com/beta/contracts?$top=999').value
    }

} catch {
    throw "Failed to authenticate to CSP tenant: $($_.Exception.Message)"
}

try {
    $AppDetails = (Invoke-RestMethod -Method GET -Uri "https://graph.microsoft.com/beta/applications(appId='$AppId')" -headers $ogheader)
} catch {
    throw "Failed to retrieve application details: $($_.Exception.Message)"
}
#endregion

#region ############################## Loop through tenants ####################################

foreach ($tenant in $tenants) {
    Write-Output "Processing tenant: $($Tenant.defaultDomainName) | $($tenant.customerId)"
    try {
        try {
            if ($token = (Get-MicrosoftToken @commonTokenSplat -TenantID $($tenant.customerId) -Scope "https://graph.microsoft.com/.default").Access_Token) {
                $header = @{
                    Authorization = 'bearer {0}' -f $token
                    Accept        = "application/json"
                }
            }
        } catch {
            throw "Failed to authenticate to $($tenant.defaultDomainName): $($_.Exception.Message)"
        }

        try {
            # Check if there is a service principal for the app, if not create it
            if (!($svcPrincipal = (Invoke-RestMethod -Method "GET" -Headers $header -Uri "https://graph.microsoft.com/v1.0/servicePrincipals?`$filter=appId eq '$($AppDetails.appId)'").value)) {
                # Define values for the new svcPrincipal
                $newsvcPrincipalBody = @{
                    appId = $AppDetails.appId
                } | ConvertTo-Json

                # Create the svcPrincipal
                if ($svcPrincipal = (Invoke-RestMethod -Method "POST" -Headers $header -Uri 'https://graph.microsoft.com/v1.0/servicePrincipals' -Body $newsvcPrincipalBody -ContentType "application/json")) {
                    #Write-Output "svcPrincipal id $($svcPrincipal.id) was created"
                } else {
                    throw "Failed to find or create service principal in tenant: $($_.Exception.Message)"
                }
            } else {
                $existingPermissions = (Invoke-RestMethod -Method GET -Headers $header -Uri "https://graph.microsoft.com/beta/servicePrincipals(appId='$($AppDetails.appId)')/oauth2PermissionGrants").value
            }
        } catch {
            throw "$($_.Exception.Message)"
        }

        <#
        # Cleanup APIs that are no longer on the multitenant app
        try {
            $existingPermissions | Where-Object {  }
            $null = Invoke-RestMethod -Method PATCH -Headers $header -Uri "https://graph.microsoft.com/v1.0/oauth2PermissionGrants/$($existingPermissionsForAPI.id)" -Body $NewMgServicePrincipalOauth2AssignmentSplat -ContentType "application/Json"
        } catch {
            Write-Error "Failed to remove permissions for $($ResourceApp.ResourceAppId) in tenant $($tenant.defaultDomainName): $($_.Exception.Message)"  
        } #>

        # Consent Delegated permissions
        foreach ($ResourceApp in ($AppDetails.requiredResourceAccess | Where-Object { $_.resourceAppId -notmatch "fa3d9a0c-3fb0-42cc-9193-47c7ecd2edbd|4990cffe-04e8-4e8b-808a-1175604b879f" } )) {

            try {
                # Get the ID, dispplayName and permission informating for this ResourceApp (eg Graph, Exchange, etc)
                $APIdata = (Invoke-RestMethod -Method GET -Headers $header -Uri "https://graph.microsoft.com/v1.0/servicePrincipals?`$filter=appId eq '$($ResourceApp.ResourceAppId)'&`$select=id,displayName,oauth2PermissionScopes").value
            } catch {
                throw "Failed to retrieve service principal for $($ResourceApp.ResourceAppId), tenant may not be licensed : $($_.Exception.Message)"
            }

            # Build the bulk consent
            $NewMgServicePrincipalOauth2AssignmentSplat = @{
                clientId = $($svcPrincipal.id) # id of the multitenant applications service principal
                consentType = "AllPrincipals"
                principalId = $null
                resourceId = $APIdata.id # id of the API service principal (i.e. Graph)
                scope = ($APIdata.oauth2PermissionScopes | Where-Object { $_.id -in $ResourceApp.resourceAccess.id }).value -join " " # Translated permission name from id to eg User.ReadWrite.All
            } | ConvertTo-Json

            # Check for existing consents
            $existingPermissionsForAPI = $existingPermissions | Where-Object { $_.resourceId -eq $APIdata.id }

            try {
                if ($existingPermissionsForAPI) {
                    #Write-Warning "Updating $($APIdata.displayName)"
                    $null = Invoke-RestMethod -Method PATCH -Headers $header -Uri "https://graph.microsoft.com/v1.0/oauth2PermissionGrants/$($existingPermissionsForAPI.id)" -Body $NewMgServicePrincipalOauth2AssignmentSplat -ContentType "application/Json"
                } else {
                    #Write-Warning "Consenting $($APIdata.displayName)"
                    $null = Invoke-RestMethod -Method POST -Headers $header -Uri "https://graph.microsoft.com/v1.0/oauth2PermissionGrants" -Body $NewMgServicePrincipalOauth2AssignmentSplat -ContentType "application/Json"
                }
            } catch {
                Write-Error "Failed to consent permissions for $($ResourceApp.ResourceAppId) in tenant $($tenant.defaultDomainName): $($_.Exception.Message)"
            }
        }
    } catch {
        Write-Error "$($tenant.defaultDomainName) on line $($_.InvocationInfo.ScriptLineNumber) | $($_.Exception.Message)"
    }
}
#endregion

Write-Output "End of run"
