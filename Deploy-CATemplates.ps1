#Requires -Version 7.0

function New-ConditionalAccessPolicy {
    [CmdletBinding()]
    param (
        [string]$PolicyJson
    )

    Begin {
        $GraphApiUrl = "https://graph.microsoft.com/beta/identity/conditionalAccess/policies"
        $Scopes = @("Policy.ReadWrite.ConditionalAccess","Policy.Read.All")

        # Get OAuth 2.0 token
        ForEach ($Scope in $Scopes) {
            If ( (Get-MgContext).Scopes -notcontains $Scope ) {
                Connect-MgGraph -Scopes $Scope
            }
        }
    }

    Process {
        If (Test-Json $PolicyJson) {
            # Create the new conditional access policy
            $response = Invoke-MgGraphRequest -Method POST -Uri $GraphApiUrl -Body $PolicyJson -ContentType "application/json"

            # Return the response
            Return $response
        }
        Else {
            Write-Error "The policy JSON is not valid."
        }
    }
}

function New-NamedLocation {
    [CmdletBinding()]
    param (
        [string]$LocationJson
    )

    Begin {
        $GraphApiUrl = "https://graph.microsoft.com/beta/identity/conditionalAccess/namedLocations"
        $Scopes = @("Policy.ReadWrite.ConditionalAccess","Policy.Read.All")


        # Get OAuth 2.0 token
        ForEach ($Scope in $Scopes) {
            If ( (Get-MgContext).Scopes -notcontains $Scope ) {
                Connect-MgGraph -Scopes $Scope
            }
        }
    }

    Process {

        If (Test-Json $LocationJson) {
            # Create the named location
            $response = Invoke-MgGraphRequest -Method POST -Uri $GraphApiUrl -Body $LocationJson -ContentType "application/json"

            # Return the response
            Return $response
        }
        Else {
            Write-Error "The location JSON is not valid."
        }
    }
}

function New-AuthenticationStrength {
    [CmdletBinding()]
    param (
        [string]$AuthStrengthJson
    )

    Begin {
        $GraphApiUrl = "https://graph.microsoft.com/beta/policies/authenticationStrengthPolicies"
        $Scopes = @("Policy.ReadWrite.ConditionalAccess","Policy.Read.All")

        # Get OAuth 2.0 token
        ForEach ($Scope in $Scopes) {
            If ( (Get-MgContext).Scopes -notcontains $Scope ) {
                Connect-MgGraph -Scopes $Scope
            }
        }
    }

    Process {

        If (Test-Json $AuthStrengthJson) {
            # Create the custom authentication strength
            $response = Invoke-MgGraphRequest -Method POST -Uri $GraphApiUrl -Body $AuthStrengthJson -ContentType "application/json"

            # Return the response
            return $response
        }
        Else {
            Write-Error "The authentication strength JSON is not valid."
        }
    }
}

function Deploy-AuthenticationStrength {
    [CmdletBinding()]
    param(
        [string]$AuthStrengthJson,
        [string]$AuthStrengthId,
        [string]$PolicyId
    )

    Begin {
        $GraphApiUrl = "https://graph.microsoft.com/beta/identity/conditionalAccess/policies/$PolicyId"
        $Scopes = @("Policy.ReadWrite.ConditionalAccess","Policy.Read.All")

        # Get OAuth 2.0 token
        ForEach ($Scope in $Scopes) {
            If ( (Get-MgContext).Scopes -notcontains $Scope ) {
                Connect-MgGraph -Scopes $Scope
            }
        }
    }

    Process {
        If (Test-Json $AuthStrengthJson) {
            $AuthStrengthJson = $AuthStrengthJson -replace "policies\(''\)", "policies('$PolicyId')"
            $AuthStrengthJson = $AuthStrengthJson -replace "authStrengthId", "$AuthStrengthId"

            # Update conditional access policies to use the custom authentication strength
            $response = Invoke-MgGraphRequest -Method PATCH -Uri $GraphApiUrl -Body $AuthStrengthJson -ContentType "application/json"
            
            # Return the response
            return $response
        }
        Else {
            Write-Error "The authentication strength JSON is not valid."
        }
    }
}

function New-CAGroup {
    [CmdletBinding()]
    param (
        [string]$GroupJson
    )

    Begin {
        $GraphApiUrl = "https://graph.microsoft.com/beta/groups"
        $Scopes = @("Group.ReadWrite.All")

        # Get OAuth 2.0 token
        ForEach ($Scope in $Scopes) {
            If ( (Get-MgContext).Scopes -notcontains $Scope ) {
                Connect-MgGraph -Scopes $Scope
            }
        }
    }

    Process {
        If (Test-Json $GroupJson) {
            # Create the group
            $response = Invoke-MgGraphRequest -Method POST -Uri $GraphApiUrl -Body $GroupJson -ContentType "application/json"
            
            # Return the response
            Return $response
        }
        Else {
            Write-Error "The policy JSON is not valid."
        }
    }
}

# Confirm that Microsoft.Graph.Authentication module is installed
# If it is, import it; if it is not, install it and then import it.

If (-not (Get-Module -Name "Microsoft.Graph.Authentication" -ListAvailable -ErrorAction SilentlyContinue)) {
    Install-Module -Name "Microsoft.Graph.Authentication" -Scope CurrentUser -Repository PSGallery -Force
}

If (-not (Get-Module -Name "Microsoft.Graph.Authentication")) {
    Try {
        Import-Module -Name "Microsoft.Graph.Authentication"
    }
    Catch {
        Write-Error "The Microsoft.Graph.Authentication module could not be imported."
        Exit 1
    }
}

# Script to deploy templates
# Connect to Microsoft Graph

$Scopes = @("Policy.ReadWrite.ConditionalAccess","Policy.Read.All","Group.ReadWrite.All")
Connect-MgGraph -Scopes $Scopes -ErrorAction Stop

# Create the Authentication Strength
$AuthStrengthResponse = New-AuthenticationStrength -AuthStrengthJson (Get-Content -Path "./AuthenticationStrengths/AuthStrength.json" -Raw)

# Create the Named Location
$NamedLocationResponse = New-NamedLocation -LocationJson (Get-Content -Path "./NamedLocations/NamedLocationUSA.json" -Raw)

# Create the 'CA - MFA - Trusted Locations Only' security group
$GroupTrustedLocationsOnlyResponse = New-CAGroup -GroupJson (Get-Content -Path "./Groups/CA-MFA-TrustedLocationsOnly.json" -Raw)

# Create the 'CA - Geo - Geolocation Exclusions' security group
$GroupGeolocationExclusionsResponse = New-CAGroup -GroupJson (Get-Content -Path "./Groups/CA-Geo-GeolocationExclusions.json" -Raw)

# Create the Conditional Access policies
$CAPolicyJsons = Get-ChildItem -Path "./Policies"

ForEach ($CAPolicyJson in $CAPolicyJsons) {

    <# Grab content of each JSON file and replace the authentication strength ID
    with the custom authentication strength we just created, if applicable #>
    $CAPolicy = Get-Content $CAPolicyJson -Raw | ConvertFrom-Json -Depth 10

    $ApplyAuthenticationStrength = $False

    <# Determine if the policy needs to be updated to use the custom authentication 
    strength, rather than the built-in MFA control.
    
    Custom authentication strengths need to be set after policy creation. #>
    If ($CAPolicy.grantControls.builtInControls -contains "mfa") {
        $ApplyAuthenticationStrength = $True
        $CAPolicy.conditions.users.excludeGroups = @($GroupTrustedLocationsOnlyResponse.Id)
    }

    If ($CAPolicy.displayName -eq "MFA - Sign-In From Trusted Locations Only") {
        $CAPolicy.conditions.users.includeGroups = @($GroupTrustedLocationsOnlyResponse.Id)
    }

    <# Grab content of the JSON for geolocation and replace the excludedLocations
    with the ID of the United States named location #>
    If ($CAPolicy.displayName -eq "Geo - Block Sign-In Outside USA") {
        $CAPolicy.conditions.locations.excludeLocations = @($NamedLocationResponse.Id)
        $CAPolicy.conditions.users.excludeGroups = @($GroupGeolocationExclusionsResponse.Id)
    }

    # Convert all policies back to JSON files and create the policies
    $CAPolicy = $CAPolicy | ConvertTo-Json -Depth 10

    $PolicyResponse = New-ConditionalAccessPolicy -PolicyJson $CAPolicy

    If ($ApplyAuthenticationStrength) {
        $PolicyResponse = Deploy-AuthenticationStrength `
            -AuthStrengthJson (Get-Content -Path "./AuthenticationStrengths/AuthStrengthTemplate.json" -Raw) `
            -AuthStrengthId $AuthStrengthResponse.Id `
            -PolicyId $PolicyResponse.Id
    }
}

Write-Output "Exiting..."
Disconnect-MgGraph
