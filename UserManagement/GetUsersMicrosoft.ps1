Install-Module Microsoft.Graph -Scope CurrentUser

Connect-Graph -Scopes User.Read.All

$users = Get-MgUser -All -Property DisplayName,UserPrincipalName,Mail,AssignedLicenses

function Get-LicenseDetails {
    param (
        [Parameter(Mandatory=$true)]
        [Microsoft.Graph.PowerShell.Models.MicrosoftGraphAssignedLicense[]]$licenses
    )
    $licenseDetails = @()
    foreach ($license in $licenses) {
        $licenseDetails += $license.SkuId
    }
    return -join ", "
}

function Get-PresenceStatus {
    param (
        [Parameter(Mandatory=$true)]
        [string]$userId
    )
    $presence = Invoke-GraphRequest -Method GET -Uri "https://graph.microsoft.com/v1.0/users/$userId/presence"
    return $presence
}

$userDetails = @()
foreach ($user in $users) {
    $presence = Get-PresenceStatus -userId $user.Id
    $userDetails += [PSCustomObject]@{
        DisplayName       = $user.DisplayName
        Mail              = $user.Mail
        UserStatus        = $presence.availability
        Licenses          = Get-LicenseDetails -licenses $user.AssignedLicenses
    }
}

$userDetails | Export-Csv -Path "C:\Users\deraldo.filho\OneDrive\Documentos\Arquivo.csv" -NoTypeInformation