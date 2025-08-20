<#
.SYNOPSIS
    Exports the members of a specified Active Directory group to a CSV file.
    Automatically handles the installation of the required ActiveDirectory module.

.DESCRIPTION
    This script connects to Active Directory to find a group, retrieves all its members,
    and exports their details to a CSV file.

    If the required 'ActiveDirectory' PowerShell module is not present, the script
    will attempt to install it automatically. This action requires the script to be
    run with Administrator privileges.

.PARAMETER GroupName
    The name of the Active Directory group to query.

.PARAMETER CsvPath
    The full path where the output CSV file will be saved.

.EXAMPLE
    # Run with default group name, will export to Desktop
    .\Get-ADGroupMembersToCsv.ps1

.EXAMPLE
    # Specify group and path. If the AD module is missing, it will prompt for elevation.
    .\Get-ADGroupMembersToCsv.ps1 -GroupName "Domain Admins" -CsvPath "C:\Temp\Admins.csv"

.NOTES
    Author: Gemini
    Version: 2.0 (with automatic dependency installation)
    Date: 12/08/2025
    Requires PowerShell to be run as Administrator if the AD module is not yet installed.
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$GroupName = "GRP LICENSE MICROSOFT365 POWERBI PRO",

    [string]$CsvPath = "$env:USERPROFILE\Desktop\$($GroupName)_Members.csv"
)

# --- Function Definitions ---

function Ensure-ADModuleIsAvailable {
    Write-Verbose "Checking for ActiveDirectory module..."
    # Check if the module is already imported or available.
    if (Get-Module -ListAvailable -Name ActiveDirectory) {
        Write-Verbose "ActiveDirectory module is already available."
        Import-Module ActiveDirectory -ErrorAction SilentlyContinue
        return
    }

    Write-Warning "The 'ActiveDirectory' PowerShell module is not installed."

    # Check for Administrator privileges, which are required for installation.
    $isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    if (-not $isAdmin) {
        throw "Module is missing. Please re-run this script with Administrator privileges ('Run as Administrator') to allow automatic installation."
    }

    Write-Host "Attempting to install the ActiveDirectory module as Administrator..."
    try {
        # Check if the feature is already installed but just not in the module path
        $capability = Get-WindowsCapability -Online -Name "Rsat.ActiveDirectory.DS-LDS.Tools~~~~0.0.1.0" -ErrorAction SilentlyContinue
        if ($capability.State -eq 'Installed') {
            Write-Host "Windows feature was already installed. Importing module directly."
            Import-Module ActiveDirectory -ErrorAction Stop
            return
        }

        Write-Host "Installing RSAT: AD DS Tools... This may take a few minutes."
        Add-WindowsCapability -Online -Name "Rsat.ActiveDirectory.DS-LDS.Tools~~~~0.0.1.0" -ErrorAction Stop
        
        Write-Host "Installation complete. Importing the module for the current session."
        Import-Module ActiveDirectory -ErrorAction Stop
    }
    catch {
        # Catch errors during installation or import
        throw "Failed to install or import the ActiveDirectory module. Error: $($_.Exception.Message)"
    }
}


function Get-ADGroupMembersToCsv {
    try {
        # Step 1: Ensure the necessary module is available or installed.
        Ensure-ADModuleIsAvailable

        # Step 2: Find the specified group in Active Directory.
        Write-Host "Searching for AD group: '$GroupName'..."
        $group = Get-ADGroup -Filter "Name -eq '$GroupName'" -ErrorAction Stop
        Write-Host "Group found successfully."

        # Step 3: Retrieve all members of the group (including from nested groups).
        Write-Host "Retrieving group members..."
        $members = Get-ADGroupMember -Identity $group -Recursive

        if ($null -eq $members) {
            Write-Warning "The group '$GroupName' does not have any members."
            return
        }
        Write-Host "Found $($members.Count) total members. Fetching user details..."

        # Step 4: Get detailed information for each member who is a user.
        $userDetails = $members | Where-Object { $_.objectClass -eq 'user' } | ForEach-Object {
            Get-ADUser -Identity $_ -Properties DisplayName, EmailAddress | Select-Object -Property DisplayName, SamAccountName, EmailAddress
        }

        if ($null -eq $userDetails) {
            Write-Warning "No user objects found in the group membership."
            return
        }

        # Step 5: Export the collected user details to a CSV file.
        Write-Host "Exporting $($userDetails.Count) users to CSV at: $CsvPath"
        $userDetails | Export-Csv -Path $CsvPath -NoTypeInformation -Encoding UTF8

        Write-Host "[SUCCESS] User list has been successfully exported."
        Write-Host "You can open the file at: $CsvPath"

        # Optional: Uncomment the line below to automatically open the CSV file after export.
        # Invoke-Item -Path $CsvPath
    }
    catch {
        # Catch any terminating errors from the try block.
        Write-Error "An unexpected error occurred: $($_.Exception.Message)"
        # Exit with a non-zero status code to indicate failure for automation.
        exit 1
    }
}

# --- Execute the main function ---
Get-ADGroupMembersToCsv
