<#
.SYNOPSIS
    Backs up application configuration files.
.DESCRIPTION
    This script automates the backup of specific application configurations to a centralized, timestamped location.
.PARAMETER CaminhoDestinoBackup
    The path where the backups will be saved.
.PARAMETER ListaAplicativos
    (Optional) Path to a text/JSON file with the list of applications and their paths. If not provided, a default list will be used.
.PARAMETER Compactar
    (Switch) If specified, the backups will be compressed into a ZIP file.
.PARAMETER ManterDias
    (Optional) Number of days to keep old backups.
.EXAMPLE
    .\New-AppBackup.ps1 -CaminhoDestinoBackup "C:\Backups" -Compactar -ManterDias 30
#>
param (
    [Parameter(Mandatory=$true)]
    [string]$CaminhoDestinoBackup,

    [string]$ListaAplicativos = "app_config.json",

    [switch]$Compactar,

    [int]$ManterDias
)

#region Functions
function Get-AppConfigPath {
    param (
        [string]$Path
    )
    return $ExecutionContext.InvokeCommand.ExpandString($Path)
}

function Backup-AppConfig {
    param (
        [string]$AppName,
        [string]$SourcePath,
        [string]$DestinationPath,
        [switch]$Compress
    )

    $Timestamp = Get-Date -Format "yyyy-MM-dd_HH-mm-ss"
    $BackupName = "$AppName-$Timestamp"
    $BackupDestination = Join-Path -Path $DestinationPath -ChildPath $BackupName

    if ($Compress) {
        $BackupDestination += ".zip"
        try {
            Compress-Archive -Path $SourcePath -DestinationPath $BackupDestination -ErrorAction Stop
            Write-BackupLog -Message "Successfully created compressed backup for $AppName at $BackupDestination"
        }
        catch {
            Write-BackupLog -Message "Error creating compressed backup for $AppName: ${_}" -Level Error
        }
    }
    else {
        try {
            Copy-Item -Path $SourcePath -Destination $BackupDestination -Recurse -Force -ErrorAction Stop
            Write-BackupLog -Message "Successfully created backup for $AppName at $BackupDestination"
        }
        catch {
            Write-BackupLog -Message "Error creating backup for $AppName: $_" -Level Error
        }
    }
}

function Cleanup-OldBackups {
    param (
        [string]$BackupPath,
        [int]$DaysToKeep
    )

    $CutoffDate = (Get-Date).AddDays(-$DaysToKeep)
    Get-ChildItem -Path $BackupPath | Where-Object { $_.CreationTime -lt $CutoffDate } | ForEach-Object {
        Write-BackupLog -Message "Deleting old backup: $($_.FullName)"
        Remove-Item -Path $_.FullName -Recurse -Force
    }
}

function Write-BackupLog {
    param (
        [string]$Message,
        [string]$Level = "Info"
    )
    $LogMessage = "[{0}] [{1}] {2}" -f (Get-Date -Format "yyyy-MM-dd HH:mm:ss"), $Level, $Message
    Write-Output $LogMessage
}
#endregion

# Create the backup destination directory if it doesn't exist
if (-not (Test-Path -Path $CaminhoDestinoBackup)) {
    New-Item -Path $CaminhoDestinoBackup -ItemType Directory
}

# Read the application list
$AppList = $null
if (Test-Path -Path $ListaAplicativos) {
    try {
        $AppList = (Get-Content -Path $ListaAplicativos | ConvertFrom-Json).apps
    }
    catch {
        Write-BackupLog -Message ("Error reading or parsing the application list file '{0}': {1}" -f $ListaAplicativos, $_) -Level Error
    }
}
else {
    Write-BackupLog -Message "Application list file not found at '$ListaAplicativos'." -Level Error
}

# Backup loop
if ($AppList) {
    foreach ($app in $AppList) {
        $SourcePath = Get-AppConfigPath -Path $app.path
        if (Test-Path -Path $SourcePath) {
            Backup-AppConfig -AppName $app.name -SourcePath $SourcePath -DestinationPath $CaminhoDestinoBackup -Compress:$Compactar
        }
        else {
            Write-BackupLog -Message "Source path not found for $($app.name): $SourcePath" -Level Warning
        }
    }
}

# Cleanup old backups
if ($ManterDias -gt 0) {
    Cleanup-OldBackups -BackupPath $CaminhoDestinoBackup -DaysToKeep $ManterDias
}