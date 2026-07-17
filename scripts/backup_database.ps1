$ErrorActionPreference = "Stop"

$ProjectRoot = Split-Path -Parent $PSScriptRoot
$LocalBackupDirectory = Join-Path $ProjectRoot "backups"
$Timestamp = Get-Date -Format "yyyy-MM-dd_HHmmss"
$BackupFileName = "engineer4me_$Timestamp.sql"
$LocalBackupPath = Join-Path $LocalBackupDirectory $BackupFileName

$ContainerName = "engineer4me-postgres"
$DatabaseName = "engineer4me"
$DatabaseUser = "engineer4me"

Write-Host "Starting Engineer4Me database backup..."

if (-not (Test-Path $LocalBackupDirectory)) {
    New-Item `
        -ItemType Directory `
        -Path $LocalBackupDirectory `
        -Force | Out-Null
}

$ContainerRunning = docker inspect `
    -f "{{.State.Running}}" `
    $ContainerName 2>$null

if ($ContainerRunning -ne "true") {
    throw "PostgreSQL container '$ContainerName' is not running."
}

docker exec $ContainerName `
    pg_dump `
    -U $DatabaseUser `
    -d $DatabaseName `
    --clean `
    --if-exists `
    --no-owner `
    --no-privileges |
    Out-File `
        -FilePath $LocalBackupPath `
        -Encoding utf8

if (-not (Test-Path $LocalBackupPath)) {
    throw "The database backup file was not created."
}

$BackupFile = Get-Item $LocalBackupPath

if ($BackupFile.Length -eq 0) {
    Remove-Item $LocalBackupPath -Force
    throw "The database backup file is empty."
}

$BackupHeader = Get-Content `
    -Path $LocalBackupPath `
    -TotalCount 10 |
    Out-String

if ($BackupHeader -notmatch "PostgreSQL database dump") {
    throw "The backup file does not appear to be a valid PostgreSQL SQL dump."
}

$OneDriveRoot = $env:OneDrive

if (-not $OneDriveRoot) {
    $OneDriveRoot = $env:OneDriveCommercial
}

if ($OneDriveRoot) {
    $CloudBackupDirectory = Join-Path `
        $OneDriveRoot `
        "Engineer4Me\DatabaseBackups"

    if (-not (Test-Path $CloudBackupDirectory)) {
        New-Item `
            -ItemType Directory `
            -Path $CloudBackupDirectory `
            -Force | Out-Null
    }

    $CloudBackupPath = Join-Path `
        $CloudBackupDirectory `
        $BackupFileName

    Copy-Item `
        -Path $LocalBackupPath `
        -Destination $CloudBackupPath `
        -Force

    Write-Host "Cloud copy created:"
    Write-Host $CloudBackupPath
}
else {
    Write-Warning "OneDrive was not detected. The local backup was still created."
}

$RetentionDate = (Get-Date).AddDays(-30)

Get-ChildItem `
    -Path $LocalBackupDirectory `
    -Filter "engineer4me_*.sql" |
    Where-Object {
        $_.LastWriteTime -lt $RetentionDate
    } |
    Remove-Item -Force

Write-Host ""
Write-Host "Backup completed successfully."
Write-Host "Local backup:"
Write-Host $LocalBackupPath
Write-Host "Size: $([math]::Round($BackupFile.Length / 1KB, 2)) KB"