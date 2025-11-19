<#
=========================================================================================
Script Name:    DefenderPolicyToggle.ps1
Description:    This script performs the following actions:
                1. Creates a snapshot of original Windows Defender-related registry values.
                2. Exports a full registry backup (.reg file) for manual restoration if needed.
                3. Prompts the user to confirm they have verified the backup file.
                4. Applies changes to disable Windows Defender features as requested.
                5. Waits for 3 minutes.
                6. Reverts all changes back to their original state or removes keys that did not exist.
                If any revert operation fails, the user is instructed to use the exported .reg file.

Author:         Jimmi Aylesworth
Date:           2025-11-19
Warning:        PROCEED WITH CAUTION!
                - This script modifies critical Windows Defender policies.
                - Ensure you have administrative privileges.
                - Improper use may compromise system security.
                - Always verify the backup file before proceeding.
=========================================================================================
#>

# Step 1: Define registry items and new values
$registryItems = @(
    @{ Path = "HKLM\Software\Policies\Microsoft\Windows Defender"; Name = "DisableAntiSpyware"; NewValue = 1 },
    @{ Path = "HKLM\Software\Policies\Microsoft\Windows Defender"; Name = "DisableAntiVirus"; NewValue = 1 },
    @{ Path = "HKLM\Software\Policies\Microsoft\Windows Defender\Real-Time Protection"; Name = "DisableBehaviorMonitoring"; NewValue = 1 },
    @{ Path = "HKLM\Software\Policies\Microsoft\Windows Defender\Real-Time Protection"; Name = "DisableIntrusionPreventionSystem"; NewValue = 1 },
    @{ Path = "HKLM\Software\Policies\Microsoft\Windows Defender\Real-Time Protection"; Name = "DisableIOAVProtection"; NewValue = 1 },
    @{ Path = "HKLM\Software\Policies\Microsoft\Windows Defender\Real-Time Protection"; Name = "DisableOnAccessProtection"; NewValue = 1 },
    @{ Path = "HKLM\Software\Policies\Microsoft\Windows Defender\Real-Time Protection"; Name = "DisableRealtimeMonitoring"; NewValue = 1 },
    @{ Path = "HKLM\Software\Policies\Microsoft\Windows Defender\Real-Time Protection"; Name = "DisableRoutinelyTakingAction"; NewValue = 1 },
    @{ Path = "HKLM\Software\Policies\Microsoft\Windows Defender\Real-Time Protection"; Name = "DisableScanOnRealtimeEnable"; NewValue = 1 },
    @{ Path = "HKLM\Software\Policies\Microsoft\Windows Defender\Real-Time Protection"; Name = "DisableScriptScanning"; NewValue = 1 },
    @{ Path = "HKLM\Software\Policies\Microsoft\Windows Defender\Reporting"; Name = "DisableEnhancedNotifications"; NewValue = 1 },
    @{ Path = "HKLM\Software\Policies\Microsoft\Windows Defender\SpyNet"; Name = "DisableBlockAtFirstSeen"; NewValue = 1 },
    @{ Path = "HKLM\Software\Policies\Microsoft\Windows Defender\SpyNet"; Name = "SpynetReporting"; NewValue = 0 },
    @{ Path = "HKLM\Software\Policies\Microsoft\Windows Defender\MpEngine"; Name = "MpEnablePus"; NewValue = 0 },
    @{ Path = "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender Security Center\App and Browser protection"; Name = "DisallowExploitProtectionOverride"; NewValue = 0 },
    @{ Path = "HKLM\SOFTWARE\Microsoft\Windows Defender\Features"; Name = "TamperProtection"; NewValue = 0 },
    @{ Path = "HKLM\software\microsoft\windows defender\spynet"; Name = "SubmitSamplesConsent"; NewValue = 0 },
    @{ Path = "HKLM\Software\Microsoft\Windows Defender"; Name = "PUAProtection"; NewValue = 0 }
)

# Step 1: Snapshot original values
$originalSnapshot = @()
foreach ($item in $registryItems) {
    $regPath = "Registry::$($item.Path)"
    $name = $item.Name
    try {
        $value = (Get-ItemProperty -Path $regPath -Name $name -ErrorAction Stop).$name
        $originalSnapshot += @{ Path = $item.Path; Name = $name; Value = $value }
    } catch {
        $originalSnapshot += @{ Path = $item.Path; Name = $name; Value = $null }
    }
}
Write-Host "Snapshot of original values taken."

# Step 1a: Export full registry branches to .reg file for backup
$timestamp = (Get-Date).ToString("yyyyMMdd_HHmmss")
$backupFile = "C:\RegistryBackup_WindowsDefender_$timestamp.reg"
Write-Host "Exporting registry backup to $backupFile..."
$pathsToBackup = @(
    "HKLM\Software\Policies\Microsoft\Windows Defender",
    "HKLM\Software\Policies\Microsoft\Windows Defender\Real-Time Protection",
    "HKLM\Software\Policies\Microsoft\Windows Defender\SpyNet",
    "HKLM\Software\Policies\Microsoft\Windows Defender\MpEngine",
    "HKLM\Software\Policies\Microsoft\Windows Defender\Reporting",
    "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender Security Center\App and Browser protection",
    "HKLM\SOFTWARE\Microsoft\Windows Defender"
)
foreach ($path in $pathsToBackup) {
    reg export $path $backupFile /y
}
Write-Host "Backup completed."

# Step 1b: Ask user to confirm backup verification
$confirmation = Read-Host "Have you verified the backup file ($backupFile)? Type YES to continue"
if ($confirmation.ToUpper() -ne "YES") {
    Write-Warning "Backup verification failed. Exiting script."
    exit
}

# Step 2: Apply changes (disable Defender)
foreach ($item in $registryItems) {
    $regPath = "Registry::$($item.Path)"
    New-Item -Path $regPath -Force | Out-Null
    Set-ItemProperty -Path $regPath -Name $item.Name -Value $item.NewValue
    Write-Host "Set $($item.Path)\$($item.Name) to $($item.NewValue)"
}

Write-Host "Changes applied. Waiting for 3 minutes..."
Start-Sleep -Seconds 180

# Step 4: Revert changes with error handling
Write-Host "Reverting to original values..."
foreach ($orig in $originalSnapshot) {
    $regPath = "Registry::$($orig.Path)"
    try {
        if ($orig.Value -eq $null) {
            Remove-ItemProperty -Path $regPath -Name $orig.Name -ErrorAction Stop
            Write-Host "Removed $($orig.Path)\$($orig.Name)"
        } else {
            Set-ItemProperty -Path $regPath -Name $orig.Name -Value $orig.Value -ErrorAction Stop
            Write-Host "Restored $($orig.Path)\$($orig.Name) to $($orig.Value)"
        }
    } catch {
        Write-Warning "Failed to revert $($orig.Path)\$($orig.Name). Please restore manually using backup file: $backupFile"
    }
}

Write-Host "`nProcess completed successfully! If any errors occurred, use the backup file located at: $backupFile"
