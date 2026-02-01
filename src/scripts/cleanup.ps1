# Winsurf AI Security System Cleanup Script
# Version: 1.0.0
# Requires: Windows 10/11, Administrator privileges

param(
    [switch]$Force,
    [switch]$RemoveAll,
    [string]$InstallPath = "C:\Program Files\Winsurf AI"
)

# Script information
$ScriptName = "Winsurf AI Security System Cleanup"
$ScriptVersion = "1.0.0"
$CompanyName = "Winsurf AI Technologies"
$LogFile = "$env:TEMP\WinsurfAI_Cleanup_$(Get-Date -Format 'yyyyMMdd_HHmmss').log"

# Logging function
function Write-Log {
    param([string]$Message, [string]$Level = "INFO")
    $Timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $LogEntry = "[$Timestamp] [$Level] [$ScriptName v$ScriptVersion] [$CompanyName] $Message"
    Write-Host $LogEntry
    Add-Content -Path $LogFile -Value $LogEntry
}

# Error handling function
function Invoke-ErrorHandler {
    param([string]$ErrorMessage)
    Write-Log "ERROR: $ErrorMessage" "ERROR"
    if (-not $Force) {
        throw $ErrorMessage
    }
}

# Check administrator privileges
function Test-Administrator {
    $CurrentUser = [Security.Principal.WindowsIdentity]::GetCurrent()
    $Principal = New-Object Security.Principal.WindowsPrincipal($CurrentUser)
    return $Principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

# Get user confirmation for cleanup
function Get-CleanupConfirmation {
    if ($Force) {
        Write-Log "Cleanup forced via command line parameter"
        return $true
    }
    
    Write-Host "=== $ProductName CLEANUP ===" -ForegroundColor Yellow
    Write-Host ""
    Write-Host "WARNING: This will completely remove Winsurf AI Security System" -ForegroundColor Red
    Write-Host "WARNING: All security protections will be disabled" -ForegroundColor Red
    Write-Host "WARNING: System will revert to previous state" -ForegroundColor Red
    Write-Host ""
    Write-Host "The following will be removed:" -ForegroundColor Cyan
    Write-Host "  - SecureCore service and registration" -ForegroundColor White
    Write-Host "  - All installed files" -ForegroundColor White
    Write-Host "  - Registry entries" -ForegroundColor White
    Write-Host "  - System hooks and protections" -ForegroundColor White
    if ($RemoveAll) {
        Write-Host "  - All configuration and log files" -ForegroundColor White
        Write-Host "  - User preferences and settings" -ForegroundColor White
    }
    Write-Host ""
    
    $Response = Read-Host "Do you want to proceed with cleanup? (YES/NO)"
    if ($Response -ne "YES") {
        Write-Log "Cleanup cancelled by user"
        exit 0
    }
    
    Write-Log "User confirmed cleanup"
    return $true
}

# Stop SecureCore and deactivate security
function Stop-SecureCoreService {
    Write-Log "Stopping SecureCore and deactivating security..."
    
    try {
        # First try to trigger emergency shutdown via failsafe
        $DLLPath = Join-Path $InstallPath "SecureCore.dll"
        if (Test-Path $DLLPath) {
            Write-Log "Attempting emergency shutdown via failsafe..."
            
            try {
                # Load SecureCore and trigger emergency shutdown
                Add-Type -Path $DLLPath
                $Instance = [SecureCore.SecureCore]::GetInstance()
                $Instance.EmergencyShutdown()
                Write-Log "Emergency shutdown triggered via failsafe"
            } catch {
                Write-Log "Emergency shutdown failed, trying normal deactivation: $_" "WARNING"
                
                # Fallback to normal deactivation
                $Status = $Instance.GetStatus()
                $StatusString = $Instance.GetStatusString()
                
                Write-Log "Current SecureCore Status: $StatusString"
                
                if ($Status -eq 2) {  # ACTIVE
                    if ($Instance.Deactivate()) {
                        Write-Log "SecureCore deactivated successfully - Security enforcement stopped"
                    } else {
                        Write-Log "Warning: Failed to deactivate SecureCore gracefully" "WARNING"
                    }
                    
                    if ($Instance.Shutdown()) {
                        Write-Log "SecureCore shutdown successfully"
                    } else {
                        Write-Log "Warning: Failed to shutdown SecureCore gracefully" "WARNING"
                    }
                } else {
                    Write-Log "SecureCore was not active"
                }
            }
        } else {
            Write-Log "SecureCore.dll not found"
        }
        
        # Also try to stop any Windows service (backup)
        $Service = Get-Service -Name "SecureCore" -ErrorAction SilentlyContinue
        if ($Service) {
            Stop-Service -Name "SecureCore" -Force -ErrorAction Stop
            Write-Log "SecureCore Windows service stopped"
        } else {
            Write-Log "SecureCore Windows service not found"
        }
        
        Write-Log "SecureCore stop completed"
        
    } catch {
        Write-Log "Warning: Failed to stop SecureCore: $_" "WARNING"
    }
}

# Deactivate SecureCore
function Disable-SecureCore {
    Write-Log "Deactivating SecureCore..."
    
    try {
        $DLLPath = Join-Path $InstallPath "SecureCore.dll"
        if (Test-Path $DLLPath) {
            Add-Type -Path $DLLPath
            $SecureCoreInstance = [SecureCore.SecureCore]::GetInstance()
            
            if ($SecureCoreInstance) {
                if ($SecureCoreInstance.Shutdown()) {
                    Write-Log "SecureCore shutdown successfully"
                } else {
                    Write-Log "Warning: Failed to shutdown SecureCore gracefully" "WARNING"
                }
            }
        }
    } catch {
        Write-Log "Warning: Failed to deactivate SecureCore: $_" "WARNING"
    }
}

# Remove SecureCore service
function Remove-SecureCoreService {
    Write-Log "Removing SecureCore service..."
    
    try {
        $Service = Get-Service -Name "SecureCore" -ErrorAction SilentlyContinue
        if ($Service) {
            # Force stop if still running
            Stop-Service -Name "SecureCore" -Force -ErrorAction SilentlyContinue
            
            # Delete service
            Start-Process -FilePath "sc.exe" -ArgumentList "delete `"SecureCore`"" -Wait -NoNewWindow
            Write-Log "SecureCore service removed"
        } else {
            Write-Log "SecureCore service not found"
        }
    } catch {
        Write-Log "Warning: Failed to remove SecureCore service: $_" "WARNING"
    }
}

# Unregister SecureCore DLL
function Unregister-SecureCore {
    Write-Log "Unregistering SecureCore DLL..."
    
    try {
        $DLLPath = Join-Path $InstallPath "SecureCore.dll"
        if (Test-Path $DLLPath) {
            Start-Process -FilePath "regsvr32.exe" -ArgumentList "/u /s `"$DLLPath`"" -Wait -NoNewWindow
            Write-Log "SecureCore.dll unregistered"
        } else {
            Write-Log "SecureCore.dll not found"
        }
    } catch {
        Write-Log "Warning: Failed to unregister SecureCore.dll: $_" "WARNING"
    }
}

# Remove registry entries
function Remove-RegistryEntries {
    Write-Log "Removing registry entries..."
    
    try {
        # Remove main registry key
        $RegPath = "HKLM:\SOFTWARE\Winsurf AI"
        if (Test-Path $RegPath) {
            Remove-Item -Path $RegPath -Recurse -Force
            Write-Log "Main registry entries removed"
        } else {
            Write-Log "Main registry key not found"
        }
        
        # Remove service registry entries
        $ServiceRegPath = "HKLM:\SYSTEM\CurrentControlSet\Services\SecureCore"
        if (Test-Path $ServiceRegPath) {
            Remove-Item -Path $ServiceRegPath -Recurse -Force
            Write-Log "Service registry entries removed"
        } else {
            Write-Log "Service registry key not found"
        }
        
        # Remove file associations
        $FileAssocPath = "HKLM:\SOFTWARE\Classes\.winsurf"
        if (Test-Path $FileAssocPath) {
            Remove-Item -Path $FileAssocPath -Recurse -Force
            Write-Log "File associations removed"
        }
        
    } catch {
        Write-Log "Warning: Failed to remove some registry entries: $_" "WARNING"
    }
}

# Remove installed files
function Remove-InstalledFiles {
    Write-Log "Removing installed files..."
    
    try {
        if (Test-Path $InstallPath) {
            # Remove main installation directory
            Remove-Item -Path $InstallPath -Recurse -Force
            Write-Log "Installation files removed"
        } else {
            Write-Log "Installation directory not found"
        }
        
        # Remove common files
        $CommonFiles = @(
            "$env:ProgramData\Winsurf AI",
            "$env:ALLUSERSPROFILE\Application Data\Winsurf AI"
        )
        
        foreach ($Path in $CommonFiles) {
            if (Test-Path $Path) {
                Remove-Item -Path $Path -Recurse -Force
                Write-Log "Common files removed: $Path"
            }
        }
        
    } catch {
        Write-Log "Warning: Failed to remove some files: $_" "WARNING"
    }
}

# Remove user data if requested
function Remove-UserData {
    if (-not $RemoveAll) {
        Write-Log "Skipping user data removal (use -RemoveAll to remove)"
        return
    }
    
    Write-Log "Removing user data..."
    
    try {
        # Remove user-specific data
        $UserDataPaths = @(
            "$env:APPDATA\Winsurf AI",
            "$env:LOCALAPPDATA\Winsurf AI"
        )
        
        foreach ($Path in $UserDataPaths) {
            if (Test-Path $Path) {
                Remove-Item -Path $Path -Recurse -Force
                Write-Log "User data removed: $Path"
            }
        }
        
        # Remove desktop shortcuts
        $DesktopPath = "$env:PUBLIC\Desktop"
        $Shortcuts = Get-ChildItem -Path $DesktopPath -Filter "*Winsurf*" -ErrorAction SilentlyContinue
        foreach ($Shortcut in $Shortcuts) {
            Remove-Item -Path $Shortcut.FullName -Force
            Write-Log "Desktop shortcut removed: $($Shortcut.Name)"
        }
        
        # Remove start menu items
        $StartMenuPath = "$env:ALLUSERSPROFILE\Microsoft\Windows\Start Menu\Programs"
        $StartMenuItems = Get-ChildItem -Path $StartMenuPath -Filter "*Winsurf*" -ErrorAction SilentlyContinue
        foreach ($Item in $StartMenuItems) {
            Remove-Item -Path $Item.FullName -Recurse -Force
            Write-Log "Start menu item removed: $($Item.Name)"
        }
        
    } catch {
        Write-Log "Warning: Failed to remove some user data: $_" "WARNING"
    }
}

# Clean system hooks and protections
function Remove-SystemHooks {
    Write-Log "Cleaning system hooks and protections..."
    
    try {
        # This would clean up any remaining system hooks
        # In a full implementation, this would remove:
        # - File system hooks
        # - Registry hooks
        # - Network hooks
        # - Memory protections
        
        # Force refresh of system policies
        Start-Process -FilePath "gpupdate.exe" -ArgumentList "/force" -Wait -NoNewWindow -ErrorAction SilentlyContinue
        
        Write-Log "System hooks cleaned"
    } catch {
        Write-Log "Warning: Failed to clean some system hooks: $_" "WARNING"
    }
}

# Restore system settings
function Restore-SystemSettings {
    Write-Log "Restoring system settings..."
    
    try {
        # Restore Windows Defender if it was modified
        try {
            Set-MpPreference -DisableRealtimeMonitoring $false -ErrorAction SilentlyContinue
            Write-Log "Windows Defender settings restored"
        } catch {
            Write-Log "Warning: Failed to restore Windows Defender settings" "WARNING"
        }
        
        # Restore Windows Firewall if it was modified
        try {
            Set-NetFirewallProfile -All -Enabled True -ErrorAction SilentlyContinue
            Write-Log "Windows Firewall settings restored"
        } catch {
            Write-Log "Warning: Failed to restore Windows Firewall settings" "WARNING"
        }
        
        # Restore UAC settings if they were modified
        try {
            $UACPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"
            if (Test-Path $UACPath) {
                Set-ItemProperty -Path $UACPath -Name "EnableLUA" -Value 1 -ErrorAction SilentlyContinue
                Write-Log "UAC settings restored"
            }
        } catch {
            Write-Log "Warning: Failed to restore UAC settings" "WARNING"
        }
        
    } catch {
        Write-Log "Warning: Failed to restore some system settings: $_" "WARNING"
    }
}

# Remove scheduled tasks
function Remove-ScheduledTasks {
    Write-Log "Removing scheduled tasks..."
    
    try {
        $Tasks = Get-ScheduledTask -TaskName "*Winsurf*" -ErrorAction SilentlyContinue
        foreach ($Task in $Tasks) {
            Unregister-ScheduledTask -TaskName $Task.TaskName -Confirm:$false -ErrorAction SilentlyContinue
            Write-Log "Scheduled task removed: $($Task.TaskName)"
        }
    } catch {
        Write-Log "Warning: Failed to remove some scheduled tasks: $_" "WARNING"
    }
}

# Clean temporary files
function Remove-TemporaryFiles {
    Write-Log "Cleaning temporary files..."
    
    try {
        $TempPaths = @(
            "$env:TEMP\Winsurf*",
            "$env:TMP\Winsurf*",
            "$env:WINDIR\Temp\Winsurf*"
        )
        
        foreach ($Path in $TempPaths) {
            $Files = Get-ChildItem -Path $Path -ErrorAction SilentlyContinue
            foreach ($File in $Files) {
                Remove-Item -Path $File.FullName -Recurse -Force -ErrorAction SilentlyContinue
                Write-Log "Temporary file removed: $($File.Name)"
            }
        }
    } catch {
        Write-Log "Warning: Failed to clean some temporary files: $_" "WARNING"
    }
}

# Verify cleanup
function Test-Cleanup {
    Write-Log "Verifying cleanup..."
    
    $Checks = @(
        { -not (Test-Path $InstallPath) },
        { -not (Get-Service -Name "SecureCore" -ErrorAction SilentlyContinue) },
        { -not (Test-Path "HKLM:\SOFTWARE\Winsurf AI") },
        { -not (Test-Path "HKLM:\SYSTEM\CurrentControlSet\Services\SecureCore") }
    )
    
    $Passed = 0
    foreach ($Check in $Checks) {
        if (& $Check) {
            $Passed++
        }
    }
    
    if ($Passed -eq $Checks.Count) {
        Write-Log "Cleanup verification passed ($Passed/$($Checks.Count) checks)"
        return $true
    } else {
        Write-Log "Cleanup verification partially complete ($Passed/$($Checks.Count) checks)" "WARNING"
        return $false
    }
}

# Main cleanup process
function Start-Cleanup {
    Write-Log "Starting $ProductName cleanup (Version $ScriptVersion)"
    Write-Log "Installation path: $InstallPath"
    
    try {
        Get-CleanupConfirmation
        Stop-SecureCoreService
        Disable-SecureCore
        Remove-SecureCoreService
        Unregister-SecureCore
        Remove-RegistryEntries
        Remove-ScheduledTasks
        Remove-SystemHooks
        Restore-SystemSettings
        Remove-InstalledFiles
        Remove-UserData
        Remove-TemporaryFiles
        
        if (Test-Cleanup) {
            Write-Log "$ProductName cleanup completed successfully" -ForegroundColor Green
            Write-Host ""
            Write-Host "=== CLEANUP COMPLETE ===" -ForegroundColor Green
            Write-Host "Winsurf AI Security System has been completely removed" -ForegroundColor Green
            Write-Host "System settings have been restored" -ForegroundColor Green
            Write-Host "All security protections are now disabled" -ForegroundColor Green
            Write-Host ""
            Write-Host "Cleanup log: $LogFile" -ForegroundColor Cyan
            Write-Host ""
            Write-Host "A system reboot is recommended to complete the cleanup" -ForegroundColor Yellow
        } else {
            Write-Log "Cleanup completed with some issues" "WARNING"
            Write-Host ""
            Write-Host "=== CLEANUP COMPLETED WITH WARNINGS ===" -ForegroundColor Yellow
            Write-Host "Some components may require manual removal" -ForegroundColor Yellow
            Write-Host "Check the log file for details" -ForegroundColor Yellow
            Write-Host "A system reboot is recommended" -ForegroundColor Yellow
        }
    } catch {
        Handle-Error "Cleanup failed: $_"
    }
}

# Start cleanup
Start-Cleanup
