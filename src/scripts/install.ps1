# Winsurf AI Security System Installer
# Version: 1.0.0
# Requires: Windows 10/11, Administrator privileges

param(
    [switch]$Force,
    [switch]$AcceptLicense,
    [string]$InstallPath = "C:\Program Files\Winsurf AI"
)

# Script variables
$ScriptVersion = "1.0.0"
$ProductName = "Winsurf AI Security System"
$CompanyName = "Winsurf AI Technologies"
$LogFile = "$env:TEMP\WinsurfAI_Install_$(Get-Date -Format 'yyyyMMdd_HHmmss').log"

# Logging function
function Write-Log {
    param([string]$Message, [string]$Level = "INFO")
    $Timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $LogEntry = "[$Timestamp] [$Level] $Message"
    Write-Host $LogEntry
    Add-Content -Path $LogFile -Value $LogEntry
}

# Error handling
function Handle-Error {
    param([string]$ErrorMessage)
    Write-Log $ErrorMessage "ERROR"
    Write-Host "Installation failed: $ErrorMessage" -ForegroundColor Red
    exit 1
}

# Check administrator privileges
function Test-Administrator {
    $CurrentUser = [Security.Principal.WindowsIdentity]::GetCurrent()
    $Principal = New-Object Security.Principal.WindowsPrincipal($CurrentUser)
    return $Principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

# Check Windows version
function Test-WindowsVersion {
    $OS = Get-WmiObject -Class Win32_OperatingSystem
    $Version = [Version]$OS.Version
    return ($Version.Major -ge 10)
}

# Check if system is compatible
function Test-SystemCompatibility {
    Write-Log "Checking system compatibility..."
    
    if (-not (Test-Administrator)) {
        Handle-Error "Administrator privileges required for installation"
    }
    
    if (-not (Test-WindowsVersion)) {
        Handle-Error "Windows 10/11 (64-bit) required"
    }
    
    $Architecture = $env:PROCESSOR_ARCHITECTURE
    if ($Architecture -ne "AMD64") {
        Handle-Error "64-bit Windows required"
    }
    
    Write-Log "System compatibility check passed"
}

# Display license and get user consent
function Show-LicenseAgreement {
    if ($AcceptLicense) {
        Write-Log "License accepted via command line parameter"
        return $true
    }
    
    $LicensePath = Join-Path $PSScriptRoot "..\policies\license.rap"
    if (-not (Test-Path $LicensePath)) {
        Handle-Error "License file not found: $LicensePath"
    }
    
    Write-Host "=== $ProductName LICENSE AGREEMENT ===" -ForegroundColor Yellow
    Write-Host ""
    Get-Content $LicensePath | Write-Host
    Write-Host ""
    Write-Host "================================================" -ForegroundColor Red
    Write-Host "IMPORTANT: This software operates at SYSTEM LEVEL" -ForegroundColor Red
    Write-Host "All damages, data loss, or system issues are YOUR RESPONSIBILITY" -ForegroundColor Red
    Write-Host "================================================" -ForegroundColor Red
    Write-Host ""
    
    $Response = Read-Host "Do you accept all terms and accept full responsibility? (YES/NO)"
    if ($Response -ne "YES") {
        Write-Log "License not accepted by user"
        Handle-Error "License agreement not accepted. Installation aborted."
    }
    
    Write-Log "License accepted by user"
    return $true
}

# Display security policies
function Show-SecurityPolicies {
    $PolicyPath = Join-Path $PSScriptRoot "..\policies\security_policy.json"
    $RestrictionPath = Join-Path $PSScriptRoot "..\policies\restrictions.json"
    
    Write-Host "=== SECURITY POLICIES AND RESTRICTIONS ===" -ForegroundColor Yellow
    Write-Host ""
    
    if (Test-Path $PolicyPath) {
        Write-Host "Security Policy Summary:" -ForegroundColor Cyan
        $Policy = Get-Content $PolicyPath | ConvertFrom-Json
        foreach ($Pol in $Policy.policies) {
            if ($Pol.enabled) {
                Write-Host "  - $($Pol.name): $($Pol.description)" -ForegroundColor White
            }
        }
    }
    
    Write-Host ""
    Write-Host "Key Restrictions:" -ForegroundColor Cyan
    Write-Host "  - Script execution BLOCKED (PowerShell, CMD, etc.)" -ForegroundColor Red
    Write-Host "  - Code injection PREVENTED" -ForegroundColor Red
    Write-Host "  - Unsigned DLL loading BLOCKED" -ForegroundColor Red
    Write-Host "  - External execution CONTROLLED" -ForegroundColor Red
    Write-Host "  - File system PROTECTED" -ForegroundColor Red
    Write-Host "  - Registry keys PROTECTED" -ForegroundColor Red
    Write-Host ""
    
    $Response = Read-Host "Do you understand and accept these security restrictions? (YES/NO)"
    if ($Response -ne "YES") {
        Write-Log "Security policies not accepted by user"
        Handle-Error "Security policies not accepted. Installation aborted."
    }
    
    Write-Log "Security policies accepted by user"
}

# Create installation directory
function Initialize-InstallationDirectory {
    Write-Log "Creating installation directory: $InstallPath"
    
    if (Test-Path $InstallPath) {
        if (-not $Force) {
            $Response = Read-Host "Installation directory already exists. Continue? (YES/NO)"
            if ($Response -ne "YES") {
                Handle-Error "Installation cancelled by user"
            }
        }
        
        try {
            Remove-Item -Path $InstallPath -Recurse -Force
        } catch {
            Handle-Error "Failed to remove existing installation: $_"
        }
    }
    
    try {
        New-Item -Path $InstallPath -ItemType Directory -Force | Out-Null
        Write-Log "Installation directory created successfully"
    } catch {
        Handle-Error "Failed to create installation directory: $_"
    }
}

# Copy files to installation directory
function Copy-InstallationFiles {
    Write-Log "Copying installation files..."
    
    $SourcePath = Split-Path $PSScriptRoot -Parent
    $FilesToCopy = @(
        "src\core\SecureCore.dll",
        "src\policies\security_policy.json",
        "src\policies\restrictions.json",
        "src\policies\license.rap"
    )
    
    foreach ($File in $FilesToCopy) {
        $SourceFile = Join-Path $SourcePath $File
        $DestFile = Join-Path $InstallPath (Split-Path $File -Leaf)
        
        if (Test-Path $SourceFile) {
            try {
                Copy-Item -Path $SourceFile -Destination $DestFile -Force
                Write-Log "Copied: $File"
            } catch {
                Handle-Error "Failed to copy $File: $_"
            }
        } else {
            Write-Log "Warning: Source file not found: $SourceFile" "WARNING"
        }
    }
}

# Register SecureCore as system component
function Register-SecureCore {
    Write-Log "Registering SecureCore as system component..."
    
    $DLLPath = Join-Path $InstallPath "SecureCore.dll"
    if (-not (Test-Path $DLLPath)) {
        Handle-Error "SecureCore.dll not found at $DLLPath"
    }
    
    try {
        # Register DLL
        Start-Process -FilePath "regsvr32.exe" -ArgumentList "/s `"$DLLPath`"" -Wait -NoNewWindow
        Write-Log "SecureCore.dll registered successfully"
    } catch {
        Handle-Error "Failed to register SecureCore.dll: $_"
    }
    
    # Create registry entries
    try {
        $RegPath = "HKLM:\SOFTWARE\Winsurf AI"
        New-Item -Path $RegPath -Force | Out-Null
        New-ItemProperty -Path $RegPath -Name "InstallPath" -Value $InstallPath -PropertyType String -Force | Out-Null
        New-ItemProperty -Path $RegPath -Name "Version" -Value $ScriptVersion -PropertyType String -Force | Out-Null
        New-ItemProperty -Path $RegPath -Name "InstallDate" -Value (Get-Date) -PropertyType String -Force | Out-Null
        New-ItemProperty -Path $RegPath -Name "LicenseAccepted" -Value $true -PropertyType DWord -Force | Out-Null
        
        Write-Log "Registry entries created successfully"
    } catch {
        Handle-Error "Failed to create registry entries: $_"
    }
}

# Install Windows service
function Install-SecureCoreService {
    Write-Log "Installing SecureCore service..."
    
    try {
        $ServiceName = "SecureCore"
        $DisplayName = "Winsurf AI SecureCore Service"
        $Description = "Winsurf AI Security Core Service"
        $Executable = Join-Path $InstallPath "SecureCore.dll"
        
        # Remove existing service if it exists
        if (Get-Service -Name $ServiceName -ErrorAction SilentlyContinue) {
            Stop-Service -Name $ServiceName -Force -ErrorAction SilentlyContinue
            Start-Process -FilePath "sc.exe" -ArgumentList "delete `"$ServiceName`"" -Wait -NoNewWindow
        }
        
        # Create new service
        Start-Process -FilePath "sc.exe" -ArgumentList "create `"$ServiceName`" binPath= `"rundll32.exe `"$Executable`",DllMain`" DisplayName= `"$DisplayName`" start= auto" -Wait -NoNewWindow
        Start-Process -FilePath "sc.exe" -ArgumentList "description `"$ServiceName`" `"$Description`"" -Wait -NoNewWindow
        
        Write-Log "SecureCore service installed successfully"
    } catch {
        Handle-Error "Failed to install SecureCore service: $_"
    }
}

# Activate SecureCore
function Activate-SecureCore {
    Write-Log "Activating SecureCore..."
    
    try {
        $DLLPath = Join-Path $InstallPath "SecureCore.dll"
        
        # Load SecureCore and activate
        $SecureCore = Add-Type -Path $DLLPath -PassThru
        $Instance = [SecureCore.SecureCore]::GetInstance()
        
        if ($Instance.Initialize()) {
            Write-Log "SecureCore initialized successfully"
            
            if ($Instance.Activate()) {
                Write-Log "SecureCore activated successfully"
                Write-Log "Security policies are now in effect"
            } else {
                Handle-Error "Failed to activate SecureCore"
            }
        } else {
            Handle-Error "Failed to initialize SecureCore"
        }
    } catch {
        Handle-Error "Failed to activate SecureCore: $_"
    }
}

# Start SecureCore and activate security
function Start-SecureCoreService {
    Write-Log "Starting SecureCore and activating security..."
    
    try {
        $DLLPath = Join-Path $InstallPath "SecureCore.dll"
        
        # Load the SecureCore DLL
        Add-Type -Path $DLLPath
        Write-Log "SecureCore.dll loaded successfully"
        
        # Initialize SecureCore
        $Initialized = [SecureCore.SecureCore]::GetInstance().Initialize()
        if (-not $Initialized) {
            throw "Failed to initialize SecureCore"
        }
        Write-Log "SecureCore initialized successfully"
        
        # Load security policies
        $PolicyPath = Join-Path $InstallPath "security_policy.json"
        $PoliciesLoaded = [SecureCore.SecureCore]::GetInstance().LoadPolicies($PolicyPath)
        if (-not $PoliciesLoaded) {
            throw "Failed to load security policies"
        }
        Write-Log "Security policies loaded successfully"
        
        # Activate SecureCore
        $Activated = [SecureCore.SecureCore]::GetInstance().Activate()
        if (-not $Activated) {
            throw "Failed to activate SecureCore"
        }
        Write-Log "SecureCore activated successfully - Security enforcement is now active"
        
        # Verify activation
        $Status = [SecureCore.SecureCore]::GetInstance().GetStatus()
        if ($Status -ne 2) {  # 2 = ACTIVE
            throw "SecureCore not in active status after activation"
        }
        
        Write-Log "SecureCore is now ACTIVE and protecting the system"
        return $true
        
    } catch {
        Handle-Error "Failed to start SecureCore: $_"
        return $false
    }
}

# Verify installation
function Test-Installation {
    Write-Log "Verifying installation..."
    
    $Checks = @(
        { Test-Path (Join-Path $InstallPath "SecureCore.dll") },
        { Test-Path (Join-Path $InstallPath "security_policy.json") },
        { Test-Path (Join-Path $InstallPath "restrictions.json") },
        { Get-ItemProperty "HKLM:\SOFTWARE\Winsurf AI" -Name "InstallPath" -ErrorAction SilentlyContinue }
    )
    
    $Passed = 0
    foreach ($Check in $Checks) {
        if (& $Check) {
            $Passed++
        }
    }
    
    # Test SecureCore activation
    try {
        $DLLPath = Join-Path $InstallPath "SecureCore.dll"
        Add-Type -Path $DLLPath
        $Status = [SecureCore.SecureCore]::GetInstance().GetStatus()
        $StatusString = [SecureCore.SecureCore]::GetInstance().GetStatusString()
        $BlockedAttempts = [SecureCore.SecureCore]::GetInstance().GetBlockedAttemptsCount()
        
        Write-Log "SecureCore Status: $StatusString"
        Write-Log "Blocked Attempts: $BlockedAttempts"
        
        if ($Status -eq 2) {  # ACTIVE
            $Passed++
            Write-Log "SecureCore is ACTIVE and protecting the system"
        } else {
            Write-Log "SecureCore is not active (Status: $Status)" "WARNING"
        }
    } catch {
        Write-Log "Failed to verify SecureCore status: $_" "WARNING"
    }
    
    if ($Passed -eq $Checks.Count + 1) {
        Write-Log "Installation verification passed ($Passed/$($Checks.Count + 1) checks)"
        return $true
    } else {
        Write-Log "Installation verification failed ($Passed/$($Checks.Count + 1) checks)" "WARNING"
        return $false
    }
}

# Main installation process
function Start-Installation {
    Write-Log "Starting $ProductName installation (Version $ScriptVersion)"
    Write-Log "Installation path: $InstallPath"
    
    try {
        Test-SystemCompatibility
        Show-LicenseAgreement
        Show-SecurityPolicies
        Initialize-InstallationDirectory
        Copy-InstallationFiles
        Register-SecureCore
        Install-SecureCoreService
        Activate-SecureCore
        Start-SecureCoreService
        
        if (Test-Installation) {
            Write-Log "$ProductName installation completed successfully" -ForegroundColor Green
            Write-Host ""
            Write-Host "=== INSTALLATION COMPLETE ===" -ForegroundColor Green
            Write-Host "Security system is now ACTIVE and protecting your system" -ForegroundColor Green
            Write-Host "All security policies are in effect" -ForegroundColor Green
            Write-Host ""
            Write-Host "Installation log: $LogFile" -ForegroundColor Cyan
            Write-Host "Installation path: $InstallPath" -ForegroundColor Cyan
            Write-Host ""
            Write-Host "WARNING: System behavior has been modified" -ForegroundColor Yellow
            Write-Host "Some applications may be restricted or blocked" -ForegroundColor Yellow
        } else {
            Handle-Error "Installation verification failed"
        }
    } catch {
        Handle-Error "Installation failed: $_"
    }
}

# Start installation
Start-Installation
