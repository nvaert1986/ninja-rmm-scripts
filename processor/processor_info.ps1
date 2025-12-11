# ============================================================================
# NinjaOne RMM Script - CPU Information for Windows
# ============================================================================
# Purpose: Displays detailed CPU information including specifications, features,
#          and security vulnerabilities in a formatted HTML report
# Platform: Windows (x86-64 / AMD64 architecture only)
# Output: WYSIWYG custom field in NinjaOne RMM dashboard
# ============================================================================
# This script is the PowerShell equivalent of a Linux bash script, designed
# specifically for Windows systems running on x86-64 (AMD64) processors.
# It collects comprehensive CPU data and formats it as HTML for display
# in NinjaOne's WYSIWYG custom field interface.
# ============================================================================

# ============================================================================
# SCRIPT VARIABLE CONFIGURATION
# ============================================================================
# This variable must be configured in NinjaOne when deploying the script.
# It should contain the name of your WYSIWYG custom field where the HTML
# output will be displayed.
# NinjaOne passes script variables as environment variables to PowerShell.
# ============================================================================
$wysiwygcustomfield = $env:wysiwygcustomfield

# ============================================================================
# VALIDATION: Check if the required custom field variable is set
# ============================================================================
# Without a valid custom field name, the script cannot output its results
# to NinjaOne, so we exit with an error if it's missing.
# ============================================================================
if ([string]::IsNullOrWhiteSpace($wysiwygcustomfield)) {
    Write-Error "ERROR: wysiwygcustomfield variable is not set. Please configure the script variable in NinjaOne."
    exit 1
}

# ============================================================================
# FUNCTION: Set-NinjaCustomField
# ============================================================================
# Purpose: Sets a custom field value in NinjaOne using multiple fallback methods
# Parameters:
#   - FieldName: The name of the NinjaOne custom field to update
#   - HtmlContent: The HTML content to write to the field
# Returns: $true on success, $false on failure
# ============================================================================
# This function attempts two methods to set the custom field:
# 1. Ninja-Property-Set cmdlet (native PowerShell method, preferred)
# 2. ninjarmm-cli.exe with --stdin flag (fallback for older agents)
# ============================================================================
function Set-NinjaCustomField {
    param(
        [string]$FieldName,
        [string]$HtmlContent
    )

    # ========================================================================
    # Method 1: Try PowerShell-native Ninja-Property-Set first (recommended)
    # ========================================================================
    # This cmdlet is provided by the NinjaOne agent and is the cleanest
    # way to set custom fields from PowerShell scripts.
    # ========================================================================
    if (Get-Command Ninja-Property-Set -ErrorAction SilentlyContinue) {
        try {
            Ninja-Property-Set -Name $FieldName -Value $HtmlContent
            return $true
        }
        catch {
            Write-Warning "Ninja-Property-Set failed: $_. Trying ninjarmm-cli..."
        }
    }

    # ========================================================================
    # Method 2: Use ninjarmm-cli.exe with --stdin flag (fallback method)
    # ========================================================================
    # The CLI executable is installed with the NinjaOne agent and provides
    # a command-line interface to interact with NinjaOne services.
    # ========================================================================
    $ninjaCli = "C:\ProgramData\NinjaRMMAgent\ninjarmm-cli.exe"

    # Verify that the CLI executable exists at the expected path
    if (-not (Test-Path $ninjaCli)) {
        Write-Error "ninjarmm-cli.exe not found at: $ninjaCli"
        return $false
    }

    try {
        # ====================================================================
        # Write content to a temporary file and pipe it to the CLI
        # ====================================================================
        # PowerShell's piping to external executables requires special handling
        # for large strings. Using a temp file ensures reliable data transfer.
        # ====================================================================
        $tempFile = [System.IO.Path]::GetTempFileName()
        try {
            # Write content with UTF-8 encoding to preserve special characters
            [System.IO.File]::WriteAllText($tempFile, $HtmlContent, [System.Text.Encoding]::UTF8)

            # Pipe the file content to ninjarmm-cli using the --stdin flag
            Get-Content $tempFile -Raw | & $ninjaCli set --stdin $FieldName

            # Check if the CLI command succeeded
            if ($LASTEXITCODE -ne 0) {
                throw "ninjarmm-cli exited with code $LASTEXITCODE"
            }
            return $true
        }
        finally {
            # ================================================================
            # Cleanup: Remove temporary file regardless of success or failure
            # ================================================================
            if (Test-Path $tempFile) {
                Remove-Item $tempFile -Force -ErrorAction SilentlyContinue
            }
        }
    }
    catch {
        Write-Error "Failed to set custom field: $_"
        return $false
    }
}

# ============================================================================
# MODULE INSTALLATION: SpeculationControl
# ============================================================================
# The SpeculationControl module is an official Microsoft module used to check
# for CPU vulnerabilities like Spectre and Meltdown. If not installed, we
# attempt to install it automatically from the PowerShell Gallery.
# ============================================================================
$speculationControlInstalled = Get-Module -ListAvailable -Name SpeculationControl -ErrorAction SilentlyContinue

if (-not $speculationControlInstalled) {
    Write-Output "SpeculationControl module not found. Installing automatically..."

    # ========================================================================
    # Check if PowerShellGet is available (required for Install-Module)
    # ========================================================================
    if (-not (Get-Module -ListAvailable -Name PowerShellGet -ErrorAction SilentlyContinue)) {
        Write-Warning "PowerShellGet module not available. Cannot install SpeculationControl automatically."
        Write-Warning "Continuing without detailed vulnerability analysis..."
    }
    else {
        try {
            # ================================================================
            # Set PSGallery as trusted to avoid prompts in non-interactive mode
            # ================================================================
            # NinjaOne scripts run non-interactively, so we need to suppress
            # any prompts that would cause the script to hang.
            # ================================================================
            $psGallery = Get-PSRepository -Name PSGallery -ErrorAction SilentlyContinue
            if ($psGallery -and $psGallery.InstallationPolicy -ne 'Trusted') {
                try {
                    Set-PSRepository -Name PSGallery -InstallationPolicy Trusted -ErrorAction Stop
                    Write-Output "Set PSGallery as trusted repository"
                }
                catch {
                    Write-Verbose "Could not set PSGallery as trusted: $_"
                }
            }

            # ================================================================
            # Install NuGet provider if not present (required for PowerShellGet)
            # ================================================================
            # NuGet is the package management framework used by PowerShellGet
            # to download and install modules from the PowerShell Gallery.
            # ================================================================
            $nugetProvider = Get-PackageProvider -Name NuGet -ListAvailable -ErrorAction SilentlyContinue
            if (-not $nugetProvider) {
                try {
                    Write-Output "Installing NuGet provider..."
                    Install-PackageProvider -Name NuGet -MinimumVersion 2.8.5.201 -Force -Scope CurrentUser -ErrorAction Stop | Out-Null
                    Write-Output "NuGet provider installed successfully"
                }
                catch {
                    Write-Warning "Could not install NuGet provider: $_"
                }
            }

            # ================================================================
            # Install SpeculationControl module from PowerShell Gallery
            # ================================================================
            # We try AllUsers scope first (requires admin), then fall back to
            # CurrentUser scope if admin rights are not available.
            # -Force: Suppress prompts and overwrite existing versions
            # -AllowClobber: Allow overwriting existing commands
            # -SkipPublisherCheck: Skip signature verification prompts
            # ================================================================
            try {
                Install-Module -Name SpeculationControl -Force -AllowClobber -SkipPublisherCheck -Scope AllUsers -Confirm:$false -ErrorAction Stop
                Write-Output "SpeculationControl module installed successfully (AllUsers scope)"
            }
            catch {
                # Try CurrentUser scope if AllUsers fails (no admin rights)
                try {
                    Install-Module -Name SpeculationControl -Force -AllowClobber -SkipPublisherCheck -Scope CurrentUser -Confirm:$false -ErrorAction Stop
                    Write-Output "SpeculationControl module installed successfully (CurrentUser scope)"
                }
                catch {
                    Write-Warning "Failed to install SpeculationControl module: $_"
                    Write-Warning "This may be due to network issues, firewall blocking PowerShell Gallery, or insufficient permissions."
                    Write-Warning "Continuing without detailed vulnerability analysis..."
                }
            }
        }
        catch {
            Write-Warning "Failed to prepare for module installation: $_"
            Write-Warning "Continuing without detailed vulnerability analysis..."
        }
    }
}
else {
    Write-Output "SpeculationControl module is already installed."
}

# ============================================================================
# POWERSHELL VERSION DETECTION
# ============================================================================
# PowerShell 7+ provides access to .NET 5+ intrinsics which allow direct
# hardware CPUID queries. Without PS7+, we use fallback detection methods
# that may be less accurate, especially in virtual machines.
# ============================================================================
$isPowerShell7 = $PSVersionTable.PSVersion.Major -ge 7
$powerShellVersion = "$($PSVersionTable.PSVersion.Major).$($PSVersionTable.PSVersion.Minor)"

# Display warning if not using PowerShell 7+
if (-not $isPowerShell7) {
    Write-Output ""
    Write-Output "========================================================================"
    Write-Output "WARNING! Microsoft PowerShell 7.x is not installed."
    Write-Output "Current version: PowerShell $powerShellVersion"
    Write-Output ""
    Write-Output "This script will continue running with fallback detection methods:"
    Write-Output "  - Windows API (IsProcessorFeaturePresent) - Limited feature support"
    Write-Output "  - Registry parsing - May not contain all features"
    Write-Output "  - Model-based detection - Makes assumptions based on CPU name"
    Write-Output ""
    Write-Output "⚠ WARNING: Results may not be completely accurate, especially in VMs!"
    Write-Output ""
    Write-Output "RECOMMENDATION: Install PowerShell 7 for accurate hardware detection"
    Write-Output "  Download: https://aka.ms/powershell"
    Write-Output "  Or run: winget install Microsoft.PowerShell"
    Write-Output "========================================================================"
    Write-Output ""
}

# ============================================================================
# ARCHITECTURE VALIDATION
# ============================================================================
# This script is designed specifically for x86-64 (AMD64) processors.
# We check the architecture and exit gracefully if running on a different
# architecture (x86, ARM, ARM64).
# ============================================================================
try {
    # Get CPU architecture from WMI
    $arch = (Get-CimInstance Win32_Processor -ErrorAction Stop).Architecture
}
catch {
    # If WMI query fails, assume x64 to avoid script failure
    # This prevents issues if WMI is temporarily unavailable
    Write-Warning "Could not determine CPU architecture via WMI: $_"
    Write-Warning "Assuming x86-64 architecture and continuing..."
    $arch = 9  # Assume x64
}

# Architecture codes: 0 = x86 (32-bit), 9 = x64 (64-bit), 5 = ARM, 12 = ARM64
if ($arch -ne 9) {
    # Map architecture code to human-readable name
    $archName = switch ($arch) {
        0 { "x86 (32-bit)" }
        5 { "ARM" }
        12 { "ARM64" }
        default { "Unknown ($arch)" }
    }

    # Generate error HTML for unsupported architecture
    $errorHtml = @"
<div style='padding: 15px; background-color: #fff3cd; border: 1px solid #ffc107; border-radius: 5px;'>
    <strong>⚠️ Unsupported Architecture</strong><br/>
    This script is designed for x86-64 (AMD64) processors only. Detected architecture: <code>$archName</code>
</div>
"@
    Set-NinjaCustomField -FieldName $wysiwygcustomfield -HtmlContent $errorHtml
    Write-Output "Unsupported architecture: $archName (x86-64 only)"
    exit 0
}

# ============================================================================
# CPU INFORMATION RETRIEVAL
# ============================================================================
# Use CIM (Common Information Model) to retrieve CPU and system information.
# CIM is the modern replacement for WMI and provides better performance.
# ============================================================================
try {
    # Get processor details (use first processor if multiple are present)
    $processor = Get-CimInstance -ClassName Win32_Processor -ErrorAction Stop | Select-Object -First 1
    # Get system details for socket count
    $computerSystem = Get-CimInstance -ClassName Win32_ComputerSystem -ErrorAction Stop
}
catch {
    # Generate error HTML if CIM query fails
    $errorHtml = @"
<div style='padding: 15px; background-color: #f8d7da; border: 1px solid #dc3545; border-radius: 5px;'>
    <strong>❌ Unable to Read CPU Information</strong><br/>
    Failed to retrieve CPU information from WMI. Error: $($_.Exception.Message)
</div>
"@
    Set-NinjaCustomField -FieldName $wysiwygcustomfield -HtmlContent $errorHtml
    Write-Error "Unable to retrieve CPU information: $_"
    exit 1
}

# ============================================================================
# EXTRACT BASIC CPU INFORMATION
# ============================================================================
# Extract key CPU properties from the WMI/CIM objects
# ============================================================================
$cpuModel = $processor.Name                         # Full CPU name/brand string
$cpuVendor = $processor.Manufacturer                # Intel, AMD, etc.
$cpuFamily = $processor.Family                      # CPU family identifier
$cpuModelNum = $processor.Model                     # CPU model number
$cpuStepping = $processor.Stepping                  # CPU stepping/revision

# ============================================================================
# CPU COUNT INFORMATION
# ============================================================================
# Physical CPUs = number of CPU sockets in the system
# Cores per Socket = number of physical cores per CPU
# Logical CPUs = total number of threads (includes hyperthreading)
# ============================================================================
$physicalCpus = $computerSystem.NumberOfProcessors
$coresPerSocket = $processor.NumberOfCores
$logicalCpus = $processor.NumberOfLogicalProcessors

# ============================================================================
# CPU FREQUENCY INFORMATION
# ============================================================================
# Current speed = actual current operating frequency
# Max speed = maximum supported frequency (may include turbo)
# Note: Base and Turbo frequencies are not directly available via WMI
# ============================================================================
$currentSpeedMHz = $processor.CurrentClockSpeed
$maxSpeedMHz = $processor.MaxClockSpeed

# Format current speed as GHz if available
if ($currentSpeedMHz -and $currentSpeedMHz -gt 0) {
    $currentSpeedGHz = "{0:N2} GHz" -f ($currentSpeedMHz / 1000)
} else {
    $currentSpeedGHz = "Unknown"
}

# Format max speed as GHz if available
if ($maxSpeedMHz -and $maxSpeedMHz -gt 0) {
    $maxSpeedGHz = "{0:N2} GHz" -f ($maxSpeedMHz / 1000)
} else {
    $maxSpeedGHz = "N/A"
}

# Base and Turbo frequencies are not directly available in Win32_Processor
$baseSpeedGHz = "N/A"
$turboSpeedGHz = "N/A"

# ============================================================================
# CPU CACHE INFORMATION
# ============================================================================
# Retrieve cache sizes for L1, L2, and L3 caches
# L2 and L3 are available from Win32_Processor
# L1 requires querying Win32_CacheMemory
# ============================================================================
$cacheL1 = "N/A"
$cacheL2 = "N/A"
$cacheL3 = "N/A"

# L2 cache size (available in Win32_Processor in KB)
if ($processor.L2CacheSize -and $processor.L2CacheSize -gt 0) {
    if ($processor.L2CacheSize -ge 1024) {
        $cacheL2 = "{0} MB" -f ($processor.L2CacheSize / 1024)
    } else {
        $cacheL2 = "$($processor.L2CacheSize) KB"
    }
}

# L3 cache size (available in Win32_Processor in KB)
if ($processor.L3CacheSize -and $processor.L3CacheSize -gt 0) {
    if ($processor.L3CacheSize -ge 1024) {
        $cacheL3 = "{0} MB" -f ($processor.L3CacheSize / 1024)
    } else {
        $cacheL3 = "$($processor.L3CacheSize) KB"
    }
}

# L1 cache requires Win32_CacheMemory (Level 3 = L1 in WMI terminology)
try {
    $cacheInfo = Get-CimInstance -ClassName Win32_CacheMemory -ErrorAction SilentlyContinue
    $l1Cache = $cacheInfo | Where-Object { $_.Level -eq 3 } | Select-Object -First 1
    if ($l1Cache -and $l1Cache.InstalledSize -gt 0) {
        $cacheL1 = "$($l1Cache.InstalledSize) KB"
    }
}
catch {
    # L1 cache info not available - this is common and not critical
}

# ============================================================================
# CPU FEATURE DEFINITIONS
# ============================================================================
# Define the x86-64 CPU features we want to detect and display.
# This ordered hashtable maps short feature names to display descriptions.
# Features include SIMD instructions, encryption, virtualization, and more.
# ============================================================================
$cpuFeatureDefinitions = [ordered]@{
    "SSE" = "SSE (Streaming SIMD Extensions)"
    "SSE2" = "SSE2 (Streaming SIMD Extensions 2)"
    "SSE3" = "SSE3 (Streaming SIMD Extensions 3)"
    "SSSE3" = "SSSE3 (Supplemental SSE3)"
    "SSE4.1" = "SSE4.1"
    "SSE4.2" = "SSE4.2"
    "AVX" = "AVX (Advanced Vector Extensions)"
    "AVX2" = "AVX2 (Advanced Vector Extensions 2)"
    "AVX-512" = "AVX-512F (Foundation)"
    "AES" = "AES-NI (AES Instruction Set)"
    "PCLMULQDQ" = "PCLMULQDQ (Carry-less Multiplication)"
    "SHA" = "SHA Extensions"
    "RDRAND" = "RDRAND (Hardware RNG)"
    "RDSEED" = "RDSEED (Hardware RNG Seed)"
    "FMA" = "FMA3 (Fused Multiply-Add)"
    "BMI1" = "BMI1 (Bit Manipulation Instructions)"
    "BMI2" = "BMI2 (Bit Manipulation Instructions 2)"
    "ADX" = "ADX (Multi-Precision Add-Carry)"
    "F16C" = "F16C (16-bit Floating Point Conversion)"
    "POPCNT" = "POPCNT (Population Count)"
    "LZCNT" = "LZCNT (Leading Zero Count)"
    "MOVBE" = "MOVBE (Move Data After Swapping Bytes)"
    "XSAVE" = "XSAVE (Extended State Save/Restore)"
    "PAE" = "PAE (Physical Address Extension)"
    "NX" = "NX (No-Execute Bit)"
    "1GB Pages" = "1GB Pages Support"
    "RDTSCP" = "RDTSCP (Read Time-Stamp Counter)"
    "64-bit" = "64-bit Long Mode"
    "VMX" = "VMX (Intel Virtualization)"
    "SVM" = "SVM (AMD Virtualization)"
    "Hypervisor" = "Running under Hypervisor"
}

# Initialize hashtable to store detected CPU features
$cpuFeatures = @{}

# ============================================================================
# CPU FEATURE DETECTION - METHOD 1: .NET 5+ CPUID INTRINSICS (MOST ACCURATE)
# ============================================================================
# PowerShell 7+ running on .NET 5+ provides direct access to CPUID instructions
# via System.Runtime.Intrinsics.X86.X86Base. This is the most reliable method
# as it queries the CPU hardware directly.
# ============================================================================
$cpuidViaIntrinsics = $false
try {
    # Check if System.Runtime.Intrinsics.X86 namespace is available
    $x86BaseType = [System.Runtime.Intrinsics.X86.X86Base] -as [Type]

    if ($null -ne $x86BaseType -and $x86BaseType::IsSupported) {
        Write-Verbose "Using .NET 5+ CPU intrinsics for CPUID detection"

        # ====================================================================
        # CPUID Function 1: Standard Feature Information
        # ====================================================================
        # EAX=1 returns version info in EAX and feature flags in ECX/EDX
        # ====================================================================
        $eax = 1
        $ecx = 0
        $cpuidResult = $x86BaseType::CpuId($eax, $ecx)
        $ecx1 = $cpuidResult.Ecx  # Feature flags (newer features)
        $edx1 = $cpuidResult.Edx  # Feature flags (older features)

        # ====================================================================
        # Parse ECX register bits (CPUID.01H:ECX)
        # Each bit indicates support for a specific CPU feature
        # ====================================================================
        if ($ecx1 -band (1 -shl 0)) { $cpuFeatures["SSE3"] = "supported" }       # Bit 0: SSE3
        if ($ecx1 -band (1 -shl 1)) { $cpuFeatures["PCLMULQDQ"] = "supported" }  # Bit 1: PCLMULQDQ
        if ($ecx1 -band (1 -shl 9)) { $cpuFeatures["SSSE3"] = "supported" }      # Bit 9: SSSE3
        if ($ecx1 -band (1 -shl 12)) { $cpuFeatures["FMA"] = "supported" }       # Bit 12: FMA
        if ($ecx1 -band (1 -shl 19)) { $cpuFeatures["SSE4.1"] = "supported" }    # Bit 19: SSE4.1
        if ($ecx1 -band (1 -shl 20)) { $cpuFeatures["SSE4.2"] = "supported" }    # Bit 20: SSE4.2
        if ($ecx1 -band (1 -shl 22)) { $cpuFeatures["MOVBE"] = "supported" }     # Bit 22: MOVBE
        if ($ecx1 -band (1 -shl 23)) { $cpuFeatures["POPCNT"] = "supported" }    # Bit 23: POPCNT
        if ($ecx1 -band (1 -shl 25)) { $cpuFeatures["AES"] = "supported" }       # Bit 25: AES-NI
        if ($ecx1 -band (1 -shl 26)) { $cpuFeatures["XSAVE"] = "supported" }     # Bit 26: XSAVE
        if ($ecx1 -band (1 -shl 28)) { $cpuFeatures["AVX"] = "supported" }       # Bit 28: AVX
        if ($ecx1 -band (1 -shl 29)) { $cpuFeatures["F16C"] = "supported" }      # Bit 29: F16C
        if ($ecx1 -band (1 -shl 30)) { $cpuFeatures["RDRAND"] = "supported" }    # Bit 30: RDRAND

        # ====================================================================
        # Parse EDX register bits (CPUID.01H:EDX)
        # ====================================================================
        if ($edx1 -band (1 -shl 25)) { $cpuFeatures["SSE"] = "supported" }       # Bit 25: SSE
        if ($edx1 -band (1 -shl 26)) { $cpuFeatures["SSE2"] = "supported" }      # Bit 26: SSE2

        # ====================================================================
        # CPUID Function 7: Extended Features
        # ====================================================================
        # EAX=7, ECX=0 returns extended feature flags
        # ====================================================================
        $cpuidResult7 = $x86BaseType::CpuId(7, 0)
        $ebx7 = $cpuidResult7.Ebx  # Extended feature flags
        $ecx7 = $cpuidResult7.Ecx  # More extended feature flags

        # ====================================================================
        # Parse EBX register bits (CPUID.07H:EBX)
        # ====================================================================
        if ($ebx7 -band (1 -shl 3)) { $cpuFeatures["BMI1"] = "supported" }       # Bit 3: BMI1
        if ($ebx7 -band (1 -shl 5)) { $cpuFeatures["AVX2"] = "supported" }       # Bit 5: AVX2
        if ($ebx7 -band (1 -shl 8)) { $cpuFeatures["BMI2"] = "supported" }       # Bit 8: BMI2
        if ($ebx7 -band (1 -shl 16)) { $cpuFeatures["AVX-512"] = "supported" }   # Bit 16: AVX-512F
        if ($ebx7 -band (1 -shl 19)) { $cpuFeatures["ADX"] = "supported" }       # Bit 19: ADX
        if ($ebx7 -band (1 -shl 18)) { $cpuFeatures["RDSEED"] = "supported" }    # Bit 18: RDSEED
        if ($ebx7 -band (1 -shl 29)) { $cpuFeatures["SHA"] = "supported" }       # Bit 29: SHA

        # ====================================================================
        # CPUID Extended Function 0x80000001: Extended Processor Info
        # ====================================================================
        # AMD-specific and extended features
        # ====================================================================
        $cpuidResultExt = $x86BaseType::CpuId([int]0x80000001, 0)
        $ecxExt = $cpuidResultExt.Ecx
        $edxExt = $cpuidResultExt.Edx

        # Parse ECX register (CPUID.80000001H:ECX)
        if ($ecxExt -band (1 -shl 5)) { $cpuFeatures["LZCNT"] = "supported" }    # Bit 5: LZCNT

        # Parse EDX register (CPUID.80000001H:EDX)
        if ($edxExt -band (1 -shl 11)) { $cpuFeatures["SYSCALL"] = "supported" } # Bit 11: SYSCALL
        if ($edxExt -band (1 -shl 20)) { $cpuFeatures["NX"] = "supported" }      # Bit 20: NX bit
        if ($edxExt -band (1 -shl 26)) { $cpuFeatures["1GB Pages"] = "supported" } # Bit 26: 1GB pages
        if ($edxExt -band (1 -shl 27)) { $cpuFeatures["RDTSCP"] = "supported" }  # Bit 27: RDTSCP
        if ($edxExt -band (1 -shl 29)) { $cpuFeatures["64-bit"] = "supported" }  # Bit 29: Long mode

        $cpuidViaIntrinsics = $true
        Write-Output "✓ Using DYNAMIC detection: .NET 5+ CPUID intrinsics (hardware query)"
    }
}
catch {
    Write-Output "⚠ .NET 5+ intrinsics not available - using fallback methods"
    Write-Output "  → Recommendation: Install PowerShell 7+ for accurate hardware detection"
}

# ============================================================================
# CPU FEATURE DETECTION - METHOD 2: REGISTRY FALLBACK
# ============================================================================
# If CPUID intrinsics are not available, we fall back to reading CPU info
# from the Windows registry and WMI properties. This is less accurate.
# ============================================================================
$cpuidPath = "HKLM:\HARDWARE\DESCRIPTION\System\CentralProcessor\0"
if (Test-Path $cpuidPath) {
    $cpuidInfo = Get-ItemProperty -Path $cpuidPath -ErrorAction SilentlyContinue

    # ========================================================================
    # Extract features from the CPU Identifier string
    # ========================================================================
    # The Identifier string sometimes contains feature flags
    # ========================================================================
    if ($cpuidInfo.Identifier) {
        $identifier = $cpuidInfo.Identifier.ToUpper()
        Write-Verbose "CPU Identifier from registry: $identifier"

        # Check for common feature flags in identifier string
        if ($identifier -match "SSE") { if (-not $cpuFeatures.ContainsKey("SSE")) { $cpuFeatures["SSE"] = "supported" } }
        if ($identifier -match "SSE2") { if (-not $cpuFeatures.ContainsKey("SSE2")) { $cpuFeatures["SSE2"] = "supported" } }
        if ($identifier -match "SSE3") { if (-not $cpuFeatures.ContainsKey("SSE3")) { $cpuFeatures["SSE3"] = "supported" } }
        if ($identifier -match "SSSE3") { if (-not $cpuFeatures.ContainsKey("SSSE3")) { $cpuFeatures["SSSE3"] = "supported" } }
        if ($identifier -match "SSE4") {
            if (-not $cpuFeatures.ContainsKey("SSE4.1")) { $cpuFeatures["SSE4.1"] = "supported" }
            if (-not $cpuFeatures.ContainsKey("SSE4.2")) { $cpuFeatures["SSE4.2"] = "supported" }
        }
    }

    # ========================================================================
    # Check Win32_Processor properties for basic features
    # ========================================================================

    # PAE (Physical Address Extension) support
    if ($processor.PAEEnabled) {
        $cpuFeatures["PAE"] = "supported"
    } else {
        $cpuFeatures["PAE"] = "not_supported"
    }

    # 64-bit support (we already verified x64 architecture)
    $cpuFeatures["64-bit"] = "supported"

    # ========================================================================
    # Virtualization support detection (Intel VT-x or AMD-V)
    # ========================================================================
    if ($processor.VirtualizationFirmwareEnabled -or $processor.VMMonitorModeExtensions) {
        # Set appropriate virtualization feature based on vendor
        if ($cpuVendor -match "Intel") {
            $cpuFeatures["VMX"] = "supported"       # Intel VT-x
            $cpuFeatures["SVM"] = "not_supported"
        } elseif ($cpuVendor -match "AMD") {
            $cpuFeatures["SVM"] = "supported"       # AMD-V
            $cpuFeatures["VMX"] = "not_supported"
        }
    } else {
        $cpuFeatures["VMX"] = "not_supported"
        $cpuFeatures["SVM"] = "not_supported"
    }

    # ========================================================================
    # Check if running under a hypervisor (VM detection)
    # ========================================================================
    try {
        $hypervisorPresent = (Get-CimInstance -ClassName Win32_ComputerSystem -ErrorAction Stop).HypervisorPresent
        if ($hypervisorPresent) {
            $cpuFeatures["Hypervisor"] = "supported"
        } else {
            $cpuFeatures["Hypervisor"] = "not_supported"
        }
    }
    catch {
        $cpuFeatures["Hypervisor"] = "not_supported"
    }

    # ========================================================================
    # NX/XD bit (No-Execute / Execute Disable) for DEP support
    # ========================================================================
    if ($processor.DataExecutionPrevention_Available) {
        $cpuFeatures["NX"] = "supported"
    } else {
        $cpuFeatures["NX"] = "not_supported"
    }
}

# ============================================================================
# CPU FEATURE DETECTION - METHOD 3: WINDOWS API (IsProcessorFeaturePresent)
# ============================================================================
# Use Windows API to check for specific CPU features. This method is more
# reliable than registry but supports fewer features than CPUID intrinsics.
# ============================================================================
try {
    # Add inline C# code to access Windows API
    Add-Type -TypeDefinition @"
using System;
using System.Runtime.InteropServices;

public class CPUIDInfo {
    [StructLayout(LayoutKind.Sequential)]
    public struct CPUIDResult {
        public uint EAX;
        public uint EBX;
        public uint ECX;
        public uint EDX;
    }

    // Import IsProcessorFeaturePresent from kernel32.dll
    // This API checks if a specific CPU feature is supported
    [DllImport("kernel32.dll")]
    private static extern bool IsProcessorFeaturePresent(int ProcessorFeature);

    // Wrapper method with error handling
    public static bool HasWindowsFeature(int feature) {
        try {
            return IsProcessorFeaturePresent(feature);
        } catch {
            return false;
        }
    }
}
"@ -ErrorAction SilentlyContinue

    # ========================================================================
    # Check features using Windows API feature codes
    # ========================================================================
    # Feature codes are defined in winnt.h (PF_* constants)
    # ========================================================================
    if ([CPUIDInfo]::HasWindowsFeature(6)) { $cpuFeatures["SSE"] = "supported" }       # PF_XMMI_INSTRUCTIONS_AVAILABLE
    if ([CPUIDInfo]::HasWindowsFeature(10)) { $cpuFeatures["SSE2"] = "supported" }     # PF_XMMI64_INSTRUCTIONS_AVAILABLE
    if ([CPUIDInfo]::HasWindowsFeature(13)) { $cpuFeatures["SSE3"] = "supported" }     # PF_SSE3_INSTRUCTIONS_AVAILABLE
    if ([CPUIDInfo]::HasWindowsFeature(36)) { $cpuFeatures["SSSE3"] = "supported" }    # PF_SSSE3_INSTRUCTIONS_AVAILABLE
    if ([CPUIDInfo]::HasWindowsFeature(37)) { $cpuFeatures["SSE4.1"] = "supported" }   # PF_SSE4_1_INSTRUCTIONS_AVAILABLE
    if ([CPUIDInfo]::HasWindowsFeature(38)) { $cpuFeatures["SSE4.2"] = "supported" }   # PF_SSE4_2_INSTRUCTIONS_AVAILABLE
    if ([CPUIDInfo]::HasWindowsFeature(39)) { $cpuFeatures["AVX"] = "supported" }      # PF_AVX_INSTRUCTIONS_AVAILABLE
    if ([CPUIDInfo]::HasWindowsFeature(40)) { $cpuFeatures["AVX2"] = "supported" }     # PF_AVX2_INSTRUCTIONS_AVAILABLE
    if ([CPUIDInfo]::HasWindowsFeature(41)) { $cpuFeatures["AVX-512"] = "supported" }  # PF_AVX512F_INSTRUCTIONS_AVAILABLE
    if ([CPUIDInfo]::HasWindowsFeature(28)) { $cpuFeatures["RDRAND"] = "supported" }   # PF_RDRAND_INSTRUCTION_AVAILABLE
    if ([CPUIDInfo]::HasWindowsFeature(32)) { $cpuFeatures["RDTSCP"] = "supported" }   # PF_RDTSCP_INSTRUCTION_AVAILABLE
    if ([CPUIDInfo]::HasWindowsFeature(17)) { $cpuFeatures["XSAVE"] = "supported" }    # PF_XSAVE_ENABLED
}
catch {
    Write-Verbose "Could not load CPUID detection: $_"
}

# ============================================================================
# CPU FEATURE DETECTION - METHOD 4: MODEL-BASED INFERENCE
# ============================================================================
# For modern CPUs, we can infer feature support based on the CPU model name.
# This is the least accurate method but provides reasonable defaults when
# other detection methods fail.
# ============================================================================
$cpuModelLower = if ($cpuModel) { $cpuModel.ToLower() } else { "" }
$isModernCPU = $false

# ============================================================================
# Detect if this is a modern CPU (post-2010)
# ============================================================================
# Modern Intel: Core iX (2nd gen+), Xeon E3/E5/E7, Xeon Scalable (Silver/Gold/Platinum/Bronze/W)
# Modern AMD: Ryzen, EPYC, Threadripper
# ============================================================================
if ($cpuModelLower -match "core.*i[3579]|xeon.*(e[357]|silver|gold|platinum|bronze|w-|scalable|[0-9]{4})|ryzen|epyc|threadripper") {
    $isModernCPU = $true
}

# ============================================================================
# Set baseline features for modern CPUs (2010+)
# ============================================================================
if ($isModernCPU) {
    # All modern CPUs support SSE through SSE4.2 (since Core 2 / Phenom II era, ~2008)
    if (-not $cpuFeatures.ContainsKey("SSE")) { $cpuFeatures["SSE"] = "supported" }
    if (-not $cpuFeatures.ContainsKey("SSE2")) { $cpuFeatures["SSE2"] = "supported" }
    if (-not $cpuFeatures.ContainsKey("SSE3")) { $cpuFeatures["SSE3"] = "supported" }
    if (-not $cpuFeatures.ContainsKey("SSSE3")) { $cpuFeatures["SSSE3"] = "supported" }
    if (-not $cpuFeatures.ContainsKey("SSE4.1")) { $cpuFeatures["SSE4.1"] = "supported" }
    if (-not $cpuFeatures.ContainsKey("SSE4.2")) { $cpuFeatures["SSE4.2"] = "supported" }

    # AVX support (Intel Sandy Bridge+ 2011, AMD Bulldozer+ 2011, Ryzen, EPYC)
    if (-not $cpuFeatures.ContainsKey("AVX")) { $cpuFeatures["AVX"] = "supported" }

    # Common features on all modern CPUs
    if (-not $cpuFeatures.ContainsKey("AES")) { $cpuFeatures["AES"] = "supported" }
    if (-not $cpuFeatures.ContainsKey("PCLMULQDQ")) { $cpuFeatures["PCLMULQDQ"] = "supported" }
    if (-not $cpuFeatures.ContainsKey("POPCNT")) { $cpuFeatures["POPCNT"] = "supported" }
    if (-not $cpuFeatures.ContainsKey("MOVBE")) { $cpuFeatures["MOVBE"] = "supported" }
    if (-not $cpuFeatures.ContainsKey("F16C")) { $cpuFeatures["F16C"] = "supported" }
    if (-not $cpuFeatures.ContainsKey("FMA")) { $cpuFeatures["FMA"] = "supported" }
    if (-not $cpuFeatures.ContainsKey("XSAVE")) { $cpuFeatures["XSAVE"] = "supported" }
    if (-not $cpuFeatures.ContainsKey("RDRAND")) { $cpuFeatures["RDRAND"] = "supported" }

    # ========================================================================
    # Intel Haswell+ features (2013+)
    # ========================================================================
    # Core i3/i5/i7/i9 4xxx+ and Xeon E3/E5/E7 v3+, Xeon Scalable
    # ========================================================================
    if ($cpuVendor -match "Intel" -and $cpuModelLower -match "core.*i[3579]-[4-9][0-9]{3}|core.*i[3579]-1[0-9]{4}|xeon.*(e[357]-?v[3-9]|e[357]-?[0-9]{4}|silver|gold|platinum|bronze|w-|scalable)") {
        if (-not $cpuFeatures.ContainsKey("AVX2")) { $cpuFeatures["AVX2"] = "supported" }
        if (-not $cpuFeatures.ContainsKey("BMI1")) { $cpuFeatures["BMI1"] = "supported" }
        if (-not $cpuFeatures.ContainsKey("BMI2")) { $cpuFeatures["BMI2"] = "supported" }
        if (-not $cpuFeatures.ContainsKey("ADX")) { $cpuFeatures["ADX"] = "supported" }
        if (-not $cpuFeatures.ContainsKey("LZCNT")) { $cpuFeatures["LZCNT"] = "supported" }
    }

    # ========================================================================
    # AMD Zen+ features (2017+)
    # ========================================================================
    # Ryzen, EPYC, Threadripper
    # ========================================================================
    if ($cpuVendor -match "AMD" -and $cpuModelLower -match "ryzen|epyc|threadripper") {
        if (-not $cpuFeatures.ContainsKey("AVX2")) { $cpuFeatures["AVX2"] = "supported" }
        if (-not $cpuFeatures.ContainsKey("BMI1")) { $cpuFeatures["BMI1"] = "supported" }
        if (-not $cpuFeatures.ContainsKey("BMI2")) { $cpuFeatures["BMI2"] = "supported" }
        if (-not $cpuFeatures.ContainsKey("ADX")) { $cpuFeatures["ADX"] = "supported" }
        if (-not $cpuFeatures.ContainsKey("LZCNT")) { $cpuFeatures["LZCNT"] = "supported" }
    }

    # Common features on all modern x64 CPUs
    if (-not $cpuFeatures.ContainsKey("NX")) { $cpuFeatures["NX"] = "supported" }
    if (-not $cpuFeatures.ContainsKey("PAE")) { $cpuFeatures["PAE"] = "supported" }
    if (-not $cpuFeatures.ContainsKey("RDTSCP")) { $cpuFeatures["RDTSCP"] = "supported" }
    if (-not $cpuFeatures.ContainsKey("SYSCALL")) { $cpuFeatures["SYSCALL"] = "supported" }

    # ========================================================================
    # Virtualization support based on vendor
    # ========================================================================
    if ($cpuVendor -match "Intel") {
        if (-not $cpuFeatures.ContainsKey("VMX")) { $cpuFeatures["VMX"] = "supported" }
        if (-not $cpuFeatures.ContainsKey("SVM")) { $cpuFeatures["SVM"] = "not_supported" }
    } elseif ($cpuVendor -match "AMD") {
        if (-not $cpuFeatures.ContainsKey("SVM")) { $cpuFeatures["SVM"] = "supported" }
        if (-not $cpuFeatures.ContainsKey("VMX")) { $cpuFeatures["VMX"] = "not_supported" }
    }

    # ========================================================================
    # SHA extensions (newer CPUs only)
    # ========================================================================
    # Intel: Goldmont+, Ice Lake+ Core, Xeon Scalable 3rd gen+
    # AMD: Zen+ Ryzen 3000+, EPYC Rome+
    # ========================================================================
    if (($cpuVendor -match "Intel" -and $cpuModelLower -match "core.*i[3579]-1[0-9]{4}|xeon.*(gold [56][0-9]{3}[a-z]?|platinum [89][0-9]{3}[a-z]?|silver [45][0-9]{3}[a-z]?|scalable)") -or
        ($cpuVendor -match "AMD" -and $cpuModelLower -match "ryzen.*[3-9][0-9]{3}|epyc.*7[0-9]{3}")) {
        if (-not $cpuFeatures.ContainsKey("SHA")) { $cpuFeatures["SHA"] = "supported" }
    }

    # ========================================================================
    # RDSEED (hardware random seed)
    # ========================================================================
    # Intel: Broadwell+ (Core i5-5xxx+), Xeon E5 v4+, Xeon Scalable
    # AMD: Zen+ Ryzen, EPYC
    # ========================================================================
    if (($cpuVendor -match "Intel" -and $cpuModelLower -match "core.*i[3579]-[5-9][0-9]{3}|core.*i[3579]-1[0-9]{4}|xeon.*(e[357]-?v[4-9]|e[357]-?[0-9]{4}|silver|gold|platinum|bronze|w-|scalable)") -or
        ($cpuVendor -match "AMD" -and $cpuModelLower -match "ryzen|epyc|threadripper")) {
        if (-not $cpuFeatures.ContainsKey("RDSEED")) { $cpuFeatures["RDSEED"] = "supported" }
    }
}

# ============================================================================
# 1GB Pages support (typically server CPUs)
# ============================================================================
if ($cpuModelLower -match "xeon|epyc|threadripper") {
    if (-not $cpuFeatures.ContainsKey("1GB Pages")) { $cpuFeatures["1GB Pages"] = "supported" }
}

# SYSCALL is always present on x64 architecture
if (-not $cpuFeatures.ContainsKey("SYSCALL")) { $cpuFeatures["SYSCALL"] = "supported" }

# ============================================================================
# Set remaining features to "not_supported" if not detected
# ============================================================================
foreach ($feature in $cpuFeatureDefinitions.Keys) {
    if (-not $cpuFeatures.ContainsKey($feature)) {
        $cpuFeatures[$feature] = "not_supported"
    }
}

# ============================================================================
# CPU VULNERABILITY DETECTION
# ============================================================================
# Check for CPU security vulnerabilities like Spectre, Meltdown, and others
# using the Microsoft SpeculationControl module or registry fallback.
# ============================================================================
$vulnerabilities = @{}
$unmitigatedVulns = 0

# ============================================================================
# Import SpeculationControl module for vulnerability checking
# ============================================================================
# The module was checked/installed at script start
# ============================================================================
$speculationControlAvailable = $false
try {
    Import-Module SpeculationControl -ErrorAction Stop
    $speculationControlAvailable = $true
    Write-Output "SpeculationControl module imported successfully"
}
catch {
    Write-Warning "Could not import SpeculationControl module: $_"
    Write-Warning "Vulnerability checking will be limited"
}

if ($speculationControlAvailable) {
    try {
        # Get speculation control settings from the module
        $specControl = Get-SpeculationControlSettings -ErrorAction SilentlyContinue

        if ($specControl) {
            # ================================================================
            # Spectre Variant 1 (Bounds Check Bypass) - CVE-2017-5753
            # ================================================================
            if ($null -ne $specControl.BTIHardwarePresent) {
                if ($specControl.BTIHardwarePresent -eq $true) {
                    $vulnerabilities["Spectre Variant 1 (Bounds Check Bypass)"] = @{
                        Status = "mitigated"
                        Mitigation = "Hardware support present, software mitigations enabled"
                    }
                } else {
                    $vulnerabilities["Spectre Variant 1 (Bounds Check Bypass)"] = @{
                        Status = "mitigated"
                        Mitigation = "Software mitigations only"
                    }
                }
            }

            # ================================================================
            # Spectre Variant 2 (Branch Target Injection) - CVE-2017-5715
            # ================================================================
            if ($null -ne $specControl.BTIWindowsSupportPresent -and $null -ne $specControl.BTIWindowsSupportEnabled) {
                if ($specControl.BTIWindowsSupportEnabled) {
                    $mitigation = "Windows support enabled"
                    if ($specControl.BTIHardwarePresent) {
                        $mitigation += ", hardware support present"
                    }
                    $vulnerabilities["Spectre Variant 2 (Branch Target Injection)"] = @{
                        Status = "mitigated"
                        Mitigation = $mitigation
                    }
                } else {
                    $vulnerabilities["Spectre Variant 2 (Branch Target Injection)"] = @{
                        Status = "vulnerable"
                        Mitigation = "Not Mitigated"
                    }
                    $unmitigatedVulns++
                }
            }

            # ================================================================
            # Spectre Variant 4 (Speculative Store Bypass) - CVE-2018-3639
            # ================================================================
            if ($null -ne $specControl.SSBDWindowsSupportPresent -and $null -ne $specControl.SSBDWindowsSupportEnabled) {
                if ($specControl.SSBDWindowsSupportEnabled) {
                    $vulnerabilities["Spectre Variant 4 (Speculative Store Bypass)"] = @{
                        Status = "mitigated"
                        Mitigation = "Windows SSBD support enabled"
                    }
                } else {
                    $vulnerabilities["Spectre Variant 4 (Speculative Store Bypass)"] = @{
                        Status = "vulnerable"
                        Mitigation = "Not Mitigated"
                    }
                    $unmitigatedVulns++
                }
            }

            # ================================================================
            # L1TF (L1 Terminal Fault / Foreshadow) - CVE-2018-3615/3620/3646
            # ================================================================
            if ($null -ne $specControl.L1TFWindowsSupportPresent -and $null -ne $specControl.L1TFWindowsSupportEnabled) {
                if ($specControl.L1TFWindowsSupportEnabled) {
                    $vulnerabilities["L1TF (L1 Terminal Fault / Foreshadow)"] = @{
                        Status = "mitigated"
                        Mitigation = "Windows L1TF mitigations enabled"
                    }
                } else {
                    $vulnerabilities["L1TF (L1 Terminal Fault / Foreshadow)"] = @{
                        Status = "vulnerable"
                        Mitigation = "Not Mitigated"
                    }
                    $unmitigatedVulns++
                }
            }

            # ================================================================
            # MDS (Microarchitectural Data Sampling) - CVE-2018-12126/12127/12130, CVE-2019-11091
            # ================================================================
            if ($null -ne $specControl.MDSWindowsSupportPresent -and $null -ne $specControl.MDSWindowsSupportEnabled) {
                if ($specControl.MDSWindowsSupportEnabled) {
                    $vulnerabilities["MDS (Microarchitectural Data Sampling)"] = @{
                        Status = "mitigated"
                        Mitigation = "Windows MDS mitigations enabled"
                    }
                } else {
                    $vulnerabilities["MDS (Microarchitectural Data Sampling)"] = @{
                        Status = "vulnerable"
                        Mitigation = "Not Mitigated"
                    }
                    $unmitigatedVulns++
                }
            }
        }
    }
    catch {
        Write-Verbose "Failed to get speculation control settings: $_"
    }
}

# ============================================================================
# FALLBACK: Check registry for mitigations if SpeculationControl unavailable
# ============================================================================
if ($vulnerabilities.Count -eq 0) {
    $regPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management"

    try {
        $memMgmt = Get-ItemProperty -Path $regPath -ErrorAction SilentlyContinue

        # Check FeatureSettingsOverride registry key for mitigations
        if ($null -ne $memMgmt.FeatureSettingsOverride) {
            $vulnerabilities["Spectre/Meltdown"] = @{
                Status = "mitigated"
                Mitigation = "Registry-based mitigations enabled (FeatureSettingsOverride: $($memMgmt.FeatureSettingsOverride))"
            }
        } else {
            $vulnerabilities["Spectre/Meltdown"] = @{
                Status = "unknown"
                Mitigation = "Unable to determine mitigation status (SpeculationControl module not available)"
            }
        }
    }
    catch {
        $vulnerabilities["CPU Vulnerabilities"] = @{
            Status = "unknown"
            Mitigation = "Unable to check vulnerability status via registry"
        }
    }
}

# ============================================================================
# Handle case where no vulnerabilities were detected
# ============================================================================
if ($vulnerabilities.Count -eq 0) {
    $vulnerabilities["CPU Vulnerabilities"] = @{
        Status = "unknown"
        Mitigation = "Unable to query vulnerability information. The SpeculationControl module may have failed to load."
    }
}

$totalVulns = $vulnerabilities.Count

# ============================================================================
# HTML OUTPUT GENERATION
# ============================================================================
# Build the HTML content that will be displayed in NinjaOne's WYSIWYG field.
# The output includes styled tables for specifications, features, and vulnerabilities.
# ============================================================================
$currentDate = Get-Date -Format "yyyy-MM-dd HH:mm:ss"

# Start HTML document with styling
$htmlOutput = @"
<div style='font-family: Arial, sans-serif;'>
<h2 style='color: #2c3e50; margin-bottom: 10px;'>🔧 CPU Information</h2>
"@

# ============================================================================
# Add PowerShell 7 warning banner if not using PS7+
# ============================================================================
if (-not $isPowerShell7) {
    $htmlOutput += @"
<div style='padding: 15px; margin-bottom: 20px; background-color: #fff3cd; border-left: 5px solid #ff9800; border-radius: 3px; box-shadow: 0 2px 4px rgba(0,0,0,0.1);'>
<div style='display: flex; align-items: flex-start;'>
<div style='font-size: 32px; margin-right: 15px; color: #ff9800;'>⚠️</div>
<div>
<strong style='color: #d35400; font-size: 16px;'>PowerShell 7 Not Detected</strong><br/>
<span style='color: #856404; font-size: 13px;'>
Current version: <strong>PowerShell $powerShellVersion</strong><br/><br/>
This script is using <strong>fallback detection methods</strong> which may not be completely accurate, especially in virtual machines.<br/><br/>
<strong>Fallback methods used:</strong>
<ul style='margin: 8px 0; padding-left: 20px;'>
<li>Windows API (IsProcessorFeaturePresent) - Limited feature support</li>
<li>Registry parsing - May not contain all CPU features</li>
<li>Model-based detection - Makes assumptions based on CPU model name</li>
</ul>
<strong style='color: #d35400;'>⚡ Recommendation:</strong> Install PowerShell 7 for accurate hardware-level CPUID detection<br/>
<span style='font-size: 12px;'>
📥 Download: <a href='https://aka.ms/powershell' style='color: #2980b9;'>https://aka.ms/powershell</a> |
Or run: <code style='background: #eee; padding: 2px 6px; border-radius: 3px;'>winget install Microsoft.PowerShell</code>
</span>
</span>
</div>
</div>
</div>
"@
}

# ============================================================================
# Summary banner showing processor name and architecture
# ============================================================================
$htmlOutput += @"
<div style='padding: 10px; margin-bottom: 15px; background-color: #f8f9fa; border-left: 4px solid #3498db; border-radius: 3px;'>
<strong style='color: #3498db;'>Processor:</strong> $cpuModel<br/>
<strong style='color: #3498db;'>Architecture:</strong> x86-64 (AMD64)
</div>
"@

# ============================================================================
# Quick stats line (CPUs, cores, logical processors, timestamp)
# ============================================================================
$htmlOutput += @"
<p style='color: #7f8c8d; margin-bottom: 20px;'>
Physical CPUs: <strong>$physicalCpus</strong> |
Cores per Socket: <strong>$coresPerSocket</strong> |
Logical CPUs: <strong>$logicalCpus</strong> |
Last Updated: <strong>$currentDate</strong>
</p>
"@

# ============================================================================
# CPU Specifications Table
# ============================================================================
$htmlOutput += @"
<h3 style='color: #2c3e50; margin-top: 20px; margin-bottom: 10px;'>Processor Specifications</h3>
<table style='width: 100%; border-collapse: collapse; box-shadow: 0 2px 4px rgba(0,0,0,0.1); margin-bottom: 20px;'>
<thead>
<tr style='background-color: #3498db; color: white;'>
<th style='padding: 12px; text-align: left; border: 1px solid #ddd; width: 30%;'>Property</th>
<th style='padding: 12px; text-align: left; border: 1px solid #ddd;'>Value</th>
</tr>
</thead>
<tbody>
"@

# Define specification rows to display
$specRows = @(
    @("Brand", $cpuModel),
    @("Vendor", $cpuVendor),
    @("CPU Family", $cpuFamily),
    @("Model Number", $cpuModelNum),
    @("Stepping", $cpuStepping),
    @("Current Clock Speed", $currentSpeedGHz),
    @("Base Clock Speed", $baseSpeedGHz),
    @("Max Clock Speed", $maxSpeedGHz),
    @("Turbo/Boost Speed", $turboSpeedGHz),
    @("L1 Cache", $cacheL1),
    @("L2 Cache", $cacheL2),
    @("L3 Cache", $cacheL3),
    @("Physical Sockets", $physicalCpus),
    @("Cores per Socket", $coresPerSocket),
    @("Logical Processors", $logicalCpus)
)

# Add alternating row colors for readability
$rowCount = 0
foreach ($row in $specRows) {
    $bgColor = if ($rowCount % 2 -eq 0) { "#f8f9fa" } else { "#ffffff" }
    $htmlOutput += @"
<tr style='background-color: $bgColor;'>
<td style='padding: 10px; border: 1px solid #ddd;'><strong>$($row[0])</strong></td>
<td style='padding: 10px; border: 1px solid #ddd;'>$($row[1])</td>
</tr>
"@
    $rowCount++
}

$htmlOutput += @"
</tbody>
</table>
"@

# ============================================================================
# CPU Features Table
# ============================================================================
$htmlOutput += @"
<h3 style='color: #2c3e50; margin-top: 20px; margin-bottom: 10px;'>CPU Features (x86-64)</h3>
<table style='width: 100%; border-collapse: collapse; box-shadow: 0 2px 4px rgba(0,0,0,0.1); margin-bottom: 20px;'>
<thead>
<tr style='background-color: #16a085; color: white;'>
<th style='padding: 12px; text-align: left; border: 1px solid #ddd; width: 40%;'>Feature</th>
<th style='padding: 12px; text-align: center; border: 1px solid #ddd; width: 20%;'>Status</th>
</tr>
</thead>
<tbody>
"@

# Sort features alphabetically by display name and add to table
$sortedFeatures = $cpuFeatureDefinitions.GetEnumerator() | Sort-Object Value
$rowCount = 0

foreach ($feature in $sortedFeatures) {
    $featureKey = $feature.Key
    $featureDesc = $feature.Value
    $status = $cpuFeatures[$featureKey]

    # Format status with color-coded icons
    if ($status -eq "supported") {
        $statusHtml = "<span style='color: #27ae60; font-weight: bold;'>✓ Supported</span>"
    } else {
        $statusHtml = "<span style='color: #95a5a6;'>✗ Not Supported</span>"
    }

    $bgColor = if ($rowCount % 2 -eq 0) { "#f8f9fa" } else { "#ffffff" }

    $htmlOutput += @"
<tr style='background-color: $bgColor;'>
<td style='padding: 10px; border: 1px solid #ddd;'>$featureDesc</td>
<td style='padding: 10px; border: 1px solid #ddd; text-align: center;'>$statusHtml</td>
</tr>
"@
    $rowCount++
}

$htmlOutput += @"
</tbody>
</table>
"@

# ============================================================================
# Vulnerability status banner
# ============================================================================
# Color-coded based on security status
# ============================================================================
$vulnBannerColor = "#27ae60"  # Green for all mitigated
$vulnBannerIcon = "✓"
$vulnBannerText = "No Unmitigated Vulnerabilities"

if ($unmitigatedVulns -gt 0) {
    # Red for unmitigated vulnerabilities
    $vulnBannerColor = "#dc3545"
    $vulnBannerIcon = "⚠"
    $vulnBannerText = "$unmitigatedVulns Unmitigated Vulnerability(ies) Found"
} elseif ($totalVulns -gt 0) {
    # Orange for mitigated vulnerabilities (still worth noting)
    $mitigatedCount = ($vulnerabilities.Values | Where-Object { $_.Status -eq "mitigated" }).Count
    if ($mitigatedCount -gt 0) {
        $vulnBannerColor = "#f39c12"
        $vulnBannerIcon = "⚠"
        $vulnBannerText = "$totalVulns Vulnerability(ies) Checked (All Known Issues Mitigated)"
    }
}

$htmlOutput += @"
<div style='padding: 10px; margin-bottom: 15px; background-color: #f8f9fa; border-left: 4px solid $vulnBannerColor; border-radius: 3px;'>
<strong style='color: $vulnBannerColor;'>$vulnBannerIcon Security Status:</strong> $vulnBannerText
</div>
"@

# ============================================================================
# CPU Security Vulnerabilities Table
# ============================================================================
$htmlOutput += @"
<h3 style='color: #2c3e50; margin-top: 20px; margin-bottom: 10px;'>CPU Security Vulnerabilities</h3>
<table style='width: 100%; border-collapse: collapse; box-shadow: 0 2px 4px rgba(0,0,0,0.1); margin-bottom: 20px;'>
<thead>
<tr style='background-color: #e74c3c; color: white;'>
<th style='padding: 12px; text-align: left; border: 1px solid #ddd; width: 30%;'>Vulnerability</th>
<th style='padding: 12px; text-align: center; border: 1px solid #ddd; width: 15%;'>Status</th>
<th style='padding: 12px; text-align: left; border: 1px solid #ddd;'>Mitigation</th>
</tr>
</thead>
<tbody>
"@

# Sort vulnerabilities alphabetically and add to table
$sortedVulns = $vulnerabilities.GetEnumerator() | Sort-Object Key
$rowCount = 0

foreach ($vuln in $sortedVulns) {
    $vulnName = $vuln.Key
    $vulnStatus = $vuln.Value.Status
    $vulnMitigation = $vuln.Value.Mitigation

    # Format status with color-coded icons
    switch ($vulnStatus) {
        "not_affected" {
            $statusHtml = "<span style='color: #27ae60; font-weight: bold;'>✓ Not Affected</span>"
        }
        "mitigated" {
            $statusHtml = "<span style='color: #f39c12; font-weight: bold;'>⚠ Mitigated</span>"
        }
        "vulnerable" {
            $statusHtml = "<span style='color: #dc3545; font-weight: bold;'>✗ Vulnerable</span>"
        }
        default {
            $statusHtml = "<span style='color: #95a5a6;'>? Unknown</span>"
        }
    }

    # Truncate long mitigation strings for display
    if ($vulnMitigation.Length -gt 100) {
        $vulnMitigation = $vulnMitigation.Substring(0, 97) + "..."
    }

    $bgColor = if ($rowCount % 2 -eq 0) { "#f8f9fa" } else { "#ffffff" }

    $htmlOutput += @"
<tr style='background-color: $bgColor;'>
<td style='padding: 10px; border: 1px solid #ddd;'>$vulnName</td>
<td style='padding: 10px; border: 1px solid #ddd; text-align: center;'>$statusHtml</td>
<td style='padding: 10px; border: 1px solid #ddd; font-size: 11px;'>$vulnMitigation</td>
</tr>
"@
    $rowCount++
}

$htmlOutput += @"
</tbody>
</table>
"@

# ============================================================================
# Add warning banner if unmitigated vulnerabilities were found
# ============================================================================
if ($unmitigatedVulns -gt 0) {
    $htmlOutput += @"
<div style='margin-top: 15px; padding: 12px; background-color: #fff3cd; border-left: 4px solid #dc3545; border-radius: 3px;'>
<strong style='color: #dc3545;'>⚠️ Unmitigated Security Vulnerabilities Detected:</strong><br/>
<span style='font-size: 12px; color: #856404;'>$unmitigatedVulns CPU security vulnerability(ies) are present and not mitigated.</span><br/>
<small style='color: #856404;'>Recommended actions: 1) Install all available Windows Updates, 2) Update CPU microcode via BIOS/UEFI firmware update, 3) Review mitigation settings in the table above for specific guidance.</small>
</div>
"@
}

# ============================================================================
# Footer with system info and detection method
# ============================================================================
try {
    $osVersion = (Get-CimInstance Win32_OperatingSystem -ErrorAction Stop).Caption
}
catch {
    $osVersion = "Unknown"
}

# Show detection method used (hardware CPUID vs fallback)
$detectionMethod = if ($cpuidViaIntrinsics) {
    "<span style='color: #27ae60; font-weight: bold;'>✓ Dynamic CPUID (Hardware)</span>"
} else {
    "<span style='color: #e67e22; font-weight: bold;'>⚠ Fallback Methods (API/Registry/Model-based)</span>"
}

$htmlOutput += @"
<hr style='border: none; border-top: 1px solid #ddd; margin: 20px 0;'>
<p style='margin-top: 10px; font-size: 12px; color: #95a5a6;'>
<strong>System Info:</strong> $osVersion | PowerShell $powerShellVersion | Architecture: x64<br/>
<strong>Detection Method:</strong> $detectionMethod
</p>
</div>
"@

# ============================================================================
# OUTPUT: Set the custom field in NinjaOne
# ============================================================================
$success = Set-NinjaCustomField -FieldName $wysiwygcustomfield -HtmlContent $htmlOutput

if ($success) {
    # Log success information to console
    Write-Output "CPU information has been written to custom field: $wysiwygcustomfield"
    Write-Output "Processor: $cpuModel"
    Write-Output "Physical CPUs: $physicalCpus | Cores: $coresPerSocket | Logical CPUs: $logicalCpus"
    Write-Output "Vulnerabilities checked: $totalVulns"
    Write-Output "Unmitigated vulnerabilities: $unmitigatedVulns"

    # ========================================================================
    # EXIT CODE DETERMINATION
    # ========================================================================
    # Exit code 0 = Success, no security issues
    # Exit code 4 = Warning, unmitigated vulnerabilities found
    # Exit code 1 = Error (handled earlier in script)
    # ========================================================================
    $exitCode = 0
    $exitReason = "No issues detected"

    if ($unmitigatedVulns -gt 0) {
        $exitCode = 4
        $exitReason = "WARNING: $unmitigatedVulns unmitigated CPU security vulnerability(ies) detected"
        Write-Output "EXIT CODE 4: $exitReason"
    } else {
        $exitReason = "All CPU security vulnerabilities are either not present or properly mitigated"
    }

    Write-Output "Exit reason: $exitReason"
    exit $exitCode
}
else {
    Write-Error "Failed to set custom field"
    exit 1
}
