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

# ============================================================================
# FUNCTION: Get-PS7Path
# ============================================================================
# Purpose: Detects if PowerShell 7 (pwsh.exe) is installed and returns path
# Returns: Path to pwsh.exe if found, $null otherwise
# ============================================================================
function Get-PS7Path {
    [CmdletBinding()]
    param()

    # Check common installation paths first
    $commonPaths = @(
        "$env:ProgramFiles\PowerShell\7\pwsh.exe"
        "${env:ProgramFiles(x86)}\PowerShell\7\pwsh.exe"
        "$env:LOCALAPPDATA\Microsoft\PowerShell\pwsh.exe"
    )

    foreach ($path in $commonPaths) {
        if (Test-Path -Path $path -PathType Leaf) {
            return $path
        }
    }

    # If not found in common paths, check PATH environment variable
    $pwshCmd = Get-Command -Name 'pwsh' -ErrorAction SilentlyContinue
    if ($pwshCmd) {
        return $pwshCmd.Source
    }

    return $null
}

# ============================================================================
# FUNCTION: Invoke-PS7Command
# ============================================================================
# Purpose: Executes a ScriptBlock in PowerShell 7 from PowerShell 5
# Parameters:
#   - ScriptBlock: The code to execute in PowerShell 7
#   - Parameters: Hashtable of named parameters to pass
#   - ArgumentList: Array of positional arguments
#   - NoThrow: Return result object instead of throwing on error
# Returns: Script output (or result object if NoThrow is specified)
# ============================================================================
# This function enables PowerShell 5 scripts to leverage PowerShell 7 features
# (like .NET 5+ CPUID intrinsics) by executing code blocks in pwsh.exe and
# returning results via JSON serialization.
# ============================================================================
function Invoke-PS7Command {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true, Position = 0)]
        [ScriptBlock]$ScriptBlock,

        [Parameter(Mandatory = $false)]
        [hashtable]$Parameters,

        [Parameter(Mandatory = $false)]
        [object[]]$ArgumentList,

        [Parameter(Mandatory = $false)]
        [switch]$NoThrow
    )

    #region PS7 Detection
    $pwshPath = Get-PS7Path

    # Error if PS7 not found
    if (-not $pwshPath) {
        $errorMsg = "PowerShell 7 (pwsh.exe) not found. Please install PowerShell 7 from https://github.com/PowerShell/PowerShell/releases"
        if ($NoThrow) {
            return [PSCustomObject]@{
                Success = $false
                Output  = $null
                Error   = $errorMsg
            }
        }
        throw $errorMsg
    }
    #endregion

    #region Build PS7 Command
    $scriptString = $ScriptBlock.ToString()

    # Encode script and parameters as Base64 to avoid escaping issues
    $scriptBytes = [System.Text.Encoding]::UTF8.GetBytes($scriptString)
    $scriptBase64 = [Convert]::ToBase64String($scriptBytes)

    $paramBase64 = 'bnVsbA=='  # 'null' in base64
    $argsBase64 = 'bnVsbA=='   # 'null' in base64

    if ($Parameters) {
        $paramJson = $Parameters | ConvertTo-Json -Compress -Depth 10
        $paramBytes = [System.Text.Encoding]::UTF8.GetBytes($paramJson)
        $paramBase64 = [Convert]::ToBase64String($paramBytes)
    }

    if ($ArgumentList) {
        $argsJson = ConvertTo-Json -InputObject $ArgumentList -Compress -Depth 10
        $argsBytes = [System.Text.Encoding]::UTF8.GetBytes($argsJson)
        $argsBase64 = [Convert]::ToBase64String($argsBytes)
    }

    # Build the wrapper script that runs in PS7
    $wrapperScript = @"
`$ErrorActionPreference = 'Stop'
`$VerbosePreference = 'SilentlyContinue'
`$WarningPreference = 'SilentlyContinue'
`$InformationPreference = 'SilentlyContinue'
`$DebugPreference = 'SilentlyContinue'
`$result = @{ Success = `$true; Output = `$null; Error = `$null }

try {
    # Decode Base64 encoded script and parameters
    `$scriptText = [System.Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('$scriptBase64'))
    `$sb = [ScriptBlock]::Create(`$scriptText)

    `$paramJson = [System.Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('$paramBase64'))
    `$argsJson = [System.Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('$argsBase64'))

    `$splatParams = @{}
    `$positionalArgs = @()

    if (`$paramJson -ne 'null') {
        `$params = `$paramJson | ConvertFrom-Json -AsHashtable
        foreach (`$key in `$params.Keys) {
            `$splatParams[`$key] = `$params[`$key]
        }
    }

    if (`$argsJson -ne 'null') {
        `$positionalArgs = @(`$argsJson | ConvertFrom-Json)
    }

    # Execute the scriptblock with parameters (suppress all output streams)
    if (`$splatParams.Count -gt 0 -and `$positionalArgs.Count -gt 0) {
        `$result.Output = & `$sb @splatParams @positionalArgs 6>`$null 5>`$null 4>`$null 3>`$null 2>`$null
    }
    elseif (`$splatParams.Count -gt 0) {
        `$result.Output = & `$sb @splatParams 6>`$null 5>`$null 4>`$null 3>`$null 2>`$null
    }
    elseif (`$positionalArgs.Count -gt 0) {
        `$result.Output = & `$sb @positionalArgs 6>`$null 5>`$null 4>`$null 3>`$null 2>`$null
    }
    else {
        `$result.Output = & `$sb 6>`$null 5>`$null 4>`$null 3>`$null 2>`$null
    }
}
catch {
    `$result.Success = `$false
    `$result.Error = `$_.Exception.Message + ' | ' + `$_.ScriptStackTrace
}

# Ensure we only output JSON
try {
    `$result | ConvertTo-Json -Depth 10 -Compress
}
catch {
    @{ Success = `$false; Output = `$null; Error = \"JSON serialization failed: `$(`$_.Exception.Message)\" } | ConvertTo-Json -Compress
}
"@
    #endregion

    #region Execute and Handle Results
    try {
        $ps7Output = & $pwshPath -NoProfile -NonInteractive -Command $wrapperScript 2>&1

        # Separate stdout from stderr
        $stdout = $ps7Output | Where-Object { $_ -is [string] -or $_.GetType().Name -eq 'String' }
        $stderr = $ps7Output | Where-Object { $_ -is [System.Management.Automation.ErrorRecord] }

        # Get the JSON result (last line of output)
        $jsonString = ($stdout | Out-String).Trim()

        if (-not $jsonString) {
            $errorMsg = "No output received from PowerShell 7"
            if ($stderr) {
                $errorMsg += ". Errors: " + ($stderr | Out-String)
            }
            throw $errorMsg
        }

        # Try to parse JSON with error handling
        try {
            $resultObject = $jsonString | ConvertFrom-Json
        }
        catch {
            $parseError = "Failed to parse PS7 JSON output. Error: $($_.Exception.Message)`nRaw output (first 500 chars): $($jsonString.Substring(0, [Math]::Min(500, $jsonString.Length)))"
            if ($NoThrow) {
                return [PSCustomObject]@{
                    Success = $false
                    Output  = $null
                    Error   = $parseError
                }
            }
            throw $parseError
        }

        if ($resultObject.Success) {
            if ($NoThrow) {
                return [PSCustomObject]@{
                    Success = $true
                    Output  = $resultObject.Output
                    Error   = $null
                }
            }
            return $resultObject.Output
        }
        else {
            if ($NoThrow) {
                return [PSCustomObject]@{
                    Success = $false
                    Output  = $null
                    Error   = $resultObject.Error
                }
            }
            throw "PS7 Error: $($resultObject.Error)"
        }
    }
    catch {
        if ($NoThrow) {
            return [PSCustomObject]@{
                Success = $false
                Output  = $null
                Error   = $_.Exception.Message
            }
        }
        throw
    }
    #endregion
}

# ============================================================================
# Check if PowerShell 7 is available for use (even if currently in PS5)
# ============================================================================
$ps7Available = $null -ne (Get-PS7Path)
$usingPS7Wrapper = $false

# Display warning if not using PowerShell 7+ directly
if (-not $isPowerShell7) {
    if ($ps7Available) {
        Write-Output ""
        Write-Output "========================================================================"
        Write-Output "INFO: Running in PowerShell $powerShellVersion, but PowerShell 7 is available."
        Write-Output "Using PS7 wrapper for accurate CPUID hardware detection."
        Write-Output "========================================================================"
        Write-Output ""
        $usingPS7Wrapper = $true
    } else {
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
        Write-Output "WARNING: Results may not be completely accurate, especially in VMs!"
        Write-Output ""
        Write-Output "RECOMMENDATION: Install PowerShell 7 for accurate hardware detection"
        Write-Output "  Download: https://aka.ms/powershell"
        Write-Output "  Or run: winget install Microsoft.PowerShell"
        Write-Output "========================================================================"
        Write-Output ""
    }
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
    "Hypervisor" = "Running under Hypervisor *"
}

# Initialize hashtable to store detected CPU features
# Each feature will have: Supported (bool/string) and Enabled (bool/string/null for N/A)
$cpuFeatures = @{}

# Track enabled status separately for features that can be enabled/disabled
# Features not in this hashtable will show "N/A" in the Enabled column
$cpuFeaturesEnabled = @{}

# Define which features can have an enabled/disabled status
# These are features that can be turned on/off in BIOS or OS settings
$featureCanBeDisabled = @(
    "VMX",           # Intel VT-x - can be disabled in BIOS
    "SVM",           # AMD-V - can be disabled in BIOS
    "Hypervisor",    # Hypervisor/Hyper-V - can be enabled/disabled in Windows
    "NX"             # DEP/NX - can be configured in Windows (though typically always on)
)

# ============================================================================
# CPU FEATURE DETECTION - METHOD 1: .NET 5+ CPUID INTRINSICS (MOST ACCURATE)
# ============================================================================
# PowerShell 7+ running on .NET 5+ provides direct access to CPUID instructions
# via System.Runtime.Intrinsics.X86.X86Base. This is the most reliable method
# as it queries the CPU hardware directly.
#
# If running in PowerShell 5 but PowerShell 7 is available, we use the
# Invoke-PS7Command wrapper to execute the CPUID detection in PS7.
# ============================================================================
$cpuidViaIntrinsics = $false

# Define the CPUID detection script block (used both natively and via wrapper)
$cpuidDetectionScriptBlock = {
    $features = @{}
    $success = $false

    try {
        # Check if System.Runtime.Intrinsics.X86 namespace is available
        $x86BaseType = [System.Runtime.Intrinsics.X86.X86Base] -as [Type]

        if ($null -ne $x86BaseType -and $x86BaseType::IsSupported) {
            # ====================================================================
            # CPUID Function 1: Standard Feature Information
            # ====================================================================
            $cpuidResult = $x86BaseType::CpuId(1, 0)
            $ecx1 = $cpuidResult.Ecx
            $edx1 = $cpuidResult.Edx

            # Parse ECX register bits (CPUID.01H:ECX)
            if ($ecx1 -band (1 -shl 0)) { $features["SSE3"] = "supported" }
            if ($ecx1 -band (1 -shl 1)) { $features["PCLMULQDQ"] = "supported" }
            if ($ecx1 -band (1 -shl 9)) { $features["SSSE3"] = "supported" }
            if ($ecx1 -band (1 -shl 12)) { $features["FMA"] = "supported" }
            if ($ecx1 -band (1 -shl 19)) { $features["SSE4.1"] = "supported" }
            if ($ecx1 -band (1 -shl 20)) { $features["SSE4.2"] = "supported" }
            if ($ecx1 -band (1 -shl 22)) { $features["MOVBE"] = "supported" }
            if ($ecx1 -band (1 -shl 23)) { $features["POPCNT"] = "supported" }
            if ($ecx1 -band (1 -shl 25)) { $features["AES"] = "supported" }
            if ($ecx1 -band (1 -shl 26)) { $features["XSAVE"] = "supported" }
            if ($ecx1 -band (1 -shl 28)) { $features["AVX"] = "supported" }
            if ($ecx1 -band (1 -shl 29)) { $features["F16C"] = "supported" }
            if ($ecx1 -band (1 -shl 30)) { $features["RDRAND"] = "supported" }

            # Parse EDX register bits (CPUID.01H:EDX)
            if ($edx1 -band (1 -shl 25)) { $features["SSE"] = "supported" }
            if ($edx1 -band (1 -shl 26)) { $features["SSE2"] = "supported" }

            # ====================================================================
            # CPUID Function 7: Extended Features
            # ====================================================================
            $cpuidResult7 = $x86BaseType::CpuId(7, 0)
            $ebx7 = $cpuidResult7.Ebx

            # Parse EBX register bits (CPUID.07H:EBX)
            if ($ebx7 -band (1 -shl 3)) { $features["BMI1"] = "supported" }
            if ($ebx7 -band (1 -shl 5)) { $features["AVX2"] = "supported" }
            if ($ebx7 -band (1 -shl 8)) { $features["BMI2"] = "supported" }
            if ($ebx7 -band (1 -shl 16)) { $features["AVX-512"] = "supported" }
            if ($ebx7 -band (1 -shl 18)) { $features["RDSEED"] = "supported" }
            if ($ebx7 -band (1 -shl 19)) { $features["ADX"] = "supported" }
            if ($ebx7 -band (1 -shl 29)) { $features["SHA"] = "supported" }

            # ====================================================================
            # CPUID Extended Function 0x80000001: Extended Processor Info
            # ====================================================================
            $cpuidResultExt = $x86BaseType::CpuId([int]0x80000001, 0)
            $ecxExt = $cpuidResultExt.Ecx
            $edxExt = $cpuidResultExt.Edx

            # Parse ECX register (CPUID.80000001H:ECX)
            if ($ecxExt -band (1 -shl 5)) { $features["LZCNT"] = "supported" }

            # Parse EDX register (CPUID.80000001H:EDX)
            if ($edxExt -band (1 -shl 11)) { $features["SYSCALL"] = "supported" }
            if ($edxExt -band (1 -shl 20)) { $features["NX"] = "supported" }
            if ($edxExt -band (1 -shl 26)) { $features["1GB Pages"] = "supported" }
            if ($edxExt -band (1 -shl 27)) { $features["RDTSCP"] = "supported" }
            if ($edxExt -band (1 -shl 29)) { $features["64-bit"] = "supported" }

            $success = $true
        }
    }
    catch {
        $success = $false
    }

    return [PSCustomObject]@{
        Success = $success
        Features = $features
    }
}

# Attempt CPUID detection - either natively (PS7) or via wrapper (PS5 + PS7 available)
if ($isPowerShell7) {
    # Running natively in PowerShell 7 - execute directly
    try {
        $cpuidResult = & $cpuidDetectionScriptBlock

        if ($cpuidResult.Success) {
            # Copy detected features to main hashtable
            foreach ($key in $cpuidResult.Features.Keys) {
                $cpuFeatures[$key] = $cpuidResult.Features[$key]
            }
            $cpuidViaIntrinsics = $true
            Write-Output "Using DYNAMIC detection: .NET 5+ CPUID intrinsics (hardware query, native PS7)"
        }
    }
    catch {
        Write-Output ".NET 5+ intrinsics failed in native PS7 - using fallback methods"
    }
}
elseif ($usingPS7Wrapper) {
    # Running in PowerShell 5 but PS7 is available - use wrapper
    try {
        $cpuidResult = Invoke-PS7Command -ScriptBlock $cpuidDetectionScriptBlock -NoThrow

        if ($cpuidResult.Success -and $cpuidResult.Output.Success) {
            # Copy detected features from PS7 result to main hashtable
            $ps7Features = $cpuidResult.Output.Features
            if ($ps7Features -is [PSCustomObject]) {
                # Convert PSCustomObject to hashtable
                $ps7Features.PSObject.Properties | ForEach-Object {
                    $cpuFeatures[$_.Name] = $_.Value
                }
            }
            elseif ($ps7Features -is [hashtable]) {
                foreach ($key in $ps7Features.Keys) {
                    $cpuFeatures[$key] = $ps7Features[$key]
                }
            }
            $cpuidViaIntrinsics = $true
            Write-Output "Using DYNAMIC detection: .NET 5+ CPUID intrinsics (hardware query via PS7 wrapper)"
        }
        else {
            $errorMsg = if ($cpuidResult.Error) { $cpuidResult.Error } else { "Unknown error" }
            Write-Output "PS7 wrapper CPUID detection failed: $errorMsg"
            Write-Output "Falling back to alternative detection methods..."
        }
    }
    catch {
        Write-Output "PS7 wrapper invocation failed: $_"
        Write-Output "Falling back to alternative detection methods..."
    }
}
else {
    # No PS7 available at all - will use fallback methods below
    Write-Output ".NET 5+ intrinsics not available - using fallback methods"
    Write-Output "  Recommendation: Install PowerShell 7+ for accurate hardware detection"
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
    # NOTE: WMI properties can be unreliable, especially on 64-bit systems.
    # We only set "supported" when positively detected here. The model-based
    # inference will handle modern CPUs that WMI fails to detect properly.
    # ========================================================================

    # PAE (Physical Address Extension) support
    # Note: PAEEnabled indicates if PAE mode is active, not if CPU supports it.
    # All x64 CPUs support PAE (it's required for 64-bit mode).
    # Only set "supported" here; model-based inference handles the rest.
    if ($processor.PAEEnabled -eq $true) {
        $cpuFeatures["PAE"] = "supported"
    }
    # Don't set "not_supported" - WMI is unreliable for this on x64 systems

    # 64-bit support (we already verified x64 architecture)
    $cpuFeatures["64-bit"] = "supported"

    # ========================================================================
    # Virtualization support detection (Intel VT-x or AMD-V)
    # ========================================================================
    # VirtualizationFirmwareEnabled = VT-x/AMD-V is enabled in BIOS AND Windows
    # VMMonitorModeExtensions = CPU supports virtualization extensions
    #
    # NOTE: If VT-x/AMD-V is disabled in BIOS, VirtualizationFirmwareEnabled
    # will be false even though the CPU SUPPORTS it. All modern Intel/AMD
    # CPUs support virtualization - it might just be disabled.
    # We track both: support (from model-based inference) and enabled status (from WMI).
    # ========================================================================
    $virtEnabled = $processor.VirtualizationFirmwareEnabled -eq $true
    $virtSupported = $processor.VMMonitorModeExtensions -eq $true

    if ($cpuVendor -match "Intel") {
        # Track enabled status for VMX
        if ($virtEnabled) {
            $cpuFeatures["VMX"] = "supported"
            $cpuFeaturesEnabled["VMX"] = "enabled"
        } elseif ($virtSupported) {
            # CPU supports it but it's not enabled (likely disabled in BIOS)
            $cpuFeatures["VMX"] = "supported"
            $cpuFeaturesEnabled["VMX"] = "disabled"
        } else {
            # WMI can't confirm - leave for model-based inference but mark as disabled
            $cpuFeaturesEnabled["VMX"] = "disabled"
        }
    } elseif ($cpuVendor -match "AMD") {
        # Track enabled status for SVM
        if ($virtEnabled) {
            $cpuFeatures["SVM"] = "supported"
            $cpuFeaturesEnabled["SVM"] = "enabled"
        } elseif ($virtSupported) {
            $cpuFeatures["SVM"] = "supported"
            $cpuFeaturesEnabled["SVM"] = "disabled"
        } else {
            $cpuFeaturesEnabled["SVM"] = "disabled"
        }
    }

    # ========================================================================
    # Check if running under a hypervisor (VM detection)
    # ========================================================================
    try {
        $hypervisorPresent = (Get-CimInstance -ClassName Win32_ComputerSystem -ErrorAction Stop).HypervisorPresent
        if ($hypervisorPresent) {
            $cpuFeatures["Hypervisor"] = "supported"
            $cpuFeaturesEnabled["Hypervisor"] = "enabled"
        } else {
            $cpuFeatures["Hypervisor"] = "not_supported"
            $cpuFeaturesEnabled["Hypervisor"] = "disabled"
        }
    }
    catch {
        # Can't determine - leave unset for model-based inference
    }

    # ========================================================================
    # NX/XD bit (No-Execute / Execute Disable) for DEP support
    # ========================================================================
    # DataExecutionPrevention_Available indicates DEP is available AND enabled.
    # All x64 CPUs support NX (required for Windows 8+).
    # We track both support (always true for x64) and enabled status.
    # ========================================================================
    if ($processor.DataExecutionPrevention_Available -eq $true) {
        $cpuFeatures["NX"] = "supported"
        $cpuFeaturesEnabled["NX"] = "enabled"
    } else {
        # NX is supported on all x64 CPUs but might be disabled in Windows settings
        $cpuFeaturesEnabled["NX"] = "disabled"
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
# VULNERABILITY METADATA
# ============================================================================
# Reference information for each vulnerability including CVE numbers,
# disclosure dates, and Microsoft guidance articles.
# ============================================================================
$vulnerabilityMetadata = @{
    "Spectre Variant 1 (Bounds Check Bypass)" = @{
        CVE = "CVE-2017-5753"
        Date = "2018-01-03"
        MSArticle = "https://support.microsoft.com/en-us/help/4073119"
        Description = "Bounds Check Bypass"
    }
    "Spectre Variant 2 (Branch Target Injection)" = @{
        CVE = "CVE-2017-5715"
        Date = "2018-01-03"
        MSArticle = "https://support.microsoft.com/en-us/help/4073119"
        Description = "Branch Target Injection"
    }
    "Meltdown (Rogue Data Cache Load)" = @{
        CVE = "CVE-2017-5754"
        Date = "2018-01-03"
        MSArticle = "https://support.microsoft.com/en-us/help/4073119"
        Description = "Rogue Data Cache Load"
    }
    "Spectre Variant 4 (Speculative Store Bypass)" = @{
        CVE = "CVE-2018-3639"
        Date = "2018-05-21"
        MSArticle = "https://support.microsoft.com/en-us/help/4073119"
        Description = "Speculative Store Bypass"
    }
    "L1TF (L1 Terminal Fault / Foreshadow)" = @{
        CVE = "CVE-2018-3615, CVE-2018-3620, CVE-2018-3646"
        Date = "2018-08-14"
        MSArticle = "https://support.microsoft.com/en-us/help/4457951"
        Description = "L1 Terminal Fault affecting SGX, OS, and VMM"
    }
    "MDS (Microarchitectural Data Sampling)" = @{
        CVE = "CVE-2018-12126, CVE-2018-12127, CVE-2018-12130, CVE-2019-11091"
        Date = "2019-05-14"
        MSArticle = "https://support.microsoft.com/en-us/help/4093836"
        Description = "MSBDS (Fallout), MFBDS (ZombieLoad), MLPDS, MDSUM"
    }
    "TAA (TSX Asynchronous Abort)" = @{
        CVE = "CVE-2019-11135"
        Date = "2019-11-12"
        MSArticle = "https://support.microsoft.com/en-us/help/4072698"
        Description = "TSX Asynchronous Abort affecting Intel CPUs with TSX"
    }
    "SBDR/SBDS (Shared Buffers Data Sampling)" = @{
        CVE = "CVE-2022-21123, CVE-2022-21125"
        Date = "2022-06-14"
        MSArticle = "https://support.microsoft.com/en-us/help/5019180"
        Description = "MMIO Stale Data vulnerabilities"
    }
}

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
            } else {
                $vulnerabilities["Spectre Variant 1 (Bounds Check Bypass)"] = @{
                    Status = "unknown"
                    Mitigation = "Unable to determine status"
                }
            }

            # ================================================================
            # Spectre Variant 2 (Branch Target Injection) - CVE-2017-5715
            # ================================================================
            if ($null -ne $specControl.BTIWindowsSupportPresent -or $null -ne $specControl.BTIWindowsSupportEnabled) {
                if ($specControl.BTIWindowsSupportEnabled -eq $true) {
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
            } else {
                $vulnerabilities["Spectre Variant 2 (Branch Target Injection)"] = @{
                    Status = "unknown"
                    Mitigation = "Unable to determine status"
                }
            }

            # ================================================================
            # Meltdown (Rogue Data Cache Load) - CVE-2017-5754
            # ================================================================
            # KVA Shadow (Kernel Virtual Address Shadow) is Windows' mitigation
            # for Meltdown, similar to Linux KPTI (Kernel Page Table Isolation)
            # ================================================================
            if ($null -ne $specControl.KVAShadowRequired) {
                if ($specControl.KVAShadowRequired -eq $false) {
                    # CPU is not affected by Meltdown (e.g., AMD CPUs, newer Intel with hardware fix)
                    $vulnerabilities["Meltdown (Rogue Data Cache Load)"] = @{
                        Status = "not_affected"
                        Mitigation = "CPU not affected (hardware not vulnerable)"
                    }
                } elseif ($specControl.KVAShadowWindowsSupportEnabled -eq $true) {
                    # KVA Shadow is enabled
                    $mitigation = "KVA Shadow enabled"
                    if ($specControl.KVAShadowPcidEnabled -eq $true) {
                        $mitigation += ", PCID optimization enabled"
                    }
                    $vulnerabilities["Meltdown (Rogue Data Cache Load)"] = @{
                        Status = "mitigated"
                        Mitigation = $mitigation
                    }
                } elseif ($specControl.KVAShadowWindowsSupportPresent -eq $true) {
                    # Support present but not enabled
                    $vulnerabilities["Meltdown (Rogue Data Cache Load)"] = @{
                        Status = "vulnerable"
                        Mitigation = "KVA Shadow available but not enabled"
                    }
                    $unmitigatedVulns++
                } else {
                    # Required but no support
                    $vulnerabilities["Meltdown (Rogue Data Cache Load)"] = @{
                        Status = "vulnerable"
                        Mitigation = "Not Mitigated - KVA Shadow not available"
                    }
                    $unmitigatedVulns++
                }
            } else {
                $vulnerabilities["Meltdown (Rogue Data Cache Load)"] = @{
                    Status = "unknown"
                    Mitigation = "Unable to determine status"
                }
            }

            # ================================================================
            # Spectre Variant 4 (Speculative Store Bypass) - CVE-2018-3639
            # ================================================================
            if ($null -ne $specControl.SSBDHardwareVulnerable) {
                if ($specControl.SSBDHardwareVulnerable -eq $false) {
                    # CPU is not affected
                    $vulnerabilities["Spectre Variant 4 (Speculative Store Bypass)"] = @{
                        Status = "not_affected"
                        Mitigation = "CPU not affected (hardware not vulnerable)"
                    }
                } elseif ($specControl.SSBDWindowsSupportEnabled -eq $true) {
                    $vulnerabilities["Spectre Variant 4 (Speculative Store Bypass)"] = @{
                        Status = "mitigated"
                        Mitigation = "Windows SSBD support enabled"
                    }
                } elseif ($specControl.SSBDWindowsSupportPresent -eq $true) {
                    $vulnerabilities["Spectre Variant 4 (Speculative Store Bypass)"] = @{
                        Status = "vulnerable"
                        Mitigation = "SSBD available but not enabled"
                    }
                    $unmitigatedVulns++
                } else {
                    $vulnerabilities["Spectre Variant 4 (Speculative Store Bypass)"] = @{
                        Status = "vulnerable"
                        Mitigation = "Not Mitigated"
                    }
                    $unmitigatedVulns++
                }
            } elseif ($null -ne $specControl.SSBDWindowsSupportPresent -or $null -ne $specControl.SSBDWindowsSupportEnabled) {
                # Fallback if SSBDHardwareVulnerable is not available
                if ($specControl.SSBDWindowsSupportEnabled -eq $true) {
                    $vulnerabilities["Spectre Variant 4 (Speculative Store Bypass)"] = @{
                        Status = "mitigated"
                        Mitigation = "Windows SSBD support enabled"
                    }
                } elseif ($specControl.SSBDWindowsSupportPresent -eq $true) {
                    $vulnerabilities["Spectre Variant 4 (Speculative Store Bypass)"] = @{
                        Status = "vulnerable"
                        Mitigation = "SSBD available but not enabled"
                    }
                    $unmitigatedVulns++
                } else {
                    $vulnerabilities["Spectre Variant 4 (Speculative Store Bypass)"] = @{
                        Status = "vulnerable"
                        Mitigation = "Not Mitigated"
                    }
                    $unmitigatedVulns++
                }
            } else {
                $vulnerabilities["Spectre Variant 4 (Speculative Store Bypass)"] = @{
                    Status = "unknown"
                    Mitigation = "Unable to determine status"
                }
            }

            # ================================================================
            # L1TF (L1 Terminal Fault / Foreshadow) - CVE-2018-3615/3620/3646
            # ================================================================
            if ($null -ne $specControl.L1TFHardwareVulnerable) {
                if ($specControl.L1TFHardwareVulnerable -eq $false) {
                    # CPU is not affected (AMD CPUs, newer Intel)
                    $vulnerabilities["L1TF (L1 Terminal Fault / Foreshadow)"] = @{
                        Status = "not_affected"
                        Mitigation = "CPU not affected (hardware not vulnerable)"
                    }
                } elseif ($specControl.L1TFWindowsSupportEnabled -eq $true) {
                    $mitigation = "Windows L1TF mitigations enabled"
                    if ($specControl.L1TFFlushSupported -eq $true) {
                        $mitigation += ", L1D flush supported"
                    }
                    $vulnerabilities["L1TF (L1 Terminal Fault / Foreshadow)"] = @{
                        Status = "mitigated"
                        Mitigation = $mitigation
                    }
                } elseif ($specControl.L1TFWindowsSupportPresent -eq $true) {
                    $vulnerabilities["L1TF (L1 Terminal Fault / Foreshadow)"] = @{
                        Status = "vulnerable"
                        Mitigation = "L1TF mitigations available but not enabled"
                    }
                    $unmitigatedVulns++
                } else {
                    $vulnerabilities["L1TF (L1 Terminal Fault / Foreshadow)"] = @{
                        Status = "vulnerable"
                        Mitigation = "Not Mitigated"
                    }
                    $unmitigatedVulns++
                }
            } elseif ($null -ne $specControl.L1TFWindowsSupportPresent -or $null -ne $specControl.L1TFWindowsSupportEnabled) {
                # Fallback if L1TFHardwareVulnerable is not available
                if ($specControl.L1TFWindowsSupportEnabled -eq $true) {
                    $vulnerabilities["L1TF (L1 Terminal Fault / Foreshadow)"] = @{
                        Status = "mitigated"
                        Mitigation = "Windows L1TF mitigations enabled"
                    }
                } elseif ($specControl.L1TFWindowsSupportPresent -eq $true) {
                    $vulnerabilities["L1TF (L1 Terminal Fault / Foreshadow)"] = @{
                        Status = "vulnerable"
                        Mitigation = "L1TF mitigations available but not enabled"
                    }
                    $unmitigatedVulns++
                } else {
                    $vulnerabilities["L1TF (L1 Terminal Fault / Foreshadow)"] = @{
                        Status = "vulnerable"
                        Mitigation = "Not Mitigated"
                    }
                    $unmitigatedVulns++
                }
            } else {
                $vulnerabilities["L1TF (L1 Terminal Fault / Foreshadow)"] = @{
                    Status = "unknown"
                    Mitigation = "Unable to determine status"
                }
            }

            # ================================================================
            # MDS (Microarchitectural Data Sampling) - CVE-2018-12126/12127/12130, CVE-2019-11091
            # Includes MSBDS (Fallout), MFBDS (ZombieLoad), MLPDS, MDSUM
            # ================================================================
            if ($null -ne $specControl.MDSHardwareVulnerable) {
                if ($specControl.MDSHardwareVulnerable -eq $false) {
                    # CPU is not affected (AMD CPUs, newer Intel with hardware fix)
                    $vulnerabilities["MDS (Microarchitectural Data Sampling)"] = @{
                        Status = "not_affected"
                        Mitigation = "CPU not affected (hardware not vulnerable)"
                    }
                } elseif ($specControl.MDSWindowsSupportEnabled -eq $true) {
                    $vulnerabilities["MDS (Microarchitectural Data Sampling)"] = @{
                        Status = "mitigated"
                        Mitigation = "Windows MDS mitigations enabled (buffer overwrite on context switch)"
                    }
                } elseif ($specControl.MDSWindowsSupportPresent -eq $true) {
                    $vulnerabilities["MDS (Microarchitectural Data Sampling)"] = @{
                        Status = "vulnerable"
                        Mitigation = "MDS mitigations available but not enabled"
                    }
                    $unmitigatedVulns++
                } else {
                    $vulnerabilities["MDS (Microarchitectural Data Sampling)"] = @{
                        Status = "vulnerable"
                        Mitigation = "Not Mitigated"
                    }
                    $unmitigatedVulns++
                }
            } elseif ($null -ne $specControl.MDSWindowsSupportPresent -or $null -ne $specControl.MDSWindowsSupportEnabled) {
                # Fallback if MDSHardwareVulnerable is not available
                if ($specControl.MDSWindowsSupportEnabled -eq $true) {
                    $vulnerabilities["MDS (Microarchitectural Data Sampling)"] = @{
                        Status = "mitigated"
                        Mitigation = "Windows MDS mitigations enabled"
                    }
                } elseif ($specControl.MDSWindowsSupportPresent -eq $true) {
                    $vulnerabilities["MDS (Microarchitectural Data Sampling)"] = @{
                        Status = "vulnerable"
                        Mitigation = "MDS mitigations available but not enabled"
                    }
                    $unmitigatedVulns++
                } else {
                    $vulnerabilities["MDS (Microarchitectural Data Sampling)"] = @{
                        Status = "vulnerable"
                        Mitigation = "Not Mitigated"
                    }
                    $unmitigatedVulns++
                }
            } else {
                $vulnerabilities["MDS (Microarchitectural Data Sampling)"] = @{
                    Status = "unknown"
                    Mitigation = "Unable to determine status"
                }
            }

            # ================================================================
            # TAA (TSX Asynchronous Abort) - CVE-2019-11135
            # Only affects Intel CPUs with TSX (Transactional Synchronization Extensions)
            # ================================================================
            if ($null -ne $specControl.TAAHardwareVulnerable) {
                if ($specControl.TAAHardwareVulnerable -eq $false) {
                    $vulnerabilities["TAA (TSX Asynchronous Abort)"] = @{
                        Status = "not_affected"
                        Mitigation = "CPU not affected (TSX disabled or not present)"
                    }
                } elseif ($specControl.TAAWindowsSupportEnabled -eq $true) {
                    $vulnerabilities["TAA (TSX Asynchronous Abort)"] = @{
                        Status = "mitigated"
                        Mitigation = "Windows TAA mitigations enabled"
                    }
                } elseif ($specControl.TAAWindowsSupportPresent -eq $true) {
                    $vulnerabilities["TAA (TSX Asynchronous Abort)"] = @{
                        Status = "vulnerable"
                        Mitigation = "TAA mitigations available but not enabled"
                    }
                    $unmitigatedVulns++
                } else {
                    $vulnerabilities["TAA (TSX Asynchronous Abort)"] = @{
                        Status = "vulnerable"
                        Mitigation = "Not Mitigated"
                    }
                    $unmitigatedVulns++
                }
            }
            # Note: If TAAHardwareVulnerable is not present, the CPU likely doesn't have TSX
            # and is therefore not affected - we don't add an "unknown" entry

            # ================================================================
            # SBDR/SBDS (Shared Buffers Data Read/Sampling) - CVE-2022-21123/21125
            # Part of MMIO Stale Data vulnerabilities
            # ================================================================
            if ($null -ne $specControl.SBDRSSDPHardwareVulnerable) {
                if ($specControl.SBDRSSDPHardwareVulnerable -eq $false) {
                    $vulnerabilities["SBDR/SBDS (Shared Buffers Data Sampling)"] = @{
                        Status = "not_affected"
                        Mitigation = "CPU not affected (hardware not vulnerable)"
                    }
                } elseif ($specControl.FBClearEnabled -eq $true) {
                    $vulnerabilities["SBDR/SBDS (Shared Buffers Data Sampling)"] = @{
                        Status = "mitigated"
                        Mitigation = "Fill buffer clearing enabled"
                    }
                } else {
                    $vulnerabilities["SBDR/SBDS (Shared Buffers Data Sampling)"] = @{
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
# Add PowerShell version info banner
# ============================================================================
if (-not $isPowerShell7) {
    if ($usingPS7Wrapper -and $cpuidViaIntrinsics) {
        # PS5 running but using PS7 wrapper successfully
        $htmlOutput += @"
<div style='padding: 15px; margin-bottom: 20px; background-color: #d4edda; border-left: 5px solid #28a745; border-radius: 3px; box-shadow: 0 2px 4px rgba(0,0,0,0.1);'>
<div style='display: flex; align-items: flex-start;'>
<div style='font-size: 32px; margin-right: 15px; color: #28a745;'>✓</div>
<div>
<strong style='color: #155724; font-size: 16px;'>PowerShell 7 Wrapper Active</strong><br/>
<span style='color: #155724; font-size: 13px;'>
Script running in: <strong>PowerShell $powerShellVersion</strong><br/>
CPUID detection: <strong>PowerShell 7 wrapper (hardware-level accuracy)</strong><br/><br/>
This script detected PowerShell 7 on the system and used it to perform accurate hardware-level CPUID detection via .NET 5+ intrinsics, even though the script was launched from PowerShell $powerShellVersion.
</span>
</div>
</div>
</div>
"@
    } else {
        # PS5 running and PS7 not available or wrapper failed
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
<th style='padding: 12px; text-align: left; border: 1px solid #ddd; width: 45%;'>Feature</th>
<th style='padding: 12px; text-align: center; border: 1px solid #ddd; width: 20%;'>Supported</th>
<th style='padding: 12px; text-align: center; border: 1px solid #ddd; width: 20%;'>Enabled</th>
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

    # Format "Supported" column with color-coded icons
    if ($status -eq "supported") {
        $supportedHtml = "<span style='color: #27ae60; font-weight: bold;'>✓ Yes</span>"
    } else {
        $supportedHtml = "<span style='color: #95a5a6;'>✗ No</span>"
    }

    # Format "Enabled" column
    # Only show enabled/disabled for features that can be toggled (VMX, SVM, Hypervisor, NX)
    # All other features show "N/A" (not applicable - they can't be disabled)
    if ($featureCanBeDisabled -contains $featureKey) {
        $enabledStatus = $cpuFeaturesEnabled[$featureKey]
        if ($enabledStatus -eq "enabled") {
            $enabledHtml = "<span style='color: #27ae60; font-weight: bold;'>✓ Yes</span>"
        } elseif ($enabledStatus -eq "disabled") {
            $enabledHtml = "<span style='color: #e74c3c; font-weight: bold;'>✗ No</span>"
        } else {
            $enabledHtml = "<span style='color: #95a5a6;'>Unknown</span>"
        }
    } else {
        # Feature cannot be disabled - it's always enabled if supported
        $enabledHtml = "<span style='color: #95a5a6;'>N/A</span>"
    }

    $bgColor = if ($rowCount % 2 -eq 0) { "#f8f9fa" } else { "#ffffff" }

    $htmlOutput += @"
<tr style='background-color: $bgColor;'>
<td style='padding: 10px; border: 1px solid #ddd;'>$featureDesc</td>
<td style='padding: 10px; border: 1px solid #ddd; text-align: center;'>$supportedHtml</td>
<td style='padding: 10px; border: 1px solid #ddd; text-align: center;'>$enabledHtml</td>
</tr>
"@
    $rowCount++
}

$htmlOutput += @"
</tbody>
</table>
<div style='margin-top: 10px; padding: 12px; background-color: #f8f9fa; border-left: 4px solid #17a2b8; border-radius: 3px; font-size: 12px;'>
<strong style='color: #17a2b8;'>* Note on "Running under Hypervisor":</strong><br/>
<span style='color: #555;'>
On physical Windows 10/11 PCs, this may show as "Yes" even though the machine is not a virtual machine.
This is <strong>expected behavior</strong> when any of the following Windows features are enabled:
<ul style='margin: 8px 0 8px 20px; padding: 0;'>
<li>Hyper-V or Windows Hypervisor Platform</li>
<li>Windows Sandbox</li>
<li>WSL2 (Windows Subsystem for Linux 2)</li>
<li>Memory Integrity / Core Isolation (HVCI)</li>
<li>Credential Guard or Device Guard</li>
</ul>
When these features are active, Windows runs in a "Hyper-V root partition" mode where the OS kernel operates on top of Microsoft's hypervisor layer.
This is a <strong>positive security indicator</strong> showing that Virtualization-Based Security (VBS) is protecting your system.
</span>
</div>
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
<th style='padding: 12px; text-align: left; border: 1px solid #ddd;'>Vulnerability</th>
<th style='padding: 12px; text-align: left; border: 1px solid #ddd;'>CVE</th>
<th style='padding: 12px; text-align: center; border: 1px solid #ddd;'>Disclosed</th>
<th style='padding: 12px; text-align: center; border: 1px solid #ddd;'>Status</th>
<th style='padding: 12px; text-align: left; border: 1px solid #ddd;'>Mitigation / Remediation</th>
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

    # Get metadata for this vulnerability (CVE, date, MS article)
    $metadata = $vulnerabilityMetadata[$vulnName]
    $cveNumber = if ($metadata) { $metadata.CVE } else { "N/A" }
    $disclosureDate = if ($metadata) { $metadata.Date } else { "N/A" }
    $msArticle = if ($metadata) { $metadata.MSArticle } else { $null }

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

    # Build mitigation column content
    # Add remediation link for vulnerable status
    $mitigationHtml = $vulnMitigation
    if ($vulnStatus -eq "vulnerable" -and $msArticle) {
        $mitigationHtml += "<br/><a href='$msArticle' style='color: #2980b9; font-size: 11px;' target='_blank'>📄 Microsoft Guidance</a>"
    }

    # Truncate long mitigation strings for display (before adding link)
    if ($vulnMitigation.Length -gt 80) {
        $truncatedMitigation = $vulnMitigation.Substring(0, 77) + "..."
        if ($vulnStatus -eq "vulnerable" -and $msArticle) {
            $mitigationHtml = "$truncatedMitigation<br/><a href='$msArticle' style='color: #2980b9; font-size: 11px;' target='_blank'>📄 Microsoft Guidance</a>"
        } else {
            $mitigationHtml = $truncatedMitigation
        }
    }

    $bgColor = if ($rowCount % 2 -eq 0) { "#f8f9fa" } else { "#ffffff" }

    # Format CVE as link(s) to NIST NVD
    $cveHtml = ""
    if ($cveNumber -ne "N/A") {
        $cveList = $cveNumber -split ", "
        $cveLinks = @()
        foreach ($cve in $cveList) {
            $cve = $cve.Trim()
            $cveLinks += "<a href='https://nvd.nist.gov/vuln/detail/$cve' style='color: #2980b9; font-size: 11px;' target='_blank'>$cve</a>"
        }
        $cveHtml = $cveLinks -join "<br/>"
    } else {
        $cveHtml = "<span style='color: #95a5a6;'>N/A</span>"
    }

    $htmlOutput += @"
<tr style='background-color: $bgColor;'>
<td style='padding: 10px; border: 1px solid #ddd; font-weight: bold;'>$vulnName</td>
<td style='padding: 10px; border: 1px solid #ddd; font-size: 11px;'>$cveHtml</td>
<td style='padding: 10px; border: 1px solid #ddd; text-align: center; font-size: 11px;'>$disclosureDate</td>
<td style='padding: 10px; border: 1px solid #ddd; text-align: center;'>$statusHtml</td>
<td style='padding: 10px; border: 1px solid #ddd; font-size: 11px;'>$mitigationHtml</td>
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
    if ($usingPS7Wrapper) {
        "<span style='color: #27ae60; font-weight: bold;'>✓ Dynamic CPUID (Hardware via PS7 Wrapper)</span>"
    } else {
        "<span style='color: #27ae60; font-weight: bold;'>✓ Dynamic CPUID (Hardware, Native PS7)</span>"
    }
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
