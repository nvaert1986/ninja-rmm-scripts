# NinjaOne RMM CPU Information Script Documentation

> **Note:** Parts of this script and documentation were written with the assistance of AI (Claude by Anthropic) to speed up the process of writing documentation, implementing logic, and generating HTML output.

> **Disclaimer:** Running this script is at your own risk. It has been tested on a limited set of hardware including Dell PowerEdge servers, Dell OptiPlex PCs, Dell Latitude and Dell Precision laptops, and some virtual machines. Results may vary on other hardware configurations.

## Overview

I created this PowerShell script to collect detailed CPU information from Windows systems and display it in a formatted HTML report within NinjaOne RMM's WYSIWYG custom field. The script provides comprehensive processor details including specifications, supported features, and security vulnerability status.

---

## Requirements

### Platform Requirements

- **Operating System**: Windows (any version supporting PowerShell)
- **Architecture**: x86-64 (AMD64) processors only
- **PowerShell Version**:
  - Windows PowerShell 5.1 (minimum, uses fallback detection methods)
  - PowerShell 7.x (recommended for accurate hardware-level CPUID detection)

### NinjaOne Requirements

- NinjaOne RMM agent installed on the target system
- A WYSIWYG-type custom field configured in NinjaOne to receive the HTML output
- Script variable `wysiwygcustomfield` configured in NinjaOne script deployment

> **Note: NinjaOne PowerShell 7 Support**
>
> NinjaOne RMM does not natively support PowerShell 7 for script execution. All scripts run through NinjaOne use Windows PowerShell 5.1 by default. However, **this script now includes a built-in PowerShell 7 wrapper** (`Invoke-PS7Command`) that automatically detects if PowerShell 7 is installed and uses it for accurate hardware-level CPUID detection, even when the script is launched from PowerShell 5.1.
>
> If PowerShell 7 is installed on the target system, the script will automatically leverage it for the best detection accuracy without any additional configuration.

### External PowerShell Modules

| Module | Source | Purpose | Auto-Install |
|--------|--------|---------|--------------|
| **SpeculationControl** | PowerShell Gallery (Microsoft) | Checks CPU security vulnerabilities (Spectre, Meltdown, etc.) | Yes |

The script automatically attempts to install the `SpeculationControl` module from the PowerShell Gallery if it's not present. This requires:
- PowerShellGet module (usually pre-installed)
- NuGet package provider (auto-installed if missing)
- Network access to PowerShell Gallery (psget.net)

---

## What the Script Does

I designed this script to perform the following tasks:

1. **Validates the Environment**
   - Checks that the `wysiwygcustomfield` variable is set
   - Verifies the CPU architecture is x86-64 (AMD64)
   - Detects PowerShell version and warns if not using PowerShell 7+

2. **Installs Required Dependencies**
   - Automatically installs the Microsoft SpeculationControl module if not present
   - Sets PSGallery as trusted to avoid interactive prompts
   - Installs NuGet provider if needed

3. **Collects CPU Information**
   - Processor brand, vendor, family, model, and stepping
   - Physical CPU count, cores per socket, logical processor count
   - Clock speeds (current, base, max, turbo)
   - Cache sizes (L1, L2, L3)

4. **Detects CPU Features**
   - SIMD instructions: SSE, SSE2, SSE3, SSSE3, SSE4.1, SSE4.2, AVX, AVX2, AVX-512
   - Encryption: AES-NI, PCLMULQDQ, SHA
   - Bit manipulation: BMI1, BMI2, POPCNT, LZCNT
   - Random number generation: RDRAND, RDSEED
   - Virtualization: VMX (Intel VT-x), SVM (AMD-V), Hypervisor detection
   - Other: FMA, F16C, MOVBE, XSAVE, ADX, PAE, NX, 1GB Pages, RDTSCP, 64-bit

5. **Checks Security Vulnerabilities**
   - Spectre Variant 1 (Bounds Check Bypass) - CVE-2017-5753
   - Spectre Variant 2 (Branch Target Injection) - CVE-2017-5715
   - Meltdown (Rogue Data Cache Load) - CVE-2017-5754
   - Spectre Variant 4 (Speculative Store Bypass) - CVE-2018-3639
   - L1TF (L1 Terminal Fault / Foreshadow) - CVE-2018-3615/3620/3646
   - MDS (Microarchitectural Data Sampling) - CVE-2018-12126/12127/12130, CVE-2019-11091
   - TAA (TSX Asynchronous Abort) - CVE-2019-11135
   - SBDR/SBDS (Shared Buffers Data Sampling / MMIO Stale Data) - CVE-2022-21123/21125

6. **Generates HTML Report**
   - Creates a styled HTML document with tables for specifications, features, and vulnerabilities
   - Uses color-coded status indicators (green for supported/mitigated, red for vulnerable)
   - CPU Features table with both "Supported" and "Enabled" columns (for features that can be disabled in BIOS/OS)
   - Vulnerability table with CVE numbers, disclosure dates, and links to Microsoft remediation guidance
   - Includes a security status banner summarizing vulnerability state
   - Shows detection method used (hardware CPUID vs fallback, native PS7 vs PS7 wrapper)

7. **Outputs to NinjaOne**
   - Writes the HTML report to the specified WYSIWYG custom field
   - Uses `Ninja-Property-Set` cmdlet (preferred) or `ninjarmm-cli.exe` (fallback)

---

## How the Script Performs This

### CPU Feature Detection Methods

I implemented a multi-layered detection approach to maximize accuracy across different environments:

#### Method 1: .NET 5+ CPUID Intrinsics (Most Accurate)
When PowerShell 7+ is available, I use `System.Runtime.Intrinsics.X86.X86Base::CpuId()` to query the CPU directly. This method:
- Reads CPUID function 1 (standard features) - ECX and EDX registers
- Reads CPUID function 7 (extended features) - EBX and ECX registers
- Reads CPUID function 0x80000001 (AMD extended features) - ECX and EDX registers
- Provides hardware-level accuracy by querying the CPU instruction set directly

**PowerShell 7 Wrapper (`Invoke-PS7Command`)**: When the script runs in PowerShell 5.1 but PowerShell 7 is installed on the system, the script automatically uses a wrapper function to execute the CPUID detection in PowerShell 7. This wrapper:
- Detects PowerShell 7 installation via common paths and PATH environment variable
- Encodes scripts and parameters as Base64 to avoid escaping issues
- Executes the code in `pwsh.exe` and returns results via JSON serialization
- Provides hardware-level CPUID accuracy even when launched from PowerShell 5.1

#### Method 2: Registry Fallback
When CPUID intrinsics aren't available, I read from:
- `HKLM:\HARDWARE\DESCRIPTION\System\CentralProcessor\0`
- CPU Identifier string for feature flags
- Win32_Processor WMI properties for basic features (PAE, NX, virtualization)

#### Method 3: Windows API (IsProcessorFeaturePresent)
I use inline C# code to call `kernel32.dll!IsProcessorFeaturePresent()` with Windows API feature codes (PF_* constants) to detect supported instructions.

#### Method 4: Model-Based Inference
As a last resort, I infer feature support based on CPU model name patterns:
- Modern Intel: Core iX 4th gen+, Xeon E3/E5/E7 v3+, Xeon Scalable
- Modern AMD: Ryzen, EPYC, Threadripper

### CPU Feature Status: Supported vs Enabled

The CPU Features table displays two columns:

| Column | Description |
|--------|-------------|
| **Supported** | Whether the CPU hardware supports this feature |
| **Enabled** | Whether the feature is currently enabled (for toggleable features) |

Most CPU features (SSE, AVX, AES, etc.) cannot be disabled - they're always enabled if supported, so these show "N/A" in the Enabled column.

The following features CAN be enabled/disabled and show their actual status:

| Feature | Can Be Disabled In |
|---------|-------------------|
| **VMX** (Intel VT-x) | BIOS/UEFI settings |
| **SVM** (AMD-V) | BIOS/UEFI settings |
| **Hypervisor** | Windows Features (Hyper-V, etc.) |
| **NX** (DEP) | Windows settings (rare) |

> **Note on "Running under Hypervisor"**: On physical Windows 10/11 PCs, this may show as "Enabled" even though the machine is not a virtual machine. This is expected behavior when Hyper-V, Windows Sandbox, WSL2, Memory Integrity (Core Isolation), Credential Guard, or Device Guard is enabled. Windows runs in a "Hyper-V root partition" mode where the OS kernel operates on top of Microsoft's hypervisor layer. This is a positive security indicator.

### Vulnerability Detection

I use the Microsoft SpeculationControl module's `Get-SpeculationControlSettings` cmdlet to check:
- BTIHardwarePresent / BTIWindowsSupportEnabled (Spectre V1/V2)
- KVAShadowRequired / KVAShadowWindowsSupportEnabled (Meltdown)
- SSBDHardwareVulnerable / SSBDWindowsSupportEnabled (Spectre V4)
- L1TFHardwareVulnerable / L1TFWindowsSupportEnabled (L1TF)
- MDSHardwareVulnerable / MDSWindowsSupportEnabled (MDS)
- TAAHardwareVulnerable / TAAWindowsSupportEnabled (TAA)
- SBDRSSDPHardwareVulnerable / FBClearEnabled (SBDR/SBDS)

The vulnerability table includes:
- CVE numbers with links to NIST NVD
- Disclosure dates
- Microsoft remediation guidance links (for vulnerable status)
- Hardware vulnerability status (Not Affected for CPUs that aren't vulnerable)

If the module isn't available, I fall back to checking registry keys:
- `HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management\FeatureSettingsOverride`

### NinjaOne Integration

I implemented two methods to set the custom field value:

1. **Ninja-Property-Set cmdlet** (preferred)
   - Native PowerShell cmdlet provided by NinjaOne agent
   - Direct integration with NinjaOne services

2. **ninjarmm-cli.exe with --stdin** (fallback)
   - Located at `C:\ProgramData\NinjaRMMAgent\ninjarmm-cli.exe`
   - Uses temporary file + pipe to handle large HTML content
   - UTF-8 encoding for special characters

---

## How to Use with Ninja RMM

### Step 1: Create the Custom Field

1. Log in to NinjaOne admin portal
2. Navigate to **Administration** > **Devices** > **Role Custom Fields** (or Global Custom Fields)
3. Click **Add** to create a new custom field
4. Configure the field:
   - **Label**: `CPU Information` (or your preferred name)
   - **Name**: `cpuinfo` (API name, remember this)
   - **Field Type**: **WYSIWYG** (important - must be WYSIWYG for HTML rendering)
   - **Technician Permission**: Read Only (or as needed)
   - **Automations**: Read/Write
5. Save the custom field

### Step 2: Upload the Script

1. Navigate to **Administration** > **Library** > **Automation**
2. Click **Add** > **New Script**
3. Configure:
   - **Name**: `CPU Information Collector`
   - **Language**: PowerShell
   - **OS**: Windows
   - **Architecture**: All (script handles architecture validation)
4. Paste the script content
5. Save the script

### Step 3: Configure Script Variables

1. In the script editor, click **Script Variables**
2. Add a new variable:
   - **Variable Name**: `wysiwygcustomfield`
   - **Variable Type**: Text
   - **Default Value**: `cpuinfo` (the API name from Step 1)
   - **Required**: Yes
3. Save the variable

### Step 4: Run the Script

#### Manual Execution
1. Navigate to a device in NinjaOne
2. Click **Run Script** or use the Actions menu
3. Select your script
4. Verify the `wysiwygcustomfield` value matches your custom field API name
5. Run the script

#### Scheduled Execution
1. Create a scheduled task or policy
2. Add the script as an action
3. Configure the schedule (e.g., daily, weekly)
4. Ensure the script variable is set correctly

#### Condition-Based Execution
1. Create a condition in NinjaOne
2. Trigger the script based on events (e.g., device checkin, alert)

### Step 5: View the Results

1. Navigate to a device that has run the script
2. Go to the device's **Details** tab
3. Find your custom field (e.g., "CPU Information")
4. The HTML report will be displayed with:
   - Processor specifications table
   - CPU features table with support status
   - Security vulnerabilities table with mitigation status

### Script Variable Reference

| Variable | Type | Required | Description |
|----------|------|----------|-------------|
| `wysiwygcustomfield` | Text | Yes | The API name of the WYSIWYG custom field where the HTML output will be written. This must match the "Name" field (not the Label) of your custom field in NinjaOne. |

### Exit Codes

| Code | Meaning |
|------|---------|
| 0 | Success - No security issues detected |
| 1 | Error - Script failed (custom field not set, WMI failure, etc.) |
| 4 | Warning - Unmitigated CPU vulnerabilities detected |

The exit code 4 can be used to create alerts in NinjaOne when devices have unmitigated security vulnerabilities.

---

## Troubleshooting

### Common Issues

**"wysiwygcustomfield variable is not set"**
- Ensure you've added the script variable in NinjaOne
- Verify the variable name matches exactly: `wysiwygcustomfield`

**HTML appears as raw text instead of formatted**
- Ensure the custom field type is WYSIWYG, not Text or Multi-line Text

**SpeculationControl module won't install**
- Check network connectivity to psget.net
- Verify PowerShellGet is available
- Check firewall rules aren't blocking PowerShell Gallery

**Fallback methods warning displayed**
- Install PowerShell 7 for accurate hardware detection
- Download from https://aka.ms/powershell or run `winget install Microsoft.PowerShell`

---

## Version History

| Version | Date | Changes |
|---------|------|---------|
| 1.1 | 2025-12-24 | **PowerShell 7 Wrapper**: Added `Invoke-PS7Command` function that automatically uses PowerShell 7 for CPUID detection when running in PS5.1, providing hardware-level accuracy without manual configuration. **Additional Vulnerabilities**: Added detection for Meltdown (CVE-2017-5754), TAA (CVE-2019-11135), and SBDR/SBDS (CVE-2022-21123/21125). **Enhanced Vulnerability Table**: Added CVE numbers with NIST NVD links, disclosure dates, and Microsoft remediation guidance links. **Supported vs Enabled Columns**: CPU Features table now shows both whether a feature is supported AND whether it's enabled (for VMX, SVM, Hypervisor, NX). **Bug Fixes**: Fixed incorrect detection of PAE, NX, and VMX features in WMI fallback mode. **Hypervisor Note**: Added explanatory note about why physical PCs may show "Running under Hypervisor" when VBS features are enabled. |
| 1.0 | Initial | Initial release with CPU info, features, and vulnerability detection |
