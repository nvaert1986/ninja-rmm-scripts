# NinjaOne RMM CPU Information Script Documentation (Linux/Bash)

> **Note:** Parts of this script and documentation were written with the assistance of AI (Claude by Anthropic) to speed up the process of writing documentation, implementing logic, and generating HTML output.

> **Disclaimer:** Running this script is at your own risk. It has been tested on a limited set of hardware including Dell PowerEdge servers, Dell OptiPlex PCs, Dell Latitude and Dell Precision laptops, and some virtual machines running various Linux distributions. Results may vary on other hardware configurations or distributions.

## Overview

I created this Bash script to collect detailed CPU information from Linux systems and display it in a formatted HTML report within NinjaOne RMM's WYSIWYG custom field. The script provides comprehensive processor details including specifications, supported features, and security vulnerability status.

---

## Requirements

### Platform Requirements

- **Operating System**: Linux (any distribution with standard procfs and sysfs)
- **Architecture**: x86-64 (AMD64) processors only
- **Shell**: Bash 4.0 or later (for associative array support)
- **Kernel**: 4.14+ recommended (for full vulnerability reporting via sysfs)

### System Requirements

The script relies on the following standard Linux interfaces:

| Interface | Purpose | Required |
|-----------|---------|----------|
| `/proc/cpuinfo` | CPU model, vendor, family, model, stepping, flags | Yes |
| `/sys/devices/system/cpu/vulnerabilities/` | Security vulnerability status | No (graceful fallback) |
| `/sys/devices/system/cpu/cpu0/cpufreq/` | CPU frequency information | No (graceful fallback) |
| `/sys/devices/system/cpu/cpu0/cache/` | Cache size information | No (graceful fallback) |
| `lscpu` | Cache information (primary method) | No (graceful fallback) |

### NinjaOne Requirements

- NinjaOne RMM agent installed on the target system (`/opt/NinjaRMMAgent/`)
- A WYSIWYG-type custom field configured in NinjaOne to receive the HTML output
- Script variable `wysiwygcustomfield` configured in NinjaOne script deployment

> **Note:** NinjaOne converts all script variable names to lowercase. The script expects the variable `wysiwygcustomfield` (lowercase).

---

## What the Script Does

I designed this script to perform the following tasks:

1. **Validates the Environment**
   - Changes to `/tmp` to avoid getcwd errors when NinjaOne runs from inaccessible directories
   - Checks that the `wysiwygcustomfield` variable is set
   - Verifies the CPU architecture is x86-64 (AMD64)
   - Confirms `/proc/cpuinfo` exists and is readable

2. **Collects CPU Information**
   - Processor brand, vendor, family, model, and stepping from `/proc/cpuinfo`
   - Physical CPU count, cores per socket, logical processor count
   - Clock speeds (current, base, max) from sysfs cpufreq interface
   - Cache sizes (L1d, L1i, L2, L3) from `lscpu` or sysfs cache interface

3. **Detects CPU Features**
   - SIMD instructions: SSE, SSE2, SSE3, SSSE3, SSE4.1, SSE4.2, AVX, AVX2, AVX-512F
   - Encryption: AES-NI, PCLMULQDQ, SHA Extensions
   - Bit manipulation: BMI1, BMI2, POPCNT, LZCNT
   - Random number generation: RDRAND, RDSEED
   - Virtualization: VMX (Intel VT-x), SVM (AMD-V), EPT, VPID, Hypervisor detection
   - Memory: PAE, NX, 1GB Pages
   - Other: FMA3, F16C, MOVBE, XSAVE, OSXSAVE, ADX, RDTSCP, 64-bit Long Mode, SYSCALL

4. **Checks Security Vulnerabilities**
   - Spectre Variant 1 (Bounds Check Bypass)
   - Spectre Variant 2 (Branch Target Injection)
   - Spectre Variant 4 (Speculative Store Bypass)
   - Meltdown (Rogue Data Cache Load)
   - L1TF (L1 Terminal Fault / Foreshadow)
   - MDS (Microarchitectural Data Sampling)
   - TAA (TSX Asynchronous Abort)
   - iTLB Multihit
   - SRBDS (Special Register Buffer Data Sampling)
   - MMIO Stale Data
   - Retbleed
   - Spectre-BHI (Branch History Injection)
   - GDS (Gather Data Sampling)

5. **Generates HTML Report**
   - Creates a styled HTML document with tables for specifications, features, and vulnerabilities
   - Uses color-coded status indicators (green for supported/not affected, yellow for mitigated, red for vulnerable)
   - Includes a security status banner summarizing vulnerability state
   - Shows kernel version and architecture in footer

6. **Outputs to NinjaOne**
   - Writes the HTML report to the specified WYSIWYG custom field
   - Uses `ninjarmm-cli set --stdin` to handle large HTML content

---

## How the Script Performs This

### CPU Information Collection

I implemented multiple data sources to gather comprehensive CPU information:

#### Method 1: /proc/cpuinfo (Primary)
The script reads `/proc/cpuinfo` to extract:
- `model name` - Full CPU brand string
- `vendor_id` - CPU vendor (GenuineIntel, AuthenticAMD)
- `cpu family`, `model`, `stepping` - CPU identification numbers
- `cpu MHz` - Current operating frequency
- `physical id` - Physical socket identification (for multi-socket systems)
- `cpu cores` - Number of cores per physical socket
- `flags` - Space-separated list of CPU feature flags

#### Method 2: lscpu (Cache Information)
When available, `lscpu` provides formatted cache information:
- L1d cache (data)
- L1i cache (instruction)
- L2 cache
- L3 cache

#### Method 3: sysfs Interfaces (Fallback/Additional)
The script reads from sysfs for additional details:

**CPU Frequency** (`/sys/devices/system/cpu/cpu0/cpufreq/`):
- `cpuinfo_max_freq` - Maximum supported frequency
- `cpuinfo_min_freq` - Minimum supported frequency
- `scaling_max_freq` - Current scaling maximum (may indicate turbo)

**Cache Information** (`/sys/devices/system/cpu/cpu0/cache/`):
- `index0/size` through `index3/size` - Cache sizes when lscpu unavailable

### CPU Feature Detection

I detect CPU features by parsing the `flags` line from `/proc/cpuinfo`. The kernel exposes all CPU capabilities as space-separated flag names. The script checks for the presence of each feature flag using pattern matching.

| Flag | Feature |
|------|---------|
| `sse`, `sse2`, `sse3`, `ssse3`, `sse4_1`, `sse4_2` | SSE instruction sets |
| `avx`, `avx2`, `avx512f` | Advanced Vector Extensions |
| `aes` | AES-NI encryption instructions |
| `vmx` | Intel VT-x virtualization |
| `svm` | AMD-V virtualization |
| `hypervisor` | Running inside a virtual machine |
| `nx` | No-Execute bit (DEP support) |
| `lm` | 64-bit Long Mode |

> **Note on "Running under Hypervisor"**: This flag indicates the system is running as a virtual machine guest. Unlike Windows, Linux does not set this flag when running with KVM/QEMU on bare metal, even with virtualization extensions enabled for nested virtualization.

### Vulnerability Detection

I read vulnerability status from the kernel's sysfs interface at `/sys/devices/system/cpu/vulnerabilities/`. Each file in this directory contains the status for a specific vulnerability class.

The kernel reports one of the following states:
- **Not affected** - CPU hardware is not vulnerable to this attack
- **Vulnerable** - CPU is vulnerable and no mitigation is active
- **Mitigation: [details]** - CPU is vulnerable but mitigation is enabled

The script parses these states and displays:
- Green checkmark for "Not Affected"
- Yellow warning for "Mitigated" (with mitigation details)
- Red X for "Vulnerable" (unmitigated)

> **Note:** Vulnerability reporting requires kernel 4.14 or later. Older kernels may not expose the `/sys/devices/system/cpu/vulnerabilities/` directory, in which case the script displays a notice that vulnerability information is unavailable.

### NinjaOne Integration

I use the NinjaOne CLI tool to set the custom field value:

```bash
echo "$HTML_OUTPUT" | /opt/NinjaRMMAgent/programdata/ninjarmm-cli set --stdin "$wysiwygCustomField"
```

The `--stdin` flag allows piping large HTML content without command-line length limitations.

---

## How to Use with NinjaOne RMM

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
   - **Name**: `CPU Information Collector (Linux)`
   - **Language**: Shell Script
   - **OS**: Linux / Mac
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
1. Navigate to a Linux device in NinjaOne
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
| 0 | Success - No unmitigated security vulnerabilities detected |
| 1 | Error - Script failed (custom field not set, /proc/cpuinfo not found, etc.) |
| 4 | Warning - Unmitigated CPU vulnerabilities detected |

The exit code 4 can be used to create alerts in NinjaOne when devices have unmitigated security vulnerabilities.

---

## Troubleshooting

### Common Issues

**"wysiwygCustomField variable is not set"**
- Ensure you've added the script variable in NinjaOne
- Verify the variable name is lowercase: `wysiwygcustomfield`

**HTML appears as raw text instead of formatted**
- Ensure the custom field type is WYSIWYG, not Text or Multi-line Text

**"Unsupported Architecture" message**
- This script only supports x86-64 (AMD64) processors
- ARM, ARM64, and other architectures are not supported

**No vulnerability information displayed**
- Update your kernel to version 4.14 or later
- Verify `/sys/devices/system/cpu/vulnerabilities/` directory exists
- Check that the kernel was compiled with `CONFIG_CPU_VULNERABILITIES=y`

**Cache information shows "N/A"**
- Install `util-linux` package for `lscpu` command
- Alternatively, verify sysfs cache interface exists at `/sys/devices/system/cpu/cpu0/cache/`

**Frequency information shows "N/A"**
- The cpufreq driver may not be loaded
- Some virtualized environments don't expose frequency controls
- Check if `/sys/devices/system/cpu/cpu0/cpufreq/` exists

**Script fails with "getcwd" errors**
- This is handled automatically by changing to `/tmp` at script start
- If issues persist, verify `/tmp` is accessible

---

## Version History

| Version | Date | Changes |
|---------|------|---------|
| 1.0 | 2025-01 | Initial Linux/Bash release with CPU info, features, and vulnerability detection via kernel sysfs interface |
