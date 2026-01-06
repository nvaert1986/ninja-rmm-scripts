#!/bin/bash

# Change to a safe directory to avoid getcwd errors when NinjaOne runs from a deleted/inaccessible directory
cd /tmp 2>/dev/null || cd / 2>/dev/null || true

# NinjaOne RMM Script - CPU Information with Security Analysis
# Displays detailed CPU information including specifications, features, and security vulnerabilities
# Designed for x86-64 (AMD64) processors only

# Script Variable - Set this in NinjaOne when deploying the script
# This should be the name of your WYSIWYG custom field
# Note: NinjaOne converts variable names to lowercase
wysiwygCustomField="${wysiwygcustomfield}"

# Validate that the custom field variable is set
if [ -z "$wysiwygCustomField" ]; then
    echo "ERROR: wysiwygCustomField variable is not set. Please configure the script variable in NinjaOne."
    exit 1
fi

# Check if we're on an x86-64 system
ARCH=$(uname -m)
if [[ ! "$ARCH" =~ ^(x86_64|amd64)$ ]]; then
    HTML_OUTPUT="<div style='padding: 15px; background-color: #fff3cd; border: 1px solid #ffc107; border-radius: 5px;'><strong>⚠️ Unsupported Architecture</strong><br/>This script is designed for x86-64 (AMD64) processors only. Detected architecture: <code>$ARCH</code></div>"
    echo "$HTML_OUTPUT" | /opt/NinjaRMMAgent/programdata/ninjarmm-cli set --stdin "$wysiwygCustomField"
    echo "Unsupported architecture: $ARCH (x86-64 only)"
    exit 0
fi

# Check if required files exist
if [ ! -f /proc/cpuinfo ]; then
    HTML_OUTPUT="<div style='padding: 15px; background-color: #f8d7da; border: 1px solid #dc3545; border-radius: 5px;'><strong>❌ /proc/cpuinfo Not Found</strong><br/>Unable to read CPU information from /proc/cpuinfo</div>"
    echo "$HTML_OUTPUT" | /opt/NinjaRMMAgent/programdata/ninjarmm-cli set --stdin "$wysiwygCustomField"
    echo "/proc/cpuinfo not found"
    exit 1
fi

# Get CPU information from /proc/cpuinfo
CPUINFO=$(cat /proc/cpuinfo 2>/dev/null)

# Extract CPU model name
CPU_MODEL=$(echo "$CPUINFO" | grep -m1 "^model name" | cut -d':' -f2 | sed 's/^[[:space:]]*//;s/[[:space:]]*$//')
if [ -z "$CPU_MODEL" ]; then
    CPU_MODEL="Unknown CPU"
fi

# Extract vendor
CPU_VENDOR=$(echo "$CPUINFO" | grep -m1 "^vendor_id" | cut -d':' -f2 | sed 's/^[[:space:]]*//;s/[[:space:]]*$//')

# Extract CPU family, model, stepping
CPU_FAMILY=$(echo "$CPUINFO" | grep -m1 "^cpu family" | cut -d':' -f2 | sed 's/^[[:space:]]*//;s/[[:space:]]*$//')
CPU_MODEL_NUM=$(echo "$CPUINFO" | grep -m1 "^model[[:space:]]*:" | cut -d':' -f2 | sed 's/^[[:space:]]*//;s/[[:space:]]*$//')
CPU_STEPPING=$(echo "$CPUINFO" | grep -m1 "^stepping" | cut -d':' -f2 | sed 's/^[[:space:]]*//;s/[[:space:]]*$//')

# Extract current CPU frequency (in MHz)
CPU_MHZ=$(echo "$CPUINFO" | grep -m1 "^cpu MHz" | cut -d':' -f2 | sed 's/^[[:space:]]*//;s/[[:space:]]*$//')
if [ -n "$CPU_MHZ" ] && [[ "$CPU_MHZ" =~ ^[0-9]+\.?[0-9]*$ ]]; then
    CPU_GHZ=$(awk "BEGIN {printf \"%.2f\", $CPU_MHZ / 1000}")
else
    CPU_GHZ="Unknown"
fi

# Get number of physical and logical CPUs
PHYSICAL_CPUS=$(echo "$CPUINFO" | grep "^physical id" | sort -u | wc -l)
if [ "$PHYSICAL_CPUS" -eq 0 ]; then
    PHYSICAL_CPUS=1
fi
LOGICAL_CPUS=$(echo "$CPUINFO" | grep "^processor" | wc -l)
CORES_PER_SOCKET=$(echo "$CPUINFO" | grep -m1 "^cpu cores" | cut -d':' -f2 | sed 's/^[[:space:]]*//;s/[[:space:]]*$//')
if [ -z "$CORES_PER_SOCKET" ]; then
    CORES_PER_SOCKET=$LOGICAL_CPUS
fi

# Get cache information
CACHE_L1D=$(lscpu 2>/dev/null | grep "L1d cache:" | awk '{print $3 " " $4}' | sed 's/[[:space:]]*$//')
CACHE_L1I=$(lscpu 2>/dev/null | grep "L1i cache:" | awk '{print $3 " " $4}' | sed 's/[[:space:]]*$//')
CACHE_L2=$(lscpu 2>/dev/null | grep "L2 cache:" | awk '{print $3 " " $4}' | sed 's/[[:space:]]*$//')
CACHE_L3=$(lscpu 2>/dev/null | grep "L3 cache:" | awk '{print $3 " " $4}' | sed 's/[[:space:]]*$//')

# Fallback to /sys if lscpu not available
if [ -z "$CACHE_L1D" ] && [ -f /sys/devices/system/cpu/cpu0/cache/index0/size ]; then
    CACHE_L1D=$(cat /sys/devices/system/cpu/cpu0/cache/index0/size 2>/dev/null)
fi
if [ -z "$CACHE_L1I" ] && [ -f /sys/devices/system/cpu/cpu0/cache/index1/size ]; then
    CACHE_L1I=$(cat /sys/devices/system/cpu/cpu0/cache/index1/size 2>/dev/null)
fi
if [ -z "$CACHE_L2" ] && [ -f /sys/devices/system/cpu/cpu0/cache/index2/size ]; then
    CACHE_L2=$(cat /sys/devices/system/cpu/cpu0/cache/index2/size 2>/dev/null)
fi
if [ -z "$CACHE_L3" ] && [ -f /sys/devices/system/cpu/cpu0/cache/index3/size ]; then
    CACHE_L3=$(cat /sys/devices/system/cpu/cpu0/cache/index3/size 2>/dev/null)
fi

# Set defaults
[ -z "$CACHE_L1D" ] && CACHE_L1D="N/A"
[ -z "$CACHE_L1I" ] && CACHE_L1I="N/A"
[ -z "$CACHE_L2" ] && CACHE_L2="N/A"
[ -z "$CACHE_L3" ] && CACHE_L3="N/A"

# Get CPU frequency information
CPU_MAX_FREQ="N/A"
CPU_MIN_FREQ="N/A"
CPU_TURBO_FREQ="N/A"

if [ -f /sys/devices/system/cpu/cpu0/cpufreq/cpuinfo_max_freq ]; then
    MAX_FREQ_KHZ=$(cat /sys/devices/system/cpu/cpu0/cpufreq/cpuinfo_max_freq 2>/dev/null)
    if [ -n "$MAX_FREQ_KHZ" ] && [[ "$MAX_FREQ_KHZ" =~ ^[0-9]+$ ]]; then
        CPU_MAX_FREQ=$(awk "BEGIN {printf \"%.2f GHz\", $MAX_FREQ_KHZ / 1000000}")
    fi
fi

if [ -f /sys/devices/system/cpu/cpu0/cpufreq/cpuinfo_min_freq ]; then
    MIN_FREQ_KHZ=$(cat /sys/devices/system/cpu/cpu0/cpufreq/cpuinfo_min_freq 2>/dev/null)
    if [ -n "$MIN_FREQ_KHZ" ] && [[ "$MIN_FREQ_KHZ" =~ ^[0-9]+$ ]]; then
        CPU_MIN_FREQ=$(awk "BEGIN {printf \"%.2f GHz\", $MIN_FREQ_KHZ / 1000000}")
    fi
fi

# Try to get turbo frequency (this varies by CPU vendor)
if [ -f /sys/devices/system/cpu/cpu0/cpufreq/scaling_max_freq ]; then
    SCALING_MAX_KHZ=$(cat /sys/devices/system/cpu/cpu0/cpufreq/scaling_max_freq 2>/dev/null)
    if [ -n "$SCALING_MAX_KHZ" ] && [ -n "$MAX_FREQ_KHZ" ] && [[ "$SCALING_MAX_KHZ" =~ ^[0-9]+$ ]] && [[ "$MAX_FREQ_KHZ" =~ ^[0-9]+$ ]]; then
        if [ "$SCALING_MAX_KHZ" -gt "$MAX_FREQ_KHZ" ]; then
            CPU_TURBO_FREQ=$(awk "BEGIN {printf \"%.2f GHz\", $SCALING_MAX_KHZ / 1000000}")
        fi
    fi
fi

# Extract CPU flags for feature detection
CPU_FLAGS=$(echo "$CPUINFO" | grep -m1 "^flags" | cut -d':' -f2)

# Define x86-64 CPU features to check
declare -A CPU_FEATURES=(
    ["sse"]="SSE (Streaming SIMD Extensions)"
    ["sse2"]="SSE2 (Streaming SIMD Extensions 2)"
    ["sse3"]="SSE3 (Streaming SIMD Extensions 3)"
    ["ssse3"]="SSSE3 (Supplemental SSE3)"
    ["sse4_1"]="SSE4.1"
    ["sse4_2"]="SSE4.2"
    ["avx"]="AVX (Advanced Vector Extensions)"
    ["avx2"]="AVX2 (Advanced Vector Extensions 2)"
    ["avx512f"]="AVX-512F (Foundation)"
    ["aes"]="AES-NI (AES Instruction Set)"
    ["pclmulqdq"]="PCLMULQDQ (Carry-less Multiplication)"
    ["sha_ni"]="SHA Extensions"
    ["rdrand"]="RDRAND (Hardware RNG)"
    ["rdseed"]="RDSEED (Hardware RNG Seed)"
    ["fma"]="FMA3 (Fused Multiply-Add)"
    ["bmi1"]="BMI1 (Bit Manipulation Instructions)"
    ["bmi2"]="BMI2 (Bit Manipulation Instructions 2)"
    ["adx"]="ADX (Multi-Precision Add-Carry)"
    ["f16c"]="F16C (16-bit Floating Point Conversion)"
    ["popcnt"]="POPCNT (Population Count)"
    ["lzcnt"]="LZCNT (Leading Zero Count)"
    ["movbe"]="MOVBE (Move Data After Swapping Bytes)"
    ["xsave"]="XSAVE (Extended State Save/Restore)"
    ["osxsave"]="OSXSAVE (OS-Enabled Extended State Management)"
    ["pae"]="PAE (Physical Address Extension)"
    ["nx"]="NX (No-Execute Bit)"
    ["pdpe1gb"]="1GB Pages Support"
    ["rdtscp"]="RDTSCP (Read Time-Stamp Counter)"
    ["lm"]="64-bit Long Mode"
    ["syscall"]="SYSCALL/SYSRET Instructions"
    ["vmx"]="VMX (Intel Virtualization)"
    ["svm"]="SVM (AMD Virtualization)"
    ["ept"]="EPT (Extended Page Tables)"
    ["vpid"]="VPID (Virtual Processor ID)"
    ["hypervisor"]="Running under Hypervisor"
)

# Define CPU security vulnerabilities to check
declare -A CPU_VULNS=(
    ["spectre_v1"]="Spectre Variant 1 (Bounds Check Bypass)"
    ["spectre_v2"]="Spectre Variant 2 (Branch Target Injection)"
    ["spec_store_bypass"]="Spectre Variant 4 (Speculative Store Bypass)"
    ["l1tf"]="L1TF (L1 Terminal Fault / Foreshadow)"
    ["mds"]="MDS (Microarchitectural Data Sampling)"
    ["tsx_async_abort"]="TAA (TSX Asynchronous Abort)"
    ["itlb_multihit"]="iTLB Multihit"
    ["srbds"]="SRBDS (Special Register Buffer Data Sampling)"
    ["mmio_stale_data"]="MMIO Stale Data"
    ["retbleed"]="Retbleed"
    ["meltdown"]="Meltdown (Rogue Data Cache Load)"
    ["spectre_v1_swapgs"]="Spectre Variant 1 (SWAPGS)"
    ["spectre_bhi"]="Spectre-BHI (Branch History Injection)"
    ["gds"]="GDS (Gather Data Sampling)"
)

# Check which features are supported
declare -A FEATURE_STATUS
for feature in "${!CPU_FEATURES[@]}"; do
    if echo "$CPU_FLAGS" | grep -qw "$feature"; then
        FEATURE_STATUS[$feature]="supported"
    else
        FEATURE_STATUS[$feature]="not_supported"
    fi
done

# Check CPU vulnerabilities from /sys/devices/system/cpu/vulnerabilities/
declare -A VULN_STATUS
declare -A VULN_MITIGATION
VULNERABILITIES_FOUND=0
UNMITIGATED_VULNS=0

if [ -d /sys/devices/system/cpu/vulnerabilities ]; then
    for vuln_file in /sys/devices/system/cpu/vulnerabilities/*; do
        if [ -f "$vuln_file" ]; then
            vuln_name=$(basename "$vuln_file")
            vuln_status=$(cat "$vuln_file" 2>/dev/null)

            # Determine if vulnerable
            if echo "$vuln_status" | grep -qiE "^Not affected|^Processor vulnerable: no"; then
                VULN_STATUS[$vuln_name]="not_affected"
                VULN_MITIGATION[$vuln_name]="Not Applicable"
            elif echo "$vuln_status" | grep -qiE "^Vulnerable|^Vulnerable:"; then
                VULN_STATUS[$vuln_name]="vulnerable"
                VULN_MITIGATION[$vuln_name]="Not Mitigated"
                VULNERABILITIES_FOUND=$((VULNERABILITIES_FOUND + 1))
                UNMITIGATED_VULNS=$((UNMITIGATED_VULNS + 1))
            elif echo "$vuln_status" | grep -qiE "^Mitigation"; then
                VULN_STATUS[$vuln_name]="mitigated"
                # Extract mitigation details
                MITIGATION_DETAIL=$(echo "$vuln_status" | sed 's/^Mitigation: //')
                VULN_MITIGATION[$vuln_name]="$MITIGATION_DETAIL"
                VULNERABILITIES_FOUND=$((VULNERABILITIES_FOUND + 1))
            else
                VULN_STATUS[$vuln_name]="unknown"
                VULN_MITIGATION[$vuln_name]="$vuln_status"
            fi
        fi
    done
fi

# Build HTML output
HTML_OUTPUT="<div style='font-family: Arial, sans-serif;'>"
HTML_OUTPUT+="<h2 style='color: #2c3e50; margin-bottom: 10px;'>🔧 CPU Information</h2>"

# Summary banner
HTML_OUTPUT+="<div style='padding: 10px; margin-bottom: 15px; background-color: #f8f9fa; border-left: 4px solid #3498db; border-radius: 3px;'>"
HTML_OUTPUT+="<strong style='color: #3498db;'>Processor:</strong> $CPU_MODEL<br/>"
HTML_OUTPUT+="<strong style='color: #3498db;'>Architecture:</strong> x86-64 (AMD64)"
HTML_OUTPUT+="</div>"

HTML_OUTPUT+="<p style='color: #7f8c8d; margin-bottom: 20px;'>"
HTML_OUTPUT+="Physical CPUs: <strong>$PHYSICAL_CPUS</strong> | "
HTML_OUTPUT+="Cores per Socket: <strong>$CORES_PER_SOCKET</strong> | "
HTML_OUTPUT+="Logical CPUs: <strong>$LOGICAL_CPUS</strong> | "
HTML_OUTPUT+="Last Updated: <strong>$(date '+%Y-%m-%d %H:%M:%S')</strong>"
HTML_OUTPUT+="</p>"

# CPU Specifications Table
HTML_OUTPUT+="<h3 style='color: #2c3e50; margin-top: 20px; margin-bottom: 10px;'>Processor Specifications</h3>"
HTML_OUTPUT+="<table style='width: 100%; border-collapse: collapse; box-shadow: 0 2px 4px rgba(0,0,0,0.1); margin-bottom: 20px;'>"
HTML_OUTPUT+="<thead>"
HTML_OUTPUT+="<tr style='background-color: #3498db; color: white;'>"
HTML_OUTPUT+="<th style='padding: 12px; text-align: left; border: 1px solid #ddd; width: 30%;'>Property</th>"
HTML_OUTPUT+="<th style='padding: 12px; text-align: left; border: 1px solid #ddd;'>Value</th>"
HTML_OUTPUT+="</tr>"
HTML_OUTPUT+="</thead>"
HTML_OUTPUT+="<tbody>"

# Add rows to specifications table
SPEC_ROWS=(
    "Brand|$CPU_MODEL"
    "Vendor|$CPU_VENDOR"
    "CPU Family|$CPU_FAMILY"
    "Model Number|$CPU_MODEL_NUM"
    "Stepping|$CPU_STEPPING"
    "Current Clock Speed|$CPU_GHZ GHz"
    "Base Clock Speed|$CPU_MIN_FREQ"
    "Max Clock Speed|$CPU_MAX_FREQ"
    "Turbo/Boost Speed|$CPU_TURBO_FREQ"
    "L1 Data Cache|$CACHE_L1D"
    "L1 Instruction Cache|$CACHE_L1I"
    "L2 Cache|$CACHE_L2"
    "L3 Cache|$CACHE_L3"
    "Physical Sockets|$PHYSICAL_CPUS"
    "Cores per Socket|$CORES_PER_SOCKET"
    "Logical Processors|$LOGICAL_CPUS"
)

ROW_COUNT=0
for row in "${SPEC_ROWS[@]}"; do
    PROPERTY=$(echo "$row" | cut -d'|' -f1)
    VALUE=$(echo "$row" | cut -d'|' -f2-)

    if [ $((ROW_COUNT % 2)) -eq 0 ]; then
        BG_COLOR="#f8f9fa"
    else
        BG_COLOR="#ffffff"
    fi

    HTML_OUTPUT+="<tr style='background-color: $BG_COLOR;'>"
    HTML_OUTPUT+="<td style='padding: 10px; border: 1px solid #ddd;'><strong>$PROPERTY</strong></td>"
    HTML_OUTPUT+="<td style='padding: 10px; border: 1px solid #ddd;'>$VALUE</td>"
    HTML_OUTPUT+="</tr>"

    ROW_COUNT=$((ROW_COUNT + 1))
done

HTML_OUTPUT+="</tbody>"
HTML_OUTPUT+="</table>"

# CPU Features Table
HTML_OUTPUT+="<h3 style='color: #2c3e50; margin-top: 20px; margin-bottom: 10px;'>CPU Features (x86-64)</h3>"
HTML_OUTPUT+="<table style='width: 100%; border-collapse: collapse; box-shadow: 0 2px 4px rgba(0,0,0,0.1); margin-bottom: 20px;'>"
HTML_OUTPUT+="<thead>"
HTML_OUTPUT+="<tr style='background-color: #16a085; color: white;'>"
HTML_OUTPUT+="<th style='padding: 12px; text-align: left; border: 1px solid #ddd; width: 40%;'>Feature</th>"
HTML_OUTPUT+="<th style='padding: 12px; text-align: center; border: 1px solid #ddd; width: 20%;'>Status</th>"
HTML_OUTPUT+="</tr>"
HTML_OUTPUT+="</thead>"
HTML_OUTPUT+="<tbody>"

# Sort features alphabetically by description
SORTED_FEATURES=$(
    for feature in "${!CPU_FEATURES[@]}"; do
        echo "${CPU_FEATURES[$feature]}|$feature"
    done | sort
)

ROW_COUNT=0
while IFS='|' read -r description feature; do
    status="${FEATURE_STATUS[$feature]}"

    if [ "$status" == "supported" ]; then
        STATUS_HTML="<span style='color: #27ae60; font-weight: bold;'>✓ Supported</span>"
    else
        STATUS_HTML="<span style='color: #95a5a6;'>✗ Not Supported</span>"
    fi

    if [ $((ROW_COUNT % 2)) -eq 0 ]; then
        BG_COLOR="#f8f9fa"
    else
        BG_COLOR="#ffffff"
    fi

    HTML_OUTPUT+="<tr style='background-color: $BG_COLOR;'>"
    HTML_OUTPUT+="<td style='padding: 10px; border: 1px solid #ddd;'>$description</td>"
    HTML_OUTPUT+="<td style='padding: 10px; border: 1px solid #ddd; text-align: center;'>$STATUS_HTML</td>"
    HTML_OUTPUT+="</tr>"

    ROW_COUNT=$((ROW_COUNT + 1))
done <<< "$SORTED_FEATURES"

HTML_OUTPUT+="</tbody>"
HTML_OUTPUT+="</table>"

# CPU Security Vulnerabilities Table
VULN_BANNER_COLOR="#27ae60"
VULN_BANNER_ICON="✓"
VULN_BANNER_TEXT="No Unmitigated Vulnerabilities"

if [ $UNMITIGATED_VULNS -gt 0 ]; then
    VULN_BANNER_COLOR="#dc3545"
    VULN_BANNER_ICON="⚠"
    VULN_BANNER_TEXT="$UNMITIGATED_VULNS Unmitigated Vulnerability(ies) Found"
elif [ $VULNERABILITIES_FOUND -gt 0 ]; then
    VULN_BANNER_COLOR="#f39c12"
    VULN_BANNER_ICON="⚠"
    VULN_BANNER_TEXT="$VULNERABILITIES_FOUND Vulnerability(ies) Present (All Mitigated)"
fi

HTML_OUTPUT+="<div style='padding: 10px; margin-bottom: 15px; background-color: #f8f9fa; border-left: 4px solid $VULN_BANNER_COLOR; border-radius: 3px;'>"
HTML_OUTPUT+="<strong style='color: $VULN_BANNER_COLOR;'>$VULN_BANNER_ICON Security Status:</strong> $VULN_BANNER_TEXT"
HTML_OUTPUT+="</div>"

HTML_OUTPUT+="<h3 style='color: #2c3e50; margin-top: 20px; margin-bottom: 10px;'>CPU Security Vulnerabilities</h3>"
HTML_OUTPUT+="<table style='width: 100%; border-collapse: collapse; box-shadow: 0 2px 4px rgba(0,0,0,0.1); margin-bottom: 20px;'>"
HTML_OUTPUT+="<thead>"
HTML_OUTPUT+="<tr style='background-color: #e74c3c; color: white;'>"
HTML_OUTPUT+="<th style='padding: 12px; text-align: left; border: 1px solid #ddd; width: 30%;'>Vulnerability</th>"
HTML_OUTPUT+="<th style='padding: 12px; text-align: center; border: 1px solid #ddd; width: 15%;'>Status</th>"
HTML_OUTPUT+="<th style='padding: 12px; text-align: left; border: 1px solid #ddd;'>Mitigation</th>"
HTML_OUTPUT+="</tr>"
HTML_OUTPUT+="</thead>"
HTML_OUTPUT+="<tbody>"

ROW_COUNT=0

# Check if there are any vulnerabilities to display
if [ ${#VULN_STATUS[@]} -eq 0 ]; then
    # No vulnerability information available
    HTML_OUTPUT+="<tr style='background-color: #f8f9fa;'>"
    HTML_OUTPUT+="<td colspan='3' style='padding: 20px; text-align: center; color: #95a5a6; border: 1px solid #ddd;'>"
    HTML_OUTPUT+="<em>No vulnerability information available. This may indicate an older kernel version that doesn't expose vulnerability status via /sys/devices/system/cpu/vulnerabilities/</em>"
    HTML_OUTPUT+="</td>"
    HTML_OUTPUT+="</tr>"
else
    # Sort vulnerabilities alphabetically by key
    for vuln_key in $(echo "${!VULN_STATUS[@]}" | tr ' ' '\n' | sort); do
        status="${VULN_STATUS[$vuln_key]}"
        mitigation="${VULN_MITIGATION[$vuln_key]}"

        # Get description from CPU_VULNS if available, otherwise use key
        if [ -n "${CPU_VULNS[$vuln_key]}" ]; then
            vuln_name="${CPU_VULNS[$vuln_key]}"
        else
            # Convert underscores to spaces and capitalize
            vuln_name=$(echo "$vuln_key" | tr '_' ' ' | sed 's/\b\(.\)/\u\1/g')
        fi

        case "$status" in
            "not_affected")
                STATUS_HTML="<span style='color: #27ae60; font-weight: bold;'>✓ Not Affected</span>"
                ;;
            "mitigated")
                STATUS_HTML="<span style='color: #f39c12; font-weight: bold;'>⚠ Mitigated</span>"
                ;;
            "vulnerable")
                STATUS_HTML="<span style='color: #dc3545; font-weight: bold;'>✗ Vulnerable</span>"
                ;;
            *)
                STATUS_HTML="<span style='color: #95a5a6;'>? Unknown</span>"
                ;;
        esac

        if [ $((ROW_COUNT % 2)) -eq 0 ]; then
            BG_COLOR="#f8f9fa"
        else
            BG_COLOR="#ffffff"
        fi

        # Truncate very long mitigation strings
        if [ ${#mitigation} -gt 100 ]; then
            mitigation="${mitigation:0:97}..."
        fi

        HTML_OUTPUT+="<tr style='background-color: $BG_COLOR;'>"
        HTML_OUTPUT+="<td style='padding: 10px; border: 1px solid #ddd;'>$vuln_name</td>"
        HTML_OUTPUT+="<td style='padding: 10px; border: 1px solid #ddd; text-align: center;'>$STATUS_HTML</td>"
        HTML_OUTPUT+="<td style='padding: 10px; border: 1px solid #ddd; font-size: 11px;'>$mitigation</td>"
        HTML_OUTPUT+="</tr>"

        ROW_COUNT=$((ROW_COUNT + 1))
    done
fi

HTML_OUTPUT+="</tbody>"
HTML_OUTPUT+="</table>"

# Add warning if unmitigated vulnerabilities found
if [ $UNMITIGATED_VULNS -gt 0 ]; then
    HTML_OUTPUT+="<div style='margin-top: 15px; padding: 12px; background-color: #fff3cd; border-left: 4px solid #dc3545; border-radius: 3px;'>"
    HTML_OUTPUT+="<strong style='color: #dc3545;'>⚠️ Unmitigated Security Vulnerabilities Detected:</strong><br/>"
    HTML_OUTPUT+="<span style='font-size: 12px; color: #856404;'>$UNMITIGATED_VULNS CPU security vulnerability(ies) are present and not mitigated.</span><br/>"
    HTML_OUTPUT+="<small style='color: #856404;'>Consider updating your kernel, microcode, and BIOS/UEFI firmware to apply security patches.</small>"
    HTML_OUTPUT+="</div>"
fi

# Add footer
KERNEL_VERSION=$(uname -r)
HTML_OUTPUT+="<p style='margin-top: 15px; font-size: 12px; color: #95a5a6;'>Kernel Version: $KERNEL_VERSION | Architecture: $ARCH</p>"

HTML_OUTPUT+="</div>"

# Set the WYSIWYG custom field in NinjaOne using ninjarmm-cli
echo "$HTML_OUTPUT" | /opt/NinjaRMMAgent/programdata/ninjarmm-cli set --stdin "$wysiwygCustomField"

# Output to console for visibility
echo "CPU information has been written to custom field: $wysiwygCustomField"
echo "Processor: $CPU_MODEL"
echo "Physical CPUs: $PHYSICAL_CPUS | Cores: $CORES_PER_SOCKET | Logical CPUs: $LOGICAL_CPUS"
echo "Vulnerabilities found: $VULNERABILITIES_FOUND"
echo "Unmitigated vulnerabilities: $UNMITIGATED_VULNS"

# Determine exit code
EXIT_CODE=0
EXIT_REASON="No issues detected"

if [ $UNMITIGATED_VULNS -gt 0 ]; then
    EXIT_CODE=4
    EXIT_REASON="WARNING: $UNMITIGATED_VULNS unmitigated CPU security vulnerability(ies) detected"
    echo "EXIT CODE 4: $EXIT_REASON"
else
    EXIT_REASON="All CPU security vulnerabilities are either not present or properly mitigated"
fi

echo "Exit reason: $EXIT_REASON"
exit $EXIT_CODE
