#!/bin/bash

# Change to a safe directory to avoid getcwd errors when NinjaOne runs from a deleted/inaccessible directory
cd /tmp 2>/dev/null || cd / 2>/dev/null || true

# NinjaOne RMM Script - Storage Information
# Displays storage device details, disk usage, SMART data, and TBW for SSDs in HTML format for WYSIWYG custom field

# Script Variable - Set this in NinjaOne when deploying the script
# This should be the name of your WYSIWYG custom field
# Note: NinjaOne converts variable names to lowercase
wysiwygCustomField="${wysiwygcustomfield}"

# Validate that the custom field variable is set
if [ -z "$wysiwygCustomField" ]; then
    echo "ERROR: wysiwygCustomField variable is not set. Please configure the script variable in NinjaOne."
    exit 1
fi

# Check if running as root (required for smartctl and some disk operations)
if [ "$EUID" -ne 0 ]; then
    HTML_OUTPUT="<div class='p-4 bg-red-50 border border-red-400 rounded-lg'><span class='font-bold text-red-800'>❌ Root Privileges Required</span><br/>This script must be run as root to access disk and SMART information. NinjaOne RMM should automatically run scripts with elevated privileges.</div>"
    echo "$HTML_OUTPUT" | /opt/NinjaRMMAgent/programdata/ninjarmm-cli set --stdin "$wysiwygCustomField"
    echo "This script requires root privileges."
    exit 1
fi

# Detect if this is a virtual machine
IS_VIRTUAL_MACHINE=false
VM_PLATFORM="Physical"

# Check for VM indicators using dmidecode if available
if command -v dmidecode &> /dev/null; then
    SYSTEM_INFO=$(dmidecode -t system 2>/dev/null)
    if echo "$SYSTEM_INFO" | grep -qiE "Manufacturer:.*(QEMU|VMware|VirtualBox|innotek|Xen|Parallels|Bochs)"; then
        IS_VIRTUAL_MACHINE=true
        VM_PLATFORM="Virtual Machine"
    fi

    # Specific check for Hyper-V (Microsoft Corporation + Virtual in model name)
    if echo "$SYSTEM_INFO" | grep -qiE "Manufacturer:.*Microsoft Corporation"; then
        if echo "$SYSTEM_INFO" | grep -qiE "Product Name:.*Virtual"; then
            IS_VIRTUAL_MACHINE=true
            VM_PLATFORM="Virtual Machine (Hyper-V)"
        fi
    fi
fi

# Additional check: /sys/class/dmi/id/ files
if [ -f /sys/class/dmi/id/product_name ]; then
    PRODUCT_NAME=$(cat /sys/class/dmi/id/product_name 2>/dev/null)
    if echo "$PRODUCT_NAME" | grep -qiE "Virtual Machine|VMware|VirtualBox|KVM|QEMU|HVM domU"; then
        IS_VIRTUAL_MACHINE=true
        VM_PLATFORM="Virtual Machine"
    fi
fi

# Check for hypervisor flag in CPU
if [ -f /proc/cpuinfo ] && grep -q "^flags.*hypervisor" /proc/cpuinfo; then
    IS_VIRTUAL_MACHINE=true
    VM_PLATFORM="Virtual Machine"
fi

# Check if required tools are installed
MISSING_TOOLS=""
if ! command -v lsblk &> /dev/null; then
    MISSING_TOOLS+="lsblk "
fi
if ! command -v smartctl &> /dev/null && [ "$IS_VIRTUAL_MACHINE" = false ]; then
    MISSING_TOOLS+="smartctl "
fi

if [ -n "$MISSING_TOOLS" ]; then
    HTML_OUTPUT="<div class='p-4 bg-yellow-50 border border-yellow-400 rounded-lg'><span class='font-bold text-yellow-800'>⚠️ Missing Tools</span><br/>The following required tools are not installed: <code class='bg-gray-100 px-1 py-0.5 rounded text-xs'>$MISSING_TOOLS</code><br/>Install them using: <code class='bg-gray-100 px-1 py-0.5 rounded text-xs'>apt install util-linux smartmontools</code> or <code class='bg-gray-100 px-1 py-0.5 rounded text-xs'>yum install util-linux smartmontools</code></div>"
    echo "$HTML_OUTPUT" | /opt/NinjaRMMAgent/programdata/ninjarmm-cli set --stdin "$wysiwygCustomField"
    echo "Required tools are missing: $MISSING_TOOLS"
    exit 0
fi

# Initialize exit code tracking
GLOBAL_EXIT_CODE=0

# Start building HTML output with Tailwind CSS
HTML_OUTPUT="<script src='https://cdn.tailwindcss.com'></script>"
HTML_OUTPUT+="<div class='font-sans max-w-full'>"
HTML_OUTPUT+="<h2 class='text-2xl font-bold text-gray-800 mb-3'>💽 Storage Information</h2>"
HTML_OUTPUT+="<p class='text-gray-600 mb-5 text-sm'>"
HTML_OUTPUT+="Platform: <span class='font-semibold text-gray-800'>$VM_PLATFORM</span> | "
HTML_OUTPUT+="Last Updated: <span class='font-semibold text-gray-800'>$(date '+%Y-%m-%d %H:%M:%S')</span>"
HTML_OUTPUT+="</p>"

# ===== TUNABLE THRESHOLDS =====
# ZFS pool capacity: warn above WARN, treat as serious above CRIT. A ZFS pool
# that is genuinely full can fail to free space, so it must outrank a warning.
ZFS_CAP_WARN=88
ZFS_CAP_CRIT=90

# Get list of physical disks (exclude loop, ram, ZFS zvols, and other virtual devices)
# ZFS zvols appear as zd0, zd1, zd192, etc. - these are virtual block devices, not physical disks
DISKS=$(lsblk -d -n -o NAME,TYPE | grep -E "disk" | awk '{print $1}' | grep -vE '^zd[0-9]+$')

if [ -z "$DISKS" ]; then
    HTML_OUTPUT+="<div class='p-4 bg-blue-50 border border-blue-400 rounded-lg'><span class='font-bold text-blue-800'>ℹ️ No Disks Found</span><br/>No physical disks were detected on this system.</div>"
    echo "$HTML_OUTPUT" | /opt/NinjaRMMAgent/programdata/ninjarmm-cli set --stdin "$wysiwygCustomField"
    echo "No physical disks found."
    exit 0
fi

# ===== COLLAPSE MULTIPATH DUPLICATES =====
# A LUN reachable over more than one path appears once per path, so the same
# device is reported twice under different kernel names. Keep the first path
# and record the rest as aliases, so the report counts LUNs and not paths.
declare -A MP_PRIMARY_FOR
declare -A DEV_ALIASES
UNIQUE_DISKS=""
for DISK in $DISKS; do
    MP_SERIAL=$(lsblk -d -n -o SERIAL "/dev/$DISK" 2>/dev/null | sed 's/^[[:space:]]*//;s/[[:space:]]*$//')
    MP_SIZE=$(lsblk -d -n -o SIZE "/dev/$DISK" 2>/dev/null | sed 's/^[[:space:]]*//;s/[[:space:]]*$//')
    MP_KEY="${MP_SERIAL}|${MP_SIZE}"
    if [ -n "$MP_SERIAL" ] && [ "$MP_SERIAL" != "Unknown" ] && [ -n "${MP_PRIMARY_FOR[$MP_KEY]}" ]; then
        MP_FIRST="${MP_PRIMARY_FOR[$MP_KEY]}"
        DEV_ALIASES[$MP_FIRST]="${DEV_ALIASES[$MP_FIRST]}${DEV_ALIASES[$MP_FIRST]:+, }$DISK"
        continue
    fi
    if [ -n "$MP_SERIAL" ] && [ "$MP_SERIAL" != "Unknown" ]; then
        MP_PRIMARY_FOR[$MP_KEY]="$DISK"
    fi
    UNIQUE_DISKS+="${UNIQUE_DISKS:+ }$DISK"
done
DISKS="$UNIQUE_DISKS"

# Iterate through each disk
DISK_COUNT=0
for DISK in $DISKS; do
    DISK_COUNT=$((DISK_COUNT + 1))
    DISK_PATH="/dev/$DISK"
    SMART_FULL=""
    SAS_ENDURANCE=""

    # Get disk information using lsblk
    DISK_SIZE=$(lsblk -d -n -o SIZE "$DISK_PATH" 2>/dev/null || echo "Unknown")
    DISK_MODEL=$(lsblk -d -n -o MODEL "$DISK_PATH" 2>/dev/null | sed 's/^[[:space:]]*//;s/[[:space:]]*$//' || echo "Unknown")
    DISK_SERIAL=$(lsblk -d -n -o SERIAL "$DISK_PATH" 2>/dev/null | sed 's/^[[:space:]]*//;s/[[:space:]]*$//' || echo "Unknown")
    DISK_TYPE_ROTA=$(lsblk -d -n -o ROTA "$DISK_PATH" 2>/dev/null)

    # Try to get more detailed info from smartctl if not in VM
    DISK_VENDOR="Unknown"
    DISK_FAMILY=""
    if [ "$IS_VIRTUAL_MACHINE" = false ] && command -v smartctl &> /dev/null; then
        SMART_INFO=$(smartctl -i "$DISK_PATH" 2>/dev/null)
        if [ -n "$SMART_INFO" ]; then
            # Try multiple methods to get vendor/manufacturer
            DISK_VENDOR=$(echo "$SMART_INFO" | grep -i "Vendor:" | awk -F: '{print $2}' | sed 's/^[[:space:]]*//;s/[[:space:]]*$//')

            # If Vendor not found, try Model Family
            if [ -z "$DISK_VENDOR" ] || [ "$DISK_VENDOR" = "Unknown" ]; then
                DISK_VENDOR=$(echo "$SMART_INFO" | grep -i "Model Family:" | awk -F: '{print $2}' | awk '{print $1}' | sed 's/^[[:space:]]*//;s/[[:space:]]*$//')
            fi

            # If still not found, extract from Model Number (common for NVMe)
            if [ -z "$DISK_VENDOR" ] || [ "$DISK_VENDOR" = "Unknown" ]; then
                MODEL_NUM=$(echo "$SMART_INFO" | grep -iE "Model Number:|Device Model:" | awk -F: '{print $2}' | sed 's/^[[:space:]]*//;s/[[:space:]]*$//')
                if [ -n "$MODEL_NUM" ]; then
                    # Extract first word as vendor (Samsung, WDC, Seagate, etc.)
                    DISK_VENDOR=$(echo "$MODEL_NUM" | awk '{print $1}')
                fi
            fi

            # Get Model Family for additional info
            DISK_FAMILY=$(echo "$SMART_INFO" | grep -i "Model Family:" | awk -F: '{print $2}' | sed 's/^[[:space:]]*//;s/[[:space:]]*$//')

            # Get model if we don't have it
            if [ "$DISK_MODEL" = "Unknown" ] || [ -z "$DISK_MODEL" ]; then
                DISK_MODEL=$(echo "$SMART_INFO" | grep -iE "Device Model:|Product:|Model Number:" | awk -F: '{print $2}' | sed 's/^[[:space:]]*//;s/[[:space:]]*$//' | head -1)
            fi

            # Get serial if we don't have it
            if [ "$DISK_SERIAL" = "Unknown" ] || [ -z "$DISK_SERIAL" ]; then
                DISK_SERIAL=$(echo "$SMART_INFO" | grep -i "Serial Number:" | awk -F: '{print $2}' | sed 's/^[[:space:]]*//;s/[[:space:]]*$//')
            fi
        fi
    fi

    # If still no vendor, try to extract from model name from lsblk
    if [ -z "$DISK_VENDOR" ] || [ "$DISK_VENDOR" = "Unknown" ]; then
        if [ -n "$DISK_MODEL" ] && [ "$DISK_MODEL" != "Unknown" ]; then
            # Try to extract vendor from model (first word)
            EXTRACTED_VENDOR=$(echo "$DISK_MODEL" | awk '{print $1}')
            if [ -n "$EXTRACTED_VENDOR" ]; then
                DISK_VENDOR="$EXTRACTED_VENDOR"
            fi
        fi
    fi

    # ===== TRANSPORT / DEVICE CLASS DETECTION =====
    # Only ATA/SATA devices expose the numbered attribute table. SAS, plain
    # SCSI/iSCSI, NVMe and RAID virtual disks each report health differently,
    # and treating them all as ATA yields an empty table plus a wear panel that
    # can never be filled in.
    DISK_TRANSPORT="unknown"
    IS_RAID_VD=false
    case "$DISK" in
        nvme*) DISK_TRANSPORT="nvme" ;;
    esac
    if [ "$DISK_TRANSPORT" = "unknown" ] && [ -n "$SMART_INFO" ]; then
        if echo "$SMART_INFO" | grep -qiE "NVMe Version|Number of Namespaces|^NVME"; then
            DISK_TRANSPORT="nvme"
        elif echo "$SMART_INFO" | grep -qiE "^Transport protocol:.*SAS"; then
            DISK_TRANSPORT="sas"
        elif echo "$SMART_INFO" | grep -qiE "^(SATA|ATA) Version is"; then
            DISK_TRANSPORT="ata"
        elif echo "$SMART_INFO" | grep -qiE "^Vendor:|^Product:"; then
            DISK_TRANSPORT="scsi"
        fi
    fi
    # RAID virtual disks answer SCSI enquiries but have no single drive behind
    # them, so their members have to be read through the controller instead.
    if echo "$DISK_MODEL $DISK_VENDOR" | grep -qiE "PERC|MegaRAID|LOGICAL VOLUME|ServeRAID|Smart Array|AVAGO|Virtual Disk"; then
        IS_RAID_VD=true
        DISK_TRANSPORT="raid"
    fi

    # Determine disk type (HDD/SSD) early so we can use the correct icon
    IS_SSD=false
    DISK_ICON="🟦"  # Default icon
    DISK_TYPE_DISPLAY="HDD"

    # Method 1: Check rotation (0 = SSD, 1 = HDD)
    if [ "$DISK_TYPE_ROTA" = "0" ]; then
        IS_SSD=true
        DISK_TYPE_DISPLAY="SSD"
        DISK_ICON="⚡"  # SSD icon
    else
        DISK_ICON="💽"  # HDD icon
    fi

    # Method 2: Double-check with smartctl
    if [ "$IS_VIRTUAL_MACHINE" = false ] && command -v smartctl &> /dev/null; then
        if [ -n "$SMART_INFO" ]; then
            if echo "$SMART_INFO" | grep -qiE "Solid State Device|SSD|NVMe"; then
                IS_SSD=true
                DISK_TYPE_DISPLAY="SSD"
                DISK_ICON="⚡"
            fi
            if echo "$SMART_INFO" | grep -qiE "NVM"; then
                DISK_TYPE_DISPLAY="NVMe SSD"
                DISK_ICON="⚡"
            fi
        fi
    fi

    # A RAID virtual disk is neither an SSD nor an HDD as far as reporting goes
    if [ "$IS_RAID_VD" = true ]; then
        IS_SSD=false
        DISK_TYPE_DISPLAY="RAID Volume"
        DISK_ICON="🧱"
    fi

    # Clean up Unknown/empty values for display
    [ -z "$DISK_MODEL" ] || [ "$DISK_MODEL" = "Unknown" ] && DISK_MODEL="<span class='text-gray-400'>Unknown</span>"
    [ -z "$DISK_VENDOR" ] || [ "$DISK_VENDOR" = "Unknown" ] && DISK_VENDOR="<span class='text-gray-400'>Unknown</span>"
    [ -z "$DISK_SERIAL" ] || [ "$DISK_SERIAL" = "Unknown" ] && DISK_SERIAL="<span class='text-gray-400'>N/A</span>"

    # Add disk header with appropriate icon
    HTML_OUTPUT+="<h3 class='text-xl font-bold text-gray-700 mt-6 mb-3 pb-2 border-b-2 border-purple-500'>$DISK_ICON Disk $DISK_COUNT: $DISK ($DISK_TYPE_DISPLAY)</h3>"
    HTML_OUTPUT+="<div class='p-3 mb-4 bg-gray-50 border-l-4 border-purple-500 rounded text-sm'>"
    HTML_OUTPUT+="<span class='font-semibold'>Model:</span> $DISK_MODEL | "
    HTML_OUTPUT+="<span class='font-semibold'>Manufacturer:</span> $DISK_VENDOR | "
    HTML_OUTPUT+="<span class='font-semibold'>Size:</span> <span class='text-green-600 font-medium'>$DISK_SIZE</span> | "
    HTML_OUTPUT+="<span class='font-semibold'>Serial:</span> $DISK_SERIAL"
    if [ -n "$DISK_FAMILY" ]; then
        HTML_OUTPUT+="<br/><span class='font-semibold'>Family:</span> $DISK_FAMILY"
    fi
    if [ -n "${DEV_ALIASES[$DISK]}" ]; then
        HTML_OUTPUT+="<br/><span class='font-semibold'>Additional paths:</span> ${DEV_ALIASES[$DISK]} "
        HTML_OUTPUT+="<span class='text-gray-500'>(same LUN reached over more than one path)</span>"
    fi
    HTML_OUTPUT+="</div>"

    # ===== PARTITION AND DISK USAGE TABLE =====
    HTML_OUTPUT+="<h4 class='text-lg font-semibold text-gray-800 mt-4 mb-3'>Partitions & Disk Usage</h4>"
    HTML_OUTPUT+="<table class='w-full border-collapse shadow-md mb-5 text-sm'>"
    HTML_OUTPUT+="<thead>"
    HTML_OUTPUT+="<tr class='bg-purple-600 text-white'>"
    HTML_OUTPUT+="<th class='px-3 py-3 text-left border border-gray-300'>Partition</th>"
    HTML_OUTPUT+="<th class='px-3 py-3 text-left border border-gray-300'>FS Type</th>"
    HTML_OUTPUT+="<th class='px-3 py-3 text-left border border-gray-300'>Mount Point</th>"
    HTML_OUTPUT+="<th class='px-3 py-3 text-left border border-gray-300'>Size</th>"
    HTML_OUTPUT+="<th class='px-3 py-3 text-left border border-gray-300'>Used</th>"
    HTML_OUTPUT+="<th class='px-3 py-3 text-left border border-gray-300'>Available</th>"
    HTML_OUTPUT+="<th class='px-3 py-3 text-left border border-gray-300 min-w-[200px]'>Usage</th>"
    HTML_OUTPUT+="</tr>"
    HTML_OUTPUT+="</thead>"
    HTML_OUTPUT+="<tbody class='bg-white'>"

    # Get partitions for this disk (use -l to avoid tree characters)
    # Restrict to partitions whose parent is this disk. Without the PKNAME
    # check, lsblk also returns partitions of any multipath map layered on top
    # (36001405...-part1), which are not partitions of this device.
    PARTITIONS=$(lsblk -n -l -o NAME,TYPE,PKNAME "$DISK_PATH" 2>/dev/null | awk -v d="$DISK" '$2=="part" && $3==d {print $1}')

    # When multipath is active the partition table is exposed on the map rather
    # than on the raw path, so the raw device legitimately has no partitions of
    # its own. Fall back to the map's partitions instead of reporting none.
    PART_VIA_MPATH=""
    if [ -z "$PARTITIONS" ]; then
        MPATH_CHILD=$(lsblk -n -l -o NAME,TYPE,PKNAME "$DISK_PATH" 2>/dev/null | awk -v d="$DISK" '$2=="mpath" && $3==d {print $1; exit}')
        if [ -n "$MPATH_CHILD" ]; then
            PARTITIONS=$(lsblk -n -l -o NAME,TYPE,PKNAME "$DISK_PATH" 2>/dev/null | awk -v m="$MPATH_CHILD" '$2=="part" && $3==m {print $1}')
            [ -n "$PARTITIONS" ] && PART_VIA_MPATH="$MPATH_CHILD"
        fi
    fi
    if [ -n "$PART_VIA_MPATH" ]; then
        HTML_OUTPUT+="<tr class='bg-blue-50'><td colspan='7' class='px-3 py-2 border border-gray-300 text-xs text-blue-800'>"
        HTML_OUTPUT+="Partitions below belong to multipath map <span class='font-mono'>$PART_VIA_MPATH</span>, which this path is a member of."
        HTML_OUTPUT+="</td></tr>"
    fi

    ROW_COUNT=0
    if [ -z "$PARTITIONS" ]; then
        # No partitions - check if disk itself is mounted
        MOUNT_POINT=$(lsblk -n -o MOUNTPOINT "$DISK_PATH" 2>/dev/null | grep -v "^$" | head -1)
        if [ -n "$MOUNT_POINT" ]; then
            # Disk is directly mounted
            # Get FSTYPE for the disk
            DISK_FSTYPE=$(lsblk -n -d -o FSTYPE "$DISK_PATH" 2>/dev/null)
            if [ "$DISK_FSTYPE" = "zfs_member" ]; then
                # ZFS pool member disk
                FSTYPE_DISPLAY="<code class='bg-blue-50 px-2 py-0.5 rounded text-xs text-blue-800'>ZFS</code>"
            elif [ -n "$DISK_FSTYPE" ]; then
                FSTYPE_DISPLAY="<code class='bg-gray-100 px-2 py-0.5 rounded text-xs'>$DISK_FSTYPE</code>"
            else
                FSTYPE_DISPLAY="<span class='text-gray-400'>N/A</span>"
            fi

            DF_OUTPUT=$(df -h "$DISK_PATH" 2>/dev/null | tail -1)
            if [ -n "$DF_OUTPUT" ]; then
                PART_SIZE=$(echo "$DF_OUTPUT" | awk '{print $2}')
                PART_USED=$(echo "$DF_OUTPUT" | awk '{print $3}')
                PART_AVAIL=$(echo "$DF_OUTPUT" | awk '{print $4}')
                PART_USE_PCT=$(echo "$DF_OUTPUT" | awk '{print $5}' | sed 's/%//')

                # Determine color based on usage (validate numeric first)
                if [[ "$PART_USE_PCT" =~ ^[0-9]+$ ]]; then
                    if [ "$PART_USE_PCT" -le 80 ]; then
                        BAR_COLOR="#27ae60"
                    elif [ "$PART_USE_PCT" -le 85 ]; then
                        BAR_COLOR="#e67e22"
                    else
                        BAR_COLOR="#dc3545"
                    fi
                else
                    # Fallback if not numeric
                    BAR_COLOR="#95a5a6"
                fi

                HTML_OUTPUT+="<tr class='bg-gray-50'>"
                HTML_OUTPUT+="<td class='px-3 py-2.5 border border-gray-300'><span class='font-semibold'>$DISK</span></td>"
                HTML_OUTPUT+="<td class='px-3 py-2.5 border border-gray-300'>$FSTYPE_DISPLAY</td>"
                HTML_OUTPUT+="<td class='px-3 py-2.5 border border-gray-300'>$MOUNT_POINT</td>"
                HTML_OUTPUT+="<td class='px-3 py-2.5 border border-gray-300'>$PART_SIZE</td>"
                HTML_OUTPUT+="<td class='px-3 py-2.5 border border-gray-300'>$PART_USED</td>"
                HTML_OUTPUT+="<td class='px-3 py-2.5 border border-gray-300'>$PART_AVAIL</td>"
                HTML_OUTPUT+="<td class='px-3 py-2.5 border border-gray-300'>"
                HTML_OUTPUT+="<div class='w-full bg-gray-200 rounded overflow-hidden'>"
                HTML_OUTPUT+="<div class='py-1 text-center text-white font-bold text-xs' style='width: ${PART_USE_PCT}%; background-color: $BAR_COLOR;'>${PART_USE_PCT}%</div>"
                HTML_OUTPUT+="</div>"
                HTML_OUTPUT+="</td>"
                HTML_OUTPUT+="</tr>"
                ROW_COUNT=1
            fi
        fi
    else
        # Process each partition
        for PARTITION in $PARTITIONS; do
            PART_PATH="/dev/$PARTITION"
            # Multipath partitions are addressed under /dev/mapper
            if [ ! -b "$PART_PATH" ] && [ -b "/dev/mapper/$PARTITION" ]; then
                PART_PATH="/dev/mapper/$PARTITION"
            fi

            # Check if this partition is LUKS encrypted (use -d to check only the device, not children)
            PART_FSTYPE=$(lsblk -n -d -o FSTYPE "$PART_PATH" 2>/dev/null)
            IS_ENCRYPTED=false
            ENCRYPTION_ICON=""
            CRYPT_DEVICE=""

            if [ "$PART_FSTYPE" = "crypto_LUKS" ]; then
                IS_ENCRYPTED=true
                ENCRYPTION_ICON="🔒 "

                # Find the child crypt device (mapper device)
                CRYPT_DEVICE=$(lsblk -n -l -o NAME,TYPE "$PART_PATH" 2>/dev/null | grep "crypt" | awk '{print $1}' | head -1)

                if [ -n "$CRYPT_DEVICE" ]; then
                    # Get mount point from the crypt device
                    MOUNT_POINT=$(lsblk -n -o MOUNTPOINT "/dev/mapper/$CRYPT_DEVICE" 2>/dev/null | grep -v "^$" | head -1)

                    # If mapper device doesn't work, try /dev/$CRYPT_DEVICE
                    if [ -z "$MOUNT_POINT" ]; then
                        MOUNT_POINT=$(lsblk -n -o MOUNTPOINT "/dev/$CRYPT_DEVICE" 2>/dev/null | grep -v "^$" | head -1)
                    fi
                else
                    MOUNT_POINT=""
                fi
            else
                # Not encrypted, get mount point directly
                MOUNT_POINT=$(lsblk -n -o MOUNTPOINT "$PART_PATH" 2>/dev/null | grep -v "^$" | head -1)
            fi

            if [ -z "$MOUNT_POINT" ]; then
                if [ "$IS_ENCRYPTED" = true ]; then
                    MOUNT_POINT="<span class='text-gray-400'>🔒 Encrypted (not unlocked)</span>"
                else
                    MOUNT_POINT="<span class='text-gray-400'>Not mounted</span>"
                fi
                PART_SIZE="<span class='text-gray-400'>N/A</span>"
                PART_USED="<span class='text-gray-400'>N/A</span>"
                PART_AVAIL="<span class='text-gray-400'>N/A</span>"
                USAGE_BAR="<span class='text-gray-400'>N/A</span>"
            else
                # Get disk usage - use the mount point for df instead of device path
                DF_OUTPUT=$(df -h "$MOUNT_POINT" 2>/dev/null | tail -1)
                if [ -n "$DF_OUTPUT" ]; then
                    PART_SIZE=$(echo "$DF_OUTPUT" | awk '{print $2}')
                    PART_USED=$(echo "$DF_OUTPUT" | awk '{print $3}')
                    PART_AVAIL=$(echo "$DF_OUTPUT" | awk '{print $4}')
                    PART_USE_PCT=$(echo "$DF_OUTPUT" | awk '{print $5}' | sed 's/%//')

                    # Determine color based on usage (validate numeric first)
                    if [[ "$PART_USE_PCT" =~ ^[0-9]+$ ]]; then
                        if [ "$PART_USE_PCT" -le 80 ]; then
                            BAR_COLOR="#27ae60"
                        elif [ "$PART_USE_PCT" -le 85 ]; then
                            BAR_COLOR="#e67e22"
                        else
                            BAR_COLOR="#dc3545"
                        fi

                        USAGE_BAR="<div class='w-full bg-gray-200 rounded overflow-hidden'>"
                        USAGE_BAR+="<div class='py-1 text-center text-white font-bold text-xs' style='width: ${PART_USE_PCT}%; background-color: $BAR_COLOR;'>${PART_USE_PCT}%</div>"
                        USAGE_BAR+="</div>"
                    else
                        # Fallback if not numeric
                        USAGE_BAR="<span class='text-gray-400'>Invalid data</span>"
                    fi

                    # Add encryption icon to mount point if encrypted
                    if [ "$IS_ENCRYPTED" = true ]; then
                        MOUNT_POINT="$ENCRYPTION_ICON$MOUNT_POINT"
                    fi
                else
                    PART_SIZE="<span class='text-gray-400'>N/A</span>"
                    PART_USED="<span class='text-gray-400'>N/A</span>"
                    PART_AVAIL="<span class='text-gray-400'>N/A</span>"
                    USAGE_BAR="<span class='text-gray-400'>N/A</span>"
                fi
            fi

            # Format FSTYPE for display
            if [ "$PART_FSTYPE" = "crypto_LUKS" ] && [ -n "$CRYPT_DEVICE" ]; then
                # For LUKS, show both the container type and the actual filesystem
                # Try /dev/mapper/ first, then fallback to /dev/
                CRYPT_FSTYPE=$(lsblk -n -d -o FSTYPE "/dev/mapper/$CRYPT_DEVICE" 2>/dev/null)
                if [ -z "$CRYPT_FSTYPE" ]; then
                    CRYPT_FSTYPE=$(lsblk -n -d -o FSTYPE "/dev/$CRYPT_DEVICE" 2>/dev/null)
                fi

                if [ -n "$CRYPT_FSTYPE" ]; then
                    # Check if encrypted FS is ZFS
                    if [ "$CRYPT_FSTYPE" = "zfs_member" ]; then
                        FSTYPE_DISPLAY="<code class='bg-yellow-50 px-2 py-0.5 rounded text-xs text-yellow-800'>LUKS (ZFS)</code>"
                    else
                        FSTYPE_DISPLAY="<code class='bg-yellow-50 px-2 py-0.5 rounded text-xs text-yellow-800'>LUKS ($CRYPT_FSTYPE)</code>"
                    fi
                else
                    FSTYPE_DISPLAY="<code class='bg-yellow-50 px-2 py-0.5 rounded text-xs text-yellow-800'>LUKS</code>"
                fi
            elif [ "$PART_FSTYPE" = "zfs_member" ]; then
                # ZFS pool member partition
                FSTYPE_DISPLAY="<code class='bg-blue-50 px-2 py-0.5 rounded text-xs text-blue-800'>ZFS</code>"
            elif [ -n "$PART_FSTYPE" ]; then
                FSTYPE_DISPLAY="<code class='bg-gray-100 px-2 py-0.5 rounded text-xs'>$PART_FSTYPE</code>"
            else
                FSTYPE_DISPLAY="<span class='text-gray-400'>N/A</span>"
            fi

            # Alternate row colors
            if [ $((ROW_COUNT % 2)) -eq 0 ]; then
                BG_CLASS="bg-gray-50"
            else
                BG_CLASS="bg-white"
            fi

            HTML_OUTPUT+="<tr class='$BG_CLASS hover:bg-gray-100'>"
            HTML_OUTPUT+="<td class='px-3 py-2.5 border border-gray-300'><span class='font-semibold'>$PARTITION</span></td>"
            HTML_OUTPUT+="<td class='px-3 py-2.5 border border-gray-300'>$FSTYPE_DISPLAY</td>"
            HTML_OUTPUT+="<td class='px-3 py-2.5 border border-gray-300'>$MOUNT_POINT</td>"
            HTML_OUTPUT+="<td class='px-3 py-2.5 border border-gray-300'>$PART_SIZE</td>"
            HTML_OUTPUT+="<td class='px-3 py-2.5 border border-gray-300'>$PART_USED</td>"
            HTML_OUTPUT+="<td class='px-3 py-2.5 border border-gray-300'>$PART_AVAIL</td>"
            HTML_OUTPUT+="<td class='px-3 py-2.5 border border-gray-300'>$USAGE_BAR</td>"
            HTML_OUTPUT+="</tr>"

            ROW_COUNT=$((ROW_COUNT + 1))
        done
    fi

    if [ $ROW_COUNT -eq 0 ]; then
        HTML_OUTPUT+="<tr class='bg-gray-50'>"
        HTML_OUTPUT+="<td colspan='7' class='px-3 py-2.5 border border-gray-300 text-center text-gray-400'>No partitions or mounted filesystems found on this disk</td>"
        HTML_OUTPUT+="</tr>"
    fi

    HTML_OUTPUT+="</tbody>"
    HTML_OUTPUT+="</table>"

    # ===== SKIP SMART AND SSD CHECKS FOR VMs =====
    if [ "$IS_VIRTUAL_MACHINE" = true ]; then
        HTML_OUTPUT+="<div class='p-3 mb-4 bg-blue-50 border-l-4 border-blue-400 rounded'>"
        HTML_OUTPUT+="<span class='font-bold text-blue-700'>ℹ️ Virtual Machine Detected</span><br/>"
        HTML_OUTPUT+="SMART data and SSD health checks are not performed on virtual machines."
        HTML_OUTPUT+="</div>"
        continue
    fi

    # ===== SMART DATA CHECK =====
    # (Disk type already determined earlier for use in header icon)
    if command -v smartctl &> /dev/null; then
        HTML_OUTPUT+="<h4 class='text-lg font-semibold text-gray-800 mt-4 mb-3'>SMART Health Status</h4>"

        SMART_HEALTH=$(smartctl -H "$DISK_PATH" 2>/dev/null)
        SMART_ALL=$(smartctl -A "$DISK_PATH" 2>/dev/null)
        # SAS error counters and the NVMe health page only appear in the full
        # output. Captured once here and reused by the wear panel below rather
        # than invoking smartctl a third time per disk.
        SMART_FULL=$(smartctl -a "$DISK_PATH" 2>/dev/null)

        SMART_STATUS="Unknown"
        SMART_EXIT_CODE=0
        SMART_COLOR="#95a5a6"
        SMART_ICON="?"

        if [ -n "$SMART_HEALTH" ]; then
            if echo "$SMART_HEALTH" | grep -qiE "SMART overall-health self-assessment test result: PASSED|SMART Health Status: OK"; then
                SMART_STATUS="PASSED"
                SMART_COLOR="#27ae60"
                SMART_ICON="✓"
                SMART_EXIT_CODE=0
            elif echo "$SMART_HEALTH" | grep -qiE "SMART overall-health self-assessment test result: FAILED|SMART Health Status: FAILING"; then
                SMART_STATUS="FAILED"
                SMART_COLOR="#dc3545"
                SMART_ICON="✗"
                SMART_EXIT_CODE=5
                [ $GLOBAL_EXIT_CODE -lt 5 ] && GLOBAL_EXIT_CODE=5
            else
                SMART_STATUS="Unknown"
                SMART_COLOR="#95a5a6"
                SMART_ICON="?"
            fi
        fi

        # Check for warning attributes
        SMART_WARNINGS=""
        if [ -n "$SMART_ALL" ]; then
            # Common critical SMART attributes
            # ID 5: Reallocated Sectors Count
            # ID 187: Reported Uncorrectable Errors
            # ID 188: Command Timeout
            # ID 197: Current Pending Sector Count
            # ID 198: Offline Uncorrectable Sector Count

            REALLOC_SECTORS=$(echo "$SMART_ALL" | grep "^  5 " | awk '{print $10}')
            UNCORRECTABLE=$(echo "$SMART_ALL" | grep "^187 " | awk '{print $10}')
            COMMAND_TIMEOUT=$(echo "$SMART_ALL" | grep "^188 " | awk '{print $10}')
            PENDING_SECTORS=$(echo "$SMART_ALL" | grep "^197 " | awk '{print $10}')
            OFFLINE_UNCORRECTABLE=$(echo "$SMART_ALL" | grep "^198 " | awk '{print $10}')

            if [ -n "$REALLOC_SECTORS" ] && [[ "$REALLOC_SECTORS" =~ ^[0-9]+$ ]] && [ "$REALLOC_SECTORS" -gt 0 ]; then
                SMART_WARNINGS+="Reallocated Sectors: $REALLOC_SECTORS; "
                [ $SMART_EXIT_CODE -lt 4 ] && SMART_EXIT_CODE=4
                [ $GLOBAL_EXIT_CODE -lt 4 ] && GLOBAL_EXIT_CODE=4
            fi
            if [ -n "$UNCORRECTABLE" ] && [[ "$UNCORRECTABLE" =~ ^[0-9]+$ ]] && [ "$UNCORRECTABLE" -gt 0 ]; then
                SMART_WARNINGS+="Uncorrectable Errors: $UNCORRECTABLE; "
                [ $SMART_EXIT_CODE -lt 5 ] && SMART_EXIT_CODE=5
                [ $GLOBAL_EXIT_CODE -lt 5 ] && GLOBAL_EXIT_CODE=5
            fi
            if [ -n "$COMMAND_TIMEOUT" ] && [[ "$COMMAND_TIMEOUT" =~ ^[0-9]+$ ]] && [ "$COMMAND_TIMEOUT" -gt 100 ]; then
                SMART_WARNINGS+="Command Timeouts: $COMMAND_TIMEOUT; "
                [ $SMART_EXIT_CODE -lt 4 ] && SMART_EXIT_CODE=4
                [ $GLOBAL_EXIT_CODE -lt 4 ] && GLOBAL_EXIT_CODE=4
            fi
            if [ -n "$PENDING_SECTORS" ] && [[ "$PENDING_SECTORS" =~ ^[0-9]+$ ]] && [ "$PENDING_SECTORS" -gt 0 ]; then
                SMART_WARNINGS+="Pending Sectors: $PENDING_SECTORS; "
                [ $SMART_EXIT_CODE -lt 4 ] && SMART_EXIT_CODE=4
                [ $GLOBAL_EXIT_CODE -lt 4 ] && GLOBAL_EXIT_CODE=4
            fi
            if [ -n "$OFFLINE_UNCORRECTABLE" ] && [[ "$OFFLINE_UNCORRECTABLE" =~ ^[0-9]+$ ]] && [ "$OFFLINE_UNCORRECTABLE" -gt 0 ]; then
                SMART_WARNINGS+="Offline Uncorrectable: $OFFLINE_UNCORRECTABLE; "
                [ $SMART_EXIT_CODE -lt 5 ] && SMART_EXIT_CODE=5
                [ $GLOBAL_EXIT_CODE -lt 5 ] && GLOBAL_EXIT_CODE=5
            fi
        fi

        # ===== NON-ATA HEALTH INDICATORS =====
        # The checks above read the numbered ATA attribute table, which SAS,
        # SCSI and NVMe devices do not have. Without the blocks below, a SAS
        # drive with a growing defect list or an NVMe with media errors is
        # reported as completely clean.
        SAS_TEMP=""; SAS_DEFECTS=""; SAS_NONMEDIUM=""; SAS_UNCORRECTED=""
        NVME_CRIT=""; NVME_MEDIA_ERR=""; NVME_SPARE=""; NVME_SPARE_THRESH=""
        RAID_MEMBER_REPORT=""

        case "$DISK_TRANSPORT" in
            sas|scsi|raid)
                # These fields are SCSI-generic, so they also cover SAS SSDs
                SAS_TEMP=$(echo "$SMART_FULL" | grep -i "Current Drive Temperature:" | head -1 | awk -F: '{print $2}' | sed 's/^[[:space:]]*//;s/[[:space:]]*$//')
                # A LUN with no thermal sensor answers 0 C. Treat that as not
                # reported, so it does not become a one-row table of nothing.
                SAS_TEMP_NUM=$(echo "$SAS_TEMP" | awk '{print $1}')
                if [[ "$SAS_TEMP_NUM" =~ ^0+$ ]]; then
                    SAS_TEMP=""
                fi
                SAS_ENDURANCE=$(echo "$SMART_FULL" | grep -i "Percentage used endurance indicator:" | head -1 | awk -F: '{print $2}' | tr -d ' %')
                SAS_DEFECTS=$(echo "$SMART_FULL" | grep -i "Elements in grown defect list:" | head -1 | awk -F: '{print $2}' | tr -d ' ')
                SAS_NONMEDIUM=$(echo "$SMART_FULL" | grep -i "Non-medium error count:" | head -1 | awk -F: '{print $2}' | tr -d ' ')
                # Error counter log: column 8 is total uncorrected errors
                SAS_UNCORRECTED=$(echo "$SMART_FULL" | awk '/^(read|write|verify):/ && NF>=8 && $8 ~ /^[0-9]+$/ {s+=$8; seen=1} END {if (seen) print s}')

                if [ -n "$SAS_DEFECTS" ] && [[ "$SAS_DEFECTS" =~ ^[0-9]+$ ]] && [ "$SAS_DEFECTS" -gt 0 ]; then
                    SMART_WARNINGS+="Grown defect list: $SAS_DEFECTS; "
                    [ $SMART_EXIT_CODE -lt 4 ] && SMART_EXIT_CODE=4
                    [ $GLOBAL_EXIT_CODE -lt 4 ] && GLOBAL_EXIT_CODE=4
                fi
                if [ -n "$SAS_UNCORRECTED" ] && [[ "$SAS_UNCORRECTED" =~ ^[0-9]+$ ]] && [ "$SAS_UNCORRECTED" -gt 0 ]; then
                    SMART_WARNINGS+="Uncorrected errors: $SAS_UNCORRECTED; "
                    [ $SMART_EXIT_CODE -lt 5 ] && SMART_EXIT_CODE=5
                    [ $GLOBAL_EXIT_CODE -lt 5 ] && GLOBAL_EXIT_CODE=5
                fi
                # Non-medium errors are usually bus level events rather than
                # media faults, so they are reported without raising an alert.
                ;;
            nvme)
                NVME_CRIT=$(echo "$SMART_FULL" | grep -i "^Critical Warning:" | head -1 | awk -F: '{print $2}' | tr -d ' ')
                NVME_MEDIA_ERR=$(echo "$SMART_FULL" | grep -i "Media and Data Integrity Errors:" | head -1 | awk -F: '{print $2}' | tr -d ' ,')
                NVME_SPARE=$(echo "$SMART_FULL" | grep -i "^Available Spare:" | head -1 | awk -F: '{print $2}' | tr -d ' %')
                NVME_SPARE_THRESH=$(echo "$SMART_FULL" | grep -i "^Available Spare Threshold:" | head -1 | awk -F: '{print $2}' | tr -d ' %')

                if [ -n "$NVME_MEDIA_ERR" ] && [[ "$NVME_MEDIA_ERR" =~ ^[0-9]+$ ]] && [ "$NVME_MEDIA_ERR" -gt 0 ]; then
                    SMART_WARNINGS+="Media and data integrity errors: $NVME_MEDIA_ERR; "
                    [ $SMART_EXIT_CODE -lt 5 ] && SMART_EXIT_CODE=5
                    [ $GLOBAL_EXIT_CODE -lt 5 ] && GLOBAL_EXIT_CODE=5
                fi
                if [ -n "$NVME_CRIT" ] && [ "$NVME_CRIT" != "0x00" ] && [ "$NVME_CRIT" != "0" ]; then
                    SMART_WARNINGS+="NVMe critical warning: $NVME_CRIT; "
                    [ $SMART_EXIT_CODE -lt 5 ] && SMART_EXIT_CODE=5
                    [ $GLOBAL_EXIT_CODE -lt 5 ] && GLOBAL_EXIT_CODE=5
                fi
                if [ -n "$NVME_SPARE" ] && [ -n "$NVME_SPARE_THRESH" ] \
                   && [[ "$NVME_SPARE" =~ ^[0-9]+$ ]] && [[ "$NVME_SPARE_THRESH" =~ ^[0-9]+$ ]] \
                   && [ "$NVME_SPARE" -le "$NVME_SPARE_THRESH" ]; then
                    SMART_WARNINGS+="Available spare ${NVME_SPARE}% at or below threshold ${NVME_SPARE_THRESH}%; "
                    [ $SMART_EXIT_CODE -lt 4 ] && SMART_EXIT_CODE=4
                    [ $GLOBAL_EXIT_CODE -lt 4 ] && GLOBAL_EXIT_CODE=4
                fi
                ;;
        esac

        # ===== RAID VIRTUAL DISK MEMBERS =====
        # A virtual disk has no SMART of its own. Ask smartctl which controller
        # device specs exist and report each physical member through those.
        if [ "$IS_RAID_VD" = true ]; then
            RAID_SPECS=$(smartctl --scan-open 2>/dev/null | grep -E "megaraid|cciss" | sed 's/#.*//' | sed 's/[[:space:]]*$//' | head -64)
            if [ -n "$RAID_SPECS" ]; then
                while IFS= read -r RSPEC; do
                    [ -z "$RSPEC" ] && continue
                    # shellcheck disable=SC2086
                    RMEM_H=$(smartctl -H $RSPEC 2>/dev/null)
                    [ -z "$RMEM_H" ] && continue
                    # shellcheck disable=SC2086
                    RMEM_I=$(smartctl -i $RSPEC 2>/dev/null)
                    RMEM_MODEL=$(echo "$RMEM_I" | grep -iE "^Device Model:|^Product:|^Model Number:" | head -1 | awk -F: '{print $2}' | sed 's/^[[:space:]]*//;s/[[:space:]]*$//')
                    RMEM_SERIAL=$(echo "$RMEM_I" | grep -iE "^Serial [Nn]umber:" | head -1 | awk -F: '{print $2}' | sed 's/^[[:space:]]*//;s/[[:space:]]*$//')
                    if echo "$RMEM_H" | grep -qiE "test result: PASSED|Health Status: OK"; then
                        RMEM_STATE="<span class='text-green-600 font-semibold'>✓ PASSED</span>"
                    elif echo "$RMEM_H" | grep -qiE "test result: FAILED|Health Status: FAILING"; then
                        RMEM_STATE="<span class='text-red-600 font-semibold'>✗ FAILED</span>"
                        SMART_WARNINGS+="RAID member ${RSPEC} SMART FAILED; "
                        [ $GLOBAL_EXIT_CODE -lt 5 ] && GLOBAL_EXIT_CODE=5
                    else
                        RMEM_STATE="<span class='text-gray-500'>? Unknown</span>"
                    fi
                    RAID_MEMBER_REPORT+="<tr class='bg-white hover:bg-gray-100'>"
                    RAID_MEMBER_REPORT+="<td class='px-3 py-2 border border-gray-300 font-mono text-xs'>$RSPEC</td>"
                    RAID_MEMBER_REPORT+="<td class='px-3 py-2 border border-gray-300'>${RMEM_MODEL:-<span class='text-gray-400'>Unknown</span>}</td>"
                    RAID_MEMBER_REPORT+="<td class='px-3 py-2 border border-gray-300'>${RMEM_SERIAL:-<span class='text-gray-400'>N/A</span>}</td>"
                    RAID_MEMBER_REPORT+="<td class='px-3 py-2 border border-gray-300'>$RMEM_STATE</td>"
                    RAID_MEMBER_REPORT+="</tr>"
                done <<< "$RAID_SPECS"
            fi
        fi

        HTML_OUTPUT+="<div class='p-3 mb-4 bg-gray-50 rounded' style='border-left: 4px solid $SMART_COLOR;'>"
        HTML_OUTPUT+="<span class='font-bold' style='color: $SMART_COLOR;'>$SMART_ICON SMART Status:</span> <span class='font-medium'>$SMART_STATUS</span>"

        if [ -n "$SMART_WARNINGS" ]; then
            HTML_OUTPUT+="<br/><span class='text-red-600 text-sm'><span class='font-bold'>⚠️ Warnings:</span> $SMART_WARNINGS</span>"
        fi

        HTML_OUTPUT+="</div>"

        # ===== NON-ATA DETAIL PANELS =====
        if [ "$DISK_TRANSPORT" = "sas" ] || [ "$DISK_TRANSPORT" = "scsi" ] || [ "$DISK_TRANSPORT" = "raid" ]; then
            SCSI_ROWS=""
            [ -n "$SAS_TEMP" ]        && SCSI_ROWS+="<tr class='bg-gray-50'><td class='px-3 py-2 border border-gray-300 font-medium'>Current drive temperature</td><td class='px-3 py-2 border border-gray-300'>$SAS_TEMP</td></tr>"
            [ -n "$SAS_ENDURANCE" ]   && SCSI_ROWS+="<tr class='bg-white'><td class='px-3 py-2 border border-gray-300 font-medium'>Endurance used</td><td class='px-3 py-2 border border-gray-300'>${SAS_ENDURANCE}%</td></tr>"
            [ -n "$SAS_DEFECTS" ]     && SCSI_ROWS+="<tr class='bg-gray-50'><td class='px-3 py-2 border border-gray-300 font-medium'>Elements in grown defect list</td><td class='px-3 py-2 border border-gray-300'>$SAS_DEFECTS</td></tr>"
            [ -n "$SAS_UNCORRECTED" ] && SCSI_ROWS+="<tr class='bg-white'><td class='px-3 py-2 border border-gray-300 font-medium'>Total uncorrected errors</td><td class='px-3 py-2 border border-gray-300'>$SAS_UNCORRECTED</td></tr>"
            [ -n "$SAS_NONMEDIUM" ]   && SCSI_ROWS+="<tr class='bg-gray-50'><td class='px-3 py-2 border border-gray-300 font-medium'>Non-medium error count</td><td class='px-3 py-2 border border-gray-300'>$SAS_NONMEDIUM</td></tr>"

            if [ -n "$SCSI_ROWS" ]; then
                HTML_OUTPUT+="<details class='mb-4'>"
                HTML_OUTPUT+="<summary class='cursor-pointer text-blue-600 font-bold p-2 hover:text-blue-800'>View SCSI/SAS Health Counters</summary>"
                HTML_OUTPUT+="<table class='w-full border-collapse shadow-md mt-3 text-xs'>"
                HTML_OUTPUT+="<thead><tr class='bg-purple-600 text-white'>"
                HTML_OUTPUT+="<th class='px-3 py-2 text-left border border-gray-300'>Indicator</th>"
                HTML_OUTPUT+="<th class='px-3 py-2 text-left border border-gray-300'>Value</th>"
                HTML_OUTPUT+="</tr></thead><tbody class='bg-white'>$SCSI_ROWS</tbody></table></details>"
            elif [ "$IS_RAID_VD" = false ]; then
                HTML_OUTPUT+="<div class='p-3 mb-4 bg-blue-50 border-l-4 border-blue-400 rounded text-sm'>"
                HTML_OUTPUT+="<span class='font-bold text-blue-800'>ℹ️ No per-drive SMART data</span><br/>"
                HTML_OUTPUT+="This is a SCSI/iSCSI LUN rather than a local drive. Disk health for it is held by the storage array that presents it."
                HTML_OUTPUT+="</div>"
            fi
        fi

        if [ "$IS_RAID_VD" = true ]; then
            HTML_OUTPUT+="<div class='p-3 mb-4 bg-blue-50 border-l-4 border-blue-400 rounded text-sm'>"
            HTML_OUTPUT+="<span class='font-bold text-blue-800'>ℹ️ RAID virtual disk</span><br/>"
            HTML_OUTPUT+="A virtual disk exposes no SMART data of its own; the physical members are read through the controller."
            HTML_OUTPUT+="</div>"
            if [ -n "$RAID_MEMBER_REPORT" ]; then
                HTML_OUTPUT+="<details class='mb-4' open>"
                HTML_OUTPUT+="<summary class='cursor-pointer text-blue-600 font-bold p-2 hover:text-blue-800'>View RAID Member Drives</summary>"
                HTML_OUTPUT+="<table class='w-full border-collapse shadow-md mt-3 text-xs'>"
                HTML_OUTPUT+="<thead><tr class='bg-purple-600 text-white'>"
                HTML_OUTPUT+="<th class='px-3 py-2 text-left border border-gray-300'>Device</th>"
                HTML_OUTPUT+="<th class='px-3 py-2 text-left border border-gray-300'>Model</th>"
                HTML_OUTPUT+="<th class='px-3 py-2 text-left border border-gray-300'>Serial</th>"
                HTML_OUTPUT+="<th class='px-3 py-2 text-left border border-gray-300'>SMART</th>"
                HTML_OUTPUT+="</tr></thead><tbody class='bg-white'>$RAID_MEMBER_REPORT</tbody></table></details>"
            else
                HTML_OUTPUT+="<div class='p-3 mb-4 bg-yellow-50 border-l-4 border-yellow-400 rounded text-sm'>"
                HTML_OUTPUT+="<span class='font-bold text-yellow-800'>⚠️ Members not enumerated</span><br/>"
                HTML_OUTPUT+="smartctl --scan-open reported no controller device specs. Install the vendor CLI (perccli/storcli) or query members directly, for example <code>smartctl -d megaraid,0 -a $DISK_PATH</code>."
                HTML_OUTPUT+="</div>"
            fi
        fi

        # Build the attribute table into a buffer first. A device can pass the
        # gate below and still yield no rows (a transient smartctl read, for
        # instance), and an empty table with only headers is worse than none.
        SMART_DETAIL=""
        # Add detailed SMART table. Only ATA and NVMe produce one, and the
        # condition requires at least one real row so that SAS, SCSI and RAID
        # devices no longer render an empty table with just headers.
        if [ -n "$SMART_ALL" ] && [ "$DISK_TRANSPORT" != "sas" ] && [ "$DISK_TRANSPORT" != "scsi" ] \
           && [ "$DISK_TRANSPORT" != "raid" ] \
           && echo "$SMART_ALL" | grep -qE "^[[:space:]]*[0-9]+[[:space:]]+[A-Za-z_-]+[[:space:]]|SMART/Health Information"; then
            SMART_DETAIL+="<details class='mb-4'>"
            SMART_DETAIL+="<summary class='cursor-pointer text-blue-600 font-bold p-2 hover:text-blue-800'>View Detailed SMART Attributes</summary>"

            # Check if this is NVMe format (key: value) or traditional SMART (table format)
            if echo "$SMART_ALL" | grep -q "SMART/Health Information"; then
                # NVMe format - display as key-value pairs
                SMART_DETAIL+="<table class='w-full border-collapse shadow-md mt-3 text-xs'>"
                SMART_DETAIL+="<thead>"
                SMART_DETAIL+="<tr class='bg-purple-600 text-white'>"
                SMART_DETAIL+="<th class='px-3 py-2 text-left border border-gray-300'>Attribute</th>"
                SMART_DETAIL+="<th class='px-3 py-2 text-left border border-gray-300'>Value</th>"
                SMART_DETAIL+="</tr>"
                SMART_DETAIL+="</thead>"
                SMART_DETAIL+="<tbody class='bg-white'>"

                ATTR_ROW=0
                while IFS= read -r line; do
                    # Match lines with format "Key:    Value"
                    if echo "$line" | grep -qE "^[A-Za-z].*:"; then
                        ATTR_NAME=$(echo "$line" | awk -F: '{print $1}' | sed 's/^[[:space:]]*//;s/[[:space:]]*$//')
                        ATTR_VALUE=$(echo "$line" | awk -F: '{print $2}' | sed 's/^[[:space:]]*//;s/[[:space:]]*$//')

                        if [ -n "$ATTR_NAME" ] && [ -n "$ATTR_VALUE" ]; then
                            if [ $((ATTR_ROW % 2)) -eq 0 ]; then
                                BG_CLASS="bg-gray-50"
                            else
                                BG_CLASS="bg-white"
                            fi

                            SMART_DETAIL+="<tr class='$BG_CLASS hover:bg-gray-100'>"
                            SMART_DETAIL+="<td class='px-3 py-2 border border-gray-300 font-medium'>$ATTR_NAME</td>"
                            SMART_DETAIL+="<td class='px-3 py-2 border border-gray-300'>$ATTR_VALUE</td>"
                            SMART_DETAIL+="</tr>"
                            ATTR_ROW=$((ATTR_ROW + 1))
                        fi
                    fi
                done <<< "$SMART_ALL"
            else
                # Traditional SMART format - display as full table
                SMART_DETAIL+="<table class='w-full border-collapse shadow-md mt-3 text-xs'>"
                SMART_DETAIL+="<thead>"
                SMART_DETAIL+="<tr class='bg-purple-600 text-white'>"
                SMART_DETAIL+="<th class='px-2 py-2 text-left border border-gray-300'>ID</th>"
                SMART_DETAIL+="<th class='px-2 py-2 text-left border border-gray-300'>Attribute</th>"
                SMART_DETAIL+="<th class='px-2 py-2 text-center border border-gray-300'>Value</th>"
                SMART_DETAIL+="<th class='px-2 py-2 text-center border border-gray-300'>Worst</th>"
                SMART_DETAIL+="<th class='px-2 py-2 text-center border border-gray-300'>Threshold</th>"
                SMART_DETAIL+="<th class='px-2 py-2 text-right border border-gray-300'>Raw Value</th>"
                SMART_DETAIL+="</tr>"
                SMART_DETAIL+="</thead>"
                SMART_DETAIL+="<tbody class='bg-white'>"

                ATTR_ROW=0
                while IFS= read -r line; do
                    if echo "$line" | grep -qE "^[[:space:]]*[0-9]+[[:space:]]"; then
                        ATTR_ID=$(echo "$line" | awk '{print $1}')
                        ATTR_NAME=$(echo "$line" | awk '{print $2}')
                        ATTR_VALUE=$(echo "$line" | awk '{print $4}')
                        ATTR_WORST=$(echo "$line" | awk '{print $5}')
                        ATTR_THRESH=$(echo "$line" | awk '{print $6}')
                        ATTR_RAW=$(echo "$line" | awk '{print $10}')

                        if [ $((ATTR_ROW % 2)) -eq 0 ]; then
                            BG_CLASS="bg-gray-50"
                        else
                            BG_CLASS="bg-white"
                        fi

                        SMART_DETAIL+="<tr class='$BG_CLASS hover:bg-gray-100'>"
                        SMART_DETAIL+="<td class='px-2 py-1.5 border border-gray-300'>$ATTR_ID</td>"
                        SMART_DETAIL+="<td class='px-2 py-1.5 border border-gray-300'>$ATTR_NAME</td>"
                        SMART_DETAIL+="<td class='px-2 py-1.5 border border-gray-300 text-center'>$ATTR_VALUE</td>"
                        SMART_DETAIL+="<td class='px-2 py-1.5 border border-gray-300 text-center'>$ATTR_WORST</td>"
                        SMART_DETAIL+="<td class='px-2 py-1.5 border border-gray-300 text-center'>$ATTR_THRESH</td>"
                        SMART_DETAIL+="<td class='px-2 py-1.5 border border-gray-300 text-right'>$ATTR_RAW</td>"
                        SMART_DETAIL+="</tr>"

                        ATTR_ROW=$((ATTR_ROW + 1))
                    fi
                done <<< "$SMART_ALL"
            fi

            SMART_DETAIL+="</tbody>"
            SMART_DETAIL+="</table>"
            SMART_DETAIL+="</details>"
        fi
        # Only publish the block if at least one DATA row was built. Matching
        # "<tr " alone is wrong: the table's own header row is a <tr> too, so an
        # attribute-less table would always look populated.
        if echo "$SMART_DETAIL" | grep -q "hover:bg-gray-100"; then
            HTML_OUTPUT+="$SMART_DETAIL"
        fi
    else
        HTML_OUTPUT+="<div class='p-3 mb-4 bg-yellow-50 border-l-4 border-yellow-400 rounded'>"
        HTML_OUTPUT+="<span class='font-bold text-yellow-800'>⚠️ SMART Tools Not Available</span><br/>smartctl is not installed. Install smartmontools to view SMART data."
        HTML_OUTPUT+="</div>"
    fi

    # ===== SSD TBW (Total Bytes Written) CHECK =====
    # Only render this panel where the device can actually supply wear data.
    # RAID virtual disks never can, and a SCSI/iSCSI LUN only can if it exposes
    # the endurance indicator, so the panel no longer prints a permanent
    # "not available" warning for devices that were never going to answer.
    WEAR_CAPABLE=true
    [ "$IS_RAID_VD" = true ] && WEAR_CAPABLE=false
    if { [ "$DISK_TRANSPORT" = "sas" ] || [ "$DISK_TRANSPORT" = "scsi" ]; } && [ -z "$SAS_ENDURANCE" ]; then
        WEAR_CAPABLE=false
    fi

    if [ "$IS_SSD" = true ] && [ "$WEAR_CAPABLE" = true ] && command -v smartctl &> /dev/null; then
        HTML_OUTPUT+="<h4 class='text-lg font-semibold text-gray-800 mt-4 mb-3'>SSD Wear Level (TBW)</h4>"

        # Try to get wear leveling indicator
        # Common attributes:
        # ID 233: Media_Wearout_Indicator (Intel)
        # ID 231: SSD_Life_Left (various)
        # ID 177: Wear_Leveling_Count (Samsung)
        # ID 202: Percent_Lifetime_Remain (various)
        # For NVMe: Percentage Used from SMART log

        WEAR_LEVEL=""
        WEAR_PERCENTAGE=""
        TBW_WRITTEN=""

        SMART_ALL=$(smartctl -A "$DISK_PATH" 2>/dev/null)

        # Check for Media Wearout Indicator (ID 233) - Intel SSDs
        MEDIA_WEAROUT=$(echo "$SMART_ALL" | grep "^233 " | awk '{print $4}')
        if [ -n "$MEDIA_WEAROUT" ] && [ "$MEDIA_WEAROUT" -gt 0 ]; then
            WEAR_PERCENTAGE=$MEDIA_WEAROUT
        fi

        # Check for SSD Life Left (ID 231)
        SSD_LIFE_LEFT=$(echo "$SMART_ALL" | grep "^231 " | awk '{print $4}')
        if [ -n "$SSD_LIFE_LEFT" ] && [ "$SSD_LIFE_LEFT" -gt 0 ]; then
            WEAR_PERCENTAGE=$SSD_LIFE_LEFT
        fi

        # Check for Percent Lifetime Remain (ID 202)
        LIFETIME_REMAIN=$(echo "$SMART_ALL" | grep "^202 " | awk '{print $4}')
        if [ -n "$LIFETIME_REMAIN" ] && [ "$LIFETIME_REMAIN" -gt 0 ]; then
            WEAR_PERCENTAGE=$LIFETIME_REMAIN
        fi

        # Check for Wear Leveling Count (ID 177) - Samsung
        WEAR_LEVELING=$(echo "$SMART_ALL" | grep "^177 " | awk '{print $4}')
        if [ -n "$WEAR_LEVELING" ] && [ "$WEAR_LEVELING" -gt 0 ]; then
            WEAR_PERCENTAGE=$WEAR_LEVELING
        fi

        # SAS/SCSI SSDs report endurance consumed rather than life remaining
        if [ -n "$SAS_ENDURANCE" ] && [[ "$SAS_ENDURANCE" =~ ^[0-9]+$ ]] && [ "$SAS_ENDURANCE" -le 100 ]; then
            WEAR_PERCENTAGE=$((100 - SAS_ENDURANCE))
        fi

        # For NVMe drives, check percentage used (reuses the full output already
        # captured in the SMART section rather than calling smartctl again)
        NVME_INFO="$SMART_FULL"
        if echo "$NVME_INFO" | grep -qiE "NVM|NVMe"; then
            PERCENTAGE_USED=$(echo "$NVME_INFO" | grep -i "Percentage Used:" | awk -F: '{print $2}' | tr -d '%' | sed 's/^[[:space:]]*//;s/[[:space:]]*$//')
            if [ -n "$PERCENTAGE_USED" ]; then
                # Convert percentage used to percentage remaining
                WEAR_PERCENTAGE=$((100 - PERCENTAGE_USED))
            fi
        fi

        # Try to get Total LBAs Written (ID 241) or Host Writes (for TBW calculation)
        TOTAL_LBAS_WRITTEN=$(echo "$SMART_ALL" | grep "^241 " | awk '{print $10}')
        DATA_UNITS_WRITTEN=$(echo "$NVME_INFO" | grep -i "Data Units Written:" | awk -F: '{print $2}' | sed 's/^[[:space:]]*//;s/[[:space:]]*$//' | awk '{print $1}' | tr -d ',')

        if [ -n "$DATA_UNITS_WRITTEN" ]; then
            # NVMe data units are 512,000 bytes each (500 KB)
            # Using decimal TB (1 TB = 1,000,000,000,000 bytes) to match smartctl output
            TBW_TB=$(awk "BEGIN {printf \"%.2f\", ($DATA_UNITS_WRITTEN * 512000) / 1000000000000}")
            TBW_WRITTEN="${TBW_TB} TB"
        fi

        if [ -n "$WEAR_PERCENTAGE" ] && [[ "$WEAR_PERCENTAGE" =~ ^[0-9]+$ ]]; then
            # Determine color based on remaining life (validate numeric and within bounds)
            if [ "$WEAR_PERCENTAGE" -ge 50 ]; then
                TBW_COLOR="#27ae60"
                TBW_EXIT_CODE=0
            elif [ "$WEAR_PERCENTAGE" -ge 25 ]; then
                TBW_COLOR="#e67e22"
                TBW_EXIT_CODE=0  # Orange but not error
                [ $GLOBAL_EXIT_CODE -eq 0 ] && GLOBAL_EXIT_CODE=0
            else
                TBW_COLOR="#dc3545"
                TBW_EXIT_CODE=0  # Red but not error (per spec)
                [ $GLOBAL_EXIT_CODE -eq 0 ] && GLOBAL_EXIT_CODE=0
            fi

            HTML_OUTPUT+="<div class='p-3 mb-4 bg-gray-50 rounded' style='border-left: 4px solid $TBW_COLOR;'>"
            HTML_OUTPUT+="<span class='font-bold'>Remaining Life:</span> <span class='font-medium'>${WEAR_PERCENTAGE}%</span>"
            if [ -n "$TBW_WRITTEN" ]; then
                HTML_OUTPUT+=" | <span class='font-bold'>Total Data Written:</span> <span class='font-medium'>$TBW_WRITTEN</span>"
            fi
            HTML_OUTPUT+="<div class='w-full bg-gray-200 rounded overflow-hidden mt-3'>"
            HTML_OUTPUT+="<div class='py-2 text-center text-white font-bold' style='width: ${WEAR_PERCENTAGE}%; background-color: $TBW_COLOR;'>${WEAR_PERCENTAGE}% Life Remaining</div>"
            HTML_OUTPUT+="</div>"
            HTML_OUTPUT+="</div>"
        else
            HTML_OUTPUT+="<div class='p-3 mb-4 bg-yellow-50 border-l-4 border-yellow-400 rounded'>"
            HTML_OUTPUT+="<span class='font-bold text-yellow-800'>⚠️ Wear Level Data Not Available</span><br/>This SSD does not report wear leveling information via SMART attributes."
            if [ -n "$TBW_WRITTEN" ]; then
                HTML_OUTPUT+="<br/><strong>Total Data Written:</strong> $TBW_WRITTEN"
            fi
            HTML_OUTPUT+="</div>"
        fi
    fi

done

# ===== ZFS POOLS AND DATASETS (if ZFS is available) =====
if command -v zfs &> /dev/null && command -v zpool &> /dev/null; then
    # Check if there are any ZFS pools
    ZFS_POOLS=$(zpool list -H -o name,size,allocated,free,capacity,dedupratio,health,altroot 2>/dev/null)

    if [ -n "$ZFS_POOLS" ]; then
        HTML_OUTPUT+="<h3 class='text-xl font-bold text-gray-700 mt-6 mb-3 pb-2 border-b-2 border-blue-500'>💠 ZFS Pools & Datasets</h3>"

        # Display ZFS pools
        HTML_OUTPUT+="<h4 class='text-lg font-semibold text-gray-800 mt-4 mb-3'>ZFS Storage Pools</h4>"
        HTML_OUTPUT+="<table class='w-full border-collapse shadow-md mb-5 text-sm'>"
        HTML_OUTPUT+="<thead>"
        HTML_OUTPUT+="<tr class='bg-blue-600 text-white'>"
        HTML_OUTPUT+="<th class='px-3 py-3 text-left border border-gray-300'>Pool Name</th>"
        HTML_OUTPUT+="<th class='px-3 py-3 text-left border border-gray-300'>Size</th>"
        HTML_OUTPUT+="<th class='px-3 py-3 text-left border border-gray-300'>Allocated</th>"
        HTML_OUTPUT+="<th class='px-3 py-3 text-left border border-gray-300'>Free</th>"
        HTML_OUTPUT+="<th class='px-3 py-3 text-left border border-gray-300'>Capacity</th>"
        HTML_OUTPUT+="<th class='px-3 py-3 text-left border border-gray-300'>Health</th>"
        HTML_OUTPUT+="</tr>"
        HTML_OUTPUT+="</thead>"
        HTML_OUTPUT+="<tbody class='bg-white'>"

        POOL_ROW=0
        while IFS=$'\t' read -r POOL_NAME POOL_SIZE POOL_ALLOC POOL_FREE POOL_CAP POOL_DEDUP POOL_HEALTH POOL_ALTROOT; do
            # Determine health color
            # Valid pool states: ONLINE DEGRADED FAULTED OFFLINE REMOVED UNAVAIL SUSPENDED
            case "$POOL_HEALTH" in
                ONLINE)
                    HEALTH_COLOR="text-green-600"
                    HEALTH_ICON="✓"
                    ;;
                DEGRADED|OFFLINE|REMOVED)
                    HEALTH_COLOR="text-orange-600"
                    HEALTH_ICON="⚠"
                    [ $GLOBAL_EXIT_CODE -lt 4 ] && GLOBAL_EXIT_CODE=4
                    ;;
                FAULTED|UNAVAIL|SUSPENDED)
                    HEALTH_COLOR="text-red-600"
                    HEALTH_ICON="✗"
                    [ $GLOBAL_EXIT_CODE -lt 5 ] && GLOBAL_EXIT_CODE=5
                    ;;
                *)
                    # Unrecognised or empty state: report it, but do not raise
                    # an alert on a string we cannot interpret
                    HEALTH_COLOR="text-gray-500"
                    HEALTH_ICON="?"
                    POOL_HEALTH="${POOL_HEALTH:-Unknown}"
                    ;;
            esac

            # Parse capacity percentage for color coding
            POOL_CAP_NUM=$(echo "$POOL_CAP" | sed 's/%//')
            if [[ "$POOL_CAP_NUM" =~ ^[0-9]+$ ]]; then
                CAP_WIDTH="${POOL_CAP_NUM}%"
                if [ "$POOL_CAP_NUM" -le "$ZFS_CAP_WARN" ]; then
                    CAP_COLOR="#27ae60"
                elif [ "$POOL_CAP_NUM" -le "$ZFS_CAP_CRIT" ]; then
                    CAP_COLOR="#e67e22"
                    [ $GLOBAL_EXIT_CODE -lt 4 ] && GLOBAL_EXIT_CODE=4
                else
                    # A pool this full can fail to free space, so it outranks
                    # a warning rather than sharing the same severity with it
                    CAP_COLOR="#dc3545"
                    [ $GLOBAL_EXIT_CODE -lt 5 ] && GLOBAL_EXIT_CODE=5
                fi
            else
                # Capacity not reportable: render an empty bar rather than
                # emitting invalid CSS such as "width: -"
                CAP_COLOR="#95a5a6"
                CAP_WIDTH="0%"
                POOL_CAP="${POOL_CAP:-n/a}"
            fi

            # Alternate row colors
            if [ $((POOL_ROW % 2)) -eq 0 ]; then
                BG_CLASS="bg-gray-50"
            else
                BG_CLASS="bg-white"
            fi

            HTML_OUTPUT+="<tr class='$BG_CLASS hover:bg-gray-100'>"
            HTML_OUTPUT+="<td class='px-3 py-2.5 border border-gray-300'><span class='font-semibold'>$POOL_NAME</span></td>"
            HTML_OUTPUT+="<td class='px-3 py-2.5 border border-gray-300'>$POOL_SIZE</td>"
            HTML_OUTPUT+="<td class='px-3 py-2.5 border border-gray-300'>$POOL_ALLOC</td>"
            HTML_OUTPUT+="<td class='px-3 py-2.5 border border-gray-300'>$POOL_FREE</td>"
            HTML_OUTPUT+="<td class='px-3 py-2.5 border border-gray-300'>"
            HTML_OUTPUT+="<div class='w-full bg-gray-200 rounded overflow-hidden'>"
            HTML_OUTPUT+="<div class='py-1 text-center text-white font-bold text-xs' style='width: ${CAP_WIDTH}; background-color: $CAP_COLOR;'>${POOL_CAP}</div>"
            HTML_OUTPUT+="</div>"
            HTML_OUTPUT+="</td>"
            HTML_OUTPUT+="<td class='px-3 py-2.5 border border-gray-300'><span class='$HEALTH_COLOR font-semibold'>$HEALTH_ICON $POOL_HEALTH</span></td>"
            HTML_OUTPUT+="</tr>"

            POOL_ROW=$((POOL_ROW + 1))
        done <<< "$ZFS_POOLS"

        HTML_OUTPUT+="</tbody>"
        HTML_OUTPUT+="</table>"

        # Display ZFS datasets (filesystems)
        ZFS_DATASETS=$(zfs list -H -o name,used,avail,refer,mountpoint -t filesystem 2>/dev/null)

        if [ -n "$ZFS_DATASETS" ]; then
            HTML_OUTPUT+="<h4 class='text-lg font-semibold text-gray-800 mt-4 mb-3'>ZFS Datasets (Filesystems)</h4>"
            HTML_OUTPUT+="<table class='w-full border-collapse shadow-md mb-5 text-sm'>"
            HTML_OUTPUT+="<thead>"
            HTML_OUTPUT+="<tr class='bg-blue-600 text-white'>"
            HTML_OUTPUT+="<th class='px-3 py-3 text-left border border-gray-300'>Dataset Name</th>"
            HTML_OUTPUT+="<th class='px-3 py-3 text-left border border-gray-300'>Used</th>"
            HTML_OUTPUT+="<th class='px-3 py-3 text-left border border-gray-300'>Available</th>"
            HTML_OUTPUT+="<th class='px-3 py-3 text-left border border-gray-300'>Referenced</th>"
            HTML_OUTPUT+="<th class='px-3 py-3 text-left border border-gray-300'>Mount Point</th>"
            HTML_OUTPUT+="</tr>"
            HTML_OUTPUT+="</thead>"
            HTML_OUTPUT+="<tbody class='bg-white'>"

            DATASET_ROW=0
            while IFS=$'\t' read -r DS_NAME DS_USED DS_AVAIL DS_REFER DS_MOUNT; do
                # Alternate row colors
                if [ $((DATASET_ROW % 2)) -eq 0 ]; then
                    BG_CLASS="bg-gray-50"
                else
                    BG_CLASS="bg-white"
                fi

                HTML_OUTPUT+="<tr class='$BG_CLASS hover:bg-gray-100'>"
                HTML_OUTPUT+="<td class='px-3 py-2.5 border border-gray-300'><span class='font-medium'>$DS_NAME</span></td>"
                HTML_OUTPUT+="<td class='px-3 py-2.5 border border-gray-300'>$DS_USED</td>"
                HTML_OUTPUT+="<td class='px-3 py-2.5 border border-gray-300'>$DS_AVAIL</td>"
                HTML_OUTPUT+="<td class='px-3 py-2.5 border border-gray-300'>$DS_REFER</td>"
                HTML_OUTPUT+="<td class='px-3 py-2.5 border border-gray-300'>$DS_MOUNT</td>"
                HTML_OUTPUT+="</tr>"

                DATASET_ROW=$((DATASET_ROW + 1))
            done <<< "$ZFS_DATASETS"

            HTML_OUTPUT+="</tbody>"
            HTML_OUTPUT+="</table>"
        fi
    fi
fi

HTML_OUTPUT+="</div>"

# Set the WYSIWYG custom field in NinjaOne using ninjarmm-cli
echo "$HTML_OUTPUT" | /opt/NinjaRMMAgent/programdata/ninjarmm-cli set --stdin "$wysiwygCustomField"

# Also output to console for visibility
echo "Storage information has been written to custom field: $wysiwygCustomField"
echo "Platform: $VM_PLATFORM"
echo "Disks found: $DISK_COUNT"

# Exit with appropriate code
if [ "$IS_VIRTUAL_MACHINE" = true ]; then
    echo "Exit Code: 0 (Virtual Machine - SMART checks skipped)"
    exit 0
else
    case $GLOBAL_EXIT_CODE in
        0)
            echo "Exit Code: 0 (No issues detected)"
            ;;
        4)
            echo "Exit Code: 4 (Storage warnings detected)"
            ;;
        5)
            echo "Exit Code: 5 (Serious storage issues detected)"
            ;;
    esac
    exit $GLOBAL_EXIT_CODE
fi
