# NinjaOne RMM Storage Information Script Documentation (Linux/Bash)

> **Note:** Parts of this script and documentation were written with the assistance of AI (Claude by Anthropic) to speed up the process of writing documentation, implementing logic, and generating HTML output.

> **Disclaimer:** Running this script is at your own risk. It has been tested on a limited set of hardware and storage configurations including SATA/SAS disks, NVMe drives, hardware RAID controllers, multipath SAN LUNs and ZFS pools. Results may vary on other configurations. The script is read-only - it queries device state and never modifies partitions, filesystems or pools.

## Overview

I created this Bash script to collect storage device details from Linux systems and display them in a formatted HTML report within NinjaOne RMM's WYSIWYG custom field.

It reports every physical disk with its partitions and usage, SMART health and the critical SMART attributes behind it, SSD wear level and total bytes written, and - where present - ZFS pool and dataset state. Beyond reporting, it raises a NinjaOne result code when something is genuinely wrong, so failing disks and full pools surface as alerts rather than as text somebody has to read.

Most of the complexity is in the awkward cases: a SAN LUN visible over four paths should be counted once, a hardware RAID virtual disk exposes no SMART of its own, a ZFS zvol is not a physical disk, and a VM has no SMART data at all and must not be alerted on for its absence.

---

## Requirements

### Platform Requirements

- **Operating System**: Linux (any distribution)
- **Shell**: Bash
- **Privileges**: **root**. `smartctl` and several disk queries require it. The script refuses to run otherwise and reports that in the custom field.

### System Requirements

| Tool | Package | Required | Purpose |
|------|---------|----------|---------|
| `lsblk` | `util-linux` | Yes | Disk, partition and serial enumeration |
| `smartctl` | `smartmontools` | On physical hosts | SMART health, attributes, NVMe log, TBW |
| `dmidecode` | `dmidecode` | No | Virtual machine detection (falls back to `/sys` and `/proc/cpuinfo`) |
| `zfs` / `zpool` | `zfsutils-linux` / `sys-fs/zfs` | No | ZFS pool and dataset reporting - skipped entirely when absent |
| `perccli` / `storcli` | vendor | No | Improves member enumeration behind some RAID controllers |

Install the mandatory tools with `apt install util-linux smartmontools` or `yum install util-linux smartmontools`.

> **Note: Missing tools exit 0, not 1**
>
> If `lsblk` or `smartctl` is missing, the script writes an explanatory panel to the custom field with the install command and exits **0**. A device that has not been prepared yet is a deployment gap, not a storage fault, and alerting on it would bury real disk failures in noise.

### NinjaOne Requirements

- NinjaOne RMM agent installed on the target system
- A WYSIWYG-type custom field configured in NinjaOne to receive the HTML output
- Script variable `wysiwygcustomfield` configured in NinjaOne script deployment

> **Note: The report loads Tailwind CSS from a CDN**
>
> The HTML begins with `<script src='https://cdn.tailwindcss.com'></script>` and styles the report with Tailwind utility classes. This means the **browser viewing the custom field** needs access to `cdn.tailwindcss.com`. The script itself makes no outbound connection - nothing is fetched on the monitored host. On a workstation behind a proxy that blocks the CDN the report still renders, but unstyled.

---

## What the Script Does

I designed this script to perform the following tasks:

1. **Validates the Environment**
   - Confirms the `wysiwygcustomfield` variable is set, exiting 1 if not
   - Confirms it is running as root, reporting into the custom field if not
   - Changes to a safe working directory, so a deleted CWD cannot cause `getcwd` errors

2. **Detects Virtual Machines**
   - `dmidecode` manufacturer strings for QEMU, VMware, VirtualBox, innotek, Xen, Parallels and Bochs
   - Microsoft Corporation plus a "Virtual" product name for Hyper-V
   - `/sys/class/dmi/id/` files as a fallback
   - The `hypervisor` CPU flag in `/proc/cpuinfo` as a final fallback

3. **Checks Tool Availability**
   - Requires `lsblk` always, and `smartctl` only on physical hosts

4. **Enumerates Physical Disks**
   - Excludes loop devices, ramdisks and ZFS zvols (`zd0`, `zd1`, `zd192`, …), which are virtual block devices rather than physical disks

5. **Collapses Multipath Duplicates**
   - Groups disks by serial plus size, keeps the first path and records the rest as aliases

6. **Reports Partitions and Usage**
   - Per-disk partition table with mount points and space usage

7. **Reports SMART Health**
   - Overall self-assessment result
   - Critical attributes including reallocated sectors (ID 5) and current pending sectors (ID 197)
   - SCSI-generic fields covering SAS SSDs, temperature and the error counter log
   - NVMe critical warning flags

8. **Handles RAID Virtual Disks**
   - A virtual disk has no SMART of its own, so members are queried through the controller device specs reported by `smartctl --scan-open`

9. **Reports SSD Wear and TBW**
   - Vendor wear indicators: Media_Wearout_Indicator (ID 233, Intel), Wear_Leveling_Count (ID 177, Samsung)
   - Total LBAs Written (ID 241) for SATA
   - Data Units Written for NVMe, converted to TB

10. **Reports ZFS Pools and Datasets**
    - Pool size, allocation, free space, capacity percentage, dedup ratio and health
    - Dataset listing
    - Only when both `zfs` and `zpool` are present, and at least one pool exists

11. **Outputs to NinjaOne**
    - Writes the HTML report through `ninjarmm-cli set --stdin`
    - Exits with a result code reflecting the worst condition found

---

## How the Script Performs This

### Multipath Collapsing

A SAN LUN reachable over more than one path appears once per path, so the same LUN shows up as `sdb`, `sdc`, `sdd` and `sde` under different kernel names. Reporting all four triples the apparent disk count and reports the same SMART data repeatedly.

The script builds a key from the device's **serial plus size**, keeps the first device seen for that key, and records the remaining paths as aliases on it:

```bash
MP_KEY="${MP_SERIAL}|${MP_SIZE}"
```

The report therefore counts LUNs, not paths. A device with no readable serial, or a serial of `Unknown`, is never collapsed - without a reliable key, two genuinely separate disks could otherwise be merged into one.

### Virtual Machines and SMART

A VM's virtual disk has no SMART data, and that absence is normal rather than a fault. Two things follow:

- `smartctl` is not treated as a required tool on a virtual machine, so a VM without `smartmontools` still produces a full report instead of the missing-tools panel
- The script **always exits 0 on a virtual machine**, regardless of what was collected, so a hypervisor guest can never raise a disk-health alert it has no way to substantiate

### RAID Virtual Disks

A hardware RAID virtual disk presents one block device to Linux and exposes no SMART of its own. Querying it directly returns nothing useful, which would otherwise read as "no problems".

Instead the script asks `smartctl --scan-open` which controller device specs exist and reports each physical member through them. When the scan returns nothing - common when the vendor CLI is absent - it says so explicitly and suggests installing `perccli`/`storcli` or querying members directly with `smartctl -d megaraid,0 -a /dev/sdX`, rather than silently reporting a healthy array.

### Deliberately Non-Alerting Conditions

Several conditions are reported but never raise a result code, because each would otherwise generate noise that buries real faults:

| Condition | Why it does not alert |
|-----------|----------------------|
| Missing `lsblk` / `smartctl` | Deployment gap, not a storage fault |
| No physical disks found | Nothing to assess |
| Running on a virtual machine | No SMART data exists to judge |
| Temperature reported as 0 °C | A LUN with no thermal sensor answers 0; treated as not reported |
| Non-medium errors | Usually bus-level events rather than media faults |
| Unrecognised ZFS pool state | The script will not alert on a string it cannot interpret |

### ZFS Capacity Thresholds

Two tunable constants sit near the top of the script:

```bash
ZFS_CAP_WARN=88
ZFS_CAP_CRIT=90
```

A ZFS pool that is genuinely full can fail to free space - deleting files needs space to write new metadata - so a full pool outranks an ordinary warning and maps to result code 5 rather than 4. Adjust these two values to change the thresholds; nothing else needs editing.

Pool health is matched against the full set of valid states: `ONLINE`, `DEGRADED`, `FAULTED`, `OFFLINE`, `REMOVED`, `UNAVAIL`, `SUSPENDED`.

### Result Code Escalation

A single `GLOBAL_EXIT_CODE` accumulates across every disk and pool, and only ever rises:

```bash
[ $GLOBAL_EXIT_CODE -lt 5 ] && GLOBAL_EXIT_CODE=5
```

One failing disk on a host with twenty healthy ones still produces result code 5. A later healthy device cannot lower a code an earlier faulty one raised.

### NinjaOne Integration

Output is written with the Linux agent CLI:

```
/opt/NinjaRMMAgent/programdata/ninjarmm-cli set --stdin "$wysiwygCustomField"
```

`--stdin` is used throughout because the HTML report is far too large to pass as a command-line argument.

---

## How to Use with NinjaOne RMM

### Step 1: Create the Custom Field

1. Log in to the NinjaOne admin portal
2. Navigate to **Administration** > **Devices** > **Role Custom Fields** (or Global Custom Fields)
3. Click **Add** to create a new custom field
4. Configure the field:
   - **Label**: `Storage Information` (or your preferred name)
   - **Name**: `storageinfo` (API name, remember this)
   - **Field Type**: **WYSIWYG** (important - must be WYSIWYG for HTML rendering)
   - **Technician Permission**: Read Only (or as needed)
   - **Automations**: Read/Write
5. Save the custom field

### Step 2: Upload the Script

1. Navigate to **Administration** > **Library** > **Automation**
2. Click **Add** > **New Script**
3. Configure:
   - **Name**: `Storage Information`
   - **Language**: Bash / Shell
   - **OS**: Linux
   - **Architecture**: All
   - **Run As**: Root
4. Paste the script content
5. Save the script

### Step 3: Configure Script Variables

1. In the script editor, click **Script Variables**
2. Add a new variable:
   - **Variable Name**: `wysiwygcustomfield`
   - **Variable Type**: Text
   - **Default Value**: `storageinfo` (the API name from Step 1)
   - **Required**: Yes
3. Save the variable

> **Note**: NinjaOne lowercases variable names before exposing them to the script. The script reads `$wysiwygcustomfield`, so keep the variable name entirely lower-case.

### Step 4: Install Prerequisites on Targets

On physical hosts, ensure `smartmontools` and `util-linux` are installed:

```bash
apt install util-linux smartmontools      # Debian / Ubuntu
yum install util-linux smartmontools      # RHEL / Rocky / Alma
emerge sys-apps/smartmontools             # Gentoo
```

Hosts behind a hardware RAID controller benefit from the vendor CLI (`perccli` or `storcli`) as well.

### Step 5: Run the Script

#### Manual Execution
1. Navigate to a Linux device in NinjaOne
2. Click **Run Script** or use the Actions menu
3. Select `Storage Information`
4. Verify the `wysiwygcustomfield` value matches your custom field API name
5. Run the script

#### Scheduled Execution
1. Create a scheduled task or policy
2. Add the script as an action
3. Configure the schedule (for example daily)
4. Ensure the script variable is set correctly

#### Condition-Based Execution
1. Create a condition in NinjaOne based on the script result
2. Alert on result code 4 for warnings and 5 for serious issues

### Step 6: View the Results

1. Navigate to a device that has run the script
2. Go to the device's **Details** tab
3. Find your custom field (for example "Storage Information")

The report contains:

- A platform banner showing Physical or Virtual Machine, and the collection timestamp
- One section per disk: partitions and usage, SMART health status, and SSD wear level where applicable
- A ZFS section with pools and datasets, on hosts that have them

### Script Variable Reference

| Variable | Type | Required | Description |
|----------|------|----------|-------------|
| `wysiwygcustomfield` | Text | Yes | The API name of the WYSIWYG custom field where the HTML output will be written. This must match the "Name" field, not the Label, of your custom field in NinjaOne. |

### Exit Codes

| Code | Meaning |
|------|---------|
| 0 | Success - no issues detected, or a non-alerting condition (virtual machine, missing tools, no disks found) |
| 1 | Error - `wysiwygcustomfield` not set, or not running as root |
| 4 | Warning - storage warnings detected (SMART attribute concerns, ZFS capacity above the warn threshold) |
| 5 | Serious - failing SMART health, NVMe critical warnings, or a ZFS pool above the critical threshold or in a bad state |

Build NinjaOne conditions on codes 4 and 5. Note that code 0 covers several distinct situations, so a device reporting 0 is not necessarily a device that was fully assessed - check the report body on VMs and on hosts where tooling may be missing.

---

## Troubleshooting

### Common Issues

**"wysiwygCustomField variable is not set"**
- Add the script variable in NinjaOne and confirm the name is exactly `wysiwygcustomfield`, all lower case.

**"This script requires root privileges"**
- Configure the script to run as root in NinjaOne. SMART queries cannot work otherwise.

**HTML appears as raw text instead of formatted**
- The custom field type must be WYSIWYG, not Text or Multi-line Text.

**The report renders unstyled**
- The browser viewing the field cannot reach `https://cdn.tailwindcss.com`. Content is unaffected; only styling is lost.

**"Missing Tools" panel and exit code 0**
- Install `smartmontools` and `util-linux` on the target. Exit 0 here is intentional so unprepared devices do not drown out real disk alerts.

**A RAID array reports no SMART data**
- Expected for a virtual disk. Install `perccli` or `storcli` so `smartctl --scan-open` can enumerate the physical members, or query them directly with `smartctl -d megaraid,0 -a /dev/sdX`.

**The same LUN still appears more than once**
- Multipath collapsing keys on serial plus size. A device reporting no serial, or `Unknown`, is deliberately never collapsed, because merging on an unreliable key risks hiding a genuinely separate disk.

**A virtual machine never alerts even when the guest disk is failing**
- By design. A VM has no SMART data to judge, so the script always exits 0 there. Monitor the underlying hypervisor's physical disks instead.

**ZFS section missing on a host with pools**
- Both `zfs` and `zpool` must be on `PATH` for the root user running the script.

---

## Version History

| Version | Date | Changes |
|---------|------|---------|
| 1.0 | 2026-08-25 | Initial release. Per-disk partitions and usage, SMART health with critical attributes (reallocated and pending sectors, SCSI error counter log, NVMe critical warnings), SSD wear level and TBW for SATA and NVMe, and ZFS pool and dataset reporting with tunable capacity thresholds. Collapses multipath duplicates by serial and size, excludes ZFS zvols from physical disk enumeration, reports RAID virtual disk members through controller device specs, detects virtual machines through four independent methods and suppresses SMART alerting on them, and escalates a single global result code across all devices. |
