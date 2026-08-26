# NinjaOne RMM Hyper-V Checkpoint (AVHDX) Audit Script Documentation

> **Note:** Parts of this script and documentation were written with the assistance of AI (Claude by Anthropic) to speed up the process of writing documentation, implementing logic, and generating HTML output.

> **Disclaimer:** Running this script is at your own risk. It has been tested on Windows Server Hyper-V hosts with VHDX-based virtual machines. Results may vary on other configurations. The script itself is read-only with respect to virtual machines and virtual disks - it never creates, merges, deletes or repoints anything.

## Overview

I created this PowerShell script to detect Hyper-V virtual disks that have accumulated checkpoint (AVHDX) files which were never merged back into their base disk.

This matters because the failure is silent. A backup product takes a checkpoint before each job and merges it afterwards; when that merge fails, nothing alerts and the next job simply adds another checkpoint. Chains hundreds of links deep build up over months or years, crippling disk performance, consuming enormous amounts of space, and leaving a VM that can be rendered unbootable by a careless attempt to merge them.

The script enumerates every VM on the host, walks each attached virtual disk's differencing chain down to its base, counts the AVHDX files along the way, and warns when any single disk exceeds a configurable maximum. It also flags the two conditions that explain *why* a chain stopped merging: a block-size mismatch that makes the merge impossible, and orphaned AVHDX files that Hyper-V no longer tracks as checkpoints.

---

## Requirements

### Platform Requirements

- **Operating System**: Windows Server with the Hyper-V role, or Windows 10/11 with Hyper-V enabled
- **PowerShell Version**: Windows PowerShell 5.1 (no PowerShell 7 features are used)
- **PowerShell Module**: `Hyper-V` (installed with the Hyper-V role or feature)
- **Privileges**: Administrator or SYSTEM. `Get-VM` and `Get-VHD` both require elevation.

### NinjaOne Requirements

- NinjaOne RMM agent installed on the target system
- Script variable `avhdxthreshold` configured and set (**required**)
- A WYSIWYG-type custom field and the `wysiwygcustomfield` variable (**optional** - omit for console-only reporting)

> **Note: Safe to target broadly**
>
> The script checks whether the device is a Hyper-V host **before** it validates its variables, and exits 0 quietly if it is not. That means it can be aimed at a mixed policy containing servers and workstations without generating failures on every non-Hyper-V device.

> **Note: Read-only by design**
>
> This audit never merges, deletes or repoints a disk. That is deliberate - merging a long or damaged chain is a decision that needs a human, a maintenance window and a backup. The script tells you what is wrong and why; acting on it is a separate, manual job.

### External PowerShell Modules

None beyond the in-box `Hyper-V` module. Nothing is downloaded or installed.

---

## What the Script Does

I designed this script to perform the following tasks:

1. **Confirms the Device Is a Hyper-V Host**
   - Checks that the `Get-VM` cmdlet from the `Hyper-V` module is available
   - Checks the `vmms` (Hyper-V Virtual Machine Management) service
   - Exits 0 immediately on any device that is not a Hyper-V host, before variable validation

2. **Validates the Environment**
   - Confirms `avhdxthreshold` is set and parses as a valid integer
   - Exits 1 on a missing or invalid threshold, or if the Hyper-V module is broken

3. **Enumerates Every Virtual Machine**
   - Audits all VMs regardless of power state, because a powered-off VM accumulates checkpoints just as readily as a running one

4. **Walks Each Virtual Disk's Chain**
   - Follows `ParentPath` from the attached disk down to the base
   - Counts AVHDX files and differencing disks encountered along the way
   - Records the base disk's path, type and block size

5. **Detects Chain Faults**
   - Circular parent references
   - Chains exceeding the 1000-link traversal ceiling
   - Disks that cannot be read at all

6. **Flags Block-Size Mismatches**
   - Compares the attached disk's block size against its base
   - A mismatch means the chain physically cannot merge, no matter how often the backup product retries

7. **Identifies Orphaned Checkpoints**
   - Compares the AVHDX file count against the number of checkpoints Hyper-V actually has registered
   - A large gap is the signature of a backup product whose post-backup merge has been failing

8. **Reports the Findings**
   - Writes a per-VM, per-disk breakdown to the console
   - Optionally writes a styled HTML report to a WYSIWYG custom field
   - Exits 4 when any disk exceeds the threshold

---

## How the Script Performs This

### Chain Traversal

Each attached virtual disk is the head of a chain. `Get-VHD` reports a `ParentPath` for differencing disks, so the walk is a simple loop that follows parents until it reaches a disk with no parent - the base.

Three guards protect that loop:

| Guard | Purpose |
|-------|---------|
| Visited-set (`HashSet[string]`, lower-cased paths) | Detects a circular parent reference and stops with a `ChainError` instead of looping forever |
| `$script:MaxChainDepth` (1000) | Hard ceiling in case a corrupt locator produces an endless non-repeating chain |
| Per-disk try/catch | An unreadable disk ends that chain with a `ChainError` rather than killing the whole run |

When a walk ends on an error, the reported `AvhdxCount` reflects only what was reachable. The script says so explicitly - those counts are described as **lower bounds, not totals**, so a partial read is never mistaken for a clean result.

### Result Caching

`Get-VHD` results are cached per run in `$script:VhdCache`, keyed on the lower-cased path. VM farms built from a shared parent disk resolve the same ancestors over and over, and on a host with a deep chain that duplicated work is the dominant cost of the script.

### Why Block Size Matters

This is the specific failure the script was written to catch.

A checkpoint AVHDX inherits a block size at creation. If it differs from the base VHDX's block size, Hyper-V cannot merge the child into the parent and rejects the operation with:

```
0x80070032  ERROR_NOT_SUPPORTED
```

The backup product sees a failed merge, leaves the checkpoint in place, and takes another one on the next run. Nothing in the Hyper-V console makes the cause visible. The result is a chain that grows forever and can never clear itself, which is exactly how a host ends up with years of accumulated orphans.

The script compares the attached disk's block size against the base and reports, for example:

```
BLOCK SIZE MISMATCH: attached 2 MB vs base 32 MB - this chain cannot merge into its base.
```

A 2 MB child against a 32 MB base is the classic signature.

### Orphaned Checkpoints

Hyper-V tracks checkpoints as objects. AVHDX files are what those checkpoints are made of, but the two can drift apart: when a merge half-completes or a checkpoint is deleted while its file is locked, the file remains on disk with nothing referencing it.

The script counts both and compares:

```
NOTE: 47 AVHDX file(s) present but only 2 registered checkpoint(s) - the remainder are orphans.
```

That gap is the clearest single indicator that a backup product's post-backup merge has been failing for a long time.

### Disks That Are Skipped

Pass-through (physical) disks and VHD Sets carry no file path the script can resolve, so they are skipped rather than reported as errors. They cannot hold an AVHDX chain in the first place.

### Error Handling Philosophy

`$ErrorActionPreference` is `Stop` so the `try`/`catch` blocks reliably catch cmdlet errors that would otherwise be non-terminating. `Set-StrictMode` is deliberately **not** used: strict mode turns any unexpected object shape into a hard crash, and an unattended monitor should degrade to a partial report rather than dying.

### NinjaOne Integration

I implemented two methods to set the custom field value, matching the other scripts in this repository:

1. **Ninja-Property-Set cmdlet** (preferred) - the native cmdlet injected by the NinjaOne agent
2. **ninjarmm-cli.exe with --stdin** (fallback) - at `C:\ProgramData\NinjaRMMAgent\ninjarmm-cli.exe`

If both fail, the script warns and continues. The console report and the exit code remain valid - a custom field write failure never invalidates the audit.

The HTML uses inline styles only, because NinjaOne WYSIWYG fields permit the `class` attribute but provide no stylesheet for it to reference.

---

## How to Use with NinjaOne RMM

### Step 1: Create the Custom Field (optional)

Skip this step if you only want console output.

1. Log in to the NinjaOne admin portal
2. Navigate to **Administration** > **Devices** > **Role Custom Fields** (or Global Custom Fields)
3. Click **Add** to create a new custom field
4. Configure the field:
   - **Label**: `Hyper-V Checkpoint Audit` (or your preferred name)
   - **Name**: `hypervcheckpointaudit` (API name, remember this)
   - **Field Type**: **WYSIWYG** (important - must be WYSIWYG for HTML rendering)
   - **Technician Permission**: Read Only (or as needed)
   - **Automations**: Read/Write
5. Save the custom field

### Step 2: Upload the Script

1. Navigate to **Administration** > **Library** > **Automation**
2. Click **Add** > **New Script**
3. Configure:
   - **Name**: `Hyper-V Checkpoint (AVHDX) Audit`
   - **Language**: PowerShell
   - **OS**: Windows
   - **Architecture**: All
   - **Run As**: System
4. Paste the script content
5. Save the script

### Step 3: Configure Script Variables

1. In the script editor, click **Script Variables**
2. Add the required variable:
   - **Variable Name**: `avhdxthreshold`
   - **Variable Type**: Integer
   - **Default Value**: `3`
   - **Required**: Yes
3. Add the optional variable, if you created a custom field:
   - **Variable Name**: `wysiwygcustomfield`
   - **Variable Type**: Text
   - **Default Value**: `hypervcheckpointaudit` (the API name from Step 1)
   - **Required**: No
4. Save the variables

### Step 4: Run the Script

#### Manual Execution
1. Navigate to a Hyper-V host in NinjaOne
2. Click **Run Script** or use the Actions menu
3. Select `Hyper-V Checkpoint (AVHDX) Audit`
4. Verify the threshold, and that `wysiwygcustomfield` matches your custom field API name
5. Run the script

#### Scheduled Execution
1. Create a scheduled task or policy
2. Add the script as an action
3. Configure the schedule (for example daily, after the backup window)
4. Ensure `avhdxthreshold` is set correctly

Running it shortly after the nightly backup window is the most useful schedule, because that is when an unmerged checkpoint will have just appeared.

#### Condition-Based Execution
1. Create a condition in NinjaOne based on the script result
2. Alert on result code 4 to catch chains growing past the threshold

### Step 5: View the Results

Console output gives a per-VM, per-disk breakdown:

```
=== Hyper-V Checkpoint (AVHDX) Audit ===

  Virtual machine 'APP01' [Running]
    SCSI 0:0     AVHDX: 2     chain links: 3     base: APP01-disk1.vhdx
    SCSI 0:1     AVHDX: 47    chain links: 48    base: APP01-data.vhdx  [OVER THRESHOLD]
                 BLOCK SIZE MISMATCH: attached 2 MB vs base 32 MB - this chain cannot merge into its base.
    NOTE: 49 AVHDX file(s) present but only 2 registered checkpoint(s) - the remainder are orphans.

RESULT CODE 4: WARNING - more than 3 AVHDX file(s) detected on 1 virtual disk(s).
```

If you configured a custom field, the same information appears as an HTML table on the device's **Details** tab.

### Step 6: Act on the Findings

The script deliberately stops at reporting. When a chain is flagged:

1. Confirm a current, restorable backup exists **before** touching anything
2. Check whether the backup product's own merge can be retried
3. If a block-size mismatch is reported, the chain will never merge as-is - the base or the checkpoints must be rebuilt with a matching block size
4. Schedule the work in a maintenance window - merging a long chain is I/O-heavy and the VM should be off

### Script Variable Reference

| Variable | Type | Required | Description |
|----------|------|----------|-------------|
| `avhdxthreshold` | Integer | Yes | Maximum number of AVHDX files tolerated on a single virtual disk before the script warns. Typical value: `3`. Passed as a string by NinjaOne even when declared Integer, and parsed by the script. |
| `wysiwygcustomfield` | Text | No | API name of the WYSIWYG custom field to receive the HTML report. This must match the "Name" field, not the Label. Omit for console-only reporting. |

### Exit Codes

| Code | Meaning |
|------|---------|
| 0 | OK - no virtual disk exceeds the threshold, **or** this device is not a Hyper-V host |
| 1 | Error - missing or invalid `avhdxthreshold`, or the Hyper-V module could not be used |
| 4 | Warning - one or more virtual disks exceed the configured maximum |

Result code 4 is the one to build a NinjaOne condition on. Note that code 0 covers both "healthy Hyper-V host" and "not a Hyper-V host at all", which is what makes the script safe to run against a mixed device policy.

---

## Troubleshooting

### Common Issues

**Every device reports code 0, including known Hyper-V hosts**
- Confirm the script runs as System, not as a user. `Get-VM` is unavailable without elevation, and the host detection will conclude the device is not a Hyper-V host.
- Confirm the `vmms` service is running.

**"avhdxthreshold" errors and exit code 1**
- Add the script variable in NinjaOne and confirm the name matches exactly, in lower case.
- The value must parse as an integer.

**Chain errors reported for several disks**
- "Cannot read *file*" usually means the file is locked or on storage that is currently unavailable. Re-run when the VM or storage is in a normal state.
- Remember the AVHDX counts in a run with chain errors are lower bounds. Treat the result as incomplete rather than clean.

**A VM shows AVHDX files but zero registered checkpoints**
- Those are orphans. Hyper-V is no longer tracking them, so they will not disappear by deleting checkpoints in the console.

**Block-size mismatch reported - what now?**
- The chain cannot merge in place. Retrying the backup product's merge will not help, and repeated retries just add more checkpoints. This needs a planned rebuild of the disk with a matching block size.

**HTML appears as raw text instead of formatted**
- The custom field type must be WYSIWYG, not Text or Multi-line Text.

**Script takes a long time on a host with deep chains**
- Expected. Each link in a chain is a separate `Get-VHD` call. The per-run cache removes duplicated ancestor lookups, but a genuinely deep chain still has to be walked link by link.

---

## Version History

| Version | Date | Changes |
|---------|------|---------|
| 1.0 | 2026-08-14 | Initial release. Walks every attached virtual disk's differencing chain per VM and counts AVHDX files, with circular-reference detection, a 1000-link traversal ceiling and a per-run `Get-VHD` cache. Detects block-size mismatches between the attached disk and its base (the `0x80070032` merge failure) and orphaned AVHDX files not tracked as registered checkpoints. Audits VMs in any power state, skips pass-through disks and VHD Sets, exits 0 on non-Hyper-V devices before variable validation, and optionally writes an inline-styled HTML report to a WYSIWYG custom field. |
