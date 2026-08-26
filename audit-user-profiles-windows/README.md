# NinjaOne RMM User Profile Audit Script Documentation

> **Note:** Parts of this script and documentation were written with the assistance of AI (Claude by Anthropic) to speed up the process of writing documentation, implementing logic, and generating output.

> **Disclaimer:** Running this script is at your own risk. This particular script is read-only and changes nothing on the target system, but results may vary on hardware and Windows configurations other than those it has been tested on.

## Overview

I created this PowerShell script as the read-only companion to the [Cleanup Inactive Local User Accounts](../clean-user-profiles-windows/README.md) script. It reports, for every folder under `C:\Users`, whether a matching `ProfileList` registry entry exists, what the real last logon time was, and what the folder contains.

I use it for two things: deciding what the cleanup script *would* do before actually running it, and identifying leftover husks after a cleanup run that could not fully complete.

Unlike most scripts in this repository, this one writes plain text to the console rather than HTML to a WYSIWYG custom field. The output is meant to be read in the NinjaOne script result window.

---

## Requirements

### Platform Requirements

- **Operating System**: Windows (any version with the standard `ProfileList` registry layout - Windows 10, Windows 11, Server 2016 and newer)
- **PowerShell Version**: Windows PowerShell 5.1 (no PowerShell 7 features are used)
- **Privileges**: Administrator / SYSTEM. Reading `HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList` and enumerating other users' profile folders both require elevation.

### NinjaOne Requirements

- NinjaOne RMM agent installed on the target system
- No custom field required
- No script variables required

> **Note: Read-only by design**
>
> This script performs no deletions, no registry writes and no service changes. It is safe to run on production machines at any time, including during business hours. Every classification it prints is advisory - the decision to act on it belongs to the cleanup script or to you.

### External PowerShell Modules

None. The script uses only built-in cmdlets (`Get-ChildItem`, `Get-ItemProperty`).

---

## What the Script Does

I designed this script to perform the following tasks:

1. **Reads the Profile Registry**
   - Enumerates every subkey of `HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList`
   - Retrieves each entry's `ProfileImagePath` so folders can be matched to SIDs

2. **Enumerates Profile Folders**
   - Lists every directory under `C:\Users`, including hidden ones (`-Force`)
   - Sorts alphabetically so output is stable between runs

3. **Recognises System Folders**
   - `Public`, `Default`, `Default User` and `All Users` are labelled as SYSTEM folders and skipped without further analysis

4. **Determines the Real Last Logon**
   - Reads `LocalProfileLoadTimeHigh` / `LocalProfileLoadTimeLow` and `LocalProfileUnloadTimeHigh` / `LocalProfileUnloadTimeLow`
   - Reassembles each split FILETIME and takes the most recent of the two

5. **Classifies Every Folder**
   - `SYSTEM folder` - built-in, never a cleanup candidate
   - `IN REGISTRY, last logon <date>` - a normal profile with a usable timestamp
   - `IN REGISTRY, no logon time recorded (by-design skip)` - a real profile the cleanup script will skip unless the guarded opt-in is enabled
   - `ORPHAN - no registry entry (leftover husk, safe to remove)` - a folder with no `ProfileList` entry at all

6. **Summarises Folder Contents**
   - `(empty)` when the folder has no children
   - A comma-separated list when there are four items or fewer
   - An item count when there are more

7. **Writes the Report to the Console**
   - One fixed-width line per folder, readable directly in the NinjaOne script output
   - Always exits 0

---

## How the Script Performs This

### Why the Registry and Not `LastUseTime`

The obvious way to find an inactive profile is `Win32_UserProfile.LastUseTime`, and it does not work. On Windows 10 1809 and newer (including Windows 11), servicing operations and Defender scans touch profiles in the background, so `LastUseTime` reports "today" for essentially every profile on the machine. Filtering on it finds nothing.

The `ProfileList` values are written only when a profile is genuinely loaded at logon or unloaded at logoff, so they are not polluted by background activity. That is why both this script and the cleanup script read them instead.

### Reassembling the Split FILETIME

Windows stores these timestamps as a 64-bit FILETIME split across two DWORD registry values, `...High` and `...Low`. PowerShell reads registry DWORDs as **signed** `Int32`, so any value with the top bit set arrives negative and a naive shift produces a nonsense date.

The script casts through `UInt32` before widening to `UInt64`:

```powershell
$fileTime = ([uint64][uint32]$high -shl 32) -bor [uint64][uint32]$low
```

Both the load time and the unload time are reassembled, and the later of the two is reported - a profile that was logged on but never cleanly logged off still yields a usable date.

### Orphan Detection

A folder is classified as an orphan when no `ProfileList` entry has a `ProfileImagePath` equal to that folder's full path. In practice these are husks left behind when a previous deletion removed the registry entry but could not remove every file. Common causes:

| Husk | Cause |
|------|-------|
| `IntelGraphicsProfiles` | Held open by the Intel graphics service (`igfxCUIService`) |
| OneDrive / SharePoint sync folders | Cloud placeholder files held by the cloud files filter driver (`cldflt.sys`) |
| Long-path or ACL-blocked trees | Files the deleting account could not take ownership of |

These are invisible to `Win32_UserProfile`, so the cleanup script's main loop never sees them. Only the opt-in orphan sweep removes them - which is why this audit exists to find them first.

### Content Summary

The content summary is deliberately short. A husk typically holds one or two leftover directories, so listing them inline immediately tells you what blocked the previous deletion. A full profile shows an item count instead, because listing thirty folder names per profile would make the report unreadable in the NinjaOne output pane.

---

## How to Use with NinjaOne RMM

### Step 1: Upload the Script

1. Navigate to **Administration** > **Library** > **Automation**
2. Click **Add** > **New Script**
3. Configure:
   - **Name**: `Audit User Profiles`
   - **Language**: PowerShell
   - **OS**: Windows
   - **Architecture**: All
   - **Run As**: System
4. Paste the script content
5. Save the script

### Step 2: Run the Script

#### Manual Execution
1. Navigate to a device in NinjaOne
2. Click **Run Script** or use the Actions menu
3. Select `Audit User Profiles`
4. Run the script - no variables need to be set

#### Scheduled Execution
1. Create a scheduled task or policy
2. Add the script as an action
3. Configure the schedule (for example weekly, ahead of a monthly cleanup window)

### Step 3: Read the Results

1. Open the device's **Activities** tab and select the script run
2. Review the output, which looks like this:

```
Administrator             IN REGISTRY, last logon 2026-08-14  [31 items]
Default                   SYSTEM folder
IntelGraphicsProfiles     ORPHAN - no registry entry (leftover husk, safe to remove)  [(empty)]
jdoe                      IN REGISTRY, last logon 2025-11-02  [28 items]
mjansen                   IN REGISTRY, no logon time recorded (by-design skip)  [Desktop, Documents, OneDrive]
Public                    SYSTEM folder
```

3. Interpret it against your cleanup threshold:
   - Profiles with a **last logon older than the threshold** will be deleted by the cleanup script
   - Profiles with **no logon time** will be skipped unless `removeProfilesWithoutLogonTime` is enabled
   - **ORPHAN** entries will only be removed if `removeOrphanProfileFolders` is enabled

### Step 4: Act on the Findings

Run the [cleanup script](../clean-user-profiles-windows/README.md) with the checkboxes that match what the audit found. Re-run this audit afterwards to confirm the result and to catch any husk that survived.

### Script Variable Reference

This script takes no variables.

### Exit Codes

| Code | Meaning |
|------|---------|
| 0 | Success - audit completed and the report was written to the console |

The script always exits 0. It reports state rather than judging it, so there is no failure condition to alert on. Alerting belongs on the cleanup script, which exits 2 when profiles could not be fully removed.

---

## Troubleshooting

### Common Issues

**Every folder shows as ORPHAN**
- The script could not read `ProfileList`. Confirm it is running as System or an administrator, not as the logged-in user.

**A folder you expect to see is missing**
- Only directories under `C:\Users` are enumerated. Profiles relocated elsewhere via a `ProfileImagePath` outside `C:\Users` will not appear.

**"no logon time recorded" on a profile that is clearly in use**
- This means the profile has not been loaded since the current OS install or feature upgrade. A feature upgrade resets these values, so shortly after one every profile can legitimately report no logon time. Wait for users to log on again before running a cleanup.

**A profile shows a last logon far older than the user remembers**
- Check whether the account signs in with a different profile path (for example a temporary `.DOMAIN` or `.000` suffixed folder created after a profile load failure). Both folders will be listed separately.

**Output is truncated in NinjaOne**
- NinjaOne caps script output length. On machines with a very large number of profiles, run the script directly on the device or reduce the number of profiles before auditing.

---

## Version History

| Version | Date | Changes |
|---------|------|---------|
| 1.0 | 2026-08-19 | Initial release. Read-only audit of `C:\Users` against the `ProfileList` registry, reporting real last logon from `LocalProfileLoadTime` / `LocalProfileUnloadTime`, classifying system folders, registered profiles, no-logon-time profiles and orphaned husks, with a short content summary per folder. Written as the companion to v4 of the cleanup script. |
