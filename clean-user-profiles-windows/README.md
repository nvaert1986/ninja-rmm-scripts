# NinjaOne RMM User Profile Cleanup Script Documentation

> **Note:** Parts of this script and documentation were written with the assistance of AI (Claude by Anthropic) to speed up the process of writing documentation, implementing logic, and generating output.

> **Disclaimer:** Running this script is at your own risk. **This script permanently deletes user profiles, their folders and their registry entries. Deleted profiles cannot be recovered.** It has been tested on Windows 10 and Windows 11 workstations in both domain-joined and Entra ID-joined configurations. Always run the [audit script](../audit-user-profiles-windows/README.md) first and confirm the results before enabling any of the opt-in options.

## Overview

I created this PowerShell script to remove local user profiles that have been inactive for a configurable number of days, so workstations with a long history of users do not slowly fill their system disk with abandoned profiles.

The core problem the script solves is that the obvious source of "when was this profile last used" - `Win32_UserProfile.LastUseTime` - is unusable on modern Windows. This script determines inactivity from the `ProfileList` registry logon and logoff timestamps instead, deletes profiles through the Windows-native removal path, and falls back to a hardened manual deleter when that is blocked.

Everything destructive beyond the basic inactivity rule is **opt-in and off by default**.

---

## Requirements

### Platform Requirements

- **Operating System**: Windows 10, Windows 11, Server 2016 and newer
- **PowerShell Version**: Windows PowerShell 5.1 (no PowerShell 7 features are used)
- **Privileges**: SYSTEM or Administrator. Profile deletion touches other users' folders, the `ProfileList` registry hive, and services.
- **Join Type**: Works on workgroup, Active Directory domain-joined and Entra ID-joined systems

### NinjaOne Requirements

- NinjaOne RMM agent installed on the target system
- Script variable `cleanupTargetDate` configured and set (**required**)
- Script variables `removeProfilesWithoutLogonTime`, `removeOrphanProfileFolders` and `excludedAccountsExtra` configured (**optional**)
- No custom field required - the script writes progress and a summary to the console, not to a WYSIWYG field

> **Note: Run the audit first**
>
> The companion [Audit User Profiles](../audit-user-profiles-windows/README.md) script is read-only and reports exactly what this script will see: which profiles have a usable logon time, which have none, and which folders are orphaned husks. Run it before every cleanup on a new device, and again afterwards to confirm the outcome.

> **Note: Runtime**
>
> Long runtimes are normal. Native profile deletion is sequential and produces no live output while it works, so a device with several large profiles can appear to hang for many minutes. The per-profile timeout only applies to the manual fallback deleter; the native delete has no timeout, which is a known and accepted limitation.

### External PowerShell Modules

None. The script uses only built-in cmdlets, plus the in-box `takeown.exe` and `icacls.exe` utilities for the permission fallback.

---

## What the Script Does

I designed this script to perform the following tasks:

1. **Validates the Environment**
   - Confirms `cleanupTargetDate` is set, and that it parses as a positive integer
   - Exits 1 immediately if either check fails, before touching anything

2. **Builds the Exclusion List**
   - Always excludes `Administrator`, `Systeembeheerder` and `DOMAIN\Administrator`
   - Appends any comma-separated names from `excludedAccountsExtra`
   - Detects the last logged-in user and adds them automatically as a safety measure

3. **Determines Real Inactivity Per Profile**
   - Reads `LocalProfileLoadTime` and `LocalProfileUnloadTime` from `ProfileList`
   - Uses the most recent of the two as the profile's real last use

4. **Decides What to Skip**
   - Excluded accounts
   - Currently loaded profiles
   - Profiles whose last use is newer than the threshold
   - Profiles with no recorded logon time (unless the guarded opt-in is enabled)

5. **Deletes Inactive Profiles**
   - Primary path: Windows-native `Remove-CimInstance` on the `Win32_UserProfile` object
   - Fallback path: manual tree deletion with ownership and ACL reset, junction-safe walking, long-path support and per-item permission escalation
   - Cleans up the `ProfileList` registry entry if it survives the folder deletion

6. **Optionally Removes No-Logon-Time Profiles** (opt-in, guarded)
   - Only when the OS install is older than the threshold **and** the profile folder shows no recent top-level folder activity

7. **Optionally Sweeps Orphaned Folders** (opt-in)
   - Removes folders under `C:\Users` that have no `ProfileList` entry at all
   - Temporarily stops the Intel graphics service, which holds handles on `IntelGraphicsProfiles` husks, and restarts it afterwards

8. **Reports a Summary**
   - Counts of profiles deleted, skipped, orphan folders removed, and profiles with errors
   - Exits 2 when anything could not be fully removed, so NinjaOne surfaces the run as Failed

---

## How the Script Performs This

### Why Not `Win32_UserProfile.LastUseTime`

On Windows 10 1809 and newer, `LastUseTime` is updated by servicing operations and Defender scans, not just by real logons. In practice it reports "today" for every profile on the machine, so any cleanup filtered on it deletes nothing.

The script reads the `ProfileList` registry values instead:

| Value | Written when |
|-------|--------------|
| `LocalProfileLoadTimeHigh` / `LocalProfileLoadTimeLow` | The profile is loaded at logon |
| `LocalProfileUnloadTimeHigh` / `LocalProfileUnloadTimeLow` | The profile is unloaded at logoff |

Each is a 64-bit FILETIME split across two DWORDs. PowerShell reads registry DWORDs as signed `Int32`, so the script casts through `UInt32` before widening, otherwise any value with the top bit set produces a nonsense date:

```powershell
$fileTime = ([uint64][uint32]$high -shl 32) -bor [uint64][uint32]$low
```

The later of the load and unload times is used, so a profile that logged on but never cleanly logged off still yields a usable date.

### Deletion Strategy

#### Primary: Windows-native removal

`Remove-CimInstance` on the `Win32_UserProfile` object is the preferred path because Windows handles the profile folder, its junctions, long paths **and** the registry entry in a single operation, using the same code path as the Advanced System Settings profile UI.

#### Fallback: manual deletion

Used only when the native call fails, or reports success while the folder is still present. The manual deleter is hardened against the specific failures seen in production:

| Hazard | Handling |
|--------|----------|
| Junctions and symlinks | Deleted as links only, never followed, so the target is never touched |
| Other reparse points | OneDrive/SharePoint cloud placeholders and app execution aliases are **real content** - they carry the ReparsePoint attribute but have a `$null` LinkType, and are recursed and deleted normally |
| Paths over `MAX_PATH` | Retried with the `\\?\` prefix instead of being skipped |
| SharePoint/OneDrive ACLs | `takeown` + `icacls` reset ownership on the tree before deletion |
| Localised `takeown` prompt | Run with both `/d y` and `/d j`, because the confirmation answer is localised on Dutch Windows |
| Group name resolution | `icacls` grants via the SID form `*S-1-5-32-544` rather than the localised `BUILTIN\Administrators` name |
| ACLs inside reparse points | Recursive `takeown /r` and `icacls /t` stop at reparse boundaries, so a file failing on permissions is retried once after per-item attribute clearing and ownership reset |
| Verbose output flooding | Repeated skip messages are capped at `$MaxDetailLines` per category per profile, because NinjaOne truncates long output |
| Runaway deletion | A `$TimeoutMinutes` (default 10) per-profile timeout stops the manual walker |

> **Note: When deletion still fails**
>
> If a file is still denied after per-item ownership and ACL reset, the blocker is the cloud files filter driver (`cldflt.sys`) holding placeholders from a dead OneDrive/SharePoint sync session. No amount of permission work clears that - only a reboot does. Reboot the device and run the script again.

### The No-Logon-Time Guard

A profile with no `LocalProfileLoadTime` at all has not been loaded since the current OS install or feature upgrade, because those values are written on every logon. That makes it *probably* inactive, but a feature upgrade resets them, so shortly after one every profile looks untouched.

When `removeProfilesWithoutLogonTime` is enabled, two guards must both pass before such a profile is deleted:

1. **OS install age** - the Windows install must itself be older than the threshold. If Windows was installed 20 days ago and the threshold is 90 days, no conclusion can be drawn and the profile is skipped.
2. **Folder activity** - the profile must show no write activity newer than the threshold.

The folder activity check deliberately looks at **top-level folders only**, never files at the profile root. `NTUSER.DAT` and its logs are rewritten daily by servicing and Defender - the same disease that makes `LastUseTime` useless - and including them caused every no-logon-time profile to look active.

### The Orphaned Folder Sweep

Orphans are folders under `C:\Users` with no `ProfileList` entry pointing at them: husks left when a previous deletion removed the registry entry but could not remove every file. Because `Win32_UserProfile` only reflects registered profiles, the main loop cannot see them at all.

When `removeOrphanProfileFolders` is enabled, the script enumerates `C:\Users`, skips the system folders (`Public`, `Default`, `Default User`, `All Users`) and every path that *is* referenced by `ProfileList`, and removes what remains using the same hardened deleter.

Before sweeping, it stops any running `igfxCUIService*` service, because the Intel graphics service holds open handles on `IntelGraphicsProfiles` husks and blocks their removal. The service is restarted when the sweep completes.

### Exclusion Safety

Beyond the configured exclusion list, the script independently determines the last logged-in user by querying non-special `Win32_UserProfile` objects, resolving each one's real last use from the registry, and taking the most recent. That account is added to the exclusions regardless of its inactivity, so a device that has been powered off for longer than the threshold cannot have its primary user's profile deleted.

---

## How to Use with NinjaOne RMM

### Step 1: Upload the Script

1. Navigate to **Administration** > **Library** > **Automation**
2. Click **Add** > **New Script**
3. Configure:
   - **Name**: `Cleanup Inactive Local User Accounts`
   - **Language**: PowerShell
   - **OS**: Windows
   - **Architecture**: All
   - **Run As**: System
4. Paste the script content
5. Save the script

### Step 2: Configure Script Variables

1. In the script editor, click **Script Variables**
2. Add the required variable:
   - **Variable Name**: `cleanupTargetDate`
   - **Variable Type**: Text (or Integer)
   - **Default Value**: `90`
   - **Required**: Yes
3. Add the optional variables:
   - **Variable Name**: `removeProfilesWithoutLogonTime` - **Type**: Checkbox - **Default**: unchecked
   - **Variable Name**: `removeOrphanProfileFolders` - **Type**: Checkbox - **Default**: unchecked
   - **Variable Name**: `excludedAccountsExtra` - **Type**: Text - **Default**: empty
4. Save the variables

### Step 3: Adjust the Built-in Exclusions

The `DOMAIN\Administrator` entry in `$excludedAccounts` is a placeholder. Either replace `DOMAIN` with the real NetBIOS domain name in the script, or leave it and supply the correct value per policy through `excludedAccountsExtra`.

### Step 4: Audit Before You Run

Run the [Audit User Profiles](../audit-user-profiles-windows/README.md) script against the target device first and confirm:

- which profiles fall outside the threshold and will be deleted
- whether any profiles report no logon time, and whether you want the guarded opt-in enabled
- whether any orphaned husks exist, and whether you want the sweep enabled

### Step 5: Run the Script

#### Manual Execution
1. Navigate to a device in NinjaOne
2. Click **Run Script** or use the Actions menu
3. Select `Cleanup Inactive Local User Accounts`
4. Set `cleanupTargetDate` and any opt-in checkboxes for this run
5. Run the script

#### Scheduled Execution
1. Create a scheduled task or policy
2. Add the script as an action
3. Configure the schedule (for example monthly, outside business hours)
4. Ensure `cleanupTargetDate` is set correctly for the policy

Start with a conservative threshold and both checkboxes off. Enable the opt-ins per device once the audit output justifies them.

### Step 6: Review the Results

Open the device's **Activities** tab and read the run output. The summary block at the end reports:

```
=============================================
  Cleanup Summary
=============================================
Profiles fully deleted:    3
Profiles skipped:          5
Orphan folders removed:    1
Profiles with errors:      0
=============================================
```

Re-run the audit script afterwards to confirm the state on disk.

### Script Variable Reference

| Variable | Type | Required | Description |
|----------|------|----------|-------------|
| `cleanupTargetDate` | Text / Integer | Yes | Inactivity threshold in **days**. Must be a positive integer. A profile is a deletion candidate when its real last logon is older than this. |
| `removeProfilesWithoutLogonTime` | Checkbox | No | Also delete profiles with no `ProfileList` logon time. Guarded by the OS install age **and** top-level folder activity. Default off. |
| `removeOrphanProfileFolders` | Checkbox | No | Sweep folders under `C:\Users` with no `ProfileList` entry (leftover husks). Default off. |
| `excludedAccountsExtra` | Text | No | Comma-separated extra account or user names to protect, on top of the built-in exclusions. |

Checkbox variables are accepted as `1`, `true`, `yes` or `on` (case-insensitive). Anything else counts as off.

### Exit Codes

| Code | Meaning |
|------|---------|
| 0 | Success - cleanup completed with no errors |
| 1 | Error - a required variable was missing, or `cleanupTargetDate` was not a positive integer. Nothing was deleted. |
| 2 | Partial - one or more profiles or orphan folders could not be fully removed |

Exit code 2 is intentional: NinjaOne shows the run as **Failed** so partial cleanups are visible rather than silently passing. It usually means locked files, and usually clears after a reboot and a re-run.

---

## Troubleshooting

### Common Issues

**"A cleanupTargetDate has not been provided, the script will not continue"**
- Add the `cleanupTargetDate` script variable in NinjaOne and confirm the name matches exactly.

**"cleanupTargetDate must be a positive integer"**
- The variable contains a non-numeric value, zero or a negative number. It is a day count, not a date.

**Nothing gets deleted even though profiles look old**
- Run the audit script. If profiles report "no logon time recorded", they are being skipped by design. Either wait for users to log on again, or enable `removeProfilesWithoutLogonTime`.
- If the OS was recently upgraded, the install-age guard will also block that opt-in until the install itself is older than the threshold.

**Exit code 2, "Some profiles could not be fully removed"**
- Locked files. Reboot the device and run the script again.
- If it persists on a folder containing OneDrive or SharePoint content, the cloud files filter driver is holding placeholders from a dead sync session. Only a reboot clears that state.

**Orphaned husk survives the sweep**
- Confirm `removeOrphanProfileFolders` is actually enabled for the run.
- `IntelGraphicsProfiles` husks need the Intel graphics service stopped, which the script does automatically - if the service failed to stop, reboot and re-run.

**The script appears to hang**
- Expected. Native profile deletion is sequential and produces no output while it runs. Large profiles take many minutes.

**A profile you wanted to keep was deleted**
- Add it to `excludedAccountsExtra`. Only the last logged-in user is protected automatically; other in-use accounts that have simply not signed in recently are legitimate candidates.

---

## Version History

| Version | Date | Changes |
|---------|------|---------|
| 4.3 | 2026-08-19 | **Per-item permission escalation**: recursive `takeown /r` and `icacls /t` stop at reparse boundaries, so files inside cloud-placeholder folders never had their ACLs reset. A file failing with a permission error is now retried once after clearing attributes and resetting ownership and ACL on that specific file. If deletion is still denied, the blocker is `cldflt.sys` holding a dead sync session's placeholders and only a reboot clears it. |
| 4.2 | 2026-08-19 | **Ownership and ACL reset**: manual deletion now runs `takeown` + `icacls` before deleting, because SharePoint/OneDrive-synced files can carry ACLs the deleting account cannot override. `takeown` runs with both `/d y` and `/d j` as the prompt answer is localised on Dutch Windows, and `icacls` grants via the SID `*S-1-5-32-544` rather than the localised group name. |
| 4.1 | 2026-08-19 | **Folder-activity guard fix**: the guard now examines top-level folders only. `NTUSER.DAT` and its logs at the profile root are rewritten daily by servicing and Defender, which made every no-logon-time profile look active. **Reparse point fix**: only real Junctions and SymbolicLinks are treated as links; OneDrive/SharePoint cloud placeholders and app execution aliases have a `$null` LinkType and are deleted as normal content, so synced folders no longer block husk removal. |
| 4.0 | 2026-08-19 | **Opt-in options, all default off**: `removeProfilesWithoutLogonTime` (guarded by OS install age and folder activity), `removeOrphanProfileFolders` (sweeps `C:\Users` folders with no `ProfileList` entry, stopping the Intel graphics service first), and `excludedAccountsExtra` (comma-separated per-policy exclusions). |
| 3.0 | Earlier | **Native deletion**: primary path switched to `Remove-CimInstance` on `Win32_UserProfile`, letting Windows handle folder, junctions, long paths and registry in one call. Manual deletion demoted to fallback and hardened: junctions/symlinks deleted as links rather than skipped, never recursing into a reparse point, `\\?\` prefix for long paths, and capped skip messages so NinjaOne output is not truncated. |
| 2.0 | Earlier | **Registry-based inactivity**: switched from the unreliable `Win32_UserProfile.LastUseTime` to `LocalProfileLoadTime` / `LocalProfileUnloadTime` in `ProfileList`. Profiles without a recorded logon time are skipped as a safe default. Fixed the `DOMAIN\Administrator` exclusion (double backslash bug). |
| 1.0 | Initial | Initial release - delete local profiles inactive for X days, with a fixed exclusion list and automatic protection of the last logged-in user. |
