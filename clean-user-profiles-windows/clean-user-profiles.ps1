# ------------------------------------------------------------
# Script: Cleanup Inactive Local User Accounts (v4)
# Purpose: Deletes user profiles that haven't logged in for X days
# Excludes: Administrator, Systeembeheerder (local), DOMAIN\Administrator,
#           and the last logged in user (automatically detected)
# Compatibility: Works with both domain and Entra ID-joined systems
#
# v2 changes:
#   - Inactivity determined from ProfileList registry values
#     (LocalProfileLoadTime / LocalProfileUnloadTime) instead of the
#     unreliable Win32_UserProfile.LastUseTime.
#   - Profiles without a recorded logon time are skipped (safe default).
#   - Fixed the DOMAIN\Administrator exclusion (double backslash bug).
#
# v3 changes:
#   - Primary deletion now uses the Windows-native profile removal
#     (Remove-CimInstance on Win32_UserProfile). Windows handles the
#     folder, junctions, long paths AND the registry entry itself.
#   - Manual deletion is only a fallback, and it now:
#       * deletes junctions/symlinks (the link only, never the target)
#         instead of skipping them, so profiles can actually empty out
#       * never recurses INTO a reparse point while walking the tree
#       * attempts long paths via the \\?\ prefix instead of skipping
#       * caps repeated skip messages so NinjaOne output isn't truncated
#
# v4 changes (all opt-in via NinjaRMM checkboxes, default off):
#   - removeProfilesWithoutLogonTime: also delete profiles that have no
#     LocalProfileLoadTime/UnloadTime in ProfileList. Guarded: only when
#     the OS install is older than the threshold (logon times are written
#     at every logon on the current install, so their absence proves
#     inactivity since at least the install/feature upgrade) AND the
#     profile folder shows no write activity newer than the threshold.
#   - removeOrphanProfileFolders: sweep folders under C:\Users that have
#     no ProfileList entry at all (husks left when a locked file blocked
#     full deletion, e.g. IntelGraphicsProfiles held open by the Intel
#     graphics service, or OneDrive placeholder folders).
#   - excludedAccountsExtra: comma-separated extra exclusions from
#     NinjaRMM, so device-specific accounts can be protected per policy.
#
# v4.1 changes:
#   - Folder-activity guard now looks at top-level FOLDERS only. The
#     profile root contains NTUSER.DAT and its logs, which servicing and
#     Defender touch daily - the same false "recent activity" problem as
#     LastUseTime, which blocked every no-logon-time profile.
#   - Manual walker only treats real Junctions/SymbolicLinks as links.
#     Other reparse points (OneDrive/SharePoint cloud placeholders, app
#     execution aliases) are real content and are deleted normally, so
#     synced-library folders no longer block husk removal.
#
# v4.2 changes:
#   - Manual deletion now resets ownership and ACLs first (takeown +
#     icacls). Files synced from SharePoint/OneDrive can carry ACLs the
#     deleting account cannot override, which blocked husk removal with
#     permission errors. takeown runs with /d y AND /d j (the prompt
#     answer is localized on Dutch Windows); icacls grants via the SID
#     *S-1-5-32-544 (BUILTIN\Administrators) for the same reason.
#
# v4.3 changes:
#   - Per-item escalation on permission errors: recursive takeown/icacls
#     stop at reparse boundaries, so files inside cloud-placeholder
#     folders never got their ACLs reset. A file that fails with a
#     permission error is now retried once after clearing attributes and
#     resetting ownership/ACL on that specific file. If deletion is still
#     denied after that, the blocker is the cloud files filter driver
#     (cldflt.sys) holding the dead sync session's placeholders: only a
#     reboot clears that state, then rerun.
# ------------------------------------------------------------

# Import variables from NinjaRMM
$cleanupTargetDate = $env:cleanupTargetDate
$removeProfilesWithoutLogonTime = $env:removeProfilesWithoutLogonTime -match '^(1|true|yes|on)$'
$removeOrphanProfileFolders = $env:removeOrphanProfileFolders -match '^(1|true|yes|on)$'

# Configuration
$TimeoutMinutes = 10
$MaxDetailLines = 5   # max log lines per skip category, per profile

# Validate variables
$global:blnAllParametersProvided = $true

function checkVariable ([string]$inputVariableName, $inputVariable){
    Write-Host "Checking Variable $inputVariableName" -ForegroundColor Cyan
    if ([string]::IsNullOrEmpty($inputVariable)){
        Write-Host "A $inputVariableName has not been provided, the script will not continue." -ForegroundColor Red
        $global:blnAllParametersProvided = $false
    } else {
        Write-Host "Validation of variable: $inputVariableName has succeeded, proceeding with execution." -ForegroundColor Green
    }
}

checkVariable -inputVariableName "cleanupTargetDate" -inputVariable $cleanupTargetDate

if (-not $global:blnAllParametersProvided){
    Write-Host "Missing required variables. Exiting script." -ForegroundColor Red
    exit 1
}

# Validate that cleanupTargetDate is a positive integer
$cleanupDays = 0
if (-not [int]::TryParse($cleanupTargetDate, [ref]$cleanupDays) -or $cleanupDays -le 0) {
    Write-Host "cleanupTargetDate must be a positive integer. Got: '$cleanupTargetDate'" -ForegroundColor Red
    exit 1
}

# Define the inactivity threshold (in days)
$thresholdDate = (Get-Date).AddDays(-$cleanupDays)

# List of user accounts to exclude from deletion
$excludedAccounts = @(
    "Administrator",                 # Local Administrator
    "Systeembeheerder",              # Local Systeembeheerder
    "DOMAIN\Administrator"           # Domain Administrator (replace DOMAIN with actual domain name)
)

# Optional extra exclusions from NinjaRMM (comma-separated account or user names)
if (-not [string]::IsNullOrWhiteSpace($env:excludedAccountsExtra)) {
    $excludedAccounts += @($env:excludedAccountsExtra -split ',' | ForEach-Object { $_.Trim() } | Where-Object { $_ })
}

# ============================================================================
# HELPER FUNCTIONS
# ============================================================================

function Get-ProfileRealLastUse {
    <#
    .SYNOPSIS
        Returns the real last logon/logoff time for a profile SID.
    .DESCRIPTION
        Reads LocalProfileLoadTimeHigh/Low and LocalProfileUnloadTimeHigh/Low
        from the ProfileList registry key. These split FILETIME values are only
        written when a profile is actually loaded (logon) or unloaded (logoff),
        so they are not polluted by Windows updates or Defender scans the way
        Win32_UserProfile.LastUseTime is. Returns the most recent of the two.
    .OUTPUTS
        [datetime] of the last real logon/logoff, or $null if no times are
        recorded for this SID.
    #>
    param([Parameter(Mandatory = $true)][string]$Sid)

    try {
        $key = Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList\$Sid" -ErrorAction Stop
    }
    catch {
        return $null
    }

    $times = @()
    foreach ($pair in @('LocalProfileLoadTime', 'LocalProfileUnloadTime')) {
        $high = $key."${pair}High"
        $low  = $key."${pair}Low"
        if ($null -ne $high -and $null -ne $low) {
            # Registry DWORDs arrive as signed Int32; go through UInt32 to avoid sign issues
            $fileTime = ([uint64][uint32]$high -shl 32) -bor [uint64][uint32]$low
            if ($fileTime -gt 0) {
                try {
                    $times += [datetime]::FromFileTime([int64]$fileTime)
                }
                catch {
                    # Ignore malformed FILETIME values
                }
            }
        }
    }

    if ($times.Count -eq 0) { return $null }
    return ($times | Sort-Object -Descending | Select-Object -First 1)
}

function Get-ProfileFolderLastActivity {
    <#
    .SYNOPSIS
        Newest write time of a profile folder and its top-level items.
    .DESCRIPTION
        Secondary inactivity signal for profiles that have no logon times
        recorded in ProfileList. Reparse points are ignored. Returns $null
        when the folder is missing or unreadable.
    #>
    param([Parameter(Mandatory = $true)][string]$Path)

    try {
        $times = @((Get-Item -LiteralPath $Path -Force -ErrorAction Stop).LastWriteTime)
    }
    catch {
        return $null
    }

    # Top-level FOLDERS only: files at the profile root (NTUSER.DAT and its
    # logs) are rewritten by servicing/Defender and would always look recent.
    $children = Get-ChildItem -LiteralPath $Path -Force -ErrorAction SilentlyContinue |
        Where-Object {
            $_.PSIsContainer -and
            (($_.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -eq 0)
        }
    foreach ($child in $children) { $times += $child.LastWriteTime }

    return ($times | Sort-Object -Descending | Select-Object -First 1)
}

function Get-LastLoggedInUser {
    <#
    .SYNOPSIS
        Retrieves the user account that was most recently logged in.
    .DESCRIPTION
        Queries all non-special user profiles and returns the account name
        of the user with the most recent real logon/logoff time (from the
        ProfileList registry, not the unreliable LastUseTime).
    .OUTPUTS
        Returns a hashtable with AccountName, Username, ProfilePath, and LastUseTime.
        Returns $null if no valid user profile is found.
    #>

    try {
        $allProfiles = Get-CimInstance -ClassName Win32_UserProfile | Where-Object {
            -not $_.Special -and
            $_.LocalPath -like "C:\Users\*"
        }

        if (-not $allProfiles -or ($allProfiles | Measure-Object).Count -eq 0) {
            Write-Host "No user profiles found to determine last logged in user." -ForegroundColor Yellow
            return $null
        }

        # Find the profile with the most recent real logon/logoff time
        $lastLoggedIn = $allProfiles |
            ForEach-Object {
                $realLastUse = Get-ProfileRealLastUse -Sid $_.SID
                if ($realLastUse) {
                    [pscustomobject]@{ Profile = $_; LastUse = $realLastUse }
                }
            } |
            Sort-Object -Property LastUse -Descending |
            Select-Object -First 1

        if (-not $lastLoggedIn) {
            return $null
        }

        # Resolve SID to account name
        try {
            $user = New-Object System.Security.Principal.SecurityIdentifier($lastLoggedIn.Profile.SID)
            $accountName = $user.Translate([System.Security.Principal.NTAccount]).Value
            $username = $accountName.Split('\')[-1]
        }
        catch {
            Write-Host "Unable to resolve SID for last logged in user: $($lastLoggedIn.Profile.SID)" -ForegroundColor Yellow
            return $null
        }

        return @{
            AccountName = $accountName
            Username    = $username
            ProfilePath = $lastLoggedIn.Profile.LocalPath
            LastUseTime = $lastLoggedIn.LastUse
        }
    }
    catch {
        Write-Host "Error determining last logged in user: $($_.Exception.Message)" -ForegroundColor Yellow
        return $null
    }
}

function Remove-FolderSafely {
    <#
    .SYNOPSIS
        Fallback manual profile folder removal with safeguards against hanging.
    .DESCRIPTION
        Walks the tree itself (never following reparse points), deletes
        junctions/symlinks as links (their targets are never touched),
        retries long paths via the \\?\ prefix, and skips locked files
        and permission errors. Has a configurable timeout. Repeated skip
        messages are capped per category to keep NinjaOne output readable.
    #>
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path,

        [int]$TimeoutMinutes = 10,

        [int]$MaxDetailLines = 5
    )

    $stats = @{
        FilesDeleted           = 0
        FoldersDeleted         = 0
        LinksDeleted           = 0
        FilesSkippedLocked     = 0
        FilesSkippedLongPath   = 0
        FilesSkippedPermission = 0
        Errors                 = 0
        TimedOut               = $false
    }

    $deadline = (Get-Date).AddMinutes($TimeoutMinutes)
    $detailCounts = @{}

    # Capped detail logging: at most $MaxDetailLines lines per category
    function Write-SkipDetail {
        param([string]$Category, [string]$Message)
        if (-not $detailCounts.ContainsKey($Category)) { $detailCounts[$Category] = 0 }
        $detailCounts[$Category]++
        if ($detailCounts[$Category] -le $MaxDetailLines) {
            Write-Host "    $Message" -ForegroundColor Yellow
        }
        elseif ($detailCounts[$Category] -eq ($MaxDetailLines + 1)) {
            Write-Host "    (further '$Category' messages suppressed)" -ForegroundColor DarkYellow
        }
    }

    # Returns a literal path usable for deletion; long paths get the \\?\ prefix
    function Get-DeletablePath {
        param([string]$ItemPath)
        if ($ItemPath.Length -ge 260 -and -not $ItemPath.StartsWith('\\?\')) {
            return "\\?\$ItemPath"
        }
        return $ItemPath
    }

    function Remove-TreeNode {
        param([string]$NodePath)

        if ($stats.TimedOut) { return }
        if ((Get-Date) -gt $deadline) {
            Write-Host "  TIMEOUT reached after $TimeoutMinutes minutes. Stopping deletion." -ForegroundColor Red
            $stats.TimedOut = $true
            return
        }

        $literal = Get-DeletablePath -ItemPath $NodePath

        $item = $null
        try {
            $item = Get-Item -LiteralPath $literal -Force -ErrorAction Stop
        }
        catch {
            if ($NodePath.Length -ge 260) {
                Write-SkipDetail -Category 'longpath' -Message "Cannot access long path: $($NodePath.Substring(0, 80))..."
                $stats.FilesSkippedLongPath++
            }
            else {
                $stats.Errors++
            }
            return
        }

        # True junctions/symlinks: delete the LINK itself; the target is
        # never touched. Other reparse types (OneDrive/SharePoint cloud
        # placeholders, app execution aliases) report LinkType $null and
        # are real content - they fall through to normal file/folder
        # handling below and get deleted like anything else.
        if ((($item.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0) -and
            ($item.LinkType -in @('Junction', 'SymbolicLink'))) {
            try {
                if ($item.PSIsContainer) {
                    # Non-recursive delete removes only the junction/symlink
                    [System.IO.Directory]::Delete($item.FullName)
                }
                else {
                    Remove-Item -LiteralPath $literal -Force -ErrorAction Stop
                }
                $stats.LinksDeleted++
            }
            catch {
                Write-SkipDetail -Category 'link' -Message "Could not remove junction/symlink: $NodePath"
                $stats.Errors++
            }
            return
        }

        if ($item.PSIsContainer) {
            # Regular folder: delete children first (never following links), then the folder
            $children = @(Get-ChildItem -LiteralPath $literal -Force -ErrorAction SilentlyContinue)
            foreach ($child in $children) {
                if ($stats.TimedOut) { return }
                Remove-TreeNode -NodePath $child.FullName
            }

            $remaining = @(Get-ChildItem -LiteralPath $literal -Force -ErrorAction SilentlyContinue)
            if ($remaining.Count -eq 0) {
                try {
                    Remove-Item -LiteralPath $literal -Force -ErrorAction Stop
                    $stats.FoldersDeleted++
                }
                catch [System.UnauthorizedAccessException] {
                    Write-SkipDetail -Category 'permission' -Message "No permission on folder: $($item.Name)"
                    $stats.FilesSkippedPermission++
                }
                catch {
                    $stats.Errors++
                }
            }
            return
        }

        # Regular file
        try {
            Remove-Item -LiteralPath $literal -Force -ErrorAction Stop
            $stats.FilesDeleted++
        }
        catch [System.UnauthorizedAccessException] {
            # Targeted retry: recursive takeown/icacls stop at reparse
            # boundaries (cloud-placeholder folders), so reset attributes,
            # ownership and ACL of this single item and try once more.
            $deleted = $false
            try {
                [System.IO.File]::SetAttributes($literal, [System.IO.FileAttributes]::Normal)
            }
            catch {
                # Attribute reset may itself be denied; the retry below decides
            }
            $null = cmd /c "takeown /f `"$($item.FullName)`" /a" 2>&1
            $null = cmd /c "icacls `"$($item.FullName)`" /grant *S-1-5-32-544:F /q" 2>&1
            try {
                Remove-Item -LiteralPath $literal -Force -ErrorAction Stop
                $stats.FilesDeleted++
                $deleted = $true
            }
            catch {
                # Still denied: filter-driver state, needs a reboot
            }
            if (-not $deleted) {
                Write-SkipDetail -Category 'permission' -Message "No permission: $($item.Name)"
                $stats.FilesSkippedPermission++
            }
        }
        catch [System.IO.PathTooLongException] {
            Write-SkipDetail -Category 'longpath' -Message "Path too long: $($item.Name)"
            $stats.FilesSkippedLongPath++
        }
        catch [System.IO.IOException] {
            # File in use by another process
            Write-SkipDetail -Category 'locked' -Message "Locked file: $($item.Name)"
            $stats.FilesSkippedLocked++
        }
        catch {
            $stats.Errors++
        }
    }

    Write-Host "  Starting manual safe deletion of: $Path" -ForegroundColor Gray
    Write-Host "  Timeout set to: $TimeoutMinutes minutes" -ForegroundColor Gray

    # Reset ownership and ACLs first: files synced from SharePoint/OneDrive
    # often carry ACLs that block deletion even for SYSTEM. This only ever
    # runs on folders already condemned (native delete failed or orphaned).
    # takeown's /d prompt answer is localized, so run with y AND j (Dutch);
    # icacls grants via SID to avoid localized group names.
    Write-Host "  Resetting ownership and ACLs..." -ForegroundColor Gray
    $null = cmd /c "takeown /f `"$Path`" /r /a /d y" 2>&1
    $null = cmd /c "takeown /f `"$Path`" /r /a /d j" 2>&1
    $null = cmd /c "icacls `"$Path`" /grant *S-1-5-32-544:(OI)(CI)F /t /c /q" 2>&1

    Remove-TreeNode -NodePath $Path

    if (Test-Path -LiteralPath $Path) {
        Write-Host "  Folder could not be fully removed: $Path" -ForegroundColor Yellow
    }
    else {
        Write-Host "  Successfully removed folder: $Path" -ForegroundColor Green
    }

    return $stats
}

function Remove-ProfileRegistry {
    param(
        [Parameter(Mandatory = $true)]
        [string]$ProfilePath
    )

    try {
        $regPath = Get-ChildItem -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList" -ErrorAction Stop |
                   Get-ItemProperty |
                   Where-Object { $_.ProfileImagePath -eq $ProfilePath } |
                   Select-Object -ExpandProperty PSPath

        if ($regPath) {
            $regPath = $regPath.Replace('Microsoft.PowerShell.Core\Registry::HKEY_LOCAL_MACHINE', 'HKLM:')
            Write-Host "  Removing registry key: $regPath" -ForegroundColor Gray
            Remove-Item -Path $regPath -Recurse -Force -ErrorAction Stop
            Write-Host "  Registry key removed successfully" -ForegroundColor Green
            return $true
        }
        else {
            Write-Host "  Registry key not found (may already be removed)" -ForegroundColor Yellow
            return $true
        }
    }
    catch {
        Write-Host "  Failed to remove registry key: $($_.Exception.Message)" -ForegroundColor Red
        return $false
    }
}

# ============================================================================
# MAIN SCRIPT
# ============================================================================

Write-Host ""
Write-Host "=============================================" -ForegroundColor Cyan
Write-Host "  User Profile Cleanup Script (v4)" -ForegroundColor Cyan
Write-Host "=============================================" -ForegroundColor Cyan
Write-Host "Computer:       $env:COMPUTERNAME"
Write-Host "Threshold:      $cleanupDays days"
Write-Host "Cutoff Date:    $($thresholdDate.ToString('yyyy-MM-dd HH:mm:ss'))"
Write-Host "Timeout:        $TimeoutMinutes minutes per profile"
Write-Host "No-logon-time profiles:  $(if ($removeProfilesWithoutLogonTime) { 'REMOVE (guarded)' } else { 'skip' })"
Write-Host "Orphaned folder sweep:   $(if ($removeOrphanProfileFolders) { 'ON' } else { 'off' })"
Write-Host "=============================================" -ForegroundColor Cyan
Write-Host ""

# Get the last logged in user and add to exclusions (safety measure)
Write-Host "Determining last logged in user..." -ForegroundColor Cyan
$lastLoggedInUser = Get-LastLoggedInUser

if ($lastLoggedInUser) {
    Write-Host "Last logged in user: $($lastLoggedInUser.AccountName)" -ForegroundColor Green
    Write-Host "  Profile Path: $($lastLoggedInUser.ProfilePath)"
    Write-Host "  Last Login:   $($lastLoggedInUser.LastUseTime.ToString('yyyy-MM-dd HH:mm:ss'))"
    Write-Host "  Status:       Protected from deletion" -ForegroundColor Green

    # Add both the full account name and username to exclusions
    if ($excludedAccounts -notcontains $lastLoggedInUser.AccountName) {
        $excludedAccounts += $lastLoggedInUser.AccountName
    }
    if ($excludedAccounts -notcontains $lastLoggedInUser.Username) {
        $excludedAccounts += $lastLoggedInUser.Username
    }
}
else {
    Write-Host "Could not determine last logged in user. Proceeding with caution." -ForegroundColor Yellow
}
Write-Host ""

# Retrieve all user profiles from the system
Write-Host "Retrieving user profiles..." -ForegroundColor Cyan
$profiles = Get-CimInstance -ClassName Win32_UserProfile | Where-Object {
    -not $_.Special -and             # Exclude special system profiles
    $_.LocalPath -like "C:\Users\*"
}

$totalProfiles = ($profiles | Measure-Object).Count
Write-Host "Found $totalProfiles user profile(s) to evaluate" -ForegroundColor Cyan
Write-Host ""

# OS install date (reset by feature upgrades) gates the no-logon-time handling
$osInstallDate = $null
try {
    $osInstallDate = (Get-CimInstance -ClassName Win32_OperatingSystem -ErrorAction Stop).InstallDate
}
catch {
    Write-Host "Could not determine OS install date; no-logon-time profiles will be skipped." -ForegroundColor Yellow
}

$deletedCount = 0
$skippedCount = 0
$errorCount = 0
$orphansRemoved = 0

foreach ($userProfile in $profiles) {
    $sid = $userProfile.SID
    $profilePath = $userProfile.LocalPath

    # Resolve SID to account name
    try {
        $user = New-Object System.Security.Principal.SecurityIdentifier($sid)
        $account = $user.Translate([System.Security.Principal.NTAccount]).Value
    }
    catch {
        Write-Host "Unable to resolve SID: $sid. Skipping profile at $profilePath" -ForegroundColor DarkYellow
        $skippedCount++
        continue
    }

    # Extract just the username part (for comparison with local exclusions)
    $username = $account.Split('\')[-1]

    # Check if account is in the excluded list
    if ($excludedAccounts -contains $account -or $excludedAccounts -contains $username) {
        Write-Host "Skipping excluded account: $account" -ForegroundColor Cyan
        $skippedCount++
        continue
    }

    # Never touch a profile that is currently loaded
    if ($userProfile.Loaded) {
        Write-Host "Skipping currently loaded profile: $account" -ForegroundColor Cyan
        $skippedCount++
        continue
    }

    # Determine the real last logon/logoff time from the ProfileList registry
    $lastUsed = Get-ProfileRealLastUse -Sid $sid
    $lastUsedSource = 'registry'

    if (-not $lastUsed) {
        # No logon recorded on this OS install. Deleting these is opt-in and
        # only allowed when the OS install itself is older than the threshold
        # AND the profile folder shows no recent write activity.
        if (-not $removeProfilesWithoutLogonTime) {
            Write-Host "No registry logon time recorded for $account. Skipping (safe default)." -ForegroundColor DarkYellow
            $skippedCount++
            continue
        }
        if (-not $osInstallDate -or $osInstallDate -ge $thresholdDate) {
            Write-Host "No registry logon time for $account and OS install is newer than the threshold. Skipping." -ForegroundColor DarkYellow
            $skippedCount++
            continue
        }

        $folderActivity = Get-ProfileFolderLastActivity -Path $profilePath
        if (-not $folderActivity) {
            Write-Host "No registry logon time and no readable folder for $account. Skipping." -ForegroundColor DarkYellow
            $skippedCount++
            continue
        }
        if ($folderActivity -ge $thresholdDate) {
            Write-Host "$account - No registry logon time but recent folder activity ($($folderActivity.ToString('yyyy-MM-dd'))). Skipping." -ForegroundColor DarkYellow
            $skippedCount++
            continue
        }

        $lastUsed = $folderActivity
        $lastUsedSource = 'folder activity; no logon since OS install'
    }

    # Check if the account has been inactive for more than the threshold
    if ($lastUsed -lt $thresholdDate) {
        Write-Host ""
        Write-Host "Processing inactive profile: $account" -ForegroundColor White
        Write-Host "  Profile Path: $profilePath"
        Write-Host "  Last Used:    $($lastUsed.ToString('yyyy-MM-dd HH:mm:ss')) ($lastUsedSource)"
        Write-Host "  Inactive for: $([math]::Round(((Get-Date) - $lastUsed).TotalDays, 0)) days"

        # Check if folder exists
        if (-not (Test-Path -Path $profilePath)) {
            Write-Host "  Profile folder does not exist, cleaning up registry only" -ForegroundColor Yellow
            Remove-ProfileRegistry -ProfilePath $profilePath
            $deletedCount++
            continue
        }

        # ------------------------------------------------------------
        # Attempt 1: Windows-native profile deletion.
        # This is the same routine as sysdm.cpl > User Profiles > Delete:
        # it removes the folder (junctions and long paths included) AND
        # the ProfileList registry entry in one operation.
        # ------------------------------------------------------------
        $nativeDeleteWorked = $false
        try {
            Write-Host "  Attempting Windows-native profile deletion..." -ForegroundColor Gray
            Remove-CimInstance -InputObject $userProfile -ErrorAction Stop
            if (-not (Test-Path -Path $profilePath)) {
                $nativeDeleteWorked = $true
            }
            else {
                Write-Host "  Native deletion reported success but folder remains. Falling back to manual cleanup..." -ForegroundColor Yellow
            }
        }
        catch {
            Write-Host "  Native deletion failed: $($_.Exception.Message)" -ForegroundColor Yellow
            Write-Host "  Falling back to manual cleanup..." -ForegroundColor Yellow
        }

        if ($nativeDeleteWorked) {
            Write-Host "  Profile completely removed (native): $account" -ForegroundColor Green
            $deletedCount++
            continue
        }

        # ------------------------------------------------------------
        # Attempt 2: manual safe deletion with timeout
        # ------------------------------------------------------------
        $stats = Remove-FolderSafely -Path $profilePath -TimeoutMinutes $TimeoutMinutes -MaxDetailLines $MaxDetailLines

        # Report stats
        Write-Host "  Deletion stats:" -ForegroundColor Gray
        Write-Host "    Files deleted:           $($stats.FilesDeleted)"
        Write-Host "    Folders deleted:         $($stats.FoldersDeleted)"
        Write-Host "    Links deleted:           $($stats.LinksDeleted)"
        Write-Host "    Skipped (locked):        $($stats.FilesSkippedLocked)"
        Write-Host "    Skipped (long path):     $($stats.FilesSkippedLongPath)"
        Write-Host "    Skipped (permission):    $($stats.FilesSkippedPermission)"
        Write-Host "    Errors:                  $($stats.Errors)"

        # Check if profile folder was fully removed
        if (-not (Test-Path -Path $profilePath)) {
            # Folder completely removed, clean up registry
            Remove-ProfileRegistry -ProfilePath $profilePath
            Write-Host "  Profile completely removed: $account" -ForegroundColor Green
            $deletedCount++
        }
        else {
            # Folder still exists (some files couldn't be deleted)
            $remainingSize = (Get-ChildItem -Path $profilePath -Recurse -Force -ErrorAction SilentlyContinue |
                              Measure-Object -Property Length -Sum -ErrorAction SilentlyContinue).Sum
            $remainingSizeMB = [math]::Round($remainingSize / 1MB, 2)

            Write-Host "  Profile partially cleaned ($remainingSizeMB MB remaining): $account" -ForegroundColor Yellow
            Write-Host "  Note: Registry entry preserved since folder still exists" -ForegroundColor Yellow
            $errorCount++
        }
    }
    else {
        Write-Host "$account - Active (Last used: $($lastUsed.ToString('yyyy-MM-dd')))" -ForegroundColor Gray
        $skippedCount++
    }
}

# ============================================================================
# ORPHANED FOLDER SWEEP (opt-in)
# Folders under C:\Users whose ProfileList entry is already gone: husks left
# behind when a locked file blocked full deletion (IntelGraphicsProfiles held
# open by the Intel graphics service, OneDrive placeholder folders, etc.).
# These are invisible to Win32_UserProfile, so the main loop never sees them.
# ============================================================================
if ($removeOrphanProfileFolders) {
    Write-Host ""
    Write-Host "Sweeping orphaned profile folders..." -ForegroundColor Cyan

    $systemFolders = @('Public', 'Default', 'Default User', 'All Users')
    $knownPaths = @(Get-ChildItem -Path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList' -ErrorAction SilentlyContinue |
        Get-ItemProperty |
        Select-Object -ExpandProperty ProfileImagePath)

    # Intel's graphics service holds open handles on IntelGraphicsProfiles folders
    $stoppedServices = @(Get-Service -Name 'igfxCUIService*' -ErrorAction SilentlyContinue |
        Where-Object { $_.Status -eq 'Running' })
    $stoppedServices | Stop-Service -Force -ErrorAction SilentlyContinue

    foreach ($dir in Get-ChildItem -Path 'C:\Users' -Directory -Force) {
        if ($systemFolders -contains $dir.Name) { continue }
        if ($knownPaths -contains $dir.FullName) { continue }   # real profile, leave it

        Write-Host "Removing orphaned folder: $($dir.FullName)" -ForegroundColor White
        $null = Remove-FolderSafely -Path $dir.FullName -TimeoutMinutes $TimeoutMinutes -MaxDetailLines $MaxDetailLines
        if (Test-Path -LiteralPath $dir.FullName) {
            Write-Host "  Orphan folder still present (locked handles; reboot and rerun): $($dir.Name)" -ForegroundColor Yellow
            $errorCount++
        }
        else {
            $orphansRemoved++
        }
    }

    $stoppedServices | Start-Service -ErrorAction SilentlyContinue
    Write-Host "Orphaned folders removed: $orphansRemoved" -ForegroundColor Green
}

# Summary
Write-Host ""
Write-Host "=============================================" -ForegroundColor Cyan
Write-Host "  Cleanup Summary" -ForegroundColor Cyan
Write-Host "=============================================" -ForegroundColor Cyan
Write-Host "Profiles fully deleted:    $deletedCount" -ForegroundColor Green
Write-Host "Profiles skipped:          $skippedCount" -ForegroundColor Cyan
if ($removeOrphanProfileFolders) {
    Write-Host "Orphan folders removed:    $orphansRemoved" -ForegroundColor Green
}
Write-Host "Profiles with errors:      $errorCount" -ForegroundColor $(if ($errorCount -gt 0) { "Yellow" } else { "Green" })
Write-Host "=============================================" -ForegroundColor Cyan

if ($errorCount -gt 0) {
    Write-Host ""
    Write-Host "Some profiles could not be fully removed due to locked files or permission issues." -ForegroundColor Yellow
    Write-Host "Consider rebooting the machine and running the script again." -ForegroundColor Yellow
    exit 2
}

exit 0
