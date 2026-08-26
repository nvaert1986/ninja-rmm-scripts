# NinjaOne RMM Script - Hyper-V Checkpoint (AVHDX) Audit
#
# Enumerates every virtual machine on this Hyper-V host, walks each attached
# virtual disk's differencing chain, and counts the AVHDX (checkpoint) files in
# that chain. Warns when any single virtual disk carries more AVHDX files than
# the configured maximum.
#
# WHY: orphaned backup checkpoints accumulate silently when the post-backup
# merge fails (e.g. a block-size mismatch between the base VHDX and the
# checkpoint AVHDX). Chains hundreds of links deep cripple disk performance,
# consume enormous space, and can leave a VM unbootable if merged carelessly.
#
# This script is READ-ONLY with respect to virtual machines and virtual disks.
# It never creates, merges, deletes or repoints anything.
#
# ---------------------------------------------------------------------------
# NinjaOne script variables (passed to the script as environment variables,
# always lower-case, always string-typed even when declared as Integer):
#
#   avhdxthreshold      (Integer, REQUIRED) Maximum AVHDX files tolerated per
#                       virtual disk before warning. Typical value: 3.
#   wysiwygcustomfield  (String, OPTIONAL)  Name of a WYSIWYG custom field to
#                       write an HTML report into. Omit to report to console
#                       only.
#
# Exit / result codes:
#   0  OK - no disk exceeds the threshold, or this device is not a Hyper-V host
#   1  Script or configuration error (missing/invalid threshold, module broken)
#   4  WARNING - one or more virtual disks exceed the configured maximum
# ---------------------------------------------------------------------------

# Deliberately no Set-StrictMode. Strict mode turns any unexpected object shape
# into a hard crash, and an unattended monitor should degrade to a partial
# report instead of dying. ErrorActionPreference is Stop so that the try/catch
# blocks below reliably catch cmdlet errors that are otherwise non-terminating.
$ErrorActionPreference = 'Stop'

# Hard ceiling on chain traversal. Guards against a corrupt or self-referencing
# parent locator turning the walk into an endless loop.
$script:MaxChainDepth = 1000

# Cache of Get-VHD results keyed on lower-case path. VM farms built from a
# shared parent disk resolve the same ancestors repeatedly; caching removes
# that duplicated work.
$script:VhdCache = @{}

#region Helper functions -----------------------------------------------------

function Test-HyperVHost {
    <#
        Returns $true only when this machine can actually be audited: the
        Hyper-V PowerShell module is present AND the VMMS service exists.
        A workstation with only the management tools installed is not a host.
    #>
    if (-not (Get-Command -Name Get-VM -Module Hyper-V -ErrorAction SilentlyContinue)) {
        if (-not (Get-Module -ListAvailable -Name Hyper-V -ErrorAction SilentlyContinue)) {
            return $false
        }
        try { Import-Module Hyper-V -ErrorAction Stop -Verbose:$false } catch { return $false }
    }
    $vmms = Get-Service -Name vmms -ErrorAction SilentlyContinue
    return ($null -ne $vmms)
}

function Get-PathLeaf {
    <#
        Filename portion of a path, splitting on both directory separators.

        [System.IO.Path]::GetFileName only honours the separator of the running
        platform, so it returns a Windows path unchanged on non-Windows. This
        script only ever runs on Windows, but keeping the helper platform-neutral
        means the output is identical under test harnesses too.
    #>
    param([AllowNull()][string]$Path)

    if ([string]::IsNullOrEmpty($Path)) { return '' }
    $index = $Path.LastIndexOfAny([char[]]@('\', '/'))
    if ($index -lt 0) { return $Path }
    return $Path.Substring($index + 1)
}

function Get-NinjaVariable {
    <#
        Reads a NinjaOne script variable from the environment.

        NinjaOne hands unset or cleared variables through as the literal string
        "null" rather than an absent variable, so that case is normalised to
        $null here. Surrounding whitespace is also trimmed.
    #>
    param([Parameter(Mandatory = $true)][string]$Name)

    $raw = [System.Environment]::GetEnvironmentVariable($Name)
    if ($null -eq $raw) { return $null }

    $value = $raw.Trim()
    if ($value.Length -eq 0) { return $null }
    if ($value -eq 'null') { return $null }
    return $value
}

function Set-NinjaCustomField {
    <#
        Writes a value into a NinjaOne custom field, preferring the native
        PowerShell cmdlet and falling back to ninjarmm-cli.exe.
    #>
    param(
        [Parameter(Mandatory = $true)][string]$FieldName,
        [Parameter(Mandatory = $true)][AllowEmptyString()][string]$HtmlContent
    )

    # Method 1: PowerShell-native cmdlet injected by the Ninja agent.
    if (Get-Command -Name Ninja-Property-Set -ErrorAction SilentlyContinue) {
        try {
            Ninja-Property-Set -Name $FieldName -Value $HtmlContent
            return $true
        }
        catch {
            Write-Warning "Ninja-Property-Set failed: $($_.Exception.Message). Trying ninjarmm-cli..."
        }
    }

    # Method 2: ninjarmm-cli.exe with --stdin.
    $ninjaCli = 'C:\ProgramData\NinjaRMMAgent\ninjarmm-cli.exe'
    if (-not (Test-Path -LiteralPath $ninjaCli)) {
        Write-Warning "ninjarmm-cli.exe not found at: $ninjaCli"
        return $false
    }

    $tempFile = $null
    try {
        $tempFile = [System.IO.Path]::GetTempFileName()
        [System.IO.File]::WriteAllText($tempFile, $HtmlContent, [System.Text.Encoding]::UTF8)

        Get-Content -LiteralPath $tempFile -Raw | & $ninjaCli set --stdin $FieldName
        if ($LASTEXITCODE -ne 0) {
            throw "ninjarmm-cli exited with code $LASTEXITCODE"
        }
        return $true
    }
    catch {
        Write-Warning "Failed to set custom field '$FieldName': $($_.Exception.Message)"
        return $false
    }
    finally {
        if ($tempFile -and (Test-Path -LiteralPath $tempFile)) {
            Remove-Item -LiteralPath $tempFile -Force -ErrorAction SilentlyContinue
        }
    }
}

function Get-VhdCached {
    <#
        Get-VHD with a per-run cache. Returns $null when the disk cannot be
        read, leaving the caller to record the failure.
    #>
    param([Parameter(Mandatory = $true)][string]$Path)

    $key = $Path.ToLowerInvariant()
    if ($script:VhdCache.ContainsKey($key)) { return $script:VhdCache[$key] }

    $vhd = $null
    try { $vhd = Get-VHD -Path $Path -ErrorAction Stop } catch { $vhd = $null }

    $script:VhdCache[$key] = $vhd
    return $vhd
}

function Get-VhdChainInfo {
    <#
        Walks a virtual disk's chain from the attached file down to its base,
        counting AVHDX files along the way.

        Returns a PSCustomObject. ChainError is populated when the walk could
        not complete; AvhdxCount then reflects only what was reachable, so it
        is a lower bound rather than a total.
    #>
    param([Parameter(Mandatory = $true)][string]$Path)

    $avhdxFiles = New-Object 'System.Collections.Generic.List[string]'
    $visited    = New-Object 'System.Collections.Generic.HashSet[string]'

    $info = [PSCustomObject]@{
        AttachedFile      = Get-PathLeaf -Path $Path
        AttachedPath      = $Path
        BasePath          = $null
        BaseType          = $null
        BaseBlockSize     = $null
        AttachedBlockSize = $null
        AvhdxCount        = 0
        DifferencingCount = 0
        ChainLength       = 0
        AvhdxFiles        = $avhdxFiles
        ChainError        = $null
    }

    $current = $Path
    while ($current) {
        if (-not $visited.Add($current.ToLowerInvariant())) {
            $info.ChainError = "Circular parent reference at $(Get-PathLeaf -Path $current)"
            break
        }
        if ($info.ChainLength -ge $script:MaxChainDepth) {
            $info.ChainError = "Chain exceeds the $($script:MaxChainDepth) link traversal limit"
            break
        }

        $vhd = Get-VhdCached -Path $current
        if ($null -eq $vhd) {
            $info.ChainError = "Cannot read $(Get-PathLeaf -Path $current)"
            break
        }

        # First iteration is the attached disk itself.
        if ($info.ChainLength -eq 0) { $info.AttachedBlockSize = $vhd.BlockSize }
        $info.ChainLength++

        if ([System.IO.Path]::GetExtension($current) -eq '.avhdx') {
            $info.AvhdxCount++
            $avhdxFiles.Add((Get-PathLeaf -Path $current))
        }
        if ($vhd.VhdType -eq 'Differencing') { $info.DifferencingCount++ }

        # Every iteration overwrites these, so once the loop ends normally they
        # describe the deepest disk reached - the base.
        $info.BasePath      = $vhd.Path
        $info.BaseType      = [string]$vhd.VhdType
        $info.BaseBlockSize = $vhd.BlockSize

        $current = $vhd.ParentPath
    }

    return $info
}

function Get-VMCheckpointCount {
    <#
        Number of checkpoints Hyper-V has registered for a VM.

        Returns $null when this cannot be determined. That is itself
        significant: Hyper-V fails to enumerate checkpoints when it cannot
        build the VM's VHD tree, which is exactly the state a broken chain
        produces.
    #>
    param([Parameter(Mandatory = $true)]$VMName)

    try {
        $snaps = @(Get-VMSnapshot -VMName $VMName -ErrorAction Stop)
        return $snaps.Count
    }
    catch {
        return $null
    }
}

function ConvertTo-HtmlEncoded {
    param([AllowNull()][string]$Text)
    if ([string]::IsNullOrEmpty($Text)) { return '' }
    return [System.Net.WebUtility]::HtmlEncode($Text)
}

#endregion -------------------------------------------------------------------

#region Preconditions --------------------------------------------------------

# Checked before the variable validation so that non-Hyper-V devices exit
# quietly instead of alerting for a variable they have no use for. This lets
# the script be scoped to an entire organisation safely.
if (-not (Test-HyperVHost)) {
    Write-Output 'Not a Hyper-V host (Hyper-V role or PowerShell module absent) - nothing to audit.'
    exit 0
}

$thresholdRaw = Get-NinjaVariable -Name 'avhdxthreshold'
if ($null -eq $thresholdRaw) {
    Write-Error "ERROR: script variable 'avhdxthreshold' is not set. Configure it in NinjaOne as an Integer (for example 3)."
    exit 1
}

$avhdxThreshold = 0
if (-not [int]::TryParse($thresholdRaw, [ref]$avhdxThreshold)) {
    Write-Error "ERROR: script variable 'avhdxthreshold' is not a valid integer (received '$thresholdRaw')."
    exit 1
}
if ($avhdxThreshold -lt 0) {
    Write-Error "ERROR: script variable 'avhdxthreshold' must be zero or greater (received $avhdxThreshold)."
    exit 1
}

$wysiwygCustomField = Get-NinjaVariable -Name 'wysiwygcustomfield'

#endregion -------------------------------------------------------------------

#region Collect --------------------------------------------------------------

try {
    $vms = @(Get-VM -ErrorAction Stop)
}
catch {
    Write-Error "ERROR: unable to enumerate virtual machines: $($_.Exception.Message)"
    exit 1
}

# Deliberately audits every VM regardless of power state. A powered-off VM is
# just as capable of sitting on a thousand-link chain, and is in fact the more
# dangerous case because nobody is looking at it.
$diskReports = New-Object 'System.Collections.Generic.List[object]'
$vmSummaries = New-Object 'System.Collections.Generic.List[object]'

foreach ($vm in $vms) {
    $vmDiskCount     = 0
    $vmAvhdxTotal    = 0
    $vmWorstAvhdx    = 0
    $vmHasError      = $false
    $checkpointCount = Get-VMCheckpointCount -VMName $vm.Name

    $vmDisks = New-Object 'System.Collections.Generic.List[object]'
    $disks = @()
    try {
        $disks = @(Get-VMHardDiskDrive -VMName $vm.Name -ErrorAction Stop)
    }
    catch {
        Write-Warning "Could not enumerate disks for VM '$($vm.Name)': $($_.Exception.Message)"
        $vmHasError = $true
    }

    foreach ($disk in $disks) {
        # Pass-through / physical disks and VHD Sets carry no file path we can
        # walk. Skip rather than emit a spurious failure.
        if ([string]::IsNullOrWhiteSpace($disk.Path)) { continue }

        $vmDiskCount++
        $chain = Get-VhdChainInfo -Path $disk.Path

        $vmAvhdxTotal += $chain.AvhdxCount
        if ($chain.AvhdxCount -gt $vmWorstAvhdx) { $vmWorstAvhdx = $chain.AvhdxCount }
        if ($chain.ChainError) { $vmHasError = $true }

        $diskEntry = [PSCustomObject]@{
            VMName            = $vm.Name
            VMState           = [string]$vm.State
            Controller        = "$($disk.ControllerType) $($disk.ControllerNumber):$($disk.ControllerLocation)"
            AttachedFile      = $chain.AttachedFile
            AttachedPath      = $chain.AttachedPath
            BaseFile          = if ($chain.ChainError) { 'unresolved' } elseif ($chain.BasePath) { Get-PathLeaf -Path $chain.BasePath } else { 'unknown' }
            BaseType          = $chain.BaseType
            BaseBlockSize     = $chain.BaseBlockSize
            AttachedBlockSize = $chain.AttachedBlockSize
            BlockSizeMismatch = ($chain.AvhdxCount -gt 0 -and
                                 $null -ne $chain.AttachedBlockSize -and
                                 $null -ne $chain.BaseBlockSize -and
                                 -not $chain.ChainError -and
                                 $chain.AttachedBlockSize -ne $chain.BaseBlockSize)
            AvhdxCount        = $chain.AvhdxCount
            DifferencingCount = $chain.DifferencingCount
            ChainLength       = $chain.ChainLength
            ChainError        = $chain.ChainError
            ExceedsThreshold  = ($chain.AvhdxCount -gt $avhdxThreshold)
        }
        $diskReports.Add($diskEntry)
        $vmDisks.Add($diskEntry)
    }

    $vmSummaries.Add([PSCustomObject]@{
        Disks            = $vmDisks
        VMName           = $vm.Name
        VMState          = [string]$vm.State
        DiskCount        = $vmDiskCount
        AvhdxTotal       = $vmAvhdxTotal
        WorstDiskAvhdx   = $vmWorstAvhdx
        CheckpointCount  = $checkpointCount
        HasError         = $vmHasError
    })
}

#endregion -------------------------------------------------------------------

#region Console report -------------------------------------------------------

$offenders   = @($diskReports | Where-Object { $_.ExceedsThreshold })
$chainErrors = @($diskReports | Where-Object { $null -ne $_.ChainError })
$currentDate = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
$hostName    = if ($env:COMPUTERNAME) { $env:COMPUTERNAME } else { [System.Net.Dns]::GetHostName() }

Write-Output '=== Hyper-V Checkpoint (AVHDX) Audit ==='
Write-Output "Host             : $hostName"
Write-Output "Date             : $currentDate"
Write-Output "AVHDX threshold  : $avhdxThreshold per virtual disk"
Write-Output "Virtual machines : $($vms.Count)"
Write-Output "Virtual disks    : $($diskReports.Count)"
Write-Output ''

foreach ($summary in $vmSummaries) {
    $checkpointText = if ($null -eq $summary.CheckpointCount) {
        'unreadable (Hyper-V cannot build the VHD tree)'
    } else {
        [string]$summary.CheckpointCount
    }

    Write-Output "VM '$($summary.VMName)' [$($summary.VMState)] - disks: $($summary.DiskCount), AVHDX total: $($summary.AvhdxTotal), registered checkpoints: $checkpointText"

    foreach ($disk in $summary.Disks) {
        $marker = if ($disk.ExceedsThreshold) { '  [OVER THRESHOLD]' } else { '' }
        Write-Output ("    {0,-12} AVHDX: {1,-5} chain links: {2,-5} base: {3}{4}" -f `
            $disk.Controller, $disk.AvhdxCount, $disk.ChainLength, $disk.BaseFile, $marker)

        if ($disk.ChainError) {
            Write-Output "                 CHAIN ERROR: $($disk.ChainError)"
        }

        # A block-size difference between the checkpoint AVHDX and its base
        # makes the final merge into the base impossible: Hyper-V rejects it
        # with 0x80070032 ERROR_NOT_SUPPORTED. The chain can therefore never
        # fully clear, no matter how often the backup product retries.
        if ($disk.BlockSizeMismatch) {
            Write-Output ("                 BLOCK SIZE MISMATCH: attached {0} MB vs base {1} MB - this chain cannot merge into its base." -f `
                [math]::Round($disk.AttachedBlockSize / 1MB, 0), [math]::Round($disk.BaseBlockSize / 1MB, 0))
        }
    }

    # A registered checkpoint count far below the AVHDX count means most of
    # those AVHDX are orphans Hyper-V no longer tracks - the signature of a
    # backup product whose post-backup merge has been failing.
    if ($null -ne $summary.CheckpointCount -and $summary.AvhdxTotal -gt 0 -and
        $summary.AvhdxTotal -gt $summary.CheckpointCount) {
        Write-Output "    NOTE: $($summary.AvhdxTotal) AVHDX file(s) present but only $($summary.CheckpointCount) registered checkpoint(s) - the remainder are orphans."
    }

    Write-Output ''
}

if ($chainErrors.Count -gt 0) {
    Write-Output "NOTE: $($chainErrors.Count) virtual disk chain(s) could not be fully read. Their AVHDX counts are lower bounds, not totals."
    Write-Output ''
}

#endregion -------------------------------------------------------------------

#region Optional WYSIWYG custom field ----------------------------------------

if ($wysiwygCustomField) {
    # Inline styles only. NinjaOne WYSIWYG fields allow the `class` attribute
    # but strip anything outside their documented class set (Bootstrap 5 grid,
    # Font Awesome 6, NinjaOne's own card/stat-card classes). Tailwind and
    # other arbitrary utility classes do not render.
    $sb = New-Object System.Text.StringBuilder

    if ($offenders.Count -gt 0) {
        $bannerColor = '#dc3545'
        $bannerIcon  = 'WARNING'
        $bannerText  = "$($offenders.Count) virtual disk(s) exceed the maximum of $avhdxThreshold AVHDX file(s)"
    }
    else {
        $bannerColor = '#27ae60'
        $bannerIcon  = 'OK'
        $bannerText  = "No virtual disk exceeds the maximum of $avhdxThreshold AVHDX file(s)"
    }

    [void]$sb.Append("<div style='font-family: Arial, sans-serif;'>")
    [void]$sb.Append("<h2 style='color: #2c3e50; margin-bottom: 10px;'>Hyper-V Checkpoint (AVHDX) Audit</h2>")
    [void]$sb.Append("<div style='padding: 10px; margin-bottom: 15px; background-color: #f8f9fa; border-left: 4px solid $bannerColor; border-radius: 3px;'>")
    [void]$sb.Append("<span style='color: $bannerColor; font-weight: bold;'>$bannerIcon</span> <span>$(ConvertTo-HtmlEncoded $bannerText)</span>")
    [void]$sb.Append('</div>')
    [void]$sb.Append("<p style='color: #7f8c8d; margin-bottom: 20px;'>Host: <span style='font-weight: bold;'>$(ConvertTo-HtmlEncoded $hostName)</span> | Virtual machines: <span style='font-weight: bold;'>$($vms.Count)</span> | Virtual disks: <span style='font-weight: bold;'>$($diskReports.Count)</span> | Threshold: <span style='font-weight: bold;'>$avhdxThreshold</span> | Last updated: <span style='font-weight: bold;'>$currentDate</span></p>")

    if ($diskReports.Count -eq 0) {
        [void]$sb.Append("<p style='padding: 10px; background-color: #e8f4f8; border-left: 4px solid #17a2b8;'>No file-backed virtual disks found on this host.</p>")
    }
    else {
        [void]$sb.Append("<table style='width: 100%; border-collapse: collapse;'>")
        [void]$sb.Append("<thead><tr style='background-color: #9b59b6; color: white;'>")
        foreach ($header in @('Virtual machine', 'State', 'Controller', 'Attached disk', 'AVHDX', 'Chain', 'Base disk')) {
            [void]$sb.Append("<th style='padding: 10px; text-align: left; border: 1px solid #ddd;'>$header</th>")
        }
        [void]$sb.Append('</tr></thead><tbody>')

        $rowIndex = 0
        foreach ($disk in $diskReports) {
            $bgColor = if ($disk.ExceedsThreshold) { '#fff3cd' } elseif ($rowIndex % 2 -eq 0) { '#f8f9fa' } else { '#ffffff' }
            $countColor = if ($disk.ExceedsThreshold) { '#dc3545' } else { '#27ae60' }

            [void]$sb.Append("<tr style='background-color: $bgColor;'>")
            [void]$sb.Append("<td style='padding: 8px; border: 1px solid #ddd; font-weight: bold;'>$(ConvertTo-HtmlEncoded $disk.VMName)</td>")
            [void]$sb.Append("<td style='padding: 8px; border: 1px solid #ddd;'>$(ConvertTo-HtmlEncoded $disk.VMState)</td>")
            [void]$sb.Append("<td style='padding: 8px; border: 1px solid #ddd;'>$(ConvertTo-HtmlEncoded $disk.Controller)</td>")
            [void]$sb.Append("<td style='padding: 8px; border: 1px solid #ddd; font-size: 11px; word-break: break-all;'>$(ConvertTo-HtmlEncoded $disk.AttachedFile)</td>")
            [void]$sb.Append("<td style='padding: 8px; border: 1px solid #ddd; color: $countColor; font-weight: bold;'>$($disk.AvhdxCount)</td>")
            [void]$sb.Append("<td style='padding: 8px; border: 1px solid #ddd;'>$($disk.ChainLength)</td>")
            [void]$sb.Append("<td style='padding: 8px; border: 1px solid #ddd; font-size: 11px; word-break: break-all;'>$(ConvertTo-HtmlEncoded $disk.BaseFile)</td>")
            [void]$sb.Append('</tr>')

            if ($disk.ChainError) {
                [void]$sb.Append("<tr style='background-color: $bgColor;'><td colspan='7' style='padding: 8px; border: 1px solid #ddd; color: #dc3545; font-size: 12px;'>Chain error: $(ConvertTo-HtmlEncoded $disk.ChainError)</td></tr>")
            }

            $rowIndex++
        }

        [void]$sb.Append('</tbody></table>')
    }

    if ($offenders.Count -gt 0) {
        [void]$sb.Append("<div style='margin-top: 15px; padding: 12px; background-color: #fff3cd; border-left: 4px solid #dc3545; border-radius: 3px;'>")
        [void]$sb.Append("<span style='color: #dc3545; font-weight: bold;'>Long checkpoint chains detected.</span>")
        [void]$sb.Append("<p style='font-size: 12px; color: #856404; margin-top: 6px;'>This usually means a backup product is creating checkpoints that Hyper-V then fails to merge. Check the backup job history for merge or checkpoint-removal warnings, and the Hyper-V-VMMS event log on this host. Do not merge a long chain without a verified backup first.</p>")
        [void]$sb.Append('</div>')
    }

    $osCaption = ''
    try { $osCaption = (Get-CimInstance -ClassName Win32_OperatingSystem -ErrorAction Stop).Caption } catch { $osCaption = 'unknown' }
    [void]$sb.Append("<p style='margin-top: 15px; font-size: 12px; color: #95a5a6;'>OS: $(ConvertTo-HtmlEncoded $osCaption) | PowerShell version: $($PSVersionTable.PSVersion)</p>")
    [void]$sb.Append('</div>')

    if (Set-NinjaCustomField -FieldName $wysiwygCustomField -HtmlContent $sb.ToString()) {
        Write-Output "Report written to custom field: $wysiwygCustomField"
    }
    else {
        # A custom-field write failure must not mask the audit result, so this
        # is a warning rather than a fatal error.
        Write-Warning "Could not write the report to custom field '$wysiwygCustomField'. The audit result below is still valid."
    }
    Write-Output ''
}

#endregion -------------------------------------------------------------------

#region Result ---------------------------------------------------------------

if ($offenders.Count -gt 0) {
    Write-Output "RESULT CODE 4: WARNING - more than $avhdxThreshold AVHDX file(s) detected on $($offenders.Count) virtual disk(s)."
    Write-Output 'This may indicate that checkpoints are not being merged after backup, which degrades disk performance and consumes space.'
    Write-Output ''
    Write-Output 'Affected disks:'
    foreach ($disk in ($offenders | Sort-Object -Property AvhdxCount -Descending)) {
        Write-Output ("  VM '{0}' [{1}] {2} - {3} AVHDX file(s), chain {4} link(s), base '{5}'" -f `
            $disk.VMName, $disk.VMState, $disk.Controller, $disk.AvhdxCount, $disk.ChainLength, $disk.BaseFile)
    }
    exit 4
}

Write-Output "RESULT CODE 0: OK - no virtual disk exceeds $avhdxThreshold AVHDX file(s)."
exit 0

#endregion -------------------------------------------------------------------
