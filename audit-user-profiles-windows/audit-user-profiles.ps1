# ------------------------------------------------------------
# Script: Audit User Profile Folders (read-only)
# Purpose: For every folder under C:\Users, report whether a
#          ProfileList registry entry exists, the real last logon
#          (LocalProfileLoadTime/UnloadTime), and the top-level
#          contents. Classifies each folder so leftovers from the
#          cleanup script can be identified. Changes nothing.
# ------------------------------------------------------------

$profileList = Get-ChildItem 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList' |
    Get-ItemProperty

function Get-RegLastLogon {
    param($Entry)
    $times = @()
    foreach ($pair in @('LocalProfileLoadTime', 'LocalProfileUnloadTime')) {
        $high = $Entry."${pair}High"
        $low  = $Entry."${pair}Low"
        if ($null -ne $high -and $null -ne $low) {
            $fileTime = ([uint64][uint32]$high -shl 32) -bor [uint64][uint32]$low
            if ($fileTime -gt 0) {
                try { $times += [datetime]::FromFileTime([int64]$fileTime) } catch {}
            }
        }
    }
    if ($times.Count -eq 0) { return $null }
    return ($times | Sort-Object -Descending | Select-Object -First 1)
}

$systemNames = @('Public', 'Default', 'Default User', 'All Users')

foreach ($dir in Get-ChildItem -Path 'C:\Users' -Directory -Force | Sort-Object Name) {
    if ($systemNames -contains $dir.Name) {
        Write-Host ("{0,-25} SYSTEM folder" -f $dir.Name)
        continue
    }

    $entry = $profileList | Where-Object { $_.ProfileImagePath -eq $dir.FullName }

    if ($entry) {
        $lastLogon = Get-RegLastLogon -Entry $entry
        if ($lastLogon) {
            $status = "IN REGISTRY, last logon $($lastLogon.ToString('yyyy-MM-dd'))"
        }
        else {
            $status = "IN REGISTRY, no logon time recorded (by-design skip)"
        }
    }
    else {
        $status = "ORPHAN - no registry entry (leftover husk, safe to remove)"
    }

    $children = @(Get-ChildItem -LiteralPath $dir.FullName -Force -ErrorAction SilentlyContinue |
        Select-Object -ExpandProperty Name)
    $contentSummary = if ($children.Count -eq 0) { "(empty)" }
                      elseif ($children.Count -le 4) { $children -join ', ' }
                      else { "$($children.Count) items" }

    Write-Host ("{0,-25} {1}  [{2}]" -f $dir.Name, $status, $contentSummary)
}

exit 0
