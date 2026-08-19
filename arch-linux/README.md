# NinjaOne Agent — dpkg Compatibility Wrappers for Arch Linux

These scripts allow the NinjaOne agent to function correctly on Arch Linux (and Arch-based distributions) by emulating the `dpkg` and `dpkg-query` tools against the pacman package database.

---

> ## ⚠️ WARNING — DO NOT USE ON SYSTEMS WITH dpkg INSTALLED
>
> **These scripts must never be installed on any system where `dpkg` is already present** (Debian, Ubuntu, Linux Mint, Pop!_OS, Kali, Raspberry Pi OS, or any Debian/Ubuntu-based distribution).
>
> Installing these wrappers on a system that already has `dpkg` will **overwrite the real `dpkg` and `dpkg-query` binaries** in `/usr/local/bin`, which takes precedence over `/usr/bin` in most PATH configurations. This will break package management for the entire system and may render it unbootable or unrecoverable.
>
> **Only install these scripts on pure Arch Linux (or Arch-based) systems where no `dpkg` package is installed.**

---

## What These Scripts Do

The NinjaOne agent was designed for Debian/Ubuntu systems and calls `dpkg-query` to inventory installed software. On Arch Linux, these tools do not exist. These wrappers intercept those calls and translate them into equivalent pacman queries, making the NinjaOne agent believe it is running on a Debian-compatible system.

AUR packages installed via **yay, paru, or any other AUR helper** are automatically detected — no special configuration is needed. All AUR helpers use pacman under the hood, so AUR packages always appear in `pacman -Qm` (foreign packages) and are listed with `Publisher: aur`.

| File | Installed path | Purpose |
|---|---|---|
| `dpkg-query.sh` | `/usr/local/bin/dpkg-query` | Main wrapper — translates `dpkg-query` calls to `pacman -Q` output |
| `dpkg.sh` | `/usr/local/bin/dpkg` | Secondary wrapper — handles `dpkg -l` listing |
| `generate-dpkg-log.sh` | `/usr/local/sbin/generate-dpkg-log` | One-time tool — backfills `/var/log/dpkg.log` from pacman.log history |
| `ninjaone-dpkg-log-update.sh` | `/usr/local/sbin/ninjaone-dpkg-log-update` | Hook script — appends new entries to dpkg.log after each transaction |
| `ninjaone-dpkg-log.hook` | `/etc/pacman.d/hooks/ninjaone-dpkg-log.hook` | pacman hook — triggers the update script after install/upgrade/remove |

### NinjaOne GUI column mapping

| NinjaOne column | Source |
|---|---|
| Software | Package name (e.g. `bash:x86_64`) |
| Version | pacman version string |
| Publisher | `arch-official` for official repos, `aur` for AUR packages |
| Install date | Parsed from `/var/log/dpkg.log` (populated from `pacman.log`) |

---

## Prerequisites

### Wrapper scripts

The wrapper scripts only depend on tools that ship with the `base` package group and are always present on any Arch installation:

| Tool | Package | Notes |
|---|---|---|
| `bash` | `bash` | `base` |
| `awk` | `gawk` | `base` |
| `stat`, `date`, `sort`, `wc`, `mktemp` | `coreutils` | `base` |
| `pacman` | `pacman` | always present |

No additional packages are required for the wrapper scripts themselves.

### NinjaOne agent runtime dependencies

The NinjaOne agent binary makes several calls to system tools at runtime. Some of these are **not** included in the Arch `base` package group and must be installed separately:

| Tool | Package | Required for |
|---|---|---|
| `nmcli` | `networkmanager` | Network interface inventory |
| `netstat` / `ifconfig` | `net-tools` | Network statistics (not in `base` on Arch) |
| `lsblk`, `lscpu` | `util-linux` | Hardware inventory (`base`) |
| `ps`, `uptime` | `procps-ng` | Process and uptime data (`base`) |
| `which` | `which` | Agent self-check (`base`) |
| `systemctl` | `systemd` | Service management (Arch default) |

Install the missing ones before deploying the agent:

```bash
sudo pacman -S networkmanager net-tools
```

If NetworkManager is not already running as your network manager, enable it:

```bash
sudo systemctl enable --now NetworkManager
```

> **Note:** On most desktop Arch installations (Manjaro, EndeavourOS, Garuda, etc.) `networkmanager` is already present. `net-tools` is the most commonly missing package on minimal installs.

---

## Installation

> ### ⚠️ CRITICAL — Read before deploying these wrapper scripts
>
> **Step 1 must be completed before these dpkg and dpkg-query wrapper scripts are installed and active.**
>
> The NinjaOne server records the install date for each package the very first time the agent reports it. Once recorded, **that date is permanent — the server will never update it**, even if the agent later reports a different date.
>
> If the agent runs its first inventory before `/var/log/dpkg.log` exists and contains correct data, it will report **1970-01-01** as the install date for every package. Correcting this afterwards requires removing and re-enrolling the device in NinjaOne entirely.
>
> **Always run `generate-dpkg-log` first, before deploying these wrapper scripts.**

---

### Step 1. Generate the install-date log (BEFORE deploying the wrapper scripts)

Script files from GitHub have a `.sh` extension that must be **removed** when copying. Copy the script, make it executable, and run it immediately:

```bash
cp generate-dpkg-log.sh /usr/local/sbin/generate-dpkg-log && chmod 755 /usr/local/sbin/generate-dpkg-log
sudo /usr/local/sbin/generate-dpkg-log
```

Verify it produced entries before continuing:

```bash
head -5 /var/log/dpkg.log
```

You should see lines like:
```
2025-11-06 18:25:23 install bash:x86_64 <none> 5.2.037-1
```

If the output is empty, do not proceed — investigate why `pacman.log` is not being parsed before installing the NinjaOne agent.

---

### Step 2. Copy remaining scripts and make executable

```bash
# Inventory wrappers
cp dpkg-query.sh /usr/local/bin/dpkg-query && chmod 755 /usr/local/bin/dpkg-query
cp dpkg.sh       /usr/local/bin/dpkg       && chmod 755 /usr/local/bin/dpkg

# Hook update script (generate-dpkg-log was already copied in Step 1)
cp ninjaone-dpkg-log-update.sh /usr/local/sbin/ninjaone-dpkg-log-update && chmod 755 /usr/local/sbin/ninjaone-dpkg-log-update
```

### Step 3. Install the pacman hook

```bash
cp ninjaone-dpkg-log.hook /etc/pacman.d/hooks/ninjaone-dpkg-log.hook
```

The hook fires automatically after every `pacman` transaction (install, upgrade, or remove), including transactions triggered by yay/paru or any other AUR helper, and appends new entries to `/var/log/dpkg.log` automatically.

### Step 4. Install the NinjaOne agent

Install the NinjaOne agent now. Because `/var/log/dpkg.log` already exists with correct data from Step 1, the agent will report accurate install dates on its very first inventory.

### Step 5. Verify

Test the dpkg-query wrapper directly:

```bash
/usr/local/bin/dpkg-query --show --showformat='${binary:Package}\t${Version}\n'
```

You should see a list of all installed packages in dpkg format. The NinjaOne agent will pick up the inventory on its next check-in cycle (usually within a few minutes).

---

## How It Works

- **`dpkg-query`** calls `pacman -Q` for the package list and reads `/var/lib/pacman/local/*/desc` files in a single awk pass to determine the architecture of each package. AUR packages are identified via `pacman -Qm`. Install dates come from `/var/log/dpkg.log`.
- **`dpkg`** handles `dpkg -l` style listing for the agent's uninstall detection queries.
- **`generate-dpkg-log`** parses the full history from `/var/log/pacman.log` (which pacman maintains automatically) and converts it to dpkg log format, preserving original timestamps.
- **`ninjaone-dpkg-log-update`** is called by the pacman hook after each transaction. It reads only the new entries from `pacman.log` (using a stored epoch timestamp) and appends them to `/var/log/dpkg.log`.
- A **sentinel package** (`a-arch-dpkg-wrapper 1.0.0`) appears in the inventory to confirm the wrapper is active.

---

## Compatibility

Tested AUR helpers (no additional configuration required):

- `yay`
- `paru`
- Any other AUR helper that uses pacman as its backend

---

## Uninstalling

```bash
sudo rm /usr/local/bin/dpkg-query
sudo rm /usr/local/bin/dpkg
sudo rm /usr/local/sbin/generate-dpkg-log
sudo rm /usr/local/sbin/ninjaone-dpkg-log-update
sudo rm /etc/pacman.d/hooks/ninjaone-dpkg-log.hook
sudo rm -rf /var/lib/ninjaone-dpkg
```
