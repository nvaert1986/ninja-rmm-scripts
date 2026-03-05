# NinjaOne Agent — dpkg Compatibility Wrappers for Gentoo Linux

These scripts allow the NinjaOne agent to function correctly on Gentoo Linux by emulating the `dpkg` and `dpkg-query` tools against the Portage package database.

---

> ## ⚠️ WARNING — DO NOT USE ON SYSTEMS WITH dpkg INSTALLED
>
> **These scripts must never be installed on any system where `dpkg` is already present** (Debian, Ubuntu, Linux Mint, Pop!_OS, Kali, Raspberry Pi OS, or any Debian/Ubuntu-based distribution).
>
> Installing these wrappers on a system that already has `dpkg` will **overwrite the real `dpkg` and `dpkg-query` binaries** in `/usr/local/bin`, which takes precedence over `/usr/bin` in most PATH configurations. This will break package management for the entire system and may render it unbootable or unrecoverable.
>
> **Only install these scripts on pure Gentoo Linux systems where no `dpkg` package is installed.**

---

## What These Scripts Do

The NinjaOne agent was designed for Debian/Ubuntu systems and calls `dpkg-query` to inventory installed software. On Gentoo, these tools do not exist. These wrappers intercept those calls and translate them into equivalent Portage (`qlist`) queries, making the NinjaOne agent believe it is running on a Debian-compatible system.

| Script | Installed path | Purpose |
|---|---|---|
| `dpkg-query.sh` | `/usr/local/bin/dpkg-query` | Main wrapper — translates `dpkg-query` calls to `qlist` output |
| `dpkg.sh` | `/usr/local/bin/dpkg` | Secondary wrapper — handles `dpkg -l` listing; blocks removal/install |
| `generate-dpkg-log.sh` | `/usr/local/sbin/generate-dpkg-log` | One-time tool — backfills `/var/log/dpkg.log` from Portage timestamps |

### NinjaOne GUI column mapping

| NinjaOne column | Source |
|---|---|
| Software | Package name (e.g. `bash:amd64`) |
| Version | Portage version string |
| Publisher | Portage category (e.g. `app-shells`, `dev-libs`) |
| Install date | Parsed from `/var/log/dpkg.log` |

---

## Prerequisites

- Gentoo Linux (amd64)
- `app-portage/portage-utils` must be installed (provides `qlist`):
  ```
  emerge --ask app-portage/portage-utils
  ```
- NinjaOne agent installed and running (`/opt/NinjaRMMAgent/`)

---

## Installation

### 1. Download the scripts

Clone or download the scripts from GitHub. The files are provided with a `.sh` extension and must be **renamed** when copied (the `.sh` extension must be removed).

### 2. Copy and make executable

Run the following as root:

```bash
# dpkg-query wrapper
cp dpkg-query.sh /usr/local/bin/dpkg-query
chmod 755 /usr/local/bin/dpkg-query

# dpkg wrapper
cp dpkg.sh /usr/local/bin/dpkg
chmod 755 /usr/local/bin/dpkg

# generate-dpkg-log tool
cp generate-dpkg-log.sh /usr/local/sbin/generate-dpkg-log
chmod 755 /usr/local/sbin/generate-dpkg-log
```

### 3. Generate the initial install-date log

Run this once to backfill `/var/log/dpkg.log` with historical install dates derived from Portage package directory timestamps:

```bash
sudo /usr/local/sbin/generate-dpkg-log
```

This creates `/var/log/dpkg.log` which NinjaOne reads to populate the "Install date" column for each package.

### 4. Set up the Portage hook for ongoing tracking

Add the following to `/etc/portage/bashrc` so that every future `emerge` automatically appends to `/var/log/dpkg.log`:

```bash
post_pkg_postinst() {
    local pn="${PN}"
    local pv="${PVR%-r0}"
    local cat="${CATEGORY}"
    local datestamp
    datestamp=$(date '+%Y-%m-%d %H:%M:%S')
    echo "${datestamp} install ${pn}:amd64 <none> ${pv}" >> /var/log/dpkg.log
}
```

If `/etc/portage/bashrc` does not exist yet, create it with that content.

### 5. Verify

Test the dpkg-query wrapper directly:

```bash
/usr/local/bin/dpkg-query --show --showformat='${binary:Package}\t${Version}\n'
```

You should see a list of all installed Portage packages in dpkg format. The NinjaOne agent will pick up the inventory on its next check-in cycle (usually within a few minutes).

---

## How It Works

- **`dpkg-query`** calls `qlist -IRv` in a single awk pass to parse Portage CPV atoms into `name:amd64`, `version`, and `category` fields. The Portage category becomes the "Publisher" field in NinjaOne.
- **`dpkg`** handles `dpkg -l` listing. Removal (`--remove`, `--purge`) and installation (`--install`) are intentionally blocked — it will print an error directing the user to use `emerge` instead.
- **`generate-dpkg-log`** iterates over `/var/db/pkg/` directories and uses their filesystem modification timestamps as a proxy for install dates, then writes them to `/var/log/dpkg.log` in dpkg log format.
- A **sentinel package** (`a-gentoo-dpkg-wrapper 1.0.0`) appears in the inventory to confirm the wrapper is active.

---

## Uninstalling

```bash
sudo rm /usr/local/bin/dpkg-query
sudo rm /usr/local/bin/dpkg
sudo rm /usr/local/sbin/generate-dpkg-log
```

Remove the `post_pkg_postinst` block from `/etc/portage/bashrc` if you added it.
