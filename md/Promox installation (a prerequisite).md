# Proxmox Installation (a Prerequisite)

This guide outlines how to install Proxmox manually — which is required before running anything in this repository.

## Why manual install?

As I mentioned in the readme, Proxmox can be bootstrapped and automated with PXE, preseed, or other tools — but I decided that the complexity wasn’t worth it. Clicking through the standard installer is much earlier, and I assume that has been done now.

> 💡 My rule: *Click through the installer (`Next`, `Next`, `Finish`) and automate everything after that.*

---

## My Personal Selections (Reference)

These are the choices I make during a fresh Proxmox install. This list is here for *me* and my specific setup — yours might have different needs.

### 🔧 Installer Settings

- **Filesystem**: `ZFS (RAID1)`
- **Country/Timezone**: `DK / Europe / Copenhagen`
- **Keyboard**: `Danish`
- **Hostname**: Manually set based on role (e.g., `pve01`)  
  *(The script will later change it to whatever you define in your config YAML)*
- **IP address**: Static, configured during installation
- **Root password**: Set manually  
  *(If you set `change_password: true` in the config, the script will prompt you to update it)*

### Post-Install Tasks

After reboot:
- Access Proxmox via the web UI: `https://<your-ip>:8006`
- Ensure SSH access is working — the script connects via SSH and expects the host to be reachable.

#### Validate SSH access to Proxmox host

    Log in to the Proxmox host using SSH. Change @x.x.x.x to the ip-address of the Proxmox host
    
```
ssh -o IdentitiesOnly=yes root@x.x.x.x
```

    if successful, continue and copy your SSH key to the Proxmox root account. I assume that an SSH key has been created for use when logging into Proxmox as root. Replace ~/.ssh/Key-for-Proxmox.pub with the path for the key you want to use, and change @x.x.x.x to the ip-address of the Proxmox host
```
ssh-copy-id -o IdentitiesOnly=yes -i ~/.ssh/Key-for-Proxmox.pub root@x.x.x.x
```

---

## Step-by-Step: Install & Prep

### 1. Download Proxmox VE ISO

- [Official site](https://www.proxmox.com/en/downloads)
- Select the latest **Proxmox VE** ISO
- Optionally verify the SHA256 hash

### 2. Flash ISO to USB

Recommended tools:
- On Linux/macOS: `balenaEtcher`, `dd`
- On Windows: `Rufus`

### 3. Boot and Install

- Boot from the USB stick
- Run through the Proxmox installer
- Apply the selections above 
- Reboot when done

---

## Using Spare Laptops for Proxmox Testing

I often repurpose spare laptops for testing Proxmox installs.

If you want the system to **continue running with the lid closed**, you need to override the default ACPI behavior. Add the following to your laptop’s systemd power settings:

```bash
echo "HandleLidSwitch=ignore" >> /etc/systemd/logind.conf
```
Then reload the configuration:
```
systemctl restart systemd-logind
```
This prevents the laptop from suspending or powering off when the lid is closed — useful for headless testing setups.

## Proxmox host configuration
Now you should be able to continue to the  [Proxmox host configuration](https://github.com/PCH-ApS/proxmox/blob/main/md/Proxmox%20host%20configuration.md) for further information on my configuration script.
