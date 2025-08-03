This guide outlines how to use the `configure_host.py` script to automate Proxmox host configuration using Infrastructure-as-Code (IaC) principles.

**The host configuration script is called from /run_configure_host.py**

```
./run_configure_host.py --config config/host_config.yaml

```

Optional override for validation rules:
```
./run_configure_host.py --config config/host_config.yaml --validation config/custom_validation.yaml
```
## Requirements

- cerberus is required for validating config files.
  if not installed, add it with:
```
pip3 install cerberus
````

## Config File Structure

YAML file must contain only populated values. Do not include unused or empty keys.

Example:
```
pve_host_ip: 192.168.100.10
pve_hostname: proxmox-node-1
pve_domain: lab.local
pve_host_username: root
pve_host_keyfile: /home/user/.ssh/id_ed25519
pve_sshkey_public:
  - ssh-ed25519 AAAAC3... user@laptop
pve_iso_urls:
  - https://cloud-images.ubuntu.com/.../server.img
pve_host_reboot: true
pve_host_change_pwd: true
```

Config keys that are not requred in config file, will be set to default values from the validation yaml file.

**The required keys are:**
* pve_hostname
* pve_host_ip

The rest of the keys can be filled with default values, that can be set up in the validation yaml file.

### ### Example Validation Rules

See `host_config_validation_example.yaml` for field-by-field schema with regex, defaults, and optional/required flags.

This table reflects what's enforced by `host_config_validation.yaml`:
#### Host Config Validation Overview

| Key                   | Required | Default                    | Description                                              |
| --------------------- | -------- | -------------------------- | -------------------------------------------------------- |
| `pve_host_username`   | ❌        | `root`                     | SSH username used to connect to the Proxmox host         |
| `pve_host_ip`         | ✅        | —                          | IPv4 address of the Proxmox host                         |
| `pve_hostname`        | ✅        | —                          | Desired hostname (e.g., `pve01`)                         |
| `pve_domain`          | ❌        | `your.domain.here`         | Domain name part of FQDN (e.g., `lab.local`)             |
| `pve_sshkey_public`   | ❌        | `'Your key goes here ...'` | List of public SSH keys to install                       |
| `pve_iso_urls`        | ❌        | `'Your URL goes here ...'` | List of URLs to download ISO/cloud images                |
| `pve_iso_path`        | ❌        | `/var/lib/vz/template/iso` | Directory to store downloaded ISOs                       |
| `pve_host_keyfile`    | ❌        | `path/to/ssh/keyfile`      | Path to SSH private key (must match `pve_host_username`) |
| `pve_host_file`       | ❌        | `/etc/hosts`               | Path to the `/etc/hosts` file                            |
| `pve_host_change_pwd` | ❌        | `false`                    | Whether to prompt and set a new root password            |
| `pve_host_reboot`     | ❌        | `false`                    | Whether to reboot after hostname change                  |

### SSHD & Security Defaults

These fields modify the `sshd_config` remotely:

| Key                      | Required | Default                             | Notes                                            |
| ------------------------ | -------- | ----------------------------------- | ------------------------------------------------ |
| `PermitRootLogin`        | ❌        | `without-password`                  | SSH login policy for root                        |
| `PasswordAuthentication` | ❌        | `no`                                | Disables password login                          |
| `PermitEmptyPasswords`   | ❌        | `no`                                | Disallow empty password usage                    |
| `UseDNS`                 | ❌        | `no`                                | Skips DNS reverse lookups in SSHD                |
| `AllowTcpForwarding`     | ❌        | `no`                                | Disables SSH TCP forwarding                      |
| `X11Forwarding`          | ❌        | `no`                                | Disables GUI/X11 forwarding                      |
| `ClientAliveInterval`    | ❌        | `300`                               | SSH keepalive interval in seconds                |
| `ClientAliveCountMax`    | ❌        | `2`                                 | Max missed keepalive responses before disconnect |
| `MaxAuthTries`           | ❌        | `3`                                 | Max failed login attempts                        |
| `MaxSessions`            | ❌        | `2`                                 | Max SSH sessions per connection                  |
| `Compression`            | ❌        | `no`                                | Enables/disables SSH compression                 |
| `LogLevel`               | ❌        | `VERBOSE`                           | SSHD log verbosity                               |
| `LoginGraceTime`         | ❌        | `30`                                | Time (seconds) before login times out            |
| `Subsystem`              | ❌        | `sftp /usr/lib/openssh/sftp-server` | SFTP handler definition                          |

### SSHD Configuration Metadata

Used to locate and override SSHD settings:

|Key|Required|Default|Description|
|---|---|---|---|
|`pve_key_prefix`|❌|`pve_`|Prefix for filtering which SSHD keys apply|
|`pve_sshd_searchstring`|❌|`include`|Term used to find config includes|
|`pve_sshd_config_path`|❌|`/etc/ssh/sshd_config`|Main SSHD config file|
|`pve_sshd_custom_config`|❌|`/etc/ssh/sshd_config.d/99-custom.conf`|
## Logs

All script output is by default logged in: logs/configure_host.log
and in terminal.

## Tips

- Test your SSH connection to the host before running the script.
- Use `ssh-copy-id` to pre-load your public key for the user specified in the config.
- Make sure Proxmox VE is installed and reachable via SSH.

## Features

### File Validation

- Ensures YAML config and schema files exist, are readable, and are `.yaml` or `.yml`.

### Config Validation

- Uses Cerberus schema (`host_config_validation.yaml`) to enforce types, defaults, and regex rules.

### Hostname Handling

- Verifies current hostname.
- Validates default config folders are empty before renaming.
- Updates `/etc/hosts` and uses `hostnamectl` to apply changes.

### Optional Host Reboot

- If the hostname changes and `pve_host_reboot: true`, the host will be rebooted and SSH connection re-established.

### SSH Key Handling

- Ensures proper permissions on `.ssh` and `authorized_keys`.
- Adds missing keys listed in the config file

### SSHD Configuration

- Checks and hardens `sshd_config`.
- Missing or incorrect parameters are added to a custom config file.
- Reloads SSHD service if changes were made.    

The desired sshd config is part of the `host_config_validation.yaml file or config file, so desired config can be controlled within the config files, and reapplied is needed.

### Repository Adjustments

- Enables `pve-no-subscription` repo.
- Disables `enterprise` and `ceph` repos.
- Optionally applies Proxmox patch to suppress subscription popups.

### ISO Download

- Downloads specified ISO/images into the host's ISO directory (`/var/lib/vz/template/iso` by default).

### Root Password Change

- If `pve_host_change_pwd` is `true`, prompts for a new root password.

### Snippets Support

- Ensures `local` storage has `snippets` enabled.
- Creates `/var/lib/vz/snippets` if needed.
- Creates a custom cloud init file to install QEMU-agent on guests.