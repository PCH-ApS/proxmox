# Prepare Proxmox Host

Prepare and sanity‑check a Proxmox VE host before use.  
This script configures hostname, repository settings, GUI patch, and downloads ISO files.


This script also checks and adjusts `sshd` configuration to match settings in your config file,
ensuring that the PVE host and/or guest is ready for further automation, e.g., provisioning with **Ansible**.

## How to run
```bash
./run_configure_host.py --config config/host_config_example.yaml   --validation config/host_config_validation.yaml
```
You can omit `--validation` to use the default schema.

## Step-by-step
1. Validate configuration against schema.
2. Connect to Proxmox host via SSH.
3. Compare and optionally change hostname (reboot if configured).
4. Configure repositories: enable no-subscription, disable enterprise & ceph.
5. Apply GUI patch for no-subscription.
6. Download ISO files to specified path.
7. Close SSH connection.

## Required config keys
| Key | Type | Constraints | Default |
| --- | ---- | ----------- | ------- |
| `host_ip` | string | Regex: `^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$` |  |
| `hostname` | string | Regex: `^[a-zA-Z0-9][a-zA-Z0-9-]{0,62}$` |  |

## Optional config keys
| Key | Type | Constraints | Default |
| --- | ---- | ----------- | ------- |
| `host_username` | string | Regex: `^[a-z_][a-z0-9_-]{0,31}$` | root |
| `domain` | string | Regex: `^[a-zA-Z0-9][a-zA-Z0-9-]{0,62}\.[a-zA-Z]{2,}$` | your.domain |
| `sshkey_public` | list |  | ['public key', 'public key'] |
| `iso_urls` | list |  | ['https://cloud-images.ubuntu.com/noble/current/noble-server-cloudimg-amd64.img', 'https://releases.ubuntu.com/24.04/ubuntu-24.04.2-live-server-amd64.iso'] |
| `iso_path` | string | Regex: `^\/([a-zA-Z0-9._+-]+\/)*[a-zA-Z0-9._+-]+$` | /var/lib/vz/template/iso |
| `host_change_pwd` | boolean | Regex: `^(true|false)$` | False |
| `host_keyfile` | string | Regex: `^/home/[a-z_][a-z0-9_-]{0,31}/\.ssh/.*$` | /path/to/.ssh/keyfile |
| `host_reboot` | boolean | Regex: `^(true|false)$` | False |
| `host_file` | string | Regex: `^\/([a-zA-Z0-9._+-]+\/)*[a-zA-Z0-9._+-]+$` | /etc/hosts |
| `sshd_searchstring` | string | Regex: `^[^\n\r]{1,512}$` | include |
| `sshd_config_path` | string | Regex: `^(/[^/\0]+)+/?$` | /etc/ssh/sshd_config |
| `sshd_custom_config` | string | Regex: `^(/[^/\0]+)+/?$` | /etc/ssh/sshd_config.d/99-custom.conf |
| `ssh_PermitRootLogin` | string | Regex: `(?i)^(yes|no|without-password|forced-commands-only)$` | without-password |
| `ssh_PasswordAuthentication` | string | Regex: `(?i)^(yes|no)$` | no |
| `ssh_PermitEmptyPasswords` | string | Regex: `(?i)^(yes|no)$` | no |
| `ssh_UseDNS` | string | Regex: `(?i)^(yes|no)$` | no |
| `ssh_AllowTcpForwarding` | string | Regex: `(?i)^(yes|no)$` | no |
| `ssh_X11Forwarding` | string | Regex: `(?i)^(yes|no)$` | no |
| `ssh_ClientAliveInterval` | integer |  | 300 |
| `ssh_ClientAliveCountMax` | integer |  | 2 |
| `ssh_MaxAuthTries` | integer |  | 3 |
| `ssh_MaxSessions` | integer |  | 2 |
| `ssh_Compression` | string | Regex: `(?i)^(yes|no|delayed)$` | no |
| `ssh_LogLevel` | string | Regex: `(?i)^(QUIET|FATAL|ERROR|INFO|VERBOSE|DEBUG|DEBUG1|DEBUG2|DEBUG3)$` | VERBOSE |
| `ssh_LoginGraceTime` | integer | min=1 | 30 |
| `ssh_Subsystem` | string |  | sftp /usr/lib/openssh/sftp-server |

**Example config:** [`config/host_config_example.yaml`](../config/host_config_example.yaml)