# Proxmox host configuration
This guide outlines how to use the `configure_host.py` script to create the desired Proxmox host configuration with at script that I can run as many times as I like, checking the initial config is correct.

Once configured, continue to [Create an image template](https://github.com/PCH-ApS/proxmox/blob/main/md/Create%20an%20image%20template.md)

## How to run
```bash
./run_configure_host.py --config config/host_config_example.yaml --validation config/host_config_validation.yaml
```
You can omit `--validation` to use the default schema.

Optional override for validation rules:
```
./run_configure_host.py --config config/host_config.yaml --validation config/custom_validation.yaml
```

## Step-by-step
1. Validate configuration against schema.
2. Connect to Proxmox host via SSH.
3. Compare and optionally change hostname (reboot if configured).
4. Checks and harden (if needed) the sshd configuration.
5. Configure repositories: enable no-subscription, disable enterprise & ceph.
6. Apply GUI patch for no-subscription.
7. Download ISO files to specified path.
8. Close SSH connection.

## Requirements

- cerberus is required for validating config files.
  if not installed, add it with:
```
pip3 install cerberus
````

## Config File Structure

YAML file must contain only populated values. Do not include unused or empty keys.
There are two YAML files used for the configuration:
1. The host config file - [host_config_example](https://github.com/PCH-ApS/proxmox/blob/main/config/host_config_example.yaml)
2. The config validation file - [host_config_validation](https://github.com/PCH-ApS/proxmox/blob/main/config/host_config_validation.yaml)

The validation file also contains default values for non-required keys. This mean that when you have set all your defaults in the file, you can configure a host with only the ip-address and the hostname in the config file.

## Required config keys
| Key | Type | Constraints | Default |
| --- | ---- | ----------- | ------- |
| `host_ip` | string | Regex: `^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$` |  |
| `hostname` | string | Regex: `^[a-zA-Z0-9][a-zA-Z0-9-]{0,62}$` |  |

## Optional config keys
| Key                          | Type    | Constraints                                            | Default                                                                                                                                                     |                  |                         |                  |       |        |        |           |         |
| ---------------------------- | ------- | ------------------------------------------------------ | ----------------------------------------------------------------------------------------------------------------------------------------------------------- | ---------------- | ----------------------- | ---------------- | ----- | ------ | ------ | --------- | ------- |
| `host_username`              | string  | Regex: `^[a-z_][a-z0-9_-]{0,31}$`                      | root                                                                                                                                                        |                  |                         |                  |       |        |        |           |         |
| `domain`                     | string  | Regex: `^[a-zA-Z0-9][a-zA-Z0-9-]{0,62}\.[a-zA-Z]{2,}$` | your.domain                                                                                                                                                 |                  |                         |                  |       |        |        |           |         |
| `sshkey_public`              | list    |                                                        | ['public key', 'public key']                                                                                                                                |                  |                         |                  |       |        |        |           |         |
| `iso_urls`                   | list    |                                                        | ['https://cloud-images.ubuntu.com/noble/current/noble-server-cloudimg-amd64.img', 'https://releases.ubuntu.com/24.04/ubuntu-24.04.2-live-server-amd64.iso'] |                  |                         |                  |       |        |        |           |         |
| `iso_path`                   | string  | Regex: `^\/([a-zA-Z0-9._+-]+\/)*[a-zA-Z0-9._+-]+$`     | /var/lib/vz/template/iso                                                                                                                                    |                  |                         |                  |       |        |        |           |         |
| `host_change_pwd`            | boolean | Regex: `^(true                                         | false)$`                                                                                                                                                    | False            |                         |                  |       |        |        |           |         |
| `host_keyfile`               | string  | Regex: `^/home/[a-z_][a-z0-9_-]{0,31}/\.ssh/.*$`       | /path/to/.ssh/keyfile                                                                                                                                       |                  |                         |                  |       |        |        |           |         |
| `host_reboot`                | boolean | Regex: `^(true                                         | false)$`                                                                                                                                                    | False            |                         |                  |       |        |        |           |         |
| `host_file`                  | string  | Regex: `^\/([a-zA-Z0-9._+-]+\/)*[a-zA-Z0-9._+-]+$`     | /etc/hosts                                                                                                                                                  |                  |                         |                  |       |        |        |           |         |
| `sshd_searchstring`          | string  | Regex: `^[^\n\r]{1,512}$`                              | include                                                                                                                                                     |                  |                         |                  |       |        |        |           |         |
| `sshd_config_path`           | string  | Regex: `^(/[^/\0]+)+/?$`                               | /etc/ssh/sshd_config                                                                                                                                        |                  |                         |                  |       |        |        |           |         |
| `sshd_custom_config`         | string  | Regex: `^(/[^/\0]+)+/?$`                               | /etc/ssh/sshd_config.d/99-custom.conf                                                                                                                       |                  |                         |                  |       |        |        |           |         |
| `ssh_PermitRootLogin`        | string  | Regex: `(?i)^(yes                                      | no                                                                                                                                                          | without-password | forced-commands-only)$` | without-password |       |        |        |           |         |
| `ssh_PasswordAuthentication` | string  | Regex: `(?i)^(yes                                      | no)$`                                                                                                                                                       | no               |                         |                  |       |        |        |           |         |
| `ssh_PermitEmptyPasswords`   | string  | Regex: `(?i)^(yes                                      | no)$`                                                                                                                                                       | no               |                         |                  |       |        |        |           |         |
| `ssh_UseDNS`                 | string  | Regex: `(?i)^(yes                                      | no)$`                                                                                                                                                       | no               |                         |                  |       |        |        |           |         |
| `ssh_AllowTcpForwarding`     | string  | Regex: `(?i)^(yes                                      | no)$`                                                                                                                                                       | no               |                         |                  |       |        |        |           |         |
| `ssh_X11Forwarding`          | string  | Regex: `(?i)^(yes                                      | no)$`                                                                                                                                                       | no               |                         |                  |       |        |        |           |         |
| `ssh_ClientAliveInterval`    | integer |                                                        | 300                                                                                                                                                         |                  |                         |                  |       |        |        |           |         |
| `ssh_ClientAliveCountMax`    | integer |                                                        | 2                                                                                                                                                           |                  |                         |                  |       |        |        |           |         |
| `ssh_MaxAuthTries`           | integer |                                                        | 3                                                                                                                                                           |                  |                         |                  |       |        |        |           |         |
| `ssh_MaxSessions`            | integer |                                                        | 2                                                                                                                                                           |                  |                         |                  |       |        |        |           |         |
| `ssh_Compression`            | string  | Regex: `(?i)^(yes                                      | no                                                                                                                                                          | delayed)$`       | no                      |                  |       |        |        |           |         |
| `ssh_LogLevel`               | string  | Regex: `(?i)^(QUIET                                    | FATAL                                                                                                                                                       | ERROR            | INFO                    | VERBOSE          | DEBUG | DEBUG1 | DEBUG2 | DEBUG3)$` | VERBOSE |
| `ssh_LoginGraceTime`         | integer | min=1                                                  | 30                                                                                                                                                          |                  |                         |                  |       |        |        |           |         |
| `ssh_Subsystem`              | string  |                                                        | sftp /usr/lib/openssh/sftp-server                                                                                                                           |                  |                         |                  |       |        |        |           |         |


## Logs

All script output is by default logged in: logs/configure_host.log
and in terminal.

## Tips

- Test your SSH connection to the host before running the script.
- Use `ssh-copy-id` to pre-load your public key for the user specified in the config.
- Make sure Proxmox VE is installed and reachable via SSH.

## What the script does!

### File Validation

- Ensures YAML config and schema files exist, are readable, and are `.yaml` or `.yml`.

### Config Validation

- Uses Cerberus schema (`host_config_validation.yaml`) to enforce types, defaults, and regex rules.

### Establishes a SSH connection to  the host 

### Hostname Handling

- Verifies current hostname, and if it is not correct, it will try to change it.
- Validates default config folders are empty before renaming.
- Updates `/etc/hosts` and uses `hostnamectl` to apply changes.
- If the hostname changes and `pve_host_reboot: true`, the host will be rebooted and SSH connection re-established.

### SSHD Configuration

- Checks and hardens `sshd_config`.
- Missing parameters are added to a custom config file, and included in the sshd_config
- Incorrect parameters are commented out where they are found, and then the correct parameter is added to the custom config file.
- Reloads SSHD service if changes were made.    

The desired sshd config is part of the `host_config_validation.yaml file or config file, so desired config can be controlled within the config files, and reapplied is needed.

### SSH Key Handling

- Ensures proper permissions on `.ssh` and `authorized_keys`.
- Adds missing keys listed in the config file, to ensure the desired keys are configured on the host for access

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