# Create virtual machine

This guide explains how to use the `create_guest.py` script to create a virtual machine from a template on Proxmox.

 The script clone a guest VM from a template and configure it with cloud-init and optional SSH/server settings. This script also checks and adjusts `sshd` configuration to match settings in your config file, and ensuring that the guest is ready for further automation, e.g., provisioning with **Ansible**.

---

## How to run
```bash
./run_create_guest.py --config config/guest_config_example.yaml --validation config/guest_config_validation.yaml
```
You can omit `--validation` to use the default schema.

Optional override for validation rules:
```
./run_create_guest.py --config config/guest_config_example.yaml --validation config/custom_guest_validation.yaml

```

## Step-by-step
1. Validate configuration against schema.
2. Connect to Proxmox host via SSH.
3. Clone from template (`clone_id`) or ensure VM exists.
4. Apply cloud-init user/password, SSH keys, DNS, hostname/domain.
5. Configure network (DHCP or static).
6. Set resources (cores, memory, ballooning) and on-boot.
7. Ensure cloud-init drive is present and attached to correct storage.
8. Start the VM and verify status.
   Scan the subnet for the ip-address, if network set to DHCP
9. Connects to the VM via SSH
10. Close SSH connection to the Proxmomx host.
11. Ensures the desired SSHD config is set on the VM
12. Installs the QEMU-client-agent
13. Changes the rott password
14. Reboot the vm

## Config File Structure

YAML file must contain only populated values. Do not include unused or empty keys.
There are two YAML files used for the configuration:
1. The template config file - [guest_config_example](https://github.com/PCH-ApS/proxmox/blob/main/config/guest_config_example.yaml)
2. The config validation file - [guest_config_validation](https://github.com/PCH-ApS/proxmox/blob/main/config/guest_config_validation.yaml)

The validation file also contains default values for non-required keys. This mean that when you have set all your defaults in the file, you can configure a virtual machine with only the name, id,  clone_id and vlan in the config file.

## Required config keys
| Key        | Type    | Constraints                              | Default |
| ---------- | ------- | ---------------------------------------- | ------- |
| `name`     | string  | Regex: `^[a-zA-Z0-9][a-zA-Z0-9-]{0,62}$` |         |
| `id`       | integer | min=100; max=999999999                   |         |
| `clone_id` | integer | min=100; max=999999999                   |         |
| `vlan`     | integer | min=2; max=4094                          |         |

## Optional config keys
| Key                          | Type    | Constraints                                                                            | Default                           |                                   |                         |                     |             |         |          |           |          |       |         |        |            |        |
| ---------------------------- | ------- | -------------------------------------------------------------------------------------- | --------------------------------- | --------------------------------- | ----------------------- | ------------------- | ----------- | ------- | -------- | --------- | -------- | ----- | ------- | ------ | ---------- | ------ |
| `host_username`              | string  | Regex: `^[a-z_][a-z0-9_-]{0,31}$`                                                      | root                              |                                   |                         |                     |             |         |          |           |          |       |         |        |            |        |
| `host_keyfile`               | string  | Regex: `^/home/[a-z_][a-z0-9_-]{0,31}/\.ssh/.*$`                                       | 'your/path/to/PVE/keyfile'        |                                   |                         |                     |             |         |          |           |          |       |         |        |            |        |
| `host_ip`                    | string  | Regex: `^(?:(?:25[0-5]                                                                 | 2[0-4][0-9]                       | [01]?[0-9][0-9]?)\.){3}(?:25[0-5] | 2[0-4][0-9]             | [01]?[0-9][0-9]?)$` | 192.168.6.3 |         |          |           |          |       |         |        |            |        |
| `cores`                      | integer | min=1; max=4                                                                           | 1                                 |                                   |                         |                     |             |         |          |           |          |       |         |        |            |        |
| `memory`                     | integer | min=256; max=8192                                                                      | 2048                              |                                   |                         |                     |             |         |          |           |          |       |         |        |            |        |
| `disk`                       | integer | min=4; max=1024                                                                        | 8                                 |                                   |                         |                     |             |         |          |           |          |       |         |        |            |        |
| `driver`                     | string  | Regex: `^(e1000                                                                        | e1000-82540em                     | e1000-82544gc                     | e1000-82545em           | e1000e              | i82551      | i82557b | i82559er | ne2k_isa  | ne2k_pci | pcnet | rtl8139 | virtio | vmxnet3)$` | virtio |
| `bridge`                     | string  | Regex: `^[A-Za-z][A-Za-z0-9_.:-]{0,14}$`                                               | vmbr0                             |                                   |                         |                     |             |         |          |           |          |       |         |        |            |        |
| `balloon`                    | integer | min=256; max=8192                                                                      | 512                               |                                   |                         |                     |             |         |          |           |          |       |         |        |            |        |
| `boot_start`                 | boolean |                                                                                        | True                              |                                   |                         |                     |             |         |          |           |          |       |         |        |            |        |
| `ci_upgrade`                 | boolean |                                                                                        | True                              |                                   |                         |                     |             |         |          |           |          |       |         |        |            |        |
| `ci_username`                | string  | Regex: `^[a-z_][a-z0-9_-]{0,31}$`                                                      | your preferred username           |                                   |                         |                     |             |         |          |           |          |       |         |        |            |        |
| `ci_password`                | string  | Regex: `^[\x20-\x7E]{8,128}$`; minlen=8                                                | password                          |                                   |                         |                     |             |         |          |           |          |       |         |        |            |        |
| `change_pwd`                 | boolean |                                                                                        | True                              |                                   |                         |                     |             |         |          |           |          |       |         |        |            |        |
| `ci_publickey`               | list    |                                                                                        | your preferred ssh publickeys     |                                   |                         |                     |             |         |          |           |          |       |         |        |            |        |
| `ci_domain`                  | string  | Regex: `^(?=.{1,253}$)([A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+[A-Za-z]{2,}$` | your_domain.com                   |                                   |                         |                     |             |         |          |           |          |       |         |        |            |        |
| `ci_dns_server`              | string  | Regex: `^(?:(?:25[0-5]                                                                 | 2[0-4][0-9]                       | [01]?[0-9][0-9]?)\.){3}(?:25[0-5] | 2[0-4][0-9]             | [01]?[0-9][0-9]?)$` | 192.168.9.5 |         |          |           |          |       |         |        |            |        |
| `ci_ipaddress`               | string  | Regex: `^(?:(?:25[0-5]                                                                 | 2[0-4][0-9]                       | [01]?[0-9][0-9]?)\.){3}(?:25[0-5] | 2[0-4][0-9]             | [01]?[0-9][0-9]?)$` |             |         |          |           |          |       |         |        |            |        |
| `ci_gateway`                 | string  | Regex: `^(?:(?:25[0-5]                                                                 | 2[0-4][0-9]                       | [01]?[0-9][0-9]?)\.){3}(?:25[0-5] | 2[0-4][0-9]             | [01]?[0-9][0-9]?)$` |             |         |          |           |          |       |         |        |            |        |
| `ci_netmask`                 | string  | Regex: `^/(?:[0-9]                                                                     | [12][0-9]                         | 3[0-2])$`                         |                         |                     |             |         |          |           |          |       |         |        |            |        |
| `ci_network`                 | string  | Regex: `^(?i)(dhcp                                                                     | static)$`                         | dhcp                              |                         |                     |             |         |          |           |          |       |         |        |            |        |
| `ip_prefix`                  | string  | Regex: `^(?:25[0-5]                                                                    | 2[0-4]\d                          | 1?\d?\d)\.(?:25[0-5]              | 2[0-4]\d                | 1?\d?\d)\.?$`       | 192.168     |         |          |           |          |       |         |        |            |        |
| `ssh_PermitRootLogin`        | string  | Regex: `(?i)^(yes                                                                      | no                                | without-password                  | forced-commands-only)$` | without-password    |             |         |          |           |          |       |         |        |            |        |
| `ssh_PasswordAuthentication` | string  | Regex: `(?i)^(yes                                                                      | no)$`                             | no                                |                         |                     |             |         |          |           |          |       |         |        |            |        |
| `ssh_PermitEmptyPasswords`   | string  | Regex: `(?i)^(yes                                                                      | no)$`                             | no                                |                         |                     |             |         |          |           |          |       |         |        |            |        |
| `ssh_UseDNS`                 | string  | Regex: `(?i)^(yes                                                                      | no)$`                             | no                                |                         |                     |             |         |          |           |          |       |         |        |            |        |
| `ssh_AllowTcpForwarding`     | string  | Regex: `(?i)^(yes                                                                      | no)$`                             | no                                |                         |                     |             |         |          |           |          |       |         |        |            |        |
| `ssh_X11Forwarding`          | string  | Regex: `(?i)^(yes                                                                      | no)$`                             | no                                |                         |                     |             |         |          |           |          |       |         |        |            |        |
| `ssh_ClientAliveInterval`    | integer |                                                                                        | 300                               |                                   |                         |                     |             |         |          |           |          |       |         |        |            |        |
| `ssh_ClientAliveCountMax`    | integer |                                                                                        | 2                                 |                                   |                         |                     |             |         |          |           |          |       |         |        |            |        |
| `ssh_MaxAuthTries`           | integer |                                                                                        | 3                                 |                                   |                         |                     |             |         |          |           |          |       |         |        |            |        |
| `ssh_MaxSessions`            | integer |                                                                                        | 2                                 |                                   |                         |                     |             |         |          |           |          |       |         |        |            |        |
| `ssh_Compression`            | string  | Regex: `(?i)^(yes                                                                      | no                                | delayed)$`                        | no                      |                     |             |         |          |           |          |       |         |        |            |        |
| `ssh_LogLevel`               | string  | Regex: `(?i)^(QUIET                                                                    | FATAL                             | ERROR                             | INFO                    | VERBOSE             | DEBUG       | DEBUG1  | DEBUG2   | DEBUG3)$` | VERBOSE  |       |         |        |            |        |
| `ssh_LoginGraceTime`         | integer | min=1                                                                                  | 30                                |                                   |                         |                     |             |         |          |           |          |       |         |        |            |        |
| `ssh_Subsystem`              | string  |                                                                                        | sftp /usr/lib/openssh/sftp-server |                                   |                         |                     |             |         |          |           |          |       |         |        |            |        |

