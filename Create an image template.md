This guide explains how to use the `create_template.py` script to create a reusable VM template on a Proxmox host using a cloud image.

## Purpose

Automate creation of a Proxmox VM template based on a downloaded `.img` image, so that virtual machines can easily be cloned by the `create_guest.py` script

Make sure the host has been configured. See:  
Proxmox host configuration

## Usage
**The create template script is called from /run_create_template.py**

```
./run_create_template.py --config config/host_template.yaml

```

Optional override for validation rules:
```
./run_create_template.py --config config/host_template.yaml --validation config/custom_validation.yaml
```
If no --validation file is provided, default is: `config/template_config_validation.yaml`
## Config File Structure

YAML file must contain only populated values. Do not include unused or empty keys.

Example:
```
tmp_name: ubuntu-22-template
tmp_id: 9001
tmp_image_path: /var/lib/vz/template/iso/ubuntu-server.img
tmp_host_ip: 192.168.100.10
tmp_host_username: root
tmp_host_keyfile: /home/user/.ssh/id_ed25519
tmp_cpu: host
tmp_cores: 2
tmp_memory: 2048
tmp_storage_ctrl: virtio-scsi-pci
tmp_bootdisk: scsi0
tmp_local_storage: local-lvm
tmp_network_ctrl: virtio
tmp_bridge: vmbr0
```

Config keys that are not requred in config file, will be set to default values from the validation yaml file.

**The required keys are:**
* tmp_name: 
* tmp_id: 
* tmp_image_path:

The rest of the keys can be filled with default values, that can be set up in the validation yaml file.

### ### Example Validation Rules

See `host_config_validation_example.yaml` for field-by-field schema with regex, defaults, and optional/required flags.

This table reflects what's enforced by `template_config_validation.yaml`:

| Key                 | Required | Default           | Notes                                |
| ------------------- | -------- | ----------------- | ------------------------------------ |
| `tmp_name`          | ✅        | —                 | Template name (hostname-safe)        |
| `tmp_id`            | ✅        | —                 | VMID (unique integer)                |
| `tmp_image_path`    | ✅        | —                 | Full path to the `.img` cloud image  |
| `tmp_cpu`           | ❌        | `host`            | Can also be `custom-<name>`          |
| `tmp_cores`         | ❌        | 1                 | Number of virtual CPUs               |
| `tmp_memory`        | ❌        | 512               | Memory in MB                         |
| `tmp_storage_ctrl`  | ❌        | `virtio-scsi-pci` | See validation file for all options  |
| `tmp_bootdisk`      | ❌        | `scsi0`           | e.g., `scsi0`, `sata0`, `virtio0`    |
| `tmp_local_storage` | ❌        | `local-zfs`       | Storage ID used for disk and image   |
| `tmp_network_ctrl`  | ❌        | `virtio`          | NIC model (e.g., `e1000`, `vmxnet3`) |
| `tmp_bridge`        | ❌        | `vmbr0`           | Proxmox bridge interface             |

## Logs

All script output is by default logged in: logs/create_template.log
and in terminal.