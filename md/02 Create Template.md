# Create Template

Create a minimal template VM on a Proxmox host.  
Validates inputs, creates VM, attaches disk and network, and converts to template.


## How to run
```bash
./run_create_template.py --config config/template_config_example.yaml   --validation config/template_config_validation.yaml
```

## Step-by-step
1. Validate configuration against schema.
2. Connect to Proxmox host via SSH.
3. Check storage controller, network bridge, and VMID availability.
4. Create VM with CPU, cores, memory, and networking as configured.
5. Import disk image, set bootdisk, and resize if configured.
6. Configure console/display settings.
7. Convert VM to template.
8. Close SSH connection.

## Required config keys
| Key | Type | Constraints | Default |
| --- | ---- | ----------- | ------- |
| `name` | string | Regex: `^(?=.{1,63}$)[A-Za-z0-9](?:[A-Za-z0-9-]*[A-Za-z0-9])?$` |  |
| `id` | integer | min=100; max=999999999 |  |
| `image_path` | string | Regex: `^\/([a-zA-Z0-9._+-]+\/)*[a-zA-Z0-9._+-]+$` |  |

## Optional config keys
| Key | Type | Constraints | Default |
| --- | ---- | ----------- | ------- |
| `host_username` | string | Regex: `^[a-z_][a-z0-9_-]{0,31}$` | root |
| `host_keyfile` | string | Regex: `^/home/[a-z_][a-z0-9_-]{0,31}/\.ssh/.*$` | <Your ssh keyfile path goes here> |
| `host_ip` | string | Regex: `^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$` | <Your PVE host ip goes here> |
| `cpu` | string | Regex: `^(host|custom-[A-Za-z0-9][A-Za-z0-9._-]*|[A-Za-z0-9][A-Za-z0-9._-]*)$` | host |
| `cores` | integer | min=1; max=4 | 1 |
| `memory` | integer | min=256; max=8192 | 512 |
| `storage_ctrl` | string | Regex: `^(lsi|lsi53c810|megasas|pvscsi|virtio-scsi-pci|virtio-scsi-single)$` | virtio-scsi-pci |
| `bootdisk` | string | Regex: `^(?:ide[0-3]|sata[0-5]|scsi(?:[0-9]|[12][0-9]|30)|virtio(?:[0-9]|1[0-5]))$` | scsi0 |
| `local_storage` | string | Regex: `^[a-z][a-z0-9_-]{0,31}$` | local-zfs |
| `network_ctrl` | string | Regex: `^(e1000|e1000-82540em|e1000-82544gc|e1000-82545em|e1000e|i82551|i82557b|i82559er|ne2k_isa|ne2k_pci|pcnet|rtl8139|virtio|vmxnet3)$` | virtio |
| `bridge` | string | Regex: `^[A-Za-z][A-Za-z0-9_.:-]{0,14}$` | vmbr0 |

**Example config:** [`config/template_config_example.yaml`](../config/template_config_example.yaml)