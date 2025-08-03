
This guide walks you through using the `create_guest.py` script to spin up a new VM instance from a pre-built template on a Proxmox host.

---

## Purpose

Automate the provisioning of a guest virtual machine on a Proxmox host from a template.

This includes:
- Cloning a template VM 
- Customizing resources (CPU, RAM, disk, network)
- Configuring cloud-init options
- Injecting SSH keys and static IPs
- Optionally starting the VM

## Requirements

- A pre-created template VM (`qm template`)  
    → Use `create_template.py`
- SSH access to the Proxmox host
- Cloud-init must be configured and supported by the template image
## Usage

**The create guest script is called from /run_create_guest.py**

```
./run_create_guest.py --config config/guest_config.yaml
```

Optional override for validation rules:
```
./run_create_guest.py --config config/guest_config.yaml --validation config/custom_validation.yaml
```

If no --validation file is provided, default is: `config/guest_config_validation.yaml`



