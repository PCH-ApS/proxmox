# const/template_const.py
MANDATORY_KEYS = {
    "name",
    "id",
    "image"
}

OPTIONAL_KEYS = {
    "username",
    "host_ip",
    "cpu",
    "cores",
    "memory",
    "storage_ctrl",
    "local_storage",
    "bootdisk",
    "network_ctrl",
    "bridge",
    }

INTEGER_KEYS = ["id", "cores", "memory"
                ]

DEFAULT_USERNAME = "root"
DEFAULT_HOST_IP = "192.168.6.3"
DEFAULT_CPU = "host"
DEFAULT_CORES = 1
DEFAULT_MEMORY = 512
DEFAULT_STORAGE_CTRL = "virtio-scsi-pci"
DEFAULT_LOCAL_STORAGE = "local-zfs"
DEFAULT_BOOTDISK = "scsi0"
DEFAULT_NETWORK_CTRL = "virtio"
DEFAULT_BRIDGE = "vmbr0"

PVE_KEYFILE = "/home/nije/.ssh/infrastructure/proxmox-root"
