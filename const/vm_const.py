# const/constants.py
MANDATORY_KEYS = {
    "clone_id",
    "name",
    "id",
    "vlan"
    }

OPTIONAL_KEYS = {
    "username",
    "host_ip",
    "cores",
    "memory",
    "disk",
    "driver",
    "bridge",
    "balloon",
    "boot_start",
    "ci_upgrade",
    "ci_username",
    "ci_password",
    "ci_publickey",
    "ci_domain",
    "ci_dns_server",
    "ci_ipaddress",
    "ci_gwadvalue",
    "ci_netmask",
    "ci_network",
    "change_pwd"
    }

INTEGER_KEYS = ["clone_id", "vlan", "id", "cores", "memory", "disk", "balloon",
                "boot_start", "ci_netmask"
                ]

SSH_CONST = {
    "PasswordAuthentication": "no",
    "ChallengeResponseAuthentication": "no",
    "PermitEmptyPasswords": "no",
    "ClientAliveInterval": "3600",
    "ClientAliveCountMax": "2",
    "X11Forwarding": "no",
    "PermitRootLogin": "prohibit-password"
    }

SSHD_CONFIG = [
    "/etc/ssh/sshd_config"
    ]

SSHD_SEARCHSTRING = "Include "
SSHD_CUSTOMFILE = "/99-automation-default-config.conf"
DEFAULT_USERNAME = "root"
DEFAULT_HOST_IP = "192.168.6.3"
DEFAULT_CORES = 4
DEFAULT_MEMORY = 2048
DEFAULT_DISK = 8
DEFAULT_DRIVER = "virtio"
DEFAULT_BRIDGE = "vmbr0"
DEFAULT_BALLOON = 512
DEFAULT_BOOT_START = 0
DEFAULT_CI_UPGRADE = 1
DEFAULT_CI_USERNAME = "pch"
DEFAULT_CI_PASSWORD = "password"
DEFAULT_CI_PUBLICKEY = [
    (
        "ssh-ed25519 "
        "AAAAC3NzaC1lZDI1NTE5AAAAIIEnQDipaxA3UXONu83gW17HAsde/DtYeNxC+Uif9YcK "
        "ansible-automation"
    ),
    (
        "ssh-ed25519 "
        "AAAAC3NzaC1lZDI1NTE5AAAAILdNDjsqywS/4LcaCg35c+QE9V2vQ4VVfXsPVJVi6Dj6 "
        "nije-key"
    )
]
DEFAULT_CI_DOMAIN = "pch.dk"
DEFAULT_CI_DNS_SERVER = "192.168.9.5"
DEFAULT_CI_NETWORK = "dhcp"
DEFAULT_CHANGE_PWD = False
DEFAULT_NIC = "eth0"
DEFAULT_PREFIX = "192.168."
PVE_KEYFILE = "/home/nije/.ssh/infrastructure/proxmox-root"
VM_KEYFILE = "/home/nije/.ssh/nije-key"
