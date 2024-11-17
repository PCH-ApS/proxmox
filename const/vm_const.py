# const/constants.py
MANDATORY_KEYS = {
    "USER": "username",
    "HOST": "host_ip",
    "TEMPLATE": "clone_id",
    "ID": "id",
    "NAME": "name",
    "CORES": "cores",
    "MEM": "memory",
    "DISK": "disk",
    "NET_DRIVER": "driver",
    "BRIDGE": "bridge",
    "VLAN": "vlan",
    "CLOUDINIT_NET": "ci_network",
    "CLOUDINIT_UPGRADE": "ci_upgrade"
    }
OPTIONAL_KEYS = {
    "BALLOON": "balloon",
    "START_AT_BOOT": "boot_start",
    "CLOUDINIT_USER": "ci_username",
    "CLOUDINIT_PW": "ci_password",
    "CLOUDINIT_PUB_KEY": "ci_publickey",
    "CLOUDINIT_DNS_DOMAIN": "ci_domain",
    "CLOUDINIT_DNS_SERVER": "ci_dns_server",
    "CLOUDINIT_IP": "ci_ipaddress",
    "CLOUDINIT_GW": "ci_gwadvalue",
    "CLOUDINIT_MASK": "ci_netmask"
    }
INTEGER_KEYS = ["TEMPLATE", "ID", "CORES", "MEM", "VLAN",
                "CLOUDINIT_UPGRADE", "CLOUDINIT_MASK", "START_AT_BOOT",
                "BALLOON", "DISK"
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
DEFAULT_BALLOON = 0
DEFAULT_START_AT_BOOT = 0
DEFAULT_CI_UPGRADE = 1
DEFAULT_USER = "ubuntu"
DEFAULT_NIC = "eth0"
DEFAULT_PREFIX = "192.168."
PVE_KEYFILE = "/home/nije/.ssh/infrastructure/proxmox-root"
VM_KEYFILE = "/home/nije/.ssh/nije-key"