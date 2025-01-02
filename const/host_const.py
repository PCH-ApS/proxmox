MANDATORY_KEYS = {
    "username",
    "host_ip",
    "hostname",
    "domain_string",
    "publickey"
}

OPTIONAL_KEYS = {
    "urls",
    "change_pwd"
}
INTEGER_KEYS = []

DEFAULT_URLS = [
    (
      "https://cloud-images.ubuntu.com/noble/current/"
      "noble-server-cloudimg-amd64.img"
    ),
    "https://releases.ubuntu.com/24.04/ubuntu-24.04.1-live-server-amd64.iso"
    ]
DEFAULT_CHANGE_PWD = False

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
PVE_KEYFILE = "/home/nije/.ssh/infrastructure/proxmox-root"
SNIPPETS_FOLDER = "/var/lib/vz/snippets"
