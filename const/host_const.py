MANDATORY_KEYS = {
    "PVE_USER": "username",
    "PVE_HOST": "host_ip",
    "PVE_NAME": "hostname",
    "PVE_DOMAIN": "domain_string",
    "PVE_SSHKEY": "publickey"
}
OPTIONAL_KEYS = {
    "PVE_ISO": "urls"
}
INTEGER_KEYS = []
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