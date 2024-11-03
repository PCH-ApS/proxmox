# const/constants.py

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
SSHD_CUSTOMFILE = "/99-automation-default-config"