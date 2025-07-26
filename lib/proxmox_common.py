#!/usr/bin/env python3
from lib.ssh_handler import SSHConnection

class ProxmoxCommon:
    def __init__(
            self,
            host,
            username,
            password=None,
            key_filename=None,
        ):

        self.ssh = SSHConnection(host, username, password, key_filename)

    def test(self):
        print("OK")
