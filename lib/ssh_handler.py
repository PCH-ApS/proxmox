#!/usr/bin/env python3
import paramiko


class SSHConnection:

    def __init__(self, host, username, password=None, key_filename=None):
        self.host = host
        self.username = username
        self.password = password
        self.key_filename = key_filename
        self.ssh = None

    def connect(self):
        try:
            self.ssh = paramiko.SSHClient()
            self.ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())

            self.ssh.connect(
                hostname=self.host,
                username=self.username,
                password=self.password,
                key_filename=self.key_filename
            )

            return True, f"Connected to {self.host} as {self.username}"

        except paramiko.AuthenticationException:
            return False, (
                f"Authentication failed for {self.username}@{self.host}"
            )

        except paramiko.SSHException as e:
            return False, f"SSH error on {self.host}: {e}"

        except Exception as e:
            return False, f"Unexpected error: {e}"

    def run(self, command):
        if not self.ssh:
            raise RuntimeError("SSH connection not established")

        stdin, stdout, stderr = self.ssh.exec_command(command)
        return {
            "stdout": stdout.read().decode(),
            "stderr": stderr.read().decode(),
            "exit_code": stdout.channel.recv_exit_status()
        }

    def close(self):
        if self.ssh:
            self.ssh.close()
        return True, f"Closed connection to {self.host} as {self.username}"
