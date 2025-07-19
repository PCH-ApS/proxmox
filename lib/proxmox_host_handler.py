#!/usr/bin/env python3
from lib.ssh_handler import SSHConnection
import shlex
import re
# import time
# import paramiko


class ProxmoxHost:
    def __init__(
            self,
            host,
            username,
            password=None,
            key_filename=None,
            domain=None
            ):
        self.host = host
        self.username = username
        self.domain = domain
        self.ssh = SSHConnection(host, username, password, key_filename)

    def connect(self):
        success, message = self.ssh.connect()
        return success, message

    def close(self):
        success, message = self.ssh.close()
        return success, message

    def get_hostname(self):
        result = self.ssh.run("hostname")
        if not result['exit_code'] == 0:
            return False, result['stderr']
        else:
            return True, result['stdout'].strip('\n')

    def is_hostname_correct(self, desired_hostname):
        flag, current = self.get_hostname()
        if not flag:
            message = f"Failed to get current hostname: '{current}'"
            return False, message, current
        if current == desired_hostname:
            message = f"Current hostname is correct: '{current}'"
            return True, message, current
        else:
            message = (
                f"Current hostname '{current}' does not match "
                f"desired hostname '{desired_hostname}'"
            )
            return False, message, current

    def is_folder_empty(self, folder_path):
        command = f'ls -A {folder_path}'
        empty_messege = self.ssh.run(command)
        if empty_messege['exit_code'] != 0:
            return False, empty_messege['stderr']
        else:
            if len(empty_messege['stdout'].strip()) == 0:
                return True, "Folder is empty"
            else:
                return False, "Folder is not empty"

    def add_to_file(self, content, file_path):
        safe_content = shlex.quote(content)
        command = f'grep -Fxq {safe_content} {file_path}'
        result = self.ssh.run(command)
        if result['exit_code'] == 0:
            return True, f"{content} already exists in {file_path}"

        command = f'echo {safe_content} >> {file_path}'
        result = self.ssh.run(command)
        if result['exit_code'] != 0:
            return False, result['stderr']
        else:
            return True, f"{content} succesfully added to {file_path}"

    def remove_line_with_content(self, content, file_path):
        safe_content = re.escape(content)
        safe_content = safe_content.replace("/", r"\/")  # Escape / for sed
        command = f'sed -i "/{safe_content}/d" {file_path}'
        safe_content = content.replace("/", r"\/")
        command = f'sed -i "/{safe_content}/d" {file_path}'
        result = self.ssh.run(command)
        if result['exit_code'] != 0:
            return False, result['stderr']
        else:
            return True, (
                f"Line with content '{content}' "
                f"removed from {file_path}"
            )

    def set_hostname(self, new_hostname):
        command = f'hostnamectl set-hostname {new_hostname}'
        result = self.ssh.run(command)
        if result['exit_code'] != 0:
            return False, result['stderr']
        else:
            return (
                True,
                f"Hostname successfully changed to {new_hostname}"
            )

    def change_hostname(
            self,
            new_hostname,
            ip_address,
            domain,
            hostfile,
            default_folders
            ):

        host_output = []

        correct_flag, correct_messege, current_hostname = (
            self.is_hostname_correct(new_hostname)
        )
        if correct_flag:
            host_output.append((True, f"{correct_messege}"))
            return host_output
        else:
            host_output.append((False, f"{correct_messege}"))

        all_empty = True
        for folderpath in default_folders:
            folder_flag, folder_messege = self.is_folder_empty(folderpath)
            if not folder_flag:
                all_empty = False
                host_output.append((False, f"{folder_messege}: {folderpath}"))
            else:
                host_output.append((True, f"{folder_messege}: {folderpath}"))

        if not all_empty:
            return host_output

        add_flag, add_messege = self.add_to_file(
                content=(
                    f"{ip_address} "
                    f"{new_hostname}.{domain} "
                    f"{new_hostname}"
                    ),
                file_path=hostfile
            )
        if not add_flag:
            host_output.append((False, f"{add_messege}"))
            return host_output

        host_output.append((True, f"{add_messege}"))

        remove_flag, remove_messege = self.remove_line_with_content(
            content=(
                f"{ip_address} "
                f"{current_hostname}.{domain} "
                f"{current_hostname}"
            ),
            file_path=hostfile
        )
        if not remove_flag:
            host_output.append((False, f"{remove_messege}"))
            return host_output

        host_output.append((True, f"{remove_messege}"))

        set_flag, set_messege = self.set_hostname(new_hostname)
        if not set_flag:
            host_output.append((False, f"{set_messege}"))
            return host_output

        host_output.append((True, f"{set_messege}"))

        return host_output
