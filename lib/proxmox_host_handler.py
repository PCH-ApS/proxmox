#!/usr/bin/env python3
from lib.ssh_handler import SSHConnection
from lib.output_handler import OutputHandler
import shlex
import re
import time
import socket


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
        self.Output = OutputHandler()

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
        empty_message = self.ssh.run(command)
        if empty_message['exit_code'] != 0:
            return False, empty_message['stderr']
        else:
            if len(empty_message['stdout'].strip()) == 0:
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
            default_folders,
            host_reboot
            ):

        host_output = []

        correct_flag, correct_message, current_hostname = (
            self.is_hostname_correct(new_hostname)
        )
        if correct_flag:
            host_output.append((True, f"{correct_message}"))
            return host_output[0][1]
        else:
            host_output.append((False, f"{correct_message}"))

        all_empty = True
        for folderpath in default_folders:
            folder_flag, folder_message = self.is_folder_empty(folderpath)
            if not folder_flag:
                all_empty = False
                host_output.append((False, f"{folder_message}: {folderpath}"))
            else:
                host_output.append((True, f"{folder_message}: {folderpath}"))

        if not all_empty:
            return host_output

        add_flag, add_message = self.add_to_file(
                content=(
                    f"{ip_address} "
                    f"{new_hostname}.{domain} "
                    f"{new_hostname}"
                    ),
                file_path=hostfile
            )
        if not add_flag:
            host_output.append((False, f"{add_message}"))
            return host_output

        host_output.append((True, f"{add_message}"))

        remove_flag, remove_message = self.remove_line_with_content(
            content=(
                f"{ip_address} "
                f"{current_hostname}.{domain} "
                f"{current_hostname}"
            ),
            file_path=hostfile
        )
        if not remove_flag:
            host_output.append((False, f"{remove_message}"))
            return host_output

        host_output.append((True, f"{remove_message}"))

        set_flag, set_message = self.set_hostname(new_hostname)
        if not set_flag:
            host_output.append((False, f"{set_message}"))
            return host_output

        host_output.append((True, f"{set_message}"))

        for host_line in host_output:
            self.Output.output(host_line[1], type="s" if host_line[0] else "e")

        if host_reboot:
            reboot_flag, reboot_message = (
                self.reboot_and_reconnect(wait_time=10, timeout=180)
                )
            self.Output.output(
                f"{reboot_message}",
                type="s" if reboot_flag else "e"
            )
        else:
            self.Output.output(
                (True, "Reboot flag set to NOT reboot Proxmox host"))

        return "Change hostname - done"

    def reboot_and_reconnect(self, wait_time=10, timeout=180):
        result = self.ssh.run("reboot")
        if result['exit_code'] != 0:
            return False, "Failed to send reboot command"

        self.ssh.close()

        self.Output.output("Waiting for host to reboot...", "i")
        time.sleep(wait_time)

        start_time = time.time()
        while time.time() - start_time < timeout:
            try:
                # Try to open a raw socket to port 22
                sock = socket.create_connection((self.host, 22), timeout=5)
                sock.close()

                # 4. Try reconnecting via SSH
                self.Output.output(
                    "SSH port is open, trying to reconnect...", "i"
                    )
                success, message = self.ssh.connect()
                if success:
                    return True, "Reconnected successfully after reboot"
            except (OSError, socket.error):
                pass

            time.sleep(5)

        return False, f"Failed to reconnect within {timeout} seconds"
