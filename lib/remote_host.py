"""Generic, reusable remote host operations over an
injected SSH-like transport.

This module defines:
- SSHLike: a structural protocol specifying the SSH API we rely on
- RemoteHost: a base class offering host-agnostic operations

Design goals
------------
- **Generic**: no dependency on a specific SSH implementation
- **Idempotent**: safe to re-run (e.g., authorized_keys management)
- **Typed**: modern Python type hints (3.12 style)
- **PEP 8**: naming, line length, docstrings

Usage
-----
from lib.ssh_handler import SSHConnection
from lib.remote_host import RemoteHost

ssh = SSHConnection(host, username, key_filename=keyfile)
remote = RemoteHost(ssh)
remote.connect()
remote.check_ssh_keys(["ssh-ed25519 AAAA... user@host"])
...
remote.close()
"""
from __future__ import annotations

from typing import Protocol
import shlex
import socket
import time
import re


class SSHLike(Protocol):
    """A minimal structural protocol for SSH clients we can work with."""

    host: str

    def connect(self) -> tuple[bool, str]:
        ...

    def close(self) -> tuple[bool, str]:
        ...

    def run(self, command: str) -> dict:
        """Execute command on the remote host.

        Expected return dict keys:
        - stdout: str
        - stderr: str
        - exit_code: int
        """
        ...


class RemoteHost:
    """Generic remote host operations implemented over an SSH-like client.

    The SSH transport is injected (dependency injection) to keep this class
    implementation-agnostic and easily testable.
    """

    def __init__(self, ssh_conn: SSHLike):
        self.ssh = ssh_conn

    # ---------------------------------------------------------------------
    # Lifecycle
    # ---------------------------------------------------------------------
    def connect(self) -> tuple[bool, str]:
        """Open the SSH connection."""
        return self.ssh.connect()

    def close(self) -> tuple[bool, str]:
        """Close the SSH connection."""
        return self.ssh.close()

    def run(self, command: str) -> dict:
        """Pass-through to the injected SSH client's run method."""
        return self.ssh.run(command)

    # ---------------------------------------------------------------------
    # Generic host operations
    # ---------------------------------------------------------------------

    def get_hostname(self) -> tuple[bool, str]:
        result = self.ssh.run("hostname")
        if result['exit_code'] != 0:
            return False, result['stderr']
        return True, result['stdout'].strip('\n')

    def add_to_file(self, content, file_path) -> tuple[bool, str]:
        safe_content = shlex.quote(content)
        safe_path = shlex.quote(file_path)
        command = f'grep -Fxq {safe_content} {safe_path}'
        exists = self.run(command)
        if exists["exit_code"] == 0:
            return True, f"{content} already exists in {safe_path}"

        command = f'echo {safe_content} >> {safe_path}'
        result = self.ssh.run(command)
        if result['exit_code'] != 0:
            return False, result['stderr']
        return True, f"{content} succesfully added to {file_path}"

    def remove_line_with_content(
            self,
            content: str,
            file_path: str
    ) -> tuple[bool, str]:
        safe_path = shlex.quote(file_path)
        safe_content = re.escape(content)
        command = f"sed -i '\\#{safe_content}#d' {safe_path}"
        result = self.run(command)
        if result['exit_code'] != 0:
            return False, result['stderr']
        return True, (
            f"Line with content '{content}' "
            f"removed from {file_path}"
        )

    @staticmethod
    def reboot_and_reconnect(
        ssh: SSHLike,
        wait_time: int = 10,
        timeout: int = 180,
        user="root"
    ) -> list[tuple[bool, str, str]]:
        """
        Reboots the host associated with the given SSH connection
        and waits until it becomes reachable again.

        Returns a list of (success_flag, message, level).
        """
        reboot_output: list[tuple[bool, str, str]] = []
        cmd = "reboot" if user == "root" else "sudo reboot"
        result = ssh.run(cmd)
        if result['exit_code'] != 0:
            reboot_output.append((False, "Failed to send reboot command", "e"))
            return reboot_output

        ssh.close()

        reboot_output.append((True, "Waiting for host to reboot...", "i"))
        time.sleep(wait_time)

        start_time = time.time()
        while time.time() - start_time < timeout:
            try:
                sock = socket.create_connection((ssh.host, 22), timeout=5)
                sock.close()

                reboot_output.append(
                    (True, "SSH port is open, trying to reconnect...", "i")
                )

                success, message = ssh.connect()
                reboot_output.append((
                    success,
                    message,
                    "s" if success else "e"
                ))

                if success:
                    return reboot_output

            except (OSError, socket.error):
                pass

            time.sleep(5)

        reboot_output.append((
            False,
            "Timed out waiting for SSH after reboot",
            "e"
        ))
        return reboot_output

    @staticmethod
    def reconnect(
        ssh: SSHLike,
        wait_time: int = 10,
        timeout: int = 180,
    ) -> list[tuple[bool, str, str]]:
        reconnect_output: list[tuple[bool, str, str]] = []
        reconnect_output.append(
            (True,
             "Waiting for server to come up...",
             "i"
             ))
        time.sleep(wait_time)

        start_time = time.time()
        while time.time() - start_time < timeout:
            try:
                sock = socket.create_connection((ssh.host, 22), timeout=5)
                sock.close()

                reconnect_output.append(
                    (True, "SSH port is open, trying to reconnect...", "i")
                )

                success, message = ssh.connect()
                reconnect_output.append((
                    success,
                    message,
                    "s" if success else "e"
                ))

                if success:
                    return reconnect_output

            except (OSError, socket.error):
                pass

            time.sleep(5)

        reconnect_output.append((
            False,
            "Timed out waiting for SSH to reconnect",
            "e"
        ))
        return reconnect_output

    def check_ssh_keys(
            self,
            ssh_keys: list[str]
    ) -> list[tuple[bool, str, str]]:
        keys_output: list[tuple[bool, str, str]] = []

        setup_commands = [
            "mkdir -p ~/.ssh",
            "chmod 700 ~/.ssh",
            "touch ~/.ssh/authorized_keys",
            "chmod 600 ~/.ssh/authorized_keys"
        ]

        for cmd in setup_commands:
            result = self.ssh.run(cmd)
            if result['exit_code'] != 0:
                keys_output.append((
                    False,
                    f"Error running command: '{cmd}':"
                    f"{result['stderr'].strip()}",
                    "e"
                ))

        result = self.ssh.run("cat ~/.ssh/authorized_keys")
        current_keys = (
            result['stdout'].splitlines()
            if result['exit_code'] == 0 else []
        )

        for key in ssh_keys:
            key = key.strip()
            if key and key not in current_keys:
                add_cmd = f'echo {shlex.quote(key)} >> ~/.ssh/authorized_keys'
                res = self.ssh.run(add_cmd)
                if res["exit_code"] == 0:
                    keys_output.append((
                        True,
                        f"Added SSH key: {key[:40]}...",
                        "s"
                    ))
                else:
                    keys_output.append((
                        False,
                        f"Failed to add key: {key[:40]}... -"
                        f" {res['stderr'].strip()}",
                        "e"
                    ))
            else:
                keys_output.append((
                    True,
                    f"SSH key already present: {key[:40]}...",
                    "i"
                ))

        return keys_output

    def change_pwd(
        self,
        user: str,
        new_password: str,
        treat_user_as_root: bool = False
    ) -> list[tuple[bool, str, str]]:
        if not user:
            return [(False, "Empty username is not allowed.", "e")]

        is_root = (
            getattr(self.ssh, "username", "") == "root" or
            treat_user_as_root
        )

        # Safely quote user:password
        user_pass = shlex.quote(f"{user}:{new_password}")

        if is_root:
            cmd = f"echo {user_pass} | chpasswd"
        else:
            # Wrap full pipeline in sudo shell
            cmd = f"sudo -n sh -c 'echo {user_pass} | chpasswd'"

        res = self.run(cmd)

        if res["exit_code"] == 0:
            return [
                (
                    True,
                    f"Password for '{user}' changed successfully.",
                    "s"
                )
            ]

        return [
            (
                False,
                f"Failed to change password for '{user}': "
                f"{res['stderr'].strip()}",
                "e"
            )
        ]

    def get_active_sshd_config(
            self,
            user="root"
    ) -> tuple[bool, dict[str, str]]:

        cmd = "sshd -T" if user == "root" else "sudo sshd -T"

        result = self.run(cmd)
        if result["exit_code"] != 0:
            return False, {"error": result["stderr"].strip()}

        active_sshd_dict: dict[str, str] = {}
        active_sshd_config = result['stdout'].splitlines()

        for line in active_sshd_config:
            parts = line.strip().split(None, 1)
            if len(parts) == 2:
                key, value = parts
                active_sshd_dict[key] = value

        return True, active_sshd_dict

    def resolve_wildcard_path(self, path: str) -> tuple[bool, list[str] | str]:
        command = f"ls -1 {path}"
        result = self.ssh.run(command)

        if result['exit_code'] != 0:
            return False, result['stderr']

        resolved_paths = result['stdout'].splitlines()
        return True, resolved_paths

    def search_configfile(
            self,
            searchstring: str,
            path: str
    ) -> tuple[bool, list[str] | str]:
        command = f"grep -i {shlex.quote(searchstring)} {shlex.quote(path)}"
        result = self.run(command)
        if result["exit_code"] != 0:
            return False, result["stderr"].strip()

        included: list[str] = []
        config_lines = result['stdout'].splitlines()
        for line in config_lines:
            tokens = line.strip().split()
            if len(tokens) > 1 and tokens[0].lower() == searchstring.lower():
                included.append(tokens[1])

        actual: list[str] = []
        for inc_path in included:
            if "*" in inc_path:
                ok, files = self.resolve_wildcard_path(inc_path)
                if ok and isinstance(files, list):
                    actual.extend(files)
            else:
                actual.append(inc_path)
        return True, actual

    def get_all_config_files(
            self,
            searchstring: str,
            root_path: str
    ) -> set[str]:
        visited: set[str] = set()
        files: list[str] = [root_path]
        while files:
            current = files.pop()
            if current not in visited:
                ok, included = self.search_configfile(searchstring, current)
                if ok and isinstance(included, list) and included:
                    files.extend(included)
                visited.add(current)
        return visited

    def comment_out_param_in_file(
            self,
            param: str,
            path: str,
            user: str = "root"
    ) -> bool:
        # Backup
        timestamp = time.strftime("%Y%m%d_%H%M%S")
        backup = f"{path}.{timestamp}.bak"
        prefix = "sudo " if user.strip().lower() != "root" else ""

        command = f"{prefix}cp {shlex.quote(path)} {shlex.quote(backup)}"
        if self.run(command)["exit_code"] != 0:
            return False

        # Comment out lines where PARAM starts the (non-commented)
        # line (allow leading spaces)
        # Use a non-slash delimiter and escape regex metacharacters.
        pattern = re.escape(param)
        safe_path = shlex.quote(path)
        cmd = (
            f"{prefix}sed -i '/^[[:space:]]*{pattern}\\b/ s/^/#/' {safe_path}"
            )
        return self.run(cmd)["exit_code"] == 0

    def is_param_explicitly_set(self, param: str, filepath: str) -> bool:
        # Match non-commented lines where the param starts a token
        grep_cmd = (
            f"grep -i '^[[:space:]]*{param}\\b' {shlex.quote(filepath)} "
            "| grep -v '^[[:space:]]*#'"
        )
        result = self.ssh.run(grep_cmd)
        return result['exit_code'] == 0 and result['stdout'].strip() != ''

    def get_missing_sshd_keys(
        self,
        active_config: dict[str, str],
        desired_config: dict[str, str],
    ) -> list[str]:
        missing: list[str] = []
        for key in desired_config:
            if key.lower() not in active_config:
                missing.append(key)
        return missing

    def get_wrong_value_sshd_keys(
        self,
        active_config: dict[str, str],
        desired_config: dict[str, str],
    ) -> list[str]:
        wrong: list[str] = []
        for key, desired in desired_config.items():
            active = active_config.get(key.lower())
            if (
                active is not None
                and str(desired).lower() != str(active).lower()
            ):
                wrong.append(key)
        return wrong

    def ensure_lines_in_file(
            self,
            lines: list[str],
            path: str,
            user: str = "root"
    ) -> list[tuple[bool, str, str]]:
        """
        Ensure each line appears in `path` exactly once (append if missing).
        Returns [(ok, message, level)].
        """
        out: list[tuple[bool, str, str]] = []

        # Ensure file exists
        prefix = "sudo " if user.strip().lower() != "root" else ""
        dir_cmd = f"{prefix}mkdir -p $(dirname {shlex.quote(path)})"
        touch_cmd = f"{prefix}touch {shlex.quote(path)}"
        for cmd in (dir_cmd, touch_cmd):
            res = self.run(cmd)
            if res["exit_code"] != 0:
                out.append((
                    False,
                    f"Error running '{cmd}': {res['stderr'].strip()}",
                    "e"
                    ))
                return out

        safe_path = shlex.quote(path)

        # For each line, append only if not present (fixed-string, whole-line)
        for line in lines:
            line = line.rstrip("\n")
            if not line:
                continue

            safe_line = shlex.quote(line)
            check = self.run(f"grep -Fxq {safe_line} {safe_path}")
            if check["exit_code"] == 0:
                out.append((True, f"Line already present: {line}", "i"))
                continue
            cmd = f"sh -c \"echo {safe_line} >> {safe_path}\""
            if user.strip().lower() != "root":
                cmd = f"sudo {cmd}"
            append = self.run(cmd)
            if append["exit_code"] == 0:
                out.append((True, f"Appended: {line}", "s"))
            else:
                out.append((
                    False,
                    f"Failed to append: {line} - {append['stderr'].strip()}",
                    "e"
                    ))

        return out

    def bool(self, value) -> str:
        """Return '1' or '0' for truthy/falsy config values."""
        return "1" if bool(value) else "0"

    def ensure_qemu_guest_agent_on_guest(
            self,
            ssh
    ) -> list[tuple[bool, str, str]]:
        """
        Ensures that qemu-guest-agent is installed and enabled on a guest VM
        via the provided SSH connection.

        Returns a list of (success_flag, message, log_level).
        """
        out: list[tuple[bool, str, str]] = []

        # Check if installed
        check_cmd = "dpkg -s qemu-guest-agent | grep -q '^Status: install'"
        check = ssh.run(check_cmd)
        if check["exit_code"] == 0:
            out.append((True, "qemu-guest-agent is already installed.", "i"))
        else:
            # Install it
            install_cmd = (
                "sudo apt-get update && sudo apt-get "
                "install -y qemu-guest-agent"
                )
            res = ssh.run(install_cmd)
            if res["exit_code"] != 0:
                out.append((
                    False,
                    "Failed to install qemu-guest-agent: "
                    f"{res['stderr'].strip()}",
                    "e"
                ))
                return out
            out.append((
                False,
                "qemu-guest-agent installed successfully.",
                "s"
                ))

        # Enable and start the service
        enable_cmd = "sudo systemctl enable --now qemu-guest-agent"
        res = ssh.run(enable_cmd)
        if res["exit_code"] != 0:
            out.append((
                False,
                "Failed to enable/start qemu-guest-agent: "
                f"{res['stderr'].strip()}",
                "e"
            ))
        else:
            out.append((True, "qemu-guest-agent enabled and running.", "s"))

        return out
