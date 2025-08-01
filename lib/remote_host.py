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

    def reboot_and_reconnect(
            self,
            wait_time=10,
            timeout=180
    ) -> list[tuple[bool, str, str]]:
        reboot_output: list[tuple[bool, str, str]] = []
        result = self.ssh.run("reboot")
        if result['exit_code'] != 0:
            reboot_output.append((False, "Failed to send reboot command", "e"))
            return reboot_output

        self.ssh.close()

        reboot_output.append((True, "Waiting for host to reboot...", "i"))
        time.sleep(wait_time)

        start_time = time.time()
        while time.time() - start_time < timeout:
            try:
                sock = socket.create_connection((self.ssh.host, 22), timeout=5)
                sock.close()

                reboot_output.append(
                    (True, "SSH port is open, trying to reconnect...", "i")
                    )
                success, message = self.ssh.connect()
                reboot_output.append(
                    (
                        True if success else False,
                        f"{message}",
                        "s" if success else "e"
                        )
                )
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
        new_password: str
    ) -> list[tuple[bool, str, str]]:
        if not user:
            return [(False, "Empty username is not allowed.", "e")]

        is_root = getattr(self.ssh, "username", "") == "root"
        prog = "chpasswd" if is_root else "sudo -n chpasswd"
        cmd = f"echo {shlex.quote(f'{user}:{new_password}')} | {prog}"

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

    def get_active_sshd_config(self) -> tuple[bool, dict[str, str]]:
        result = self.run("sshd -T")
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

    def comment_out_param_in_file(self, param: str, path: str) -> bool:
        # Backup
        timestamp = time.strftime("%Y%m%d_%H%M%S")
        backup = f"{path}.{timestamp}.bak"
        command = f"cp {shlex.quote(path)} {shlex.quote(backup)}"
        if self.run(command)["exit_code"] != 0:
            return False

        # Comment out lines where PARAM starts the (non-commented)
        # line (allow leading spaces)
        # Use a non-slash delimiter and escape regex metacharacters.
        pattern = re.escape(param)
        safe_path = shlex.quote(path)
        cmd = f"sed -i '/^[[:space:]]*{pattern}\\b/ s/^/#/' {safe_path}"
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
        ignore_prefix: str | None = None,
    ) -> list[str]:
        missing: list[str] = []
        for key in desired_config:
            if ignore_prefix and key.startswith(ignore_prefix):
                continue
            if key.lower() not in active_config:
                missing.append(key)
        return missing

    def get_wrong_value_sshd_keys(
        self,
        active_config: dict[str, str],
        desired_config: dict[str, str],
        ignore_prefix: str | None = None,
    ) -> list[str]:
        wrong: list[str] = []
        for key, desired in desired_config.items():
            if ignore_prefix and key.startswith(ignore_prefix):
                continue
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
            path: str
    ) -> list[tuple[bool, str, str]]:
        """
        Ensure each line appears in `path` exactly once (append if missing).
        Returns [(ok, message, level)].
        """
        out: list[tuple[bool, str, str]] = []

        # Ensure file exists
        dir_cmd = f"mkdir -p $(dirname {shlex.quote(path)})"
        touch_cmd = f"touch {shlex.quote(path)}"
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
            append = self.run(f"printf '%s\\n' {safe_line} >> {safe_path}")
            if append["exit_code"] == 0:
                out.append((True, f"Appended: {line}", "s"))
            else:
                out.append((
                    False,
                    f"Failed to append: {line} - {append['stderr'].strip()}",
                    "e"
                    ))

        return out
