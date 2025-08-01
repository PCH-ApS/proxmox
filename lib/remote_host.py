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
        """Return (success, hostname_or_error)."""
        res = self.run("hostname")
        if res["exit_code"] != 0:
            return False, res["stderr"].strip()
        return True, res["stdout"].strip()

    def add_to_file(self, content: str, file_path: str) -> tuple[bool, str]:
        """Add an exact line to a file if it's not already present.

        Uses grep -Fxq for exact, fixed-string, whole-line match.
        """
        safe_line = shlex.quote(content)
        safe_path = shlex.quote(file_path)

        exists = self.run(f"grep -Fxq {safe_line} {safe_path}")
        if exists["exit_code"] == 0:
            return True, f"Line already present in {file_path}"

        res = self.run(f"echo {safe_line} >> {safe_path}")
        if res["exit_code"] != 0:
            return False, res["stderr"].strip()
        return True, f"Added line to {file_path}"

    def remove_line_with_content(
        self,
        content: str,
        file_path: str
    ) -> tuple[bool, str]:
        """Remove any line containing the given content (simple sed-based).

        Escapes forward slashes to keep the sed pattern valid.
        """
        # Escape for sed delimiter
        pattern = content.replace("/", r"\/")
        safe_path = shlex.quote(file_path)

        res = self.run(f"sed -i \"/{pattern}/d\" {safe_path}")
        if res["exit_code"] != 0:
            return False, res["stderr"].strip()
        return True, f"Removed lines containing '{content}' from {file_path}"

    def reboot_and_reconnect(
        self, *, wait_time: int = 10, timeout: int = 180
    ) -> list[tuple[bool, str, str]]:
        """Reboot the host and poll until SSH is reachable again.

        Returns a list of (ok, message, level) steps for logging.
        """
        out: list[tuple[bool, str, str]] = []

        res = self.run("reboot")
        if res["exit_code"] != 0:
            out.append((False, "Failed to issue reboot command", "e"))
            return out

        # Close current session
        self.ssh.close()
        out.append((True, "Waiting for host to reboot...", "i"))
        time.sleep(wait_time)

        start = time.time()
        while time.time() - start < timeout:
            try:
                # Probe TCP/22 to see if SSH is up
                sock = socket.create_connection((self.ssh.host, 22), timeout=5)
                sock.close()
                out.append((
                    True,
                    "SSH port open, attempting reconnect...",
                    "i"
                    ))
                ok, msg = self.ssh.connect()
                out.append((ok, msg, "s" if ok else "e"))
                if ok:
                    return out
            except OSError:
                pass
            time.sleep(5)

        out.append((False, "Timed out waiting for SSH after reboot", "e"))
        return out

    def check_ssh_keys(
        self,
        ssh_keys: list[str]
    ) -> list[tuple[bool, str, str]]:
        """Ensure each key exists in ~/.ssh/authorized_keys.

        Idempotent: re-running will not duplicate keys.
        """
        output: list[tuple[bool, str, str]] = []

        for cmd in (
            "mkdir -p ~/.ssh",
            "chmod 700 ~/.ssh",
            "touch ~/.ssh/authorized_keys",
            "chmod 600 ~/.ssh/authorized_keys",
        ):
            res = self.run(cmd)
            if res["exit_code"] != 0:
                output.append((
                    False,
                    f"Error running '{cmd}': {res['stderr'].strip()}",
                    "e"
                    ))

        res = self.run("cat ~/.ssh/authorized_keys")
        if res["exit_code"] == 0:
            current_keys = res["stdout"].splitlines()
        else:
            current_keys = []

        for key in ssh_keys:
            k = key.strip()
            if not k:
                continue
            if k not in current_keys:
                add_cmd = f"echo {shlex.quote(k)} >> ~/.ssh/authorized_keys"
                add_res = self.run(add_cmd)
                if add_res["exit_code"] == 0:
                    output.append((True, f"Added SSH key: {k[:40]}...", "s"))
                else:
                    output.append((
                        False,
                        f"Failed to add key: {k[:40]}... - "
                        f"{add_res['stderr'].strip()}",
                        "e"
                        ))
            else:
                output.append((
                    True,
                    f"SSH key already present: {k[:40]}...",
                    "i"
                    ))

        return output

    def change_pwd(
            self,
            user: str,
            new_password: str
    ) -> list[tuple[bool, str, str]]:
        """Change a user's password via chpasswd."""
        cmd = f"echo {shlex.quote(f'{user}:{new_password}')} | chpasswd"
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
