#!/usr/bin/env python3
from lib.ssh_handler import SSHConnection
from lib.output_handler import OutputHandler
import shlex
import re
import time
import socket
import datetime


class ProxmoxHost:
    def __init__(
            self,
            host,
            username,
            password=None,
            key_filename=None,
            domain=None,
            logfile=None
            ):
        self.host = host
        self.username = username
        self.domain = domain
        self.ssh = SSHConnection(host, username, password, key_filename)
        self.Output = OutputHandler(logfile)

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

    def get_active_sshd_config(self):
        result = self.ssh.run('sshd -T')
        if result['exit_code'] != 0:
            return []
        active_sshd_config = result['stdout'].splitlines()
        active_sshd_dict = {}
        for line in active_sshd_config:
            parts = line.strip().split(None, 1)
            if len(parts) == 2:
                key, value = parts
                active_sshd_dict[key] = value
        return active_sshd_dict

    def get_missing_sshd_keys(self, active_config, desired_config):
        missing = []
        prefix = desired_config['pve_key_prefix']
        for v_key in desired_config:

            if not v_key.startswith(f"{prefix}"):
                if not v_key.lower() in active_config:
                    missing.append(v_key)

        return missing

    def get_wrong_value_sshd_keys(self, active_config, desired_config):
        wrong = []
        prefix = desired_config['pve_key_prefix']
        for v_key, desired_value in desired_config.items():

            if not v_key.startswith(f"{prefix}"):
                active_value = active_config.get(v_key.lower())
                if active_value is not None:
                    if str(desired_value).lower() != str(active_value).lower():
                        wrong.append(v_key)

        return wrong

    def resolve_wildcard_path(self, path):
        command = f"ls -1 {path}"
        result = self.ssh.run(command)

        if result['exit_code'] != 0:
            return False, []

        resolved_paths = result['stdout'].splitlines()
        return True, resolved_paths

    def search_configfile(self, searchstring, path):
        actual_paths = []
        command = (
            f"grep -i {shlex.quote(searchstring)} {shlex.quote(path)}"
            )
        result = self.ssh.run(command)
        if result['exit_code'] != 0:
            return []

        config_lines = result['stdout'].splitlines()
        included_paths = []
        for line in config_lines:
            # Naive way: split on whitespace, take everything after "Include"
            tokens = line.strip().split()
            if len(tokens) > 1 and tokens[0].lower() == searchstring.lower():
                included_paths.append(tokens[1])

        for path in included_paths:
            if "*" in path:
                success, files = self.resolve_wildcard_path(path)
                if success:
                    actual_paths.extend(files)
                else:
                    actual_paths.append(path)

        return actual_paths

    def get_all_config_files(self, v_config):
        visited = set()
        config_files = []
        config_files.append(v_config['pve_sshd_config_path'])

        while config_files:
            current = config_files.pop()
            if current not in visited:
                included = self.search_configfile(
                    v_config['pve_sshd_searchstring'],
                    current
                    )
                if not len(included) == 0:
                    config_files.extend(included)

                visited.add(current)

        return visited

    def comment_out_param_in_file(self, param, path):
        timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        backup_path = f"{path}.{timestamp}.bak"

        copy_cmd = f"cp {shlex.quote(path)} {shlex.quote(backup_path)}"
        self.ssh.run(copy_cmd)

        cmd = f"sed -i '/^{shlex.quote(param)}\\b/ s/^/#/' {shlex.quote(path)}"
        result = self.ssh.run(cmd)
        return result['exit_code'] == 0

    def is_param_explicitly_set(self, param, filepath):
        # grep_cmd = f"grep -i '^{param}\\b' {shlex.quote(filepath)}"
        grep_cmd = (
            f"grep -i '^[[:space:]]*{param}\\b' {shlex.quote(filepath)} "
            "| grep -v '^[[:space:]]*#'"
        )
        result = self.ssh.run(grep_cmd)
        return result['exit_code'] == 0 and result['stdout'].strip() != ''

    def append_custom_sshd_file(self, missing, v_config):
        lines = []
        path = v_config['pve_sshd_custom_config']
        for param in missing:
            param_value = v_config[f"{param}"]
            line = f"{param} {param_value}"
            lines.append(line)
        content = "\n".join(lines) + "\n"
        command = f'echo {shlex.quote(content)} >> {shlex.quote(path)}'
        return self.ssh.run(command)['exit_code'] == 0

    def check_sshd_config(self, v_config):
        return_value = "success"
        sshd_files = self.get_all_config_files(v_config)
        if len(sshd_files) > 0:
            for file in sshd_files:
                self.Output.output(
                    f"SSHD config file found: '{file}'",
                    "i"
                )
        else:
            self.Output.output(
                "No SSHD config file found",
                "e"
            )
            return_value = "error"
            return return_value

        active_config_dict = self.get_active_sshd_config()
        if len(active_config_dict) > 0:
            self.Output.output(
                "Retriving active SSHD config (sshd -T)",
                "i"
            )
        else:
            self.Output.output(
                "Error retriving active SSHD config",
                "e"
            )
            return_value = "error"
            return return_value

        missing = self.get_missing_sshd_keys(active_config_dict, v_config)
        missing_set = set()
        if len(missing) > 0:
            for missing_param in missing:
                missing_set.add(missing_param)
                self.Output.output(
                    f"Missing key: '{missing_param}'",
                    "i"
                )
        else:
            self.Output.output(
                "No missing keys found in SSHD config",
                "i"
            )

        wrong = (
            self.get_wrong_value_sshd_keys(active_config_dict, v_config)
        )
        wrong_set = set()
        if len(wrong) > 0:
            for wrong_param in wrong:
                wrong_set.add(wrong_param)
                self.Output.output(
                    f"Wrong value in key: '{wrong_param}'",
                    "i"
                )
        else:
            self.Output.output(
                "No wrong keys found in SSHD config",
                "i"
            )

        if len(wrong) > 0:
            explicit_keys = []
            implicit_keys = []
            for param in wrong:
                explicit_set = []
                for file in sshd_files:
                    if self.is_param_explicitly_set(param, file):
                        explicit_set.append((param, file))

                if len(explicit_set) > 0:
                    explicit_keys.extend(explicit_set)
                else:
                    implicit_keys.append(param)

            if len(explicit_keys) > 0:
                for key in explicit_keys:
                    e_key, e_path = key
                    self.Output.output(
                        f"Explicit set key: '{e_key}' in '{e_path}'",
                        "i"
                    )
            else:
                self.Output.output(
                    "No explicit set keys in SSHD config",
                    "i"
                )

            if len(implicit_keys) > 0:
                for key in implicit_keys:
                    self.Output.output(
                        f"Implicit set key: '{key}'",
                        "i"
                    )
            else:
                self.Output.output(
                    "No implicit set keys in SSHD config",
                    "i"
                )

            if len(explicit_keys) > 0:
                for key in explicit_keys:
                    e_key, e_path = key
                    success = self.comment_out_param_in_file(e_key, e_path)
                    if success:
                        self.Output.output(
                            (
                                "Commented out explicit key: "
                                f"'{e_key}' in '{e_path}'"
                            ),
                            "s"
                        )
                        self.Output.output(
                            (
                                f"Adding '{e_key}' to missing list"
                            ),
                            "s"
                        )
                        missing_set.add(e_key)
                    else:
                        self.Output.output(
                            (
                                "Error commenting out explicit key: "
                                f"'{e_key}' in "
                                f"'{v_config['pve_sshd_config_path']}'"
                            ),
                            "e"
                        )

            if len(implicit_keys) > 0:
                for im_key in implicit_keys:
                    self.Output.output(
                        (
                            f"Adding impllicit key '{im_key}' to missing list"
                        ),
                        "s"
                        )
                    missing_set.add(im_key)

        if len(missing_set) > 0:
            for m_key in missing_set:
                self.Output.output(
                        f"Missing key: '{m_key}'",
                        "i"
                    )

            missing = list(missing_set)
            success = self.append_custom_sshd_file(
                    missing,
                    v_config
                )
            if success:
                self.Output.output(
                    "Appended missing keys to custom config: "
                    f"'{v_config['pve_sshd_custom_config']}'",
                    "s"
                )
                return_value = "check"
                return return_value
            else:
                self.Output.output("Failed to append missing keys", "e")
                return_value = "error"
                return return_value

            sshd_files = self.get_all_config_files(v_config)
            if v_config['pve_sshd_custom_config'] not in sshd_files:
                include_cmd = (
                    "echo Include "
                    f"{shlex.quote(v_config['pve_sshd_custom_config'])} "
                    ">> "
                    f"{shlex.quote(v_config['pve_sshd_config_path'])}"
                )
                success = self.ssh.run(include_cmd)['exit_code'] == 0
                if success:
                    self.Output.output(
                        "Included custom config in "
                        f"'{v_config['pve_sshd_config_path']}'",
                        "s"
                    )
                else:
                    self.Output.output(
                        "Custom config file NOT included in "
                        f"'{v_config['pve_sshd_config_path']}'",
                        "e"
                    )
                    return_value = "error"
                    return return_value
            else:
                self.Output.output(
                    "Custom config file already part of existing 'Include'"
                    " statements'",
                    "s"
                )

            reload_cmd = "systemctl reload sshd"
            success = self.ssh.run(reload_cmd)['exit_code'] == 0
            if success:
                self.Output.output(
                    "SHHD confing reloaded",
                    "s"
                )
            else:
                self.Output.output(
                    "Failed to reload SSHD config",
                    "e"
                )
                return_value = "error"
                return return_value

        return return_value
