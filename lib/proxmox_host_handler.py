#!/usr/bin/env python3
from lib.ssh_handler import SSHConnection
# from lib.proxmox_common import ProxmoxCommon
import shlex
import re
import time
import socket
import datetime
import getpass


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
        # self.Output = OutputHandler(logfile)

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
            ):

        host_output = []

        correct_flag, correct_message, current_hostname = (
            self.is_hostname_correct(new_hostname)
        )
        if correct_flag:
            host_output.append((True, f"{correct_message}", "s"))
            return host_output
        else:
            host_output.append((False, f"{correct_message}", "e"))

        all_empty = True
        for folderpath in default_folders:
            folder_flag, folder_message = self.is_folder_empty(folderpath)
            if not folder_flag:
                all_empty = False
                host_output.append(
                    (False, f"{folder_message}: {folderpath}", "e")
                    )
            else:
                host_output.append(
                    (True, f"{folder_message}: {folderpath}", "s")
                    )

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
            host_output.append((False, f"{add_message}", "e"))
            return host_output

        host_output.append((True, f"{add_message}", "s"))

        remove_flag, remove_message = self.remove_line_with_content(
            content=(
                f"{ip_address} "
                f"{current_hostname}.{domain} "
                f"{current_hostname}"
            ),
            file_path=hostfile
        )
        if not remove_flag:
            host_output.append((False, f"{remove_message}", "e"))
            return host_output

        host_output.append((True, f"{remove_message}", "s"))

        set_flag, set_message = self.set_hostname(new_hostname)
        if not set_flag:
            host_output.append((False, f"{set_message}", "e"))
            return host_output

        host_output.append((True, f"{set_message}", "s"))

        return host_output

    def reboot_and_reconnect(self, wait_time=10, timeout=180):
        reboot_output = []
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
                sock = socket.create_connection((self.host, 22), timeout=5)
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

        return reboot_output

    def get_active_sshd_config(self):
        result = self.ssh.run('sshd -T')
        if result['exit_code'] != 0:
            return False, result['stderr']
        active_sshd_config = result['stdout'].splitlines()
        active_sshd_dict = {}
        for line in active_sshd_config:
            parts = line.strip().split(None, 1)
            if len(parts) == 2:
                key, value = parts
                active_sshd_dict[key] = value
        return True, active_sshd_dict

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
            return False, result['stderr']

        resolved_paths = result['stdout'].splitlines()
        return True, resolved_paths

    def search_configfile(self, searchstring, path):
        actual_paths = []
        command = (
            f"grep -i {shlex.quote(searchstring)} {shlex.quote(path)}"
            )
        result = self.ssh.run(command)
        if result['exit_code'] != 0:
            return False, result['stderr']

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
            if "*" not in path:
                actual_paths.append(path)

        return True, actual_paths

    def get_all_config_files(self, searchstring, path):
        visited = set()
        config_files = [path]

        while config_files:
            current = config_files.pop()
            if current not in visited:
                included = self.search_configfile(
                    searchstring,
                    current
                    )
                if not len(included[1]) == 0:
                    config_files.extend(included[1])

                visited.add(current)

        return visited

    def comment_out_param_in_file(self, param, path):
        timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        backup_path = f"{path}.{timestamp}.bak"

        copy_cmd = f"cp {shlex.quote(path)} {shlex.quote(backup_path)}"
        result = self.ssh.run(copy_cmd)
        if result['exit_code'] != 0:
            return False, result['stderr']

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
        config_output = []
        sshd_files = self.get_all_config_files(
            v_config['pve_sshd_searchstring'],
            v_config['pve_sshd_config_path']
            )
        if len(sshd_files) > 0:
            for file in sshd_files:
                config_output.append((
                    True,
                    f"SSHD config file found: '{file}'",
                    "s"
                ))
        else:
            config_output.append((
                    False,
                    "No SSHD config file found",
                    "e"
                ))
            return config_output

        config_flag, active_config_dict = self.get_active_sshd_config()
        if config_flag:
            config_output.append((
                    True,
                    "Reading active SSHD config (sshd -T)",
                    "s"
                ))
        else:
            config_output.append((
                    False,
                    "Errot reading active SSHD config (sshd -T)",
                    "e"
                ))
            return config_output

        missing = self.get_missing_sshd_keys(active_config_dict, v_config)
        missing_set = set()
        if len(missing) > 0:
            for missing_param in missing:
                missing_set.add(missing_param)
                config_output.append((
                    False,
                    f"Missing key: '{missing_param}'",
                    "e"
                ))
        else:
            config_output.append((
                    True,
                    "No keys missing in SSHD configuration",
                    "s"
                ))

        wrong = (
            self.get_wrong_value_sshd_keys(active_config_dict, v_config)
        )
        wrong_set = set()
        if len(wrong) > 0:
            for wrong_param in wrong:
                wrong_set.add(wrong_param)
                config_output.append((
                    False,
                    f"Wrong key value: '{wrong_param}'",
                    "e"
                ))
        else:
            config_output.append((
                    True,
                    "No keys with wrong value in SSHD configuration",
                    "s"
                ))
            return config_output

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
                    config_output.append((
                        True,
                        f"Explicit set key: '{e_key}' in '{e_path}'",
                        "i"
                    ))
            else:
                config_output.append((
                        True,
                        "No keys set explicitly in SSHD config",
                        "s"
                    ))

            if len(implicit_keys) > 0:
                for key in implicit_keys:
                    config_output.append((
                        True,
                        f"Implicit set key: '{key}'",
                        "i"
                    ))
            else:
                config_output.append((
                        True,
                        "No keys set implicitly in SSHD config",
                        "s"
                    ))

            if len(explicit_keys) > 0:
                for key in explicit_keys:
                    e_key, e_path = key
                    success = self.comment_out_param_in_file(e_key, e_path)
                    if success:
                        config_output.append((
                            True,
                            "Commented out explicit key: "
                            f"'{e_key}' in '{e_path}'",
                            "s"
                        ))
                        config_output.append((
                            True,
                            f"Adding '{e_key}' to missing list",
                            "s"
                        ))
                        missing_set.add(e_key)
                    else:
                        config_output.append((
                            False,
                            "Error commenting out explicit key: "
                            f"'{e_key}' in "
                            f"'{v_config['pve_sshd_config_path']}'",
                            "e"
                        ))

            if len(implicit_keys) > 0:
                for im_key in implicit_keys:
                    config_output.append((
                        True,
                        f"Adding '{im_key}' to missing list",
                        "s"
                    ))
                    missing_set.add(im_key)

        if len(missing_set) > 0:
            for m_key in missing_set:
                config_output.append((
                    True,
                    f"Missing key: '{m_key}'",
                    "e"
                ))

            missing = list(missing_set)
            success = self.append_custom_sshd_file(
                    missing,
                    v_config
                )
            if success:
                config_output.append((
                    True,
                    "Appended missing keys to custom config: "
                    f"'{v_config['pve_sshd_custom_config']}'",
                    "s"
                ))
            else:
                config_output.append((
                    False,
                    "Failed to append missing keys",
                    "e"
                ))

            sshd_files = self.get_all_config_files(
                v_config['pve_sshd_searchstring'],
                v_config['pve_sshd_config_path']
                )
            if v_config['pve_sshd_custom_config'] not in sshd_files:
                include_cmd = (
                    "echo Include "
                    f"{shlex.quote(v_config['pve_sshd_custom_config'])} "
                    ">> "
                    f"{shlex.quote(v_config['pve_sshd_config_path'])}"
                )
                success = self.ssh.run(include_cmd)['exit_code'] == 0
                if success:
                    config_output.append((
                        True,
                        "Included custom config in "
                        f"'{v_config['pve_sshd_config_path']}'",
                        "s"
                    ))
                else:
                    config_output.append((
                        False,
                        "Custom config file NOT included in "
                        f"'{v_config['pve_sshd_config_path']}'",
                        "e"
                    ))
                    return config_output
            else:
                config_output.append((
                        True,
                        "Custom config file already part of existing 'Include'"
                        " statements'",
                        "s"
                    ))

            reload_cmd = "systemctl reload sshd"
            success = self.ssh.run(reload_cmd)['exit_code'] == 0
            if success:
                config_output.append((
                        True,
                        "SSHD config reloaded",
                        "s"
                    ))
            else:
                config_output.append((
                    True,
                    "SSHD config failed to reload",
                    "e"
                ))
                return config_output

        return config_output

    def check_pve_no_subscribtion(self):
        subscription_output = []
        while True:
            command = (
                'grep -q "^deb .*pve-no-subscription" '
                '/etc/apt/sources.list && echo "enabled"'
            )
            result = self.ssh.run(command)
            if result['stdout'].strip() == "enabled":
                subscription_output.append((
                    True,
                    "pve-no-subscription repository is enabled.",
                    "s"
                ))
                return subscription_output

            command = (
                'grep -q "^# deb .*pve-no-subscription" '
                '/etc/apt/sources.list && echo "commented"'
            )
            result = self.ssh.run(command)
            if result['stdout'].strip() == "commented":
                subscription_output.append((
                    True,
                    "pve-no-subscription repository is found "
                    "but not enabled. Enabling it now...",
                    "w"
                ))

                command = (
                    "sed -i 's/^# deb \\(.*pve-no-subscription\\)/deb \\1/' "
                    "/etc/apt/sources.list"
                )
                result = self.ssh.run(command)
                if result['exit_code'] == 0:
                    continue
                else:
                    subscription_output.append((
                        False,
                        "Error enabling pve-no-subscription repository.",
                        "e"
                    ))
                    return subscription_output

            subscription_output.append((
                True,
                "pve-no-subscription repository is not found. "
                "Adding it now...",
                "w"
            ))

            http_str = "deb http://download.proxmox.com/debian/pve "
            pve_no = "bookworm pve-no-subscription"
            command = (
                'echo '
                f'"{http_str} {pve_no}"'
                ' | tee -a /etc/apt/sources.list'
            )
            result = self.ssh.run(command)
            if result['exit_code'] == 0:
                continue

            else:
                subscription_output.append((
                    False,
                    "Error adding pve-no-subscription repository"
                    " to /etc/apt/sources.list.",
                    "e"
                ))
                return subscription_output

    def check_pve_enterprise(self):
        enterprise_message = []
        while True:
            command = (
                'grep -q "^deb .*bookworm pve-enterprise" '
                '/etc/apt/sources.list.d/pve-enterprise.list '
                '&& echo "enabled" || echo "disabled"'
            )
            result = self.ssh.run(command)
            if result['stdout'].strip() == "disabled":
                enterprise_message.append((
                    True,
                    "pve-enterprise repository is disabled.",
                    "s"
                ))
                return enterprise_message

            if result['stdout'].strip() == "enabled":
                enterprise_message.append((
                    True,
                    "pve-enterprise repository is enabled. "
                    "Disabling it now...",
                    "w"
                ))

                command = (
                    r"sed -i 's/^\(deb .*bookworm pve-enterprise\)/# \1/' "
                    r"/etc/apt/sources.list.d/pve-enterprise.list"
                )
                result = self.ssh.run(command)
                if result['exit_code'] == 0:
                    continue
                else:
                    enterprise_message.append((
                        False,
                        "Error disabling pve-enterprise repository.",
                        "e"
                    ))
                    return enterprise_message

    def check_pve_ceph(self):
        ceph_message = []
        while True:
            command = (
                'grep -q "^deb .*ceph-quincy bookworm enterprise" '
                '/etc/apt/sources.list.d/ceph.list && '
                'echo "enabled" || echo "disabled"'
            )
            result = self.ssh.run(command)
            if result['stdout'].strip() == "disabled":
                ceph_message.append((
                    True,
                    "pve-ceph repository is disabled.",
                    "s"
                ))
                return ceph_message

            if result['stdout'].strip() == "enabled":
                ceph_message.append((
                    True,
                    "pve-ceph repository is enabled. "
                    "Disabling it now...",
                    "w"
                ))

                command = (
                    r"sed -i 's/^\(deb .*bookworm enterprise\)/# \1/' "
                    r"/etc/apt/sources.list.d/ceph.list"
                    )
                result = self.ssh.run(command)
                if result['exit_code'] == 0:
                    continue
                else:
                    ceph_message.append((
                        False,
                        "Error disabling pve-ceph repository.",
                        "e"
                    ))
                    return ceph_message

    def check_pve_pve_no_subscription_patch(self):
        patch_message = []
        file_path = '/usr/share/perl5/PVE/API2/Subscription.pm'
        find_str = 'NotFound'
        replace_str = 'Active'

        while True:
            command = (
                f'test -f "{file_path}" && echo "exists" '
                '|| echo "not_exists"'
            )
            result = self.ssh.run(command)
            if result['stdout'].strip() == "not_exists":
                patch_message.append((
                    False,
                    (
                        f"pve-no-subscription patch error: {file_path} "
                        "does not exist! Are you sure this is PVE?"
                    ),
                    "e"
                ))
                return patch_message

            # File exists
            command = (
                f'grep -i "{find_str}" "{file_path}" >/dev/null && '
                'echo "found" || echo "not_found"'
            )
            result = self.ssh.run(command)
            if result['stdout'].strip() == "not_found":
                patch_message.append((
                    True,
                    "pve-no-subscription patch already applied.",
                    "s"
                ))
                return patch_message

            if result['stdout'].strip() == "found":
                command = (
                    f'sed -i "s/{find_str}/{replace_str}/gi" "{file_path}"'
                )
                result = self.ssh.run(command)
                if result['exit_code'] == 0:
                    patch_message.append((
                        True,
                        "pve-no-subscription patch has been applied.",
                        "s"
                    ))
                    self.ssh.run("systemctl restart pvedaemon")
                    self.ssh.run("systemctl restart pveproxy")
                    return patch_message
                else:
                    patch_message.append((
                        False,
                        "Error applying pve-no-subscription patch.",
                        "e"
                    ))
                    return patch_message

    def download_iso_files(self, v_config):
        download_output = []
        path = v_config['pve_iso_path']
        command = f"mkdir -p {path}"
        result = self.ssh.run(command)
        if result['exit_code'] != 0:
            download_output.append((
                False,
                f"Error creating: {path}",
                "e"
            ))
            return download_output

        if result['exit_code'] == 0:
            urls = v_config['pve_iso_urls']
            for url in urls:
                iso_filename = url.split('/')[-1]
                iso_filepath = f"{path}/{iso_filename}"
                command = (
                        f"test -f {iso_filepath} && "
                        "echo 'exists' || echo 'not_exists'"
                    )
                result = self.ssh.run(command)
                if result['stdout'].strip() == "exists":
                    download_output.append((
                        True,
                        f"{iso_filename} already exists, skipping download.",
                        "s"
                    ))
                if result['stdout'].strip() == "not_exists":
                    download_output.append((
                        True,
                        f"Downloading {iso_filename}",
                        "i"
                    ))
                    command = f"wget -q -P {path} {url}"
                    result = self.ssh.run(command)
                    if result['exit_code'] == 0:
                        download_output.append((
                            True,
                            f"{iso_filename} downloaded",
                            "s"
                        ))

                    if result['exit_code'] != 0:
                        download_output.append((
                            False,
                            f"Error downloading {iso_filename}",
                            "e"
                        ))
        return download_output

    def change_pwd(self, v_config):
        password_output = []
        pwd1 = getpass.getpass("Enter new root password: ")
        pwd2 = getpass.getpass("Confirm new root password: ")

        if pwd1 != pwd2:
            password_output.append((
                False,
                "Passwords do not match. Aborting.",
                "e"
            ))
            return password_output

        if not pwd1:
            password_output.append((
                False,
                "Empty password is not allowed.",
                "e"
            ))
            return password_output

        user = v_config['pve_host_username']
        command = f"echo {shlex.quote(f'{user}:{pwd1}')} | chpasswd"
        result = self.ssh.run(command)

        if result['exit_code'] == 0:
            password_output.append((
                True,
                "Root password changed successfully.",
                "s"
            ))
        else:
            password_output.append((
                False,
                "Failed to change root password!",
                "e"
            ))

        return password_output

    def check_ssh_keys(self, ssh_keys):
        keys_output = []

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
