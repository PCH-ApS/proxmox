#!/usr/bin/env python3
from lib.ssh_handler import SSHConnection
from lib.remote_host import RemoteHost
import shlex


class ProxmoxHost(RemoteHost):
    def __init__(
            self,
            host,
            username,
            password=None,
            key_filename=None,
            domain=None,
            ):
        self.host = host
        self.domain = domain
        ssh = SSHConnection(host, username, password, key_filename)
        super().__init__(ssh)

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
        command = f'ls -A {shlex.quote(folder_path)}'
        empty_message = self.run(command)
        if empty_message['exit_code'] != 0:
            return False, empty_message['stderr'].strip()
        else:
            if len(empty_message['stdout'].strip()) == 0:
                return True, "Folder is empty"
            else:
                return False, "Folder is not empty"

    def set_hostname(self, new_hostname):
        command = f'hostnamectl set-hostname {shlex.quote(new_hostname)}'
        result = self.run(command)
        if result['exit_code'] != 0:
            return False, result['stderr'].strip()
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
                    "Error reading active SSHD config (sshd -T)",
                    "e"
                ))
            return config_output

        missing = self.get_missing_sshd_keys(
            active_config_dict,
            v_config,
            v_config['pve_key_prefix']
            )
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
            self.get_wrong_value_sshd_keys(
                active_config_dict,
                v_config,
                v_config['pve_key_prefix']
                )
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
            lines: list[str] = []
            for param in missing:
                if param in v_config:
                    lines.append(f"{param} {v_config[param]}")

            results = self.ensure_lines_in_file(
                lines,
                v_config["pve_sshd_custom_config"]
                )

            for flag, msg, type in results:
                config_output.append((flag, msg, type))

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
                success = self.run(include_cmd)['exit_code'] == 0
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
            success = self.run(reload_cmd)['exit_code'] == 0
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
        command = f"mkdir -p {shlex.quote(path)}"
        result = self.run(command)
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
                        f"test -f {shlex.quote(iso_filepath)} && "
                        "echo 'exists' || echo 'not_exists'"
                    )
                result = self.run(command)
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
                    command = (
                        f"wget -q -P {shlex.quote(path)} {shlex.quote(url)}"
                    )
                    result = self.run(command)
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

    def check_bridge_exists(self, name: str) -> tuple[bool, str]:
        """
        Verify that a Proxmox bridge exists on the host.
        Returns (ok, message). Accepts Linux bridges and OVS bridges.
        """
        if not name:
            return False, "Empty bridge name."

        safe = shlex.quote(name)

        # Linux bridge?
        res = self.run(
            f"test -d /sys/class/net/{safe}/bridge && echo ok || echo no"
            )
        if res["exit_code"] == 0 and res["stdout"].strip() == "ok":
            return True, f"Linux bridge '{name}' exists."

        # OVS bridge?
        res2 = self.run(
            f"command -v ovs-vsctl >/dev/null 2>&1 "
            f"&& ovs-vsctl br-exists {safe}"
        )
        if res2["exit_code"] == 0:
            return True, f"OVS bridge '{name}' exists."

        # Interface present at all?
        res3 = self.run(f"test -d /sys/class/net/{safe} && echo ok || echo no")
        if res3["exit_code"] == 0 and res3["stdout"].strip() == "ok":
            return False, (
                f"Interface '{name}' exists but is not a Linux/OVS bridge."
            )

        # Optional: suggest available bridges to help the user
        hint = self.run(
            "ls -1 /sys/class/net | xargs -I{} sh -c "
            "'if [ -d /sys/class/net/{}/bridge ]; then echo {}; fi'"
        )
        candidates = ", ".join(hint["stdout"].split())
        suffix = (
            f" Available Linux bridges: {candidates}" if candidates else ""
            )
        return False, f"No such bridge '{name}'.{suffix}"

    def check_storage_exists(self, storage_id: str) -> tuple[bool, str]:
        """
        Check that a storage ID is defined in /etc/pve/storage.cfg.
        Returns (ok, message).
        """
        if not storage_id:
            return False, "Empty storage id."

        cmd = (
            "awk -v id={id} '"
            "$1 ~ /:$/ && $2==id {{ found=1; exit }} "
            "END{{ exit !found }}' /etc/pve/storage.cfg"
        ).format(id=shlex.quote(storage_id))

        res = self.run(cmd)
        if res["exit_code"] == 0:
            return True, f"Storage '{storage_id}' exists."
        if res["stderr"].strip():
            return False, res["stderr"].strip()
        return False, f"Storage '{storage_id}' not found."

    def is_vmid_in_use(self, vmid: int) -> tuple[bool, str]:
        """
        True if VMID is used by a QEMU VM or LXC CT (or template),
        based on cluster config files.
        """
        vid = str(vmid)
        cmd = (
            f"if test -f /etc/pve/qemu-server/{vid}.conf "
            f"|| test -f /etc/pve/lxc/{vid}.conf; then "
            f"echo in_use; else echo free; fi"
        )
        res = self.run(cmd)
        if res["exit_code"] != 0:
            return False, res["stderr"].strip() or (
                f"Failed to check VMID {vmid}"
                )
        used = res["stdout"].strip() == "in_use"
        return used, (
            f"VMID {vmid} is already in use." if used else (
                f"VMID {vmid} is free."
                )
            )

    def check_cpu_model_supported(self, model: str) -> tuple[bool, str]:
        """
        Validate that a CPU model string is usable on this PVE host.

        Accepts:
        - 'host'
        - Built-in QEMU models available on this host
          (via qemu-system-<arch> -cpu help)
        - Proxmox custom models defined in
          /etc/pve/virtual-guest/cpu-models.conf
          (must be referenced as 'custom-<name>' in VM config)
        """
        if not model:
            return False, "Empty CPU model."

        # 1) host is always allowed
        if model == "host":
            return True, "CPU model 'host' is supported."

        # 2) custom-* models -> check cpu-models.conf
        if model.startswith("custom-"):
            name = model[len("custom-"):]
            if not name:
                return False, "Invalid custom CPU model (empty name)."
            # Matches a section header line: 'cpu-model: <name>'
            cmd = (
                "test -f /etc/pve/virtual-guest/cpu-models.conf && "
                f"grep -Eq '^\\s*cpu-model:\\s+{shlex.quote(name)}\\s*$' "
                "/etc/pve/virtual-guest/cpu-models.conf"
            )
            res = self.run(cmd)
            if res["exit_code"] == 0:
                return True, f"Custom CPU model '{model}' is defined."
            return False, (
                f"Custom CPU model '{model}' is not defined in "
                "/etc/pve/virtual-guest/cpu-models.conf"
            )

        # 3) built-in QEMU models: query the right qemu-system binary
        # Map common arches; fallback to uname mapping.
        qemu_bin_cmd = (
            "arch=$(uname -m); "
            "case \"$arch\" in "
            "  x86_64) echo qemu-system-x86_64 ;; "
            "  aarch64) echo qemu-system-aarch64 ;; "
            "  armv7l|armv6l) echo qemu-system-arm ;; "
            "  ppc64le) echo qemu-system-ppc64 ;; "
            "  s390x) echo qemu-system-s390x ;; "
            "  *) echo qemu-system-$arch ;; "
            "esac"
        )
        rb = self.run(qemu_bin_cmd)
        if rb["exit_code"] != 0:
            return False, rb["stderr"].strip() or (
                "Failed to determine qemu-system binary."
                )

        qemu_bin = rb["stdout"].strip() or "qemu-system-x86_64"

        # Ask QEMU for supported CPU models and check for an exact match.
        # We extract first "word" per line (how QEMU lists models) and
        # grep -x for exact match.
        cmd = (
            f"{qemu_bin} -cpu help 2>/dev/null | "
            "awk '{print $1}' | "
            f"grep -x -- {shlex.quote(model)}"
        )
        res = self.run(cmd)
        if res["exit_code"] == 0:
            return True, f"CPU model '{model}' is supported by {qemu_bin}."

        return False, (
            f"CPU model '{model}' not found on this host. "
            "Use 'host', a supported built-in model, or define"
            " a custom model in cpu-models.conf."
        )

    def check_storage_ctrl_exists(self, controller: str) -> tuple[bool, str]:
        """
        Check if a storage controller/model is supported by the host's QEMU.
        Matches both device 'name' and 'alias' from `-device help`.
        """
        if not controller:
            return False, "Empty controller value."

        ctrl = shlex.quote(controller)

        # If you want arch detection, replace qemu-system-x86_64 with the bin
        cmd = (
            "qemu-system-x86_64 -device help 2>/dev/null | "
            # Extract values inside quotes after name "/alias "
            "awk -F\\\" '/name \\\"/{print $2} /alias \\\"/{print $2}' | "
            "tr -d '\\r' | "          # strip any CRs just in case
            f"grep -x -- {ctrl}"
        )
        res = self.run(cmd)
        if res["exit_code"] == 0:
            return True, f"Storage controller '{controller}' is supported."
        return False, f"Storage controller '{controller}' is NOT supported."

    def check_network_ctrl_exists(self, controller: str) -> tuple[bool, str]:
        """
        Check if a network controller/model is supported by the host's QEMU.
        Matches both device 'name' and 'alias' from `-device help`.
        Maps common Proxmox terms (e.g. 'virtio' -> 'virtio-net-pci').
        Returns (ok, message).
        """
        if not controller:
            return False, "Empty controller value."

        # Map common PVE names to QEMU device names where needed
        alias_map = {
            "virtio": "virtio-net-pci",
            # PVE 'virtio' NIC = QEMU 'virtio-net-pci'
            # The others usually match QEMU names directly:
            # 'e1000', 'e1000e', 'rtl8139', 'vmxnet3', 'ne2k_pci', 'pcnet'
        }
        target = alias_map.get(controller, controller)
        target_q = shlex.quote(target)

        # If you need arch detection, replace
        # qemu-system-x86_64 with detected binary
        cmd = (
            "qemu-system-x86_64 -device help 2>/dev/null | "
            # Extract values inside quotes after name "/ alias "
            "awk -F\\\" '/name \\\"/{print $2} /alias \\\"/{print $2}' | "
            "tr -d '\\r' | "
            f"grep -x -- {target_q}"
        )
        res = self.run(cmd)
        if res["exit_code"] == 0:
            note = (
                "" if target == controller
                else f" (QEMU device: '{target}')"
            )
            return True, (
                f"Network controller '{controller}' is supported{note}."
            )
        return False, f"Network controller '{controller}' is NOT supported."
