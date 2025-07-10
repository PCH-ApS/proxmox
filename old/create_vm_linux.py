#!/usr/bin/env python3
from urllib.parse import unquote
from old.lib import functions
import const.vm_const as vm

# /home/nije/json-files/dhcp/main.json

import os
import json
import sys
import time
import ipaddress
import paramiko
import urllib.parse

# Add the parent directory to the Python path to make `lib` available
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))


def load_config(config_file):
    try:
        with open(config_file, 'r') as file:
            config = json.load(file)
        return config
    except Exception as e:
        functions.output_message(
            f"Error reading the configuration file: {e}",
            "e"
            )


def get_config_values(config):
    allowed_keys = set(vm.MANDATORY_KEYS).union(vm.OPTIONAL_KEYS)
    value_keys = {}
    errors = []

    try:
        for key in config.keys():
            if key not in allowed_keys:
                message = (
                    f"Invalid key '{key}' found in JSON configuration."
                )
                errors.append(message)

    except Exception as e:
        functions.output_message(
            f"Error getting configuration keys: {e}",
            "e"
            )

    finally:
        if errors:
            error_message = "\n".join(errors)
            functions.output_message(
                error_message,
                "e"
            )

    try:

        static_net_keys = [
            "ci_ipaddress",
            "ci_netmask",
            "ci_gwadvalue"
            ]
        ci_network = config.get("ci_network")

        for key in allowed_keys:
            key_value = config.get(key)
            if key_value is not None:
                value_keys[key] = key_value
            else:
                default_value_key = f"DEFAULT_{key}".upper()
                default_value = getattr(vm, default_value_key, None)

                if default_value is not None:
                    value_keys[key] = default_value
                else:
                    if (
                        ci_network and ci_network.upper() == "STATIC"
                        and key in static_net_keys
                    ):
                        functions.output_message(
                            (
                                "No value found for static network key",
                                f"'{key}' in json."
                            ),
                            "e"
                        )
                    elif key not in static_net_keys:
                        functions.output_message(
                            (
                                f"No value found for '{key}' in json or in "
                                f"constant '{default_value_key})'."
                            ),
                            "e"
                        )

    except Exception as e:
        functions.output_message(
            f"Error getting configuration values: {e}",
            "e"
            )

    finally:
        return value_keys


def check_conditional_values(values):
    if not values.get("balloon"):
        values["balloon"] = vm.DEFAULT_BALLOON

    if not values.get("start_at_boot"):
        values["start_at_boot"] = vm.DEFAULT_BOOT_START

    if not values.get("ci_upgrade"):
        values["ci_upgrade"] = vm.DEFAULT_CI_UPGRADE

    ci_network = values.get("ci_network")
    if ci_network in ["dhcp", "static"]:
        if ci_network == "static":
            functions.check_vlan(values.get("vlan"))
            functions.check_valid_ip_address(values.get(
                "ci_ipaddress"), values.get("vlan"))
            functions.check_valid_ip_address(values.get(
                "ci_gwadvalue"), values.get("vlan"))
            functions.check_netmask(values.get("ci_netmask"))
    else:
        functions.output_message(
            f"Invalid network type '{ci_network}', ",
            "expected 'dhcp' or 'static'",
            "e"
        )

    name = values.get("name")
    ci_domain = values.get("ci_domain")
    if name:
        if ci_domain:
            fqdn = f"{name}.{ci_domain}"
            functions.is_valid_hostname(fqdn)
        else:
            functions.is_valid_hostname(name)


def create_server(ssh, values):
    # Create the server template on the Proxmox host.
    clone_id = values.get("clone_id")
    name = values.get("name")
    id = values.get("id")
    cores = values.get("cores")
    memory = values.get("memory")
    disk = values.get("disk")
    balloon = values.get('balloon')
    boot_start = values.get('boot_start')
    driver = values.get('driver')
    bridge = values.get('bridge')
    vlan = values.get('vlan')

    functions.output_message(
        f"Checking configuration for '{name}'.",
        "s"
    )

    id_in_use = functions.check_if_id_in_use(ssh, id)
    scr_string = None
    scr_config_info = None

    if id_in_use:
        command = f"qm status {id} --verbose"
        scr_string = functions.execute_ssh_command(
            ssh,
            command,
            f"Failed to get status for {name}."
        )

        command = f"qm config {id}"
        scr_config_info = functions.execute_ssh_command(
            ssh,
            command,
            f"Failed to get status for {name}."
        )

    compare = False

    if scr_string is not None and scr_config_info is not None:
        compare = True

    name_value_str = None
    core_value_str = None
    memory_value_str = None
    disk_value_str = None
    balloon_value_str = None
    onboot_value_str = None
    net_value_str = None
    bridge_value_str = None
    vlan_value_str = None

    name_value = None
    core_value = None
    memory_value = None
    disk_value = None
    balloon_value = None
    onboot_value = None
    bridge_value = None
    vlan_value = None

    if compare:
        name_value_str = functions.get_status_info("name", scr_string)
        core_value_str = functions.get_status_info("cpus", scr_string)
        memory_value_str = functions.get_status_info("maxmem", scr_string)
        disk_value_str = functions.get_status_info("maxdisk", scr_string)
        balloon_value_str = functions.get_status_info(
            "balloon",
            scr_config_info
        )
        onboot_value_str = functions.get_status_info("onboot", scr_config_info)
        net_value_str = functions.get_status_info("net0", scr_config_info)
        bridge_value_str = functions.get_config_info("bridge", net_value_str)
        vlan_value_str = functions.get_config_info("tag", net_value_str)

        if name_value_str is not None:
            name_value = name_value_str

        if core_value_str is not None:
            core_value = int(core_value_str)

        if memory_value_str is not None:
            memory_value = int(memory_value_str) / (1024 * 1024)

        if disk_value_str is not None:
            disk_value = int(disk_value_str) / (1024 * 1024 * 1024)

        if balloon_value_str is not None:
            balloon_value = int(balloon_value_str)

        if onboot_value_str is not None:
            onboot_value = int(onboot_value_str)

        if bridge_value_str is not None:
            bridge_value = bridge_value_str

        if vlan_value_str is not None:
            vlan_value = int(vlan_value_str)

    try:

        if id_in_use is False:
            command = f"qm clone {clone_id} {id} --full 1"
            functions.execute_ssh_command(
                ssh,
                command,
                f"Failed to clone {name} from {clone_id}."
            )
            functions.output_message(
                f"Provisioning of virtual server '{name}' started.",
                "s"
            )

        if id_in_use:
            functions.output_message(
                f"ID '{id}' exists. No new instance, only updating..",
                "W"
            )

        if name:
            name_upd = False
            if name_value is None or not name == name_value:
                name_upd = True

            if name_upd:
                command = f"qm set {id} --name {name}"
                functions.execute_ssh_command(
                    ssh,
                    command,
                    f"'{command}' failed on the Proxmox host."
                )

                functions.output_message(
                    f"Changing name to: {name}.",
                    "s"
                )

        if cores:
            cores_upd = False
            if core_value is None or not cores == core_value:
                cores_upd = True

            if cores_upd:
                command = f"qm set {id} --cores {cores}"
                functions.execute_ssh_command(
                    ssh,
                    command,
                    f"'{command}' failed on the Proxmox host."
                )
                functions.output_message(
                    f"Changing CPU cores to: {cores}.",
                    "s"
                )

        if memory:
            memory_upd = False
            if memory_value is None or not memory == memory_value:
                memory_upd = True

            if memory_upd:
                command = f"qm set {id} --memory {memory}"
                functions.execute_ssh_command(
                    ssh,
                    command,
                    f"'{command}' failed on the Proxmox host."
                )
                functions.output_message(
                    f"Changing memory to: {memory}MB.",
                    "s"
                )

        if disk:
            disk_upd = False
            if disk_value is None or not disk == disk_value:
                disk_upd = True

            if disk_upd:
                command = f"qm disk resize {id} scsi0 {values.get('disk')}G"
                functions.execute_ssh_command(
                    ssh,
                    command,
                    f"'{command}' failed on the Proxmox host."
                )
                functions.output_message(
                    f"Changing disk sioze to: {disk}GB.",
                    "s"
                )

        if balloon:
            balloon_upd = False
            if balloon_value is None or not balloon == balloon_value:
                balloon_upd = True

            if balloon_upd:
                command = f"qm set {id} --balloon {balloon}"
                functions.execute_ssh_command(
                    ssh,
                    command,
                    f"'{command}' failed on the Proxmox host."
                )
                functions.output_message(
                    f"Changing 'Ballooning' to: {balloon}.",
                    "s"
                )

        if boot_start:
            boot_start_upd = False
            if onboot_value is None or not boot_start == onboot_value:
                boot_start_upd = True

            if boot_start_upd:
                command = f"qm set {id} --onboot {boot_start}"
                functions.execute_ssh_command(
                    ssh,
                    command,
                    f"'{command}' failed on the Proxmox host."
                )
                functions.output_message(
                    f"Changing 'Start at boot' to: {boot_start}.",
                    "s"
                )

        if bridge:
            bridge_upd = False
            if bridge_value is None or not bridge == bridge_value:
                bridge_upd = True

            if vlan:
                if str(vlan_value) is None or not vlan == vlan_value:
                    bridge_upd = True

            if bridge_upd:
                net_driver = f"{driver}"
                net_bridge = f"bridge={bridge}"
                net_tag = f"tag={vlan}"

                ln1 = f"qm set {id} --net0 {net_driver},"
                ln2 = f"{net_bridge},{net_tag}"

                command = ln1+ln2
                functions.execute_ssh_command(
                    ssh,
                    command,
                    f"'{command}' failed on the Proxmox host."
                )
                lin1 = "Changing bridge and/or vlan to: "
                lin2 = f"{net_bridge} and {net_tag}."
                functions.output_message(
                    lin1+lin2,
                    "s"
                )

    except Exception as e:
        functions.output_message(
            f"Failed to create server: {e}",
            "e"
        )

    functions.output_message(
        f"Configuration checked for '{name}'.",
        "s"
    )


def create_ssh_public_key(ssh, values):
    id = values.get("id")
    ci_publickeys = values.get("ci_publickey")
    name = values.get("name")
    filename = "/tmp/temp_key.pub"
    sftp = ssh.open_sftp()

    try:
        if ci_publickeys:
            if not isinstance(ci_publickeys, list):
                # Ensure it's a list
                ci_publickeys = [ci_publickeys]

            try:
                # Write all public keys to the temporary file
                with sftp.file(filename, 'w') as file:
                    for pubkey in ci_publickeys:
                        # Write each key on a new line
                        file.write(pubkey + '\n')

                # Execute the qm set command
                command = f"qm set {id} --sshkeys {filename}"
                functions.execute_ssh_command(
                    ssh,
                    command,
                    "Failed to set default user public key"
                )

                # Remove the temporary file
                sftp.remove(filename)

            except FileNotFoundError:
                functions.output_message(
                     "Error extracting SSH publickey from ",
                     f"'{filename}' on virtual server '{name}'.",
                     "e"
                )
            finally:
                sftp.close()

    except Exception as e:
        functions.output_message(
            f"Failed to execute command on Proxmox host: {e}",
            "e"
        )


def create_ci_options(ssh, values):
    name = values.get("name")
    id = values.get("id")
    ci_username = values.get("ci_username")
    ci_password = values.get("ci_password")
    ci_domain = values.get('ci_domain')
    ci_dns_server = values.get('ci_dns_server')
    ci_publickey = values.get("ci_publickey")
    ci_upgrade = values.get('ci_upgrade')
    ci_network = values.get('ci_network')
    if ci_network.upper() == "STATIC":
        ci_gwadvalue = values.get("ci_gwadvalue")
        ci_ipaddress = values.get("ci_ipaddress")
        ci_netmask = values.get("ci_netmask")

    functions.output_message(
        f"Checking Cloud-Init input for '{name}'.",
        "i"
    )

    command = f"qm config {id}"
    scr_config_info = functions.execute_ssh_command(
        ssh,
        command,
        f"Failed to get status for {name}."
    )

    compare = False
    if scr_config_info is not None:
        compare = True

    usr_value = None
    pwd_value = None
    domain_value = None
    ns_value = None
    key_value = None
    upg_value = None
    net_ip_value = None
    net_gw_value = None

    if compare:
        usr_str = functions.get_status_info("ciuser", scr_config_info)
        pwd_str = functions.get_status_info("cipassword", scr_config_info)
        domain_str = functions.get_status_info("searchdomain", scr_config_info)
        ns_str = functions.get_status_info("nameserver", scr_config_info)
        key_str = functions.get_status_info("sshkeys", scr_config_info)
        upg_int = functions.get_status_info("ciupgrade", scr_config_info)
        net_str = functions.get_status_info("ipconfig0", scr_config_info)

        if usr_str is not None:
            usr_value = usr_str

        if pwd_str is not None:
            pwd_value = pwd_str

        if domain_str is not None:
            domain_value = domain_str

        if ns_str is not None:
            ns_value = ns_str

        if key_str is not None:
            key_value = unquote(key_str)

        if upg_int is not None:
            upg_value = int(upg_int)

        if net_str is not None:
            net_ip_value = functions.get_config_info("ip", net_str)
            net_gw_value = functions.get_config_info("gw", net_str)

        regenerate = False

    try:

        if ci_username:
            ci_usr_upd = False
            if usr_value is None or not ci_username == usr_value:
                ci_usr_upd = True
                regenerate = True

            if ci_usr_upd:
                command = (
                    f"qm set {id} --ciuser {ci_username}"
                )
                functions.execute_ssh_command(
                    ssh,
                    command,
                    "Failed to set user"
                )
                functions.output_message(
                    f"Changing 'Username' to {ci_username}.",
                    "s"
                )

        if ci_password:
            ci_pwd_upd = False
            if ci_password and not pwd_value == "**********":
                ci_pwd_upd = True

            if ci_pwd_upd:
                command = (
                    f"qm set {id} --cipassword {ci_password}"
                )
                functions.execute_ssh_command(
                    ssh,
                    command,
                    "Failed to set password"
                )
                functions.output_message(
                    "Changing password.",
                    "s"
                )

        if ci_domain:
            ci_dns_upd = False
            if domain_value is None or not ci_domain == domain_value:
                ci_dns_upd = True
                regenerate = True

            if ci_dns_upd:
                command = (
                    f"qm set {id} --searchdomain {ci_domain}"
                )
                functions.execute_ssh_command(
                    ssh,
                    command,
                    "Failed to set dns domain"
                )
                functions.output_message(
                    f"Changing searchdomain to {ci_domain}.",
                    "s"
                )

        if ci_dns_server:
            ci_ns_upd = False
            if ns_value is None or not ci_dns_server == ns_value:
                ci_ns_upd = True
                regenerate = True

            if ci_ns_upd:
                command = (
                    f"qm set {id} --nameserver {ci_dns_server}"
                )
                functions.execute_ssh_command(
                    ssh,
                    command,
                    "Failed to set dns server ip"
                )
                functions.output_message(
                    f"Changing nameserver to {ci_dns_server}.",
                    "s"
                )

        if ci_publickey:
            ci_key_upd = False
            decoded_key = None
            if key_value is not None:
                decoded_key = urllib.parse.unquote(key_value).replace(
                    "\n",
                    " "
                )
            ci_key_upd = False
            for pubkey in ci_publickey:
                if decoded_key is None or pubkey not in decoded_key:
                    ci_key_upd = True
                    regenerate = True
                    break

            if ci_key_upd:
                create_ssh_public_key(ssh, values)

        if ci_upgrade:
            ci_upg_upd = False
            if upg_value is None or not ci_upgrade == upg_value:
                ci_upg_upd = True
                regenerate = True

            if ci_upg_upd:
                command = (
                    f"qm set {id} --ciupgrade {ci_upgrade}"
                )
                functions.execute_ssh_command(
                    ssh,
                    command,
                    "Failed to set update flag"
                )
                functions.output_message(
                    f"Changing 'Upgrade' to {ci_upgrade}.",
                    "s"
                )

        if ci_network:
            ci_net_upd = False

            if ci_network.upper() == "DHCP":
                if (
                    net_ip_value is None or
                    not ci_network.upper() == net_ip_value.upper()
                ):
                    ci_net_upd = True
                    regenerate = True

                if ci_net_upd:
                    command = f"qm set {id} --ipconfig0 ip=dhcp"
                    functions.execute_ssh_command(
                        ssh,
                        command,
                        "Failed to set network to DHCP"
                    )
                    functions.output_message(
                        "Changing network to DHCP.",
                        "s"
                    )

            if ci_network.upper() == "STATIC":
                ip_str = f"{ci_ipaddress}/{ci_netmask}"
                if str(net_ip_value) is None:
                    ci_net_upd = True
                    regenerate = True
                elif ip_str != net_ip_value or ci_gwadvalue != net_gw_value:
                    ci_net_upd = True
                    regenerate = True

                if ci_net_upd:
                    first_line = f"qm set {id} --ipconfig0"
                    second_line = f" gw={ci_gwadvalue},ip={ci_ipaddress}"
                    third_line = f"/{ci_netmask}"
                    command = first_line+second_line+third_line
                    functions.execute_ssh_command(
                        ssh,
                        command,
                        "Failed to set network to static ip"
                    )
                    functions.output_message(
                        "Changing network config.",
                        "s"
                    )

        functions.output_message(
            f"Cloud-Init checked for '{name}'.",
            "s"
        )

        if regenerate:
            values["vm_reboot"] = True
            functions.output_message(
                f"Cloud-Init image for '{name}' must be regenerated.",
                "w"
            )
            functions.output_message(
                f"Server '{name}' will restart to apply changes.",
                "w"
            )
            command = f"qm cloudinit update {id}"
            functions.execute_ssh_command(
                ssh,
                command,
                "Failed to update cloud-init image"
            )

    except Exception as e:
        functions.output_message(
            f"Failed to set cloud-init settings: {e}",
            "e"
        )


def start_vm(ssh, values):
    id = values.get("id")
    name = values.get("name")

    command = f"qm status {id}"
    result = functions.execute_ssh_command(
        ssh,
        command,
        f"Failed to get status of virtual server '{name}"
    )
    if not result == "status: running":
        try:
            functions.output_message(
                f"Attempting to start virtual server '{name}'.",
                "i"
            )
            command = f"qm start {id}"
            result = functions.execute_ssh_command(
                ssh,
                command,
                f"Failed to start virtual server '{name}"
            )
            functions.output_message(
                f"{result}",
                "s"
            )
            functions.output_message(
                f"Virtual server '{name}' started.",
                "s"
            )
            values["vm_reboot"] = False

        except Exception as e:
            functions.output_message(
                f"Failed to execute command on Proxmox host: {e}",
                "e"
            )

    else:
        functions.output_message(
            f"Virtual server '{name}' already started.",
            "s"
        )
        values["vm_status"] = "running"


def get_vm_ipv4_address(ssh, values):

    def ssh_connect(host, username, timeout=1,  key_filename=None):
        """Establish a new SSH connection to the specified host."""
        try:
            ssh_client = paramiko.SSHClient()
            ssh_client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            ssh_client.connect(
                hostname=host,
                username=username,
                timeout=timeout,
                key_filename=key_filename
            )
            return ssh_client
        except Exception:
            return None

    def get_remote_hostname(ssh_client):
        """Retrieve the hostname of the remote system."""
        try:
            stdin, stdout, stderr = ssh_client.exec_command("hostname")
            hostname = stdout.read().decode().strip()
            return hostname if hostname else None
        except Exception:
            return None

    id = values.get("id")
    name = values.get("name")
    ci_username = values.get("ci_username")
    ci_ipaddress = values.get("ci_ipaddress")
    ci_network = values.get("ci_network")
    vlan = values.get("vlan")

    # If the network type is STATIC and an IP address is provided, return it
    if ci_network.upper() == "STATIC" and ci_ipaddress:
        vm_status = None
        vm_status = values.get("vm_status")
        if vm_status is None:
            functions.output_message(
                "Allowing for vm to fully boot",
                "s"
            )
            time.sleep(90)

        return ci_ipaddress

    max_wait_time = 300
    check_interval = 10
    total_waited = 0

    # Step 1: Wait for the VM to be "running"
    while total_waited < max_wait_time:
        try:
            command = f"qm status {id}"
            result = functions.execute_ssh_command(
                ssh,
                command,
                f"Failed to get status of VM '{name}'"
            )

            if result.lower() == "status: running":
                break

            message = (
                f"'{name}' not running - retrying in {check_interval} sec."
            )
            functions.output_message(message, "w")
            total_waited += check_interval
            time.sleep(check_interval)

        except Exception as e:
            error_message = f"'{name}' Failed to get VM status: {e}"
            functions.output_message(error_message, "e")
            total_waited += check_interval
            time.sleep(check_interval)

    if total_waited >= max_wait_time:
        functions.output_message(
            f"'{name}' did not start within {max_wait_time} seconds.", "e"
        )
        return None

    # Step 2: Attempt to connect to each IP in the subnet
    try:
        vm_status = None
        vm_status = values.get("vm_status")
        if vm_status is None:
            functions.output_message(
                "Allowing for vm to fully (re)boot",
                "s"
            )
            time.sleep(90)

        if vm_status == "running":
            ssh1 = None
            host = values.get("host_ip")
            user = values.get("username")
            ssh1 = functions.ssh_connect(host, user, "", vm.PVE_KEYFILE)
            command = f"qm agent {id} network-get-interfaces"
            dhcp_ip_info = functions.execute_ssh_command(
                ssh1,
                command,
                f"Failed to get status for {name}."
            )
            ssh1.close
            dhcp_ip = json.loads(dhcp_ip_info)
            # Loop through the interfaces to find 'eth0' and its IPv4 address
            ipv4_address = None
            for interface in dhcp_ip:
                if interface.get("name") == "eth0":
                    for ip in interface.get("ip-addresses", []):
                        if ip.get("ip-address-type") == "ipv4":
                            ipv4_address = ip.get("ip-address")
                            break
            if ipv4_address is not None:
                return ipv4_address
            else:
                return None
        else:
            ci_subnet = f"{vm.DEFAULT_PREFIX}{vlan}"
            if ci_network.upper() == "DHCP" and ci_subnet:
                vm_keyfile = vm.VM_KEYFILE
                try:
                    functions.output_message(
                        "Scanning VLAN to find host-ip.",
                        "i"
                    )
                    for i in range(3, 255):
                        ip_str = f"{ci_subnet}.{i}"
                        new_ssh = None
                        try:
                            # Create a new SSH connection for the target VM
                            new_ssh = ssh_connect(
                                ip_str,
                                ci_username,
                                1,
                                vm_keyfile
                            )
                            if new_ssh:
                                hostname = get_remote_hostname(new_ssh)
                                if hostname == name:
                                    functions.output_message(
                                        f"connected to '{ip_str}' - "
                                        f"Hostname: {hostname}", "s"
                                    )
                                    return ip_str
                        except Exception as e:
                            functions.output_message(
                                f"Failed to connect to {ip_str}: {e}", "w"
                            )
                        finally:
                            if new_ssh:
                                new_ssh.close()  # Close the new SSH connection

                        functions.output_message(
                            f"VM not found on {ip_str}, continueing scan...",
                            "i"
                        )
                except ValueError:
                    functions.output_message(
                        f"Invalid subnet '{ci_subnet}' provided.",
                        "e"
                    )

                    return None

    except NameError:
        functions.output_message("DEFAULT_PREFIX is not defined.", "e")

    return None


def on_guest_configuration(ssh, values, ipaddress):
    def compare_sshd_paths(local_sshd_customfile):
        # Check if the directory of local_sshd_customfile
        # matches the SSHD_CONFIG directory."""
        local_dir = os.path.dirname(local_sshd_customfile)
        config_dir = os.path.dirname(vm.SSHD_CONFIG[0])
        return local_dir == config_dir

    # install agent
    try:
        command = "which qemu-ga"
        stdin, stdout, stderr = ssh.exec_command(command)
        stdout.read().decode().strip()

        qemu_ga = stdout.read().decode().strip()

        if qemu_ga == "/usr/sbin/qemu-ga":

            functions.output_message(
                (
                    "QEMU agent already installed on VM."
                ),
                "s"
            )
        else:
            cmd1 = "sudo apt update && "
            cmd2 = "sudo apt install qemu-guest-agent -y && "
            cmd3 = "sudo systemctl enable --now qemu-guest-agent"
            install_qemu_cmd = cmd1+cmd2+cmd3
            functions.execute_ssh_command(
                ssh,
                install_qemu_cmd,
                "Failed to install QEMU agent"
                )

            functions.output_message(
                (
                    "QEMU agent installed."
                ),
                "s"
            )

    except Exception as e:
        functions.output_message(
            (
                "Failed to execute command on ",
                f"{ipaddress}: {e}",
            ),
            "e"
        )

    # Set BASH shell on VM
    try:
        command = "echo $SHELL"
        current_shell = functions.execute_ssh_command(
            ssh,
            command,
            "Failed to query shell vm"
        )

        if current_shell == "/bin/bash":
            functions.output_message(
                (
                    "Shell is already set to BASH."
                ),
                "s"
            )
        else:
            ci_password = values.get("ci_password")
            change_shell_cmd = f"echo '{ci_password}' | chsh -s /bin/bash"
            current_shell = functions.execute_ssh_command(
                ssh,
                change_shell_cmd,
                "Failed to change shell to BASH"
                )
            if current_shell == "/bin/bash":
                functions.output_message(
                    (
                        "Shell changed to BASH."
                    ),
                    "s"
                )

    except Exception as e:
        functions.output_message(
                            (
                                "Failed to execute command on ",
                                f"{ipaddress}: {e}",
                            ),
                            "e"
                        )

    # Set SSHD_CONFIG setting on VM
    for iteration in range(2):
        conf_file_dir = []
        conf_files = []
        try:
            # Step 1: Gather list of configuration files
            # Check if config_file has include statements to other *.conf files
            for conf_file in vm.SSHD_CONFIG:
                command = f"cat {conf_file}"
                stdin, stdout, stderr = ssh.exec_command(command)
                for line_number, line in enumerate(stdout, start=1):
                    if line.startswith(vm.SSHD_SEARCHSTRING):
                        elements = line.split()
                        for element in elements:
                            if element.startswith("/"):
                                if "*" in element:
                                    conf_file_dir.append(element)
                                else:
                                    vm.SSHD_CONFIG.append(element)

            # Find all files matching the pattern
            # specified in include statements
            for pattern in conf_file_dir:
                command = f"ls {pattern} 2>/dev/null"
                stdin, stdout, stderr = ssh.exec_command(command)
                matched_files = stdout.read().decode().splitlines()
                conf_files.extend(matched_files)

            for file in conf_files:
                vm.SSHD_CONFIG.append(file)

            # Step 2: Run through all files found to
            # check if parameters have been set
            # Tracks parameters that are set correctly
            params_no_change = {}
            # Tracks parameters that are missing
            params_to_add = vm.SSH_CONST.copy()
            # Tracks parameters that need to be changed
            params_to_change = {}

            # Check each parameter in every configuration file
            for param, expected_value in vm.SSH_CONST.items():
                param_found = False  # Track if parameter was found in any file
                for conf_file in vm.SSHD_CONFIG:
                    command = f"cat {conf_file}"
                    stdin, stdout, stderr = ssh.exec_command(command)
                    for line_number, line in enumerate(stdout, start=1):
                        if line.startswith(param):
                            param_found = True
                            if expected_value in line:
                                params_no_change[param] = expected_value
                            else:
                                params_to_change[param] = {
                                    "expected_value": expected_value,
                                    "conf_file": conf_file
                                }

                if not param_found:
                    # Parameter was not found in any
                    # of the configuration files
                    functions.output_message(
                        (
                            f"'{param}' is missing in all "
                            "configuration files."
                        ),
                        "i"
                    )

            # Remove the verified parameters from params_to_add
            for verified_param in params_no_change:
                if verified_param in params_to_add:
                    del params_to_add[verified_param]

            # Remove the parameters that need modification from params_to_add
            for verified_param in params_to_change:
                if verified_param in params_to_add:
                    del params_to_add[verified_param]

            if len(params_to_change) > 0:
                for param, values in params_to_change.items():
                    expected_value = values["expected_value"]
                    path_value = values["conf_file"]
                    param_found = False
                    command = f"cat {path_value}"
                    stdin, stdout, stderr = ssh.exec_command(command)
                    for line_number, line in enumerate(stdout, start=1):
                        if line.startswith(param):
                            param_found = True
                            if param in line:
                                command = (
                                    f"sudo sed -i 's/^{param} .*/{param} "
                                    f"{expected_value}/' {path_value}"
                                )
                                functions.execute_ssh_command(
                                    ssh,
                                    command,
                                    (
                                        "Failed to modify paramter: "
                                        f"{param} {expected_value} "
                                        f"in {path_value}"
                                    )
                                )
                                functions.output_message(
                                    (
                                        "Modified paramter: "
                                        f"{param} {expected_value} "
                                        f"in {path_value}"
                                    ),
                                    "s"
                                )

            if len(params_to_add) > 0:
                # Use the parth from first found include in conf_file_dir
                # for SSHD_CUSTOMFILE filename
                # and if no Include is found then use the path of the
                # initial SSHD_CONFIG file for the SSHD_CUSTOMFILE filename
                if conf_file_dir:
                    # Use the directory from the first Include found
                    # as the target directory for the custom file
                    include_dir = os.path.dirname(conf_file_dir[0])
                else:
                    # Use the directory of the first
                    # SSHD_CONFIG file as the fallback
                    include_dir = os.path.dirname(vm.SSHD_CONFIG[0])

                local_sshd_customfile = os.path.join(
                    include_dir,
                    os.path.basename(vm.SSHD_CUSTOMFILE)
                    )

                if local_sshd_customfile not in vm.SSHD_CONFIG:
                    command = f"sudo touch {local_sshd_customfile}"
                    functions.execute_ssh_command(
                        ssh,
                        command,
                        (
                            f"Failed to touch {local_sshd_customfile}"
                        )
                    )
                    command = f"sudo chmod 644 {local_sshd_customfile}"
                    functions.execute_ssh_command(
                        ssh,
                        command,
                        (
                            "Failed to change permissions "
                            f"on {local_sshd_customfile}"
                        )
                    )
                    functions.output_message(
                        (
                            "Created "
                            f"{local_sshd_customfile}."
                        ),
                        "s"
                    )
                    if compare_sshd_paths(local_sshd_customfile):
                        cmd1 = f"echo 'Include {local_sshd_customfile}' | "
                        cmd2 = f"sudo tee -a {vm.SSHD_CONFIG[0]}"

                        command = cmd1+cmd2
                        functions.execute_ssh_command(
                            ssh,
                            command,
                            (
                                "Failed to include "
                                f"{local_sshd_customfile} "
                                f"in {vm.SSHD_CONFIG[0]}"
                            )
                        )
                        functions.output_message(
                            (
                                "Included "
                                f"{local_sshd_customfile} in "
                                f"{vm.SSHD_CONFIG[0]}"
                            ),
                            "s"
                        )

                for param, value in params_to_add.items():
                    command = (
                            f"echo {param} {value} | "
                            f"sudo tee -a {local_sshd_customfile}"
                        )
                    functions.execute_ssh_command(
                        ssh,
                        command,
                        (
                            "Error adding "
                            f"{param} {value}"
                            f" to {local_sshd_customfile}"
                        )
                    )
                    functions.output_message(
                        (
                            "Added paramter: "
                            f"{param} {expected_value} to "
                            f"{local_sshd_customfile}"
                        ),
                        "s"
                    )

        except Exception as e:
            print(f"An error occurred: {e}")
            functions.output_message(f"An error occurred: {e}.", "e")

        finally:
            if len(params_to_change) > 0 or len(params_to_add) > 0:
                command = "sudo systemctl restart ssh"
                functions.execute_ssh_command(
                    ssh,
                    command,
                    "Failed to restart SSH service"
                )
                functions.output_message(
                    "Restarted SSH service",
                    "s"
                )

        if iteration == 0:
            time.sleep(5)

    functions.output_message(
        "SSH configuration verified",
        "s"
    )

    vm_reboot = values.get("vm_reboot")
    if vm_reboot:
        command = "sudo reboot"
        functions.execute_ssh_command(
                ssh,
                command,
                "Failed to reboot VM"
                )
        functions.output_message(
            "VM rebooting....",
            "w"
        )


os.system('cls' if os.name == 'nt' else 'clear')
config_file = None
try:
    config_file = sys.argv[1]
except Exception as e:
    if config_file is None:
        functions.output_message()
        functions.output_message(
            f"Missig json-file arg: {e}",
            "e"
        )

script_directory = os.path.dirname(os.path.abspath(__file__))

functions.output_message()
functions.output_message("script info:", "h")
functions.output_message()
functions.output_message(f"Parameter filename: {config_file}")
functions.output_message(f"Script directory  : {script_directory}")
functions.output_message()
config = load_config(config_file)
values = get_config_values(config)

functions.output_message()
functions.output_message("Validate config values", "h")
functions.output_message()
functions.integer_check(values, vm.INTEGER_KEYS)

functions.output_message()
functions.output_message("Build virtual server", "h")
functions.output_message()

host_ip = values.get("host_ip")
username = values.get("username")
ssh = None
try:
    ssh = functions.ssh_connect(host_ip, username, "", vm.PVE_KEYFILE)
    if ssh is not None:
        create_server(ssh, values)
        create_ci_options(ssh, values)
        start_vm(ssh, values)

        # Wait and get the VM's IPv4 address
        vm_ipaddress = get_vm_ipv4_address(ssh, values)
        ssh.close()

except Exception as e:
    functions.output_message(
        f"SSH connection to PVE host failed: {e}",
        "e"
    )

ssh = None
try:
    # login as user cloud-init shpuld have created
    ci_username = values.get("ci_username")
    ssh = functions.ssh_connect(vm_ipaddress, ci_username, "", vm.VM_KEYFILE)
    if ssh is not None:
        on_guest_configuration(ssh, values, ipaddress)
        ssh.close()
        functions.output_message()

except Exception as e:
    functions.output_message(
        f"SSH connection to VM failed: {e}",
        "e"
    )
