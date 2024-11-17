#!/usr/bin/env python3
from urllib.parse import unquote
from lib import functions
from const.vm_const import (MANDATORY_KEYS, OPTIONAL_KEYS, INTEGER_KEYS,
                            SSH_CONST, SSHD_CONFIG, SSHD_SEARCHSTRING,
                            SSHD_CUSTOMFILE, DEFAULT_BALLOON,
                            DEFAULT_START_AT_BOOT, DEFAULT_CI_UPGRADE,
                            DEFAULT_USER, PVE_KEYFILE
                            )


import os
import json
import sys
import time

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


def get_json_values(config):
    # Extract needed variables from JSON file
    return {
        "user": config.get("USER").get("username"),
        "host": config.get("HOST").get("host_ip"),
        "template_id": config.get("TEMPLATE").get("clone_id"),
        "id": config.get("ID").get("id"),
        "name": config.get("NAME").get("name"),
        "disk": config.get("DISK").get("disk"),
        "cores": config.get("CORES").get("cores"),
        "mem": config.get("MEM").get("memory"),
        "balloon": config.get("BALLOON").get("balloon"),
        "driver": config.get("NET_DRIVER").get("driver"),
        "bridge": config.get("BRIDGE").get("bridge"),
        "vlan": config.get("VLAN").get("vlan"),
        "start_at_boot": config.get("START_AT_BOOT").get("boot_start"),
        "ci_username": config.get("CLOUDINIT_USER").get("ci_username"),
        "ci_password": config.get("CLOUDINIT_PW").get("ci_password"),
        "ci_publickey": config.get("CLOUDINIT_PUB_KEY").get("ci_publickey"),
        "ci_network": config.get("CLOUDINIT_NET").get("ci_network"),
        "ci_domain": config.get("CLOUDINIT_DNS_DOMAIN").get("ci_domain"),
        "ci_dns_server": config.get(
            "CLOUDINIT_DNS_SERVER").get("ci_dns_server"),
        "ci_upgrade": config.get("CLOUDINIT_UPGRADE").get("ci_upgrade"),
        "ci_ipaddress": config.get("CLOUDINIT_IP").get("ci_ipaddress"),
        "ci_gwadvalue": config.get("CLOUDINIT_GW").get("ci_gwadvalue"),
        "ci_netmask": config.get("CLOUDINIT_MASK").get("ci_netmask")
    }


def check_conditional_values(values):
    if not values.get("balloon"):
        values["balloon"] = DEFAULT_BALLOON

    if not values.get("start_at_boot"):
        values["start_at_boot"] = DEFAULT_START_AT_BOOT

    if not values.get("ci_upgrade"):
        values["ci_upgrade"] = DEFAULT_CI_UPGRADE

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

    vm_name = values.get("name")
    ci_domain = values.get("ci_domain")
    if vm_name:
        if ci_domain:
            fqdn = f"{vm_name}.{ci_domain}"
            functions.is_valid_hostname(fqdn)
        else:
            functions.is_valid_hostname(vm_name)


def create_server(ssh, values):
    # Create the server template on the Proxmox host.
    vm_id = values.get("id")
    template_id = values.get("template_id")
    vm_name = values.get("name")
    vm_cores = values.get("cores")
    vm_mem = values.get("mem")
    vm_disk = values.get("disk")
    vm_balloon = values.get('balloon')
    vm_onboot = values.get('start_at_boot')
    vm_driver = values.get('driver')
    vm_bridge = values.get('bridge')
    vm_vlan = values.get('vlan')

    functions.output_message(
        f"Checking configuration for '{vm_name}'.",
        "s"
    )

    vm_id_in_use = functions.check_if_id_in_use(ssh, vm_id)
    scr_string = None
    scr_config_info = None

    if vm_id_in_use:
        command = f"qm status {vm_id} --verbose"
        scr_string = functions.execute_ssh_command(
            ssh,
            command,
            f"Failed to get status for {vm_name}."
        )

        command = f"qm config {vm_id}"
        scr_config_info = functions.execute_ssh_command(
            ssh,
            command,
            f"Failed to get status for {vm_name}."
        )

    compare = False

    if scr_string is not None and scr_config_info is not None:
        compare = True

    name_value_str = None
    core_value_str = None
    memory_size_str = None
    disk_size_str = None
    balloon_str = None
    onboot_str = None
    net_str = None
    bridge_str = None
    vlan_str = None

    name_value = None
    core_value = None
    memory_size = None
    disk_size = None
    balloon = None
    onboot = None
    bridge = None
    vlan = None

    if compare:
        name_value_str = functions.get_status_info("name", scr_string)
        core_value_str = functions.get_status_info("cpus", scr_string)
        memory_size_str = functions.get_status_info("maxmem", scr_string)
        disk_size_str = functions.get_status_info("maxdisk", scr_string)
        balloon_str = functions.get_status_info("balloon", scr_config_info)
        onboot_str = functions.get_status_info("onboot", scr_config_info)
        net_str = functions.get_status_info("net0", scr_config_info)
        bridge_str = functions.get_config_info("bridge", net_str)
        vlan_str = functions.get_config_info("tag", net_str)

        if name_value_str is not None:
            name_value = name_value_str

        if core_value_str is not None:
            core_value = int(core_value_str)

        if memory_size_str is not None:
            memory_size = int(memory_size_str) / (1024 * 1024)

        if disk_size_str is not None:
            disk_size = int(disk_size_str) / (1024 * 1024 * 1024)

        if balloon_str is not None:
            balloon = int(balloon_str)

        if onboot_str is not None:
            onboot = int(onboot_str)

        if bridge_str is not None:
            bridge = bridge_str

        if vlan_str is not None:
            vlan = int(vlan_str)

    try:

        if vm_id_in_use is False:
            command = f"qm clone {template_id} {vm_id} --full 1"
            functions.execute_ssh_command(
                ssh,
                command,
                f"Failed to clone {vm_name} from {template_id}."
            )
            functions.output_message(
                f"Provisioning of virtual server '{vm_name}' started.",
                "s"
            )

        if vm_id_in_use:
            functions.output_message(
                f"ID '{vm_id}' exists. No new instance, only updating..",
                "W"
            )

        if vm_name:
            vm_name_upd = False
            if name_value is None or not vm_name == name_value:
                vm_name_upd = True

            if vm_name_upd:
                command = f"qm set {vm_id} --name {vm_name}"
                functions.execute_ssh_command(
                    ssh,
                    command,
                    f"'{command}' failed on the Proxmox host."
                )

                functions.output_message(
                    f"Changing name to: {vm_name}.",
                    "s"
                )

        if vm_cores:
            vm_cores_upd = False
            if core_value is None or not vm_cores == core_value:
                vm_cores_upd = True

            if vm_cores_upd:
                command = f"qm set {vm_id} --cores {vm_cores}"
                functions.execute_ssh_command(
                    ssh,
                    command,
                    f"'{command}' failed on the Proxmox host."
                )
                functions.output_message(
                    f"Changing CPU cores to: {vm_cores}.",
                    "s"
                )

        if vm_mem:
            vm_mem_upd = False
            if memory_size is None or not vm_mem == memory_size:
                vm_mem_upd = True

            if vm_mem_upd:
                command = f"qm set {vm_id} --memory {vm_mem}"
                functions.execute_ssh_command(
                    ssh,
                    command,
                    f"'{command}' failed on the Proxmox host."
                )
                functions.output_message(
                    f"Changing memory to: {vm_mem}MB.",
                    "s"
                )

        if vm_disk:
            vm_disk_upd = False
            if disk_size is None or not vm_disk == disk_size:
                vm_disk_upd = True

            if vm_disk_upd:
                command = f"qm disk resize {vm_id} scsi0 {values.get('disk')}G"
                functions.execute_ssh_command(
                    ssh,
                    command,
                    f"'{command}' failed on the Proxmox host."
                )
                functions.output_message(
                    f"Changing disk sioze to: {vm_disk}GB.",
                    "s"
                )

        if vm_balloon:
            vm_balloon_upd = False
            if balloon is None or not vm_balloon == balloon:
                vm_balloon_upd = True

            if vm_balloon_upd:
                command = f"qm set {vm_id} --balloon {vm_balloon}"
                functions.execute_ssh_command(
                    ssh,
                    command,
                    f"'{command}' failed on the Proxmox host."
                )
                functions.output_message(
                    f"Changing 'Ballooning' to: {vm_balloon}.",
                    "s"
                )

        if vm_onboot:
            vm_onboot_upd = False
            if onboot is None or not vm_onboot == onboot:
                vm_onboot_upd = True

            if vm_onboot_upd:
                command = f"qm set {vm_id} --onboot {vm_onboot}"
                functions.execute_ssh_command(
                    ssh,
                    command,
                    f"'{command}' failed on the Proxmox host."
                )
                functions.output_message(
                    f"Changing 'Start at boot' to: {vm_onboot}.",
                    "s"
                )

        if vm_bridge:
            vm_bridge_upd = False
            if bridge is None or not vm_bridge == bridge:
                vm_bridge_upd = True

            if vm_vlan:
                if str(vlan) is None or not vm_vlan == vlan:
                    vm_bridge_upd = True

            if vm_bridge_upd:
                net_driver = f"{vm_driver}"
                net_bridge = f"bridge={vm_bridge}"
                net_tag = f"tag={vm_vlan}"

                ln1 = f"qm set {vm_id} --net0 {net_driver},"
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
        f"Configuration checked for '{vm_name}'.",
        "s"
    )


def create_ssh_public_key(ssh, values):
    vm_id = values.get("id")
    vm_name = values.get("name")
    filename = "/tmp/temp_key.pub"
    sftp = ssh.open_sftp()
    try:
        if values.get("ci_publickey"):
            sftp = ssh.open_sftp()
            try:
                with sftp.file(filename, 'w') as file:
                    file.write(values.get("ci_publickey"))
                command = f"qm set {vm_id} --sshkeys {filename}"
                functions.execute_ssh_command(
                    ssh,
                    command,
                    "Failed to set default user public key"
                )
                sftp.remove(filename)
            except FileNotFoundError:
                functions.output_message(
                     "Error extracting SSH publickey from ",
                     f"'{filename}' on virtual server '{vm_name}'.",
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
    vm_name = values.get("name")
    vm_id = values.get("id")
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
        f"Checking Cloud-Init input for '{vm_name}'.",
        "i"
    )

    command = f"qm config {vm_id}"
    scr_config_info = functions.execute_ssh_command(
        ssh,
        command,
        f"Failed to get status for {vm_name}."
    )

    compare = False
    if scr_config_info is not None:
        compare = True

    usr = None
    pwd = None
    domain = None
    ns = None
    key = None
    upg = None
    net_ip = None
    net_gw = None

    if compare:
        usr_str = functions.get_status_info("ciuser", scr_config_info)
        pwd_str = functions.get_status_info("cipassword", scr_config_info)
        domain_str = functions.get_status_info("searchdomain", scr_config_info)
        ns_str = functions.get_status_info("nameserver", scr_config_info)
        key_str = functions.get_status_info("sshkeys", scr_config_info)
        upg_int = functions.get_status_info("ciupgrade", scr_config_info)
        net_str = functions.get_status_info("ipconfig0", scr_config_info)

        if usr_str is not None:
            usr = usr_str

        if pwd_str is not None:
            pwd = pwd_str

        if domain_str is not None:
            domain = domain_str

        if ns_str is not None:
            ns = ns_str

        if key_str is not None:
            key = unquote(key_str)

        if upg_int is not None:
            upg = int(upg_int)

        if net_str is not None:
            net_ip = functions.get_config_info("ip", net_str)
            net_gw = functions.get_config_info("gw", net_str)

        regenerate = False

    try:

        if ci_username:
            ci_usr_upd = False
            if usr is None or not ci_username == usr:
                ci_usr_upd = True
                regenerate = True

            if ci_usr_upd:
                command = (
                    f"qm set {vm_id} --ciuser {ci_username}"
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
            if ci_password and not pwd == "**********":
                ci_pwd_upd = True

            if ci_pwd_upd:
                command = (
                    f"qm set {vm_id} --cipassword {ci_password}"
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
            if domain is None or not ci_domain == domain:
                ci_dns_upd = True
                regenerate = True

            if ci_dns_upd:
                command = (
                    f"qm set {vm_id} --searchdomain {ci_domain}"
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
            if ns is None or not ci_dns_server == ns:
                ci_ns_upd = True
                regenerate = True

            if ci_ns_upd:
                command = (
                    f"qm set {vm_id} --nameserver {ci_dns_server}"
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
            if key is None or not ci_publickey == key:
                ci_key_upd = True

            if ci_key_upd:
                create_ssh_public_key(ssh, values)

        if ci_upgrade:
            ci_upg_upd = False
            if upg is None or not ci_upgrade == upg:
                ci_upg_upd = True
                regenerate = True

            if ci_upg_upd:
                command = (
                    f"qm set {vm_id} --ciupgrade {ci_upgrade}"
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
                if net_ip is None or not ci_network.upper() == net_ip.upper():
                    ci_net_upd = True
                    regenerate = True

                if ci_net_upd:
                    command = f"qm set {vm_id} --ipconfig0 ip=dhcp"
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
                if str(net_ip) is None:
                    ci_net_upd = True
                    regenerate = True
                elif ip_str != net_ip or ci_gwadvalue != net_gw:
                    ci_net_upd = True
                    regenerate = True

                if ci_net_upd:
                    first_line = f"qm set {vm_id} --ipconfig0"
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
            f"Cloud-Init checked for '{vm_name}'.",
            "s"
        )

        if regenerate:
            functions.output_message(
                f"Cloud-Init image for '{vm_name}' must be regenerated.",
                "w"
            )
            functions.output_message(
                f"Server '{vm_name}' will restart to apply changes.",
                "w"
            )
            command = f"qm cloudinit update {vm_id}"
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
    vm_id = values.get("id")
    vm_name = values.get("name")

    command = f"qm status {vm_id}"
    result = functions.execute_ssh_command(
        ssh,
        command,
        f"Failed to get status of virtual server '{vm_name}"
    )
    if not result == "status: running":
        try:
            functions.output_message(
                f"Attempting to start virtual server '{vm_name}'.",
                "i"
            )
            command = f"qm start {vm_id}"
            result = functions.execute_ssh_command(
                ssh,
                command,
                f"Failed to start virtual server '{vm_name}"
            )
            functions.output_message(
                f"{result}",
                "s"
            )
            functions.output_message(
                f"Virtual server '{vm_name}' started successfully.",
                "s"
            )
        except Exception as e:
            functions.output_message(
                f"Failed to execute command on Proxmox host: {e}",
                "e"
            )
    else:
        functions.output_message(
            f"Virtual server '{vm_name}' already started.",
            "s"
        )
        values["vm_status"] = "running"


def get_vm_ipv4_address(ssh, values):
    vm_id = values.get("id")
    vm_name = values.get("name")
    ci_ipaddress = values.get("ci_ipaddress")

    if ci_ipaddress:
        return ci_ipaddress
    else:
        max_wait_time = 300  # max wait time in seconds
        check_interval = 10  # time interval between retries in seconds
        total_waited = 0

        while total_waited < max_wait_time:
            try:
                command = f"qm status {vm_id}"
                result = functions.execute_ssh_command(
                    ssh,
                    command,
                    f"Failed to start virtual server '{vm_name}"
                )

                if result == "status: running":
                    break
                else:
                    first_line = f"'{vm_name}' not running - retrying in "
                    third_line = f"{check_interval} sec."
                    functions.output_message(
                        first_line+third_line,
                        "w"
                    )
                    total_waited += check_interval
                    # Retry after the specified interval
                    time.sleep(check_interval)
                    continue

            except Exception as e:
                first_line = f"'{vm_name}' Failed to retrieve VM "
                secound_line = f"network interfaces: {e}"
                functions.output_message(
                    first_line+secound_line,
                    "e"
                )
                total_waited += check_interval
                # Retry after the specified interval
                time.sleep(check_interval)


def on_guest_configuration(ssh, values, ipaddress):
    def compare_sshd_paths(local_sshd_customfile):
        # Check if the directory of local_sshd_customfile
        # matches the SSHD_CONFIG directory."""
        local_dir = os.path.dirname(local_sshd_customfile)
        config_dir = os.path.dirname(SSHD_CONFIG[0])
        return local_dir == config_dir

    # install agent
    try:
        command = "which qemu-ga"
        qemu_ga = functions.execute_ssh_command(
            ssh,
            command,
            "Failed to query QEMU agent"
        )
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
                    "QEMU agent installed successfully."
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
                        "Shell changed to BASH successfully."
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
            for conf_file in SSHD_CONFIG:
                command = f"cat {conf_file}"
                stdin, stdout, stderr = ssh.exec_command(command)
                for line_number, line in enumerate(stdout, start=1):
                    if line.startswith(SSHD_SEARCHSTRING):
                        elements = line.split()
                        for element in elements:
                            if element.startswith("/"):
                                if "*" in element:
                                    conf_file_dir.append(element)
                                else:
                                    SSHD_CONFIG.append(element)

            # Find all files matching the pattern
            # specified in include statements
            for pattern in conf_file_dir:
                command = f"ls {pattern} 2>/dev/null"
                stdin, stdout, stderr = ssh.exec_command(command)
                matched_files = stdout.read().decode().splitlines()
                conf_files.extend(matched_files)

            for file in conf_files:
                SSHD_CONFIG.append(file)

            # Step 2: Run through all files found to
            # check if parameters have been set
            # Tracks parameters that are set correctly
            params_no_change = {}
            # Tracks parameters that are missing
            params_to_add = SSH_CONST.copy()
            # Tracks parameters that need to be changed
            params_to_change = {}

            # Check each parameter in every configuration file
            for param, expected_value in SSH_CONST.items():
                param_found = False  # Track if parameter was found in any file
                for conf_file in SSHD_CONFIG:
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
                                        "Successfully modified paramter: "
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
                    include_dir = os.path.dirname(SSHD_CONFIG[0])

                local_sshd_customfile = os.path.join(
                    include_dir,
                    os.path.basename(SSHD_CUSTOMFILE)
                    )

                if local_sshd_customfile not in SSHD_CONFIG:
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
                            "Successfully created "
                            f"{local_sshd_customfile}."
                        ),
                        "s"
                    )
                    if compare_sshd_paths(local_sshd_customfile):
                        cmd1 = f"echo 'Include {local_sshd_customfile}' | "
                        cmd2 = f"sudo tee -a {SSHD_CONFIG[0]}"

                        command = cmd1+cmd2
                        functions.execute_ssh_command(
                            ssh,
                            command,
                            (
                                "Failed to include "
                                f"{local_sshd_customfile} "
                                f"in {SSHD_CONFIG[0]}"
                            )
                        )
                        functions.output_message(
                            (
                                "Successfully included "
                                f"{local_sshd_customfile} in "
                                f"{SSHD_CONFIG[0]}"
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
                            "Successfully added paramter: "
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
                    "Successfully restarted SSH service",
                    "s"
                )

        if iteration == 0:
            time.sleep(5)

    functions.output_message(
        "SSH configuration successfully verified",
        "s"
    )

    # ci_username = values.get("ci_username")
    # functions.change_remote_password(ssh, ci_username, ci_password)


def on_host_temp_fix_create_cloudinit(ssh, values):
    functions.output_message()
    functions.output_message(
        (
            "Temp. ci-fix"
        ),
        "h"
    )
    functions.output_message()
    vm_id = values.get("id")
    vm_name = values.get("name")
    remote_filename = f"{vm_id}-cloud-init.yml"
    remote_path = f"/var/lib/vz/snippets/{remote_filename}"

    command = f"qm status {vm_id}"
    result = functions.execute_ssh_command(
        ssh,
        command,
        f"Failed to get status of virtual server '{vm_name}"
    )
    if not result == "status: running":

        try:
            # Cloud-init content with dynamic values
            cloud_init_content = """
#cloud-config
runcmd:
- apt install qemu-guest-agent -y
- sleep 5
- systemctl enable --now qemu-guest-agent
"""

            # Open SFTP session to write directly to the file
            sftp = ssh.open_sftp()
            with sftp.file(remote_path, 'w') as remote_file:
                remote_file.write(cloud_init_content)
            sftp.close()

            first_line = f"qm set {vm_id} --cicustom "
            second_line = f"'user=local:snippets/{remote_filename}'"
            command = first_line+second_line
            functions.execute_ssh_command(
                ssh,
                command,
                "Failed to set custom cloud-init file"
            )
            functions.output_message(
                f"Custom cloud-init file set for {vm_name} successfully.",
                "s"
            )

        except Exception as e:
            functions.output_message(
                f"Failed to create cloud-init file: {e}",
                "e"
            )


def on_host_temp_fix_cloudinit(ssh, values):
    functions.output_message()
    functions.output_message(
        (
            "Temp. ci-fix"
        ),
        "h"
    )
    functions.output_message()

    vm_id = values.get("id")

    try:
        # Set root password if `ci_password` is provided
        if values.get("ci_password"):
            ci_password = values.get('ci_password')
            set_password_cmd = (
                f"qm guest passwd {vm_id} ",
                f"{DEFAULT_USER} --password {ci_password}"
            )
            functions.execute_ssh_command(
                ssh,
                set_password_cmd,
                (
                     f"Failed to set password for '{DEFAULT_USER}' user"
                )
            )
            functions.output_message(
                (
                    f"Password set for '{DEFAULT_USER}' user successfully."
                ),
                "s"
            )

        # Add SSH public key to root's
        # authorized_keys if `ci_publickey` is provided
        if values.get("ci_publickey"):
            ci_publickey = values.get("ci_publickey")
            make_homedir_cmd = (
                f"qm guest exec {vm_id} -- mkdir -p home/{DEFAULT_USER}/.ssh"
            )
            functions.execute_ssh_command(
                ssh,
                make_homedir_cmd,
                (
                    f"Failed to create homedir for '{DEFAULT_USER}' user"
                )
            )

            add_to_authorized_keys = (
                f"qm guest exec {vm_id} -- sh -c '",
                f"echo \"{ci_publickey}\" >> ",
                f"/home/{DEFAULT_USER}/.ssh/authorized_keys'"
            )
            functions.execute_ssh_command(
                ssh,
                add_to_authorized_keys,
                (
                    "Failed to add public key to authorized_keys",
                    f" for '{DEFAULT_USER}' user"
                )
            )

            mod_file_permissions_cmd = (
                f"qm guest exec {vm_id} -- chmod 600 ",
                f"/home/{DEFAULT_USER}/.ssh/authorized_keys"
            )
            functions.execute_ssh_command(
                ssh,
                mod_file_permissions_cmd,
                (
                    "Failed to set filepermissions to ",
                    f"authorized_keys for '{DEFAULT_USER}' user"
                )
            )

            mod_folder_permissions_cmd = (
                f"qm guest exec {vm_id} -- "
                f"chmod 700 /home/{DEFAULT_USER}/.ssh"
            )
            functions.execute_ssh_command(
                ssh,
                mod_folder_permissions_cmd,
                (
                    "Failed to set filepermissions to .ssh ",
                    f"folder for '{DEFAULT_USER}' user"
                )
            )
            functions.output_message(
                (
                    "Public key added to authorized_keys ",
                    f"for '{DEFAULT_USER}' user."
                ),
                "s"
            )

    except Exception as e:
        functions.output_message(
            (
                f"Failed fix cloud-init settings: {e}."
            ),
            "e"
        )


def on_guest_temp_fix_cloudinit(ssh, values, ipaddress):
    # runs as the default ubuntu user with passwordless sudo priviliges
    ci_username = values.get("ci_username")
    ci_password = values.get("ci_password")
    ci_publickey = values.get("ci_publickey")

    functions.output_message(
        (
            "Temp. ci-fix"
        ),
        "h"
    )

    try:
        # Step 1: Check if user already exists
        check_user_cmd = f"id -u {ci_username}"
        result = functions.execute_ssh_command(ssh, check_user_cmd)
        if ci_username:
            if isinstance(result, int):
                functions.output_message(
                    (
                        f"User '{ci_username}' already exist.",
                        "No need to apply fix."
                    ),
                    "w"
                )
                return
            else:
                functions.output_message(
                    (
                        f"User '{ci_username}' does not exist.",
                        "Proceeding with user creation."
                    ),
                    "w"
                )

                # Create the user without setting the password initially
                add_user_cmd = f"sudo useradd -m {ci_username}"
                functions.execute_ssh_command(
                    ssh,
                    add_user_cmd,
                    (
                        f"Failed to add user '{ci_username}'"
                    )
                )
                functions.output_message(
                    (
                        f"User '{ci_username}' added",
                    ),
                    "s"
                )

                # Add user to sudo group
                add_sudo_cmd = (
                    f"sudo usermod -aG sudo {ci_username}"
                )
                functions.execute_ssh_command(
                    ssh,
                    add_sudo_cmd,
                    (
                        f"Failed to add user '{ci_username}' to sudo group"
                    )
                )
                functions.output_message(
                    (
                        f"User '{ci_username}' added to ",
                        "sudo group."
                    ),
                    "s"
                )

                # Set the user's password
                set_password_cmd = (
                    f"echo '{ci_username}:{ci_password}' ",
                    "| sudo chpasswd"
                )
                functions.execute_ssh_command(
                    ssh,
                    set_password_cmd,
                    (
                        f"Failed to set password for user '{ci_username}'"
                    )
                )
                functions.output_message(
                    (
                        "Password set successfully for user ",
                        f"'{ci_username}'."
                    ),
                    "s"
                )

                # Step 3: Add SSH public key to authorized_keys
                if ci_publickey:
                    ci_publickey = ci_publickey.strip()

                    # Create the .ssh directory and set the correct permissions
                    create_ssh_dir_cmd = (
                        f"sudo -u {ci_username}",
                        f"mkdir -p /home/{ci_username}/.ssh"
                    )
                    functions.execute_ssh_command(
                        ssh,
                        create_ssh_dir_cmd,
                        (
                            "Failed to create .ssh ",
                            f"directory for '{ci_username}'"
                        )
                    )

                    set_ssh_dir_permissions_cmd = (
                        f"sudo chmod 700 /home/{ci_username}/.ssh ",
                        f"&& sudo chown {ci_username}:{ci_username}",
                        f" /home/{ci_username}/.ssh"
                    )
                    functions.execute_ssh_command(
                        ssh,
                        set_ssh_dir_permissions_cmd,
                        (
                            "Failed to set permissions for .ssh ",
                            f"directory for '{ci_username}'"
                        )
                    )
                    # Add the SSH key to authorized_keys
                    add_ssh_key_cmd = (
                            f"echo '{ci_publickey}' |",
                            f" sudo -u {ci_username} ",
                            f"tee -a /home/{ci_username}/.ssh/authorized_keys",
                            " > /dev/null"
                        )
                    functions.execute_ssh_command(
                        ssh,
                        add_ssh_key_cmd,
                        (
                            f"Failed to add SSH public key for '{ci_username}'"
                        )
                    )

                    # Set the correct permissions for authorized_keys
                    set_auth_keys_permissions_cmd = (
                        "sudo chmod 600 ",
                        f"/home/{ci_username}/.ssh/authorized_keys",
                        f" && sudo chown {ci_username}:{ci_username} ",
                        f"/home/{ci_username}/.ssh/authorized_keys"
                    )
                    functions.execute_ssh_command(
                        ssh,
                        set_auth_keys_permissions_cmd,
                        (
                            "Failed to set permissions for authorized_keys",
                            f" for '{ci_username}'",
                        )
                    )
                    functions.output_message(
                        (
                            "SSH public key added successfully ",
                            f"for user '{ci_username}'."
                        ),
                        "s"
                    )

        # Step 4: Perform a login test with the newly created user
            login_attempts = 3
            for attempt in range(1, login_attempts + 1):
                try:
                    # Use unhashed password for login test
                    test_ssh = functions.ssh_connect(
                        ipaddress,
                        ci_username,
                        ci_password
                    )
                    functions.output_message(
                        (
                            "Login test successful for ",
                            f"user '{ci_username}'."
                        ),
                        "s"
                    )
                    break
                except Exception as e:
                    if attempt == login_attempts:
                        functions.output_message(
                            (
                                f"Login test failed for user '{ci_username}' ",
                                f"after {login_attempts} attempts: {e}"
                            ),
                            "e"
                        )
                    else:
                        functions.output_message(
                            (
                                f"Login attempt {attempt} failed ",
                                f"for user '{ci_username}'. Retrying..."
                            ),
                            "w"
                        )
                        time.sleep(5)

        # Test sudo access after login
        try:
            # Use unhashed password for sudo test
            sudo_test_cmd = f"echo '{ci_password}' | sudo -S whoami"
            stdin, stdout, stderr = test_ssh.exec_command(sudo_test_cmd)
            exit_status = stdout.channel.recv_exit_status()
            if exit_status == 0 and 'root' in stdout.read().decode().strip():
                functions.output_message(
                    (
                        "Sudo access verified for ",
                        f"user '{ci_username}'"
                    ),
                    "s"
                )
            else:
                functions.output_message(
                    (
                        "Sudo access test failed for ",
                        f"user '{ci_username}'"
                    ),
                    "e"
                )
        except Exception as e:
            functions.output_message(
                (
                    "Sudo access test failed for ",
                    f"user '{ci_username}': {e}"
                ),
                "e"
            )

        finally:
            test_ssh.close()

    except Exception as e:
        functions.output_message(
            (
                "Failed to execute command on ",
                f"{ipaddress}: {e}"
            ),
            "e"
        )


def on_guest_temp_fix_cloudinit_part_2(ssh, values, ipaddress):
    try:
        # Step 0: Check for any running processes by the 'ubuntu' user
        functions.output_message(
            (
                "Temp. ci-fix"
            ),
            "h"
        )

        command = "pgrep -u ubuntu"
        processes = functions.execute_ssh_sudo_command(
            ssh,
            "CI_PASSWORD",
            command,
            (
                "Failed to grep processes for 'ubuntu' user"
            )
        )

        if processes:
            functions.output_message(
                    (
                        "Processes found for user 'ubuntu': ",
                        f"{processes.strip()}"
                    ),
                    "w"
                )

            # Kill all processes belonging to 'ubuntu' user
            command = "pkill -u ubuntu"
            functions.execute_ssh_sudo_command(
                ssh,
                "CI_PASSWORD",
                command,
                (
                    "Failed to kill processes for 'ubuntu' user")
                )
            functions.output_message(
                    (
                        "All processes for 'ubuntu' user killed."
                    ),
                    "s"
                )
        else:
            functions.output_message(
                    (
                        "No running processes found for user 'ubuntu'."
                    ),
                    "s"
                )
        # Step 1: Disable the default ubuntu user
        command = "deluser --remove-home ubuntu"
        functions.execute_ssh_sudo_command(
            ssh,
            "CI_PASSWORD",
            command,
            (
                "Failed to delete 'ubuntu' user"
            )
        )
        functions.output_message(
                    (
                        "User 'ubuntu' deleted successfully."
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


os.system('cls' if os.name == 'nt' else 'clear')
#
config_file = "/home/nije/json-files/pve01-maschine0.json"
script_directory = os.path.dirname(os.path.abspath(__file__))

functions.output_message()
functions.output_message("script info:", "h")
functions.output_message()
functions.output_message(f"Parameter filename: {config_file}")
functions.output_message(f"Script directory  : {script_directory}")
functions.output_message()

config = load_config(config_file)
values = get_json_values(config)
host = values.get("host")
user = values.get("user")

functions.output_message()
functions.output_message("Validate JSON structure", "h")
functions.output_message()
functions.check_parameters(config, MANDATORY_KEYS, OPTIONAL_KEYS)

functions.output_message()
functions.output_message("Validate JSON values", "h")
functions.output_message()
functions.check_values(config, integer_keys=INTEGER_KEYS)

functions.output_message()
functions.output_message("Evaluate configuration", "h")
functions.output_message()
check_conditional_values(values)

functions.output_message()
functions.output_message("Build virtual server", "h")
functions.output_message()

ssh = functions.ssh_connect(host, user, "", PVE_KEYFILE)
create_server(ssh, values)
create_ci_options(ssh, values)
start_vm(ssh, values)

# Wait and get the VM's IPv4 address
ipaddress = get_vm_ipv4_address(ssh, values)
ssh.close()

# login as user cloud-init shpuld have created
ci_username = values.get("ci_username")
ssh = functions.ssh_connect(ipaddress, ci_username)
on_guest_configuration(ssh, values, ipaddress)
ssh.close()
functions.output_message()
