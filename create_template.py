#!/usr/bin/env python3
from lib import functions
from const.template_const import (MANDATORY_KEYS, OPTIONAL_KEYS,
                                  INTEGER_KEYS, PVE_KEYFILE
                                  )

import json
import sys
import os
# Add the parent directory to the Python path to make `lib` available
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))


def load_config(config_file):
    """Load configuration from a JSON file."""
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
        "id": config.get("ID").get("id"),
        "name": config.get("NAME").get("name"),
        "cores": config.get("CORES").get("cores"),
        "mem": config.get("MEMORY").get("mem"),
        "storage_ctrl": config.get("STORAGE_CONTROLLER").get("storage_ctrl"),
        "local_storage": config.get("LOCAL_STORAGE").get("local_storage"),
        "nic": config.get("NETWORK_CONTROLLER").get("nic"),
        "bridge": config.get("NETWORK_BRIDGE").get("bridge"),
        "image": config.get("DISKIMAGE").get("image")
    }


def check_bridge_exists(ssh, values):
    bridge = values.get("bridge")
    command = f"brctl show | grep -w '{bridge}'"
    result = functions.execute_ssh_command(
        ssh,
        command,
        (
            f"Network bridge: {bridge} does not exist "
            "or is not active on the Proxmox host."
        )
    )

    if result:
        functions.output_message(
            (
                f"Network bridge: {bridge} exist and id "
                "active on the Proxmox host."
            ),
            "s"
        )


def check_storage_exists(ssh, values):
    local_storage = values.get("local_storage")
    stdin, stdout, stderr = ssh.exec_command(
        f"pvesm status | awk '{{print $1}}' | grep -w '{local_storage}'"
    )

    command = f"pvesm status | awk '{{print $1}}' | grep -w '{local_storage}'"
    result = functions.execute_ssh_command(
        ssh,
        command,
        f"Storage: {local_storage} does NOT exist on the Proxmox host."
    )
    if result:
        functions.output_message(
            f"Storage: {local_storage} exist on the Proxmox host.",
            "s"
        )


def create_template(ssh, values):
    template_id = values.get("id")
    result = functions.check_if_id_in_use(ssh, template_id)

    if result is False:
        command = f"qm create {template_id} --name {values['name']}"
        functions.execute_ssh_command(
            ssh,
            command,
            f"'{command}' failed on the Proxmox host."
        )
        functions.output_message(
            "Started building template on proxmox host.",
            "s"
        )

    try:

        commands = [
            f"qm set {template_id} --cpu host",
            f"qm set {template_id} --cores {values['cores']}",
            f"qm set {template_id} --memory {values['mem']}",
            f"qm set {template_id} --scsihw {values['storage_ctrl']}",
            (
                f"qm set {template_id} --scsi0 {values['local_storage']}:0,"
                f"import-from={values['image']},discard=on"
            ),
            (
                f"qm set {template_id} --net0 model={values['nic']},"
                f"bridge={values['bridge']}"
            ),
            f"qm set {template_id} --boot c --bootdisk scsi0",
            f"qm set {template_id} --boot order=scsi0",
            f"qm set {template_id} --agent enabled=1,fstrim_cloned_disks=1",
            f"qm set {template_id} --serial0 socket",
            f"qm set {template_id} --vga serial0",
        ]

        # Execute each command via SSH
        for command in commands:
            functions.execute_ssh_command(
                ssh,
                command,
                f"'{command}' failed on the Proxmox host."
            )

    except Exception as e:
        functions.output_message(
            f"Failed to create server template: {e}",
            "e"
        )

    if result is False:
        command = (
            f"qm set {template_id} --ide2 {values['local_storage']}:cloudinit"
        )
        functions.execute_ssh_command(
            ssh,
            command,
            f"'{command}' failed on the Proxmox host."
        )
        command = f"qm template {template_id}"
        functions.execute_ssh_command(
            ssh,
            command,
            f"'{command}' failed on the Proxmox host."
        )


os.system('cls' if os.name == 'nt' else 'clear')
config_file = sys.argv[1]
script_directory = os.path.dirname(os.path.abspath(__file__))
functions.output_message()
functions.output_message("script info:", "h")
functions.output_message()
functions.output_message(f"Parameter filename: {config_file}")
functions.output_message(f"Script directory  : {script_directory}")
functions.output_message()

print("")
config = load_config(config_file)
values = get_json_values(config)

functions.output_message()
functions.output_message("Validate JSON structure", "h")
functions.output_message()
functions.check_parameters(config, MANDATORY_KEYS, OPTIONAL_KEYS)

functions.output_message()
functions.output_message("Validate JSON values", "h")
functions.output_message()
functions.check_values(config, integer_keys=INTEGER_KEYS)

functions.output_message()
functions.output_message("build template", "h")
functions.output_message()

host = values.get("host")
user = values.get("user")
ssh = functions.ssh_connect(host, user, "", PVE_KEYFILE)
# check_template_id_in_use(ssh, values)
check_bridge_exists(ssh, values)
check_storage_exists(ssh, values)
create_template(ssh, values)
ssh.close()
functions.output_message(f"Succesfully applied template: {config_file}", "s")
functions.output_message()
