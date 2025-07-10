#!/usr/bin/env python3
from old.lib import functions
import const.template_const as template

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


def get_config_values(config):
    allowed_keys = set(template.MANDATORY_KEYS).union(template.OPTIONAL_KEYS)
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

        for key in allowed_keys:
            key_value = config.get(key)
            if key_value is not None:
                value_keys[key] = key_value
            else:
                default_value_key = f"DEFAULT_{key}".upper()
                default_value = getattr(template, default_value_key, None)

                if default_value is not None:
                    value_keys[key] = default_value

    except Exception as e:
        functions.output_message(
            f"Error getting configuration values: {e}",
            "e"
            )

    finally:
        return value_keys


def create_template(ssh, values):
    name = values.get("name")
    id = values.get("id")
    cpu = values.get("cpu")
    cores = values.get("cores")
    memory = values.get("memory")
    storage_ctrl = values.get("storage_ctrl")
    local_storage = values.get("local_storage")
    bootdisk = values.get("bootdisk")
    nic = values.get("network_ctrl")
    bridge = values.get("bridge")
    image = values.get("image")

    functions.output_message(
        f"Checking configuration for '{name}'.",
        "s"
    )

    if name:
        functions.is_valid_hostname(name)

    if bridge:
        bridge_exist = functions.check_bridge_exists(ssh, bridge)
        if bridge_exist:
            functions.output_message(
                (
                    f"Network bridge: {bridge} exist and is "
                    "active on the Proxmox host."
                ),
                "s"
            )

    if local_storage:
        storage_exist = functions.check_storage_exists(ssh, local_storage)
        if storage_exist:
            functions.output_message(
                    f"Storage: {local_storage} exist on the Proxmox host.",
                    "s"
                )

    id_in_use = functions.check_if_id_in_use(ssh, id)

    if id_in_use:
        functions.output_message(
            "Template id already exists on host.",
            "e"
            )

    if id_in_use is False:
        command = f"qm create {id} --name {name}"
        functions.execute_ssh_command(
            ssh,
            command,
            f"'{command}' failed on the Proxmox host."
        )
        functions.output_message(
            f"Setting template id: {id} and name: {name}",
            "s"
        )

    try:

        if cpu:
            command = (
                f"qm set {id} --cpu {cpu}"
            )
            functions.execute_ssh_command(
                ssh,
                command,
                f"Failed to set cpt type: {cpu}"
            )
            functions.output_message(
                f"Setting cpu type to {cpu}.",
                "s"
            )

        if cores:
            command = (
                f"qm set {id} --cores {cores}"
            )
            functions.execute_ssh_command(
                ssh,
                command,
                f"Failed to set cores: {cores}"
            )
            functions.output_message(
                f"Setting cores to {cores}.",
                "s"
            )

        if memory:
            command = (
                f"qm set {id} --memory {memory}"
            )
            functions.execute_ssh_command(
                ssh,
                command,
                f"Failed to set memory: {memory} MB"
            )
            functions.output_message(
                f"Setting memory to {memory} MB.",
                "s"
            )

        if storage_ctrl:
            command = (
                f"qm set {id} --scsihw {storage_ctrl}"
            )
            functions.execute_ssh_command(
                ssh,
                command,
                f"Failed to set SCSI HW: {storage_ctrl}"
            )
            functions.output_message(
                f"Setting SCSI HW to {storage_ctrl}.",
                "s"
            )

        if local_storage:
            command = (
                f"qm set {id} --{bootdisk} {local_storage}:0,"
                f"import-from={image},discard=on"
            )
            functions.execute_ssh_command(
                ssh,
                command,
                f"Failed to set boot disk {bootdisk} on {local_storage}"
            )
            functions.output_message(
                (
                    f"Setting SCSI boot disk {bootdisk} on {local_storage}. "
                    f"Applying image file: {image}."
                ),
                "s"
            )

        if nic:
            command = (
                f"qm set {id} --net0 model={nic},"
                f"bridge={bridge}"
            )
            functions.execute_ssh_command(
                ssh,
                command,
                f"Failed to set NIC: {nic} and bridge: {bridge}"
            )
            functions.output_message(
                f"Setting NIC: {nic} and bridge: {bridge}.",
                "s"
            )

        if bootdisk:
            command = (
                f"qm set {id} --boot c --bootdisk {bootdisk}"
            )
            functions.execute_ssh_command(
                ssh,
                command,
                f"Failed to set bootdisk {bootdisk}"
            )
            functions.output_message(
                f"Setting bootdisk {bootdisk}.",
                "s"
            )

            command = (
                f"qm set {id} --boot order={bootdisk}"
            )
            functions.execute_ssh_command(
                ssh,
                command,
                f"Failed to set boot order for {bootdisk}"
            )
            functions.output_message(
                f"Setting boot order for {bootdisk}.",
                "s"
            )

        commands = [
            f"qm set {id} --agent enabled=1,fstrim_cloned_disks=1",
            f"qm set {id} --serial0 socket",
            f"qm set {id} --vga serial0",
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

    command = f"qm template {id}"
    functions.execute_ssh_command(
        ssh,
        command,
        f"'{command}' failed on the Proxmox host."
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

functions.output_message("Validate config values", "h")
functions.output_message()
functions.integer_check(values, template.INTEGER_KEYS)

functions.output_message()
functions.output_message("build template", "h")
functions.output_message()

host = values.get("host_ip")
user = values.get("username")
ssh = functions.ssh_connect(host, user, "", template.PVE_KEYFILE)
create_template(ssh, values)
ssh.close()
functions.output_message(f"Succesfully applied template: {config_file}", "s")
functions.output_message()
