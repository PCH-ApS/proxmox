#!/usr/bin/env python3
import os
import sys
import argparse
import yaml

from lib.output_handler import OutputHandler
from lib.check_files_handler import CheckFiles
from lib.yaml_config_loader import LoaderNoDuplicates
from cerberus import Validator
from lib.proxmox_host_handler import ProxmoxHost

DEFAULT_YAML_VALIDATION_FILE = "config/template_config_validation.yaml"
DEFAULT_LOGFILE = "logs/create_teamplate.log"
output = OutputHandler(DEFAULT_LOGFILE)


def parse_args():
    parser = argparse.ArgumentParser(description="Create Proxmox template")
    parser.add_argument(
        "--config",
        dest="config_file",
        required=True,
        help="Path to your configuration YAML file for the Proxmox template"
    )
    parser.add_argument(
        "--validation",
        dest="validation_file",
        default=DEFAULT_YAML_VALIDATION_FILE,
        help=(
            "Optional: Specify a differant set of validation rules "
            "for the config file, if the default file is not to be used"
        )
    )
    return parser.parse_args()


def check_files(args):
    filename = os.path.basename(args)
    checker = CheckFiles(args)
    if checker.check():
        output.output(f"{filename} access checks passed", type="s")
    else:
        for i, error in enumerate(checker.errors):
            is_last = (i == len(checker.errors) - 1)
            if not is_last:
                output.output(
                    f"{filename} access checks failed: {error}",
                    type="e"
                    )
            else:
                output.output(
                    f"{filename} access checks failed: {error}",
                    type="e",
                    exit_on_error=True
                    )


def load_yaml_file(yaml_file):
    try:
        yaml_dict = yaml.load(
            open(yaml_file, 'r').read(),
            Loader=LoaderNoDuplicates
        )
    except Exception as e:
        print(
            f'File yaml load error in '
            f'"{yaml_file}": {str(e)}'
        )

    return yaml_dict


def validate_config(config, validation_rules):
    validator = Validator(validation_rules)
    if not validator.validate(config):
        for field, errors in validator.errors.items():
            for error in errors:
                output.output(f"{field}: {error}", type="e")
        output.output(
            "Configuration validation failed",
            type="e",
            exit_on_error=True
        )
    else:
        output.output("Configuration validation passed", type="s")
        return validator.document


def main():
    args = parse_args()
    this_script = os.path.abspath(__file__)

    output.output()
    output.output("Create template on Proxmox Host", type="h")
    output.output()
    output.output(f"Initial script      : {sys.argv[0]}", type="i")
    output.output(f"Active script       : {this_script}", type="i")
    output.output(f"Config file         : {args.config_file}", type="i")
    output.output(f"Validation file     : {args.validation_file}", type="i")
    output.output(f"Default logfile     : {DEFAULT_LOGFILE}", type="i")
    output.output()
    output.output("Checking files", type="h")
    output.output()

    # Check config files
    check_files(args.config_file)
    check_files(args.validation_file)
    config_values = load_yaml_file(args.config_file)
    validation_rules = load_yaml_file(args.validation_file)
    v_config = validate_config(config_values, validation_rules)

    max_key_len = max(len(key) for key in v_config)
    for key in v_config:
        label = "set by user" if key in config_values else "using default"
        output.output(f"{key.ljust(max_key_len + 1)}: {label}", type="i")

    host = ProxmoxHost(
        host=v_config["tmp_host_ip"],
        username=v_config["tmp_host_username"],
        key_filename=v_config["tmp_host_keyfile"],
    )

    output.output()
    output.output("Checking SSH connectivity", type="h")
    output.output()

    connect_flag, connect_message = host.connect()
    output.output(
        connect_message,
        type="s" if connect_flag else "e",
        exit_on_error=not connect_flag
        )

    output.output()
    output.output("Validating Proxmox components", type="h")
    output.output()

    ok, msg = host.is_vmid_in_use(v_config["tmp_id"])
    output.output(msg, "s" if not ok else "e", exit_on_error=ok)
    ok, msg = host.check_cpu_model_supported(v_config["tmp_cpu"])
    output.output(msg, "s" if ok else "e", exit_on_error=not ok)
    ok, msg = host.check_storage_ctrl_exists(v_config["tmp_storage_ctrl"])
    output.output(msg, "s" if ok else "e", exit_on_error=not ok)
    ok, msg = host.check_storage_exists(v_config["tmp_local_storage"])
    output.output(msg, "s" if ok else "e", exit_on_error=not ok)
    ok, msg = host.check_bridge_exists(v_config["tmp_bridge"])
    output.output(msg, "s" if ok else "e", exit_on_error=not ok)
    ok, msg = host.check_network_ctrl_exists(v_config["tmp_network_ctrl"])
    output.output(msg, "s" if ok else "e", exit_on_error=not ok)

    output.output()
    output.output("Creating template", type="h")
    output.output()

    command = f"qm create {v_config['tmp_id']} --name {v_config['tmp_name']}"
    result = host.run(command)
    if result["exit_code"] != 0:
        output.output(
            f"Error setting template id: {result['stderr']}",
            "e",
            exit_on_error=True
            )
    output.output(
            f"Setting template id: {v_config['tmp_id']} "
            f"and name: {v_config["tmp_name"]}",
            "s",
            )

    command = f"qm set {v_config['tmp_id']} --cpu {v_config['tmp_cpu']}"
    result = host.run(command)
    if result["exit_code"] != 0:
        output.output(
            f"Error setting CPU: {result['stderr']}",
            "e",
            exit_on_error=True
            )
    output.output(
            f"Setting template CPU: {v_config['tmp_cpu']}",
            "s",
            )

    command = f"qm set {v_config['tmp_id']} --cores {v_config['tmp_cores']}"
    result = host.run(command)
    if result["exit_code"] != 0:
        output.output(
            f"Error setting CPU cores: {result['stderr']}",
            "e",
            exit_on_error=True
            )
    output.output(
            f"Setting template CPU cores: {v_config["tmp_cores"]} ",
            "s",
            )

    command = f"qm set {v_config['tmp_id']} --memory {v_config['tmp_memory']}"
    result = host.run(command)
    if result["exit_code"] != 0:
        output.output(
            f"Error setting memory: {result['stderr']}",
            "e",
            exit_on_error=True
            )
    output.output(
            f"Setting template memory: {v_config["tmp_memory"]} ",
            "s",
            )

    command = (
        f"qm set {v_config['tmp_id']} --scsihw {v_config['tmp_storage_ctrl']}"
    )
    result = host.run(command)
    if result["exit_code"] != 0:
        output.output(
            f"Error setting storage controller: {result['stderr']}",
            "e",
            exit_on_error=True
            )
    output.output(
            f"Setting template storage ctrl: {v_config['tmp_storage_ctrl']} ",
            "s",
            )

    command = (
        f"qm set {v_config['tmp_id']} --net0 model="
        f"{v_config['tmp_network_ctrl']}"
    )
    result = host.run(command)
    if result["exit_code"] != 0:
        output.output(
            f"Error setting network controller: {result['stderr']}",
            "e",
            exit_on_error=True
            )
    output.output(
            "Setting template network controller: "
            f"{v_config['tmp_network_ctrl']}",
            "s"
            )

    command = (
        f"qm set {v_config['tmp_id']} "
        f"--{v_config['tmp_bootdisk']} "
        f"{v_config['tmp_local_storage']}:0,"
        f"import-from={v_config['tmp_image_path']},discard=on"
    )
    result = host.run(command)
    if result["exit_code"] != 0:
        output.output(
            f"Error setting bootdisk: {result['stderr']}",
            "e",
            exit_on_error=True
            )
    output.output(
            f"Setting template bootdisk: {v_config['tmp_bootdisk']} "
            f"on {v_config['tmp_local_storage']}",
            "s",
            )
    output.output(
            f"Applying image file: {v_config['tmp_image_path']}",
            "s",
            )

    commands = [
      f"qm set {v_config['tmp_id']} --agent enabled=1,fstrim_cloned_disks=1",
      f"qm set {v_config['tmp_id']} --serial0 socket",
      f"qm set {v_config['tmp_id']} --vga serial0",
        ]

    # Execute each command via SSH
    for command in commands:
        result = host.run(command)
        if result["exit_code"] != 0:
            output.output(
                f"Error creating template: {result['stderr']}",
                "e",
                exit_on_error=True
                )

    command = (
        f"qm template {v_config['tmp_id']}"
    )
    result = host.run(command)
    if result["exit_code"] != 0:
        output.output(
            f"Error creating template: {result['stderr']}",
            "e",
            exit_on_error=True
            )
    output.output(
            "Conveting to template",
            "s"
            )

    output.output()
    output.output("Closing SSH", type="h")
    output.output()
    flag, message = host.close()
    output.output(message, type="s" if flag else "e", exit_on_error=not flag)
    output.output()
