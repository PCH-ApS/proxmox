#!/usr/bin/env python3
import os
import sys
import argparse
import yaml
import shlex

from lib.output_handler import OutputHandler
from lib.check_files_handler import CheckFiles
from lib.yaml_config_loader import LoaderNoDuplicates
from cerberus import Validator
from lib.proxmox_host_handler import ProxmoxHost

DEFAULT_YAML_VALIDATION_FILE = "config/template_config_validation.yaml"
DEFAULT_LOGFILE = "logs/create_template.log"
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


def load_yaml_file(yaml_file: str) -> dict:
    try:
        with open(yaml_file, "r") as fh:
            return yaml.load(
                fh.read(), Loader=LoaderNoDuplicates
            )
    except Exception as e:
        output.output(
            f'File yaml load error in "{yaml_file}": {e}',
            "e",
            exit_on_error=True
            )
        return {}


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


def run_steps(host, steps, *, fail_prefix="Error creating template"):
    """
    steps: list[tuple[str, str]] -> (command, success_message)
    Executes each qm command; aborts on first error.
    """
    for cmd, ok_msg in steps:
        res = host.run(cmd)
        if res["exit_code"] != 0:
            stderr = res.get("stderr", "").strip()
            output.output(
                f"{fail_prefix}: {stderr or cmd}",
                "e",
                exit_on_error=True
                )
        else:
            output.output(ok_msg, "s")


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
    if not v_config:
        output.output(
            "Error retrieving config from yaml-files",
            "e",
            exit_on_error=True
            )
        return

    max_key_len = max(len(key) for key in v_config)
    for key in v_config:
        label = "set by user" if key in config_values else "using default"
        output.output(f"{key.ljust(max_key_len + 1)}: {label}", type="i")

    host = ProxmoxHost(
        host=v_config["host_ip"],
        username=v_config["host_username"],
        key_filename=v_config["host_keyfile"],
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

    ok, msg = host.is_vmid_in_use(v_config["id"])
    output.output(msg, "s" if not ok else "e", exit_on_error=ok)

    ok, msg = host.check_cpu_model_supported(v_config["cpu"])
    output.output(msg, "s" if ok else "e", exit_on_error=not ok)

    ok, msg = host.check_storage_ctrl_exists(v_config["storage_ctrl"])
    output.output(msg, "s" if ok else "e", exit_on_error=not ok)

    ok, msg = host.check_storage_exists(v_config["local_storage"])
    output.output(msg, "s" if ok else "e", exit_on_error=not ok)

    ok, msg = host.check_bridge_exists(v_config["bridge"])
    output.output(msg, "s" if ok else "e", exit_on_error=not ok)

    ok, msg = host.check_network_ctrl_exists(v_config["network_ctrl"])
    output.output(msg, "s" if ok else "e", exit_on_error=not ok)

    ok, msg = host.check_image_file_exists(v_config["image_path"])
    output.output(msg, "s" if ok else "e", exit_on_error=not ok)

    # Optional: bootdisk slot sanity (e.g., scsi0 / sata0 / ide0 / virtio0)
    ok, msg = host.validate_disk_slot(v_config["bootdisk"])
    output.output(msg, "s" if ok else "e", exit_on_error=not ok)

    output.output()
    output.output("Creating template", type="h")
    output.output()

    vmid = v_config["id"]
    name = shlex.quote(v_config["name"])
    cpu = shlex.quote(v_config["cpu"])
    cores = v_config["cores"]
    memory = v_config["memory"]
    scsihw = shlex.quote(v_config["storage_ctrl"])
    netmdl = shlex.quote(v_config["network_ctrl"])
    bridge = shlex.quote(v_config["bridge"])
    store = shlex.quote(v_config["local_storage"])
    slot = shlex.quote(v_config["bootdisk"])
    img = shlex.quote(v_config["image_path"])

    # Build net0 parameter once (minimal: model + bridge)
    net0 = f"model={netmdl},bridge={bridge}"

    # Steps to create template. Each tuple = (command, success_message)
    steps = [
        (
            f"qm create {vmid} --name {name}",
            f"Setting template id: {vmid} and name: "
            f"{v_config['name']}"
            ),

        (
            f"qm set {vmid} --cpu {cpu}",
            f"Setting template CPU: {v_config['cpu']}"
            ),

        (
            f"qm set {vmid} --cores {cores}",
            f"Setting template CPU cores: {cores}"
            ),

        (
            f"qm set {vmid} --memory {memory}",
            f"Setting template memory: {memory}"
            ),

        (
            f"qm set {vmid} --scsihw {scsihw}",
            f"Setting template storage ctrl: {v_config['storage_ctrl']}"
            ),

        (
            f"qm set {vmid} --net0 {net0}",
            "Setting template network controller: "
            f"{v_config['network_ctrl']} on {v_config['bridge']}"
            ),

        # Import image into storage and attach as boot disk (PVE 8.x)
        (
            f"qm set {vmid} --{slot} {store}:0,import-from={img},discard=on",
            "Setting template bootdisk: "
            f"{v_config['bootdisk']} on {v_config['local_storage']}"
            ),
    ]

    run_steps(host, steps)

    # Extra quality-of-life defaults for templates
    extras = [
        (
            f"qm set {vmid} --agent enabled=1,fstrim_cloned_disks=1",
            "Enabled qemu-guest-agent and fstrim for cloned disks"
            ),

        (
            f"qm set {vmid} --serial0 socket",
            "Added serial0 console socket"
            ),

        (
            f"qm set {vmid} --vga serial0",
            "Set VGA to serial0 (for console usability)"
            ),
    ]
    run_steps(host, extras)

    # Convert to template (finalize)
    run_steps(host, [
        (f"qm template {vmid}", "Converting to template"),
    ])

    output.output()
    output.output("Closing SSH", type="h")
    output.output()
    flag, message = host.close()
    output.output(message, type="s" if flag else "e", exit_on_error=not flag)
    output.output()
