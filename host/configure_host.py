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
# from lib.promox_common import ProxmoxCommon

DEFAULT_YAML_VALIDATION_FILE = "config/host_config_validation.yaml"
DEFAULT_LOGFILE = "logs/configure_host.log"
output = OutputHandler(DEFAULT_LOGFILE)


def parse_args():
    parser = argparse.ArgumentParser(description="Configure Proxmox Host")
    parser.add_argument(
        "--config",
        dest="config_file",
        required=True,
        help="Path to your configuration YAML file for the Proxmox host"
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
    output.output("Configure Proxmox Host", type="h")
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

    # Format key for display
    max_key_len = max(len(key) for key in v_config)
    for key in v_config:
        label = "set by user" if key in config_values else "using default"
        output.output(f"{key.ljust(max_key_len + 1)}: {label}", type="i")

    host = ProxmoxHost(
        host=v_config["pve_host_ip"],
        username=v_config["pve_host_username"],
        key_filename=v_config["pve_host_keyfile"],
        logfile=DEFAULT_LOGFILE
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
    output.output("Checking Proxmox hostname", type="h")
    output.output()

    current_hostname = host.get_hostname()
    DEFAULT_FOLDERS = [
        f"/etc/pve/nodes/{current_hostname[1]}/lxc",
        f"/etc/pve/nodes/{current_hostname[1]}/qemu-server",
        ]
    host_message = host.change_hostname(
        v_config["pve_hostname"],
        v_config['pve_host_ip'],
        v_config["pve_domain"],
        v_config['pve_host_file'],
        DEFAULT_FOLDERS
        )

    for line in host_message:
        output.output(
            f"{line[1]}",
            f"{line[2]}"
        )

    if line[1] != f"Current hostname is correct: '{v_config["pve_hostname"]}'":
        if v_config["pve_host_reboot"]:
            wait_time = 10
            timeout = 180
            output.output(
                f"Reboot wait between try: {wait_time}s, timeout: {timeout}s",
                "i"
                )
            reboot_message = (
                host.reboot_and_reconnect(wait_time, timeout)
                )
            for line in reboot_message:
                output.output(
                    f"{line[1]}",
                    f"{line[2]}"
                )
        else:
            output.output("Reboot flag set to NOT reboot Proxmox host", "i")

    output.output()
    output.output("Checking Proxmox sshd config", type="h")
    output.output()

    check_message = host.check_sshd_config(v_config)
    for line in check_message:
        output.output(
            f"{line[1]}",
            f"{line[2]}"
        )

    if len(check_message) > 5:
        output.output(
            "Rechecking SSHD config",
            "i"
        )
        sshd_success = host.check_sshd_config(v_config)
        for line in sshd_success:
            output.output(
                f"{line[1]}",
                f"{line[2]}"
            )

    output.output()
    output.output("Checking Proxmox repository settings", type="h")
    output.output()
    subscription_message = host.check_pve_no_subscribtion()
    for line in subscription_message:
        output.output(
            f"{line[1]}",
            f"{line[2]}"
        )

    enterprise_message = host.check_pve_enterprise()
    for line in enterprise_message:
        output.output(
            f"{line[1]}",
            f"{line[2]}"
        )

    ceph_message = host.check_pve_ceph()
    for line in ceph_message:
        output.output(
            f"{line[1]}",
            f"{line[2]}"
        )

    patch_message = host.check_pve_pve_no_subscription_patch()
    for line in patch_message:
        output.output(
            f"{line[1]}",
            f"{line[2]}"
        )

    output.output()
    output.output("Downloading ISO files", type="h")
    output.output()
    download_message = host.download_iso_files(v_config)
    for line in download_message:
        output.output(
            f"{line[1]}",
            f"{line[2]}"
        )

    if v_config['pve_host_change_pwd']:
        output.output()
        output.output("Root password change", type="h")
        output.output()
        password_message = host.change_pwd(v_config)
        for line in password_message:
            output.output(
                f"{line[1]}",
                f"{line[2]}"
            )

    output.output()
    output.output("Closing SSH", type="h")
    output.output()
    flag, message = host.close()
    output.output(message, type="s" if flag else "e", exit_on_error=not flag)
    output.output()
