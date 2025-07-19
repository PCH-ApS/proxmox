#!/usr/bin/env python3
import os
import sys
import argparse
import yaml

from lib.output_handler import OutputHandler
from lib.check_files_handler import CheckFiles
from lib.yaml_config_loader import LoaderNoDuplicates
from cerberus import Validator
from lib.ssh_handler import SSHConnection
from lib.proxmox_host_handler import ProxmoxHost

DEFAULT_YAML_VALIDATION_FILE = "config/host_config_validation.yaml"
DEFAULT_LOGFILE = "logs/configure_host.log"
DEFAULT_HOSTFILE = "/etc/hosts"

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


def run():
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

    check_files(args.config_file)
    check_files(args.validation_file)
    config_values = load_yaml_file(args.config_file)
    validation_rules = load_yaml_file(args.validation_file)
    v_config = validate_config(config_values, validation_rules)
    for key in v_config:
        if key in config_values:
            output.output(f"{key}: set by user", type="i")
        else:
            output.output(f"{key}: using default", type="i")

    output.output()
    output.output("Checking SSH connectivity", type="h")
    output.output()

    ssh = SSHConnection(
        host=v_config["pve_host_ip"],
        username=v_config["pve_host_username"],
        key_filename=v_config["pve_host_keyfile"],
        )
    flag, message = ssh.connect()
    output.output(message, type="s" if flag else "e", exit_on_error=not flag)
    flag, message = ssh.close()
    output.output(message, type="s" if flag else "e", exit_on_error=not flag)

    output.output()
    output.output("Checking Proxmox host", type="h")
    output.output()

    host = ProxmoxHost(
        host=v_config["pve_host_ip"],
        username=v_config["pve_host_username"],
        key_filename=v_config["pve_host_keyfile"],
    )
    connect_flag, connect_message = host.connect()
    output.output(
        connect_message,
        type="s" if connect_flag else "e",
        exit_on_error=not connect_flag
        )

    current_hostname = host.get_hostname()
    DEFAULT_FOLDERS = [
        f"/etc/pve/nodes/{current_hostname[1]}/lxc",
        f"/etc/pve/nodes/{current_hostname[1]}/qemu-server",
    ]
    file_path = DEFAULT_HOSTFILE
    host_messege = host.change_hostname(
        v_config["pve_hostname"],
        v_config['pve_host_ip'],
        v_config["pve_domain"],
        file_path,
        DEFAULT_FOLDERS
    )

    for host_line in host_messege:
        output.output(host_line[1], type="s" if host_line[0] else "e")

    flag, message = host.close()
    output.output(message, type="s" if flag else "e", exit_on_error=not flag)
