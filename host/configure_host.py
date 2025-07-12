#!/usr/bin/env python3
import os
import sys
import argparse
# import yaml

from lib.output_handler import OutputHandler
from lib.check_files_handler import CheckFiles
# from lib.yaml_config_loader import loader_no_dup
# from lib.yaml_validation_handler import ValidationHandler

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
            "for the config file, if the default is not to be used"
        )
    )
    return parser.parse_args()


def run():
    args = parse_args()
    this_script = os.path.abspath(__file__)
    checker = CheckFiles(args.config_file)

    output.output()
    output.output("Configure Proxmox Host", type="h")
    output.output()
    output.output(f"Initial script : {sys.argv[0]}", type="i")
    output.output(f"Active script  : {this_script}", type="i")
    output.output(f"Config file    : {args.config_file}", type="i")
    output.output(f"Validation file: {args.validation_file}", type="i")
    output.output(f"Default logfile: {DEFAULT_LOGFILE}", type="i")
    output.output()
    output.output("Validating config file", type="h")
    output.output()
    if checker.check():
        output.output("Config File access checks passed", type="s")
    else:
        for i, error in enumerate(checker.errors):
            is_last = (i == len(checker.errors) - 1)
            if not is_last:
                output.output(f"File access checks failed: {error}", type="e")
            else:
                output.output(
                    f"File access checks failed: {error}",
                    type="e",
                    exit_on_error=True
                    )


#    with open("config/config.yaml") as f:
#        config_values = yaml.safe_load(f)

    # with open("config/schema.yaml") as f:
    #    config_schema = yaml.safe_load(f)

    # validator = ConfigValidator(config_values, config_schema, output)

    # if not validator.validate():
    #   output.output("Validation failed.", type="e", exit_on_error=True)
