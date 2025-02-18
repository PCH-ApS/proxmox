#!/usr/bin/env python3
from lib import functions
import const.host_const as host

import os
import json
import sys


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
            "w"
            )
        return None


def get_config_values(config):
    allowed_keys = set(host.MANDATORY_KEYS).union(host.OPTIONAL_KEYS)
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
                default_value = getattr(host, default_value_key, None)

                if default_value is not None:
                    value_keys[key] = default_value

    except Exception as e:
        functions.output_message(
            f"Error getting configuration values: {e}",
            "e"
            )

    finally:
        return value_keys


def validate_config(values):
    host_ip = values.get("host_ip")
    hostname = values.get("hostname")
    domain_string = values.get("domain_string")

    if host_ip:
        result, message = functions.check_valid_ip_address_v2(host_ip)
        if result:
            functions.output_message(message, "s")
        else:
            functions.output_message(message, "e")

    fqdn = f"{hostname}.{domain_string}"
    if fqdn:
        result, message = functions.is_valid_hostname_v2(fqdn)
        if result:
            functions.output_message(message, "s")
        else:
            functions.output_message(message, "e")


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
functions.output_message("Validating config", "h")
functions.output_message()
validate_config(values)
functions.output_message()

functions.output_message("Configure PROXMOX host", "h")
functions.output_message()

host_ip = values.get("host_ip")
username = values.get("username")
result, message, ssh = functions.ssh_connect_v2(
    host_ip, username,
    "",
    host.PVE_KEYFILE
)

if result is False:
    functions.output_message(message, "e")

if result:
    functions.output_message(message, "s")
    """
    Get all the config files. The default file, and any included files
    """
    result_flag, message = functions.list_config_files(
        ssh, host.SSHD_CONFIG, host.SSHD_SEARCHSTRING
        )
    if result_flag:
        config_files = message
    else:
        functions.output_message(message, "e")
        functions.output_message()

    """
    Extract the current set of active parameters from the
    """
    result_flag, message = functions.extract_active_parameters(
        ssh, config_files
        )

    if result_flag:
        active_parameters = message
    else:
        functions.output_message(message, "e")
        functions.output_message()

    result_flag, message = functions.find_multiple_definitions(
        active_parameters
        )

    if result_flag:
        multi_defined = message
        functions.output_message(
            "Found multiple instances of same SSHD parameters",
            "w"
            )
        comment_out, to_add = functions.analyse_multiple_definitions(
            multi_defined,
            host.SSH_CONST,
            host.SSHD_CUSTOMFILE
        )

        result_flag, message = functions.comment_out_parameters(
            ssh,
            comment_out
        )
        if result_flag:
            functions.output_message(message, "s")
        else:
            functions.output_message(message, "i")
    else:
        functions.output_message(message, "i")

    result_flag, message = functions.extract_active_parameters(
        ssh,
        config_files
        )
    if result_flag:
        active_parameters = message
    else:
        functions.output_message(message, "e")
        functions.output_message()

    result_flag, message, missing_parameters = functions.get_missing_parameter(
        ssh,
        active_parameters,
        host.SSH_CONST,
        )

    if result_flag:
        functions.output_message(message, "w")
    else:
        functions.output_message(message, "i")
        functions.output_message()

    print(f"Config files: {config_files}")
    result_flag, message = functions.check_custom_file(
        config_files,
        host.SSHD_CUSTOMFILE
    )

    if result_flag:
        custom_file = message
        functions.output_message(
            f"Found: {custom_file}",
            "s"
        )
    else:
        functions.output_message(
            "Custom config file not found. Creating...",
            "i"
        )
        result_flag, return_value = functions.determine_custom_file_path(
            active_parameters,
            host.SSHD_CONFIG,
            host.SSHD_CUSTOMFILE
        )

        print(f"{result_flag}")
        print(f"{return_value}")

    print(f"Add include in config: {result_flag}")
    if result_flag:
        print(f"Custom file: {custom_file}")

    print(f"Active paramters: {active_parameters}")

