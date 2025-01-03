#!/usr/bin/env python3
# lib/functions.py

import sys
import paramiko
import time
import re
import getpass
import os


def ssh_connect(host, username, password=None, key_filename=None):
    # Establish SSH connection to the remote
    # host securely using key-based auth.
    try:
        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        if password:
            ssh.connect(
                hostname=host,
                username=username,
                password=password
            )
        elif key_filename:
            ssh.connect(
                hostname=host,
                username=username,
                key_filename=key_filename
            )
        else:
            ssh.connect(
                hostname=host,
                username=username
            )
        output_message(
            f"Connected to {host} as {username}.",
            "s"
        )
        return ssh

    except paramiko.AuthenticationException:
        output_message(
            f"Authentication failed when connecting to {host}.",
            "Please check your credentials.",
            "w"
        )
    except paramiko.SSHException as e:
        output_message(
            f"Unable to establish SSH connection to {host}: {e}",
            "e"
        )
    except Exception as e:
        output_message(
            f"Unexpected error while connecting to {host}: {e}",
            "e"
        )
    return None


def execute_ssh_command(ssh, command, error_message=None):
    stdin, stdout, stderr = ssh.exec_command(command)
    exit_status = stdout.channel.recv_exit_status()
    error_output = stderr.read().decode().strip()
    if exit_status != 0:
        if error_message:
            output_message(f"{error_message}: {error_output}", "e")
    return stdout.read().decode().strip()


def execute_ssh_sudo_command(ssh, sudo_env, command, error_message=None):
    sudo_password = os.getenv(sudo_env)

    if not sudo_password:
        raise EnvironmentError(
            "The environment variable 'CI_PASSWORD' is not set.",
            " Please set it before running the script."
        )

    # Construct the sudo command with the password
    sudo_command = f'echo {sudo_password} | sudo -S -p "" bash -c "{command}"'

    try:
        # Execute the sudo command
        stdin, stdout, stderr = ssh.exec_command(sudo_command)

        # No need to write password again here; it is piped via the command.

        # Get the command's exit status and output
        exit_status = stdout.channel.recv_exit_status()
        output = stdout.read().decode().strip()
        error_output = stderr.read().decode().strip()

        # Handle command errors
        if exit_status != 0:
            if error_message:
                output_message(f"{error_message}: {error_output}", "e")

        return output

    except Exception as e:
        print(f"An unexpected error occurred while executing the command: {e}")


def wait_for_reboot(host, username, password=None, timeout=300, interval=10):
    start_time = time.time()
    while time.time() - start_time < timeout:
        try:
            ssh = paramiko.SSHClient()
            ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            if password:
                ssh.connect(host, username, password)
            else:
                ssh.connect(host, username)
            output_message(
                f"Successfully reconnected to {host} after reboot.",
                "s"
                )
            return ssh
        except Exception:
            output_message(
                f"SWaiting for '{host}' to reboot...",
                "w"
            )
            time.sleep(interval)
    output_message(
        f"Timeout while waiting for {host} to reboot.",
        "e"
    )


def is_valid_hostname(value_str):
    hostname_regex = re.compile(r'^(?!-)[A-Za-z0-9-]{1,63}(?<!-)$')

    # First, check if value_str is a string
    if not isinstance(value_str, str):
        output_message(
            f"{value_str}' is NOT a string value.",
            "e"
        )

    # Split the hostname into labels
    labels = value_str.split('.')

    # Check total length of the hostname
    if len(value_str) > 253:
        message = (
            f"{value_str} exceedes the masximum "
            "length of 253 characters."
        )
        output_message(
            message,
            "e"
        )

    # If there are multiple labels, validate each label
    for label in labels:
        if len(label) > 63:  # Each label must not exceed 63 characters
            message = (
                f"{value_str} exceeds the masximum length of 63 characters."
            )
            output_message(
                message,
                "e"
            )
        if not hostname_regex.match(label):  # Each label must match the regex
            message = (
                f"{value_str} contains invalid characters."
            )
            output_message(
                message,
                "e"
            )

    # If there is only one label, still need to validate it
    if len(labels) == 1:
        # Validate the single label (without considering it as multiple labels)
        if not hostname_regex.match(value_str):
            output_message(
                f"{value_str}' contains invalid characters.",
                "e"
            )

    output_message(
        f"{value_str}' is a valid hostname.",
        "s"
    )


def check_valid_ip_address(which_ip, vlan=None):

    parts = which_ip.split('.')

    if len(parts) != 4:
        message = (
            f"Invalid IP address '{which_ip}'. "
            "IP address should have exactly four parts."
        )
        output_message(message, "E")

    for part in parts:
        try:
            part_int = int(part)
            if not 0 <= part_int <= 255:
                message = (
                    f"Invalid IP address '{which_ip}'. "
                    "Each part should be between 0 and 255."
                )
                output_message(message, "E")
        except ValueError:
            message = (
                f"Invalid IP address '{which_ip}'. "
                "Each part should be an integer."
            )
            output_message(message, "E")

    message = (
        f"IP address '{which_ip}' is a valid ip-address."
    )
    output_message(message, "s")

    if vlan:
        try:
            if int(vlan) == int(parts[2]):
                message = (
                    f"IP address 3rd octect '{parts[2]}' "
                    f"match VLAN ID '{vlan}'."
                )
                output_message(message, "s")
            else:
                message = (
                    f"IP address 3rd octect '{parts[2]}' does not "
                    f"match VLAN ID '{vlan}'. Continuing..."
                )
                output_message(message, "w")

        except ValueError:
            output_message("Error occured checking VLAN.", "E")


def check_netmask(value_string):
    try:
        netmask = int(value_string)
        if netmask not in range(23, 30):
            message = (
                f"Invalid netmask '{value_string}'. "
                "Netmask is not a number between /24 and /29."
            )
            output_message(message, "E")
            return

    except ValueError:
        message = (
            f"Invalid netmask '{value_string}'. Netmask is not a number value."
        )
        output_message(message, "E")
        return

    output_message(f"Netmask '/{netmask}' is a valid netmask.", "s")


def check_vlan(vlanid):
    try:
        if not int(vlanid) in range(2, 4095):
            message = (
                f"Invalid VLAN '{vlanid}'. Vlan should be a "
                "number between 2 and 4094."
            )
            output_message(message, "E")

    except ValueError:
        message = (
            f"Invalid VLAN '{vlanid}'. Vlan id must be a number."
        )
        output_message(message, "E")

    message = (
        f"VLAN id '{vlanid}' is a valid VLAN."
    )
    output_message(message, "s")


def change_remote_password(ssh, remote_user, current_password):

    # Change the password of ci_username
    try:
        # Prompt for the new password and store it in an environment variable
        message = (
            f"Enter new password for user '{remote_user}': "
        )
        new_password = getpass.getpass(message)

        if not new_password:
            output_message("New password value is not set", "e")

        # Construct the command to change the password
        # Make sure to properly format the string and
        # include the environment variable correctly
        sudo_command = (
            f"echo {current_password} | "
            "sudo -S -p '' bash -c \"echo "
            f"'{remote_user}:{new_password}' | chpasswd\""
        )

        # Execute the sudo command
        stdin, stdout, stderr = ssh.exec_command(sudo_command)

        # No need to write password again here; it is piped via the command

        # Get the command's exit status and output
        exit_status = stdout.channel.recv_exit_status()
        error_output = stderr.read().decode().strip()

        # Handle command errors
        if exit_status != 0:
            message = (
                f"Failed to change password on {remote_user}: {error_output}."
            )
            output_message(message, "e")

        message = (
            f"Password for user '{remote_user}' has been changed."
        )
        output_message(message, "s")

    except Exception as e:
        print(f"An error occurred: {e}")

    finally:
        # Remove the NEW_PASSWORD from environment variables
        new_password = ""


def output_message(message=None, type=None):
    # Set pre_message to the correct prefix based on 'type'
    if type == "s" or type == "S":
        pre_message = "[✓] "
        color = '\033[32m'
    elif type == "i" or type == "I":
        pre_message = "[ ] "
        color = '\033[32m'
    elif type == "w" or type == "W":
        pre_message = "[*] "
        color = '\033[33m'
    elif type == "e" or type == "E":
        pre_message = "[x] "
        color = '\033[31m'
    elif type == "h" or type == "H":
        pre_message = ""
        color = '\033[0m'
        if message:
            message = message.upper()
            if len(message) < 78:
                blanks = 78 - len(message)
                left_padding = blanks // 2
                right_padding = blanks - left_padding
                left = "-" + ' ' * left_padding
                right = ' ' * right_padding + "-"
                heading = (
                    f"{left}"
                    f"{message}"
                    f"{right}"
                )
            else:
                heading = message[:78]
        else:
            heading = "-" * 80
        message = heading
    else:
        color = '\033[0m'
        if message:
            pre_message = "[?] "
        else:
            pre_message = ""

    reset = '\033[0m'

    if not message:
        message = "-" * 80

    # Now print the formatted message
    print(f"{color}{pre_message}{message}{reset}")
    if type == "e" or type == "E":
        message = "-" * 80
        print(f"{message}")
        sys.exit(1)


def validate_boolean(value, field_name):
    if not isinstance(value, bool):
        output_message(f"'{field_name}' must be a boolean (true/false)", "e")
        return False
    return True


def check_parameters(config, mandatory_keys, optional_keys):
    allowed_keys = set(mandatory_keys.keys()).union(optional_keys.keys())
    errors = []

    try:
        # Check for invalid keys in the JSON
        for key in config.keys():
            if key not in allowed_keys:
                message = (
                    f"Invalid key '{key}' found in JSON configuration."
                )
                errors.append(message)

        # Check for mandatory keys and sub-keys
        for key, sub_key in mandatory_keys.items():
            if key not in config:
                errors.append(
                    f"Missing mandatory key '{key}'"
                    " in JSON configuration."
                )
            elif sub_key not in config[key]:
                errors.append(
                    f"Missing mandatory sub-key '{sub_key}'"
                    f" in '{key}' object."
                )
            elif not validate_boolean(
                config[key].get("allow_blank", None),
                f"{key}.allow_blank"
            ):
                errors.append(
                    f"Invalid boolean value for '{key}.allow_blank'."
                )
            elif not validate_boolean(
                config[key].get("allow_spaces", None),
                f"{key}.allow_spaces"
            ):
                errors.append(
                    f"Invalid boolean value for '{key}.allow_spaces'."
                )

        # Check for 'comment' key in each object, if required
        for key, obj in config.items():
            if "comment" not in obj:
                errors.append(f"'{key}' is missing 'comment' key.")

        # Output all errors if found
        if errors:
            for error in errors:
                output_message(f"{error}", "e")

        output_message("All parameters are structured correctly", "s")

    except Exception as e:
        message = (
            f"Error while validating the structure in JSON file: {e}"
        )
        output_message(message, "e")


def check_values(config, integer_keys=None):
    errors = []

    for key, obj in config.items():
        first_key = next(iter(obj))
        first_value = obj[first_key]

        # Check if allow_blank is false and
        # the value is empty (only for strings)
        if (
            obj.get("allow_blank") is False
            and isinstance(first_value, str)
            and first_value == ""
        ):
            errors.append(f"'{first_key}' is blank but cannot be blank.")

        # Check if allow_spaces is false and
        # the value contains spaces (only for strings)
        if (
            obj.get("allow_spaces") is False
            and isinstance(first_value, str)
            and " " in first_value
        ):
            errors.append(
                f"'{first_key}' contains spaces "
                "but cannot have spaces."
            )

        # Check if value should be an integer,
        # allowing strings that represent integers
        if integer_keys and key in integer_keys:
            if not isinstance(first_value, int):
                if isinstance(first_value, str):
                    try:
                        # Try to convert the string to an integer
                        int(first_value)
                    except ValueError:
                        errors.append(
                            f"'{first_key}' should be an integer, "
                            f"but found non-integer value: '{first_value}'."
                        )
                else:
                    errors.append(
                        f"'{first_key}' should be an integer, but found type "
                        f"'{type(first_value).__name__}'."
                    )

    # Output any errors found
    if errors:
        for error in errors:
            output_message(f"{error}", "e")

    output_message("All values are the correct type", "s")


def check_if_id_in_use(ssh, pve_id):
    command = (
        "qm list | "
        f"awk '{{print $1}}' | "
        f"grep -q '^{pve_id}$' && "
        "echo 'in_use' || echo 'not_in_use'"
    )
    message = (
        f"Unable to query ID {pve_id} on proxmox host."
    )
    result = execute_ssh_command(ssh, command, message)
    """Check if TEMPLATE_ID is already in use on the Proxmox host"""
    # stdin, stdout, stderr = ssh.exec_command(f"qm list
    # | awk '{{print $1}}' | grep -q '^{template_id}$'
    # && echo 'in_use' || echo 'not_in_use'")
    # result = stdout.read().decode().strip()
    if result == "in_use":
        return True
    else:
        return False


def get_status_info(search_string, scr_string):
    pattern = rf'{search_string}:\s*(.+)'
    match = re.search(pattern, scr_string)
    if match:
        search_string_value = match.group(1).strip()
    else:
        search_string_value = None
    return search_string_value


def get_config_info(search_string, scr_string):
    pattern = rf'{search_string}=(.*?)(?:,|$)'
    # rf'{search_string}=': Look for the key followed by =.
    # (.*?): Capture everything lazily (up to the
    # next comma or end of string).
    # (?:,|$): Stop at the next comma or the end of the string.
    match = re.search(pattern, scr_string)
    if match:
        search_string_value = match.group(1).strip()
    else:
        search_string_value = None
    return search_string_value


def integer_check(values, integers):
    errors = []

    for key in values:
        if key in integers:
            key_value = values.get(key)
            if not isinstance(key_value, int):
                errors.append(
                    f"'{key}' should be an integer, "
                    f"but found non-integer value: '{key_value}'."
                )

    if errors:
        for error in errors:
            output_message(f"{error}", "e")
    else:
        output_message("All integer values are correct", "s")


def check_bridge_exists(ssh, bridge):
    command = f"brctl show | grep -w '{bridge}'"
    result = execute_ssh_command(
        ssh,
        command,
        (
            f"Network bridge: {bridge} does not exist "
            "or is not active on the Proxmox host."
        )
    )

    if result:
        return True
    else:
        return False


def check_storage_exists(ssh, local_storage):
    stdin, stdout, stderr = ssh.exec_command(
        f"pvesm status | awk '{{print $1}}' | grep -w '{local_storage}'"
    )

    command = f"pvesm status | awk '{{print $1}}' | grep -w '{local_storage}'"
    result = execute_ssh_command(
        ssh,
        command,
        f"Storage: {local_storage} does NOT exist on the Proxmox host."
    )
    if result:
        return True
    else:
        return False


def check_valid_ip_address_v2(which_ip):

    parts = which_ip.split('.')

    if len(parts) != 4:
        message = (
            f"Invalid IP address '{which_ip}'. "
            "An IP address should have exactly four parts."
        )
        return False, message

    for part in parts:
        try:
            part_int = int(part)
            if not 0 <= part_int <= 255:
                message = (
                    f"Invalid IP address '{which_ip}'. "
                    "Each part should be between 0 and 255."
                )
                return False, message

        except ValueError:
            message = (
                f"Invalid IP address '{which_ip}'. "
                "Each part should be an integer."
            )
            return False, message

    message = (
        f"IP address '{which_ip}' is valid."
    )
    return True, message


def is_valid_hostname_v2(value_str):
    hostname_regex = re.compile(r'^(?!-)[A-Za-z0-9-]{1,63}(?<!-)$')

    # First, check if value_str is a string
    if not isinstance(value_str, str):
        message = (
            f"{value_str}' is NOT a string value.")
        return False, message

    # Split the hostname into labels
    labels = value_str.split('.')

    # Check total length of the hostname
    if len(value_str) > 253:
        message = (
            f"{value_str} exceedes the masximum "
            "length of 253 characters."
        )
        return False, message

    # If there are multiple labels, validate each label
    for label in labels:
        if len(label) > 63:  # Each label must not exceed 63 characters
            message = (
                f"{label} exceeds the masximum length of 63 characters."
            )
            return False, message

        if not hostname_regex.match(label):  # Each label must match the regex
            message = (
                f"{label} contains invalid characters."
            )
            return False, message

    # If there is only one label, still need to validate it
    if len(labels) == 1:
        # Validate the single label (without considering it as multiple labels)
        if not hostname_regex.match(value_str):
            message = (
                f"{value_str}' contains invalid characters."
            )
            return False, message

    message = (
        f"Hostname {value_str}' is a valid."
    )
    return True, message


def ssh_connect_v2(host, username, password=None, key_filename=None):
    # Establish SSH connection to the remote
    # host securely using key-based auth.
    try:
        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        if password:
            ssh.connect(
                hostname=host,
                username=username,
                password=password
            )
        elif key_filename:
            ssh.connect(
                hostname=host,
                username=username,
                key_filename=key_filename
            )
        else:
            ssh.connect(
                hostname=host,
                username=username
            )
        message = f"Connected to {host} as {username}."
        return True, message, ssh

    except paramiko.AuthenticationException:
        message = (
            f"Authentication failed when connecting to {host}."
            "Please check your credentials."
        )
        return False, message, None

    except paramiko.SSHException as e:
        message = f"Unable to establish SSH connection to {host}: {e}"
        return False, message, None

    except Exception as e:
        message = f"Unexpected error while connecting to {host}: {e}"
        return False, message, None

    finally:
        if ssh and not ssh.get_transport():
            ssh.close()  # Ensure cleanup of uninitialized connections
